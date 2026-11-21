/**
 * @file src/platform/windows/clipboard.cpp
 * @brief Win32 clipboard backend for the shared clipboard.
 *
 * sunshine.exe runs as SYSTEM inside the user's session on WinSta0\Default (started by
 * tools/sunshinesvc.cpp). The backend owns one thread with a message-only window that is
 * registered with AddClipboardFormatListener. That thread never changes its desktop (a thread
 * that owns windows cannot call SetThreadDesktop, unlike the capture threads that call
 * syncThreadDesktop()); the clipboard belongs to the window station, so this is sufficient.
 *
 * Every clipboard access runs on the window thread so EmptyClipboard() makes our window the
 * owner; WM_CLIPBOARDUPDATE with GetClipboardOwner() == our window is our own change and is
 * not reported. OpenClipboard is retried with exponential backoff because other applications
 * may hold the clipboard open briefly.
 *
 * Text: CF_UNICODETEXT (UTF-16, CRLF) <-> UTF-8 (LF). Images: read the registered "PNG" (or
 * "image/png") format when present, else CF_DIBV5/CF_DIB converted to PNG with WIC; write
 * "PNG" and CF_DIB (decoded with WIC). Delayed rendering is not used.
 */
// standard includes
#include <array>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <functional>
#include <future>
#include <mutex>
#include <string>
#include <thread>

// platform includes
#include <objbase.h>
#include <wincodec.h>
#include <windows.h>

// local includes
#include "src/logging.h"
#include "src/sds/clipboard_backend.h"
#include "src/sds/clipboard_backend_util.h"

using namespace std::literals;

namespace sds::clipboard::win32 {
  namespace {
    using steady = std::chrono::steady_clock;

    constexpr UINT wm_task = WM_APP + 0x51;  ///< Wake-up: run queued tasks.
    constexpr UINT wm_quit = WM_APP + 0x52;  ///< Destroy the window and leave the loop.
    constexpr wchar_t window_class[] = L"SunshineSdsClipboardWindow";
    constexpr auto write_wait = 3s;
    constexpr auto open_wait = 1s;

    // WIC identifiers, defined here so no import library has to provide them
    constexpr GUID clsid_wic_factory {0xcacaf262, 0x9370, 0x4615, {0xa1, 0x3b, 0x9f, 0x55, 0x39, 0xda, 0x4c, 0x0a}};
    constexpr GUID iid_wic_factory {0xec5ec8a9, 0xc395, 0x4314, {0x9c, 0x77, 0x54, 0xd7, 0xa9, 0x35, 0xff, 0x70}};
    constexpr GUID container_png {0x1b7cfaf4, 0x713f, 0x473c, {0xbb, 0xcd, 0x61, 0x37, 0x42, 0x5f, 0xae, 0xaf}};
    constexpr GUID format_bgra32 {0x6fddc324, 0x4e03, 0x4bfe, {0xb1, 0x85, 0x3d, 0x77, 0x76, 0x8d, 0xc9, 0x0f}};

    /**
     * @brief Minimal owning COM pointer.
     */
    template<typename T>
    class com_ptr_t {
    public:
      com_ptr_t() = default;
      com_ptr_t(const com_ptr_t &) = delete;
      com_ptr_t &operator=(const com_ptr_t &) = delete;

      ~com_ptr_t() {
        reset();
      }

      /**
       * @brief Release the interface.
       */
      void reset() {
        if (ptr_) {
          ptr_->Release();
          ptr_ = nullptr;
        }
      }

      /**
       * @brief Address for out-parameters (releases the current interface).
       */
      T **put() {
        reset();
        return &ptr_;
      }

      /**
       * @brief Access the interface.
       */
      T *operator->() const {
        return ptr_;
      }

      /**
       * @brief Raw interface pointer.
       */
      T *get() const {
        return ptr_;
      }

      /**
       * @brief Whether an interface is held.
       */
      explicit operator bool() const {
        return ptr_ != nullptr;
      }

    private:
      T *ptr_ = nullptr;
    };

    /**
     * @brief Encode a BGRA image as PNG with WIC.
     *
     * @return PNG bytes, or nullopt on failure.
     */
    std::optional<std::vector<std::uint8_t>> encode_png(IWICImagingFactory *factory, const util::bgra_image_t &image) {
      if (!factory || image.width == 0 || image.height == 0) {
        return std::nullopt;
      }
      com_ptr_t<IStream> stream;
      if (FAILED(CreateStreamOnHGlobal(nullptr, TRUE, stream.put()))) {
        return std::nullopt;
      }
      com_ptr_t<IWICBitmapEncoder> encoder;
      if (FAILED(factory->CreateEncoder(container_png, nullptr, encoder.put())) || FAILED(encoder->Initialize(stream.get(), WICBitmapEncoderNoCache))) {
        return std::nullopt;
      }
      com_ptr_t<IWICBitmapFrameEncode> frame;
      if (FAILED(encoder->CreateNewFrame(frame.put(), nullptr)) || FAILED(frame->Initialize(nullptr)) || FAILED(frame->SetSize(image.width, image.height))) {
        return std::nullopt;
      }
      WICPixelFormatGUID format = format_bgra32;
      if (FAILED(frame->SetPixelFormat(&format)) || !IsEqualGUID(format, format_bgra32)) {
        return std::nullopt;
      }
      const UINT stride = image.width * 4;
      if (FAILED(frame->WritePixels(image.height, stride, static_cast<UINT>(image.pixels.size()), const_cast<BYTE *>(image.pixels.data()))) || FAILED(frame->Commit()) || FAILED(encoder->Commit())) {
        return std::nullopt;
      }
      STATSTG stat {};
      if (FAILED(stream->Stat(&stat, STATFLAG_NONAME)) || stat.cbSize.QuadPart > 0x7FFFFFFF) {
        return std::nullopt;
      }
      std::vector<std::uint8_t> png(static_cast<std::size_t>(stat.cbSize.QuadPart));
      LARGE_INTEGER zero {};
      ULONG read = 0;
      if (FAILED(stream->Seek(zero, STREAM_SEEK_SET, nullptr)) || FAILED(stream->Read(png.data(), static_cast<ULONG>(png.size()), &read)) || read != png.size()) {
        return std::nullopt;
      }
      return png;
    }

    /**
     * @brief Decode PNG bytes to BGRA with WIC after the header sanity check.
     *
     * @return Decoded image, or nullopt on failure.
     */
    std::optional<util::bgra_image_t> decode_png(IWICImagingFactory *factory, std::span<const std::uint8_t> png) {
      if (!factory || !util::png_header_sane(png) || png.size() > 0xFFFFFFFF) {
        return std::nullopt;
      }
      com_ptr_t<IWICStream> stream;
      if (FAILED(factory->CreateStream(stream.put())) || FAILED(stream->InitializeFromMemory(const_cast<BYTE *>(png.data()), static_cast<DWORD>(png.size())))) {
        return std::nullopt;
      }
      com_ptr_t<IWICBitmapDecoder> decoder;
      if (FAILED(factory->CreateDecoderFromStream(stream.get(), nullptr, WICDecodeMetadataCacheOnDemand, decoder.put()))) {
        return std::nullopt;
      }
      com_ptr_t<IWICBitmapFrameDecode> frame;
      if (FAILED(decoder->GetFrame(0, frame.put()))) {
        return std::nullopt;
      }
      com_ptr_t<IWICFormatConverter> converter;
      if (FAILED(factory->CreateFormatConverter(converter.put())) || FAILED(converter->Initialize(frame.get(), format_bgra32, WICBitmapDitherTypeNone, nullptr, 0.0, WICBitmapPaletteTypeCustom))) {
        return std::nullopt;
      }
      UINT width = 0;
      UINT height = 0;
      if (FAILED(converter->GetSize(&width, &height)) || width == 0 || height == 0 || std::uint64_t {width} * height * 4 > util::max_decoded_image_bytes) {
        return std::nullopt;
      }
      util::bgra_image_t image;
      image.width = width;
      image.height = height;
      image.pixels.resize(static_cast<std::size_t>(width) * height * 4);
      if (FAILED(converter->CopyPixels(nullptr, width * 4, static_cast<UINT>(image.pixels.size()), image.pixels.data()))) {
        return std::nullopt;
      }
      return image;
    }

    /**
     * @brief Copy bytes into a movable global memory block for SetClipboardData.
     *
     * @return Handle, or nullptr on failure.
     */
    HGLOBAL make_global(const void *data, std::size_t size) {
      HGLOBAL handle = GlobalAlloc(GMEM_MOVEABLE, size == 0 ? 1 : size);
      if (!handle) {
        return nullptr;
      }
      void *dst = GlobalLock(handle);
      if (!dst) {
        GlobalFree(handle);
        return nullptr;
      }
      if (size > 0) {
        std::memcpy(dst, data, size);
      }
      GlobalUnlock(handle);
      return handle;
    }

    /**
     * @brief Copy a clipboard memory block.
     *
     * @param format Clipboard format; must be available and HGLOBAL-based.
     * @param max_size Larger blocks are not copied.
     * @return Bytes, or nullopt when missing, unreadable or too large.
     */
    std::optional<std::vector<std::uint8_t>> copy_clipboard_block(UINT format, std::size_t max_size) {
      HANDLE handle = GetClipboardData(format);
      if (!handle) {
        return std::nullopt;
      }
      const SIZE_T size = GlobalSize(handle);
      if (size == 0 || size > max_size) {
        return std::nullopt;
      }
      const auto *src = static_cast<const std::uint8_t *>(GlobalLock(handle));
      if (!src) {
        return std::nullopt;
      }
      std::vector<std::uint8_t> bytes(src, src + size);
      GlobalUnlock(handle);
      return bytes;
    }

    /**
     * @brief Opens the clipboard for a window with retries and closes it on destruction.
     */
    class clipboard_lock_t {
    public:
      /**
       * @brief Try OpenClipboard until it succeeds or the deadline passes (backoff 2 ms .. 64 ms).
       */
      clipboard_lock_t(HWND hwnd, steady::time_point deadline) {
        auto delay = 2ms;
        while (!(open_ = OpenClipboard(hwnd) != FALSE)) {
          if (steady::now() + delay > deadline) {
            break;
          }
          std::this_thread::sleep_for(delay);
          delay = std::min(delay * 2, 64ms);
        }
      }

      clipboard_lock_t(const clipboard_lock_t &) = delete;
      clipboard_lock_t &operator=(const clipboard_lock_t &) = delete;

      ~clipboard_lock_t() {
        close();
      }

      /**
       * @brief Close the clipboard early.
       */
      void close() {
        if (open_) {
          CloseClipboard();
          open_ = false;
        }
      }

      /**
       * @brief Whether the clipboard is open.
       */
      explicit operator bool() const {
        return open_;
      }

    private:
      bool open_ = false;
    };

    /**
     * @brief Work posted to the window thread; `cancel` runs instead of `run` during shutdown.
     */
    struct task_t {
      std::function<void()> run;  ///< Work for the window thread.
      std::function<void()> cancel;  ///< Completes the caller's wait when the task cannot run.
    };

    /**
     * @brief The Win32 clipboard backend.
     */
    class win32_backend_t final: public backend_t {
    public:
      ~win32_backend_t() override {
        stop();
      }

      int start(std::function<void()> on_change) override {
        std::lock_guard lifecycle(lifecycle_mutex_);
        stop_locked();
        notifier_.start(std::move(on_change));
        std::promise<bool> ready;
        auto started = ready.get_future();
        thread_ = std::thread(&win32_backend_t::run, this, std::move(ready));
        if (!started.get()) {
          thread_.join();
          notifier_.stop();
          return -1;
        }
        return 0;
      }

      void stop() override {
        std::lock_guard lifecycle(lifecycle_mutex_);
        stop_locked();
      }

      std::optional<item_t> read(const limits_t &limits, std::chrono::milliseconds timeout) override {
        const auto deadline = steady::now() + timeout;
        auto result = std::make_shared<std::promise<std::optional<item_t>>>();
        auto future = result->get_future();
        const auto inner = deadline - std::min<steady::duration>(timeout / 10, 50ms);
        if (!post({[this, result, limits, inner]() {
                     result->set_value(read_on_thread(limits, inner));
                   },
                   [result]() {
                     result->set_value(std::nullopt);
                   }})) {
          return std::nullopt;
        }
        if (future.wait_until(deadline) != std::future_status::ready) {
          return std::nullopt;
        }
        return future.get();
      }

      int write(const item_t &item) override {
        auto result = std::make_shared<std::promise<int>>();
        auto future = result->get_future();
        if (!post({[this, result, item]() {
                     result->set_value(write_on_thread(item));
                   },
                   [result]() {
                     result->set_value(-1);
                   }})) {
          return -1;
        }
        if (future.wait_for(write_wait) != std::future_status::ready) {
          return -1;
        }
        return future.get();
      }

      [[nodiscard]] std::string_view name() const override {
        return "win32"sv;
      }

    private:
      /**
       * @brief Window procedure: clipboard notifications and task wake-ups.
       */
      static LRESULT CALLBACK window_proc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam) {
        if (message == WM_NCCREATE) {
          const auto *create = reinterpret_cast<const CREATESTRUCTW *>(lparam);
          SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(create->lpCreateParams));
        }
        auto *self = reinterpret_cast<win32_backend_t *>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        if (self) {
          switch (message) {
            case WM_CLIPBOARDUPDATE:
              if (GetClipboardOwner() != hwnd) {
                self->notifier_.notify();
              }
              return 0;
            case wm_task:
              self->run_tasks();
              return 0;
            case wm_quit:
              RemoveClipboardFormatListener(hwnd);
              DestroyWindow(hwnd);
              return 0;
            case WM_DESTROY:
              PostQuitMessage(0);
              return 0;
            default:
              break;
          }
        }
        return DefWindowProcW(hwnd, message, wparam, lparam);
      }

      /**
       * @brief Window thread body.
       */
      void run(std::promise<bool> ready) {
        const HRESULT com = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        if (SUCCEEDED(com)) {
          CoCreateInstance(clsid_wic_factory, nullptr, CLSCTX_INPROC_SERVER, iid_wic_factory, reinterpret_cast<void **>(wic_.put()));
        }
        if (!wic_) {
          BOOST_LOG(warning) << "[clipboard/win32] WIC is unavailable; images cannot be converted"sv;
        }

        const HINSTANCE instance = GetModuleHandleW(nullptr);
        WNDCLASSEXW cls {};
        cls.cbSize = sizeof(cls);
        cls.lpfnWndProc = window_proc;
        cls.hInstance = instance;
        cls.lpszClassName = window_class;
        if (!RegisterClassExW(&cls) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
          BOOST_LOG(error) << "[clipboard/win32] RegisterClassExW failed: "sv << GetLastError();
        }
        const HWND hwnd = CreateWindowExW(0, window_class, L"", 0, 0, 0, 0, 0, HWND_MESSAGE, nullptr, instance, this);
        if (!hwnd || !AddClipboardFormatListener(hwnd)) {
          BOOST_LOG(error) << "[clipboard/win32] Cannot create the clipboard listener window: "sv << GetLastError();
          if (hwnd) {
            DestroyWindow(hwnd);
          }
          wic_.reset();
          if (SUCCEEDED(com)) {
            CoUninitialize();
          }
          ready.set_value(false);
          return;
        }
        png_format_ = RegisterClipboardFormatW(L"PNG");
        mime_png_format_ = RegisterClipboardFormatW(L"image/png");
        {
          std::lock_guard lock(mutex_);
          hwnd_ = hwnd;
          accepting_ = true;
        }
        ready.set_value(true);
        BOOST_LOG(info) << "[clipboard/win32] Watching the clipboard"sv;

        MSG msg;
        while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
          TranslateMessage(&msg);
          DispatchMessageW(&msg);
        }

        std::deque<task_t> leftover;
        {
          std::lock_guard lock(mutex_);
          accepting_ = false;
          hwnd_ = nullptr;
          leftover.swap(tasks_);
        }
        for (auto &task : leftover) {
          task.cancel();
        }
        wic_.reset();
        if (SUCCEEDED(com)) {
          CoUninitialize();
        }
      }

      /**
       * @brief Queue work for the window thread.
       *
       * @return False when the backend is not running.
       */
      bool post(task_t task) {
        std::lock_guard lock(mutex_);
        if (!accepting_ || !hwnd_) {
          return false;
        }
        tasks_.push_back(std::move(task));
        PostMessageW(hwnd_, wm_task, 0, 0);
        return true;
      }

      /**
       * @brief Run queued tasks on the window thread.
       */
      void run_tasks() {
        std::deque<task_t> tasks;
        {
          std::lock_guard lock(mutex_);
          tasks.swap(tasks_);
        }
        for (auto &task : tasks) {
          task.run();
        }
      }

      /**
       * @brief Stop the window thread; caller holds lifecycle_mutex_.
       */
      void stop_locked() {
        HWND hwnd;
        {
          std::lock_guard lock(mutex_);
          accepting_ = false;
          hwnd = hwnd_;
        }
        if (thread_.joinable()) {
          if (hwnd) {
            PostMessageW(hwnd, wm_quit, 0, 0);
          }
          thread_.join();
        }
        notifier_.stop();
      }

      /**
       * @brief Read the clipboard on the window thread.
       */
      std::optional<item_t> read_on_thread(const limits_t &limits, steady::time_point deadline) {
        item_t out;
        std::optional<std::vector<std::uint8_t>> dib;
        {
          clipboard_lock_t lock(hwnd_, deadline);
          if (!lock) {
            BOOST_LOG(debug) << "[clipboard/win32] The clipboard stayed locked by another application"sv;
            return std::nullopt;
          }
          if (IsClipboardFormatAvailable(CF_UNICODETEXT)) {
            // Each UTF-16 unit becomes at least one UTF-8 byte; CRLF pairs shrink by one byte
            if (auto block = copy_clipboard_block(CF_UNICODETEXT, (limits.text_max * 2 + 1) * sizeof(char16_t))) {
              const std::size_t units = block->size() / sizeof(char16_t);
              std::u16string utf16(units, u'\0');
              std::memcpy(utf16.data(), block->data(), units * sizeof(char16_t));
              utf16.resize(std::char_traits<char16_t>::length(utf16.c_str()));
              auto text = util::sanitize_text(util::crlf_to_lf(util::utf16_to_utf8(utf16)));
              if (text && text->size() <= limits.text_max) {
                out.text = std::move(text);
              }
            }
          }

          for (const UINT format : {png_format_, mime_png_format_}) {
            if (format == 0 || out.png || !IsClipboardFormatAvailable(format)) {
              continue;
            }
            // Clipboard blocks may carry padding after IEND; cap generously and trim below
            if (auto block = copy_clipboard_block(format, limits.image_max + 4096)) {
              const std::size_t length = util::png_stream_length(*block);
              if (length > 0 && length <= limits.image_max) {
                block->resize(length);
                out.png = std::move(block);
              }
            }
          }
          if (!out.png) {
            for (const UINT format : {UINT {CF_DIBV5}, UINT {CF_DIB}}) {
              if (IsClipboardFormatAvailable(format)) {
                dib = copy_clipboard_block(format, util::max_decoded_image_bytes + 4096);
                if (dib) {
                  break;
                }
              }
            }
          }
        }

        // Convert after closing the clipboard so other applications are not blocked meanwhile
        if (dib) {
          if (const auto image = util::dib_to_bgra(*dib)) {
            if (auto png = encode_png(wic_.get(), *image); png && png->size() <= limits.image_max) {
              out.png = std::move(png);
            }
          }
        }
        return out.empty() ? std::nullopt : std::optional {std::move(out)};
      }

      /**
       * @brief Replace the clipboard content on the window thread.
       *
       * @return 0 on success, -1 on failure.
       */
      int write_on_thread(const item_t &item) {
        struct block_t {
          UINT format;  ///< Clipboard format.
          HGLOBAL handle;  ///< Data handed to SetClipboardData.
        };

        std::vector<block_t> blocks;
        if (item.text) {
          const auto utf16 = util::utf8_to_utf16(util::lf_to_crlf(*item.text));
          blocks.push_back({CF_UNICODETEXT, make_global(utf16.c_str(), (utf16.size() + 1) * sizeof(char16_t))});
        }
        if (item.png) {
          if (png_format_) {
            blocks.push_back({png_format_, make_global(item.png->data(), item.png->size())});
          }
          if (const auto image = decode_png(wic_.get(), *item.png)) {
            const auto dib = util::bgra_to_dib(*image);
            if (!dib.empty()) {
              blocks.push_back({CF_DIB, make_global(dib.data(), dib.size())});
            }
          } else {
            BOOST_LOG(warning) << "[clipboard/win32] Could not decode the PNG; offering it without CF_DIB"sv;
          }
        }

        clipboard_lock_t lock(hwnd_, steady::now() + open_wait);
        if (!lock || !EmptyClipboard()) {
          for (const auto &block : blocks) {
            if (block.handle) {
              GlobalFree(block.handle);
            }
          }
          BOOST_LOG(warning) << "[clipboard/win32] Could not open the clipboard for writing"sv;
          return -1;
        }
        bool ok = true;
        for (const auto &block : blocks) {
          if (!block.handle || !SetClipboardData(block.format, block.handle)) {
            ok = false;
            if (block.handle) {
              GlobalFree(block.handle);  // ownership stays with us when SetClipboardData fails
            }
          }
        }
        return ok ? 0 : -1;
      }

      std::mutex lifecycle_mutex_;  ///< Serializes start() and stop().
      std::mutex mutex_;  ///< Guards tasks_, accepting_ and hwnd_ for posting.
      std::deque<task_t> tasks_;
      bool accepting_ = false;
      HWND hwnd_ = nullptr;
      std::thread thread_;
      util::change_notifier_t notifier_;

      // Window thread state
      com_ptr_t<IWICImagingFactory> wic_;
      UINT png_format_ = 0;
      UINT mime_png_format_ = 0;
    };
  }  // namespace
}  // namespace sds::clipboard::win32

namespace sds::clipboard {
  std::unique_ptr<backend_t> make_backend() {
    return std::make_unique<win32::win32_backend_t>();
  }
}  // namespace sds::clipboard
