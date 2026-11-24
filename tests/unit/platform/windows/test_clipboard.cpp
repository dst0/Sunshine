/**
 * @file tests/unit/platform/windows/test_clipboard.cpp
 * @brief Tests for the Win32 clipboard backend (they use the real clipboard of the test session).
 */
// test includes
#include "../../../tests_common.h"

#ifdef _WIN32
  // standard includes
  #include <array>
  #include <chrono>
  #include <condition_variable>
  #include <cstring>
  #include <mutex>
  #include <string>
  #include <thread>
  #include <vector>

  // platform includes
  #include <windows.h>

  // local includes
  #include "src/sds/clipboard_backend.h"
  #include "src/sds/clipboard_backend_util.h"

using namespace std::literals;
using sds::clipboard::item_t;
using sds::clipboard::limits_t;

namespace {
  constexpr limits_t big_limits {1024 * 1024, 16 * 1024 * 1024};

  /**
   * @brief A valid 2x1 RGBA PNG: opaque red, then blue at alpha 128.
   */
  const std::vector<std::uint8_t> two_pixel_png {
    0x89,
    0x50,
    0x4E,
    0x47,
    0x0D,
    0x0A,
    0x1A,
    0x0A,
    0x00,
    0x00,
    0x00,
    0x0D,
    0x49,
    0x48,
    0x44,
    0x52,
    0x00,
    0x00,
    0x00,
    0x02,
    0x00,
    0x00,
    0x00,
    0x01,
    0x08,
    0x06,
    0x00,
    0x00,
    0x00,
    0xF4,
    0x22,
    0x7F,
    0x8A,
    0x00,
    0x00,
    0x00,
    0x0E,
    0x49,
    0x44,
    0x41,
    0x54,
    0x78,
    0x9C,
    0x63,
    0xF8,
    0xCF,
    0xC0,
    0x00,
    0x42,
    0x0D,
    0x00,
    0x0F,
    0x7A,
    0x03,
    0x7E,
    0x77,
    0xE9,
    0x7F,
    0x97,
    0x00,
    0x00,
    0x00,
    0x00,
    0x49,
    0x45,
    0x4E,
    0x44,
    0xAE,
    0x42,
    0x60,
    0x82
  };

  /**
   * @brief Open the clipboard from the test thread, retrying briefly.
   *
   * @param owner Window that becomes the owner on EmptyClipboard (SetClipboardData needs one).
   */
  bool open_clipboard(HWND owner = nullptr) {
    for (int i = 0; i < 100; ++i) {
      if (OpenClipboard(owner)) {
        return true;
      }
      std::this_thread::sleep_for(10ms);
    }
    return false;
  }

  /**
   * @brief Put data on the clipboard as "another application" owning it through `owner`.
   */
  bool set_foreign(HWND owner, UINT format, const void *data, std::size_t size) {
    if (!open_clipboard(owner)) {
      return false;
    }
    EmptyClipboard();
    HGLOBAL handle = GlobalAlloc(GMEM_MOVEABLE, size);
    std::memcpy(GlobalLock(handle), data, size);
    GlobalUnlock(handle);
    const bool ok = SetClipboardData(format, handle) != nullptr;
    CloseClipboard();
    return ok;
  }

  /**
   * @brief Read a clipboard format as bytes from the test thread.
   */
  std::vector<std::uint8_t> get_clipboard(UINT format) {
    std::vector<std::uint8_t> bytes;
    if (!open_clipboard()) {
      return bytes;
    }
    if (HANDLE handle = GetClipboardData(format)) {
      const auto *src = static_cast<const std::uint8_t *>(GlobalLock(handle));
      bytes.assign(src, src + GlobalSize(handle));
      GlobalUnlock(handle);
    }
    CloseClipboard();
    return bytes;
  }

  /**
   * @brief Each test runs with a started Win32 backend.
   */
  class Win32ClipboardTest: public BaseTest {
  protected:
    void SetUp() override {
      BaseTest::SetUp();
      // The "other application": a message-only window owned by the test thread
      foreign_ = CreateWindowExW(0, L"STATIC", L"", 0, 0, 0, 0, 0, HWND_MESSAGE, nullptr, GetModuleHandleW(nullptr), nullptr);
      ASSERT_NE(foreign_, nullptr);
      backend_ = sds::clipboard::make_backend();
      ASSERT_TRUE(backend_);
      ASSERT_EQ(backend_->start([this]() {
        std::lock_guard lock(mutex_);
        ++changes_;
        cv_.notify_all();
      }),
                0);
      EXPECT_EQ(backend_->name(), "win32");
    }

    void TearDown() override {
      if (backend_) {
        backend_->stop();
      }
      if (foreign_) {
        DestroyWindow(foreign_);
      }
      BaseTest::TearDown();
    }

    /**
     * @brief Put data on the clipboard as the other application.
     */
    bool set_foreign(UINT format, const void *data, std::size_t size) {
      return ::set_foreign(foreign_, format, data, size);
    }

    /**
     * @brief Wait until at least `count` change notifications arrived.
     */
    bool wait_changes(int count, std::chrono::milliseconds timeout = 3s) {
      std::unique_lock lock(mutex_);
      return cv_.wait_for(lock, timeout, [&]() {
        return changes_ >= count;
      });
    }

    /**
     * @brief Number of change notifications so far.
     */
    int changes() {
      std::lock_guard lock(mutex_);
      return changes_;
    }

    HWND foreign_ = nullptr;
    std::unique_ptr<sds::clipboard::backend_t> backend_;
    std::mutex mutex_;
    std::condition_variable cv_;
    int changes_ = 0;
  };
}  // namespace

TEST_F(Win32ClipboardTest, WritesTextWithCrlf) {
  ASSERT_EQ(backend_->write({.text = "caf\xC3\xA9\nline \xF0\x9F\x8E\x89", .png = std::nullopt}), 0);
  const auto bytes = get_clipboard(CF_UNICODETEXT);
  ASSERT_GE(bytes.size(), 2u);
  const std::u16string text(reinterpret_cast<const char16_t *>(bytes.data()));
  EXPECT_EQ(text, u"café\r\nline \U0001F389");
  EXPECT_NE(GetClipboardOwner(), nullptr);
}

TEST_F(Win32ClipboardTest, ReadsForeignTextAndNotifies) {
  const std::u16string text = u"x\r\ny ✓";
  ASSERT_TRUE(set_foreign(CF_UNICODETEXT, text.c_str(), (text.size() + 1) * sizeof(char16_t)));
  ASSERT_TRUE(wait_changes(1));
  const auto item = backend_->read(big_limits, 2s);
  ASSERT_TRUE(item);
  EXPECT_EQ(item->text, "x\ny \xE2\x9C\x93");
}

TEST_F(Win32ClipboardTest, DoesNotNotifyForItsOwnWrites) {
  ASSERT_EQ(backend_->write({.text = "ours", .png = std::nullopt}), 0);
  std::this_thread::sleep_for(300ms);
  EXPECT_EQ(changes(), 0);
  const auto item = backend_->read(big_limits, 2s);
  ASSERT_TRUE(item);
  EXPECT_EQ(item->text, "ours");
}

TEST_F(Win32ClipboardTest, DropsOversizedText) {
  const std::u16string text(5000, u'a');
  ASSERT_TRUE(set_foreign(CF_UNICODETEXT, text.c_str(), (text.size() + 1) * sizeof(char16_t)));
  EXPECT_FALSE(backend_->read({1000, 1000}, 2s));
}

TEST_F(Win32ClipboardTest, WritesPngAndDib) {
  ASSERT_EQ(backend_->write({.text = std::nullopt, .png = two_pixel_png}), 0);
  const auto png = get_clipboard(RegisterClipboardFormatW(L"PNG"));
  ASSERT_GE(png.size(), two_pixel_png.size());
  EXPECT_TRUE(std::equal(two_pixel_png.begin(), two_pixel_png.end(), png.begin()));

  const auto dib = get_clipboard(CF_DIB);
  const auto image = sds::clipboard::util::dib_to_bgra(dib);
  ASSERT_TRUE(image);
  EXPECT_EQ(image->width, 2u);
  EXPECT_EQ(image->height, 1u);
  EXPECT_EQ(image->pixels[2], 0xFF);  // red
  EXPECT_EQ(image->pixels[3], 0xFF);  // opaque
  EXPECT_EQ(image->pixels[4], 0xFF);  // blue
  EXPECT_EQ(image->pixels[7], 128);  // half transparent

  const auto item = backend_->read(big_limits, 2s);
  ASSERT_TRUE(item);
  EXPECT_EQ(item->png, two_pixel_png);
}

TEST_F(Win32ClipboardTest, ReadsDibAsPng) {
  sds::clipboard::util::bgra_image_t image;
  image.width = 3;
  image.height = 2;
  image.pixels.assign(3 * 2 * 4, 0x80);
  const auto dib = sds::clipboard::util::bgra_to_dib(image);
  ASSERT_TRUE(set_foreign(CF_DIB, dib.data(), dib.size()));
  const auto item = backend_->read(big_limits, 2s);
  ASSERT_TRUE(item);
  ASSERT_TRUE(item->png);
  const auto dims = sds::clipboard::util::png_dimensions(*item->png);
  ASSERT_TRUE(dims);
  EXPECT_EQ(dims->width, 3u);
  EXPECT_EQ(dims->height, 2u);
}

TEST_F(Win32ClipboardTest, ReadsForeignPngFormat) {
  std::vector<std::uint8_t> padded = two_pixel_png;
  padded.resize(padded.size() + 32, 0);  // padding after IEND is trimmed
  ASSERT_TRUE(set_foreign(RegisterClipboardFormatW(L"PNG"), padded.data(), padded.size()));
  const auto item = backend_->read(big_limits, 2s);
  ASSERT_TRUE(item);
  EXPECT_EQ(item->png, two_pixel_png);
}

TEST_F(Win32ClipboardTest, StopIsIdempotentAndDisablesIo) {
  backend_->stop();
  backend_->stop();
  EXPECT_FALSE(backend_->read(big_limits, 100ms));
  EXPECT_EQ(backend_->write({.text = "x", .png = std::nullopt}), -1);
  ASSERT_EQ(backend_->start([]() {
  }),
            0);
  EXPECT_EQ(backend_->write({.text = "again", .png = std::nullopt}), 0);
}
#endif
