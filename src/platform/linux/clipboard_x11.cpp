/**
 * @file src/platform/linux/clipboard_x11.cpp
 * @brief X11 CLIPBOARD backend for the shared clipboard.
 *
 * The backend opens its own connection to $DISPLAY and confines every Xlib call to one event
 * thread. Callers talk to that thread through a task queue and a wake-up pipe; the thread
 * sleeps in poll() on the X connection and the pipe, so it never busy-loops.
 *
 * - Change detection: XFixes selection-owner notifications on CLIPBOARD; notifications whose
 *   owner is our own window are ignored.
 * - Reading: TARGETS first, then UTF8_STRING / text/plain;charset=utf-8 / STRING and
 *   image/png, including INCR transfers from other clients, with per-representation size caps
 *   and an overall deadline.
 * - Serving: TARGETS, TIMESTAMP, MULTIPLE, UTF8_STRING, text/plain;charset=utf-8, STRING
 *   (lossy Latin-1) and image/png; data larger than the server's maximum request size goes out
 *   via INCR. Requestors that stop deleting the property or disappear are dropped after a
 *   timeout or on DestroyNotify.
 *
 * libX11 and libXfixes are linked directly (see cmake/compile_definitions/linux.cmake).
 */
// standard includes
#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <condition_variable>
#include <csignal>
#include <cstring>
#include <deque>
#include <future>
#include <map>
#include <mutex>
#include <thread>

// platform includes
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <unistd.h>
#include <X11/extensions/Xfixes.h>
#include <X11/Xatom.h>
#include <X11/Xlib.h>

// local includes
#include "clipboard_linux.h"
#include "src/logging.h"
#include "src/sds/clipboard_backend_util.h"
#include "src/sds/file_clipboard.h"

using namespace std::literals;

namespace sds::clipboard::x11 {
  namespace {
    using steady = std::chrono::steady_clock;

    constexpr std::size_t property_pool_size = 8;
    constexpr std::size_t max_outgoing_transfers = 8;
    constexpr std::size_t default_incr_chunk = 256 * 1024;
    constexpr auto write_wait = 3s;
    constexpr auto server_time_wait = 1s;
    constexpr int open_attempts = 3;
    constexpr auto open_retry_delay = 25ms;

    std::mutex error_mutex;
    std::map<Display *, int> error_counts;  ///< Displays owned by clipboard backends and their swallowed error count.
    XErrorHandler previous_error_handler = nullptr;
    std::once_flag error_handler_once;

    /**
     * @brief Swallow protocol errors on our displays (a requestor window that vanished is
     *        expected) and forward all others to the previously installed handler.
     */
    int error_handler(Display *dpy, XErrorEvent *event) {
      XErrorHandler previous;
      {
        std::lock_guard lock(error_mutex);
        if (const auto it = error_counts.find(dpy); it != error_counts.end()) {
          ++it->second;
          return 0;
        }
        previous = previous_error_handler;
      }
      return previous ? previous(dpy, event) : 0;
    }

    /**
     * @brief Route protocol errors of `dpy` to error_handler().
     */
    void register_display(Display *dpy) {
      std::call_once(error_handler_once, []() {
        // Installed once and never removed: it forwards everything that is not ours
        const XErrorHandler previous = XSetErrorHandler(error_handler);
        std::lock_guard lock(error_mutex);
        previous_error_handler = previous;
      });
      std::lock_guard lock(error_mutex);
      error_counts[dpy] = 0;
    }

    /**
     * @brief Stop treating `dpy` as ours.
     */
    void unregister_display(Display *dpy) {
      std::lock_guard lock(error_mutex);
      error_counts.erase(dpy);
    }

    /**
     * @brief Atoms used by the backend.
     */
    struct atoms_t {
      Atom clipboard;  ///< CLIPBOARD selection.
      Atom targets;  ///< TARGETS.
      Atom timestamp;  ///< TIMESTAMP.
      Atom multiple;  ///< MULTIPLE.
      Atom atom_pair;  ///< ATOM_PAIR.
      Atom incr;  ///< INCR.
      Atom utf8_string;  ///< UTF8_STRING.
      Atom text_utf8;  ///< text/plain;charset=utf-8.
      Atom text_utf8_upper;  ///< text/plain;charset=UTF-8 (spelling used by some toolkits).
      Atom image_png;  ///< image/png.
      Atom file_offer;  ///< x-special/gnome-copied-files.
      Atom time_property;  ///< Property used to obtain a server timestamp.
      std::array<Atom, property_pool_size> properties;  ///< Properties that receive converted selections.
    };

    /**
     * @brief Clipboard content we own, with the lossy Latin-1 form precomputed for STRING.
     */
    struct owned_t {
      item_t item;  ///< Content offered to other clients.
      std::string latin1;  ///< item.text converted to Latin-1.
    };

    /**
     * @brief Result slot shared between a caller of read() and the event thread.
     */
    struct read_state_t {
      std::mutex mutex;  ///< Guards the fields below.
      std::condition_variable cv;  ///< Signalled when done.
      bool done = false;  ///< Result available.
      std::optional<item_t> result;  ///< Read content.
    };

    /**
     * @brief A read in progress on the event thread.
     */
    struct read_op_t {
      /**
       * @brief Conversion currently requested from the owner.
       */
      enum class stage_e {
        targets,  ///< TARGETS.
        text,  ///< The chosen text target.
        image,  ///< image/png.
        files,  ///< x-special/gnome-copied-files.
      };

      std::shared_ptr<read_state_t> state;  ///< Caller's result slot.
      limits_t limits {};  ///< Size limits.
      steady::time_point deadline;  ///< When the read is finished with whatever is complete.
      bool active = false;  ///< A conversion has been requested.
      stage_e stage = stage_e::targets;  ///< Current conversion.
      Atom target = None;  ///< Target of the current conversion.
      Atom property = None;  ///< Property receiving the current conversion.
      bool incr = false;  ///< The current conversion arrives via INCR.
      std::size_t cap = 0;  ///< Byte cap for the current conversion.
      std::vector<std::uint8_t> buffer;  ///< INCR data received so far.
      Atom text_target = None;  ///< Text target chosen from TARGETS.
      Atom file_target = None;
      Atom image_target = None;  ///< Image target chosen from TARGETS.
      item_t out;  ///< Completed representations.
    };

    /**
     * @brief An INCR transfer we are sending to another client.
     */
    struct outgoing_t {
      Window requestor;  ///< Receiving window.
      Atom property;  ///< Property on the requestor.
      Atom type;  ///< Type of each chunk.
      std::shared_ptr<const owned_t> keepalive;  ///< Keeps `data` valid after the selection changes.
      std::span<const std::uint8_t> data;  ///< Bytes to send.
      std::size_t offset = 0;  ///< Bytes sent so far.
      steady::time_point deadline;  ///< Dropped when the requestor makes no progress until then.
    };

    /**
     * @brief A property whose remaining INCR chunks are discarded (aborted or oversized read).
     */
    struct drain_t {
      Atom property;  ///< Our property still receiving chunks.
      steady::time_point deadline;  ///< Freed for reuse at this time even if chunks keep coming.
    };

    /**
     * @brief Work posted to the event thread; `cancel` runs instead of `run` during shutdown.
     */
    struct task_t {
      std::function<void()> run;  ///< Work to do on the event thread.
      std::function<void()> cancel;  ///< Completes the caller's wait when the task cannot run.
    };

    /**
     * @brief Bytes of a property read with XGetWindowProperty.
     */
    struct property_t {
      Atom type = None;  ///< Property type, None when missing.
      int format = 0;  ///< 8, 16 or 32.
      unsigned long items = 0;  ///< Number of items.
      unsigned long bytes_after = 0;  ///< Bytes not returned.
      unsigned char *data = nullptr;  ///< Xlib-allocated data.

      property_t() = default;
      property_t(const property_t &) = delete;
      property_t &operator=(const property_t &) = delete;

      ~property_t() {
        if (data) {
          XFree(data);
        }
      }
    };

    /**
     * @brief Predicate arguments for waiting on a PropertyNotify of our timestamp property.
     */
    struct property_wait_t {
      Window window;  ///< Our window.
      Atom atom;  ///< Property that was appended.
    };

    /**
     * @brief The X11 clipboard backend.
     */
    class x11_backend_t final: public backend_t {
    public:
      /**
       * @brief Create a stopped backend.
       */
      explicit x11_backend_t(const options_t &options):
          options_(options) {}

      ~x11_backend_t() override {
        stop();
      }

      int start(std::function<void()> on_change) override {
        std::lock_guard lifecycle(lifecycle_mutex_);
        stop_locked();

        // Connecting can fail transiently (ECONNRESET/EAGAIN from a busy server); retry briefly
        Display *dpy = nullptr;
        for (int attempt = 0; attempt < open_attempts && !dpy; ++attempt) {
          if (attempt > 0) {
            std::this_thread::sleep_for(open_retry_delay * attempt);
          }
          dpy = XOpenDisplay(nullptr);
        }
        if (!dpy) {
          BOOST_LOG(warning) << "[clipboard/x11] Cannot open the X display"sv;
          return -1;
        }
        register_display(dpy);
        auto fail = [&](std::string_view why) {
          BOOST_LOG(warning) << "[clipboard/x11] "sv << why;
          XCloseDisplay(dpy);
          unregister_display(dpy);
          return -1;
        };

        int error_base = 0;
        if (!XFixesQueryExtension(dpy, &xfixes_event_base_, &error_base)) {
          return fail("The X server lacks the XFixes extension"sv);
        }
        int major = 1;
        int minor = 0;
        if (!XFixesQueryVersion(dpy, &major, &minor) || major < 1) {
          return fail("XFixes 1.0 or newer is required"sv);
        }

        std::array<std::string, property_pool_size> pool_names;
        std::vector<char *> names {
          const_cast<char *>("CLIPBOARD"),
          const_cast<char *>("TARGETS"),
          const_cast<char *>("TIMESTAMP"),
          const_cast<char *>("MULTIPLE"),
          const_cast<char *>("ATOM_PAIR"),
          const_cast<char *>("INCR"),
          const_cast<char *>("UTF8_STRING"),
          const_cast<char *>("text/plain;charset=utf-8"),
          const_cast<char *>("text/plain;charset=UTF-8"),
          const_cast<char *>("image/png"),
          const_cast<char *>("x-special/gnome-copied-files"),
          const_cast<char *>("SDS_CLIPBOARD_TIME"),
        };
        for (std::size_t i = 0; i < pool_names.size(); ++i) {
          pool_names[i] = "SDS_CLIPBOARD_" + std::to_string(i);
          names.push_back(pool_names[i].data());
        }
        std::vector<Atom> atoms(names.size());
        if (!XInternAtoms(dpy, names.data(), static_cast<int>(names.size()), False, atoms.data())) {
          return fail("Cannot intern atoms"sv);
        }
        atoms_ = {atoms[0], atoms[1], atoms[2], atoms[3], atoms[4], atoms[5], atoms[6], atoms[7], atoms[8], atoms[9], atoms[10], atoms[11], {}};
        std::copy(atoms.begin() + 12, atoms.end(), atoms_.properties.begin());

        XSetWindowAttributes attributes {};
        attributes.event_mask = PropertyChangeMask;
        window_ = XCreateWindow(dpy, DefaultRootWindow(dpy), -10, -10, 1, 1, 0, 0, InputOnly, CopyFromParent, CWEventMask, &attributes);
        if (window_ == None) {
          return fail("Cannot create the clipboard window"sv);
        }
        XFixesSelectSelectionInput(dpy, window_, atoms_.clipboard, XFixesSetSelectionOwnerNotifyMask | XFixesSelectionWindowDestroyNotifyMask | XFixesSelectionClientCloseNotifyMask);

        if (options_.incr_chunk > 0) {
          chunk_ = options_.incr_chunk;
        } else {
          // Classic (non-BIG-REQUESTS) limit in bytes, less room for the request header
          const long max_request_bytes = XMaxRequestSize(dpy) * 4;
          chunk_ = std::min<std::size_t>(default_incr_chunk, static_cast<std::size_t>(std::max<long>(max_request_bytes - 256, 4096)));
        }
        XSync(dpy, False);

        if (pipe2(wake_.data(), O_CLOEXEC | O_NONBLOCK) != 0) {
          XDestroyWindow(dpy, window_);
          window_ = None;
          return fail("Cannot create the wake-up pipe"sv);
        }

        dpy_ = dpy;
        owning_ = false;
        owned_.reset();
        quit_ = false;
        dead_ = false;
        notifier_.start(std::move(on_change));
        {
          std::lock_guard lock(mutex_);
          accepting_ = true;
        }
        thread_ = std::thread(&x11_backend_t::run, this);
        BOOST_LOG(info) << "[clipboard/x11] Watching CLIPBOARD on "sv << DisplayString(dpy) << " (INCR above "sv << chunk_ << " bytes)"sv;
        return 0;
      }

      void stop() override {
        std::lock_guard lifecycle(lifecycle_mutex_);
        stop_locked();
      }

      std::optional<item_t> read(const limits_t &limits, std::chrono::milliseconds timeout) override {
        const auto start = steady::now();
        const auto deadline = start + timeout;
        // Finish slightly early on the event thread so partial results reach the caller in time
        const auto margin = std::min<steady::duration>(timeout / 10, 50ms);
        auto state = std::make_shared<read_state_t>();
        const bool posted = post(
          {[this, state, limits, inner = deadline - margin]() {
             auto op = std::make_unique<read_op_t>();
             op->state = state;
             op->limits = limits;
             op->deadline = inner;
             reads_.push_back(std::move(op));
             begin_read();
           },
           [state]() {
             complete(*state, std::nullopt);
           }}
        );
        if (!posted) {
          return std::nullopt;
        }
        std::unique_lock lock(state->mutex);
        if (!state->cv.wait_until(lock, deadline, [&]() {
              return state->done;
            })) {
          return std::nullopt;
        }
        return state->result;
      }

      int write(const item_t &item) override {
        auto result = std::make_shared<std::promise<int>>();
        auto future = result->get_future();
        auto owned = std::make_shared<owned_t>();
        owned->item = item;
        owned->item.file_offer.reset();
        if (item.text) {
          owned->latin1 = util::utf8_to_latin1_lossy(*item.text);
        }
        const bool posted = post(
          {[this, result, owned = std::shared_ptr<const owned_t>(std::move(owned))]() {
             result->set_value(take_ownership(owned));
           },
           [result]() {
             result->set_value(-1);
           }}
        );
        if (!posted || future.wait_for(write_wait) != std::future_status::ready) {
          return -1;
        }
        return future.get();
      }

      [[nodiscard]] bool supports_file_clipboard() const override { return true; }

      std::optional<std::uint64_t> file_clipboard_generation() override {
        return file_transaction([](x11_backend_t &self, file_transaction_t &) { return std::optional {self.generation_}; });
      }

      std::optional<std::uint64_t> publish_file_clipboard(std::uint64_t expected, std::string offer, std::function<bool()> allowed) override {
        if (!offer.starts_with("copy\n") || offer.size() > file_clipboard::offer_max) return {};
        const auto deadline = steady::now() + write_wait;
        auto owned = std::make_shared<owned_t>();
        owned->item.file_offer = std::move(offer);
        return file_transaction([expected, owned = std::move(owned), allowed = std::move(allowed), deadline](x11_backend_t &self, file_transaction_t &transaction) {
          if (self.generation_ != expected || steady::now() >= deadline || !allowed()) return std::optional<std::uint64_t> {};
          const auto time = self.server_time();
          if (time == CurrentTime || !allowed() || !transaction.claim(deadline) || self.take_ownership(owned, time) != 0) {
            return std::optional<std::uint64_t> {};
          }
          return std::optional {self.generation_};
        });
      }

      void retire_file_clipboard(std::uint64_t generation) override {
        file_transaction([generation](x11_backend_t &self, file_transaction_t &) {
          if (self.generation_ == generation && self.owned_ && self.owned_->item.file_offer) {
            self.take_ownership(std::make_shared<owned_t>());
          }
          return std::optional {self.generation_};
        });
      }

      [[nodiscard]] std::string_view name() const override {
        return "x11"sv;
      }

    private:
      // A timed-out caller can cancel uncommitted work. Once XSetSelectionOwner can
      // be issued, wait for the actual result so it cannot succeed after a failed
      // response drops the private staging lease.
      struct file_transaction_t {
        enum class state_e { pending, canceled, committing };
        std::atomic<state_e> state {state_e::pending};

        bool claim(steady::time_point deadline) {
          auto expected = state_e::pending;
          return steady::now() < deadline && state.compare_exchange_strong(expected, state_e::committing);
        }

        bool cancel() {
          auto expected = state_e::pending;
          return state.compare_exchange_strong(expected, state_e::canceled);
        }
      };

      // Drain native generation notifications while the server is grabbed. No other X11
      // connection can change selection ownership between the comparison and publication.
      std::optional<std::uint64_t> file_transaction(std::function<std::optional<std::uint64_t>(x11_backend_t &, file_transaction_t &)> fn) {
        auto transaction = std::make_shared<file_transaction_t>();
        auto result = std::make_shared<std::promise<std::optional<std::uint64_t>>>();
        auto future = result->get_future();
        const auto deadline = steady::now() + write_wait;
        if (!post({[this, result, transaction, fn = std::move(fn), deadline]() {
              if (steady::now() >= deadline) {
                result->set_value(std::nullopt);
                return;
              }
              XGrabServer(dpy_);
              struct ungrab_t {
                Display *display;
                ~ungrab_t() { XUngrabServer(display); XFlush(display); }
              } ungrab {dpy_};
              XSync(dpy_, False);
              XEvent event;
              while (XCheckTypedEvent(dpy_, xfixes_event_base_ + XFixesSelectionNotify, &event)) {
                handle_event(event);
              }
              result->set_value(steady::now() < deadline ? fn(*this, *transaction) : std::nullopt);
            }, [result]() { result->set_value(std::nullopt); }})) {
          return std::nullopt;
        }
        if (future.wait_until(deadline) != std::future_status::ready && transaction->cancel()) {
          return std::nullopt;
        }
        return future.get();
      }

      /**
       * @brief Mark a read finished and wake its caller.
       */
      static void complete(read_state_t &state, std::optional<item_t> result) {
        {
          std::lock_guard lock(state.mutex);
          if (state.done) {
            return;
          }
          state.result = std::move(result);
          state.done = true;
        }
        state.cv.notify_all();
      }

      /**
       * @brief Queue work for the event thread.
       *
       * @return False when the backend is not running (the task is not queued).
       */
      bool post(task_t task) {
        // The wake-up pipe is only written and closed while holding mutex_
        std::lock_guard lock(mutex_);
        if (!accepting_) {
          return false;
        }
        tasks_.push_back(std::move(task));
        wake();
        return true;
      }

      /**
       * @brief Interrupt the event thread's poll().
       */
      void wake() {
        const char byte = 1;
        while (::write(wake_[1], &byte, 1) < 0 && errno == EINTR) {
        }
      }

      /**
       * @brief Stop the event thread and release ownership; caller holds lifecycle_mutex_.
       */
      void stop_locked() {
        std::deque<task_t> leftover;
        {
          std::lock_guard lock(mutex_);
          accepting_ = false;
          leftover.swap(tasks_);
        }
        if (thread_.joinable()) {
          quit_ = true;
          {
            std::lock_guard lock(mutex_);
            wake();
          }
          thread_.join();
        }
        for (auto &task : leftover) {
          task.cancel();
        }
        {
          // Tasks queued between the swap above and the thread's exit
          std::lock_guard lock(mutex_);
          leftover.swap(tasks_);
        }
        for (auto &task : leftover) {
          task.cancel();
        }
        notifier_.stop();
        std::lock_guard lock(mutex_);
        for (auto &fd : wake_) {
          if (fd >= 0) {
            close(fd);
            fd = -1;
          }
        }
      }

      /**
       * @brief Event thread body.
       */
      void run() {
        // Writes to a dead X server must fail with EPIPE instead of killing the process
        sigset_t sigpipe;
        sigemptyset(&sigpipe);
        sigaddset(&sigpipe, SIGPIPE);
        pthread_sigmask(SIG_BLOCK, &sigpipe, nullptr);

        const int xfd = ConnectionNumber(dpy_);
        while (!quit_ && !dead_) {
          run_tasks();
          if (dead_) {
            break;
          }
          while (!quit_ && XPending(dpy_) > 0) {
            XEvent event;
            XNextEvent(dpy_, &event);
            handle_event(event);
          }
          expire(steady::now());
          if (quit_) {
            break;
          }
          // XPending flushes our requests and picks up events that Xlib already read off the
          // socket during flushes and round trips; poll() on the fd would not see those.
          if (XPending(dpy_) > 0) {
            continue;
          }

          std::array<pollfd, 2> fds {{{xfd, POLLIN, 0}, {wake_[0], POLLIN, 0}}};
          if (poll(fds.data(), fds.size(), poll_timeout()) < 0 && errno != EINTR) {
            BOOST_LOG(error) << "[clipboard/x11] poll failed: "sv << std::strerror(errno);
            dead_ = true;
          }
          if (fds[0].revents & (POLLHUP | POLLERR | POLLNVAL)) {
            // Calling Xlib on a closed connection would end the process through its I/O error handler
            BOOST_LOG(warning) << "[clipboard/x11] X server connection lost"sv;
            dead_ = true;
          }
          if (fds[1].revents & POLLIN) {
            std::array<char, 64> sink {};
            while (::read(wake_[0], sink.data(), sink.size()) > 0) {
            }
          }
        }
        shutdown();

        // After a lost connection, fail new requests immediately instead of letting them time out
        std::deque<task_t> leftover;
        {
          std::lock_guard lock(mutex_);
          accepting_ = false;
          leftover.swap(tasks_);
        }
        for (auto &task : leftover) {
          task.cancel();
        }
      }

      /**
       * @brief Run queued tasks on the event thread.
       */
      void run_tasks() {
        std::deque<task_t> tasks;
        {
          std::lock_guard lock(mutex_);
          tasks.swap(tasks_);
        }
        for (auto &task : tasks) {
          if (quit_ || dead_) {
            task.cancel();
          } else {
            task.run();
          }
        }
      }

      /**
       * @brief Release everything owned by the event thread.
       */
      void shutdown() {
        for (auto &op : reads_) {
          complete(*op->state, std::nullopt);
        }
        reads_.clear();
        if (dead_) {
          // The connection is unusable; leak it rather than let Xlib exit the process
          unregister_display(dpy_);
          dpy_ = nullptr;
          return;
        }
        if (owning_ && XGetSelectionOwner(dpy_, atoms_.clipboard) == window_) {
          XSetSelectionOwner(dpy_, atoms_.clipboard, None, own_time_);
        }
        for (const auto &transfer : outgoing_) {
          XSelectInput(dpy_, transfer.requestor, NoEventMask);
        }
        outgoing_.clear();
        draining_.clear();
        owning_ = false;
        owned_.reset();
        XDestroyWindow(dpy_, window_);
        window_ = None;
        XSync(dpy_, False);
        XCloseDisplay(dpy_);
        unregister_display(dpy_);
        dpy_ = nullptr;
      }

      /**
       * @brief Milliseconds until the nearest deadline (-1 for none).
       */
      int poll_timeout() const {
        std::optional<steady::time_point> next;
        auto consider = [&](steady::time_point t) {
          if (!next || t < *next) {
            next = t;
          }
        };
        for (const auto &op : reads_) {
          consider(op->deadline);
        }
        for (const auto &transfer : outgoing_) {
          consider(transfer.deadline);
        }
        for (const auto &drain : draining_) {
          consider(drain.deadline);
        }
        if (!next) {
          return -1;
        }
        const auto ms = std::chrono::ceil<std::chrono::milliseconds>(*next - steady::now()).count();
        return static_cast<int>(std::clamp<long long>(ms, 0, 60'000));
      }

      /**
       * @brief Dispatch one X event.
       */
      void handle_event(XEvent &event) {
        if (event.type == xfixes_event_base_ + XFixesSelectionNotify) {
          const auto &notify = reinterpret_cast<const XFixesSelectionNotifyEvent &>(event);
          if (notify.selection == atoms_.clipboard && notify.owner != window_) {
            ++generation_;
            notifier_.notify();
          }
          return;
        }
        switch (event.type) {
          case SelectionRequest:
            serve(event.xselectionrequest);
            break;
          case SelectionClear:
            if (event.xselectionclear.window == window_ && event.xselectionclear.selection == atoms_.clipboard &&
                XGetSelectionOwner(dpy_, atoms_.clipboard) != window_) {
              owning_ = false;
              owned_.reset();
            }
            break;
          case SelectionNotify:
            on_selection_notify(event.xselection);
            break;
          case PropertyNotify:
            on_property_notify(event.xproperty);
            break;
          case DestroyNotify:
            drop_requestor(event.xdestroywindow.window);
            break;
          default:
            break;
        }
      }

      /**
       * @brief Get a server timestamp by appending zero bytes to our property.
       *
       * @return Server time, or CurrentTime when the server did not answer in time.
       */
      Time server_time() {
        unsigned char nothing = 0;
        XChangeProperty(dpy_, window_, atoms_.time_property, XA_INTEGER, 8, PropModeAppend, &nothing, 0);
        XFlush(dpy_);
        property_wait_t wait {window_, atoms_.time_property};
        auto predicate = [](Display *, XEvent *event, XPointer arg) -> Bool {
          const auto *w = reinterpret_cast<const property_wait_t *>(arg);
          return event->type == PropertyNotify && event->xproperty.window == w->window && event->xproperty.atom == w->atom;
        };
        const auto deadline = steady::now() + server_time_wait;
        const int xfd = ConnectionNumber(dpy_);
        while (true) {
          XEvent event;
          if (XCheckIfEvent(dpy_, &event, predicate, reinterpret_cast<XPointer>(&wait))) {
            return event.xproperty.time;
          }
          const auto remaining = std::chrono::ceil<std::chrono::milliseconds>(deadline - steady::now()).count();
          if (remaining <= 0) {
            return CurrentTime;
          }
          pollfd pfd {xfd, POLLIN, 0};
          if (poll(&pfd, 1, static_cast<int>(remaining)) < 0 && errno != EINTR) {
            return CurrentTime;
          }
          if (pfd.revents & (POLLHUP | POLLERR | POLLNVAL)) {
            dead_ = true;
            return CurrentTime;
          }
        }
      }

      /**
       * @brief Become the CLIPBOARD owner offering `owned` (or give up ownership for an empty item).
       *
       * @return 0 on success, -1 on failure.
       */
      int take_ownership(std::shared_ptr<const owned_t> owned, Time sampled = CurrentTime) {
        if (owned->item.empty()) {
          if (owning_ && XGetSelectionOwner(dpy_, atoms_.clipboard) == window_) {
            XSetSelectionOwner(dpy_, atoms_.clipboard, None, own_time_);
            // Round trip so the release is in effect when write() returns
            XSync(dpy_, False);
          }
          owning_ = false;
          owned_.reset();
          return 0;
        }
        const Time time = sampled == CurrentTime ? server_time() : sampled;
        if (time == CurrentTime) {
          BOOST_LOG(warning) << "[clipboard/x11] Could not get a server timestamp"sv;
          return -1;
        }
        XSetSelectionOwner(dpy_, atoms_.clipboard, window_, time);
        if (XGetSelectionOwner(dpy_, atoms_.clipboard) != window_) {
          BOOST_LOG(warning) << "[clipboard/x11] Could not take CLIPBOARD ownership"sv;
          return -1;
        }
        ++generation_;
        owned_ = std::move(owned);
        own_time_ = time;
        owning_ = true;
        return 0;
      }

      /**
       * @brief Bytes and property type to send for a data target, or nullopt if not offered.
       */
      std::optional<std::pair<std::span<const std::uint8_t>, Atom>> data_for(Atom target) const {
        const auto &item = owned_->item;
        auto bytes = [](const std::string &s) {
          return std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(s.data()), s.size());
        };
        if (item.text) {
          if (target == atoms_.utf8_string || target == atoms_.text_utf8 || target == atoms_.text_utf8_upper) {
            return std::pair {bytes(*item.text), target};
          }
          if (target == XA_STRING) {
            return std::pair {bytes(owned_->latin1), Atom {XA_STRING}};
          }
        }
        if (item.file_offer && target == atoms_.file_offer) {
          return std::pair {bytes(*item.file_offer), target};
        }
        if (item.png && target == atoms_.image_png) {
          return std::pair {std::span<const std::uint8_t>(*item.png), target};
        }
        return std::nullopt;
      }

      /**
       * @brief Convert our selection to `target` on the requestor's `property`.
       *
       * @return True when the conversion was performed (or an INCR transfer was started).
       */
      bool serve_target(Window requestor, Atom target, Atom property) {
        if (target == atoms_.targets) {
          std::vector<Atom> list {atoms_.targets, atoms_.timestamp, atoms_.multiple};
          if (owned_->item.text) {
            list.insert(list.end(), {atoms_.utf8_string, atoms_.text_utf8, Atom {XA_STRING}});
          }
          if (owned_->item.file_offer) {
            list.push_back(atoms_.file_offer);
          }
          if (owned_->item.png) {
            list.push_back(atoms_.image_png);
          }
          XChangeProperty(dpy_, requestor, property, XA_ATOM, 32, PropModeReplace, reinterpret_cast<const unsigned char *>(list.data()), static_cast<int>(list.size()));
          return true;
        }
        if (target == atoms_.timestamp) {
          const long time = static_cast<long>(own_time_);
          XChangeProperty(dpy_, requestor, property, XA_INTEGER, 32, PropModeReplace, reinterpret_cast<const unsigned char *>(&time), 1);
          return true;
        }
        const auto data = data_for(target);
        if (!data) {
          return false;
        }
        const auto [bytes, type] = *data;
        if (bytes.size() > chunk_) {
          // INCR: announce a lower bound of the size, then send chunks as the requestor deletes the property
          const auto existing = std::ranges::find_if(outgoing_, [&](const outgoing_t &t) {
            return t.requestor == requestor && t.property == property;
          });
          if (existing == outgoing_.end() && outgoing_.size() >= max_outgoing_transfers) {
            return false;
          }
          if (existing != outgoing_.end()) {
            outgoing_.erase(existing);
          }
          XSelectInput(dpy_, requestor, PropertyChangeMask | StructureNotifyMask);
          const long size = static_cast<long>(bytes.size());
          XChangeProperty(dpy_, requestor, property, atoms_.incr, 32, PropModeReplace, reinterpret_cast<const unsigned char *>(&size), 1);
          outgoing_.push_back({requestor, property, type, owned_, bytes, 0, steady::now() + options_.transfer_timeout});
          return true;
        }
        XChangeProperty(dpy_, requestor, property, type, 8, PropModeReplace, bytes.data(), static_cast<int>(bytes.size()));
        return true;
      }

      /**
       * @brief Answer a MULTIPLE request by converting each (target, property) pair.
       */
      bool serve_multiple(Window requestor, Atom property) {
        property_t pairs;
        if (XGetWindowProperty(dpy_, requestor, property, 0, 4096, False, AnyPropertyType, &pairs.type, &pairs.format, &pairs.items, &pairs.bytes_after, &pairs.data) != Success || pairs.format != 32 || pairs.items % 2 != 0) {
          return false;
        }
        auto *atoms = reinterpret_cast<unsigned long *>(pairs.data);
        for (unsigned long i = 0; i + 1 < pairs.items; i += 2) {
          if (atoms[i] == atoms_.multiple || atoms[i + 1] == None || !serve_target(requestor, atoms[i], atoms[i + 1])) {
            atoms[i + 1] = None;
          }
        }
        XChangeProperty(dpy_, requestor, property, pairs.type, 32, PropModeReplace, pairs.data, static_cast<int>(pairs.items));
        return true;
      }

      /**
       * @brief Handle a SelectionRequest from another client.
       */
      void serve(const XSelectionRequestEvent &request) {
        XSelectionEvent reply {};
        reply.type = SelectionNotify;
        reply.display = dpy_;
        reply.requestor = request.requestor;
        reply.selection = request.selection;
        reply.target = request.target;
        reply.time = request.time;
        reply.property = None;

        // Obsolete clients pass None and expect the target name as the property
        const Atom property = request.property == None ? request.target : request.property;
        const bool time_ok = request.time == CurrentTime || request.time >= own_time_;
        if (owning_ && owned_ && request.selection == atoms_.clipboard && request.owner == window_ && time_ok) {
          const bool served = request.target == atoms_.multiple ? request.property != None && serve_multiple(request.requestor, property) : serve_target(request.requestor, request.target, property);
          if (served) {
            reply.property = property;
          }
        }
        XSendEvent(dpy_, request.requestor, False, NoEventMask, reinterpret_cast<XEvent *>(&reply));
        XFlush(dpy_);
      }

      /**
       * @brief Forget transfers to a requestor window and stop listening to it.
       */
      void drop_requestor(Window requestor) {
        std::erase_if(outgoing_, [&](const outgoing_t &t) {
          return t.requestor == requestor;
        });
      }

      /**
       * @brief Stop listening to a requestor's property changes when no transfer needs them.
       */
      void release_requestor(Window requestor) {
        const bool busy = std::ranges::any_of(outgoing_, [&](const outgoing_t &t) {
          return t.requestor == requestor;
        });
        if (!busy) {
          XSelectInput(dpy_, requestor, NoEventMask);
        }
      }

      /**
       * @brief Send the next INCR chunk after the requestor deleted the property.
       */
      void continue_outgoing(const XPropertyEvent &event) {
        const auto it = std::ranges::find_if(outgoing_, [&](const outgoing_t &t) {
          return t.requestor == event.window && t.property == event.atom;
        });
        if (it == outgoing_.end()) {
          return;
        }
        const std::size_t n = std::min(chunk_, it->data.size() - it->offset);
        XChangeProperty(dpy_, it->requestor, it->property, it->type, 8, PropModeReplace, it->data.data() + it->offset, static_cast<int>(n));
        if (n == 0) {
          // The zero-length chunk ends the transfer
          const Window requestor = it->requestor;
          outgoing_.erase(it);
          release_requestor(requestor);
          return;
        }
        it->offset += n;
        it->deadline = steady::now() + options_.transfer_timeout;
      }

      /**
       * @brief Pick a property for a new conversion, skipping ones still being drained.
       */
      Atom next_property() {
        for (std::size_t i = 0; i < atoms_.properties.size(); ++i) {
          const Atom candidate = atoms_.properties[(property_cursor_ + i) % atoms_.properties.size()];
          const bool busy = std::ranges::any_of(draining_, [&](const drain_t &d) {
            return d.property == candidate;
          });
          if (!busy) {
            property_cursor_ = (property_cursor_ + i + 1) % atoms_.properties.size();
            return candidate;
          }
        }
        property_cursor_ = (property_cursor_ + 1) % atoms_.properties.size();
        return atoms_.properties[property_cursor_];
      }

      /**
       * @brief Ask the owner to convert CLIPBOARD to `target`.
       */
      void request(read_op_t &op, Atom target, std::size_t cap) {
        op.active = true;
        op.target = target;
        op.property = next_property();
        op.incr = false;
        op.cap = cap;
        op.buffer.clear();
        XDeleteProperty(dpy_, window_, op.property);
        XConvertSelection(dpy_, atoms_.clipboard, target, op.property, window_, CurrentTime);
        XFlush(dpy_);
      }

      /**
       * @brief Start the oldest queued read if none is active.
       */
      void begin_read() {
        while (!reads_.empty() && !reads_.front()->active) {
          auto &op = *reads_.front();
          if (owning_ && owned_) {
            // Our own content: no round trip through the server
            item_t item = op.limits.file_offer ? item_t {} : owned_->item;
            // Never re-export a network file offer as a local copy or text.
            item.file_offer.reset();
            util::apply_limits(item, op.limits);
            finish(item.empty() ? std::nullopt : std::optional {std::move(item)});
            continue;
          }
          op.stage = read_op_t::stage_e::targets;
          request(op, atoms_.targets, 0);
        }
      }

      /**
       * @brief Complete the active read and start the next.
       */
      void finish(std::optional<item_t> result) {
        auto op = std::move(reads_.front());
        reads_.pop_front();
        complete(*op->state, std::move(result));
        begin_read();
      }

      /**
       * @brief Move on after the current conversion finished (`data`) or failed (nullopt).
       */
      void advance(read_op_t &op, std::optional<std::vector<std::uint8_t>> data) {
        switch (op.stage) {
          case read_op_t::stage_e::targets:
            break;
          case read_op_t::stage_e::text:
            if (data) {
              const std::string_view raw(reinterpret_cast<const char *>(data->data()), data->size());
              auto text = util::sanitize_text(op.target == XA_STRING ? util::latin1_to_utf8(raw) : std::string {raw});
              if (text && text->size() <= op.limits.text_max) {
                op.out.text = std::move(text);
              }
            }
            break;
          case read_op_t::stage_e::files:
            if (data && !data->empty()) {
              op.out.file_offer = std::string(reinterpret_cast<const char *>(data->data()), data->size());
            }
            break;
          case read_op_t::stage_e::image:
            if (data && data->size() <= op.limits.image_max && util::has_png_signature(*data)) {
              op.out.png = std::move(data);
            }
            break;
        }

        if (op.stage == read_op_t::stage_e::targets && op.file_target != None) {
          op.stage = read_op_t::stage_e::files;
          request(op, op.file_target, file_clipboard::offer_max);
          return;
        }
        if (op.stage != read_op_t::stage_e::image && op.stage != read_op_t::stage_e::text && op.text_target != None) {
          op.stage = read_op_t::stage_e::text;
          // UTF-8 targets may carry a trailing NUL; Latin-1 only grows when converted
          request(op, op.text_target, op.text_target == XA_STRING ? op.limits.text_max : op.limits.text_max + 1);
          return;
        }
        if (op.stage != read_op_t::stage_e::image && op.image_target != None) {
          op.stage = read_op_t::stage_e::image;
          request(op, op.image_target, op.limits.image_max);
          return;
        }
        finish(op.out.empty() ? std::nullopt : std::optional {std::move(op.out)});
      }

      /**
       * @brief Choose text and image targets from a TARGETS reply.
       */
      void choose_targets(read_op_t &op, const property_t *targets) {
        op.text_target = None;
        op.image_target = None;
        if (!targets) {
          // No TARGETS support: ask for UTF-8 text directly
          if (!op.limits.file_offer) op.text_target = atoms_.utf8_string;
          return;
        }
        const auto *list = reinterpret_cast<const unsigned long *>(targets->data);
        const std::span<const unsigned long> offered(list, targets->items);
        auto has = [&](Atom a) {
          return std::ranges::find(offered, a) != offered.end();
        };
        if (op.limits.file_offer) {
          if (has(atoms_.file_offer)) op.file_target = atoms_.file_offer;
          return;
        }
        for (const Atom candidate : {atoms_.utf8_string, atoms_.text_utf8, atoms_.text_utf8_upper, Atom {XA_STRING}}) {
          if (has(candidate)) {
            op.text_target = candidate;
            break;
          }
        }
        if (has(atoms_.image_png)) {
          op.image_target = atoms_.image_png;
        }
      }

      /**
       * @brief Handle the owner's answer to our ConvertSelection.
       */
      void on_selection_notify(const XSelectionEvent &event) {
        if (reads_.empty() || !reads_.front()->active) {
          return;
        }
        auto &op = *reads_.front();
        if (event.requestor != window_ || event.selection != atoms_.clipboard || event.target != op.target || op.incr) {
          return;
        }
        if (event.property == None) {
          if (op.stage == read_op_t::stage_e::targets) {
            choose_targets(op, nullptr);
          }
          advance(op, std::nullopt);
          return;
        }

        if (op.stage == read_op_t::stage_e::targets) {
          property_t targets;
          const int status = XGetWindowProperty(dpy_, window_, op.property, 0, 1024, True, AnyPropertyType, &targets.type, &targets.format, &targets.items, &targets.bytes_after, &targets.data);
          const bool ok = status == Success && targets.format == 32 && (targets.type == XA_ATOM || targets.type == atoms_.targets);
          choose_targets(op, ok ? &targets : nullptr);
          advance(op, std::nullopt);
          return;
        }

        property_t header;
        if (XGetWindowProperty(dpy_, window_, op.property, 0, 0, False, AnyPropertyType, &header.type, &header.format, &header.items, &header.bytes_after, &header.data) != Success || header.type == None) {
          advance(op, std::nullopt);
          return;
        }

        if (header.type == atoms_.incr) {
          property_t size;
          XGetWindowProperty(dpy_, window_, op.property, 0, 1, False, atoms_.incr, &size.type, &size.format, &size.items, &size.bytes_after, &size.data);
          const unsigned long lower_bound = size.format == 32 && size.items == 1 ? *reinterpret_cast<const unsigned long *>(size.data) : 0;
          // Deleting the property asks the owner for the first chunk
          XDeleteProperty(dpy_, window_, op.property);
          XFlush(dpy_);
          if (lower_bound > op.cap) {
            drain(op.property);
            advance(op, std::nullopt);
            return;
          }
          op.incr = true;
          return;
        }

        if (header.format != 8 || header.bytes_after > op.cap) {
          XDeleteProperty(dpy_, window_, op.property);
          advance(op, std::nullopt);
          return;
        }
        property_t value;
        if (XGetWindowProperty(dpy_, window_, op.property, 0, static_cast<long>((header.bytes_after + 3) / 4), True, AnyPropertyType, &value.type, &value.format, &value.items, &value.bytes_after, &value.data) != Success || value.format != 8) {
          advance(op, std::nullopt);
          return;
        }
        advance(op, std::vector<std::uint8_t>(value.data, value.data + value.items));
      }

      /**
       * @brief Discard the remaining INCR chunks arriving on `property`.
       */
      void drain(Atom property) {
        draining_.push_back({property, steady::now() + options_.transfer_timeout});
      }

      /**
       * @brief Outcome of probing/reading one INCR chunk property.
       */
      struct chunk_read_t {
        enum class state_e {
          none,  ///< Property missing or read failed.
          eof,  ///< Zero-length INCR terminator.
          aborted,  ///< Draining, invalid format, or oversized chunk (deleted without fetching payload).
          data,  ///< Valid chunk payload in `bytes`.
        };

        state_e state = state_e::none;
        std::vector<std::uint8_t> bytes;
      };

      /**
       * @brief Probe, read (when within cap and not draining), and delete one INCR chunk from our property.
       *
       * @param property Property atom on our window.
       * @param cap_remaining Maximum bytes accepted, or `std::nullopt` when draining.
       * @return Chunk outcome and payload bytes when `state == data`.
       */
      chunk_read_t take_chunk(Atom property, std::optional<std::size_t> cap_remaining) {
        property_t header;
        if (XGetWindowProperty(dpy_, window_, property, 0, 0, False, AnyPropertyType, &header.type, &header.format, &header.items, &header.bytes_after, &header.data) != Success || header.type == None) {
          return {chunk_read_t::state_e::none, {}};
        }
        if (header.bytes_after == 0) {
          XDeleteProperty(dpy_, window_, property);
          XFlush(dpy_);
          return {chunk_read_t::state_e::eof, {}};
        }
        const bool draining = !cap_remaining || std::ranges::any_of(draining_, [property](const drain_t &d) {
          return d.property == property;
        });
        if (draining || header.format != 8 || header.bytes_after > *cap_remaining) {
          XDeleteProperty(dpy_, window_, property);
          XFlush(dpy_);
          return {chunk_read_t::state_e::aborted, {}};
        }
        property_t chunk;
        if (XGetWindowProperty(dpy_, window_, property, 0, static_cast<long>((header.bytes_after + 3) / 4), True, AnyPropertyType, &chunk.type, &chunk.format, &chunk.items, &chunk.bytes_after, &chunk.data) != Success || chunk.type == None) {
          return {chunk_read_t::state_e::none, {}};
        }
        if ((chunk.items != 0 && chunk.format != 8) || chunk.bytes_after > 0 || chunk.items > *cap_remaining) {
          if (chunk.bytes_after > 0) {
            XDeleteProperty(dpy_, window_, property);
            XFlush(dpy_);
          }
          return {chunk_read_t::state_e::aborted, {}};
        }
        return {chunk_read_t::state_e::data, std::vector<std::uint8_t>(chunk.data, chunk.data + chunk.items)};
      }

      /**
       * @brief Handle property changes: INCR chunks for us and INCR progress of our transfers.
       */
      void on_property_notify(const XPropertyEvent &event) {
        if (event.window != window_) {
          if (event.state == PropertyDelete) {
            continue_outgoing(event);
          }
          return;
        }
        if (event.state != PropertyNewValue) {
          return;
        }

        if (!reads_.empty() && reads_.front()->active && reads_.front()->incr && event.atom == reads_.front()->property) {
          auto &op = *reads_.front();
          const std::size_t remaining = op.cap >= op.buffer.size() ? op.cap - op.buffer.size() : 0;
          auto chunk = take_chunk(event.atom, remaining);
          if (chunk.state == chunk_read_t::state_e::none) {
            return;
          }
          if (chunk.state == chunk_read_t::state_e::eof) {
            op.incr = false;
            advance(op, std::move(op.buffer));
            return;
          }
          if (chunk.state == chunk_read_t::state_e::aborted) {
            op.incr = false;
            drain(op.property);
            advance(op, std::nullopt);
            return;
          }
          op.buffer.insert(op.buffer.end(), chunk.bytes.begin(), chunk.bytes.end());
          return;
        }

        const auto drain_it = std::ranges::find_if(draining_, [&](const drain_t &d) {
          return d.property == event.atom;
        });
        if (drain_it != draining_.end()) {
          const auto chunk = take_chunk(event.atom, std::nullopt);
          if (chunk.state == chunk_read_t::state_e::eof) {
            draining_.erase(drain_it);
          } else {
            drain_it->deadline = steady::now() + options_.transfer_timeout;
          }
        }
      }

      /**
       * @brief Apply deadlines to reads, outgoing transfers and drained properties.
       */
      void expire(steady::time_point now) {
        std::vector<Window> stalled;
        std::erase_if(outgoing_, [&](const outgoing_t &t) {
          if (t.deadline <= now) {
            stalled.push_back(t.requestor);
            return true;
          }
          return false;
        });
        for (const auto requestor : stalled) {
          BOOST_LOG(debug) << "[clipboard/x11] Dropped an INCR transfer to an unresponsive requestor"sv;
          release_requestor(requestor);
        }
        std::erase_if(draining_, [&](const drain_t &d) {
          return d.deadline <= now;
        });

        // Queued reads that expired before their turn
        for (auto it = reads_.begin(); it != reads_.end();) {
          if (!(*it)->active && (*it)->deadline <= now) {
            complete(*(*it)->state, std::nullopt);
            it = reads_.erase(it);
          } else {
            ++it;
          }
        }
        if (!reads_.empty() && reads_.front()->active && reads_.front()->deadline <= now) {
          auto &op = *reads_.front();
          if (op.incr) {
            drain(op.property);
          }
          finish(op.out.empty() ? std::nullopt : std::optional {std::move(op.out)});
        }
        begin_read();
      }

      options_t options_;
      std::mutex lifecycle_mutex_;  ///< Serializes start() and stop().
      std::mutex mutex_;  ///< Guards tasks_ and accepting_.
      std::deque<task_t> tasks_;
      bool accepting_ = false;
      std::array<int, 2> wake_ {-1, -1};
      std::thread thread_;
      std::atomic<bool> quit_ {false};
      util::change_notifier_t notifier_;

      // Event thread state (also touched by start()/stop() while the thread is not running)
      Display *dpy_ = nullptr;
      Window window_ = None;
      atoms_t atoms_ {};
      int xfixes_event_base_ = 0;
      bool dead_ = false;
      std::size_t chunk_ = default_incr_chunk;
      std::shared_ptr<const owned_t> owned_;
      Time own_time_ = CurrentTime;
      bool owning_ = false;
      std::uint64_t generation_ = 1;
      std::deque<std::unique_ptr<read_op_t>> reads_;
      std::vector<outgoing_t> outgoing_;
      std::vector<drain_t> draining_;
      std::size_t property_cursor_ = 0;
    };
  }  // namespace

  std::unique_ptr<backend_t> make_backend(const options_t &options) {
    return std::make_unique<x11_backend_t>(options);
  }
}  // namespace sds::clipboard::x11
