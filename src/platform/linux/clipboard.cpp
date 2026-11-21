/**
 * @file src/platform/linux/clipboard.cpp
 * @brief Linux clipboard backend factory and file descriptor helpers.
 *
 * The backend is chosen when the clipboard starts (at stream start), after platform
 * initialisation has selected the capture source: the xdg-desktop-portal Clipboard on the
 * shared RemoteDesktop session when portal capture is active, otherwise X11 when DISPLAY is
 * set. If the portal clipboard cannot start (for example because the saved consent does not
 * include the clipboard) and DISPLAY is set, X11 is tried next.
 */
// standard includes
#include <algorithm>
#include <array>
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <ctime>
#include <mutex>
#include <string_view>

// platform includes
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <unistd.h>

// local includes
#include "clipboard_linux.h"
#include "portal_session.h"
#include "src/logging.h"

using namespace std::literals;

namespace sds::clipboard {
  namespace fdio {
    namespace {
      /**
       * @brief Switch a descriptor to non-blocking mode.
       *
       * @return True on success.
       */
      bool set_nonblocking(int fd) {
        const int flags = fcntl(fd, F_GETFL);
        return flags >= 0 && (flags & O_NONBLOCK || fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0);
      }

      /**
       * @brief Milliseconds until the deadline, rounded up, or -1 when it has passed.
       */
      int poll_timeout(std::chrono::steady_clock::time_point deadline) {
        const auto remaining = deadline - std::chrono::steady_clock::now();
        if (remaining <= std::chrono::steady_clock::duration::zero()) {
          return -1;
        }
        const auto ms = std::chrono::ceil<std::chrono::milliseconds>(remaining).count();
        return static_cast<int>(std::min<long long>(ms, 60'000));
      }

      /**
       * @brief Blocks SIGPIPE for the calling thread while alive and discards one raised meanwhile.
       */
      class sigpipe_guard_t {
      public:
        sigpipe_guard_t() {
          sigemptyset(&set_);
          sigaddset(&set_, SIGPIPE);
          sigset_t pending;
          sigemptyset(&pending);
          was_pending_ = sigpending(&pending) == 0 && sigismember(&pending, SIGPIPE) == 1;
          pthread_sigmask(SIG_BLOCK, &set_, &old_);
        }

        sigpipe_guard_t(const sigpipe_guard_t &) = delete;
        sigpipe_guard_t &operator=(const sigpipe_guard_t &) = delete;

        ~sigpipe_guard_t() {
          if (raised && !was_pending_) {
            const timespec zero {};
            while (sigtimedwait(&set_, nullptr, &zero) == -1 && errno == EINTR) {
            }
          }
          pthread_sigmask(SIG_SETMASK, &old_, nullptr);
        }

        bool raised = false;  ///< Set when a write failed with EPIPE.

      private:
        sigset_t set_ {};
        sigset_t old_ {};
        bool was_pending_ = false;
      };
    }  // namespace

    read_result_t read_capped(int fd, std::size_t cap, std::chrono::steady_clock::time_point deadline) {
      read_result_t result;
      if (fd < 0 || !set_nonblocking(fd)) {
        return result;
      }
      std::array<std::uint8_t, 64 * 1024> buffer {};
      while (true) {
        const ssize_t n = ::read(fd, buffer.data(), buffer.size());
        if (n > 0) {
          if (result.data.size() + static_cast<std::size_t>(n) > cap) {
            result.status = status_e::too_large;
            return result;
          }
          result.data.insert(result.data.end(), buffer.begin(), buffer.begin() + n);
          continue;
        }
        if (n == 0) {
          result.status = status_e::ok;
          return result;
        }
        if (errno == EINTR) {
          continue;
        }
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
          result.status = status_e::error;
          return result;
        }
        const int timeout = poll_timeout(deadline);
        if (timeout < 0) {
          result.status = status_e::timeout;
          return result;
        }
        pollfd pfd {fd, POLLIN, 0};
        if (poll(&pfd, 1, timeout) < 0 && errno != EINTR) {
          result.status = status_e::error;
          return result;
        }
      }
    }

    status_e write_all(int fd, std::span<const std::uint8_t> data, std::chrono::steady_clock::time_point deadline) {
      if (fd < 0 || !set_nonblocking(fd)) {
        return status_e::error;
      }
      sigpipe_guard_t guard;
      std::size_t offset = 0;
      while (offset < data.size()) {
        const ssize_t n = ::write(fd, data.data() + offset, data.size() - offset);
        if (n > 0) {
          offset += static_cast<std::size_t>(n);
          continue;
        }
        if (n < 0 && errno == EINTR) {
          continue;
        }
        if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
          guard.raised = errno == EPIPE;
          return status_e::error;
        }
        const int timeout = poll_timeout(deadline);
        if (timeout < 0) {
          return status_e::timeout;
        }
        pollfd pfd {fd, POLLOUT, 0};
        if (poll(&pfd, 1, timeout) < 0 && errno != EINTR) {
          return status_e::error;
        }
        if (pfd.revents & (POLLERR | POLLHUP)) {
          // The reader went away; the next write would raise SIGPIPE
          return status_e::error;
        }
      }
      return status_e::ok;
    }
  }  // namespace fdio

  namespace {
    /**
     * @brief Whether an X11 display is configured for this process.
     */
    bool display_configured() {
      const char *display = std::getenv("DISPLAY");
      return display && *display;
    }

    /**
     * @brief Picks the portal or X11 backend when the clipboard starts and forwards to it.
     */
    class auto_backend_t final: public backend_t {
    public:
      ~auto_backend_t() override {
        stop();
      }

      int start(std::function<void()> on_change) override {
        stop();
        std::lock_guard lock(mutex_);
#ifdef SUNSHINE_BUILD_PORTAL
        if (portal::capture_active()) {
          if (auto backend = std::shared_ptr<backend_t>(xdp::make_backend()); backend->start(on_change) == 0) {
            return activate(std::move(backend));
          }
          BOOST_LOG(warning) << "[clipboard] Portal clipboard unavailable"sv << (display_configured() ? ", trying X11"sv : ""sv);
        }
#endif
#ifdef SUNSHINE_BUILD_X11_CLIPBOARD
        if (display_configured()) {
          if (auto backend = std::shared_ptr<backend_t>(x11::make_backend()); backend->start(on_change) == 0) {
            return activate(std::move(backend));
          }
        }
#endif
        BOOST_LOG(warning) << "[clipboard] No host clipboard backend could be started"sv;
        return -1;
      }

      void stop() override {
        std::shared_ptr<backend_t> backend;
        {
          std::lock_guard lock(mutex_);
          backend = std::move(active_);
        }
        if (backend) {
          backend->stop();
        }
      }

      std::optional<item_t> read(const limits_t &limits, std::chrono::milliseconds timeout) override {
        const auto backend = current();
        return backend ? backend->read(limits, timeout) : std::nullopt;
      }

      int write(const item_t &item) override {
        const auto backend = current();
        return backend ? backend->write(item) : -1;
      }

      [[nodiscard]] std::string_view name() const override {
        std::lock_guard lock(mutex_);
        return name_;
      }

    private:
      /**
       * @brief Make a started backend the active one.
       */
      int activate(std::shared_ptr<backend_t> backend) {
        name_ = backend->name();
        BOOST_LOG(info) << "[clipboard] Using the "sv << name_ << " clipboard backend"sv;
        active_ = std::move(backend);
        return 0;
      }

      /**
       * @brief The active backend, if any.
       */
      std::shared_ptr<backend_t> current() const {
        std::lock_guard lock(mutex_);
        return active_;
      }

      mutable std::mutex mutex_;
      std::shared_ptr<backend_t> active_;
      std::string_view name_ = "linux"sv;  ///< Backend names are string literals, so the view outlives the backend.
    };
  }  // namespace

  std::unique_ptr<backend_t> make_backend() {
    bool usable = false;
#ifdef SUNSHINE_BUILD_PORTAL
    // Creating a backend means the feature is enabled: RemoteDesktop sessions created from now
    // on (capture, enumeration and token negotiation) request clipboard access.
    portal::set_clipboard_requested(true);
    usable = true;
#endif
#ifdef SUNSHINE_BUILD_X11_CLIPBOARD
    usable = usable || display_configured();
#endif
    if (!usable) {
      return nullptr;
    }
    return std::make_unique<auto_backend_t>();
  }
}  // namespace sds::clipboard
