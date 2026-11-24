/**
 * @file src/platform/linux/clipboard_linux.h
 * @brief Linux clipboard backends (X11 and xdg-desktop-portal) and their shared helpers.
 */
#pragma once

// standard includes
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

// local includes
#include "src/sds/clipboard_backend.h"

namespace sds::clipboard {
  namespace fdio {
    /**
     * @brief Outcome of a bounded file descriptor transfer.
     */
    enum class status_e {
      ok,  ///< Completed (EOF reached when reading, everything written when writing).
      too_large,  ///< More than the allowed number of bytes was available.
      timeout,  ///< The deadline passed first.
      error,  ///< Read or write failed (including a closed pipe).
    };

    /**
     * @brief Data read from a file descriptor and how the read ended.
     */
    struct read_result_t {
      status_e status = status_e::error;  ///< How the read ended.
      std::vector<std::uint8_t> data;  ///< Bytes read (complete only when status is ok).
    };

    /**
     * @brief Read until EOF without blocking past the deadline or buffering more than `cap` bytes.
     *
     * The descriptor is switched to non-blocking mode. It is not closed.
     *
     * @param fd Readable descriptor (typically a pipe from the portal).
     * @param cap Largest accepted payload; one more byte makes the result too_large.
     * @param deadline Time at which the read is abandoned.
     * @return Read status and data.
     */
    read_result_t read_capped(int fd, std::size_t cap, std::chrono::steady_clock::time_point deadline);

    /**
     * @brief Write all bytes without blocking past the deadline.
     *
     * The descriptor is switched to non-blocking mode and SIGPIPE is suppressed for the
     * calling thread, so a reader that went away yields status_e::error.
     *
     * @param fd Writable descriptor.
     * @param data Bytes to write.
     * @param deadline Time at which the write is abandoned.
     * @return Write status.
     */
    status_e write_all(int fd, std::span<const std::uint8_t> data, std::chrono::steady_clock::time_point deadline);
  }  // namespace fdio

  namespace x11 {
    /**
     * @brief Tunables of the X11 backend (tests shorten the timeouts).
     */
    struct options_t {
      std::chrono::milliseconds transfer_timeout {5000};  ///< Idle time after which an INCR transfer to or from another client is abandoned.
      std::size_t incr_chunk = 0;  ///< INCR chunk/threshold in bytes; 0 derives it from the server's maximum request size.
    };

    /**
     * @brief Create the X11 CLIPBOARD backend (own connection to $DISPLAY on its own thread).
     *
     * @param options Tunables.
     * @return Backend; start() fails when the display or XFixes is unavailable.
     */
    std::unique_ptr<backend_t> make_backend(const options_t &options = {});

    /**
     * @brief Return true if an X11 window class/name/process string matches a known clipboard manager.
     */
    bool is_clipboard_manager_name(std::string_view value);
  }  // namespace x11

  namespace xdp {
    /**
     * @brief Create the xdg-desktop-portal Clipboard backend on the shared RemoteDesktop session.
     *
     * @return Backend; start() fails when the portal session cannot provide clipboard access.
     */
    std::unique_ptr<backend_t> make_backend();
  }  // namespace xdp
}  // namespace sds::clipboard
