/**
 * @file src/sds/clipboard_backend.h
 * @brief Platform clipboard backend interface for the secure-desktop-stream shared clipboard.
 *
 * Contract (docs/DESIGN.md section 8a in the secure-desktop-stream workspace):
 * - Backends convert host clipboard content to UTF-8 text and/or PNG bytes and back.
 * - on_change is invoked (from any thread) only for changes made by other applications,
 *   never for the backend's own write().
 * - read() never returns a representation larger than the given limits (oversized
 *   representations are dropped, not truncated) and blocks at most `timeout`.
 */
#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace sds::clipboard {
  struct limits_t {
    std::size_t text_max;  ///< maximum UTF-8 bytes
    std::size_t image_max;  ///< maximum PNG bytes
    bool file_offer = false;  ///< Read only the native file-copy selection.
  };

  struct item_t {
    std::optional<std::string> text;  ///< valid UTF-8 without NUL bytes
    std::optional<std::vector<std::uint8_t>> png;  ///< PNG file bytes

    std::optional<std::string> file_offer {};  ///< Validated native file selection payload.

    [[nodiscard]] bool empty() const {
      return !text && !png && !file_offer;
    }
  };

  class backend_t {
  public:
    virtual ~backend_t() = default;

    /**
     * @brief Start watching the host clipboard.
     * @return 0 on success, negative on failure (feature then reported unavailable).
     */
    virtual int start(std::function<void()> on_change) = 0;

    /** @brief Stop watching and release clipboard ownership. Idempotent. */
    virtual void stop() = 0;

    /** @brief Current host clipboard content within limits, or nullopt if empty/unavailable. */
    virtual std::optional<item_t> read(const limits_t &limits, std::chrono::milliseconds timeout) = 0;

    /**
     * @brief Take clipboard ownership and offer `item` to local applications.
     * @return 0 on success, negative on failure.
     */
    virtual int write(const item_t &item) = 0;

    // X11 backend implements native file selections and lazy on-demand offers.
    // All operations share that backend’s X11 event thread and native change counter.
    [[nodiscard]] virtual bool supports_file_clipboard() const { return false; }
    virtual std::optional<std::uint64_t> file_clipboard_generation() { return std::nullopt; }
    virtual std::optional<std::uint64_t> publish_file_clipboard(std::uint64_t, std::string, std::function<bool()>) { return std::nullopt; }
    virtual void retire_file_clipboard(std::uint64_t) {}

    using lazy_pull_callback_t = std::function<void(std::string offer_id, std::vector<std::string> targets)>;
    virtual std::optional<std::uint64_t> publish_lazy_offer(
      std::uint64_t,
      std::string,
      std::string,
      lazy_pull_callback_t
    ) { return std::nullopt; }
    virtual void complete_lazy_offer(
      std::string_view,
      std::string,
      std::string,
      std::function<bool()>
    ) {}
    virtual void fail_lazy_offer(std::string_view) {}

    [[nodiscard]] virtual std::string_view name() const = 0;
  };

  /**
   * @brief Create the backend for this host, chosen at runtime.
   *
   * Windows: Win32 clipboard. Linux: xdg-desktop-portal Clipboard on the shared RemoteDesktop
   * session when it is available, else X11 when DISPLAY is set. Returns nullptr when no
   * backend is usable (the feature is then reported as unavailable).
   */
  std::unique_ptr<backend_t> make_backend();
}  // namespace sds::clipboard
