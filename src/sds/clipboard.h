/**
 * @file src/sds/clipboard.h
 * @brief Platform-independent shared clipboard core (DESIGN section 5): validation, limits,
 *        sequence numbers, echo suppression and coalescing.
 */
#pragma once

// standard includes
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

// lib includes
#include <nlohmann/json.hpp>

// local includes
#include "clipboard_backend.h"

namespace sds::clipboard {
  /**
   * @brief Largest decoded image accepted from a PNG header (width * height * 4 bytes).
   */
  inline constexpr std::uint64_t PNG_DECODED_MAX = 256ull * 1024 * 1024;

  /**
   * @brief Clipboard representation.
   */
  enum class type_e {
    text,  ///< `text/plain;charset=utf-8`.
    png,  ///< `image/png`.
  };

  /**
   * @brief Map a media type to a representation.
   *
   * @param media_type Lowercase media type without parameters.
   * @return Representation, or no value when unsupported.
   */
  std::optional<type_e> parse_type(std::string_view media_type);

  /**
   * @brief Media type of a representation as used in events and the `type` query parameter.
   *
   * @param type Representation.
   * @return `text/plain` or `image/png`.
   */
  std::string_view type_name(type_e type);

  /**
   * @brief Result of validating clipboard content.
   */
  enum class validation_e {
    ok,  ///< Acceptable.
    too_large,  ///< Exceeds the configured byte limit.
    invalid_utf8,  ///< Text is not well-formed UTF-8.
    contains_nul,  ///< Text contains a NUL byte.
    bad_png_signature,  ///< Data does not start with the PNG signature.
    bad_png_header,  ///< Missing or malformed IHDR chunk.
    image_too_large,  ///< Decoded size would exceed PNG_DECODED_MAX.
  };

  /**
   * @brief Validate clipboard text.
   *
   * @param text UTF-8 bytes.
   * @param max Byte limit.
   * @return Validation result.
   */
  validation_e validate_text(std::string_view text, std::size_t max);

  /**
   * @brief Validate a PNG before any decoder sees it (signature, IHDR, CRC, decoded size).
   *
   * @param png PNG file bytes.
   * @param max Byte limit.
   * @return Validation result.
   */
  validation_e validate_png(std::span<const std::uint8_t> png, std::size_t max);

  /**
   * @brief Human-readable description of a validation result.
   *
   * @param result Validation result.
   * @return Message.
   */
  std::string_view describe(validation_e result);

  /**
   * @brief Outcome of a clipboard request handled by the core.
   */
  struct result_t {
    int status = 200;  ///< HTTP status.
    std::string error;  ///< Error code when status >= 400.
    std::string message;  ///< Error message.
    std::uint64_t host_seq = 0;  ///< Value for `X-SDS-Host-Seq`.
    std::string content_type;  ///< Response media type for GET.
    std::string body;  ///< Response body for GET.
  };

  /**
   * @brief Callbacks into the rest of the module.
   */
  struct hooks_t {
    std::function<void(const std::string &client, nlohmann::json event)> publish;  ///< Queue a clipboard event for a client.
    std::function<void(const std::string &client)> retract;  ///< Drop a queued clipboard event of a client.
    std::function<std::vector<std::string>()> readers;  ///< Clients with an active stream and `clipboard_read`.
    std::function<bool(std::function<void()>)> post;  ///< Run a job on the clipboard worker thread.
  };

  /**
   * @brief Clipboard state machine.
   *
   * Every member except the constructor, available() and backend_name() must run on the clipboard
   * worker thread; the backend's change callback is marshalled there through hooks_t::post.
   */
  class core_t {
  public:
    /**
     * @brief Create the core.
     *
     * @param backend Platform backend, or `nullptr` when unavailable.
     * @param limits Byte limits per representation.
     * @param read_timeout Maximum time a backend read may block.
     * @param coalesce_window Window in which a second PUT with the same client seq extends the item.
     * @param hooks Callbacks.
     */
    core_t(std::unique_ptr<backend_t> backend, limits_t limits, std::chrono::milliseconds read_timeout, std::chrono::milliseconds coalesce_window, hooks_t hooks);

    /**
     * @brief Stops the backend.
     */
    ~core_t();

    core_t(const core_t &) = delete;
    core_t &operator=(const core_t &) = delete;

    /**
     * @brief Check whether a backend exists.
     *
     * @return `true` when the platform backend was created.
     */
    [[nodiscard]] bool available() const;

    /**
     * @brief Name of the backend.
     *
     * @return Backend name, or empty.
     */
    [[nodiscard]] std::string_view backend_name() const;

    /**
     * @brief Handle `PUT /sds/v1/clipboard`.
     *
     * @param client Client key.
     * @param content_type Raw `Content-Type`.
     * @param body Request body.
     * @param client_seq Raw `X-SDS-Client-Seq` header value.
     * @return Response description (204 on success).
     */
    result_t put(const std::string &client, std::string_view content_type, std::string body, std::string_view client_seq);

    /**
     * @brief Handle `GET /sds/v1/clipboard`.
     *
     * @param client Client key.
     * @param seq Requested host seq, or no value for the current item.
     * @param type Requested representation.
     * @return Response description (200, 404 or 410).
     */
    result_t get(const std::string &client, std::optional<std::uint64_t> seq, type_e type);

    /**
     * @brief Read the host clipboard after a change notification and announce it.
     */
    void on_host_change();

    /**
     * @brief Start or stop watching depending on whether any permitted stream is active.
     *
     * @param needed `true` while at least one active client holds a clipboard permission.
     */
    void set_watching(bool needed);

    /**
     * @brief Send the current item to a client whose stream just started.
     *
     * @param client Client key.
     */
    void announce_to(const std::string &client);

    /**
     * @brief Drop per-client state (coalescing) of a client.
     *
     * @param client Client key.
     */
    void forget_client(const std::string &client);

    /**
     * @brief Stop the backend and drop all content.
     */
    void shutdown();

    /**
     * @brief Current host seq.
     *
     * @return Sequence number.
     */
    [[nodiscard]] std::uint64_t seq() const;

    /**
     * @brief Whether the backend is being watched.
     *
     * @return `true` while watching.
     */
    [[nodiscard]] bool watching() const;

    /**
     * @brief Whether any content is cached.
     *
     * @return `true` when the current item has a representation.
     */
    [[nodiscard]] bool has_content() const;

  private:
    /**
     * @brief Build the event announcing the current item.
     *
     * @return Event object.
     */
    nlohmann::json make_event() const;

    /**
     * @brief Announce the current item to every reader except its origin.
     */
    void announce();

    /**
     * @brief Drop representations that fail validation.
     *
     * @param item Item read from the backend.
     */
    void sanitize(item_t &item) const;

    /**
     * @brief Coalescing state of the last client PUT.
     */
    struct last_put_t {
      std::string client;  ///< Client that sent it.
      std::uint64_t client_seq;  ///< Its `X-SDS-Client-Seq`.
      std::uint64_t host_seq;  ///< Host seq it produced.
      std::chrono::steady_clock::time_point at;  ///< When it was applied.
    };

    std::unique_ptr<backend_t> backend_;  ///< Platform backend.
    limits_t limits_;  ///< Byte limits.
    std::chrono::milliseconds read_timeout_;  ///< Backend read timeout.
    std::chrono::milliseconds coalesce_window_;  ///< PUT coalescing window.
    hooks_t hooks_;  ///< Callbacks.
    bool watching_ = false;  ///< Backend started.
    std::uint64_t seq_ = 0;  ///< Host clipboard seq.
    item_t item_;  ///< Current item (cached while watching).
    std::string origin_;  ///< Client that produced the current item, empty for host changes.
    std::optional<last_put_t> last_put_;  ///< Coalescing state.
    std::shared_ptr<bool> alive_ = std::make_shared<bool>(true);  ///< Invalidated on shutdown so late backend callbacks are ignored.
  };
}  // namespace sds::clipboard
