/**
 * @file src/sds/auth.h
 * @brief Request identity and the single authorization pipeline for `/sds/v1` (DESIGN 4.1).
 */
#pragma once

// standard includes
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>

// local includes
#include "permissions.h"

namespace sds {
  /**
   * @brief Globally switchable features (`sunshine.conf`).
   */
  enum class feature_e {
    clipboard,  ///< Shared clipboard (`clipboard`).
    files,  ///< File transfer (`file_transfer`).
    mic,  ///< Microphone passthrough (`mic_passthrough`).
  };

  /**
   * @brief Every operation of the `/sds/v1` API; each maps to one row of the authorization table.
   */
  enum class op_e {
    capabilities,  ///< `GET /sds/v1/capabilities`.
    events,  ///< `GET /sds/v1/events`.
    clipboard_get,  ///< `GET /sds/v1/clipboard`.
    clipboard_put,  ///< `PUT /sds/v1/clipboard`.
    upload_create,  ///< `POST /sds/v1/files/uploads`.
    upload_chunk,  ///< `PUT /sds/v1/files/uploads/{id}`.
    upload_complete,  ///< `POST /sds/v1/files/uploads/{id}/complete`.
    upload_cancel,  ///< `DELETE /sds/v1/files/uploads/{id}`.
    outbox_list,  ///< `GET /sds/v1/files/outbox`.
    outbox_read,  ///< `GET /sds/v1/files/outbox/{id}`.
  };

  /**
   * @brief Maximum body accepted by requests that carry no payload or only small JSON.
   */
  inline constexpr std::size_t SMALL_BODY_MAX = 64 * 1024;

  /**
   * @brief Paired client resolved from a verified certificate.
   */
  struct client_t {
    std::string cert;  ///< Canonical PEM certificate (also the key of all per-client state).
    std::string uuid;  ///< Paired-client UUID.
    std::string name;  ///< Friendly name.
    permission_set_t permissions;  ///< Granted permissions.
  };

  /**
   * @brief Transport-independent view of the request fields authorization needs.
   */
  struct request_view_t {
    std::optional<std::string> cert_pem;  ///< Verified TLS client certificate, if any.
    std::size_t body_size = 0;  ///< Buffered request body size.
    std::string content_type;  ///< Raw `Content-Type` header.
    std::optional<std::uint64_t> range_length;  ///< Requested download length (`outbox_read`).
  };

  /**
   * @brief Outcome of authorize().
   */
  struct auth_result_t {
    int status = 0;  ///< Zero when authorized, otherwise the HTTP status to return.
    std::string error;  ///< Error code (DESIGN 4.4).
    std::string message;  ///< Human-readable message.
    std::optional<std::uint64_t> retry_after;  ///< `Retry-After` seconds for 429.
    client_t client;  ///< Resolved client (valid from step 2 on).

    /**
     * @brief Check for success.
     *
     * @return `true` when all checks passed.
     */
    [[nodiscard]] bool ok() const {
      return status == 0;
    }
  };

  /**
   * @brief Per-client token bucket.
   */
  class rate_limiter_t {
  public:
    using clock = std::chrono::steady_clock;  ///< Clock for refills.

    /**
     * @brief Create a limiter.
     *
     * @param rate_per_second Sustained rate and bucket capacity (at least 1).
     */
    explicit rate_limiter_t(double rate_per_second);

    /**
     * @brief Take one token.
     *
     * @param key Client key.
     * @param now Current time.
     * @return No value when allowed, otherwise whole seconds until a token is available (>= 1).
     */
    std::optional<std::uint64_t> acquire(const std::string &key, clock::time_point now);

    /**
     * @brief Drop the bucket of a client.
     *
     * @param key Client key.
     */
    void forget(const std::string &key);

    /**
     * @brief Check whether a bucket exists (tests).
     *
     * @param key Client key.
     * @return `true` when tracked.
     */
    [[nodiscard]] bool tracked(const std::string &key) const;

  private:
    /**
     * @brief Bucket state.
     */
    struct bucket_t {
      double tokens;  ///< Available tokens.
      clock::time_point updated;  ///< Last refill.
    };

    double rate_;  ///< Tokens per second and capacity.
    mutable std::mutex mutex_;  ///< Protects buckets_.
    std::map<std::string, bucket_t, std::less<>> buckets_;  ///< Buckets by client.
  };

  /**
   * @brief Dependencies and limits consulted by authorize().
   */
  struct auth_context_t {
    std::function<std::optional<client_t>(std::string_view cert)> find_client;  ///< Step 2: certificate -> enabled paired client.
    std::function<bool(feature_e)> feature_available;  ///< Step 3: global switch and backend availability.
    std::function<bool(std::string_view cert)> stream_active;  ///< Step 4: running stream of this certificate.
    rate_limiter_t *clipboard_rate = nullptr;  ///< Step 6: clipboard requests (both directions).
    std::function<std::size_t(std::string_view cert)> open_uploads;  ///< Step 6: upload sessions of the client.
    std::size_t uploads_max = 2;  ///< Step 6: concurrent upload sessions per client.
    std::size_t clipboard_text_max = 1024 * 1024;  ///< Step 7: text body limit.
    std::size_t clipboard_image_max = 16 * 1024 * 1024;  ///< Step 7: PNG body limit.
    std::size_t chunk_max = 4 * 1024 * 1024;  ///< Step 7: upload chunk and download range limit.
  };

  /**
   * @brief Run the authorization pipeline of DESIGN 4.1 for one request.
   *
   * Order: verified certificate, paired client (401), feature switch (404), active stream (409),
   * permission (403), rate/concurrency limit (429), size limit (413). Every `/sds/v1` handler
   * calls this before touching clipboard or file code.
   *
   * @param context Dependencies and limits.
   * @param request Request fields.
   * @param op Operation being requested.
   * @param charge_limits Whether to consume rate/concurrency admission; false revalidates deferred work.
   * @return Authorization outcome.
   */
  auth_result_t authorize(const auth_context_t &context, const request_view_t &request, op_e op, bool charge_limits = true);

  /**
   * @brief Split a `Content-Type` header into a lowercase media type and charset.
   *
   * @param header Raw header value.
   * @return Pair of media type and lowercase charset (empty when absent).
   */
  std::pair<std::string, std::string> parse_content_type(std::string_view header);

}  // namespace sds
