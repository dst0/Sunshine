/**
 * @file src/httpcommon.h
 * @brief Declarations for common HTTP.
 */
#pragma once

// standard includes
#include <cstddef>
#include <memory>
#include <string_view>

// lib includes
#include <Simple-Web-Server/utility.hpp>

// local includes
#include "network.h"
#include "thread_safe.h"

namespace http {

  /**
   * @brief Initialize shared HTTP client state.
   *
   * @return 0 when HTTP state initializes successfully; nonzero on failure.
   */
  int init();
  /**
   * @brief Generate HTTPS credential files from the provided key and certificate paths.
   *
   * @param pkey Private key PEM data or private key file path.
   * @param cert Certificate data or object used by the operation.
   * @return Created creds object or status.
   */
  int create_creds(const std::string &pkey, const std::string &cert);
  int save_user_creds(
    const std::string &file,
    const std::string &username,
    const std::string &password,
    bool run_our_mouth = false
  );

  /**
   * @brief Load the Web UI credentials and refuse to continue without them.
   * @details There is no unauthenticated first-run setup: credentials must be created with
   *          `sunshine --creds <username>` before Sunshine starts.
   *
   * @param file Credentials file path.
   * @return 0 when credentials were loaded; -1 (after logging how to create them) otherwise.
   */
  int require_user_creds(const std::string &file);

  /**
   * @brief Reload Web UI user credentials from disk.
   *
   * @param file Credentials file path.
   * @return 0 when credentials reload successfully; nonzero on failure.
   */
  int reload_user_creds(const std::string &file);

  /**
   * @brief Check that a raw HTTP request head uses canonical CRLF framing without bare LF/CR/NUL, missing colons, or obs-fold.
   *
   * @param raw Bounded raw request line and headers ending with `\r\n\r\n`.
   * @return `true` when the request line and every header field name and framing are canonical.
   */
  bool has_canonical_header_lines(std::string_view raw);

  /**
   * @brief Validate request framing (`has_canonical_header_lines`, no `Transfer-Encoding`, and a single decimal `Content-Length` within `max_body_size`).
   *
   * @param raw_header Raw HTTP request head.
   * @param header Parsed request header multimap.
   * @param max_body_size Maximum permitted `Content-Length` in bytes.
   * @param content_length Optional out parameter receiving the parsed `Content-Length` (0 when absent).
   * @return `true` when request framing is unambiguous and within limits.
   */
  bool validate_request_framing(
    std::string_view raw_header,
    const SimpleWeb::CaseInsensitiveMultimap &header,
    std::size_t max_body_size,
    std::size_t *content_length = nullptr
  );

  /**
   * @brief Lock-free RAII concurrency cap for accepted HTTP/HTTPS connections.
   */
  class connection_limiter_t {
  public:
    /**
     * @brief Construct a limiter permitting up to `max_connections` live sockets.
     *
     * @param max_connections Maximum concurrent connections.
     */
    explicit connection_limiter_t(std::size_t max_connections);

    /**
     * @brief Attempt to acquire a connection slot lease.
     *
     * @return Opaque lease releasing the slot when destroyed, or null if the limit is reached.
     */
    std::shared_ptr<void> try_acquire();

  private:
    struct state_t;  ///< Shared atomic counter and limit outliving individual connections.
    std::shared_ptr<state_t> state_;  ///< Owned accounting state.
  };

  extern std::string unique_id;
  extern net::net_e origin_web_ui_allowed;

}  // namespace http
