/**
 * @file src/httpcommon.h
 * @brief Declarations for common HTTP.
 */
#pragma once

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

  extern std::string unique_id;
  extern net::net_e origin_web_ui_allowed;

}  // namespace http
