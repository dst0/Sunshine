/**
 * @file src/sds/http.h
 * @brief Routes `/sds/v1` on the paired nvhttp HTTPS server (only there).
 */
#pragma once

// lib includes
#include <Simple-Web-Server/server_http.hpp>

// local includes
#include "src/nvhttp.h"

namespace sds::http {
  /**
   * @brief Paired HTTPS server type.
   */
  using https_server_t = SimpleWeb::ServerBase<nvhttp::SunshineHTTPS>;

  /**
   * @brief Plain HTTP server type.
   */
  using http_server_t = SimpleWeb::ServerBase<SimpleWeb::HTTP>;

  /**
   * @brief Register the `/sds/...` dispatcher on the paired HTTPS server and raise its request
   *        buffer limit to max_request_body_size().
   *
   * Handlers only extract fields and call sds::handle(); responses are written asynchronously
   * from the sds worker threads. Request bodies are never logged.
   *
   * @param server Paired HTTPS server, before start().
   */
  void register_routes(https_server_t &server);

  /**
   * @brief Make the plain HTTP server answer every `/sds/...` request with 404 for all methods.
   *
   * @param server Plain HTTP server, before start().
   */
  void register_plain_http_guard(http_server_t &server);
}  // namespace sds::http
