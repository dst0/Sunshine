/**
 * @file src/sds/http.h
 * @brief Routes `/sds/v1` on the paired nvhttp HTTPS server (only there).
 */
#pragma once

// standard includes
#include <string_view>

// lib includes
#include <Simple-Web-Server/server_http.hpp>

// local includes
#include "src/nvhttp.h"

namespace sds::http {
  /** @brief Limits spanning socket admission, body buffering and asynchronous response writes. */
  struct transport_limits_t {
    std::size_t connections = 64;  ///< Accepted sockets, including TLS/header work.
    std::size_t client_connections = 8;  ///< Connections per verified certificate.
    std::size_t bytes = 256 * 1024 * 1024;  ///< Aggregate body/output copy reservations.
    std::size_t client_bytes = 128 * 1024 * 1024;  ///< Reservations per certificate.
    long content_timeout = 35;  ///< Finite body/send timeout, above the maximum event poll.
  };

  /** @brief Current transport reservations; counters remain readable after server shutdown. */
  struct transport_usage_t {
    std::size_t connections = 0;  ///< Accepted connections.
    std::size_t requests = 0;  ///< Admitted requests still buffering, executing or sending.
    std::size_t bytes = 0;  ///< Reserved body/output copies.
  };

  /** @brief Lifetime-safe accounting observer for the server's RAII transport reservations. */
  class transport_budget_t {
  public:
    /** @brief Construct an independent server budget. @param limits Admission limits. */
    explicit transport_budget_t(transport_limits_t limits);
    /** @brief Read counters under their accounting mutex. @return Current usage. */
    transport_usage_t usage() const;
  private:
    friend std::shared_ptr<transport_budget_t> register_routes(SimpleWeb::ServerBase<nvhttp::SunshineHTTPS> &, transport_limits_t);
    struct state_t;  ///< Internal accounting state shared with connection/request leases.
    std::shared_ptr<state_t> state;  ///< Shared state; no server lifetime dependency.
  };
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
  std::shared_ptr<transport_budget_t> register_routes(https_server_t &server, transport_limits_t limits = {});

  /**
   * @brief Make the plain HTTP server answer every `/sds/...` request with 404 for all methods.
   *
   * @param server Plain HTTP server, before start().
   */
  void register_plain_http_guard(http_server_t &server);

  /**
   * @brief Validate that raw HTTP request line and header lines use canonical CRLF framing.
   *
   * @param raw Raw request head up to and including `\r\n\r\n`.
   * @return `true` when the request head is well-formed.
   */
  bool canonical_header_lines(std::string_view raw);
}  // namespace sds::http
