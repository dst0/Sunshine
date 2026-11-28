/**
 * @file src/sds/http.cpp
 * @brief Simple-Web-Server adapter for `/sds/v1`.
 */
// standard includes
#include <array>
#include <atomic>
#include <cctype>
#include <charconv>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <regex>
#include <string>
#include <utility>

// local includes
#include "auth.h"
#include "http.h"
#include "sds.h"
#include "src/httpcommon.h"
#include "src/nvhttp.h"

namespace sds::http {
  /** @brief Shared accounting; leases never retain a server or network callback. */
  struct transport_budget_t::state_t: std::enable_shared_from_this<state_t> {
    /** @brief Per-certificate usage, retained while either connection or request bytes exist. */
    struct client_t {
      std::size_t connections = 0;  ///< Verified sockets.
      std::size_t requests = 0;  ///< Requests may legally outlive their weak connection reference.
      std::size_t bytes = 0;  ///< Request and output reservations.
    };
    /** @brief Accepted socket lease, extended with its verified certificate after TLS. */
    struct connection_t {
      std::shared_ptr<state_t> state;  ///< Accounting owner.
      std::string cert;  ///< Verified certificate, empty before authentication.
      bool counted = false;  ///< Global connection reservation was acquired.
      ~connection_t() {
        if (counted) {
          std::lock_guard lock {state->mutex};
          --state->current.connections;
          if (!cert.empty()) {
            if (auto it = state->clients.find(cert); it != state->clients.end()) {
              auto &client = it->second;
              --client.connections;
              if (!client.connections && !client.requests && !client.bytes) {
                state->clients.erase(it);
              }
            }
          }
        }
      }
    };
    /** @brief Body/output lease retained by the Request through asynchronous socket completion. */
    struct request_t {
      std::shared_ptr<state_t> state;  ///< Accounting owner.
      std::string cert;  ///< Verified identity.
      std::size_t bytes = 0;  ///< Current input and output reservation.
      bool counted = false;  ///< Reservation was acquired.
      ~request_t() {
        if (counted) {
          std::lock_guard lock {state->mutex};
          --state->current.requests;
          state->current.bytes -= bytes;
          if (auto it = state->clients.find(cert); it != state->clients.end()) {
            auto &client = it->second;
            --client.requests;
            client.bytes -= bytes;
            if (!client.connections && !client.requests && !client.bytes) {
              state->clients.erase(it);
            }
          }
        }
      }
      /** @brief Reserve both output copies before constructing the SWS output buffer. */
      bool response(std::size_t size) {
        if (size > std::numeric_limits<std::size_t>::max() / 2) {
          return false;
        }
        const auto extra = size * 2;
        std::lock_guard lock {state->mutex};
        const auto it = state->clients.find(cert);
        if (it == state->clients.end()) { return false; }
        auto &client = it->second;
        if (extra > state->limits.bytes - state->current.bytes || extra > state->limits.client_bytes - client.bytes) {
          return false;
        }
        state->current.bytes += extra;
        client.bytes += extra;
        bytes += extra;
        return true;
      }
    };
    transport_limits_t limits;  ///< Immutable server limits.
    mutable std::mutex mutex;  ///< Serializes worker/network accounting updates.
    transport_usage_t current;  ///< Aggregate usage.
    std::map<std::string, client_t> clients;  ///< Bounded by accepted connections/requests.
  };

  transport_budget_t::transport_budget_t(transport_limits_t limits): state(std::make_shared<state_t>()) {
    state->limits = limits;
  }

  transport_usage_t transport_budget_t::usage() const {
    std::lock_guard lock {state->mutex};
    return state->current;
  }

  namespace {
    /**
     * @brief Methods routed to the dispatcher (others never reach SDS code).
     */
    constexpr std::array<const char *, 7> METHODS {"GET", "PUT", "POST", "DELETE", "HEAD", "PATCH", "OPTIONS"};

    /**
     * @brief Regex covering the whole `/sds` namespace.
     */
    constexpr const char *NAMESPACE_PATTERN = "^/sds(?:/.*)?$";

    /**
     * @brief One API route.
     */
    struct route_t {
      const char *method;  ///< HTTP method.
      std::regex pattern;  ///< Full-path pattern; group 1 is the id when present.
      op_e op;  ///< Operation.
    };

    /**
     * @brief Route table.
     *
     * @return Routes.
     */
    const std::vector<route_t> &routes() {
      static const std::vector<route_t> table = []() {
        const std::string id = "([0-9a-f]{32})";
        const std::string token = "([0-9A-Za-z_-]{1,64})";
        std::vector<route_t> list;
        list.push_back({"GET", std::regex {"^/sds/v1/capabilities$"}, op_e::capabilities});
        list.push_back({"GET", std::regex {"^/sds/v1/events$"}, op_e::events});
        list.push_back({"GET", std::regex {"^/sds/v1/tile-refinement$"}, op_e::tile_refinement});
        list.push_back({"GET", std::regex {"^/sds/v1/lossless-stream$"}, op_e::lossless_stream});
        list.push_back({"GET", std::regex {"^/sds/v1/clipboard$"}, op_e::clipboard_get});
        list.push_back({"PUT", std::regex {"^/sds/v1/clipboard$"}, op_e::clipboard_put});
        list.push_back({"GET", std::regex {"^/sds/v1/file-clipboard$"}, op_e::file_clipboard_get});
        list.push_back({"PUT", std::regex {"^/sds/v1/file-clipboard$"}, op_e::file_clipboard_put});
        list.push_back({"PUT", std::regex {"^/sds/v1/clipboard-offer$"}, op_e::clipboard_offer_put});
        list.push_back({"POST", std::regex {"^/sds/v1/clipboard-offer/" + token + "/entries/" + token + "$"}, op_e::clipboard_offer_entry_start});
        list.push_back({"PUT", std::regex {"^/sds/v1/clipboard-offer/" + token + "/entries/" + token + "$"}, op_e::clipboard_offer_entry_chunk});
        list.push_back({"POST", std::regex {"^/sds/v1/clipboard-offer/" + token + "/complete$"}, op_e::clipboard_offer_complete});
        list.push_back({"POST", std::regex {"^/sds/v1/clipboard-offer/" + token + "/cancel$"}, op_e::clipboard_offer_cancel});
        list.push_back({"GET", std::regex {"^/sds/v1/clipboard-offer/" + token + "/entries/" + token + "$"}, op_e::clipboard_offer_entry_read});
        list.push_back({"POST", std::regex {"^/sds/v1/files/uploads$"}, op_e::upload_create});
        list.push_back({"PUT", std::regex {"^/sds/v1/files/uploads/" + id + "$"}, op_e::upload_chunk});
        list.push_back({"DELETE", std::regex {"^/sds/v1/files/uploads/" + id + "$"}, op_e::upload_cancel});
        list.push_back({"POST", std::regex {"^/sds/v1/files/uploads/" + id + "/complete$"}, op_e::upload_complete});
        list.push_back({"GET", std::regex {"^/sds/v1/files/outbox$"}, op_e::outbox_list});
        list.push_back({"GET", std::regex {"^/sds/v1/files/outbox/" + id + "$"}, op_e::outbox_read});
        list.push_back({"POST", std::regex {"^/sds/v1/drops$"}, op_e::drop_create});
        list.push_back({"PUT", std::regex {"^/sds/v1/drops/" + id + "$"}, op_e::drop_chunk});
        list.push_back({"POST", std::regex {"^/sds/v1/drops/" + id + "/complete$"}, op_e::drop_complete});
        list.push_back({"DELETE", std::regex {"^/sds/v1/drops/" + id + "$"}, op_e::drop_cancel});
        return list;
      }();
      return table;
    }

    /**
     * @brief Serialize a reply into an SWS response.
     *
     * @tparam Response SWS response type.
     * @param response Response to write.
     * @param reply Reply.
     */
    template<class Response>
    void write_reply(Response &response, reply_t reply, const std::function<bool(std::size_t)> &reserve = {}) {
      SimpleWeb::CaseInsensitiveMultimap headers;
      headers.emplace("Cache-Control", "no-store");
      headers.emplace("X-Content-Type-Options", "nosniff");
      for (auto &[name, value] : reply.headers) {
        headers.emplace(std::move(name), std::move(value));
      }
      std::string body;
      if (reply.status >= 400) {
        auto error = reply.extra.is_object() ? reply.extra : nlohmann::json::object();
        error["error"] = reply.error.empty() ? "internal" : reply.error;
        error["message"] = reply.message;
        body = error.dump();
        headers.emplace("Content-Type", "application/json");
      } else if (reply.json) {
        body = reply.json->dump();
        headers.emplace("Content-Type", "application/json");
      } else if (!reply.content_type.empty()) {
        body = std::move(reply.body);
        headers.emplace("Content-Type", reply.content_type);
      }
      if (reserve && !reserve(body.size())) {
        response.abort();
        return;
      }
      response.write(static_cast<SimpleWeb::StatusCode>(reply.status), body, headers);
      if (reply.status == 401) {
        response.close_connection_after_response = true;
      }
    }

    /**
     * @brief Guarantees exactly one write per response; answers 500 if the reply was lost.
     *
     * @tparam Response SWS response type.
     */
    template<class Response>
    struct reply_guard_t {
      std::shared_ptr<Response> response;  ///< Response being produced.
      std::function<bool(std::size_t)> reserve;  ///< Output reservation held through the Request.
      std::atomic_bool done {false};  ///< Set once written.

      /**
       * @brief Write the reply if none was written yet.
       *
       * @param reply Reply.
       */
      void send(reply_t reply) {
        if (done.exchange(true)) {
          return;
        }
        write_reply(*response, std::move(reply), reserve);
      }

      /**
       * @brief Answer 500 when every holder dropped the guard without replying.
       */
      ~reply_guard_t() {
        if (!done.exchange(true)) {
          write_reply(*response, reply_t::failure(500, "internal", "request was not completed"), reserve);
        }
      }
    };

    /**
     * @brief Dispatch one request under `/sds`.
     *
     * @param response SWS response.
     * @param request SWS request.
     */
    void dispatch(const std::shared_ptr<https_server_t::Response> &response, const std::shared_ptr<https_server_t::Request> &request) {
      auto guard = std::make_shared<reply_guard_t<https_server_t::Response>>();
      guard->response = response;
      guard->reserve = request->reserve_response;
      reply_fn respond = [guard](reply_t reply) {
        guard->send(std::move(reply));
      };

      bool path_known = false;
      const route_t *matched = nullptr;
      std::smatch match;
      for (const auto &route : routes()) {
        if (std::regex_match(request->path, match, route.pattern)) {
          path_known = true;
          if (request->method == route.method) {
            matched = &route;
            break;
          }
        }
      }
      if (!matched) {
        if (path_known) {
          auto reply = reply_t::failure(405, "bad_request", "method not allowed");
          respond(std::move(reply));
        } else {
          respond(reply_t::failure(404, "not_found", "unknown endpoint"));
        }
        return;
      }

      request_t fields;
      fields.cert_pem = nvhttp::verified_client_cert(request);
      if (match.size() > 1) {
        fields.id = match[1].str();
      }
      if (match.size() > 2) {
        fields.sub_id = match[2].str();
      }
      for (const auto &[key, value] : request->parse_query_string()) {
        std::string lower;
        for (const char ch : key) {
          lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
        }
        if (!fields.query.emplace(std::move(lower), value).second) {
          respond(reply_t::failure(400, "bad_request", "duplicate query parameter"));
          return;
        }
      }
      if (matched->op == op_e::clipboard_put ||
          matched->op == op_e::upload_create ||
          matched->op == op_e::upload_chunk ||
          matched->op == op_e::upload_cancel ||
          matched->op == op_e::upload_complete ||
          matched->op == op_e::clipboard_offer_put ||
          matched->op == op_e::clipboard_offer_entry_start ||
          matched->op == op_e::clipboard_offer_entry_chunk ||
          matched->op == op_e::clipboard_offer_complete ||
          matched->op == op_e::drop_create ||
          matched->op == op_e::drop_chunk ||
          matched->op == op_e::drop_complete) {
        if (request->header.count("Content-Type") > 1 || request->header.count("X-SDS-Client-Seq") > 1) {
          respond(reply_t::failure(400, "bad_request", "duplicate header"));
          return;
        }
      }
      if (const auto it = request->header.find("Content-Type"); it != request->header.end()) {
        fields.content_type = it->second;
      }
      if (const auto it = request->header.find("X-SDS-Client-Seq"); it != request->header.end()) {
        fields.client_seq = it->second;
      }
      if (matched->op == op_e::file_clipboard_get || matched->op == op_e::file_clipboard_put) {
        if (request->header.count("X-SDS-Clipboard-Seq") > 1 || request->header.count("X-SDS-Clipboard-Epoch") > 1 || request->header.count("Content-Type") > 1) {
          respond(reply_t::failure(400, "bad_request", "duplicate file clipboard header"));
          return;
        }
        if (const auto it = request->header.find("X-SDS-Clipboard-Seq"); it != request->header.end()) {
          fields.file_clipboard_seq = it->second;
        }
        if (const auto it = request->header.find("X-SDS-Clipboard-Epoch"); it != request->header.end()) {
          fields.file_clipboard_epoch = it->second;
        }
      }
      fields.body = request->content.string();
      if (matched->op == op_e::lossless_stream) {
        const auto ieq = [](std::string_view a, std::string_view b) {
          if (a.size() != b.size()) {
            return false;
          }
          for (std::size_t i = 0; i < a.size(); ++i) {
            if (std::tolower(static_cast<unsigned char>(a[i])) != std::tolower(static_cast<unsigned char>(b[i]))) {
              return false;
            }
          }
          return true;
        };
        const auto has_header_token = [&ieq](std::string_view header_val, std::string_view token) {
          std::size_t pos = 0;
          while (pos < header_val.size()) {
            const auto comma = header_val.find(',', pos);
            std::string_view part = (comma == std::string_view::npos)
                                      ? header_val.substr(pos)
                                      : header_val.substr(pos, comma - pos);
            while (!part.empty() && (part.front() == ' ' || part.front() == '\t')) {
              part.remove_prefix(1);
            }
            while (!part.empty() && (part.back() == ' ' || part.back() == '\t')) {
              part.remove_suffix(1);
            }
            if (ieq(part, token)) {
              return true;
            }
            if (comma == std::string_view::npos) {
              break;
            }
            pos = comma + 1;
          }
          return false;
        };
        if (request->http_version != "1.1" || !fields.body.empty()) {
          respond(reply_t::failure(400, "bad_request", "invalid upgrade request version or body"));
          return;
        }
        if (request->header.count("Upgrade") != 1) {
          respond(reply_t::failure(400, "bad_request", "missing or duplicate Upgrade header"));
          return;
        }
        const auto upg_it = request->header.find("Upgrade");
        const auto conn_it = request->header.find("Connection");
        if (upg_it == request->header.end() || !ieq(upg_it->second, "sds-lossless-v1") ||
            conn_it == request->header.end() || !has_header_token(conn_it->second, "upgrade")) {
          respond(reply_t::failure(400, "bad_request", "missing or invalid Upgrade header"));
          return;
        }
        fields.upgrade_raw = [guard](
                               sds::lossless::lossless_stream_t::raw_data_cb_t on_data,
                               sds::lossless::lossless_stream_t::raw_closed_cb_t on_closed,
                               void *user_data
                             ) -> SdsHttpRawStream * {
          if (guard->done.exchange(true)) {
            return nullptr;
          }
          static constexpr const char *UPGRADE_HEAD =
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: sds-lossless-v1\r\n"
            "Connection: Upgrade\r\n"
            "\r\n";
          SdsHttpRawStream *raw = guard->response->upgrade_raw(UPGRADE_HEAD, 2, on_data, on_closed, user_data);
          if (!raw) {
            guard->done.store(false);
          }
          return raw;
        };
      }

      handle(matched->op, std::move(fields), std::move(respond));
    }
  }  // namespace

  std::shared_ptr<transport_budget_t> register_routes(https_server_t &server, transport_limits_t limits) {
    auto budget = std::make_shared<transport_budget_t>(limits);
    auto state = budget->state;
    server.on_connection_accepted = [state](auto request) {
      auto lease = std::make_shared<transport_budget_t::state_t::connection_t>();
      lease->state = state;
      {
        std::lock_guard lock {state->mutex};
        if (state->current.connections >= state->limits.connections) {
          return false;
        }
        ++state->current.connections;
        lease->counted = true;
      }
      request->connection_context(lease);
      return true;
    };
    server.on_connection_authenticated = [state](auto request) {
      auto lease = std::static_pointer_cast<transport_budget_t::state_t::connection_t>(request->connection_context());
      const auto cert = nvhttp::verified_client_cert(request);
      if (!lease || !cert || cert->empty()) {
        return false;
      }
      std::lock_guard lock {state->mutex};
      auto &client = state->clients[*cert];
      if (client.connections >= state->limits.client_connections) {
        if (!client.connections && !client.requests && !client.bytes) {
          state->clients.erase(*cert);
        }
        return false;
      }
      ++client.connections;
      lease->cert = *cert;
      return true;
    };
    server.on_request_header = [state](auto request) {
      const bool sds = request->path == "/sds" || request->path.starts_with("/sds/");
      std::size_t length = 0;
      if (!::http::validate_request_framing(
            request->raw_header,
            request->header,
            sds ? max_request_body_size() : nvhttp::HTTP_MAX_REQUEST_SIZE,
            &length
          ) ||
          length > std::numeric_limits<std::size_t>::max() / 2) {
        return false;
      }
      auto connection = std::static_pointer_cast<transport_budget_t::state_t::connection_t>(request->connection_context());
      if (!connection || connection->cert.empty()) {
        return false;
      }
      auto lease = std::make_shared<transport_budget_t::state_t::request_t>();
      lease->state = state;
      lease->cert = connection->cert;
      lease->bytes = length * 2;
      {
        std::lock_guard lock {state->mutex};
        auto &client = state->clients.at(lease->cert);
        if (state->current.requests >= state->limits.connections || client.requests >= state->limits.client_connections || lease->bytes > state->limits.bytes - state->current.bytes || lease->bytes > state->limits.client_bytes - client.bytes) {
          return false;
        }
        ++state->current.requests;
        ++client.requests;
        state->current.bytes += lease->bytes;
        client.bytes += lease->bytes;
        lease->counted = true;
      }
      request->admission_context = lease;
      request->reserve_response = [lease](std::size_t size) {
        return lease->response(size);
      };
      return true;
    };
    for (const auto *method : METHODS) {
      server.resource[NAMESPACE_PATTERN][method] = [](std::shared_ptr<https_server_t::Response> response, std::shared_ptr<https_server_t::Request> request) {
        dispatch(response, request);
      };
    }
    server.config.max_request_streambuf_size = max_request_body_size();
    server.config.max_request_header_size = 64 * 1024;
    server.config.timeout_content = std::max(1L, limits.content_timeout);
    return budget;
  }

  void register_plain_http_guard(http_server_t &server) {
    for (const auto *method : METHODS) {
      server.resource[NAMESPACE_PATTERN][method] = [](std::shared_ptr<http_server_t::Response> response, std::shared_ptr<http_server_t::Request>) {
        write_reply(*response, reply_t::failure(404, "not_found", "not found"));
      };
    }
  }
  bool canonical_header_lines(const std::string_view raw) {
    return ::http::has_canonical_header_lines(raw);
  }
}  // namespace sds::http
