/**
 * @file src/sds/http.cpp
 * @brief Simple-Web-Server adapter for `/sds/v1`.
 */
// standard includes
#include <array>
#include <atomic>
#include <cctype>
#include <memory>
#include <regex>
#include <string>
#include <utility>

// local includes
#include "auth.h"
#include "http.h"
#include "sds.h"

namespace sds::http {
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
        std::vector<route_t> list;
        list.push_back({"GET", std::regex {"^/sds/v1/capabilities$"}, op_e::capabilities});
        list.push_back({"GET", std::regex {"^/sds/v1/events$"}, op_e::events});
        list.push_back({"GET", std::regex {"^/sds/v1/clipboard$"}, op_e::clipboard_get});
        list.push_back({"PUT", std::regex {"^/sds/v1/clipboard$"}, op_e::clipboard_put});
        list.push_back({"POST", std::regex {"^/sds/v1/files/uploads$"}, op_e::upload_create});
        list.push_back({"PUT", std::regex {"^/sds/v1/files/uploads/" + id + "$"}, op_e::upload_chunk});
        list.push_back({"DELETE", std::regex {"^/sds/v1/files/uploads/" + id + "$"}, op_e::upload_cancel});
        list.push_back({"POST", std::regex {"^/sds/v1/files/uploads/" + id + "/complete$"}, op_e::upload_complete});
        list.push_back({"GET", std::regex {"^/sds/v1/files/outbox$"}, op_e::outbox_list});
        list.push_back({"GET", std::regex {"^/sds/v1/files/outbox/" + id + "$"}, op_e::outbox_read});
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
    void write_reply(Response &response, reply_t reply) {
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
      response.write(static_cast<SimpleWeb::StatusCode>(reply.status), body, headers);
    }

    /**
     * @brief Guarantees exactly one write per response; answers 500 if the reply was lost.
     *
     * @tparam Response SWS response type.
     */
    template<class Response>
    struct reply_guard_t {
      std::shared_ptr<Response> response;  ///< Response being produced.
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
        write_reply(*response, std::move(reply));
      }

      /**
       * @brief Answer 500 when every holder dropped the guard without replying.
       */
      ~reply_guard_t() {
        if (!done.exchange(true)) {
          write_reply(*response, reply_t::failure(500, "internal", "request was not completed"));
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
      fields.cert_pem = client_cert_pem(*request);
      if (match.size() > 1) {
        fields.id = match[1].str();
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
      if (const auto it = request->header.find("Content-Type"); it != request->header.end()) {
        fields.content_type = it->second;
      }
      if (const auto it = request->header.find("X-SDS-Client-Seq"); it != request->header.end()) {
        fields.client_seq = it->second;
      }
      fields.body = request->content.string();

      handle(matched->op, std::move(fields), std::move(respond));
    }
  }  // namespace

  void register_routes(https_server_t &server) {
    for (const auto *method : METHODS) {
      server.resource[NAMESPACE_PATTERN][method] = [](std::shared_ptr<https_server_t::Response> response, std::shared_ptr<https_server_t::Request> request) {
        dispatch(response, request);
      };
    }
    server.config.max_request_streambuf_size = max_request_body_size();
  }

  void register_plain_http_guard(http_server_t &server) {
    for (const auto *method : METHODS) {
      server.resource[NAMESPACE_PATTERN][method] = [](std::shared_ptr<http_server_t::Response> response, std::shared_ptr<http_server_t::Request>) {
        write_reply(*response, reply_t::failure(404, "not_found", "not found"));
      };
    }
  }
}  // namespace sds::http
