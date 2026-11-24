/**
 * @file src/sds/reply.h
 * @brief Transport-independent description of an `/sds/v1` HTTP response.
 */
#pragma once

// standard includes
#include <optional>
#include <string>
#include <utility>
#include <vector>

// lib includes
#include <nlohmann/json.hpp>

namespace sds {
  /**
   * @brief HTTP response produced by the clipboard and file cores.
   */
  struct reply_t {
    int status = 200;  ///< HTTP status.
    std::string error;  ///< Error code (DESIGN 4.4) when status >= 400.
    std::string message;  ///< Human-readable error message.
    nlohmann::json extra = nlohmann::json::object();  ///< Additional fields of the error object.
    std::optional<nlohmann::json> json;  ///< JSON body of a successful response.
    std::string content_type;  ///< Media type of a raw body.
    std::string body;  ///< Raw body.
    std::vector<std::pair<std::string, std::string>> headers;  ///< Extra response headers.

    /**
     * @brief Build an error reply.
     *
     * @param status HTTP status.
     * @param error Error code.
     * @param message Message.
     * @return Reply.
     */
    static reply_t failure(int status, std::string error, std::string message) {
      reply_t reply;
      reply.status = status;
      reply.error = std::move(error);
      reply.message = std::move(message);
      return reply;
    }

    /**
     * @brief Build a JSON success reply.
     *
     * @param status HTTP status.
     * @param json Body.
     * @return Reply.
     */
    static reply_t success(int status, nlohmann::json json) {
      reply_t reply;
      reply.status = status;
      reply.json = std::move(json);
      return reply;
    }
  };
}  // namespace sds
