#ifndef SIMPLE_WEB_CLIENT_HTTP_HPP
#define SIMPLE_WEB_CLIENT_HTTP_HPP

#include "server_http.hpp"
#include "sds_http_rs/ffi.h"
#include "utility.hpp"
#include <algorithm>
#include <cstdint>
#include <istream>
#include <limits>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace SimpleWeb {
  template <class socket_type>
  class ClientBase {
  public:
    class Content : public std::istream {
      std::string data_;
      std::stringbuf streambuf_;

    public:
      Content() : std::istream(nullptr), streambuf_(std::ios_base::in) {
        this->rdbuf(&streambuf_);
      }

      explicit Content(std::string data)
          : std::istream(nullptr),
            data_(std::move(data)),
            streambuf_(data_, std::ios_base::in) {
        this->rdbuf(&streambuf_);
      }

      std::size_t size() const noexcept {
        return data_.size();
      }

      std::string string() const noexcept {
        return data_;
      }
    };

    class Response {
    public:
      std::string http_version;
      std::string status_code;
      CaseInsensitiveMultimap header;
      Content content;

      Response() = default;

      Response(std::string ver, std::string code, CaseInsensitiveMultimap hdrs, std::string body_str)
          : http_version(std::move(ver)),
            status_code(std::move(code)),
            header(std::move(hdrs)),
            content(std::move(body_str)) {}
    };

    class Config {
      friend class ClientBase<socket_type>;
      Config() noexcept = default;

    public:
      long timeout {0};
      long timeout_connect {0};
      std::size_t max_response_streambuf_size {std::numeric_limits<std::size_t>::max()};
      std::string proxy_server;
    };

    Config config;

  protected:
    std::string host_;
    std::uint16_t port_ {0};
    std::uint16_t default_port_ {80};
    std::string base_path_;
    bool is_https_ {std::is_base_of_v<HTTPS, socket_type>};
    bool verify_certificate_ {true};
    std::string cert_file_;
    std::string key_file_;
    std::string verify_file_;

    std::mutex client_mutex_;
    std::shared_ptr<SdsHttpClient> rust_client_;

    static std::uint16_t parse_port_checked(std::string_view port_str) {
      if (port_str.empty() || !std::all_of(port_str.begin(), port_str.end(), [](unsigned char c) {
            return c >= '0' && c <= '9';
          })) {
        throw system_error(error::make_error_code(error::protocol_error), "invalid port");
      }
      unsigned long parsed = 0;
      for (unsigned char c : port_str) {
        parsed = parsed * 10 + static_cast<unsigned long>(c - '0');
        if (parsed > 65535) {
          throw system_error(error::make_error_code(error::protocol_error), "invalid port");
        }
      }
      if (parsed == 0) {
        throw system_error(error::make_error_code(error::protocol_error), "invalid port");
      }
      return static_cast<std::uint16_t>(parsed);
    }

    void parse_host_port(const std::string &server_port_path, std::uint16_t default_port) {
      default_port_ = default_port;
      std::string host_port = server_port_path;
      const auto slash_pos = host_port.find('/');
      if (slash_pos != std::string::npos) {
        base_path_ = host_port.substr(slash_pos);
        if (base_path_ == "/") {
          base_path_.clear();
        }
        host_port.erase(slash_pos);
      }

      if (!host_port.empty() && host_port.front() == '[') {
        const auto close_bracket = host_port.find(']');
        if (close_bracket == std::string::npos) {
          throw system_error(error::make_error_code(error::protocol_error), "invalid IPv6 host literal");
        }
        host_ = host_port.substr(1, close_bracket - 1);
        if (close_bracket + 1 == host_port.size()) {
          port_ = default_port_;
        } else if (host_port[close_bracket + 1] == ':') {
          port_ = parse_port_checked(std::string_view(host_port).substr(close_bracket + 2));
        } else {
          throw system_error(error::make_error_code(error::protocol_error), "invalid host or port");
        }
        return;
      }

      const auto colon_pos = host_port.find(':');
      if (colon_pos != std::string::npos) {
        host_ = host_port.substr(0, colon_pos);
        port_ = parse_port_checked(std::string_view(host_port).substr(colon_pos + 1));
      } else {
        host_ = std::move(host_port);
        port_ = default_port_;
      }
    }

    void init_rust_client() {
      SdsHttpClientConfig cfg {};
      cfg.host = host_.c_str();
      cfg.port = port_;
      cfg.default_port = default_port_;
      cfg.is_https = is_https_;
      cfg.verify_certificate = verify_certificate_;
      cfg.cert_file = cert_file_.empty() ? nullptr : cert_file_.c_str();
      cfg.key_file = key_file_.empty() ? nullptr : key_file_.c_str();
      cfg.verify_file = verify_file_.empty() ? nullptr : verify_file_.c_str();

      SdsHttpBytes err {};
      SdsHttpClient *raw_cli = sds_http_client_create(&cfg, &err);
      std::string err_msg = bytes_to_string_and_free(err);
      if (!raw_cli) {
        throw system_error(
          error::make_error_code(is_https_ ? error::tls_error : error::io_error),
          err_msg.empty() ? "failed to initialize HTTP client" : err_msg
        );
      }
      std::lock_guard lock(client_mutex_);
      rust_client_ = std::shared_ptr<SdsHttpClient>(raw_cli, [](SdsHttpClient *p) {
        if (p) {
          sds_http_client_stop(p);
          sds_http_client_destroy(p);
        }
      });
    }

    ClientBase(const std::string &server_port_path, std::uint16_t default_port) {
      parse_host_port(server_port_path, default_port);
    }

  public:
    virtual ~ClientBase() {
      std::shared_ptr<SdsHttpClient> cli;
      {
        std::lock_guard lock(client_mutex_);
        cli = std::move(rust_client_);
      }
      if (cli) {
        sds_http_client_stop(cli.get());
      }
    }

    std::shared_ptr<Response> request(
      const std::string &method,
      const std::string &path = {"/"},
      string_view content = {},
      const CaseInsensitiveMultimap &header = CaseInsensitiveMultimap()
    ) {
      std::shared_ptr<SdsHttpClient> cli;
      {
        std::lock_guard lock(client_mutex_);
        cli = rust_client_;
      }
      if (!cli) {
        throw system_error(error::make_error_code(error::operation_aborted), "client stopped");
      }

      std::string effective_path = base_path_;
      if (path.empty()) {
        if (effective_path.empty()) {
          effective_path = "/";
        }
      } else if (path.front() == '/') {
        effective_path += path;
      } else {
        effective_path += "/" + path;
      }

      std::vector<SdsHttpHeaderRef> hdr_refs;
      hdr_refs.reserve(header.size());
      for (const auto &kv : header) {
        hdr_refs.push_back(SdsHttpHeaderRef {
          reinterpret_cast<const std::uint8_t *>(kv.first.data()),
          kv.first.size(),
          reinterpret_cast<const std::uint8_t *>(kv.second.data()),
          kv.second.size(),
        });
      }

      SdsHttpClientResponse raw = sds_http_client_request(
        cli.get(),
        reinterpret_cast<const std::uint8_t *>(method.data()),
        method.size(),
        reinterpret_cast<const std::uint8_t *>(effective_path.data()),
        effective_path.size(),
        hdr_refs.empty() ? nullptr : hdr_refs.data(),
        hdr_refs.size(),
        content.empty() ? nullptr : reinterpret_cast<const std::uint8_t *>(content.data()),
        content.size(),
        static_cast<std::int64_t>(config.timeout),
        static_cast<std::int64_t>(config.timeout_connect),
        config.max_response_streambuf_size
      );

      if (!raw.ok) {
        const auto err_kind = raw.error_kind;
        std::string msg;
        if (raw.error_message.data && raw.error_message.len > 0) {
          msg.assign(reinterpret_cast<const char *>(raw.error_message.data), raw.error_message.len);
        }
        sds_http_client_response_free(raw);
        throw system_error(error::make_error_code(err_kind), msg.empty() ? "HTTP client request failed" : msg);
      }

      std::string ver;
      if (raw.http_version.data && raw.http_version.len > 0) {
        ver.assign(reinterpret_cast<const char *>(raw.http_version.data), raw.http_version.len);
      }
      std::string status;
      if (raw.status_code.data && raw.status_code.len > 0) {
        status.assign(reinterpret_cast<const char *>(raw.status_code.data), raw.status_code.len);
      }
      CaseInsensitiveMultimap resp_headers;
      for (std::size_t i = 0; i < raw.headers.len; ++i) {
        std::string name;
        if (raw.headers.items[i].name.data && raw.headers.items[i].name.len > 0) {
          name.assign(
            reinterpret_cast<const char *>(raw.headers.items[i].name.data),
            raw.headers.items[i].name.len
          );
        }
        std::string val;
        if (raw.headers.items[i].value.data && raw.headers.items[i].value.len > 0) {
          val.assign(
            reinterpret_cast<const char *>(raw.headers.items[i].value.data),
            raw.headers.items[i].value.len
          );
        }
        resp_headers.emplace(std::move(name), std::move(val));
      }
      std::string body_str;
      if (raw.body.data && raw.body.len > 0) {
        body_str.assign(reinterpret_cast<const char *>(raw.body.data), raw.body.len);
      }
      sds_http_client_response_free(raw);

      return std::make_shared<Response>(
        std::move(ver),
        std::move(status),
        std::move(resp_headers),
        std::move(body_str)
      );
    }

    std::shared_ptr<Response> request(
      const std::string &method,
      const std::string &path,
      const CaseInsensitiveMultimap &header
    ) {
      return request(method, path, string_view {}, header);
    }

    std::shared_ptr<Response> request(
      const std::string &method,
      const std::string &path,
      std::istream &content,
      const CaseInsensitiveMultimap &header = CaseInsensitiveMultimap()
    ) {
      std::ostringstream oss;
      oss << content.rdbuf();
      return request(method, path, oss.str(), header);
    }

    void stop() noexcept {
      std::shared_ptr<SdsHttpClient> cli;
      {
        std::lock_guard lock(client_mutex_);
        cli = rust_client_;
      }
      if (cli) {
        sds_http_client_stop(cli.get());
      }
    }
  };

  template <class socket_type>
  class Client : public ClientBase<socket_type> {};

  template <>
  class Client<HTTP> : public ClientBase<HTTP> {
  public:
    explicit Client(const std::string &server_port_path)
        : ClientBase<HTTP>(server_port_path, 80) {
      is_https_ = false;
      init_rust_client();
    }
  };
}  // namespace SimpleWeb

#endif  // SIMPLE_WEB_CLIENT_HTTP_HPP
