#ifndef SIMPLE_WEB_SERVER_HTTP_HPP
#define SIMPLE_WEB_SERVER_HTTP_HPP

#include "sds_http_rs/ffi.h"
#include "utility.hpp"
#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <istream>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <ostream>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <utility>
#include <vector>

namespace SimpleWeb {
  using error_code = std::error_code;
  using system_error = std::system_error;

  namespace error {
    enum errc {
      operation_aborted = SDS_HTTP_ERR_OPERATION_ABORTED,
      eof = SDS_HTTP_ERR_EOF,
      protocol_error = SDS_HTTP_ERR_PROTOCOL,
      message_size = SDS_HTTP_ERR_MESSAGE_SIZE,
      timed_out = SDS_HTTP_ERR_TIMED_OUT,
      tls_error = SDS_HTTP_ERR_TLS,
      io_error = SDS_HTTP_ERR_IO,
    };

    class ErrorCategory : public std::error_category {
    public:
      const char *name() const noexcept override {
        return "simple_web";
      }

      std::string message(int ev) const override {
        switch (static_cast<errc>(ev)) {
          case operation_aborted:
            return "Operation aborted";
          case eof:
            return "End of file";
          case protocol_error:
            return "HTTP protocol error";
          case message_size:
            return "Message size exceeded";
          case timed_out:
            return "Timed out";
          case tls_error:
            return "TLS error";
          case io_error:
          default:
            return "I/O error";
        }
      }
    };

    inline const ErrorCategory &error_category() noexcept {
      static const ErrorCategory instance;
      return instance;
    }

    inline std::error_code make_error_code(errc e) noexcept {
      return {static_cast<int>(e), error_category()};
    }

    inline std::error_code make_error_code(SdsHttpErrorKind kind) noexcept {
      switch (kind) {
        case SDS_HTTP_ERR_NONE:
          return {};
        case SDS_HTTP_ERR_OPERATION_ABORTED:
          return make_error_code(operation_aborted);
        case SDS_HTTP_ERR_EOF:
          return make_error_code(eof);
        case SDS_HTTP_ERR_PROTOCOL:
          return make_error_code(protocol_error);
        case SDS_HTTP_ERR_MESSAGE_SIZE:
          return make_error_code(message_size);
        case SDS_HTTP_ERR_TIMED_OUT:
          return make_error_code(timed_out);
        case SDS_HTTP_ERR_TLS:
          return make_error_code(tls_error);
        case SDS_HTTP_ERR_IO:
        default:
          return make_error_code(io_error);
      }
    }
  }  // namespace error

  inline std::error_code make_error_code(error::errc e) noexcept {
    return error::make_error_code(e);
  }
}  // namespace SimpleWeb

namespace std {
  template <>
  struct is_error_code_enum<SimpleWeb::error::errc> : std::true_type {};
}  // namespace std

namespace SimpleWeb {
  class IpAddress {
    std::string address_;
    bool is_v6_ {false};

  public:
    IpAddress() = default;

    explicit IpAddress(std::string addr)
        : address_(std::move(addr)),
          is_v6_(address_.find(':') != std::string::npos) {}

    static IpAddress from_string(std::string addr) {
      return IpAddress(std::move(addr));
    }

    std::string to_string() const {
      return address_;
    }

    bool is_v4() const noexcept {
      return !address_.empty() && !is_v6_;
    }

    bool is_v6() const noexcept {
      return is_v6_;
    }

    bool operator==(const IpAddress &other) const noexcept {
      return address_ == other.address_;
    }

    bool operator!=(const IpAddress &other) const noexcept {
      return !(*this == other);
    }

    bool operator<(const IpAddress &other) const noexcept {
      return address_ < other.address_;
    }
  };

  class Endpoint {
    IpAddress address_;
    std::uint16_t port_ {0};

  public:
    Endpoint() = default;

    Endpoint(IpAddress addr, std::uint16_t port)
        : address_(std::move(addr)), port_(port) {}

    const IpAddress &address() const noexcept {
      return address_;
    }

    std::uint16_t port() const noexcept {
      return port_;
    }

    bool operator==(const Endpoint &other) const noexcept {
      return port_ == other.port_ && address_ == other.address_;
    }

    bool operator!=(const Endpoint &other) const noexcept {
      return !(*this == other);
    }

    bool operator<(const Endpoint &other) const noexcept {
      if (address_ != other.address_) {
        return address_ < other.address_;
      }
      return port_ < other.port_;
    }
  };

  class HTTP {};
  class HTTPS {};

  class regex_orderable : public std::regex {
  public:
    std::string str;

    regex_orderable(const char *regex_cstr) : std::regex(regex_cstr), str(regex_cstr) {}

    regex_orderable(std::string regex_str) : std::regex(regex_str), str(std::move(regex_str)) {}

    bool operator<(const regex_orderable &rhs) const noexcept {
      return str < rhs.str;
    }
  };

  template <class socket_type>
  class ServerBase {
  protected:
    struct CxxConnection {
      std::uint64_t id {0};
      Endpoint local_ep;
      Endpoint remote_ep;
      std::mutex ctx_mutex;
      std::shared_ptr<void> ctx;

      CxxConnection(std::uint64_t conn_id, Endpoint local, Endpoint remote)
          : id(conn_id), local_ep(std::move(local)), remote_ep(std::move(remote)) {}

      std::shared_ptr<void> get_context() noexcept {
        std::lock_guard lock(ctx_mutex);
        return ctx;
      }

      void set_context(std::shared_ptr<void> next) noexcept {
        std::lock_guard lock(ctx_mutex);
        ctx = std::move(next);
      }
    };

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

      void set_data(const std::uint8_t *bytes, std::size_t len) {
        if (bytes && len > 0) {
          data_.assign(reinterpret_cast<const char *>(bytes), len);
        } else {
          data_.clear();
        }
        streambuf_.str(data_);
        this->clear();
      }

      std::size_t size() const noexcept {
        return data_.size();
      }

      std::string string() const noexcept {
        return data_;
      }
    };

    class Response : public std::ostream {
      std::stringbuf streambuf_;
      std::mutex mutex_;
      SdsHttpResponseSender *sender_ {nullptr};
      bool aborted_ {false};

      static bool is_tchar(unsigned char ch) noexcept {
        return (ch >= '0' && ch <= '9') ||
               (ch >= 'A' && ch <= 'Z') ||
               (ch >= 'a' && ch <= 'z') ||
               ch == '!' || ch == '#' || ch == '$' || ch == '%' || ch == '&' ||
               ch == '\'' || ch == '*' || ch == '+' || ch == '-' || ch == '.' ||
               ch == '^' || ch == '_' || ch == '`' || ch == '|' || ch == '~';
      }

      static bool is_valid_header_name(std::string_view name) noexcept {
        return !name.empty() && std::all_of(name.begin(), name.end(), [](unsigned char c) {
          return is_tchar(c);
        });
      }

      static bool is_valid_header_value(std::string_view value) noexcept {
        return std::all_of(value.begin(), value.end(), [](unsigned char c) {
          return c == '\t' || (c >= 0x20 && c <= 0x7e);
        });
      }

      void write_http_response(StatusCode status_code_value, std::string_view content, const CaseInsensitiveMultimap &header) {
        const auto &status_str = SimpleWeb::status_code(status_code_value);
        if (status_str.empty() || !is_valid_header_value(status_str)) {
          std::lock_guard lock(mutex_);
          aborted_ = true;
          return;
        }
        for (const auto &field : header) {
          if (!is_valid_header_name(field.first) || !is_valid_header_value(field.second)) {
            std::lock_guard lock(mutex_);
            aborted_ = true;
            return;
          }
        }

        std::string head = "HTTP/1.1 " + status_str + "\r\n";
        bool has_content_length = header.find("Content-Length") != header.end();
        if (!has_content_length) {
          head += "Content-Length: " + std::to_string(content.size()) + "\r\n";
        }
        for (const auto &field : header) {
          head += field.first;
          head += ": ";
          head += field.second;
          head += "\r\n";
        }
        head += "\r\n";

        std::lock_guard lock(mutex_);
        if (aborted_) {
          return;
        }
        if (!head.empty()) {
          streambuf_.sputn(head.data(), static_cast<std::streamsize>(head.size()));
        }
        if (!content.empty()) {
          streambuf_.sputn(content.data(), static_cast<std::streamsize>(content.size()));
        }
      }

      std::string take_wire_locked() {
#if __cplusplus >= 202002L
        return std::move(streambuf_).str();
#else
        std::string out = streambuf_.str();
        streambuf_.str(std::string {});
        return out;
#endif
      }

    public:
      using std::ostream::write;

      bool close_connection_after_response {false};

      explicit Response(SdsHttpResponseSender *sender) noexcept
          : std::ostream(nullptr), sender_(sender) {
        this->rdbuf(&streambuf_);
      }

      ~Response() override {
        SdsHttpResponseSender *sender = nullptr;
        bool aborted = false;
        bool close_conn = false;
        std::string wire;
        {
          std::lock_guard lock(mutex_);
          sender = sender_;
          sender_ = nullptr;
          aborted = aborted_;
          close_conn = close_connection_after_response;
          if (sender && !aborted) {
            wire = take_wire_locked();
          }
        }
        if (!sender) {
          return;
        }
        if (aborted || wire.empty()) {
          sds_http_response_abort(sender);
        } else {
          sds_http_response_send(
            sender,
            reinterpret_cast<const std::uint8_t *>(wire.data()),
            wire.size(),
            close_conn
          );
        }
      }

      std::size_t size() noexcept {
        std::lock_guard lock(mutex_);
        const auto pos = streambuf_.pubseekoff(0, std::ios_base::cur, std::ios_base::out);
        return pos > 0 ? static_cast<std::size_t>(pos) : 0;
      }

      void write(StatusCode status_code_value, const CaseInsensitiveMultimap &header = CaseInsensitiveMultimap()) {
        write_http_response(status_code_value, std::string_view {}, header);
      }

      void write(StatusCode status_code_value, const std::string &content, const CaseInsensitiveMultimap &header = CaseInsensitiveMultimap()) {
        write_http_response(status_code_value, content, header);
      }

      void write(StatusCode status_code_value, std::istream &content, const CaseInsensitiveMultimap &header = CaseInsensitiveMultimap()) {
        std::ostringstream oss;
        if (content.rdbuf() && content.peek() != std::istream::traits_type::eof()) {
          oss << content.rdbuf();
        }
        write_http_response(status_code_value, oss.str(), header);
      }

      void write(const std::string &content, const CaseInsensitiveMultimap &header = CaseInsensitiveMultimap()) {
        write_http_response(StatusCode::success_ok, content, header);
      }

      void write(std::istream &content, const CaseInsensitiveMultimap &header = CaseInsensitiveMultimap()) {
        write(StatusCode::success_ok, content, header);
      }

      void write(const CaseInsensitiveMultimap &header) {
        write_http_response(StatusCode::success_ok, std::string_view {}, header);
      }

      void send(std::function<void(const error_code &)> callback = nullptr) {
        SdsHttpResponseSender *sender = nullptr;
        bool aborted = false;
        bool close_conn = false;
        std::string wire;
        {
          std::lock_guard lock(mutex_);
          sender = sender_;
          sender_ = nullptr;
          aborted = aborted_;
          close_conn = close_connection_after_response;
          if (sender && !aborted) {
            wire = take_wire_locked();
          }
        }
        if (sender) {
          if (aborted || wire.empty()) {
            sds_http_response_abort(sender);
          } else {
            sds_http_response_send(
              sender,
              reinterpret_cast<const std::uint8_t *>(wire.data()),
              wire.size(),
              close_conn
            );
          }
        }
        if (callback) {
          callback(aborted ? error::make_error_code(error::operation_aborted) : error_code {});
        }
      }

      void abort() noexcept {
        SdsHttpResponseSender *sender = nullptr;
        {
          std::lock_guard lock(mutex_);
          aborted_ = true;
          sender = sender_;
          sender_ = nullptr;
        }
        if (sender) {
          sds_http_response_abort(sender);
        }
      }

      SdsHttpRawStream *upgrade_raw(
        const std::string &http_response_head,
        std::size_t queue_capacity,
        void (*on_client_data)(void *user_data, const std::uint8_t *data, std::size_t len),
        void (*on_closed)(void *user_data),
        void *user_data
      ) noexcept {
        SdsHttpResponseSender *sender = nullptr;
        {
          std::lock_guard lock(mutex_);
          if (aborted_ || !sender_) {
            return nullptr;
          }
          sender = sender_;
          sender_ = nullptr;
        }
        return sds_http_response_upgrade(
          sender,
          reinterpret_cast<const std::uint8_t *>(http_response_head.data()),
          http_response_head.size(),
          queue_capacity,
          on_client_data,
          on_closed,
          user_data
        );
      }
    };

    class Request {
      std::weak_ptr<CxxConnection> conn_;
      std::uint64_t connection_id_ {0};
      Endpoint local_endpoint_;
      Endpoint remote_endpoint_;

    public:
      std::string method;
      std::string path;
      std::string query_string;
      std::string http_version;
      std::string raw_header;
      Content content;
      CaseInsensitiveMultimap header;
      std::smatch path_match;
      std::shared_ptr<void> admission_context;
      std::function<bool(std::size_t)> reserve_response;

      explicit Request(std::shared_ptr<CxxConnection> conn)
          : conn_(conn),
            connection_id_(conn ? conn->id : 0),
            local_endpoint_(conn ? conn->local_ep : Endpoint {}),
            remote_endpoint_(conn ? conn->remote_ep : Endpoint {}) {}

      std::uint64_t connection_id() const noexcept {
        return connection_id_;
      }

      Endpoint local_endpoint() const noexcept {
        return local_endpoint_;
      }

      Endpoint remote_endpoint() const noexcept {
        return remote_endpoint_;
      }

      std::shared_ptr<void> connection_context() const noexcept {
        if (auto c = conn_.lock()) {
          return c->get_context();
        }
        return nullptr;
      }

      void connection_context(std::shared_ptr<void> ctx) noexcept {
        if (auto c = conn_.lock()) {
          c->set_context(std::move(ctx));
        }
      }

      CaseInsensitiveMultimap parse_query_string() const noexcept {
        return QueryString::parse(query_string);
      }

      bool header_matches(const std::string &key, const std::string &val) const {
        const auto [begin, end] = header.equal_range(key);
        for (auto it = begin; it != end; ++it) {
          if (case_insensitive_equal(it->second, val)) {
            return true;
          }
        }
        return false;
      }
    };

    class Config {
      friend class ServerBase<socket_type>;

      explicit Config(unsigned short port) noexcept : port(port) {}

    public:
      unsigned short port;
      std::size_t thread_pool_size {1};
      long timeout_request {5};
      long timeout_content {300};
      std::size_t max_request_streambuf_size {std::numeric_limits<std::size_t>::max()};
      std::size_t max_request_header_size {64 * 1024};
      std::string address;
      bool reuse_address {true};
      bool fast_open {false};
      bool is_https {std::is_base_of_v<HTTPS, socket_type>};
      std::string cert_file;
      std::string key_file;
      std::string verify_file;
      bool require_client_cert {false};
    };

    Config config;

    std::map<regex_orderable, std::map<std::string, std::function<void(std::shared_ptr<Response>, std::shared_ptr<Request>)>>> resource;
    std::map<std::string, std::function<void(std::shared_ptr<Response>, std::shared_ptr<Request>)>> default_resource;

    std::function<void(std::shared_ptr<Request>, const error_code &)> on_error;
    std::function<void(std::shared_ptr<Request>)> on_upgrade;
    std::function<bool(std::shared_ptr<Request>)> on_connection_accepted;
    std::function<bool(std::shared_ptr<Request>)> on_connection_authenticated;
    std::function<void(std::uint64_t)> on_connection_closed;
    std::function<bool(std::uint64_t, const std::uint8_t *, std::size_t)> on_verify_client;
    std::function<void(std::shared_ptr<Response>, std::shared_ptr<Request>)> on_verify_failed;
    std::function<bool(std::shared_ptr<Request>)> on_request_header;

  protected:
    std::shared_ptr<ScopeRunner> handler_runner;

  private:
    struct CxxConnectionHolder {
      std::shared_ptr<CxxConnection> conn;
      std::shared_ptr<Request> conn_req;
    };

    std::mutex state_mutex_;
    std::condition_variable start_done_cv_;
    SdsHttpServer *rust_server_ {nullptr};
    bool in_start_ {false};
    bool stop_requested_ {false};
    std::function<void(unsigned short)> on_bound_callback_;

    static std::string copy_bytes(const std::uint8_t *ptr, std::size_t len) {
      if (!ptr || len == 0) {
        return {};
      }
      return {reinterpret_cast<const char *>(ptr), len};
    }

    static void cb_on_bound(void *user_data, std::uint16_t port) {
      auto *self = static_cast<ServerBase *>(user_data);
      if (!self || !self->on_bound_callback_) {
        return;
      }
      try {
        self->on_bound_callback_(port);
      } catch (...) {
      }
    }

    static void *cb_create_connection(
      void * /*user_data*/,
      std::uint64_t conn_id,
      const std::uint8_t *local_addr,
      std::size_t local_addr_len,
      std::uint16_t local_port,
      const std::uint8_t *remote_addr,
      std::size_t remote_addr_len,
      std::uint16_t remote_port
    ) {
      try {
        Endpoint local {IpAddress::from_string(copy_bytes(local_addr, local_addr_len)), local_port};
        Endpoint remote {IpAddress::from_string(copy_bytes(remote_addr, remote_addr_len)), remote_port};
        auto conn = std::make_shared<CxxConnection>(conn_id, std::move(local), std::move(remote));
        auto conn_req = std::make_shared<Request>(conn);
        return new CxxConnectionHolder {std::move(conn), std::move(conn_req)};
      } catch (...) {
        return nullptr;
      }
    }

    static void cb_drop_connection(void *user_data, void *cxx_conn) {
      auto *holder = static_cast<CxxConnectionHolder *>(cxx_conn);
      if (!holder) {
        return;
      }
      auto *self = static_cast<ServerBase *>(user_data);
      const std::uint64_t conn_id = holder->conn ? holder->conn->id : 0;
      if (self && self->on_connection_closed && conn_id != 0) {
        try {
          self->on_connection_closed(conn_id);
        } catch (...) {
        }
      }
      delete holder;
    }

    static bool cb_on_connection_accepted(void *user_data, void *cxx_conn) {
      auto *self = static_cast<ServerBase *>(user_data);
      auto *holder = static_cast<CxxConnectionHolder *>(cxx_conn);
      if (!self || !holder) {
        return false;
      }
      if (!self->on_connection_accepted) {
        return true;
      }
      auto lock = self->handler_runner->continue_lock();
      if (!lock) {
        return false;
      }
      try {
        return self->on_connection_accepted(holder->conn_req);
      } catch (...) {
        return false;
      }
    }

    static bool cb_on_verify_client(
      void *user_data,
      std::uint64_t conn_id,
      const std::uint8_t *cert_der,
      std::size_t cert_der_len
    ) {
      auto *self = static_cast<ServerBase *>(user_data);
      if (!self || !self->on_verify_client) {
        return true;
      }
      auto lock = self->handler_runner->continue_lock();
      if (!lock) {
        return false;
      }
      try {
        return self->on_verify_client(conn_id, cert_der, cert_der_len);
      } catch (...) {
        return false;
      }
    }

    static void cb_on_verify_failed(void *user_data, void *cxx_conn, SdsHttpResponseSender *resp_sender) {
      auto *self = static_cast<ServerBase *>(user_data);
      auto *holder = static_cast<CxxConnectionHolder *>(cxx_conn);
      if (!self || !holder) {
        if (resp_sender) {
          sds_http_response_abort(resp_sender);
        }
        return;
      }
      auto resp = std::make_shared<Response>(resp_sender);
      auto lock = self->handler_runner->continue_lock();
      if (!lock || !self->on_verify_failed) {
        resp->abort();
        return;
      }
      try {
        self->on_verify_failed(resp, holder->conn_req);
      } catch (...) {
        resp->abort();
      }
    }

    static bool cb_on_connection_authenticated(void *user_data, void *cxx_conn) {
      auto *self = static_cast<ServerBase *>(user_data);
      auto *holder = static_cast<CxxConnectionHolder *>(cxx_conn);
      if (!self || !holder) {
        return false;
      }
      if (!self->on_connection_authenticated) {
        return true;
      }
      auto lock = self->handler_runner->continue_lock();
      if (!lock) {
        return false;
      }
      try {
        return self->on_connection_authenticated(holder->conn_req);
      } catch (...) {
        return false;
      }
    }

    static void *cb_create_request(void * /*user_data*/, void *cxx_conn, const SdsHttpRequestHead *head) {
      auto *holder = static_cast<CxxConnectionHolder *>(cxx_conn);
      if (!holder || !head) {
        return nullptr;
      }
      try {
        auto req = std::make_shared<Request>(holder->conn);
        req->method = copy_bytes(head->method, head->method_len);
        req->path = copy_bytes(head->path, head->path_len);
        req->query_string = copy_bytes(head->query_string, head->query_string_len);
        req->http_version = copy_bytes(head->http_version, head->http_version_len);
        req->raw_header = copy_bytes(head->raw_header, head->raw_header_len);
        if (head->headers && head->header_count > 0) {
          for (std::size_t i = 0; i < head->header_count; ++i) {
            req->header.emplace(
              copy_bytes(head->headers[i].name, head->headers[i].name_len),
              copy_bytes(head->headers[i].value, head->headers[i].value_len)
            );
          }
        }
        return new std::shared_ptr<Request>(std::move(req));
      } catch (...) {
        return nullptr;
      }
    }

    static void cb_drop_request(void * /*user_data*/, void *cxx_req) {
      delete static_cast<std::shared_ptr<Request> *>(cxx_req);
    }

    static bool cb_on_request_header(void *user_data, void *cxx_req) {
      auto *self = static_cast<ServerBase *>(user_data);
      auto *req_ptr = static_cast<std::shared_ptr<Request> *>(cxx_req);
      if (!self || !req_ptr || !*req_ptr) {
        return false;
      }
      if (!self->on_request_header) {
        return true;
      }
      auto lock = self->handler_runner->continue_lock();
      if (!lock) {
        return false;
      }
      try {
        return self->on_request_header(*req_ptr);
      } catch (...) {
        return false;
      }
    }

    static void cb_attach_request_body(void * /*user_data*/, void *cxx_req, const std::uint8_t *body, std::size_t body_len) {
      auto *req_ptr = static_cast<std::shared_ptr<Request> *>(cxx_req);
      if (!req_ptr || !*req_ptr) {
        return;
      }
      try {
        (*req_ptr)->content.set_data(body, body_len);
      } catch (...) {
      }
    }

    static void cb_dispatch_request(void *user_data, void *cxx_req, SdsHttpResponseSender *resp_sender) {
      auto *self = static_cast<ServerBase *>(user_data);
      auto *req_ptr = static_cast<std::shared_ptr<Request> *>(cxx_req);
      if (!self || !req_ptr || !*req_ptr) {
        if (resp_sender) {
          sds_http_response_abort(resp_sender);
        }
        return;
      }

      auto req = *req_ptr;
      auto resp = std::make_shared<Response>(resp_sender);
      auto lock = self->handler_runner->continue_lock();
      if (!lock) {
        resp->abort();
        return;
      }

      try {
        for (const auto &res_pair : self->resource) {
          auto it_method = res_pair.second.find(req->method);
          if (it_method == res_pair.second.end()) {
            continue;
          }
          std::smatch sm_res;
          if (std::regex_match(req->path, sm_res, res_pair.first)) {
            req->path_match = std::move(sm_res);
            it_method->second(std::move(resp), std::move(req));
            return;
          }
        }
        auto it_def = self->default_resource.find(req->method);
        if (it_def != self->default_resource.end()) {
          it_def->second(std::move(resp), std::move(req));
          return;
        }
        resp->abort();
      } catch (...) {
        resp->abort();
      }
    }

    static void cb_on_error(
      void *user_data,
      void *cxx_conn,
      void *cxx_req,
      SdsHttpErrorKind kind,
      const std::uint8_t * /*msg*/,
      std::size_t /*msg_len*/
    ) {
      auto *self = static_cast<ServerBase *>(user_data);
      if (!self || !self->on_error) {
        return;
      }
      auto lock = self->handler_runner->continue_lock();
      if (!lock) {
        return;
      }
      std::shared_ptr<Request> req;
      if (auto *req_ptr = static_cast<std::shared_ptr<Request> *>(cxx_req)) {
        req = *req_ptr;
      } else if (auto *holder = static_cast<CxxConnectionHolder *>(cxx_conn)) {
        req = holder->conn_req;
      }
      try {
        self->on_error(std::move(req), error::make_error_code(kind));
      } catch (...) {
      }
    }

  protected:
    explicit ServerBase(unsigned short port) noexcept
        : config(port), handler_runner(std::make_shared<ScopeRunner>()) {}

  public:
    virtual ~ServerBase() {
      stop();
      std::unique_lock lock(state_mutex_);
      start_done_cv_.wait(lock, [this]() {
        return !in_start_;
      });
      if (handler_runner) {
        handler_runner->stop();
      }
    }

    void start(const std::function<void(unsigned short)> &callback = nullptr) {
      SdsHttpServer *created = nullptr;
      {
        std::lock_guard lock(state_mutex_);
        if (stop_requested_) {
          stop_requested_ = false;
          return;
        }
        on_bound_callback_ = callback;

        SdsHttpServerConfig cfg {};
        cfg.port = config.port;
        cfg.thread_pool_size = config.thread_pool_size;
        cfg.timeout_request_secs = static_cast<std::int64_t>(config.timeout_request);
        cfg.timeout_content_secs = static_cast<std::int64_t>(config.timeout_content);
        cfg.max_request_streambuf_size = config.max_request_streambuf_size;
        cfg.max_request_header_size = config.max_request_header_size;
        cfg.address = config.address.c_str();
        cfg.reuse_address = config.reuse_address;
        cfg.fast_open = config.fast_open;
        cfg.is_https = config.is_https;
        cfg.cert_file = config.cert_file.empty() ? nullptr : config.cert_file.c_str();
        cfg.key_file = config.key_file.empty() ? nullptr : config.key_file.c_str();
        cfg.verify_file = config.verify_file.empty() ? nullptr : config.verify_file.c_str();
        cfg.require_client_cert = config.require_client_cert || static_cast<bool>(on_verify_client);

        SdsHttpServerCallbacks cbs {};
        cbs.user_data = this;
        cbs.on_bound = &cb_on_bound;
        cbs.create_connection = &cb_create_connection;
        cbs.drop_connection = &cb_drop_connection;
        cbs.on_connection_accepted = &cb_on_connection_accepted;
        cbs.on_verify_client = on_verify_client ? &cb_on_verify_client : nullptr;
        cbs.on_verify_failed = &cb_on_verify_failed;
        cbs.on_connection_authenticated = &cb_on_connection_authenticated;
        cbs.create_request = &cb_create_request;
        cbs.drop_request = &cb_drop_request;
        cbs.on_request_header = &cb_on_request_header;
        cbs.attach_request_body = &cb_attach_request_body;
        cbs.dispatch_request = &cb_dispatch_request;
        cbs.on_error = &cb_on_error;

        SdsHttpBytes create_err {};
        created = sds_http_server_create(&cfg, &cbs, &create_err);
        std::string create_err_msg = bytes_to_string_and_free(create_err);
        if (!created) {
          throw std::runtime_error(create_err_msg.empty() ? "failed to create HTTP server" : create_err_msg);
        }

        rust_server_ = created;
        in_start_ = true;
      }

      SdsHttpBytes start_err {};
      const bool ok = sds_http_server_start(created, &start_err);
      const std::string start_err_msg = bytes_to_string_and_free(start_err);

      {
        std::lock_guard lock(state_mutex_);
        rust_server_ = nullptr;
      }
      sds_http_server_destroy(created);
      {
        std::lock_guard lock(state_mutex_);
        in_start_ = false;
        stop_requested_ = false;
      }
      start_done_cv_.notify_all();

      if (!ok) {
        throw std::runtime_error(start_err_msg.empty() ? "HTTP server exited with error" : start_err_msg);
      }
    }

    void stop() {
      std::lock_guard lock(state_mutex_);
      stop_requested_ = true;
      if (rust_server_) {
        sds_http_server_stop(rust_server_);
      }
    }
  };

  template <class socket_type>
  class Server : public ServerBase<socket_type> {};

  template <>
  class Server<HTTP> : public ServerBase<HTTP> {
  public:
    Server() noexcept : ServerBase<HTTP>(80) {
      config.is_https = false;
    }
  };
}  // namespace SimpleWeb

#endif  // SIMPLE_WEB_SERVER_HTTP_HPP
