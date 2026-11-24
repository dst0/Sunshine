#ifndef SIMPLE_WEB_CLIENT_HTTPS_HPP
#define SIMPLE_WEB_CLIENT_HTTPS_HPP

#include "client_http.hpp"
#include <string>

namespace SimpleWeb {
  template <>
  class Client<HTTPS> : public ClientBase<HTTPS> {
  public:
    explicit Client(
      const std::string &server_port_path,
      bool verify_certificate = true,
      const std::string &certification_file = std::string(),
      const std::string &private_key_file = std::string(),
      const std::string &verify_file = std::string()
    )
        : ClientBase<HTTPS>(server_port_path, 443) {
      is_https_ = true;
      verify_certificate_ = verify_certificate;
      cert_file_ = certification_file;
      key_file_ = private_key_file;
      verify_file_ = verify_file;
      init_rust_client();
    }
  };
}  // namespace SimpleWeb

#endif  // SIMPLE_WEB_CLIENT_HTTPS_HPP
