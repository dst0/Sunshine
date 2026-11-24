#ifndef SIMPLE_WEB_SERVER_HTTPS_HPP
#define SIMPLE_WEB_SERVER_HTTPS_HPP

#include "server_http.hpp"
#include <string>

namespace SimpleWeb {
  template <>
  class Server<HTTPS> : public ServerBase<HTTPS> {
  public:
    Server(
      const std::string &certification_file,
      const std::string &private_key_file,
      const std::string &verify_file = std::string()
    )
        : ServerBase<HTTPS>(443) {
      config.is_https = true;
      config.cert_file = certification_file;
      config.key_file = private_key_file;
      config.verify_file = verify_file;
      config.require_client_cert = !verify_file.empty();
    }
  };
}  // namespace SimpleWeb

#endif  // SIMPLE_WEB_SERVER_HTTPS_HPP
