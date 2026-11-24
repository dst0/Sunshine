#ifndef SIMPLE_WEB_CRYPTO_HPP
#define SIMPLE_WEB_CRYPTO_HPP

#include "sds_http_rs/ffi.h"
#include <cstdint>
#include <string>

namespace SimpleWeb {
  class Crypto {
  public:
    class Base64 {
    public:
      static std::string encode(const std::string &input) noexcept {
        if (input.empty()) {
          return {};
        }
        auto buf = sds_http_base64_encode(
          reinterpret_cast<const std::uint8_t *>(input.data()),
          input.size()
        );
        std::string out;
        if (buf.data && buf.len > 0) {
          out.assign(reinterpret_cast<const char *>(buf.data), buf.len);
        }
        sds_http_bytes_free(buf);
        return out;
      }

      static std::string decode(const std::string &base64) noexcept {
        if (base64.empty()) {
          return {};
        }
        auto buf = sds_http_base64_decode(
          reinterpret_cast<const std::uint8_t *>(base64.data()),
          base64.size()
        );
        std::string out;
        if (buf.data && buf.len > 0) {
          out.assign(reinterpret_cast<const char *>(buf.data), buf.len);
        }
        sds_http_bytes_free(buf);
        return out;
      }
    };
  };
}  // namespace SimpleWeb

#endif  // SIMPLE_WEB_CRYPTO_HPP
