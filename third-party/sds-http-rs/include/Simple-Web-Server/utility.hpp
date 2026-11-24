#ifndef SIMPLE_WEB_UTILITY_HPP
#define SIMPLE_WEB_UTILITY_HPP

#include "sds_http_rs/ffi.h"
#include "status_code.hpp"
#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>

#ifdef __SSE2__
  #include <emmintrin.h>
#endif

namespace SimpleWeb {
  using string_view = std::string_view;

  inline bool case_insensitive_equal(const std::string &str1, const std::string &str2) noexcept {
    return str1.size() == str2.size() &&
           std::equal(str1.begin(), str1.end(), str2.begin(), [](unsigned char a, unsigned char b) {
             return std::tolower(a) == std::tolower(b);
           });
  }

  class CaseInsensitiveEqual {
  public:
    bool operator()(const std::string &str1, const std::string &str2) const noexcept {
      return case_insensitive_equal(str1, str2);
    }
  };

  class CaseInsensitiveHash {
  public:
    std::size_t operator()(const std::string &str) const noexcept {
      std::size_t h = 0;
      std::hash<int> hash;
      for (unsigned char c : str) {
        h ^= hash(std::tolower(c)) + 0x9e3779b9 + (h << 6) + (h >> 2);
      }
      return h;
    }
  };

  using CaseInsensitiveMultimap = std::unordered_multimap<std::string, std::string, CaseInsensitiveHash, CaseInsensitiveEqual>;

  inline std::string bytes_to_string_and_free(SdsHttpBytes buf) {
    std::string out;
    if (buf.data && buf.len > 0) {
      out.assign(reinterpret_cast<const char *>(buf.data), buf.len);
    }
    sds_http_bytes_free(buf);
    return out;
  }

  class Percent {
  public:
    static std::string encode(const std::string &value) noexcept {
      if (value.empty()) {
        return {};
      }
      return bytes_to_string_and_free(sds_http_percent_encode(
        reinterpret_cast<const std::uint8_t *>(value.data()),
        value.size()
      ));
    }

    static std::string decode(const std::string &value) noexcept {
      if (value.empty()) {
        return {};
      }
      return bytes_to_string_and_free(sds_http_percent_decode(
        reinterpret_cast<const std::uint8_t *>(value.data()),
        value.size()
      ));
    }
  };

  class QueryString {
  public:
    static std::string create(const CaseInsensitiveMultimap &fields) noexcept {
      std::string result;
      bool first = true;
      for (const auto &field : fields) {
        result += (!first ? "&" : "") + field.first + '=' + Percent::encode(field.second);
        first = false;
      }
      return result;
    }

    static CaseInsensitiveMultimap parse(const std::string &query_string) noexcept {
      CaseInsensitiveMultimap result;
      if (query_string.empty()) {
        return result;
      }
      auto vec = sds_http_parse_query_string(
        reinterpret_cast<const std::uint8_t *>(query_string.data()),
        query_string.size()
      );
      for (std::size_t i = 0; i < vec.len; ++i) {
        std::string name;
        if (vec.items[i].name.data && vec.items[i].name.len > 0) {
          name.assign(reinterpret_cast<const char *>(vec.items[i].name.data), vec.items[i].name.len);
        }
        std::string value;
        if (vec.items[i].value.data && vec.items[i].value.len > 0) {
          value.assign(reinterpret_cast<const char *>(vec.items[i].value.data), vec.items[i].value.len);
        }
        if (!name.empty()) {
          result.emplace(std::move(name), std::move(value));
        }
      }
      sds_http_header_vec_free(vec);
      return result;
    }
  };

  inline void spin_loop_pause() noexcept {
#ifdef __SSE2__
    _mm_pause();
#endif
  }

  class ScopeRunner {
    std::atomic<long> count;

  public:
    class SharedLock {
      friend class ScopeRunner;
      std::atomic<long> &count;
      SharedLock(std::atomic<long> &count) noexcept : count(count) {}
      SharedLock &operator=(const SharedLock &) = delete;
      SharedLock(const SharedLock &) = delete;

    public:
      ~SharedLock() noexcept {
        count.fetch_sub(1);
      }
    };

    ScopeRunner() noexcept : count(0) {}

    std::unique_ptr<SharedLock> continue_lock() noexcept {
      long expected = count;
      while (expected >= 0 && !count.compare_exchange_weak(expected, expected + 1)) {
        spin_loop_pause();
      }
      if (expected < 0) {
        return nullptr;
      }
      return std::unique_ptr<SharedLock>(new SharedLock(count));
    }

    void stop() noexcept {
      long expected = 0;
      while (!count.compare_exchange_weak(expected, -1)) {
        if (expected < 0) {
          return;
        }
        expected = 0;
        spin_loop_pause();
      }
    }
  };
}  // namespace SimpleWeb

#endif  // SIMPLE_WEB_UTILITY_HPP
