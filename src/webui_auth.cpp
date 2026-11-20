/**
 * @file src/webui_auth.cpp
 * @brief Definitions for Web UI password hashing, Basic authentication and login rate limiting.
 */
// standard includes
#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <charconv>
#include <format>
#include <stdexcept>
#include <vector>

// lib includes
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

// local includes
#include "config.h"
#include "crypto.h"
#include "httpcommon.h"
#include "logging.h"
#include "network.h"
#include "utility.h"
#include "webui_auth.h"

using namespace std::literals;

namespace webui_auth {
  namespace {
    /**
     * @brief Run PBKDF2-HMAC-SHA256.
     *
     * @param password Plain-text password.
     * @param salt Salt bytes.
     * @param iterations Iteration count.
     * @return Derived key, or no value if OpenSSL fails.
     */
    std::optional<std::string> pbkdf2(const std::string_view password, const std::string_view salt, const std::uint32_t iterations) {
      std::string key(HASH_SIZE, '\0');
      if (PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()), reinterpret_cast<const unsigned char *>(salt.data()), static_cast<int>(salt.size()), static_cast<int>(iterations), EVP_sha256(), static_cast<int>(key.size()), reinterpret_cast<unsigned char *>(key.data())) != 1) {
        return std::nullopt;
      }
      return key;
    }

    /**
     * @brief Split a string on a separator.
     *
     * @param text Text to split.
     * @param separator Separator character.
     * @return Parts, including empty ones.
     */
    std::vector<std::string_view> split(std::string_view text, const char separator) {
      std::vector<std::string_view> parts;
      while (true) {
        const auto position = text.find(separator);
        parts.push_back(text.substr(0, position));
        if (position == std::string_view::npos) {
          return parts;
        }
        text.remove_prefix(position + 1);
      }
    }

    /**
     * @brief Lower-case an ASCII string.
     *
     * @param text Text to convert.
     * @return Lower-case copy.
     */
    std::string ascii_lower(const std::string_view text) {
      std::string lower {text};
      std::ranges::transform(lower, lower.begin(), [](const unsigned char c) {
        return static_cast<char>(std::tolower(c));
      });
      return lower;
    }

    /**
     * @brief Get the per-process secret used to key cache entries.
     *
     * @return 32 random bytes generated on first use.
     */
    const std::array<unsigned char, 32> &process_key() {
      static const auto key = []() {
        std::array<unsigned char, 32> bytes {};
        if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1) {
          // Fail closed: without a secret key the request handler throws and no request authenticates.
          BOOST_LOG(error) << "Web UI: failed to generate the verification cache key"sv;
          throw std::runtime_error("RAND_bytes failed");
        }
        return bytes;
      }();
      return key;
    }

    /**
     * @brief Compute HMAC-SHA256 of a value with the per-process key.
     *
     * @param value Value to authenticate.
     * @return 32-byte MAC.
     */
    std::string keyed_digest(const std::string_view value) {
      const auto &key = process_key();
      std::string mac(EVP_MAX_MD_SIZE, '\0');
      unsigned int length = 0;
      HMAC(
        EVP_sha256(),
        key.data(),
        static_cast<int>(key.size()),
        reinterpret_cast<const unsigned char *>(value.data()),
        value.size(),
        reinterpret_cast<unsigned char *>(mac.data()),
        &length
      );
      mac.resize(length);
      return mac;
    }

    /**
     * @brief Fingerprint the currently configured credentials.
     *
     * @return MAC binding cache entries to the stored username and hash.
     */
    std::string credentials_fingerprint() {
      std::string material = ascii_lower(config::sunshine.username);
      material.push_back('\0');
      material += config::sunshine.password;
      material.push_back('\0');
      material += config::sunshine.salt;
      return keyed_digest(material);
    }

    /**
     * @brief Bounded cache of successful verifications keyed by a MAC of the Authorization header.
     */
    class verification_cache_t {
    public:
      using clock = std::chrono::steady_clock;  ///< Monotonic clock used for expiry.

      /**
       * @brief Check whether a header was successfully verified recently against the current credentials.
       *
       * @param header_mac MAC of the Authorization header.
       * @param fingerprint Fingerprint of the current credentials.
       * @param now Current time.
       * @return `true` on a valid cache hit.
       */
      bool contains(const std::string &header_mac, const std::string &fingerprint, const clock::time_point now) {
        std::scoped_lock lock {mutex_};
        const auto it = entries_.find(header_mac);
        if (it == entries_.end()) {
          return false;
        }
        if (it->second.expires_at <= now || !constant_time_equals(it->second.fingerprint, fingerprint)) {
          entries_.erase(it);
          return false;
        }
        return true;
      }

      /**
       * @brief Remember a successful verification.
       *
       * @param header_mac MAC of the Authorization header.
       * @param fingerprint Fingerprint of the credentials it was verified against.
       * @param now Current time.
       */
      void insert(const std::string &header_mac, const std::string &fingerprint, const clock::time_point now) {
        std::scoped_lock lock {mutex_};
        std::erase_if(entries_, [now](const auto &entry) {
          return entry.second.expires_at <= now;
        });
        while (entries_.size() >= VERIFICATION_CACHE_SIZE) {
          const auto oldest = std::ranges::min_element(entries_, {}, [](const auto &entry) {
            return entry.second.expires_at;
          });
          entries_.erase(oldest);
        }
        entries_.insert_or_assign(header_mac, entry_t {now + VERIFICATION_CACHE_TTL, fingerprint});
      }

      /**
       * @brief Drop all entries.
       */
      void clear() {
        std::scoped_lock lock {mutex_};
        entries_.clear();
      }

      /**
       * @brief Number of entries.
       *
       * @return Entry count.
       */
      std::size_t size() {
        std::scoped_lock lock {mutex_};
        return entries_.size();
      }

    private:
      /**
       * @brief One cached verification.
       */
      struct entry_t {
        clock::time_point expires_at;  ///< Expiry of the entry.
        std::string fingerprint;  ///< Credentials fingerprint at verification time.
      };

      std::mutex mutex_;  ///< Protects `entries_`.
      std::map<std::string, entry_t> entries_;  ///< Entries keyed by header MAC.
    };

    /**
     * @brief Get the process-wide verification cache.
     *
     * @return Cache instance.
     */
    verification_cache_t &verification_cache() {
      static verification_cache_t cache;
      return cache;
    }

    /**
     * @brief Get the process-wide login limiter.
     *
     * @return Limiter instance.
     */
    login_limiter_t &limiter() {
      static login_limiter_t instance;
      return instance;
    }

    std::atomic<std::size_t> password_evaluations {0};  ///< Count of password hash evaluations (for tests).

    /**
     * @brief Round a duration up to whole seconds (at least one).
     *
     * @param duration Remaining duration.
     * @return Whole seconds, never zero.
     */
    std::chrono::seconds ceil_seconds(const login_limiter_t::clock::duration duration) {
      return std::max(std::chrono::seconds {1}, std::chrono::ceil<std::chrono::seconds>(duration));
    }
  }  // namespace

  bool constant_time_equals(const std::string_view a, const std::string_view b) {
    // Compare digests so that the comparison time does not depend on where the inputs differ,
    // nor (beyond hashing) on their lengths.
    const auto digest_a = keyed_digest(a);
    const auto digest_b = keyed_digest(b);
    return digest_a.size() == digest_b.size() && CRYPTO_memcmp(digest_a.data(), digest_b.data(), digest_a.size()) == 0;
  }

  std::string base64_encode(const std::string_view data) {
    std::string encoded(4 * ((data.size() + 2) / 3), '\0');
    const auto length = EVP_EncodeBlock(reinterpret_cast<unsigned char *>(encoded.data()), reinterpret_cast<const unsigned char *>(data.data()), static_cast<int>(data.size()));
    encoded.resize(static_cast<std::size_t>(std::max(length, 0)));
    return encoded;
  }

  std::optional<std::string> base64_decode(const std::string_view text) {
    if (text.size() % 4 != 0) {
      return std::nullopt;
    }
    const auto padding = text.ends_with("==") ? 2u : (text.ends_with('=') ? 1u : 0u);
    for (std::size_t i = 0; i < text.size() - padding; ++i) {
      const auto c = static_cast<unsigned char>(text[i]);
      if (!std::isalnum(c) && c != '+' && c != '/') {
        return std::nullopt;
      }
    }
    if (text.empty()) {
      return std::string {};
    }

    std::string decoded(text.size() / 4 * 3, '\0');
    const auto length = EVP_DecodeBlock(reinterpret_cast<unsigned char *>(decoded.data()), reinterpret_cast<const unsigned char *>(text.data()), static_cast<int>(text.size()));
    if (length < 0 || static_cast<std::size_t>(length) < padding) {
      return std::nullopt;
    }
    decoded.resize(static_cast<std::size_t>(length) - padding);
    return decoded;
  }

  std::string hash_password(const std::string_view password, const std::uint32_t iterations) {
    const auto salt = crypto::rand(SALT_SIZE);
    const auto key = pbkdf2(password, salt, iterations);
    if (!key) {
      throw std::runtime_error("PBKDF2 failed");
    }
    return std::format("{}${}${}${}", PBKDF2_SCHEME, iterations, base64_encode(salt), base64_encode(*key));
  }

  password_match_e verify_password(const std::string_view password, const std::string_view stored_hash, const std::string_view legacy_salt) {
    if (stored_hash.starts_with(PBKDF2_SCHEME)) {
      const auto parts = split(stored_hash, '$');
      if (parts.size() != 4 || parts[0] != PBKDF2_SCHEME) {
        return password_match_e::mismatch;
      }
      std::uint32_t iterations = 0;
      const auto [end, error] = std::from_chars(parts[1].data(), parts[1].data() + parts[1].size(), iterations);
      if (error != std::errc {} || end != parts[1].data() + parts[1].size() || iterations == 0 || iterations > PBKDF2_MAX_ITERATIONS) {
        return password_match_e::mismatch;
      }
      const auto salt = base64_decode(parts[2]);
      const auto expected = base64_decode(parts[3]);
      if (!salt || salt->size() < 8 || !expected || expected->size() != HASH_SIZE) {
        return password_match_e::mismatch;
      }
      const auto actual = pbkdf2(password, *salt, iterations);
      if (!actual || CRYPTO_memcmp(actual->data(), expected->data(), HASH_SIZE) != 0) {
        return password_match_e::mismatch;
      }
      return iterations < PBKDF2_ITERATIONS ? password_match_e::match_needs_upgrade : password_match_e::match;
    }

    // Legacy format: upper-case hex of SHA-256(password + salt), as produced by util::hex().
    if (stored_hash.size() != 2 * HASH_SIZE) {
      return password_match_e::mismatch;
    }
    std::string candidate {password};
    candidate += legacy_salt;
    const auto actual = util::hex(crypto::hash(candidate)).to_string();
    std::fill(candidate.begin(), candidate.end(), '\0');
    std::string expected {stored_hash};
    std::ranges::transform(expected, expected.begin(), [](const unsigned char c) {
      return static_cast<char>(std::toupper(c));
    });
    if (actual.size() != expected.size() || CRYPTO_memcmp(actual.data(), expected.data(), actual.size()) != 0) {
      return password_match_e::mismatch;
    }
    return password_match_e::match_needs_upgrade;
  }

  std::optional<basic_credentials_t> parse_basic_authorization(std::string_view header) {
    if (header.size() > MAX_AUTHORIZATION_SIZE || header.size() < 6 || ascii_lower(header.substr(0, 5)) != "basic" || header[5] != ' ') {
      return std::nullopt;
    }
    header.remove_prefix(6);
    while (!header.empty() && header.front() == ' ') {
      header.remove_prefix(1);
    }
    while (!header.empty() && header.back() == ' ') {
      header.remove_suffix(1);
    }

    auto decoded = base64_decode(header);
    if (!decoded) {
      return std::nullopt;
    }
    const auto colon = decoded->find(':');
    if (colon == std::string::npos || colon + 1 >= decoded->size()) {
      std::fill(decoded->begin(), decoded->end(), '\0');
      return std::nullopt;
    }
    basic_credentials_t credentials {decoded->substr(0, colon), decoded->substr(colon + 1)};
    std::fill(decoded->begin(), decoded->end(), '\0');
    return credentials;
  }

  login_limiter_t::login_limiter_t(limiter_config_t config):
      config_ {config} {
  }

  std::optional<std::chrono::seconds> login_limiter_t::locked_for(const std::string &source, const clock::time_point now) {
    std::scoped_lock lock {mutex_};
    auto remaining = clock::duration::zero();
    if (global_locked_until_ > now) {
      remaining = global_locked_until_ - now;
    }
    if (const auto it = sources_.find(source); it != sources_.end() && it->second.locked_until > now) {
      remaining = std::max(remaining, it->second.locked_until - now);
    }
    if (remaining <= clock::duration::zero()) {
      return std::nullopt;
    }
    return ceil_seconds(remaining);
  }

  void login_limiter_t::record_failure(const std::string &source, const clock::time_point now) {
    std::scoped_lock lock {mutex_};

    std::erase_if(global_failures_, [&](const auto failure) {
      return failure + config_.global_window <= now;
    });
    global_failures_.push_back(now);
    if (global_failures_.size() >= config_.max_failures_global) {
      global_failures_.clear();
      global_locked_until_ = now + config_.global_lockout;
      BOOST_LOG(warning) << "Web UI: "sv << config_.max_failures_global << " failed logins from all sources within "sv
                         << std::chrono::duration_cast<std::chrono::minutes>(config_.global_window).count()
                         << " minutes -- all logins locked for "sv
                         << std::chrono::duration_cast<std::chrono::minutes>(config_.global_lockout).count() << " minutes"sv;
    }

    auto it = sources_.find(source);
    if (it == sources_.end()) {
      make_room(now);
      it = sources_.emplace(source, source_state_t {}).first;
    }
    auto &state = it->second;
    state.last_seen = now;
    std::erase_if(state.failures, [&](const auto failure) {
      return failure + config_.source_window <= now;
    });
    state.failures.push_back(now);
    BOOST_LOG(warning) << "Web UI: ["sv << source << "] -- login failed ("sv << state.failures.size() << " of "sv
                       << config_.max_failures_per_source << " allowed within "sv
                       << std::chrono::duration_cast<std::chrono::minutes>(config_.source_window).count() << " minutes)"sv;
    if (state.failures.size() >= config_.max_failures_per_source) {
      state.failures.clear();
      state.locked_until = now + config_.source_lockout;
      BOOST_LOG(warning) << "Web UI: ["sv << source << "] -- locked out for "sv
                         << std::chrono::duration_cast<std::chrono::minutes>(config_.source_lockout).count()
                         << " minutes after "sv << config_.max_failures_per_source << " failed logins"sv;
    }
  }

  void login_limiter_t::record_success(const std::string &source) {
    std::scoped_lock lock {mutex_};
    if (const auto it = sources_.find(source); it != sources_.end() && it->second.locked_until <= clock::now()) {
      sources_.erase(it);
    }
  }

  void login_limiter_t::reset() {
    std::scoped_lock lock {mutex_};
    sources_.clear();
    global_failures_.clear();
    global_locked_until_ = {};
  }

  std::size_t login_limiter_t::tracked_sources() {
    std::scoped_lock lock {mutex_};
    return sources_.size();
  }

  void login_limiter_t::make_room(const clock::time_point now) {
    // Forget sources that are neither locked nor have failures inside the window.
    std::erase_if(sources_, [&](const auto &entry) {
      const auto &state = entry.second;
      return state.locked_until <= now && (state.failures.empty() || state.failures.back() + config_.source_window <= now);
    });
    while (!sources_.empty() && sources_.size() >= config_.max_tracked_sources) {
      // Evict unlocked sources first (oldest activity), then the lockout that ends soonest.
      const auto victim = std::ranges::min_element(sources_, [now](const auto &a, const auto &b) {
        const bool a_locked = a.second.locked_until > now;
        const bool b_locked = b.second.locked_until > now;
        if (a_locked != b_locked) {
          return !a_locked;
        }
        return a_locked ? a.second.locked_until < b.second.locked_until : a.second.last_seen < b.second.last_seen;
      });
      sources_.erase(victim);
    }
  }

  std::string source_key(const boost::asio::ip::address &address) {
    if (address.is_v6()) {
      const auto v6 = address.to_v6();
      if (v6.is_v4_mapped()) {
        return boost::asio::ip::make_address_v4(boost::asio::ip::v4_mapped, v6).to_string();
      }
      if (v6.is_loopback()) {
        return v6.to_string();
      }
      auto bytes = v6.to_bytes();
      std::fill(bytes.begin() + 8, bytes.end(), 0);
      return boost::asio::ip::address_v6 {bytes}.to_string() + "/64";
    }
    return address.to_string();
  }

  result_t authenticate(const std::optional<std::string_view> authorization, const boost::asio::ip::address &remote) {
    if (!authorization) {
      return {outcome_e::missing};
    }

    const auto now = login_limiter_t::clock::now();
    const auto source = source_key(remote);
    if (const auto remaining = limiter().locked_for(source, now)) {
      // Do not evaluate anything (not even the cache) while locked.
      return {outcome_e::locked_out, *remaining};
    }

    auto credentials = parse_basic_authorization(*authorization);
    if (credentials && credentials->username == LOGOUT_USERNAME && !constant_time_equals(ascii_lower(config::sunshine.username), LOGOUT_USERNAME)) {
      // The Web UI's logout sends these credentials on purpose; it is not a guess.
      return {outcome_e::rejected};
    }

    const auto header_mac = keyed_digest(*authorization);
    if (credentials && verification_cache().contains(header_mac, credentials_fingerprint(), now)) {
      limiter().record_success(source);
      return {outcome_e::authenticated};
    }

    auto match = password_match_e::mismatch;
    bool username_matches = false;
    if (credentials && !config::sunshine.username.empty()) {
      ++password_evaluations;
      // Always evaluate the password so that timing does not reveal whether the username exists.
      username_matches = constant_time_equals(ascii_lower(credentials->username), ascii_lower(config::sunshine.username));
      match = verify_password(credentials->password, config::sunshine.password, config::sunshine.salt);
    }

    if (!username_matches || match == password_match_e::mismatch) {
      if (credentials) {
        std::fill(credentials->password.begin(), credentials->password.end(), '\0');
      }
      limiter().record_failure(source, now);
      return {outcome_e::rejected};
    }

    if (match == password_match_e::match_needs_upgrade) {
      if (http::save_user_creds(config::sunshine.credentials_file, config::sunshine.username, credentials->password) == 0 && http::reload_user_creds(config::sunshine.credentials_file) == 0) {
        BOOST_LOG(info) << "Web UI: upgraded the stored password hash to PBKDF2-SHA256"sv;
      } else {
        BOOST_LOG(warning) << "Web UI: could not upgrade the stored password hash; the old hash remains in use"sv;
      }
    }
    std::fill(credentials->password.begin(), credentials->password.end(), '\0');

    limiter().record_success(source);
    verification_cache().insert(header_mac, credentials_fingerprint(), now);
    return {outcome_e::authenticated};
  }

  void clear_verification_cache() {
    verification_cache().clear();
  }

#ifdef SUNSHINE_TESTS
  void reset_limiter_for_testing() {
    limiter().reset();
  }

  std::size_t password_evaluations_for_testing() {
    return password_evaluations.load();
  }

  std::size_t verification_cache_size_for_testing() {
    return verification_cache().size();
  }
#endif
}  // namespace webui_auth
