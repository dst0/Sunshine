/**
 * @file src/webui_auth.h
 * @brief Declarations for Web UI password hashing, Basic authentication and login rate limiting.
 */
#pragma once

// standard includes
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

// lib includes
#include <boost/asio/ip/address.hpp>

/**
 * @brief Web UI credential handling: password hashing, Basic authentication and login rate limiting.
 */
namespace webui_auth {
  /**
   * @brief PBKDF2-HMAC-SHA256 iterations used for newly stored passwords.
   * @details OWASP's 2023 recommendation for PBKDF2-HMAC-SHA256. Successful logins re-hash
   *          passwords stored with fewer iterations.
   */
  constexpr std::uint32_t PBKDF2_ITERATIONS = 600000;

  /**
   * @brief Largest iteration count accepted from a stored hash (bounds the cost of one login).
   */
  constexpr std::uint32_t PBKDF2_MAX_ITERATIONS = 10000000;

  /**
   * @brief Random salt size for newly stored passwords, in bytes.
   */
  constexpr std::size_t SALT_SIZE = 16;

  /**
   * @brief Derived key size, in bytes.
   */
  constexpr std::size_t HASH_SIZE = 32;

  /**
   * @brief Scheme identifier at the start of a stored PBKDF2 hash.
   */
  constexpr std::string_view PBKDF2_SCHEME = "pbkdf2-sha256";

  /**
   * @brief Longest Authorization header that is evaluated; longer headers are rejected.
   */
  constexpr std::size_t MAX_AUTHORIZATION_SIZE = 4096;

  /**
   * @brief Username the Web UI sends on purpose to make the browser forget its credentials.
   */
  constexpr std::string_view LOGOUT_USERNAME = "sunshine-logout";

  /**
   * @brief Lifetime of a cached successful verification.
   */
  constexpr auto VERIFICATION_CACHE_TTL = std::chrono::minutes {10};

  /**
   * @brief Maximum number of cached successful verifications.
   */
  constexpr std::size_t VERIFICATION_CACHE_SIZE = 64;

  /**
   * @brief Result of checking a password against a stored hash.
   */
  enum class password_match_e {
    mismatch,  ///< The password does not match, or the stored hash is malformed.
    match,  ///< The password matches a current PBKDF2 hash.
    match_needs_upgrade,  ///< The password matches a legacy or weaker hash that should be replaced.
  };

  /**
   * @brief Hash a password for storage.
   *
   * @param password Plain-text password.
   * @param iterations PBKDF2 iteration count.
   * @return Self-describing hash `pbkdf2-sha256$<iterations>$<salt-b64>$<hash-b64>`.
   */
  std::string hash_password(std::string_view password, std::uint32_t iterations = PBKDF2_ITERATIONS);

  /**
   * @brief Check a password against a stored hash.
   * @details Accepts the PBKDF2 format produced by @ref hash_password and the legacy
   *          `hex(SHA-256(password + salt))` format. All comparisons are constant time.
   *
   * @param password Plain-text password to check.
   * @param stored_hash Stored hash.
   * @param legacy_salt Salt stored next to a legacy hash; ignored for PBKDF2 hashes.
   * @return Whether the password matches and whether the stored hash should be upgraded.
   */
  password_match_e verify_password(std::string_view password, std::string_view stored_hash, std::string_view legacy_salt);

  /**
   * @brief Compare two byte strings in time independent of their contents.
   *
   * @param a First value.
   * @param b Second value.
   * @return `true` when both values are equal.
   */
  bool constant_time_equals(std::string_view a, std::string_view b);

  /**
   * @brief Encode bytes as standard base64 with padding.
   *
   * @param data Bytes to encode.
   * @return Base64 text.
   */
  std::string base64_encode(std::string_view data);

  /**
   * @brief Decode strict standard base64 (correct alphabet, length and padding).
   *
   * @param text Base64 text.
   * @return Decoded bytes, or no value for malformed input.
   */
  std::optional<std::string> base64_decode(std::string_view text);

  /**
   * @brief Username and password decoded from an HTTP Basic Authorization header.
   */
  struct basic_credentials_t {
    std::string username;  ///< Decoded user name.
    std::string password;  ///< Decoded password.
  };

  /**
   * @brief Parse an HTTP Basic Authorization header value.
   * @details Requires the `Basic` scheme, strict base64 and a `user:password` pair with a
   *          non-empty password.
   *
   * @param header Authorization header value.
   * @return Decoded credentials, or no value for anything else.
   */
  std::optional<basic_credentials_t> parse_basic_authorization(std::string_view header);

  /**
   * @brief Limits for @ref login_limiter_t.
   */
  struct limiter_config_t {
    std::size_t max_failures_per_source = 5;  ///< Failures from one source that trigger its lockout.
    std::chrono::seconds source_window = std::chrono::minutes {15};  ///< Window in which source failures are counted.
    std::chrono::seconds source_lockout = std::chrono::minutes {15};  ///< Duration of a source lockout.
    std::size_t max_failures_global = 50;  ///< Failures from all sources that trigger the global lockout.
    std::chrono::seconds global_window = std::chrono::minutes {15};  ///< Window in which global failures are counted.
    std::chrono::seconds global_lockout = std::chrono::minutes {5};  ///< Duration of the global lockout.
    std::size_t max_tracked_sources = 1024;  ///< Upper bound on tracked sources (memory bound).
  };

  /**
   * @brief Thread-safe failed-login tracker with per-source and global lockouts.
   */
  class login_limiter_t {
  public:
    using clock = std::chrono::steady_clock;  ///< Monotonic clock used for all time points.

    /**
     * @brief Create a limiter.
     *
     * @param config Limits to enforce.
     */
    explicit login_limiter_t(limiter_config_t config = {});

    /**
     * @brief Check whether a source may attempt a login now.
     *
     * @param source Source key (see @ref source_key).
     * @param now Current time.
     * @return Remaining lockout (rounded up to whole seconds), or no value when allowed.
     */
    std::optional<std::chrono::seconds> locked_for(const std::string &source, clock::time_point now);

    /**
     * @brief Record a failed login and apply lockouts.
     *
     * @param source Source key.
     * @param now Current time.
     */
    void record_failure(const std::string &source, clock::time_point now);

    /**
     * @brief Forget the failures of a source after a successful login.
     *
     * @param source Source key.
     */
    void record_success(const std::string &source);

    /**
     * @brief Forget all state.
     */
    void reset();

    /**
     * @brief Number of tracked sources.
     *
     * @return Tracked source count.
     */
    std::size_t tracked_sources();

  private:
    /**
     * @brief Failure history of one source.
     */
    struct source_state_t {
      std::vector<clock::time_point> failures;  ///< Failure times within the window.
      clock::time_point locked_until {};  ///< End of the current lockout.
      clock::time_point last_seen {};  ///< Time of the last failure, used for eviction.
    };

    /**
     * @brief Drop entries until a new source fits, preferring unlocked and stale ones.
     *
     * @param now Current time.
     */
    void make_room(clock::time_point now);

    limiter_config_t config_;  ///< Enforced limits.
    std::mutex mutex_;  ///< Protects all state below.
    std::map<std::string, source_state_t> sources_;  ///< State per source.
    std::vector<clock::time_point> global_failures_;  ///< Failure times from all sources within the window.
    clock::time_point global_locked_until_ {};  ///< End of the global lockout.
  };

  /**
   * @brief Derive the rate-limiting key for a remote address.
   * @details IPv4 addresses are tracked individually; IPv6 addresses by their /64 prefix, since a
   *          single host can use any address in its prefix. IPv4-mapped IPv6 is treated as IPv4.
   *
   * @param address Remote address.
   * @return Source key.
   */
  std::string source_key(const boost::asio::ip::address &address);

  /**
   * @brief Outcome of authenticating one request.
   */
  enum class outcome_e {
    authenticated,  ///< Valid credentials.
    missing,  ///< No Authorization header (not counted as a failure).
    rejected,  ///< Invalid credentials.
    locked_out,  ///< Too many failures; credentials were not evaluated.
  };

  /**
   * @brief Result of authenticating one request.
   */
  struct result_t {
    outcome_e outcome;  ///< What happened.
    std::chrono::seconds retry_after {0};  ///< Remaining lockout when `outcome` is `locked_out`.
  };

  /**
   * @brief Authenticate a Web UI request against the configured credentials.
   * @details Applies the login limiter before evaluating anything, reuses cached successful
   *          verifications, records failures, and transparently upgrades legacy password hashes
   *          in the credentials file after a successful login.
   *
   * @param authorization Authorization header value, if present.
   * @param remote Remote address of the request.
   * @return Authentication result.
   */
  result_t authenticate(std::optional<std::string_view> authorization, const boost::asio::ip::address &remote);

  /**
   * @brief Drop all cached successful verifications (call after the credentials change).
   */
  void clear_verification_cache();

#ifdef SUNSHINE_TESTS
  /**
   * @brief Forget all failed-login state (per-source and global).
   */
  void reset_limiter_for_testing();

  /**
   * @brief Number of password hash evaluations performed by @ref authenticate so far.
   *
   * @return Evaluation count.
   */
  std::size_t password_evaluations_for_testing();

  /**
   * @brief Number of cached successful verifications.
   *
   * @return Cache entry count.
   */
  std::size_t verification_cache_size_for_testing();
#endif
}  // namespace webui_auth
