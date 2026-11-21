/**
 * @file tests/unit/test_webui_auth.cpp
 * @brief Test Web UI password hashing, Basic authentication parsing and login rate limiting.
 */

// test includes
#include "../tests_common.h"

// standard includes
#include <chrono>
#include <filesystem>
#include <format>
#include <string>
#include <vector>

// lib includes
#include <boost/asio/ip/address.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

// local includes
#include <src/config.h>
#include <src/crypto.h>
#include <src/httpcommon.h>
#include <src/utility.h>
#include <src/webui_auth.h>

using namespace std::literals;

namespace {
  constexpr std::uint32_t FAST_ITERATIONS = 1000;  ///< Iterations used where the cost is irrelevant to the test.

  /**
   * @brief Build a Basic Authorization header value.
   *
   * @param user_pass `user:password` text.
   * @return Header value.
   */
  std::string basic(const std::string_view user_pass) {
    return "Basic " + webui_auth::base64_encode(user_pass);
  }

  /**
   * @brief Legacy stored hash, exactly as the previous implementation computed it.
   *
   * @param password Password.
   * @param salt Legacy salt.
   * @return Upper-case hex digest.
   */
  std::string legacy_hash(const std::string &password, const std::string &salt) {
    return util::hex(crypto::hash(password + salt)).to_string();
  }

  /**
   * @brief Split a stored PBKDF2 hash into its fields.
   *
   * @param stored Stored hash.
   * @return Fields separated by `$`.
   */
  std::vector<std::string> fields(const std::string &stored) {
    std::vector<std::string> parts;
    std::string::size_type start = 0;
    while (true) {
      const auto end = stored.find('$', start);
      parts.emplace_back(stored.substr(start, end - start));
      if (end == std::string::npos) {
        return parts;
      }
      start = end + 1;
    }
  }
}  // namespace

TEST(WebUiPasswordHashTest, UsesSelfDescribingPbkdf2Format) {
  const auto stored = webui_auth::hash_password("correct horse");
  const auto parts = fields(stored);
  ASSERT_EQ(parts.size(), 4);
  EXPECT_EQ(parts[0], "pbkdf2-sha256");
  EXPECT_EQ(parts[1], std::to_string(webui_auth::PBKDF2_ITERATIONS));
  EXPECT_GE(webui_auth::PBKDF2_ITERATIONS, 210000u);
  EXPECT_EQ(webui_auth::base64_decode(parts[2]).value_or("").size(), 16);
  EXPECT_EQ(webui_auth::base64_decode(parts[3]).value_or("").size(), 32);
  EXPECT_EQ(webui_auth::verify_password("correct horse", stored, ""), webui_auth::password_match_e::match);
}

TEST(WebUiPasswordHashTest, UsesARandomSaltPerHash) {
  const auto first = webui_auth::hash_password("same", FAST_ITERATIONS);
  const auto second = webui_auth::hash_password("same", FAST_ITERATIONS);
  EXPECT_NE(first, second);
  EXPECT_NE(fields(first)[2], fields(second)[2]);
}

TEST(WebUiPasswordHashTest, RejectsWrongPasswords) {
  const auto stored = webui_auth::hash_password("secret", FAST_ITERATIONS);
  EXPECT_EQ(webui_auth::verify_password("Secret", stored, ""), webui_auth::password_match_e::mismatch);
  EXPECT_EQ(webui_auth::verify_password("secret ", stored, ""), webui_auth::password_match_e::mismatch);
  EXPECT_EQ(webui_auth::verify_password("", stored, ""), webui_auth::password_match_e::mismatch);
}

TEST(WebUiPasswordHashTest, AsksToUpgradeWeakerPbkdf2Hashes) {
  const auto stored = webui_auth::hash_password("secret", FAST_ITERATIONS);
  EXPECT_EQ(webui_auth::verify_password("secret", stored, ""), webui_auth::password_match_e::match_needs_upgrade);
}

TEST(WebUiPasswordHashTest, RejectsMalformedPbkdf2Hashes) {
  const auto parts = fields(webui_auth::hash_password("secret", FAST_ITERATIONS));
  const auto salt = parts[2];
  const auto hash = parts[3];
  for (const auto &stored : {
         std::format("pbkdf2-sha256${}${}", FAST_ITERATIONS, salt),
         std::format("pbkdf2-sha256${}${}${}$extra", FAST_ITERATIONS, salt, hash),
         std::format("pbkdf2-sha256$abc${}${}", salt, hash),
         std::format("pbkdf2-sha256$0${}${}", salt, hash),
         std::format("pbkdf2-sha256$-5${}${}", salt, hash),
         std::format("pbkdf2-sha256${}${}${}", webui_auth::PBKDF2_MAX_ITERATIONS + 1, salt, hash),
         std::format("pbkdf2-sha256${}$!!!!${}", FAST_ITERATIONS, hash),
         std::format("pbkdf2-sha256${}${}$c2hvcnQ=", FAST_ITERATIONS, salt),
         std::format("pbkdf2-sha256${}$YQ==${}", FAST_ITERATIONS, hash),
         std::format("pbkdf2-sha512${}${}${}", FAST_ITERATIONS, salt, hash),
         std::string {},
       }) {
    EXPECT_EQ(webui_auth::verify_password("secret", stored, ""), webui_auth::password_match_e::mismatch) << stored;
  }
}

TEST(WebUiPasswordHashTest, VerifiesLegacyHashesAndAsksToUpgrade) {
  const auto stored = legacy_hash("old password", "0123456789abcdef");
  EXPECT_EQ(webui_auth::verify_password("old password", stored, "0123456789abcdef"), webui_auth::password_match_e::match_needs_upgrade);

  std::string lower = stored;
  std::ranges::transform(lower, lower.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  EXPECT_EQ(webui_auth::verify_password("old password", lower, "0123456789abcdef"), webui_auth::password_match_e::match_needs_upgrade);

  EXPECT_EQ(webui_auth::verify_password("wrong", stored, "0123456789abcdef"), webui_auth::password_match_e::mismatch);
  EXPECT_EQ(webui_auth::verify_password("old password", stored, "other salt"), webui_auth::password_match_e::mismatch);
  EXPECT_EQ(webui_auth::verify_password("old password", stored.substr(1), "0123456789abcdef"), webui_auth::password_match_e::mismatch);
}

TEST(WebUiConstantTimeTest, ComparesByContentForAnyLength) {
  EXPECT_TRUE(webui_auth::constant_time_equals("", ""));
  EXPECT_TRUE(webui_auth::constant_time_equals("abc", "abc"));
  EXPECT_FALSE(webui_auth::constant_time_equals("abc", "abd"));
  EXPECT_FALSE(webui_auth::constant_time_equals("abc", "abcd"));
  EXPECT_FALSE(webui_auth::constant_time_equals("abc", ""));
  EXPECT_TRUE(webui_auth::constant_time_equals(std::string("a\0b", 3), std::string("a\0b", 3)));
  EXPECT_FALSE(webui_auth::constant_time_equals(std::string("a\0b", 3), std::string("a\0c", 3)));
}

TEST(WebUiBase64Test, RoundTripsAndRejectsMalformedInput) {
  for (const auto &value : {""s, "a"s, "ab"s, "abc"s, std::string("\0\xff\x10", 3)}) {
    EXPECT_EQ(webui_auth::base64_decode(webui_auth::base64_encode(value)), value);
  }
  EXPECT_EQ(webui_auth::base64_encode("user:pass"), "dXNlcjpwYXNz");
  for (const auto *invalid : {"dXNlcjpwYXN", "dXNl cjpw", "dXNlcjpw*XNz", "a===", "ab=c", "====", "dXNlcjpwYXNz\n"}) {
    EXPECT_FALSE(webui_auth::base64_decode(invalid)) << invalid;
  }
}

TEST(WebUiBasicAuthTest, RequiresTheBasicScheme) {
  const auto credentials = webui_auth::parse_basic_authorization(basic("admin:pass"));
  ASSERT_TRUE(credentials);
  EXPECT_EQ(credentials->username, "admin");
  EXPECT_EQ(credentials->password, "pass");

  EXPECT_TRUE(webui_auth::parse_basic_authorization("basic " + webui_auth::base64_encode("admin:pass")));
  EXPECT_TRUE(webui_auth::parse_basic_authorization("BASIC  " + webui_auth::base64_encode("admin:pass")));

  // Without the scheme the old code decoded whatever followed the first six characters.
  EXPECT_FALSE(webui_auth::parse_basic_authorization(webui_auth::base64_encode("xxxxxxadmin:pass")));
  EXPECT_FALSE(webui_auth::parse_basic_authorization("Bearer " + webui_auth::base64_encode("admin:pass")));
  EXPECT_FALSE(webui_auth::parse_basic_authorization("Basic" + webui_auth::base64_encode("admin:pass")));
  EXPECT_FALSE(webui_auth::parse_basic_authorization("Basic"));
  EXPECT_FALSE(webui_auth::parse_basic_authorization(""));
}

TEST(WebUiBasicAuthTest, RejectsMalformedCredentials) {
  EXPECT_FALSE(webui_auth::parse_basic_authorization(basic("adminpass")));
  EXPECT_FALSE(webui_auth::parse_basic_authorization(basic("admin:")));
  EXPECT_FALSE(webui_auth::parse_basic_authorization("Basic not*base64"));
  EXPECT_FALSE(webui_auth::parse_basic_authorization(basic("admin:" + std::string(webui_auth::MAX_AUTHORIZATION_SIZE, 'x'))));

  const auto with_colon = webui_auth::parse_basic_authorization(basic("admin:pa:ss"));
  ASSERT_TRUE(with_colon);
  EXPECT_EQ(with_colon->password, "pa:ss");
}

TEST(WebUiSourceKeyTest, GroupsIpv6ByPrefix) {
  using boost::asio::ip::make_address;
  EXPECT_EQ(webui_auth::source_key(make_address("192.0.2.7")), "192.0.2.7");
  EXPECT_EQ(webui_auth::source_key(make_address("::ffff:192.0.2.7")), "192.0.2.7");
  EXPECT_EQ(webui_auth::source_key(make_address("::1")), "::1");
  EXPECT_EQ(webui_auth::source_key(make_address("2001:db8:1:2:aaaa::1")), webui_auth::source_key(make_address("2001:db8:1:2:bbbb::2")));
  EXPECT_NE(webui_auth::source_key(make_address("2001:db8:1:2::1")), webui_auth::source_key(make_address("2001:db8:1:3::1")));
}

/**
 * @brief Exercise the limiter with synthetic time.
 */
class LoginLimiterTest: public BaseTest {
protected:
  using clock = webui_auth::login_limiter_t::clock;

  /**
   * @brief Record several failures for one source at the same time.
   *
   * @param source Source key.
   * @param count Number of failures.
   * @param at Time of the failures.
   */
  void fail(const std::string &source, const std::size_t count, const clock::time_point at) {
    for (std::size_t i = 0; i < count; ++i) {
      limiter.record_failure(source, at);
    }
  }

  webui_auth::login_limiter_t limiter;  ///< Limiter with default limits.
  clock::time_point t0 = clock::now();  ///< Reference time.
};

TEST_F(LoginLimiterTest, LocksASourceAfterFiveFailuresForFifteenMinutes) {
  fail("192.0.2.1", 4, t0);
  EXPECT_FALSE(limiter.locked_for("192.0.2.1", t0));

  limiter.record_failure("192.0.2.1", t0 + 1s);
  const auto remaining = limiter.locked_for("192.0.2.1", t0 + 1s);
  ASSERT_TRUE(remaining);
  EXPECT_EQ(*remaining, 15min);
  EXPECT_EQ(limiter.locked_for("192.0.2.1", t0 + 1s + 14min), 1min);
  EXPECT_FALSE(limiter.locked_for("192.0.2.1", t0 + 1s + 15min));

  // Other sources are unaffected.
  EXPECT_FALSE(limiter.locked_for("192.0.2.2", t0 + 1s));
}

TEST_F(LoginLimiterTest, OnlyCountsFailuresInsideTheWindow) {
  fail("192.0.2.1", 4, t0);
  limiter.record_failure("192.0.2.1", t0 + 15min);
  EXPECT_FALSE(limiter.locked_for("192.0.2.1", t0 + 15min));
}

TEST_F(LoginLimiterTest, SuccessForgetsEarlierFailures) {
  fail("192.0.2.1", 4, t0);
  limiter.record_success("192.0.2.1");
  limiter.record_failure("192.0.2.1", t0 + 1s);
  EXPECT_FALSE(limiter.locked_for("192.0.2.1", t0 + 1s));
}

TEST_F(LoginLimiterTest, GlobalCeilingLocksEverySource) {
  for (int i = 0; i < 49; ++i) {
    limiter.record_failure(std::format("198.51.100.{}", i), t0);
  }
  EXPECT_FALSE(limiter.locked_for("203.0.113.1", t0));

  limiter.record_failure("198.51.100.200", t0);
  const auto remaining = limiter.locked_for("203.0.113.1", t0);
  ASSERT_TRUE(remaining);
  EXPECT_EQ(*remaining, 5min);
  EXPECT_FALSE(limiter.locked_for("203.0.113.1", t0 + 5min));
}

TEST_F(LoginLimiterTest, BoundsTrackedSourcesAndKeepsLockouts) {
  webui_auth::limiter_config_t config;
  config.max_tracked_sources = 8;
  config.max_failures_global = 1000;
  webui_auth::login_limiter_t bounded {config};

  for (int i = 0; i < 5; ++i) {
    bounded.record_failure("192.0.2.99", t0);
  }
  ASSERT_TRUE(bounded.locked_for("192.0.2.99", t0));

  for (int i = 0; i < 100; ++i) {
    bounded.record_failure(std::format("198.51.100.{}", i), t0 + 1s);
    EXPECT_LE(bounded.tracked_sources(), config.max_tracked_sources);
  }
  EXPECT_TRUE(bounded.locked_for("192.0.2.99", t0 + 1s)) << "eviction must prefer unlocked sources";
}

/**
 * @brief Run webui_auth::authenticate() against temporary credentials.
 */
class WebUiAuthenticateTest: public BaseTest {
protected:
  void SetUp() override {
    BaseTest::SetUp();
    saved_username = config::sunshine.username;
    saved_password = config::sunshine.password;
    saved_salt = config::sunshine.salt;
    saved_file = config::sunshine.credentials_file;
    file = std::filesystem::path {SUNSHINE_TEST_BIN_DIR} / "webui_auth_credentials.json";
    std::filesystem::remove(file);
    config::sunshine.credentials_file = file.string();
    config::sunshine.username = "Admin";
    config::sunshine.password = stored_hash();
    config::sunshine.salt.clear();
    webui_auth::reset_limiter_for_testing();
    webui_auth::clear_verification_cache();
  }

  void TearDown() override {
    webui_auth::reset_limiter_for_testing();
    webui_auth::clear_verification_cache();
    std::filesystem::remove(file);
    config::sunshine.username = saved_username;
    config::sunshine.password = saved_password;
    config::sunshine.salt = saved_salt;
    config::sunshine.credentials_file = saved_file;
    BaseTest::TearDown();
  }

  /**
   * @brief Current-strength hash of the test password, computed once.
   *
   * @return Stored hash.
   */
  static const std::string &stored_hash() {
    static const auto hash = webui_auth::hash_password("let me in");
    return hash;
  }

  static webui_auth::result_t attempt(const std::string &header, const std::string_view address = "192.0.2.10") {
    return webui_auth::authenticate(header, boost::asio::ip::make_address(address));
  }

  std::filesystem::path file;  ///< Temporary credentials file.

private:
  std::string saved_username;  ///< Username restored after the test.
  std::string saved_password;  ///< Password hash restored after the test.
  std::string saved_salt;  ///< Salt restored after the test.
  std::string saved_file;  ///< Credentials file restored after the test.
};

TEST_F(WebUiAuthenticateTest, AcceptsValidCredentialsCaseInsensitiveUsername) {
  EXPECT_EQ(attempt(basic("admin:let me in")).outcome, webui_auth::outcome_e::authenticated);
  EXPECT_EQ(attempt(basic("ADMIN:let me in")).outcome, webui_auth::outcome_e::authenticated);
}

TEST_F(WebUiAuthenticateTest, MissingHeaderIsNotAFailure) {
  for (int i = 0; i < 10; ++i) {
    EXPECT_EQ(webui_auth::authenticate(std::nullopt, boost::asio::ip::make_address("192.0.2.10")).outcome, webui_auth::outcome_e::missing);
  }
  EXPECT_EQ(attempt(basic("admin:let me in")).outcome, webui_auth::outcome_e::authenticated);
}

TEST_F(WebUiAuthenticateTest, RejectsWrongCredentialsAndMissingBasicPrefix) {
  EXPECT_EQ(attempt(basic("admin:wrong")).outcome, webui_auth::outcome_e::rejected);
  EXPECT_EQ(attempt(basic("intruder:let me in")).outcome, webui_auth::outcome_e::rejected);
  EXPECT_EQ(attempt("xxxxxx" + webui_auth::base64_encode("admin:let me in")).outcome, webui_auth::outcome_e::rejected);
}

TEST_F(WebUiAuthenticateTest, CachesSuccessfulVerifications) {
  const auto before = webui_auth::password_evaluations_for_testing();
  ASSERT_EQ(attempt(basic("admin:let me in")).outcome, webui_auth::outcome_e::authenticated);
  EXPECT_EQ(webui_auth::password_evaluations_for_testing(), before + 1);
  EXPECT_EQ(webui_auth::verification_cache_size_for_testing(), 1);

  for (int i = 0; i < 5; ++i) {
    ASSERT_EQ(attempt(basic("admin:let me in")).outcome, webui_auth::outcome_e::authenticated);
  }
  EXPECT_EQ(webui_auth::password_evaluations_for_testing(), before + 1) << "PBKDF2 must run once per session";
}

TEST_F(WebUiAuthenticateTest, CacheIsBoundToTheStoredCredentials) {
  ASSERT_EQ(attempt(basic("admin:let me in")).outcome, webui_auth::outcome_e::authenticated);
  config::sunshine.password = webui_auth::hash_password("new password");
  EXPECT_EQ(attempt(basic("admin:let me in")).outcome, webui_auth::outcome_e::rejected);

  config::sunshine.password = stored_hash();
  ASSERT_EQ(attempt(basic("admin:let me in")).outcome, webui_auth::outcome_e::authenticated);
  webui_auth::clear_verification_cache();
  EXPECT_EQ(webui_auth::verification_cache_size_for_testing(), 0);
}

TEST_F(WebUiAuthenticateTest, LocksOutAndStopsEvaluatingPasswords) {
  for (int i = 0; i < 5; ++i) {
    EXPECT_EQ(attempt(basic("admin:guess")).outcome, webui_auth::outcome_e::rejected);
  }

  const auto evaluations = webui_auth::password_evaluations_for_testing();
  const auto locked = attempt(basic("admin:let me in"));
  EXPECT_EQ(locked.outcome, webui_auth::outcome_e::locked_out);
  EXPECT_GT(locked.retry_after.count(), 0);
  EXPECT_LE(locked.retry_after, 15min);
  EXPECT_EQ(attempt(basic("admin:guess")).outcome, webui_auth::outcome_e::locked_out);
  EXPECT_EQ(webui_auth::password_evaluations_for_testing(), evaluations) << "passwords must not be evaluated while locked";

  // Another source is not locked out.
  EXPECT_EQ(attempt(basic("admin:let me in"), "192.0.2.11").outcome, webui_auth::outcome_e::authenticated);
}

TEST_F(WebUiAuthenticateTest, CachedSessionsDoNotBypassALockout) {
  ASSERT_EQ(attempt(basic("admin:let me in")).outcome, webui_auth::outcome_e::authenticated);
  for (int i = 0; i < 5; ++i) {
    attempt(basic("admin:guess"));
  }
  EXPECT_EQ(attempt(basic("admin:let me in")).outcome, webui_auth::outcome_e::locked_out);
}

TEST_F(WebUiAuthenticateTest, LogoutCredentialsAreNotCountedAsGuesses) {
  for (int i = 0; i < 10; ++i) {
    EXPECT_EQ(attempt(basic(std::format("sunshine-logout:{}", i))).outcome, webui_auth::outcome_e::rejected);
  }
  EXPECT_EQ(attempt(basic("admin:let me in")).outcome, webui_auth::outcome_e::authenticated);
}

TEST_F(WebUiAuthenticateTest, UpgradesLegacyHashesOnSuccessfulLogin) {
  config::sunshine.password = legacy_hash("let me in", "legacysalt123456");
  config::sunshine.salt = "legacysalt123456";

  ASSERT_EQ(attempt(basic("admin:let me in")).outcome, webui_auth::outcome_e::authenticated);
  EXPECT_TRUE(config::sunshine.password.starts_with("pbkdf2-sha256$")) << config::sunshine.password;
  EXPECT_EQ(config::sunshine.username, "Admin");

  boost::property_tree::ptree tree;
  boost::property_tree::read_json(file.string(), tree);
  EXPECT_EQ(tree.get<std::string>("username"), "Admin");
  EXPECT_TRUE(tree.get<std::string>("password").starts_with("pbkdf2-sha256$"));
#ifndef _WIN32
  EXPECT_EQ(std::filesystem::status(file).permissions() & std::filesystem::perms::all, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write);
#endif

  // The upgraded hash keeps working and still rejects wrong passwords.
  webui_auth::clear_verification_cache();
  EXPECT_EQ(attempt(basic("admin:let me in")).outcome, webui_auth::outcome_e::authenticated);
  EXPECT_EQ(attempt(basic("admin:wrong")).outcome, webui_auth::outcome_e::rejected);
}

TEST_F(WebUiAuthenticateTest, LegacyWrongPasswordIsNotUpgraded) {
  config::sunshine.password = legacy_hash("let me in", "legacysalt123456");
  config::sunshine.salt = "legacysalt123456";

  EXPECT_EQ(attempt(basic("admin:wrong")).outcome, webui_auth::outcome_e::rejected);
  EXPECT_FALSE(std::filesystem::exists(file));
  EXPECT_FALSE(config::sunshine.password.starts_with("pbkdf2-sha256$"));
}

TEST(WebUiSaveCredentialsTest, StoresPbkdf2HashesOnly) {
  const auto file = std::filesystem::path {SUNSHINE_TEST_BIN_DIR} / "webui_auth_save.json";
  std::filesystem::remove(file);
  ASSERT_EQ(http::save_user_creds(file.string(), "user", "plain secret"), 0);

  boost::property_tree::ptree tree;
  boost::property_tree::read_json(file.string(), tree);
  const auto stored = tree.get<std::string>("password");
  EXPECT_TRUE(stored.starts_with("pbkdf2-sha256$"));
  EXPECT_EQ(stored.find("plain secret"), std::string::npos);
  EXPECT_EQ(webui_auth::verify_password("plain secret", stored, tree.get<std::string>("salt")), webui_auth::password_match_e::match);
  std::filesystem::remove(file);
}
