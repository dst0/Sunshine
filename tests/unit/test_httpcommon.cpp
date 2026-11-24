/**
 * @file tests/unit/test_httpcommon.cpp
 * @brief Test src/httpcommon.*.
 */
// test includes
#include "../tests_common.h"

// standard includes
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>

// lib includes
#include <Simple-Web-Server/utility.hpp>

// local includes
#include <src/config.h>
#include <src/httpcommon.h>

/**
 * @brief Isolate the startup credential check in a temporary credentials file.
 */
class RequireUserCredsTest: public BaseTest {
protected:
  void SetUp() override {
    BaseTest::SetUp();
    saved_username = config::sunshine.username;
    saved_password = config::sunshine.password;
    saved_salt = config::sunshine.salt;
    file = (std::filesystem::path {SUNSHINE_TEST_BIN_DIR} / "require_user_creds_test.json").string();
    std::filesystem::remove(file);
    config::sunshine.username.clear();
    config::sunshine.password.clear();
    config::sunshine.salt.clear();
  }

  void TearDown() override {
    std::filesystem::remove(file);
    config::sunshine.username = saved_username;
    config::sunshine.password = saved_password;
    config::sunshine.salt = saved_salt;
    BaseTest::TearDown();
  }

  std::string file;  ///< Temporary credentials file.

private:
  std::string saved_username;  ///< Username restored after the test.
  std::string saved_password;  ///< Password hash restored after the test.
  std::string saved_salt;  ///< Salt restored after the test.
};

TEST_F(RequireUserCredsTest, RefusesToStartWithoutCredentialsFile) {
  EXPECT_NE(http::require_user_creds(file), 0);
  EXPECT_TRUE(config::sunshine.username.empty());
}

TEST_F(RequireUserCredsTest, RefusesToStartWithIncompleteCredentials) {
  std::ofstream {file} << R"({"username": "admin"})";
  EXPECT_NE(http::require_user_creds(file), 0);

  std::ofstream {file} << R"({"username": "", "password": "", "salt": ""})";
  EXPECT_NE(http::require_user_creds(file), 0);

  std::ofstream {file} << "not json";
  EXPECT_NE(http::require_user_creds(file), 0);
}

TEST_F(RequireUserCredsTest, LoadsCredentialsCreatedWithTheCredsCommand) {
  ASSERT_EQ(http::save_user_creds(file, "admin", "a long passphrase"), 0);
  config::sunshine.username.clear();
  EXPECT_EQ(http::require_user_creds(file), 0);
  EXPECT_EQ(config::sunshine.username, "admin");
  EXPECT_FALSE(config::sunshine.password.empty());
}

/**
 * @brief Isolate generated private key and certificate files for create_creds tests.
 */
class CreateCredsTest: public BaseTest {
protected:
  void SetUp() override {
    BaseTest::SetUp();
    temp_dir = std::filesystem::path {SUNSHINE_TEST_BIN_DIR} / "httpcommon_create_creds_test";
    std::error_code ec;
    std::filesystem::remove_all(temp_dir, ec);
    std::filesystem::create_directories(temp_dir, ec);
    pkey_path = (temp_dir / "server.key").string();
    cert_path = (temp_dir / "server.crt").string();
  }

  void TearDown() override {
    std::error_code ec;
    std::filesystem::remove_all(temp_dir, ec);
    BaseTest::TearDown();
  }

  std::filesystem::path temp_dir;  ///< Temporary credential output directory.
  std::string pkey_path;  ///< Private key output file path.
  std::string cert_path;  ///< Certificate output file path.
};

TEST_F(CreateCredsTest, CreatesPrivateKeyWithOwnerOnlyPermissions) {
  ASSERT_EQ(http::create_creds(pkey_path, cert_path), 0);
  ASSERT_TRUE(std::filesystem::exists(pkey_path));
  ASSERT_TRUE(std::filesystem::exists(cert_path));
  EXPECT_GT(std::filesystem::file_size(pkey_path), 0u);
  EXPECT_GT(std::filesystem::file_size(cert_path), 0u);

#if !defined(_WIN32)
  const auto perms = std::filesystem::status(pkey_path).permissions() & std::filesystem::perms::mask;
  EXPECT_EQ(perms, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write);
#endif
}

TEST_F(BaseTest, CanonicalHeaderLinesValidationRejectsMalformedHeads) {
  EXPECT_TRUE(http::has_canonical_header_lines("GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\n"));

  EXPECT_FALSE(http::has_canonical_header_lines(""));
  EXPECT_FALSE(http::has_canonical_header_lines("\r\nHost: localhost\r\n\r\n"));
  EXPECT_FALSE(http::has_canonical_header_lines("GET / HTTP/1.1\nHost: localhost\r\n\r\n"));
  EXPECT_FALSE(http::has_canonical_header_lines("GET / HTTP/1.1\rHost: localhost\r\n\r\n"));
  EXPECT_FALSE(http::has_canonical_header_lines(std::string_view {"GET /\0 HTTP/1.1\r\nHost: localhost\r\n\r\n", 36}));
  EXPECT_FALSE(http::has_canonical_header_lines("GET / HTTP/1.1\r\nHost: localhost\nX-Test: 1\r\n\r\n"));
  EXPECT_FALSE(http::has_canonical_header_lines("GET / HTTP/1.1\r\nHost: localhost\rX-Test: 1\r\n\r\n"));
  EXPECT_FALSE(http::has_canonical_header_lines(std::string_view {"GET / HTTP/1.1\r\nX-Test: a\0b\r\n\r\n", 31}));
  EXPECT_FALSE(http::has_canonical_header_lines("GET / HTTP/1.1\r\nMissingColon\r\n\r\n"));
  EXPECT_FALSE(http::has_canonical_header_lines("GET / HTTP/1.1\r\n: value\r\n\r\n"));
  EXPECT_FALSE(http::has_canonical_header_lines("GET / HTTP/1.1\r\nHost: localhost\r\n folded\r\n\r\n"));
  EXPECT_FALSE(http::has_canonical_header_lines("GET / HTTP/1.1\r\nHost: localhost\r\n\tfolded\r\n\r\n"));
  EXPECT_FALSE(http::has_canonical_header_lines("GET / HTTP/1.1\r\nHost Name: localhost\r\n\r\n"));
}

TEST_F(BaseTest, ValidateRequestFramingEnforcesTransferEncodingAndContentLengthLimits) {
  constexpr std::string_view valid_head = "POST /api/test HTTP/1.1\r\nHost: localhost\r\nContent-Length: 128\r\n\r\n";
  SimpleWeb::CaseInsensitiveMultimap headers {
    {"Host", "localhost"},
    {"Content-Length", "128"},
  };
  std::size_t content_length = 999;
  EXPECT_TRUE(http::validate_request_framing(valid_head, headers, 1024, &content_length));
  EXPECT_EQ(content_length, 128u);

  SimpleWeb::CaseInsensitiveMultimap no_len_headers {{"Host", "localhost"}};
  EXPECT_TRUE(http::validate_request_framing("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n", no_len_headers, 1024, &content_length));
  EXPECT_EQ(content_length, 0u);

  SimpleWeb::CaseInsensitiveMultimap chunked_headers {
    {"Host", "localhost"},
    {"Transfer-Encoding", "chunked"},
  };
  EXPECT_FALSE(http::validate_request_framing(valid_head, chunked_headers, 1024));

  SimpleWeb::CaseInsensitiveMultimap dup_len_headers {
    {"Host", "localhost"},
    {"Content-Length", "5"},
    {"Content-Length", "5"},
  };
  EXPECT_FALSE(http::validate_request_framing(valid_head, dup_len_headers, 1024));

  SimpleWeb::CaseInsensitiveMultimap bad_len_headers {{"Content-Length", "12abc"}};
  EXPECT_FALSE(http::validate_request_framing(valid_head, bad_len_headers, 1024));

  SimpleWeb::CaseInsensitiveMultimap plus_len_headers {{"Content-Length", "+5"}};
  EXPECT_FALSE(http::validate_request_framing(valid_head, plus_len_headers, 1024));

  SimpleWeb::CaseInsensitiveMultimap empty_len_headers {{"Content-Length", ""}};
  EXPECT_FALSE(http::validate_request_framing(valid_head, empty_len_headers, 1024));

  SimpleWeb::CaseInsensitiveMultimap overflow_len_headers {{"Content-Length", "99999999999999999999999999999"}};
  EXPECT_FALSE(http::validate_request_framing(valid_head, overflow_len_headers, 1024));

  EXPECT_FALSE(http::validate_request_framing(valid_head, headers, 127));
  EXPECT_FALSE(http::validate_request_framing("POST /api/test HTTP/1.1\nHost: localhost\r\n\r\n", headers, 1024));
}

TEST_F(BaseTest, ConnectionLimiterEnforcesCapAndReleasesSlotsOnDestruction) {
  http::connection_limiter_t zero_limiter {0};
  EXPECT_EQ(zero_limiter.try_acquire(), nullptr);

  http::connection_limiter_t limiter {2};
  auto lease1 = limiter.try_acquire();
  auto lease2 = limiter.try_acquire();
  ASSERT_NE(lease1, nullptr);
  ASSERT_NE(lease2, nullptr);
  EXPECT_EQ(limiter.try_acquire(), nullptr);

  lease1.reset();
  auto lease3 = limiter.try_acquire();
  ASSERT_NE(lease3, nullptr);
  EXPECT_EQ(limiter.try_acquire(), nullptr);
}
