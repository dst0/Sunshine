/**
 * @file tests/unit/test_httpcommon.cpp
 * @brief Test src/httpcommon.*.
 */
// test includes
#include "../tests_common.h"

// lib includes
#include <curl/curl.h>

// standard includes
#include <filesystem>
#include <fstream>

// local includes
#include <src/config.h>
#include <src/httpcommon.h>

struct UrlEscapeTest: BaseTest, testing::WithParamInterface<std::tuple<std::string, std::string>> {};

TEST_P(UrlEscapeTest, Run) {
  const auto &[input, expected] = GetParam();
  ASSERT_EQ(http::url_escape(input), expected);
}

INSTANTIATE_TEST_SUITE_P(
  UrlEscapeTests,
  UrlEscapeTest,
  testing::Values(
    std::make_tuple("igdb_0123456789", "igdb_0123456789"),
    std::make_tuple("../../../", "..%2F..%2F..%2F"),
    std::make_tuple("..*\\", "..%2A%5C")
  )
);

struct UrlGetHostTest: BaseTest, testing::WithParamInterface<std::tuple<std::string, std::string>> {};

TEST_P(UrlGetHostTest, Run) {
  const auto &[input, expected] = GetParam();
  ASSERT_EQ(http::url_get_host(input), expected);
}

INSTANTIATE_TEST_SUITE_P(
  UrlGetHostTests,
  UrlGetHostTest,
  testing::Values(
    std::make_tuple("https://images.igdb.com/example.txt", "images.igdb.com"),
    std::make_tuple("http://localhost:8080", "localhost"),
    std::make_tuple("nonsense!!}{::", "")
  )
);

struct DownloadFileTest: BaseTest, testing::WithParamInterface<std::tuple<std::string, std::string>> {};

TEST_P(DownloadFileTest, Run) {
  const auto &[url, filename] = GetParam();
  const std::string test_dir = platf::appdata().string() + "/tests/";
  std::string path = test_dir + filename;
  ASSERT_TRUE(http::download_file(url, path, CURL_SSLVERSION_TLSv1_0));
}

#ifdef SUNSHINE_BUILD_FLATPAK
// requires running `npm run serve` prior to running the tests
constexpr const char *URL_1 = "http://0.0.0.0:3000/hello.txt";
constexpr const char *URL_2 = "http://0.0.0.0:3000/hello-redirect.txt";
#else
constexpr const char *URL_1 = "https://httpbin.org/base64/aGVsbG8h";
constexpr const char *URL_2 = "https://httpbin.org/redirect-to?url=/base64/aGVsbG8h";
#endif

INSTANTIATE_TEST_SUITE_P(
  DownloadFileTests,
  DownloadFileTest,
  testing::Values(
    std::make_tuple(URL_1, "hello.txt"),
    std::make_tuple(URL_2, "hello-redirect.txt")
  )
);

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
