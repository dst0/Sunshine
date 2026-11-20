/**
 * @file tests/unit/test_httpcommon.cpp
 * @brief Test src/httpcommon.*.
 */
// test includes
#include "../tests_common.h"

// standard includes
#include <filesystem>
#include <fstream>

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
