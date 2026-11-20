/**
 * @file tests/unit/test_entry_handler.cpp
 * @brief Test src/entry_handler.*.
 */

// test includes
#include "../tests_common.h"
#include "../tests_log_checker.h"

// standard includes
#include <filesystem>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

// local includes
#include <src/config.h>
#include <src/crypto.h>
#include <src/entry_handler.h>
#include <src/httpcommon.h>
#include <src/utility.h>

/**
 * @brief Test fixture that restores Web UI URL configuration after each test.
 */
class LaunchUiUrlTest: public BaseTest {
private:
  std::string original_bind_address;
  std::uint16_t original_port;

protected:
  void SetUp() override {
    BaseTest::SetUp();
    original_bind_address = config::sunshine.bind_address;
    original_port = config::sunshine.port;
    config::sunshine.port = 47989;
  }

  void TearDown() override {
    config::sunshine.bind_address = original_bind_address;
    config::sunshine.port = original_port;
    BaseTest::TearDown();
  }
};

/**
 * @brief Test that Web UI URLs use localhost when no bind address is configured.
 */
TEST_F(LaunchUiUrlTest, UsesLocalhostWithoutBindAddress) {
  config::sunshine.bind_address = "";

  EXPECT_EQ(get_launch_ui_url(), "https://localhost:47990");
  EXPECT_EQ(get_launch_ui_url("/pin"), "https://localhost:47990/pin");
}

/**
 * @brief Test that Web UI URLs use the configured IPv4 bind address.
 */
TEST_F(LaunchUiUrlTest, UsesConfiguredIPv4Address) {
  config::sunshine.bind_address = "198.51.100.56";

  EXPECT_EQ(get_launch_ui_url(), "https://198.51.100.56:47990");
}

/**
 * @brief Test that Web UI URLs enclose configured IPv6 bind addresses in brackets.
 */
TEST_F(LaunchUiUrlTest, EscapesConfiguredIPv6Address) {
  config::sunshine.bind_address = "2001:db8::1";

  EXPECT_EQ(get_launch_ui_url("/config"), "https://[2001:db8::1]:47990/config");
}

TEST(EntryHandlerTests, LogPublisherDataTest) {
  // call log_publisher_data
  log_publisher_data();

  // check if specific log messages exist
  ASSERT_TRUE(log_checker::line_starts_with("test_sunshine.log", "Info: Package Publisher: "));
  ASSERT_TRUE(log_checker::line_starts_with("test_sunshine.log", "Info: Publisher Website: "));
  ASSERT_TRUE(log_checker::line_starts_with("test_sunshine.log", "Info: Get support: "));
}

namespace {
  /**
   * @brief Create a publisher factory that counts how often it is invoked.
   *
   * @param calls Counter incremented on each invocation.
   * @return Factory returning a dummy publisher guard.
   */
  std::function<std::unique_ptr<platf::deinit_t>()> counting_publisher(int &calls) {
    return [&calls]() {
      ++calls;
      return std::make_unique<platf::deinit_t>();
    };
  }
}  // namespace

/**
 * @brief Disabled mDNS advertising never starts the platform publisher.
 */
TEST(MdnsPublisherTest, DisabledAdvertisingNeverStartsThePublisher) {
  int calls = 0;
  const auto guard = start_mdns_publisher(false, counting_publisher(calls));
  EXPECT_EQ(calls, 0);
  EXPECT_EQ(guard, nullptr);
  EXPECT_TRUE(log_checker::line_contains("test_sunshine.log", "mDNS advertising is disabled"));
}

/**
 * @brief Enabled mDNS advertising starts the publisher exactly once and keeps its guard.
 */
TEST(MdnsPublisherTest, EnabledAdvertisingStartsThePublisherOnce) {
  int calls = 0;
  const auto guard = start_mdns_publisher(true, counting_publisher(calls));
  EXPECT_EQ(calls, 1);
  EXPECT_NE(guard, nullptr);
}

/**
 * @brief The default configuration does not advertise the host.
 */
TEST(MdnsPublisherTest, DefaultConfigurationDoesNotAdvertise) {
  int calls = 0;
  const auto guard = start_mdns_publisher(config::sunshine.mdns_advertise, counting_publisher(calls));
  EXPECT_FALSE(config::sunshine.mdns_advertise);
  EXPECT_EQ(calls, 0);
  EXPECT_EQ(guard, nullptr);
}

/**
 * @brief Isolate `--creds` tests in a temporary credentials file.
 */
class CredsCommandTest: public BaseTest {
protected:
  void SetUp() override {
    BaseTest::SetUp();
    saved_file = config::sunshine.credentials_file;
    saved_username = config::sunshine.username;
    saved_password = config::sunshine.password;
    saved_salt = config::sunshine.salt;
    file = (std::filesystem::path {SUNSHINE_TEST_BIN_DIR} / "creds_command_test.json").string();
    std::filesystem::remove(file);
    config::sunshine.credentials_file = file;
  }

  void TearDown() override {
    std::filesystem::remove(file);
    config::sunshine.credentials_file = saved_file;
    config::sunshine.username = saved_username;
    config::sunshine.password = saved_password;
    config::sunshine.salt = saved_salt;
    BaseTest::TearDown();
  }

  /**
   * @brief Run `--creds` with the given arguments and password input.
   *
   * @param arguments Arguments following `--creds`.
   * @param input Text available on the password input stream.
   * @param interactive Whether the input behaves like a terminal.
   * @return Exit code of the command.
   */
  static int run(std::vector<std::string> arguments, const std::string &input, bool interactive) {
    std::vector<char *> argv;
    for (auto &argument : arguments) {
      argv.push_back(argument.data());
    }
    argv.push_back(nullptr);
    std::istringstream stream {input};
    return args::creds("sunshine", static_cast<int>(arguments.size()), argv.data(), stream, interactive);
  }

  /**
   * @brief Check whether the stored credentials accept a password.
   *
   * @param password Candidate password.
   * @return `true` when the credentials file holds this password.
   */
  bool stored_password_is(const std::string &password) const {
    if (http::reload_user_creds(file) != 0) {
      return false;
    }
    return util::hex(crypto::hash(password + config::sunshine.salt)).to_string() == config::sunshine.password;
  }

  std::string file;  ///< Temporary credentials file.

private:
  std::string saved_file;  ///< Credentials file restored after the test.
  std::string saved_username;  ///< Username restored after the test.
  std::string saved_password;  ///< Password hash restored after the test.
  std::string saved_salt;  ///< Salt restored after the test.
};

TEST_F(CredsCommandTest, ReadsOmittedPasswordFromStandardInput) {
  ASSERT_EQ(run({"alice"}, "correct horse battery\n", false), 0);
  EXPECT_TRUE(stored_password_is("correct horse battery"));
  EXPECT_EQ(config::sunshine.username, "alice");
}

TEST_F(CredsCommandTest, KeepsTheTwoArgumentForm) {
  ASSERT_EQ(run({"bob", "hunter2"}, "", false), 0);
  EXPECT_TRUE(stored_password_is("hunter2"));
  EXPECT_EQ(config::sunshine.username, "bob");
}

TEST_F(CredsCommandTest, PromptsTwiceOnATerminal) {
  ASSERT_EQ(run({"carol"}, "s3cret\r\ns3cret\n", true), 0);
  EXPECT_TRUE(stored_password_is("s3cret"));
}

TEST_F(CredsCommandTest, RejectsMismatchedConfirmation) {
  EXPECT_NE(run({"carol"}, "s3cret\nother\n", true), 0);
  EXPECT_FALSE(std::filesystem::exists(file));
}

TEST_F(CredsCommandTest, RejectsMissingOrEmptyPassword) {
  EXPECT_NE(run({"dave"}, "", false), 0);
  EXPECT_NE(run({"dave"}, "\n", false), 0);
  EXPECT_NE(run({"dave", ""}, "", false), 0);
  EXPECT_FALSE(std::filesystem::exists(file));
}

TEST_F(CredsCommandTest, RejectsMissingUsername) {
  EXPECT_NE(run({}, "", false), 0);
  EXPECT_NE(run({""}, "pw\n", false), 0);
  EXPECT_FALSE(std::filesystem::exists(file));
}

TEST(ReadPasswordLineTest, StripsLineEndings) {
  std::istringstream unix_line {"secret\nnext\n"};
  EXPECT_EQ(args::read_password_line(unix_line), "secret");
  EXPECT_EQ(args::read_password_line(unix_line), "next");
  EXPECT_EQ(args::read_password_line(unix_line), std::nullopt);

  std::istringstream windows_line {"secret\r\n"};
  EXPECT_EQ(args::read_password_line(windows_line), "secret");

  std::istringstream unterminated {"last"};
  EXPECT_EQ(args::read_password_line(unterminated), "last");

  std::istringstream empty_line {"\n"};
  EXPECT_EQ(args::read_password_line(empty_line), "");
}
