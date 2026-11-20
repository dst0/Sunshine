/**
 * @file tests/unit/test_entry_handler.cpp
 * @brief Test src/entry_handler.*.
 */

// test includes
#include "../tests_common.h"
#include "../tests_log_checker.h"

// standard includes
#include <memory>

// local includes
#include <src/config.h>
#include <src/entry_handler.h>

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
