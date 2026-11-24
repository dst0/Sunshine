/**
 * @file tests/unit/sds/test_sds_config.cpp
 * @brief Test parsing of the secure-desktop-stream configuration keys (DESIGN 4.3).
 */

// test includes
#include "../../tests_common.h"
#include "sds_test_utils.h"

// standard includes
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

// local includes
#include <src/config.h>
#include <src/file_handler.h>

namespace fs = std::filesystem;
using namespace std::literals;

namespace {
  /**
   * @brief Restores every global the configuration parser touches.
   */
  class SdsConfigTest: public BaseTest {
  protected:
    void SetUp() override {
      BaseTest::SetUp();
      saved_sds = config::sds;
      saved_apps = config::stream.file_apps;
      saved_origins = config::sunshine.csrf_allowed_origins;
      base = test_utils::sds::scratch_dir("sds_config");
      const auto apps = base / "apps.json";
      ASSERT_EQ(file_handler::write_file(apps.string().c_str(), "{}"), 0);
      config::stream.file_apps = apps.string();
    }

    void TearDown() override {
      config::sds = saved_sds;
      config::stream.file_apps = saved_apps;
      config::sunshine.csrf_allowed_origins = saved_origins;
      std::error_code ec;
      fs::remove_all(base, ec);
      BaseTest::TearDown();
    }

    config::sds_t saved_sds;  ///< Restored after the test.
    std::string saved_apps;  ///< Restored after the test.
    std::vector<std::string> saved_origins;  ///< Restored after the test.
    fs::path base;  ///< Scratch root.
  };
}  // namespace

TEST(SdsConfigDefaultsTest, MatchTheDesign) {
  const config::sds_t defaults = config::sds;
  EXPECT_TRUE(defaults.clipboard);
  EXPECT_TRUE(defaults.file_transfer);
  EXPECT_TRUE(defaults.mic_passthrough);
  EXPECT_EQ(defaults.clipboard_text_max, 1024u * 1024);
  EXPECT_EQ(defaults.clipboard_image_max, 16u * 1024 * 1024);
  EXPECT_EQ(defaults.clipboard_rate, 10);
  EXPECT_EQ(defaults.file_max, 4ull * 1024 * 1024 * 1024);
  EXPECT_EQ(defaults.file_chunk_max, 4u * 1024 * 1024);
  EXPECT_EQ(defaults.file_uploads_max_concurrent, 2);
  EXPECT_EQ(defaults.file_min_free_space, 1024ull * 1024 * 1024);
  EXPECT_EQ(defaults.file_upload_idle_timeout, 120s);
  EXPECT_TRUE(defaults.file_inbox_dir.empty());
  EXPECT_TRUE(defaults.file_outbox_dir.empty());
  EXPECT_TRUE(defaults.default_permissions.empty());
}

TEST(SdsConfigByteSizeTest, ParsesBinarySuffixes) {
  EXPECT_EQ(config::parse_byte_size("4194304"), 4194304u);
  EXPECT_EQ(config::parse_byte_size("0"), 0u);
  EXPECT_EQ(config::parse_byte_size("512B"), 512u);
  EXPECT_EQ(config::parse_byte_size("64K"), 64u * 1024);
  EXPECT_EQ(config::parse_byte_size("64kb"), 64u * 1024);
  EXPECT_EQ(config::parse_byte_size("4M"), 4u * 1024 * 1024);
  EXPECT_EQ(config::parse_byte_size("4 MiB"), 4u * 1024 * 1024);
  EXPECT_EQ(config::parse_byte_size("\"16 MiB\""), 16u * 1024 * 1024);
  EXPECT_EQ(config::parse_byte_size("1G"), 1024ull * 1024 * 1024);
  EXPECT_EQ(config::parse_byte_size("2TiB"), 2ull * 1024 * 1024 * 1024 * 1024);
  EXPECT_FALSE(config::parse_byte_size(""));
  EXPECT_FALSE(config::parse_byte_size("MiB"));
  EXPECT_FALSE(config::parse_byte_size("-1"));
  EXPECT_FALSE(config::parse_byte_size("4X"));
  EXPECT_FALSE(config::parse_byte_size("4 MiBs"));
  EXPECT_FALSE(config::parse_byte_size("99999999999999999999"));
  EXPECT_FALSE(config::parse_byte_size("17000000T")) << "overflow";
}

TEST_F(SdsConfigTest, AppliesAllKeys) {
  config::apply_config_for_test(
    "clipboard = disabled\n"
    "file_transfer = off\n"
    "mic_passthrough = false\n"
    "clipboard_text_max = 2 MiB\n"
    "clipboard_image_max = 32M\n"
    "clipboard_rate = 20/s\n"
    "file_max = 8G\n"
    "file_chunk_max = 1M\n"
    "file_uploads_max_concurrent = 4\n"
    "file_min_free_space = 512M\n"
    "file_upload_idle_timeout = 300s\n"
    "file_inbox_dir = /srv/inbox\n"
    "file_outbox_dir = /srv/outbox\n"
    "sds_default_permissions = clipboard_read, file_download, bogus\n"
  );
  EXPECT_FALSE(config::sds.clipboard);
  EXPECT_FALSE(config::sds.file_transfer);
  EXPECT_FALSE(config::sds.mic_passthrough);
  EXPECT_EQ(config::sds.clipboard_text_max, 2u * 1024 * 1024);
  EXPECT_EQ(config::sds.clipboard_image_max, 32u * 1024 * 1024);
  EXPECT_EQ(config::sds.clipboard_rate, 20);
  EXPECT_EQ(config::sds.file_max, 8ull * 1024 * 1024 * 1024);
  EXPECT_EQ(config::sds.file_chunk_max, 1024u * 1024);
  EXPECT_EQ(config::sds.file_uploads_max_concurrent, 4);
  EXPECT_EQ(config::sds.file_min_free_space, 512ull * 1024 * 1024);
  EXPECT_EQ(config::sds.file_upload_idle_timeout, 300s);
  EXPECT_EQ(config::sds.file_inbox_dir, "/srv/inbox");
  EXPECT_EQ(config::sds.file_outbox_dir, "/srv/outbox");
  EXPECT_EQ(config::sds.default_permissions, (std::vector<std::string> {"clipboard_read", "file_download"}));

  config::apply_config_for_test("clipboard_rate = 7\nfile_upload_idle_timeout = 60\n");
  EXPECT_EQ(config::sds.clipboard_rate, 7);
  EXPECT_EQ(config::sds.file_upload_idle_timeout, 60s);
}

TEST_F(SdsConfigTest, RejectsOutOfRangeAndMalformedValues) {
  const auto before = config::sds;
  config::apply_config_for_test(
    "clipboard_text_max = 0\n"
    "clipboard_image_max = 1T\n"
    "clipboard_rate = 0\n"
    "file_chunk_max = 1K\n"
    "file_uploads_max_concurrent = 99\n"
    "file_upload_idle_timeout = 5s\n"
    "file_max = lots\n"
    "file_min_free_space = -5\n"
    "file_inbox_dir = relative/inbox\n"
    "file_outbox_dir = ~/outbox\n"
  );
  EXPECT_EQ(config::sds.clipboard_text_max, before.clipboard_text_max);
  EXPECT_EQ(config::sds.clipboard_image_max, before.clipboard_image_max);
  EXPECT_EQ(config::sds.clipboard_rate, before.clipboard_rate);
  EXPECT_EQ(config::sds.file_chunk_max, before.file_chunk_max);
  EXPECT_EQ(config::sds.file_uploads_max_concurrent, before.file_uploads_max_concurrent);
  EXPECT_EQ(config::sds.file_upload_idle_timeout, before.file_upload_idle_timeout);
  EXPECT_EQ(config::sds.file_max, before.file_max);
  EXPECT_EQ(config::sds.file_min_free_space, before.file_min_free_space);
  EXPECT_EQ(config::sds.file_inbox_dir, before.file_inbox_dir);
  EXPECT_EQ(config::sds.file_outbox_dir, before.file_outbox_dir);
}
