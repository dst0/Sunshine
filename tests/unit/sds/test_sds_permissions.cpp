/**
 * @file tests/unit/sds/test_sds_permissions.cpp
 * @brief Test src/sds/permissions.*.
 */

// test includes
#include "../../tests_common.h"

// standard includes
#include <string>
#include <vector>

// local includes
#include <src/sds/permissions.h>

TEST(SdsPermissionsTest, ParsesCanonicalNamesOnly) {
  EXPECT_EQ(sds::parse_permission("clipboard_read"), sds::permission_e::clipboard_read);
  EXPECT_EQ(sds::parse_permission("clipboard_write"), sds::permission_e::clipboard_write);
  EXPECT_EQ(sds::parse_permission("file_upload"), sds::permission_e::file_upload);
  EXPECT_EQ(sds::parse_permission("file_download"), sds::permission_e::file_download);
  EXPECT_EQ(sds::parse_permission("mic"), sds::permission_e::mic);
  EXPECT_FALSE(sds::parse_permission("MIC").has_value());
  EXPECT_FALSE(sds::parse_permission("").has_value());
  EXPECT_FALSE(sds::parse_permission("admin").has_value());
  EXPECT_EQ(sds::permission_name(sds::permission_e::file_download), "file_download");
}

TEST(SdsPermissionsTest, NormalizationDropsUnknownSortsAndDeduplicates) {
  const std::vector<std::string> input {"mic", "bogus", "clipboard_read", "mic", "file_upload"};
  const std::vector<std::string> expected {"clipboard_read", "file_upload", "mic"};
  EXPECT_EQ(sds::normalize_permissions(input), expected);
  EXPECT_TRUE(sds::normalize_permissions({}).empty());
  EXPECT_FALSE(sds::all_permissions_known(input));
  EXPECT_TRUE(sds::all_permissions_known(expected));
  EXPECT_TRUE(sds::all_permissions_known({}));
}

TEST(SdsPermissionsTest, SetConversionRoundTrips) {
  const auto set = sds::to_permission_set({"file_download", "clipboard_write", "nope"});
  EXPECT_TRUE(set.test(static_cast<std::size_t>(sds::permission_e::file_download)));
  EXPECT_TRUE(set.test(static_cast<std::size_t>(sds::permission_e::clipboard_write)));
  EXPECT_EQ(set.count(), 2u);
  const std::vector<std::string> expected {"clipboard_write", "file_download"};
  EXPECT_EQ(sds::to_permission_names(set), expected);
}

TEST(SdsPermissionsTest, ParsesConfigurationLists) {
  const std::vector<std::string> expected {"clipboard_read", "clipboard_write"};
  EXPECT_EQ(sds::parse_permission_list(" clipboard_write , clipboard_read,unknown,, "), expected);
  EXPECT_TRUE(sds::parse_permission_list("").empty());
  EXPECT_TRUE(sds::parse_permission_list(" , ,").empty());
}
