/**
 * @file tests/unit/sds/test_sds_sanitize.cpp
 * @brief Test the file-name sanitizer and collision naming (DESIGN 6.4, checks S7 and S9).
 */

// test includes
#include "../../tests_common.h"

// standard includes
#include <optional>
#include <string>
#include <utility>
#include <vector>

// local includes
#include <src/sds/files.h>

using namespace std::literals;

namespace {
  /**
   * @brief Sanitizer expectation.
   */
  struct sanitize_case_t {
    std::string input;  ///< Untrusted name.
    std::optional<std::string> expected;  ///< Expected result, or rejection.
  };
}  // namespace

TEST(SdsSanitizeTest, TableOfRewritesAndRejections) {
  const std::vector<sanitize_case_t> cases {
    {"report.pdf", "report.pdf"},
    {"", std::nullopt},
    {".", std::nullopt},
    {"..", std::nullopt},
    {"....", std::nullopt},
    {". .", std::nullopt},
    {" ", std::nullopt},
    {"\xFF", std::nullopt},
    {"bad\xC0\x80utf8", std::nullopt},
    {"../etc/passwd", "_._etc_passwd"},
    {"..\\windows\\system32", "_._windows_system32"},
    {"/absolute", "_absolute"},
    {"a/b\\c:d*e?f\"g<h>i|j", "a_b_c_d_e_f_g_h_i_j"},
    {std::string {"nul\0byte", 8}, "nul_byte"},
    {"tab\tname\r\n", "tab_name__"},
    {"del\x7f", "del_"},
    {"c1\xC2\x85here", "c1_here"},
    {".hidden", "_hidden"},
    {"-rf", "_rf"},
    {"--help.txt", "_-help.txt"},
    {"name. . .", "name"},
    {"trailing   ", "trailing"},
    {"CON", "_CON"},
    {"con.txt", "_con.txt"},
    {"Aux.tar.gz", "_Aux.tar.gz"},
    {"LPT9.log", "_LPT9.log"},
    {"COM1", "_COM1"},
    {"COM\xC2\xB9.txt", "_COM\xC2\xB9.txt"},
    {"CONIN$", "_CONIN$"},
    {"NUL .txt", "_NUL .txt"},
    {"CONSOLE.txt", "CONSOLE.txt"},
    {"com10", "com10"},
    {"LPT0", "LPT0"},
    {"Cafe\xCC\x81.txt", "Caf\xC3\xA9.txt"},
    {"photo\xE2\x80\xAEgnp.exe", "photo_gnp.exe"},
    {"///", "___"},
    {"\xE6\x96\x87\xE6\xA1\xA3.docx", "\xE6\x96\x87\xE6\xA1\xA3.docx"},
  };
  for (const auto &[input, expected] : cases) {
    EXPECT_EQ(sds::files::sanitize_file_name(input), expected) << "input: " << input;
  }
}

TEST(SdsSanitizeTest, TruncatesOverlongNamesKeepingShortExtensions) {
  const auto long_ascii = std::string(250, 'a') + ".pdf";
  const auto truncated = sds::files::sanitize_file_name(long_ascii);
  ASSERT_TRUE(truncated);
  EXPECT_EQ(*truncated, std::string(196, 'a') + ".pdf");
  EXPECT_EQ(truncated->size(), sds::files::NAME_MAX_BYTES);

  std::string accented;
  for (int i = 0; i < 150; ++i) {
    accented += "\xC3\xA9";
  }
  const auto truncated_multibyte = sds::files::sanitize_file_name(accented);
  ASSERT_TRUE(truncated_multibyte);
  EXPECT_EQ(truncated_multibyte->size(), 200u);
  EXPECT_EQ(*truncated_multibyte, accented.substr(0, 200));

  std::string three_byte;
  for (int i = 0; i < 80; ++i) {
    three_byte += "\xE2\x82\xAC";  // 240 bytes
  }
  const auto truncated_boundary = sds::files::sanitize_file_name(three_byte);
  ASSERT_TRUE(truncated_boundary);
  EXPECT_EQ(truncated_boundary->size(), 198u);  // 66 whole code points, never a split sequence

  const auto long_extension = "x." + std::string(300, 'y');
  const auto truncated_extension = sds::files::sanitize_file_name(long_extension);
  ASSERT_TRUE(truncated_extension);
  EXPECT_EQ(*truncated_extension, "x." + std::string(198, 'y'));

  const auto dots_at_cut = std::string(199, 'b') + "." + std::string(40, 'x');
  const auto stripped = sds::files::sanitize_file_name(dots_at_cut);
  ASSERT_TRUE(stripped);
  EXPECT_EQ(*stripped, std::string(199, 'b'));

  const auto short_extension = std::string(199, 'b') + ". tail";
  const auto kept = sds::files::sanitize_file_name(short_extension);
  ASSERT_TRUE(kept);
  EXPECT_EQ(*kept, std::string(194, 'b') + ". tail");

  const auto ext32 = "." + std::string(31, 'e');
  const auto kept32 = sds::files::sanitize_file_name(std::string(250, 'c') + ext32);
  ASSERT_TRUE(kept32);
  EXPECT_EQ(*kept32, std::string(168, 'c') + ext32);
}

TEST(SdsSanitizeTest, SanitizedNamesAreSingleSafeComponents) {
  const std::vector<std::string> hostile {
    "../../.ssh/authorized_keys",
    "..\\..\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\x.bat",
    "C:\\Windows\\win.ini",
    "\\\\server\\share\\file",
    "dir/..",
    "a\x01\x02\x1f",
  };
  for (const auto &input : hostile) {
    const auto result = sds::files::sanitize_file_name(input);
    ASSERT_TRUE(result) << input;
    EXPECT_EQ(result->find('/'), std::string::npos);
    EXPECT_EQ(result->find('\\'), std::string::npos);
    EXPECT_EQ(result->find(':'), std::string::npos);
    EXPECT_NE(result->front(), '.');
    EXPECT_NE(*result, "..");
    for (const char c : *result) {
      EXPECT_GE(static_cast<unsigned char>(c), 0x20u);
    }
  }
}

TEST(SdsSanitizeTest, CollisionNamesInsertCounterBeforeExtension) {
  EXPECT_EQ(sds::files::collision_name("report.pdf", 1), "report (1).pdf");
  EXPECT_EQ(sds::files::collision_name("noext", 2), "noext (2)");
  EXPECT_EQ(sds::files::collision_name("archive.tar.gz", 3), "archive.tar (3).gz");
  EXPECT_EQ(sds::files::collision_name("_hidden", 999), "_hidden (999)");
  EXPECT_EQ(sds::files::collision_name("x." + std::string(40, 'y'), 1), "x (1)." + std::string(40, 'y'));
  EXPECT_EQ(sds::files::collision_name("trailing.", 4), "trailing (4).");
}

TEST(SdsSanitizeTest, IdFormat) {
  EXPECT_TRUE(sds::files::is_id("0123456789abcdef0123456789abcdef"));
  EXPECT_FALSE(sds::files::is_id("0123456789ABCDEF0123456789abcdef"));
  EXPECT_FALSE(sds::files::is_id("0123456789abcdef0123456789abcde"));
  EXPECT_FALSE(sds::files::is_id("0123456789abcdef0123456789abcdeg"));
  EXPECT_FALSE(sds::files::is_id(""));
}
