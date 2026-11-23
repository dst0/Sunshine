/**
 * @file tests/unit/sds/test_sds_text.cpp
 * @brief Test src/sds/text.* (UTF-8 validation and NFC normalization).
 */

// test includes
#include "../../tests_common.h"

// standard includes
#include <chrono>
#include <string>
#include <utility>
#include <vector>

// local includes
#include <src/sds/text.h>

using namespace std::literals;

TEST(SdsTextTest, AcceptsWellFormedUtf8) {
  EXPECT_TRUE(sds::text::is_valid_utf8(""sv));
  EXPECT_TRUE(sds::text::is_valid_utf8("plain ascii"sv));
  EXPECT_TRUE(sds::text::is_valid_utf8("\xC3\xA9"sv));  // U+00E9
  EXPECT_TRUE(sds::text::is_valid_utf8("\xE2\x82\xAC"sv));  // U+20AC
  EXPECT_TRUE(sds::text::is_valid_utf8("\xF0\x9F\x98\x80"sv));  // U+1F600
  EXPECT_TRUE(sds::text::is_valid_utf8("\xF4\x8F\xBF\xBF"sv));  // U+10FFFF
  EXPECT_TRUE(sds::text::is_valid_utf8(std::string_view {"a\0b", 3}));  // NUL is valid UTF-8; callers reject it separately
}

TEST(SdsTextTest, RejectsMalformedUtf8) {
  const std::vector<std::string_view> invalid {
    "\x80"sv,  // stray continuation
    "\xC0\x80"sv,  // overlong NUL
    "\xC1\xBF"sv,  // overlong
    "\xE0\x80\x80"sv,  // overlong 3-byte
    "\xF0\x80\x80\x80"sv,  // overlong 4-byte
    "\xED\xA0\x80"sv,  // surrogate U+D800
    "\xF4\x90\x80\x80"sv,  // above U+10FFFF
    "\xF5\x80\x80\x80"sv,  // invalid lead byte
    "\xC3"sv,  // truncated
    "\xE2\x82"sv,  // truncated
    "\xE2\x28\xA1"sv,  // bad continuation
    "\xFF"sv,
  };
  for (const auto bytes : invalid) {
    EXPECT_FALSE(sds::text::is_valid_utf8(bytes));
    EXPECT_FALSE(sds::text::decode_utf8(bytes).has_value());
    EXPECT_FALSE(sds::text::to_nfc(bytes).has_value());
  }
}

TEST(SdsTextTest, RoundTripsCodePoints) {
  const std::u32string code_points {U'a', 0xE9, 0x20AC, 0x1F600, 0x10FFFF};
  const auto encoded = sds::text::encode_utf8(code_points);
  EXPECT_EQ(encoded, "a\xC3\xA9\xE2\x82\xAC\xF0\x9F\x98\x80\xF4\x8F\xBF\xBF");
  const auto decoded = sds::text::decode_utf8(encoded);
  ASSERT_TRUE(decoded);
  EXPECT_EQ(*decoded, code_points);
}

TEST(SdsTextTest, NormalizesNfdToNfc) {
  // Expected values computed with Python unicodedata.normalize('NFC', ...).
  const std::vector<std::pair<std::string_view, std::string_view>> cases {
    {"e\xCC\x81"sv, "\xC3\xA9"sv},  // e + COMBINING ACUTE -> U+00E9
    {"Cafe\xCC\x81.txt"sv, "Caf\xC3\xA9.txt"sv},
    {"A\xCC\x8A"sv, "\xC3\x85"sv},  // A + RING -> U+00C5 (not U+212B ANGSTROM SIGN)
    {"\xE2\x84\xAB"sv, "\xC3\x85"sv},  // U+212B singleton decomposes to U+00C5
    {"\xE1\x84\x80\xE1\x85\xA1"sv, "\xEA\xB0\x80"sv},  // Hangul L+V -> U+AC00
    {"\xE1\x84\x80\xE1\x85\xA1\xE1\x86\xA8"sv, "\xEA\xB0\x81"sv},  // Hangul L+V+T -> U+AC01
    {"a\xCC\x82\xCC\xA3"sv, "\xE1\xBA\xAD"sv},  // a + circumflex + dot below reorders -> U+1EAD
    {"a\xCC\xA3\xCC\x82"sv, "\xE1\xBA\xAD"sv},
    {"\xD0\x98\xCC\x86"sv, "\xD0\x99"sv},  // Cyrillic I + BREVE -> U+0419
    {"\xE0\xA5\x98"sv, "\xE0\xA4\x95\xE0\xA4\xBC"sv},  // U+0958 is a composition exclusion
    {"already composed \xC3\xBC"sv, "already composed \xC3\xBC"sv},
    {"\xCC\x81"sv, "\xCC\x81"sv},  // leading combining mark stays
  };
  for (const auto &[input, expected] : cases) {
    const auto normalized = sds::text::to_nfc(input);
    ASSERT_TRUE(normalized) << input;
    EXPECT_EQ(*normalized, expected) << input;
  }
}

TEST(SdsTextTest, NormalizesLongCombiningMarkRunsEfficiently) {
  constexpr int count = 10000;
  std::string input = "e";
  input.reserve(1 + count * 4);
  for (int i = 0; i < count; ++i) {
    input += "\xCC\x81";  // U+0301 COMBINING ACUTE ACCENT (ccc=230)
  }
  for (int i = 0; i < count; ++i) {
    input += "\xCC\x96";  // U+0316 COMBINING GRAVE ACCENT BELOW (ccc=220)
  }

  std::string expected = "\xC3\xA9";  // U+00E9
  expected.reserve(2 + count * 2 + (count - 1) * 2);
  for (int i = 0; i < count; ++i) {
    expected += "\xCC\x96";
  }
  for (int i = 0; i < count - 1; ++i) {
    expected += "\xCC\x81";
  }

  const auto start = std::chrono::steady_clock::now();
  const auto normalized = sds::text::to_nfc(input);
  const auto elapsed = std::chrono::steady_clock::now() - start;
  ASSERT_TRUE(normalized);
  EXPECT_EQ(*normalized, expected);
  EXPECT_LT(elapsed, std::chrono::seconds(2));
}
