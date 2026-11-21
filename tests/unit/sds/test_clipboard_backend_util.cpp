/**
 * @file tests/unit/sds/test_clipboard_backend_util.cpp
 * @brief Tests for the platform-independent clipboard backend helpers.
 */
// The helpers are built with the Linux and Windows backends only.
#ifndef __APPLE__

  // test includes
  #include "../../tests_common.h"

  // standard includes
  #include <array>
  #include <atomic>
  #include <chrono>
  #include <cstdint>
  #include <string>
  #include <thread>
  #include <vector>

  // local includes
  #include "src/sds/clipboard_backend_util.h"

using namespace sds::clipboard;
using namespace std::literals;

namespace {
  /**
   * @brief Append a little-endian value to a byte vector.
   */
  template<typename T>
  void put(std::vector<std::uint8_t> &out, T value) {
    for (std::size_t i = 0; i < sizeof(T); ++i) {
      out.push_back(static_cast<std::uint8_t>(static_cast<std::uint64_t>(value) >> (8 * i)));
    }
  }

  /**
   * @brief Build a BITMAPINFOHEADER-family header.
   *
   * @param header_size 40, 52, 56, 108 or 124.
   * @param width Width.
   * @param height Height (negative for top-down).
   * @param bit_count Bits per pixel.
   * @param compression BI_* value.
   * @param colors_used biClrUsed.
   * @param masks R, G, B, A masks stored in V2+ headers.
   */
  std::vector<std::uint8_t> dib_header(std::uint32_t header_size, std::int32_t width, std::int32_t height, std::uint16_t bit_count, std::uint32_t compression, std::uint32_t colors_used = 0, std::array<std::uint32_t, 4> masks = {}) {
    std::vector<std::uint8_t> out;
    put<std::uint32_t>(out, header_size);
    put<std::int32_t>(out, width);
    put<std::int32_t>(out, height);
    put<std::uint16_t>(out, 1);
    put<std::uint16_t>(out, bit_count);
    put<std::uint32_t>(out, compression);
    put<std::uint32_t>(out, 0);
    put<std::int32_t>(out, 0);
    put<std::int32_t>(out, 0);
    put<std::uint32_t>(out, colors_used);
    put<std::uint32_t>(out, 0);
    if (header_size >= 52) {
      put<std::uint32_t>(out, masks[0]);
      put<std::uint32_t>(out, masks[1]);
      put<std::uint32_t>(out, masks[2]);
    }
    if (header_size >= 56) {
      put<std::uint32_t>(out, masks[3]);
    }
    out.resize(header_size, 0);
    return out;
  }

  /**
   * @brief Pixel at (x, y) of a decoded image as B, G, R, A.
   */
  std::array<std::uint8_t, 4> pixel(const util::bgra_image_t &image, std::uint32_t x, std::uint32_t y) {
    const auto *p = image.pixels.data() + (static_cast<std::size_t>(y) * image.width + x) * 4;
    return {p[0], p[1], p[2], p[3]};
  }

  /**
   * @brief A 1x1 PNG with a valid IHDR and IEND (the IDAT payload is not inspected by the helpers).
   */
  std::vector<std::uint8_t> tiny_png(std::uint32_t width = 1, std::uint32_t height = 1) {
    std::vector<std::uint8_t> png {0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n'};
    auto be32 = [&](std::uint32_t v) {
      png.push_back(static_cast<std::uint8_t>(v >> 24));
      png.push_back(static_cast<std::uint8_t>(v >> 16));
      png.push_back(static_cast<std::uint8_t>(v >> 8));
      png.push_back(static_cast<std::uint8_t>(v));
    };
    be32(13);
    png.insert(png.end(), {'I', 'H', 'D', 'R'});
    be32(width);
    be32(height);
    png.insert(png.end(), {8, 6, 0, 0, 0});
    be32(0);  // CRC (not checked)
    be32(0);
    png.insert(png.end(), {'I', 'E', 'N', 'D'});
    be32(0);
    return png;
  }
}  // namespace

TEST(ClipboardUtilTest, RepairUtf8KeepsValidText) {
  const std::string text = "plain ASCII, caf\xC3\xA9, \xE2\x9C\x93, \xF0\x9F\x8E\x89";
  EXPECT_TRUE(util::is_valid_utf8(text));
  EXPECT_EQ(util::repair_utf8(text), text);
}

TEST(ClipboardUtilTest, RepairUtf8ReplacesInvalidSequences) {
  EXPECT_FALSE(util::is_valid_utf8("\xC0\xAF"));  // overlong '/'
  EXPECT_EQ(util::repair_utf8("a\xFF"
                              "b"),
            "a\xEF\xBF\xBD"
            "b");
  EXPECT_EQ(util::repair_utf8("\xED\xA0\x80"), "\xEF\xBF\xBD\xEF\xBF\xBD\xEF\xBF\xBD");  // surrogate
  EXPECT_EQ(util::repair_utf8("\xF4\x90\x80\x80").substr(0, 3), "\xEF\xBF\xBD");  // > U+10FFFF
  EXPECT_EQ(util::repair_utf8("x\xE2\x9C"), "x\xEF\xBF\xBD\xEF\xBF\xBD");  // truncated
  EXPECT_EQ(util::repair_utf8("\xE2(\xA1"), "\xEF\xBF\xBD(\xEF\xBF\xBD");  // bad continuation
  EXPECT_EQ(util::repair_utf8("\xC0\xAF"), "\xEF\xBF\xBD\xEF\xBF\xBD");
}

TEST(ClipboardUtilTest, SanitizeTextStripsTrailingNulAndRejectsEmbeddedNul) {
  EXPECT_EQ(util::sanitize_text(std::string("hello\0\0", 7)), "hello");
  EXPECT_FALSE(util::sanitize_text(std::string("he\0llo", 6)));
  EXPECT_FALSE(util::sanitize_text(""));
  EXPECT_FALSE(util::sanitize_text(std::string("\0", 1)));
  EXPECT_EQ(util::sanitize_text("ok\xFF"), "ok\xEF\xBF\xBD");
}

TEST(ClipboardUtilTest, Latin1Conversions) {
  EXPECT_EQ(util::latin1_to_utf8("caf\xE9 \xFF"), "caf\xC3\xA9 \xC3\xBF");
  EXPECT_EQ(util::utf8_to_latin1_lossy("caf\xC3\xA9 \xE2\x9C\x93 \xF0\x9F\x8E\x89"), "caf\xE9 ? ?");
  EXPECT_EQ(util::utf8_to_latin1_lossy("bad\xFF"), "bad?");
}

TEST(ClipboardUtilTest, LineEndingConversions) {
  EXPECT_EQ(util::crlf_to_lf("a\r\nb\r\n\rc\n"), "a\nb\n\rc\n");
  EXPECT_EQ(util::lf_to_crlf("a\nb\r\nc\n"), "a\r\nb\r\nc\r\n");
  EXPECT_EQ(util::lf_to_crlf("\n"), "\r\n");
  EXPECT_EQ(util::crlf_to_lf(util::lf_to_crlf("x\ny\n\nz")), "x\ny\n\nz");
  EXPECT_EQ(util::crlf_to_lf(""), "");
}

TEST(ClipboardUtilTest, Utf16Conversions) {
  const std::string utf8 = "A\xC3\xA9\xE2\x9C\x93\xF0\x9F\x8E\x89";
  const std::u16string utf16 = u"Aé✓\U0001F389";
  EXPECT_EQ(util::utf8_to_utf16(utf8), utf16);
  EXPECT_EQ(util::utf16_to_utf8(utf16), utf8);
  EXPECT_EQ(util::utf16_to_utf8(std::u16string {char16_t(0xD800), u'x'}), "\xEF\xBF\xBDx");  // unpaired high
  EXPECT_EQ(util::utf16_to_utf8(std::u16string {char16_t(0xDC00)}), "\xEF\xBF\xBD");  // lone low
  EXPECT_EQ(util::utf16_to_utf8(std::u16string {char16_t(0xD800)}), "\xEF\xBF\xBD");  // high at end
  EXPECT_EQ(util::utf8_to_utf16("\xFF"), std::u16string {char16_t(0xFFFD)});
}

TEST(ClipboardUtilTest, PngHeaderChecks) {
  const auto png = tiny_png(640, 480);
  EXPECT_TRUE(util::has_png_signature(png));
  const auto dims = util::png_dimensions(png);
  ASSERT_TRUE(dims);
  EXPECT_EQ(dims->width, 640u);
  EXPECT_EQ(dims->height, 480u);
  EXPECT_TRUE(util::png_header_sane(png));
  EXPECT_FALSE(util::png_header_sane(tiny_png(20000, 20000)));  // 1.6 GB decoded
  EXPECT_FALSE(util::png_dimensions(tiny_png(0, 5)));
  EXPECT_FALSE(util::png_dimensions(tiny_png(0x80000000u, 1)));

  auto wrong_chunk = png;
  wrong_chunk[12] = 'X';
  EXPECT_FALSE(util::png_dimensions(wrong_chunk));
  EXPECT_FALSE(util::has_png_signature(std::vector<std::uint8_t> {'G', 'I', 'F', '8', '9', 'a', 0, 0}));
  EXPECT_FALSE(util::png_dimensions(std::vector<std::uint8_t>(png.begin(), png.begin() + 20)));
}

TEST(ClipboardUtilTest, PngStreamLengthStopsAtIend) {
  auto png = tiny_png();
  const auto length = png.size();
  EXPECT_EQ(util::png_stream_length(png), length);
  png.resize(length + 100, 0xAB);  // GlobalAlloc padding
  EXPECT_EQ(util::png_stream_length(png), length);
  png.resize(length - 1);  // truncated IEND
  EXPECT_EQ(util::png_stream_length(png), 0u);
  EXPECT_EQ(util::png_stream_length(std::vector<std::uint8_t> {1, 2, 3}), 0u);
  auto no_iend = tiny_png();
  no_iend.resize(length - 12);
  EXPECT_EQ(util::png_stream_length(no_iend), 0u);
}

TEST(ClipboardUtilTest, Dib24BitBottomUp) {
  auto dib = dib_header(40, 2, 2, 24, 0);
  // Bottom row first: (0,1)=blue (1,1)=green, then top row (0,0)=red (1,0)=white; rows padded to 8 bytes
  dib.insert(dib.end(), {0xFF, 0, 0, 0, 0xFF, 0, 0, 0});
  dib.insert(dib.end(), {0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0});
  const auto image = util::dib_to_bgra(dib);
  ASSERT_TRUE(image);
  EXPECT_EQ(image->width, 2u);
  EXPECT_EQ(image->height, 2u);
  EXPECT_EQ(pixel(*image, 0, 0), (std::array<std::uint8_t, 4> {0, 0, 0xFF, 0xFF}));
  EXPECT_EQ(pixel(*image, 1, 0), (std::array<std::uint8_t, 4> {0xFF, 0xFF, 0xFF, 0xFF}));
  EXPECT_EQ(pixel(*image, 0, 1), (std::array<std::uint8_t, 4> {0xFF, 0, 0, 0xFF}));
  EXPECT_EQ(pixel(*image, 1, 1), (std::array<std::uint8_t, 4> {0, 0xFF, 0, 0xFF}));
}

TEST(ClipboardUtilTest, Dib32BitRgbWithZeroReservedBytesIsOpaque) {
  auto dib = dib_header(40, 1, -2, 32, 0);  // top-down
  dib.insert(dib.end(), {10, 20, 30, 0, 40, 50, 60, 0});
  const auto image = util::dib_to_bgra(dib);
  ASSERT_TRUE(image);
  EXPECT_EQ(pixel(*image, 0, 0), (std::array<std::uint8_t, 4> {10, 20, 30, 0xFF}));
  EXPECT_EQ(pixel(*image, 0, 1), (std::array<std::uint8_t, 4> {40, 50, 60, 0xFF}));
}

TEST(ClipboardUtilTest, Dib32BitRgbKeepsReservedAlphaWhenUsed) {
  auto dib = dib_header(40, 2, 1, 32, 0);
  dib.insert(dib.end(), {10, 20, 30, 0x80, 40, 50, 60, 0});
  const auto image = util::dib_to_bgra(dib);
  ASSERT_TRUE(image);
  EXPECT_EQ(pixel(*image, 0, 0)[3], 0x80);
  EXPECT_EQ(pixel(*image, 1, 0)[3], 0);
}

TEST(ClipboardUtilTest, DibV5BitfieldsWithAlpha) {
  // V5 header, BI_BITFIELDS with masks inside the header (as Firefox and Chrome write CF_DIBV5)
  auto dib = dib_header(124, 1, 1, 32, 3, 0, {0x00FF0000, 0x0000FF00, 0x000000FF, 0xFF000000});
  put<std::uint32_t>(dib, 0x40112233);  // A=0x40 R=0x11 G=0x22 B=0x33
  const auto image = util::dib_to_bgra(dib);
  ASSERT_TRUE(image);
  EXPECT_EQ(pixel(*image, 0, 0), (std::array<std::uint8_t, 4> {0x33, 0x22, 0x11, 0x40}));
}

TEST(ClipboardUtilTest, DibInfoHeaderBitfieldsMasksFollowHeader) {
  // BITMAPINFOHEADER + three masks (RGB565)
  auto dib = dib_header(40, 2, 1, 16, 3);
  put<std::uint32_t>(dib, 0xF800);
  put<std::uint32_t>(dib, 0x07E0);
  put<std::uint32_t>(dib, 0x001F);
  put<std::uint16_t>(dib, 0xF800);  // red
  put<std::uint16_t>(dib, 0x001F);  // blue
  const auto image = util::dib_to_bgra(dib);
  ASSERT_TRUE(image);
  EXPECT_EQ(pixel(*image, 0, 0), (std::array<std::uint8_t, 4> {0, 0, 0xFF, 0xFF}));
  EXPECT_EQ(pixel(*image, 1, 0), (std::array<std::uint8_t, 4> {0xFF, 0, 0, 0xFF}));
}

TEST(ClipboardUtilTest, DibAlphaBitfieldsMasksFollowHeader) {
  auto dib = dib_header(40, 1, 1, 32, 6);
  put<std::uint32_t>(dib, 0x00FF0000);
  put<std::uint32_t>(dib, 0x0000FF00);
  put<std::uint32_t>(dib, 0x000000FF);
  put<std::uint32_t>(dib, 0xFF000000);
  put<std::uint32_t>(dib, 0x80010203);
  const auto image = util::dib_to_bgra(dib);
  ASSERT_TRUE(image);
  EXPECT_EQ(pixel(*image, 0, 0), (std::array<std::uint8_t, 4> {3, 2, 1, 0x80}));
}

TEST(ClipboardUtilTest, Dib16BitDefault555) {
  auto dib = dib_header(40, 1, 1, 16, 0);
  put<std::uint16_t>(dib, 0x7C00);  // red in 555
  put<std::uint16_t>(dib, 0);  // row padding
  const auto image = util::dib_to_bgra(dib);
  ASSERT_TRUE(image);
  EXPECT_EQ(pixel(*image, 0, 0), (std::array<std::uint8_t, 4> {0, 0, 0xFF, 0xFF}));
}

TEST(ClipboardUtilTest, DibPaletted8And4And1Bit) {
  {
    auto dib = dib_header(40, 2, 1, 8, 0, 2);
    dib.insert(dib.end(), {1, 2, 3, 0, 4, 5, 6, 0});  // palette
    dib.insert(dib.end(), {1, 0, 0, 0});  // pixels + padding
    const auto image = util::dib_to_bgra(dib);
    ASSERT_TRUE(image);
    EXPECT_EQ(pixel(*image, 0, 0), (std::array<std::uint8_t, 4> {4, 5, 6, 0xFF}));
    EXPECT_EQ(pixel(*image, 1, 0), (std::array<std::uint8_t, 4> {1, 2, 3, 0xFF}));
  }
  {
    auto dib = dib_header(40, 3, 1, 4, 0, 3);
    dib.insert(dib.end(), {0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0, 9, 9, 9, 0});
    dib.insert(dib.end(), {0x12, 0x00, 0, 0});  // indices 1, 2, 0
    const auto image = util::dib_to_bgra(dib);
    ASSERT_TRUE(image);
    EXPECT_EQ(pixel(*image, 0, 0)[0], 0xFF);
    EXPECT_EQ(pixel(*image, 1, 0)[0], 9);
    EXPECT_EQ(pixel(*image, 2, 0)[0], 0);
  }
  {
    auto dib = dib_header(40, 9, 1, 1, 0);  // default palette size 2
    dib.insert(dib.end(), {0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0});
    dib.insert(dib.end(), {0x80, 0x80, 0, 0});  // pixel 0 and pixel 8 set
    const auto image = util::dib_to_bgra(dib);
    ASSERT_TRUE(image);
    EXPECT_EQ(pixel(*image, 0, 0)[0], 0xFF);
    EXPECT_EQ(pixel(*image, 1, 0)[0], 0);
    EXPECT_EQ(pixel(*image, 8, 0)[0], 0xFF);
  }
}

TEST(ClipboardUtilTest, DibSkipsOptionalColorTableOfTrueColorImages) {
  auto dib = dib_header(40, 1, 1, 24, 0, 1);
  dib.insert(dib.end(), {9, 9, 9, 0});  // color table entry to skip
  dib.insert(dib.end(), {1, 2, 3, 0});
  const auto image = util::dib_to_bgra(dib);
  ASSERT_TRUE(image);
  EXPECT_EQ(pixel(*image, 0, 0), (std::array<std::uint8_t, 4> {1, 2, 3, 0xFF}));
}

TEST(ClipboardUtilTest, DibRejectsMalformedAndUnsupported) {
  EXPECT_FALSE(util::dib_to_bgra(std::vector<std::uint8_t>(10)));
  auto truncated = dib_header(40, 4, 4, 32, 0);
  truncated.resize(truncated.size() + 10);
  EXPECT_FALSE(util::dib_to_bgra(truncated));
  auto rle = dib_header(40, 1, 1, 8, 1);
  rle.resize(rle.size() + 1024 + 4);
  EXPECT_FALSE(util::dib_to_bgra(rle));
  auto png_compressed = dib_header(40, 1, 1, 0, 5);
  png_compressed.resize(png_compressed.size() + 64);
  EXPECT_FALSE(util::dib_to_bgra(png_compressed));
  auto zero_width = dib_header(40, 0, 1, 32, 0);
  zero_width.resize(zero_width.size() + 4);
  EXPECT_FALSE(util::dib_to_bgra(zero_width));
  auto zero_height = dib_header(40, 1, 0, 32, 0);
  EXPECT_FALSE(util::dib_to_bgra(zero_height));
  auto bad_depth = dib_header(40, 1, 1, 7, 0);
  bad_depth.resize(bad_depth.size() + 4);
  EXPECT_FALSE(util::dib_to_bgra(bad_depth));
  auto bitfields_24 = dib_header(40, 1, 1, 24, 3);
  bitfields_24.resize(bitfields_24.size() + 16);
  EXPECT_FALSE(util::dib_to_bgra(bitfields_24));
  auto missing_masks = dib_header(40, 1, 1, 32, 3);
  EXPECT_FALSE(util::dib_to_bgra(missing_masks));
  auto big_palette = dib_header(40, 1, 1, 1, 0, 3);
  big_palette.resize(big_palette.size() + 64);
  EXPECT_FALSE(util::dib_to_bgra(big_palette));
  auto header_too_big = dib_header(40, 1, 1, 32, 0);
  header_too_big[0] = 0xFF;
  EXPECT_FALSE(util::dib_to_bgra(header_too_big));
  // 20000 x 20000 x 4 exceeds the decoded size limit before any pixel data is needed
  auto huge = dib_header(40, 20000, 20000, 32, 0);
  EXPECT_FALSE(util::dib_to_bgra(huge));
}

TEST(ClipboardUtilTest, BgraToDibRoundTrip) {
  util::bgra_image_t image;
  image.width = 3;
  image.height = 2;
  for (std::uint8_t i = 0; i < 24; ++i) {
    image.pixels.push_back(static_cast<std::uint8_t>(i * 10 + 1));
  }
  const auto dib = util::bgra_to_dib(image);
  ASSERT_EQ(dib.size(), 40u + 24u);
  EXPECT_EQ(dib[0], 40);
  const auto decoded = util::dib_to_bgra(dib);
  ASSERT_TRUE(decoded);
  EXPECT_EQ(decoded->width, 3u);
  EXPECT_EQ(decoded->height, 2u);
  EXPECT_EQ(decoded->pixels, image.pixels);

  util::bgra_image_t inconsistent;
  inconsistent.width = 2;
  inconsistent.height = 2;
  inconsistent.pixels.resize(3);
  EXPECT_TRUE(util::bgra_to_dib(inconsistent).empty());
  EXPECT_TRUE(util::bgra_to_dib(util::bgra_image_t {}).empty());
}

TEST(ClipboardUtilTest, MimeMatching) {
  EXPECT_TRUE(util::mime_equal("text/plain;charset=utf-8", "TEXT/PLAIN; charset=UTF-8"));
  EXPECT_FALSE(util::mime_equal("text/plain", "text/plain;charset=utf-8"));
  EXPECT_FALSE(util::mime_equal("image/png", "image/pn"));

  const std::vector<std::string> offered {"TARGETS", "text/plain;charset=UTF-8", "image/png", "UTF8_STRING"};
  EXPECT_EQ(util::pick_mime(offered, {"text/plain;charset=utf-8", "UTF8_STRING"}), "text/plain;charset=UTF-8");
  EXPECT_EQ(util::pick_mime(offered, {"STRING", "UTF8_STRING"}), "UTF8_STRING");
  EXPECT_FALSE(util::pick_mime(offered, {"image/jpeg"}));
  EXPECT_FALSE(util::pick_mime({}, {"image/png"}));
}

TEST(ClipboardUtilTest, ApplyLimitsDropsOversizedRepresentations) {
  item_t item;
  item.text = std::string(11, 'x');
  item.png = std::vector<std::uint8_t>(5, 1);
  util::apply_limits(item, {10, 5});
  EXPECT_FALSE(item.text);
  ASSERT_TRUE(item.png);
  EXPECT_EQ(item.png->size(), 5u);
  util::apply_limits(item, {10, 4});
  EXPECT_TRUE(item.empty());
}

TEST(ClipboardUtilTest, NotifierCoalescesAndStops) {
  util::change_notifier_t notifier;
  std::atomic<int> calls {0};
  std::atomic<bool> release {false};
  notifier.start([&]() {
    ++calls;
    while (!release.load()) {
      std::this_thread::sleep_for(1ms);
    }
  });
  notifier.notify();
  for (int i = 0; i < 200 && calls.load() == 0; ++i) {
    std::this_thread::sleep_for(5ms);
  }
  ASSERT_EQ(calls.load(), 1);
  // While the callback runs, a burst of notifications collapses into one more call
  for (int i = 0; i < 10; ++i) {
    notifier.notify();
  }
  release = true;
  for (int i = 0; i < 200 && calls.load() < 2; ++i) {
    std::this_thread::sleep_for(5ms);
  }
  std::this_thread::sleep_for(50ms);
  EXPECT_EQ(calls.load(), 2);

  notifier.stop();
  notifier.stop();  // idempotent
  notifier.notify();  // ignored after stop
  std::this_thread::sleep_for(20ms);
  EXPECT_EQ(calls.load(), 2);
}

TEST(ClipboardUtilTest, NotifierCanBeStoppedFromItsCallback) {
  util::change_notifier_t notifier;
  std::atomic<bool> stopped {false};
  notifier.start([&]() {
    notifier.stop();
    stopped = true;
  });
  notifier.notify();
  for (int i = 0; i < 200 && !stopped.load(); ++i) {
    std::this_thread::sleep_for(5ms);
  }
  EXPECT_TRUE(stopped.load());
  std::this_thread::sleep_for(20ms);  // let the detached thread return before the notifier is destroyed
}

TEST(ClipboardUtilTest, NotifierRestartsWithNewCallback) {
  util::change_notifier_t notifier;
  std::atomic<int> first {0};
  std::atomic<int> second {0};
  notifier.start([&]() {
    ++first;
  });
  notifier.start([&]() {
    ++second;
  });
  notifier.notify();
  for (int i = 0; i < 200 && second.load() == 0; ++i) {
    std::this_thread::sleep_for(5ms);
  }
  EXPECT_EQ(first.load(), 0);
  EXPECT_EQ(second.load(), 1);
}

#endif
