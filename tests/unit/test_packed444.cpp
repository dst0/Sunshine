/**
 * @file tests/unit/test_packed444.cpp
 * @brief Unit tests for Layout A1 packed YCoCg-R P010 4:4:4 geometry, validation, and lossless math.
 */

// test includes
#include "../tests_common.h"

// standard includes
#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <tuple>
#include <vector>

// local includes
#include <src/video_packed444.h>

TEST(Packed444LayoutTest, ComputesExpectedCtuAlignedGeometry) {
  const std::array cases {
    std::tuple {1920, 1080, 1920, 960, 960, 1088, 2880, 2176},
    std::tuple {2560, 1440, 2560, 1280, 1280, 1472, 3840, 2944},
    std::tuple {2880, 1864, 2880, 1440, 1472, 1920, 4352, 3840},
    std::tuple {3024, 1964, 3072, 1512, 1536, 1984, 4608, 3968},
    std::tuple {3840, 2160, 3840, 1920, 1920, 2176, 5760, 4352},
    std::tuple {1511, 981, 1536, 756, 768, 1024, 2304, 2048},
    std::tuple {64, 64, 64, 32, 64, 64, 128, 128},
  };

  for (const auto &[w, h, tile_w, split_x, half_w, tile_h, enc_w, enc_h] : cases) {
    const auto layout = video::compute_ycocgr_a1_layout(w, h);
    ASSERT_TRUE(layout.has_value()) << w << "x" << h;
    EXPECT_EQ(layout->logical_w, w);
    EXPECT_EQ(layout->logical_h, h);
    EXPECT_EQ(layout->tile_w, tile_w);
    EXPECT_EQ(layout->split_x, split_x);
    EXPECT_EQ(layout->half_w, half_w);
    EXPECT_EQ(layout->tile_h, tile_h);
    EXPECT_EQ(layout->enc_w, enc_w);
    EXPECT_EQ(layout->enc_h, enc_h);

    EXPECT_EQ(layout->tile_w % 64, 0);
    EXPECT_EQ(layout->half_w % 64, 0);
    EXPECT_EQ(layout->tile_h % 64, 0);
    EXPECT_EQ(layout->enc_w % 64, 0);
    EXPECT_EQ(layout->enc_h % 64, 0);
    EXPECT_LE(layout->enc_w, video::PACKED_YCOCGR_MAX_ENC_W);
    EXPECT_LE(layout->enc_h, video::PACKED_YCOCGR_MAX_ENC_H);
  }
}

TEST(Packed444LayoutTest, RejectsInvalidAndOutOfBoundsDimensions) {
  const std::array invalid_cases {
    std::pair {0, 0},
    std::pair {63, 64},
    std::pair {64, 63},
    std::pair {-1920, 1080},
    std::pair {1920, -1080},
    std::pair {5120, 2880},
    std::pair {8192, 2160},
    std::pair {std::numeric_limits<int>::max(), std::numeric_limits<int>::max()},
  };

  for (const auto &[w, h] : invalid_cases) {
    EXPECT_FALSE(video::compute_ycocgr_a1_layout(w, h).has_value()) << w << "x" << h;
  }
}

TEST(Packed444MathTest, ExhaustiveRgb888YCoCgRAndP010RoundtripIsLossless) {
  for (int val10 = 0; val10 < 1024; ++val10) {
    EXPECT_EQ(video::p010_unorm_roundtrip(static_cast<std::uint16_t>(val10)), val10);
  }
  EXPECT_EQ(video::p010_unorm_roundtrip(512), 512);

  int max_err = 0;
  for (int r = 0; r < 256; ++r) {
    for (int g = 0; g < 256; ++g) {
      for (int b = 0; b < 256; ++b) {
        const auto enc = video::rgb8_to_ycocgr10(
          static_cast<std::uint8_t>(r),
          static_cast<std::uint8_t>(g),
          static_cast<std::uint8_t>(b)
        );

        ASSERT_LE(enc[0], 1020u);
        ASSERT_EQ(enc[0] % 4u, 0u);
        ASSERT_GE(enc[1], 2u);
        ASSERT_LE(enc[1], 1022u);
        ASSERT_EQ(enc[1] % 2u, 0u);
        ASSERT_GE(enc[2], 2u);
        ASSERT_LE(enc[2], 1022u);
        ASSERT_EQ(enc[2] % 2u, 0u);

        const auto y10 = video::p010_unorm_roundtrip(enc[0]);
        const auto co10 = video::p010_unorm_roundtrip(enc[1]);
        const auto cg10 = video::p010_unorm_roundtrip(enc[2]);
        ASSERT_EQ(y10, enc[0]);
        ASSERT_EQ(co10, enc[1]);
        ASSERT_EQ(cg10, enc[2]);

        const auto dec = video::ycocgr10_to_rgb8(y10, co10, cg10);
        max_err = std::max({
          max_err,
          std::abs(static_cast<int>(dec[0]) - r),
          std::abs(static_cast<int>(dec[1]) - g),
          std::abs(static_cast<int>(dec[2]) - b),
        });
        ASSERT_EQ(max_err, 0) << "rgb=(" << r << "," << g << "," << b << ")";
      }
    }
  }
  EXPECT_EQ(max_err, 0);
}

TEST(Packed444LayoutTest, RegionA1PackAndUnpackPreservesOddFramePixels) {
  const auto layout_opt = video::compute_ycocgr_a1_layout(1511, 981);
  ASSERT_TRUE(layout_opt.has_value());
  const auto &l = *layout_opt;

  const auto pixel_rgb = [](int x, int y) -> std::array<std::uint8_t, 3> {
    return {
      static_cast<std::uint8_t>((x * 7 + y * 13) & 0xFF),
      static_cast<std::uint8_t>((x * 11 + y * 5 + 37) & 0xFF),
      static_cast<std::uint8_t>((x * 3 + y * 17 + 91) & 0xFF),
    };
  };

  std::vector<std::uint16_t> y_plane(static_cast<std::size_t>(l.enc_w) * l.enc_h, 0);
  for (int dy = 0; dy < l.enc_h; ++dy) {
    for (int dx = 0; dx < l.enc_w; ++dx) {
      int sx = 0;
      int sy = 0;
      int ch = 0;
      if (dx < l.tile_w) {
        sx = std::min(dx, l.logical_w - 1);
        if (dy < l.tile_h) {
          sy = std::min(dy, l.logical_h - 1);
          ch = 0;
        } else {
          sy = std::min(dy - l.tile_h, l.logical_h - 1);
          ch = 1;
        }
      } else {
        const int rx = dx - l.tile_w;
        if (dy < l.tile_h) {
          sx = std::min(rx, l.split_x - 1);
          sy = std::min(dy, l.logical_h - 1);
        } else {
          sx = std::min(l.split_x + rx, l.logical_w - 1);
          sy = std::min(dy - l.tile_h, l.logical_h - 1);
        }
        ch = 2;
      }

      const auto rgb = pixel_rgb(sx, sy);
      const auto ycocg = video::rgb8_to_ycocgr10(rgb[0], rgb[1], rgb[2]);
      y_plane[static_cast<std::size_t>(dy) * l.enc_w + dx] = video::p010_unorm_roundtrip(ycocg[ch]);
    }
  }

  for (int y = 0; y < l.logical_h; ++y) {
    for (int x = 0; x < l.logical_w; ++x) {
      const auto y10 = y_plane[static_cast<std::size_t>(y) * l.enc_w + x];
      const auto co10 = y_plane[static_cast<std::size_t>(y + l.tile_h) * l.enc_w + x];
      const int cg_x = l.tile_w + (x < l.split_x ? x : (x - l.split_x));
      const int cg_y = y + (x < l.split_x ? 0 : l.tile_h);
      const auto cg10 = y_plane[static_cast<std::size_t>(cg_y) * l.enc_w + cg_x];

      const auto dec = video::ycocgr10_to_rgb8(y10, co10, cg10);
      ASSERT_EQ(dec, pixel_rgb(x, y)) << "mismatch at (" << x << "," << y << ")";
    }
  }
}

TEST(Packed444ValidationTest, ValidatesModeCapabilitiesAndSessionOverrides) {
  video::clear_session_packed_ycocgr_mode();
  EXPECT_EQ(video::get_session_packed_ycocgr_mode(), 0);

  video::set_session_packed_ycocgr_mode(1);
  EXPECT_EQ(video::get_session_packed_ycocgr_mode(), 1);
  video::set_session_packed_ycocgr_mode(99);
  EXPECT_EQ(video::get_session_packed_ycocgr_mode(), 0);
  video::set_session_packed_ycocgr_mode(1);
  video::clear_session_packed_ycocgr_mode();
  EXPECT_EQ(video::get_session_packed_ycocgr_mode(), 0);

  int out_mode = -1;
  EXPECT_TRUE(video::validate_packed_ycocgr_request("", false, false, 0, 1, 5120, 2880, out_mode));
  EXPECT_EQ(out_mode, 0);

  out_mode = -1;
  EXPECT_TRUE(video::validate_packed_ycocgr_request("ycocgr_p010_a1", true, true, 1, 0, 1920, 1080, out_mode));
  EXPECT_EQ(out_mode, 1);

  EXPECT_FALSE(video::validate_packed_ycocgr_request("ycocgr_unknown", true, true, 1, 0, 1920, 1080, out_mode));
  EXPECT_EQ(out_mode, 0);

  EXPECT_FALSE(video::validate_packed_ycocgr_request("ycocgr_p010_a1", false, true, 1, 0, 1920, 1080, out_mode));
  EXPECT_EQ(out_mode, 0);

  EXPECT_FALSE(video::validate_packed_ycocgr_request("ycocgr_p010_a1", true, false, 1, 0, 1920, 1080, out_mode));
  EXPECT_EQ(out_mode, 0);

  EXPECT_FALSE(video::validate_packed_ycocgr_request("ycocgr_p010_a1", true, true, 0, 0, 1920, 1080, out_mode));
  EXPECT_EQ(out_mode, 0);

  EXPECT_FALSE(video::validate_packed_ycocgr_request("ycocgr_p010_a1", true, true, 2, 0, 1920, 1080, out_mode));
  EXPECT_EQ(out_mode, 0);

  EXPECT_FALSE(video::validate_packed_ycocgr_request("ycocgr_p010_a1", true, true, 1, 1, 1920, 1080, out_mode));
  EXPECT_EQ(out_mode, 0);

  EXPECT_FALSE(video::validate_packed_ycocgr_request("ycocgr_p010_a1", true, true, 1, 0, 5120, 2880, out_mode));
  EXPECT_EQ(out_mode, 0);

  EXPECT_FALSE(video::validate_packed_ycocgr_request("ycocgr_p010_a1", true, true, 1, 0, 0, 0, out_mode));
  EXPECT_EQ(out_mode, 0);
}
