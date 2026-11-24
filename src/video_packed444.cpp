/**
 * @file src/video_packed444.cpp
 * @brief Layout geometry, validation, and reference math for packed YCoCg-R P010 4:4:4 streaming.
 */
// this include
#include "video_packed444.h"

// standard includes
#include <algorithm>
#include <atomic>
#include <cmath>

namespace video {
  namespace {
    std::atomic<int> session_packed_ycocgr_mode {0};  ///< Active session override (`0` = off, `1` = Layout A1).

    constexpr std::int64_t align_up_64(std::int64_t value) {
      return ((value + 63) / 64) * 64;
    }

    constexpr int floor_div2(int value) {
      return (value >= 0) ? (value >> 1) : -((-value + 1) >> 1);
    }

    constexpr int round_div2(int value) {
      return (value >= 0) ? ((value + 1) >> 1) : -((-value + 1) >> 1);
    }
  }  // namespace

  std::optional<packed_ycocgr_layout_t> compute_ycocgr_a1_layout(
    int logical_w,
    int logical_h,
    int max_enc_w,
    int max_enc_h
  ) {
    if (logical_w < 64 || logical_h < 64 || max_enc_w <= 0 || max_enc_h <= 0) {
      return std::nullopt;
    }
    if (logical_w > max_enc_w || logical_h > max_enc_h) {
      return std::nullopt;
    }

    const std::int64_t tile_w = align_up_64(logical_w);
    const std::int64_t split_x = (static_cast<std::int64_t>(logical_w) + 1) / 2;
    const std::int64_t half_w = align_up_64(split_x);
    const std::int64_t tile_h = align_up_64(logical_h);
    const std::int64_t enc_w = tile_w + half_w;
    const std::int64_t enc_h = 2 * tile_h;

    if (enc_w > max_enc_w || enc_h > max_enc_h) {
      return std::nullopt;
    }

    return packed_ycocgr_layout_t {
      logical_w,
      logical_h,
      static_cast<int>(tile_w),
      static_cast<int>(split_x),
      static_cast<int>(half_w),
      static_cast<int>(tile_h),
      static_cast<int>(enc_w),
      static_cast<int>(enc_h),
    };
  }

  void set_session_packed_ycocgr_mode(int mode) {
    session_packed_ycocgr_mode.store(mode == 1 ? 1 : 0, std::memory_order_release);
  }

  int get_session_packed_ycocgr_mode() {
    return session_packed_ycocgr_mode.load(std::memory_order_acquire);
  }

  void clear_session_packed_ycocgr_mode() {
    session_packed_ycocgr_mode.store(0, std::memory_order_release);
  }

  bool validate_packed_ycocgr_request(
    std::string_view mode,
    bool is_vaapi,
    bool hevc_10bit_supported,
    int video_format,
    int dynamic_range,
    int logical_w,
    int logical_h,
    int &out_mode
  ) {
    out_mode = 0;
    if (mode.empty()) {
      return true;
    }
    if (mode != PACKED_YCOCGR_MODE_NAME) {
      return false;
    }
    if (!is_vaapi || !hevc_10bit_supported || video_format != 1 || dynamic_range != 0) {
      return false;
    }
    if (!compute_ycocgr_a1_layout(logical_w, logical_h).has_value()) {
      return false;
    }

    out_mode = 1;
    return true;
  }

  std::array<std::uint16_t, 3> rgb8_to_ycocgr10(std::uint8_t r, std::uint8_t g, std::uint8_t b) {
    const int ri = r;
    const int gi = g;
    const int bi = b;

    const int co = ri - bi;
    const int t = bi + floor_div2(co);
    const int cg = gi - t;
    const int y = t + floor_div2(cg);

    return {
      static_cast<std::uint16_t>(4 * y),
      static_cast<std::uint16_t>(512 + 2 * co),
      static_cast<std::uint16_t>(512 + 2 * cg),
    };
  }

  std::array<std::uint8_t, 3> ycocgr10_to_rgb8(std::uint16_t y10, std::uint16_t co10, std::uint16_t cg10) {
    const int y10_clamped = std::clamp<int>(y10, 0, 1023);
    const int co10_clamped = std::clamp<int>(co10, 0, 1023);
    const int cg10_clamped = std::clamp<int>(cg10, 0, 1023);

    const int y = (y10_clamped + 2) >> 2;
    const int co = round_div2(co10_clamped - 512);
    const int cg = round_div2(cg10_clamped - 512);

    const int t = y - floor_div2(cg);
    const int g = cg + t;
    const int b = t - floor_div2(co);
    const int r = b + co;

    return {
      static_cast<std::uint8_t>(std::clamp(r, 0, 255)),
      static_cast<std::uint8_t>(std::clamp(g, 0, 255)),
      static_cast<std::uint8_t>(std::clamp(b, 0, 255)),
    };
  }

  std::uint16_t p010_unorm_roundtrip(std::uint16_t val10) {
    const int clamped = std::clamp<int>(val10, 0, 1023);
    const float unorm = static_cast<float>(clamped * 64) / 65535.0f;
    const int u16 = static_cast<int>(std::lround(std::clamp(unorm, 0.0f, 1.0f) * 65535.0f));
    return static_cast<std::uint16_t>(u16 >> 6);
  }

}  // namespace video
