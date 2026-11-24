/**
 * @file src/video_packed444.h
 * @brief Layout geometry, validation, and reference math for packed YCoCg-R P010 4:4:4 streaming.
 */
#pragma once

// standard includes
#include <array>
#include <cstdint>
#include <optional>
#include <string_view>

namespace video {

  inline constexpr int PACKED_YCOCGR_MAX_ENC_W = 8192;  ///< Default maximum coded width for Layout A1.
  inline constexpr int PACKED_YCOCGR_MAX_ENC_H = 4352;  ///< Default maximum coded height for Layout A1.
  inline constexpr std::string_view PACKED_YCOCGR_MODE_NAME = "ycocgr_p010_a1";  ///< Negotiated sdsChromaMode identifier.

  /**
   * @brief Coded frame geometry for 64px CTU-aligned Layout A1 (`1.5W x 2H`).
   */
  struct packed_ycocgr_layout_t {
    int logical_w {0};  ///< Logical desktop width in pixels.
    int logical_h {0};  ///< Logical desktop height in pixels.
    int tile_w {0};  ///< 64-aligned luma/Co tile width (`align_up(logical_w, 64)`).
    int split_x {0};  ///< Horizontal split point for Cg top/bottom tiles (`(logical_w + 1) / 2`).
    int half_w {0};  ///< 64-aligned Cg tile width (`align_up(split_x, 64)`).
    int tile_h {0};  ///< 64-aligned tile height (`align_up(logical_h, 64)`).
    int enc_w {0};  ///< Total coded frame width (`tile_w + half_w`).
    int enc_h {0};  ///< Total coded frame height (`2 * tile_h`).

    bool operator==(const packed_ycocgr_layout_t &) const = default;
  };

  /**
   * @brief Compute Layout A1 coded dimensions for a logical desktop resolution.
   *
   * @param logical_w Logical desktop width in pixels (`>= 64`).
   * @param logical_h Logical desktop height in pixels (`>= 64`).
   * @param max_enc_w Maximum allowed coded width.
   * @param max_enc_h Maximum allowed coded height.
   * @return Computed layout, or `std::nullopt` when dimensions are invalid or exceed bounds.
   */
  std::optional<packed_ycocgr_layout_t> compute_ycocgr_a1_layout(
    int logical_w,
    int logical_h,
    int max_enc_w = PACKED_YCOCGR_MAX_ENC_W,
    int max_enc_h = PACKED_YCOCGR_MAX_ENC_H
  );

  /**
   * @brief Set the active session packed YCoCg-R mode override (`0` = off, `1` = Layout A1).
   *
   * @param mode Packed mode value (`0` or `1`).
   */
  void set_session_packed_ycocgr_mode(int mode);

  /**
   * @brief Get the active session packed YCoCg-R mode override.
   *
   * @return `0` when disabled, `1` when Layout A1 is active.
   */
  int get_session_packed_ycocgr_mode();

  /**
   * @brief Clear the active session packed YCoCg-R mode override back to `0`.
   */
  void clear_session_packed_ycocgr_mode();

  /**
   * @brief Validate a client packed YCoCg-R request against encoder capabilities and bounds.
   *
   * @param mode Requested `sdsChromaMode` string (empty disables packed mode).
   * @param is_vaapi Whether the active hardware encoder is VAAPI.
   * @param hevc_10bit_supported Whether VAAPI HEVC 10-bit (`DYNAMIC_RANGE`) is supported.
   * @param video_format Negotiated codec (`1` = HEVC).
   * @param dynamic_range Requested dynamic range (`0` = SDR; HDR is rejected).
   * @param logical_w Logical stream width in pixels.
   * @param logical_h Logical stream height in pixels.
   * @param out_mode Receives `0` or `1` when validation succeeds, or `0` on failure.
   * @return `true` when the request is valid; `false` otherwise.
   */
  bool validate_packed_ycocgr_request(
    std::string_view mode,
    bool is_vaapi,
    bool hevc_10bit_supported,
    int video_format,
    int dynamic_range,
    int logical_w,
    int logical_h,
    int &out_mode
  );

  /**
   * @brief Convert 8-bit sRGB channels to 10-bit packed YCoCg-R samples `[Y, Co, Cg]`.
   *
   * @param r Red channel `[0..255]`.
   * @param g Green channel `[0..255]`.
   * @param b Blue channel `[0..255]`.
   * @return Array `{y10, co10, cg10}` with `Y in [0..1020]` and `Co, Cg in [2..1022]`.
   */
  std::array<std::uint16_t, 3> rgb8_to_ycocgr10(std::uint8_t r, std::uint8_t g, std::uint8_t b);

  /**
   * @brief Convert 10-bit packed YCoCg-R samples `[Y, Co, Cg]` back to 8-bit RGB `[R, G, B]`.
   *
   * @param y10 10-bit luma value `[0..1023]`.
   * @param co10 10-bit biased Co value `[0..1023]`.
   * @param cg10 10-bit biased Cg value `[0..1023]`.
   * @return Clamped 8-bit RGB array `{r, g, b}`.
   */
  std::array<std::uint8_t, 3> ycocgr10_to_rgb8(std::uint16_t y10, std::uint16_t co10, std::uint16_t cg10);

  /**
   * @brief Simulate OpenGL `R16` UNORM upload/readback and P010 `[15:6]` extraction for a 10-bit sample.
   *
   * @param val10 10-bit sample value `[0..1023]`.
   * @return Recovered 10-bit sample `(u16 >> 6)`.
   */
  std::uint16_t p010_unorm_roundtrip(std::uint16_t val10);

}  // namespace video
