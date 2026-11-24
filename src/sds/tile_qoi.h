/**
 * @file src/sds/tile_qoi.h
 * @brief Self-contained lossless QOI-RGB24 codec for 1..64 x 1..64 adaptive refinement tiles.
 */
#pragma once

// standard includes
#include <cstddef>
#include <cstdint>
#include <vector>

namespace sds::tile_qoi {
  inline constexpr int TILE_SIZE = 64;  ///< Maximum tile width and height in pixels.
  inline constexpr std::size_t MAX_TILE_PAYLOAD = 24 * 1024;  ///< Hard cap for one encoded tile payload.
  inline constexpr std::size_t HEADER_SIZE = 14;  ///< Standard QOI header length in bytes.
  inline constexpr std::size_t END_MARKER_SIZE = 8;  ///< Standard QOI stream terminator length in bytes.

  /**
   * @brief Encode an RGB24 pixel tile (`1..64 x 1..64`) into a standard QOI-RGB24 byte stream.
   *
   * @param rgb Pointer to top-left RGB24 pixel.
   * @param stride_bytes Row stride in bytes (>= width * 3).
   * @param width Tile width in `[1, 64]`.
   * @param height Tile height in `[1, 64]`.
   * @param out Destination byte vector overwritten with the encoded QOI stream.
   * @return `true` when encoding succeeds within `MAX_TILE_PAYLOAD`.
   */
  bool qoi_encode_rgb24(
    const std::uint8_t *rgb,
    int stride_bytes,
    int width,
    int height,
    std::vector<std::uint8_t> &out
  );

  /**
   * @brief Strictly decode and validate a QOI-RGB24 tile stream against expected dimensions.
   *
   * @param data Encoded QOI stream bytes.
   * @param size Byte count of `data`.
   * @param expected_width Expected tile width in `[1, 64]`.
   * @param expected_height Expected tile height in `[1, 64]`.
   * @param out_rgb Output RGB24 buffer resized to `expected_width * expected_height * 3`.
   * @return `true` when valid, complete, and exact-sized; `false` on any malformed/truncated/oversized input.
   */
  bool qoi_decode_rgb24(
    const std::uint8_t *data,
    std::size_t size,
    int expected_width,
    int expected_height,
    std::vector<std::uint8_t> &out_rgb
  );
}  // namespace sds::tile_qoi
