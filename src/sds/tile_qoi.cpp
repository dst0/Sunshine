/**
 * @file src/sds/tile_qoi.cpp
 * @brief Self-contained lossless QOI-RGB24 encoder and strict bounds-checked decoder.
 */

// standard includes
#include <array>
#include <cstring>

// local includes
#include "tile_qoi.h"

namespace sds::tile_qoi {
  namespace {
    constexpr std::array<std::uint8_t, 4> QOI_MAGIC {'q', 'o', 'i', 'f'};
    constexpr std::array<std::uint8_t, 8> QOI_END_MARKER {0, 0, 0, 0, 0, 0, 0, 1};
    constexpr std::uint8_t QOI_OP_RGB = 0xFE;
    constexpr std::uint8_t QOI_OP_RGBA = 0xFF;
    constexpr std::uint8_t QOI_OP_INDEX = 0x00;
    constexpr std::uint8_t QOI_OP_DIFF = 0x40;
    constexpr std::uint8_t QOI_OP_LUMA = 0x80;
    constexpr std::uint8_t QOI_OP_RUN = 0xC0;
    constexpr std::uint8_t QOI_MASK_2 = 0xC0;

    struct rgba_t {
      std::uint8_t r = 0;
      std::uint8_t g = 0;
      std::uint8_t b = 0;
      std::uint8_t a = 0;

      bool operator==(const rgba_t &other) const = default;
    };

    inline std::size_t color_hash(const rgba_t &px) {
      return (static_cast<std::size_t>(px.r) * 3u +
              static_cast<std::size_t>(px.g) * 5u +
              static_cast<std::size_t>(px.b) * 7u +
              static_cast<std::size_t>(px.a) * 11u) & 63u;
    }

    inline void write_u32_be(std::vector<std::uint8_t> &out, std::uint32_t v) {
      out.push_back(static_cast<std::uint8_t>((v >> 24) & 0xFFu));
      out.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFFu));
      out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFFu));
      out.push_back(static_cast<std::uint8_t>(v & 0xFFu));
    }

    inline std::uint32_t read_u32_be(const std::uint8_t *p) {
      return (static_cast<std::uint32_t>(p[0]) << 24) |
             (static_cast<std::uint32_t>(p[1]) << 16) |
             (static_cast<std::uint32_t>(p[2]) << 8) |
             static_cast<std::uint32_t>(p[3]);
    }
  }  // namespace

  bool qoi_encode_rgb24(
    const std::uint8_t *rgb,
    int stride_bytes,
    int width,
    int height,
    std::vector<std::uint8_t> &out
  ) {
    out.clear();
    if (!rgb || width < 1 || width > TILE_SIZE || height < 1 || height > TILE_SIZE || stride_bytes < width * 3) {
      return false;
    }

    const std::size_t total_pixels = static_cast<std::size_t>(width) * static_cast<std::size_t>(height);
    out.reserve(HEADER_SIZE + total_pixels * 2 + END_MARKER_SIZE);

    out.insert(out.end(), QOI_MAGIC.begin(), QOI_MAGIC.end());
    write_u32_be(out, static_cast<std::uint32_t>(width));
    write_u32_be(out, static_cast<std::uint32_t>(height));
    out.push_back(3);  // RGB24 channels
    out.push_back(0);  // sRGB with linear alpha

    std::array<rgba_t, 64> index {};
    rgba_t prev {0, 0, 0, 255};
    int run = 0;

    for (int y = 0; y < height; ++y) {
      const std::uint8_t *row = rgb + static_cast<std::size_t>(y) * static_cast<std::size_t>(stride_bytes);
      for (int x = 0; x < width; ++x) {
        const std::uint8_t *p = row + static_cast<std::size_t>(x) * 3u;
        const rgba_t px {p[0], p[1], p[2], 255};
        const bool is_last = (y == height - 1) && (x == width - 1);

        if (px == prev) {
          ++run;
          if (run == 62 || is_last) {
            out.push_back(static_cast<std::uint8_t>(QOI_OP_RUN | (run - 1)));
            run = 0;
          }
          continue;
        }

        if (run > 0) {
          out.push_back(static_cast<std::uint8_t>(QOI_OP_RUN | (run - 1)));
          run = 0;
        }

        const std::size_t idx = color_hash(px);
        if (index[idx] == px) {
          out.push_back(static_cast<std::uint8_t>(QOI_OP_INDEX | idx));
        } else {
          index[idx] = px;

          const int dr = static_cast<std::int8_t>(px.r - prev.r);
          const int dg = static_cast<std::int8_t>(px.g - prev.g);
          const int db = static_cast<std::int8_t>(px.b - prev.b);

          if (dr >= -2 && dr <= 1 && dg >= -2 && dg <= 1 && db >= -2 && db <= 1) {
            out.push_back(static_cast<std::uint8_t>(
              QOI_OP_DIFF |
              ((dr + 2) << 4) |
              ((dg + 2) << 2) |
              (db + 2)
            ));
          } else {
            const int dr_dg = static_cast<std::int8_t>(dr - dg);
            const int db_dg = static_cast<std::int8_t>(db - dg);
            if (dg >= -32 && dg <= 31 && dr_dg >= -8 && dr_dg <= 7 && db_dg >= -8 && db_dg <= 7) {
              out.push_back(static_cast<std::uint8_t>(QOI_OP_LUMA | (dg + 32)));
              out.push_back(static_cast<std::uint8_t>(((dr_dg + 8) << 4) | (db_dg + 8)));
            } else {
              out.push_back(QOI_OP_RGB);
              out.push_back(px.r);
              out.push_back(px.g);
              out.push_back(px.b);
            }
          }
        }
        prev = px;
      }
    }

    out.insert(out.end(), QOI_END_MARKER.begin(), QOI_END_MARKER.end());
    if (out.size() > MAX_TILE_PAYLOAD) {
      out.clear();
      return false;
    }
    return true;
  }

  bool qoi_decode_rgb24(
    const std::uint8_t *data,
    std::size_t size,
    int expected_width,
    int expected_height,
    std::vector<std::uint8_t> &out_rgb
  ) {
    out_rgb.clear();
    if (!data ||
        expected_width < 1 ||
        expected_width > TILE_SIZE ||
        expected_height < 1 ||
        expected_height > TILE_SIZE ||
        size < HEADER_SIZE + END_MARKER_SIZE ||
        size > MAX_TILE_PAYLOAD) {
      return false;
    }

    if (std::memcmp(data, QOI_MAGIC.data(), QOI_MAGIC.size()) != 0) {
      return false;
    }
    const std::uint32_t w = read_u32_be(data + 4);
    const std::uint32_t h = read_u32_be(data + 8);
    const std::uint8_t channels = data[12];
    const std::uint8_t colorspace = data[13];
    if (w != static_cast<std::uint32_t>(expected_width) ||
        h != static_cast<std::uint32_t>(expected_height) ||
        channels != 3 ||
        colorspace > 1) {
      return false;
    }

    const std::size_t total_pixels = static_cast<std::size_t>(w) * static_cast<std::size_t>(h);
    const std::size_t expected_bytes = total_pixels * 3u;
    out_rgb.resize(expected_bytes);

    const std::size_t payload_end = size - END_MARKER_SIZE;
    std::size_t pos = HEADER_SIZE;
    std::size_t px_idx = 0;

    std::array<rgba_t, 64> index {};
    rgba_t px {0, 0, 0, 255};

    while (px_idx < total_pixels) {
      if (pos >= payload_end) {
        out_rgb.clear();
        return false;
      }

      const std::uint8_t b1 = data[pos++];
      if (b1 == QOI_OP_RGB) {
        if (pos + 3 > payload_end) {
          out_rgb.clear();
          return false;
        }
        px.r = data[pos++];
        px.g = data[pos++];
        px.b = data[pos++];
        px.a = 255;
      } else if (b1 == QOI_OP_RGBA) {
        out_rgb.clear();
        return false;
      } else if ((b1 & QOI_MASK_2) == QOI_OP_RUN) {
        const std::size_t run = static_cast<std::size_t>(b1 & 0x3Fu) + 1u;
        if (run > total_pixels - px_idx) {
          out_rgb.clear();
          return false;
        }
        for (std::size_t i = 0; i < run; ++i) {
          const std::size_t out_off = px_idx * 3u;
          out_rgb[out_off + 0] = px.r;
          out_rgb[out_off + 1] = px.g;
          out_rgb[out_off + 2] = px.b;
          ++px_idx;
        }
        continue;
      } else if ((b1 & QOI_MASK_2) == QOI_OP_INDEX) {
        px = index[b1 & 0x3Fu];
        px.a = 255;
      } else if ((b1 & QOI_MASK_2) == QOI_OP_DIFF) {
        px.r = static_cast<std::uint8_t>(static_cast<int>(px.r) + static_cast<int>((b1 >> 4) & 0x03u) - 2);
        px.g = static_cast<std::uint8_t>(static_cast<int>(px.g) + static_cast<int>((b1 >> 2) & 0x03u) - 2);
        px.b = static_cast<std::uint8_t>(static_cast<int>(px.b) + static_cast<int>(b1 & 0x03u) - 2);
      } else {
        // QOI_OP_LUMA
        if (pos >= payload_end) {
          out_rgb.clear();
          return false;
        }
        const std::uint8_t b2 = data[pos++];
        const int dg = static_cast<int>(b1 & 0x3Fu) - 32;
        const int dr_dg = static_cast<int>((b2 >> 4) & 0x0Fu) - 8;
        const int db_dg = static_cast<int>(b2 & 0x0Fu) - 8;
        px.r = static_cast<std::uint8_t>(static_cast<int>(px.r) + dg + dr_dg);
        px.g = static_cast<std::uint8_t>(static_cast<int>(px.g) + dg);
        px.b = static_cast<std::uint8_t>(static_cast<int>(px.b) + dg + db_dg);
      }

      index[color_hash(px)] = px;
      const std::size_t out_off = px_idx * 3u;
      out_rgb[out_off + 0] = px.r;
      out_rgb[out_off + 1] = px.g;
      out_rgb[out_off + 2] = px.b;
      ++px_idx;
    }

    if (pos != payload_end || std::memcmp(data + pos, QOI_END_MARKER.data(), END_MARKER_SIZE) != 0) {
      out_rgb.clear();
      return false;
    }

    return true;
  }
}  // namespace sds::tile_qoi
