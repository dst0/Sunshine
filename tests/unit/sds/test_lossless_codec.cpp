/**
 * @file tests/unit/sds/test_lossless_codec.cpp
 * @brief Unit tests for SDLL v1 lossless codec and canonical RGB24 CRC32C / BLAKE3 hashing.
 */

#ifdef SDS_STANDALONE_TEST
  #include <gtest/gtest.h>
#else
  #include "../../tests_common.h"
#endif

#include <src/sds/lossless_codec.h>
#include <src/sds/lossless_hash.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <vector>

namespace {
  std::vector<std::uint8_t> make_pattern_bgra(int w, int h, int seed) {
    std::vector<std::uint8_t> buf(static_cast<std::size_t>(w) * static_cast<std::size_t>(h) * 4u);
    std::uint32_t rng = static_cast<std::uint32_t>(seed * 2654435761u + 17u);
    for (int y = 0; y < h; ++y) {
      for (int x = 0; x < w; ++x) {
        const std::size_t idx = (static_cast<std::size_t>(y) * w + x) * 4u;
        if ((x / 32 + y / 32) % 3 == 0) {
          buf[idx + 0] = 40;
          buf[idx + 1] = 80;
          buf[idx + 2] = 120;
        } else if ((x / 32) % 2 == 0) {
          const bool fg = ((x + y) % 4) == 0;
          buf[idx + 0] = fg ? 240 : 12;
          buf[idx + 1] = fg ? 240 : 14;
          buf[idx + 2] = fg ? 240 : 18;
        } else {
          rng = rng * 1664525u + 1013904223u;
          buf[idx + 0] = static_cast<std::uint8_t>(rng >> 24);
          buf[idx + 1] = static_cast<uint8_t>(rng >> 16);
          buf[idx + 2] = static_cast<uint8_t>(rng >> 8);
        }
        buf[idx + 3] = static_cast<std::uint8_t>((x ^ y ^ seed) & 0xFF);
      }
    }
    return buf;
  }
}  // namespace

TEST(LosslessHash, Crc32cStandardAndCombine) {
  const char *s = "123456789";
  EXPECT_EQ(sds::lossless::crc32c_update(0, reinterpret_cast<const std::uint8_t *>(s), 9), 0xE3069283u);

  const int w = 1920;
  const int h = 1080;
  const auto bgra = make_pattern_bgra(w, h, 7);
  const std::uint32_t full = sds::lossless::crc32c_rgb24_from_bgra(bgra.data(), w * 4, w, h);
  std::uint32_t comb = sds::lossless::crc32c_rgb24_from_bgra_row(bgra.data(), w);
  for (int y = 1; y < h; ++y) {
    const auto row = sds::lossless::crc32c_rgb24_from_bgra_row(bgra.data() + static_cast<std::size_t>(y) * w * 4u, w);
    comb = sds::lossless::crc32c_combine(comb, row, static_cast<std::uint64_t>(w) * 3ULL);
  }
  EXPECT_EQ(comb, full);
}

TEST(LosslessHash, Blake3OfficialVectors) {
  const auto empty = sds::lossless::blake3_hash(nullptr, 0);
  const std::array<std::uint8_t, 32> expected_empty {
    0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6,
    0xa0, 0x40, 0x4d, 0xea, 0x36, 0xdc, 0xc9, 0x49,
    0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7,
    0xcc, 0x9a, 0x93, 0xca, 0xe4, 0x1f, 0x32, 0x62,
  };
  EXPECT_EQ(empty, expected_empty);

  const std::uint8_t abc[3] {'a', 'b', 'c'};
  const auto h_abc = sds::lossless::blake3_hash(abc, 3);
  const std::array<std::uint8_t, 32> expected_abc {
    0x64, 0x37, 0xb3, 0xac, 0x38, 0x46, 0x51, 0x33,
    0xff, 0xb6, 0x3b, 0x75, 0x27, 0x3a, 0x8d, 0xb5,
    0x48, 0xc5, 0x58, 0x46, 0x5d, 0x79, 0xdb, 0x03,
    0xfd, 0x35, 0x9c, 0x6c, 0xd5, 0xbd, 0x9d, 0x85,
  };
  EXPECT_EQ(h_abc, expected_abc);
}

TEST(LosslessCodec, MultiFrameScrollAndOddDimsRoundtrip) {
  const int w = 1366;
  const int h = 768;
  auto f1 = make_pattern_bgra(w, h, 1);
  auto f2 = f1;
  // Scroll up by 40 rows
  for (int y = 0; y < h - 40; ++y) {
    std::memcpy(f2.data() + static_cast<std::size_t>(y) * w * 4u,
                f1.data() + static_cast<std::size_t>(y + 40) * w * 4u,
                static_cast<std::size_t>(w) * 4u);
  }

  sds::lossless::cpu_encoder_t enc(2);
  sds::lossless::cpu_decoder_t dec(2);
  std::vector<std::uint8_t> pkt;
  sds::lossless::encode_stats_t estats;
  sds::lossless::decode_stats_t dstats;

  ASSERT_TRUE(enc.encode_frame(f1.data(), w * 4, w, h, 1, 1000, sds::lossless::hash_algo_e::crc32c, true, pkt, &estats));
  ASSERT_TRUE(dec.decode_frame(pkt.data(), pkt.size(), true, nullptr, &dstats));
  EXPECT_TRUE(dstats.hash_matched);

  ASSERT_TRUE(enc.encode_frame(f2.data(), w * 4, w, h, 2, 2000, sds::lossless::hash_algo_e::blake3, false, pkt, &estats));
  EXPECT_GE(estats.copy_rects, 1u);
  ASSERT_TRUE(dec.decode_frame(pkt.data(), pkt.size(), true, nullptr, &dstats));
  EXPECT_TRUE(dstats.hash_matched);
}
