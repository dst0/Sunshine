/**
 * @file tests/unit/sds/test_tile_refiner.cpp
 * @brief Test src/sds/tile_qoi.* and src/sds/tile_refiner.* (QOI-RGB24, 64x64 tracker,
 *        4:2:0 chroma filter, binary batching, coalescing, and bandwidth caps).
 */

#ifdef SDS_STANDALONE_TEST
  #include <gtest/gtest.h>
#else
  #include "../../tests_common.h"
#endif

// standard includes
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <future>
#include <string>
#include <vector>

// local includes
#include <src/sds/tile_qoi.h>
#include <src/sds/tile_refiner.h>

using namespace std::literals;

namespace {
  struct decoded_tile_t {
    std::uint32_t seq = 0;
    std::uint16_t x = 0;
    std::uint16_t y = 0;
    std::uint16_t w = 0;
    std::uint16_t h = 0;
    std::vector<std::uint8_t> rgb;
  };

  struct decoded_batch_t {
    std::uint16_t flags = 0;
    std::uint16_t frame_w = 0;
    std::uint16_t frame_h = 0;
    std::vector<decoded_tile_t> tiles;
  };

  std::uint16_t read_u16_le(const std::uint8_t *p) {
    return static_cast<std::uint16_t>(p[0]) | (static_cast<std::uint16_t>(p[1]) << 8);
  }

  std::uint32_t read_u32_le(const std::uint8_t *p) {
    return static_cast<std::uint32_t>(p[0]) |
           (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) |
           (static_cast<std::uint32_t>(p[3]) << 24);
  }

  bool parse_batch(const std::string &bin, decoded_batch_t &out) {
    if (bin.size() < sds::tile_wire::HEADER_SIZE || bin.size() > sds::tile_wire::MAX_BATCH_BYTES) {
      return false;
    }
    const auto *p = reinterpret_cast<const std::uint8_t *>(bin.data());
    if (std::memcmp(p, sds::tile_wire::MAGIC.data(), sds::tile_wire::MAGIC.size()) != 0) {
      return false;
    }
    if (read_u16_le(p + 4) != sds::tile_wire::VERSION) {
      return false;
    }
    out.flags = read_u16_le(p + 6);
    out.frame_w = read_u16_le(p + 8);
    out.frame_h = read_u16_le(p + 10);
    const std::uint16_t tile_count = read_u16_le(p + 12);
    if (tile_count > sds::tile_wire::MAX_TILES_PER_BATCH) {
      return false;
    }

    std::size_t off = sds::tile_wire::HEADER_SIZE;
    out.tiles.clear();
    out.tiles.reserve(tile_count);
    for (std::uint16_t i = 0; i < tile_count; ++i) {
      if (off + sds::tile_wire::TILE_HEADER_SIZE > bin.size()) {
        return false;
      }
      decoded_tile_t tile;
      tile.seq = read_u32_le(p + off);
      tile.x = read_u16_le(p + off + 4);
      tile.y = read_u16_le(p + off + 6);
      tile.w = read_u16_le(p + off + 8);
      tile.h = read_u16_le(p + off + 10);
      const std::uint32_t len = read_u32_le(p + off + 12);
      off += sds::tile_wire::TILE_HEADER_SIZE;
      if (tile.w == 0 || tile.w > sds::tile_wire::TILE_SIZE ||
          tile.h == 0 || tile.h > sds::tile_wire::TILE_SIZE ||
          len > sds::tile_wire::MAX_TILE_PAYLOAD ||
          off + len > bin.size()) {
        return false;
      }
      if (!sds::tile_qoi::qoi_decode_rgb24(p + off, len, tile.w, tile.h, tile.rgb)) {
        return false;
      }
      off += len;
      out.tiles.push_back(std::move(tile));
    }
    return off == bin.size();
  }

  void fill_bgra(std::vector<std::uint8_t> &bgra, int width, int height, std::uint8_t r, std::uint8_t g, std::uint8_t b) {
    bgra.resize(static_cast<std::size_t>(width) * static_cast<std::size_t>(height) * 4u);
    for (int i = 0; i < width * height; ++i) {
      bgra[static_cast<std::size_t>(i) * 4u + 0] = b;
      bgra[static_cast<std::size_t>(i) * 4u + 1] = g;
      bgra[static_cast<std::size_t>(i) * 4u + 2] = r;
      bgra[static_cast<std::size_t>(i) * 4u + 3] = 255;
    }
  }

  void set_pixel_bgra(
    std::vector<std::uint8_t> &bgra,
    int width,
    int x,
    int y,
    std::uint8_t r,
    std::uint8_t g,
    std::uint8_t b
  ) {
    const std::size_t idx = (static_cast<std::size_t>(y) * static_cast<std::size_t>(width) + static_cast<std::size_t>(x)) * 4u;
    bgra[idx + 0] = b;
    bgra[idx + 1] = g;
    bgra[idx + 2] = r;
    bgra[idx + 3] = 255;
  }

  void draw_colored_text_glyph(std::vector<std::uint8_t> &bgra, int width, int tile_x, int tile_y) {
    // Thin 1px colored strokes (red + cyan) that suffer severe 4:2:0 subsampling blur
    for (int y = 8; y < 24; ++y) {
      set_pixel_bgra(bgra, width, tile_x + 10, tile_y + y, 255, 24, 24);
      set_pixel_bgra(bgra, width, tile_x + 12, tile_y + y, 16, 240, 255);
    }
    for (int x = 14; x < 34; ++x) {
      set_pixel_bgra(bgra, width, tile_x + x, tile_y + 15, 255, 220, 0);
    }
  }
}  // namespace

TEST(TileQoiTest, RoundTripsSyntheticTextAndGradients) {
  // Exercise 1x1, odd partial edge tile (17x13), and full 64x64 with RUN/INDEX/DIFF/LUMA/RGB ops
  struct case_dim {
    int w;
    int h;
  };
  const std::array<case_dim, 3> dims {{{1, 1}, {17, 13}, {64, 64}}};

  for (const auto &d : dims) {
    std::vector<std::uint8_t> rgb(static_cast<std::size_t>(d.w) * static_cast<std::size_t>(d.h) * 3u);
    for (int y = 0; y < d.h; ++y) {
      for (int x = 0; x < d.w; ++x) {
        const std::size_t i = (static_cast<std::size_t>(y) * static_cast<std::size_t>(d.w) + static_cast<std::size_t>(x)) * 3u;
        if (y < d.h / 2 && (x % 9) != 0) {
          // Triggers RUN and INDEX ops
          rgb[i + 0] = 30;
          rgb[i + 1] = 34;
          rgb[i + 2] = 42;
        } else if (x % 3 == 0) {
          // Small deltas -> DIFF / LUMA
          rgb[i + 0] = static_cast<std::uint8_t>((30 + x) & 0xFF);
          rgb[i + 1] = static_cast<std::uint8_t>((34 + y) & 0xFF);
          rgb[i + 2] = static_cast<std::uint8_t>((42 + x - y) & 0xFF);
        } else {
          // Sharp colored text jumps -> RGB op + INDEX
          rgb[i + 0] = static_cast<std::uint8_t>((x * 73 + y * 19) & 0xFF);
          rgb[i + 1] = static_cast<std::uint8_t>((x * 41 + y * 97) & 0xFF);
          rgb[i + 2] = static_cast<std::uint8_t>((x * 13 + y * 53) & 0xFF);
        }
      }
    }

    std::vector<std::uint8_t> encoded;
    ASSERT_TRUE(sds::tile_qoi::qoi_encode_rgb24(rgb.data(), d.w * 3, d.w, d.h, encoded));
    EXPECT_LE(encoded.size(), sds::tile_qoi::MAX_TILE_PAYLOAD);

    std::vector<std::uint8_t> decoded;
    ASSERT_TRUE(sds::tile_qoi::qoi_decode_rgb24(encoded.data(), encoded.size(), d.w, d.h, decoded));
    EXPECT_EQ(decoded, rgb);
  }
}

TEST(TileQoiTest, RejectsMalformedTruncatedOversizedAndRgbaStreams) {
  std::vector<std::uint8_t> rgb(64 * 64 * 3, 0);
  rgb[0] = 255;
  rgb[1] = 10;
  rgb[2] = 20;

  std::vector<std::uint8_t> encoded;
  ASSERT_TRUE(sds::tile_qoi::qoi_encode_rgb24(rgb.data(), 64 * 3, 64, 64, encoded));

  std::vector<std::uint8_t> out;
  EXPECT_FALSE(sds::tile_qoi::qoi_decode_rgb24(encoded.data(), encoded.size() - 1, 64, 64, out));
  EXPECT_FALSE(sds::tile_qoi::qoi_decode_rgb24(encoded.data(), encoded.size(), 63, 64, out));
  EXPECT_FALSE(sds::tile_qoi::qoi_decode_rgb24(encoded.data(), encoded.size(), 65, 64, out));
  EXPECT_FALSE(sds::tile_qoi::qoi_decode_rgb24(encoded.data(), encoded.size(), 0, 64, out));

  // Corrupt magic
  {
    auto bad = encoded;
    bad[0] = 'X';
    EXPECT_FALSE(sds::tile_qoi::qoi_decode_rgb24(bad.data(), bad.size(), 64, 64, out));
  }
  // Reject channels == 4
  {
    auto bad = encoded;
    bad[12] = 4;
    EXPECT_FALSE(sds::tile_qoi::qoi_decode_rgb24(bad.data(), bad.size(), 64, 64, out));
  }
  // Reject colorspace > 1
  {
    auto bad = encoded;
    bad[13] = 2;
    EXPECT_FALSE(sds::tile_qoi::qoi_decode_rgb24(bad.data(), bad.size(), 64, 64, out));
  }
  // Corrupt end marker
  {
    auto bad = encoded;
    bad.back() = 0x02;
    EXPECT_FALSE(sds::tile_qoi::qoi_decode_rgb24(bad.data(), bad.size(), 64, 64, out));
  }
  // Extra trailing byte after end marker
  {
    auto bad = encoded;
    bad.push_back(0x00);
    EXPECT_FALSE(sds::tile_qoi::qoi_decode_rgb24(bad.data(), bad.size(), 64, 64, out));
  }
  // Explicit QOI_OP_RGBA (0xFF) stream on 1x1 must be rejected
  {
    std::vector<std::uint8_t> rgba_qoi {
      'q', 'o', 'i', 'f',
      0, 0, 0, 1,
      0, 0, 0, 1,
      3, 0,
      0xFF, 10, 20, 30, 255,
      0, 0, 0, 0, 0, 0, 0, 1
    };
    EXPECT_FALSE(sds::tile_qoi::qoi_decode_rgb24(rgba_qoi.data(), rgba_qoi.size(), 1, 1, out));
  }
  // Oversized payload (> MAX_TILE_PAYLOAD) rejected by decoder
  {
    std::vector<std::uint8_t> oversized(sds::tile_qoi::MAX_TILE_PAYLOAD + 1, 0);
    EXPECT_FALSE(sds::tile_qoi::qoi_decode_rgb24(oversized.data(), oversized.size(), 64, 64, out));
  }
}

TEST(TileRefinerTest, RequiresTwoSettledFramesAndSkipsMotion) {
  sds::tile_refiner_t refiner(false);
  const auto t0 = sds::tile_refiner_t::clock::now();
  std::vector<std::uint8_t> frame;
  fill_bgra(frame, 128, 128, 28, 30, 34);
  draw_colored_text_glyph(frame, 128, 0, 0);

  // Frame 0: initial observation (res change emits reset_all with 0 tiles)
  refiner.process_frame_at(frame.data(), 128 * 4, 128, 128, t0);
  {
    int status = 0;
    std::string body;
    EXPECT_FALSE(refiner.poll_at("c1", std::nullopt, t0, [&](int s, std::string b) {
      status = s;
      body = std::move(b);
    }));
    EXPECT_EQ(status, 200);
    decoded_batch_t batch;
    ASSERT_TRUE(parse_batch(body, batch));
    EXPECT_EQ(batch.flags & sds::tile_wire::FLAG_RESET_ALL, sds::tile_wire::FLAG_RESET_ALL);
    EXPECT_TRUE(batch.tiles.empty());
  }

  // Frame 1 (settled_frames == 1): still must NOT emit tile
  refiner.process_frame_at(frame.data(), 128 * 4, 128, 128, t0 + 16ms);
  EXPECT_EQ(refiner.ready_queue_size(), 0u);

  // Motion on frame 2 resets settled counter back to 0
  set_pixel_bgra(frame, 128, 3, 3, 0, 255, 128);
  refiner.process_frame_at(frame.data(), 128 * 4, 128, 128, t0 + 32ms);
  EXPECT_EQ(refiner.ready_queue_size(), 0u);

  // Repeat identical frames twice -> settles cleanly at settled_frames == 2
  refiner.process_frame_at(frame.data(), 128 * 4, 128, 128, t0 + 48ms);
  EXPECT_EQ(refiner.ready_queue_size(), 0u);
  refiner.process_frame_at(frame.data(), 128 * 4, 128, 128, t0 + 64ms);
  EXPECT_EQ(refiner.ready_queue_size(), 1u);

  int status = 0;
  std::string body;
  refiner.poll_at("c1", std::nullopt, t0 + 64ms, [&](int s, std::string b) {
    status = s;
    body = std::move(b);
  });
  ASSERT_EQ(status, 200);
  decoded_batch_t batch;
  ASSERT_TRUE(parse_batch(body, batch));
  ASSERT_EQ(batch.tiles.size(), 1u);
  EXPECT_EQ(batch.tiles[0].x, 0);
  EXPECT_EQ(batch.tiles[0].y, 0);
  EXPECT_EQ(batch.tiles[0].w, 64);
  EXPECT_EQ(batch.tiles[0].h, 64);

  // Further identical frames must not re-emit already refined tile
  refiner.process_frame_at(frame.data(), 128 * 4, 128, 128, t0 + 80ms);
  EXPECT_EQ(refiner.ready_queue_size(), 0u);
}

TEST(TileRefinerTest, SkipsFlatAndLowChromaErrorTilesAndEmits1PxColoredText) {
  sds::tile_refiner_t refiner(false);
  const auto t0 = sds::tile_refiner_t::clock::now();
  std::vector<std::uint8_t> frame;
  fill_bgra(frame, 192, 64, 40, 42, 46);

  // Tile (0,0): solid flat fill -> skipped
  // Tile (64,0): sharp pure white/black monochrome stripes (zero chroma error) -> skipped
  for (int y = 0; y < 64; ++y) {
    for (int x = 0; x < 64; ++x) {
      const std::uint8_t luma = ((x + y) % 2 == 0) ? 245 : 15;
      set_pixel_bgra(frame, 192, 64 + x, y, luma, luma, luma);
    }
  }
  // Tile (128,0): single 1px saturated red glyph stroke on dark background -> MUST emit!
  for (int x = 10; x < 30; ++x) {
    set_pixel_bgra(frame, 192, 128 + x, 20, 255, 20, 20);
  }

  for (int i = 0; i < 3; ++i) {
    refiner.process_frame_at(frame.data(), 192 * 4, 192, 64, t0 + i * 16ms);
  }

  int status = 0;
  std::string body;
  refiner.poll_at("c1", std::nullopt, t0 + 48ms, [&](int s, std::string b) {
    status = s;
    body = std::move(b);
  });
  ASSERT_EQ(status, 200);
  decoded_batch_t batch;
  ASSERT_TRUE(parse_batch(body, batch));
  ASSERT_EQ(batch.tiles.size(), 1u);
  EXPECT_EQ(batch.tiles[0].x, 128);
  EXPECT_EQ(batch.tiles[0].y, 0);
}

TEST(TileRefinerTest, ResetsGridAndEmitsResetAllOnResolutionChange) {
  sds::tile_refiner_t refiner(false);
  const auto t0 = sds::tile_refiner_t::clock::now();

  std::vector<std::uint8_t> f1;
  fill_bgra(f1, 128, 128, 20, 20, 20);
  draw_colored_text_glyph(f1, 128, 0, 0);
  for (int i = 0; i < 3; ++i) {
    refiner.process_frame_at(f1.data(), 128 * 4, 128, 128, t0 + i * 16ms);
  }
  EXPECT_EQ(refiner.ready_queue_size(), 1u);

  // Switch resolution before client drains ready queue -> old tile cleared, reset_all emitted for new dims
  std::vector<std::uint8_t> f2;
  fill_bgra(f2, 192, 128, 25, 25, 25);
  refiner.process_frame_at(f2.data(), 192 * 4, 192, 128, t0 + 64ms);
  EXPECT_EQ(refiner.ready_queue_size(), 0u);

  int status = 0;
  std::string body;
  refiner.poll_at("c1", std::nullopt, t0 + 64ms, [&](int s, std::string b) {
    status = s;
    body = std::move(b);
  });
  ASSERT_EQ(status, 200);
  decoded_batch_t batch;
  ASSERT_TRUE(parse_batch(body, batch));
  EXPECT_EQ(batch.flags & sds::tile_wire::FLAG_RESET_ALL, sds::tile_wire::FLAG_RESET_ALL);
  EXPECT_EQ(batch.frame_w, 192);
  EXPECT_EQ(batch.frame_h, 128);
  EXPECT_TRUE(batch.tiles.empty());
}

TEST(TileRefinerTest, CoalescesAndCapsReadyQueueAt256) {
  sds::tile_refiner_t refiner(false);
  const auto t0 = sds::tile_refiner_t::clock::now();

  // 20 x 16 = 320 tiles (> MAX_READY_QUEUE 256)
  constexpr int w = 1280;
  constexpr int h = 1024;
  std::vector<std::uint8_t> frame;
  fill_bgra(frame, w, h, 24, 24, 28);
  for (int ty = 0; ty < 16; ++ty) {
    for (int tx = 0; tx < 20; ++tx) {
      draw_colored_text_glyph(frame, w, tx * 64, ty * 64);
    }
  }
  for (int i = 0; i < 3; ++i) {
    refiner.process_frame_at(frame.data(), w * 4, w, h, t0 + i * 16ms);
  }
  EXPECT_EQ(refiner.ready_queue_size(), sds::tile_wire::MAX_READY_QUEUE);

  // Repeated motion/re-settle cycles without polling must erase stale order entries rather than evicting unrelated live tiles
  for (int cycle = 0; cycle < 400; ++cycle) {
    set_pixel_bgra(frame, w, 0, 0, static_cast<std::uint8_t>((cycle * 13 + 1) & 0xFF), 240, 20);
    for (int f = 0; f < 3; ++f) {
      refiner.process_frame_at(frame.data(), w * 4, w, h, t0 + (3 + cycle * 3 + f) * 16ms);
    }
  }
  EXPECT_EQ(refiner.ready_queue_size(), sds::tile_wire::MAX_READY_QUEUE);
}

TEST(TileRefinerTest, EnforcesBatchCapsAndBandwidthTokenBucket) {
  sds::tile_refiner_t refiner(false);
  const auto t0 = sds::tile_refiner_t::clock::now();

  // 16 x 8 = 128 tiles (> MAX_TILES_PER_BATCH 64), dense colored pixels so total > 256 KiB burst
  constexpr int w = 1024;
  constexpr int h = 512;
  std::vector<std::uint8_t> frame;
  fill_bgra(frame, w, h, 16, 16, 20);
  for (int y = 0; y < h; ++y) {
    for (int x = 0; x < w; ++x) {
      if ((x + y) % 2 == 0) {
        set_pixel_bgra(frame, w, x, y, static_cast<std::uint8_t>((x * 31 + 17) & 0xFF), static_cast<std::uint8_t>((y * 47 + 5) & 0xFF), static_cast<std::uint8_t>(((x ^ y) * 19) & 0xFF));
      } else {
        set_pixel_bgra(frame, w, x, y, 255, 20, 40);
      }
    }
  }
  for (int i = 0; i < 3; ++i) {
    refiner.process_frame_at(frame.data(), w * 4, w, h, t0 + i * 16ms);
  }
  EXPECT_GT(refiner.ready_queue_size(), sds::tile_wire::MAX_TILES_PER_BATCH);

  // First batch drains burst up to <= 64 tiles and <= 256 KiB
  int status = 0;
  std::string body1;
  refiner.poll_at("c1", std::nullopt, t0 + 32ms, [&](int s, std::string b) {
    status = s;
    body1 = std::move(b);
  });
  ASSERT_EQ(status, 200);
  EXPECT_LE(body1.size(), sds::tile_wire::MAX_BATCH_BYTES);
  decoded_batch_t b1;
  ASSERT_TRUE(parse_batch(body1, b1));
  EXPECT_GT(b1.tiles.size(), 0u);
  EXPECT_LE(b1.tiles.size(), sds::tile_wire::MAX_TILES_PER_BATCH);

  // Keep draining any remaining burst tokens at t0 + 32ms until token bucket stops immediate batch
  std::size_t drained_bytes = body1.size();
  for (int iter = 0; iter < 16; ++iter) {
    int st = 0;
    std::string bx;
    refiner.poll_at("c1", std::nullopt, t0 + 32ms, [&](int s, std::string b) {
      st = s;
      bx = std::move(b);
    });
    if (st == 204) {
      break;
    }
    ASSERT_EQ(st, 200);
    EXPECT_LE(bx.size(), sds::tile_wire::MAX_BATCH_BYTES);
    drained_bytes += bx.size();
  }
  EXPECT_LE(drained_bytes, sds::tile_wire::BANDWIDTH_BURST_BYTES + 64u);

  // At t0 + 282ms (+250ms refill => ~1 MiB tokens), queue makes progress again
  int status_refilled = 0;
  std::string body_refilled;
  refiner.poll_at("c1", std::nullopt, t0 + 282ms, [&](int s, std::string b) {
    status_refilled = s;
    body_refilled = std::move(b);
  });
  ASSERT_EQ(status_refilled, 200);
  decoded_batch_t b2;
  ASSERT_TRUE(parse_batch(body_refilled, b2));
  EXPECT_GT(b2.tiles.size(), 0u);
}

TEST(TileRefinerTest, WorkerWakesParkedPollAndHandlesLifecycleResponses) {
  sds::tile_refiner_t refiner(true);
  refiner.set_active(true);

  std::promise<std::pair<int, std::string>> poll_promise;
  auto poll_future = poll_promise.get_future();
  const auto now = sds::tile_refiner_t::clock::now();

  ASSERT_TRUE(refiner.poll_at("client-a", now + 5s, now, [&](int s, std::string b) {
    poll_promise.set_value({s, std::move(b)});
  }));
  EXPECT_EQ(refiner.parked_poll_count(), 1u);

  std::vector<std::uint8_t> frame;
  fill_bgra(frame, 128, 128, 30, 30, 34);
  draw_colored_text_glyph(frame, 128, 64, 64);

  // First submission emits initial reset_all batch immediately to the parked poll
  refiner.submit_bgra_frame(frame.data(), 128 * 4, 128, 128);
  ASSERT_EQ(poll_future.wait_for(2s), std::future_status::ready);
  const auto [s0, b0] = poll_future.get();
  EXPECT_EQ(s0, 200);
  decoded_batch_t reset_batch;
  ASSERT_TRUE(parse_batch(b0, reset_batch));
  EXPECT_EQ(reset_batch.flags & sds::tile_wire::FLAG_RESET_ALL, sds::tile_wire::FLAG_RESET_ALL);

  // Park second poll before settled frames emit the text tile
  std::promise<std::pair<int, std::string>> tile_promise;
  auto tile_future = tile_promise.get_future();
  ASSERT_TRUE(refiner.poll_at("client-a", now + 5s, now + 10ms, [&](int s, std::string b) {
    tile_promise.set_value({s, std::move(b)});
  }));

  refiner.drain_for_test();
  refiner.submit_bgra_frame(frame.data(), 128 * 4, 128, 128);
  refiner.drain_for_test();
  refiner.submit_bgra_frame(frame.data(), 128 * 4, 128, 128);
  refiner.drain_for_test();

  ASSERT_EQ(tile_future.wait_for(2s), std::future_status::ready);
  const auto [s1, b1] = tile_future.get();
  EXPECT_EQ(s1, 200);
  decoded_batch_t tile_batch;
  ASSERT_TRUE(parse_batch(b1, tile_batch));
  ASSERT_EQ(tile_batch.tiles.size(), 1u);
  EXPECT_EQ(tile_batch.tiles[0].x, 64);
  EXPECT_EQ(tile_batch.tiles[0].y, 64);

  // end_stream -> 409, expire -> 204, shutdown -> 503
  int status_409 = 0;
  ASSERT_TRUE(refiner.poll_at("client-409", now + 5s, now, [&](int s, std::string) { status_409 = s; }));
  refiner.end_stream("client-409");
  EXPECT_EQ(status_409, 409);

  int status_204 = 0;
  ASSERT_TRUE(refiner.poll_at("client-204", now + 1s, now, [&](int s, std::string) { status_204 = s; }));
  refiner.expire(now + 2s);
  EXPECT_EQ(status_204, 204);

  int status_503 = 0;
  ASSERT_TRUE(refiner.poll_at("client-503", now + 5s, now, [&](int s, std::string) { status_503 = s; }));
  refiner.shutdown();
  EXPECT_EQ(status_503, 503);
}
