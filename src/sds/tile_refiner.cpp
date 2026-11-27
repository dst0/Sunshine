/**
 * @file src/sds/tile_refiner.cpp
 * @brief Non-blocking 64x64 dirty-tile tracker, chroma-error filter, and `/sds/v1/tile-refinement` batcher.
 */

// standard includes
#include <algorithm>
#include <cmath>
#include <cstring>
#include <utility>

// local includes
#include "tile_refiner.h"

namespace sds {
  namespace {
    inline std::uint32_t tile_key(int tx, int ty) {
      return (static_cast<std::uint32_t>(static_cast<std::uint16_t>(ty)) << 16) |
             static_cast<std::uint32_t>(static_cast<std::uint16_t>(tx));
    }

    inline void append_u16_le(std::string &out, std::uint16_t v) {
      out.push_back(static_cast<char>(v & 0xFFu));
      out.push_back(static_cast<char>((v >> 8) & 0xFFu));
    }

    inline void append_u32_le(std::string &out, std::uint32_t v) {
      out.push_back(static_cast<char>(v & 0xFFu));
      out.push_back(static_cast<char>((v >> 8) & 0xFFu));
      out.push_back(static_cast<char>((v >> 16) & 0xFFu));
      out.push_back(static_cast<char>((v >> 24) & 0xFFu));
    }

    inline std::uint64_t hash_tile_bgr(
      const std::uint8_t *bgra,
      int stride,
      int tile_x,
      int tile_y,
      int tile_w,
      int tile_h
    ) {
      std::uint64_t h = 14695981039346656037ULL;
      for (int y = 0; y < tile_h; ++y) {
        const std::uint8_t *row = bgra +
                                  static_cast<std::size_t>(tile_y + y) * static_cast<std::size_t>(stride) +
                                  static_cast<std::size_t>(tile_x) * 4u;
        for (int x = 0; x < tile_w; ++x) {
          const std::uint8_t *p = row + static_cast<std::size_t>(x) * 4u;
          const std::uint64_t rgb = static_cast<std::uint64_t>(p[0]) |
                                    (static_cast<std::uint64_t>(p[1]) << 8) |
                                    (static_cast<std::uint64_t>(p[2]) << 16);
          h ^= rgb;
          h *= 1099511628211ULL;
        }
      }
      // Final avalanche so small single-pixel changes spread across all 64 bits
      h ^= h >> 33;
      h *= 0xff51afd7ed558ccdULL;
      h ^= h >> 33;
      h *= 0xc4ceb9fe1a85ec53ULL;
      h ^= h >> 33;
      return h;
    }

    inline int round_shift_14(std::int64_t val) {
      if (val >= 0) {
        return static_cast<int>((val + 8192) >> 14);
      }
      return -static_cast<int>((-val + 8192) >> 14);
    }

    inline int clamp_u8(int v) {
      return std::clamp(v, 0, 255);
    }
  }  // namespace

  tile_refiner_t::tile_refiner_t(bool start_worker, schedule_wake_t schedule_wake):
      schedule_wake_(std::move(schedule_wake)) {
    if (start_worker) {
      worker_ = std::thread([this]() {
        worker_loop();
      });
    }
  }

  tile_refiner_t::~tile_refiner_t() {
    shutdown();
  }

  void tile_refiner_t::set_active(bool active) {
    const bool was_active = active_.exchange(active, std::memory_order_acq_rel);
    if (was_active && !active) {
      {
        std::lock_guard slot_lock {slot_mutex_};
        has_pending_ = false;
      }
      std::lock_guard lock {state_mutex_};
      reset_grid_locked();
    }
  }

  void tile_refiner_t::submit_bgra_frame(
    const std::uint8_t *bgra,
    int stride,
    int width,
    int height,
    std::optional<cursor_rect_t> cursor_rect
  ) {
    if (!active_.load(std::memory_order_acquire)) {
      return;
    }
    if (!bgra || width <= 0 || height <= 0 || width > 16384 || height > 16384) {
      return;
    }
    const std::size_t row_bytes = static_cast<std::size_t>(width) * 4u;
    if (stride < static_cast<int>(row_bytes)) {
      return;
    }

    std::unique_lock slot_lock {slot_mutex_, std::try_to_lock};
    if (!slot_lock.owns_lock() || stopping_) {
      return;
    }

    const std::size_t total_bytes = row_bytes * static_cast<std::size_t>(height);
    pending_frame_.resize(total_bytes);
    if (static_cast<std::size_t>(stride) == row_bytes) {
      std::memcpy(pending_frame_.data(), bgra, total_bytes);
    } else {
      for (int y = 0; y < height; ++y) {
        std::memcpy(
          pending_frame_.data() + static_cast<std::size_t>(y) * row_bytes,
          bgra + static_cast<std::size_t>(y) * static_cast<std::size_t>(stride),
          row_bytes
        );
      }
    }

    pending_w_ = width;
    pending_h_ = height;
    pending_stride_ = static_cast<int>(row_bytes);
    pending_cursor_rect_ = cursor_rect;
    has_pending_ = true;
    slot_lock.unlock();
    slot_cv_.notify_one();
  }

  void tile_refiner_t::worker_loop() {
    while (true) {
      int w = 0;
      int h = 0;
      int stride = 0;
      std::optional<cursor_rect_t> cursor_rect;
      {
        std::unique_lock lock {slot_mutex_};
        slot_cv_.wait(lock, [this]() {
          return stopping_ || has_pending_;
        });
        if (stopping_) {
          return;
        }
        work_frame_.swap(pending_frame_);
        w = pending_w_;
        h = pending_h_;
        stride = pending_stride_;
        cursor_rect = pending_cursor_rect_;
        has_pending_ = false;
        processing_ = true;
      }

      if (active_.load(std::memory_order_acquire)) {
        process_frame_at(work_frame_.data(), stride, w, h, clock::now(), cursor_rect);
      }

      {
        std::lock_guard lock {slot_mutex_};
        processing_ = false;
      }
      slot_cv_.notify_all();
    }
  }

  bool tile_refiner_t::has_high_chroma_error_bgra(
    const std::uint8_t *bgra,
    int stride,
    int tile_x,
    int tile_y,
    int tile_w,
    int tile_h
  ) {
    if (!bgra || tile_w <= 0 || tile_h <= 0 || stride < (tile_x + tile_w) * 4) {
      return false;
    }

    for (int y0 = 0; y0 < tile_h; y0 += 2) {
      const int y1 = std::min(y0 + 1, tile_h - 1);
      const std::uint8_t *row0 = bgra + static_cast<std::size_t>(tile_y + y0) * static_cast<std::size_t>(stride);
      const std::uint8_t *row1 = bgra + static_cast<std::size_t>(tile_y + y1) * static_cast<std::size_t>(stride);

      for (int x0 = 0; x0 < tile_w; x0 += 2) {
        const int x1 = std::min(x0 + 1, tile_w - 1);
        const std::array<const std::uint8_t *, 4> pts {
          row0 + static_cast<std::size_t>(tile_x + x0) * 4u,
          row0 + static_cast<std::size_t>(tile_x + x1) * 4u,
          row1 + static_cast<std::size_t>(tile_x + x0) * 4u,
          row1 + static_cast<std::size_t>(tile_x + x1) * 4u,
        };

        std::array<int, 4> orig_r {};
        std::array<int, 4> orig_g {};
        std::array<int, 4> orig_b {};
        std::array<int, 4> ys {};
        std::int64_t cb_sum = 0;
        std::int64_t cr_sum = 0;

        for (int k = 0; k < 4; ++k) {
          const int b = pts[k][0];
          const int g = pts[k][1];
          const int r = pts[k][2];
          orig_r[k] = r;
          orig_g[k] = g;
          orig_b[k] = b;

          // Full-range BT.601 in Q14 fixed point
          ys[k] = clamp_u8(round_shift_14(4899LL * r + 9617LL * g + 1868LL * b));
          cb_sum += -2764LL * r - 5428LL * g + 8192LL * b;
          cr_sum += 8192LL * r - 6860LL * g - 1332LL * b;
        }

        const int cb_avg = round_shift_14(cb_sum / 4);
        const int cr_avg = round_shift_14(cr_sum / 4);

        const int dr_chroma = round_shift_14(22970LL * cr_avg);
        const int dg_chroma = round_shift_14(-5638LL * cb_avg - 11700LL * cr_avg);
        const int db_chroma = round_shift_14(29032LL * cb_avg);

        for (int k = 0; k < 4; ++k) {
          const int rec_r = clamp_u8(ys[k] + dr_chroma);
          const int rec_g = clamp_u8(ys[k] + dg_chroma);
          const int rec_b = clamp_u8(ys[k] + db_chroma);

          if (std::abs(orig_r[k] - rec_r) >= tile_wire::CHROMA_ERROR_THRESHOLD ||
              std::abs(orig_g[k] - rec_g) >= tile_wire::CHROMA_ERROR_THRESHOLD ||
              std::abs(orig_b[k] - rec_b) >= tile_wire::CHROMA_ERROR_THRESHOLD) {
            return true;
          }
        }
      }
    }

    return false;
  }

  void tile_refiner_t::reset_grid_locked() {
    grid_w_ = 0;
    grid_h_ = 0;
    tiles_x_ = 0;
    tiles_y_ = 0;
    pending_reset_all_ = false;
    tiles_.clear();
    ready_order_.clear();
    ready_tiles_.clear();
    invalidation_order_.clear();
    pending_invalidations_.clear();
    bw_tokens_ = static_cast<double>(tile_wire::BANDWIDTH_BURST_BYTES);
    bw_initialized_ = false;
  }

  void tile_refiner_t::erase_queued_tile_locked(std::uint32_t key) {
    if (auto it = ready_tiles_.find(key); it != ready_tiles_.end()) {
      ready_order_.erase(it->second.order_it);
      ready_tiles_.erase(it);
    }
  }

  void tile_refiner_t::enqueue_invalidation_locked(int tx, int ty) {
    const std::uint32_t key = tile_key(tx, ty);
    if (pending_invalidations_.contains(key)) {
      return;
    }
    invalidation_order_.push_back(key);
    pending_invalidations_.emplace(key, std::prev(invalidation_order_.end()));
  }

  void tile_refiner_t::erase_invalidation_locked(std::uint32_t key) {
    if (auto it = pending_invalidations_.find(key); it != pending_invalidations_.end()) {
      invalidation_order_.erase(it->second);
      pending_invalidations_.erase(it);
    }
  }

  void tile_refiner_t::collapse_invalidations_to_reset_locked() {
    invalidation_order_.clear();
    pending_invalidations_.clear();
    pending_reset_all_ = true;
    for (auto &t : tiles_) {
      if (t.client_active) {
        t.client_active = false;
        t.refined_sent = false;
      }
    }
  }

  void tile_refiner_t::enqueue_tile_locked(int tx, int ty, int tile_w, int tile_h, std::vector<std::uint8_t> &&payload) {
    const std::uint32_t key = tile_key(tx, ty);
    if (auto it = ready_tiles_.find(key); it != ready_tiles_.end()) {
      it->second.seq = ++seq_counter_;
      it->second.w = static_cast<std::uint16_t>(tile_w);
      it->second.h = static_cast<std::uint16_t>(tile_h);
      it->second.payload = std::move(payload);
      return;
    }

    if (ready_tiles_.size() >= tile_wire::MAX_READY_QUEUE) {
      return;
    }

    queued_tile_t entry;
    entry.seq = ++seq_counter_;
    entry.x = static_cast<std::uint16_t>(tx * tile_wire::TILE_SIZE);
    entry.y = static_cast<std::uint16_t>(ty * tile_wire::TILE_SIZE);
    entry.w = static_cast<std::uint16_t>(tile_w);
    entry.h = static_cast<std::uint16_t>(tile_h);
    entry.payload = std::move(payload);

    ready_order_.push_back(key);
    entry.order_it = std::prev(ready_order_.end());
    ready_tiles_.emplace(key, std::move(entry));
  }

  void tile_refiner_t::process_frame_at(
    const std::uint8_t *bgra,
    int stride,
    int width,
    int height,
    clock::time_point now,
    std::optional<cursor_rect_t> cursor_rect
  ) {
    if (!bgra || width <= 0 || height <= 0 || width > 16384 || height > 16384 || stride < width * 4) {
      return;
    }

    std::vector<std::pair<responder_t, std::string>> ready_replies;
    std::optional<clock::time_point> next_wake;
    {
      std::lock_guard lock {state_mutex_};

      if (width != grid_w_ || height != grid_h_) {
        grid_w_ = width;
        grid_h_ = height;
        tiles_x_ = (width + tile_wire::TILE_SIZE - 1) / tile_wire::TILE_SIZE;
        tiles_y_ = (height + tile_wire::TILE_SIZE - 1) / tile_wire::TILE_SIZE;
        tiles_.assign(static_cast<std::size_t>(tiles_x_) * static_cast<std::size_t>(tiles_y_), tile_state_t {});
        ready_order_.clear();
        ready_tiles_.clear();
        invalidation_order_.clear();
        pending_invalidations_.clear();
        pending_reset_all_ = true;
      }

      const bool has_cursor = cursor_rect && cursor_rect->w > 0 && cursor_rect->h > 0;

      for (int ty = 0; ty < tiles_y_; ++ty) {
        const int tile_y = ty * tile_wire::TILE_SIZE;
        const int tile_h = std::min(tile_wire::TILE_SIZE, height - tile_y);
        for (int tx = 0; tx < tiles_x_; ++tx) {
          const int tile_x = tx * tile_wire::TILE_SIZE;
          const int tile_w = std::min(tile_wire::TILE_SIZE, width - tile_x);

          const std::uint32_t key = tile_key(tx, ty);
          auto &state = tiles_[static_cast<std::size_t>(ty) * static_cast<std::size_t>(tiles_x_) + static_cast<std::size_t>(tx)];

          const bool touches_cursor = has_cursor &&
                                      tile_x < cursor_rect->x + cursor_rect->w &&
                                      tile_x + tile_w > cursor_rect->x &&
                                      tile_y < cursor_rect->y + cursor_rect->h &&
                                      tile_y + tile_h > cursor_rect->y;
          if (touches_cursor) {
            state.has_hash = false;
            state.settled_frames = 0;
            state.refined_sent = false;
            erase_queued_tile_locked(key);
            if (state.client_active) {
              enqueue_invalidation_locked(tx, ty);
            }
            continue;
          }

          const std::uint64_t h = hash_tile_bgr(bgra, stride, tile_x, tile_y, tile_w, tile_h);

          if (!state.has_hash || state.hash != h) {
            state.hash = h;
            state.has_hash = true;
            state.settled_frames = 0;
            state.refined_sent = false;
            erase_queued_tile_locked(key);
            if (state.client_active) {
              enqueue_invalidation_locked(tx, ty);
            }
            continue;
          }

          if (state.settled_frames < 2) {
            ++state.settled_frames;
          }

          if (state.settled_frames == 2 && !state.refined_sent) {
            if (!has_high_chroma_error_bgra(bgra, stride, tile_x, tile_y, tile_w, tile_h)) {
              state.refined_sent = true;
              if (state.client_active) {
                enqueue_invalidation_locked(tx, ty);
              }
              continue;
            }

            if (ready_tiles_.size() >= tile_wire::MAX_READY_QUEUE && !ready_tiles_.contains(key)) {
              // Leave refined_sent = false so the tile enqueues on the next frame once drained.
              continue;
            }

            scratch_rgb_.resize(static_cast<std::size_t>(tile_w) * static_cast<std::size_t>(tile_h) * 3u);
            for (int y = 0; y < tile_h; ++y) {
              const std::uint8_t *src = bgra +
                                        static_cast<std::size_t>(tile_y + y) * static_cast<std::size_t>(stride) +
                                        static_cast<std::size_t>(tile_x) * 4u;
              std::uint8_t *dst = scratch_rgb_.data() + static_cast<std::size_t>(y) * static_cast<std::size_t>(tile_w) * 3u;
              for (int x = 0; x < tile_w; ++x) {
                dst[x * 3 + 0] = src[x * 4 + 2];  // R
                dst[x * 3 + 1] = src[x * 4 + 1];  // G
                dst[x * 3 + 2] = src[x * 4 + 0];  // B
              }
            }

            if (tile_qoi::qoi_encode_rgb24(scratch_rgb_.data(), tile_w * 3, tile_w, tile_h, scratch_qoi_) &&
                scratch_qoi_.size() <= tile_wire::MAX_TILE_PAYLOAD) {
              erase_invalidation_locked(key);
              enqueue_tile_locked(tx, ty, tile_w, tile_h, std::move(scratch_qoi_));
            } else if (state.client_active) {
              enqueue_invalidation_locked(tx, ty);
            }
            state.refined_sent = true;
          }
        }
      }

      if (pending_invalidations_.size() > tile_wire::MAX_PER_TILE_INVALIDATIONS) {
        collapse_invalidations_to_reset_locked();
      }

      wake_waiting_locked(now, ready_replies, next_wake);
    }

    for (auto &[responder, body] : ready_replies) {
      responder(200, std::move(body));
    }
    if (next_wake && schedule_wake_) {
      schedule_wake_(*next_wake);
    }
  }

  bool tile_refiner_t::build_batch_locked(
    clock::time_point now,
    std::string &out_binary,
    std::optional<std::chrono::milliseconds> &out_retry_after
  ) {
    out_binary.clear();
    out_retry_after.reset();

    if (!bw_initialized_) {
      bw_tokens_ = static_cast<double>(tile_wire::BANDWIDTH_BURST_BYTES);
      bw_last_refill_ = now;
      bw_initialized_ = true;
    } else {
      const double elapsed = std::max(0.0, std::chrono::duration<double>(now - bw_last_refill_).count());
      bw_tokens_ = std::min(
        static_cast<double>(tile_wire::BANDWIDTH_BURST_BYTES),
        bw_tokens_ + elapsed * static_cast<double>(tile_wire::BANDWIDTH_BYTES_PER_SEC)
      );
      bw_last_refill_ = now;
    }

    // Drop stale order entries that were removed on motion/coalesce
    while (!ready_order_.empty() && !ready_tiles_.contains(ready_order_.front())) {
      ready_order_.pop_front();
    }

    const bool send_reset = pending_reset_all_ && grid_w_ > 0 && grid_h_ > 0;
    const bool has_invalidations = !send_reset && !invalidation_order_.empty();
    if (!send_reset && !has_invalidations && ready_order_.empty()) {
      return false;
    }

    if (!send_reset && !has_invalidations && !ready_order_.empty()) {
      const auto &front_tile = ready_tiles_.at(ready_order_.front());
      const double min_needed = static_cast<double>(tile_wire::HEADER_SIZE + tile_wire::TILE_HEADER_SIZE + front_tile.payload.size());
      if (bw_tokens_ < min_needed) {
        const double deficit = min_needed - bw_tokens_;
        const auto wait_ms = std::max<std::int64_t>(
          1,
          static_cast<std::int64_t>(std::ceil(deficit * 1000.0 / static_cast<double>(tile_wire::BANDWIDTH_BYTES_PER_SEC)))
        );
        out_retry_after = std::chrono::milliseconds {wait_ms};
        return false;
      }
    }

    std::string body;
    body.resize(tile_wire::HEADER_SIZE, '\0');
    std::size_t batch_bytes = tile_wire::HEADER_SIZE;
    std::uint16_t tile_count = 0;

    if (send_reset) {
      invalidation_order_.clear();
      pending_invalidations_.clear();
      for (auto &t : tiles_) {
        if (t.client_active) {
          t.client_active = false;
          t.refined_sent = false;
        }
      }
    } else {
      // Emit per-tile invalidations first so stale refined tiles clear immediately without QOI throttling
      while (!invalidation_order_.empty() && tile_count < tile_wire::MAX_TILES_PER_BATCH) {
        if (batch_bytes + tile_wire::TILE_HEADER_SIZE > tile_wire::MAX_BATCH_BYTES) {
          break;
        }
        const std::uint32_t key = invalidation_order_.front();
        invalidation_order_.pop_front();
        pending_invalidations_.erase(key);

        const int tx = static_cast<int>(key & 0xFFFFu);
        const int ty = static_cast<int>((key >> 16) & 0xFFFFu);
        if (tx < 0 || tx >= tiles_x_ || ty < 0 || ty >= tiles_y_) {
          continue;
        }

        const int tile_x = tx * tile_wire::TILE_SIZE;
        const int tile_y = ty * tile_wire::TILE_SIZE;
        const int tile_w = std::min(tile_wire::TILE_SIZE, grid_w_ - tile_x);
        const int tile_h = std::min(tile_wire::TILE_SIZE, grid_h_ - tile_y);
        if (tile_w <= 0 || tile_h <= 0) {
          continue;
        }

        tiles_[static_cast<std::size_t>(ty) * static_cast<std::size_t>(tiles_x_) + static_cast<std::size_t>(tx)].client_active = false;
        append_u32_le(body, ++seq_counter_);
        append_u16_le(body, static_cast<std::uint16_t>(tile_x));
        append_u16_le(body, static_cast<std::uint16_t>(tile_y));
        append_u16_le(body, static_cast<std::uint16_t>(tile_w));
        append_u16_le(body, static_cast<std::uint16_t>(tile_h));
        append_u32_le(body, 0u);

        batch_bytes += tile_wire::TILE_HEADER_SIZE;
        ++tile_count;
      }
    }

    while (!ready_order_.empty() && tile_count < tile_wire::MAX_TILES_PER_BATCH) {
      const std::uint32_t key = ready_order_.front();
      auto it = ready_tiles_.find(key);
      if (it == ready_tiles_.end()) {
        ready_order_.pop_front();
        continue;
      }
      const auto &tile = it->second;
      const std::size_t rec_bytes = tile_wire::TILE_HEADER_SIZE + tile.payload.size();
      if (batch_bytes + rec_bytes > tile_wire::MAX_BATCH_BYTES) {
        break;
      }
      const double cost = static_cast<double>(rec_bytes + (tile_count == 0 ? tile_wire::HEADER_SIZE : 0));
      if (cost > bw_tokens_) {
        break;
      }

      bw_tokens_ -= cost;
      append_u32_le(body, tile.seq);
      append_u16_le(body, tile.x);
      append_u16_le(body, tile.y);
      append_u16_le(body, tile.w);
      append_u16_le(body, tile.h);
      append_u32_le(body, static_cast<std::uint32_t>(tile.payload.size()));
      body.append(reinterpret_cast<const char *>(tile.payload.data()), tile.payload.size());

      const int tx = tile.x / tile_wire::TILE_SIZE;
      const int ty = tile.y / tile_wire::TILE_SIZE;
      if (tx >= 0 && tx < tiles_x_ && ty >= 0 && ty < tiles_y_) {
        tiles_[static_cast<std::size_t>(ty) * static_cast<std::size_t>(tiles_x_) + static_cast<std::size_t>(tx)].client_active = true;
      }

      batch_bytes += rec_bytes;
      ++tile_count;
      ready_tiles_.erase(it);
      ready_order_.pop_front();
    }

    if (send_reset) {
      pending_reset_all_ = false;
      if (tile_count == 0) {
        bw_tokens_ = std::max(0.0, bw_tokens_ - static_cast<double>(tile_wire::HEADER_SIZE));
      }
    } else if (tile_count == 0) {
      return false;
    }

    // Write 16-byte little-endian batch header
    std::memcpy(body.data(), tile_wire::MAGIC.data(), tile_wire::MAGIC.size());
    auto put_u16 = [&](std::size_t off, std::uint16_t v) {
      body[off + 0] = static_cast<char>(v & 0xFFu);
      body[off + 1] = static_cast<char>((v >> 8) & 0xFFu);
    };
    put_u16(4, tile_wire::VERSION);
    put_u16(6, send_reset ? tile_wire::FLAG_RESET_ALL : 0);
    put_u16(8, static_cast<std::uint16_t>(grid_w_));
    put_u16(10, static_cast<std::uint16_t>(grid_h_));
    put_u16(12, tile_count);
    put_u16(14, 0);

    out_binary = std::move(body);
    return true;
  }

  void tile_refiner_t::wake_waiting_locked(
    clock::time_point now,
    std::vector<std::pair<responder_t, std::string>> &ready_replies,
    std::optional<clock::time_point> &next_wake
  ) {
    for (auto it = parked_.begin(); it != parked_.end();) {
      std::string batch;
      std::optional<std::chrono::milliseconds> retry_after;
      if (build_batch_locked(now, batch, retry_after)) {
        ready_replies.emplace_back(std::move(it->second.responder), std::move(batch));
        it = parked_.erase(it);
      } else {
        if (retry_after) {
          const auto candidate = std::min(it->second.deadline, now + *retry_after);
          if (!next_wake || candidate < *next_wake) {
            next_wake = candidate;
          }
        }
        ++it;
      }
    }
  }

  bool tile_refiner_t::poll_at(
    const std::string &client,
    std::optional<clock::time_point> deadline,
    clock::time_point now,
    responder_t responder
  ) {
    std::optional<responder_t> superseded;
    std::optional<std::string> immediate_batch;
    std::optional<clock::time_point> next_wake;
    bool parked = false;

    {
      std::lock_guard lock {state_mutex_};
      if (auto it = parked_.find(client); it != parked_.end()) {
        superseded = std::move(it->second.responder);
        parked_.erase(it);
      }

      std::string batch;
      std::optional<std::chrono::milliseconds> retry_after;
      if (build_batch_locked(now, batch, retry_after)) {
        immediate_batch = std::move(batch);
      } else if (!deadline) {
        immediate_batch = std::string {};
      } else {
        parked_.emplace(client, parked_poll_t {std::move(responder), *deadline});
        parked = true;
        if (retry_after) {
          next_wake = std::min(*deadline, now + *retry_after);
        }
      }
    }

    if (superseded) {
      (*superseded)(204, std::string {});
    }
    if (!parked) {
      if (immediate_batch && !immediate_batch->empty()) {
        responder(200, std::move(*immediate_batch));
      } else {
        responder(204, std::string {});
      }
    } else if (next_wake && schedule_wake_) {
      schedule_wake_(*next_wake);
    }
    return parked;
  }

  void tile_refiner_t::flush_waiting(clock::time_point now) {
    std::vector<std::pair<responder_t, std::string>> ready_replies;
    std::optional<clock::time_point> next_wake;
    {
      std::lock_guard lock {state_mutex_};
      wake_waiting_locked(now, ready_replies, next_wake);
    }
    for (auto &[responder, body] : ready_replies) {
      responder(200, std::move(body));
    }
    if (next_wake && schedule_wake_) {
      schedule_wake_(*next_wake);
    }
  }

  void tile_refiner_t::expire(clock::time_point now) {
    std::vector<responder_t> expired;
    {
      std::lock_guard lock {state_mutex_};
      for (auto it = parked_.begin(); it != parked_.end();) {
        if (it->second.deadline <= now) {
          expired.push_back(std::move(it->second.responder));
          it = parked_.erase(it);
        } else {
          ++it;
        }
      }
    }
    for (auto &responder : expired) {
      responder(204, std::string {});
    }
  }

  void tile_refiner_t::end_stream(const std::string &client) {
    std::optional<responder_t> parked;
    {
      std::lock_guard lock {state_mutex_};
      if (auto it = parked_.find(client); it != parked_.end()) {
        parked = std::move(it->second.responder);
        parked_.erase(it);
      }
    }
    if (parked) {
      (*parked)(409, std::string {});
    }
  }

  void tile_refiner_t::shutdown() {
    {
      std::lock_guard slot_lock {slot_mutex_};
      stopping_ = true;
      has_pending_ = false;
    }
    slot_cv_.notify_all();
    if (worker_.joinable()) {
      worker_.join();
    }

    std::vector<responder_t> doomed;
    {
      std::lock_guard lock {state_mutex_};
      for (auto &[_, entry] : parked_) {
        doomed.push_back(std::move(entry.responder));
      }
      parked_.clear();
      reset_grid_locked();
    }
    for (auto &responder : doomed) {
      responder(503, std::string {});
    }
  }

  void tile_refiner_t::drain_for_test() {
    std::unique_lock lock {slot_mutex_};
    slot_cv_.wait(lock, [this]() {
      return stopping_ || (!has_pending_ && !processing_);
    });
  }

  std::size_t tile_refiner_t::ready_queue_size() const {
    std::lock_guard lock {state_mutex_};
    return ready_tiles_.size();
  }

  std::size_t tile_refiner_t::pending_invalidation_count() const {
    std::lock_guard lock {state_mutex_};
    return pending_invalidations_.size();
  }

  std::size_t tile_refiner_t::parked_poll_count() const {
    std::lock_guard lock {state_mutex_};
    return parked_.size();
  }
}  // namespace sds
