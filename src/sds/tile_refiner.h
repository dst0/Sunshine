/**
 * @file src/sds/tile_refiner.h
 * @brief Non-blocking 64x64 dirty-tile tracker, chroma-error filter, and `/sds/v1/tile-refinement` batcher.
 */
#pragma once

// standard includes
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <list>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

// local includes
#include "tile_qoi.h"

namespace sds {
  /**
   * @brief Wire framing constants and hard caps for `/sds/v1/tile-refinement`.
   */
  namespace tile_wire {
    inline constexpr std::array<char, 4> MAGIC {'S', 'D', 'T', 'R'};  ///< Binary batch magic.
    inline constexpr std::uint16_t VERSION = 1;  ///< Binary protocol version.
    inline constexpr std::uint16_t FLAG_RESET_ALL = 0x0001;  ///< Clear client refinement buffers.
    inline constexpr std::size_t HEADER_SIZE = 16;  ///< Batch header byte size.
    inline constexpr std::size_t TILE_HEADER_SIZE = 16;  ///< Per-tile record header byte size.
    inline constexpr std::size_t MAX_TILES_PER_BATCH = 64;  ///< Max tiles in one HTTP response.
    inline constexpr std::size_t MAX_BATCH_BYTES = 256 * 1024;  ///< Max binary batch byte length.
    inline constexpr std::size_t MAX_TILE_PAYLOAD = tile_qoi::MAX_TILE_PAYLOAD;  ///< Max QOI payload per tile.
    inline constexpr std::size_t MAX_READY_QUEUE = 256;  ///< Bounded coalescing queue capacity.
    inline constexpr int TILE_SIZE = tile_qoi::TILE_SIZE;  ///< 64x64 tile edge length.
    inline constexpr int CHROMA_ERROR_THRESHOLD = 10;  ///< Min 4:2:0 round-trip abs RGB error (out of 255).
    inline constexpr std::size_t BANDWIDTH_BYTES_PER_SEC = 4 * 1024 * 1024;  ///< Soft ~4 MiB/s output cap.
    inline constexpr std::size_t BANDWIDTH_BURST_BYTES = MAX_BATCH_BYTES;  ///< Token bucket burst ceiling.
  }  // namespace tile_wire

  /**
   * @brief Tracks settled 64x64 BGRA desktop tiles and serves lossless QOI-RGB24 refinement batches.
   *
   * Thread-safe. `submit_bgra_frame()` uses a single non-blocking staging slot so capture/encode
   * threads never stall. Long-poll callbacks are always invoked without internal mutexes held.
   */
  class tile_refiner_t {
  public:
    using clock = std::chrono::steady_clock;  ///< Clock for poll deadlines and bandwidth pacing.
    /** @brief Long-poll completion callback: `(http_status, binary_or_empty_body)`. */
    using responder_t = std::function<void(int status, std::string body)>;
    /** @brief Optional scheduler invoked when a parked poll is waiting on bandwidth refill. */
    using schedule_wake_t = std::function<void(clock::time_point when)>;

    /**
     * @brief Construct the refiner.
     *
     * @param start_worker Whether to spawn the background worker thread (`false` for synchronous unit tests).
     * @param schedule_wake Optional timer callback to flush bandwidth-throttled parked polls.
     */
    explicit tile_refiner_t(bool start_worker = true, schedule_wake_t schedule_wake = {});

    /**
     * @brief Stop the worker thread and cancel any parked polls.
     */
    ~tile_refiner_t();

    tile_refiner_t(const tile_refiner_t &) = delete;
    tile_refiner_t &operator=(const tile_refiner_t &) = delete;

    /**
     * @brief Enable or disable background frame tapping/tracking. Never blocks.
     *
     * @param active True while at least one running session uses tile refinement.
     */
    void set_active(bool active);

    /**
     * @brief Check whether tile refinement tracking is currently active.
     */
    [[nodiscard]] bool active() const {
      return active_.load(std::memory_order_acquire);
    }

    /**
     * @brief Non-blocking single-slot BGRA submission from the capture/encode thread.
     *
     * Drops any stale unconsumed frame in the slot so capture/encode latency is never blocked.
     *
     * @param bgra Pointer to top-left 32-bit BGRA/BGRX pixel.
     * @param stride Row pitch in bytes (`>= width * 4`).
     * @param width Frame width in pixels (`1..16384`).
     * @param height Frame height in pixels (`1..16384`).
     */
    void submit_bgra_frame(const std::uint8_t *bgra, int stride, int width, int height);

    /**
     * @brief Synchronously inspect one BGRA frame at an explicit timestamp (worker & tests).
     */
    void process_frame_at(const std::uint8_t *bgra, int stride, int width, int height, clock::time_point now);

    /**
     * @brief Poll for a binary refinement batch or park until `deadline`.
     *
     * @param client Client key (canonical PEM certificate).
     * @param deadline Optional timeout deadline; `std::nullopt` never parks (`timeout=0`).
     * @param now Current time.
     * @param responder Completion callback invoked with `200` (batch), `204` (empty/timeout), or `409`/`503`.
     * @return `true` when the poll was parked awaiting dirty settled tiles or bandwidth refill.
     */
    bool poll_at(
      const std::string &client,
      std::optional<clock::time_point> deadline,
      clock::time_point now,
      responder_t responder
    );

    /**
     * @brief Attempt to emit batches for parked polls (called on worker completion or refill timer).
     */
    void flush_waiting(clock::time_point now = clock::now());

    /**
     * @brief Complete parked polls whose deadline has elapsed with HTTP 204.
     */
    void expire(clock::time_point now);

    /**
     * @brief Complete any parked poll for `client` with HTTP 409 and reset tracker if idle.
     */
    void end_stream(const std::string &client);

    /**
     * @brief Stop the worker thread and complete every parked poll with HTTP 503.
     */
    void shutdown();

    /**
     * @brief Wait until the background worker has drained any queued single-slot frame (tests).
     */
    void drain_for_test();

    /**
     * @brief Number of tiles currently queued for transmission (tests).
     */
    [[nodiscard]] std::size_t ready_queue_size() const;

    /**
     * @brief Number of currently parked polls (tests).
     */
    [[nodiscard]] std::size_t parked_poll_count() const;

    /**
     * @brief Compute whether a `tile_w x tile_h` BGRA region exhibits 4:2:0 chroma round-trip error >= threshold.
     */
    static bool has_high_chroma_error_bgra(
      const std::uint8_t *bgra,
      int stride,
      int tile_x,
      int tile_y,
      int tile_w,
      int tile_h
    );

  private:
    struct tile_state_t {
      std::uint64_t hash = 0;
      bool has_hash = false;
      std::uint8_t settled_frames = 0;
      bool refined_sent = false;
    };

    struct queued_tile_t {
      std::uint32_t seq = 0;
      std::uint16_t x = 0;
      std::uint16_t y = 0;
      std::uint16_t w = 0;
      std::uint16_t h = 0;
      std::vector<std::uint8_t> payload;
      std::list<std::uint32_t>::iterator order_it {};
    };

    struct parked_poll_t {
      responder_t responder;
      clock::time_point deadline;
    };

    void worker_loop();
    void enqueue_tile_locked(int tx, int ty, int tile_w, int tile_h, std::vector<std::uint8_t> &&payload);
    void erase_queued_tile_locked(std::uint32_t key);
    bool build_batch_locked(
      clock::time_point now,
      std::string &out_binary,
      std::optional<std::chrono::milliseconds> &out_retry_after
    );
    void wake_waiting_locked(
      clock::time_point now,
      std::vector<std::pair<responder_t, std::string>> &ready_replies,
      std::optional<clock::time_point> &next_wake
    );
    void reset_grid_locked();

    std::atomic_bool active_ {false};
    schedule_wake_t schedule_wake_;

    // Single-slot staging between capture thread and refiner worker
    mutable std::mutex slot_mutex_;
    std::condition_variable slot_cv_;
    bool has_pending_ = false;
    bool processing_ = false;
    bool stopping_ = false;
    int pending_w_ = 0;
    int pending_h_ = 0;
    int pending_stride_ = 0;
    std::vector<std::uint8_t> pending_frame_;
    std::vector<std::uint8_t> work_frame_;
    std::thread worker_;

    // Tracker, queue, rate limiter, and parked polls
    mutable std::mutex state_mutex_;
    int grid_w_ = 0;
    int grid_h_ = 0;
    int tiles_x_ = 0;
    int tiles_y_ = 0;
    bool pending_reset_all_ = false;
    std::uint32_t seq_counter_ = 0;
    std::vector<tile_state_t> tiles_;
    std::list<std::uint32_t> ready_order_;
    std::unordered_map<std::uint32_t, queued_tile_t> ready_tiles_;
    double bw_tokens_ = static_cast<double>(tile_wire::BANDWIDTH_BURST_BYTES);
    clock::time_point bw_last_refill_ {};
    bool bw_initialized_ = false;
    std::map<std::string, parked_poll_t, std::less<>> parked_;
    std::vector<std::uint8_t> scratch_rgb_;
    std::vector<std::uint8_t> scratch_qoi_;
  };
}  // namespace sds
