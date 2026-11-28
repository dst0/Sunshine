/**
 * @file src/sds/lossless_stream.h
 * @brief Host-side PQ TLS 1.3 upgraded binary stream controller and latest-frame-wins encoder worker.
 */
#pragma once

#include "lossless_codec.h"
#include "lossless_gpu_encoder.h"

#include <sds_http_rs/ffi.h>

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace sds::lossless {

  class lossless_stream_t {
  public:
    lossless_stream_t();
    ~lossless_stream_t();

    lossless_stream_t(const lossless_stream_t &) = delete;
    lossless_stream_t &operator=(const lossless_stream_t &) = delete;

    void configure_session(
      std::string client_cert,
      hash_algo_e hash_algo,
      std::string encoder_pref
    );

    void set_active(bool active);
    [[nodiscard]] bool active() const {
      return active_.load(std::memory_order_acquire);
    }

    using raw_data_cb_t = void (*)(void *user_data, const std::uint8_t *data, std::size_t len);
    using raw_closed_cb_t = void (*)(void *user_data);
    using upgrade_invoker_t = std::function<SdsHttpRawStream *(raw_data_cb_t, raw_closed_cb_t, void *user_data)>;

    /**
     * @brief Upgrade an HTTP/1.1 connection using lifetime-safe callback state.
     * @return `true` if upgraded and bound cleanly.
     */
    bool accept_http_upgrade(std::string_view client_cert, const upgrade_invoker_t &do_upgrade);

    /**
     * @brief Non-blocking latest-frame-wins BGRA submission from capture/video thread.
     */
    void submit_bgra_frame(
      const std::uint8_t *bgra,
      int stride,
      int width,
      int height,
      std::uint64_t capture_ts_us
    );

    void on_client_bytes(const std::uint8_t *data, std::size_t len);
    void on_raw_stream_closed(SdsHttpRawStream *stream);

    void end_stream(std::string_view client_cert);
    void shutdown();

    [[nodiscard]] std::string active_backend_name() const;

  private:
    struct alive_state_t {
      std::mutex mutex;
      bool alive = true;
      lossless_stream_t *owner = nullptr;
    };

    struct callback_ctx_t {
      std::shared_ptr<alive_state_t> state;
      std::atomic<SdsHttpRawStream *> raw {nullptr};
      std::atomic_bool closed_before_attach {false};
    };

    struct raw_stream_handle_t {
      SdsHttpRawStream *raw = nullptr;

      explicit raw_stream_handle_t(SdsHttpRawStream *r) : raw(r) {}

      ~raw_stream_handle_t() {
        if (raw) {
          sds_http_raw_stream_close(raw);
          sds_http_raw_stream_release(raw);
        }
      }

      raw_stream_handle_t(const raw_stream_handle_t &) = delete;
      raw_stream_handle_t &operator=(const raw_stream_handle_t &) = delete;
    };

    static void cb_client_data(void *user_data, const std::uint8_t *data, std::size_t len);
    static void cb_stream_closed(void *user_data);

    void worker_loop();
    void close_raw_stream_locked();

    std::shared_ptr<alive_state_t> alive_;
    std::atomic_bool active_ {false};
    std::atomic_bool force_keyframe_ {true};
    std::atomic<std::uint8_t> hash_algo_ {static_cast<std::uint8_t>(hash_algo_e::crc32c)};
    std::atomic_uint64_t session_epoch_ {1};

    mutable std::mutex config_mutex_;
    std::string session_cert_;
    std::string encoder_pref_ {"auto"};
    std::unique_ptr<encoder_backend_t> encoder_;

    // Pre-encode latest-frame-wins staging slot
    mutable std::mutex slot_mutex_;
    std::condition_variable slot_cv_;
    bool stopping_ = false;
    bool has_pending_ = false;
    bool has_last_frame_ = false;
    int pending_w_ = 0;
    int pending_h_ = 0;
    int pending_stride_ = 0;
    std::uint64_t pending_ts_us_ = 0;
    std::vector<std::uint8_t> pending_frame_;
    std::vector<std::uint8_t> work_frame_;

    // Upgraded raw stream ownership
    mutable std::mutex stream_mutex_;
    std::shared_ptr<raw_stream_handle_t> active_raw_;
    std::string active_cert_;
    std::vector<std::uint8_t> ctrl_rx_buf_;
    std::vector<std::uint8_t> packet_buf_;
    std::uint64_t frame_id_counter_ = 0;

    std::thread worker_;
  };

}  // namespace sds::lossless
