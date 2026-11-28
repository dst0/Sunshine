/**
 * @file src/sds/lossless_stream.cpp
 * @brief Host-side PQ TLS 1.3 upgraded binary stream controller and latest-frame-wins encoder worker.
 */

#include "lossless_stream.h"

#include <algorithm>
#include <cstring>

namespace sds::lossless {
  namespace {
    class cpu_backend_adapter_t final: public encoder_backend_t {
    public:
      explicit cpu_backend_adapter_t(int thread_count = 0):
          enc_(thread_count) {}

      std::string name() const override {
        return "cpu-simd";
      }

      bool is_gpu() const override {
        return false;
      }

      void reset() override {
        enc_.reset();
      }

      bool encode_frame(
        const std::uint8_t *bgra,
        int stride,
        int width,
        int height,
        std::uint64_t frame_id,
        std::uint64_t capture_ts_us,
        hash_algo_e hash_algo,
        bool force_keyframe,
        std::vector<std::uint8_t> &out_packet,
        encode_stats_t *out_stats
      ) override {
        return enc_.encode_frame(
          bgra,
          stride,
          width,
          height,
          frame_id,
          capture_ts_us,
          hash_algo,
          force_keyframe,
          out_packet,
          out_stats
        );
      }

    private:
      cpu_encoder_t enc_;
    };
  }  // namespace

  std::unique_ptr<encoder_backend_t> make_cpu_encoder_backend(int thread_count) {
    return std::make_unique<cpu_backend_adapter_t>(thread_count);
  }

  std::unique_ptr<encoder_backend_t> select_encoder_backend(std::string_view preference) {
    if (preference != "cpu") {
      if (auto gpu = make_gpu_encoder_backend()) {
        return gpu;
      }
    }
    return make_cpu_encoder_backend();
  }

  // Fallback stub when no platform GPU file is linked (macOS/Linux/Windows each provide real implementation)
#if !defined(__APPLE__) && !defined(_WIN32) && !defined(__linux__)
  std::unique_ptr<encoder_backend_t> make_gpu_encoder_backend() {
    return nullptr;
  }
  std::string available_encoder_backends() {
    return "cpu";
  }
#endif

  lossless_stream_t::lossless_stream_t() {
    alive_ = std::make_shared<alive_state_t>();
    alive_->alive = true;
    alive_->owner = this;
    worker_ = std::thread([this]() {
      worker_loop();
    });
  }

  lossless_stream_t::~lossless_stream_t() {
    shutdown();
  }

  void lossless_stream_t::configure_session(
    std::string client_cert,
    hash_algo_e hash_algo,
    std::string encoder_pref
  ) {
    session_epoch_.fetch_add(1, std::memory_order_acq_rel);
    {
      std::lock_guard lock {config_mutex_};
      session_cert_ = std::move(client_cert);
      encoder_pref_ = encoder_pref.empty() ? std::string {"auto"} : std::move(encoder_pref);
      encoder_.reset();
    }
    hash_algo_.store(static_cast<std::uint8_t>(hash_algo), std::memory_order_release);
    force_keyframe_.store(true, std::memory_order_release);
  }

  void lossless_stream_t::set_active(bool active) {
    const bool prev = active_.exchange(active, std::memory_order_acq_rel);
    if (prev && !active) {
      session_epoch_.fetch_add(1, std::memory_order_acq_rel);
      {
        std::lock_guard lock {slot_mutex_};
        has_pending_ = false;
        has_last_frame_ = false;
      }
      {
        std::lock_guard lock {stream_mutex_};
        close_raw_stream_locked();
      }
      std::lock_guard lock {config_mutex_};
      if (encoder_) {
        encoder_->reset();
      }
    }
  }

  void lossless_stream_t::close_raw_stream_locked() {
    if (active_raw_) {
      if (active_raw_->raw) {
        sds_http_raw_stream_close(active_raw_->raw);
      }
      active_raw_.reset();
    }
    active_cert_.clear();
    ctrl_rx_buf_.clear();
  }

  void lossless_stream_t::cb_client_data(void *user_data, const std::uint8_t *data, std::size_t len) {
    auto *heap_sp = static_cast<std::shared_ptr<callback_ctx_t> *>(user_data);
    if (!heap_sp || !*heap_sp || !data || len == 0) {
      return;
    }
    auto ctx = *heap_sp;
    if (!ctx->state) {
      return;
    }
    std::lock_guard lock {ctx->state->mutex};
    if (ctx->state->alive && ctx->state->owner) {
      ctx->state->owner->on_client_bytes(data, len);
    }
  }

  void lossless_stream_t::cb_stream_closed(void *user_data) {
    auto *heap_sp = static_cast<std::shared_ptr<callback_ctx_t> *>(user_data);
    if (!heap_sp) {
      return;
    }
    auto ctx = *heap_sp;
    delete heap_sp;
    if (!ctx || !ctx->state) {
      return;
    }
    std::lock_guard lock {ctx->state->mutex};
    ctx->closed_before_attach.store(true, std::memory_order_release);
    if (ctx->state->alive && ctx->state->owner) {
      SdsHttpRawStream *raw = ctx->raw.load(std::memory_order_acquire);
      if (raw) {
        ctx->state->owner->on_raw_stream_closed(raw);
      }
    }
  }

  bool lossless_stream_t::accept_http_upgrade(std::string_view client_cert, const upgrade_invoker_t &do_upgrade) {
    if (!do_upgrade) {
      return false;
    }
    {
      std::lock_guard lock {config_mutex_};
      if (session_cert_.empty() || session_cert_ != client_cert) {
        return false;
      }
    }
    auto ctx = std::make_shared<callback_ctx_t>();
    ctx->state = alive_;
    auto *heap_sp = new std::shared_ptr<callback_ctx_t>(ctx);

    SdsHttpRawStream *raw_stream = do_upgrade(&cb_client_data, &cb_stream_closed, heap_sp);
    if (!raw_stream) {
      delete heap_sp;
      return false;
    }

    bool closed_before_attach = false;
    {
      std::lock_guard lock {alive_->mutex};
      ctx->raw.store(raw_stream, std::memory_order_release);
      closed_before_attach = ctx->closed_before_attach.load(std::memory_order_acquire);
    }
    if (closed_before_attach) {
      sds_http_raw_stream_close(raw_stream);
      sds_http_raw_stream_release(raw_stream);
      return false;
    }

    auto raw_handle = std::make_shared<raw_stream_handle_t>(raw_stream);
    {
      std::lock_guard lock {stream_mutex_};
      close_raw_stream_locked();
      active_raw_ = std::move(raw_handle);
      active_cert_ = std::string {client_cert};
      ctrl_rx_buf_.clear();
    }
    force_keyframe_.store(true, std::memory_order_release);
    {
      std::lock_guard lock {slot_mutex_};
      if (has_last_frame_ && !last_frame_.empty() && last_w_ > 0 && last_h_ > 0) {
        resend_last_ = true;
      }
    }
    slot_cv_.notify_one();
    return true;
  }

  void lossless_stream_t::submit_bgra_frame(
    const std::uint8_t *bgra,
    int stride,
    int width,
    int height,
    std::uint64_t capture_ts_us
  ) {
    if (!active_.load(std::memory_order_acquire)) {
      return;
    }
    if (!bgra || width <= 0 || height <= 0 || width > MAX_FRAME_DIM || height > MAX_FRAME_DIM || stride < width * 4) {
      return;
    }

    const std::size_t row_bytes = static_cast<std::size_t>(width) * 4u;
    const std::size_t total_bytes = row_bytes * static_cast<std::size_t>(height);

    std::unique_lock lock {slot_mutex_, std::try_to_lock};
    if (!lock.owns_lock() || stopping_) {
      return;
    }

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
    pending_ts_us_ = capture_ts_us;
    has_pending_ = true;
    lock.unlock();
    slot_cv_.notify_one();
  }

  void lossless_stream_t::on_client_bytes(const std::uint8_t *data, std::size_t len) {
    if (!data || len == 0) {
      return;
    }
    std::lock_guard lock {stream_mutex_};
    if (ctrl_rx_buf_.size() + len > 4096) {
      ctrl_rx_buf_.clear();
      return;
    }
    ctrl_rx_buf_.insert(ctrl_rx_buf_.end(), data, data + len);
    while (ctrl_rx_buf_.size() >= CONTROL_MSG_SIZE) {
      control_msg_t msg;
      if (parse_control_msg(ctrl_rx_buf_.data(), CONTROL_MSG_SIZE, msg)) {
        ctrl_rx_buf_.erase(ctrl_rx_buf_.begin(), ctrl_rx_buf_.begin() + CONTROL_MSG_SIZE);
        if (msg.type == control_msg_e::request_keyframe) {
          force_keyframe_.store(true, std::memory_order_release);
          {
            std::lock_guard slock {slot_mutex_};
            if (has_last_frame_ && !last_frame_.empty() && last_w_ > 0 && last_h_ > 0) {
              resend_last_ = true;
            }
          }
          slot_cv_.notify_one();
        } else if (msg.type == control_msg_e::set_hash_algo &&
                   msg.arg <= static_cast<std::uint32_t>(hash_algo_e::blake3)) {
          hash_algo_.store(static_cast<std::uint8_t>(msg.arg), std::memory_order_release);
          force_keyframe_.store(true, std::memory_order_release);
        }
      } else {
        // Resync on next magic byte if misaligned
        ctrl_rx_buf_.erase(ctrl_rx_buf_.begin());
      }
    }
  }

  void lossless_stream_t::on_raw_stream_closed(SdsHttpRawStream *stream) {
    std::lock_guard lock {stream_mutex_};
    if (active_raw_ && active_raw_->raw == stream) {
      active_raw_.reset();
      active_cert_.clear();
      ctrl_rx_buf_.clear();
    }
  }

  void lossless_stream_t::end_stream(std::string_view client_cert) {
    std::lock_guard lock {stream_mutex_};
    if (active_raw_ && (client_cert.empty() || active_cert_ == client_cert)) {
      close_raw_stream_locked();
    }
  }

  void lossless_stream_t::shutdown() {
    if (alive_) {
      std::lock_guard lock {alive_->mutex};
      alive_->alive = false;
      alive_->owner = nullptr;
    }
    {
      std::lock_guard lock {slot_mutex_};
      stopping_ = true;
      has_pending_ = false;
    }
    slot_cv_.notify_all();
    {
      std::lock_guard lock {stream_mutex_};
      close_raw_stream_locked();
    }
    if (worker_.joinable()) {
      worker_.join();
    }
  }

  std::string lossless_stream_t::active_backend_name() const {
    std::lock_guard lock {config_mutex_};
    return encoder_ ? encoder_->name() : std::string {"none"};
  }

  void lossless_stream_t::worker_loop() {
    while (true) {
      int w = 0;
      int h = 0;
      int stride = 0;
      std::uint64_t ts_us = 0;
      {
        std::unique_lock lock {slot_mutex_};
        slot_cv_.wait(lock, [this]() {
          return stopping_ || (active_.load(std::memory_order_acquire) && has_pending_);
        });
        if (stopping_) {
          return;
        }
        // Check transport capacity BEFORE popping/encoding so we never drop an encoded delta frame!
        lock.unlock();

        std::shared_ptr<raw_stream_handle_t> raw;
        {
          std::lock_guard sl {stream_mutex_};
          if (active_raw_ && active_raw_->raw && !sds_http_raw_stream_is_closed(active_raw_->raw)) {
            raw = active_raw_;
          }
        }
        if (!raw) {
          std::unique_lock relock {slot_mutex_};
          has_pending_ = false;
          continue;
        }
        if (!sds_http_raw_stream_can_send(raw->raw)) {
          sds_http_raw_stream_wait_writable(raw->raw, 16);
          continue;
        }

        lock.lock();
        if (stopping_) {
          return;
        }
        slot_cv_.wait(lock, [this]() {
          return stopping_ || has_pending_ || resend_last_;
        });
        if (stopping_) {
          return;
        }
        if (has_pending_) {
          work_frame_.swap(pending_frame_);
          w = pending_w_;
          h = pending_h_;
          stride = pending_stride_;
          ts_us = pending_ts_us_;
          last_frame_ = work_frame_;
          last_w_ = w;
          last_h_ = h;
          last_stride_ = stride;
          last_ts_us_ = ts_us;
          has_pending_ = false;
          resend_last_ = false;
          has_last_frame_ = true;
        } else if (resend_last_ && has_last_frame_ && !last_frame_.empty() && last_w_ > 0 && last_h_ > 0) {
          work_frame_ = last_frame_;
          w = last_w_;
          h = last_h_;
          stride = last_stride_;
          ts_us = last_ts_us_;
          resend_last_ = false;
        } else {
          resend_last_ = false;
          continue;
        }
      }

      const std::uint64_t epoch = session_epoch_.load(std::memory_order_acquire);
      std::unique_ptr<encoder_backend_t> local_enc;
      {
        std::lock_guard lock {config_mutex_};
        if (!encoder_) {
          encoder_ = select_encoder_backend(encoder_pref_);
        }
        local_enc.swap(encoder_);
      }

      bool has_live_raw = false;
      {
        std::lock_guard sl {stream_mutex_};
        has_live_raw = (active_raw_ != nullptr && active_raw_->raw != nullptr);
      }

      const bool stale_before_encode =
        !active_.load(std::memory_order_acquire) ||
        session_epoch_.load(std::memory_order_acquire) != epoch;

      bool encoded = false;
      if (local_enc && !stale_before_encode && has_live_raw) {
        const bool keyframe = force_keyframe_.exchange(false, std::memory_order_acq_rel);
        const auto algo = static_cast<hash_algo_e>(hash_algo_.load(std::memory_order_acquire));
        const std::uint64_t fid = ++frame_id_counter_;
        encoded = local_enc->encode_frame(
          work_frame_.data(),
          stride,
          w,
          h,
          fid,
          ts_us,
          algo,
          keyframe,
          packet_buf_,
          nullptr
        );
      }

      const bool stale_epoch = (session_epoch_.load(std::memory_order_acquire) != epoch) ||
                               !active_.load(std::memory_order_acquire);
      if (stale_epoch) {
        local_enc.reset();
        force_keyframe_.store(true, std::memory_order_release);
        continue;
      }

      {
        std::lock_guard lock {config_mutex_};
        if (!encoder_) {
          encoder_.swap(local_enc);
        }
      }

      if (!has_live_raw) {
        force_keyframe_.store(true, std::memory_order_release);
        continue;
      }

      if (!encoded) {
        force_keyframe_.store(true, std::memory_order_release);
        continue;
      }

      std::lock_guard sl {stream_mutex_};
      if (active_.load(std::memory_order_acquire) &&
          session_epoch_.load(std::memory_order_acquire) == epoch &&
          active_raw_ && active_raw_->raw && !sds_http_raw_stream_is_closed(active_raw_->raw)) {
        const std::int32_t rc = sds_http_raw_stream_try_send(
          active_raw_->raw,
          packet_buf_.data(),
          packet_buf_.size()
        );
        if (rc <= 0) {
          force_keyframe_.store(true, std::memory_order_release);
        }
      } else {
        force_keyframe_.store(true, std::memory_order_release);
      }
    }
  }

}  // namespace sds::lossless
