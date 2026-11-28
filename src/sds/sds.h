/**
 * @file src/sds/sds.h
 * @brief secure-desktop-stream module: lifecycle, worker threads, stream hooks and the
 *        transport-independent request dispatcher for `/sds/v1`.
 */
#pragma once

// standard includes
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

// local includes
#include "auth.h"
#include "clipboard_backend.h"
#include "files.h"
#include "lossless_stream.h"
#include "reply.h"
#include "tile_refiner.h"

namespace sds {
  namespace file_clipboard {
    class stage_t;
  }

  /**
   * @brief Protocol version reported in `/serverinfo` and capabilities.
   */
  inline constexpr int PROTOCOL_VERSION = 1;

  /**
   * @brief Runtime configuration of the module.
   */
  struct options_t {
    bool clipboard = true;  ///< `clipboard` switch.
    bool file_transfer = true;  ///< `file_transfer` switch.
    bool file_clipboard = false;  ///< Explicit opt-in for the isolated X11 desktop.
    bool mic_passthrough = true;  ///< `mic_passthrough` switch.
    bool tile_refinement = true;  ///< Adaptive dirty-tile lossless refinement switch.
    bool lossless_video = true;  ///< Bit-exact SDLL v1 lossless video mode switch.
    std::string lossless_encoder = "auto";  ///< Default host lossless encoder ("auto", "gpu", "cpu").
    std::size_t clipboard_text_max = 1024 * 1024;  ///< `clipboard_text_max`.
    std::size_t clipboard_image_max = 16 * 1024 * 1024;  ///< `clipboard_image_max`.
    double clipboard_rate = 10;  ///< `clipboard_rate` per second.
    files::options_t files;  ///< File limits and folders.
    std::chrono::milliseconds poll_default = std::chrono::seconds {25};  ///< Long-poll timeout without `timeout` (DESIGN 4.5).
    std::chrono::milliseconds poll_max = std::chrono::seconds {30};  ///< Upper clamp of `timeout`; `timeout=0` never parks.
    std::chrono::milliseconds outbox_poll_interval = std::chrono::seconds {2};  ///< Outbox change detection period.
    std::chrono::milliseconds coalesce_window = std::chrono::milliseconds {500};  ///< Clipboard PUT coalescing window.
    std::chrono::milliseconds clipboard_read_timeout = std::chrono::seconds {1};  ///< Backend read timeout.
    std::chrono::milliseconds file_clipboard_lease_grace = std::chrono::seconds {15};  ///< Grace period before freeing retired file-clipboard leases.
    std::chrono::milliseconds file_clipboard_lease_ttl = std::chrono::minutes {3};  ///< Maximum lifetime of a published file-clipboard lease.
    std::size_t lazy_image_threshold = 256 * 1024;  ///< Host PNG size above which lazy chunked offers replace inline clipboard PNGs.
    std::size_t event_queue_max = 64;  ///< Per-client event queue bound.
  };

  /**
   * @brief Build options from `config::sds`.
   *
   * @return Options.
   */
  options_t options_from_config();

  /**
   * @brief Replaceable collaborators (production defaults when empty).
   */
  struct dependencies_t {
    std::function<bool(std::string_view cert)> stream_active;  ///< Default: rtsp_stream::has_running_session.
    std::function<bool(std::string_view cert)> tile_refinement_active;  ///< Default: rtsp_stream::has_tile_refinement_session.
    std::function<bool()> any_tile_refinement_active;  ///< Default: rtsp_stream::any_tile_refinement_session.
    std::function<bool(std::string_view cert)> lossless_active;  ///< Default: rtsp_stream::has_lossless_session.
    std::function<bool()> any_lossless_active;  ///< Default: rtsp_stream::any_lossless_session.
    std::function<bool(std::string_view cert, std::uint8_t &hash_algo, std::string &encoder_pref)> lossless_config;  ///< Default: rtsp_stream::get_lossless_session_config.
    std::function<std::optional<client_t>(std::string_view cert)> find_client;  ///< Default: nvhttp paired-client store.
    std::function<std::unique_ptr<clipboard::backend_t>()> make_clipboard_backend;  ///< Default: clipboard::make_backend.
    std::function<std::shared_ptr<const file_clipboard::stage_t>(std::string_view body, const std::function<bool()> &allowed)> stage_file_clipboard;  ///< Default: file_clipboard::stage.
    bool observe_sessions = true;  ///< Register with rtsp_stream for session start/stop notifications.
  };

  /**
   * @brief Request fields extracted by the HTTP adapter.
   */
  struct request_t {
    std::optional<std::string> cert_pem;  ///< Verified client certificate.
    std::string id;  ///< Primary path parameter (upload, outbox, offer, or drop id).
    std::string sub_id;  ///< Secondary path parameter (e.g. offer entry id).
    std::map<std::string, std::string, std::less<>> query;  ///< Query parameters.
    std::string content_type;  ///< `Content-Type`.
    std::string client_seq;  ///< `X-SDS-Client-Seq`.
    std::string body;  ///< Request body.
    std::string file_clipboard_seq {};  ///< `X-SDS-Clipboard-Seq`.
    std::string file_clipboard_epoch {};  ///< `X-SDS-Clipboard-Epoch`.
    sds::lossless::lossless_stream_t::upgrade_invoker_t upgrade_raw;  ///< Raw HTTP 101 stream upgrade callback for `op_e::lossless_stream`.
  };

  /**
   * @brief Completion callback; invoked exactly once, possibly from a worker thread.
   */
  using reply_fn = std::function<void(reply_t)>;

  /**
   * @brief Create the platform clipboard backend early, when `clipboard` is enabled.
   *
   * Called from main() before platf::init(): the Linux backend must register before portal
   * capture sessions are created so they request clipboard access. start() takes the prepared
   * backend; without this call start() creates it itself.
   */
  void prepare_clipboard_backend();

  /**
   * @brief Check whether the enabled paired client with this certificate holds a permission.
   *
   * Adapter for other modules (e.g. microphone passthrough); it does not check streams or switches.
   *
   * @param cert_pem Canonical PEM certificate.
   * @param permission Permission.
   * @return `true` when granted.
   */
  bool permission_granted(std::string_view cert_pem, permission_e permission);

  /**
   * @brief Start the module (idempotent; restarts with new options when already running).
   *
   * @param options Configuration.
   * @param deps Collaborators.
   * @return Zero on success.
   */
  int start(options_t options, dependencies_t deps = {});

  /**
   * @brief Start with options from the global configuration.
   *
   * @return Zero on success.
   */
  int start();

  /**
   * @brief Stop the module: complete parked polls, delete partial uploads, stop the clipboard
   *        backend and join the worker threads. Idempotent.
   */
  void stop();

  /**
   * @brief Check whether the module is running.
   *
   * @return `true` between start() and stop().
   */
  bool running();

  /**
   * @brief Authorize and dispatch one request.
   *
   * @param op Operation.
   * @param request Request fields.
   * @param respond Completion callback.
   */
  void handle(op_e op, request_t request, reply_fn respond);

  /**
   * @brief Session observer: a stream of `cert_pem` started or stopped. Never blocks.
   *
   * @param cert_pem Client certificate of the session.
   * @param running Captured aggregate state: false means this certificate reached zero running streams.
   */
  void on_stream_state(std::string_view cert_pem, bool running);

  /**
   * @brief A paired client's permissions or enabled state changed (admin API). Never blocks.
   *
   * @param cert_pem Client certificate.
   */
  void on_client_changed(std::string_view cert_pem);

  /**
   * @brief Comma-separated features for `/serverinfo` (`clipboard,files,mic`), enabled and available.
   *
   * @return Feature list, empty when the module is stopped.
   */
  std::string server_features();

  /**
   * @brief Largest request body the HTTPS server must buffer for `/sds/v1`.
   *
   * @return max(file_chunk_max, clipboard_image_max, clipboard_text_max) + 64 KiB.
   */
  std::size_t max_request_body_size();

  /**
   * @brief Report whether the microphone backend is usable (set by the mic module).
   *
   * @param available Availability.
   */
  void set_mic_available(bool available);

  /**
   * @brief Refresh tile refiner active state from running session flags. Never blocks.
   *
   * @param stopped_cert Optional client certificate whose tile-refinement stream just stopped.
   */
  void on_tile_refinement_sessions_changed(std::string_view stopped_cert = {});

  /**
   * @brief Lock-free check whether any active stream wants BGRA frames for tile refinement.
   */
  bool tile_refinement_wanted();

  /**
   * @brief Non-blocking single-slot BGRA submission from video capture/encode.
   *
   * @param bgra Top-left 32-bit BGRA/BGRX pixel pointer.
   * @param stride Row stride in bytes (`>= width * 4`).
   * @param width Frame width in pixels.
   * @param height Frame height in pixels.
   */
  void submit_bgra_frame(
    const std::uint8_t *bgra,
    int stride,
    int width,
    int height,
    std::optional<cursor_rect_t> cursor_rect = std::nullopt
  );

  /**
   * @brief Refresh SDLL v1 lossless stream active state from running session flags. Never blocks.
   */
  void on_lossless_sessions_changed(std::string_view stopped_cert = {});

  /**
   * @brief Lock-free check whether any active stream uses SDLL v1 lossless video mode.
   */
  bool lossless_wanted();

  /**
   * @brief Non-blocking single-slot BGRA submission for SDLL v1 lossless video streaming.
   */
  void submit_lossless_bgra_frame(
    const std::uint8_t *bgra,
    int stride,
    int width,
    int height,
    std::uint64_t capture_ts_us
  );

  /**
   * @brief Block until both worker threads have run every job queued so far (tests).
   */
  void drain_for_test();

  /**
   * @brief Queue a job on the file worker thread (tests use it to keep the worker busy).
   *
   * @param job Job.
   * @return `false` when the module is not running.
   */
  bool post_to_file_worker_for_test(std::function<void()> job);

  /**
   * @brief Queue a job on the clipboard worker so tests can hold deferred requests.
   *
   * @param job Job.
   * @return `false` when the module is not running.
   */
  bool post_to_control_worker_for_test(std::function<void()> job);

  /**
   * @brief Diagnostics for tests.
   */
  struct test_state_t {
    bool running = false;  ///< Module running.
    std::size_t open_uploads = 0;  ///< Upload sessions of the client.
    std::size_t queued_events = 0;  ///< Queued events of the client.
    bool parked_poll = false;  ///< Parked poll of the client.
    bool event_state = false;  ///< Any event state of the client.
    bool rate_bucket = false;  ///< Rate-limit state of the client.
    bool active = false;  ///< Client tracked as streaming.
    bool clipboard_watching = false;  ///< Backend watched.
    bool clipboard_content = false;  ///< Clipboard content cached.
    std::uint64_t clipboard_seq = 0;  ///< Host clipboard seq.
    std::size_t file_clipboard_leases = 0;  ///< Active or grace-retained file-clipboard leases.
  };

  /**
   * @brief Snapshot internal state for a client (tests). Drains the workers first.
   *
   * @param cert_pem Client certificate.
   * @return State.
   */
  test_state_t state_for_test(std::string_view cert_pem);
}  // namespace sds
