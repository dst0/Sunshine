/**
 * @file src/sds/sds.cpp
 * @brief secure-desktop-stream module lifecycle, worker threads, stream hooks and dispatcher.
 */
// standard includes
#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <charconv>
#include <cmath>
#include <future>
#include <map>
#include <mutex>
#include <set>
#include <utility>
#include <vector>

#include <openssl/evp.h>

// local includes
#include "clipboard.h"
#include "events.h"
#include "file_clipboard.h"
#include "mic.h"
#include "sds.h"
#include "src/config.h"
#include "src/logging.h"
#include "src/nvhttp.h"
#ifdef SUNSHINE_BUILD_X11
  #include "src/platform/linux/xdnd_x11.h"
#endif
#include "src/rtsp.h"
#include "tile_refiner.h"
#include "worker.h"

using namespace std::literals;

namespace sds {
  namespace {
    std::atomic_bool mic_available {false};  ///< Set by the microphone module.
    std::atomic_bool tile_refinement_enabled_atomic {false};  ///< Fast-path flag for active tile refinement capture tap.

    /**
     * @brief Mutex protecting the prepared clipboard backend.
     *
     * @return Mutex.
     */
    std::mutex &prepared_backend_mutex() {
      static std::mutex mutex;
      return mutex;
    }

    /**
     * @brief Backend created by prepare_clipboard_backend(), consumed by the next start().
     *
     * @return Storage.
     */
    std::unique_ptr<clipboard::backend_t> &prepared_backend() {
      static std::unique_ptr<clipboard::backend_t> backend;
      return backend;
    }

    /**
     * @brief Whether prepare_clipboard_backend() ran (a null result is remembered too).
     *
     * @return Flag storage.
     */
    bool &backend_prepared() {
      static bool prepared = false;
      return prepared;
    }

    /**
     * @brief Default backend factory: the prepared backend if any, otherwise a new one.
     *
     * @return Backend or nullptr.
     */
    std::unique_ptr<clipboard::backend_t> take_or_make_backend() {
      {
        std::lock_guard lock {prepared_backend_mutex()};
        if (backend_prepared()) {
          backend_prepared() = false;
          return std::move(prepared_backend());
        }
      }
      return clipboard::make_backend();
    }

    struct evp_ctx_deleter_t {
      void operator()(EVP_MD_CTX *ctx) const {
        if (ctx) {
          EVP_MD_CTX_free(ctx);
        }
      }
    };
    using md_ctx_ptr = std::unique_ptr<EVP_MD_CTX, evp_ctx_deleter_t>;

    bool is_safe_token(std::string_view token) {
      if (token.empty() || token.size() > 64) {
        return false;
      }
      return std::ranges::all_of(token, [](unsigned char ch) {
        return std::isalnum(ch) || ch == '_' || ch == '-';
      });
    }

    std::optional<std::string> normalize_hex_sha256(std::string_view value) {
      if (value.size() != 64) {
        return std::nullopt;
      }
      std::string out;
      out.reserve(64);
      for (const unsigned char ch : value) {
        if (!std::isxdigit(ch)) {
          return std::nullopt;
        }
        out.push_back(static_cast<char>(std::tolower(ch)));
      }
      return out;
    }

    std::string digest_hex(EVP_MD_CTX *ctx) {
      std::array<unsigned char, EVP_MAX_MD_SIZE> md {};
      unsigned int len = 0;
      if (!ctx || EVP_DigestFinal_ex(ctx, md.data(), &len) != 1) {
        return {};
      }
      std::string hex;
      hex.reserve(len * 2);
      for (unsigned int i = 0; i < len; ++i) {
        hex += "0123456789abcdef"[md[i] >> 4];
        hex += "0123456789abcdef"[md[i] & 15];
      }
      return hex;
    }

    struct staged_upload_entry_t {
      std::string id;
      std::string name;
      std::uint64_t expected_size = 0;
      std::uint64_t received = 0;
      bool started = false;
      bool committed = false;
      std::string part_name;
      std::unique_ptr<fs::file_t> part_file;
      md_ctx_ptr sha_ctx;
      std::string computed_sha256;
    };

    std::optional<reply_t> start_staged_entry(staged_upload_entry_t &entry, file_clipboard::chunk_stage_t &stage) {
      if (entry.started) {
        return std::nullopt;
      }
      const auto token = file_clipboard::new_epoch();
      if (!token) {
        return reply_t::failure(500, "internal", "failed to generate part name");
      }
      entry.part_name = "." + *token + ".part";
      if (auto ec = stage.create_part(entry.part_name, entry.part_file); ec || !entry.part_file) {
        return reply_t::failure(500, "internal", "failed to create staging file");
      }
      entry.sha_ctx.reset(EVP_MD_CTX_new());
      if (!entry.sha_ctx || EVP_DigestInit_ex(entry.sha_ctx.get(), EVP_sha256(), nullptr) != 1) {
        entry.part_file.reset();
        stage.remove_file(entry.part_name);
        return reply_t::failure(500, "internal", "failed to initialize hash");
      }
      entry.started = true;
      return std::nullopt;
    }

    reply_t write_staged_chunk(staged_upload_entry_t &entry, std::uint64_t offset, std::string_view data) {
      if (!entry.started || entry.committed || !entry.part_file) {
        return reply_t::failure(409, "conflict", "upload entry is not open");
      }
      if (offset != entry.received) {
        auto r = reply_t::failure(409, "conflict", "unexpected chunk offset");
        r.extra = nlohmann::json {{"expected_offset", entry.received}};
        return r;
      }
      if (data.size() > entry.expected_size - entry.received) {
        return reply_t::failure(413, "too_large", "chunk exceeds declared entry size");
      }
      if (!data.empty()) {
        if (auto ec = entry.part_file->write_at(offset, data); ec) {
          return reply_t::failure(500, "internal", "failed to write staged chunk");
        }
        if (EVP_DigestUpdate(entry.sha_ctx.get(), data.data(), data.size()) != 1) {
          return reply_t::failure(500, "internal", "failed to hash staged chunk");
        }
        entry.received += data.size();
      }
      return reply_t::success(200, nlohmann::json {{"offset", entry.received}});
    }

    std::optional<reply_t> finalize_staged_entry(
      staged_upload_entry_t &entry,
      file_clipboard::chunk_stage_t &stage,
      const std::optional<std::string> &expected_sha256
    ) {
      if (!entry.started || entry.received != entry.expected_size || !entry.part_file) {
        return reply_t::failure(422, "mismatch", "incomplete staged file");
      }
      if (entry.committed) {
        if (expected_sha256 && entry.computed_sha256 != *expected_sha256) {
          return reply_t::failure(422, "mismatch", "sha256 mismatch");
        }
        return std::nullopt;
      }
      entry.computed_sha256 = digest_hex(entry.sha_ctx.get());
      if (entry.computed_sha256.empty()) {
        return reply_t::failure(500, "internal", "failed to finalize hash");
      }
      if (expected_sha256 && entry.computed_sha256 != *expected_sha256) {
        return reply_t::failure(422, "mismatch", "sha256 mismatch");
      }
      if (auto ec = entry.part_file->sync(); ec) {
        return reply_t::failure(500, "internal", "failed to sync staged file");
      }
      entry.part_file.reset();
      if (auto ec = stage.commit_part(entry.part_name, entry.name); ec) {
        return reply_t::failure(500, "internal", "failed to commit staged file");
      }
      entry.committed = true;
      return std::nullopt;
    }

    std::string collision_name(std::string_view name, int attempt) {
      if (attempt <= 0) {
        return std::string {name};
      }
      const auto dot = name.rfind('.');
      if (dot == std::string_view::npos || dot == 0) {
        return std::string {name} + " (" + std::to_string(attempt) + ")";
      }
      return std::string {name.substr(0, dot)} + " (" + std::to_string(attempt) + ")" + std::string {name.substr(dot)};
    }

    std::optional<std::vector<std::string>> commit_staged_files_to_inbox(
      const std::filesystem::path &inbox_dir,
      const std::filesystem::path &stage_dir,
      const std::vector<staged_upload_entry_t> &entries,
      std::uint64_t total_size,
      std::uint64_t min_free_space
    ) {
      if (inbox_dir.empty() || !inbox_dir.is_absolute()) {
        return std::nullopt;
      }
      std::unique_ptr<fs::directory_t> target_dir;
      std::unique_ptr<fs::directory_t> src_dir;
      if (fs::open_directory(inbox_dir, true, target_dir) || !target_dir ||
          fs::open_directory(stage_dir, false, src_dir) || !src_dir) {
        return std::nullopt;
      }
      if (const auto free = target_dir->free_space(); free && (*free < min_free_space || *free - min_free_space < total_size)) {
        return std::nullopt;
      }
      std::vector<std::string> committed;
      committed.reserve(entries.size());
      std::vector<char> buf(64 * 1024);

      for (const auto &entry : entries) {
        std::unique_ptr<fs::file_t> src_file;
        if (src_dir->open_read(entry.name, src_file) || !src_file) {
          return std::nullopt;
        }
        const auto part_token = file_clipboard::new_epoch();
        if (!part_token) {
          return std::nullopt;
        }
        const std::string part = "." + *part_token + ".part";
        std::unique_ptr<fs::file_t> dst_file;
        if (target_dir->create_exclusive(part, dst_file) || !dst_file) {
          return std::nullopt;
        }
        std::uint64_t off = 0;
        bool write_ok = true;
        while (off < entry.expected_size) {
          std::size_t got = 0;
          const auto want = static_cast<std::size_t>(std::min<std::uint64_t>(buf.size(), entry.expected_size - off));
          if (src_file->read_at(off, std::span<char> {buf.data(), want}, got) || got == 0) {
            write_ok = false;
            break;
          }
          if (dst_file->write_at(off, std::span<const char> {buf.data(), got})) {
            write_ok = false;
            break;
          }
          off += got;
        }
        if (!write_ok || dst_file->sync()) {
          dst_file.reset();
          (void) target_dir->remove(part);
          return std::nullopt;
        }
        dst_file.reset();
        bool renamed = false;
        for (int attempt = 0; attempt <= 999; ++attempt) {
          const auto candidate = collision_name(entry.name, attempt);
          const auto ren = target_dir->rename_noreplace(part, candidate);
          if (ren == fs::rename_result_e::ok) {
            committed.push_back(candidate);
            renamed = true;
            break;
          }
          if (ren != fs::rename_result_e::exists) {
            break;
          }
        }
        if (!renamed) {
          (void) target_dir->remove(part);
          return std::nullopt;
        }
      }
      return committed;
    }

    /**
     * @brief Parse an unsigned decimal query value.
     *
     * @param value Text.
     * @return Number, or no value when malformed.
     */
    std::optional<std::uint64_t> parse_u64(std::string_view value) {
      std::uint64_t number = 0;
      if (value.empty()) {
        return std::nullopt;
      }
      const auto [end, ec] = std::from_chars(value.data(), value.data() + value.size(), number);
      if (ec != std::errc {} || end != value.data() + value.size()) {
        return std::nullopt;
      }
      return number;
    }

    /**
     * @brief Look up an optional query parameter.
     *
     * @param request Request.
     * @param name Parameter name.
     * @return Value, or no value when absent.
     */
    std::optional<std::string_view> query_value(const request_t &request, std::string_view name) {
      const auto it = request.query.find(name);
      if (it == request.query.end()) {
        return std::nullopt;
      }
      return std::string_view {it->second};
    }

    /**
     * @brief Reply used when the module is stopping.
     *
     * @return 503 reply.
     */
    reply_t unavailable() {
      return reply_t::failure(503, "internal", "service is shutting down");
    }

    /**
     * @brief Convert a clipboard core result into a reply.
     *
     * @param result Core result.
     * @return Reply.
     */
    reply_t to_reply(clipboard::result_t result) {
      reply_t reply;
      reply.status = result.status;
      reply.error = std::move(result.error);
      reply.message = std::move(result.message);
      if (result.status == 200 || result.status == 204 || result.status == 410) {
        reply.headers.emplace_back("X-SDS-Host-Seq", std::to_string(result.host_seq));
      }
      if (result.status == 200) {
        reply.content_type = std::move(result.content_type);
        reply.body = std::move(result.body);
      }
      return reply;
    }

    /**
     * @brief Default client lookup through the nvhttp paired-client store.
     *
     * @param cert Certificate PEM.
     * @return Client, or no value when unknown, duplicated or disabled.
     */
    std::optional<client_t> find_paired_client(std::string_view cert) {
      auto info = nvhttp::find_enabled_client(cert);
      if (!info) {
        return std::nullopt;
      }
      client_t client;
      client.cert = std::string {cert};
      client.uuid = std::move(info->uuid);
      client.name = std::move(info->name);
      client.permissions = to_permission_set(info->permissions);
      return client;
    }

    /**
     * @brief Request jobs and retained payload bytes charged to one budget.
     */
    struct pending_usage_t {
      std::size_t jobs = 0;  ///< Queued or executing jobs.
      std::size_t bytes = 0;  ///< Retained request-body capacity.
    };

    /**
     * @brief Shared admission state across the clipboard and file workers.
     */
    struct pending_state_t {
      std::mutex mutex;  ///< Protects usage.
      pending_usage_t total;  ///< Runtime-wide usage.
      std::map<std::string, pending_usage_t, std::less<>> clients;  ///< Per-client usage.
    };

    /**
     * @brief Releases admission after execution, exceptions or a rejected worker post.
     */
    struct pending_reservation_t {
      std::shared_ptr<pending_state_t> state;  ///< State outlives every retained job.
      std::string cert;  ///< Charged client.
      std::size_t bytes = 0;  ///< Charged body capacity.
      bool admitted = false;  ///< Set only after the counters were incremented.

      /**
       * @brief Return both the global and client reservation exactly once.
       */
      ~pending_reservation_t() {
        if (!admitted) {
          return;
        }
        std::lock_guard lock {state->mutex};
        --state->total.jobs;
        state->total.bytes -= bytes;
        const auto it = state->clients.find(cert);
        --it->second.jobs;
        it->second.bytes -= bytes;
        if (it->second.jobs == 0) {
          state->clients.erase(it);
        }
      }
    };

    /**
     * @brief Why queued work lost the authority captured at admission.
     */
    enum class authority_e {
      current,  ///< The original stream and client authority are still valid.
      stream_ended,  ///< The last stream ended, even if a later stream reconnects.
      client_changed,  ///< Pairing, enabled state or permissions changed.
    };

    using authority_t = std::shared_ptr<std::atomic<authority_e>>;  ///< Revocable authority of admitted jobs.

    /**
     * @brief Module state between start() and stop().
     */
    class runtime_t {
    public:
      /**
       * @brief Create the cores and start the worker threads.
       *
       * @param options Configuration.
       * @param deps Collaborators.
       */
      runtime_t(options_t options, dependencies_t deps):
          options_(std::move(options)),
          deps_(std::move(deps)),
          clipboard_rate_(options_.clipboard_rate),
          events_(options_.event_queue_max) {
        if (!deps_.stream_active) {
          deps_.stream_active = rtsp_stream::has_running_session;
        }
        if (!deps_.tile_refinement_active) {
          deps_.tile_refinement_active = rtsp_stream::has_tile_refinement_session;
        }
        if (!deps_.any_tile_refinement_active) {
          deps_.any_tile_refinement_active = rtsp_stream::any_tile_refinement_session;
        }
        if (!deps_.find_client) {
          deps_.find_client = find_paired_client;
        }
        if (!deps_.make_clipboard_backend) {
          deps_.make_clipboard_backend = take_or_make_backend;
        }
        if (!deps_.stage_file_clipboard) {
          deps_.stage_file_clipboard = file_clipboard::stage;
        }

        std::unique_ptr<clipboard::backend_t> backend;
        if (options_.clipboard) {
          backend = deps_.make_clipboard_backend();
        }
        BOOST_LOG(info) << "sds: clipboard "sv << (!options_.clipboard ? "disabled"sv : backend ? backend->name() :
                                                                                                  "unavailable (no backend)"sv)
                        << ", file transfer "sv << (options_.file_transfer ? "enabled"sv : "disabled"sv);

        control_ = std::make_unique<worker_t>("sds");
        io_ = std::make_unique<worker_t>("sds-io");
        if (options_.tile_refinement) {
          tile_refiner_ = std::make_unique<tile_refiner_t>(
            true,
            [this](tile_refiner_t::clock::time_point when) {
              if (!shut_down_.load(std::memory_order_acquire) && control_) {
                control_->post_at(when, [this]() {
                  if (!shut_down_.load(std::memory_order_acquire) && tile_refiner_) {
                    tile_refiner_->flush_waiting(tile_refiner_t::clock::now());
                  }
                });
              }
            }
          );
        }
        refresh_tile_refinement_active();

        clipboard::hooks_t hooks;
        hooks.publish = [this](const std::string &client, nlohmann::json event) {
          publish_if_active(client, std::move(event), "clipboard");
        };
        hooks.retract = [this](const std::string &client) {
          events_.retract(client, "clipboard");
        };
        hooks.readers = [this]() {
          return active_with(permission_e::clipboard_read);
        };
        hooks.post = [this](std::function<void()> job) {
          return control_->post(std::move(job));
        };
        hooks.intercept_host_offer = [this](clipboard::item_t &item, bool initial_scan) {
          return handle_host_lazy_offer(item, initial_scan);
        };
        if (options_.file_clipboard && backend && backend->supports_file_clipboard()) {
          file_clipboard_backend_ = backend.get();
        }
        clipboard_ = std::make_unique<clipboard::core_t>(
          std::move(backend),
          clipboard::limits_t {options_.clipboard_text_max, options_.clipboard_image_max},
          options_.clipboard_read_timeout,
          options_.coalesce_window,
          std::move(hooks)
        );
        files_ = std::make_unique<files::manager_t>(options_.files);

        auth_.find_client = [this](std::string_view cert) {
          return deps_.find_client(cert);
        };
        auth_.feature_available = [this](feature_e feature) {
          return feature_available(feature);
        };
        auth_.stream_active = [this](std::string_view cert) {
          return deps_.stream_active(cert);
        };
        auth_.clipboard_rate = &clipboard_rate_;
        auth_.open_uploads = [this](std::string_view cert) {
          return files_->open_uploads(cert) + open_drops(cert);
        };
        auth_.uploads_max = options_.files.uploads_max;
        auth_.clipboard_text_max = options_.clipboard_text_max;
        auth_.clipboard_image_max = options_.clipboard_image_max;
        auth_.chunk_max = options_.files.chunk_max;

        schedule_idle_check();
      }

      /**
       * @brief Shut down (idempotent).
       */
      ~runtime_t() {
        shutdown();
      }

      runtime_t(const runtime_t &) = delete;
      runtime_t &operator=(const runtime_t &) = delete;

      /**
       * @brief Release every parked response and partial upload and join the workers.
       */
      void shutdown() {
        if (shut_down_.exchange(true)) {
          return;
        }
        tile_refinement_enabled_atomic.store(false, std::memory_order_release);
        if (tile_refiner_) {
          tile_refiner_->shutdown();
        }
        events_.shutdown();
        control_->post([this]() {
          reset_file_clipboard();
          retire_all_lazy_offers();
          clipboard_->shutdown();
        });
        io_->post([this]() {
          files_->shutdown();
          clear_all_drops();
        });
        control_->stop();
        io_->stop();
        if (tile_refiner_) {
          tile_refiner_->shutdown();
        }
        retire_all_lazy_offers();
        clear_all_drops();
        clipboard_->shutdown();
        files_->shutdown();
        events_.shutdown();
      }

      /**
       * @brief Options in effect.
       *
       * @return Options.
       */
      const options_t &options() const {
        return options_;
      }

      /**
       * @brief Global switch plus backend availability of a feature.
       *
       * @param feature Feature.
       * @return `true` when usable.
       */
      bool feature_available(feature_e feature) const {
        switch (feature) {
          case feature_e::clipboard:
            return options_.clipboard && clipboard_->available();
          case feature_e::files:
            return options_.file_transfer;
          case feature_e::file_clipboard:
            return file_clipboard_backend_ && options_.clipboard && options_.file_transfer;
          case feature_e::mic:
            return options_.mic_passthrough && mic_available.load();
          case feature_e::tile_refinement:
            return options_.tile_refinement && tile_refiner_ != nullptr;
        }
        return false;
      }

      /**
       * @brief Features for `/serverinfo`.
       *
       * @return Comma-separated list.
       */
      std::string features() const {
        std::string out;
        const auto add = [&out](std::string_view name) {
          if (!out.empty()) {
            out.push_back(',');
          }
          out += name;
        };
        if (feature_available(feature_e::clipboard)) {
          add("clipboard"sv);
        }
        if (feature_available(feature_e::files)) {
          add("files"sv);
        }
        if (feature_available(feature_e::file_clipboard)) {
          add("file_clipboard"sv);
        }
        if (feature_available(feature_e::mic)) {
          add("mic"sv);
        }
        return out;
      }

      /**
       * @brief Authorize and dispatch a request.
       *
       * @param op Operation.
       * @param request Request.
       * @param respond Completion callback.
       */
      void handle(op_e op, request_t request, reply_fn respond) {
        if (op == op_e::file_clipboard_get && !request.query.contains("after")) {
          op = op_e::file_clipboard_baseline;
        }
        const auto authority = request.cert_pem ? request_authority(*request.cert_pem) : authority_t {};
        request_view_t view;
        view.cert_pem = request.cert_pem;
        view.body_size = request.body.size();
        view.content_type = request.content_type;
        if (op == op_e::outbox_read || op == op_e::clipboard_offer_entry_read) {
          if (const auto length = query_value(request, "length"); length) {
            view.range_length = parse_u64(*length);
          }
        }

        auto auth = authorize(auth_, view, op);
        if (!auth.ok()) {
          if (request.cert_pem) {
            release_unused_authority(*request.cert_pem, authority);
          }
          auto reply = reply_t::failure(auth.status, std::move(auth.error), std::move(auth.message));
          if (auth.retry_after) {
            reply.headers.emplace_back("Retry-After", std::to_string(*auth.retry_after));
          }
          respond(std::move(reply));
          return;
        }
        const auto client = std::move(auth.client);

        switch (op) {
          case op_e::capabilities:
            respond(capabilities(client));
            return;
          case op_e::events:
            poll_events(client, request, std::move(respond));
            return;
          case op_e::tile_refinement:
            poll_tile_refinement(client, request, std::move(respond));
            return;
          case op_e::clipboard_get:
            clipboard_get(client, request, authority, std::move(respond));
            return;
          case op_e::clipboard_put:
            clipboard_put(client, std::move(request), authority, std::move(respond));
            return;
          case op_e::file_clipboard_baseline:
          case op_e::file_clipboard_get:
          case op_e::file_clipboard_put:
            handle_file_clipboard(op, client, std::move(request), authority, std::move(respond));
            return;
          case op_e::clipboard_offer_put:
            handle_clipboard_offer_put(client, std::move(request), authority, std::move(respond));
            return;
          case op_e::clipboard_offer_entry_start:
          case op_e::clipboard_offer_entry_chunk:
          case op_e::clipboard_offer_complete:
          case op_e::clipboard_offer_cancel:
          case op_e::clipboard_offer_entry_read:
            handle_clipboard_offer_entry_op(op, client, std::move(request), authority, std::move(respond));
            return;
          case op_e::upload_create:
          case op_e::upload_chunk:
          case op_e::upload_complete:
          case op_e::upload_cancel:
          case op_e::outbox_list:
          case op_e::outbox_read:
            file_op(op, client, std::move(request), authority, std::move(respond));
            return;
          case op_e::drop_create:
          case op_e::drop_chunk:
          case op_e::drop_complete:
          case op_e::drop_cancel:
            handle_drop_op(op, client, std::move(request), authority, std::move(respond));
            return;
        }
        respond(reply_t::failure(404, "not_found", "unknown operation"));
      }

      /**
       * @brief Queue a stream start/stop for the control worker.
       *
       * @param cert Client certificate.
       * @param running Stream state.
       */
      void stream_state(std::string cert, bool running) {
        if (!running) {
          // New request capture uses the same mutex: its work cannot enter I/O ahead of
          // cleanup belonging to the stream that just ended. Never wait for a worker here.
          std::lock_guard lock {authority_mutex_};
          invalidate_authority_locked(cert, authority_e::stream_ended);
          io_->post([this, cert]() {
            files_->end_client(cert);
            end_drops_for_client(cert);
          });
          control_->post([this, cert = std::move(cert)]() {
            retire_lazy_offers_for_client(cert);
            handle_stream_state(cert, false);
          });
          return;
        }
        control_->post([this, cert = std::move(cert), running]() {
          handle_stream_state(cert, running);
        });
      }

      /**
       * @brief Queue a permission/enable change for the control worker.
       *
       * @param cert Client certificate.
       */
      void client_changed(std::string cert) {
        invalidate_authority(cert, authority_e::client_changed);
        control_->post([this, cert = std::move(cert)]() {
          handle_client_changed(cert);
        });
      }

      /**
       * @brief Wait for queued work on both workers (they may post to each other).
       */
      void drain() {
        for (int round = 0; round < 3; ++round) {
          control_->drain();
          io_->drain();
        }
      }

      /**
       * @brief Queue a job on the file worker (tests).
       *
       * @param job Job.
       * @return `false` when stopping.
       */
      bool post_io(std::function<void()> job) {
        return io_->post(std::move(job));
      }

      /**
       * @brief Queue a job on the clipboard worker (tests).
       *
       * @param job Job.
       * @return `false` when stopping.
       */
      bool post_control(std::function<void()> job) {
        return control_->post(std::move(job));
      }

      /**
       * @brief Internal state for tests.
       *
       * @param cert Client certificate.
       * @return State.
       */
      test_state_t test_state(const std::string &cert) {
        drain();
        test_state_t state;
        state.running = true;
        state.open_uploads = files_->open_uploads(cert);
        state.queued_events = events_.queued(cert);
        state.parked_poll = events_.parked(cert);
        state.event_state = events_.has_client(cert);
        state.rate_bucket = clipboard_rate_.tracked(cert);
        {
          std::lock_guard lock {active_mutex_};
          state.active = active_.contains(cert);
        }
        std::promise<void> done;
        auto future = done.get_future();
        if (control_->post([&]() {
              state.clipboard_watching = clipboard_->watching();
              state.clipboard_content = clipboard_->has_content();
              state.clipboard_seq = clipboard_->seq();
              state.file_clipboard_leases = file_clipboard_leases_.size();
              done.set_value();
            })) {
          future.wait();
        }
        return state;
      }

    private:
      /**
       * @brief Reserve bounded request work; internal lifecycle jobs bypass this budget.
       *
       * @param cert Paired client.
       * @param bytes Retained body capacity.
       * @return Reservation, or null when the global or client budget is full.
       */
      std::shared_ptr<pending_reservation_t> reserve_work(const std::string &cert, std::size_t bytes) {
        constexpr std::size_t GLOBAL_JOBS = 32;
        constexpr std::size_t GLOBAL_BYTES = 128 * 1024 * 1024;
        constexpr std::size_t CLIENT_JOBS = 4;
        constexpr std::size_t CLIENT_BYTES = 64 * 1024 * 1024;
        auto reservation = std::make_shared<pending_reservation_t>();
        reservation->state = pending_;
        reservation->cert = cert;
        reservation->bytes = bytes;
        std::lock_guard lock {pending_->mutex};
        const auto found = pending_->clients.find(cert);
        const auto client = found == pending_->clients.end() ? pending_usage_t {} : found->second;
        if (pending_->total.jobs >= GLOBAL_JOBS || client.jobs >= CLIENT_JOBS || bytes > GLOBAL_BYTES - pending_->total.bytes || bytes > CLIENT_BYTES - client.bytes) {
          return nullptr;
        }
        auto &usage = pending_->clients[cert];
        ++usage.jobs;
        usage.bytes += bytes;
        ++pending_->total.jobs;
        pending_->total.bytes += bytes;
        reservation->admitted = true;
        return reservation;
      }

      /**
       * @brief Get the revocable authority shared by currently admitted client requests.
       *
       * @param cert Paired client.
       * @return Authority retained by deferred work.
       */
      authority_t request_authority(const std::string &cert) {
        std::lock_guard lock {authority_mutex_};
        auto &authority = authorities_[cert];
        if (!authority) {
          authority = std::make_shared<std::atomic<authority_e>>(authority_e::current);
        }
        return authority;
      }

      /**
       * @brief Forget unused authority from a rejected request without retaining unknown identities.
       *
       * @param cert Certificate supplied by the request.
       * @param authority Provisional request authority.
       */
      void release_unused_authority(const std::string &cert, const authority_t &authority) {
        std::lock_guard lock {authority_mutex_};
        const auto found = authorities_.find(cert);
        if (found != authorities_.end() && found->second == authority && authority.use_count() == 2) {
          authorities_.erase(found);
        }
      }

      /**
       * @brief Invalidate old jobs synchronously before queueing lifecycle cleanup.
       *
       * @param cert Client certificate.
       * @param reason Stream end or client change.
       */
      void invalidate_authority(const std::string &cert, authority_e reason) {
        std::lock_guard lock {authority_mutex_};
        invalidate_authority_locked(cert, reason);
      }

      /**
       * @brief Revoke authority while its caller holds authority_mutex_.
       *
       * @param cert Client certificate.
       * @param reason Stream end or client change.
       */
      void invalidate_authority_locked(const std::string &cert, authority_e reason) {
        const auto found = authorities_.find(cert);
        if (found != authorities_.end()) {
          found->second->store(reason);
          authorities_.erase(found);
        }
      }

      /**
       * @brief Revalidate live authorization and the original authority without charging limits again.
       *
       * @param cert Client certificate.
       * @param op Operation.
       * @param authority Authority captured at admission.
       * @return Failure reply, or no value when the side effect may proceed.
       */
      std::optional<reply_t> deferred_failure(const std::string &cert, op_e op, const authority_t &authority) {
        if (shut_down_) {
          return unavailable();
        }
        request_view_t view;
        view.cert_pem = cert;
        auto auth = authorize(auth_, view, op, false);
        if (!auth.ok()) {
          return reply_t::failure(auth.status, std::move(auth.error), std::move(auth.message));
        }
        switch (authority->load()) {
          case authority_e::stream_ended:
            return reply_t::failure(409, "no_active_stream", "request belongs to an ended stream");
          case authority_e::client_changed:
            return reply_t::failure(403, "forbidden", "client authorization changed after admission");
          case authority_e::current:
            return std::nullopt;
        }
        return reply_t::failure(403, "forbidden", "invalid request authority");
      }

      /**
       * @brief Reply when a bounded worker queue cannot retain more requests.
       *
       * @param respond Completion callback.
       */
      static void admission_rejected(const reply_fn &respond) {
        auto reply = reply_t::failure(429, "rate_limited", "too much pending work");
        reply.headers.emplace_back("Retry-After", "1");
        respond(std::move(reply));
      }

      /**
       * @brief Queue an event only while the client's stream is tracked as active.
       *
       * Holding active_mutex_ serializes this with stream-end cleanup, so no event state can be
       * recreated for a client whose stream just ended.
       *
       * @param cert Client certificate.
       * @param event Event.
       * @param key Coalescing key.
       */
      void publish_if_active(const std::string &cert, nlohmann::json event, std::string_view key) {
        std::lock_guard lock {active_mutex_};
        if (active_.contains(cert)) {
          events_.publish(cert, std::move(event), key);
        }
      }

      /**
       * @brief Active clients holding a permission.
       *
       * @param permission Permission.
       * @return Client certificates.
       */
      std::vector<std::string> active_with(permission_e permission) const {
        std::vector<std::string> certs;
        {
          std::lock_guard lock {active_mutex_};
          certs.assign(active_.begin(), active_.end());
        }
        std::erase_if(certs, [this, permission](const std::string &cert) {
          const auto client = deps_.find_client(cert);
          return !client || !client->permissions.test(static_cast<std::size_t>(permission));
        });
        return certs;
      }

      /**
       * @brief Build the capabilities reply.
       *
       * @param client Caller.
       * @return Reply.
       */
      reply_t capabilities(const client_t &client) const {
        nlohmann::json features = nlohmann::json::array();
        for (const auto &[feature, name] : {std::pair {feature_e::clipboard, "clipboard"sv}, std::pair {feature_e::files, "files"sv}, std::pair {feature_e::file_clipboard, "file_clipboard"sv}, std::pair {feature_e::mic, "mic"sv}}) {
          if (feature_available(feature)) {
            features.push_back(name);
            if (feature == feature_e::file_clipboard) {
              features.push_back("lazy_clipboard"sv);
            }
          }
        }
        const auto feature_of = [](permission_e permission) {
          switch (permission) {
            case permission_e::clipboard_read:
            case permission_e::clipboard_write:
              return feature_e::clipboard;
            case permission_e::file_upload:
            case permission_e::file_download:
              return feature_e::files;
            default:
              return feature_e::mic;
          }
        };
        nlohmann::json permissions = nlohmann::json::array();
        for (std::size_t index = 0; index < static_cast<std::size_t>(permission_e::count); ++index) {
          const auto permission = static_cast<permission_e>(index);
          if (client.permissions.test(index) && feature_available(feature_of(permission))) {
            permissions.push_back(permission_name(permission));
          }
        }
        nlohmann::json body {
          {"version", PROTOCOL_VERSION},
          {"features", std::move(features)},
          {"permissions", std::move(permissions)},
          {"limits",
           {
             {"clipboard_text_max", options_.clipboard_text_max},
             {"clipboard_image_max", options_.clipboard_image_max},
             {"file_max", options_.files.file_max},
             {"chunk_max", options_.files.chunk_max},
             {"uploads_max_concurrent", options_.files.uploads_max},
           }},
          {"stream_active", true},
        };
        return reply_t::success(200, std::move(body));
      }

      /**
       * @brief `GET /sds/v1/events`.
       *
       * @param client Caller.
       * @param request Request.
       * @param respond Completion callback.
       */
      void poll_events(const client_t &client, const request_t &request, reply_fn respond) {
        std::uint64_t after = 0;
        if (const auto value = query_value(request, "after"); value) {
          const auto parsed = parse_u64(*value);
          if (!parsed) {
            respond(reply_t::failure(400, "bad_request", "invalid after"));
            return;
          }
          after = *parsed;
        }
        auto timeout = options_.poll_default;
        if (const auto value = query_value(request, "timeout"); value) {
          const auto seconds = parse_u64(*value);
          if (!seconds) {
            respond(reply_t::failure(400, "bad_request", "invalid timeout"));
            return;
          }
          timeout = std::chrono::milliseconds {std::min<std::uint64_t>(*seconds, 3600) * 1000};
        }
        timeout = std::min(timeout, options_.poll_max);

        std::optional<event_hub_t::clock::time_point> deadline;
        if (timeout.count() > 0) {
          deadline = event_hub_t::clock::now() + timeout;
        }
        auto responder = [respond](int status, std::string body) {
          reply_t reply;
          reply.status = status;
          reply.content_type = "application/json";
          reply.body = std::move(body);
          respond(std::move(reply));
        };
        if (!events_.poll(client.cert, after, deadline, std::move(responder))) {
          return;
        }
        if (!control_->post_at(*deadline, [this]() {
              events_.expire(event_hub_t::clock::now());
            })) {
          events_.end_stream(client.cert);
          return;
        }
        // The stream may have stopped between authorization and parking; its stop job could have
        // run already, so re-check now that the poll is visible to end_stream().
        if (!deps_.stream_active(client.cert)) {
          events_.end_stream(client.cert);
        }
      }

      /**
       * @brief `GET /sds/v1/tile-refinement`.
       *
       * @param client Caller.
       * @param request Request.
       * @param respond Completion callback.
       */
      void poll_tile_refinement(const client_t &client, const request_t &request, reply_fn respond) {
        if (!tile_refiner_) {
          respond(reply_t::failure(404, "not_found", "feature not available"));
          return;
        }
        if (!deps_.tile_refinement_active || !deps_.tile_refinement_active(client.cert)) {
          respond(reply_t::failure(409, "no_active_stream", "no active tile refinement stream for this client"));
          return;
        }
        auto timeout = std::min(options_.poll_default, std::chrono::milliseconds {25000});
        if (const auto value = query_value(request, "timeout"); value) {
          const auto seconds = parse_u64(*value);
          if (!seconds) {
            respond(reply_t::failure(400, "bad_request", "invalid timeout"));
            return;
          }
          timeout = std::chrono::milliseconds {std::min<std::uint64_t>(*seconds, 25) * 1000};
        }
        timeout = std::min(timeout, options_.poll_max);

        const auto now = tile_refiner_t::clock::now();
        std::optional<tile_refiner_t::clock::time_point> deadline;
        if (timeout.count() > 0) {
          deadline = now + timeout;
        }
        auto responder = [respond](int status, std::string body) {
          reply_t reply;
          if (status == 200) {
            reply.status = 200;
            reply.content_type = "application/octet-stream";
            reply.body = std::move(body);
          } else if (status == 409) {
            reply = reply_t::failure(409, "no_active_stream", "no active tile refinement stream for this client");
          } else if (status == 503) {
            reply = reply_t::failure(503, "internal", "service shutting down");
          } else {
            reply.status = status;
          }
          respond(std::move(reply));
        };
        if (!tile_refiner_->poll_at(client.cert, deadline, now, std::move(responder))) {
          return;
        }
        if (!control_->post_at(*deadline, [this]() {
              if (!shut_down_.load(std::memory_order_acquire) && tile_refiner_) {
                tile_refiner_->expire(tile_refiner_t::clock::now());
              }
            })) {
          tile_refiner_->end_stream(client.cert);
          return;
        }
        if (!deps_.stream_active(client.cert) || !deps_.tile_refinement_active(client.cert)) {
          tile_refiner_->end_stream(client.cert);
        }
      }

      /**
       * @brief `GET /sds/v1/clipboard`.
       *
       * @param client Caller.
       * @param request Request.
       * @param authority Authority captured before initial authorization.
       * @param respond Completion callback.
       */
      void clipboard_get(const client_t &client, const request_t &request, const authority_t &authority, reply_fn respond) {
        std::optional<std::uint64_t> seq;
        if (const auto value = query_value(request, "seq"); value) {
          seq = parse_u64(*value);
          if (!seq) {
            respond(reply_t::failure(400, "bad_request", "invalid seq"));
            return;
          }
        }
        const auto type_value = query_value(request, "type");
        const auto type = type_value ? clipboard::parse_type(parse_content_type(*type_value).first) : std::nullopt;
        if (!type) {
          respond(reply_t::failure(400, "bad_request", "type must be text/plain or image/png"));
          return;
        }
        const auto reservation = reserve_work(client.cert, 0);
        if (!reservation) {
          admission_rejected(respond);
          return;
        }
        if (!control_->post([this, cert = client.cert, seq, type = *type, authority, reservation, respond]() {
              if (auto failure = deferred_failure(cert, op_e::clipboard_get, authority)) {
                respond(std::move(*failure));
                return;
              }
              respond(to_reply(clipboard_->get(cert, seq, type)));
            })) {
          respond(unavailable());
        }
      }

      /**
       * @brief `PUT /sds/v1/clipboard`.
       *
       * @param client Caller.
       * @param request Request (body moved).
       * @param authority Authority captured before initial authorization.
       * @param respond Completion callback.
       */
      void clipboard_put(const client_t &client, request_t request, const authority_t &authority, reply_fn respond) {
        const auto reservation = reserve_work(client.cert, request.body.capacity());
        if (!reservation) {
          admission_rejected(respond);
          return;
        }
        if (!control_->post([this, cert = client.cert, content_type = std::move(request.content_type), client_seq = std::move(request.client_seq), body = std::move(request.body), authority, reservation, respond]() mutable {
              if (auto failure = deferred_failure(cert, op_e::clipboard_put, authority)) {
                respond(std::move(*failure));
                return;
              }
              respond(to_reply(clipboard_->put(cert, content_type, std::move(body), client_seq)));
            })) {
          respond(unavailable());
        }
      }

      struct file_clipboard_session_t {
        std::string cert;
        std::string epoch;
        std::uint64_t floor;
      };

      bool only_file_clipboard_stream(const std::string &cert) const {
        const std::lock_guard lock {active_mutex_};
        return active_.size() == 1 && active_.contains(cert);
      }

      void reset_file_clipboard() {
        file_clipboard_session_.reset();
        if (file_clipboard_owned_) {
          const auto previous = *file_clipboard_owned_;
          file_clipboard_backend_->retire_file_clipboard(previous);
          file_clipboard_owned_.reset();
          if (shut_down_) {
            file_clipboard_leases_.clear();
          } else {
            control_->post_at(worker_t::clock::now() + options_.file_clipboard_lease_grace, [this, previous]() {
              file_clipboard_leases_.erase(previous);
            });
          }
        }
        // Keep the small, private lease until its timer fires: a file manager can
        // have already requested the URI and still be reading the staged bytes.
      }

      static reply_t stale_file_clipboard() {
        return reply_t::failure(409, "clipboard_conflict", "file clipboard has changed or the stream ended");
      }

      static reply_t file_clipboard_reply(std::string_view epoch, std::uint64_t seq, std::optional<nlohmann::json> bundle = std::nullopt) {
        reply_t result;
        result.status = bundle ? 200 : 204;
        result.json = std::move(bundle);
        result.headers.emplace_back("X-SDS-Clipboard-Seq", std::to_string(seq));
        result.headers.emplace_back("X-SDS-Clipboard-Epoch", epoch);
        return result;
      }

      void handle_file_clipboard(op_e op, const client_t &client, request_t request, const authority_t &authority, reply_fn respond) {
        const bool put = op == op_e::file_clipboard_put;
        const bool baseline = op == op_e::file_clipboard_baseline;
        const auto after = query_value(request, "after");
        const auto seq = put ? parse_u64(request.file_clipboard_seq) : after ? parse_u64(*after) : std::nullopt;
        if ((!put && !request.body.empty()) || request.query.size() != (after ? 1u : 0u) ||
            (put && after) || (!baseline && !seq) ||
            (!put && !request.file_clipboard_seq.empty()) ||
            (baseline ? !request.file_clipboard_epoch.empty() : !files::is_id(request.file_clipboard_epoch))) {
          respond(reply_t::failure(400, "bad_request", "invalid file clipboard request"));
          return;
        }
        if (put && parse_content_type(request.content_type).first != "application/json") {
          respond(reply_t::failure(415, "unsupported_media_type", "file clipboard requires application/json"));
          return;
        }
        const auto reservation = reserve_work(client.cert, put ? request.body.capacity() : baseline ? 0 : file_clipboard::wire_max);
        if (!reservation) {
          admission_rejected(respond);
          return;
        }
        if (!control_->post([this, op, put, baseline, cert = client.cert, seq, epoch = std::move(request.file_clipboard_epoch), body = std::move(request.body), authority, reservation, respond]() mutable {
              if (auto failure = deferred_failure(cert, op, authority)) {
                respond(std::move(*failure));
                return;
              }
              if (!only_file_clipboard_stream(cert)) {
                respond(stale_file_clipboard());
                return;
              }
              const auto before = file_clipboard_backend_->file_clipboard_generation();
              if (!before) {
                respond(unavailable());
                return;
              }
              if (baseline) {
                if (auto failure = deferred_failure(cert, op, authority)) {
                  respond(std::move(*failure));
                  return;
                }
                if (!file_clipboard_session_ || file_clipboard_session_->cert != cert) {
                  auto token = file_clipboard::new_epoch();
                  if (!token) {
                    respond(unavailable());
                    return;
                  }
                  file_clipboard_session_ = file_clipboard_session_t {cert, std::move(*token), *before};
                } else {
                  file_clipboard_session_->floor = *before;
                }
                respond(file_clipboard_reply(file_clipboard_session_->epoch, *before));
                return;
              }
              if (!file_clipboard_session_ || file_clipboard_session_->cert != cert || file_clipboard_session_->epoch != epoch ||
                  *seq < file_clipboard_session_->floor || *seq > *before || (put && *seq != *before)) {
                respond(stale_file_clipboard());
                return;
              }
              if (!put && *seq == *before) {
                respond(file_clipboard_reply(epoch, *before));
                return;
              }
              if (put && file_clipboard_leases_.size() >= 4) {
                admission_rejected(respond);
                return;
              }
              std::optional<clipboard::item_t> item;
              if (!put) {
                item = file_clipboard_backend_->read(clipboard::limits_t {0, 0, true}, options_.clipboard_read_timeout);
                if (file_clipboard_backend_->file_clipboard_generation() != before) {
                  respond(stale_file_clipboard());
                  return;
                }
                if (!item || !item->file_offer) {
                  if (auto failure = deferred_failure(cert, op, authority)) {
                    respond(std::move(*failure));
                  } else {
                    respond(file_clipboard_reply(epoch, *before));
                  }
                  return;
                }
              }
              if (!io_->post([this, op, put, cert, epoch, before = *before, authority, body = std::move(body), item = std::move(item), reservation, respond]() {
                    const auto allowed = [&]() {
                      return !deferred_failure(cert, op, authority) && only_file_clipboard_stream(cert);
                    };
                    if (!allowed()) {
                      respond(stale_file_clipboard());
                      return;
                    }
                    auto staged = put ? deps_.stage_file_clipboard(body, allowed) : nullptr;
                    auto bundle = !put ? file_clipboard::read_offer(*item->file_offer, allowed) : std::nullopt;
                    if (!control_->post([this, op, put, cert, epoch, before, authority, staged = std::move(staged), bundle = std::move(bundle), reservation, respond]() mutable {
                          if (auto failure = deferred_failure(cert, op, authority)) {
                            respond(std::move(*failure));
                            return;
                          }
                          if (!only_file_clipboard_stream(cert) || !file_clipboard_session_ || file_clipboard_session_->epoch != epoch ||
                              before < file_clipboard_session_->floor || file_clipboard_backend_->file_clipboard_generation() != before) {
                            respond(stale_file_clipboard());
                            return;
                          }
                          if (!put) {
                            if (auto failure = deferred_failure(cert, op, authority)) {
                              respond(std::move(*failure));
                            } else {
                              respond(file_clipboard_reply(epoch, before, std::move(bundle)));
                            }
                            return;
                          }
                          if (!staged) {
                            respond(reply_t::failure(422, "invalid_file_bundle", "file bundle cannot be safely staged"));
                            return;
                          }
                          if (file_clipboard_leases_.size() >= 4) {
                            admission_rejected(respond);
                            return;
                          }
                          const auto committed = file_clipboard_backend_->publish_file_clipboard(before, std::string {file_clipboard::native_offer(*staged)}, [this, cert, op, authority]() {
                            return !deferred_failure(cert, op, authority) && only_file_clipboard_stream(cert);
                          });
                          if (!committed) {
                            respond(stale_file_clipboard());
                            return;
                          }
                          if (file_clipboard_owned_) {
                            control_->post_at(worker_t::clock::now() + options_.file_clipboard_lease_grace, [this, previous = *file_clipboard_owned_]() {
                              file_clipboard_leases_.erase(previous);
                            });
                          }
                          file_clipboard_owned_ = *committed;
                          file_clipboard_leases_.emplace(*committed, std::move(staged));
                          control_->post_at(worker_t::clock::now() + options_.file_clipboard_lease_ttl, [this, seq = *committed]() {
                            if (file_clipboard_owned_ == seq) {
                              file_clipboard_backend_->retire_file_clipboard(seq);
                              file_clipboard_owned_.reset();
                            }
                            file_clipboard_leases_.erase(seq);
                          });
                          if (auto failure = deferred_failure(cert, op, authority)) {
                            reset_file_clipboard();
                            respond(std::move(*failure));
                            return;
                          }
                          respond(file_clipboard_reply(epoch, *committed));
                        })) {
                      respond(unavailable());
                    }
                  })) {
                respond(unavailable());
              }
            })) {
          respond(unavailable());
        }
      }

      /**
       * @brief Upload and outbox operations on the file worker.
       *
       * @param op Operation.
       * @param client Caller.
       * @param request Request (body moved).
       * @param authority Authority captured before initial authorization.
       * @param respond Completion callback.
       */
      void file_op(op_e op, const client_t &client, request_t request, const authority_t &authority, reply_fn respond) {
        std::optional<std::uint64_t> offset;
        std::optional<std::uint64_t> length;
        if (const auto value = query_value(request, "offset"); value) {
          offset = parse_u64(*value);
          if (!offset) {
            respond(reply_t::failure(400, "bad_request", "invalid offset"));
            return;
          }
        }
        if (const auto value = query_value(request, "length"); value && op == op_e::outbox_read) {
          length = parse_u64(*value);
          if (!length) {
            respond(reply_t::failure(400, "bad_request", "invalid length"));
            return;
          }
        }
        if (op != op_e::upload_create && op != op_e::outbox_list && !files::is_id(request.id)) {
          respond(reply_t::failure(404, "not_found", "unknown id"));
          return;
        }

        const auto reservation = reserve_work(client.cert, request.body.capacity());
        if (!reservation) {
          admission_rejected(respond);
          return;
        }
        if (!io_->post([this, op, cert = client.cert, id = std::move(request.id), body = std::move(request.body), offset, length, authority, reservation, respond]() {
              if (auto failure = deferred_failure(cert, op, authority)) {
                respond(std::move(*failure));
                return;
              }
              switch (op) {
                case op_e::upload_create:
                  respond(files_->create(cert, body));
                  return;
                case op_e::upload_chunk:
                  respond(files_->write_chunk(cert, id, offset, body));
                  return;
                case op_e::upload_complete:
                  respond(files_->complete(cert, id, [this, cert, authority]() {
                    return deferred_failure(cert, op_e::upload_complete, authority);
                  }));
                  return;
                case op_e::upload_cancel:
                  respond(files_->cancel(cert, id));
                  return;
                case op_e::outbox_list:
                  {
                    auto reply = files_->list_outbox();
                    if (auto failure = deferred_failure(cert, op, authority)) {
                      reply = std::move(*failure);
                    }
                    respond(std::move(reply));
                  }
                  return;
                case op_e::outbox_read:
                  {
                    auto reply = files_->read_outbox(id, offset.value_or(0), length);
                    if (auto failure = deferred_failure(cert, op, authority)) {
                      reply = std::move(*failure);
                    }
                    respond(std::move(reply));
                  }
                  return;
                default:
                  respond(reply_t::failure(404, "not_found", "unknown operation"));
                  return;
              }
            })) {
          respond(unavailable());
        }
      }

      /**
       * @brief Start or stop clipboard watching (control worker).
       */
      void refresh_clipboard_watching() {
        bool needed = false;
        if (feature_available(feature_e::clipboard)) {
          needed = !active_with(permission_e::clipboard_read).empty() || !active_with(permission_e::clipboard_write).empty();
        }
        clipboard_->set_watching(needed);
      }

      /**
       * @brief Apply a stream start or stop (control worker).
       *
       * @param cert Client certificate.
       * @param running Stream state.
       */
      void handle_stream_state(const std::string &cert, bool running) {
        if (running) {
          if (!deps_.stream_active(cert)) {
            return;
          }
          {
            std::lock_guard lock {active_mutex_};
            // Several sessions may share this certificate. Only the first
            // active notification should announce the current clipboard.
            if (!active_.insert(cert).second) {
              refresh_tile_refinement_active();
              return;
            }
          }
          refresh_tile_refinement_active();
          reset_file_clipboard();
          refresh_clipboard_watching();
          const auto client = deps_.find_client(cert);
          if (client && client->permissions.test(static_cast<std::size_t>(permission_e::clipboard_read)) && feature_available(feature_e::clipboard)) {
            clipboard_->announce_to(cert);
          }
          if (client && client->permissions.test(static_cast<std::size_t>(permission_e::file_download)) && feature_available(feature_e::files)) {
            io_->post([this]() {
              start_outbox_polling();
            });
          }
          return;
        }

        {
          std::lock_guard lock {active_mutex_};
          active_.erase(cert);
        }
        reset_file_clipboard();
        events_.end_stream(cert);
        if (tile_refiner_) {
          tile_refiner_->end_stream(cert);
        }
        refresh_tile_refinement_active();
        clipboard_rate_.forget(cert);
        clipboard_->forget_client(cert);
        refresh_clipboard_watching();
        BOOST_LOG(debug) << "sds: cleared state of a client whose stream ended"sv;
      }

      /**
       * @brief Apply a permission/enable change (control worker).
       *
       * @param cert Client certificate.
       */
      void handle_client_changed(const std::string &cert) {
        if (file_clipboard_session_ && file_clipboard_session_->cert == cert) reset_file_clipboard();
        const auto client = deps_.find_client(cert);
        const bool may_upload = client && client->permissions.test(static_cast<std::size_t>(permission_e::file_upload));
        const bool may_write_cb = client && client->permissions.test(static_cast<std::size_t>(permission_e::clipboard_write));
        if (!may_upload) {
          io_->post([this, cert]() {
            files_->end_client(cert);
            end_drops_for_client(cert);
          });
        }
        if (!may_upload || !may_write_cb) {
          retire_lazy_offers_for_client(cert);
        }
        bool active;
        {
          std::lock_guard lock {active_mutex_};
          active = active_.contains(cert);
        }
        if (!active) {
          return;
        }
        publish_if_active(cert, nlohmann::json {{"type", "capabilities"}}, "capabilities");
        refresh_clipboard_watching();
        if (client && client->permissions.test(static_cast<std::size_t>(permission_e::file_download))) {
          io_->post([this]() {
            start_outbox_polling();
          });
        }
      }

      struct lazy_offer_t {
        std::mutex mutex;
        std::string offer_id;
        std::string cert;
        bool from_client = false;
        std::string kind;
        std::string mime;
        std::uint64_t total_size = 0;
        std::shared_ptr<file_clipboard::chunk_stage_t> client_stage;
        std::vector<std::string> client_entry_order;
        std::map<std::string, staged_upload_entry_t> client_entries;
        bool completed = false;
        bool failed = false;
        std::optional<std::uint64_t> published_generation;
        std::map<std::string, file_clipboard::lazy_source_entry_t> host_entries;
        std::shared_ptr<const file_clipboard::stage_t> host_image_lease;
      };

      struct drop_session_t {
        std::mutex mutex;
        std::string id;
        std::string cert;
        double nx = 0.0;
        double ny = 0.0;
        std::uint64_t total_size = 0;
        std::shared_ptr<file_clipboard::chunk_stage_t> stage;
        std::vector<staged_upload_entry_t> entries;
        std::chrono::steady_clock::time_point touched_at = worker_t::clock::now();
      };

      std::vector<std::string> active_file_clipboard_readers() const {
        std::vector<std::string> certs;
        {
          std::lock_guard lock {active_mutex_};
          certs.assign(active_.begin(), active_.end());
        }
        std::erase_if(certs, [this](const std::string &cert) {
          const auto client = deps_.find_client(cert);
          return !client ||
                 !client->permissions.test(static_cast<std::size_t>(permission_e::clipboard_read)) ||
                 !client->permissions.test(static_cast<std::size_t>(permission_e::file_download));
        });
        return certs;
      }

      void retire_offer_object(const std::shared_ptr<lazy_offer_t> &offer) {
        if (!offer) {
          return;
        }
        {
          std::lock_guard lock {offer->mutex};
          offer->failed = true;
        }
        if (offer->from_client && file_clipboard_backend_) {
          file_clipboard_backend_->fail_lazy_offer(offer->offer_id);
          if (offer->published_generation) {
            file_clipboard_backend_->retire_file_clipboard(*offer->published_generation);
          }
        }
      }

      void retire_all_lazy_offers() {
        std::map<std::string, std::shared_ptr<lazy_offer_t>, std::less<>> old;
        {
          std::lock_guard lock {lazy_mutex_};
          old.swap(lazy_offers_);
        }
        for (const auto &[id, offer] : old) {
          retire_offer_object(offer);
        }
      }

      void retire_lazy_offers_for_client(std::string_view cert) {
        std::vector<std::shared_ptr<lazy_offer_t>> doomed;
        {
          std::lock_guard lock {lazy_mutex_};
          for (auto it = lazy_offers_.begin(); it != lazy_offers_.end();) {
            if (it->second->from_client && it->second->cert == cert) {
              doomed.push_back(it->second);
              it = lazy_offers_.erase(it);
            } else {
              ++it;
            }
          }
        }
        for (const auto &offer : doomed) {
          retire_offer_object(offer);
        }
      }

      void store_lazy_offer(std::shared_ptr<lazy_offer_t> offer) {
        std::vector<std::shared_ptr<lazy_offer_t>> evicted;
        {
          std::lock_guard lock {lazy_mutex_};
          if (offer->from_client) {
            for (auto it = lazy_offers_.begin(); it != lazy_offers_.end();) {
              if (it->second->from_client) {
                evicted.push_back(it->second);
                it = lazy_offers_.erase(it);
              } else {
                ++it;
              }
            }
          } else {
            std::size_t host_count = 0;
            std::optional<std::string> oldest_host_id;
            for (const auto &[id, existing] : lazy_offers_) {
              if (!existing->from_client) {
                ++host_count;
                if (!oldest_host_id) {
                  oldest_host_id = id;
                }
              }
            }
            if (host_count >= 4 && oldest_host_id) {
              if (auto it = lazy_offers_.find(*oldest_host_id); it != lazy_offers_.end()) {
                evicted.push_back(it->second);
                lazy_offers_.erase(it);
              }
            }
          }
          lazy_offers_.insert_or_assign(offer->offer_id, std::move(offer));
        }
        for (const auto &old : evicted) {
          retire_offer_object(old);
        }
      }

      std::shared_ptr<lazy_offer_t> find_lazy_offer(std::string_view offer_id) {
        std::lock_guard lock {lazy_mutex_};
        const auto it = lazy_offers_.find(offer_id);
        return it == lazy_offers_.end() ? nullptr : it->second;
      }

      bool handle_host_lazy_offer(clipboard::item_t &item, bool initial_scan) {
        if (!initial_scan) {
          std::vector<std::shared_ptr<lazy_offer_t>> client_offers;
          {
            std::lock_guard lock {lazy_mutex_};
            for (auto it = lazy_offers_.begin(); it != lazy_offers_.end();) {
              if (it->second->from_client) {
                client_offers.push_back(it->second);
                it = lazy_offers_.erase(it);
              } else {
                ++it;
              }
            }
          }
          for (const auto &old : client_offers) {
            retire_offer_object(old);
          }
        }

        if (initial_scan || !feature_available(feature_e::file_clipboard) || !file_clipboard_backend_) {
          return false;
        }

        const auto readers = active_file_clipboard_readers();
        if (item.file_offer) {
          if (readers.empty()) {
            return true;
          }
          auto sources = file_clipboard::capture_lazy_sources(*item.file_offer, options_.files.file_max);
          if (!sources || sources->empty()) {
            return true;
          }
          const auto offer_id = file_clipboard::new_epoch();
          if (!offer_id) {
            return true;
          }
          auto offer = std::make_shared<lazy_offer_t>();
          offer->offer_id = *offer_id;
          offer->from_client = false;
          offer->kind = "files";
          nlohmann::json entries_json = nlohmann::json::array();
          for (auto &src : *sources) {
            offer->total_size += src.size;
            entries_json.push_back({
              {"id", src.id},
              {"name", src.name},
              {"size", src.size},
            });
            offer->host_entries.emplace(src.id, std::move(src));
          }
          store_lazy_offer(offer);
          const nlohmann::json event {
            {"type", "clipboard_offer"},
            {"offer_id", *offer_id},
            {"kind", "files"},
            {"entries", std::move(entries_json)},
          };
          for (const auto &reader : readers) {
            publish_if_active(reader, event, "clipboard_offer");
          }
          return true;
        }

        if (item.png && item.png->size() > options_.lazy_image_threshold && !readers.empty()) {
          auto staged = file_clipboard::stage_host_image(*item.png, options_.files.min_free_space);
          const auto offer_id = file_clipboard::new_epoch();
          if (staged && offer_id) {
            auto offer = std::make_shared<lazy_offer_t>();
            offer->offer_id = *offer_id;
            offer->from_client = false;
            offer->kind = "image";
            offer->mime = "image/png";
            offer->total_size = staged->size;
            offer->host_image_lease = std::move(staged->lease);
            const nlohmann::json entries_json = nlohmann::json::array({{
              {"id", staged->entry_id},
              {"name", staged->name},
              {"size", staged->size},
            }});
            offer->host_entries.emplace(staged->entry_id, file_clipboard::lazy_source_entry_t {
              .id = staged->entry_id,
              .name = staged->name,
              .size = staged->size,
              .handle = std::move(staged->handle),
            });
            store_lazy_offer(offer);
            const nlohmann::json event {
              {"type", "clipboard_offer"},
              {"offer_id", *offer_id},
              {"kind", "image"},
              {"mime", "image/png"},
              {"entries", entries_json},
            };
            for (const auto &reader : readers) {
              publish_if_active(reader, event, "clipboard_offer");
            }
            item.png.reset();
            return item.empty();
          }
        }
        return false;
      }

      void handle_clipboard_offer_put(const client_t &client, request_t request, const authority_t &authority, reply_fn respond) {
        const auto parsed = nlohmann::json::parse(request.body, nullptr, false);
        if (!parsed.is_object() ||
            !parsed.contains("offer_id") || !parsed.at("offer_id").is_string() ||
            !parsed.contains("kind") || !parsed.at("kind").is_string() ||
            !parsed.contains("entries") || !parsed.at("entries").is_array()) {
          respond(reply_t::failure(400, "bad_request", "invalid clipboard offer json"));
          return;
        }
        const auto &offer_id = parsed.at("offer_id").get_ref<const std::string &>();
        const auto &kind = parsed.at("kind").get_ref<const std::string &>();
        if (!is_safe_token(offer_id) || (kind != "files" && kind != "image")) {
          respond(reply_t::failure(400, "bad_request", "invalid offer_id or kind"));
          return;
        }
        const auto &entries = parsed.at("entries");
        if (entries.empty() || entries.size() > file_clipboard::lazy_entry_limit || (kind == "image" && entries.size() != 1)) {
          respond(reply_t::failure(400, "bad_request", "invalid clipboard offer entries"));
          return;
        }

        auto offer = std::make_shared<lazy_offer_t>();
        offer->offer_id = offer_id;
        offer->cert = client.cert;
        offer->from_client = true;
        offer->kind = kind;
        if (parsed.contains("mime") && parsed.at("mime").is_string()) {
          offer->mime = parsed.at("mime").get_ref<const std::string &>();
        }

        std::set<std::string> seen_names;
        for (const auto &entry_json : entries) {
          if (!entry_json.is_object() ||
              !entry_json.contains("id") || !entry_json.at("id").is_string() ||
              !entry_json.contains("name") || !entry_json.at("name").is_string() ||
              !entry_json.contains("size") || !entry_json.at("size").is_number_unsigned()) {
            respond(reply_t::failure(400, "bad_request", "invalid clipboard offer entry"));
            return;
          }
          const auto &eid = entry_json.at("id").get_ref<const std::string &>();
          const auto &raw_name = entry_json.at("name").get_ref<const std::string &>();
          const auto size = entry_json.at("size").get<std::uint64_t>();
          const auto safe_name = files::sanitize_file_name(raw_name);
          if (!is_safe_token(eid) || !safe_name || offer->client_entries.contains(eid)) {
            respond(reply_t::failure(400, "bad_request", "invalid entry id or filename"));
            return;
          }
          std::string folded = *safe_name;
          std::transform(folded.begin(), folded.end(), folded.begin(), [](unsigned char ch) {
            return static_cast<char>(std::tolower(ch));
          });
          if (!seen_names.insert(std::move(folded)).second) {
            respond(reply_t::failure(400, "bad_request", "duplicate entry filename"));
            return;
          }
          if (size > options_.files.file_max || offer->total_size > options_.files.file_max - size) {
            respond(reply_t::failure(413, "too_large", "clipboard offer exceeds file_max"));
            return;
          }
          offer->total_size += size;
          offer->client_entry_order.push_back(eid);
          offer->client_entries.emplace(eid, staged_upload_entry_t {
            .id = eid,
            .name = *safe_name,
            .expected_size = size,
          });
        }

        const auto reservation = reserve_work(client.cert, 0);
        if (!reservation) {
          admission_rejected(respond);
          return;
        }

        if (!control_->post([this, cert = client.cert, offer = std::move(offer), authority, reservation, respond]() mutable {
              if (auto failure = deferred_failure(cert, op_e::clipboard_offer_put, authority)) {
                respond(std::move(*failure));
                return;
              }
              if (!file_clipboard_backend_ || !only_file_clipboard_stream(cert)) {
                respond(stale_file_clipboard());
                return;
              }
              const auto before = file_clipboard_backend_->file_clipboard_generation();
              if (!before) {
                respond(unavailable());
                return;
              }
              store_lazy_offer(offer);
              const auto offer_id_copy = offer->offer_id;
              const auto committed = file_clipboard_backend_->publish_lazy_offer(
                *before,
                offer_id_copy,
                offer->kind,
                [this, cert, offer_id = offer_id_copy, authority](std::string pulled_id, std::vector<std::string> targets) {
                  control_->post([this, cert, pulled_id = std::move(pulled_id), targets = std::move(targets), authority]() {
                    if (deferred_failure(cert, op_e::clipboard_offer_put, authority) || !only_file_clipboard_stream(cert)) {
                      return;
                    }
                    const auto live = find_lazy_offer(pulled_id);
                    if (!live) {
                      return;
                    }
                    {
                      std::lock_guard lock {live->mutex};
                      if (live->failed || !live->from_client || live->cert != cert) {
                        return;
                      }
                    }
                    publish_if_active(
                      cert,
                      nlohmann::json {
                        {"type", "clipboard_pull"},
                        {"offer_id", pulled_id},
                        {"targets", std::move(targets)},
                      },
                      "clipboard_pull:" + pulled_id
                    );
                  });
                }
              );
              if (!committed) {
                retire_lazy_offers_for_client(cert);
                respond(stale_file_clipboard());
                return;
              }
              {
                std::lock_guard lock {offer->mutex};
                offer->published_generation = *committed;
              }
              respond(reply_t::success(200, nlohmann::json {{"offer_id", offer->offer_id}, {"generation", *committed}}));
            })) {
          respond(unavailable());
        }
      }

      void handle_clipboard_offer_entry_op(op_e op, const client_t &client, request_t request, const authority_t &authority, reply_fn respond) {
        if (!is_safe_token(request.id)) {
          respond(reply_t::failure(404, "not_found", "unknown offer"));
          return;
        }
        const bool needs_entry = (op == op_e::clipboard_offer_entry_start || op == op_e::clipboard_offer_entry_chunk || op == op_e::clipboard_offer_entry_read);
        if (needs_entry && !is_safe_token(request.sub_id)) {
          respond(reply_t::failure(404, "not_found", "unknown entry"));
          return;
        }
        std::optional<std::uint64_t> offset;
        std::optional<std::uint64_t> length;
        if (const auto v = query_value(request, "offset"); v) {
          offset = parse_u64(*v);
          if (!offset) {
            respond(reply_t::failure(400, "bad_request", "invalid offset"));
            return;
          }
        } else if (op == op_e::clipboard_offer_entry_chunk) {
          respond(reply_t::failure(400, "bad_request", "missing offset"));
          return;
        }
        if (const auto v = query_value(request, "length"); v && op == op_e::clipboard_offer_entry_read) {
          length = parse_u64(*v);
          if (!length) {
            respond(reply_t::failure(400, "bad_request", "invalid length"));
            return;
          }
        }

        const auto reservation = reserve_work(client.cert, op == op_e::clipboard_offer_entry_chunk ? request.body.capacity() : 0);
        if (!reservation) {
          admission_rejected(respond);
          return;
        }

        if (!io_->post([this, op, cert = client.cert, offer_id = std::move(request.id), entry_id = std::move(request.sub_id), body = std::move(request.body), offset, length, authority, reservation, respond]() mutable {
              if (auto failure = deferred_failure(cert, op, authority)) {
                respond(std::move(*failure));
                return;
              }
              const auto offer = find_lazy_offer(offer_id);
              if (!offer) {
                respond(reply_t::failure(404, "not_found", "unknown offer"));
                return;
              }

              if (op == op_e::clipboard_offer_entry_read) {
                file_clipboard::lazy_source_entry_t src;
                {
                  std::lock_guard lock {offer->mutex};
                  if (offer->from_client || offer->failed) {
                    respond(reply_t::failure(404, "not_found", "offer unavailable"));
                    return;
                  }
                  const auto it = offer->host_entries.find(entry_id);
                  if (it == offer->host_entries.end()) {
                    respond(reply_t::failure(404, "not_found", "unknown entry"));
                    return;
                  }
                  src = it->second;
                }
                const auto off = offset.value_or(0);
                if (off > src.size) {
                  respond(reply_t::failure(400, "bad_request", "offset beyond file size"));
                  return;
                }
                const auto want = static_cast<std::size_t>(std::min<std::uint64_t>(length.value_or(options_.files.chunk_max), options_.files.chunk_max));
                std::vector<char> chunk;
                std::string chunk_sha;
                if (!src.handle || !src.handle->read_chunk(off, want, chunk, chunk_sha)) {
                  retire_offer_object(offer);
                  respond(reply_t::failure(409, "conflict", "source file changed or became unreadable"));
                  return;
                }
                reply_t reply;
                reply.status = 200;
                reply.content_type = "application/octet-stream";
                reply.body.assign(chunk.data(), chunk.size());
                reply.headers.emplace_back("X-SDS-Chunk-Sha256", std::move(chunk_sha));
                reply.headers.emplace_back("X-SDS-File-Size", std::to_string(src.size));
                if (off + chunk.size() == src.size) {
                  std::string file_sha;
                  if (src.handle->finalize_file_sha256(file_sha)) {
                    reply.headers.emplace_back("X-SDS-File-Sha256", std::move(file_sha));
                  }
                }
                respond(std::move(reply));
                return;
              }

              if (op == op_e::clipboard_offer_cancel) {
                retire_offer_object(offer);
                std::lock_guard lock {lazy_mutex_};
                lazy_offers_.erase(offer_id);
                respond(reply_t::success(200, nlohmann::json {{"cancelled", true}}));
                return;
              }

              if (op == op_e::clipboard_offer_entry_start) {
                std::lock_guard lock {offer->mutex};
                if (!offer->from_client || offer->cert != cert || offer->failed || offer->completed) {
                  respond(reply_t::failure(409, "conflict", "offer is not writable"));
                  return;
                }
                const auto it = offer->client_entries.find(entry_id);
                if (it == offer->client_entries.end()) {
                  respond(reply_t::failure(404, "not_found", "unknown entry"));
                  return;
                }
                if (!offer->client_stage) {
                  offer->client_stage = file_clipboard::create_chunk_stage(offer->total_size, options_.files.min_free_space);
                  if (!offer->client_stage) {
                    respond(reply_t::failure(507, "insufficient_space", "insufficient staging space"));
                    return;
                  }
                }
                const bool already_started = it->second.started;
                if (auto err = start_staged_entry(it->second, *offer->client_stage)) {
                  respond(std::move(*err));
                  return;
                }
                respond(reply_t::success(already_started ? 200 : 201, nlohmann::json {{"offset", it->second.received}, {"chunk_max", options_.files.chunk_max}}));
                return;
              }

              if (op == op_e::clipboard_offer_entry_chunk) {
                std::lock_guard lock {offer->mutex};
                if (!offer->from_client || offer->cert != cert || offer->failed || offer->completed) {
                  respond(reply_t::failure(409, "conflict", "offer is not writable"));
                  return;
                }
                const auto it = offer->client_entries.find(entry_id);
                if (it == offer->client_entries.end()) {
                  respond(reply_t::failure(404, "not_found", "unknown entry"));
                  return;
                }
                respond(write_staged_chunk(it->second, *offset, body));
                return;
              }

              // clipboard_offer_complete
              std::map<std::string, std::string> expected_hashes;
              if (!body.empty()) {
                const auto complete_json = nlohmann::json::parse(body, nullptr, false);
                if (!complete_json.is_object()) {
                  respond(reply_t::failure(400, "bad_request", "invalid complete json"));
                  return;
                }
                if (complete_json.contains("entries")) {
                  if (!complete_json.at("entries").is_array()) {
                    respond(reply_t::failure(400, "bad_request", "invalid entries array"));
                    return;
                  }
                  for (const auto &h : complete_json.at("entries")) {
                    if (!h.is_object() || !h.contains("id") || !h.at("id").is_string() ||
                        !h.contains("sha256") || !h.at("sha256").is_string()) {
                      respond(reply_t::failure(400, "bad_request", "invalid entry hash object"));
                      return;
                    }
                    const auto norm = normalize_hex_sha256(h.at("sha256").get_ref<const std::string &>());
                    if (!norm) {
                      respond(reply_t::failure(400, "bad_request", "invalid sha256"));
                      return;
                    }
                    expected_hashes.emplace(h.at("id").get<std::string>(), *norm);
                  }
                }
              }

              std::string native_offer;
              std::string staged_image_path;
              {
                std::lock_guard lock {offer->mutex};
                if (!offer->from_client || offer->cert != cert || offer->failed || !offer->client_stage) {
                  if (file_clipboard_backend_) {
                    file_clipboard_backend_->fail_lazy_offer(offer_id);
                  }
                  respond(reply_t::failure(409, "conflict", "offer cannot be completed"));
                  return;
                }
                std::vector<std::string> committed_names;
                committed_names.reserve(offer->client_entry_order.size());
                for (const auto &eid : offer->client_entry_order) {
                  auto &entry = offer->client_entries.at(eid);
                  std::optional<std::string> exp_sha;
                  if (const auto hit = expected_hashes.find(eid); hit != expected_hashes.end()) {
                    exp_sha = hit->second;
                  }
                  if (auto err = finalize_staged_entry(entry, *offer->client_stage, exp_sha)) {
                    offer->failed = true;
                    if (file_clipboard_backend_) {
                      file_clipboard_backend_->fail_lazy_offer(offer_id);
                    }
                    respond(std::move(*err));
                    return;
                  }
                  committed_names.push_back(entry.name);
                }
                offer->completed = true;
                if (offer->kind == "files") {
                  native_offer = offer->client_stage->native_copy_offer(committed_names);
                } else {
                  staged_image_path = (offer->client_stage->dir_path() / committed_names.front()).string();
                }
              }

              if (file_clipboard_backend_) {
                file_clipboard_backend_->complete_lazy_offer(
                  offer_id,
                  std::move(native_offer),
                  std::move(staged_image_path),
                  [this, cert, offer_id, authority]() {
                    const auto live = find_lazy_offer(offer_id);
                    return live && !deferred_failure(cert, op_e::clipboard_offer_complete, authority) && only_file_clipboard_stream(cert);
                  }
                );
              }
              control_->post_at(worker_t::clock::now() + options_.file_clipboard_lease_ttl, [this, offer_id]() {
                const auto live = find_lazy_offer(offer_id);
                if (!live) {
                  return;
                }
                {
                  std::lock_guard lock {lazy_mutex_};
                  lazy_offers_.erase(offer_id);
                }
                retire_offer_object(live);
              });
              respond(reply_t::success(200, nlohmann::json {{"offer_id", offer_id}, {"ready", true}}));
            })) {
          respond(unavailable());
        }
      }

      std::size_t open_drops(std::string_view cert) const {
        std::lock_guard lock {drop_mutex_};
        std::size_t count = 0;
        for (const auto &[id, drop] : drops_) {
          if (drop->cert == cert) {
            ++count;
          }
        }
        return count;
      }

      void clear_all_drops() {
        {
          std::lock_guard lock {drop_mutex_};
          drops_.clear();
        }
        drop_leases_.clear();
      }

      void end_drops_for_client(std::string_view cert) {
        std::lock_guard lock {drop_mutex_};
        std::erase_if(drops_, [cert](const auto &kv) {
          return kv.second->cert == cert;
        });
      }

      void handle_drop_op(op_e op, const client_t &client, request_t request, const authority_t &authority, reply_fn respond) {
        std::optional<std::uint64_t> offset;
        std::uint64_t index = 0;
        if (const auto v = query_value(request, "offset"); v) {
          offset = parse_u64(*v);
          if (!offset) {
            respond(reply_t::failure(400, "bad_request", "invalid offset"));
            return;
          }
        } else if (op == op_e::drop_chunk) {
          respond(reply_t::failure(400, "bad_request", "missing offset"));
          return;
        }
        if (const auto v = query_value(request, "index"); v) {
          const auto parsed_idx = parse_u64(*v);
          if (!parsed_idx) {
            respond(reply_t::failure(400, "bad_request", "invalid index"));
            return;
          }
          index = *parsed_idx;
        }
        if (op != op_e::drop_create && !files::is_id(request.id)) {
          respond(reply_t::failure(404, "not_found", "unknown drop id"));
          return;
        }

        const auto reservation = reserve_work(client.cert, op == op_e::drop_chunk ? request.body.capacity() : 0);
        if (!reservation) {
          admission_rejected(respond);
          return;
        }

        if (!io_->post([this, op, cert = client.cert, id = std::move(request.id), body = std::move(request.body), offset, index, authority, reservation, respond]() mutable {
              if (auto failure = deferred_failure(cert, op, authority)) {
                respond(std::move(*failure));
                return;
              }
              if (op == op_e::drop_create) {
                const auto json = nlohmann::json::parse(body, nullptr, false);
                if (!json.is_object() || !json.contains("nx") || !json.at("nx").is_number() ||
                    !json.contains("ny") || !json.at("ny").is_number()) {
                  respond(reply_t::failure(400, "bad_request", "invalid drop json"));
                  return;
                }
                const double nx = json.at("nx").get<double>();
                const double ny = json.at("ny").get<double>();
                if (!std::isfinite(nx) || nx < 0.0 || nx > 1.0 || !std::isfinite(ny) || ny < 0.0 || ny > 1.0) {
                  respond(reply_t::failure(400, "bad_request", "invalid drop coordinates"));
                  return;
                }
                nlohmann::json files_arr = nlohmann::json::array();
                if (json.contains("files")) {
                  if (!json.at("files").is_array()) {
                    respond(reply_t::failure(400, "bad_request", "invalid drop files"));
                    return;
                  }
                  files_arr = json.at("files");
                } else if (json.contains("name") && json.contains("size")) {
                  files_arr.push_back({{"name", json.at("name")}, {"size", json.at("size")}});
                }
                if (files_arr.empty() || files_arr.size() > file_clipboard::lazy_entry_limit) {
                  respond(reply_t::failure(400, "bad_request", "invalid drop file count"));
                  return;
                }

                auto drop = std::make_shared<drop_session_t>();
                drop->cert = cert;
                drop->nx = nx;
                drop->ny = ny;
                std::set<std::string> seen_names;
                nlohmann::json names_json = nlohmann::json::array();
                for (std::size_t i = 0; i < files_arr.size(); ++i) {
                  const auto &f = files_arr[i];
                  if (!f.is_object() || !f.contains("name") || !f.at("name").is_string() ||
                      !f.contains("size") || !f.at("size").is_number_unsigned()) {
                    respond(reply_t::failure(400, "bad_request", "invalid drop file entry"));
                    return;
                  }
                  const auto safe_name = files::sanitize_file_name(f.at("name").get_ref<const std::string &>());
                  const auto size = f.at("size").get<std::uint64_t>();
                  if (!safe_name) {
                    respond(reply_t::failure(400, "bad_request", "invalid drop filename"));
                    return;
                  }
                  std::string folded = *safe_name;
                  std::transform(folded.begin(), folded.end(), folded.begin(), [](unsigned char ch) {
                    return static_cast<char>(std::tolower(ch));
                  });
                  if (!seen_names.insert(std::move(folded)).second) {
                    respond(reply_t::failure(400, "bad_request", "duplicate drop filename"));
                    return;
                  }
                  if (size > options_.files.file_max || drop->total_size > options_.files.file_max - size) {
                    respond(reply_t::failure(413, "too_large", "drop exceeds file_max"));
                    return;
                  }
                  drop->total_size += size;
                  names_json.push_back(*safe_name);
                  drop->entries.push_back(staged_upload_entry_t {
                    .id = std::to_string(i),
                    .name = *safe_name,
                    .expected_size = size,
                  });
                }

                const auto drop_id = file_clipboard::new_epoch();
                if (!drop_id) {
                  respond(unavailable());
                  return;
                }
                drop->id = *drop_id;
                drop->stage = file_clipboard::create_chunk_stage(drop->total_size, options_.files.min_free_space);
                if (!drop->stage) {
                  respond(reply_t::failure(507, "insufficient_space", "insufficient drop staging space"));
                  return;
                }
                for (auto &entry : drop->entries) {
                  if (auto err = start_staged_entry(entry, *drop->stage)) {
                    respond(std::move(*err));
                    return;
                  }
                }
                {
                  std::lock_guard lock {drop_mutex_};
                  drops_.emplace(drop->id, drop);
                }
                respond(reply_t::success(201, nlohmann::json {{"id", drop->id}, {"chunk_max", options_.files.chunk_max}, {"files", std::move(names_json)}}));
                return;
              }

              std::shared_ptr<drop_session_t> drop;
              {
                std::lock_guard lock {drop_mutex_};
                const auto it = drops_.find(id);
                if (it != drops_.end() && it->second->cert == cert) {
                  drop = it->second;
                }
              }
              if (!drop) {
                respond(reply_t::failure(404, "not_found", "unknown drop id"));
                return;
              }

              if (op == op_e::drop_cancel) {
                std::lock_guard lock {drop_mutex_};
                drops_.erase(id);
                respond(reply_t::success(200, nlohmann::json {{"cancelled", true}}));
                return;
              }

              if (op == op_e::drop_chunk) {
                std::lock_guard lock {drop->mutex};
                if (index >= drop->entries.size()) {
                  respond(reply_t::failure(404, "not_found", "unknown drop entry index"));
                  return;
                }
                drop->touched_at = worker_t::clock::now();
                respond(write_staged_chunk(drop->entries[index], *offset, body));
                return;
              }

              // drop_complete
              std::map<std::size_t, std::string> expected_hashes;
              if (!body.empty()) {
                const auto complete_json = nlohmann::json::parse(body, nullptr, false);
                if (!complete_json.is_object()) {
                  respond(reply_t::failure(400, "bad_request", "invalid drop complete json"));
                  return;
                }
                if (complete_json.contains("sha256")) {
                  if (!complete_json.at("sha256").is_string()) {
                    respond(reply_t::failure(400, "bad_request", "invalid sha256"));
                    return;
                  }
                  const auto norm = normalize_hex_sha256(complete_json.at("sha256").get_ref<const std::string &>());
                  if (!norm) {
                    respond(reply_t::failure(400, "bad_request", "invalid sha256"));
                    return;
                  }
                  expected_hashes.emplace(0, *norm);
                } else if (complete_json.contains("entries")) {
                  if (!complete_json.at("entries").is_array()) {
                    respond(reply_t::failure(400, "bad_request", "invalid entries array"));
                    return;
                  }
                  for (const auto &h : complete_json.at("entries")) {
                    if (!h.is_object() || !h.contains("index") || !h.at("index").is_number_unsigned() ||
                        !h.contains("sha256") || !h.at("sha256").is_string()) {
                      respond(reply_t::failure(400, "bad_request", "invalid entry hash"));
                      return;
                    }
                    const auto norm = normalize_hex_sha256(h.at("sha256").get_ref<const std::string &>());
                    if (!norm) {
                      respond(reply_t::failure(400, "bad_request", "invalid sha256"));
                      return;
                    }
                    expected_hashes.emplace(h.at("index").get<std::size_t>(), *norm);
                  }
                }
              }

              std::vector<std::string> final_names;
              {
                std::lock_guard lock {drop->mutex};
                final_names.reserve(drop->entries.size());
                for (std::size_t i = 0; i < drop->entries.size(); ++i) {
                  std::optional<std::string> exp_sha;
                  if (const auto hit = expected_hashes.find(i); hit != expected_hashes.end()) {
                    exp_sha = hit->second;
                  }
                  if (auto err = finalize_staged_entry(drop->entries[i], *drop->stage, exp_sha)) {
                    respond(std::move(*err));
                    return;
                  }
                  final_names.push_back(drop->entries[i].name);
                }
              }

              {
                std::lock_guard lock {drop_mutex_};
                drops_.erase(id);
              }

#ifdef SUNSHINE_BUILD_X11
              const auto uris = drop->stage->uris_for(final_names);
              if (platf::xdnd::deliver_xdnd_drop(drop->nx, drop->ny, uris) == platf::xdnd::drop_delivery_status_e::accepted) {
                auto lease_stage = drop->stage;
                control_->post([this, id, lease_stage = std::move(lease_stage)]() mutable {
                  drop_leases_.emplace(id, lease_stage);
                  control_->post_at(worker_t::clock::now() + options_.file_clipboard_lease_grace, [this, id]() {
                    drop_leases_.erase(id);
                  });
                });
                respond(reply_t::success(200, nlohmann::json {{"delivered", "xdnd"}, {"files", std::move(final_names)}}));
                return;
              }
#endif
              const auto committed = commit_staged_files_to_inbox(
                files_->inbox_dir(),
                drop->stage->dir_path(),
                drop->entries,
                drop->total_size,
                options_.files.min_free_space
              );
              if (!committed) {
                respond(reply_t::failure(507, "insufficient_space", "failed to commit drop into inbox"));
                return;
              }
              respond(reply_t::success(200, nlohmann::json {{"delivered", "inbox"}, {"files", *committed}}));
            })) {
          respond(unavailable());
        }
      }

      /**
       * @brief Begin outbox change detection when a downloader is streaming (file worker).
       */
      void start_outbox_polling() {
        if (outbox_polling_ || active_with(permission_e::file_download).empty()) {
          return;
        }
        outbox_polling_ = true;
        files_->reset_outbox_baseline();
        io_->post_at(worker_t::clock::now() + options_.outbox_poll_interval, [this]() {
          outbox_tick();
        });
      }

      /**
       * @brief One outbox scan (file worker).
       */
      void outbox_tick() {
        const auto downloaders = active_with(permission_e::file_download);
        if (downloaders.empty() || !feature_available(feature_e::files)) {
          outbox_polling_ = false;
          return;
        }
        if (const auto count = files_->scan_outbox_changes(); count) {
          for (const auto &cert : downloaders) {
            publish_if_active(cert, nlohmann::json {{"type", "outbox"}, {"count", *count}}, "outbox");
          }
        }
        io_->post_at(worker_t::clock::now() + options_.outbox_poll_interval, [this]() {
          outbox_tick();
        });
      }

      /**
       * @brief Schedule the next idle-upload sweep (file worker).
       */
      void schedule_idle_check() {
        const auto interval = std::clamp<std::chrono::milliseconds>(options_.files.idle_timeout / 4, 50ms, 5s);
        io_->post_at(worker_t::clock::now() + interval, [this]() {
          files_->expire_idle(files::manager_t::clock::now());
          {
            const auto now = worker_t::clock::now();
            std::lock_guard lock {drop_mutex_};
            std::erase_if(drops_, [&](const auto &kv) {
              std::lock_guard entry_lock {kv.second->mutex};
              return now - kv.second->touched_at > options_.files.idle_timeout;
            });
          }
          schedule_idle_check();
        });
      }

      options_t options_;  ///< Configuration.
      dependencies_t deps_;  ///< Collaborators.
      rate_limiter_t clipboard_rate_;  ///< Clipboard token buckets.
      event_hub_t events_;  ///< Event queues and parked polls.
      std::unique_ptr<clipboard::core_t> clipboard_;  ///< Clipboard core (control worker).
      clipboard::backend_t *file_clipboard_backend_ = nullptr;  ///< Owned by clipboard_.
      std::optional<file_clipboard_session_t> file_clipboard_session_;  ///< Control worker only.
      std::optional<std::uint64_t> file_clipboard_owned_;  ///< Last published selection.
      std::map<std::uint64_t, std::shared_ptr<const file_clipboard::stage_t>> file_clipboard_leases_;
      mutable std::mutex lazy_mutex_;  ///< Protects lazy_offers_.
      std::map<std::string, std::shared_ptr<lazy_offer_t>, std::less<>> lazy_offers_;
      mutable std::mutex drop_mutex_;  ///< Protects drops_.
      std::map<std::string, std::shared_ptr<drop_session_t>, std::less<>> drops_;
      std::map<std::string, std::shared_ptr<file_clipboard::chunk_stage_t>, std::less<>> drop_leases_;
      std::unique_ptr<files::manager_t> files_;  ///< File core (file worker).
      auth_context_t auth_;  ///< Authorization dependencies.
      std::shared_ptr<pending_state_t> pending_ = std::make_shared<pending_state_t>();  ///< One request budget for both workers.
      std::mutex authority_mutex_;  ///< Protects authorities_.
      std::map<std::string, authority_t, std::less<>> authorities_;  ///< Current revocable request authority per client.
      mutable std::mutex active_mutex_;  ///< Protects active_.
      std::set<std::string, std::less<>> active_;  ///< Clients with a running stream.
      bool outbox_polling_ = false;  ///< Outbox timer armed (file worker).
      std::atomic_bool shut_down_ {false};  ///< Set by shutdown().
      std::unique_ptr<worker_t> control_;  ///< Clipboard, events and lifecycle jobs.
      std::unique_ptr<worker_t> io_;  ///< Disk I/O and hashing jobs.
      std::unique_ptr<tile_refiner_t> tile_refiner_;  ///< Adaptive dirty-tile refiner.

    public:
      void refresh_tile_refinement_active() {
        const bool active = !shut_down_.load(std::memory_order_acquire) &&
                            options_.tile_refinement &&
                            tile_refiner_ != nullptr &&
                            deps_.any_tile_refinement_active &&
                            deps_.any_tile_refinement_active();
        if (tile_refiner_) {
          tile_refiner_->set_active(active);
        }
        tile_refinement_enabled_atomic.store(active, std::memory_order_release);
      }

      void post_refresh_tile_refinement(std::string stopped_cert) {
        if (shut_down_.load(std::memory_order_acquire) || !control_) {
          return;
        }
        control_->post([this, stopped_cert = std::move(stopped_cert)]() {
          if (shut_down_.load(std::memory_order_acquire)) {
            return;
          }
          if (!stopped_cert.empty() && tile_refiner_ &&
              (!deps_.tile_refinement_active || !deps_.tile_refinement_active(stopped_cert))) {
            tile_refiner_->end_stream(stopped_cert);
          }
          refresh_tile_refinement_active();
        });
      }

      void submit_bgra(const std::uint8_t *bgra, int stride, int width, int height) {
        if (!shut_down_.load(std::memory_order_acquire) && tile_refiner_) {
          tile_refiner_->submit_bgra_frame(bgra, stride, width, height);
        }
      }
    };

    std::mutex runtime_mutex;  ///< Protects current_runtime.
    std::shared_ptr<runtime_t> current_runtime;  ///< Running module, if any.

    /**
     * @brief Access the running module.
     *
     * @return Runtime, or `nullptr`.
     */
    std::shared_ptr<runtime_t> current() {
      std::lock_guard lock {runtime_mutex};
      return current_runtime;
    }
  }  // namespace

  void prepare_clipboard_backend() {
    if (!config::sds.clipboard) {
      return;
    }
    std::lock_guard lock {prepared_backend_mutex()};
    if (!backend_prepared()) {
      prepared_backend() = clipboard::make_backend();
      backend_prepared() = true;
    }
  }

  bool permission_granted(std::string_view cert_pem, permission_e permission) {
    const auto client = find_paired_client(cert_pem);
    return client && permission != permission_e::count && client->permissions.test(static_cast<std::size_t>(permission));
  }

  options_t options_from_config() {
    options_t options;
    options.clipboard = config::sds.clipboard;
    options.file_transfer = config::sds.file_transfer;
    options.file_clipboard = file_clipboard::private_x11_enabled();
    options.mic_passthrough = config::sds.mic_passthrough;
    options.clipboard_text_max = config::sds.clipboard_text_max;
    options.clipboard_image_max = config::sds.clipboard_image_max;
    options.clipboard_rate = config::sds.clipboard_rate;
    options.files.file_max = config::sds.file_max;
    options.files.chunk_max = config::sds.file_chunk_max;
    options.files.uploads_max = static_cast<std::size_t>(config::sds.file_uploads_max_concurrent);
    options.files.min_free_space = config::sds.file_min_free_space;
    options.files.idle_timeout = config::sds.file_upload_idle_timeout;
    options.files.inbox = config::sds.file_inbox_dir;
    options.files.outbox = config::sds.file_outbox_dir;
    return options;
  }

  int start(options_t options, dependencies_t deps) {
    stop();
    const bool observe = deps.observe_sessions;
    auto runtime = std::make_shared<runtime_t>(std::move(options), std::move(deps));
    {
      std::lock_guard lock {runtime_mutex};
      current_runtime = std::move(runtime);
    }
    if (observe) {
      rtsp_stream::set_session_observer([](std::string_view cert, bool running) {
        on_stream_state(cert, running);
      });
    }
    return 0;
  }

  int start() {
    return start(options_from_config());
  }

  void stop() {
    tile_refinement_enabled_atomic.store(false, std::memory_order_release);
    std::shared_ptr<runtime_t> runtime;
    {
      std::lock_guard lock {runtime_mutex};
      runtime = std::move(current_runtime);
    }
    if (!runtime) {
      return;
    }
    rtsp_stream::set_session_observer(nullptr);
    runtime->shutdown();
  }

  bool running() {
    return current() != nullptr;
  }

  void handle(op_e op, request_t request, reply_fn respond) {
    const auto runtime = current();
    if (!runtime) {
      respond(reply_t::failure(503, "internal", "service not running"));
      return;
    }
    runtime->handle(op, std::move(request), std::move(respond));
  }

  void on_stream_state(std::string_view cert_pem, bool running) {
    if (cert_pem.empty()) {
      return;
    }
    if (const auto runtime = current(); runtime) {
      runtime->stream_state(std::string {cert_pem}, running);
    }
  }

  void on_client_changed(std::string_view cert_pem) {
    if (cert_pem.empty()) {
      return;
    }
    mic::on_client_changed(cert_pem);
    if (const auto runtime = current(); runtime) {
      runtime->client_changed(std::string {cert_pem});
    }
  }

  std::string server_features() {
    const auto runtime = current();
    return runtime ? runtime->features() : std::string {};
  }

  std::size_t max_request_body_size() {
    const auto runtime = current();
    const auto options = runtime ? runtime->options() : options_from_config();
    return std::max({options.files.chunk_max, options.clipboard_image_max, options.clipboard_text_max,
                     options.file_clipboard ? file_clipboard::wire_max : 0u}) + SMALL_BODY_MAX;
  }

  void set_mic_available(bool available) {
    mic_available = available;
  }

  void on_tile_refinement_sessions_changed(std::string_view stopped_cert) {
    if (const auto runtime = current(); runtime) {
      runtime->post_refresh_tile_refinement(std::string {stopped_cert});
    } else {
      tile_refinement_enabled_atomic.store(false, std::memory_order_release);
    }
  }

  bool tile_refinement_wanted() {
    return tile_refinement_enabled_atomic.load(std::memory_order_acquire);
  }

  void submit_bgra_frame(const std::uint8_t *bgra, int stride, int width, int height) {
    if (!tile_refinement_enabled_atomic.load(std::memory_order_acquire)) {
      return;
    }
    if (const auto runtime = current(); runtime) {
      runtime->submit_bgra(bgra, stride, width, height);
    }
  }

  void drain_for_test() {
    if (const auto runtime = current(); runtime) {
      runtime->drain();
    }
  }

  bool post_to_file_worker_for_test(std::function<void()> job) {
    const auto runtime = current();
    return runtime && runtime->post_io(std::move(job));
  }

  bool post_to_control_worker_for_test(std::function<void()> job) {
    const auto runtime = current();
    return runtime && runtime->post_control(std::move(job));
  }

  test_state_t state_for_test(std::string_view cert_pem) {
    const auto runtime = current();
    if (!runtime) {
      return {};
    }
    return runtime->test_state(std::string {cert_pem});
  }
}  // namespace sds
