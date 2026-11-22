/**
 * @file src/sds/sds.cpp
 * @brief secure-desktop-stream module lifecycle, worker threads, stream hooks and dispatcher.
 */
// standard includes
#include <algorithm>
#include <atomic>
#include <charconv>
#include <future>
#include <map>
#include <mutex>
#include <set>
#include <utility>
#include <vector>

// local includes
#include "clipboard.h"
#include "events.h"
#include "sds.h"
#include "src/config.h"
#include "src/logging.h"
#include "src/nvhttp.h"
#include "src/rtsp.h"
#include "worker.h"

using namespace std::literals;

namespace sds {
  namespace {
    std::atomic_bool mic_available {false};  ///< Set by the microphone module.

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
        if (!deps_.find_client) {
          deps_.find_client = find_paired_client;
        }
        if (!deps_.make_clipboard_backend) {
          deps_.make_clipboard_backend = take_or_make_backend;
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
          return files_->open_uploads(cert);
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
        events_.shutdown();
        control_->post([this]() {
          clipboard_->shutdown();
        });
        io_->post([this]() {
          files_->shutdown();
        });
        control_->stop();
        io_->stop();
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
          case feature_e::mic:
            return options_.mic_passthrough && mic_available.load();
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
        const auto authority = request.cert_pem ? request_authority(*request.cert_pem) : authority_t {};
        request_view_t view;
        view.cert_pem = request.cert_pem;
        view.body_size = request.body.size();
        view.content_type = request.content_type;
        if (op == op_e::outbox_read) {
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
          case op_e::clipboard_get:
            clipboard_get(client, request, authority, std::move(respond));
            return;
          case op_e::clipboard_put:
            clipboard_put(client, std::move(request), authority, std::move(respond));
            return;
          case op_e::upload_create:
          case op_e::upload_chunk:
          case op_e::upload_complete:
          case op_e::upload_cancel:
          case op_e::outbox_list:
          case op_e::outbox_read:
            file_op(op, client, std::move(request), authority, std::move(respond));
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
          io_->post([this, cert]() { files_->end_client(cert); });
          control_->post([this, cert = std::move(cert)]() { handle_stream_state(cert, false); });
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
        for (const auto &[feature, name] : {std::pair {feature_e::clipboard, "clipboard"sv}, std::pair {feature_e::files, "files"sv}, std::pair {feature_e::mic, "mic"sv}}) {
          if (feature_available(feature)) {
            features.push_back(name);
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
              return;
            }
          }
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
        events_.end_stream(cert);
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
        const auto client = deps_.find_client(cert);
        const bool may_upload = client && client->permissions.test(static_cast<std::size_t>(permission_e::file_upload));
        if (!may_upload) {
          io_->post([this, cert]() {
            files_->end_client(cert);
          });
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
          schedule_idle_check();
        });
      }

      options_t options_;  ///< Configuration.
      dependencies_t deps_;  ///< Collaborators.
      rate_limiter_t clipboard_rate_;  ///< Clipboard token buckets.
      event_hub_t events_;  ///< Event queues and parked polls.
      std::unique_ptr<clipboard::core_t> clipboard_;  ///< Clipboard core (control worker).
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
    return std::max({options.files.chunk_max, options.clipboard_image_max, options.clipboard_text_max}) + SMALL_BODY_MAX;
  }

  void set_mic_available(bool available) {
    mic_available = available;
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
