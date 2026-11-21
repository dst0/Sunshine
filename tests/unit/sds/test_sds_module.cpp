/**
 * @file tests/unit/sds/test_sds_module.cpp
 * @brief Test the sds module dispatcher, stream lifecycle and long-poll behaviour end to end
 *        without HTTP (checks S3-S5, S12, S16).
 */

// test includes
#include "../../tests_common.h"
#include "fake_clipboard_backend.h"
#include "sds_test_utils.h"

// standard includes
#include <atomic>
#include <chrono>
#include <filesystem>
#include <future>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <thread>

// local includes
#include <src/config.h>
#include <src/sds/sds.h>

namespace fs = std::filesystem;
using namespace std::literals;

namespace {
  constexpr auto CERT_A = "cert-a";
  constexpr auto CERT_B = "cert-b";

  /**
   * @brief Find a response header.
   *
   * @param reply Reply.
   * @param name Header name.
   * @return Value, or empty.
   */
  std::string header(const sds::reply_t &reply, const std::string &name) {
    for (const auto &[key, value] : reply.headers) {
      if (key == name) {
        return value;
      }
    }
    return {};
  }

  /**
   * @brief Running sds module with fake collaborators.
   */
  class SdsModuleTest: public BaseTest {
  protected:
    void SetUp() override {
      BaseTest::SetUp();
      base = test_utils::sds::scratch_dir("sds_module");
      clipboard = std::make_shared<test_utils::sds::fake_clipboard_state_t>();
      options.clipboard_text_max = 1024;
      options.clipboard_image_max = 64 * 1024;
      options.clipboard_rate = 1000;
      options.files.inbox = base / "inbox";
      options.files.outbox = base / "outbox";
      options.files.chunk_max = 16 * 1024;
      options.files.file_max = 1024 * 1024;
      options.files.min_free_space = 0;
      options.files.idle_timeout = 10s;
      options.poll_default = 300ms;
      options.poll_max = 1s;
      options.outbox_poll_interval = 50ms;
      add_client(CERT_A, "uuid-a");
      add_client(CERT_B, "uuid-b");
      start();
    }

    void TearDown() override {
      sds::stop();
      sds::set_mic_available(false);
      std::error_code ec;
      fs::remove_all(base, ec);
      BaseTest::TearDown();
    }

    /**
     * @brief Register a client with every permission and an active stream.
     *
     * @param cert Certificate.
     * @param uuid UUID.
     */
    void add_client(const std::string &cert, const std::string &uuid) {
      std::lock_guard lock {mutex};
      sds::client_t client;
      client.cert = cert;
      client.uuid = uuid;
      client.permissions.set();
      clients[cert] = client;
      streaming.insert(cert);
    }

    /**
     * @brief Change a client's permissions.
     *
     * @param cert Certificate.
     * @param permission Permission.
     * @param granted Granted.
     */
    void set_permission(const std::string &cert, sds::permission_e permission, bool granted) {
      std::lock_guard lock {mutex};
      clients[cert].permissions.set(static_cast<std::size_t>(permission), granted);
    }

    /**
     * @brief Mark a stream active or inactive.
     *
     * @param cert Certificate.
     * @param active Stream state.
     */
    void set_streaming(const std::string &cert, bool active) {
      std::lock_guard lock {mutex};
      if (active) {
        streaming.insert(cert);
      } else {
        streaming.erase(cert);
      }
    }

    /**
     * @brief (Re)start the module with the fixture's options.
     */
    void start() {
      sds::dependencies_t deps;
      deps.stream_active = [this](std::string_view cert) {
        if (stream_override) {
          return stream_override(cert);
        }
        std::lock_guard lock {mutex};
        return streaming.contains(std::string {cert});
      };
      deps.find_client = [this](std::string_view cert) -> std::optional<sds::client_t> {
        std::lock_guard lock {mutex};
        const auto it = clients.find(std::string {cert});
        if (it == clients.end()) {
          return std::nullopt;
        }
        return it->second;
      };
      deps.make_clipboard_backend = backend_available ? test_utils::sds::fake_backend_factory(clipboard) : std::function<std::unique_ptr<sds::clipboard::backend_t>()> {[]() {
        return std::unique_ptr<sds::clipboard::backend_t> {};
      }};
      deps.observe_sessions = false;
      ASSERT_EQ(sds::start(options, std::move(deps)), 0);
    }

    /**
     * @brief Dispatch a request and wait for its reply.
     *
     * @param op Operation.
     * @param request Request (certificate defaults to CERT_A).
     * @param wait Maximum wait.
     * @return Reply.
     */
    sds::reply_t call(sds::op_e op, sds::request_t request = {}, std::chrono::milliseconds wait = 5s) {
      if (!request.cert_pem) {
        request.cert_pem = CERT_A;
      }
      auto promise = std::make_shared<std::promise<sds::reply_t>>();
      auto future = promise->get_future();
      sds::handle(op, std::move(request), [promise](sds::reply_t reply) {
        promise->set_value(std::move(reply));
      });
      if (future.wait_for(wait) != std::future_status::ready) {
        ADD_FAILURE() << "no reply within the deadline";
        return sds::reply_t::failure(0, "timeout", "timeout");
      }
      return future.get();
    }

    /**
     * @brief Dispatch a request without waiting.
     *
     * @param op Operation.
     * @param request Request.
     * @return Future reply.
     */
    std::future<sds::reply_t> call_async(sds::op_e op, sds::request_t request) {
      auto promise = std::make_shared<std::promise<sds::reply_t>>();
      auto future = promise->get_future();
      sds::handle(op, std::move(request), [promise](sds::reply_t reply) {
        promise->set_value(std::move(reply));
      });
      return future;
    }

    /**
     * @brief Build a request.
     *
     * @param cert Certificate.
     * @param query Query parameters.
     * @param body Body.
     * @return Request.
     */
    static sds::request_t req(const std::string &cert, std::map<std::string, std::string, std::less<>> query = {}, std::string body = {}) {
      sds::request_t request;
      request.cert_pem = cert;
      request.query = std::move(query);
      request.body = std::move(body);
      return request;
    }

    /**
     * @brief Parse a JSON reply body (events and raw replies).
     *
     * @param reply Reply.
     * @return JSON.
     */
    static nlohmann::json body_json(const sds::reply_t &reply) {
      if (reply.json) {
        return *reply.json;
      }
      return nlohmann::json::parse(reply.body);
    }

    fs::path base;  ///< Scratch root.
    sds::options_t options;  ///< Module options.
    std::shared_ptr<test_utils::sds::fake_clipboard_state_t> clipboard;  ///< Fake backend state.
    bool backend_available = true;  ///< Whether the factory returns a backend.
    std::function<bool(std::string_view)> stream_override;  ///< Overrides the stream checker.
    std::mutex mutex;  ///< Protects clients and streaming.
    std::map<std::string, sds::client_t> clients;  ///< Paired clients.
    std::set<std::string> streaming;  ///< Active streams.
  };
}  // namespace

TEST(SdsModuleLifecycleTest, RequestsWhileStoppedAreUnavailable) {
  sds::stop();
  EXPECT_FALSE(sds::running());
  std::promise<sds::reply_t> promise;
  sds::handle(sds::op_e::capabilities, {}, [&promise](sds::reply_t reply) {
    promise.set_value(std::move(reply));
  });
  EXPECT_EQ(promise.get_future().get().status, 503);
  EXPECT_EQ(sds::server_features(), "");
  EXPECT_FALSE(sds::state_for_test(CERT_A).running);
  EXPECT_FALSE(sds::post_to_file_worker_for_test([]() {}));
  sds::on_stream_state(CERT_A, true);
  sds::on_client_changed(CERT_A);
  sds::drain_for_test();
}

TEST(SdsModuleLifecycleTest, OptionsFollowTheConfiguration) {
  const auto saved = config::sds;
  config::sds.clipboard = false;
  config::sds.file_chunk_max = 1234;
  config::sds.file_inbox_dir = "/srv/inbox";
  config::sds.file_uploads_max_concurrent = 5;
  config::sds.file_upload_idle_timeout = 30s;
  const auto options = sds::options_from_config();
  EXPECT_FALSE(options.clipboard);
  EXPECT_EQ(options.files.chunk_max, 1234u);
  EXPECT_EQ(options.files.inbox, fs::path {"/srv/inbox"});
  EXPECT_EQ(options.files.uploads_max, 5u);
  EXPECT_EQ(options.files.idle_timeout, 30s);
  EXPECT_EQ(options.poll_default, 25s);
  EXPECT_EQ(options.poll_max, 30s);
  EXPECT_EQ(sds::max_request_body_size(), std::max<std::size_t>(config::sds.clipboard_image_max, 1234) + 64 * 1024);
  config::sds = saved;
}

TEST_F(SdsModuleTest, CapabilitiesReportPermittedAvailableFeatures) {
  EXPECT_TRUE(sds::running());
  auto reply = call(sds::op_e::capabilities);
  ASSERT_EQ(reply.status, 200);
  auto body = *reply.json;
  EXPECT_EQ(body["version"], 1);
  EXPECT_EQ(body["stream_active"], true);
  EXPECT_EQ(body["features"], nlohmann::json::array({"clipboard", "files"}));
  EXPECT_EQ(body["permissions"], nlohmann::json::array({"clipboard_read", "clipboard_write", "file_upload", "file_download"})) << "mic is granted but unavailable";
  EXPECT_EQ(body["limits"]["clipboard_text_max"], 1024);
  EXPECT_EQ(body["limits"]["clipboard_image_max"], 64 * 1024);
  EXPECT_EQ(body["limits"]["chunk_max"], 16 * 1024);
  EXPECT_EQ(body["limits"]["file_max"], 1024 * 1024);
  EXPECT_EQ(body["limits"]["uploads_max_concurrent"], 2);
  EXPECT_EQ(sds::server_features(), "clipboard,files");

  sds::set_mic_available(true);
  set_permission(CERT_A, sds::permission_e::clipboard_write, false);
  body = *call(sds::op_e::capabilities).json;
  EXPECT_EQ(body["features"], nlohmann::json::array({"clipboard", "files", "mic"}));
  EXPECT_EQ(body["permissions"], nlohmann::json::array({"clipboard_read", "file_upload", "file_download", "mic"}));
  EXPECT_EQ(sds::server_features(), "clipboard,files,mic");
}

TEST_F(SdsModuleTest, ClipboardIsUnavailableWithoutBackendOrWhenDisabled) {
  sds::stop();
  backend_available = false;
  start();
  EXPECT_EQ(sds::server_features(), "files");
  EXPECT_EQ(call(sds::op_e::clipboard_get, req(CERT_A, {{"type", "text/plain"}})).status, 404);
  EXPECT_EQ((*call(sds::op_e::capabilities).json)["permissions"], nlohmann::json::array({"file_upload", "file_download"}));

  sds::stop();
  backend_available = true;
  options.clipboard = false;
  options.file_transfer = false;
  start();
  EXPECT_EQ(sds::server_features(), "");
  EXPECT_EQ(call(sds::op_e::capabilities).status, 404);
  EXPECT_EQ(call(sds::op_e::events).status, 404);
  EXPECT_EQ(call(sds::op_e::outbox_list).status, 404);
  EXPECT_EQ(clipboard->starts, 0) << "a disabled clipboard never creates or starts a backend";
}

TEST_F(SdsModuleTest, PipelineStatusesAreWiredThroughTheDispatcher) {
  EXPECT_EQ(call(sds::op_e::capabilities, req("stranger")).status, 401);
  set_streaming(CERT_A, false);
  const auto no_stream = call(sds::op_e::clipboard_get, req(CERT_A, {{"type", "text/plain"}}));
  EXPECT_EQ(no_stream.status, 409);
  EXPECT_EQ(no_stream.error, "no_active_stream");
  set_streaming(CERT_A, true);
  set_permission(CERT_A, sds::permission_e::file_download, false);
  EXPECT_EQ(call(sds::op_e::outbox_list).status, 403);
  sds::request_t big = req(CERT_A, {}, std::string(17 * 1024, 'x'));
  big.id = "0123456789abcdef0123456789abcdef";
  EXPECT_EQ(call(sds::op_e::upload_chunk, big).status, 413);
}

TEST_F(SdsModuleTest, ClipboardRoundTripThroughTheDispatcher) {
  sds::request_t put = req(CERT_A, {}, "hello host");
  put.content_type = "text/plain;charset=utf-8";
  put.client_seq = "1";
  const auto stored = call(sds::op_e::clipboard_put, put);
  ASSERT_EQ(stored.status, 204);
  EXPECT_EQ(header(stored, "X-SDS-Host-Seq"), "1");
  ASSERT_EQ(clipboard->write_count(), 1u);

  const auto fetched = call(sds::op_e::clipboard_get, req(CERT_B, {{"seq", "1"}, {"type", "text/plain"}}));
  ASSERT_EQ(fetched.status, 200);
  EXPECT_EQ(fetched.body, "hello host");
  EXPECT_EQ(fetched.content_type, "text/plain; charset=utf-8");
  EXPECT_EQ(header(fetched, "X-SDS-Host-Seq"), "1");

  EXPECT_EQ(call(sds::op_e::clipboard_get, req(CERT_B, {{"seq", "0"}, {"type", "text/plain"}})).status, 410);
  EXPECT_EQ(call(sds::op_e::clipboard_get, req(CERT_B, {{"seq", "x"}, {"type", "text/plain"}})).status, 400);
  EXPECT_EQ(call(sds::op_e::clipboard_get, req(CERT_B, {{"type", "text/html"}})).status, 400);
  EXPECT_EQ(call(sds::op_e::clipboard_get, req(CERT_B)).status, 400);
  EXPECT_EQ(call(sds::op_e::clipboard_get, req(CERT_B, {{"type", "image/png"}})).status, 404);
}

TEST_F(SdsModuleTest, ClipboardRateLimitReturnsRetryAfter) {
  sds::stop();
  options.clipboard_rate = 2;
  start();
  EXPECT_EQ(call(sds::op_e::clipboard_get, req(CERT_A, {{"type", "text/plain"}})).status, 404);
  EXPECT_EQ(call(sds::op_e::clipboard_get, req(CERT_A, {{"type", "text/plain"}})).status, 404);
  const auto limited = call(sds::op_e::clipboard_get, req(CERT_A, {{"type", "text/plain"}}));
  EXPECT_EQ(limited.status, 429);
  EXPECT_EQ(header(limited, "Retry-After"), "1");
  EXPECT_EQ(call(sds::op_e::clipboard_get, req(CERT_B, {{"type", "text/plain"}})).status, 404) << "limits are per client";
}

TEST_F(SdsModuleTest, LongPollWakesOnHostClipboardChange) {
  sds::on_stream_state(CERT_A, true);
  sds::drain_for_test();
  EXPECT_TRUE(sds::state_for_test(CERT_A).clipboard_watching);

  auto poll = call_async(sds::op_e::events, req(CERT_A, {{"timeout", "55"}}));
  sds::drain_for_test();
  EXPECT_EQ(poll.wait_for(50ms), std::future_status::timeout) << "no events yet: the poll is parked";
  EXPECT_TRUE(sds::state_for_test(CERT_A).parked_poll);

  clipboard->host_set(sds::clipboard::item_t {"copied on host", std::nullopt});
  ASSERT_EQ(poll.wait_for(5s), std::future_status::ready);
  const auto reply = poll.get();
  ASSERT_EQ(reply.status, 200);
  EXPECT_EQ(reply.content_type, "application/json");
  const auto body = body_json(reply);
  ASSERT_EQ(body["events"].size(), 1u);
  EXPECT_EQ(body["events"][0]["type"], "clipboard");
  EXPECT_EQ(body["events"][0]["id"], 1);
  EXPECT_EQ(body["last_id"], 1);
  const auto seq = body["events"][0]["seq"].get<std::uint64_t>();

  const auto fetched = call(sds::op_e::clipboard_get, req(CERT_A, {{"seq", std::to_string(seq)}, {"type", "text/plain"}}));
  EXPECT_EQ(fetched.body, "copied on host");

  // Nothing newer than last_id: the next poll times out (clamped to poll_max).
  const auto started = std::chrono::steady_clock::now();
  const auto empty = call(sds::op_e::events, req(CERT_A, {{"after", std::to_string(body["last_id"].get<std::uint64_t>())}, {"timeout", "100"}}));
  const auto elapsed = std::chrono::steady_clock::now() - started;
  ASSERT_EQ(empty.status, 200);
  EXPECT_TRUE(body_json(empty)["events"].empty());
  EXPECT_EQ(body_json(empty)["last_id"], 1);
  EXPECT_GE(elapsed, 900ms);
  EXPECT_LT(elapsed, 4s);
}

TEST_F(SdsModuleTest, LongPollParametersAreValidated) {
  EXPECT_EQ(call(sds::op_e::events, req(CERT_A, {{"after", "-1"}})).status, 400);
  EXPECT_EQ(call(sds::op_e::events, req(CERT_A, {{"timeout", "soon"}})).status, 400);
  const auto immediate = call(sds::op_e::events, req(CERT_A, {{"after", "0"}, {"timeout", "0"}}), 200ms);
  EXPECT_EQ(immediate.status, 200) << "timeout=0 never parks";
  EXPECT_EQ(body_json(immediate)["last_id"], 0);
  const auto default_started = std::chrono::steady_clock::now();
  EXPECT_EQ(call(sds::op_e::events, req(CERT_A)).status, 200);
  EXPECT_GE(std::chrono::steady_clock::now() - default_started, 250ms);
}

TEST_F(SdsModuleTest, StreamEndCompletesParkedPollAndClearsAllClientState) {
  sds::on_stream_state(CERT_A, true);
  sds::drain_for_test();

  // Build up state of every kind for client A.
  const nlohmann::json upload {{"name", "partial.bin"}, {"size", 10}, {"sha256", test_utils::sds::sha256_hex("0123456789")}};
  const auto created = call(sds::op_e::upload_create, req(CERT_A, {}, upload.dump()));
  ASSERT_EQ(created.status, 201);
  const auto id = created.json->at("id").get<std::string>();
  const auto part = options.files.inbox / ("." + id + ".part");
  ASSERT_TRUE(fs::exists(part));
  EXPECT_EQ(call(sds::op_e::clipboard_get, req(CERT_A, {{"type", "text/plain"}})).status, 404);
  clipboard->host_set(sds::clipboard::item_t {"queued", std::nullopt});
  sds::drain_for_test();
  auto before = sds::state_for_test(CERT_A);
  EXPECT_TRUE(before.active);
  EXPECT_EQ(before.open_uploads, 1u);
  EXPECT_EQ(before.queued_events, 1u);
  EXPECT_TRUE(before.rate_bucket);
  EXPECT_TRUE(before.clipboard_watching);
  EXPECT_TRUE(before.clipboard_content);

  auto seen = call(sds::op_e::events, req(CERT_A));
  auto poll = call_async(sds::op_e::events, req(CERT_A, {{"after", std::to_string(body_json(seen)["last_id"].get<std::uint64_t>())}, {"timeout", "55"}}));
  sds::drain_for_test();
  ASSERT_TRUE(sds::state_for_test(CERT_A).parked_poll);

  // A stop notification while another session of the client still runs changes nothing.
  sds::on_stream_state(CERT_A, false);
  sds::drain_for_test();
  EXPECT_TRUE(sds::state_for_test(CERT_A).active);
  EXPECT_EQ(poll.wait_for(10ms), std::future_status::timeout);

  set_streaming(CERT_A, false);
  sds::on_stream_state(CERT_A, false);
  ASSERT_EQ(poll.wait_for(5s), std::future_status::ready);
  const auto ended = body_json(poll.get());
  ASSERT_EQ(ended["events"].size(), 1u);
  EXPECT_EQ(ended["events"][0]["type"], "stream_ended");
  EXPECT_EQ(ended["events"][0]["id"], 2);

  const auto after = sds::state_for_test(CERT_A);
  EXPECT_FALSE(after.active);
  EXPECT_EQ(after.open_uploads, 0u);
  EXPECT_FALSE(fs::exists(part)) << "partial uploads are deleted with the stream";
  EXPECT_EQ(after.queued_events, 0u);
  EXPECT_FALSE(after.event_state);
  EXPECT_FALSE(after.parked_poll);
  EXPECT_FALSE(after.rate_bucket);
  EXPECT_FALSE(after.clipboard_watching) << "nobody permitted is streaming any more";
  EXPECT_FALSE(after.clipboard_content) << "cached host clipboard content is dropped";
  EXPECT_EQ(clipboard->stops, 1);

  EXPECT_EQ(call(sds::op_e::events, req(CERT_A)).status, 409);
}

TEST_F(SdsModuleTest, PollRacingWithStreamEndCompletesImmediately) {
  auto calls = std::make_shared<std::atomic_int>(0);
  stream_override = [calls](std::string_view) {
    // Authorization sees the stream, the post-park re-check sees it gone.
    return (*calls)++ == 0;
  };
  const auto reply = call(sds::op_e::events, req(CERT_A, {{"timeout", "55"}}), 2s);
  ASSERT_EQ(reply.status, 200);
  EXPECT_EQ(body_json(reply)["events"][0]["type"], "stream_ended");
  stream_override = nullptr;
}

TEST_F(SdsModuleTest, StreamStartAnnouncesCurrentHostClipboard) {
  clipboard->content = sds::clipboard::item_t {"already there", std::nullopt};
  sds::on_stream_state(CERT_A, true);
  sds::drain_for_test();
  EXPECT_EQ(sds::state_for_test(CERT_A).queued_events, 1u);
  const auto events = body_json(call(sds::op_e::events, req(CERT_A)));
  EXPECT_EQ(events["events"][0]["type"], "clipboard");

  // A start notification for a session that already ended is ignored.
  set_streaming(CERT_B, false);
  sds::on_stream_state(CERT_B, true);
  sds::drain_for_test();
  EXPECT_FALSE(sds::state_for_test(CERT_B).active);
}

TEST_F(SdsModuleTest, PermissionChangesTakeEffectImmediately) {
  sds::on_stream_state(CERT_A, true);
  sds::drain_for_test();
  const nlohmann::json upload {{"name", "a.bin"}, {"size", 3}, {"sha256", test_utils::sds::sha256_hex("abc")}};
  ASSERT_EQ(call(sds::op_e::upload_create, req(CERT_A, {}, upload.dump())).status, 201);

  set_permission(CERT_A, sds::permission_e::file_upload, false);
  set_permission(CERT_A, sds::permission_e::clipboard_read, false);
  set_permission(CERT_A, sds::permission_e::clipboard_write, false);
  sds::on_client_changed(CERT_A);
  const auto state = sds::state_for_test(CERT_A);
  EXPECT_EQ(state.open_uploads, 0u) << "revoking file_upload drops open uploads";
  EXPECT_FALSE(state.clipboard_watching);
  const auto events = body_json(call(sds::op_e::events, req(CERT_A)));
  ASSERT_EQ(events["events"].size(), 1u);
  EXPECT_EQ(events["events"][0]["type"], "capabilities");

  // Changes for clients without a stream only drop their uploads.
  sds::on_client_changed(CERT_B);
  EXPECT_FALSE(sds::state_for_test(CERT_B).event_state);
}

TEST_F(SdsModuleTest, OutboxChangesAreAnnouncedToDownloaders) {
  fs::create_directories(options.files.outbox);
  test_utils::sds::write_file(options.files.outbox / "before.txt", "b");
  sds::on_stream_state(CERT_A, true);
  sds::drain_for_test();
  std::this_thread::sleep_for(120ms);
  EXPECT_EQ(sds::state_for_test(CERT_A).queued_events, 0u) << "files present at stream start are not announced";

  test_utils::sds::write_file(options.files.outbox / "new.txt", "n");
  const auto reply = call(sds::op_e::events, req(CERT_A, {{"timeout", "55"}}));
  const auto body = body_json(reply);
  ASSERT_EQ(body["events"].size(), 1u);
  EXPECT_EQ(body["events"][0]["type"], "outbox");
  EXPECT_EQ(body["events"][0]["count"], 2);

  // Polling stops once no downloader streams.
  set_streaming(CERT_A, false);
  sds::on_stream_state(CERT_A, false);
  sds::drain_for_test();
  std::this_thread::sleep_for(120ms);
  EXPECT_FALSE(sds::state_for_test(CERT_A).event_state);
}

TEST_F(SdsModuleTest, FileOperationsThroughTheDispatcher) {
  const std::string data = "file transfer payload";
  const nlohmann::json upload {{"name", "notes.txt"}, {"size", data.size()}, {"sha256", test_utils::sds::sha256_hex(data)}};
  const auto created = call(sds::op_e::upload_create, req(CERT_A, {}, upload.dump()));
  ASSERT_EQ(created.status, 201);
  auto chunk = req(CERT_A, {{"offset", "0"}}, data);
  chunk.id = created.json->at("id").get<std::string>();
  const auto written = call(sds::op_e::upload_chunk, chunk);
  ASSERT_EQ(written.status, 200);
  EXPECT_EQ(written.json->at("offset"), data.size());

  auto bad_offset = req(CERT_A, {{"offset", "abc"}}, "x");
  bad_offset.id = chunk.id;
  EXPECT_EQ(call(sds::op_e::upload_chunk, bad_offset).status, 400);
  auto bad_id = req(CERT_A, {{"offset", "0"}}, "x");
  bad_id.id = "../../etc";
  EXPECT_EQ(call(sds::op_e::upload_chunk, bad_id).status, 404);

  auto other = req(CERT_B);
  other.id = chunk.id;
  EXPECT_EQ(call(sds::op_e::upload_complete, other).status, 404) << "S10: another client's session";
  EXPECT_EQ(call(sds::op_e::upload_cancel, other).status, 404);

  auto complete = req(CERT_A);
  complete.id = chunk.id;
  const auto done = call(sds::op_e::upload_complete, complete);
  ASSERT_EQ(done.status, 201);
  EXPECT_EQ(done.json->at("name"), "notes.txt");
  EXPECT_EQ(test_utils::sds::read_file(options.files.inbox / "notes.txt"), data);

  fs::create_directories(options.files.outbox);
  test_utils::sds::write_file(options.files.outbox / "out.bin", "outbound");
  const auto listing = call(sds::op_e::outbox_list);
  ASSERT_EQ(listing.status, 200);
  ASSERT_EQ(listing.json->at("files").size(), 1u);
  auto read = req(CERT_A, {{"offset", "2"}, {"length", "3"}});
  read.id = listing.json->at("files")[0]["id"].get<std::string>();
  const auto bytes = call(sds::op_e::outbox_read, read);
  ASSERT_EQ(bytes.status, 200);
  EXPECT_EQ(bytes.body, "tbo");
  EXPECT_EQ(header(bytes, "X-SDS-File-Size"), "8");

  auto bad_length = req(CERT_A, {{"length", "lots"}});
  bad_length.id = read.id;
  EXPECT_EQ(call(sds::op_e::outbox_read, bad_length).status, 400);
  auto too_long = req(CERT_A, {{"length", std::to_string(16 * 1024 + 1)}});
  too_long.id = read.id;
  EXPECT_EQ(call(sds::op_e::outbox_read, too_long).status, 413);
}

TEST_F(SdsModuleTest, BusyFileWorkerDoesNotBlockClipboardOrEvents) {
  std::promise<void> release;
  auto released = release.get_future().share();
  ASSERT_TRUE(sds::post_to_file_worker_for_test([released]() {
    released.wait();
  }));
  auto listing = call_async(sds::op_e::outbox_list, req(CERT_A));
  EXPECT_EQ(listing.wait_for(50ms), std::future_status::timeout);

  EXPECT_EQ(call(sds::op_e::capabilities).status, 200);
  EXPECT_EQ(call(sds::op_e::clipboard_get, req(CERT_A, {{"type", "text/plain"}})).status, 404);

  release.set_value();
  ASSERT_EQ(listing.wait_for(5s), std::future_status::ready);
  EXPECT_EQ(listing.get().status, 200);
}

TEST_F(SdsModuleTest, StopReleasesParkedPollsAndRejectsLateWork) {
  auto poll = call_async(sds::op_e::events, req(CERT_A, {{"timeout", "55"}}));
  sds::drain_for_test();
  sds::stop();
  ASSERT_EQ(poll.wait_for(5s), std::future_status::ready);
  EXPECT_EQ(body_json(poll.get())["events"][0]["type"], "stream_ended");
  EXPECT_EQ(call(sds::op_e::capabilities).status, 503);
}
