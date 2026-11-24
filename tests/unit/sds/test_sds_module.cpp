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
#include <fstream>
#include <map>
#include <mutex>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

// local includes
#include <src/config.h>
#include <src/sds/file_clipboard.h>
#include <src/sds/sds.h>

#ifdef __linux__
  #include <cstdlib>
  #include <sys/stat.h>
  #include <unistd.h>
#endif
#include <src/utility.h>

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
      deps.stage_file_clipboard = stage_override;
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
    std::function<std::shared_ptr<const sds::file_clipboard::stage_t>(std::string_view, const std::function<bool()> &)> stage_override;  ///< Overrides file clipboard staging.
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
  EXPECT_FALSE(sds::post_to_file_worker_for_test([]() {
  }));
  EXPECT_FALSE(sds::post_to_control_worker_for_test([]() {
  }));
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

TEST_F(SdsModuleTest, NativeFileClipboardBaselineNeverSendsDataAndEpochEndsOnReconnect) {
  using enum sds::op_e;
  options.file_clipboard = true;
  {
    const std::lock_guard lock {clipboard->mutex};
    clipboard->native_file_clipboard = true;
  }
  start();
  sds::on_stream_state(CERT_A, true);
  sds::drain_for_test();
  EXPECT_NE(sds::server_features().find("file_clipboard"), std::string::npos);
  set_permission(CERT_A, sds::permission_e::file_download, false);
  const auto baseline = call(file_clipboard_get);
  ASSERT_EQ(baseline.status, 204);
  EXPECT_FALSE(baseline.json);
  EXPECT_TRUE(baseline.body.empty());
  const auto epoch = header(baseline, "X-SDS-Clipboard-Epoch");
  const auto seq = header(baseline, "X-SDS-Clipboard-Seq");
  ASSERT_EQ(epoch.size(), 32);
  ASSERT_FALSE(seq.empty());
  auto pull = req(CERT_A, {{"after", seq}});
  pull.file_clipboard_epoch = epoch;
  EXPECT_EQ(call(file_clipboard_get, pull).status, 403);
  set_permission(CERT_A, sds::permission_e::file_download, true);
  EXPECT_EQ(call(file_clipboard_get, pull).status, 204);

  set_streaming(CERT_A, false);
  sds::on_stream_state(CERT_A, false);
  EXPECT_EQ(call(file_clipboard_get, pull).status, 409);
  set_streaming(CERT_A, true);
  sds::on_stream_state(CERT_A, true);
  sds::drain_for_test();
  const auto reconnect = call(file_clipboard_get);
  ASSERT_EQ(reconnect.status, 204);
  EXPECT_EQ(header(reconnect, "X-SDS-Clipboard-Seq"), seq);
  EXPECT_NE(header(reconnect, "X-SDS-Clipboard-Epoch"), epoch);
  EXPECT_EQ(call(file_clipboard_get, pull).status, 409);
  auto push = req(CERT_A, {}, R"({"files":[{"name":"synthetic.txt","data":"eA=="}]})");
  push.content_type = "application/json";
  push.file_clipboard_seq = seq;
  push.file_clipboard_epoch = epoch;
  EXPECT_EQ(call(file_clipboard_put, push).status, 409);
  EXPECT_EQ(clipboard->write_count(), 0);
}

TEST_F(SdsModuleTest, ResetFileClipboardReleasesRetiredLeasesAfterGracePeriod) {
  using enum sds::op_e;
  options.file_clipboard = true;
  options.file_clipboard_lease_grace = 60ms;
  options.file_clipboard_lease_ttl = 60s;
  {
    const std::lock_guard lock {clipboard->mutex};
    clipboard->native_file_clipboard = true;
  }
  stage_override = [](std::string_view, const std::function<bool()> &) {
    return sds::file_clipboard::make_test_stage("copy\nfile:///tmp/synthetic.txt");
  };
  start();

  auto publish_one = [&]() {
    sds::on_stream_state(CERT_A, true);
    sds::drain_for_test();
    const auto baseline = call(file_clipboard_get);
    if (baseline.status != 204) {
      return baseline;
    }
    auto push = req(CERT_A, {}, R"({"files":[{"name":"synthetic.txt","data":"eA=="}]})");
    push.content_type = "application/json";
    push.file_clipboard_seq = header(baseline, "X-SDS-Clipboard-Seq");
    push.file_clipboard_epoch = header(baseline, "X-SDS-Clipboard-Epoch");
    return call(file_clipboard_put, std::move(push));
  };

  // Disconnects retire ownership and release leases after the short grace period instead of 3 minutes.
  for (int cycle = 0; cycle < 5; ++cycle) {
    ASSERT_EQ(publish_one().status, 204) << "cycle " << cycle;
    set_streaming(CERT_A, false);
    sds::on_stream_state(CERT_A, false);
    sds::drain_for_test();
    EXPECT_EQ(sds::state_for_test(CERT_A).file_clipboard_leases, 1u);
    std::this_thread::sleep_for(90ms);
    EXPECT_EQ(sds::state_for_test(CERT_A).file_clipboard_leases, 0u);
    set_streaming(CERT_A, true);
  }

  // Four rapid disconnects within the grace window fill the 4 lease slots, then recover once grace elapses.
  options.file_clipboard_lease_grace = 300ms;
  start();
  for (int i = 0; i < 4; ++i) {
    ASSERT_EQ(publish_one().status, 204) << "fill " << i;
    set_streaming(CERT_A, false);
    sds::on_stream_state(CERT_A, false);
    sds::drain_for_test();
    set_streaming(CERT_A, true);
  }
  EXPECT_EQ(sds::state_for_test(CERT_A).file_clipboard_leases, 4u);
  EXPECT_EQ(publish_one().status, 429);

  std::this_thread::sleep_for(350ms);
  EXPECT_EQ(sds::state_for_test(CERT_A).file_clipboard_leases, 0u);
  ASSERT_EQ(publish_one().status, 204);

  // Permission change via on_client_changed also retires and schedules short grace release.
  set_permission(CERT_A, sds::permission_e::file_upload, false);
  sds::on_client_changed(CERT_A);
  sds::drain_for_test();
  EXPECT_EQ(sds::state_for_test(CERT_A).file_clipboard_leases, 1u);
  std::this_thread::sleep_for(350ms);
  EXPECT_EQ(sds::state_for_test(CERT_A).file_clipboard_leases, 0u);

  // Revocation right before responding (deferred_failure after publish_file_clipboard) retires and frees too.
  set_permission(CERT_A, sds::permission_e::file_upload, true);
  options.file_clipboard_lease_grace = 60ms;
  start();
  sds::on_stream_state(CERT_A, true);
  sds::drain_for_test();
  const auto baseline = call(file_clipboard_get);
  ASSERT_EQ(baseline.status, 204);

  {
    const std::lock_guard lock {clipboard->mutex};
    clipboard->on_publish = [this]() {
      set_streaming(CERT_A, false);
    };
  }
  auto push = req(CERT_A, {}, R"({"files":[{"name":"late.txt","data":"eA=="}]})");
  push.content_type = "application/json";
  push.file_clipboard_seq = header(baseline, "X-SDS-Clipboard-Seq");
  push.file_clipboard_epoch = header(baseline, "X-SDS-Clipboard-Epoch");
  const auto revoked_reply = call(file_clipboard_put, std::move(push));
  {
    const std::lock_guard lock {clipboard->mutex};
    clipboard->on_publish = nullptr;
  }
  EXPECT_EQ(revoked_reply.status, 409);
  EXPECT_EQ(sds::state_for_test(CERT_A).file_clipboard_leases, 1u);
  std::this_thread::sleep_for(90ms);
  EXPECT_EQ(sds::state_for_test(CERT_A).file_clipboard_leases, 0u);
}

#ifdef __linux__
TEST_F(SdsModuleTest, NativeFileClipboardReadsCompleteLocalCopyAndRejectsNonFiles) {
  const auto allowed = [] { return true; };
  const auto path = base / "synthetic.bin";
  ASSERT_TRUE(std::ofstream(path, std::ios::binary).write("A\0B", 3));
  const auto prefix = "copy\nfile://";
  const auto native = prefix + path.string();
  const auto bundle = sds::file_clipboard::read_offer(native, allowed);
  ASSERT_TRUE(bundle);
  const auto expected = nlohmann::json::parse(R"({"files":[{"name":"synthetic.bin","data":"QQBC"}]})");
  EXPECT_EQ(*bundle, expected);
  EXPECT_FALSE(sds::file_clipboard::read_offer(native, [] { return false; }));
  EXPECT_FALSE(sds::file_clipboard::read_offer("cut\nfile://" + path.string(), allowed));
  EXPECT_FALSE(sds::file_clipboard::read_offer("copy\nfile://localhost" + path.string(), allowed));
  fs::create_symlink(path, base / "symlink.bin");
  EXPECT_FALSE(sds::file_clipboard::read_offer(prefix + (base / "symlink.bin").string(), allowed));
  EXPECT_FALSE(sds::file_clipboard::read_offer(prefix + base.string(), allowed));
  ASSERT_EQ(mkfifo((base / "pipe").c_str(), 0600), 0);
  EXPECT_FALSE(sds::file_clipboard::read_offer(prefix + (base / "pipe").string(), allowed));
  EXPECT_FALSE(sds::file_clipboard::read_offer(native + "\nfile://" + (base / "pipe").string(), allowed));
}

TEST_F(SdsModuleTest, NativeFileClipboardStagesPrivateFilesAndRejectsUnsafeBundles) {
  const auto *runtime = std::getenv("XDG_RUNTIME_DIR");
  if (!geteuid() || !runtime || runtime != "/run/user/" + std::to_string(geteuid())) {
    GTEST_SKIP() << "Needs the non-root user's actual private Linux runtime directory";
  }
  constexpr auto bundle = R"({"files":[{"name":"synthetic.bin","data":"QQBC"},{"name":"empty.txt","data":""}]})";
  const auto allowed = [] { return true; };
  auto staged = sds::file_clipboard::stage(bundle, allowed);
  ASSERT_TRUE(staged);
  const auto offer = sds::file_clipboard::native_offer(*staged);
  ASSERT_TRUE(offer.starts_with("copy\nfile://"));
  const auto end = offer.find('\n', 5);
  ASSERT_NE(end, std::string_view::npos);
  const fs::path path = std::string {offer.substr(12, end - 12)};
  struct stat file {};
  ASSERT_EQ(stat(path.c_str(), &file), 0);
  EXPECT_EQ(file.st_mode & 0777, 0600u);
  EXPECT_EQ(file.st_size, 3);
  EXPECT_FALSE(sds::file_clipboard::read_offer(offer, allowed)) << "receiving then recopying a staged path never echoes";
  auto stop = std::atomic_int {0};
  EXPECT_FALSE(sds::file_clipboard::stage(bundle, [&] { return stop++ < 3; }));
  for (const auto invalid : {
         R"({"files":[{"name":"../escape","data":"QQBC"}]})",
         R"({"files":[{"name":"a","data":"YR=="}]})",
         R"({"files":[{"name":"a","name":"b","data":"QQBC"}]})",
         R"({"files":[{"name":"É.txt","data":""},{"name":"é.txt","data":""}]})",
         R"({"files":[[["unbounded"]]]})",
         R"({"files":[{"name":"a","data":0}]})",
       }) {
    EXPECT_FALSE(sds::file_clipboard::stage(invalid, allowed));
  }
  staged.reset();
  EXPECT_FALSE(fs::exists(path));
  EXPECT_FALSE(fs::exists(path.parent_path()));
}

TEST_F(SdsModuleTest, NativeFileClipboardRejectsCredentialAndSunshineConfigPaths) {
  const auto allowed = [] { return true; };
  const auto offer_for = [](const fs::path &p) {
    return "copy\nfile://" + p.string();
  };

  const std::vector<fs::path> forbidden_dirs {
    base / ".ssh",
    base / ".gnupg",
    base / ".config" / "sunshine",
    base / ".config" / "custom-sunshine",
    base / "sds-sunshine",
    base / "sds-host-sunshine",
    base / "sds-custom-sunshine",
    base / "sds-host-display",
  };
  std::vector<fs::path> forbidden_files;
  for (const auto &dir : forbidden_dirs) {
    fs::create_directories(dir);
    const auto file = dir / "secret.txt";
    test_utils::sds::write_file(file, "secret");
    forbidden_files.push_back(file);
  }

  const auto custom_state_dir = base / "custom_state";
  const auto custom_creds_dir = base / "credentials";
  const auto custom_xdg = base / "xdg_cfg";
  fs::create_directories(custom_state_dir);
  fs::create_directories(custom_creds_dir);
  fs::create_directories(custom_xdg / "sunshine");
  const auto state_file = custom_state_dir / "sunshine_state.json";
  const auto pkey_file = custom_creds_dir / "cakey.pem";
  const auto sibling_cert = custom_creds_dir / "cacert.pem";
  const auto xdg_secret = custom_xdg / "sunshine" / "cakey.pem";
  test_utils::sds::write_file(state_file, "{}");
  test_utils::sds::write_file(pkey_file, "key");
  test_utils::sds::write_file(sibling_cert, "cert");
  test_utils::sds::write_file(xdg_secret, "xdgkey");

  const auto saved_file_state = config::nvhttp.file_state;
  const auto saved_creds_file = config::sunshine.credentials_file;
  const auto saved_pkey = config::nvhttp.pkey;
  const auto *old_xdg = std::getenv("XDG_CONFIG_HOME");
  const std::optional<std::string> saved_xdg = old_xdg ? std::optional<std::string> {old_xdg} : std::nullopt;
  auto restore = util::fail_guard([&]() {
    config::nvhttp.file_state = saved_file_state;
    config::sunshine.credentials_file = saved_creds_file;
    config::nvhttp.pkey = saved_pkey;
    if (saved_xdg) {
      ::setenv("XDG_CONFIG_HOME", saved_xdg->c_str(), 1);
    } else {
      ::unsetenv("XDG_CONFIG_HOME");
    }
  });
  config::nvhttp.file_state = state_file.string();
  config::sunshine.credentials_file = state_file.string();
  config::nvhttp.pkey = pkey_file.string();
  ::setenv("XDG_CONFIG_HOME", custom_xdg.c_str(), 1);

  forbidden_files.push_back(state_file);
  forbidden_files.push_back(pkey_file);
  forbidden_files.push_back(sibling_cert);
  forbidden_files.push_back(xdg_secret);

  for (const auto &path : forbidden_files) {
    EXPECT_FALSE(sds::file_clipboard::read_offer(offer_for(path), allowed)) << "must reject " << path;
  }

  const auto safe_file = base / "sunshine_notes.txt";
  test_utils::sds::write_file(safe_file, "ok");
  EXPECT_TRUE(sds::file_clipboard::read_offer(offer_for(safe_file), allowed));
}
#endif

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
  sds::on_stream_state(CERT_A, true);
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

TEST_F(SdsModuleTest, QueuedDownloadRechecksPermissionStreamAndPairing) {
  fs::create_directories(options.files.outbox);
  test_utils::sds::write_file(options.files.outbox / "private.txt", "private payload");
  const auto listed = call(sds::op_e::outbox_list);
  ASSERT_EQ(listed.status, 200);
  const auto id = listed.json->at("files")[0]["id"].get<std::string>();
  for (int revoke = 0; revoke < 3; ++revoke) {
    add_client(CERT_A, "uuid-a");
    std::promise<void> release;
    auto released = release.get_future().share();
    bool opened = false;
    auto cleanup = util::fail_guard([&]() {
      if (!opened) {
        release.set_value();
      }
    });
    ASSERT_TRUE(sds::post_to_file_worker_for_test([released]() {
      released.wait();
    }));
    auto request = req(CERT_A);
    request.id = id;
    auto queued = call_async(sds::op_e::outbox_read, request);
    EXPECT_EQ(queued.wait_for(20ms), std::future_status::timeout);
    if (revoke == 0) {
      set_permission(CERT_A, sds::permission_e::file_download, false);
    } else if (revoke == 1) {
      set_streaming(CERT_A, false);
    } else {
      std::lock_guard lock {mutex};
      clients.erase(CERT_A);
    }
    opened = true;
    release.set_value();
    ASSERT_EQ(queued.wait_for(5s), std::future_status::ready);
    const auto denied = queued.get();
    EXPECT_EQ(denied.status, revoke == 0 ? 403 : revoke == 1 ? 409 :
                                                               401);
    EXPECT_NE(denied.body, "private payload");
  }
}

TEST_F(SdsModuleTest, QueuedUploadCannotPublishAfterPermissionRevocation) {
  const std::string data = "authorized before queuing";
  const nlohmann::json upload {{"name", "revoked.txt"}, {"size", data.size()}, {"sha256", test_utils::sds::sha256_hex(data)}};
  const auto created = call(sds::op_e::upload_create, req(CERT_A, {}, upload.dump()));
  ASSERT_EQ(created.status, 201);
  auto chunk = req(CERT_A, {{"offset", "0"}}, data);
  chunk.id = created.json->at("id").get<std::string>();
  ASSERT_EQ(call(sds::op_e::upload_chunk, chunk).status, 200);
  std::promise<void> release;
  auto released = release.get_future().share();
  bool opened = false;
  auto cleanup = util::fail_guard([&]() {
    if (!opened) {
      release.set_value();
    }
  });
  ASSERT_TRUE(sds::post_to_file_worker_for_test([released]() {
    released.wait();
  }));
  auto complete = req(CERT_A);
  complete.id = chunk.id;
  auto queued = call_async(sds::op_e::upload_complete, complete);
  set_permission(CERT_A, sds::permission_e::file_upload, false);
  opened = true;
  release.set_value();
  ASSERT_EQ(queued.wait_for(5s), std::future_status::ready);
  EXPECT_EQ(queued.get().status, 403);
  EXPECT_FALSE(fs::exists(options.files.inbox / "revoked.txt"));
}

TEST_F(SdsModuleTest, QueuedWorkCannotRegainAuthorityAfterReconnectOrPermissionRegrant) {
  for (const bool reconnect : {false, true}) {
    std::promise<void> release;
    auto released = release.get_future().share();
    bool opened = false;
    auto cleanup = util::fail_guard([&]() {
      if (!opened) {
        release.set_value();
      }
    });
    ASSERT_TRUE(sds::post_to_file_worker_for_test([released]() {
      released.wait();
    }));
    auto old_request = call_async(sds::op_e::outbox_list, req(CERT_A));
    if (reconnect) {
      set_streaming(CERT_A, false);
      sds::on_stream_state(CERT_A, false);
      set_streaming(CERT_A, true);
      sds::on_stream_state(CERT_A, true);
    } else {
      set_permission(CERT_A, sds::permission_e::file_download, false);
      sds::on_client_changed(CERT_A);
      set_permission(CERT_A, sds::permission_e::file_download, true);
      sds::on_client_changed(CERT_A);
    }
    auto new_request = call_async(sds::op_e::outbox_list, req(CERT_A));
    opened = true;
    release.set_value();
    ASSERT_EQ(old_request.wait_for(5s), std::future_status::ready);
    EXPECT_EQ(old_request.get().status, reconnect ? 409 : 403);
    ASSERT_EQ(new_request.wait_for(5s), std::future_status::ready);
    EXPECT_EQ(new_request.get().status, 200) << "new requests use the current authority";
    sds::drain_for_test();
  }
}

TEST_F(SdsModuleTest, AdmissionCapturesAuthorityBeforeTheFirstClientSnapshotCanBecomeStale) {
  auto checks = std::make_shared<std::atomic_int>(0);
  stream_override = [this, checks](std::string_view) {
    if (++*checks == 1) {
      // authorize() has already copied the paired client's old permissions.
      set_permission(CERT_A, sds::permission_e::file_download, false);
      sds::on_client_changed(CERT_A);
      set_permission(CERT_A, sds::permission_e::file_download, true);
      sds::on_client_changed(CERT_A);
    }
    return true;
  };
  const auto stale = call(sds::op_e::outbox_list);
  stream_override = nullptr;
  EXPECT_EQ(stale.status, 403);
  EXPECT_EQ(call(sds::op_e::outbox_list).status, 200);
}

TEST_F(SdsModuleTest, ObservedZeroActiveTransitionCannotBeErasedByAFreshReconnectQuery) {
  std::promise<void> release;
  auto released = release.get_future().share();
  bool opened = false;
  auto cleanup = util::fail_guard([&]() { if (!opened) release.set_value(); });
  ASSERT_TRUE(sds::post_to_file_worker_for_test([released]() { released.wait(); }));
  auto stale = call_async(sds::op_e::outbox_list, req(CERT_A));
  // The observer already captured an all-streams-ended event. A newer stream is visible
  // by the time the callback receives it, so consulting stream_active() here loses history.
  sds::on_stream_state(CERT_A, false);
  sds::on_stream_state(CERT_A, true);
  auto fresh = call_async(sds::op_e::outbox_list, req(CERT_A));
  opened = true;
  release.set_value();
  ASSERT_EQ(stale.wait_for(5s), std::future_status::ready);
  EXPECT_EQ(stale.get().status, 409);
  ASSERT_EQ(fresh.wait_for(5s), std::future_status::ready);
  EXPECT_EQ(fresh.get().status, 200);
}

TEST_F(SdsModuleTest, ReconnectedUploadSurvivesDelayedCleanupOfTheOldStream) {
  sds::on_stream_state(CERT_A, true);
  sds::drain_for_test();
  std::promise<void> entered;
  auto started = entered.get_future();
  std::promise<void> release;
  auto released = release.get_future().share();
  bool opened = false;
  auto cleanup = util::fail_guard([&]() { if (!opened) release.set_value(); });
  ASSERT_TRUE(sds::post_to_control_worker_for_test([&entered, released]() { entered.set_value(); released.wait(); }));
  EXPECT_EQ(started.wait_for(5s), std::future_status::ready);
  set_streaming(CERT_A, false);
  sds::on_stream_state(CERT_A, false);
  set_streaming(CERT_A, true);
  sds::on_stream_state(CERT_A, true);
  const std::string data = "new stream upload";
  const nlohmann::json upload {{"name", "reconnected.txt"}, {"size", data.size()}, {"sha256", test_utils::sds::sha256_hex(data)}};
  const auto created = call(sds::op_e::upload_create, req(CERT_A, {}, upload.dump()));
  EXPECT_EQ(created.status, 201);
  opened = true;
  release.set_value();
  sds::drain_for_test();
  ASSERT_EQ(created.status, 201);
  EXPECT_EQ(sds::state_for_test(CERT_A).open_uploads, 1u);
  auto chunk = req(CERT_A, {{"offset", "0"}}, data);
  chunk.id = created.json->at("id").get<std::string>();
  ASSERT_EQ(call(sds::op_e::upload_chunk, chunk).status, 200);
  auto complete = req(CERT_A);
  complete.id = chunk.id;
  ASSERT_EQ(call(sds::op_e::upload_complete, complete).status, 201);
  EXPECT_EQ(test_utils::sds::read_file(options.files.inbox / "reconnected.txt"), data);
}

TEST_F(SdsModuleTest, UploadPublicationRevalidatesPermissionAfterExecutionAuthorization) {
  const std::string data = "revoke after admission";
  const nlohmann::json upload {{"name", "late-revoked.txt"}, {"size", data.size()}, {"sha256", test_utils::sds::sha256_hex(data)}};
  const auto created = call(sds::op_e::upload_create, req(CERT_A, {}, upload.dump()));
  ASSERT_EQ(created.status, 201);
  auto chunk = req(CERT_A, {{"offset", "0"}}, data);
  chunk.id = created.json->at("id").get<std::string>();
  ASSERT_EQ(call(sds::op_e::upload_chunk, chunk).status, 200);
  auto checks = std::make_shared<std::atomic_int>(0);
  stream_override = [this, checks](std::string_view) {
    // Each authorization reads the paired client before consulting the stream predicate.
    // Revoke after execution has captured its client, so only the publication check sees it.
    if (++*checks == 2) {
      set_permission(CERT_A, sds::permission_e::file_upload, false);
    }
    return true;
  };
  auto complete = req(CERT_A);
  complete.id = chunk.id;
  EXPECT_EQ(call(sds::op_e::upload_complete, complete).status, 403);
  stream_override = nullptr;
  EXPECT_FALSE(fs::exists(options.files.inbox / "late-revoked.txt"));
  EXPECT_EQ(sds::state_for_test(CERT_A).open_uploads, 0u);
}

TEST_F(SdsModuleTest, DownloadDeliveryRevalidatesPermissionAfterExecutionAuthorization) {
  fs::create_directories(options.files.outbox);
  test_utils::sds::write_file(options.files.outbox / "private.txt", "private payload");
  const auto listing = call(sds::op_e::outbox_list);
  ASSERT_EQ(listing.status, 200);
  auto request = req(CERT_A);
  request.id = listing.json->at("files")[0]["id"].get<std::string>();
  auto checks = std::make_shared<std::atomic_int>(0);
  stream_override = [this, checks](std::string_view) {
    if (++*checks == 2) {
      set_permission(CERT_A, sds::permission_e::file_download, false);
    }
    return true;
  };
  const auto denied = call(sds::op_e::outbox_read, request);
  stream_override = nullptr;
  EXPECT_EQ(denied.status, 403);
  EXPECT_NE(denied.body, "private payload");
}

TEST_F(SdsModuleTest, PendingFileJobsAreBoundedPerClientAndDoNotExcludeOtherClients) {
  std::promise<void> release;
  auto released = release.get_future().share();
  bool opened = false;
  auto cleanup = util::fail_guard([&]() {
    if (!opened) {
      release.set_value();
    }
  });
  ASSERT_TRUE(sds::post_to_file_worker_for_test([released]() {
    released.wait();
  }));
  std::vector<std::future<sds::reply_t>> accepted;
  int refused = 0;
  for (int i = 0; i < 128; ++i) {
    auto reply = call_async(sds::op_e::outbox_list, req(CERT_A));
    if (reply.wait_for(0ms) == std::future_status::ready) {
      EXPECT_EQ(reply.get().status, 429);
      ++refused;
    } else {
      accepted.push_back(std::move(reply));
    }
  }
  EXPECT_EQ(accepted.size(), 4u);
  EXPECT_EQ(refused, 124);
  auto other = call_async(sds::op_e::outbox_list, req(CERT_B));
  EXPECT_EQ(other.wait_for(0ms), std::future_status::timeout);
  EXPECT_EQ(call(sds::op_e::capabilities, req(CERT_B)).status, 200);
  opened = true;
  release.set_value();
  for (auto &reply : accepted) {
    ASSERT_EQ(reply.wait_for(5s), std::future_status::ready);
    EXPECT_EQ(reply.get().status, 200);
  }
  ASSERT_EQ(other.wait_for(5s), std::future_status::ready);
  EXPECT_EQ(other.get().status, 200);
  EXPECT_EQ(call(sds::op_e::outbox_list).status, 200) << "admission capacity is released";
}

TEST_F(SdsModuleTest, QueuedClipboardRechecksPermissionStreamAndPairing) {
  sds::on_stream_state(CERT_A, true);
  sds::drain_for_test();
  sds::clipboard::item_t host_item;
  host_item.text = "private clipboard";
  clipboard->host_set(std::move(host_item));
  sds::drain_for_test();
  for (const bool write : {false, true}) {
    for (int revoke = 0; revoke < 3; ++revoke) {
      add_client(CERT_A, "uuid-a");
      std::promise<void> release;
      auto released = release.get_future().share();
      bool opened = false;
      auto cleanup = util::fail_guard([&]() {
        if (!opened) {
          release.set_value();
        }
      });
      ASSERT_TRUE(sds::post_to_control_worker_for_test([released]() {
        released.wait();
      }));
      auto request = req(CERT_A, {{"type", "text/plain"}}, write ? "revoked content" : "");
      request.content_type = "text/plain;charset=utf-8";
      request.client_seq = std::to_string(revoke + 1);
      const auto writes = clipboard->write_count();
      auto queued = call_async(write ? sds::op_e::clipboard_put : sds::op_e::clipboard_get, std::move(request));
      EXPECT_EQ(queued.wait_for(0ms), std::future_status::timeout);
      if (revoke == 0) {
        set_permission(CERT_A, write ? sds::permission_e::clipboard_write : sds::permission_e::clipboard_read, false);
      } else if (revoke == 1) {
        set_streaming(CERT_A, false);
      } else {
        std::lock_guard lock {mutex};
        clients.erase(CERT_A);
      }
      opened = true;
      release.set_value();
      ASSERT_EQ(queued.wait_for(5s), std::future_status::ready);
      const auto reply = queued.get();
      EXPECT_EQ(reply.status, revoke == 0 ? 403 : revoke == 1 ? 409 :
                                                                401);
      EXPECT_NE(reply.body, "private clipboard");
      EXPECT_EQ(clipboard->write_count(), writes);
    }
  }
}

TEST_F(SdsModuleTest, PendingBudgetIsSharedAcrossBothWorkers) {
  std::promise<void> release;
  auto released = release.get_future().share();
  bool opened = false;
  auto cleanup = util::fail_guard([&]() {
    if (!opened) {
      release.set_value();
    }
  });
  ASSERT_TRUE(sds::post_to_file_worker_for_test([released]() {
    released.wait();
  }));
  ASSERT_TRUE(sds::post_to_control_worker_for_test([released]() {
    released.wait();
  }));
  std::vector<std::future<sds::reply_t>> accepted;
  for (int i = 0; i < 3; ++i) {
    accepted.push_back(call_async(sds::op_e::outbox_list, req(CERT_A)));
  }
  accepted.push_back(call_async(sds::op_e::clipboard_get, req(CERT_A, {{"type", "text/plain"}})));
  auto denied = call_async(sds::op_e::clipboard_get, req(CERT_A, {{"type", "text/plain"}}));
  EXPECT_EQ(denied.wait_for(100ms), std::future_status::ready);
  if (denied.wait_for(0ms) == std::future_status::ready) {
    const auto reply = denied.get();
    EXPECT_EQ(reply.status, 429);
    EXPECT_EQ(header(reply, "Retry-After"), "1");
  }
  auto other = call_async(sds::op_e::clipboard_get, req(CERT_B, {{"type", "text/plain"}}));
  EXPECT_EQ(other.wait_for(0ms), std::future_status::timeout);
  opened = true;
  release.set_value();
  for (auto &reply : accepted) {
    ASSERT_EQ(reply.wait_for(5s), std::future_status::ready);
    EXPECT_NE(reply.get().status, 429);
  }
  ASSERT_EQ(other.wait_for(5s), std::future_status::ready);
  EXPECT_NE(other.get().status, 429);
  sds::drain_for_test();
  EXPECT_NE(call(sds::op_e::clipboard_get, req(CERT_A, {{"type", "text/plain"}})).status, 429);
}

TEST_F(SdsModuleTest, PendingPayloadBytesAreBoundedPerClientAndGlobally) {
  constexpr std::size_t MIB = 1024 * 1024;
  options.files.chunk_max = 32 * MIB;
  start();
  add_client("cert-c", "uuid-c");
  std::promise<void> release;
  auto released = release.get_future().share();
  bool opened = false;
  auto cleanup = util::fail_guard([&]() {
    if (!opened) {
      release.set_value();
    }
  });
  ASSERT_TRUE(sds::post_to_file_worker_for_test([released]() {
    released.wait();
  }));
  const auto chunk = [&](const std::string &cert, std::size_t bytes) {
    auto request = req(cert, {{"offset", "0"}}, std::string(bytes, 'x'));
    request.id = std::string(32, 'a');
    return call_async(sds::op_e::upload_chunk, std::move(request));
  };
  std::vector<std::future<sds::reply_t>> accepted;
  for (const auto cert : {CERT_A, CERT_B}) {
    for (int i = 0; i < 2; ++i) {
      accepted.push_back(chunk(cert, 32 * MIB));
      EXPECT_EQ(accepted.back().wait_for(0ms), std::future_status::timeout);
    }
    auto denied = chunk(cert, 1);
    EXPECT_EQ(denied.wait_for(100ms), std::future_status::ready);
    if (denied.wait_for(0ms) == std::future_status::ready) {
      const auto reply = denied.get();
      EXPECT_EQ(reply.status, 429);
      EXPECT_EQ(header(reply, "Retry-After"), "1");
    }
  }
  auto global_denied = chunk("cert-c", 1);
  EXPECT_EQ(global_denied.wait_for(100ms), std::future_status::ready);
  if (global_denied.wait_for(0ms) == std::future_status::ready) {
    EXPECT_EQ(global_denied.get().status, 429);
  }
  opened = true;
  release.set_value();
  for (auto &reply : accepted) {
    ASSERT_EQ(reply.wait_for(5s), std::future_status::ready);
    EXPECT_EQ(reply.get().status, 404) << "unknown upload is checked after admission";
  }
  sds::drain_for_test();
  auto recovered = chunk(CERT_A, 32 * MIB);
  ASSERT_EQ(recovered.wait_for(5s), std::future_status::ready);
  EXPECT_EQ(recovered.get().status, 404) << "error paths release the entire byte reservation";
}

TEST_F(SdsModuleTest, PendingJobsHaveAGlobalBoundAcrossClients) {
  sds::on_stream_state(CERT_A, true);
  sds::drain_for_test();
  ASSERT_TRUE(sds::state_for_test(CERT_A).active);
  std::promise<void> release;
  auto released = release.get_future().share();
  bool opened = false;
  auto cleanup = util::fail_guard([&]() {
    if (!opened) {
      release.set_value();
    }
  });
  ASSERT_TRUE(sds::post_to_file_worker_for_test([released]() {
    released.wait();
  }));
  std::vector<std::future<sds::reply_t>> accepted;
  for (int client = 0; client < 8; ++client) {
    const auto cert = "global-client-" + std::to_string(client);
    add_client(cert, cert);
    for (int i = 0; i < 4; ++i) {
      accepted.push_back(call_async(sds::op_e::outbox_list, req(cert)));
      EXPECT_EQ(accepted.back().wait_for(0ms), std::future_status::timeout);
    }
  }
  auto denied = call_async(sds::op_e::outbox_list, req(CERT_A));
  EXPECT_EQ(denied.wait_for(100ms), std::future_status::ready);
  if (denied.wait_for(0ms) == std::future_status::ready) {
    EXPECT_EQ(denied.get().status, 429);
  }
  // Stream teardown is trusted lifecycle work and must survive a full request budget.
  set_streaming(CERT_A, false);
  sds::on_stream_state(CERT_A, false);
  opened = true;
  release.set_value();
  for (auto &reply : accepted) {
    ASSERT_EQ(reply.wait_for(5s), std::future_status::ready);
    EXPECT_NE(reply.get().status, 429);
  }
  sds::drain_for_test();
  EXPECT_FALSE(sds::state_for_test(CERT_A).active);
  set_streaming(CERT_A, true);
  EXPECT_EQ(call(sds::op_e::outbox_list).status, 200);
}

TEST_F(SdsModuleTest, ThrowingCompletionCallbacksReleasePendingAdmission) {
  std::promise<void> release;
  auto released = release.get_future().share();
  bool opened = false;
  auto cleanup = util::fail_guard([&]() {
    if (!opened) {
      release.set_value();
    }
  });
  ASSERT_TRUE(sds::post_to_file_worker_for_test([released]() {
    released.wait();
  }));
  std::atomic_int callbacks {0};
  for (int i = 0; i < 4; ++i) {
    sds::handle(sds::op_e::outbox_list, req(CERT_A), [&](sds::reply_t reply) {
      EXPECT_EQ(reply.status, 200);
      ++callbacks;
      throw std::runtime_error("synthetic completion failure");
    });
  }
  auto refused = call_async(sds::op_e::outbox_list, req(CERT_A));
  EXPECT_EQ(refused.wait_for(100ms), std::future_status::ready);
  if (refused.wait_for(0ms) == std::future_status::ready) {
    EXPECT_EQ(refused.get().status, 429);
  }
  opened = true;
  release.set_value();
  sds::drain_for_test();
  EXPECT_EQ(callbacks.load(), 4);
  EXPECT_EQ(call(sds::op_e::outbox_list).status, 200);
}

TEST_F(SdsModuleTest, StopReleasesParkedPollsAndRejectsLateWork) {
  auto poll = call_async(sds::op_e::events, req(CERT_A, {{"timeout", "55"}}));
  sds::drain_for_test();
  sds::stop();
  ASSERT_EQ(poll.wait_for(5s), std::future_status::ready);
  EXPECT_EQ(body_json(poll.get())["events"][0]["type"], "stream_ended");
  EXPECT_EQ(call(sds::op_e::capabilities).status, 503);
}

TEST_F(SdsModuleTest, LazyClipboardOfferStreamsClientToHostOnlyAfterPasteDemand) {
  using enum sds::op_e;
  sds::stop();
  options.file_clipboard = true;
  {
    const std::lock_guard lock {clipboard->mutex};
    clipboard->native_file_clipboard = true;
  }
  start();
  set_streaming(CERT_B, false);
  sds::on_stream_state(CERT_A, true);
  sds::drain_for_test();

  // Capabilities advertise lazy_clipboard once file_clipboard is active.
  const auto caps = body_json(call(capabilities));
  bool has_lazy = false;
  for (const auto &f : caps["features"]) {
    if (f == "lazy_clipboard") {
      has_lazy = true;
    }
  }
  EXPECT_TRUE(has_lazy);

  // 1. Copy on client publishes metadata only (zero bytes moved, zero pull events yet).
  auto put_req = req(CERT_A);
  put_req.body = R"({"offer_id":"offer_01","kind":"files","entries":[{"id":"e0","name":"hello.bin","size":20000}]})";
  ASSERT_EQ(call(clipboard_offer_put, std::move(put_req)).status, 200);

  auto pre_paste_events = body_json(call(events, req(CERT_A, {{"after", "0"}, {"timeout", "0"}})));
  for (const auto &ev : pre_paste_events["events"]) {
    EXPECT_NE(ev["type"], "clipboard_pull");
  }

  // 2. Non-manager paste demand fires clipboard_pull once.
  ASSERT_TRUE(clipboard->trigger_lazy_pull("offer_01", {"x-special/gnome-copied-files"}));
  sds::drain_for_test();
  const auto pull_events = body_json(call(events, req(CERT_A, {{"after", "0"}, {"timeout", "0"}})));
  bool saw_pull = false;
  for (const auto &ev : pull_events["events"]) {
    if (ev["type"] == "clipboard_pull" && ev["offer_id"] == "offer_01") {
      saw_pull = true;
    }
  }
  EXPECT_TRUE(saw_pull);

  // 3. Stream chunked bytes (< chunk_max split into 2 pieces) + verify SHA-256 mismatch is rejected first.
  const std::string payload = test_utils::sds::random_bytes(20000, 77);
  auto start_req = req(CERT_A);
  start_req.id = "offer_01";
  start_req.sub_id = "e0";
  ASSERT_EQ(call(clipboard_offer_entry_start, std::move(start_req)).status, 201);

  auto c1 = req(CERT_A, {{"offset", "0"}});
  c1.id = "offer_01";
  c1.sub_id = "e0";
  c1.body = payload.substr(0, 12000);
  ASSERT_EQ(call(clipboard_offer_entry_chunk, std::move(c1)).status, 200);

  auto c2 = req(CERT_A, {{"offset", "12000"}});
  c2.id = "offer_01";
  c2.sub_id = "e0";
  c2.body = payload.substr(12000);
  ASSERT_EQ(call(clipboard_offer_entry_chunk, std::move(c2)).status, 200);

  auto bad_complete = req(CERT_A);
  bad_complete.id = "offer_01";
  bad_complete.body = R"({"entries":[{"id":"e0","sha256":"0000000000000000000000000000000000000000000000000000000000000000"}]})";
  EXPECT_EQ(call(clipboard_offer_complete, std::move(bad_complete)).status, 422);

  // Re-offer cleanly with valid SHA-256 and complete.
  auto put_req2 = req(CERT_A);
  put_req2.body = R"({"offer_id":"offer_02","kind":"files","entries":[{"id":"e0","name":"hello.bin","size":20000}]})";
  ASSERT_EQ(call(clipboard_offer_put, std::move(put_req2)).status, 200);
  auto s2 = req(CERT_A);
  s2.id = "offer_02";
  s2.sub_id = "e0";
  ASSERT_EQ(call(clipboard_offer_entry_start, std::move(s2)).status, 201);
  auto c2a = req(CERT_A, {{"offset", "0"}});
  c2a.id = "offer_02";
  c2a.sub_id = "e0";
  c2a.body = payload.substr(0, 12000);
  ASSERT_EQ(call(clipboard_offer_entry_chunk, std::move(c2a)).status, 200);

  auto c2b = req(CERT_A, {{"offset", "12000"}});
  c2b.id = "offer_02";
  c2b.sub_id = "e0";
  c2b.body = payload.substr(12000);
  ASSERT_EQ(call(clipboard_offer_entry_chunk, std::move(c2b)).status, 200);

  auto ok_complete = req(CERT_A);
  ok_complete.id = "offer_02";
  ok_complete.body = nlohmann::json {{"entries", {{{"id", "e0"}, {"sha256", test_utils::sds::sha256_hex(payload)}}}}}.dump();
  ASSERT_EQ(call(clipboard_offer_complete, std::move(ok_complete)).status, 200);

  const std::lock_guard lock {clipboard->mutex};
  ASSERT_FALSE(clipboard->lazy_completed.empty());
  const auto &native = clipboard->lazy_completed.back().second;
  ASSERT_TRUE(native.starts_with("copy\nfile://"));
  const fs::path staged_file = native.substr(12);
  EXPECT_EQ(test_utils::sds::read_file(staged_file), payload);
}

TEST_F(SdsModuleTest, LazyClipboardOfferStreamsHostFilesAndLargePngInChunks) {
  using enum sds::op_e;
  sds::stop();
  options.file_clipboard = true;
  options.lazy_image_threshold = 32;  // Trigger lazy staging for PNGs > 32 bytes.
  {
    const std::lock_guard lock {clipboard->mutex};
    clipboard->native_file_clipboard = true;
  }
  start();
  set_streaming(CERT_B, false);
  sds::on_stream_state(CERT_A, true);
  sds::drain_for_test();

  // Host copies a synthetic regular file (> chunk_max to test chunked range read).
  const auto src_path = base / "big_host.bin";
  const std::string host_bytes = test_utils::sds::random_bytes(24000, 99);
  ASSERT_TRUE(std::ofstream(src_path, std::ios::binary).write(host_bytes.data(), static_cast<std::streamsize>(host_bytes.size())));
  clipboard->host_set(::sds::clipboard::item_t {std::nullopt, std::nullopt, "copy\nfile://" + src_path.string()});
  sds::drain_for_test();

  const auto evs = body_json(call(events, req(CERT_A, {{"after", "0"}, {"timeout", "0"}})));
  std::string offer_id;
  for (const auto &ev : evs["events"]) {
    if (ev["type"] == "clipboard_offer" && ev["kind"] == "files") {
      offer_id = ev["offer_id"].get<std::string>();
      ASSERT_EQ(ev["entries"].size(), 1u);
      EXPECT_EQ(ev["entries"][0]["name"], "big_host.bin");
      EXPECT_EQ(ev["entries"][0]["size"], 24000u);
    }
  }
  ASSERT_FALSE(offer_id.empty());

  auto r1 = req(CERT_A, {{"offset", "0"}, {"length", "16384"}});
  r1.id = offer_id;
  r1.sub_id = "e0";
  const auto rep1 = call(clipboard_offer_entry_read, std::move(r1));
  ASSERT_EQ(rep1.status, 200);
  EXPECT_EQ(header(rep1, "X-SDS-Chunk-Sha256"), test_utils::sds::sha256_hex(host_bytes.substr(0, 16384)));

  auto r2 = req(CERT_A, {{"offset", "16384"}, {"length", "16384"}});
  r2.id = offer_id;
  r2.sub_id = "e0";
  const auto rep2 = call(clipboard_offer_entry_read, std::move(r2));
  ASSERT_EQ(rep2.status, 200);
  EXPECT_EQ(rep1.body + rep2.body, host_bytes);
  EXPECT_EQ(header(rep2, "X-SDS-File-Sha256"), test_utils::sds::sha256_hex(host_bytes));
}

TEST_F(SdsModuleTest, UnifiedDropCommitsToInboxFallbackWithCollisionAndNoExecBits) {
  using enum sds::op_e;
  const std::string data_a = test_utils::sds::random_bytes(5000, 12);
  const std::string data_b = test_utils::sds::random_bytes(3000, 34);

  auto post_drop = [&](const std::string &payload) {
    auto create_req = req(CERT_A);
    create_req.body = nlohmann::json {{"nx", 0.5}, {"ny", 0.5}, {"name", "drop_item.bin"}, {"size", payload.size()}}.dump();
    const auto create_rep = call(drop_create, std::move(create_req));
    EXPECT_EQ(create_rep.status, 201);
    const auto drop_id = body_json(create_rep)["id"].get<std::string>();

    auto chunk_req = req(CERT_A, {{"offset", "0"}});
    chunk_req.id = drop_id;
    chunk_req.body = payload;
    EXPECT_EQ(call(drop_chunk, std::move(chunk_req)).status, 200);

    auto complete_req = req(CERT_A);
    complete_req.id = drop_id;
    complete_req.body = nlohmann::json {{"sha256", test_utils::sds::sha256_hex(payload)}}.dump();
    return call(drop_complete, std::move(complete_req));
  };

  // In unit tests without a matching XdndAware target at (0.5, 0.5), fallback commits to inbox safely.
  const auto rep_a = post_drop(data_a);
  ASSERT_EQ(rep_a.status, 200);
  const auto json_a = body_json(rep_a);
  if (json_a["delivered"] == "inbox") {
    EXPECT_EQ(json_a["files"][0], "drop_item.bin");
    EXPECT_EQ(test_utils::sds::read_file(options.files.inbox / "drop_item.bin"), data_a);
#ifdef __linux__
    struct stat st {};
    ASSERT_EQ(stat((options.files.inbox / "drop_item.bin").c_str(), &st), 0);
    EXPECT_EQ(st.st_mode & 0111, 0u);
#endif
    const auto rep_b = post_drop(data_b);
    ASSERT_EQ(rep_b.status, 200);
    const auto json_b = body_json(rep_b);
    EXPECT_EQ(json_b["delivered"], "inbox");
    EXPECT_EQ(json_b["files"][0], "drop_item (1).bin");
    EXPECT_EQ(test_utils::sds::read_file(options.files.inbox / "drop_item (1).bin"), data_b);
  }
}
