/**
 * @file tests/unit/sds/test_sds_http.cpp
 * @brief End-to-end tests of `/sds/v1` over the production HTTPS server with client
 *        certificates (checks S1, S2, S6, S10; asynchronous responses).
 */

// test includes
#include "../../tests_common.h"
#include "fake_clipboard_backend.h"
#include "sds_test_utils.h"

// standard includes
#include <chrono>
#include <filesystem>
#include <format>
#include <fstream>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <thread>

// lib includes
#include <Simple-Web-Server/client_http.hpp>
#include <Simple-Web-Server/client_https.hpp>
#include <Simple-Web-Server/server_http.hpp>

// local includes
#include <src/config.h>
#include <src/crypto.h>
#include <src/nvhttp.h>
#include <src/sds/http.h>
#include <src/sds/sds.h>

namespace fs = std::filesystem;
using namespace std::literals;

namespace {
  using https_client_t = SimpleWeb::Client<SimpleWeb::HTTPS>;
  using http_client_t = SimpleWeb::Client<SimpleWeb::HTTP>;

  /**
   * @brief Credentials written to disk for Simple-Web-Server.
   */
  struct credential_files_t {
    std::string cert_pem;  ///< Canonical certificate PEM.
    fs::path cert;  ///< Certificate file.
    fs::path key;  ///< Private key file.
  };

  /**
   * @brief Result of a request that may fail at the transport level.
   */
  struct result_t {
    int status = 0;  ///< HTTP status (0 when the connection failed).
    std::string body;  ///< Response body.
    SimpleWeb::CaseInsensitiveMultimap header;  ///< Response headers.
  };

  /**
   * @brief Paired HTTPS server with the sds routes and a plain HTTP server with the guard.
   */
  class SdsHttpTest: public BaseTest {
  protected:
    void SetUp() override {
      BaseTest::SetUp();
      base = test_utils::sds::scratch_dir("sds_http");
      saved_state_file = config::nvhttp.file_state;
      saved_fresh_state = config::sunshine.flags[config::flag::FRESH_STATE];
      config::nvhttp.file_state = (base / "state.json").string();
      config::sunshine.flags[config::flag::FRESH_STATE] = false;
      nvhttp::test_support::reset_client_state();

      server_creds = write_creds("server", crypto::gen_creds("Sunshine SDS Test Server", 2048));
      client_a = write_creds("a", crypto::gen_creds("SDS Client A", 2048));
      client_b = write_creds("b", crypto::gen_creds("SDS Client B", 2048));
      stranger = write_creds("stranger", crypto::gen_creds("SDS Stranger", 2048));
      uuid_a = nvhttp::test_support::add_client("A", client_a.cert_pem, true);
      uuid_b = nvhttp::test_support::add_client("B", client_b.cert_pem, true);
      ASSERT_FALSE(uuid_a.empty());
      ASSERT_FALSE(uuid_b.empty());
      const std::vector<std::string> all {"clipboard_read", "clipboard_write", "file_upload", "file_download"};
      ASSERT_TRUE(nvhttp::set_client_permissions(uuid_a, all));
      ASSERT_TRUE(nvhttp::set_client_permissions(uuid_b, all));
      {
        std::lock_guard lock {mutex};
        streaming = {client_a.cert_pem, client_b.cert_pem};
      }

      options.files.inbox = base / "inbox";
      options.files.outbox = base / "outbox";
      options.files.chunk_max = 64 * 1024;
      options.clipboard_text_max = 16 * 1024;
      options.clipboard_image_max = 128 * 1024;
      options.files.min_free_space = 0;
      sds::dependencies_t deps;
      deps.stream_active = [this](std::string_view cert) {
        std::lock_guard lock {mutex};
        return streaming.contains(std::string {cert});
      };
      deps.make_clipboard_backend = test_utils::sds::fake_backend_factory(std::make_shared<test_utils::sds::fake_clipboard_state_t>());
      deps.observe_sessions = false;
      ASSERT_EQ(sds::start(options, std::move(deps)), 0);

      https_server = nvhttp::test_support::make_verifying_https_server(server_creds.cert.string(), server_creds.key.string(), handler_scope);
      https_server->config.address = "127.0.0.1";
      https_server->config.port = 0;
      https_server->resource["^/serverinfo$"]["GET"] = nvhttp::test_support::serverinfo_https;
      sds::http::register_routes(*https_server);
      EXPECT_EQ(https_server->config.max_request_streambuf_size, sds::max_request_body_size());
      std::promise<unsigned short> https_port_promise;
      auto https_port_future = https_port_promise.get_future();
      https_thread = std::jthread([this, promise = std::move(https_port_promise)]() mutable {
        https_server->start([&promise](unsigned short port) {
          promise.set_value(port);
        });
      });
      ASSERT_EQ(https_port_future.wait_for(10s), std::future_status::ready);
      https_port = https_port_future.get();

      http_server = std::make_unique<SimpleWeb::Server<SimpleWeb::HTTP>>();
      http_server->config.address = "127.0.0.1";
      http_server->config.port = 0;
      sds::http::register_plain_http_guard(*http_server);
      std::promise<unsigned short> http_port_promise;
      auto http_port_future = http_port_promise.get_future();
      http_thread = std::jthread([this, promise = std::move(http_port_promise)]() mutable {
        http_server->start([&promise](unsigned short port) {
          promise.set_value(port);
        });
      });
      ASSERT_EQ(http_port_future.wait_for(10s), std::future_status::ready);
      http_port = http_port_future.get();
    }

    void TearDown() override {
      // Release parked responses before the servers go away, as nvhttp::start() does.
      sds::stop();
      if (https_server) {
        https_server->stop();
      }
      if (http_server) {
        http_server->stop();
      }
      if (https_thread.joinable()) {
        https_thread.join();
      }
      if (http_thread.joinable()) {
        http_thread.join();
      }
      https_server.reset();
      http_server.reset();
      nvhttp::test_support::reset_client_state();
      config::nvhttp.file_state = saved_state_file;
      config::sunshine.flags[config::flag::FRESH_STATE] = saved_fresh_state;
      std::error_code ec;
      fs::remove_all(base, ec);
      BaseTest::TearDown();
    }

    /**
     * @brief Write credentials to the scratch directory.
     *
     * @param name File prefix.
     * @param creds Credentials.
     * @return Paths and canonical PEM.
     */
    credential_files_t write_creds(const std::string &name, const crypto::creds_t &creds) {
      credential_files_t files;
      auto certificate = crypto::x509(creds.x509);
      files.cert_pem = crypto::pem(certificate);
      files.cert = base / (name + "_cert.pem");
      files.key = base / (name + "_key.pem");
      test_utils::sds::write_file(files.cert, creds.x509);
      test_utils::sds::write_file(files.key, creds.pkey);
      return files;
    }

    /**
     * @brief HTTPS client presenting a certificate (or none).
     *
     * @param creds Credentials, or nullptr for no client certificate.
     * @return Client.
     */
    std::unique_ptr<https_client_t> client(const credential_files_t *creds) const {
      auto result = creds ? std::make_unique<https_client_t>(std::format("127.0.0.1:{}", https_port), false, creds->cert.string(), creds->key.string()) : std::make_unique<https_client_t>(std::format("127.0.0.1:{}", https_port), false);
      result->config.timeout = 10;
      return result;
    }

    /**
     * @brief Perform a request, mapping transport failures to status 0.
     *
     * @tparam Client Client type.
     * @param client Client.
     * @param method Method.
     * @param path Path and query.
     * @param body Body.
     * @param headers Headers.
     * @return Result.
     */
    template<class Client>
    static result_t send(Client &client, const std::string &method, const std::string &path, const std::string &body = {}, const SimpleWeb::CaseInsensitiveMultimap &headers = {}) {
      result_t result;
      try {
        auto response = client.request(method, path, body, headers);
        result.status = std::stoi(response->status_code.substr(0, 3));
        result.body = response->content.string();
        result.header = response->header;
      } catch (const std::exception &) {
        result.status = 0;
      }
      return result;
    }

    /**
     * @brief Set the active-stream state of a certificate.
     *
     * @param cert Certificate PEM.
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

    fs::path base;  ///< Scratch root.
    std::string saved_state_file;  ///< Restored after the test.
    bool saved_fresh_state = false;  ///< Restored after the test.
    credential_files_t server_creds;  ///< Server identity.
    credential_files_t client_a;  ///< Paired client A.
    credential_files_t client_b;  ///< Paired client B.
    credential_files_t stranger;  ///< Unpaired client.
    std::string uuid_a;  ///< UUID of A.
    std::string uuid_b;  ///< UUID of B.
    sds::options_t options;  ///< Module options.
    std::mutex mutex;  ///< Protects streaming.
    std::set<std::string> streaming;  ///< Active streams.
    std::shared_ptr<SimpleWeb::ScopeRunner> handler_scope;  ///< HTTPS handler scope.
    std::unique_ptr<SimpleWeb::ServerBase<nvhttp::SunshineHTTPS>> https_server;  ///< Paired server.
    std::unique_ptr<SimpleWeb::Server<SimpleWeb::HTTP>> http_server;  ///< Plain server.
    std::jthread https_thread;  ///< Runs the HTTPS server.
    std::jthread http_thread;  ///< Runs the HTTP server.
    unsigned short https_port = 0;  ///< HTTPS port.
    unsigned short http_port = 0;  ///< HTTP port.
  };
}  // namespace

TEST_F(SdsHttpTest, PairedClientGetsCapabilitiesAsJson) {
  auto a = client(&client_a);
  const auto reply = send(*a, "GET", "/sds/v1/capabilities");
  ASSERT_EQ(reply.status, 200) << reply.body;
  const auto body = nlohmann::json::parse(reply.body);
  EXPECT_EQ(body["version"], 1);
  EXPECT_EQ(body["permissions"], nlohmann::json::array({"clipboard_read", "clipboard_write", "file_upload", "file_download"}));
  EXPECT_EQ(reply.header.find("Content-Type")->second, "application/json");
  EXPECT_EQ(reply.header.find("Cache-Control")->second, "no-store");
  EXPECT_EQ(nvhttp::test_support::verified_connection_count(), 1u);
}

TEST_F(SdsHttpTest, PlainHttpNeverRoutesSdsEndpoints) {
  http_client_t plain {std::format("127.0.0.1:{}", http_port)};
  plain.config.timeout = 10;
  const nlohmann::json upload {{"name", "x"}, {"size", 1}, {"sha256", test_utils::sds::sha256_hex("x")}};
  for (const auto *method : {"GET", "PUT", "POST", "DELETE", "PATCH", "OPTIONS"}) {
    for (const auto *path : {"/sds/v1/capabilities", "/sds/v1/files/uploads", "/sds/v1/clipboard", "/sds", "/sds/anything"}) {
      http_client_t fresh {std::format("127.0.0.1:{}", http_port)};
      fresh.config.timeout = 10;
      const auto reply = send(fresh, method, path, upload.dump());
      EXPECT_EQ(reply.status, 404) << method << ' ' << path;
    }
  }
  EXPECT_EQ(sds::state_for_test(client_a.cert_pem).open_uploads, 0u);
}

TEST_F(SdsHttpTest, ClientsWithoutPairedCertificateAreRejected) {
  // No client certificate: the TLS handshake fails before HTTP.
  auto anonymous = client(nullptr);
  EXPECT_EQ(send(*anonymous, "GET", "/sds/v1/capabilities").status, 0);

  // Unknown certificate: nvhttp's verify callback answers with its 401 document; sds is never reached.
  auto unknown = client(&stranger);
  const auto reply = send(*unknown, "GET", "/sds/v1/capabilities");
  EXPECT_TRUE(reply.body.empty() || reply.body.find("status_code=\"401\"") != std::string::npos) << reply.body;
  EXPECT_EQ(reply.body.find("\"version\""), std::string::npos);
  EXPECT_EQ(nvhttp::test_support::verified_connection_count(), 0u);

  // A client unpaired while its keep-alive connection stays open loses access immediately.
  auto a = client(&client_a);
  ASSERT_EQ(send(*a, "GET", "/sds/v1/capabilities").status, 200);
  ASSERT_TRUE(nvhttp::set_client_enabled(uuid_a, false));
  const auto disabled = send(*a, "GET", "/sds/v1/capabilities");
  EXPECT_EQ(disabled.status, 401);
  EXPECT_EQ(nlohmann::json::parse(disabled.body)["error"], "unauthorized");
}

TEST_F(SdsHttpTest, NoStreamAndMissingPermissionOverHttps) {
  auto a = client(&client_a);
  set_streaming(client_a.cert_pem, false);
  const auto no_stream = send(*a, "GET", "/sds/v1/files/outbox");
  EXPECT_EQ(no_stream.status, 409);
  EXPECT_EQ(nlohmann::json::parse(no_stream.body)["error"], "no_active_stream");
  set_streaming(client_a.cert_pem, true);
  ASSERT_TRUE(nvhttp::set_client_permissions(uuid_a, {"clipboard_read"}));
  const auto forbidden = send(*a, "GET", "/sds/v1/files/outbox");
  EXPECT_EQ(forbidden.status, 403);
  EXPECT_EQ(nlohmann::json::parse(forbidden.body)["error"], "forbidden");
}

TEST_F(SdsHttpTest, UnknownEndpointsMethodsAndDuplicateParameters) {
  auto a = client(&client_a);
  const auto unknown = send(*a, "GET", "/sds/v1/nope");
  EXPECT_EQ(unknown.status, 404);
  EXPECT_EQ(nlohmann::json::parse(unknown.body)["error"], "not_found");
  EXPECT_EQ(send(*a, "DELETE", "/sds/v1/capabilities").status, 405);
  EXPECT_EQ(send(*a, "GET", "/sds/v1/files/uploads/0123456789ABCDEF0123456789abcdef").status, 404);
  EXPECT_EQ(send(*a, "GET", "/sds/v1/events?timeout=1&timeout=2").status, 400);
}

TEST_F(SdsHttpTest, OversizedBodiesAreRejectedBeforeTheHandler) {
  // Larger than the server-wide buffer limit: Simple-Web-Server refuses it without buffering.
  const nlohmann::json padding {{"name", "x"}, {"size", 1}, {"sha256", test_utils::sds::sha256_hex("x")}, {"pad", std::string(sds::max_request_body_size() + 1024, 'p')}};
  auto a = client(&client_a);
  const auto refused = send(*a, "POST", "/sds/v1/files/uploads", padding.dump());
  EXPECT_TRUE(refused.status == 0 || refused.status == 413) << refused.status;
  EXPECT_EQ(sds::state_for_test(client_a.cert_pem).open_uploads, 0u);

  // Within the server limit but above the operation's limit: 413 from the authorization pipeline.
  auto b = client(&client_b);
  const auto too_large = send(*b, "PUT", "/sds/v1/files/uploads/0123456789abcdef0123456789abcdef?offset=0", std::string(options.files.chunk_max + 1, 'c'));
  EXPECT_EQ(too_large.status, 413);
  EXPECT_EQ(nlohmann::json::parse(too_large.body)["error"], "too_large");
}

TEST_F(SdsHttpTest, UploadOverHttpsAndSessionIsolation) {
  auto a = client(&client_a);
  auto b = client(&client_b);
  const auto data = test_utils::sds::random_bytes(100 * 1024, 9);
  const nlohmann::json create {{"name", "Cafe\xCC\x81 menu.pdf"}, {"size", data.size()}, {"sha256", test_utils::sds::sha256_hex(data)}};
  const auto created = send(*a, "POST", "/sds/v1/files/uploads", create.dump(), {{"Content-Type", "application/json"}});
  ASSERT_EQ(created.status, 201) << created.body;
  const auto id = nlohmann::json::parse(created.body)["id"].get<std::string>();

  std::size_t offset = 0;
  while (offset < data.size()) {
    const auto chunk = data.substr(offset, options.files.chunk_max);
    // Client B can never write into A's session.
    EXPECT_EQ(send(*b, "PUT", std::format("/sds/v1/files/uploads/{}?offset={}", id, offset), chunk).status, 404);
    const auto written = send(*a, "PUT", std::format("/sds/v1/files/uploads/{}?offset={}", id, offset), chunk, {{"Content-Type", "application/octet-stream"}});
    ASSERT_EQ(written.status, 200) << written.body;
    offset = nlohmann::json::parse(written.body)["offset"].get<std::size_t>();
  }
  EXPECT_EQ(send(*b, "POST", std::format("/sds/v1/files/uploads/{}/complete", id)).status, 404);
  const auto completed = send(*a, "POST", std::format("/sds/v1/files/uploads/{}/complete", id));
  ASSERT_EQ(completed.status, 201) << completed.body;
  const auto name = nlohmann::json::parse(completed.body)["name"].get<std::string>();
  EXPECT_EQ(name, "Caf\xC3\xA9 menu.pdf") << "NFD names are stored as NFC";
  EXPECT_EQ(test_utils::sds::read_file(options.files.inbox / name), data);
}

TEST_F(SdsHttpTest, ServerInfoIsAnsweredWhileAnUploadChunkIsBeingWritten) {
  auto a = client(&client_a);
  const nlohmann::json create {{"name", "slow.bin"}, {"size", 5}, {"sha256", test_utils::sds::sha256_hex("hello")}};
  const auto created = send(*a, "POST", "/sds/v1/files/uploads", create.dump());
  ASSERT_EQ(created.status, 201);
  const auto id = nlohmann::json::parse(created.body)["id"].get<std::string>();

  // Keep the file worker busy so the chunk stays in flight.
  std::promise<void> release;
  auto released = release.get_future().share();
  ASSERT_TRUE(sds::post_to_file_worker_for_test([released]() {
    released.wait();
  }));
  auto uploader = client(&client_a);
  auto chunk = std::async(std::launch::async, [&]() {
    return send(*uploader, "PUT", std::format("/sds/v1/files/uploads/{}?offset=0", id), "hello"s);
  });
  EXPECT_EQ(chunk.wait_for(100ms), std::future_status::timeout);

  auto b = client(&client_b);
  const auto started = std::chrono::steady_clock::now();
  const auto info = send(*b, "GET", "/serverinfo?uniqueid=test");
  EXPECT_LT(std::chrono::steady_clock::now() - started, 3s);
  ASSERT_EQ(info.status, 200);
  EXPECT_NE(info.body.find("<sdsVersion>1</sdsVersion>"), std::string::npos) << info.body;
  EXPECT_NE(info.body.find("<sdsFeatures>clipboard,files</sdsFeatures>"), std::string::npos) << info.body;
  EXPECT_EQ(chunk.wait_for(0ms), std::future_status::timeout) << "the chunk is still being processed";

  release.set_value();
  ASSERT_EQ(chunk.wait_for(10s), std::future_status::ready);
  const auto written = chunk.get();
  EXPECT_EQ(written.status, 200);
  EXPECT_EQ(nlohmann::json::parse(written.body)["offset"], 5);
}

TEST_F(SdsHttpTest, ParkedLongPollDoesNotBlockOtherRequestsAndEndsWithTheStream) {
  sds::on_stream_state(client_b.cert_pem, true);
  sds::drain_for_test();
  auto poller = client(&client_b);
  auto poll = std::async(std::launch::async, [&]() {
    return send(*poller, "GET", "/sds/v1/events?timeout=55");
  });
  EXPECT_EQ(poll.wait_for(200ms), std::future_status::timeout);

  auto a = client(&client_a);
  EXPECT_EQ(send(*a, "GET", "/sds/v1/capabilities").status, 200);
  EXPECT_EQ(send(*a, "GET", "/serverinfo").status, 200);

  set_streaming(client_b.cert_pem, false);
  sds::on_stream_state(client_b.cert_pem, false);
  ASSERT_EQ(poll.wait_for(10s), std::future_status::ready);
  const auto ended = poll.get();
  ASSERT_EQ(ended.status, 200);
  EXPECT_EQ(nlohmann::json::parse(ended.body)["events"][0]["type"], "stream_ended");
}
