/**
 * @file tests/unit/test_nvhttp_verified_clients.cpp
 * @brief Verify per-connection client certificate attribution and request size limits in nvhttp.
 */

// test includes
#include "../tests_common.h"

// standard includes
#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <future>
#include <optional>
#include <string>
#include <thread>
#include <tuple>
#include <vector>

// lib includes
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <openssl/ssl.h>

// local includes
#include <src/config.h>
#include <src/crypto.h>
#include <src/nvhttp.h>
#include <src/sds/http.h>

namespace {
  using namespace std::chrono_literals;
  using boost::asio::ip::tcp;
  namespace fs = std::filesystem;
  namespace ssl = boost::asio::ssl;

  /**
   * @brief Minimal parsed HTTP response.
   */
  struct http_response_t {
    std::string status_line;  ///< First response line.
    std::string body;  ///< Response body.
  };

  /**
   * @brief Read one HTTP/1.1 response with a Content-Length body from a stream.
   *
   * @param stream Connected stream to read from.
   * @return Parsed response, or no value when the connection closed before a full response arrived.
   */
  template<class Stream>
  std::optional<http_response_t> read_response(Stream &stream) {
    boost::asio::streambuf buffer;
    boost::system::error_code ec;
    boost::asio::read_until(stream, buffer, "\r\n\r\n", ec);
    if (ec) {
      return std::nullopt;
    }

    std::istream input {&buffer};
    http_response_t response;
    std::getline(input, response.status_line);
    std::size_t content_length = 0;
    std::string line;
    while (std::getline(input, line) && line != "\r") {
      if (const auto colon = line.find(':'); colon != std::string::npos) {
        auto name = line.substr(0, colon);
        std::ranges::transform(name, name.begin(), [](unsigned char c) {
          return static_cast<char>(std::tolower(c));
        });
        if (name == "content-length") {
          content_length = std::stoul(line.substr(colon + 1));
        }
      }
    }

    if (buffer.size() < content_length) {
      boost::asio::read(stream, buffer, boost::asio::transfer_exactly(content_length - buffer.size()), ec);
      if (ec) {
        return std::nullopt;
      }
    }
    response.body.resize(content_length);
    input.read(response.body.data(), static_cast<std::streamsize>(content_length));
    return response;
  }

  /**
   * @brief Wait until a predicate becomes true or a deadline passes.
   *
   * @param predicate Condition to wait for.
   * @return `true` when the predicate became true before the deadline.
   */
  template<class Predicate>
  bool wait_for(Predicate predicate) {
    const auto deadline = std::chrono::steady_clock::now() + 5s;
    while (std::chrono::steady_clock::now() < deadline) {
      if (predicate()) {
        return true;
      }
      std::this_thread::sleep_for(10ms);
    }
    return predicate();
  }

  /**
   * @brief Check whether the peer closes a connection without sending an HTTP response.
   *
   * @param stream Connected stream to read from.
   * @return `true` when the next read ends with an error such as EOF or a reset.
   */
  template<class Stream>
  bool closed_without_response(Stream &stream) {
    std::array<char, 1> byte {};
    boost::system::error_code ec;
    const auto read = stream.read_some(boost::asio::buffer(byte), ec);
    return read == 0 && ec;
  }

  /**
   * @brief Run the production GameStream HTTPS server with paired-client verification on loopback.
   */
  class VerifiedClientTest: public BaseTest {
  protected:
    /**
     * @brief Pair two clients and start the HTTPS server on an ephemeral loopback port.
     */
    void SetUp() override {
      BaseTest::SetUp();
      original_state_file = config::nvhttp.file_state;
      original_fresh_state = config::sunshine.flags[config::flag::FRESH_STATE];
      state_file = fs::path {SUNSHINE_TEST_BIN_DIR} / "verified_clients_state.json";
      config::nvhttp.file_state = state_file.string();
      config::sunshine.flags[config::flag::FRESH_STATE] = true;
      nvhttp::test_support::reset_client_state();

      const auto server_credentials = crypto::gen_creds("Sunshine verified client test", 2048);
      certificate_file = fs::path {SUNSHINE_TEST_BIN_DIR} / "verified_clients_cert.pem";
      private_key_file = fs::path {SUNSHINE_TEST_BIN_DIR} / "verified_clients_key.pem";
      std::ofstream {certificate_file} << server_credentials.x509;
      std::ofstream {private_key_file} << server_credentials.pkey;

      client_a = crypto::gen_creds("Sunshine client A", 2048);
      client_b = crypto::gen_creds("Sunshine client B", 2048);
      unpaired = crypto::gen_creds("Sunshine unpaired client", 2048);
      client_a_uuid = nvhttp::test_support::add_client("client-a", client_a.x509, true);
      ASSERT_FALSE(client_a_uuid.empty());
      ASSERT_FALSE(nvhttp::test_support::add_client("client-b", client_b.x509, true).empty());
      client_a.x509 = normalized_pem(client_a.x509);
      client_b.x509 = normalized_pem(client_b.x509);

      server = nvhttp::test_support::make_https_server(certificate_file.string(), private_key_file.string(), handler_scope, true);
      server->config.address = "127.0.0.1";
      server->config.port = 0;
      server->resource["^/whoami$"]["GET"] = [](const auto &response, const auto &request) {
        const auto client = nvhttp::verified_client(request);
        const auto cert = nvhttp::verified_client_cert(request);
        if (!client || !cert || *cert != client->cert) {
          response->write(SimpleWeb::StatusCode::client_error_unauthorized, "none");
          return;
        }
        response->write(client->name + "\n" + *cert);
      };
      server->resource["^/upload$"]["POST"] = [](const auto &response, const auto &request) {
        response->write(std::to_string(request->content.size()));
      };
      server_thread = std::jthread([this]() {
        server->start([this](unsigned short assigned_port) {
          port = assigned_port;
        });
      });
      ASSERT_TRUE(wait_for([this]() {
        return port != 0;
      }));
    }

    /**
     * @brief Stop the server and restore the persisted-state configuration.
     */
    void TearDown() override {
      if (server) {
        server->stop();
      }
      if (server_thread.joinable()) {
        server_thread.join();
      }
      server.reset();
      nvhttp::test_support::reset_client_state();
      std::error_code cleanup_error;
      fs::remove(certificate_file, cleanup_error);
      fs::remove(private_key_file, cleanup_error);
      fs::remove(state_file, cleanup_error);
      config::nvhttp.file_state = original_state_file;
      config::sunshine.flags[config::flag::FRESH_STATE] = original_fresh_state;
      BaseTest::TearDown();
    }

    /**
     * @brief Re-encode a PEM certificate the way the production verifier reports it.
     *
     * @param pem PEM-encoded certificate.
     * @return Canonical PEM produced by OpenSSL.
     */
    static std::string normalized_pem(const std::string &pem) {
      auto certificate = crypto::x509(pem);
      return crypto::pem(certificate);
    }

    /**
     * @brief Open a TLS connection presenting the given client credentials.
     *
     * @param credentials Client certificate and key.
     * @return Connected TLS stream after a completed handshake.
     */
    std::unique_ptr<ssl::stream<tcp::socket>> connect(const crypto::creds_t &credentials) {
      auto context = std::make_unique<ssl::context>(ssl::context::tls_client);
      context->set_verify_mode(ssl::verify_none);
      context->use_certificate(boost::asio::buffer(credentials.x509), ssl::context::pem);
      context->use_private_key(boost::asio::buffer(credentials.pkey), ssl::context::pem);
      contexts.emplace_back(std::move(context));

      auto stream = std::make_unique<ssl::stream<tcp::socket>>(client_io, *contexts.back());
      stream->lowest_layer().connect({boost::asio::ip::address_v4::loopback(), port});
      stream->handshake(ssl::stream_base::client);
      return stream;
    }

    /**
     * @brief Send `GET /whoami` on a keep-alive connection and read the response.
     *
     * @param stream Connected TLS stream.
     * @return Parsed response, or no value when the connection was closed.
     */
    static std::optional<http_response_t> whoami(ssl::stream<tcp::socket> &stream) {
      const std::string request = "GET /whoami HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n";
      boost::system::error_code ec;
      boost::asio::write(stream, boost::asio::buffer(request), ec);
      if (ec) {
        return std::nullopt;
      }
      return read_response(stream);
    }

    /**
     * @brief Close a client connection without waiting for the server.
     *
     * @param stream Connected TLS stream.
     */
    static void close(std::unique_ptr<ssl::stream<tcp::socket>> &stream) {
      boost::system::error_code ec;
      stream->lowest_layer().shutdown(tcp::socket::shutdown_both, ec);
      stream->lowest_layer().close(ec);
      stream.reset();
    }

    std::unique_ptr<SimpleWeb::ServerBase<nvhttp::SunshineHTTPS>> server;  ///< Production HTTPS server.
    std::shared_ptr<SimpleWeb::ScopeRunner> handler_scope;  ///< Server callback lifetime guard.
    std::jthread server_thread;  ///< Thread running the server's io_context.
    std::atomic<unsigned short> port = 0;  ///< Assigned loopback port.
    boost::asio::io_context client_io;  ///< Context used by blocking test clients.
    std::vector<std::unique_ptr<ssl::context>> contexts;  ///< TLS contexts kept alive for open streams.
    crypto::creds_t client_a;  ///< First paired client.
    std::string client_a_uuid;  ///< Paired-client record of the first client.
    crypto::creds_t client_b;  ///< Second paired client.
    crypto::creds_t unpaired;  ///< Client that was never paired.
    fs::path certificate_file;  ///< Server certificate file.
    fs::path private_key_file;  ///< Server private key file.
    fs::path state_file;  ///< Temporary state file path.
    std::string original_state_file;  ///< State-file setting restored after each test.
    bool original_fresh_state = false;  ///< Fresh-state flag restored after each test.
  };

  /**
   * @brief Two interleaved connections each resolve to the certificate verified on their own handshake.
   */
  TEST_F(VerifiedClientTest, InterleavedConnectionsResolveTheirOwnCertificates) {
    auto connection_a = connect(client_a);
    auto connection_b = connect(client_b);

    // Complete a request on B first so B's handshake was verified after A's: a single
    // "last verified client" would now attribute A's requests to B.
    const auto first_b = whoami(*connection_b);
    ASSERT_TRUE(first_b);
    EXPECT_EQ(first_b->body, "client-b\n" + client_b.x509);

    const auto first_a = whoami(*connection_a);
    ASSERT_TRUE(first_a);
    EXPECT_EQ(first_a->body, "client-a\n" + client_a.x509);

    const auto second_b = whoami(*connection_b);
    ASSERT_TRUE(second_b);
    EXPECT_EQ(second_b->body, "client-b\n" + client_b.x509);

    EXPECT_EQ(nvhttp::test_support::verified_connection_count(), 2);
  }

  /**
   * @brief Registry entries are removed when their connection is destroyed.
   */
  TEST_F(VerifiedClientTest, EntriesAreRemovedWhenConnectionsClose) {
    auto connection_a = connect(client_a);
    auto connection_b = connect(client_b);
    ASSERT_TRUE(whoami(*connection_a));
    ASSERT_TRUE(whoami(*connection_b));
    ASSERT_EQ(nvhttp::test_support::verified_connection_count(), 2);

    close(connection_a);
    EXPECT_TRUE(wait_for([]() {
      return nvhttp::test_support::verified_connection_count() == 1;
    }));

    const auto still_b = whoami(*connection_b);
    ASSERT_TRUE(still_b);
    EXPECT_EQ(still_b->body, "client-b\n" + client_b.x509);

    close(connection_b);
    EXPECT_TRUE(wait_for([]() {
      return nvhttp::test_support::verified_connection_count() == 0;
    }));
  }

  /**
   * @brief Disabling or unpairing a client revokes its identity on connections that are already open.
   */
  TEST_F(VerifiedClientTest, RevokedClientLosesItsIdentityOnOpenConnections) {
    auto connection = connect(client_a);
    const auto before = whoami(*connection);
    ASSERT_TRUE(before);
    EXPECT_EQ(before->body, "client-a\n" + client_a.x509);

    ASSERT_TRUE(nvhttp::set_client_enabled(client_a_uuid, false));
    const auto disabled = whoami(*connection);
    ASSERT_TRUE(disabled);
    EXPECT_EQ(disabled->body, "none");

    ASSERT_TRUE(nvhttp::set_client_enabled(client_a_uuid, true));
    const auto enabled = whoami(*connection);
    ASSERT_TRUE(enabled);
    EXPECT_EQ(enabled->body, "client-a\n" + client_a.x509);

    ASSERT_TRUE(nvhttp::unpair_client(client_a_uuid));
    const auto unpaired_response = whoami(*connection);
    ASSERT_TRUE(unpaired_response);
    EXPECT_EQ(unpaired_response->body, "none");
  }

  /**
   * @brief An unpaired certificate is rejected and never registered.
   */
  TEST_F(VerifiedClientTest, UnpairedCertificateIsRejected) {
    auto connection = connect(unpaired);
    const auto response = whoami(*connection);
    if (response) {
      EXPECT_EQ(response->status_line.rfind("HTTP/1.1 401", 0), 0) << response->status_line;
    }
    EXPECT_EQ(nvhttp::test_support::verified_connection_count(), 0);
  }

  /**
   * @brief A rejected client that never completes the TLS shutdown cannot stall the server thread.
   */
  TEST_F(VerifiedClientTest, SilentRejectedClientDoesNotBlockOtherClients) {
    auto stalled = connect(unpaired);
    std::ignore = whoami(*stalled);  // Server rejects the client and closes its side; we keep ours open.

    auto other = std::async(std::launch::async, [this]() {
      auto connection = connect(client_a);
      return whoami(*connection);
    });
    const auto status = other.wait_for(5s);
    if (status != std::future_status::ready) {
      close(stalled);  // Unblock the server so the helper thread can finish.
    }
    ASSERT_EQ(status, std::future_status::ready) << "server thread blocked by a silent client";
    const auto response = other.get();
    ASSERT_TRUE(response);
    EXPECT_EQ(response->body, "client-a\n" + client_a.x509);
  }

  /**
   * @brief A request without a registered connection does not resolve to any client.
   */
  TEST(VerifiedClientLookupTest, MissingRequestHasNoClient) {
    EXPECT_FALSE(nvhttp::verified_client(nullptr));
    EXPECT_FALSE(nvhttp::verified_client_cert(nullptr));
  }

  /**
   * @brief The HTTPS request size limit leaves room for one file chunk plus headers.
   */
  TEST(NvhttpRequestLimitTest, HttpsLimitIsChunkPlusHeaders) {
    EXPECT_EQ(nvhttp::HTTPS_MAX_CHUNK_SIZE, 4u * 1024 * 1024);
    EXPECT_EQ(nvhttp::HTTPS_MAX_REQUEST_SIZE, nvhttp::HTTPS_MAX_CHUNK_SIZE + 64u * 1024);
    EXPECT_EQ(nvhttp::HTTP_MAX_REQUEST_SIZE, 64u * 1024);
  }

  /**
   * @brief An HTTPS body within the limit is accepted, and an oversized one is refused without reading it.
   */
  TEST_F(VerifiedClientTest, OversizedHttpsBodyIsRejectedBeforeBuffering) {
    auto accepted = connect(client_a);
    const std::string body(1024, 'x');
    const std::string small_request = "POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1024\r\n\r\n" + body;
    boost::asio::write(*accepted, boost::asio::buffer(small_request));
    const auto small_response = read_response(*accepted);
    ASSERT_TRUE(small_response);
    EXPECT_EQ(small_response->body, "1024");

    auto rejected = connect(client_a);
    // Only the headers are sent: the server must close the connection instead of waiting for the body.
    const auto oversized = std::to_string(nvhttp::HTTPS_MAX_REQUEST_SIZE + 1);
    const std::string headers = "POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: " + oversized + "\r\n\r\n";
    boost::asio::write(*rejected, boost::asio::buffer(headers));
    EXPECT_TRUE(closed_without_response(*rejected));
  }

  /**
   * @brief Run the production plain HTTP server on loopback.
   */
  class PlainHttpLimitTest: public BaseTest {
  protected:
    /**
     * @brief Start the plain HTTP server on an ephemeral loopback port.
     */
    void SetUp() override {
      BaseTest::SetUp();
      server = nvhttp::test_support::make_http_server();
      server->config.address = "127.0.0.1";
      server->config.port = 0;
      server->default_resource["GET"] = [](const auto &response, const auto &) {
        response->write("ok");
      };
      server_thread = std::jthread([this]() {
        server->start([this](unsigned short assigned_port) {
          port = assigned_port;
        });
      });
      ASSERT_TRUE(wait_for([this]() {
        return port != 0;
      }));
    }

    /**
     * @brief Stop the plain HTTP server.
     */
    void TearDown() override {
      if (server) {
        server->stop();
      }
      if (server_thread.joinable()) {
        server_thread.join();
      }
      server.reset();
      BaseTest::TearDown();
    }

    std::unique_ptr<SimpleWeb::ServerBase<SimpleWeb::HTTP>> server;  ///< Production plain HTTP server.
    std::jthread server_thread;  ///< Thread running the server's io_context.
    std::atomic<unsigned short> port = 0;  ///< Assigned loopback port.
    boost::asio::io_context client_io;  ///< Context used by blocking test clients.
  };

  /**
   * @brief Small requests are served and requests above 64 KiB are refused without buffering the body.
   */
  TEST_F(PlainHttpLimitTest, OversizedRequestIsRejected) {
    tcp::socket accepted {client_io};
    accepted.connect({boost::asio::ip::address_v4::loopback(), port});
    boost::asio::write(accepted, boost::asio::buffer(std::string {"GET /serverinfo HTTP/1.1\r\nHost: localhost\r\n\r\n"}));
    const auto response = read_response(accepted);
    ASSERT_TRUE(response);
    EXPECT_EQ(response->body, "ok");

    tcp::socket rejected {client_io};
    rejected.connect({boost::asio::ip::address_v4::loopback(), port});
    const auto oversized = std::to_string(nvhttp::HTTP_MAX_REQUEST_SIZE + 1);
    const std::string headers = "GET /serverinfo HTTP/1.1\r\nHost: localhost\r\nContent-Length: " + oversized + "\r\n\r\n";
    boost::asio::write(rejected, boost::asio::buffer(headers));
    EXPECT_TRUE(closed_without_response(rejected));

    tcp::socket long_headers {client_io};
    long_headers.connect({boost::asio::ip::address_v4::loopback(), port});
    const std::string padding(nvhttp::HTTP_MAX_REQUEST_SIZE + 1, 'a');
    boost::system::error_code write_error;
    boost::asio::write(long_headers, boost::asio::buffer("GET /serverinfo HTTP/1.1\r\nX-Padding: " + padding), write_error);
    EXPECT_TRUE(closed_without_response(long_headers));
  }

  /**
   * @brief Revoked or unpaired keep-alive clients receive 401 and close immediately on protected GameStream routes.
   */
  TEST_F(VerifiedClientTest, RevokedKeepAliveClientReceives401AndClosesOnProtectedRoutes) {
    server->resource["^/serverinfo$"]["GET"] = nvhttp::test_support::serverinfo_https;
    server->resource["^/applist$"]["GET"] = nvhttp::test_support::applist_https;
    server->resource["^/appasset$"]["GET"] = nvhttp::test_support::appasset_https;
    server->resource["^/cancel$"]["GET"] = nvhttp::test_support::cancel_https;
    server->resource["^/pair$"]["GET"] = nvhttp::test_support::pair_https;

    for (const auto *route : {"/serverinfo", "/applist", "/appasset", "/cancel", "/pair"}) {
      ASSERT_TRUE(nvhttp::set_client_enabled(client_a_uuid, true));
      auto connection = connect(client_a);
      const auto active = whoami(*connection);
      ASSERT_TRUE(active);
      EXPECT_EQ(active->body, "client-a\n" + client_a.x509);

      ASSERT_TRUE(nvhttp::set_client_enabled(client_a_uuid, false));
      const std::string req = std::string {"GET "} + route + " HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n";
      boost::asio::write(*connection, boost::asio::buffer(req));
      const auto revoked = read_response(*connection);
      ASSERT_TRUE(revoked) << route;
      EXPECT_EQ(revoked->status_line.rfind("HTTP/1.1 401", 0), 0) << route << ": " << revoked->status_line;
      EXPECT_NE(revoked->body.find("status_code=\"401\""), std::string::npos) << route << ": " << revoked->body;
      EXPECT_TRUE(closed_without_response(*connection)) << route;
    }

    ASSERT_TRUE(nvhttp::set_client_enabled(client_a_uuid, true));
    auto unpaired_conn = connect(client_a);
    ASSERT_TRUE(whoami(*unpaired_conn));
    ASSERT_TRUE(nvhttp::unpair_client(client_a_uuid));
    boost::asio::write(*unpaired_conn, boost::asio::buffer(std::string {"GET /applist HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n"}));
    const auto after_unpair = read_response(*unpaired_conn);
    ASSERT_TRUE(after_unpair);
    EXPECT_EQ(after_unpair->status_line.rfind("HTTP/1.1 401", 0), 0);
    EXPECT_TRUE(closed_without_response(*unpaired_conn));
  }

  /**
   * @brief The GameStream HTTPS server rejects TLS 1.2 clients and enforces TLS 1.3 minimum.
   */
  TEST_F(VerifiedClientTest, EnforcesTls13MinimumVersion) {
    ssl::context tls12_ctx {ssl::context::tls_client};
    tls12_ctx.set_verify_mode(ssl::verify_none);
    tls12_ctx.use_certificate(boost::asio::buffer(client_a.x509), ssl::context::pem);
    tls12_ctx.use_private_key(boost::asio::buffer(client_a.pkey), ssl::context::pem);
    ASSERT_EQ(SSL_CTX_set_max_proto_version(tls12_ctx.native_handle(), TLS1_2_VERSION), 1);

    ssl::stream<tcp::socket> stream {client_io, tls12_ctx};
    stream.lowest_layer().connect({boost::asio::ip::address_v4::loopback(), port});
    boost::system::error_code ec;
    stream.handshake(ssl::stream_base::client, ec);
    EXPECT_TRUE(ec);
  }

  /**
   * @brief Plain HTTP server rejects Transfer-Encoding smuggling and non-canonical request heads.
   */
  TEST_F(PlainHttpLimitTest, RejectsSmugglingAndNonCanonicalFraming) {
    const std::array malformed_requests {
      std::string {"POST /serverinfo HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"},
      std::string {"GET /serverinfo HTTP/1.1\nHost: localhost\r\n\r\n"},
      std::string {"GET /serverinfo HTTP/1.1\r\nHost: localhost\nX-Foo: bar\r\n\r\n"},
      std::string {"GET /serverinfo HTTP/1.1\r\nMissingColon\r\n\r\n"},
      std::string {"GET /serverinfo HTTP/1.1\r\nHost: localhost\r\n folded\r\n\r\n"},
      std::string {"GET /serverinfo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n"},
    };
    for (const auto &raw_request : malformed_requests) {
      tcp::socket sock {client_io};
      sock.connect({boost::asio::ip::address_v4::loopback(), port});
      boost::system::error_code write_error;
      boost::asio::write(sock, boost::asio::buffer(raw_request), write_error);
      EXPECT_TRUE(closed_without_response(sock));
    }

    EXPECT_TRUE(sds::http::canonical_header_lines("GET /sds/v1/clipboard HTTP/1.1\r\nHost: localhost\r\n\r\n"));
    EXPECT_FALSE(sds::http::canonical_header_lines("GET /sds/v1/clipboard HTTP/1.1\nHost: localhost\r\n\r\n"));
    EXPECT_FALSE(sds::http::canonical_header_lines("GET /sds/v1/clipboard HTTP/1.1\rHost: localhost\r\n\r\n"));
    EXPECT_FALSE(sds::http::canonical_header_lines(std::string_view {"GET /\0 HTTP/1.1\r\nHost: localhost\r\n\r\n", 36}));
  }
}  // namespace
