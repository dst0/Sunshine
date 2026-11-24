/**
 * @file tests/unit/test_nvhttp_https.cpp
 * @brief Verify HTTPS callbacks retain the guard protecting server lifetime.
 */

// test includes
#include "../tests_common.h"

// standard includes
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <future>
#include <thread>

// lib includes
#include <boost/asio.hpp>

// local includes
#include <src/crypto.h>
#include <src/nvhttp.h>

namespace {
  using namespace std::chrono_literals;
  using boost::asio::ip::tcp;

  /**
   * @brief Run real HTTPS callbacks against an isolated loopback listener.
   */
  struct HttpsHandlerLifetimeTest: BaseTest {
    /**
     * @brief Create credentials and start the production HTTPS accept handler.
     */
    void SetUp() override {
      BaseTest::SetUp();
      const auto credentials = crypto::gen_creds("Sunshine HTTPS lifetime test", 2048);
      certificate_file = std::filesystem::path {SUNSHINE_TEST_BIN_DIR} / "https_lifetime_cert.pem";
      private_key_file = std::filesystem::path {SUNSHINE_TEST_BIN_DIR} / "https_lifetime_key.pem";
      std::ofstream {certificate_file} << credentials.x509;
      std::ofstream {private_key_file} << credentials.pkey;

      server = nvhttp::test_support::make_https_server(certificate_file.string(), private_key_file.string(), handler_scope);
      server->config.address = "127.0.0.1";
      server->config.port = 0;
    }

    void start_server() {
      std::promise<unsigned short> bound_promise;
      auto bound_future = bound_promise.get_future();
      auto shared_promise = std::make_shared<std::promise<unsigned short>>(std::move(bound_promise));
      server_thread = std::jthread([this, shared_promise]() mutable {
        server->start([shared_promise](unsigned short assigned_port) mutable {
          shared_promise->set_value(assigned_port);
        });
      });
      ASSERT_EQ(bound_future.wait_for(2s), std::future_status::ready);
      port = bound_future.get();
      ASSERT_NE(port, 0);
    }

    /**
     * @brief Drain canceled callbacks and remove the generated credentials.
     */
    void TearDown() override {
      if (server) {
        server->stop();
      }
      if (server_thread.joinable()) {
        server_thread.join();
      }
      if (stop_thread.joinable()) {
        stop_thread.join();
      }
      server.reset();
      std::error_code cleanup_error;
      std::filesystem::remove(certificate_file, cleanup_error);
      std::filesystem::remove(private_key_file, cleanup_error);
      BaseTest::TearDown();
    }

    /**
     * @brief Check that stopping the scope runner waits until the error callback exits.
     *
     * @param callback_error Error delivered by the real accept or TLS handshake operation.
     */
    void check_handler_guard(const SimpleWeb::error_code &callback_error) {
      EXPECT_TRUE(callback_error);
      ++error_callbacks;
      std::promise<void> stopping;
      auto stopping_future = stopping.get_future();
      std::promise<void> stopped;
      stopped_future = stopped.get_future();
      stop_thread = std::jthread([this, stopping = std::move(stopping), stopped = std::move(stopped)]() mutable {
        stopping.set_value();
        handler_scope->stop();
        stopped.set_value();
      });
      stopping_future.wait();
      EXPECT_EQ(stopped_future.wait_for(50ms), std::future_status::timeout);
    }

    std::unique_ptr<SimpleWeb::ServerBase<nvhttp::SunshineHTTPS>> server;  ///< Server running production accept and handshake callbacks.
    std::shared_ptr<SimpleWeb::ScopeRunner> handler_scope;  ///< Guard used by the server destructor.
    std::jthread server_thread;  ///< Thread running the HTTPS server.
    std::jthread stop_thread;  ///< Concurrent attempt to stop the handler scope.
    std::future<void> stopped_future;  ///< Signals that all callback guards have been released.
    unsigned short port = 0;  ///< Assigned loopback port.
    std::atomic<int> error_callbacks = 0;  ///< Number of errors delivered while testing a handler.
    std::filesystem::path certificate_file;  ///< Generated server certificate.
    std::filesystem::path private_key_file;  ///< Generated server private key.
  };

  /**
   * @brief Canceling a pending accept holds the server guard through its error callback.
   */
  TEST_F(HttpsHandlerLifetimeTest, AcceptErrorRetainsGuardUntilCallbackReturns) {
    server->on_error = [this](auto, const auto &callback_error) {
      check_handler_guard(callback_error);
    };
    start_server();
    server->stop();
    server_thread.join();
    ASSERT_EQ(error_callbacks, 1);
    ASSERT_TRUE(stopped_future.valid());
    EXPECT_EQ(stopped_future.wait_for(2s), std::future_status::ready);
  }

  /**
   * @brief A failed TLS handshake holds the server guard through its error callback.
   */
  TEST_F(HttpsHandlerLifetimeTest, HandshakeErrorRetainsGuardUntilCallbackReturns) {
    std::promise<void> handled;
    auto handled_future = handled.get_future();
    auto handled_shared = std::make_shared<std::promise<void>>(std::move(handled));
    server->on_error = [this, handled_shared](auto, const auto &callback_error) {
      if (callback_error != SimpleWeb::error::operation_aborted) {
        check_handler_guard(callback_error);
        handled_shared->set_value();
      }
    };
    start_server();
    boost::asio::io_context client_io;
    tcp::socket client {client_io};
    client.connect({boost::asio::ip::address_v4::loopback(), port});
    client.close();
    ASSERT_EQ(handled_future.wait_for(2s), std::future_status::ready);
    server->stop();
    server_thread.join();
    ASSERT_EQ(error_callbacks, 1);
    ASSERT_TRUE(stopped_future.valid());
    EXPECT_EQ(stopped_future.wait_for(2s), std::future_status::ready);
  }

  /**
   * @brief A stopped server scope prevents a canceled accept from dispatching an error.
   */
  TEST_F(HttpsHandlerLifetimeTest, StoppedScopeSkipsAcceptCallback) {
    server->on_error = [this](auto, const auto &) {
      ++error_callbacks;
    };
    start_server();
    handler_scope->stop();
    server->stop();
    server_thread.join();
    EXPECT_EQ(error_callbacks, 0);
  }

  /**
   * @brief A stopped server scope prevents an outstanding handshake from dispatching an error.
   */
  TEST_F(HttpsHandlerLifetimeTest, StoppedScopeSkipsHandshakeCallback) {
    server->on_error = [this](auto, const auto &) {
      ++error_callbacks;
    };
    std::promise<void> accepted;
    auto accepted_future = accepted.get_future();
    auto accepted_shared = std::make_shared<std::promise<void>>(std::move(accepted));
    auto orig_accepted = server->on_connection_accepted;
    server->on_connection_accepted = [orig_accepted, accepted_shared](const auto &req) {
      const bool ok = !orig_accepted || orig_accepted(req);
      accepted_shared->set_value();
      return ok;
    };
    start_server();
    boost::asio::io_context client_io;
    tcp::socket client {client_io};
    client.connect({boost::asio::ip::address_v4::loopback(), port});
    ASSERT_EQ(accepted_future.wait_for(2s), std::future_status::ready);
    handler_scope->stop();
    client.close();
    std::this_thread::sleep_for(50ms);
    server->stop();
    server_thread.join();
    EXPECT_EQ(error_callbacks, 0);
  }
}  // namespace
