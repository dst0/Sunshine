/**
 * @file tests/unit/platform/linux/test_clipboard_linux.cpp
 * @brief Tests for the Linux clipboard file descriptor helpers and the backend factory.
 */
#ifdef __linux__

  // test includes
  #include "../../../tests_common.h"

  // standard includes
  #include <array>
  #include <chrono>
  #include <cstdlib>
  #include <optional>
  #include <string>
  #include <thread>
  #include <vector>

  // lib includes
  #include <fcntl.h>
  #include <unistd.h>

  // local includes
  #include "src/platform/linux/clipboard_linux.h"
  #include "src/platform/linux/portal_session.h"

using namespace std::literals;
using sds::clipboard::fdio::status_e;

namespace {
  /**
   * @brief A pipe whose ends are closed on destruction.
   */
  struct pipe_t {
    std::array<int, 2> fds {-1, -1};  ///< Read and write ends.

    pipe_t() {
      if (pipe2(fds.data(), O_CLOEXEC) != 0) {
        fds = {-1, -1};
      }
    }

    pipe_t(const pipe_t &) = delete;
    pipe_t &operator=(const pipe_t &) = delete;

    ~pipe_t() {
      close_read();
      close_write();
    }

    /**
     * @brief Close the read end.
     */
    void close_read() {
      if (fds[0] >= 0) {
        close(fds[0]);
        fds[0] = -1;
      }
    }

    /**
     * @brief Close the write end.
     */
    void close_write() {
      if (fds[1] >= 0) {
        close(fds[1]);
        fds[1] = -1;
      }
    }
  };

  /**
   * @brief Set or unset an environment variable for the lifetime of the object.
   */
  class scoped_env_t {
  public:
    scoped_env_t(const char *name, const char *value):
        name_(name) {
      if (const char *previous = std::getenv(name)) {
        previous_ = previous;
      }
      logging::log_flush();
      if (value) {
        setenv(name, value, 1);
      } else {
        unsetenv(name);
      }
    }

    scoped_env_t(const scoped_env_t &) = delete;
    scoped_env_t &operator=(const scoped_env_t &) = delete;

    ~scoped_env_t() {
      logging::log_flush();
      if (previous_) {
        setenv(name_.c_str(), previous_->c_str(), 1);
      } else {
        unsetenv(name_.c_str());
      }
    }

  private:
    std::string name_;
    std::optional<std::string> previous_;
  };

  /**
   * @brief Deadline `ms` from now.
   */
  std::chrono::steady_clock::time_point in(std::chrono::milliseconds ms) {
    return std::chrono::steady_clock::now() + ms;
  }
}  // namespace

TEST(ClipboardFdioTest, ReadsUntilEof) {
  pipe_t p;
  ASSERT_EQ(::write(p.fds[1], "hello", 5), 5);
  p.close_write();
  const auto result = sds::clipboard::fdio::read_capped(p.fds[0], 100, in(1s));
  EXPECT_EQ(result.status, status_e::ok);
  EXPECT_EQ(std::string(result.data.begin(), result.data.end()), "hello");
}

TEST(ClipboardFdioTest, AcceptsExactlyTheCap) {
  pipe_t p;
  const std::string data(100, 'x');
  ASSERT_EQ(::write(p.fds[1], data.data(), data.size()), 100);
  p.close_write();
  const auto result = sds::clipboard::fdio::read_capped(p.fds[0], 100, in(1s));
  EXPECT_EQ(result.status, status_e::ok);
  EXPECT_EQ(result.data.size(), 100u);
}

TEST(ClipboardFdioTest, StopsReadingPastTheCap) {
  pipe_t p;
  const std::string data(200, 'x');
  ASSERT_EQ(::write(p.fds[1], data.data(), data.size()), 200);
  p.close_write();
  EXPECT_EQ(sds::clipboard::fdio::read_capped(p.fds[0], 100, in(1s)).status, status_e::too_large);
}

TEST(ClipboardFdioTest, ReadTimesOutWhenWriterStalls) {
  pipe_t p;
  ASSERT_EQ(::write(p.fds[1], "x", 1), 1);
  const auto start = std::chrono::steady_clock::now();
  const auto result = sds::clipboard::fdio::read_capped(p.fds[0], 100, in(150ms));
  EXPECT_EQ(result.status, status_e::timeout);
  const auto elapsed = std::chrono::steady_clock::now() - start;
  EXPECT_GE(elapsed, 140ms);
  EXPECT_LT(elapsed, 1s);
}

TEST(ClipboardFdioTest, ReadRejectsInvalidDescriptor) {
  EXPECT_EQ(sds::clipboard::fdio::read_capped(-1, 100, in(100ms)).status, status_e::error);
}

TEST(ClipboardFdioTest, ReadReportsErrors) {
  pipe_t p;
  // Reading from the write end of a pipe fails with EBADF
  EXPECT_EQ(sds::clipboard::fdio::read_capped(p.fds[1], 100, in(100ms)).status, status_e::error);
}

TEST(ClipboardFdioTest, WritesEverythingToASlowReader) {
  pipe_t p;
  std::vector<std::uint8_t> data(1024 * 1024);
  for (std::size_t i = 0; i < data.size(); ++i) {
    data[i] = static_cast<std::uint8_t>(i);
  }
  std::vector<std::uint8_t> received;
  std::thread reader([&]() {
    std::array<std::uint8_t, 4096> buffer {};
    while (true) {
      const ssize_t n = ::read(p.fds[0], buffer.data(), buffer.size());
      if (n <= 0) {
        break;
      }
      received.insert(received.end(), buffer.begin(), buffer.begin() + n);
    }
  });
  EXPECT_EQ(sds::clipboard::fdio::write_all(p.fds[1], data, in(5s)), status_e::ok);
  p.close_write();
  reader.join();
  EXPECT_EQ(received, data);
}

TEST(ClipboardFdioTest, WriteToAClosedReaderFailsWithoutSigpipe) {
  pipe_t p;
  p.close_read();
  const std::vector<std::uint8_t> data(1000, 1);
  EXPECT_EQ(sds::clipboard::fdio::write_all(p.fds[1], data, in(1s)), status_e::error);
  // Still alive: SIGPIPE was suppressed. A second failure behaves the same way.
  EXPECT_EQ(sds::clipboard::fdio::write_all(p.fds[1], data, in(1s)), status_e::error);
}

TEST(ClipboardFdioTest, WriteTimesOutWhenReaderStalls) {
  pipe_t p;
  const std::vector<std::uint8_t> data(1024 * 1024, 7);
  const auto start = std::chrono::steady_clock::now();
  EXPECT_EQ(sds::clipboard::fdio::write_all(p.fds[1], data, in(150ms)), status_e::timeout);
  EXPECT_LT(std::chrono::steady_clock::now() - start, 1s);
}

TEST(ClipboardFdioTest, WriteRejectsInvalidDescriptor) {
  EXPECT_EQ(sds::clipboard::fdio::write_all(-1, std::vector<std::uint8_t> {1}, in(100ms)), status_e::error);
}

TEST(ClipboardFdioTest, WriteOfNothingSucceeds) {
  pipe_t p;
  EXPECT_EQ(sds::clipboard::fdio::write_all(p.fds[1], {}, in(100ms)), status_e::ok);
}

  #ifdef SUNSHINE_BUILD_PORTAL
/**
 * @brief Restores the portal flags changed by the factory tests.
 */
class ClipboardFactoryTest: public BaseTest {
protected:
  void SetUp() override {
    BaseTest::SetUp();
    saved_capture_ = portal::capture_active();
    saved_requested_ = portal::clipboard_requested();
  }

  void TearDown() override {
    portal::set_capture_active(saved_capture_);
    portal::set_clipboard_requested(saved_requested_);
    BaseTest::TearDown();
  }

  bool saved_capture_ = false;
  bool saved_requested_ = false;
};

TEST_F(ClipboardFactoryTest, MakeBackendRequestsPortalClipboard) {
  portal::set_clipboard_requested(false);
  const auto backend = sds::clipboard::make_backend();
  ASSERT_TRUE(backend);
  EXPECT_TRUE(portal::clipboard_requested());
  EXPECT_EQ(backend->name(), "linux");
  EXPECT_FALSE(backend->read({10, 10}, 10ms));  // not started
  EXPECT_EQ(backend->write({.text = "x", .png = std::nullopt}), -1);
}

TEST_F(ClipboardFactoryTest, StartFailsWhenNoBackendIsUsable) {
  portal::set_capture_active(false);
  const scoped_env_t display("DISPLAY", nullptr);
  const auto backend = sds::clipboard::make_backend();
  ASSERT_TRUE(backend);
  EXPECT_LT(backend->start([]() {
  }),
            0);
  EXPECT_EQ(backend->name(), "linux");
  backend->stop();
}

    #ifdef SUNSHINE_BUILD_X11_CLIPBOARD
TEST_F(ClipboardFactoryTest, ChoosesX11WithoutPortalCapture) {
  const char *display = std::getenv("DISPLAY");
  if (!display || !*display) {
    GTEST_SKIP() << "DISPLAY is not set";
  }
  portal::set_capture_active(false);
  const auto backend = sds::clipboard::make_backend();
  ASSERT_TRUE(backend);
  ASSERT_EQ(backend->start([]() {
  }),
            0);
  EXPECT_EQ(backend->name(), "x11");
  ASSERT_EQ(backend->write({.text = "factory", .png = std::nullopt}), 0);
  const auto item = backend->read({100, 100}, 1s);
  ASSERT_TRUE(item);
  EXPECT_EQ(item->text, "factory");
  backend->stop();
  backend->stop();
  EXPECT_FALSE(backend->read({100, 100}, 10ms));
}

TEST_F(ClipboardFactoryTest, FallsBackToX11WhenPortalClipboardFails) {
  const char *display = std::getenv("DISPLAY");
  if (!display || !*display) {
    GTEST_SKIP() << "DISPLAY is not set";
  }
  // No reachable session bus: the portal backend fails quickly
  const scoped_env_t bus("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent/sunshine-test-bus");
  portal::set_capture_active(true);
  const auto backend = sds::clipboard::make_backend();
  ASSERT_TRUE(backend);
  ASSERT_EQ(backend->start([]() {
  }),
            0);
  EXPECT_EQ(backend->name(), "x11");
  backend->stop();
}
    #endif
  #endif

#endif
