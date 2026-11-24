/**
 * @file tests/unit/sds/test_sds_clipboard.cpp
 * @brief Test the platform-independent clipboard core (DESIGN 5.1-5.4, check S13).
 */

// test includes
#include "../../tests_common.h"
#include "fake_clipboard_backend.h"

// standard includes
#include <array>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <thread>
#include <vector>

// local includes
#include <src/sds/clipboard.h>

using namespace std::literals;

namespace {
  /**
   * @brief CRC-32 as used by PNG, for building test headers.
   *
   * @param data Bytes.
   * @return Checksum.
   */
  std::uint32_t png_crc(const std::string &data) {
    std::uint32_t crc = 0xFFFFFFFFu;
    for (const unsigned char byte : data) {
      crc ^= byte;
      for (int k = 0; k < 8; ++k) {
        crc = (crc & 1) ? 0xEDB88320u ^ (crc >> 1) : crc >> 1;
      }
    }
    return crc ^ 0xFFFFFFFFu;
  }

  /**
   * @brief Append a big-endian 32-bit integer.
   *
   * @param out Destination.
   * @param value Value.
   */
  void put_be32(std::string &out, std::uint32_t value) {
    out.push_back(static_cast<char>(value >> 24));
    out.push_back(static_cast<char>(value >> 16));
    out.push_back(static_cast<char>(value >> 8));
    out.push_back(static_cast<char>(value));
  }

  /**
   * @brief Build a PNG signature + IHDR chunk with a correct or corrupted CRC.
   *
   * @param width Width.
   * @param height Height.
   * @param depth Bit depth.
   * @param color Color type.
   * @param interlace Interlace method.
   * @param corrupt_crc Flip the CRC.
   * @return Bytes.
   */
  std::string png_header(std::uint32_t width, std::uint32_t height, std::uint8_t depth = 8, std::uint8_t color = 6, std::uint8_t interlace = 0, bool corrupt_crc = false) {
    std::string out = "\x89PNG\r\n\x1a\n"s;
    put_be32(out, 13);
    std::string chunk = "IHDR";
    put_be32(chunk, width);
    put_be32(chunk, height);
    chunk.push_back(static_cast<char>(depth));
    chunk.push_back(static_cast<char>(color));
    chunk.push_back(0);
    chunk.push_back(0);
    chunk.push_back(static_cast<char>(interlace));
    out += chunk;
    put_be32(out, png_crc(chunk) ^ (corrupt_crc ? 1u : 0u));
    return out;
  }

  /**
   * @brief View a string as PNG bytes.
   *
   * @param data Bytes.
   * @return Span.
   */
  std::span<const std::uint8_t> bytes(const std::string &data) {
    return {reinterpret_cast<const std::uint8_t *>(data.data()), data.size()};
  }

  /**
   * @brief Clipboard core driven synchronously on the test thread.
   */
  class SdsClipboardCoreTest: public BaseTest {
  protected:
    void SetUp() override {
      BaseTest::SetUp();
      state = std::make_shared<test_utils::sds::fake_clipboard_state_t>();
      make_core(std::make_unique<test_utils::sds::fake_clipboard_backend_t>(state));
    }

    void TearDown() override {
      core.reset();
      BaseTest::TearDown();
    }

    /**
     * @brief (Re)create the core under test.
     *
     * @param backend Backend, may be null.
     * @param window Coalescing window.
     */
    void make_core(std::unique_ptr<sds::clipboard::backend_t> backend, std::chrono::milliseconds window = 500ms) {
      sds::clipboard::hooks_t hooks;
      hooks.publish = [this](const std::string &client, nlohmann::json event) {
        published[client].push_back(std::move(event));
      };
      hooks.retract = [this](const std::string &client) {
        retracted.push_back(client);
      };
      hooks.readers = [this]() {
        return readers;
      };
      hooks.post = [this](std::function<void()> job) {
        posted.push_back(std::move(job));
        return true;
      };
      core = std::make_unique<sds::clipboard::core_t>(std::move(backend), sds::clipboard::limits_t {64, 4096}, 100ms, window, std::move(hooks));
    }

    /**
     * @brief Run jobs the core posted to its "worker".
     */
    void run_posted() {
      auto jobs = std::move(posted);
      posted.clear();
      for (auto &job : jobs) {
        job();
      }
    }

    std::shared_ptr<test_utils::sds::fake_clipboard_state_t> state;  ///< Fake backend state.
    std::unique_ptr<sds::clipboard::core_t> core;  ///< Core under test.
    std::map<std::string, std::vector<nlohmann::json>> published;  ///< Events by client.
    std::vector<std::string> retracted;  ///< Retracted clients.
    std::vector<std::string> readers {"A", "B"};  ///< Clients with clipboard_read.
    std::vector<std::function<void()>> posted;  ///< Jobs posted by the core.
  };
}  // namespace

TEST(SdsClipboardValidationTest, Text) {
  EXPECT_EQ(sds::clipboard::validate_text("hello \xC3\xA9", 64), sds::clipboard::validation_e::ok);
  EXPECT_EQ(sds::clipboard::validate_text("", 64), sds::clipboard::validation_e::ok);
  EXPECT_EQ(sds::clipboard::validate_text(std::string(65, 'x'), 64), sds::clipboard::validation_e::too_large);
  EXPECT_EQ(sds::clipboard::validate_text(std::string {"a\0b", 3}, 64), sds::clipboard::validation_e::contains_nul);
  EXPECT_EQ(sds::clipboard::validate_text("\xC0\x80", 64), sds::clipboard::validation_e::invalid_utf8);
  EXPECT_EQ(sds::clipboard::validate_text("\xED\xA0\x80", 64), sds::clipboard::validation_e::invalid_utf8);
}

TEST(SdsClipboardValidationTest, Png) {
  using sds::clipboard::validation_e;
  const auto tiny = test_utils::sds::tiny_png();
  EXPECT_EQ(sds::clipboard::validate_png(bytes(tiny), 4096), validation_e::ok);
  EXPECT_EQ(sds::clipboard::validate_png(bytes(png_header(1, 1)), 4096), validation_e::ok);
  EXPECT_EQ(sds::clipboard::validate_png(bytes(tiny), 10), validation_e::too_large);
  EXPECT_EQ(sds::clipboard::validate_png(bytes("GIF89a.........................................."s), 4096), validation_e::bad_png_signature);
  EXPECT_EQ(sds::clipboard::validate_png(bytes("\x89PN"s), 4096), validation_e::bad_png_signature);
  EXPECT_EQ(sds::clipboard::validate_png(bytes(tiny.substr(0, 20)), 4096), validation_e::bad_png_header);

  auto wrong_type = png_header(1, 1);
  wrong_type[12] = 'X';
  EXPECT_EQ(sds::clipboard::validate_png(bytes(wrong_type), 4096), validation_e::bad_png_header);
  auto wrong_length = png_header(1, 1);
  wrong_length[11] = 14;
  EXPECT_EQ(sds::clipboard::validate_png(bytes(wrong_length), 4096), validation_e::bad_png_header);

  EXPECT_EQ(sds::clipboard::validate_png(bytes(png_header(0, 1)), 4096), validation_e::bad_png_header);
  EXPECT_EQ(sds::clipboard::validate_png(bytes(png_header(1, 0)), 4096), validation_e::bad_png_header);
  EXPECT_EQ(sds::clipboard::validate_png(bytes(png_header(0x80000000u, 1)), 4096), validation_e::bad_png_header);
  EXPECT_EQ(sds::clipboard::validate_png(bytes(png_header(1, 1, 3, 6)), 4096), validation_e::bad_png_header);
  EXPECT_EQ(sds::clipboard::validate_png(bytes(png_header(1, 1, 16, 3)), 4096), validation_e::bad_png_header);
  EXPECT_EQ(sds::clipboard::validate_png(bytes(png_header(1, 1, 8, 5)), 4096), validation_e::bad_png_header);
  EXPECT_EQ(sds::clipboard::validate_png(bytes(png_header(1, 1, 8, 6, 2)), 4096), validation_e::bad_png_header);
  EXPECT_EQ(sds::clipboard::validate_png(bytes(png_header(1, 1, 8, 6, 0, true)), 4096), validation_e::bad_png_header);
  EXPECT_EQ(sds::clipboard::validate_png(bytes(png_header(1, 1, 1, 0)), 4096), validation_e::ok);
  EXPECT_EQ(sds::clipboard::validate_png(bytes(png_header(1, 1, 16, 2, 1)), 4096), validation_e::ok);

  // 8192 x 8192 x 4 = 256 MiB is the largest accepted decoded size.
  EXPECT_EQ(sds::clipboard::validate_png(bytes(png_header(8192, 8192)), 4096), validation_e::ok);
  EXPECT_EQ(sds::clipboard::validate_png(bytes(png_header(8192, 8193)), 4096), validation_e::image_too_large);
  EXPECT_EQ(sds::clipboard::validate_png(bytes(png_header(65535, 65535)), 4096), validation_e::image_too_large);
}

TEST(SdsClipboardValidationTest, TypesAndDescriptions) {
  EXPECT_EQ(sds::clipboard::parse_type("text/plain"), sds::clipboard::type_e::text);
  EXPECT_EQ(sds::clipboard::parse_type("image/png"), sds::clipboard::type_e::png);
  EXPECT_FALSE(sds::clipboard::parse_type("text/html").has_value());
  EXPECT_EQ(sds::clipboard::type_name(sds::clipboard::type_e::text), "text/plain");
  EXPECT_EQ(sds::clipboard::type_name(sds::clipboard::type_e::png), "image/png");
  for (const auto result : {sds::clipboard::validation_e::ok, sds::clipboard::validation_e::too_large, sds::clipboard::validation_e::invalid_utf8, sds::clipboard::validation_e::contains_nul, sds::clipboard::validation_e::bad_png_signature, sds::clipboard::validation_e::bad_png_header, sds::clipboard::validation_e::image_too_large}) {
    EXPECT_FALSE(sds::clipboard::describe(result).empty());
  }
}

TEST_F(SdsClipboardCoreTest, PutSetsHostClipboardAndAnnouncesToOtherReaders) {
  EXPECT_TRUE(core->available());
  EXPECT_EQ(core->backend_name(), "fake");
  const auto result = core->put("A", "text/plain;charset=utf-8", "hello", "7");
  EXPECT_EQ(result.status, 204);
  EXPECT_EQ(result.host_seq, 1u);
  EXPECT_EQ(core->seq(), 1u);
  ASSERT_EQ(state->write_count(), 1u);
  EXPECT_EQ(state->written.back().text, "hello");
  EXPECT_FALSE(state->written.back().png.has_value());

  EXPECT_TRUE(published["A"].empty()) << "the origin client must not get its own change back";
  ASSERT_EQ(published["B"].size(), 1u);
  const auto &event = published["B"].front();
  EXPECT_EQ(event["type"], "clipboard");
  EXPECT_EQ(event["seq"], 1);
  EXPECT_EQ(event["types"], nlohmann::json::array({"text/plain"}));
  EXPECT_EQ(event["sizes"]["text/plain"], 5);
  EXPECT_EQ(retracted, std::vector<std::string> {"A"});

  const auto fetched = core->get("B", 1, sds::clipboard::type_e::text);
  EXPECT_EQ(fetched.status, 200);
  EXPECT_EQ(fetched.body, "hello");
  EXPECT_EQ(fetched.content_type, "text/plain; charset=utf-8");
  EXPECT_EQ(fetched.host_seq, 1u);
}

TEST_F(SdsClipboardCoreTest, PutRejectsInvalidRequests) {
  EXPECT_EQ(core->put("A", "text/plain", "x", "").status, 400);
  EXPECT_EQ(core->put("A", "text/plain", "x", "abc").status, 400);
  EXPECT_EQ(core->put("A", "text/plain", "x", "-1").status, 400);
  EXPECT_EQ(core->put("A", "text/html", "x", "1").status, 415);
  EXPECT_EQ(core->put("A", "", "x", "1").status, 415);
  EXPECT_EQ(core->put("A", "text/plain; charset=latin1", "x", "1").status, 415);
  EXPECT_EQ(core->put("A", "text/plain; charset=\"UTF-8\"", "x", "1").status, 204);

  auto invalid_utf8 = core->put("A", "text/plain", "\xC0\x80", "2");
  EXPECT_EQ(invalid_utf8.status, 400);
  EXPECT_EQ(invalid_utf8.error, "bad_request");
  EXPECT_EQ(core->put("A", "text/plain", std::string {"a\0b", 3}, "2").status, 400);
  auto oversized = core->put("A", "text/plain", std::string(65, 'x'), "2");
  EXPECT_EQ(oversized.status, 413);
  EXPECT_EQ(oversized.error, "too_large");
  EXPECT_EQ(core->put("A", "image/png", "not a png at all, definitely not one", "2").status, 400);
  EXPECT_EQ(core->put("A", "image/png", png_header(8192, 8193), "2").status, 400);
  EXPECT_EQ(core->put("A", "image/png", std::string(5000, 'x'), "2").status, 413);
  EXPECT_EQ(core->seq(), 1u) << "rejected PUTs must not change the clipboard";

  state->fail_write = true;
  const auto failed = core->put("A", "text/plain", "y", "3");
  EXPECT_EQ(failed.status, 500);
  EXPECT_EQ(core->seq(), 1u);
}

TEST_F(SdsClipboardCoreTest, SecondRepresentationWithSameClientSeqExtendsTheItem) {
  ASSERT_EQ(core->put("A", "text/plain", "caption", "5").status, 204);
  const auto png = test_utils::sds::tiny_png();
  const auto merged = core->put("A", "image/png", png, "5");
  ASSERT_EQ(merged.status, 204);
  EXPECT_EQ(merged.host_seq, 2u);
  ASSERT_EQ(state->write_count(), 2u);
  EXPECT_EQ(state->written.back().text, "caption");
  ASSERT_TRUE(state->written.back().png.has_value());
  EXPECT_EQ(state->written.back().png->size(), png.size());
  ASSERT_EQ(published["B"].size(), 2u);
  EXPECT_EQ(published["B"].back()["types"], nlohmann::json::array({"text/plain", "image/png"}));
  EXPECT_EQ(core->get("B", 2, sds::clipboard::type_e::png).body, png);
  EXPECT_EQ(core->get("B", 2, sds::clipboard::type_e::text).body, "caption");

  // A different client seq starts a new item.
  ASSERT_EQ(core->put("A", "image/png", png, "6").status, 204);
  EXPECT_FALSE(state->written.back().text.has_value());

  // Another client never extends A's item.
  ASSERT_EQ(core->put("B", "text/plain", "b", "6").status, 204);
  EXPECT_FALSE(state->written.back().png.has_value());
}

TEST_F(SdsClipboardCoreTest, CoalescingWindowExpires) {
  make_core(std::make_unique<test_utils::sds::fake_clipboard_backend_t>(state), 20ms);
  ASSERT_EQ(core->put("A", "text/plain", "caption", "5").status, 204);
  std::this_thread::sleep_for(60ms);
  ASSERT_EQ(core->put("A", "image/png", test_utils::sds::tiny_png(), "5").status, 204);
  EXPECT_FALSE(state->written.back().text.has_value());
}

TEST_F(SdsClipboardCoreTest, GetReportsStaleSeqAndMissingRepresentations) {
  ASSERT_EQ(core->put("A", "text/plain", "one", "1").status, 204);
  ASSERT_EQ(core->put("A", "text/plain", "two", "2").status, 204);
  const auto stale = core->get("B", 1, sds::clipboard::type_e::text);
  EXPECT_EQ(stale.status, 410);
  EXPECT_EQ(stale.host_seq, 2u);
  EXPECT_EQ(core->get("B", std::nullopt, sds::clipboard::type_e::text).body, "two");
  const auto missing = core->get("B", 2, sds::clipboard::type_e::png);
  EXPECT_EQ(missing.status, 404);
  EXPECT_EQ(missing.error, "not_found");
}

TEST_F(SdsClipboardCoreTest, WatchingReadsHostChangesAndAnnouncesThem) {
  state->content = sds::clipboard::item_t {"initial", std::nullopt};
  core->set_watching(true);
  EXPECT_TRUE(core->watching());
  EXPECT_TRUE(state->started);
  EXPECT_EQ(core->seq(), 1u) << "starting to watch primes the cache";
  EXPECT_EQ(published["A"].size(), 1u);
  EXPECT_EQ(published["B"].size(), 1u);

  state->host_set(sds::clipboard::item_t {"from host", std::nullopt});
  EXPECT_EQ(core->seq(), 1u) << "changes are processed on the worker";
  run_posted();
  EXPECT_EQ(core->seq(), 2u);
  EXPECT_EQ(published["A"].back()["seq"], 2);
  EXPECT_EQ(published["B"].back()["seq"], 2);
  EXPECT_EQ(core->get("A", 2, sds::clipboard::type_e::text).body, "from host");

  // A duplicate notification without a content change is ignored.
  state->host_set(sds::clipboard::item_t {"from host", std::nullopt});
  run_posted();
  EXPECT_EQ(core->seq(), 2u);

  // Content the host cleared is not announced but invalidates the old seq.
  state->host_set(sds::clipboard::item_t {});
  run_posted();
  EXPECT_EQ(core->seq(), 3u);
  EXPECT_EQ(published["A"].size(), 2u);
  EXPECT_EQ(core->get("A", 2, sds::clipboard::type_e::text).status, 410);

  core->announce_to("C");
  EXPECT_TRUE(published["C"].empty()) << "nothing to announce for an empty clipboard";

  core->set_watching(false);
  EXPECT_FALSE(core->watching());
  EXPECT_FALSE(state->started);
  EXPECT_FALSE(core->has_content());
  EXPECT_EQ(state->stops, 1);
}

TEST_F(SdsClipboardCoreTest, EchoOfOwnWriteIsSuppressed) {
  core->set_watching(true);
  state->notify_own_writes = true;
  ASSERT_EQ(core->put("A", "text/plain", "mine", "1").status, 204);
  const auto seq = core->seq();
  run_posted();
  EXPECT_EQ(core->seq(), seq) << "the backend reporting our own write must not create a new host change";
  EXPECT_TRUE(published["A"].empty());
  EXPECT_EQ(published["B"].size(), 1u);
}

TEST_F(SdsClipboardCoreTest, BackendContentIsValidatedBeforeCaching) {
  state->content = sds::clipboard::item_t {"\xC0\x80 invalid", std::vector<std::uint8_t> {1, 2, 3}};
  core->set_watching(true);
  EXPECT_FALSE(core->has_content());
  const auto png = test_utils::sds::tiny_png();
  state->host_set(sds::clipboard::item_t {std::string(100, 'x'), std::vector<std::uint8_t>(png.begin(), png.end())});
  run_posted();
  EXPECT_TRUE(core->has_content());
  EXPECT_EQ(core->get("A", std::nullopt, sds::clipboard::type_e::text).status, 404) << "oversized text is dropped";
  EXPECT_EQ(core->get("A", std::nullopt, sds::clipboard::type_e::png).body, png);
}

TEST_F(SdsClipboardCoreTest, AnnounceToSkipsOriginAndForgetClientResetsCoalescing) {
  ASSERT_EQ(core->put("A", "text/plain", "x", "9").status, 204);
  core->announce_to("A");
  EXPECT_TRUE(published["A"].empty());
  core->announce_to("C");
  ASSERT_EQ(published["C"].size(), 1u);

  core->forget_client("A");
  ASSERT_EQ(core->put("A", "image/png", test_utils::sds::tiny_png(), "9").status, 204);
  EXPECT_FALSE(state->written.back().text.has_value()) << "forgotten clients do not coalesce";
}

TEST_F(SdsClipboardCoreTest, StartFailureAndShutdown) {
  state->fail_start = true;
  core->set_watching(true);
  EXPECT_FALSE(core->watching());

  state->fail_start = false;
  core->set_watching(true);
  ASSERT_TRUE(core->watching());
  auto callback = state->on_change;
  core->shutdown();
  EXPECT_FALSE(core->watching());
  ASSERT_TRUE(callback);
  callback();
  const auto seq = core->seq();
  run_posted();
  EXPECT_EQ(core->seq(), seq) << "callbacks after shutdown are ignored";
}

TEST_F(SdsClipboardCoreTest, WithoutBackendTheFeatureIsUnavailable) {
  make_core(nullptr);
  EXPECT_FALSE(core->available());
  EXPECT_TRUE(core->backend_name().empty());
  EXPECT_EQ(core->put("A", "text/plain", "x", "1").status, 404);
  core->set_watching(true);
  EXPECT_FALSE(core->watching());
}
