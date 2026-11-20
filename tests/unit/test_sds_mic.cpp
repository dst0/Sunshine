/**
 * @file tests/unit/test_sds_mic.cpp
 * @brief Microphone passthrough: framing, AES-GCM test vectors shared with moonlight-common-c, replay window,
 *        rate limit, ping binding, jitter buffer, playout, UDP receiver, advertising and RTSP negotiation.
 */

// local includes
// Include before test helpers so transitive atomic includes cannot hide C++ templates inside C linkage.
#include <src/compat/moonlight.h>

// test includes
#include "../tests_common.h"

// standard includes
#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cmath>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

// lib includes
#include <boost/asio.hpp>
#include <opus/opus.h>
extern "C" {
#include <moonlight-common-c/src/Rtsp.h>
}

// local includes
#include <src/config.h>
#include <src/network.h>
#include <src/rtsp.h>
#include <src/sds/mic.h>

using namespace std::literals;
using boost::asio::ip::udp;

namespace {
  const crypto::aes_t test_key {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

  // Test vectors from moonlight-common-c tests/sds_mic_test.c (cross-checked with Python cryptography AESGCM).
  const std::vector<std::uint8_t> vector1_opus {0xf8, 0xff, 0xfe};
  const std::vector<std::uint8_t> vector1_datagram {
    0x01,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x1c,
    0x34,
    0x27,
    0xe5,
    0x61,
    0xcd,
    0x56,
    0xa1,
    0x23,
    0xba,
    0x6e,
    0x51,
    0x4a,
    0x2d,
    0x15,
    0xb1,
    0xa8,
    0x93,
    0xdc
  };
  const std::vector<std::uint8_t> vector2_datagram {
    0x01,
    0x00,
    0x00,
    0x00,
    0x01,
    0x02,
    0x03,
    0x04,
    0x0a,
    0x0b,
    0x0c,
    0x0d,
    0x4c,
    0x18,
    0x08,
    0x03,
    0xf5,
    0x66,
    0xcf,
    0x29,
    0xcc,
    0xb2,
    0xa8,
    0x3d,
    0x0c,
    0xb0,
    0xeb,
    0xbc,
    0xda,
    0xc1,
    0xcd,
    0x4d,
    0xf2,
    0x3f,
    0x80,
    0x1c,
    0x45,
    0x08,
    0x46,
    0x59,
    0x30,
    0x9a,
    0xac,
    0xa9,
    0xa2,
    0x2a,
    0x06,
    0x8c,
    0xc4,
    0xfb,
    0xb0,
    0x5f,
    0xcd,
    0x6a,
    0xd7,
    0xb7,
    0x55,
    0xf0,
    0x2d,
    0x20
  };
  const std::string test_ping_payload = "0123456789ABCDEF";

  std::vector<std::uint8_t> vector2_opus() {
    std::vector<std::uint8_t> opus(32);
    for (std::size_t i = 0; i < opus.size(); ++i) {
      opus[i] = static_cast<std::uint8_t>(i);
    }
    return opus;
  }

  std::vector<std::uint8_t> make_ping(const std::string &payload, std::uint32_t counter = 1) {
    std::vector<std::uint8_t> ping(payload.begin(), payload.end());
    ping.push_back(static_cast<std::uint8_t>(counter >> 24));
    ping.push_back(static_cast<std::uint8_t>(counter >> 16));
    ping.push_back(static_cast<std::uint8_t>(counter >> 8));
    ping.push_back(static_cast<std::uint8_t>(counter));
    return ping;
  }

  /**
   * @brief Sink that records PCM.
   */
  class fake_sink_t: public sds::mic::sink_t {
  public:
    explicit fake_sink_t(int start_result = 0):
        start_result {start_result} {
    }

    int start() override {
      ++starts;
      return start_result;
    }

    void write(std::span<const std::int16_t> pcm) override {
      std::scoped_lock lock {mutex};
      samples.insert(samples.end(), pcm.begin(), pcm.end());
      ++writes;
    }

    void stop() override {
      ++stops;
    }

    std::string_view name() const override {
      return "fake"sv;
    }

    std::vector<std::int16_t> copy() {
      std::scoped_lock lock {mutex};
      return samples;
    }

    int start_result;
    std::atomic_int starts {0};
    std::atomic_int stops {0};
    std::atomic_int writes {0};
    std::mutex mutex;
    std::vector<std::int16_t> samples;
  };

  /**
   * @brief Decoder that records the requested actions and writes a marker sample.
   */
  class fake_decoder_t: public sds::mic::decoder_t {
  public:
    struct call_t {
      std::vector<std::uint8_t> packet;
      bool fec;
    };

    int decode(std::span<const std::uint8_t> packet, bool fec, std::span<std::int16_t> out) override {
      calls->push_back({{packet.begin(), packet.end()}, fec});
      const std::int16_t marker = packet.empty() ? std::int16_t {-1} : static_cast<std::int16_t>(packet[0]);
      std::fill(out.begin(), out.begin() + sds::mic::FRAME_SAMPLES, marker);
      return sds::mic::FRAME_SAMPLES;
    }

    std::shared_ptr<std::vector<call_t>> calls = std::make_shared<std::vector<call_t>>();
  };

  /**
   * @brief Restores global mic configuration after each test.
   */
  class SdsMicTest: public BaseTest {
  protected:
    void SetUp() override {
      BaseTest::SetUp();
      saved_passthrough = config::sds_mic.passthrough;
      config::sds_mic.passthrough = true;
    }

    void TearDown() override {
      config::sds_mic.passthrough = saved_passthrough;
      sds::mic::set_sink_provider({});
      BaseTest::TearDown();
    }

    static sds::mic::session_config_t make_config() {
      sds::mic::session_config_t cfg;
      cfg.key = test_key;
      cfg.ping_payload = test_ping_payload;
      cfg.expected_address = boost::asio::ip::make_address("192.168.1.20");
      cfg.client_cert = "-----BEGIN CERTIFICATE-----\nclient\n-----END CERTIFICATE-----\n";
      cfg.start_playout_thread = false;
      return cfg;
    }

    struct harness_t {
      fake_sink_t *sink;
      std::shared_ptr<std::vector<fake_decoder_t::call_t>> calls;
      std::shared_ptr<sds::mic::session_t> session;
    };

    static harness_t make_session(sds::mic::session_config_t cfg = make_config()) {
      auto sink = std::make_unique<fake_sink_t>();
      auto decoder = std::make_unique<fake_decoder_t>();
      harness_t h {sink.get(), decoder->calls, nullptr};
      h.session = std::make_shared<sds::mic::session_t>(std::move(cfg), std::move(sink), std::move(decoder));
      return h;
    }

    bool saved_passthrough = true;
    const udp::endpoint client {boost::asio::ip::make_address("192.168.1.20"), 50123};
    const std::chrono::steady_clock::time_point t0 {std::chrono::seconds {1000}};
  };

  using sds::mic::result_e;
}  // namespace

TEST(SdsMicPacketTest, HeaderAndIvLayoutMatchDesign) {
  const auto header = sds::mic::make_header(0xdeadbeef, 0x01020304);
  const std::array<std::uint8_t, 12> expected_header {0x01, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04};
  EXPECT_EQ(header, expected_header);

  const auto iv = sds::mic::make_iv(0x01020304);
  const std::array<std::uint8_t, 12> expected_iv {0x04, 0x03, 0x02, 0x01, 0, 0, 0, 0, 0, 0, 'C', 'M'};
  EXPECT_EQ(iv, expected_iv);
}

TEST(SdsMicPacketTest, ParseHeaderValidatesSizeVersionFlagsAndReserved) {
  std::vector<std::uint8_t> datagram(sds::mic::HEADER_SIZE + sds::mic::TAG_SIZE + 1, 0);
  const auto header = sds::mic::make_header(7, 960 * 7);
  std::copy(header.begin(), header.end(), datagram.begin());

  auto parsed = sds::mic::parse_header(datagram);
  ASSERT_TRUE(parsed);
  EXPECT_EQ(parsed->sequence, 7u);
  EXPECT_EQ(parsed->timestamp, 960u * 7);

  // No Opus payload
  EXPECT_FALSE(sds::mic::parse_header(std::span {datagram}.first(sds::mic::HEADER_SIZE + sds::mic::TAG_SIZE)));
  // Largest and one-too-large datagram
  datagram.resize(sds::mic::MAX_DATAGRAM);
  EXPECT_TRUE(sds::mic::parse_header(datagram));
  datagram.resize(sds::mic::MAX_DATAGRAM + 1);
  EXPECT_FALSE(sds::mic::parse_header(datagram));
  datagram.resize(64);

  for (std::size_t byte : {0u, 1u, 2u, 3u}) {
    auto copy = datagram;
    copy[byte] ^= byte == 0 ? 0x03 : 0x01;
    EXPECT_FALSE(sds::mic::parse_header(copy)) << "byte " << byte;
  }
}

TEST(SdsMicPacketTest, SharedTestVectorsDecryptAndEncryptByteForByte) {
  sds::mic::packet_cipher_t cipher {test_key};

  auto header1 = sds::mic::parse_header(vector1_datagram);
  ASSERT_TRUE(header1);
  EXPECT_EQ(header1->sequence, 0u);
  auto plain1 = cipher.decrypt(vector1_datagram, *header1);
  ASSERT_TRUE(plain1);
  EXPECT_EQ(*plain1, vector1_opus);

  auto header2 = sds::mic::parse_header(vector2_datagram);
  ASSERT_TRUE(header2);
  EXPECT_EQ(header2->sequence, 0x01020304u);
  EXPECT_EQ(header2->timestamp, 0x0a0b0c0du);
  auto plain2 = cipher.decrypt(vector2_datagram, *header2);
  ASSERT_TRUE(plain2);
  EXPECT_EQ(*plain2, vector2_opus());

  sds::mic::packet_cipher_t encryptor {test_key};
  EXPECT_EQ(encryptor.encrypt(0, 0, vector1_opus), vector1_datagram);
  EXPECT_EQ(encryptor.encrypt(0x01020304, 0x0a0b0c0d, vector2_opus()), vector2_datagram);
}

TEST(SdsMicPacketTest, TagFailureOnAnyModifiedByteOrWrongKey) {
  sds::mic::packet_cipher_t cipher {test_key};
  for (std::size_t byte = 0; byte < vector2_datagram.size(); ++byte) {
    auto copy = vector2_datagram;
    copy[byte] ^= 0x80;
    auto header = sds::mic::parse_header(copy);
    if (!header) {
      continue;  // version/flags/reserved bytes are rejected before decryption
    }
    EXPECT_FALSE(cipher.decrypt(copy, *header)) << "byte " << byte;
  }

  auto wrong_key = test_key;
  wrong_key[0] ^= 1;
  sds::mic::packet_cipher_t wrong {wrong_key};
  EXPECT_FALSE(wrong.decrypt(vector1_datagram, *sds::mic::parse_header(vector1_datagram)));

  // A packet re-labelled with another sequence number fails (IV and AAD both bind it)
  auto relabelled = vector2_datagram;
  relabelled[7] = 0x05;
  EXPECT_FALSE(cipher.decrypt(relabelled, *sds::mic::parse_header(relabelled)));
}

TEST(SdsMicReplayTest, RejectsDuplicatesAndOldButAcceptsInWindowReordering) {
  sds::mic::replay_window_t window;
  EXPECT_TRUE(window.check(10));
  window.commit(10);
  EXPECT_FALSE(window.check(10));  // duplicate

  EXPECT_TRUE(window.check(12));
  window.commit(12);
  EXPECT_TRUE(window.check(11));  // out of order, inside the window
  window.commit(11);
  EXPECT_FALSE(window.check(11));

  // check() alone does not commit
  EXPECT_TRUE(window.check(300));
  EXPECT_TRUE(window.check(300));
  window.commit(300);

  EXPECT_TRUE(window.check(300 - 127));  // oldest still inside the window
  EXPECT_FALSE(window.check(300 - 128));  // just outside
  EXPECT_FALSE(window.check(12));
  window.commit(300 - 127);
  EXPECT_FALSE(window.check(300 - 127));

  // A jump beyond the window clears history
  window.commit(1000);
  EXPECT_FALSE(window.check(1000));
  EXPECT_TRUE(window.check(999));
  EXPECT_FALSE(window.check(300));
}

TEST(SdsMicRateTest, TokenBucketCapsBurstAndSustainedRate) {
  sds::mic::rate_limiter_t limiter;
  const std::chrono::steady_clock::time_point start {std::chrono::seconds {50}};

  int allowed = 0;
  for (int i = 0; i < 100; ++i) {
    allowed += limiter.allow(start) ? 1 : 0;
  }
  EXPECT_EQ(allowed, sds::mic::RATE_LIMIT_BURST);

  // 100 ms later: 20 more tokens at 200/s
  allowed = 0;
  for (int i = 0; i < 100; ++i) {
    allowed += limiter.allow(start + 100ms) ? 1 : 0;
  }
  EXPECT_EQ(allowed, 20);

  // Sustained 50 packets/s (normal 20 ms Opus) is never limited
  sds::mic::rate_limiter_t normal;
  for (int i = 0; i < 500; ++i) {
    EXPECT_TRUE(normal.allow(start + i * 20ms));
  }

  // 1000 packets/s for 2 s: at most 200/s plus the burst get through
  sds::mic::rate_limiter_t flood;
  allowed = 0;
  for (int i = 0; i < 2000; ++i) {
    allowed += flood.allow(start + i * 1ms) ? 1 : 0;
  }
  EXPECT_LE(allowed, 2 * sds::mic::RATE_LIMIT_PER_SECOND + sds::mic::RATE_LIMIT_BURST);
  EXPECT_GE(allowed, 2 * sds::mic::RATE_LIMIT_PER_SECOND - 2);
}

TEST(SdsMicJitterTest, BuffersReordersAndConceals) {
  using action = sds::mic::jitter_buffer_t::action_e;
  sds::mic::jitter_buffer_t jitter {2, 3, 5};

  EXPECT_EQ(jitter.pop().action, action::none);
  ASSERT_TRUE(jitter.push(1, {1}));
  EXPECT_EQ(jitter.pop().action, action::none);  // below target
  ASSERT_TRUE(jitter.push(0, {0}));  // arrives late but before playout: reordered

  auto step = jitter.pop();
  EXPECT_EQ(step.action, action::decode);
  EXPECT_EQ(step.payload, std::vector<std::uint8_t> {0});
  step = jitter.pop();
  EXPECT_EQ(step.action, action::decode);
  EXPECT_EQ(step.payload, std::vector<std::uint8_t> {1});

  // 2 lost, 3 present -> FEC from 3, then 3 decoded normally
  ASSERT_TRUE(jitter.push(3, {3}));
  step = jitter.pop();
  EXPECT_EQ(step.action, action::fec);
  EXPECT_EQ(step.payload, std::vector<std::uint8_t> {3});
  step = jitter.pop();
  EXPECT_EQ(step.action, action::decode);
  EXPECT_EQ(step.payload, std::vector<std::uint8_t> {3});

  // Late (already concealed/played) and duplicate frames are refused
  EXPECT_FALSE(jitter.push(2, {2}));
  EXPECT_FALSE(jitter.push(3, {3}));
  ASSERT_TRUE(jitter.push(5, {5}));
  EXPECT_FALSE(jitter.push(5, {5}));

  // 4 lost, 5 buffered: 4 is recovered from 5's FEC, then 5 decoded
  EXPECT_EQ(jitter.pop().action, action::fec);
  EXPECT_EQ(jitter.pop().action, action::decode);
  // Nothing buffered: PLC
  EXPECT_EQ(jitter.pop().action, action::plc);
}

TEST(SdsMicJitterTest, StopsAfterSustainedLossAndRestartsAfterRebuffering) {
  using action = sds::mic::jitter_buffer_t::action_e;
  sds::mic::jitter_buffer_t jitter {2, 3, 5};
  jitter.push(0, {0});
  jitter.push(1, {1});
  EXPECT_EQ(jitter.pop().action, action::decode);
  EXPECT_EQ(jitter.pop().action, action::decode);
  for (int i = 0; i < 5; ++i) {
    EXPECT_EQ(jitter.pop().action, action::plc);
  }
  EXPECT_EQ(jitter.pop().action, action::none);
  EXPECT_FALSE(jitter.playing());
  EXPECT_EQ(jitter.pop().action, action::none);

  // Resume (e.g. after mute) with a later sequence: rebuffer, then play from the oldest frame
  jitter.push(50, {50});
  EXPECT_EQ(jitter.pop().action, action::none);
  jitter.push(51, {51});
  auto step = jitter.pop();
  EXPECT_EQ(step.action, action::decode);
  EXPECT_EQ(step.payload, std::vector<std::uint8_t> {50});
  EXPECT_TRUE(jitter.playing());
}

TEST(SdsMicJitterTest, BoundsLatencyBySkippingOldFrames) {
  using action = sds::mic::jitter_buffer_t::action_e;
  sds::mic::jitter_buffer_t jitter {2, 3, 5};
  for (std::uint8_t seq = 0; seq < 10; ++seq) {
    jitter.push(seq, {seq});
  }
  // At most 3 frames (60 ms) between playout and the newest frame: play 7, 8, 9
  for (std::uint8_t expected = 7; expected < 10; ++expected) {
    auto step = jitter.pop();
    EXPECT_EQ(step.action, action::decode);
    EXPECT_EQ(step.payload, std::vector<std::uint8_t> {expected});
  }
  EXPECT_FALSE(jitter.push(3, {3}));
  EXPECT_EQ(jitter.size(), 0u);
}

TEST(SdsMicRingTest, PrefillUnderrunAndOverflow) {
  sds::mic::pcm_ring_t ring {10, 4};
  std::array<std::int16_t, 3> out {};

  const std::array<std::int16_t, 3> first {1, 2, 3};
  ring.write(first);
  EXPECT_EQ(ring.read(out), 0u);  // below prefill: silence
  EXPECT_EQ(out, (std::array<std::int16_t, 3> {0, 0, 0}));
  EXPECT_EQ(ring.size(), 3u);

  const std::array<std::int16_t, 2> second {4, 5};
  ring.write(second);
  EXPECT_EQ(ring.read(out), 3u);
  EXPECT_EQ(out, (std::array<std::int16_t, 3> {1, 2, 3}));
  EXPECT_EQ(ring.read(out), 2u);  // underrun: rest padded
  EXPECT_EQ(out, (std::array<std::int16_t, 3> {4, 5, 0}));

  // After an underrun the prefill applies again
  ring.write(first);
  EXPECT_EQ(ring.read(out), 0u);

  // Overflow keeps the newest samples
  ring.clear();
  std::array<std::int16_t, 12> many {};
  for (std::size_t i = 0; i < many.size(); ++i) {
    many[i] = static_cast<std::int16_t>(i + 1);
  }
  ring.write(many);
  EXPECT_EQ(ring.size(), 10u);
  std::array<std::int16_t, 10> all {};
  EXPECT_EQ(ring.read(all), 10u);
  EXPECT_EQ(all[0], 3);
  EXPECT_EQ(all[9], 12);
}

TEST_F(SdsMicTest, PingBindsOnlyFromTheRtspClientAddressWithTheRightPayload) {
  auto h = make_session();
  ASSERT_EQ(h.session->start(), 0);

  // Wrong payload, right address
  EXPECT_EQ(h.session->handle_datagram(make_ping("FEDCBA9876543210"), client, t0), result_e::ping_rejected);
  // Right payload, other address
  const udp::endpoint stranger {boost::asio::ip::make_address("192.168.1.66"), 50123};
  EXPECT_EQ(h.session->handle_datagram(make_ping(test_ping_payload), stranger, t0), result_e::ping_rejected);
  EXPECT_FALSE(h.session->bound_endpoint());

  // IPv4-mapped form of the expected address binds too
  const udp::endpoint mapped {boost::asio::ip::make_address("::ffff:192.168.1.20"), 50123};
  EXPECT_EQ(h.session->handle_datagram(make_ping(test_ping_payload), mapped, t0), result_e::ping_bound);
  EXPECT_EQ(h.session->bound_endpoint(), mapped);
  EXPECT_EQ(h.session->handle_datagram(make_ping(test_ping_payload, 2), mapped, t0), result_e::ping_keepalive);

  // Another port of the same host cannot rebind
  const udp::endpoint other_port {boost::asio::ip::make_address("::ffff:192.168.1.20"), 50124};
  EXPECT_EQ(h.session->handle_datagram(make_ping(test_ping_payload), other_port, t0), result_e::ping_rejected);
  EXPECT_EQ(h.session->bound_endpoint(), mapped);
}

TEST_F(SdsMicTest, DropsUnboundWrongSourceReplayedTamperedAndMalformedPackets) {
  auto h = make_session();
  ASSERT_EQ(h.session->start(), 0);
  sds::mic::packet_cipher_t encryptor {test_key};
  const std::vector<std::uint8_t> opus {0x10, 0x20, 0x30};

  auto packet0 = encryptor.encrypt(0, 0, opus);
  EXPECT_EQ(h.session->handle_datagram(packet0, client, t0), result_e::dropped_unbound);

  ASSERT_EQ(h.session->handle_datagram(make_ping(test_ping_payload), client, t0), result_e::ping_bound);
  const udp::endpoint other_port {client.address(), static_cast<unsigned short>(client.port() + 1)};
  EXPECT_EQ(h.session->handle_datagram(packet0, other_port, t0), result_e::dropped_wrong_source);

  EXPECT_EQ(h.session->handle_datagram(packet0, client, t0), result_e::accepted);
  EXPECT_EQ(h.session->handle_datagram(packet0, client, t0 + 1ms), result_e::dropped_replay);

  auto tampered = encryptor.encrypt(1, 960, opus);
  tampered.back() ^= 1;
  EXPECT_EQ(h.session->handle_datagram(tampered, client, t0 + 2ms), result_e::dropped_auth);
  // The failed packet did not consume sequence 1
  EXPECT_EQ(h.session->handle_datagram(encryptor.encrypt(1, 960, opus), client, t0 + 3ms), result_e::accepted);

  auto bad_version = encryptor.encrypt(2, 1920, opus);
  bad_version[0] = 2;
  EXPECT_EQ(h.session->handle_datagram(bad_version, client, t0 + 4ms), result_e::dropped_malformed);

  // Encrypted under another key (e.g. another session's rikey)
  auto other_key = test_key;
  other_key[15] ^= 0xff;
  sds::mic::packet_cipher_t other {other_key};
  EXPECT_EQ(h.session->handle_datagram(other.encrypt(5, 4800, opus), client, t0 + 5ms), result_e::dropped_auth);

  // Too old for the replay window
  EXPECT_EQ(h.session->handle_datagram(encryptor.encrypt(200, 0, opus), client, t0 + 6ms), result_e::accepted);
  EXPECT_EQ(h.session->handle_datagram(encryptor.encrypt(60, 0, opus), client, t0 + 7ms), result_e::dropped_replay);

  EXPECT_EQ(h.session->count(result_e::accepted), 3u);
  EXPECT_EQ(h.session->count(result_e::dropped_auth), 2u);
}

TEST_F(SdsMicTest, RateLimitAppliesBeforeDecryption) {
  auto h = make_session();
  ASSERT_EQ(h.session->start(), 0);
  sds::mic::packet_cipher_t encryptor {test_key};
  ASSERT_EQ(h.session->handle_datagram(make_ping(test_ping_payload), client, t0), result_e::ping_bound);

  int accepted = 0;
  int limited = 0;
  for (std::uint32_t seq = 0; seq < 300; ++seq) {
    auto result = h.session->handle_datagram(encryptor.encrypt(seq, seq * 960, std::vector<std::uint8_t> {1, 2, 3}), client, t0);
    accepted += result == result_e::accepted ? 1 : 0;
    limited += result == result_e::dropped_rate ? 1 : 0;
  }
  EXPECT_EQ(accepted, sds::mic::RATE_LIMIT_BURST);
  EXPECT_EQ(limited, 300 - sds::mic::RATE_LIMIT_BURST);
}

TEST_F(SdsMicTest, InactiveRevokedOrStoppingSessionsDropEverything) {
  auto h = make_session();
  ASSERT_EQ(h.session->start(), 0);
  sds::mic::packet_cipher_t encryptor {test_key};
  ASSERT_EQ(h.session->handle_datagram(make_ping(test_ping_payload), client, t0), result_e::ping_bound);
  EXPECT_EQ(h.session->handle_datagram(encryptor.encrypt(0, 0, std::vector<std::uint8_t> {1}), client, t0), result_e::accepted);

  // Global switch turned off mid-stream: the periodic permission check deactivates the session
  config::sds_mic.passthrough = false;
  h.session->refresh_permission();
  EXPECT_FALSE(h.session->active());
  EXPECT_EQ(h.session->handle_datagram(encryptor.encrypt(1, 960, std::vector<std::uint8_t> {1}), client, t0), result_e::dropped_inactive);
  config::sds_mic.passthrough = true;
  h.session->refresh_permission();
  EXPECT_FALSE(h.session->active());  // never re-enabled within the same stream

  auto h2 = make_session();
  ASSERT_EQ(h2.session->start(), 0);
  h2.session->deactivate();
  EXPECT_EQ(h2.session->handle_datagram(make_ping(test_ping_payload), client, t0), result_e::dropped_inactive);
}

TEST_F(SdsMicTest, StreamStoppingPredicateDeactivatesThePlayoutLoop) {
  auto cfg = make_config();
  std::atomic_bool running {true};
  cfg.stream_running = [&running]() {
    return running.load();
  };
  cfg.start_playout_thread = true;
  auto h = make_session(std::move(cfg));
  ASSERT_EQ(h.session->start(), 0);
  EXPECT_TRUE(h.session->active());
  running = false;
  for (int i = 0; i < 100 && h.session->active(); ++i) {
    std::this_thread::sleep_for(5ms);
  }
  EXPECT_FALSE(h.session->active());
  h.session->shutdown();
  EXPECT_EQ(h.sink->stops.load(), 1);
  h.session->shutdown();
  EXPECT_EQ(h.sink->stops.load(), 1);  // idempotent
}

TEST_F(SdsMicTest, StartFailsForBadParametersOrSinkFailure) {
  auto cfg = make_config();
  cfg.ping_payload = "short";
  EXPECT_NE(make_session(std::move(cfg)).session->start(), 0);

  auto cfg2 = make_config();
  cfg2.key.resize(8);
  EXPECT_NE(make_session(std::move(cfg2)).session->start(), 0);

  auto sink = std::make_unique<fake_sink_t>(-1);
  auto *sink_ptr = sink.get();
  sds::mic::session_t session {make_config(), std::move(sink), std::make_unique<fake_decoder_t>()};
  EXPECT_NE(session.start(), 0);
  EXPECT_EQ(sink_ptr->starts.load(), 1);
  session.shutdown();
  EXPECT_EQ(sink_ptr->stops.load(), 0);  // never started, never stopped
}

TEST_F(SdsMicTest, TickDecodesConcealsAndWritesToTheSink) {
  auto h = make_session();
  ASSERT_EQ(h.session->start(), 0);
  sds::mic::packet_cipher_t encryptor {test_key};
  ASSERT_EQ(h.session->handle_datagram(make_ping(test_ping_payload), client, t0), result_e::ping_bound);

  h.session->tick();  // nothing buffered yet
  EXPECT_EQ(h.sink->writes.load(), 0);

  auto send = [&](std::uint32_t seq) {
    return h.session->handle_datagram(encryptor.encrypt(seq, seq * 960, std::vector<std::uint8_t> {static_cast<std::uint8_t>(seq + 10)}), client, t0 + seq * 20ms);
  };
  ASSERT_EQ(send(0), result_e::accepted);
  ASSERT_EQ(send(1), result_e::accepted);
  h.session->tick();  // 0
  h.session->tick();  // 1
  ASSERT_EQ(send(3), result_e::accepted);  // 2 is lost
  h.session->tick();  // 2 via FEC
  h.session->tick();  // 3
  h.session->tick();  // PLC

  ASSERT_EQ(h.calls->size(), 5u);
  EXPECT_FALSE((*h.calls)[0].fec);
  EXPECT_EQ((*h.calls)[0].packet, std::vector<std::uint8_t> {10});
  EXPECT_EQ((*h.calls)[1].packet, std::vector<std::uint8_t> {11});
  EXPECT_TRUE((*h.calls)[2].fec);  // 2 recovered from 3's FEC
  EXPECT_EQ((*h.calls)[2].packet, std::vector<std::uint8_t> {13});
  EXPECT_FALSE((*h.calls)[3].fec);
  EXPECT_EQ((*h.calls)[3].packet, std::vector<std::uint8_t> {13});
  EXPECT_TRUE((*h.calls)[4].packet.empty());  // PLC

  auto samples = h.sink->copy();
  ASSERT_EQ(samples.size(), 5u * sds::mic::FRAME_SAMPLES);
  EXPECT_EQ(samples[0], 10);
  EXPECT_EQ(samples[2 * sds::mic::FRAME_SAMPLES], 13);
  EXPECT_EQ(samples.back(), -1);
}

TEST_F(SdsMicTest, RealOpusRoundTripReachesTheSink) {
  int error = 0;
  auto *encoder = opus_encoder_create(sds::mic::SAMPLE_RATE, 1, OPUS_APPLICATION_VOIP, &error);
  ASSERT_EQ(error, OPUS_OK);
  opus_encoder_ctl(encoder, OPUS_SET_BITRATE(48000));
  opus_encoder_ctl(encoder, OPUS_SET_INBAND_FEC(1));
  opus_encoder_ctl(encoder, OPUS_SET_PACKET_LOSS_PERC(10));

  auto sink = std::make_unique<fake_sink_t>();
  auto *sink_ptr = sink.get();
  auto decoder = sds::mic::make_opus_decoder();
  ASSERT_TRUE(decoder);
  sds::mic::session_t session {make_config(), std::move(sink), std::move(decoder)};
  ASSERT_EQ(session.start(), 0);
  ASSERT_EQ(session.handle_datagram(make_ping(test_ping_payload), client, t0), result_e::ping_bound);

  sds::mic::packet_cipher_t encryptor {test_key};
  std::array<std::int16_t, sds::mic::FRAME_SAMPLES> pcm {};
  std::array<std::uint8_t, sds::mic::MAX_OPUS> packet {};
  std::uint64_t phase = 0;
  for (std::uint32_t seq = 0; seq < 50; ++seq) {
    for (auto &sample : pcm) {
      sample = static_cast<std::int16_t>(8000.0 * std::sin(2.0 * 3.14159265358979 * 440.0 * static_cast<double>(phase++) / sds::mic::SAMPLE_RATE));
    }
    auto bytes = opus_encode(encoder, pcm.data(), sds::mic::FRAME_SAMPLES, packet.data(), static_cast<opus_int32>(packet.size()));
    ASSERT_GT(bytes, 0);
    if (seq == 20) {
      continue;  // lost packet, recovered via FEC
    }
    ASSERT_EQ(session.handle_datagram(encryptor.encrypt(seq, seq * 960, std::span {packet.data(), static_cast<std::size_t>(bytes)}), client, t0 + seq * 20ms), result_e::accepted);
    session.tick();
  }
  opus_encoder_destroy(encoder);

  auto samples = sink_ptr->copy();
  ASSERT_GE(samples.size(), 40u * sds::mic::FRAME_SAMPLES);
  // After the codec settles the output carries the tone (RMS of an 8000-amplitude sine is ~5657)
  double sum = 0;
  const std::size_t from = 10 * sds::mic::FRAME_SAMPLES;
  for (std::size_t i = from; i < samples.size(); ++i) {
    sum += static_cast<double>(samples[i]) * samples[i];
  }
  const auto rms = std::sqrt(sum / static_cast<double>(samples.size() - from));
  EXPECT_GT(rms, 3000.0);
  EXPECT_LT(rms, 8000.0);
}

TEST_F(SdsMicTest, ReceiverRoutesPingsAndPacketsOverRealUdp) {
  auto cfg = make_config();
  cfg.expected_address = boost::asio::ip::address_v4::loopback();
  auto h = make_session(std::move(cfg));
  ASSERT_EQ(h.session->start(), 0);

  sds::mic::receiver_t receiver;
  ASSERT_EQ(receiver.add(h.session, {boost::asio::ip::address_v4::loopback(), 0}), 0);
  auto local = receiver.local_endpoint();
  ASSERT_TRUE(local);

  boost::asio::io_context io;
  udp::socket client_socket {io, udp::endpoint {boost::asio::ip::address_v4::loopback(), 0}};
  sds::mic::packet_cipher_t encryptor {test_key};

  // Data before ping: no session is bound to this source, dropped
  client_socket.send_to(boost::asio::buffer(encryptor.encrypt(0, 0, std::vector<std::uint8_t> {1})), *local);
  client_socket.send_to(boost::asio::buffer(make_ping(test_ping_payload)), *local);
  for (std::uint32_t seq = 1; seq <= 3; ++seq) {
    client_socket.send_to(boost::asio::buffer(encryptor.encrypt(seq, seq * 960, std::vector<std::uint8_t> {static_cast<std::uint8_t>(seq)})), *local);
  }
  for (int i = 0; i < 200 && h.session->count(result_e::accepted) < 3; ++i) {
    std::this_thread::sleep_for(5ms);
  }
  EXPECT_EQ(h.session->count(result_e::ping_bound), 1u);
  EXPECT_EQ(h.session->count(result_e::accepted), 3u);
  EXPECT_EQ(h.session->bound_endpoint(), client_socket.local_endpoint());

  // Routing: unknown source or unknown ping payload matches no session
  const udp::endpoint stranger {boost::asio::ip::address_v4::loopback(), 1};
  EXPECT_FALSE(receiver.route(encryptor.encrypt(9, 0, std::vector<std::uint8_t> {1}), stranger));
  EXPECT_FALSE(receiver.route(make_ping("FFFFFFFFFFFFFFFF"), stranger));
  EXPECT_EQ(receiver.route(make_ping(test_ping_payload), client_socket.local_endpoint()), result_e::ping_keepalive);

  receiver.remove(h.session);
  EXPECT_FALSE(receiver.local_endpoint());
  h.session->shutdown();
}

TEST_F(SdsMicTest, AdvertisingRequiresSwitchPermissionAndSink) {
  const std::string cert = "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n";
  bool sink_available = true;
  sds::mic::set_sink_provider({
    [&sink_available]() {
      return sink_available;
    },
    []() -> std::unique_ptr<sds::mic::sink_t> {
      return std::make_unique<fake_sink_t>();
    },
  });

  EXPECT_TRUE(sds::mic::should_advertise(cert));
  EXPECT_TRUE(sds_mic_permission_granted(cert));
  EXPECT_FALSE(sds::mic::should_advertise(""));  // not a paired client
  EXPECT_FALSE(sds_mic_permission_granted(""));
  sink_available = false;
  EXPECT_FALSE(sds::mic::should_advertise(cert));
  sink_available = true;
  config::sds_mic.passthrough = false;
  EXPECT_FALSE(sds::mic::should_advertise(cert));
  EXPECT_FALSE(sds_mic_permission_granted(cert));
}

TEST_F(SdsMicTest, StartSessionRespectsSwitchAndBindsTheMicPort) {
  sds::mic::set_sink_provider({
    []() {
      return true;
    },
    []() -> std::unique_ptr<sds::mic::sink_t> {
      return std::make_unique<fake_sink_t>();
    },
  });

  config::sds_mic.passthrough = false;
  EXPECT_FALSE(sds::mic::start_session(make_config()));
  config::sds_mic.passthrough = true;

  auto cfg = make_config();
  cfg.client_cert.clear();
  EXPECT_FALSE(sds::mic::start_session(std::move(cfg)));

  auto session = sds::mic::start_session(make_config());
  ASSERT_TRUE(session);
  EXPECT_TRUE(session->active());
  {
    // The production receiver owns base port + 13 while the session runs
    boost::asio::io_context io;
    udp::socket probe {io};
    probe.open(udp::v4());
    boost::system::error_code ec;
    probe.bind({boost::asio::ip::address_v4::any(), net::map_port(sds::mic::PORT_OFFSET)}, ec);
    EXPECT_TRUE(ec) << "mic port should be in use";
  }
  sds::mic::session_handle_t handle {session};
  handle.reset();
  EXPECT_FALSE(session->active());
  {
    boost::asio::io_context io;
    udp::socket probe {io};
    probe.open(udp::v4());
    boost::system::error_code ec;
    probe.bind({boost::asio::ip::address_v4::any(), net::map_port(sds::mic::PORT_OFFSET)}, ec);
    EXPECT_FALSE(ec) << "mic port should be released when the last session ends: " << ec.message();
  }
}

TEST(SdsMicPacketTest, PingPayloadsAreSixteenFreshHexCharacters) {
  auto a = sds::mic::generate_ping_payload();
  auto b = sds::mic::generate_ping_payload();
  EXPECT_EQ(a.size(), sds::mic::PING_PAYLOAD_SIZE);
  EXPECT_NE(a, b);
  EXPECT_TRUE(std::all_of(a.begin(), a.end(), [](char c) {
    return std::isxdigit(static_cast<unsigned char>(c)) != 0;
  }));
}

namespace rtsp_stream {
  class rtsp_server_t;
  void free_msg(PRTSP_MESSAGE message);
  using msg_t = util::safe_ptr<RTSP_MESSAGE, &free_msg>;
  void cmd_describe(rtsp_server_t *, boost::asio::ip::tcp::socket &sock, launch_session_t &session, msg_t &&req);
  void cmd_setup(rtsp_server_t *rtsp_server, boost::asio::ip::tcp::socket &sock, launch_session_t &session, msg_t &&req);
}  // namespace rtsp_stream

namespace {
  using rtsp_handler_t = void (*)(rtsp_stream::rtsp_server_t *, boost::asio::ip::tcp::socket &, rtsp_stream::launch_session_t &, rtsp_stream::msg_t &&);

  std::string run_rtsp(rtsp_handler_t handler, rtsp_stream::launch_session_t &session, std::string request_text) {
    using boost::asio::ip::tcp;
    boost::asio::io_context io;
    tcp::acceptor acceptor {io, {boost::asio::ip::address_v4::loopback(), 0}};
    tcp::socket client {io};
    client.connect(acceptor.local_endpoint());
    auto server_socket = acceptor.accept();

    std::vector<char> buffer(request_text.begin(), request_text.end());
    buffer.push_back('\0');
    rtsp_stream::msg_t request {new RTSP_MESSAGE {}};
    if (parseRtspMessage(request.get(), buffer.data(), static_cast<int>(request_text.size())) != RTSP_ERROR_SUCCESS) {
      return {};
    }
    handler(nullptr, server_socket, session, std::move(request));
    server_socket.shutdown(tcp::socket::shutdown_send);

    std::string response;
    boost::system::error_code read_error;
    boost::asio::read(client, boost::asio::dynamic_buffer(response), read_error);
    return response;
  }

  std::uint32_t feature_flags_of(const std::string &response) {
    const std::string key = "a=x-ss-general.featureFlags:";
    auto pos = response.find(key);
    if (pos == std::string::npos) {
      return 0;
    }
    return static_cast<std::uint32_t>(std::stoul(response.substr(pos + key.size())));
  }
}  // namespace

TEST_F(SdsMicTest, RtspDescribeAdvertisesTheFlagOnlyWhenAllowed) {
  rtsp_stream::launch_session_t session {};
  session.client_cert = "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n";
  const auto describe = "DESCRIBE rtsp://localhost RTSP/1.0\r\nCSeq: 2\r\n\r\n"s;

  sds::mic::set_sink_provider({
    []() {
      return true;
    },
    []() -> std::unique_ptr<sds::mic::sink_t> {
      return std::make_unique<fake_sink_t>();
    },
  });
  auto response = run_rtsp(&rtsp_stream::cmd_describe, session, describe);
  ASSERT_TRUE(response.starts_with("RTSP/1.0 200 OK\r\n"));
  EXPECT_EQ(feature_flags_of(response) & sds::mic::FEATURE_FLAG, sds::mic::FEATURE_FLAG);

  config::sds_mic.passthrough = false;
  response = run_rtsp(&rtsp_stream::cmd_describe, session, describe);
  EXPECT_EQ(feature_flags_of(response) & sds::mic::FEATURE_FLAG, 0u);
  config::sds_mic.passthrough = true;

  sds::mic::set_sink_provider({
    []() {
      return false;
    },
    []() -> std::unique_ptr<sds::mic::sink_t> {
      return nullptr;
    },
  });
  response = run_rtsp(&rtsp_stream::cmd_describe, session, describe);
  EXPECT_EQ(feature_flags_of(response) & sds::mic::FEATURE_FLAG, 0u);
}

TEST_F(SdsMicTest, RtspSetupMicReturnsPortAndPingPayloadOrNotFound) {
  rtsp_stream::launch_session_t session {};
  session.client_cert = "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n";
  const auto setup = "SETUP streamid=mic/0/0 RTSP/1.0\r\nCSeq: 5\r\nTransport: unicast;X-GS-ClientPort=50000-50001\r\n\r\n"s;

  // Not advertised (no sink): stock behaviour, 404 and nothing recorded
  sds::mic::set_sink_provider({
    []() {
      return false;
    },
    []() -> std::unique_ptr<sds::mic::sink_t> {
      return nullptr;
    },
  });
  auto response = run_rtsp(&rtsp_stream::cmd_setup, session, setup);
  EXPECT_TRUE(response.starts_with("RTSP/1.0 404")) << response;
  EXPECT_FALSE(session.mic_requested);
  EXPECT_TRUE(session.mic_ping_payload.empty());

  sds::mic::set_sink_provider({
    []() {
      return true;
    },
    []() -> std::unique_ptr<sds::mic::sink_t> {
      return std::make_unique<fake_sink_t>();
    },
  });
  response = run_rtsp(&rtsp_stream::cmd_setup, session, setup);
  ASSERT_TRUE(response.starts_with("RTSP/1.0 200 OK\r\n")) << response;
  EXPECT_NE(response.find("CSeq: 5\r\n"), std::string::npos);
  EXPECT_NE(response.find("server_port=" + std::to_string(net::map_port(sds::mic::PORT_OFFSET))), std::string::npos);
  EXPECT_TRUE(session.mic_requested);
  ASSERT_EQ(session.mic_ping_payload.size(), sds::mic::PING_PAYLOAD_SIZE);
  EXPECT_NE(response.find("X-SS-Ping-Payload: " + session.mic_ping_payload + "\r\n"), std::string::npos);
  EXPECT_NE(session.mic_ping_payload, session.av_ping_payload);

  // A repeated SETUP keeps the same payload
  const auto payload = session.mic_ping_payload;
  run_rtsp(&rtsp_stream::cmd_setup, session, setup);
  EXPECT_EQ(session.mic_ping_payload, payload);
}
