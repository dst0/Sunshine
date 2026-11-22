/**
 * @file src/sds/mic.cpp
 * @brief Microphone passthrough receive path: validation, AES-GCM, replay/rate limits, jitter buffer, decode, sink.
 */
// header include
#include "mic.h"

// standard includes
#include <algorithm>
#include <cstring>

// lib includes
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <opus/opus.h>

// local includes
#include "sds.h"
#include "src/config.h"
#include "src/logging.h"
#include "src/network.h"
#include "src/platform/common.h"
#include "src/utility.h"

using namespace std::literals;

bool sds_mic_permission_granted(const std::string &cert_pem) {
  return config::sds.mic_passthrough && sds::permission_granted(cert_pem, sds::permission_e::mic);
}

namespace sds::mic {
  namespace {
    std::uint32_t read_be32(const std::uint8_t *p) {
      return (std::uint32_t {p[0]} << 24) | (std::uint32_t {p[1]} << 16) | (std::uint32_t {p[2]} << 8) | std::uint32_t {p[3]};
    }

    std::mutex provider_mutex;
    std::optional<sink_provider_t> provider_override;

    sink_provider_t current_provider() {
      std::scoped_lock lock {provider_mutex};
      return provider_override ? *provider_override : platform_sink_provider();
    }

    std::string_view result_name(result_e result) {
      switch (result) {
        case result_e::ping_bound:
          return "ping_bound"sv;
        case result_e::ping_keepalive:
          return "ping_keepalive"sv;
        case result_e::ping_rejected:
          return "ping_rejected"sv;
        case result_e::accepted:
          return "accepted"sv;
        case result_e::dropped_inactive:
          return "dropped_inactive"sv;
        case result_e::dropped_unbound:
          return "dropped_unbound"sv;
        case result_e::dropped_wrong_source:
          return "dropped_wrong_source"sv;
        case result_e::dropped_rate:
          return "dropped_rate"sv;
        case result_e::dropped_malformed:
          return "dropped_malformed"sv;
        case result_e::dropped_replay:
          return "dropped_replay"sv;
        case result_e::dropped_auth:
          return "dropped_auth"sv;
        case result_e::dropped_late:
          return "dropped_late"sv;
      }
      return "unknown"sv;
    }

    /**
     * @brief libopus decoder for 48 kHz mono.
     */
    class opus_decoder_t: public decoder_t {
    public:
      explicit opus_decoder_t(OpusDecoder *decoder):
          _decoder {decoder} {
      }

      ~opus_decoder_t() override {
        opus_decoder_destroy(_decoder);
      }

      opus_decoder_t(const opus_decoder_t &) = delete;
      opus_decoder_t &operator=(const opus_decoder_t &) = delete;

      int decode(std::span<const std::uint8_t> packet, bool fec, std::span<std::int16_t> out) override {
        if (out.size() < static_cast<std::size_t>(FRAME_SAMPLES)) {
          return -1;
        }
        return opus_decode(_decoder, packet.empty() ? nullptr : packet.data(), static_cast<opus_int32>(packet.size()), out.data(), FRAME_SAMPLES, fec ? 1 : 0);
      }

    private:
      OpusDecoder *_decoder;
    };
  }  // namespace

  std::optional<header_t> parse_header(std::span<const std::uint8_t> datagram) {
    if (datagram.size() < HEADER_SIZE + TAG_SIZE + 1 || datagram.size() > MAX_DATAGRAM) {
      return std::nullopt;
    }
    if (datagram[0] != VERSION || datagram[1] != 0 || datagram[2] != 0 || datagram[3] != 0) {
      return std::nullopt;
    }
    return header_t {read_be32(&datagram[4]), read_be32(&datagram[8])};
  }

  std::array<std::uint8_t, IV_SIZE> make_iv(std::uint32_t sequence) {
    // NIST SP 800-38D 8.2.1 deterministic IV: invocation field = sequence (little-endian, like the
    // control stream), fixed field = 'C' (client originated) 'M' (microphone).
    std::array<std::uint8_t, IV_SIZE> iv {};
    iv[0] = static_cast<std::uint8_t>(sequence);
    iv[1] = static_cast<std::uint8_t>(sequence >> 8);
    iv[2] = static_cast<std::uint8_t>(sequence >> 16);
    iv[3] = static_cast<std::uint8_t>(sequence >> 24);
    iv[10] = 'C';
    iv[11] = 'M';
    return iv;
  }

  std::array<std::uint8_t, HEADER_SIZE> make_header(std::uint32_t sequence, std::uint32_t timestamp) {
    return {
      VERSION,
      0,
      0,
      0,
      static_cast<std::uint8_t>(sequence >> 24),
      static_cast<std::uint8_t>(sequence >> 16),
      static_cast<std::uint8_t>(sequence >> 8),
      static_cast<std::uint8_t>(sequence),
      static_cast<std::uint8_t>(timestamp >> 24),
      static_cast<std::uint8_t>(timestamp >> 16),
      static_cast<std::uint8_t>(timestamp >> 8),
      static_cast<std::uint8_t>(timestamp),
    };
  }

  packet_cipher_t::packet_cipher_t(const crypto::aes_t &key):
      _cipher {key, false} {
  }

  std::optional<std::vector<std::uint8_t>> packet_cipher_t::decrypt(std::span<const std::uint8_t> datagram, const header_t &header) {
    if (datagram.size() < HEADER_SIZE + TAG_SIZE) {
      return std::nullopt;
    }
    auto iv_array = make_iv(header.sequence);
    crypto::aes_t iv {iv_array.begin(), iv_array.end()};
    std::string_view aad {reinterpret_cast<const char *>(datagram.data()), HEADER_SIZE};
    std::string_view tagged {reinterpret_cast<const char *>(datagram.data()) + HEADER_SIZE, datagram.size() - HEADER_SIZE};

    std::vector<std::uint8_t> plaintext;
    if (_cipher.decrypt(tagged, plaintext, &iv, aad) != 0) {
      return std::nullopt;
    }
    return plaintext;
  }

  std::vector<std::uint8_t> packet_cipher_t::encrypt(std::uint32_t sequence, std::uint32_t timestamp, std::span<const std::uint8_t> opus) {
    auto header = make_header(sequence, timestamp);
    auto iv_array = make_iv(sequence);
    crypto::aes_t iv {iv_array.begin(), iv_array.end()};

    std::vector<std::uint8_t> datagram(HEADER_SIZE + TAG_SIZE + opus.size());
    std::copy(header.begin(), header.end(), datagram.begin());
    auto bytes = _cipher.encrypt(
      std::string_view {reinterpret_cast<const char *>(opus.data()), opus.size()},
      datagram.data() + HEADER_SIZE,
      datagram.data() + HEADER_SIZE + TAG_SIZE,
      &iv,
      std::string_view {reinterpret_cast<const char *>(header.data()), header.size()}
    );
    if (bytes != static_cast<int>(opus.size())) {
      return {};
    }
    return datagram;
  }

  bool replay_window_t::check(std::uint32_t sequence) const {
    if (!_any || sequence > _highest) {
      return true;
    }
    const auto age = _highest - sequence;
    if (age >= REPLAY_WINDOW) {
      return false;
    }
    return !_seen.test(age);
  }

  void replay_window_t::commit(std::uint32_t sequence) {
    if (!_any) {
      _any = true;
      _highest = sequence;
      _seen.reset();
      _seen.set(0);
      return;
    }
    if (sequence > _highest) {
      const auto shift = sequence - _highest;
      if (shift >= REPLAY_WINDOW) {
        _seen.reset();
      } else {
        _seen <<= shift;
      }
      _highest = sequence;
      _seen.set(0);
      return;
    }
    const auto age = _highest - sequence;
    if (age < REPLAY_WINDOW) {
      _seen.set(age);
    }
  }

  rate_limiter_t::rate_limiter_t(int rate_per_second, int burst):
      _rate {static_cast<double>(rate_per_second)},
      _burst {static_cast<double>(burst)},
      _tokens {static_cast<double>(burst)} {
  }

  bool rate_limiter_t::allow(std::chrono::steady_clock::time_point now) {
    if (_last) {
      const std::chrono::duration<double> elapsed = now - *_last;
      if (elapsed.count() > 0) {
        _tokens = std::min(_burst, _tokens + elapsed.count() * _rate);
      }
    }
    _last = now;
    if (_tokens < 1.0) {
      return false;
    }
    _tokens -= 1.0;
    return true;
  }

  jitter_buffer_t::jitter_buffer_t(std::size_t target_frames, std::size_t max_frames, std::size_t max_concealed):
      _target {std::max<std::size_t>(1, target_frames)},
      _max {std::max(max_frames, std::max<std::size_t>(1, target_frames))},
      _max_concealed {max_concealed} {
  }

  bool jitter_buffer_t::push(std::uint32_t sequence, std::vector<std::uint8_t> payload) {
    if (_last_played && sequence <= *_last_played) {
      return false;
    }
    if (!_frames.try_emplace(sequence, std::move(payload)).second) {
      return false;
    }
    // Hard memory bound independent of playout state
    while (_frames.size() > 64) {
      _frames.erase(_frames.begin());
    }
    return true;
  }

  jitter_buffer_t::step_t jitter_buffer_t::pop() {
    if (!_playing) {
      if (_frames.size() < _target) {
        return {action_e::none, {}};
      }
      _playing = true;
      _next = _frames.begin()->first;
      _concealed = 0;
    }

    // Bound latency: never keep more than _max frames between the playout position and the newest frame
    if (!_frames.empty()) {
      const auto newest = _frames.rbegin()->first;
      if (newest >= _next && newest - _next + 1 > _max) {
        const auto skip_to = newest - static_cast<std::uint32_t>(_max) + 1;
        _frames.erase(_frames.begin(), _frames.lower_bound(skip_to));
        _next = skip_to;
        _last_played = skip_to - 1;
      }
    }

    if (auto it = _frames.find(_next); it != _frames.end()) {
      step_t step {action_e::decode, std::move(it->second)};
      _frames.erase(it);
      _last_played = _next;
      ++_next;
      _concealed = 0;
      return step;
    }

    if (++_concealed > _max_concealed) {
      // Sustained gap (mute, pause or outage): stop until enough frames are buffered again
      _playing = false;
      _concealed = 0;
      return {action_e::none, {}};
    }

    _last_played = _next;
    ++_next;
    if (auto it = _frames.find(_next); it != _frames.end()) {
      return {action_e::fec, it->second};
    }
    return {action_e::plc, {}};
  }

  std::size_t jitter_buffer_t::size() const {
    return _frames.size();
  }

  bool jitter_buffer_t::playing() const {
    return _playing;
  }

  pcm_ring_t::pcm_ring_t(std::size_t capacity, std::size_t prefill):
      _buffer(std::max<std::size_t>(1, capacity)),
      _prefill {std::min(prefill, std::max<std::size_t>(1, capacity))} {
  }

  void pcm_ring_t::write(std::span<const std::int16_t> samples) {
    std::scoped_lock lock {_mutex};
    const auto capacity = _buffer.size();
    for (auto sample : samples) {
      if (_count == capacity) {
        // Overflow (producer clock faster than consumer): drop the oldest sample
        _head = (_head + 1) % capacity;
        --_count;
      }
      _buffer[(_head + _count) % capacity] = sample;
      ++_count;
    }
  }

  std::size_t pcm_ring_t::read(std::span<std::int16_t> out) {
    std::scoped_lock lock {_mutex};
    if (!_primed) {
      if (_count < _prefill) {
        std::fill(out.begin(), out.end(), std::int16_t {0});
        return 0;
      }
      _primed = true;
    }

    const auto capacity = _buffer.size();
    const auto n = std::min(_count, out.size());
    for (std::size_t i = 0; i < n; ++i) {
      out[i] = _buffer[(_head + i) % capacity];
    }
    _head = (_head + n) % capacity;
    _count -= n;
    std::fill(out.begin() + static_cast<std::ptrdiff_t>(n), out.end(), std::int16_t {0});
    if (n < out.size()) {
      // Underrun: rebuild the cushion before playing again
      _primed = false;
    }
    return n;
  }

  std::size_t pcm_ring_t::size() const {
    std::scoped_lock lock {_mutex};
    return _count;
  }

  void pcm_ring_t::clear() {
    std::scoped_lock lock {_mutex};
    _head = 0;
    _count = 0;
    _primed = false;
  }

  std::unique_ptr<decoder_t> make_opus_decoder() {
    int status = OPUS_OK;
    auto *decoder = opus_decoder_create(SAMPLE_RATE, 1, &status);
    if (!decoder || status != OPUS_OK) {
      BOOST_LOG(error) << "Microphone: couldn't create Opus decoder: "sv << opus_strerror(status);
      return nullptr;
    }
    return std::make_unique<opus_decoder_t>(decoder);
  }

  void set_sink_provider(sink_provider_t provider) {
    std::scoped_lock lock {provider_mutex};
    if (provider.available || provider.create) {
      provider_override = std::move(provider);
    } else {
      provider_override.reset();
    }
  }

  bool should_advertise(const std::string &client_cert) {
    if (!config::sds.mic_passthrough || !sds_mic_permission_granted(client_cert)) {
      return false;
    }
    auto provider = current_provider();
    return provider.available && provider.create && provider.available();
  }

  session_t::session_t(session_config_t params, std::unique_ptr<sink_t> sink, std::unique_ptr<decoder_t> decoder):
      _config {std::move(params)},
      _sink {std::move(sink)},
      _decoder {std::move(decoder)},
      _cipher {_config.key} {
  }

  session_t::~session_t() {
    shutdown();
  }

  int session_t::start() {
    if (!_sink || !_decoder || _config.key.size() != 16 || _config.ping_payload.size() != PING_PAYLOAD_SIZE) {
      return -1;
    }
    if (_sink->start() != 0) {
      BOOST_LOG(error) << "Microphone: couldn't start virtual microphone ("sv << _sink->name() << ')';
      return -1;
    }
    _sink_started = true;
    _active = true;
    if (_config.start_playout_thread) {
      _playout = std::jthread {[this](std::stop_token stop) {
        playout_loop(stop);
      }};
    }
    BOOST_LOG(info) << "Microphone passthrough started ("sv << _sink->name() << ')';
    return 0;
  }

  void session_t::deactivate() {
    std::scoped_lock playout_lock {_playout_mutex};
    _active = false;
    {
      std::scoped_lock lock {_mutex};
      _jitter = jitter_buffer_t {};
    }
    if (_sink_started.exchange(false)) {
      _sink->stop();
      BOOST_LOG(info) << "Microphone passthrough stopped: "sv
                      << count(result_e::accepted) << " frames, "sv
                      << count(result_e::dropped_auth) << " auth failures, "sv
                      << count(result_e::dropped_replay) << " replays, "sv
                      << count(result_e::dropped_rate) << " rate-limited, "sv
                      << count(result_e::dropped_wrong_source) + count(result_e::ping_rejected) << " wrong source"sv;
    }
  }

  void session_t::shutdown() {
    std::scoped_lock lock {_shutdown_mutex};
    deactivate();
    if (_playout.joinable()) {
      _playout.request_stop();
      _playout.join();
    }
  }

  bool session_t::ping_matches(std::span<const std::uint8_t> payload) const {
    return payload.size() == PING_PAYLOAD_SIZE && _config.ping_payload.size() == PING_PAYLOAD_SIZE &&
           CRYPTO_memcmp(payload.data(), _config.ping_payload.data(), PING_PAYLOAD_SIZE) == 0;
  }

  std::optional<boost::asio::ip::udp::endpoint> session_t::bound_endpoint() const {
    std::scoped_lock lock {_mutex};
    return _bound;
  }

  bool session_t::active() const {
    return _active;
  }

  std::uint64_t session_t::count(result_e result) const {
    return _counts[static_cast<std::size_t>(result)].load(std::memory_order_relaxed);
  }

  result_e session_t::handle_datagram(std::span<const std::uint8_t> datagram, const boost::asio::ip::udp::endpoint &from, std::chrono::steady_clock::time_point now) {
    auto result = [&]() -> result_e {
      if (!_active) {
        return result_e::dropped_inactive;
      }

      if (datagram.size() == PING_SIZE) {
        if (!ping_matches(datagram.first(PING_PAYLOAD_SIZE))) {
          return result_e::ping_rejected;
        }
        // Only the RTSP client's own address may bind (an on-path attacker could still race
        // the binding, which only denies service: data must authenticate either way).
        if (net::normalize_address(from.address()) != net::normalize_address(_config.expected_address)) {
          return result_e::ping_rejected;
        }
        std::scoped_lock lock {_mutex};
        if (!_active) {
          return result_e::dropped_inactive;
        }
        if (!_bound) {
          _bound = from;
          BOOST_LOG(debug) << "Microphone: bound "sv << from.address().to_string() << ':' << from.port();
          return result_e::ping_bound;
        }
        return *_bound == from ? result_e::ping_keepalive : result_e::ping_rejected;
      }

      std::scoped_lock lock {_mutex};
      if (!_active) {
        return result_e::dropped_inactive;
      }
      if (!_bound) {
        return result_e::dropped_unbound;
      }
      if (*_bound != from) {
        return result_e::dropped_wrong_source;
      }
      if (!_rate.allow(now)) {
        return result_e::dropped_rate;
      }
      auto header = parse_header(datagram);
      if (!header) {
        return result_e::dropped_malformed;
      }
      if (!_replay.check(header->sequence)) {
        return result_e::dropped_replay;
      }
      auto payload = _cipher.decrypt(datagram, *header);
      if (!payload) {
        return result_e::dropped_auth;
      }
      _replay.commit(header->sequence);
      if (!_jitter.push(header->sequence, std::move(*payload))) {
        return result_e::dropped_late;
      }
      return result_e::accepted;
    }();

    if (_counts[static_cast<std::size_t>(result)].fetch_add(1, std::memory_order_relaxed) == 0 && result != result_e::accepted && result != result_e::ping_keepalive && result != result_e::ping_bound) {
      BOOST_LOG(debug) << "Microphone: first "sv << result_name(result) << " from "sv << from.address().to_string() << ':' << from.port();
    }
    return result;
  }

  void session_t::tick() {
    std::scoped_lock playout_lock {_playout_mutex};
    if (!_active) {
      return;
    }
    jitter_buffer_t::step_t step;
    {
      std::scoped_lock lock {_mutex};
      step = _jitter.pop();
    }
    if (step.action == jitter_buffer_t::action_e::none) {
      return;
    }

    std::array<std::int16_t, FRAME_SAMPLES> pcm {};
    int samples = -1;
    switch (step.action) {
      case jitter_buffer_t::action_e::decode:
        samples = _decoder->decode(step.payload, false, pcm);
        break;
      case jitter_buffer_t::action_e::fec:
        samples = _decoder->decode(step.payload, true, pcm);
        break;
      case jitter_buffer_t::action_e::plc:
        samples = _decoder->decode({}, false, pcm);
        break;
      case jitter_buffer_t::action_e::none:
        break;
    }

    if (samples <= 0 || samples > FRAME_SAMPLES) {
      // Undecodable (e.g. frames longer than 20 ms): keep timing with silence
      pcm.fill(0);
      samples = FRAME_SAMPLES;
    }
    _sink->write(std::span<const std::int16_t> {pcm.data(), static_cast<std::size_t>(samples)});
  }

  void session_t::refresh_permission() {
    if (!config::sds.mic_passthrough || !sds_mic_permission_granted(_config.client_cert)) {
      if (_active) {
        deactivate();
        BOOST_LOG(warning) << "Microphone: permission revoked or feature disabled, dropping further audio"sv;
      }
    }
  }

  void session_t::playout_loop(std::stop_token stop) {
    platf::set_thread_name("sds::mic");
    std::mutex wait_mutex;
    std::condition_variable_any wait_cv;
    auto next = std::chrono::steady_clock::now();
    auto next_permission_check = next + 1s;

    while (!stop.stop_requested()) {
      if (_config.stream_running && !_config.stream_running() && _active) {
        deactivate();
        BOOST_LOG(debug) << "Microphone: stream stopping, dropping further audio"sv;
      }
      tick();

      auto now = std::chrono::steady_clock::now();
      if (now >= next_permission_check) {
        refresh_permission();
        next_permission_check = now + 1s;
      }

      next += FRAME_DURATION;
      if (now - next > 200ms) {
        // Far behind (suspend, scheduling stall): resynchronize instead of bursting
        next = now + FRAME_DURATION;
      }
      std::unique_lock lock {wait_mutex};
      wait_cv.wait_until(lock, stop, next, []() {
        return false;
      });
    }
  }

  receiver_t::receiver_t(std::function<void()> before_receive_loop, std::function<void()> after_detach):
      _before_receive_loop {std::move(before_receive_loop)},
      _after_detach {std::move(after_detach)} {
  }

  receiver_t::~receiver_t() {
    std::vector<std::shared_ptr<session_t>> sessions;
    {
      std::scoped_lock lock {_mutex};
      sessions = _sessions;
    }
    for (auto &session : sessions) {
      remove(session);
    }
  }

  int receiver_t::add(const std::shared_ptr<session_t> &session, const boost::asio::ip::udp::endpoint &bind_endpoint) {
    std::scoped_lock lock {_mutex};
    if (!_socket) {
      auto io = std::make_unique<boost::asio::io_context>();
      auto socket = std::make_unique<boost::asio::ip::udp::socket>(*io);
      boost::system::error_code ec;
      socket->open(bind_endpoint.protocol(), ec);
      if (!ec && bind_endpoint.address().is_v6() && bind_endpoint.address().is_unspecified()) {
        // Accept IPv4-mapped clients when bound to the IPv6 wildcard (address_family = both)
        socket->set_option(boost::asio::ip::v6_only {false}, ec);
      }
      if (!ec) {
        socket->bind(bind_endpoint, ec);
      }
      if (ec) {
        BOOST_LOG(error) << "Microphone: couldn't bind UDP port "sv << bind_endpoint.port() << ": "sv << ec.message();
        return -1;
      }
      _io = std::move(io);
      _socket = std::move(socket);
      _thread = std::thread {[this, io = _io.get(), socket = _socket.get()]() {
        if (_before_receive_loop) {
          _before_receive_loop();
        }
        receive_loop(*io, *socket);
      }};
    }
    _sessions.push_back(session);
    return 0;
  }

  void receiver_t::remove(const std::shared_ptr<session_t> &session) {
    std::unique_ptr<boost::asio::io_context> io;
    std::unique_ptr<boost::asio::ip::udp::socket> socket;
    std::thread thread;
    {
      std::scoped_lock lock {_mutex};
      std::erase(_sessions, session);
      if (!_sessions.empty() || !_socket) {
        return;
      }
      io = std::move(_io);
      socket = std::move(_socket);
      thread = std::move(_thread);
    }
    if (_after_detach) {
      _after_detach();
    }
    io->stop();
    if (thread.joinable()) {
      thread.join();
    }
    boost::system::error_code ec;
    socket->close(ec);
  }

  std::optional<boost::asio::ip::udp::endpoint> receiver_t::local_endpoint() const {
    std::scoped_lock lock {_mutex};
    if (!_socket) {
      return std::nullopt;
    }
    boost::system::error_code ec;
    auto endpoint = _socket->local_endpoint(ec);
    if (ec) {
      return std::nullopt;
    }
    return endpoint;
  }

  std::optional<result_e> receiver_t::route(std::span<const std::uint8_t> datagram, const boost::asio::ip::udp::endpoint &from) {
    std::vector<std::shared_ptr<session_t>> sessions;
    {
      std::scoped_lock lock {_mutex};
      sessions = _sessions;
    }
    const auto now = std::chrono::steady_clock::now();

    if (datagram.size() == PING_SIZE) {
      for (auto &session : sessions) {
        if (session->ping_matches(datagram.first(PING_PAYLOAD_SIZE))) {
          return session->handle_datagram(datagram, from, now);
        }
      }
      return std::nullopt;
    }

    for (auto &session : sessions) {
      if (session->bound_endpoint() == from) {
        return session->handle_datagram(datagram, from, now);
      }
    }
    // Unknown source: not bound to any session, drop without further work
    return std::nullopt;
  }

  void receiver_t::receive_loop(boost::asio::io_context &io, boost::asio::ip::udp::socket &socket) {
    platf::set_thread_name("sds::mic::recv");

    std::array<std::uint8_t, MAX_DATAGRAM + 1> buffer;
    boost::asio::ip::udp::endpoint peer;
    std::function<void(const boost::system::error_code &, std::size_t)> on_receive;
    on_receive = [&](const boost::system::error_code &ec, std::size_t bytes) {
      if (ec == boost::asio::error::operation_aborted) {
        return;
      }
      if (!ec && bytes > 0 && bytes <= MAX_DATAGRAM) {
        route(std::span<const std::uint8_t> {buffer.data(), bytes}, peer);
      }
      // ICMP-induced errors (connection refused/reset) and oversized datagrams are ignored
      socket.async_receive_from(boost::asio::buffer(buffer), peer, on_receive);
    };
    socket.async_receive_from(boost::asio::buffer(buffer), peer, on_receive);
    io.run();
  }

  namespace {
    receiver_t &global_receiver() {
      static receiver_t receiver;
      return receiver;
    }
  }  // namespace

  std::shared_ptr<session_t> start_session(session_config_t params) {
    if (!config::sds.mic_passthrough || !sds_mic_permission_granted(params.client_cert)) {
      return nullptr;
    }
    auto provider = current_provider();
    if (!provider.create) {
      return nullptr;
    }
    auto sink = provider.create();
    auto decoder = make_opus_decoder();
    if (!sink || !decoder) {
      BOOST_LOG(warning) << "Microphone: no virtual microphone available, continuing without microphone"sv;
      return nullptr;
    }

    auto session = std::make_shared<session_t>(std::move(params), std::move(sink), std::move(decoder));
    if (session->start() != 0) {
      return nullptr;
    }

    const auto af = net::get_effective_address_family(net::af_from_enum_string(config::sunshine.address_family));
    boost::system::error_code ec;
    const auto bind_address = boost::asio::ip::make_address(net::get_bind_address(af), ec);
    if (ec || global_receiver().add(session, {bind_address, net::map_port(PORT_OFFSET)}) != 0) {
      session->shutdown();
      return nullptr;
    }
    return session;
  }

  void stop_session(const std::shared_ptr<session_t> &session) {
    if (!session) {
      return;
    }
    session->deactivate();
    global_receiver().remove(session);
    session->shutdown();
  }

  session_handle_t::session_handle_t(std::shared_ptr<session_t> session):
      _session {std::move(session)} {
  }

  session_handle_t::~session_handle_t() {
    reset();
  }

  session_handle_t::session_handle_t(session_handle_t &&other) noexcept:
      _session {std::move(other._session)} {
  }

  session_handle_t &session_handle_t::operator=(session_handle_t &&other) noexcept {
    if (this != &other) {
      reset();
      _session = std::move(other._session);
    }
    return *this;
  }

  void session_handle_t::reset() {
    if (_session) {
      stop_session(_session);
      _session.reset();
    }
  }

  session_t *session_handle_t::get() const {
    return _session.get();
  }

  std::string generate_ping_payload() {
    std::array<std::uint8_t, PING_PAYLOAD_SIZE / 2> raw {};
    RAND_bytes(raw.data(), static_cast<int>(raw.size()));
    return util::hex_vec(raw);
  }
}  // namespace sds::mic
