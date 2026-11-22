/**
 * @file src/sds/mic.h
 * @brief Microphone passthrough (client -> host virtual microphone), secure-desktop-stream DESIGN.md section 7.
 *
 * Wire format (client -> host UDP, base port + 13):
 * @code{.unparsed}
 * header[12]  version(1) flags(0) reserved16(0) sequence32be timestamp32be   (GCM AAD)
 * tag[16]     AES-128-GCM tag
 * ciphertext  one Opus frame (48 kHz, mono, 20 ms), at most 1372 bytes
 * IV[12]      sequence32le || 0^6 || 'C' || 'M'      key: the session rikey
 * @endcode
 * The UDP source endpoint is bound by the first SS_PING (16-byte X-SS-Ping-Payload from the
 * RTSP SETUP streamid=mic response + 4-byte counter) from the RTSP client's address.
 */
#pragma once

// standard includes
#include <array>
#include <atomic>
#include <bitset>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

// lib includes
#include <boost/asio.hpp>

// local includes
#include "src/crypto.h"

/**
 * @brief Report whether a paired client may send microphone audio.
 *
 * Checks the current enabled paired-client store and the global feature switch.
 * Unknown, disabled, unpaired or unpermitted clients are refused.
 *
 * @param cert_pem PEM certificate of the paired client that owns the stream.
 * @return True when the `mic` permission is granted.
 */
bool sds_mic_permission_granted(const std::string &cert_pem);

namespace sds::mic {
  constexpr std::uint32_t FEATURE_FLAG = 0x10000000;  ///< `SS_FF_SDS_MIC` bit in `x-ss-general.featureFlags`.
  constexpr int PORT_OFFSET = 13;  ///< Base-port offset of the microphone UDP stream (48002 by default).
  constexpr std::uint8_t VERSION = 1;  ///< Packet format version.
  constexpr std::size_t HEADER_SIZE = 12;  ///< Cleartext header size (authenticated as AAD).
  constexpr std::size_t TAG_SIZE = 16;  ///< AES-GCM tag size.
  constexpr std::size_t IV_SIZE = 12;  ///< AES-GCM IV size.
  constexpr std::size_t PING_SIZE = 20;  ///< Size of an `SS_PING` (16-byte payload + 4-byte counter).
  constexpr std::size_t PING_PAYLOAD_SIZE = 16;  ///< Size of the ping payload sent in `X-SS-Ping-Payload`.
  constexpr std::size_t MAX_DATAGRAM = 1400;  ///< Largest accepted datagram.
  constexpr std::size_t MAX_OPUS = MAX_DATAGRAM - HEADER_SIZE - TAG_SIZE;  ///< Largest Opus frame.
  constexpr std::uint32_t REPLAY_WINDOW = 128;  ///< Replay window size in packets.
  constexpr int RATE_LIMIT_PER_SECOND = 200;  ///< Sustained packet rate limit.
  constexpr int RATE_LIMIT_BURST = 40;  ///< Token-bucket burst allowance.
  constexpr int SAMPLE_RATE = 48000;  ///< Opus and sink sample rate.
  constexpr int FRAME_SAMPLES = 960;  ///< Samples per 20 ms frame (mono).
  constexpr auto FRAME_DURATION = std::chrono::milliseconds {20};  ///< Duration of one frame.

  /**
   * @brief Parsed cleartext packet header.
   */
  struct header_t {
    std::uint32_t sequence;  ///< Packet sequence number (starts at 0, never wraps).
    std::uint32_t timestamp;  ///< 48 kHz sample clock of the first sample in the frame.
  };

  /**
   * @brief Validate the datagram size and header fields.
   *
   * @param datagram Complete received datagram.
   * @return Parsed header, or `std::nullopt` for a wrong size, version, flags or reserved field.
   */
  std::optional<header_t> parse_header(std::span<const std::uint8_t> datagram);

  /**
   * @brief Build the deterministic GCM IV for a sequence number.
   *
   * @param sequence Packet sequence number.
   * @return 12-byte IV: sequence (little-endian), six zero bytes, 'C', 'M'.
   */
  std::array<std::uint8_t, IV_SIZE> make_iv(std::uint32_t sequence);

  /**
   * @brief Serialize a packet header.
   *
   * @param sequence Packet sequence number.
   * @param timestamp 48 kHz timestamp.
   * @return 12-byte big-endian header.
   */
  std::array<std::uint8_t, HEADER_SIZE> make_header(std::uint32_t sequence, std::uint32_t timestamp);

  /**
   * @brief AES-128-GCM packet cipher bound to one session key.
   */
  class packet_cipher_t {
  public:
    /**
     * @brief Create a cipher for the session's remote input key.
     *
     * @param key 16-byte rikey.
     */
    explicit packet_cipher_t(const crypto::aes_t &key);

    /**
     * @brief Authenticate and decrypt a datagram whose header was already parsed.
     *
     * @param datagram Complete datagram (header, tag, ciphertext).
     * @param header Parsed header of `datagram`.
     * @return Opus payload, or `std::nullopt` when authentication fails.
     */
    std::optional<std::vector<std::uint8_t>> decrypt(std::span<const std::uint8_t> datagram, const header_t &header);

    /**
     * @brief Build an encrypted datagram (used by tests and tools; the host never sends mic packets).
     *
     * @param sequence Packet sequence number.
     * @param timestamp 48 kHz timestamp.
     * @param opus Opus payload.
     * @return Complete datagram, or an empty vector on failure.
     */
    std::vector<std::uint8_t> encrypt(std::uint32_t sequence, std::uint32_t timestamp, std::span<const std::uint8_t> opus);

  private:
    crypto::cipher::gcm_t _cipher;  ///< AES-128-GCM context bound to the session key.
  };

  /**
   * @brief 128-packet anti-replay window for sequence numbers that never wrap.
   */
  class replay_window_t {
  public:
    /**
     * @brief Check whether a sequence number may still be accepted.
     *
     * @param sequence Packet sequence number.
     * @return False when it is older than the window or was already committed.
     */
    bool check(std::uint32_t sequence) const;

    /**
     * @brief Record a sequence number after its packet authenticated successfully.
     *
     * @param sequence Packet sequence number previously passed to `check()`.
     */
    void commit(std::uint32_t sequence);

  private:
    bool _any = false;  ///< Whether any sequence number was committed yet.
    std::uint32_t _highest = 0;  ///< Highest committed sequence number.
    std::bitset<REPLAY_WINDOW> _seen;  ///< Bit i set: sequence `_highest - i` was accepted.
  };

  /**
   * @brief Token-bucket packet rate limiter.
   */
  class rate_limiter_t {
  public:
    /**
     * @brief Construct a limiter.
     *
     * @param rate_per_second Sustained rate.
     * @param burst Bucket size.
     */
    rate_limiter_t(int rate_per_second = RATE_LIMIT_PER_SECOND, int burst = RATE_LIMIT_BURST);

    /**
     * @brief Consume one token.
     *
     * @param now Current time.
     * @return False when the packet exceeds the rate limit.
     */
    bool allow(std::chrono::steady_clock::time_point now);

  private:
    double _rate;  ///< Tokens added per second.
    double _burst;  ///< Bucket capacity.
    double _tokens;  ///< Tokens currently available.
    std::optional<std::chrono::steady_clock::time_point> _last;  ///< Time of the previous call.
  };

  /**
   * @brief Reordering jitter buffer with loss concealment decisions.
   */
  class jitter_buffer_t {
  public:
    /**
     * @brief What the playout loop should do for the next 20 ms frame.
     */
    enum class action_e {
      none,  ///< Not playing (buffering or idle); write nothing.
      decode,  ///< Decode `payload` normally.
      fec,  ///< Recover the missing frame from the in-band FEC in `payload` (the following frame).
      plc,  ///< Conceal the missing frame with Opus packet loss concealment.
    };

    /**
     * @brief Result of one playout step.
     */
    struct step_t {
      action_e action;  ///< Action to take.
      std::vector<std::uint8_t> payload;  ///< Opus payload for `decode` and `fec`.
    };

    /**
     * @brief Construct a jitter buffer.
     *
     * @param target_frames Frames buffered before playout (re)starts.
     * @param max_frames Maximum frames buffered ahead of playout (older ones are skipped).
     * @param max_concealed Consecutive concealed frames before playout stops until rebuffered.
     */
    explicit jitter_buffer_t(std::size_t target_frames = 2, std::size_t max_frames = 3, std::size_t max_concealed = 5);

    /**
     * @brief Queue an authenticated frame.
     *
     * @param sequence Packet sequence number.
     * @param payload Opus payload.
     * @return False when the frame was dropped as late or duplicate.
     */
    bool push(std::uint32_t sequence, std::vector<std::uint8_t> payload);

    /**
     * @brief Produce the decision for the next 20 ms frame.
     *
     * @return Playout step.
     */
    step_t pop();

    /**
     * @brief Number of queued frames.
     *
     * @return Frame count.
     */
    std::size_t size() const;

    /**
     * @brief Whether playout is running.
     *
     * @return True while playing.
     */
    bool playing() const;

  private:
    std::size_t _target;  ///< Frames buffered before playout starts.
    std::size_t _max;  ///< Maximum frames between the playout position and the newest frame.
    std::size_t _max_concealed;  ///< Consecutive concealed frames before playout stops.
    std::map<std::uint32_t, std::vector<std::uint8_t>> _frames;  ///< Queued frames by sequence number.
    bool _playing = false;  ///< Whether playout is running.
    std::uint32_t _next = 0;  ///< Sequence number of the next frame to play.
    std::optional<std::uint32_t> _last_played;  ///< Last sequence number played or concealed; older frames are late.
    std::size_t _concealed = 0;  ///< Consecutive concealed frames.
  };

  /**
   * @brief Single-producer/single-consumer PCM ring with prefill, used by sinks.
   *
   * The consumer receives silence until `prefill` samples are queued and again after an underrun,
   * which avoids audible fragmenting when producer and consumer chunk sizes differ.
   */
  class pcm_ring_t {
  public:
    /**
     * @brief Construct a ring.
     *
     * @param capacity Maximum queued samples; the oldest are dropped on overflow.
     * @param prefill Samples required before reading starts.
     */
    explicit pcm_ring_t(std::size_t capacity = SAMPLE_RATE / 5, std::size_t prefill = FRAME_SAMPLES * 2);

    /**
     * @brief Append samples.
     *
     * @param samples PCM samples.
     */
    void write(std::span<const std::int16_t> samples);

    /**
     * @brief Fill `out` completely, padding with silence.
     *
     * @param out Destination.
     * @return Number of real (non-silence) samples copied.
     */
    std::size_t read(std::span<std::int16_t> out);

    /**
     * @brief Queued sample count.
     *
     * @return Samples.
     */
    std::size_t size() const;

    /**
     * @brief Drop all queued samples and require prefill again.
     */
    void clear();

  private:
    mutable std::mutex _mutex;  ///< Guards all ring state.
    std::vector<std::int16_t> _buffer;  ///< Sample storage.
    std::size_t _prefill;  ///< Samples required before reading starts.
    std::size_t _head = 0;  ///< Index of the oldest queued sample.
    std::size_t _count = 0;  ///< Queued sample count.
    bool _primed = false;  ///< Whether the prefill was reached since the last underrun.
  };

  /**
   * @brief Virtual microphone output.
   */
  class sink_t {
  public:
    virtual ~sink_t() = default;

    /**
     * @brief Create the platform device/stream.
     *
     * @return 0 on success.
     */
    virtual int start() = 0;

    /**
     * @brief Queue 48 kHz mono S16 PCM. Must not block for long.
     *
     * @param pcm Samples.
     */
    virtual void write(std::span<const std::int16_t> pcm) = 0;

    /**
     * @brief Destroy the platform device/stream. Idempotent.
     */
    virtual void stop() = 0;

    /**
     * @brief Backend name for logs.
     *
     * @return Name.
     */
    virtual std::string_view name() const = 0;
  };

  /**
   * @brief Opus decoder abstraction (replaceable in tests).
   */
  class decoder_t {
  public:
    virtual ~decoder_t() = default;

    /**
     * @brief Decode one frame.
     *
     * @param packet Opus packet, or empty for packet loss concealment.
     * @param fec Decode the in-band FEC data of `packet` (recovers the previous frame).
     * @param out Exactly `FRAME_SAMPLES` samples.
     * @return Decoded samples, or a negative value on error.
     */
    virtual int decode(std::span<const std::uint8_t> packet, bool fec, std::span<std::int16_t> out) = 0;
  };

  /**
   * @brief Create the libopus decoder (48 kHz mono).
   *
   * @return Decoder, or nullptr on failure.
   */
  std::unique_ptr<decoder_t> make_opus_decoder();

  /**
   * @brief Platform sink discovery and creation; replaceable for tests.
   */
  struct sink_provider_t {
    std::function<bool()> available;  ///< Whether a virtual microphone can be created now.
    std::function<std::unique_ptr<sink_t>()> create;  ///< Create (but do not start) a sink.
  };

  /**
   * @brief Platform default provider (PipeWire, then PulseAudio on Linux; WASAPI cable on Windows; none elsewhere).
   *
   * @return Provider.
   */
  sink_provider_t platform_sink_provider();

  /**
   * @brief Replace the provider used by `should_advertise()` and new sessions.
   *
   * @param provider New provider; an empty provider restores the platform default.
   */
  void set_sink_provider(sink_provider_t provider);

  /**
   * @brief Whether to advertise `SS_FF_SDS_MIC` and accept `SETUP streamid=mic` for a client.
   *
   * @param client_cert PEM certificate of the client.
   * @return True when `mic_passthrough` is on, the client holds the `mic` permission and a sink is available.
   */
  bool should_advertise(const std::string &client_cert);

  /**
   * @brief Outcome of handling one datagram (for tests and statistics).
   */
  enum class result_e {
    ping_bound,  ///< First valid ping; endpoint bound.
    ping_keepalive,  ///< Ping from the bound endpoint.
    ping_rejected,  ///< Ping from a different endpoint or address.
    accepted,  ///< Authenticated frame queued.
    dropped_inactive,  ///< Session stopped or permission revoked.
    dropped_unbound,  ///< Data before the ping binding.
    dropped_wrong_source,  ///< Data from an endpoint other than the bound one.
    dropped_rate,  ///< Rate limit exceeded.
    dropped_malformed,  ///< Size/version/flags/reserved invalid.
    dropped_replay,  ///< Outside the replay window or duplicate.
    dropped_auth,  ///< GCM authentication failed.
    dropped_late,  ///< Authenticated but too late for playout.
  };

  /**
   * @brief Session parameters.
   */
  struct session_config_t {
    crypto::aes_t key;  ///< Session rikey.
    std::string ping_payload;  ///< 16-character ping payload from SETUP.
    boost::asio::ip::address expected_address;  ///< RTSP client address; pings from elsewhere are rejected.
    std::string client_cert;  ///< Client certificate for permission re-checks.
    std::function<bool()> stream_running;  ///< Optional; packets are dropped once it returns false (stream stopping).
    bool start_playout_thread = true;  ///< Tests drive `tick()` manually when false.
  };

  /**
   * @brief Per-stream microphone state: binding, replay window, rate limit, jitter buffer, decoder and sink.
   */
  class session_t {
  public:
    /**
     * @brief Build a session; call `start()` before use.
     *
     * @param config Parameters.
     * @param sink Virtual microphone sink.
     * @param decoder Opus decoder.
     */
    session_t(session_config_t config, std::unique_ptr<sink_t> sink, std::unique_ptr<decoder_t> decoder);

    /**
     * @brief Calls `shutdown()`.
     */
    ~session_t();

    session_t(const session_t &) = delete;
    session_t &operator=(const session_t &) = delete;

    /**
     * @brief Start the sink and the playout thread.
     *
     * @return 0 on success.
     */
    int start();

    /**
     * @brief Stop accepting packets, discard queued audio and synchronously stop sink writes.
     */
    void deactivate();

    /**
     * @brief Stop playout and destroy the sink. Idempotent.
     */
    void shutdown();

    /**
     * @brief Handle one datagram received on the microphone port.
     *
     * @param datagram Datagram bytes.
     * @param from UDP source endpoint.
     * @param now Receive time.
     * @return Outcome.
     */
    result_e handle_datagram(std::span<const std::uint8_t> datagram, const boost::asio::ip::udp::endpoint &from, std::chrono::steady_clock::time_point now);

    /**
     * @brief Constant-time comparison of a ping payload with this session's.
     *
     * @param payload 16 bytes from a received ping.
     * @return True on match.
     */
    bool ping_matches(std::span<const std::uint8_t> payload) const;

    /**
     * @brief Bound endpoint, if any.
     *
     * @return Endpoint.
     */
    std::optional<boost::asio::ip::udp::endpoint> bound_endpoint() const;

    /**
     * @brief Run one 20 ms playout step (called by the playout thread or tests).
     */
    void tick();

    /**
     * @brief Re-check the global switch and the client's permission.
     */
    void refresh_permission();

    /**
     * @brief Whether packets are accepted.
     *
     * @return True while active.
     */
    bool active() const;

    /**
     * @brief Number of datagrams with a given outcome.
     *
     * @param result Outcome.
     * @return Count.
     */
    std::uint64_t count(result_e result) const;

  private:
    void playout_loop(std::stop_token stop);

    session_config_t _config;  ///< Session parameters.
    std::unique_ptr<sink_t> _sink;  ///< Virtual microphone output.
    std::unique_ptr<decoder_t> _decoder;  ///< Opus decoder.
    packet_cipher_t _cipher;  ///< Packet decryption.

    mutable std::mutex _mutex;  ///< Guards binding, replay window, rate limiter and jitter buffer.
    std::optional<boost::asio::ip::udp::endpoint> _bound;  ///< UDP endpoint bound by the first valid ping.
    replay_window_t _replay;  ///< Anti-replay window.
    rate_limiter_t _rate;  ///< Packet rate limiter.
    jitter_buffer_t _jitter;  ///< Reordering jitter buffer.

    std::mutex _playout_mutex;  ///< Serializes decode/sink writes with deactivation; acquired before _mutex.

    std::atomic_bool _active {false};  ///< Whether packets are accepted.
    std::atomic_bool _sink_started {false};  ///< Whether the sink needs stopping.
    std::mutex _shutdown_mutex;  ///< Serializes shutdown().
    std::jthread _playout;  ///< 20 ms playout thread.
    std::array<std::atomic_uint64_t, 12> _counts {};  ///< Datagram outcome counters indexed by result_e.
  };

  /**
   * @brief Owns the microphone UDP socket and routes datagrams to sessions.
   */
  class receiver_t {
  public:
    /**
     * @brief Create a receiver with optional lifecycle synchronization probes.
     *
     * @param before_receive_loop Called on the receive thread before its loop starts.
     * @param after_detach Called after the last session transfers socket ownership to removal.
     */
    explicit receiver_t(std::function<void()> before_receive_loop = {}, std::function<void()> after_detach = {});

    /**
     * @brief Removes all sessions and closes the socket.
     */
    ~receiver_t();

    receiver_t(const receiver_t &) = delete;
    receiver_t &operator=(const receiver_t &) = delete;

    /**
     * @brief Register a session, opening the socket on first use.
     *
     * @param session Session to route to.
     * @param bind_endpoint Local endpoint to bind when the socket is not open yet.
     * @return 0 on success.
     */
    int add(const std::shared_ptr<session_t> &session, const boost::asio::ip::udp::endpoint &bind_endpoint);

    /**
     * @brief Unregister a session, closing the socket after the last one.
     *
     * @param session Session to remove.
     */
    void remove(const std::shared_ptr<session_t> &session);

    /**
     * @brief Bound local endpoint (tests use port 0 and query it).
     *
     * @return Endpoint, or nullopt when closed.
     */
    std::optional<boost::asio::ip::udp::endpoint> local_endpoint() const;

    /**
     * @brief Route one datagram (exposed for tests).
     *
     * @param datagram Datagram bytes.
     * @param from Source endpoint.
     * @return Outcome, or nullopt when no session matched.
     */
    std::optional<result_e> route(std::span<const std::uint8_t> datagram, const boost::asio::ip::udp::endpoint &from);

  private:
    /**
     * @brief Receive using the stable resources retained by the matching removal operation.
     *
     * @param io Context captured before publishing the receive thread.
     * @param socket Socket captured before publishing the receive thread.
     */
    void receive_loop(boost::asio::io_context &io, boost::asio::ip::udp::socket &socket);

    mutable std::mutex _mutex;  ///< Guards the session list and socket ownership.
    std::vector<std::shared_ptr<session_t>> _sessions;  ///< Registered sessions.
    std::unique_ptr<boost::asio::io_context> _io;  ///< Asio context driving the socket.
    std::unique_ptr<boost::asio::ip::udp::socket> _socket;  ///< Microphone UDP socket (open while sessions exist).
    std::thread _thread;  ///< Thread running the Asio context.
    std::function<void()> _before_receive_loop;  ///< Optional receive-thread startup probe.
    std::function<void()> _after_detach;  ///< Optional last-session removal probe.
  };

  /**
   * @brief Start microphone passthrough for a stream session (production entry point).
   *
   * @param config Session parameters.
   * @return Running session, or nullptr when disabled, not permitted or the sink failed.
   */
  std::shared_ptr<session_t> start_session(session_config_t config);

  /**
   * @brief Stop and tear down a session started with `start_session()`. Idempotent.
   *
   * @param session Session (may be null).
   */
  void stop_session(const std::shared_ptr<session_t> &session);

  /**
   * @brief Move-only owner that stops its session (`stop_session()`) when reset or destroyed.
   */
  class session_handle_t {
  public:
    session_handle_t() = default;

    /**
     * @brief Take ownership of a running session.
     *
     * @param session Session from `start_session()` (may be null).
     */
    explicit session_handle_t(std::shared_ptr<session_t> session);

    /**
     * @brief Calls `reset()`.
     */
    ~session_handle_t();

    /**
     * @brief Move constructor.
     *
     * @param other Handle to take over.
     */
    session_handle_t(session_handle_t &&other) noexcept;

    /**
     * @brief Move assignment; stops the currently owned session first.
     *
     * @param other Handle to take over.
     * @return This handle.
     */
    session_handle_t &operator=(session_handle_t &&other) noexcept;

    session_handle_t(const session_handle_t &) = delete;
    session_handle_t &operator=(const session_handle_t &) = delete;

    /**
     * @brief Stop and release the session. Idempotent.
     */
    void reset();

    /**
     * @brief Owned session.
     *
     * @return Session or null.
     */
    session_t *get() const;

  private:
    std::shared_ptr<session_t> _session;  ///< Owned session.
  };

  /**
   * @brief Generate a fresh 16-character ping payload.
   *
   * @return Hex string from 8 random bytes.
   */
  std::string generate_ping_payload();
}  // namespace sds::mic
