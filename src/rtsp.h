/**
 * @file src/rtsp.h
 * @brief Declarations for RTSP streaming.
 */
#pragma once

// standard includes
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string_view>

// local includes
#include "crypto.h"
#include "thread_safe.h"

namespace stream {
  struct session_t;
}  // namespace stream

namespace rtsp_stream {
  constexpr auto RTSP_SETUP_PORT = 21;  ///< GameStream base-port offset used for the RTSP setup listener.

#pragma pack(push, 1)

  /**
   * @brief Encrypted RTSP message header used by GameStream.
   */
  struct encrypted_rtsp_header_t {
    // We set the MSB in encrypted RTSP messages to allow format-agnostic
    // parsing code to be able to tell encrypted from plaintext messages.
    static constexpr std::uint32_t ENCRYPTED_MESSAGE_TYPE_BIT = 0x80000000;  ///< Protocol or platform constant for encrypted message type bit.

    /**
     * @brief Return a pointer to the protocol payload following the packet header.
     *
     * @return Parsed or serialized payload data.
     */
    uint8_t *payload() {
      return (uint8_t *) (this + 1);
    }

    /**
     * @brief Decode the RTSP interleaved-frame payload length.
     *
     * @return Payload byte count with the encrypted-message flag masked out.
     */
    std::uint32_t payload_length() const {
      return util::endian::big<std::uint32_t>(typeAndLength) & ~ENCRYPTED_MESSAGE_TYPE_BIT;
    }

    /**
     * @brief Inspect the encrypted-message flag without modifying the wire header.
     *
     * @return True when the encrypted-message flag is set.
     */
    bool is_encrypted() const {
      return !!(util::endian::big<std::uint32_t>(typeAndLength) & ENCRYPTED_MESSAGE_TYPE_BIT);
    }

    // This field is the length of the payload + ENCRYPTED_MESSAGE_TYPE_BIT in big-endian
    std::uint32_t typeAndLength;  ///< Type and length.

    // This field is the number used to initialize the bottom 4 bytes of the AES IV in big-endian
    std::uint32_t sequenceNumber;  ///< Sequence number.

    // This field is the AES GCM authentication tag
    std::array<std::uint8_t, 16> tag;  ///< Authentication tag appended to the encrypted payload.
  };

#pragma pack(pop)

  static_assert(sizeof(encrypted_rtsp_header_t) == 24);
  static_assert(offsetof(encrypted_rtsp_header_t, tag) == 8);

  /**
   * @brief RTSP launch session state shared with stream setup.
   */
  struct launch_session_t {
    uint32_t id;  ///< RTSP launch-session identifier assigned before stream startup.

    crypto::aes_t gcm_key;  ///< AES-GCM key negotiated for encrypted RTSP messages.
    crypto::aes_t iv;  ///< Initial RTSP AES-GCM IV supplied by the client.

    std::string av_ping_payload;  ///< AV ping payload.
    uint32_t control_connect_data;  ///< Client-provided token used when connecting the control channel.

    bool host_audio;  ///< Whether host audio should be played locally.
    std::string unique_id;  ///< Moonlight client unique identifier for this launch request.
    int width;  ///< Frame or display width in pixels.
    int height;  ///< Frame or display height in pixels.
    int fps;  ///< Requested video frame rate.
    int gcmap;  ///< Game controller mapping requested by the client.
    int appid;  ///< Application ID requested for launch or resume.
    int surround_info;  ///< Encoded GameStream surround-sound capability flags.
    std::string surround_params;  ///< Client-provided surround-sound layout parameters.
    bool continuous_audio;  ///< Whether audio packets continue during silence.
    bool enable_hdr;  ///< Whether HDR streaming is requested.
    bool enable_sops;  ///< Whether sequence output protection is requested.
    std::string client_name;  ///< Friendly client name from initial pairing.

    std::optional<crypto::cipher::gcm_t> rtsp_cipher;  ///< AES-GCM cipher used once encrypted RTSP is negotiated.
    std::string rtsp_url_scheme;  ///< URL scheme selected by the RTSP SETUP flow.
    uint32_t rtsp_iv_counter;  ///< Counter value mixed into encrypted RTSP IVs.
    std::string client_cert;  ///< PEM certificate for the paired Moonlight client.

    // secure-desktop-stream microphone passthrough (set by RTSP SETUP streamid=mic)
    bool mic_requested = false;  ///< Whether the client completed SETUP for the microphone stream.
    std::string mic_ping_payload;  ///< Ping payload that binds the client's microphone UDP endpoint.

    // Packed YCoCg-R P010 4:4:4 mode negotiated on /launch or /resume (0 = off, 1 = Layout A1)
    int packed_ycocgr_mode = 0;  ///< Packed YCoCg-R mode requested for this launch session.

    // Adaptive dirty-tile lossless refinement negotiated on /launch or /resume
    bool tile_refinement = false;  ///< Adaptive dirty-tile refinement enabled for this launch session.

    // Dedicated bit-exact SDLL v1 lossless video mode negotiated on /launch or /resume
    bool lossless_mode = false;  ///< True bit-exact SDLL v1 lossless video mode enabled for this launch session.
    std::uint8_t lossless_hash_algo = 1;  ///< Negotiated hash algorithm (0=none, 1=crc32c, 2=blake3).
    std::string lossless_encoder_pref = "auto";  ///< Negotiated host lossless encoder ("auto", "gpu", "cpu").
  };

  /**
   * @brief Queue a launch session until the RTSP client connects.
   *
   * @param launch_session Session state prepared by the GameStream launch handler.
   */
  void launch_session_raise(std::shared_ptr<launch_session_t> launch_session);

  /**
   * @brief Clear state for the specified launch session.
   * @param launch_session_id The ID of the session to clear.
   */
  void launch_session_clear(uint32_t launch_session_id);

  /**
   * @brief Get the number of active sessions.
   * @return Count of active sessions.
   */
  int session_count();

  /**
   * @brief Terminates all running streaming sessions.
   */
  void terminate_sessions();
  /**
   * @brief Terminate active sessions associated with a client certificate.
   *
   * @param cert Certificate data or object used by the operation.
   */
  void terminate_sessions_by_cert(std::string_view cert);

  /**
   * @brief Check whether a streaming session of this client certificate is running.
   *
   * Walks the session slots under their lock and never joins or clears sessions.
   *
   * @param cert_pem Canonical PEM certificate of the client.
   * @return `true` when a session for the certificate is in the RUNNING state.
   */
  bool has_running_session(std::string_view cert_pem);

  /**
   * @brief Check whether a running session of this client certificate has tile refinement enabled.
   *
   * @param cert_pem Canonical PEM certificate of the client.
   * @return `true` when an active RUNNING session for `cert_pem` uses adaptive tile refinement.
   */
  bool has_tile_refinement_session(std::string_view cert_pem);

  /**
   * @brief Check whether any running session uses adaptive tile refinement.
   */
  bool any_tile_refinement_session();

  /**
   * @brief Check whether a running session of this client certificate uses SDLL lossless mode.
   */
  bool has_lossless_session(std::string_view cert_pem);

  /**
   * @brief Check whether any running session uses SDLL lossless mode.
   */
  bool any_lossless_session();

  /**
   * @brief Read negotiated lossless hash algo & encoder preference for `cert_pem`.
   */
  bool get_lossless_session_config(std::string_view cert_pem, std::uint8_t &hash_algo, std::string &encoder_pref);

  /**
   * @brief Observer notified when a streaming session starts running or begins to stop.
   *
   * Called from session and RTSP threads, possibly while the session slots are locked: it must not
   * block and must not call back into rtsp_stream synchronously.
   */
  using session_observer_t = std::function<void(std::string_view cert_pem, bool running)>;

  /**
   * @brief Install (or clear with an empty function) the session observer.
   *
   * @param observer Observer.
   */
  void set_session_observer(session_observer_t observer);

  /**
   * @brief Notify the observer about a session state change (called by stream::session).
   *
   * @param cert_pem Client certificate of the session.
   * @param running `true` when the session started running, `false` when it began stopping.
   */
  void notify_session_state(std::string_view cert_pem, bool running);

#ifdef SUNSHINE_TESTS
  namespace test_support {
    /**
     * @brief Insert a session into the RTSP session slots without starting it.
     *
     * @param session Session to insert.
     */
    void insert_session(const std::shared_ptr<stream::session_t> &session);

    /**
     * @brief Remove a session from the RTSP session slots without stopping or joining it.
     *
     * @param session Session to remove.
     */
    void remove_session(const std::shared_ptr<stream::session_t> &session);
  }  // namespace test_support
#endif

  /**
   * @brief Runs the RTSP server loop.
   */
  void start();
}  // namespace rtsp_stream
