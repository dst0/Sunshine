/**
 * @file src/platform/linux/portal_session.h
 * @brief Process-wide xdg-desktop-portal RemoteDesktop session shared by capture and clipboard.
 *
 * When the shared clipboard feature is enabled, portal capture displays and the portal
 * clipboard backend lease one RemoteDesktop+ScreenCast session instead of each display owning
 * its own. The session requests clipboard access (Clipboard.RequestClipboard) before Start,
 * stays open while any lease exists (so it outlives display re-initialisation while the
 * clipboard backend is running) and is closed when the last lease is released. Enumeration
 * probes never create it; they reuse it when it is live.
 *
 * With the feature disabled, portal capture keeps its previous behaviour: every display and
 * every enumeration probe owns a private session.
 */
#pragma once

#ifdef SUNSHINE_BUILD_PORTAL

  // standard includes
  #include <memory>
  #include <string>

typedef struct _GDBusConnection GDBusConnection;

namespace portal {
  /**
   * @brief Choose whether RemoteDesktop sessions created from now on request clipboard access.
   *
   * Enabling it also switches portal capture to the shared session. Call it before capture
   * initialisation so that a first-time consent dialog includes the clipboard switch.
   *
   * @param requested True when the shared clipboard feature is enabled.
   */
  void set_clipboard_requested(bool requested);

  /**
   * @brief Whether RemoteDesktop sessions request clipboard access.
   *
   * @return True after set_clipboard_requested(true).
   */
  bool clipboard_requested();

  /**
   * @brief Record whether platform initialisation selected portal capture.
   *
   * @param active True when portal capture is the active capture source.
   */
  void set_capture_active(bool active);

  /**
   * @brief Whether portal capture is the active capture source.
   *
   * @return Value last passed to set_capture_active().
   */
  bool capture_active();

  /**
   * @brief A lease on the shared RemoteDesktop session.
   *
   * The session stays open while at least one lease exists. All methods are thread-safe.
   */
  class session_t {
  public:
    virtual ~session_t() = default;

    /**
     * @brief D-Bus connection that owns the session (portal calls must use it).
     *
     * @return Borrowed connection, valid while the lease exists.
     */
    [[nodiscard]] virtual GDBusConnection *connection() const = 0;

    /**
     * @brief Object path of the portal session.
     *
     * @return Session handle.
     */
    [[nodiscard]] virtual const std::string &handle() const = 0;

    /**
     * @brief Whether the portal granted clipboard access (Start result `clipboard_enabled`).
     *
     * @return True when the Clipboard interface may be used with this session.
     */
    [[nodiscard]] virtual bool clipboard_enabled() const = 0;

    /**
     * @brief Ask the portal whether the session is still open (one D-Bus round trip).
     *
     * @return True when the portal has closed the session.
     */
    [[nodiscard]] virtual bool is_closed() const = 0;

    /**
     * @brief Get a PipeWire remote for the session's streams.
     *
     * @return New file descriptor owned by the caller, or -1 on failure.
     */
    virtual int open_pipewire_remote() = 0;
  };

  /**
   * @brief Lease the shared session, creating and starting it if no open session exists.
   *
   * @param allow_start_timeout True to give up when Start does not answer within the D-Bus
   *        timeout (for example while a consent dialog is shown).
   * @return Lease, or nullptr when the session could not be created.
   */
  std::shared_ptr<session_t> acquire_shared_session(bool allow_start_timeout);

  /**
   * @brief Lease the shared session only if one is already open; never creates one.
   *
   * @return Lease, or nullptr when no open shared session exists.
   */
  std::shared_ptr<session_t> current_shared_session();
}  // namespace portal

#endif
