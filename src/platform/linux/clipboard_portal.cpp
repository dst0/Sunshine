/**
 * @file src/platform/linux/clipboard_portal.cpp
 * @brief xdg-desktop-portal Clipboard backend (GNOME Wayland) on the shared RemoteDesktop session.
 *
 * The session comes from portalgrab.cpp (portal::acquire_shared_session), which requests
 * clipboard access before starting it. This backend
 * - listens to SelectionOwnerChanged (changes with session_is_owner = true are ours and are
 *   ignored) and SelectionTransfer on a dedicated thread running a GMainLoop on its own
 *   GMainContext (the subscriptions are made on that context),
 * - reads with SelectionRead, which returns a pipe that is drained without blocking, with a
 *   byte cap and the caller's deadline (one read at a time: mutter rejects parallel reads),
 * - offers content with SetSelection and answers each SelectionTransfer on a worker thread
 *   with SelectionWrite + SelectionWriteDone,
 * - releases ownership on stop() with SetSelection without mime types.
 */
// standard includes
#include <array>
#include <atomic>
#include <condition_variable>
#include <deque>
#include <future>
#include <mutex>
#include <thread>

// lib includes
#include <gio/gio.h>
#include <gio/gunixfdlist.h>
#include <unistd.h>

// local includes
#include "clipboard_linux.h"
#include "portal_session.h"
#include "src/logging.h"
#include "src/sds/clipboard_backend_util.h"

using namespace std::literals;

namespace sds::clipboard::xdp {
  namespace {
    using steady = std::chrono::steady_clock;

    constexpr const char *PORTAL_NAME = "org.freedesktop.portal.Desktop";
    constexpr const char *PORTAL_PATH = "/org/freedesktop/portal/desktop";
    constexpr const char *CLIPBOARD_IFACE = "org.freedesktop.portal.Clipboard";
    constexpr const char *SESSION_IFACE = "org.freedesktop.portal.Session";

    constexpr auto call_timeout = 5s;  ///< SetSelection / SelectionWrite / SelectionWriteDone.
    constexpr auto transfer_timeout = 10s;  ///< Writing one representation to a requesting application.
    constexpr auto own_change_grace = 2s;  ///< How long to wait for the portal to confirm our SetSelection.

    constexpr std::string_view mime_text_utf8 = "text/plain;charset=utf-8";
    constexpr std::string_view mime_utf8_string = "UTF8_STRING";
    constexpr std::string_view mime_text_plain = "text/plain";
    constexpr std::string_view mime_string = "STRING";
    constexpr std::string_view mime_png = "image/png";

    /**
     * @brief Content we offer, with the lossy Latin-1 form precomputed for STRING.
     */
    struct owned_t {
      item_t item;  ///< Offered content.
      std::string latin1;  ///< item.text in Latin-1.
    };

    /**
     * @brief Bytes to serve for a requested MIME type, or nullopt when it is not offered.
     */
    std::optional<std::span<const std::uint8_t>> bytes_for(const owned_t &owned, std::string_view mime) {
      auto bytes = [](const std::string &s) {
        return std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(s.data()), s.size());
      };
      if (owned.item.text) {
        if (util::mime_equal(mime, mime_text_utf8) || util::mime_equal(mime, mime_utf8_string) || util::mime_equal(mime, mime_text_plain)) {
          return bytes(*owned.item.text);
        }
        if (util::mime_equal(mime, mime_string)) {
          return bytes(owned.latin1);
        }
      }
      if (owned.item.png && util::mime_equal(mime, mime_png)) {
        return std::span<const std::uint8_t>(*owned.item.png);
      }
      return std::nullopt;
    }

    /**
     * @brief The portal clipboard backend.
     */
    class portal_backend_t final: public backend_t {
    public:
      ~portal_backend_t() override {
        stop();
      }

      int start(std::function<void()> on_change) override {
        std::lock_guard lifecycle(lifecycle_mutex_);
        stop_locked();

        auto session = portal::acquire_shared_session(true);
        if (!session) {
          BOOST_LOG(warning) << "[clipboard/portal] No portal RemoteDesktop session"sv;
          return -1;
        }
        if (!session->clipboard_enabled()) {
          BOOST_LOG(warning) << "[clipboard/portal] The portal session has no clipboard access"sv;
          return -1;
        }

        {
          std::lock_guard lock(mutex_);
          session_ = session;
          handle_ = session->handle();
          owned_.reset();
          owner_ = false;
          pending_own_ = false;
          offered_.clear();
          offered_known_ = false;
          closed_ = false;
          stopping_ = false;
          transfers_.clear();
          running_ = true;
        }
        notifier_.start(std::move(on_change));

        context_ = g_main_context_new();
        loop_ = g_main_loop_new(context_, FALSE);
        std::promise<void> ready;
        auto subscribed = ready.get_future();
        loop_thread_ = std::thread(&portal_backend_t::loop_main, this, session->connection(), std::move(ready));
        subscribed.wait();
        transfer_thread_ = std::thread(&portal_backend_t::transfer_main, this);
        BOOST_LOG(info) << "[clipboard/portal] Clipboard attached to portal session "sv << handle_;
        return 0;
      }

      void stop() override {
        std::lock_guard lifecycle(lifecycle_mutex_);
        stop_locked();
      }

      std::optional<item_t> read(const limits_t &limits, std::chrono::milliseconds timeout) override {
        const auto deadline = steady::now() + timeout;
        std::shared_ptr<portal::session_t> session;
        std::vector<std::string> offered;
        bool known;
        {
          std::lock_guard lock(mutex_);
          if (!running_ || closed_ || !session_) {
            return std::nullopt;
          }
          if (owner_ && owned_) {
            // The portal refuses to read our own selection; answer from memory
            item_t item = owned_->item;
            util::apply_limits(item, limits);
            return item.empty() ? std::nullopt : std::optional {std::move(item)};
          }
          if (offered_known_ && offered_.empty()) {
            return std::nullopt;
          }
          session = session_;
          offered = offered_;
          known = offered_known_;
        }

        std::unique_lock serial(read_mutex_, std::defer_lock);
        if (!serial.try_lock_until(deadline)) {
          return std::nullopt;
        }

        item_t out;
        // Until the first SelectionOwnerChanged arrives, the offered types are unknown: try the
        // canonical ones; an owner that lacks a type yields an empty transfer.
        const auto text_mime = known ? util::pick_mime(offered, {mime_text_utf8, mime_utf8_string, mime_text_plain, mime_string}) : std::optional {std::string {mime_text_utf8}};
        if (text_mime) {
          const bool latin1 = util::mime_equal(*text_mime, mime_string);
          const auto result = selection_read(*session, *text_mime, latin1 ? limits.text_max : limits.text_max + 1, deadline);
          if (result.status == fdio::status_e::ok && !result.data.empty()) {
            const std::string_view raw(reinterpret_cast<const char *>(result.data.data()), result.data.size());
            auto text = util::sanitize_text(latin1 ? util::latin1_to_utf8(raw) : std::string {raw});
            if (text && text->size() <= limits.text_max) {
              out.text = std::move(text);
            }
          }
        }
        const auto image_mime = known ? util::pick_mime(offered, {mime_png}) : std::optional {std::string {mime_png}};
        if (image_mime && steady::now() < deadline) {
          auto result = selection_read(*session, *image_mime, limits.image_max, deadline);
          if (result.status == fdio::status_e::ok && util::has_png_signature(result.data)) {
            out.png = std::move(result.data);
          }
        }
        return out.empty() ? std::nullopt : std::optional {std::move(out)};
      }

      int write(const item_t &item) override {
        auto owned = std::make_shared<owned_t>();
        owned->item = item;
        if (item.text) {
          owned->latin1 = util::utf8_to_latin1_lossy(*item.text);
        }
        std::vector<std::string> mimes;
        if (item.text) {
          mimes.insert(mimes.end(), {std::string {mime_text_utf8}, std::string {mime_utf8_string}, std::string {mime_text_plain}, std::string {mime_string}});
        }
        if (item.png) {
          mimes.emplace_back(mime_png);
        }

        std::shared_ptr<portal::session_t> session;
        {
          std::lock_guard lock(mutex_);
          if (!running_ || closed_ || !session_) {
            return -1;
          }
          session = session_;
          // Serve transfers that arrive before SetSelection returns
          owned_ = mimes.empty() ? nullptr : std::shared_ptr<const owned_t>(std::move(owned));
          owner_ = !mimes.empty();
          pending_own_ = owner_;
          pending_since_ = steady::now();
        }

        if (!set_selection(*session, mimes)) {
          std::lock_guard lock(mutex_);
          owned_.reset();
          owner_ = false;
          pending_own_ = false;
          return -1;
        }
        return 0;
      }

      [[nodiscard]] std::string_view name() const override {
        return "xdg-portal"sv;
      }

    private:
      /**
       * @brief Stop threads and release ownership; caller holds lifecycle_mutex_.
       */
      void stop_locked() {
        std::shared_ptr<portal::session_t> session;
        bool owner;
        bool closed;
        {
          std::lock_guard lock(mutex_);
          if (!running_) {
            return;
          }
          running_ = false;
          stopping_ = true;
          owner = owner_;
          closed = closed_;
          owner_ = false;
          owned_.reset();
          session = session_;
        }
        transfer_cv_.notify_all();
        if (transfer_thread_.joinable()) {
          transfer_thread_.join();
        }
        if (owner && !closed && session) {
          set_selection(*session, {});
        }

        g_main_context_invoke(
          context_,
          [](gpointer loop) {
            g_main_loop_quit(static_cast<GMainLoop *>(loop));
            return G_SOURCE_REMOVE;
          },
          loop_
        );
        if (loop_thread_.joinable()) {
          loop_thread_.join();
        }
        g_main_loop_unref(loop_);
        loop_ = nullptr;
        g_main_context_unref(context_);
        context_ = nullptr;
        notifier_.stop();

        std::lock_guard lock(mutex_);
        session_.reset();  // the last lease closes the portal session
        handle_.clear();
      }

      /**
       * @brief Signal thread: subscribe on our context and run its main loop.
       */
      void loop_main(GDBusConnection *conn, std::promise<void> ready) {
        g_main_context_push_thread_default(context_);
        const std::array<guint, 3> subscriptions {
          g_dbus_connection_signal_subscribe(conn, PORTAL_NAME, CLIPBOARD_IFACE, "SelectionOwnerChanged", PORTAL_PATH, nullptr, G_DBUS_SIGNAL_FLAGS_NONE, on_owner_changed, this, nullptr),
          g_dbus_connection_signal_subscribe(conn, PORTAL_NAME, CLIPBOARD_IFACE, "SelectionTransfer", PORTAL_PATH, nullptr, G_DBUS_SIGNAL_FLAGS_NONE, on_transfer, this, nullptr),
          g_dbus_connection_signal_subscribe(conn, PORTAL_NAME, SESSION_IFACE, "Closed", nullptr, nullptr, G_DBUS_SIGNAL_FLAGS_NONE, on_closed, this, nullptr),
        };
        // GDBus resolves the portal's unique name for these subscriptions with a GetNameOwner call
        // and drops matching signals until the reply arrives. Replies come back in order, so one
        // round trip here guarantees no signal sent after start() returns is lost.
        g_autoptr(GVariant) owner = g_dbus_connection_call_sync(conn, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "GetNameOwner", g_variant_new("(s)", PORTAL_NAME), nullptr, G_DBUS_CALL_FLAGS_NONE, static_cast<gint>(std::chrono::milliseconds(call_timeout).count()), nullptr, nullptr);
        ready.set_value();
        g_main_loop_run(loop_);
        for (const auto id : subscriptions) {
          g_dbus_connection_signal_unsubscribe(conn, id);
        }
        // Signals queued for this context are never dispatched: nobody iterates it any more
        g_main_context_pop_thread_default(context_);
      }

      /**
       * @brief Whether a signal belongs to our session.
       */
      bool is_our_session(const gchar *path) {
        std::lock_guard lock(mutex_);
        return running_ && handle_ == path;
      }

      /**
       * @brief SelectionOwnerChanged(o session_handle, a{sv} options).
       */
      static void on_owner_changed(GDBusConnection *, const gchar *, const gchar *, const gchar *, const gchar *, GVariant *parameters, gpointer user_data) {
        auto *self = static_cast<portal_backend_t *>(user_data);
        const gchar *path = nullptr;
        g_autoptr(GVariant) options = nullptr;
        g_variant_get(parameters, "(&o@a{sv})", &path, &options);
        if (!self->is_our_session(path)) {
          return;
        }
        gboolean is_owner = FALSE;
        const bool has_owner = g_variant_lookup(options, "session_is_owner", "b", &is_owner);
        std::vector<std::string> mimes;
        g_autofree const gchar **types = nullptr;
        if (g_variant_lookup(options, "mime_types", "^a&s", &types)) {
          for (auto **type = types; type && *type; ++type) {
            mimes.emplace_back(*type);
          }
        }
        self->owner_changed(has_owner && is_owner, std::move(mimes));
      }

      /**
       * @brief Apply a selection owner change.
       *
       * @param ours True when the portal reports our session as the owner.
       * @param mimes Types offered by the new owner.
       */
      void owner_changed(bool ours, std::vector<std::string> mimes) {
        {
          std::lock_guard lock(mutex_);
          if (ours) {
            pending_own_ = false;
            return;
          }
          // Signals are delivered in order, so a foreign change seen before the portal confirmed
          // our SetSelection happened before it and is superseded by our content.
          if (pending_own_ && steady::now() - pending_since_ < own_change_grace) {
            return;
          }
          pending_own_ = false;
          owner_ = false;
          owned_.reset();
          offered_ = std::move(mimes);
          offered_known_ = true;
        }
        notifier_.notify();
      }

      /**
       * @brief SelectionTransfer(o session_handle, s mime_type, u serial).
       */
      static void on_transfer(GDBusConnection *, const gchar *, const gchar *, const gchar *, const gchar *, GVariant *parameters, gpointer user_data) {
        auto *self = static_cast<portal_backend_t *>(user_data);
        const gchar *path = nullptr;
        const gchar *mime = nullptr;
        guint32 serial = 0;
        g_variant_get(parameters, "(&o&su)", &path, &mime, &serial);
        if (!self->is_our_session(path)) {
          return;
        }
        {
          std::lock_guard lock(self->mutex_);
          self->transfers_.emplace_back(mime, serial);
        }
        self->transfer_cv_.notify_one();
      }

      /**
       * @brief org.freedesktop.portal.Session.Closed on any session; ours stops the backend's I/O.
       */
      static void on_closed(GDBusConnection *, const gchar *, const gchar *object_path, const gchar *, const gchar *, GVariant *, gpointer user_data) {
        auto *self = static_cast<portal_backend_t *>(user_data);
        if (!self->is_our_session(object_path)) {
          return;
        }
        BOOST_LOG(warning) << "[clipboard/portal] The portal closed the session"sv;
        std::lock_guard lock(self->mutex_);
        self->closed_ = true;
        self->owner_ = false;
        self->owned_.reset();
      }

      /**
       * @brief Worker answering SelectionTransfer requests one at a time.
       */
      void transfer_main() {
        std::unique_lock lock(mutex_);
        while (true) {
          transfer_cv_.wait(lock, [this]() {
            return stopping_ || !transfers_.empty();
          });
          if (transfers_.empty()) {
            return;
          }
          auto [mime, serial] = std::move(transfers_.front());
          transfers_.pop_front();
          const auto owned = owner_ ? owned_ : nullptr;
          const auto session = session_;
          const bool stopping = stopping_ || closed_;
          lock.unlock();
          if (session) {
            serve_transfer(*session, stopping ? nullptr : owned.get(), mime, serial);
          }
          lock.lock();
        }
      }

      /**
       * @brief Answer one SelectionTransfer.
       */
      static void serve_transfer(portal::session_t &session, const owned_t *owned, const std::string &mime, guint32 serial) {
        const auto data = owned ? bytes_for(*owned, mime) : std::nullopt;
        if (!data) {
          selection_write_done(session, serial, false);
          return;
        }
        const int fd = selection_write(session, serial);
        if (fd < 0) {
          selection_write_done(session, serial, false);
          return;
        }
        const auto status = fdio::write_all(fd, *data, steady::now() + transfer_timeout);
        close(fd);
        if (status != fdio::status_e::ok) {
          BOOST_LOG(debug) << "[clipboard/portal] Transfer of "sv << mime << " did not complete"sv;
        }
        selection_write_done(session, serial, status == fdio::status_e::ok);
      }

      /**
       * @brief Clipboard.SetSelection with the given types (none releases ownership).
       *
       * @return True on success.
       */
      static bool set_selection(portal::session_t &session, const std::vector<std::string> &mimes) {
        GVariantBuilder options;
        g_variant_builder_init(&options, G_VARIANT_TYPE_VARDICT);
        if (!mimes.empty()) {
          GVariantBuilder types;
          g_variant_builder_init(&types, G_VARIANT_TYPE_STRING_ARRAY);
          for (const auto &mime : mimes) {
            g_variant_builder_add(&types, "s", mime.c_str());
          }
          g_variant_builder_add(&options, "{sv}", "mime_types", g_variant_builder_end(&types));
        }
        g_autoptr(GError) err = nullptr;
        g_autoptr(GVariant) reply = g_dbus_connection_call_sync(session.connection(), PORTAL_NAME, PORTAL_PATH, CLIPBOARD_IFACE, "SetSelection", g_variant_new("(oa{sv})", session.handle().c_str(), &options), nullptr, G_DBUS_CALL_FLAGS_NONE, static_cast<gint>(std::chrono::milliseconds(call_timeout).count()), nullptr, &err);
        if (!reply) {
          BOOST_LOG(warning) << "[clipboard/portal] SetSelection failed: "sv << (err ? err->message : "unknown error");
          return false;
        }
        return true;
      }

      /**
       * @brief Clipboard.SelectionWrite: get the pipe for one transfer.
       *
       * @return Writable file descriptor owned by the caller, or -1.
       */
      static int selection_write(portal::session_t &session, guint32 serial) {
        g_autoptr(GError) err = nullptr;
        g_autoptr(GUnixFDList) fds = nullptr;
        g_autoptr(GVariant) reply = g_dbus_connection_call_with_unix_fd_list_sync(session.connection(), PORTAL_NAME, PORTAL_PATH, CLIPBOARD_IFACE, "SelectionWrite", g_variant_new("(ou)", session.handle().c_str(), serial), G_VARIANT_TYPE("(h)"), G_DBUS_CALL_FLAGS_NONE, static_cast<gint>(std::chrono::milliseconds(call_timeout).count()), nullptr, &fds, nullptr, &err);
        if (!reply || !fds) {
          BOOST_LOG(warning) << "[clipboard/portal] SelectionWrite failed: "sv << (err ? err->message : "no file descriptor");
          return -1;
        }
        gint32 index = -1;
        g_variant_get(reply, "(h)", &index);
        return g_unix_fd_list_get(fds, index, nullptr);
      }

      /**
       * @brief Clipboard.SelectionWriteDone.
       */
      static void selection_write_done(portal::session_t &session, guint32 serial, bool success) {
        g_autoptr(GError) err = nullptr;
        g_autoptr(GVariant) reply = g_dbus_connection_call_sync(session.connection(), PORTAL_NAME, PORTAL_PATH, CLIPBOARD_IFACE, "SelectionWriteDone", g_variant_new("(oub)", session.handle().c_str(), serial, success), nullptr, G_DBUS_CALL_FLAGS_NONE, static_cast<gint>(std::chrono::milliseconds(call_timeout).count()), nullptr, &err);
        if (!reply) {
          BOOST_LOG(debug) << "[clipboard/portal] SelectionWriteDone failed: "sv << (err ? err->message : "unknown error");
        }
      }

      /**
       * @brief Clipboard.SelectionRead and drain the returned pipe.
       */
      static fdio::read_result_t selection_read(portal::session_t &session, const std::string &mime, std::size_t cap, steady::time_point deadline) {
        const auto remaining = std::chrono::ceil<std::chrono::milliseconds>(deadline - steady::now()).count();
        if (remaining <= 0) {
          return {fdio::status_e::timeout, {}};
        }
        g_autoptr(GError) err = nullptr;
        g_autoptr(GUnixFDList) fds = nullptr;
        g_autoptr(GVariant) reply = g_dbus_connection_call_with_unix_fd_list_sync(session.connection(), PORTAL_NAME, PORTAL_PATH, CLIPBOARD_IFACE, "SelectionRead", g_variant_new("(os)", session.handle().c_str(), mime.c_str()), G_VARIANT_TYPE("(h)"), G_DBUS_CALL_FLAGS_NONE, static_cast<gint>(remaining), nullptr, &fds, nullptr, &err);
        if (!reply || !fds) {
          BOOST_LOG(debug) << "[clipboard/portal] SelectionRead("sv << mime << ") failed: "sv << (err ? err->message : "no file descriptor");
          return {fdio::status_e::error, {}};
        }
        gint32 index = -1;
        g_variant_get(reply, "(h)", &index);
        const int fd = g_unix_fd_list_get(fds, index, nullptr);
        if (fd < 0) {
          return {fdio::status_e::error, {}};
        }
        auto result = fdio::read_capped(fd, cap, deadline);
        close(fd);
        if (result.status == fdio::status_e::too_large) {
          BOOST_LOG(debug) << "[clipboard/portal] Dropped "sv << mime << ": larger than "sv << cap << " bytes"sv;
        }
        return result;
      }

      std::mutex lifecycle_mutex_;  ///< Serializes start() and stop().
      std::mutex mutex_;  ///< Guards the state below.
      std::shared_ptr<portal::session_t> session_;
      std::string handle_;
      std::shared_ptr<const owned_t> owned_;
      bool owner_ = false;
      bool pending_own_ = false;
      steady::time_point pending_since_;
      std::vector<std::string> offered_;
      bool offered_known_ = false;
      bool closed_ = false;
      bool running_ = false;
      bool stopping_ = false;
      std::deque<std::pair<std::string, guint32>> transfers_;
      std::condition_variable transfer_cv_;

      std::timed_mutex read_mutex_;  ///< One SelectionRead at a time.
      GMainContext *context_ = nullptr;
      GMainLoop *loop_ = nullptr;
      std::thread loop_thread_;
      std::thread transfer_thread_;
      util::change_notifier_t notifier_;
    };
  }  // namespace

  std::unique_ptr<backend_t> make_backend() {
    return std::make_unique<portal_backend_t>();
  }
}  // namespace sds::clipboard::xdp
