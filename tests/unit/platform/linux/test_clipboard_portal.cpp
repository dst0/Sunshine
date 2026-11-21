/**
 * @file tests/unit/platform/linux/test_clipboard_portal.cpp
 * @brief Tests for the shared portal session and the portal clipboard backend against a fake
 *        xdg-desktop-portal (RemoteDesktop, ScreenCast, Clipboard, Session) on a private D-Bus.
 */
#ifdef SUNSHINE_BUILD_PORTAL
  // test includes
  #include "../../../tests_common.h"

  // standard includes
  #include <algorithm>
  #include <array>
  #include <atomic>
  #include <chrono>
  #include <condition_variable>
  #include <csignal>
  #include <cstdio>
  #include <filesystem>
  #include <format>
  #include <fstream>
  #include <future>
  #include <map>
  #include <mutex>
  #include <optional>
  #include <set>
  #include <string>
  #include <thread>
  #include <vector>

  // lib includes
  #include <fcntl.h>
  #include <gio/gio.h>
  #include <gio/gunixfdlist.h>
  #include <poll.h>
  #include <pthread.h>
  #include <sys/wait.h>
  #include <unistd.h>

  // local includes
  #include "src/logging.h"
  #include "src/platform/linux/clipboard_linux.h"
  #include "src/platform/linux/misc.h"
  #include "src/platform/linux/portal_session.h"

namespace platf {
  std::vector<std::string> portal_display_names(bool allow_start_timeout);
}  // namespace platf

using namespace std::literals;
using sds::clipboard::item_t;
using sds::clipboard::limits_t;

namespace {
  using bytes_t = std::vector<std::uint8_t>;

  constexpr const char *PORTAL_NAME = "org.freedesktop.portal.Desktop";
  constexpr const char *PORTAL_PATH = "/org/freedesktop/portal/desktop";
  constexpr const char *CLIPBOARD_IFACE = "org.freedesktop.portal.Clipboard";
  constexpr limits_t big_limits {1024 * 1024, 16 * 1024 * 1024};

  /**
   * @brief Portal interfaces used by Sunshine.
   */
  constexpr const char *PORTAL_XML = R"(
<node>
  <interface name='org.freedesktop.portal.RemoteDesktop'>
    <method name='CreateSession'><arg type='a{sv}' direction='in'/><arg type='o' direction='out'/></method>
    <method name='SelectDevices'><arg type='o' direction='in'/><arg type='a{sv}' direction='in'/><arg type='o' direction='out'/></method>
    <method name='Start'><arg type='o' direction='in'/><arg type='s' direction='in'/><arg type='a{sv}' direction='in'/><arg type='o' direction='out'/></method>
  </interface>
  <interface name='org.freedesktop.portal.ScreenCast'>
    <method name='SelectSources'><arg type='o' direction='in'/><arg type='a{sv}' direction='in'/><arg type='o' direction='out'/></method>
    <method name='OpenPipeWireRemote'><arg type='o' direction='in'/><arg type='a{sv}' direction='in'/><arg type='h' direction='out'/></method>
  </interface>
  <interface name='org.freedesktop.portal.Clipboard'>
    <method name='RequestClipboard'><arg type='o' direction='in'/><arg type='a{sv}' direction='in'/></method>
    <method name='SetSelection'><arg type='o' direction='in'/><arg type='a{sv}' direction='in'/></method>
    <method name='SelectionWrite'><arg type='o' direction='in'/><arg type='u' direction='in'/><arg type='h' direction='out'/></method>
    <method name='SelectionWriteDone'><arg type='o' direction='in'/><arg type='u' direction='in'/><arg type='b' direction='in'/></method>
    <method name='SelectionRead'><arg type='o' direction='in'/><arg type='s' direction='in'/><arg type='h' direction='out'/></method>
    <signal name='SelectionOwnerChanged'><arg type='o'/><arg type='a{sv}'/></signal>
    <signal name='SelectionTransfer'><arg type='o'/><arg type='s'/><arg type='u'/></signal>
  </interface>
</node>)";

  /**
   * @brief The portal Session object exported for every created session.
   */
  constexpr const char *SESSION_XML = R"(
<node>
  <interface name='org.freedesktop.portal.Session'>
    <method name='Close'/>
    <signal name='Closed'><arg type='a{sv}'/></signal>
    <property name='version' type='u' access='read'/>
  </interface>
</node>)";

  /**
   * @brief Block SIGPIPE in the calling thread (the backend may close a pipe early).
   */
  void block_sigpipe() {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &set, nullptr);
  }

  /**
   * @brief A PNG signature and IHDR followed by filler.
   */
  bytes_t fake_png(std::size_t size) {
    bytes_t png {0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n', 0, 0, 0, 13, 'I', 'H', 'D', 'R', 0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0};
    for (std::size_t i = 0; i < size; ++i) {
      png.push_back(static_cast<std::uint8_t>(i * 7 + 3));
    }
    return png;
  }

  /**
   * @brief Fake xdg-desktop-portal with the Clipboard interface.
   */
  class fake_portal_t {
  public:
    /**
     * @brief How SelectionRead answers for a MIME type.
     */
    enum class read_mode_e {
      normal,  ///< Write the content and close the pipe.
      stall,  ///< Keep the pipe open without writing.
    };

    /**
     * @brief Result of one SelectionTransfer round.
     */
    struct transfer_result_t {
      bool success = false;  ///< SelectionWriteDone(success).
      bytes_t data;  ///< Bytes written to the SelectionWrite pipe.
      bool wrote = false;  ///< SelectionWrite was called.
    };

    /**
     * @brief Serve the portal on the given bus from a background thread.
     */
    bool start(const std::string &bus_address) {
      context_ = g_main_context_new();
      loop_ = g_main_loop_new(context_, false);
      std::promise<bool> ready;
      auto started = ready.get_future();
      thread_ = std::thread([this, bus_address, ready = std::move(ready)]() mutable {
        g_main_context_push_thread_default(context_);
        const bool ok = setup(bus_address);
        ready.set_value(ok);
        if (ok) {
          g_main_loop_run(loop_);
        }
        for (const auto id : registrations_) {
          g_dbus_connection_unregister_object(conn_, id);
        }
        for (auto &[path, session] : sessions_) {
          if (session.registration) {
            g_dbus_connection_unregister_object(conn_, session.registration);
          }
        }
        g_clear_object(&conn_);
        g_main_context_pop_thread_default(context_);
      });
      return started.get();
    }

    /**
     * @brief Stop serving and release everything.
     */
    void stop() {
      if (thread_.joinable()) {
        g_main_context_invoke(
          context_,
          [](gpointer loop) {
            g_main_loop_quit(static_cast<GMainLoop *>(loop));
            return G_SOURCE_REMOVE;
          },
          loop_
        );
        thread_.join();
      }
      {
        std::lock_guard lock(mutex_);
        for (const int fd : stalled_fds_) {
          close(fd);
        }
        stalled_fds_.clear();
      }
      for (auto &worker : workers_) {
        if (worker.joinable()) {
          worker.join();
        }
      }
      workers_.clear();
      if (loop_) {
        g_main_loop_unref(loop_);
        loop_ = nullptr;
      }
      if (context_) {
        g_main_context_unref(context_);
        context_ = nullptr;
      }
    }

    ~fake_portal_t() {
      stop();
    }

    /**
     * @brief Make Clipboard methods fail as on a portal without the interface.
     */
    void set_clipboard_supported(bool supported) {
      clipboard_supported_ = supported;
    }

    /**
     * @brief Value of `clipboard_enabled` in Start results for sessions that requested it.
     */
    void set_grant_clipboard(bool grant) {
      grant_clipboard_ = grant;
    }

    /**
     * @brief Whether SetSelection is confirmed with SelectionOwnerChanged(session_is_owner=true).
     */
    void set_confirm_set_selection(bool confirm) {
      confirm_set_selection_ = confirm;
    }

    /**
     * @brief Content returned by SelectionRead.
     */
    void set_read_content(std::map<std::string, bytes_t> content, std::map<std::string, read_mode_e> modes = {}) {
      std::lock_guard lock(mutex_);
      read_content_ = std::move(content);
      read_modes_ = std::move(modes);
    }

    /**
     * @brief Number of calls to a method.
     */
    int count(const std::string &method) {
      std::lock_guard lock(mutex_);
      return static_cast<int>(std::ranges::count(calls_, method));
    }

    /**
     * @brief Method names in call order.
     */
    std::vector<std::string> calls() {
      std::lock_guard lock(mutex_);
      return calls_;
    }

    /**
     * @brief MIME types requested with SelectionRead, in order.
     */
    std::vector<std::string> reads() {
      std::lock_guard lock(mutex_);
      return reads_;
    }

    /**
     * @brief Arguments of every SetSelection (nullopt: no mime_types key).
     */
    std::vector<std::optional<std::vector<std::string>>> selections() {
      std::lock_guard lock(mutex_);
      return selections_;
    }

    /**
     * @brief Path of the most recently created session.
     */
    std::string last_session() {
      std::lock_guard lock(mutex_);
      return last_session_;
    }

    /**
     * @brief Whether a session was closed (explicitly or by the portal).
     */
    bool session_closed(const std::string &path) {
      std::lock_guard lock(mutex_);
      const auto it = sessions_.find(path);
      return it != sessions_.end() && it->second.closed;
    }

    /**
     * @brief Emit SelectionOwnerChanged for the last session.
     */
    void emit_owner_changed(const std::vector<std::string> &mimes, std::optional<bool> session_is_owner) {
      GVariantBuilder options;
      g_variant_builder_init(&options, G_VARIANT_TYPE_VARDICT);
      GVariantBuilder types;
      g_variant_builder_init(&types, G_VARIANT_TYPE_STRING_ARRAY);
      for (const auto &mime : mimes) {
        g_variant_builder_add(&types, "s", mime.c_str());
      }
      g_variant_builder_add(&options, "{sv}", "mime_types", g_variant_builder_end(&types));
      if (session_is_owner) {
        g_variant_builder_add(&options, "{sv}", "session_is_owner", g_variant_new_boolean(*session_is_owner));
      }
      std::string client;
      std::string session;
      {
        std::lock_guard lock(mutex_);
        client = client_;
        session = last_session_;
      }
      g_dbus_connection_emit_signal(conn_, client.c_str(), PORTAL_PATH, CLIPBOARD_IFACE, "SelectionOwnerChanged", g_variant_new("(oa{sv})", session.c_str(), &options), nullptr);
      g_dbus_connection_flush_sync(conn_, nullptr, nullptr);
    }

    /**
     * @brief Ask the client for its selection in `mime` (SelectionTransfer).
     *
     * @return Serial of the transfer.
     */
    guint32 request_transfer(const std::string &mime) {
      std::string client;
      std::string session;
      guint32 serial;
      {
        std::lock_guard lock(mutex_);
        client = client_;
        session = last_session_;
        serial = ++serial_;
        pending_serials_.insert(serial);
      }
      g_dbus_connection_emit_signal(conn_, client.c_str(), PORTAL_PATH, CLIPBOARD_IFACE, "SelectionTransfer", g_variant_new("(osu)", session.c_str(), mime.c_str(), serial), nullptr);
      g_dbus_connection_flush_sync(conn_, nullptr, nullptr);
      return serial;
    }

    /**
     * @brief Wait for SelectionWriteDone of a transfer and the data written for it.
     */
    std::optional<transfer_result_t> wait_transfer(guint32 serial, std::chrono::milliseconds timeout = 3s) {
      std::unique_lock lock(mutex_);
      if (!cv_.wait_for(lock, timeout, [&]() {
            const auto done = write_done_.find(serial);
            if (done == write_done_.end()) {
              return false;
            }
            // When data was written, also wait for the reader to see EOF
            return !written_.contains(serial) || finished_.contains(serial);
          })) {
        return std::nullopt;
      }
      transfer_result_t result;
      result.success = write_done_[serial];
      result.wrote = written_.contains(serial);
      if (result.wrote) {
        result.data = written_[serial];
      }
      return result;
    }

    /**
     * @brief Close the last session from the portal side and emit Session.Closed.
     */
    void close_session_from_portal() {
      std::string path;
      std::string client;
      {
        std::lock_guard lock(mutex_);
        path = last_session_;
        client = client_;
      }
      std::promise<void> done;
      auto finished = done.get_future();

      struct ctx_t {
        fake_portal_t *self;
        std::string path;
        std::promise<void> *done;
      } ctx {this, path, &done};

      g_main_context_invoke(
        context_,
        [](gpointer data) {
          auto *c = static_cast<ctx_t *>(data);
          c->self->mark_closed(c->path);
          c->done->set_value();
          return G_SOURCE_REMOVE;
        },
        &ctx
      );
      finished.wait();
      g_dbus_connection_emit_signal(conn_, client.c_str(), path.c_str(), "org.freedesktop.portal.Session", "Closed", g_variant_new("(a{sv})", nullptr), nullptr);
      g_dbus_connection_flush_sync(conn_, nullptr, nullptr);
    }

  private:
    /**
     * @brief State of one portal session.
     */
    struct session_t {
      bool clipboard_requested = false;  ///< RequestClipboard was called.
      bool started = false;  ///< Start was called.
      bool closed = false;  ///< Closed.
      guint registration = 0;  ///< Exported Session object.
    };

    /**
     * @brief Connect, claim the portal name and export the portal object.
     */
    bool setup(const std::string &bus_address) {
      conn_ = g_dbus_connection_new_for_address_sync(bus_address.c_str(), GDBusConnectionFlags(G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT | G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION), nullptr, nullptr, nullptr);
      if (!conn_) {
        return false;
      }
      g_autoptr(GVariant) name_reply = g_dbus_connection_call_sync(conn_, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "RequestName", g_variant_new("(su)", PORTAL_NAME, 4u), G_VARIANT_TYPE("(u)"), G_DBUS_CALL_FLAGS_NONE, -1, nullptr, nullptr);
      guint32 name_result = 0;
      if (!name_reply) {
        return false;
      }
      g_variant_get(name_reply, "(u)", &name_result);
      if (name_result != 1) {
        return false;
      }
      portal_node_ = g_dbus_node_info_new_for_xml(PORTAL_XML, nullptr);
      session_node_ = g_dbus_node_info_new_for_xml(SESSION_XML, nullptr);
      static const GDBusInterfaceVTable vtable {handle_method_call, nullptr, nullptr, {}};
      for (auto **iface = portal_node_->interfaces; *iface; ++iface) {
        const auto id = g_dbus_connection_register_object(conn_, PORTAL_PATH, *iface, &vtable, this, nullptr, nullptr);
        if (id == 0) {
          return false;
        }
        registrations_.push_back(id);
      }
      return true;
    }

    /**
     * @brief Mark a session closed and stop exporting its object (Properties.Get then fails).
     */
    void mark_closed(const std::string &path) {
      std::lock_guard lock(mutex_);
      auto &session = sessions_[path];
      session.closed = true;
      if (session.registration) {
        g_dbus_connection_unregister_object(conn_, session.registration);
        session.registration = 0;
      }
    }

    /**
     * @brief Session object: Close and the version property.
     */
    static void handle_session_call(GDBusConnection *, const gchar *, const gchar *object_path, const gchar *, const gchar *method_name, GVariant *, GDBusMethodInvocation *invocation, gpointer user_data) {  // NOSONAR(cpp:S107): GDBusInterfaceMethodCallFunc signature.
      auto *self = static_cast<fake_portal_t *>(user_data);
      if (g_str_equal(method_name, "Close")) {
        {
          std::lock_guard lock(self->mutex_);
          self->calls_.emplace_back("Session.Close");
        }
        self->mark_closed(object_path);
      }
      g_dbus_method_invocation_return_value(invocation, nullptr);
    }

    /**
     * @brief Session object property getter.
     */
    static GVariant *get_session_property(GDBusConnection *, const gchar *, const gchar *, const gchar *, const gchar *, GError **, gpointer) {  // NOSONAR(cpp:S107): GDBusInterfaceGetPropertyFunc signature.
      return g_variant_new_uint32(1);
    }

    /**
     * @brief Return an fd list with one descriptor (duplicated) and close ours.
     */
    static void return_fd(GDBusMethodInvocation *invocation, int fd) {
      g_autoptr(GUnixFDList) list = g_unix_fd_list_new();
      g_unix_fd_list_append(list, fd, nullptr);
      close(fd);
      g_dbus_method_invocation_return_value_with_unix_fd_list(invocation, g_variant_new("(h)", 0), list);
    }

    /**
     * @brief Answer the Clipboard methods.
     */
    void handle_clipboard(const gchar *method_name, GVariant *parameters, GDBusMethodInvocation *invocation) {
      if (!clipboard_supported_) {
        g_dbus_method_invocation_return_dbus_error(invocation, "org.freedesktop.DBus.Error.UnknownMethod", "No Clipboard here");
        return;
      }
      const gchar *session_path = nullptr;
      g_autoptr(GVariant) first = g_variant_get_child_value(parameters, 0);
      session_path = g_variant_get_string(first, nullptr);

      if (g_str_equal(method_name, "RequestClipboard")) {
        std::lock_guard lock(mutex_);
        auto &session = sessions_[session_path];
        if (session.started) {
          g_dbus_method_invocation_return_error_literal(invocation, G_DBUS_ERROR, G_DBUS_ERROR_FAILED, "Invalid state");
          return;
        }
        session.clipboard_requested = true;
        g_dbus_method_invocation_return_value(invocation, nullptr);
        return;
      }

      if (g_str_equal(method_name, "SetSelection")) {
        g_autoptr(GVariant) options = g_variant_get_child_value(parameters, 1);
        std::optional<std::vector<std::string>> mimes;
        g_autofree const gchar **types = nullptr;
        if (g_variant_lookup(options, "mime_types", "^a&s", &types)) {
          mimes.emplace();
          for (auto **t = types; *t; ++t) {
            mimes->emplace_back(*t);
          }
        }
        {
          std::lock_guard lock(mutex_);
          selections_.push_back(mimes);
        }
        g_dbus_method_invocation_return_value(invocation, nullptr);
        if (mimes && confirm_set_selection_) {
          emit_owner_changed(*mimes, true);
        }
        return;
      }

      if (g_str_equal(method_name, "SelectionRead")) {
        const gchar *mime = nullptr;
        g_variant_get(parameters, "(&o&s)", nullptr, &mime);
        bytes_t content;
        read_mode_e mode = read_mode_e::normal;
        {
          std::lock_guard lock(mutex_);
          reads_.emplace_back(mime);
          const auto it = read_content_.find(mime);
          if (it == read_content_.end()) {
            g_dbus_method_invocation_return_error_literal(invocation, G_DBUS_ERROR, G_DBUS_ERROR_FAILED, "Not offered");
            return;
          }
          content = it->second;
          if (const auto m = read_modes_.find(mime); m != read_modes_.end()) {
            mode = m->second;
          }
        }
        std::array<int, 2> fds {};
        if (pipe2(fds.data(), O_CLOEXEC) != 0) {
          g_dbus_method_invocation_return_error_literal(invocation, G_DBUS_ERROR, G_DBUS_ERROR_FAILED, "pipe");
          return;
        }
        if (mode == read_mode_e::stall) {
          std::lock_guard lock(mutex_);
          stalled_fds_.push_back(fds[1]);
        } else {
          workers_.emplace_back([fd = fds[1], content = std::move(content)]() {
            block_sigpipe();
            std::size_t offset = 0;
            while (offset < content.size()) {
              const ssize_t n = ::write(fd, content.data() + offset, content.size() - offset);
              if (n <= 0) {
                break;
              }
              offset += static_cast<std::size_t>(n);
            }
            close(fd);
          });
        }
        return_fd(invocation, fds[0]);
        return;
      }

      if (g_str_equal(method_name, "SelectionWrite")) {
        guint32 serial = 0;
        g_variant_get(parameters, "(&ou)", nullptr, &serial);
        {
          std::lock_guard lock(mutex_);
          if (!pending_serials_.contains(serial)) {
            g_dbus_method_invocation_return_error_literal(invocation, G_DBUS_ERROR, G_DBUS_ERROR_FAILED, "Unknown serial");
            return;
          }
          written_[serial];
        }
        std::array<int, 2> fds {};
        if (pipe2(fds.data(), O_CLOEXEC) != 0) {
          g_dbus_method_invocation_return_error_literal(invocation, G_DBUS_ERROR, G_DBUS_ERROR_FAILED, "pipe");
          return;
        }
        workers_.emplace_back([this, fd = fds[0], serial]() {
          std::array<std::uint8_t, 65536> buffer {};
          bytes_t data;
          while (true) {
            const ssize_t n = ::read(fd, buffer.data(), buffer.size());
            if (n <= 0) {
              break;
            }
            data.insert(data.end(), buffer.begin(), buffer.begin() + n);
          }
          close(fd);
          {
            std::lock_guard lock(mutex_);
            written_[serial] = std::move(data);
            finished_.insert(serial);
          }
          cv_.notify_all();
        });
        return_fd(invocation, fds[1]);
        return;
      }

      if (g_str_equal(method_name, "SelectionWriteDone")) {
        guint32 serial = 0;
        gboolean success = FALSE;
        g_variant_get(parameters, "(&oub)", nullptr, &serial, &success);
        {
          std::lock_guard lock(mutex_);
          write_done_[serial] = success;
          pending_serials_.erase(serial);
        }
        cv_.notify_all();
        g_dbus_method_invocation_return_value(invocation, nullptr);
        return;
      }
      g_dbus_method_invocation_return_error_literal(invocation, G_DBUS_ERROR, G_DBUS_ERROR_UNKNOWN_METHOD, method_name);
    }

    /**
     * @brief Answer portal method calls; request methods emit Response before returning.
     */
    static void handle_method_call(GDBusConnection *conn, const gchar *sender, const gchar *, const gchar *interface_name, const gchar *method_name, GVariant *parameters, GDBusMethodInvocation *invocation, gpointer user_data) {  // NOSONAR(cpp:S107): GDBusInterfaceMethodCallFunc signature.
      auto *self = static_cast<fake_portal_t *>(user_data);
      {
        std::lock_guard lock(self->mutex_);
        self->calls_.emplace_back(method_name);
        self->client_ = sender;
      }
      if (g_str_equal(interface_name, CLIPBOARD_IFACE)) {
        self->handle_clipboard(method_name, parameters, invocation);
        return;
      }
      if (g_str_equal(method_name, "OpenPipeWireRemote")) {
        return_fd(invocation, open("/dev/null", O_RDONLY | O_CLOEXEC));
        return;
      }

      g_autoptr(GVariant) options = g_variant_get_child_value(parameters, g_variant_n_children(parameters) - 1);
      const gchar *handle_token = nullptr;
      if (!g_variant_lookup(options, "handle_token", "&s", &handle_token)) {
        g_dbus_method_invocation_return_error_literal(invocation, G_DBUS_ERROR, G_DBUS_ERROR_INVALID_ARGS, "handle_token is required");
        return;
      }
      g_autofree gchar *sender_id = g_strdelimit(g_strdup(sender + 1), ".", '_');
      g_autofree gchar *request_path = g_strdup_printf("%s/request/%s/%s", PORTAL_PATH, sender_id, handle_token);

      GVariantBuilder results;
      g_variant_builder_init(&results, G_VARIANT_TYPE_VARDICT);
      if (g_str_equal(method_name, "CreateSession")) {
        const gchar *session_token = nullptr;
        g_variant_lookup(options, "session_handle_token", "&s", &session_token);
        g_autofree gchar *session_path = g_strdup_printf("%s/session/%s/%s", PORTAL_PATH, sender_id, session_token);
        static const GDBusInterfaceVTable session_vtable {handle_session_call, get_session_property, nullptr, {}};
        const guint registration = g_dbus_connection_register_object(conn, session_path, self->session_node_->interfaces[0], &session_vtable, self, nullptr, nullptr);
        {
          std::lock_guard lock(self->mutex_);
          self->sessions_[session_path] = session_t {.registration = registration};
          self->last_session_ = session_path;
        }
        g_variant_builder_add(&results, "{sv}", "session_handle", g_variant_new_string(session_path));
      } else if (g_str_equal(method_name, "Start")) {
        g_autoptr(GVariant) session_value = g_variant_get_child_value(parameters, 0);
        const std::string session_path = g_variant_get_string(session_value, nullptr);
        bool clipboard_requested;
        {
          std::lock_guard lock(self->mutex_);
          auto &session = self->sessions_[session_path];
          session.started = true;
          clipboard_requested = session.clipboard_requested;
        }
        GVariantBuilder properties;
        g_variant_builder_init(&properties, G_VARIANT_TYPE_VARDICT);
        g_variant_builder_add(&properties, "{sv}", "size", g_variant_new("(ii)", 1234, 567));
        g_variant_builder_add(&properties, "{sv}", "position", g_variant_new("(ii)", 7, 9));
        GVariantBuilder streams;
        g_variant_builder_init(&streams, G_VARIANT_TYPE("a(ua{sv})"));
        g_variant_builder_add(&streams, "(ua{sv})", 42u, &properties);
        g_variant_builder_add(&results, "{sv}", "streams", g_variant_builder_end(&streams));
        g_variant_builder_add(&results, "{sv}", "restore_token", g_variant_new_string("fresh-token"));
        if (clipboard_requested) {
          g_variant_builder_add(&results, "{sv}", "clipboard_enabled", g_variant_new_boolean(self->grant_clipboard_.load()));
        }
      }
      g_dbus_connection_emit_signal(conn, sender, request_path, "org.freedesktop.portal.Request", "Response", g_variant_new("(ua{sv})", 0u, &results), nullptr);
      g_dbus_method_invocation_return_value(invocation, g_variant_new("(o)", request_path));
    }

    GMainContext *context_ = nullptr;
    GMainLoop *loop_ = nullptr;
    GDBusConnection *conn_ = nullptr;
    GDBusNodeInfo *portal_node_ = nullptr;
    GDBusNodeInfo *session_node_ = nullptr;
    std::vector<guint> registrations_;
    std::thread thread_;
    std::vector<std::thread> workers_;

    std::atomic<bool> clipboard_supported_ {true};
    std::atomic<bool> grant_clipboard_ {true};
    std::atomic<bool> confirm_set_selection_ {true};

    std::mutex mutex_;
    std::condition_variable cv_;
    std::vector<std::string> calls_;
    std::string client_;
    std::string last_session_;
    std::map<std::string, session_t> sessions_;
    std::map<std::string, bytes_t> read_content_;
    std::map<std::string, read_mode_e> read_modes_;
    std::vector<std::string> reads_;
    std::vector<std::optional<std::vector<std::string>>> selections_;
    std::vector<int> stalled_fds_;
    guint32 serial_ = 0;
    std::set<guint32> pending_serials_;
    std::map<guint32, bytes_t> written_;
    std::set<guint32> finished_;
    std::map<guint32, bool> write_done_;
  };

  /**
   * @brief Configuration of the private test bus.
   */
  constexpr const char *BUS_CONFIG = R"(<busconfig>
  <type>session</type>
  <listen>unix:dir={}</listen>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>
)";

  /**
   * @brief Runs each test against the fake portal on a private session bus.
   */
  class PortalSessionTest: public BaseTest {
  protected:
    void SetUp() override {
      BaseTest::SetUp();
      if (HasFatalFailure() || IsSkipped()) {
        return;
      }
      g_autofree gchar *daemon = g_find_program_in_path("dbus-daemon");
      if (!daemon) {
        GTEST_SKIP() << "dbus-daemon is required for a private test bus";
      }
      auto directory_template = (std::filesystem::temp_directory_path() / "sunshine-clipboard-bus-XXXXXX").string();  // NOSONAR(cpp:S5443): mkdtemp creates a private unique directory.
      ASSERT_NE(mkdtemp(directory_template.data()), nullptr);
      bus_directory_ = directory_template;
      token_path_ = bus_directory_ / "portal_token.test";
      portal::set_saved_token_path_for_testing(token_path_);
      portal::clear_saved_token();

      const auto config_path = bus_directory_ / "bus.conf";
      std::ofstream(config_path) << std::format(BUS_CONFIG, bus_directory_.string());
      std::string config_arg = "--config-file=" + config_path.string();
      std::string nofork_arg = "--nofork";
      std::string address_arg = "--print-address";
      std::array<gchar *, 5> argv {daemon, config_arg.data(), nofork_arg.data(), address_arg.data(), nullptr};
      gint output_fd = -1;
      ASSERT_TRUE(g_spawn_async_with_pipes(nullptr, argv.data(), nullptr, G_SPAWN_DO_NOT_REAP_CHILD, nullptr, nullptr, &daemon_pid_, nullptr, &output_fd, nullptr, nullptr));
      daemon_output_ = fdopen(output_fd, "r");
      ASSERT_NE(daemon_output_, nullptr);
      pollfd output_poll {output_fd, POLLIN, 0};
      ASSERT_EQ(poll(&output_poll, 1, 5000), 1);
      std::array<char, 512> address {};
      ASSERT_NE(fgets(address.data(), address.size(), daemon_output_), nullptr);
      const std::string bus_address = g_strchomp(address.data());

      logging::log_flush();
      set_env("DBUS_SESSION_BUS_ADDRESS", bus_address);
      set_env("WAYLAND_DISPLAY", (bus_directory_ / "no-wayland").string());
      portal::set_clipboard_requested(true);
      ASSERT_TRUE(portal_.start(bus_address));
    }

    void TearDown() override {
      portal::set_clipboard_requested(false);
      portal_.stop();
      if (!token_path_.empty()) {
        portal::clear_saved_token();
        portal::reset_saved_token_path_for_testing();
      }
      logging::log_flush();
      for (const auto &[name, previous] : previous_env_) {
        if (previous) {
          g_setenv(name.c_str(), previous->c_str(), true);
        } else {
          g_unsetenv(name.c_str());
        }
      }
      if (daemon_pid_ > 0) {
        kill(daemon_pid_, SIGTERM);
        waitpid(daemon_pid_, nullptr, 0);
        g_spawn_close_pid(daemon_pid_);
      }
      if (daemon_output_) {
        fclose(daemon_output_);
      }
      if (!bus_directory_.empty()) {
        std::error_code ec;
        std::filesystem::remove_all(bus_directory_, ec);
      }
      BaseTest::TearDown();
    }

    /**
     * @brief Set an environment variable for the test, remembering the previous value.
     */
    void set_env(const std::string &name, const std::string &value) {
      if (!previous_env_.contains(name)) {
        const gchar *previous = g_getenv(name.c_str());
        previous_env_[name] = previous ? std::optional<std::string> {previous} : std::nullopt;
      }
      g_setenv(name.c_str(), value.c_str(), true);
    }

    fake_portal_t portal_;
    GPid daemon_pid_ = 0;
    FILE *daemon_output_ = nullptr;
    std::filesystem::path bus_directory_;
    std::filesystem::path token_path_;
    std::map<std::string, std::optional<std::string>, std::less<>> previous_env_;
  };

  /**
   * @brief Portal tests with a started clipboard backend.
   */
  class PortalClipboardTest: public PortalSessionTest {
  protected:
    void SetUp() override {
      PortalSessionTest::SetUp();
      if (HasFatalFailure() || IsSkipped()) {
        return;
      }
      backend_ = sds::clipboard::xdp::make_backend();
      ASSERT_EQ(backend_->start([this]() {
        std::lock_guard lock(mutex_);
        ++changes_;
        cv_.notify_all();
      }),
                0);
      EXPECT_EQ(backend_->name(), "xdg-portal");
    }

    void TearDown() override {
      if (backend_) {
        backend_->stop();
        backend_.reset();
      }
      PortalSessionTest::TearDown();
    }

    /**
     * @brief Wait until at least `count` change notifications arrived.
     */
    bool wait_changes(int count, std::chrono::milliseconds timeout = 3s) {
      std::unique_lock lock(mutex_);
      return cv_.wait_for(lock, timeout, [&]() {
        return changes_ >= count;
      });
    }

    /**
     * @brief Number of change notifications so far.
     */
    int changes() {
      std::lock_guard lock(mutex_);
      return changes_;
    }

    std::unique_ptr<sds::clipboard::backend_t> backend_;
    std::mutex mutex_;
    std::condition_variable cv_;
    int changes_ = 0;
  };
}  // namespace

TEST_F(PortalSessionTest, RequestsClipboardBeforeStart) {
  const auto session = portal::acquire_shared_session(true);
  ASSERT_TRUE(session);
  EXPECT_TRUE(session->clipboard_enabled());
  EXPECT_FALSE(session->is_closed());
  EXPECT_EQ(session->handle(), portal_.last_session());
  EXPECT_NE(session->connection(), nullptr);

  const auto calls = portal_.calls();
  const auto position = [&](const std::string &name) {
    return std::ranges::find(calls, name) - calls.begin();
  };
  ASSERT_EQ(portal_.count("RequestClipboard"), 1);
  EXPECT_LT(position("SelectSources"), position("RequestClipboard"));
  EXPECT_LT(position("SelectDevices"), position("RequestClipboard"));
  EXPECT_LT(position("RequestClipboard"), position("Start"));
}

TEST_F(PortalSessionTest, ReusesTheOpenSession) {
  const auto first = portal::acquire_shared_session(true);
  const auto second = portal::acquire_shared_session(false);
  ASSERT_TRUE(first);
  ASSERT_TRUE(second);
  EXPECT_EQ(first->handle(), second->handle());
  EXPECT_EQ(portal_.count("CreateSession"), 1);
  const auto current = portal::current_shared_session();
  ASSERT_TRUE(current);
  EXPECT_EQ(current->handle(), first->handle());
}

TEST_F(PortalSessionTest, ReleasingTheLastLeaseClosesTheSession) {
  auto session = portal::acquire_shared_session(true);
  ASSERT_TRUE(session);
  const auto path = session->handle();
  session.reset();
  EXPECT_TRUE(portal_.session_closed(path));
  EXPECT_FALSE(portal::current_shared_session());

  session = portal::acquire_shared_session(true);
  ASSERT_TRUE(session);
  EXPECT_NE(session->handle(), path);
  EXPECT_EQ(portal_.count("CreateSession"), 2);
}

TEST_F(PortalSessionTest, ReplacesASessionClosedByThePortal) {
  const auto first = portal::acquire_shared_session(true);
  ASSERT_TRUE(first);
  portal_.close_session_from_portal();
  EXPECT_TRUE(first->is_closed());
  EXPECT_FALSE(portal::current_shared_session());

  const auto second = portal::acquire_shared_session(true);
  ASSERT_TRUE(second);
  EXPECT_NE(second->handle(), first->handle());
  EXPECT_EQ(portal_.count("CreateSession"), 2);
}

TEST_F(PortalSessionTest, CurrentSessionNeverCreatesOne) {
  EXPECT_FALSE(portal::current_shared_session());
  EXPECT_EQ(portal_.count("CreateSession"), 0);
}

TEST_F(PortalSessionTest, DoesNotRequestClipboardWhenFeatureIsOff) {
  portal::set_clipboard_requested(false);
  const auto session = portal::acquire_shared_session(true);
  ASSERT_TRUE(session);
  EXPECT_FALSE(session->clipboard_enabled());
  EXPECT_EQ(portal_.count("RequestClipboard"), 0);
}

TEST_F(PortalSessionTest, StartsWithoutClipboardWhenThePortalLacksIt) {
  portal_.set_clipboard_supported(false);
  const auto session = portal::acquire_shared_session(true);
  ASSERT_TRUE(session);
  EXPECT_FALSE(session->clipboard_enabled());
  EXPECT_EQ(portal_.count("Start"), 1);
}

TEST_F(PortalSessionTest, ReportsDeniedClipboard) {
  portal_.set_grant_clipboard(false);
  const auto session = portal::acquire_shared_session(true);
  ASSERT_TRUE(session);
  EXPECT_FALSE(session->clipboard_enabled());
}

TEST_F(PortalSessionTest, OpensOnePipeWireRemotePerDisplay) {
  const auto session = portal::acquire_shared_session(true);
  ASSERT_TRUE(session);
  EXPECT_EQ(portal_.count("OpenPipeWireRemote"), 1);
  const int first = session->open_pipewire_remote();  // the remote opened while starting
  EXPECT_EQ(portal_.count("OpenPipeWireRemote"), 1);
  const int second = session->open_pipewire_remote();
  EXPECT_EQ(portal_.count("OpenPipeWireRemote"), 2);
  EXPECT_GE(first, 0);
  EXPECT_GE(second, 0);
  EXPECT_NE(first, second);
  close(first);
  close(second);
}

TEST_F(PortalSessionTest, EnumerationReusesTheSharedSession) {
  const auto session = portal::acquire_shared_session(true);
  ASSERT_TRUE(session);
  const auto names = platf::portal_display_names(true);
  EXPECT_EQ(names, std::vector<std::string> {"position-7x9-resolution-1234x567"});
  EXPECT_EQ(portal_.count("CreateSession"), 1);
}

TEST_F(PortalSessionTest, EnumerationRequestsClipboardForTokenNegotiation) {
  const auto names = platf::portal_display_names(true);
  EXPECT_EQ(names, std::vector<std::string> {"position-7x9-resolution-1234x567"});
  EXPECT_EQ(portal_.count("RequestClipboard"), 1);
  EXPECT_TRUE(portal_.session_closed(portal_.last_session()));
  EXPECT_FALSE(portal::current_shared_session());  // probes never create the shared session
}

TEST_F(PortalSessionTest, EnumerationWithoutFeatureDoesNotRequestClipboard) {
  portal::set_clipboard_requested(false);
  const auto names = platf::portal_display_names(true);
  EXPECT_EQ(names.size(), 1u);
  EXPECT_EQ(portal_.count("RequestClipboard"), 0);
}

TEST_F(PortalSessionTest, BackendStartFailsWithoutClipboardAccess) {
  portal_.set_grant_clipboard(false);
  auto backend = sds::clipboard::xdp::make_backend();
  EXPECT_LT(backend->start([]() {
  }),
            0);
  EXPECT_FALSE(backend->read(big_limits, 100ms));
  EXPECT_EQ(backend->write({.text = "x", .png = std::nullopt}), -1);
  backend->stop();
  EXPECT_TRUE(portal_.session_closed(portal_.last_session()));
}

TEST_F(PortalClipboardTest, ReadsTextAndPngOfferedByAnotherApplication) {
  const auto png = fake_png(5000);
  portal_.set_read_content({{"text/plain;charset=utf-8", bytes_t {'h', 0xC3, 0xA9, 'l', 'l', 'o'}}, {"image/png", png}});
  portal_.emit_owner_changed({"text/plain;charset=utf-8", "UTF8_STRING", "image/png"}, false);
  ASSERT_TRUE(wait_changes(1));
  const auto item = backend_->read(big_limits, 3s);
  ASSERT_TRUE(item);
  EXPECT_EQ(item->text, "h\xC3\xA9llo");
  EXPECT_EQ(item->png, png);
  EXPECT_EQ(portal_.reads(), (std::vector<std::string> {"text/plain;charset=utf-8", "image/png"}));
}

TEST_F(PortalClipboardTest, IgnoresOwnerChangesOfItsOwnSession) {
  portal_.emit_owner_changed({"text/plain;charset=utf-8"}, true);
  std::this_thread::sleep_for(300ms);
  EXPECT_EQ(changes(), 0);
}

TEST_F(PortalClipboardTest, TreatsAMissingOwnerFlagAsAForeignChange) {
  portal_.emit_owner_changed({}, std::nullopt);
  EXPECT_TRUE(wait_changes(1));
  EXPECT_FALSE(backend_->read(big_limits, 1s));  // nothing offered: no SelectionRead
  EXPECT_TRUE(portal_.reads().empty());
}

TEST_F(PortalClipboardTest, UsesTextAliases) {
  portal_.set_read_content({{"UTF8_STRING", bytes_t {'a', 'l', 'i', 'a', 's'}}});
  portal_.emit_owner_changed({"UTF8_STRING", "TARGETS"}, false);
  ASSERT_TRUE(wait_changes(1));
  auto item = backend_->read(big_limits, 3s);
  ASSERT_TRUE(item);
  EXPECT_EQ(item->text, "alias");

  portal_.set_read_content({{"STRING", bytes_t {'c', 'a', 'f', 0xE9}}});
  portal_.emit_owner_changed({"STRING"}, false);
  ASSERT_TRUE(wait_changes(2));
  item = backend_->read(big_limits, 3s);
  ASSERT_TRUE(item);
  EXPECT_EQ(item->text, "caf\xC3\xA9");
}

TEST_F(PortalClipboardTest, TriesCanonicalTypesBeforeTheFirstOwnerChange) {
  portal_.set_read_content({{"text/plain;charset=utf-8", bytes_t {'e', 'a', 'r', 'l', 'y'}}});
  const auto item = backend_->read(big_limits, 3s);
  ASSERT_TRUE(item);
  EXPECT_EQ(item->text, "early");
  EXPECT_FALSE(item->png);  // image/png attempted and refused
}

TEST_F(PortalClipboardTest, DropsOversizedRepresentations) {
  const auto png = fake_png(100);
  portal_.set_read_content({{"text/plain;charset=utf-8", bytes_t(2000, 'x')}, {"image/png", png}});
  portal_.emit_owner_changed({"text/plain;charset=utf-8", "image/png"}, false);
  ASSERT_TRUE(wait_changes(1));
  auto item = backend_->read({1000, 1000}, 3s);
  ASSERT_TRUE(item);
  EXPECT_FALSE(item->text);
  EXPECT_EQ(item->png, png);
  EXPECT_FALSE(backend_->read({1000, 50}, 3s));
}

TEST_F(PortalClipboardTest, ReadHonoursTheTimeout) {
  portal_.set_read_content({{"text/plain;charset=utf-8", bytes_t {'x'}}}, {{"text/plain;charset=utf-8", fake_portal_t::read_mode_e::stall}});
  portal_.emit_owner_changed({"text/plain;charset=utf-8"}, false);
  ASSERT_TRUE(wait_changes(1));
  const auto start = std::chrono::steady_clock::now();
  EXPECT_FALSE(backend_->read(big_limits, 300ms));
  EXPECT_LT(std::chrono::steady_clock::now() - start, 700ms);
}

TEST_F(PortalClipboardTest, WriteOffersTypesAndServesTransfers) {
  const auto png = fake_png(300 * 1024);
  ASSERT_EQ(backend_->write({.text = "caf\xC3\xA9 \xE2\x9C\x93", .png = png}), 0);
  const auto selections = portal_.selections();
  ASSERT_EQ(selections.size(), 1u);
  ASSERT_TRUE(selections[0]);
  EXPECT_EQ(*selections[0], (std::vector<std::string> {"text/plain;charset=utf-8", "UTF8_STRING", "text/plain", "STRING", "image/png"}));

  const std::map<std::string, std::string> expected {
    {"text/plain;charset=utf-8", "caf\xC3\xA9 \xE2\x9C\x93"},
    {"UTF8_STRING", "caf\xC3\xA9 \xE2\x9C\x93"},
    {"text/plain", "caf\xC3\xA9 \xE2\x9C\x93"},
    {"STRING", "caf\xE9 ?"},
  };
  for (const auto &[mime, text] : expected) {
    const auto result = portal_.wait_transfer(portal_.request_transfer(mime));
    ASSERT_TRUE(result) << mime;
    EXPECT_TRUE(result->success) << mime;
    EXPECT_EQ(std::string(result->data.begin(), result->data.end()), text) << mime;
  }
  const auto image = portal_.wait_transfer(portal_.request_transfer("image/png"));
  ASSERT_TRUE(image);
  EXPECT_TRUE(image->success);
  EXPECT_EQ(image->data, png);

  const auto unknown = portal_.wait_transfer(portal_.request_transfer("image/jpeg"));
  ASSERT_TRUE(unknown);
  EXPECT_FALSE(unknown->success);
  EXPECT_FALSE(unknown->wrote);

  // Our own SetSelection was confirmed with session_is_owner = true: no change notification
  EXPECT_EQ(changes(), 0);
}

TEST_F(PortalClipboardTest, ReadsItsOwnContentFromMemory) {
  ASSERT_EQ(backend_->write({.text = "mine", .png = std::nullopt}), 0);
  const auto item = backend_->read(big_limits, 1s);
  ASSERT_TRUE(item);
  EXPECT_EQ(item->text, "mine");
  EXPECT_TRUE(portal_.reads().empty());
}

TEST_F(PortalClipboardTest, ForeignChangeAfterWriteEndsOwnership) {
  ASSERT_EQ(backend_->write({.text = "mine", .png = std::nullopt}), 0);
  std::this_thread::sleep_for(100ms);  // let the confirmation arrive
  portal_.set_read_content({{"text/plain;charset=utf-8", bytes_t {'t', 'h', 'e', 'i', 'r', 's'}}});
  portal_.emit_owner_changed({"text/plain;charset=utf-8"}, false);
  ASSERT_TRUE(wait_changes(1));
  const auto item = backend_->read(big_limits, 3s);
  ASSERT_TRUE(item);
  EXPECT_EQ(item->text, "theirs");

  const auto refused = portal_.wait_transfer(portal_.request_transfer("text/plain;charset=utf-8"));
  ASSERT_TRUE(refused);
  EXPECT_FALSE(refused->success);
}

TEST_F(PortalClipboardTest, IgnoresStaleForeignChangeBeforeConfirmation) {
  portal_.set_confirm_set_selection(false);
  ASSERT_EQ(backend_->write({.text = "mine", .png = std::nullopt}), 0);
  portal_.emit_owner_changed({"text/plain;charset=utf-8"}, false);
  std::this_thread::sleep_for(300ms);
  EXPECT_EQ(changes(), 0);
  const auto item = backend_->read(big_limits, 1s);
  ASSERT_TRUE(item);
  EXPECT_EQ(item->text, "mine");

  // Without a confirmation the grace period ends and foreign changes count again
  std::this_thread::sleep_for(2s);
  portal_.emit_owner_changed({"text/plain;charset=utf-8"}, false);
  EXPECT_TRUE(wait_changes(1));
}

TEST_F(PortalClipboardTest, StopReleasesOwnershipAndIsIdempotent) {
  ASSERT_EQ(backend_->write({.text = "bye", .png = std::nullopt}), 0);
  const auto path = portal_.last_session();
  backend_->stop();
  const auto selections = portal_.selections();
  ASSERT_EQ(selections.size(), 2u);
  EXPECT_FALSE(selections[1]);  // SetSelection without mime_types
  EXPECT_TRUE(portal_.session_closed(path));  // the backend held the last lease
  backend_->stop();
  EXPECT_FALSE(backend_->read(big_limits, 100ms));
  EXPECT_EQ(backend_->write({.text = "x", .png = std::nullopt}), -1);
}

TEST_F(PortalClipboardTest, StopsUsingASessionClosedByThePortal) {
  portal_.close_session_from_portal();
  for (int i = 0; i < 100 && backend_->write({.text = "x", .png = std::nullopt}) == 0; ++i) {
    std::this_thread::sleep_for(20ms);
  }
  EXPECT_EQ(backend_->write({.text = "x", .png = std::nullopt}), -1);
  EXPECT_FALSE(backend_->read(big_limits, 100ms));
}

TEST_F(PortalClipboardTest, SharesTheSessionWithCapture) {
  const auto session = portal::current_shared_session();
  ASSERT_TRUE(session);
  EXPECT_EQ(session->handle(), portal_.last_session());
  EXPECT_EQ(portal_.count("CreateSession"), 1);
}

#endif
