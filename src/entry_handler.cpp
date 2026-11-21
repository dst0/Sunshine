/**
 * @file entry_handler.cpp
 * @brief Definitions for entry handling functions.
 */
// standard includes
#include <algorithm>
#include <csignal>
#include <format>
#include <iostream>
#include <thread>

#ifdef _WIN32
  #include <io.h>
#else
  #include <termios.h>
  #include <unistd.h>
#endif

// local includes
#include "config.h"
#include "confighttp.h"
#include "entry_handler.h"
#include "globals.h"
#include "httpcommon.h"
#include "logging.h"
#include "network.h"
#include "platform/common.h"

extern "C" {
#ifdef _WIN32
  #include <iphlpapi.h>
#endif
}

using namespace std::literals;

std::string get_launch_ui_url(const std::optional<std::string> &path) {
  std::string url = std::format("https://{}:{}", net::get_bind_address_url_host(), static_cast<int>(net::map_port(confighttp::PORT_HTTPS)));
  if (path) {
    url += *path;
  }
  return url;
}

void launch_ui(const std::optional<std::string> &path) {
  platf::open_url(get_launch_ui_url(path));
}

std::unique_ptr<platf::deinit_t> start_mdns_publisher(const bool enabled, const std::function<std::unique_ptr<platf::deinit_t>()> &start_publisher) {
  if (!enabled) {
    BOOST_LOG(info) << "mDNS advertising is disabled (mdns_advertise = disabled)"sv;
    return nullptr;
  }
  return start_publisher();
}

std::unique_ptr<platf::deinit_t> start_mdns_publisher(const bool enabled) {
  return start_mdns_publisher(enabled, []() {
    return platf::publish::start();
  });
}

namespace {
  /**
   * @brief Disable terminal echo on standard input for the lifetime of the object.
   */
  class scoped_echo_off_t {
  public:
    scoped_echo_off_t() {
#ifdef _WIN32
      handle_ = GetStdHandle(STD_INPUT_HANDLE);
      if (handle_ != INVALID_HANDLE_VALUE && GetConsoleMode(handle_, &mode_)) {
        restore_ = SetConsoleMode(handle_, mode_ & ~ENABLE_ECHO_INPUT) != 0;
      }
#else
      if (tcgetattr(STDIN_FILENO, &mode_) == 0) {
        auto silent = mode_;
        silent.c_lflag &= ~static_cast<tcflag_t>(ECHO);
        restore_ = tcsetattr(STDIN_FILENO, TCSAFLUSH, &silent) == 0;
      }
#endif
    }

    scoped_echo_off_t(const scoped_echo_off_t &) = delete;
    scoped_echo_off_t &operator=(const scoped_echo_off_t &) = delete;

    ~scoped_echo_off_t() {
      if (!restore_) {
        return;
      }
#ifdef _WIN32
      SetConsoleMode(handle_, mode_);
#else
      tcsetattr(STDIN_FILENO, TCSAFLUSH, &mode_);
#endif
    }

  private:
#ifdef _WIN32
    HANDLE handle_ = INVALID_HANDLE_VALUE;  ///< Console input handle.
    DWORD mode_ = 0;  ///< Console mode restored on destruction.
#else
    termios mode_ {};  ///< Terminal attributes restored on destruction.
#endif
    bool restore_ = false;  ///< Whether echo was disabled and must be restored.
  };

  /**
   * @brief Check whether standard input is an interactive terminal.
   *
   * @return `true` when standard input is a terminal.
   */
  bool stdin_is_terminal() {
#ifdef _WIN32
    return _isatty(_fileno(stdin)) != 0;
#else
    return isatty(STDIN_FILENO) != 0;
#endif
  }

  /**
   * @brief Prompt for a password on the terminal without echoing it.
   *
   * @param input Terminal input stream.
   * @param prompt Prompt written to standard error.
   * @return Entered password, or no value at end of input.
   */
  std::optional<std::string> prompt_password(std::istream &input, const std::string_view prompt) {
    std::cerr << prompt << std::flush;
    const scoped_echo_off_t echo_off;
    auto password = args::read_password_line(input);
    std::cerr << std::endl;
    return password;
  }
}  // namespace

namespace args {
  std::optional<std::string> read_password_line(std::istream &input) {
    std::string line;
    if (!std::getline(input, line) && line.empty()) {
      return std::nullopt;
    }
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }
    return line;
  }

  int creds(const char *name, int argc, char *argv[], std::istream &input, const bool interactive) {
    if (argc < 1 || argv[0] == "help"sv || (argc >= 2 && argv[1] == "help"sv)) {
      help(name);
      return argc < 1 ? 1 : 0;
    }

    const std::string username = argv[0];
    if (username.empty()) {
      std::cerr << "Error: the username must not be empty." << std::endl;
      return 1;
    }

    std::string password;
    if (argc >= 2) {
      std::cerr << "Warning: a password on the command line is visible to other users and in the shell history; "
                   "omit it to be prompted instead."
                << std::endl;
      password = argv[1];
    } else if (interactive) {
      auto first = prompt_password(input, "New Web UI password: ");
      auto second = first ? prompt_password(input, "Confirm password: ") : std::nullopt;
      if (!first || !second) {
        std::cerr << "Error: no password entered." << std::endl;
        return 1;
      }
      if (*first != *second) {
        std::cerr << "Error: the passwords do not match." << std::endl;
        return 1;
      }
      password = std::move(*first);
    } else {
      auto line = read_password_line(input);
      if (!line) {
        std::cerr << "Error: no password on standard input." << std::endl;
        return 1;
      }
      password = std::move(*line);
    }

    if (password.empty()) {
      std::cerr << "Error: the password must not be empty." << std::endl;
      return 1;
    }

    const auto result = http::save_user_creds(config::sunshine.credentials_file, username, password);
    std::fill(password.begin(), password.end(), '\0');
    if (result != 0) {
      std::cerr << "Error: could not save the credentials to " << config::sunshine.credentials_file << std::endl;
      return 1;
    }
    std::cerr << "Web UI credentials saved to " << config::sunshine.credentials_file << std::endl;
    return 0;
  }

  int creds(const char *name, int argc, char *argv[]) {
    return creds(name, argc, argv, std::cin, stdin_is_terminal());
  }

  int help(const char *name) {
    logging::print_help(name);
    return 0;
  }

  int version() {
    // version was already logged at startup
    return 0;
  }

#ifdef _WIN32
  int restore_nvprefs_undo() {
    if (nvprefs_instance.load()) {
      nvprefs_instance.restore_from_and_delete_undo_file_if_exists();
      nvprefs_instance.unload();
    }
    return 0;
  }
#endif
}  // namespace args

namespace lifetime {
  char **argv;  ///< Command-line argument vector.
  std::atomic_int desired_exit_code;  ///< Desired exit code.

  void exit_sunshine(int exit_code, bool async) {
    // Store the exit code of the first exit_sunshine() call
    int zero = 0;
    desired_exit_code.compare_exchange_strong(zero, exit_code);

    // Raise SIGINT to start termination
    std::raise(SIGINT);

    // Termination will happen asynchronously, but the caller may
    // have wanted synchronous behavior.
    while (!async) {
      std::this_thread::sleep_for(1s);
    }
  }

  void debug_trap() {
#ifdef _WIN32
    DebugBreak();
#else
    std::raise(SIGTRAP);
#endif
  }

  char **get_argv() {
    return argv;
  }
}  // namespace lifetime

void log_publisher_data() {
  BOOST_LOG(info) << "Package Publisher: "sv << SUNSHINE_PUBLISHER_NAME;
  BOOST_LOG(info) << "Publisher Website: "sv << SUNSHINE_PUBLISHER_WEBSITE;
  BOOST_LOG(info) << "Get support: "sv << SUNSHINE_PUBLISHER_ISSUE_URL;
}

#ifdef _WIN32
bool is_gamestream_enabled() {
  DWORD enabled;
  DWORD size = sizeof(enabled);
  return RegGetValueW(
           HKEY_LOCAL_MACHINE,
           L"SOFTWARE\\NVIDIA Corporation\\NvStream",
           L"EnableStreaming",
           RRF_RT_REG_DWORD,
           nullptr,
           &enabled,
           &size
         ) == ERROR_SUCCESS &&
         enabled != 0;
}

namespace service_ctrl {
  /**
   * @brief Owns Windows service-manager handles for the Sunshine service.
   */
  class service_controller {
  public:
    /**
     * @brief Explicitly open the Windows service manager and Sunshine service handle.
     *
     * @param service_desired_access SERVICE_* desired access flags.
     */
    explicit service_controller(DWORD service_desired_access) {
      scm_handle = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
      if (!scm_handle) {
        auto winerr = GetLastError();
        BOOST_LOG(error) << "OpenSCManager() failed: "sv << winerr;
        return;
      }

      service_handle = OpenServiceA(scm_handle, "SunshineService", service_desired_access);
      if (!service_handle) {
        auto winerr = GetLastError();
        BOOST_LOG(error) << "OpenService() failed: "sv << winerr;
        return;
      }
    }

    ~service_controller() {
      if (service_handle) {
        CloseServiceHandle(service_handle);
      }

      if (scm_handle) {
        CloseServiceHandle(scm_handle);
      }
    }

    /**
     * @brief Asynchronously starts the Sunshine service.
     *
     * @return True when the Windows service API call succeeds.
     */
    bool start_service() {
      if (!service_handle) {
        return false;
      }

      if (!StartServiceA(service_handle, 0, nullptr)) {
        auto winerr = GetLastError();
        if (winerr != ERROR_SERVICE_ALREADY_RUNNING) {
          BOOST_LOG(error) << "StartService() failed: "sv << winerr;
          return false;
        }
      }

      return true;
    }

    /**
     * @brief Query the service status.
     * @param status The SERVICE_STATUS struct to populate.
     *
     * @return True when the Windows service API call succeeds.
     */
    bool query_service_status(SERVICE_STATUS &status) {
      if (!service_handle) {
        return false;
      }

      if (!QueryServiceStatus(service_handle, &status)) {
        auto winerr = GetLastError();
        BOOST_LOG(error) << "QueryServiceStatus() failed: "sv << winerr;
        return false;
      }

      return true;
    }

  private:
    SC_HANDLE scm_handle = nullptr;
    SC_HANDLE service_handle = nullptr;
  };

  bool is_service_running() {
    service_controller sc {SERVICE_QUERY_STATUS};

    SERVICE_STATUS status;
    if (!sc.query_service_status(status)) {
      return false;
    }

    return status.dwCurrentState == SERVICE_RUNNING;
  }

  bool start_service() {
    service_controller sc {SERVICE_QUERY_STATUS | SERVICE_START};

    std::cout << "Starting Sunshine..."sv;

    // This operation is asynchronous, so we must wait for it to complete
    if (!sc.start_service()) {
      return false;
    }

    SERVICE_STATUS status;
    do {
      Sleep(1000);
      std::cout << '.';
    } while (sc.query_service_status(status) && status.dwCurrentState == SERVICE_START_PENDING);

    if (status.dwCurrentState != SERVICE_RUNNING) {
      BOOST_LOG(error) << std::format("{} failed to start: {}"sv, platf::SERVICE_NAME, status.dwWin32ExitCode);
      return false;
    }

    std::cout << std::endl;
    return true;
  }

  bool wait_for_ui_ready() {
    std::cout << "Waiting for Web UI to be ready...";

    // Wait up to 30 seconds for the web UI to start
    for (int i = 0; i < 30; i++) {
      PMIB_TCPTABLE tcp_table = nullptr;
      ULONG table_size = 0;
      ULONG err;

      auto fg = util::fail_guard([&tcp_table]() {
        free(tcp_table);
      });

      do {
        // Query all open TCP sockets to look for our web UI port
        err = GetTcpTable(tcp_table, &table_size, false);
        if (err == ERROR_INSUFFICIENT_BUFFER) {
          free(tcp_table);
          tcp_table = (PMIB_TCPTABLE) malloc(table_size);
        }
      } while (err == ERROR_INSUFFICIENT_BUFFER);

      if (err != NO_ERROR) {
        BOOST_LOG(error) << "Failed to query TCP table: "sv << err;
        return false;
      }

      uint16_t port_nbo = htons(net::map_port(confighttp::PORT_HTTPS));
      for (DWORD entry_index = 0; entry_index < tcp_table->dwNumEntries; entry_index++) {
        auto &entry = tcp_table->table[entry_index];

        // Look for our port in the listening state
        if (entry.dwLocalPort == port_nbo && entry.dwState == MIB_TCP_STATE_LISTEN) {
          std::cout << std::endl;
          return true;
        }
      }

      Sleep(1000);
      std::cout << '.';
    }

    std::cout << "timed out"sv << std::endl;
    return false;
  }
}  // namespace service_ctrl
#endif
