/**
 * @file entry_handler.h
 * @brief Declarations for entry handling functions.
 */
#pragma once

// standard includes
#include <atomic>
#include <functional>
#include <istream>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

// local includes
#include "thread_pool.h"
#include "thread_safe.h"

namespace platf {
  class deinit_t;
}  // namespace platf

/**
 * @brief Build the URL used to launch the Web UI.
 * @param path Optional path to append to the base URL.
 * @return HTTPS URL using the configured bind address and Web UI port.
 * @examples
 * get_launch_ui_url();
 * get_launch_ui_url("/pin");
 * @examples_end
 */
std::string get_launch_ui_url(const std::optional<std::string> &path = std::nullopt);

/**
 * @brief Launch the Web UI.
 * @param path Optional path to append to the base URL.
 */
void launch_ui(const std::optional<std::string> &path = std::nullopt);

/**
 * @brief Start mDNS service advertising only when it is enabled.
 * @param enabled Whether the `mdns_advertise` option is enabled.
 * @param start_publisher Function that starts the platform mDNS publisher.
 * @return Publisher lifetime guard, or `nullptr` when advertising is disabled or failed to start.
 */
std::unique_ptr<platf::deinit_t> start_mdns_publisher(bool enabled, const std::function<std::unique_ptr<platf::deinit_t>()> &start_publisher);

/**
 * @brief Start the platform mDNS publisher only when it is enabled.
 * @param enabled Whether the `mdns_advertise` option is enabled.
 * @return Publisher lifetime guard, or `nullptr` when advertising is disabled or failed to start.
 */
std::unique_ptr<platf::deinit_t> start_mdns_publisher(bool enabled);

/**
 * @brief Functions for handling command line arguments.
 */
namespace args {
  /**
   * @brief Reset the user credentials.
   * @details When the password argument is omitted, it is read from the terminal without echo
   *          (and confirmed), or from the first line of standard input when it is not a terminal.
   * @param name The name of the program.
   * @param argc The number of arguments.
   * @param argv The arguments.
   * @examples
   * creds("sunshine", 1, {"new_username"});
   * creds("sunshine", 2, {"new_username", "new_password"});
   * @examples_end
   *
   * @return Process exit code from updating the stored credentials (0 on success).
   */
  int creds(const char *name, int argc, char *argv[]);

  /**
   * @brief Reset the user credentials, reading an omitted password from the given stream.
   * @param name The name of the program.
   * @param argc The number of arguments.
   * @param argv The arguments.
   * @param input Stream the password is read from when it is not passed as an argument.
   * @param interactive Whether `input` is a terminal: prompt, disable echo and ask for confirmation.
   * @return Process exit code from updating the stored credentials (0 on success).
   */
  int creds(const char *name, int argc, char *argv[], std::istream &input, bool interactive);

  /**
   * @brief Read one password line from a stream.
   * @param input Stream to read from.
   * @return The line without its trailing line ending, or no value at end of input.
   */
  std::optional<std::string> read_password_line(std::istream &input);

  /**
   * @brief Print help to stdout, then exit.
   * @param name The name of the program.
   * @examples
   * help("sunshine");
   * @examples_end
   *
   * @return Process exit code after printing command usage.
   */
  int help(const char *name);

  /**
   * @brief Print the version to stdout, then exit.
   * @examples
   * version();
   * @examples_end
   *
   * @return Process exit code after printing the Sunshine version.
   */
  int version();

#ifdef _WIN32
  /**
   * @brief Restore global NVIDIA control panel settings.
   * If Sunshine was improperly terminated, this function restores
   * the global NVIDIA control panel settings to the undo file left
   * by Sunshine. This function is typically called by the uninstaller.
   * @examples
   * restore_nvprefs_undo();
   * @examples_end
   *
   * @return Process exit code from restoring NVIDIA profile preferences.
   */
  int restore_nvprefs_undo();
#endif
}  // namespace args

/**
 * @brief Functions for handling the lifetime of Sunshine.
 */
namespace lifetime {
  extern char **argv;
  extern std::atomic_int desired_exit_code;

  /**
   * @brief Terminates Sunshine gracefully with the provided exit code.
   * @param exit_code The exit code to return from main().
   * @param async Specifies whether our termination will be non-blocking.
   */
  void exit_sunshine(int exit_code, bool async);

  /**
   * @brief Breaks into the debugger or terminates Sunshine if no debugger is attached.
   */
  void debug_trap();

  /**
   * @brief Get the argv array passed to main().
   *
   * @return Original argument vector captured from main().
   */
  char **get_argv();
}  // namespace lifetime

/**
 * @brief Log the publisher metadata provided from CMake.
 */
void log_publisher_data();

#ifdef _WIN32
/**
 * @brief Check if NVIDIA's GameStream software is running.
 * @return `true` if GameStream is enabled, `false` otherwise.
 */
bool is_gamestream_enabled();

/**
 * @brief Namespace for controlling the Sunshine service model on Windows.
 */
namespace service_ctrl {
  /**
   * @brief Check if the service is running.
   * @examples
   * is_service_running();
   * @examples_end
   *
   * @return True when the requested service or UI readiness condition is satisfied.
   */
  bool is_service_running();

  /**
   * @brief Start the service and wait for startup to complete.
   * @examples
   * start_service();
   * @examples_end
   *
   * @return True when the requested service or UI readiness condition is satisfied.
   */
  bool start_service();

  /**
   * @brief Wait for the UI to be ready after Sunshine startup.
   * @examples
   * wait_for_ui_ready();
   * @examples_end
   *
   * @return True when the requested service or UI readiness condition is satisfied.
   */
  bool wait_for_ui_ready();
}  // namespace service_ctrl
#endif
