/**
 * @file src/httpcommon.cpp
 * @brief Definitions for common HTTP.
 */
#define BOOST_BIND_GLOBAL_PLACEHOLDERS

// standard includes
#include <atomic>
#include <cerrno>
#include <charconv>
#include <filesystem>
#include <fstream>
#include <utility>

#ifndef _WIN32
  #include <fcntl.h>
  #include <sys/stat.h>
  #include <unistd.h>
#endif

// lib includes
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>
#include <Simple-Web-Server/server_http.hpp>
#include <Simple-Web-Server/server_https.hpp>
#include <vector>

// local includes
#include "config.h"
#include "crypto.h"
#include "file_handler.h"
#include "httpcommon.h"
#include "logging.h"
#include "network.h"
#include "nvhttp.h"
#include "platform/common.h"
#include "process.h"
#include "rtsp.h"
#include "utility.h"
#include "uuid.h"
#include "webui_auth.h"

namespace http {
  using namespace std::literals;
  namespace fs = std::filesystem;
  namespace pt = boost::property_tree;

  int reload_user_creds(const std::string &file);
  /**
   * @brief Check whether the Web UI credentials file exists and is readable.
   *
   * @param file Path to the credentials file.
   * @return True when the credentials file is present.
   */
  bool user_creds_exist(const std::string &file);

  std::string unique_id;  ///< Unique ID.
  net::net_e origin_web_ui_allowed;  ///< Origin web ui allowed.

  /**
   * @brief Load persisted HTTP credentials and initialize shared request state.
   */
  int init() {
    bool clean_slate = config::sunshine.flags[config::flag::FRESH_STATE];
    origin_web_ui_allowed = net::from_enum_string(config::nvhttp.origin_web_ui_allowed);

    if (clean_slate) {
      unique_id = uuid_util::uuid_t::generate().string();
      auto dir = std::filesystem::temp_directory_path() / "Sunshine"sv;
      config::nvhttp.cert = (dir / ("cert-"s + unique_id)).string();
      config::nvhttp.pkey = (dir / ("pkey-"s + unique_id)).string();
    }

    if (require_user_creds(config::sunshine.credentials_file)) {
      return -1;
    }
    if ((!fs::exists(config::nvhttp.pkey) || !fs::exists(config::nvhttp.cert)) && create_creds(config::nvhttp.pkey, config::nvhttp.cert)) {
      return -1;
    }
    return 0;
  }

  int require_user_creds(const std::string &file) {
    if (user_creds_exist(file) && reload_user_creds(file) == 0 && !config::sunshine.username.empty() && !config::sunshine.password.empty()) {
      return 0;
    }

    BOOST_LOG(fatal) << "No Web UI credentials are configured in ["sv << file << "]. Sunshine will not start without them."sv;
    BOOST_LOG(fatal) << "Create them first by running: sunshine --creds <username>  (the password is prompted for)"sv;
    return -1;
  }

  /**
   * @brief Save user creds.
   *
   * @param file Credentials file path.
   * @param username Username to save.
   * @param password Password to save.
   * @param run_our_mouth Whether to log user-facing status messages.
   * @return 0 on success, non-zero on failure.
   */
  int save_user_creds(const std::string &file, const std::string &username, const std::string &password, bool run_our_mouth) {
    pt::ptree outputTree;

    if (fs::exists(file)) {
      try {
        pt::read_json(file, outputTree);
      } catch (std::exception &e) {
        BOOST_LOG(error) << "Couldn't read user credentials: "sv << e.what();
        return -1;
      }
    }

    // The PBKDF2 hash carries its own salt and iteration count; the legacy salt field is kept
    // (empty) so the file keeps the layout older code and tools expect.
    outputTree.put("username", username);
    outputTree.put("salt", "");
    try {
      outputTree.put("password", webui_auth::hash_password(password));

      // The file holds the password hash: make it private to the user running Sunshine before the
      // hash is written (writing truncates the file and keeps its permissions).
      {
        std::ofstream touch {file, std::ios::app};
      }
      std::error_code permissions_error;
      fs::permissions(file, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::replace, permissions_error);
      if (permissions_error) {
        BOOST_LOG(warning) << "Couldn't restrict permissions of ["sv << file << "]: "sv << permissions_error.message();
      }

      pt::write_json(file, outputTree);
    } catch (std::exception &e) {
      BOOST_LOG(error) << "error writing to the credentials file, perhaps try this again as an administrator? Details: "sv << e.what();
      return -1;
    }
    webui_auth::clear_verification_cache();

    BOOST_LOG(info) << "New credentials have been created"sv;
    return 0;
  }

  /**
   * @brief Check whether the Web UI credentials file exists and is readable.
   */
  bool user_creds_exist(const std::string &file) {
    if (!fs::exists(file)) {
      return false;
    }

    pt::ptree inputTree;
    try {
      pt::read_json(file, inputTree);
      return inputTree.find("username") != inputTree.not_found() &&
             inputTree.find("password") != inputTree.not_found() &&
             inputTree.find("salt") != inputTree.not_found();
    } catch (std::exception &e) {
      BOOST_LOG(error) << "validating user credentials: "sv << e.what();
    }

    return false;
  }

  /**
   * @brief Reload the Web UI credentials from disk.
   */
  int reload_user_creds(const std::string &file) {
    pt::ptree inputTree;
    try {
      pt::read_json(file, inputTree);
      config::sunshine.username = inputTree.get<std::string>("username");
      config::sunshine.password = inputTree.get<std::string>("password");
      config::sunshine.salt = inputTree.get<std::string>("salt");
    } catch (std::exception &e) {
      BOOST_LOG(error) << "loading user credentials: "sv << e.what();
      return -1;
    }
    return 0;
  }

  /**
   * @brief Shared atomic connection counter for @ref connection_limiter_t.
   */
  struct connection_limiter_t::state_t {
    /**
     * @brief RAII slot lease decrementing @ref state_t on destruction.
     */
    struct lease_t {
      /**
       * @brief Acquire ownership of one counted connection slot.
       *
       * @param owner Shared counter state.
       */
      explicit lease_t(std::shared_ptr<state_t> owner):
          state(std::move(owner)) {}

      std::shared_ptr<state_t> state;  ///< Accounting owner.

      ~lease_t() {
        if (state) {
          state->active.fetch_sub(1, std::memory_order_relaxed);
        }
      }
    };

    /**
     * @brief Construct counter state with a maximum connection limit.
     *
     * @param max_connections Maximum concurrent leases.
     */
    explicit state_t(const std::size_t max_connections):
        limit(max_connections) {}

    std::atomic<std::size_t> active {0};  ///< Currently leased connection count.
    std::size_t limit = 0;  ///< Maximum concurrent leases.
  };

  namespace {

#ifndef _WIN32
    /**
     * @brief Create or truncate a file with owner-only (`0600`) permissions before writing bytes.
     *
     * @param path Destination path.
     * @param content Contents to write.
     * @return `0` on success, `-1` on failure.
     */
    int write_private_file(const std::string &path, const std::string_view content) {
      const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, S_IRUSR | S_IWUSR);
      if (fd < 0) {
        return -1;
      }

      if (::fchmod(fd, S_IRUSR | S_IWUSR) != 0) {
        ::close(fd);
        return -1;
      }

      const char *data = content.data();
      std::size_t remaining = content.size();
      while (remaining > 0) {
        const auto written = ::write(fd, data, remaining);
        if (written < 0) {
          if (errno == EINTR) {
            continue;
          }
          ::close(fd);
          return -1;
        }
        data += written;
        remaining -= static_cast<std::size_t>(written);
      }

      return ::close(fd) == 0 ? 0 : -1;
    }
#endif
  }  // namespace

  connection_limiter_t::connection_limiter_t(const std::size_t max_connections):
      state_(std::make_shared<state_t>(max_connections)) {}

  std::shared_ptr<void> connection_limiter_t::try_acquire() {
    auto current = state_->active.load(std::memory_order_relaxed);
    while (current < state_->limit) {
      if (state_->active.compare_exchange_weak(current, current + 1, std::memory_order_acq_rel, std::memory_order_relaxed)) {
        return std::make_shared<state_t::lease_t>(state_);
      }
    }
    return {};
  }

  bool has_canonical_header_lines(std::string_view raw) {
    return sds_http_has_canonical_header_lines(
      reinterpret_cast<const std::uint8_t *>(raw.data()),
      raw.size()
    );
  }

  bool validate_request_framing(
    const std::string_view raw_header,
    const SimpleWeb::CaseInsensitiveMultimap &header,
    const std::size_t max_body_size,
    std::size_t *content_length
  ) {
    std::vector<SdsHttpHeaderRef> header_refs;
    header_refs.reserve(header.size());
    for (const auto &entry : header) {
      header_refs.push_back(SdsHttpHeaderRef {
        reinterpret_cast<const std::uint8_t *>(entry.first.data()),
        entry.first.size(),
        reinterpret_cast<const std::uint8_t *>(entry.second.data()),
        entry.second.size(),
      });
    }
    return sds_http_validate_request_framing(
      reinterpret_cast<const std::uint8_t *>(raw_header.data()),
      raw_header.size(),
      header_refs.empty() ? nullptr : header_refs.data(),
      header_refs.size(),
      max_body_size,
      content_length
    );
  }

  /**
   * @brief Generate HTTPS credential files from the provided key and certificate paths.
   */
  int create_creds(const std::string &pkey, const std::string &cert) {
    fs::path pkey_path = pkey;
    fs::path cert_path = cert;

    auto creds = crypto::gen_creds("Sunshine Gamestream Host"sv, 2048);

    auto pkey_dir = pkey_path;
    auto cert_dir = cert_path;
    pkey_dir.remove_filename();
    cert_dir.remove_filename();

    std::error_code err_code {};
    if (!pkey_dir.empty()) {
      fs::create_directories(pkey_dir, err_code);
      if (err_code) {
        BOOST_LOG(error) << "Couldn't create directory ["sv << pkey_dir << "] :"sv << err_code.message();
        return -1;
      }
    }

    if (!cert_dir.empty()) {
      fs::create_directories(cert_dir, err_code);
      if (err_code) {
        BOOST_LOG(error) << "Couldn't create directory ["sv << cert_dir << "] :"sv << err_code.message();
        return -1;
      }
    }

#ifdef _WIN32
    if (file_handler::write_file(pkey.c_str(), creds.pkey)) {
      BOOST_LOG(error) << "Couldn't open ["sv << config::nvhttp.pkey << ']';
      return -1;
    }
#else
    if (write_private_file(pkey, creds.pkey) != 0) {
      BOOST_LOG(error) << "Couldn't open ["sv << pkey << ']';
      return -1;
    }
#endif

    if (file_handler::write_file(cert.c_str(), creds.x509)) {
      BOOST_LOG(error) << "Couldn't open ["sv << config::nvhttp.cert << ']';
      return -1;
    }

    fs::permissions(pkey_path, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::replace, err_code);

    if (err_code) {
      BOOST_LOG(error) << "Couldn't change permissions of ["sv << config::nvhttp.pkey << "] :"sv << err_code.message();
      return -1;
    }

    fs::permissions(cert_path, fs::perms::owner_read | fs::perms::group_read | fs::perms::others_read | fs::perms::owner_write, fs::perm_options::replace, err_code);

    if (err_code) {
      BOOST_LOG(error) << "Couldn't change permissions of ["sv << config::nvhttp.cert << "] :"sv << err_code.message();
      return -1;
    }

    return 0;
  }
}  // namespace http
