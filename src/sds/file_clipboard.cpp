/** @file src/sds/file_clipboard.cpp
 *  @brief The bounded native file clipboard bundle and Linux source/destination policy.
 */
#include "file_clipboard.h"

#include <algorithm>
#include <array>
#include <utility>

#include <openssl/rand.h>

#ifdef __linux__
  #include <cerrno>
  #include <cstdlib>
  #include <fcntl.h>
  #include <filesystem>
  #include <limits>
  #include <set>
  #include <sys/stat.h>
  #include <sys/statvfs.h>
  #include <type_traits>
  #include <unistd.h>
  #include <vector>

  #include <glib.h>
  #include <openssl/evp.h>

  #include "files.h"
  #include "src/config.h"
#endif

namespace sds::file_clipboard {
  std::optional<std::string> new_epoch() {
    std::array<unsigned char, 16> bytes;
    if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1) {
      return std::nullopt;
    }
    std::string hex;
    for (auto byte : bytes) {
      hex += "0123456789abcdef"[byte >> 4];
      hex += "0123456789abcdef"[byte & 15];
    }
    return hex;
  }

#ifdef __linux__
  namespace {
    constexpr std::string_view stage_prefix = "sds-file-clipboard-";
    constexpr std::uint64_t stage_headroom_bytes = 64ull * 1024 * 1024;

    bool forbidden_component(std::string_view prev_part, std::string_view part) {
      if (part.empty() || part == "." || part == ".." || part.starts_with(stage_prefix)) {
        return true;
      }
      if (part == ".ssh" || part == ".gnupg" ||
          part == "sds-minipc-sunshine" || part == "sds-pc2-sunshine" ||
          part == "sds-minipc-display" ||
          (part.starts_with("sds-") && part.ends_with("-sunshine"))) {
        return true;
      }
      if (prev_part == ".config" && part == "sunshine") {
        return true;
      }
      return false;
    }

    bool path_is_or_under(std::string_view candidate, const std::filesystem::path &blocked) {
      if (blocked.empty() || !blocked.is_absolute()) {
        return false;
      }
      auto norm = blocked.lexically_normal().string();
      while (norm.size() > 1 && norm.back() == '/') {
        norm.pop_back();
      }
      if (norm == "/") {
        return false;
      }
      return candidate == norm || (candidate.size() > norm.size() && candidate.starts_with(norm) && candidate[norm.size()] == '/');
    }

    bool sensitive_sunshine_dir_name(const std::filesystem::path &dir) {
      const auto name = dir.filename().string();
      return name == "credentials" || name == "sunshine" || (name.starts_with("sds-") && name.ends_with("-sunshine"));
    }

    bool forbidden_sunshine_path(std::string_view absolute_path) {
      const auto norm_candidate = std::filesystem::path(absolute_path).lexically_normal().string();
      auto check_env_sub = [&](const char *var, std::string_view sub) {
        const auto *val = std::getenv(var);
        if (!val || *val != '/') {
          return false;
        }
        return path_is_or_under(norm_candidate, std::filesystem::path(val) / sub);
      };
      if (check_env_sub("CONFIGURATION_DIRECTORY", "sunshine") ||
          check_env_sub("XDG_CONFIG_HOME", "sunshine") ||
          check_env_sub("HOME", ".config/sunshine")) {
        return true;
      }

      std::vector<std::filesystem::path> bases;
      if (const auto *cfg_dir = std::getenv("CONFIGURATION_DIRECTORY"); cfg_dir && *cfg_dir == '/') {
        bases.push_back(std::filesystem::path(cfg_dir) / "sunshine");
      }
      if (const auto *xdg_cfg = std::getenv("XDG_CONFIG_HOME"); xdg_cfg && *xdg_cfg == '/') {
        bases.push_back(std::filesystem::path(xdg_cfg) / "sunshine");
      }
      if (const auto *home = std::getenv("HOME"); home && *home == '/') {
        bases.push_back(std::filesystem::path(home) / ".config" / "sunshine");
      }
      if (!config::sunshine.config_file.empty()) {
        const std::filesystem::path cfg_path {config::sunshine.config_file};
        if (cfg_path.is_absolute() && cfg_path.has_parent_path()) {
          bases.push_back(cfg_path.parent_path());
        }
      }
      std::error_code ec;
      if (const auto cwd = std::filesystem::current_path(ec); !ec && cwd.is_absolute()) {
        bases.push_back(cwd);
      }

      for (const auto *raw : {
             &config::nvhttp.file_state,
             &config::sunshine.credentials_file,
             &config::nvhttp.pkey,
             &config::nvhttp.cert,
             &config::sunshine.config_file,
           }) {
        if (raw->empty()) {
          continue;
        }
        const std::filesystem::path configured {*raw};
        if (configured.is_absolute()) {
          if (path_is_or_under(norm_candidate, configured)) {
            return true;
          }
          if (configured.has_parent_path() && sensitive_sunshine_dir_name(configured.parent_path()) &&
              path_is_or_under(norm_candidate, configured.parent_path())) {
            return true;
          }
        } else {
          for (const auto &base : bases) {
            const auto resolved = base / configured;
            if (path_is_or_under(norm_candidate, resolved)) {
              return true;
            }
            if (configured.has_parent_path() && resolved.has_parent_path() &&
                sensitive_sunshine_dir_name(resolved.parent_path()) &&
                path_is_or_under(norm_candidate, resolved.parent_path())) {
              return true;
            }
          }
        }
      }
      return false;
    }

    std::optional<std::uint64_t> available_space(int dir_fd) {
      struct statvfs vfs {};
      if (fstatvfs(dir_fd, &vfs) != 0 || vfs.f_frsize == 0) {
        return std::nullopt;
      }
      if constexpr (std::is_signed_v<decltype(vfs.f_bavail)>) {
        if (vfs.f_bavail < 0) {
          return 0;
        }
      }
      const auto bavail = static_cast<std::uint64_t>(vfs.f_bavail);
      const auto frsize = static_cast<std::uint64_t>(vfs.f_frsize);
      if (bavail > std::numeric_limits<std::uint64_t>::max() / frsize) {
        return std::numeric_limits<std::uint64_t>::max();
      }
      return bavail * frsize;
    }

    class fd_t {
    public:
      explicit fd_t(int n = -1): n_ {n} {}
      ~fd_t() { if (n_ >= 0) close(n_); }
      fd_t(const fd_t &) = delete;
      fd_t &operator=(const fd_t &) = delete;
      fd_t(fd_t &&other) noexcept: n_ {std::exchange(other.n_, -1)} {}
      fd_t &operator=(fd_t &&other) noexcept {
        std::swap(n_, other.n_);
        return *this;
      }
      [[nodiscard]] int get() const { return n_; }
      explicit operator bool() const { return n_ >= 0; }

    private:
      int n_;
    };

    std::string runtime_path() {
      return "/run/user/" + std::to_string(geteuid());
    }

    bool private_node(int fd, bool directory) {
      struct stat st {};
      return fd >= 0 && fstat(fd, &st) == 0 &&
             (directory ? S_ISDIR(st.st_mode) : S_ISREG(st.st_mode) && st.st_size > 0) &&
             st.st_uid == geteuid() && !(st.st_mode & 0077);
    }

    fd_t secure_runtime() {
      const auto *env = std::getenv("XDG_RUNTIME_DIR");
      const auto path = runtime_path();
      if (!geteuid() || !env || env != path) {
        return fd_t {};
      }
      // Every ancestor of this fixed path is system-controlled. Reject runtime symlinks.
      fd_t runtime {open(path.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)};
      return private_node(runtime.get(), true) ? std::move(runtime) : fd_t {};
    }

    bool safe_name(std::string_view name) {
      if (name.empty() || name.size() > 200) {
        return false;
      }
      const auto safe = files::sanitize_file_name(name);
      return safe && *safe == name;
    }

    std::string name_key(const std::string &name) {
      const std::unique_ptr<gchar, decltype(&g_free)> folded {g_utf8_casefold(name.c_str(), name.size()), &g_free};
      const std::unique_ptr<gchar, decltype(&g_free)> normalized {g_utf8_normalize(folded.get(), -1, G_NORMALIZE_NFC), &g_free};
      return normalized ? normalized.get() : name;
    }

    int hex_value(char c) {
      if (c >= '0' && c <= '9') return c - '0';
      if (c >= 'A' && c <= 'F') return c - 'A' + 10;
      if (c >= 'a' && c <= 'f') return c - 'a' + 10;
      return -1;
    }

    std::optional<std::string> uri_path(std::string_view uri) {
      if (!uri.starts_with("file:///") || uri.size() > 4096) {
        return std::nullopt;
      }
      uri.remove_prefix(7);
      std::string path;
      for (std::size_t i = 0; i < uri.size(); ++i) {
        char c = uri[i];
        if (c == '%') {
          if (i + 2 >= uri.size()) return std::nullopt;
          const int hi = hex_value(uri[i + 1]), lo = hex_value(uri[i + 2]);
          if (hi < 0 || lo < 0) return std::nullopt;
          c = static_cast<char>(hi * 16 + lo);
          i += 2;
          if (c == '/' || c == '\0') return std::nullopt;
        } else if (static_cast<unsigned char>(c) <= 0x20 || c == '#' || c == '?') {
          return std::nullopt;
        }
        path.push_back(c);
      }
      return path;
    }

    std::string file_uri(std::string_view path) {
      std::string uri = "file://";
      for (const unsigned char c : path) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '/' || c == '.' || c == '_' || c == '-' || c == '~') {
          uri += static_cast<char>(c);
        } else {
          uri += '%';
          uri += "0123456789ABCDEF"[c >> 4];
          uri += "0123456789ABCDEF"[c & 15];
        }
      }
      return uri;
    }

    fd_t source_file(std::string_view absolute_path, std::string &name) {
      if (absolute_path.empty() || absolute_path.front() != '/' || forbidden_sunshine_path(absolute_path)) {
        return fd_t {};
      }
      fd_t directory {open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)};
      auto remaining = absolute_path.substr(1);
      std::string prev_part;
      while (directory) {
        const auto end = remaining.find('/');
        const std::string part {remaining.substr(0, end)};
        if (forbidden_component(prev_part, part)) {
          return fd_t {};
        }
        if (end == std::string_view::npos) {
          name = part;
          struct stat initial {};
          // Reject device/FIFO arguments before attempting an open; O_PATH allows checking
          // the exact inode without opening a device even if a local rename wins the race.
          fd_t pin {openat(directory.get(), name.c_str(), O_PATH | O_NOFOLLOW | O_CLOEXEC)};
          if (!pin || fstat(pin.get(), &initial) != 0 || !S_ISREG(initial.st_mode) || initial.st_uid != geteuid()) {
            return fd_t {};
          }
          const auto proc = "/proc/self/fd/" + std::to_string(pin.get());
          fd_t readable {open(proc.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC)};
          struct stat check {};
          if (!readable || fstat(readable.get(), &check) != 0 || initial.st_ino != check.st_ino || initial.st_dev != check.st_dev) {
            return fd_t {};
          }
          return readable;
        }
        directory = fd_t {openat(directory.get(), part.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)};
        prev_part = part;
        remaining.remove_prefix(end + 1);
      }
      return fd_t {};
    }

    std::string encode(const std::vector<unsigned char> &bytes) {
      if (bytes.empty()) return {};
      std::string out(4 * ((bytes.size() + 2) / 3) + 1, '\0');
      const auto n = EVP_EncodeBlock(reinterpret_cast<unsigned char *>(out.data()), bytes.data(), static_cast<int>(bytes.size()));
      out.resize(static_cast<std::size_t>(n));
      return out;
    }

    std::optional<std::vector<unsigned char>> decode(const std::string &data, std::size_t remaining) {
      if (data.empty()) return std::vector<unsigned char> {};
      if (data.size() % 4 || data.size() > 4 * ((remaining + 2) / 3)) return std::nullopt;
      const auto padding = data.ends_with("==") ? 2 : data.ends_with("=") ? 1 : 0;
      const auto decoded_size = data.size() / 4 * 3 - padding;
      if (decoded_size > remaining) return std::nullopt;
      std::vector<unsigned char> bytes(data.size() / 4 * 3);
      const auto n = EVP_DecodeBlock(bytes.data(), reinterpret_cast<const unsigned char *>(data.data()), static_cast<int>(data.size()));
      if (n < 0 || static_cast<std::size_t>(n) != bytes.size()) return std::nullopt;
      bytes.resize(decoded_size);
      if (encode(bytes) != data) return std::nullopt;
      return bytes;
    }

    bool bounded_json_depth(std::string_view body) {
      int depth = 0;
      unsigned structure = 0;
      bool quoted = false, escaped = false;
      for (const char c : body) {
        if (quoted) {
          if (escaped) escaped = false;
          else if (c == '\\') escaped = true;
          else if (c == '"') quoted = false;
        } else if (c == '"') {
          quoted = true;
        } else if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
          continue;
        } else {
          // The schema has at most 16 flat file objects with two string values each.
          // Stop oversized token arrays before they can expand into a large JSON tree.
          if (++structure > 128) return false;
          if (c == '{' || c == '[') {
            if (++depth > 3) return false;
          } else if (c == '}' || c == ']') {
            if (--depth < 0) return false;
          } else if (c != ',' && c != ':') {
            return false;
          }
        }
      }
      return !quoted && depth == 0;
    }
  }  // namespace

  bool private_x11_enabled() {
    const auto *enabled = std::getenv("SDS_FILE_CLIPBOARD");
    const auto *target = std::getenv("SUNSHINE_PRIVATE_X11_INPUT");
    const auto *display = std::getenv("DISPLAY");
    const auto *auth = std::getenv("XAUTHORITY");
    if (!enabled || std::string_view {enabled} != "1" || !target || std::string_view {target} != ":97" ||
        !display || std::string_view {display} != ":97" || !auth || auth != runtime_path() + "/sds-minipc-display/Xauthority") {
      return false;
    }
    auto root = secure_runtime();
    fd_t directory {openat(root.get(), "sds-minipc-display", O_DIRECTORY | O_RDONLY | O_NOFOLLOW | O_CLOEXEC)};
    fd_t cookie {openat(directory.get(), "Xauthority", O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)};
    return private_node(directory.get(), true) && private_node(cookie.get(), false);
  }

  std::optional<nlohmann::json> read_offer(std::string_view offer, const std::function<bool()> &allowed) {
    if (offer.size() > offer_max || !offer.starts_with("copy\n")) return std::nullopt;
    offer.remove_prefix(5);
    auto entries = nlohmann::json::array();
    std::set<std::string> names;
    std::size_t remaining = bytes_max;
    while (!offer.empty()) {
      if (entries.size() >= file_max || !allowed()) return std::nullopt;
      const auto end = offer.find('\n');
      auto uri = offer.substr(0, end);
      if (uri.ends_with('\r')) uri.remove_suffix(1);
      auto path = uri_path(uri);
      if (!path) return std::nullopt;
      std::string name;
      auto file = source_file(*path, name);
      struct stat before {};
      if (!file || !safe_name(name) || !names.insert(name_key(name)).second || fstat(file.get(), &before) ||
          before.st_size < 0 || static_cast<std::uintmax_t>(before.st_size) > remaining) {
        return std::nullopt;
      }
      std::vector<unsigned char> data(static_cast<std::size_t>(before.st_size));
      std::size_t offset = 0;
      while (offset < data.size()) {
        if (!allowed()) return std::nullopt;
        const auto n = read(file.get(), data.data() + offset, std::min<std::size_t>(data.size() - offset, 64 * 1024));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return std::nullopt;
        offset += static_cast<std::size_t>(n);
      }
      struct stat after {};
      if (fstat(file.get(), &after) || before.st_size != after.st_size ||
          before.st_ctim.tv_sec != after.st_ctim.tv_sec || before.st_ctim.tv_nsec != after.st_ctim.tv_nsec ||
          before.st_mtim.tv_sec != after.st_mtim.tv_sec || before.st_mtim.tv_nsec != after.st_mtim.tv_nsec) {
        return std::nullopt;
      }
      remaining -= data.size();
      entries.push_back({{"name", std::move(name)}, {"data", encode(data)}});
      if (end == std::string_view::npos) break;
      offer.remove_prefix(end + 1);
    }
    if (entries.empty() || !allowed()) return std::nullopt;
    return nlohmann::json {{"files", std::move(entries)}};
  }

  class stage_t {
  public:
    explicit stage_t(fd_t root_fd, std::string name): root {std::move(root_fd)}, leaf {std::move(name)} {}
    ~stage_t() {
      if (root && !leaf.empty()) {
        for (const auto &name : files) unlinkat(directory.get(), name.c_str(), 0);
        unlinkat(root.get(), leaf.c_str(), AT_REMOVEDIR);
      }
    }
    fd_t root;
    std::string leaf;
    fd_t directory;
    std::vector<std::string> files;
    std::string offer = "copy";
  };

  std::shared_ptr<const stage_t> stage(std::string_view body, const std::function<bool()> &allowed) {
    if (!allowed() || body.size() > wire_max || !bounded_json_depth(body)) return {};
    bool duplicate = false;
    std::array<std::set<std::string>, 4> keys;
    const auto parse = [&duplicate, &keys](int depth, nlohmann::json::parse_event_t event, nlohmann::json &value) {
      if (event == nlohmann::json::parse_event_t::object_start) keys.at(static_cast<std::size_t>(depth + 1)).clear();
      if (event == nlohmann::json::parse_event_t::key && !keys.at(static_cast<std::size_t>(depth)).insert(value.get<std::string>()).second) duplicate = true;
      return true;
    };
    const auto parsed = nlohmann::json::parse(body, parse, false);
    if (duplicate || !parsed.is_object() || parsed.size() != 1 || !parsed.contains("files")) return {};
    const auto &entries = parsed.at("files");
    if (!entries.is_array() || entries.empty() || entries.size() > file_max) return {};
    auto root = secure_runtime();
    const auto token = new_epoch();
    if (!root || !token) return {};
    const auto free_space = available_space(root.get());
    if (!free_space || *free_space < stage_headroom_bytes) return {};
    std::uint64_t free_remaining = *free_space;
    const auto leaf = std::string {stage_prefix} + *token;
    if (mkdirat(root.get(), leaf.c_str(), 0700) != 0) return {};
    auto offer = std::make_shared<stage_t>(std::move(root), leaf);
    offer->directory = fd_t {openat(offer->root.get(), leaf.c_str(), O_DIRECTORY | O_RDONLY | O_NOFOLLOW | O_CLOEXEC)};
    if (!private_node(offer->directory.get(), true)) return {};
    std::size_t remaining = bytes_max;
    std::set<std::string> names;
    for (const auto &entry : entries) {
      if (!allowed() || !entry.is_object() || entry.size() != 2 || !entry.contains("name") || !entry.at("name").is_string() ||
          !entry.contains("data") || !entry.at("data").is_string()) return {};
      const auto &name = entry.at("name").get_ref<const std::string &>();
      if (!safe_name(name) || !names.insert(name_key(name)).second) return {};
      auto bytes = decode(entry.at("data").get_ref<const std::string &>(), remaining);
      if (!bytes) return {};
      if (free_remaining < stage_headroom_bytes || free_remaining - stage_headroom_bytes < bytes->size()) return {};
      free_remaining -= bytes->size();
      remaining -= bytes->size();
      fd_t fd {openat(offer->directory.get(), name.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600)};
      if (!fd) return {};
      offer->files.push_back(name);
      std::size_t offset = 0;
      while (offset < bytes->size()) {
        if (!allowed()) return {};
        const auto n = write(fd.get(), bytes->data() + offset, std::min<std::size_t>(bytes->size() - offset, 64 * 1024));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return {};
        offset += static_cast<std::size_t>(n);
      }
      offer->offer += '\n';
      offer->offer += file_uri(runtime_path() + '/' + leaf + '/' + name);
    }
    return allowed() ? offer : nullptr;
  }

  std::string_view native_offer(const stage_t &stage) {
    return stage.offer;
  }

  std::shared_ptr<const stage_t> make_test_stage(std::string offer) {
    auto out = std::make_shared<stage_t>(fd_t {}, std::string {});
    out->offer = std::move(offer);
    return out;
  }
#else
  class stage_t {
  public:
    std::string offer = "copy";
  };

  bool private_x11_enabled() { return false; }
  std::optional<nlohmann::json> read_offer(std::string_view, const std::function<bool()> &) { return {}; }
  std::shared_ptr<const stage_t> stage(std::string_view, const std::function<bool()> &) { return {}; }
  std::string_view native_offer(const stage_t &stage) { return stage.offer; }
  std::shared_ptr<const stage_t> make_test_stage(std::string offer) {
    auto out = std::make_shared<stage_t>();
    out->offer = std::move(offer);
    return out;
  }
#endif
}  // namespace sds::file_clipboard
