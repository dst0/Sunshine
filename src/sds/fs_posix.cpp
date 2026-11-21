/**
 * @file src/sds/fs_posix.cpp
 * @brief POSIX inbox/outbox primitives: openat/O_NOFOLLOW, owner checks, no-replace renames.
 */
// standard includes
#include <cerrno>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <utility>

// platform includes
#include <dirent.h>
#include <fcntl.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>
#ifdef __linux__
  #include <sys/syscall.h>
#endif
#ifdef __APPLE__
  #include <stdio.h>
#endif

// local includes
#include "fs.h"
#include "text.h"

#if defined(__linux__) && !defined(RENAME_NOREPLACE)
  #define RENAME_NOREPLACE (1 << 0)
#endif

namespace sds::fs {
  namespace {
    /**
     * @brief Error code from errno.
     *
     * @param value errno value.
     * @return Error code.
     */
    std::error_code from_errno(int value) {
      return {value, std::generic_category()};
    }

    /**
     * @brief Modification time of a stat result in nanoseconds.
     *
     * @param st Stat result.
     * @return Nanoseconds since the epoch.
     */
    std::int64_t mtime_ns(const struct stat &st) {
#ifdef __APPLE__
      return static_cast<std::int64_t>(st.st_mtimespec.tv_sec) * 1'000'000'000 + st.st_mtimespec.tv_nsec;
#else
      return static_cast<std::int64_t>(st.st_mtim.tv_sec) * 1'000'000'000 + st.st_mtim.tv_nsec;
#endif
    }

    /**
     * @brief Check that a name is a single, plain path component.
     *
     * @param name Candidate.
     * @return `true` when safe to pass to *at() calls.
     */
    bool plain_component(std::string_view name) {
      return !name.empty() && name != "." && name != ".." && name.find('/') == std::string_view::npos && name.find('\0') == std::string_view::npos;
    }

    /**
     * @brief Close a file descriptor, retrying on EINTR is not safe, so close once.
     *
     * @param fd Descriptor.
     */
    void close_fd(int fd) {
      if (fd >= 0) {
        ::close(fd);
      }
    }

    /**
     * @brief Open POSIX file.
     */
    class posix_file_t: public file_t {
    public:
      /**
       * @brief Take ownership of a descriptor.
       *
       * @param fd Open descriptor.
       */
      explicit posix_file_t(int fd):
          fd_(fd) {
      }

      ~posix_file_t() override {
        close_fd(fd_);
      }

      posix_file_t(const posix_file_t &) = delete;
      posix_file_t &operator=(const posix_file_t &) = delete;

      std::error_code write_at(std::uint64_t offset, std::span<const char> data) override {
        while (!data.empty()) {
          const auto written = ::pwrite(fd_, data.data(), data.size(), static_cast<off_t>(offset));
          if (written < 0) {
            if (errno == EINTR) {
              continue;
            }
            return from_errno(errno);
          }
          data = data.subspan(static_cast<std::size_t>(written));
          offset += static_cast<std::uint64_t>(written);
        }
        return {};
      }

      std::error_code read_at(std::uint64_t offset, std::span<char> buffer, std::size_t &read) override {
        read = 0;
        while (read < buffer.size()) {
          const auto got = ::pread(fd_, buffer.data() + read, buffer.size() - read, static_cast<off_t>(offset + read));
          if (got < 0) {
            if (errno == EINTR || errno == EAGAIN) {
              continue;
            }
            return from_errno(errno);
          }
          if (got == 0) {
            break;
          }
          read += static_cast<std::size_t>(got);
        }
        return {};
      }

      std::error_code truncate(std::uint64_t size) override {
        return ::ftruncate(fd_, static_cast<off_t>(size)) == 0 ? std::error_code {} : from_errno(errno);
      }

      std::error_code sync() override {
        return ::fsync(fd_) == 0 ? std::error_code {} : from_errno(errno);
      }

      std::error_code stat(entry_t &out) override {
        struct stat st {};
        if (::fstat(fd_, &st) != 0) {
          return from_errno(errno);
        }
        out.size = static_cast<std::uint64_t>(st.st_size);
        out.mtime_ns = mtime_ns(st);
        out.file_id = static_cast<std::uint64_t>(st.st_ino);
        out.device = static_cast<std::uint64_t>(st.st_dev);
        return {};
      }

      bool is_regular_non_executable() override {
        struct stat st {};
        return ::fstat(fd_, &st) == 0 && S_ISREG(st.st_mode) && (st.st_mode & 0111) == 0;
      }

    private:
      int fd_;  ///< Owned descriptor.
    };

    /**
     * @brief Directory opened with O_DIRECTORY|O_NOFOLLOW.
     */
    class posix_directory_t: public directory_t {
    public:
      /**
       * @brief Take ownership of a directory descriptor.
       *
       * @param fd Directory descriptor.
       * @param path Path it was opened from.
       */
      posix_directory_t(int fd, std::filesystem::path path):
          fd_(fd),
          path_(std::move(path)) {
      }

      ~posix_directory_t() override {
        close_fd(fd_);
      }

      posix_directory_t(const posix_directory_t &) = delete;
      posix_directory_t &operator=(const posix_directory_t &) = delete;

      /**
       * @brief Check type, owner and mode of the open directory.
       *
       * @param st Filled with the directory's metadata.
       * @return Error, or empty when acceptable.
       */
      std::error_code check(struct stat &st) const {
        if (::fstat(fd_, &st) != 0) {
          return from_errno(errno);
        }
        if (!S_ISDIR(st.st_mode)) {
          return std::make_error_code(std::errc::not_a_directory);
        }
        if (st.st_uid != ::geteuid() || (st.st_mode & 022) != 0) {
          return std::make_error_code(std::errc::permission_denied);
        }
        return {};
      }

      std::error_code verify() override {
        struct stat st {};
        if (auto ec = check(st); ec) {
          return ec;
        }
        struct stat path_st {};
        if (::lstat(path_.c_str(), &path_st) != 0) {
          return from_errno(errno);
        }
        if (S_ISLNK(path_st.st_mode)) {
          return std::make_error_code(std::errc::too_many_symbolic_link_levels);
        }
        if (path_st.st_ino != st.st_ino || path_st.st_dev != st.st_dev) {
          return std::make_error_code(std::errc::no_such_file_or_directory);
        }
        return {};
      }

      [[nodiscard]] std::filesystem::path path() const override {
        return path_;
      }

      std::error_code create_exclusive(std::string_view name, std::unique_ptr<file_t> &out) override {
        if (!plain_component(name)) {
          return std::make_error_code(std::errc::invalid_argument);
        }
        const std::string component {name};
        const int fd = ::openat(fd_, component.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd < 0) {
          return from_errno(errno);
        }
        // The creation mode is already filtered by the umask; make the absence of group, other and
        // execute bits explicit regardless of it.
        if (::fchmod(fd, 0600) != 0) {
          const auto ec = from_errno(errno);
          close_fd(fd);
          ::unlinkat(fd_, component.c_str(), 0);
          return ec;
        }
        out = std::make_unique<posix_file_t>(fd);
        return {};
      }

      std::error_code open_read(std::string_view name, std::unique_ptr<file_t> &out) override {
        if (!plain_component(name)) {
          return std::make_error_code(std::errc::invalid_argument);
        }
        const std::string component {name};
        const int fd = ::openat(fd_, component.c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
        if (fd < 0) {
          return from_errno(errno);
        }
        struct stat st {};
        if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
          close_fd(fd);
          return std::make_error_code(std::errc::invalid_argument);
        }
        out = std::make_unique<posix_file_t>(fd);
        return {};
      }

      std::error_code remove(std::string_view name) override {
        if (!plain_component(name)) {
          return std::make_error_code(std::errc::invalid_argument);
        }
        const std::string component {name};
        return ::unlinkat(fd_, component.c_str(), 0) == 0 ? std::error_code {} : from_errno(errno);
      }

      rename_result_e rename_noreplace(std::string_view from, std::string_view to) override {
        if (!plain_component(from) || !plain_component(to)) {
          return rename_result_e::error;
        }
        const std::string source {from};
        const std::string target {to};
#if defined(__linux__) && defined(SYS_renameat2)
        if (::syscall(SYS_renameat2, fd_, source.c_str(), fd_, target.c_str(), RENAME_NOREPLACE) == 0) {
          return rename_result_e::ok;
        }
        if (errno == EEXIST) {
          return rename_result_e::exists;
        }
        if (errno != EINVAL && errno != ENOSYS && errno != EOPNOTSUPP) {
          return rename_result_e::error;
        }
#elif defined(__APPLE__)
        if (::renameatx_np(fd_, source.c_str(), fd_, target.c_str(), RENAME_EXCL) == 0) {
          return rename_result_e::ok;
        }
        if (errno == EEXIST) {
          return rename_result_e::exists;
        }
        if (errno != ENOTSUP && errno != EINVAL) {
          return rename_result_e::error;
        }
#endif
        // Fallback for file systems without no-replace renames: link() never replaces.
        if (::linkat(fd_, source.c_str(), fd_, target.c_str(), 0) != 0) {
          return errno == EEXIST ? rename_result_e::exists : rename_result_e::error;
        }
        ::unlinkat(fd_, source.c_str(), 0);
        return rename_result_e::ok;
      }

      bool same_file(std::string_view name, file_t &file) override {
        if (!plain_component(name)) {
          return false;
        }
        const std::string component {name};
        struct stat st {};
        if (::fstatat(fd_, component.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0 || !S_ISREG(st.st_mode)) {
          return false;
        }
        entry_t open_entry;
        if (file.stat(open_entry)) {
          return false;
        }
        return open_entry.file_id == static_cast<std::uint64_t>(st.st_ino) && open_entry.device == static_cast<std::uint64_t>(st.st_dev);
      }

      std::optional<std::uint64_t> free_space() override {
        struct statvfs vfs {};
        if (::fstatvfs(fd_, &vfs) != 0) {
          return std::nullopt;
        }
        return static_cast<std::uint64_t>(vfs.f_bavail) * static_cast<std::uint64_t>(vfs.f_frsize);
      }

      std::error_code list_names(std::vector<std::string> &out) override {
        out.clear();
        return for_each_name([&out](const char *name) {
          out.emplace_back(name);
        });
      }

      std::error_code list_regular_files(std::vector<entry_t> &out) override {
        out.clear();
        const auto uid = ::geteuid();
        return for_each_name([&](const char *name) {
          const std::string_view view {name};
          if (view.starts_with('.') || !text::is_valid_utf8(view)) {
            return;
          }
          struct stat st {};
          if (::fstatat(fd_, name, &st, AT_SYMLINK_NOFOLLOW) != 0 || !S_ISREG(st.st_mode) || st.st_uid != uid) {
            return;
          }
          entry_t entry;
          entry.name = name;
          entry.size = static_cast<std::uint64_t>(st.st_size);
          entry.mtime_ns = mtime_ns(st);
          entry.file_id = static_cast<std::uint64_t>(st.st_ino);
          entry.device = static_cast<std::uint64_t>(st.st_dev);
          out.push_back(std::move(entry));
        });
      }

      std::error_code mark_from_internet(std::string_view) override {
        return {};
      }

    private:
      /**
       * @brief Iterate the names of all children except `.` and `..`.
       *
       * @param callback Invoked per name.
       * @return Error, or empty on success.
       */
      template<class F>
      std::error_code for_each_name(F &&callback) {
        const int dup_fd = ::fcntl(fd_, F_DUPFD_CLOEXEC, 0);
        if (dup_fd < 0) {
          return from_errno(errno);
        }
        DIR *dir = ::fdopendir(dup_fd);
        if (!dir) {
          const auto ec = from_errno(errno);
          close_fd(dup_fd);
          return ec;
        }
        // The duplicate shares the file offset with fd_; start from the beginning every time.
        ::rewinddir(dir);
        while (true) {
          errno = 0;
          const auto *entry = ::readdir(dir);
          if (!entry) {
            break;
          }
          const std::string_view name {entry->d_name};
          if (name == "." || name == "..") {
            continue;
          }
          callback(entry->d_name);
        }
        const int error = errno;
        ::closedir(dir);
        return error ? from_errno(error) : std::error_code {};
      }

      int fd_;  ///< Owned directory descriptor.
      std::filesystem::path path_;  ///< Path it was opened from.
    };

    /**
     * @brief Home directory of the effective user.
     *
     * @return Path, or empty.
     */
    std::filesystem::path home_dir() {
      if (const char *home = std::getenv("HOME"); home && *home == '/') {
        return home;
      }
      if (const auto *pw = ::getpwuid(::geteuid()); pw && pw->pw_dir) {
        return pw->pw_dir;
      }
      return {};
    }
  }  // namespace

  std::error_code open_directory(const std::filesystem::path &path, bool create, std::unique_ptr<directory_t> &out) {
    if (path.empty() || !path.is_absolute()) {
      return std::make_error_code(std::errc::invalid_argument);
    }
    const auto normalized = path.lexically_normal();
    if (create) {
      std::filesystem::path prefix;
      for (const auto &component : normalized) {
        prefix /= component;
        if (prefix == prefix.root_path()) {
          continue;
        }
        struct stat existing {};
        if (::stat(prefix.c_str(), &existing) == 0) {
          continue;
        }
        if (errno != ENOENT) {
          return from_errno(errno);
        }
        if (::mkdir(prefix.c_str(), 0700) != 0 && errno != EEXIST) {
          return from_errno(errno);
        }
      }
    }
    const int fd = ::open(normalized.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
      // O_NOFOLLOW on a symlinked final component yields ELOOP (Linux) or ENOTDIR (with O_DIRECTORY).
      return from_errno(errno);
    }
    auto directory = std::make_unique<posix_directory_t>(fd, normalized);
    struct stat st {};
    if (auto ec = directory->check(st); ec) {
      return ec;
    }
    out = std::move(directory);
    return {};
  }

  std::filesystem::path user_download_dir() {
#ifdef __APPLE__
    const auto home = home_dir();
    return home.empty() ? std::filesystem::path {} : home / "Downloads";
#else
    if (const char *env = std::getenv("XDG_DOWNLOAD_DIR"); env && *env == '/') {
      return env;
    }
    const auto home = home_dir();
    std::filesystem::path config_home;
    if (const char *xdg_config = std::getenv("XDG_CONFIG_HOME"); xdg_config && *xdg_config == '/') {
      config_home = xdg_config;
    } else if (!home.empty()) {
      config_home = home / ".config";
    }
    if (!config_home.empty()) {
      std::ifstream file {config_home / "user-dirs.dirs"};
      if (file) {
        std::stringstream buffer;
        buffer << file.rdbuf();
        if (auto parsed = parse_xdg_download_dir(buffer.str(), home); parsed) {
          return *parsed;
        }
      }
    }
    return home.empty() ? std::filesystem::path {} : home / "Downloads";
#endif
  }
}  // namespace sds::fs
