/**
 * @file src/sds/fs.h
 * @brief Directory and file primitives for the inbox/outbox (DESIGN 6.1-6.3).
 *
 * POSIX: everything is relative to a directory fd opened with O_NOFOLLOW (openat & co.).
 * Windows: CreateFileW with FILE_FLAG_OPEN_REPARSE_POINT under the session user's token.
 */
#pragma once

// standard includes
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace sds::fs {
  /**
   * @brief Metadata of a regular file.
   */
  struct entry_t {
    std::string name;  ///< File name (UTF-8).
    std::uint64_t size = 0;  ///< Size in bytes.
    std::int64_t mtime_ns = 0;  ///< Modification time, nanoseconds since the Unix epoch.
    std::uint64_t file_id = 0;  ///< Inode number / NTFS file index.
    std::uint64_t device = 0;  ///< Device / volume serial number.
  };

  /**
   * @brief Open file.
   */
  class file_t {
  public:
    virtual ~file_t() = default;

    /**
     * @brief Write all bytes at an offset.
     *
     * @param offset Byte offset.
     * @param data Bytes to write.
     * @return Error, or empty on success.
     */
    virtual std::error_code write_at(std::uint64_t offset, std::span<const char> data) = 0;

    /**
     * @brief Read up to `buffer.size()` bytes at an offset.
     *
     * @param offset Byte offset.
     * @param buffer Destination.
     * @param read Bytes read (less than requested only at end of file).
     * @return Error, or empty on success.
     */
    virtual std::error_code read_at(std::uint64_t offset, std::span<char> buffer, std::size_t &read) = 0;

    /**
     * @brief Truncate or extend the file.
     *
     * @param size New size.
     * @return Error, or empty on success.
     */
    virtual std::error_code truncate(std::uint64_t size) = 0;

    /**
     * @brief Flush data to stable storage.
     *
     * @return Error, or empty on success.
     */
    virtual std::error_code sync() = 0;

    /**
     * @brief Query metadata of the open file.
     *
     * @param out Metadata (name left empty).
     * @return Error, or empty on success.
     */
    virtual std::error_code stat(entry_t &out) = 0;

    /**
     * @brief Check that the open file is a regular file without execute permission.
     *
     * @return `true` when the file is regular and not executable (always `true` on Windows).
     */
    virtual bool is_regular_non_executable() = 0;
  };

  /**
   * @brief Result of rename_noreplace().
   */
  enum class rename_result_e {
    ok,  ///< Renamed.
    exists,  ///< Destination exists; nothing changed.
    error,  ///< Other failure.
  };

  /**
   * @brief Verified directory; all operations are confined to its direct children.
   */
  class directory_t {
  public:
    virtual ~directory_t() = default;

    /**
     * @brief Re-check that the directory is still a real directory owned by the session user.
     *
     * @return Error, or empty when still valid.
     */
    virtual std::error_code verify() = 0;

    /**
     * @brief Path the directory was opened from.
     *
     * @return Path.
     */
    [[nodiscard]] virtual std::filesystem::path path() const = 0;

    /**
     * @brief Create a new file (O_CREAT|O_EXCL|O_NOFOLLOW, mode 0600 / CREATE_NEW).
     *
     * @param name Child name.
     * @param out Opened file.
     * @return Error (`file_exists` when the name is taken), or empty on success.
     */
    virtual std::error_code create_exclusive(std::string_view name, std::unique_ptr<file_t> &out) = 0;

    /**
     * @brief Open an existing regular file for reading without following symlinks.
     *
     * @param name Child name.
     * @param out Opened file.
     * @return Error, or empty on success.
     */
    virtual std::error_code open_read(std::string_view name, std::unique_ptr<file_t> &out) = 0;

    /**
     * @brief Remove a child file (never follows symlinks).
     *
     * @param name Child name.
     * @return Error, or empty on success.
     */
    virtual std::error_code remove(std::string_view name) = 0;

    /**
     * @brief Rename a child without replacing an existing destination.
     *
     * @param from Existing child name.
     * @param to New child name.
     * @return Outcome.
     */
    virtual rename_result_e rename_noreplace(std::string_view from, std::string_view to) = 0;

    /**
     * @brief Check that a child name still refers to an open file (not swapped for a link).
     *
     * @param name Child name.
     * @param file Open file.
     * @return `true` when both refer to the same regular file.
     */
    virtual bool same_file(std::string_view name, file_t &file) = 0;

    /**
     * @brief Bytes available to the session user on the directory's file system.
     *
     * @return Free bytes, or no value on error.
     */
    virtual std::optional<std::uint64_t> free_space() = 0;

    /**
     * @brief List regular, non-hidden files directly inside the directory.
     *
     * Symlinks, directories, special files, names starting with `.`, names that are not valid
     * UTF-8 and files not owned by the session user are skipped.
     *
     * @param out Entries.
     * @return Error, or empty on success.
     */
    virtual std::error_code list_regular_files(std::vector<entry_t> &out) = 0;

    /**
     * @brief Names of all direct children (any type), for maintenance such as stale-part cleanup.
     *
     * @param out Names.
     * @return Error, or empty on success.
     */
    virtual std::error_code list_names(std::vector<std::string> &out) = 0;

    /**
     * @brief Mark a received file as downloaded from the internet (Windows Zone.Identifier ZoneId=3).
     *
     * @param name Child name.
     * @return Error, or empty on success (no-op on POSIX).
     */
    virtual std::error_code mark_from_internet(std::string_view name) = 0;
  };

  /**
   * @brief Open (and optionally create, mode 0700) a directory and verify it.
   *
   * The final path component must be a real directory (not a symlink or reparse point), owned by
   * the session user and not writable by group or others.
   *
   * @param path Absolute directory path.
   * @param create Create missing components.
   * @param out Opened directory.
   * @return Error, or empty on success.
   */
  std::error_code open_directory(const std::filesystem::path &path, bool create, std::unique_ptr<directory_t> &out);

  /**
   * @brief The session user's download folder (Linux: XDG_DOWNLOAD_DIR, Windows: FOLDERID_Downloads).
   *
   * @return Path, or empty when unknown.
   */
  std::filesystem::path user_download_dir();

  /**
   * @brief Resolve XDG_DOWNLOAD_DIR from a user-dirs.dirs file body.
   *
   * @param user_dirs Contents of `user-dirs.dirs`.
   * @param home Home directory used for `$HOME` expansion.
   * @return Absolute path, or no value when the file has no usable entry.
   */
  std::optional<std::filesystem::path> parse_xdg_download_dir(std::string_view user_dirs, const std::filesystem::path &home);
}  // namespace sds::fs
