/**
 * @file src/sds/files.h
 * @brief File transfer core (DESIGN section 6): upload sessions, outbox listing/ids, range reads
 *        and the file-name sanitizer.
 */
#pragma once

// standard includes
#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

// lib includes
#include <openssl/evp.h>

// local includes
#include "fs.h"
#include "reply.h"

namespace sds::files {
  /**
   * @brief Maximum UTF-8 length of a sanitized file name.
   */
  inline constexpr std::size_t NAME_MAX_BYTES = 200;

  /**
   * @brief Highest collision suffix tried: `name (999).ext`.
   */
  inline constexpr unsigned COLLISION_MAX = 999;

  /**
   * @brief Maximum number of outbox entries listed.
   */
  inline constexpr std::size_t OUTBOX_LIST_MAX = 1000;

  /**
   * @brief Sanitize a file name according to DESIGN 6.4.
   *
   * Rejects names larger than 1024 bytes, invalid UTF-8, empty names, `.` and `..`. Normalizes
   * to NFC; replaces `/ \ : * ? " < > |`, C0/C1 controls, DEL and bidirectional formatting
   * characters with `_`; strips trailing dots and spaces; replaces a leading `.` or `-` with `_`;
   * prefixes Windows reserved device names with `_`; shortens to NAME_MAX_BYTES on a code point
   * boundary keeping an extension of up to 32 bytes.
   *
   * @param name Untrusted name.
   * @return Safe single path component, or no value when rejected.
   */
  std::optional<std::string> sanitize_file_name(std::string_view name);

  /**
   * @brief Build the n-th collision variant of a sanitized name (`report (1).pdf`).
   *
   * @param name Sanitized name.
   * @param n Collision counter (> 0).
   * @return Variant.
   */
  std::string collision_name(std::string_view name, unsigned n);

  /**
   * @brief Check the format of an upload or outbox id (32 lowercase hex digits).
   *
   * @param id Candidate.
   * @return `true` when well-formed.
   */
  bool is_id(std::string_view id);

  /**
   * @brief Configuration of the file core.
   */
  struct options_t {
    std::uint64_t file_max = 4ull * 1024 * 1024 * 1024;  ///< Maximum file size.
    std::size_t chunk_max = 4 * 1024 * 1024;  ///< Maximum chunk and range length.
    std::size_t uploads_max = 2;  ///< Concurrent upload sessions per client.
    std::uint64_t min_free_space = 1024ull * 1024 * 1024;  ///< Free-space floor.
    std::chrono::milliseconds idle_timeout = std::chrono::seconds {120};  ///< Idle upload expiry.
    std::filesystem::path inbox;  ///< Inbox directory (absolute); empty: `<user downloads>/Moonlight`, resolved at use.
    std::filesystem::path outbox;  ///< Outbox directory (absolute); empty: `<inbox>/Outbox`, resolved at use.
  };

  /**
   * @brief Upload sessions and outbox access.
   *
   * All members except open_uploads() must run on the file worker thread.
   */
  class manager_t {
  public:
    using clock = std::chrono::steady_clock;  ///< Clock for idle expiry.

    /**
     * @brief Create the manager with a fresh per-boot outbox id key.
     *
     * @param options Configuration.
     */
    explicit manager_t(options_t options);

    /**
     * @brief Deletes all partial uploads.
     */
    ~manager_t();

    manager_t(const manager_t &) = delete;
    manager_t &operator=(const manager_t &) = delete;

    /**
     * @brief `POST /sds/v1/files/uploads`.
     *
     * @param client Client key.
     * @param body JSON body `{"name","size","sha256"}`.
     * @return 201 with id, or an error.
     */
    reply_t create(const std::string &client, std::string_view body);

    /**
     * @brief `PUT /sds/v1/files/uploads/{id}?offset=n`.
     *
     * @param client Client key.
     * @param id Upload id.
     * @param offset Offset query parameter, if present and numeric.
     * @param data Chunk.
     * @return 200 with the new offset, 409 with the expected offset, or an error.
     */
    reply_t write_chunk(const std::string &client, std::string_view id, std::optional<std::uint64_t> offset, std::string_view data);

    /**
     * @brief `POST /sds/v1/files/uploads/{id}/complete`.
     *
     * @param client Client key.
     * @param id Upload id.
     * @param before_publish Optional synchronous authorization check, rerun before every rename
     * attempt after integrity/flush/zone work. Return a denial reply to discard the upload.
     * The production dispatcher supplies a fresh request/stream-bound authorization check.
     * @return 201 with the final name, 422 on size/hash mismatch, or an error.
     */
    reply_t complete(const std::string &client, std::string_view id, std::function<std::optional<reply_t>()> before_publish = {});

    /**
     * @brief `DELETE /sds/v1/files/uploads/{id}`.
     *
     * @param client Client key.
     * @param id Upload id.
     * @return 204, or 404.
     */
    reply_t cancel(const std::string &client, std::string_view id);

    /**
     * @brief `GET /sds/v1/files/outbox`.
     *
     * @return Listing.
     */
    reply_t list_outbox();

    /**
     * @brief `GET /sds/v1/files/outbox/{id}?offset=n&length=m`.
     *
     * @param id Outbox id.
     * @param offset Start offset.
     * @param length Requested length (defaults to chunk_max).
     * @return Bytes with size/hash headers, or an error.
     */
    reply_t read_outbox(std::string_view id, std::uint64_t offset, std::optional<std::uint64_t> length);

    /**
     * @brief Drop upload sessions idle for longer than the timeout.
     *
     * @param now Current time.
     */
    void expire_idle(clock::time_point now);

    /**
     * @brief Drop every upload session of a client (stream ended or permission revoked).
     *
     * @param client Client key.
     */
    void end_client(const std::string &client);

    /**
     * @brief Drop every upload session.
     */
    void shutdown();

    /**
     * @brief Rescan the outbox and report its file count when the content changed.
     *
     * @return File count after a change, or no value when unchanged or unreadable.
     */
    std::optional<std::size_t> scan_outbox_changes();

    /**
     * @brief Take the current outbox content as the baseline for scan_outbox_changes().
     */
    void reset_outbox_baseline();

    /**
     * @brief Number of open upload sessions of a client. Thread-safe.
     *
     * @param client Client key.
     * @return Session count.
     */
    [[nodiscard]] std::size_t open_uploads(std::string_view client) const;

    /**
     * @brief Number of open upload sessions of all clients (tests).
     *
     * @return Session count.
     */
    [[nodiscard]] std::size_t total_uploads() const;

    /**
     * @brief Options in effect.
     *
     * @return Options.
     */
    [[nodiscard]] const options_t &options() const;

  private:
    /**
     * @brief Deleter for EVP_MD_CTX.
     */
    struct md_ctx_deleter_t {
      /**
       * @brief Free the context.
       *
       * @param ctx Context.
       */
      void operator()(EVP_MD_CTX *ctx) const {
        EVP_MD_CTX_free(ctx);
      }
    };

    /**
     * @brief One upload session.
     */
    struct upload_t {
      std::string owner;  ///< Client key.
      std::string name;  ///< Sanitized target name.
      std::string part_name;  ///< `.<id>.part`.
      std::uint64_t size = 0;  ///< Declared size.
      std::array<std::uint8_t, 32> expected_sha {};  ///< Declared SHA-256.
      std::uint64_t offset = 0;  ///< Bytes received.
      std::unique_ptr<fs::directory_t> dir;  ///< Inbox the part lives in.
      std::unique_ptr<fs::file_t> file;  ///< Open part file.
      std::unique_ptr<EVP_MD_CTX, md_ctx_deleter_t> sha;  ///< Incremental hash.
      clock::time_point last_activity;  ///< For idle expiry.
    };

    /**
     * @brief Outbox entry with its id metadata.
     */
    struct outbox_entry_t {
      fs::entry_t entry;  ///< Metadata at listing time.
      std::optional<std::string> sha256;  ///< Cached hex digest.
    };

    /**
     * @brief Close and delete a session's part file and forget the session.
     *
     * @param id Upload id.
     */
    void drop(const std::string &id);

    /**
     * @brief Look up a session owned by a client.
     *
     * @param client Client key.
     * @param id Upload id.
     * @return Session, or `nullptr` when unknown or owned by another client.
     */
    upload_t *find(const std::string &client, std::string_view id);

    /**
     * @brief Inbox path in effect.
     *
     * @return Configured inbox, or the session user's default; empty when unknown.
     */
    std::filesystem::path inbox_dir() const;

    /**
     * @brief Outbox path in effect.
     *
     * @return Configured outbox, or `<inbox>/Outbox`; empty when unknown.
     */
    std::filesystem::path outbox_dir() const;

    /**
     * @brief Open the inbox, removing stale part files on first use.
     *
     * @param out Directory.
     * @return Error, or empty.
     */
    std::error_code open_inbox(std::unique_ptr<fs::directory_t> &out);

    /**
     * @brief Re-list the outbox into the id cache.
     *
     * @param out Directory used for the listing.
     * @return Error, or empty.
     */
    std::error_code refresh_outbox(std::unique_ptr<fs::directory_t> &out);

    /**
     * @brief Compute the id of an outbox entry.
     *
     * @param entry Metadata.
     * @return 32 hex digits, or no value when key/HMAC initialization failed.
     */
    std::optional<std::string> outbox_id(const fs::entry_t &entry) const;

    /**
     * @brief Signature of the cached listing used for change detection.
     *
     * @return Concatenated ids.
     */
    std::string outbox_signature() const;

    options_t options_;  ///< Configuration.
    std::array<unsigned char, 32> id_key_ {};  ///< Per-boot HMAC key for outbox ids.
    bool id_key_ready_ = false;  ///< Whether id_key_ was initialized from the CSPRNG.
    std::map<std::string, upload_t, std::less<>> uploads_;  ///< Sessions by id.
    std::map<std::string, outbox_entry_t, std::less<>> outbox_;  ///< Outbox cache by id.
    std::optional<std::string> outbox_baseline_;  ///< Signature at the last change report.
    bool inbox_cleaned_ = false;  ///< Stale parts removed.
    mutable std::mutex counts_mutex_;  ///< Protects counts_.
    std::map<std::string, std::size_t, std::less<>> counts_;  ///< Sessions per client.
  };
}  // namespace sds::files
