/** @file src/sds/file_clipboard.h
 *  @brief Bounds and private staging for the native X11 file clipboard and lazy offers.
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <nlohmann/json.hpp>

#include "fs.h"

namespace sds::file_clipboard {
  inline constexpr std::size_t file_max = 16;
  inline constexpr std::size_t bytes_max = 8 * 1024 * 1024;
  inline constexpr std::size_t wire_max = 12 * 1024 * 1024;
  inline constexpr std::size_t offer_max = 32 * 1024;
  inline constexpr std::size_t lazy_entry_limit = 64;

  // Enabled when config/env opts in on an active X11 display.
  bool private_x11_enabled();
  std::optional<std::string> new_epoch();

  // Strictly native Copy offers only. Reads explicitly selected, owned regular files without
  // following symlinks. No paths are included in the returned bundle.
  std::optional<nlohmann::json> read_offer(std::string_view offer, const std::function<bool()> &allowed);

  class stage_t;
  // Fully validate and stage into a private, randomized runtime directory. The returned
  // lease controls lifetime and owns the only directory cleanup operation.
  std::shared_ptr<const stage_t> stage(std::string_view body, const std::function<bool()> &allowed);
  std::string_view native_offer(const stage_t &stage);

  /**
   * @brief Create an in-memory lease stage with no filesystem backing (for dispatcher tests).
   *
   * @param offer Native clipboard offer payload.
   * @return Opaque stage lease.
   */
  std::shared_ptr<const stage_t> make_test_stage(std::string offer);

  /**
   * @brief Safe read handle over an opened, mutation-checked source or staged file.
   */
  class source_handle_t {
  public:
    virtual ~source_handle_t() = default;
    virtual bool read_chunk(
      std::uint64_t offset,
      std::size_t length,
      std::vector<char> &out,
      std::string &chunk_sha256_hex
    ) = 0;
    virtual bool finalize_file_sha256(std::string &out_hex) = 0;
  };

  /**
   * @brief Verified metadata + lazy read handle for one copied source entry.
   */
  struct lazy_source_entry_t {
    std::string id;
    std::string name;
    std::uint64_t size = 0;
    std::shared_ptr<source_handle_t> handle;
  };

  /**
   * @brief Stage lease + entry handle for a materialized host PNG offered lazily.
   */
  struct host_image_stage_t {
    std::string entry_id;
    std::string name;
    std::uint64_t size = 0;
    std::shared_ptr<source_handle_t> handle;
    std::shared_ptr<const stage_t> lease;
  };

  /**
   * @brief Private 0700 stage directory holding client-uploaded lazy clipboard or XDND drop files.
   */
  class chunk_stage_t {
  public:
    virtual ~chunk_stage_t() = default;
    [[nodiscard]] virtual std::filesystem::path dir_path() const = 0;
    [[nodiscard]] virtual std::string file_uri_for(std::string_view filename) const = 0;
    [[nodiscard]] virtual std::string native_copy_offer(const std::vector<std::string> &filenames) const = 0;
    [[nodiscard]] virtual std::vector<std::string> uris_for(const std::vector<std::string> &filenames) const = 0;
    virtual std::error_code create_part(std::string_view part_name, std::unique_ptr<fs::file_t> &out) = 0;
    virtual std::error_code commit_part(std::string_view part_name, std::string_view final_name) = 0;
    virtual void remove_file(std::string_view name) = 0;
  };

  /**
   * @brief Capture metadata and pinned descriptors for copied files without reading bytes eagerly.
   */
  std::optional<std::vector<lazy_source_entry_t>> capture_lazy_sources(
    std::string_view offer,
    std::uint64_t max_file_bytes,
    std::size_t max_entries = lazy_entry_limit
  );

  /**
   * @brief Materialize host clipboard PNG into a private 0600 stage file for chunked streaming.
   */
  std::optional<host_image_stage_t> stage_host_image(
    std::span<const std::uint8_t> png_bytes,
    std::uint64_t min_free_bytes
  );

  /**
   * @brief Allocate a private 0700 stage directory under $XDG_RUNTIME_DIR/sds-clipboard-stage or appdata.
   */
  std::shared_ptr<chunk_stage_t> create_chunk_stage(
    std::uint64_t required_bytes,
    std::uint64_t min_free_bytes,
    const std::filesystem::path &override_base = {}
  );
}  // namespace sds::file_clipboard
