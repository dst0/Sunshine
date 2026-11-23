/** @file src/sds/file_clipboard.h
 *  @brief Bounds and private staging for the native X11 file clipboard.
 */
#pragma once

#include <cstddef>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

namespace sds::file_clipboard {
  inline constexpr std::size_t file_max = 16;
  inline constexpr std::size_t bytes_max = 8 * 1024 * 1024;
  inline constexpr std::size_t wire_max = 12 * 1024 * 1024;
  inline constexpr std::size_t offer_max = 32 * 1024;

  // Production opt-in is deliberately tied to the authenticated private mini-PC X server.
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
}  // namespace sds::file_clipboard
