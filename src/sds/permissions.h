/**
 * @file src/sds/permissions.h
 * @brief Per-client secure-desktop-stream permissions (DESIGN section 4.2).
 *
 * This header is intentionally dependency-free so nvhttp can normalize persisted permission lists.
 */
#pragma once

// standard includes
#include <array>
#include <bitset>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace sds {
  /**
   * @brief Operation classes a paired client can be granted.
   */
  enum class permission_e : std::size_t {
    clipboard_read,  ///< Read the host clipboard (host -> client).
    clipboard_write,  ///< Set the host clipboard (client -> host).
    file_upload,  ///< Drop files into the host inbox.
    file_download,  ///< List and download files from the host outbox.
    mic,  ///< Send microphone audio.
    count  ///< Number of permissions.
  };

  /**
   * @brief Set of granted permissions.
   */
  using permission_set_t = std::bitset<static_cast<std::size_t>(permission_e::count)>;

  /**
   * @brief Canonical permission names in enum order.
   */
  inline constexpr std::array<std::string_view, static_cast<std::size_t>(permission_e::count)> permission_names {
    "clipboard_read",
    "clipboard_write",
    "file_upload",
    "file_download",
    "mic",
  };

  /**
   * @brief Parse a canonical permission name.
   *
   * @param name Permission name, case-sensitive.
   * @return Permission, or no value for an unknown name.
   */
  std::optional<permission_e> parse_permission(std::string_view name);

  /**
   * @brief Return the canonical name of a permission.
   *
   * @param permission Permission to name.
   * @return Canonical name.
   */
  std::string_view permission_name(permission_e permission);

  /**
   * @brief Convert names to a permission set, ignoring unknown names.
   *
   * @param names Permission names.
   * @return Set of recognized permissions.
   */
  permission_set_t to_permission_set(const std::vector<std::string> &names);

  /**
   * @brief Convert a permission set to canonical names in enum order.
   *
   * @param permissions Permission set.
   * @return Canonical names.
   */
  std::vector<std::string> to_permission_names(const permission_set_t &permissions);

  /**
   * @brief Drop unknown names, remove duplicates and sort into canonical order.
   *
   * @param names Permission names as persisted or configured.
   * @return Normalized names.
   */
  std::vector<std::string> normalize_permissions(const std::vector<std::string> &names);

  /**
   * @brief Parse a comma-separated permission list (configuration syntax).
   *
   * Whitespace around entries is ignored; unknown names are dropped.
   *
   * @param list Comma-separated names.
   * @return Normalized names.
   */
  std::vector<std::string> parse_permission_list(std::string_view list);

  /**
   * @brief Check that every name is a known permission.
   *
   * @param names Names to check.
   * @return `true` when all names are known.
   */
  bool all_permissions_known(const std::vector<std::string> &names);
}  // namespace sds
