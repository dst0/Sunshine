/**
 * @file src/sds/permissions.cpp
 * @brief Per-client secure-desktop-stream permission parsing.
 */
// standard includes
#include <algorithm>

// local includes
#include "permissions.h"

namespace sds {
  std::optional<permission_e> parse_permission(std::string_view name) {
    for (std::size_t index = 0; index < permission_names.size(); ++index) {
      if (permission_names[index] == name) {
        return static_cast<permission_e>(index);
      }
    }
    return std::nullopt;
  }

  std::string_view permission_name(permission_e permission) {
    return permission_names.at(static_cast<std::size_t>(permission));
  }

  permission_set_t to_permission_set(const std::vector<std::string> &names) {
    permission_set_t permissions;
    for (const auto &name : names) {
      if (const auto permission = parse_permission(name); permission) {
        permissions.set(static_cast<std::size_t>(*permission));
      }
    }
    return permissions;
  }

  std::vector<std::string> to_permission_names(const permission_set_t &permissions) {
    std::vector<std::string> names;
    for (std::size_t index = 0; index < permission_names.size(); ++index) {
      if (permissions.test(index)) {
        names.emplace_back(permission_names[index]);
      }
    }
    return names;
  }

  std::vector<std::string> normalize_permissions(const std::vector<std::string> &names) {
    return to_permission_names(to_permission_set(names));
  }

  std::vector<std::string> parse_permission_list(std::string_view list) {
    std::vector<std::string> names;
    while (!list.empty()) {
      const auto comma = list.find(',');
      auto entry = list.substr(0, comma);
      list = comma == std::string_view::npos ? std::string_view {} : list.substr(comma + 1);

      const auto first = entry.find_first_not_of(" \t\r\n");
      if (first == std::string_view::npos) {
        continue;
      }
      entry = entry.substr(first, entry.find_last_not_of(" \t\r\n") - first + 1);
      names.emplace_back(entry);
    }
    return normalize_permissions(names);
  }

  bool all_permissions_known(const std::vector<std::string> &names) {
    return std::ranges::all_of(names, [](const std::string &name) {
      return parse_permission(name).has_value();
    });
  }
}  // namespace sds
