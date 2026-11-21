/**
 * @file src/sds/fs_common.cpp
 * @brief Platform-independent helpers of the inbox/outbox file primitives.
 */
// standard includes
#include <sstream>

// local includes
#include "fs.h"

namespace sds::fs {
  std::optional<std::filesystem::path> parse_xdg_download_dir(std::string_view user_dirs, const std::filesystem::path &home) {
    std::istringstream stream {std::string {user_dirs}};
    std::string line;
    std::optional<std::filesystem::path> result;
    while (std::getline(stream, line)) {
      const auto first = line.find_first_not_of(" \t");
      if (first == std::string::npos || line[first] == '#') {
        continue;
      }
      std::string_view view {line};
      view.remove_prefix(first);
      constexpr std::string_view key = "XDG_DOWNLOAD_DIR=";
      if (!view.starts_with(key)) {
        continue;
      }
      view.remove_prefix(key.size());
      while (!view.empty() && (view.back() == ' ' || view.back() == '\t' || view.back() == '\r')) {
        view.remove_suffix(1);
      }
      if (view.size() >= 2 && view.front() == '"' && view.back() == '"') {
        view = view.substr(1, view.size() - 2);
      }

      // Per the XDG user-dirs spec, a value equal to $HOME disables the directory.
      if (view == "$HOME" || view == "$HOME/") {
        result.reset();
      } else if (view.starts_with("$HOME/")) {
        if (!home.empty()) {
          result = home / std::filesystem::path {std::string {view.substr(6)}};
        }
      } else if (view.starts_with('/')) {
        result = std::filesystem::path {std::string {view}};
      } else {
        result.reset();
      }
    }
    return result;
  }
}  // namespace sds::fs
