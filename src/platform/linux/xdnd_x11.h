/**
 * @file src/platform/linux/xdnd_x11.h
 * @brief X11 XDND v5 protocol drag-and-drop delivery helper.
 */
#pragma once

#include <string>
#include <utility>
#include <vector>

namespace platf::xdnd {

  /**
   * @brief Outcome of attempting XDND drop delivery onto an X11 window.
   */
  enum class drop_delivery_status_e {
    accepted,  ///< Target XdndAware window accepted the drop and received the URI list.
    rejected,  ///< Target window declined XdndStatus/XdndFinished or timed out.
    no_target,  ///< No mapped XdndAware window found at the drop point.
    unavailable,  ///< X11 display unavailable (e.g. headless/Wayland).
  };

  /**
   * @brief Map normalized [0,1] stream coordinates to clamped screen pixel coordinates.
   */
  std::pair<int, int> map_normalized_to_screen(double nx, double ny, int screen_w, int screen_h);

  /**
   * @brief Format a CRLF-terminated RFC 2483 text/uri-list payload.
   */
  std::string build_uri_list_payload(const std::vector<std::string> &uris);

  /**
   * @brief Format an x-special/gnome-copied-files payload.
   */
  std::string build_gnome_copy_payload(const std::vector<std::string> &uris);

  /**
   * @brief Deliver staged file:// URIs to the deepest XdndAware window at normalized (nx, ny).
   */
  drop_delivery_status_e deliver_xdnd_drop(double nx, double ny, const std::vector<std::string> &uris);

}  // namespace platf::xdnd
