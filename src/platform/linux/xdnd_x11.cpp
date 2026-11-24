/**
 * @file src/platform/linux/xdnd_x11.cpp
 * @brief X11 XDND v5 protocol drag-and-drop delivery helper.
 */

#include "xdnd_x11.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <poll.h>
#include <vector>

#include <X11/Xatom.h>
#include <X11/Xlib.h>

#include "src/logging.h"
#include "src/platform/common.h"

namespace platf::xdnd {

  std::pair<int, int> map_normalized_to_screen(double nx, double ny, int screen_w, int screen_h) {
    if (screen_w <= 0 || screen_h <= 0) {
      return {0, 0};
    }
    const double clamped_x = std::isfinite(nx) ? std::clamp(nx, 0.0, 1.0) : 0.0;
    const double clamped_y = std::isfinite(ny) ? std::clamp(ny, 0.0, 1.0) : 0.0;
    const int x_px = std::clamp(static_cast<int>(std::llround(clamped_x * static_cast<double>(screen_w - 1))), 0, screen_w - 1);
    const int y_px = std::clamp(static_cast<int>(std::llround(clamped_y * static_cast<double>(screen_h - 1))), 0, screen_h - 1);
    return {x_px, y_px};
  }

  std::string build_uri_list_payload(const std::vector<std::string> &uris) {
    std::string out;
    for (const auto &uri : uris) {
      if (uri.empty()) {
        continue;
      }
      out += uri;
      out += "\r\n";
    }
    return out;
  }

  std::string build_gnome_copy_payload(const std::vector<std::string> &uris) {
    std::string out = "copy";
    bool any = false;
    for (const auto &uri : uris) {
      if (uri.empty()) {
        continue;
      }
      out += '\n';
      out += uri;
      any = true;
    }
    return any ? out : std::string {};
  }

  namespace {

    using steady = std::chrono::steady_clock;

    struct xprop_t {
      Atom type = None;
      int format = 0;
      unsigned long items = 0;
      unsigned long bytes_after = 0;
      unsigned char *data = nullptr;

      ~xprop_t() {
        if (data) {
          XFree(data);
        }
      }
    };

    struct xdnd_atoms_t {
      Atom xdnd_selection;
      Atom xdnd_aware;
      Atom xdnd_proxy;
      Atom xdnd_enter;
      Atom xdnd_position;
      Atom xdnd_status;
      Atom xdnd_leave;
      Atom xdnd_drop;
      Atom xdnd_finished;
      Atom xdnd_action_copy;
      Atom targets;
      Atom text_uri_list;
      Atom gnome_copied_files;
      Atom utf8_string;
      Atom text_plain;
    };

    bool read_xdnd_aware(Display *dpy, Window win, Atom xdnd_aware, long &out_version) {
      xprop_t prop;
      if (XGetWindowProperty(dpy, win, xdnd_aware, 0, 1, False, AnyPropertyType, &prop.type, &prop.format, &prop.items, &prop.bytes_after, &prop.data) != Success ||
          prop.format != 32 || prop.items < 1 || !prop.data) {
        return false;
      }
      const long version = static_cast<long>(*reinterpret_cast<const unsigned long *>(prop.data));
      if (version < 3) {
        return false;
      }
      out_version = std::min<long>(5, version);
      return true;
    }

    std::optional<Window> read_xdnd_proxy(Display *dpy, Window win, Atom xdnd_proxy) {
      xprop_t prop;
      if (XGetWindowProperty(dpy, win, xdnd_proxy, 0, 1, False, XA_WINDOW, &prop.type, &prop.format, &prop.items, &prop.bytes_after, &prop.data) != Success ||
          prop.format != 32 || prop.items != 1 || !prop.data) {
        return std::nullopt;
      }
      const Window proxy = *reinterpret_cast<const Window *>(prop.data);
      return proxy == None ? std::nullopt : std::optional<Window> {proxy};
    }

    void collect_window_stack_at(
      Display *dpy,
      Window root,
      Window current,
      int x_px,
      int y_px,
      Window skip_win,
      std::vector<Window> &chain_bottom_up
    ) {
      Window q_root = None;
      Window parent = None;
      Window *children = nullptr;
      unsigned int nchildren = 0;
      if (!XQueryTree(dpy, current, &q_root, &parent, &children, &nchildren)) {
        return;
      }
      // Children are ordered bottom-to-top; check topmost first.
      for (unsigned int idx = nchildren; idx > 0; --idx) {
        const Window child = children[idx - 1];
        if (child == skip_win) {
          continue;
        }
        XWindowAttributes attrs {};
        if (!XGetWindowAttributes(dpy, child, &attrs) || attrs.map_state != IsViewable || attrs.width <= 0 || attrs.height <= 0) {
          continue;
        }
        int root_x = 0;
        int root_y = 0;
        Window dummy = None;
        if (!XTranslateCoordinates(dpy, child, root, 0, 0, &root_x, &root_y, &dummy)) {
          continue;
        }
        if (x_px >= root_x && x_px < root_x + attrs.width &&
            y_px >= root_y && y_px < root_y + attrs.height) {
          collect_window_stack_at(dpy, root, child, x_px, y_px, skip_win, chain_bottom_up);
          chain_bottom_up.push_back(child);
          break;
        }
      }
      if (children) {
        XFree(children);
      }
    }

    bool find_xdnd_target(
      Display *dpy,
      Window root,
      int x_px,
      int y_px,
      Window skip_win,
      const xdnd_atoms_t &atoms,
      Window &out_target_win,
      Window &out_event_win,
      long &out_version
    ) {
      std::vector<Window> candidates;
      {
        XGrabServer(dpy);
        collect_window_stack_at(dpy, root, root, x_px, y_px, skip_win, candidates);
        candidates.push_back(root);
        XUngrabServer(dpy);
        XSync(dpy, False);
      }

      for (const Window win : candidates) {
        if (const auto proxy = read_xdnd_proxy(dpy, win, atoms.xdnd_proxy)) {
          const auto self_proxy = read_xdnd_proxy(dpy, *proxy, atoms.xdnd_proxy);
          long ver = 0;
          if (self_proxy && *self_proxy == *proxy && read_xdnd_aware(dpy, *proxy, atoms.xdnd_aware, ver)) {
            out_target_win = win;
            out_event_win = *proxy;
            out_version = ver;
            return true;
          }
        }
        long ver = 0;
        if (read_xdnd_aware(dpy, win, atoms.xdnd_aware, ver)) {
          out_target_win = win;
          out_event_win = win;
          out_version = ver;
          return true;
        }
      }
      return false;
    }

    void send_client_message(
      Display *dpy,
      Window target,
      Atom msg_type,
      long l0,
      long l1,
      long l2,
      long l3,
      long l4
    ) {
      XEvent ev {};
      ev.xclient.type = ClientMessage;
      ev.xclient.display = dpy;
      ev.xclient.window = target;
      ev.xclient.message_type = msg_type;
      ev.xclient.format = 32;
      ev.xclient.data.l[0] = l0;
      ev.xclient.data.l[1] = l1;
      ev.xclient.data.l[2] = l2;
      ev.xclient.data.l[3] = l3;
      ev.xclient.data.l[4] = l4;
      XSendEvent(dpy, target, False, NoEventMask, &ev);
      XFlush(dpy);
    }

    bool handle_selection_request(
      Display *dpy,
      Window src_win,
      const XSelectionRequestEvent &req,
      const xdnd_atoms_t &atoms,
      const std::string &uri_list,
      const std::string &gnome_copy
    ) {
      XSelectionEvent reply {};
      reply.type = SelectionNotify;
      reply.display = dpy;
      reply.requestor = req.requestor;
      reply.selection = req.selection;
      reply.target = req.target;
      reply.time = req.time;
      reply.property = None;

      bool served_uri_data = false;
      const Atom prop = (req.property == None) ? req.target : req.property;
      if (req.selection == atoms.xdnd_selection && req.owner == src_win) {
        if (req.target == atoms.targets) {
          std::vector<Atom> list {
            atoms.targets,
            atoms.text_uri_list,
            atoms.gnome_copied_files,
            atoms.utf8_string,
            atoms.text_plain,
            Atom {XA_STRING},
          };
          XChangeProperty(dpy, req.requestor, prop, XA_ATOM, 32, PropModeReplace, reinterpret_cast<const unsigned char *>(list.data()), static_cast<int>(list.size()));
          reply.property = prop;
        } else if (req.target == atoms.gnome_copied_files && !gnome_copy.empty()) {
          XChangeProperty(dpy, req.requestor, prop, req.target, 8, PropModeReplace, reinterpret_cast<const unsigned char *>(gnome_copy.data()), static_cast<int>(gnome_copy.size()));
          reply.property = prop;
          served_uri_data = true;
        } else if (req.target == atoms.text_uri_list || req.target == atoms.utf8_string || req.target == atoms.text_plain || req.target == XA_STRING) {
          XChangeProperty(dpy, req.requestor, prop, req.target, 8, PropModeReplace, reinterpret_cast<const unsigned char *>(uri_list.data()), static_cast<int>(uri_list.size()));
          reply.property = prop;
          served_uri_data = true;
        }
      }
      XSendEvent(dpy, req.requestor, False, NoEventMask, reinterpret_cast<XEvent *>(&reply));
      XFlush(dpy);
      return served_uri_data;
    }

  }  // namespace

  drop_delivery_status_e deliver_xdnd_drop(double nx, double ny, const std::vector<std::string> &uris) {
    if (uris.empty()) {
      return drop_delivery_status_e::rejected;
    }
    const char *display_env = std::getenv("DISPLAY");
    if (!display_env || *display_env == '\0') {
      return drop_delivery_status_e::unavailable;
    }
    Display *dpy = XOpenDisplay(display_env);
    if (!dpy) {
      return drop_delivery_status_e::unavailable;
    }

    Window src_win = None;
    auto cleanup = [&]() {
      if (src_win != None) {
        XDestroyWindow(dpy, src_win);
      }
      XCloseDisplay(dpy);
    };

    const int screen = DefaultScreen(dpy);
    const Window root = RootWindow(dpy, screen);
    const auto [x_px, y_px] = map_normalized_to_screen(nx, ny, DisplayWidth(dpy, screen), DisplayHeight(dpy, screen));

    src_win = XCreateSimpleWindow(dpy, root, -10, -10, 1, 1, 0, 0, 0);
    if (src_win == None) {
      cleanup();
      return drop_delivery_status_e::unavailable;
    }

    xdnd_atoms_t atoms {
      .xdnd_selection = XInternAtom(dpy, "XdndSelection", False),
      .xdnd_aware = XInternAtom(dpy, "XdndAware", False),
      .xdnd_proxy = XInternAtom(dpy, "XdndProxy", False),
      .xdnd_enter = XInternAtom(dpy, "XdndEnter", False),
      .xdnd_position = XInternAtom(dpy, "XdndPosition", False),
      .xdnd_status = XInternAtom(dpy, "XdndStatus", False),
      .xdnd_leave = XInternAtom(dpy, "XdndLeave", False),
      .xdnd_drop = XInternAtom(dpy, "XdndDrop", False),
      .xdnd_finished = XInternAtom(dpy, "XdndFinished", False),
      .xdnd_action_copy = XInternAtom(dpy, "XdndActionCopy", False),
      .targets = XInternAtom(dpy, "TARGETS", False),
      .text_uri_list = XInternAtom(dpy, "text/uri-list", False),
      .gnome_copied_files = XInternAtom(dpy, "x-special/gnome-copied-files", False),
      .utf8_string = XInternAtom(dpy, "UTF8_STRING", False),
      .text_plain = XInternAtom(dpy, "text/plain", False),
    };

    Window target_win = None;
    Window dispatch_win = None;
    long xdnd_version = 5;
    if (!find_xdnd_target(dpy, root, x_px, y_px, src_win, atoms, target_win, dispatch_win, xdnd_version)) {
      cleanup();
      return drop_delivery_status_e::no_target;
    }

    XSetSelectionOwner(dpy, atoms.xdnd_selection, src_win, CurrentTime);
    if (XGetSelectionOwner(dpy, atoms.xdnd_selection) != src_win) {
      cleanup();
      return drop_delivery_status_e::rejected;
    }

    const std::string uri_list = build_uri_list_payload(uris);
    const std::string gnome_copy = build_gnome_copy_payload(uris);

    // 1. XdndEnter
    send_client_message(
      dpy,
      dispatch_win,
      atoms.xdnd_enter,
      static_cast<long>(src_win),
      xdnd_version << 24,
      static_cast<long>(atoms.text_uri_list),
      static_cast<long>(atoms.gnome_copied_files),
      static_cast<long>(None)
    );

    // 2. XdndPosition
    send_client_message(
      dpy,
      dispatch_win,
      atoms.xdnd_position,
      static_cast<long>(src_win),
      0,
      ((static_cast<long>(x_px) & 0xFFFFL) << 16) | (static_cast<long>(y_px) & 0xFFFFL),
      CurrentTime,
      static_cast<long>(atoms.xdnd_action_copy)
    );

    const int xfd = ConnectionNumber(dpy);
    bool got_status = false;
    bool status_ok = false;
    const auto status_deadline = steady::now() + std::chrono::milliseconds {1500};
    while (!got_status && steady::now() < status_deadline) {
      while (XPending(dpy) > 0 && !got_status) {
        XEvent ev;
        XNextEvent(dpy, &ev);
        if (ev.type == SelectionRequest) {
          handle_selection_request(dpy, src_win, ev.xselectionrequest, atoms, uri_list, gnome_copy);
        } else if (ev.type == ClientMessage && ev.xclient.message_type == atoms.xdnd_status) {
          const Window responder = static_cast<Window>(ev.xclient.data.l[0]);
          if (responder == target_win || responder == dispatch_win) {
            status_ok = (ev.xclient.data.l[1] & 1L) != 0;
            got_status = true;
          }
        }
      }
      if (got_status) {
        break;
      }
      const auto rem_ms = std::chrono::ceil<std::chrono::milliseconds>(status_deadline - steady::now()).count();
      if (rem_ms <= 0) {
        break;
      }
      pollfd pfd {xfd, POLLIN, 0};
      const int pr = poll(&pfd, 1, static_cast<int>(rem_ms));
      if (pr == 0 || (pr < 0 && errno != EINTR)) {
        break;
      }
    }

    if (!status_ok) {
      send_client_message(dpy, dispatch_win, atoms.xdnd_leave, static_cast<long>(src_win), 0, 0, 0, 0);
      cleanup();
      return drop_delivery_status_e::rejected;
    }

    // 3. XdndDrop
    send_client_message(
      dpy,
      dispatch_win,
      atoms.xdnd_drop,
      static_cast<long>(src_win),
      0,
      CurrentTime,
      0,
      0
    );

    bool served_uri = false;
    bool finished = false;
    bool finish_accepted = false;
    const auto drop_deadline = steady::now() + std::chrono::milliseconds {5000};
    while (!finished && steady::now() < drop_deadline) {
      while (XPending(dpy) > 0 && !finished) {
        XEvent ev;
        XNextEvent(dpy, &ev);
        if (ev.type == SelectionRequest) {
          if (handle_selection_request(dpy, src_win, ev.xselectionrequest, atoms, uri_list, gnome_copy)) {
            served_uri = true;
          }
        } else if (ev.type == ClientMessage && ev.xclient.message_type == atoms.xdnd_finished) {
          const Window responder = static_cast<Window>(ev.xclient.data.l[0]);
          if (responder == target_win || responder == dispatch_win) {
            finished = true;
            finish_accepted = (xdnd_version < 5) || ((ev.xclient.data.l[1] & 1L) != 0);
          }
        }
      }
      if (finished) {
        break;
      }
      const auto rem_ms = std::chrono::ceil<std::chrono::milliseconds>(drop_deadline - steady::now()).count();
      if (rem_ms <= 0) {
        break;
      }
      pollfd pfd {xfd, POLLIN, 0};
      const int pr = poll(&pfd, 1, static_cast<int>(rem_ms));
      if (pr == 0 || (pr < 0 && errno != EINTR)) {
        break;
      }
    }

    cleanup();
    if (finished) {
      return finish_accepted ? drop_delivery_status_e::accepted : drop_delivery_status_e::rejected;
    }
    return served_uri ? drop_delivery_status_e::accepted : drop_delivery_status_e::rejected;
  }

}  // namespace platf::xdnd
