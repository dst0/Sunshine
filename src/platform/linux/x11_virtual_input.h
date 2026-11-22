/** @file src/platform/linux/x11_virtual_input.h
 *  @brief Keyboard and mouse delivery for a dedicated local Xvfb display.
 */
#pragma once

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>

#include <sys/stat.h>
#include <unistd.h>
#include <X11/XF86keysym.h>
#include <X11/Xlib.h>
#include <X11/extensions/XTest.h>
#include <X11/keysym.h>

namespace platf::x11_virtual_input {
  /** @brief Translate a Moonlight Windows virtual key into a host layout symbol. */
  inline KeySym key_symbol(std::uint16_t vk, bool extended) {
    if (vk >= 0x30 && vk <= 0x39) return XK_0 + vk - 0x30;
    if (vk >= 0x41 && vk <= 0x5A) return XK_a + vk - 0x41;
    if (vk >= 0x60 && vk <= 0x69) return XK_KP_0 + vk - 0x60;
    if (vk >= 0x70 && vk <= 0x87) return XK_F1 + vk - 0x70;
    switch (vk) {
      case 0x08: return XK_BackSpace;
      case 0x09: return XK_Tab;
      case 0x0C: return XK_Clear;
      case 0x0D: return extended ? XK_KP_Enter : XK_Return;
      case 0x10: case 0xA0: return XK_Shift_L;
      case 0x11: case 0xA2: return XK_Control_L;
      case 0x12: case 0xA4: return XK_Alt_L;
      case 0x13: return XK_Pause;
      case 0x14: return XK_Caps_Lock;
      case 0x1B: return XK_Escape;
      case 0x20: return XK_space;
      case 0x21: return XK_Page_Up;
      case 0x22: return XK_Page_Down;
      case 0x23: return XK_End;
      case 0x24: return XK_Home;
      case 0x25: return XK_Left;
      case 0x26: return XK_Up;
      case 0x27: return XK_Right;
      case 0x28: return XK_Down;
      case 0x2C: return XK_Print;
      case 0x2D: return XK_Insert;
      case 0x2E: return XK_Delete;
      case 0x5B: return XK_Super_L;
      case 0x5C: return XK_Super_R;
      case 0x5D: return XK_Menu;
      case 0x6A: return XK_KP_Multiply;
      case 0x6B: return XK_KP_Add;
      case 0x6C: return XK_KP_Separator;
      case 0x6D: return XK_KP_Subtract;
      case 0x6E: return XK_KP_Decimal;
      case 0x6F: return XK_KP_Divide;
      case 0x90: return XK_Num_Lock;
      case 0x91: return XK_Scroll_Lock;
      case 0xA1: return XK_Shift_R;
      case 0xA3: return XK_Control_R;
      case 0xA5: return XK_Alt_R;
      case 0xAD: return XF86XK_AudioMute;
      case 0xAE: return XF86XK_AudioLowerVolume;
      case 0xAF: return XF86XK_AudioRaiseVolume;
      case 0xB0: return XF86XK_AudioNext;
      case 0xB1: return XF86XK_AudioPrev;
      case 0xB2: return XF86XK_AudioStop;
      case 0xB3: return XF86XK_AudioPlay;
      case 0xBA: return XK_semicolon;
      case 0xBB: return XK_equal;
      case 0xBC: return XK_comma;
      case 0xBD: return XK_minus;
      case 0xBE: return XK_period;
      case 0xBF: return XK_slash;
      case 0xC0: return XK_grave;
      case 0xDB: return XK_bracketleft;
      case 0xDC: return XK_backslash;
      case 0xDD: return XK_bracketright;
      case 0xDE: return XK_apostrophe;
      case 0xE2: return XK_less;
      case 0x100: return XK_Undo;
      case 0x101: return XF86XK_Cut;
      case 0x102: return XF86XK_Copy;
      case 0x103: return XF86XK_Paste;
      default: return NoSymbol;
    }
  }

  /** @brief XTEST input connection confined to a private local X server. */
  class session_t {
  public:
    /** @brief Connect only if both the opt-in and private X authority match the service. */
    session_t() {
      const auto *target = std::getenv("SUNSHINE_PRIVATE_X11_INPUT");
      const auto *display = std::getenv("DISPLAY");
      const auto *auth = std::getenv("XAUTHORITY");
      const auto uid = geteuid();
      const auto directory = "/run/user/" + std::to_string(uid) + "/sds-minipc-display";
      struct stat dir {}, file {};
      if (!uid || !target || !display || !auth || std::string_view {target} != ":97" ||
          std::string_view {display} != target || auth != directory + "/Xauthority" ||
          lstat(directory.c_str(), &dir) || !S_ISDIR(dir.st_mode) || dir.st_uid != uid || (dir.st_mode & 0077) ||
          lstat(auth, &file) || !S_ISREG(file.st_mode) || file.st_uid != uid || (file.st_mode & 0077) || !file.st_size) {
        return;
      }
      connection.reset(XOpenDisplay(display));
      int event {}, error {}, major {}, minor {};
      if (connection && (!XTestQueryExtension(connection.get(), &event, &error, &major, &minor) || major < 2 ||
                         (major == 2 && minor < 2))) {
        connection.reset();
      }
    }

    /** @brief Report whether the private server accepted the authorized connection. */
    explicit operator bool() const { return bool(connection); }

    /** @brief Send a press or release using the server's keyboard layout. */
    void key(std::uint16_t vk, bool release, bool extended) {
      const std::lock_guard lock {mutex};
      const auto symbol = key_symbol(vk, extended);
      if (!connection || symbol == NoSymbol) return;
      if (const auto code = XKeysymToKeycode(connection.get(), symbol)) {
        XTestFakeKeyEvent(connection.get(), code, !release, CurrentTime);
        XFlush(connection.get());
      }
    }

    /** @brief Send a relative move within the private display. */
    void move(int dx, int dy) {
      const std::lock_guard lock {mutex};
      if (!connection) return;
      XTestFakeRelativeMotionEvent(connection.get(), std::clamp(dx, -32767, 32767), std::clamp(dy, -32767, 32767), CurrentTime);
      XFlush(connection.get());
    }

    /** @brief Clamp desktop-space coordinates to the private Xvfb screen. */
    void absolute(float x, float y) {
      const std::lock_guard lock {mutex};
      if (!connection || !std::isfinite(x) || !std::isfinite(y)) return;
      auto *d = connection.get();
      auto screen = DefaultScreen(d);
      XTestFakeMotionEvent(d, screen,
        static_cast<int>(std::clamp(x, 0.f, static_cast<float>(DisplayWidth(d, screen) - 1))),
        static_cast<int>(std::clamp(y, 0.f, static_cast<float>(DisplayHeight(d, screen) - 1))), CurrentTime);
      XFlush(d);
    }

    /** @brief Send a mouse button transition; preserve X11's wheel numbering. */
    void button(int button, bool release) {
      constexpr std::array buttons {1, 2, 3, 8, 9};
      const std::lock_guard lock {mutex};
      if (!connection || button < 1 || button > static_cast<int>(buttons.size())) return;
      XTestFakeButtonEvent(connection.get(), buttons[button - 1], !release, CurrentTime);
      XFlush(connection.get());
    }

    /** @brief Accumulate high-resolution wheel distances into X11 wheel steps. */
    void scroll(int distance, bool horizontal) {
      const std::lock_guard lock {mutex};
      if (!connection) return;
      auto &remainder = horizontal ? horizontal_remainder : vertical_remainder;
      const int total = remainder + std::clamp(distance, -32767, 32767);
      const int steps = total / 120;
      remainder = total % 120;
      const unsigned button = horizontal ? (steps > 0 ? 7 : 6) : (steps > 0 ? 4 : 5);
      for (int i = 0; i < std::abs(steps); ++i) {
        XTestFakeButtonEvent(connection.get(), button, true, CurrentTime);
        XTestFakeButtonEvent(connection.get(), button, false, CurrentTime);
      }
      if (steps) XFlush(connection.get());
    }

  private:
    /** @brief Close an Xlib display owned by this backend. */
    struct close_t { void operator()(Display *d) const { XCloseDisplay(d); } };
    std::unique_ptr<Display, close_t> connection;  ///< Owned server connection, never shared with host input.
    std::mutex mutex;  ///< Serializes events, including wheel press/release pairs.
    int vertical_remainder = 0;  ///< Vertical wheel distance below one tick.
    int horizontal_remainder = 0;  ///< Horizontal wheel distance below one tick.
  };
}
