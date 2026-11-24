/**
 * @file src/platform/linux/x11_display_mode.cpp
 * @brief X11 XRandR host resolution switching and CVT 1.2 reduced-blanking mode creation.
 */

#include "x11_display_mode.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <mutex>
#include <string_view>
#include <vector>

#include <X11/extensions/Xrandr.h>
#include <X11/Xatom.h>
#include <X11/Xlib.h>

#include "misc.h"
#include "src/logging.h"
#include "src/platform/common.h"

namespace platf::x11_mode {

  static_assert(CVT_HSYNC_POSITIVE == RR_HSyncPositive, "HSync flag mismatch with Xrandr.h");
  static_assert(CVT_VSYNC_NEGATIVE == RR_VSyncNegative, "VSync flag mismatch with Xrandr.h");

  bool validate_mode_params(int width, int height, int fps) {
    if (width < 640 || width > 7680 || (width % 2) != 0) {
      return false;
    }
    if (height < 480 || height > 4320 || (height % 2) != 0) {
      return false;
    }
    if (fps < 24 || fps > 240) {
      return false;
    }
    return true;
  }

  std::optional<cvt_mode_t> compute_cvt_rb_mode(int width, int height, int fps) {
    if (!validate_mode_params(width, height, fps)) {
      return std::nullopt;
    }

    constexpr int rb_h_blank = 160;
    constexpr int rb_h_sync = 32;
    constexpr int rb_h_fporch = 48;
    constexpr int rb_v_fporch = 3;
    constexpr int rb_min_v_bporch = 6;
    constexpr double rb_min_v_blank_us = 460.0;
    constexpr double clock_step_mhz = 0.25;

    unsigned int v_sync = 10;
    if (width * 3 == height * 4) {
      v_sync = 4;
    } else if (width * 9 == height * 16) {
      v_sync = 5;
    } else if (width * 10 == height * 16) {
      v_sync = 6;
    } else if (width * 4 == height * 5 || width * 9 == height * 15) {
      v_sync = 7;
    }

    const unsigned int h_total = static_cast<unsigned int>(width + rb_h_blank);
    const unsigned int h_sync_start = static_cast<unsigned int>(width + rb_h_fporch);
    const unsigned int h_sync_end = h_sync_start + rb_h_sync;

    const double h_period_est = ((1000000.0 / static_cast<double>(fps)) - rb_min_v_blank_us) / static_cast<double>(height);
    if (h_period_est <= 0.0) {
      return std::nullopt;
    }

    const int vbi_lines = static_cast<int>(rb_min_v_blank_us / h_period_est) + 1;
    const unsigned int min_vbi = static_cast<unsigned int>(rb_v_fporch) + v_sync + static_cast<unsigned int>(rb_min_v_bporch);
    const unsigned int v_blank = std::max(static_cast<unsigned int>(std::max(vbi_lines, 1)), min_vbi);
    const unsigned int v_total = static_cast<unsigned int>(height) + v_blank;
    const unsigned int v_sync_start = static_cast<unsigned int>(height + rb_v_fporch);
    const unsigned int v_sync_end = v_sync_start + v_sync;

    const double pclk_mhz = clock_step_mhz * std::floor((static_cast<double>(h_total) / h_period_est) / clock_step_mhz);
    if (pclk_mhz <= 0.0) {
      return std::nullopt;
    }

    return cvt_mode_t {
      .width = width,
      .height = height,
      .fps = fps,
      .dot_clock_hz = static_cast<unsigned long>(std::llround(pclk_mhz * 1000000.0)),
      .h_sync_start = h_sync_start,
      .h_sync_end = h_sync_end,
      .h_total = h_total,
      .v_sync_start = v_sync_start,
      .v_sync_end = v_sync_end,
      .v_total = v_total,
      .mode_flags = CVT_HSYNC_POSITIVE | CVT_VSYNC_NEGATIVE,
      .name = std::to_string(width) + "x" + std::to_string(height) + "R_" + std::to_string(fps),
    };
  }

  namespace {

    struct xrr_api_t {
      static inline decltype(&XRRGetScreenResourcesCurrent) GetScreenResourcesCurrent = nullptr;
      static inline decltype(&XRRGetScreenResources) GetScreenResources = nullptr;
      static inline decltype(&XRRFreeScreenResources) FreeScreenResources = nullptr;
      static inline decltype(&XRRGetOutputInfo) GetOutputInfo = nullptr;
      static inline decltype(&XRRFreeOutputInfo) FreeOutputInfo = nullptr;
      static inline decltype(&XRRGetCrtcInfo) GetCrtcInfo = nullptr;
      static inline decltype(&XRRFreeCrtcInfo) FreeCrtcInfo = nullptr;
      static inline decltype(&XRRGetOutputPrimary) GetOutputPrimary = nullptr;
      static inline decltype(&XRRGetScreenSizeRange) GetScreenSizeRange = nullptr;
      static inline decltype(&XRRCreateMode) CreateMode = nullptr;
      static inline decltype(&XRRDestroyMode) DestroyMode = nullptr;
      static inline decltype(&XRRAddOutputMode) AddOutputMode = nullptr;
      static inline decltype(&XRRDeleteOutputMode) DeleteOutputMode = nullptr;
      static inline decltype(&XRRSetCrtcConfig) SetCrtcConfig = nullptr;
      static inline decltype(&XRRSetScreenSize) SetScreenSize = nullptr;
      static inline decltype(&XRRGetOutputProperty) GetOutputProperty = nullptr;
      static inline decltype(&XRRGetProviderResources) GetProviderResources = nullptr;
      static inline decltype(&XRRFreeProviderResources) FreeProviderResources = nullptr;
      static inline decltype(&XRRGetProviderInfo) GetProviderInfo = nullptr;
      static inline decltype(&XRRFreeProviderInfo) FreeProviderInfo = nullptr;

      static bool load() {
        static std::once_flag load_once;
        static bool loaded_ok = false;
        std::call_once(load_once, []() {
          dyn::library_t *handle = dyn::handle({"libXrandr.so.2", "libXrandr.so"});
          if (!handle) {
            return;
          }
          std::vector<std::tuple<dyn::apiproc *, const char *>> funcs {
            {reinterpret_cast<dyn::apiproc *>(&GetScreenResourcesCurrent), "XRRGetScreenResourcesCurrent"},
            {reinterpret_cast<dyn::apiproc *>(&GetScreenResources), "XRRGetScreenResources"},
            {reinterpret_cast<dyn::apiproc *>(&FreeScreenResources), "XRRFreeScreenResources"},
            {reinterpret_cast<dyn::apiproc *>(&GetOutputInfo), "XRRGetOutputInfo"},
            {reinterpret_cast<dyn::apiproc *>(&FreeOutputInfo), "XRRFreeOutputInfo"},
            {reinterpret_cast<dyn::apiproc *>(&GetCrtcInfo), "XRRGetCrtcInfo"},
            {reinterpret_cast<dyn::apiproc *>(&FreeCrtcInfo), "XRRFreeCrtcInfo"},
            {reinterpret_cast<dyn::apiproc *>(&GetOutputPrimary), "XRRGetOutputPrimary"},
            {reinterpret_cast<dyn::apiproc *>(&GetScreenSizeRange), "XRRGetScreenSizeRange"},
            {reinterpret_cast<dyn::apiproc *>(&CreateMode), "XRRCreateMode"},
            {reinterpret_cast<dyn::apiproc *>(&DestroyMode), "XRRDestroyMode"},
            {reinterpret_cast<dyn::apiproc *>(&AddOutputMode), "XRRAddOutputMode"},
            {reinterpret_cast<dyn::apiproc *>(&DeleteOutputMode), "XRRDeleteOutputMode"},
            {reinterpret_cast<dyn::apiproc *>(&SetCrtcConfig), "XRRSetCrtcConfig"},
            {reinterpret_cast<dyn::apiproc *>(&SetScreenSize), "XRRSetScreenSize"},
          };
          if (dyn::load(handle, funcs) != 0) {
            return;
          }
          std::vector<std::tuple<dyn::apiproc *, const char *>> opt_funcs {
            {reinterpret_cast<dyn::apiproc *>(&GetOutputProperty), "XRRGetOutputProperty"},
            {reinterpret_cast<dyn::apiproc *>(&GetProviderResources), "XRRGetProviderResources"},
            {reinterpret_cast<dyn::apiproc *>(&FreeProviderResources), "XRRFreeProviderResources"},
            {reinterpret_cast<dyn::apiproc *>(&GetProviderInfo), "XRRGetProviderInfo"},
            {reinterpret_cast<dyn::apiproc *>(&FreeProviderInfo), "XRRFreeProviderInfo"},
          };
          (void) dyn::load(handle, opt_funcs, false);
          loaded_ok = true;
        });
        return loaded_ok;
      }
    };

    struct saved_mode_state_t {
      std::string display_name;
      RROutput output = None;
      RRCrtc crtc = None;
      RRMode orig_mode = None;
      int orig_x = 0;
      int orig_y = 0;
      Rotation orig_rotation = RR_Rotate_0;
      std::vector<RROutput> orig_outputs;
      int orig_screen_w = 0;
      int orig_screen_h = 0;
      int orig_screen_mm_w = 0;
      int orig_screen_mm_h = 0;
      RRMode created_custom_mode = None;
    };

    std::mutex mode_mutex;
    std::optional<saved_mode_state_t> saved_mode_state;

    struct display_guard_t {
      Display *dpy = nullptr;
      ~display_guard_t() {
        if (dpy) {
          XCloseDisplay(dpy);
        }
      }
    };

    struct server_grab_guard_t {
      Display *dpy = nullptr;
      explicit server_grab_guard_t(Display *d):
          dpy(d) {
        if (dpy) {
          XGrabServer(dpy);
        }
      }
      ~server_grab_guard_t() {
        if (dpy) {
          XUngrabServer(dpy);
          XSync(dpy, False);
        }
      }
    };

    double mode_refresh_hz(const XRRModeInfo &mode) {
      if (mode.hTotal == 0 || mode.vTotal == 0 || mode.dotClock == 0) {
        return 0.0;
      }
      double v_total = static_cast<double>(mode.vTotal);
      if (mode.modeFlags & RR_DoubleScan) {
        v_total *= 2.0;
      }
      if (mode.modeFlags & RR_Interlace) {
        v_total *= 0.5;
      }
      return static_cast<double>(mode.dotClock) / (static_cast<double>(mode.hTotal) * v_total);
    }

    const XRRModeInfo *find_mode_by_id(const XRRScreenResources *res, RRMode mode_id) {
      for (int i = 0; i < res->nmode; ++i) {
        if (res->modes[i].id == mode_id) {
          return &res->modes[i];
        }
      }
      return nullptr;
    }

    RRMode find_best_existing_mode(const XRRScreenResources *res, const XRROutputInfo *out_info, int width, int height, int fps) {
      RRMode best_mode = None;
      double best_diff = std::numeric_limits<double>::max();
      for (int i = 0; i < out_info->nmode; ++i) {
        const auto *mode = find_mode_by_id(res, out_info->modes[i]);
        if (!mode) {
          continue;
        }
        if (static_cast<int>(mode->width) != width || static_cast<int>(mode->height) != height) {
          continue;
        }
        const double hz = mode_refresh_hz(*mode);
        const double diff = std::abs(hz - static_cast<double>(fps));
        if (diff <= 1.0 && diff < best_diff) {
          best_diff = diff;
          best_mode = mode->id;
        }
      }
      return best_mode;
    }

    bool select_active_output(
      Display *dpy,
      Window root,
      const xrr_api_t &xrr,
      const XRRScreenResources *res,
      RROutput &out_id,
      XRROutputInfo *&out_info,
      RRCrtc &crtc_id,
      XRRCrtcInfo *&crtc_info
    ) {
      out_id = None;
      out_info = nullptr;
      crtc_id = None;
      crtc_info = nullptr;

      std::vector<RROutput> candidates;
      const RROutput primary = xrr.GetOutputPrimary(dpy, root);
      if (primary != None) {
        candidates.push_back(primary);
      }
      for (int i = 0; i < res->noutput; ++i) {
        if (res->outputs[i] != primary) {
          candidates.push_back(res->outputs[i]);
        }
      }

      for (RROutput candidate : candidates) {
        XRROutputInfo *info = xrr.GetOutputInfo(dpy, const_cast<XRRScreenResources *>(res), candidate);
        if (!info) {
          continue;
        }
        if (info->connection != RR_Connected || info->crtc == None) {
          xrr.FreeOutputInfo(info);
          continue;
        }
        XRRCrtcInfo *cinfo = xrr.GetCrtcInfo(dpy, const_cast<XRRScreenResources *>(res), info->crtc);
        if (!cinfo || cinfo->mode == None) {
          if (cinfo) {
            xrr.FreeCrtcInfo(cinfo);
          }
          xrr.FreeOutputInfo(info);
          continue;
        }
        out_id = candidate;
        out_info = info;
        crtc_id = info->crtc;
        crtc_info = cinfo;
        return true;
      }
      return false;
    }

    void compute_screen_bounds(
      Display *dpy,
      const xrr_api_t &xrr,
      const XRRScreenResources *res,
      RRCrtc target_crtc,
      int target_x,
      int target_y,
      int target_w,
      int target_h,
      int &screen_w,
      int &screen_h
    ) {
      screen_w = target_x + target_w;
      screen_h = target_y + target_h;
      for (int i = 0; i < res->ncrtc; ++i) {
        if (res->crtcs[i] == target_crtc) {
          continue;
        }
        XRRCrtcInfo *other = xrr.GetCrtcInfo(dpy, const_cast<XRRScreenResources *>(res), res->crtcs[i]);
        if (!other) {
          continue;
        }
        if (other->mode != None && other->width > 0 && other->height > 0) {
          screen_w = std::max(screen_w, other->x + static_cast<int>(other->width));
          screen_h = std::max(screen_h, other->y + static_cast<int>(other->height));
        }
        xrr.FreeCrtcInfo(other);
      }
    }

    Status apply_crtc_and_screen(
      Display *dpy,
      Window root,
      const xrr_api_t &xrr,
      XRRScreenResources *res,
      RRCrtc crtc_id,
      int crtc_x,
      int crtc_y,
      RRMode target_mode,
      Rotation rotation,
      RROutput *outputs,
      int noutput,
      int cur_screen_w,
      int cur_screen_h,
      int cur_mm_w,
      int cur_mm_h,
      int new_screen_w,
      int new_screen_h,
      int new_mm_w,
      int new_mm_h
    ) {
      const bool growing = (new_screen_w > cur_screen_w || new_screen_h > cur_screen_h);
      if (growing) {
        xrr.SetScreenSize(dpy, root, new_screen_w, new_screen_h, new_mm_w, new_mm_h);
      }
      Status status = xrr.SetCrtcConfig(
        dpy,
        res,
        crtc_id,
        CurrentTime,
        crtc_x,
        crtc_y,
        target_mode,
        rotation,
        outputs,
        noutput
      );
      if (status != RRSetConfigSuccess) {
        if (growing) {
          xrr.SetScreenSize(dpy, root, cur_screen_w, cur_screen_h, cur_mm_w, cur_mm_h);
        }
        return status;
      }
      if (!growing && (new_screen_w != cur_screen_w || new_screen_h != cur_screen_h)) {
        xrr.SetScreenSize(dpy, root, new_screen_w, new_screen_h, new_mm_w, new_mm_h);
      }
      return RRSetConfigSuccess;
    }

  }  // namespace

  bool apply_and_maybe_save(int width, int height, int fps, bool revert) {
    if (!validate_mode_params(width, height, fps)) {
      BOOST_LOG(warning) << "Refusing invalid host resolution request: "sv << width << 'x' << height << '@' << fps;
      return false;
    }

    std::lock_guard lock(mode_mutex);
    if (!revert) {
      saved_mode_state.reset();
    }

    const char *display_raw = std::getenv("DISPLAY");
    if (!display_raw || *display_raw == '\0') {
      return true;  // Non-X11 session (e.g. Wayland/KMS); nothing for X11 XRandR to do.
    }
    const std::string display_env {display_raw};

    xrr_api_t xrr;
    if (!xrr.load()) {
      BOOST_LOG(warning) << "libXrandr.so.2 unavailable; skipping X11 host resolution switch"sv;
      return false;
    }

    display_guard_t dpy_guard {XOpenDisplay(display_env.c_str())};
    if (!dpy_guard.dpy) {
      BOOST_LOG(warning) << "Failed to open X11 display ["sv << display_env << "] for resolution switch"sv;
      return false;
    }
    Display *dpy = dpy_guard.dpy;
    const int screen = DefaultScreen(dpy);
    const Window root = RootWindow(dpy, screen);

    server_grab_guard_t grab(dpy);
    XRRScreenResources *res = xrr.GetScreenResourcesCurrent(dpy, root);
    if (!res) {
      res = xrr.GetScreenResources(dpy, root);
    }
    if (!res) {
      BOOST_LOG(warning) << "XRRGetScreenResources returned null; skipping X11 host resolution switch"sv;
      return false;
    }

    RROutput out_id = None;
    XRROutputInfo *out_info = nullptr;
    RRCrtc crtc_id = None;
    XRRCrtcInfo *crtc_info = nullptr;
    const bool found_output = select_active_output(dpy, root, xrr, res, out_id, out_info, crtc_id, crtc_info);

    auto cleanup = [&]() {
      if (crtc_info) {
        xrr.FreeCrtcInfo(crtc_info);
      }
      if (out_info) {
        xrr.FreeOutputInfo(out_info);
      }
      if (res) {
        xrr.FreeScreenResources(res);
      }
    };

    if (!found_output) {
      BOOST_LOG(warning) << "No connected active X11 output found for resolution switch"sv;
      cleanup();
      return false;
    }

    const XRRModeInfo *cur_mode = find_mode_by_id(res, crtc_info->mode);
    const bool already_matches =
      cur_mode &&
      static_cast<int>(cur_mode->width) == width &&
      static_cast<int>(cur_mode->height) == height &&
      std::abs(mode_refresh_hz(*cur_mode) - static_cast<double>(fps)) <= 0.5;

    if (already_matches) {
      cleanup();
      return true;
    }

    int min_w = 0, min_h = 0, max_w = 0, max_h = 0;
    if (!xrr.GetScreenSizeRange(dpy, root, &min_w, &min_h, &max_w, &max_h)) {
      BOOST_LOG(warning) << "XRRGetScreenSizeRange failed; skipping X11 resolution switch"sv;
      cleanup();
      return false;
    }

    int new_screen_w = 0;
    int new_screen_h = 0;
    compute_screen_bounds(dpy, xrr, res, crtc_id, crtc_info->x, crtc_info->y, width, height, new_screen_w, new_screen_h);
    if (new_screen_w < min_w || new_screen_w > max_w || new_screen_h < min_h || new_screen_h > max_h) {
      BOOST_LOG(warning) << "Requested X11 resolution " << new_screen_w << 'x' << new_screen_h
                         << " exceeds screen size range [" << min_w << 'x' << min_h << " .. " << max_w << 'x' << max_h << ']';
      cleanup();
      return false;
    }

    const int cur_screen_w = DisplayWidth(dpy, screen);
    const int cur_screen_h = DisplayHeight(dpy, screen);
    const int cur_mm_w = DisplayWidthMM(dpy, screen);
    const int cur_mm_h = DisplayHeightMM(dpy, screen);
    const int new_mm_w = std::max(1, static_cast<int>(std::llround(static_cast<double>(new_screen_w) * cur_mm_w / std::max(1, cur_screen_w))));
    const int new_mm_h = std::max(1, static_cast<int>(std::llround(static_cast<double>(new_screen_h) * cur_mm_h / std::max(1, cur_screen_h))));

    RRMode target_mode = find_best_existing_mode(res, out_info, width, height, fps);
    RRMode created_mode = None;
    if (target_mode == None) {
      const auto cvt = compute_cvt_rb_mode(width, height, fps);
      if (!cvt) {
        cleanup();
        return false;
      }
      XRRModeInfo mode_info {};
      std::string name_copy = cvt->name;
      mode_info.width = static_cast<unsigned int>(cvt->width);
      mode_info.height = static_cast<unsigned int>(cvt->height);
      mode_info.dotClock = cvt->dot_clock_hz;
      mode_info.hSyncStart = cvt->h_sync_start;
      mode_info.hSyncEnd = cvt->h_sync_end;
      mode_info.hTotal = cvt->h_total;
      mode_info.vSyncStart = cvt->v_sync_start;
      mode_info.vSyncEnd = cvt->v_sync_end;
      mode_info.vTotal = cvt->v_total;
      mode_info.modeFlags = cvt->mode_flags;
      mode_info.name = name_copy.data();
      mode_info.nameLength = static_cast<int>(name_copy.size());

      created_mode = xrr.CreateMode(dpy, root, &mode_info);
      if (created_mode == None) {
        BOOST_LOG(warning) << "XRRCreateMode failed for "sv << cvt->name;
        cleanup();
        return false;
      }
      xrr.AddOutputMode(dpy, out_id, created_mode);
      XSync(dpy, False);
      target_mode = created_mode;
    }

    // Snapshot original state before switching if revert=true (preserving initial state if already saved).
    saved_mode_state_t candidate_save;
    candidate_save.display_name = display_env;
    candidate_save.output = out_id;
    candidate_save.crtc = crtc_id;
    candidate_save.orig_mode = crtc_info->mode;
    candidate_save.orig_x = crtc_info->x;
    candidate_save.orig_y = crtc_info->y;
    candidate_save.orig_rotation = crtc_info->rotation;
    candidate_save.orig_outputs.assign(crtc_info->outputs, crtc_info->outputs + crtc_info->noutput);
    candidate_save.orig_screen_w = cur_screen_w;
    candidate_save.orig_screen_h = cur_screen_h;
    candidate_save.orig_screen_mm_w = cur_mm_w;
    candidate_save.orig_screen_mm_h = cur_mm_h;
    candidate_save.created_custom_mode = created_mode;

    // Refresh screen resources so newly created mode ID is visible to SetCrtcConfig.
    XRRScreenResources *live_res = xrr.GetScreenResources(dpy, root);
    if (!live_res) {
      live_res = res;
    }
    const Status status = apply_crtc_and_screen(
      dpy,
      root,
      xrr,
      live_res,
      crtc_id,
      crtc_info->x,
      crtc_info->y,
      target_mode,
      crtc_info->rotation,
      crtc_info->outputs,
      crtc_info->noutput,
      cur_screen_w,
      cur_screen_h,
      cur_mm_w,
      cur_mm_h,
      new_screen_w,
      new_screen_h,
      new_mm_w,
      new_mm_h
    );
    if (live_res != res) {
      xrr.FreeScreenResources(live_res);
    }

    if (status != RRSetConfigSuccess) {
      BOOST_LOG(warning) << "XRRSetCrtcConfig failed with status " << status << " for " << width << 'x' << height << '@' << fps;
      if (created_mode != None) {
        xrr.DeleteOutputMode(dpy, out_id, created_mode);
        xrr.DestroyMode(dpy, created_mode);
      }
      cleanup();
      return false;
    }

    if (revert) {
      if (!saved_mode_state) {
        saved_mode_state = std::move(candidate_save);
      } else if (created_mode != None) {
        saved_mode_state->created_custom_mode = created_mode;
      }
    }

    BOOST_LOG(info) << "Switched X11 host resolution to " << width << 'x' << height << '@' << fps
                    << (revert ? " (will revert on stream end)" : " (kept after stream end)");
    cleanup();
    return true;
  }

  void revert_if_saved() {
    std::lock_guard lock(mode_mutex);
    if (!saved_mode_state) {
      return;
    }
    const auto state = std::move(*saved_mode_state);
    saved_mode_state.reset();

    xrr_api_t xrr;
    if (!xrr.load()) {
      return;
    }

    display_guard_t dpy_guard {XOpenDisplay(state.display_name.c_str())};
    if (!dpy_guard.dpy) {
      return;
    }
    Display *dpy = dpy_guard.dpy;
    const int screen = DefaultScreen(dpy);
    const Window root = RootWindow(dpy, screen);

    server_grab_guard_t grab(dpy);
    XRRScreenResources *res = xrr.GetScreenResources(dpy, root);
    if (!res) {
      return;
    }

    std::vector<RROutput> outputs = state.orig_outputs;
    const Status status = apply_crtc_and_screen(
      dpy,
      root,
      xrr,
      res,
      state.crtc,
      state.orig_x,
      state.orig_y,
      state.orig_mode,
      state.orig_rotation,
      outputs.empty() ? nullptr : outputs.data(),
      static_cast<int>(outputs.size()),
      DisplayWidth(dpy, screen),
      DisplayHeight(dpy, screen),
      DisplayWidthMM(dpy, screen),
      DisplayHeightMM(dpy, screen),
      state.orig_screen_w,
      state.orig_screen_h,
      state.orig_screen_mm_w,
      state.orig_screen_mm_h
    );

    if (state.created_custom_mode != None) {
      xrr.DeleteOutputMode(dpy, state.output, state.created_custom_mode);
      xrr.DestroyMode(dpy, state.created_custom_mode);
    }

    xrr.FreeScreenResources(res);
    BOOST_LOG(info) << "Reverted X11 host resolution to " << state.orig_screen_w << 'x' << state.orig_screen_h
                    << " (status=" << status << ')';
  }

  bool has_saved_mode() {
    std::lock_guard lock(mode_mutex);
    return saved_mode_state.has_value();
  }

  namespace {
    std::string lowercase_ascii(std::string_view sv) {
      std::string out(sv);
      std::transform(out.begin(), out.end(), out.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
      });
      return out;
    }

    std::string extract_pci_slot_from_provider_name(std::string_view name) {
      constexpr std::string_view marker = "@ pci:";
      const auto pos = name.find(marker);
      if (pos == std::string_view::npos) {
        return {};
      }
      auto rest = name.substr(pos + marker.size());
      const auto end = rest.find_first_of(" \t\r\n");
      if (end != std::string_view::npos) {
        rest = rest.substr(0, end);
      }
      // Accept standard domain:bus:dev.func ("0000:02:00.0").
      if (rest.size() == 12 && rest[4] == ':' && rest[7] == ':' && rest[10] == '.') {
        return lowercase_ascii(rest);
      }
      return {};
    }

    std::optional<unsigned long> query_output_connector_id(Display *dpy, const xrr_api_t &xrr, RROutput output) {
      if (!xrr.GetOutputProperty || output == None) {
        return std::nullopt;
      }
      const Atom conn_atom = XInternAtom(dpy, "CONNECTOR_ID", True);
      if (conn_atom == None) {
        return std::nullopt;
      }
      Atom actual_type = None;
      int actual_format = 0;
      unsigned long nitems = 0;
      unsigned long bytes_after = 0;
      unsigned char *prop = nullptr;
      const int status = xrr.GetOutputProperty(
        dpy,
        output,
        conn_atom,
        0,
        1,
        False,
        False,
        XA_INTEGER,
        &actual_type,
        &actual_format,
        &nitems,
        &bytes_after,
        &prop
      );
      if (status != Success || !prop) {
        return std::nullopt;
      }
      std::optional<unsigned long> result;
      if (actual_type == XA_INTEGER && actual_format == 32 && nitems >= 1) {
        result = *reinterpret_cast<const unsigned long *>(prop);
      }
      XFree(prop);
      return result;
    }
  }  // namespace

  std::string detect_active_display_pci() {
    const char *display_raw = std::getenv("DISPLAY");
    if (!display_raw || *display_raw == '\0') {
      return {};
    }

    xrr_api_t xrr;
    if (!xrr.load()) {
      return {};
    }

    display_guard_t dpy_guard {XOpenDisplay(display_raw)};
    if (!dpy_guard.dpy) {
      return {};
    }
    Display *dpy = dpy_guard.dpy;
    const Window root = RootWindow(dpy, DefaultScreen(dpy));

    XRRScreenResources *res = xrr.GetScreenResourcesCurrent(dpy, root);
    if (!res) {
      res = xrr.GetScreenResources(dpy, root);
    }
    if (!res) {
      return {};
    }

    std::string pci;
    RROutput out_id = None;
    XRROutputInfo *out_info = nullptr;
    RRCrtc crtc_id = None;
    XRRCrtcInfo *crtc_info = nullptr;
    if (select_active_output(dpy, root, xrr, res, out_id, out_info, crtc_id, crtc_info)) {
      if (const auto conn_id = query_output_connector_id(dpy, xrr, out_id)) {
        pci = drm_connector_id_pci_slot(*conn_id);
      }
      if (crtc_info) {
        xrr.FreeCrtcInfo(crtc_info);
      }
      if (out_info) {
        xrr.FreeOutputInfo(out_info);
      }
    }

    if (pci.empty() && xrr.GetProviderResources && xrr.FreeProviderResources && xrr.GetProviderInfo && xrr.FreeProviderInfo) {
      if (XRRProviderResources *prov_res = xrr.GetProviderResources(dpy, root)) {
        std::string fallback_pci;
        for (int i = 0; i < prov_res->nproviders; ++i) {
          XRRProviderInfo *pinfo = xrr.GetProviderInfo(dpy, res, prov_res->providers[i]);
          if (!pinfo) {
            continue;
          }
          const std::string candidate = pinfo->name ? extract_pci_slot_from_provider_name(pinfo->name) : std::string {};
          const bool is_source = (pinfo->capabilities & RR_Capability_SourceOutput) != 0;
          xrr.FreeProviderInfo(pinfo);
          if (candidate.empty()) {
            continue;
          }
          if (is_source) {
            pci = candidate;
            break;
          }
          if (fallback_pci.empty()) {
            fallback_pci = candidate;
          }
        }
        if (pci.empty()) {
          pci = std::move(fallback_pci);
        }
        xrr.FreeProviderResources(prov_res);
      }
    }

    xrr.FreeScreenResources(res);
    return pci;
  }

  std::string find_output_name_for_pci(std::string_view pci_slot) {
    const std::string target_pci = lowercase_ascii(pci_slot);
    if (target_pci.empty()) {
      return {};
    }
    const char *display_raw = std::getenv("DISPLAY");
    if (!display_raw || *display_raw == '\0') {
      return {};
    }

    xrr_api_t xrr;
    if (!xrr.load()) {
      return {};
    }

    display_guard_t dpy_guard {XOpenDisplay(display_raw)};
    if (!dpy_guard.dpy) {
      return {};
    }
    Display *dpy = dpy_guard.dpy;
    const Window root = RootWindow(dpy, DefaultScreen(dpy));

    XRRScreenResources *res = xrr.GetScreenResourcesCurrent(dpy, root);
    if (!res) {
      res = xrr.GetScreenResources(dpy, root);
    }
    if (!res) {
      return {};
    }

    const RROutput primary = xrr.GetOutputPrimary(dpy, root);
    std::vector<RROutput> candidates;
    if (primary != None) {
      candidates.push_back(primary);
    }
    for (int i = 0; i < res->noutput; ++i) {
      if (res->outputs[i] != primary) {
        candidates.push_back(res->outputs[i]);
      }
    }

    std::string matched_name;
    for (RROutput candidate : candidates) {
      XRROutputInfo *info = xrr.GetOutputInfo(dpy, res, candidate);
      if (!info) {
        continue;
      }
      const bool active = (info->connection == RR_Connected && info->crtc != None);
      const std::string name = (info->name && info->nameLen > 0) ? std::string {info->name, static_cast<std::size_t>(info->nameLen)} : std::string {};
      xrr.FreeOutputInfo(info);
      if (!active || name.empty()) {
        continue;
      }
      const auto conn_id = query_output_connector_id(dpy, xrr, candidate);
      if (conn_id && drm_connector_id_pci_slot(*conn_id) == target_pci) {
        matched_name = name;
        break;
      }
    }

    xrr.FreeScreenResources(res);
    return matched_name;
  }

}  // namespace platf::x11_mode
