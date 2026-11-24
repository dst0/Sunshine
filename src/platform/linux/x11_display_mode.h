/**
 * @file src/platform/linux/x11_display_mode.h
 * @brief X11 XRandR host resolution switching and CVT 1.2 timing utilities.
 */
#pragma once

#include <optional>
#include <string>

namespace platf::x11_mode {

  constexpr unsigned long CVT_HSYNC_POSITIVE = 1;
  constexpr unsigned long CVT_VSYNC_NEGATIVE = 8;

  /**
   * @brief Pure-C++ VESA CVT 1.2 reduced-blanking display timing parameters.
   */
  struct cvt_mode_t {
    int width = 0;
    int height = 0;
    int fps = 0;
    unsigned long dot_clock_hz = 0;
    unsigned int h_sync_start = 0;
    unsigned int h_sync_end = 0;
    unsigned int h_total = 0;
    unsigned int v_sync_start = 0;
    unsigned int v_sync_end = 0;
    unsigned int v_total = 0;
    unsigned long mode_flags = 0;
    std::string name;
  };

  /**
   * @brief Validate client display mode parameters against safe bounds.
   * @details Requires even width in [640, 7680], even height in [480, 4320], fps in [24, 240].
   */
  bool validate_mode_params(int width, int height, int fps);

  /**
   * @brief Compute VESA CVT 1.2 reduced-blanking timing parameters for the given mode.
   * @return Populated timings if parameters are valid, or std::nullopt otherwise.
   */
  std::optional<cvt_mode_t> compute_cvt_rb_mode(int width, int height, int fps);

  /**
   * @brief Switch the active X11 output to width x height @ fps and optionally save original mode.
   * @param width Target width in pixels.
   * @param height Target height in pixels.
   * @param fps Target refresh rate in Hz.
   * @param revert When true, remember the pre-stream mode for revert_if_saved(); when false, clear any saved mode.
   * @return true if already matching, skipped on non-X11, or switched cleanly; false on validation/XRandR failure.
   */
  bool apply_and_maybe_save(int width, int height, int fps, bool revert);

  /**
   * @brief Revert to the saved original X11 display mode if one was stored with revert=true.
   */
  void revert_if_saved();

  /**
   * @brief Return whether an original X11 display mode is currently saved for revert.
   */
  bool has_saved_mode();

  /**
   * @brief Detect the lowercase PCI bus ID (e.g. "0000:02:00.0") driving the active X11 display, if determinable.
   */
  std::string detect_active_display_pci();

  /**
   * @brief Find the connected active XRandR output name owned by `pci_slot`, if any.
   */
  std::string find_output_name_for_pci(std::string_view pci_slot);

}  // namespace platf::x11_mode
