/**
 * @file tests/unit/test_session_overrides_and_modes.cpp
 * @brief Unit tests for adapter enumeration, session encoder overrides, XRandR CVT timings, and XDND helpers.
 */

#include "../tests_common.h"

#include <algorithm>
#include <cmath>
#include <limits>
#include <string>

#include <src/config.h>
#include <src/platform/common.h>
#include <src/process.h>
#include <src/video.h>
#include <src/video_packed444.h>

#ifdef SUNSHINE_BUILD_X11
  #include <src/platform/linux/misc.h>
  #include <src/platform/linux/x11_display_mode.h>
  #include <src/platform/linux/xdnd_x11.h>
#endif

TEST(SessionOverrideTest, ValidatesAndResolvesRenderAdapterOverride) {
  platf::set_session_render_device_override(std::nullopt);
  platf::set_session_capture_adapter_override(std::nullopt);
  const auto baseline_dev = platf::resolve_render_device();

  // Arbitrary paths must fail allowlist validation.
  EXPECT_FALSE(platf::validate_render_adapter_id(""));
  EXPECT_FALSE(platf::validate_render_adapter_id("/etc/passwd"));
  EXPECT_FALSE(platf::validate_render_adapter_id("pci-0000:ff:ff.f-render"));

  const auto adapters = platf::enumerate_render_adapters();
  int defaults = 0;
  int capture_defaults = 0;
  for (const auto &adapter : adapters) {
    EXPECT_FALSE(adapter.id.empty());
    EXPECT_FALSE(adapter.name.empty());
    EXPECT_EQ(platf::validate_render_adapter_id(adapter.id), adapter.id);
    if (adapter.is_default) {
      ++defaults;
    }
    if (adapter.is_capture_default) {
      ++capture_defaults;
    }
  }
  EXPECT_LE(defaults, 1);
  EXPECT_LE(capture_defaults, 1);

  platf::set_session_render_device_override("/dev/dri/by-path/pci-0000:02:00.0-render");
  EXPECT_EQ(platf::resolve_render_device(), "/dev/dri/by-path/pci-0000:02:00.0-render");

  platf::set_session_render_device_override(std::nullopt);
  EXPECT_EQ(platf::resolve_render_device(), baseline_dev);

  EXPECT_FALSE(platf::is_session_capture_adapter_overridden());
  platf::set_session_capture_adapter_override("/dev/dri/by-path/pci-0000:02:00.0-render");
  EXPECT_TRUE(platf::is_session_capture_adapter_overridden());
  const auto cap = platf::resolve_capture_adapter();
  ASSERT_TRUE(cap.has_value());
  EXPECT_EQ(cap->id, "/dev/dri/by-path/pci-0000:02:00.0-render");
  EXPECT_EQ(cap->pci_slot, "0000:02:00.0");

  platf::set_session_capture_adapter_override(std::nullopt);
  EXPECT_FALSE(platf::is_session_capture_adapter_overridden());
}

TEST(SessionOverrideTest, AppliesCaptureGpuOffloadEnvironment) {
  boost::process::v1::environment mesa_env;
  platf::render_adapter_t amd_gpu;
  amd_gpu.id = "/dev/dri/by-path/pci-0000:02:00.0-render";
  amd_gpu.pci_slot = "0000:02:00.0";
  amd_gpu.vendor_id = "1002";
  amd_gpu.device_id = "7550";
  proc::apply_capture_gpu_env(mesa_env, amd_gpu);
  EXPECT_EQ(mesa_env["SUNSHINE_CAPTURE_ADAPTER"].to_string(), "/dev/dri/by-path/pci-0000:02:00.0-render");
  EXPECT_EQ(mesa_env["SUNSHINE_CAPTURE_PCI"].to_string(), "0000:02:00.0");
  EXPECT_EQ(mesa_env["DRI_PRIME"].to_string(), "pci-0000_02_00_0");
  EXPECT_EQ(mesa_env["MESA_VK_DEVICE_SELECT"].to_string(), "1002:7550!");
  EXPECT_EQ(mesa_env["SUNSHINE_CAPTURE_VK_DEVICE"].to_string(), "1002:7550!");

  boost::process::v1::environment nv_env;
  platf::render_adapter_t nv_gpu;
  nv_gpu.id = "/dev/dri/by-path/pci-0000:01:00.0-render";
  nv_gpu.pci_slot = "0000:01:00.0";
  nv_gpu.vendor_id = "10de";
  nv_gpu.device_id = "2684";
  proc::apply_capture_gpu_env(nv_env, nv_gpu);
  EXPECT_EQ(nv_env["__NV_PRIME_RENDER_OFFLOAD"].to_string(), "1");
  EXPECT_EQ(nv_env["__GLX_VENDOR_LIBRARY_NAME"].to_string(), "nvidia");
  EXPECT_EQ(nv_env["__VK_LAYER_NV_optimus"].to_string(), "NVIDIA_only");

#ifdef SUNSHINE_BUILD_X11
  EXPECT_TRUE(platf::drm_node_pci_slot("").empty());
  EXPECT_TRUE(platf::drm_node_pci_slot(".").empty());
  EXPECT_TRUE(platf::drm_node_pci_slot("..").empty());
  EXPECT_TRUE(platf::drm_node_pci_slot("../bad").empty());
  EXPECT_TRUE(platf::drm_node_pci_slot("card0\\bad").empty());
  EXPECT_TRUE(platf::drm_connector_id_pci_slot(0).empty());
#endif
}

TEST(SessionOverrideTest, SoftwareEncoderFlagsAndSessionOverrideState) {
  const auto encoders = video::available_encoders();
  EXPECT_NE(std::ranges::find(encoders, "software"), encoders.end());

  const auto sw_flags = video::software_codec_mode_flags();
  EXPECT_NE(sw_flags & SCM_H264, 0u);
  EXPECT_NE(sw_flags & SCM_H264_HIGH8_444, 0u);

  video::clear_session_encoder_override();
  EXPECT_FALSE(video::current_session_encoder_override());

  video::set_session_encoder_override("auto", false, false);
  EXPECT_FALSE(video::current_session_encoder_override());

  video::set_session_encoder_override("software", true, false);
  EXPECT_EQ(video::current_session_encoder_override(), "software");

  video::clear_session_encoder_override();
  EXPECT_FALSE(video::current_session_encoder_override());

  video::set_session_packed_ycocgr_mode(1);
  EXPECT_EQ(video::get_session_packed_ycocgr_mode(), 1);
  video::clear_session_packed_ycocgr_mode();
  EXPECT_EQ(video::get_session_packed_ycocgr_mode(), 0);
}

#ifdef SUNSHINE_BUILD_X11
TEST(X11DisplayModeTest, ValidatesBoundsStrictly) {
  using platf::x11_mode::validate_mode_params;
  EXPECT_TRUE(validate_mode_params(640, 480, 24));
  EXPECT_TRUE(validate_mode_params(2560, 1440, 60));
  EXPECT_TRUE(validate_mode_params(3440, 1440, 120));
  EXPECT_TRUE(validate_mode_params(3840, 2160, 60));
  EXPECT_TRUE(validate_mode_params(7680, 4320, 240));

  EXPECT_FALSE(validate_mode_params(638, 480, 60));
  EXPECT_FALSE(validate_mode_params(7682, 4320, 60));
  EXPECT_FALSE(validate_mode_params(1921, 1080, 60));
  EXPECT_FALSE(validate_mode_params(1920, 1081, 60));
  EXPECT_FALSE(validate_mode_params(1920, 478, 60));
  EXPECT_FALSE(validate_mode_params(1920, 4322, 60));
  EXPECT_FALSE(validate_mode_params(1920, 1080, 23));
  EXPECT_FALSE(validate_mode_params(1920, 1080, 241));
}

TEST(X11DisplayModeTest, ComputesExactVesaCvtReducedBlankingTimings) {
  using platf::x11_mode::compute_cvt_rb_mode;
  const auto m_1440 = compute_cvt_rb_mode(2560, 1440, 60);
  ASSERT_TRUE(m_1440);
  EXPECT_EQ(m_1440->dot_clock_hz, 241500000UL);
  EXPECT_EQ(m_1440->h_sync_start, 2608u);
  EXPECT_EQ(m_1440->h_sync_end, 2640u);
  EXPECT_EQ(m_1440->h_total, 2720u);
  EXPECT_EQ(m_1440->v_sync_start, 1443u);
  EXPECT_EQ(m_1440->v_sync_end, 1448u);
  EXPECT_EQ(m_1440->v_total, 1481u);

  const auto m_4k = compute_cvt_rb_mode(3840, 2160, 60);
  ASSERT_TRUE(m_4k);
  EXPECT_EQ(m_4k->dot_clock_hz, 533000000UL);
  EXPECT_EQ(m_4k->h_total, 4000u);
  EXPECT_EQ(m_4k->v_total, 2222u);

  const auto m_16_10 = compute_cvt_rb_mode(1920, 1200, 60);
  ASSERT_TRUE(m_16_10);
  EXPECT_EQ(m_16_10->dot_clock_hz, 154000000UL);
  EXPECT_EQ(m_16_10->v_sync_end, 1209u);
  EXPECT_EQ(m_16_10->v_total, 1235u);

  EXPECT_FALSE(compute_cvt_rb_mode(1921, 1080, 60));
  platf::x11_mode::revert_if_saved();
  EXPECT_FALSE(platf::x11_mode::has_saved_mode());
}

TEST(XdndHelperTest, ClampsCoordinatesAndFormatsUriPayloads) {
  using namespace platf::xdnd;
  EXPECT_EQ(map_normalized_to_screen(0.0, 0.0, 1920, 1080), (std::pair<int, int> {0, 0}));
  EXPECT_EQ(map_normalized_to_screen(1.0, 1.0, 1920, 1080), (std::pair<int, int> {1919, 1079}));
  EXPECT_EQ(map_normalized_to_screen(-0.5, 2.5, 1920, 1080), (std::pair<int, int> {0, 1079}));
  EXPECT_EQ(
    map_normalized_to_screen(std::numeric_limits<double>::quiet_NaN(), 0.5, 1001, 1001),
    (std::pair<int, int> {0, 500})
  );

  const std::vector<std::string> uris {"file:///tmp/a.txt", "file:///tmp/b%20c.png"};
  EXPECT_EQ(build_uri_list_payload(uris), "file:///tmp/a.txt\r\nfile:///tmp/b%20c.png\r\n");
  EXPECT_EQ(build_gnome_copy_payload(uris), "copy\nfile:///tmp/a.txt\nfile:///tmp/b%20c.png");
  EXPECT_TRUE(build_gnome_copy_payload({}).empty());
}
#endif
