/**
 * @file tests/unit/sds/test_sds_rtsp.cpp
 * @brief Test rtsp_stream::has_running_session and the session observer used by sds.
 */

// test includes
#include "../../tests_common.h"

// standard includes
#include <mutex>
#include <string>
#include <utility>
#include <vector>

// local includes
#include <src/rtsp.h>
#include <src/stream.h>

TEST(SdsRtspSessionTest, HasRunningSessionMatchesCertificateAndRunningState) {
  using stream::session::state_e;
  auto running = stream::session::test_support::make_session("cert-a", state_e::RUNNING);
  auto stopping = stream::session::test_support::make_session("cert-b", state_e::STOPPING);
  auto starting = stream::session::test_support::make_session("cert-c", state_e::STARTING);
  rtsp_stream::test_support::insert_session(running);
  rtsp_stream::test_support::insert_session(stopping);
  rtsp_stream::test_support::insert_session(starting);

  EXPECT_TRUE(rtsp_stream::has_running_session("cert-a"));
  EXPECT_FALSE(rtsp_stream::has_running_session("cert-b")) << "stopping sessions are not active";
  EXPECT_FALSE(rtsp_stream::has_running_session("cert-c"));
  EXPECT_FALSE(rtsp_stream::has_running_session("cert-unknown"));
  EXPECT_FALSE(rtsp_stream::has_running_session(""));

  rtsp_stream::test_support::remove_session(running);
  rtsp_stream::test_support::remove_session(stopping);
  rtsp_stream::test_support::remove_session(starting);
  EXPECT_FALSE(rtsp_stream::has_running_session("cert-a"));
}

TEST(SdsRtspSessionTest, ObserverIsNotifiedOnceWhenASessionStops) {
  std::mutex mutex;
  std::vector<std::pair<std::string, bool>> notifications;
  rtsp_stream::set_session_observer([&](std::string_view cert, bool running) {
    std::lock_guard lock {mutex};
    notifications.emplace_back(std::string {cert}, running);
  });

  auto session = stream::session::test_support::make_session("cert-a", stream::session::state_e::RUNNING);
  stream::session::stop(*session);
  EXPECT_EQ(stream::session::state(*session), stream::session::state_e::STOPPING);
  stream::session::stop(*session);

  rtsp_stream::notify_session_state("cert-b", true);
  rtsp_stream::set_session_observer(nullptr);
  rtsp_stream::notify_session_state("cert-c", true);

  std::lock_guard lock {mutex};
  const std::vector<std::pair<std::string, bool>> expected {{"cert-a", false}, {"cert-b", true}};
  EXPECT_EQ(notifications, expected);
}
