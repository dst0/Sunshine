/**
 * @file tests/unit/sds/test_sds_events.cpp
 * @brief Test the per-client event queues and long-poll parking (DESIGN 4.5).
 */

// test includes
#include "../../tests_common.h"

// standard includes
#include <chrono>
#include <optional>
#include <string>
#include <vector>

// local includes
#include <src/sds/events.h>

using namespace std::literals;

namespace {
  /**
   * @brief Captures poll completions.
   */
  struct capture_t {
    std::vector<std::pair<int, nlohmann::json>> replies;  ///< Completed polls.

    /**
     * @brief Make a responder appending to replies.
     *
     * @return Responder.
     */
    sds::responder_t responder() {
      return [this](int status, std::string body) {
        replies.emplace_back(status, nlohmann::json::parse(body));
      };
    }
  };

  /**
   * @brief Deadline far in the future.
   *
   * @return Time point.
   */
  std::optional<sds::event_hub_t::clock::time_point> later() {
    return sds::event_hub_t::clock::now() + 1h;
  }
}  // namespace

TEST(SdsEventsTest, RetainedEventsAreReturnedByIdAndParkWhenNothingIsNewer) {
  sds::event_hub_t hub;
  capture_t capture;
  hub.publish("A", {{"type", "outbox"}, {"count", 1}}, "outbox");
  hub.publish("A", {{"type", "clipboard"}, {"seq", 4}}, "clipboard");
  EXPECT_EQ(hub.queued("A"), 2u);

  EXPECT_FALSE(hub.poll("A", 0, later(), capture.responder()));
  ASSERT_EQ(capture.replies.size(), 1u);
  EXPECT_EQ(capture.replies[0].first, 200);
  const auto &events = capture.replies[0].second["events"];
  ASSERT_EQ(events.size(), 2u);
  EXPECT_EQ(events[0]["id"], 1);
  EXPECT_EQ(events[0]["type"], "outbox");
  EXPECT_EQ(events[1]["id"], 2);
  EXPECT_EQ(events[1]["seq"], 4);
  EXPECT_EQ(capture.replies[0].second["last_id"], 2);

  // after=1 returns only the newer event; events stay retained (no acknowledgement).
  EXPECT_FALSE(hub.poll("A", 1, later(), capture.responder()));
  ASSERT_EQ(capture.replies[1].second["events"].size(), 1u);
  EXPECT_EQ(capture.replies[1].second["events"][0]["id"], 2);
  EXPECT_EQ(hub.queued("A"), 2u);

  // Nothing newer than 2: park.
  EXPECT_TRUE(hub.poll("A", 2, later(), capture.responder()));
  EXPECT_TRUE(hub.parked("A"));
  EXPECT_EQ(capture.replies.size(), 2u);
}

TEST(SdsEventsTest, TimeoutZeroNeverParks) {
  sds::event_hub_t hub;
  capture_t capture;
  EXPECT_FALSE(hub.poll("A", 0, std::nullopt, capture.responder()));
  ASSERT_EQ(capture.replies.size(), 1u);
  EXPECT_TRUE(capture.replies[0].second["events"].empty());
  EXPECT_EQ(capture.replies[0].second["last_id"], 0);
  EXPECT_FALSE(hub.parked("A"));
}

TEST(SdsEventsTest, PublishWakesParkedPoll) {
  sds::event_hub_t hub;
  capture_t capture;
  EXPECT_TRUE(hub.poll("A", 0, later(), capture.responder()));
  EXPECT_TRUE(capture.replies.empty());
  hub.publish("B", {{"type", "clipboard"}, {"seq", 1}}, "clipboard");
  EXPECT_TRUE(capture.replies.empty()) << "events of other clients must not wake this poll";
  hub.publish("A", {{"type", "clipboard"}, {"seq", 1}}, "clipboard");
  ASSERT_EQ(capture.replies.size(), 1u);
  EXPECT_EQ(capture.replies[0].second["events"][0]["seq"], 1);
  EXPECT_EQ(capture.replies[0].second["events"][0]["id"], 1);
  EXPECT_EQ(capture.replies[0].second["last_id"], 1);
  EXPECT_FALSE(hub.parked("A"));
}

TEST(SdsEventsTest, CoalescingKeepsOnlyTheLatestEventPerKey) {
  sds::event_hub_t hub;
  capture_t capture;
  hub.publish("A", {{"type", "clipboard"}, {"seq", 1}}, "clipboard");
  hub.publish("A", {{"type", "outbox"}, {"count", 1}}, "outbox");
  hub.publish("A", {{"type", "clipboard"}, {"seq", 2}}, "clipboard");
  hub.publish("A", {{"type", "clipboard"}, {"seq", 3}}, "clipboard");
  EXPECT_EQ(hub.queued("A"), 2u);
  hub.poll("A", 0, later(), capture.responder());
  const auto &events = capture.replies[0].second["events"];
  ASSERT_EQ(events.size(), 2u);
  EXPECT_EQ(events[0]["type"], "outbox");
  EXPECT_EQ(events[0]["id"], 2);
  EXPECT_EQ(events[1]["seq"], 3);
  EXPECT_EQ(events[1]["id"], 4);
  EXPECT_EQ(capture.replies[0].second["last_id"], 4);

  hub.retract("A", "clipboard");
  EXPECT_EQ(hub.queued("A"), 1u);
  hub.retract("nobody", "clipboard");
}

TEST(SdsEventsTest, RetentionIsBounded) {
  sds::event_hub_t hub {4};
  for (int i = 0; i < 10; ++i) {
    hub.publish("A", {{"type", "custom"}, {"n", i}}, "");
  }
  EXPECT_EQ(hub.queued("A"), 4u);
  capture_t capture;
  hub.poll("A", 0, later(), capture.responder());
  EXPECT_EQ(capture.replies[0].second["events"].size(), 4u);
  EXPECT_EQ(capture.replies[0].second["events"][0]["n"], 6);
  EXPECT_EQ(capture.replies[0].second["events"][0]["id"], 7);
  EXPECT_EQ(capture.replies[0].second["last_id"], 10);
}

TEST(SdsEventsTest, AfterBeyondNewestIdAnswersImmediately) {
  sds::event_hub_t hub;
  capture_t capture;
  hub.publish("A", {{"type", "outbox"}, {"count", 1}}, "outbox");
  EXPECT_FALSE(hub.poll("A", 1000, later(), capture.responder())) << "numbering restarted: the client must learn last_id at once";
  ASSERT_EQ(capture.replies.size(), 1u);
  EXPECT_TRUE(capture.replies[0].second["events"].empty());
  EXPECT_EQ(capture.replies[0].second["last_id"], 1);
}

TEST(SdsEventsTest, ExpiredPollsCompleteWithAnEmptyList) {
  sds::event_hub_t hub;
  capture_t capture;
  const auto now = sds::event_hub_t::clock::now();
  hub.publish("A", {{"type", "outbox"}, {"count", 1}}, "outbox");
  hub.poll("A", 1, now + 10ms, capture.responder());
  hub.poll("B", 0, now + 1h, capture.responder());
  hub.expire(now);
  EXPECT_TRUE(capture.replies.empty());
  hub.expire(now + 20ms);
  ASSERT_EQ(capture.replies.size(), 1u);
  EXPECT_TRUE(capture.replies[0].second["events"].empty());
  EXPECT_EQ(capture.replies[0].second["last_id"], 1);
  EXPECT_FALSE(hub.parked("A"));
  EXPECT_TRUE(hub.parked("B"));
}

TEST(SdsEventsTest, NewPollSupersedesParkedPollOfTheSameClient) {
  sds::event_hub_t hub;
  capture_t first;
  capture_t second;
  EXPECT_TRUE(hub.poll("A", 0, later(), first.responder()));
  EXPECT_TRUE(hub.poll("A", 0, later(), second.responder()));
  ASSERT_EQ(first.replies.size(), 1u);
  EXPECT_TRUE(first.replies[0].second["events"].empty());
  EXPECT_TRUE(second.replies.empty());
  EXPECT_TRUE(hub.parked("A"));
}

TEST(SdsEventsTest, StreamEndCompletesParkedPollAndDropsState) {
  sds::event_hub_t hub;
  capture_t capture;
  hub.publish("A", {{"type", "outbox"}, {"count", 1}}, "outbox");
  hub.poll("A", 1, later(), capture.responder());
  ASSERT_TRUE(hub.parked("A"));
  hub.end_stream("A");
  ASSERT_EQ(capture.replies.size(), 1u);
  ASSERT_EQ(capture.replies[0].second["events"].size(), 1u);
  EXPECT_EQ(capture.replies[0].second["events"][0]["type"], "stream_ended");
  EXPECT_EQ(capture.replies[0].second["events"][0]["id"], 2);
  EXPECT_EQ(capture.replies[0].second["last_id"], 2);
  EXPECT_FALSE(hub.has_client("A"));
  EXPECT_EQ(hub.queued("A"), 0u);
  hub.end_stream("A");  // idempotent

  // A new stream session numbers its events from 1 again.
  hub.publish("A", {{"type", "outbox"}, {"count", 2}}, "outbox");
  capture_t fresh;
  hub.poll("A", 0, later(), fresh.responder());
  EXPECT_EQ(fresh.replies[0].second["events"][0]["id"], 1);

  hub.publish("B", {{"type", "outbox"}, {"count", 2}}, "outbox");
  hub.end_stream("B");
  EXPECT_FALSE(hub.has_client("B")) << "retained events are dropped with the stream";
}

TEST(SdsEventsTest, ShutdownCompletesAllParkedPolls) {
  sds::event_hub_t hub;
  capture_t capture;
  hub.poll("A", 0, later(), capture.responder());
  hub.poll("B", 0, later(), capture.responder());
  hub.publish("C", {{"type", "outbox"}, {"count", 1}}, "outbox");
  hub.shutdown();
  ASSERT_EQ(capture.replies.size(), 2u);
  for (const auto &[status, body] : capture.replies) {
    EXPECT_EQ(status, 200);
    EXPECT_EQ(body["events"][0]["type"], "stream_ended");
  }
  EXPECT_FALSE(hub.has_client("C"));
}
