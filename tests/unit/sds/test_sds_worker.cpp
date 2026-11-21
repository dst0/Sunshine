/**
 * @file tests/unit/sds/test_sds_worker.cpp
 * @brief Test the sds worker thread (FIFO jobs, timers, cancellation, stop).
 */

// test includes
#include "../../tests_common.h"

// standard includes
#include <atomic>
#include <chrono>
#include <future>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <vector>

// local includes
#include <src/sds/worker.h>

using namespace std::literals;

TEST(SdsWorkerTest, RunsJobsInOrderOnItsOwnThread) {
  sds::worker_t worker {"sds-test"};
  std::vector<int> order;
  std::mutex mutex;
  std::atomic_bool on_worker {false};
  for (int i = 0; i < 5; ++i) {
    ASSERT_TRUE(worker.post([&, i]() {
      std::lock_guard lock {mutex};
      order.push_back(i);
      on_worker = worker.on_worker_thread();
    }));
  }
  worker.drain();
  EXPECT_EQ(order, (std::vector<int> {0, 1, 2, 3, 4}));
  EXPECT_TRUE(on_worker);
  EXPECT_FALSE(worker.on_worker_thread());
}

TEST(SdsWorkerTest, TimersFireInDeadlineOrderAndCanBeCancelled) {
  sds::worker_t worker {"sds-test"};
  std::vector<int> fired;
  std::mutex mutex;
  std::promise<void> done;
  const auto now = sds::worker_t::clock::now();
  worker.post_at(now + 60ms, [&]() {
    std::lock_guard lock {mutex};
    fired.push_back(2);
    done.set_value();
  });
  worker.post_at(now + 20ms, [&]() {
    std::lock_guard lock {mutex};
    fired.push_back(1);
  });
  const auto cancelled = worker.post_at(now + 40ms, [&]() {
    std::lock_guard lock {mutex};
    fired.push_back(99);
  });
  EXPECT_NE(cancelled, 0u);
  worker.cancel(cancelled);
  worker.cancel(123456);  // unknown ids are ignored
  ASSERT_EQ(done.get_future().wait_for(5s), std::future_status::ready);
  std::lock_guard lock {mutex};
  EXPECT_EQ(fired, (std::vector<int> {1, 2}));
}

TEST(SdsWorkerTest, StopRunsQueuedJobsDropsTimersAndRejectsNewWork) {
  auto worker = std::make_unique<sds::worker_t>("sds-test");
  std::atomic_int ran {0};
  std::promise<void> release;
  auto released = release.get_future().share();
  worker->post([released]() {
    released.wait();
  });
  for (int i = 0; i < 3; ++i) {
    worker->post([&ran]() {
      ++ran;
    });
  }
  std::atomic_bool timer_ran {false};
  worker->post_at(sds::worker_t::clock::now() + 1h, [&timer_ran]() {
    timer_ran = true;
  });
  std::jthread stopper {[&worker]() {
    worker->stop();
  }};
  std::this_thread::sleep_for(20ms);
  release.set_value();
  stopper.join();
  EXPECT_EQ(ran, 3);
  EXPECT_FALSE(timer_ran);
  EXPECT_FALSE(worker->post([]() {}));
  EXPECT_EQ(worker->post_at(sds::worker_t::clock::now(), []() {}), 0u);
  worker->drain();  // returns immediately once stopped
  worker->stop();  // idempotent
}

TEST(SdsWorkerTest, ThrowingJobsDoNotKillTheWorker) {
  sds::worker_t worker {"sds-test"};
  worker.post([]() {
    throw std::runtime_error("boom");
  });
  worker.post_at(sds::worker_t::clock::now(), []() {
    throw std::runtime_error("timer boom");
  });
  std::this_thread::sleep_for(20ms);
  std::atomic_bool ran {false};
  worker.post([&ran]() {
    ran = true;
  });
  worker.drain();
  EXPECT_TRUE(ran);
}
