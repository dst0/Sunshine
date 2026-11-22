/**
 * @file src/sds/worker.cpp
 * @brief Single-threaded job queue with timers.
 */
// standard includes
#include <future>
#include <utility>

// local includes
#include "src/logging.h"
#include "src/platform/common.h"
#include "worker.h"

using namespace std::literals;

namespace sds {
  worker_t::worker_t(std::string name):
      name_(std::move(name)) {
    thread_ = std::thread([this]() {
      run();
    });
  }

  worker_t::~worker_t() {
    stop();
  }

  bool worker_t::post(job_t job) {
    {
      std::lock_guard lock {mutex_};
      if (stopping_) {
        return false;
      }
      jobs_.push_back(std::move(job));
    }
    cv_.notify_one();
    return true;
  }

  worker_t::timer_id_t worker_t::post_at(clock::time_point when, job_t job) {
    timer_id_t id;
    {
      std::lock_guard lock {mutex_};
      if (stopping_) {
        return 0;
      }
      id = next_timer_id_++;
      timers_.emplace(when, std::make_pair(id, std::move(job)));
    }
    cv_.notify_one();
    return id;
  }

  void worker_t::cancel(timer_id_t id) {
    std::lock_guard lock {mutex_};
    for (auto it = timers_.begin(); it != timers_.end(); ++it) {
      if (it->second.first == id) {
        timers_.erase(it);
        return;
      }
    }
  }

  void worker_t::stop() {
    {
      std::lock_guard lock {mutex_};
      stopping_ = true;
    }
    cv_.notify_all();
    std::lock_guard join_lock {join_mutex_};
    if (thread_.joinable() && !on_worker_thread()) {
      thread_.join();
    }
  }

  void worker_t::drain() {
    std::promise<void> done;
    auto future = done.get_future();
    if (!post([&done]() {
          done.set_value();
        })) {
      return;
    }
    future.wait();
  }

  bool worker_t::wait_until_stopping(std::chrono::milliseconds timeout) {
    std::unique_lock lock {mutex_};
    return cv_.wait_for(lock, timeout, [this]() { return stopping_; });
  }

  bool worker_t::on_worker_thread() const {
    return std::this_thread::get_id() == thread_.get_id();
  }

  void worker_t::run() {
    platf::set_thread_name(name_);
    std::unique_lock lock {mutex_};
    while (true) {
      // Timers include response deadlines and upload expiry, so request traffic must not starve
      // them. During shutdown only admitted FIFO jobs are drained; timers remain discarded.
      if (!stopping_ && !timers_.empty() && timers_.begin()->first <= clock::now()) {
        auto job = std::move(timers_.begin()->second.second);
        timers_.erase(timers_.begin());
        lock.unlock();
        try {
          job();
        } catch (const std::exception &e) {
          BOOST_LOG(error) << "sds: timer on "sv << name_ << " threw: "sv << e.what();
        }
        lock.lock();
        continue;
      }
      if (!jobs_.empty()) {
        auto job = std::move(jobs_.front());
        jobs_.pop_front();
        lock.unlock();
        try {
          job();
        } catch (const std::exception &e) {
          BOOST_LOG(error) << "sds: job on "sv << name_ << " threw: "sv << e.what();
        }
        lock.lock();
        continue;
      }
      if (stopping_) {
        timers_.clear();
        return;
      }
      if (timers_.empty()) {
        cv_.wait(lock);
      } else {
        cv_.wait_until(lock, timers_.begin()->first);
      }
    }
  }
}  // namespace sds
