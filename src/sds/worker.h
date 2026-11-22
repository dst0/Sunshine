/**
 * @file src/sds/worker.h
 * @brief Single-threaded job queue with timers used to keep blocking work off the nvhttp thread.
 */
#pragma once

// standard includes
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <thread>

namespace sds {
  /**
   * @brief Dedicated thread that runs posted jobs in FIFO order and delayed jobs at their deadline.
   *
   * Jobs never run concurrently with each other, so state touched only by jobs of one worker needs
   * no further locking.
   */
  class worker_t {
  public:
    using clock = std::chrono::steady_clock;  ///< Clock used for timers.
    using job_t = std::function<void()>;  ///< Unit of work.
    using timer_id_t = std::uint64_t;  ///< Handle for cancelling a delayed job.

    /**
     * @brief Start the worker thread.
     *
     * @param name Thread name for diagnostics.
     */
    explicit worker_t(std::string name);

    /**
     * @brief Stop the worker (see stop()) and join its thread.
     *
     * Must not run on the worker thread itself.
     */
    ~worker_t();

    worker_t(const worker_t &) = delete;
    worker_t &operator=(const worker_t &) = delete;

    /**
     * @brief Queue a job.
     *
     * @param job Job to run on the worker thread.
     * @return `false` when the worker is stopping and the job was discarded.
     */
    bool post(job_t job);

    /**
     * @brief Queue a job to run at or after a deadline.
     *
     * @param when Deadline.
     * @param job Job to run.
     * @return Timer handle, or zero when the worker is stopping.
     */
    timer_id_t post_at(clock::time_point when, job_t job);

    /**
     * @brief Cancel a delayed job that has not started yet.
     *
     * @param id Timer handle returned by post_at().
     */
    void cancel(timer_id_t id);

    /**
     * @brief Run all queued jobs, discard pending timers and join the thread. Idempotent.
     */
    void stop();

    /**
     * @brief Wait for shutdown to begin without guessing worker scheduling delays.
     *
     * @param timeout Maximum wait.
     * @return True when stop() has marked the worker as stopping.
     */
    bool wait_until_stopping(std::chrono::milliseconds timeout);

    /**
     * @brief Block until every job queued before this call has run.
     *
     * Must not be called from the worker thread itself.
     */
    void drain();

    /**
     * @brief Check whether the caller runs on this worker's thread.
     *
     * @return `true` on the worker thread.
     */
    [[nodiscard]] bool on_worker_thread() const;

  private:
    /**
     * @brief Thread body.
     */
    void run();

    std::string name_;  ///< Thread name.
    mutable std::mutex mutex_;  ///< Protects all members below.
    std::condition_variable cv_;  ///< Signals new jobs, timers or stop.
    std::deque<job_t> jobs_;  ///< FIFO job queue.
    std::multimap<clock::time_point, std::pair<timer_id_t, job_t>> timers_;  ///< Delayed jobs by deadline.
    timer_id_t next_timer_id_ = 1;  ///< Next timer handle.
    bool stopping_ = false;  ///< Set once stop() begins.
    std::mutex join_mutex_;  ///< Serializes joining the thread.
    std::thread thread_;  ///< Worker thread.
  };
}  // namespace sds
