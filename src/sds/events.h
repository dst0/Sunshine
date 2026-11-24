/**
 * @file src/sds/events.h
 * @brief Per-client event queues and parked long-polls for `GET /sds/v1/events` (DESIGN 4.5).
 *
 * Every event gets a per-client id (1, 2, ...; restarting with each stream session). A poll
 * returns all retained events with `id > after` together with `last_id`, the newest id assigned.
 */
#pragma once

// standard includes
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>

// lib includes
#include <nlohmann/json.hpp>

namespace sds {
  /**
   * @brief Completion callback of a long-poll: HTTP status and JSON body.
   */
  using responder_t = std::function<void(int status, std::string body)>;

  /**
   * @brief Holds bounded per-client event queues and at most one parked long-poll per client.
   *
   * Thread-safe. Responders are always invoked without the internal lock held.
   */
  class event_hub_t {
  public:
    using clock = std::chrono::steady_clock;  ///< Clock for poll deadlines.

    /**
     * @brief Create a hub.
     *
     * @param queue_max Maximum queued events per client; the oldest is dropped beyond it.
     */
    explicit event_hub_t(std::size_t queue_max = 64);

    /**
     * @brief Queue an event for a client (assigning its id) and wake its parked poll.
     *
     * @param client Client key (certificate PEM).
     * @param event Event object; must contain `type`.
     * @param coalesce_key Non-empty to replace an already queued event with the same key.
     */
    void publish(const std::string &client, nlohmann::json event, std::string_view coalesce_key);

    /**
     * @brief Remove a queued, undelivered event with the given coalescing key.
     *
     * @param client Client key.
     * @param coalesce_key Key of the event to remove.
     */
    void retract(const std::string &client, std::string_view coalesce_key);

    /**
     * @brief Answer a poll immediately if retained events with `id > after` exist, otherwise park it.
     *
     * A poll whose `after` is beyond the newest id (numbering restarted) and a poll without a
     * deadline (`timeout=0`) are answered at once with an empty list. A parked poll of the same
     * client is completed with an empty list.
     *
     * @param client Client key.
     * @param after Newest event id the client has seen (0 for all retained events).
     * @param deadline When a parked poll completes with an empty list; no value never parks.
     * @param responder Completion callback, invoked exactly once.
     * @return `true` when the poll was parked.
     */
    bool poll(const std::string &client, std::uint64_t after, std::optional<clock::time_point> deadline, responder_t responder);

    /**
     * @brief Complete parked polls whose deadline has passed with an empty batch.
     *
     * @param now Current time.
     */
    void expire(clock::time_point now);

    /**
     * @brief Complete the client's parked poll with a `stream_ended` event and drop all its state.
     *
     * @param client Client key.
     */
    void end_stream(const std::string &client);

    /**
     * @brief Complete every parked poll with `stream_ended` and drop all state.
     */
    void shutdown();

    /**
     * @brief Number of queued events of a client (diagnostics and tests).
     *
     * @param client Client key.
     * @return Queued events.
     */
    [[nodiscard]] std::size_t queued(const std::string &client) const;

    /**
     * @brief Check whether a client has a parked poll.
     *
     * @param client Client key.
     * @return `true` when parked.
     */
    [[nodiscard]] bool parked(const std::string &client) const;

    /**
     * @brief Check whether any state exists for a client.
     *
     * @param client Client key.
     * @return `true` when a queue or parked poll exists.
     */
    [[nodiscard]] bool has_client(const std::string &client) const;

  private:
    /**
     * @brief Queued event with its cursor id.
     */
    struct queued_event_t {
      std::uint64_t id;  ///< Cursor id.
      std::string key;  ///< Coalescing key.
      nlohmann::json event;  ///< Event object.
    };

    /**
     * @brief Parked long-poll.
     */
    struct parked_t {
      responder_t responder;  ///< Completion callback.
      clock::time_point deadline;  ///< Timeout.
      std::uint64_t after = 0;  ///< Newest id the client has seen.
    };

    /**
     * @brief State of one client.
     */
    struct client_state_t {
      std::uint64_t next_id = 1;  ///< Id of the next queued event.
      std::deque<queued_event_t> queue;  ///< Retained events, oldest first.
      std::optional<parked_t> parked;  ///< Parked poll.
    };

    /**
     * @brief Serialize the retained events newer than `after`.
     *
     * @param state Client state.
     * @param after Newest id the client has seen.
     * @return JSON body `{"events":[...],"last_id":N}`.
     */
    static std::string batch_body(const client_state_t &state, std::uint64_t after);

    /**
     * @brief Check whether retained events newer than `after` exist.
     *
     * @param state Client state.
     * @param after Newest id the client has seen.
     * @return `true` when at least one event would be delivered.
     */
    static bool has_newer(const client_state_t &state, std::uint64_t after);

    /**
     * @brief Serialize the stream-ended batch.
     *
     * @param id Id of the `stream_ended` event.
     * @return JSON body.
     */
    static std::string stream_ended_body(std::uint64_t id);

    std::size_t queue_max_;  ///< Queue bound.
    mutable std::mutex mutex_;  ///< Protects clients_.
    std::map<std::string, client_state_t, std::less<>> clients_;  ///< Per-client state.
  };
}  // namespace sds
