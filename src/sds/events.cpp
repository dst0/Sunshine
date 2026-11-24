/**
 * @file src/sds/events.cpp
 * @brief Per-client event queues and parked long-polls (DESIGN 4.5).
 */
// standard includes
#include <algorithm>
#include <utility>
#include <vector>

// local includes
#include "events.h"

namespace sds {
  event_hub_t::event_hub_t(std::size_t queue_max):
      queue_max_(std::max<std::size_t>(queue_max, 1)) {
  }

  bool event_hub_t::has_newer(const client_state_t &state, std::uint64_t after) {
    return !state.queue.empty() && state.queue.back().id > after;
  }

  std::string event_hub_t::batch_body(const client_state_t &state, std::uint64_t after) {
    nlohmann::json events = nlohmann::json::array();
    for (const auto &queued : state.queue) {
      if (queued.id > after) {
        events.push_back(queued.event);
      }
    }
    nlohmann::json body;
    body["events"] = std::move(events);
    body["last_id"] = state.next_id - 1;
    return body.dump();
  }

  std::string event_hub_t::stream_ended_body(std::uint64_t id) {
    nlohmann::json body;
    body["events"] = nlohmann::json::array({nlohmann::json {{"id", id}, {"type", "stream_ended"}}});
    body["last_id"] = id;
    return body.dump();
  }

  void event_hub_t::publish(const std::string &client, nlohmann::json event, std::string_view coalesce_key) {
    std::optional<parked_t> wake;
    std::string body;
    {
      std::lock_guard lock {mutex_};
      auto &state = clients_[client];
      if (!coalesce_key.empty()) {
        std::erase_if(state.queue, [&](const queued_event_t &queued) {
          return queued.key == coalesce_key;
        });
      }
      const auto id = state.next_id++;
      event["id"] = id;
      state.queue.push_back({id, std::string {coalesce_key}, std::move(event)});
      while (state.queue.size() > queue_max_) {
        state.queue.pop_front();
      }
      if (state.parked && has_newer(state, state.parked->after)) {
        body = batch_body(state, state.parked->after);
        wake = std::move(state.parked);
        state.parked.reset();
      }
    }
    if (wake) {
      wake->responder(200, std::move(body));
    }
  }

  void event_hub_t::retract(const std::string &client, std::string_view coalesce_key) {
    std::lock_guard lock {mutex_};
    const auto it = clients_.find(client);
    if (it == clients_.end()) {
      return;
    }
    std::erase_if(it->second.queue, [&](const queued_event_t &queued) {
      return queued.key == coalesce_key;
    });
  }

  bool event_hub_t::poll(const std::string &client, std::uint64_t after, std::optional<clock::time_point> deadline, responder_t responder) {
    std::optional<parked_t> superseded;
    std::string superseded_body;
    std::string body;
    bool parked = false;
    {
      std::lock_guard lock {mutex_};
      auto &state = clients_[client];
      if (state.parked) {
        superseded_body = batch_body(state, state.next_id);
        superseded = std::move(state.parked);
        state.parked.reset();
      }
      const auto last_id = state.next_id - 1;
      if (has_newer(state, after) || after > last_id || !deadline) {
        body = batch_body(state, after);
      } else {
        state.parked = parked_t {std::move(responder), *deadline, after};
        parked = true;
      }
    }
    if (superseded) {
      superseded->responder(200, std::move(superseded_body));
    }
    if (!parked) {
      responder(200, std::move(body));
    }
    return parked;
  }

  void event_hub_t::expire(clock::time_point now) {
    std::vector<std::pair<responder_t, std::string>> expired;
    {
      std::lock_guard lock {mutex_};
      for (auto &[_, state] : clients_) {
        if (state.parked && state.parked->deadline <= now) {
          expired.emplace_back(std::move(state.parked->responder), batch_body(state, state.parked->after));
          state.parked.reset();
        }
      }
    }
    for (auto &[responder, body] : expired) {
      responder(200, std::move(body));
    }
  }

  void event_hub_t::end_stream(const std::string &client) {
    std::optional<parked_t> parked;
    std::uint64_t id = 1;
    {
      std::lock_guard lock {mutex_};
      const auto it = clients_.find(client);
      if (it == clients_.end()) {
        return;
      }
      parked = std::move(it->second.parked);
      id = it->second.next_id;
      clients_.erase(it);
    }
    if (parked) {
      parked->responder(200, stream_ended_body(id));
    }
  }

  void event_hub_t::shutdown() {
    std::vector<std::pair<responder_t, std::uint64_t>> parked;
    {
      std::lock_guard lock {mutex_};
      for (auto &[_, state] : clients_) {
        if (state.parked) {
          parked.emplace_back(std::move(state.parked->responder), state.next_id);
        }
      }
      clients_.clear();
    }
    for (auto &[responder, id] : parked) {
      responder(200, stream_ended_body(id));
    }
  }

  std::size_t event_hub_t::queued(const std::string &client) const {
    std::lock_guard lock {mutex_};
    const auto it = clients_.find(client);
    return it == clients_.end() ? 0 : it->second.queue.size();
  }

  bool event_hub_t::parked(const std::string &client) const {
    std::lock_guard lock {mutex_};
    const auto it = clients_.find(client);
    return it != clients_.end() && it->second.parked.has_value();
  }

  bool event_hub_t::has_client(const std::string &client) const {
    std::lock_guard lock {mutex_};
    return clients_.contains(client);
  }
}  // namespace sds
