/**
 * @file tests/unit/sds/fake_clipboard_backend.h
 * @brief In-memory clipboard backend for secure-desktop-stream tests.
 */
#pragma once

// standard includes
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

// local includes
#include <src/sds/clipboard_backend.h>

namespace test_utils::sds {
  /**
   * @brief Shared, inspectable state of a fake backend.
   */
  struct fake_clipboard_state_t {
    std::mutex mutex;  ///< Protects all fields.
    std::optional<::sds::clipboard::item_t> content;  ///< Simulated host clipboard.
    std::function<void()> on_change;  ///< Callback registered by start().
    std::vector<::sds::clipboard::item_t> written;  ///< Items passed to write().
    int starts = 0;  ///< Successful start() calls.
    int stops = 0;  ///< stop() calls.
    int reads = 0;  ///< read() calls.
    bool native_file_clipboard = false;  ///< Allow tests to model the isolated X11 native selection.
    std::uint64_t generation = 1;  ///< Monotonic clipboard selection generation.
    std::uint64_t retired_calls = 0;  ///< Number of retire_file_clipboard() calls.
    std::vector<std::uint64_t> retired_generations;  ///< Generations passed to retire_file_clipboard().
    std::vector<std::string> published_offers;  ///< Offers passed to publish_file_clipboard().
    std::function<void()> on_publish;  ///< Optional hook invoked after publish_file_clipboard() commits.
    std::map<std::string, ::sds::clipboard::backend_t::lazy_pull_callback_t, std::less<>> lazy_pull_hooks;
    std::vector<std::pair<std::string, std::string>> lazy_published;
    std::vector<std::pair<std::string, std::string>> lazy_completed;
    std::vector<std::string> lazy_failed;
    bool started = false;  ///< Currently watching.
    bool fail_start = false;  ///< Make start() fail.
    bool fail_write = false;  ///< Make write() fail.
    bool notify_own_writes = false;  ///< Violate the contract: report own writes as changes.

    bool trigger_lazy_pull(const std::string &offer_id, std::vector<std::string> targets) {
      ::sds::clipboard::backend_t::lazy_pull_callback_t cb;
      {
        const std::lock_guard lock {mutex};
        const auto it = lazy_pull_hooks.find(offer_id);
        if (it == lazy_pull_hooks.end()) {
          return false;
        }
        cb = it->second;
      }
      if (cb) {
        cb(offer_id, std::move(targets));
        return true;
      }
      return false;
    }

    /**
     * @brief Simulate another application changing the host clipboard.
     *
     * @param item New content.
     */
    void host_set(::sds::clipboard::item_t item) {
      std::function<void()> callback;
      {
        std::lock_guard lock {mutex};
        content = std::move(item);
        ++generation;
        callback = on_change;
      }
      if (callback) {
        callback();
      }
    }

    /**
     * @brief Snapshot of the counters.
     *
     * @return Number of writes so far.
     */
    std::size_t write_count() {
      std::lock_guard lock {mutex};
      return written.size();
    }
  };

  /**
   * @brief Backend whose behaviour is driven by a fake_clipboard_state_t.
   */
  class fake_clipboard_backend_t: public ::sds::clipboard::backend_t {
  public:
    /**
     * @brief Bind to shared state.
     *
     * @param state State.
     */
    explicit fake_clipboard_backend_t(std::shared_ptr<fake_clipboard_state_t> state):
        state_(std::move(state)) {
    }

    int start(std::function<void()> on_change) override {
      std::lock_guard lock {state_->mutex};
      if (state_->fail_start) {
        return -1;
      }
      state_->on_change = std::move(on_change);
      state_->started = true;
      ++state_->starts;
      return 0;
    }

    void stop() override {
      std::lock_guard lock {state_->mutex};
      state_->on_change = nullptr;
      state_->started = false;
      ++state_->stops;
    }

    std::optional<::sds::clipboard::item_t> read(const ::sds::clipboard::limits_t &, std::chrono::milliseconds) override {
      std::lock_guard lock {state_->mutex};
      ++state_->reads;
      return state_->content;
    }

    int write(const ::sds::clipboard::item_t &item) override {
      std::function<void()> callback;
      {
        std::lock_guard lock {state_->mutex};
        if (state_->fail_write) {
          return -1;
        }
        state_->content = item;
        state_->written.push_back(item);
        if (state_->notify_own_writes) {
          callback = state_->on_change;
        }
      }
      if (callback) {
        callback();
      }
      return 0;
    }

    [[nodiscard]] bool supports_file_clipboard() const override {
      const std::lock_guard lock {state_->mutex};
      return state_->native_file_clipboard;
    }

    std::optional<std::uint64_t> file_clipboard_generation() override {
      const std::lock_guard lock {state_->mutex};
      return state_->started ? std::optional {state_->generation} : std::nullopt;
    }

    std::optional<std::uint64_t> publish_file_clipboard(std::uint64_t expected, std::string offer, std::function<bool()> allowed) override {
      if (allowed && !allowed()) {
        return std::nullopt;
      }
      std::function<void()> hook;
      std::uint64_t published_generation = 0;
      {
        const std::lock_guard lock {state_->mutex};
        if (!state_->started || !state_->native_file_clipboard || state_->generation != expected) {
          return std::nullopt;
        }
        ++state_->generation;
        published_generation = state_->generation;
        state_->published_offers.push_back(offer);
        state_->content = ::sds::clipboard::item_t {std::nullopt, std::nullopt, std::move(offer)};
        hook = state_->on_publish;
      }
      if (hook) {
        hook();
      }
      return published_generation;
    }

    void retire_file_clipboard(std::uint64_t generation) override {
      const std::lock_guard lock {state_->mutex};
      ++state_->retired_calls;
      state_->retired_generations.push_back(generation);
      if (state_->generation == generation && state_->content && state_->content->file_offer) {
        state_->content.reset();
        ++state_->generation;
      }
    }

    std::optional<std::uint64_t> publish_lazy_offer(
      std::uint64_t expected,
      std::string offer_id,
      std::string kind,
      lazy_pull_callback_t on_pull
    ) override {
      const std::lock_guard lock {state_->mutex};
      if (!state_->started || !state_->native_file_clipboard || state_->generation != expected) {
        return std::nullopt;
      }
      ++state_->generation;
      state_->lazy_published.emplace_back(offer_id, std::move(kind));
      state_->lazy_pull_hooks.insert_or_assign(std::move(offer_id), std::move(on_pull));
      return state_->generation;
    }

    void complete_lazy_offer(
      std::string_view offer_id,
      std::string native_offer,
      std::string staged_image_path,
      std::function<bool()>
    ) override {
      const std::lock_guard lock {state_->mutex};
      state_->lazy_completed.emplace_back(
        std::string {offer_id},
        !native_offer.empty() ? std::move(native_offer) : std::move(staged_image_path)
      );
    }

    void fail_lazy_offer(std::string_view offer_id) override {
      const std::lock_guard lock {state_->mutex};
      state_->lazy_failed.emplace_back(offer_id);
      state_->lazy_pull_hooks.erase(std::string {offer_id});
    }

    [[nodiscard]] std::string_view name() const override {
      return "fake";
    }

  private:
    std::shared_ptr<fake_clipboard_state_t> state_;  ///< Shared state.
  };

  /**
   * @brief Make a factory returning a fake backend bound to `state`.
   *
   * @param state State.
   * @return Factory.
   */
  inline std::function<std::unique_ptr<::sds::clipboard::backend_t>()> fake_backend_factory(std::shared_ptr<fake_clipboard_state_t> state) {
    return [state]() {
      return std::make_unique<fake_clipboard_backend_t>(state);
    };
  }

  /**
   * @brief A minimal valid 1x1 RGBA PNG.
   *
   * @return PNG bytes.
   */
  inline std::string tiny_png() {
    static const unsigned char bytes[] = {
      0x89,
      0x50,
      0x4E,
      0x47,
      0x0D,
      0x0A,
      0x1A,
      0x0A,
      0x00,
      0x00,
      0x00,
      0x0D,
      0x49,
      0x48,
      0x44,
      0x52,
      0x00,
      0x00,
      0x00,
      0x01,
      0x00,
      0x00,
      0x00,
      0x01,
      0x08,
      0x06,
      0x00,
      0x00,
      0x00,
      0x1F,
      0x15,
      0xC4,
      0x89,
      0x00,
      0x00,
      0x00,
      0x0D,
      0x49,
      0x44,
      0x41,
      0x54,
      0x78,
      0x9C,
      0x63,
      0xF8,
      0xCF,
      0xC0,
      0xF0,
      0x1F,
      0x00,
      0x05,
      0x00,
      0x01,
      0xFF,
      0x89,
      0x99,
      0x3D,
      0x1D,
      0x00,
      0x00,
      0x00,
      0x00,
      0x49,
      0x45,
      0x4E,
      0x44,
      0xAE,
      0x42,
      0x60,
      0x82,
    };
    return std::string(reinterpret_cast<const char *>(bytes), sizeof(bytes));
  }
}  // namespace test_utils::sds
