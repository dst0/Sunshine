/**
 * @file tests/unit/sds/fake_clipboard_backend.h
 * @brief In-memory clipboard backend for secure-desktop-stream tests.
 */
#pragma once

// standard includes
#include <functional>
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
    bool started = false;  ///< Currently watching.
    bool fail_start = false;  ///< Make start() fail.
    bool fail_write = false;  ///< Make write() fail.
    bool notify_own_writes = false;  ///< Violate the contract: report own writes as changes.

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
      0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
      0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4,
      0x89, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0xF8, 0xCF, 0xC0, 0xF0,
      0x1F, 0x00, 0x05, 0x00, 0x01, 0xFF, 0x89, 0x99, 0x3D, 0x1D, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45,
      0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
    };
    return std::string(reinterpret_cast<const char *>(bytes), sizeof(bytes));
  }
}  // namespace test_utils::sds
