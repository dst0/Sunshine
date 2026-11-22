/**
 * @file src/platform/linux/mic_linux.cpp
 * @brief Linux virtual microphone selection and the PulseAudio fallback
 *        (module-null-sink + module-remap-source, fed by a playback stream).
 */
// standard includes
#include <chrono>
#include <string>
#include <thread>
#include <vector>

// lib includes
#include <pulse/pulseaudio.h>

// local includes
#include "mic_sinks.h"
#include "src/logging.h"

using namespace std::literals;

namespace sds::mic {
  sink_provider_t platform_sink_provider() {
    return {
      []() {
        return linux_sinks::pipewire_available() || linux_sinks::pulse_available();
      },
      []() -> std::unique_ptr<sink_t> {
        if (linux_sinks::pipewire_available()) {
          return linux_sinks::make_pipewire_sink();
        }
        if (linux_sinks::pulse_available()) {
          return linux_sinks::make_pulse_sink();
        }
        return nullptr;
      },
    };
  }
}  // namespace sds::mic

namespace sds::mic::linux_sinks {
#ifndef SUNSHINE_MIC_PIPEWIRE
  bool pipewire_available() {
    return false;
  }

  std::unique_ptr<sink_t> make_pipewire_sink() {
    return nullptr;
  }
#endif

  namespace {
    constexpr auto NULL_SINK_NAME = "sunshine_mic_sink";

    /**
     * @brief PulseAudio virtual microphone: a mono null sink whose monitor is remapped into a real source.
     */
    class pulse_sink_t: public sink_t {
    public:
      pulse_sink_t() = default;

      ~pulse_sink_t() override {
        stop();
      }

      pulse_sink_t(const pulse_sink_t &) = delete;
      pulse_sink_t &operator=(const pulse_sink_t &) = delete;

      int start() override {
        _mainloop = pa_threaded_mainloop_new();
        if (!_mainloop || pa_threaded_mainloop_start(_mainloop) < 0) {
          stop();
          return -1;
        }

        pa_threaded_mainloop_lock(_mainloop);
        auto result = start_locked();
        pa_threaded_mainloop_unlock(_mainloop);
        if (result != 0) {
          stop();
        }
        return result;
      }

      void write(std::span<const std::int16_t> pcm) override {
        _ring.write(pcm);
      }

      void stop() override {
        if (_mainloop) {
          pa_threaded_mainloop_lock(_mainloop);
          if (_stream) {
            pa_stream_set_write_callback(_stream, nullptr, nullptr);
            pa_stream_set_state_callback(_stream, nullptr, nullptr);
            pa_stream_disconnect(_stream);
            pa_stream_unref(_stream);
            _stream = nullptr;
          }
          if (_context && pa_context_get_state(_context) == PA_CONTEXT_READY) {
            for (auto it = _modules.rbegin(); it != _modules.rend(); ++it) {
              wait_operation(pa_context_unload_module(_context, *it, &on_success, this));
            }
          }
          _modules.clear();
          if (_context) {
            pa_context_set_state_callback(_context, nullptr, nullptr);
            pa_context_disconnect(_context);
            pa_context_unref(_context);
            _context = nullptr;
          }
          pa_threaded_mainloop_unlock(_mainloop);
          pa_threaded_mainloop_stop(_mainloop);
          pa_threaded_mainloop_free(_mainloop);
          _mainloop = nullptr;
        }
        _ring.clear();
      }

      std::string_view name() const override {
        return "pulseaudio"sv;
      }

    private:
      int start_locked() {
        _context = pa_context_new(pa_threaded_mainloop_get_api(_mainloop), "Sunshine Microphone");
        if (!_context) {
          return -1;
        }
        pa_context_set_state_callback(_context, &on_context_state, this);
        if (pa_context_connect(_context, nullptr, PA_CONTEXT_NOFLAGS, nullptr) < 0) {
          return -1;
        }
        for (;;) {
          auto state = pa_context_get_state(_context);
          if (state == PA_CONTEXT_READY) {
            break;
          }
          if (!PA_CONTEXT_IS_GOOD(state)) {
            return -1;
          }
          pa_threaded_mainloop_wait(_mainloop);
        }

        const std::string null_args = std::string {"sink_name="} + NULL_SINK_NAME +
                                      " rate=48000 channels=1 channel_map=mono"
                                      " sink_properties='device.description=\"Moonlight Microphone Sink\"'";
        const std::string remap_args = std::string {"master="} + NULL_SINK_NAME + ".monitor source_name=" + NODE_NAME +
                                       " channels=1 channel_map=mono"
                                       " source_properties='device.description=\"" +
                                       NODE_DESCRIPTION + "\"'";
        if (load_module("module-null-sink", null_args) != 0 || load_module("module-remap-source", remap_args) != 0) {
          BOOST_LOG(error) << "Microphone: couldn't load PulseAudio virtual microphone modules"sv;
          return -1;
        }

        const pa_sample_spec spec {PA_SAMPLE_S16LE, static_cast<std::uint32_t>(SAMPLE_RATE), 1};
        pa_channel_map map;
        pa_channel_map_init_mono(&map);
        _stream = pa_stream_new(_context, NODE_DESCRIPTION, &spec, &map);
        if (!_stream) {
          return -1;
        }
        pa_stream_set_state_callback(_stream, &on_stream_state, this);
        pa_stream_set_write_callback(_stream, &on_write, this);

        pa_buffer_attr attr {};
        attr.maxlength = static_cast<std::uint32_t>(-1);
        attr.tlength = static_cast<std::uint32_t>(FRAME_SAMPLES * 2 * sizeof(std::int16_t));  // 40 ms
        attr.prebuf = static_cast<std::uint32_t>(-1);
        attr.minreq = static_cast<std::uint32_t>(-1);
        attr.fragsize = static_cast<std::uint32_t>(-1);
        if (pa_stream_connect_playback(_stream, NULL_SINK_NAME, &attr, PA_STREAM_ADJUST_LATENCY, nullptr, nullptr) < 0) {
          return -1;
        }
        for (;;) {
          auto state = pa_stream_get_state(_stream);
          if (state == PA_STREAM_READY) {
            return 0;
          }
          if (!PA_STREAM_IS_GOOD(state)) {
            return -1;
          }
          pa_threaded_mainloop_wait(_mainloop);
        }
      }

      int load_module(const char *module, const std::string &args) {
        _last_index = PA_INVALID_INDEX;
        wait_operation(pa_context_load_module(_context, module, args.c_str(), &on_index, this));
        if (_last_index == PA_INVALID_INDEX) {
          return -1;
        }
        _modules.push_back(_last_index);
        return 0;
      }

      void wait_operation(pa_operation *op) {
        if (!op) {
          return;
        }
        while (pa_operation_get_state(op) == PA_OPERATION_RUNNING) {
          pa_threaded_mainloop_wait(_mainloop);
        }
        pa_operation_unref(op);
      }

      static void on_context_state(pa_context *, void *userdata) {
        pa_threaded_mainloop_signal(static_cast<pulse_sink_t *>(userdata)->_mainloop, 0);
      }

      static void on_stream_state(pa_stream *, void *userdata) {
        pa_threaded_mainloop_signal(static_cast<pulse_sink_t *>(userdata)->_mainloop, 0);
      }

      static void on_index(pa_context *, std::uint32_t index, void *userdata) {
        auto *self = static_cast<pulse_sink_t *>(userdata);
        self->_last_index = index;
        pa_threaded_mainloop_signal(self->_mainloop, 0);
      }

      static void on_success(pa_context *, int, void *userdata) {
        pa_threaded_mainloop_signal(static_cast<pulse_sink_t *>(userdata)->_mainloop, 0);
      }

      static void on_write(pa_stream *stream, std::size_t bytes, void *userdata) {
        auto *self = static_cast<pulse_sink_t *>(userdata);
        std::vector<std::int16_t> samples(bytes / sizeof(std::int16_t));
        if (samples.empty()) {
          return;
        }
        self->_ring.read(samples);
        pa_stream_write(stream, samples.data(), samples.size() * sizeof(std::int16_t), nullptr, 0, PA_SEEK_RELATIVE);
      }

      pcm_ring_t _ring;  ///< Decoded PCM waiting for the PulseAudio server.
      pa_threaded_mainloop *_mainloop = nullptr;  ///< Dedicated PulseAudio thread.
      pa_context *_context = nullptr;  ///< Server connection.
      pa_stream *_stream = nullptr;  ///< Playback stream into the null sink.
      std::vector<std::uint32_t> _modules;  ///< Loaded module indices, unloaded in reverse order.
      std::uint32_t _last_index = PA_INVALID_INDEX;  ///< Result of the last module load.
    };
  }  // namespace

  bool pulse_available() {
    auto *mainloop = pa_mainloop_new();
    if (!mainloop) {
      return false;
    }
    auto *context = pa_context_new(pa_mainloop_get_api(mainloop), "Sunshine Microphone probe");
    bool available = false;
    if (context && pa_context_connect(context, nullptr, PA_CONTEXT_NOAUTOSPAWN, nullptr) >= 0) {
      const auto deadline = std::chrono::steady_clock::now() + 2s;
      while (std::chrono::steady_clock::now() < deadline) {
        auto state = pa_context_get_state(context);
        if (state == PA_CONTEXT_READY) {
          available = true;
          break;
        }
        if (!PA_CONTEXT_IS_GOOD(state)) {
          break;
        }
        if (pa_mainloop_iterate(mainloop, 0, nullptr) < 0) {
          break;
        }
        std::this_thread::sleep_for(5ms);
      }
      pa_context_disconnect(context);
    }
    if (context) {
      pa_context_unref(context);
    }
    pa_mainloop_free(mainloop);
    return available;
  }

  std::unique_ptr<sink_t> make_pulse_sink() {
    return std::make_unique<pulse_sink_t>();
  }
}  // namespace sds::mic::linux_sinks
