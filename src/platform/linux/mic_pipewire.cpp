/**
 * @file src/platform/linux/mic_pipewire.cpp
 * @brief PipeWire virtual microphone: a pw_stream with media.class=Audio/Source (like module-loopback's
 *        playback side) fed with decoded 48 kHz mono PCM.
 */
// standard includes
#include <array>
#include <mutex>

// lib includes
#include <pipewire/pipewire.h>
#include <spa/param/audio/format-utils.h>
#include <spa/pod/builder.h>
#include <spa/utils/result.h>

// local includes
#include "mic_sinks.h"
#include "src/logging.h"

using namespace std::literals;

namespace sds::mic::linux_sinks {
  namespace {
    void ensure_pipewire_initialized() {
      static std::once_flag once;
      std::call_once(once, []() {
        pw_init(nullptr, nullptr);
      });
    }

    /**
     * @brief Virtual source node backed by a PipeWire output stream.
     */
    class pipewire_sink_t: public sink_t {
    public:
      pipewire_sink_t() = default;

      ~pipewire_sink_t() override {
        stop();
      }

      pipewire_sink_t(const pipewire_sink_t &) = delete;
      pipewire_sink_t &operator=(const pipewire_sink_t &) = delete;

      int start() override {
        ensure_pipewire_initialized();

        _loop = pw_thread_loop_new("sunshine-mic", nullptr);
        if (!_loop) {
          return -1;
        }
        _context = pw_context_new(pw_thread_loop_get_loop(_loop), nullptr, 0);
        if (!_context || pw_thread_loop_start(_loop) < 0) {
          stop();
          return -1;
        }

        pw_thread_loop_lock(_loop);
        _core = pw_context_connect(_context, nullptr, 0);
        if (!_core) {
          pw_thread_loop_unlock(_loop);
          BOOST_LOG(warning) << "Microphone: PipeWire daemon not reachable"sv;
          stop();
          return -1;
        }

        auto *props = pw_properties_new(
          PW_KEY_MEDIA_TYPE,
          "Audio",
          PW_KEY_MEDIA_CLASS,
          "Audio/Source",
          PW_KEY_NODE_NAME,
          NODE_NAME,
          PW_KEY_NODE_DESCRIPTION,
          NODE_DESCRIPTION,
          PW_KEY_NODE_LATENCY,
          "960/48000",
          PW_KEY_NODE_WANT_DRIVER,
          "true",
          PW_KEY_AUDIO_CHANNELS,
          "1",
          PW_KEY_AUDIO_RATE,
          "48000",
          nullptr
        );
        _stream = pw_stream_new(_core, NODE_DESCRIPTION, props);
        if (!_stream) {
          pw_thread_loop_unlock(_loop);
          stop();
          return -1;
        }
        pw_stream_add_listener(_stream, &_listener, &stream_events, this);

        std::array<std::uint8_t, 1024> pod_buffer {};
        struct spa_pod_builder builder = SPA_POD_BUILDER_INIT(pod_buffer.data(), static_cast<std::uint32_t>(pod_buffer.size()));
        std::array<std::uint32_t, 1> positions {SPA_AUDIO_CHANNEL_MONO};
        const auto *format = static_cast<const struct spa_pod *>(spa_pod_builder_add_object(
          &builder,
          SPA_TYPE_OBJECT_Format,
          SPA_PARAM_EnumFormat,
          SPA_FORMAT_mediaType,
          SPA_POD_Id(SPA_MEDIA_TYPE_audio),
          SPA_FORMAT_mediaSubtype,
          SPA_POD_Id(SPA_MEDIA_SUBTYPE_raw),
          SPA_FORMAT_AUDIO_format,
          SPA_POD_Id(SPA_AUDIO_FORMAT_S16),
          SPA_FORMAT_AUDIO_rate,
          SPA_POD_Int(SAMPLE_RATE),
          SPA_FORMAT_AUDIO_channels,
          SPA_POD_Int(1),
          SPA_FORMAT_AUDIO_position,
          SPA_POD_Array(sizeof(std::uint32_t), SPA_TYPE_Id, 1, positions.data())
        ));
        std::array params {format};

        // Same flags as module-loopback's playback stream. With media.class=Audio/Source the session
        // manager exposes the node as a capture device instead of linking it to a speaker.
        const auto flags = static_cast<enum pw_stream_flags>(PW_STREAM_FLAG_AUTOCONNECT | PW_STREAM_FLAG_MAP_BUFFERS);
        const auto result = pw_stream_connect(_stream, PW_DIRECTION_OUTPUT, PW_ID_ANY, flags, params.data(), static_cast<std::uint32_t>(params.size()));
        pw_thread_loop_unlock(_loop);
        if (result < 0) {
          BOOST_LOG(error) << "Microphone: couldn't connect PipeWire stream: "sv << spa_strerror(result);
          stop();
          return -1;
        }
        return 0;
      }

      void write(std::span<const std::int16_t> pcm) override {
        _ring.write(pcm);
      }

      void stop() override {
        if (_loop) {
          pw_thread_loop_lock(_loop);
          if (_stream) {
            spa_hook_remove(&_listener);
            pw_stream_disconnect(_stream);
            pw_stream_destroy(_stream);
            _stream = nullptr;
          }
          if (_core) {
            pw_core_disconnect(_core);
            _core = nullptr;
          }
          pw_thread_loop_unlock(_loop);
          pw_thread_loop_stop(_loop);
        }
        if (_context) {
          pw_context_destroy(_context);
          _context = nullptr;
        }
        if (_loop) {
          pw_thread_loop_destroy(_loop);
          _loop = nullptr;
        }
        _ring.clear();
      }

      std::string_view name() const override {
        return "pipewire"sv;
      }

    private:
      static void on_process(void *userdata) {
        auto *self = static_cast<pipewire_sink_t *>(userdata);
        auto *buffer = pw_stream_dequeue_buffer(self->_stream);
        if (!buffer) {
          return;
        }
        auto *spa_buffer = buffer->buffer;
        auto &data = spa_buffer->datas[0];
        if (!data.data) {
          pw_stream_queue_buffer(self->_stream, buffer);
          return;
        }

        constexpr std::uint32_t stride = sizeof(std::int16_t);
        auto frames = data.maxsize / stride;
        if (buffer->requested > 0 && buffer->requested < frames) {
          frames = static_cast<std::uint32_t>(buffer->requested);
        }
        self->_ring.read(std::span<std::int16_t> {static_cast<std::int16_t *>(data.data), frames});

        data.chunk->offset = 0;
        data.chunk->stride = stride;
        data.chunk->size = frames * stride;
        pw_stream_queue_buffer(self->_stream, buffer);
      }

      static constexpr struct pw_stream_events stream_events = {
        .version = PW_VERSION_STREAM_EVENTS,
        .process = on_process,
      };

      pcm_ring_t _ring;  ///< Decoded PCM waiting for the PipeWire graph.
      struct pw_thread_loop *_loop = nullptr;  ///< Dedicated PipeWire thread loop.
      struct pw_context *_context = nullptr;  ///< PipeWire context.
      struct pw_core *_core = nullptr;  ///< Connection to the PipeWire daemon.
      struct pw_stream *_stream = nullptr;  ///< The Audio/Source stream node.
      struct spa_hook _listener {};  ///< Stream event listener.
    };
  }  // namespace

  bool pipewire_available() {
    ensure_pipewire_initialized();
    auto *loop = pw_loop_new(nullptr);
    if (!loop) {
      return false;
    }
    auto *context = pw_context_new(loop, nullptr, 0);
    bool available = false;
    if (context) {
      if (auto *core = pw_context_connect(context, nullptr, 0)) {
        available = true;
        pw_core_disconnect(core);
      }
      pw_context_destroy(context);
    }
    pw_loop_destroy(loop);
    return available;
  }

  std::unique_ptr<sink_t> make_pipewire_sink() {
    return std::make_unique<pipewire_sink_t>();
  }
}  // namespace sds::mic::linux_sinks
