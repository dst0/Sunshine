/**
 * @file src/platform/windows/mic_wasapi.cpp
 * @brief Windows virtual microphone: render decoded PCM into the playback side of a loopback cable
 *        (VB-CABLE "CABLE Input" or the Steam Streaming Microphone render endpoint, or `mic_device`).
 *        Applications record from the cable's capture side. No driver is shipped.
 */
// standard includes
#include <algorithm>
#include <cwctype>
#include <future>
#include <string>
#include <thread>

// platform includes
#include <Audioclient.h>
#include <mmdeviceapi.h>
#include <windows.h>

// local includes
#include "src/config.h"
#include "src/logging.h"
#include "src/sds/mic.h"
#include "utf_utils.h"

#ifndef AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM
  #define AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM 0x80000000
#endif
#ifndef AUDCLNT_STREAMFLAGS_SRC_DEFAULT_QUALITY
  #define AUDCLNT_STREAMFLAGS_SRC_DEFAULT_QUALITY 0x08000000
#endif

using namespace std::literals;

namespace sds::mic {
  namespace {
    /// PKEY_Device_FriendlyName, defined locally to stay independent of audio.cpp.
    const PROPERTYKEY mic_friendly_name_key = {{0xa45c254e, 0xdf1c, 0x4efd, {0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0}}, 14};

    template<class T>
    void release(T *p) {
      if (p) {
        p->Release();
      }
    }

    template<class T>
    using com_t = util::safe_ptr<T, &release<T>>;

    void free_co_string(wchar_t *p) {
      CoTaskMemFree(p);
    }

    using co_string_t = util::safe_ptr<wchar_t, &free_co_string>;

    /**
     * @brief Per-thread COM initialization guard.
     */
    struct com_scope_t {
      com_scope_t():
          hr {CoInitializeEx(nullptr, COINIT_MULTITHREADED)} {
      }

      ~com_scope_t() {
        if (SUCCEEDED(hr)) {
          CoUninitialize();
        }
      }

      com_scope_t(const com_scope_t &) = delete;
      com_scope_t &operator=(const com_scope_t &) = delete;

      HRESULT hr;  ///< Result of CoInitializeEx.
    };

    std::wstring lower(std::wstring s) {
      std::transform(s.begin(), s.end(), s.begin(), [](wchar_t c) {
        return static_cast<wchar_t>(std::towlower(c));
      });
      return s;
    }

    /**
     * @brief Find the render endpoint that feeds a virtual microphone.
     *
     * @param chosen_name Receives the endpoint's friendly name.
     * @return Endpoint ID, or empty when none matches.
     */
    std::wstring find_cable_render_endpoint(std::string *chosen_name) {
      com_scope_t com;

      com_t<IMMDeviceEnumerator> enumerator;
      if (FAILED(CoCreateInstance(CLSID_MMDeviceEnumerator, nullptr, CLSCTX_ALL, IID_IMMDeviceEnumerator, (void **) &enumerator))) {
        return {};
      }

      com_t<IMMDeviceCollection> collection;
      if (FAILED(enumerator->EnumAudioEndpoints(eRender, DEVICE_STATE_ACTIVE, &collection))) {
        return {};
      }

      const auto configured = lower(utf_utils::from_utf8(config::sds_mic.device));
      UINT count = 0;
      collection->GetCount(&count);

      std::wstring fallback_id;
      std::string fallback_name;
      for (UINT i = 0; i < count; ++i) {
        com_t<IMMDevice> device;
        if (FAILED(collection->Item(i, &device))) {
          continue;
        }
        co_string_t id;
        if (FAILED(device->GetId(&id)) || !id) {
          continue;
        }
        com_t<IPropertyStore> props;
        if (FAILED(device->OpenPropertyStore(STGM_READ, &props))) {
          continue;
        }
        PROPVARIANT value;
        PropVariantInit(&value);
        std::wstring name;
        if (SUCCEEDED(props->GetValue(mic_friendly_name_key, &value)) && value.vt == VT_LPWSTR && value.pwszVal) {
          name = value.pwszVal;
        }
        PropVariantClear(&value);

        const auto lname = lower(name);
        const std::wstring wid {id.get()};
        if (!configured.empty()) {
          // An explicit mic_device must match exactly one way or the other; no automatic fallback
          if (lname.find(configured) != std::wstring::npos || lower(wid) == configured) {
            *chosen_name = utf_utils::to_utf8(name);
            return wid;
          }
          continue;
        }
        if (lname.find(L"cable input") != std::wstring::npos) {
          *chosen_name = utf_utils::to_utf8(name);
          return wid;
        }
        if (fallback_id.empty() && lname.find(L"steam streaming microphone") != std::wstring::npos) {
          fallback_id = wid;
          fallback_name = utf_utils::to_utf8(name);
        }
      }
      *chosen_name = fallback_name;
      return fallback_id;
    }

    /**
     * @brief WASAPI shared-mode render client writing 48 kHz mono S16 into the cable endpoint.
     */
    class wasapi_sink_t: public sink_t {
    public:
      wasapi_sink_t() = default;

      ~wasapi_sink_t() override {
        stop();
      }

      wasapi_sink_t(const wasapi_sink_t &) = delete;
      wasapi_sink_t &operator=(const wasapi_sink_t &) = delete;

      int start() override {
        std::string name;
        auto id = find_cable_render_endpoint(&name);
        if (id.empty()) {
          BOOST_LOG(warning) << "Microphone: no virtual cable render endpoint found (install VB-CABLE or set mic_device)"sv;
          return -1;
        }

        std::promise<int> started;
        auto result = started.get_future();
        _thread = std::jthread {[this, id, &started](std::stop_token stop) {
          render_loop(stop, id, started);
        }};
        if (result.get() != 0) {
          _thread.request_stop();
          _thread.join();
          return -1;
        }
        BOOST_LOG(info) << "Microphone: rendering into ["sv << name << ']';
        return 0;
      }

      void write(std::span<const std::int16_t> pcm) override {
        _ring.write(pcm);
      }

      void stop() override {
        if (_thread.joinable()) {
          _thread.request_stop();
          _thread.join();
        }
        _ring.clear();
      }

      std::string_view name() const override {
        return "wasapi"sv;
      }

    private:
      void render_loop(std::stop_token stop, const std::wstring &id, std::promise<int> &started) {
        com_scope_t com;
        bool reported = false;
        auto report = [&](int value) {
          if (!reported) {
            reported = true;
            started.set_value(value);
          }
        };

        com_t<IMMDeviceEnumerator> enumerator;
        com_t<IMMDevice> device;
        com_t<IAudioClient> client;
        com_t<IAudioRenderClient> render;
        HANDLE event = nullptr;

        do {
          if (FAILED(CoCreateInstance(CLSID_MMDeviceEnumerator, nullptr, CLSCTX_ALL, IID_IMMDeviceEnumerator, (void **) &enumerator)) || FAILED(enumerator->GetDevice(id.c_str(), &device)) || FAILED(device->Activate(IID_IAudioClient, CLSCTX_ALL, nullptr, (void **) &client))) {
            break;
          }

          WAVEFORMATEX format {};
          format.wFormatTag = WAVE_FORMAT_PCM;
          format.nChannels = 1;
          format.nSamplesPerSec = SAMPLE_RATE;
          format.wBitsPerSample = 16;
          format.nBlockAlign = 2;
          format.nAvgBytesPerSec = SAMPLE_RATE * 2;

          constexpr REFERENCE_TIME buffer_duration = 400000;  // 40 ms in 100 ns units
          if (FAILED(client->Initialize(AUDCLNT_SHAREMODE_SHARED, AUDCLNT_STREAMFLAGS_EVENTCALLBACK | AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM | AUDCLNT_STREAMFLAGS_SRC_DEFAULT_QUALITY, buffer_duration, 0, &format, nullptr))) {
            break;
          }

          event = CreateEventW(nullptr, FALSE, FALSE, nullptr);
          UINT32 buffer_frames = 0;
          if (!event || FAILED(client->SetEventHandle(event)) || FAILED(client->GetBufferSize(&buffer_frames)) || FAILED(client->GetService(__uuidof(IAudioRenderClient), (void **) &render)) || FAILED(client->Start())) {
            break;
          }
          report(0);

          while (!stop.stop_requested()) {
            if (WaitForSingleObject(event, 100) != WAIT_OBJECT_0) {
              continue;
            }
            UINT32 padding = 0;
            if (FAILED(client->GetCurrentPadding(&padding))) {
              break;
            }
            const auto frames = buffer_frames - padding;
            if (frames == 0) {
              continue;
            }
            BYTE *data = nullptr;
            if (FAILED(render->GetBuffer(frames, &data))) {
              break;
            }
            _ring.read(std::span<std::int16_t> {reinterpret_cast<std::int16_t *>(data), frames});
            render->ReleaseBuffer(frames, 0);
          }
          client->Stop();
        } while (false);

        if (!reported) {
          BOOST_LOG(error) << "Microphone: couldn't open the virtual cable render endpoint"sv;
        }
        report(-1);
        if (event) {
          CloseHandle(event);
        }
      }

      pcm_ring_t _ring;  ///< Decoded PCM waiting for the render thread.
      std::jthread _thread;  ///< WASAPI render thread.
    };
  }  // namespace

  sink_provider_t platform_sink_provider() {
    return {
      []() {
        std::string name;
        return !find_cable_render_endpoint(&name).empty();
      },
      []() -> std::unique_ptr<sink_t> {
        return std::make_unique<wasapi_sink_t>();
      },
    };
  }
}  // namespace sds::mic
