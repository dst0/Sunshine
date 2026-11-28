<script setup>
import {ref} from 'vue'
import {$tp} from '../../platform-i18n'
import PlatformLayout from '../../PlatformLayout.vue'
import AdapterNameSelector from './audiovideo/AdapterNameSelector.vue'
import DisplayOutputSelector from './audiovideo/DisplayOutputSelector.vue'
import DisplayDeviceOptions from "./audiovideo/DisplayDeviceOptions.vue";
import DisplayModesSettings from "./audiovideo/DisplayModesSettings.vue";
import Checkbox from "../../Checkbox.vue";

const props = defineProps({
  platform: String,
  config: Object,
})

const config = ref(props.config)
</script>

<template>
  <div id="audio-video" class="config-page">
    <!-- Audio Sink -->
    <div class="mb-3">
      <label for="audio_sink" class="form-label">{{ $t('config.audio_sink') }}</label>
      <input type="text" class="form-control" id="audio_sink"
             :placeholder="$tp('config.audio_sink_placeholder', 'alsa_output.pci-0000_09_00.3.analog-stereo')"
             v-model="config.audio_sink" />
      <div class="form-text">
        {{ $tp('config.audio_sink_desc') }}<br>
        <PlatformLayout :platform="platform">
          <template #windows>
            <pre>tools\audio-info.exe</pre>
          </template>
          <template #freebsd>
            <pre>pacmd list-sinks | grep "name:"</pre>
            <pre>pactl list short sinks</pre>
          </template>
          <template #linux>
            <pre>pacmd list-sinks | grep "name:"</pre>
            <pre>pactl list short sinks</pre>
          </template>
          <template #macos>
            <a href="https://github.com/mattingalls/Soundflower" target="_blank">Soundflower</a><br>
            <a href="https://github.com/ExistentialAudio/BlackHole" target="_blank">BlackHole</a>.
          </template>
        </PlatformLayout>
      </div>
    </div>


    <PlatformLayout :platform="platform">
      <template #windows>
        <!-- Virtual Sink -->
        <div class="mb-3">
          <label for="virtual_sink" class="form-label">{{ $t('config.virtual_sink') }}</label>
          <input type="text" class="form-control" id="virtual_sink" :placeholder="$t('config.virtual_sink_placeholder')"
                 v-model="config.virtual_sink" />
          <div class="form-text">{{ $t('config.virtual_sink_desc') }}</div>
        </div>

        <!-- Install Steam Audio Drivers -->
        <Checkbox class="mb-3"
                  id="install_steam_audio_drivers"
                  locale-prefix="config"
                  v-model="config.install_steam_audio_drivers"
                  default="true"
        ></Checkbox>
      </template>
    </PlatformLayout>

    <!-- Disable Audio -->
    <Checkbox class="mb-3"
              id="stream_audio"
              locale-prefix="config"
              v-model="config.stream_audio"
              default="true"
    ></Checkbox>

    <PlatformLayout :platform="platform">
      <template #windows>
        <!-- Externally Managed Audio -->
        <Checkbox class="mb-3"
                  id="external_audio"
                  locale-prefix="config"
                  v-model="config.external_audio"
                  default="false"
        ></Checkbox>
      </template>
    </PlatformLayout>

    <!-- Microphone Passthrough (secure-desktop-stream) -->
    <Checkbox class="mb-3"
              id="mic_passthrough"
              locale-prefix="config"
              v-model="config.mic_passthrough"
              default="true"
    ></Checkbox>

    <PlatformLayout :platform="platform">
      <template #windows>
        <!-- Microphone Device -->
        <div class="mb-3">
          <label for="mic_device" class="form-label">{{ $t('config.mic_device') }}</label>
          <input type="text" class="form-control" id="mic_device" placeholder="CABLE Input"
                 v-model="config.mic_device" />
          <div class="form-text">{{ $t('config.mic_device_desc') }}</div>
        </div>
      </template>
    </PlatformLayout>

    <AdapterNameSelector
        :platform="platform"
        :config="config"
    />

    <DisplayOutputSelector
      :platform="platform"
      :config="config"
    />

    <DisplayDeviceOptions
      :platform="platform"
      :config="config"
    />

    <!-- Display Modes -->
    <DisplayModesSettings
        :platform="platform"
        :config="config"
    />

    <!-- Bit-Exact Lossless Video (secure-desktop-stream) -->
    <Checkbox class="mb-3"
              id="lossless_video"
              locale-prefix="config"
              v-model="config.lossless_video"
              default="true"
    ></Checkbox>

    <div class="mb-3" v-if="config.lossless_video === 'enabled' || config.lossless_video === true">
      <label for="lossless_encoder" class="form-label">{{ $t('config.lossless_encoder') }}</label>
      <select id="lossless_encoder" class="form-select" v-model="config.lossless_encoder">
        <option value="auto">{{ $t('config.lossless_encoder_auto') }}</option>
        <option value="gpu">{{ $t('config.lossless_encoder_gpu') }}</option>
        <option value="cpu">{{ $t('config.lossless_encoder_cpu') }}</option>
      </select>
      <div class="form-text">{{ $t('config.lossless_encoder_desc') }}</div>
    </div>

  </div>
</template>
