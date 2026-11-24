/**
 * @file src/platform/linux/mic_sinks.h
 * @brief Linux virtual microphone backends for microphone passthrough.
 */
#pragma once

// standard includes
#include <memory>

// local includes
#include "src/sds/mic.h"

namespace sds::mic::linux_sinks {
  constexpr auto NODE_NAME = "sunshine-mic";  ///< PipeWire node name / PulseAudio source name.
  constexpr auto NODE_DESCRIPTION = "Moonlight Microphone";  ///< Human-readable device name.

  /**
   * @brief Whether a PipeWire daemon is reachable (always false without PipeWire support).
   *
   * @return True when a PipeWire core connection succeeds.
   */
  bool pipewire_available();

  /**
   * @brief Create a PipeWire `Audio/Source` stream sink.
   *
   * @return Sink, or nullptr without PipeWire support.
   */
  std::unique_ptr<sink_t> make_pipewire_sink();

  /**
   * @brief Whether a PulseAudio server is reachable.
   *
   * @return True when a PulseAudio context reaches the ready state.
   */
  bool pulse_available();

  /**
   * @brief Create a PulseAudio null-sink + remap-source sink.
   *
   * @return Sink.
   */
  std::unique_ptr<sink_t> make_pulse_sink();
}  // namespace sds::mic::linux_sinks
