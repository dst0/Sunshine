/**
 * @file src/sds/mic_sink_none.cpp
 * @brief Microphone passthrough sink provider for platforms without a virtual microphone backend.
 */
// local includes
#include "mic.h"

namespace sds::mic {
  sink_provider_t platform_sink_provider() {
    return {
      []() {
        return false;
      },
      []() -> std::unique_ptr<sink_t> {
        return nullptr;
      },
    };
  }
}  // namespace sds::mic
