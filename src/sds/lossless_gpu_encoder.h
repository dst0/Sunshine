/**
 * @file src/sds/lossless_gpu_encoder.h
 * @brief Platform abstraction for host GPU Compute and CPU SIMD SDLL v1 lossless encoders.
 */
#pragma once

#include "lossless_codec.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace sds::lossless {

  class encoder_backend_t {
  public:
    virtual ~encoder_backend_t() = default;

    [[nodiscard]] virtual std::string name() const = 0;
    [[nodiscard]] virtual bool is_gpu() const = 0;

    virtual void reset() = 0;

    virtual bool encode_frame(
      const std::uint8_t *bgra,
      int stride,
      int width,
      int height,
      std::uint64_t frame_id,
      std::uint64_t capture_ts_us,
      hash_algo_e hash_algo,
      bool force_keyframe,
      std::vector<std::uint8_t> &out_packet,
      encode_stats_t *out_stats = nullptr
    ) = 0;
  };

  /**
   * @brief Create the CPU SIMD encoder backend (always available on all OSes).
   */
  std::unique_ptr<encoder_backend_t> make_cpu_encoder_backend(int thread_count = 0);

  /**
   * @brief Try to create the native GPU Compute encoder backend for the current OS
   *        (Metal on macOS, Vulkan Compute on Linux, D3D11 CS 5.0 on Windows).
   *        Returns nullptr if unavailable.
   */
  std::unique_ptr<encoder_backend_t> make_gpu_encoder_backend();

  /**
   * @brief Comma-separated list of supported lossless encoder backends on this host (e.g. "metal,cpu").
   */
  std::string available_encoder_backends();

  /**
   * @brief Select encoder backend according to preference ("auto", "gpu", "cpu").
   */
  std::unique_ptr<encoder_backend_t> select_encoder_backend(std::string_view preference);

}  // namespace sds::lossless
