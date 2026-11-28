/**
 * @file src/sds/lossless_gpu_d3d11.cpp
 * @brief Windows Direct3D 11 CS 5.0 bit-exact SDLL v1 lossless GPU Compute encoder.
 */

#include "lossless_gpu_encoder.h"

#ifdef _WIN32

#include <d3d11.h>
#include <d3dcompiler.h>
#include <wrl/client.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <vector>

#include "src/logging.h"

namespace sds::lossless {
  namespace {
    using Microsoft::WRL::ComPtr;

    struct d3d_copy_rect_t {
      std::uint32_t src_x;
      std::uint32_t src_y;
      std::uint32_t dst_x;
      std::uint32_t dst_y;
      std::uint32_t w;
      std::uint32_t h;
      std::uint32_t pad0;
      std::uint32_t pad1;
    };

    struct alignas(16) d3d_params_t {
      std::uint32_t width;
      std::uint32_t height;
      std::uint32_t tiles_x;
      std::uint32_t tiles_y;
      std::uint32_t is_keyframe;
      std::uint32_t copy_rect_count;
      std::uint32_t pad0;
      std::uint32_t pad1;
      d3d_copy_rect_t copy_rects[MAX_COPY_RECTS];
    };

    constexpr const char *kHlslEncoderSource = R"HLSL(
struct CopyRectParam {
    uint src_x;
    uint src_y;
    uint dst_x;
    uint dst_y;
    uint w;
    uint h;
    uint pad0;
    uint pad1;
};

cbuffer EncodeParams : register(b0) {
    uint width;
    uint height;
    uint tiles_x;
    uint tiles_y;
    uint is_keyframe;
    uint copy_rect_count;
    uint pad0;
    uint pad1;
    CopyRectParam copy_rects[4];
};

StructuredBuffer<uint> curr_bgra : register(t0);
StructuredBuffer<uint> prev_bgra : register(t1);
StructuredBuffer<uint> crc_table : register(t2);
RWStructuredBuffer<uint> pred_bgra : register(u0);
RWByteAddressBuffer out_slots : register(u1);
RWStructuredBuffer<uint> row_crcs : register(u2);

static const uint TILE_SZ = 32u;
static const uint SLOT_STRIDE = 3088u;
static const int RICE_ESCAPE_Q = 16;

groupshared uint sh_px[1024];
groupshared int sh_y[1024];
groupshared int sh_co[1024];
groupshared int sh_cg[1024];
groupshared uint sh_sy[1024];
groupshared uint sh_sco[1024];
groupshared uint sh_scg[1024];
groupshared uint sh_dirty;
groupshared uint sh_best_mode;
groupshared uint sh_best_size;

int floor_div2_i(int v) {
    return (v >= 0) ? (v >> 1) : -((-v + 1) >> 1);
}

void rgb8_to_ycocgr_i(uint r, uint g, uint b, out int out_y, out int out_co, out int out_cg) {
    int ri = (int)r;
    int gi = (int)g;
    int bi = (int)b;
    out_co = ri - bi;
    int t = bi + floor_div2_i(out_co);
    out_cg = gi - t;
    out_y = t + floor_div2_i(out_cg);
}

int med_predict_i(int a, int b, int c) {
    int mn = min(a, b);
    int mx = max(a, b);
    if (c >= mx) return mn;
    if (c <= mn) return mx;
    return a + b - c;
}

uint zigzag_u(int v) {
    return (v >= 0) ? (uint)(v * 2) : (uint)((-v) * 2 - 1);
}

uint read_sym(uint idx, uint ch) {
    if (ch == 0u) return sh_sy[idx];
    if (ch == 1u) return sh_sco[idx];
    return sh_scg[idx];
}

void slot_store_byte(uint byte_addr, uint v) {
    uint aligned = byte_addr & ~3u;
    uint shift = (byte_addr & 3u) * 8u;
    uint cur = out_slots.Load(aligned);
    out_slots.Store(aligned, (cur & ~(0xFFu << shift)) | ((v & 0xFFu) << shift));
}

uint measure_rice(uint tile_w, uint tile_h, int raw_bits, uint ch) {
    uint bit_count = 0u;
    for (uint y = 0u; y < tile_h; ++y) {
        uint row_off = y * tile_w;
        bool all_zero = true;
        for (uint x = 0u; x < tile_w; ++x) {
            if (read_sym(row_off + x, ch) != 0u) { all_zero = false; break; }
        }
        if (all_zero) { bit_count += 1u; continue; }
        int best_bits = 1 << 28;
        for (int k = 0; k < 8; ++k) {
            int bits = 4;
            for (uint x = 0u; x < tile_w; ++x) {
                uint q = read_sym(row_off + x, ch) >> k;
                if (q < (uint)RICE_ESCAPE_Q) bits += (int)q + 1 + k;
                else bits += RICE_ESCAPE_Q + raw_bits;
            }
            if (bits < best_bits) best_bits = bits;
        }
        bit_count += (uint)best_bits;
    }
    return (bit_count + 7u) >> 3;
}

uint write_rice(uint base_addr, uint tile_w, uint tile_h, int raw_bits, uint ch) {
    uint pos = base_addr;
    uint cur = 0u;
    int bits = 0;
    for (uint y = 0u; y < tile_h; ++y) {
        uint row_off = y * tile_w;
        bool all_zero = true;
        for (uint x = 0u; x < tile_w; ++x) {
            if (read_sym(row_off + x, ch) != 0u) { all_zero = false; break; }
        }
        if (all_zero) {
            cur <<= 1;
            if (++bits == 8) { slot_store_byte(pos++, cur); cur = 0u; bits = 0; }
            continue;
        }
        int best_k = 0;
        int best_bits = 1 << 28;
        for (int k = 0; k < 8; ++k) {
            int b = 4;
            for (uint x = 0u; x < tile_w; ++x) {
                uint q = read_sym(row_off + x, ch) >> k;
                if (q < (uint)RICE_ESCAPE_Q) b += (int)q + 1 + k;
                else b += RICE_ESCAPE_Q + raw_bits;
            }
            if (b < best_bits) { best_bits = b; best_k = k; }
        }
        cur = (cur << 1) | 1u;
        if (++bits == 8) { slot_store_byte(pos++, cur); cur = 0u; bits = 0; }
        for (int bi = 2; bi >= 0; --bi) {
            cur = (cur << 1) | (((uint)best_k >> bi) & 1u);
            if (++bits == 8) { slot_store_byte(pos++, cur); cur = 0u; bits = 0; }
        }
        for (uint x = 0u; x < tile_w; ++x) {
            uint u = read_sym(row_off + x, ch);
            uint q = u >> best_k;
            if (q < (uint)RICE_ESCAPE_Q) {
                for (int zi = 0; zi < (int)q; ++zi) {
                    cur <<= 1;
                    if (++bits == 8) { slot_store_byte(pos++, cur); cur = 0u; bits = 0; }
                }
                cur = (cur << 1) | 1u;
                if (++bits == 8) { slot_store_byte(pos++, cur); cur = 0u; bits = 0; }
                for (int bi = best_k - 1; bi >= 0; --bi) {
                    cur = (cur << 1) | ((u >> bi) & 1u);
                    if (++bits == 8) { slot_store_byte(pos++, cur); cur = 0u; bits = 0; }
                }
            } else {
                for (int zi = 0; zi < RICE_ESCAPE_Q; ++zi) {
                    cur <<= 1;
                    if (++bits == 8) { slot_store_byte(pos++, cur); cur = 0u; bits = 0; }
                }
                for (int bi = raw_bits - 1; bi >= 0; --bi) {
                    cur = (cur << 1) | ((u >> bi) & 1u);
                    if (++bits == 8) { slot_store_byte(pos++, cur); cur = 0u; bits = 0; }
                }
            }
        }
    }
    if (bits > 0) {
        cur <<= (8 - bits);
        slot_store_byte(pos++, cur);
    }
    return pos - base_addr;
}

[numthreads(16, 16, 1)]
void cs_copy_rects(uint3 gid : SV_DispatchThreadID) {
    if (gid.x >= width || gid.y >= height) return;
    uint sx = gid.x;
    uint sy = gid.y;
    for (uint i = 0u; i < copy_rect_count && i < 4u; ++i) {
        CopyRectParam r = copy_rects[i];
        if (gid.x >= r.dst_x && gid.x < r.dst_x + r.w &&
            gid.y >= r.dst_y && gid.y < r.dst_y + r.h) {
            sx = r.src_x + (gid.x - r.dst_x);
            sy = r.src_y + (gid.y - r.dst_y);
        }
    }
    pred_bgra[gid.y * width + gid.x] = prev_bgra[sy * width + sx] | 0xFF000000u;
}

[numthreads(64, 1, 1)]
void cs_encode_tiles(uint3 tgid : SV_GroupID, uint lid : SV_GroupIndex) {
    if (tgid.x >= tiles_x || tgid.y >= tiles_y) return;
    uint tile_x = tgid.x * TILE_SZ;
    uint tile_y = tgid.y * TILE_SZ;
    uint tile_w = min(TILE_SZ, width - tile_x);
    uint tile_h = min(TILE_SZ, height - tile_y);
    uint pixels = tile_w * tile_h;
    uint tile_idx = tgid.y * tiles_x + tgid.x;
    uint slot_addr = tile_idx * SLOT_STRIDE;

    if (lid == 0u) sh_dirty = 0u;
    GroupMemoryBarrierWithGroupSync();

    for (uint i = lid; i < pixels; i += 64u) {
        uint x = i % tile_w;
        uint y = i / tile_w;
        uint c_raw = curr_bgra[(tile_y + y) * width + (tile_x + x)] & 0x00FFFFFFu;
        uint r = (c_raw >> 16) & 0xFFu;
        uint g = (c_raw >> 8) & 0xFFu;
        uint b = c_raw & 0xFFu;
        sh_px[i] = r | (g << 8) | (b << 16);
        if (is_keyframe == 0u) {
            uint p_raw = prev_bgra[(tile_y + y) * width + (tile_x + x)] & 0x00FFFFFFu;
            if (p_raw != c_raw) InterlockedOr(sh_dirty, 1u);
        }
        int cy, cco, ccg;
        rgb8_to_ycocgr_i(r, g, b, cy, cco, ccg);
        sh_y[i] = cy; sh_co[i] = cco; sh_cg[i] = ccg;
    }
    GroupMemoryBarrierWithGroupSync();

    if (is_keyframe == 0u && sh_dirty == 0u) {
        if (lid == 0u) out_slots.Store(slot_addr, 0u);
        return;
    }

    for (uint i = lid; i < pixels; i += 64u) {
        uint x = i % tile_w;
        uint y = i / tile_w;
        int py = med_predict_i((x > 0u) ? sh_y[i - 1u] : 0, (y > 0u) ? sh_y[i - tile_w] : 0,
                               (x > 0u && y > 0u) ? sh_y[i - tile_w - 1u] : 0);
        int dy = ((sh_y[i] - py) & 0xFF);
        if (dy >= 128) dy -= 256;
        sh_sy[i] = zigzag_u(dy);

        int pco = med_predict_i((x > 0u) ? sh_co[i - 1u] : 0, (y > 0u) ? sh_co[i - tile_w] : 0,
                                (x > 0u && y > 0u) ? sh_co[i - tile_w - 1u] : 0);
        sh_sco[i] = zigzag_u(sh_co[i] - pco);

        int pcg = med_predict_i((x > 0u) ? sh_cg[i - 1u] : 0, (y > 0u) ? sh_cg[i - tile_w] : 0,
                                (x > 0u && y > 0u) ? sh_cg[i - tile_w - 1u] : 0);
        sh_scg[i] = zigzag_u(sh_cg[i] - pcg);
    }
    GroupMemoryBarrierWithGroupSync();

    if (lid == 0u) {
        uint raw_size = pixels * 3u;
        uint best_mode = 5u;
        uint best_size = raw_size;
        uint palette[16];
        uint pal_count = 0u;
        bool pal_overflow = false;
        for (uint i = 0u; i < pixels; ++i) {
            uint rgb = sh_px[i];
            int found = -1;
            for (uint p = 0u; p < pal_count; ++p) {
                if (palette[p] == rgb) { found = (int)p; break; }
            }
            if (found < 0) {
                if (pal_count < 16u) palette[pal_count++] = rgb;
                else { pal_overflow = true; break; }
            }
        }
        if (!pal_overflow && pal_count == 1u) {
            out_slots.Store(slot_addr, 1u | (1u << 8) | (3u << 16));
            slot_store_byte(slot_addr + 16u, palette[0] & 0xFFu);
            slot_store_byte(slot_addr + 17u, (palette[0] >> 8) & 0xFFu);
            slot_store_byte(slot_addr + 18u, (palette[0] >> 16) & 0xFFu);
            sh_best_mode = 1u;
            sh_best_size = 3u;
        } else {
            uint med_sz = 6u + measure_rice(tile_w, tile_h, 8, 0u)
                             + measure_rice(tile_w, tile_h, 10, 1u)
                             + measure_rice(tile_w, tile_h, 10, 2u);
            if (!pal_overflow && pal_count >= 2u) {
                int bpp = (pal_count <= 2u) ? 1 : (pal_count <= 4u ? 2 : 4);
                uint pal_sz = 1u + pal_count * 3u + ((pixels * (uint)bpp + 7u) >> 3);
                if (pal_sz < best_size) { best_size = pal_sz; best_mode = 2u; }
            }
            if (med_sz < best_size) { best_size = med_sz; best_mode = 3u; }
            sh_best_mode = best_mode;
            sh_best_size = best_size;
            if (best_mode == 2u) {
                int bpp = (pal_count <= 2u) ? 1 : (pal_count <= 4u ? 2 : 4);
                uint pos = slot_addr + 16u;
                slot_store_byte(pos++, pal_count);
                for (uint p = 0u; p < pal_count; ++p) {
                    slot_store_byte(pos++, palette[p] & 0xFFu);
                    slot_store_byte(pos++, (palette[p] >> 8) & 0xFFu);
                    slot_store_byte(pos++, (palette[p] >> 16) & 0xFFu);
                }
                uint cur = 0u;
                int bits = 0;
                for (uint i = 0u; i < pixels; ++i) {
                    uint rgb = sh_px[i];
                    uint idx = 0u;
                    for (uint p = 0u; p < pal_count; ++p) { if (palette[p] == rgb) { idx = p; break; } }
                    for (int bi = bpp - 1; bi >= 0; --bi) {
                        cur = (cur << 1) | ((idx >> bi) & 1u);
                        if (++bits == 8) { slot_store_byte(pos++, cur); cur = 0u; bits = 0; }
                    }
                }
                if (bits > 0) {
                    cur <<= (8 - bits);
                    slot_store_byte(pos++, cur);
                }
                sh_best_size = pos - (slot_addr + 16u);
            } else if (best_mode == 3u) {
                uint sy_len = write_rice(slot_addr + 22u, tile_w, tile_h, 8, 0u);
                uint sco_len = write_rice(slot_addr + 22u + sy_len, tile_w, tile_h, 10, 1u);
                uint scg_len = write_rice(slot_addr + 22u + sy_len + sco_len, tile_w, tile_h, 10, 2u);
                slot_store_byte(slot_addr + 16u, sy_len & 0xFFu); slot_store_byte(slot_addr + 17u, sy_len >> 8);
                slot_store_byte(slot_addr + 18u, sco_len & 0xFFu); slot_store_byte(slot_addr + 19u, sco_len >> 8);
                slot_store_byte(slot_addr + 20u, scg_len & 0xFFu); slot_store_byte(slot_addr + 21u, scg_len >> 8);
                sh_best_size = 6u + sy_len + sco_len + scg_len;
            }
        }
    }
    GroupMemoryBarrierWithGroupSync();

    if (sh_best_mode == 1u) return;

    if (is_keyframe == 0u) {
        for (uint i = lid; i < pixels; i += 64u) {
            uint x = i % tile_w;
            uint y = i / tile_w;
            uint p_raw = prev_bgra[(tile_y + y) * width + (tile_x + x)] & 0x00FFFFFFu;
            int py, pco, pcg;
            rgb8_to_ycocgr_i((p_raw >> 16) & 0xFFu, (p_raw >> 8) & 0xFFu, p_raw & 0xFFu, py, pco, pcg);
            int dy = ((sh_y[i] - py) & 0xFF);
            if (dy >= 128) dy -= 256;
            sh_sy[i] = zigzag_u(dy);
            sh_sco[i] = zigzag_u(sh_co[i] - pco);
            sh_scg[i] = zigzag_u(sh_cg[i] - pcg);
        }
        GroupMemoryBarrierWithGroupSync();

        if (lid == 0u) {
            uint temp_sz = 6u + measure_rice(tile_w, tile_h, 8, 0u)
                              + measure_rice(tile_w, tile_h, 10, 1u)
                              + measure_rice(tile_w, tile_h, 10, 2u);
            if (temp_sz < sh_best_size) {
                uint sy_len = write_rice(slot_addr + 22u, tile_w, tile_h, 8, 0u);
                uint sco_len = write_rice(slot_addr + 22u + sy_len, tile_w, tile_h, 10, 1u);
                uint scg_len = write_rice(slot_addr + 22u + sy_len + sco_len, tile_w, tile_h, 10, 2u);
                slot_store_byte(slot_addr + 16u, sy_len & 0xFFu); slot_store_byte(slot_addr + 17u, sy_len >> 8);
                slot_store_byte(slot_addr + 18u, sco_len & 0xFFu); slot_store_byte(slot_addr + 19u, sco_len >> 8);
                slot_store_byte(slot_addr + 20u, scg_len & 0xFFu); slot_store_byte(slot_addr + 21u, scg_len >> 8);
                sh_best_size = 6u + sy_len + sco_len + scg_len;
                sh_best_mode = 4u;
            }
        }
        GroupMemoryBarrierWithGroupSync();
    }

    if (lid == 0u) {
        if (sh_best_mode == 5u) {
            uint pos = slot_addr + 16u;
            for (uint i = 0u; i < pixels; ++i) {
                uint rgb = sh_px[i];
                slot_store_byte(pos++, rgb & 0xFFu);
                slot_store_byte(pos++, (rgb >> 8) & 0xFFu);
                slot_store_byte(pos++, (rgb >> 16) & 0xFFu);
            }
            sh_best_size = pixels * 3u;
        }
        out_slots.Store(slot_addr, 1u | (sh_best_mode << 8) | ((sh_best_size & 0xFFFFu) << 16));
    }
}

[numthreads(64, 1, 1)]
void cs_crc32c_rows(uint3 gid : SV_DispatchThreadID) {
    uint y = gid.x;
    if (y >= height) return;
    uint crc = 0xFFFFFFFFu;
    uint base = y * width;
    for (uint x = 0u; x < width; ++x) {
        uint px = curr_bgra[base + x];
        uint b = px & 0xFFu;
        uint g = (px >> 8) & 0xFFu;
        uint r = (px >> 16) & 0xFFu;
        crc = (crc >> 8) ^ crc_table[(crc ^ r) & 0xFFu];
        crc = (crc >> 8) ^ crc_table[(crc ^ g) & 0xFFu];
        crc = (crc >> 8) ^ crc_table[(crc ^ b) & 0xFFu];
    }
    row_crcs[y] = crc ^ 0xFFFFFFFFu;
}
)HLSL";

    inline void write_u16_le(std::uint8_t *p, std::uint16_t v) {
      p[0] = static_cast<std::uint8_t>(v & 0xFFu);
      p[1] = static_cast<std::uint8_t>((v >> 8) & 0xFFu);
    }

    inline void write_u32_le(std::uint8_t *p, std::uint32_t v) {
      p[0] = static_cast<std::uint8_t>(v & 0xFFu);
      p[1] = static_cast<std::uint8_t>((v >> 8) & 0xFFu);
      p[2] = static_cast<std::uint8_t>((v >> 16) & 0xFFu);
      p[3] = static_cast<std::uint8_t>((v >> 24) & 0xFFu);
    }

    class d3d11_encoder_backend_t final: public encoder_backend_t {
    public:
      d3d11_encoder_backend_t() {
        D3D_FEATURE_LEVEL levels[] = {D3D_FEATURE_LEVEL_11_0};
        D3D_FEATURE_LEVEL achieved {};
        if (FAILED(D3D11CreateDevice(
              nullptr,
              D3D_DRIVER_TYPE_HARDWARE,
              nullptr,
              0,
              levels,
              1,
              D3D11_SDK_VERSION,
              &device_,
              &achieved,
              &ctx_
            ))) {
          return;
        }
        auto compile_cs = [&](const char *entry, ComPtr<ID3D11ComputeShader> &out_cs) -> bool {
          ComPtr<ID3DBlob> blob;
          ComPtr<ID3DBlob> err;
          if (FAILED(D3DCompile(
                kHlslEncoderSource,
                std::strlen(kHlslEncoderSource),
                "sds_lossless_encode.hlsl",
                nullptr,
                nullptr,
                entry,
                "cs_5_0",
                D3DCOMPILE_OPTIMIZATION_LEVEL3,
                0,
                &blob,
                &err
              ))) {
            if (err) {
              BOOST_LOG(warning) << "sds lossless HLSL compile failed (" << entry << "): "
                                 << static_cast<const char *>(err->GetBufferPointer());
            }
            return false;
          }
          return SUCCEEDED(device_->CreateComputeShader(blob->GetBufferPointer(), blob->GetBufferSize(), nullptr, &out_cs));
        };
        if (!compile_cs("cs_copy_rects", cs_copy_rects_) ||
            !compile_cs("cs_encode_tiles", cs_encode_tiles_) ||
            !compile_cs("cs_crc32c_rows", cs_crc32c_)) {
          return;
        }

        D3D11_BUFFER_DESC cbd {};
        cbd.ByteWidth = sizeof(d3d_params_t);
        cbd.Usage = D3D11_USAGE_DYNAMIC;
        cbd.BindFlags = D3D11_BIND_CONSTANT_BUFFER;
        cbd.CPUAccessFlags = D3D11_CPU_ACCESS_WRITE;
        if (FAILED(device_->CreateBuffer(&cbd, nullptr, &cb_params_))) {
          return;
        }

        std::array<std::uint32_t, 256> tbl {};
        for (std::uint32_t i = 0; i < 256; ++i) {
          std::uint32_t c = i;
          for (int k = 0; k < 8; ++k) {
            c = (c & 1u) ? ((c >> 1) ^ 0x82F63B78u) : (c >> 1);
          }
          tbl[i] = c;
        }
        D3D11_BUFFER_DESC tbd {};
        tbd.ByteWidth = sizeof(tbl);
        tbd.Usage = D3D11_USAGE_IMMUTABLE;
        tbd.BindFlags = D3D11_BIND_SHADER_RESOURCE;
        tbd.MiscFlags = D3D11_RESOURCE_MISC_BUFFER_STRUCTURED;
        tbd.StructureByteStride = sizeof(std::uint32_t);
        D3D11_SUBRESOURCE_DATA init {};
        init.pSysMem = tbl.data();
        if (FAILED(device_->CreateBuffer(&tbd, &init, &crc_table_buf_))) {
          return;
        }
        D3D11_SHADER_RESOURCE_VIEW_DESC srvd {};
        srvd.Format = DXGI_FORMAT_UNKNOWN;
        srvd.ViewDimension = D3D11_SRV_DIMENSION_BUFFER;
        srvd.Buffer.NumElements = 256;
        ready_ = SUCCEEDED(device_->CreateShaderResourceView(crc_table_buf_.Get(), &srvd, &crc_table_srv_));
      }

      [[nodiscard]] bool is_ready() const {
        return ready_;
      }

      std::string name() const override {
        return "d3d11";
      }

      bool is_gpu() const override {
        return true;
      }

      void reset() override {
        has_prev_ = false;
        width_ = 0;
        height_ = 0;
      }

      bool encode_frame(
        const std::uint8_t *bgra,
        int stride,
        int width,
        int height,
        std::uint64_t frame_id,
        std::uint64_t capture_ts_us,
        hash_algo_e hash_algo,
        bool force_keyframe,
        std::vector<std::uint8_t> &out_packet,
        encode_stats_t *out_stats
      ) override {
        if (!ready_ || !bgra || width <= 0 || height <= 0 || width > MAX_FRAME_DIM || height > MAX_FRAME_DIM || stride < width * 4) {
          return false;
        }
        const bool dims_changed = (width != width_ || height != height_);
        const bool is_keyframe = force_keyframe || !has_prev_ || dims_changed;
        const int dst_stride = width * 4;
        const std::size_t frame_bytes = static_cast<std::size_t>(dst_stride) * static_cast<std::size_t>(height);
        const int tiles_x = (width + TILE_SIZE - 1) / TILE_SIZE;
        const int tiles_y = (height + TILE_SIZE - 1) / TILE_SIZE;
        const std::size_t total_tiles = static_cast<std::size_t>(tiles_x) * static_cast<std::size_t>(tiles_y);

        if (!ensure_buffers(width, height, frame_bytes, total_tiles)) {
          return false;
        }

        curr_cpu_.resize(frame_bytes);
        if (stride == dst_stride) {
          std::memcpy(curr_cpu_.data(), bgra, frame_bytes);
        } else {
          for (int y = 0; y < height; ++y) {
            std::memcpy(curr_cpu_.data() + static_cast<std::size_t>(y) * dst_stride, bgra + static_cast<std::size_t>(y) * stride, dst_stride);
          }
        }

        std::vector<copy_rect_t> copy_rects;
        if (!is_keyframe && prev_cpu_.size() == frame_bytes) {
          copy_rects = detect_scroll_copy_rects(prev_cpu_.data(), dst_stride, curr_cpu_.data(), dst_stride, width, height);
        }

        {
          D3D11_MAPPED_SUBRESOURCE ms {};
          if (FAILED(ctx_->Map(curr_upload_.Get(), 0, D3D11_MAP_WRITE_DISCARD, 0, &ms))) {
            return false;
          }
          std::memcpy(ms.pData, curr_cpu_.data(), frame_bytes);
          ctx_->Unmap(curr_upload_.Get(), 0);
        }
        {
          D3D11_MAPPED_SUBRESOURCE ms {};
          if (FAILED(ctx_->Map(cb_params_.Get(), 0, D3D11_MAP_WRITE_DISCARD, 0, &ms))) {
            return false;
          }
          auto *p = static_cast<d3d_params_t *>(ms.pData);
          std::memset(p, 0, sizeof(*p));
          p->width = static_cast<std::uint32_t>(width);
          p->height = static_cast<std::uint32_t>(height);
          p->tiles_x = static_cast<std::uint32_t>(tiles_x);
          p->tiles_y = static_cast<std::uint32_t>(tiles_y);
          p->is_keyframe = is_keyframe ? 1u : 0u;
          p->copy_rect_count = static_cast<std::uint32_t>(std::min<std::size_t>(copy_rects.size(), MAX_COPY_RECTS));
          for (std::uint32_t i = 0; i < p->copy_rect_count; ++i) {
            p->copy_rects[i].src_x = copy_rects[i].src_x;
            p->copy_rects[i].src_y = copy_rects[i].src_y;
            p->copy_rects[i].dst_x = copy_rects[i].dst_x;
            p->copy_rects[i].dst_y = copy_rects[i].dst_y;
            p->copy_rects[i].w = copy_rects[i].w;
            p->copy_rects[i].h = copy_rects[i].h;
          }
          ctx_->Unmap(cb_params_.Get(), 0);
        }

        ctx_->CSSetConstantBuffers(0, 1, cb_params_.GetAddressOf());
        if (!is_keyframe) {
          ID3D11ShaderResourceView *srvs[2] = {curr_srv_.Get(), prev_srv_.Get()};
          ID3D11UnorderedAccessView *uavs[1] = {pred_uav_.Get()};
          ctx_->CSSetShader(cs_copy_rects_.Get(), nullptr, 0);
          ctx_->CSSetShaderResources(0, 2, srvs);
          ctx_->CSSetUnorderedAccessViews(0, 1, uavs, nullptr);
          ctx_->Dispatch((static_cast<UINT>(width) + 15u) / 16u, (static_cast<UINT>(height) + 15u) / 16u, 1u);
          ID3D11UnorderedAccessView *null_uavs[1] = {nullptr};
          ctx_->CSSetUnorderedAccessViews(0, 1, null_uavs, nullptr);
        }

        {
          ID3D11ShaderResourceView *enc_srvs[3] = {curr_srv_.Get(), pred_srv_.Get(), crc_table_srv_.Get()};
          ID3D11UnorderedAccessView *enc_uavs[3] = {nullptr, slots_uav_.Get(), row_crc_uav_.Get()};
          ctx_->CSSetShader(cs_encode_tiles_.Get(), nullptr, 0);
          ctx_->CSSetShaderResources(0, 3, enc_srvs);
          ctx_->CSSetUnorderedAccessViews(0, 3, enc_uavs, nullptr);
          ctx_->Dispatch(static_cast<UINT>(tiles_x), static_cast<UINT>(tiles_y), 1u);

          if (hash_algo == hash_algo_e::crc32c) {
            ctx_->CSSetShader(cs_crc32c_.Get(), nullptr, 0);
            ctx_->Dispatch((static_cast<UINT>(height) + 63u) / 64u, 1u, 1u);
          }

          ID3D11UnorderedAccessView *null3[3] = {nullptr, nullptr, nullptr};
          ID3D11ShaderResourceView *null_s3[3] = {nullptr, nullptr, nullptr};
          ctx_->CSSetUnorderedAccessViews(0, 3, null3, nullptr);
          ctx_->CSSetShaderResources(0, 3, null_s3);
        }

        ctx_->CopyResource(slots_staging_.Get(), slots_buf_.Get());
        if (hash_algo == hash_algo_e::crc32c) {
          ctx_->CopyResource(row_crc_staging_.Get(), row_crc_buf_.Get());
        }
        ctx_->Flush();

        std::array<std::uint8_t, 32> frame_hash {};
        if (hash_algo == hash_algo_e::blake3) {
          frame_hash = blake3_rgb24_from_bgra(curr_cpu_.data(), dst_stride, width, height);
        } else if (hash_algo == hash_algo_e::crc32c) {
          D3D11_MAPPED_SUBRESOURCE ms {};
          if (FAILED(ctx_->Map(row_crc_staging_.Get(), 0, D3D11_MAP_READ, 0, &ms))) {
            return false;
          }
          const auto *row_crcs = static_cast<const std::uint32_t *>(ms.pData);
          const std::uint64_t row_bytes_rgb = static_cast<std::uint64_t>(width) * 3ULL;
          std::uint32_t combined = row_crcs[0];
          for (int y = 1; y < height; ++y) {
            combined = crc32c_combine(combined, row_crcs[y], row_bytes_rgb);
          }
          ctx_->Unmap(row_crc_staging_.Get(), 0);
          write_u32_le(frame_hash.data(), combined);
        }

        D3D11_MAPPED_SUBRESOURCE sms {};
        if (FAILED(ctx_->Map(slots_staging_.Get(), 0, D3D11_MAP_READ, 0, &sms))) {
          return false;
        }
        const auto *slots = static_cast<const std::uint8_t *>(sms.pData);

        const std::size_t copy_bytes = copy_rects.size() * COPY_RECT_WIRE_SIZE;
        const std::size_t bitmap_bytes = (total_tiles + 7u) / 8u;
        std::uint32_t dirty_count = 0;
        std::size_t dirty_bytes = 0;
        encode_stats_t stats {};
        stats.total_tiles = static_cast<std::uint32_t>(total_tiles);
        stats.copy_rects = static_cast<std::uint32_t>(copy_rects.size());

        for (std::size_t i = 0; i < total_tiles; ++i) {
          const std::uint8_t *slot = slots + i * static_cast<std::size_t>(GPU_TILE_SLOT_STRIDE);
          if (slot[0] == 0) {
            continue;
          }
          const std::uint16_t plen = static_cast<std::uint16_t>(slot[2]) |
                                     (static_cast<std::uint16_t>(slot[3]) << 8);
          if (plen == 0 || plen > MAX_TILE_PAYLOAD) {
            ctx_->Unmap(slots_staging_.Get(), 0);
            return false;
          }
          ++dirty_count;
          dirty_bytes += TILE_HEADER_SIZE + plen;
          switch (static_cast<tile_mode_e>(slot[1])) {
            case tile_mode_e::solid: ++stats.solid_tiles; break;
            case tile_mode_e::palette: ++stats.palette_tiles; break;
            case tile_mode_e::ycocgr_med_rice: ++stats.med_rice_tiles; break;
            case tile_mode_e::ycocgr_temporal_rice: ++stats.temporal_rice_tiles; break;
            case tile_mode_e::raw_rgb24: ++stats.raw_tiles; break;
          }
        }
        stats.dirty_tiles = dirty_count;

        const std::size_t payload_len = copy_bytes + bitmap_bytes + dirty_bytes;
        if (payload_len > MAX_PAYLOAD_BYTES) {
          ctx_->Unmap(slots_staging_.Get(), 0);
          return false;
        }

        out_packet.resize(HEADER_SIZE + payload_len);
        frame_header_t hdr;
        hdr.version = PROTOCOL_VERSION;
        hdr.flags = (is_keyframe ? FLAG_KEYFRAME : 0u) | FLAG_GPU_ENCODED;
        hdr.frame_id = frame_id;
        hdr.capture_ts_us = capture_ts_us;
        hdr.width = static_cast<std::uint16_t>(width);
        hdr.height = static_cast<std::uint16_t>(height);
        hdr.tile_size = TILE_SIZE;
        hdr.hash_algo = hash_algo;
        hdr.copy_rect_count = static_cast<std::uint8_t>(copy_rects.size());
        hdr.dirty_tile_count = dirty_count;
        hdr.payload_len = static_cast<std::uint32_t>(payload_len);
        hdr.frame_hash = frame_hash;
        write_frame_header(out_packet.data(), hdr);

        std::uint8_t *p = out_packet.data() + HEADER_SIZE;
        for (const auto &r : copy_rects) {
          write_u16_le(p + 0, r.src_x);
          write_u16_le(p + 2, r.src_y);
          write_u16_le(p + 4, r.dst_x);
          write_u16_le(p + 6, r.dst_y);
          write_u16_le(p + 8, r.w);
          write_u16_le(p + 10, r.h);
          p += COPY_RECT_WIRE_SIZE;
        }

        std::memset(p, 0, bitmap_bytes);
        for (std::size_t i = 0; i < total_tiles; ++i) {
          const std::uint8_t *slot = slots + i * static_cast<std::size_t>(GPU_TILE_SLOT_STRIDE);
          if (slot[0] != 0) {
            p[i >> 3] |= static_cast<std::uint8_t>(1u << (i & 7u));
          }
        }
        p += bitmap_bytes;

        for (std::size_t i = 0; i < total_tiles; ++i) {
          const std::uint8_t *slot = slots + i * static_cast<std::size_t>(GPU_TILE_SLOT_STRIDE);
          if (slot[0] == 0) {
            continue;
          }
          const std::uint16_t plen = static_cast<std::uint16_t>(slot[2]) |
                                     (static_cast<std::uint16_t>(slot[3]) << 8);
          p[0] = slot[1];
          write_u16_le(p + 1, plen);
          std::memcpy(p + TILE_HEADER_SIZE, slot + 16, plen);
          p += TILE_HEADER_SIZE + plen;
        }
        ctx_->Unmap(slots_staging_.Get(), 0);

        std::swap(curr_upload_, prev_upload_);
        std::swap(curr_srv_, prev_srv_);
        prev_cpu_.swap(curr_cpu_);
        has_prev_ = true;
        width_ = width;
        height_ = height;

        if (out_stats) {
          *out_stats = stats;
        }
        return true;
      }

    private:
      bool ensure_buffers(int width, int height, std::size_t frame_bytes, std::size_t total_tiles) {
        (void) width;
        if (frame_bytes > cap_frame_bytes_) {
          auto make_frame_srv = [&](ComPtr<ID3D11Buffer> &buf, ComPtr<ID3D11ShaderResourceView> &srv) -> bool {
            D3D11_BUFFER_DESC bd {};
            bd.ByteWidth = static_cast<UINT>(frame_bytes);
            bd.Usage = D3D11_USAGE_DYNAMIC;
            bd.BindFlags = D3D11_BIND_SHADER_RESOURCE;
            bd.CPUAccessFlags = D3D11_CPU_ACCESS_WRITE;
            bd.MiscFlags = D3D11_RESOURCE_MISC_BUFFER_STRUCTURED;
            bd.StructureByteStride = 4;
            if (FAILED(device_->CreateBuffer(&bd, nullptr, &buf))) {
              return false;
            }
            D3D11_SHADER_RESOURCE_VIEW_DESC sd {};
            sd.Format = DXGI_FORMAT_UNKNOWN;
            sd.ViewDimension = D3D11_SRV_DIMENSION_BUFFER;
            sd.Buffer.NumElements = static_cast<UINT>(frame_bytes / 4u);
            return SUCCEEDED(device_->CreateShaderResourceView(buf.Get(), &sd, &srv));
          };
          if (!make_frame_srv(curr_upload_, curr_srv_) || !make_frame_srv(prev_upload_, prev_srv_)) {
            return false;
          }
          D3D11_BUFFER_DESC pbd {};
          pbd.ByteWidth = static_cast<UINT>(frame_bytes);
          pbd.Usage = D3D11_USAGE_DEFAULT;
          pbd.BindFlags = D3D11_BIND_SHADER_RESOURCE | D3D11_BIND_UNORDERED_ACCESS;
          pbd.MiscFlags = D3D11_RESOURCE_MISC_BUFFER_STRUCTURED;
          pbd.StructureByteStride = 4;
          if (FAILED(device_->CreateBuffer(&pbd, nullptr, &pred_buf_))) {
            return false;
          }
          D3D11_SHADER_RESOURCE_VIEW_DESC psd {};
          psd.Format = DXGI_FORMAT_UNKNOWN;
          psd.ViewDimension = D3D11_SRV_DIMENSION_BUFFER;
          psd.Buffer.NumElements = static_cast<UINT>(frame_bytes / 4u);
          D3D11_UNORDERED_ACCESS_VIEW_DESC pud {};
          pud.Format = DXGI_FORMAT_UNKNOWN;
          pud.ViewDimension = D3D11_UAV_DIMENSION_BUFFER;
          pud.Buffer.NumElements = static_cast<UINT>(frame_bytes / 4u);
          if (FAILED(device_->CreateShaderResourceView(pred_buf_.Get(), &psd, &pred_srv_)) ||
              FAILED(device_->CreateUnorderedAccessView(pred_buf_.Get(), &pud, &pred_uav_))) {
            return false;
          }
          cap_frame_bytes_ = frame_bytes;
        }

        const std::size_t slots_bytes = total_tiles * static_cast<std::size_t>(GPU_TILE_SLOT_STRIDE);
        if (slots_bytes > cap_slots_bytes_) {
          D3D11_BUFFER_DESC bd {};
          bd.ByteWidth = static_cast<UINT>(slots_bytes);
          bd.Usage = D3D11_USAGE_DEFAULT;
          bd.BindFlags = D3D11_BIND_UNORDERED_ACCESS;
          bd.MiscFlags = D3D11_RESOURCE_MISC_BUFFER_ALLOW_RAW_VIEWS;
          if (FAILED(device_->CreateBuffer(&bd, nullptr, &slots_buf_))) {
            return false;
          }
          D3D11_UNORDERED_ACCESS_VIEW_DESC ud {};
          ud.Format = DXGI_FORMAT_R32_TYPELESS;
          ud.ViewDimension = D3D11_UAV_DIMENSION_BUFFER;
          ud.Buffer.NumElements = static_cast<UINT>(slots_bytes / 4u);
          ud.Buffer.Flags = D3D11_BUFFER_UAV_FLAG_RAW;
          if (FAILED(device_->CreateUnorderedAccessView(slots_buf_.Get(), &ud, &slots_uav_))) {
            return false;
          }
          bd.Usage = D3D11_USAGE_STAGING;
          bd.BindFlags = 0;
          bd.MiscFlags = 0;
          bd.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
          if (FAILED(device_->CreateBuffer(&bd, nullptr, &slots_staging_))) {
            return false;
          }
          cap_slots_bytes_ = slots_bytes;
        }

        const std::size_t row_bytes = static_cast<std::size_t>(height) * sizeof(std::uint32_t);
        if (row_bytes > cap_row_bytes_) {
          D3D11_BUFFER_DESC bd {};
          bd.ByteWidth = static_cast<UINT>(row_bytes);
          bd.Usage = D3D11_USAGE_DEFAULT;
          bd.BindFlags = D3D11_BIND_UNORDERED_ACCESS;
          bd.MiscFlags = D3D11_RESOURCE_MISC_BUFFER_STRUCTURED;
          bd.StructureByteStride = sizeof(std::uint32_t);
          if (FAILED(device_->CreateBuffer(&bd, nullptr, &row_crc_buf_))) {
            return false;
          }
          D3D11_UNORDERED_ACCESS_VIEW_DESC ud {};
          ud.Format = DXGI_FORMAT_UNKNOWN;
          ud.ViewDimension = D3D11_UAV_DIMENSION_BUFFER;
          ud.Buffer.NumElements = static_cast<UINT>(height);
          if (FAILED(device_->CreateUnorderedAccessView(row_crc_buf_.Get(), &ud, &row_crc_uav_))) {
            return false;
          }
          bd.Usage = D3D11_USAGE_STAGING;
          bd.BindFlags = 0;
          bd.MiscFlags = 0;
          bd.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
          if (FAILED(device_->CreateBuffer(&bd, nullptr, &row_crc_staging_))) {
            return false;
          }
          cap_row_bytes_ = row_bytes;
        }
        return true;
      }

      ComPtr<ID3D11Device> device_;
      ComPtr<ID3D11DeviceContext> ctx_;
      ComPtr<ID3D11ComputeShader> cs_copy_rects_;
      ComPtr<ID3D11ComputeShader> cs_encode_tiles_;
      ComPtr<ID3D11ComputeShader> cs_crc32c_;
      ComPtr<ID3D11Buffer> cb_params_;
      ComPtr<ID3D11Buffer> crc_table_buf_;
      ComPtr<ID3D11ShaderResourceView> crc_table_srv_;
      ComPtr<ID3D11Buffer> curr_upload_;
      ComPtr<ID3D11Buffer> prev_upload_;
      ComPtr<ID3D11Buffer> pred_buf_;
      ComPtr<ID3D11Buffer> slots_buf_;
      ComPtr<ID3D11Buffer> slots_staging_;
      ComPtr<ID3D11Buffer> row_crc_buf_;
      ComPtr<ID3D11Buffer> row_crc_staging_;
      ComPtr<ID3D11ShaderResourceView> curr_srv_;
      ComPtr<ID3D11ShaderResourceView> prev_srv_;
      ComPtr<ID3D11ShaderResourceView> pred_srv_;
      ComPtr<ID3D11UnorderedAccessView> pred_uav_;
      ComPtr<ID3D11UnorderedAccessView> slots_uav_;
      ComPtr<ID3D11UnorderedAccessView> row_crc_uav_;
      std::vector<std::uint8_t> curr_cpu_;
      std::vector<std::uint8_t> prev_cpu_;
      std::size_t cap_frame_bytes_ = 0;
      std::size_t cap_slots_bytes_ = 0;
      std::size_t cap_row_bytes_ = 0;
      int width_ = 0;
      int height_ = 0;
      bool has_prev_ = false;
      bool ready_ = false;
    };
  }  // namespace

  std::unique_ptr<encoder_backend_t> make_gpu_encoder_backend() {
    auto enc = std::make_unique<d3d11_encoder_backend_t>();
    return enc->is_ready() ? std::move(enc) : nullptr;
  }

  std::string available_encoder_backends() {
    ComPtr<ID3D11Device> dev;
    ComPtr<ID3D11DeviceContext> ctx;
    D3D_FEATURE_LEVEL lvl {};
    D3D_FEATURE_LEVEL req = D3D_FEATURE_LEVEL_11_0;
    if (SUCCEEDED(D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0, &req, 1, D3D11_SDK_VERSION, &dev, &lvl, &ctx))) {
      return "d3d11,cpu";
    }
    return "cpu";
  }
}  // namespace sds::lossless

#endif
