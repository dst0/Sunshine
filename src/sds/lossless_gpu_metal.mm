/**
 * @file src/sds/lossless_gpu_metal.mm
 * @brief macOS Metal Compute SDLL v1 bit-exact lossless encoder + Castagnoli CRC32C shader.
 */

#include "lossless_gpu_encoder.h"

#import <Foundation/Foundation.h>
#import <Metal/Metal.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <vector>

#ifdef SDS_LOSSLESS_NO_BOOST_LOG
#include <iostream>
#define BOOST_LOG(lvl) if (false) std::cerr
#else
#include "src/logging.h"
#endif

namespace sds::lossless {
  namespace {
    struct alignas(16) metal_copy_rect_t {
      std::uint32_t src_x;
      std::uint32_t src_y;
      std::uint32_t dst_x;
      std::uint32_t dst_y;
      std::uint32_t w;
      std::uint32_t h;
      std::uint32_t pad0;
      std::uint32_t pad1;
    };

    struct alignas(16) metal_encode_params_t {
      std::uint32_t width;
      std::uint32_t height;
      std::uint32_t curr_stride;
      std::uint32_t pred_stride;
      std::uint32_t tiles_x;
      std::uint32_t tiles_y;
      std::uint32_t is_keyframe;
      std::uint32_t copy_rect_count;
      metal_copy_rect_t copy_rects[MAX_COPY_RECTS];
    };

    constexpr const char *kMetalEncoderSource = R"METAL(
#include <metal_stdlib>
using namespace metal;

constant uint TILE_SZ = 32u;
constant uint SLOT_STRIDE = 3088u;
constant int RICE_ESCAPE_Q = 16;

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

struct EncodeParams {
    uint width;
    uint height;
    uint curr_stride;
    uint pred_stride;
    uint tiles_x;
    uint tiles_y;
    uint is_keyframe;
    uint copy_rect_count;
    CopyRectParam copy_rects[4];
};

inline int floor_div2_i(int v) {
    return (v >= 0) ? (v >> 1) : -((-v + 1) >> 1);
}

inline void rgb8_to_ycocgr_i(uint r, uint g, uint b, thread int& out_y, thread int& out_co, thread int& out_cg) {
    int ri = int(r);
    int gi = int(g);
    int bi = int(b);
    out_co = ri - bi;
    int t = bi + floor_div2_i(out_co);
    out_cg = gi - t;
    out_y = t + floor_div2_i(out_cg);
}

inline int med_predict_i(int a, int b, int c) {
    int mn = min(a, b);
    int mx = max(a, b);
    if (c >= mx) return mn;
    if (c <= mn) return mx;
    return a + b - c;
}

inline ushort zigzag_u16(int v) {
    return ushort((v >= 0) ? (v * 2) : ((-v) * 2 - 1));
}

inline uint read_px_rgb(device const uchar* base, uint stride, uint x, uint y) {
    device const uchar* p = base + ulong(y) * ulong(stride) + ulong(x) * 4ul;
    return uint(p[2]) | (uint(p[1]) << 8) | (uint(p[0]) << 16);
}

// Measure exact compressed byte size of one Rice channel (matches lossless_codec.cpp bit-for-bit)
inline uint measure_rice_channel_u16(threadgroup const ushort* syms, uint tile_w, uint tile_h, int raw_bits) {
    uint bit_count = 0u;
    for (uint y = 0u; y < tile_h; ++y) {
        uint row_off = y * tile_w;
        bool all_zero = true;
        for (uint x = 0u; x < tile_w; ++x) {
            uint v = (syms[row_off + x] >> 0);
            if (v != 0u) {
                all_zero = false;
                break;
            }
        }
        if (all_zero) {
            bit_count += 1u;
            continue;
        }
        int best_bits = 1 << 28;
        for (int k = 0; k < 8; ++k) {
            int bits = 4;
            for (uint x = 0u; x < tile_w; ++x) {
                uint q = uint(syms[row_off + x]) >> k;
                if (q < uint(RICE_ESCAPE_Q)) {
                    bits += int(q) + 1 + k;
                } else {
                    bits += RICE_ESCAPE_Q + raw_bits;
                }
            }
            if (bits < best_bits) {
                best_bits = bits;
            }
        }
        bit_count += uint(best_bits);
    }
    return (bit_count + 7u) >> 3;
}

// Extract packed 16-bit symbol arrays from shared uint/ushort storage
struct BitWriter {
    device uchar* out;
    uint pos;
    uint cur;
    int bits;

    void write_bit(uint bit) {
        cur = (cur << 1) | (bit & 1u);
        ++bits;
        if (bits == 8) {
            out[pos++] = uchar(cur & 0xFFu);
            cur = 0u;
            bits = 0;
        }
    }

    void write_bits(uint val, int count) {
        for (int i = count - 1; i >= 0; --i) {
            write_bit((val >> i) & 1u);
        }
    }

    void write_zeros(int count) {
        for (int i = 0; i < count; ++i) {
            write_bit(0u);
        }
    }

    void align() {
        if (bits > 0) {
            cur <<= (8 - bits);
            out[pos++] = uchar(cur & 0xFFu);
            cur = 0u;
            bits = 0;
        }
    }
};

inline uint write_rice_channel_u16(threadgroup const ushort* syms, uint tile_w, uint tile_h, int raw_bits, device uchar* out) {
    BitWriter bw;
    bw.out = out;
    bw.pos = 0u;
    bw.cur = 0u;
    bw.bits = 0;

    for (uint y = 0u; y < tile_h; ++y) {
        uint row_off = y * tile_w;
        bool all_zero = true;
        for (uint x = 0u; x < tile_w; ++x) {
            if (syms[row_off + x] != 0u) {
                all_zero = false;
                break;
            }
        }
        if (all_zero) {
            bw.write_bit(0u);
            continue;
        }

        int best_k = 0;
        int best_bits = 1 << 28;
        for (int k = 0; k < 8; ++k) {
            int bits = 4;
            for (uint x = 0u; x < tile_w; ++x) {
                uint q = uint(syms[row_off + x]) >> k;
                if (q < uint(RICE_ESCAPE_Q)) {
                    bits += int(q) + 1 + k;
                } else {
                    bits += RICE_ESCAPE_Q + raw_bits;
                }
            }
            if (bits < best_bits) {
                best_bits = bits;
                best_k = k;
            }
        }

        bw.write_bit(1u);
        bw.write_bits(uint(best_k), 3);
        uint rem_mask = (1u << best_k) - 1u;
        for (uint x = 0u; x < tile_w; ++x) {
            uint u = uint(syms[row_off + x]);
            uint q = u >> best_k;
            if (q < uint(RICE_ESCAPE_Q)) {
                bw.write_zeros(int(q));
                bw.write_bit(1u);
                if (best_k > 0) {
                    bw.write_bits(u & rem_mask, best_k);
                }
            } else {
                bw.write_zeros(RICE_ESCAPE_Q);
                bw.write_bits(u, raw_bits);
            }
        }
    }
    bw.align();
    return bw.pos;
}

kernel void cs_copy_rects(
    device const uchar* prev_bgra [[buffer(0)]],
    device uchar* pred_bgra [[buffer(1)]],
    constant EncodeParams& params [[buffer(2)]],
    uint2 gid [[thread_position_in_grid]])
{
    if (gid.x >= params.width || gid.y >= params.height) {
        return;
    }
    uint src_x = gid.x;
    uint src_y = gid.y;
    // Last matching CopyRect wins (forward order overwrite semantics)
    for (uint i = 0u; i < params.copy_rect_count && i < 4u; ++i) {
        CopyRectParam r = params.copy_rects[i];
        if (gid.x >= r.dst_x && gid.x < r.dst_x + r.w &&
            gid.y >= r.dst_y && gid.y < r.dst_y + r.h) {
            src_x = r.src_x + (gid.x - r.dst_x);
            src_y = r.src_y + (gid.y - r.dst_y);
        }
    }
    device const uchar* sp = prev_bgra + ulong(src_y) * ulong(params.pred_stride) + ulong(src_x) * 4ul;
    device uchar* dp = pred_bgra + ulong(gid.y) * ulong(params.pred_stride) + ulong(gid.x) * 4ul;
    dp[0] = sp[0];
    dp[1] = sp[1];
    dp[2] = sp[2];
    dp[3] = 255;
}

kernel void cs_encode_tiles(
    device const uchar* curr_bgra [[buffer(0)]],
    device const uchar* pred_bgra [[buffer(1)]],
    device uchar* out_slots [[buffer(2)]],
    constant EncodeParams& params [[buffer(3)]],
    uint2 tgid [[threadgroup_position_in_grid]],
    uint lid [[thread_index_in_threadgroup]])
{
    if (tgid.x >= params.tiles_x || tgid.y >= params.tiles_y) {
        return;
    }

    uint tile_x = tgid.x * TILE_SZ;
    uint tile_y = tgid.y * TILE_SZ;
    uint tile_w = min(TILE_SZ, params.width - tile_x);
    uint tile_h = min(TILE_SZ, params.height - tile_y);
    uint pixels = tile_w * tile_h;
    uint tile_idx = tgid.y * params.tiles_x + tgid.x;
    device uchar* slot = out_slots + ulong(tile_idx) * ulong(SLOT_STRIDE);

    threadgroup uint tg_px[1024];       // packed R | (G<<8) | (B<<16)
    threadgroup short tg_y[1024];
    threadgroup short tg_co[1024];
    threadgroup short tg_cg[1024];
    threadgroup ushort tg_sy[1024];
    threadgroup ushort tg_sco[1024];
    threadgroup ushort tg_scg[1024];
    threadgroup atomic_uint tg_dirty;
    threadgroup uint tg_best_mode;
    threadgroup uint tg_best_size;

    if (lid == 0u) {
        atomic_store_explicit(&tg_dirty, 0u, memory_order_relaxed);
    }
    threadgroup_barrier(mem_flags::mem_threadgroup);

    for (uint i = lid; i < pixels; i += 64u) {
        uint x = i % tile_w;
        uint y = i / tile_w;
        uint c_rgb = read_px_rgb(curr_bgra, params.curr_stride, tile_x + x, tile_y + y);
        tg_px[i] = c_rgb;
        if (params.is_keyframe == 0u) {
            uint p_rgb = read_px_rgb(pred_bgra, params.pred_stride, tile_x + x, tile_y + y);
            if (p_rgb != c_rgb) {
                atomic_fetch_or_explicit(&tg_dirty, 1u, memory_order_relaxed);
            }
        }
        int cy = 0, cco = 0, ccg = 0;
        rgb8_to_ycocgr_i(c_rgb & 0xFFu, (c_rgb >> 8) & 0xFFu, (c_rgb >> 16) & 0xFFu, cy, cco, ccg);
        tg_y[i] = short(cy);
        tg_co[i] = short(cco);
        tg_cg[i] = short(ccg);
    }
    threadgroup_barrier(mem_flags::mem_threadgroup);

    if (params.is_keyframe == 0u && atomic_load_explicit(&tg_dirty, memory_order_relaxed) == 0u) {
        if (lid == 0u) {
            slot[0] = 0u;
            slot[1] = 0u;
            slot[2] = 0u;
            slot[3] = 0u;
        }
        return;
    }

    // Parallel MED residuals
    for (uint i = lid; i < pixels; i += 64u) {
        uint x = i % tile_w;
        uint y = i / tile_w;
        int ya = (x > 0u) ? int(tg_y[i - 1u]) : 0;
        int yb = (y > 0u) ? int(tg_y[i - tile_w]) : 0;
        int yc = (x > 0u && y > 0u) ? int(tg_y[i - tile_w - 1u]) : 0;
        int py = med_predict_i(ya, yb, yc);
        int dy = int(char(uchar(tg_y[i]) - uchar(py)));
        tg_sy[i] = zigzag_u16(dy);

        int coa = (x > 0u) ? int(tg_co[i - 1u]) : 0;
        int cob = (y > 0u) ? int(tg_co[i - tile_w]) : 0;
        int coc = (x > 0u && y > 0u) ? int(tg_co[i - tile_w - 1u]) : 0;
        tg_sco[i] = zigzag_u16(int(tg_co[i]) - med_predict_i(coa, cob, coc));

        int cga = (x > 0u) ? int(tg_cg[i - 1u]) : 0;
        int cgb = (y > 0u) ? int(tg_cg[i - tile_w]) : 0;
        int cgc = (x > 0u && y > 0u) ? int(tg_cg[i - tile_w - 1u]) : 0;
        tg_scg[i] = zigzag_u16(int(tg_cg[i]) - med_predict_i(cga, cgb, cgc));
    }
    threadgroup_barrier(mem_flags::mem_threadgroup);

    if (lid == 0u) {
        uint raw_size = pixels * 3u;
        uint best_mode = 5u; // raw_rgb24
        uint best_size = raw_size;

        // Check SOLID + PALETTE <= 16
        uint palette[16];
        uint pal_count = 0u;
        bool pal_overflow = false;
        for (uint i = 0u; i < pixels; ++i) {
            uint rgb = tg_px[i];
            int found = -1;
            for (uint p = 0u; p < pal_count; ++p) {
                if (palette[p] == rgb) {
                    found = int(p);
                    break;
                }
            }
            if (found < 0) {
                if (pal_count < 16u) {
                    palette[pal_count++] = rgb;
                } else {
                    pal_overflow = true;
                    break;
                }
            }
        }

        if (!pal_overflow && pal_count == 1u) {
            slot[0] = 1u;
            slot[1] = 1u; // solid
            slot[2] = 3u;
            slot[3] = 0u;
            slot[16] = uchar(palette[0] & 0xFFu);
            slot[17] = uchar((palette[0] >> 8) & 0xFFu);
            slot[18] = uchar((palette[0] >> 16) & 0xFFu);
            tg_best_mode = 1u;
            tg_best_size = 3u;
        } else {
            uint med_y_sz = measure_rice_channel_u16(tg_sy, tile_w, tile_h, 8);
            uint med_co_sz = measure_rice_channel_u16(tg_sco, tile_w, tile_h, 10);
            uint med_cg_sz = measure_rice_channel_u16(tg_scg, tile_w, tile_h, 10);
            uint med_sz = 6u + med_y_sz + med_co_sz + med_cg_sz;

            if (!pal_overflow && pal_count >= 2u) {
                int bpp = (pal_count <= 2u) ? 1 : (pal_count <= 4u ? 2 : 4);
                uint idx_bytes = (pixels * uint(bpp) + 7u) >> 3;
                uint pal_sz = 1u + pal_count * 3u + idx_bytes;
                if (pal_sz < best_size) {
                    best_size = pal_sz;
                    best_mode = 2u;
                }
            }
            if (med_sz < best_size) {
                best_size = med_sz;
                best_mode = 3u;
            }
            tg_best_mode = best_mode;
            tg_best_size = best_size;

            // Emit winning intra mode directly unless temporal wins below
            if (params.is_keyframe != 0u || best_mode <= 3u) {
                if (best_mode == 2u) {
                    device uchar* dst = slot + 16;
                    int bpp = (pal_count <= 2u) ? 1 : (pal_count <= 4u ? 2 : 4);
                    uint pos = 0u;
                    dst[pos++] = uchar(pal_count);
                    for (uint p = 0u; p < pal_count; ++p) {
                        dst[pos++] = uchar(palette[p] & 0xFFu);
                        dst[pos++] = uchar((palette[p] >> 8) & 0xFFu);
                        dst[pos++] = uchar((palette[p] >> 16) & 0xFFu);
                    }
                    BitWriter bw;
                    bw.out = dst + pos;
                    bw.pos = 0u;
                    bw.cur = 0u;
                    bw.bits = 0;
                    for (uint i = 0u; i < pixels; ++i) {
                        uint rgb = tg_px[i];
                        uint idx = 0u;
                        for (uint p = 0u; p < pal_count; ++p) {
                            if (palette[p] == rgb) { idx = p; break; }
                        }
                        bw.write_bits(idx, bpp);
                    }
                    bw.align();
                    best_size = pos + bw.pos;
                    tg_best_size = best_size;
                } else if (best_mode == 3u) {
                    device uchar* dst = slot + 16;
                    uint sy_len = write_rice_channel_u16(tg_sy, tile_w, tile_h, 8, dst + 6);
                    uint sco_len = write_rice_channel_u16(tg_sco, tile_w, tile_h, 10, dst + 6 + sy_len);
                    uint scg_len = write_rice_channel_u16(tg_scg, tile_w, tile_h, 10, dst + 6 + sy_len + sco_len);
                    dst[0] = uchar(sy_len & 0xFFu); dst[1] = uchar(sy_len >> 8);
                    dst[2] = uchar(sco_len & 0xFFu); dst[3] = uchar(sco_len >> 8);
                    dst[4] = uchar(scg_len & 0xFFu); dst[5] = uchar(scg_len >> 8);
                    best_size = 6u + sy_len + sco_len + scg_len;
                    tg_best_size = best_size;
                }
            }
        }
    }
    threadgroup_barrier(mem_flags::mem_threadgroup);

    if (tg_best_mode == 1u) {
        return;
    }

    if (params.is_keyframe == 0u) {
        // Compute parallel temporal residuals
        for (uint i = lid; i < pixels; i += 64u) {
            uint x = i % tile_w;
            uint y = i / tile_w;
            uint p_rgb = read_px_rgb(pred_bgra, params.pred_stride, tile_x + x, tile_y + y);
            int py = 0, pco = 0, pcg = 0;
            rgb8_to_ycocgr_i(p_rgb & 0xFFu, (p_rgb >> 8) & 0xFFu, (p_rgb >> 16) & 0xFFu, py, pco, pcg);
            int dy = int(char(uchar(tg_y[i]) - uchar(py)));
            tg_sy[i] = zigzag_u16(dy);
            tg_sco[i] = zigzag_u16(int(tg_co[i]) - pco);
            tg_scg[i] = zigzag_u16(int(tg_cg[i]) - pcg);
        }
        threadgroup_barrier(mem_flags::mem_threadgroup);

        if (lid == 0u) {
            uint ty_sz = measure_rice_channel_u16(tg_sy, tile_w, tile_h, 8);
            uint tco_sz = measure_rice_channel_u16(tg_sco, tile_w, tile_h, 10);
            uint tcg_sz = measure_rice_channel_u16(tg_scg, tile_w, tile_h, 10);
            uint temp_sz = 6u + ty_sz + tco_sz + tcg_sz;
            if (temp_sz < tg_best_size) {
                device uchar* dst = slot + 16;
                uint sy_len = write_rice_channel_u16(tg_sy, tile_w, tile_h, 8, dst + 6);
                uint sco_len = write_rice_channel_u16(tg_sco, tile_w, tile_h, 10, dst + 6 + sy_len);
                uint scg_len = write_rice_channel_u16(tg_scg, tile_w, tile_h, 10, dst + 6 + sy_len + sco_len);
                dst[0] = uchar(sy_len & 0xFFu); dst[1] = uchar(sy_len >> 8);
                dst[2] = uchar(sco_len & 0xFFu); dst[3] = uchar(sco_len >> 8);
                dst[4] = uchar(scg_len & 0xFFu); dst[5] = uchar(scg_len >> 8);
                tg_best_size = 6u + sy_len + sco_len + scg_len;
                tg_best_mode = 4u;
            }
        }
        threadgroup_barrier(mem_flags::mem_threadgroup);
    }

    if (lid == 0u) {
        if (tg_best_mode == 5u) {
            uint raw_size = pixels * 3u;
            device uchar* dst = slot + 16;
            for (uint i = 0u; i < pixels; ++i) {
                uint rgb = tg_px[i];
                dst[i * 3u + 0u] = uchar(rgb & 0xFFu);
                dst[i * 3u + 1u] = uchar((rgb >> 8) & 0xFFu);
                dst[i * 3u + 2u] = uchar((rgb >> 16) & 0xFFu);
            }
            tg_best_size = raw_size;
        }
        slot[0] = 1u;
        slot[1] = uchar(tg_best_mode);
        slot[2] = uchar(tg_best_size & 0xFFu);
        slot[3] = uchar((tg_best_size >> 8) & 0xFFu);
    }
}

kernel void cs_crc32c_rows(
    device const uchar* bgra [[buffer(0)]],
    device uint* row_crcs [[buffer(1)]],
    constant uint* crc_table [[buffer(2)]],
    constant EncodeParams& params [[buffer(3)]],
    uint y [[thread_position_in_grid]])
{
    if (y >= params.height) {
        return;
    }
    device const uchar* row = bgra + ulong(y) * ulong(params.curr_stride);
    uint crc = 0xFFFFFFFFu;
    for (uint x = 0u; x < params.width; ++x) {
        uint b = row[x * 4u + 0u];
        uint g = row[x * 4u + 1u];
        uint r = row[x * 4u + 2u];
        crc = (crc >> 8) ^ crc_table[(crc ^ r) & 0xFFu];
        crc = (crc >> 8) ^ crc_table[(crc ^ g) & 0xFFu];
        crc = (crc >> 8) ^ crc_table[(crc ^ b) & 0xFFu];
    }
    row_crcs[y] = crc ^ 0xFFFFFFFFu;
}
)METAL";

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

    class metal_encoder_backend_t final: public encoder_backend_t {
    public:
      metal_encoder_backend_t() {
        @autoreleasepool {
          device_ = MTLCreateSystemDefaultDevice();
          if (!device_) {
            return;
          }
          queue_ = [device_ newCommandQueue];
          if (!queue_) {
            return;
          }
          NSError *err = nil;
          NSString *src = [NSString stringWithUTF8String:kMetalEncoderSource];
          id<MTLLibrary> lib = [device_ newLibraryWithSource:src options:nil error:&err];
          if (!lib) {
            BOOST_LOG(warning) << "sds lossless Metal shader compilation failed: "
                               << (err ? [[err localizedDescription] UTF8String] : "unknown");
            return;
          }
          auto make_pso = [&](NSString *name) -> id<MTLComputePipelineState> {
            id<MTLFunction> fn = [lib newFunctionWithName:name];
            if (!fn) {
              return nil;
            }
            NSError *perr = nil;
            id<MTLComputePipelineState> pso = [device_ newComputePipelineStateWithFunction:fn error:&perr];
#if !__has_feature(objc_arc)
            [fn release];
#endif
            return pso;
          };
          pso_copy_rects_ = make_pso(@"cs_copy_rects");
          pso_encode_tiles_ = make_pso(@"cs_encode_tiles");
          pso_crc32c_ = make_pso(@"cs_crc32c_rows");
#if !__has_feature(objc_arc)
          [lib release];
#endif
          if (!pso_copy_rects_ || !pso_encode_tiles_ || !pso_crc32c_) {
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
          crc_table_buf_ = [device_ newBufferWithBytes:tbl.data()
                                                length:sizeof(tbl)
                                               options:MTLResourceStorageModeShared];
          params_buf_ = [device_ newBufferWithLength:sizeof(metal_encode_params_t)
                                             options:MTLResourceStorageModeShared];
          ready_ = (crc_table_buf_ != nil && params_buf_ != nil);
        }
      }

      ~metal_encoder_backend_t() override {
#if !__has_feature(objc_arc)
        [curr_buf_ release];
        [prev_buf_ release];
        [pred_buf_ release];
        [tile_slots_buf_ release];
        [row_crcs_buf_ release];
        [crc_table_buf_ release];
        [params_buf_ release];
        [pso_copy_rects_ release];
        [pso_encode_tiles_ release];
        [pso_crc32c_ release];
        [queue_ release];
        [device_ release];
#endif
      }

      [[nodiscard]] bool is_ready() const {
        return ready_;
      }

      std::string name() const override {
        return "metal";
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

        @autoreleasepool {
          const bool dims_changed = (width != width_ || height != height_);
          const bool is_keyframe = force_keyframe || !has_prev_ || dims_changed;
          const int dst_stride = width * 4;
          const std::size_t frame_bytes = static_cast<std::size_t>(dst_stride) * static_cast<std::size_t>(height);
          const int tiles_x = (width + TILE_SIZE - 1) / TILE_SIZE;
          const int tiles_y = (height + TILE_SIZE - 1) / TILE_SIZE;
          const std::size_t total_tiles = static_cast<std::size_t>(tiles_x) * static_cast<std::size_t>(tiles_y);

          if (!ensure_buffers(width, height, frame_bytes, total_tiles)) {
            has_prev_ = false;
            return false;
          }

          auto *curr_dst = static_cast<std::uint8_t *>([curr_buf_ contents]);
          if (stride == dst_stride) {
            std::memcpy(curr_dst, bgra, frame_bytes);
          } else {
            for (int y = 0; y < height; ++y) {
              std::memcpy(
                curr_dst + static_cast<std::size_t>(y) * dst_stride,
                bgra + static_cast<std::size_t>(y) * stride,
                static_cast<std::size_t>(dst_stride)
              );
            }
          }

          std::vector<copy_rect_t> copy_rects;
          if (!is_keyframe) {
            const auto *prev_ptr = static_cast<const std::uint8_t *>([prev_buf_ contents]);
            copy_rects = detect_scroll_copy_rects(prev_ptr, dst_stride, curr_dst, dst_stride, width, height);
          }

          auto *params = static_cast<metal_encode_params_t *>([params_buf_ contents]);
          std::memset(params, 0, sizeof(*params));
          params->width = static_cast<std::uint32_t>(width);
          params->height = static_cast<std::uint32_t>(height);
          params->curr_stride = static_cast<std::uint32_t>(dst_stride);
          params->pred_stride = static_cast<std::uint32_t>(dst_stride);
          params->tiles_x = static_cast<std::uint32_t>(tiles_x);
          params->tiles_y = static_cast<std::uint32_t>(tiles_y);
          params->is_keyframe = is_keyframe ? 1u : 0u;
          params->copy_rect_count = static_cast<std::uint32_t>(std::min<std::size_t>(copy_rects.size(), MAX_COPY_RECTS));
          for (std::uint32_t i = 0; i < params->copy_rect_count; ++i) {
            params->copy_rects[i].src_x = copy_rects[i].src_x;
            params->copy_rects[i].src_y = copy_rects[i].src_y;
            params->copy_rects[i].dst_x = copy_rects[i].dst_x;
            params->copy_rects[i].dst_y = copy_rects[i].dst_y;
            params->copy_rects[i].w = copy_rects[i].w;
            params->copy_rects[i].h = copy_rects[i].h;
          }

          id<MTLCommandBuffer> cmd = [queue_ commandBuffer];
          if (!cmd) {
            return false;
          }

          id<MTLComputeCommandEncoder> enc = [cmd computeCommandEncoder];
          if (!enc) {
            return false;
          }

          if (!is_keyframe) {
            [enc setComputePipelineState:pso_copy_rects_];
            [enc setBuffer:prev_buf_ offset:0 atIndex:0];
            [enc setBuffer:pred_buf_ offset:0 atIndex:1];
            [enc setBuffer:params_buf_ offset:0 atIndex:2];
            [enc dispatchThreads:MTLSizeMake(static_cast<NSUInteger>(width), static_cast<NSUInteger>(height), 1)
           threadsPerThreadgroup:MTLSizeMake(16, 16, 1)];
          }

          [enc setComputePipelineState:pso_encode_tiles_];
          [enc setBuffer:curr_buf_ offset:0 atIndex:0];
          [enc setBuffer:pred_buf_ offset:0 atIndex:1];
          [enc setBuffer:tile_slots_buf_ offset:0 atIndex:2];
          [enc setBuffer:params_buf_ offset:0 atIndex:3];
          [enc dispatchThreadgroups:MTLSizeMake(static_cast<NSUInteger>(tiles_x), static_cast<NSUInteger>(tiles_y), 1)
              threadsPerThreadgroup:MTLSizeMake(64, 1, 1)];

          if (hash_algo == hash_algo_e::crc32c) {
            [enc setComputePipelineState:pso_crc32c_];
            [enc setBuffer:curr_buf_ offset:0 atIndex:0];
            [enc setBuffer:row_crcs_buf_ offset:0 atIndex:1];
            [enc setBuffer:crc_table_buf_ offset:0 atIndex:2];
            [enc setBuffer:params_buf_ offset:0 atIndex:3];
            [enc dispatchThreads:MTLSizeMake(static_cast<NSUInteger>(height), 1, 1)
           threadsPerThreadgroup:MTLSizeMake(64, 1, 1)];
          }

          [enc endEncoding];
          [cmd commit];

          std::array<std::uint8_t, 32> frame_hash {};
          if (hash_algo == hash_algo_e::blake3) {
            frame_hash = blake3_rgb24_from_bgra(curr_dst, dst_stride, width, height);
          }

          [cmd waitUntilCompleted];
          if ([cmd status] != MTLCommandBufferStatusCompleted) {
            return false;
          }

          if (hash_algo == hash_algo_e::crc32c) {
            const auto *row_crcs = static_cast<const std::uint32_t *>([row_crcs_buf_ contents]);
            const std::uint64_t row_bytes_rgb = static_cast<std::uint64_t>(width) * 3ULL;
            std::uint32_t combined = row_crcs[0];
            for (int y = 1; y < height; ++y) {
              combined = crc32c_combine(combined, row_crcs[y], row_bytes_rgb);
            }
            write_u32_le(frame_hash.data(), combined);
          }

          const auto *tile_slots = static_cast<const std::uint8_t *>([tile_slots_buf_ contents]);
          const std::size_t copy_bytes = copy_rects.size() * COPY_RECT_WIRE_SIZE;
          const std::size_t bitmap_bytes = (total_tiles + 7u) / 8u;
          std::uint32_t dirty_count = 0;
          std::size_t dirty_bytes = 0;
          encode_stats_t stats {};
          stats.total_tiles = static_cast<std::uint32_t>(total_tiles);
          stats.copy_rects = static_cast<std::uint32_t>(copy_rects.size());

          for (std::size_t i = 0; i < total_tiles; ++i) {
            const std::uint8_t *slot = tile_slots + i * static_cast<std::size_t>(GPU_TILE_SLOT_STRIDE);
            if (slot[0] == 0) {
              continue;
            }
            const std::uint16_t plen = static_cast<std::uint16_t>(slot[2]) |
                                       (static_cast<std::uint16_t>(slot[3]) << 8);
            if (plen == 0 || plen > MAX_TILE_PAYLOAD) {
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
            const std::uint8_t *slot = tile_slots + i * static_cast<std::size_t>(GPU_TILE_SLOT_STRIDE);
            if (slot[0] != 0) {
              p[i >> 3] |= static_cast<std::uint8_t>(1u << (i & 7u));
            }
          }
          p += bitmap_bytes;

          for (std::size_t i = 0; i < total_tiles; ++i) {
            const std::uint8_t *slot = tile_slots + i * static_cast<std::size_t>(GPU_TILE_SLOT_STRIDE);
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

          std::swap(prev_buf_, curr_buf_);
          has_prev_ = true;
          width_ = width;
          height_ = height;

          if (out_stats) {
            *out_stats = stats;
          }
          return true;
        }
      }

    private:
      bool ensure_buffers(int /*width*/, int height, std::size_t frame_bytes, std::size_t total_tiles) {
        if (frame_bytes > cap_frame_bytes_) {
#if !__has_feature(objc_arc)
          [curr_buf_ release];
          [prev_buf_ release];
          [pred_buf_ release];
#endif
          curr_buf_ = [device_ newBufferWithLength:frame_bytes options:MTLResourceStorageModeShared];
          prev_buf_ = [device_ newBufferWithLength:frame_bytes options:MTLResourceStorageModeShared];
          pred_buf_ = [device_ newBufferWithLength:frame_bytes options:MTLResourceStorageModeShared];
          if (!curr_buf_ || !prev_buf_ || !pred_buf_) {
            cap_frame_bytes_ = 0;
            has_prev_ = false;
            return false;
          }
          cap_frame_bytes_ = frame_bytes;
        }
        const std::size_t slots_bytes = total_tiles * static_cast<std::size_t>(GPU_TILE_SLOT_STRIDE);
        if (slots_bytes > cap_slots_bytes_) {
#if !__has_feature(objc_arc)
          [tile_slots_buf_ release];
#endif
          tile_slots_buf_ = [device_ newBufferWithLength:slots_bytes options:MTLResourceStorageModeShared];
          if (!tile_slots_buf_) {
            cap_slots_bytes_ = 0;
            has_prev_ = false;
            return false;
          }
          cap_slots_bytes_ = slots_bytes;
        }
        const std::size_t row_bytes = static_cast<std::size_t>(height) * sizeof(std::uint32_t);
        if (row_bytes > cap_row_crc_bytes_) {
#if !__has_feature(objc_arc)
          [row_crcs_buf_ release];
#endif
          row_crcs_buf_ = [device_ newBufferWithLength:row_bytes options:MTLResourceStorageModeShared];
          if (!row_crcs_buf_) {
            cap_row_crc_bytes_ = 0;
            return false;
          }
          cap_row_crc_bytes_ = row_bytes;
        }
        return true;
      }

      id<MTLDevice> device_ = nil;
      id<MTLCommandQueue> queue_ = nil;
      id<MTLComputePipelineState> pso_copy_rects_ = nil;
      id<MTLComputePipelineState> pso_encode_tiles_ = nil;
      id<MTLComputePipelineState> pso_crc32c_ = nil;
      id<MTLBuffer> curr_buf_ = nil;
      id<MTLBuffer> prev_buf_ = nil;
      id<MTLBuffer> pred_buf_ = nil;
      id<MTLBuffer> tile_slots_buf_ = nil;
      id<MTLBuffer> row_crcs_buf_ = nil;
      id<MTLBuffer> crc_table_buf_ = nil;
      id<MTLBuffer> params_buf_ = nil;
      std::size_t cap_frame_bytes_ = 0;
      std::size_t cap_slots_bytes_ = 0;
      std::size_t cap_row_crc_bytes_ = 0;
      int width_ = 0;
      int height_ = 0;
      bool has_prev_ = false;
      bool ready_ = false;
    };
  }  // namespace

  std::unique_ptr<encoder_backend_t> make_gpu_encoder_backend() {
    auto enc = std::make_unique<metal_encoder_backend_t>();
    return enc->is_ready() ? std::move(enc) : nullptr;
  }

  std::string available_encoder_backends() {
    static const std::string cached = []() -> std::string {
      @autoreleasepool {
        id<MTLDevice> dev = MTLCreateSystemDefaultDevice();
        if (dev) {
#if !__has_feature(objc_arc)
          [dev release];
#endif
          return "metal,cpu";
        }
        return "cpu";
      }
    }();
    return cached;
  }
}  // namespace sds::lossless
