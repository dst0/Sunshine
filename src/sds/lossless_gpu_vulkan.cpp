/**
 * @file src/sds/lossless_gpu_vulkan.cpp
 * @brief Linux Vulkan Compute bit-exact SDLL v1 lossless encoder (with safe CPU SIMD fallback when Vulkan unavailable).
 */

#include "lossless_gpu_encoder.h"

#ifdef __linux__

#if defined(SUNSHINE_BUILD_VULKAN)
#include <vulkan/vulkan.h>
#endif

#include <algorithm>
#include <array>
#include <cstring>
#include <vector>

#include "src/logging.h"

namespace sds::lossless {
  namespace {
#if defined(SUNSHINE_BUILD_VULKAN)
    constexpr std::uint32_t kLosslessSpirv[] =
#include "shaders/sds_lossless_encode.spv.inc"
      ;

    struct vulkan_push_t {
      std::uint32_t stage;
      std::uint32_t width;
      std::uint32_t height;
      std::uint32_t tiles_x;
      std::uint32_t tiles_y;
      std::uint32_t is_keyframe;
      std::uint32_t copy_rect_count;
      std::uint32_t reserved0;
      std::uint32_t rects0[4];
      std::uint32_t sizes0[4];
      std::uint32_t rects1[4];
      std::uint32_t rects2[4];
      std::uint32_t sizes2[4];
      std::uint32_t rects3[4];
    };

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

    class vulkan_encoder_backend_t final: public encoder_backend_t {
    public:
      vulkan_encoder_backend_t() {
        VkApplicationInfo app {};
        app.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
        app.pApplicationName = "sunshine-lossless";
        app.apiVersion = VK_API_VERSION_1_0;

        VkInstanceCreateInfo ici {};
        ici.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
        ici.pApplicationInfo = &app;
        if (vkCreateInstance(&ici, nullptr, &instance_) != VK_SUCCESS) {
          return;
        }

        std::uint32_t phys_count = 0;
        vkEnumeratePhysicalDevices(instance_, &phys_count, nullptr);
        if (phys_count == 0) {
          return;
        }
        std::vector<VkPhysicalDevice> phys(phys_count);
        vkEnumeratePhysicalDevices(instance_, &phys_count, phys.data());

        for (VkPhysicalDevice pd : phys) {
          std::uint32_t qcount = 0;
          vkGetPhysicalDeviceQueueFamilyProperties(pd, &qcount, nullptr);
          std::vector<VkQueueFamilyProperties> qprops(qcount);
          vkGetPhysicalDeviceQueueFamilyProperties(pd, &qcount, qprops.data());
          for (std::uint32_t qi = 0; qi < qcount; ++qi) {
            if (qprops[qi].queueFlags & VK_QUEUE_COMPUTE_BIT) {
              phys_ = pd;
              queue_family_ = qi;
              break;
            }
          }
          if (phys_ != VK_NULL_HANDLE) {
            break;
          }
        }
        if (phys_ == VK_NULL_HANDLE) {
          return;
        }

        vkGetPhysicalDeviceMemoryProperties(phys_, &mem_props_);

        float prio = 1.0f;
        VkDeviceQueueCreateInfo qci {};
        qci.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
        qci.queueFamilyIndex = queue_family_;
        qci.queueCount = 1;
        qci.pQueuePriorities = &prio;

        VkDeviceCreateInfo dci {};
        dci.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
        dci.queueCreateInfoCount = 1;
        dci.pQueueCreateInfos = &qci;
        if (vkCreateDevice(phys_, &dci, nullptr, &device_) != VK_SUCCESS) {
          return;
        }
        vkGetDeviceQueue(device_, queue_family_, 0, &queue_);

        VkDescriptorSetLayoutBinding bindings[6] {};
        for (std::uint32_t i = 0; i < 6; ++i) {
          bindings[i].binding = i;
          bindings[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
          bindings[i].descriptorCount = 1;
          bindings[i].stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
        }
        VkDescriptorSetLayoutCreateInfo dsl_ci {};
        dsl_ci.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO;
        dsl_ci.bindingCount = 6;
        dsl_ci.pBindings = bindings;
        if (vkCreateDescriptorSetLayout(device_, &dsl_ci, nullptr, &dsl_) != VK_SUCCESS) {
          return;
        }

        VkPushConstantRange pcr {};
        pcr.stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
        pcr.offset = 0;
        pcr.size = sizeof(vulkan_push_t);

        VkPipelineLayoutCreateInfo pl_ci {};
        pl_ci.sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;
        pl_ci.setLayoutCount = 1;
        pl_ci.pSetLayouts = &dsl_;
        pl_ci.pushConstantRangeCount = 1;
        pl_ci.pPushConstantRanges = &pcr;
        if (vkCreatePipelineLayout(device_, &pl_ci, nullptr, &pipeline_layout_) != VK_SUCCESS) {
          return;
        }

        VkShaderModuleCreateInfo sm_ci {};
        sm_ci.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
        sm_ci.codeSize = sizeof(kLosslessSpirv);
        sm_ci.pCode = kLosslessSpirv;
        VkShaderModule shader_mod = VK_NULL_HANDLE;
        if (vkCreateShaderModule(device_, &sm_ci, nullptr, &shader_mod) != VK_SUCCESS) {
          return;
        }

        VkComputePipelineCreateInfo cp_ci {};
        cp_ci.sType = VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO;
        cp_ci.stage.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
        cp_ci.stage.stage = VK_SHADER_STAGE_COMPUTE_BIT;
        cp_ci.stage.module = shader_mod;
        cp_ci.stage.pName = "main";
        cp_ci.layout = pipeline_layout_;
        VkResult pres = vkCreateComputePipelines(device_, VK_NULL_HANDLE, 1, &cp_ci, nullptr, &pipeline_);
        vkDestroyShaderModule(device_, shader_mod, nullptr);
        if (pres != VK_SUCCESS) {
          return;
        }

        VkDescriptorPoolSize psz {VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, 6};
        VkDescriptorPoolCreateInfo dp_ci {};
        dp_ci.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
        dp_ci.maxSets = 1;
        dp_ci.poolSizeCount = 1;
        dp_ci.pPoolSizes = &psz;
        if (vkCreateDescriptorPool(device_, &dp_ci, nullptr, &desc_pool_) != VK_SUCCESS) {
          return;
        }

        VkDescriptorSetAllocateInfo ds_ai {};
        ds_ai.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO;
        ds_ai.descriptorPool = desc_pool_;
        ds_ai.descriptorSetCount = 1;
        ds_ai.pSetLayouts = &dsl_;
        if (vkAllocateDescriptorSets(device_, &ds_ai, &desc_set_) != VK_SUCCESS) {
          return;
        }

        VkCommandPoolCreateInfo cmdp_ci {};
        cmdp_ci.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
        cmdp_ci.flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;
        cmdp_ci.queueFamilyIndex = queue_family_;
        if (vkCreateCommandPool(device_, &cmdp_ci, nullptr, &cmd_pool_) != VK_SUCCESS) {
          return;
        }

        VkCommandBufferAllocateInfo cb_ai {};
        cb_ai.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
        cb_ai.commandPool = cmd_pool_;
        cb_ai.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
        cb_ai.commandBufferCount = 1;
        if (vkAllocateCommandBuffers(device_, &cb_ai, &cmd_buf_) != VK_SUCCESS) {
          return;
        }

        VkFenceCreateInfo f_ci {};
        f_ci.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
        if (vkCreateFence(device_, &f_ci, nullptr, &fence_) != VK_SUCCESS) {
          return;
        }

        if (!create_host_buf(256 * sizeof(std::uint32_t), crc_table_)) {
          return;
        }
        auto *tbl = static_cast<std::uint32_t *>(crc_table_.mapped);
        for (std::uint32_t i = 0; i < 256; ++i) {
          std::uint32_t c = i;
          for (int k = 0; k < 8; ++k) {
            c = (c & 1u) ? ((c >> 1) ^ 0x82F63B78u) : (c >> 1);
          }
          tbl[i] = c;
        }
        ready_ = true;
      }

      ~vulkan_encoder_backend_t() override {
        if (device_ != VK_NULL_HANDLE) {
          vkDeviceWaitIdle(device_);
          destroy_host_buf(curr_);
          destroy_host_buf(prev_);
          destroy_host_buf(pred_);
          destroy_host_buf(slots_);
          destroy_host_buf(row_crcs_);
          destroy_host_buf(crc_table_);
          if (fence_ != VK_NULL_HANDLE) vkDestroyFence(device_, fence_, nullptr);
          if (cmd_pool_ != VK_NULL_HANDLE) vkDestroyCommandPool(device_, cmd_pool_, nullptr);
          if (desc_pool_ != VK_NULL_HANDLE) vkDestroyDescriptorPool(device_, desc_pool_, nullptr);
          if (pipeline_ != VK_NULL_HANDLE) vkDestroyPipeline(device_, pipeline_, nullptr);
          if (pipeline_layout_ != VK_NULL_HANDLE) vkDestroyPipelineLayout(device_, pipeline_layout_, nullptr);
          if (dsl_ != VK_NULL_HANDLE) vkDestroyDescriptorSetLayout(device_, dsl_, nullptr);
          vkDestroyDevice(device_, nullptr);
        }
        if (instance_ != VK_NULL_HANDLE) {
          vkDestroyInstance(instance_, nullptr);
        }
      }

      [[nodiscard]] bool is_ready() const {
        return ready_;
      }

      std::string name() const override {
        return "vulkan";
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

        if (!ensure_buffers(height, frame_bytes, total_tiles)) {
          return false;
        }

        auto *curr_dst = static_cast<std::uint8_t *>(curr_.mapped);
        if (stride == dst_stride) {
          std::memcpy(curr_dst, bgra, frame_bytes);
        } else {
          for (int y = 0; y < height; ++y) {
            std::memcpy(curr_dst + static_cast<std::size_t>(y) * dst_stride, bgra + static_cast<std::size_t>(y) * stride, dst_stride);
          }
        }

        std::vector<copy_rect_t> copy_rects;
        if (!is_keyframe) {
          copy_rects = detect_scroll_copy_rects(
            static_cast<const std::uint8_t *>(prev_.mapped), dst_stride, curr_dst, dst_stride, width, height);
        }

        vulkan_push_t pc {};
        pc.width = static_cast<std::uint32_t>(width);
        pc.height = static_cast<std::uint32_t>(height);
        pc.tiles_x = static_cast<std::uint32_t>(tiles_x);
        pc.tiles_y = static_cast<std::uint32_t>(tiles_y);
        pc.is_keyframe = is_keyframe ? 1u : 0u;
        pc.copy_rect_count = static_cast<std::uint32_t>(std::min<std::size_t>(copy_rects.size(), MAX_COPY_RECTS));
        if (pc.copy_rect_count > 0) {
          pc.rects0[0] = copy_rects[0].src_x; pc.rects0[1] = copy_rects[0].src_y;
          pc.rects0[2] = copy_rects[0].dst_x; pc.rects0[3] = copy_rects[0].dst_y;
          pc.sizes0[0] = copy_rects[0].w; pc.sizes0[1] = copy_rects[0].h;
        }
        if (pc.copy_rect_count > 1) {
          pc.sizes0[2] = copy_rects[1].src_x; pc.sizes0[3] = copy_rects[1].src_y;
          pc.rects1[0] = copy_rects[1].dst_x; pc.rects1[1] = copy_rects[1].dst_y;
          pc.rects1[2] = copy_rects[1].w; pc.rects1[3] = copy_rects[1].h;
        }
        if (pc.copy_rect_count > 2) {
          pc.rects2[0] = copy_rects[2].src_x; pc.rects2[1] = copy_rects[2].src_y;
          pc.rects2[2] = copy_rects[2].dst_x; pc.rects2[3] = copy_rects[2].dst_y;
          pc.sizes2[0] = copy_rects[2].w; pc.sizes2[1] = copy_rects[2].h;
        }
        if (pc.copy_rect_count > 3) {
          pc.sizes2[2] = copy_rects[3].src_x; pc.sizes2[3] = copy_rects[3].src_y;
          pc.rects3[0] = copy_rects[3].dst_x; pc.rects3[1] = copy_rects[3].dst_y;
          pc.rects3[2] = copy_rects[3].w; pc.rects3[3] = copy_rects[3].h;
        }

        vkResetCommandBuffer(cmd_buf_, 0);
        VkCommandBufferBeginInfo bi {};
        bi.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
        bi.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
        vkBeginCommandBuffer(cmd_buf_, &bi);

        vkCmdBindPipeline(cmd_buf_, VK_PIPELINE_BIND_POINT_COMPUTE, pipeline_);
        vkCmdBindDescriptorSets(cmd_buf_, VK_PIPELINE_BIND_POINT_COMPUTE, pipeline_layout_, 0, 1, &desc_set_, 0, nullptr);

        if (!is_keyframe) {
          pc.stage = 0;
          vkCmdPushConstants(cmd_buf_, pipeline_layout_, VK_SHADER_STAGE_COMPUTE_BIT, 0, sizeof(pc), &pc);
          vkCmdDispatch(cmd_buf_, static_cast<std::uint32_t>(height), 1, 1);

          VkMemoryBarrier bar {};
          bar.sType = VK_STRUCTURE_TYPE_MEMORY_BARRIER;
          bar.srcAccessMask = VK_ACCESS_SHADER_WRITE_BIT;
          bar.dstAccessMask = VK_ACCESS_SHADER_READ_BIT;
          vkCmdPipelineBarrier(cmd_buf_, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
                               0, 1, &bar, 0, nullptr, 0, nullptr);
        }

        pc.stage = 1;
        vkCmdPushConstants(cmd_buf_, pipeline_layout_, VK_SHADER_STAGE_COMPUTE_BIT, 0, sizeof(pc), &pc);
        vkCmdDispatch(cmd_buf_, static_cast<std::uint32_t>(tiles_x), static_cast<std::uint32_t>(tiles_y), 1);

        if (hash_algo == hash_algo_e::crc32c) {
          pc.stage = 2;
          vkCmdPushConstants(cmd_buf_, pipeline_layout_, VK_SHADER_STAGE_COMPUTE_BIT, 0, sizeof(pc), &pc);
          vkCmdDispatch(cmd_buf_, (static_cast<std::uint32_t>(height) + 63u) / 64u, 1, 1);
        }

        VkMemoryBarrier end_bar {};
        end_bar.sType = VK_STRUCTURE_TYPE_MEMORY_BARRIER;
        end_bar.srcAccessMask = VK_ACCESS_SHADER_WRITE_BIT;
        end_bar.dstAccessMask = VK_ACCESS_HOST_READ_BIT;
        vkCmdPipelineBarrier(cmd_buf_, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, VK_PIPELINE_STAGE_HOST_BIT,
                             0, 1, &end_bar, 0, nullptr, 0, nullptr);
        vkEndCommandBuffer(cmd_buf_);

        vkResetFences(device_, 1, &fence_);
        VkSubmitInfo si {};
        si.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
        si.commandBufferCount = 1;
        si.pCommandBuffers = &cmd_buf_;
        if (vkQueueSubmit(queue_, 1, &si, fence_) != VK_SUCCESS) {
          return false;
        }

        std::array<std::uint8_t, 32> frame_hash {};
        if (hash_algo == hash_algo_e::blake3) {
          frame_hash = blake3_rgb24_from_bgra(curr_dst, dst_stride, width, height);
        }

        if (vkWaitForFences(device_, 1, &fence_, VK_TRUE, UINT64_MAX) != VK_SUCCESS) {
          return false;
        }

        if (hash_algo == hash_algo_e::crc32c) {
          const auto *row_crcs = static_cast<const std::uint32_t *>(row_crcs_.mapped);
          const std::uint64_t row_bytes_rgb = static_cast<std::uint64_t>(width) * 3ULL;
          std::uint32_t combined = row_crcs[0];
          for (int y = 1; y < height; ++y) {
            combined = crc32c_combine(combined, row_crcs[y], row_bytes_rgb);
          }
          write_u32_le(frame_hash.data(), combined);
        }

        const auto *slots = static_cast<const std::uint8_t *>(slots_.mapped);
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

        std::swap(curr_, prev_);
        update_descriptors();
        has_prev_ = true;
        width_ = width;
        height_ = height;

        if (out_stats) {
          *out_stats = stats;
        }
        return true;
      }

    private:
      struct host_buf_t {
        VkBuffer buf = VK_NULL_HANDLE;
        VkDeviceMemory mem = VK_NULL_HANDLE;
        void *mapped = nullptr;
        std::size_t size = 0;
      };

      bool create_host_buf(std::size_t sz, host_buf_t &out) {
        destroy_host_buf(out);
        VkBufferCreateInfo ci {};
        ci.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
        ci.size = sz;
        ci.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT;
        ci.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
        if (vkCreateBuffer(device_, &ci, nullptr, &out.buf) != VK_SUCCESS) {
          return false;
        }
        VkMemoryRequirements mr {};
        vkGetBufferMemoryRequirements(device_, out.buf, &mr);
        std::uint32_t mem_idx = UINT32_MAX;
        const VkMemoryPropertyFlags want = VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT;
        for (std::uint32_t i = 0; i < mem_props_.memoryTypeCount; ++i) {
          if ((mr.memoryTypeBits & (1u << i)) && (mem_props_.memoryTypes[i].propertyFlags & want) == want) {
            mem_idx = i;
            break;
          }
        }
        if (mem_idx == UINT32_MAX) {
          destroy_host_buf(out);
          return false;
        }
        VkMemoryAllocateInfo ai {};
        ai.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
        ai.allocationSize = mr.size;
        ai.memoryTypeIndex = mem_idx;
        if (vkAllocateMemory(device_, &ai, nullptr, &out.mem) != VK_SUCCESS) {
          destroy_host_buf(out);
          return false;
        }
        vkBindBufferMemory(device_, out.buf, out.mem, 0);
        vkMapMemory(device_, out.mem, 0, sz, 0, &out.mapped);
        out.size = sz;
        return out.mapped != nullptr;
      }

      void destroy_host_buf(host_buf_t &b) {
        if (b.mapped) {
          vkUnmapMemory(device_, b.mem);
          b.mapped = nullptr;
        }
        if (b.buf != VK_NULL_HANDLE) {
          vkDestroyBuffer(device_, b.buf, nullptr);
          b.buf = VK_NULL_HANDLE;
        }
        if (b.mem != VK_NULL_HANDLE) {
          vkFreeMemory(device_, b.mem, nullptr);
          b.mem = VK_NULL_HANDLE;
        }
        b.size = 0;
      }

      void update_descriptors() {
        host_buf_t *all[6] = {&curr_, &prev_, &pred_, &slots_, &row_crcs_, &crc_table_};
        VkDescriptorBufferInfo bi[6] {};
        VkWriteDescriptorSet ws[6] {};
        for (int i = 0; i < 6; ++i) {
          bi[i].buffer = all[i]->buf;
          bi[i].offset = 0;
          bi[i].range = all[i]->size;
          ws[i].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
          ws[i].dstSet = desc_set_;
          ws[i].dstBinding = static_cast<std::uint32_t>(i);
          ws[i].descriptorCount = 1;
          ws[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
          ws[i].pBufferInfo = &bi[i];
        }
        vkUpdateDescriptorSets(device_, 6, ws, 0, nullptr);
      }

      bool ensure_buffers(int height, std::size_t frame_bytes, std::size_t total_tiles) {
        bool need_desc = false;
        if (frame_bytes > curr_.size) {
          if (!create_host_buf(frame_bytes, curr_) ||
              !create_host_buf(frame_bytes, prev_) ||
              !create_host_buf(frame_bytes, pred_)) {
            return false;
          }
          need_desc = true;
        }
        const std::size_t slots_bytes = total_tiles * static_cast<std::size_t>(GPU_TILE_SLOT_STRIDE);
        if (slots_bytes > slots_.size) {
          if (!create_host_buf(slots_bytes, slots_)) {
            return false;
          }
          need_desc = true;
        }
        const std::size_t row_bytes = static_cast<std::size_t>(height) * sizeof(std::uint32_t);
        if (row_bytes > row_crcs_.size) {
          if (!create_host_buf(row_bytes, row_crcs_)) {
            return false;
          }
          need_desc = true;
        }
        if (need_desc) {
          update_descriptors();
        }
        return true;
      }

      VkInstance instance_ = VK_NULL_HANDLE;
      VkPhysicalDevice phys_ = VK_NULL_HANDLE;
      VkPhysicalDeviceMemoryProperties mem_props_ {};
      std::uint32_t queue_family_ = 0;
      VkDevice device_ = VK_NULL_HANDLE;
      VkQueue queue_ = VK_NULL_HANDLE;
      VkDescriptorSetLayout dsl_ = VK_NULL_HANDLE;
      VkPipelineLayout pipeline_layout_ = VK_NULL_HANDLE;
      VkPipeline pipeline_ = VK_NULL_HANDLE;
      VkDescriptorPool desc_pool_ = VK_NULL_HANDLE;
      VkDescriptorSet desc_set_ = VK_NULL_HANDLE;
      VkCommandPool cmd_pool_ = VK_NULL_HANDLE;
      VkCommandBuffer cmd_buf_ = VK_NULL_HANDLE;
      VkFence fence_ = VK_NULL_HANDLE;
      host_buf_t curr_, prev_, pred_, slots_, row_crcs_, crc_table_;
      int width_ = 0;
      int height_ = 0;
      bool has_prev_ = false;
      bool ready_ = false;
    };
#endif
  }  // namespace

  std::unique_ptr<encoder_backend_t> make_gpu_encoder_backend() {
#if defined(SUNSHINE_BUILD_VULKAN)
    auto enc = std::make_unique<vulkan_encoder_backend_t>();
    return enc->is_ready() ? std::move(enc) : nullptr;
#else
    return nullptr;
#endif
  }

  std::string available_encoder_backends() {
#if defined(SUNSHINE_BUILD_VULKAN)
    auto enc = make_gpu_encoder_backend();
    if (enc) {
      return "vulkan,cpu";
    }
#endif
    return "cpu";
  }
}  // namespace sds::lossless

#endif
