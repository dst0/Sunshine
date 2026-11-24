/**
 * @file src/sds/clipboard_backend_util.cpp
 * @brief Definitions for the platform-independent clipboard backend helpers.
 */
// standard includes
#include <algorithm>
#include <array>
#include <bit>
#include <cctype>
#include <limits>

// local includes
#include "clipboard_backend_util.h"

namespace sds::clipboard::util {
  namespace {
    constexpr char32_t replacement_char = 0xFFFD;
    constexpr std::array<std::uint8_t, 8> png_signature {0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n'};

    /**
     * @brief Append one code point to a UTF-8 string.
     */
    void append_utf8(std::string &out, char32_t cp) {
      if (cp < 0x80) {
        out.push_back(static_cast<char>(cp));
      } else if (cp < 0x800) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
      } else if (cp < 0x10000) {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
      } else {
        out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
      }
    }

    /**
     * @brief Decode one UTF-8 sequence starting at `pos`.
     *
     * @param in Input bytes.
     * @param pos Position of the lead byte; advanced past the sequence (or one byte when invalid).
     * @return Code point, or nullopt for an invalid sequence.
     */
    std::optional<char32_t> decode_utf8(std::string_view in, std::size_t &pos) {
      const auto lead = static_cast<unsigned char>(in[pos]);
      if (lead < 0x80) {
        ++pos;
        return lead;
      }

      std::size_t length;
      char32_t cp;
      char32_t min;
      if ((lead & 0xE0) == 0xC0) {
        length = 2;
        cp = lead & 0x1F;
        min = 0x80;
      } else if ((lead & 0xF0) == 0xE0) {
        length = 3;
        cp = lead & 0x0F;
        min = 0x800;
      } else if ((lead & 0xF8) == 0xF0) {
        length = 4;
        cp = lead & 0x07;
        min = 0x10000;
      } else {
        ++pos;
        return std::nullopt;
      }

      if (pos + length > in.size()) {
        ++pos;
        return std::nullopt;
      }
      for (std::size_t i = 1; i < length; ++i) {
        const auto cont = static_cast<unsigned char>(in[pos + i]);
        if ((cont & 0xC0) != 0x80) {
          ++pos;
          return std::nullopt;
        }
        cp = (cp << 6) | (cont & 0x3F);
      }
      if (cp < min || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) {
        ++pos;
        return std::nullopt;
      }
      pos += length;
      return cp;
    }

    /**
     * @brief Read a little-endian unsigned integer.
     */
    template<typename T>
    T read_le(std::span<const std::uint8_t> data, std::size_t offset) {
      T value = 0;
      for (std::size_t i = 0; i < sizeof(T); ++i) {
        value |= static_cast<T>(static_cast<T>(data[offset + i]) << (8 * i));
      }
      return value;
    }

    /**
     * @brief Read a big-endian 32-bit integer.
     */
    std::uint32_t read_be32(std::span<const std::uint8_t> data, std::size_t offset) {
      return (std::uint32_t {data[offset]} << 24) | (std::uint32_t {data[offset + 1]} << 16) | (std::uint32_t {data[offset + 2]} << 8) | std::uint32_t {data[offset + 3]};
    }

    /**
     * @brief Append a little-endian integer.
     */
    template<typename T>
    void write_le(std::vector<std::uint8_t> &out, T value) {
      using U = std::make_unsigned_t<T>;
      auto u = static_cast<U>(value);
      for (std::size_t i = 0; i < sizeof(T); ++i) {
        out.push_back(static_cast<std::uint8_t>(u >> (8 * i)));
      }
    }

    /**
     * @brief Extracts one channel from a pixel value with a bit mask and scales it to 8 bits.
     */
    struct channel_t {
      std::uint32_t mask = 0;  ///< Channel bit mask.
      unsigned shift = 0;  ///< Position of the lowest mask bit.
      unsigned bits = 0;  ///< Number of contiguous mask bits.

      /**
       * @brief Build a channel from a mask.
       */
      explicit channel_t(std::uint32_t m = 0):
          mask(m) {
        if (m != 0) {
          shift = static_cast<unsigned>(std::countr_zero(m));
          bits = static_cast<unsigned>(std::popcount(m >> shift));
        }
      }

      /**
       * @brief Extract and scale the channel to 0-255.
       */
      [[nodiscard]] std::uint8_t extract(std::uint32_t pixel) const {
        if (bits == 0) {
          return 0;
        }
        const std::uint32_t value = (pixel & mask) >> shift;
        if (bits >= 8) {
          return static_cast<std::uint8_t>(value >> (bits - 8));
        }
        const std::uint32_t max = (1u << bits) - 1;
        return static_cast<std::uint8_t>((value * 255 + max / 2) / max);
      }
    };

    constexpr std::uint32_t bi_rgb = 0;
    constexpr std::uint32_t bi_bitfields = 3;
    constexpr std::uint32_t bi_alphabitfields = 6;
  }  // namespace

  bool is_valid_utf8(std::string_view input) {
    std::size_t pos = 0;
    while (pos < input.size()) {
      if (!decode_utf8(input, pos)) {
        return false;
      }
    }
    return true;
  }

  std::string repair_utf8(std::string_view input) {
    if (is_valid_utf8(input)) {
      return std::string {input};
    }
    std::string out;
    out.reserve(input.size() + 8);
    std::size_t pos = 0;
    while (pos < input.size()) {
      const auto cp = decode_utf8(input, pos);
      append_utf8(out, cp.value_or(replacement_char));
    }
    return out;
  }

  std::optional<std::string> sanitize_text(std::string_view raw) {
    while (!raw.empty() && raw.back() == '\0') {
      raw.remove_suffix(1);
    }
    if (raw.empty() || raw.find('\0') != std::string_view::npos) {
      return std::nullopt;
    }
    return repair_utf8(raw);
  }

  std::string latin1_to_utf8(std::string_view latin1) {
    std::string out;
    out.reserve(latin1.size());
    for (const char c : latin1) {
      append_utf8(out, static_cast<unsigned char>(c));
    }
    return out;
  }

  std::string utf8_to_latin1_lossy(std::string_view utf8) {
    std::string out;
    out.reserve(utf8.size());
    std::size_t pos = 0;
    while (pos < utf8.size()) {
      const auto cp = decode_utf8(utf8, pos);
      out.push_back(cp && *cp <= 0xFF ? static_cast<char>(*cp) : '?');
    }
    return out;
  }

  std::string crlf_to_lf(std::string_view text) {
    std::string out;
    out.reserve(text.size());
    for (std::size_t i = 0; i < text.size(); ++i) {
      if (text[i] == '\r' && i + 1 < text.size() && text[i + 1] == '\n') {
        continue;
      }
      out.push_back(text[i]);
    }
    return out;
  }

  std::string lf_to_crlf(std::string_view text) {
    std::string out;
    out.reserve(text.size() + text.size() / 16);
    for (std::size_t i = 0; i < text.size(); ++i) {
      if (text[i] == '\n' && (i == 0 || text[i - 1] != '\r')) {
        out.push_back('\r');
      }
      out.push_back(text[i]);
    }
    return out;
  }

  std::string utf16_to_utf8(std::u16string_view utf16) {
    std::string out;
    out.reserve(utf16.size());
    for (std::size_t i = 0; i < utf16.size(); ++i) {
      const char16_t unit = utf16[i];
      if (unit >= 0xD800 && unit <= 0xDBFF) {
        if (i + 1 < utf16.size() && utf16[i + 1] >= 0xDC00 && utf16[i + 1] <= 0xDFFF) {
          const char32_t cp = 0x10000 + ((char32_t {unit} - 0xD800) << 10) + (char32_t {utf16[i + 1]} - 0xDC00);
          append_utf8(out, cp);
          ++i;
        } else {
          append_utf8(out, replacement_char);
        }
      } else if (unit >= 0xDC00 && unit <= 0xDFFF) {
        append_utf8(out, replacement_char);
      } else {
        append_utf8(out, unit);
      }
    }
    return out;
  }

  std::u16string utf8_to_utf16(std::string_view utf8) {
    std::u16string out;
    out.reserve(utf8.size());
    std::size_t pos = 0;
    while (pos < utf8.size()) {
      const char32_t cp = decode_utf8(utf8, pos).value_or(replacement_char);
      if (cp >= 0x10000) {
        const char32_t v = cp - 0x10000;
        out.push_back(static_cast<char16_t>(0xD800 + (v >> 10)));
        out.push_back(static_cast<char16_t>(0xDC00 + (v & 0x3FF)));
      } else {
        out.push_back(static_cast<char16_t>(cp));
      }
    }
    return out;
  }

  bool has_png_signature(std::span<const std::uint8_t> data) {
    return data.size() >= png_signature.size() && std::equal(png_signature.begin(), png_signature.end(), data.begin());
  }

  std::optional<png_dimensions_t> png_dimensions(std::span<const std::uint8_t> data) {
    // signature (8) + chunk length (4) + "IHDR" (4) + width (4) + height (4)
    if (data.size() < 24 || !has_png_signature(data)) {
      return std::nullopt;
    }
    if (read_be32(data, 8) != 13 || data[12] != 'I' || data[13] != 'H' || data[14] != 'D' || data[15] != 'R') {
      return std::nullopt;
    }
    const png_dimensions_t dims {read_be32(data, 16), read_be32(data, 20)};
    constexpr std::uint32_t max_dimension = 0x7FFFFFFF;  // PNG specification limit
    if (dims.width == 0 || dims.height == 0 || dims.width > max_dimension || dims.height > max_dimension) {
      return std::nullopt;
    }
    return dims;
  }

  bool png_header_sane(std::span<const std::uint8_t> data, std::size_t max_bytes) {
    const auto dims = png_dimensions(data);
    if (!dims) {
      return false;
    }
    const std::uint64_t bytes = std::uint64_t {dims->width} * dims->height * 4;
    return bytes <= max_bytes;
  }

  std::size_t png_stream_length(std::span<const std::uint8_t> data) {
    if (!has_png_signature(data)) {
      return 0;
    }
    std::size_t pos = png_signature.size();
    while (pos + 12 <= data.size()) {
      const std::uint64_t length = read_be32(data, pos);
      const std::uint64_t end = pos + 12 + length;  // length + type + data + CRC
      if (end > data.size()) {
        return 0;
      }
      const bool iend = data[pos + 4] == 'I' && data[pos + 5] == 'E' && data[pos + 6] == 'N' && data[pos + 7] == 'D';
      pos = static_cast<std::size_t>(end);
      if (iend) {
        return pos;
      }
    }
    return 0;
  }

  std::optional<bgra_image_t> dib_to_bgra(std::span<const std::uint8_t> dib, std::size_t max_bytes) {
    constexpr std::size_t info_header_size = 40;
    if (dib.size() < info_header_size) {
      return std::nullopt;
    }
    const auto header_size = read_le<std::uint32_t>(dib, 0);
    if (header_size < info_header_size || header_size > dib.size()) {
      return std::nullopt;
    }
    const auto raw_width = static_cast<std::int32_t>(read_le<std::uint32_t>(dib, 4));
    const auto raw_height = static_cast<std::int32_t>(read_le<std::uint32_t>(dib, 8));
    const auto bit_count = read_le<std::uint16_t>(dib, 14);
    const auto compression = read_le<std::uint32_t>(dib, 16);
    const auto colors_used = read_le<std::uint32_t>(dib, 32);

    if (raw_width <= 0 || raw_height == 0 || raw_height == std::numeric_limits<std::int32_t>::min()) {
      return std::nullopt;
    }
    const bool top_down = raw_height < 0;
    const auto width = static_cast<std::uint32_t>(raw_width);
    const auto height = static_cast<std::uint32_t>(top_down ? -raw_height : raw_height);
    const std::uint64_t decoded = std::uint64_t {width} * height * 4;
    if (decoded > max_bytes) {
      return std::nullopt;
    }

    const bool bitfields = compression == bi_bitfields || compression == bi_alphabitfields;
    if (compression != bi_rgb && !bitfields) {
      return std::nullopt;
    }
    switch (bit_count) {
      case 1:
      case 4:
      case 8:
        if (compression != bi_rgb) {
          return std::nullopt;
        }
        break;
      case 16:
      case 32:
        break;
      case 24:
        if (compression != bi_rgb) {
          return std::nullopt;
        }
        break;
      default:
        return std::nullopt;
    }

    std::size_t offset = header_size;
    std::uint32_t masks[4] {};
    if (bitfields) {
      const std::size_t mask_count = compression == bi_alphabitfields ? 4 : 3;
      if (header_size == info_header_size) {
        // Masks follow a plain BITMAPINFOHEADER
        if (dib.size() < offset + mask_count * 4) {
          return std::nullopt;
        }
        for (std::size_t i = 0; i < mask_count; ++i) {
          masks[i] = read_le<std::uint32_t>(dib, offset + i * 4);
        }
        offset += mask_count * 4;
      } else {
        // V2+ headers carry the masks at offset 40 (alpha at 52 for V3+)
        const std::size_t required = compression == bi_alphabitfields ? 56 : 52;
        if (header_size < required) {
          return std::nullopt;
        }
        for (std::size_t i = 0; i < 3; ++i) {
          masks[i] = read_le<std::uint32_t>(dib, 40 + i * 4);
        }
        if (header_size >= 56) {
          masks[3] = read_le<std::uint32_t>(dib, 52);
        }
      }
    } else if (bit_count == 16) {
      masks[0] = 0x7C00;
      masks[1] = 0x03E0;
      masks[2] = 0x001F;
    } else if (bit_count == 32) {
      masks[0] = 0x00FF0000;
      masks[1] = 0x0000FF00;
      masks[2] = 0x000000FF;
      masks[3] = 0xFF000000;  // reserved byte; used only if any pixel sets it
    }

    std::vector<std::array<std::uint8_t, 4>> palette;
    if (bit_count <= 8) {
      const std::uint64_t max_colors = 1ull << bit_count;
      const std::uint64_t count = colors_used == 0 ? max_colors : colors_used;
      if (count > max_colors || dib.size() < offset + count * 4) {
        return std::nullopt;
      }
      palette.resize(static_cast<std::size_t>(count));
      for (std::size_t i = 0; i < palette.size(); ++i) {
        palette[i] = {dib[offset + i * 4], dib[offset + i * 4 + 1], dib[offset + i * 4 + 2], 0xFF};
      }
      offset += palette.size() * 4;
    } else if (colors_used != 0) {
      // Optional color table for true-color images; skip it
      const std::uint64_t skip = std::uint64_t {colors_used} * 4;
      if (skip > dib.size() - offset) {
        return std::nullopt;
      }
      offset += static_cast<std::size_t>(skip);
    }

    const std::uint64_t stride = ((std::uint64_t {width} * bit_count + 31) / 32) * 4;
    if (stride * height > dib.size() - offset) {
      return std::nullopt;
    }

    const channel_t red {masks[0]};
    const channel_t green {masks[1]};
    const channel_t blue {masks[2]};
    const channel_t alpha {masks[3]};

    bgra_image_t image;
    image.width = width;
    image.height = height;
    image.pixels.resize(static_cast<std::size_t>(decoded));
    bool any_alpha = false;

    for (std::uint32_t y = 0; y < height; ++y) {
      const std::uint32_t src_row = top_down ? y : height - 1 - y;
      const std::size_t row_offset = offset + static_cast<std::size_t>(stride * src_row);
      std::uint8_t *dst = image.pixels.data() + static_cast<std::size_t>(y) * width * 4;
      for (std::uint32_t x = 0; x < width; ++x, dst += 4) {
        switch (bit_count) {
          case 1:
          case 4:
          case 8:
            {
              const std::size_t bit = static_cast<std::size_t>(x) * bit_count;
              const std::uint8_t byte = dib[row_offset + bit / 8];
              const unsigned shift = 8 - bit_count - static_cast<unsigned>(bit % 8);
              const std::size_t index = (byte >> shift) & ((1u << bit_count) - 1);
              const auto &entry = index < palette.size() ? palette[index] : palette.front();
              std::copy(entry.begin(), entry.end(), dst);
              break;
            }
          case 24:
            {
              const std::size_t p = row_offset + static_cast<std::size_t>(x) * 3;
              dst[0] = dib[p];
              dst[1] = dib[p + 1];
              dst[2] = dib[p + 2];
              dst[3] = 0xFF;
              break;
            }
          default:
            {
              const std::uint32_t pixel = bit_count == 16 ? read_le<std::uint16_t>(dib, row_offset + static_cast<std::size_t>(x) * 2) : read_le<std::uint32_t>(dib, row_offset + static_cast<std::size_t>(x) * 4);
              dst[0] = blue.extract(pixel);
              dst[1] = green.extract(pixel);
              dst[2] = red.extract(pixel);
              if (alpha.bits != 0) {
                dst[3] = alpha.extract(pixel);
                any_alpha = any_alpha || dst[3] != 0;
              } else {
                dst[3] = 0xFF;
              }
              break;
            }
        }
      }
    }

    // An alpha channel that is zero everywhere means "no alpha" (BI_RGB reserved bytes, and
    // screenshot tools that declare an alpha mask without filling it); show the image opaque.
    if (alpha.bits != 0 && !any_alpha) {
      for (std::size_t i = 3; i < image.pixels.size(); i += 4) {
        image.pixels[i] = 0xFF;
      }
    }
    return image;
  }

  std::vector<std::uint8_t> bgra_to_dib(const bgra_image_t &image) {
    const std::uint64_t size = std::uint64_t {image.width} * image.height * 4;
    if (image.width == 0 || image.height == 0 || image.pixels.size() != size || image.width > 0x7FFFFFFF || image.height > 0x7FFFFFFF || size > 0xFFFFFFFF) {
      return {};
    }
    std::vector<std::uint8_t> out;
    out.reserve(40 + static_cast<std::size_t>(size));
    write_le<std::uint32_t>(out, 40);  // biSize
    write_le<std::int32_t>(out, static_cast<std::int32_t>(image.width));
    write_le<std::int32_t>(out, static_cast<std::int32_t>(image.height));  // positive: bottom-up
    write_le<std::uint16_t>(out, 1);  // biPlanes
    write_le<std::uint16_t>(out, 32);  // biBitCount
    write_le<std::uint32_t>(out, bi_rgb);
    write_le<std::uint32_t>(out, static_cast<std::uint32_t>(size));  // biSizeImage
    write_le<std::int32_t>(out, 2835);  // 72 DPI
    write_le<std::int32_t>(out, 2835);
    write_le<std::uint32_t>(out, 0);  // biClrUsed
    write_le<std::uint32_t>(out, 0);  // biClrImportant
    const std::size_t row = static_cast<std::size_t>(image.width) * 4;
    for (std::uint32_t y = image.height; y-- > 0;) {
      const auto *src = image.pixels.data() + static_cast<std::size_t>(y) * row;
      out.insert(out.end(), src, src + row);
    }
    return out;
  }

  bool mime_equal(std::string_view a, std::string_view b) {
    auto next = [](std::string_view s, std::size_t &i) -> int {
      while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) {
        ++i;
      }
      if (i == s.size()) {
        return -1;
      }
      return std::tolower(static_cast<unsigned char>(s[i++]));
    };
    std::size_t i = 0;
    std::size_t j = 0;
    while (true) {
      const int ca = next(a, i);
      const int cb = next(b, j);
      if (ca != cb) {
        return false;
      }
      if (ca == -1) {
        return true;
      }
    }
  }

  std::optional<std::string> pick_mime(const std::vector<std::string> &offered, std::initializer_list<std::string_view> preferred) {
    for (const auto want : preferred) {
      for (const auto &have : offered) {
        if (mime_equal(have, want)) {
          return have;
        }
      }
    }
    return std::nullopt;
  }

  void apply_limits(item_t &item, const limits_t &limits) {
    if (item.text && item.text->size() > limits.text_max) {
      item.text.reset();
    }
    if (item.png && item.png->size() > limits.image_max) {
      item.png.reset();
    }
  }

  change_notifier_t::~change_notifier_t() {
    stop();
  }

  void change_notifier_t::start(std::function<void()> callback) {
    stop();
    std::lock_guard lock(mutex_);
    callback_ = std::move(callback);
    pending_ = false;
    stopping_ = false;
    thread_ = std::thread(&change_notifier_t::run, this);
  }

  void change_notifier_t::notify() {
    {
      std::lock_guard lock(mutex_);
      if (!thread_.joinable() || stopping_) {
        return;
      }
      pending_ = true;
    }
    cv_.notify_one();
  }

  void change_notifier_t::stop() {
    std::thread thread;
    {
      std::lock_guard lock(mutex_);
      stopping_ = true;
      thread = std::move(thread_);
    }
    cv_.notify_one();
    if (!thread.joinable()) {
      return;
    }
    if (thread.get_id() == std::this_thread::get_id()) {
      // Called from the callback: the thread exits once the callback returns
      thread.detach();
      return;
    }
    thread.join();
  }

  void change_notifier_t::run() {
    std::unique_lock lock(mutex_);
    while (true) {
      cv_.wait(lock, [this]() {
        return pending_ || stopping_;
      });
      if (stopping_) {
        return;
      }
      pending_ = false;
      auto callback = callback_;
      lock.unlock();
      if (callback) {
        callback();
      }
      lock.lock();
    }
  }
}  // namespace sds::clipboard::util
