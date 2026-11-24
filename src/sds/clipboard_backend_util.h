/**
 * @file src/sds/clipboard_backend_util.h
 * @brief Platform-independent helpers shared by the host clipboard backends.
 *
 * Everything here is pure C++ so that the conversions used by the X11, portal and Win32
 * backends can be unit-tested on any host: UTF-8 repair, Latin-1 and UTF-16 conversion,
 * line-ending conversion, PNG header checks, DIB (CF_DIB / CF_DIBV5) decoding and encoding,
 * MIME selection, limit enforcement and a coalescing change notifier.
 */
#pragma once

// standard includes
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <initializer_list>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

// local includes
#include "clipboard_backend.h"

namespace sds::clipboard::util {
  /**
   * @brief Largest decoded image (width * height * 4 bytes) any backend will handle.
   *
   * Matches the PNG header sanity check of DESIGN section 5.1.
   */
  constexpr std::size_t max_decoded_image_bytes = 256u * 1024u * 1024u;

  /**
   * @brief Replace invalid UTF-8 sequences with U+FFFD.
   *
   * Overlong encodings, surrogates and code points above U+10FFFF are treated as invalid.
   *
   * @param input Bytes that should be UTF-8.
   * @return Valid UTF-8.
   */
  std::string repair_utf8(std::string_view input);

  /**
   * @brief Check whether a byte string is valid UTF-8.
   *
   * @param input Bytes to check.
   * @return True when the input is well-formed UTF-8.
   */
  bool is_valid_utf8(std::string_view input);

  /**
   * @brief Normalize host clipboard text into the item_t text contract.
   *
   * Trailing NUL bytes (common in X11 and Win32 clipboard data) are removed, text that still
   * contains a NUL byte is rejected, and invalid UTF-8 is repaired with U+FFFD.
   *
   * @param raw Raw text bytes in UTF-8.
   * @return Valid, non-empty UTF-8 without NUL bytes, or nullopt.
   */
  std::optional<std::string> sanitize_text(std::string_view raw);

  /**
   * @brief Convert ISO-8859-1 bytes to UTF-8.
   *
   * @param latin1 Latin-1 bytes.
   * @return UTF-8 text.
   */
  std::string latin1_to_utf8(std::string_view latin1);

  /**
   * @brief Convert UTF-8 to ISO-8859-1, replacing unrepresentable characters with '?'.
   *
   * @param utf8 Valid UTF-8 text.
   * @return Latin-1 bytes.
   */
  std::string utf8_to_latin1_lossy(std::string_view utf8);

  /**
   * @brief Convert CRLF line endings to LF. Lone CR characters are kept.
   *
   * @param text Text with Windows line endings.
   * @return Text with LF line endings.
   */
  std::string crlf_to_lf(std::string_view text);

  /**
   * @brief Convert LF line endings to CRLF without doubling existing CRLF pairs.
   *
   * @param text Text with LF line endings.
   * @return Text with CRLF line endings.
   */
  std::string lf_to_crlf(std::string_view text);

  /**
   * @brief Convert UTF-16 to UTF-8. Unpaired surrogates become U+FFFD.
   *
   * @param utf16 UTF-16 code units.
   * @return UTF-8 text.
   */
  std::string utf16_to_utf8(std::u16string_view utf16);

  /**
   * @brief Convert UTF-8 to UTF-16. Invalid input is repaired first.
   *
   * @param utf8 UTF-8 text.
   * @return UTF-16 code units.
   */
  std::u16string utf8_to_utf16(std::string_view utf8);

  /**
   * @brief Dimensions read from a PNG IHDR chunk.
   */
  struct png_dimensions_t {
    std::uint32_t width;  ///< Image width in pixels.
    std::uint32_t height;  ///< Image height in pixels.
  };

  /**
   * @brief Check for the 8-byte PNG signature.
   *
   * @param data Candidate PNG bytes.
   * @return True when the signature is present.
   */
  bool has_png_signature(std::span<const std::uint8_t> data);

  /**
   * @brief Read width and height from the IHDR chunk that must follow the PNG signature.
   *
   * @param data Candidate PNG bytes.
   * @return Dimensions, or nullopt when the signature or IHDR chunk is missing or invalid.
   */
  std::optional<png_dimensions_t> png_dimensions(std::span<const std::uint8_t> data);

  /**
   * @brief PNG sanity check applied before any decoder sees the data.
   *
   * @param data Candidate PNG bytes.
   * @param max_bytes Largest allowed width * height * 4.
   * @return True when the signature and IHDR are valid and the decoded size is within bounds.
   */
  bool png_header_sane(std::span<const std::uint8_t> data, std::size_t max_bytes = max_decoded_image_bytes);

  /**
   * @brief Length of a PNG stream up to and including its IEND chunk.
   *
   * Win32 clipboard memory blocks may be larger than the PNG they contain; this finds the
   * real end so trailing padding is not passed on.
   *
   * @param data PNG bytes, possibly followed by padding.
   * @return Byte length through IEND, or 0 when the chunk structure is malformed.
   */
  std::size_t png_stream_length(std::span<const std::uint8_t> data);

  /**
   * @brief Uncompressed 32-bit image in top-down BGRA order (Windows DIB byte order).
   */
  struct bgra_image_t {
    std::uint32_t width = 0;  ///< Width in pixels.
    std::uint32_t height = 0;  ///< Height in pixels.
    std::vector<std::uint8_t> pixels;  ///< width * height * 4 bytes, rows top to bottom, B G R A.
  };

  /**
   * @brief Decode a packed DIB (CF_DIB or CF_DIBV5 clipboard memory) to BGRA.
   *
   * Supports BITMAPINFOHEADER, V2-V5 headers, 1/4/8-bit palettes, 16/24/32-bit pixels,
   * BI_RGB, BI_BITFIELDS and BI_ALPHABITFIELDS, bottom-up and top-down rows. An alpha
   * channel (or 32-bit BI_RGB reserved byte) that is zero for every pixel is treated as
   * opaque. Compressed formats (RLE, JPEG, PNG) are rejected.
   *
   * @param dib Packed DIB bytes (header, optional masks/palette, pixels).
   * @param max_bytes Largest allowed decoded size.
   * @return Decoded image, or nullopt when the DIB is malformed, unsupported or too large.
   */
  std::optional<bgra_image_t> dib_to_bgra(std::span<const std::uint8_t> dib, std::size_t max_bytes = max_decoded_image_bytes);

  /**
   * @brief Encode a BGRA image as a packed CF_DIB (BITMAPINFOHEADER, 32 bpp, BI_RGB, bottom-up).
   *
   * @param image Image to encode; pixels must hold width * height * 4 bytes.
   * @return Packed DIB bytes, or an empty vector when the image is empty or inconsistent.
   */
  std::vector<std::uint8_t> bgra_to_dib(const bgra_image_t &image);

  /**
   * @brief Compare two MIME types or X11 target names, ignoring ASCII case and blanks.
   *
   * @param a First type.
   * @param b Second type.
   * @return True when both name the same type.
   */
  bool mime_equal(std::string_view a, std::string_view b);

  /**
   * @brief Pick the first preferred type that is offered.
   *
   * @param offered Types offered by the clipboard owner.
   * @param preferred Acceptable types in order of preference.
   * @return The offered spelling of the chosen type, or nullopt.
   */
  std::optional<std::string> pick_mime(const std::vector<std::string> &offered, std::initializer_list<std::string_view> preferred);

  /**
   * @brief Drop representations that exceed the limits (no truncation).
   *
   * @param item Item to adjust in place.
   * @param limits Size limits.
   */
  void apply_limits(item_t &item, const limits_t &limits);

  /**
   * @brief Calls a change callback on its own thread, coalescing bursts of notifications.
   *
   * Backends call notify() from their event threads; the callback runs on the notifier
   * thread, so it may call back into the backend (for example read()) without deadlocking
   * the event thread. After stop() returns, the callback is never invoked again.
   */
  class change_notifier_t {
  public:
    change_notifier_t() = default;
    change_notifier_t(const change_notifier_t &) = delete;
    change_notifier_t &operator=(const change_notifier_t &) = delete;

    /**
     * @brief Stop the thread if the owner did not.
     */
    ~change_notifier_t();

    /**
     * @brief Start the notifier thread.
     *
     * @param callback Function invoked once per burst of notify() calls.
     */
    void start(std::function<void()> callback);

    /**
     * @brief Request a callback; repeated requests before it runs collapse into one.
     */
    void notify();

    /**
     * @brief Stop and join the notifier thread. Idempotent; safe to call from the callback.
     */
    void stop();

  private:
    /**
     * @brief Thread body: wait for notifications and run the callback.
     */
    void run();

    std::mutex mutex_;
    std::condition_variable cv_;
    std::function<void()> callback_;
    bool pending_ = false;
    bool stopping_ = false;
    std::thread thread_;
  };
}  // namespace sds::clipboard::util
