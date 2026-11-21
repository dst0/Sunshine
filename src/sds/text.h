/**
 * @file src/sds/text.h
 * @brief UTF-8 validation and Unicode NFC normalization used by the clipboard and file-name rules.
 */
#pragma once

// standard includes
#include <optional>
#include <string>
#include <string_view>

namespace sds::text {
  /**
   * @brief Check that bytes are well-formed UTF-8.
   *
   * Rejects overlong encodings, surrogate code points and values above U+10FFFF.
   *
   * @param bytes Bytes to validate.
   * @return `true` when the input is valid UTF-8.
   */
  bool is_valid_utf8(std::string_view bytes);

  /**
   * @brief Decode well-formed UTF-8 into code points.
   *
   * @param bytes UTF-8 input.
   * @return Decoded code points, or no value when the input is not valid UTF-8.
   */
  std::optional<std::u32string> decode_utf8(std::string_view bytes);

  /**
   * @brief Encode code points as UTF-8.
   *
   * @param code_points Valid Unicode scalar values.
   * @return UTF-8 encoding.
   */
  std::string encode_utf8(std::u32string_view code_points);

  /**
   * @brief Normalize code points to Unicode Normalization Form C.
   *
   * @param code_points Valid Unicode scalar values.
   * @return Canonically composed code points.
   */
  std::u32string to_nfc(std::u32string_view code_points);

  /**
   * @brief Normalize UTF-8 text to Unicode Normalization Form C.
   *
   * @param bytes UTF-8 input.
   * @return NFC text, or no value when the input is not valid UTF-8.
   */
  std::optional<std::string> to_nfc(std::string_view bytes);
}  // namespace sds::text
