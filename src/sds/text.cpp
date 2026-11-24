/**
 * @file src/sds/text.cpp
 * @brief UTF-8 validation and Unicode NFC normalization.
 */
// standard includes
#include <algorithm>
#include <cstdint>
#include <utility>
#include <vector>

// local includes
#include "nfc_data.h"
#include "text.h"

namespace sds::text {
  namespace {
    constexpr char32_t HANGUL_S_BASE = 0xAC00;
    constexpr char32_t HANGUL_L_BASE = 0x1100;
    constexpr char32_t HANGUL_V_BASE = 0x1161;
    constexpr char32_t HANGUL_T_BASE = 0x11A7;
    constexpr char32_t HANGUL_L_COUNT = 19;
    constexpr char32_t HANGUL_V_COUNT = 21;
    constexpr char32_t HANGUL_T_COUNT = 28;
    constexpr char32_t HANGUL_N_COUNT = HANGUL_V_COUNT * HANGUL_T_COUNT;
    constexpr char32_t HANGUL_S_COUNT = HANGUL_L_COUNT * HANGUL_N_COUNT;

    /**
     * @brief Decode one UTF-8 sequence.
     *
     * @param bytes Input buffer.
     * @param pos Position of the first byte; advanced past the sequence on success.
     * @return Decoded scalar value, or no value for a malformed sequence.
     */
    std::optional<char32_t> decode_one(std::string_view bytes, std::size_t &pos) {
      const auto lead = static_cast<unsigned char>(bytes[pos]);
      if (lead < 0x80) {
        ++pos;
        return lead;
      }

      std::size_t length;
      char32_t value;
      char32_t minimum;
      if (lead >= 0xC2 && lead <= 0xDF) {
        length = 2;
        value = lead & 0x1F;
        minimum = 0x80;
      } else if (lead >= 0xE0 && lead <= 0xEF) {
        length = 3;
        value = lead & 0x0F;
        minimum = 0x800;
      } else if (lead >= 0xF0 && lead <= 0xF4) {
        length = 4;
        value = lead & 0x07;
        minimum = 0x10000;
      } else {
        return std::nullopt;
      }

      if (bytes.size() - pos < length) {
        return std::nullopt;
      }
      for (std::size_t i = 1; i < length; ++i) {
        const auto continuation = static_cast<unsigned char>(bytes[pos + i]);
        if ((continuation & 0xC0) != 0x80) {
          return std::nullopt;
        }
        value = (value << 6) | (continuation & 0x3F);
      }
      if (value < minimum || value > 0x10FFFF || (value >= 0xD800 && value <= 0xDFFF)) {
        return std::nullopt;
      }
      pos += length;
      return value;
    }

    /**
     * @brief Look up the canonical combining class of a code point.
     *
     * @param code_point Unicode scalar value.
     * @return Canonical combining class, zero for starters.
     */
    std::uint8_t combining_class(char32_t code_point) {
      const auto &ranges = nfc_data::ccc_ranges;
      const auto it = std::upper_bound(ranges.begin(), ranges.end(), code_point, [](char32_t value, const nfc_data::ccc_range_t &range) {
        return value < range.first;
      });
      if (it == ranges.begin()) {
        return 0;
      }
      const auto &range = *std::prev(it);
      return code_point <= range.last ? range.ccc : 0;
    }

    /**
     * @brief Find the one-level canonical decomposition of a code point.
     *
     * @param code_point Unicode scalar value.
     * @return Pointer to the table entry, or `nullptr` when the code point does not decompose.
     */
    const nfc_data::decomposition_t *find_decomposition(char32_t code_point) {
      const auto &table = nfc_data::decompositions;
      const auto it = std::lower_bound(table.begin(), table.end(), code_point, [](const nfc_data::decomposition_t &entry, char32_t value) {
        return entry.code_point < value;
      });
      return it != table.end() && it->code_point == code_point ? &*it : nullptr;
    }

    /**
     * @brief Append the full canonical decomposition of a code point.
     *
     * @param code_point Unicode scalar value.
     * @param out Destination.
     */
    void decompose(char32_t code_point, std::u32string &out) {
      if (code_point >= HANGUL_S_BASE && code_point < HANGUL_S_BASE + HANGUL_S_COUNT) {
        const auto index = code_point - HANGUL_S_BASE;
        out.push_back(HANGUL_L_BASE + index / HANGUL_N_COUNT);
        out.push_back(HANGUL_V_BASE + (index % HANGUL_N_COUNT) / HANGUL_T_COUNT);
        if (const auto trailing = index % HANGUL_T_COUNT; trailing != 0) {
          out.push_back(HANGUL_T_BASE + trailing);
        }
        return;
      }
      if (const auto *entry = find_decomposition(code_point); entry) {
        decompose(entry->first, out);
        if (entry->second != 0) {
          decompose(entry->second, out);
        }
        return;
      }
      out.push_back(code_point);
    }

    /**
     * @brief Build the primary-composite lookup table once.
     *
     * @return Pairs `(first, second) -> composite` sorted by pair.
     */
    const std::vector<std::pair<std::uint64_t, char32_t>> &composition_table() {
      static const auto table = []() {
        std::vector<std::pair<std::uint64_t, char32_t>> pairs;
        for (const auto &entry : nfc_data::decompositions) {
          if (entry.composable) {
            pairs.emplace_back((static_cast<std::uint64_t>(entry.first) << 32) | entry.second, entry.code_point);
          }
        }
        std::ranges::sort(pairs);
        return pairs;
      }();
      return table;
    }

    /**
     * @brief Compose a starter with a following character.
     *
     * @param first Starter.
     * @param second Following character.
     * @return Primary composite, or no value when the pair does not compose.
     */
    std::optional<char32_t> compose_pair(char32_t first, char32_t second) {
      if (first >= HANGUL_L_BASE && first < HANGUL_L_BASE + HANGUL_L_COUNT && second >= HANGUL_V_BASE && second < HANGUL_V_BASE + HANGUL_V_COUNT) {
        return HANGUL_S_BASE + ((first - HANGUL_L_BASE) * HANGUL_V_COUNT + (second - HANGUL_V_BASE)) * HANGUL_T_COUNT;
      }
      if (first >= HANGUL_S_BASE && first < HANGUL_S_BASE + HANGUL_S_COUNT && (first - HANGUL_S_BASE) % HANGUL_T_COUNT == 0 && second > HANGUL_T_BASE && second < HANGUL_T_BASE + HANGUL_T_COUNT) {
        return first + (second - HANGUL_T_BASE);
      }
      const auto key = (static_cast<std::uint64_t>(first) << 32) | second;
      const auto &table = composition_table();
      const auto it = std::lower_bound(table.begin(), table.end(), key, [](const auto &entry, std::uint64_t value) {
        return entry.first < value;
      });
      if (it != table.end() && it->first == key) {
        return it->second;
      }
      return std::nullopt;
    }
  }  // namespace

  bool is_valid_utf8(std::string_view bytes) {
    std::size_t pos = 0;
    while (pos < bytes.size()) {
      if (!decode_one(bytes, pos)) {
        return false;
      }
    }
    return true;
  }

  std::optional<std::u32string> decode_utf8(std::string_view bytes) {
    std::u32string out;
    out.reserve(bytes.size());
    std::size_t pos = 0;
    while (pos < bytes.size()) {
      const auto value = decode_one(bytes, pos);
      if (!value) {
        return std::nullopt;
      }
      out.push_back(*value);
    }
    return out;
  }

  std::string encode_utf8(std::u32string_view code_points) {
    std::string out;
    out.reserve(code_points.size());
    for (const char32_t value : code_points) {
      if (value < 0x80) {
        out.push_back(static_cast<char>(value));
      } else if (value < 0x800) {
        out.push_back(static_cast<char>(0xC0 | (value >> 6)));
        out.push_back(static_cast<char>(0x80 | (value & 0x3F)));
      } else if (value < 0x10000) {
        out.push_back(static_cast<char>(0xE0 | (value >> 12)));
        out.push_back(static_cast<char>(0x80 | ((value >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (value & 0x3F)));
      } else {
        out.push_back(static_cast<char>(0xF0 | (value >> 18)));
        out.push_back(static_cast<char>(0x80 | ((value >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((value >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (value & 0x3F)));
      }
    }
    return out;
  }

  std::u32string to_nfc(std::u32string_view code_points) {
    std::u32string decomposed;
    decomposed.reserve(code_points.size());
    for (const char32_t value : code_points) {
      decompose(value, decomposed);
    }

    // Canonical ordering: stable-sort each run of non-starters by combining class.
    std::vector<std::pair<std::uint8_t, char32_t>> run;
    std::size_t pos = 0;
    while (pos < decomposed.size()) {
      if (combining_class(decomposed[pos]) == 0) {
        ++pos;
        continue;
      }
      run.clear();
      const std::size_t run_start = pos;
      while (pos < decomposed.size()) {
        const auto ccc = combining_class(decomposed[pos]);
        if (ccc == 0) {
          break;
        }
        run.emplace_back(ccc, decomposed[pos]);
        ++pos;
      }
      if (run.size() > 1) {
        std::stable_sort(run.begin(), run.end(), [](const auto &a, const auto &b) {
          return a.first < b.first;
        });
        for (std::size_t i = 0; i < run.size(); ++i) {
          decomposed[run_start + i] = run[i].second;
        }
      }
    }

    std::u32string out;
    out.reserve(decomposed.size());
    constexpr auto no_starter = std::u32string::npos;
    std::size_t starter = no_starter;
    std::uint8_t last_class = 0;
    for (const char32_t value : decomposed) {
      const auto current_class = combining_class(value);
      if (starter != no_starter) {
        const bool adjacent = out.size() - 1 == starter;
        const bool blocked = !adjacent && (last_class == 0 || last_class >= current_class);
        if (!blocked) {
          if (const auto composite = compose_pair(out[starter], value); composite) {
            out[starter] = *composite;
            continue;
          }
        }
      }
      if (current_class == 0) {
        starter = out.size();
      }
      last_class = current_class;
      out.push_back(value);
    }
    return out;
  }

  std::optional<std::string> to_nfc(std::string_view bytes) {
    const auto decoded = decode_utf8(bytes);
    if (!decoded) {
      return std::nullopt;
    }
    return encode_utf8(to_nfc(std::u32string_view {*decoded}));
  }
}  // namespace sds::text
