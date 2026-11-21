/**
 * @file src/sds/clipboard.cpp
 * @brief Platform-independent shared clipboard core.
 */
// standard includes
#include <algorithm>
#include <array>
#include <charconv>
#include <utility>

// local includes
#include "auth.h"
#include "clipboard.h"
#include "src/logging.h"
#include "text.h"

using namespace std::literals;

namespace sds::clipboard {
  namespace {
    constexpr std::array<std::uint8_t, 8> PNG_SIGNATURE {0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n'};
    constexpr std::size_t PNG_MIN_SIZE = 8 + 4 + 4 + 13 + 4;  // signature + IHDR length, type, data, CRC

    /**
     * @brief Read a big-endian 32-bit integer.
     *
     * @param data At least four bytes.
     * @return Value.
     */
    std::uint32_t read_be32(const std::uint8_t *data) {
      return (static_cast<std::uint32_t>(data[0]) << 24) | (static_cast<std::uint32_t>(data[1]) << 16) | (static_cast<std::uint32_t>(data[2]) << 8) | data[3];
    }

    /**
     * @brief CRC-32 (ISO-HDLC, as used by PNG).
     *
     * @param data Input.
     * @return Checksum.
     */
    std::uint32_t crc32(std::span<const std::uint8_t> data) {
      static const auto table = []() {
        std::array<std::uint32_t, 256> values {};
        for (std::uint32_t n = 0; n < values.size(); ++n) {
          std::uint32_t c = n;
          for (int k = 0; k < 8; ++k) {
            c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
          }
          values[n] = c;
        }
        return values;
      }();
      std::uint32_t crc = 0xFFFFFFFFu;
      for (const auto byte : data) {
        crc = table[(crc ^ byte) & 0xFF] ^ (crc >> 8);
      }
      return crc ^ 0xFFFFFFFFu;
    }

    /**
     * @brief Check a PNG bit depth / color type combination.
     *
     * @param bit_depth IHDR bit depth.
     * @param color_type IHDR color type.
     * @return `true` when permitted by the PNG specification.
     */
    bool valid_depth(std::uint8_t bit_depth, std::uint8_t color_type) {
      switch (color_type) {
        case 0:
          return bit_depth == 1 || bit_depth == 2 || bit_depth == 4 || bit_depth == 8 || bit_depth == 16;
        case 3:
          return bit_depth == 1 || bit_depth == 2 || bit_depth == 4 || bit_depth == 8;
        case 2:
        case 4:
        case 6:
          return bit_depth == 8 || bit_depth == 16;
        default:
          return false;
      }
    }

    /**
     * @brief Byte view of a PNG vector.
     *
     * @param png PNG bytes.
     * @return Span.
     */
    std::span<const std::uint8_t> bytes_of(const std::vector<std::uint8_t> &png) {
      return {png.data(), png.size()};
    }
  }  // namespace

  std::optional<type_e> parse_type(std::string_view media_type) {
    if (media_type == "text/plain"sv) {
      return type_e::text;
    }
    if (media_type == "image/png"sv) {
      return type_e::png;
    }
    return std::nullopt;
  }

  std::string_view type_name(type_e type) {
    return type == type_e::text ? "text/plain"sv : "image/png"sv;
  }

  validation_e validate_text(std::string_view text, std::size_t max) {
    if (text.size() > max) {
      return validation_e::too_large;
    }
    if (text.find('\0') != std::string_view::npos) {
      return validation_e::contains_nul;
    }
    if (!text::is_valid_utf8(text)) {
      return validation_e::invalid_utf8;
    }
    return validation_e::ok;
  }

  validation_e validate_png(std::span<const std::uint8_t> png, std::size_t max) {
    if (png.size() > max) {
      return validation_e::too_large;
    }
    if (png.size() < PNG_SIGNATURE.size() || !std::equal(PNG_SIGNATURE.begin(), PNG_SIGNATURE.end(), png.begin())) {
      return validation_e::bad_png_signature;
    }
    if (png.size() < PNG_MIN_SIZE) {
      return validation_e::bad_png_header;
    }
    const auto *chunk = png.data() + PNG_SIGNATURE.size();
    if (read_be32(chunk) != 13 || std::string_view(reinterpret_cast<const char *>(chunk + 4), 4) != "IHDR"sv) {
      return validation_e::bad_png_header;
    }
    const auto *ihdr = chunk + 8;
    const std::uint64_t width = read_be32(ihdr);
    const std::uint64_t height = read_be32(ihdr + 4);
    const auto bit_depth = ihdr[8];
    const auto color_type = ihdr[9];
    const auto compression = ihdr[10];
    const auto filter = ihdr[11];
    const auto interlace = ihdr[12];
    if (width == 0 || height == 0 || width > 0x7FFFFFFFu || height > 0x7FFFFFFFu || !valid_depth(bit_depth, color_type) || compression != 0 || filter != 0 || interlace > 1) {
      return validation_e::bad_png_header;
    }
    if (crc32({chunk + 4, 4 + 13}) != read_be32(ihdr + 13)) {
      return validation_e::bad_png_header;
    }
    if (width * height * 4 > PNG_DECODED_MAX) {
      return validation_e::image_too_large;
    }
    return validation_e::ok;
  }

  std::string_view describe(validation_e result) {
    switch (result) {
      case validation_e::ok:
        return "ok"sv;
      case validation_e::too_large:
        return "content exceeds the size limit"sv;
      case validation_e::invalid_utf8:
        return "text is not valid UTF-8"sv;
      case validation_e::contains_nul:
        return "text contains NUL bytes"sv;
      case validation_e::bad_png_signature:
        return "not a PNG image"sv;
      case validation_e::bad_png_header:
        return "malformed PNG header"sv;
      case validation_e::image_too_large:
        return "image dimensions too large"sv;
    }
    return "invalid content"sv;
  }

  core_t::core_t(std::unique_ptr<backend_t> backend, limits_t limits, std::chrono::milliseconds read_timeout, std::chrono::milliseconds coalesce_window, hooks_t hooks):
      backend_(std::move(backend)),
      limits_(limits),
      read_timeout_(read_timeout),
      coalesce_window_(coalesce_window),
      hooks_(std::move(hooks)) {
  }

  core_t::~core_t() {
    shutdown();
  }

  bool core_t::available() const {
    return backend_ != nullptr;
  }

  std::string_view core_t::backend_name() const {
    return backend_ ? backend_->name() : std::string_view {};
  }

  result_t core_t::put(const std::string &client, std::string_view content_type, std::string body, std::string_view client_seq) {
    result_t result;
    const auto fail = [&result](int status, std::string error, std::string_view message) {
      result.status = status;
      result.error = std::move(error);
      result.message = std::string {message};
      return result;
    };

    if (!backend_) {
      return fail(404, "not_found", "clipboard backend not available");
    }

    std::uint64_t seq_value = 0;
    if (client_seq.empty() || std::from_chars(client_seq.data(), client_seq.data() + client_seq.size(), seq_value).ptr != client_seq.data() + client_seq.size()) {
      return fail(400, "bad_request", "missing or invalid X-SDS-Client-Seq");
    }

    const auto [media_type, charset] = parse_content_type(content_type);
    const auto type = parse_type(media_type);
    if (!type || (type == type_e::text && !charset.empty() && charset != "utf-8" && charset != "utf8")) {
      return fail(415, "unsupported_type", "content type must be text/plain;charset=utf-8 or image/png");
    }

    item_t update;
    if (*type == type_e::text) {
      if (const auto valid = validate_text(body, limits_.text_max); valid != validation_e::ok) {
        return fail(valid == validation_e::too_large ? 413 : 400, valid == validation_e::too_large ? "too_large" : "bad_request", describe(valid));
      }
      update.text = std::move(body);
    } else {
      std::vector<std::uint8_t> png(body.begin(), body.end());
      if (const auto valid = validate_png(bytes_of(png), limits_.image_max); valid != validation_e::ok) {
        return fail(valid == validation_e::too_large ? 413 : 400, valid == validation_e::too_large ? "too_large" : "bad_request", describe(valid));
      }
      update.png = std::move(png);
    }

    const auto now = std::chrono::steady_clock::now();
    item_t next;
    if (last_put_ && last_put_->client == client && last_put_->client_seq == seq_value && last_put_->host_seq == seq_ && origin_ == client && now - last_put_->at <= coalesce_window_) {
      // Second representation of the same client item: extend it.
      next = item_;
    }
    if (update.text) {
      next.text = std::move(update.text);
    }
    if (update.png) {
      next.png = std::move(update.png);
    }

    if (backend_->write(next) != 0) {
      BOOST_LOG(warning) << "sds: clipboard backend "sv << backend_->name() << " failed to write"sv;
      return fail(500, "internal", "failed to set the host clipboard");
    }

    item_ = std::move(next);
    origin_ = client;
    ++seq_;
    last_put_ = last_put_t {client, seq_value, seq_, now};

    // The origin client already has this content; drop any older announcement it has not fetched.
    if (hooks_.retract) {
      hooks_.retract(client);
    }
    announce();

    result.status = 204;
    result.host_seq = seq_;
    return result;
  }

  result_t core_t::get(const std::string &, std::optional<std::uint64_t> seq, type_e type) {
    result_t result;
    result.host_seq = seq_;
    if (seq && *seq != seq_) {
      result.status = 410;
      result.error = "conflict";
      result.message = "the clipboard has changed since the requested seq";
      return result;
    }
    if (type == type_e::text && item_.text) {
      result.content_type = "text/plain; charset=utf-8";
      result.body = *item_.text;
      return result;
    }
    if (type == type_e::png && item_.png) {
      result.content_type = "image/png";
      result.body.assign(item_.png->begin(), item_.png->end());
      return result;
    }
    result.status = 404;
    result.error = "not_found";
    result.message = "the clipboard has no such representation";
    return result;
  }

  void core_t::sanitize(item_t &item) const {
    if (item.text && validate_text(*item.text, limits_.text_max) != validation_e::ok) {
      item.text.reset();
    }
    if (item.png && validate_png(bytes_of(*item.png), limits_.image_max) != validation_e::ok) {
      item.png.reset();
    }
  }

  void core_t::on_host_change() {
    if (!backend_ || !watching_) {
      return;
    }
    auto read = backend_->read(limits_, read_timeout_);
    item_t item = read ? std::move(*read) : item_t {};
    sanitize(item);

    if (!origin_.empty() && item.text == item_.text && item.png == item_.png) {
      // Our own write echoed back by the platform: not a new host change.
      return;
    }
    if (origin_.empty() && item.text == item_.text && item.png == item_.png && seq_ != 0) {
      // Duplicate notification for unchanged host content.
      return;
    }

    item_ = std::move(item);
    origin_.clear();
    last_put_.reset();
    ++seq_;
    announce();
  }

  nlohmann::json core_t::make_event() const {
    nlohmann::json types = nlohmann::json::array();
    nlohmann::json sizes = nlohmann::json::object();
    if (item_.text) {
      types.push_back(type_name(type_e::text));
      sizes[std::string {type_name(type_e::text)}] = item_.text->size();
    }
    if (item_.png) {
      types.push_back(type_name(type_e::png));
      sizes[std::string {type_name(type_e::png)}] = item_.png->size();
    }
    return nlohmann::json {{"type", "clipboard"}, {"seq", seq_}, {"types", std::move(types)}, {"sizes", std::move(sizes)}};
  }

  void core_t::announce() {
    if (item_.empty() || !hooks_.readers || !hooks_.publish) {
      return;
    }
    const auto event = make_event();
    for (const auto &reader : hooks_.readers()) {
      if (reader != origin_) {
        hooks_.publish(reader, event);
      }
    }
  }

  void core_t::announce_to(const std::string &client) {
    if (item_.empty() || client == origin_ || !hooks_.publish) {
      return;
    }
    hooks_.publish(client, make_event());
  }

  void core_t::set_watching(bool needed) {
    if (!backend_ || needed == watching_) {
      return;
    }
    if (needed) {
      std::weak_ptr<bool> alive = alive_;
      auto post = hooks_.post;
      const auto status = backend_->start([alive, post, this]() {
        if (!post) {
          return;
        }
        post([alive, this]() {
          if (const auto flag = alive.lock(); flag && *flag) {
            on_host_change();
          }
        });
      });
      if (status != 0) {
        BOOST_LOG(warning) << "sds: clipboard backend "sv << backend_->name() << " failed to start ("sv << status << ')';
        return;
      }
      watching_ = true;
      BOOST_LOG(info) << "sds: watching the host clipboard ("sv << backend_->name() << ')';
      on_host_change();
      return;
    }

    backend_->stop();
    watching_ = false;
    item_ = {};
    origin_.clear();
    last_put_.reset();
    BOOST_LOG(info) << "sds: stopped watching the host clipboard"sv;
  }

  void core_t::forget_client(const std::string &client) {
    if (last_put_ && last_put_->client == client) {
      last_put_.reset();
    }
  }

  void core_t::shutdown() {
    if (alive_) {
      *alive_ = false;
    }
    if (backend_ && watching_) {
      backend_->stop();
    }
    watching_ = false;
    item_ = {};
    origin_.clear();
    last_put_.reset();
  }

  std::uint64_t core_t::seq() const {
    return seq_;
  }

  bool core_t::watching() const {
    return watching_;
  }

  bool core_t::has_content() const {
    return !item_.empty();
  }
}  // namespace sds::clipboard
