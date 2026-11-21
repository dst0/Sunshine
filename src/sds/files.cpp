/**
 * @file src/sds/files.cpp
 * @brief File transfer core: upload sessions, outbox listing/ids, range reads, sanitizer.
 */
// standard includes
#include <algorithm>
#include <cctype>
#include <format>
#include <regex>
#include <utility>

// lib includes
#include <openssl/hmac.h>
#include <openssl/rand.h>

// local includes
#include "files.h"
#include "src/logging.h"
#include "text.h"

using namespace std::literals;

namespace sds::files {
  namespace {
    /**
     * @brief Longest extension (including the dot) kept when shortening an overlong name (DESIGN 6.4).
     */
    constexpr std::size_t EXTENSION_MAX_BYTES = 32;

    /**
     * @brief Hex-encode bytes in lowercase.
     *
     * @param data Bytes.
     * @param size Byte count.
     * @return Hex string.
     */
    std::string to_hex(const unsigned char *data, std::size_t size) {
      static constexpr char digits[] = "0123456789abcdef";
      std::string out;
      out.reserve(size * 2);
      for (std::size_t i = 0; i < size; ++i) {
        out.push_back(digits[data[i] >> 4]);
        out.push_back(digits[data[i] & 0x0F]);
      }
      return out;
    }

    /**
     * @brief Decode a 64-digit hex SHA-256.
     *
     * @param hex Candidate (either case).
     * @return Digest, or no value when malformed.
     */
    std::optional<std::array<std::uint8_t, 32>> parse_sha256(std::string_view hex) {
      if (hex.size() != 64) {
        return std::nullopt;
      }
      std::array<std::uint8_t, 32> out {};
      for (std::size_t i = 0; i < 64; ++i) {
        const auto ch = static_cast<unsigned char>(std::tolower(static_cast<unsigned char>(hex[i])));
        std::uint8_t value;
        if (ch >= '0' && ch <= '9') {
          value = ch - '0';
        } else if (ch >= 'a' && ch <= 'f') {
          value = ch - 'a' + 10;
        } else {
          return std::nullopt;
        }
        out[i / 2] = static_cast<std::uint8_t>((out[i / 2] << 4) | value);
      }
      return out;
    }

    /**
     * @brief Generate a 128-bit random id from the OpenSSL CSPRNG.
     *
     * @return 32 hex digits, or empty when the CSPRNG fails.
     */
    std::string random_id() {
      std::array<unsigned char, 16> bytes {};
      if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1) {
        return {};
      }
      return to_hex(bytes.data(), bytes.size());
    }

    /**
     * @brief Check whether a code point must be replaced in file names.
     *
     * @param c Code point.
     * @return `true` for separators, reserved punctuation, controls and bidi formatting.
     */
    bool forbidden(char32_t c) {
      if (c < 0x20 || c == 0x7F || (c >= 0x80 && c <= 0x9F)) {
        return true;
      }
      switch (c) {
        case U'/':
        case U'\\':
        case U':':
        case U'*':
        case U'?':
        case U'"':
        case U'<':
        case U'>':
        case U'|':
        // Bidirectional formatting characters can disguise an extension ("photo<RLO>gnp.exe").
        case 0x061C:
        case 0x200E:
        case 0x200F:
        case 0x202A:
        case 0x202B:
        case 0x202C:
        case 0x202D:
        case 0x202E:
        case 0x2066:
        case 0x2067:
        case 0x2068:
        case 0x2069:
          return true;
        default:
          return false;
      }
    }

    /**
     * @brief Check whether a stem is a Windows reserved device name.
     *
     * @param stem Part before the first dot, trailing spaces removed.
     * @return `true` when reserved.
     */
    bool reserved_device_name(std::u32string_view stem) {
      std::string upper;
      for (const char32_t c : stem) {
        if (c == 0xB9 || c == 0xB2 || c == 0xB3) {
          upper.push_back(c == 0xB9 ? '1' : c == 0xB2 ? '2' : '3');
          upper.push_back('^');  // superscript marker so plain digits and superscripts both match below
          continue;
        }
        if (c > 0x7F) {
          return false;
        }
        upper.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
      }
      static const std::regex reserved {R"(^(CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|COM[1-9]\^?|LPT[1-9]\^?)$)"};
      return std::regex_match(upper, reserved);
    }

    /**
     * @brief Byte length of the UTF-8 encoding of a code point.
     *
     * @param c Code point.
     * @return 1-4.
     */
    std::size_t utf8_length(char32_t c) {
      return c < 0x80 ? 1 : c < 0x800 ? 2 : c < 0x10000 ? 3 : 4;
    }

    /**
     * @brief Byte length of the UTF-8 encoding of code points.
     *
     * @param text Code points.
     * @return Bytes.
     */
    std::size_t utf8_length(std::u32string_view text) {
      std::size_t total = 0;
      for (const char32_t c : text) {
        total += utf8_length(c);
      }
      return total;
    }

    /**
     * @brief Position of the extension dot kept when shortening a name.
     *
     * @param name Name.
     * @return Index of the dot, or npos when the name has no short extension.
     */
    std::size_t extension_position(const std::u32string &name) {
      const auto dot = name.find_last_of(U'.');
      if (dot == std::u32string::npos || dot == 0 || utf8_length(std::u32string_view {name}.substr(dot)) > EXTENSION_MAX_BYTES) {
        return std::u32string::npos;
      }
      return dot;
    }

    /**
     * @brief Hash a file through an open handle.
     *
     * @param file Open file.
     * @param size Bytes to hash.
     * @return Hex digest, or no value on error.
     */
    std::optional<std::string> hash_file(fs::file_t &file, std::uint64_t size) {
      std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx {EVP_MD_CTX_new(), &EVP_MD_CTX_free};
      if (!ctx || EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1) {
        return std::nullopt;
      }
      std::vector<char> buffer(1024 * 1024);
      std::uint64_t offset = 0;
      while (offset < size) {
        std::size_t read = 0;
        const auto want = static_cast<std::size_t>(std::min<std::uint64_t>(buffer.size(), size - offset));
        if (file.read_at(offset, std::span<char> {buffer.data(), want}, read) || read == 0) {
          return std::nullopt;
        }
        if (EVP_DigestUpdate(ctx.get(), buffer.data(), read) != 1) {
          return std::nullopt;
        }
        offset += read;
      }
      std::array<unsigned char, EVP_MAX_MD_SIZE> digest {};
      unsigned int length = 0;
      if (EVP_DigestFinal_ex(ctx.get(), digest.data(), &length) != 1) {
        return std::nullopt;
      }
      return to_hex(digest.data(), length);
    }
  }  // namespace

  std::optional<std::string> sanitize_file_name(std::string_view name) {
    const auto decoded = text::decode_utf8(name);
    if (!decoded || decoded->empty()) {
      return std::nullopt;
    }
    auto cps = text::to_nfc(std::u32string_view {*decoded});
    if (cps == U"." || cps == U"..") {
      return std::nullopt;
    }
    for (auto &c : cps) {
      if (forbidden(c)) {
        c = U'_';
      }
    }
    while (!cps.empty() && (cps.back() == U'.' || cps.back() == U' ')) {
      cps.pop_back();
    }
    if (cps.empty()) {
      return std::nullopt;
    }
    if (cps.front() == U'.' || cps.front() == U'-') {
      cps.front() = U'_';
    }

    auto stem = std::u32string_view {cps}.substr(0, cps.find(U'.'));
    while (!stem.empty() && stem.back() == U' ') {
      stem.remove_suffix(1);
    }
    if (reserved_device_name(stem)) {
      cps.insert(cps.begin(), U'_');
    }

    if (utf8_length(std::u32string_view {cps}) > NAME_MAX_BYTES) {
      const auto dot = extension_position(cps);
      const std::u32string extension = dot == std::u32string::npos ? std::u32string {} : cps.substr(dot);
      std::u32string base = dot == std::u32string::npos ? cps : cps.substr(0, dot);
      const auto budget = NAME_MAX_BYTES - utf8_length(std::u32string_view {extension});
      std::size_t used = 0;
      std::size_t keep = 0;
      while (keep < base.size() && used + utf8_length(base[keep]) <= budget) {
        used += utf8_length(base[keep]);
        ++keep;
      }
      base.resize(keep);
      if (extension.empty()) {
        while (!base.empty() && (base.back() == U'.' || base.back() == U' ')) {
          base.pop_back();
        }
      }
      cps = base + extension;
      if (cps.empty()) {
        return std::nullopt;
      }
    }
    return text::encode_utf8(cps);
  }

  std::string collision_name(std::string_view name, unsigned n) {
    const std::string value {name};
    // Split at the last dot like the client does (DESIGN 6.5); a leading dot is not an extension.
    const auto dot = value.find_last_of('.');
    if (dot == std::string::npos || dot == 0) {
      return std::format("{} ({})", value, n);
    }
    return std::format("{} ({}){}", value.substr(0, dot), n, value.substr(dot));
  }

  bool is_id(std::string_view id) {
    return id.size() == 32 && std::ranges::all_of(id, [](char c) {
             return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
           });
  }

  manager_t::manager_t(options_t options):
      options_(std::move(options)) {
    if (RAND_bytes(id_key_.data(), static_cast<int>(id_key_.size())) != 1) {
      // Without a key the ids would be predictable; derive one from fresh upload ids instead.
      const auto fallback = random_id() + random_id();
      std::copy_n(fallback.begin(), std::min(fallback.size(), id_key_.size()), id_key_.begin());
    }
  }

  manager_t::~manager_t() {
    shutdown();
  }

  const options_t &manager_t::options() const {
    return options_;
  }

  std::size_t manager_t::open_uploads(std::string_view client) const {
    std::lock_guard lock {counts_mutex_};
    const auto it = counts_.find(client);
    return it == counts_.end() ? 0 : it->second;
  }

  std::size_t manager_t::total_uploads() const {
    std::lock_guard lock {counts_mutex_};
    std::size_t total = 0;
    for (const auto &[_, count] : counts_) {
      total += count;
    }
    return total;
  }

  manager_t::upload_t *manager_t::find(const std::string &client, std::string_view id) {
    const auto it = uploads_.find(id);
    if (it == uploads_.end() || it->second.owner != client) {
      return nullptr;
    }
    return &it->second;
  }

  void manager_t::drop(const std::string &id) {
    const auto it = uploads_.find(id);
    if (it == uploads_.end()) {
      return;
    }
    auto &upload = it->second;
    upload.file.reset();
    if (upload.dir) {
      if (const auto ec = upload.dir->remove(upload.part_name); ec && ec != std::errc::no_such_file_or_directory) {
        BOOST_LOG(warning) << "sds: could not delete a partial upload: "sv << ec.message();
      }
    }
    {
      std::lock_guard lock {counts_mutex_};
      if (auto count = counts_.find(upload.owner); count != counts_.end() && --count->second == 0) {
        counts_.erase(count);
      }
    }
    uploads_.erase(it);
  }

  std::filesystem::path manager_t::inbox_dir() const {
    if (!options_.inbox.empty()) {
      return options_.inbox;
    }
    const auto downloads = fs::user_download_dir();
    return downloads.empty() ? std::filesystem::path {} : downloads / "Moonlight";
  }

  std::filesystem::path manager_t::outbox_dir() const {
    if (!options_.outbox.empty()) {
      return options_.outbox;
    }
    const auto inbox = inbox_dir();
    return inbox.empty() ? std::filesystem::path {} : inbox / "Outbox";
  }

  std::error_code manager_t::open_inbox(std::unique_ptr<fs::directory_t> &out) {
    if (const auto ec = fs::open_directory(inbox_dir(), true, out); ec) {
      return ec;
    }
    if (!inbox_cleaned_) {
      // Sessions live in memory only, so part files left by a previous run are stale.
      static const std::regex part_pattern {R"(^\.[0-9a-f]{32}\.part$)"};
      std::vector<std::string> names;
      if (!out->list_names(names)) {
        for (const auto &name : names) {
          if (std::regex_match(name, part_pattern) && !uploads_.contains(name.substr(1, 32))) {
            out->remove(name);
          }
        }
      }
      inbox_cleaned_ = true;
    }
    return {};
  }

  reply_t manager_t::create(const std::string &client, std::string_view body) {
    const auto request = nlohmann::json::parse(body, nullptr, false);
    if (request.is_discarded() || !request.is_object()) {
      return reply_t::failure(400, "bad_request", "body must be a JSON object");
    }
    const auto name_it = request.find("name");
    const auto size_it = request.find("size");
    const auto sha_it = request.find("sha256");
    if (name_it == request.end() || !name_it->is_string() || size_it == request.end() || !size_it->is_number_integer() || sha_it == request.end() || !sha_it->is_string()) {
      return reply_t::failure(400, "bad_request", "name, size and sha256 are required");
    }
    if (!size_it->is_number_unsigned() && size_it->get<std::int64_t>() < 0) {
      return reply_t::failure(400, "bad_request", "size must not be negative");
    }
    const auto size = size_it->get<std::uint64_t>();
    if (size > options_.file_max) {
      return reply_t::failure(413, "too_large", "file exceeds file_max");
    }
    const auto expected_sha = parse_sha256(sha_it->get<std::string>());
    if (!expected_sha) {
      return reply_t::failure(400, "bad_request", "sha256 must be 64 hex digits");
    }
    auto name = sanitize_file_name(name_it->get<std::string>());
    if (!name) {
      return reply_t::failure(400, "bad_request", "invalid file name");
    }
    if (open_uploads(client) >= options_.uploads_max) {
      auto reply = reply_t::failure(429, "rate_limited", "too many concurrent uploads");
      reply.headers.emplace_back("Retry-After", "1");
      return reply;
    }

    std::unique_ptr<fs::directory_t> dir;
    if (const auto ec = open_inbox(dir); ec) {
      BOOST_LOG(warning) << "sds: inbox "sv << inbox_dir().string() << " refused: "sv << ec.message();
      return reply_t::failure(500, "internal", "inbox directory unavailable");
    }
    const auto available = dir->free_space();
    if (!available || *available < options_.min_free_space || *available - options_.min_free_space < size) {
      return reply_t::failure(507, "insufficient_space", "not enough free space on the host");
    }

    upload_t upload;
    std::string id;
    for (int attempt = 0; attempt < 3 && !upload.file; ++attempt) {
      id = random_id();
      if (id.empty()) {
        return reply_t::failure(500, "internal", "random number generator failure");
      }
      upload.part_name = "." + id + ".part";
      if (const auto ec = dir->create_exclusive(upload.part_name, upload.file); ec && ec != std::errc::file_exists) {
        BOOST_LOG(warning) << "sds: could not create a partial upload: "sv << ec.message();
        return reply_t::failure(500, "internal", "could not create the upload file");
      }
    }
    if (!upload.file) {
      return reply_t::failure(500, "internal", "could not allocate an upload id");
    }
    upload.sha.reset(EVP_MD_CTX_new());
    if (!upload.sha || EVP_DigestInit_ex(upload.sha.get(), EVP_sha256(), nullptr) != 1) {
      upload.file.reset();
      dir->remove(upload.part_name);
      return reply_t::failure(500, "internal", "hash initialization failed");
    }
    upload.owner = client;
    upload.name = std::move(*name);
    upload.size = size;
    upload.expected_sha = *expected_sha;
    upload.dir = std::move(dir);
    upload.last_activity = clock::now();
    uploads_.emplace(id, std::move(upload));
    {
      std::lock_guard lock {counts_mutex_};
      ++counts_[client];
    }
    BOOST_LOG(debug) << "sds: upload "sv << id << " started ("sv << size << " bytes)"sv;
    return reply_t::success(201, {{"id", id}, {"chunk_max", options_.chunk_max}, {"offset", 0}});
  }

  reply_t manager_t::write_chunk(const std::string &client, std::string_view id, std::optional<std::uint64_t> offset, std::string_view data) {
    auto *upload = find(client, id);
    if (!upload) {
      return reply_t::failure(404, "not_found", "unknown upload");
    }
    if (!offset) {
      return reply_t::failure(400, "bad_request", "offset query parameter required");
    }
    if (*offset != upload->offset) {
      auto reply = reply_t::failure(409, "conflict", "offset does not match the upload");
      reply.extra["offset"] = upload->offset;
      return reply;
    }
    if (data.size() > options_.chunk_max) {
      return reply_t::failure(413, "too_large", "chunk exceeds chunk_max");
    }
    if (data.size() > upload->size - upload->offset) {
      return reply_t::failure(413, "too_large", "chunk exceeds the declared file size");
    }
    upload->last_activity = clock::now();
    if (data.empty()) {
      return reply_t::success(200, {{"offset", upload->offset}});
    }
    const auto available = upload->dir->free_space();
    if (!available || *available < options_.min_free_space || *available - options_.min_free_space < data.size()) {
      return reply_t::failure(507, "insufficient_space", "not enough free space on the host");
    }
    if (const auto ec = upload->file->write_at(upload->offset, std::span<const char> {data.data(), data.size()}); ec) {
      BOOST_LOG(warning) << "sds: write to a partial upload failed: "sv << ec.message();
      upload->file->truncate(upload->offset);
      return reply_t::failure(500, "internal", "write failed");
    }
    if (EVP_DigestUpdate(upload->sha.get(), data.data(), data.size()) != 1) {
      drop(std::string {id});
      return reply_t::failure(500, "internal", "hash update failed");
    }
    upload->offset += data.size();
    return reply_t::success(200, {{"offset", upload->offset}});
  }

  reply_t manager_t::complete(const std::string &client, std::string_view id) {
    auto *upload = find(client, id);
    if (!upload) {
      return reply_t::failure(404, "not_found", "unknown upload");
    }
    const std::string key {id};
    if (upload->offset != upload->size) {
      drop(key);
      return reply_t::failure(422, "mismatch", "received size does not match the declared size");
    }
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest {};
    unsigned int length = 0;
    if (EVP_DigestFinal_ex(upload->sha.get(), digest.data(), &length) != 1 || length != upload->expected_sha.size()) {
      drop(key);
      return reply_t::failure(500, "internal", "hash finalization failed");
    }
    if (!std::equal(upload->expected_sha.begin(), upload->expected_sha.end(), digest.begin())) {
      drop(key);
      return reply_t::failure(422, "mismatch", "sha256 does not match");
    }
    if (const auto ec = upload->dir->verify(); ec) {
      BOOST_LOG(warning) << "sds: inbox changed during an upload: "sv << ec.message();
      drop(key);
      return reply_t::failure(500, "internal", "inbox directory changed");
    }
    if (!upload->dir->same_file(upload->part_name, *upload->file) || !upload->file->is_regular_non_executable()) {
      BOOST_LOG(warning) << "sds: partial upload was replaced on disk; discarding"sv;
      drop(key);
      return reply_t::failure(500, "internal", "partial upload was modified");
    }
    if (const auto ec = upload->file->sync(); ec) {
      BOOST_LOG(warning) << "sds: fsync of an upload failed: "sv << ec.message();
      drop(key);
      return reply_t::failure(500, "internal", "could not flush the file");
    }

    std::optional<std::string> final_name;
    for (unsigned n = 0; n <= COLLISION_MAX && !final_name; ++n) {
      auto candidate = n == 0 ? upload->name : collision_name(upload->name, n);
      switch (upload->dir->rename_noreplace(upload->part_name, candidate)) {
        case fs::rename_result_e::ok:
          final_name = std::move(candidate);
          break;
        case fs::rename_result_e::exists:
          break;
        case fs::rename_result_e::error:
          drop(key);
          return reply_t::failure(500, "internal", "could not store the file");
      }
    }
    if (!final_name) {
      drop(key);
      return reply_t::failure(409, "conflict", "no free file name");
    }
    if (const auto ec = upload->dir->mark_from_internet(*final_name); ec) {
      BOOST_LOG(warning) << "sds: could not mark a received file as downloaded: "sv << ec.message();
    }
    const auto size = upload->size;
    // The part name is gone now; forget the session without deleting anything.
    upload->part_name.clear();
    upload->dir.reset();
    drop(key);
    BOOST_LOG(info) << "sds: received a file ("sv << size << " bytes)"sv;
    return reply_t::success(201, {{"name", *final_name}, {"size", size}});
  }

  reply_t manager_t::cancel(const std::string &client, std::string_view id) {
    if (!find(client, id)) {
      return reply_t::failure(404, "not_found", "unknown upload");
    }
    drop(std::string {id});
    reply_t reply;
    reply.status = 204;
    return reply;
  }

  void manager_t::expire_idle(clock::time_point now) {
    std::vector<std::string> expired;
    for (const auto &[id, upload] : uploads_) {
      if (now - upload.last_activity >= options_.idle_timeout) {
        expired.push_back(id);
      }
    }
    for (const auto &id : expired) {
      BOOST_LOG(debug) << "sds: upload "sv << id << " expired"sv;
      drop(id);
    }
  }

  void manager_t::end_client(const std::string &client) {
    std::vector<std::string> owned;
    for (const auto &[id, upload] : uploads_) {
      if (upload.owner == client) {
        owned.push_back(id);
      }
    }
    for (const auto &id : owned) {
      drop(id);
    }
  }

  void manager_t::shutdown() {
    while (!uploads_.empty()) {
      drop(uploads_.begin()->first);
    }
    outbox_.clear();
    outbox_baseline_.reset();
  }

  std::string manager_t::outbox_id(const fs::entry_t &entry) const {
    std::string message = entry.name;
    message.push_back('\0');
    message += std::to_string(entry.size);
    message.push_back('\0');
    message += std::to_string(entry.mtime_ns);
    message.push_back('\0');
    message += std::to_string(entry.file_id);
    message.push_back('\0');
    message += std::to_string(entry.device);
    std::array<unsigned char, EVP_MAX_MD_SIZE> mac {};
    unsigned int length = 0;
    HMAC(EVP_sha256(), id_key_.data(), static_cast<int>(id_key_.size()), reinterpret_cast<const unsigned char *>(message.data()), message.size(), mac.data(), &length);
    return to_hex(mac.data(), 16);
  }

  std::error_code manager_t::refresh_outbox(std::unique_ptr<fs::directory_t> &out) {
    if (const auto ec = fs::open_directory(outbox_dir(), true, out); ec) {
      return ec;
    }
    std::vector<fs::entry_t> entries;
    if (const auto ec = out->list_regular_files(entries); ec) {
      return ec;
    }
    std::ranges::sort(entries, {}, &fs::entry_t::name);
    if (entries.size() > OUTBOX_LIST_MAX) {
      entries.resize(OUTBOX_LIST_MAX);
    }
    std::map<std::string, outbox_entry_t, std::less<>> fresh;
    for (auto &entry : entries) {
      auto id = outbox_id(entry);
      outbox_entry_t value {std::move(entry), std::nullopt};
      if (const auto previous = outbox_.find(id); previous != outbox_.end()) {
        value.sha256 = previous->second.sha256;
      }
      fresh.emplace(std::move(id), std::move(value));
    }
    outbox_ = std::move(fresh);
    return {};
  }

  std::string manager_t::outbox_signature() const {
    std::string signature;
    for (const auto &[id, _] : outbox_) {
      signature += id;
    }
    return signature;
  }

  reply_t manager_t::list_outbox() {
    std::unique_ptr<fs::directory_t> dir;
    if (const auto ec = refresh_outbox(dir); ec) {
      BOOST_LOG(warning) << "sds: outbox "sv << outbox_dir().string() << " refused: "sv << ec.message();
      return reply_t::failure(500, "internal", "outbox directory unavailable");
    }
    std::vector<std::pair<std::string, const outbox_entry_t *>> sorted;
    for (const auto &[id, value] : outbox_) {
      sorted.emplace_back(id, &value);
    }
    std::ranges::sort(sorted, {}, [](const auto &item) {
      return item.second->entry.name;
    });
    nlohmann::json files = nlohmann::json::array();
    for (const auto &[id, value] : sorted) {
      files.push_back({
        {"id", id},
        {"name", value->entry.name},
        {"size", value->entry.size},
        {"mtime", value->entry.mtime_ns / 1'000'000'000},
      });
    }
    return reply_t::success(200, {{"files", std::move(files)}});
  }

  reply_t manager_t::read_outbox(std::string_view id, std::uint64_t offset, std::optional<std::uint64_t> length) {
    std::unique_ptr<fs::directory_t> dir;
    auto it = outbox_.find(id);
    if (it == outbox_.end()) {
      if (refresh_outbox(dir)) {
        return reply_t::failure(404, "not_found", "unknown outbox file");
      }
      it = outbox_.find(id);
      if (it == outbox_.end()) {
        return reply_t::failure(404, "not_found", "unknown outbox file");
      }
    } else if (const auto ec = fs::open_directory(outbox_dir(), false, dir); ec) {
      return reply_t::failure(404, "not_found", "outbox unavailable");
    }

    auto &cached = it->second;
    std::unique_ptr<fs::file_t> file;
    if (dir->open_read(cached.entry.name, file)) {
      return reply_t::failure(404, "not_found", "outbox file no longer available");
    }
    fs::entry_t current;
    if (file->stat(current) || current.size != cached.entry.size || current.mtime_ns != cached.entry.mtime_ns || current.file_id != cached.entry.file_id || current.device != cached.entry.device) {
      return reply_t::failure(404, "not_found", "outbox file changed");
    }
    if (offset > current.size) {
      return reply_t::failure(400, "bad_request", "offset beyond end of file");
    }
    const auto want = std::min<std::uint64_t>(length.value_or(options_.chunk_max), current.size - offset);
    if (want > options_.chunk_max) {
      return reply_t::failure(413, "too_large", "requested range exceeds chunk_max");
    }

    reply_t reply;
    reply.status = 200;
    reply.content_type = "application/octet-stream";
    reply.body.resize(static_cast<std::size_t>(want));
    std::size_t read = 0;
    if (want > 0 && (file->read_at(offset, std::span<char> {reply.body.data(), reply.body.size()}, read) || read != want)) {
      return reply_t::failure(500, "internal", "read failed");
    }
    reply.headers.emplace_back("X-SDS-File-Size", std::to_string(current.size));
    if (offset == 0) {
      if (!cached.sha256) {
        cached.sha256 = hash_file(*file, current.size);
      }
      if (!cached.sha256) {
        return reply_t::failure(500, "internal", "hashing failed");
      }
      reply.headers.emplace_back("X-SDS-File-Sha256", *cached.sha256);
    }
    return reply;
  }

  std::optional<std::size_t> manager_t::scan_outbox_changes() {
    std::unique_ptr<fs::directory_t> dir;
    if (refresh_outbox(dir)) {
      return std::nullopt;
    }
    auto signature = outbox_signature();
    if (outbox_baseline_ && *outbox_baseline_ == signature) {
      return std::nullopt;
    }
    const bool first = !outbox_baseline_.has_value();
    outbox_baseline_ = std::move(signature);
    if (first) {
      return std::nullopt;
    }
    return outbox_.size();
  }

  void manager_t::reset_outbox_baseline() {
    std::unique_ptr<fs::directory_t> dir;
    if (refresh_outbox(dir)) {
      outbox_baseline_.reset();
      return;
    }
    outbox_baseline_ = outbox_signature();
  }
}  // namespace sds::files
