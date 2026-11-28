/**
 * @file src/sds/auth.cpp
 * @brief Request identity and the authorization pipeline for `/sds/v1`.
 */
// standard includes
#include <algorithm>
#include <cctype>
#include <cmath>
#include <utility>

// local includes
#include "auth.h"
#include "file_clipboard.h"

namespace sds {
  namespace {
    /**
     * @brief Which feature switch an operation depends on.
     */
    enum class feature_rule_e {
      any_feature,  ///< At least one of clipboard, files or mic.
      any_data_feature,  ///< At least one of clipboard or files (event stream).
      clipboard,  ///< Clipboard.
      files,  ///< File transfer.
      file_clipboard,  ///< The explicitly enabled native file clipboard.
      tile_refinement,  ///< Adaptive dirty-tile refinement.
      lossless_video,  ///< Bit-exact SDLL v1 lossless video mode.
    };

    /**
     * @brief Which limit step 6 applies.
     */
    enum class limit_rule_e {
      none,  ///< No rate or concurrency limit.
      clipboard_rate,  ///< Clipboard token bucket.
      upload_concurrency,  ///< Open upload sessions.
    };

    /**
     * @brief Which body/range limit step 7 applies.
     */
    enum class size_rule_e {
      small,  ///< SMALL_BODY_MAX.
      clipboard,  ///< Depends on the content type.
      chunk,  ///< `file_chunk_max` body.
      file_clipboard,  ///< Bounded native file bundle.
      range,  ///< `file_chunk_max` for the requested download length; small body.
    };

    /**
     * @brief Authorization table row.
     */
    struct rule_t {
      feature_rule_e feature;  ///< Step 3.
      std::optional<permission_e> permission;  ///< Step 5.
      limit_rule_e limit;  ///< Step 6.
      size_rule_e size;  ///< Step 7.
    };

    /**
     * @brief Look up the authorization rule of an operation.
     *
     * @param op Operation.
     * @return Rule.
     */
    rule_t rule_for(op_e op) {
      switch (op) {
        case op_e::capabilities:
          return {feature_rule_e::any_feature, std::nullopt, limit_rule_e::none, size_rule_e::small};
        case op_e::events:
          return {feature_rule_e::any_data_feature, std::nullopt, limit_rule_e::none, size_rule_e::small};
        case op_e::tile_refinement:
          return {feature_rule_e::tile_refinement, std::nullopt, limit_rule_e::none, size_rule_e::small};
        case op_e::lossless_stream:
          return {feature_rule_e::lossless_video, std::nullopt, limit_rule_e::none, size_rule_e::small};
        case op_e::clipboard_get:
          return {feature_rule_e::clipboard, permission_e::clipboard_read, limit_rule_e::clipboard_rate, size_rule_e::small};
        case op_e::clipboard_put:
          return {feature_rule_e::clipboard, permission_e::clipboard_write, limit_rule_e::clipboard_rate, size_rule_e::clipboard};
        case op_e::file_clipboard_baseline:
        case op_e::file_clipboard_get:
          return {feature_rule_e::file_clipboard, std::nullopt, limit_rule_e::clipboard_rate, size_rule_e::small};
        case op_e::file_clipboard_put:
          return {feature_rule_e::file_clipboard, std::nullopt, limit_rule_e::clipboard_rate, size_rule_e::file_clipboard};
        case op_e::upload_create:
          return {feature_rule_e::files, permission_e::file_upload, limit_rule_e::upload_concurrency, size_rule_e::small};
        case op_e::upload_chunk:
          return {feature_rule_e::files, permission_e::file_upload, limit_rule_e::none, size_rule_e::chunk};
        case op_e::upload_complete:
        case op_e::upload_cancel:
          return {feature_rule_e::files, permission_e::file_upload, limit_rule_e::none, size_rule_e::small};
        case op_e::outbox_list:
          return {feature_rule_e::files, permission_e::file_download, limit_rule_e::none, size_rule_e::small};
        case op_e::outbox_read:
          return {feature_rule_e::files, permission_e::file_download, limit_rule_e::none, size_rule_e::range};
        case op_e::clipboard_offer_put:
          return {feature_rule_e::file_clipboard, std::nullopt, limit_rule_e::clipboard_rate, size_rule_e::small};
        case op_e::clipboard_offer_entry_start:
        case op_e::clipboard_offer_complete:
        case op_e::clipboard_offer_cancel:
          return {feature_rule_e::file_clipboard, std::nullopt, limit_rule_e::none, size_rule_e::small};
        case op_e::clipboard_offer_entry_chunk:
          return {feature_rule_e::file_clipboard, std::nullopt, limit_rule_e::none, size_rule_e::chunk};
        case op_e::clipboard_offer_entry_read:
          return {feature_rule_e::file_clipboard, std::nullopt, limit_rule_e::none, size_rule_e::range};
        case op_e::drop_create:
          return {feature_rule_e::files, permission_e::file_upload, limit_rule_e::upload_concurrency, size_rule_e::small};
        case op_e::drop_chunk:
          return {feature_rule_e::files, permission_e::file_upload, limit_rule_e::none, size_rule_e::chunk};
        case op_e::drop_complete:
        case op_e::drop_cancel:
          return {feature_rule_e::files, permission_e::file_upload, limit_rule_e::none, size_rule_e::small};
      }
      return {feature_rule_e::any_feature, permission_e::count, limit_rule_e::none, size_rule_e::small};
    }

    /**
     * @brief Build a failed result.
     *
     * @param status HTTP status.
     * @param error Error code.
     * @param message Human-readable message.
     * @return Result.
     */
    auth_result_t fail(int status, std::string error, std::string message) {
      auth_result_t result;
      result.status = status;
      result.error = std::move(error);
      result.message = std::move(message);
      return result;
    }

    /**
     * @brief Evaluate the feature rule.
     *
     * @param context Dependencies.
     * @param rule Feature rule.
     * @return `true` when the feature is present.
     */
    bool feature_present(const auth_context_t &context, feature_rule_e rule) {
      const auto available = [&context](feature_e feature) {
        return context.feature_available && context.feature_available(feature);
      };
      switch (rule) {
        case feature_rule_e::any_feature:
          return available(feature_e::clipboard) || available(feature_e::files) || available(feature_e::mic);
        case feature_rule_e::any_data_feature:
          return available(feature_e::clipboard) || available(feature_e::files);
        case feature_rule_e::clipboard:
          return available(feature_e::clipboard);
        case feature_rule_e::files:
          return available(feature_e::files);
        case feature_rule_e::file_clipboard:
          return available(feature_e::clipboard) && available(feature_e::files) && available(feature_e::file_clipboard);
        case feature_rule_e::tile_refinement:
          return available(feature_e::tile_refinement);
        case feature_rule_e::lossless_video:
          return available(feature_e::lossless_video);
      }
      return false;
    }

    /**
     * @brief Compute the body limit of a request.
     *
     * @param context Limits.
     * @param request Request fields.
     * @param rule Size rule.
     * @return Maximum accepted body size.
     */
    std::size_t body_limit(const auth_context_t &context, const request_view_t &request, size_rule_e rule) {
      switch (rule) {
        case size_rule_e::file_clipboard:
          return file_clipboard::wire_max;
        case size_rule_e::clipboard:
          {
            const auto media_type = parse_content_type(request.content_type).first;
            if (media_type == "text/plain") {
              return context.clipboard_text_max;
            }
            if (media_type == "image/png") {
              return context.clipboard_image_max;
            }
            // Unsupported types are rejected by the handler with 415; cap them like the largest type.
            return std::max(context.clipboard_text_max, context.clipboard_image_max);
          }
        case size_rule_e::chunk:
          return context.chunk_max;
        case size_rule_e::small:
        case size_rule_e::range:
          return SMALL_BODY_MAX;
      }
      return SMALL_BODY_MAX;
    }

  }  // namespace

  rate_limiter_t::rate_limiter_t(double rate_per_second):
      rate_(std::max(rate_per_second, 1.0)) {
  }

  std::optional<std::uint64_t> rate_limiter_t::acquire(const std::string &key, clock::time_point now) {
    std::lock_guard lock {mutex_};
    auto [it, inserted] = buckets_.try_emplace(key, bucket_t {rate_, now});
    auto &bucket = it->second;
    if (!inserted) {
      const std::chrono::duration<double> elapsed = now - bucket.updated;
      bucket.tokens = std::min(rate_, bucket.tokens + std::max(elapsed.count(), 0.0) * rate_);
      bucket.updated = now;
    }
    if (bucket.tokens >= 1.0) {
      bucket.tokens -= 1.0;
      return std::nullopt;
    }
    const auto wait = (1.0 - bucket.tokens) / rate_;
    return std::max<std::uint64_t>(1, static_cast<std::uint64_t>(std::ceil(wait)));
  }

  void rate_limiter_t::forget(const std::string &key) {
    std::lock_guard lock {mutex_};
    buckets_.erase(key);
  }

  bool rate_limiter_t::tracked(const std::string &key) const {
    std::lock_guard lock {mutex_};
    return buckets_.contains(key);
  }

  std::pair<std::string, std::string> parse_content_type(std::string_view header) {
    const auto lower = [](std::string_view text) {
      std::string out;
      for (const char ch : text) {
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
      }
      return out;
    };
    const auto trim = [](std::string_view text) {
      const auto first = text.find_first_not_of(" \t");
      if (first == std::string_view::npos) {
        return std::string_view {};
      }
      return text.substr(first, text.find_last_not_of(" \t") - first + 1);
    };

    const auto semicolon = header.find(';');
    auto media_type = lower(trim(header.substr(0, semicolon)));
    std::string charset;
    auto params = semicolon == std::string_view::npos ? std::string_view {} : header.substr(semicolon + 1);
    while (!params.empty()) {
      const auto next = params.find(';');
      const auto param = trim(params.substr(0, next));
      params = next == std::string_view::npos ? std::string_view {} : params.substr(next + 1);
      const auto equals = param.find('=');
      if (equals == std::string_view::npos) {
        continue;
      }
      if (lower(trim(param.substr(0, equals))) == "charset") {
        auto value = trim(param.substr(equals + 1));
        if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
          value = value.substr(1, value.size() - 2);
        }
        charset = lower(value);
      }
    }
    return {std::move(media_type), std::move(charset)};
  }

  auth_result_t authorize(const auth_context_t &context, const request_view_t &request, op_e op, bool charge_limits) {
    const auto rule = rule_for(op);

    // 1. The TLS client certificate was verified by nvhttp during the handshake.
    if (!request.cert_pem || request.cert_pem->empty()) {
      return fail(401, "unauthorized", "client certificate not verified");
    }

    // 2. Certificate -> enabled paired client.
    std::optional<client_t> client;
    if (context.find_client) {
      client = context.find_client(*request.cert_pem);
    }
    if (!client) {
      return fail(401, "unauthorized", "client is not paired");
    }

    // 3. Global feature switch (and backend availability).
    if (!feature_present(context, rule.feature)) {
      auto result = fail(404, "not_found", "feature not available");
      result.client = std::move(*client);
      return result;
    }

    // 4. Active stream of this client certificate.
    if (!context.stream_active || !context.stream_active(client->cert)) {
      auto result = fail(409, "no_active_stream", "no active stream for this client");
      result.client = std::move(*client);
      return result;
    }

    // 5. Per-client permission.
    const auto allowed = [&client](permission_e permission) {
      return permission != permission_e::count && client->permissions.test(static_cast<std::size_t>(permission));
    };
    const bool can_pull = allowed(permission_e::clipboard_read) && allowed(permission_e::file_download);
    const bool can_push = allowed(permission_e::clipboard_write) && allowed(permission_e::file_upload);
    const bool needs_fc_pull = (op == op_e::file_clipboard_get || op == op_e::clipboard_offer_entry_read);
    const bool needs_fc_push = (
      op == op_e::file_clipboard_put ||
      op == op_e::clipboard_offer_put ||
      op == op_e::clipboard_offer_entry_start ||
      op == op_e::clipboard_offer_entry_chunk ||
      op == op_e::clipboard_offer_complete ||
      op == op_e::clipboard_offer_cancel
    );
    if ((rule.permission && !allowed(*rule.permission)) ||
        (needs_fc_pull && !can_pull) ||
        (needs_fc_push && !can_push) ||
        (op == op_e::file_clipboard_baseline && !can_pull && !can_push)) {
      auto result = fail(403, "forbidden", "permission not granted");
      result.client = std::move(*client);
      return result;
    }

    // 6. Rate and concurrency limits.
    if (charge_limits && rule.limit == limit_rule_e::clipboard_rate) {
      if (!context.clipboard_rate) {
        return fail(500, "internal", "rate limiter unavailable");
      }
      if (const auto wait = context.clipboard_rate->acquire(client->cert, rate_limiter_t::clock::now()); wait) {
        auto result = fail(429, "rate_limited", "too many clipboard requests");
        result.retry_after = *wait;
        result.client = std::move(*client);
        return result;
      }
    } else if (charge_limits && rule.limit == limit_rule_e::upload_concurrency) {
      const auto open = context.open_uploads ? context.open_uploads(client->cert) : 0;
      if (open >= context.uploads_max) {
        auto result = fail(429, "rate_limited", "too many concurrent uploads");
        result.retry_after = 1;
        result.client = std::move(*client);
        return result;
      }
    }

    // 7. Size limits.
    if (request.body_size > body_limit(context, request, rule.size)) {
      auto result = fail(413, "too_large", "request body too large");
      result.client = std::move(*client);
      return result;
    }
    if (rule.size == size_rule_e::range && request.range_length && *request.range_length > context.chunk_max) {
      auto result = fail(413, "too_large", "requested range exceeds chunk_max");
      result.client = std::move(*client);
      return result;
    }

    auth_result_t result;
    result.client = std::move(*client);
    return result;
  }

}  // namespace sds
