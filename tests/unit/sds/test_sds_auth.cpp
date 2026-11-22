/**
 * @file tests/unit/sds/test_sds_auth.cpp
 * @brief Test the single authorization pipeline (DESIGN 4.1; checks S2-S6 and S12) and the
 *        execution-time revalidation without a second rate/concurrency charge.
 */

// test includes
#include "../../tests_common.h"

// standard includes
#include <chrono>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <thread>
#include <vector>

// local includes
#include <src/sds/auth.h>

using namespace std::literals;

namespace {
  constexpr auto PAIRED = "paired-cert";

  /**
   * @brief Configurable fake environment for authorize().
   */
  class SdsAuthorizeTest: public BaseTest {
  protected:
    void SetUp() override {
      BaseTest::SetUp();
      sds::client_t client;
      client.cert = PAIRED;
      client.uuid = "uuid-1";
      client.name = "mac";
      clients[PAIRED] = client;
      streaming.insert(PAIRED);
      grant_all();
      rebuild();
    }

    /**
     * @brief Grant every permission to the paired client.
     */
    void grant_all() {
      clients[PAIRED].permissions.set();
    }

    /**
     * @brief (Re)build the context from the fixture fields.
     */
    void rebuild() {
      rate = std::make_unique<sds::rate_limiter_t>(rate_per_second);
      context.find_client = [this](std::string_view cert) -> std::optional<sds::client_t> {
        const auto it = clients.find(std::string {cert});
        if (it == clients.end()) {
          return std::nullopt;
        }
        return it->second;
      };
      context.feature_available = [this](sds::feature_e feature) {
        return features.contains(feature);
      };
      context.stream_active = [this](std::string_view cert) {
        return streaming.contains(std::string {cert});
      };
      context.clipboard_rate = rate.get();
      context.open_uploads = [this](std::string_view) {
        return open_uploads;
      };
      context.uploads_max = 2;
      context.clipboard_text_max = 100;
      context.clipboard_image_max = 1000;
      context.chunk_max = 500;
    }

    /**
     * @brief Authorize a request from the paired client.
     *
     * @param op Operation.
     * @param body_size Body size.
     * @param content_type Content type.
     * @return Result.
     */
    sds::auth_result_t check(sds::op_e op, std::size_t body_size = 0, std::string content_type = "") {
      sds::request_view_t request;
      request.cert_pem = PAIRED;
      request.body_size = body_size;
      request.content_type = std::move(content_type);
      return sds::authorize(context, request, op);
    }

    std::map<std::string, sds::client_t> clients;  ///< Paired clients by certificate.
    std::set<std::string> streaming;  ///< Certificates with an active stream.
    std::set<sds::feature_e> features {sds::feature_e::clipboard, sds::feature_e::files, sds::feature_e::mic};  ///< Enabled features.
    std::size_t open_uploads = 0;  ///< Reported open uploads.
    double rate_per_second = 1000;  ///< Clipboard rate.
    std::unique_ptr<sds::rate_limiter_t> rate;  ///< Limiter.
    sds::auth_context_t context;  ///< Context under test.
  };

  const std::vector<sds::op_e> ALL_OPS {
    sds::op_e::capabilities,
    sds::op_e::events,
    sds::op_e::clipboard_get,
    sds::op_e::clipboard_put,
    sds::op_e::upload_create,
    sds::op_e::upload_chunk,
    sds::op_e::upload_complete,
    sds::op_e::upload_cancel,
    sds::op_e::outbox_list,
    sds::op_e::outbox_read,
  };
}  // namespace

TEST_F(SdsAuthorizeTest, FullyAuthorizedRequestsPass) {
  for (const auto op : ALL_OPS) {
    const auto result = check(op, 0, op == sds::op_e::clipboard_put ? "text/plain" : "");
    EXPECT_TRUE(result.ok()) << static_cast<int>(op) << " -> " << result.status;
    EXPECT_EQ(result.client.uuid, "uuid-1");
  }
}

TEST_F(SdsAuthorizeTest, MissingOrUnknownCertificateIsUnauthorized) {
  for (const auto op : ALL_OPS) {
    sds::request_view_t request;
    auto result = sds::authorize(context, request, op);
    EXPECT_EQ(result.status, 401);
    EXPECT_EQ(result.error, "unauthorized");

    request.cert_pem = "";
    EXPECT_EQ(sds::authorize(context, request, op).status, 401);

    request.cert_pem = "someone-else";
    result = sds::authorize(context, request, op);
    EXPECT_EQ(result.status, 401);
  }
}

TEST_F(SdsAuthorizeTest, DisabledFeatureIsNotFound) {
  features = {sds::feature_e::files};
  for (const auto op : {sds::op_e::clipboard_get, sds::op_e::clipboard_put}) {
    const auto result = check(op);
    EXPECT_EQ(result.status, 404);
    EXPECT_EQ(result.error, "not_found");
  }
  EXPECT_TRUE(check(sds::op_e::upload_create).ok());

  features = {sds::feature_e::clipboard};
  for (const auto op : {sds::op_e::upload_create, sds::op_e::upload_chunk, sds::op_e::upload_complete, sds::op_e::upload_cancel, sds::op_e::outbox_list, sds::op_e::outbox_read}) {
    EXPECT_EQ(check(op).status, 404);
  }
  EXPECT_TRUE(check(sds::op_e::events).ok());

  features = {sds::feature_e::mic};
  EXPECT_TRUE(check(sds::op_e::capabilities).ok());
  EXPECT_EQ(check(sds::op_e::events).status, 404) << "the event stream carries only clipboard and file events";

  features.clear();
  for (const auto op : ALL_OPS) {
    EXPECT_EQ(check(op).status, 404);
  }
}

TEST_F(SdsAuthorizeTest, NoActiveStreamIsConflict) {
  streaming.clear();
  for (const auto op : ALL_OPS) {
    const auto result = check(op);
    EXPECT_EQ(result.status, 409);
    EXPECT_EQ(result.error, "no_active_stream");
  }
}

TEST_F(SdsAuthorizeTest, MissingPermissionIsForbiddenPerEndpoint) {
  const std::vector<std::pair<sds::op_e, sds::permission_e>> required {
    {sds::op_e::clipboard_get, sds::permission_e::clipboard_read},
    {sds::op_e::clipboard_put, sds::permission_e::clipboard_write},
    {sds::op_e::upload_create, sds::permission_e::file_upload},
    {sds::op_e::upload_chunk, sds::permission_e::file_upload},
    {sds::op_e::upload_complete, sds::permission_e::file_upload},
    {sds::op_e::upload_cancel, sds::permission_e::file_upload},
    {sds::op_e::outbox_list, sds::permission_e::file_download},
    {sds::op_e::outbox_read, sds::permission_e::file_download},
  };
  for (const auto &[op, permission] : required) {
    grant_all();
    clients[PAIRED].permissions.reset(static_cast<std::size_t>(permission));
    const auto result = check(op, 0, "text/plain");
    EXPECT_EQ(result.status, 403) << static_cast<int>(op);
    EXPECT_EQ(result.error, "forbidden");

    // Holding only other permissions does not help.
    clients[PAIRED].permissions.reset();
    for (std::size_t index = 0; index < static_cast<std::size_t>(sds::permission_e::count); ++index) {
      if (index != static_cast<std::size_t>(permission)) {
        clients[PAIRED].permissions.set(index);
      }
    }
    EXPECT_EQ(check(op, 0, "text/plain").status, 403);
  }

  clients[PAIRED].permissions.reset();
  EXPECT_TRUE(check(sds::op_e::capabilities).ok()) << "capabilities needs steps 1-4 only";
  EXPECT_TRUE(check(sds::op_e::events).ok());
}

TEST_F(SdsAuthorizeTest, ClipboardRateLimitAppliesToBothDirections) {
  rate_per_second = 2;
  rebuild();
  EXPECT_TRUE(check(sds::op_e::clipboard_get).ok());
  EXPECT_TRUE(check(sds::op_e::clipboard_put, 0, "text/plain").ok());
  const auto limited = check(sds::op_e::clipboard_get);
  EXPECT_EQ(limited.status, 429);
  EXPECT_EQ(limited.error, "rate_limited");
  ASSERT_TRUE(limited.retry_after.has_value());
  EXPECT_GE(*limited.retry_after, 1u);
  EXPECT_EQ(check(sds::op_e::clipboard_put, 0, "text/plain").status, 429);
  EXPECT_TRUE(check(sds::op_e::outbox_list).ok()) << "file operations do not use the clipboard bucket";
}

TEST_F(SdsAuthorizeTest, UploadConcurrencyLimit) {
  open_uploads = 2;
  const auto result = check(sds::op_e::upload_create);
  EXPECT_EQ(result.status, 429);
  EXPECT_EQ(result.retry_after, 1u);
  EXPECT_TRUE(check(sds::op_e::upload_chunk).ok()) << "existing sessions keep working";
  open_uploads = 1;
  EXPECT_TRUE(check(sds::op_e::upload_create).ok());
}

TEST_F(SdsAuthorizeTest, DeferredRevalidationKeepsLiveChecksWithoutChargingAdmissionTwice) {
  rate_per_second = 1;
  rebuild();
  ASSERT_TRUE(check(sds::op_e::clipboard_get).ok());
  sds::request_view_t request;
  request.cert_pem = PAIRED;
  EXPECT_TRUE(sds::authorize(context, request, sds::op_e::clipboard_get, false).ok());
  EXPECT_EQ(check(sds::op_e::clipboard_get).status, 429);
  open_uploads = context.uploads_max;
  EXPECT_TRUE(sds::authorize(context, request, sds::op_e::upload_create, false).ok());
  clients[PAIRED].permissions.reset();
  EXPECT_EQ(sds::authorize(context, request, sds::op_e::clipboard_get, false).status, 403);
  streaming.clear();
  EXPECT_EQ(sds::authorize(context, request, sds::op_e::clipboard_get, false).status, 409);
  clients.clear();
  EXPECT_EQ(sds::authorize(context, request, sds::op_e::clipboard_get, false).status, 401);
}

TEST_F(SdsAuthorizeTest, SizeLimitsPerOperation) {
  EXPECT_TRUE(check(sds::op_e::clipboard_put, 100, "text/plain;charset=utf-8").ok());
  EXPECT_EQ(check(sds::op_e::clipboard_put, 101, "text/plain;charset=utf-8").status, 413);
  EXPECT_TRUE(check(sds::op_e::clipboard_put, 1000, "image/png").ok());
  EXPECT_EQ(check(sds::op_e::clipboard_put, 1001, "image/png").status, 413);
  EXPECT_TRUE(check(sds::op_e::clipboard_put, 1000, "application/x-unknown").ok()) << "unsupported types get 415 from the handler";
  EXPECT_EQ(check(sds::op_e::clipboard_put, 1001, "application/x-unknown").status, 413);
  EXPECT_TRUE(check(sds::op_e::upload_chunk, 500).ok());
  const auto too_large = check(sds::op_e::upload_chunk, 501);
  EXPECT_EQ(too_large.status, 413);
  EXPECT_EQ(too_large.error, "too_large");
  EXPECT_TRUE(check(sds::op_e::upload_create, sds::SMALL_BODY_MAX).ok());
  for (const auto op : {sds::op_e::capabilities, sds::op_e::events, sds::op_e::clipboard_get, sds::op_e::upload_create, sds::op_e::upload_complete, sds::op_e::upload_cancel, sds::op_e::outbox_list, sds::op_e::outbox_read}) {
    EXPECT_EQ(check(op, sds::SMALL_BODY_MAX + 1).status, 413) << static_cast<int>(op);
  }

  sds::request_view_t range;
  range.cert_pem = PAIRED;
  range.range_length = 500;
  EXPECT_TRUE(sds::authorize(context, range, sds::op_e::outbox_read).ok());
  range.range_length = 501;
  EXPECT_EQ(sds::authorize(context, range, sds::op_e::outbox_read).status, 413);
}

TEST_F(SdsAuthorizeTest, ChecksRunInTheDesignatedOrder) {
  // 2 before 3: an unknown client never learns which features exist.
  features.clear();
  sds::request_view_t unknown;
  unknown.cert_pem = "unknown";
  EXPECT_EQ(sds::authorize(context, unknown, sds::op_e::clipboard_get).status, 401);

  // 3 before 4.
  streaming.clear();
  EXPECT_EQ(check(sds::op_e::clipboard_get).status, 404);

  // 4 before 5.
  features = {sds::feature_e::clipboard, sds::feature_e::files};
  clients[PAIRED].permissions.reset();
  EXPECT_EQ(check(sds::op_e::clipboard_get).status, 409);

  // 5 before 6: forbidden requests do not consume rate tokens.
  streaming.insert(PAIRED);
  rate_per_second = 1;
  rebuild();
  for (int i = 0; i < 5; ++i) {
    EXPECT_EQ(check(sds::op_e::clipboard_get).status, 403);
  }
  grant_all();
  EXPECT_TRUE(check(sds::op_e::clipboard_get).ok());

  // 6 before 7.
  EXPECT_EQ(check(sds::op_e::clipboard_put, 5000, "text/plain").status, 429);

  // 7 last.
  open_uploads = 0;
  EXPECT_EQ(check(sds::op_e::upload_chunk, 501).status, 413);
}

TEST_F(SdsAuthorizeTest, MissingDependenciesFailClosed) {
  sds::auth_context_t empty;
  sds::request_view_t request;
  request.cert_pem = PAIRED;
  EXPECT_EQ(sds::authorize(empty, request, sds::op_e::capabilities).status, 401);

  context.clipboard_rate = nullptr;
  EXPECT_EQ(check(sds::op_e::clipboard_get).status, 500);
  context.stream_active = nullptr;
  EXPECT_EQ(check(sds::op_e::outbox_list).status, 409);
  context.feature_available = nullptr;
  EXPECT_EQ(check(sds::op_e::outbox_list).status, 404);
}

TEST(SdsRateLimiterTest, RefillsOverTime) {
  sds::rate_limiter_t limiter {2};
  const auto start = sds::rate_limiter_t::clock::now();
  EXPECT_FALSE(limiter.acquire("A", start));
  EXPECT_FALSE(limiter.acquire("A", start));
  const auto wait = limiter.acquire("A", start);
  ASSERT_TRUE(wait.has_value());
  EXPECT_EQ(*wait, 1u);
  EXPECT_FALSE(limiter.acquire("B", start)) << "buckets are per client";
  EXPECT_FALSE(limiter.acquire("A", start + 600ms));
  EXPECT_TRUE(limiter.acquire("A", start + 600ms));
  EXPECT_FALSE(limiter.acquire("A", start + 10s));
  EXPECT_TRUE(limiter.tracked("A"));
  limiter.forget("A");
  EXPECT_FALSE(limiter.tracked("A"));

  sds::rate_limiter_t floor {0};
  EXPECT_FALSE(floor.acquire("A", start)) << "rates below one are raised to one per second";
  EXPECT_TRUE(floor.acquire("A", start));
}

TEST(SdsContentTypeTest, ParsesMediaTypeAndCharset) {
  EXPECT_EQ(sds::parse_content_type("text/plain;charset=utf-8"), std::make_pair("text/plain"s, "utf-8"s));
  EXPECT_EQ(sds::parse_content_type(" Text/Plain ; Charset=\"UTF-8\" ; x=y"), std::make_pair("text/plain"s, "utf-8"s));
  EXPECT_EQ(sds::parse_content_type("image/png"), std::make_pair("image/png"s, ""s));
  EXPECT_EQ(sds::parse_content_type(""), std::make_pair(""s, ""s));
  EXPECT_EQ(sds::parse_content_type("text/plain; novalue"), std::make_pair("text/plain"s, ""s));
}
