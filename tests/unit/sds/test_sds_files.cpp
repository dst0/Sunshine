/**
 * @file tests/unit/sds/test_sds_files.cpp
 * @brief Test the file-transfer core: uploads, resume, integrity, collisions, limits, outbox
 *        (DESIGN 6.1-6.3; checks S8, S9, S10, S11, S14).
 */

// test includes
#include "../../tests_common.h"
#include "sds_test_utils.h"

// standard includes
#include <algorithm>
#include <chrono>
#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <vector>

#ifndef _WIN32
  // platform includes
  #include <sys/stat.h>
  #include <unistd.h>
#endif

// local includes
#include <src/sds/files.h>

namespace fs = std::filesystem;
using namespace std::literals;

namespace {
  constexpr auto CLIENT_A = "client-a";
  constexpr auto CLIENT_B = "client-b";

  /**
   * @brief File manager on scratch inbox/outbox directories.
   */
  class SdsFilesTest: public BaseTest {
  protected:
    void SetUp() override {
      BaseTest::SetUp();
      base = test_utils::sds::scratch_dir("sds_files");
      options.inbox = base / "inbox";
      options.outbox = base / "outbox";
      options.file_max = 1024 * 1024;
      options.chunk_max = 64 * 1024;
      options.uploads_max = 2;
      options.min_free_space = 0;
      options.idle_timeout = 200ms;
      manager = std::make_unique<sds::files::manager_t>(options);
    }

    void TearDown() override {
      manager.reset();
      std::error_code ec;
      fs::remove_all(base, ec);
      BaseTest::TearDown();
    }

    /**
     * @brief Start an upload.
     *
     * @param client Client key.
     * @param name File name.
     * @param data Content (for size and hash).
     * @return Reply.
     */
    sds::reply_t create(const std::string &client, const std::string &name, const std::string &data) {
      const nlohmann::json body {{"name", name}, {"size", data.size()}, {"sha256", test_utils::sds::sha256_hex(data)}};
      return manager->create(client, body.dump());
    }

    /**
     * @brief Upload a whole file in chunks and complete it.
     *
     * @param client Client key.
     * @param name File name.
     * @param data Content.
     * @return Final name, or empty on failure.
     */
    std::string upload(const std::string &client, const std::string &name, const std::string &data) {
      const auto created = create(client, name, data);
      if (created.status != 201) {
        return {};
      }
      const auto id = created.json->at("id").get<std::string>();
      std::uint64_t offset = 0;
      while (offset < data.size()) {
        const auto chunk = data.substr(offset, options.chunk_max);
        const auto reply = manager->write_chunk(client, id, offset, chunk);
        if (reply.status != 200) {
          return {};
        }
        offset = reply.json->at("offset").get<std::uint64_t>();
      }
      const auto completed = manager->complete(client, id);
      return completed.status == 201 ? completed.json->at("name").get<std::string>() : std::string {};
    }

    /**
     * @brief Part file path of an upload.
     *
     * @param id Upload id.
     * @return Path.
     */
    fs::path part(const std::string &id) const {
      return options.inbox / ("." + id + ".part");
    }

    fs::path base;  ///< Scratch root.
    sds::files::options_t options;  ///< Manager options.
    std::unique_ptr<sds::files::manager_t> manager;  ///< Manager under test.
  };
}  // namespace

TEST_F(SdsFilesTest, ChunkedUploadCompletesIntoTheInbox) {
  const auto data = test_utils::sds::random_bytes(150 * 1024);
  const auto created = create(CLIENT_A, "report.pdf", data);
  ASSERT_EQ(created.status, 201);
  const auto id = created.json->at("id").get<std::string>();
  EXPECT_TRUE(sds::files::is_id(id));
  EXPECT_EQ(created.json->at("chunk_max"), options.chunk_max);
  EXPECT_EQ(created.json->at("offset"), 0);
  EXPECT_EQ(manager->open_uploads(CLIENT_A), 1u);
  ASSERT_TRUE(fs::exists(part(id)));

  std::uint64_t offset = 0;
  while (offset < data.size()) {
    const auto reply = manager->write_chunk(CLIENT_A, id, offset, data.substr(offset, options.chunk_max));
    ASSERT_EQ(reply.status, 200);
    const auto next = reply.json->at("offset").get<std::uint64_t>();
    EXPECT_EQ(next, std::min<std::uint64_t>(offset + options.chunk_max, data.size()));
    offset = next;
  }
  const auto completed = manager->complete(CLIENT_A, id);
  ASSERT_EQ(completed.status, 201);
  EXPECT_EQ(completed.json->at("name"), "report.pdf");
  EXPECT_EQ(completed.json->at("size"), data.size());
  EXPECT_EQ(test_utils::sds::read_file(options.inbox / "report.pdf"), data);
  EXPECT_FALSE(fs::exists(part(id)));
  EXPECT_EQ(manager->open_uploads(CLIENT_A), 0u);
  EXPECT_EQ(manager->complete(CLIENT_A, id).status, 404) << "a completed session is gone";
}

TEST_F(SdsFilesTest, EmptyFileUpload) {
  EXPECT_EQ(upload(CLIENT_A, "empty.txt", ""), "empty.txt");
  EXPECT_EQ(fs::file_size(options.inbox / "empty.txt"), 0u);
}

TEST_F(SdsFilesTest, ResumesAfterOffsetConflict) {
  const auto data = test_utils::sds::random_bytes(100 * 1024, 2);
  const auto created = create(CLIENT_A, "resume.bin", data);
  ASSERT_EQ(created.status, 201);
  const auto id = created.json->at("id").get<std::string>();
  ASSERT_EQ(manager->write_chunk(CLIENT_A, id, 0, data.substr(0, 40000)).status, 200);

  // The client lost the response and retries the same chunk.
  const auto conflict = manager->write_chunk(CLIENT_A, id, 0, data.substr(0, 40000));
  EXPECT_EQ(conflict.status, 409);
  EXPECT_EQ(conflict.error, "conflict");
  EXPECT_EQ(conflict.extra.at("offset"), 40000);
  EXPECT_EQ(manager->write_chunk(CLIENT_A, id, 99999, "x").extra.at("offset"), 40000);
  EXPECT_EQ(manager->write_chunk(CLIENT_A, id, std::nullopt, "x").status, 400);
  EXPECT_EQ(manager->write_chunk(CLIENT_A, id, 40000, "").json->at("offset"), 40000);

  ASSERT_EQ(manager->write_chunk(CLIENT_A, id, 40000, data.substr(40000)).status, 200);
  ASSERT_EQ(manager->complete(CLIENT_A, id).status, 201);
  EXPECT_EQ(test_utils::sds::read_file(options.inbox / "resume.bin"), data);
}

TEST_F(SdsFilesTest, IntegrityMismatchDeletesThePartFile) {
  const auto data = test_utils::sds::random_bytes(1000, 3);
  const nlohmann::json body {{"name", "bad.bin"}, {"size", data.size()}, {"sha256", test_utils::sds::sha256_hex("other")}};
  const auto created = manager->create(CLIENT_A, body.dump());
  ASSERT_EQ(created.status, 201);
  const auto id = created.json->at("id").get<std::string>();
  ASSERT_EQ(manager->write_chunk(CLIENT_A, id, 0, data).status, 200);
  const auto mismatch = manager->complete(CLIENT_A, id);
  EXPECT_EQ(mismatch.status, 422);
  EXPECT_EQ(mismatch.error, "mismatch");
  EXPECT_FALSE(fs::exists(part(id)));
  EXPECT_FALSE(fs::exists(options.inbox / "bad.bin"));
  EXPECT_EQ(manager->write_chunk(CLIENT_A, id, 1000, "x").status, 404);
  EXPECT_EQ(manager->open_uploads(CLIENT_A), 0u);

  // Completing before all bytes arrived is a size mismatch.
  const auto short_upload = create(CLIENT_A, "short.bin", data);
  const auto short_id = short_upload.json->at("id").get<std::string>();
  ASSERT_EQ(manager->write_chunk(CLIENT_A, short_id, 0, data.substr(0, 10)).status, 200);
  EXPECT_EQ(manager->complete(CLIENT_A, short_id).status, 422);
  EXPECT_FALSE(fs::exists(part(short_id)));
}

TEST_F(SdsFilesTest, ChunkLimits) {
  const auto data = test_utils::sds::random_bytes(1000, 4);
  const auto created = create(CLIENT_A, "limits.bin", data);
  const auto id = created.json->at("id").get<std::string>();
  EXPECT_EQ(manager->write_chunk(CLIENT_A, id, 0, std::string(1001, 'x')).status, 413) << "beyond the declared size";
  EXPECT_EQ(manager->write_chunk(CLIENT_A, id, 0, std::string(options.chunk_max + 1, 'x')).status, 413);
  EXPECT_EQ(manager->write_chunk(CLIENT_A, id, 0, data).status, 200);
}

TEST_F(SdsFilesTest, CreateValidatesTheRequest) {
  EXPECT_EQ(manager->create(CLIENT_A, "not json").status, 400);
  EXPECT_EQ(manager->create(CLIENT_A, "[]").status, 400);
  EXPECT_EQ(manager->create(CLIENT_A, R"({"name":"a","size":1})").status, 400);
  EXPECT_EQ(manager->create(CLIENT_A, R"({"name":5,"size":1,"sha256":"00"})").status, 400);
  EXPECT_EQ(manager->create(CLIENT_A, R"({"name":"a","size":"1","sha256":"00"})").status, 400);
  const auto sha = test_utils::sds::sha256_hex("");
  EXPECT_EQ(manager->create(CLIENT_A, nlohmann::json {{"name", "a"}, {"size", -1}, {"sha256", sha}}.dump()).status, 400);
  EXPECT_EQ(manager->create(CLIENT_A, nlohmann::json {{"name", "a"}, {"size", options.file_max + 1}, {"sha256", sha}}.dump()).status, 413);
  EXPECT_EQ(manager->create(CLIENT_A, nlohmann::json {{"name", "a"}, {"size", 1}, {"sha256", "xyz"}}.dump()).status, 400);
  EXPECT_EQ(manager->create(CLIENT_A, nlohmann::json {{"name", "a"}, {"size", 1}, {"sha256", std::string(64, 'g')}}.dump()).status, 400);
  EXPECT_EQ(manager->create(CLIENT_A, nlohmann::json {{"name", ".."}, {"size", 1}, {"sha256", sha}}.dump()).status, 400);
  EXPECT_EQ(manager->open_uploads(CLIENT_A), 0u);

  const auto upper = nlohmann::json {{"name", "../evil"}, {"size", 0}, {"sha256", "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"}};
  const auto created = manager->create(CLIENT_A, upper.dump());
  ASSERT_EQ(created.status, 201) << "uppercase digests are accepted";
  const auto completed = manager->complete(CLIENT_A, created.json->at("id").get<std::string>());
  ASSERT_EQ(completed.status, 201);
  EXPECT_EQ(completed.json->at("name"), "_._evil");
  EXPECT_TRUE(fs::exists(options.inbox / "_._evil"));
  EXPECT_FALSE(fs::exists(base / "evil"));
}

TEST_F(SdsFilesTest, NeverOverwritesExistingFiles) {
  fs::create_directories(options.inbox);
  test_utils::sds::write_file(options.inbox / "report.pdf", "original");
  test_utils::sds::write_file(options.inbox / "report (1).pdf", "first copy");
  EXPECT_EQ(upload(CLIENT_A, "report.pdf", "new"), "report (2).pdf");
  EXPECT_EQ(test_utils::sds::read_file(options.inbox / "report.pdf"), "original");
  EXPECT_EQ(test_utils::sds::read_file(options.inbox / "report (1).pdf"), "first copy");
  EXPECT_EQ(test_utils::sds::read_file(options.inbox / "report (2).pdf"), "new");
  EXPECT_EQ(upload(CLIENT_A, "report.pdf", "newer"), "report (3).pdf");

  fs::create_directories(options.inbox / "folder");
  EXPECT_EQ(upload(CLIENT_A, "folder", "data"), "folder (1)") << "a directory with the same name is not replaced";
}

TEST_F(SdsFilesTest, CollisionSpaceExhaustedIsConflict) {
  fs::create_directories(options.inbox);
  test_utils::sds::write_file(options.inbox / "x", "");
  for (unsigned n = 1; n <= sds::files::COLLISION_MAX; ++n) {
    test_utils::sds::write_file(options.inbox / sds::files::collision_name("x", n), "");
  }
  const auto created = create(CLIENT_A, "x", "");
  ASSERT_EQ(created.status, 201);
  const auto id = created.json->at("id").get<std::string>();
  const auto completed = manager->complete(CLIENT_A, id);
  EXPECT_EQ(completed.status, 409);
  EXPECT_FALSE(fs::exists(part(id)));
}

TEST_F(SdsFilesTest, ConcurrencyLimitIsPerClient) {
  const auto first = create(CLIENT_A, "1", "a");
  const auto second = create(CLIENT_A, "2", "b");
  ASSERT_EQ(first.status, 201);
  ASSERT_EQ(second.status, 201);
  const auto third = create(CLIENT_A, "3", "c");
  EXPECT_EQ(third.status, 429);
  ASSERT_FALSE(third.headers.empty());
  EXPECT_EQ(third.headers.front().first, "Retry-After");
  EXPECT_EQ(create(CLIENT_B, "4", "d").status, 201);
  EXPECT_EQ(manager->total_uploads(), 3u);

  EXPECT_EQ(manager->cancel(CLIENT_A, first.json->at("id").get<std::string>()).status, 204);
  EXPECT_EQ(create(CLIENT_A, "3", "c").status, 201);
}

TEST_F(SdsFilesTest, UploadSessionsAreNotUsableByOtherClients) {
  const auto data = test_utils::sds::random_bytes(100, 5);
  const auto created = create(CLIENT_A, "private.bin", data);
  const auto id = created.json->at("id").get<std::string>();
  EXPECT_EQ(manager->write_chunk(CLIENT_B, id, 0, data).status, 404);
  EXPECT_EQ(manager->complete(CLIENT_B, id).status, 404);
  EXPECT_EQ(manager->cancel(CLIENT_B, id).status, 404);
  EXPECT_TRUE(fs::exists(part(id)));
  ASSERT_EQ(manager->write_chunk(CLIENT_A, id, 0, data).status, 200);
  EXPECT_EQ(manager->complete(CLIENT_A, id).status, 201);
}

TEST_F(SdsFilesTest, CancelExpiryAndClientCleanupDeletePartFiles) {
  const auto a = create(CLIENT_A, "a", "aaa").json->at("id").get<std::string>();
  EXPECT_EQ(manager->cancel(CLIENT_A, a).status, 204);
  EXPECT_FALSE(fs::exists(part(a)));
  EXPECT_EQ(manager->cancel(CLIENT_A, a).status, 404);
  EXPECT_EQ(manager->cancel(CLIENT_A, "00000000000000000000000000000000").status, 404);

  const auto idle = create(CLIENT_A, "idle", "iii").json->at("id").get<std::string>();
  manager->expire_idle(sds::files::manager_t::clock::now());
  EXPECT_TRUE(fs::exists(part(idle)));
  manager->expire_idle(sds::files::manager_t::clock::now() + options.idle_timeout);
  EXPECT_FALSE(fs::exists(part(idle)));
  EXPECT_EQ(manager->open_uploads(CLIENT_A), 0u);

  const auto mine = create(CLIENT_A, "mine", "m").json->at("id").get<std::string>();
  const auto theirs = create(CLIENT_B, "theirs", "t").json->at("id").get<std::string>();
  manager->end_client(CLIENT_A);
  EXPECT_FALSE(fs::exists(part(mine)));
  EXPECT_TRUE(fs::exists(part(theirs)));
  EXPECT_EQ(manager->open_uploads(CLIENT_B), 1u);
  manager->shutdown();
  EXPECT_FALSE(fs::exists(part(theirs)));
  EXPECT_EQ(manager->total_uploads(), 0u);
}

TEST_F(SdsFilesTest, StalePartFilesFromAPreviousRunAreRemoved) {
  fs::create_directories(options.inbox);
  const auto stale = options.inbox / ".0123456789abcdef0123456789abcdef.part";
  test_utils::sds::write_file(stale, "stale");
  test_utils::sds::write_file(options.inbox / ".hidden", "keep");
  test_utils::sds::write_file(options.inbox / ".0123.part", "keep");
  ASSERT_EQ(create(CLIENT_A, "f", "x").status, 201);
  EXPECT_FALSE(fs::exists(stale));
  EXPECT_TRUE(fs::exists(options.inbox / ".hidden"));
  EXPECT_TRUE(fs::exists(options.inbox / ".0123.part"));
}

TEST_F(SdsFilesTest, DiskSpaceFloorAndPerFileMaximum) {
  options.min_free_space = 1ull << 60;
  manager = std::make_unique<sds::files::manager_t>(options);
  const auto refused = create(CLIENT_A, "f", "x");
  EXPECT_EQ(refused.status, 507);
  EXPECT_EQ(refused.error, "insufficient_space");

  options.min_free_space = 0;
  options.file_max = 1ull << 60;
  manager = std::make_unique<sds::files::manager_t>(options);
  const nlohmann::json huge {{"name", "huge"}, {"size", 1ull << 59}, {"sha256", test_utils::sds::sha256_hex("")}};
  EXPECT_EQ(manager->create(CLIENT_A, huge.dump()).status, 507) << "larger than the free space";
  EXPECT_EQ(manager->total_uploads(), 0u);
}

TEST_F(SdsFilesTest, OutboxListsOnlyRegularVisibleFiles) {
  fs::create_directories(options.outbox);
  test_utils::sds::write_file(options.outbox / "b.bin", "bbbb");
  test_utils::sds::write_file(options.outbox / "a.txt", "aa");
  test_utils::sds::write_file(options.outbox / ".secret", "hidden");
  fs::create_directories(options.outbox / "subdir");
  test_utils::sds::write_file(options.outbox / "subdir" / "nested.txt", "nested");

  const auto listing = manager->list_outbox();
  ASSERT_EQ(listing.status, 200);
  const auto &files = listing.json->at("files");
  ASSERT_EQ(files.size(), 2u);
  EXPECT_EQ(files[0]["name"], "a.txt");
  EXPECT_EQ(files[0]["size"], 2);
  EXPECT_EQ(files[1]["name"], "b.bin");
  EXPECT_TRUE(sds::files::is_id(files[0]["id"].get<std::string>()));
  EXPECT_NE(files[0]["id"], files[1]["id"]);
  EXPECT_GT(files[0]["mtime"].get<std::int64_t>(), 1600000000);

  const auto again = manager->list_outbox();
  EXPECT_EQ(again.json->at("files")[0]["id"], files[0]["id"]) << "ids are stable while the file is unchanged";

  test_utils::sds::write_file(options.outbox / "a.txt", "changed content");
  const auto changed = manager->list_outbox();
  EXPECT_NE(changed.json->at("files")[0]["id"], files[0]["id"]) << "ids change when the file changes";

  sds::files::manager_t other {options};
  EXPECT_NE(other.list_outbox().json->at("files")[0]["id"], changed.json->at("files")[0]["id"]) << "ids depend on a per-boot key";
}

TEST_F(SdsFilesTest, OutboxReadsRangesWithSizeAndHashHeaders) {
  fs::create_directories(options.outbox);
  const auto data = test_utils::sds::random_bytes(100 * 1024, 6);
  test_utils::sds::write_file(options.outbox / "photo.jpg", data);
  const auto listing = manager->list_outbox();
  const auto id = listing.json->at("files")[0]["id"].get<std::string>();

  const auto first = manager->read_outbox(id, 0, std::nullopt);
  ASSERT_EQ(first.status, 200);
  EXPECT_EQ(first.content_type, "application/octet-stream");
  EXPECT_EQ(first.body, data.substr(0, options.chunk_max));
  std::map<std::string, std::string> headers(first.headers.begin(), first.headers.end());
  EXPECT_EQ(headers["X-SDS-File-Size"], std::to_string(data.size()));
  EXPECT_EQ(headers["X-SDS-File-Sha256"], test_utils::sds::sha256_hex(data));

  const auto second = manager->read_outbox(id, options.chunk_max, 1000);
  ASSERT_EQ(second.status, 200);
  EXPECT_EQ(second.body, data.substr(options.chunk_max, 1000));
  std::map<std::string, std::string> second_headers(second.headers.begin(), second.headers.end());
  EXPECT_FALSE(second_headers.contains("X-SDS-File-Sha256")) << "the hash is sent with offset 0 only";

  EXPECT_EQ(manager->read_outbox(id, data.size(), std::nullopt).body, "");
  EXPECT_EQ(manager->read_outbox(id, data.size() + 1, std::nullopt).status, 400);
  EXPECT_EQ(manager->read_outbox(id, 0, options.chunk_max + 1).status, 413);
  EXPECT_EQ(manager->read_outbox("00000000000000000000000000000000", 0, std::nullopt).status, 404);

  // A changed file no longer matches its id.
  test_utils::sds::write_file(options.outbox / "photo.jpg", "replaced");
  EXPECT_EQ(manager->read_outbox(id, 0, std::nullopt).status, 404);

  // Unknown ids trigger a rescan, so files added since the last listing are readable.
  test_utils::sds::write_file(options.outbox / "late.txt", "late");
  sds::files::manager_t fresh {options};
  const auto fresh_listing = fresh.list_outbox();
  std::string late_id;
  for (const auto &file : fresh_listing.json->at("files")) {
    if (file["name"] == "late.txt") {
      late_id = file["id"];
    }
  }
  ASSERT_FALSE(late_id.empty());
  EXPECT_EQ(manager->read_outbox(late_id, 0, std::nullopt).status, 404) << "ids are per-boot keyed, other managers' ids are meaningless";
}

TEST_F(SdsFilesTest, OutboxChangeDetection) {
  fs::create_directories(options.outbox);
  EXPECT_FALSE(manager->scan_outbox_changes().has_value()) << "the first scan only establishes a baseline";
  EXPECT_FALSE(manager->scan_outbox_changes().has_value());
  test_utils::sds::write_file(options.outbox / "new.txt", "n");
  EXPECT_EQ(manager->scan_outbox_changes(), 1u);
  EXPECT_FALSE(manager->scan_outbox_changes().has_value());
  test_utils::sds::write_file(options.outbox / "second.txt", "s");
  manager->reset_outbox_baseline();
  EXPECT_FALSE(manager->scan_outbox_changes().has_value()) << "files present at the baseline are not announced";
  fs::remove(options.outbox / "new.txt");
  EXPECT_EQ(manager->scan_outbox_changes(), 1u);
}

TEST_F(SdsFilesTest, DefaultFoldersAreDerivedFromTheInbox) {
  options.outbox.clear();
  manager = std::make_unique<sds::files::manager_t>(options);
  ASSERT_EQ(manager->list_outbox().status, 200);
  EXPECT_TRUE(fs::is_directory(options.inbox / "Outbox"));
}

#ifndef _WIN32
TEST_F(SdsFilesTest, ReceivedFilesAndFoldersHaveRestrictiveModes) {
  const auto old_umask = ::umask(0);
  const auto name = upload(CLIENT_A, "script.sh", "#!/bin/sh\necho hi\n");
  ::umask(old_umask);
  ASSERT_EQ(name, "script.sh");
  struct stat st {};
  ASSERT_EQ(::stat((options.inbox / name).c_str(), &st), 0);
  EXPECT_EQ(st.st_mode & 0777, 0600) << "no execute bit, no group/other access";
  ASSERT_EQ(::stat(options.inbox.c_str(), &st), 0);
  EXPECT_EQ(st.st_mode & 0777, 0700);
}

TEST_F(SdsFilesTest, SymlinkedOrUnsafeFoldersAreRefused) {
  const auto real = base / "real";
  fs::create_directories(real);
  fs::create_symlink(real, options.inbox);
  const auto refused = create(CLIENT_A, "f", "x");
  EXPECT_EQ(refused.status, 500);
  EXPECT_TRUE(fs::is_empty(real)) << "nothing may be written through a symlinked inbox";

  fs::create_symlink(real, options.outbox);
  test_utils::sds::write_file(real / "leak.txt", "secret");
  EXPECT_EQ(manager->list_outbox().status, 500);

  fs::remove(options.inbox);
  fs::create_directories(options.inbox);
  fs::permissions(options.inbox, fs::perms::all, fs::perm_options::replace);
  EXPECT_EQ(create(CLIENT_A, "f", "x").status, 500) << "a world-writable inbox is refused";
  fs::permissions(options.inbox, fs::perms::owner_all, fs::perm_options::replace);
  EXPECT_EQ(create(CLIENT_A, "f", "x").status, 201);
}

TEST_F(SdsFilesTest, OutboxSymlinksAndSpecialFilesAreNeverServed) {
  fs::create_directories(options.outbox);
  const auto secret = base / "secret.txt";
  test_utils::sds::write_file(secret, "top secret");
  fs::create_symlink(secret, options.outbox / "link.txt");
  ASSERT_EQ(::mkfifo((options.outbox / "pipe").c_str(), 0600), 0);
  test_utils::sds::write_file(options.outbox / "ok.txt", "ok");

  const auto listing = manager->list_outbox();
  ASSERT_EQ(listing.status, 200);
  ASSERT_EQ(listing.json->at("files").size(), 1u);
  EXPECT_EQ(listing.json->at("files")[0]["name"], "ok.txt");

  // Swap the listed file for a symlink before it is read.
  const auto id = listing.json->at("files")[0]["id"].get<std::string>();
  fs::remove(options.outbox / "ok.txt");
  fs::create_symlink(secret, options.outbox / "ok.txt");
  const auto read = manager->read_outbox(id, 0, std::nullopt);
  EXPECT_EQ(read.status, 404);
  EXPECT_EQ(read.body.find("top secret"), std::string::npos);
}

TEST_F(SdsFilesTest, SwappedPartFileIsDiscarded) {
  const auto victim = base / "victim.txt";
  test_utils::sds::write_file(victim, "do not touch");
  const auto data = std::string("payload");
  const auto created = create(CLIENT_A, "swap.txt", data);
  const auto id = created.json->at("id").get<std::string>();
  fs::remove(part(id));
  fs::create_symlink(victim, part(id));
  ASSERT_EQ(manager->write_chunk(CLIENT_A, id, 0, data).status, 200) << "writes go to the open descriptor, not the path";
  EXPECT_EQ(manager->complete(CLIENT_A, id).status, 500);
  EXPECT_EQ(test_utils::sds::read_file(victim), "do not touch");
  EXPECT_FALSE(fs::exists(options.inbox / "swap.txt"));
  EXPECT_FALSE(fs::is_symlink(part(id)));
}

TEST_F(SdsFilesTest, ExistingSymlinkAtTheTargetNameIsNotFollowed) {
  fs::create_directories(options.inbox);
  const auto victim = base / "victim.txt";
  test_utils::sds::write_file(victim, "do not touch");
  fs::create_symlink(victim, options.inbox / "notes.txt");
  EXPECT_EQ(upload(CLIENT_A, "notes.txt", "incoming"), "notes (1).txt");
  EXPECT_EQ(test_utils::sds::read_file(victim), "do not touch");
  EXPECT_TRUE(fs::is_symlink(options.inbox / "notes.txt"));
}
#endif
