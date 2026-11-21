/**
 * @file tests/unit/sds/test_sds_nvhttp_permissions.cpp
 * @brief Test per-client sds permissions in the nvhttp paired-client store.
 */

// test includes
#include "../../certificate_test_utils.h"
#include "../../tests_common.h"
#include "sds_test_utils.h"

// standard includes
#include <filesystem>
#include <future>
#include <string>
#include <vector>

// lib includes
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

// local includes
#include <src/config.h>
#include <src/nvhttp.h>
#include <src/sds/sds.h>

namespace fs = std::filesystem;
namespace pt = boost::property_tree;

namespace {
  /**
   * @brief Isolated paired-client state.
   */
  class SdsNvhttpPermissionsTest: public BaseTest {
  protected:
    void SetUp() override {
      BaseTest::SetUp();
      base = test_utils::sds::scratch_dir("sds_nvhttp");
      saved_state_file = config::nvhttp.file_state;
      saved_fresh_state = config::sunshine.flags[config::flag::FRESH_STATE];
      saved_defaults = config::sds.default_permissions;
      config::nvhttp.file_state = (base / "state.json").string();
      config::sunshine.flags[config::flag::FRESH_STATE] = false;
      config::sds.default_permissions.clear();
      nvhttp::test_support::reset_client_state();
    }

    void TearDown() override {
      nvhttp::test_support::reset_client_state();
      config::nvhttp.file_state = saved_state_file;
      config::sunshine.flags[config::flag::FRESH_STATE] = saved_fresh_state;
      config::sds.default_permissions = saved_defaults;
      std::error_code ec;
      fs::remove_all(base, ec);
      BaseTest::TearDown();
    }

    /**
     * @brief Permissions reported by get_all_clients() for a UUID.
     *
     * @param uuid Client UUID.
     * @return Permission names.
     */
    static std::vector<std::string> listed_permissions(const std::string &uuid) {
      for (const auto &client : nvhttp::get_all_clients()) {
        if (client["uuid"] == uuid) {
          return client["permissions"].get<std::vector<std::string>>();
        }
      }
      return {"<missing>"};
    }

    fs::path base;  ///< Scratch root.
    std::string saved_state_file;  ///< Restored after the test.
    bool saved_fresh_state = false;  ///< Restored after the test.
    std::vector<std::string> saved_defaults;  ///< Restored after the test.
  };
}  // namespace

TEST_F(SdsNvhttpPermissionsTest, NewPairingsGetConfiguredDefaults) {
  const auto plain = crypto::gen_creds("Default Client", 2048);
  const auto uuid = nvhttp::test_support::add_client("default", plain.x509, true);
  EXPECT_TRUE(listed_permissions(uuid).empty()) << "no permissions by default";

  config::sds.default_permissions = {"clipboard_read", "clipboard_write"};
  const auto other = crypto::gen_creds("Trusted Client", 2048);
  const auto trusted = nvhttp::test_support::add_client("trusted", other.x509, true);
  EXPECT_EQ(listed_permissions(trusted), (std::vector<std::string> {"clipboard_read", "clipboard_write"}));
}

TEST_F(SdsNvhttpPermissionsTest, PermissionsAreNormalizedPersistedAndReloaded) {
  const auto creds = crypto::gen_creds("Client", 2048);
  const auto uuid = nvhttp::test_support::add_client("client", creds.x509, true);
  EXPECT_TRUE(nvhttp::set_client_permissions(uuid, {"mic", "bogus", "file_upload", "mic"}));
  EXPECT_FALSE(nvhttp::set_client_permissions("no-such-uuid", {"mic"}));
  EXPECT_EQ(listed_permissions(uuid), (std::vector<std::string> {"file_upload", "mic"}));

  nvhttp::test_support::reset_client_state();
  nvhttp::test_support::reload_client_state();
  EXPECT_EQ(listed_permissions(uuid), (std::vector<std::string> {"file_upload", "mic"}));

  // An explicitly empty list stays empty even when defaults would grant something.
  config::sds.default_permissions = {"clipboard_read"};
  ASSERT_TRUE(nvhttp::set_client_permissions(uuid, {}));
  nvhttp::test_support::reset_client_state();
  nvhttp::test_support::reload_client_state();
  EXPECT_TRUE(listed_permissions(uuid).empty());
}

TEST_F(SdsNvhttpPermissionsTest, LoadIgnoresUnknownNamesAndDefaultsMissingLists) {
  const auto first = crypto::gen_creds("First", 2048);
  const auto second = crypto::gen_creds("Second", 2048);
  pt::ptree root;
  root.put("root.uniqueid", "test-unique-id");
  pt::ptree devices;
  {
    pt::ptree device;
    device.put("name", "with-list");
    device.put("cert", first.x509);
    device.put("uuid", "uuid-with-list");
    device.put("enabled", true);
    pt::ptree permissions;
    for (const auto *name : {"file_download", "root_shell", "clipboard_read"}) {
      pt::ptree entry;
      entry.put_value(name);
      permissions.push_back({"", entry});
    }
    device.add_child("permissions", permissions);
    devices.push_back({"", device});
  }
  {
    pt::ptree device;
    device.put("name", "legacy");
    device.put("cert", second.x509);
    device.put("uuid", "uuid-legacy");
    devices.push_back({"", device});
  }
  root.add_child("root.named_devices", devices);
  pt::write_json(config::nvhttp.file_state, root);

  config::sds.default_permissions = {"clipboard_write"};
  nvhttp::test_support::reload_client_state();
  EXPECT_EQ(listed_permissions("uuid-with-list"), (std::vector<std::string> {"clipboard_read", "file_download"}));
  EXPECT_EQ(listed_permissions("uuid-legacy"), (std::vector<std::string> {"clipboard_write"}));
}

TEST_F(SdsNvhttpPermissionsTest, FindEnabledClientFailsClosed) {
  const auto creds = test_utils::certificates::generate_ca_credentials("Lookup Client");
  const auto uuid = nvhttp::test_support::add_client("lookup", test_utils::certificates::to_crlf_pem(creds.x509), true);
  ASSERT_TRUE(nvhttp::set_client_permissions(uuid, {"file_upload"}));
  auto certificate = crypto::x509(creds.x509);
  const auto canonical = crypto::pem(certificate);

  auto found = nvhttp::find_enabled_client(canonical);
  ASSERT_TRUE(found);
  EXPECT_EQ(found->uuid, uuid);
  EXPECT_EQ(found->name, "lookup");
  EXPECT_EQ(found->permissions, std::vector<std::string> {"file_upload"});

  EXPECT_FALSE(nvhttp::find_enabled_client("").has_value());
  EXPECT_FALSE(nvhttp::find_enabled_client(crypto::gen_creds("Other", 2048).x509).has_value());

  EXPECT_TRUE(sds::permission_granted(canonical, sds::permission_e::file_upload));
  EXPECT_FALSE(sds::permission_granted(canonical, sds::permission_e::mic));
  EXPECT_FALSE(sds::permission_granted(canonical, sds::permission_e::count));
  EXPECT_FALSE(sds::permission_granted("unknown", sds::permission_e::file_upload));

  ASSERT_TRUE(nvhttp::set_client_enabled(uuid, false));
  EXPECT_FALSE(nvhttp::find_enabled_client(canonical).has_value());
  EXPECT_FALSE(sds::permission_granted(canonical, sds::permission_e::file_upload));
  ASSERT_TRUE(nvhttp::set_client_enabled(uuid, true));
  ASSERT_TRUE(nvhttp::test_support::duplicate_client(uuid));
  EXPECT_FALSE(nvhttp::find_enabled_client(canonical).has_value()) << "duplicate identities are ambiguous";
}

TEST_F(SdsNvhttpPermissionsTest, ModuleRunsWithProductionCollaborators) {
  const auto saved_clipboard = config::sds.clipboard;
  config::sds.clipboard = false;
  sds::prepare_clipboard_backend();  // disabled: nothing is created
  config::sds.clipboard = true;
  sds::prepare_clipboard_backend();
  sds::prepare_clipboard_backend();  // idempotent until consumed

  sds::options_t options;
  options.files.inbox = base / "inbox";
  options.files.outbox = base / "outbox";
  sds::dependencies_t deps;
  deps.observe_sessions = false;
  ASSERT_EQ(sds::start(options, deps), 0);
  EXPECT_TRUE(sds::running());
  const auto creds = crypto::gen_creds("Production Collaborators", 2048);
  const auto uuid = nvhttp::test_support::add_client("prod", creds.x509, true);
  ASSERT_TRUE(nvhttp::set_client_permissions(uuid, {"file_download"}));
  auto certificate = crypto::x509(creds.x509);

  sds::request_t request;
  request.cert_pem = crypto::pem(certificate);
  std::promise<sds::reply_t> promise;
  sds::handle(sds::op_e::outbox_list, request, [&promise](sds::reply_t reply) {
    promise.set_value(std::move(reply));
  });
  EXPECT_EQ(promise.get_future().get().status, 409) << "the real rtsp session table has no stream for this client";
  sds::stop();
  config::sds.clipboard = saved_clipboard;
}
