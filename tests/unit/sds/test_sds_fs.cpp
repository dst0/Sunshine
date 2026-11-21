/**
 * @file tests/unit/sds/test_sds_fs.cpp
 * @brief Test the inbox/outbox file primitives (DESIGN 6.1; check S8).
 */

// test includes
#include "../../tests_common.h"
#include "sds_test_utils.h"

// standard includes
#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <optional>
#include <string>

#ifndef _WIN32
  // platform includes
  #include <sys/stat.h>
#endif

// local includes
#include <src/sds/fs.h>

namespace fs = std::filesystem;

#ifndef _WIN32
TEST(SdsXdgUserDirsTest, ParsesDownloadDirectory) {
  const fs::path home {"/home/alice"};
  EXPECT_EQ(sds::fs::parse_xdg_download_dir("XDG_DOWNLOAD_DIR=\"$HOME/Downloads\"\n", home), fs::path {"/home/alice/Downloads"});
  EXPECT_EQ(sds::fs::parse_xdg_download_dir("# comment\nXDG_DESKTOP_DIR=\"$HOME/Desktop\"\n  XDG_DOWNLOAD_DIR=\"$HOME/Téléchargements\"\r\n", home), fs::path {"/home/alice/Téléchargements"});
  EXPECT_EQ(sds::fs::parse_xdg_download_dir("XDG_DOWNLOAD_DIR=\"/data/dl\"", home), fs::path {"/data/dl"});
  EXPECT_EQ(sds::fs::parse_xdg_download_dir("XDG_DOWNLOAD_DIR=$HOME/dl", home), fs::path {"/home/alice/dl"});
  EXPECT_FALSE(sds::fs::parse_xdg_download_dir("XDG_DOWNLOAD_DIR=\"$HOME/\"", home).has_value()) << "$HOME means disabled";
  EXPECT_FALSE(sds::fs::parse_xdg_download_dir("XDG_DOWNLOAD_DIR=\"$HOME\"", home).has_value());
  EXPECT_FALSE(sds::fs::parse_xdg_download_dir("XDG_DOWNLOAD_DIR=\"relative/dl\"", home).has_value());
  EXPECT_FALSE(sds::fs::parse_xdg_download_dir("XDG_DOWNLOAD_DIR=\"$HOME/x\"", fs::path {}).has_value());
  EXPECT_FALSE(sds::fs::parse_xdg_download_dir("#XDG_DOWNLOAD_DIR=\"/x\"", home).has_value());
  EXPECT_FALSE(sds::fs::parse_xdg_download_dir("", home).has_value());
}

namespace {
  /**
   * @brief Set an environment variable for the lifetime of the object.
   */
  class scoped_env_t {
  public:
    /**
     * @brief Set or unset a variable.
     *
     * @param name Variable.
     * @param value New value, or no value to unset.
     */
    scoped_env_t(const char *name, std::optional<std::string> value):
        name_(name) {
      if (const char *old = std::getenv(name)) {
        old_ = old;
      }
      if (value) {
        ::setenv(name, value->c_str(), 1);
      } else {
        ::unsetenv(name);
      }
    }

    ~scoped_env_t() {
      if (old_) {
        ::setenv(name_, old_->c_str(), 1);
      } else {
        ::unsetenv(name_);
      }
    }

    scoped_env_t(const scoped_env_t &) = delete;
    scoped_env_t &operator=(const scoped_env_t &) = delete;

  private:
    const char *name_;  ///< Variable name.
    std::optional<std::string> old_;  ///< Previous value.
  };

  /**
   * @brief Scratch directory per test.
   */
  class SdsPosixFsTest: public BaseTest {
  protected:
    void SetUp() override {
      BaseTest::SetUp();
      base = test_utils::sds::scratch_dir("sds_fs");
    }

    void TearDown() override {
      std::error_code ec;
      fs::remove_all(base, ec);
      BaseTest::TearDown();
    }

    fs::path base;  ///< Scratch root.
  };
}  // namespace

TEST_F(SdsPosixFsTest, UserDownloadDirFollowsXdgConfiguration) {
  const auto home = base / "home";
  fs::create_directories(home / ".config");
  scoped_env_t home_env {"HOME", home.string()};
  scoped_env_t xdg_env {"XDG_DOWNLOAD_DIR", std::nullopt};
  scoped_env_t config_env {"XDG_CONFIG_HOME", std::nullopt};
  EXPECT_EQ(sds::fs::user_download_dir(), home / "Downloads");

  test_utils::sds::write_file(home / ".config" / "user-dirs.dirs", "XDG_DOWNLOAD_DIR=\"$HOME/Загрузки\"\n");
  EXPECT_EQ(sds::fs::user_download_dir(), home / "Загрузки");

  const auto config = base / "config";
  fs::create_directories(config);
  test_utils::sds::write_file(config / "user-dirs.dirs", "XDG_DOWNLOAD_DIR=\"/srv/downloads\"\n");
  {
    scoped_env_t custom_config {"XDG_CONFIG_HOME", config.string()};
    EXPECT_EQ(sds::fs::user_download_dir(), fs::path {"/srv/downloads"});
  }
  {
    scoped_env_t direct {"XDG_DOWNLOAD_DIR", "/direct/dl"};
    EXPECT_EQ(sds::fs::user_download_dir(), fs::path {"/direct/dl"});
  }
}

TEST_F(SdsPosixFsTest, OpenDirectoryCreatesAndVerifies) {
  std::unique_ptr<sds::fs::directory_t> dir;
  EXPECT_EQ(sds::fs::open_directory("relative/path", true, dir), std::errc::invalid_argument);
  EXPECT_EQ(sds::fs::open_directory("", true, dir), std::errc::invalid_argument);
  EXPECT_TRUE(sds::fs::open_directory(base / "missing", false, dir));

  const auto nested = base / "a" / "b" / "c";
  ASSERT_FALSE(sds::fs::open_directory(nested, true, dir));
  ASSERT_TRUE(dir);
  EXPECT_EQ(dir->path(), nested);
  EXPECT_FALSE(dir->verify());
  struct stat st {};
  ASSERT_EQ(::stat(nested.c_str(), &st), 0);
  EXPECT_EQ(st.st_mode & 077, 0);
  EXPECT_TRUE(dir->free_space().has_value());

  test_utils::sds::write_file(base / "file", "x");
  EXPECT_TRUE(sds::fs::open_directory(base / "file", false, dir));
  EXPECT_TRUE(sds::fs::open_directory(base / "file" / "sub", true, dir)) << "a file in the path cannot become a directory";

  fs::create_symlink(nested, base / "link");
  EXPECT_TRUE(sds::fs::open_directory(base / "link", false, dir)) << "a symlinked final component is refused";
  EXPECT_TRUE(sds::fs::open_directory(base / "link", true, dir));
}

TEST_F(SdsPosixFsTest, VerifyDetectsReplacedDirectory) {
  const auto path = base / "inbox";
  std::unique_ptr<sds::fs::directory_t> dir;
  ASSERT_FALSE(sds::fs::open_directory(path, true, dir));
  fs::rename(path, base / "moved");
  EXPECT_TRUE(dir->verify());
  fs::create_symlink(base / "moved", path);
  EXPECT_EQ(dir->verify(), std::errc::too_many_symbolic_link_levels);
  fs::remove(path);
  fs::create_directories(path);
  EXPECT_TRUE(dir->verify()) << "a different directory at the same path is not the verified one";
}

TEST_F(SdsPosixFsTest, FilePrimitivesNeverFollowSymlinks) {
  std::unique_ptr<sds::fs::directory_t> dir;
  ASSERT_FALSE(sds::fs::open_directory(base / "d", true, dir));
  const auto victim = base / "victim";
  test_utils::sds::write_file(victim, "keep");
  fs::create_symlink(victim, base / "d" / "trap");

  std::unique_ptr<sds::fs::file_t> file;
  EXPECT_EQ(dir->create_exclusive("trap", file), std::errc::file_exists);
  EXPECT_TRUE(dir->open_read("trap", file));
  EXPECT_EQ(test_utils::sds::read_file(victim), "keep");
  for (const auto *bad : {"", ".", "..", "a/b"}) {
    EXPECT_EQ(dir->create_exclusive(bad, file), std::errc::invalid_argument);
    EXPECT_EQ(dir->open_read(bad, file), std::errc::invalid_argument);
    EXPECT_EQ(dir->remove(bad), std::errc::invalid_argument);
    EXPECT_EQ(dir->rename_noreplace(bad, "x"), sds::fs::rename_result_e::error);
  }

  ASSERT_FALSE(dir->create_exclusive("new", file));
  EXPECT_FALSE(file->write_at(0, std::span<const char> {"hello", 5}));
  EXPECT_FALSE(file->write_at(5, std::span<const char> {" world", 6}));
  EXPECT_FALSE(file->sync());
  EXPECT_TRUE(file->is_regular_non_executable());
  sds::fs::entry_t entry;
  ASSERT_FALSE(file->stat(entry));
  EXPECT_EQ(entry.size, 11u);
  EXPECT_FALSE(file->truncate(5));
  ASSERT_FALSE(file->stat(entry));
  EXPECT_EQ(entry.size, 5u);
  EXPECT_TRUE(dir->same_file("new", *file));
  EXPECT_FALSE(dir->same_file("trap", *file));
  EXPECT_FALSE(dir->same_file("..", *file));
  EXPECT_EQ(dir->create_exclusive("new", file), std::errc::file_exists);

  std::unique_ptr<sds::fs::file_t> reader;
  ASSERT_FALSE(dir->open_read("new", reader));
  std::string buffer(10, '\0');
  std::size_t read = 0;
  ASSERT_FALSE(reader->read_at(1, std::span<char> {buffer.data(), buffer.size()}, read));
  EXPECT_EQ(read, 4u);
  EXPECT_EQ(buffer.substr(0, read), "ello");

  fs::create_directories(base / "d" / "sub");
  EXPECT_TRUE(dir->open_read("sub", reader)) << "directories are not readable as files";

  EXPECT_EQ(dir->rename_noreplace("new", "trap"), sds::fs::rename_result_e::exists);
  EXPECT_EQ(dir->rename_noreplace("new", "renamed"), sds::fs::rename_result_e::ok);
  EXPECT_EQ(dir->rename_noreplace("missing", "other"), sds::fs::rename_result_e::error);
  EXPECT_FALSE(dir->remove("trap"));
  EXPECT_TRUE(fs::exists(victim)) << "removing a link never removes its target";
  EXPECT_TRUE(dir->remove("trap"));
  EXPECT_FALSE(dir->mark_from_internet("renamed"));

  std::vector<std::string> names;
  ASSERT_FALSE(dir->list_names(names));
  std::ranges::sort(names);
  EXPECT_EQ(names, (std::vector<std::string> {"renamed", "sub"}));
  std::vector<sds::fs::entry_t> entries;
  ASSERT_FALSE(dir->list_regular_files(entries));
  ASSERT_EQ(entries.size(), 1u);
  EXPECT_EQ(entries[0].name, "renamed");
  ASSERT_FALSE(dir->list_regular_files(entries)) << "listing twice starts from the beginning again";
  EXPECT_EQ(entries.size(), 1u);
}

TEST_F(SdsPosixFsTest, ExecutableFilesAreDetected) {
  std::unique_ptr<sds::fs::directory_t> dir;
  ASSERT_FALSE(sds::fs::open_directory(base / "d", true, dir));
  std::unique_ptr<sds::fs::file_t> file;
  ASSERT_FALSE(dir->create_exclusive("tool", file));
  ASSERT_EQ(::chmod((base / "d" / "tool").c_str(), 0700), 0);
  EXPECT_FALSE(file->is_regular_non_executable());
}
#endif
