/**
 * @file tests/unit/platform/windows/test_sds_fs.cpp
 * @brief Real Windows ACL, retained-handle and downloaded-file security regressions.
 */

// test includes
#include "../../../tests_common.h"
#include "../../sds/sds_test_utils.h"

#ifdef _WIN32
  // standard includes
  #include <array>
  #include <filesystem>
  #include <memory>
  #include <vector>

  // platform includes
  #include <aclapi.h>
  #include <sddl.h>
  #include <windows.h>

  // local includes
  #include <src/sds/fs.h>

namespace {
  /**
   * @brief Replace a scratch object's DACL from SDDL without changing its owner.
   * @param path Scratch object.
   * @param sddl DACL description.
   * @return Win32 result.
   */
  DWORD set_dacl(const std::filesystem::path &path, const wchar_t *sddl) {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &descriptor, nullptr)) {
      return GetLastError();
    }
    PACL acl = nullptr;
    BOOL present = FALSE;
    BOOL defaulted = FALSE;
    DWORD result = ERROR_INVALID_SECURITY_DESCR;
    if (GetSecurityDescriptorDacl(descriptor, &present, &acl, &defaulted) && present) {
      result = SetNamedSecurityInfoW(const_cast<wchar_t *>(path.c_str()), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr, acl, nullptr);
    }
    LocalFree(descriptor);
    return result;
  }

  /**
   * @brief Require a protected DACL granting access only to the process user and trusted OS SIDs.
   * @param path Scratch object.
   */
  void expect_private_dacl(const std::filesystem::path &path) {
    HANDLE token = nullptr;
    ASSERT_TRUE(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token));
    std::array<unsigned char, sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE> user {};
    DWORD size = 0;
    const auto got_user = GetTokenInformation(token, TokenUser, user.data(), static_cast<DWORD>(user.size()), &size);
    CloseHandle(token);
    ASSERT_TRUE(got_user);
    const auto sid = reinterpret_cast<TOKEN_USER *>(user.data())->User.Sid;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    PACL acl = nullptr;
    ASSERT_EQ(GetNamedSecurityInfoW(const_cast<wchar_t *>(path.c_str()), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, &acl, nullptr, &descriptor), ERROR_SUCCESS);
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    EXPECT_TRUE(GetSecurityDescriptorControl(descriptor, &control, &revision));
    EXPECT_NE(control & SE_DACL_PROTECTED, 0);
    EXPECT_NE(acl, nullptr);
    if (acl) {
      EXPECT_GT(acl->AceCount, 0);
      for (DWORD index = 0; index < acl->AceCount; ++index) {
        void *raw = nullptr;
        EXPECT_TRUE(GetAce(acl, index, &raw));
        if (!raw) {
          continue;
        }
        const auto *ace = static_cast<ACCESS_ALLOWED_ACE *>(raw);
        EXPECT_EQ(ace->Header.AceType, ACCESS_ALLOWED_ACE_TYPE);
        EXPECT_EQ(ace->Header.AceFlags & INHERITED_ACE, 0);
        const auto trustee = const_cast<DWORD *>(&ace->SidStart);
        EXPECT_TRUE(EqualSid(trustee, sid) || IsWellKnownSid(trustee, WinLocalSystemSid) || IsWellKnownSid(trustee, WinBuiltinAdministratorsSid));
      }
    }
    LocalFree(descriptor);
  }

  /**
   * @brief Keep each test confined to synthetic scratch files.
   */
  class SdsWindowsFsTest: public BaseTest {
  protected:
    void SetUp() override {
      BaseTest::SetUp();
      base = test_utils::sds::scratch_dir("sds_windows_acl");
    }

    void TearDown() override {
      directory.reset();
      std::error_code ignored;
      std::filesystem::remove_all(base, ignored);
      BaseTest::TearDown();
    }

    std::filesystem::path base;  ///< Synthetic scratch directory.
    std::unique_ptr<sds::fs::directory_t> directory;  ///< Retained directory under test.
  };
}  // namespace

TEST_F(SdsWindowsFsTest, RejectsOwnedDirectoryWritableByEveryone) {
  ASSERT_EQ(set_dacl(base, L"D:P(A;OICI;FA;;;WD)"), ERROR_SUCCESS);
  EXPECT_EQ(sds::fs::open_directory(base, false, directory), std::make_error_code(std::errc::permission_denied));
  EXPECT_FALSE(directory);
}

TEST_F(SdsWindowsFsTest, RejectsNullDacl) {
  ASSERT_EQ(SetNamedSecurityInfoW(const_cast<wchar_t *>(base.c_str()), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr, nullptr, nullptr), ERROR_SUCCESS);
  EXPECT_EQ(sds::fs::open_directory(base, false, directory), std::make_error_code(std::errc::permission_denied));
}

TEST_F(SdsWindowsFsTest, NewDirectoriesAndFilesStayPrivateUnderPermissiveParent) {
  ASSERT_EQ(set_dacl(base, L"D:P(A;OICI;FA;;;WD)"), ERROR_SUCCESS);
  const auto inbox = base / "nested" / "inbox";
  ASSERT_FALSE(sds::fs::open_directory(inbox, true, directory));
  expect_private_dacl(base / "nested");
  expect_private_dacl(inbox);
  std::unique_ptr<sds::fs::file_t> file;
  ASSERT_FALSE(directory->create_exclusive("payload.part", file));
  expect_private_dacl(inbox / "payload.part");
  EXPECT_TRUE(directory->same_file("payload.part", *file));
}

TEST_F(SdsWindowsFsTest, RevalidatesDaclUnderRetainedDirectoryHandle) {
  ASSERT_FALSE(sds::fs::open_directory(base / "inbox", true, directory));
  ASSERT_FALSE(directory->verify());
  ASSERT_EQ(set_dacl(base / "inbox", L"D:P(A;OICI;FA;;;WD)"), ERROR_SUCCESS);
  EXPECT_EQ(directory->verify(), std::make_error_code(std::errc::permission_denied));
}

TEST_F(SdsWindowsFsTest, ExistingWritableByEveryoneFileCannotBeListedOrRead) {
  const auto inbox = base / "inbox";
  ASSERT_FALSE(sds::fs::open_directory(inbox, true, directory));
  std::unique_ptr<sds::fs::file_t> file;
  ASSERT_FALSE(directory->create_exclusive("unsafe.txt", file));
  ASSERT_EQ(set_dacl(inbox / "unsafe.txt", L"D:P(A;;FA;;;WD)"), ERROR_SUCCESS);
  EXPECT_FALSE(file->is_regular_non_executable()) << "a retained part must also retain safe security";
  file.reset();
  std::vector<sds::fs::entry_t> listed;
  ASSERT_FALSE(directory->list_regular_files(listed));
  EXPECT_TRUE(listed.empty());
  EXPECT_EQ(directory->open_read("unsafe.txt", file), std::make_error_code(std::errc::permission_denied));
  EXPECT_FALSE(file);
}

TEST_F(SdsWindowsFsTest, RetainedDirectoryCannotBeRenamedAndPartIdentityCannotBeSubstituted) {
  const auto inbox = base / "inbox";
  ASSERT_FALSE(sds::fs::open_directory(inbox, true, directory));
  EXPECT_FALSE(MoveFileExW(inbox.c_str(), (base / "replacement").c_str(), 0));
  EXPECT_EQ(GetLastError(), ERROR_SHARING_VIOLATION);
  std::unique_ptr<sds::fs::file_t> file;
  ASSERT_FALSE(directory->create_exclusive("payload.part", file));
  ASSERT_EQ(directory->rename_noreplace("payload.part", "original.part"), sds::fs::rename_result_e::ok);
  std::unique_ptr<sds::fs::file_t> substitute;
  ASSERT_FALSE(directory->create_exclusive("payload.part", substitute));
  EXPECT_FALSE(directory->same_file("payload.part", *file));
  EXPECT_TRUE(directory->same_file("original.part", *file));
}

TEST_F(SdsWindowsFsTest, RejectsDirectoryReparsePointWithoutTouchingTarget) {
  const auto target = base / "target";
  std::filesystem::create_directory(target);
  const auto link = base / "link";
  if (!CreateSymbolicLinkW(link.c_str(), target.c_str(), SYMBOLIC_LINK_FLAG_DIRECTORY | SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE)) {
    const auto error = GetLastError();
    ASSERT_EQ(error, ERROR_PRIVILEGE_NOT_HELD);
    GTEST_SKIP() << "Windows test account lacks symlink privilege/developer mode";
  }
  EXPECT_EQ(sds::fs::open_directory(link, false, directory), std::make_error_code(std::errc::too_many_symbolic_link_levels));
  EXPECT_TRUE(std::filesystem::is_empty(target));
}
#endif
