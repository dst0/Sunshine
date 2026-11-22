/**
 * @file src/sds/fs_windows.cpp
 * @brief Windows inbox/outbox primitives: CreateFileW with FILE_FLAG_OPEN_REPARSE_POINT under the
 *        session user's token, reparse-point and ACL checks, no-replace renames and MOTW.
 *
 * File system access that resolves paths runs while impersonating the active console user, so new
 * files are owned by that user with a protected private DACL. Handles opened under impersonation are
 * used afterwards without it.
 */
// standard includes
#include <algorithm>
#include <array>
#include <utility>
#include <vector>

// platform includes
// clang-format off
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <shlobj.h>
// clang-format on

// local includes
#include "fs.h"
#include "src/platform/windows/misc.h"
#include "src/platform/windows/utf_utils.h"
#include "text.h"

namespace sds::fs {
  namespace {
    constexpr std::int64_t FILETIME_UNIX_EPOCH = 116444736000000000LL;  ///< 1970-01-01 in FILETIME ticks.

    /**
     * @brief Map a Win32 error to a portable error code.
     *
     * @param error Win32 error.
     * @return Error code.
     */
    std::error_code from_win32(DWORD error) {
      switch (error) {
        case ERROR_FILE_EXISTS:
        case ERROR_ALREADY_EXISTS:
          return std::make_error_code(std::errc::file_exists);
        case ERROR_FILE_NOT_FOUND:
        case ERROR_PATH_NOT_FOUND:
          return std::make_error_code(std::errc::no_such_file_or_directory);
        case ERROR_ACCESS_DENIED:
        case ERROR_SHARING_VIOLATION:
          return std::make_error_code(std::errc::permission_denied);
        case ERROR_DISK_FULL:
          return std::make_error_code(std::errc::no_space_on_device);
        default:
          return {static_cast<int>(error), std::system_category()};
      }
    }

    /**
     * @brief Last Win32 error as an error code.
     *
     * @return Error code.
     */
    std::error_code last_error() {
      return from_win32(GetLastError());
    }

    /**
     * @brief RAII wrapper for a Win32 handle.
     */
    struct handle_t {
      HANDLE value = INVALID_HANDLE_VALUE;  ///< Owned handle.

      handle_t() = default;

      /**
       * @brief Take ownership.
       *
       * @param handle Handle.
       */
      explicit handle_t(HANDLE handle):
          value(handle) {
      }

      ~handle_t() {
        reset();
      }

      handle_t(const handle_t &) = delete;
      handle_t &operator=(const handle_t &) = delete;

      /**
       * @brief Move-construct.
       *
       * @param other Source.
       */
      handle_t(handle_t &&other) noexcept:
          value(std::exchange(other.value, INVALID_HANDLE_VALUE)) {
      }

      /**
       * @brief Close the handle.
       */
      void reset() {
        if (value != INVALID_HANDLE_VALUE && value != nullptr) {
          CloseHandle(value);
        }
        value = INVALID_HANDLE_VALUE;
      }

      /**
       * @brief Check validity.
       *
       * @return `true` when a handle is held.
       */
      [[nodiscard]] bool valid() const {
        return value != INVALID_HANDLE_VALUE && value != nullptr;
      }
    };

    /**
     * @brief Check whether the process runs as LocalSystem.
     *
     * @return `true` for the SYSTEM account.
     */
    bool running_as_system() {
      HANDLE raw = nullptr;
      if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw)) {
        return false;
      }
      handle_t token {raw};
      std::array<std::uint8_t, sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE> buffer {};
      DWORD size = 0;
      if (!GetTokenInformation(token.value, TokenUser, buffer.data(), static_cast<DWORD>(buffer.size()), &size)) {
        return false;
      }
      const auto *user = reinterpret_cast<const TOKEN_USER *>(buffer.data());
      return IsWellKnownSid(user->User.Sid, WinLocalSystemSid) != FALSE;
    }

    /**
     * @brief Run file-system work as the session user.
     *
     * Without a console user token (Sunshine started by the user, not as a service) the work runs as
     * the process user; as SYSTEM without a logged-on user it is refused.
     *
     * @param work Callable returning std::error_code.
     * @return Error from impersonation or from the work.
     */
    template<class F>
    std::error_code as_user(F &&work) {
      HANDLE raw = platf::retrieve_users_token(false);
      if (!raw) {
        if (running_as_system()) {
          return std::make_error_code(std::errc::operation_not_permitted);
        }
        return work();
      }
      handle_t token {raw};
      std::error_code inner;
      const auto ec = platf::impersonate_current_user(token.value, [&]() {
        inner = work();
      });
      return ec ? ec : inner;
    }

    /**
     * @brief SID of the user the current thread acts for (impersonated or process user).
     *
     * @param out Buffer receiving the SID.
     * @return `true` on success.
     */
    bool effective_user_sid(std::vector<std::uint8_t> &out) {
      HANDLE raw = nullptr;
      if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &raw)) {
        if (GetLastError() != ERROR_NO_TOKEN || !OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw)) {
          return false;
        }
      }
      handle_t token {raw};
      DWORD size = 0;
      GetTokenInformation(token.value, TokenUser, nullptr, 0, &size);
      std::vector<std::uint8_t> buffer(size);
      if (!size || !GetTokenInformation(token.value, TokenUser, buffer.data(), size, &size)) {
        return false;
      }
      const auto *user = reinterpret_cast<const TOKEN_USER *>(buffer.data());
      const auto length = GetLengthSid(user->User.Sid);
      out.assign(static_cast<const std::uint8_t *>(user->User.Sid), static_cast<const std::uint8_t *>(user->User.Sid) + length);
      return true;
    }

    /**
     * @brief Check whether a SID is the effective user or an explicitly trusted OS principal.
     * @param sid Trustee SID.
     * @param user Effective user SID.
     * @return Whether this principal may modify inbox/outbox objects.
     */
    bool trusted_sid(PSID sid, const std::vector<std::uint8_t> &user) {
      return sid && IsValidSid(sid) && (EqualSid(sid, const_cast<std::uint8_t *>(user.data())) || IsWellKnownSid(sid, WinLocalSystemSid) || IsWellKnownSid(sid, WinBuiltinAdministratorsSid));
    }

    /**
     * @brief Check the owner and DACL of an open object under the effective user's token.
     *
     * Deny ACEs never grant rights. Unknown granting ACE forms are rejected rather than assuming
     * that callback/object-specific conditions make them safe. Inherit-only ACEs do not apply
     * to this object; every newly created child gets its own protected DACL.
     * @param handle Object opened with READ_CONTROL.
     * @return Error when ownership or writable ACL grants cannot be proved safe.
     */
    std::error_code check_security(HANDLE handle) {
      std::vector<std::uint8_t> user;
      if (!effective_user_sid(user)) {
        return std::make_error_code(std::errc::permission_denied);
      }
      PSID owner = nullptr;
      PACL acl = nullptr;
      PSECURITY_DESCRIPTOR descriptor = nullptr;
      if (GetSecurityInfo(handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, nullptr, &acl, nullptr, &descriptor) != ERROR_SUCCESS) {
        return std::make_error_code(std::errc::permission_denied);
      }
      bool safe = trusted_sid(owner, user) && acl && IsValidAcl(acl);
      constexpr ACCESS_MASK mutation = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_WRITE | GENERIC_ALL | MAXIMUM_ALLOWED;
      for (DWORD index = 0; safe && index < acl->AceCount; ++index) {
        void *raw = nullptr;
        if (!GetAce(acl, index, &raw)) {
          safe = false;
          break;
        }
        const auto *header = static_cast<ACE_HEADER *>(raw);
        if (header->AceFlags & INHERIT_ONLY_ACE) {
          continue;
        }
        if (header->AceType == ACCESS_DENIED_ACE_TYPE || header->AceType == ACCESS_DENIED_OBJECT_ACE_TYPE || header->AceType == ACCESS_DENIED_CALLBACK_ACE_TYPE || header->AceType == ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE) {
          continue;
        }
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE || header->AceSize < sizeof(ACCESS_ALLOWED_ACE)) {
          safe = false;
          break;
        }
        const auto *ace = static_cast<ACCESS_ALLOWED_ACE *>(raw);
        if ((ace->Mask & mutation) && !trusted_sid(const_cast<DWORD *>(&ace->SidStart), user)) {
          safe = false;
        }
      }
      LocalFree(descriptor);
      return safe ? std::error_code {} : std::make_error_code(std::errc::permission_denied);
    }

    /**
     * @brief Protected creation descriptor granting full access only to user, SYSTEM and Admins.
     */
    class private_security_t {
    public:
      private_security_t() = default;
      private_security_t(const private_security_t &) = delete;
      private_security_t &operator=(const private_security_t &) = delete;

      ~private_security_t() {
        LocalFree(acl_);
      }

      /**
       * @brief Initialize under the effective user's impersonation context.
       * @param directory Whether ACEs should also inherit to children.
       * @return Error, or empty when attributes() may be used.
       */
      std::error_code initialize(bool directory) {
        if (!effective_user_sid(user_)) {
          return std::make_error_code(std::errc::permission_denied);
        }
        DWORD size = static_cast<DWORD>(system_.size());
        if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, system_.data(), &size)) {
          return last_error();
        }
        size = static_cast<DWORD>(admins_.size());
        if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, admins_.data(), &size)) {
          return last_error();
        }
        std::array<EXPLICIT_ACCESSW, 3> grants {};
        const std::array<PSID, 3> sids {user_.data(), system_.data(), admins_.data()};
        for (std::size_t i = 0; i < grants.size(); ++i) {
          grants[i].grfAccessPermissions = FILE_ALL_ACCESS;
          grants[i].grfAccessMode = SET_ACCESS;
          grants[i].grfInheritance = directory ? SUB_CONTAINERS_AND_OBJECTS_INHERIT : NO_INHERITANCE;
          BuildTrusteeWithSidW(&grants[i].Trustee, sids[i]);
        }
        const auto result = SetEntriesInAclW(static_cast<ULONG>(grants.size()), grants.data(), nullptr, &acl_);
        if (result != ERROR_SUCCESS) {
          return from_win32(result);
        }
        if (!InitializeSecurityDescriptor(&descriptor_, SECURITY_DESCRIPTOR_REVISION) || !SetSecurityDescriptorOwner(&descriptor_, user_.data(), FALSE) || !SetSecurityDescriptorDacl(&descriptor_, TRUE, acl_, FALSE) || !SetSecurityDescriptorControl(&descriptor_, SE_DACL_PROTECTED, SE_DACL_PROTECTED)) {
          return last_error();
        }
        attributes_ = {sizeof(SECURITY_ATTRIBUTES), &descriptor_, FALSE};
        return {};
      }

      /**
       * @brief Creation attributes, valid until this object is destroyed.
       * @return Non-inheritable handle attributes with protected object security.
       */
      SECURITY_ATTRIBUTES *attributes() {
        return &attributes_;
      }

    private:
      std::vector<std::uint8_t> user_;  ///< Effective user SID backing storage.
      std::array<std::uint8_t, SECURITY_MAX_SID_SIZE> system_ {};  ///< SYSTEM SID.
      std::array<std::uint8_t, SECURITY_MAX_SID_SIZE> admins_ {};  ///< Administrators SID.
      PACL acl_ = nullptr;  ///< LocalAlloc-backed explicit DACL.
      SECURITY_DESCRIPTOR descriptor_ {};  ///< Absolute creation descriptor.
      SECURITY_ATTRIBUTES attributes_ {};  ///< Creation attributes.
    };

    /**
     * @brief Check a name is one plain path component.
     *
     * @param name Candidate (UTF-8).
     * @return `true` when safe to append to a directory path.
     */
    bool plain_component(std::string_view name) {
      return !name.empty() && name != "." && name != ".." && name.find_first_of("/\\:") == std::string_view::npos && name.find('\0') == std::string_view::npos;
    }

    /**
     * @brief Convert FILETIME to nanoseconds since the Unix epoch.
     *
     * @param time FILETIME.
     * @return Nanoseconds.
     */
    std::int64_t filetime_ns(const FILETIME &time) {
      const auto ticks = (static_cast<std::int64_t>(time.dwHighDateTime) << 32) | time.dwLowDateTime;
      return (ticks - FILETIME_UNIX_EPOCH) * 100;
    }

    /**
     * @brief Fill metadata from handle information.
     *
     * @param info Handle information.
     * @param out Metadata.
     */
    void fill_entry(const BY_HANDLE_FILE_INFORMATION &info, entry_t &out) {
      out.size = (static_cast<std::uint64_t>(info.nFileSizeHigh) << 32) | info.nFileSizeLow;
      out.mtime_ns = filetime_ns(info.ftLastWriteTime);
      out.file_id = (static_cast<std::uint64_t>(info.nFileIndexHigh) << 32) | info.nFileIndexLow;
      out.device = info.dwVolumeSerialNumber;
    }

    /**
     * @brief Open Windows file.
     */
    class windows_file_t: public file_t {
    public:
      /**
       * @brief Take ownership of a handle.
       *
       * @param handle Open file handle.
       */
      explicit windows_file_t(handle_t handle):
          handle_(std::move(handle)) {
      }

      std::error_code write_at(std::uint64_t offset, std::span<const char> data) override {
        while (!data.empty()) {
          OVERLAPPED overlapped {};
          overlapped.Offset = static_cast<DWORD>(offset);
          overlapped.OffsetHigh = static_cast<DWORD>(offset >> 32);
          const auto want = static_cast<DWORD>(std::min<std::size_t>(data.size(), 1u << 30));
          DWORD written = 0;
          if (!WriteFile(handle_.value, data.data(), want, &written, &overlapped)) {
            return last_error();
          }
          if (written == 0) {
            return std::make_error_code(std::errc::io_error);
          }
          data = data.subspan(written);
          offset += written;
        }
        return {};
      }

      std::error_code read_at(std::uint64_t offset, std::span<char> buffer, std::size_t &read) override {
        read = 0;
        while (read < buffer.size()) {
          OVERLAPPED overlapped {};
          const auto position = offset + read;
          overlapped.Offset = static_cast<DWORD>(position);
          overlapped.OffsetHigh = static_cast<DWORD>(position >> 32);
          const auto want = static_cast<DWORD>(std::min<std::size_t>(buffer.size() - read, 1u << 30));
          DWORD got = 0;
          if (!ReadFile(handle_.value, buffer.data() + read, want, &got, &overlapped)) {
            const auto error = GetLastError();
            if (error == ERROR_HANDLE_EOF) {
              break;
            }
            return from_win32(error);
          }
          if (got == 0) {
            break;
          }
          read += got;
        }
        return {};
      }

      std::error_code truncate(std::uint64_t size) override {
        FILE_END_OF_FILE_INFO info {};
        info.EndOfFile.QuadPart = static_cast<LONGLONG>(size);
        return SetFileInformationByHandle(handle_.value, FileEndOfFileInfo, &info, sizeof(info)) ? std::error_code {} : last_error();
      }

      std::error_code sync() override {
        return FlushFileBuffers(handle_.value) ? std::error_code {} : last_error();
      }

      std::error_code stat(entry_t &out) override {
        BY_HANDLE_FILE_INFORMATION info {};
        if (!GetFileInformationByHandle(handle_.value, &info)) {
          return last_error();
        }
        fill_entry(info, out);
        return {};
      }

      bool is_regular_non_executable() override {
        return !as_user([&]() -> std::error_code {
          BY_HANDLE_FILE_INFORMATION info {};
          if (!GetFileInformationByHandle(handle_.value, &info) || (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DEVICE))) {
            return std::make_error_code(std::errc::invalid_argument);
          }
          return check_security(handle_.value);
        });
      }

    private:
      handle_t handle_;  ///< Owned handle.
    };

    /**
     * @brief Directory held open without FILE_SHARE_DELETE, so it cannot be renamed or replaced
     *        while in use; children are addressed by its final path.
     */
    class windows_directory_t: public directory_t {
    public:
      /**
       * @brief Take ownership of a directory handle.
       *
       * @param handle Directory handle.
       * @param requested Path as configured.
       * @param final_path Final path reported by the handle.
       */
      windows_directory_t(handle_t handle, std::filesystem::path requested, std::wstring final_path):
          handle_(std::move(handle)),
          requested_(std::move(requested)),
          final_path_(std::move(final_path)) {
      }

      /**
       * @brief Check type, reparse attribute, owner and DACL of the open directory.
       *
       * @return Error, or empty.
       */
      std::error_code check() const {
        BY_HANDLE_FILE_INFORMATION info {};
        if (!GetFileInformationByHandle(handle_.value, &info)) {
          return last_error();
        }
        if (!(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
          return std::make_error_code(std::errc::not_a_directory);
        }
        if (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
          return std::make_error_code(std::errc::too_many_symbolic_link_levels);
        }
        return check_security(handle_.value);
      }

      std::error_code verify() override {
        return as_user([this]() -> std::error_code {
          if (auto ec = check(); ec) {
            return ec;
          }
          std::wstring current(MAX_PATH, L'\0');
          auto length = GetFinalPathNameByHandleW(handle_.value, current.data(), static_cast<DWORD>(current.size()), FILE_NAME_NORMALIZED);
          if (length >= current.size()) {
            current.resize(length + 1);
            length = GetFinalPathNameByHandleW(handle_.value, current.data(), static_cast<DWORD>(current.size()), FILE_NAME_NORMALIZED);
          }
          if (length == 0) {
            return last_error();
          }
          current.resize(length);
          if (CompareStringOrdinal(current.c_str(), -1, final_path_.c_str(), -1, TRUE) != CSTR_EQUAL) {
            return std::make_error_code(std::errc::no_such_file_or_directory);
          }
          return {};
        });
      }

      [[nodiscard]] std::filesystem::path path() const override {
        return requested_;
      }

      std::error_code create_exclusive(std::string_view name, std::unique_ptr<file_t> &out) override {
        if (!plain_component(name)) {
          return std::make_error_code(std::errc::invalid_argument);
        }
        const auto path = child(name);
        return as_user([&]() -> std::error_code {
          private_security_t security;
          if (const auto ec = security.initialize(false); ec) {
            return ec;
          }
          handle_t file {CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE | DELETE, FILE_SHARE_READ | FILE_SHARE_DELETE, security.attributes(), CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
          if (!file.valid()) {
            return last_error();
          }
          if (const auto ec = check_security(file.value); ec) {
            // The filesystem must honor object ACLs; never publish a file on an unsupported FS.
            FILE_DISPOSITION_INFO remove {TRUE};
            SetFileInformationByHandle(file.value, FileDispositionInfo, &remove, sizeof(remove));
            return ec;
          }
          out = std::make_unique<windows_file_t>(std::move(file));
          return {};
        });
      }

      std::error_code open_read(std::string_view name, std::unique_ptr<file_t> &out) override {
        if (!plain_component(name)) {
          return std::make_error_code(std::errc::invalid_argument);
        }
        const auto path = child(name);
        return as_user([&]() -> std::error_code {
          handle_t file {CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr)};
          if (!file.valid()) {
            return last_error();
          }
          BY_HANDLE_FILE_INFORMATION info {};
          if (GetFileType(file.value) != FILE_TYPE_DISK || !GetFileInformationByHandle(file.value, &info) || (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DEVICE))) {
            return std::make_error_code(std::errc::invalid_argument);
          }
          if (const auto ec = check_security(file.value); ec) {
            return ec;
          }
          out = std::make_unique<windows_file_t>(std::move(file));
          return {};
        });
      }

      std::error_code remove(std::string_view name) override {
        if (!plain_component(name)) {
          return std::make_error_code(std::errc::invalid_argument);
        }
        const auto path = child(name);
        return as_user([&]() -> std::error_code {
          return DeleteFileW(path.c_str()) ? std::error_code {} : last_error();
        });
      }

      rename_result_e rename_noreplace(std::string_view from, std::string_view to) override {
        if (!plain_component(from) || !plain_component(to)) {
          return rename_result_e::error;
        }
        const auto source = child(from);
        const auto target = child(to);
        bool exists = false;
        const auto ec = as_user([&]() -> std::error_code {
          // No MOVEFILE_REPLACE_EXISTING: an existing target makes the call fail.
          if (MoveFileExW(source.c_str(), target.c_str(), MOVEFILE_WRITE_THROUGH)) {
            return {};
          }
          const auto error = GetLastError();
          exists = error == ERROR_ALREADY_EXISTS || error == ERROR_FILE_EXISTS;
          return from_win32(error);
        });
        if (!ec) {
          return rename_result_e::ok;
        }
        return exists ? rename_result_e::exists : rename_result_e::error;
      }

      bool same_file(std::string_view name, file_t &file) override {
        if (!plain_component(name)) {
          return false;
        }
        const auto path = child(name);
        entry_t by_name;
        const auto ec = as_user([&]() -> std::error_code {
          handle_t probe {CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
          if (!probe.valid()) {
            return last_error();
          }
          BY_HANDLE_FILE_INFORMATION info {};
          if (!GetFileInformationByHandle(probe.value, &info) || (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))) {
            return std::make_error_code(std::errc::invalid_argument);
          }
          fill_entry(info, by_name);
          return {};
        });
        entry_t open_entry;
        return !ec && !file.stat(open_entry) && open_entry.file_id == by_name.file_id && open_entry.device == by_name.device;
      }

      std::optional<std::uint64_t> free_space() override {
        ULARGE_INTEGER available {};
        const auto ec = as_user([&]() -> std::error_code {
          return GetDiskFreeSpaceExW(final_path_.c_str(), &available, nullptr, nullptr) ? std::error_code {} : last_error();
        });
        if (ec) {
          return std::nullopt;
        }
        return available.QuadPart;
      }

      std::error_code list_names(std::vector<std::string> &out) override {
        out.clear();
        return for_each([&out](const WIN32_FIND_DATAW &, const std::string &name) {
          out.push_back(name);
        });
      }

      std::error_code list_regular_files(std::vector<entry_t> &out) override {
        out.clear();
        return for_each([&](const WIN32_FIND_DATAW &data, const std::string &name) {
          constexpr DWORD skipped = FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DEVICE | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM;
          if ((data.dwFileAttributes & skipped) || name.starts_with('.') || !text::is_valid_utf8(name)) {
            return;
          }
          handle_t probe {CreateFileW(child(name).c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
          BY_HANDLE_FILE_INFORMATION info {};
          if (!probe.valid() || !GetFileInformationByHandle(probe.value, &info) || (info.dwFileAttributes & skipped)) {
            return;
          }
          if (check_security(probe.value)) {
            return;
          }
          entry_t entry;
          entry.name = name;
          fill_entry(info, entry);
          out.push_back(std::move(entry));
        });
      }

      std::error_code mark_from_internet(std::string_view name) override {
        if (!plain_component(name)) {
          return std::make_error_code(std::errc::invalid_argument);
        }
        const auto path = child(name) + L":Zone.Identifier";
        return as_user([&]() -> std::error_code {
          handle_t stream {CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
          if (!stream.valid()) {
            return last_error();
          }
          static constexpr char zone[] = "[ZoneTransfer]\r\nZoneId=3\r\n";
          DWORD written = 0;
          if (!WriteFile(stream.value, zone, sizeof(zone) - 1, &written, nullptr)) {
            return last_error();
          }
          if (written != sizeof(zone) - 1) {
            return std::make_error_code(std::errc::io_error);
          }
          return FlushFileBuffers(stream.value) ? std::error_code {} : last_error();
        });
      }

    private:
      /**
       * @brief Full path of a child.
       *
       * @param name Child name (UTF-8).
       * @return Wide path.
       */
      std::wstring child(std::string_view name) const {
        return final_path_ + L"\\" + utf_utils::from_utf8(std::string {name});
      }

      /**
       * @brief Enumerate children except `.` and `..` as the session user.
       *
       * @param callback Invoked with the find data and UTF-8 name.
       * @return Error, or empty.
       */
      template<class F>
      std::error_code for_each(F &&callback) {
        const auto pattern = final_path_ + L"\\*";
        return as_user([&]() -> std::error_code {
          WIN32_FIND_DATAW data {};
          HANDLE find = FindFirstFileExW(pattern.c_str(), FindExInfoBasic, &data, FindExSearchNameMatch, nullptr, 0);
          if (find == INVALID_HANDLE_VALUE) {
            const auto error = GetLastError();
            return error == ERROR_FILE_NOT_FOUND ? std::error_code {} : from_win32(error);
          }
          do {
            const std::wstring wide {data.cFileName};
            if (wide == L"." || wide == L"..") {
              continue;
            }
            callback(data, utf_utils::to_utf8(wide));
          } while (FindNextFileW(find, &data));
          const auto error = GetLastError();
          FindClose(find);
          return error == ERROR_NO_MORE_FILES ? std::error_code {} : from_win32(error);
        });
      }

      handle_t handle_;  ///< Directory handle (no FILE_SHARE_DELETE).
      std::filesystem::path requested_;  ///< Configured path.
      std::wstring final_path_;  ///< Final path of the handle (`\\?\` form).
    };
  }  // namespace

  std::error_code open_directory(const std::filesystem::path &path, bool create, std::unique_ptr<directory_t> &out) {
    if (path.empty() || !path.is_absolute()) {
      return std::make_error_code(std::errc::invalid_argument);
    }
    const auto normalized = path.lexically_normal();
    std::unique_ptr<windows_directory_t> directory;
    const auto ec = as_user([&]() -> std::error_code {
      if (create) {
        private_security_t security;
        if (const auto error = security.initialize(true); error) {
          return error;
        }
        std::filesystem::path prefix;
        for (const auto &component : normalized) {
          prefix /= component;
          if (prefix == prefix.root_path() || prefix == prefix.root_name()) {
            continue;
          }
          if (GetFileAttributesW(prefix.c_str()) != INVALID_FILE_ATTRIBUTES) {
            continue;
          }
          if (!CreateDirectoryW(prefix.c_str(), security.attributes()) && GetLastError() != ERROR_ALREADY_EXISTS) {
            return last_error();
          }
        }
      }
      handle_t handle {CreateFileW(normalized.c_str(), FILE_LIST_DIRECTORY | FILE_TRAVERSE | READ_CONTROL | FILE_READ_ATTRIBUTES | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
      if (!handle.valid()) {
        return last_error();
      }
      std::wstring final_path(MAX_PATH, L'\0');
      auto length = GetFinalPathNameByHandleW(handle.value, final_path.data(), static_cast<DWORD>(final_path.size()), FILE_NAME_NORMALIZED);
      if (length >= final_path.size()) {
        final_path.resize(length + 1);
        length = GetFinalPathNameByHandleW(handle.value, final_path.data(), static_cast<DWORD>(final_path.size()), FILE_NAME_NORMALIZED);
      }
      if (length == 0) {
        return last_error();
      }
      final_path.resize(length);
      directory = std::make_unique<windows_directory_t>(std::move(handle), normalized, std::move(final_path));
      return directory->check();
    });
    if (ec) {
      return ec;
    }
    out = std::move(directory);
    return {};
  }

  std::filesystem::path user_download_dir() {
    HANDLE raw = platf::retrieve_users_token(false);
    handle_t token {raw ? raw : INVALID_HANDLE_VALUE};
    if (!raw && running_as_system()) {
      return {};
    }
    // FOLDERID_Downloads, defined here so no import library for the GUID is needed.
    static constexpr GUID downloads_folder {0x374DE290, 0x123F, 0x4565, {0x91, 0x64, 0x39, 0xC4, 0x92, 0x5E, 0x46, 0x7B}};
    PWSTR folder = nullptr;
    if (FAILED(SHGetKnownFolderPath(downloads_folder, KF_FLAG_DEFAULT, raw, &folder)) || !folder) {
      return {};
    }
    std::filesystem::path result {folder};
    CoTaskMemFree(folder);
    return result;
  }
}  // namespace sds::fs
