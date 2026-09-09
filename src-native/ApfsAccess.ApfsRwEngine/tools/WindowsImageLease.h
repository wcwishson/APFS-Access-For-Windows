#pragma once
#include "RandomAccessSource.h"
#include <windows.h>
#include <mutex>
#include <stdexcept>
#include <algorithm>
#include <utility>

namespace apfsaccess::transport
{
// Shared observer/read-tool lease. Ordinary local drive-absolute paths only.
// All I/O addresses the acquired file object; a path is never reopened for reads.
class WindowsImageLease final : public catalog::RandomAccessSource
{
public:
    explicit WindowsImageLease(const std::wstring& path, bool require_local_image_path = true)
    {
        auto admitted_path = path;
        if (require_local_image_path)
        {
            std::replace(admitted_path.begin(), admitted_path.end(), L'/', L'\\');
            if (!OrdinaryPath(admitted_path)) throw std::runtime_error("RegularImagePathRequired");
            const auto root = admitted_path.substr(0, 3);
            if (GetDriveTypeW(root.c_str()) != DRIVE_FIXED) throw std::runtime_error("LocalFixedImageRequired");
            // Pin and validate ancestors before opening a child. This rejects a
            // local-looking path redirected through a junction/symbolic link.
            for (std::size_t end = 2; end != std::wstring::npos; end = admitted_path.find(L'\\', end + 1))
            {
                const auto prefix = admitted_path.substr(0, end == 2 ? 3 : end);
                Handle directory{CreateFileW(prefix.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
                    nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
                FILE_ATTRIBUTE_TAG_INFO info{};
                if (directory.value == INVALID_HANDLE_VALUE ||
                    !GetFileInformationByHandleEx(directory.value, FileAttributeTagInfo, &info, sizeof(info)) ||
                    !(info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) || (info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
                    throw std::runtime_error("RegularImagePathRequired");
                directories_.push_back(std::move(directory));
            }
        }
        Handle file{CreateFileW(admitted_path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
            OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_RANDOM_ACCESS, nullptr)};
        if (file.value == INVALID_HANDLE_VALUE) throw std::runtime_error("ImageLeaseDenied");
        if (GetFileType(file.value) != FILE_TYPE_DISK || !GetFileInformationByHandle(file.value, &identity_) ||
            (identity_.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)))
            throw std::runtime_error("RegularImageRequired");
        if (require_local_image_path)
        {
            FILE_STANDARD_INFO standard{};
            if ((identity_.dwFileAttributes & FILE_ATTRIBUTE_DEVICE) ||
                !GetFileInformationByHandleEx(file.value, FileStandardInfo, &standard, sizeof(standard)) ||
                standard.Directory || standard.DeletePending || !standard.NumberOfLinks)
                throw std::runtime_error("RegularImageRequired");
            constexpr DWORD flags = FILE_NAME_NORMALIZED | VOLUME_NAME_GUID;
            const auto length = GetFinalPathNameByHandleW(file.value, nullptr, 0, flags);
            if (!length || length > 32768) throw std::runtime_error("LocalFixedImageRequired");
            std::wstring final_path(length, L'\0');
            const auto copied = GetFinalPathNameByHandleW(file.value, final_path.data(), length, flags);
            if (!copied || copied >= length) throw std::runtime_error("LocalFixedImageRequired");
            final_path.resize(copied);
            const auto end = final_path.find(L"}\\");
            if (!final_path.starts_with(LR"(\\?\Volume{)") || end == std::wstring::npos ||
                end + 2 >= final_path.size() || final_path.find(L':', end + 2) != std::wstring::npos ||
                GetDriveTypeW(final_path.substr(0, end + 2).c_str()) != DRIVE_FIXED)
                throw std::runtime_error("LocalFixedImageRequired");
        }
        handle_ = std::exchange(file.value, INVALID_HANDLE_VALUE);
    }
    ~WindowsImageLease() override { if (handle_ != INVALID_HANDLE_VALUE) CloseHandle(handle_); }
    WindowsImageLease(const WindowsImageLease&) = delete;
    WindowsImageLease& operator=(const WindowsImageLease&) = delete;
    std::uint64_t SizeBytes() const override
    { return (std::uint64_t(identity_.nFileSizeHigh) << 32) | identity_.nFileSizeLow; }
    std::string Identity() const
    {
        return "windows-file:" + std::to_string(identity_.dwVolumeSerialNumber) + ":" +
            std::to_string((std::uint64_t(identity_.nFileIndexHigh) << 32) | identity_.nFileIndexLow) + ":" +
            std::to_string(SizeBytes()) + ":" +
            std::to_string((std::uint64_t(identity_.ftLastWriteTime.dwHighDateTime) << 32) | identity_.ftLastWriteTime.dwLowDateTime);
    }
    bool VerifyUnchanged() const
    {
        BY_HANDLE_FILE_INFORMATION now{};
        return GetFileInformationByHandle(handle_, &now) && now.dwVolumeSerialNumber == identity_.dwVolumeSerialNumber &&
            now.nFileIndexHigh == identity_.nFileIndexHigh && now.nFileIndexLow == identity_.nFileIndexLow &&
            now.nFileSizeHigh == identity_.nFileSizeHigh && now.nFileSizeLow == identity_.nFileSizeLow &&
            CompareFileTime(&now.ftLastWriteTime, &identity_.ftLastWriteTime) == 0;
    }
    bool Read(std::uint64_t offset, std::size_t size, std::vector<std::byte>& bytes) const override
    {
        std::lock_guard lock(io_);
        bytes.clear();
        if (offset > SizeBytes() || size > SizeBytes() - offset || size > MAXDWORD || offset > INT64_MAX) return false;
        LARGE_INTEGER at{}; at.QuadPart = static_cast<LONGLONG>(offset);
        if (!SetFilePointerEx(handle_, at, nullptr, FILE_BEGIN)) return false;
        bytes.resize(size); DWORD read = 0;
        if (!::ReadFile(handle_, bytes.data(), static_cast<DWORD>(size), &read, nullptr) || read != size)
        { bytes.clear(); return false; }
        return true;
    }
private:
    struct Handle
    {
        HANDLE value;
        explicit Handle(HANDLE handle) : value(handle) {}
        Handle(Handle&& other) noexcept : value(std::exchange(other.value, INVALID_HANDLE_VALUE)) {}
        Handle(const Handle&) = delete;
        ~Handle() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    };
    // Pure syntax, before any filesystem/device call. The observer opts out.
    static bool OrdinaryPath(const std::wstring& path)
    {
        if (path.size() < 4 || !((path[0] >= L'A' && path[0] <= L'Z') ||
            (path[0] >= L'a' && path[0] <= L'z')) || path[1] != L':' || path[2] != L'\\' ||
            path.find_first_of(L":*?\"<>|", 3) != path.npos ||
            std::any_of(path.begin(), path.end(), [](wchar_t c) { return c < 32; })) return false;
        for (std::size_t begin = 3; begin < path.size();)
        {
            auto end = path.find(L'\\', begin);
            if (end == path.npos) end = path.size();
            const auto part = path.substr(begin, end-begin);
            if (part.empty() || part == L"." || part == L".." || part.back() == L'.' || part.back() == L' ') return false;
            auto stem = part.substr(0, part.find(L'.'));
            std::transform(stem.begin(), stem.end(), stem.begin(), [](wchar_t c) -> wchar_t {
                return c >= L'a' && c <= L'z' ? static_cast<wchar_t>(c-32) : c; });
            if (stem == L"CON" || stem == L"PRN" || stem == L"AUX" || stem == L"NUL" ||
                stem == L"CONIN$" || stem == L"CONOUT$" ||
                (stem.size() == 4 && (stem.starts_with(L"COM") || stem.starts_with(L"LPT")))) return false;
            begin = end+1;
        }
        return path.back() != L'\\';
    }
    std::vector<Handle> directories_;
    HANDLE handle_ = INVALID_HANDLE_VALUE;
    BY_HANDLE_FILE_INFORMATION identity_{};
    mutable std::mutex io_;
};
}
