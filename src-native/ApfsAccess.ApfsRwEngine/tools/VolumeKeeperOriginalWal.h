#pragma once

#include "WriteAheadLog.h"
#include "WindowsImageLease.h"
#include <bcrypt.h>
#include <array>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <utility>

namespace apfsaccess::rw::volume_keeper
{
class OwnedHandle
{
public:
    HANDLE value = INVALID_HANDLE_VALUE;
    explicit OwnedHandle(HANDLE handle) : value(handle) {}
    OwnedHandle(OwnedHandle&& other) noexcept : value(std::exchange(other.value, INVALID_HANDLE_VALUE)) {}
    OwnedHandle(const OwnedHandle&) = delete;
    ~OwnedHandle() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};

// Retain the existing file and its namespace until a validated TM takes over.
struct OriginalWal
{
    std::vector<OwnedHandle> directories;
    std::unique_ptr<transport::WindowsImageLease> read_fence;
    OwnedHandle file_identity;
    BY_HANDLE_FILE_INFORMATION original{};
    std::string identity, hash;
    std::vector<std::unique_ptr<WriteAheadLog>> leases;

    static void Require(bool ok, const char* error) { if (!ok) throw std::runtime_error(error); }
    static std::string Digest(std::span<const std::byte> bytes)
    {
        BCRYPT_ALG_HANDLE algorithm = nullptr;
        std::array<unsigned char, 32> digest{};
        Require(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0, "SHA256 provider failed");
        const auto status = BCryptHash(algorithm, nullptr, 0,
            reinterpret_cast<PUCHAR>(const_cast<std::byte*>(bytes.data())), static_cast<ULONG>(bytes.size()), digest.data(), 32);
        BCryptCloseAlgorithmProvider(algorithm, 0);
        Require(status >= 0, "SHA256 failed");
        std::string out;
        constexpr char hex[] = "0123456789abcdef";
        for (auto byte : digest) { out += hex[byte >> 4]; out += hex[byte & 15]; }
        return out;
    }

    explicit OriginalWal(const std::filesystem::path& path) : file_identity(INVALID_HANDLE_VALUE)
    {
        for (auto parent = path.parent_path(); !parent.empty();
            parent = parent == parent.root_path() ? std::filesystem::path{} : parent.parent_path())
        {
            OwnedHandle directory(CreateFileW(parent.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ, nullptr,
                OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
            FILE_ATTRIBUTE_TAG_INFO info{};
            Require(directory.value != INVALID_HANDLE_VALUE &&
                GetFileInformationByHandleEx(directory.value, FileAttributeTagInfo, &info, sizeof(info)) &&
                (info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) && !(info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT),
                "original WAL parent unavailable or redirected");
            directories.push_back(std::move(directory));
        }
        read_fence = std::make_unique<transport::WindowsImageLease>(path.wstring());
        file_identity.value = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        Require(file_identity.value != INVALID_HANDLE_VALUE && GetFileInformationByHandle(file_identity.value, &original) &&
            original.nNumberOfLinks == 1 && !(original.dwFileAttributes &
                (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DEVICE)), "original single-link WAL required");
        Require(read_fence->SizeBytes() <= 64ULL * 1024 * 1024, "WAL read resource budget exceeded");
        std::vector<std::byte> bytes;
        Require(read_fence->Read(0, static_cast<std::size_t>(read_fence->SizeBytes()), bytes), "original WAL read failed");
        hash = Digest(bytes);
    }

    std::string FileBinding() const
    {
        return std::to_string(original.dwVolumeSerialNumber) + ":" + std::to_string(original.nFileIndexHigh) + ":" +
            std::to_string(original.nFileIndexLow) + ":" + std::to_string(original.ftCreationTime.dwHighDateTime) + ":" +
            std::to_string(original.ftCreationTime.dwLowDateTime) + ":" + hash;
    }

    void Verify(const std::filesystem::path& path) const
    {
        OwnedHandle reader(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
            OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        BY_HANDLE_FILE_INFORMATION now{};
        Require(reader.value != INVALID_HANDLE_VALUE && GetFileInformationByHandle(reader.value, &now) &&
            now.nNumberOfLinks == 1 && now.dwVolumeSerialNumber == original.dwVolumeSerialNumber &&
            now.nFileIndexHigh == original.nFileIndexHigh && now.nFileIndexLow == original.nFileIndexLow &&
            now.nFileSizeHigh == original.nFileSizeHigh && now.nFileSizeLow == original.nFileSizeLow &&
            !(now.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DEVICE)),
            "original WAL identity changed");
        const auto size = (std::uint64_t(now.nFileSizeHigh) << 32) | now.nFileSizeLow;
        Require(size <= 64ULL * 1024 * 1024, "WAL read resource budget exceeded");
        std::vector<std::byte> bytes(static_cast<std::size_t>(size));
        DWORD count = 0;
        Require(ReadFile(reader.value, bytes.data(), static_cast<DWORD>(bytes.size()), &count, nullptr) &&
            count == bytes.size() && Digest(bytes) == hash, "original WAL bytes changed");
    }
};
}
