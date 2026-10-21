#pragma once
#include "ContainerMountCoordinator.h"
#include <Windows.h>
#include <algorithm>
#include <filesystem>
#include <sstream>
#include <string>
#include <string_view>

namespace apfsaccess::host
{
// Created only after ParseContainerManifest and launch-checksum validation.
// A coordinator takes over all settlement once it has acquired ownership.
class ManifestStartupTerminal final
{
public:
    ManifestStartupTerminal(std::wstring status_file, const catalog::ContainerManifest& manifest,
        std::string_view expected_sha256)
        : status_file_(std::move(status_file)), container_(manifest.container_uuid_hex)
    {
        const auto hex = [](std::string_view value, std::size_t size) {
            return value.size() == size && value.find_first_not_of("0123456789abcdef") == std::string_view::npos;
        };
        armed_ = hex(expected_sha256, 64) && expected_sha256 == manifest.manifest_sha256 &&
            hex(container_, 32) && container_ != std::string(32, '0') && !manifest.volumes.empty();
    }
    ManifestStartupTerminal(const ManifestStartupTerminal&) = delete;
    ManifestStartupTerminal& operator=(const ManifestStartupTerminal&) = delete;
    ~ManifestStartupTerminal() { if (armed_) (void)Publish(); }
    void CoordinatorAcquired() noexcept { armed_ = false; }
    bool Publish() noexcept
    {
        if (!armed_ || status_file_.empty()) return false;
        try {
            const auto path = std::filesystem::path(status_file_);
            if (!path.is_absolute() || status_file_.find(L'\0') != std::wstring::npos) return false;
            FILETIME created{}, exited{}, kernel{}, user{};
            if (!GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user)) return false;
            ULARGE_INTEGER started{}; started.LowPart = created.dwLowDateTime; started.HighPart = created.dwHighDateTime;
            if (!started.QuadPart) return false;
            const auto pid = GetCurrentProcessId(); std::ostringstream json;
            json << "{\"containerUuid\":\"" << container_ << "\",\"ownerPid\":" << pid
                 << ",\"ownerStartFileTimeUtc\":" << started.QuadPart
                 << ",\"leaseHeld\":false,\"checkpointXid\":0,\"recoveryRequired\":false,"
                    "\"recoveryVolumeObjectId\":null,\"recoveryReason\":\"\",\"volumes\":[]}";
            const auto contents = json.str(); auto temporary = path;
            temporary += L".early-terminal-" + std::to_wstring(pid) + L"-" + std::to_wstring(started.QuadPart) + L".tmp";
            const auto native = [](const std::filesystem::path& value) {
                auto normalized = value;
                normalized.make_preferred();
                const auto text = normalized.wstring(); return text.starts_with(L"\\\\?\\") ? text : L"\\\\?\\" + text;
            };
            const auto temporary_name = native(temporary), target_name = native(path);
            const auto file = CreateFileW(temporary_name.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH, nullptr);
            if (file == INVALID_HANDLE_VALUE) return false;
            DWORD written{};
            const bool durable = contents.size() <= MAXDWORD &&
                WriteFile(file, contents.data(), static_cast<DWORD>(contents.size()), &written, nullptr) &&
                written == contents.size() && FlushFileBuffers(file);
            CloseHandle(file);
            // No replace flag: a stale ready/status record must retain its veto.
            // Failed temporary evidence is preserved for startup diagnosis.
            return durable && MoveFileExW(temporary_name.c_str(), target_name.c_str(), MOVEFILE_WRITE_THROUGH);
        } catch (...) { return false; }
    }
private:
    std::wstring status_file_;
    std::string container_;
    bool armed_ = false;
};
}
