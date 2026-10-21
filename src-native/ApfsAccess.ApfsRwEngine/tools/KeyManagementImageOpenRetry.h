#pragma once
#include "EncryptedImageRuntime.h"
#include <Windows.h>
#include <atomic>
#include <string_view>

namespace apfsaccess::transport
{
inline bool IsKeyManagementSharingOpenRefusal(std::string_view error) noexcept
{
    return error == "ImageWriterExclusiveSingleLinkRegularFileRequired:stage=FileOpen:win32=32:attempts=4" ||
        error == "ImageWriterExclusiveSingleLinkRegularFileRequired:stage=FileOpen:win32=33:attempts=4";
}

inline std::unique_ptr<catalog::EncryptedImageRuntime> OpenKeyManagementImageRuntime(
    const catalog::EncryptedImageRuntime::Options& options, const std::atomic<bool>& cancelled, std::string& error)
{
    const auto deadline = GetTickCount64() + 2500;
    const auto cancelled_open = [&] {
        error = "KeyManagementImageOpenCancelled";
        return std::unique_ptr<catalog::EncryptedImageRuntime>{};
    };
    for (;;) {
        if (cancelled.load()) return cancelled_open();
        auto runtime = catalog::EncryptedImageRuntime::Open(options, error);
        if (runtime) {
            if (cancelled.load()) { runtime->Cancel(); runtime->Close(); return cancelled_open(); }
            return runtime;
        }
        if (cancelled.load()) return cancelled_open();
        // This exact refusal precedes image admission and protected journal I/O.
        // Each retry must acquire and validate the complete owner again.
        if (!IsKeyManagementSharingOpenRefusal(error) || GetTickCount64() >= deadline) return {};
        for (unsigned wait = 0; wait < 25 && GetTickCount64() < deadline; wait += 5) {
            if (cancelled.load()) return cancelled_open();
            Sleep(5);
        }
    }
}
}
