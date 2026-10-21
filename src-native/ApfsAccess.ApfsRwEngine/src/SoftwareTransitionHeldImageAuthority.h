#pragma once
#include <optional>
#include <windows.h>

namespace apfsaccess::catalog { class ApfsEncryptedImageWriteSession; }
namespace apfsaccess::rw
{
class BlockDevice;
// Only the held owner can establish this synchronous duplicate-handle scope.
// It owns no key and cannot outlive the store callback or escape its thread.
class SoftwareTransitionHeldImageAuthority final
{
    friend class catalog::ApfsEncryptedImageWriteSession;
    friend class BlockDevice;
    inline static thread_local const SoftwareTransitionHeldImageAuthority* current_ = nullptr;
    const SoftwareTransitionHeldImageAuthority* previous_;
    const BlockDevice* device_;
    HANDLE owner_;
    SoftwareTransitionHeldImageAuthority(const BlockDevice& device, HANDLE owner)
        : previous_(current_), device_(&device), owner_(owner) { current_ = this; }
    ~SoftwareTransitionHeldImageAuthority() { current_ = previous_; }
    SoftwareTransitionHeldImageAuthority(const SoftwareTransitionHeldImageAuthority&) = delete;
    static std::optional<ULONG> ExpectedHandleCount(const BlockDevice& device, HANDLE reader, HANDLE writer)
    {
        const auto* proof = current_;
        if (!proof || proof->device_ != &device) return 2;
        using Compare = BOOL (WINAPI*)(HANDLE, HANDLE);
        static const auto compare = reinterpret_cast<Compare>(GetProcAddress(GetModuleHandleW(L"kernelbase.dll"), "CompareObjectHandles"));
        if (!compare || !proof->owner_ || proof->owner_ == INVALID_HANDLE_VALUE ||
            proof->owner_ == reader || proof->owner_ == writer || reader == writer ||
            !compare(proof->owner_, reader) || !compare(proof->owner_, writer)) return std::nullopt;
        return 3;
    }
};
}
