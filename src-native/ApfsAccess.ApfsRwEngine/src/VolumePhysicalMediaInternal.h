#pragma once
#include "VolumePhysicalMedia.h"
#include <functional>
#include <mutex>

namespace apfsaccess::rw
{
struct VolumePhysicalSource::Impl
{
    std::shared_ptr<BlockDevice> metadata_device;
    RawSnapshotBinding binding;
    std::wstring instance;
    std::string identity;
    mutable std::mutex gate;
    bool poisoned = false;
    std::function<bool()> current, flush;
    std::function<bool(std::uint64_t, std::size_t, std::vector<std::byte>&, bool)> read;
    std::function<bool(std::uint64_t, std::span<const std::byte>)> write;
    std::function<bool(std::uint64_t, std::size_t)> zero;
    std::function<bool(std::uint64_t, std::size_t, std::vector<std::byte>&)> read_metadata;
    bool Current() { if (poisoned) return false; if (current()) return true; poisoned = true; return false; }
    bool Result(bool value) { if (!value) poisoned = true; return value; }
};
bool ValidateVolumePhysicalPolicy(const RawSnapshotBinding&, std::wstring_view instance, std::string& error);
std::string VolumePhysicalIdentity(const RawSnapshotBinding&, std::wstring_view instance);
}
