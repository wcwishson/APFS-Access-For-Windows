#pragma once

#include "ApfsFormat.h"
#include "BlockDevice.h"
#include "RandomAccessSource.h"
#include <limits>

namespace apfsaccess::rw {

inline bool SnapshotRuntimeStoreSize(const catalog::NxSuperblock& nx, std::uint64_t& bytes) noexcept
{
    bytes = 0;
    if (!nx.block_size || !nx.block_count ||
        nx.block_count > (std::numeric_limits<std::uint64_t>::max)() / nx.block_size) return false;
    bytes = nx.block_count * static_cast<std::uint64_t>(nx.block_size);
    return true;
}

// A container-relative byte window, not mutation or recovery authority.
// BlockDevice applies its physical base; this source never adds it again.
class SnapshotRuntimeDeviceSource final : public catalog::RandomAccessSource
{
public:
    SnapshotRuntimeDeviceSource(const BlockDevice& device, const catalog::NxSuperblock& nx)
        : device_(device)
    {
        if (!SnapshotRuntimeStoreSize(nx, size_bytes_) ||
            device.BaseOffsetBytes() > (std::numeric_limits<std::uint64_t>::max)() - size_bytes_)
        {
            size_bytes_ = 0;
            return;
        }
        if (device.IsRawWriterAccepted())
        {
            raw_lease_ = device.CaptureHeldRawSnapshotLease();
            if (!raw_lease_ || size_bytes_ > device.RawWriteLimitBytes()) size_bytes_ = 0;
        }
        else if (!device.IsRegularFile() || size_bytes_ > device.GetGeometry().total_bytes) size_bytes_ = 0;
    }

    [[nodiscard]] bool IsValid() const
    {
        return size_bytes_ != 0 && (!raw_lease_ || device_.IsHeldRawSnapshotLeaseCurrent(*raw_lease_));
    }
    std::uint64_t SizeBytes() const override { return IsValid() ? size_bytes_ : 0; }
    bool Read(std::uint64_t offset, std::size_t size, std::vector<std::byte>& out) const override
    {
        out.clear();
        if (!IsValid() || offset > size_bytes_ || size > size_bytes_ - offset) return false;
        if (!size) return true;
        if (!device_.Read(offset, size, out) || out.size() != size || !IsValid())
        {
            out.clear();
            return false;
        }
        return true;
    }

private:
    const BlockDevice& device_;
    std::uint64_t size_bytes_ = 0;
    std::optional<BlockDevice::RawSnapshotLease> raw_lease_;
};

}
