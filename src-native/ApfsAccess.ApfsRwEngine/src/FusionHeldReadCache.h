#pragma once
#include "BlockDevice.h"
#include <map>
#include <mutex>
#include <optional>

namespace apfsaccess::catalog {
// Canonical parser reads only. Publication guards/readback bypass this cache.
// BlockDevice advances this opaque observation at both ends of every write
// admission, including failed writes, and when its held handles are retired.
class FusionHeldReadCache final {
    using Observation = rw::BlockDevice::WriteSourceObservation;
    static constexpr std::size_t MaxBytes = 8 * 1024 * 1024;
    mutable std::mutex gate_;
    mutable std::optional<Observation> observation_;
    mutable std::map<std::pair<std::uint64_t, std::size_t>, std::vector<std::byte>> entries_;
    mutable std::size_t bytes_ = 0;
public:
    bool Read(rw::BlockDevice& device, std::uint64_t at, std::size_t size,
        std::vector<std::byte>& out) const {
        std::lock_guard lock(gate_);
        out.clear();
        const auto current = device.CaptureExclusiveWriteSourceObservation();
        if (!current || current != observation_) {
            entries_.clear(); bytes_ = 0; observation_ = current;
        }
        if (!current) return false;
        const auto key = std::pair{at, size};
        const auto found = entries_.find(key);
        if (found != entries_.end()) out = found->second;
        else if (!device.ReadForVerification(at, size, out) || out.size() != size) {
            out.clear(); return false;
        }
        if (!device.IsExclusiveWriteSourceObservationCurrent(*current)) {
            entries_.clear(); bytes_ = 0; observation_.reset(); out.clear(); return false;
        }
        if (found == entries_.end() && size && size <= 64 * 1024) {
            if (size > MaxBytes - bytes_) { entries_.clear(); bytes_ = 0; }
            entries_.emplace(key, out); bytes_ += size;
        }
        return true;
    }
};
}
