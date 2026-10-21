#pragma once

#include "AppleCheckpointPublisher.h"
#include "ApfsFusionStore.h"
#include "ApfsFusionWriteSession.h"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace apfsaccess::rw
{
// Publisher write target over one complete Fusion member set. Reads route
// through the bound store's encoded address space; writes split to container
// block size and route through the bound ordered write session; flushes use
// the session's crash-safe tier-2-then-main order. Both the store and the
// session must outlive the target, and the session must be bound to the same
// store generation. Single-block reads use the default implementation, which
// is always aligned and never crosses the tier gap.
class ApfsFusionCheckpointTarget final : public AppleCheckpointWriteTarget
{
public:
    ApfsFusionCheckpointTarget(
        const catalog::ApfsFusionStore& store,
        catalog::ApfsFusionWriteSession& writer,
        std::uint32_t block_size);

    bool ReadBlock(std::uint64_t physical_block, std::uint32_t block_size,
        std::vector<std::byte>& out_bytes) override;
    bool WriteBlock(std::uint64_t physical_block,
        std::span<const std::byte> bytes) override;
    bool Flush() override;

private:
    const catalog::ApfsFusionStore* store_;
    catalog::ApfsFusionWriteSession* writer_;
    std::uint32_t block_size_ = 0;
    bool binding_valid_ = false;
};
} // namespace apfsaccess::rw
