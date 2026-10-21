#pragma once

#include "ApfsFusionStore.h"
#include "BlockDevice.h"
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace apfsaccess::catalog
{
// Ordered two-store write session for one COMPLETE Fusion container set.
// This is the storage half of multi-device publication: it routes aligned
// block writes to the owning member and flushes members in crash-safe order
// (tier-2 payload first, main with the checkpoint last). The caller's
// copy-on-write plan must preserve the previous checkpoint until its switch.
// Allocation, checkpoint planning, the NXSB switch itself, and
// WAL/journal integration belong to the planner/publisher layers, which do
// not call this yet: admission there stays closed until they do.
//
// Binding reuses a verified ApfsFusionStore (container UUID, checkpoint XID,
// member geometry and exact file identities) and additionally requires two
// caller-held writable member devices whose held identities match the bound
// store. Identities are re-verified before every write and flush: a replaced
// member refuses instead of routing to the wrong file. Regular image files
// are the only supported member kind, matching the read path; raw devices
// refuse explicitly. Never synthesizes data for a missing member.
//
// Lifetime and threading: the bound store must outlive the session, and the
// session is not thread-safe. The owning coordinator serializes all calls,
// matching the read session discipline.
class ApfsFusionWriteSession final
{
public:
    ~ApfsFusionWriteSession();
    ApfsFusionWriteSession(const ApfsFusionWriteSession&) = delete;
    ApfsFusionWriteSession& operator=(const ApfsFusionWriteSession&) = delete;

    struct Counters
    {
        std::uint64_t main_blocks_written = 0;
        std::uint64_t tier2_blocks_written = 0;
        std::uint64_t main_flushes = 0;
        std::uint64_t tier2_flushes = 0;
    };

    // Both devices must be held writable by the caller (ownership and lock
    // policy stay with the coordinator). Devices are matched to roles by
    // held file identity, never by argument order.
    [[nodiscard]] static std::unique_ptr<ApfsFusionWriteSession> Bind(
        const ApfsFusionStore& store,
        std::shared_ptr<rw::BlockDevice> first_device,
        std::shared_ptr<rw::BlockDevice> second_device,
        std::string& error, unsigned* unavailable_members = nullptr);

    // One complete block addressed in container physical-block numbering.
    // Size must equal the container block size; cross-tier and out-of-range
    // spans refuse before any byte is written.
    [[nodiscard]] bool WriteBlock(std::uint64_t physical_block,
        std::span<const std::byte> bytes, std::string& error);
    // Validate the entire contiguous member range and reserve its allowance
    // before dispatch. An I/O failure may stage a prefix and poisons the session.
    [[nodiscard]] bool WriteBlocks(std::uint64_t physical_block,
        std::span<const std::byte> bytes, std::string& error);
    [[nodiscard]] bool CheckAvailable(std::string& error);
    [[nodiscard]] bool IsBoundTo(const ApfsFusionStore& store) const noexcept;
    // Durability barrier in crash-safe order: tier-2 first, then main. A
    // tier-2 failure returns before main is flushed and poisons the session.
    // Already staged bytes are not rolled back. Both flushes run on success, even when
    // only one member received writes in this session.
    [[nodiscard]] bool FlushOrdered(std::string& error);

    [[nodiscard]] std::uint32_t BlockSize() const noexcept;
    [[nodiscard]] std::uint64_t MainBlocks() const noexcept;
    [[nodiscard]] std::uint64_t Tier2Blocks() const noexcept;
    [[nodiscard]] const std::string& ContainerUuid() const noexcept;
    [[nodiscard]] std::uint64_t CheckpointXid() const noexcept;
    [[nodiscard]] Counters counters() const noexcept;
    [[nodiscard]] const std::string& LastError() const noexcept;

private:
    struct Impl;
    explicit ApfsFusionWriteSession(std::unique_ptr<Impl> impl);
    std::unique_ptr<Impl> impl_;
};
} // namespace apfsaccess::catalog
