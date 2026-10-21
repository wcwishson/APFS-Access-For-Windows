#pragma once
#include "AppleVolumeTransaction.h"
#include <array>

namespace apfsaccess::rw
{
enum class NativeSparseAction : std::uint64_t { SetSparse = 1, ZeroRange = 2 };
struct NativeSparseRequest
{
    NativeSparseAction action = NativeSparseAction::SetSparse;
    bool sparse = true;
    std::uint64_t offset = 0, length = 0, timestamp_ns = 0;
    bool operator==(const NativeSparseRequest&) const = default;
};
struct NativeSparseAllocatedRange
{
    std::uint64_t offset = 0, length = 0;
    bool operator==(const NativeSparseAllocatedRange&) const = default;
};
struct NativeSparseSourceBlock
{
    std::uint64_t physical_block = 0;
    std::array<std::byte,4096> bytes{};
    bool operator==(const NativeSparseSourceBlock&) const = default;
};
inline constexpr std::uint64_t NativeSparseMaxImageBytes = 256ull << 20;
inline constexpr std::size_t NativeSparseMaxRecords = 4096;
inline constexpr std::size_t NativeSparseMaxMaterializedBytes = 512u << 10;
struct NativeSparseState
{
    AppleInodeRecord inode;
    std::uint64_t size = 0, allocated = 0;
    bool sparse = false;
    std::vector<catalog::BtreeRecord> filesystem, references;
    std::vector<ApplePhysicalExtentRecord> payload;
    std::vector<AppleFileExtentRecord> extents;
    std::vector<NativeSparseAllocatedRange> ranges;
};
bool NativeSparseRequestIsValid(const NativeSparseRequest&);
// Canonical graph and allocator proof. No caller-supplied extent is trusted.
bool ReadNativeSparseState(const catalog::RandomAccessSource&, const catalog::AppleCheckpointView&,
    std::uint64_t volume_oid, std::uint64_t inode, NativeSparseState&, std::string& error);
bool QueryNativeSparseRanges(const NativeSparseState&, std::uint64_t offset, std::uint64_t length,
    std::size_t maximum, std::vector<NativeSparseAllocatedRange>&, std::string& error);
// Planning only. Publication requires the separately accepted owner capability.
bool PlanNativeSparseTransaction(const catalog::RandomAccessSource&, const catalog::AppleCheckpointView&,
    std::uint64_t volume_oid, std::uint64_t inode, const NativeSparseRequest&,
    NativeSparseState& before, AppleVolumeTransactionPlan&, std::string& error);
// NSP2 uses complete ownership instead of a whole-payload content hash. These
// additive entrypoints preserve NSP1's source-size and replay contract.
bool ReadNativeSparseStateV2(const catalog::RandomAccessSource&, const catalog::AppleCheckpointView&,
    std::uint64_t volume_oid, std::uint64_t inode, NativeSparseState&, std::string& error);
bool PlanNativeSparseTransactionV2(const catalog::RandomAccessSource&, const catalog::AppleCheckpointView&,
    std::uint64_t volume_oid, std::uint64_t inode, const NativeSparseRequest&,
    NativeSparseState& before, AppleVolumeTransactionPlan&, std::vector<NativeSparseSourceBlock>&, std::string& error);
bool PlanNativeSparseTransactionV2Legacy(const catalog::RandomAccessSource&, const catalog::AppleCheckpointView&,
    std::uint64_t volume_oid, std::uint64_t inode, const NativeSparseRequest&,
    NativeSparseState& before, AppleVolumeTransactionPlan&, std::vector<NativeSparseSourceBlock>&, std::string& error);
// Complete logical coverage with explicit physical-block-zero extents. Pending
// COW writes occupy their logical ranges but have no physical mapping yet.
bool CompleteNativeSparseExtentCoverage(std::uint64_t inode, std::uint64_t size,
    std::vector<catalog::BtreeRecord>& extents, std::span<const NativeSparseAllocatedRange> pending_materialized,
    std::string& error);
}
