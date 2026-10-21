#pragma once

#include "AppleTransactionCommit.h"
#include "TestFixtureBuilder.h"
#include <algorithm>
#include <iostream>
#include <limits>
#include <new>
#include <stdexcept>

// Include in ApfsCompatibilityTests.cpp and register the TestApfsRecoveryBudget*
// functions with its run(name, function) selector. All fixtures stay in memory.
namespace apfsaccess::recovery_budget_tests
{
using namespace catalog;
using namespace rw;
namespace fixture = testfixture;
constexpr std::uint32_t BlockSize = 4096;
constexpr auto Unlimited = (std::numeric_limits<std::uint64_t>::max)();

inline bool Check(bool condition, const char* message)
{
    if (!condition) std::cerr << "[FAIL] recovery budget: " << message << '\n';
    return condition;
}

class Source final : public RandomAccessSource
{
public:
    explicit Source(std::vector<std::byte> bytes = {}, std::uint64_t reported_size = 0)
        : bytes_(std::move(bytes)), size_(reported_size ? reported_size : bytes_.size()) {}
    std::uint64_t SizeBytes() const override { return size_; }
    bool Read(std::uint64_t offset, std::size_t size, std::vector<std::byte>& out) const override
    {
        ++reads;
        out.clear();
        if (throw_kind == 1) throw std::bad_alloc{};
        if (throw_kind == 2) throw std::length_error("injected recovery allocation failure");
        if (offset > bytes_.size() || size > bytes_.size() - offset) return false;
        out.assign(bytes_.begin() + static_cast<std::size_t>(offset),
            bytes_.begin() + static_cast<std::size_t>(offset) + size);
        return true;
    }
    mutable std::uint64_t reads = 0;
    unsigned throw_kind = 0;
private:
    std::vector<std::byte> bytes_;
    std::uint64_t size_;
};

// Minimal caller projection for isolating metadata collection, with one real
// checksum-valid empty physical OMAP leaf. Full checkpoint parsing is exercised
// separately by TestApfsRecoveryBudgetEncodedOwnership.
inline AppleCheckpointView MetadataCheckpoint()
{
    AppleCheckpointView checkpoint;
    auto& nx = checkpoint.container.superblock;
    nx.block_size = BlockSize;
    nx.block_count = 4;
    nx.xid = 7;
    nx.next_xid = 8;
    checkpoint.container.checkpoint_map_blocks.push_back(3);
    auto& map = checkpoint.container_object_map;
    map.object.physical_block = 1;
    map.object.size_bytes = BlockSize;
    map.tree.object_id = 2;
    map.tree.physical_block = 2;
    map.tree.size_bytes = BlockSize;
    map.tree.type = kObjectPhysical | kObjectTypeBtree;
    map.tree.subtype = kObjectTypeOmap;
    return checkpoint;
}

inline std::vector<std::byte> MetadataImage()
{
    std::vector<std::byte> bytes(4 * BlockSize);
    const auto leaf = fixture::BuildRawLeafNode({}, {}, 7, BlockSize, 0, 2,
        kObjectPhysical | kObjectTypeBtree, kObjectTypeOmap);
    std::copy(leaf.begin(), leaf.end(), bytes.begin() + 2 * BlockSize);
    return bytes;
}

inline bool TestApfsRecoveryBudgetObjectExpansion()
{
    bool ok = true;
    for (bool byte_limit : {false, true})
    {
        Source raw({}, Unlimited);
        auto checkpoint = MetadataCheckpoint();
        checkpoint.container.superblock.block_count = Unlimited / BlockSize;
        checkpoint.container_object_map.object.size_bytes = 0xfffff000u;
        auto budget = std::make_shared<ApfsReadBudget>(Unlimited, Unlimited,
            byte_limit ? Unlimited : 1, byte_limit ? 8 : Unlimited);
        BudgetedRandomAccessSource source(raw, budget);
        std::string error;
        ok &= Check(!ValidateAppleCheckpointPayloadOwnership(source, checkpoint, {}, error) &&
            error == "ApfsReadBudgetRecordLimit" && raw.reads == 0,
            "million-block object expansion refuses before vector growth or IO");
        checkpoint.container_object_map.object.size_bytes = BlockSize;
        ok &= Check(!ValidateAppleCheckpointPayloadOwnership(source, checkpoint, {}, error) &&
            error == "ApfsReadBudgetRecordLimit" && raw.reads == 0,
            "shrinking the next request does not reset a failed budget");
    }
    Source raw({}, Unlimited);
    auto checkpoint = MetadataCheckpoint();
    checkpoint.container_object_map.object.physical_block = Unlimited - 1;
    std::string error;
    ok &= Check(!ValidateAppleCheckpointPayloadOwnership(raw, checkpoint, {}, error) &&
        error == "AppleCheckpointMetadataOutsideContainer" && raw.reads == 0,
        "out-of-container object rejects without overflowing its end");
    return ok;
}

inline bool TestApfsRecoveryBudgetSpacemanReferences()
{
    auto checkpoint = MetadataCheckpoint();
    // These are two materialized references even though final dedup merges them.
    checkpoint.spaceman.chunks.resize(2);
    for (auto& chunk : checkpoint.spaceman.chunks) chunk.bitmap_block = 3;
    Source raw(MetadataImage());
    std::string error;
    bool ok = Check(ValidateAppleCheckpointPayloadOwnership(raw, checkpoint, {}, error),
        "unbudgeted metadata collection retains its behavior");
    auto short_budget = std::make_shared<ApfsReadBudget>(Unlimited, Unlimited, 3, Unlimited);
    BudgetedRandomAccessSource limited(raw, short_budget);
    const auto reads_before = raw.reads;
    ok &= Check(!ValidateAppleCheckpointPayloadOwnership(limited, checkpoint, {}, error) &&
        error == "ApfsReadBudgetRecordLimit" && raw.reads == reads_before + 1,
        "spaceman append spends the allowance remaining after object and tree references");
    auto exact_budget = std::make_shared<ApfsReadBudget>(Unlimited, Unlimited, 4, Unlimited);
    BudgetedRandomAccessSource exact(raw, exact_budget);
    ok &= Check(ValidateAppleCheckpointPayloadOwnership(exact, checkpoint, {}, error) &&
        !exact_budget->Failed(), "four references succeed without helper-layer double charging");
    const auto after_success = raw.reads;
    BudgetedRandomAccessSource nested(exact, exact_budget);
    ok &= Check(!ValidateAppleCheckpointPayloadOwnership(nested, checkpoint, {}, error) &&
        error == "ApfsReadBudgetRecordLimit" && raw.reads == after_success,
        "second collection cannot replenish the shared reference allowance");
    return ok;
}

inline bool TestApfsRecoveryBudgetPendingHistory()
{
    Source raw(MetadataImage());
    auto checkpoint = MetadataCheckpoint();
    const std::vector<std::uint64_t> requested{7, 7, 7};
    std::vector<AppleRecoveryCheckpointView> output(1);
    std::string error;
    bool ok = true;
    for (bool byte_limit : {false, true})
    {
        auto budget = std::make_shared<ApfsReadBudget>(Unlimited, Unlimited,
            byte_limit ? Unlimited : 2, byte_limit ? 2 * sizeof(std::uint64_t) : Unlimited);
        BudgetedRandomAccessSource source(raw, budget);
        output.resize(1);
        ok &= Check(!LoadAppleRecoveryCheckpoints(source, checkpoint, requested, output, error) &&
            output.empty() && error == "ApfsReadBudgetRecordLimit" && raw.reads == 0,
            "pending history copy refuses count/byte exhaustion and clears stale output");
    }
    auto budget = std::make_shared<ApfsReadBudget>(Unlimited, Unlimited, 6, Unlimited);
    BudgetedRandomAccessSource source(raw, budget);
    ok &= Check(LoadAppleRecoveryCheckpoints(source, checkpoint, requested, output, error) &&
        LoadAppleRecoveryCheckpoints(source, checkpoint, requested, output, error) &&
        !LoadAppleRecoveryCheckpoints(source, checkpoint, requested, output, error) &&
        output.empty() && raw.reads == 0 && error == "ApfsReadBudgetRecordLimit",
        "current-XID fast path still charges each pending copy cumulatively");
    ok &= Check(LoadAppleRecoveryCheckpoints(raw, checkpoint, requested, output, error) &&
        output.empty() && error.empty(), "unbudgeted current-XID history remains an empty success");
    return ok;
}

inline bool TestApfsRecoveryBudgetAllocationFailure()
{
    bool ok = true;
    for (unsigned kind : {1u, 2u})
    {
        Source raw(MetadataImage());
        raw.throw_kind = kind;
        const auto checkpoint = MetadataCheckpoint();
        auto budget = std::make_shared<ApfsReadBudget>(Unlimited, Unlimited, Unlimited, Unlimited);
        BudgetedRandomAccessSource source(raw, budget);
        std::string error;
        ok &= Check(!ValidateAppleCheckpointPayloadOwnership(source, checkpoint, {}, error) &&
            error == "ApfsReadBudgetAllocationFailed" && raw.reads == 1,
            "allocation exception becomes a sticky ownership refusal");
        std::vector<AppleRecoveryCheckpointView> output(1);
        ok &= Check(!LoadAppleRecoveryCheckpoints(source, checkpoint, {}, output, error) &&
            output.empty() && error == "ApfsReadBudgetAllocationFailed" && raw.reads == 1,
            "failed allowance clears history even on the empty-request path");
        AppleVolumeReplayBoundary boundary{7, 8};
        ok &= Check(!FindAppleVolumeReplayBoundary(source, checkpoint, 101, 7, boundary, error) &&
            boundary.preimage_checkpoint_xid == 0 && !boundary.first_changed_checkpoint_xid &&
            error == "ApfsReadBudgetAllocationFailed" && raw.reads == 1,
            "failed allowance clears a stale replay boundary without another read");

        auto history_budget = std::make_shared<ApfsReadBudget>(Unlimited, Unlimited, Unlimited, Unlimited);
        BudgetedRandomAccessSource history_source(raw, history_budget);
        output.resize(1);
        ok &= Check(!LoadAppleRecoveryCheckpoints(history_source, checkpoint, {6}, output, error) &&
            output.empty() && error == "ApfsReadBudgetAllocationFailed" && raw.reads == 2,
            "checkpoint loader allocation exception cannot leak partial recovery output");
    }
    return ok;
}

inline bool TestApfsRecoveryBudgetEncodedOwnership()
{
    fixture::BuilderStore spec;
    spec.authoritative_checkpoint = true;
    Source raw(fixture::BuildStoreImage(spec));
    std::string error;
    const auto checkpoint = LoadAppleCheckpointView(raw, 0, raw.SizeBytes(), error, spec.xid);
    if (!Check(checkpoint.has_value(), "encoded authoritative checkpoint loads")) return false;
    bool ok = Check(ValidateAppleCheckpointPayloadOwnership(raw, *checkpoint, {}, error),
        "encoded checkpoint metadata passes ordinary ownership traversal");
    auto budget = std::make_shared<ApfsReadBudget>(10000, 64ULL << 20, 10000, 64ULL << 20);
    BudgetedRandomAccessSource source(raw, budget);
    ok &= Check(ValidateAppleCheckpointPayloadOwnership(source, *checkpoint, {}, error) &&
        !budget->Failed(), "encoded volume/OMAP/spaceman graph accepts a generous budget");
    auto no_reads = std::make_shared<ApfsReadBudget>(0, Unlimited, Unlimited, Unlimited);
    BudgetedRandomAccessSource limited(raw, no_reads);
    const auto before = raw.reads;
    ok &= Check(!ValidateAppleCheckpointPayloadOwnership(limited, *checkpoint, {}, error) &&
        error == "ApfsReadBudgetSourceLimit" && raw.reads == before,
        "recovery preserves the underlying source-budget reason without fallback IO");
    return ok;
}
} // namespace apfsaccess::recovery_budget_tests
