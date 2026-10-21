#pragma once

#include "ApfsReadBudgetTests.h"

namespace apfsaccess::omap_lookup_tests
{
using namespace catalog;
namespace fixture = testfixture;
using read_budget_tests::CountingSource;
using read_budget_tests::Check;
using read_budget_tests::Put;
constexpr std::uint32_t BlockSize = 4096;
constexpr std::size_t Children = 12;

inline std::vector<std::byte> Image(std::vector<fixture::OmapRecordSpec> extra = {},
    bool historical = false)
{
    std::vector<std::byte> image((4 + Children) * BlockSize);
    std::vector<std::vector<std::byte>> keys, values;
    std::vector<fixture::OmapRecordSpec> mappings;
    for (std::size_t index = 0; index < Children; ++index)
    {
        std::vector<std::byte> key(8), child(8);
        fixture::PutU64LE(key, 0, index + 1);
        fixture::PutU64LE(child, 0, 100 + index);
        keys.push_back(key); values.push_back(child);
        if (historical) mappings.push_back({100 + index, image.size(), 0, 6});
        mappings.push_back({100 + index, 4 + index, 0, 7});
        // A future version must not override the selected checkpoint mapping.
        if (!historical) mappings.push_back({100 + index, image.size(), 0, 8});
        std::vector<std::byte> value(8);
        fixture::PutU64LE(value, 0, index + 1000);
        auto leaf = fixture::BuildRawLeafNode({key}, {value}, 7, BlockSize,
            0, 100 + index, kObjectTypeBtreeNode, kObjectTypeFsTree);
        std::copy(value.begin(), value.end(), leaf.end() - value.size());
        fixture::PutU16LE(leaf, 0x20, 2);
        fixture::PutU16LE(leaf, 0x2E, ReadU16LE(leaf, 0x2E).value() + 40);
        fixture::FletcherForBlock(leaf, BlockSize);
        Put(image, 4 + index, leaf);
    }
    mappings.insert(mappings.end(), extra.begin(), extra.end());
    auto root = fixture::BuildRawLeafNode(keys, values, 7, BlockSize,
        0, 1, kObjectTypeBtree, kObjectTypeFsTree);
    fixture::PutU16LE(root, 0x20, 1);
    fixture::PutU16LE(root, 0x22, 1);
    fixture::PutU64LE(root, BlockSize - 16, Children);
    fixture::PutU64LE(root, BlockSize - 8, Children + 1);
    fixture::FletcherForBlock(root, BlockSize);
    Put(image, 1, root);
    Put(image, 2, fixture::BuildOmap(3, 7, BlockSize, 2,
        kObjectPhysical | kObjectTypeOmap, kObjectPhysical | kObjectTypeBtree));
    Put(image, 3, fixture::BuildBtreeNode(mappings, 7, BlockSize,
        0, 3, kObjectPhysical | kObjectTypeBtree, kObjectTypeOmap));
    return image;
}

inline bool Walk(const RandomAccessSource& source, std::vector<BtreeRecord>& records,
    std::vector<std::uint64_t>& visited, std::string& error)
{
    BtreeReadPolicy policy;
    policy.enforce_object_identity = true;
    policy.require_complete_traversal = true;
    policy.reject_unsupported_flags = true;
    policy.root_object_id = 1;
    policy.subtype = kObjectTypeFsTree;
    policy.visited_physical_blocks = &visited;
    return ReadBtreeLeafRecords(source, BlockSize, 1, false, 2, 7,
        policy, records, error);
}

inline bool TestOmapWalkReadsMapOnce()
{
    CountingSource raw(Image());
    std::vector<BtreeRecord> records;
    std::vector<std::uint64_t> visited;
    std::string error;
    bool ok = Check(Walk(raw, records, visited, error) && records.size() == Children &&
        visited.size() == Children + 1, "virtual tree is completely validated");
    ok &= Check(raw.reads == Children + 3,
        "one OMAP header/tree scan instead of one complete scan per child");
    for (std::size_t index = 0; index < records.size(); ++index)
        ok &= Check(ReadU64LE(records[index].value, 0) == index + 1000,
            "checkpoint-version lookup preserves every leaf value");
    // A tight source allowance verifies the same gain without a timing assertion.
    CountingSource bounded_raw(Image());
    auto budget = std::make_shared<ApfsReadBudget>(Children + 3,
        (Children + 3) * BlockSize, 10000, 1ULL << 20);
    BudgetedRandomAccessSource bounded(bounded_raw, budget);
    ok &= Check(Walk(bounded, records, visited, error) && !budget->Failed(),
        "complete walk fits the single-scan read allowance");
    return ok;
}

inline bool TestOmapWalkRejectsMalformedAndRefreshes()
{
    bool ok = true;
    std::vector<BtreeRecord> records;
    std::vector<std::uint64_t> visited;
    std::string error;
    CountingSource original(Image());
    ok &= Check(Walk(original, records, visited, error), "original mapping walk succeeds");
    VectorRandomAccessSource reused_source(Image());
    ok &= Check(Walk(reused_source, records, visited, error), "same source begins with valid mappings");
    auto changed_bytes = Image();
    changed_bytes[3 * BlockSize + 200] ^= std::byte{1};
    reused_source = VectorRandomAccessSource(std::move(changed_bytes));
    ok &= Check(!Walk(reused_source, records, visited, error) && records.empty() && visited.empty(),
        "same source address and checkpoint cannot retain a previous mapping verdict");
    for (unsigned failure = 0; failure < 4; ++failure)
    {
        auto image = failure == 0 ? Image({{900, 4, 0, 7}, {900, 5, 0, 7}}) :
            failure == 1 ? Image({{100, 4, 1, 7}}) : Image();
        if (failure == 1)
        {
            // Replace the original live version with a tombstone; keep its older
            // valid version to prove that deletion does not fall back to it.
            auto map = fixture::BuildBtreeNode({{100, 4, 0, 6}, {100, 0, 1, 7}},
                7, BlockSize, 0, 3, kObjectPhysical | kObjectTypeBtree, kObjectTypeOmap);
            Put(image, 3, map);
        }
        if (failure == 2) image[3 * BlockSize + 200] ^= std::byte{1};
        if (failure == 3)
        {
            auto map = fixture::BuildRawLeafNode({std::vector<std::byte>(8)},
                {std::vector<std::byte>(16)}, 7, BlockSize, 0, 3,
                kObjectPhysical | kObjectTypeBtree, kObjectTypeOmap);
            Put(image, 3, map);
        }
        CountingSource changed(std::move(image));
        ok &= Check(!Walk(changed, records, visited, error) && records.empty() &&
            visited.empty() && changed.reads == 3,
            "new traversal rereads the source and rejects malformed or deleted mappings");
    }
    CountingSource exhausted_raw(Image());
    auto budget = std::make_shared<ApfsReadBudget>(Children + 2, 1ULL << 20, 10000, 1ULL << 20);
    BudgetedRandomAccessSource exhausted(exhausted_raw, budget);
    ok &= Check(!Walk(exhausted, records, visited, error) && records.empty() &&
        visited.empty() && error == "ApfsReadBudgetSourceLimit",
        "the cumulative read limit remains enforced");
    const auto reads = exhausted_raw.reads;
    ok &= Check(!Walk(exhausted, records, visited, error) && exhausted_raw.reads == reads,
        "exhaustion remains sticky on the next traversal");
    return ok;
}

inline bool StrictWalk(const RandomAccessSource& source,
    std::vector<BtreeRecord>& records, std::string& error)
{
    ContainerCheckpointView checkpoint;
    checkpoint.superblock.block_size = BlockSize;
    checkpoint.superblock.xid = 7;
    AppleVolumeCheckpointView volume;
    volume.root_tree = {1, 7, 1, kObjectTypeBtree, kObjectTypeFsTree, BlockSize};
    volume.object_map.object = {2, 7, 2, kObjectPhysical | kObjectTypeOmap, 0, BlockSize};
    volume.object_map.tree = {3, 7, 3, kObjectPhysical | kObjectTypeBtree, kObjectTypeOmap, BlockSize};
    return ReadAppleVolumeFileSystemRecords(source, checkpoint, volume, records, error);
}

inline bool TestStrictOmapWalkReadsOnceAndPreservesRefusals()
{
    CountingSource raw(Image({}, true));
    std::vector<BtreeRecord> records;
    std::string error;
    bool ok = Check(StrictWalk(raw, records, error) && records.size() == Children &&
        raw.reads == Children + 2, "strict resolver scans the validated OMAP tree once");
    for (unsigned failure = 0; failure < 5; ++failure)
    {
        auto image = failure == 0 ? Image() :
            failure == 1 ? Image({{900, 4, 4, 7}}, true) :
            failure == 2 ? Image({{900, 4, 0, 7}, {900, 5, 0, 7}}, true) : Image({}, true);
        if (failure == 3)
        {
            // Keep valid checksum/layout while reversing two original keys.
            const auto table_end = 3 * BlockSize + 0x38 + 2 * Children * 8;
            for (std::size_t offset = 0; offset < 16; ++offset)
                std::swap(image[table_end + offset], image[table_end + 16 + offset]);
            std::vector<std::byte> map(image.begin() + 3 * BlockSize, image.begin() + 4 * BlockSize);
            fixture::FletcherForBlock(map, BlockSize); Put(image, 3, map);
        }
        if (failure == 4)
        {
            std::vector<std::byte> leaf(image.begin() + 4 * BlockSize, image.begin() + 5 * BlockSize);
            fixture::PutU64LE(leaf, 16, 8);
            fixture::FletcherForBlock(leaf, BlockSize); Put(image, 4, leaf);
        }
        CountingSource malformed(std::move(image));
        ok &= Check(!StrictWalk(malformed, records, error) && records.empty(),
            "strict map flags, original order, duplicate keys and node XID remain enforced");
    }
    return ok;
}

inline bool TestOmapLookupRejectsZeroChildAndIndexBudget()
{
    auto image = Image({{0, 4, 0, 7}});
    auto root = std::vector<std::byte>(image.begin() + BlockSize, image.begin() + 2 * BlockSize);
    fixture::PutU64LE(root, BlockSize - 40 - 8, 0);
    fixture::FletcherForBlock(root, BlockSize); Put(image, 1, root);
    auto leaf = std::vector<std::byte>(image.begin() + 4 * BlockSize, image.begin() + 5 * BlockSize);
    fixture::PutU64LE(leaf, 8, 0);
    fixture::FletcherForBlock(leaf, BlockSize); Put(image, 4, leaf);
    CountingSource malformed(std::move(image));
    std::vector<BtreeRecord> records(1);
    std::vector<std::uint64_t> visited{123};
    std::string error;
    BtreeReadPolicy loose;
    loose.visited_physical_blocks = &visited;
    bool ok = Check(!ReadBtreeLeafRecords(malformed, BlockSize, 1, false, 2, 7,
        loose, records, error) && records.empty() && visited.empty() && malformed.reads == 1,
        "zero virtual child cannot be resolved through a non-strict OMAP");
    CountingSource limited_raw(Image());
    auto budget = std::make_shared<ApfsReadBudget>(1000, 1ULL << 20, 10000, 2400);
    BudgetedRandomAccessSource limited(limited_raw, budget);
    ok &= Check(!Walk(limited, records, visited, error) && records.empty() && visited.empty() &&
        limited_raw.reads == 3 && error == "ApfsReadBudgetRecordLimit",
        "retained mapping index participates in the cumulative materialization budget");
    const auto reads = limited_raw.reads;
    ok &= Check(!Walk(limited, records, visited, error) && limited_raw.reads == reads,
        "index-budget refusal stays sticky");
    return ok;
}
} // namespace apfsaccess::omap_lookup_tests
