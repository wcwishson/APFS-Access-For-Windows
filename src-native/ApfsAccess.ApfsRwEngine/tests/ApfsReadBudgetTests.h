#pragma once

#include "ApfsFormat.h"
#include "NativeApfsReader.h"
#include "TestFixtureBuilder.h"
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>

// Included and selected by ApfsCompatibilityTests.cpp; no registration side effects.
namespace apfsaccess::read_budget_tests
{
using namespace catalog;
namespace fixture = testfixture;
constexpr std::uint32_t BlockSize = 4096;
constexpr std::uint64_t Unlimited = (std::numeric_limits<std::uint64_t>::max)();

inline bool Check(bool condition, const char* message)
{
    if (!condition) std::cerr << "[FAIL] parser budget: " << message << '\n';
    return condition;
}

class CountingSource final : public RandomAccessSource
{
public:
    explicit CountingSource(std::vector<std::byte> bytes) : bytes_(std::move(bytes)) {}
    std::uint64_t SizeBytes() const override { return bytes_.size(); }
    bool Read(std::uint64_t offset, std::size_t size, std::vector<std::byte>& out) const override
    {
        ++reads;
        requested_bytes += size;
        out.clear();
        if (offset > bytes_.size() || size > bytes_.size() - offset) return false;
        out.assign(bytes_.begin() + static_cast<std::size_t>(offset),
            bytes_.begin() + static_cast<std::size_t>(offset) + size);
        return true;
    }
    mutable std::uint64_t reads = 0, requested_bytes = 0;
private:
    std::vector<std::byte> bytes_;
};

inline std::vector<std::byte> Leaf(std::size_t count = 1, std::size_t value_bytes = 8)
{
    std::vector<std::vector<std::byte>> keys, values;
    for (std::size_t i = 0; i < count; ++i)
    {
        std::vector<std::byte> key(8);
        fixture::PutU64LE(key, 0, i + 1);
        keys.push_back(key);
        values.emplace_back(value_bytes, std::byte{0x42});
    }
    return fixture::BuildRawLeafNode(keys, values, 7, BlockSize, 0, 1);
}

inline void Put(std::vector<std::byte>& image, std::size_t block, const std::vector<std::byte>& bytes)
{
    std::copy(bytes.begin(), bytes.end(), image.begin() + block * BlockSize);
}

inline bool Walk(const RandomAccessSource& source, std::vector<BtreeRecord>& records,
    std::string& error, std::vector<std::uint64_t>* visited = nullptr)
{
    BtreeReadPolicy policy;
    policy.require_complete_traversal = true;
    policy.visited_physical_blocks = visited;
    return ReadBtreeLeafRecords(source, BlockSize, 1, true, 0, 7, policy, records, error);
}

inline bool TestApfsBudgetRejectsReadBeforeAllocation()
{
    CountingSource raw(std::vector<std::byte>{});
    auto budget = std::make_shared<ApfsReadBudget>(10, BlockSize, 10, Unlimited);
    BudgetedRandomAccessSource source(raw, budget);
    std::vector<BtreeRecord> records(1);
    std::vector<std::uint64_t> visited{99};
    BtreeReadPolicy policy;
    policy.require_complete_traversal = true;
    policy.visited_physical_blocks = &visited;
    std::string error;
    const bool loaded = ReadBtreeLeafRecords(source, 1u << 20, 1, true, 0, 7,
        policy, records, error);
    return Check(!loaded && raw.reads == 0 && raw.requested_bytes == 0,
            "oversized node rejected before backing read/allocation") &&
        Check(records.empty() && visited.empty() && error == "ApfsReadBudgetSourceLimit",
            "failed node invalidates output and explains source limit");
}

inline bool TestApfsBudgetCumulativeViewsAndIdentity()
{
    const auto node = Leaf();
    std::vector<std::byte> image(3 * BlockSize);
    Put(image, 1, node); Put(image, 2, node);
    CountingSource raw(image);
    auto budget = std::make_shared<ApfsReadBudget>(2, 2 * BlockSize, 2, Unlimited);
    BudgetedRandomAccessSource source(raw, budget);
    OffsetRandomAccessSource offset(&source, BlockSize, 2 * BlockSize);
    BudgetedRandomAccessSource nested(offset, budget);
    std::vector<BtreeRecord> first, second, ordinary;
    std::string error;
    bool ok = Check(source.ReadBudget() == offset.ReadBudget() && nested.ReadBudget() == budget,
        "views propagate exactly the same budget");
    ok &= Check(Walk(source, first, error) && Walk(nested, second, error),
        "separate trees share allowance without double charging nested adapters");
    ok &= Check(raw.reads == 2 && raw.requested_bytes == 2 * BlockSize &&
        first.size() == 1 && second.size() == 1 && first[0].key == second[0].key &&
        first[0].value == second[0].value, "exact read count/bytes and record identity");
    ok &= Check(!Walk(source, second, error) && second.empty() && raw.reads == 2 &&
        error == "ApfsReadBudgetSourceLimit", "third tree cannot reset exhausted allowance");
    CountingSource unbudgeted(image);
    ok &= Check(Walk(unbudgeted, ordinary, error) && !first.empty() && ordinary.size() == first.size() &&
        ordinary[0].key == first[0].key && ordinary[0].value == first[0].value,
        "ordinary parser remains compatible");
    auto read_budget = std::make_shared<ApfsReadBudget>(1, BlockSize, 0, 0);
    BudgetedRandomAccessSource verify(unbudgeted, read_budget);
    std::vector<std::byte> observed;
    ok &= Check(verify.Read(BlockSize, BlockSize, observed) && observed == node &&
        VerifyObjectChecksum(observed, BlockSize) && ReadU64LE(observed, 8) == 1 &&
        ReadU64LE(observed, 16) == 7, "successful reads preserve bytes, checksum, OID and XID");
    // Isolate cumulative byte exhaustion from the read-count limit.
    auto bytes_only = std::make_shared<ApfsReadBudget>(Unlimited, BlockSize, 10, Unlimited);
    BudgetedRandomAccessSource bytes_view(unbudgeted, bytes_only);
    ok &= Check(Walk(bytes_view, ordinary, error) && !Walk(bytes_view, ordinary, error) &&
        ordinary.empty() && error == "ApfsReadBudgetSourceLimit", "read-byte allowance is cumulative");
    return ok;
}

inline bool TestApfsBudgetRecordsBeforeAppend()
{
    bool ok = true;
    for (const bool count_limit : {true, false})
    {
        std::vector<std::byte> image(2 * BlockSize);
        Put(image, 1, Leaf(2, 128));
        CountingSource raw(image);
        auto budget = std::make_shared<ApfsReadBudget>(10, Unlimited,
            count_limit ? 1 : Unlimited, count_limit ? Unlimited : 128);
        BudgetedRandomAccessSource source(raw, budget);
        std::vector<BtreeRecord> records(1);
        std::vector<std::uint64_t> visited{88};
        std::string error;
        ok &= Check(!Walk(source, records, error, &visited) && raw.reads == 1 &&
            records.empty() && visited.empty() && error == "ApfsReadBudgetRecordLimit",
            "record count/bytes refuse before copy/append and discard earlier records");
        ok &= Check(!Walk(source, records, error) && raw.reads == 1,
            "record exhaustion remains sticky across new trees");
    }
    return ok;
}

inline bool TestApfsBudgetMalformedWalkClearsOutput()
{
    auto node = Leaf(2);
    // Second key is absent, after the first valid record would be appended.
    fixture::PutU16LE(node, 0x40, 0xffffu);
    fixture::FletcherForBlock(node, BlockSize);
    std::vector<std::byte> image(2 * BlockSize); Put(image, 1, node);
    CountingSource raw(image);
    auto budget = std::make_shared<ApfsReadBudget>(10, Unlimited, 10, Unlimited);
    BudgetedRandomAccessSource source(raw, budget);
    std::vector<BtreeRecord> records(1);
    std::vector<std::uint64_t> visited{99}; std::string error;
    bool ok = Check(!Walk(source, records, error, &visited) && records.empty() && visited.empty() &&
        error == "CatalogBtreeMissingEntry" && !budget->Failed(),
        "strict unknown record invalidates earlier output independently of budget");
    node = Leaf(); node[100] ^= std::byte{1}; Put(image, 1, node);
    CountingSource corrupt(image);
    BudgetedRandomAccessSource corrupt_view(corrupt, budget);
    ok &= Check(!Walk(corrupt_view, records, error) && records.empty() &&
        error == "CatalogBtreeChecksumInvalid", "budget does not weaken checksum validation");
    return ok;
}

inline bool TestApfsBudgetRecursiveObjectMap()
{
    std::vector<std::byte> image(5 * BlockSize);
    std::vector<std::byte> key(8), child(8);
    fixture::PutU64LE(key, 0, 1); fixture::PutU64LE(child, 0, 55);
    auto root = fixture::BuildRawLeafNode({key}, {child}, 7, BlockSize, 0, 1);
    fixture::PutU16LE(root, 0x20, 1); // root, internal
    fixture::PutU16LE(root, 0x22, 1);
    fixture::FletcherForBlock(root, BlockSize);
    Put(image, 1, root);
    Put(image, 2, fixture::BuildOmap(3, 7, BlockSize));
    Put(image, 3, fixture::BuildBtreeNode(std::vector<fixture::OmapRecordSpec>{{55, 4, 0, 7}}, 7, BlockSize));
    // The child is deliberately not read: budget runs out in recursive OMAP.
    Put(image, 4, Leaf());
    CountingSource raw(image);
    auto budget = std::make_shared<ApfsReadBudget>(2, Unlimited, 10, Unlimited);
    BudgetedRandomAccessSource source(raw, budget);
    BtreeReadPolicy policy; policy.require_complete_traversal = true;
    std::vector<BtreeRecord> records(1); std::string error;
    return Check(!ReadBtreeLeafRecords(source, BlockSize, 1, false, 2, 7, policy, records, error) &&
        raw.reads == 2 && records.empty() && error == "ApfsReadBudgetSourceLimit",
        "recursive OMAP traversal spends the parent's source budget");
}

inline bool TestApfsBudgetCheckpointAndNativeAdapter()
{
    fixture::BuilderStore spec;
    spec.authoritative_checkpoint = true;
    const auto bytes = fixture::BuildStoreImage(spec);
    CountingSource raw(bytes);
    auto budget = std::make_shared<ApfsReadBudget>(10000, 64ULL << 20, 10000, 64ULL << 20);
    BudgetedRandomAccessSource source(raw, budget);
    std::string error;
    const auto checkpoint = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error, spec.xid);
    bool ok = Check(checkpoint.has_value(), "real encoded exact checkpoint accepts generous budget");

    // This fixture is created only when the parent runs this test, always on D:.
    struct ImageFile
    {
        std::filesystem::path path;
        ~ImageFile() { std::error_code ignored; if (!path.empty()) std::filesystem::remove(path, ignored); }
    } file;
    const std::filesystem::path directory =
        L"D:/Temp/ApfsAccess-read-budget";
    std::filesystem::create_directories(directory);
    for (unsigned i = 0; ; ++i)
    {
        const auto candidate = directory / ("apfs-read-budget-fixture-" + std::to_string(i) + ".img");
        if (!std::filesystem::exists(candidate)) { file.path = candidate; break; }
    }
    {
        std::ofstream stream(file.path, std::ios::binary);
        stream.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        if (!Check(stream.good(), "D: native fixture writes")) return false;
    }
    rw::BlockDevice device(file.path.wstring(), 0);
    rw::NativeApfsVolumeProjection ordinary, bounded;
    std::wstring native_error;
    ok &= Check(rw::NativeApfsReader::TryLoadVolumeProjection(device, spec.volumes[0].oid,
        ordinary, native_error, spec.xid), "ordinary exact projection remains available");
    ok &= Check(rw::NativeApfsReader::TryLoadVolumeProjection(device, spec.volumes[0].oid,
        bounded, native_error, spec.xid, budget), "same checkpoint budget crosses native device adapter");
    ok &= Check(bounded.checkpoint_xid == ordinary.checkpoint_xid &&
        bounded.volume_object_id == ordinary.volume_object_id &&
        bounded.root_tree_block == ordinary.root_tree_block &&
        !bounded.inodes.empty() && bounded.inodes.size() == ordinary.inodes.size(),
        "native budget preserves checkpoint/volume/root identity and projection");

    auto spent = std::make_shared<ApfsReadBudget>(1, BlockSize, 10, Unlimited);
    BudgetedRandomAccessSource prelude(raw, spent);
    std::vector<std::byte> probe;
    ok &= Check(prelude.Read(0, BlockSize, probe), "spend shared allowance before constructing adapter");
    std::uint64_t misses = 0;
    device.SetReadCacheMissHookForTests([&] { ++misses; });
    for (int attempt = 0; attempt < 2; ++attempt)
    {
        bounded = ordinary;
        ok &= Check(!rw::NativeApfsReader::TryLoadVolumeProjection(device, spec.volumes[0].oid,
            bounded, native_error, spec.xid, spent) && bounded.inodes.empty() &&
            bounded.checkpoint_xid == 0 && bounded.volume_object_id == 0 &&
            native_error == L"ApfsReadBudgetSourceLimit" && misses == 0,
            "recreated native adapters cannot reset budget or use direct-device fallback");
    }
    device.SetReadCacheMissHookForTests({});

    auto no_records = std::make_shared<ApfsReadBudget>(1000, Unlimited, 0, Unlimited);
    BudgetedRandomAccessSource limited(raw, no_records);
    ok &= Check(!LoadAppleCheckpointView(limited, 0, limited.SizeBytes(), error, spec.xid) &&
        error == "ApfsReadBudgetRecordLimit", "checkpoint record allocations honor caller allowance");
    return ok;
}
} // namespace apfsaccess::read_budget_tests
