#define NOMINMAX
#include <windows.h>
#include "EncryptedDeltaData.h"
#include "EncryptedDeltaTree.h"
#include "ApfsEncryptedWriteTransform.h"
#include <iostream>
#include <map>
#include <stdexcept>

namespace c = apfsaccess::catalog;
namespace r = apfsaccess::rw;
namespace d = c::encrypted_delta;
namespace crypto = apfsaccess::crypto;
unsigned checks = 0;
void Check(bool ok, const std::string& reason) { ++checks; if (!ok) throw std::runtime_error(reason); }
std::byte Pattern(std::uint64_t at) { return static_cast<std::byte>((at * 17 + at / 4096 * 11 + 53) % 251); }
r::AppleEncryptedFileExtentRecord Extent(std::uint64_t size)
{ return {{21, 0, size, 1000, 1ULL << 51, 4096}, 1}; }
void Data()
{
    std::string error; d::DataPlan plan;
    const std::uint64_t old_size = (1ULL << 32) + 4096;
    const auto original = Extent(old_size);
    const std::array<std::byte, 2> patch{std::byte{0xFE}, std::byte{0xFD}};
    c::EncryptedMutationRequest request; request.inode = 21; request.offset = (1ULL << 32) - 1; request.data = patch;
    Check(d::PlanData(std::span(&original, 1), 21, old_size, request, 64, plan, error), "64BitPlan:" + error);
    Check(plan.changed == std::vector<std::uint64_t>{(1ULL << 20) - 1, 1ULL << 20} && plan.preserved.size() == 1,
        "TwoBlocksForFourGiBFile");
    Check(plan.preserved.front().extent.length_bytes == (1ULL << 32) - 4096 &&
        plan.preserved.front().extent.physical_block == original.extent.physical_block &&
        plan.preserved.front().extent.crypto_id == original.extent.crypto_id && plan.preserved.front().flags == original.flags,
        "UnchangedPrefixExact");
    auto buffer = crypto::SecureBytes::Allocate(4096); Check(static_cast<bool>(buffer), "Locked4KiB");
    std::size_t reads = 0;
    const auto read = [&](const r::AppleFileExtentRecord& e, std::uint64_t index, crypto::SecureBytes& out, std::string&) {
        ++reads;
        for (std::size_t i = 0; i != 4096; ++i) out.Bytes()[i] = Pattern(e.logical_address + index * 4096 + i);
        return true;
    };
    for (auto logical : plan.changed)
    {
        Check(d::RenderBlock(plan, request, logical, buffer.bytes, read, error), "Render:" + error);
        for (unsigned i = 0; i != 4096; ++i)
        {
            const auto at = logical * 4096 + i;
            Check(buffer.bytes.Bytes()[i] == (at == request.offset ? patch[0] : at == request.offset + 1 ? patch[1] : Pattern(at)), "BoundaryKnownAnswer");
        }
    }
    Check(reads == 2 && buffer.bytes.Size() == 4096, "BoundedReadAndLockedPlaintext");
    std::vector<r::AppleEncryptedFileExtentRecord> bound;
    const std::array<std::uint64_t, 2> physical{2000000, 2000007}, units{(1ULL << 51) + 2000000, (1ULL << 51) + 2000007};
    Check(d::BindData(plan, physical, units, 1, bound, error) && bound.size() == 3, "BindNoncontiguous");
    auto reused = physical; reused[0] = 1001;
    Check(!d::BindData(plan, reused, units, 1, bound, error) && bound.empty(), "RejectOldPhysicalReuse");
    auto reused_units = units; reused_units[0] = original.extent.crypto_id + 1;
    Check(!d::BindData(plan, physical, reused_units, 1, bound, error), "RejectOldTweakReuse");
    request = {}; request.kind = c::EncryptedMutationKind::Resize; request.size = old_size - 4095;
    Check(d::PlanData(std::span(&original, 1), 21, old_size, request, 64, plan, error) && plan.changed.size() == 1, "LargeShrinkTailOnly");
    Check(d::RenderBlock(plan, request, plan.changed.front(), buffer.bytes, read, error), "ShrinkRender");
    Check(buffer.bytes.Bytes()[0] == Pattern(old_size - 4096) &&
        std::all_of(buffer.bytes.Bytes().begin() + 1, buffer.bytes.Bytes().end(), [](auto b) { return b == std::byte{}; }), "ShrinkTailZeroed");
    request.size = old_size + 65 * 4096;
    Check(!d::PlanData(std::span(&original, 1), 21, old_size, request, 64, plan, error) &&
        error == "EncryptedDeltaChangedBlockCapacityLimit" && plan.changed.empty(), "GrowthCapacityTruthful");
    const auto short_extent = Extent(4096);
    request.size = 8195;
    Check(d::PlanData(std::span(&short_extent, 1), 21, 22, request, 64, plan, error) && plan.changed.size() == 3, "GrowthPartialOldPlusNew");
    for (auto logical : plan.changed)
    {
        Check(d::RenderBlock(plan, request, logical, buffer.bytes, read, error), "GrowRender");
        for (unsigned i = 0; i != 4096; ++i)
        { const auto at = logical * 4096 + i; Check(buffer.bytes.Bytes()[i] == (at < 22 ? Pattern(at) : std::byte{}), "GrowKnownAnswer"); }
    }
    const auto failed = [](const auto&, auto, auto& out, auto&) { out.Bytes()[0] = std::byte{0xF1}; return false; };
    Check(!d::RenderBlock(plan, request, 0, buffer.bytes, failed, error) &&
        std::all_of(buffer.bytes.Bytes().begin(), buffer.bytes.Bytes().end(), [](auto b) { return b == std::byte{}; }), "ReadFailureWipesBlock");
    buffer.bytes.Bytes()[0] = std::byte{0xF1};
    Check(!d::RenderBlock(plan, request, UINT64_MAX, buffer.bytes, read, error) &&
        std::all_of(buffer.bytes.Bytes().begin(), buffer.bytes.Bytes().end(), [](auto b) { return b == std::byte{}; }), "InvalidRenderWipesBlock");
    request.size = UINT64_MAX;
    Check(!d::PlanData(std::span(&short_extent, 1), 21, 22, request, 64, plan, error), "OverflowRefused");
    auto prefix = Extent(8192), suffix = Extent(8192);
    suffix.extent.logical_address = 8192;
    suffix.extent.physical_block = prefix.extent.physical_block + 1;
    suffix.extent.crypto_id += 2;
    auto split = std::array{prefix, suffix};
    request = {}; request.offset = 8191; request.data = patch;
    Check(!d::PlanData(split, 21, 16384, request, 64, plan, error) &&
        error == "EncryptedDeltaOriginalExtentOverlap", "OriginalPhysicalOverlapRefused");
    split[1].extent.physical_block += 1; split[1].extent.crypto_id -= 1;
    Check(!d::PlanData(split, 21, 16384, request, 64, plan, error) &&
        error == "EncryptedDeltaOriginalExtentOverlap", "OriginalTweakOverlapRefused");
    split[1].extent.crypto_id += 1;
    Check(d::PlanData(split, 21, 16384, request, 64, plan, error) && plan.preserved.size() == 2,
        "InteriorPatchPreservesPrefixAndSuffix");
    Check(plan.preserved[1].extent.logical_address == 12288 && plan.preserved[1].extent.length_bytes == 4096 &&
        plan.preserved[1].extent.physical_block == 1003 && plan.preserved[1].extent.crypto_id == (1ULL << 51) + 3,
        "PreservedSuffixPhysicalAndTweakOffsets");
}
struct TreeSource final : c::RandomAccessSource
{
    std::map<std::uint64_t, std::vector<std::byte>> nodes;
    std::shared_ptr<c::ApfsReadBudget> budget = std::make_shared<c::ApfsReadBudget>(1000000, 256ULL << 20, 1000000, 256ULL << 20);
    std::uint64_t SizeBytes() const override { return 1ULL << 32; }
    std::shared_ptr<c::ApfsReadBudget> ReadBudget() const override { return budget; }
    bool Read(std::uint64_t at, std::size_t size, std::vector<std::byte>& out) const override
    {
        out.clear(); const auto found = nodes.find(at / 4096);
        if (at % 4096 || size != 4096 || found == nodes.end() || !budget->Read(size)) return false;
        out = found->second; return true;
    }
};
struct DecryptNodes final : c::BtreeNodeReadContext
{
    TreeSource& source; const crypto::SecureBytes& key;
    crypto::SecureBytes node;
    DecryptNodes(TreeSource& s, const crypto::SecureBytes& k) : source(s), key(k) {}
    void ReleaseNode() noexcept override { node.Clear(); }
    bool ReadNode(std::uint64_t, std::uint64_t physical, bool,
        std::span<const std::byte>& bytes, std::string&) override
    {
        bytes = {}; ReleaseNode(); std::vector<std::byte> cipher;
        if (!source.Read(physical * 4096, 4096, cipher)) return false;
        auto locked = crypto::SecureBytes::Allocate(4096); if (!locked) return false;
        node = std::move(locked.bytes);
        for (std::size_t at = 0; at != 4096; at += 512)
        {
            std::array<std::byte, 16> tweak{}; const auto unit = physical * 8 + at / 512;
            for (unsigned i = 0; i != 8; ++i) tweak[i] = static_cast<std::byte>(unit >> (i * 8));
            auto plain = crypto::XtsTransform(key.Bytes(), tweak, std::span(cipher).subspan(at, 512), crypto::XtsDirection::Decrypt);
            if (!plain) return false;
            std::copy(plain.bytes.Bytes().begin(), plain.bytes.Bytes().end(), node.Bytes().begin() + at);
        }
        bytes = node.Bytes(); return true;
    }
};
void Tree(bool encrypted)
{
    std::string error; std::vector<c::BtreeRecord> records;
    for (unsigned i = 0; i != 20000; ++i)
    {
        c::BtreeRecord row;
        if (encrypted) Check(r::EncodeAppleEncryptedFileExtentRecord({{21, std::uint64_t(i) * 4096, 4096, 100000 + i,
            (1ULL << 51) + i, 4096}, 1}, r::AppleEncryptedExtentProfile::OneKeyGenerationZero, row, error), "EncodeFs");
        else Check(r::EncodeAppleOmapRecord({1000 + i, 42, 0, 4096, 30000 + i}, row, error), "EncodeOmap");
        records.push_back(std::move(row));
    }
    r::AppleBtreeOptions shape; shape.block_size = 4096; shape.xid = 42;
    shape.storage_type = encrypted ? 0 : c::kObjectPhysical;
    shape.subtype = encrypted ? c::kObjectTypeFsTree : c::kObjectTypeOmap;
    shape.tree_flags = encrypted ? 0 : r::kAppleBtreePhysical;
    const auto order = encrypted ? r::AppleBtreeKeyOrder::FileSystemCaseSensitive : r::AppleBtreeKeyOrder::ObjectMap;
    d::TreeSize size;
    Check(d::SizeTree(records, shape, order, 512, size, error) && size.height >= 2 && size.nodes > 2, "CanonicalThreeLevels:" + error);
    std::vector<d::NodeReservation> reserved;
    for (std::size_t i = 0; i != size.nodes; ++i)
    { const auto block = 10000 + i * 7; reserved.push_back({encrypted ? 90000 + i * 11 : block, block}); }
    r::AppleSerializedBtree serialized;
    Check(d::SerializeReservedTree(records, shape, order, reserved, serialized, error), "NoncontiguousTree:" + error);
    TreeSource source;
    auto key = crypto::SecureBytes::Allocate(32); Check(static_cast<bool>(key), "TreeKey");
    for (unsigned i = 0; i != 32; ++i) key.bytes.Bytes()[i] = static_cast<std::byte>(i + 1);
    for (auto& object : serialized.objects)
    {
        if (encrypted)
        {
            const auto type = c::ReadU32LE(object.bytes, 24).value() | 0x10000000u;
            for (unsigned i = 0; i != 4; ++i) object.bytes[24 + i] = static_cast<std::byte>(type >> (i * 8));
            Check(r::FinalizeAppleObjectChecksum(object.bytes, error), "FinalizeEncryptedNode");
            auto cipher = c::EncryptAppleMetadataBlock(key.bytes.Bytes(), object.location.physical_block, object.bytes);
            Check(static_cast<bool>(cipher), "EncryptNode"); source.nodes.emplace(object.location.physical_block, std::move(cipher.bytes));
            std::fill(object.bytes.begin(), object.bytes.end(), std::byte{});
        }
        else source.nodes.emplace(object.location.physical_block, object.bytes);
    }
    c::BtreeReadPolicy policy;
    policy.enforce_object_identity = true; policy.require_complete_traversal = true; policy.reject_unsupported_flags = true;
    policy.root_object_id = reserved.front().oid; policy.storage_type = shape.storage_type; policy.subtype = shape.subtype;
    policy.virtual_child_resolver = [&](std::uint64_t oid, std::string&) -> std::optional<c::BtreeVirtualChildMapping> {
        for (const auto& n : reserved) if (n.oid == oid) return c::BtreeVirtualChildMapping{n.physical, 42, 4, 4096};
        return {};
    };
    DecryptNodes context(source, key.bytes);
    std::vector<c::BtreeRecord> reopened;
    Check(c::ReadBtreeLeafRecords(source, 4096, reserved.front().physical, !encrypted, 0, 42, policy, reopened, error,
        encrypted ? &context : nullptr), "CanonicalReopen:" + error);
    Check(reopened.size() == records.size(), "CompleteTreeCount");
    for (std::size_t i = 0; i != records.size(); ++i)
        Check(records[i].key == reopened[i].key && records[i].value == reopened[i].value, "CanonicalTreeRecordExact");
    auto overlap = reserved; overlap.back().physical = overlap.front().physical;
    Check(!d::SerializeReservedTree(records, shape, order, overlap, serialized, error) && serialized.objects.empty(), "DuplicateReservationRefuses");
    auto surplus = reserved; const auto b = reserved.back().physical + 7;
    surplus.push_back({encrypted ? reserved.back().oid + 11 : b, b});
    Check(!d::SerializeReservedTree(records, shape, order, surplus, serialized, error) && serialized.objects.empty(), "SurplusReservationRefuses");
    Check(!d::SizeTree(records, shape, order, 1, size, error), "MetadataWorkLimitRefuses");
}
int main()
{
    try { Data(); Tree(false); Tree(true); std::cout << "PASS delta data and canonical three-level trees: " << checks << " assertions\n"; return 0; }
    catch (const std::exception& ex) { std::cerr << "FAIL:" << ex.what() << '\n'; return 1; }
}
