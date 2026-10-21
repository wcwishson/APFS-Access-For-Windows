#pragma once
// Shared synthetic two-member Fusion fixture (64 main + 32 data blocks at
// 4K by default): valid anchors, checkpoint, spaceman, empty middle tree and
// empty writeback cache for the CleanAnchorsEmptyCachesMainCheckpoint read
// profile. Moved verbatim from ApfsFusionStoreTests.cpp so writer-side gates
// exercise the identical image family; Good() throws instead of using a
// translation unit's Check so both consumers share it.
#include "ApfsFusionStore.h"
#include "TestFixtureBuilder.h"
#include <array>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace apfsaccess::fusiontest
{
using namespace apfsaccess::catalog;
using Bytes = std::vector<std::byte>;
inline void Put(Bytes& b, std::size_t at, std::uint64_t value, std::size_t width = 8)
{ for (std::size_t n = 0; n < width; ++n) b.at(at + n) = std::byte((value >> (8 * n)) & 255); }
inline void Seal(Bytes& b) { Put(b, 0, Fletcher64(b.data() + 8, b.size() - 8).value()); }
inline Bytes Object(std::size_t bs, std::uint64_t oid, std::uint32_t type, std::uint64_t xid = 20)
{
    Bytes b(bs); Put(b, 8, oid); Put(b, 16, xid); Put(b, 24, type, 4); Seal(b); return b;
}
inline Bytes MiddleTree(std::size_t bs, std::uint64_t oid, bool nonempty = false)
{
    auto b = Object(bs, oid, kObjectPhysical | kObjectTypeBtree);
    Put(b, 28, 0x15, 4); Put(b, 0x20, 7, 2); // physical root, leaf, fixed KV
    Put(b, 0x24, nonempty ? 1 : 0, 4); Put(b, 0x2A, nonempty ? 4 : 0, 2);
    Put(b, 0x2C, nonempty ? 8 : 0, 2);
    Put(b, 0x2E, bs - 40 - 0x38 - (nonempty ? 28 : 0), 2);
    Put(b, 0x30, 0xFFFF, 2); Put(b, 0x34, 0xFFFF, 2);
    const auto info = bs - 40;
    Put(b, info, 0x11, 4); Put(b, info + 4, bs, 4); Put(b, info + 8, 8, 4);
    Put(b, info + 12, 16, 4); Put(b, info + 16, nonempty ? 8 : 0, 4);
    Put(b, info + 20, nonempty ? 16 : 0, 4); Put(b, info + 24, nonempty ? 1 : 0);
    Put(b, info + 32, 1);
    if (nonempty)
    {
        Put(b, 0x38, 0, 2); Put(b, 0x3A, 16, 2);
        Put(b, 0x3C, kFusionTier2ByteAddress / bs + 20);
        Put(b, info - 16, 20); Put(b, info - 8, 1, 4); Put(b, info - 4, 1, 4);
    }
    Seal(b); return b;
}
struct Source final : RandomAccessSource
{
    Bytes bytes;
    bool present = true, short_read = false, false_read = false;
    mutable std::uint64_t calls = 0, bytes_read = 0;
    mutable std::vector<std::pair<std::uint64_t, std::size_t>> reads;
    std::shared_ptr<ApfsReadBudget> budget;
    std::function<void()> after_read;
    explicit Source(std::size_t size) : bytes(size) {}
    std::uint64_t SizeBytes() const override { return bytes.size(); }
    std::shared_ptr<ApfsReadBudget> ReadBudget() const override { return budget; }
    bool Read(std::uint64_t offset, std::size_t size, Bytes& out) const override
    {
        ++calls; bytes_read += size; reads.emplace_back(offset, size); out.clear();
        if (budget && !budget->Read(size)) return false;
        if (!present || offset > bytes.size() || size > bytes.size() - offset) return false;
        out.assign(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
            bytes.begin() + static_cast<std::ptrdiff_t>(offset + size));
        if (short_read && !out.empty()) out.pop_back();
        if (after_read) after_read();
        return !false_read;
    }
};
struct Fixture
{
    std::uint32_t bs;
    std::uint64_t prefix;
    std::array<std::shared_ptr<Source>, 2> sources;
    FusionBindRequest request;
    explicit Fixture(std::uint32_t block_size = 4096, std::uint64_t prefix_blocks = 0)
        : bs(block_size), prefix(prefix_blocks * block_size)
    {
        sources[0] = std::make_shared<Source>(static_cast<std::size_t>(prefix + 64 * bs));
        sources[1] = std::make_shared<Source>(static_cast<std::size_t>(prefix + 32 * bs));
        request.container_uuid_hex = std::string(32, 'a');
        request.fusion_uuid_hex = std::string(32, 'b'); request.fusion_uuid_hex.back() = 'a';
        request.checkpoint_xid = 20;
        request.convention = FusionRoleConvention::LinuxApfsLastByteLowBit;
        Budget();
        for (std::size_t i = 0; i < 2; ++i)
        {
            FusionImageMember m;
            m.exact_identity = {1, {}, sources[i]->SizeBytes(), 1, 2};
            m.exact_identity.file_id[0] = std::byte(i + 1);
            m.stable_store_id = i ? "apfs-store:test-tier2" : "apfs-store:test-main";
            m.role = i ? FusionMemberRole::Tier2 : FusionMemberRole::Main;
            m.store_offset = prefix; m.store_size = (i ? 32ULL : 64ULL) * bs;
            request.members.push_back(m);
        }
        auto nx = Object(bs, 1, kObjectEphemeral | kNxSuperblockObjectType);
        Put(nx, 0x20, kNxsbMagic, 4); Put(nx, 0x24, bs, 4); Put(nx, 0x28, 96);
        Put(nx, 0x40, 0x102); std::fill_n(nx.begin() + 0x48, 16, std::byte{0xAA});
        Put(nx, 0x58, 100); Put(nx, 0x60, 21);
        Put(nx, 0x68, 4, 4); Put(nx, 0x6C, 4, 4); Put(nx, 0x70, 1); Put(nx, 0x78, 8);
        Put(nx, 0x80, 2, 4); Put(nx, 0x84, 2, 4); Put(nx, 0x88, 0, 4);
        Put(nx, 0x8C, 2, 4); Put(nx, 0x90, 0, 4); Put(nx, 0x94, 2, 4);
        Put(nx, 0x98, 10); Put(nx, 0xA0, 15); Put(nx, 0xB4, 100, 4);
        std::fill_n(nx.begin() + 0x500, 16, std::byte{0xBB}); nx[0x50F] = std::byte{0xBA};
        Put(nx, 0x548, 17); Put(nx, 0x550, 19); Put(nx, 0x558, 24); Put(nx, 0x560, 4);
        Seal(nx); Place(0, 0, nx); Place(0, 2, nx);
        nx[0x50F] |= std::byte{1}; Seal(nx); Place(1, 0, nx);
        auto map = Object(bs, 1, kObjectPhysical | kObjectTypeCheckpointMap);
        Put(map, 0x20, 1, 4); Put(map, 0x24, 2, 4);
        Put(map, 0x28, kObjectEphemeral | kObjectTypeSpaceman, 4);
        Put(map, 0x30, bs, 4); Put(map, 0x40, 10); Put(map, 0x48, 8);
        Put(map, 0x50, kObjectEphemeral | 0x16, 4); Put(map, 0x58, bs, 4);
        Put(map, 0x68, 19); Put(map, 0x70, 9); Seal(map); Place(0, 1, map);
        auto sm = Object(bs, 10, kObjectEphemeral | kObjectTypeSpaceman);
        Put(sm, 0x20, bs, 4); Put(sm, 0x24, 8ULL * bs, 4);
        Put(sm, 0x28, (bs - 0x28) / 0x20, 4); Put(sm, 0x2C, (bs - 0x28) / 8, 4);
        for (std::size_t i = 0; i < 2; ++i)
        { auto at = 0x30 + i * 0x30; Put(sm, at, i ? 32 : 64); Put(sm, at + 8, 1); Put(sm, at + 0x10, 1, 4); }
        Put(sm, 0x154, 0x158, 4); Seal(sm); Place(0, 8, sm);
        auto cache = Object(bs, 19, kObjectEphemeral | 0x16);
        Put(cache, 0x20, 0x70); Seal(cache); Place(0, 9, cache);
        Place(0, 17, MiddleTree(bs, 17));
        Place(0, 16, Object(bs, 16, kObjectPhysical | kObjectTypeFs));
        Place(1, 4, Object(bs, TierBlock() + 4, kObjectPhysical | kObjectTypeFs));
        for (std::size_t i = 0; i < 2; ++i)
        {
            Place(i, 20, Bytes(bs, std::byte(i ? 0xB1 : 0xA1)));
            Place(i, 21, Bytes(bs, std::byte(i ? 0xB2 : 0xA2)));
        }
    }
    std::uint64_t TierBlock() const { return kFusionTier2ByteAddress / bs; }
    void Budget(std::uint64_t reads = 10000, std::uint64_t bytes = 64 * 1024 * 1024,
        std::uint64_t records = 10000, std::uint64_t material = 64 * 1024 * 1024)
    { request.budget = std::make_shared<ApfsReadBudget>(reads, bytes, records, material); }
    void Place(std::size_t member, std::uint64_t block, const Bytes& bytes)
    { std::copy(bytes.begin(), bytes.end(), sources[member]->bytes.begin() + static_cast<std::ptrdiff_t>(prefix + block * bs)); }
    Bytes Block(std::size_t member, std::uint64_t block)
    {
        const auto at = static_cast<std::ptrdiff_t>(prefix + block * bs);
        return Bytes(sources[member]->bytes.begin() + at, sources[member]->bytes.begin() + at + bs);
    }
    void Edit(std::size_t member, std::uint64_t block, const std::function<void(Bytes&)>& change)
    { auto b = Block(member, block); change(b); Seal(b); Place(member, block, b); }
    void EditNx(const std::function<void(Bytes&)>& change)
    { Edit(0, 0, change); Edit(0, 2, change); Edit(1, 0, change); }
    std::vector<ApfsFusionStore::TestMember> Inputs() const
    {
        std::vector<ApfsFusionStore::TestMember> out;
        for (const auto& m : request.members)
        { auto src = sources[m.role == FusionMemberRole::Main ? 0 : 1]; out.push_back({src, [src] { return src->present; }}); }
        return out;
    }
    std::unique_ptr<ApfsFusionStore> Bind(std::string& error)
    { return ApfsFusionStore::BindTestSources(request, Inputs(), error); }
    std::unique_ptr<ApfsFusionStore> Good()
    {
        std::string error; auto result = Bind(error);
        if (!result) throw std::runtime_error("bind failed: " + error);
        return result;
    }
    std::uint64_t Calls() const { return sources[0]->calls + sources[1]->calls; }
};
} // namespace apfsaccess::fusiontest
