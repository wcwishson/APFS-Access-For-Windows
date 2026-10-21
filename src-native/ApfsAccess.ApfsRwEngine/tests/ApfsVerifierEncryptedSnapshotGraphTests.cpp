#include "ApfsProfileSnapshotGraph.h"
#include "ApfsVerifierEncryptedSource.h"
#include "ApfsSpaceAccounting.h"
#include <filesystem>
#include <fstream>
#define APFS_ENCRYPTED_SNAPSHOT_OWNERSHIP_FIXTURES_ONLY
#include "ApfsEncryptedSnapshotOwnershipTests.cpp"
#undef APFS_ENCRYPTED_SNAPSHOT_OWNERSHIP_FIXTURES_ONLY

namespace
{
void GraphCheck(bool okay, const std::string& reason)
{ ++checks; if (!okay) throw std::runtime_error(reason); }
void SnapshotExtentTree(Source& source, unsigned fault)
{
    std::vector<BtreeRecord> records; std::string error;
    if (fault != 1) {
        rw::ApplePhysicalExtentRecord extent{100, 1, rw::kApplePhysicalExtentKindNew, fault == 2 ? 101ull : 100ull, 1};
        BtreeRecord record; GraphCheck(rw::EncodeApplePhysicalExtentRecord(extent, record, error), error);
        records.push_back(std::move(record));
    }
    rw::AppleBtreeOptions options; options.block_size = 4096; options.xid = 8;
    options.root_object_id = options.root_physical_block = 74;
    options.storage_type = kObjectPhysical; options.tree_flags = rw::kAppleBtreePhysical;
    options.subtype = kObjectTypeBlockRefTree; options.key_order = rw::AppleBtreeKeyOrder::PhysicalExtent;
    rw::AppleSerializedBtree tree; GraphCheck(rw::SerializeAppleBtree(records, options, tree, error), error);
    Check(tree.objects.size() == 1, "single canonical extent layer fixture");
    if (fault == 3) {
        auto& bytes = tree.objects.front().bytes;
        const auto& value = records.front().value;
        const auto at = std::search(bytes.begin() + 0x38, bytes.end() - 40, value.begin(), value.end());
        Check(at != bytes.end() - 40, "canonical physical record value for malformed-kind control");
        *(at + 7) |= std::byte{0xF0};
    }
    Put(source, 74, tree.objects.front().bytes);
    Edit(source, 70, [](auto& bytes) { PutU64LE(bytes, 0x90, 74); PutU64LE(bytes, 0x58, 17); });
    const auto inventory_oid = ReadU64LE(source.image, 4 * 4096 + 0x98).value();
    GraphCheck(ReadBtreeLeafRecords(source, 4096, 72, false, 92, 8, records, error), error);
    for (auto& record : records) if ((ReadU64LE(record.key, 0).value() >> 60) == 1) PutU64LE(record.value, 0, 74);
    options.root_object_id = inventory_oid; options.root_physical_block = 72;
    options.storage_type = 0; options.tree_flags = 0; options.subtype = kObjectTypeSnapMetaTree;
    options.key_order = rw::AppleBtreeKeyOrder::FileSystemCaseSensitive;
    GraphCheck(rw::SerializeAppleBtree(records, options, tree, error) && tree.objects.size() == 1, error);
    Put(source, 72, tree.objects.front().bytes);
}
void AllocateGraph(Source& source, std::uint64_t endpoint)
{
    std::string error;
    const auto container = LoadContainerCheckpointView(source, 0, source.SizeBytes(), error, endpoint);
    GraphCheck(container.has_value(), error); AppleSpacemanView allocation;
    GraphCheck(LoadAppleSpacemanOwnershipView(source, *container, allocation, error), error);
    Check(allocation.chunks.size() == 1 && allocation.devices[0].cibs.size() == 1,
        "fixture allocator is canonical single chunk");
    const auto& chunk = allocation.chunks.front();
    auto bitmap = chunk.allocation_bitmap;
    for (std::uint64_t block = 0; block < 128; ++block) {
        const auto begin = source.image.begin() + block * 4096;
        if (block == 100 || std::any_of(begin, begin + 4096, [](auto byte) { return byte != std::byte{0}; }))
            bitmap.at(block / 8) |= std::byte(1u << (block % 8));
    }
    // The allocator still owns reserved rings and inactive pool slots. Preserve
    // its original bits and update only the canonical free-count fields.
    std::uint64_t allocated = 0;
    for (std::uint64_t block = 0; block < 128; ++block)
        allocated += (std::to_integer<unsigned>(bitmap.at(block / 8)) >> (block % 8)) & 1;
    std::copy(bitmap.begin(), bitmap.end(), source.image.begin() + chunk.bitmap_block * 4096);
    Edit(source, allocation.devices[0].cibs.front().object.physical_block,
        [&](auto& bytes) { PutU32LE(bytes, 0x3C, static_cast<std::uint32_t>(128 - allocated)); });
    for (std::uint64_t block = container->superblock.xp_data_base_block;
        block < container->superblock.xp_data_base_block + container->superblock.xp_data_block_count; ++block)
        if (ReadU32LE(source.image, block * 4096 + 24).value_or(0) == (kObjectEphemeral | kObjectTypeSpaceman))
            Edit(source, block, [&](auto& bytes) { PutU64LE(bytes, 0x48, 128 - allocated); });
}
std::shared_ptr<Source> GraphSource(unsigned extent_fault = 0, bool retained = true)
{
    auto source = std::make_shared<Source>(); AddSnapshot(*source); SnapshotExtentTree(*source, extent_fault);
    if (retained) AddCheckpoint(*source);
    AllocateGraph(*source, retained ? 9 : 8); return source;
}
VerificationScope EncryptedGraphScope(const Source& source, std::uint64_t xid)
{
    VerificationScope scope; scope.source_identity = source.SourceIdentity();
    scope.exact = {0, source.SizeBytes(), std::string(fixture::ContainerUuid), std::string(fixture::VolumeUuid), 101, xid};
    return scope;
}
std::pair<std::shared_ptr<ApfsVerifierEncryptedSource>, std::unique_ptr<ApfsEncryptedReadSession>>
OpenGraph(const std::shared_ptr<Source>& source, const VerificationScope& scope)
{
    auto observed = std::make_shared<ApfsVerifierEncryptedSource>(source, scope, [] { return true; });
    auto selection = Selection(); selection.checkpoint_xid = scope.exact.checkpoint_xid;
    PasswordUnlockBudget attempts; EncryptedReadError status; UnlockError unlock;
    auto session = ApfsEncryptedReadSession::Unlock(observed, observed->SourceIdentity(), observed->Revision(),
        selection, HexToBytes(std::string(fixture::Password)), attempts, status, unlock);
    Check(session != nullptr, "observational wrapper must be held before canonical unlock");
    return {std::move(observed), std::move(session)};
}
ProfileSnapshotGraphReport VerifyGraph(const ApfsVerifierEncryptedSource& observed, ApfsEncryptedReadSession& session,
    const VerificationScope& scope, std::optional<std::uint64_t> from)
{
    return VerifyEncryptedSnapshotProfile(observed, session, scope, from, [] { return true; });
}
void FailedGraph(const ProfileSnapshotGraphReport& report)
{
    Check(report.outcome != VerificationOutcome::Complete && !report.findings.empty(), "invalid encrypted graph published complete");
    Check(!report.selected && report.stores.empty() && report.chain_xids.empty() && report.checkpoints.empty() &&
        !report.allocation_unit_bytes, "invalid encrypted graph published partial evidence");
    Check(!report.snapshot_allocation_charge_bytes && !report.apple_purgeable_bytes && !report.reclaimable_bytes,
        "graph failure manufactured a charge");
}
void RunGraphCases()
{
    for (const bool retained : {false, true})
    {
        auto source = GraphSource(0, retained);
        const auto before = source->image; const auto scope = EncryptedGraphScope(*source, retained ? 9 : 8);
        auto [observed, session] = OpenGraph(source, scope);
        std::string error;
        for (unsigned repeat = 0; repeat < 2; ++repeat)
        {
            const auto report = VerifyGraph(*observed, *session, scope, retained ? std::optional<std::uint64_t>{8} : std::nullopt);
            Check(report.outcome == VerificationOutcome::Complete,
                (report.findings.empty() ? "no complete encrypted graph" : report.findings.front().detail).c_str());
            Check(report.selected && report.chain_xids == (retained ? std::vector<std::uint64_t>{8, 9} : std::vector<std::uint64_t>{8}) &&
                report.checkpoints.size() == (retained ? 2 : 1), "exact requested historical parent chain");
            for (const auto& checkpoint : report.checkpoints) {
                Check(checkpoint.views.size() == 2 && checkpoint.views[0].view_xid == 7 && !checkpoint.views[0].current &&
                    checkpoint.views[1].current, "snapshot namespace and parent namespace both verified");
                Check(checkpoint.views[0].descriptor.xid == 8 && checkpoint.views[0].declared_filesystem_allocation.blocks == 17,
                    "COW descriptor generation and parsed counter retained separately from snapshot XID");
                Check(checkpoint.protected_graph.payload_ranges.size() == 1 &&
                    checkpoint.protected_graph.payload_ranges.front().physical_block == 100 &&
                    checkpoint.protected_graph.payload_ranges.front().block_count == 1, "shared snapshot/current payload was summed");
            }
            Check(!report.snapshot_allocation_charge_bytes && !report.apple_purgeable_bytes && !report.reclaimable_bytes,
                "saved volume counter became an Apple charge");
            std::optional<ApfsProfileSnapshotSpaceAttribution> amounts;
            GraphCheck(TryAttributeVerifiedProfileSnapshotSpace(report, amounts, error, [] { return true; }), error);
            Check(amounts && amounts->complete && amounts->snapshots.size() == 1 &&
                amounts->referenced_snapshot_payload.blocks == 1 && amounts->live_payload.blocks == 1,
                "canonical encrypted snapshot/live unions feed actual bounded accounting");
            const auto& row = amounts->snapshots.front();
            Check(row.payload.referenced.blocks == 1 && row.payload.shared_with_live.blocks == 1 &&
                row.payload.absent_from_live.blocks == 0 && row.payload.potential_reclaim_upper_bound.blocks == 0 &&
                row.payload.retained_or_peer_protected.blocks == (retained ? 1 : 0),
                "retained proof and current sharing are separate physical set partitions");
            Check(row.declared_filesystem_allocation.blocks == 17 && !amounts->snapshot_allocation_charge &&
                !amounts->apple_purgeable && !amounts->reclaimable, "parsed descriptor counter is not a policy amount");
            if (retained) Check(!session->CreateRetainedVerificationContext(8, error),
                "strict old parent cannot accept snapshot-bearing wider profile");
        }
        Check(source->image == before, "verification mutated encrypted image"); ++cases;
    }
    for (unsigned fault = 1; fault <= 3; ++fault) {
        auto source = GraphSource(fault); const auto scope = EncryptedGraphScope(*source, 9);
        auto [observed, session] = OpenGraph(source, scope);
        FailedGraph(VerifyGraph(*observed, *session, scope, 8)); ++cases;
    }
    for (unsigned fault = 0; fault < 7; ++fault)
    {
        auto source = GraphSource(); auto scope = EncryptedGraphScope(*source, 9);
        auto [observed, session] = OpenGraph(source, scope);
        if (fault == 0) source->image[80 * 4096 + 100] ^= std::byte{1};
        if (fault == 1) ++source->revision;
        if (fault == 2) session->Cancel();
        if (fault == 3) source->budget->LimitRemainingTo(1, 4096, 100, 4096);
        if (fault == 4) scope.exact.volume_oid = 102;
        if (fault == 5) scope.require_whole_volume = true;
        if (fault == 6) source->on_read = [&](auto at) { if (at == 80 * 4096) session->Cancel(); };
        FailedGraph(VerifyGraph(*observed, *session, scope, 8)); ++cases;
    }
}
}
int main(int argc, char** argv) try
{
    if (argc == 3 && std::string_view(argv[1]) == "--export") {
        const auto root = std::filesystem::absolute(argv[2]).lexically_normal();
        Check(root.wstring().starts_with(L"D:\\ApfsAccessScratch\\") && std::filesystem::create_directories(root), "new D-only synthetic fixture folder");
        const auto source = GraphSource(); std::ofstream file(root / "encrypted-snapshots.apfs", std::ios::binary);
        file.write(reinterpret_cast<const char*>(source->image.data()), static_cast<std::streamsize>(source->image.size()));
        Check(static_cast<bool>(file), "bounded canonical encrypted fixture export");
        std::cout << "PASS canonical synthetic encrypted snapshot image exported\n"; return 0;
    }
    Check(argc == 1, "known focused selector required");
    RunGraphCases();
    std::cout << "PASS " << cases << " cases / " << checks << " checks; opaque encrypted current/retained snapshot graphs\n";
    return 0;
}
catch (const std::exception& error)
{ std::cerr << "FAIL " << error.what() << " after " << checks << " checks\n"; return 1; }
