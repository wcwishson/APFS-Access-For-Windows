#define wmain FormatStreamedFixtureMain
#include "VolumeFormatStreamedTests.cpp"
#undef wmain
#include "../src/VolumeResizeRelocation.h"
#include "../src/VolumeGptGeometry.h"
#include "VolumeResizeRelocationFixture.h"

VolumeImageRequest RelocationImage(const std::string& name, bool payload)
{
    auto format = Large(name); const auto prepared = PrepareVolumeFormat(format);
    Check(prepared.outcome == VolumeImageOutcome::Prepared, "actual source format prepare: " + prepared.error);
    Check(ApplyVolumeFormat(format, prepared.token).outcome == VolumeImageOutcome::Committed, "actual source format apply");
    VolumeImageRequest r; r.image = format.image; r.journal_directory = format.journal_directory;
    r.operation = VolumeImageOperation::Shrink; r.expected_bytes = format.expected_bytes;
    r.target_bytes = (3 * mc::ChunkBlocks - 25) * 4096;
    { Target target(r.image); if (payload) { mc::NativeWrite(target); MoveFixturePayloadToTail(target); } const auto cp = mc::Load(target);
      r.container_uuid = cp.container.superblock.uuid_hex; r.volume_uuid = cp.volumes.front().superblock.uuid_hex;
      r.volume_oid = cp.volumes.front().superblock.object_id; r.checkpoint_xid = cp.container.superblock.xid; }
    r.sibling_wals = {{r.volume_oid, format.new_volume_wal}}; return r;
}
void RetainedPayload(Target& target, bool payload)
{
    const auto cp = mc::Load(target); mc::Verify(target, cp); const auto& v = cp.volumes.front(); std::string error;
    std::vector<apfsaccess::catalog::BtreeRecord> records;
    Check(ReadAppleVolumeFileSystemRecords(target, cp.container, v, records, error), error);
    std::size_t bytes = 0;
    for (const auto& r : records) if ((ReadU64LE(r.key, 0).value_or(0) >> 60) == 8) {
        AppleFileExtentRecord extent; Check(DecodeAppleFileExtentRecord(r, 4096, extent, error), error);
        if (extent.object_id != 1030) continue;
        Bytes actual; Check(target.Read(extent.physical_block * 4096, static_cast<std::size_t>(extent.length_bytes), actual) &&
            std::all_of(actual.begin(), actual.end(), [](auto b) { return b == std::byte{0x59}; }), "complete original payload remains exact");
        bytes += actual.size();
    }
    Check(bytes == (payload ? 8192 : 0), "exact original stream length");
}
void NativeMetadataWrite(Target& target)
{
    const auto cp = mc::Load(target); AppleVolumeTransactionRequest r; r.volume_object_id = cp.volumes.front().superblock.object_id;
    r.last_modification_time = 1700000000000000001ull; std::string error;
    Check(ReadAppleVolumeFileSystemRecords(target, cp.container, cp.volumes.front(), r.filesystem_records, error), error);
    AppleVolumeTransactionPlan plan; Check(PlanAppleVolumeTransaction(target, cp, r, plan, error), "fresh ordinary metadata plan: " + error);
    Check(ExecuteAppleCheckpointPublication(target, plan.commit.publication, error), "fresh ordinary metadata publication: " + error);
}
void PositiveRelocation()
{
    for (bool payload : {false, true}) {
        auto r = RelocationImage(payload ? "positive-payload" : "positive-empty", payload); const auto before = Digests(r.image);
        { Target target(r.image); Check(vi::InspectResizeRelocationSource(target, r).physical_snapshot_root_in_tail,
            "current formatter places physical snapshot metadata in the relocation tail"); }
        const auto p = PrepareVolumeResize(r); Check(p.outcome == VolumeImageOutcome::Prepared, "relocation prepare: " + p.error);
        Check(Digests(r.image) == before, "all source bytes unchanged by relocation preparation");
        const auto frame = Read(p.journal);
        Check(ReadU64LE(frame, 0) == volume_geometry::PhysicalSnapshotRelocationMagic &&
            ReadU64LE(frame, 48) == static_cast<std::uint64_t>(r.operation), "bounded physical-snapshot relocation frame and exact operation");
        const auto applied = ApplyVolumeResize(r, p.token); Check(applied.outcome == VolumeImageOutcome::Committed, "actual relocation apply: " + applied.error);
        Check(std::filesystem::file_size(r.image) == r.target_bytes, "actual relocation EOF");
        Check(RecoverVolumeResize(r).outcome == VolumeImageOutcome::Committed, "fresh completed relocation recovery");
        { Target target(r.image); RetainedPayload(target, payload); auto history = AcquireVolumeKeeperHistory(p.source_identity, target, r.journal_directory, {});
          NativeMetadataWrite(target); RetainedPayload(target, payload); }
        Check(RecoverVolumeResize(r).outcome == VolumeImageOutcome::Committed, "later native generation reopens VIF5 history");
        Check(InspectVolumeKeeperImage(r.image, 0, r.journal_directory).admitted, "completed relocation authorizes ordinary admission");
    }
    Pass("actual bootstrap and queue relocation preserves files and native write/reopen");
}
void RelocationCuts()
{
    const std::vector<std::string> stages{"after-image-accept", "before-apple-prepublication-flush", "before-apple-checkpoint-switch",
        "before-image-anchor", "after-image-anchor", "after-image-truncate"};
    for (std::size_t i = 0; i < stages.size(); ++i) {
        auto r = RelocationImage("cut-" + std::to_string(i), true); const auto p = PrepareVolumeResize(r);
        Check(p.outcome == VolumeImageOutcome::Prepared, p.error); bool hit = false;
        const auto cut = ApplyVolumeResize(r, p.token, [&](auto s) { if (s == stages[i]) { hit = true; return false; } return true; });
        Check(hit && cut.outcome == VolumeImageOutcome::RecoveryRequired, "actual relocation cut: " + cut.error);
        if (!i) {
            vi::Plan plan; { Target target(r.image); plan = vi::BuildResizeRelocationPublicationV2(target, r); }
            const auto& destination = plan.publication.before_superblock_writes.front();
            Target target(r.image); auto torn = destination.bytes; std::fill(torn.begin() + 700, torn.end(), std::byte{0xa6});
            Check(target.WriteBlock(destination.physical_block, torn) && target.Flush(), "actual torn planned free destination");
        }
        const auto recovered = RecoverVolumeResize(r); Check(recovered.outcome == VolumeImageOutcome::Committed, "relocation forward recovery: " + recovered.error);
        Target target(r.image); RetainedPayload(target, true);
    }
    Pass("actual relocation cuts and torn planned destination recover forward");
}
void RelocationControls()
{
    for (unsigned variant = 0; variant < 7; ++variant) {
        auto r = RelocationImage("control-" + std::to_string(variant), true);
        const auto p = PrepareVolumeResize(r); Check(p.outcome == VolumeImageOutcome::Prepared, p.error);
        if (!variant) {
            const auto before = Digests(r.image);
            Check(CancelVolumeResize(r, p.token).outcome == VolumeImageOutcome::Cancelled && Digests(r.image) == before,
                "VIF5 cancel preserves every source byte"); continue;
        }
        if (variant == 1 || variant == 2) {
            if (variant == 1) Change(r, 40000, [](auto& bytes) { bytes[15] ^= std::byte{1}; });
            else Save(r.sibling_wals.at(r.volume_oid), {std::byte{1}});
            const auto before = Digests(r.image);
            Check(ApplyVolumeResize(r, p.token).outcome == VolumeImageOutcome::Refused && Digests(r.image) == before,
                "stale original or WAL refuses unchanged target"); continue;
        }
        if (variant == 3) {
            auto frame = Read(p.journal); vi::Put(frame, 0, fe::ResizeMagic); Save(p.journal, frame); const auto before = Digests(r.image);
            const auto recovered = RecoverVolumeResize(r);
            Check(recovered.outcome == VolumeImageOutcome::RecoveryRequired && recovered.error == "VolumeImageJournalOriginalInvalid" && Digests(r.image) == before,
                "VIF5 body cannot be relabeled as VIF4"); continue;
        }
        vi::Plan plan; { Target target(r.image); plan = vi::BuildResizeRelocationPublicationV2(target, r); }
        const auto cut = ApplyVolumeResize(r, p.token, [variant](auto s) { return s != (variant == 6 ? "after-image-anchor" : "after-image-accept"); });
        Check(cut.outcome == VolumeImageOutcome::RecoveryRequired, cut.error);
        if (variant == 4) {
            const auto block = plan.before.volumes.front().root_tree.physical_block;
            Check(!plan.destinations.contains(block), "original owner is never a staging destination");
            Change(r, block, [](auto& bytes) { bytes[100] ^= std::byte{1}; });
        } else if (variant == 5) {
            const auto block = plan.publication.before_superblock_writes.front().physical_block;
            Change(r, block, [&](auto& bytes) {
                bytes = plan.before.container.superblock_bytes; vi::Put(bytes, 16, r.checkpoint_xid + 991);
                vi::Put(bytes, 0x60, r.checkpoint_xid + 992); vi::Checksum(bytes);
                Check(ParseNxSuperblock(bytes).has_value(), "genuine foreign valid NX in planned destination");
            });
        } else { auto frame = Read(p.journal); frame.resize(frame.size() - 3); Save(p.journal, frame); }
        const auto before = Digests(r.image); const auto recovered = RecoverVolumeResize(r);
        if (variant == 6) {
            Check(recovered.outcome == VolumeImageOutcome::Committed, "torn final authorized VIF5 receipt recovers: " + recovered.error);
            Target target(r.image); RetainedPayload(target, true);
        } else Check(recovered.outcome == VolumeImageOutcome::RecoveryRequired && Digests(r.image) == before,
            "changed required original or foreign planned NX refuses unchanged target: " + recovered.error);
    }
    Pass("VIF5 cancel stale source WAL mode spoof original-owner corruption foreign NX and torn receipt");
}
#ifndef APFS_RELOCATION_KEEPER_FIXTURE_ONLY
int wmain(int argc, wchar_t** argv)
{
    try { const auto mode = argc == 3 ? std::wstring_view(argv[2]) : L"";
        Check(argc == 2 || (argc == 3 && (mode == L"--positive-only" || mode == L"--cuts-controls" || mode == L"--controls-only")), "private root and known selector");
        root = argv[1]; std::filesystem::create_directories(root); if (mode.empty() || mode == L"--positive-only") PositiveRelocation();
        if (mode.empty() || mode == L"--cuts-controls") RelocationCuts();
        if (mode != L"--positive-only") RelocationControls();
        std::cout << "PASS groups=" << groups << " checks=" << checks << '\n'; return 0;
    } catch (const std::exception& ex) { std::cerr << "FAIL checks=" << checks << " " << ex.what() << '\n'; return 1; }
}
#endif
