#include "VolumeRetiredHistoryCases.h"
using namespace apfsaccess::volume_image_test;
namespace
{
void CurrentOwnerCorruptionRefusals()
{
    for (const auto op : {VolumeImageOperation::Grow, VolumeImageOperation::Shrink}) for (const bool payload : {false, true}) {
        const auto r = Setup("owner-corruption-" + std::to_string(static_cast<unsigned>(op)) + (payload ? "-payload" : "-metadata"), op);
        const auto original = Read(r.image); const auto cp = Checkpoint(original); VectorRandomAccessSource source(original); std::string error;
        std::vector<std::uint64_t> metadata; std::vector<ApplePhysicalExtentRecord> extents;
        Check(LoadAppleSnapshotCheckpointOwners(source, cp, metadata, extents, error) && !metadata.empty() && extents.size() == 2,
            "explicit populated current owner census: " + error);
        const auto block = payload ? extents.front().physical_block : cp.volumes.front().root_tree.physical_block;
        Check(block != 0 && (payload || std::find(metadata.begin(), metadata.end(), block) != metadata.end()), "corruption selects an actual protected owner");
        const auto p = Prepare(r); Check(p.outcome == VolumeImageOutcome::Prepared, p.error);
        bool hit = false;
        Check(Apply(r, p.token, [&](auto stage) { if (stage == "after-image-accept") { hit = true; return false; } return true; }).outcome ==
            VolumeImageOutcome::RecoveryRequired && hit, "real accepted owner interruption before publication");
        const auto accepted = Read(p.journal); auto changed = Read(r.image); changed[block * 4096 + 111] ^= std::byte{1}; Save(r.image, changed);
        const auto refused = Recover(r);
        Check(refused.outcome == VolumeImageOutcome::RecoveryRequired && refused.error == "VolumeImageRecoveryUnrelatedBytesChanged" &&
            Read(r.image) == changed && Read(p.journal) == accepted, "protected owner corruption cannot replay or overwrite evidence: " + refused.error);
        // Restore only this test's injected byte to prove recovery still works.
        Save(r.image, original); Check(Recover(r).outcome == VolumeImageOutcome::Committed, "intact original still recovers");
        const auto post = Read(r.image);
        Check(Recover(r).outcome == VolumeImageOutcome::Committed && Read(r.image) == post, "recovered owner remains idempotent");
        std::cout << "OWNER CORRUPTION REFUSED operation=" << static_cast<unsigned>(op) << " payload=" << payload << " block=" << block << '\n';
    }
    Pass("grow/shrink actual metadata and payload corruption refuses replay and preserves accepted evidence");
}
void ResizeSnapshotRefusals()
{
    const auto image = SnapshotFixture(); const auto cp = Checkpoint(image);
    apfsaccess::catalog::VectorRandomAccessSource source(image);
    apfsaccess::rw::AppleSnapshotRetentionView retained; std::string error;
    Check(apfsaccess::rw::LoadAppleSnapshotRetention(source, cp, retained, error) && retained.identities.size() == 1,
        "complete original production snapshot ownership: " + error);
    for (const auto op : {apfsaccess::rw::VolumeImageOperation::Grow, apfsaccess::rw::VolumeImageOperation::Shrink}) {
        const auto request = Setup("snapshot-refusal-" + std::to_string(static_cast<unsigned>(op)), op, image);
        const auto result = Prepare(request);
        Check(result.outcome == apfsaccess::rw::VolumeImageOutcome::Refused &&
            result.error == "VolumeImageSnapshotHistoryAuthorityUnproven" && Read(request.image) == image,
            "snapshot-bearing resize keeps exact authority refusal and all source bytes: " + result.error);
    }
    Pass("production snapshot grow/shrink refuses without complete image-history authority and preserves bytes");
}
}
int wmain(int argc, wchar_t** argv)
{
    try {
        Check(argc >= 2 && argc <= 4, "fresh absolute evidence directory required"); root = argv[1]; std::filesystem::create_directories(root);
        if (argc >= 3) {
            if (std::wstring_view(argv[2]) == L"--owners-only") {
                CurrentOwnerCorruptionRefusals(); std::cout << "PASS groups=" << groups << " checks=" << checks << '\n'; return 0;
            }
            Check(std::wstring_view(argv[2]) == L"--retention-only", "known focused selector");
            RetiredHistory(VolumeImageOperation::Grow, argc == 4 ? argv[3] : nullptr);
            ResizeSnapshotRefusals(); std::cout << "PASS groups=" << groups << " checks=" << checks << '\n'; return 0;
        }
        const auto fixture = Fixture(); Save(root / "original.apfs", fixture);
        Positive(VolumeImageOperation::Grow); Positive(VolumeImageOperation::Shrink); Refusals(VolumeImageOperation::Grow);
        TokensAndWal(VolumeImageOperation::Shrink); Interruptions(VolumeImageOperation::Grow); Interruptions(VolumeImageOperation::Shrink);
        JournalTails(VolumeImageOperation::Shrink); LongPath(VolumeImageOperation::Grow);
        PolicyAndTail(VolumeImageOperation::Shrink); BusyAndBinding(VolumeImageOperation::Grow);
        RecoveryConflicts(VolumeImageOperation::Grow); CurrentOwnerCorruptionRefusals(); ResizeSnapshotRefusals();
        std::cout << "PASS groups=" << groups << " checks=" << checks << '\n'; return 0;
    } catch (const std::exception& ex) { std::cerr << "FAIL checks=" << checks << " " << ex.what() << '\n'; return 1; }
}
