#define APFS_RELOCATION_KEEPER_FIXTURE_ONLY
#include "VolumeResizeRelocationKeeperTests.cpp"
#undef APFS_RELOCATION_KEEPER_FIXTURE_ONLY

namespace
{
std::string PlanDigest(const vi::Plan& plan)
{
    Bytes bytes;
    const auto number = [&](std::uint64_t n) { fe::Number(bytes, n); };
    const auto blob = [&](const Bytes& b) { number(b.size()); bytes.insert(bytes.end(), b.begin(), b.end()); };
    number(plan.publication.expected_checkpoint_xid); number(plan.publication.transaction_xid); number(plan.publication.next_object_id);
    const auto write = [&](const auto& w) { number(static_cast<unsigned>(w.kind)); number(w.physical_block); number(w.object_id); blob(w.bytes); };
    number(plan.publication.before_superblock_writes.size()); for (const auto& w : plan.publication.before_superblock_writes) write(w);
    write(plan.publication.superblock_write); number(plan.publication.guard_blocks.size());
    for (const auto& guard : plan.publication.guard_blocks) { number(guard.physical_block); blob(guard.bytes); }
    blob(plan.anchor); const auto hash = fe::Hash(bytes); constexpr char hex[] = "0123456789abcdef"; std::string result;
    for (const auto b : hash) { const auto n = std::to_integer<unsigned>(b); result += hex[n >> 4]; result += hex[n & 15]; }
    return result;
}
VolumeImageRequest LegacyRequest()
{
    const auto dir = root / "legacy"; VolumeImageRequest r; r.image = dir / "image.apfs"; r.journal_directory = dir;
    Target target(r.image); const auto cp = mc::Load(target); r.operation = VolumeImageOperation::Shrink;
    r.expected_bytes = target.SizeBytes(); r.target_bytes = (3 * mc::ChunkBlocks - 25) * 4096;
    r.container_uuid = cp.container.superblock.uuid_hex; r.volume_uuid = cp.volumes.front().superblock.uuid_hex;
    r.volume_oid = cp.volumes.front().superblock.object_id; r.checkpoint_xid = cp.container.superblock.xid;
    r.sibling_wals = {{r.volume_oid, dir / "destination.wal"}}; return r;
}
void Produce()
{
    Check(!std::filesystem::exists(root) && std::filesystem::create_directories(root), "fresh old-version producer root");
    const auto r = RelocationImage("legacy", true); std::string digest;
    { Target target(r.image); digest = PlanDigest(vi::BuildResizeRelocationPublication(target, r)); }
    const auto p = PrepareVolumeResize(r); Check(p.outcome == VolumeImageOutcome::Prepared && ReadU64LE(Read(p.journal), 0) == fe::RelocationMagic,
        "historical producer creates exact VIF5 original: " + p.error);
    const auto cut = ApplyVolumeResize(r, p.token, [](auto stage) { return stage != "after-image-accept"; });
    Check(cut.outcome == VolumeImageOutcome::RecoveryRequired, "historical accepted VIF5 cut");
    std::ofstream out(root / "publication.sha256"); out << digest << '\n'; Check(out.good(), "persist old exact publication commitment");
}
void Replay()
{
    const auto r = LegacyRequest(); std::string expected; std::ifstream in(root / "publication.sha256"); in >> expected;
    Check(expected.size() == 64, "immutable old publication commitment");
    { Target target(r.image); Check(PlanDigest(vi::BuildResizeRelocationPublication(target, r)) == expected,
        "current VIF5 derivation preserves every old planned byte, destination and guard"); }
    const auto done = RecoverVolumeResize(r); Check(done.outcome == VolumeImageOutcome::Committed, "fresh current producer recovers exact old VIF5: " + done.error);
    { Target target(r.image); RetainedPayload(target, true); auto history = AcquireVolumeKeeperHistory(done.source_identity, target, r.journal_directory, {});
      NativeMetadataWrite(target); RetainedPayload(target, true); }
    Check(RecoverVolumeResize(r).outcome == VolumeImageOutcome::Committed && InspectVolumeKeeperImage(r.image, 0, r.journal_directory).admitted,
        "old VIF5 completion admits later ordinary mutation and reopen");
}
}
int wmain(int argc, wchar_t** argv)
{
    try { Check(argc == 3, "old-version producer or fresh replay mode and D root"); root = argv[2];
        Check(root.is_absolute() && root.wstring().starts_with(L"D:\\ApfsAccessScratch\\"), "private D evidence");
        if (std::wstring_view(argv[1]) == L"--produce") Produce(); else { Check(std::wstring_view(argv[1]) == L"--replay", "known replay mode"); Replay(); }
        std::cout << "PASS legacy VIF5 checks=" << checks << '\n'; return 0;
    } catch (const std::exception& e) { std::cerr << "FAIL legacy VIF5 checks=" << checks << ' ' << e.what() << '\n'; return 1; }
}
