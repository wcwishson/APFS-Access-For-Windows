#define main ExistingVerifierTestsMain
#include "ApfsVerifierTests.cpp"
#undef main

namespace
{
void Hint(Fixture& f, std::uint64_t flags, bool directory = false)
{
    auto& record = f.fs[directory ? 0 : 2];
    AppleInodeRecord inode; std::string error;
    Check(ApfsExtendedRecordCodec::DecodeInode(record, inode, error), error);
    inode.internal_flags = flags;
    if (flags & kAppleInodeSparseFlag)
        inode.extended_fields.push_back(AppleExtendedField{13, 0, Bytes(8)});
    record = Encode(inode, EncodeAppleInodeRecord);
    f.Rebuild();
}
VerificationReport Observe(Fixture& f)
{
    f.scope.observe_payload_content = true;
    const auto before = f.image; TracedSource source(f.image);
    const auto report = ApfsVerifier::VerifyReadOnly(source, f.scope);
    Check(f.image == before, "read-only hint verification preserves all source bytes");
    Check(!report.whole_volume_verified && !report.payload_content_hashes_verified,
        "historical hint cannot grant global content or allocation certification");
    return report;
}
void Refuse(Fixture& f, const std::string& reason)
{
    const auto report = Observe(f);
    Check(report.outcome != VerificationOutcome::Complete && !report.findings.empty(), reason);
    Check(report.covered_filesystem_records == 0 && report.covered_physical_extents == 0 &&
        !report.allocation_census && !report.payload_projection, "refusal clears complete proof");
    Check(!report.payload_inventory || !report.payload_inventory->hashesObserved,
        "malformed hint cannot publish a complete payload inventory");
    Pass(reason);
}
void CloneHintControls()
{
    { Fixture f; Hint(f, 0x400); const auto report = Observe(f);
      Check(report.outcome == VerificationOutcome::Complete && report.findings.empty(),
          "known historical regular-file clone hint: " + Detail(report));
      Check(report.payload_inventory && report.payload_inventory->exactComplete(),
          "clone hint leaves actual current payload observation enabled");
      Check(report.repair.refusal == ApfsRepairRefusal::NoIndependentReconstructionEvidence,
          "historical hint grants no repair authority");
      Pass("read-only historical clone hint with one real extent owner"); }
    { Fixture f; Hint(f, 0x600); const auto report = Observe(f);
      Check(report.outcome == VerificationOutcome::Complete && report.findings.empty(),
          "historical clone plus canonical zero sparse-byte counter: " + Detail(report));
      Pass("read-only historical clone and sparse hint"); }
    { Fixture f; Hint(f, 0x400); const auto report = Verify(f);
      Check(report.outcome != VerificationOutcome::Complete && !report.findings.empty(),
          "strict ordinary verification admission remains unchanged");
      Pass("strict ordinary route still refuses clone hint"); }
    { Fixture f; Hint(f, 0x400, true); Refuse(f, "directory clone hint remains refused"); }
    { Fixture f; Hint(f, 1ull << 63); Refuse(f, "unknown inode flag remains refused"); }
    { Fixture f; Hint(f, (1ull << 63) | 0x400); Refuse(f, "known hint cannot hide unknown inode flag"); }
    { Fixture f; Hint(f, 0x400); PutU16LE(f.fs[2].value, 0x52, 1); f.Rebuild();
      Refuse(f, "nonzero reserved inode pad remains refused"); }
    { Fixture f; Hint(f, 0x400); PutU64LE(f.fs[2].value, 0x30, 0x600); f.Rebuild();
      Refuse(f, "sparse hint still requires canonical sparse-byte field"); }
    { Fixture f; Hint(f, 0x400); f.fs[0] = Inode(2, 0, 2, true, f.bs);
      f.fs.push_back(Drec(31, "second.txt"));
      auto second = Inode(31, 8, 1, false, f.bs);
      PutU64LE(second.value, 0x30, 0x400); f.fs.push_back(std::move(second));
      f.fs.push_back(Encode(AppleFileExtentRecord{31, 0, f.bs, 220, 0, f.bs}, EncodeAppleFileExtentRecord));
      f.fs.push_back(Encode(AppleDataStreamIdRecord{31, 1}, EncodeAppleDataStreamIdRecord));
      f.Rebuild(); const auto report = Observe(f);
      Check(Has(report, VerificationCode::ExtentReferenceInconsistent) &&
          Detail(report) == "AppleVolumePhysicalExtentOwnerMismatch",
          "single-owner refcount must retain its owner identity check: " + Detail(report));
      Refuse(f, "historical hint cannot hide a visible two-owner extent refcount undercount");
      f.refs[0] = Encode(ApplePhysicalExtentRecord{220, 1, 1, 30, 2}, EncodeApplePhysicalExtentRecord);
      f.Rebuild(); const auto shared = Observe(f);
      Check(shared.outcome == VerificationOutcome::Complete && shared.findings.empty(),
          "two visible owners with exact refcount two: " + Detail(shared));
      Pass("historical hint retains exact shared extent reference multiplicity");
      f.refs[0] = Encode(ApplePhysicalExtentRecord{220, 1, 1, 30, 3}, EncodeApplePhysicalExtentRecord);
      f.Rebuild(); const auto overcount = Observe(f);
      Check(Has(overcount, VerificationCode::ExtentReferenceInconsistent) &&
          Detail(overcount) == "AppleVolumePhysicalExtentRefcountMismatch",
          "shared extent must reach the unchanged refcount integrity check: " + Detail(overcount));
      Refuse(f, "historical hint cannot hide an extent refcount overcount"); }
    { Fixture f; Hint(f, 0x400); TracedSource source(f.image); std::string error;
      const auto checkpoint = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error, 20);
      Check(checkpoint.has_value(), error); auto volume = checkpoint->volumes.front().superblock;
      auto budget = std::make_shared<ApfsReadBudget>(65536, 1ull << 28, 1000000, 1ull << 28);
      volume.role_raw = 0x0180;
      Check(apfsaccess::rw::NativeApfsReader::ValidateBackupWriterFileSystemRecords(f.fs,
          checkpoint->container.superblock, volume, budget, error), "existing bounded backup clone hint: " + error);
      volume.role_raw = 0x0040;
      Check(!apfsaccess::rw::NativeApfsReader::ValidateBackupWriterFileSystemRecords(f.fs,
          checkpoint->container.superblock, volume, budget, error), "backup writer still requires its exact role");
      Pass("backup-only writer role and clone-hint semantics unchanged"); }
}
void AcceptedStandardImage(const std::filesystem::path& path)
{
    Check(std::filesystem::file_size(path) == 4194304, "exact accepted standard image length");
    Bytes bytes(4194304); std::ifstream input(path, std::ios::binary);
    Check(static_cast<bool>(input.read(reinterpret_cast<char*>(bytes.data()), bytes.size())),
        "read exact caller-pinned accepted image");
    const auto before = bytes; TracedSource source(bytes); VerificationScope scope;
    scope.observe_payload_content = true;
    scope.source_identity = "private-pinned-accepted-standard-image";
    scope.exact = {0, bytes.size(), std::string(32, 'a'), "50000000000040006500000000000000", 101, 43};
    const auto report = ApfsVerifier::VerifyReadOnly(source, scope);
    Check(report.outcome == VerificationOutcome::Complete && report.findings.empty(),
        "actual admitted standard clone/sparse image: " + Detail(report));
    Check(report.payload_inventory && report.payload_inventory->exactComplete() &&
        report.payload_inventory->hashesObserved, "actual accepted image payload inventory is complete");
    const auto& inventory = *report.payload_inventory;
    const auto expect = [&](std::uint64_t inode, const std::string& sha) {
        const auto found = std::find_if(inventory.entries.begin(), inventory.entries.end(), [&](const auto& entry) {
            return entry.kind == payload::Kind::FileData && entry.inodeOid == inode;
        });
        Check(found != inventory.entries.end() && found->logicalSizeBytes == 32768 &&
            found->logicalBytesRead == 32768 && found->observedSha256 == sha,
            "actual whole-file hash agrees with prior independent libfsapfs evidence");
    };
    expect(24680, "a79970fdd1a43cbac7c780ac9631209f88e390abbc190f3666883845dfe894f6");
    expect(24696, "1c5b1d5a1eb0ac56f8f0fe7634854f9c36f31b248c7f121ea25c6c66bb8e0c1f");
    Check(std::count_if(inventory.aliases.begin(), inventory.aliases.end(), [](const auto& link) {
        return link.child_object_id == 24696;
    }) == 2, "actual target and alias preserve one inode and two namespace links");
    Check(bytes == before && !report.whole_volume_verified && !report.payload_content_hashes_verified,
        "actual accepted image stays immutable with truthful finite verification scope");
    Pass("actual accepted image independent hashes and hardlink/sparse/clone inventory");
}
}
int main(int argc, char** argv)
{
    try {
        Check(argc == 1 || (argc == 3 && std::string(argv[1]) == "--accepted-image"), "argument contract");
        CloneHintControls();
        if (argc == 3) AcceptedStandardImage(argv[2]);
        std::cout << "PASS " << cases << " cases, " << checks << " checks\n"; return 0;
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
