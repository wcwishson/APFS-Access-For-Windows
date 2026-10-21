#include "ApfsVerificationJson.h"
#define APFS_RETAINED_OWNERSHIP_FIXTURES_ONLY
#include "ApfsVerifierRetainedOwnershipTests.cpp"
#undef APFS_RETAINED_OWNERSHIP_FIXTURES_ONLY

namespace
{
void SaveMagicCase(const std::filesystem::path& directory, const std::string& name,
    const Fixture& fixture, const VerificationReport& report)
{
    const auto path = directory / (name + ".apfs");
    std::ofstream image(path, std::ios::binary);
    image.write(reinterpret_cast<const char*>(fixture.image.data()), fixture.image.size());
    image.close(); Check(static_cast<bool>(image), "magic image evidence written");
    std::string json; payload::Reason reason = payload::Reason::None;
    Check(SerializeImageVerificationReport(report, path.string(), [] { return true; },
        MaxImageVerificationJsonBytes, json, reason), "magic report encoded: " + std::string(payload::Name(reason)));
    std::ofstream output(directory / (name + ".json"), std::ios::binary);
    output << json; output.close(); Check(static_cast<bool>(output), "magic JSON evidence written");
}

void MagicCase(const std::filesystem::path& directory, std::uint32_t bs, bool snapshot, bool recompute)
{
    auto fixture = snapshot ? Fixture(bs) : Ordinary(bs);
    if (snapshot) fixture.Create("shared", {20});
    fixture.scope.retained_from_xid.reset();
    const auto control = Account(fixture); Accounted(control);
    Check(control.retained_ownership->checkpoint_xids.front() == 20 &&
        control.retained_ownership->checkpoint_xids.size() >= 2, "control has an older retained descriptor");
    const auto name = std::string("descriptor-magic-") + (snapshot ? "shared-snapshot-" : "ordinary-") +
        std::to_string(bs) + (recompute ? "-recomputed-checksum" : "-stale-checksum");
    const auto& old = fixture.generations.front().container;
    const auto block = old.superblock_physical_block;
    const auto before = fixture.image;
    fixture.Edit(block, [](auto& bytes) { bytes[0x20] ^= std::byte{1}; }, recompute);
    Bytes descriptor(fixture.image.begin() + block * bs, fixture.image.begin() + (block + 1) * bs);
    Check(ReadU64LE(descriptor, 0x08) == old.superblock.object_id &&
        ReadU64LE(descriptor, 0x10) == old.superblock.xid &&
        (ReadU32LE(descriptor, 0x18).value_or(0) & kObjectTypeMask) == kNxSuperblockObjectType,
        "recognizable canonical object type/OID/XID preserved");
    Check(ReadU32LE(descriptor, 0x20).value_or(0) != kNxsbMagic &&
        VerifyObjectChecksum(descriptor, bs) == recompute && !ParseNxSuperblock(descriptor),
        "only NX magic and optional checksum invalidate canonical decoding");
    for (std::size_t i = 0; i < before.size(); ++i)
        if (before[i] != fixture.image[i])
            Check(i == block * bs + 0x20 || (recompute && i >= block * bs && i < block * bs + 8),
                "no other image byte changed");
    const auto report = Account(fixture);
    SaveMagicCase(directory, name, fixture, report);
    std::cout << "OBSERVED " << name << " outcome=" << static_cast<unsigned>(report.outcome);
    if (!report.findings.empty()) std::cout << " code=" << static_cast<unsigned>(report.findings.front().code)
        << " detail=" << report.findings.front().detail;
    if (report.retained_ownership)
    {
        std::cout << " retainedXids=";
        for (const auto xid : report.retained_ownership->checkpoint_xids) std::cout << xid << ',';
    }
    std::cout << '\n';
    const auto expected = recompute ? VerificationCode::StructuralInconsistency : VerificationCode::ChecksumMismatch;
    Check(report.outcome == VerificationOutcome::Incomplete && Has(report, expected),
        "magic-only corruption must be Incomplete with typed checksum/structure failure");
    const auto& finding = report.findings.front();
    Check(finding.check == VerificationCheck::HistoricalReachability && finding.physical_block == block &&
        finding.checkpoint_xid == old.superblock.xid, "failure identifies the damaged older descriptor");
    Check(!report.retained_ownership && !report.allocation_census && !report.requested_history &&
        !report.covered_filesystem_records && !report.covered_physical_extents, "no completed ownership escapes descriptor failure");
    Pass(name);
}
}

int main(int argc, char** argv)
{
    try
    {
        Check(argc == 2, "absolute D: output directory required"); const std::filesystem::path directory(argv[1]);
        Check(directory.is_absolute() && directory.root_name() == "D:", "magic evidence stays on D:");
        std::filesystem::create_directories(directory);
        unsigned failed = 0;
        for (const auto bs : {4096u, 8192u})
            for (const bool snapshot : {false, true})
                for (const bool recompute : {false, true})
                    try { MagicCase(directory, bs, snapshot, recompute); }
                    catch (const std::exception& e) { ++failed; std::cout << "RED " << e.what() << '\n'; }
        std::cout << (failed ? "RED " : "PASS ") << cases << " cases, " << checks << " checks";
        if (failed) std::cout << ", " << failed << " failed";
        std::cout << '\n'; return failed ? 1 : 0;
    }
    catch (const std::exception& e) { std::cerr << "FAIL " << e.what() << '\n'; return 1; }
}
