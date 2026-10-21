// Offline bounded RCT2 repair tool contract gates. Drives the production
// RunVolumeRepair entry (tools/ApfsVolumeRepairTool.cpp, main excluded by
// APFS_VOLUME_REPAIR_TOOL_TESTING) against fixture images on scratch paths:
// dry-run display, confirmation intent, apply + post-verify, replay,
// expiry-adjacent guards, wrong selectors, stale graphs, snapshot-bearing,
// foreign journals, concurrent owners, interrupted commits, Fusion refusal,
// and argument validation. Every refusal proves image bytes unchanged.
// Mount-free beyond the tool's own exclusive owner; file images only.
#define APFS_VOLUME_REPAIR_TOOL_TESTING 1
#define SNAPSHOT_RUNTIME_TEST_HELPERS_ONLY
#include "SnapshotRuntimeTests.cpp"
#ifdef APFS_REPAIR_TOOL_BASELINE
#include APFS_REPAIR_TOOL_BASELINE
#else
#include "../tools/ApfsVolumeRepairTool.cpp"
#endif
#include "FusionTestFixture.h"
#include <cstdlib>
#include <iostream>
#include <stdexcept>

using namespace apfsaccess::catalog;
namespace
{
// Check/checks come from the included harness TU; cases/Pass are local.
unsigned cases = 0;
void Pass(const std::string& name) { ++cases; std::cout << "PASS " << name << '\n'; }
namespace fs = std::filesystem;

void FreshRepair(const fs::path& path)
{
    auto spec = RuntimeSpec();
    std::string error;
    for (auto& volume : spec.volumes)
        Check(SortAppleBtreeRecords(volume.filesystem_records, AppleBtreeKeyOrder::FileSystemHashedDirectory, error),
            "sort repair census: " + error);
    Fresh(path, spec);
}

void DamageCount(const fs::path& path, std::uint64_t bad_count = 99)
{
    auto image = Bytes(path);
    VectorRandomAccessSource source(image);
    std::string error;
    const auto checkpoint = LoadAppleCheckpointView(source, 0, image.size(), error);
    Check(!!checkpoint, "load damage preimage: " + error);
    const auto block = checkpoint->volumes[0].superblock_object.physical_block;
    std::vector<std::byte> apsb(image.begin() + block * kBlockSize, image.begin() + (block + 1) * kBlockSize);
    PutU64LE(apsb, 0xb8, bad_count);
    Check(FinalizeAppleObjectChecksum(apsb, error), "checksum typed damage");
    std::copy(apsb.begin(), apsb.end(), image.begin() + block * kBlockSize);
    Save(path, image);
}

struct LiveScope
{
    std::string container_uuid, volume_uuid;
    std::uint64_t xid = 0, size = 0;
};

LiveScope ScopeOf(const fs::path& path, std::uint64_t oid = 101)
{
    const auto image = Bytes(path);
    VectorRandomAccessSource source(image);
    std::string error;
    const auto checkpoint = LoadAppleCheckpointView(source, 0, image.size(), error);
    Check(!!checkpoint, "load scope checkpoint: " + error);
    LiveScope scope;
    scope.container_uuid = checkpoint->container.superblock.uuid_hex;
    scope.xid = checkpoint->container.superblock.xid;
    scope.size = image.size();
    for (const auto& volume : checkpoint->volumes)
    {
        if (volume.superblock.object_id == oid)
        {
            scope.volume_uuid = volume.superblock.uuid_hex;
            return scope;
        }
    }
    throw std::runtime_error("scope volume missing");
}

VolumeRepairToolOptions BaseOptions(const fs::path& image, const LiveScope& scope,
    const fs::path& journal, const fs::path& evidence, std::uint64_t oid = 101)
{
    VolumeRepairToolOptions options;
    options.image = image.string();
    options.container_uuid = scope.container_uuid;
    options.volume_uuid = scope.volume_uuid;
    options.volume_oid = oid;
    options.checkpoint_xid = scope.xid;
    options.store_offset_bytes = 0;
    options.store_size_bytes = scope.size;
    options.journal_path = journal.string();
    options.evidence_dir = evidence.string();
    return options;
}

bool JsonHas(const std::string& json, const std::string& fragment)
{
    return json.find(fragment) != std::string::npos;
}

std::uint64_t JsonExpectedCount(const std::string& json)
{
    const auto at = json.find("\"expectedCount\":");
    Check(at != std::string::npos, "plan carries expected count");
    return std::stoull(json.substr(at + 16));
}

std::uint64_t LiveFileCount(const fs::path& path, std::uint64_t oid = 101)
{
    const auto image = Bytes(path);
    VectorRandomAccessSource source(image);
    std::string error;
    const auto checkpoint = LoadAppleCheckpointView(source, 0, image.size(), error);
    Check(!!checkpoint, "load count checkpoint: " + error);
    for (const auto& volume : checkpoint->volumes)
        if (volume.superblock.object_id == oid) return volume.superblock.file_count;
    throw std::runtime_error("count volume missing");
}

void DryRunDisplaysPlanWithoutMutation()
{
    FreshRepair("dry.apfs");
    DamageCount("dry.apfs");
    const auto before = Bytes("dry.apfs");
    const auto scope = ScopeOf("dry.apfs");
    auto options = BaseOptions("dry.apfs", scope, "dry.wal", "dry-evidence");
    const auto result = RunVolumeRepair(options);
    Check(result.exit_code == 3, "dry run asks for confirmation");
    Check(JsonHas(result.json, "\"code\":\"RepairNeedsConfirmation\""), "typed dry-run code");
    Check(JsonHas(result.json, "\"expectedCount\":"), "plan displayed");
    Check(Bytes("dry.apfs") == before, "dry run mutates image");
    const bool journal_staged = fs::exists("dry.wal");
    Check(!journal_staged || fs::file_size("dry.wal") == 0, "dry run stages journal content");
    Pass("dry run displays the prepared plan without mutation");
}

void DryRunThenConfirmSameJournal()
{
    // The operator-friendly flow reuses one journal path: the empty file a
    // dry run may stage carries no authority and must not block confirmation.
    FreshRepair("samejournal.apfs");
    DamageCount("samejournal.apfs");
    const auto scope = ScopeOf("samejournal.apfs");
    auto probe = BaseOptions("samejournal.apfs", scope, "same.wal", "same-evidence");
    const auto displayed = RunVolumeRepair(probe);
    Check(displayed.exit_code == 3, "plan first: " + displayed.json);
    const auto intent = JsonExpectedCount(displayed.json);
    auto options = BaseOptions("samejournal.apfs", scope, "same.wal", "same-evidence");
    options.confirm = true;
    options.expected_count = intent;
    const auto result = RunVolumeRepair(options);
    Check(result.exit_code == 0, "confirm on dry-run journal succeeds: " + result.json);
    Check(LiveFileCount("samejournal.apfs") == intent, "count restored through shared journal");
    Pass("dry run then confirm on one journal repairs");
}

void ApplyRepairsAndVerifies()
{
    FreshRepair("apply.apfs");
    DamageCount("apply.apfs");
    const auto scope = ScopeOf("apply.apfs");
    auto probe = BaseOptions("apply.apfs", scope, "apply-probe.wal", "apply-evidence");
    const auto displayed = RunVolumeRepair(probe);
    Check(displayed.exit_code == 3, "plan first: " + displayed.json);
    const auto intent = JsonExpectedCount(displayed.json);
    auto options = BaseOptions("apply.apfs", scope, "apply.wal", "apply-evidence");
    options.confirm = true;
    options.expected_count = intent;
    const auto result = RunVolumeRepair(options);
    Check(result.exit_code == 0, "apply succeeds: " + result.json);
    Check(JsonHas(result.json, "\"code\":\"RepairedAndVerified\""), "typed success code: " + result.json);
    Check(JsonHas(result.json, "\"postVerify\":{\"outcome\":1"), "post verification complete: " + result.json);
    Check(LiveFileCount("apply.apfs") == intent, "count restored to prepared intent");
    Check(fs::exists("apply.wal"), "journal retained as evidence");
    Check(!fs::path("apply-evidence").empty() && fs::exists(
        fs::path("apply-evidence") / ("repair-backup-101-" + std::to_string(scope.xid) + ".apfs")),
        "pre-repair backup retained");
    Pass("confirmed apply repairs and post-verifies");
}

void RerunAfterSuccessReportsHealthy()
{
    FreshRepair("rerun.apfs");
    DamageCount("rerun.apfs");
    const auto scope = ScopeOf("rerun.apfs");
    auto probe = BaseOptions("rerun.apfs", scope, "rerun-probe.wal", "rerun-evidence");
    const auto intent = JsonExpectedCount(RunVolumeRepair(probe).json);
    auto options = BaseOptions("rerun.apfs", scope, "rerun.wal", "rerun-evidence");
    options.confirm = true;
    options.expected_count = intent;
    Check(RunVolumeRepair(options).exit_code == 0, "first apply succeeds");
    const auto after = Bytes("rerun.apfs");
    // Repair advanced the generation: re-derive selectors (stale XIDs must
    // refuse, proven by WrongSelectorsRefuse) before the healthy rerun.
    const auto rescoped = ScopeOf("rerun.apfs");
    Check(rescoped.xid != scope.xid, "repair advanced the generation");
    auto again = BaseOptions("rerun.apfs", rescoped, "rerun-again.wal", "rerun-evidence");
    const auto result = RunVolumeRepair(again);
    Check(result.exit_code == 0, "rerun succeeds");
    Check(JsonHas(result.json, "\"code\":\"RepairHealthyNoFinding\""), "rerun reports no finding");
    Check(Bytes("rerun.apfs") == after, "rerun mutates nothing");
    Pass("rerun after success reports healthy");
}

void WrongIntentRefuses()
{
    FreshRepair("intent.apfs");
    DamageCount("intent.apfs");
    const auto before = Bytes("intent.apfs");
    const auto scope = ScopeOf("intent.apfs");
    auto probe = BaseOptions("intent.apfs", scope, "intent-probe.wal", "intent-evidence");
    const auto intent = JsonExpectedCount(RunVolumeRepair(probe).json);
    auto options = BaseOptions("intent.apfs", scope, "intent.wal", "intent-evidence");
    options.confirm = true;
    options.expected_count = intent + 1;
    const auto result = RunVolumeRepair(options);
    Check(result.exit_code == 4, "mismatched intent refuses");
    Check(Bytes("intent.apfs") == before, "mismatched intent mutates image");
    Pass("wrong confirmation intent refuses");
}

void WrongSelectorsRefuse()
{
    FreshRepair("selectors.apfs");
    DamageCount("selectors.apfs");
    const auto before = Bytes("selectors.apfs");
    const auto scope = ScopeOf("selectors.apfs");
    {
        auto options = BaseOptions("selectors.apfs", scope, "selectors-oid.wal", "selectors-evidence", 999);
        Check(RunVolumeRepair(options).exit_code == 4, "ghost OID admitted");
    }
    {
        auto options = BaseOptions("selectors.apfs", scope, "selectors-uuid.wal", "selectors-evidence");
        options.volume_uuid = std::string(32, 'd');
        Check(RunVolumeRepair(options).exit_code == 4, "wrong volume UUID admitted");
    }
    {
        auto options = BaseOptions("selectors.apfs", scope, "selectors-xid.wal", "selectors-evidence");
        options.checkpoint_xid = scope.xid + 1;
        Check(RunVolumeRepair(options).exit_code == 4, "stale XID admitted");
    }
    Check(Bytes("selectors.apfs") == before, "wrong selectors mutate image");
    Pass("wrong selectors refuse");
}

void GrowthBeyondScopeRefuses()
{
    // The store window binds the image geometry: an image that grew past the
    // selected scope (stale size after external growth) must refuse, never
    // plan against a mismatched geometry.
    FreshRepair("growth.apfs");
    DamageCount("growth.apfs");
    const auto scope = ScopeOf("growth.apfs");
    {
        auto image = Bytes("growth.apfs");
        image.insert(image.end(), 4096, std::byte{0});
        Save("growth.apfs", image);
    }
    const auto grown = Bytes("growth.apfs");
    auto options = BaseOptions("growth.apfs", scope, "growth.wal", "growth-evidence");
    const auto result = RunVolumeRepair(options);
    Check(result.exit_code == 4, "grown image admitted: " + result.json);
    Check(Bytes("growth.apfs") == grown, "growth refusal mutates image");
    Pass("growth beyond scope refuses");
}

void SnapshotBearingRefuses()
{
    FreshRepair("snapbore.apfs");
    DamageCount("snapbore.apfs");
    {
        Tx journal(L"Strict");
        Configure(journal, "snapbore-setup.wal");
        auto owner = Open("snapbore.apfs", journal);
        std::string error;
        SnapshotRuntimePlan snapshot;
        Check(PrepareSnapshotCreate(*owner, 101, "pinned", 1, 0, snapshot, error), "pin snapshot: " + error);
        Check(ApplySnapshot(*owner, journal, snapshot).committed, "snapshot commits");
    }
    const auto before = Bytes("snapbore.apfs");
    const auto scope = ScopeOf("snapbore.apfs");
    auto options = BaseOptions("snapbore.apfs", scope, "snapbore.wal", "snapbore-evidence");
    const auto result = RunVolumeRepair(options);
    Check(result.exit_code == 4, "snapshot-bearing repair admitted: " + result.json);
    Check(Bytes("snapbore.apfs") == before, "snapshot-bearing refusal mutates image");
    Pass("snapshot-bearing image refuses");
}

void ForeignJournalRefuses()
{
    FreshRepair("foreign.apfs");
    DamageCount("foreign.apfs");
    const auto before = Bytes("foreign.apfs");
    {
        std::ofstream foreign("foreign.wal", std::ios::binary | std::ios::trunc);
        foreign << "not-a-journal";
    }
    const auto scope = ScopeOf("foreign.apfs");
    auto options = BaseOptions("foreign.apfs", scope, "foreign.wal", "foreign-evidence");
    const auto result = RunVolumeRepair(options);
    Check(result.exit_code == 4, "foreign journal admitted: " + result.json);
    Check(Bytes("foreign.apfs") == before, "foreign journal mutates image");
    Pass("foreign journal refuses");
}

void ConcurrentOwnerRefuses()
{
    FreshRepair("concurrent.apfs");
    DamageCount("concurrent.apfs");
    const auto before = Bytes("concurrent.apfs");
    Tx journal(L"Strict");
    Configure(journal, "concurrent-held.wal");
    auto owner = Open("concurrent.apfs", journal);
    const auto scope = ScopeOf("concurrent.apfs");
    auto options = BaseOptions("concurrent.apfs", scope, "concurrent.wal", "concurrent-evidence");
    const auto result = RunVolumeRepair(options);
    Check(result.exit_code != 0, "concurrent owner admitted");
    Check(Bytes("concurrent.apfs") == before, "concurrent attempt mutates image");
    Pass("concurrent owner refuses");
}

void InterruptedCommitReplays()
{
    FreshRepair("interrupt.apfs");
    DamageCount("interrupt.apfs");
    const auto scope = ScopeOf("interrupt.apfs");
    auto probe = BaseOptions("interrupt.apfs", scope, "interrupt-probe.wal", "interrupt-evidence");
    const auto intent = JsonExpectedCount(RunVolumeRepair(probe).json);
    Check(_putenv_s("APFS_REPAIR_TEST_HOOKS", "1") == 0, "enable test hooks");
    auto aborted = BaseOptions("interrupt.apfs", scope, "interrupt.wal", "interrupt-evidence");
    aborted.confirm = true;
    aborted.expected_count = intent;
    aborted.test_abort_stage = "before-apple-publish";
    const auto interrupted = RunVolumeRepair(aborted);
    Check(_putenv_s("APFS_REPAIR_TEST_HOOKS", "") == 0, "disable test hooks");
    Check(interrupted.exit_code == 5, "interruption must not report success: " + interrupted.json);
    Check(JsonHas(interrupted.json, "\"code\":\"RepairRecoveryRequired\""), "recovery required reported");
    Check(fs::exists("interrupt.wal"), "interrupted journal retained");
    auto options = BaseOptions("interrupt.apfs", scope, "interrupt.wal", "interrupt-evidence");
    const auto recovered = RunVolumeRepair(options);
    Check(recovered.exit_code == 0, "replay after interruption succeeds: " + recovered.json);
    Check(JsonHas(recovered.json, "\"replayed\":true"), "replay reported");
    Check(LiveFileCount("interrupt.apfs") == intent, "replayed count restored");
    Pass("interrupted commit replays to verified repair");
}

void FusionMemberRefuses()
{
    apfsaccess::fusiontest::Fixture fixture;
    Save("fusion-main.apfs", fixture.sources[0]->bytes);
    Save("fusion-tier2.apfs", fixture.sources[1]->bytes);
    const auto before = Bytes("fusion-main.apfs");
    VolumeRepairToolOptions options;
    options.image = "fusion-main.apfs";
    options.container_uuid = std::string(32, 'a');
    options.volume_uuid = std::string(32, 'c');
    options.volume_oid = 101;
    options.checkpoint_xid = 20;
    options.store_offset_bytes = 0;
    options.store_size_bytes = before.size();
    options.journal_path = "fusion.wal";
    options.evidence_dir = "fusion-evidence";
    const auto result = RunVolumeRepair(options);
    Check(result.exit_code == 4, "Fusion member admitted: " + result.json);
    Check(Bytes("fusion-main.apfs") == before, "Fusion refusal mutates image");
    Pass("Fusion member refuses");
}

void ArgumentValidation()
{
    const auto parse = [](std::vector<std::string> argv) {
        try
        {
            ParseVolumeRepairArguments(argv);
            return false;
        }
        catch (const ToolArgumentError&)
        {
            return true;
        }
    };
    Check(parse({}), "empty argv admitted");
    Check(parse({"--image", "a.apfs", "--mystery", "x"}), "unknown flag admitted");
    std::vector<std::string> missing_confirm = {"--image", "a.apfs", "--container-uuid", std::string(32, 'a'),
        "--volume-uuid", std::string(32, 'b'), "--volume-oid", "101", "--checkpoint-xid", "20",
        "--store-offset-bytes", "0", "--store-size-bytes", "4096", "--journal", "a.wal",
        "--evidence-dir", "ev", "--confirm"};
    Check(parse(missing_confirm), "confirm without intent admitted");
    std::vector<std::string> minimal = {"--image", "a.apfs", "--container-uuid", std::string(32, 'a'),
        "--volume-uuid", std::string(32, 'b'), "--volume-oid", "101", "--checkpoint-xid", "20",
        "--store-offset-bytes", "0", "--store-size-bytes", "4096", "--journal", "a.wal",
        "--evidence-dir", "ev"};
    try
    {
        // Shape validation stats the input: provide a real regular file.
        Save("a.apfs", std::vector<std::byte>(4096, std::byte{0}));
        const auto options = ParseVolumeRepairArguments(minimal);
        Check(!options.confirm && options.expected_count == 0, "minimal parse shapes wrong");
    }
    catch (const ToolArgumentError& error)
    {
        Check(false, std::string("minimal parse refused: ") + error.what());
    }
    Pass("argument validation fails closed");
}

void ReportOutputNeverOverwritesExistingFiles()
{
    FreshRepair("report.apfs");
    const auto before = Bytes("report.apfs");
    const auto scope = ScopeOf("report.apfs");
    auto options = BaseOptions("report.apfs", scope, "report.wal", "report-evidence");
    options.out_path = options.image;
    // Identity refusal occurs before the exclusive image owner is opened, so
    // the old best-effort report writer could truncate the image on this path.
    ++options.checkpoint_xid;
    auto result = RunVolumeRepair(options);
    Check(Bytes("report.apfs") == before, "report output overwrote the input image");
    Check(result.exit_code == 4, "input report collision must refuse");
    Check(!fs::exists("report.wal"), "report collision opened a journal");
    options.checkpoint_xid = scope.xid;

    fs::create_hard_link("report.apfs", "report-alias.json");
    options.out_path = "report-alias.json";
    result = RunVolumeRepair(options);
    Check(result.exit_code == 4 && Bytes("report.apfs") == before,
        "hard-linked report overwrote the image");

    const std::vector<std::byte> sentinel{std::byte{0x12}, std::byte{0x34}};
    Save("retained.wal", sentinel);
    options.out_path = "retained.wal";
    result = RunVolumeRepair(options);
    Check(result.exit_code == 4 && Bytes("retained.wal") == sentinel,
        "report overwrote existing recovery evidence");

    options.out_path = options.journal_path;
    result = RunVolumeRepair(options);
    Check(result.exit_code == 4 && !fs::exists(options.journal_path),
        "report reserved the repair journal as its own output");

    options.out_path = "new-report.json";
    result = RunVolumeRepair(options);
    Check(result.exit_code == 3, "fresh dry-run report failed: " + result.json);
    const auto report_bytes = Bytes(options.out_path);
    const std::string report(reinterpret_cast<const char*>(report_bytes.data()), report_bytes.size());
    Check(report == result.json + "\n", "fresh report differs from terminal result");
    Check(Bytes("report.apfs") == before, "fresh report changed the image");
    Pass("report output refuses existing files and writes a new report");
}

std::string ApprovalHash(const fs::path& path)
{
    std::array<std::uint8_t, 32> hash{};
    HashPayload(Bytes(path), hash);
    std::string value;
    for (const auto byte : hash) { value += "0123456789abcdef"[byte >> 4]; value += "0123456789abcdef"[byte & 15]; }
    return value;
}

std::string ApprovalIdentity(const fs::path& path)
{
    BlockDevice device(fs::absolute(path).wstring());
    std::vector<std::byte> block;
    Check(device.Read(0, kBlockSize, block), "open approval identity reader");
    BlockDevice::StableImageIdentity identity{};
    std::string value;
    Check(device.QueryHeldImageIdentity(identity) && device.QueryRegularImageIdentity(value), "read approval file identity");
    return "windows-image-v1:" + value + ":" + std::to_string(identity.creation_time);
}

std::string JsonString(const std::string& json, const std::string& key)
{
    const auto marker = "\"" + key + "\":\"";
    const auto start = json.find(marker);
    Check(start != std::string::npos, "report string missing: " + key + ": " + json);
    const auto end = json.find('"', start + marker.size());
    Check(end != std::string::npos, "unterminated report string");
    return json.substr(start + marker.size(), end - start - marker.size());
}

VolumeRepairToolOptions ReviewedApproval(const fs::path& path)
{
    auto options = BaseOptions(path, ScopeOf(path), "apply.wal", "evidence");
    auto probe = options;
    // Independently read review inputs so this regression also compiles with
    // the preserved pre-approval implementation, which ignored these fields.
    const auto review = RunVolumeRepair(probe);
    Check(review.exit_code == 3, "review RCT2 count: " + review.json);
    options.exact_source_approval = true;
    options.confirm = true;
    options.expected_count = JsonExpectedCount(review.json);
    options.approved_source_identity = ApprovalIdentity(path);
    options.approved_source_sha256 = ApprovalHash(path);
    return options;
}

void SameCountApprovalDriftRefuses()
{
    for (const auto kind : {"peer-metadata", "payload", "unused"})
    {
        const auto image = fs::path(std::string(kind) + ".apfs");
        FreshRepair(image); DamageCount(image);
        auto options = ReviewedApproval(image);
        options.journal_path = std::string(kind) + ".wal";
        options.evidence_dir = std::string(kind) + "-evidence";
        if (std::string_view(kind) == "peer-metadata")
        {
            auto spec = RuntimeSpec(); std::string error; bool changed = false;
            for (auto& record : spec.volumes[1].filesystem_records) if (Type(record) == 3)
            {
                AppleInodeRecord inode;
                Check(ApfsExtendedRecordCodec::DecodeInode(record, inode, error), "decode peer inode: " + error);
                ++inode.access_time;
                Check(EncodeAppleInodeRecord(inode, record, error), "encode peer inode: " + error);
                changed = true; break;
            }
            Check(changed, "peer metadata control changed an actual inode");
            for (auto& volume : spec.volumes)
                Check(SortAppleBtreeRecords(volume.filesystem_records, AppleBtreeKeyOrder::FileSystemHashedDirectory, error), error);
            Fresh(image, spec); DamageCount(image);
        }
        else
        {
            auto bytes = Bytes(image);
            const auto offset = std::string_view(kind) == "payload" ? 512 * kBlockSize : bytes.size() - 1;
            bytes[offset] ^= std::byte{1}; Save(image, bytes);
        }
        const auto before = Bytes(image);
        Check(ApprovalIdentity(image) == options.approved_source_identity && ApprovalHash(image) != options.approved_source_sha256,
            "drift preserves exact file identity but changes complete source hash");
        auto reprobe = BaseOptions(image, ScopeOf(image), std::string(kind) + "-probe.wal", "probe-evidence");
        const auto same_count = RunVolumeRepair(reprobe);
        Check(same_count.exit_code == 3 && JsonExpectedCount(same_count.json) == options.expected_count,
            "changed graph remains a real eligible same-count repair: " + same_count.json);
        const auto refused = RunVolumeRepair(options);
        Check(refused.exit_code == 4, "stale same-count approval must refuse: " + refused.json);
        Check(Bytes(image) == before, "stale approval refusal preserves every image byte");
        Check(!fs::exists(options.journal_path) && !fs::exists(fs::path(options.evidence_dir) /
            ("repair-backup-101-" + std::to_string(options.checkpoint_xid) + ".apfs")), "stale approval creates no WAL or backup");
        Pass(std::string("exact approval refuses same-count ") + kind + " drift");
    }
}

void ExactApprovalFlow()
{
    FreshRepair("approved.apfs"); DamageCount("approved.apfs");
    auto options = BaseOptions("approved.apfs", ScopeOf("approved.apfs"), "approved.wal", "approved-evidence");
    options.exact_source_approval = true;
    const auto before = Bytes(options.image);
    const auto dry = RunVolumeRepair(options);
    Check(dry.exit_code == 3 && JsonHas(dry.json, "\"version\":2"), "strict dry plan: " + dry.json);
    Check(JsonString(dry.json, "identity") == ApprovalIdentity(options.image) &&
        JsonString(dry.json, "sha256") == ApprovalHash(options.image), "dry evidence equals independent complete file bytes and identity");
    Check(Bytes(options.image) == before && !JsonHas(dry.json, "confirmationToken"), "dry report preserves bytes and keeps token internal");
    options.confirm = true; options.expected_count = JsonExpectedCount(dry.json);
    options.approved_source_identity = JsonString(dry.json, "identity");
    options.approved_source_sha256 = JsonString(dry.json, "sha256");
    const auto applied = RunVolumeRepair(options);
    Check(applied.exit_code == 0 && JsonHas(applied.json, "\"replayed\":false"), "approved apply and postverify: " + applied.json);
    Check(JsonString(applied.json, "sha256") == options.approved_source_sha256 && LiveFileCount(options.image) == options.expected_count,
        "success binds approved preimage and repairs count");
    const auto after = Bytes(options.image);
    for (const auto block : {512, 513, 514, 515, 528, 529, 530, 531})
        Check(std::equal(before.begin() + block * kBlockSize, before.begin() + (block + 1) * kBlockSize,
            after.begin() + block * kBlockSize), "approved repair preserves original payload bytes");
    auto healthy = BaseOptions(options.image, ScopeOf(options.image), "healthy.wal", "healthy-evidence");
    healthy.exact_source_approval = true;
    const auto result = RunVolumeRepair(healthy);
    Check(result.exit_code == 0 && JsonHas(result.json, "\"plan\":null") &&
        JsonHas(result.json, "RepairHealthyNoFinding") && Bytes(options.image) == after, "healthy strict dry run is a verified no-op");
    Pass("exact reviewed approval applies once and healthy rerun is truthful");
}

void ExactApprovalIdentityAndScopeRefuse()
{
    FreshRepair("identity.apfs"); DamageCount("identity.apfs");
    auto options = ReviewedApproval("identity.apfs");
    const auto original = Bytes(options.image);
    fs::rename(options.image, "retained-original.apfs"); Save(options.image, original);
    Check(ApprovalHash(options.image) == options.approved_source_sha256 && ApprovalIdentity(options.image) != options.approved_source_identity,
        "replacement preserves every image byte but has a new file identity");
    Check(RunVolumeRepair(options).exit_code == 4 && Bytes(options.image) == original, "byte-identical replacement refuses");
    options.approved_source_identity = ApprovalIdentity(options.image);
    auto wrong_count = options; ++wrong_count.expected_count;
    Check(RunVolumeRepair(wrong_count).exit_code == 4 && Bytes(options.image) == original, "approved source still requires exact count intent");
    for (unsigned selector = 0; selector < 5; ++selector)
    {
        auto wrong = options;
        if (selector == 0) ++wrong.checkpoint_xid;
        if (selector == 1) wrong.volume_uuid = std::string(32, 'd');
        if (selector == 2) wrong.container_uuid = std::string(32, 'd');
        if (selector == 3) wrong.volume_oid = 999;
        if (selector == 4) wrong.store_offset_bytes = kBlockSize;
        Check(RunVolumeRepair(wrong).exit_code == 4 && Bytes(options.image) == original, "strict source approval never bypasses exact scope");
    }
    Pass("exact approval rejects replacement and wrong UUID/OID/XID/window");
}

void ExactApprovalExclusiveOwner()
{
    FreshRepair("leased.apfs"); DamageCount("leased.apfs");
    const auto before = Bytes("leased.apfs");
    auto options = BaseOptions("leased.apfs", ScopeOf("leased.apfs"), "leased.wal", "leased-evidence");
    options.exact_source_approval = true;
    std::string error;
    {
        auto held = BlockDevice::OpenExclusiveManagementImage(fs::absolute(options.image).wstring(), 0, error);
        Check(!!held, "hold exact image lease: " + error);
        const auto refused = RunVolumeRepair(options);
        Check(refused.exit_code == 4 && JsonHas(refused.json, "\"source\":null"), "strict invocation cannot borrow another owner's file");
    }
    Check(Bytes(options.image) == before, "exclusive-owner refusal preserves every byte");
    Check(!fs::exists(options.journal_path), "exclusive-owner refusal creates no journal");
    Pass("strict approval source is read only after acquiring its own exclusive owner");
}

void ExactApprovalReplay()
{
    FreshRepair("replay.apfs"); DamageCount("replay.apfs");
    auto options = ReviewedApproval("replay.apfs");
    Check(_putenv_s("APFS_REPAIR_TEST_HOOKS", "1") == 0, "enable strict interruption");
    options.test_abort_stage = "before-apple-publish";
    const auto interrupted = RunVolumeRepair(options);
    Check(_putenv_s("APFS_REPAIR_TEST_HOOKS", "") == 0, "disable strict interruption");
    Check(interrupted.exit_code == 5 && JsonHas(interrupted.json, "RepairRecoveryRequired"), "strict accepted interruption is not success");
    auto resume = BaseOptions(options.image, ScopeOf(options.image), options.journal_path, options.evidence_dir);
    resume.exact_source_approval = true;
    const auto replay = RunVolumeRepair(resume);
    Check(replay.exit_code == 0 && JsonHas(replay.json, "\"replayed\":true") && JsonHas(replay.json, "\"plan\":null"),
        "exact original-journal recovery requires no new approval: " + replay.json);
    Save("foreign.wal", {std::byte{1}, std::byte{2}});
    const auto before = Bytes(options.image);
    resume = BaseOptions(options.image, ScopeOf(options.image), "foreign.wal", "foreign-evidence"); resume.exact_source_approval = true;
    Check(RunVolumeRepair(resume).exit_code == 4 && Bytes(options.image) == before, "strict mode does not adopt foreign journal authority");
    Pass("strict original accepted journal replays and foreign journal refuses");
}

void CompletedOriginalJournalLostReplyCase(bool zero_files)
{
    if (zero_files)
    {
        auto spec = RuntimeSpec();
        auto& selected = spec.volumes[0];
        std::erase_if(selected.filesystem_records, [](const auto& record) { return Type(record) != 3 || Id(record) != 2; });
        std::string error;
        Check(selected.filesystem_records.size() == 1, "zero-file fixture keeps its genuine root inode");
        AppleInodeRecord root;
        Check(ApfsExtendedRecordCodec::DecodeInode(selected.filesystem_records[0], root, error), error);
        root.children_or_links = 0;
        Check(EncodeAppleInodeRecord(root, selected.filesystem_records[0], error), error);
        selected.extentref_records.clear(); selected.additional_file_system_allocated_blocks = 0;
        for (auto& volume : spec.volumes)
            Check(SortAppleBtreeRecords(volume.filesystem_records, AppleBtreeKeyOrder::FileSystemHashedDirectory, error), error);
        Fresh("terminal.apfs", spec);
    }
    else FreshRepair("terminal.apfs");
    DamageCount("terminal.apfs");
    auto original = ReviewedApproval("terminal.apfs");
    Check(!zero_files || original.expected_count == 0, "zero-file repair uses literal expected count zero");
    const auto applied = RunVolumeRepair(original);
    Check(applied.exit_code == 0 && JsonHas(applied.json, "RepairedAndVerified") &&
        JsonHas(applied.json, "\"replayed\":false"), "genuine apply fully succeeds before reply loss: " + applied.json);
    const auto current = ScopeOf(original.image);
    Check(current.xid > original.checkpoint_xid, "lost reply follows real checkpoint publication");
    const auto image = Bytes(original.image), wal = Bytes(original.journal_path);
    const auto backup_path = fs::path(original.evidence_dir) /
        ("repair-backup-101-" + std::to_string(original.checkpoint_xid) + ".apfs");
    const auto backup = Bytes(backup_path);
    {
        Tx journal(L"Strict"); std::string error;
        Check(journal.OpenExistingRepairJournal(fs::absolute(original.journal_path).wstring(),
            AsciiWiden("apfs-vol:" + original.container_uuid + ":101"), error), "open genuine terminal receipt: " + error);
        const auto marks = journal.Watermarks();
        Check(marks.accepted_sequence && marks.accepted_sequence == marks.apfs_durable_sequence &&
            marks.accepted_sequence == marks.cleanup_sequence && !journal.HasUnappliedAcceptedWork(),
            "genuine repair has completed original cleanup, not replayable debt");
    }
    for (unsigned retry = 0; retry != 2; ++retry)
    {
        const auto result = RunVolumeRepair(original);
        std::cout << "TERMINAL_ORIGINAL_RETRY " << retry << " " << result.json << '\n';
        Check(Bytes(original.image) == image && Bytes(original.journal_path) == wal && Bytes(backup_path) == backup,
            "completed original retry preserves image, original WAL and approved backup exactly");
        Check(result.exit_code == 0 && JsonHas(result.json, "RepairedAndVerified") &&
            JsonHas(result.json, "\"replayed\":true") && JsonHas(result.json, "\"applied\":true") &&
            JsonHas(result.json, "\"plan\":null") && JsonHas(result.json, "\"finding\":null") &&
            JsonHas(result.json, "\"bytesUnchanged\":true") && JsonHas(result.json, "\"findings\":0"),
            "completed original journal must reconcile lost genuine success: " + result.json);
        Check(JsonString(result.json, "identity") == original.approved_source_identity &&
            JsonString(result.json, "sha256") == ApprovalHash(original.image) &&
            ScopeOf(original.image).xid == current.xid, "terminal receipt binds current leased source without another publication");
    }
    Pass(std::string("completed original journal reconciles repeated lost success with ") + (zero_files ? "zero files" : "real payload"));
}

void CompletedOriginalJournalLostReply() { CompletedOriginalJournalLostReplyCase(false); }
void CompletedZeroFileOriginalJournal() { CompletedOriginalJournalLostReplyCase(true); }

void SaveWalRecords(const fs::path& path, const std::vector<WriteAheadLog::Record>& records)
{
    std::vector<std::byte> bytes;
    for (const auto& record : records)
    {
        const auto encoded = WriteAheadLog::EncodeForTest(record);
        Check(!encoded.empty(), "control WAL uses the actual versioned checksum codec");
        const auto* first = reinterpret_cast<const std::byte*>(encoded.data());
        bytes.insert(bytes.end(), first, first + encoded.size());
    }
    Save(path, bytes);
}

void CompletedOriginalJournalRefusals()
{
    FreshRepair("controls.apfs"); DamageCount("controls.apfs");
    const auto original = ReviewedApproval("controls.apfs");
    const auto applied = RunVolumeRepair(original);
    Check(applied.exit_code == 0, "terminal controls start after genuine full success: " + applied.json);
    const auto image = Bytes(original.image), wal = Bytes(original.journal_path);
    const auto backup_path = fs::path(original.evidence_dir) /
        ("repair-backup-101-" + std::to_string(original.checkpoint_xid) + ".apfs");
    const auto backup = Bytes(backup_path);
    const auto identity = "apfs-vol:" + original.container_uuid + ":101";
    const auto decoded = WriteAheadLog::ReadAll(original.journal_path, identity);
    Check(decoded.status == WriteAheadLog::ReadStatus::Ok && decoded.records.size() == 4, "actual retained terminal transaction decoded");
    const auto refuse = [&](const std::string& name, const VolumeRepairToolOptions& options, std::string_view detail = {}) {
        const auto before_image = Bytes(original.image), before_wal = Bytes(original.journal_path);
        const bool has_backup = fs::exists(backup_path), has_input_wal = fs::exists(options.journal_path);
        const auto before_backup = has_backup ? Bytes(backup_path) : std::vector<std::byte>{};
        const auto input_wal = has_input_wal ? Bytes(options.journal_path) : std::vector<std::byte>{};
        const auto result = RunVolumeRepair(options);
        std::cout << "TERMINAL_REFUSAL " << name << " " << result.json << '\n';
        Check(Bytes(original.image) == before_image && Bytes(original.journal_path) == before_wal &&
            fs::exists(backup_path) == has_backup && (!has_backup || Bytes(backup_path) == before_backup) &&
            fs::exists(options.journal_path) == has_input_wal && (!has_input_wal || Bytes(options.journal_path) == input_wal),
            name + " preserves image, original/input WAL and original backup including absence");
        Check(result.exit_code == 4 && JsonHas(result.json, "\"code\":\"RepairRefused\"") &&
            JsonHas(result.json, "\"applied\":false") && JsonHas(result.json, "\"replayed\":false") &&
            JsonHas(result.json, "\"bytesUnchanged\":true") && (detail.empty() || JsonHas(result.json, std::string(detail))),
            name + " must refuse without adopting healthy/current-count authority: " + result.json);
        Pass("terminal refusal: " + name);
    };
    auto wrong = original; ++wrong.expected_count;
    refuse("wrong original count", wrong, "OriginalReceiptMismatch");
    wrong = original; wrong.approved_source_sha256 = std::string(64, '0');
    refuse("wrong original approval hash", wrong, "ApprovedBackupMismatch");
    for (unsigned field = 0; field != 6; ++field)
    {
        wrong = original;
        if (field == 0) --wrong.checkpoint_xid;
        if (field == 1) wrong.volume_uuid = std::string(32, 'd');
        if (field == 2) wrong.container_uuid = std::string(32, 'd');
        if (field == 3) wrong.volume_oid = 999;
        if (field == 4) wrong.store_offset_bytes = kBlockSize;
        if (field == 5) wrong.store_size_bytes += kBlockSize;
        refuse("wrong original selector " + std::to_string(field), wrong);
    }
    fs::rename(backup_path, "held-backup.apfs");
    refuse("missing original backup", original, "held original approved backup");
    fs::rename("held-backup.apfs", backup_path);
    auto changed = backup; changed.back() ^= std::byte{1}; Save(backup_path, changed);
    refuse("tampered original backup unused byte", original, "ApprovedBackupMismatch"); Save(backup_path, backup);
    {
        HANDLE writer = CreateFileW(fs::absolute(backup_path).c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        Check(writer != INVALID_HANDLE_VALUE, "hold a real incompatible backup writer without writing");
        const auto result = RunVolumeRepair(original);
        Check(CloseHandle(writer) != FALSE, "close held control writer");
        Check(result.exit_code == 4 && Bytes(original.image) == image && Bytes(original.journal_path) == wal && Bytes(backup_path) == backup,
            "completed proof must acquire its own write-denying backup lease: " + result.json);
        Pass("terminal refusal: backup cannot obtain a stable read lease");
    }
    fs::rename(original.image, "original-image-held.apfs"); Save(original.image, image);
    Check(ApprovalIdentity(original.image) != original.approved_source_identity, "byte-identical control has a different actual file ID");
    refuse("byte-identical replacement image", original, "exact original image identity");
    fs::rename(original.image, "replacement-image.apfs"); fs::rename("original-image-held.apfs", original.image);
    wrong = original; wrong.journal_path = "missing.wal";
    refuse("missing original journal", wrong);
    Save("empty.wal", {}); wrong.journal_path = "empty.wal"; refuse("empty original journal", wrong);
    Save("foreign.wal", {std::byte{1}, std::byte{2}}); wrong.journal_path = "foreign.wal"; refuse("foreign journal", wrong);
    auto torn = wal; torn.pop_back(); Save("torn.wal", torn); wrong.journal_path = "torn.wal"; refuse("torn terminal journal", wrong);
    Save("oversize.wal", std::vector<std::byte>(8 * 1024 * 1024 + 1)); wrong.journal_path = "oversize.wal";
    refuse("bounded journal oversize", wrong, "8 MiB");
    auto records = decoded.records;
    NativeCountRepair repair;
    Check(DecodeNativeCountRepair(records[0].inline_payload, repair), "decode genuine RCT2 control");
    repair.graph_sha256[0] = repair.graph_sha256[0] == '0' ? '1' : '0';
    records[0].inline_payload = EncodeNativeCountRepair(repair);
    HashPayload(records[0].inline_payload, records[0].payload_sha256);
    SaveWalRecords("forged-graph.wal", records); wrong.journal_path = "forged-graph.wal";
    refuse("valid-codec forged RCT2 graph proof", wrong, "ApprovedPreimageInvalid");
    records = decoded.records;
    auto extra = decoded.records;
    for (auto& record : extra)
    {
        record.sequence += records.back().sequence;
        if (record.transaction_id) record.transaction_id += 10;
        if (record.operation == WriteAheadLog::OperationKind::DurabilityWatermark) record.logical_offset += records.back().sequence;
    }
    records.insert(records.end(), extra.begin(), extra.end());
    SaveWalRecords("mixed.wal", records); wrong.journal_path = "mixed.wal";
    refuse("mixed completed transactions", wrong, "OriginalReceiptMissing");
    records.assign(decoded.records.begin() + 2, decoded.records.end());
    SaveWalRecords("watermarks-only.wal", records); wrong.journal_path = "watermarks-only.wal";
    refuse("clean watermarks without original acceptance", wrong);
    Save("compacted.wal", wal);
    {
        WriteAheadLog compacted({fs::absolute("compacted.wal"), identity});
        Check(compacted.Compact(decoded.records[1].sequence + 1), "actual canonical compaction drops original acceptance");
    }
    const auto compacted = WriteAheadLog::ReadAll("compacted.wal", identity);
    Check(compacted.status == WriteAheadLog::ReadStatus::Ok && !compacted.records.empty() &&
        std::none_of(compacted.records.begin(), compacted.records.end(), [](const auto& record) {
            return record.operation == WriteAheadLog::OperationKind::RepairVolumeFileCount ||
                record.operation == WriteAheadLog::OperationKind::TransactionMarker;
        }), "real compacted control has lost original mutation/acceptance authority");
    wrong.journal_path = "compacted.wal"; refuse("actual compacted-away original receipt", wrong);
    changed = image; changed[512 * kBlockSize] ^= std::byte{1}; Save(original.image, changed);
    refuse("current payload differs from original RCT2 graph", original); Save(original.image, image);
    VectorRandomAccessSource source(backup); std::string error;
    const auto before = LoadAppleCheckpointView(source, 0, backup.size(), error);
    Check(!!before, "load exact approved historical APSB for corruption control: " + error);
    const auto old_block = before->volumes[0].superblock_object.physical_block;
    changed = image;
    std::vector<std::byte> apsb(changed.begin() + old_block * kBlockSize, changed.begin() + (old_block + 1) * kBlockSize);
    PutU64LE(apsb, 0xb8, 98); Check(FinalizeAppleObjectChecksum(apsb, error), "valid-codec retained-preimage change");
    std::copy(apsb.begin(), apsb.end(), changed.begin() + old_block * kBlockSize); Save(original.image, changed);
    auto current = original; current.checkpoint_xid = ScopeOf(original.image).xid;
    VerificationReport healthy;
    Check(VerifyImageBytes(changed, current, healthy, error), "current subset remains healthy despite changed retained preimage: " + error);
    refuse("healthy current graph with damaged original retained preimage", original, "PublicationPreimageMismatch");
    Save(original.image, image);
    Check(Bytes(original.journal_path) == wal && Bytes(backup_path) == backup, "all terminal controls preserve original accepted evidence");
}

void ExactApprovalArguments()
{
    FreshRepair("arguments.apfs"); DamageCount("arguments.apfs");
    auto options = ReviewedApproval("arguments.apfs");
    for (const auto bad : {"", "a", "ABCDEF", "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg"})
    {
        auto wrong = options; wrong.approved_source_sha256 = bad;
        Check(RunVolumeRepair(wrong).exit_code == 2, "malformed or missing source hash refuses before owner");
    }
    auto wrong = options; wrong.approved_source_identity.clear(); Check(RunVolumeRepair(wrong).exit_code == 2, "count-only strict apply refuses");
    wrong = options; wrong.exact_source_approval = false; Check(RunVolumeRepair(wrong).exit_code == 2, "approval cannot silently select legacy mode");
    const auto args = std::vector<std::string>{"--image", options.image, "--container-uuid", options.container_uuid,
        "--volume-uuid", options.volume_uuid, "--volume-oid", "101", "--checkpoint-xid", std::to_string(options.checkpoint_xid),
        "--store-offset-bytes", "0", "--store-size-bytes", std::to_string(options.store_size_bytes), "--journal", "parser.wal", "--evidence-dir", "parser-evidence"};
    for (const auto tail : {std::vector<std::string>{"--approval-mode", "wrong"},
        std::vector<std::string>{"--approval-mode", "exact-source-v1", "--approval-mode", "exact-source-v1"},
        std::vector<std::string>{"--approval-mode", "exact-source-v1", "--confirm", "--expected-count", "1"}})
    {
        auto input = args; input.insert(input.end(), tail.begin(), tail.end()); bool rejected = false;
        try { (void)ParseVolumeRepairArguments(input); } catch (const ToolArgumentError&) { rejected = true; }
        Check(rejected, "malformed mode, duplicate mode, or count-only strict argv refuses");
    }
    Pass("strict mode and approval arguments fail closed");
}

std::vector<std::string> RepairArgumentVector(const VolumeRepairToolOptions& options)
{
    return {"--image", options.image, "--container-uuid", options.container_uuid,
        "--volume-uuid", options.volume_uuid, "--volume-oid", std::to_string(options.volume_oid),
        "--checkpoint-xid", std::to_string(options.checkpoint_xid), "--store-offset-bytes", "0",
        "--store-size-bytes", std::to_string(options.store_size_bytes), "--journal", options.journal_path,
        "--evidence-dir", options.evidence_dir};
}

void ExplicitEmptyApprovalArgumentsRefuse()
{
    FreshRepair("empty-approval.apfs"); DamageCount("empty-approval.apfs");
    const auto before = Bytes("empty-approval.apfs");
    const auto scope = ScopeOf("empty-approval.apfs");
    auto probe = BaseOptions("empty-approval.apfs", scope, "probe.wal", "probe-evidence");
    const auto review = RunVolumeRepair(probe);
    Check(review.exit_code == 3, "empty-argument control is a genuine eligible repair: " + review.json);
    const auto count = JsonExpectedCount(review.json);
    unsigned ordinal = 0;
    // Put the confirmed legacy cases first: the preserved implementation must
    // demonstrate actual count-only publication, rather than a setup failure.
    for (const bool strict : {false, true}) for (const bool confirm : {true, false})
        for (const unsigned fields : {1u, 2u, 3u})
    {
        auto options = probe;
        options.journal_path = "empty-" + std::to_string(++ordinal) + ".wal";
        options.evidence_dir = "empty-evidence-" + std::to_string(ordinal);
        auto input = RepairArgumentVector(options);
        if (confirm) input.insert(input.end(), {"--confirm", "--expected-count", std::to_string(count)});
        if (strict) input.insert(input.end(), {"--approval-mode", "exact-source-v1"});
        if (fields & 1) input.insert(input.end(), {"--approved-source-identity", ""});
        if (fields & 2) input.insert(input.end(), {"--approved-source-sha256", ""});
        bool rejected = false;
        VolumeRepairToolOptions parsed;
        try { parsed = ParseVolumeRepairArguments(input); }
        catch (const ToolArgumentError&) { rejected = true; }
        if (!rejected)
        {
            const auto result = RunVolumeRepair(parsed);
            std::cout << "EMPTY_APPROVAL_CONTROL strict=" << strict << " confirm=" << confirm
                << " fields=" << fields << " imageUnchanged=" << (Bytes(options.image) == before)
                << " journalExists=" << fs::exists(options.journal_path) << " result=" << result.json << '\n';
            Check(false, "explicit empty source approval argv reached owner admission: " + result.json);
        }
        Check(Bytes(options.image) == before && !fs::exists(options.journal_path) && !fs::exists(options.evidence_dir),
            "explicit empty approval rejects before owner/WAL/backup admission and preserves all bytes");
        Pass("explicit empty source approval argv refuses: " + std::to_string(ordinal));
    }
}

void ValidApprovalArgumentFlow()
{
    FreshRepair("valid-argv.apfs"); DamageCount("valid-argv.apfs");
    auto options = BaseOptions("valid-argv.apfs", ScopeOf("valid-argv.apfs"), "valid-argv.wal", "valid-evidence");
    auto input = RepairArgumentVector(options);
    input.insert(input.end(), {"--approval-mode", "exact-source-v1"});
    const auto dry = RunVolumeRepair(ParseVolumeRepairArguments(input));
    Check(dry.exit_code == 3 && JsonHas(dry.json, "\"version\":2"), "valid strict argv still plans: " + dry.json);
    input.insert(input.end(), {"--confirm", "--expected-count", std::to_string(JsonExpectedCount(dry.json)),
        "--approved-source-identity", JsonString(dry.json, "identity"), "--approved-source-sha256", JsonString(dry.json, "sha256")});
    const auto result = RunVolumeRepair(ParseVolumeRepairArguments(input));
    Check(result.exit_code == 0 && JsonHas(result.json, "\"version\":2") && JsonHas(result.json, "RepairedAndVerified"),
        "valid strict argv still confirms exact source: " + result.json);
    Pass("valid strict approval argv plans and confirms");
}

void LegacyArgumentConfirmation()
{
    FreshRepair("legacy-argv.apfs"); DamageCount("legacy-argv.apfs");
    auto options = BaseOptions("legacy-argv.apfs", ScopeOf("legacy-argv.apfs"), "legacy-argv.wal", "legacy-evidence");
    auto input = RepairArgumentVector(options);
    const auto dry = RunVolumeRepair(ParseVolumeRepairArguments(input));
    Check(dry.exit_code == 3 && JsonHas(dry.json, "\"version\":1"), "legacy argv dry run remains v1: " + dry.json);
    const auto count = JsonExpectedCount(dry.json);
    input.insert(input.end(), {"--confirm", "--expected-count", std::to_string(count)});
    const auto parsed = ParseVolumeRepairArguments(input);
    Check(parsed.confirm && !parsed.exact_source_approval, "legacy absence of source flags retains legacy confirmation");
    const auto result = RunVolumeRepair(parsed);
    Check(result.exit_code == 0 && JsonHas(result.json, "\"version\":1") && !JsonHas(result.json, "\"source\":") &&
        LiveFileCount(options.image) == count, "legacy count-only argv confirmation remains supported: " + result.json);
    Pass("legacy argv confirmation remains v1 without source flags");
}

#ifndef APFS_REPAIR_TOOL_BASELINE
std::string TestPathUtf8(const fs::path& path)
{
    const auto text = path.u8string();
    return std::string(reinterpret_cast<const char*>(text.data()), text.size());
}

void UnicodeRepairPaths(bool supplementary, bool strict)
{
    const auto segment = supplementary ? fs::path(u8"\U0001f680 \u8def\u5f84") : fs::path(u8"\u4e2d\u6587 \u8def\u5f84");
    const auto directory = fs::current_path() / segment;
    fs::create_directories(directory);
    const auto image_path = directory / fs::path(u8"\u955c\u50cf.apfs");
    const auto journal_path = directory / fs::path(u8"\u539f\u59cb.rct2");
    const auto evidence_path = directory / fs::path(u8"\u5907\u4efd\u8bc1\u636e");
    FreshRepair(image_path); DamageCount(image_path);
    const auto before = Bytes(image_path);
    auto options = BaseOptions("unused.apfs", ScopeOf(image_path), "unused.wal", "unused-evidence");
    options.image = TestPathUtf8(image_path);
    options.journal_path = TestPathUtf8(journal_path);
    options.evidence_dir = TestPathUtf8(evidence_path);
    options.exact_source_approval = strict;
    const auto invoke = [&](const VolumeRepairToolOptions& input, const char* stage) {
        auto args = RepairArgumentVector(input);
        const auto out = directory / fs::path(u8"\u62a5\u544a") / (std::string(stage) + ".json");
        args.insert(args.end(), {"--out", TestPathUtf8(out)});
        if (strict) args.insert(args.end(), {"--approval-mode", "exact-source-v1"});
        if (input.confirm) {
            args.insert(args.end(), {"--confirm", "--expected-count", std::to_string(input.expected_count)});
            if (strict) args.insert(args.end(), {"--approved-source-identity", input.approved_source_identity,
                "--approved-source-sha256", input.approved_source_sha256});
        }
        const auto result = RunVolumeRepair(ParseVolumeRepairArguments(args));
        Check(IsValidUtf8(reinterpret_cast<const std::byte*>(result.json.data()), result.json.size()),
            "Unicode report is valid UTF-8: " + result.json);
        Check(JsonHas(result.json, TestPathUtf8(segment)) && JsonHas(result.json, TestPathUtf8(image_path.filename())) &&
            JsonHas(result.json, TestPathUtf8(fs::u8path(input.journal_path).filename())), "report preserves original Unicode image and journal names");
        const auto saved = Bytes(out);
        Check(std::string(reinterpret_cast<const char*>(saved.data()), saved.size()) == result.json + "\n",
            "Unicode report output exists at the exact requested path and equals stdout document");
        return result;
    };
    const auto dry = invoke(options, "dry");
    Check(dry.exit_code == 3 && Bytes(image_path) == before, "Unicode dry run prepares real repair without mutation: " + dry.json);
    options.confirm = true; options.expected_count = JsonExpectedCount(dry.json);
    if (strict) {
        options.approved_source_identity = JsonString(dry.json, "identity");
        options.approved_source_sha256 = JsonString(dry.json, "sha256");
        Check(options.approved_source_sha256 == ApprovalHash(image_path), "Unicode public approval binds exact image bytes");
    }
    const auto result = invoke(options, "apply");
    Check(result.exit_code == 0 && JsonHas(result.json, "RepairedAndVerified"), "Unicode confirmed repair succeeds: " + result.json);
    const auto current = ScopeOf(image_path);
    Check(current.xid > options.checkpoint_xid && LiveFileCount(image_path) == options.expected_count,
        "Unicode path repair actually publishes the expected counter");
    const auto backup_path = evidence_path / ("repair-backup-101-" + std::to_string(options.checkpoint_xid) + ".apfs");
    Check(Bytes(backup_path) == before && fs::file_size(journal_path) > 0 && JsonHas(result.json, TestPathUtf8(evidence_path.filename())),
        "Unicode backup and accepted journal are preserved at the exact native paths");
    const auto after = Bytes(image_path), wal = Bytes(journal_path);
    if (strict) {
        const auto replay = invoke(options, "original-retry");
        Check(replay.exit_code == 0 && JsonHas(replay.json, "\"replayed\":true") &&
            Bytes(image_path) == after && Bytes(journal_path) == wal && Bytes(backup_path) == before,
            "Unicode original-terminal reconciliation preserves every authority byte: " + replay.json);
    }
    auto healthy = options;
    healthy.checkpoint_xid = current.xid; healthy.confirm = false; healthy.expected_count = 0;
    healthy.approved_source_identity.clear(); healthy.approved_source_sha256.clear();
    healthy.journal_path = TestPathUtf8(directory / fs::path(u8"\u5065\u5eb7.rct2"));
    const auto no_op = invoke(healthy, "healthy");
    Check(no_op.exit_code == 0 && JsonHas(no_op.json, "RepairHealthyNoFinding") && Bytes(image_path) == after,
        "Unicode healthy result remains an unchanged verified no-op: " + no_op.json);
    Pass(std::string(strict ? "v2" : "v1") + " Unicode image/report/journal/backup paths: " + (supplementary ? "supplementary" : "Chinese"));
}

void UnicodeChineseStrictPaths() { UnicodeRepairPaths(false, true); }
void UnicodeSupplementaryStrictPaths() { UnicodeRepairPaths(true, true); }
void UnicodeChineseLegacyPaths() { UnicodeRepairPaths(false, false); }
void UnicodeSupplementaryLegacyPaths() { UnicodeRepairPaths(true, false); }

void InvalidUnicodeArgumentsRefuse()
{
    FreshRepair("invalid-unicode.apfs"); DamageCount("invalid-unicode.apfs");
    auto options = BaseOptions("invalid-unicode.apfs", ScopeOf("invalid-unicode.apfs"), "absent.wal", "absent-evidence");
    options.exact_source_approval = true;
    const auto before = Bytes(options.image);
    for (const auto& bad : {std::string("\xc0\xaf", 2), std::string("\x80", 1), std::string("\xed\xa0\x80", 3),
        std::string("\xf0\x9f\x98", 3), std::string("prefix\0suffix", 13)})
        for (unsigned field = 0; field != 4; ++field)
    {
        auto wrong = options;
        if (field == 0) wrong.image = bad;
        if (field == 1) wrong.journal_path = bad;
        if (field == 2) wrong.evidence_dir = bad;
        if (field == 3) wrong.out_path = bad;
        const auto result = RunVolumeRepair(wrong);
        Check(result.exit_code == 2 && JsonHas(result.json, "InvalidArguments") &&
            IsValidUtf8(reinterpret_cast<const std::byte*>(result.json.data()), result.json.size()) &&
            Bytes(options.image) == before && !fs::exists(options.journal_path) && !fs::exists(options.evidence_dir),
            "invalid UTF-8/NUL path refuses before output/owner/WAL admission: " + result.json);
    }
    Pass("all path arguments reject invalid UTF-8 and embedded NUL before filesystem admission");
}

void UnicodeEntryAndDiagnostics()
{
#if defined(_WIN32)
    Check(RepairArgumentUtf8(L"\u4e2d\u6587 \U0001f680") == std::string("\xe4\xb8\xad\xe6\x96\x87 \xf0\x9f\x9a\x80"),
        "Windows entry converts BMP and surrogate pairs to exact UTF-8 without ACP");
    for (const wchar_t invalid : {wchar_t(0xd800), wchar_t(0xdc00)})
    {
        std::ostringstream output;
        auto* previous = std::cout.rdbuf(output.rdbuf());
        const auto code = VolumeRepairToolEntry([&] { return std::vector<std::string>{RepairArgumentUtf8(std::wstring(1, invalid))}; });
        std::cout.rdbuf(previous);
        Check(code == 2 && JsonHas(output.str(), "InvalidArguments") && JsonHas(output.str(), "invalid UTF-16 argument"),
            "Windows entry catches malformed UTF-16 and emits a bounded JSON argument failure");
    }
#endif
    std::string escaped;
    JsonEscape(escaped, std::string("diagnostic \xd6\xd0\xce\xc4", 15));
    Check(escaped == "diagnostic \\u00d6\\u00d0\\u00ce\\u00c4" &&
        IsValidUtf8(reinterpret_cast<const std::byte*>(escaped.data()), escaped.size()), "non-UTF-8 diagnostic bytes cannot corrupt JSON transport");
    Pass("Windows Unicode entry and unknown diagnostic encodings preserve valid JSON transport");
}

void BoundedInitialRead()
{
    std::string error;
    std::istringstream oversized("sentinel");
    Check(ReadBoundedRepairBytes(oversized, kMaxRepairImageBytes + 1, error).empty() &&
        oversized.tellg() == 0 && !error.empty(), "oversize rejected before input read or allocation");
    std::istringstream growing("12345");
    Check(ReadBoundedRepairBytes(growing, 4, error).empty() && !error.empty(), "reader growth beyond observed size refuses");
    std::istringstream short_read("123");
    Check(ReadBoundedRepairBytes(short_read, 4, error).empty() && !error.empty(), "short initial read refuses");
    std::istringstream exact("1234");
    Check(ReadBoundedRepairBytes(exact, 4, error).size() == 4 && error.empty(), "bounded exact initial read remains admitted");
    Pass("initial image reads reject oversize, growth and short read");
}
#endif
} // namespace
int main(int argc, char** argv)
{
    try
    {
        const auto root = fs::current_path() /
            ("run-" + std::to_string(GetCurrentProcessId()) + "-" + std::to_string(GetTickCount64()));
        fs::create_directories(root);
        unsigned ordinal = 0;
        const auto run = [&](auto test) {
            const auto path = root / std::to_string(++ordinal);
            fs::create_directory(path);
            fs::current_path(path);
            test();
            fs::current_path(root);
        };
        const std::string_view group = argc == 3 && std::string_view(argv[1]) == "--group" ? argv[2] : "all";
        Check((argc == 1 || argc == 3) && (group == "all" || group == "legacy" || group == "approval" || group == "approval-red" ||
            group == "bounds" || group == "arguments" || group == "arguments-red" || group == "legacy-confirmation" ||
            group == "terminal" || group == "terminal-red" || group == "terminal-controls" || group == "recovery-compat" ||
            group == "unicode" || group == "unicode-compat"), "known focused repair group");
        if (group == "all" || group == "legacy") {
        run(DryRunDisplaysPlanWithoutMutation);
        run(DryRunThenConfirmSameJournal);
        run(ApplyRepairsAndVerifies);
        run(RerunAfterSuccessReportsHealthy);
        run(WrongIntentRefuses);
        run(WrongSelectorsRefuse);
        run(GrowthBeyondScopeRefuses);
        run(SnapshotBearingRefuses);
        run(ForeignJournalRefuses);
        run(ConcurrentOwnerRefuses);
        run(InterruptedCommitReplays);
        run(FusionMemberRefuses);
        run(ArgumentValidation);
        run(ReportOutputNeverOverwritesExistingFiles);
        }
        if (group == "all" || group == "approval" || group == "approval-red") run(SameCountApprovalDriftRefuses);
        if (group == "all" || group == "approval") {
            run(ExactApprovalFlow);
            run(ExactApprovalIdentityAndScopeRefuse);
            run(ExactApprovalExclusiveOwner);
            run(ExactApprovalReplay);
            run(ExactApprovalArguments);
        }
        if (group == "all" || group == "arguments" || group == "arguments-red") run(ExplicitEmptyApprovalArgumentsRefuse);
        if (group == "arguments") {
            run(ArgumentValidation);
            run(ExactApprovalArguments);
            run(ValidApprovalArgumentFlow);
        }
        if (group == "all" || group == "legacy-confirmation") run(LegacyArgumentConfirmation);
        if (group == "all" || group == "terminal" || group == "terminal-red") run(CompletedOriginalJournalLostReply);
        if (group == "all" || group == "terminal") run(CompletedZeroFileOriginalJournal);
        if (group == "all" || group == "terminal-controls") run(CompletedOriginalJournalRefusals);
        if (group == "recovery-compat") {
            run(ExactApprovalReplay);
            run(ValidApprovalArgumentFlow);
            run(LegacyArgumentConfirmation);
        }
#ifndef APFS_REPAIR_TOOL_BASELINE
        if (group == "all" || group == "unicode") {
            run(UnicodeChineseStrictPaths);
            run(UnicodeSupplementaryStrictPaths);
            run(UnicodeChineseLegacyPaths);
            run(UnicodeSupplementaryLegacyPaths);
            run(InvalidUnicodeArgumentsRefuse);
            run(UnicodeEntryAndDiagnostics);
        }
        if (group == "unicode-compat") {
            run(ValidApprovalArgumentFlow);
            run(LegacyArgumentConfirmation);
            run(CompletedOriginalJournalLostReply);
        }
        if (group == "all" || group == "bounds") run(BoundedInitialRead);
#endif
        std::cout << "PASS " << cases << " cases, " << checks << " checks\n";
        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << "FAIL after " << cases << " cases, " << checks << " checks: " << error.what() << '\n';
        return 1;
    }
}
