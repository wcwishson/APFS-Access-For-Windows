#include "VolumeKeeperAdmission.h"
#include "VolumeManagement.h"
#include "VolumeResizeFixture.h"
#include "../src/VolumeResizeInternal.h"
#include <Windows.h>
#include <bcrypt.h>
#include <iostream>
#include <future>
#include "TransactionManager.h"
#include "BlockDevice.h"
#include "ApfsContainerCatalog.h"
#include "AppleVolumeTransaction.h"
using namespace apfsaccess;
using namespace rw;
using namespace volume_image_test;
namespace
{
unsigned checks = 0, groups = 0;
std::filesystem::path root;
void Check(bool ok, const std::string& message) { ++checks; if (!ok) throw std::runtime_error(message); }
void Pass(const char* name) { ++groups; std::cout << "PASS " << name << std::endl; }
Bytes CrossFixture()
{
    auto b = Fixture();
    for (std::size_t at = 0; at < b.size(); at += 4096) {
        Bytes nx(b.begin() + at, b.begin() + at + 4096); if (!catalog::ParseNxSuperblock(nx)) continue;
        nx[0x48] = std::byte{0x7a}; nx[0x49] = std::byte{0x19};
        testfixture::FletcherForBlock(nx, 4096); std::copy(nx.begin(), nx.end(), b.begin() + at);
    }
    return b;
}
VolumeImageRequest Setup(const std::string& name, VolumeImageOperation op = VolumeImageOperation::Grow)
{
    auto path = root / name; Check(!std::filesystem::exists(path), "fresh artifact directory"); std::filesystem::create_directories(path);
    const auto b = CrossFixture(); auto r = Request(path, op, b); Save(r.image, b);
    for (const auto& [oid, wal] : r.sibling_wals) Save(wal, {});
    r.new_container_uuid = op == VolumeImageOperation::Format ? "7b294455667748899abbccddeeff0022" : "";
    return r;
}
VolumeManagementRequest Management(const VolumeImageRequest& r, bool create = true)
{
    const auto cp = Checkpoint(Read(r.image)); VolumeManagementRequest m;
    m.image = r.image; m.journal_directory = r.journal_directory; m.container_uuid = cp.container.superblock.uuid_hex;
    m.checkpoint_xid = cp.container.superblock.xid;
    for (const auto& v : cp.volumes) m.sibling_wals[v.superblock.object_id] = r.journal_directory / (std::to_string(v.superblock.object_id) + ".wal");
    m.operation = create ? VolumeManagementOperation::Create : VolumeManagementOperation::Delete;
    m.volume_oid = create ? cp.container.superblock.next_oid : cp.volumes.front().superblock.object_id;
    m.volume_uuid = create ? "7c394455667748899abbccddeeff0066" : cp.volumes.front().superblock.uuid_hex;
    if (create) m.name_utf8 = "Cross Family"; return m;
}
VolumeKeeperAdmission Inspect(const VolumeImageRequest& r) { return InspectVolumeKeeperImage(r.image, 0, r.journal_directory); }
void DeniedManagement(const VolumeImageRequest& r, const std::string& state)
{
    const auto before = Read(r.image); const auto inspection = Inspect(r);
    Check(!inspection.admitted && inspection.error.starts_with("VolumeKeeperAdmissionBlocked:vif1:" + state), "bootstrap veto: " + inspection.error);
    const auto m = Management(r); auto result = PrepareVolumeCreate(m);
    Check(result.outcome == VolumeManagementOutcome::Refused && result.error == inspection.error, "create preflight veto: " + result.error);
    result = PrepareVolumeDelete(Management(r, false));
    Check(result.outcome == VolumeManagementOutcome::Refused && result.error == inspection.error, "delete preflight veto: " + result.error);
    Check(Read(r.image) == before, "foreign debt preserves every source byte");
}
void DeniedImage(const VolumeImageRequest& r, const std::string& state)
{
    const auto before = Read(r.image); const auto inspection = Inspect(r);
    Check(!inspection.admitted && inspection.error.starts_with("VolumeKeeperAdmissionBlocked:vmt1:" + state), "bootstrap management veto: " + inspection.error);
    auto result = PrepareVolumeResize(r);
    Check(result.outcome == VolumeImageOutcome::Refused && result.error == inspection.error, "resize preflight veto: " + result.error);
    auto format = Request(r.journal_directory, VolumeImageOperation::Format, before);
    result = PrepareVolumeFormat(format);
    Check(result.outcome == VolumeImageOutcome::Refused && result.error == inspection.error, "format preflight veto: " + result.error);
    Check(Read(r.image) == before, "management debt preserves every source byte");
}
void PreparedAndCancelled()
{
    auto r = Setup("image-prepared"); const auto original = Read(r.image);
    const auto clean = Inspect(r); Check(clean.admitted && clean.journals.size() == 2, "no journal admits bootstrap");
    const auto p = PrepareVolumeResize(r); Check(p.outcome == VolumeImageOutcome::Prepared, p.error);
    const auto journal = Read(p.journal); DeniedManagement(r, "prepared"); Check(Read(p.journal) == journal, "foreign prepared evidence unchanged");
    Check(CancelVolumeResize(r, p.token).outcome == VolumeImageOutcome::Cancelled, "own cancel available");
    const auto cancelled = Inspect(r); Check(cancelled.admitted, "fully validated cancelled VIF admits: " + cancelled.error);
    auto m = Management(r); const auto mp = PrepareVolumeCreate(m); Check(mp.outcome == VolumeManagementOutcome::Prepared, mp.error);
    Check(CancelVolumeManagement(m, mp.confirmation_token).outcome == VolumeManagementOutcome::Cancelled, "management plans across cancelled VIF");
    Check(Inspect(r).admitted && Read(r.image) == original, "both exact terminal cancellations admit and preserve image");

    r = Setup("management-prepared"); m = Management(r); const auto q = PrepareVolumeCreate(m);
    Check(q.outcome == VolumeManagementOutcome::Prepared, q.error); const auto evidence = Read(q.journal_path);
    DeniedImage(r, "prepared"); Check(Read(q.journal_path) == evidence, "foreign VMT evidence unchanged");
    Check(CancelVolumeManagement(m, q.confirmation_token).outcome == VolumeManagementOutcome::Cancelled, "own management cancel");
    const auto next = PrepareVolumeResize(r); Check(next.outcome == VolumeImageOutcome::Prepared, next.error);
    Check(CancelVolumeResize(r, next.token).outcome == VolumeImageOutcome::Cancelled && Inspect(r).admitted, "cancelled VMT permits real image plan");
    Pass("reciprocal prepared admission and fully terminal cancellation");
}
void LongManagementJournalPaths()
{
    struct RestoreRoot {
        std::filesystem::path saved;
        ~RestoreRoot() { root = saved; }
    } restore{root};
    root /= "long-management-paths";
    if (root.wstring().size() < 188) root /= std::string(187 - root.wstring().size(), 'p');
    Check(root.wstring().size() < 230, "test root leaves room for the ordinary image path");
    std::filesystem::create_directories(root);
    const auto r = Setup("archive-cycle");
    const auto original = Read(r.image);
    const auto m = Management(r);
    const auto first = PrepareVolumeCreate(m);
    Check(first.outcome == VolumeManagementOutcome::Prepared, first.error);
    Check(first.journal_path.wstring().size() > 260, "active management journal exceeds MAX_PATH");
    Check(CancelVolumeManagement(m, first.confirmation_token).outcome == VolumeManagementOutcome::Cancelled,
        "long-path management cancellation");
    const auto terminal = Read(first.journal_path);
    const auto second = PrepareVolumeCreate(m);
    Check(second.outcome == VolumeManagementOutcome::Prepared, second.error);
    auto archive = first.journal_path;
    archive += "." + first.confirmation_token + ".completed";
    Check(Read(archive) == terminal, "long active journal archives its exact cancelled original");
    Check(CancelVolumeManagement(m, second.confirmation_token).outcome == VolumeManagementOutcome::Cancelled,
        "long-path second cancellation");
    const auto admitted = Inspect(r);
    Check(admitted.admitted && admitted.journals.size() == 3, "long-path canonical and archive admission: " + admitted.error);
    Check(Read(r.image) == original, "long-path planning preserves all source bytes");
    for (const auto& [oid, wal] : r.sibling_wals) Check(Read(wal).empty(), "long-path sibling WAL remains unchanged");
    Pass("long active management journals preserve source and terminal archive ownership");
}
void RecoverUnacceptedImage()
{
    for (const auto op : {VolumeImageOperation::Grow, VolumeImageOperation::Shrink,
                         VolumeImageOperation::Format, VolumeImageOperation::Erase}) {
        auto r = Setup("unaccepted-recovery-" + std::to_string(static_cast<unsigned>(op)), op);
        const bool format = op == VolumeImageOperation::Format || op == VolumeImageOperation::Erase;
        if (op == VolumeImageOperation::Erase) r.new_container_uuid = "7b294455667748899abbccddeeff0022";
        const auto original = Read(r.image);
        const auto p = format ? PrepareVolumeFormat(r) : PrepareVolumeResize(r);
        Check(p.outcome == VolumeImageOutcome::Prepared, p.error);
        const auto prepared = Read(p.journal);
        const auto recover = [&](const VolumeImageRequest& request) {
            return format ? RecoverVolumeFormat(request) : RecoverVolumeResize(request);
        };
        auto wrong = r; ++wrong.checkpoint_xid;
        const auto rejected = recover(wrong);
        Check(rejected.outcome != VolumeImageOutcome::Cancelled && Read(r.image) == original &&
              Read(p.journal) == prepared, "different original request cannot cancel prepared evidence");
        const auto wal_path = r.sibling_wals.begin()->second;
        const auto wal = Read(wal_path); auto damaged_wal = wal; damaged_wal.push_back(std::byte{0x7f});
        Save(wal_path, damaged_wal);
        const auto debt = recover(r);
        Check(debt.outcome != VolumeImageOutcome::Cancelled && Read(r.image) == original &&
              Read(p.journal) == prepared && Read(wal_path) == damaged_wal,
              "unaccepted recovery retains malformed original WAL evidence");
        Save(wal_path, wal);
        const auto missing_wal = [&](const Bytes& expected_journal) {
            auto preserved = wal_path; preserved += L".preserved";
            const auto extended = [](std::filesystem::path path) {
                path.make_preferred(); return L"\\\\?\\" + path.wstring();
            };
            Check(MoveFileExW(extended(wal_path).c_str(), extended(preserved).c_str(), MOVEFILE_WRITE_THROUGH) != FALSE,
                  "retain missing original WAL witness");
            const auto refused = recover(r);
            Check(refused.outcome != VolumeImageOutcome::Cancelled && !std::filesystem::exists(wal_path) &&
                  Read(preserved) == wal && Read(r.image) == original && Read(p.journal) == expected_journal,
                  "missing original WAL refuses without manufacturing replacement evidence");
            Check(MoveFileExW(extended(preserved).c_str(), extended(wal_path).c_str(), MOVEFILE_WRITE_THROUGH) != FALSE,
                  "restore test-owned original WAL identity");
        };
        missing_wal(prepared);
        const auto done = recover(r);
        Check(done.outcome == VolumeImageOutcome::Cancelled, "lost prepare reply cancels exact original: " + done.error);
        Check(done.pre_xid == p.pre_xid && done.post_xid == p.post_xid && done.source_identity == p.source_identity,
              "cancelled recovery returns complete original binding");
        const auto terminal = Read(p.journal);
        missing_wal(terminal);
        Check(Read(r.image) == original && Read(wal_path) == wal && Inspect(r).admitted,
              "prepared recovery changes only cancellation receipt");
        const auto again = recover(r);
        Check(again.outcome == VolumeImageOutcome::Cancelled && again.pre_xid == p.pre_xid &&
              Read(r.image) == original && Read(p.journal) == terminal && Read(wal_path) == wal,
              "already-cancelled recovery is byte-identical and bound");
    }
    Pass("lost prepare reply and cancelled image recovery preserve exact original request/source/WAL census");
}
void AcceptedImage()
{
    for (const auto& [op, stage] : std::vector<std::pair<VolumeImageOperation, std::string>>{
        {VolumeImageOperation::Grow, "after-image-accept"}, {VolumeImageOperation::Grow, "after-image-grow"},
        {VolumeImageOperation::Grow, "after-image-anchor"}, {VolumeImageOperation::Format, "after-image-accept"},
        {VolumeImageOperation::Format, "after-image-anchor"}}) {
        auto r = Setup(std::to_string(static_cast<unsigned>(op)) + "-" + stage, op);
        const auto p = op == VolumeImageOperation::Grow ? PrepareVolumeResize(r) : PrepareVolumeFormat(r);
        Check(p.outcome == VolumeImageOutcome::Prepared, p.error); const auto locator = Inspect(r).locator;
        const auto hook = [&](std::string_view at) { return at != stage; };
        const auto interrupted = op == VolumeImageOperation::Grow ? ApplyVolumeResize(r, p.token, hook) : ApplyVolumeFormat(r, p.token, hook);
        Check(interrupted.outcome == VolumeImageOutcome::RecoveryRequired, interrupted.error);
        const auto journal = Read(p.journal); DeniedManagement(r, stage == "after-image-anchor" ? "anchor-durable" : "accepted");
        Check(Read(p.journal) == journal && Inspect(r).locator == locator, "changed length or UUID cannot hide locator");
        if (op == VolumeImageOperation::Grow && stage != "after-image-accept") Check(Read(r.image).size() == r.target_bytes, "actual length changed before admission");
        const auto done = op == VolumeImageOperation::Grow ? RecoverVolumeResize(r) : RecoverVolumeFormat(r);
        Check(done.outcome == VolumeImageOutcome::Committed, done.error);
        const auto terminal = Inspect(r); Check(terminal.admitted && terminal.locator == locator &&
            terminal.journals.back().state == VolumeKeeperJournalState::Completed, "exact complete chain admits same file despite new capacity/UUID: " + terminal.error);
    }
    Pass("accepted grow/format debt blocks create/delete before and after source changes");
}
void AcceptedManagement()
{
    for (auto op : {VolumeImageOperation::Grow, VolumeImageOperation::Shrink}) {
    auto r = Setup(op == VolumeImageOperation::Grow ? "management-accepted" : "management-accepted-shrink", op);
    const auto original = Read(r.image); const auto original_cp = Checkpoint(original);
    auto m = Management(r); const auto p = PrepareVolumeCreate(m);
    Check(p.outcome == VolumeManagementOutcome::Prepared, p.error);
    const auto interrupted = ApplyVolumeManagement(m, p.confirmation_token, [](auto stage) { return stage != "after-volume-management-accept"; });
    Check(interrupted.outcome == VolumeManagementOutcome::RecoveryRequired, interrupted.error);
    const auto journal = Read(p.journal_path); DeniedImage(r, "accepted"); Check(Read(p.journal_path) == journal, "accepted VMT unchanged");
    const auto done = RecoverVolumeManagement(m); Check(done.outcome == VolumeManagementOutcome::Committed, done.error);
    Check(Inspect(r).admitted, "validated complete VMT receipt chain admits");
    const auto completed = Read(r.image);
    const auto before = Checkpoint(completed); catalog::VectorRandomAccessSource source(completed); std::string error;
    std::vector<AppleRecoveryCheckpointView> retained;
    Check(LoadAppleSnapshotRecoveryCheckpoints(source, before, {original_cp.container.superblock.xid}, retained, error) && !retained.empty(), error);
    Check(before.spaceman.internal_pool.active_bitmaps.front().rotation_index !=
        retained.front().checkpoint.spaceman.internal_pool.active_bitmaps.front().rotation_index, "distinct current and retained bitmap rotations");
    auto next = Request(r.journal_directory, op, completed); const auto rp = PrepareVolumeResize(next);
    Check(rp.outcome == VolumeImageOutcome::Prepared, "resize after production management recovery: " + rp.error);
    const auto interrupted_resize = ApplyVolumeResize(next, rp.token, [](auto stage) { return stage != "after-image-anchor"; });
    Check(interrupted_resize.outcome == VolumeImageOutcome::RecoveryRequired, interrupted_resize.error);
    const auto resized = RecoverVolumeResize(next); Check(resized.outcome == VolumeImageOutcome::Committed, resized.error);
    const auto post = Read(r.image); const auto after = Checkpoint(post); volume_image::Verify(post, after); ++checks;
    Check(post.size() == next.target_bytes && after.volumes.size() == before.volumes.size() && after.volumes.size() == 3, "actual new capacity and every sibling");
    for (std::size_t i = 0; i < before.volumes.size(); ++i) {
        const auto block = before.volumes[i].superblock_object.physical_block;
        Check(after.volumes[i].superblock_object.physical_block == block && std::equal(completed.begin() + block * 4096,
            completed.begin() + (block + 1) * 4096, post.begin() + block * 4096), "sibling APSB bytes preserved");
    }
    for (const auto block : {240u, 248u}) Check(std::equal(post.begin() + block * 4096, post.begin() + (block + 1) * 4096,
        original.begin() + block * 4096), "existing sibling payload preserved");
    for (const auto& old : retained) {
        for (const auto block : old.metadata_blocks) if (block) Check(block < post.size() / 4096 &&
            std::equal(completed.begin() + block * 4096, completed.begin() + (block + 1) * 4096, post.begin() + block * 4096), "proved historical metadata remains byte-identical");
        for (const auto& extent : old.payload_extents) Check(extent.physical_block + extent.block_count <= post.size() / 4096 &&
            std::equal(completed.begin() + extent.physical_block * 4096, completed.begin() + (extent.physical_block + extent.block_count) * 4096,
                post.begin() + extent.physical_block * 4096), "proved historical payload remains byte-identical");
    }
    auto repeat = Request(r.journal_directory, VolumeImageOperation::Grow, post);
    const auto repeated = PrepareVolumeResize(repeat);
    Check(repeated.outcome == VolumeImageOutcome::Prepared && Read(r.image) == post,
        "held clean census permits repeat resize after geometry change: " + repeated.error);
    Check(repeated.pre_xid == after.container.superblock.xid && repeated.post_xid > repeated.pre_xid,
        "repeat plan binds the current checkpoint and next publication");
    const auto cancelled = CancelVolumeResize(repeat, repeated.token);
    Check(cancelled.outcome == VolumeImageOutcome::Cancelled && Read(r.image) == post && Inspect(repeat).admitted,
        "repeat cancellation settles its frame without altering the image: " + cancelled.error);
    if (op == VolumeImageOperation::Grow) {
        auto bad = completed; const auto& old = retained.front().checkpoint; const auto& chunk = old.spaceman.chunks.front();
        Check(chunk.bitmap_block != before.spaceman.chunks.front().bitmap_block, "retained allocation map independent of current map");
        bad[chunk.bitmap_block * 4096 + 240 / 8] &= std::byte(~(1u << (240 % 8)) & 255u);
        const auto patch = [&](std::uint64_t block, std::size_t at, unsigned width) {
            Bytes bytes(bad.begin() + block * 4096, bad.begin() + (block + 1) * 4096);
            const auto n = width == 4 ? catalog::ReadU32LE(bytes, at).value() : catalog::ReadU64LE(bytes, at).value();
            volume_image::Put(bytes, at, n + 1, width); testfixture::FletcherForBlock(bytes, 4096);
            std::copy(bytes.begin(), bytes.end(), bad.begin() + block * 4096);
        };
        patch(old.spaceman.devices[0].cibs.front().object.physical_block, 0x3c, 4); patch(old.spaceman.object.physical_block, 0x48, 8);
        auto damaged = Setup("retained-owner-missing"); damaged = Request(damaged.journal_directory, VolumeImageOperation::Grow, bad); Save(damaged.image, bad);
        (void)volume_image::Admit(bad, damaged); ++checks;
        catalog::VectorRandomAccessSource damaged_source(bad);
        std::vector<AppleRecoveryCheckpointView> required_history;
        error.clear();
        const bool loaded = LoadAppleSnapshotRecoveryCheckpoints(damaged_source, before,
            {original_cp.container.superblock.xid}, required_history, error);
        Check(!loaded &&
            error == "AppleSnapshotRetirementOwnershipUnproven" && Read(damaged.image) == bad,
            "explicit required recovery pin refuses payload ownership loss despite valid current checkpoint: " + error);
    }
    }
    Pass("production create/recover then grow/shrink preserves sibling payload and proved history; ownership loss refuses");
}
void Rehash(Bytes& frame)
{
    const auto count = catalog::ReadU64LE(frame, 8).value(); BCRYPT_ALG_HANDLE algorithm{};
    Check(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0, "test hash provider");
    const auto hash = [&](std::span<const std::byte> bytes) {
        std::array<std::byte, 32> digest{};
        Check(BCryptHash(algorithm, nullptr, 0, reinterpret_cast<PUCHAR>(const_cast<std::byte*>(bytes.data())), static_cast<ULONG>(bytes.size()),
            reinterpret_cast<PUCHAR>(digest.data()), 32) >= 0, "test hash"); return digest;
    };
    const auto digest = hash(std::span<const std::byte>(frame).subspan(48, count)); std::copy(digest.begin(), digest.end(), frame.begin() + 16);
    for (std::size_t at = 48 + count; frame.size() - at >= 40; at += 40) {
        Bytes data(digest.begin(), digest.end()); data.insert(data.end(), frame.begin() + at, frame.begin() + at + 8);
        const auto receipt = hash(data); std::copy(receipt.begin(), receipt.end(), frame.begin() + at + 8);
    }
    BCryptCloseAlgorithmProvider(algorithm, 0);
}
void OriginalOmapSnapshotCounts()
{
    for (const bool image : {false, true}) for (unsigned target = 0; target < 3; ++target) {
        auto r = Setup(std::string("omap-count-") + (image ? "vif-" : "vmt-") + std::to_string(target));
        const auto original = Read(r.image); const auto cp = Checkpoint(original);
        std::filesystem::path path; std::string identity;
        if (image) {
            const auto p = PrepareVolumeResize(r); Check(p.outcome == VolumeImageOutcome::Prepared, p.error);
            path = p.journal; identity = p.source_identity;
            Check(CancelVolumeResize(r, p.token).outcome == VolumeImageOutcome::Cancelled, "terminal OMAP-count VIF control");
        } else {
            const auto m = Management(r, false); const auto p = PrepareVolumeDelete(m);
            Check(p.outcome == VolumeManagementOutcome::Prepared, p.error); path = p.journal_path; identity = p.source_identity;
            Check(CancelVolumeManagement(m, p.confirmation_token).outcome == VolumeManagementOutcome::Cancelled, "terminal OMAP-count VMT control");
        }
        Check(Inspect(r).admitted, "zero-count typed OMAP control admits");
        const auto block = target == 0 ? cp.container_object_map.object.physical_block : cp.volumes[target - 1].object_map.object.physical_block;
        auto witness = original; Bytes omap(witness.begin() + block * 4096, witness.begin() + (block + 1) * 4096);
        Check((catalog::ReadU32LE(omap, 0x18).value() & catalog::kObjectTypeMask) == catalog::kObjectTypeOmap &&
            catalog::ReadU32LE(omap, 0x24).value() == 0 && catalog::ReadU64LE(omap, 0x38).value() == 0, "actual typed OMAP with zero snapshot fields");
        testfixture::PutU32LE(omap, 0x24, 1); testfixture::FletcherForBlock(omap, 4096);
        std::copy(omap.begin(), omap.end(), witness.begin() + block * 4096);
        const auto changed = Checkpoint(witness); catalog::VectorRandomAccessSource source(witness); std::string error;
        AppleSnapshotRetentionView snapshots; std::vector<std::uint64_t> metadata; std::vector<ApplePhysicalExtentRecord> payload;
        Check(LoadAppleSnapshotRetention(source, changed, snapshots, error) && snapshots.identities.empty(), "count-only original has empty public inventory: " + error);
        const bool owners = LoadAppleSnapshotCheckpointOwners(source, changed, metadata, payload, error);
        Check(!owners && error == (target == 0 ? "SnapshotOmapSnapshotRootMissing" : "AppleSnapshotRetirementOmapHistoryUnproven"),
            "count-only typed OMAP retains exact ownership refusal: " + error);
        Check(std::none_of(changed.spaceman.chunks.begin(), changed.spaceman.chunks.end(), [&](const auto& c) { return c.bitmap_block == block; }) &&
            std::none_of(changed.spaceman.internal_pool.active_bitmaps.begin(), changed.spaceman.internal_pool.active_bitmaps.end(),
                [&](const auto& b) { return b.physical_block == block; }), "typed OMAP is not a raw allocator bitmap");
        auto frame = Read(path); const auto body = catalog::ReadU64LE(frame, 8).value();
        std::copy(witness.begin(), witness.end(), frame.begin() + 48 + body - witness.size()); Rehash(frame); Save(path, frame);
        std::string decoded_error;
        try { (void)DecodeVolumeKeeperHistoryBinding(frame, path, r.journal_directory, identity); }
        catch (const std::exception& ex) { decoded_error = ex.what(); }
        Check(decoded_error == "KeeperOriginalSnapshotHistoryAuthorityUnproven", "nonzero actual OMAP count original refuses: " + decoded_error);
        const auto expected = std::string("VolumeKeeperAdmissionBlocked:") + (image ? "vif1:" : "vmt1:") + "invalid:KeeperOriginalSnapshotHistoryAuthorityUnproven";
        const auto admission = Inspect(r); Check(!admission.admitted && admission.error == expected, "typed OMAP count admission refusal: " + admission.error);
        const auto refused = image ? PrepareVolumeCreate(Management(r)).error : PrepareVolumeResize(r).error;
        Check(refused == expected && Read(r.image) == original && Read(path) == frame, "typed OMAP count foreign preflight refuses with source/frame intact: " + refused);
        std::cout << "TYPED OMAP COUNT REFUSED family=" << (image ? "vif1" : "vmt1") << " target=" << target << " ownerError=" << error << std::endl;
    }
    Pass("actual container selected and sibling OMAP snapshot counts refuse in both original-frame families");
}
void OriginalSnapshotFrames()
{
    for (const bool image : {false, true}) for (const bool completed : {false, true}) for (const bool archive : {false, true})
        for (const bool hidden : {false, true}) {
        auto r = Setup(std::string("original-snapshot-") + (image ? "vif-" : "vmt-") +
            (completed ? "completed-" : "cancelled-") + (archive ? "archive-" : "canonical-") + (hidden ? "opaque" : "public"));
        const auto original = Read(r.image);
        std::filesystem::path path; std::string token, identity;
        if (image) {
            const auto p = PrepareVolumeResize(r); Check(p.outcome == VolumeImageOutcome::Prepared, p.error);
            path = p.journal; token = p.token; identity = p.source_identity;
            Check(CancelVolumeResize(r, token).outcome == VolumeImageOutcome::Cancelled, "terminal VIF control");
        } else {
            const auto m = Management(r, false); const auto p = PrepareVolumeDelete(m);
            Check(p.outcome == VolumeManagementOutcome::Prepared, p.error);
            path = p.journal_path; token = p.confirmation_token; identity = p.source_identity;
            Check(CancelVolumeManagement(m, token).outcome == VolumeManagementOutcome::Cancelled, "terminal VMT control");
        }
        Check(Inspect(r).admitted, "snapshot-free terminal original admits");
        auto snapshot_image = original; const auto cp = Checkpoint(original); catalog::VectorRandomAccessSource source(original);
        AppleSnapshotCreateRequest request; request.volume_object_id = 201; request.name_utf8 = "original-only";
        request.creation_time_ns = 1700000000000000000ull; AppleSnapshotCreatePlan plan; std::string error;
        Check(PlanAppleSnapshotCreate(source, cp, request, plan, error), "real snapshot original: " + error);
        const auto put = [&](const auto& w) { std::copy(w.bytes.begin(), w.bytes.end(), snapshot_image.begin() + w.physical_block * 4096); };
        for (const auto& w : plan.commit.publication.before_superblock_writes) put(w);
        put(plan.commit.publication.superblock_write);
        auto snapshot_cp = Checkpoint(snapshot_image); catalog::VectorRandomAccessSource historical(snapshot_image);
        AppleSnapshotRetentionView snapshots;
        Check(LoadAppleSnapshotRetention(historical, snapshot_cp, snapshots, error) && snapshots.identities.size() == 1 &&
            !snapshots.metadata_blocks.empty() && !snapshots.payload_extents.empty(), "nonempty original snapshot graph: " + error);
        if (hidden) {
            const auto snapshot_map = snapshot_cp.volumes.front().object_map.object.physical_block;
            const Bytes old_map(snapshot_image.begin() + snapshot_map * 4096, snapshot_image.begin() + (snapshot_map + 1) * 4096);
            AppleSnapshotDeleteRequest deletion; deletion.expected = snapshots.identities.front(); deletion.modification_time_ns = 1700000000000000100ull;
            AppleSnapshotDeletePlan deleted;
            const auto planned = PlanAppleSnapshotDelete(historical, snapshot_cp, deletion, deleted, error);
            Check(planned, "production snapshot removal: " + error);
            for (const auto& w : deleted.commit.publication.before_superblock_writes) put(w);
            put(deleted.commit.publication.superblock_write); snapshot_cp = Checkpoint(snapshot_image);
            catalog::VectorRandomAccessSource removed(snapshot_image); AppleSnapshotRetentionView logical;
            Check(LoadAppleSnapshotRetention(removed, snapshot_cp, logical, error) && logical.identities.empty(), "original public snapshot census is empty after deletion: " + error);
            std::vector<std::uint64_t> metadata; std::vector<ApplePhysicalExtentRecord> payload;
            Check(LoadAppleSnapshotCheckpointOwners(removed, snapshot_cp, metadata, payload, error), "complete original hidden-owner graph: " + error);
            // Model an opaque legacy original: a stale snapshot OMAP boundary
            // attached to a real snapshot-deleted checkpoint with empty inventory.
            const auto map_block = snapshot_cp.volumes.front().object_map.object.physical_block;
            Bytes map(snapshot_image.begin() + map_block * 4096, snapshot_image.begin() + (map_block + 1) * 4096);
            Check(catalog::ReadU64LE(old_map, 0x38).value_or(0) != 0, "real old snapshot OMAP root exists");
            for (const auto [offset, width] : {std::pair{0x24u, 4u}, {0x28u, 4u}, {0x38u, 8u}, {0x40u, 8u}})
                std::copy_n(old_map.begin() + offset, width, map.begin() + offset);
            testfixture::FletcherForBlock(map, 4096); std::copy(map.begin(), map.end(), snapshot_image.begin() + map_block * 4096);
            snapshot_cp = Checkpoint(snapshot_image); catalog::VectorRandomAccessSource opaque(snapshot_image);
            const auto loaded = LoadAppleSnapshotRetention(opaque, snapshot_cp, logical, error);
            Check(!loaded, "opaque original snapshot OMAP cannot establish snapshot absence");
        }
        AppleSnapshotRetentionView current;
        Check(LoadAppleSnapshotRetention(source, cp, current, error) && current.identities.empty(), "current source remains snapshot-free");
        auto frame = Read(path); const auto body = catalog::ReadU64LE(frame, 8).value();
        const auto original_at = 48 + body - original.size();
        std::size_t at = 56;
        const auto skip_text = [&]() { const auto n = catalog::ReadU64LE(frame, at).value(); at += 8 + n; };
        skip_text(); skip_text(); if (!image) at += 8; skip_text(); skip_text(); at += 8;
        testfixture::PutU64LE(frame, at, snapshot_cp.container.superblock.xid);
        std::copy(snapshot_image.begin(), snapshot_image.end(), frame.begin() + original_at);
        frame.resize(48 + body);
        for (const auto state : completed ? (image ? std::vector{1u, 2u, 3u} : std::vector{1u, 2u}) :
            (image ? std::vector{4u} : std::vector{3u})) {
            const auto receipt = frame.size(); frame.resize(receipt + 40); testfixture::PutU64LE(frame, receipt, state);
        }
        Rehash(frame);
        if (archive) path += "." + token + ".completed";
        Save(path, frame);
        std::string decoded_error;
        try { (void)DecodeVolumeKeeperHistoryBinding(frame, path, r.journal_directory, identity); }
        catch (const std::exception& ex) { decoded_error = ex.what(); }
        Check(decoded_error == "KeeperOriginalSnapshotHistoryAuthorityUnproven", "decoded snapshot original must refuse: " + decoded_error);
        const auto inspection = Inspect(r);
        const auto expected = std::string("VolumeKeeperAdmissionBlocked:") + (image ? "vif1:" : "vmt1:") +
            "invalid:KeeperOriginalSnapshotHistoryAuthorityUnproven";
        Check(!inspection.admitted && inspection.error == expected, "original snapshot admission refusal: " + inspection.error);
        const auto refused = image ? PrepareVolumeCreate(Management(r)).error : PrepareVolumeResize(r).error;
        Check(refused == expected && Read(r.image) == original && Read(path) == frame,
            "foreign family refuses opaque original snapshot history and preserves source/frame bytes: " + refused);
        std::cout << "ORIGINAL SNAPSHOT REFUSED family=" << (image ? "vif1" : "vmt1") << " completed=" << completed
            << " archive=" << archive << " opaque=" << hidden << std::endl;
    }
    Pass("canonical/archive completed/cancelled originals require snapshot absence even with snapshot-free current source");
}
void MalformedFrames(bool image)
{
    for (unsigned variant = 0; variant < 8; ++variant) {
        auto r = Setup(std::string(image ? "vif-malformed-" : "vmt-malformed-") + std::to_string(variant));
        std::filesystem::path path; std::string identity;
        if (image) {
            const auto p = PrepareVolumeResize(r); Check(p.outcome == VolumeImageOutcome::Prepared, p.error); path = p.journal; identity = p.source_identity;
            Check(CancelVolumeResize(r, p.token).outcome == VolumeImageOutcome::Cancelled, "make terminal VIF");
        } else {
            const auto m = Management(r); const auto p = PrepareVolumeCreate(m); Check(p.outcome == VolumeManagementOutcome::Prepared, p.error);
            path = p.journal_path; identity = p.source_identity;
            Check(CancelVolumeManagement(m, p.confirmation_token).outcome == VolumeManagementOutcome::Cancelled, "make terminal VMT");
        }
        Check(Inspect(r).admitted, "valid terminal control"); auto bytes = Read(path);
        const auto body = catalog::ReadU64LE(bytes, 8).value();
        if (variant == 0) bytes.resize(bytes.size() - 1);
        if (variant == 1) bytes[100] ^= std::byte{1};
        if (variant == 2) { testfixture::PutU64LE(bytes, 48, 99); Rehash(bytes); }
        if (variant == 3) {
            const auto pattern = std::as_bytes(std::span(identity.data(), identity.size()));
            const auto found = std::search(bytes.begin() + 48, bytes.begin() + 48 + body, pattern.begin(), pattern.end());
            Check(found != bytes.begin() + 48 + body, "stored identity located"); found[16] = found[16] == std::byte{'a'} ? std::byte{'b'} : std::byte{'a'}; Rehash(bytes);
        }
        if (variant == 4) { testfixture::PutU64LE(bytes, 48 + body, image ? 3 : 2); Rehash(bytes); }
        if (variant == 5) bytes.push_back(std::byte{0});
        if (variant == 6) { testfixture::PutU64LE(bytes, 48 + body - Read(r.image).size() - 8, Read(r.image).size() + 1); Rehash(bytes); }
        if (variant == 7) bytes.resize(20);
        Save(path, bytes);
        if (image) DeniedManagement(r, "invalid"); else DeniedImage(r, "invalid");
        Check(Read(path) == bytes, "malformed foreign evidence never deleted or repaired by admission");
    }
    Pass(image ? "VIF malformed body source binding terminal receipts and torn evidence" : "VMT malformed body source binding terminal receipts and torn evidence");
}
void ApplyPreflight()
{
    for (auto op : {VolumeImageOperation::Grow, VolumeImageOperation::Format}) for (bool accepted : {false, true}) {
        auto r = Setup("apply-" + std::to_string(static_cast<unsigned>(op)) + (accepted ? "-accepted" : "-prepared"), op);
        const auto p = op == VolumeImageOperation::Grow ? PrepareVolumeResize(r) : PrepareVolumeFormat(r);
        Check(p.outcome == VolumeImageOutcome::Prepared, p.error); auto foreign = Read(p.journal);
        const auto cancelled = op == VolumeImageOperation::Grow ? CancelVolumeResize(r, p.token) : CancelVolumeFormat(r, p.token);
        Check(cancelled.outcome == VolumeImageOutcome::Cancelled, "normal terminal VIF before overlap fixture");
        const auto m = Management(r); const auto mp = PrepareVolumeCreate(m); Check(mp.outcome == VolumeManagementOutcome::Prepared, mp.error);
        // Model evidence left by older keepers that lacked reciprocal admission.
        // No production bypass and no journal deletion are used.
        if (accepted) {
            const auto at = foreign.size(); foreign.resize(at + 40); testfixture::PutU64LE(foreign, at, 1); Rehash(foreign);
        }
        Save(p.journal, foreign); const auto source = Read(r.image), own = Read(mp.journal_path);
        const auto vm = ApplyVolumeManagement(m, mp.confirmation_token);
        Check(vm.outcome == VolumeManagementOutcome::Refused && vm.error.starts_with("VolumeKeeperAdmissionBlocked:vif1:"), "apply rechecks foreign evidence before acceptance");
        const auto vi = op == VolumeImageOperation::Grow ? ApplyVolumeResize(r, p.token) : ApplyVolumeFormat(r, p.token);
        Check(vi.outcome == VolumeImageOutcome::Refused && vi.error.starts_with("VolumeKeeperAdmissionBlocked:vmt1:prepared"), "reciprocal apply preflight");
        Check(Read(r.image) == source && Read(mp.journal_path) == own && Read(p.journal) == foreign, "overlapping evidence and source stay untouched");
    }
    auto r = Setup("expired-prepared"); const auto p = PrepareVolumeResize(r); Check(p.outcome == VolumeImageOutcome::Prepared, p.error);
    auto frame = Read(p.journal); const auto body = catalog::ReadU64LE(frame, 8).value();
    testfixture::PutU64LE(frame, 48 + body - Read(r.image).size() - 16, 1); Rehash(frame); Save(p.journal, frame);
    DeniedManagement(r, "prepared"); Check(Read(p.journal) == frame, "expired unaccepted evidence remains blocking");
    Pass("apply preflight preserves overlapping pending families and expired prepared evidence");
}
void ArchivedFrames(bool image)
{
    for (unsigned variant = 0; variant < 6; ++variant) {
        auto label = std::string(image ? "vif-archive-" : "vmt-archive-") + std::to_string(variant);
        if (!variant && root.wstring().size() + label.size() + 1 < 160) label.resize(159 - root.wstring().size(), 'x');
        auto r = Setup(label);
        std::filesystem::path active; std::string token; Bytes prepared, terminal;
        if (image) {
            const auto p = PrepareVolumeResize(r); Check(p.outcome == VolumeImageOutcome::Prepared, p.error);
            active = p.journal; token = p.token; prepared = Read(active);
            Check(CancelVolumeResize(r, token).outcome == VolumeImageOutcome::Cancelled, "first VIF terminal"); terminal = Read(active);
            const auto q = PrepareVolumeResize(r); Check(q.outcome == VolumeImageOutcome::Prepared, q.error);
            Check(CancelVolumeResize(r, q.token).outcome == VolumeImageOutcome::Cancelled, "second VIF terminal");
        } else {
            const auto m = Management(r); const auto p = PrepareVolumeCreate(m); Check(p.outcome == VolumeManagementOutcome::Prepared, p.error);
            active = p.journal_path; token = p.confirmation_token; prepared = Read(active);
            Check(CancelVolumeManagement(m, token).outcome == VolumeManagementOutcome::Cancelled, "first VMT terminal"); terminal = Read(active);
            const auto q = PrepareVolumeCreate(m); Check(q.outcome == VolumeManagementOutcome::Prepared, q.error);
            Check(CancelVolumeManagement(m, q.confirmation_token).outcome == VolumeManagementOutcome::Cancelled, "second VMT terminal");
        }
        auto archive = active; archive += "." + token + ".completed";
        Check(Read(std::filesystem::path(L"\\\\?\\" + archive.wstring())) == terminal, "real keeper archived complete original frame without replacement");
        const auto admitted = Inspect(r); Check(admitted.admitted && admitted.journals.size() == 3, "all canonical and archived terminal frames inspected: " + admitted.error);
        if (!variant) {
            Check(active.wstring().size() < 260 && archive.wstring().size() > 260, "actual long archive under MAX_PATH canonical journal");
            if (image) {
                const auto m = Management(r); const auto p = PrepareVolumeCreate(m); Check(p.outcome == VolumeManagementOutcome::Prepared, p.error);
                Check(CancelVolumeManagement(m, p.confirmation_token).outcome == VolumeManagementOutcome::Cancelled, "terminal VIF archive permits actual management plan");
            } else {
                const auto p = PrepareVolumeResize(r); Check(p.outcome == VolumeImageOutcome::Prepared, p.error);
                Check(CancelVolumeResize(r, p.token).outcome == VolumeImageOutcome::Cancelled, "terminal VMT archive permits actual resize plan");
            }
            Check(Inspect(r).admitted, "both families with exact valid archive proof admit"); continue;
        }
        auto bytes = terminal; std::string state = "invalid";
        if (variant <= 2) {
            bytes = prepared; state = variant == 1 ? "prepared" : "accepted";
            if (variant == 2) { const auto at = bytes.size(); bytes.resize(at + 40); testfixture::PutU64LE(bytes, at, 1); Rehash(bytes); }
        }
        if (variant == 3) bytes.resize(bytes.size() - 1);
        if (variant == 4) { token[0] = token[0] == 'a' ? 'b' : 'a'; archive = active; archive += "." + token + ".completed"; }
        if (variant == 5) { archive = active; archive += ".torn"; }
        Save(archive, bytes); const auto current = Read(active);
        if (image) DeniedManagement(r, state); else DeniedImage(r, state);
        Check(Read(active) == current && Read(archive) == bytes, "archived debt and terminal canonical evidence remain untouched");
    }
    Pass(image ? "VIF terminal archives admit; pending torn mismatched and unknown archive evidence veto" :
        "VMT terminal archives admit; pending torn mismatched and unknown archive evidence veto");
}
void OffsetLocator()
{
    auto r = Setup("offset-locator"); const auto m = Management(r); const auto original = Read(r.image);
    const auto p = PrepareVolumeCreate(m); Check(p.outcome == VolumeManagementOutcome::Prepared, p.error);
    Check(CancelVolumeManagement(m, p.confirmation_token).outcome == VolumeManagementOutcome::Cancelled, "offset fixture initial cancellation");
    auto terminal = Read(p.journal_path);
    Bytes file(4096, std::byte{0x5a}); file.insert(file.end(), original.begin(), original.end()); Save(r.image, file);
    const auto empty = InspectVolumeKeeperImage(m.image, 4096, m.journal_directory);
    Check(empty.admitted && empty.source_identity.size() == 80, "new offset has independent locator");
    // Encode the same authoritative original at an offset for the shared inspector.
    // Production management currently refuses nonzero-offset WAL scope.
    std::size_t offset_at = 56;
    for (unsigned i = 0; i < 2; ++i) offset_at += 8 + catalog::ReadU64LE(terminal, offset_at).value();
    testfixture::PutU64LE(terminal, offset_at, 4096);
    const auto pattern = std::as_bytes(std::span(p.source_identity.data(), p.source_identity.size()));
    const auto found = std::search(terminal.begin() + 48, terminal.end(), pattern.begin(), pattern.end());
    Check(found != terminal.end(), "offset fixture stored identity located");
    for (unsigned i = 0; i < 80; ++i) found[i] = std::byte(empty.source_identity[i]);
    Rehash(terminal); auto prepared = terminal; prepared.resize(prepared.size() - 40);
    const auto path = empty.journals.front().path; Save(path, prepared);
    const auto at_store = InspectVolumeKeeperImage(m.image, 4096, m.journal_directory);
    const auto at_zero = InspectVolumeKeeperImage(m.image, 0, m.journal_directory);
    Check(!at_store.admitted && !at_zero.admitted && at_store.locator != at_zero.locator, "overlapping file intervals cannot hide another offset's evidence");
    Save(path, terminal);
    Check(InspectVolumeKeeperImage(m.image, 4096, m.journal_directory).admitted && Read(m.image) == file, "nonzero-offset terminal proof and prefix integrity");
    Pass("held source offset locator and terminal frame original-length binding");
}
struct HeldWal
{
    std::promise<bool> acquired; std::promise<void> release; std::future<void> owner;
    HeldWal(const std::filesystem::path& path, const std::string& identity)
    {
        auto signal = release.get_future().share();
        owner = std::async(std::launch::async, [this, path, identity, signal] {
            WriteAheadLog wal({path, identity}); acquired.set_value(wal.AcquireWriterLeaseOnly()); signal.wait();
        });
        if (!acquired.get_future().get()) { release.set_value(); owner.get(); throw std::runtime_error("live production WAL fixture busy"); }
    }
    ~HeldWal() { if (owner.valid()) { release.set_value(); owner.get(); } }
};
void ProductionOwners()
{
    bool all_refused = true;
    for (const auto op : {VolumeImageOperation::Grow, VolumeImageOperation::Shrink, VolumeImageOperation::Format, VolumeImageOperation::Erase}) {
        auto r = Setup("production-owner-" + std::to_string(static_cast<unsigned>(op)), op);
        if (op == VolumeImageOperation::Erase) r.new_container_uuid = "7b294455667748899abbccddeeff0022";
        const auto original = Read(r.image);
        HeldWal live(r.sibling_wals.at(201), DerivePartitionlessVolumeRecoveryIdentity(r.container_uuid, 201));
        const auto control = PrepareVolumeCreate(Management(r));
        Check(control.error == "VolumeManagementWalBusy", "management production owner control: " + control.error);
        const bool format = op == VolumeImageOperation::Format || op == VolumeImageOperation::Erase;
        const auto p = format ? PrepareVolumeFormat(r) : PrepareVolumeResize(r);
        VolumeImageResult applied;
        if (p.outcome == VolumeImageOutcome::Prepared) applied = format ? ApplyVolumeFormat(r, p.token) : ApplyVolumeResize(r, p.token);
        const bool unchanged = Read(r.image) == original;
        const bool refused = p.outcome == VolumeImageOutcome::Refused && p.error == "VolumeImageWalBusy" && unchanged;
        all_refused &= refused;
        std::cout << "PRODUCTION_OWNER op=" << static_cast<unsigned>(op) << " prepared=" << static_cast<unsigned>(p.outcome)
            << ':' << p.error << " applied=" << static_cast<unsigned>(applied.outcome) << " sourceUnchanged=" << unchanged << std::endl;
    }
    Check(all_refused, "all four production owners must veto before planning/publication with source unchanged");
    Pass("four live production WAL identities fence grow shrink format erase");
}
void WriteProductionWal(const std::filesystem::path& path, const std::string& identity, bool accepted, std::uint64_t xid)
{
    TransactionManager tx(L"Strict"); tx.SetJournalPath(path.wstring()); tx.SetVolumeIdentity(std::wstring(identity.begin(), identity.end()));
    TransactionManager::MutationIntent mutation; mutation.kind = TransactionManager::MutationKind::CreateFile;
    mutation.path = L"\\aborted"; mutation.object_id = 900; mutation.generation = xid + 1;
    Check(tx.Begin() && tx.RecordMutation(mutation), "production transaction recorded");
    Check(accepted ? tx.Accept(xid) : (tx.FlushPreparedRecords() && tx.Abort()), "production accepted or aborted records durable");
}
void CheckAbortedHistory(const std::filesystem::path& path, const std::string& identity)
{
    const auto records = WriteAheadLog::ReadAll(path, identity);
    Check(records.status == WriteAheadLog::ReadStatus::Ok && !records.recovered_torn_tail && records.records.size() == 2,
        "original native abort history decodes completely");
    const auto& prepared = records.records.front(); const auto& aborted = records.records.back();
    Check(prepared.state == WriteAheadLog::RecordState::Prepared && prepared.transaction_id != 0 &&
        aborted.operation == WriteAheadLog::OperationKind::TransactionMarker && aborted.state == WriteAheadLog::RecordState::Cleaned &&
        aborted.flags == 0x2 && aborted.transaction_id == prepared.transaction_id && aborted.volume_identity == prepared.volume_identity &&
        aborted.sequence > prepared.sequence, "real later exact Abort covers its original Prepared mutation");
    std::vector<TransactionManager::AcceptedTransaction> transactions;
    TransactionManager::DurabilityWatermarks marks{}; std::string error;
    Check(TransactionManager::InspectAcceptedTransactionsReadOnly(path, identity, transactions, marks, error) &&
        transactions.empty() && marks.accepted_sequence == 0 && marks.apfs_durable_sequence == 0 && marks.cleanup_sequence == 0,
        "native original abort semantics have no accepted debt or watermark: " + error);
}
std::array<std::byte, 32> WalDigest(const Bytes& bytes)
{
    BCRYPT_ALG_HANDLE algorithm{}; std::array<std::byte, 32> digest{};
    Check(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0, "destination WAL hash provider");
    const auto status = BCryptHash(algorithm, nullptr, 0,
        reinterpret_cast<PUCHAR>(const_cast<std::byte*>(bytes.data())), static_cast<ULONG>(bytes.size()),
        reinterpret_cast<PUCHAR>(digest.data()), static_cast<ULONG>(digest.size()));
    BCryptCloseAlgorithmProvider(algorithm, 0);
    Check(status >= 0, "destination WAL SHA256"); return digest;
}
void ProductionRecords(bool canonical = false)
{
    const auto identity = [&](const std::string& container, std::uint64_t oid) {
        return canonical ? "apfs-vol:" + container + ":" + std::to_string(oid) : DerivePartitionlessVolumeRecoveryIdentity(container, oid);
    };
    for (auto op : {VolumeImageOperation::Grow, VolumeImageOperation::Shrink, VolumeImageOperation::Format, VolumeImageOperation::Erase}) {
        const bool format = op == VolumeImageOperation::Format || op == VolumeImageOperation::Erase;
        auto r = Setup(std::string(canonical ? "canonical-records-" : "production-records-") + std::to_string(static_cast<unsigned>(op)), op);
        if (format) r.new_container_uuid = "7b294455667748899abbccddeeff0022";
        std::map<std::filesystem::path, Bytes> originals;
        for (const auto& [oid, path] : r.sibling_wals) {
            WriteProductionWal(path, identity(r.container_uuid, oid), false, r.checkpoint_xid); originals[path] = Read(path);
            CheckAbortedHistory(path, identity(r.container_uuid, oid));
        }
        if (format) {
            WriteProductionWal(r.new_volume_wal, identity(r.new_container_uuid, 1024), false, r.checkpoint_xid);
            originals[r.new_volume_wal] = Read(r.new_volume_wal);
            CheckAbortedHistory(r.new_volume_wal, identity(r.new_container_uuid, 1024));
        }
        const auto unchanged_wals = [&]() {
            for (const auto& [path, bytes] : originals) Check(Read(path) == bytes, "original source/destination aborted WAL bytes unchanged");
        };
        const auto original = Read(r.image);
        if (format) {
            const auto destination_before = Read(r.new_volume_wal); const auto digest = WalDigest(destination_before);
            const auto refused = PrepareVolumeFormat(r);
            Check(refused.outcome == VolumeImageOutcome::Refused && refused.error == "VolumeImageDestinationWalNotEmpty" &&
                Read(r.image) == original, "nonempty prospective destination refuses: " + refused.error);
            const auto destination_after = Read(r.new_volume_wal);
            Check(destination_after == destination_before && WalDigest(destination_after) == digest,
                "valid aborted destination refusal preserves every byte and SHA256");
            unchanged_wals();
            r.new_volume_wal = r.journal_directory / "fresh-destination.wal";
            Save(r.new_volume_wal, {}); originals[r.new_volume_wal] = {};
        }
        const auto p = format ? PrepareVolumeFormat(r) : PrepareVolumeResize(r);
        Check(p.outcome == VolumeImageOutcome::Prepared && Read(r.image) == original, "source aborted WALs and empty destination prepare: " + p.error);
        unchanged_wals();
        const auto journal = Read(p.journal);
        {
            const auto path = format ? r.new_volume_wal : r.sibling_wals.at(202);
            HeldWal owner(path, DerivePartitionlessVolumeRecoveryIdentity(format ? r.new_container_uuid : r.container_uuid, format ? 1024 : 202));
            const auto refused = format ? ApplyVolumeFormat(r, p.token) : ApplyVolumeResize(r, p.token);
            Check(refused.error == "VolumeImageWalBusy" && Read(r.image) == original && Read(p.journal) == journal, "live source/destination production owner blocks apply without consuming plan");
            unchanged_wals();
        }
        const std::string stage = op == VolumeImageOperation::Grow ? "after-image-grow" : op == VolumeImageOperation::Shrink ?
            "after-image-truncate" : op == VolumeImageOperation::Format ? "after-image-anchor" : "after-image-cleanup";
        const auto hook = [&](std::string_view at) { return at != stage; };
        const auto partial = format ? ApplyVolumeFormat(r, p.token, hook) : ApplyVolumeResize(r, p.token, hook);
        Check(partial.outcome == VolumeImageOutcome::RecoveryRequired, partial.error);
        unchanged_wals();
        const auto interrupted = Read(r.image), evidence = Read(p.journal); auto wrong = r; ++wrong.checkpoint_xid;
        const auto mismatch = format ? RecoverVolumeFormat(wrong) : RecoverVolumeResize(wrong);
        Check(mismatch.error == "VolumeImageJournalBindingMismatch" && Read(r.image) == interrupted && Read(p.journal) == evidence,
            "changed original XID recovery preserves image and journal");
        unchanged_wals();
        {
            HeldWal owner(r.sibling_wals.at(201), DerivePartitionlessVolumeRecoveryIdentity(r.container_uuid, 201));
            const auto blocked = format ? RecoverVolumeFormat(r) : RecoverVolumeResize(r);
            Check(blocked.error == "VolumeImageWalBusy" && Read(r.image) == interrupted && Read(p.journal) == evidence, "accepted recovery fences production lease with no writes");
            unchanged_wals();
        }
        const auto recovered = format ? RecoverVolumeFormat(r) : RecoverVolumeResize(r);
        Check(recovered.outcome == VolumeImageOutcome::Committed, "production WAL recovery: " + recovered.error);
        unchanged_wals();
        const auto post = Read(r.image); volume_image::Verify(post, Checkpoint(post)); ++checks;
        const auto replay = format ? RecoverVolumeFormat(r) : RecoverVolumeResize(r);
        Check(replay.outcome == VolumeImageOutcome::Committed && Read(r.image) == post, "production record lifecycle idempotent");
        for (const auto& [path, bytes] : originals) Check(Read(path) == bytes, "all source/destination production WAL bytes unchanged");
    }
    if (!canonical) for (unsigned variant = 0; variant < 3; ++variant) {
        auto r = Setup("production-debt-" + std::to_string(variant)); const auto path = r.sibling_wals.at(201);
        const auto id = DerivePartitionlessVolumeRecoveryIdentity(r.container_uuid, 201);
        WriteProductionWal(path, variant == 1 ? "legacy-unknown-volume" : id, variant == 0, r.checkpoint_xid);
        if (variant == 2) {
            const auto canonical = r.journal_directory / "canonical-source.wal";
            WriteProductionWal(canonical, "apfs-vol:" + r.container_uuid + ":201", false, r.checkpoint_xid);
            auto mixed = Read(path), extra = Read(canonical); mixed.insert(mixed.end(), extra.begin(), extra.end()); Save(path, mixed);
        }
        const auto original = Read(r.image), wal = Read(path); const auto p = PrepareVolumeResize(r);
        const auto expected = variant == 0 ? "VolumeImageWalDebtOrPins" : variant == 1 ? "VolumeImageWalIdentityUnproven" : "VolumeImageWalMixedIdentities";
        Check(p.error == expected && Read(r.image) == original && Read(path) == wal, "production debt/unknown/mixed identity refusal: " + p.error);
    }
    Pass(canonical ? "canonical aborted records four-operation interrupted recovery with original WAL invariance" :
        "production records four-operation interrupted recovery plus unknown mixed and accepted-debt refusal");
}
std::map<std::filesystem::path, Bytes> FixtureFiles(const std::filesystem::path& directory)
{
    std::map<std::filesystem::path, Bytes> files;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(FixtureIoPath(directory)))
        if (entry.is_regular_file()) files.emplace(entry.path(), Read(entry.path()));
    return files;
}
void CheckFixtureFiles(const std::filesystem::path& directory, const std::map<std::filesystem::path, Bytes>& before)
{
    const auto after = FixtureFiles(directory);
    Check(after.size() == before.size(), "refusal neither creates nor removes original evidence files");
    for (const auto& [path, bytes] : before)
        Check(after.contains(path) && after.at(path) == bytes, "refusal preserves whole image/WAL/journal: " + path.filename().string());
}
void AbortBoundaryRefusals()
{
    for (const bool canonical : {false, true}) for (const std::string variant : {
        "orphan-prepared", "checkpointed-before-cleanup", "accepted-with-later-abort", "wrong-transaction",
        "zero-transaction", "wrong-abort-flags", "wrong-abort-state", "reordered-abort", "prepared-after-abort",
        "mixed-identity-abort", "unknown-identity-abort", "torn-abort"}) {
        const auto name = std::string(canonical ? "canonical-abort-" : "production-abort-") + variant;
        auto r = Setup(name + "-apply"); const auto path = r.sibling_wals.at(201);
        const auto identity = canonical ? "apfs-vol:" + r.container_uuid + ":201" : DerivePartitionlessVolumeRecoveryIdentity(r.container_uuid, 201);
        const auto prepared = PrepareVolumeResize(r);
        Check(prepared.outcome == VolumeImageOutcome::Prepared, "clean original plan for refusal witness: " + prepared.error);
        WriteProductionWal(path, identity, variant == "accepted-with-later-abort", r.checkpoint_xid);
        if (variant == "accepted-with-later-abort") WriteProductionWal(path, identity, false, r.checkpoint_xid);
        if (variant == "checkpointed-before-cleanup") {
            TransactionManager tx(L"Strict"); tx.SetJournalPath(path.wstring()); tx.SetVolumeIdentity(std::wstring(identity.begin(), identity.end()));
            TransactionManager::MutationIntent mutation; mutation.kind = TransactionManager::MutationKind::CreateFile;
            mutation.path = L"\\checkpointed"; mutation.object_id = 901; mutation.generation = r.checkpoint_xid + 1;
            Check(tx.Begin() && tx.RecordMutation(mutation) && tx.Commit(r.checkpoint_xid), "real committed marker retains pre-cleanup debt");
        }
        const bool debt = variant == "checkpointed-before-cleanup" || variant == "accepted-with-later-abort";
        std::string expected = debt ? "VolumeImageWalDebtOrPins" : "VolumeManagementWalSemanticsInvalid:";
        if (debt) {
            std::vector<TransactionManager::AcceptedTransaction> transactions;
            TransactionManager::DurabilityWatermarks marks{}; std::string error;
            Check(TransactionManager::InspectAcceptedTransactionsReadOnly(path, identity, transactions, marks, error) &&
                transactions.size() == 1 && marks.accepted_sequence > marks.cleanup_sequence && marks.cleanup_sequence == 0 &&
                marks.apfs_durable_sequence == (variant == "checkpointed-before-cleanup" ? marks.accepted_sequence : 0),
                "native original accepted/checkpointed debt remains above cleanup: " + error);
        } else if (variant == "torn-abort") {
            auto bytes = Read(path); bytes.pop_back(); Save(path, bytes); expected = "VolumeImageWalReadOnlyInspectionFailed";
        } else {
            const auto original = WriteAheadLog::ReadAll(path, identity);
            Check(original.status == WriteAheadLog::ReadStatus::Ok && !original.recovered_torn_tail && original.records.size() == 2,
                "negative derived from real original native Abort history");
            auto records = original.records;
            if (variant == "orphan-prepared") records.pop_back();
            else if (variant == "wrong-transaction") ++records.back().transaction_id;
            else if (variant == "zero-transaction") records.back().transaction_id = 0;
            else if (variant == "wrong-abort-flags") records.back().flags |= 0x1;
            else if (variant == "wrong-abort-state") records.back().state = WriteAheadLog::RecordState::Checkpointed;
            else if (variant == "reordered-abort") std::swap(records.front(), records.back());
            else if (variant == "prepared-after-abort") {
                auto mutation = records.front(); mutation.sequence = records.back().sequence + 1; records.push_back(mutation);
            } else if (variant == "mixed-identity-abort") {
                records.back().volume_identity = canonical ? DerivePartitionlessVolumeRecoveryIdentity(r.container_uuid, 201) : "apfs-vol:" + r.container_uuid + ":201";
                expected = "VolumeImageWalMixedIdentities";
            } else if (variant == "unknown-identity-abort") {
                records.back().volume_identity = "legacy-unknown-volume"; expected = "VolumeImageWalIdentityUnproven";
            }
            // Only corrupt negative witnesses are re-encoded; positive histories come from TransactionManager.
            Bytes bytes;
            for (const auto& record : records) for (const auto byte : WriteAheadLog::EncodeForTest(record)) bytes.push_back(static_cast<std::byte>(byte));
            Save(path, bytes);
            const auto decoded = WriteAheadLog::ReadAll(path, "");
            Check(decoded.status == WriteAheadLog::ReadStatus::Ok && !decoded.recovered_torn_tail && decoded.records.size() == records.size(),
                "CRC-valid negative reaches identity/transaction semantics instead of decode refusal");
        }
        const auto bad_wal = Read(path); const auto before_apply = FixtureFiles(r.journal_directory);
        const auto refused = ApplyVolumeResize(r, prepared.token);
        Check(refused.outcome == VolumeImageOutcome::Refused && refused.error == expected, "exact original history apply refusal " + name + ": " + refused.error);
        CheckFixtureFiles(r.journal_directory, before_apply);
        auto fresh = Setup(name + "-prepare"); Save(fresh.sibling_wals.at(201), bad_wal);
        const auto before_prepare = FixtureFiles(fresh.journal_directory); const auto denied = PrepareVolumeResize(fresh);
        Check(denied.outcome == VolumeImageOutcome::Refused && denied.error == expected, "exact original history prepare refusal " + name + ": " + denied.error);
        CheckFixtureFiles(fresh.journal_directory, before_prepare);
    }
    Pass("canonical/production orphan checkpointed accepted malformed misbound reordered mixed unknown and torn Abort refusals preserve all evidence");
}
void HeldRuntimeBridge()
{
    auto r = Setup("held-runtime"); const auto original = Read(r.image); const auto p = PrepareVolumeResize(r);
    Check(p.outcome == VolumeImageOutcome::Prepared, p.error); std::string error;
    {
        auto device = BlockDevice::OpenExclusiveManagementImage(r.image.wstring(), 0, error); Check(!!device, error);
        const auto blocked = InspectHeldVolumeKeeperImage(*device, r.journal_directory);
        Check(!blocked.admitted && blocked.error == "VolumeKeeperAdmissionBlocked:vif1:prepared" && blocked.source_identity == p.source_identity,
            "actual retained device identity sees pending debt without reopening");
        Check(InspectHeldVolumeKeeperImage(*device, {}).error == "VolumeKeeperJournalRootRequired", "missing trusted root refused");
        Check(InspectHeldVolumeKeeperImage(*device, r.journal_directory, true).error == "VolumeKeeperHistoricalSourceAmbiguous", "historical source refused");
        Bytes held; Check(device->Read(0, original.size(), held) && held == original, "held refusal source byte integrity");
    }
    Check(CancelVolumeResize(r, p.token).outcome == VolumeImageOutcome::Cancelled, "normal owner settles pending intent");
    {
        auto device = BlockDevice::OpenExclusiveManagementImage(r.image.wstring(), 0, error); Check(!!device, error);
        Check(InspectHeldVolumeKeeperImage(*device, r.journal_directory).admitted, "terminal journal admits retained actual image");
        std::string busy; Check(!BlockDevice::OpenExclusiveManagementImage(r.image.wstring(), 0, busy), "retained runtime excludes other keeper for entire lifetime");
        auto identity = InspectHeldVolumeKeeperImage(*device, r.journal_directory).source_identity;
        Bytes held; Check(device->Read(0, original.size(), held) && held == original && identity == p.source_identity, "terminal admission keeps exact original source");
    }
    Check(Read(r.image) == original, "bridge never mutates source"); Pass("runtime bridge uses retained exact image and requires stable root/current source");
}
void OverlappingRuntimeScopes()
{
    auto inner = Setup("inner-scope-builder", VolumeImageOperation::Shrink); auto inner_source = Read(inner.image);
    for (std::size_t at = 0; at < inner_source.size(); at += 4096) {
        Bytes nx(inner_source.begin() + at, inner_source.begin() + at + 4096); if (!catalog::ParseNxSuperblock(nx)) continue;
        nx[0x48] = std::byte{0x7d}; testfixture::FletcherForBlock(nx, 4096); std::copy(nx.begin(), nx.end(), inner_source.begin() + at);
    }
    inner = Request(inner.journal_directory, VolumeImageOperation::Shrink, inner_source); Save(inner.image, inner_source);
    constexpr std::size_t offset = 2 * 1024 * 1024; inner.target_bytes = offset;
    const auto ip = PrepareVolumeResize(inner); Check(ip.outcome == VolumeImageOutcome::Prepared, ip.error);
    const auto id = ApplyVolumeResize(inner, ip.token); Check(id.outcome == VolumeImageOutcome::Committed, id.error);
    const auto inner_bytes = Read(inner.image); volume_image::Verify(inner_bytes, Checkpoint(inner_bytes)); ++checks;
    for (const auto stage : {"after-image-accept", "after-image-grow"}) {
        auto r = Setup(std::string("overlap-") + stage); auto original = Read(r.image); const auto cp = Checkpoint(original);
        Check(offset + inner_bytes.size() == original.size(), "inner APFS fits outer free suffix");
        bool free = true; for (auto block = offset / 4096; block < original.size() / 4096; ++block)
            free &= !volume_image::Bit(cp.spaceman.chunks.front().allocation_bitmap, block);
        Check(free, "every inner store block is free to outer allocator");
        std::copy(inner_bytes.begin(), inner_bytes.end(), original.begin() + offset); Save(r.image, original);
        volume_image::Verify(original, Checkpoint(original)); ++checks;
        const auto held_admission = [&]() {
            std::string error; auto held = BlockDevice::OpenExclusiveManagementImage(r.image.wstring(), offset, error); Check(!!held, error);
            catalog::ApfsContainerCatalog parsed; std::wstring detail;
            Check(catalog::ApfsContainerCatalog::TryLoadDevice(*held, parsed, detail, catalog::CatalogLoadPolicy::StrictApple) &&
                parsed.Containers().size() == 1 && parsed.Containers().front().container_uuid_hex == inner.container_uuid,
                "real strict runtime parser accepts distinct inner APFS");
            const auto admission = InspectHeldVolumeKeeperImage(*held, r.journal_directory);
            Bytes payload; Check(held->Read(240 * 4096, 4096, payload) && std::equal(payload.begin(), payload.end(), inner_bytes.begin() + 240 * 4096),
                "held admission leaves inner payload intact"); return admission;
        };
        Check(held_admission().admitted, "nonzero-offset source with no debt admits");
        const auto p = PrepareVolumeResize(r); Check(p.outcome == VolumeImageOutcome::Prepared, p.error); const auto prepared = Read(p.journal);
        const auto blocked_prepared = held_admission();
        Check(!blocked_prepared.admitted && blocked_prepared.error == "VolumeKeeperAdmissionBlocked:vif1:prepared" &&
            Read(r.image) == original && Read(p.journal) == prepared, "whole-image prepared intent blocks interior runtime without writes");
        const auto interrupted = ApplyVolumeResize(r, p.token, [&](auto at) { return at != stage; });
        Check(interrupted.outcome == VolumeImageOutcome::RecoveryRequired, interrupted.error);
        const auto partial = Read(r.image), accepted = Read(p.journal); const auto blocked_accepted = held_admission();
        Check(!blocked_accepted.admitted && blocked_accepted.error == "VolumeKeeperAdmissionBlocked:vif1:accepted" &&
            Read(r.image) == partial && Read(p.journal) == accepted, "accepted whole-image geometry binds interior even after actual growth");
        const auto recovered = RecoverVolumeResize(r); Check(recovered.outcome == VolumeImageOutcome::Committed, recovered.error);
        const auto post = Read(r.image); volume_image::Verify(post, Checkpoint(post)); ++checks;
        Check(held_admission().admitted, "completed overlapping geometry proof admits inner runtime");
        Check(RecoverVolumeResize(r).outcome == VolumeImageOutcome::Committed && Read(r.image) == post, "blocked overlap keeps exact idempotent outer recovery");
        auto unrelated = r; unrelated.image = r.journal_directory / "other.apfs"; Save(unrelated.image, original);
        const auto other = PrepareVolumeResize(unrelated); Check(other.outcome == VolumeImageOutcome::Prepared, other.error);
        Check(held_admission().admitted, "validated different file ID in common root does not own this source");
        const auto valid = Read(other.journal); auto malformed = valid; malformed[100] ^= std::byte{1}; Save(other.journal, malformed);
        Check(!held_admission().admitted && Read(other.journal) == malformed && Read(r.image) == post,
            "unbound foreign-locator evidence cannot be assumed disjoint");
        Save(other.journal, valid); Check(CancelVolumeResize(unrelated, other.token).outcome == VolumeImageOutcome::Cancelled, "settle unrelated owner normally");
    }
    Pass("actual nested APFS runtime overlap blocks prepared and accepted whole-image debt; original recovery stays intact");
}
}
int wmain(int argc, wchar_t** argv)
{
    try {
        Check(argc == 2 || (argc == 3 && (std::wstring_view(argv[2]) == L"--leases-only" ||
            std::wstring_view(argv[2]) == L"--unaccepted-only" || std::wstring_view(argv[2]) == L"--aborted-only" ||
            std::wstring_view(argv[2]) == L"--abort-refusals-only" || std::wstring_view(argv[2]) == L"--original-snapshots-only" ||
            std::wstring_view(argv[2]) == L"--omap-counts-only" || std::wstring_view(argv[2]) == L"--long-paths-only")), "fresh D: evidence root required"); root = argv[1]; std::filesystem::create_directories(root);
        if (argc == 3 && std::wstring_view(argv[2]) == L"--long-paths-only") {
            LongManagementJournalPaths(); std::cout << "PASS groups=" << groups << " checks=" << checks << std::endl; return 0;
        }
        if (argc == 3 && std::wstring_view(argv[2]) == L"--omap-counts-only") {
            OriginalOmapSnapshotCounts(); std::cout << "PASS groups=" << groups << " checks=" << checks << std::endl; return 0;
        }
        if (argc == 3 && std::wstring_view(argv[2]) == L"--original-snapshots-only") {
            OriginalSnapshotFrames(); std::cout << "PASS groups=" << groups << " checks=" << checks << std::endl; return 0;
        }
        if (argc == 3 && std::wstring_view(argv[2]) == L"--unaccepted-only") {
            RecoverUnacceptedImage(); std::cout << "PASS groups=" << groups << " checks=" << checks << std::endl; return 0;
        }
        if (argc == 3 && std::wstring_view(argv[2]) == L"--abort-refusals-only") {
            AbortBoundaryRefusals(); std::cout << "PASS groups=" << groups << " checks=" << checks << std::endl; return 0;
        }
        if (argc == 3 && std::wstring_view(argv[2]) == L"--aborted-only") {
            ProductionOwners(); ProductionRecords(); ProductionRecords(true); AbortBoundaryRefusals();
            std::cout << "PASS groups=" << groups << " checks=" << checks << std::endl; return 0;
        }
        ProductionOwners(); if (argc == 3) { std::cout << "PASS groups=" << groups << " checks=" << checks << std::endl; return 0; }
        LongManagementJournalPaths(); PreparedAndCancelled(); RecoverUnacceptedImage(); AcceptedImage(); AcceptedManagement(); MalformedFrames(true); MalformedFrames(false); ApplyPreflight();
        ArchivedFrames(true); ArchivedFrames(false); OriginalSnapshotFrames(); OriginalOmapSnapshotCounts(); OffsetLocator();
        ProductionRecords(); ProductionRecords(true); AbortBoundaryRefusals(); HeldRuntimeBridge(); OverlappingRuntimeScopes();
        std::cout << "PASS groups=" << groups << " checks=" << checks << std::endl; return 0;
    } catch (const std::exception& ex) { std::cerr << "FAIL checks=" << checks << " " << ex.what() << std::endl; return 1; }
}
