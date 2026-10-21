#pragma once
#include "VolumeResizeFixture.h"
#include "../src/VolumeResizeInternal.h"
#include "TransactionManager.h"
#include "AppleVolumeTransaction.h"
#include <Windows.h>
#undef CreateFile
#include <iostream>
namespace apfsaccess::volume_image_test
{
inline unsigned checks = 0, groups = 0;
inline std::filesystem::path root;
inline void Check(bool ok, const std::string& why) { ++checks; if (!ok) throw std::runtime_error(why); }
inline void Pass(const char* name) { ++groups; std::cout << "PASS " << name << std::endl; }
inline bool Format(VolumeImageOperation op) { return op == VolumeImageOperation::Format || op == VolumeImageOperation::Erase; }
inline VolumeImageResult Prepare(const VolumeImageRequest& r) { return Format(r.operation) ? PrepareVolumeFormat(r) : PrepareVolumeResize(r); }
inline VolumeImageResult Apply(const VolumeImageRequest& r, std::string_view t, const AppleCheckpointStageHook& h = {})
{ return Format(r.operation) ? ApplyVolumeFormat(r, t, h) : ApplyVolumeResize(r, t, h); }
inline VolumeImageResult Recover(const VolumeImageRequest& r)
{ return Format(r.operation) ? RecoverVolumeFormat(r) : RecoverVolumeResize(r); }
inline VolumeImageResult Cancel(const VolumeImageRequest& r, std::string_view t)
{ return Format(r.operation) ? CancelVolumeFormat(r, t) : CancelVolumeResize(r, t); }
inline VolumeImageRequest Setup(const std::string& name, VolumeImageOperation op, const Bytes& image = Fixture())
{
    const auto dir = root / name; Check(!std::filesystem::exists(dir), "fresh evidence directory required");
    std::filesystem::create_directories(dir); auto r = Request(dir, op, image); Save(r.image, image); return r;
}
inline void Positive(VolumeImageOperation op)
{
    auto r = Setup("positive-" + std::to_string(static_cast<unsigned>(op)), op); const auto original = Read(r.image);
    const auto prepared = Prepare(r); Check(prepared.outcome == VolumeImageOutcome::Prepared, "prepare: " + prepared.error);
    Check(Read(r.image) == original && prepared.token.size() == 64, "preview preserves entire image");
    Check(Prepare(r).error == "VolumeImageUnfinishedJournal", "unfinished intent cannot be replaced");
    const auto done = Apply(r, prepared.token); Check(done.outcome == VolumeImageOutcome::Committed, "apply: " + done.error);
    const auto post = Read(r.image); const auto cp = Checkpoint(post);
    Check(post.size() == r.target_bytes && cp.container.superblock.block_count * 4096 == post.size() &&
        cp.spaceman.devices[0].block_count * 4096 == post.size(), "real length and both Apple geometries agree");
    Check(cp.container.superblock.xid == prepared.post_xid, "one planned generation");
    rw::volume_image::Verify(post, cp); ++checks;
    if (Format(op)) {
        Check(cp.volumes.size() == 1 && cp.container.superblock.uuid_hex == r.new_container_uuid &&
            cp.volumes.front().superblock.uuid_hex == r.new_volume_uuid, "fresh container and volume replace siblings");
        Check(cp.volumes.front().superblock.object_id == 1024 && cp.volumes.front().superblock.name_utf8 == r.name_utf8 &&
            cp.volumes.front().superblock.space.allocated_block_count == 6, "fresh APSB name root and six owned blocks");
        Check(cp.spaceman.devices[0].free_count == cp.container.superblock.block_count - 345, "fresh allocator ownership exactly 345 blocks");
        Check(ReadU32LE(cp.container.superblock_bytes, 0xb4) == ReadU32LE(Checkpoint(original).container.superblock_bytes, 0xb4) &&
            ReadU64LE(cp.container.superblock_bytes, 0x520) == ((8ull << 32) | (4ull << 16) | 1),
            "Apple source volume capacity and ephemeral geometry fields");
        if (op == VolumeImageOperation::Erase) {
            Check(std::all_of(post.begin() + 240 * 4096, post.begin() + 241 * 4096, [](auto b) { return b == std::byte{}; }), "erased old payload bytes");
            Check(std::all_of(post.begin() + 248 * 4096, post.begin() + 249 * 4096, [](auto b) { return b == std::byte{}; }), "erased sibling payload bytes");
        } else Check(post[240 * 4096] == std::byte{0x71}, "format does not claim free-byte erasure");
    } else {
        Check(cp.volumes.size() == 2 && cp.container.superblock.uuid_hex == r.container_uuid, "resize preserves topology identity");
        for (const auto block : {240u, 248u}) Check(std::equal(post.begin() + block * 4096, post.begin() + (block + 1) * 4096,
            original.begin() + block * 4096), "owned payload preserved");
        const auto delta = static_cast<std::int64_t>(r.target_bytes / 4096) - static_cast<std::int64_t>(r.expected_bytes / 4096);
        Check(static_cast<std::int64_t>(done.free_blocks_after) == static_cast<std::int64_t>(done.free_blocks_before) + delta - 1,
            "free count reflects geometry and one new OMAP object");
        if (op == VolumeImageOperation::Grow) {
            const auto& c = cp.spaceman.chunks.front();
            for (auto b = r.expected_bytes / 4096; b < r.target_bytes / 4096; ++b) Check(!rw::volume_image::Bit(c.allocation_bitmap, b), "new blocks are free");
        }
    }
    Check(Recover(r).outcome == VolumeImageOutcome::Committed, "idempotent verified recovery");
    Check(Apply(r, prepared.token).error == "VolumeImageConfirmationConsumed", "token cannot be reused");
    Pass(Format(op) ? "format/erase genuine fresh topology and allocator" : "resize length geometry ownership and payload");
}
inline void Refusals(VolumeImageOperation op)
{
    unsigned n = 0;
    const auto test = [&](const std::function<void(VolumeImageRequest&)>& alter) {
        auto r = Setup("refusal-" + std::to_string(n++), op); const auto original = Read(r.image); alter(r);
        const auto p = Prepare(r); Check(p.outcome == VolumeImageOutcome::Refused && !p.error.empty(),
            "typed refusal case=" + std::to_string(n - 1) + " outcome=" + std::to_string(static_cast<unsigned>(p.outcome)) + " error=" + p.error);
        Check(Read(r.image) == original, "refusal image byte-identical");
    };
    test([](auto& r) { r.volume_oid = 0; }); test([](auto& r) { ++r.checkpoint_xid; });
    test([](auto& r) { r.container_uuid[0] = 'f'; }); test([](auto& r) { r.volume_uuid[0] = 'e'; });
    test([](auto& r) { r.expected_bytes += 4096; }); test([](auto& r) { r.target_bytes = (1ull << 40) + 4096; });
    test([](auto& r) { r.sibling_wals.erase(202); }); test([](auto& r) { r.sibling_wals[202] = r.sibling_wals[201]; });
    test([](auto& r) { r.journal_directory /= "missing-root"; });
    if (Format(op)) {
        test([](auto& r) { r.new_container_uuid = r.container_uuid; });
        test([](auto& r) { r.new_volume_wal = r.sibling_wals.at(201); });
        test([](auto& r) { r.name_utf8 = std::string(1, char(0xff)); });
        auto no_space = Setup("no-space", op, Fixture(1)); const auto before = Read(no_space.image);
        Check(Prepare(no_space).outcome == VolumeImageOutcome::Refused && Read(no_space.image) == before, "no room for independent bootstrap");
    } else {
        auto streamed = Setup("streamed-former-profile-limit", VolumeImageOperation::Grow);
        const auto original = Read(streamed.image);
        streamed.target_bytes = 256ull * 1024 * 1024 + 4096;
        const auto planned = Prepare(streamed);
        Check(planned.outcome == VolumeImageOutcome::Prepared && Read(streamed.image) == original,
            "existing streamed resize accepts the former bounded-image threshold without image writes: " + planned.error);
        Check(Cancel(streamed, planned.token).outcome == VolumeImageOutcome::Cancelled && Read(streamed.image) == original,
            "streamed preview cancellation preserves every original byte");
        test([](auto& r) { r.operation = VolumeImageOperation::Shrink; r.target_bytes = 245 * 4096; });
    }
    Pass("identity capacity unsupported layout WAL and missing-root refusals");
}
inline void TokensAndWal(VolumeImageOperation op)
{
    for (unsigned variant = 0; variant < 4; ++variant) {
        auto r = Setup("token-" + std::to_string(variant), op); const auto before = Read(r.image); const auto p = Prepare(r);
        Check(p.outcome == VolumeImageOutcome::Prepared, p.error);
        if (variant == 0) Check(Cancel(r, p.token).outcome == VolumeImageOutcome::Cancelled, "cancel");
        if (variant == 1) Check(Apply(r, "wrong").error == "VolumeImageConfirmationMismatch", "wrong confirmation");
        if (variant == 2) {
            auto changed = before; changed.back() ^= std::byte{1}; Save(r.image, changed);
            Check(Apply(r, p.token).error == "VolumeImageStaleSource" && Read(r.image) == changed, "stale source consumes confirmation");
        }
        if (variant == 3) Check(Apply(r, p.token, [](auto stage) { return stage != "before-image-accept"; }).outcome ==
            VolumeImageOutcome::Cancelled, "cancel before durable acceptance");
        Check(Apply(r, p.token).error == "VolumeImageConfirmationConsumed", "terminal token remains consumed");
        if (variant != 2) Check(Read(r.image) == before, "cancel leaves source bytes intact");
    }
    auto r = Setup("accepted-wal", op); const auto before = Read(r.image);
    {
        TransactionManager writer(L"Strict"); writer.SetJournalPath(r.sibling_wals.at(202).wstring());
        const auto id = "apfs-vol:" + r.container_uuid + ":202"; writer.SetVolumeIdentity(std::wstring(id.begin(), id.end()));
        TransactionManager::MutationIntent intent; intent.kind = TransactionManager::MutationKind::CreateFile;
        intent.path = L"\\pending.txt"; intent.object_id = 500; intent.generation = r.checkpoint_xid + 1;
        Check(writer.Begin() && writer.RecordMutation(intent) && writer.Accept(r.checkpoint_xid), "real accepted WAL debt fixture");
    }
    Check(Prepare(r).error == "VolumeImageWalDebtOrPins" && Read(r.image) == before, "accepted sibling WAL veto");
    r = Setup("compaction-evidence", op); const auto p = Prepare(r); Check(p.outcome == VolumeImageOutcome::Prepared, p.error);
    auto receipt = r.sibling_wals.at(201); receipt += L".compact.intent"; Save(receipt, {std::byte{1}});
    Check(Apply(r, p.token).error == "VolumeImageWalCompactionEvidence", "compaction evidence vetoes before acceptance");
    Check(Cancel(r, p.token).outcome == VolumeImageOutcome::Cancelled, "blocked unaccepted intent cancellable");
    Pass("single-use cancel stale accepted WAL and compaction debt");
}
inline void Interruptions(VolumeImageOperation op)
{
    const std::vector<std::string> stages = {"after-image-accept", "after-image-grow", "before-apple-device-write",
        "before-apple-prepublication-flush", "before-apple-checkpoint-switch", "before-apple-final-flush",
        "before-image-anchor", "after-image-anchor", "after-image-cleanup", "after-image-truncate", "before-image-complete"};
    for (std::size_t i = 0; i < stages.size(); ++i) {
        auto r = Setup("interrupt-" + std::to_string(static_cast<unsigned>(op)) + "-" + std::to_string(i), op);
        const auto p = Prepare(r); Check(p.outcome == VolumeImageOutcome::Prepared, p.error); bool hit = false;
        const auto result = Apply(r, p.token, [&](auto stage) { if (stage == stages[i]) { hit = true; return false; } return true; });
        Check(hit && result.outcome == VolumeImageOutcome::RecoveryRequired, "durable boundary interrupted: " + result.error);
        const auto interrupted = Read(r.image); const auto cp = Checkpoint(interrupted);
        Check(cp.container.superblock.xid == p.pre_xid || cp.container.superblock.xid == p.post_xid, "old or new complete generation at durable boundary");
        rw::volume_image::Verify(interrupted, cp); ++checks;
        const auto recovered = Recover(r); Check(recovered.outcome == VolumeImageOutcome::Committed, "fresh lease replay: " + recovered.error);
        Check(Read(r.image).size() == r.target_bytes && Checkpoint(Read(r.image)).container.superblock.xid == p.post_xid, "one exact post-generation and length");
        Check(Recover(r).outcome == VolumeImageOutcome::Committed, "recovery idempotence");
    }
    Pass("old/new proof and forward recovery at eleven boundaries");
}
inline void JournalTails(VolumeImageOperation op)
{
    for (bool after_anchor : {false, true}) {
        auto r = Setup(after_anchor ? "partial-anchor-receipt" : "partial-accept-receipt", op); const auto original = Read(r.image);
        const auto p = Prepare(r); Check(p.outcome == VolumeImageOutcome::Prepared, p.error);
        Check(Apply(r, p.token, [&](auto stage) { return stage != (after_anchor ? "after-image-anchor" : "after-image-accept"); }).outcome ==
            VolumeImageOutcome::RecoveryRequired, "receipt fixture interruption");
        auto bytes = Read(p.journal); bytes.resize(bytes.size() - 9); Save(p.journal, bytes);
        const auto recovered = Recover(r);
        Check(recovered.outcome == (after_anchor ? VolumeImageOutcome::Committed : VolumeImageOutcome::Cancelled), "partial receipt: " + recovered.error);
        if (!after_anchor) Check(Read(r.image) == original, "partial acceptance cannot authorize writes");
    }
    auto r = Setup("torn-anchor", op); const auto p = Prepare(r); Check(p.outcome == VolumeImageOutcome::Prepared, p.error);
    Check(Apply(r, p.token, [](auto stage) { return stage != "before-image-anchor"; }).outcome == VolumeImageOutcome::RecoveryRequired, "pre-anchor fixture");
    auto bytes = Read(r.image); std::fill(bytes.begin() + 100, bytes.begin() + 2111, std::byte{0x55}); Save(r.image, bytes);
    const auto recovered = Recover(r); Check(recovered.outcome == VolumeImageOutcome::Committed, "journal restores torn anchor: " + recovered.error);
    r = Setup("corrupt-journal", op); const auto original = Read(r.image); const auto plan = Prepare(r);
    Check(plan.outcome == VolumeImageOutcome::Prepared, plan.error); bytes = Read(plan.journal); bytes[100] ^= std::byte{1}; Save(plan.journal, bytes);
    Check(Apply(r, plan.token).error == "VolumeImageJournalChecksumInvalid" && Read(r.image) == original, "corrupt journal cannot authorize mutation");
    Pass("partial receipts torn anchor and corrupt journal");
}
inline void LongPath(VolumeImageOperation op)
{
    auto r = Setup("long-journal-root", op); const auto original = Read(r.image);
    auto dir = r.journal_directory;
    while (dir.wstring().size() < 220) { dir /= L"durable-root-component"; std::filesystem::create_directory(dir); }
    r.journal_directory = dir;
    const auto p = Prepare(r); Check(p.outcome == VolumeImageOutcome::Prepared && p.journal.wstring().size() > MAX_PATH, "extended active journal: " + p.error);
    Check(Cancel(r, p.token).outcome == VolumeImageOutcome::Cancelled, "cancel long journal");
    const auto next = Prepare(r); Check(next.outcome == VolumeImageOutcome::Prepared, "extended archive reprepare: " + next.error);
    const auto archive = L"\\\\?\\" + p.journal.wstring() + L"." + std::wstring(p.token.begin(), p.token.end()) + L".completed";
    Check(GetFileAttributesW(archive.c_str()) != INVALID_FILE_ATTRIBUTES && Read(r.image) == original, "long archive preserved original");
    Check(Cancel(r, next.token).outcome == VolumeImageOutcome::Cancelled, "consume replacement plan");
    Pass("active and archived journal paths beyond MAX_PATH");
}
inline void PolicyAndTail(VolumeImageOperation op)
{
    for (auto offset : {0x4e0u, 0x4e8u, 0x4f8u, 0x518u, 0x578u}) {
        auto b = Fixture();
        for (std::size_t at = 0; at < b.size(); at += 4096) {
            Bytes nx(b.begin() + at, b.begin() + at + 4096); if (!ParseNxSuperblock(nx)) continue;
            PutU64LE(nx, offset, 1); FletcherForBlock(nx, 4096); std::copy(nx.begin(), nx.end(), b.begin() + at);
        }
        auto r = Setup("auxiliary-" + std::to_string(offset), op, b); const auto p = Prepare(r);
        Check(p.outcome == VolumeImageOutcome::Refused && Read(r.image) == b, "unproven auxiliary ownership preserves source");
    }
    if (!Format(op)) {
        auto b = Fixture(); const auto cp = Checkpoint(b); auto sm = cp.spaceman.bytes;
        PutU64LE(sm, 0x160, 900); FletcherForBlock(sm, 4096);
        std::copy(sm.begin(), sm.end(), b.begin() + cp.spaceman.object.physical_block * 4096);
        auto r = Setup("nonempty-zone-policy", op, b);
        const auto denied_zone = Prepare(r);
        Check(denied_zone.outcome == VolumeImageOutcome::Refused && denied_zone.token.empty() &&
            denied_zone.error == "VolumeResizeAllocationZoneIdentityProfileUnsupported" && Read(r.image) == b,
            "populated zone with zero identity refuses unchanged under the restricted profile: " + denied_zone.error);
        r = Setup("allocated-tail", VolumeImageOperation::Shrink, Fixture(0, 900)); b = Read(r.image);
        Check(Prepare(r).error == "VolumeResizeAllocatedTailRequiresRelocation" && Read(r.image) == b, "real payload beyond target requires relocation");
    }
    Pass("auxiliary ownership allocation-zone policy and real allocated tail");
}
inline void BusyAndBinding(VolumeImageOperation op)
{
    auto r = Setup("busy-lease", op); const auto original = Read(r.image); auto p = Prepare(r);
    Check(p.outcome == VolumeImageOutcome::Prepared, p.error);
    {
        const auto id = Format(op) ? "apfs-vol:" + r.new_container_uuid + ":1024" : "apfs-vol:" + r.container_uuid + ":202";
        WriteAheadLog lease({Format(op) ? r.new_volume_wal : r.sibling_wals.at(202), id});
        Check(lease.AcquireWriterLeaseOnly(), "independent live WAL owner");
        Check(Apply(r, p.token).error == "VolumeImageWalBusy" && Read(r.image) == original, "busy apply does not consume or mutate");
    }
    Check(Apply(r, p.token).outcome == VolumeImageOutcome::Committed, "same confirmation works after owner releases");
    r = Setup("request-binding", op); p = Prepare(r); Check(p.outcome == VolumeImageOutcome::Prepared, p.error);
    auto changed = r; changed.sibling_wals.at(201) += L".other";
    Check(Apply(changed, p.token).error == "VolumeImageJournalBindingMismatch", "canonical WAL path part of confirmation");
    changed = r;
    if (Format(op)) changed.name_utf8 += " altered"; else changed.target_bytes += 4096;
    Check(Apply(changed, p.token).error == "VolumeImageJournalBindingMismatch", "capacity or format options part of confirmation");
    Check(Cancel(r, p.token).outcome == VolumeImageOutcome::Cancelled, "unaltered request still owns intent");
    if (Format(op)) {
        r = Setup("destination-debt", op);
        {
            TransactionManager writer(L"Strict"); writer.SetJournalPath(r.new_volume_wal.wstring());
            const auto id = "apfs-vol:" + r.new_container_uuid + ":1024"; writer.SetVolumeIdentity(std::wstring(id.begin(), id.end()));
            TransactionManager::MutationIntent intent; intent.kind = TransactionManager::MutationKind::CreateFile;
            intent.path = L"\\pending.txt"; intent.object_id = 500; intent.generation = r.checkpoint_xid + 1;
            Check(writer.Begin() && writer.RecordMutation(intent) && writer.Accept(r.checkpoint_xid), "accepted destination WAL debt");
        }
        const auto before_image = Read(r.image), before_wal = Read(r.new_volume_wal);
        const auto denied = Prepare(r);
        Check(denied.outcome == VolumeImageOutcome::Refused && denied.token.empty() &&
            denied.error == "VolumeImageDestinationWalNotEmpty" && Read(r.image) == before_image &&
            Read(r.new_volume_wal) == before_wal, "new destination refuses prior WAL contents without changing image or WAL");
    }
    Pass("live leases exact request binding and destination WAL debt");
}
inline void RecoveryConflicts(VolumeImageOperation op)
{
    for (bool foreign : {false, true}) {
        auto r = Setup(foreign ? "foreign-checkpoint" : "unrelated-recovery-change", op);
        const auto p = Prepare(r); Check(p.outcome == VolumeImageOutcome::Prepared, p.error);
        Check(Apply(r, p.token, [](auto stage) { return stage != "after-image-accept"; }).outcome == VolumeImageOutcome::RecoveryRequired,
            "accepted original fixture");
        const auto original = Read(r.image); auto changed = original;
        if (foreign) {
            Bytes nx(changed.begin(), changed.begin() + 4096); nx[0x48] ^= std::byte{0x01}; FletcherForBlock(nx, 4096);
            std::copy(nx.begin(), nx.end(), changed.begin());
        } else changed[240 * 4096] ^= std::byte{0x01};
        Save(r.image, changed); const auto refused = Recover(r);
        Check(refused.outcome == VolumeImageOutcome::RecoveryRequired && refused.error == (foreign ?
            "VolumeImageRecoveryForeignCheckpoint" : "VolumeImageRecoveryUnrelatedBytesChanged") && Read(r.image) == changed,
            "conflicting recovery evidence preserved: " + refused.error);
        Save(r.image, original); Check(Recover(r).outcome == VolumeImageOutcome::Committed, "exact original permits forward recovery");
    }
    if (op == VolumeImageOperation::Grow) {
        auto r = Setup("partial-grown-tail", op); const auto p = Prepare(r);
        Check(p.outcome == VolumeImageOutcome::Prepared, p.error);
        Check(Apply(r, p.token, [](auto stage) { return stage != "after-image-grow"; }).outcome == VolumeImageOutcome::RecoveryRequired,
            "already-extended crash fixture");
        auto b = Read(r.image); std::fill(b.begin() + r.expected_bytes, b.end(), std::byte{0xa7}); Save(r.image, b);
        const auto recovered = Recover(r); Check(recovered.outcome == VolumeImageOutcome::Committed,
            "replay initializes already-extended range: " + recovered.error);
        b = Read(r.image); Check(std::all_of(b.begin() + r.expected_bytes, b.end(), [](auto v) { return v == std::byte{}; }),
            "new unowned range has deterministic zero bytes");
    }
    Pass("foreign checkpoint and unrelated data prevent destructive recovery");
}
inline Bytes SnapshotFixture()
{
    auto image = Fixture(); const auto cp = Checkpoint(image); VectorRandomAccessSource source(image); std::string e;
    AppleSnapshotCreateRequest r; r.volume_object_id = 201; r.name_utf8 = "retained"; r.creation_time_ns = 1700000000000000000ull;
    AppleSnapshotCreatePlan plan; Check(PlanAppleSnapshotCreate(source, cp, r, plan, e), "production snapshot create plan: " + e);
    const auto put = [&](const auto& w) { std::copy(w.bytes.begin(), w.bytes.end(), image.begin() + w.physical_block * 4096); };
    for (const auto& w : plan.commit.publication.before_superblock_writes) put(w);
    put(plan.commit.publication.superblock_write);
    (void)Checkpoint(image); return image;
}
inline void SnapshotOwners(bool format)
{
    const auto image = SnapshotFixture(); const auto prior = Checkpoint(image); VectorRandomAccessSource before(image);
    AppleSnapshotRetentionView old; std::string e; Check(LoadAppleSnapshotRetention(before, prior, old, e) && old.identities.size() == 1, e);
    const std::vector<VolumeImageOperation> operations = format ? std::vector{VolumeImageOperation::Format, VolumeImageOperation::Erase} :
        std::vector{VolumeImageOperation::Grow, VolumeImageOperation::Shrink};
    for (const auto op : operations) {
        auto r = Setup("snapshot-refusal-" + std::to_string(static_cast<unsigned>(op)), op, image); const auto p = Prepare(r);
        Check(p.outcome == VolumeImageOutcome::Refused &&
            p.error == "VolumeImageSnapshotHistoryAuthorityUnproven" &&
            Read(r.image) == image, "exact historical image authority refusal leaves every source byte unchanged: " + p.error);
    }
    Pass("production-created snapshot refuses with exact historical-ownership gap and unchanged bytes");
}
inline void FormatThenResize()
{
    auto r = Setup("format-then-grow", VolumeImageOperation::Format); r.case_sensitive = true; const auto p = Prepare(r);
    Check(p.outcome == VolumeImageOutcome::Prepared, p.error); const auto done = Apply(r, p.token);
    Check(done.outcome == VolumeImageOutcome::Committed, done.error);
    const auto image = Read(r.image); auto resize = Request(r.journal_directory, VolumeImageOperation::Grow, image);
    resize.sibling_wals.at(1024) = r.new_volume_wal;
    const auto planned = Prepare(resize); Check(planned.outcome == VolumeImageOutcome::Prepared, "production formatter output is resizable: " + planned.error);
    const auto grown = Apply(resize, planned.token); Check(grown.outcome == VolumeImageOutcome::Committed, grown.error);
    const auto cp = Checkpoint(Read(r.image)); Check(cp.container.superblock.uuid_hex == r.new_container_uuid &&
        cp.volumes.front().superblock.uuid_hex == r.new_volume_uuid && cp.volumes.front().superblock.incompatible_features == 0,
        "formatter case-sensitive identity survives subsequent production grow");
    Pass("production format output supports real subsequent resize");
}
}
