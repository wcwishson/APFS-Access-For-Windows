#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "VolumeFormatMultichunkCases.h"
#include "VolumeKeeperWal.h"
#include "../src/VolumeFormatEvidence.h"
using namespace apfsaccess::volume_image_test;
namespace mc = apfsaccess::volume_image_test::multichunk;
namespace vi = apfsaccess::rw::volume_image;
namespace fe = apfsaccess::rw::format_evidence;

class Target final : public RandomAccessSource, public AppleCheckpointWriteTarget
{
public:
    explicit Target(const std::filesystem::path& path)
    {
        h_ = CreateFileW(FixtureIoPath(path).c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        Check(h_ != INVALID_HANDLE_VALUE, "exclusive actual image"); LARGE_INTEGER size{};
        Check(GetFileSizeEx(h_, &size) && size.QuadPart > 0, "actual size"); size_ = size.QuadPart;
    }
    ~Target() { CloseHandle(h_); }
    std::uint64_t SizeBytes() const override { return size_; }
    bool Read(std::uint64_t offset, std::size_t size, Bytes& out) const override
    {
        out.clear(); if (offset > size_ || size > size_ - offset || size > MAXDWORD) return false;
        LARGE_INTEGER at{}; at.QuadPart = offset; DWORD got{}; out.resize(size);
        if (SetFilePointerEx(h_, at, nullptr, FILE_BEGIN) && ReadFile(h_, out.data(), static_cast<DWORD>(size), &got, nullptr) && got == size) return true;
        out.clear(); return false;
    }
    bool ReadBlock(std::uint64_t block, std::uint32_t size, Bytes& out) override { return Read(block * size, size, out); }
    bool WriteBlock(std::uint64_t block, std::span<const std::byte> bytes) override
    {
        if (bytes.size() != 4096 || block >= size_ / 4096) return false;
        LARGE_INTEGER at{}; at.QuadPart = block * 4096; DWORD wrote{};
        return SetFilePointerEx(h_, at, nullptr, FILE_BEGIN) && WriteFile(h_, bytes.data(), 4096, &wrote, nullptr) && wrote == 4096;
    }
    bool Flush() override { return FlushFileBuffers(h_) != FALSE; }
private:
    HANDLE h_ = INVALID_HANDLE_VALUE;
    std::uint64_t size_ = 0;
};
mc::SparseStore Source()
{
    const auto original = Fixture(); const auto old = Checkpoint(original);
    mc::SparseStore source; source.block_count = 4 * mc::ChunkBlocks - 17;
    for (std::size_t at = 0; at < original.size(); at += 4096) {
        Bytes block(original.begin() + at, original.begin() + at + 4096);
        if (ParseNxSuperblock(block)) { vi::Put(block, 0x28, source.block_count); vi::Checksum(block); }
        if (std::any_of(block.begin(), block.end(), [](auto b) { return b != std::byte{}; })) source.blocks[at / 4096] = std::move(block);
    }
    const auto allocated = old.spaceman.devices[0].block_count - old.spaceman.devices[0].free_count;
    auto sm = old.spaceman.bytes; vi::Put(sm, 0x30, source.block_count); vi::Put(sm, 0x38, 4); vi::Put(sm, 0x48, source.block_count - allocated);
    vi::Checksum(sm); source.blocks[old.spaceman.object.physical_block] = std::move(sm);
    auto cib = old.spaceman.devices[0].cibs.front().bytes; vi::Put(cib, 0x24, 4, 4);
    std::fill(cib.begin() + 0x28, cib.end(), std::byte{});
    for (unsigned i = 0; i < 4; ++i) {
        const auto start = i * mc::ChunkBlocks, length = (std::min)(mc::ChunkBlocks, source.block_count - start);
        const auto at = 0x28 + i * 0x20; vi::Put(cib, at, old.container.superblock.xid); vi::Put(cib, at + 8, start);
        vi::Put(cib, at + 16, length, 4); vi::Put(cib, at + 20, length - (i == 0 ? allocated : 0), 4);
        vi::Put(cib, at + 24, i == 0 ? old.spaceman.chunks.front().bitmap_block : 0);
    }
    vi::Checksum(cib); source.blocks[old.spaceman.devices[0].cibs.front().object.physical_block] = std::move(cib);
    mc::Verify(source, mc::Load(source)); return source;
}
VolumeImageRequest Large(const std::string& name)
{
    const auto dir = root / name; std::filesystem::create_directories(dir);
    const auto source = Source(); auto request = Request(dir, VolumeImageOperation::Format, Fixture());
    request.expected_bytes = request.target_bytes = source.SizeBytes(); mc::SparseFile(request.image, source); return request;
}
std::vector<fe::Digest> Digests(const std::filesystem::path& image) { Target target(image); return fe::Scan(target).digests; }
void Change(const VolumeImageRequest& r, std::uint64_t block, const std::function<void(Bytes&)>& change)
{
    Target target(r.image); Bytes bytes; Check(target.Read(block * 4096, 4096, bytes), "fault read"); change(bytes);
    Check(target.WriteBlock(block, bytes) && target.Flush(), "fault write and flush");
}
void Codec()
{
    const auto source = Source(); auto evidence = fe::Scan(source); fe::Capture capture(source, evidence); Bytes bytes;
    Check(capture.Read(0, 4096, bytes), "capture anchor"); fe::Snapshot saved(evidence);
    Check(!saved.Read(fe::Chunk, 4096, bytes) && bytes.empty(), "missing original is unknown, never zero");
    const auto encoded = fe::Encode(evidence); const auto decoded = fe::Decode(encoded, source.SizeBytes());
    Check(decoded.digests == evidence.digests && decoded.chunks == evidence.chunks, "exact bounded evidence round trip");
    auto bad = encoded; bad.back() ^= std::byte{1}; bool refused = false;
    try { (void)fe::Decode(bad, source.SizeBytes()); } catch (...) { refused = true; }
    Check(refused, "stored chunk hash mismatch refuses");
    Pass("bounded original codec and missing-chunk refusal");
}
void PositiveLarge()
{
    auto r = Large("positive"); const auto before = Digests(r.image); const auto p = Prepare(r);
    Check(p.outcome == VolumeImageOutcome::Prepared, "large prepare: " + p.error);
    Check(Digests(r.image) == before, "all original bytes unchanged by prepare");
    const auto frame = Read(p.journal); Check(ReadU64LE(frame, 0) == fe::FlaggedStreamedMagic &&
        ReadU64LE(frame, 48) == static_cast<std::uint64_t>(r.operation) && frame.size() < 24 * 1024 * 1024,
        "explicit flagged Format frame with exact operation and bounded original evidence");
    Check(!InspectVolumeKeeperImage(r.image, 0, r.journal_directory).admitted, "prepared evidence fences ordinary source");
    const auto committed = Apply(r, p.token); Check(committed.outcome == VolumeImageOutcome::Committed, "large commit: " + committed.error);
    Check(Recover(r).outcome == VolumeImageOutcome::Committed, "idempotent large recovery");
    Check(InspectVolumeKeeperImage(r.image, 0, r.journal_directory).admitted, "completed VIF2 recognized by ordinary admission");
    {
        Target target(r.image); const auto cp = mc::Load(target); mc::Verify(target, cp);
        Check(cp.container.superblock.uuid_hex == r.new_container_uuid && cp.volumes.size() == 1 &&
            cp.volumes.front().superblock.name_utf8 == r.name_utf8, "actual new canonical identity/name");
        auto history = AcquireVolumeKeeperHistory(p.source_identity, target, r.journal_directory, {});
        Check(history->CheckpointXid() == p.post_xid && history->Members().size() == 3, "source history includes old siblings and new volume");
        mc::NativeWrite(target); history.reset();
    }
    Check(Recover(r).outcome == VolumeImageOutcome::Committed, "completed history permits subsequent native transaction and reopen");
    {
        Target target(r.image); const auto cp = mc::Load(target);
        auto history = AcquireVolumeKeeperHistory(p.source_identity, target, r.journal_directory, {});
        Check(history->CheckpointXid() == cp.container.superblock.xid && cp.container.superblock.xid > p.post_xid,
            "fresh source history after ordinary native write");
    }
    // Reformat again to exercise archived VIF2 history and a new CLEAN census.
    { Target target(r.image); const auto cp = mc::Load(target); r.container_uuid = cp.container.superblock.uuid_hex;
      r.volume_uuid = cp.volumes.front().superblock.uuid_hex; r.volume_oid = 1024; r.checkpoint_xid = cp.container.superblock.xid; }
    r.sibling_wals = {{1024, r.new_volume_wal}}; r.new_container_uuid = std::string(32, 'a'); r.new_volume_uuid = std::string(32, 'b');
    r.new_volume_wal = r.journal_directory / "second.wal";
    const auto second = Prepare(r); Check(second.outcome == VolumeImageOutcome::Prepared, "second large prepare: " + second.error);
    Check(Apply(r, second.token).outcome == VolumeImageOutcome::Committed, "second actual large publication");
    Check(Recover(r).outcome == VolumeImageOutcome::Committed, "mixed completed history exact reopen");
    Pass("actual large prepare apply ordinary write reopen and sequential format");
}
void Unaccepted()
{
    for (unsigned variant = 0; variant < 5; ++variant) {
        auto r = Large("unaccepted-" + std::to_string(variant)); const auto before = Digests(r.image); const auto p = Prepare(r);
        Check(p.outcome == VolumeImageOutcome::Prepared, p.error);
        if (variant == 0) Check(Cancel(r, p.token).outcome == VolumeImageOutcome::Cancelled, "large cancel");
        if (variant == 1) Check(Apply(r, "wrong").error == "VolumeImageConfirmationMismatch", "wrong token");
        if (variant == 2) {
            Change(r, 30000, [](auto& bytes) { bytes[51] ^= std::byte{1}; }); const auto changed = Digests(r.image);
            Check(Apply(r, p.token).error == "VolumeImageStaleSource" && Digests(r.image) == changed, "uncaptured stale chunk refuses unchanged");
        }
        if (variant == 3) {
            Save(r.sibling_wals.at(201), {std::byte{1}});
            Check(Apply(r, p.token).outcome == VolumeImageOutcome::Refused, "stale WAL refuses");
        }
        if (variant == 4) Check(Apply(r, p.token, [](auto stage) { return stage != "before-image-accept"; }).outcome ==
            VolumeImageOutcome::Cancelled, "before-accept cancellation");
        if (variant != 2) Check(Digests(r.image) == before, "unaccepted refusal/cancel target unchanged");
    }
    auto r = Large("scope-refusals"); const auto before = Digests(r.image);
    for (const auto op : {VolumeImageOperation::Grow, VolumeImageOperation::Shrink}) {
        auto request = r; request.operation = op;
        Check(Prepare(request).outcome == VolumeImageOutcome::Refused, "resize with Format options refuses");
    }
    Check(PrepareVolumeResize(r).error == "VolumeImageEntrypointMismatch" && Digests(r.image) == before, "old entrypoint guard preserved");
    Pass("large cancel stale source WAL and operation scope refusals");
}
void ProductionHistory()
{
    auto r = Large("production"); r.history_context = {r.journal_directory / "spool", r.journal_directory / "recovery"};
    std::filesystem::create_directories(r.history_context.spool_root); std::filesystem::create_directories(r.history_context.recovery_root);
    const auto wal = [&](const std::string& container, std::uint64_t oid) {
        const auto id = DerivePartitionlessVolumeRecoveryIdentity(container, oid).substr(17);
        const auto path = r.history_context.spool_root / ("apfs_recovery_v1_" + id) / "write-ahead.wal";
        std::filesystem::create_directories(path.parent_path()); return path;
    };
    for (auto& [oid, path] : r.sibling_wals) {
        path = wal(r.container_uuid, oid);
        Check(!std::filesystem::exists(path), "fresh current-source WAL fixture"); Save(path, {});
        const auto id = DerivePartitionlessVolumeRecoveryIdentity(r.container_uuid, oid).substr(17);
        const auto text = "dirty=0\nlastCommitXid=" + std::to_string(r.checkpoint_xid) + "\n";
        Save(r.history_context.recovery_root / ("apfs_recovery_v1_" + id + "_Native.state"),
            Bytes(reinterpret_cast<const std::byte*>(text.data()), reinterpret_cast<const std::byte*>(text.data() + text.size())));
    }
    r.new_volume_wal = wal(r.new_container_uuid, 1024);
    const auto p = Prepare(r); Check(p.outcome == VolumeImageOutcome::Prepared, "production prepare: " + p.error);
    const auto done = Apply(r, p.token); Check(done.outcome == VolumeImageOutcome::Committed, "production apply: " + done.error);
    bool admitted = false; const auto observation = ObserveVolumeKeeperHistoryJson(r.image, r.journal_directory, r.history_context, admitted);
    Check(admitted, "source-based production history observation: " + observation);
    const auto binding = DecodeVolumeKeeperHistoryBinding(Read(p.journal), p.journal, r.journal_directory, p.source_identity);
    const auto bad = r.journal_directory / (p.journal.filename().string() + "." + std::string(64, 'a') + ".completed");
    Save(bad, {std::byte{1}});
    Check(!InspectVolumeKeeperImage(r.image, 0, r.journal_directory).admitted, "malformed same-source archive cannot be ignored");
    bool refused = false;
    try { Target target(r.image); (void)AcquireVolumeKeeperHistory(p.source_identity, target, r.journal_directory, {}, {}, {}, {}, r.history_context); }
    catch (...) { refused = true; }
    Check(refused && binding.after.size() == 1, "source history refuses malformed original archive");
    Pass("production CLEAN markers source observation and malformed history refusal");
}
void Cuts()
{
    const std::vector<std::string> stages = {"after-image-accept", "before-apple-device-write", "before-apple-prepublication-flush",
        "before-apple-checkpoint-switch", "before-apple-final-flush", "before-image-anchor", "after-image-anchor", "before-image-complete"};
    for (std::size_t i = 0; i < stages.size(); ++i) {
        auto r = Large("cut-" + std::to_string(i)); const auto p = Prepare(r); Check(p.outcome == VolumeImageOutcome::Prepared, p.error);
        bool hit = false;
        const auto result = Apply(r, p.token, [&](auto stage) {
            if (stage == stages[i]) { hit = true; return false; } return true;
        });
        Check(hit && result.outcome == VolumeImageOutcome::RecoveryRequired, "real accepted cut: " + result.error);
        const auto done = Recover(r); Check(done.outcome == VolumeImageOutcome::Committed, "fresh replay: " + done.error);
        { Target target(r.image); const auto cp = mc::Load(target); mc::Verify(target, cp);
          Check(cp.container.superblock.xid == p.post_xid && cp.container.superblock.uuid_hex == r.new_container_uuid, "cut exact post-generation"); }
        Check(Recover(r).outcome == VolumeImageOutcome::Committed, "cut idempotence");
    }
    Pass("actual streamed publication cuts and fresh held-source recovery");
}
void ConflictsAndTails()
{
    for (unsigned variant = 0; variant < 9; ++variant) {
        auto r = Large("conflict-" + std::to_string(variant)); const auto p = Prepare(r); Check(p.outcome == VolumeImageOutcome::Prepared, p.error);
        const auto original = Source(); auto planned = vi::BuildFormatPublicationV2(original, r, mc::Load(original));
        vi::FinishFormatSource(original, r, planned);
        Check(Apply(r, p.token, [](auto stage) { return stage != "after-image-accept"; }).outcome == VolumeImageOutcome::RecoveryRequired,
            "accepted original fixture");
        if (variant == 0) Change(r, planned.publication.superblock_write.physical_block, [](auto& bytes) { std::fill_n(bytes.begin() + 99, 700, std::byte{0xa7}); });
        if (variant == 1) Change(r, 30000, [](auto& bytes) { bytes[31] ^= std::byte{1}; });
        if (variant == 2) Change(r, 0, [](auto& bytes) { vi::Put(bytes, 0x10, 900); vi::Checksum(bytes); });
        if (variant == 3) { auto receipt = Read(p.journal); receipt.resize(receipt.size() - 9); Save(p.journal, receipt); }
        if (variant == 4) {
            const auto binding = DecodeVolumeKeeperHistoryBinding(Read(p.journal), p.journal, r.journal_directory, p.source_identity);
            std::filesystem::rename(r.journal_directory / ("wal-history-" + binding.frame_digest + ".vkh1"),
                r.journal_directory / "missing-proof.private");
        }
        if (variant == 5) {
            // A legal partial next receipt must be truncated to its complete prefix.
            auto receipt = Read(p.journal); const auto digest = std::span(receipt).subspan(16, 32); Bytes body(digest.begin(), digest.end());
            fe::Number(body, 2); const auto hash = fe::Hash(body); Bytes tail; fe::Number(tail, 2); tail.insert(tail.end(), hash.begin(), hash.begin() + 11);
            receipt.insert(receipt.end(), tail.begin(), tail.end()); Save(p.journal, receipt);
        }
        if (variant == 6) {
            Target target(r.image); Check(planned.publication.before_superblock_writes.size() > 3, "partial staging fixture");
            for (std::size_t i = 0; i < 3; ++i) {
                const auto& write = planned.publication.before_superblock_writes[i];
                Check(target.WriteBlock(write.physical_block, write.bytes), "actual partial planned blocks");
            }
            Check(target.Flush(), "actual partial staging flush");
        }
        if (variant == 7) std::filesystem::resize_file(r.image, r.expected_bytes - 4096);
        if (variant == 8) Change(r, planned.publication.superblock_write.physical_block, [&](auto& bytes) {
            bytes = planned.publication.superblock_write.bytes; vi::Put(bytes, 0x10, 901); vi::Checksum(bytes);
        });
        const auto before = Digests(r.image); const auto done = Recover(r);
        if (variant == 0 || variant == 5 || variant == 6) Check(done.outcome == VolumeImageOutcome::Committed, "torn destination/legal receipt replay: " + done.error);
        else if (variant == 3) Check(done.outcome == VolumeImageOutcome::Cancelled && Digests(r.image) == before,
            "incomplete acceptance never grants target authority");
        else Check(done.outcome == VolumeImageOutcome::RecoveryRequired && Digests(r.image) == before, "conflict/certificate refusal writes nothing: " + done.error);
    }
    Pass("torn destination receipt acceptance boundary unrelated bytes foreign NX and missing original certificate");
}
void LaterCanonical()
{
    auto r = Large("later-canonical"); const auto p = Prepare(r); Check(p.outcome == VolumeImageOutcome::Prepared, p.error);
    Check(Apply(r, p.token, [](auto stage) { return stage != "after-image-accept"; }).outcome == VolumeImageOutcome::RecoveryRequired,
        "accepted exact original");
    const auto original = Source(); auto plan = vi::BuildFormatPublicationV2(original, r, mc::Load(original));
    vi::FinishFormatSource(original, r, plan);
    {
        Target target(r.image); std::string error;
        Check(ExecuteAppleCheckpointPublication(target, plan.publication, error) && target.WriteBlock(0, plan.anchor) && target.Flush(),
            "actual post-generation before missing receipt");
        const auto cp = mc::Load(target); AppleCheckpointPublicationRequest request;
        request.expected_checkpoint_xid = cp.container.superblock.xid; request.transaction_xid = cp.container.superblock.next_xid;
        request.next_object_id = cp.container.superblock.next_oid;
        for (const auto& mapping : cp.container.mappings) {
            AppleCheckpointEphemeralObject object; object.file_system_oid = mapping.file_system_oid;
            object.object = {mapping.object_id, request.transaction_xid, 0, mapping.type, mapping.subtype, mapping.size_bytes};
            Check(target.Read(mapping.physical_block * 4096, mapping.size_bytes, object.bytes), "native later mapped object");
            vi::Put(object.bytes, 0x10, request.transaction_xid); vi::Checksum(object.bytes);
            request.ephemeral_objects.push_back(std::move(object));
        }
        AppleCheckpointPublicationPlan later;
        Check(PlanAppleCheckpointPublication(target, cp.container, request, later, error), "native later plan: " + error);
        for (const auto& write : later.before_superblock_writes) Check(plan.destinations.contains(write.physical_block), "later generation only uses original planned destinations");
        Check(plan.destinations.contains(later.superblock_write.physical_block) && later.superblock_write.physical_block != plan.publication.superblock_write.physical_block,
            "later switch is a distinct planned ring block");
        Check(ExecuteAppleCheckpointPublication(target, later, error), "actual later publication: " + error);
        const auto after = mc::Load(target); mc::Verify(target, after);
        Check(after.container.superblock.xid == request.transaction_xid, "genuine complete later canonical checkpoint");
    }
    const auto before = Digests(r.image); const auto result = Recover(r);
    Check(result.outcome == VolumeImageOutcome::RecoveryRequired && Digests(r.image) == before,
        "later canonical checkpoint must refuse without rollback: " + result.error);
    Pass("later valid canonical generation within planned ring refuses without rollback");
}
int wmain(int argc, wchar_t** argv)
{
    try {
        Check(argc == 2 || (argc == 3 && std::wstring_view(argv[2]) == L"--canonical-only"), "private evidence directory");
        root = argv[1]; std::filesystem::create_directories(root);
        if (argc == 3) { LaterCanonical(); std::cout << "PASS groups=" << groups << " checks=" << checks << '\n'; return 0; }
        const auto source = Source(); mc::SparseFile(root / "original-large.apfs", source);
        const auto request = mc::RequestFor(source, mc::Load(source));
        const auto plan = vi::BuildFormatPublicationV2(source, request, mc::Load(source));
        mc::SparseFile(root / "expected-format.apfs", mc::Publish(source, plan));
        Codec(); PositiveLarge(); Unaccepted(); ProductionHistory(); Cuts(); ConflictsAndTails(); LaterCanonical();
        std::cout << "PASS groups=" << groups << " checks=" << checks << '\n'; return 0;
    } catch (const std::exception& ex) { std::cerr << "FAIL checks=" << checks << " " << ex.what() << '\n'; return 1; }
}
