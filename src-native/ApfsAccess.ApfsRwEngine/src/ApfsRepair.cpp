#include "ApfsRepair.h"
#include <bcrypt.h>

namespace apfsaccess::rw
{
namespace
{
using Store = MetadataStore;
using Owner = catalog::ContainerMountCoordinator;
using Result = catalog::ContainerCommitResult;
bool Hash(std::span<const std::byte> bytes, std::array<std::uint8_t, 32>& out);
std::string Hex(std::span<const std::uint8_t> bytes)
{
    std::string out;
    for (auto b : bytes) { out += "0123456789abcdef"[b >> 4]; out += "0123456789abcdef"[b & 15]; }
    return out;
}
std::string ImageIdentity(const BlockDevice& device)
{
    BlockDevice::StableImageIdentity id;
    if (!device.QueryHeldImageIdentity(id)) return {};
    return std::to_string(id.volume_serial) + ":" +
        Hex({reinterpret_cast<const std::uint8_t*>(id.file_id.data()), id.file_id.size()}) + ":" +
        std::to_string(id.size_bytes) + ":" + std::to_string(id.creation_time) + ":" +
        std::to_string(device.BaseOffsetBytes()) + ":" + std::to_string(device.GetGeometry().total_bytes);
}
class Source final : public catalog::RandomAccessSource
{
public:
    explicit Source(const BlockDevice& device) : device_(device) {}
    std::uint64_t SizeBytes() const override { return device_.GetGeometry().total_bytes; }
    bool Read(std::uint64_t offset, std::size_t size, std::vector<std::byte>& bytes) const override
    { return device_.Read(offset, size, bytes) && bytes.size() == size; }
private:
    const BlockDevice& device_;
};
bool Fail(std::string& error, const char* reason) { error = reason; return false; }
// The first image-only profile is deliberately bounded to 256 MiB. Bind all
// preacceptance bytes, including payload and unused regions, without I/O writes.
bool ImageHash(const catalog::RandomAccessSource& source, std::string& digest, std::string& error)
{
    if (!source.SizeBytes() || source.SizeBytes() > 256ull * 1024 * 1024)
        return Fail(error, "CountRepairImageSizeUnsupported");
    std::vector<std::byte> bytes; std::array<std::uint8_t, 32> hash{};
    if (!source.Read(0, static_cast<std::size_t>(source.SizeBytes()), bytes) || bytes.size() != source.SizeBytes() || !Hash(bytes, hash))
        return Fail(error, "CountRepairImageHashFailed");
    digest = Hex(hash); return true;
}
const catalog::AppleVolumeCheckpointView* Volume(const catalog::AppleCheckpointView& cp, std::uint64_t oid)
{
    const auto it = std::find_if(cp.volumes.begin(), cp.volumes.end(),
        [&](const auto& volume) { return volume.superblock.object_id == oid; });
    return it == cp.volumes.end() ? nullptr : &*it;
}
bool ReadSuperblock(const catalog::RandomAccessSource& source, const catalog::AppleCheckpointView& cp,
    const catalog::AppleVolumeCheckpointView& volume, std::vector<std::byte>& bytes)
{
    return source.Read(volume.superblock_object.physical_block * cp.container.superblock.block_size,
        cp.container.superblock.block_size, bytes);
}
bool ReadTree(const catalog::RandomAccessSource& source, const catalog::AppleCheckpointView& cp,
    const catalog::AppleVolumeCheckpointView& volume, const catalog::AppleObjectLocation& root,
    std::vector<catalog::BtreeRecord>& records, std::string& error)
{
    catalog::BtreeReadPolicy policy;
    policy.enforce_object_identity = true;
    policy.root_object_id = root.object_id;
    policy.storage_type = root.type;
    policy.subtype = root.subtype;
    const bool physical = (root.type & catalog::kObjectStorageTypeMask) == catalog::kObjectPhysical;
    return catalog::ReadBtreeLeafRecords(source, cp.container.superblock.block_size, root.physical_block,
        physical, physical ? 0 : volume.superblock.omap_oid, cp.container.superblock.xid, policy, records, error);
}
bool EqualRecords(std::vector<catalog::BtreeRecord> left, std::vector<catalog::BtreeRecord> right)
{
    const auto less = [](const auto& a, const auto& b) { return std::tie(a.key, a.value) < std::tie(b.key, b.value); };
    std::sort(left.begin(), left.end(), less); std::sort(right.begin(), right.end(), less);
    return left.size() == right.size() && std::equal(left.begin(), left.end(), right.begin(),
        [](const auto& a, const auto& b) { return a.key == b.key && a.value == b.value; });
}
bool SamePreservedSuperblock(std::vector<std::byte> before, std::vector<std::byte> after)
{
    if (before.size() != after.size() || before.size() < 0x3c0) return false;
    // Only canonical COW bookkeeping and the admitted regular-file count.
    for (const auto offset : {0u, 0x10u, 0x58u, 0x80u, 0xe0u, 0xe8u, 0xb8u})
    {
        std::fill_n(before.begin() + offset, 8, std::byte{});
        std::fill_n(after.begin() + offset, 8, std::byte{});
    }
    return before == after;
}
// Hash every byte read by the independent verifier, with exact read framing.
// This includes siblings, allocator and checkpoint ownership, not just inodes.
class Witness final : public catalog::RandomAccessSource
{
public:
    explicit Witness(const catalog::RandomAccessSource& s) : source(s) {}
    const catalog::RandomAccessSource& source;
    mutable std::vector<std::byte> transcript;
    std::uint64_t SizeBytes() const override { return source.SizeBytes(); }
    bool Read(std::uint64_t offset, std::size_t size, std::vector<std::byte>& bytes) const override
    {
        if (transcript.size() > 8u * 1024 * 1024 || !source.Read(offset, size, bytes) || bytes.size() != size) return false;
        std::array<std::uint8_t, 32> digest{};
        if (!Hash(bytes, digest)) return false;
        for (const auto n : {offset, std::uint64_t(size)})
            for (unsigned i = 0; i != 8; ++i) transcript.push_back(std::byte((n >> (8 * i)) & 255));
        for (auto b : digest) transcript.push_back(std::byte(b));
        return true;
    }
};
class StagedSource final : public catalog::RandomAccessSource
{
public:
    StagedSource(const catalog::RandomAccessSource& s, const AppleCheckpointPublicationPlan& p) : source(s), plan(p) {}
    const catalog::RandomAccessSource& source;
    const AppleCheckpointPublicationPlan& plan;
    std::uint64_t SizeBytes() const override { return source.SizeBytes(); }
    bool Read(std::uint64_t offset, std::size_t size, std::vector<std::byte>& bytes) const override
    {
        if (!source.Read(offset, size, bytes) || bytes.size() != size) return false;
        const auto overlay = [&](const AppleCheckpointPlannedWrite& write) {
            const auto at = write.physical_block * plan.block_size;
            const auto first = (std::max)(offset, at), last = (std::min)(offset + size, at + write.bytes.size());
            if (first < last) std::copy_n(write.bytes.begin() + (first - at), last - first, bytes.begin() + (first - offset));
        };
        for (const auto& write : plan.before_superblock_writes) overlay(write);
        overlay(plan.superblock_write); return true;
    }
};
bool Inspect(const catalog::RandomAccessSource& source, const catalog::AppleCheckpointView& cp,
    const catalog::AppleVolumeCheckpointView& volume, const std::string& identity,
    std::uint64_t& count, std::string& digest, std::string& error, std::string* source_witness = nullptr)
{
    Witness witness(source);
    catalog::VerificationScope scope;
    scope.source_identity = identity;
    scope.exact = {0, source.SizeBytes(), cp.container.superblock.uuid_hex, volume.superblock.uuid_hex,
        volume.superblock.object_id, cp.container.superblock.xid};
    const auto report = catalog::ApfsVerifier::Verify(witness, scope);
    if (report.outcome != catalog::VerificationOutcome::Complete || !report.findings.empty() || !report.allocation_census) {
        error = "CountRepairIndependentCurrentGraphNotVerified";
        if (!report.findings.empty()) error += ":" + report.findings.front().detail;
        return false;
    }
    std::vector<catalog::BtreeRecord> records;
    if (!ReadTree(witness, cp, volume, volume.root_tree, records, error)) return false;
    count = 0;
    for (const auto& record : records) {
        if ((catalog::ReadU64LE(record.key, 0).value_or(0) >> 60) != 3) continue;
        const auto mode = catalog::ReadU16LE(record.value, 80);
        if (!mode) return Fail(error, "CountRepairInodeModeMissing");
        if ((*mode & 0170000) == 0100000) ++count;
    }
    std::array<std::uint8_t, 32> hash{};
    if (!Hash(witness.transcript, hash)) return Fail(error, "CountRepairEvidenceHashFailed");
    if (source_witness) *source_witness = Hex(hash);
    std::vector<std::byte> framed;
    // Preserve actual selected and sibling content, including external xattr
    // streams. These independently validated payload ranges are never written
    // by this profile; their digest remains checkable after partial COW/restart.
    std::uint64_t payload_bytes = 0;
    for (const auto& peer : cp.volumes) {
        std::vector<catalog::BtreeRecord> fs, refs;
        std::vector<ApplePhysicalExtentRecord> extents;
        if (!peer.extentref_tree || !ReadTree(source, cp, peer, peer.root_tree, fs, error) ||
            !ReadTree(source, cp, peer, *peer.extentref_tree, refs, error) ||
            !ValidateApplePayloadExtentGraph(fs, refs, cp.container.superblock.block_size,
                cp.container.superblock.block_count, extents, error)) return false;
        // The durable proof must bind inline sibling data and metadata too.
        // APSB equality alone cannot detect a valid in-place change in a
        // retained FS leaf. Frame each complete validated tree independently.
        std::uint64_t tree_kind = 0;
        for (const auto* tree : {&fs, &refs}) {
            std::vector<std::byte> record_frame;
            for (const auto& record : *tree) for (const auto* bytes : {&record.key, &record.value}) {
                for (unsigned i = 0; i != 8; ++i)
                    record_frame.push_back(std::byte((std::uint64_t(bytes->size()) >> (8 * i)) & 255));
                record_frame.insert(record_frame.end(), bytes->begin(), bytes->end());
            }
            if (!Hash(record_frame, hash)) return Fail(error, "CountRepairVolumeRecordsHashFailed");
            for (const auto n : {peer.superblock.object_id, tree_kind++, std::uint64_t(tree->size())})
                for (unsigned i = 0; i != 8; ++i) framed.push_back(std::byte((n >> (8 * i)) & 255));
            for (auto b : hash) framed.push_back(std::byte(b));
        }
        for (const auto& extent : extents) {
            const auto size = extent.block_count * cp.container.superblock.block_size;
            if (size > 256ull * 1024 * 1024 - payload_bytes) return Fail(error, "CountRepairPayloadBudgetExceeded");
            payload_bytes += size;
            std::vector<std::byte> payload;
            if (!source.Read(extent.physical_block * cp.container.superblock.block_size, static_cast<std::size_t>(size), payload) ||
                payload.size() != size || !Hash(payload, hash)) return Fail(error, "CountRepairPayloadReadFailed");
            for (const auto n : {peer.superblock.object_id, extent.physical_block, size})
                for (unsigned i = 0; i != 8; ++i) framed.push_back(std::byte((n >> (8 * i)) & 255));
            for (auto b : hash) framed.push_back(std::byte(b));
        }
    }
    if (!Hash(framed, hash)) return Fail(error, "CountRepairGraphHashFailed");
    digest = Hex(hash); return true;
}
bool ValidatePreimage(const catalog::RandomAccessSource& source, const catalog::AppleCheckpointView& cp,
    const NativeCountRepair& rename, std::string& error)
{
    const auto* volume = Volume(cp, rename.volume);
    if (source.SizeBytes() > 256ull * 1024 * 1024) return Fail(error, "CountRepairImageSizeUnsupported");
    NativeCountRepair checked;
    if (!DecodeNativeCountRepair(EncodeNativeCountRepair(rename), checked) || !volume ||
        cp.container.superblock.uuid_hex != rename.container_uuid || cp.container.superblock.xid != rename.checkpoint ||
        volume->superblock.uuid_hex != rename.volume_uuid)
        return Fail(error, "CountRepairStaleIdentityOrCheckpoint");
    if (!CheckAppleVolumeWriteFeatures(cp.container.superblock, volume->superblock, error)) return false;
    // Preserve this admission even when the independent snapshot writer lands.
    if (catalog::ReadU64LE(rename.superblock, 0xd8).value_or(UINT64_MAX) != 0 ||
        volume->object_map.snapshot_tree_oid || cp.container_object_map.snapshot_tree_oid)
        return Fail(error, "CountRepairSnapshotsUnsupported");
    if (volume->snapshot_metadata_tree)
    {
        std::vector<catalog::BtreeRecord> records;
        if (!ReadTree(source, cp, *volume, *volume->snapshot_metadata_tree, records, error) || !records.empty())
            return Fail(error, "CountRepairSnapshotsUnsupported");
    }
    std::vector<std::byte> bytes;
    if (!ReadSuperblock(source, cp, *volume, bytes) || bytes != rename.superblock)
        return Fail(error, "CountRepairSuperblockPreimageChanged");
    std::uint64_t count = 0; std::string digest;
    if (!Inspect(source, cp, *volume, rename.source_identity, count, digest, error)) return false;
    if (count != rename.expected_count || digest != rename.graph_sha256)
        return Fail(error, "CountRepairIndependentEvidenceChanged");
    return true;
}
bool Hash(std::span<const std::byte> bytes, std::array<std::uint8_t, 32>& out)
{
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) return false;
    const auto status = BCryptHash(algorithm, nullptr, 0,
        reinterpret_cast<PUCHAR>(const_cast<std::byte*>(bytes.data())), static_cast<ULONG>(bytes.size()), out.data(), 32);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return status >= 0;
}
bool Finalize(Owner& owner, TransactionManager& journal, std::uint64_t oid, std::uint64_t sequence, std::string& error)
{
    if (!sequence || !journal.MarkApfsDurableThrough(sequence) || !journal.MarkCleanedThrough(sequence))
        return Fail(error, "CountRepairJournalFinalizationFailed");
    std::vector<std::uint64_t> pins;
    return journal.LoadRequiredCheckpointXidsSinceCleanup(pins, &error) &&
        owner.UpdateRequiredCheckpointXids(oid, pins, error, journal.HasUnappliedAcceptedWork());
}
}

bool ValidateCountRepairMutation(const Store& store, const Store::MutationRequest& request, std::string& error)
{
    error.clear();
    NativeCountRepair rename;
    const auto* cp = store.AuthoritativeAppleCheckpointView();
    if (request.operation != Store::MutationOperation::RepairVolumeFileCount || !store.IsNativeWriteReady() ||
        store.IsRecoveryRequired() || !cp || request.path != L"\\" || !request.secondary_path.empty() ||
        request.offset || request.timestamp_utc || request.replace_if_exists || request.expected_unlink_outcome ||
        request.length != request.inline_payload.size() || !DecodeNativeCountRepair(request.inline_payload, rename) ||
        request.object_id != rename.volume || request.generation != rename.checkpoint + 1 ||
        store.Context().volume_object_id != rename.volume || store.Context().container_uuid_hex != rename.container_uuid ||
        store.Context().volume_uuid_hex != rename.volume_uuid || ImageIdentity(store.Device()) != rename.source_identity)
        return Fail(error, "CountRepairRequestInvalid");
    return ValidatePreimage(Source(store.Device()), *cp, rename, error);
}

bool PrepareApfsCountRepair(Owner& owner, std::uint64_t oid, ApfsCountRepairPlan& out, std::string& error,
    std::chrono::milliseconds lifetime)
{
    error.clear();
    if (out.owner_ || out.consumed_) return Fail(error, "CountRepairPlanAlreadyPrepared");
    if (lifetime <= std::chrono::milliseconds(0) || lifetime > std::chrono::minutes(5))
        return Fail(error, "CountRepairExpiryInvalid");
    return owner.InspectCurrentSession(oid, [&](const Store& live, std::string& error) {
    const auto* store = &live;
    if (!store->Device().IsRegularFile()) return Fail(error, "CountRepairOrdinaryImageRequired");
    if (!ImageHash(Source(store->Device()), out.image_preimage_, error)) return false;
    const auto* cp = store->AuthoritativeAppleCheckpointView();
    const auto* volume = cp ? Volume(*cp, oid) : nullptr;
    if (!volume) return Fail(error, "CountRepairVolumeMissing");
    NativeCountRepair rename;
    rename.checkpoint = cp->container.superblock.xid; rename.volume = oid;
    rename.container_uuid = cp->container.superblock.uuid_hex; rename.volume_uuid = volume->superblock.uuid_hex;
    rename.source_identity = ImageIdentity(store->Device());
    if (rename.source_identity.empty() || !Inspect(Source(store->Device()), *cp, *volume, rename.source_identity,
        rename.expected_count, rename.graph_sha256, error, &out.source_witness_)) return false;
    if (rename.expected_count == volume->superblock.file_count) return Fail(error, "CountRepairNoFinding");
    if (!ReadSuperblock(Source(store->Device()), *cp, *volume, rename.superblock)) return Fail(error, "CountRepairReadFailed");
    Store::MutationRequest request;
    request.operation = Store::MutationOperation::RepairVolumeFileCount; request.path = L"\\";
    request.object_id = oid; request.generation = rename.checkpoint + 1;
    request.inline_payload = EncodeNativeCountRepair(rename); request.length = request.inline_payload.size();
    if (!ValidateCountRepairMutation(*store, request, error)) return false;
    std::array<std::uint8_t, 32> token{};
    if (BCryptGenRandom(nullptr, token.data(), token.size(), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
        return Fail(error, "CountRepairConfirmationUnavailable");
    out.request_ = std::move(request); out.owner_ = &owner; out.evidence_ = std::move(rename);
    out.token_ = Hex(token);
    out.finding_ = {catalog::VerificationCode::VolumeFileCountInconsistent, catalog::VerificationSeverity::Error,
        catalog::VerificationCheck::NamespaceLinksAndStreams, oid, volume->superblock.object_id,
        volume->superblock_object.physical_block, cp->container.superblock.xid, std::nullopt,
        "APSB regular-file count differs from complete independently validated inode graph"};
    out.lifetime_ = owner.LifetimeToken();
    out.expires_ = std::chrono::steady_clock::now() + lifetime;
    return true;
    }, error);
}

bool PlanCountRepairCheckpoint(const catalog::RandomAccessSource& source, const catalog::AppleCheckpointView& cp,
    const NativeCountRepair& rename, const std::vector<std::uint64_t>& pins,
    AppleVolumeTransactionPlan& out, std::string& error)
{
    out = {}; error.clear();
    if (!ValidatePreimage(source, cp, rename, error)) return false;
    const auto& volume = *Volume(cp, rename.volume);
    AppleVolumeTransactionRequest request;
    request.volume_object_id = rename.volume; request.required_checkpoint_xids = pins;
    request.preserve_source_metadata = true;
    if (!ReadTree(source, cp, volume, volume.root_tree, request.filesystem_records, error)) return false;
    AppleVolumeTransactionPlan planned;
    if (!PlanAppleVolumeTransaction(source, cp, request, planned, error)) return false;
    if (!planned.payload_blocks.empty() || !EqualRecords(request.filesystem_records, planned.filesystem_records))
        return Fail(error, "CountRepairUnexpectedPayloadMutation");
    unsigned changed = 0;
    for (auto& write : planned.commit.publication.before_superblock_writes)
    {
        const auto apsb = catalog::ParseApsb(write.bytes);
        if (!apsb || apsb->object_id != rename.volume) continue;
        if (++changed != 1 || apsb->uuid_hex != rename.volume_uuid ||
            !SamePreservedSuperblock(rename.superblock, write.bytes))
            return Fail(error, "CountRepairUnexpectedMetadataMutation");
        for (unsigned i = 0; i != 8; ++i)
            write.bytes[0xb8 + i] = std::byte((rename.expected_count >> (8 * i)) & 255);
        if (!FinalizeAppleObjectChecksum(write.bytes, error)) return false;
        const auto renamed = catalog::ParseApsb(write.bytes);
        if (!renamed || renamed->file_count != rename.expected_count)
            return Fail(error, "CountRepairCounterRoundTripFailed");
    }
    if (changed != 1) return Fail(error, "CountRepairPublicationSuperblockMissing");
    StagedSource staged(source, planned.commit.publication);
    const auto next = catalog::LoadAppleCheckpointView(staged, 0, staged.SizeBytes(), error,
        planned.commit.publication.transaction_xid);
    std::uint64_t reconstructed = 0; std::string digest;
    const auto* next_volume = next ? Volume(*next, rename.volume) : nullptr;
    if (!next_volume || next_volume->superblock.file_count != rename.expected_count ||
        !Inspect(staged, *next, *next_volume, rename.source_identity, reconstructed, digest, error) ||
        reconstructed != rename.expected_count || digest != rename.graph_sha256)
        return Fail(error, "CountRepairStagedCurrentSubsetNotVerified");
    out = std::move(planned);
    return true;
}

bool CountRepairFromWal(const WriteAheadLog::Record& record, Store::MutationRequest& out)
{
    if (record.operation != WriteAheadLog::OperationKind::RepairVolumeFileCount || !WriteAheadLog::CountRepairIsConsistent(record)) return false;
    Store::MutationRequest request;
    request.operation = Store::MutationOperation::RepairVolumeFileCount; request.path = L"\\";
    request.object_id = record.object_id; request.generation = record.parent_object_id;
    request.inline_payload = record.inline_payload; request.length = request.inline_payload.size();
    out = std::move(request); return true;
}

bool VerifyPublishedCountRepair(const Store& store, const NativeCountRepair& rename, std::string& error)
{
    error.clear();
    const auto* current = store.AuthoritativeAppleCheckpointView();
    if (!current || store.PendingMutationCount() || current->container.superblock.xid <= rename.checkpoint ||
        store.Context().volume_object_id != rename.volume || current->container.superblock.uuid_hex != rename.container_uuid)
        return Fail(error, "CountRepairPublicationNotObserved");
    Source source(store.Device());
    AppleVolumeReplayBoundary boundary;
    if (!FindAppleVolumeReplayBoundary(source, *current, rename.volume, rename.checkpoint, boundary, error) ||
        !boundary.first_changed_checkpoint_xid) return Fail(error, "CountRepairPublicationBoundaryMissing");
    // The retention API returns the complete continuity chain, including all
    // intermediate checkpoints. Select proof endpoints by XID, not count or
    // vector order, so later selected-volume and sibling commits remain valid.
    std::vector<AppleRecoveryCheckpointView> history;
    if (!LoadAppleRecoveryCheckpoints(source, *current, {rename.checkpoint}, history, error)) return false;
    const auto retained = [&](std::uint64_t xid) -> const catalog::AppleCheckpointView* {
        if (current->container.superblock.xid == xid) return current;
        const auto it = std::find_if(history.begin(), history.end(), [&](const auto& entry) {
            return entry.checkpoint.container.superblock.xid == xid;
        });
        return it == history.end() ? nullptr : &it->checkpoint;
    };
    const auto* preimage = retained(rename.checkpoint);
    if (!preimage) return Fail(error, "CountRepairPublicationPreimageMissing");
    const auto& before = *preimage;
    if (*boundary.first_changed_checkpoint_xid != before.container.superblock.next_xid ||
        !ValidatePreimage(source, before, rename, error)) return Fail(error, "CountRepairPublicationPreimageMismatch");
    const auto* after = retained(*boundary.first_changed_checkpoint_xid);
    if (!after) return Fail(error, "CountRepairPublicationCheckpointMissing");
    if (before.volumes.size() != after->volumes.size()) return Fail(error, "CountRepairSiblingSetChanged");
    for (const auto& old_volume : before.volumes)
    {
        const auto* new_volume = Volume(*after, old_volume.superblock.object_id);
        std::vector<std::byte> a, b;
        if (!new_volume || !ReadSuperblock(source, before, old_volume, a) || !ReadSuperblock(source, *after, *new_volume, b)) return false;
        if (old_volume.superblock.object_id != rename.volume)
        {
            if (a != b) return Fail(error, "CountRepairSiblingChanged");
            continue;
        }
        if (a != rename.superblock || !SamePreservedSuperblock(a, b) ||
            new_volume->superblock.file_count != rename.expected_count || new_volume->superblock.uuid_hex != rename.volume_uuid)
            return Fail(error, "CountRepairPublishedMetadataMismatch");
        const std::optional<catalog::AppleObjectLocation> old_roots[] = {old_volume.root_tree, old_volume.extentref_tree,
            old_volume.snapshot_metadata_tree, old_volume.file_extent_tree};
        const std::optional<catalog::AppleObjectLocation> new_roots[] = {new_volume->root_tree, new_volume->extentref_tree,
            new_volume->snapshot_metadata_tree, new_volume->file_extent_tree};
        for (unsigned i = 0; i != 4; ++i)
        {
            if (old_roots[i].has_value() != new_roots[i].has_value()) return Fail(error, "CountRepairTreeSetChanged");
            if (!old_roots[i]) continue;
            std::vector<catalog::BtreeRecord> left, right;
            if (!ReadTree(source, before, old_volume, *old_roots[i], left, error) ||
                !ReadTree(source, *after, *new_volume, *new_roots[i], right, error) || !EqualRecords(left, right))
                return Fail(error, "CountRepairTreeRecordsChanged");
        }
    }
    std::uint64_t count = 0; std::string digest;
    return Inspect(source, *after, *Volume(*after, rename.volume), rename.source_identity, count, digest, error) &&
        count == rename.expected_count && digest == rename.graph_sha256;
}

bool VerifyCompletedApfsCountRepair(Owner& owner, TransactionManager& journal, const std::wstring& journal_path,
    const catalog::ApfsSnapshotScope& original, std::uint64_t expected_count,
    std::span<const std::byte> approved_preimage, std::string_view approved_sha256, std::string& error)
{
    error.clear();
    const auto observation = owner.Device().CaptureExclusiveWriteSourceObservation();
    if (!owner.Device().IsRegularFile() || !observation || !owner.CheckpointCensusRequired() || owner.IsRecoveryRequired() ||
        original.store_offset_bytes || !original.store_size_bytes || original.store_size_bytes > 256ull * 1024 * 1024 ||
        owner.Device().BaseOffsetBytes() || owner.Device().GetGeometry().total_bytes != original.store_size_bytes ||
        approved_preimage.size() != original.store_size_bytes || !original.checkpoint_xid ||
        owner.CheckpointXid() <= original.checkpoint_xid || owner.ContainerUuidHex() != original.container_uuid_hex)
        return Fail(error, "CountRepairCompletedScopeInvalid");
    const auto identity = "apfs-vol:" + original.container_uuid_hex + ":" + std::to_string(original.volume_oid);
    const std::wstring wide_identity(identity.begin(), identity.end());
    const auto generation = journal.ObservedJournalWriterLeaseGeneration();
    const auto sequence = journal.Watermarks().accepted_sequence;
    const auto owned = [&] {
        const auto marks = journal.Watermarks();
        return generation && journal.OwnsJournalForMaintenance(journal_path, wide_identity) &&
            journal.ObservedJournalWriterLeaseGeneration() == generation &&
            journal.ObservedJournalAppendLeaseGeneration() == generation && journal.RecoveryStateValid() &&
            journal.CurrentState() == TransactionManager::State::Idle && !journal.PendingMutationCount() &&
            !journal.HasUnappliedAcceptedWork() && sequence && marks.accepted_sequence == sequence &&
            marks.apfs_durable_sequence == sequence && marks.cleanup_sequence == sequence;
    };
    if (!owned()) return Fail(error, "CountRepairCompletedOriginalJournalNotOwned");
    // Keep the reader as well as the real writer lease throughout the proof.
    // Existing WAL decoding supplies framing/checksum/semantic authority.
    struct Reader {
        HANDLE handle;
        ~Reader() { if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle); }
    } reader{CreateFileW(journal_path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
    if (reader.handle == INVALID_HANDLE_VALUE) return Fail(error, "CountRepairCompletedOriginalJournalUnreadable");
    const auto history = WriteAheadLog::ReadAllEvidenceFromHeldHandle(reader.handle, identity,
        {8ull * 1024 * 1024, 65536}, 256ull * 1024 * 1024);
    if (history.status != WriteAheadLog::ReadStatus::Ok || history.recovered_torn_tail || !owned() || history.records.size() != 4)
        return Fail(error, "CountRepairCompletedOriginalReceiptMissing");
    const auto& mutation = history.records[0];
    const auto& accepted = history.records[1];
    const auto& durable = history.records[2];
    const auto& cleaned = history.records[3];
    Store::MutationRequest request; NativeCountRepair repair;
    if (!CountRepairFromWal(mutation, request) || !DecodeNativeCountRepair(request.inline_payload, repair) ||
        mutation.state != WriteAheadLog::RecordState::Prepared || !mutation.transaction_id || !mutation.sequence ||
        accepted.operation != WriteAheadLog::OperationKind::TransactionMarker ||
        accepted.state != WriteAheadLog::RecordState::Accepted || accepted.flags != 0x8 || accepted.logical_length != 1 ||
        accepted.transaction_id != mutation.transaction_id || accepted.sequence != sequence || accepted.object_id != original.checkpoint_xid ||
        mutation.sequence >= accepted.sequence || accepted.sequence >= durable.sequence || durable.sequence >= cleaned.sequence ||
        durable.operation != WriteAheadLog::OperationKind::DurabilityWatermark || durable.state != WriteAheadLog::RecordState::Checkpointed ||
        cleaned.operation != WriteAheadLog::OperationKind::DurabilityWatermark || cleaned.state != WriteAheadLog::RecordState::Cleaned ||
        durable.logical_offset != sequence || cleaned.logical_offset != sequence ||
        repair.checkpoint != original.checkpoint_xid || repair.volume != original.volume_oid ||
        repair.container_uuid != original.container_uuid_hex || repair.volume_uuid != original.volume_uuid_hex ||
        repair.expected_count != expected_count || mutation.object_id != repair.volume ||
        mutation.parent_object_id != repair.checkpoint + 1 || ImageIdentity(owner.Device()) != repair.source_identity)
        return Fail(error, "CountRepairCompletedOriginalReceiptMismatch");
    std::array<std::uint8_t, 32> hash{};
    if (approved_sha256.size() != 64 || !Hash(approved_preimage, hash) || Hex(hash) != approved_sha256)
        return Fail(error, "CountRepairCompletedApprovedBackupMismatch");
    catalog::VectorRandomAccessSource backup(std::vector<std::byte>(approved_preimage.begin(), approved_preimage.end()));
    const auto before = catalog::LoadAppleCheckpointView(backup, 0, backup.SizeBytes(), error);
    if (!before || before->container.superblock.xid != original.checkpoint_xid || !ValidatePreimage(backup, *before, repair, error))
        return Fail(error, "CountRepairCompletedApprovedPreimageInvalid");
    if (!owner.InspectCurrentSession(original.volume_oid,
        [&](const Store& live, std::string& why) { return VerifyPublishedCountRepair(live, repair, why); }, error)) return false;
    if (!owned() || !owner.Device().IsExclusiveWriteSourceObservationCurrent(*observation))
        return Fail(error, "CountRepairCompletedSourceOrJournalChanged");
    return true;
}

Result ApplyApfsCountRepair(Owner& owner, TransactionManager& journal, ApfsCountRepairPlan& plan, std::string_view confirmation_token)
{
    Result result;
    const bool already_consumed = plan.consumed_.exchange(true);
    if (already_consumed || plan.owner_ != &owner || plan.lifetime_.expired() || std::chrono::steady_clock::now() >= plan.expires_ ||
        confirmation_token.empty() || confirmation_token != plan.token_)
    { result.error = "ApfsCountRepairPlanInvalidOrConsumed"; return result; }
    NativeCountRepair rename;
    if (!owner.CheckpointCensusRequired() || !DecodeNativeCountRepair(plan.request_.inline_payload, rename))
    { result.error = "CountRepairOwnerConflict"; return result; }
    bool acceptance_started = false;
    std::uint64_t sequence = 0;
    try
    {
        result = owner.Commit(rename.volume, {plan.request_},
            [&](const auto& requests, const auto& identities, std::uint64_t xid, auto& pins, std::string& error) {
                if (std::chrono::steady_clock::now() >= plan.expires_) return Fail(error, "CountRepairPlanExpiredBeforeAcceptance");
                if (requests.size() != 1 || identities.size() != 1 || xid != rename.checkpoint ||
                    requests[0].inline_payload != plan.request_.inline_payload || identities[0].object_id != rename.volume ||
                    identities[0].generation != xid + 1) return Fail(error, "CountRepairAcceptanceIdentityMismatch");
                TransactionManager::MutationIntent intent;
                intent.kind = TransactionManager::MutationKind::RepairVolumeFileCount; intent.path = L"\\";
                intent.object_id = rename.volume; intent.generation = xid + 1;
                intent.inline_payload = requests[0].inline_payload;
                intent.length = intent.payload_length = intent.inline_payload.size();
                if (!Hash(intent.inline_payload, intent.payload_checksum)) return Fail(error, "CountRepairAcceptanceHashFailed");
                acceptance_started = true;
                if (!journal.Begin() || !journal.RecordMutation(intent) || !journal.Accept(xid))
                    return Fail(error, "CountRepairDurableAcceptanceFailed");
                sequence = journal.Watermarks().accepted_sequence;
                return sequence && journal.LoadRequiredCheckpointXidsSinceCleanup(pins, &error);
            }, {}, {}, false, {},
            [&](const Store& live, auto& requests, std::string& error) {
                // Distinct prepared plans can race too. Check the caller's WAL
                // only after obtaining the same serializer used for acceptance.
                if (journal.CurrentState() != TransactionManager::State::Idle || journal.PendingMutationCount() ||
                    !journal.RecoveryStateValid() || journal.HasUnappliedAcceptedWork())
                    return Fail(error, "CountRepairOwnerConflict");
                const auto identity = CountRepairJournalIdentity(rename);
                if (!journal.JournalMatchesVolumeIdentity(std::wstring(identity.begin(), identity.end())))
                    return Fail(error, "CountRepairJournalIdentityMismatch");
                std::vector<TransactionManager::AcceptedTransaction> existing;
                if (!journal.LoadAcceptedTransactionsSinceCleanup(existing) || !existing.empty())
                    return Fail(error, "CountRepairJournalDebt");
                if (std::chrono::steady_clock::now() >= plan.expires_) return Fail(error, "CountRepairPlanExpired");
                std::string image_hash;
                if (!ImageHash(Source(live.Device()), image_hash, error) || image_hash != plan.image_preimage_)
                    return Fail(error, "CountRepairImagePreimageChanged");
                const auto* cp = live.AuthoritativeAppleCheckpointView();
                const auto* v = cp ? Volume(*cp, rename.volume) : nullptr;
                std::uint64_t count = 0; std::string digest, witness;
                if (!v || !Inspect(Source(live.Device()), *cp, *v, rename.source_identity,
                    count, digest, error, &witness) || witness != plan.source_witness_)
                    return Fail(error, "CountRepairPreparedSourceBytesChanged");
                return requests.size() == 1 && ValidateCountRepairMutation(live, requests[0], error);
            },
            [&](const Store& live, std::uint64_t, std::string& error) {
                return VerifyPublishedCountRepair(live, rename, error);
            }, true);
        if (result.commit_status_code == static_cast<int>(Store::CommitStatus::Committed) &&
            result.committed && !result.commit_recovery_required)
        {
            if (Finalize(owner, journal, rename.volume, sequence, result.error)) return result;
        }
    }
    catch (...) { result.error = "CountRepairException"; }
    if (acceptance_started)
    {
        // Even ambiguous acceptance keeps its source checkpoint owned until
        // canonical startup recovery proves publication and cleans the WAL.
        result.commit_recovery_required = true;
        result.commit_recovery_reason = L"CountRepairRequiresRecovery";
        result.commit_status_code = static_cast<int>(Store::CommitStatus::InvariantFailed);
        std::vector<std::uint64_t> pins{rename.checkpoint}; std::string error;
        for (const auto& entry : owner.CheckpointCensusSnapshot())
            if (entry.volume_object_id == rename.volume) pins.insert(pins.end(), entry.required_checkpoint_xids.begin(), entry.required_checkpoint_xids.end());
        std::sort(pins.begin(), pins.end()); pins.erase(std::unique(pins.begin(), pins.end()), pins.end());
        (void)owner.UpdateRequiredCheckpointXids(rename.volume, pins, error, true);
    }
    return result;
}

std::optional<bool> ReplayApfsCountRepair(Owner& owner, TransactionManager& journal, std::uint64_t oid, std::string& error)
{
    std::vector<TransactionManager::AcceptedTransaction> transactions;
    if (!journal.LoadAcceptedTransactionsSinceCleanup(transactions, &error)) return false;
    bool found = false;
    for (const auto& tx : transactions) for (const auto& record : tx.mutations)
        found |= record.operation == WriteAheadLog::OperationKind::RepairVolumeFileCount;
    if (!found) return std::nullopt;
    if (!owner.CheckpointCensusRequired() || transactions.size() != 1 || transactions[0].mutations.size() != 1)
        return Fail(error, "CountRepairReplayNotIsolated");
    const auto& tx = transactions[0];
    Store::MutationRequest request; NativeCountRepair rename;
    if (!CountRepairFromWal(tx.mutations[0], request) || !DecodeNativeCountRepair(request.inline_payload, rename) ||
        rename.volume != oid || rename.checkpoint != tx.preimage_checkpoint_xid ||
        ImageIdentity(owner.Device()) != rename.source_identity) return Fail(error, "CountRepairReplayIdentityInvalid");
    std::vector<std::uint64_t> pins;
    if (!journal.LoadRequiredCheckpointXidsSinceCleanup(pins, &error) ||
        !owner.UpdateRequiredCheckpointXids(oid, pins, error, true) || !owner.RefreshSessionForRecovery(oid, error)) return false;
    if (owner.CheckpointXid() == rename.checkpoint)
    {
        const auto result = owner.Commit(oid, {request}, {}, {}, {}, true, rename.checkpoint, {},
            [&](const Store& live, std::uint64_t, std::string& why) { return VerifyPublishedCountRepair(live, rename, why); });
        if (!result.committed || result.commit_recovery_required || result.commit_status_code != static_cast<int>(Store::CommitStatus::Committed))
        { error = result.error; return false; }
    }
    else if (!owner.InspectCurrentSession(oid,
        [&](const Store& live, std::string& why) { return VerifyPublishedCountRepair(live, rename, why); },
        error, true)) return false;
    return Finalize(owner, journal, oid, tx.accepted_sequence, error);
}
}
