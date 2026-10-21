#include "VolumeMetadata.h"
#include <bcrypt.h>
#include "ApfsSharedSpace.h"
#include "ApfsVerifier.h"
#include "VolumeManagement.h"

namespace apfsaccess::rw
{
struct VolumeMetadataPlanAccess {
    static void Seal(VolumeRenamePlan& p, const MetadataStore* store) { p.sealed_payload_=p.request.inline_payload; p.sealed_store_=store; }
    static bool Matches(const VolumeRenamePlan& p, const MetadataStore* store) { return store && p.sealed_store_==store && !p.sealed_payload_.empty() && p.sealed_payload_==p.request.inline_payload; }
};
namespace
{
using Store = MetadataStore;
using Owner = catalog::ContainerMountCoordinator;
using Result = catalog::ContainerCommitResult;
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
bool QuotaJournalMatchesOwner(const TransactionManager& journal, const Owner& owner,
    std::string_view container, std::uint64_t oid)
{
    const auto canonical = "apfs-vol:" + std::string(container) + ":" + std::to_string(oid);
    const std::wstring canonical_wide(canonical.begin(), canonical.end());
    if (journal.JournalMatchesVolumeIdentity(canonical_wide)) return true;
    if (!owner.Device().IsRegularFile() || owner.Device().BaseOffsetBytes() != 0 ||
        journal.EnrolledCanonicalJournalIdentity() != canonical_wide) return false;
    const auto production = DerivePartitionlessVolumeRecoveryIdentity(container, oid);
    return journal.JournalMatchesVolumeIdentity(std::wstring(production.begin(), production.end()));
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
bool HasSnapshots(const catalog::AppleCheckpointView& checkpoint)
{
    return std::any_of(checkpoint.volumes.begin(), checkpoint.volumes.end(),
        [](const auto& volume) { return volume.object_map.snapshot_tree_oid != 0; });
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
bool SamePreservedSuperblock(std::vector<std::byte> before, std::vector<std::byte> after, bool limits = false)
{
    if (before.size() != after.size() || before.size() < 0x3c0) return false;
    // Only checksum, object XID, allocated block accounting, physical OMAP and
    // lifetime COW counters may change in addition to the explicit label.
    for (const auto offset : {0u, 0x10u, 0x58u, 0x80u, 0xe0u, 0xe8u})
    {
        std::fill_n(before.begin() + offset, 8, std::byte{});
        std::fill_n(after.begin() + offset, 8, std::byte{});
    }
    if (limits) {
        std::fill_n(before.begin() + 0x48, 16, std::byte{});
        std::fill_n(after.begin() + 0x48, 16, std::byte{});
    } else {
        std::fill_n(before.begin() + 0x2c0, 256, std::byte{});
        std::fill_n(after.begin() + 0x2c0, 256, std::byte{});
    }
    return before == after;
}
bool Hash(std::span<const std::byte> bytes, std::array<std::uint8_t, 32>& out);
bool SpaceCensusDigest(const catalog::RandomAccessSource& input, const catalog::AppleCheckpointView& cp,
    std::string& out, std::string& error)
{
    // This private QRS1 census revision binds every current metadata input,
    // not merely self-consistent APSB totals. Retained versions reproduce it.
    // Do not include block zero or unrelated checkpoint-ring slots: they move
    // after publication. The retained selected NXSB is the proof endpoint.
    constexpr std::uint64_t max_bytes = 64ull * 1024 * 1024;
    auto budget = input.ReadBudget();
    if (!budget) budget = std::make_shared<catalog::ApfsReadBudget>(65536, 256ull*1024*1024, 1000000, 256ull*1024*1024);
    else budget->LimitRemainingTo(65536, 256ull*1024*1024, 1000000, 256ull*1024*1024);
    catalog::BudgetedRandomAccessSource source(input, budget);
    const auto block_size = cp.container.superblock.block_size;
    const auto block_count = cp.container.superblock.block_count;
    if (block_size < 4096 || block_size > 65536 || (block_size & (block_size-1)) ||
        !block_count || block_count > source.SizeBytes()/block_size)
        return Fail(error,"VolumeQuotaReserveCensusGeometryInvalid");
    std::vector<std::byte> bytes;
    const auto number=[&](std::uint64_t n){for(unsigned i=0;i<8;++i)bytes.push_back(std::byte((n>>(8*i))&255));};
    const auto append=[&](std::uint64_t address, const auto& raw) {
        if (bytes.size()>max_bytes-16 || raw.size()>max_bytes-16-bytes.size())
            return Fail(error,"VolumeQuotaReserveCensusBudgetExceeded");
        number(address);number(raw.size());bytes.insert(bytes.end(),raw.begin(),raw.end());return true;
    };
    number(2); // explicit census domain revision; old private proofs fail closed
    const auto read=[&](std::uint64_t block, std::vector<std::byte>& raw) {
        if(block>=block_count || !source.Read(block*block_size,block_size,raw))
            return Fail(error,"VolumeQuotaReserveCensusReadFailed");
        return true;
    };
    const auto object=[&](const catalog::AppleObjectLocation& location) {
        if(location.size_bytes!=block_size)return Fail(error,"VolumeQuotaReserveCensusObjectSizeUnsupported");
        std::vector<std::byte> raw;
        return read(location.physical_block,raw)&&append(location.physical_block,raw);
    };
    std::vector<std::byte> raw;
    if(!read(cp.container.superblock_physical_block,raw) || raw!=cp.container.superblock_bytes)
        return Fail(error,"VolumeQuotaReserveCheckpointCensusChanged");
    if(!append(cp.container.superblock_physical_block,raw)||!object(cp.spaceman.object)||!object(cp.container_object_map.object))return false;
    for(const auto block:cp.container.checkpoint_map_blocks)
        if(!read(block,raw)||!append(block,raw))return false;
    for(const auto& device:cp.spaceman.devices) {
        for(const auto& cab:device.cabs)if(!object(cab.object))return false;
        for(const auto& cib:device.cibs)if(!object(cib.object))return false;
    }
    const auto tree=[&](const catalog::AppleVolumeCheckpointView& volume, const catalog::AppleObjectLocation& root,
                        std::vector<catalog::BtreeRecord>& records, std::vector<std::uint64_t>& owned) {
        catalog::BtreeReadPolicy policy;
        policy.enforce_object_identity=true;policy.root_object_id=root.object_id;
        policy.storage_type=root.type;policy.subtype=root.subtype;
        policy.require_complete_traversal=true;policy.reject_unsupported_flags=true;
        policy.ephemeral_checkpoint=&cp.container;
        std::vector<std::uint64_t> visited;policy.visited_physical_blocks=&visited;
        const bool physical=(root.type&catalog::kObjectStorageTypeMask)==catalog::kObjectPhysical;
        if(!catalog::ReadBtreeLeafRecords(source,block_size,root.physical_block,physical,
            physical?0:volume.superblock.omap_oid,cp.container.superblock.xid,policy,records,error))return false;
        for(const auto block:visited) {
            if(!read(block,raw)||!append(block,raw))return false;
            owned.push_back(block);
        }
        return true;
    };
    if(cp.volumes.empty())return Fail(error,"VolumeQuotaReserveCensusVolumeMissing");
    std::vector<catalog::BtreeRecord> records;std::vector<std::uint64_t> container_nodes;
    if(!tree(cp.volumes.front(),cp.container_object_map.tree,records,container_nodes))return false;
    // The spaceman loader already resolves the complete ephemeral queue,
    // including its valid ghost entries. Bind those exact visited blocks.
    for(const auto& queue:cp.spaceman.free_queues)
        for(const auto block:queue.tree_blocks)
            if(!read(block,raw)||!append(block,raw))return false;
    for(const auto& v:cp.volumes) {
        if(!read(v.superblock_object.physical_block,raw))return false;
        const auto parsed=catalog::ParseApsb(raw);
        if(!parsed || parsed->object_id!=v.superblock.object_id || parsed->uuid_hex!=v.superblock.uuid_hex ||
            parsed->xid!=v.superblock.xid || parsed->space.allocated_block_count!=v.superblock.space.allocated_block_count ||
            parsed->space.reserve_block_count!=v.superblock.space.reserve_block_count ||
            parsed->space.quota_block_count!=v.superblock.space.quota_block_count)
            return Fail(error,"VolumeQuotaReserveSiblingCensusChanged");
        if(!append(v.superblock_object.physical_block,raw)||!object(v.object_map.object))return false;
        std::vector<std::uint64_t> owned{v.superblock_object.physical_block,v.object_map.object.physical_block};
        std::vector<catalog::BtreeRecord> filesystem,extentrefs;
        if(!tree(v,v.object_map.tree,records,owned)||!tree(v,v.root_tree,filesystem,owned))return false;
        if(!v.extentref_tree || v.file_extent_tree)
            return Fail(error,"VolumeQuotaReserveExactChargeProfileUnsupported");
        if(!tree(v,*v.extentref_tree,extentrefs,owned))return false;
        if(v.snapshot_metadata_tree&&!tree(v,*v.snapshot_metadata_tree,records,owned))return false;
        std::vector<ApplePhysicalExtentRecord> payload;
        if(!ValidateApplePayloadExtentGraph(filesystem,extentrefs,block_size,block_count,payload,error))return false;
        std::sort(owned.begin(),owned.end());owned.erase(std::unique(owned.begin(),owned.end()),owned.end());
        std::uint64_t charged=owned.size();
        if(charged>block_count)return Fail(error,"VolumeQuotaReserveChargeOverflow");
        for(const auto& extent:payload) {
            if(extent.block_count>block_count-charged)return Fail(error,"VolumeQuotaReserveChargeOverflow");
            charged+=extent.block_count;
        }
        // Historical/unattributed ownership cannot discharge a reserve promise.
        // Admit only the exact ordinary current-charge profile we can prove.
        if(charged!=v.superblock.space.allocated_block_count)
            return Fail(error,"VolumeQuotaReserveExactChargedAllocationUnproven");
    }
    for(const auto& chunk:cp.spaceman.chunks) {
        if(bytes.size()>max_bytes-32)return Fail(error,"VolumeQuotaReserveCensusBudgetExceeded");
        number(chunk.start_block);number(chunk.block_count);number(chunk.free_count);number(chunk.bitmap_block);
        if(!chunk.allocation_bitmap.empty()) {
            if(chunk.allocation_bitmap.size()!=block_size || !read(chunk.bitmap_block,raw) || raw!=chunk.allocation_bitmap)
                return Fail(error,"VolumeQuotaReserveAllocationCensusChanged");
            if(!append(chunk.bitmap_block,raw))return false;
        }
    }
    for(const auto& bitmap:cp.spaceman.internal_pool.active_bitmaps) {
        if(bitmap.bytes.size()!=block_size || !read(bitmap.physical_block,raw)||raw!=bitmap.bytes)
            return Fail(error,"VolumeQuotaReserveInternalCensusChanged");
        if(!append(bitmap.physical_block,raw))return false;
    }
    std::array<std::uint8_t,32> digest{};if(!Hash(bytes,digest))return Fail(error,"VolumeQuotaReserveCensusHashFailed");
    out.clear();const char hex[]="0123456789abcdef";for(auto b:digest){out+=hex[b>>4];out+=hex[b&15];}return true;
}
bool ValidatePreimage(const catalog::RandomAccessSource& source, const catalog::AppleCheckpointView& cp,
    const NativeVolumeRename& rename, std::string& error)
{
    const auto* volume = Volume(cp, rename.volume);
    NativeVolumeRename checked;
    if (!DecodeNativeVolumeMetadata(EncodeNativeVolumeRename(rename), checked) || !volume ||
        cp.container.superblock.uuid_hex != rename.container_uuid || cp.container.superblock.xid != rename.checkpoint ||
        volume->superblock.uuid_hex != rename.volume_uuid || !volume->superblock.name_valid ||
        volume->superblock.name_utf8 != rename.old_label)
        return Fail(error, "VolumeRenameStaleIdentityOrCheckpoint");
    if (!CheckAppleVolumeWriteFeatures(cp.container.superblock, volume->superblock, error)) return false;
    if (cp.container_object_map.snapshot_tree_oid)
        return Fail(error, "VolumeRenameSnapshotsUnsupported");
    const bool snapshots = HasSnapshots(cp);
    if (snapshots && !rename.quota_reserve) {
        std::vector<std::uint64_t> metadata;
        std::vector<ApplePhysicalExtentRecord> payload;
        if (!LoadAppleSnapshotCheckpointOwners(source, cp, metadata, payload, error)) return false;
    }
    if (rename.quota_reserve && (catalog::ReadU64LE(rename.superblock, 0xd8).value_or(UINT64_MAX) != 0 ||
        volume->object_map.snapshot_tree_oid)) return Fail(error, "VolumeRenameSnapshotsUnsupported");
    if (!snapshots && catalog::ReadU64LE(rename.superblock, 0xd8).value_or(UINT64_MAX) != 0)
        return Fail(error, "VolumeRenameSnapshotsUnsupported");
    if (volume->snapshot_metadata_tree)
    {
        std::vector<catalog::BtreeRecord> records;
        if (!ReadTree(source, cp, *volume, *volume->snapshot_metadata_tree, records, error) ||
            ((!snapshots || rename.quota_reserve) && !records.empty()))
            return Fail(error, "VolumeRenameSnapshotsUnsupported");
    }
    std::vector<std::byte> bytes;
    if (!ReadSuperblock(source, cp, *volume, bytes) || bytes != rename.superblock)
        return Fail(error, "VolumeRenameSuperblockPreimageChanged");
    if (rename.quota_reserve) {
        std::string digest;
        if(!SpaceCensusDigest(source,cp,digest,error))return false;
        if(digest!=rename.space_census_sha256)return Fail(error,"VolumeQuotaReserveSpaceCensusPreimageChanged");
        auto proposed = cp;
        for (auto& peer : proposed.volumes) {
            std::vector<std::byte> apsb;
            if (!ReadSuperblock(source, cp, peer, apsb) ||
                catalog::ReadU64LE(apsb, 0xd8).value_or(UINT64_MAX) || peer.object_map.snapshot_tree_oid)
                return Fail(error, "VolumeQuotaReserveSnapshotAccountingUnproven");
            if (peer.snapshot_metadata_tree) {
                std::vector<catalog::BtreeRecord> records;
                if (!ReadTree(source, cp, peer, *peer.snapshot_metadata_tree, records, error) || !records.empty())
                    return Fail(error, "VolumeQuotaReserveSnapshotAccountingUnproven");
            }
            if (peer.superblock.object_id == rename.volume) {
                peer.superblock.space.quota_block_count = rename.quota_blocks;
                peer.superblock.space.reserve_block_count = rename.reserve_blocks;
            }
        }
        catalog::ApfsSharedSpaceProjection census;
        if (!catalog::TryProjectAppleSharedSpace(cp, census, error) ||
            !catalog::TryProjectAppleSharedSpace(proposed, census, error)) return false;
    }
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
bool QuotaSessionsIdle(Owner& owner, std::string& error, std::uint64_t staged_volume = 0)
{
    for(const auto& pins:owner.CheckpointCensusSnapshot()) {
        const auto* store=owner.FindSessionStore(pins.volume_object_id);
        if(store && (store->HasUncommittedAllocatorState() || store->IsRecoveryRequired() ||
            (pins.volume_object_id != staged_volume && (store->PendingMutationCount() ||
            store->PendingAllocationCount() || store->PendingDeallocationCount() ||
            store->PendingObjectMapUpdateCount() || store->PendingBtreeRecordCount() || store->PendingPayloadByteEstimate()))))
            return Fail(error,"VolumeQuotaReserveActiveSessionReservation");
    }
    return true;
}
bool Finalize(Owner& owner, TransactionManager& journal, std::uint64_t oid, std::uint64_t sequence, std::string& error)
{
    if (!sequence || !journal.MarkApfsDurableThrough(sequence) || !journal.MarkCleanedThrough(sequence))
        return Fail(error, "VolumeRenameJournalFinalizationFailed");
    std::vector<std::uint64_t> pins;
    return journal.LoadRequiredCheckpointXidsSinceCleanup(pins, &error) &&
        owner.UpdateRequiredCheckpointXids(oid, pins, error, journal.HasUnappliedAcceptedWork());
}
}

bool ValidateVolumeMetadataMutation(const Store& store, const Store::MutationRequest& request, std::string& error)
{
    error.clear();
    NativeVolumeRename rename;
    const auto* cp = store.AuthoritativeAppleCheckpointView();
    if ((request.operation != Store::MutationOperation::RenameVolume && request.operation != Store::MutationOperation::SetVolumeQuotaReserve) || !store.IsNativeWriteReady() ||
        store.IsRecoveryRequired() || !cp || request.path != L"\\" || !request.secondary_path.empty() ||
        request.offset || request.timestamp_utc || request.replace_if_exists || request.expected_unlink_outcome ||
        request.length != request.inline_payload.size() || !DecodeNativeVolumeMetadata(request.inline_payload, rename) ||
        request.object_id != rename.volume || request.generation != rename.checkpoint + 1 ||
        store.Context().volume_object_id != rename.volume || store.Context().container_uuid_hex != rename.container_uuid ||
        store.Context().volume_uuid_hex != rename.volume_uuid)
        return Fail(error, "VolumeRenameRequestInvalid");
    if (rename.quota_reserve != (request.operation == Store::MutationOperation::SetVolumeQuotaReserve))
        return Fail(error, "VolumeMetadataOperationMismatch");
    if (rename.quota_reserve) {
        std::string identity;
        if (store.Context().device_path!=store.Device().Path() ||
            store.Context().device_offset_bytes!=store.Device().BaseOffsetBytes() ||
            !store.Device().QueryRegularImageIdentity(identity) || identity != rename.image_identity)
            return Fail(error, "VolumeQuotaReserveImageIdentityMismatch");
        catalog::VerificationScope scope;
        scope.source_identity = identity;
        scope.exact = {0, store.Device().GetGeometry().total_bytes, rename.container_uuid,
            rename.volume_uuid, rename.volume, rename.checkpoint};
        const auto report = catalog::ApfsVerifier::Verify(Source(store.Device()), scope);
        if (report.outcome != catalog::VerificationOutcome::Complete || !report.allocation_census)
        { error="VolumeQuotaReserveCurrentOwnershipUnproven";
          if(!report.findings.empty()) error+=":"+report.findings.front().detail;
          return false; }
    }
    return ValidatePreimage(Source(store.Device()), *cp, rename, error);
}

static bool PrepareVolumeMetadata(Owner& owner, std::uint64_t oid, std::string_view label,
    std::optional<std::pair<std::uint64_t, std::uint64_t>> limits, VolumeRenamePlan& out, std::string& error)
{
    error.clear();
    if (limits && !QuotaSessionsIdle(owner,error)) return false;
    if (!limits && !ValidNativeVolumeLabel(label)) return Fail(error, "VolumeRenameLabelInvalid");
    auto* store = owner.FindSessionStore(oid);
    if (!oid || owner.IsRecoveryRequired() || !owner.CheckpointCensusRequired() || !store ||
        store->PendingMutationCount() || !store->IsNativeWriteReady()) return Fail(error, "VolumeRenameOwnerNotReady");
    for (const auto& pins : owner.CheckpointCensusSnapshot())
        if (pins.unapplied_accepted_work) return Fail(error, "VolumeRenameAcceptedOwnerConflict");
    const auto* cp = store->AuthoritativeAppleCheckpointView();
    const auto* volume = cp ? Volume(*cp, oid) : nullptr;
    if (!volume) return Fail(error, "VolumeRenameVolumeMissing");
    NativeVolumeRename rename;
    rename.checkpoint = cp->container.superblock.xid; rename.volume = oid;
    rename.container_uuid = cp->container.superblock.uuid_hex; rename.volume_uuid = volume->superblock.uuid_hex;
    rename.old_label = volume->superblock.name_utf8; rename.new_label = std::string(label);
    if (!ReadSuperblock(Source(store->Device()), *cp, *volume, rename.superblock)) return Fail(error, "VolumeRenameReadFailed");
    if (limits) {
        rename.quota_reserve = true; rename.reserve_blocks = limits->first; rename.quota_blocks = limits->second;
        rename.new_label = rename.old_label;
        if (!store->Device().QueryRegularImageIdentity(rename.image_identity)) return Fail(error, "VolumeQuotaReserveRequiresRegularImage");
        if(!SpaceCensusDigest(Source(store->Device()),*cp,rename.space_census_sha256,error))return false;
    }
    Store::MutationRequest request;
    request.operation = limits ? Store::MutationOperation::SetVolumeQuotaReserve : Store::MutationOperation::RenameVolume; request.path = L"\\";
    request.object_id = oid; request.generation = rename.checkpoint + 1;
    request.inline_payload = EncodeNativeVolumeRename(rename); request.length = request.inline_payload.size();
    if (!ValidateVolumeMetadataMutation(*store, request, error)) return false;
    if (limits) {
        std::vector<std::uint64_t> required{rename.checkpoint};
        for (const auto& pins : owner.CheckpointCensusSnapshot())
            required.insert(required.end(), pins.required_checkpoint_xids.begin(), pins.required_checkpoint_xids.end());
        AppleVolumeTransactionPlan preview;
        if (!PlanVolumeMetadataCheckpoint(Source(store->Device()), *cp, rename, required, preview, error)) return false;
    }
    out.request = std::move(request); out.owner = &owner; out.consumed = false;
    out.expires = std::chrono::steady_clock::now() + std::chrono::minutes(5);
    VolumeMetadataPlanAccess::Seal(out, store);
    return true;
}

bool PlanVolumeMetadataCheckpoint(const catalog::RandomAccessSource& source, const catalog::AppleCheckpointView& cp,
    const NativeVolumeRename& rename, const std::vector<std::uint64_t>& pins,
    AppleVolumeTransactionPlan& out, std::string& error)
{
    out = {}; error.clear();
    if (!ValidatePreimage(source, cp, rename, error)) return false;
    const auto& volume = *Volume(cp, rename.volume);
    AppleVolumeTransactionRequest request;
    request.volume_object_id = rename.volume; request.required_checkpoint_xids = pins;
    if (rename.quota_reserve) request.volume_reserve_quota = {rename.reserve_blocks, rename.quota_blocks};
    if (!ReadTree(source, cp, volume, volume.root_tree, request.filesystem_records, error)) return false;
    AppleVolumeTransactionPlan planned;
    if (!rename.quota_reserve && HasSnapshots(cp)) {
        request.preserve_source_metadata = true;
        if (!PlanAppleSnapshotMetadataTransaction(source, cp, request, planned, error)) return false;
    }
    else if (!PlanAppleVolumeTransaction(source, cp, request, planned, error)) return false;
    if (!planned.payload_blocks.empty() || !EqualRecords(request.filesystem_records, planned.filesystem_records))
        return Fail(error, "VolumeRenameUnexpectedPayloadMutation");
    unsigned changed = 0;
    for (auto& write : planned.commit.publication.before_superblock_writes)
    {
        const auto apsb = catalog::ParseApsb(write.bytes);
        if (!apsb || apsb->object_id != rename.volume) continue;
        if (++changed != 1 || apsb->uuid_hex != rename.volume_uuid ||
            !SamePreservedSuperblock(rename.superblock, write.bytes, rename.quota_reserve))
            return Fail(error, "VolumeRenameUnexpectedMetadataMutation");
        if (rename.quota_reserve) {
            for (unsigned i=0; i<8; ++i) {
                write.bytes[0x48+i] = std::byte((rename.reserve_blocks>>(8*i))&255);
                write.bytes[0x50+i] = std::byte((rename.quota_blocks>>(8*i))&255);
            }
        } else {
        std::fill_n(write.bytes.begin() + 0x2c0, 256, std::byte{});
        for (std::size_t i = 0; i < rename.new_label.size(); ++i)
            write.bytes[0x2c0 + i] = std::byte(static_cast<unsigned char>(rename.new_label[i]));
        }
        if (!FinalizeAppleObjectChecksum(write.bytes, error)) return false;
        const auto renamed = catalog::ParseApsb(write.bytes);
        if (!renamed || !renamed->name_valid || renamed->name_utf8 != rename.new_label)
            return Fail(error, "VolumeRenameLabelRoundTripFailed");
    }
    if (changed != 1) return Fail(error, "VolumeRenamePublicationSuperblockMissing");
    out = std::move(planned);
    return true;
}

bool VolumeMetadataFromWal(const WriteAheadLog::Record& record, Store::MutationRequest& out)
{
    if ((record.operation != WriteAheadLog::OperationKind::RenameVolume && record.operation != WriteAheadLog::OperationKind::SetVolumeQuotaReserve) ||
        !WriteAheadLog::VolumeRenameIsConsistent(record) || !WriteAheadLog::VolumeQuotaReserveIsConsistent(record)) return false;
    Store::MutationRequest request;
    request.operation = static_cast<Store::MutationOperation>(record.operation); request.path = L"\\";
    request.object_id = record.object_id; request.generation = record.parent_object_id;
    request.inline_payload = record.inline_payload; request.length = request.inline_payload.size();
    out = std::move(request); return true;
}

bool VerifyPublishedVolumeRename(const Store& store, const NativeVolumeRename& rename, std::string& error)
{
    error.clear();
    const auto* current = store.AuthoritativeAppleCheckpointView();
    if (!current || store.PendingMutationCount() || current->container.superblock.xid <= rename.checkpoint ||
        store.Context().volume_object_id != rename.volume || current->container.superblock.uuid_hex != rename.container_uuid)
        return Fail(error, "VolumeRenamePublicationNotObserved");
    if (rename.quota_reserve) {
        std::string identity;
        if (!store.Device().QueryRegularImageIdentity(identity) || identity != rename.image_identity ||
            store.Context().volume_uuid_hex != rename.volume_uuid)
            return Fail(error, "VolumeQuotaReservePublishedImageMismatch");
    }
    Source source(store.Device());
    AppleVolumeReplayBoundary boundary;
    const bool snapshots = !rename.quota_reserve && HasSnapshots(*current);
    const auto find_boundary = snapshots ? FindAppleSnapshotVolumeReplayBoundary : FindAppleVolumeReplayBoundary;
    if (!find_boundary(source, *current, rename.volume, rename.checkpoint, boundary, error) ||
        !boundary.first_changed_checkpoint_xid) return Fail(error, "VolumeRenamePublicationBoundaryMissing");
    // The retention API returns the complete continuity chain, including all
    // intermediate checkpoints. Select proof endpoints by XID, not count or
    // vector order, so later selected-volume and sibling commits remain valid.
    std::vector<AppleRecoveryCheckpointView> history;
    const auto load_history = snapshots ? LoadAppleSnapshotRecoveryCheckpoints : LoadAppleRecoveryCheckpoints;
    if (!load_history(source, *current, {rename.checkpoint}, history, error)) return false;
    const auto retained = [&](std::uint64_t xid) -> const catalog::AppleCheckpointView* {
        if (current->container.superblock.xid == xid) return current;
        const auto it = std::find_if(history.begin(), history.end(), [&](const auto& entry) {
            return entry.checkpoint.container.superblock.xid == xid;
        });
        return it == history.end() ? nullptr : &it->checkpoint;
    };
    const auto* preimage = retained(rename.checkpoint);
    if (!preimage) return Fail(error, "VolumeRenamePublicationPreimageMissing");
    const auto& before = *preimage;
    if (*boundary.first_changed_checkpoint_xid != before.container.superblock.next_xid ||
        !ValidatePreimage(source, before, rename, error)) return Fail(error, "VolumeRenamePublicationPreimageMismatch");
    const auto* after = retained(*boundary.first_changed_checkpoint_xid);
    if (!after) return Fail(error, "VolumeRenamePublicationCheckpointMissing");
    if (before.volumes.size() != after->volumes.size()) return Fail(error, "VolumeRenameSiblingSetChanged");
    for (const auto& old_volume : before.volumes)
    {
        const auto* new_volume = Volume(*after, old_volume.superblock.object_id);
        std::vector<std::byte> a, b;
        if (!new_volume || !ReadSuperblock(source, before, old_volume, a) || !ReadSuperblock(source, *after, *new_volume, b)) return false;
        if (old_volume.superblock.object_id != rename.volume)
        {
            if (a != b) return Fail(error, "VolumeRenameSiblingChanged");
            continue;
        }
        if (a != rename.superblock || !SamePreservedSuperblock(a, b, rename.quota_reserve) || !new_volume->superblock.name_valid ||
            new_volume->superblock.name_utf8 != rename.new_label || new_volume->superblock.uuid_hex != rename.volume_uuid)
            return Fail(error, "VolumeRenamePublishedMetadataMismatch");
        if (rename.quota_reserve && (new_volume->superblock.space.quota_block_count != rename.quota_blocks ||
            new_volume->superblock.space.reserve_block_count != rename.reserve_blocks ||
            (rename.quota_blocks && new_volume->superblock.space.allocated_block_count > rename.quota_blocks)))
            return Fail(error, "VolumeQuotaReservePublishedLimitsMismatch");
        const std::optional<catalog::AppleObjectLocation> old_roots[] = {old_volume.root_tree, old_volume.extentref_tree,
            old_volume.snapshot_metadata_tree, old_volume.file_extent_tree};
        const std::optional<catalog::AppleObjectLocation> new_roots[] = {new_volume->root_tree, new_volume->extentref_tree,
            new_volume->snapshot_metadata_tree, new_volume->file_extent_tree};
        for (unsigned i = 0; i != 4; ++i)
        {
            if (old_roots[i].has_value() != new_roots[i].has_value()) return Fail(error, "VolumeRenameTreeSetChanged");
            if (!old_roots[i]) continue;
            std::vector<catalog::BtreeRecord> left, right;
            if (!ReadTree(source, before, old_volume, *old_roots[i], left, error) ||
                !ReadTree(source, *after, *new_volume, *new_roots[i], right, error) || !EqualRecords(left, right))
                return Fail(error, "VolumeRenameTreeRecordsChanged");
        }
    }
    if (rename.quota_reserve) {
        std::string observed;
        catalog::ApfsSharedSpaceProjection space;
        if (!SpaceCensusDigest(source, *after, observed, error) ||
            !catalog::TryProjectAppleSharedSpace(*after, space, error)) return false;
    }
    return true;
}

Result ApplyVolumeMetadata(Owner& owner, TransactionManager& journal, VolumeRenamePlan& plan, VolumeRenameObserver observer = {})
{
    Result result;
    const bool already_consumed = plan.consumed;
    plan.consumed = true;
    if (already_consumed || plan.owner != &owner || std::chrono::steady_clock::now() >= plan.expires)
    { result.error = "VolumeRenamePlanInvalidOrConsumed"; return result; }
    NativeVolumeRename rename;
    if (!owner.CheckpointCensusRequired() || !DecodeNativeVolumeMetadata(plan.request.inline_payload, rename) ||
        journal.CurrentState() != TransactionManager::State::Idle || journal.PendingMutationCount() ||
        !journal.RecoveryStateValid() || journal.HasUnappliedAcceptedWork())
    { result.error = "VolumeRenameOwnerConflict"; return result; }
    observer.Mark("rename.journal-debt");
    std::vector<TransactionManager::AcceptedTransaction> existing;
    if (!journal.LoadAcceptedTransactionsSinceCleanup(existing) || !existing.empty())
    { result.error = "VolumeRenameJournalDebt"; return result; }
    if (rename.quota_reserve) {
        if (!QuotaJournalMatchesOwner(journal, owner, rename.container_uuid, rename.volume) ||
            !VolumeMetadataPlanAccess::Matches(plan, owner.FindSessionStore(rename.volume)))
        { result.error = "VolumeQuotaReservePlanOrJournalBindingMismatch"; return result; }
    }
    const auto fault = [&](std::string_view stage) { return plan.fault_hook_for_tests && plan.fault_hook_for_tests(stage); };
    bool acceptance_started = false;
    std::uint64_t sequence = 0;
    try
    {
        observer.Mark("rename.coordinator");
        result = owner.Commit(rename.volume, {plan.request},
            [&](const auto& requests, const auto& identities, std::uint64_t xid, auto& pins, std::string& error) {
                observer.Mark("rename.acceptance");
                if (requests.size() != 1 || identities.size() != 1 || xid != rename.checkpoint ||
                    requests[0].inline_payload != plan.request.inline_payload || identities[0].object_id != rename.volume ||
                    identities[0].generation != xid + 1) return Fail(error, "VolumeRenameAcceptanceIdentityMismatch");
                if (fault("before-acceptance")) return Fail(error, "VolumeMetadataInjectedBeforeAcceptance");
                // Last source/identity/census proof while the coordinator still
                // holds serialization and before a byte enters accepted WAL.
                const auto* live = owner.FindSessionStore(rename.volume);
                if (!live) return Fail(error,"VolumeQuotaReserveSessionMissing");
                if (rename.quota_reserve) {
                    // Commit already holds serialization. Use its current full
                    // checkpoint membership; never reacquire the census mutex.
                    const auto* checkpoint=live->AuthoritativeAppleCheckpointView();
                    if(!checkpoint)return Fail(error,"VolumeQuotaReserveCheckpointMissing");
                    for(const auto& volume:checkpoint->volumes) {
                        const auto* peer=owner.FindSessionStore(volume.superblock.object_id);
                        if(peer && (peer->HasUncommittedAllocatorState() || peer->IsRecoveryRequired() ||
                            (volume.superblock.object_id!=rename.volume && (peer->PendingMutationCount() ||
                            peer->PendingAllocationCount() || peer->PendingDeallocationCount() ||
                            peer->PendingObjectMapUpdateCount() || peer->PendingBtreeRecordCount() || peer->PendingPayloadByteEstimate()))))
                            return Fail(error,"VolumeQuotaReserveActiveSessionReservation");
                    }
                }
                if (!ValidateVolumeMetadataMutation(*live, requests[0], error)) return false;
                TransactionManager::MutationIntent intent;
                intent.kind = rename.quota_reserve ? TransactionManager::MutationKind::SetVolumeQuotaReserve : TransactionManager::MutationKind::RenameVolume; intent.path = L"\\";
                intent.object_id = rename.volume; intent.generation = xid + 1;
                intent.inline_payload = requests[0].inline_payload;
                intent.length = intent.payload_length = intent.inline_payload.size();
                if (!Hash(intent.inline_payload, intent.payload_checksum)) return Fail(error, "VolumeRenameAcceptanceHashFailed");
                acceptance_started = true;
                if (!journal.Begin() || !journal.RecordMutation(intent) || !journal.Accept(xid))
                    return Fail(error, "VolumeRenameDurableAcceptanceFailed");
                sequence = journal.Watermarks().accepted_sequence;
                const bool accepted = sequence && journal.LoadRequiredCheckpointXidsSinceCleanup(pins, &error);
                observer.Mark("rename.publication");
                return accepted;
            }, {}, {}, false, {},
            [&](const Store& live, auto& requests, std::string& error) {
                observer.Mark("rename.validate");
                const bool valid = requests.size() == 1 && ValidateVolumeMetadataMutation(live, requests[0], error);
                observer.Mark("rename.stage-checkpoint");
                return valid;
            },
            [&](const Store& live, std::uint64_t, std::string& error) {
                observer.Mark("rename.verify");
                const bool verified = VerifyPublishedVolumeRename(live, rename, error);
                observer.Mark("rename.coordinator-complete");
                return verified;
            });
        if (result.commit_status_code == static_cast<int>(Store::CommitStatus::Committed) &&
            result.committed && !result.commit_recovery_required)
        {
            observer.Mark("rename.finalize");
            if (fault("before-durable-watermark")) result.error="VolumeMetadataInjectedBeforeDurable";
            else if (!journal.MarkApfsDurableThrough(sequence)) result.error="VolumeMetadataDurableWatermarkFailed";
            else if (fault("before-cleanup")) result.error="VolumeMetadataInjectedBeforeCleanup";
            else if (Finalize(owner, journal, rename.volume, sequence, result.error)) {
                // A crash here has no debt; the fresh owner must see an empty
                // WAL suffix and must never publish the operation twice.
                if (!fault("after-cleanup")) return result;
                result.error="VolumeMetadataInjectedAfterCleanup";
                result.commit_recovery_required=true;
                result.commit_status_code=static_cast<int>(Store::CommitStatus::InvariantFailed);
                return result;
            }
        }
    }
    catch (...) { result.error = "VolumeRenameException"; }
    if (acceptance_started)
    {
        // Even ambiguous acceptance keeps its source checkpoint owned until
        // canonical startup recovery proves publication and cleans the WAL.
        result.commit_recovery_required = true;
        result.commit_recovery_reason = L"VolumeRenameRequiresRecovery";
        result.commit_status_code = static_cast<int>(Store::CommitStatus::InvariantFailed);
        std::vector<std::uint64_t> pins{rename.checkpoint}; std::string error;
        for (const auto& entry : owner.CheckpointCensusSnapshot())
            if (entry.volume_object_id == rename.volume) pins.insert(pins.end(), entry.required_checkpoint_xids.begin(), entry.required_checkpoint_xids.end());
        (void)owner.UpdateRequiredCheckpointXids(rename.volume, pins, error, true);
    }
    return result;
}

static std::optional<bool> ReplayVolumeMetadata(Owner& owner, TransactionManager& journal, std::uint64_t oid, std::string& error, bool limits)
{
    std::vector<TransactionManager::AcceptedTransaction> transactions;
    if (!journal.LoadAcceptedTransactionsSinceCleanup(transactions, &error)) return false;
    bool found = false;
    for (const auto& tx : transactions) for (const auto& record : tx.mutations)
        found |= record.operation == (limits ? WriteAheadLog::OperationKind::SetVolumeQuotaReserve : WriteAheadLog::OperationKind::RenameVolume);
    if (!found) return std::nullopt;
    if (!owner.CheckpointCensusRequired() || transactions.size() != 1 || transactions[0].mutations.size() != 1)
        return Fail(error, "VolumeRenameReplayNotIsolated");
    if (limits && !QuotaSessionsIdle(owner,error)) return false;
    if (limits) for (const auto& entry : owner.CheckpointCensusSnapshot())
        if (entry.volume_object_id != oid && entry.unapplied_accepted_work)
            return Fail(error, "VolumeQuotaReserveSiblingReplayConflict");
    const auto& tx = transactions[0];
    Store::MutationRequest request; NativeVolumeRename rename;
    if (!VolumeMetadataFromWal(tx.mutations[0], request) || !DecodeNativeVolumeMetadata(request.inline_payload, rename) ||
        rename.volume != oid || rename.checkpoint != tx.preimage_checkpoint_xid) return Fail(error, "VolumeRenameReplayIdentityInvalid");
    if (rename.quota_reserve) {
        if (!QuotaJournalMatchesOwner(journal, owner, rename.container_uuid, rename.volume))
            return Fail(error, "VolumeQuotaReserveReplayJournalIdentityMismatch");
    }
    std::vector<std::uint64_t> pins;
    if (!journal.LoadRequiredCheckpointXidsSinceCleanup(pins, &error) ||
        !owner.UpdateRequiredCheckpointXids(oid, pins, error, true) || !owner.RefreshSessionForRecovery(oid, error)) return false;
    auto* store = owner.FindSessionStore(oid);
    if (!store) return Fail(error, "VolumeRenameReplaySessionMissing");
    if (store->CheckpointXid() == rename.checkpoint)
    {
        const auto result = owner.Commit(oid, {request}, {}, {}, {}, true, rename.checkpoint, {},
            [&](const Store& live, std::uint64_t, std::string& why) { return VerifyPublishedVolumeRename(live, rename, why); });
        if (!result.committed || result.commit_recovery_required || result.commit_status_code != static_cast<int>(Store::CommitStatus::Committed))
        { error = result.error; return false; }
    }
    else if (!owner.InspectCurrentSession(oid,
        [&](const Store& live, std::string& why) { return VerifyPublishedVolumeRename(live, rename, why); },
        error, true)) return false;
    return Finalize(owner, journal, oid, tx.accepted_sequence, error);
}
bool PrepareVolumeRename(Owner& owner, std::uint64_t oid, std::string_view label, VolumeRenamePlan& out, std::string& error)
{ return PrepareVolumeMetadata(owner, oid, label, {}, out, error); }
bool PrepareVolumeQuotaReserve(Owner& owner, std::uint64_t oid, std::uint64_t quota, std::uint64_t reserve, VolumeQuotaReservePlan& out, std::string& error)
{ return PrepareVolumeMetadata(owner, oid, {}, {{reserve, quota}}, out, error); }
bool ValidateVolumeRenameMutation(const Store& store, const Store::MutationRequest& request, std::string& error)
{ return request.operation == Store::MutationOperation::RenameVolume && ValidateVolumeMetadataMutation(store, request, error); }
bool PlanVolumeRenameCheckpoint(const catalog::RandomAccessSource& source, const catalog::AppleCheckpointView& cp,
    const NativeVolumeRename& rename, const std::vector<std::uint64_t>& pins, AppleVolumeTransactionPlan& out, std::string& error)
{ return !rename.quota_reserve && PlanVolumeMetadataCheckpoint(source, cp, rename, pins, out, error); }
bool VolumeRenameFromWal(const WriteAheadLog::Record& record, Store::MutationRequest& out)
{ return record.operation == WriteAheadLog::OperationKind::RenameVolume && VolumeMetadataFromWal(record, out); }
Result ApplyVolumeRename(Owner& owner, TransactionManager& journal, VolumeRenamePlan& plan, VolumeRenameObserver observer)
{ if (plan.request.operation != Store::MutationOperation::RenameVolume) { plan.consumed=true; Result r; r.error="VolumeRenamePlanKindMismatch"; return r; } return ApplyVolumeMetadata(owner, journal, plan, observer); }
Result ApplyVolumeQuotaReserve(Owner& owner, TransactionManager& journal, VolumeQuotaReservePlan& plan)
{ if (plan.request.operation != Store::MutationOperation::SetVolumeQuotaReserve) { plan.consumed=true; Result r; r.error="VolumeQuotaReservePlanKindMismatch"; return r; } return ApplyVolumeMetadata(owner, journal, plan); }
std::optional<bool> ReplayVolumeRename(Owner& owner, TransactionManager& journal, std::uint64_t oid, std::string& error)
{ return ReplayVolumeMetadata(owner, journal, oid, error, false); }
std::optional<bool> ReplayVolumeQuotaReserve(Owner& owner, TransactionManager& journal, std::uint64_t oid, std::string& error)
{ return ReplayVolumeMetadata(owner, journal, oid, error, true); }

}
