#include "SoftwareVolumeTransition.h"
#include "SoftwareVolumeKeyRotation.h"
#include "SoftwareTransitionCompletedProofSource.h"
#include "AppleSpacemanAllocator.h"
#include "ApfsExtendedRecordCodec.h"
#include "ApfsEncryptedWriteTransform.h"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <map>
#include <set>
#include <stdexcept>
#include <thread>

namespace apfsaccess::catalog
{
namespace
{
constexpr std::uint32_t block_size = 4096;
void Wipe(std::vector<std::byte>& bytes) noexcept
{
    if (!bytes.empty()) SecureZeroMemory(bytes.data(), bytes.size());
}
bool Nonzero(const std::array<std::byte, 32>& bytes)
{
    return std::any_of(bytes.begin(), bytes.end(), [](auto b) { return b != std::byte{}; });
}
bool Block(const RandomAccessSource& source, std::uint64_t block, std::vector<std::byte>& bytes)
{
    return block < source.SizeBytes() / block_size && source.Read(block * block_size, block_size, bytes) &&
        bytes.size() == block_size;
}
bool CollectDescriptorXids(const RandomAccessSource& source, const NxSuperblock& nx,
    std::set<std::uint64_t>& xids, std::string& error)
{
    for (std::uint64_t i = 0; i < nx.xp_desc_block_count; ++i) {
        std::vector<std::byte> raw;
        if (!Block(source, nx.xp_desc_base_block + i, raw)) { error = "SoftwareTransitionDescriptorReadFailed"; return false; }
        const auto candidate = ParseNxSuperblock(raw);
        if (!candidate) {
            if (ReadU32LE(raw, 0x20).value_or(0) == kNxsbMagic ||
                (ReadU32LE(raw, 0x18).value_or(0) & kObjectTypeMask) == kNxSuperblockObjectType) {
                error = VerifyObjectChecksum(raw, block_size)
                    ? "SoftwareTransitionDescriptorStructureInvalid" : "SoftwareTransitionDescriptorChecksumInvalid";
                return false;
            }
            continue;
        }
        if (candidate->uuid_hex != nx.uuid_hex || candidate->block_size != nx.block_size ||
            candidate->block_count != nx.block_count || candidate->xid > nx.xid) {
            error = "SoftwareTransitionDescriptorIdentityMismatch"; return false;
        }
        xids.insert(candidate->xid);
    }
    return true;
}
bool Allocated(const AppleSpacemanView& allocator, std::uint64_t block)
{
    for (const auto& chunk : allocator.chunks) if (block >= chunk.start_block && block - chunk.start_block < chunk.block_count) {
        const auto bit = block - chunk.start_block;
        return bit / 8 < chunk.allocation_bitmap.size() &&
            (std::to_integer<unsigned>(chunk.allocation_bitmap[bit / 8]) & (1u << (bit % 8)));
    }
    return false;
}
std::array<std::byte, 32> Binding(std::string_view identity, std::string_view container,
    std::uint64_t oid, std::string_view volume)
{
    const auto text = "apfs-image-writer-binding-v2:" + std::string(identity) + ":" + std::string(container) + ":" +
        std::to_string(oid) + ":" + std::string(volume);
    std::array<std::byte, 32> result{};
    if (BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0,
        reinterpret_cast<PUCHAR>(const_cast<char*>(text.data())), static_cast<ULONG>(text.size()),
        reinterpret_cast<PUCHAR>(result.data()), static_cast<ULONG>(result.size())) < 0)
        throw std::runtime_error("SoftwareTransitionBindingHashFailed");
    return result;
}
bool SuccessorOwnsSlot(const RandomAccessSource& source, const ContainerCheckpointView& current,
    const SoftwareVolumeRetainedGeneration& generation)
{
    const auto& nx = current.superblock;
    std::set<std::uint64_t> candidates{nx.xid};
    // Retirement needs a positive complete successor occupying an old slot.
    // An unrelated torn next NXSB is not such proof and cannot invalidate it.
    // Factories still use the separate strict descriptor scan before minting.
    for (std::uint64_t i = 0; i < nx.xp_desc_block_count; ++i) {
        std::vector<std::byte> bytes;
        if (!Block(source, nx.xp_desc_base_block + i, bytes)) return false;
        const auto candidate = ParseNxSuperblock(bytes);
        if (candidate && candidate->xid > generation.checkpoint.superblock.xid && candidate->xid <= nx.xid)
            candidates.insert(candidate->xid);
    }
    std::set<std::uint64_t> successor_slots;
    for (auto xid : candidates) {
        if (xid <= generation.checkpoint.superblock.xid) continue;
        std::string detail;
        auto cp = LoadContainerCheckpointView(source, 0, source.SizeBytes(), detail, xid);
        if (!cp) continue;
        successor_slots.insert(cp->superblock_physical_block);
        successor_slots.insert(cp->checkpoint_map_blocks.begin(), cp->checkpoint_map_blocks.end());
        for (const auto& mapping : cp->mappings) {
            if (!mapping.size_bytes || mapping.size_bytes % block_size) return false;
            for (std::uint64_t i = 0; i < mapping.size_bytes / block_size; ++i) successor_slots.insert(mapping.physical_block + i);
        }
    }
    for (const auto& guard : generation.checkpoint_guards) {
        if (!successor_slots.contains(guard.physical_block)) continue;
        std::vector<std::byte> actual;
        if (!Block(source, guard.physical_block, actual)) return false;
        if (actual != guard.bytes) return true;
    }
    return false;
}
void Put(std::vector<std::byte>& bytes, std::size_t offset, std::uint64_t value, unsigned size = 8)
{
    if (offset > bytes.size() || size > bytes.size() - offset) throw std::runtime_error("SoftwareTransitionFieldBounds");
    for (unsigned i = 0; i < size; ++i) bytes[offset + i] = static_cast<std::byte>(value >> (8 * i));
}
struct Rows
{
    std::vector<BtreeRecord> values;
    ~Rows() { for (auto& row : values) { Wipe(row.key); Wipe(row.value); } }
};
struct BytesOwner
{
    std::vector<std::byte> bytes;
    ~BytesOwner() { Wipe(bytes); }
};
struct InodeOwner
{
    rw::AppleInodeRecord value;
    ~InodeOwner() { for (auto& field : value.extended_fields) Wipe(field.data); }
};
class TrackedSource final : public ImmutableEncryptedReadSource
{
public:
    explicit TrackedSource(std::shared_ptr<const ImmutableEncryptedReadSource> source) : inner(std::move(source)) {}
    const std::shared_ptr<const ImmutableEncryptedReadSource> inner;
    mutable std::map<std::uint64_t, std::vector<std::byte>> guards;
    ~TrackedSource() { for (auto& [block, bytes] : guards) { (void)block; Wipe(bytes); } }
    std::string SourceIdentity() const override { return inner->SourceIdentity(); }
    std::uint64_t Revision() const override { return inner->Revision(); }
    std::uint64_t SizeBytes() const override { return inner->SizeBytes(); }
    std::shared_ptr<ApfsReadBudget> ReadBudget() const override { return inner->ReadBudget(); }
    bool Read(std::uint64_t at, std::size_t size, std::vector<std::byte>& out) const override
    {
        out.clear();
        if (at > SizeBytes() || size > SizeBytes() - at || !ReadBudget()) return false;
        std::vector<std::byte> result(size);
        for (std::size_t done = 0; done < size;) {
            const auto block = (at + done) / block_size;
            std::vector<std::byte> raw;
            if (!Block(*inner, block, raw)) return false;
            auto found = guards.find(block);
            if (found != guards.end() && found->second != raw) return false;
            if (found == guards.end()) {
                if (guards.size() >= 1024 || !ReadBudget()->Materialize(1, block_size + 96)) return false;
                guards.emplace(block, raw);
            }
            const auto within = static_cast<std::size_t>((at + done) % block_size);
            const auto count = (std::min)(size - done, block_size - within);
            std::copy_n(raw.begin() + within, count, result.begin() + done); done += count;
        }
        out = std::move(result); return true;
    }
};
class TransitionCandidate final : public ImmutableEncryptedReadSource
{
public:
    TransitionCandidate(std::shared_ptr<const ImmutableEncryptedReadSource> source, const rw::AppleCheckpointPublicationPlan& plan)
        : inner(std::move(source)), xid(plan.transaction_xid)
    {
        for (const auto& write : plan.before_superblock_writes)
            if (write.bytes.size() != block_size || !blocks.emplace(write.physical_block, &write.bytes).second)
                throw std::runtime_error("SoftwareTransitionCandidateDuplicate");
        if (plan.superblock_write.bytes.size() != block_size ||
            !blocks.emplace(plan.superblock_write.physical_block, &plan.superblock_write.bytes).second)
            throw std::runtime_error("SoftwareTransitionCandidateSwitch");
    }
    const std::shared_ptr<const ImmutableEncryptedReadSource> inner;
    const std::uint64_t xid;
    std::map<std::uint64_t, const std::vector<std::byte>*> blocks;
    std::string SourceIdentity() const override { return inner->SourceIdentity() + ":transition-candidate:" + std::to_string(xid); }
    std::uint64_t Revision() const override { return inner->Revision() ^ xid; }
    std::uint64_t SizeBytes() const override { return inner->SizeBytes(); }
    std::shared_ptr<ApfsReadBudget> ReadBudget() const override { return inner->ReadBudget(); }
    bool Read(std::uint64_t at, std::size_t size, std::vector<std::byte>& out) const override
    {
        out.clear();
        if (at > SizeBytes() || size > SizeBytes() - at || !ReadBudget()->Read(size)) return false;
        std::vector<std::byte> result(size);
        for (std::size_t done = 0; done < size;) {
            const auto block = (at + done) / block_size; const auto found = blocks.find(block);
            std::vector<std::byte> raw;
            if (found == blocks.end() && !Block(*inner, block, raw)) return false;
            const auto& bytes = found == blocks.end() ? raw : *found->second;
            const auto within = static_cast<std::size_t>((at + done) % block_size);
            const auto count = (std::min)(size - done, block_size - within);
            std::copy_n(bytes.begin() + within, count, result.begin() + done); done += count;
        }
        out = std::move(result); return true;
    }
};
bool Tree(const RandomAccessSource& source, const AppleObjectLocation& location, std::uint64_t xid,
    Rows& records, std::set<std::uint64_t>* owners, std::string& error)
{
    std::vector<std::uint64_t> blocks;
    BtreeReadPolicy policy; policy.enforce_object_identity = true; policy.require_complete_traversal = true;
    policy.reject_unsupported_flags = true; policy.root_object_id = location.object_id;
    policy.storage_type = location.type; policy.subtype = location.subtype; policy.visited_physical_blocks = &blocks;
    if (!ReadBtreeLeafRecords(source, block_size, location.physical_block, true, 0, xid, policy, records.values, error)) return false;
    if (owners) owners->insert(blocks.begin(), blocks.end());
    return true;
}
bool Compose(const RandomAccessSource& source, const ContainerCheckpointView& cp,
    const AppleSpacemanView* previous, const rw::AppleSpacemanAllocationPlan* allocation,
    std::span<const rw::AppleCheckpointPhysicalWrite> writes, const std::vector<std::uint64_t>& required,
    std::uint64_t container_omap, rw::AppleCheckpointPublicationPlan& output, std::string& error,
    const rw::AppleCheckpointKeylockerReplacement* replacement = nullptr)
{
    rw::AppleCheckpointPublicationRequest request;
    struct ClearRequest {
        rw::AppleCheckpointPublicationRequest& value;
        ~ClearRequest() {
            for (auto& write : value.allocator_owned_writes) Wipe(write.bytes);
            for (auto& object : value.ephemeral_objects) Wipe(object.bytes);
        }
    } clear{request};
    request.expected_checkpoint_xid = cp.superblock.xid; request.transaction_xid = cp.superblock.next_xid;
    request.next_object_id = cp.superblock.next_oid; request.container_object_map_oid = container_omap;
    request.required_checkpoint_xids = required; request.allocator_owned_writes.assign(writes.begin(), writes.end());
    std::map<std::uint64_t, rw::AppleCheckpointEphemeralObject> objects;
    if (allocation) {
        rw::AppleCheckpointEphemeralObject sm;
        sm.object = allocation->updated_spaceman.object; sm.object.physical_block = 0;
        sm.bytes = allocation->updated_spaceman.bytes; sm.object.size_bytes = static_cast<std::uint32_t>(sm.bytes.size());
        objects.emplace(sm.object.object_id, std::move(sm));
        for (const auto& write : allocation->writes) {
            if (write.kind == rw::AppleSpacemanWriteKind::FreeQueueTree) {
                if (!write.object_location || write.physical_block) { error = "SoftwareTransitionAllocatorObject"; return false; }
                rw::AppleCheckpointEphemeralObject object;
                object.object = *write.object_location; object.object.physical_block = 0; object.bytes = write.bytes;
                if (!objects.emplace(object.object.object_id, std::move(object)).second) { error = "SoftwareTransitionAllocatorDuplicate"; return false; }
                request.next_object_id = (std::max)(request.next_object_id, write.object_location->object_id + 1);
            } else {
                if (!write.physical_block || write.object_location || write.bytes.size() != block_size) {
                    error = "SoftwareTransitionAllocatorWrite"; return false;
                }
                request.allocator_owned_writes.push_back({write.physical_block, write.bytes});
            }
        }
    }
    for (const auto& mapping : cp.mappings) {
        if (objects.contains(mapping.object_id)) continue;
        bool retired = false;
        if (previous) for (const auto& queue : previous->free_queues)
            if (objects.contains(queue.tree_oid) && std::find(queue.tree_blocks.begin(), queue.tree_blocks.end(), mapping.physical_block) != queue.tree_blocks.end())
                retired = true;
        if (retired) { request.retired_ephemeral_object_ids.push_back(mapping.object_id); continue; }
        if (mapping.size_bytes != block_size) { error = "SoftwareTransitionEphemeralSize"; return false; }
        rw::AppleCheckpointEphemeralObject object; object.file_system_oid = mapping.file_system_oid;
        object.object = {mapping.object_id, cp.superblock.next_xid, 0, mapping.type, mapping.subtype, mapping.size_bytes};
        if (!Block(source, mapping.physical_block, object.bytes)) return false;
        Put(object.bytes, 16, cp.superblock.next_xid);
        if (!rw::FinalizeAppleObjectChecksum(object.bytes, error)) return false;
        objects.emplace(mapping.object_id, std::move(object));
    }
    for (auto& [oid, object] : objects) { (void)oid; request.ephemeral_objects.push_back(std::move(object)); }
    if (replacement && ReadU64LE(cp.superblock_bytes, 0x510) == 0 && ReadU64LE(cp.superblock_bytes, 0x518) == 0) {
        if (!previous || !allocation) { error = "SoftwareTransitionInitializationAllocationRequired"; return false; }
        return rw::PlanAppleCheckpointKeylockerInitialization(source, cp, request, output, error,
            {replacement->start_block, replacement->block_count});
    }
    return replacement ? rw::PlanAppleCheckpointPublication(source, cp, request, output, error, *replacement) :
        rw::PlanAppleCheckpointPublication(source, cp, request, output, error);
}
bool InReservedArea(const AppleCheckpointView& current, std::uint64_t block)
{
    const auto within = [block](std::uint64_t first, std::uint64_t count) { return block >= first && block - first < count; };
    const auto& nx = current.container.superblock; const auto& pool = current.spaceman.internal_pool;
    return !block || within(nx.xp_desc_base_block, nx.xp_desc_block_count) || within(nx.xp_data_base_block, nx.xp_data_block_count) ||
        within(pool.base_block, pool.block_count) || within(pool.bitmap_base_block, pool.bitmap_block_count);
}
std::array<std::byte, 32> AllocatorDigest(const RandomAccessSource& source, const AppleSpacemanView& allocator)
{
    std::vector<std::byte> bytes;
    const auto append = [&](const auto& value) { bytes.insert(bytes.end(), value.begin(), value.end()); };
    append(allocator.bytes);
    for (const auto& device : allocator.devices) {
        for (const auto& cib : device.cibs) append(cib.bytes);
        for (const auto& cab : device.cabs) append(cab.bytes);
    }
    for (const auto& chunk : allocator.chunks) append(chunk.allocation_bitmap);
    for (const auto& bitmap : allocator.internal_pool.active_bitmaps) append(bitmap.bytes);
    for (const auto& queue : allocator.free_queues) for (auto block : queue.tree_blocks) {
        std::vector<std::byte> raw;
        if (!Block(source, block, raw)) throw std::runtime_error("SoftwareTransitionAllocatorQueueReadFailed");
        append(raw);
    }
    std::array<std::byte, 32> digest{};
    if (BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0, reinterpret_cast<PUCHAR>(bytes.data()), static_cast<ULONG>(bytes.size()),
        reinterpret_cast<PUCHAR>(digest.data()), static_cast<ULONG>(digest.size())) < 0)
        throw std::runtime_error("SoftwareTransitionAllocatorHashFailed");
    return digest;
}
bool SerializeLeaf(const Rows& rows, std::uint64_t oid, std::uint64_t physical, std::uint64_t xid,
    std::uint32_t storage, std::uint32_t subtype, rw::AppleBtreeKeyOrder order,
    std::vector<std::byte>& output, std::string& error)
{
    rw::AppleBtreeOptions options;
    options.block_size = block_size; options.xid = xid; options.root_object_id = oid;
    options.root_physical_block = physical; options.storage_type = storage; options.subtype = subtype;
    options.key_order = order; options.max_nodes = 1;
    if (storage == kObjectPhysical) options.tree_flags = rw::kAppleBtreePhysical;
    if (order == rw::AppleBtreeKeyOrder::ObjectMap) {
        options.fixed_key_size = 16; options.fixed_value_size = 16;
    }
    rw::AppleSerializedBtree serialized;
    if (!rw::SerializeAppleBtree(rows.values, options, serialized, error) || serialized.objects.size() != 1) {
        for (auto& object : serialized.objects) Wipe(object.bytes);
        error = "SoftwareTransitionSingleLeafRequired:" + error; return false;
    }
    output = std::move(serialized.objects.front().bytes); return true;
}
bool SameRows(const Rows& a, const Rows& b)
{
    return a.values.size() == b.values.size() && std::equal(a.values.begin(), a.values.end(), b.values.begin(),
        [](const auto& x, const auto& y) { return x.key == y.key && x.value == y.value; });
}
void AddRange(SoftwareVolumeRetainedGeneration& output, std::uint64_t block, SoftwareVolumeOwnerKind kind)
{
    output.ranges.push_back({block, 1, kind});
}
bool CaptureGeneration(const std::shared_ptr<TrackedSource>& source, const AppleCheckpointView& current,
    ApfsEncryptedReadSession& session, std::uint64_t xid, std::uint64_t volume_oid, KeybagLength length,
    SoftwareVolumeRetainedGeneration& output, std::set<std::uint64_t>& metadata,
    std::set<std::uint64_t>& payload, std::set<std::uint64_t>& selected_fs,
    std::set<std::uint64_t>& referenced_fs, Rows* current_records, std::string& error)
{
    const auto fail = [&](const char* reason) { error = reason; return false; };
    EncryptedReadError read_error{};
    auto context = xid == current.container.superblock.xid
        ? session.CreateMetadataReadContext(read_error)
        : session.CreateRetainedVerificationContext(xid, error);
    if (!context) {
        if (error.empty()) error = "SoftwareTransitionHistoricalKeyEraUnproved";
        return false;
    }
    auto view = context ? LoadAppleCheckpointView(*source, 0, source->SizeBytes(), error, *context, xid, false) : std::nullopt;
    if (!view || view->volumes.size() != 1) return fail("SoftwareTransitionHistoricalMetadataUnavailable");
    const auto& volume = view->volumes.front();
    if (volume.superblock.object_id != volume_oid || volume.superblock.uuid_hex != current.volumes.front().superblock.uuid_hex ||
        volume.superblock.fs_flags != kFsFlagOneKey || !volume.extentref_tree || volume.file_extent_tree ||
        volume.object_map.snapshot_tree_oid || view->container_object_map.snapshot_tree_oid)
        return fail("SoftwareTransitionHistoricalProfileUnsupported");
    std::vector<std::byte> apsb;
    if (!Block(*source, volume.superblock_object.physical_block, apsb) || ReadU64LE(apsb, 0xD8) != 0 ||
        ReadU64LE(apsb, 0x3D0) != 0 || ReadU64LE(apsb, 0xA0) != 0 || ReadU64LE(apsb, 0xA8) != 0 ||
        volume.superblock.snap_meta_ext_oid) return fail("SoftwareTransitionSnapshotOrRollingUnsupported");
    std::set<std::uint64_t> local_metadata{volume.superblock_object.physical_block, volume.root_tree.physical_block,
        volume.object_map.object.physical_block, view->container_object_map.object.physical_block};
    Rows filesystem, references, volume_omap, container_omap;
    if (!ReadAppleVolumeFileSystemRecords(*source, view->container, volume, filesystem.values, error, *context) ||
        !Tree(*source, *volume.extentref_tree, xid, references, &local_metadata, error) ||
        !Tree(*source, volume.object_map.tree, xid, volume_omap, &local_metadata, error) ||
        !Tree(*source, view->container_object_map.tree, xid, container_omap, &local_metadata, error)) return false;
    if (container_omap.values.size() != 1 || ReadU64LE(container_omap.values.front().key, 0) != volume_oid ||
        ReadU64LE(container_omap.values.front().key, 8) != volume.superblock.xid)
        return fail("SoftwareTransitionContainerOmapHistoryUnsupported");
    selected_fs.insert(volume.root_tree.physical_block);
    for (const auto& row : volume_omap.values) {
        const auto flags = ReadU32LE(row.value, 0).value_or(~0u);
        if (flags == 1) continue;
        if (flags != 4 || ReadU64LE(row.key, 0) != volume.root_tree.object_id || ReadU32LE(row.value, 4) != block_size)
            return fail("SoftwareTransitionVolumeOmapHistoryUnsupported");
        const auto block = ReadU64LE(row.value, 8).value_or(0);
        referenced_fs.insert(block); local_metadata.insert(block);
    }
    if (volume.snapshot_metadata_tree) {
        Rows snapshots;
        if (!Tree(*source, *volume.snapshot_metadata_tree, xid, snapshots, &local_metadata, error) || !snapshots.values.empty())
            return fail("SoftwareTransitionSnapshotsUnsupported");
    }
    for (const auto& row : filesystem.values)
        if ((ReadU64LE(row.key, 0).value_or(0) >> 60) == 4 && (ReadU16LE(row.value, 0).value_or(0) & rw::kAppleXattrDataStream))
            return fail("SoftwareTransitionExternalStreamsUnsupported");
    std::vector<rw::ApplePhysicalExtentRecord> extents;
    if (!rw::ValidateAppleEncryptedPayloadExtentGraph(filesystem.values, references.values, block_size,
        current.container.superblock.block_count, extents, error)) return false;
    std::set<std::uint64_t> local_payload;
    for (const auto& extent : extents) {
        if (extent.reference_count != 1 || extent.block_count > 64) return fail("SoftwareTransitionExclusivePayloadRequired");
        for (std::uint64_t i = 0; i < extent.block_count; ++i) local_payload.insert(extent.physical_block + i);
    }
    if (local_payload.size() > 64 || local_metadata.size() > 192) return fail("SoftwareTransitionOwnerLimit");
    UnlockError unlock{}; std::uint64_t container_bag = 0, volume_bag = 0;
    auto bags = InspectPasswordKeybagMetadataAtCheckpoint(*source, volume_oid, length, xid, unlock, container_bag, volume_bag);
    if (!bags || bags->users.size() != 1) return fail("SoftwareTransitionHistoricalKeybagInvalid");
    const std::set<std::uint64_t> keybags{container_bag, volume_bag};
    if (keybags.size() != 2 || local_metadata.contains(container_bag) || local_metadata.contains(volume_bag))
        return fail("SoftwareTransitionHistoricalKeybagOverlap");
    const std::array<const std::set<std::uint64_t>*, 3> owner_sets{&local_metadata, &local_payload, &keybags};
    for (const auto* blocks : owner_sets) for (auto block : *blocks) {
        if (InReservedArea(current, block) || !Allocated(current.spaceman, block) ||
            (blocks != &local_payload && local_payload.contains(block)))
            return fail("SoftwareTransitionHistoricalOwnerUnproved");
        std::vector<std::byte> raw;
        if (!Block(*source, block, raw)) return false;
        output.graph_guards.push_back({block, std::move(raw)});
        AddRange(output, block, blocks == &local_payload ? SoftwareVolumeOwnerKind::Payload :
            blocks == &keybags ? SoftwareVolumeOwnerKind::Keybag : SoftwareVolumeOwnerKind::Metadata);
    }
    output.checkpoint = view->container;
    std::set<std::uint64_t> checkpoint_blocks{view->container.superblock_physical_block};
    checkpoint_blocks.insert(view->container.checkpoint_map_blocks.begin(), view->container.checkpoint_map_blocks.end());
    for (const auto& mapping : view->container.mappings) {
        if (mapping.size_bytes != block_size) return fail("SoftwareTransitionHistoricalEphemeralSize");
        checkpoint_blocks.insert(mapping.physical_block);
    }
    for (auto block : checkpoint_blocks) {
        std::vector<std::byte> raw;
        if (!Block(*source, block, raw)) return false;
        output.checkpoint_guards.push_back({block, std::move(raw)});
    }
    metadata.insert(local_metadata.begin(), local_metadata.end()); metadata.insert(keybags.begin(), keybags.end());
    payload.insert(local_payload.begin(), local_payload.end());
    if (current_records) current_records->values = std::move(filesystem.values);
    return true;
}
#include "SoftwareTransitionPlainAttributes.inc"
bool CapturePlainGeneration(const std::shared_ptr<TrackedSource>& source, const AppleCheckpointView& current,
    const AppleCheckpointView& allocation_authority, SoftwareVolumeRetainedGeneration& output,
    Rows& filesystem, Rows& references, std::string& error)
{
    const auto fail = [&](const char* reason) { error = reason; return false; };
    if (current.volumes.size() != 1 || allocation_authority.volumes.size() != 1 ||
        current.container.superblock.xid > allocation_authority.container.superblock.xid ||
        current.container.superblock.uuid_hex != allocation_authority.container.superblock.uuid_hex ||
        current.container.superblock.block_count != allocation_authority.container.superblock.block_count ||
        current.volumes.front().superblock.uuid_hex != allocation_authority.volumes.front().superblock.uuid_hex ||
        current.volumes.front().superblock.object_id != allocation_authority.volumes.front().superblock.object_id ||
        !rw::VerifyAppleSpacemanOwnershipUnchanged(*source, 0, source->SizeBytes(),
            allocation_authority.container, allocation_authority.spaceman, error))
        return fail("SoftwareTransitionPlainCurrentAllocationAuthorityRequired");
    const auto& volume = current.volumes.front(); const auto& nx = current.container.superblock;
    std::set<std::uint64_t> metadata{volume.superblock_object.physical_block, volume.object_map.object.physical_block,
        current.container_object_map.object.physical_block};
    if (volume.superblock.fs_flags != kFsFlagUnencrypted || !volume.extentref_tree || volume.file_extent_tree ||
        volume.object_map.snapshot_tree_oid || current.container_object_map.snapshot_tree_oid)
        return fail("SoftwareTransitionPlainProfileUnsupported");
    BytesOwner apsb;
    if (!Block(*source, volume.superblock_object.physical_block, apsb.bytes) || ReadU64LE(apsb.bytes, 0xD8) != 0 ||
        ReadU64LE(apsb.bytes, 0x3D0) != 0 || ReadU64LE(apsb.bytes, 0xA0) != 0 || ReadU64LE(apsb.bytes, 0xA8) != 0 ||
        volume.superblock.snap_meta_ext_oid) return fail("SoftwareTransitionPlainSnapshotsOrRollingUnsupported");
    Rows vomap, comap;
    if (!Tree(*source, volume.root_tree, nx.xid, filesystem, &metadata, error) ||
        !Tree(*source, *volume.extentref_tree, nx.xid, references, &metadata, error) ||
        !Tree(*source, volume.object_map.tree, nx.xid, vomap, &metadata, error) ||
        !Tree(*source, current.container_object_map.tree, nx.xid, comap, &metadata, error)) return false;
    if (comap.values.size() != 1 || ReadU64LE(comap.values.front().key, 0) != volume.superblock.object_id ||
        ReadU64LE(comap.values.front().key, 8) != volume.superblock.xid)
        return fail("SoftwareTransitionPlainContainerOmapHistoryUnsupported");
    for (const auto& row : vomap.values) {
        const auto flags = ReadU32LE(row.value, 0).value_or(~0u);
        if (flags == 1) continue;
        if (flags || ReadU64LE(row.key, 0) != volume.root_tree.object_id || ReadU32LE(row.value, 4) != block_size ||
            ReadU64LE(row.value, 8) != volume.root_tree.physical_block)
            return fail("SoftwareTransitionPlainVolumeOmapHistoryUnsupported");
    }
    if (volume.snapshot_metadata_tree) {
        Rows snapshots;
        if (!Tree(*source, *volume.snapshot_metadata_tree, nx.xid, snapshots, &metadata, error) || !snapshots.values.empty())
            return fail("SoftwareTransitionPlainSnapshotsUnsupported");
    }
    for (const auto& row : filesystem.values) {
        const auto type = ReadU64LE(row.key, 0).value_or(0) >> 60;
        if (type == 7) return fail("SoftwareTransitionPlainCryptoRecordUnsupported");
    }
    std::vector<rw::ApplePhysicalExtentRecord> extents;
    if (!rw::ValidateApplePayloadExtentGraph(filesystem.values, references.values, block_size, nx.block_count, extents, error)) return false;
    {
        Rows materialized; materialized.values = filesystem.values;
        std::vector<rw::AppleXattrRecord> attributes;
        if (!MaterializeSmallPlainAttributes(*source, materialized, attributes, error)) return false;
        for (auto& attribute : attributes) Wipe(attribute.data);
    }
    output.checkpoint = current.container;
    for (const auto& extent : extents) {
        if (extent.reference_count != 1 || extent.block_count > 64) return fail("SoftwareTransitionPlainExclusivePayloadRequired");
        for (std::uint64_t i = 0; i < extent.block_count; ++i) {
            const auto block = extent.physical_block + i;
            if (!Allocated(allocation_authority.spaceman, block) || InReservedArea(allocation_authority, block) || metadata.contains(block))
                return fail("SoftwareTransitionPlainPayloadOwnerUnproved");
            BytesOwner raw; if (!Block(*source, block, raw.bytes)) return false;
            output.graph_guards.push_back({block, std::move(raw.bytes)}); AddRange(output, block, SoftwareVolumeOwnerKind::Payload);
        }
    }
    for (auto block : metadata) {
        if (!Allocated(allocation_authority.spaceman, block) || InReservedArea(allocation_authority, block)) return fail("SoftwareTransitionPlainMetadataOwnerUnproved");
        BytesOwner raw; if (!Block(*source, block, raw.bytes)) return false;
        output.graph_guards.push_back({block, std::move(raw.bytes)}); AddRange(output, block, SoftwareVolumeOwnerKind::Metadata);
    }
    std::set<std::uint64_t> checkpoint_blocks{current.container.superblock_physical_block};
    checkpoint_blocks.insert(current.container.checkpoint_map_blocks.begin(), current.container.checkpoint_map_blocks.end());
    for (const auto& mapping : current.container.mappings) {
        if (mapping.size_bytes != block_size) return fail("SoftwareTransitionPlainEphemeralSize");
        checkpoint_blocks.insert(mapping.physical_block);
    }
    for (auto block : checkpoint_blocks) {
        BytesOwner raw; if (!Block(*source, block, raw.bytes)) return false;
        output.checkpoint_guards.push_back({block, std::move(raw.bytes)});
    }
    return output.ranges.size() <= 256 && output.graph_guards.size() <= 256;
}
bool CarryCanonicalPlainKeybags(const std::shared_ptr<TrackedSource>& source,
    const SoftwareVolumeRetainedOwners& previous, SoftwareVolumeRetainedGeneration& generation, std::string& error)
{
    const auto start = ReadU64LE(generation.checkpoint.superblock_bytes, 0x510).value_or(0);
    if (!start || ReadU64LE(generation.checkpoint.superblock_bytes, 0x518) != 1) {
        error = "SoftwareTransitionPlainRetainedBagRangeUnsupported"; return false;
    }
    for (const auto& proved : previous.Generations()) {
        if (ReadU64LE(proved.checkpoint.superblock_bytes, 0x510) != start ||
            ReadU64LE(proved.checkpoint.superblock_bytes, 0x518) != 1) continue;
        const bool owns_container = std::any_of(proved.ranges.begin(), proved.ranges.end(), [&](const auto& range) {
            return range.kind == SoftwareVolumeOwnerKind::Keybag && range.start_block == start && range.block_count == 1;
        });
        if (!owns_container) continue;
        for (const auto& range : proved.ranges) if (range.kind == SoftwareVolumeOwnerKind::Keybag) {
            const auto raw = std::find_if(proved.graph_guards.begin(), proved.graph_guards.end(),
                [&](const auto& guard) { return guard.physical_block == range.start_block; });
            BytesOwner actual;
            if (range.block_count != 1 || raw == proved.graph_guards.end() ||
                std::any_of(generation.graph_guards.begin(), generation.graph_guards.end(),
                    [&](const auto& guard) { return guard.physical_block == range.start_block; }) ||
                !Block(*source, range.start_block, actual.bytes) || actual.bytes != raw->bytes) {
                error = "SoftwareTransitionPlainRetainedBagOwnerUnproved"; return false;
            }
            generation.ranges.push_back(range); generation.graph_guards.push_back(*raw);
        }
        return true;
    }
    error = "SoftwareTransitionPlainRetainedBagAuthorityMissing"; return false;
}

class RetiredKeybagTemplateSource final : public ImmutableEncryptedReadSource
{
    const std::shared_ptr<TrackedSource> source_;
    const SoftwareVolumeRetainedGeneration& generation_;
public:
    RetiredKeybagTemplateSource(std::shared_ptr<TrackedSource> source, const SoftwareVolumeRetainedGeneration& generation)
        : source_(std::move(source)), generation_(generation) {}
    std::uint64_t SizeBytes() const override { return source_->SizeBytes(); }
    std::string SourceIdentity() const override { return source_->SourceIdentity(); }
    std::uint64_t Revision() const override { return source_->Revision(); }
    std::shared_ptr<ApfsReadBudget> ReadBudget() const override { return source_->ReadBudget(); }
    bool Read(std::uint64_t at, std::size_t count, std::vector<std::byte>& bytes) const override
    {
        if (!Revision() || at > SizeBytes() || count > SizeBytes() - at || !source_->Read(at, count, bytes) || bytes.size() != count)
            return false;
        const auto overlay = [&](std::uint64_t block, const std::vector<std::byte>& raw) {
            const auto begin = block * block_size;
            const auto first = (std::max)(at, begin), last = (std::min)(at + count, begin + raw.size());
            if (first < last) std::copy(raw.begin() + (first - begin), raw.begin() + (last - begin), bytes.begin() + (first - at));
        };
        for (const auto& guard : generation_.checkpoint_guards) overlay(guard.physical_block, guard.bytes);
        overlay(0, generation_.checkpoint.superblock_bytes);
        return Revision() != 0;
    }
};

bool CaptureRetiredKeybagTemplate(const std::shared_ptr<TrackedSource>& source, const AppleCheckpointView& current,
    const SoftwareVolumeRetainedOwners& owners, const std::array<std::byte, 32>& journal_identity,
    std::shared_ptr<const ImmutableEncryptedReadSource>& template_source, PasswordUnlockRequest& selection, std::string& error)
{
    const auto fail = [&](const char* reason) { error = reason; return false; };
    std::vector<SoftwareVolumeOwnedRange> exclusions;
    if (!owners.RevalidateProtectedHistory(*source, journal_identity, exclusions, error)) return false;
    const auto revision = source->Revision();
    const auto& nx = current.container.superblock;
    const auto bag = ReadU64LE(current.container.superblock_bytes, 0x510).value_or(0);
    if (!revision || !bag || ReadU64LE(current.container.superblock_bytes, 0x518) != 1)
        return fail("SoftwareTransitionRetiredTemplateCurrentBagRequired");
    // Only checkpoint controls are reconstructed. Every graph and bag byte is
    // read from the actual held image and proved allocated in the current map.
    for (auto it = owners.Generations().rbegin(); it != owners.Generations().rend(); ++it) {
        const auto& generation = *it;
        const auto& old = generation.checkpoint.superblock;
        if (ReadU64LE(generation.checkpoint.superblock_bytes, 0x510) != bag ||
            ReadU64LE(generation.checkpoint.superblock_bytes, 0x518) != 1 || old.uuid_hex != nx.uuid_hex ||
            old.block_count != nx.block_count || old.fs_oids != nx.fs_oids || old.block_size != block_size ||
            old.xp_desc_base_block != nx.xp_desc_base_block || old.xp_desc_block_count != nx.xp_desc_block_count ||
            old.xp_data_base_block != nx.xp_data_base_block || old.xp_data_block_count != nx.xp_data_block_count)
            continue;
        bool retired = false;
        if (!owners.VerifyGenerationRetirement(*source, journal_identity, old.xid, retired, error)) return false;
        if (!retired) continue;
        std::set<std::uint64_t> graph, bags;
        for (const auto& guard : generation.graph_guards) {
            BytesOwner actual;
            if (!graph.insert(guard.physical_block).second || !Allocated(current.spaceman, guard.physical_block) ||
                guard.bytes.size() != block_size || !Block(*source, guard.physical_block, actual.bytes) || actual.bytes != guard.bytes)
                return fail("SoftwareTransitionRetiredTemplateActualGraphChanged");
        }
        for (const auto& range : generation.ranges) {
            if (!range.start_block || !range.block_count || range.start_block >= nx.block_count ||
                range.block_count > nx.block_count - range.start_block || range.block_count > 64)
                return fail("SoftwareTransitionRetiredTemplateRangeInvalid");
            for (std::uint64_t i = 0; i < range.block_count; ++i)
                if (!graph.contains(range.start_block + i)) return fail("SoftwareTransitionRetiredTemplateOwnerMissing");
            if (range.kind == SoftwareVolumeOwnerKind::Keybag) {
                if (range.block_count != 1 || !bags.insert(range.start_block).second)
                    return fail("SoftwareTransitionRetiredTemplateBagOwnersInvalid");
            }
        }
        if (bags.size() != 2 || !bags.contains(bag)) continue;
        auto candidate = std::make_shared<RetiredKeybagTemplateSource>(source, generation);
        UnlockError unlock{}; std::uint64_t container = 0, volume = 0;
        auto metadata = InspectPasswordKeybagMetadataAtCheckpoint(*candidate, owners.VolumeObjectId(), KeybagLength::IncludesHeader,
            old.xid, unlock, container, volume);
        if (!metadata || metadata->users.size() != 1 || container != bag || container == volume || !bags.contains(volume) ||
            BytesToHexLower(metadata->selection.volume_uuid.data(), 16) != owners.VolumeUuid() ||
            BytesToHexLower(metadata->selection.container_uuid.data(), 16) != owners.ContainerUuid())
            return fail("SoftwareTransitionRetiredTemplateCanonicalMetadataInvalid");
        if (source->Revision() != revision || source->ReadBudget()->Failed())
            return fail("SoftwareTransitionRetiredTemplateSourceRevoked");
        selection = metadata->selection; selection.user_uuid = metadata->users.front();
        template_source = std::move(candidate); error.clear(); return true;
    }
    return fail("SoftwareTransitionEncryptionCanonicalBagTemplateUnavailable");
}
#include "SoftwareTransitionEmptyHistory.inc"
bool TransformPayload(const crypto::SecureBytes& key, std::uint64_t crypto_id,
    std::span<const std::byte> plain, std::vector<std::byte>& ciphertext)
{
    ciphertext.clear();
    if (!key.IsLocked() || key.Size() != 32 || plain.size() != block_size || crypto_id > (UINT64_MAX - 7) / 8) return false;
    std::vector<std::byte> result(block_size);
    for (std::size_t i = 0; i < block_size; i += 512) {
        std::array<std::byte, 16> tweak{};
        const auto unit = crypto_id * 8 + i / 512;
        for (unsigned j = 0; j < 8; ++j) tweak[j] = static_cast<std::byte>(unit >> (8 * j));
        auto cipher = crypto::XtsTransform(key.Bytes(), tweak, plain.subspan(i, 512), crypto::XtsDirection::Encrypt);
        if (!cipher) return false;
        std::copy(cipher.bytes.Bytes().begin(), cipher.bytes.Bytes().end(), result.begin() + i);
    }
    ciphertext = std::move(result); return true;
}
}

std::unique_ptr<SoftwareVolumeTransitionPublication> SoftwareVolumeTransition::PrepareEncryption(
    std::shared_ptr<const ImmutableEncryptedReadSource> source, const std::string& expected_identity,
    std::uint64_t expected_revision, std::uint64_t volume_oid, const crypto::SecureBytes& password,
    PasswordUnlockBudget& budget, const std::array<std::byte, 32>& journal_identity,
    const SoftwareVolumeRetainedOwners* previous_owners, std::string& error,
    std::span<const std::uint64_t> recovery_xids, std::span<const std::uint64_t> read_xids)
{
    return PrepareEncryptionCore(std::move(source), expected_identity, expected_revision, volume_oid,
        password, budget, journal_identity, previous_owners, error, recovery_xids, read_xids, nullptr);
}

std::unique_ptr<SoftwareVolumeKeyRotationPublication> SoftwareVolumeKeyRotation::Prepare(
    std::shared_ptr<const ImmutableEncryptedReadSource> source, const std::string& expected_identity,
    std::uint64_t expected_revision, std::uint64_t volume_oid, const crypto::SecureBytes& old_password,
    const crypto::SecureBytes& new_password, PasswordUnlockBudget& budget,
    const std::array<std::byte, 32>& journal_identity, const SoftwareVolumeRetainedOwners* previous_owners,
    std::string& error, std::span<const std::uint64_t> recovery_xids, std::span<const std::uint64_t> read_xids)
{
    auto material = SoftwareVolumeTransition::PrepareEncryptionCore(std::move(source), expected_identity,
        expected_revision, volume_oid, new_password, budget, journal_identity, previous_owners,
        error, recovery_xids, read_xids, &old_password);
    if (!material) return {};
    return std::unique_ptr<SoftwareVolumeKeyRotationPublication>(new SoftwareVolumeKeyRotationPublication(std::move(material)));
}

std::unique_ptr<SoftwareVolumeTransitionPublication> SoftwareVolumeTransition::PrepareEncryptionCore(
    std::shared_ptr<const ImmutableEncryptedReadSource> source, const std::string& expected_identity,
    std::uint64_t expected_revision, std::uint64_t volume_oid, const crypto::SecureBytes& password,
    PasswordUnlockBudget& budget, const std::array<std::byte, 32>& journal_identity,
    const SoftwareVolumeRetainedOwners* previous_owners, std::string& error,
    std::span<const std::uint64_t> recovery_xids, std::span<const std::uint64_t> read_xids,
    const crypto::SecureBytes* old_password)
{
    error.clear();
    const bool rotating = old_password != nullptr;
    const bool pristine = !rotating && !previous_owners;
    const auto fail = [&](const char* reason) -> std::unique_ptr<SoftwareVolumeTransitionPublication> { error = reason; return {}; };
    if (!source || !source->ReadBudget() || expected_identity.empty() || expected_identity.size() > 8192 ||
        source->SourceIdentity() != expected_identity || source->Revision() != expected_revision || !volume_oid ||
        !password.IsLocked() || !password.Size() || !Nonzero(journal_identity) ||
        (rotating && (!old_password->IsLocked() || !old_password->Size())) ||
        recovery_xids.size() > 6 || read_xids.size() > 6)
        return fail("SoftwareTransitionEncryptionScopeInvalid");
    try {
        auto tracked = std::make_shared<TrackedSource>(std::move(source));
        std::shared_ptr<const ImmutableEncryptedReadSource> template_source = tracked;
        std::shared_ptr<ApfsEncryptedReadSession> original_session;
        std::unique_ptr<AppleEncryptedMetadataReadContext> original_context;
        PasswordUnlockRequest template_selection; bool have_template = false;
        if (rotating) {
            UnlockError unlock{}; EncryptedReadError read{};
            auto bags = InspectPasswordKeybagMetadata(*tracked, volume_oid, KeybagLength::IncludesHeader, unlock);
            if (!bags || bags->users.size() != 1) return fail("SoftwareKeyRotationCurrentBagRequired");
            template_selection = bags->selection; template_selection.user_uuid = bags->users.front(); have_template = true;
            original_session = ApfsEncryptedReadSession::Unlock(tracked, expected_identity, expected_revision,
                template_selection, old_password->Bytes(), budget, read, unlock);
            if (!original_session) return fail("SoftwareKeyRotationCurrentCredentialRefused");
            original_context = original_session->CreateMetadataReadContext(read);
            if (!original_context) return fail("SoftwareKeyRotationCurrentContextRequired");
        }
        auto current = original_context
            ? LoadAppleCheckpointView(*tracked, 0, tracked->SizeBytes(), error, *original_context)
            : LoadAppleCheckpointView(*tracked, 0, tracked->SizeBytes(), error);
        if (!current || current->volumes.size() != 1) return {};
        const auto& nx = current->container.superblock; const auto& volume = current->volumes.front();
        if (nx.block_size != block_size || nx.block_count > UINT64_MAX / block_size || nx.block_count * block_size != tracked->SizeBytes() ||
            nx.fs_oids != std::vector<std::uint64_t>{volume_oid} || nx.next_xid <= nx.xid || nx.xp_desc_noncontiguous ||
            nx.xp_data_noncontiguous || nx.xp_desc_block_count > 256 ||
            ReadU64LE(current->container.superblock_bytes, 0x4F0) != (rotating ? 4u : 0u) ||
            volume.superblock.fs_flags != (rotating ? kFsFlagOneKey : kFsFlagUnencrypted) ||
            (pristine ? ReadU64LE(current->container.superblock_bytes, 0x518) != 0 ||
                ReadU64LE(current->container.superblock_bytes, 0x510) != 0 :
                ReadU64LE(current->container.superblock_bytes, 0x518) != 1 || !ReadU64LE(current->container.superblock_bytes, 0x510).value_or(0)))
            return fail("SoftwareTransitionEncryptionCanonicalProfileUnsupported");
        std::vector<SoftwareVolumeOwnedRange> prior_exclusions;
        if (previous_owners && !previous_owners->Revalidate(*tracked, journal_identity, prior_exclusions, error)) return {};
        auto result = std::unique_ptr<SoftwareVolumeTransitionPublication>(new SoftwareVolumeTransitionPublication);
        result->before_ = rotating ? SoftwareVolumeMode::OneKeyGenerationZero : SoftwareVolumeMode::Plain;
        result->after_ = SoftwareVolumeMode::OneKeyGenerationZero;
        result->owners_ = std::unique_ptr<SoftwareVolumeRetainedOwners>(new SoftwareVolumeRetainedOwners);
        auto& certificate = *result->owners_;
        certificate.identity_ = expected_identity; certificate.container_uuid_ = nx.uuid_hex;
        certificate.volume_oid_ = volume_oid; certificate.volume_uuid_ = volume.superblock.uuid_hex;
        certificate.binding_ = Binding(expected_identity, nx.uuid_hex, volume_oid, volume.superblock.uuid_hex);
        certificate.journal_identity_ = journal_identity; certificate.minted_xid_ = nx.xid; certificate.block_count_ = nx.block_count;
        certificate.allocator_sha256_ = AllocatorDigest(*tracked, current->spaceman);
        std::set<std::uint64_t> required_set{nx.xid};
        for (auto xid : recovery_xids) if (!xid || xid > nx.xid) return fail("SoftwareTransitionEncryptionRecoveryXidInvalid"); else required_set.insert(xid);
        for (auto xid : read_xids) if (!xid || xid > nx.xid) return fail("SoftwareTransitionEncryptionReadXidInvalid"); else required_set.insert(xid);
        std::vector<std::uint64_t> required(required_set.begin(), required_set.end());
        rw::AppleCheckpointPublicationPlan preview;
        if (!Compose(*tracked, current->container, nullptr, nullptr, {}, required, 0, preview, error)) return {};
        auto preview_source = std::make_shared<TransitionCandidate>(tracked, preview);
        std::set<std::uint64_t> all_xids{nx.xid};
        if (!CollectDescriptorXids(*tracked, nx, all_xids, error)) return {};
        if (all_xids.size() > 6 || required.size() > 6) return fail("SoftwareTransitionEncryptionHistoryLimit");
        Rows filesystem, references;
        SoftwareVolumeRetainedGeneration plain_generation;
        std::set<std::uint64_t> historical_metadata, historical_payload, selected_fs, referenced_fs;
        if (rotating) {
            if (!CaptureGeneration(tracked, *current, *original_session, nx.xid, volume_oid,
                KeybagLength::IncludesHeader, plain_generation, historical_metadata, historical_payload,
                selected_fs, referenced_fs, &filesystem, error)) return {};
        } else if (!CapturePlainGeneration(tracked, *current, *current, plain_generation, filesystem, references, error) ||
            (!pristine && !CarryCanonicalPlainKeybags(tracked, *previous_owners, plain_generation, error))) return {};
        certificate.generations_.push_back(std::move(plain_generation));
        for (auto xid : all_xids) if (xid != nx.xid) {
            auto old = LoadContainerCheckpointView(*tracked, 0, tracked->SizeBytes(), error, xid);
            if (!old) return fail("SoftwareTransitionEncryptionHistoricalCheckpointIncomplete");
            if (pristine && (ReadU64LE(old->superblock_bytes, 0x510) != 0 || ReadU64LE(old->superblock_bytes, 0x518) != 0 ||
                ReadU64LE(old->superblock_bytes, 0x4F0) != 0))
                return fail("SoftwareTransitionPristineHistoricalEncryptionPresent");
            const SoftwareVolumeRetainedGeneration* proved = nullptr;
            if (previous_owners) for (const auto& generation : previous_owners->Generations())
                if (generation.checkpoint.superblock.xid == xid) proved = &generation;
            SoftwareVolumeRetainedGeneration captured;
            if (!proved && rotating) {
                if (!CaptureGeneration(tracked, *current, *original_session, xid, volume_oid, KeybagLength::IncludesHeader,
                    captured, historical_metadata, historical_payload, selected_fs, referenced_fs, nullptr, error)) return {};
                proved = &captured;
            }
            if (!proved && !rotating) {
                if (pristine && old->superblock.fs_oids.empty()) {
                    const auto object_map = LoadAppleContainerObjectMapView(*tracked, *old, error);
                    if (!object_map || !CaptureEmptyPlainGeneration(tracked, *old, *object_map, *current, captured, error)) return {};
                    proved = &captured;
                } else {
                    auto view = pristine ? LoadApplePlainTransitionVolumeView(*tracked, *old, error) :
                        LoadAppleReadOnlyVolumeView(*tracked, *old, error);
                    if (!view) {
                        error = "SoftwareTransitionEncryptionHistoricalViewInvalid:xid=" + std::to_string(xid) + ":" + error;
                        if (tracked->ReadBudget()->Failed()) error += ":budget=" + std::string(tracked->ReadBudget()->Failure());
                        return {};
                    }
                    if (view->volumes.size() != 1 || view->volumes.front().superblock.fs_flags != kFsFlagUnencrypted)
                        return fail("SoftwareTransitionEncryptionUncertifiedEncryptedHistory");
                    AppleCheckpointView historical;
                    historical.container = view->container; historical.container_object_map = view->container_object_map;
                    historical.volumes = std::move(view->volumes);
                    Rows historical_files, historical_references;
                    if (!CapturePlainGeneration(tracked, historical, *current, captured, historical_files, historical_references, error) ||
                        (!pristine && !CarryCanonicalPlainKeybags(tracked, *previous_owners, captured, error))) return {};
                    proved = &captured;
                }
            }
            if (!proved) return fail("SoftwareTransitionEncryptionHistoricalAuthorityMissing");
            if (!have_template || template_selection.checkpoint_xid < xid) {
                const auto bag = std::find_if(proved->ranges.begin(), proved->ranges.end(), [](const auto& range) {
                    return range.kind == SoftwareVolumeOwnerKind::Keybag;
                });
                if (bag != proved->ranges.end()) {
                    auto volume_view = LoadAppleReadOnlyVolumeView(*tracked, *old, error);
                    if (!volume_view || volume_view->volumes.size() != 1)
                        return fail("SoftwareTransitionEncryptionHistoricalVolumeInvalid");
                    if (volume_view->volumes.front().superblock.fs_flags == kFsFlagOneKey) {
                        UnlockError status{}; std::uint64_t a = 0, b = 0;
                        auto metadata = InspectPasswordKeybagMetadataAtCheckpoint(*tracked, volume_oid, KeybagLength::IncludesHeader, xid, status, a, b);
                        if (!metadata || metadata->users.size() != 1) return fail("SoftwareTransitionEncryptionBagTemplateInvalid");
                        template_selection = metadata->selection; template_selection.user_uuid = metadata->users.front(); have_template = true;
                    }
                }
            }
            std::string detail;
            if (LoadContainerCheckpointView(*preview_source, 0, tracked->SizeBytes(), detail, xid)) certificate.generations_.push_back(*proved);
            else if (required_set.contains(xid)) return fail("SoftwareTransitionEncryptionRequiredGenerationWouldRetire");
        }
        if (rotating && !std::includes(selected_fs.begin(), selected_fs.end(), referenced_fs.begin(), referenced_fs.end()))
            return fail("SoftwareKeyRotationUnselectedMetadataUnsupported");
        if (!have_template && !pristine) {
            if (rotating || !previous_owners || !CaptureRetiredKeybagTemplate(tracked, *current, *previous_owners,
                    journal_identity, template_source, template_selection, error)) return {};
            have_template = true;
        }
        for (auto xid : required) if (!all_xids.contains(xid)) return fail("SoftwareTransitionEncryptionRequiredGenerationMissing");
        std::vector<rw::AppleXattrRecord> materialized_attributes;
        struct ClearAttributes { std::vector<rw::AppleXattrRecord>& value; ~ClearAttributes() {
            for (auto& attribute : value) Wipe(attribute.data);
        } } clear_attributes{materialized_attributes};
        if (!rotating && !MaterializeSmallPlainAttributes(*tracked, filesystem, materialized_attributes, error)) return {};
        struct File { std::uint64_t inode = 0, stream = 0, size = 0; };
        std::vector<File> files;
        Rows encrypted_fs, encrypted_refs;
        std::uint64_t data_blocks = 0;
        for (const auto& row : filesystem.values) {
            const auto type = ReadU64LE(row.key, 0).value_or(0) >> 60;
            if (type == 8 || (rotating && type == 7)) continue;
            if (type != 3) { encrypted_fs.values.push_back(row); continue; }
            InodeOwner inode;
            if (!rw::ApfsExtendedRecordCodec::DecodeInodeReadOnly(row, inode.value, error)) return {};
            bool stream_seen = false;
            for (auto& field : inode.value.extended_fields) if (field.type == 8) {
                rw::AppleDataStreamRecord stream;
                if (stream_seen || !rw::ApfsExtendedRecordCodec::DecodeDataStream(field, stream, error) ||
                    stream.default_crypto_id != (rotating ? 4u : 0u) ||
                    stream.size > 64 * block_size || stream.allocated_size != ((stream.size + block_size - 1) / block_size) * block_size ||
                    !inode.value.private_id || (inode.value.mode & 0170000) != 0100000 || inode.value.internal_flags & rw::kAppleInodeSparseFlag)
                    return fail("SoftwareTransitionEncryptionDenseRegularProfileRequired");
                stream_seen = true; files.push_back({inode.value.object_id, inode.value.private_id, stream.size});
                data_blocks += stream.allocated_size / block_size; Put(field.data, 16, 4);
            }
            if (!rotating && !stream_seen && (inode.value.mode & 0170000) == 0100000) {
                if (!inode.value.private_id || inode.value.internal_flags & rw::kAppleInodeSparseFlag ||
                    std::any_of(filesystem.values.begin(), filesystem.values.end(), [&](const auto& extent) {
                        const auto key = ReadU64LE(extent.key, 0).value_or(0);
                        return key >> 60 == 8 && (key & 0x0FFFFFFFFFFFFFFFULL) == inode.value.private_id;
                    })) return fail("SoftwareTransitionEncryptionEmptyFileOwnerUnproved");
                rw::AppleExtendedField field; field.type = 8; field.data.resize(40);
                Put(field.data, 16, 4); inode.value.extended_fields.push_back(std::move(field));
                files.push_back({inode.value.object_id, inode.value.private_id, 0});
            }
            BtreeRecord canonical;
            if (!rw::EncodeAppleInodeRecord(inode.value, canonical, error)) return {};
            encrypted_fs.values.push_back(std::move(canonical));
        }
        if (files.empty() || files.size() > 64 || !data_blocks || data_blocks > 64)
            return fail("SoftwareTransitionEncryptionCompletePayloadBound");
        std::vector<std::uint16_t> bitmap_indices;
        for (const auto& bitmap : current->spaceman.internal_pool.active_bitmaps) bitmap_indices.push_back(bitmap.rotation_index);
        for (auto xid : required) if (xid != nx.xid) {
            auto old = LoadContainerCheckpointView(*tracked, 0, tracked->SizeBytes(), error, xid);
            if (!old) return {};
            if (std::find(recovery_xids.begin(), recovery_xids.end(), xid) != recovery_xids.end()) {
                AppleSpacemanView complete;
                if (!LoadAppleSpacemanOwnershipView(*tracked, *old, complete, error)) return {};
            }
            AppleSpacemanInternalPoolView pins;
            if (!LoadAppleSpacemanRetentionBitmaps(*tracked, *old, pins, error) || pins.base_block != current->spaceman.internal_pool.base_block ||
                pins.block_count != current->spaceman.internal_pool.block_count || pins.bitmap_base_block != current->spaceman.internal_pool.bitmap_base_block ||
                pins.bitmap_block_count != current->spaceman.internal_pool.bitmap_block_count)
                return fail("SoftwareTransitionEncryptionHistoricalBitmapGeometryChanged");
            for (const auto& bitmap : pins.active_bitmaps) bitmap_indices.push_back(bitmap.rotation_index);
        }
        rw::AppleSpacemanAllocationRequest request;
        request.expected_checkpoint_xid = nx.xid; request.transaction_xid = nx.next_xid;
        request.oldest_required_checkpoint_xid = *required_set.begin(); request.first_ephemeral_object_id = nx.next_oid;
        request.main_block_count = static_cast<std::size_t>(data_blocks + 9); request.reclaim_internal_pool_only = true;
        request.protected_internal_pool_bitmap_indices = bitmap_indices;
        rw::AppleSpacemanAllocationPlan allocation;
        if (!rw::PlanAppleSpacemanAllocation(current->spaceman, request, allocation, error)) return {};
        if (allocation.allocated_main_blocks.size() != data_blocks + 9 ||
            std::any_of(allocation.deferred_frees.begin(), allocation.deferred_frees.end(), [](const auto& free) { return free.queue_index != 0; }))
            return fail("SoftwareTransitionEncryptionAllocationCoverageInvalid");
        for (auto block : allocation.allocated_main_blocks)
            if (Allocated(current->spaceman, block) || tracked->guards.contains(block)) return fail("SoftwareTransitionEncryptionRetainedOwnerReused");
        for (auto block : allocation.allocated_internal_pool_blocks)
            if (tracked->guards.contains(block)) return fail("SoftwareTransitionEncryptionRetainedInternalOwnerReused");
        const auto& blocks = allocation.allocated_main_blocks; const auto n = static_cast<std::size_t>(data_blocks);
        const auto fs_block = blocks[n], refs_block = blocks[n + 1], vomap_tree = blocks[n + 2], comap_tree = blocks[n + 3];
        const auto vomap_block = blocks[n + 4], apsb_block = blocks[n + 5], comap_block = blocks[n + 6];
        const auto container_bag = blocks[n + 7], volume_bag = blocks[n + 8];
        std::vector<rw::AppleCheckpointPhysicalWrite> writes;
        struct ClearWrites { std::vector<rw::AppleCheckpointPhysicalWrite>& value; ~ClearWrites() { for (auto& write : value) Wipe(write.bytes); } } clear_writes{writes};
        crypto::SecureBytes key; BytesOwner container_bytes, volume_bytes;
        if (rotating) std::this_thread::sleep_for(std::chrono::milliseconds(250));
        const auto initialized = pristine
            ? InitializePristineKeybags(*tracked, volume_oid, container_bag, volume_bag, nx.next_xid,
                password, budget, key, container_bytes.bytes, volume_bytes.bytes, error)
            : InitializeRetainedKeybags(*template_source, template_selection, container_bag, volume_bag, nx.next_xid,
                password, budget, key, container_bytes.bytes, volume_bytes.bytes, error);
        if (!initialized) return {};
        writes.push_back({container_bag, std::move(container_bytes.bytes)}); writes.push_back({volume_bag, std::move(volume_bytes.bytes)});
        const auto decode_extent = [&](const BtreeRecord& row, rw::AppleFileExtentRecord& extent) {
            if (!rotating) return rw::DecodeAppleFileExtentRecord(row, block_size, extent, error);
            rw::AppleEncryptedFileExtentRecord encrypted;
            if (!rw::DecodeAppleEncryptedFileExtentRecord(row, block_size,
                rw::AppleEncryptedExtentProfile::OneKeyGenerationZero, encrypted, error)) return false;
            extent = encrypted.extent; return true;
        };
        std::size_t at = 0;
        for (const auto& file : files) {
            std::uint64_t covered = 0;
            for (const auto& row : filesystem.values) {
                if ((ReadU64LE(row.key, 0).value_or(0) >> 60) != 8) continue;
                rw::AppleFileExtentRecord extent;
                if (!decode_extent(row, extent)) return {};
                if (extent.object_id != file.stream) continue;
                if (extent.logical_address != covered || (!rotating && extent.crypto_id) ||
                    !extent.physical_block || extent.length_bytes % block_size)
                    return fail("SoftwareTransitionEncryptionDensePayloadMappingRequired");
                for (std::uint64_t offset = 0; offset < extent.length_bytes; offset += block_size) {
                    if (covered >= file.size || at >= n) return fail("SoftwareTransitionEncryptionPayloadExceedsInventory");
                    BytesOwner plain, cipher;
                    if (rotating) {
                        const auto count = static_cast<std::size_t>((std::min)(std::uint64_t(block_size), file.size - covered));
                        if (original_session->ReadFile(file.inode, covered, count, plain.bytes) != EncryptedReadError::None)
                            return fail("SoftwareKeyRotationCompletePayloadReadFailed");
                        plain.bytes.resize(block_size, std::byte{});
                    } else if (!Block(*tracked, extent.physical_block + offset / block_size, plain.bytes))
                        return fail("SoftwareTransitionEncryptionPayloadTransformFailed");
                    if (!TransformPayload(key, blocks[at], plain.bytes, cipher.bytes))
                        return fail("SoftwareTransitionEncryptionPayloadTransformFailed");
                    BtreeRecord next, reference;
                    if (!rw::EncodeAppleEncryptedFileExtentRecord({{file.stream, covered, block_size, blocks[at], blocks[at], block_size}, 0},
                        rw::AppleEncryptedExtentProfile::OneKeyGenerationZero, next, error) ||
                        !rw::EncodeApplePhysicalExtentRecord({blocks[at], 1, rw::kApplePhysicalExtentKindNew, file.stream, 1}, reference, error)) return {};
                    encrypted_fs.values.push_back(std::move(next)); encrypted_refs.values.push_back(std::move(reference));
                    writes.push_back({blocks[at++], std::move(cipher.bytes)}); covered += (std::min)(std::uint64_t(block_size), file.size - covered);
                }
            }
            if (covered != file.size) return fail("SoftwareTransitionEncryptionCompletePayloadMissing");
        }
        if (at != n) return fail("SoftwareTransitionEncryptionPayloadCoverageMismatch");
        BtreeRecord placeholder; placeholder.key.resize(8); placeholder.value.resize(24);
        Put(placeholder.key, 0, (std::uint64_t{7} << 60) | 4); Put(placeholder.value, 0, files.size(), 4);
        encrypted_fs.values.push_back(std::move(placeholder));
        const auto policy = rw::ApfsNamePolicy::FromIncompatibleFeatures(volume.superblock.incompatible_features);
        const auto fs_order = policy.UsesHashedDirectoryKeys() ? rw::AppleBtreeKeyOrder::FileSystemHashedDirectory : rw::AppleBtreeKeyOrder::FileSystemCaseSensitive;
        if (!rw::SortAppleBtreeRecords(encrypted_fs.values, fs_order, error) ||
            !rw::SortAppleBtreeRecords(encrypted_refs.values, rw::AppleBtreeKeyOrder::PhysicalExtent, error)) return {};
        std::vector<rw::ApplePhysicalExtentRecord> extents;
        if (!rw::ValidateAppleEncryptedPayloadExtentGraph(encrypted_fs.values, encrypted_refs.values, block_size, nx.block_count, extents, error)) return {};
        BytesOwner bytes, original;
        if (!SerializeLeaf(encrypted_fs, volume.root_tree.object_id, fs_block, nx.next_xid, 0, kObjectTypeFsTree, fs_order, bytes.bytes, error)) return {};
        Put(bytes.bytes, 24, 0x10000000u | kObjectTypeBtree, 4);
        if (!rw::FinalizeAppleObjectChecksum(bytes.bytes, error)) return {};
        auto encrypted_metadata = EncryptAppleMetadataBlock(key.Bytes(), fs_block, bytes.bytes);
        if (!encrypted_metadata) return fail("SoftwareTransitionEncryptionMetadataTransformFailed");
        Wipe(bytes.bytes); writes.push_back({fs_block, std::move(encrypted_metadata.bytes)});
        if (!SerializeLeaf(encrypted_refs, refs_block, refs_block, nx.next_xid, kObjectPhysical, kObjectTypeBlockRefTree,
            rw::AppleBtreeKeyOrder::PhysicalExtent, bytes.bytes, error)) return {};
        writes.push_back({refs_block, std::move(bytes.bytes)});
        Rows vomap, comap; BtreeRecord mapping;
        if (!rw::EncodeAppleOmapRecord({volume.root_tree.object_id, nx.next_xid, 4, block_size, fs_block}, mapping, error)) return {};
        vomap.values.push_back(std::move(mapping));
        if (!SerializeLeaf(vomap, vomap_tree, vomap_tree, nx.next_xid, kObjectPhysical, kObjectTypeOmap,
            rw::AppleBtreeKeyOrder::ObjectMap, bytes.bytes, error)) return {};
        writes.push_back({vomap_tree, std::move(bytes.bytes)});
        if (!Block(*tracked, volume.object_map.object.physical_block, original.bytes) ||
            !rw::PatchAppleObjectMap(original.bytes, vomap_block, nx.next_xid, vomap_tree, bytes.bytes, error)) return {};
        writes.push_back({vomap_block, std::move(bytes.bytes)});
        if (!Block(*tracked, volume.superblock_object.physical_block, bytes.bytes)) return {};
        const auto charged = data_blocks + 5;
        const auto charge = ReadU64LE(bytes.bytes, 0x58).value_or(UINT64_MAX), total = ReadU64LE(bytes.bytes, 0xE0).value_or(UINT64_MAX);
        if (charge > UINT64_MAX - charged || total > UINT64_MAX - charged ||
            (volume.superblock.space.quota_block_count && charge + charged > volume.superblock.space.quota_block_count))
            return fail("SoftwareTransitionEncryptionVolumeCapacityExceeded");
        Put(bytes.bytes, 16, nx.next_xid); Put(bytes.bytes, 0x58, charge + charged); Put(bytes.bytes, 0xE0, total + charged);
        Put(bytes.bytes, 0x80, vomap_block); Put(bytes.bytes, 0x90, refs_block); Put(bytes.bytes, 0x108, kFsFlagOneKey);
        if (!rw::FinalizeAppleObjectChecksum(bytes.bytes, error)) return {};
        writes.push_back({apsb_block, std::move(bytes.bytes)});
        if (!rw::EncodeAppleOmapRecord({volume_oid, nx.next_xid, 0, block_size, apsb_block}, mapping, error)) return {};
        comap.values.push_back(std::move(mapping));
        if (!SerializeLeaf(comap, comap_tree, comap_tree, nx.next_xid, kObjectPhysical, kObjectTypeOmap,
            rw::AppleBtreeKeyOrder::ObjectMap, bytes.bytes, error)) return {};
        writes.push_back({comap_tree, std::move(bytes.bytes)});
        if (!Block(*tracked, current->container_object_map.object.physical_block, original.bytes) ||
            !rw::PatchAppleObjectMap(original.bytes, comap_block, nx.next_xid, comap_tree, bytes.bytes, error)) return {};
        writes.push_back({comap_block, std::move(bytes.bytes)});
        rw::AppleCheckpointKeylockerReplacement replacement{container_bag, 1};
        if (!Compose(*tracked, current->container, &current->spaceman, &allocation, writes, required, comap_block,
            result->publication_, error, &replacement)) return {};
        Put(result->publication_.superblock_write.bytes, 0x4F0, 4);
        if (!rw::FinalizeAppleObjectChecksum(result->publication_.superblock_write.bytes, error)) return {};
        key.Clear();
        auto candidate = std::make_shared<TransitionCandidate>(tracked, result->publication_);
        UnlockError unlock{}; EncryptedReadError read_error{};
        auto bags = InspectPasswordKeybagMetadata(*candidate, volume_oid, KeybagLength::IncludesHeader, unlock);
        if (!bags || bags->users.size() != 1 || bags->selection.checkpoint_xid != nx.next_xid)
            return fail("SoftwareTransitionEncryptionCandidateBagInvalid");
        auto selected = bags->selection; selected.user_uuid = bags->users.front();
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
        auto session = ApfsEncryptedReadSession::Unlock(candidate, candidate->SourceIdentity(), candidate->Revision(), selected,
            password.Bytes(), budget, read_error, unlock);
        if (!session) {
            error = "SoftwareTransitionEncryptionCandidateUnlockFailed:read=" + std::to_string(static_cast<unsigned>(read_error)) +
                ":unlock=" + std::to_string(static_cast<unsigned>(unlock)); return {};
        }
        auto context = session ? session->CreateMetadataReadContext(read_error) : nullptr;
        if (!context) return fail("SoftwareTransitionEncryptionCandidateContextFailed");
        auto after = context ? LoadAppleCheckpointView(*candidate, 0, candidate->SizeBytes(), error, *context) : std::nullopt;
        if (!after) { error = "SoftwareTransitionEncryptionCandidateCanonicalLoadFailed:" + error; return {}; }
        Rows candidate_fs;
        if (!after || after->volumes.size() != 1 || after->volumes.front().superblock.fs_flags != kFsFlagOneKey ||
            after->container.superblock.xid != nx.next_xid || ReadU64LE(after->container.superblock_bytes, 0x4F0) != 4 ||
            !ReadAppleVolumeFileSystemRecords(*candidate, after->container, after->volumes.front(), candidate_fs.values, error, *context) ||
            !SameRows(candidate_fs, encrypted_fs)) return fail("SoftwareTransitionEncryptionCandidateGraphMismatch");
        for (const auto& attribute : materialized_attributes) {
            BytesOwner actual;
            if (session->ReadXattr(attribute.object_id, attribute.name_utf8, actual.bytes) != EncryptedReadError::None ||
                actual.bytes != attribute.data) return fail("SoftwareTransitionEncryptionCandidateAttributeMismatch");
        }
        for (const auto& file : files) {
            EncryptedNodeInfo metadata;
            if (session->GetMetadata(file.inode, metadata) != EncryptedReadError::None || metadata.size != file.size)
                return fail("SoftwareTransitionEncryptionCandidateInventoryMismatch");
            for (const auto& row : filesystem.values) {
                if ((ReadU64LE(row.key, 0).value_or(0) >> 60) != 8) continue;
                rw::AppleFileExtentRecord extent;
                if (!decode_extent(row, extent)) return {};
                if (extent.object_id != file.stream) continue;
                for (std::uint64_t offset = 0; offset < extent.length_bytes; offset += block_size) {
                    BytesOwner actual, plain;
                    const auto logical = extent.logical_address + offset;
                    const auto count = static_cast<std::size_t>((std::min)(std::uint64_t(block_size), file.size - logical));
                    const auto read_input = rotating
                        ? original_session->ReadFile(file.inode, logical, count, plain.bytes) == EncryptedReadError::None
                        : Block(*tracked, extent.physical_block + offset / block_size, plain.bytes);
                    if (!read_input || session->ReadFile(file.inode, logical, count, actual.bytes) != EncryptedReadError::None ||
                        actual.bytes.size() != count || plain.bytes.size() < count ||
                        !std::equal(actual.bytes.begin(), actual.bytes.end(), plain.bytes.begin()))
                        return fail("SoftwareTransitionEncryptionCandidatePayloadMismatch");
                }
            }
        }
        result->publication_.published_checkpoint = after->container;
        for (auto block : allocation.allocated_main_blocks) if (!Allocated(after->spaceman, block))
            return fail("SoftwareTransitionEncryptionCandidateAllocationLost");
        for (const auto& generation : certificate.generations_) {
            auto old = LoadContainerCheckpointView(*candidate, 0, candidate->SizeBytes(), error, generation.checkpoint.superblock.xid);
            if (!old || old->superblock_bytes != generation.checkpoint.superblock_bytes)
                return fail("SoftwareTransitionEncryptionRetainedCheckpointChanged");
            for (const auto& guard : generation.graph_guards) {
                BytesOwner actual;
                if (!Block(*candidate, guard.physical_block, actual.bytes) || actual.bytes != guard.bytes || !Allocated(after->spaceman, guard.physical_block))
                    return fail("SoftwareTransitionEncryptionRetainedGraphChanged");
            }
        }
        std::set<std::uint64_t> staged, guarded;
        for (const auto& write : result->publication_.before_superblock_writes) staged.insert(write.physical_block);
        staged.insert(result->publication_.superblock_write.physical_block);
        for (const auto& guard : result->publication_.guard_blocks) guarded.insert(guard.physical_block);
        for (const auto& [block, raw] : tracked->guards)
            if (!staged.contains(block) && guarded.insert(block).second) result->publication_.guard_blocks.push_back({block, raw});
        if (result->publication_.guard_blocks.size() > 384 || tracked->ReadBudget()->Failed() ||
            tracked->SourceIdentity() != expected_identity || tracked->Revision() != expected_revision)
            return fail("SoftwareTransitionEncryptionFinalBindingOrBudgetFailed");
        return result;
    } catch (const std::bad_alloc&) { return fail("SoftwareTransitionEncryptionResourceLimit"); }
      catch (const std::exception& exception) { error = "SoftwareTransitionEncryptionException:" + std::string(exception.what()); return {}; }
}

SoftwareVolumeRetainedOwners::~SoftwareVolumeRetainedOwners()
{
    for (auto& generation : generations_) {
        Wipe(generation.checkpoint.superblock_bytes);
        for (auto& guard : generation.checkpoint_guards) Wipe(guard.bytes);
        for (auto& guard : generation.graph_guards) Wipe(guard.bytes);
    }
}
SoftwareVolumeTransitionPublication::~SoftwareVolumeTransitionPublication()
{
    for (auto& write : publication_.before_superblock_writes) Wipe(write.bytes);
    Wipe(publication_.superblock_write.bytes);
    for (auto& guard : publication_.guard_blocks) Wipe(guard.bytes);
    Wipe(publication_.published_checkpoint.superblock_bytes);
    if (publication_.fusion_tier2_anchor_write) Wipe(publication_.fusion_tier2_anchor_write->bytes);
}

bool SoftwareVolumeRetainedOwners::RevalidateProtectedHistory(const ImmutableEncryptedReadSource& source,
    const std::array<std::byte, 32>& journal_identity, std::vector<SoftwareVolumeOwnedRange>& exclusions,
    std::string& error, std::span<const std::uint64_t> required) const
{
    if (!restored_accepted_sequence_ || !Nonzero(restored_plan_sha256_)) {
        exclusions.clear(); error = "SoftwareTransitionProtectedOwnerHistoryRequired"; return false;
    }
    return Revalidate(source, journal_identity, exclusions, error, required);
}

bool SoftwareVolumeRetainedOwners::Revalidate(const ImmutableEncryptedReadSource& source,
    const std::array<std::byte, 32>& journal_identity, std::vector<SoftwareVolumeOwnedRange>& exclusions,
    std::string& error, std::span<const std::uint64_t> required) const
{
    exclusions.clear(); error.clear();
    const auto fail = [&](const char* reason) { exclusions.clear(); error = reason; return false; };
    try {
        if (source.SourceIdentity() != identity_ || block_count_ > UINT64_MAX / block_size || source.SizeBytes() != block_count_ * block_size ||
            !Nonzero(journal_identity_) || journal_identity != journal_identity_ || !Nonzero(allocator_sha256_) ||
            !minted_xid_ || generations_.empty() || generations_.size() > 6 || required.size() > 6)
            return fail("SoftwareTransitionRetentionScopeMismatch");
        const auto revision = source.Revision();
        auto current = LoadContainerCheckpointView(source, 0, source.SizeBytes(), error);
        if (!current || current->superblock.block_size != block_size || current->superblock.block_count != block_count_ ||
            current->superblock.uuid_hex != container_uuid_ || current->superblock.xid <= minted_xid_ ||
            current->superblock.xp_desc_noncontiguous || current->superblock.xp_data_noncontiguous ||
            current->superblock.xp_desc_block_count > 256 || current->superblock.fs_oids != std::vector<std::uint64_t>{volume_oid_})
            return fail("SoftwareTransitionRetentionCurrentCheckpointMismatch");
        auto volumes = LoadAppleReadOnlyVolumeView(source, *current, error);
        if (!volumes || volumes->volumes.size() != 1 || volumes->volumes.front().superblock.object_id != volume_oid_ ||
            volumes->volumes.front().superblock.uuid_hex != volume_uuid_ ||
            (volumes->volumes.front().superblock.fs_flags != kFsFlagUnencrypted && volumes->volumes.front().superblock.fs_flags != kFsFlagOneKey) ||
            Binding(identity_, container_uuid_, volume_oid_, volume_uuid_) != binding_)
            return fail("SoftwareTransitionRetentionCurrentProfileRequired");
        AppleSpacemanView allocator;
        if (!LoadAppleSpacemanOwnershipView(source, *current, allocator, error)) return false;
        std::vector<SoftwareVolumeOwnedRange> validated;
        std::set<std::uint64_t> xids;
        for (const auto& generation : generations_) {
            const auto xid = generation.checkpoint.superblock.xid;
            if (!xid || xid > minted_xid_ || !xids.insert(xid).second || generation.ranges.empty() ||
                generation.ranges.size() > 384 || generation.checkpoint_guards.empty() ||
                generation.checkpoint_guards.size() > 64 || generation.graph_guards.empty() || generation.graph_guards.size() > 384)
                return fail("SoftwareTransitionRetentionCertificateInvalid");
            auto old = LoadContainerCheckpointView(source, 0, source.SizeBytes(), error, xid);
            if (!old) {
                bool retired = false;
                if (const auto* completed = dynamic_cast<const SoftwareTransitionCompletedProofSource*>(&source)) {
                    if (!completed->ProveActualRetirement(*this, xid, retired, error)) return false;
                } else retired = SuccessorOwnsSlot(source, *current, generation);
                if (std::find(required.begin(), required.end(), xid) != required.end() || !retired)
                    return fail("SoftwareTransitionRetentionUnprovedRetirement");
                continue;
            }
            if (old->superblock_bytes != generation.checkpoint.superblock_bytes ||
                old->superblock_physical_block != generation.checkpoint.superblock_physical_block)
                return fail("SoftwareTransitionRetentionCheckpointChanged");
            std::set<std::uint64_t> graph_blocks;
            for (const auto& guard : generation.graph_guards)
                if (!graph_blocks.insert(guard.physical_block).second) return fail("SoftwareTransitionRetentionDuplicateGuard");
            for (const auto* guards : {&generation.checkpoint_guards, &generation.graph_guards}) for (const auto& guard : *guards) {
                std::vector<std::byte> actual;
                if (guard.bytes.size() != block_size || !Block(source, guard.physical_block, actual) || actual != guard.bytes)
                    return fail("SoftwareTransitionRetentionRawGuardChanged");
            }
            for (const auto& range : generation.ranges) {
                if (!range.start_block || !range.block_count || range.start_block >= block_count_ ||
                    range.block_count > block_count_ - range.start_block || range.block_count > 64 ||
                    static_cast<unsigned>(range.kind) > static_cast<unsigned>(SoftwareVolumeOwnerKind::Keybag))
                    return fail("SoftwareTransitionRetentionRangeInvalid");
                for (std::uint64_t i = 0; i < range.block_count; ++i)
                    if (!graph_blocks.contains(range.start_block + i) || !Allocated(allocator, range.start_block + i))
                        return fail("SoftwareTransitionRetentionOwnerNotProvedAndAllocated");
                validated.push_back(range);
            }
        }
        for (auto xid : required)
            if (!xid || xid > current->superblock.xid || (xid <= minted_xid_ && !xids.contains(xid)))
                return fail("SoftwareTransitionRetentionRequiredGenerationUncertified");
        if (source.SourceIdentity() != identity_ || source.Revision() != revision ||
            (source.ReadBudget() && source.ReadBudget()->Failed())) return fail("SoftwareTransitionRetentionSourceRevoked");
        exclusions = std::move(validated); return true;
    } catch (const std::bad_alloc&) { return fail("SoftwareTransitionRetentionResourceLimit"); }
      catch (...) { return fail("SoftwareTransitionRetentionValidationException"); }
}

bool SoftwareVolumeRetainedOwners::VerifyGenerationRetirement(const ImmutableEncryptedReadSource& source,
    const std::array<std::byte, 32>& original_journal_identity, std::uint64_t xid, bool& retired, std::string& error) const
{
    retired = false; error.clear();
    const auto found = std::find_if(generations_.begin(), generations_.end(),
        [&](const auto& generation) { return generation.checkpoint.superblock.xid == xid; });
    if (!restored_accepted_sequence_ || !Nonzero(restored_plan_sha256_) || original_journal_identity != journal_identity_ ||
        source.SourceIdentity() != identity_ || !source.Revision() || found == generations_.end()) {
        error = "SoftwareTransitionRetirementProtectedScopeRequired"; return false;
    }
    const auto revision = source.Revision();
    auto current = LoadContainerCheckpointView(source, 0, source.SizeBytes(), error);
    AppleSpacemanView allocator;
    if (!current || current->superblock.uuid_hex != container_uuid_ || current->superblock.block_count != block_count_ ||
        current->superblock.xid < xid || !LoadAppleSpacemanOwnershipView(source, *current, allocator, error)) return false;
    auto old = LoadContainerCheckpointView(source, 0, source.SizeBytes(), error, xid);
    if (!old) retired = SuccessorOwnsSlot(source, *current, *found);
    if (source.Revision() != revision || (source.ReadBudget() && source.ReadBudget()->Failed())) {
        retired = false; error = "SoftwareTransitionRetirementSourceRevoked"; return false;
    }
    error.clear(); return true;
}

std::unique_ptr<SoftwareVolumeTransitionPublication> SoftwareVolumeTransition::PrepareDecryption(
    std::shared_ptr<const ImmutableEncryptedReadSource> source, const std::string& expected_identity,
    std::uint64_t expected_revision, std::uint64_t volume_oid, KeybagLength length,
    const crypto::SecureBytes& password, PasswordUnlockBudget& budget,
    const std::array<std::byte, 32>& journal_identity, std::string& error,
    std::span<const std::uint64_t> recovery_xids, std::span<const std::uint64_t> read_xids,
    const SoftwareVolumeRetainedOwners* previous_owners)
{
    error.clear();
    const auto fail = [&](const char* reason) -> std::unique_ptr<SoftwareVolumeTransitionPublication> { error = reason; return {}; };
    if (!source || !source->ReadBudget() || expected_identity.empty() || expected_identity.size() > 8192 ||
        source->SourceIdentity() != expected_identity || source->Revision() != expected_revision ||
        !volume_oid || !password.IsLocked() || !Nonzero(journal_identity) || recovery_xids.size() > 6 || read_xids.size() > 6)
        return fail("SoftwareTransitionSourceCredentialOrScopeInvalid");
    try {
        auto tracked = std::make_shared<TrackedSource>(std::move(source));
        UnlockError unlock{}; EncryptedReadError read_error{};
        auto bags = InspectPasswordKeybagMetadata(*tracked, volume_oid, length, unlock);
        if (!bags || bags->users.size() != 1) return fail("SoftwareTransitionCurrentKeybagUnsupported");
        auto selection = bags->selection; selection.user_uuid = bags->users.front();
        auto session = ApfsEncryptedReadSession::Unlock(tracked, expected_identity, expected_revision,
            selection, password.Bytes(), budget, read_error, unlock);
        if (!session) return fail("SoftwareTransitionCurrentCredentialRefused");
        auto context = session->CreateMetadataReadContext(read_error);
        auto current = context ? LoadAppleCheckpointView(*tracked, 0, tracked->SizeBytes(), error, *context) : std::nullopt;
        if (!current || current->volumes.size() != 1) return {};
        const auto& nx = current->container.superblock; const auto& volume = current->volumes.front();
        if (nx.block_size != block_size || nx.block_count > UINT64_MAX / block_size || nx.block_count * block_size != tracked->SizeBytes() ||
            nx.fs_oids != std::vector<std::uint64_t>{volume_oid} || nx.next_xid <= nx.xid || nx.xp_desc_noncontiguous ||
            nx.xp_data_noncontiguous || nx.xp_desc_block_count > 256 || ReadU64LE(current->container.superblock_bytes, 0x4F0) != 4 ||
            volume.superblock.fs_flags != kFsFlagOneKey || !volume.extentref_tree || volume.file_extent_tree)
            return fail("SoftwareTransitionCurrentSoftwareProfileUnsupported");
        auto result = std::unique_ptr<SoftwareVolumeTransitionPublication>(new SoftwareVolumeTransitionPublication);
        result->owners_ = std::unique_ptr<SoftwareVolumeRetainedOwners>(new SoftwareVolumeRetainedOwners);
        auto& certificate = *result->owners_;
        certificate.identity_ = expected_identity; certificate.container_uuid_ = nx.uuid_hex;
        certificate.volume_oid_ = volume_oid; certificate.volume_uuid_ = volume.superblock.uuid_hex;
        certificate.binding_ = Binding(expected_identity, nx.uuid_hex, volume_oid, volume.superblock.uuid_hex);
        certificate.journal_identity_ = journal_identity; certificate.minted_xid_ = nx.xid; certificate.block_count_ = nx.block_count;
        certificate.allocator_sha256_ = AllocatorDigest(*tracked, current->spaceman);
        std::set<std::uint64_t> required_set{nx.xid};
        for (auto xid : recovery_xids) if (!xid || xid > nx.xid) return fail("SoftwareTransitionRecoveryGenerationInvalid"); else required_set.insert(xid);
        for (auto xid : read_xids) if (!xid || xid > nx.xid) return fail("SoftwareTransitionReadGenerationInvalid"); else required_set.insert(xid);
        if (required_set.size() > 6) return fail("SoftwareTransitionRequiredGenerationLimit");
        std::vector<std::uint64_t> required(required_set.begin(), required_set.end());
        rw::AppleCheckpointPublicationPlan preview;
        if (!Compose(*tracked, current->container, nullptr, nullptr, {}, {}, 0, preview, error)) return {};
        auto preview_source = std::make_shared<TransitionCandidate>(tracked, preview);
        std::set<std::uint64_t> all_xids{nx.xid}, survivors{nx.xid};
        if (!CollectDescriptorXids(*tracked, nx, all_xids, error)) return {};
        if (all_xids.size() > 6) return fail("SoftwareTransitionHistoricalGenerationLimit");
        for (auto xid : required) if (!all_xids.contains(xid)) return fail("SoftwareTransitionRequiredGenerationUnavailable");
        for (auto xid : all_xids) if (xid != nx.xid) {
            std::string detail;
            if (!LoadContainerCheckpointView(*tracked, 0, tracked->SizeBytes(), detail, xid))
                return fail("SoftwareTransitionHistoricalCheckpointIncomplete");
            if (LoadContainerCheckpointView(*preview_source, 0, tracked->SizeBytes(), detail, xid)) survivors.insert(xid);
            else if (required_set.contains(xid)) return fail("SoftwareTransitionRequiredGenerationWouldRetire");
        }
        std::vector<SoftwareVolumeOwnedRange> prior_exclusions;
        if (previous_owners && !previous_owners->Revalidate(*tracked, journal_identity, prior_exclusions, error, required)) return {};
        Rows current_fs;
        std::set<std::uint64_t> metadata, payload, selected_fs, referenced_fs;
        std::vector<std::uint16_t> bitmap_indices;
        for (const auto& bitmap : current->spaceman.internal_pool.active_bitmaps) bitmap_indices.push_back(bitmap.rotation_index);
        for (auto xid : survivors) {
            SoftwareVolumeRetainedGeneration generation;
            const SoftwareVolumeRetainedGeneration* prior = nullptr;
            if (previous_owners && xid != nx.xid)
                for (const auto& candidate : previous_owners->Generations()) if (candidate.checkpoint.superblock.xid == xid) prior = &candidate;
            if (prior) {
                generation = *prior;
                for (const auto& range : generation.ranges) for (std::uint64_t i = 0; i < range.block_count; ++i)
                    (range.kind == SoftwareVolumeOwnerKind::Payload ? payload : metadata).insert(range.start_block + i);
            } else if (xid == nx.xid) {
                if (!CaptureGeneration(tracked, *current, *session, xid, volume_oid, length, generation,
                    metadata, payload, selected_fs, referenced_fs, &current_fs, error)) return {};
            } else {
                if (!CaptureGeneration(tracked, *current, *session, xid, volume_oid, length, generation,
                    metadata, payload, selected_fs, referenced_fs, nullptr, error)) return {};
            }
            auto old = LoadContainerCheckpointView(*tracked, 0, tracked->SizeBytes(), error, xid);
            if (!old) return {};
            const bool recovery_pin = std::find(recovery_xids.begin(), recovery_xids.end(), xid) != recovery_xids.end();
            if (recovery_pin) {
                AppleSpacemanView complete;
                if (!LoadAppleSpacemanOwnershipView(*tracked, *old, complete, error)) return {};
            }
            if (recovery_pin || std::find(read_xids.begin(), read_xids.end(), xid) != read_xids.end()) {
                AppleSpacemanInternalPoolView pins;
                if (!LoadAppleSpacemanRetentionBitmaps(*tracked, *old, pins, error) ||
                    pins.base_block != current->spaceman.internal_pool.base_block || pins.block_count != current->spaceman.internal_pool.block_count ||
                    pins.bitmap_base_block != current->spaceman.internal_pool.bitmap_base_block || pins.bitmap_block_count != current->spaceman.internal_pool.bitmap_block_count)
                    return fail("SoftwareTransitionHistoricalBitmapGeometryChanged");
                for (const auto& bitmap : pins.active_bitmaps) bitmap_indices.push_back(bitmap.rotation_index);
            }
            certificate.generations_.push_back(std::move(generation));
        }
        if (!std::includes(selected_fs.begin(), selected_fs.end(), referenced_fs.begin(), referenced_fs.end()))
            return fail("SoftwareTransitionUnselectedEncryptedMetadataUnsupported");
        for (auto block : metadata) if (payload.contains(block) || !Allocated(current->spaceman, block))
            return fail("SoftwareTransitionCrossGenerationOwnerOverlap");
        std::vector<EncryptedFileInfo> files;
        if (session->ListFiles(files) != EncryptedReadError::None || files.size() > 64)
            return fail("SoftwareTransitionFileInventoryUnavailable");
        std::uint64_t data_blocks = 0;
        for (const auto& file : files) {
            if (file.size > 64 * block_size || file.size > UINT64_MAX - block_size + 1)
                return fail("SoftwareTransitionCompletePayloadBound");
            data_blocks += (file.size + block_size - 1) / block_size;
        }
        if (!data_blocks || data_blocks > 64) return fail("SoftwareTransitionCompletePayloadBound");
        rw::AppleSpacemanAllocationRequest request;
        request.expected_checkpoint_xid = nx.xid; request.transaction_xid = nx.next_xid;
        request.oldest_required_checkpoint_xid = *required_set.begin(); request.first_ephemeral_object_id = nx.next_oid;
        request.main_block_count = static_cast<std::size_t>(data_blocks + 7); request.reclaim_internal_pool_only = true;
        request.protected_internal_pool_bitmap_indices = bitmap_indices;
        rw::AppleSpacemanAllocationPlan allocation;
        if (!rw::PlanAppleSpacemanAllocation(current->spaceman, request, allocation, error)) return {};
        if (allocation.allocated_main_blocks.size() != data_blocks + 7 ||
            std::any_of(allocation.deferred_frees.begin(), allocation.deferred_frees.end(), [](const auto& free) { return free.queue_index != 0; }))
            return fail("SoftwareTransitionAllocationCoverageInvalid");
        for (auto block : allocation.allocated_main_blocks)
            if (Allocated(current->spaceman, block) || metadata.contains(block) || payload.contains(block) || tracked->guards.contains(block))
                return fail("SoftwareTransitionRetainedOwnerReused");
        for (auto block : allocation.allocated_internal_pool_blocks) if (tracked->guards.contains(block))
            return fail("SoftwareTransitionRetainedInternalOwnerReused");
        const auto& blocks = allocation.allocated_main_blocks;
        const auto n = static_cast<std::size_t>(data_blocks);
        const auto fs_block = blocks[n], refs_block = blocks[n + 1], vomap_tree = blocks[n + 2], comap_tree = blocks[n + 3];
        const auto vomap_block = blocks[n + 4], apsb_block = blocks[n + 5], comap_block = blocks[n + 6];
        Rows plain_fs, plain_refs, new_vomap, new_comap;
        for (const auto& row : current_fs.values) {
            const auto type = ReadU64LE(row.key, 0).value_or(0) >> 60;
            if (type == 8 || type == 7) continue;
            if (type != 3) { plain_fs.values.push_back(row); continue; }
            InodeOwner inode;
            if (!rw::ApfsExtendedRecordCodec::DecodeInodeReadOnly(row, inode.value, error)) return {};
            for (auto& field : inode.value.extended_fields) if (field.type == 8) {
                rw::AppleDataStreamRecord stream;
                if (!rw::ApfsExtendedRecordCodec::DecodeDataStream(field, stream, error) || stream.default_crypto_id != 4)
                    return fail("SoftwareTransitionUnexpectedStreamCryptoState");
                Put(field.data, 16, 0);
            }
            BtreeRecord canonical;
            if (!rw::EncodeAppleInodeRecord(inode.value, canonical, error)) return {};
            plain_fs.values.push_back(std::move(canonical));
        }
        std::vector<rw::AppleCheckpointPhysicalWrite> writes;
        struct ClearWrites {
            std::vector<rw::AppleCheckpointPhysicalWrite>& value;
            ~ClearWrites() { for (auto& write : value) Wipe(write.bytes); }
        } clear_writes{writes};
        std::size_t at = 0;
        for (const auto& file : files) {
            EncryptedNodeInfo inode;
            if (session->GetMetadata(file.inode_id, inode) != EncryptedReadError::None || !inode.private_id || inode.size != file.size ||
                inode.allocated_size != ((file.size + block_size - 1) / block_size) * block_size || inode.internal_flags & rw::kAppleInodeSparseFlag)
                return fail("SoftwareTransitionDenseFileProfileRequired");
            for (std::uint64_t offset = 0; offset < file.size; offset += block_size) {
                BytesOwner bytes;
                const auto size = static_cast<std::size_t>((std::min)(static_cast<std::uint64_t>(block_size), file.size - offset));
                if (session->ReadFile(file.inode_id, offset, size, bytes.bytes) != EncryptedReadError::None)
                    return fail("SoftwareTransitionCompleteFileReadFailed");
                bytes.bytes.resize(block_size, std::byte{});
                const auto physical = blocks[at++];
                BtreeRecord extent, reference;
                if (!rw::EncodeAppleFileExtentRecord({inode.private_id, offset, block_size, physical, 0, block_size}, extent, error) ||
                    !rw::EncodeApplePhysicalExtentRecord({physical, 1, rw::kApplePhysicalExtentKindNew, inode.private_id, 1}, reference, error)) return {};
                plain_fs.values.push_back(std::move(extent)); plain_refs.values.push_back(std::move(reference));
                writes.push_back({physical, std::move(bytes.bytes)});
            }
        }
        if (at != n) return fail("SoftwareTransitionPayloadCoverageMismatch");
        const auto policy = rw::ApfsNamePolicy::FromIncompatibleFeatures(volume.superblock.incompatible_features);
        const auto fs_order = policy.UsesHashedDirectoryKeys() ? rw::AppleBtreeKeyOrder::FileSystemHashedDirectory : rw::AppleBtreeKeyOrder::FileSystemCaseSensitive;
        if (!rw::SortAppleBtreeRecords(plain_fs.values, fs_order, error) ||
            !rw::SortAppleBtreeRecords(plain_refs.values, rw::AppleBtreeKeyOrder::PhysicalExtent, error)) return {};
        std::vector<rw::ApplePhysicalExtentRecord> plain_extents;
        if (!rw::ValidateApplePayloadExtentGraph(plain_fs.values, plain_refs.values, block_size, nx.block_count, plain_extents, error)) return {};
        BytesOwner bytes, original;
        if (!SerializeLeaf(plain_fs, volume.root_tree.object_id, fs_block, nx.next_xid, 0,
            kObjectTypeFsTree, fs_order, bytes.bytes, error)) return {};
        writes.push_back({fs_block, std::move(bytes.bytes)});
        if (!SerializeLeaf(plain_refs, refs_block, refs_block, nx.next_xid, kObjectPhysical,
            kObjectTypeBlockRefTree, rw::AppleBtreeKeyOrder::PhysicalExtent, bytes.bytes, error)) return {};
        writes.push_back({refs_block, std::move(bytes.bytes)});
        BtreeRecord mapping;
        if (!rw::EncodeAppleOmapRecord({volume.root_tree.object_id, nx.next_xid, 0, block_size, fs_block}, mapping, error)) return {};
        new_vomap.values.push_back(std::move(mapping));
        if (!SerializeLeaf(new_vomap, vomap_tree, vomap_tree, nx.next_xid, kObjectPhysical,
            kObjectTypeOmap, rw::AppleBtreeKeyOrder::ObjectMap, bytes.bytes, error)) return {};
        writes.push_back({vomap_tree, std::move(bytes.bytes)});
        if (!Block(*tracked, volume.object_map.object.physical_block, original.bytes) ||
            !rw::PatchAppleObjectMap(original.bytes, vomap_block, nx.next_xid, vomap_tree, bytes.bytes, error)) return {};
        writes.push_back({vomap_block, std::move(bytes.bytes)});
        if (!Block(*tracked, volume.superblock_object.physical_block, bytes.bytes)) return {};
        const auto volume_blocks = data_blocks + 5;
        const auto charge = ReadU64LE(bytes.bytes, 0x58).value_or(UINT64_MAX), total = ReadU64LE(bytes.bytes, 0xE0).value_or(UINT64_MAX);
        if (charge > UINT64_MAX - volume_blocks || total > UINT64_MAX - volume_blocks ||
            (volume.superblock.space.quota_block_count && charge + volume_blocks > volume.superblock.space.quota_block_count))
            return fail("SoftwareTransitionVolumeCapacityExceeded");
        Put(bytes.bytes, 16, nx.next_xid); Put(bytes.bytes, 0x58, charge + volume_blocks);
        Put(bytes.bytes, 0x80, vomap_block); Put(bytes.bytes, 0x90, refs_block); Put(bytes.bytes, 0xE0, total + volume_blocks);
        Put(bytes.bytes, 0x108, kFsFlagUnencrypted);
        if (!rw::FinalizeAppleObjectChecksum(bytes.bytes, error)) return {};
        writes.push_back({apsb_block, std::move(bytes.bytes)});
        if (!rw::EncodeAppleOmapRecord({volume_oid, nx.next_xid, 0, block_size, apsb_block}, mapping, error)) return {};
        new_comap.values.push_back(std::move(mapping));
        if (!SerializeLeaf(new_comap, comap_tree, comap_tree, nx.next_xid, kObjectPhysical,
            kObjectTypeOmap, rw::AppleBtreeKeyOrder::ObjectMap, bytes.bytes, error)) return {};
        writes.push_back({comap_tree, std::move(bytes.bytes)});
        if (!Block(*tracked, current->container_object_map.object.physical_block, original.bytes) ||
            !rw::PatchAppleObjectMap(original.bytes, comap_block, nx.next_xid, comap_tree, bytes.bytes, error)) return {};
        writes.push_back({comap_block, std::move(bytes.bytes)});
        if (!Compose(*tracked, current->container, &current->spaceman, &allocation, writes, required, comap_block, result->publication_, error)) return {};
        Put(result->publication_.superblock_write.bytes, 0x4F0, 0);
        if (!rw::FinalizeAppleObjectChecksum(result->publication_.superblock_write.bytes, error)) return {};
        auto candidate = std::make_shared<TransitionCandidate>(tracked, result->publication_);
        auto after = LoadAppleCheckpointView(*candidate, 0, candidate->SizeBytes(), error);
        Rows candidate_fs, candidate_refs;
        if (!after || after->container.superblock.xid != nx.next_xid || after->volumes.size() != 1 ||
            after->volumes.front().superblock.fs_flags != kFsFlagUnencrypted || !after->volumes.front().extentref_tree ||
            ReadU64LE(after->container.superblock_bytes, 0x4F0) != 0 ||
            !ReadAppleVolumeFileSystemRecords(*candidate, after->container, after->volumes.front(), candidate_fs.values, error) ||
            !Tree(*candidate, *after->volumes.front().extentref_tree, nx.next_xid, candidate_refs, nullptr, error) ||
            !SameRows(plain_fs, candidate_fs) || !SameRows(plain_refs, candidate_refs))
            return fail("SoftwareTransitionPlainCandidateReopenFailed");
        result->publication_.published_checkpoint = after->container;
        for (const auto& file : files) {
            EncryptedNodeInfo inode;
            if (session->GetMetadata(file.inode_id, inode) != EncryptedReadError::None)
                return fail("SoftwareTransitionCandidateFileInventoryChanged");
            std::uint64_t covered = 0;
            for (const auto& row : candidate_fs.values) {
                if ((ReadU64LE(row.key, 0).value_or(0) >> 60) != 8) continue;
                rw::AppleFileExtentRecord extent;
                if (!rw::DecodeAppleFileExtentRecord(row, block_size, extent, error)) return {};
                if (extent.object_id != inode.private_id) continue;
                if (extent.logical_address != covered || extent.crypto_id || extent.length_bytes != block_size || covered >= file.size)
                    return fail("SoftwareTransitionCandidatePayloadLayoutChanged");
                BytesOwner plain, actual;
                const auto size = static_cast<std::size_t>((std::min)(std::uint64_t(block_size), file.size - covered));
                if (session->ReadFile(file.inode_id, covered, size, plain.bytes) != EncryptedReadError::None ||
                    !Block(*candidate, extent.physical_block, actual.bytes) ||
                    !std::equal(plain.bytes.begin(), plain.bytes.end(), actual.bytes.begin()) ||
                    !std::all_of(actual.bytes.begin() + size, actual.bytes.end(), [](auto b) { return b == std::byte{}; }))
                    return fail("SoftwareTransitionCandidatePayloadMismatch");
                covered += size;
            }
            if (covered != file.size) return fail("SoftwareTransitionCandidatePayloadIncomplete");
        }
        for (auto block : allocation.allocated_main_blocks) if (!Allocated(after->spaceman, block))
            return fail("SoftwareTransitionCandidateAllocationLost");
        for (auto block : metadata) if (!Allocated(after->spaceman, block)) return fail("SoftwareTransitionCandidateMetadataOwnershipLost");
        for (auto block : payload) if (!Allocated(after->spaceman, block)) return fail("SoftwareTransitionCandidatePayloadOwnershipLost");
        for (const auto& generation : certificate.generations_) {
            auto old = LoadContainerCheckpointView(*candidate, 0, candidate->SizeBytes(), error, generation.checkpoint.superblock.xid);
            if (!old || old->superblock_bytes != generation.checkpoint.superblock_bytes)
                return fail("SoftwareTransitionRetainedCheckpointChanged");
            for (const auto& guard : generation.graph_guards) {
                std::vector<std::byte> actual;
                if (!Block(*candidate, guard.physical_block, actual) || actual != guard.bytes)
                    return fail("SoftwareTransitionRetainedGraphChanged");
            }
        }
        std::set<std::uint64_t> staged, guarded;
        for (const auto& write : result->publication_.before_superblock_writes) staged.insert(write.physical_block);
        staged.insert(result->publication_.superblock_write.physical_block);
        for (const auto& guard : result->publication_.guard_blocks) guarded.insert(guard.physical_block);
        for (const auto& [block, raw] : tracked->guards)
            if (!staged.contains(block) && guarded.insert(block).second) result->publication_.guard_blocks.push_back({block, raw});
        if (result->publication_.guard_blocks.size() > 384 || tracked->ReadBudget()->Failed() ||
            tracked->SourceIdentity() != expected_identity || tracked->Revision() != expected_revision)
            return fail("SoftwareTransitionFinalBindingOrBudgetFailed");
        return result;
    } catch (const std::bad_alloc&) { return fail("SoftwareTransitionPreparationResourceLimit"); }
      catch (const std::exception& exception) { error = "SoftwareTransitionPreparationException:" + std::string(exception.what()); return {}; }
}
}
