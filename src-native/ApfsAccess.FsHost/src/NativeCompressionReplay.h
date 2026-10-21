#pragma once

#include "NativeCompressionRewrite.h"
#include "CompressionAttributeDigest.h"
#include "ApfsNameCodec.h"
#include "NativeApfsReader.h"
#include "AppleTransactionCommit.h"
#include "ApfsExtendedRecordCodec.h"
#include "PayloadSpool.h"
#include <climits>
#include <map>
#include <set>

namespace apfsaccess::fshost
{
// Read-only, immediate-publication proof. The host holds its mutation/publication
// gate and metadata/journal serialization, including the existing checkpoint
// census, through verification AND its subsequent durability/cleanup decision.
// This helper never owns/releases pins, stages work, advances watermarks or
// repairs evidence. A failure must retain WAL, spool and checkpoint evidence.
class NativeCompressionReplay
{
public:
    using Store = rw::MetadataStore;
    using Tx = rw::TransactionManager;
    using Wal = rw::WriteAheadLog;
    enum class Result
    {
        Verified, Unavailable, AcceptedEvidenceInvalid, HistoryUnsupported,
        OriginalEvidenceUnavailable, SourceMismatch, MetadataMismatch,
        PayloadMismatch, ContentMismatch, ResourceFailure,
    };
    static constexpr std::size_t MaxMutations = 256;
    static constexpr std::uint64_t MaxWriteBytes = 32ULL << 20;
    static constexpr std::size_t MaxTreeRecords = 65536;

    [[nodiscard]] static bool ContainsRewrite(const Tx::AcceptedTransaction& batch) noexcept
    {
        return std::any_of(batch.mutations.begin(), batch.mutations.end(), [](const auto& r) {
            return r.operation == Wal::OperationKind::RewriteCompressedContent;
        });
    }

    // accepted_sequence selects ORIGINAL durable WAL, not a supplied/prepared
    // request or a projected replay copy. volume_identity is the host's existing
    // immutable WAL/spool identity for this selected store. No payload callbacks,
    // caller-provided source snapshots, or caller-supplied "proof" booleans.
    [[nodiscard]] static Result Verify(const Store& store, Tx& tx,
        std::uint64_t accepted_sequence, rw::PayloadSpool* spool,
        const std::string& volume_identity)
    {
        try
        {
            if (!accepted_sequence || volume_identity.empty() || !tx.RecoveryStateValid() ||
                tx.CurrentState() != Tx::State::Idle || tx.PendingMutationCount() ||
                !store.Device().IsRegularFile() || store.PendingMutationCount() ||
                !store.AuthoritativeAppleCheckpointView()) return Result::Unavailable;
            std::vector<Tx::AcceptedTransaction> batches;
            std::string error;
            if (!tx.LoadAcceptedTransactionsSinceCleanup(batches, &error, {64ULL << 20, 4096}))
                return Result::AcceptedEvidenceInvalid;
            const Tx::AcceptedTransaction* batch = nullptr;
            for (const auto& candidate : batches)
                if (candidate.accepted_sequence == accepted_sequence)
                {
                    if (batch) return Result::AcceptedEvidenceInvalid;
                    batch = &candidate;
                }
            if (!batch || batch->mutations.empty() || batch->mutations.size() > MaxMutations ||
                !ContainsRewrite(*batch) || !NativeCompressionRewrite::AcceptedBatchIsConsistent(
                    *batch, store.Context().volume_object_id) ||
                batch->mutations.front().volume_identity != volume_identity)
                return Result::AcceptedEvidenceInvalid;
            rw::CompressionRewrite proof;
            if (!rw::DecodeCompressionRewrite(batch->mutations.front().inline_payload, proof))
                return Result::AcceptedEvidenceInvalid;
            // No generic sibling rebase and no later-write/delete supersession.
            // Even a later checkpoint with apparently identical owner bytes is
            // outside this proof's history contract.
            if (store.CheckpointXid() != proof.checkpoint + 1 ||
                store.AuthoritativeAppleCheckpointView()->container.superblock.xid != proof.checkpoint + 1)
                return Result::HistoryUnsupported;
            for (const auto& candidate : batches)
                if (candidate.accepted_sequence > accepted_sequence)
                    return Result::HistoryUnsupported;
            std::vector<std::uint64_t> pins;
            for (const auto& accepted : batches)
            {
                if (!accepted.preimage_checkpoint_xid) return Result::OriginalEvidenceUnavailable;
                pins.push_back(accepted.preimage_checkpoint_xid);
            }
            if (std::find(pins.begin(), pins.end(), proof.checkpoint) == pins.end()) return Result::OriginalEvidenceUnavailable;
            std::sort(pins.begin(), pins.end());
            pins.erase(std::unique(pins.begin(), pins.end()), pins.end());
            const auto budget = std::make_shared<catalog::ApfsReadBudget>(65536, 256ULL << 20, 262144, 256ULL << 20);
            DeviceSource device_source(store.Device());
            catalog::BudgetedRandomAccessSource source(device_source, budget);
            std::vector<rw::AppleRecoveryCheckpointView> retained;
            if (!rw::LoadAppleRecoveryCheckpoints(source, *store.AuthoritativeAppleCheckpointView(),
                    pins, retained, error))
                return Result::OriginalEvidenceUnavailable;
            const auto preimage = std::find_if(retained.begin(), retained.end(), [&](const auto& candidate) {
                return candidate.checkpoint.container.superblock.xid == proof.checkpoint;
            });
            if (preimage == retained.end()) return Result::OriginalEvidenceUnavailable;
            Trees before, after;
            if (!LoadTrees(source, preimage->checkpoint, proof.volume, before) ||
                !LoadTrees(source, *store.AuthoritativeAppleCheckpointView(), proof.volume, after))
                return Result::OriginalEvidenceUnavailable;
            rw::NativeApfsVolumeProjection original, published;
            std::wstring read_error;
            if (!rw::NativeApfsReader::TryLoadVolumeProjection(store.Device(), proof.volume,
                    original, read_error, proof.checkpoint, budget) ||
                !rw::NativeApfsReader::TryLoadVolumeProjection(store.Device(), proof.volume,
                    published, read_error, proof.checkpoint + 1, budget) ||
                original.checkpoint_xid != proof.checkpoint || published.checkpoint_xid != proof.checkpoint + 1 ||
                original.block_size != published.block_size || original.incompatible_features != published.incompatible_features)
                return Result::OriginalEvidenceUnavailable;
            const auto* old = UniqueInode(original, proof.object);
            const auto* next = UniqueInode(published, proof.object);
            if (!old || !next || old->xid != proof.generation || old->private_id != proof.private_id ||
                old->logical_size != proof.size || old->node_type != Store::NodeType::RegularFile ||
                old->is_directory || !(old->bsd_flags & rw::kAppleBsdCompressedFlag) ||
                old->data_physical_address || old->allocation_size.value_or(0) ||
                HasExtents(original, proof.object)) return Result::SourceMismatch;
            for (const auto& inode : original.inodes)
                if (inode.object_id != proof.object && inode.private_id == proof.private_id)
                    return Result::SourceMismatch;
            std::uint64_t allocated = 0;
            if (!NativeCompressionRewrite::PublicationBytes(proof.size, original.block_size, allocated) ||
                next->xid != proof.checkpoint + 1 || next->logical_size != proof.size ||
                next->allocation_size != allocated || next->node_type != Store::NodeType::RegularFile ||
                next->is_directory || next->private_id != proof.private_id ||
                next->bsd_flags != (old->bsd_flags & ~rw::kAppleBsdCompressedFlag))
                return Result::MetadataMismatch;
            // Check all accepted paths against both native namespaces. Exact
            // spelling is deliberately bounded; no lossy UTF-8/path fallback.
            for (const auto& record : batch->mutations)
            {
                std::wstring path;
                if (!DecodePath(record.path_utf8, path) ||
                    !OwnsPath(original, proof.object, path) || !OwnsPath(published, proof.object, path))
                    return Result::MetadataMismatch;
            }
            std::set<std::uint64_t> retired_streams;
            if (!AuthenticateAttribute(store, original, before, proof.object, "com.apple.decmpfs",
                    proof.decmpfs_flags, proof.decmpfs_descriptor, proof.decmpfs, &retired_streams) ||
                !AuthenticateAttribute(store, original, before, proof.object, "com.apple.ResourceFork",
                    proof.resource_flags, proof.resource_descriptor, proof.resource,
                    rw::CompressionRewrite::UsesResourceFork(proof.type) ? &retired_streams : nullptr)) return Result::SourceMismatch;
            if (!AuthenticatePreservedAttributes(store, original, proof) ||
                !AuthenticatePreservedAttributes(store, published, proof)) return Result::MetadataMismatch;
            if (!VerifyMetadata(before, after, original, published, proof, *batch, allocated, retired_streams))
                return Result::MetadataMismatch;

            rw::ApfsCompressionResourceReader resource;
            if (rw::CompressionRewrite::UsesResourceFork(proof.type))
            {
                resource.size = proof.resource.size();
                resource.read = [&](std::uint64_t at, std::span<std::byte> out) {
                    if (at > proof.resource.size() || out.size() > proof.resource.size() - at) return std::size_t{0};
                    std::copy_n(proof.resource.begin() + static_cast<std::size_t>(at), out.size(), out.begin());
                    return out.size();
                };
            }
            rw::ApfsCompressionLimits limits;
            limits.max_file_bytes = rw::CompressionRewrite::MaxLogicalBytes;
            limits.max_resource_bytes = rw::CompressionRewrite::MaxResourceBytes;
            std::vector<std::byte> expected;
            // Complete EOF selects every compressed block, including untouched
            // blocks. CRW1 bytes were independently matched to retained storage.
            if (!rw::ApfsCompression::DecodeRange(proof.decmpfs, resource, 0, proof.size, limits, expected) ||
                expected.size() != proof.size) return Result::SourceMismatch;
            std::uint64_t total = 0;
            for (const auto& record : batch->mutations)
            {
                if (record.operation != Wal::OperationKind::Write) continue;
                if (record.payload_length > MaxWriteBytes - total) return Result::ResourceFailure;
                total += record.payload_length;
                std::vector<std::byte> payload;
                if (!ReadPayload(record, spool, volume_identity, payload)) return Result::PayloadMismatch;
                std::copy(payload.begin(), payload.end(), expected.begin() + static_cast<std::size_t>(record.logical_offset));
            }
            const auto extents = published.read_extents_by_inode.find(proof.object);
            if (extents == published.read_extents_by_inode.end()) return Result::ContentMismatch;
            std::vector<std::byte> actual;
            if (!ReadExtents(store, proof.object, proof.size, extents->second, actual) || actual != expected)
                return Result::ContentMismatch;
            // Recheck retention before returning a positive result. The caller's
            // gate, not this second check, prevents a publication/reclaim race.
            const auto current = catalog::LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
            if (store.CheckpointXid() != proof.checkpoint + 1 || !current ||
                current->container.superblock_bytes != store.AuthoritativeAppleCheckpointView()->container.superblock_bytes)
                return Result::OriginalEvidenceUnavailable;
            if (budget->Failed()) return Result::ResourceFailure;
            return Result::Verified;
        }
        catch (const std::bad_alloc&) { return Result::ResourceFailure; }
        catch (const std::length_error&) { return Result::ResourceFailure; }
    }

private:
    // Dispatch tags only. All record bodies are handled by the existing native
    // codecs below; the engine currently keeps these tag names in its .cpp.
    enum FsType : std::uint64_t
    {
        Inode = 3, Xattr = 4, DstreamId = 6, CryptoState = 7,
        FileExtent = 8, DirectoryStats = 10, FileInfo = 13,
    };
    using Raw = catalog::BtreeRecord;
    using Records = std::map<std::vector<std::byte>, std::vector<std::byte>>;
    class DeviceSource final : public catalog::RandomAccessSource
    {
    public:
        explicit DeviceSource(const rw::BlockDevice& device) : device_(device) {}
        std::uint64_t SizeBytes() const override { return device_.GetGeometry().total_bytes; }
        bool Read(std::uint64_t offset, std::size_t size, std::vector<std::byte>& out) const override
        {
            out.clear();
            return size == 0 || (device_.Read(offset, size, out) && out.size() == size);
        }
    private:
        const rw::BlockDevice& device_;
    };
    struct Trees
    {
        std::vector<Raw> filesystem;
        std::vector<rw::ApplePhysicalExtentRecord> physical;
    };
    static bool LoadTrees(const catalog::RandomAccessSource& source, const catalog::AppleCheckpointView& checkpoint,
        std::uint64_t volume_id, Trees& trees)
    {
        const catalog::AppleVolumeCheckpointView* volume = nullptr;
        for (const auto& candidate : checkpoint.volumes)
            if (candidate.superblock.object_id == volume_id)
            {
                if (volume) return false;
                volume = &candidate;
            }
        if (!volume || !volume->extentref_tree) return false;
        std::string error;
        const auto read = [&](const catalog::AppleObjectLocation& root, std::uint64_t omap, auto& records) {
            catalog::BtreeReadPolicy policy;
            policy.enforce_object_identity = true;
            policy.require_complete_traversal = true;
            policy.root_object_id = root.object_id; policy.storage_type = root.type; policy.subtype = root.subtype;
            const auto physical = (root.type & catalog::kObjectStorageTypeMask) == catalog::kObjectPhysical;
            return catalog::ReadBtreeLeafRecords(source, checkpoint.container.superblock.block_size,
                root.physical_block, physical, physical ? 0 : omap, checkpoint.container.superblock.xid,
                policy, records, error) && records.size() <= MaxTreeRecords;
        };
        std::vector<Raw> references, separate, snapshots;
        if (!read(volume->root_tree, volume->superblock.omap_oid, trees.filesystem) ||
            !read(*volume->extentref_tree, 0, references) ||
            (volume->file_extent_tree && (!read(*volume->file_extent_tree, 0, separate) || !separate.empty())) ||
            (volume->snapshot_metadata_tree && (!read(*volume->snapshot_metadata_tree,
                volume->superblock.omap_oid, snapshots) || !snapshots.empty()))) return false;
        return rw::ValidateApplePayloadExtentGraph(trees.filesystem, references,
            checkpoint.container.superblock.block_size, checkpoint.container.superblock.block_count,
            trees.physical, error) && rw::ValidateAppleCheckpointPayloadOwnership(source, checkpoint, trees.physical, error);
    }
    static const Store::InodeRecord* UniqueInode(const rw::NativeApfsVolumeProjection& view, std::uint64_t id)
    {
        const Store::InodeRecord* result = nullptr;
        for (const auto& inode : view.inodes) if (inode.object_id == id)
        {
            if (result) return nullptr;
            result = &inode;
        }
        return result;
    }
    static bool HasExtents(const rw::NativeApfsVolumeProjection& view, std::uint64_t id)
    {
        const auto found = view.read_extents_by_inode.find(id);
        return found != view.read_extents_by_inode.end() && !found->second.empty();
    }
    static bool DecodePath(const std::string& bytes, std::wstring& path)
    {
        if (bytes.empty() || bytes.front() != '\\' || bytes.find('\0') != std::string::npos ||
            bytes.size() > static_cast<std::size_t>(INT_MAX)) return false;
        const auto count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, bytes.data(),
            static_cast<int>(bytes.size()), nullptr, 0);
        if (count <= 0) return false;
        path.resize(count);
        return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, bytes.data(),
            static_cast<int>(bytes.size()), path.data(), count) == count;
    }
    static bool OwnsPath(const rw::NativeApfsVolumeProjection& view, std::uint64_t id, const std::wstring& path)
    {
        const auto slash = path.find_last_of(L'\\');
        if (slash == std::wstring::npos || slash + 1 == path.size()) return false;
        const auto parent_path = slash == 0 ? L"\\" : path.substr(0, slash);
        const Store::InodeRecord* parent = nullptr;
        for (const auto& inode : view.inodes) if (inode.full_path == parent_path)
        {
            if (parent || !inode.is_directory) return false;
            parent = &inode;
        }
        if (!parent) return false;
        std::size_t matches = 0;
        for (const auto& link : view.directory_links)
            if (link.parent_object_id == parent->object_id && link.entry_name == path.substr(slash + 1))
            {
                if (link.child_object_id != id) return false;
                ++matches;
            }
        return matches == 1;
    }
    static bool ReadExtents(const Store& store, std::uint64_t id, std::uint64_t size,
        const std::vector<Store::FileExtent>& extents, std::vector<std::byte>& bytes)
    {
        if (size > rw::CompressionRewrite::MaxLogicalBytes) return false;
        Store::CommittedFileReadPlan plan;
        plan.object_id = id; plan.logical_size = size;
        plan.extents_snapshot = std::make_shared<const std::vector<Store::FileExtent>>(extents);
        bytes.resize(static_cast<std::size_t>(size));
        std::size_t read = 0;
        return store.ReadCommittedFileRangeFromPlan(plan, L"<CRW1 retained proof>", 0, bytes.size(),
            bytes.data(), bytes.size(), read) && read == bytes.size();
    }
    static bool AuthenticateAttribute(const Store& store, const rw::NativeApfsVolumeProjection& view,
        const Trees& tree, std::uint64_t owner, const char* name, std::uint16_t flags,
        const std::vector<std::byte>& descriptor, const std::vector<std::byte>& bytes,
        std::set<std::uint64_t>* retired)
    {
        const auto attrs = view.extended_attributes_by_inode.find(owner);
        const rw::AppleXattrRecord* attribute = nullptr;
        if (attrs != view.extended_attributes_by_inode.end())
        {
            const auto found = attrs->second.find(name);
            if (found != attrs->second.end()) attribute = &found->second;
        }
        if (!flags) return !attribute && descriptor.empty() && bytes.empty();
        if (!attribute || attribute->flags != flags || attribute->data != descriptor) return false;
        if (flags == rw::kAppleXattrDataEmbedded) return bytes == descriptor;
        // Descriptor syntax and extents have already been decoded/validated by
        // NativeApfsReader and ValidateApplePayloadExtentGraph.
        const auto id = catalog::ReadU64LE(descriptor, 0).value_or(0);
        if (flags != rw::kAppleXattrDataStream || !id ||
            catalog::ReadU64LE(descriptor, 8) != bytes.size()) return false;
        const auto extents = view.attribute_stream_extents.find(id);
        if (extents == view.attribute_stream_extents.end() || !extents->second) return false;
        // Shared attribute streams need a wider retirement proof. Refuse them.
        std::size_t ids = 0;
        std::string error;
        for (const auto& record : tree.filesystem)
        {
            const auto key = catalog::ReadU64LE(record.key, 0).value_or(0);
            if ((key & 0x0fffffffffffffffULL) != id || (key >> 60) != DstreamId) continue;
            rw::AppleDataStreamIdRecord stream;
            if (!rw::DecodeAppleDataStreamIdRecord(record, stream, error) || stream.reference_count != 1) return false;
            ++ids;
        }
        if (ids != 1) return false;
        std::vector<std::byte> actual;
        if (!ReadExtents(store, id, bytes.size(), *extents->second, actual) || actual != bytes) return false;
        return !retired || retired->insert(id).second;
    }
    static bool ReadPayload(const Wal::Record& record, rw::PayloadSpool* spool,
        const std::string& identity, std::vector<std::byte>& payload)
    {
        if (record.volume_identity != identity || record.payload_spool_id != record.sequence ||
            !record.object_id || !record.parent_object_id || !record.payload_length ||
            record.payload_length != record.logical_length) return false;
        if (!record.inline_payload.empty())
        {
            if (!Wal::InlinePayloadIsConsistent(record)) return false;
            payload = record.inline_payload;
        }
        else if (!spool || !spool->ReadPersistedRange({identity, record.object_id, record.parent_object_id,
            record.logical_offset, record.payload_length, record.payload_offset, record.payload_spool_id,
            record.payload_sha256}, payload)) return false;
        return payload.size() == record.logical_length;
    }

    static bool AuthenticatePreservedAttributes(const Store& store,
        const rw::NativeApfsVolumeProjection& view, const rw::CompressionRewrite& proof)
    {
        std::vector<rw::AppleXattrRecord> records;
        const auto owner = view.extended_attributes_by_inode.find(proof.object);
        if (owner != view.extended_attributes_by_inode.end())
        {
            if (owner->second.size() > 256) return false;
            for (const auto& [name, attribute] : owner->second)
            {
                if (!proof.preserved_attributes_sha256 && attribute.flags == rw::kAppleXattrDataStream &&
                    name != "com.apple.decmpfs" && name != "com.apple.ResourceFork") return false;
                records.push_back(attribute);
            }
        }
        if (!proof.preserved_attributes_sha256) return true;
        std::array<std::uint8_t, 32> digest{};
        return rw::ComputeCompressionAttributeDigest(records,
            [&](const rw::AppleXattrRecord& attribute, std::uint64_t at, std::span<std::byte> target) {
                if (attribute.flags == rw::kAppleXattrDataEmbedded)
                {
                    if (at > attribute.data.size() || target.size() > attribute.data.size() - at) return false;
                    std::copy_n(attribute.data.begin() + static_cast<std::size_t>(at), target.size(), target.begin());
                    return true;
                }
                const auto id = catalog::ReadU64LE(attribute.data, 0).value_or(0);
                const auto extents = view.attribute_stream_extents.find(id);
                if (!id || extents == view.attribute_stream_extents.end() || !extents->second) return false;
                Store::CommittedFileReadPlan plan;
                plan.object_id = id;
                plan.logical_size = catalog::ReadU64LE(attribute.data, 8).value_or(0);
                plan.extents_snapshot = extents->second;
                std::size_t read = 0;
                return store.ReadCommittedFileRangeFromPlan(plan, L"<compression attribute authentication>",
                    at, target.size(), target.data(), target.size(), read) && read == target.size();
            }, digest) && digest == *proof.preserved_attributes_sha256;
    }

    static bool VerifyMetadata(const Trees& before, const Trees& after,
        const rw::NativeApfsVolumeProjection& original, const rw::NativeApfsVolumeProjection& published,
        const rw::CompressionRewrite& proof, const Tx::AcceptedTransaction& batch, std::uint64_t allocated,
        const std::set<std::uint64_t>& retired)
    {
        Records old_records, new_records;
        for (const auto& r : before.filesystem) if (!old_records.emplace(r.key, r.value).second) return false;
        for (const auto& r : after.filesystem) if (!new_records.emplace(r.key, r.value).second) return false;
        const Raw* old_raw = nullptr;
        const Raw* next_raw = nullptr;
        const auto locate = [&](const auto& records, const Raw*& inode) {
            for (const auto& record : records)
            {
                const auto key = catalog::ReadU64LE(record.key, 0).value_or(0);
                if ((key & 0x0fffffffffffffffULL) == proof.object && (key >> 60) == Inode)
                {
                    if (inode) return false;
                    inode = &record;
                }
            }
            return inode != nullptr;
        };
        rw::AppleInodeRecord old, next;
        std::string error;
        if (!locate(before.filesystem, old_raw) || !locate(after.filesystem, next_raw) ||
            !rw::ApfsExtendedRecordCodec::DecodeInode(*old_raw, old, error) ||
            !rw::ApfsExtendedRecordCodec::DecodeInode(*next_raw, next, error)) return false;
        Raw canonical_old, canonical_next;
        if (!rw::EncodeAppleInodeRecord(old, canonical_old, error) ||
            !rw::EncodeAppleInodeRecord(next, canonical_next, error) ||
            canonical_old.key != old_raw->key || canonical_old.value != old_raw->value ||
            canonical_next.key != next_raw->key || canonical_next.value != next_raw->value) return false;
        auto expected = old;
        expected.bsd_flags &= ~rw::kAppleBsdCompressedFlag;
        expected.uncompressed_size = proof.size;
        if (expected.write_generation != UINT32_MAX) ++expected.write_generation;
        auto modification = UniqueInode(original, proof.object)->modification_time_utc;
        auto change = UniqueInode(original, proof.object)->change_time_utc;
        for (const auto& record : batch.mutations)
            if (record.operation == Wal::OperationKind::SetInodeMetadata)
            {
                rw::InodeMetadataPatch patch;
                if (!rw::DecodeInodeMetadataPatch(record.inline_payload, patch)) return false;
                if (patch.mask & rw::InodeMetadataPatch::ModificationTime) modification = patch.modification_time_utc;
                if (patch.mask & rw::InodeMetadataPatch::ChangeTime) change = patch.change_time_utc;
            }
        const auto* projected_old = UniqueInode(original, proof.object);
        if (modification != projected_old->modification_time_utc)
            expected.modification_time = (modification - rw::InodeMetadataPatch::UnixEpochTicks) * 100;
        if (change != projected_old->change_time_utc)
            expected.change_time = (change - rw::InodeMetadataPatch::UnixEpochTicks) * 100;
        auto name = std::find_if(expected.extended_fields.begin(), expected.extended_fields.end(),
            [](const auto& field) { return field.type == 4; });
        if (name == expected.extended_fields.end())
        {
            auto bytes = projected_old->name_utf8;
            if (bytes.empty())
            {
                const auto encoded = rw::ApfsNameCodec::EncodeWindowsName(projected_old->name);
                if (!encoded.ok()) return false;
                bytes = *encoded.value;
            }
            if (bytes.empty()) return false;
            std::vector<std::byte> value(reinterpret_cast<const std::byte*>(bytes.data()),
                reinterpret_cast<const std::byte*>(bytes.data() + bytes.size()));
            value.push_back(std::byte{0});
            expected.extended_fields.push_back({4, 0, std::move(value)});
        }
        // Use the native projection for data-stream length/allocation decoding;
        // retain every other byte of the codec's typed extended field. No raw
        // inode byte offsets or competing inode/decmpfs parsers live here.
        rw::AppleExtendedField* original_stream = nullptr;
        const rw::AppleExtendedField* new_stream = nullptr;
        for (auto& field : expected.extended_fields) if (field.type == 8)
        {
            if (original_stream || field.data.size() != 40 ||
                catalog::ReadU64LE(field.data, 0).value_or(1) ||
                catalog::ReadU64LE(field.data, 8).value_or(1) ||
                catalog::ReadU64LE(field.data, 16).value_or(1)) return false;
            original_stream = &field;
        }
        for (const auto& field : next.extended_fields) if (field.type == 8)
        {
            if (new_stream || field.data.size() != 40) return false;
            new_stream = &field;
        }
        if (!new_stream) return false;
        if (!original_stream)
        {
            expected.extended_fields.push_back({8, 0, std::vector<std::byte>(40)});
            original_stream = &expected.extended_fields.back();
        }
        if (new_stream->flags != original_stream->flags ||
            !std::equal(new_stream->data.begin() + 16, new_stream->data.end(), original_stream->data.begin() + 16) ||
            UniqueInode(published, proof.object)->logical_size != proof.size ||
            UniqueInode(published, proof.object)->allocation_size != allocated) return false;
        std::copy_n(new_stream->data.begin(), 16, original_stream->data.begin());
        Raw expected_raw;
        if (!rw::EncodeAppleInodeRecord(expected, expected_raw, error) ||
            expected_raw.key != next_raw->key || expected_raw.value != next_raw->value) return false;
        old_records.erase(old_raw->key); new_records.erase(next_raw->key);
        // Everything outside the specifically authorized removals/new data
        // stream must be byte-identical, including aliases, sibling records,
        // other inodes, unknown extended metadata and independent forks.
        for (const auto& record : before.filesystem)
        {
            const auto key = catalog::ReadU64LE(record.key, 0).value_or(0);
            const auto id = key & 0x0fffffffffffffffULL, type = key >> 60;
            if (id == proof.object && (type == CryptoState || type == FileInfo || type == DirectoryStats)) return false;
            if (type == Xattr && id == proof.object)
            {
                rw::AppleXattrRecord attr;
                if (!rw::ApfsExtendedRecordCodec::DecodeXattr(record, attr, error) ||
                    (!rw::IsOrdinaryAppleXattrName(attr.name_utf8) && attr.name_utf8 != "com.apple.decmpfs" &&
                        attr.name_utf8 != "com.apple.ResourceFork")) return false;
                if (attr.name_utf8 == "com.apple.decmpfs" || (rw::CompressionRewrite::UsesResourceFork(proof.type) && attr.name_utf8 == "com.apple.ResourceFork"))
                {
                    if (new_records.contains(record.key)) return false;
                    old_records.erase(record.key);
                }
            }
            if (retired.contains(id) && (type == FileExtent || type == DstreamId))
            {
                if (new_records.contains(record.key)) return false;
                old_records.erase(record.key);
            }
            if (id == proof.private_id && type == FileExtent) return false;
        }
        std::uint64_t covered = 0;
        std::size_t stream_count = 0;
        std::vector<rw::AppleFileExtentRecord> extents;
        for (const auto& record : after.filesystem)
        {
            const auto key = catalog::ReadU64LE(record.key, 0).value_or(0);
            const auto id = key & 0x0fffffffffffffffULL, type = key >> 60;
            if (retired.contains(id)) return false;
            if (id != proof.private_id) continue;
            if (type == FileExtent)
            {
                rw::AppleFileExtentRecord extent;
                if (!rw::DecodeAppleFileExtentRecord(record, published.block_size, extent, error) ||
                    !extent.physical_block || extent.crypto_id) return false;
                extents.push_back(extent); new_records.erase(record.key);
            }
            if (type == DstreamId)
            {
                rw::AppleDataStreamIdRecord stream;
                if (!rw::DecodeAppleDataStreamIdRecord(record, stream, error) || stream.reference_count != 1) return false;
                ++stream_count; new_records.erase(record.key);
                const auto prior = old_records.find(record.key);
                if (prior != old_records.end())
                {
                    if (prior->second != record.value) return false;
                    old_records.erase(prior);
                }
            }
        }
        std::sort(extents.begin(), extents.end(), [](const auto& a, const auto& b) { return a.logical_address < b.logical_address; });
        for (const auto& extent : extents)
        {
            if (extent.logical_address != covered || extent.length_bytes > allocated - covered) return false;
            covered += extent.length_bytes;
        }
        if (covered != allocated || stream_count != 1 || old_records != new_records) return false;
        // Extent-reference removal is checked separately from attribute absence.
        // Historical allocation remains pinned by LoadAppleRecoveryCheckpoints.
        using Range = std::pair<std::uint64_t, std::uint64_t>;
        std::vector<Range> removed, added;
        const auto add_range = [&](auto& ranges, std::uint64_t block, std::uint64_t bytes) {
            if (!block || !bytes || bytes % original.block_size ||
                ranges.size() >= MaxTreeRecords || block > UINT64_MAX - bytes / original.block_size) return false;
            ranges.emplace_back(block, block + bytes / original.block_size);
            return true;
        };
        for (const auto stream : retired)
        {
            const auto found = original.attribute_stream_extents.find(stream);
            if (found == original.attribute_stream_extents.end() || !found->second) return false;
            for (const auto& extent : *found->second)
                if (extent.physical_address % original.block_size ||
                    !add_range(removed, extent.physical_address / original.block_size, extent.bytes)) return false;
        }
        for (const auto& extent : extents)
            if (!add_range(added, extent.physical_block, extent.length_bytes)) return false;
        // An attribute's physical owner is its header inode, not its stream ID.
        // Subtract only authenticated stream/file ranges, preserving independent
        // attributes with the same owner and any coalesced neighboring records.
        const auto unrelated = [&](const auto& records, std::vector<Range> excluded,
                                   std::uint64_t excluded_owner, Records& output) {
            std::sort(excluded.begin(), excluded.end());
            for (std::size_t i = 1; i < excluded.size(); ++i)
                if (excluded[i].first < excluded[i - 1].second) return false;
            auto sorted = records;
            std::sort(sorted.begin(), sorted.end(), [](const auto& a, const auto& b) {
                return a.physical_block < b.physical_block;
            });
            std::vector<rw::ApplePhysicalExtentRecord> retained_refs;
            const auto retain = [&](const auto& source, std::uint64_t begin, std::uint64_t end) {
                if (begin == end) return;
                auto part = source;
                part.physical_block = begin; part.block_count = end - begin;
                if (!retained_refs.empty())
                {
                    auto& prior = retained_refs.back();
                    if (prior.physical_block + prior.block_count == begin && prior.kind == part.kind &&
                        prior.owning_object_id == part.owning_object_id && prior.reference_count == part.reference_count)
                    {
                        prior.block_count += part.block_count;
                        return;
                    }
                }
                retained_refs.push_back(part);
            };
            std::size_t range = 0;
            for (const auto& extent : sorted)
            {
                if (!extent.block_count || extent.physical_block > UINT64_MAX - extent.block_count) return false;
                const auto end = extent.physical_block + extent.block_count;
                auto cursor = extent.physical_block;
                while (range < excluded.size() && excluded[range].first < end)
                {
                    auto& cut = excluded[range];
                    if (cut.first < cursor || extent.owning_object_id != excluded_owner || extent.reference_count != 1)
                        return false;
                    retain(extent, cursor, cut.first);
                    cursor = (std::min)(end, cut.second);
                    if (cursor == cut.second) ++range;
                    else cut.first = cursor;
                }
                retain(extent, cursor, end);
            }
            if (range != excluded.size()) return false;
            for (const auto& extent : retained_refs)
            {
                Raw encoded;
                if (!rw::EncodeApplePhysicalExtentRecord(extent, encoded, error) ||
                    !output.emplace(encoded.key, encoded.value).second) return false;
            }
            return true;
        };
        Records old_refs, new_refs;
        return unrelated(before.physical, std::move(removed), proof.object, old_refs) &&
            unrelated(after.physical, std::move(added), proof.private_id, new_refs) && old_refs == new_refs;
    }
};
}
