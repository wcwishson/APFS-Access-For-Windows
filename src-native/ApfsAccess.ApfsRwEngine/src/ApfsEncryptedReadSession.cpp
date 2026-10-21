#include "ApfsEncryptedReadSession.h"
#include "ApfsEncryptedSnapshotReadContext.h"
#include "ApfsSoftwareKeybagEra.h"
#include "SoftwareEncryptedRetentionAuthority.h"
#include "InodeMetadataPatch.h"
#include "ApfsFormat.h"
#include "ApfsExtendedRecordCodec.h"
#include "ApfsEncryptedWriteTransform.h"
#include "EncryptedDeltaData.h"
#include "EncryptedDeltaTree.h"
#include "AppleSpacemanAllocator.h"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <atomic>
#include <limits>
#include <map>
#include <mutex>
#include <set>
#include <stdexcept>
#include <type_traits>

namespace apfsaccess::catalog
{
namespace
{
using Error = EncryptedReadError;
constexpr std::uint64_t kInodeHasResourceFork = 0x4000;
constexpr std::uint64_t kInodeNoResourceFork = 0x8000;
void Wipe(std::vector<std::byte>& bytes) noexcept
{
    // Ordinary parser materializations are not secret key storage. Clear their
    // live bytes on the owned scope boundary; allocator copies are not covered.
    volatile std::byte* data = bytes.data();
    for (std::size_t i = 0; i < bytes.size(); ++i) data[i] = std::byte{};
    bytes.clear();
}
template<class T> void WipeScalar(T& value) noexcept
{
    static_assert(std::is_trivially_copyable_v<T>);
    volatile std::byte* data = reinterpret_cast<volatile std::byte*>(&value);
    for (std::size_t i = 0; i < sizeof(value); ++i) data[i] = {};
}
template<class T> void WipeText(T& text) noexcept
{
    volatile typename T::value_type* data = text.data();
    for (std::size_t i = 0; i < text.size(); ++i) data[i] = {};
    text.clear();
}
void Clear(rw::AppleInodeRecord& value) noexcept
{ for (auto& f : value.extended_fields) Wipe(f.data); value.extended_fields.clear(); }
void Clear(rw::AppleDirectoryRecord& value) noexcept
{ WipeText(value.name_utf8); for (auto& f : value.extended_fields) Wipe(f.data); value.extended_fields.clear(); }
void Clear(rw::AppleSiblingLinkRecord& value) noexcept { WipeText(value.name_utf8); }
void Clear(rw::AppleXattrRecord& value) noexcept { WipeText(value.name_utf8); Wipe(value.data); }
void Clear(rw::ApfsName& value) noexcept
{ WipeText(value.original_utf8); WipeText(value.windows_display); Wipe(value.lookup_key); }
void Clear(EncryptedDirectoryEntry& value) noexcept { WipeText(value.name_utf8); WipeText(value.windows_name); }
void Clear(EncryptedXattr& value) noexcept { WipeText(value.name_utf8); Wipe(value.data); }
void Clear(std::vector<std::byte>& value) noexcept { Wipe(value); }
template<class T> void Clear(std::vector<T>& values) noexcept { for (auto& v : values) Clear(v); values.clear(); }
template<class T> struct Cleanup
{
    T& value;
    ~Cleanup() { Clear(value); }
};
struct Records
{
    std::vector<BtreeRecord> bytes;
    ~Records() { for (auto& r : bytes) { Wipe(r.key); Wipe(r.value); } }
};
// Apple-made images also use a data-only xf_used_data count. Adapt only an
// exact, bounded frame to the shared codec's descriptor-inclusive convention.
// The codec still validates every descriptor, field size and aligned data end.
template<class T, class Decode> bool DecodeImageRecord(const BtreeRecord& record,
    std::size_t offset, T& output, std::string& detail, Decode decode)
{
    const auto count = ReadU16LE(record.value, offset);
    const auto used = ReadU16LE(record.value, offset + 2);
    if (!count || !used || *count == 0 || *count > 1024)
        return decode(record, output, detail);
    const auto descriptors = static_cast<std::size_t>(*count) * 4;
    if (offset + 4 + descriptors + *used != record.value.size() ||
        descriptors + *used > UINT16_MAX)
        return decode(record, output, detail);
    Records adapted;
    adapted.bytes.emplace_back();
    auto& copy = adapted.bytes.back();
    copy.key = record.key; copy.value = record.value;
    const auto total = static_cast<std::uint16_t>(descriptors + *used);
    copy.value[offset + 2] = static_cast<std::byte>(total & 0xFF);
    copy.value[offset + 3] = static_cast<std::byte>(total >> 8);
    return decode(copy, output, detail);
}
Error CryptoErrorFor(crypto::CryptoError error)
{
    using C = crypto::CryptoError;
    return error == C::ResourceLimit || error == C::AllocationFailed || error == C::MemoryLockFailed
        ? Error::ResourceLimit : Error::CryptoFailure;
}
}

struct ApfsEncryptedReadSession::Impl final : RandomAccessSource, BtreeNodeReadContext
{
    struct CowPlanner;
    std::shared_ptr<const ImmutableEncryptedReadSource> source;
    std::shared_ptr<ApfsReadBudget> budget;
    std::optional<EncryptedRuntimeReadLimits> runtime_limits;
    ApfsReadBudget* operation_budget = nullptr; // Borrowed only inside RuntimeScope under mutex.
    std::string identity;
    std::uint64_t revision = 0, source_size = 0;
    std::atomic<bool> cancelled{false};
    std::shared_ptr<const std::atomic<bool>> external_cancellation;
    std::mutex mutex;
    bool closed = false;
    mutable Error failure = Error::None;
    mutable Error source_failure = Error::None;
    PasswordUnlockResult key;
    ContainerCheckpointView checkpoint;
    ApsbVolume volume;
    crypto::SecureBytes node;
    std::vector<std::byte> node_ciphertext;
    struct File
    {
        EncryptedFileInfo info;
        std::uint64_t private_id = 0;
        bool sparse = false;
        std::vector<rw::AppleFileExtentRecord> extents;
    };
    std::map<std::uint64_t, File> files;
    rw::ApfsNamePolicy name_policy;
    bool namespace_ready = false;
    std::map<std::uint64_t, EncryptedNodeInfo> nodes;
    std::map<std::uint64_t, std::string> primary_names;
    struct Entry
    {
        EncryptedDirectoryEntry info;
        std::vector<std::byte> lookup_key;
        Entry() = default;
        Entry(Entry&&) = default;
        Entry& operator=(Entry&&) = default;
        ~Entry() { Clear(info); Wipe(lookup_key); }
    };
    std::vector<Entry> entries;
    std::map<std::uint64_t, std::vector<std::size_t>> children;
    struct Attribute
    {
        std::uint64_t inode_id = 0;
        EncryptedXattr info;
        Attribute() = default;
        Attribute(Attribute&&) = default;
        Attribute& operator=(Attribute&&) = default;
        ~Attribute() { Clear(info); }
    };
    std::vector<Attribute> attributes;
    std::vector<rw::AppleSiblingLinkRecord> siblings;
    std::map<std::uint64_t, std::uint64_t> sibling_maps;
    // Borrowed only by a synchronous, keyless historical namespace projection
    // under the authority's mutex. No projection escapes the public call.
    const Impl* projection_authority = nullptr;
    void ClearMetadata() noexcept
    {
        entries.clear(); attributes.clear(); Clear(siblings); sibling_maps.clear(); children.clear();
        // Scalar inode/extent metadata is decrypted too.
        for (auto& [id, n] : nodes) { (void)id; WipeScalar(n); }
        nodes.clear();
        for (auto& [id, name] : primary_names) { (void)id; WipeText(name); }
        primary_names.clear();
        for (auto& [id, f] : files)
        {
            (void)id;
            for (auto& e : f.extents) WipeScalar(e);
            WipeScalar(f.info); WipeScalar(f.private_id);
        }
        files.clear(); namespace_ready = false;
    }
    ~Impl() { ReleaseNode(); ClearMetadata(); }


    bool Fail(Error error) const {
        if (failure == Error::None) failure = error;
        return false;
    }
    bool FailSource(Error error) const
    {
        if (source_failure == Error::None) source_failure = error;
        return Fail(source_failure);
    }
    // Construct only at public runtime boundaries, never during Unlock/Initialize.
    // No shared budget is reset or refilled. Stack lifetime also covers exceptions.
    struct RuntimeScope
    {
        Impl& owner;
        std::optional<ApfsReadBudget> allowance;
        explicit RuntimeScope(Impl& impl) : owner(impl)
        {
            if (owner.runtime_limits)
            {
                const auto& limits = *owner.runtime_limits;
                allowance.emplace(limits.reads, limits.read_bytes, limits.records, limits.materialized_bytes);
                owner.operation_budget = &*allowance;
            }
        }
        ~RuntimeScope() { owner.operation_budget = nullptr; }
        RuntimeScope(const RuntimeScope&) = delete;
        RuntimeScope& operator=(const RuntimeScope&) = delete;
    };
    bool BindRuntimeLimits()
    {
        if (!Check()) return false;
        runtime_limits = source->RuntimeReadLimits();
        if (runtime_limits)
        {
            const EncryptedRuntimeReadLimits ceiling;
            auto& limits = *runtime_limits;
            limits.reads = std::min(limits.reads, ceiling.reads);
            limits.read_bytes = std::min(limits.read_bytes, ceiling.read_bytes);
            limits.records = std::min(limits.records, ceiling.records);
            limits.materialized_bytes = std::min(limits.materialized_bytes, ceiling.materialized_bytes);
        }
        return Check();
    }
    bool Check() const
    {
        if (projection_authority && !projection_authority->Check())
            return Fail(projection_authority->failure);
        if (closed) return Fail(Error::Closed);
        if (cancelled.load() || (external_cancellation && external_cancellation->load()))
            return FailSource(Error::Cancelled);
        if (source_failure != Error::None) return Fail(source_failure);
        if (!source || source->SourceIdentity() != identity || source->Revision() != revision ||
            source->SizeBytes() != source_size || source->ReadBudget() != budget)
            return FailSource(Error::SourceIdentityMismatch);
        if (!budget || budget->Failed()) return FailSource(Error::ResourceLimit);
        // Source callbacks can block or signal cancellation. Check again after
        // the last borrowed callback, before publishing even cached metadata.
        if (cancelled.load() || (external_cancellation && external_cancellation->load()))
            return FailSource(Error::Cancelled);
        if (operation_budget && operation_budget->Failed()) return Fail(Error::ResourceLimit);
        return true;
    }
    std::uint64_t SizeBytes() const override { return source_size; }
    std::shared_ptr<ApfsReadBudget> ReadBudget() const override
    { return operation_budget ? std::shared_ptr<ApfsReadBudget>(budget, operation_budget) : budget; }
    bool Read(std::uint64_t offset, std::size_t size, std::vector<std::byte>& out) const override
    {
        Wipe(out);
        if (!Check()) return false;
        if (offset > source_size || size > source_size - offset) return Fail(Error::ReadFailure);
        // Own the output through false/short/throw and final binding checks.
        // The reservation is source-bound and cannot be constructed by callers.
        std::vector<std::byte> result;
        Cleanup clear{result};
        bool read;
        if (operation_budget)
        {
            if (!operation_budget->Read(size)) return Fail(Error::ResourceLimit);
            const ImmutableEncryptedReadSource::RuntimeRead request(*source, offset, size);
            read = source->ReadRuntime(request, result);
        }
        else read = source->Read(offset, size, result);
        // Check even failed reads: observed source/cancel failures stay sticky.
        if (!Check()) return false;
        if (!read || result.size() != size)
        {
            return Fail(budget->Failed() ? Error::ResourceLimit : Error::ReadFailure);
        }
        out = std::move(result);
        return true;
    }
    bool Charge(std::uint64_t count, std::uint64_t bytes)
    {
        return (Check() && (operation_budget ? operation_budget : budget.get())->Materialize(count, bytes)) ||
            Fail(Error::ResourceLimit);
    }
    bool ReadBlock(std::uint64_t block, std::vector<std::byte>& out)
    {
        const auto bs = checkpoint.superblock.block_size;
        if (!bs || block >= checkpoint.superblock.block_count || block > UINT64_MAX / bs)
            return Fail(Error::MetadataIntegrityFailure);
        return Read(block * bs, bs, out);
    }
    std::optional<OmapValue> Mapping(std::uint64_t map, std::uint64_t oid, std::uint64_t xid)
    {
        std::string detail;
        auto value = ResolveOmapValue(*this, checkpoint.superblock.block_size, map, oid, xid, detail, true);
        if (!value)
        {
            Fail(budget->Failed() ? Error::ResourceLimit :
                detail.find("Unsupported") != std::string::npos ? Error::UnsupportedEncryptionLayout :
                Error::MetadataIntegrityFailure);
            return {};
        }
        if ((value->flags != 0 && value->flags != 4) ||
            value->size != checkpoint.superblock.block_size)
        { Fail(Error::UnsupportedEncryptionLayout); return {}; }
        if (!value->xid || value->xid > xid || value->physical_block >= checkpoint.superblock.block_count)
        { Fail(Error::MetadataIntegrityFailure); return {}; }
        return value;
    }
    bool Transform(std::span<const std::byte> cipher, std::uint64_t first_unit,
        std::span<std::byte> plain)
    {
        if (cipher.empty() || cipher.size() % 512 || plain.size() != cipher.size() ||
            cipher.size() / 512 - 1 > UINT64_MAX - first_unit)
            return Fail(Error::UnsupportedEncryptionLayout);
        for (std::size_t offset = 0; offset < cipher.size(); offset += 512)
        {
            if (!Charge(0, 512)) return false;
            const auto unit = first_unit + offset / 512;
            std::array<std::byte, 16> tweak{};
            for (unsigned i = 0; i < 8; ++i) tweak[i] = static_cast<std::byte>(unit >> (8 * i));
            auto result = crypto::XtsTransform(key.xts_key.Bytes(), tweak, cipher.subspan(offset, 512),
                crypto::XtsDirection::Decrypt);
            if (!result) return Fail(CryptoErrorFor(result.error));
            std::copy(result.bytes.Bytes().begin(), result.bytes.Bytes().end(), plain.begin() + offset);
        }
        return Check();
    }
    bool ReadNode(std::uint64_t oid, std::uint64_t physical, bool root,
        std::span<const std::byte>& bytes, std::string& detail) override
    {
        bytes = {};
        auto mapping = Mapping(volume.omap_oid, oid, volume.xid);
        if (!mapping) return false;
        return ReadMappedNode(oid, {physical, mapping->xid, mapping->flags, mapping->size}, root, bytes, detail);
    }
    bool ReadMappedNode(std::uint64_t oid, const BtreeVirtualChildMapping& selected, bool root,
        std::span<const std::byte>& bytes, std::string& detail) override
    {
        bytes = {};
        ReleaseNode();
        auto mapping = Mapping(volume.omap_oid, oid, volume.xid);
        if (!mapping) return false;
        const auto physical = selected.physical_block;
        if (mapping->physical_block != physical || mapping->xid != selected.xid ||
            mapping->flags != selected.flags || mapping->size != selected.size)
        { detail = "AppleEncryptedMappingBindingMismatch"; return Fail(Error::SourceIdentityMismatch); }
        if (!ReadBlock(physical, node_ciphertext)) return false;
        const auto bs = checkpoint.superblock.block_size;
        if (!Charge(0, bs)) return false;
        auto allocation = crypto::SecureBytes::Allocate(bs);
        if (!allocation) return Fail(CryptoErrorFor(allocation.error));
        node = std::move(allocation.bytes);
        if (mapping->flags == 4)
        {
            const std::uint64_t units = bs / 512;
            if (physical > UINT64_MAX / units) return Fail(Error::UnsupportedEncryptionLayout);
            if (!Transform(node_ciphertext, physical * units, node.Bytes())) return false;
        }
        else
        {
            std::copy(node_ciphertext.begin(), node_ciphertext.end(), node.Bytes().begin());
        }
        const auto plain = std::span<const std::byte>(node.Bytes());
        // Apple OBJ_ENCRYPTED is the sole extra admitted header bit. Requiring
        // it for OMAP_VAL_ENCRYPTED is an explicit subset, never mask-and-guess.
        const auto type = (root ? kObjectTypeBtree : kObjectTypeBtreeNode) |
            (mapping->flags == 4 ? 0x10000000u : 0u);
        if (!VerifyObjectChecksum(plain, bs)) return Fail(Error::MetadataIntegrityFailure);
        if ((ReadU32LE(plain, 24).value_or(~0u) & ~0x1000FFFFu) != 0 ||
            (ReadU16LE(plain, 32).value_or(0xFFFFu) & ~7u) != 0)
            return Fail(Error::UnsupportedEncryptionLayout);
        if (ReadU64LE(plain, 8) != oid ||
            ReadU64LE(plain, 16) != mapping->xid || ReadU32LE(plain, 24) != type ||
            ReadU32LE(plain, 28) != kObjectTypeFsTree)
            return Fail(Error::MetadataIntegrityFailure);
        bytes = plain;
        return true;
    }
    void ReleaseNode() noexcept override { node.Clear(); Wipe(node_ciphertext); }

    bool Initialize()
    {
        if (!Check() || !key) return false;
        std::string detail;
        auto selected = LoadContainerCheckpointView(*this, 0, source_size, detail, key.checkpoint_xid);
        if (!selected) return Fail(budget->Failed() ? Error::ResourceLimit : Error::MetadataIntegrityFailure);
        checkpoint = std::move(*selected);
        const auto& nx = checkpoint.superblock;
        const auto bs = nx.block_size;
        if (bs < 4096 || bs > 65536 || (bs & (bs - 1)) ||
            nx.readonly_features || (nx.incompatible_features & ~kNxSupportedIncompatibleFeaturesMask))
            return Fail(Error::UnsupportedEncryptionLayout);
        if (nx.block_count > UINT64_MAX / bs || nx.block_count * bs != source_size ||
            nx.uuid_hex != BytesToHexLower(key.container_uuid.data(), 16) || nx.xid != key.checkpoint_xid ||
            ReadU32LE(checkpoint.superblock_bytes, 24) != (kObjectEphemeral | kNxSuperblockObjectType) ||
            ReadU32LE(checkpoint.superblock_bytes, 28) != 0u ||
            std::find(nx.fs_oids.begin(), nx.fs_oids.end(), key.volume_oid) == nx.fs_oids.end())
            return Fail(Error::SourceIdentityMismatch);
        // The container OMAP is manually managed on Apple-made containers.
        // Reuse its strict readonly checkpoint selection; volume OMAP reads
        // below retain their separate generation-zero encrypted profile.
        auto readonly = LoadAppleReadOnlyVolumeView(*this,checkpoint,detail);
        if (!readonly) return Fail(budget->Failed() ? Error::ResourceLimit : Error::MetadataIntegrityFailure);
        const auto selected_volume = std::find_if(readonly->volumes.begin(),readonly->volumes.end(),
            [&](const auto& value) { return value.superblock.object_id == key.volume_oid; });
        if (selected_volume == readonly->volumes.end()) return Fail(Error::SourceIdentityMismatch);
        std::vector<std::byte> apsb;
        if (!ReadBlock(selected_volume->superblock_object.physical_block, apsb)) return false;
        auto parsed = ParseApsb(apsb);
        if (!parsed || parsed->object_id != key.volume_oid || parsed->xid != key.volume_xid ||
            parsed->xid != selected_volume->superblock.xid || parsed->uuid_hex != BytesToHexLower(key.volume_uuid.data(), 16) ||
            ReadU32LE(apsb, 24) != kObjectTypeFs || ReadU32LE(apsb, 28) != 0u)
            return Fail(Error::SourceIdentityMismatch);
        volume = std::move(*parsed);
        // ENC_ROLLED records historical key changes. Only the current ONEKEY
        // generation-zero profile is admitted; active rolling and other OMAP
        // generations still fail in Mapping before any plaintext publication.
        constexpr std::uint64_t encryption_rolled = 0x4;
        if (volume.fs_flags != kFsFlagOneKey || volume.readonly_features ||
            (volume.features & ~kVolumeKnownOptionalFeaturesMask) ||
            (volume.incompatible_features & ~(kVolumeSupportedIncompatibleFeaturesMask | encryption_rolled)) ||
            ReadU64LE(apsb, 0x3D0).value_or(~0ULL) != 0 ||
            volume.root_tree_type != kObjectTypeBtree || volume.fext_tree_oid != 0)
            return Fail(Error::UnsupportedEncryptionLayout);
        auto root = Mapping(volume.omap_oid, volume.root_oid, volume.xid);
        if (!root) return false;
        BtreeReadPolicy policy;
        policy.enforce_object_identity = true;
        policy.root_object_id = volume.root_oid;
        policy.subtype = kObjectTypeFsTree;
        policy.require_complete_traversal = true;
        policy.reject_unsupported_flags = true;
        policy.virtual_child_resolver = [&](std::uint64_t oid, std::string&)
            -> std::optional<BtreeVirtualChildMapping>
        {
            auto child = Mapping(volume.omap_oid, oid, volume.xid);
            if (!child) return {};
            return BtreeVirtualChildMapping{child->physical_block, child->xid, child->flags, child->size};
        };
        Records records;
        if (!ReadBtreeLeafRecords(*this, bs, root->physical_block, false, volume.omap_oid,
                volume.xid, policy, records.bytes, detail, this))
            return Fail(budget->Failed() ? Error::ResourceLimit : Error::MetadataIntegrityFailure);
        // Reuse the existing key validator/comparator, including directory-key
        // mode. Compare with a charged sorted copy so malformed ordering is
        // refused rather than repaired during readonly projection.
        Records ordered;
        for (const auto& record : records.bytes)
            if (!Charge(1, 8192 + 32ULL * (record.key.size() + record.value.size()))) return false;
        // A vector's deep-copy constructor can discard a partially copied
        // record before Records sees it. Guard each key/value until insertion.
        for (const auto& record : records.bytes)
        {
            BtreeRecord copy;
            struct ClearUnpublishedCopy
            {
                BtreeRecord& record;
                ~ClearUnpublishedCopy() { Wipe(record.key); Wipe(record.value); }
            } clear_copy{copy};
            copy.key = record.key;
            copy.value = record.value;
            ordered.bytes.push_back(std::move(copy));
        }
        name_policy = rw::ApfsNamePolicy::FromIncompatibleFeatures(volume.incompatible_features);
        if (!rw::SortAppleBtreeRecords(ordered.bytes, name_policy.UsesHashedDirectoryKeys()
                ? rw::AppleBtreeKeyOrder::FileSystemHashedDirectory
                : rw::AppleBtreeKeyOrder::FileSystemCaseSensitive, detail))
            return Fail(Error::MetadataIntegrityFailure);
        for (std::size_t i = 0; i < records.bytes.size(); ++i)
            if (ordered.bytes[i].key != records.bytes[i].key) return Fail(Error::MetadataIntegrityFailure);
        if (!Project(records.bytes)) return false;
        return Check();
    }

    bool Project(const std::vector<BtreeRecord>& records)
    {
        std::string detail;
        std::map<std::uint64_t, std::vector<rw::AppleFileExtentRecord>> streams;
        std::map<std::uint64_t, std::uint32_t> stream_references;
        bool crypto_placeholder_seen = false;
        for (const auto& record : records)
        {
            const auto header = ReadU64LE(record.key, 0);
            if (!header) return Fail(Error::MetadataIntegrityFailure);
            switch (*header >> 60)
            {
            case 3:
            {
                rw::AppleInodeRecord inode;
                Cleanup clear_inode{inode};
                if (!Charge(0, 16 * static_cast<std::uint64_t>(record.value.size()) + sizeof(inode))) return false;
                if (!DecodeImageRecord(record, 0x5c, inode, detail, rw::ApfsExtendedRecordCodec::DecodeInode))
                    return Fail(Error::MetadataIntegrityFailure);
                const auto mode = inode.mode & 0170000;
                if ((mode != 0100000 && mode != 0040000 && mode != 0120000) || (inode.bsd_flags & rw::kAppleBsdCompressedFlag) ||
                    (inode.internal_flags & ~(rw::kAppleInodeSparseFlag | kInodeHasResourceFork | kInodeNoResourceFork)) ||
                    (inode.internal_flags & (kInodeHasResourceFork | kInodeNoResourceFork)) ==
                        (kInodeHasResourceFork | kInodeNoResourceFork))
                    return Fail(Error::UnsupportedEncryptionLayout);
                EncryptedNodeInfo metadata;
                metadata.inode_id = inode.object_id; metadata.parent_id = inode.parent_id;
                metadata.private_id = inode.private_id; metadata.mode = inode.mode;
                metadata.uid = inode.owner; metadata.gid = inode.group; metadata.bsd_flags = inode.bsd_flags;
                metadata.internal_flags = inode.internal_flags;
                metadata.protection_class = inode.default_protection_class; metadata.write_generation = inode.write_generation;
                metadata.children_or_links = static_cast<std::uint32_t>(inode.children_or_links);
                metadata.create_time = inode.create_time; metadata.modification_time = inode.modification_time;
                metadata.change_time = inode.change_time; metadata.access_time = inode.access_time;
                rw::AppleDataStreamRecord stream;
                bool found = false;
                for (const auto& field : inode.extended_fields)
                {
                    if (field.type == 4)
                    {
                        if (field.data.size() < 2 || field.data.back() != std::byte{})
                            return Fail(Error::MetadataIntegrityFailure);
                        auto name = rw::ApfsNameCodec::Decode(std::span(field.data).first(field.data.size()-1), name_policy);
                        if (!name.ok()) return Fail(Error::MetadataIntegrityFailure);
                        Cleanup clear_name{*name.value};
                        primary_names[inode.object_id] = std::move(name.value->original_utf8);
                        continue;
                    }
                    if (field.type == 1 || field.type == rw::kAppleInodeSparseBytesField)
                    {
                        if (field.data.size() != 8) return Fail(Error::MetadataIntegrityFailure);
                        continue;
                    }
                    if (field.type != 8) return Fail(Error::UnsupportedEncryptionLayout);
                    if (found || !rw::ApfsExtendedRecordCodec::DecodeDataStream(field, stream, detail))
                        return Fail(Error::MetadataIntegrityFailure);
                    found = true;
                }
                if (mode == 0040000 || mode == 0120000)
                {
                    if (found || (inode.internal_flags & ~kInodeNoResourceFork))
                        return Fail(Error::UnsupportedEncryptionLayout);
                }
                else if (!found) return Fail(Error::UnsupportedEncryptionLayout);
                metadata.size = stream.size; metadata.allocated_size = stream.allocated_size;
                metadata.default_crypto_id = stream.default_crypto_id;
                if (!Charge(1, sizeof(metadata) + 96)) return false;
                if (!nodes.emplace(inode.object_id, metadata).second) return Fail(Error::MetadataIntegrityFailure);
                if (mode != 0100000) break;
                if (!Charge(1, sizeof(File))) return false;
                File file{{inode.object_id, stream.size, stream.default_crypto_id}, inode.private_id,
                    (inode.internal_flags & rw::kAppleInodeSparseFlag) != 0, {}};
                if (!files.emplace(inode.object_id, std::move(file)).second)
                    return Fail(Error::MetadataIntegrityFailure);
                break;
            }
            case 8:
            {
                rw::AppleEncryptedFileExtentRecord decoded;
                if (!rw::DecodeAppleEncryptedFileExtentRecord(record, checkpoint.superblock.block_size,
                        rw::AppleEncryptedExtentProfile::OneKeyGenerationZero, decoded, detail))
                    return Fail(detail == "AppleEncryptedFileExtentFlagsUnsupported" ||
                        detail == "AppleEncryptedFileExtentCryptoIdInvalid" ||
                        detail == "AppleEncryptedFileExtentProfileUnsupported"
                        ? Error::UnsupportedEncryptionLayout : Error::MetadataIntegrityFailure);
                const auto& extent = decoded.extent;
                if (!Charge(1, sizeof(extent))) return false;
                streams[extent.object_id].push_back(extent);
                break;
            }
            case 6:
            {
                rw::AppleDataStreamIdRecord stream;
                if (!Charge(1, 96)) return false;
                if (!rw::DecodeAppleDataStreamIdRecord(record, stream, detail) ||
                    !stream_references.emplace(stream.object_id, stream.reference_count).second)
                    return Fail(Error::MetadataIntegrityFailure);
                break;
            }
            case 7:
            {
                // CRYPTO_SW_ID has no wrapped key in these ONEKEY profiles.
                // Admit the zero state and the observed version-5 meta state;
                // never interpret another record as a per-file key.
                if (crypto_placeholder_seen || record.key.size() != 8 || (*header & 0x0FFFFFFFFFFFFFFFULL) != 4 ||
                    record.value.size() != 24 || ReadU32LE(record.value,0).value_or(~0U) > INT32_MAX)
                    return Fail(Error::UnsupportedEncryptionLayout);
                if (std::any_of(record.value.begin()+4, record.value.end(), [](auto byte) { return byte != std::byte{}; }) &&
                    !(ReadU16LE(record.value,4) == 5 && ReadU16LE(record.value,6) == 0 &&
                      ReadU32LE(record.value,8) == 0 && ReadU32LE(record.value,12) == 3 &&
                      ReadU16LE(record.value,20) == 1 && ReadU16LE(record.value,22) == 0))
                    return Fail(Error::UnsupportedEncryptionLayout);
                crypto_placeholder_seen = true;
                break;
            }
            case 9:
            {
                if (!Charge(4, 8192 + record.key.size() * 64ULL + record.value.size() * 16ULL)) return false;
                rw::AppleDirectoryRecord directory;
                Cleanup clear_directory{directory};
                if (!DecodeImageRecord(record, 18, directory, detail,
                        [&](const auto& value, auto& output, auto& error) {
                            return rw::ApfsExtendedRecordCodec::DecodeDirectory(value, name_policy, output, error);
                        }))
                    return Fail(Error::MetadataIntegrityFailure);
                if (directory.flags & ~0xfu) return Fail(Error::UnsupportedEncryptionLayout);
                Entry entry;
                entry.info.parent_id = directory.parent_id; entry.info.inode_id = directory.file_id;
                entry.info.date_added = directory.date_added; entry.info.flags = directory.flags;
                for (const auto& field : directory.extended_fields)
                {
                    if (field.type != 1) return Fail(Error::UnsupportedEncryptionLayout);
                    if (field.data.size() != 8 || !(entry.info.sibling_id = ReadU64LE(field.data, 0).value()))
                        return Fail(Error::MetadataIntegrityFailure);
                }
                auto decoded = rw::ApfsNameCodec::Decode(std::as_bytes(std::span(directory.name_utf8)), name_policy);
                if (!decoded.ok()) return Fail(Error::MetadataIntegrityFailure);
                Cleanup clear_name{*decoded.value};
                entry.info.name_utf8 = std::move(decoded.value->original_utf8);
                entry.info.windows_name = std::move(decoded.value->windows_display);
                entry.lookup_key = std::move(decoded.value->lookup_key);
                entries.push_back(std::move(entry));
                break;
            }
            case 4:
            {
                if (!Charge(2, 4096 + 16ULL * (record.key.size() + record.value.size()))) return false;
                rw::AppleXattrRecord xattr; Cleanup clear_xattr{xattr};
                if (!rw::ApfsExtendedRecordCodec::DecodeXattr(record, xattr, detail))
                    return Fail(Error::MetadataIntegrityFailure);
                if ((xattr.flags & ~rw::kAppleXattrFileSystemOwned) != rw::kAppleXattrDataEmbedded ||
                    xattr.name_utf8 == "com.apple.decmpfs")
                    return Fail(Error::UnsupportedEncryptionLayout);
                Attribute attribute; attribute.inode_id = xattr.object_id;
                attribute.info.flags = xattr.flags; attribute.info.name_utf8 = std::move(xattr.name_utf8);
                attribute.info.data = std::move(xattr.data); attributes.push_back(std::move(attribute));
                break;
            }
            case 5:
            {
                if (!Charge(2, 4096 + 16ULL * record.value.size())) return false;
                rw::AppleSiblingLinkRecord link; Cleanup clear_link{link};
                if (!rw::ApfsExtendedRecordCodec::DecodeSiblingLink(record, link, detail))
                    return Fail(Error::MetadataIntegrityFailure);
                siblings.push_back(std::move(link)); break;
            }
            case 12:
            {
                if (!Charge(1, 128)) return false;
                rw::AppleSiblingMapRecord map;
                if (!rw::ApfsExtendedRecordCodec::DecodeSiblingMap(record, map, detail) ||
                    !sibling_maps.emplace(map.sibling_id, map.file_id).second)
                    return Fail(Error::MetadataIntegrityFailure);
                break;
            }
            default:
                return Fail(Error::UnsupportedEncryptionLayout);
            }
        }
        const auto bs = checkpoint.superblock.block_size;
        for (auto& [id, file] : files)
        {
            (void)id;
            const auto references = stream_references.find(file.private_id);
            if (references != stream_references.end())
            {
                if (references->second != 1) return Fail(Error::MetadataIntegrityFailure);
                stream_references.erase(references);
            }
            auto stream = streams.find(file.private_id);
            if (stream != streams.end()) { file.extents = std::move(stream->second); streams.erase(stream); }
            std::sort(file.extents.begin(), file.extents.end(), [](const auto& a, const auto& b) {
                return a.logical_address < b.logical_address;
            });
            std::uint64_t end = 0;
            for (const auto& extent : file.extents)
            {
                if (extent.logical_address != end) return Fail(Error::MetadataIntegrityFailure);
                end += extent.length_bytes; // Decoder checked addition.
                if (extent.physical_block == 0)
                {
                    if (!file.sparse) return Fail(Error::MetadataIntegrityFailure);
                    continue;
                }
                if (!extent.crypto_id) return Fail(Error::UnsupportedEncryptionLayout);
                const auto blocks = extent.length_bytes / bs;
                const auto units = bs / 512;
                if (extent.physical_block >= checkpoint.superblock.block_count ||
                    blocks > checkpoint.superblock.block_count - extent.physical_block)
                    return Fail(Error::MetadataIntegrityFailure);
                if (blocks - 1 > UINT64_MAX - extent.crypto_id ||
                    extent.crypto_id + blocks - 1 > (UINT64_MAX - (units - 1)) / units)
                    return Fail(Error::UnsupportedEncryptionLayout);
            }
            if (file.info.size > UINT64_MAX - (bs - 1) ||
                end != ((file.info.size + bs - 1) / bs) * bs)
                return Fail(Error::MetadataIntegrityFailure);
        }
        if (!streams.empty()) return Fail(Error::UnsupportedEncryptionLayout);
        if (!stream_references.empty()) return Fail(Error::MetadataIntegrityFailure);
        return ValidateNamespace();
    }

    bool ValidateNamespace()
    {
        const auto root_entry = std::find_if(entries.begin(),entries.end(),[](const auto& e) { return e.info.inode_id == 2; });
        if (root_entry != entries.end())
        {
            const auto root = nodes.find(2);
            const auto name = primary_names.find(2);
            if (std::count_if(entries.begin(),entries.end(),[](const auto& e) { return e.info.inode_id == 2; }) != 1 ||
                root == nodes.end() || !root->second.IsDirectory() || root->second.parent_id != 1 ||
                name == primary_names.end() || name->second != "root" || root_entry->info.name_utf8 != "root" ||
                root_entry->info.parent_id != 1 || root_entry->info.flags != 4 || root_entry->info.sibling_id)
                return Fail(Error::MetadataIntegrityFailure);
            Clear(root_entry->info); Wipe(root_entry->lookup_key); entries.erase(root_entry);
        }
        // Apple's initialized private directory is outside the user namespace.
        // Only its exact empty reserved profile may be excluded from reachability.
        if (auto hidden = nodes.find(3); hidden != nodes.end())
        {
            const auto& inode = hidden->second;
            const auto name = primary_names.find(3);
            if (!inode.IsDirectory() || inode.parent_id != 1 || inode.private_id != 3 ||
                inode.children_or_links || name == primary_names.end() || name->second != "private-dir" ||
                std::count_if(entries.begin(),entries.end(),[](const auto& e) { return e.info.inode_id == 3; }) != 1 ||
                std::any_of(entries.begin(),entries.end(),[](const auto& e) {
                    return e.info.parent_id == 3 || (e.info.inode_id == 3 &&
                        (e.info.parent_id != 1 || e.info.flags != 4 || e.info.sibling_id || e.info.name_utf8 != "private-dir"));
                }) ||
                std::any_of(attributes.begin(),attributes.end(),[](const auto& a) { return a.inode_id == 3; }) ||
                std::any_of(siblings.begin(),siblings.end(),[](const auto& s) { return s.inode_id == 3 || s.parent_id == 3; }) ||
                std::any_of(sibling_maps.begin(),sibling_maps.end(),[](const auto& s) { return s.second == 3; }))
                return Fail(Error::UnsupportedEncryptionLayout);
            const auto entry = std::find_if(entries.begin(),entries.end(),[](const auto& e) { return e.info.inode_id == 3; });
            Clear(entry->info); Wipe(entry->lookup_key); entries.erase(entry);
            WipeScalar(hidden->second); nodes.erase(hidden);
            WipeText(name->second); primary_names.erase(name);
        }
        // Compatibility with the pre-namespace file API's inode-only vectors.
        // This is an explicit unavailable namespace, never a fabricated root.
        if (!nodes.contains(2) && entries.empty() && attributes.empty() && siblings.empty() && sibling_maps.empty() &&
            std::all_of(nodes.begin(), nodes.end(), [](const auto& n) { return (n.second.mode & 0170000) == 0100000; }))
            return true;
        if (!nodes.contains(2) || !nodes.at(2).IsDirectory() ||
            (nodes.at(2).parent_id != 1 && nodes.at(2).parent_id != 2))
            return Fail(Error::MetadataIntegrityFailure);
        if (!Charge(nodes.size() + entries.size(), 256ULL * nodes.size() + 128ULL * entries.size())) return false;
        std::map<std::uint64_t, std::size_t> incoming;
        std::set<std::uint64_t> primary_parent_seen;
        std::map<std::uint64_t, const rw::AppleSiblingLinkRecord*> links;
        for (const auto& link : siblings)
        {
            if (!Check()) return false;
            const auto map = sibling_maps.find(link.sibling_id);
            if (map == sibling_maps.end() || map->second != link.inode_id ||
                !links.emplace(link.sibling_id, &link).second) return Fail(Error::MetadataIntegrityFailure);
        }
        if (links.size() != sibling_maps.size()) return Fail(Error::MetadataIntegrityFailure);
        for (std::size_t i = 0; i < entries.size(); ++i)
        {
            if (!Check()) return false;
            const auto& e = entries[i].info;
            const auto parent = nodes.find(e.parent_id), child = nodes.find(e.inode_id);
            if (parent == nodes.end() || !parent->second.IsDirectory() || child == nodes.end() ||
                e.inode_id == 2 || e.parent_id == e.inode_id ||
                e.flags != ((child->second.mode >> 12) & 0xfu))
                return Fail(Error::MetadataIntegrityFailure);
            const auto& inode = child->second;
            ++incoming[e.inode_id];
            const auto primary_name = primary_names.find(e.inode_id);
            if (e.parent_id == inode.parent_id && (primary_name == primary_names.end() || primary_name->second == e.name_utf8))
                primary_parent_seen.insert(e.inode_id);
            if (!inode.IsDirectory() && inode.children_or_links > 1)
            {
                const auto link = links.find(e.sibling_id);
                if (link == links.end() || link->second->inode_id != e.inode_id ||
                    link->second->parent_id != e.parent_id || link->second->name_utf8 != e.name_utf8)
                    return Fail(Error::MetadataIntegrityFailure);
                links.erase(link);
            }
            else if (e.sibling_id) return Fail(Error::MetadataIntegrityFailure);
            children[e.parent_id].push_back(i);
        }
        if (!links.empty()) return Fail(Error::MetadataIntegrityFailure);
        for (auto& [parent, indices] : children)
        {
            (void)parent;
            std::sort(indices.begin(), indices.end(), [&](auto a, auto b) { return entries[a].lookup_key < entries[b].lookup_key; });
            for (std::size_t i = 1; i < indices.size(); ++i)
                if (entries[indices[i-1]].lookup_key == entries[indices[i]].lookup_key)
                    return Fail(Error::MetadataIntegrityFailure);
        }
        for (const auto& [id, inode] : nodes)
        {
            if (!Check()) return false;
            const auto expected = id == 2 ? 0u : inode.IsDirectory() ? 1u : inode.children_or_links;
            if ((id != 2 && (!expected || !primary_parent_seen.contains(id))) || incoming[id] != expected ||
                (inode.IsDirectory() && children[id].size() != inode.children_or_links))
                return Fail(Error::MetadataIntegrityFailure);
        }
        // Unique incoming directory links plus root reachability reject cycles,
        // detached subgraphs and directory hard links without recursive traversal.
        std::vector<std::uint64_t> pending{2};
        std::set<std::uint64_t> reached{2};
        for (std::size_t at = 0; at < pending.size(); ++at)
        {
            if (!Check()) return false;
            for (auto index : children[pending[at]])
            {
                const auto id = entries[index].info.inode_id;
                if (reached.insert(id).second && nodes.at(id).IsDirectory()) pending.push_back(id);
            }
        }
        if (reached.size() != nodes.size()) return Fail(Error::MetadataIntegrityFailure);
        for (const auto& a : attributes)
            if (!nodes.contains(a.inode_id)) return Fail(Error::MetadataIntegrityFailure);
        std::sort(attributes.begin(), attributes.end(), [](const auto& a, const auto& b) {
            return a.inode_id != b.inode_id ? a.inode_id < b.inode_id : a.info.name_utf8 < b.info.name_utf8;
        });
        for (std::size_t i = 1; i < attributes.size(); ++i)
            if (attributes[i-1].inode_id == attributes[i].inode_id && attributes[i-1].info.name_utf8 == attributes[i].info.name_utf8)
                return Fail(Error::MetadataIntegrityFailure);
        for (auto& [id, inode] : nodes)
        {
            const bool symlink = (inode.mode & 0170000) == 0120000;
            const Attribute* target = nullptr;
            const Attribute* resource_fork = nullptr;
            const auto first = std::lower_bound(attributes.begin(),attributes.end(),id,
                [](const auto& attribute, auto owner) { return attribute.inode_id < owner; });
            for (auto at = first; at != attributes.end() && at->inode_id == id; ++at)
                {
                    const auto& attribute = *at;
                    if (attribute.info.name_utf8 == "com.apple.ResourceFork") {
                        if (inode.internal_flags & kInodeNoResourceFork) return Fail(Error::MetadataIntegrityFailure);
                        resource_fork = &attribute;
                    }
                    if (attribute.info.name_utf8 == "com.apple.fs.symlink") target = &attribute;
                }
            if (symlink != (target != nullptr)) return Fail(Error::UnsupportedEncryptionLayout);
            if ((inode.internal_flags & kInodeHasResourceFork) &&
                (!resource_fork || !rw::IsUncompressedAppleResourceForkOwner(id, inode.private_id, inode.mode, inode.bsd_flags, false)))
                return Fail(Error::MetadataIntegrityFailure);
            if (target)
            {
                const auto& data = target->info.data;
                if (target->info.flags != (rw::kAppleXattrDataEmbedded | rw::kAppleXattrFileSystemOwned) ||
                    data.size() < 2 || data.size() > 3804 || data.back() != std::byte{} ||
                    std::find(data.begin(),data.end()-1,std::byte{}) != data.end()-1)
                    return Fail(Error::MetadataIntegrityFailure);
                inode.size = data.size()-1;
            }
        }
        for (const auto& [id, file] : files)
        {
            std::uint64_t allocated = 0;
            for (const auto& extent : file.extents)
                if (extent.physical_block) allocated += extent.length_bytes; // bounded by validated logical coverage
            if (nodes.at(id).allocated_size != allocated) return Fail(Error::MetadataIntegrityFailure);
        }
        nodes.at(2).parent_id = 2;
        Clear(siblings); sibling_maps.clear();
        namespace_ready = true;
        return Check();
    }

    Error NamespaceCheck()
    {
        if (!Check()) return failure;
        return namespace_ready ? Error::None : Error::NamespaceUnavailable;
    }
    Error DirectoryCheck(std::uint64_t id)
    {
        if (const auto error = NamespaceCheck(); error != Error::None) return error;
        const auto inode = nodes.find(id);
        if (inode == nodes.end()) return Error::FileNotFound;
        return inode->second.IsDirectory() ? Error::None : Error::NotDirectory;
    }
    Error Find(std::uint64_t parent, std::string_view name, const Entry*& out)
    {
        out = nullptr;
        if (const auto error = DirectoryCheck(parent); error != Error::None) return error;
        if (name.size() > rw::ApfsNameCodec::kMaxApfsNameBytes) return Error::InvalidArgument;
        if (!Charge(1, 8192 + 64ULL * name.size())) return failure;
        auto decoded = rw::ApfsNameCodec::Decode(std::as_bytes(std::span(name)), name_policy);
        if (!decoded.ok()) return Error::InvalidArgument;
        Cleanup clear_name{*decoded.value};
        const auto& indices = children.at(parent);
        const auto found = std::lower_bound(indices.begin(), indices.end(), decoded.value->lookup_key,
            [&](auto i, const auto& key_bytes) { return entries[i].lookup_key < key_bytes; });
        if (!Check()) return failure;
        if (found == indices.end() || entries[*found].lookup_key != decoded.value->lookup_key) return Error::FileNotFound;
        out = &entries[*found]; return Error::None;
    }
    Error FindWindows(std::uint64_t parent, std::wstring_view name, const Entry*& out)
    {
        out = nullptr;
        if (const auto error = DirectoryCheck(parent); error != Error::None) return error;
        if (name.size() > 1024) return Error::InvalidArgument;
        if (!Charge(1, 8192 + 64ULL * name.size())) return failure;
        auto raw = rw::ApfsNameCodec::EncodeWindowsName(name);
        if (!raw.ok()) return Error::InvalidArgument;
        struct ClearText { std::string& text; ~ClearText() { WipeText(text); } } clear{*raw.value};
        return Find(parent, *raw.value, out);
    }
    Error CopyEntry(const Entry& entry, EncryptedDirectoryEntry& output)
    {
        if (!Charge(1, sizeof(output) + entry.info.name_utf8.size() + 2ULL * entry.info.windows_name.size())) return failure;
        EncryptedDirectoryEntry result; Cleanup clear{result};
        // Assign separately under a guard so allocation failure cannot discard a
        // partially deep-copied name before our cleanup sees it.
        result.parent_id = entry.info.parent_id; result.inode_id = entry.info.inode_id;
        result.sibling_id = entry.info.sibling_id; result.date_added = entry.info.date_added; result.flags = entry.info.flags;
        result.name_utf8 = entry.info.name_utf8; result.windows_name = entry.info.windows_name;
        if (!Check()) return failure;
        output = std::move(result); return Error::None;
    }
    // Common publication wrapper for new APIs. The local result stays guarded
    // through the final source/cancellation check, including thrown exceptions.
    template<class T, class F> Error MetadataOperation(T& output, F&& operation)
    {
        output = {};
        std::lock_guard lock(mutex); failure = Error::None;
        try
        {
            RuntimeScope scope(*this);
            if (const auto error = NamespaceCheck(); error != Error::None) return error;
            return operation();
        }
        catch (const std::bad_alloc&) { return Error::ResourceLimit; }
        catch (...) { return Error::ReadFailure; }
    }

    Error ReadFile(std::uint64_t id, std::uint64_t offset, std::size_t size, std::vector<std::byte>& out)
    {
        if (!Check()) return failure;
        const auto it = files.find(id);
        if (it == files.end()) return Error::FileNotFound;
        const auto& file = it->second;
        if (offset > file.info.size || size > file.info.size - offset) return Error::InvalidArgument;
        if (!size) return Error::None;
        if (size > crypto::SecureBytes::kMaxBytes) return Error::ResourceLimit;
        if (!Charge(0, 2 * static_cast<std::uint64_t>(size))) return failure;
        auto result = crypto::SecureBytes::Allocate(size);
        if (!result) return CryptoErrorFor(result.error);
        const auto bs = checkpoint.superblock.block_size;
        const auto end = offset + size;
        std::vector<std::byte> cipher;
        for (const auto& extent : file.extents)
        {
            const auto begin = std::max(offset, extent.logical_address);
            const auto stop = std::min(end, extent.logical_address + extent.length_bytes);
            if (begin >= stop) continue;
            if (!Check()) return failure;
            if (!extent.physical_block) continue; // VirtualAlloc output is zero-filled.
            auto relative = ((begin - extent.logical_address) / 512) * 512;
            while (relative < stop - extent.logical_address)
            {
                const auto physical = extent.physical_block * bs + relative;
                if (!Read(physical, 512, cipher)) return failure;
                const auto unit = (extent.crypto_id + relative / bs) * (bs / 512) + (relative % bs) / 512;
                if (!Charge(0, 512)) return failure;
                auto sector = crypto::SecureBytes::Allocate(512);
                if (!sector) return CryptoErrorFor(sector.error);
                if (!Transform(cipher, unit, sector.bytes.Bytes())) return failure;
                const auto sector_begin = extent.logical_address + relative;
                const auto copy_begin = std::max(begin, sector_begin);
                const auto copy_end = std::min(stop, sector_begin + 512);
                std::copy_n(sector.bytes.Bytes().begin() + (copy_begin - sector_begin),
                    static_cast<std::size_t>(copy_end - copy_begin), result.bytes.Bytes().begin() + (copy_begin - offset));
                relative += 512;
            }
        }
        if (!Check()) return failure;
        std::vector<std::byte> published(result.bytes.Bytes().begin(), result.bytes.Bytes().end());
        struct ClearUnpublished
        {
            std::vector<std::byte>& bytes;
            ~ClearUnpublished() { Wipe(bytes); }
        } clear_unpublished{published};
        if (!Check()) return failure;
        out = std::move(published);
        return Error::None;
    }
};

struct AppleEncryptedMetadataReadContext::State : BtreeNodeReadContext
{
    using RuntimeScope = ApfsEncryptedReadSession::Impl::RuntimeScope;
    std::shared_ptr<ApfsEncryptedReadSession::Impl> session;
    std::optional<ContainerCheckpointView> historical_checkpoint;
    std::optional<ApsbVolume> historical_volume;
    std::vector<std::byte> cipher;
    crypto::SecureBytes plain;
    explicit State(std::shared_ptr<ApfsEncryptedReadSession::Impl> value) : session(std::move(value)) {}
    State(std::shared_ptr<ApfsEncryptedReadSession::Impl> value, ContainerCheckpointView checkpoint, ApsbVolume volume)
        : session(std::move(value)), historical_checkpoint(std::move(checkpoint)), historical_volume(std::move(volume)) {}
    ~State() override { ReleaseNode(); }
    struct NodeScope { State& state; ~NodeScope() { state.ReleaseNode(); } };
    const ContainerCheckpointView& Checkpoint() const { return historical_checkpoint ? *historical_checkpoint : session->checkpoint; }
    const ApsbVolume& Volume() const { return historical_volume ? *historical_volume : session->volume; }
    void ReleaseNode() noexcept override { plain.Clear(); Wipe(cipher); }
    bool ReadNode(std::uint64_t oid, std::uint64_t physical, bool root,
        std::span<const std::byte>& bytes, std::string& error) override
    {
        bytes = {}; ReleaseNode();
        auto map = ResolveOmapValue(*session, 4096, Volume().omap_oid, oid, Volume().xid, error, true);
        return map && ReadMappedNode(oid, {physical, map->xid, map->flags, map->size}, root, bytes, error);
    }
    bool ReadMappedNode(std::uint64_t oid, const BtreeVirtualChildMapping& selected, bool root,
        std::span<const std::byte>& bytes, std::string& error) override
    {
        bytes = {}; ReleaseNode();
        if (!historical_checkpoint || !session->Check()) return false;
        auto map = ResolveOmapValue(*session, 4096, Volume().omap_oid, oid, Volume().xid, error, true);
        if (!map || map->physical_block != selected.physical_block || map->xid != selected.xid ||
            map->flags != selected.flags || map->size != selected.size || map->flags != 4 || map->size != 4096 ||
            !map->xid || map->xid > Volume().xid || map->physical_block >= session->source_size / 4096) {
            error = "SoftwareKeybagEraMappingMismatch"; return false;
        }
        if (!session->Read(map->physical_block * 4096, 4096, cipher)) return false;
        auto allocation = crypto::SecureBytes::Allocate(4096);
        if (!allocation) { error = "SoftwareKeybagEraSecureAllocationFailed"; return false; }
        plain = std::move(allocation.bytes);
        if (!session->Transform(cipher, map->physical_block * 8, plain.Bytes())) return false;
        const auto view = std::span<const std::byte>(plain.Bytes());
        if (!VerifyObjectChecksum(view, 4096) || ReadU64LE(view, 8) != oid || ReadU64LE(view, 16) != map->xid ||
            ReadU32LE(view, 24) != (0x10000000u | (root ? kObjectTypeBtree : kObjectTypeBtreeNode)) ||
            ReadU32LE(view, 28) != kObjectTypeFsTree) { error = "SoftwareKeybagEraNodeIntegrityFailure"; return false; }
        bytes = view; return session->Check();
    }
    bool Bound(const RandomAccessSource& original, std::string& error) const
    {
        if (!session->Check())
        {
            switch (session->failure)
            {
            case Error::Closed: error = "AppleEncryptedContextClosed"; break;
            case Error::Cancelled: error = "AppleEncryptedContextCancelled"; break;
            case Error::ResourceLimit: error = "AppleEncryptedContextResourceLimit"; break;
            default: error = "AppleEncryptedSourceBindingMismatch"; break;
            }
            return false;
        }
        if (&original != session->source.get())
        { error = "AppleEncryptedOriginalSourceMismatch"; return false; }
        return true;
    }
    bool Selection(const ContainerCheckpointView& supplied, const AppleVolumeCheckpointView& volume) const
    {
        const auto& nx = Checkpoint().superblock;
        const auto& v = Volume();
        // Never trust caller-modified semantic fields even with identical NXSB bytes.
        return supplied.superblock_bytes == Checkpoint().superblock_bytes &&
            supplied.superblock.xid == nx.xid && supplied.superblock.uuid_hex == nx.uuid_hex &&
            supplied.superblock.block_size == nx.block_size && supplied.superblock.block_count == nx.block_count &&
            supplied.superblock.omap_oid == nx.omap_oid && supplied.superblock.spaceman_oid == nx.spaceman_oid &&
            supplied.superblock.fs_oids == nx.fs_oids &&
            volume.superblock.object_id == v.object_id && volume.superblock.uuid_hex == v.uuid_hex &&
            volume.superblock.xid == v.xid && volume.superblock.omap_oid == v.omap_oid &&
            volume.superblock.root_oid == v.root_oid && volume.superblock.root_tree_type == v.root_tree_type &&
            volume.superblock.features == v.features && volume.superblock.readonly_features == v.readonly_features &&
            volume.superblock.incompatible_features == v.incompatible_features &&
            volume.superblock.fext_tree_oid == v.fext_tree_oid && volume.superblock.fext_tree_type == v.fext_tree_type &&
            volume.superblock.fs_flags == v.fs_flags;
    }
};

AppleEncryptedMetadataReadContext::AppleEncryptedMetadataReadContext(std::shared_ptr<State> state)
    : state_(std::move(state)) {}
AppleEncryptedMetadataReadContext::~AppleEncryptedMetadataReadContext() = default;

std::unique_ptr<AppleEncryptedMetadataReadContext> ApfsEncryptedReadSession::CreateMetadataReadContext(Error& error)
{
    std::lock_guard lock(impl_->mutex);
    impl_->failure = Error::None;
    if (!impl_->Check()) { error = impl_->failure; return {}; }
    try
    {
        auto result = std::unique_ptr<AppleEncryptedMetadataReadContext>(new AppleEncryptedMetadataReadContext(
            std::make_shared<AppleEncryptedMetadataReadContext::State>(impl_)));
        error = Error::None;
        return result;
    }
    catch (const std::bad_alloc&) { error = Error::ResourceLimit; return {}; }
}

std::unique_ptr<AppleEncryptedMetadataReadContext> ApfsEncryptedReadSession::CreateRetainedVerificationContext(
    std::uint64_t xid, std::string& error)
{
    return CreateHistoricalKeybagEraContext(xid, error);
}

Error ApfsEncryptedReadSession::ValidateRetainedNamespace(AppleEncryptedMetadataReadContext& context,
    EncryptedNamespaceInfo& output, std::string& error)
{
    output = {}; error.clear();
    std::lock_guard lock(impl_->mutex);
    impl_->failure = Error::None;
    auto& state = *context.state_;
    const auto fail = [&](Error code, const char* detail) {
        if (error.empty()) error = detail;
        return code;
    };
    if (state.session != impl_)
        return fail(Error::SourceIdentityMismatch, "RetainedNamespaceContextOwnerMismatch");
    if (!impl_->Check()) return fail(impl_->failure, "RetainedNamespaceSessionRevoked");
    if (!state.historical_checkpoint || !state.historical_volume ||
        !state.Checkpoint().superblock.xid || state.Checkpoint().superblock.xid >= impl_->checkpoint.superblock.xid)
        return fail(Error::InvalidArgument, "RetainedNamespaceHistoricalSelectionRequired");
    AppleEncryptedMetadataReadContext::State::NodeScope clear_node{state};
    try
    {
        Impl::RuntimeScope scope(*impl_);
        if (!state.Bound(*impl_->source, error)) return impl_->failure;
        auto checkpoint = AppleEncryptedMetadataReadContext::LoadCanonical(*impl_, state.Checkpoint(),
            state.Volume(), state, error, false);
        if (!checkpoint) return fail(impl_->Check() ? Error::MetadataIntegrityFailure : impl_->failure,
            "RetainedNamespaceCanonicalSelectionFailure");
        const auto volume = std::find_if(checkpoint->volumes.begin(), checkpoint->volumes.end(),
            [&](const auto& value) { return value.superblock.object_id == state.Volume().object_id; });
        if (volume == checkpoint->volumes.end() || !state.Selection(checkpoint->container, *volume))
            return fail(Error::SourceIdentityMismatch, "RetainedNamespaceSelectionMismatch");
        Records records;
        if (!AppleEncryptedMetadataReadContext::ReadCanonical(*impl_, checkpoint->container, *volume, state, records.bytes, error))
            return fail(impl_->Check() ? Error::MetadataIntegrityFailure : impl_->failure,
                "RetainedNamespaceCanonicalReadFailure");
        if (!impl_->Charge(1, sizeof(Impl))) return fail(impl_->failure, "RetainedNamespaceBudgetExceeded");
        Impl projection;
        projection.projection_authority = impl_.get();
        projection.source = impl_->source; projection.identity = impl_->identity;
        projection.revision = impl_->revision; projection.source_size = impl_->source_size;
        projection.budget = impl_->budget; projection.operation_budget = impl_->operation_budget;
        projection.checkpoint.superblock.block_size = state.Checkpoint().superblock.block_size;
        projection.checkpoint.superblock.block_count = state.Checkpoint().superblock.block_count;
        projection.name_policy = rw::ApfsNamePolicy::FromIncompatibleFeatures(state.Volume().incompatible_features);
        if (!projection.Project(records.bytes))
            return fail(projection.failure, projection.failure == Error::UnsupportedEncryptionLayout
                ? "RetainedNamespaceProfileUnsupported" : "RetainedNamespaceIntegrityFailure");
        if (!projection.namespace_ready)
            return fail(Error::NamespaceUnavailable, "RetainedNamespaceUnavailable");
        if (!state.Bound(*impl_->source, error) || !state.Selection(checkpoint->container, *volume))
            return fail(impl_->failure == Error::None ? Error::SourceIdentityMismatch : impl_->failure,
                "RetainedNamespaceFinalBindingMismatch");
        output = {2, projection.nodes.size(), projection.entries.size(), projection.name_policy};
        return Error::None;
    }
    catch (const std::bad_alloc&) { return fail(Error::ResourceLimit, "RetainedNamespaceAllocationFailed"); }
    catch (...) { return fail(Error::ReadFailure, "RetainedNamespaceReadFailure"); }
}

std::unique_ptr<AppleEncryptedMetadataReadContext> ApfsEncryptedReadSession::CreateHistoricalKeybagEraContext(
    std::uint64_t xid, std::string& error)
{
    std::lock_guard lock(impl_->mutex); impl_->failure = Error::None; error.clear();
    if (!impl_->Check()) { error = "SoftwareKeybagEraSessionRevoked"; return {}; }
    try {
        Impl::RuntimeScope scope(*impl_);
        auto proof = SoftwareKeybagEraAuthority::Prove(*impl_->source, *impl_, impl_->identity, impl_->revision,
            impl_->key, impl_->checkpoint, impl_->volume, xid, error);
        if (!proof || !impl_->Check()) return {};
        return std::unique_ptr<AppleEncryptedMetadataReadContext>(new AppleEncryptedMetadataReadContext(
            std::make_shared<AppleEncryptedMetadataReadContext::State>(impl_, std::move(proof->checkpoint_), std::move(proof->volume_))));
    } catch (const std::bad_alloc&) { error = "SoftwareKeybagEraResourceLimit"; return {}; }
      catch (...) { error = "SoftwareKeybagEraReadFailure"; return {}; }
}

std::optional<AppleCheckpointView> LoadAppleCheckpointView(const RandomAccessSource& source,
    std::uint64_t offset, std::uint64_t size, std::string& error,
    AppleEncryptedMetadataReadContext& context, std::optional<std::uint64_t> xid)
{
    return LoadAppleCheckpointView(source, offset, size, error, context, xid, true);
}

std::optional<AppleCheckpointView> LoadAppleCheckpointView(const RandomAccessSource& source,
    std::uint64_t offset, std::uint64_t size, std::string& error,
    AppleEncryptedMetadataReadContext& context, std::optional<std::uint64_t> xid, bool load_allocator)
{
    auto& state = *context.state_;
    auto& owner = *state.session;
    std::lock_guard lock(owner.mutex);
    AppleEncryptedMetadataReadContext::State::NodeScope clear_node{state};
    owner.failure = Error::None;
    error.clear();
    try
    {
        AppleEncryptedMetadataReadContext::State::RuntimeScope scope(owner);
        if (!state.Bound(source, error)) return {};
        if (offset != 0 || size != owner.source_size || (xid && *xid != state.Checkpoint().superblock.xid))
        { error = "AppleEncryptedGeometryOrCheckpointMismatch"; return {}; }
        auto& nodes = state.historical_checkpoint ? static_cast<BtreeNodeReadContext&>(state) : static_cast<BtreeNodeReadContext&>(owner);
        auto result = AppleEncryptedMetadataReadContext::LoadCanonical(owner, state.Checkpoint(), state.Volume(), nodes, error, load_allocator);
        if (!state.Bound(source, error)) return {};
        return result;
    }
    catch (const std::bad_alloc&) { error = "AppleEncryptedContextResourceLimit"; }
    catch (...) { error = "AppleEncryptedContextReadFailure"; }
    owner.ReleaseNode();
    return {};
}

bool ReadAppleVolumeFileSystemRecords(const RandomAccessSource& source,
    const ContainerCheckpointView& checkpoint, const AppleVolumeCheckpointView& volume,
    std::vector<BtreeRecord>& records, std::string& error, AppleEncryptedMetadataReadContext& context)
{
    for (auto& record : records) { Wipe(record.key); Wipe(record.value); }
    records.clear(); error.clear();
    auto& state = *context.state_;
    auto& owner = *state.session;
    std::lock_guard lock(owner.mutex);
    AppleEncryptedMetadataReadContext::State::NodeScope clear_node{state};
    owner.failure = Error::None;
    try
    {
        AppleEncryptedMetadataReadContext::State::RuntimeScope scope(owner);
        if (!state.Bound(source, error)) return false;
        if (!state.Selection(checkpoint, volume))
        { error = "AppleEncryptedSelectionBindingMismatch"; return false; }
        Records result;
        auto& nodes = state.historical_checkpoint ? static_cast<BtreeNodeReadContext&>(state) : static_cast<BtreeNodeReadContext&>(owner);
        if (!AppleEncryptedMetadataReadContext::ReadCanonical(owner, state.Checkpoint(), volume, nodes, result.bytes, error) ||
            !state.Bound(source, error)) return false;
        records = std::move(result.bytes);
        return true;
    }
    catch (const std::bad_alloc&) { error = "AppleEncryptedContextResourceLimit"; }
    catch (...) { error = "AppleEncryptedContextReadFailure"; }
    owner.ReleaseNode();
    return false;
}

#ifdef APFSACCESS_ENCRYPTED_COW_TESTING
namespace encrypted_cow_testing {
thread_local unsigned fault = 0;
void SetFault(unsigned value) { fault = value <= 3 ? value : 0; }
}
#endif
#include "EncryptedCowPlanner.h"
#include "EncryptedReadTransitionRetention.inc"

std::unique_ptr<EncryptedCowOverwrite> ApfsEncryptedReadSession::PrepareCowOverwrite(
    const ImmutableEncryptedReadSource& expected_source, std::uint64_t xid,
    std::uint64_t inode, std::uint64_t offset, std::span<const std::byte> replacement, std::string& error,
    std::span<const std::uint64_t> required_checkpoint_xids)
{
    std::lock_guard lock(impl_->mutex);
    impl_->failure = Error::None; error.clear();
    try {
        Impl::RuntimeScope scope(*impl_);
        if (!impl_->Check()) { error = "EncryptedCowSessionRevoked"; return {}; }
        if (&expected_source != impl_->source.get() || xid != impl_->checkpoint.superblock.xid)
            { error = "EncryptedCowSourceOrCheckpointMismatch"; return {}; }
        Impl::CowPlanner planner(*impl_, error);
        EncryptedMutationRequest request;
        request.kind = EncryptedMutationKind::Overwrite; request.inode = inode;
        request.offset = offset; request.data = replacement;
        auto result = planner.Prepare(request, required_checkpoint_xids);
        if (!result && error.empty()) error = "EncryptedCowPreparationFailed";
        return result;
    } catch (const std::bad_alloc&) { error = "EncryptedCowResourceLimit"; }
      catch (...) { error = "EncryptedCowPreparationException"; }
    return {};
}

std::unique_ptr<EncryptedCowOverwrite> ApfsEncryptedReadSession::PrepareMutation(
    const ImmutableEncryptedReadSource& expected_source, std::uint64_t xid,
    const EncryptedMutationRequest& request, std::string& error,
    std::span<const std::uint64_t> required_checkpoint_xids)
{
    std::lock_guard lock(impl_->mutex);
    impl_->failure = Error::None; error.clear();
    try {
        Impl::RuntimeScope scope(*impl_);
        if (!impl_->Check()) { error = "EncryptedCowSessionRevoked"; return {}; }
        if (&expected_source != impl_->source.get() || xid != impl_->checkpoint.superblock.xid)
            { error = "EncryptedCowSourceOrCheckpointMismatch"; return {}; }
        Impl::CowPlanner planner(*impl_, error);
        auto result = planner.Prepare(request, required_checkpoint_xids);
        if (!result && error.empty()) error = "EncryptedCowPreparationFailed";
        return result;
    } catch (const std::bad_alloc&) { error = "EncryptedCowResourceLimit"; }
      catch (...) { error = "EncryptedCowPreparationException"; }
    return {};
}

std::unique_ptr<EncryptedCowOverwrite> ApfsEncryptedReadSession::PrepareDeltaMutation(
    const ImmutableEncryptedReadSource& source, std::uint64_t xid, const EncryptedMutationRequest& request,
    std::string& error, std::span<const std::uint64_t> required)
{
    return PrepareDeltaMutationWithReadPins(source, xid, request, error, required, {});
}

std::unique_ptr<EncryptedCowOverwrite> ApfsEncryptedReadSession::PrepareDeltaMutationWithReadPins(
    const ImmutableEncryptedReadSource& source, std::uint64_t xid, const EncryptedMutationRequest& request,
    std::string& error, std::span<const std::uint64_t> required, std::span<const std::uint64_t> read_pins)
{
    std::lock_guard lock(impl_->mutex); impl_->failure = Error::None; error.clear();
    try {
        Impl::RuntimeScope scope(*impl_);
        if (!impl_->Check()) { error = "EncryptedDeltaSessionRevoked"; return {}; }
        if (&source != impl_->source.get() || xid != impl_->checkpoint.superblock.xid)
        { error = "EncryptedDeltaSourceOrCheckpointMismatch"; return {}; }
        Impl::CowPlanner planner(*impl_, error, true);
        auto result = planner.Prepare(request, required, read_pins);
        if (!result && error.empty()) error = "EncryptedDeltaPreparationFailed";
        return result;
    } catch (const std::bad_alloc&) { error = "EncryptedDeltaResourceLimit"; }
      catch (...) { error = "EncryptedDeltaPreparationException"; }
    return {};
}
ApfsEncryptedReadSession::ApfsEncryptedReadSession(std::shared_ptr<Impl> impl) : impl_(std::move(impl)) {}
ApfsEncryptedReadSession::~ApfsEncryptedReadSession() { Close(); }

std::unique_ptr<ApfsEncryptedReadSession> ApfsEncryptedReadSession::Unlock(
    std::shared_ptr<const ImmutableEncryptedReadSource> source, std::string identity, std::uint64_t revision,
    const PasswordUnlockRequest& request, std::span<const std::byte> password,
    PasswordUnlockBudget& attempts, Error& error, UnlockError& unlock_error,
    std::shared_ptr<const std::atomic<bool>> cancellation)
{
    error = Error::InvalidArgument;
    unlock_error = UnlockError::InvalidArgument;
    try
    {
        if (!source || identity.empty()) return {};
        auto impl = std::make_shared<Impl>();
        impl->external_cancellation = std::move(cancellation);
        impl->source = std::move(source); impl->identity = std::move(identity); impl->revision = revision;
        impl->source_size = impl->source->SizeBytes(); impl->budget = impl->source->ReadBudget();
        if (!impl->Check()) { error = impl->failure; return {}; }
        impl->key = UnlockPasswordKeybags(*impl, request, password, attempts);
        unlock_error = impl->key.error;
        if (!impl->key)
        {
            error = impl->failure != Error::None ? impl->failure :
                unlock_error == UnlockError::ResourceLimit ? Error::ResourceLimit : Error::UnlockFailed;
            return {};
        }
        if (!impl->Initialize() || !impl->BindRuntimeLimits()) { error = impl->failure; return {}; }
        error = Error::None;
        return std::unique_ptr<ApfsEncryptedReadSession>(new ApfsEncryptedReadSession(std::move(impl)));
    }
    catch (const std::bad_alloc&) { error = Error::ResourceLimit; return {}; }
    catch (...) { error = Error::ReadFailure; return {}; }
}

PasswordUnlockResult ApfsEncryptedReadSession::CopyKeyForImageWriter(Error& error)
{
    std::lock_guard lock(impl_->mutex);
    impl_->failure = Error::None;
    PasswordUnlockResult copy;
    if (!impl_->Check() || !impl_->key) { error = impl_->failure; return copy; }
    auto bytes = crypto::SecureBytes::Allocate(32);
    if (!bytes) { error = CryptoErrorFor(bytes.error); return copy; }
    const auto& key = impl_->key;
    copy.container_uuid = key.container_uuid; copy.volume_uuid = key.volume_uuid;
    copy.user_uuid = key.user_uuid; copy.checkpoint_xid = key.checkpoint_xid;
    copy.volume_oid = key.volume_oid; copy.volume_xid = key.volume_xid;
    std::copy(key.xts_key.Bytes().begin(), key.xts_key.Bytes().end(), bytes.bytes.Bytes().begin());
    copy.xts_key = std::move(bytes.bytes); copy.error = UnlockError::None;
    error = Error::None;
    return copy;
}

std::unique_ptr<ApfsEncryptedReadSession> ApfsEncryptedReadSession::OpenImageWriterView(
    std::shared_ptr<const ImmutableEncryptedReadSource> source, const PasswordUnlockResult& key,
    const PasswordUnlockRequest& admitted, Error& error)
{
    return OpenImageWriterView(std::move(source), key, admitted, error, {});
}

std::unique_ptr<ApfsEncryptedReadSession> ApfsEncryptedReadSession::OpenImageWriterView(
    std::shared_ptr<const ImmutableEncryptedReadSource> source, const PasswordUnlockResult& key,
    const PasswordUnlockRequest& admitted, Error& error, std::shared_ptr<const std::atomic<bool>> cancellation)
{
    return OpenImageWriterView(std::move(source), key, admitted, error, std::move(cancellation), 0);
}

std::unique_ptr<ApfsEncryptedReadSession> ApfsEncryptedReadSession::OpenImageWriterView(
    std::shared_ptr<const ImmutableEncryptedReadSource> source, const PasswordUnlockResult& key,
    const PasswordUnlockRequest& admitted, Error& error, std::shared_ptr<const std::atomic<bool>> cancellation,
    std::uint64_t retained_xid)
{
    error = Error::InvalidArgument;
    try
    {
        if (cancellation && cancellation->load()) { error = Error::Cancelled; return {}; }
        if (!source || !key) return {};
        UnlockError inspect_error{};
        std::uint64_t container_block = 0, volume_block = 0;
        auto metadata = retained_xid
            ? InspectPasswordKeybagMetadataAtCheckpoint(*source, key.volume_oid, admitted.length,
                retained_xid, inspect_error, container_block, volume_block)
            : InspectPasswordKeybagMetadata(*source, key.volume_oid, admitted.length, inspect_error);
        if (!metadata) { error = Error::MetadataIntegrityFailure; return {}; }
        const auto& selected = metadata->selection;
        if (selected.container_uuid != key.container_uuid || selected.volume_uuid != key.volume_uuid ||
            selected.container_bag.oid != admitted.container_bag.oid ||
            selected.container_bag.xid != admitted.container_bag.xid ||
            selected.volume_bag.oid != admitted.volume_bag.oid || selected.volume_bag.xid != admitted.volume_bag.xid ||
            std::find(metadata->users.begin(), metadata->users.end(), key.user_uuid) == metadata->users.end())
        { error = Error::SourceIdentityMismatch; return {}; }
        std::string detail;
        auto checkpoint = LoadContainerCheckpointView(*source, 0, source->SizeBytes(), detail, selected.checkpoint_xid);
        if (!checkpoint) { error = Error::MetadataIntegrityFailure; return {}; }
        auto volumes = LoadAppleReadOnlyVolumeView(*source, *checkpoint, detail);
        if (!volumes) { error = Error::MetadataIntegrityFailure; return {}; }
        const auto volume = std::find_if(volumes->volumes.begin(), volumes->volumes.end(),
            [&](const auto& value) { return value.superblock.object_id == key.volume_oid; });
        if (volume == volumes->volumes.end()) { error = Error::SourceIdentityMismatch; return {}; }
        auto bytes = crypto::SecureBytes::Allocate(32);
        if (!bytes) { error = CryptoErrorFor(bytes.error); return {}; }
        auto impl = std::make_shared<Impl>();
        impl->external_cancellation = std::move(cancellation);
        impl->source = std::move(source); impl->identity = impl->source->SourceIdentity();
        impl->revision = impl->source->Revision(); impl->source_size = impl->source->SizeBytes();
        impl->budget = impl->source->ReadBudget();
        auto& copy = impl->key;
        copy.container_uuid = key.container_uuid; copy.volume_uuid = key.volume_uuid; copy.user_uuid = key.user_uuid;
        copy.volume_oid = key.volume_oid; copy.checkpoint_xid = selected.checkpoint_xid;
        copy.volume_xid = volume->superblock.xid;
        std::copy(key.xts_key.Bytes().begin(), key.xts_key.Bytes().end(), bytes.bytes.Bytes().begin());
        copy.xts_key = std::move(bytes.bytes); copy.error = UnlockError::None;
        if (!impl->Initialize() || !impl->BindRuntimeLimits()) { error = impl->failure; return {}; }
        error = Error::None;
        return std::unique_ptr<ApfsEncryptedReadSession>(new ApfsEncryptedReadSession(std::move(impl)));
    }
    catch (const std::bad_alloc&) { error = Error::ResourceLimit; return {}; }
    catch (...) { error = Error::ReadFailure; return {}; }
}

#ifdef APFSACCESS_CRYPTO_TESTING
std::unique_ptr<ApfsEncryptedReadSession> ApfsEncryptedReadSession::OpenForTesting(
    std::shared_ptr<const ImmutableEncryptedReadSource> source, PasswordUnlockResult key, Error& error,
    std::shared_ptr<const std::atomic<bool>> cancellation)
{
    error = Error::InvalidArgument;
    try
    {
        if (!source || !key) return {};
        auto impl = std::make_shared<Impl>();
        impl->external_cancellation = std::move(cancellation);
        impl->source = std::move(source); impl->identity = impl->source->SourceIdentity();
        impl->revision = impl->source->Revision(); impl->source_size = impl->source->SizeBytes();
        impl->budget = impl->source->ReadBudget(); impl->key = std::move(key);
        if (!impl->Initialize() || !impl->BindRuntimeLimits()) { error = impl->failure; return {}; }
        error = Error::None;
        return std::unique_ptr<ApfsEncryptedReadSession>(new ApfsEncryptedReadSession(std::move(impl)));
    }
    catch (const std::bad_alloc&) { error = Error::ResourceLimit; return {}; }
    catch (...) { error = Error::ReadFailure; return {}; }
}
#endif

Error ApfsEncryptedReadSession::ReadFile(std::uint64_t id, std::uint64_t offset,
    std::size_t size, std::vector<std::byte>& output)
{
    output.clear();
    std::lock_guard lock(impl_->mutex);
    impl_->failure = Error::None;
    try { Impl::RuntimeScope scope(*impl_); return impl_->ReadFile(id, offset, size, output); }
    catch (const std::bad_alloc&) { return Error::ResourceLimit; }
    catch (...) { return Error::ReadFailure; }
}
Error ApfsEncryptedReadSession::ListFiles(std::vector<EncryptedFileInfo>& output)
{
    output.clear();
    std::lock_guard lock(impl_->mutex);
    impl_->failure = Error::None;
    try
    {
        Impl::RuntimeScope scope(*impl_);
        if (!impl_->Check() || !impl_->Charge(impl_->files.size(), impl_->files.size() * sizeof(EncryptedFileInfo)))
            return impl_->failure;
        std::vector<EncryptedFileInfo> result;
        struct ClearFiles
        {
            std::vector<EncryptedFileInfo>& values;
            ~ClearFiles() { for (auto& value : values) WipeScalar(value); }
        } clear{result};
        result.reserve(impl_->files.size());
        for (const auto& [id, file] : impl_->files) { (void)id; result.push_back(file.info); }
        if (!impl_->Check()) return impl_->failure;
        output = std::move(result);
        return Error::None;
    }
    catch (const std::bad_alloc&) { return Error::ResourceLimit; }
    catch (...) { return Error::ReadFailure; }
}
Error ApfsEncryptedReadSession::GetNamespaceInfo(EncryptedNamespaceInfo& output)
{
    return impl_->MetadataOperation(output, [&] {
        if (!impl_->Charge(1, sizeof(output)) || !impl_->Check()) return impl_->failure;
        output = {2, impl_->nodes.size(), impl_->entries.size(), impl_->name_policy}; return Error::None;
    });
}
Error ApfsEncryptedReadSession::GetMetadata(std::uint64_t id, EncryptedNodeInfo& output)
{
    return impl_->MetadataOperation(output, [&] {
        const auto n = impl_->nodes.find(id);
        if (n == impl_->nodes.end()) return Error::FileNotFound;
        if (!impl_->Charge(1, sizeof(output)) || !impl_->Check()) return impl_->failure;
        output = n->second; return Error::None;
    });
}
Error ApfsEncryptedReadSession::ListDirectory(std::uint64_t parent, std::vector<EncryptedDirectoryEntry>& output)
{
    return impl_->MetadataOperation(output, [&] {
        if (const auto error = impl_->DirectoryCheck(parent); error != Error::None) return error;
        const auto& indices = impl_->children.at(parent);
        if (!impl_->Charge(indices.size(), indices.size() * sizeof(EncryptedDirectoryEntry))) return impl_->failure;
        std::vector<EncryptedDirectoryEntry> result; Cleanup clear{result}; result.reserve(indices.size());
        for (const auto index : indices)
        {
            result.emplace_back();
            if (const auto error = impl_->CopyEntry(impl_->entries[index], result.back()); error != Error::None) return error;
        }
        if (!impl_->Check()) return impl_->failure;
        output = std::move(result); return Error::None;
    });
}
Error ApfsEncryptedReadSession::Lookup(std::uint64_t parent, std::string_view name, EncryptedDirectoryEntry& output)
{
    return impl_->MetadataOperation(output, [&] {
        const Impl::Entry* entry;
        if (const auto error = impl_->Find(parent, name, entry); error != Error::None) return error;
        return impl_->CopyEntry(*entry, output);
    });
}
Error ApfsEncryptedReadSession::LookupWindows(std::uint64_t parent, std::wstring_view name, EncryptedDirectoryEntry& output)
{
    return impl_->MetadataOperation(output, [&] {
        const Impl::Entry* entry;
        if (const auto error = impl_->FindWindows(parent, name, entry); error != Error::None) return error;
        return impl_->CopyEntry(*entry, output);
    });
}
Error ApfsEncryptedReadSession::ResolvePath(std::wstring_view path, EncryptedNodeInfo& output)
{
    return impl_->MetadataOperation(output, [&] {
        if (path.empty() || path.size() > 32768 || path.front() != L'\\' || path.find(L'/') != path.npos)
            return Error::InvalidArgument;
        std::uint64_t id = 2;
        for (std::size_t begin = 1; begin < path.size();)
        {
            auto end = path.find(L'\\', begin); if (end == path.npos) end = path.size();
            if (begin == end || end == path.size()-1) return Error::InvalidArgument;
            const Impl::Entry* entry;
            if (const auto error = impl_->FindWindows(id, path.substr(begin, end-begin), entry); error != Error::None) return error;
            id = entry->info.inode_id; begin = end + 1;
        }
        if (!impl_->Charge(1, sizeof(output)) || !impl_->Check()) return impl_->failure;
        output = impl_->nodes.at(id); return Error::None;
    });
}
Error ApfsEncryptedReadSession::ListXattrs(std::uint64_t id, std::vector<EncryptedXattr>& output)
{
    return impl_->MetadataOperation(output, [&] {
        if (!impl_->nodes.contains(id)) return Error::FileNotFound;
        std::vector<EncryptedXattr> result; Cleanup clear{result};
        auto first = std::lower_bound(impl_->attributes.begin(), impl_->attributes.end(), id,
            [](const auto& a, auto owner) { return a.inode_id < owner; });
        auto last = first; while (last != impl_->attributes.end() && last->inode_id == id) ++last;
        if (!impl_->Charge(static_cast<std::uint64_t>(last-first), static_cast<std::uint64_t>(last-first) * sizeof(EncryptedXattr)))
            return impl_->failure;
        result.reserve(static_cast<std::size_t>(last-first));
        for (auto at = first; at != last; ++at)
        {
            const auto& a = at->info;
            if (!impl_->Charge(1, a.name_utf8.size() + a.data.size())) return impl_->failure;
            result.emplace_back(); result.back().flags = a.flags;
            result.back().name_utf8 = a.name_utf8; result.back().data = a.data;
        }
        if (!impl_->Check()) return impl_->failure;
        output = std::move(result); return Error::None;
    });
}
Error ApfsEncryptedReadSession::ReadXattr(std::uint64_t id, std::string_view name, std::vector<std::byte>& output)
{
    return impl_->MetadataOperation(output, [&] {
        if (!impl_->nodes.contains(id)) return Error::FileNotFound;
        if (name.empty() || name.size() > 255 || name.find('\0') != name.npos) return Error::InvalidArgument;
        const auto at = std::lower_bound(impl_->attributes.begin(), impl_->attributes.end(), std::pair{id,name},
            [](const auto& a, const auto& key) { return a.inode_id != key.first ? a.inode_id < key.first : a.info.name_utf8 < key.second; });
        if (at == impl_->attributes.end() || at->inode_id != id || at->info.name_utf8 != name) return Error::XattrNotFound;
        if (!impl_->Charge(1, at->info.data.size())) return impl_->failure;
        std::vector<std::byte> result; Cleanup clear{result}; result = at->info.data;
        if (!impl_->Check()) return impl_->failure;
        output = std::move(result); return Error::None;
    });
}

void ApfsEncryptedReadSession::Cancel() noexcept { impl_->cancelled.store(true); }
void ApfsEncryptedReadSession::Close() noexcept
{
    Cancel();
    std::lock_guard lock(impl_->mutex);
    impl_->closed = true;
    impl_->ReleaseNode(); impl_->key.xts_key.Clear(); impl_->ClearMetadata();
    impl_->checkpoint = {}; impl_->volume = {}; impl_->source.reset();
}
#include "EncryptedSnapshotReadContext.inc"
} // namespace apfsaccess::catalog
