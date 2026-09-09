#include "ApfsEncryptedReadSession.h"
#include "ApfsFormat.h"
#include "ApfsExtendedRecordCodec.h"
#include <algorithm>
#include <atomic>
#include <limits>
#include <map>
#include <mutex>

namespace apfsaccess::catalog
{
namespace
{
using Error = EncryptedReadError;
void Wipe(std::vector<std::byte>& bytes) noexcept
{
    // Ordinary parser materializations are not secret key storage. Clear their
    // live bytes on the owned scope boundary; allocator copies are not covered.
    volatile std::byte* data = bytes.data();
    for (std::size_t i = 0; i < bytes.size(); ++i) data[i] = std::byte{};
    bytes.clear();
}
struct Records
{
    std::vector<BtreeRecord> bytes;
    ~Records() { for (auto& r : bytes) { Wipe(r.key); Wipe(r.value); } }
};
Error CryptoErrorFor(crypto::CryptoError error)
{
    using C = crypto::CryptoError;
    return error == C::ResourceLimit || error == C::AllocationFailed || error == C::MemoryLockFailed
        ? Error::ResourceLimit : Error::CryptoFailure;
}
}

struct ApfsEncryptedReadSession::Impl final : RandomAccessSource, BtreeNodeReadContext
{
    std::shared_ptr<const ImmutableEncryptedReadSource> source;
    std::shared_ptr<ApfsReadBudget> budget;
    std::string identity;
    std::uint64_t revision = 0, source_size = 0;
    std::atomic<bool> cancelled{false};
    std::shared_ptr<const std::atomic<bool>> external_cancellation;
    std::mutex mutex;
    bool closed = false;
    mutable Error failure = Error::None;
    PasswordUnlockResult key;
    ContainerCheckpointView checkpoint;
    ApsbVolume volume;
    crypto::SecureBytes node;
    struct File
    {
        EncryptedFileInfo info;
        std::uint64_t private_id = 0;
        bool sparse = false;
        std::vector<rw::AppleFileExtentRecord> extents;
    };
    std::map<std::uint64_t, File> files;

    bool Fail(Error error) const { if (failure == Error::None) failure = error; return false; }
    bool Check() const
    {
        if (closed) return Fail(Error::Closed);
        if (cancelled.load() || (external_cancellation && external_cancellation->load()))
            return Fail(Error::Cancelled);
        if (!source || source->SourceIdentity() != identity || source->Revision() != revision ||
            source->SizeBytes() != source_size || source->ReadBudget() != budget)
            return Fail(Error::SourceIdentityMismatch);
        if (!budget || budget->Failed()) return Fail(Error::ResourceLimit);
        return true;
    }
    std::uint64_t SizeBytes() const override { return source_size; }
    std::shared_ptr<ApfsReadBudget> ReadBudget() const override { return budget; }
    bool Read(std::uint64_t offset, std::size_t size, std::vector<std::byte>& out) const override
    {
        out.clear();
        if (!Check()) return false;
        if (offset > source_size || size > source_size - offset) return Fail(Error::ReadFailure);
        if (!source->Read(offset, size, out) || out.size() != size)
        {
            out.clear();
            return Fail(budget->Failed() ? Error::ResourceLimit : Error::ReadFailure);
        }
        if (!Check()) { out.clear(); return false; }
        return true;
    }
    bool Charge(std::uint64_t count, std::uint64_t bytes)
    {
        return (Check() && budget->Materialize(count, bytes)) || Fail(Error::ResourceLimit);
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
        std::span<const std::byte>& bytes, std::string&) override
    {
        bytes = {};
        ReleaseNode();
        auto mapping = Mapping(volume.omap_oid, oid, volume.xid);
        if (!mapping) return false;
        if (mapping->physical_block != physical) return Fail(Error::SourceIdentityMismatch);
        std::vector<std::byte> ciphertext;
        if (!ReadBlock(physical, ciphertext)) return false;
        const auto bs = checkpoint.superblock.block_size;
        if (!Charge(0, bs)) return false;
        auto allocation = crypto::SecureBytes::Allocate(bs);
        if (!allocation) return Fail(CryptoErrorFor(allocation.error));
        node = std::move(allocation.bytes);
        if (mapping->flags == 4)
        {
            const std::uint64_t units = bs / 512;
            if (physical > UINT64_MAX / units) return Fail(Error::UnsupportedEncryptionLayout);
            if (!Transform(ciphertext, physical * units, node.Bytes())) return false;
        }
        else
        {
            std::copy(ciphertext.begin(), ciphertext.end(), node.Bytes().begin());
            Wipe(ciphertext);
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
    void ReleaseNode() noexcept override { node.Clear(); }

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
        auto mapping = Mapping(nx.omap_oid, key.volume_oid, nx.xid);
        if (!mapping) return false;
        if (mapping->flags != 0) return Fail(Error::UnsupportedEncryptionLayout);
        std::vector<std::byte> apsb;
        if (!ReadBlock(mapping->physical_block, apsb)) return false;
        auto parsed = ParseApsb(apsb);
        if (!parsed || parsed->object_id != key.volume_oid || parsed->xid != key.volume_xid ||
            parsed->xid != mapping->xid || parsed->uuid_hex != BytesToHexLower(key.volume_uuid.data(), 16) ||
            ReadU32LE(apsb, 24) != kObjectTypeFs || ReadU32LE(apsb, 28) != 0u)
            return Fail(Error::SourceIdentityMismatch);
        volume = std::move(*parsed);
        if (volume.fs_flags != kFsFlagOneKey || volume.readonly_features ||
            (volume.features & ~kVolumeKnownOptionalFeaturesMask) ||
            (volume.incompatible_features & ~kVolumeSupportedIncompatibleFeaturesMask) ||
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
            return BtreeVirtualChildMapping{child->physical_block, child->xid};
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
        const auto name_policy = rw::ApfsNamePolicy::FromIncompatibleFeatures(volume.incompatible_features);
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
        for (const auto& record : records)
        {
            const auto header = ReadU64LE(record.key, 0);
            if (!header) return Fail(Error::MetadataIntegrityFailure);
            switch (*header >> 60)
            {
            case 3:
            {
                rw::AppleInodeRecord inode;
                if (!Charge(0, 16 * static_cast<std::uint64_t>(record.value.size()) + sizeof(inode))) return false;
                if (!rw::ApfsExtendedRecordCodec::DecodeInode(record, inode, detail))
                    return Fail(Error::MetadataIntegrityFailure);
                const auto mode = inode.mode & 0170000;
                if (mode == 0040000) break; // No namespace/path projection in this API.
                if (mode != 0100000 || (inode.bsd_flags & rw::kAppleBsdCompressedFlag) ||
                    (inode.internal_flags & ~rw::kAppleInodeSparseFlag))
                    return Fail(Error::UnsupportedEncryptionLayout);
                rw::AppleDataStreamRecord stream;
                bool found = false;
                for (const auto& field : inode.extended_fields)
                {
                    if (field.type != 8) continue;
                    if (found || !rw::ApfsExtendedRecordCodec::DecodeDataStream(field, stream, detail))
                        return Fail(Error::MetadataIntegrityFailure);
                    found = true;
                }
                if (!found) return Fail(Error::UnsupportedEncryptionLayout);
                if (!Charge(1, sizeof(File))) return false;
                File file{{inode.object_id, stream.size, stream.default_crypto_id}, inode.private_id,
                    (inode.internal_flags & rw::kAppleInodeSparseFlag) != 0, {}};
                if (!files.emplace(inode.object_id, std::move(file)).second)
                    return Fail(Error::MetadataIntegrityFailure);
                break;
            }
            case 8:
            {
                rw::AppleFileExtentRecord extent;
                if (!rw::DecodeAppleFileExtentRecord(record, checkpoint.superblock.block_size, extent, detail))
                    return Fail(Error::MetadataIntegrityFailure);
                if (!Charge(1, sizeof(extent))) return false;
                streams[extent.object_id].push_back(extent);
                break;
            }
            case 6:
            {
                rw::AppleDataStreamIdRecord stream;
                if (!rw::DecodeAppleDataStreamIdRecord(record, stream, detail))
                    return Fail(Error::MetadataIntegrityFailure);
                break;
            }
            case 9: break; // Directory records remain opaque; never published as names.
            default: return Fail(Error::UnsupportedEncryptionLayout);
            }
        }
        const auto bs = checkpoint.superblock.block_size;
        for (auto& [id, file] : files)
        {
            (void)id;
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
        return true;
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

ApfsEncryptedReadSession::ApfsEncryptedReadSession(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
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
        auto impl = std::make_unique<Impl>();
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
        if (!impl->Initialize()) { error = impl->failure; return {}; }
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
        auto impl = std::make_unique<Impl>();
        impl->external_cancellation = std::move(cancellation);
        impl->source = std::move(source); impl->identity = impl->source->SourceIdentity();
        impl->revision = impl->source->Revision(); impl->source_size = impl->source->SizeBytes();
        impl->budget = impl->source->ReadBudget(); impl->key = std::move(key);
        if (!impl->Initialize()) { error = impl->failure; return {}; }
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
    try { return impl_->ReadFile(id, offset, size, output); }
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
        if (!impl_->Check() || !impl_->Charge(impl_->files.size(), impl_->files.size() * sizeof(EncryptedFileInfo)))
            return impl_->failure;
        std::vector<EncryptedFileInfo> result;
        result.reserve(impl_->files.size());
        for (const auto& [id, file] : impl_->files) { (void)id; result.push_back(file.info); }
        if (!impl_->Check()) return impl_->failure;
        output = std::move(result);
        return Error::None;
    }
    catch (const std::bad_alloc&) { return Error::ResourceLimit; }
    catch (...) { return Error::ReadFailure; }
}
void ApfsEncryptedReadSession::Cancel() noexcept { impl_->cancelled.store(true); }
void ApfsEncryptedReadSession::Close() noexcept
{
    Cancel();
    std::lock_guard lock(impl_->mutex);
    impl_->closed = true;
    impl_->node.Clear(); impl_->key.xts_key.Clear(); impl_->files.clear();
    impl_->checkpoint = {}; impl_->volume = {}; impl_->source.reset();
}
} // namespace apfsaccess::catalog
