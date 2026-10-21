#pragma once
#include "ApfsFirmlinkRouter.h"
#include <array>

namespace apfsaccess::rw
{
struct FirmlinkImageOptions
{
    std::string container_uuid_hex, group_uuid_hex;
    std::uint64_t system_volume_oid=0, data_volume_oid=0, checkpoint_xid=0;
};
struct FirmlinkLookupResult
{
    FirmlinkObjectIdentity identity;
    MetadataStore::NodeType node_type=MetadataStore::NodeType::RegularFile;
    std::uint64_t logical_size=0;
};
struct FirmlinkDirectoryEntry
{
    std::wstring windows_name;
    std::string unix_path;
    FirmlinkLookupResult target;
};
class ApfsFirmlinkProducer final
{
public:
    // One stable ordinary image, complete canonical group/projections and table
    // bytes. Never accepts caller-supplied projections, pairs, xattr data or IO.
    // Initial profile is a partitionless single-store current checkpoint only.
    static bool TryOpenImage(const std::wstring& image,const FirmlinkImageOptions& expected,
        std::shared_ptr<const ApfsFirmlinkProducer>& out,std::string& error);
    bool CheckAvailable(std::string& error) const;
    bool TryLookup(std::string_view unix_path,FirmlinkAccess access,
        FirmlinkLookupResult& out,std::string& error) const;
    // Bounded ordinary nontransformed file read. Returned identities are
    // read-only observations, never mutation or independent cached-read tokens.
    bool TryReadFile(std::string_view unix_path,std::uint64_t offset,std::size_t bytes,
        std::vector<std::byte>& out,std::string& error) const;
    bool TryWindowsPath(std::wstring_view path,std::string& unix_path,std::string& error) const;
    bool TryGetMetadata(std::string_view unix_path,MetadataStore::InodeRecord& out,
        std::uint64_t& file_index,std::string& error) const;
    bool TryEnumerate(std::string_view unix_path,std::vector<FirmlinkDirectoryEntry>& out,std::string& error) const;
    const std::vector<VerifiedFirmlinkRecord>& Records() const noexcept {return records_;}
    const BlockDevice::StableImageIdentity& SourceIdentity() const noexcept {return source_identity_;}
    const std::array<std::uint8_t,32>& TableSha256() const noexcept {return table_sha_;}
    const FirmlinkObjectIdentity& TableIdentity() const noexcept {return table_identity_;}
    std::size_t TableByteLength() const noexcept {return table_bytes_;}
    std::uint64_t OpaqueMarkerCount() const noexcept {return opaque_marker_count_;}
private:
    using Key=std::pair<std::uint64_t,std::uint64_t>;
    using NameKey=std::pair<Key,std::vector<std::byte>>;
    ApfsFirmlinkProducer()=default;
    bool Index(std::string& error);
    const NativeApfsVolumeProjection* Volume(std::uint64_t oid) const;
    const MetadataStore::InodeRecord* Inode(Key key) const;
    bool LookupBacking(std::uint64_t volume,std::string_view path,FirmlinkLookupResult& out,std::string& error) const;
    bool ReadBacking(const FirmlinkLookupResult& file,std::uint64_t offset,std::size_t bytes,
        std::vector<std::byte>& out,std::string& error) const;
    FirmlinkObjectIdentity Identity(Key key) const;
    std::shared_ptr<BlockDevice> device_;
    BlockDevice::StableImageIdentity source_identity_;
    FirmlinkImageOptions options_;
    catalog::ApfsContainerDescriptor container_;
    NativeApfsVolumeProjection system_,data_;
    std::map<Key,std::size_t> inodes_;
    std::map<NameKey,std::uint64_t> children_;
    std::shared_ptr<const ApfsFirmlinkRouter> router_;
    std::shared_ptr<catalog::ApfsReadBudget> budget_;
    std::vector<VerifiedFirmlinkRecord> records_;
    FirmlinkObjectIdentity table_identity_;
    std::array<std::uint8_t,32> table_sha_{};
    std::size_t table_bytes_=0;
    std::uint64_t opaque_marker_count_=0;
};
}
