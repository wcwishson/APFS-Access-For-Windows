#pragma once
#include "ApfsFusionStore.h"
#include "NativeApfsReader.h"

namespace apfsaccess::rw {
enum class FusionReadStatus { Ok, Unavailable, SelectionMismatch, EncryptionUnsupported,
    FeaturesUnsupported, FileExtentTreeUnsupported, FilesystemUnsupported,
    MetadataInvalid, NotFound, NotRegularFile, RangeLimit, ResourceLimit };
struct FusionVolumeSelection {
    std::string container_uuid_hex, volume_uuid_hex;
    std::array<std::string, 2> member_store_ids; // main, tier2
    std::uint64_t volume_oid = 0, checkpoint_xid = 0;
};
struct FusionNodeInfo {
    std::uint64_t inode_id=0, parent_id=0, size=0, allocated_size=0;
    // FILETIME ticks, as returned by the shared native projector.
    std::uint64_t create_time=0, modification_time=0, change_time=0, access_time=0;
    std::uint32_t uid=0, gid=0, children_or_links=0;
    std::uint16_t mode=0;
    bool IsDirectory() const noexcept { return (mode & 0170000)==0040000; }
};
struct FusionXattrInfo { std::string name_utf8; std::uint64_t size=0; };
struct FusionNamespaceInfo {
    std::uint64_t root_inode_id=0, incompatible_features=0;
    ApfsNamePolicy name_policy;
};
// Single-threaded, owned readonly acquisition. No writable projection escapes.
// Rechecks both held members even for EOF, zero-fill and cached enumeration.
class ApfsFusionReadSession final {
public:
    // Source-free namespace/stream validation for an already parsed planning
    // graph. Uses exact bound member windows; returns no read/write capability.
    static bool ValidatePlanningRecords(const catalog::ApfsFusionStore& store,
        const catalog::NxSuperblock& container, const catalog::ApsbVolume& volume,
        const std::vector<catalog::BtreeRecord>& records, std::string& error);
    static std::unique_ptr<ApfsFusionReadSession> Open(
        std::unique_ptr<catalog::ApfsFusionStore> source, const FusionVolumeSelection& selected,
        FusionReadStatus& status, std::string& error, unsigned* unavailable_members = nullptr);
    // Explicit host opt-in, only after successful Open on held production files.
    // Legacy CLI callers retain their original cumulative budget semantics.
    bool EnableRuntimeReads(std::string& error);
    bool GetNamespaceInfo(FusionNamespaceInfo& out, std::string& error) const;
    bool GetMetadata(std::uint64_t oid, FusionNodeInfo& out, std::string& error) const;
    bool ListXattrs(std::uint64_t oid, std::vector<FusionXattrInfo>& out, std::string& error) const;
    bool GetCatalog(catalog::ApfsContainerCatalog& out, std::string& error) const;
    bool Enumerate(std::uint64_t directory_oid, std::vector<MetadataStore::DirectoryLink>& out,
        std::string& error) const;
    bool Lookup(std::uint64_t directory_oid, std::wstring_view name,
        std::uint64_t& out_oid, std::string& error) const;
    bool LookupEntry(std::uint64_t directory_oid, std::wstring_view name,
        MetadataStore::DirectoryLink& out, std::string& error) const;
    bool ReadFile(std::uint64_t inode_oid, std::uint64_t offset, std::size_t count,
        std::vector<std::byte>& out, std::string& error) const;
    bool ReadXattr(std::uint64_t inode_oid, const std::string& name, std::uint64_t offset,
        std::size_t count, std::vector<std::byte>& out, std::string& error) const;
    bool CheckAvailable(std::string& error) const;
    void Cancel() const;
    unsigned UnavailableMembers() const noexcept {return source_->UnavailableMembers();}
    FusionReadStatus LastStatus() const noexcept { return status_; }
private:
    friend class FusionImageRuntime;
    bool PrivateFiles(std::map<std::uint64_t, std::string>&, std::string&) const;
    ApfsFusionReadSession() = default;
    struct Operation;
    bool Charge(std::uint64_t records, std::uint64_t bytes, std::string& error) const;
    bool ReadBytes(std::uint64_t offset, std::size_t size, std::vector<std::byte>& out, std::string& error) const;
    bool runtime_enabled_ = false;
    mutable catalog::ApfsReadBudget* operation_budget_ = nullptr;
    bool Fail(FusionReadStatus status, const char* reason, std::string& error) const;
    bool AllocationFailed(std::string& error) const;
    bool ReadRange(const std::vector<MetadataStore::FileExtent>& extents,
        std::uint64_t logical_size, std::uint64_t offset, std::size_t count,
        std::vector<std::byte>& out, std::string& error) const;
    std::unique_ptr<catalog::ApfsFusionStore> source_;
    catalog::ApfsContainerCatalog catalog_;
    NativeApfsVolumeProjection view_;
    mutable FusionReadStatus status_ = FusionReadStatus::Ok;
};
}
