#pragma once
#include "ApfsFusionStore.h"
#include "NativeApfsReader.h"

namespace apfsaccess::rw {
enum class FusionReadStatus { Ok, Unavailable, SelectionMismatch, EncryptionUnsupported,
    FeaturesUnsupported, FileExtentTreeUnsupported, FilesystemUnsupported,
    MetadataInvalid, NotFound, NotRegularFile, RangeLimit };
struct FusionVolumeSelection {
    std::string container_uuid_hex, volume_uuid_hex;
    std::array<std::string, 2> member_store_ids; // main, tier2
    std::uint64_t volume_oid = 0, checkpoint_xid = 0;
};
// Single-threaded, owned readonly acquisition. No writable projection escapes.
// Rechecks both held members even for EOF, zero-fill and cached enumeration.
class ApfsFusionReadSession final {
public:
    static std::unique_ptr<ApfsFusionReadSession> Open(
        std::unique_ptr<catalog::ApfsFusionStore> source, const FusionVolumeSelection& selected,
        FusionReadStatus& status, std::string& error);
    bool GetCatalog(catalog::ApfsContainerCatalog& out, std::string& error) const;
    bool Enumerate(std::uint64_t directory_oid, std::vector<MetadataStore::DirectoryLink>& out,
        std::string& error) const;
    bool Lookup(std::uint64_t directory_oid, std::wstring_view name,
        std::uint64_t& out_oid, std::string& error) const;
    bool ReadFile(std::uint64_t inode_oid, std::uint64_t offset, std::size_t count,
        std::vector<std::byte>& out, std::string& error) const;
    bool ReadXattr(std::uint64_t inode_oid, const std::string& name, std::uint64_t offset,
        std::size_t count, std::vector<std::byte>& out, std::string& error) const;
    bool CheckAvailable(std::string& error) const;
    void Cancel() const;
    FusionReadStatus LastStatus() const noexcept { return status_; }
private:
    ApfsFusionReadSession() = default;
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
