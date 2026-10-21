#pragma once

#include "ApfsFormat.h"

namespace apfsaccess::catalog
{

// Read-only authority minted from an admitted current or retained parent.
// Source binding, cancellation, key lifetime and budget remain session-owned.
class AppleEncryptedSnapshotReadContext final
{
public:
    ~AppleEncryptedSnapshotReadContext();
    AppleEncryptedSnapshotReadContext(const AppleEncryptedSnapshotReadContext&) = delete;
    AppleEncryptedSnapshotReadContext& operator=(const AppleEncryptedSnapshotReadContext&) = delete;

private:
    friend class ApfsEncryptedReadSession;
    struct State;
    explicit AppleEncryptedSnapshotReadContext(std::shared_ptr<State> state);
    std::shared_ptr<State> state_;
    bool LoadCatalogBound(const RandomAccessSource& original, AppleSnapshotCatalogRecords& output,
        std::vector<AppleSnapshotMetadataClaim>& owners, std::string& error);
    bool LoadCatalogLocked(const RandomAccessSource& original, AppleSnapshotCatalogRecords& output,
        std::vector<AppleSnapshotMetadataClaim>& owners, std::string& error);
    bool LoadCatalogBound(const RandomAccessSource& original, AppleCheckpointView& canonical_parent,
        AppleSnapshotCatalogRecords& output, std::vector<AppleSnapshotMetadataClaim>& owners, std::string& error);
    bool LoadCatalogLocked(const RandomAccessSource& original, AppleCheckpointView& canonical_parent,
        AppleSnapshotCatalogRecords& output, std::vector<AppleSnapshotMetadataClaim>& owners, std::string& error);

    std::unique_ptr<BtreeNodeReadContext> CreateCanonicalNodeReader(
        const RandomAccessSource& wrapped_owner, const ContainerCheckpointView& checkpoint,
        const AppleVolumeCheckpointView& canonical_volume, std::uint64_t fs_selection_xid,
        std::string& error);
    static bool LoadCatalogCanonical(const RandomAccessSource& wrapped_owner,
        const AppleCheckpointView& checkpoint, std::uint64_t owner_volume_oid,
        AppleEncryptedSnapshotReadContext& context, AppleSnapshotCatalogRecords& output,
        std::vector<AppleSnapshotMetadataClaim>& owners, std::string& error);
    static std::optional<OmapValue> ResolveCanonicalMapping(const RandomAccessSource& wrapped_owner,
        const ContainerCheckpointView& checkpoint, const AppleVolumeCheckpointView& canonical_volume,
        std::uint64_t fs_selection_xid, std::uint64_t oid, std::string& error);

    friend bool LoadAppleEncryptedSnapshotCatalog(const RandomAccessSource& original,
        AppleEncryptedSnapshotReadContext& context, AppleSnapshotCatalogRecords& output,
        std::vector<AppleSnapshotMetadataClaim>& owners, std::string& error);
    friend bool LoadAppleEncryptedSnapshotCatalog(const RandomAccessSource& original,
        AppleEncryptedSnapshotReadContext& context, AppleCheckpointView& canonical_parent,
        AppleSnapshotCatalogRecords& output, std::vector<AppleSnapshotMetadataClaim>& owners, std::string& error);
};

// No caller-selected roots, mappings, keys or decrypt callbacks. On failure all
// decoded output is wiped; a successful caller owns and must wipe the records.
bool LoadAppleEncryptedSnapshotCatalog(const RandomAccessSource& original,
    AppleEncryptedSnapshotReadContext& context, AppleSnapshotCatalogRecords& output,
    std::vector<AppleSnapshotMetadataClaim>& owners, std::string& error);

// Parent facts from the same canonical walk. Allocator ownership is not loaded;
// the observer must prove it separately. All outputs reset together on failure.
// The successful caller also owns and must wipe the parent's decoded names.
bool LoadAppleEncryptedSnapshotCatalog(const RandomAccessSource& original,
    AppleEncryptedSnapshotReadContext& context, AppleCheckpointView& canonical_parent,
    AppleSnapshotCatalogRecords& output, std::vector<AppleSnapshotMetadataClaim>& owners, std::string& error);

}
