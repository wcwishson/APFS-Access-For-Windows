// Included after the host argument and MetadataStore context helpers.
#pragma once
#include "ApfsSnapshotStore.h"

// The adapter opens its retained lease by path. Pin each ordinary ancestor
// until that open finishes, so a renamed directory or retargeted junction
// cannot substitute a different file between the two stable image opens.
bool PinSnapshotImageAncestors(const std::wstring& image,
    std::vector<UniqueWinHandle>& pins, std::string& error)
{
    const auto path = std::filesystem::path(image).lexically_normal();
    auto parent = path.root_path();
    const auto pin = [&]() {
        const auto handle = CreateFileW(parent.c_str(), GENERIC_READ,
            FILE_SHARE_READ, nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (handle == INVALID_HANDLE_VALUE) return false;
        auto owned = TakeWinHandle(handle);
        FILE_ATTRIBUTE_TAG_INFO attributes{};
        if (!GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &attributes, sizeof(attributes)) ||
            !(attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
            (attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) return false;
        pins.push_back(std::move(owned)); return true;
    };
    if (!pin()) { error = "SnapshotImageAncestorNotStable"; return false; }
    for (const auto& component : path.parent_path().relative_path())
    {
        parent /= component;
        if (!pin()) { error = "SnapshotImageAncestorNotStable"; return false; }
    }
    return true;
}

// Bridge the leased device to the authoritative inventory without reopening it.
class SnapshotLeaseSource final : public apfsaccess::catalog::RandomAccessSource
{
public:
    explicit SnapshotLeaseSource(const apfsaccess::rw::BlockDevice& device) : device_(device) {}
    std::uint64_t SizeBytes() const override { return device_.GetGeometry().total_bytes; }
    bool Read(std::uint64_t offset, std::size_t count, std::vector<std::byte>& out) const override
    { return device_.Read(offset, count, out); }
private:
    const apfsaccess::rw::BlockDevice& device_;
};

bool PrepareExplicitSnapshotMount(MountContext& ctx, std::string& error)
{
    using namespace apfsaccess::catalog;
    using namespace apfsaccess::rw;
    error.clear();
    if (!ValidateSnapshotArguments(ctx.args) || ctx.metadata_store || ctx.tx_manager ||
        ctx.payload_spool || !ctx.tx_journal_file.empty() || !ctx.recovery_marker_file.empty() ||
        ctx.native_write_enabled || ctx.overlay_write_enabled)
    { error = "SnapshotRequiresFreshExplicitReadOnlySession"; return false; }
    auto arguments = ctx.args;
    arguments.device = std::filesystem::path(arguments.device).lexically_normal().wstring();
    std::vector<UniqueWinHandle> ancestor_pins;
    if (!PinSnapshotImageAncestors(arguments.device, ancestor_pins, error)) return false;
    auto lease = BlockDevice::OpenStableReadOnlyImage(arguments.device, error);
    if (!lease) return false;
    SnapshotLeaseSource source(*lease);
    ApfsContainerCatalog catalog;
    if (!ApfsContainerCatalog::TryLoadImage(source, "snapshot-image", WideToUtf8(ctx.args.device),
            catalog, error, CatalogLoadPolicy::StrictApple)) return false;
    const auto container_id = WideToUtf8(ctx.args.container_id);
    ResolvedMountVolume volume;
    if (!catalog.TryResolveVolume(container_id, ctx.args.volume_object_id, volume, error)) return false;
    if (!ctx.args.volume.empty() && WideToUtf8(ctx.args.volume) != volume.name_utf8)
    { error = "SnapshotVolumeNameMismatch"; return false; }
    const ApfsContainerDescriptor* container = nullptr;
    const ApfsPhysicalStoreDescriptor* store = nullptr;
    for (const auto& candidate : catalog.Containers())
        if (candidate.container_uuid_hex == container_id)
        {
            if (container) { error = "SnapshotContainerAmbiguous"; return false; }
            container = &candidate;
        }
    for (const auto& candidate : catalog.Stores())
        if (candidate.container_uuid_hex == container_id)
        {
            if (store) { error = "SnapshotRequiresSingleStore"; return false; }
            store = &candidate;
        }
    if (!container || !store || container->fusion || container->member_store_ids.size() != 1 ||
        store->offset_bytes != ctx.args.device_offset_bytes)
    { error = "SnapshotStoreScopeMismatch"; return false; }
    ApfsSnapshotScope scope{store->offset_bytes, store->size_bytes, container_id,
        volume.volume_uuid_hex, volume.object_id, container->checkpoint_xid};
    std::vector<ApfsSnapshotInfo> inventory;
    if (!ApfsSnapshotStore::Enumerate(source, scope, inventory, error)) return false;
    const ApfsSnapshotInfo* selected = nullptr;
    for (const auto& snapshot : inventory)
        if (snapshot.identity.snapshot_xid == ctx.args.snapshot_xid)
        {
            if (selected) { error = "SnapshotXidAmbiguous"; return false; }
            selected = &snapshot;
        }
    if (!selected) { error = "SnapshotXidNotFound"; return false; }
    arguments.volume = Utf8ToWide(volume.name_utf8);
    arguments.incompatible_features = volume.incompatible_features;
    arguments.allow_legacy_scaffold_for_fixtures = false;
    auto metadata = std::make_unique<MetadataStore>(BuildMetadataStoreVolumeContext(arguments));
    // The original lease survives until the adapter has installed its own
    // stable lease, leaving no writer/replacement gap during selection.
    if (!metadata->PrepareNativeSnapshotReadPath(selected->identity, error)) return false;
    if (!lease->RevalidateStableReadOnlyImage())
    { error = "SnapshotSelectionLeaseChanged"; return false; }
    arguments.incompatible_features = metadata->Context().incompatible_features;
    arguments.snapshot_name = Utf8ToWide(selected->identity.name_utf8);
    ctx.args = std::move(arguments);
    ctx.owned_metadata_store = std::move(metadata);
    ctx.metadata_store = ctx.owned_metadata_store.get();
    ctx.runtime_last_commit_xid = ctx.args.snapshot_xid;
    RefreshReportedVolumeInfoFromMetadata(ctx);
    return true;
}
