#pragma once
#include "MetadataStore.h"
#include "VolumePhysicalMedia.h"

namespace apfsaccess::rw
{
// Ownership only. Canonical graph, original journal/spool and publication
// admission remain the separate runtime's responsibility.
inline std::unique_ptr<MetadataStore> CreateVolumePhysicalMetadataStore(
    const std::shared_ptr<VolumePhysicalSource>& held, const RawSnapshotBinding& trusted_binding,
    std::wstring_view trusted_instance, MetadataStore::VolumeContext context, std::string& error)
try
{
    auto device = VolumePhysicalSource::RetainMetadataDevice(held, trusted_binding, trusted_instance, error);
    // A null device would invoke MetadataStore's independent-open fallback.
    if (!device) return {};
    if (context.device_path != device->Path() || context.device_offset_bytes != trusted_binding.media.base_offset_bytes) {
        error = "VolumePhysicalMetadataContextMismatch";return {};
    }
    auto store = std::make_unique<MetadataStore>(std::move(context), std::move(device));
    if (!held->OwnsMetadataDevice(store->Device(), error)) return {};
    return store;
}
catch (...)
{
    error = "VolumePhysicalMetadataConstructionFailed";return {};
}
}
