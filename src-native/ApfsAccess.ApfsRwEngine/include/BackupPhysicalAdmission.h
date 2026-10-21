#pragma once
#include "BackupImageWriterProfile.h"
#include "VolumePhysicalMedia.h"

namespace apfsaccess::rw
{
enum class BackupPhysicalAdmissionResult
{
    Rejected,
    ExactGraphRequiresPhysicalRecoveryBridge,
};

// A read-only bridge from G08's already-held window into the SAME bounded
// graph validator. It cannot mint/open a raw writer or authorize publication.
// The regular-file-only accepted reconstruction/flush must gain its own exact
// held-window counterpart before a caller can enable backup physical writes.
inline BackupPhysicalAdmissionResult InspectHeldBackupPhysicalProfile(
    const std::shared_ptr<VolumePhysicalSource>& held, const RawSnapshotBinding& trusted_binding,
    std::wstring_view trusted_instance, const catalog::AppleCheckpointView& selected,
    std::uint64_t volume_oid, std::string& error)
try
{
    error.clear();
    if (!held || trusted_instance.empty() || held->InstanceId() != trusted_instance ||
        held->Binding() != trusted_binding || !held->Revalidate() ||
        !held->SizeBytes() || held->SizeBytes() != trusted_binding.media.limit_bytes ||
        held->SizeBytes() > (256ull << 20) || held->SizeBytes() % 4096 ||
        selected.volumes.size() != 1 || selected.volumes.front().superblock.object_id != volume_oid)
    {
        error = "BackupPhysicalHeldWindowAuthorityUnproven";
        return BackupPhysicalAdmissionResult::Rejected;
    }
    if (!ValidateBackupImageWriterProfile(*held, selected, volume_oid, error))
        return BackupPhysicalAdmissionResult::Rejected;
    if (!held->Revalidate() || held->Binding() != trusted_binding || held->InstanceId() != trusted_instance)
    {
        error = "BackupPhysicalHeldWindowChanged";
        return BackupPhysicalAdmissionResult::Rejected;
    }
    error = "BackupPhysicalAcceptedRecoveryBridgeRequired";
    return BackupPhysicalAdmissionResult::ExactGraphRequiresPhysicalRecoveryBridge;
}
catch (...)
{
    error = "BackupPhysicalAdmissionFailed";
    return BackupPhysicalAdmissionResult::Rejected;
}
}
