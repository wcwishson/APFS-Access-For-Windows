#pragma once
#include "BackupHeldOriginalCensus.h"
#include "BackupPhysicalWriteOwner.h"
#include "VolumePhysicalMetadataOwner.h"

namespace backup_held_mount
{
inline constexpr std::size_t InlinePayloadLimitBytes = 4096;
struct Options
{
    bool enabled = false;
    std::wstring binding_hex, volume_uuid;
    std::uint64_t checkpoint_xid = 0;
};
struct State
{
    std::shared_ptr<apfsaccess::rw::VolumePhysicalSource> held;
    std::unique_ptr<apfsaccess::rw::BackupRetainedSource> source;
    std::unique_ptr<apfsaccess::fshost::NativeRawSnapshotStartupEvidence> key_parents;
    std::unique_ptr<apfsaccess::fshost::BackupHeldOriginalCensus> census;
    std::string source_identity, error;
    bool startup_admitted = false;
};
}
