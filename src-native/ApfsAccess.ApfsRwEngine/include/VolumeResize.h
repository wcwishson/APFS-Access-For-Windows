#pragma once
#include "AppleTransactionCommit.h"
#include "VolumeKeeperHistory.h"
#include <filesystem>
#include <map>

namespace apfsaccess::rw
{
enum class VolumeImageOperation : std::uint8_t { Grow = 1, Shrink = 2, Format = 3, Erase = 4 };
enum class VolumeImageOutcome : std::uint8_t { Refused, Prepared, Committed, Cancelled, RecoveryRequired };
struct VolumeImageRequest
{
    VolumeImageOperation operation = VolumeImageOperation::Grow;
    std::filesystem::path image;
    // Trusted service configuration: private, pre-existing, durable and identical
    // across restarts. Never a client choice or a temporary/fallback directory.
    std::filesystem::path journal_directory;
    std::string container_uuid, volume_uuid;
    std::uint64_t volume_oid = 0, checkpoint_xid = 0;
    std::uint64_t expected_bytes = 0, target_bytes = 0;
    std::map<std::uint64_t, std::filesystem::path> sibling_wals;
    // Format/erase only. They replace the entire container, including siblings.
    std::string new_container_uuid, new_volume_uuid, name_utf8;
    std::filesystem::path new_volume_wal;
    bool case_sensitive = false;
    VolumeKeeperHistoryContext history_context;
};
struct VolumeImageResult
{
    VolumeImageOutcome outcome = VolumeImageOutcome::Refused;
    std::string error, token, source_identity;
    std::filesystem::path journal;
    std::uint64_t pre_xid = 0, post_xid = 0, expires_unix_seconds = 0;
    std::uint64_t free_blocks_before = 0, free_blocks_after = 0;
};
// Ordinary whole-file image resize. Large images use bounded original chunk
// evidence and canonical owner-proved tail relocation. Protected physical
// windows have separate held-source entrypoints in VolumePhysicalKeeper.h.
VolumeImageResult PrepareVolumeResize(const VolumeImageRequest&);
VolumeImageResult ApplyVolumeResize(const VolumeImageRequest&, std::string_view token,
    const AppleCheckpointStageHook& interrupt = {});
VolumeImageResult RecoverVolumeResize(const VolumeImageRequest&, const AppleCheckpointStageHook& interrupt = {});
VolumeImageResult CancelVolumeResize(const VolumeImageRequest&, std::string_view token);
// Schema 1: uint64 values are decimal strings; one result document, never logs.
std::string VolumeImageJson(const VolumeImageRequest&, const VolumeImageResult&);
}
