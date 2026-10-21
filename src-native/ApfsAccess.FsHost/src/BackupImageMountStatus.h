#pragma once
std::string BackupImageStatusJson(const MountContext& c)
{
    if (!c.args.backup_image.enabled) return {};
    const auto& b = c.args.backup_image;
    return ",\"backupImageWriter\":{\"profile\":\"bounded-backup-image-v1\",\"roleRaw\":384,"
        "\"volumeOid\":" + std::to_string(c.args.volume_object_id) +
        ",\"volumeUuid\":\"" + WideToUtf8(b.volume_uuid) +
        "\",\"admittedCheckpointXid\":" + std::to_string(b.checkpoint_xid) +
        ",\"sourceSha256\":\"" + WideToUtf8(b.source_sha256) +
        "\",\"fileIdentity\":\"" + WideToUtf8(b.file_identity) +
        "\",\"nativeWriteEnabled\":" + (c.native_write_enabled.load() ? "true" : "false") +
        ",\"writeDegraded\":" + (c.write_degraded.load() ? "true" : "false") + "}";
}
