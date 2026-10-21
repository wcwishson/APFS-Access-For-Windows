#pragma once
std::string BackupHeldStatusJson(const MountContext& c)
{
    if (!c.args.backup_held.enabled) return {};
    const auto* b = c.backup_held.get();
    const bool current = b && b->source && b->source->Current();
    const auto marks = c.tx_manager ? c.tx_manager->Watermarks()
        : apfsaccess::rw::TransactionManager::DurabilityWatermarks{};
    return ",\"backupHeldWriter\":{\"profile\":\"bounded-backup-held-v1\",\"roleRaw\":384,"
        "\"volumeOid\":" + std::to_string(c.args.volume_object_id) +
        ",\"volumeUuid\":\"" + WideToUtf8(c.args.backup_held.volume_uuid) +
        "\",\"bindingHex\":\"" + WideToUtf8(c.args.backup_held.binding_hex) +
        "\",\"sourceIdentity\":\"" + (b ? b->source_identity : std::string{}) +
        "\",\"admittedCheckpointXid\":" + std::to_string(c.args.backup_held.checkpoint_xid) +
        ",\"sourceCurrent\":" + (current ? "true" : "false") +
        ",\"startupAdmitted\":" + (b && b->startup_admitted ? "true" : "false") +
        ",\"acceptedSequence\":" + std::to_string(marks.accepted_sequence) +
        ",\"apfsDurableSequence\":" + std::to_string(marks.apfs_durable_sequence) +
        ",\"cleanupSequence\":" + std::to_string(marks.cleanup_sequence) +
        ",\"nativeWriteEnabled\":" + (c.native_write_enabled.load() ? "true" : "false") +
        ",\"writeDegraded\":" + (c.write_degraded.load() ? "true" : "false") + "}";
}
