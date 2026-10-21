#pragma once

// Caller holds the metadata and journal gates for this retained mount owner.
bool EnrollNativeHardLinkJournalIdentity(MountContext& c)
{
    if (!c.metadata_store || !c.tx_manager || c.args.encrypted.enabled || c.args.fusion.enabled ||
        IsManifestSession(&c) || !c.args.readwrite || !IsWriteBackendMode(c.args.write_backend, L"Native")) return false;
    const auto& store = *c.metadata_store;
    const auto* checkpoint = store.AuthoritativeAppleCheckpointView();
    const auto oid = store.Context().volume_object_id;
    if (!checkpoint || !oid || checkpoint->volumes.size() != 1 ||
        checkpoint->volumes.front().superblock.object_id != oid ||
        store.CheckpointXid() != checkpoint->container.superblock.xid ||
        checkpoint->container.superblock.uuid_hex.size() != 32) return false;
    const auto identity = "apfs-vol:" + checkpoint->container.superblock.uuid_hex + ":" + std::to_string(oid);
    return c.tx_manager->EnrollCanonicalJournalIdentity(Utf8ToWide(identity));
}
