#pragma once
// Included after the canonical startup-recovery helpers. Recovery identities in
// args and the existing journal/marker paths remain fixed for the session.
bool RefreshNativeVolumeLabel(MountContext& c, bool commit_complete = true)
{
    const auto* cp = c.metadata_store ? c.metadata_store->AuthoritativeAppleCheckpointView() : nullptr;
    if (!cp) return false;
    const auto it = std::find_if(cp->volumes.begin(), cp->volumes.end(),
        [&](const auto& v) { return v.superblock.object_id == c.container_volume_oid; });
    std::wstring label;
    if (it == cp->volumes.end() || !it->superblock.name_valid ||
        !TryUtf8ToWideStrict(it->superblock.name_utf8, label)) return false;
    {
        std::lock_guard label_lock(c.volume_label_mutex);
        c.label = label;
    }
    {
        std::lock_guard<std::recursive_mutex> runtime(c.runtime_state_mutex);
        c.runtime_volume_label = std::move(label);
        if (commit_complete)
        {
            c.runtime_last_commit_xid = c.metadata_store->CheckpointXid();
            c.pending_native_writes = false;
        }
    }
    RequestCallbackStatusPublish(&c);
    return true;
}

std::optional<bool> ReplayIsolatedVolumeRename(MountContext& c)
{
    using Op = apfsaccess::rw::WriteAheadLog::OperationKind;
    std::vector<apfsaccess::rw::TransactionManager::AcceptedTransaction> transactions;
    if (!c.tx_manager->LoadAcceptedTransactionsSinceCleanup(transactions)) return std::nullopt;
    bool found = false;
    for (const auto& tx : transactions) for (const auto& r : tx.mutations) found |= r.operation == Op::RenameVolume;
    if (!found) return std::nullopt;
    try
    {
        if (!IsManifestSession(&c))
        { (void)BlockNativeCloneRecovery(c, L"VolumeRenameCoordinatorRequired"); return false; }
        std::lock_guard commit(c.commit_mutex);
        std::unique_lock reads(c.committed_read_gate);
        std::lock_guard metadata(c.metadata_mutex);
        std::lock_guard journal(c.tx_mutex);
        std::string error;
        const auto replay = apfsaccess::rw::ReplayVolumeRename(*c.container_coordinator,
            *c.tx_manager, c.container_volume_oid, error);
        if (!replay.value_or(false) || !RefreshNativeVolumeLabel(c) || !UpdateRecoveryMarkerBestEffort(&c, false))
        { (void)BlockNativeCloneRecovery(c, L"VolumeRenameReplayFailed"); return false; }
        {
            std::lock_guard<std::recursive_mutex> runtime(c.runtime_state_mutex);
            c.recovery_active = false; c.write_degraded = false;
            c.runtime_recovery_reason.clear(); c.runtime_last_recovery_action = L"VolumeRenameReplayApplied";
        }
        return true;
    }
    catch (...) { (void)BlockNativeCloneRecovery(c, L"VolumeRenameReplayException"); return false; }
}
