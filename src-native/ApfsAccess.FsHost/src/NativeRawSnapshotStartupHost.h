#pragma once

// Included after the host's original-peer gates and recovery observations.
bool PrepareRawSnapshotHostStartup(
    apfsaccess::catalog::ContainerMountCoordinator& coordinator,
    const std::vector<std::unique_ptr<MountContext>>& sessions, std::string& error)
{
    using namespace apfsaccess;
    error.clear();
    if (sessions.empty() || !sessions.front() || sessions.size() > 100 || coordinator.IsRecoveryRequired() ||
        !coordinator.CheckpointCensusRequired() || coordinator.MountedVolumeCount() != sessions.size())
        return SnapshotRecoveryFail(error, "RawSnapshotStartupCohortRequired");
    SnapshotControlLocks gates(*sessions.front(), true);
    if (!gates.acquired) return SnapshotRecoveryFail(error, "RawSnapshotStartupPeerGatesRequired");
    const auto qualification = BuildRawSnapshotHardwareQualification(sessions.front()->args.raw_snapshot_hardware);
    const auto qualification_fields = [](const auto& q) {
        return std::tie(q.kind, q.bus_type, q.vendor, q.product, q.qualified_serial, q.qualified_vpd_type);
    };
    const auto lease = coordinator.Device().CaptureHeldRawSnapshotLease();
    rw::RawSnapshotBinding original_binding;
    if (!lease || !coordinator.Device().QueryHeldRawSnapshotBinding(*lease, qualification, original_binding, error))
        return false;
    std::vector<rw::RawSnapshotRuntimePeerOwner> originals;
    std::optional<rw::TransactionManager::AcceptedTransaction> restart;
    std::optional<rw::NativeSnapshotIntent> restart_intent;
    std::vector<MountContext*> marker_recovery_peers;
    MountContext* recovering = nullptr;
    for (const auto& session : sessions)
    {
        if (!session) return SnapshotRecoveryFail(error, "RawSnapshotStartupPeerMissing");
        auto& peer = *session;
        const auto peer_qualification = BuildRawSnapshotHardwareQualification(peer.args.raw_snapshot_hardware);
        if (!peer.args.enable_raw_snapshots || !peer.args.readwrite ||
            qualification_fields(peer_qualification) != qualification_fields(qualification) ||
            peer.container_coordinator != &coordinator || !peer.container_volume_oid ||
            peer.args.volume_object_id != peer.container_volume_oid ||
            coordinator.FindSessionStore(peer.container_volume_oid) != peer.metadata_store ||
            !peer.metadata_store || !peer.tx_manager || !peer.payload_spool ||
            !peer.raw_snapshot_startup_evidence || !peer.raw_snapshot_startup_evidence->Verify() ||
            HasBlockedRecoveryEvidence(peer) || !SnapshotRecoveryHostIdle(peer) ||
            !SnapshotRecoveryStoreClean(*peer.metadata_store) || !SnapshotRecoverySpoolClean(peer))
            return SnapshotRecoveryFail(error, "RawSnapshotStartupCleanPeerRequired");
        std::string canonical, recovery_identity;
        if (!coordinator.SessionCanonicalJournalIdentity(peer.container_volume_oid, canonical) ||
            !coordinator.SessionRecoveryIdentity(peer.container_volume_oid, recovery_identity) ||
            recovery_identity != WideToUtf8(peer.args.recovery_identity) ||
            peer.tx_manager->ConfiguredVolumeIdentity() != BuildWalVolumeIdentity(peer.args) ||
            peer.tx_manager->EnrolledCanonicalJournalIdentity() != Utf8ToWide(canonical) ||
            !peer.tx_manager->ObservedJournalWriterLeaseGeneration() ||
            peer.tx_manager->CurrentState() != rw::TransactionManager::State::Idle ||
            peer.tx_manager->PendingMutationCount() || !peer.tx_manager->RecoveryStateValid())
            return SnapshotRecoveryFail(error, "RawSnapshotStartupOriginalJournalRequired");
        const auto root = BuildPayloadSpoolSessionRoot(peer.args, rw::PayloadSpool::ResolveDefaultRoot());
        if (peer.tx_journal_file != root / "write-ahead.wal" ||
            peer.payload_spool->SpoolFilePath() != root / "payload-spool.bin" ||
            peer.payload_spool_volume_identity != recovery_identity ||
            peer.recovery_marker_file != BuildRecoveryMarkerPath(peer.args))
            return SnapshotRecoveryFail(error, "RawSnapshotStartupOriginalStorageRequired");
        std::vector<rw::TransactionManager::AcceptedTransaction> debt;
        const auto marks = peer.tx_manager->Watermarks();
        if (!peer.tx_manager->LoadAcceptedTransactionsSinceCleanup(debt, &error)) return false;
        RecoveryMarkerState marker;
        const auto marker_status = LoadRecoveryMarkerState(peer.recovery_marker_file, marker);
        if (marker_status == RecoveryMarkerLoadStatus::Invalid)
            return SnapshotRecoveryFail(error, "RawSnapshotStartupMarkerInvalid");
        if (debt.empty())
        {
            const bool dirty_marker = marker_status == RecoveryMarkerLoadStatus::Loaded && marker.dirty;
            const bool marker_recovery = dirty_marker &&
                IsCrashReplayModeReplayIfSafe(peer.args.write_crash_replay_mode) &&
                marker.last_commit_xid && *marker.last_commit_xid != 0 &&
                *marker.last_commit_xid <= coordinator.CheckpointXid() &&
                peer.pending_native_writes && peer.recovery_active &&
                peer.runtime_recovery_reason == L"RecoveryMarkerDirty" &&
                peer.runtime_last_recovery_action == L"RecoveryMarkerDetected" &&
                peer.runtime_last_commit_xid == marker.last_commit_xid &&
                peer.last_recovery_marker_dirty == true &&
                peer.last_recovery_marker_commit_xid == marker.last_commit_xid &&
                peer.tx_manager->ObservedJournalAppendLeaseGeneration() ==
                    peer.tx_manager->ObservedJournalWriterLeaseGeneration() &&
                peer.tx_manager->ValidatedCleanJournalGeneration() && peer.tx_manager->CanClearRecoveryState();
            if (!peer.native_write_enabled || peer.write_degraded ||
                ((!marker_recovery) && (peer.recovery_active || peer.pending_native_writes || dirty_marker)) ||
                marks.accepted_sequence != marks.apfs_durable_sequence || marks.accepted_sequence != marks.cleanup_sequence ||
                (marker_status == RecoveryMarkerLoadStatus::Loaded &&
                    marker.last_commit_xid && *marker.last_commit_xid > coordinator.CheckpointXid()))
                return SnapshotRecoveryFail(error, "RawSnapshotStartupCleanPeerRequired");
            if (marker_recovery) marker_recovery_peers.push_back(&peer);
        }
        else
        {
            rw::NativeSnapshotIntent intent;
            if (restart || debt.size() != 1 || debt.front().mutations.size() != 1 ||
                !rw::WriteAheadLog::SnapshotIntentIsConsistent(debt.front().mutations.front()) ||
                !rw::DecodeNativeSnapshotIntent(debt.front().mutations.front().inline_payload, intent) || !intent.raw_receipt ||
                intent.scope.volume_oid != peer.container_volume_oid || intent.scope.checkpoint_xid == UINT64_MAX ||
                intent.scope.container_uuid_hex != coordinator.ContainerUuidHex() ||
                intent.scope.volume_uuid_hex != peer.metadata_store->Context().volume_uuid_hex ||
                debt.front().preimage_checkpoint_xid != intent.scope.checkpoint_xid ||
                debt.front().mutations.front().volume_identity != recovery_identity ||
                !debt.front().accepted_sequence || marks.accepted_sequence != debt.front().accepted_sequence ||
                marks.cleanup_sequence >= marks.accepted_sequence ||
                (coordinator.CheckpointXid() != intent.scope.checkpoint_xid &&
                    coordinator.CheckpointXid() != intent.scope.checkpoint_xid + 1) ||
                marker_status != RecoveryMarkerLoadStatus::Loaded ||
                (marker.dirty
                    ? (marker.last_commit_xid && *marker.last_commit_xid > intent.scope.checkpoint_xid)
                    : (coordinator.CheckpointXid() != intent.scope.checkpoint_xid + 1 ||
                        marker.last_commit_xid != intent.scope.checkpoint_xid + 1 ||
                        marks.apfs_durable_sequence != marks.accepted_sequence)))
                return SnapshotRecoveryFail(error, "RawSnapshotStartupIsolatedReceiptRequired");
            recovering = &peer;
            restart = debt.front();
            restart_intent = std::move(intent);
        }
        if (debt.size() > 1)
            return SnapshotRecoveryFail(error, "RawSnapshotStartupReceiptRecoveryRequired");
        originals.push_back({peer.container_volume_oid, peer.metadata_store, peer.tx_manager.get(), peer.tx_journal_file.wstring()});
    }
    if (!marker_recovery_peers.empty())
    {
        if (restart) return SnapshotRecoveryFail(error, "RawSnapshotStartupMarkerRecoveryMixedDebt");
        // Marker-only recovery must authenticate existing journals for every
        // peer; creating an absent WAL cannot prove interrupted preacceptance.
        for (const auto& peer : originals)
            if (!peer.journal->ObservedJournalAppendLeaseGeneration() ||
                peer.journal->ObservedJournalAppendLeaseGeneration() != peer.journal->ObservedJournalWriterLeaseGeneration() ||
                !peer.journal->ValidatedCleanJournalGeneration() || !peer.journal->CanClearRecoveryState())
                return SnapshotRecoveryFail(error, "RawSnapshotStartupOriginalJournalRequired");
    }
    const auto census = coordinator.CheckpointCensusSnapshot();
    if (census.size() != originals.size()) return SnapshotRecoveryFail(error, "RawSnapshotStartupCensusIncomplete");
    for (const auto& entry : census)
    {
        const bool selected = recovering && entry.volume_object_id == recovering->container_volume_oid;
        if (std::count_if(originals.begin(), originals.end(), [&](const auto& peer) {
                return peer.volume_oid == entry.volume_object_id;
            }) != 1 ||
            (selected && (entry.required_checkpoint_xids != restart_intent->pins ||
                entry.unapplied_accepted_work != recovering->tx_manager->HasUnappliedAcceptedWork())) ||
            (!selected && (entry.unapplied_accepted_work || !entry.required_checkpoint_xids.empty())))
            return SnapshotRecoveryFail(error, "RawSnapshotStartupCensusMismatch");
    }
    const auto* mounted = originals.front().store->AuthoritativeAppleCheckpointView();
    if (!mounted) return SnapshotRecoveryFail(error, "RawSnapshotStartupCheckpointRequired");
    rw::SnapshotRuntimeDeviceSource source(coordinator.Device(), mounted->container.superblock);
    if (!source.IsValid() || source.SizeBytes() != original_binding.media.limit_bytes)
        return SnapshotRecoveryFail(error, "RawSnapshotStartupSourceWindowChanged");
    const auto disk = catalog::LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
    if (!disk || disk->container.superblock_bytes != mounted->container.superblock_bytes ||
        disk->container.superblock.uuid_hex != coordinator.ContainerUuidHex() ||
        disk->container.superblock.xid != coordinator.CheckpointXid() || disk->volumes.size() != originals.size())
        return SnapshotRecoveryFail(error, "RawSnapshotStartupCheckpointChanged");
    std::set<std::uint64_t> seen;
    for (const auto& volume : disk->volumes)
    {
        const auto found = std::find_if(originals.begin(), originals.end(), [&](const auto& peer) {
            return peer.volume_oid == volume.superblock.object_id;
        });
        if (found == originals.end() || !seen.insert(volume.superblock.object_id).second ||
            found->store->Context().volume_uuid_hex != volume.superblock.uuid_hex ||
            !found->store->Context().allow_native_snapshot_runtime ||
            !found->store->Context().allow_raw_device_canonical_commit ||
            found->store->Context().container_uuid_hex != coordinator.ContainerUuidHex() ||
            found->store->Context().volume_object_id != found->volume_oid ||
            !rw::CheckAppleVolumeWriteFeatures(disk->container.superblock, volume.superblock, error))
            return SnapshotRecoveryFail(error, "RawSnapshotStartupSourceCohortChanged");
    }
    rw::RawSnapshotBinding current_binding;
    if (!source.IsValid() || !coordinator.Device().QueryHeldRawSnapshotBinding(*lease, qualification, current_binding, error) ||
        current_binding != original_binding)
        return SnapshotRecoveryFail(error, "RawSnapshotStartupOriginalSourceChanged");
    for (const auto& session : sessions)
        if (!session->raw_snapshot_startup_evidence->Verify())
            return SnapshotRecoveryFail(error, "RawSnapshotStartupOriginalEvidenceChanged");
    // Keep original evidence and every existing/new ancestor pinned through
    // strict capture. Missing WALs use exclusive creation, never Begin/Abort.
    std::vector<fshost::NativeRawSnapshotStartupEvidence*> fences;
    for (const auto& session : sessions) fences.push_back(session->raw_snapshot_startup_evidence.get());
    if (!fshost::NativeRawSnapshotStartupEvidence::PrepareMissingParents(fences))
        return SnapshotRecoveryFail(error, "RawSnapshotStartupParentMaterializationFailed");
    for (const auto& peer : originals)
        if (!peer.journal->ObservedJournalAppendLeaseGeneration() &&
            !peer.journal->MaterializeAbsentStartupJournal(error))
            return SnapshotRecoveryFail(error, "RawSnapshotStartupJournalMaterializationFailed");
    std::shared_ptr<const rw::RawSnapshotRuntimeAuthority> authority;
    if (restart
        ? !rw::CaptureRawSnapshotRuntimeRestartAuthority(coordinator, originals, qualification, *restart, authority, error)
        : !rw::CaptureRawSnapshotRuntimeAuthority(coordinator, originals, qualification, authority, error)) return false;
    for (const auto& session : sessions)
        if (!session->raw_snapshot_startup_evidence->Verify())
            return SnapshotRecoveryFail(error, "RawSnapshotStartupOriginalEvidenceChanged");
    if (restart)
    {
        const rw::RawSnapshotRuntimeReplayParameters parameters{authority, restart->accepted_sequence};
        if (!rw::AdmitRawSnapshotRestartRecovery(coordinator, *recovering->tx_manager,
            recovering->container_volume_oid, parameters, error)) return false;
    }
    else for (const auto& session : sessions)
    {
        catalog::ApfsSnapshotScope scope;
        if (!rw::InspectRawSnapshotRuntimeAuthority(authority, coordinator, session->container_volume_oid, scope, nullptr, error))
            return false;
    }
    for (const auto& session : sessions)
        if (!session->raw_snapshot_startup_evidence->Verify())
            return SnapshotRecoveryFail(error, "RawSnapshotStartupOriginalEvidenceChanged");
    const auto clean_marker = std::string("dirty=0\nlastCommitXid=") +
        std::to_string(coordinator.CheckpointXid()) + "\n";
    const auto clean_bytes = std::as_bytes(std::span(clean_marker));
    for (const auto& session : sessions)
        if (!session->raw_snapshot_startup_evidence->PromoteMarkerOwner(clean_bytes))
            return SnapshotRecoveryFail(error, "RawSnapshotStartupMarkerOwnershipFailed");
    for (const auto& session : sessions)
        if (!session->raw_snapshot_startup_evidence->VerifyMarkerOwner())
            return SnapshotRecoveryFail(error, "RawSnapshotStartupMarkerOwnershipChanged");
    // Original cohort, source, checkpoint and WAL proofs precede every marker
    // write. An existing marker is preserved by promotion and needs persistence.
    RecoveryMarkerState reconciled_marker;
    reconciled_marker.dirty = false;
    reconciled_marker.last_commit_xid = coordinator.CheckpointXid();
    for (auto* peer : marker_recovery_peers)
        if (!PersistRecoveryMarkerState(peer, peer->recovery_marker_file, reconciled_marker))
            return SnapshotRecoveryFail(error, "RawSnapshotStartupMarkerRecoveryPersistFailed");
    for (const auto& session : sessions)
        if (!session->raw_snapshot_startup_evidence->VerifyMarkerOwner())
            return SnapshotRecoveryFail(error, "RawSnapshotStartupMarkerOwnershipChanged");
    for (auto* peer : marker_recovery_peers)
    {
        std::lock_guard<std::recursive_mutex> runtime_lock(peer->runtime_state_mutex);
        peer->pending_native_writes = false;
        peer->recovery_active = false;
        peer->runtime_recovery_reason.clear();
        peer->runtime_last_recovery_action = L"RawSnapshotStartupMarkerReconciled";
        peer->runtime_last_commit_xid = reconciled_marker.last_commit_xid;
    }
    for (const auto& session : sessions)
    {
        session->raw_snapshot_authority = authority;
        session->raw_snapshot_startup_admitted = true;
        if (restart)
        {
            session->raw_snapshot_host_write_paused = session->native_write_enabled;
            session->native_write_enabled = false;
        }
    }
    if (restart)
    {
        recovering->raw_snapshot_restart_sequence = restart->accepted_sequence;
        recovering->raw_snapshot_completion_xid = restart_intent->scope.checkpoint_xid + 1;
    }
    return true;
}
