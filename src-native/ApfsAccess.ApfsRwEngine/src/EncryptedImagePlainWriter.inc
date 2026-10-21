bool ApfsEncryptedImageWriteSession::WithTransitionPlainStore(rw::TransactionManager& tx,
    rw::EncryptedPublicationJournal& journal, PlainWriterPurpose purpose, std::uint64_t accepted,
    const std::function<bool(rw::MetadataStore&, std::string&)>& operation, std::string& error)
{
    std::lock_guard lock(impl_->gate); error.clear();
    const auto status = impl_->Snapshot();
    const auto recovery = purpose == PlainWriterPurpose::AcceptedRecovery;
    if (!operation || impl_->cancelled->load() || impl_->writing || impl_->key ||
        (status.phase != Phase::Locked && !(recovery && status.phase == Phase::RecoveryRequired)) ||
        (!recovery && status.recovery_required) || !tx.RecoveryStateValid() ||
        tx.CurrentState() != rw::TransactionManager::State::Idle ||
        tx.ProtectedSourceBinding() != std::optional{impl_->binding}) {
        error = "ImageWriterHeldPlainOwnerRequired"; return false;
    }
    bool invoked = false;
    const auto failed = [&] {
        if (invoked) impl_->PhaseTo(Phase::RecoveryRequired, true);
        return false;
    };
    try {
        impl_->PruneInodes();
        if (!impl_->read_inodes.empty()) { error = "ImageWriterHeldPlainReadInodesUnsupported"; return false; }
        const auto jid = tx.ProtectedJournalIdentity();
        const auto marks = tx.Watermarks();
        if (!jid || (!recovery && (accepted || marks.accepted_sequence != marks.cleanup_sequence ||
                marks.apfs_durable_sequence != marks.cleanup_sequence)) ||
            (recovery && (!accepted || marks.accepted_sequence != accepted || marks.cleanup_sequence >= accepted))) {
            error = "ImageWriterHeldPlainOriginalBoundaryMismatch"; return false;
        }
        auto source = impl_->NewSource();
        auto before = LoadAppleCheckpointView(*source, 0, impl_->io->bytes, error);
        if (!before || before->volumes.size() != 1 || before->container.superblock.uuid_hex != impl_->uuid ||
            before->container.superblock.block_size != 4096 || before->container.superblock.block_count != impl_->io->bytes / 4096 ||
            before->container.superblock.xid != status.checkpoint_xid ||
            before->volumes.front().superblock.object_id != impl_->image.volume_oid ||
            before->volumes.front().superblock.uuid_hex != impl_->volume_uuid ||
            before->volumes.front().superblock.fs_flags != kFsFlagUnencrypted) {
            error = "ImageWriterHeldPlainCurrentAllocatorRequired"; return false;
        }
        std::shared_ptr<const SoftwareVolumeRetainedOwners> owners;
        if (recovery) owners = journal.RestoreTransitionRetainedOwnersForPlainReplay(tx, *source, accepted, error);
        else owners = journal.RestoreTransitionRetainedOwners(tx, *source, error);
        if (!owners || owners->SourceIdentity() != impl_->identity || owners->SourceBinding() != impl_->binding ||
            owners->OriginalJournalIdentity() != *jid || owners->VolumeObjectId() != impl_->image.volume_oid ||
            owners->VolumeUuid() != impl_->volume_uuid) {
            if (error.empty()) error = "ImageWriterHeldPlainRetainedAuthorityRequired";
            return false;
        }
        impl_->Revoke(); impl_->admitted = {}; impl_->PhaseTo(Phase::Preparing, recovery);
        bool success = false;
        {
            // Duplicate handles share a file position. Keep the original I/O
            // mutex until every synchronous store/adapter operation has ended.
            std::lock_guard io_lock(impl_->io->mutex);
            auto path = impl_->image.path;
            HANDLE duplicate = INVALID_HANDLE_VALUE;
            if (!impl_->io->Valid() || !DuplicateHandle(GetCurrentProcess(), impl_->io->file,
                    GetCurrentProcess(), &duplicate, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
                error = "ImageWriterHeldPlainDuplicateFailed"; impl_->PhaseTo(status.phase, status.recovery_required); return false;
            }
            auto device = rw::BlockDevice::AdoptSoftwareTransitionImage(std::move(path), duplicate,
                impl_->image.offset, impl_->image.bytes,
                (std::uint64_t(impl_->io->identity.nFileSizeHigh) << 32) | impl_->io->identity.nFileSizeLow, error);
            if (!device) { impl_->PhaseTo(status.phase, status.recovery_required); return false; }
            rw::SoftwareTransitionHeldImageAuthority held_image(*device, impl_->io->file);
            rw::MetadataStore::VolumeContext context;
            context.device_path = impl_->image.path; context.device_offset_bytes = impl_->image.offset;
            context.volume_object_id = impl_->image.volume_oid; context.container_uuid_hex = impl_->uuid;
            context.volume_uuid_hex = impl_->volume_uuid; context.allow_legacy_scaffold_for_fixtures = false;
            rw::MetadataStore store(context, device);
            invoked = true;
            success = rw::WithSoftwareTransitionPlainWriter(store, tx, owners,
                [&](std::string& detail) { return !impl_->cancelled->load() && operation(store, detail); }, error);
        }
        if (!success) return failed();
        source = impl_->NewSource();
        auto after = LoadAppleCheckpointView(*source, 0, impl_->io->bytes, error);
        if (!after || after->volumes.size() != 1 || after->container.superblock.uuid_hex != impl_->uuid ||
            after->container.superblock.xid < before->container.superblock.xid ||
            after->container.superblock.xid - before->container.superblock.xid > 1 ||
            after->volumes.front().superblock.object_id != impl_->image.volume_oid ||
            after->volumes.front().superblock.uuid_hex != impl_->volume_uuid ||
            after->volumes.front().superblock.fs_flags != kFsFlagUnencrypted) {
            error = "ImageWriterHeldPlainCanonicalReadbackFailed"; return failed();
        }
        std::uint64_t free = 0;
        for (const auto& device : after->spaceman.devices) {
            if (device.free_count > UINT64_MAX / 4096 || free > UINT64_MAX - device.free_count * 4096) {
                error = "ImageWriterHeldPlainFreeSpaceOverflow"; return failed();
            }
            free += device.free_count * 4096;
        }
        {
            std::lock_guard status_lock(impl_->status_gate);
            impl_->status.checkpoint_xid = after->container.superblock.xid;
            impl_->status.next_inode_id = after->volumes.front().superblock.next_object_id;
            impl_->status.free_bytes = free; impl_->status.free_space_valid = true;
            if (after->container.superblock.xid != before->container.superblock.xid) ++impl_->status.commits;
        }
        impl_->PhaseTo(Phase::Locked); return true;
    } catch (const std::exception& ex) {
        error = ex.what();
        if (!invoked) impl_->PhaseTo(status.phase, status.recovery_required);
        return failed();
    }
}
