bool ApfsEncryptedImageWriteSession::ObserveKeyManagementEndpoint(
    ImageKeyManagementEndpoint& output, std::string& error)
{
    std::lock_guard lock(impl_->gate); output = {}; error.clear();
    const auto status = impl_->Snapshot();
    if (impl_->cancelled->load() || impl_->writing || status.recovery_required ||
        (status.phase != Phase::Locked && status.phase != Phase::Ready)) {
        error = "ImageWriterEndpointUnavailable"; return false;
    }
    try {
        auto source = impl_->NewSource();
        auto checkpoint = LoadContainerCheckpointView(*source, 0, impl_->io->bytes, error);
        if (!checkpoint || checkpoint->superblock.uuid_hex != impl_->uuid ||
            checkpoint->superblock.block_size != 4096 ||
            checkpoint->superblock.block_count != impl_->io->bytes / 4096 ||
            checkpoint->superblock.xid != status.checkpoint_xid) {
            error = "ImageWriterEndpointCheckpointMismatch"; return false;
        }
        auto volumes = LoadAppleReadOnlyVolumeView(*source, *checkpoint, error);
        if (!volumes) return false;
        const auto selected = std::find_if(volumes->volumes.begin(), volumes->volumes.end(), [&](const auto& volume) {
            return volume.superblock.object_id == impl_->image.volume_oid && volume.superblock.uuid_hex == impl_->volume_uuid;
        });
        if (selected == volumes->volumes.end()) {
            error = "ImageWriterEndpointVolumeMismatch"; return false;
        }
        ImageKeyManagementEndpoint observed;
        observed.source_identity = impl_->identity; observed.container_uuid = impl_->uuid;
        observed.volume_uuid = impl_->volume_uuid; observed.volume_object_id = impl_->image.volume_oid;
        observed.checkpoint_xid = checkpoint->superblock.xid;
        const auto flags = selected->superblock.fs_flags;
        if (flags == kFsFlagOneKey) {
            UnlockError reason{};
            auto bags = InspectPasswordKeybagMetadata(*source, impl_->image.volume_oid, impl_->image.keybag_length, reason);
            if (!bags || bags->users.size() != 1 || bags->selection.checkpoint_xid != observed.checkpoint_xid ||
                BytesToHexLower(bags->selection.container_uuid.data(), 16) != impl_->uuid ||
                BytesToHexLower(bags->selection.volume_uuid.data(), 16) != impl_->volume_uuid) {
                error = "ImageWriterEndpointSoftwareBagRequired"; return false;
            }
            observed.mode = SoftwareVolumeMode::OneKeyGenerationZero;
            observed.encrypted_selection = bags->selection;
            observed.encrypted_selection->user_uuid = bags->users.front();
        } else if (flags != kFsFlagUnencrypted) {
            error = "ImageWriterEndpointModeUnsupported"; return false;
        }
        auto final = LoadContainerCheckpointView(*source, 0, impl_->io->bytes, error);
        if (impl_->cancelled->load() || !impl_->io->Valid() || !final ||
            final->superblock_physical_block != checkpoint->superblock_physical_block ||
            final->superblock_bytes != checkpoint->superblock_bytes) {
            error = "ImageWriterEndpointChanged"; return false;
        }
        output = std::move(observed); return true;
    } catch (const std::exception& ex) { error = ex.what(); return false; }
}
