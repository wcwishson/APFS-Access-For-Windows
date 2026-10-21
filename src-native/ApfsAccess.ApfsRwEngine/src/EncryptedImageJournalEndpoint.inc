rw::ProtectedJournalContinuation::Result ApfsEncryptedImageWriteSession::WithCleanJournalEndpoint(
    const std::function<rw::ProtectedJournalContinuation::Result(
        rw::ProtectedJournalContinuation::Endpoint&, std::string&)>& use,
    std::string& error)
{
    using Continuation = rw::ProtectedJournalContinuation;
    using Result = Continuation::Result;
    std::lock_guard lock(impl_->gate); error.clear();
    const auto status = impl_->Snapshot();
    if (!use || impl_->cancelled->load() || impl_->writing ||
        (status.phase != Phase::Locked && status.phase != Phase::Ready)) {
        error = "ImageWriterCleanJournalEndpointUnavailable"; return Result::RejectedBeforeWrite;
    }
    bool invoked = false;
    try {
        auto source = impl_->NewSource();
        auto checkpoint = LoadContainerCheckpointView(*source, 0, impl_->io->bytes, error);
        if (!checkpoint || checkpoint->superblock.uuid_hex != impl_->uuid ||
            checkpoint->superblock.block_size != 4096 ||
            checkpoint->superblock.block_count != impl_->io->bytes / 4096 ||
            checkpoint->superblock.xid != status.checkpoint_xid ||
            checkpoint->superblock_bytes.size() != 4096 ||
            checkpoint->superblock_physical_block >= impl_->io->bytes / 4096) {
            error = "ImageWriterCleanJournalCheckpointMismatch"; return Result::RejectedBeforeWrite;
        }
        auto volumes = LoadAppleReadOnlyVolumeView(*source, *checkpoint, error);
        if (!volumes || std::none_of(volumes->volumes.begin(), volumes->volumes.end(), [&](const auto& volume) {
                return volume.superblock.object_id == impl_->image.volume_oid &&
                    volume.superblock.uuid_hex == impl_->volume_uuid;
            })) {
            error = "ImageWriterCleanJournalVolumeMismatch"; return Result::RejectedBeforeWrite;
        }
        Continuation::Endpoint::Description description;
        description.source_binding = impl_->binding; description.source_identity = impl_->identity;
        description.container_uuid = impl_->uuid; description.volume_uuid = impl_->volume_uuid;
        description.container_bytes = impl_->io->bytes; description.volume_object_id = impl_->image.volume_oid;
        description.checkpoint_xid = checkpoint->superblock.xid;
        description.physical_nx_offset = checkpoint->superblock_physical_block * 4096;
        description.physical_nx_bytes = checkpoint->superblock_bytes;
        if (BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0,
            reinterpret_cast<PUCHAR>(description.physical_nx_bytes.data()),
            static_cast<ULONG>(description.physical_nx_bytes.size()),
            description.physical_nx_sha256.data(), static_cast<ULONG>(description.physical_nx_sha256.size())) < 0) {
            error = "ImageWriterCleanJournalEndpointHashFailed"; return Result::RejectedBeforeWrite;
        }
        const auto revalidate = [&, source](std::string& reason) {
            if (impl_->cancelled->load() || !impl_->io->Valid() || source->SourceIdentity() != description.source_identity) {
                reason = "ImageWriterCleanJournalSourceChanged"; return false;
            }
            auto current = LoadContainerCheckpointView(*source, 0, impl_->io->bytes, reason);
            if (!current || current->superblock.xid != description.checkpoint_xid ||
                current->superblock.uuid_hex != description.container_uuid ||
                current->superblock_physical_block * 4096 != description.physical_nx_offset ||
                current->superblock_bytes != description.physical_nx_bytes) {
                reason = "ImageWriterCleanJournalEndpointChanged"; return false;
            }
            auto selected = LoadAppleReadOnlyVolumeView(*source, *current, reason);
            if (!selected || std::none_of(selected->volumes.begin(), selected->volumes.end(), [&](const auto& volume) {
                    return volume.superblock.object_id == description.volume_object_id &&
                        volume.superblock.uuid_hex == description.volume_uuid;
                })) {
                reason = "ImageWriterCleanJournalVolumeChanged"; return false;
            }
            return true;
        };
        const auto read = [source](std::uint64_t at, std::span<std::byte> output, std::string& reason) {
            std::vector<std::byte> bytes;
            if (output.empty() || output.size() > 65536 || at > source->SizeBytes() ||
                output.size() > source->SizeBytes() - at || !source->Read(at, output.size(), bytes) || bytes.size() != output.size()) {
                reason = "ImageWriterCleanJournalGuardReadFailed"; return false;
            }
            std::copy(bytes.begin(), bytes.end(), output.begin()); return true;
        };
        Continuation::Endpoint endpoint(description, revalidate, read);
        invoked = true;
        const auto result = use(endpoint, error);
        if (result == Result::RecoveryRequired) impl_->PhaseTo(Phase::RecoveryRequired, true);
        return result;
    } catch (const std::exception& ex) {
        error = ex.what();
        if (invoked) { impl_->PhaseTo(Phase::RecoveryRequired, true); return Result::RecoveryRequired; }
        return Result::RejectedBeforeWrite;
    }
}
