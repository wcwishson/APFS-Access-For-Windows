#pragma once
// Included after MountContext and the direct checkpoint helpers.
class BackupImageVerificationSource final : public apfsaccess::catalog::RandomAccessSource
{
public:
    explicit BackupImageVerificationSource(const apfsaccess::rw::BlockDevice& device) : device_(device) {}
    std::uint64_t SizeBytes() const override { return device_.GetGeometry().total_bytes; }
    bool Read(std::uint64_t at, std::size_t count, std::vector<std::byte>& out) const override
    {
        out.clear();
        const auto size = SizeBytes();
        if (at > size || count > size - at) return false;
        if (!count) return true;
        const auto base = at - at % 4096;
        const auto prefix = static_cast<std::size_t>(at - base);
        const auto length = (prefix + count + 4095) / 4096 * 4096;
        if (length > size - base || !device_.ReadForVerification(base, length, out)) return false;
        out.erase(out.begin(), out.begin() + prefix); out.resize(count); return true;
    }
private:
    const apfsaccess::rw::BlockDevice& device_;
};

bool BackupImageSourceHash(const BackupImageVerificationSource& source, std::string& out)
{
    out.clear();
    BCRYPT_ALG_HANDLE algorithm = nullptr; BCRYPT_HASH_HANDLE hash = nullptr;
    ScopeExit close{[&]() { if (hash) BCryptDestroyHash(hash); if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0); }};
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0 ||
        BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0) < 0) return false;
    for (std::uint64_t at = 0; at < source.SizeBytes();) {
        const auto count = static_cast<std::size_t>((std::min)(source.SizeBytes() - at, 1ull << 20));
        std::vector<std::byte> bytes;
        if (!source.Read(at, count, bytes) || BCryptHashData(hash,
            reinterpret_cast<PUCHAR>(bytes.data()), static_cast<ULONG>(bytes.size()), 0) < 0) return false;
        at += count;
    }
    std::array<unsigned char, 32> digest{};
    if (BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) < 0) return false;
    constexpr char hex[] = "0123456789abcdef";
    for (auto b : digest) { out.push_back(hex[b >> 4]); out.push_back(hex[b & 15]); }
    return true;
}

bool ValidateBackupImageStartupLocked(MountContext& c, std::string& error)
{
    if (!c.args.backup_image.enabled) return true;
    const auto fail = [&](const char* reason) { error = std::string("BackupImageStartupUnproven:") + reason; return false; };
    if (!c.metadata_store || !c.native_write_enabled || IsManifestSession(&c)) return fail("Owner");
    const auto& device = c.metadata_store->Device();
    const auto observation = device.CaptureExclusiveWriteSourceObservation();
    const auto* checkpoint = c.metadata_store->AuthoritativeAppleCheckpointView();
    const auto& expected = c.args.backup_image;
    std::string identity, digest;
    if (!observation || !device.IsRegularFile() || device.BaseOffsetBytes()) return fail("ExclusiveWholeImage");
    if (!device.QueryRegularImageIdentity(identity)) return fail("FileIdentityUnavailable");
    if (identity != WideToUtf8(expected.file_identity)) return fail("FileIdentityMismatch");
    if (!checkpoint || checkpoint->volumes.size() != 1 ||
        checkpoint->container.superblock.xid != expected.checkpoint_xid ||
        checkpoint->container.superblock.uuid_hex != WideToUtf8(c.args.container_id) ||
        checkpoint->volumes.front().superblock.object_id != c.args.volume_object_id ||
        checkpoint->volumes.front().superblock.uuid_hex != WideToUtf8(expected.volume_uuid)) return fail("SelectedCheckpoint");
    BackupImageVerificationSource source(device);
    if (!source.SizeBytes() || source.SizeBytes() > (256ull << 20)) return fail("SourceGeometry");
    if (!BackupImageSourceHash(source, digest)) return fail("SourceHashUnavailable");
    if (digest != WideToUtf8(expected.source_sha256)) return fail("SourceHashMismatch");
    if (!apfsaccess::rw::ValidateBackupImageWriterProfile(source, *checkpoint, c.args.volume_object_id, error))
        return error.empty() ? fail("Profile") : false;
    if (!device.IsExclusiveWriteSourceObservationCurrent(*observation)) return fail("SourceChanged");
    return true;
}

bool ProveSelectedRetainedPrefix(MountContext& c, std::vector<std::uint64_t>& sequences, std::string& error)
{
    if (c.backup_held && c.backup_held->source)
        return c.metadata_store->ProveBackupRetainedAcceptedPrefix(*c.tx_manager, *c.payload_spool,
            c.tx_journal_file, c.payload_spool_volume_identity, *c.backup_held->source, sequences, error);
    if (c.args.backup_image.enabled)
        return c.metadata_store->ProveBackupRetainedAcceptedPrefix(*c.tx_manager, *c.payload_spool,
            c.tx_journal_file, c.payload_spool_volume_identity, sequences, error);
    return c.metadata_store->ProveRetainedAcceptedPrefix(*c.tx_manager, *c.payload_spool,
        c.tx_journal_file, c.payload_spool_volume_identity, sequences, error);
}

std::optional<bool> RecoverPublishedBackupImage(MountContext& c)
{
    if (!c.args.backup_image.enabled) return std::nullopt;
    std::lock_guard commit(c.commit_mutex);
    std::unique_lock reads(c.committed_read_gate);
    std::lock_guard metadata(c.metadata_mutex);
    std::lock_guard journal(c.tx_mutex);
    using Tx = apfsaccess::rw::TransactionManager;
    std::vector<Tx::AcceptedTransaction> transactions;
    std::string error;
    const auto fail = [&]() -> std::optional<bool> {
        SetRuntimeRecoveryReason(c, L"BackupAcceptedPublicationUnproven"); return false;
    };
    if (!c.payload_spool || !c.tx_manager->LoadAcceptedTransactionsSinceCleanup(transactions, &error)) return fail();
    if (transactions.empty()) return std::nullopt;
    // Flush even when a readable Checkpointed marker already claims durability.
    const auto sequence = c.tx_manager->Watermarks().accepted_sequence;
    if (!c.tx_manager->FlushAcceptedEvidenceDurability(sequence)) return fail();
    for (const auto& transaction : transactions)
        for (const auto& record : transaction.mutations)
            if (record.operation == apfsaccess::rw::WriteAheadLog::OperationKind::CloneFile)
                return std::nullopt;
    const auto current = c.metadata_store->CheckpointXid().value_or(0);
    if (transactions.front().preimage_checkpoint_xid >= current) return std::nullopt;
    std::vector<std::uint64_t> proven;
    if (!ProveSelectedRetainedPrefix(c, proven, error)) return fail();
    // A mixed published prefix and pending tail continues through normal replay,
    // whose prefix checks call the same exact backup proof a second time.
    if (proven.size() != transactions.size()) return std::nullopt;
    if (proven.back() != sequence || !c.metadata_store->FlushBackupImageRecoveryEvidence() ||
        !c.tx_manager->MarkApfsDurableThrough(sequence) || !c.tx_manager->MarkCleanedThrough(sequence)) return fail();
    if (!c.payload_spool->CleanupThroughSequence(sequence)) return fail();
    return std::nullopt;
}

bool ReconcileCleanedBackupPayloadSpool(MountContext& c, std::string& error)
try
{
    error.clear();
    if (!c.args.backup_image.enabled || !c.payload_spool || !c.payload_spool->RecoveryRequired() ||
        !c.native_write_enabled) return true;
    const auto fail = [&](const char* reason) { error = reason; return false; };
    {
        std::lock_guard commit(c.commit_mutex);
        std::unique_lock reads(c.committed_read_gate);
        std::lock_guard metadata(c.metadata_mutex);
        std::lock_guard journal(c.tx_mutex);
        if (!c.tx_manager || !c.metadata_store) return fail("BackupCleanedPayloadOwnerMissing");
        const auto marks = c.tx_manager->Watermarks();
        // Pending accepted work still belongs to normal replay. Only an actual
        // complete Cleaned boundary can retire these indexed payload ranges.
        if (!marks.accepted_sequence || marks.accepted_sequence != marks.apfs_durable_sequence ||
            marks.accepted_sequence != marks.cleanup_sequence) return true;
        const auto lease = c.tx_manager->ObservedJournalWriterLeaseGeneration();
        const auto unchanged = [&] {
            const auto current = c.tx_manager->Watermarks();
            return lease && c.tx_manager->ObservedJournalWriterLeaseGeneration() == lease &&
                c.tx_manager->ObservedJournalAppendLeaseGeneration() == lease &&
                current.accepted_sequence == marks.accepted_sequence &&
                current.apfs_durable_sequence == marks.apfs_durable_sequence &&
                current.cleanup_sequence == marks.cleanup_sequence && c.tx_manager->CanClearRecoveryState();
        };
        if (HasBlockedRecoveryEvidence(c) || !c.metadata_store->IsCommitPathReady() || !unchanged() ||
            !c.tx_manager->FlushRetainedOriginalEvidenceDurability() ||
            !c.metadata_store->FlushBackupImageRecoveryEvidence() || !unchanged())
            return fail("BackupCleanedPayloadDurabilityUnproven");
        if (!c.payload_spool->CleanupThroughSequence(marks.cleanup_sequence) || !unchanged())
            return fail("BackupCleanedPayloadCleanupUnproven");
    }
    ClearRecoveredMarkerIfClean(c, L"BackupCleanedPayloadSpoolRecovered");
    return true;
}
catch (...) { error = "BackupCleanedPayloadRecoveryFailed"; return false; }
