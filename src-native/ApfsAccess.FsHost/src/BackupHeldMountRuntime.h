#pragma once
namespace
{
constexpr std::uint64_t kBackupHeldSpoolMaxBytes = 512ull << 20;

void ConfigureBackupHeldProviders(MountContext& c)
{
    c.metadata_store->SetFilePayloadProvider([p = &c](const std::wstring& path, std::uint64_t size) {
        return LoadHydratedPayloadForPath(p, path, size, false);
    });
    c.metadata_store->SetFilePayloadRangeProvider([p = &c](const std::wstring& path,
        apfsaccess::rw::MetadataStore::PayloadIdentity id, std::uint64_t at, std::span<std::byte> out) {
        return ReadHydratedPayloadRangeForPath(p, path, id, at, out);
    });
    c.metadata_store->SetCommitStageHook([p = &c](std::string_view) {
        const auto deadline = p->commit_deadline_tick_ms.load(std::memory_order_relaxed);
        if (!deadline || GetTickCount64() <= deadline) return true;
        p->commit_timeout_latched.store(true, std::memory_order_relaxed); return false;
    }, false);
}

bool IsBackupHeldCommitSettled(MountContext& c)
{
    if (!c.backup_held || !c.backup_held->startup_admitted || !c.backup_held->source ||
        !c.backup_held->census || !c.tx_manager || !c.metadata_store || c.metadata_store->PendingMutationCount())
        return false;
    const auto* cp = c.metadata_store->AuthoritativeAppleCheckpointView();
    if (!cp || !c.backup_held->source->MatchesCheckpoint(*cp)) return false;
    std::lock_guard journal(c.tx_mutex);
    return c.tx_manager->CanClearRecoveryState() && c.backup_held->census->Ready() &&
        c.backup_held->source->Current();
}

std::unique_ptr<apfsaccess::rw::MetadataStore> PublishBackupHeldForHost(MountContext& c,
    std::string& error, const apfsaccess::rw::BackupPhysicalWriteOwner::PostpublicationVerifier& verify)
{
    using Owner = apfsaccess::rw::BackupPhysicalWriteOwner;
    if (!c.backup_held || !c.backup_held->startup_admitted || !c.backup_held->source ||
        !c.backup_held->source->Current() || !c.tx_manager || !c.payload_spool || !c.metadata_store)
    { error = "BackupHeldPublicationOwnerMissing"; return {}; }
    const auto keeper = apfsaccess::rw::InspectHeldVolumeKeeperJournals(c.args.management_journal_directory,
        c.backup_held->held->Identity());
    if (!keeper.admitted) { error = "BackupHeldKeeperEvidenceUnsettled"; return {}; }
    const auto* cp = c.metadata_store->AuthoritativeAppleCheckpointView();
    if (!cp || !c.backup_held->source->MatchesCheckpoint(*cp))
    { error = "BackupHeldPublicationSelectionChanged"; return {}; }
    auto owner = Owner::Bind(c.backup_held->held, c.backup_held->held->Binding(),
        c.backup_held->held->InstanceId(), {cp->container.superblock.uuid_hex,
            cp->volumes.front().superblock.uuid_hex, c.args.volume_object_id, cp->container.superblock.xid},
        *c.tx_manager, *c.payload_spool, c.tx_journal_file, error);
    if (!owner) return {};
    return owner->PublishAcceptedForHost(error, verify, [&c](std::string_view) {
        const auto deadline = c.commit_deadline_tick_ms.load(std::memory_order_relaxed);
        if (!c.backup_held->source->Current()) return false;
        if (!deadline || GetTickCount64() <= deadline) return true;
        c.commit_timeout_latched.store(true, std::memory_order_relaxed); return false;
    });
}

// Tests may supply an already-held regular-file G08 model. The shipping call
// always obtains its authority from OpenExclusiveRaw's checked Windows owner.
bool PrepareBackupHeldMount(MountContext& c,
    std::shared_ptr<apfsaccess::rw::VolumePhysicalSource> supplied = {})
try
{
    using namespace apfsaccess;
    using namespace apfsaccess::rw;
    c.backup_held = std::make_unique<backup_held_mount::State>();
    auto& b = *c.backup_held;
    const auto refuse = [&](const char* reason) {
        if (b.error.empty()) b.error = reason;
        c.native_write_enabled = false; c.write_degraded = true; return false;
    };
    RawSnapshotBinding binding; std::wstring instance;
    if (!DecodeBackupHeldOption(c.args.backup_held, binding, instance, b.error)) return refuse("BackupHeldBindingInvalid");
    b.held = supplied ? std::move(supplied) : VolumePhysicalSource::OpenExclusiveRaw(binding, instance, b.error, c.args.device);
    if (!b.held || b.held->Binding() != binding || b.held->InstanceId() != instance || !b.held->Revalidate())
        return refuse("BackupHeldSourceUnavailable");
    const auto cp = catalog::LoadAppleCheckpointView(*b.held, 0, b.held->SizeBytes(), b.error);
    if (!cp || cp->volumes.size() != 1 || cp->container.superblock.uuid_hex != WideToUtf8(c.args.container_id) ||
        cp->container.superblock.xid != c.args.backup_held.checkpoint_xid ||
        cp->volumes.front().superblock.object_id != c.args.volume_object_id ||
        cp->volumes.front().superblock.uuid_hex != WideToUtf8(c.args.backup_held.volume_uuid))
        return refuse("BackupHeldSelectedCheckpointMismatch");
    b.source = BackupRetainedSource::HeldPhysical(b.held, binding, instance, *cp, c.args.volume_object_id, b.error);
    if (!b.source || b.source->RecoveryIdentity() != WideToUtf8(c.args.recovery_identity))
        return refuse("BackupHeldRecoveryIdentityMismatch");
    b.source_identity = b.held->Identity();
    const auto keeper = InspectHeldVolumeKeeperJournals(c.args.management_journal_directory, b.source_identity);
    if (!keeper.admitted) return refuse("BackupHeldKeeperEvidenceUnsettled");
    auto legacy_scan_args = c.args;
    legacy_scan_args.enable_raw_snapshots = true;
    const auto spool_base = PayloadSpool::ResolveDefaultRoot();
    const auto recovery_base = ResolveRecoveryRoot();
    if (spool_base.empty() || recovery_base.empty() ||
        FindAmbiguousLegacyRecoveryEvidence(legacy_scan_args, spool_base, recovery_base))
        return refuse("BackupHeldLegacyOriginalEvidenceAmbiguous");
    const auto root = BuildPayloadSpoolSessionRoot(c.args, spool_base);
    const auto keys = root / L"journal-keys";
    c.recovery_marker_file = BuildRecoveryMarkerPath(c.args);
    c.tx_journal_file = root / L"write-ahead.wal";
    auto evidence = std::make_unique<fshost::NativeRawSnapshotStartupEvidence>(
        fshost::RawSnapshotStartupEvidencePaths{c.recovery_marker_file.wstring(),
            (root / L"payload-spool.idx").wstring(), (root / L"payload-spool.bin").wstring()}, kBackupHeldSpoolMaxBytes);
    if (!evidence->Ready() || !b.source->Current()) return refuse("BackupHeldInitialCensusRefused");
    const auto attributes = GetFileAttributesW(c.tx_journal_file.c_str());
    const bool existing = attributes != INVALID_FILE_ATTRIBUTES;
    if (!existing && GetLastError() != ERROR_FILE_NOT_FOUND && GetLastError() != ERROR_PATH_NOT_FOUND)
        return refuse("BackupHeldOriginalExistenceUnproven");
    const auto key_attributes = GetFileAttributesW(keys.c_str());
    if (existing && (key_attributes == INVALID_FILE_ATTRIBUTES || !(key_attributes & FILE_ATTRIBUTE_DIRECTORY)))
        return refuse("BackupHeldExistingOriginalKeysAbsent");
    if (!existing)
    {
        fshost::RawSnapshotStartupEvidence empty;
        if (!evidence->Verify(empty) || empty.marker.present || empty.spool_index.present || empty.payload.present ||
            !b.source->Current() || !evidence->PrepareMissingParents())
            return refuse("BackupHeldAbsentOriginalParentCensusRefused");
    }
    // Pin the directory mapping without creating a sentinel or touching keys.
    b.key_parents = std::make_unique<fshost::NativeRawSnapshotStartupEvidence>(
        fshost::RawSnapshotStartupEvidencePaths{(keys / L".census-a").wstring(),
            (keys / L".census-b").wstring(), (keys / L".census-c").wstring()}, 4096);
    if (!b.key_parents->Ready() || !evidence->Verify() || !b.source->Current() ||
        !b.key_parents->PrepareMissingParents()) return refuse("BackupHeldKeyParentsUnproven");
    WriteAheadLog::ProtectedPersistence protection;
    protection.key_directory = keys;
    protection.source_binding = *b.source->JournalSourceBinding();
    const auto identity = "backup-held-original-v1:" + b.source->RecoveryIdentity();
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
        return refuse("BackupHeldJournalIdentityFailed");
    const auto hashed = BCryptHash(algorithm, nullptr, 0,
        reinterpret_cast<PUCHAR>(const_cast<char*>(identity.data())), static_cast<ULONG>(identity.size()),
        reinterpret_cast<PUCHAR>(protection.journal_identity.data()), static_cast<ULONG>(protection.journal_identity.size()));
    BCryptCloseAlgorithmProvider(algorithm, 0);
    if (hashed < 0) return refuse("BackupHeldJournalIdentityFailed");
    if (!b.source->Current()) return refuse("BackupHeldSourceChangedBeforeJournal");
    if (!evidence->Verify())
    {
        b.error = std::string("BackupHeldStartupEvidenceChanged:") + evidence->Failure() +
            ":Win32=" + std::to_string(evidence->Win32Error());
        return refuse("BackupHeldStartupEvidenceChanged");
    }
    c.tx_manager = std::make_unique<TransactionManager>(L"Strict");
    if (!c.tx_manager->OpenProtectedStartupJournal(c.tx_journal_file.wstring(), c.args.recovery_identity, protection, b.error) ||
        !c.tx_manager->EnrollCanonicalJournalIdentity(Utf8ToWide("apfs-vol:" + cp->container.superblock.uuid_hex +
            ":" + std::to_string(c.args.volume_object_id)))) return refuse("BackupHeldOriginalOpenFailed");
    b.census = fshost::BackupHeldOriginalCensus::Inspect(*b.source, *c.tx_manager, c.tx_journal_file,
        {c.recovery_marker_file.wstring(), (root / L"payload-spool.idx").wstring(), (root / L"payload-spool.bin").wstring()},
        kBackupHeldSpoolMaxBytes, cp->container.superblock.xid, b.error);
    if (!b.census || !evidence->Verify() || !b.key_parents->Verify() || !b.source->Current())
        return refuse("BackupHeldOriginalSuccessorCensusFailed");
    // The verified successor retains every original leaf and ancestor. Retire
    // the old marker reader before its successor requests exclusive write access.
    evidence.reset(); b.key_parents.reset();
    if (!b.census->PromoteForRecovery(b.error)) return refuse("BackupHeldOriginalPromotionFailed");
    c.payload_spool_volume_identity = b.source->RecoveryIdentity();
    c.payload_spool = std::make_unique<PayloadSpool>(PayloadSpool::Options{root, c.payload_spool_volume_identity,
        kBackupHeldSpoolMaxBytes, kPayloadSpoolForegroundFlushBytes, kPayloadSpoolForegroundFlushAppends, 8ull << 20, 32ull << 20});
    auto owner = BackupPhysicalWriteOwner::Bind(b.held, binding, instance,
        {cp->container.superblock.uuid_hex, cp->volumes.front().superblock.uuid_hex,
            c.args.volume_object_id, cp->container.superblock.xid}, *c.tx_manager, *c.payload_spool, c.tx_journal_file, b.error);
    if (!owner || !owner->Recover(b.error)) return refuse("BackupHeldOriginalRecoveryFailed");
    c.owned_metadata_store = owner->TakeVerifiedStore(b.error);
    c.metadata_store = c.owned_metadata_store.get();
    if (!c.metadata_store || !b.census->CompleteRecovery(c.metadata_store->CheckpointXid().value_or(0), b.error))
        return refuse("BackupHeldOriginalCompletionFailed");
    ConfigureBackupHeldProviders(c);
    b.startup_admitted = true;
    c.last_recovery_marker_dirty = false;
    c.last_recovery_marker_commit_xid = c.metadata_store->CheckpointXid();
    c.runtime_last_commit_xid = c.metadata_store->CheckpointXid();
    return true;
}
catch (...) { if (c.backup_held) c.backup_held->error = "BackupHeldStartupException"; return false; }
}
