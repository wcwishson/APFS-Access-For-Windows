bool TestNativeLowSpaceRefusalMapping()
{
    using Status = apfsaccess::rw::MetadataStore::CommitStatus;
    using Staging = apfsaccess::rw::MetadataStore::MutationStatus;
    ManifestCommitOutcome outcome;
    outcome.clean_prepublication_refusal = true;
    outcome.status = Status::CapacityBlocked;
    if (!Require(CleanManifestRefusalStatus(outcome) == STATUS_DISK_FULL,
            "typed clean planner capacity maps to DiskFull")) return false;
    outcome.status = Status::NotReady;
    outcome.mutation_staging_status = Staging::AllocationFailed;
    if (!Require(CleanManifestRefusalStatus(outcome) == STATUS_DISK_FULL,
            "typed clean extent allocation refusal maps to DiskFull")) return false;
    outcome.mutation_staging_status.reset();
    outcome.status = Status::InvariantFailed;
    outcome.error = "CommitCapacityAdmissionRefused: AppleCommitPlanFailed | ";
    if (!Require(CleanManifestRefusalStatus(outcome) == STATUS_UNSUCCESSFUL,
            "generic planner failure cannot become DiskFull from its error text")) return false;
    outcome.error = "ApplePreparedPlanSourceChanged";
    if (!Require(CleanManifestRefusalStatus(outcome) == STATUS_UNSUCCESSFUL,
            "source invariant cannot enter the retryable capacity shortcut")) return false;
    for (unsigned evidence = 0; evidence < 3; ++evidence)
    {
        outcome.status = Status::CapacityBlocked;
        outcome.clean_prepublication_refusal = evidence != 0;
        outcome.recovery_required = evidence == 1;
        outcome.accepted_without_publication = evidence == 2;
        if (!Require(CleanManifestRefusalStatus(outcome) == STATUS_UNSUCCESSFUL,
                "missing clean proof, recovery or accepted work excludes retryable classification")) return false;
    }
    return true;
}

bool TestNativeLowSpaceOriginalDebtLatch()
{
    using Status = apfsaccess::rw::MetadataStore::CommitStatus;
    using TM = apfsaccess::rw::TransactionManager;
    for (const auto status : {Status::CapacityBlocked, Status::RetentionBlocked, Status::PersistFailed})
    {
        for (const unsigned evidence : {0u, 1u, 2u})
        {
            MountContext context;
            if (!Require(ConfigureNativeCommitFailureForUnitTest(context), "RW engine is required for low-space host gate") ||
                !Require(std::filesystem::temp_directory_path().root_name() == L"D:", "low-space test evidence stays on D") ||
                !Require(PrepareUnitHydrationRoot(context, L"low-space-debt") &&
                    ConfigureUnitRecoveryMarker(context, L"low-space-debt"), "private low-space evidence paths")) return false;
            context.test_forced_native_commit_status = status;
            context.test_forced_native_commit_recovery_reason.clear();
            context.test_forced_native_commit_recovery_required = evidence == 1;
            context.test_forced_native_mutations_pending = true;
            context.pending_native_writes = true;
            context.tx_manager = std::make_unique<TM>(L"Strict");
            context.tx_manager->SetVolumeIdentity(L"low-space-host-original");
            const auto wal = context.session_root / "original.wal";
            context.tx_manager->SetJournalPath(wal.wstring());
            if (evidence == 2)
            {
                TM::MutationIntent intent;
                intent.kind = TM::MutationKind::CreateFile;
                intent.path = L"\\accepted-before-capacity.bin";
                intent.object_id = 1002;
                intent.generation = 7;
                if (!Require(context.tx_manager->Begin() && context.tx_manager->RecordMutation(intent) &&
                        context.tx_manager->Accept(7) && context.tx_manager->HasUnappliedAcceptedWork(),
                        "real original WAL acceptance precedes host failure classification")) return false;
            }
            const auto original = ReadFileBytes(wal);
            const auto marks = context.tx_manager->Watermarks();
            const auto result = CommitNativeMutationsBestEffort(&context, L"LowSpaceOriginalDebt");
            const bool retryable = evidence == 0 && status != Status::PersistFailed;
            if (retryable)
            {
                if (!Require(result == (status == Status::CapacityBlocked ? STATUS_DISK_FULL : STATUS_DEVICE_BUSY) &&
                        context.native_write_enabled && !context.write_degraded && !context.recovery_active,
                        "clean typed pressure retains RW admission")) return false;
            }
            else
            {
                RecoveryMarkerState marker;
                if (!Require(!NT_SUCCESS(result) && context.write_degraded && context.recovery_active &&
                        !context.native_write_enabled && !context.overlay_write_enabled &&
                        TryLoadRecoveryMarkerState(context.recovery_marker_file, marker) && marker.dirty,
                        "publication, reported recovery and real original debt preserve the failure latch")) return false;
            }
            const auto after = context.tx_manager->Watermarks();
            if (!Require(ReadFileBytes(wal) == original && after.accepted_sequence == marks.accepted_sequence &&
                    after.apfs_durable_sequence == marks.apfs_durable_sequence && after.cleanup_sequence == marks.cleanup_sequence &&
                    context.tx_manager->HasUnappliedAcceptedWork() == (evidence == 2),
                    "host classification neither retires nor fabricates original recovery evidence")) return false;
        }
    }
    return true;
}
