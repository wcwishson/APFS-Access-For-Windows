namespace
{
int TransitionPlainEncryptionPrepare(const std::filesystem::path& run)
{
    const auto image = run / Profile{false}.Name();
    const auto before = DigestFile(image), original = DigestFile(run / L"original.wal"), witness = DigestFile(run / L"witness.wal");
    auto password = Receive(); std::string error;
    {
    const auto scope = TransitionScope(run); auto tx = TransitionTx(run, scope); Journal journal(scope.journal);
    auto source = std::make_shared<TransitionSource>(image);
    auto owners = journal.RestoreTransitionRetainedOwners(*tx, *source, error);
    Check(static_cast<bool>(owners), ("TransitionPlainEncryptionActualProtectedOwners:" + error).c_str());
    c::PasswordUnlockBudget budget;
    auto prepared = c::SoftwareVolumeTransition::PrepareEncryption(source, source->SourceIdentity(), source->Revision(), 1026,
        password, budget, *tx->ProtectedJournalIdentity(), owners.get(), error);
    password.Clear();
    Check(static_cast<bool>(prepared), ("TransitionPlainEncryptionAfterOrdinaryWrite:" + error).c_str());
    Check(prepared->BeforeMode() == c::SoftwareVolumeMode::Plain && prepared->AfterMode() == c::SoftwareVolumeMode::OneKeyGenerationZero &&
        prepared->Publication().expected_checkpoint_xid == 9 && prepared->Publication().transaction_xid == 10,
        "TransitionPlainEncryptionExactFollowingCheckpoint");
    Check(std::any_of(prepared->RetainedOwners().Generations().begin(), prepared->RetainedOwners().Generations().end(),
        [](const auto& generation) { return generation.checkpoint.superblock.xid == 8; }), "TransitionPlainEncryptionHistoricalPlainOwnerCaptured");
    }
    Check(DigestFile(image) == before && DigestFile(run / L"original.wal") == original && DigestFile(run / L"witness.wal") == witness,
        "TransitionPlainEncryptionPrepareNoPublicationOrJournalWrites");
    std::cout << "{\"plainWriteThenEncryptionPrepared\":true,\"preimageXid\":9,\"candidateXid\":10,\"historicalPlainOwners\":true,\"targetWrites\":0}\n";
    return 0;
}
int TransitionPlainEncryptionProbe(const std::filesystem::path& executable, const std::filesystem::path& run)
{
    auto password = RandomCredential();
    const auto log = run.parent_path() / (run.filename().wstring() + L"-" + executable.parent_path().parent_path().filename().wstring() +
        L"-" + executable.parent_path().filename().wstring() + L"-encryption-probe.log");
    const auto result = Child(executable, L"transition-plain-encrypt-prepare " + Quoted(run), password.Bytes(), log);
    Absent(log, password.Bytes(), password.Bytes()); password.Clear();
    std::cout << "{\"plainEncryptionProbeExit\":" << result << "}\n";
    return result;
}
int TransitionPlainCycleStep(const std::filesystem::path& run, unsigned step)
{
    const auto image = run / Profile{false}.Name(); auto password = Receive(); std::string error;
    const auto scope = TransitionScope(run); auto tx = TransitionTx(run, scope); Journal journal(scope.journal);
    std::uint64_t accepted = 0;
    if (step == 0) {
        {
            auto source = std::make_shared<TransitionSource>(image); c::PasswordUnlockBudget budget;
            auto owners = journal.RestoreTransitionRetainedOwners(*tx, *source, error);
            Check(static_cast<bool>(owners), ("TransitionPlainCycleEncryptionOwners:" + error).c_str());
            auto prepared = c::SoftwareVolumeTransition::PrepareEncryption(source, source->SourceIdentity(), source->Revision(), 1026,
                password, budget, *tx->ProtectedJournalIdentity(), owners.get(), error);
            Check(prepared && prepared->Publication().expected_checkpoint_xid == 9, ("TransitionPlainCycleEncryptionPrepare:" + error).c_str());
            const bool admitted = journal.AcceptTransition(*tx, *prepared, accepted, error);
            Check(admitted, ("TransitionPlainCycleEncryptionAccept:" + error).c_str());
            Check(journal.StageTransition(*tx, accepted, *prepared, error), ("TransitionPlainCycleEncryptionStage:" + error).c_str());
        }
        password.Clear();
        {
            TransitionJournalTarget target(image, scope);
            Check(journal.PublishOrRecover(*tx, accepted, target, error), ("TransitionPlainCycleEncryptionPublish:" + error).c_str());
        }
    } else {
        auto owner = c::ApfsEncryptedImageWriteSession::Open({image.wstring(), 20480, 4153344, 1026}, error);
        Check(static_cast<bool>(owner), ("TransitionPlainCycleFreshOwner:" + error).c_str());
        c::PasswordUnlockBudget budget;
        Check(owner->Unlock(password, budget, error), ("TransitionPlainCycleFreshCanonicalUnlock:" + error).c_str());
        const std::vector<std::byte> payload(22, std::byte{0x6B});
        if (step == 1) {
            Check(owner->CachedStatus().checkpoint_xid == 10, "TransitionPlainCycleDataPreimage");
            c::EncryptedMutationRequest request; request.kind = c::EncryptedMutationKind::Write;
            request.inode = 21; request.data = payload;
            auto prepared = owner->PrepareMutationWithTransitionRetention(*tx, journal, 10, request, error);
            Check(static_cast<bool>(prepared), ("TransitionPlainCycleFreshTypedDataPrepare:" + error).c_str());
            Tx::MutationIntent original; original.path = L"encrypted-data"; original.object_id = 21;
            original.length = original.payload_length = payload.size(); original.inline_payload = payload; original.payload_checksum = Sha(payload);
            Check(tx->ProtectedMutationCapacityAvailable(original, error) && tx->Begin() && tx->RecordMutation(original) &&
                tx->FlushPreparedRecords() && tx->Accept(10), ("TransitionPlainCycleActualDataAccept:" + error).c_str());
            ExitProcess(86);
        } else if (step == 2) {
            accepted = tx->Watermarks().accepted_sequence;
            const std::array<std::uint64_t, 1> pins{10};
            Check(owner->RecoverAcceptedMutationWithTransitionRetention(*tx, journal, accepted, {}, error, pins),
                ("TransitionPlainCycleFreshDataReplay:" + error).c_str());
            c::EncryptedReadError read{}; auto view = owner->OpenReadView(read); std::vector<std::byte> actual;
            Check(owner->CachedStatus().checkpoint_xid == 11 && view && view->ReadFile(21, 0, payload.size(), actual) == c::EncryptedReadError::None &&
                actual == payload, "TransitionPlainCycleFreshRecoveredDataExact");
            view->Close(); view.reset();
        } else {
            c::PasswordUnlockBudget decrypt_budget;
            Check(owner->Decrypt(*tx, journal, 11, password, decrypt_budget, accepted, error),
                ("TransitionPlainCycleFinalDecryption:" + error).c_str());
            Check(owner->CachedStatus().checkpoint_xid == 12 && !owner->CachedStatus().key_present,
                "TransitionPlainCycleFinalPlainKeyRevoked");
        }
        owner->Close(); password.Clear();
    }
    Check(accepted && tx->Watermarks().apfs_durable_sequence == accepted && tx->MarkCleanedThrough(accepted),
        "TransitionPlainCycleActualProtectedCleanup");
    std::cout << "{\"plainCycleStep\":" << step << ",\"accepted\":" << accepted << ",\"durable\":" << tx->Watermarks().apfs_durable_sequence
        << ",\"cleaned\":" << tx->Watermarks().cleanup_sequence << "}\n"; return 0;
}
int TransitionPlainCycleDriver(const std::filesystem::path& executable, const std::filesystem::path& run)
{
    Check(TransitionPlainStoreDriver(executable, run) == 0, "TransitionPlainCycleProtectedPlainPrefix");
    auto fresh = RandomCredential(), old = NoteCredential(Profile{false});
    Check(Child(executable, L"transition-plain-cycle-encrypt " + Quoted(run), fresh.Bytes(), run / L"cycle-encrypt.log") == 0,
        "TransitionPlainCycleActualEncryption");
    Check(Child(executable, L"transition-data-encrypted-oracle " + Quoted(run), fresh.Bytes(), run / L"cycle-encrypt-oracle.log") == 0,
        "TransitionPlainCycleIndependentEncryptionSixFiles");
    Check(Child(executable, L"transition-old-oracle " + Quoted(run), old.Bytes(), run / L"cycle-old-password-oracle.log") == 0,
        "TransitionPlainCycleIndependentOldCredentialRefused");
    {
        std::ifstream before(run / L"expected-plain-write-files.txt"); std::ofstream after(run / L"expected-after-encrypted-write-files.txt");
        std::string magic; std::size_t count = 0; before >> magic >> count;
        Check(before && magic == "E06FILES1" && count == 6, "TransitionPlainCyclePlainInventory");
        after << magic << '\n' << count << '\n'; const std::vector<std::byte> payload(22, std::byte{0x6B});
        for (std::size_t i = 0; i < count; ++i) {
            ExpectedFile file; before >> file.inode >> file.bytes >> file.sha256;
            Check(static_cast<bool>(before), "TransitionPlainCycleSiblingInventory");
            after << file.inode << ' ' << file.bytes << ' ' << (file.inode == 21 ? Digest(payload) : file.sha256) << '\n';
        }
        Check(static_cast<bool>(after), "TransitionPlainCycleExpectedChangedPayload");
    }
    Check(Child(executable, L"transition-plain-cycle-data-cut " + Quoted(run), fresh.Bytes(), run / L"cycle-data-cut.log") == 86,
        "TransitionPlainCycleGenuineBeforeStageDataExit");
    Check(Child(executable, L"transition-plain-cycle-data-replay " + Quoted(run), fresh.Bytes(), run / L"cycle-data-replay.log") == 0,
        "TransitionPlainCycleFreshDataRecovery");
    Check(Child(executable, L"transition-cycle-data-oracle " + Quoted(run), fresh.Bytes(), run / L"cycle-data-oracle.log") == 0,
        "TransitionPlainCycleIndependentChangedEncryptedFiles");
    Check(Child(executable, L"transition-plain-cycle-decrypt " + Quoted(run), fresh.Bytes(), run / L"cycle-decrypt.log") == 0,
        "TransitionPlainCycleActualFinalDecrypt");
    Check(Child(executable, L"transition-cycle-plain-oracle " + Quoted(run), {}, run / L"cycle-final-plain-oracle.log") == 0,
        "TransitionPlainCycleIndependentFinalPlainFiles");
    for (const auto& file : std::filesystem::recursive_directory_iterator(run)) if (file.is_regular_file()) Absent(file.path(), old.Bytes(), fresh.Bytes());
    Check(DigestFile(std::filesystem::path(fixtures) / Profile{false}.Name()) == Profile{false}.Pin(), "TransitionPlainCycleOriginalPreserved");
    std::cout << "TRANSITION_PLAIN_WRITE_ENCRYPT_FRESH_DATA_RECOVERY_DECRYPT_PASS\n"; return 0;
}
}
