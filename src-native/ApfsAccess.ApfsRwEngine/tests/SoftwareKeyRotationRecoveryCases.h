namespace
{
int RotationRecoveryPrepare(const std::filesystem::path& run, std::wstring_view cut)
{
    auto pair = ReceivePair(); const auto scope = TransitionScope(run); auto tx = TransitionTx(run, scope);
    if (!cut.empty()) tx->SetFaultInjectionHook([cut](const std::string& stage) {
        if ((cut == L"authorization" && stage == "transition-after-private-authorization") ||
            (cut == L"prefix" && stage == "transition-after-original-prepared-chunk")) ExitProcess(86);
    });
    Journal journal(scope.journal); std::string error; std::uint64_t accepted = 0;
    auto source = std::make_shared<TransitionSource>(run / Profile{false}.Name());
    c::PasswordUnlockBudget budget;
    auto prepared = c::SoftwareVolumeKeyRotation::Prepare(source, source->SourceIdentity(), source->Revision(),
        1026, pair.old_password, pair.new_password, budget, scope.original.journal_identity, nullptr, error);
    Check(static_cast<bool>(prepared), ("V8RecoveryGenuinePrivatePlan:" + error).c_str());
    {
        std::ofstream out(run / L"rotation-switch-block.txt"); out << prepared->Publication().superblock_write.physical_block;
        Check(static_cast<bool>(out), "V8RecoveryNonsecretFaultLocation");
        std::ofstream bytes(run / L"rotation-planned-nxsb.bin", std::ios::binary);
        const auto& block = prepared->Publication().superblock_write.bytes;
        bytes.write(reinterpret_cast<const char*>(block.data()), static_cast<std::streamsize>(block.size()));
        Check(static_cast<bool>(bytes), "V8RecoveryCaptureActualPlannedCiphertextSwitch");
    }
    Check(journal.AcceptKeyRotation(*tx, *prepared, accepted, error), ("V8RecoveryPrivateAcceptance:" + error).c_str());
    Check(accepted && !tx->Watermarks().apfs_durable_sequence, "V8RecoveryActualAcceptedBeforeStage");
    return 0;
}

int RotationRecoveryPublish(const std::filesystem::path& run, std::wstring_view cut)
{
    const auto image = run / Profile{false}.Name(), wal = run / L"original.wal", witness = run / L"witness.wal";
    const auto image_before = DigestFile(image), wal_before = DigestFile(wal), witness_before = DigestFile(witness);
    const auto scope = TransitionScope(run); auto tx = TransitionTx(run, scope); Journal journal(scope.journal);
    std::string error; const auto accepted = tx->Watermarks().accepted_sequence;
    const auto staged = journal.RestageKeyRotation(*tx, accepted, error);
    if (cut == L"negative") {
        Check(!staged && !tx->Watermarks().apfs_durable_sequence, "V8RecoveryRefusalHasNoDurableTarget");
        tx.reset();
        Check(DigestFile(image) == image_before &&
            DigestFile(wal) == wal_before && DigestFile(witness) == witness_before, "V8RecoveryRefusalPreservesAllThree");
        std::cout << "{\"v8TornNegative\":true,\"targetCalls\":0,\"allBytesPreserved\":true}\n"; return 0;
    }
    Check(staged, ("V8RecoveryAuthenticatedRestage:" + error).c_str());
    bool reached = false;
    {
        TransitionJournalTarget target(image, scope);
        const auto hook = [&](std::string_view stage) {
            if ((cut == L"data" && stage == "before-apple-checkpoint-switch") ||
                (cut == L"watermark" && stage == "before-apple-final-flush")) { reached = true; return false; }
            return true;
        };
        const auto published = journal.PublishOrRecover(*tx, accepted, target, error, hook);
        if (!cut.empty()) {
            Check(!published && reached && target.calls && !tx->Watermarks().apfs_durable_sequence,
                "V8RecoveryActualPublicationFailureCut"); return 0;
        }
        Check(published && tx->MarkCleanedThrough(accepted), ("V8RecoveryCanonicalPublication:" + error).c_str());
    }
    auto source = std::make_shared<TransitionSource>(image);
    auto owners = journal.RestoreTransitionRetainedOwners(*tx, *source, error);
    auto cp = c::LoadContainerCheckpointView(*source, 0, source->SizeBytes(), error);
    Check(owners && cp && cp->superblock.xid == 8 && tx->Watermarks().cleanup_sequence == accepted &&
        tx->Watermarks().apfs_durable_sequence == accepted, "V8RecoveryProtectedOwnersAndCleanPublishedEndpoint");
    std::cout << "{\"v8Recovered\":true,\"checkpoint\":8,\"accepted\":" << accepted << ",\"clean\":true}\n"; return 0;
}

void RotationRecoveryWitnessFault(const std::filesystem::path& run, std::wstring_view mode,
    const std::filesystem::path& witness_path = {}, std::uint64_t selected_offset = 0)
{
    const auto path = witness_path.empty() ? run / L"witness.wal" : witness_path;
    std::ifstream input(path, std::ios::binary); std::vector<std::byte> bytes(static_cast<std::size_t>(std::filesystem::file_size(path)));
    input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    Check(static_cast<bool>(input), "V8RecoveryReadActualWitnessBytes"); input.close();
    struct Frame { std::size_t offset, size; }; std::vector<Frame> frames;
    for (std::size_t at = 16; at < bytes.size();) {
        const auto size = c::ReadU32LE(bytes, at + 16).value_or(0);
        Check(bytes.size() - at >= 64 && std::memcmp(bytes.data() + at, "APFSREC1", 8) == 0 && size >= 80 && size <= bytes.size() - at,
            "V8RecoveryActualProtectedFrames"); frames.push_back({at, size}); at += size;
    }
    Check(frames.size() > 8, "V8RecoveryCompletePrivateWitnessFrames");
    std::size_t selected = 1;
    if (selected_offset) {
        while (selected < frames.size() && frames[selected].offset != selected_offset) ++selected;
        Check(selected + 2 < frames.size(), "V8RecoverySelectedGroupStartsAfterExactOldHistory");
    }
    if (mode == L"bad-tag") {
        std::fstream out(path, std::ios::in | std::ios::out | std::ios::binary); const char byte = static_cast<char>(std::to_integer<unsigned>(bytes.back()) ^ 1u);
        out.seekp(-1, std::ios::end); out.write(&byte, 1); Check(static_cast<bool>(out), "V8RecoveryActualBadTagInjection");
    } else {
        std::size_t index = mode == L"first" ? selected + 1 : mode == L"middle" ? (selected + frames.size()) / 2 : frames.size() - 1;
        if (mode == L"missing-certificate") index = selected;
        const auto prefix = mode == L"first" ? std::size_t{1} : frames[index].size / 2;
        std::filesystem::resize_file(path, frames[index].offset + prefix);
    }
}

int RotationRecoveryBindingControls(const std::filesystem::path& run)
{
    const auto image = run / Profile{false}.Name(), wal = run / L"original.wal", witness = run / L"witness.wal";
    const auto image_before = DigestFile(image), original_before = DigestFile(wal), witness_before = DigestFile(witness);
    const auto scope = TransitionScope(run); std::string error;
    auto tx = TransitionTx(run, scope); const auto accepted = tx->Watermarks().accepted_sequence;
    for (unsigned mode = 0; mode < 3; ++mode) {
        auto changed = scope.journal;
        if (!mode) changed.preimage_source_identity += ":substituted";
        else if (mode == 1) changed.maintenance_original_journal_identity.front() ^= std::byte{1};
        else ++changed.volume_object_id;
        Journal wrong(changed);
        Check(!wrong.RestageKeyRotation(*tx, accepted, error) && !tx->Watermarks().apfs_durable_sequence,
            "V8ActualSourceOriginalJidAndVolumeSubstitutionRefused");
    }
    std::vector<Tx::AcceptedTransaction> groups;
    Check(tx->LoadAcceptedTransactionsSinceCleanup(groups, &error) && groups.size() == 1, "V8M2ActualAcceptedOriginal");
    std::vector<std::byte> blob;
    for (const auto& row : groups.front().mutations) blob.insert(blob.end(), row.inline_payload.begin(), row.inline_payload.end());
    std::size_t nx_at = 0; unsigned candidates = 0;
    for (std::size_t at = 0; at + 4096 <= blob.size(); ++at) {
        if (c::ReadU32LE(blob, at + 32) != c::kNxsbMagic || c::ReadU64LE(blob, at + 16) != 8) continue;
        const std::vector<std::byte> bytes(blob.begin() + at, blob.begin() + at + 4096);
        const auto nx = c::ParseNxSuperblock(bytes);
        if (nx && nx->uuid_hex == scope.journal.container_uuid) { nx_at = at; ++candidates; }
    }
    Check(candidates == 1, "V8M2ExactActualPublishedNxsbLocated");
    std::vector<std::byte> changed_nx(blob.begin() + nx_at, blob.begin() + nx_at + 4096);
    changed_nx.back() ^= std::byte{1};
    Check(r::FinalizeAppleObjectChecksum(changed_nx, error) && c::ParseNxSuperblock(changed_nx).has_value(),
        "V8M2ChangedNxsbStillAuthenticFormatAndChecksum");
    std::copy(changed_nx.begin(), changed_nx.end(), blob.begin() + nx_at);
    const auto original_jid = tx->ProtectedJournalIdentity();
    const auto original_binding = tx->ProtectedSourceBinding();
    tx.reset();
    auto other = std::make_unique<Tx>(L"Conservative");
    auto other_protection = scope.original; other_protection.key_directory = run / L"other-original-keys";
    Check(std::filesystem::create_directory(other_protection.key_directory), "V8M2IndependentProtectedControlKeys");
    const auto opened = other->OpenProtectedJournal((run / L"other-original.wal").wstring(), scope.volume, other_protection, error);
    Check(opened, ("V8M2IndependentOriginalOpen:" + error + ":win32=" + std::to_string(GetLastError())).c_str());
    Check(other->ProtectedJournalIdentity() == original_jid && other->ProtectedSourceBinding() == original_binding && other->Begin(),
        "V8M2ExactSourceAndJidAttackControl");
    std::size_t offset = 0;
    for (const auto& row : groups.front().mutations) {
        Check(row.path_utf8 == "\\$apfs-software-key-rotation-v1", "V8M2ActualRotationSentinel");
        Tx::MutationIntent mutation; mutation.path = L"\\$apfs-software-key-rotation-v1"; mutation.object_id = row.object_id;
        mutation.generation = row.parent_object_id; mutation.offset = row.logical_offset;
        mutation.length = mutation.payload_length = row.inline_payload.size();
        mutation.inline_payload.assign(blob.begin() + offset, blob.begin() + offset + row.inline_payload.size());
        mutation.payload_checksum = Sha(mutation.inline_payload);
        Check(other->RecordMutation(mutation) && other->FlushPreparedRecords(), "V8M2RealAuthenticatedAlteredOriginalChunks");
        offset += row.inline_payload.size();
    }
    Check(other->Accept(7) && other->Watermarks().accepted_sequence == accepted, "V8M2ExactAcceptedBoundary");
    Journal journal(scope.journal);
    Check(!journal.RestageKeyRotation(*other, accepted, error), "V8M2FullPrivateAuthorizationRejectsAlteredOriginal");
    const auto full = run / L"m2-full-private-authorization.wal";
    Check(CopyFileW(witness.c_str(), full.c_str(), TRUE), "V8M2PreservePrivateAuthorizationBeforeTear");
    RotationRecoveryWitnessFault(run, L"first");
    const auto torn = DigestFile(witness);
    Check(!journal.RestageKeyRotation(*other, accepted, error) && DigestFile(witness) == torn &&
        !other->Watermarks().apfs_durable_sequence, "V8M2FirstPrivateCertificateCannotAuthorizeDifferentOriginal");
    Check(CopyFileW(witness.c_str(), (run / L"m2-torn-private-authorization.wal").c_str(), TRUE) &&
        CopyFileW(full.c_str(), witness.c_str(), FALSE), "V8M2RestoreOnlyUnchangedInjectedTear");
    other.reset(); tx.reset();
    Check(DigestFile(image) == image_before && DigestFile(wal) == original_before && DigestFile(witness) == witness_before,
        "V8BindingAndM2ControlsPreserveCanonicalAllBytes");
    std::cout << "{\"v8SourceJidVolumeRefused\":true,\"m2ValidNxsbChecksum\":true,\"m2SameOriginalJidAndSource\":true,"
        "\"m2FullAndTornPrivateAuthorizationRefused\":true,\"targetCalls\":0,\"allCanonicalBytesPreserved\":true}\n";
    return 0;
}

int RotationRetainedHistoryDriver(const std::filesystem::path& executable, const std::filesystem::path& run)
{
    Check(run.wstring().starts_with(std::wstring(transition_root) + L"\\run-") && std::filesystem::create_directory(run),
        "V8RetainedHistoryPrivateRun");
    const auto original = std::filesystem::path(fixtures) / Profile{false}.Name(), image = run / Profile{false}.Name();
    Check(DigestFile(original) == Profile{false}.Pin() && CopyFileW(original.c_str(), image.c_str(), TRUE),
        "V8RetainedHistoryAuthenticOriginal");
    auto old = NoteCredential(Profile{false}), middle = RandomCredential(), latest = RandomCredential();
    auto first_pair = Pair(old.Bytes(), middle.Bytes()), second_pair = Pair(middle.Bytes(), latest.Bytes());
    Check(Child(executable, L"key-rotation-accept-cut " + Quoted(run), first_pair.Bytes(), run / L"first-accept.log") == 86 &&
        Child(executable, L"key-rotation-fresh-unlock " + Quoted(run), middle.Bytes(), run / L"first-recover.log") == 0,
        "V8RetainedHistoryFirstActualPublicRotation");
    const auto witness = run / L"runtime" / L"witness.wal", wal = run / L"runtime" / L"original.wal";
    const auto old_bytes = std::filesystem::file_size(witness);
    Check(CopyFileW(witness.c_str(), (run / L"first-complete-witness.wal").c_str(), TRUE), "V8RetainedHistoryKeepPriorCertificate");
    Check(Child(executable, L"key-rotation-next-accept-cut " + Quoted(run), second_pair.Bytes(), run / L"second-accept.log") == 86,
        "V8RetainedHistorySecondActualPublicRotationAcceptance");
    const auto full = run / L"second-complete-witness.wal";
    Check(CopyFileW(witness.c_str(), full.c_str(), TRUE), "V8RetainedHistoryKeepSecondCompleteAuthorization");
    for (const auto negative : {L"missing-certificate", L"bad-tag"}) {
        RotationRecoveryWitnessFault(run, negative, witness, old_bytes);
        const auto image_before = DigestFile(image), wal_before = DigestFile(wal), witness_before = DigestFile(witness);
        Check(Child(executable, L"key-rotation-missing-auth " + Quoted(run), latest.Bytes(), run / (std::wstring(negative) + L".log")) == 0 &&
            DigestFile(image) == image_before && DigestFile(wal) == wal_before && DigestFile(witness) == witness_before,
            "V8RetainedHistoryMissingNewCertificateAndFullBadTagPreserveEverything");
        Check(CopyFileW(witness.c_str(), (run / (std::wstring(negative) + L".wal")).c_str(), TRUE) &&
            CopyFileW(full.c_str(), witness.c_str(), FALSE), "V8RetainedHistoryPreserveAndRestoreOnlyInjectedControl");
    }
    RotationRecoveryWitnessFault(run, L"first", witness, old_bytes);
    const auto torn_hash = DigestFile(witness);
    Check(CopyFileW(witness.c_str(), (run / L"second-proper-eof.wal").c_str(), TRUE), "V8RetainedHistoryPreserveActualTornPredecessor");
    Check(Child(executable, L"key-rotation-next-fresh-unlock " + Quoted(run), latest.Bytes(), run / L"second-torn-recovery.log") == 0,
        "V8RetainedHistoryFreshPublicUnlockRepairsSelectedTear");
    bool archive = false;
    for (const auto& file : std::filesystem::directory_iterator(run / L"runtime"))
        if (file.path().filename().wstring().starts_with(L"witness.wal.wrsaved.") && DigestFile(file.path()) == torn_hash) archive = true;
    Check(archive, "V8RetainedHistoryExactRawPredecessorArchiveSurvives");
    Check(Child(executable, L"transition-encrypted-oracle " + Quoted(run), latest.Bytes(), run / L"latest-oracle.log") == 0 &&
        Child(executable, L"transition-old-oracle " + Quoted(run), old.Bytes(), run / L"original-refusal.log") == 0 &&
        Child(executable, L"transition-old-oracle " + Quoted(run), middle.Bytes(), run / L"intermediate-refusal.log") == 0,
        "V8RetainedHistoryIndependentLatestAndBothOldCredentialRules");
    Check(Child(executable, L"key-rotation-next-following-data " + Quoted(run), latest.Bytes(), run / L"fresh-following-data.log") == 0 &&
        Child(executable, L"transition-data-encrypted-oracle " + Quoted(run), latest.Bytes(), run / L"following-data-oracle.log") == 0,
        "V8RetainedHistoryFreshActualDataUsesRestoredOwners");
    for (const auto& file : std::filesystem::recursive_directory_iterator(run)) if (file.is_regular_file()) {
        Absent(file.path(), old.Bytes(), middle.Bytes()); Absent(file.path(), latest.Bytes(), latest.Bytes());
    }
    Check(DigestFile(original) == Profile{false}.Pin(), "V8RetainedHistoryOriginalStillPinned");
    std::cout << "V8_RETAINED_HISTORY_PUBLIC_TORN_RECOVERY_AND_FRESH_DATA_PASS\n"; return 0;
}

int RotationRecoveryMatrix(const std::filesystem::path& executable, const std::filesystem::path& run, std::wstring_view only = {})
{
    Check(run.wstring().starts_with(std::wstring(transition_root) + L"\\run-") && std::filesystem::create_directory(run), "V8RecoveryPrivateMatrixRoot");
    const auto original = std::filesystem::path(fixtures) / Profile{false}.Name();
    auto old = NoteCredential(Profile{false}), fresh = RandomCredential(); auto pair = Pair(old.Bytes(), fresh.Bytes());
    unsigned cases = 0;
    for (const auto mode : {L"authorization", L"prefix", L"first", L"middle", L"final", L"data", L"watermark", L"switch", L"controls"}) {
        if (!only.empty() && only != mode) continue;
        ULARGE_INTEGER free{}; Check(GetDiskFreeSpaceExW(L"D:\\", &free, nullptr, nullptr) && free.QuadPart >= (150ull + 8) * 1024 * 1024,
            "V8RecoverySharedReserveBeforeEachCase");
        const auto test = run / mode; Check(std::filesystem::create_directory(test), "V8RecoveryPrivateCase");
        Check(CopyFileW(original.c_str(), (test / Profile{false}.Name()).c_str(), TRUE) &&
            std::filesystem::create_directory(test / L"original-keys") && std::filesystem::create_directory(test / L"witness-keys"), "V8RecoveryAuthenticCaseCopy");
        // The target helper confines writes to run-* paths; each case is itself one.
        const auto case_path = std::filesystem::path(transition_root) / (run.filename().wstring() + L"-" + mode);
        Check(MoveFileW(test.c_str(), case_path.c_str()), "V8RecoveryBoundedSiblingCase");
        const bool preaccept = std::wstring_view(mode) == L"authorization" || std::wstring_view(mode) == L"prefix";
        const auto prepare = preaccept ? L"v8-recovery-prepare-" + std::wstring(mode) : std::wstring(L"v8-recovery-prepare");
        Check(Child(executable, prepare + L" " + Quoted(case_path), pair.Bytes(), case_path / L"prepare.log") == (preaccept ? 86 : 0), "V8RecoveryActualPrivateCutOrAcceptance");
        if (preaccept) {
            Check(DigestFile(case_path / Profile{false}.Name()) == Profile{false}.Pin(), "V8RecoveryPreacceptNeverWritesImage");
            Check(Child(executable, L"v8-recovery-dispose " + Quoted(case_path), {}, case_path / L"dispose.log") == 0, "V8RecoveryFreshDispositionWithoutCredential");
            Check(Child(executable, L"v8-recovery-prepare " + Quoted(case_path), pair.Bytes(), case_path / L"next-accept.log") == 0,
                "V8RecoveryDispositionAllowsNextGenuineRotation");
        } else if (std::wstring_view(mode) == L"first" || std::wstring_view(mode) == L"middle" || std::wstring_view(mode) == L"final") {
            const auto full = case_path / L"witness-before-tear.wal";
            Check(CopyFileW((case_path / L"witness.wal").c_str(), full.c_str(), TRUE), "V8RecoveryPreserveFullAuthorization");
            if (std::wstring_view(mode) == L"first") for (const auto negative : {L"missing-certificate", L"bad-tag"}) {
                RotationRecoveryWitnessFault(case_path, negative);
                Check(Child(executable, L"v8-recovery-negative " + Quoted(case_path), {}, case_path / (std::wstring(negative) + L".log")) == 0,
                    "V8RecoveryMissingCertificateAndBadTagRefuse");
                Check(CopyFileW((case_path / L"witness.wal").c_str(), (case_path / (std::wstring(negative) + L".wal")).c_str(), TRUE) &&
                    CopyFileW(full.c_str(), (case_path / L"witness.wal").c_str(), FALSE), "V8RecoveryPreserveAndRestoreOnlyInjectedWitness");
            }
            RotationRecoveryWitnessFault(case_path, mode);
            Check(CopyFileW((case_path / L"witness.wal").c_str(), (case_path / L"witness-torn-predecessor.wal").c_str(), TRUE), "V8RecoveryPreserveActualTornPredecessor");
        } else if (std::wstring_view(mode) == L"controls") {
            Check(Child(executable, L"v8-recovery-binding-controls " + Quoted(case_path), {}, case_path / L"binding-controls.log") == 0,
                "V8RecoveryActualBindingAndM2Controls");
        } else {
            const auto cut = std::wstring_view(mode) == L"switch" ? std::wstring(L"data") : std::wstring(mode);
            Check(Child(executable, L"v8-recovery-cut-" + cut + L" " + Quoted(case_path), {}, case_path / L"publication-cut.log") == 0,
                "V8RecoveryActualDataOrLostWatermarkCut");
            if (std::wstring_view(mode) == L"switch") {
                std::uint64_t block = 0; std::ifstream location(case_path / L"rotation-switch-block.txt"); location >> block;
                std::vector<std::byte> planned(4096); std::ifstream bytes(case_path / L"rotation-planned-nxsb.bin", std::ios::binary);
                bytes.read(reinterpret_cast<char*>(planned.data()), 4096);
                Check(location && bytes && block, "V8RecoveryActualTornSwitchScope");
                const auto scope = TransitionScope(case_path); TransitionJournalTarget target(case_path / Profile{false}.Name(), scope);
                std::vector<std::byte> before; Check(target.ReadBlock(block, 4096, before) && before.size() == 4096,
                    "V8RecoveryTornSwitchOldDestinationRead");
                std::copy_n(planned.begin(), 1024, before.begin());
                Check(!c::VerifyObjectChecksum(before, 4096) && target.WriteBlock(block, before) && target.Flush(),
                    "V8RecoveryActualTornChecksummedNxsbInjection");
            }
        }
        Check(Child(executable, L"v8-recovery-publish " + Quoted(case_path), {}, case_path / L"recovery.log") == 0, "V8RecoveryFreshKeylessPublication");
        // Independent reader checks use a full inventory captured from the original source.
        Check(Child(executable, L"v8-recovery-manifest " + Quoted(case_path), old.Bytes(), case_path / L"manifest.log") == 0,
            "V8RecoveryIndependentOriginalInventory");
        Check(Child(executable, L"transition-encrypted-oracle " + Quoted(case_path), fresh.Bytes(), case_path / L"new-oracle.log") == 0 &&
            Child(executable, L"transition-old-oracle " + Quoted(case_path), old.Bytes(), case_path / L"old-oracle.log") == 0,
            "V8RecoveryIndependentCredentialAndCompletePayloadOracle");
        for (const auto& file : std::filesystem::recursive_directory_iterator(case_path)) if (file.is_regular_file()) Absent(file.path(), old.Bytes(), fresh.Bytes());
        ++cases;
    }
    Check(DigestFile(original) == Profile{false}.Pin(), "V8RecoveryPreserveAuthenticOriginal");
    std::cout << "V8_PREACCEPT_TORN_DATA_WATERMARK_MATRIX_PASS cases=" << cases << '\n'; return 0;
}

int ObserveGenuineKeybagProfiles()
{
    for (const bool native : {false, true}) {
        const Profile profile{native}; const auto path = std::filesystem::path(fixtures) / profile.Name();
        auto lease = std::make_shared<t::WindowsImageLease>(path.wstring());
        auto source = std::make_shared<t::OwnedEncryptedImageSource>(lease, profile.Base(), profile.Size());
        std::string error; auto cp = c::LoadContainerCheckpointView(*source, 0, source->SizeBytes(), error);
        auto volumes = cp ? c::LoadAppleReadOnlyVolumeView(*source, *cp, error) : std::nullopt;
        Check(volumes && volumes->volumes.size() == 1, "ConstructionProfileGenuineCanonicalVolume");
        c::UnlockError reason{}; std::uint64_t container_block = 0, volume_block = 0;
        auto bags = c::InspectPasswordKeybagMetadataAtCheckpoint(*source, volumes->volumes.front().superblock.object_id,
            c::KeybagLength::IncludesHeader, cp->superblock.xid, reason, container_block, volume_block);
        Check(bags && bags->users.size() == 1, "ConstructionProfileCanonicalAuthenticatedBags");
        std::vector<std::byte> raw; Check(source->Read(container_block * 4096, 4096, raw), "ConstructionProfileContainerRead");
        auto container = c::DecryptApfsUuidKeybagBlock(bags->selection.container_uuid, container_block, raw);
        Check(source->Read(volume_block * 4096, 4096, raw), "ConstructionProfileVolumeRead");
        auto volume = c::DecryptApfsUuidKeybagBlock(bags->selection.volume_uuid, volume_block, raw);
        Check(container && volume && c::VerifyObjectChecksum(container.bytes.Bytes(), 4096) &&
            c::VerifyObjectChecksum(volume.bytes.Bytes(), 4096), "ConstructionProfileRealChecksummedObjects");
        const auto [vek_at, vek_bytes] = ExistingBagRecord(container.bytes.Bytes(), bags->selection.volume_uuid, 2);
        const auto [kek_at, kek_bytes] = ExistingBagRecord(volume.bytes.Bytes(), bags->users.front(), 3);
        auto observed = c::ObserveSoftwareKeyRecordEncoding(container.bytes.Bytes().subspan(vek_at, vek_bytes),
            volume.bytes.Bytes().subspan(kek_at, kek_bytes));
        Check(static_cast<bool>(observed), "ConstructionProfileOwnedDerAndHmacParser");
        std::cout << "{\"genuineFixture\":" << std::quoted(native ? "native-filevault.raw" : "dfvfs-apfs-encrypted.dmg")
            << ",\"containerBagBlock\":" << container_block << ",\"volumeBagBlock\":" << volume_block
            << ",\"vekEnvelopeInteger\":" << observed->vek_envelope_integer << ",\"vekBodyInteger\":" << observed->vek_body_integer
            << ",\"kekEnvelopeInteger\":" << observed->kek_envelope_integer << ",\"kekBodyInteger\":" << observed->kek_body_integer
            << ",\"vekInfo\":" << std::quoted(c::BytesToHexLower(observed->vek_info.data(), observed->vek_info.size()))
            << ",\"kekInfo\":" << std::quoted(c::BytesToHexLower(observed->kek_info.data(), observed->kek_info.size()))
            << ",\"iterations\":" << observed->iterations << ",\"vekBytes\":" << observed->vek_key_bytes
            << ",\"kekBytes\":" << observed->kek_key_bytes << "}\n";
    }
    return 0;
}

int RotationRecoveryManifest(const std::filesystem::path& run)
{
    auto password = Receive(); auto source = std::make_shared<TransitionSource>(std::filesystem::path(fixtures) / Profile{false}.Name());
    c::UnlockError unlock{}; c::EncryptedReadError read{}; c::PasswordUnlockBudget budget;
    auto bags = c::InspectPasswordKeybagMetadata(*source, 1026, c::KeybagLength::IncludesHeader, unlock);
    Check(bags && bags->users.size() == 1, "V8RecoveryOriginalManifestBag"); auto selected = bags->selection; selected.user_uuid = bags->users.front();
    auto session = c::ApfsEncryptedReadSession::Unlock(source, source->SourceIdentity(), source->Revision(), selected, password.Bytes(), budget, read, unlock);
    std::vector<c::EncryptedFileInfo> files; Check(session && session->ListFiles(files) == c::EncryptedReadError::None, "V8RecoveryOriginalManifestRead");
    std::ofstream out(run / L"expected-files.txt"); out << "E06FILES1\n" << files.size() << '\n';
    for (const auto& file : files) { std::vector<std::byte> bytes; Check(session->ReadFile(file.inode_id, 0, static_cast<std::size_t>(file.size), bytes) == c::EncryptedReadError::None,
        "V8RecoveryOriginalWholeFile"); out << file.inode_id << ' ' << file.size << ' ' << Digest(bytes) << '\n'; SecureZeroMemory(bytes.data(), bytes.size()); }
    session->Close(); Check(static_cast<bool>(out), "V8RecoveryOriginalManifestComplete"); return 0;
}
}
