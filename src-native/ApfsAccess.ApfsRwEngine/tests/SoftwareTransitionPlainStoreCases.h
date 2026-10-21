#ifdef APFSACCESS_SOFTWARE_TRANSITION_PLAIN_STORE_TESTING
#include "SoftwareTransitionPlainWriter.h"
#include "MetadataStore.h"

namespace
{
std::string TransitionPlainStoreReason(const std::wstring& reason)
{
    if (reason.empty()) return {};
    if (reason.size() > 4096) return "NativeDiagnosticUnavailable";
    const auto size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, reason.data(), static_cast<int>(reason.size()), nullptr, 0, nullptr, nullptr);
    if (size <= 0) return "NativeDiagnosticUnavailable";
    std::string text(static_cast<std::size_t>(size), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, reason.data(), static_cast<int>(reason.size()), text.data(), size, nullptr, nullptr) != size)
        return "NativeDiagnosticUnavailable";
    return text;
}
int TransitionProtectedPlainStore(const std::filesystem::path& run, bool replay, bool cut, bool post_switch = false, bool proof_only = false)
{
    const auto image = run / Profile{false}.Name(); const auto scope = TransitionScope(run);
    auto tx = TransitionTx(run, scope); Journal journal(scope.journal); std::string error;
    const auto preimage = std::uint64_t{8}; std::uint64_t accepted = 0;
    std::shared_ptr<const c::SoftwareVolumeRetainedOwners> owners;
    std::vector<Tx::AcceptedTransaction> pending; std::vector<std::byte> payload(22, std::byte{0x5A});
    {
        auto source = std::make_shared<TransitionSource>(image);
        if (replay) {
            Check(tx->LoadAcceptedTransactionsSinceCleanup(pending, &error) && pending.size() == 1 &&
                pending.front().preimage_checkpoint_xid == preimage && pending.front().mutations.size() == 1,
                "TransitionPlainReplayExactAcceptedOriginal");
            accepted = pending.front().accepted_sequence;
            auto restored = journal.RestoreTransitionRetainedOwnersForPlainReplay(*tx, *source, accepted, error);
            Check(static_cast<bool>(restored), ("TransitionPlainReplayPriorProtectedOwners:" + error).c_str());
            owners = std::move(restored);
            Check(pending.front().mutations.front().inline_payload == payload, "TransitionPlainReplayExactInlinePayload");
            std::unique_ptr<const c::SoftwareVolumeRetainedOwners> strict;
            Check(!journal.TryRestoreTransitionRetainedOwners(*tx, *source, strict, error) && !strict &&
                error == "EncryptedPublicationTransitionRestoreRequiresCleanOriginal", "TransitionPreparationStillRequiresCleanOriginal");
        } else {
            auto restored = journal.RestoreTransitionRetainedOwners(*tx, *source, error);
            Check(static_cast<bool>(restored), ("TransitionPlainStoreProtectedOwners:" + error).c_str()); owners = std::move(restored);
        }
    }
    auto device = r::BlockDevice::OpenExclusiveManagementImage(image.wstring(), 20480, error);
    Check(static_cast<bool>(device), ("TransitionPlainStoreSameExclusiveImage:" + error).c_str());
    r::MetadataStore::VolumeContext context; context.device_path = image.wstring(); context.device_offset_bytes = 20480;
    context.volume_object_id = 1026; context.allow_legacy_scaffold_for_fixtures = false;
    context.container_uuid_hex = owners->ContainerUuid(); context.volume_uuid_hex = owners->VolumeUuid();
    r::MetadataStore store(context, device);
    const auto success = r::WithSoftwareTransitionPlainWriter(store, *tx, owners, [&](std::string& detail) {
        if (!store.PrepareNativeWritePath()) {
            detail = "TransitionPlainStorePrepareFailed:" + TransitionPlainStoreReason(store.LastCanonicalGateFailure()) + ":" +
                TransitionPlainStoreReason(store.RecoveryReason()) + ":integrity=" +
                TransitionPlainStoreReason(store.LastIntegrityFailureReason()) + ":object=" +
                std::to_string(store.LastIntegrityFailureObjectId().value_or(0)); return false;
        }
        if (replay && post_switch) {
            r::PayloadSpool::Options options;
            options.root = run / L"plain-payload";
            options.volume_identity = Tx::WideToUtf8(scope.volume);
            options.max_bytes = 8ull << 20;
            options.protected_persistence = true;
            options.protected_binding = scope.original.source_binding;
            options.protected_key_directory = run / L"plain-payload-keys";
            r::PayloadSpool spool(options);
            const auto held_digest = [&] {
                std::vector<std::byte> bytes;
                Check(device->ReadForVerification(0, 4153344, bytes) && bytes.size() == 4153344,
                    "TransitionPlainCompletedHeldImageRead");
                return Digest(bytes);
            };
            const auto image_before = held_digest();
            const auto marks = tx->Watermarks();
            std::vector<std::uint64_t> applied;
            if (!store.ProveRetainedAcceptedPrefix(*tx, spool, run / L"original.wal", options.volume_identity, applied, detail))
                return false;
            if (applied != std::vector<std::uint64_t>{accepted} || store.CheckpointXid() != preimage + 1 ||
                held_digest() != image_before || tx->Watermarks().apfs_durable_sequence != marks.apfs_durable_sequence ||
                tx->Watermarks().cleanup_sequence != marks.cleanup_sequence) {
                detail = "TransitionPlainCompletedProofMustBeReadOnly"; return false;
            }
            if (proof_only) return true;
            if (!tx->MarkApfsDurableThrough(accepted) || !tx->MarkCleanedThrough(accepted)) {
                detail = "TransitionPlainCompletedProofBoundaryFailed"; return false;
            }
            const auto inode = store.LookupCommittedInodeByObjectId(21);
            std::vector<std::byte> actual;
            if (!inode || !store.ReadCommittedFileRange(inode->full_path, 0, payload.size(), actual) || actual != payload) {
                detail = "TransitionPlainCompletedProofPayloadFailed"; return false;
            }
            return true;
        }
        const auto inode = store.LookupCommittedInodeByObjectId(21);
        if (!inode || inode->logical_size != payload.size() || store.CheckpointXid() != preimage) {
            detail = "TransitionPlainStorePreimageMismatch"; return false;
        }
        r::MetadataStore::MutationRequest write; write.path = inode->full_path; write.length = payload.size();
        if (replay) { write.object_id = pending.front().mutations.front().object_id; write.generation = pending.front().mutations.front().parent_object_id; }
        else if (!tx->Begin()) { detail = "TransitionPlainStoreBeginFailed"; return false; }
        r::MetadataStore::PayloadIdentity identity;
        if (store.StageMutation(write, &identity) != r::MetadataStore::MutationStatus::Applied) {
            detail = "TransitionPlainStoreStageFailed:" + TransitionPlainStoreReason(store.LastMutationFailureReason()); return false;
        }
        store.SetFilePayloadRangeProvider([&](const auto& path, auto actual, auto at, std::span<std::byte> bytes) {
            if (path != write.path || actual.object_id != identity.object_id || actual.generation != identity.generation ||
                at > payload.size() || bytes.size() > payload.size() - at) return false;
            std::copy_n(payload.begin() + static_cast<std::ptrdiff_t>(at), bytes.size(), bytes.begin()); return true;
        });
        if (!replay) {
            Tx::MutationIntent original; original.path = write.path; original.object_id = identity.object_id;
            original.generation = identity.generation; original.length = original.payload_length = payload.size(); original.inline_payload = payload;
            original.payload_checksum = Sha(payload);
            if (!tx->RecordMutation(original) || !tx->FlushPreparedRecords() || !tx->Accept(preimage)) {
                detail = "TransitionPlainStoreOriginalAcceptanceFailed"; return false;
            }
            accepted = tx->Watermarks().accepted_sequence;
        }
        if (cut && !post_switch) store.SetCommitStageHook([](std::string_view stage) {
            if (stage == "before-apple-checkpoint-switch") ExitProcess(86);
            return true;
        });
        if (store.CommitPendingMutations({preimage}) != r::MetadataStore::CommitStatus::Committed) {
            detail = "TransitionPlainStoreCanonicalCommitFailed:" + TransitionPlainStoreReason(store.LastCommitFailureReason()) + ":" + TransitionPlainStoreReason(store.LastCommitFailureDetail()); return false;
        }
        if (cut && post_switch) ExitProcess(86);
        if (store.CheckpointXid() != preimage + 1 || !tx->MarkApfsDurableThrough(accepted) || !tx->MarkCleanedThrough(accepted)) {
            detail = "TransitionPlainStoreDurableBoundaryFailed"; return false;
        }
        std::vector<std::byte> actual;
        if (!store.ReadCommittedFileRange(inode->full_path, 0, payload.size(), actual) || actual != payload) {
            detail = "TransitionPlainStoreExactPayloadFailed"; return false;
        }
        return true;
    }, error);
    if (!success && tx->CurrentState() == Tx::State::Active) (void)tx->Abort();
    Check(success, ("TransitionActualProtectedOrdinaryPlainWrite:" + error).c_str());
    std::ifstream before(run / L"expected-files.txt"); std::ofstream after(run / L"expected-plain-write-files.txt");
    std::string magic; std::size_t count = 0; before >> magic >> count;
    Check(before && magic == "E06FILES1" && count == 6, "TransitionPlainStoreOriginalInventoryManifest");
    after << magic << '\n' << count << '\n';
    for (std::size_t i = 0; i < count; ++i) {
        ExpectedFile file; before >> file.inode >> file.bytes >> file.sha256;
        Check(static_cast<bool>(before), "TransitionPlainStorePreservedSiblingManifest");
        after << file.inode << ' ' << file.bytes << ' ' << (file.inode == 21 ? Digest(payload) : file.sha256) << '\n';
    }
    Check(static_cast<bool>(after), "TransitionPlainStorePostimageManifest");
    std::cout << "{\"actualProtectedOrdinaryPlainWrite\":true,\"readOnlyCompletedProof\":" << (proof_only ? "true" : "false") << ",\"freshReplay\":" << (replay ? "true" : "false")
        << ",\"xid\":9,\"accepted\":" << accepted << ",\"durable\":" << tx->Watermarks().apfs_durable_sequence
        << ",\"cleaned\":" << tx->Watermarks().cleanup_sequence << "}\n"; return 0;
}

int TransitionPlainControlNegative(const std::filesystem::path& executable, const std::filesystem::path& run)
{
    const auto image = run / Profile{false}.Name(); const auto baseline = DigestFile(image);
    std::uint64_t block = 0; std::string identity, error; std::vector<std::byte> original;
    {
        const auto scope = TransitionScope(run); auto tx = TransitionTx(run, scope); Journal journal(scope.journal);
        auto source = std::make_shared<TransitionSource>(image); identity = source->SourceIdentity();
        auto owners = journal.RestoreTransitionRetainedOwnersForPlainReplay(*tx, *source, tx->Watermarks().accepted_sequence, error);
        Check(static_cast<bool>(owners), ("TransitionPlainNegativeActualAcceptedAuthority:" + error).c_str());
        for (const auto& generation : owners->Generations()) for (const auto& guard : generation.checkpoint_guards) {
            std::vector<std::byte> actual;
            Check(source->Read(guard.physical_block * 4096, 4096, actual), "TransitionPlainNegativeReadActualControl");
            if (!block && actual != guard.bytes) { block = guard.physical_block; original = std::move(actual); }
        }
        Check(block && original.size() == 4096, "TransitionPlainNegativeRealBeforeSwitchControlReuse");
    }
    for (const bool checksum : {false, true}) {
        auto damaged = original; damaged.back() ^= std::byte{1};
        if (checksum) Check(r::FinalizeAppleObjectChecksum(damaged, error), "TransitionPlainNegativeRepairOnlyChecksum");
        {
            TransitionTarget target(image, identity);
            Check(target.WriteBlock(block, damaged) && target.Flush(), "TransitionPlainNegativeOwnedFaultSetup");
        }
        const auto fault = DigestFile(image), wal = DigestFile(run / L"original.wal"), witness = DigestFile(run / L"witness.wal");
        const auto log = run / (checksum ? L"control-checksum-repaired-negative.log" : L"control-damaged-negative.log");
        const auto result = Child(executable, L"transition-protected-plain-replay " + Quoted(run), {}, log);
        const bool preserved = DigestFile(image) == fault && DigestFile(run / L"original.wal") == wal && DigestFile(run / L"witness.wal") == witness;
        std::ifstream input(log); const std::string diagnostic((std::istreambuf_iterator<char>(input)), {});
        {
            TransitionTarget target(image, identity);
            Check(target.WriteBlock(block, original) && target.Flush(), "TransitionPlainNegativeRestoreInjectedBytes");
        }
        Check(DigestFile(image) == baseline, "TransitionPlainNegativeExactFaultRestore");
        Check(result != 0 && preserved && diagnostic.find("AppleSoftwareTransitionControlReplayPrefixMismatch") != std::string::npos,
            "TransitionPlainNegativeUnplannedControlHasNoReplayAuthority");
        std::cout << "{\"changedControlRefused\":true,\"checksumRepaired\":" << (checksum ? "true" : "false")
            << ",\"imageOriginalWitnessPreserved\":true,\"targetWrites\":0}\n";
    }
    return 0;
}

int TransitionPlainStoreDriver(const std::filesystem::path& executable, const std::filesystem::path& run, bool post_switch = false)
{
    Check(run.wstring().starts_with(std::wstring(transition_root) + L"\\run-") && std::filesystem::create_directory(run),
        "TransitionPlainStorePrivateRun");
    const auto original = std::filesystem::path(fixtures) / Profile{false}.Name(), image = run / Profile{false}.Name();
    Check(DigestFile(original) == Profile{false}.Pin() && CopyFileW(original.c_str(), image.c_str(), TRUE), "TransitionPlainStoreAuthenticCopy");
    Check(std::filesystem::create_directory(run / L"original-keys") && std::filesystem::create_directory(run / L"witness-keys"),
        "TransitionPlainStorePrivateJournalKeys");
    auto password = NoteCredential(Profile{false});
    Check(Child(executable, L"transition-journal-prepare " + Quoted(run), password.Bytes(), run / L"prepare.log") == 0,
        "TransitionPlainStoreRealTransitionAccept");
    Check(Child(executable, L"transition-journal-recover " + Quoted(run), {}, run / L"publish.log") == 0,
        "TransitionPlainStoreRealKeylessTransitionPublication");
    Check(Child(executable, L"transition-plain-oracle " + Quoted(run), {}, run / L"initial-plain-oracle.log") == 0,
        "TransitionPlainStoreIndependentInitialFiles");
    Check(Child(executable, (post_switch ? L"transition-protected-plain-post-switch-cut " : L"transition-protected-plain-cut ") + Quoted(run), {}, run / L"plain-store-cut.log") == 86,
        "TransitionPlainStoreActualSelectedProcessExit");
    if (!post_switch) Check(Child(executable, L"transition-protected-plain-control-negative " + Quoted(run), {}, run / L"plain-control-negatives.log") == 0,
        "TransitionPlainStoreExactControlPrefixNegatives");
    const auto published_image = post_switch ? DigestFile(image) : std::string{};
    Check(Child(executable, (post_switch ? L"transition-protected-plain-post-switch-replay " : L"transition-protected-plain-replay ") + Quoted(run), {}, run / L"plain-store-replay.log") == 0,
        "TransitionPlainStoreActualFreshReplay");
    if (post_switch) Check(DigestFile(image) == published_image, "TransitionPlainCompletedProofWholeImageUnchanged");
    Check(Child(executable, L"transition-plain-write-oracle " + Quoted(run), {}, run / L"plain-store-oracle.log") == 0,
        "TransitionPlainStoreIndependentChangedAndUnchangedFiles");
    for (const auto& file : std::filesystem::recursive_directory_iterator(run))
        if (file.is_regular_file()) Absent(file.path(), password.Bytes(), password.Bytes());
    Check(DigestFile(original) == Profile{false}.Pin(), "TransitionPlainStoreOriginalPreserved");
    std::cout << (post_switch ? "TRANSITION_PROTECTED_PLAIN_STORE_POST_SWITCH_PROOF_AND_FRESH_REPLAY_PASS\n" :
        "TRANSITION_PROTECTED_PLAIN_STORE_CUT_AND_FRESH_REPLAY_PASS\n"); return 0;
}
}
#endif
