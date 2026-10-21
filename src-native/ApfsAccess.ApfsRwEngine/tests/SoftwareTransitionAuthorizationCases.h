namespace apfsaccess::rw
{
struct AuthorizationDispositionTestAccess
{
    static std::string OriginalDigest(const std::filesystem::path& run)
    { return std::filesystem::exists(run / L"original.wal") ? DigestFile(run / L"original.wal") : "absent"; }
    static ProtectedJournalContinuation::Endpoint Endpoint(const std::shared_ptr<TransitionSource>& source,
        const TransitionJournalScope& scope, std::uint64_t xid)
    {
        ProtectedJournalContinuation::Endpoint::Description description;
        description.source_binding = scope.original.source_binding;
        description.source_identity = source->SourceIdentity();
        description.container_uuid = scope.journal.container_uuid;
        description.volume_uuid = scope.journal.volume_uuid;
        description.volume_object_id = 1026; description.container_bytes = source->SizeBytes(); description.checkpoint_xid = xid;
        std::string error;
        const auto current = c::LoadContainerCheckpointView(*source, 0, source->SizeBytes(), error);
        Check(current && current->superblock.xid == 7, "TransitionDispositionActualPreimage");
        const auto raw = current->superblock_bytes;
        const auto block = current->superblock_physical_block;
        return ProtectedJournalContinuation::Endpoint(std::move(description),
            [source, raw, block](std::string&) {
                std::vector<std::byte> actual;
                return source->Read(block * 4096, 4096, actual) && actual == raw;
            }, [source](std::uint64_t offset, std::span<std::byte> out, std::string&) {
                std::vector<std::byte> actual;
                if (out.size() != 4096 || offset % 4096 || !source->Read(offset, out.size(), actual) || actual.size() != out.size()) return false;
                std::copy(actual.begin(), actual.end(), out.begin()); return true;
            });
    }
    static std::unique_ptr<Tx> Open(const std::filesystem::path& run, const TransitionJournalScope& scope)
    {
        auto tx = std::make_unique<Tx>(L"Conservative"); std::string error;
        const auto opened = tx->OpenProtectedJournal((run / L"original.wal").wstring(), scope.volume, scope.original, error);
        Check(opened || (!tx->RecoveryStateValid() && error == "ProtectedJournalEvidenceInvalid"),
            ("TransitionDispositionBoundedPreparedAdmission:" + error).c_str());
        return tx;
    }
    struct NoTarget final : EncryptedPublicationTarget
    {
        std::array<std::byte, 32> binding{}; unsigned calls = 0;
        std::array<std::byte, 32> SourceBinding() const noexcept override { return binding; }
        bool ReadBlock(std::uint64_t, std::uint32_t, std::vector<std::byte>&) override { ++calls; return false; }
        bool WriteBlock(std::uint64_t, std::span<const std::byte>) override { ++calls; return false; }
        bool Flush() override { ++calls; return false; }
    };
    static int Dispose(const std::filesystem::path& run, std::string_view cut, std::uint64_t expected_version = 6)
    {
        const auto image = run / Profile{false}.Name(); const auto image_before = DigestFile(image);
        const auto scope = TransitionScope(run); std::string error;
        {
            Wal witness(scope.journal.witness); const auto prior = witness.ReadAll();
            Check(prior.status == Wal::ReadStatus::Ok && !prior.records.empty() &&
                c::ReadU64LE(prior.records.front().inline_payload, 0) == expected_version, "DispositionActualTypedPrivateWitness");
        }
        const auto original_before = OriginalDigest(run), witness_before = DigestFile(run / L"witness.wal");
        auto source = std::make_shared<TransitionSource>(image);
        if (cut.empty()) {
            {
                auto tx = Open(run, scope); Journal journal(scope.journal); auto wrong = Endpoint(source, scope, 8);
                Check(!journal.ReconcileUnacceptedAuthorizations(*tx, wrong, error), "TransitionDispositionWrongHeadRefused");
            }
            Check(OriginalDigest(run) == original_before && DigestFile(run / L"witness.wal") == witness_before,
                "TransitionDispositionWrongHeadAllBytesPreserved");
            {
                auto tx = Open(run, scope); auto options = scope.journal;
                options.maintenance_original_journal_identity.front() ^= std::byte{1};
                Journal wrong(options); auto held = Endpoint(source, scope, 7);
                Check(!wrong.ReconcileUnacceptedAuthorizations(*tx, held, error), "TransitionDispositionWrongJournalRefused");
            }
            Check(OriginalDigest(run) == original_before && DigestFile(run / L"witness.wal") == witness_before,
                "TransitionDispositionWrongJournalAllBytesPreserved");
        }
        std::uint64_t reserved = 0, next = 0;
        {
            auto tx = Open(run, scope); Journal journal(scope.journal); auto held = Endpoint(source, scope, 7);
            const auto hook = [cut](std::string_view stage) { if (!cut.empty() && stage == cut) ExitProcess(86); return true; };
            const auto retired = journal.ReconcileUnacceptedAuthorizations(*tx, held, error, hook);
            Check(retired, ("TransitionActualFreshAuthorizationDisposition:" + error).c_str());
            std::vector<std::uint64_t> spent;
            Check(journal.ValidateUnacceptedDispositions(*tx, spent, error) && spent.size() == 1 &&
                tx->RecoveryStateValid() && !tx->Watermarks().accepted_sequence && !tx->Watermarks().apfs_durable_sequence &&
                !tx->Watermarks().cleanup_sequence && !tx->HasUnappliedAcceptedWork(), "TransitionDispositionNoInventedAcceptance");
            reserved = spent.front(); next = tx->NextMutationSequence();
            Check(next == reserved + 1, "TransitionDispositionReservedSequenceConsumed");
            NoTarget target; target.binding = scope.original.source_binding;
            Check(!journal.PublishOrRecover(*tx, reserved, target, error) && !target.calls, "TransitionSpentCannotReachTarget");
            std::unique_ptr<const c::SoftwareVolumeRetainedOwners> owners;
            Check(journal.TryRestoreTransitionRetainedOwners(*tx, *source, owners, error) && !owners,
                ("TransitionSpentCannotMintRetainedAuthority:" + error).c_str());
        }
        const auto original_completed = DigestFile(run / L"original.wal"), witness_completed = DigestFile(run / L"witness.wal");
        {
            auto tx = Open(run, scope); Journal journal(scope.journal); auto held = Endpoint(source, scope, 7);
            Check(journal.ReconcileUnacceptedAuthorizations(*tx, held, error) && tx->NextMutationSequence() == next,
                ("TransitionDispositionFreshIdempotentReceipt:" + error).c_str());
        }
        Check(DigestFile(run / L"original.wal") == original_completed && DigestFile(run / L"witness.wal") == witness_completed &&
            DigestFile(image) == image_before, "TransitionDispositionIdempotentBytesAndImagePreserved");
        std::cout << "{\"genuinePrivateAuthorizationDisposed\":true,\"version\":" << expected_version << ",\"reserved\":" << reserved << ",\"nextSequence\":" << next
            << ",\"freshIdempotence\":true,\"accepted\":0,\"targetCalls\":0,\"imageUnchanged\":true}\n";
        return 0;
    }
};
}
namespace
{
int TransitionDispositionDriver(const std::filesystem::path& executable, const std::filesystem::path& run, bool resume = false)
{
    Check(run.wstring().starts_with(std::wstring(transition_root) + L"\\run-") &&
        (resume ? std::filesystem::is_directory(run) : std::filesystem::create_directory(run)),
        "TransitionDispositionPrivateRun");
    const auto original = std::filesystem::path(fixtures) / Profile{false}.Name(), image = run / Profile{false}.Name();
    Check(DigestFile(original) == Profile{false}.Pin() &&
        (resume ? DigestFile(image) == Profile{false}.Pin() : CopyFileW(original.c_str(), image.c_str(), TRUE)), "TransitionDispositionAuthenticCopy");
    if (!resume) Check(std::filesystem::create_directory(run / L"witness-keys") && std::filesystem::create_directory(run / L"original-keys"),
        "TransitionDispositionPrivateKeyDirectories");
    auto password = NoteCredential(Profile{false});
    const bool prefix = run.filename().wstring().ends_with(L"prefix");
    if (!resume) Check(Child(executable, std::wstring(prefix ? L"transition-journal-prefix-cut " : L"transition-journal-authorization-cut ") + Quoted(run),
        password.Bytes(), run / L"authorization-exit.log") == 86, "TransitionDispositionActualProcessExit");
    if (std::filesystem::exists(run / L"original.wal"))
        Check(CopyFileW((run / L"original.wal").c_str(), (run / L"original-before-disposition.wal").c_str(), TRUE),
            "TransitionDispositionOriginalPredecessorPreserved");
    else {
        std::ofstream absence(run / L"original-before-disposition.absent"); absence << "Original WAL absent before disposition.\n";
        Check(static_cast<bool>(absence), "TransitionDispositionOriginalAbsenceRecorded");
    }
    Check(CopyFileW((run / L"witness.wal").c_str(), (run / L"witness-before-disposition.wal").c_str(), TRUE),
        "TransitionDispositionPredecessorEvidencePreserved");
    const auto interrupted = prefix ? L"transition-dispose-abort-cut " : L"transition-dispose-intent-cut ";
    Check(Child(executable, std::wstring(interrupted) + Quoted(run), {}, run / L"disposition-exit.log") == 86,
        "TransitionDispositionDurableProtocolProcessExit");
    Check(Child(executable, L"transition-dispose " + Quoted(run), {}, run / L"disposition-recover.log") == 0,
        "TransitionDispositionFreshNoCredentialResume");
    Check(Child(executable, L"transition-journal-prepare " + Quoted(run), password.Bytes(), run / L"subsequent-accept.log") == 0,
        "TransitionDispositionSubsequentGenuinePrivateAcceptance");
    Check(Child(executable, L"transition-journal-recover " + Quoted(run), {}, run / L"subsequent-publish.log") == 0,
        "TransitionDispositionSubsequentActualPublication");
    Check(Child(executable, L"transition-plain-oracle " + Quoted(run), {}, run / L"subsequent-plain-oracle.log") == 0,
        "TransitionDispositionIndependentSubsequentPayloads");
    for (const auto& file : std::filesystem::recursive_directory_iterator(run)) if (file.is_regular_file())
        Absent(file.path(), password.Bytes(), password.Bytes());
    Check(DigestFile(original) == Profile{false}.Pin(), "TransitionDispositionAuthenticOriginalPreserved");
    std::cout << "TRANSITION_AUTHORIZATION_DISPOSITION_AND_NEW_PUBLICATION_PASS\n"; return 0;
}
}
