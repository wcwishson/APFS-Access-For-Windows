#define APFSACCESS_AUTHORIZATION_DISPOSITION_TESTING
#define APFS_VOLUME_TRANSITION_MAIN TransitionPrimitiveMain
#define APFS_KEYBAG_CHILD_DEADLINE_MS 300000
#include "SoftwareVolumeTransitionTests.cpp"
#include "EncryptedImageRuntime.h"
#include "../tools/KeyManagementImageOpenRetry.h"

namespace
{
struct TransitionJournalScope
{
    Journal::Options journal;
    Wal::ProtectedPersistence original;
    std::wstring volume;
};
TransitionJournalScope TransitionScope(const std::filesystem::path& run)
{
    auto source = std::make_shared<TransitionSource>(run / Profile{false}.Name()); std::string error;
    auto cp = c::LoadContainerCheckpointView(*source, 0, source->SizeBytes(), error);
    auto volumes = cp ? c::LoadAppleReadOnlyVolumeView(*source, *cp, error) : std::nullopt;
    Check(volumes && volumes->volumes.size() == 1 && volumes->volumes.front().superblock.object_id == 1026,
        "TransitionJournalActualHeldScope");
    const auto container = cp->superblock.uuid_hex, uuid = volumes->volumes.front().superblock.uuid_hex;
    const auto identity = source->SourceIdentity();
    const auto binding = Binding("apfs-image-writer-binding-v2:" + identity + ":" + container + ":1026:" + uuid);
    TransitionJournalScope scope;
    const auto volume = "apfs-vol:" + container + ":1026:e06-private:" + identity;
    scope.volume.assign(volume.begin(), volume.end());
    scope.original = {run / L"original-keys", binding, Binding("e06-original-journal-v6"), {64ull << 20, 65536}, 256ull << 20};
    scope.journal.witness = {run / L"witness.wal", volume + ":transition-witness", 64ull << 20,
        Wal::ProtectedPersistence{run / L"witness-keys", binding, Binding("e06-witness-journal-v6"), {64ull << 20, 65536}, 256ull << 20}};
    scope.journal.container_bytes = 4153344; scope.journal.container_uuid = container;
    scope.journal.preimage_source_identity = identity; scope.journal.volume_object_id = 1026; scope.journal.volume_uuid = uuid;
    scope.journal.maintenance_original_journal_identity = scope.original.journal_identity; return scope;
}
std::unique_ptr<Tx> TransitionTx(const std::filesystem::path& run, const TransitionJournalScope& scope)
{
    auto tx = std::make_unique<Tx>(L"Conservative"); std::string error;
    const bool opened = tx->OpenProtectedJournal((run / L"original.wal").wstring(), scope.volume, scope.original, error);
    const auto system_error = GetLastError();
    Check(opened,
        ("TransitionProtectedOriginalAdmission:" + error + ":win32=" + std::to_string(system_error)).c_str());
    return tx;
}
class TransitionJournalTarget final : public r::EncryptedPublicationTarget
{
    TransitionTarget target_;
    const std::array<std::byte, 32> binding_;
public:
    std::size_t calls = 0;
    TransitionJournalTarget(const std::filesystem::path& image, const TransitionJournalScope& scope)
        : target_(image, scope.journal.preimage_source_identity), binding_(scope.original.source_binding) {}
    std::array<std::byte, 32> SourceBinding() const noexcept override { return binding_; }
    bool ReadBlock(std::uint64_t block, std::uint32_t size, std::vector<std::byte>& out) override { return target_.ReadBlock(block, size, out); }
    bool WriteBlock(std::uint64_t block, Bytes bytes) override { ++calls; return target_.WriteBlock(block, bytes); }
    bool Flush() override { return target_.Flush(); }
};
int TransitionJournalPrepare(const std::filesystem::path& run, std::wstring_view cut = {})
{
    auto password = Receive(); const auto scope = TransitionScope(run); auto tx = TransitionTx(run, scope);
    if (!cut.empty()) tx->SetFaultInjectionHook([cut](const std::string& stage) {
        if ((cut == L"authorization" && stage == "transition-after-private-authorization") ||
            (cut == L"prefix" && stage == "transition-after-original-prepared-chunk")) ExitProcess(86);
    });
    Journal journal(scope.journal); std::string error; std::uint64_t accepted = 0;
    const auto image = run / Profile{false}.Name(); const auto before = DigestFile(image);
    {
        auto source = std::make_shared<TransitionSource>(image); c::UnlockError unlock{}; c::EncryptedReadError read{};
        auto bags = c::InspectPasswordKeybagMetadata(*source, 1026, c::KeybagLength::IncludesHeader, unlock);
        Check(bags && bags->users.size() == 1, "TransitionProtectedBaselineSelection");
        auto selection = bags->selection; selection.user_uuid = bags->users.front(); c::PasswordUnlockBudget read_budget;
        auto reader = c::ApfsEncryptedReadSession::Unlock(source, source->SourceIdentity(), source->Revision(), selection,
            password.Bytes(), read_budget, read, unlock);
        std::vector<c::EncryptedFileInfo> files;
        Check(reader && reader->ListFiles(files) == c::EncryptedReadError::None && files.size() == 6, "TransitionProtectedCompleteBaselineInventory");
        std::ofstream output(run / L"expected-files.txt"); output << "E06FILES1\n" << files.size() << '\n';
        for (const auto& file : files) {
            std::vector<std::byte> bytes;
            Check(reader->ReadFile(file.inode_id, 0, static_cast<std::size_t>(file.size), bytes) == c::EncryptedReadError::None,
                "TransitionProtectedCompleteBaselinePayload");
            output << file.inode_id << ' ' << file.size << ' ' << Digest(bytes) << '\n'; SecureZeroMemory(bytes.data(), bytes.size());
        }
    }
    {
        auto source = std::make_shared<TransitionSource>(image); c::PasswordUnlockBudget budget;
        auto prepared = c::SoftwareVolumeTransition::PrepareDecryption(source, source->SourceIdentity(), source->Revision(), 1026,
            c::KeybagLength::IncludesHeader, password, budget, scope.original.journal_identity, error);
        Check(static_cast<bool>(prepared), ("TransitionProtectedPrivatePrepare:" + error).c_str());
        const bool admitted = journal.AcceptTransition(*tx, *prepared, accepted, error);
        Check(admitted, ("TransitionActualProtectedAccept:" + error).c_str());
    }
    password.Clear();
    std::vector<Tx::AcceptedTransaction> original;
    Check(tx->LoadAcceptedTransactionsSinceCleanup(original, &error) && original.size() == 1 && original.front().accepted_sequence == accepted &&
        original.front().preimage_checkpoint_xid == 7, "TransitionProtectedOriginalBoundary");
    std::size_t total = 0;
    for (const auto& row : original.front().mutations) {
        Check(row.path_utf8 == "\\$apfs-software-transition-v1" && row.logical_offset == total && row.inline_payload.size() <= 4096 &&
            row.payload_length == row.inline_payload.size() && row.payload_spool_id == row.sequence && row.parent_object_id == 7 && row.object_id == 1026 &&
            Sha(row.inline_payload) == row.payload_sha256, "TransitionProtectedOriginalOrderedChunks");
        total += row.inline_payload.size();
    }
    Check(DigestFile(image) == before && tx->Watermarks().apfs_durable_sequence == 0, "TransitionAcceptedBeforeStageNoTargetWrites");
    std::cout << "{\"transitionVersion\":6,\"intentBytes\":" << total << ",\"originalChunks\":" << original.front().mutations.size()
        << ",\"accepted\":" << accepted << ",\"preimageXid\":7,\"protectedOriginalAccepted\":true,\"targetWrites\":0}\n"; return 0;
}
int TransitionJournalRecover(const std::filesystem::path& run, std::wstring_view mode)
{
    const auto image = run / Profile{false}.Name();
    const auto before = DigestFile(image), original_before = DigestFile(run / L"original.wal"), witness_before = DigestFile(run / L"witness.wal");
    const auto scope = TransitionScope(run);
    if (mode == L"missing") {
        {
            auto tx = TransitionTx(run, scope); Journal journal(scope.journal); std::string error;
            const bool staged = journal.RestageTransition(*tx, tx->Watermarks().accepted_sequence, error);
            Check(!staged && tx->Watermarks().apfs_durable_sequence == 0, "TransitionMissingPrivateAuthorizationRefused");
        }
        Check(DigestFile(image) == before && DigestFile(run / L"original.wal") == original_before && DigestFile(run / L"witness.wal") == witness_before,
            "TransitionMissingAuthorityAllBytesPreserved");
        std::cout << "{\"missingAuthorizationRefused\":true,\"targetWrites\":0,\"allBytesPreserved\":true}\n"; return 0;
    }
    auto tx = TransitionTx(run, scope); Journal journal(scope.journal); std::string error;
    const auto accepted = tx->Watermarks().accepted_sequence;
    const bool staged = journal.RestageTransition(*tx, accepted, error);
    Check(staged, ("TransitionFreshNoCredentialRestage:" + error).c_str());
    bool cut = false;
    {
        TransitionJournalTarget target(image, scope);
        const auto hook = [&](std::string_view stage) {
            if (mode == L"switch-cut" && stage == "before-apple-checkpoint-switch") { cut = true; return false; }
            return true;
        };
        const bool published = journal.PublishOrRecover(*tx, accepted, target, error, hook);
        if (mode == L"switch-cut") {
            Check(!published && cut && target.calls > 0 && tx->Watermarks().apfs_durable_sequence == 0,
                "TransitionGenuinePreSwitchCut");
            std::cout << "{\"beforeSwitchCut\":true,\"targetWrites\":" << target.calls << ",\"durable\":0}\n"; return 0;
        }
        Check(published, ("TransitionActualNoCredentialPublication:" + error).c_str());
    }
    Check(tx->Watermarks().apfs_durable_sequence == accepted && tx->MarkCleanedThrough(accepted), "TransitionProtectedDurableAndCleaned");
    {
        auto source = std::make_shared<TransitionSource>(image);
        auto current = c::LoadAppleCheckpointView(*source, 0, source->SizeBytes(), error);
        Check(current && current->container.superblock.xid == 8 && current->volumes.front().superblock.fs_flags == 1,
            "TransitionProtectedFreshPlainReopen");
        auto owners = journal.RestoreTransitionRetainedOwners(*tx, *source, error);
        Check(owners && owners->OriginalJournalIdentity() == scope.original.journal_identity && owners->MintedCheckpointXid() == 7 &&
            owners->Generations().size() == 3, ("TransitionPostCleanOriginalAuthenticatedOwnersRestored:" + error).c_str());
    }
    std::cout << "{\"transitionVersion\":6,\"freshNoCredentialRecovery\":true,\"xid\":8,\"accepted\":" << accepted
        << ",\"durable\":" << tx->Watermarks().apfs_durable_sequence << ",\"cleaned\":" << tx->Watermarks().cleanup_sequence
        << ",\"postCleanCertificateRestored\":true}\n"; return 0;
}
int TransitionJournalRestore(const std::filesystem::path& run)
{
    const auto scope = TransitionScope(run); auto tx = TransitionTx(run, scope); Journal journal(scope.journal); std::string error;
    auto source = std::make_shared<TransitionSource>(run / Profile{false}.Name());
    auto owners = journal.RestoreTransitionRetainedOwners(*tx, *source, error);
    Check(owners && owners->Generations().size() == 3 && owners->OriginalJournalIdentity() == *tx->ProtectedJournalIdentity(),
        ("TransitionFreshPostCleanProtectedRestoration:" + error).c_str());
    std::vector<c::SoftwareVolumeOwnedRange> exclusions;
    Check(owners->RevalidateProtectedHistory(*source, *tx->ProtectedJournalIdentity(), exclusions, error) && !exclusions.empty(),
        "TransitionFreshPostCleanCurrentAllocatorAndRawOwners");
    std::cout << "{\"freshProcessCertificateRestored\":true,\"authenticatedOriginalMatched\":true,\"restoredGenerations\":3,\"exclusions\":" << exclusions.size()
        << ",\"targetWrites\":0}\n"; return 0;
}
int TransitionJournalPristine(const std::filesystem::path& run)
{
    const auto image = run / Profile{false}.Name(); const auto before = DigestFile(image);
    const auto scope = TransitionScope(run); auto tx = TransitionTx(run, scope); Journal journal(scope.journal); std::string error;
    auto source = std::make_shared<TransitionSource>(image); std::unique_ptr<const c::SoftwareVolumeRetainedOwners> owners;
    const bool empty = journal.TryRestoreTransitionRetainedOwners(*tx, *source, owners, error);
    Check(empty && !owners, ("TransitionPristineProtectedAbsence:" + error).c_str());
    const auto from = run / L"original-keys", to = run / L"original-keys-rename-probe";
    Check(from.parent_path() == run && to.parent_path() == run && !std::filesystem::exists(to), "TransitionAncestryProbeOwnedScope");
    const bool moved = MoveFileExW(from.c_str(), to.c_str(), 0) != FALSE;
    if (moved) Check(MoveFileExW(to.c_str(), from.c_str(), 0) != FALSE, "TransitionRestoreUnexpectedRename");
    Check(!moved, "TransitionProtectedAncestryPinnedAgainstRename");
    Check(tx->Watermarks().accepted_sequence == 0 && tx->NextMutationSequence() == 1 && DigestFile(image) == before &&
        !std::filesystem::exists(run / L"original.wal") && !std::filesystem::exists(run / L"witness.wal"),
        "TransitionPristineAbsenceNoTargetOrOriginalMutation");
    const bool repeated = journal.TryRestoreTransitionRetainedOwners(*tx, *source, owners, error);
    Check(repeated && !owners, ("TransitionPristineProtectedAbsenceRepeated:" + error).c_str());
    std::cout << "{\"pristineAbsenceUnderBothLeases\":true,\"ancestryRenameRefused\":true,\"repeat\":true,\"targetWrites\":0}\n"; return 0;
}
int TransitionJournalUnaccepted(const std::filesystem::path& run)
{
    const auto image = run / Profile{false}.Name(); const auto before = DigestFile(image);
    const auto witness_before = DigestFile(run / L"witness.wal");
    const bool original_exists = std::filesystem::exists(run / L"original.wal");
    const auto original_before = original_exists ? DigestFile(run / L"original.wal") : std::string{};
    const auto scope = TransitionScope(run); auto tx = TransitionTx(run, scope); Journal journal(scope.journal); std::string error;
    std::vector<Tx::AcceptedTransaction> accepted;
    Check(tx->LoadAcceptedTransactionsSinceCleanup(accepted, &error) && accepted.empty() && tx->Watermarks().accepted_sequence == 0,
        "TransitionExitHasNoOriginalAcceptance");
    auto source = std::make_shared<TransitionSource>(image); std::unique_ptr<const c::SoftwareVolumeRetainedOwners> owners;
    const bool restored = journal.TryRestoreTransitionRetainedOwners(*tx, *source, owners, error);
    Check(!restored && !owners, "TransitionUnacceptedAuthorizationCannotBecomePristineOrOwners");
    Check(DigestFile(image) == before && DigestFile(run / L"witness.wal") == witness_before &&
        std::filesystem::exists(run / L"original.wal") == original_exists && (!original_exists || DigestFile(run / L"original.wal") == original_before),
        "TransitionUnacceptedAuthorizationNoTargetReplay");
    std::cout << "{\"noOriginalAcceptance\":true,\"nextSequence\":" << tx->NextMutationSequence()
        << ",\"pristineInferenceRefused\":true,\"targetWrites\":0,\"normalRecoveryComplete\":false,\"dependency\":\"typed-authenticated-abort-and-witness-retirement\"}\n";
    return 0;
}
int TransitionJournalUnsafeKeys(const std::filesystem::path& run)
{
    const auto image = run / Profile{false}.Name(); const auto before = DigestFile(image); const auto scope = TransitionScope(run);
    auto tx = std::make_unique<Tx>(L"Conservative"); std::string error;
    const bool opened = tx->OpenProtectedJournal((run / L"original.wal").wstring(), scope.volume, scope.original, error);
    Check(!opened && !std::filesystem::exists(run / L"original.wal") && !std::filesystem::exists(run / L"witness.wal") && DigestFile(image) == before,
        "TransitionProtectedKeyDirectoryReparseRefused");
    std::cout << "{\"actualReparseDirectoryRefused\":true,\"targetWrites\":0,\"walCreated\":false}\n"; return 0;
}
int TransitionRuntimeStep(const std::filesystem::path& run, unsigned step)
{
    auto password = Receive(); std::string error;
    c::EncryptedImageRuntime::Options options;
    options.image = {(run / Profile{false}.Name()).wstring(), 20480, 4153344, 1026};
    options.recovery_directory = run / L"runtime"; options.payload_bytes = 1ull << 20;
    std::unique_ptr<c::EncryptedImageRuntime> runtime;
    for (unsigned attempt = 0; attempt < 4; ++attempt) {
        runtime = c::EncryptedImageRuntime::Open(options, error);
        if (runtime || error.find("stage=FileOpen:win32=32:") == error.npos) break;
        Sleep(500);
    }
    Check(static_cast<bool>(runtime), ("TransitionActualRuntimeOpen:" + error).c_str());
    if (step == 1) {
        c::PasswordUnlockBudget budget; const bool unlocked = runtime->Unlock(password, budget, error);
        Check(unlocked, ("TransitionRuntimeOriginalUnlock:" + error).c_str());
        c::EncryptedReadError read{}; auto view = runtime->OpenReadView(read); std::vector<c::EncryptedFileInfo> files;
        Check(view && view->ListFiles(files) == c::EncryptedReadError::None && files.size() == 6, "TransitionRuntimeCompleteBaseline");
        std::ofstream output(run / L"expected-files.txt"); output << "E06FILES1\n" << files.size() << '\n';
        for (const auto& file : files) {
            std::vector<std::byte> bytes;
            Check(view->ReadFile(file.inode_id, 0, static_cast<std::size_t>(file.size), bytes) == c::EncryptedReadError::None,
                "TransitionRuntimeCompleteBaselinePayload");
            output << file.inode_id << ' ' << file.size << ' ' << Digest(bytes) << '\n'; SecureZeroMemory(bytes.data(), bytes.size());
        }
        view->Close(); view.reset();
    }
    c::PasswordUnlockBudget budget;
    const bool published = step == 2 ? runtime->Encrypt(password, budget, error) : runtime->Decrypt(password, budget, error);
    password.Clear(); Check(published, ("TransitionActualRuntimePublication:" + error).c_str());
    const auto status = runtime->CachedStatus();
    Check(status.image.checkpoint_xid == 7 + step && status.image.phase == c::EncryptedImageWritePhase::Locked &&
        !status.image.key_present && !status.image.recovery_required && !status.recovery_required && status.accepted &&
        status.accepted == status.durable && status.durable == status.cleaned && runtime->CachedPersistenceStateValid(),
        "TransitionActualRuntimeCleanLockedEndpoint");
    runtime->Close(); runtime.reset();
    std::cout << "{\"actualRuntimeTransition\":" << step << ",\"xid\":" << 7 + step << ",\"accepted\":" << status.accepted
        << ",\"durable\":" << status.durable << ",\"cleaned\":" << status.cleaned << ",\"freshLockedEndpoint\":true}\n"; return 0;
}
int TransitionRuntimeDriver(const std::filesystem::path& executable, const std::filesystem::path& run)
{
    Check(run.wstring().starts_with(std::wstring(transition_root) + L"\\run-") && std::filesystem::create_directory(run), "TransitionRuntimePrivateRun");
    const auto original = std::filesystem::path(fixtures) / Profile{false}.Name(), image = run / Profile{false}.Name();
    Check(DigestFile(original) == Profile{false}.Pin() && CopyFileW(original.c_str(), image.c_str(), TRUE), "TransitionRuntimeAuthenticPrivateCopy");
    auto password = NoteCredential(Profile{false}), fresh = RandomCredential();
    Check(Child(executable, L"transition-runtime-decrypt " + Quoted(run), password.Bytes(), run / L"runtime-decrypt.log") == 0,
        "TransitionActualRuntimeDecryptChild");
    Check(Child(executable, L"transition-plain-oracle " + Quoted(run), {}, run / L"runtime-first-plain-oracle.log") == 0,
        "TransitionRuntimeIndependentPlainPayloads");
    Check(Child(executable, L"transition-runtime-encrypt " + Quoted(run), fresh.Bytes(), run / L"runtime-encrypt.log") == 0,
        "TransitionActualRuntimeEncryptChild");
    Check(Child(executable, L"transition-encrypted-oracle " + Quoted(run), fresh.Bytes(), run / L"runtime-new-password-oracle.log") == 0,
        "TransitionRuntimeIndependentNewPasswordPayloads");
    Check(Child(executable, L"transition-old-oracle " + Quoted(run), password.Bytes(), run / L"runtime-old-password-oracle.log") == 0,
        "TransitionRuntimeIndependentOldPasswordRefused");
    Check(Child(executable, L"transition-runtime-decrypt-again " + Quoted(run), fresh.Bytes(), run / L"runtime-decrypt-again.log") == 0,
        "TransitionActualRuntimeSecondDecryptChild");
    Check(Child(executable, L"transition-plain-oracle " + Quoted(run), {}, run / L"runtime-final-plain-oracle.log") == 0,
        "TransitionRuntimeIndependentFinalPlainPayloads");
    for (const auto& item : std::filesystem::recursive_directory_iterator(run)) if (item.is_regular_file()) Absent(item.path(), password.Bytes(), fresh.Bytes());
    Check(DigestFile(original) == Profile{false}.Pin(), "TransitionRuntimeOriginalPreserved");
    std::cout << "TRANSITION_RUNTIME_THREE_PUBLICATIONS_PASS\n"; return 0;
}
int TransitionJournalDriver(const std::filesystem::path& executable, const std::filesystem::path& run, std::wstring_view cut = {}, bool resume = false)
{
    Check(run.wstring().starts_with(std::wstring(transition_root) + L"\\run-") &&
        (resume ? std::filesystem::is_directory(run) : std::filesystem::create_directory(run)), "TransitionProtectedPrivateRun");
    const auto original = std::filesystem::path(fixtures) / Profile{false}.Name(), image = run / Profile{false}.Name();
    Check(DigestFile(original) == Profile{false}.Pin() && (resume ? std::filesystem::exists(image) : CopyFileW(original.c_str(), image.c_str(), TRUE)),
        "TransitionProtectedAuthenticPrivateCopy");
    if (!resume) {
        Check(std::filesystem::create_directory(run / L"witness-keys"), "TransitionProtectedExistingWitnessKeys");
        if (cut == L"reparse") {
            Check(std::filesystem::create_directory(run / L"reparse-target-keys"), "TransitionPrivateReparseTarget");
            Check(CreateSymbolicLinkW((run / L"original-keys").c_str(), (run / L"reparse-target-keys").c_str(),
                SYMBOLIC_LINK_FLAG_DIRECTORY | SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE) != FALSE, "TransitionActualPrivateDirectorySymlink");
            return Child(executable, L"transition-journal-reparse " + Quoted(run), {}, run / L"reparse.log");
        }
        Check(std::filesystem::create_directory(run / L"original-keys"), "TransitionProtectedExistingOriginalKeys");
    }
    if (cut == L"pristine") return Child(executable, L"transition-journal-pristine " + Quoted(run), {}, run / L"pristine.log");
    auto password = NoteCredential(Profile{false});
    if (!cut.empty()) {
        const auto image_before = DigestFile(image);
        const auto verb = cut == L"authorization" ? L"transition-journal-authorization-cut " : L"transition-journal-prefix-cut ";
        Check(Child(executable, std::wstring(verb) + Quoted(run), password.Bytes(), run / L"prepare.log") == 86,
            "TransitionActualExitBeforeOriginalAcceptance");
        Check(DigestFile(image) == image_before, "TransitionUnacceptedAuthorizationCannotPublish");
        Check(Child(executable, L"transition-journal-unaccepted " + Quoted(run), {}, run / L"unaccepted.log") == 0,
            "TransitionActualUnacceptedPrefixInspection");
        std::cout << "TRANSITION_V6_PREACCEPT_EXIT_CAPTURED\n"; return 0;
    }
    if (!resume) Check(Child(executable, L"transition-journal-prepare " + Quoted(run), password.Bytes(), run / L"prepare.log") == 0, "TransitionProtectedAcceptChild");
    Check(CopyFileW((run / L"witness.wal").c_str(), (run / L"witness-authorized.wal").c_str(), TRUE), "TransitionPreserveFullProtectedAuthorization");
    {
        Handle file(CreateFileW((run / L"witness.wal").c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr));
        LARGE_INTEGER zero{};
        Check(file.h != INVALID_HANDLE_VALUE && SetFilePointerEx(file.h, zero, nullptr, FILE_BEGIN) && SetEndOfFile(file.h) && FlushFileBuffers(file.h),
            "TransitionSetMissingAuthorizationControl");
    }
    Check(Child(executable, L"transition-journal-missing " + Quoted(run), {}, run / L"missing.log") == 0, "TransitionProtectedMissingAuthorityChild");
    Check(CopyFileW((run / L"witness-authorized.wal").c_str(), (run / L"witness.wal").c_str(), FALSE), "TransitionRestoreExactAuthorizedStream");
    Check(Child(executable, L"transition-journal-cut " + Quoted(run), {}, run / L"switch-cut.log") == 0, "TransitionProtectedSwitchCutChild");
    Check(Child(executable, L"transition-journal-recover " + Quoted(run), {}, run / L"recover.log") == 0, "TransitionProtectedFreshRecoveryChild");
    Check(Child(executable, L"transition-journal-restore " + Quoted(run), {}, run / L"restore.log") == 0, "TransitionProtectedFreshPostCleanRestoreChild");
    Check(Child(executable, L"transition-plain-oracle " + Quoted(run), {}, run / L"plain-oracle.log") == 0, "TransitionProtectedIndependentAllPayloads");
    for (const auto& item : std::filesystem::recursive_directory_iterator(run)) if (item.is_regular_file()) Absent(item.path(), password.Bytes(), password.Bytes());
    Check(DigestFile(original) == Profile{false}.Pin(), "TransitionProtectedOriginalPreserved");
    std::cout << "TRANSITION_V6_PROTECTED_DECRYPT_PASS\n"; return 0;
}
}
#include "SoftwareTransitionPlainCases.h"
#include "SoftwareTransitionDescriptorCases.h"
#include "SoftwareTransitionPlainStoreCases.h"
#include "SoftwareTransitionHeldPlainRuntimeCases.h"
#include "SoftwareTransitionPlainEncryptionCases.h"
#include "SoftwareTransitionPasswordEraCases.h"
#include "SoftwareTransitionAuthorizationCases.h"
#include "SoftwareTransitionEncryptedDataCases.h"
#include "SoftwareKeyRotationRuntimeCases.h"
#include "ImageKeyManagementProductCases.h"
#include "SoftwareKeybagEncodingProfile.h"
#include "SoftwareKeyRotationRecoveryCases.h"
#include "SoftwarePristineEncryptionCases.h"
int wmain(int argc, wchar_t** argv)
{
    try {
        if (argc == 3 && std::wstring_view(argv[1]) == L"drive-key-rotation-continuation") return KeyRotationContinuationDriver(argv[0], argv[2]);
        if (argc == 3 && std::wstring_view(argv[1]) == L"drive-key-rotation-torn-history") return RotationRetainedHistoryDriver(argv[0], argv[2]);
        if (argc == 3 && std::wstring_view(argv[1]) == L"key-rotation-next-accept-cut") return KeyRotationRuntimeStep(argv[2], 0, true);
        if (argc == 3 && std::wstring_view(argv[1]) == L"key-rotation-next-fresh-unlock") return KeyRotationRuntimeStep(argv[2], 1, true);
        if (argc == 3 && std::wstring_view(argv[1]) == L"key-rotation-next-following-data") return KeyRotationRuntimeStep(argv[2], 2, true);
        if (argc == 3 && std::wstring_view(argv[1]) == L"key-rotation-continuation-data") return KeyRotationContinuationData(argv[2], false);
        if (argc == 3 && std::wstring_view(argv[1]) == L"key-rotation-certificate-fresh-data") return KeyRotationContinuationData(argv[2], true);
        if (argc == 3 && std::wstring_view(argv[1]) == L"pristine-observe-plain") { PristineInventory(argv[2]); return 0; }
        if (argc == 3 && std::wstring_view(argv[1]) == L"drive-pristine-encryption") return PristineEncryptionDriver(argv[0], argv[2]);
        if (argc == 3 && std::wstring_view(argv[1]) == L"pristine-runtime-encrypt") return PristineRuntimeStep(argv[2], 0);
        if (argc == 3 && std::wstring_view(argv[1]) == L"pristine-runtime-data") return PristineRuntimeStep(argv[2], 1);
        if (argc == 3 && std::wstring_view(argv[1]) == L"pristine-runtime-decrypt") return PristineRuntimeStep(argv[2], 2);
        if (argc == 3 && std::wstring_view(argv[1]) == L"pristine-plain-oracle") return PlainOracle(argv[2], 0, false, nullptr, true);
        if (argc == 3 && std::wstring_view(argv[1]) == L"pristine-new-oracle") return PlainOracle(argv[2], 1, false, nullptr, true);
        if (argc == 3 && std::wstring_view(argv[1]) == L"pristine-wrong-oracle") return PlainOracle(argv[2], 2, false, nullptr, true);
        if (argc == 3 && std::wstring_view(argv[1]) == L"pristine-data-oracle") return PlainOracle(argv[2], 1, false, L"expected-after-write.txt", true);
        if (argc == 3 && std::wstring_view(argv[1]) == L"pristine-final-oracle") return PlainOracle(argv[2], 0, false, L"expected-after-write.txt", true);
        if (argc == 2 && std::wstring_view(argv[1]) == L"observe-genuine-keybag-profiles") return ObserveGenuineKeybagProfiles();
        if (argc == 4 && std::wstring_view(argv[1]) == L"drive-v8-recovery-case") return RotationRecoveryMatrix(argv[0], argv[2], argv[3]);
        if (argc == 3 && std::wstring_view(argv[1]) == L"drive-v8-recovery-matrix") return RotationRecoveryMatrix(argv[0], argv[2]);
        if (argc == 3 && std::wstring_view(argv[1]) == L"v8-recovery-prepare") return RotationRecoveryPrepare(argv[2], {});
        if (argc == 3 && std::wstring_view(argv[1]) == L"v8-recovery-prepare-authorization") return RotationRecoveryPrepare(argv[2], L"authorization");
        if (argc == 3 && std::wstring_view(argv[1]) == L"v8-recovery-prepare-prefix") return RotationRecoveryPrepare(argv[2], L"prefix");
        if (argc == 3 && std::wstring_view(argv[1]) == L"v8-recovery-publish") return RotationRecoveryPublish(argv[2], {});
        if (argc == 3 && std::wstring_view(argv[1]) == L"v8-recovery-negative") return RotationRecoveryPublish(argv[2], L"negative");
        if (argc == 3 && std::wstring_view(argv[1]) == L"v8-recovery-cut-data") return RotationRecoveryPublish(argv[2], L"data");
        if (argc == 3 && std::wstring_view(argv[1]) == L"v8-recovery-cut-watermark") return RotationRecoveryPublish(argv[2], L"watermark");
        if (argc == 3 && std::wstring_view(argv[1]) == L"v8-recovery-manifest") return RotationRecoveryManifest(argv[2]);
        if (argc == 3 && std::wstring_view(argv[1]) == L"v8-recovery-binding-controls") return RotationRecoveryBindingControls(argv[2]);
        if (argc == 3 && std::wstring_view(argv[1]) == L"v8-recovery-dispose") return r::AuthorizationDispositionTestAccess::Dispose(argv[2], {}, 8);
        if (argc == 5 && std::wstring_view(argv[1]) == L"drive-key-management-product") return KeyManagementProductDriver(argv[0], argv[2], argv[3], argv[4]);
        if (argc == 5 && std::wstring_view(argv[1]) == L"drive-key-management-complete") return KeyManagementProductDriver(argv[0], argv[2], argv[3], argv[4], true);
        if (argc == 5 && std::wstring_view(argv[1]) == L"drive-e05-public-acceptance") return KeyManagementProductDriver(argv[0], argv[2], argv[3], argv[4], true, true);
        if (argc == 3 && std::wstring_view(argv[1]) == L"drive-key-rotation-runtime") return KeyRotationRuntimeDriver(argv[0], argv[2]);
        if (argc == 3 && std::wstring_view(argv[1]) == L"key-rotation-accept-cut") return KeyRotationRuntimeStep(argv[2], 0);
        if (argc == 3 && std::wstring_view(argv[1]) == L"key-rotation-fresh-unlock") return KeyRotationRuntimeStep(argv[2], 1);
        if (argc == 3 && std::wstring_view(argv[1]) == L"key-rotation-following-data") return KeyRotationRuntimeStep(argv[2], 2);
        if (argc == 3 && std::wstring_view(argv[1]) == L"key-rotation-following-decrypt") return KeyRotationRuntimeStep(argv[2], 3);
        if (argc == 3 && std::wstring_view(argv[1]) == L"key-rotation-missing-auth") return KeyRotationRuntimeStep(argv[2], 4);
        if (argc == 3 && std::wstring_view(argv[1]) == L"drive-transition-data") return TransitionDataDriver(argv[0], argv[2]);
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-data-cut") return TransitionRuntimeData(argv[2], TransitionDataStep::BeforeStageCut);
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-data-recover") return TransitionRuntimeData(argv[2], TransitionDataStep::FreshRecovery);
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-data-final-decrypt") return TransitionRuntimeData(argv[2], TransitionDataStep::FinalDecrypt);
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-data-encrypted-oracle") return PlainOracle(argv[2], 1, true);
        if (argc == 3 && std::wstring_view(argv[1]) == L"drive-transition-disposition") return TransitionDispositionDriver(argv[0], argv[2]);
        if (argc == 3 && std::wstring_view(argv[1]) == L"resume-transition-disposition") return TransitionDispositionDriver(argv[0], argv[2], true);
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-dispose") return r::AuthorizationDispositionTestAccess::Dispose(argv[2], {});
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-dispose-intent-cut") return r::AuthorizationDispositionTestAccess::Dispose(argv[2], "authorization-disposition-after-intent");
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-dispose-abort-cut") return r::AuthorizationDispositionTestAccess::Dispose(argv[2], "authorization-disposition-after-original-abort");
#ifdef APFSACCESS_SOFTWARE_TRANSITION_PLAIN_STORE_TESTING
        if (argc == 3 && std::wstring_view(argv[1]) == L"drive-transition-plain-store") return TransitionPlainStoreDriver(argv[0], argv[2]);
        if (argc == 3 && std::wstring_view(argv[1]) == L"drive-transition-plain-post-switch") return TransitionPlainStoreDriver(argv[0], argv[2], true);
        if (argc == 3 && std::wstring_view(argv[1]) == L"probe-transition-plain-encrypt") return TransitionPlainEncryptionProbe(argv[0], argv[2]);
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-plain-encrypt-prepare") return TransitionPlainEncryptionPrepare(argv[2]);
        if (argc == 3 && std::wstring_view(argv[1]) == L"drive-transition-plain-cycle") return TransitionPlainCycleDriver(argv[0], argv[2]);
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-plain-cycle-encrypt") return TransitionPlainCycleStep(argv[2], 0);
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-plain-cycle-data-cut") return TransitionPlainCycleStep(argv[2], 1);
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-plain-cycle-data-replay") return TransitionPlainCycleStep(argv[2], 2);
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-plain-cycle-decrypt") return TransitionPlainCycleStep(argv[2], 3);
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-cycle-data-oracle") return PlainOracle(argv[2], 1, false, L"expected-after-encrypted-write-files.txt");
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-cycle-plain-oracle") return PlainOracle(argv[2], 0, false, L"expected-after-encrypted-write-files.txt");
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-protected-plain-write") return TransitionProtectedPlainStore(argv[2], false, false);
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-protected-plain-cut") return TransitionProtectedPlainStore(argv[2], false, true);
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-protected-plain-replay") return TransitionProtectedPlainStore(argv[2], true, false);
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-protected-plain-post-switch-cut") return TransitionProtectedPlainStore(argv[2], false, true, true);
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-protected-plain-post-switch-replay") return TransitionProtectedPlainStore(argv[2], true, false, true);
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-protected-plain-post-switch-proof") return TransitionProtectedPlainStore(argv[2], true, false, true, true);
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-protected-plain-control-negative") return TransitionPlainControlNegative(argv[0], argv[2]);
#endif
        if (argc == 3 && std::wstring_view(argv[1]) == L"drive-transition-password-era") return TransitionPasswordEraDriver(argv[0], argv[2]);
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-password-era-change") return TransitionPasswordEraStep(argv[2], true);
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-password-era-decrypt") return TransitionPasswordEraStep(argv[2], false);
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-plain-write-oracle") return PlainOracle(argv[2], 0, true);
        if (argc == 3 && std::wstring_view(argv[1]) == L"drive-transition-descriptor") return TransitionDescriptorDriver(argv[0], argv[2]);
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-descriptor-damage") return TransitionDescriptorDamage(argv[2]);
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-protected-plain-plan") return TransitionProtectedPlainPlan(argv[2]);
        if (argc == 3 && std::wstring_view(argv[1]) == L"drive-transition-journal") return TransitionJournalDriver(argv[0], argv[2]);
        if (argc == 3 && std::wstring_view(argv[1]) == L"drive-transition-runtime") return TransitionRuntimeDriver(argv[0], argv[2]);
        if (argc == 3 && std::wstring_view(argv[1]) == L"drive-transition-held-plain-runtime") return TransitionHeldPlainRuntimeDriver(argv[0], argv[2]);
        if (argc == 3 && std::wstring_view(argv[1]) == L"drive-transition-held-plain-existing") return TransitionHeldPlainRuntimeDriver(argv[0], argv[2], true);
        if (argc == 3 && std::wstring_view(argv[1]) == L"drive-transition-held-plain-after-accepted") return TransitionHeldPlainRuntimeDriver(argv[0], argv[2], true, 10);
        if (argc == 3 && std::wstring_view(argv[1]) == L"drive-transition-held-plain-torn-existing") return TransitionHeldPlainRuntimeDriver(argv[0], argv[2], true, 10, true);
        if (argc == 4 && std::wstring_view(argv[1]) == L"drive-transition-held-plain-retear") return TransitionHeldPlainRetearDriver(argv[0], argv[2], argv[3]);
        if (argc == 3 && std::wstring_view(argv[1]) == L"drive-transition-held-plain-completed") return TransitionHeldPlainCompletedDriver(argv[0], argv[2]);
        if (argc == 3 && std::wstring_view(argv[1]) == L"drive-transition-held-plain-epochs") return TransitionHeldPlainEpochDriver(argv[0], argv[2]);
        if (argc == 3 && std::wstring_view(argv[1]) == L"drive-transition-held-epochs-after-cuts") return TransitionHeldPlainEpochDriver(argv[0], argv[2], true);
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-held-epoch-encrypt") return TransitionHeldPlainEpochStep(argv[2], 0);
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-held-epoch-data") return TransitionHeldPlainEpochStep(argv[2], 1);
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-held-epoch-decrypt") return TransitionHeldPlainEpochStep(argv[2], 2);
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-held-epoch-plain") return TransitionHeldPlainEpochStep(argv[2], 3);
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-held-plain-cut-accepted") return TransitionHeldPlainRuntimeStep(argv[2], L"accepted", 9);
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-held-plain-cut-switch") return TransitionHeldPlainRuntimeStep(argv[2], L"switch", 10);
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-held-plain-cut-published") return TransitionHeldPlainRuntimeStep(argv[2], L"published", 11);
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-held-plain-recover9") return TransitionHeldPlainRuntimeStep(argv[2], {}, 9);
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-held-plain-recover10") return TransitionHeldPlainRuntimeStep(argv[2], {}, 10);
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-held-plain-recover11") return TransitionHeldPlainRuntimeStep(argv[2], {}, 11);
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-runtime-decrypt") return TransitionRuntimeStep(argv[2], 1);
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-runtime-encrypt") return TransitionRuntimeStep(argv[2], 2);
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-runtime-decrypt-again") return TransitionRuntimeStep(argv[2], 3);
        if (argc == 3 && std::wstring_view(argv[1]) == L"resume-transition-journal") return TransitionJournalDriver(argv[0], argv[2], {}, true);
        if (argc == 3 && std::wstring_view(argv[1]) == L"drive-transition-pristine") return TransitionJournalDriver(argv[0], argv[2], L"pristine");
        if (argc == 3 && std::wstring_view(argv[1]) == L"drive-transition-reparse") return TransitionJournalDriver(argv[0], argv[2], L"reparse");
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-journal-pristine") return TransitionJournalPristine(argv[2]);
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-journal-reparse") return TransitionJournalUnsafeKeys(argv[2]);
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-journal-unaccepted") return TransitionJournalUnaccepted(argv[2]);
        if (argc == 3 && std::wstring_view(argv[1]) == L"drive-transition-authorization-cut") return TransitionJournalDriver(argv[0], argv[2], L"authorization");
        if (argc == 3 && std::wstring_view(argv[1]) == L"drive-transition-prefix-cut") return TransitionJournalDriver(argv[0], argv[2], L"prefix");
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-journal-prepare") return TransitionJournalPrepare(argv[2]);
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-journal-authorization-cut") return TransitionJournalPrepare(argv[2], L"authorization");
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-journal-prefix-cut") return TransitionJournalPrepare(argv[2], L"prefix");
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-journal-missing") return TransitionJournalRecover(argv[2], L"missing");
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-journal-cut") return TransitionJournalRecover(argv[2], L"switch-cut");
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-journal-recover") return TransitionJournalRecover(argv[2], L"complete");
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-journal-restore") return TransitionJournalRestore(argv[2]);
        return TransitionPrimitiveMain(argc, argv);
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
