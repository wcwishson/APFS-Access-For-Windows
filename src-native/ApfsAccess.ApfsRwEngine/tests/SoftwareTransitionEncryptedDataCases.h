namespace
{
enum class TransitionDataStep { BeforeStageCut, FreshRecovery, FinalDecrypt };
int TransitionRuntimeData(const std::filesystem::path& run, TransitionDataStep step)
{
    auto password = Receive(); std::string error;
    c::EncryptedImageRuntime::Options options;
    options.image = {(run / Profile{false}.Name()).wstring(), 20480, 4153344, 1026};
    options.recovery_directory = run / L"runtime"; options.payload_bytes = 1ull << 20;
    auto runtime = c::EncryptedImageRuntime::Open(options, error);
    Check(static_cast<bool>(runtime), ("TransitionDataRuntimeOpen:" + error).c_str());
    c::PasswordUnlockBudget budget;
    const auto unlocked = runtime->Unlock(password, budget, error);
    Check(unlocked, ("TransitionDataFreshCanonicalUnlock:" + error).c_str());
    if (step == TransitionDataStep::BeforeStageCut) {
        Check(runtime->CachedStatus().image.checkpoint_xid == 9, "TransitionDataCurrentNewKeyEpoch");
        std::vector<std::byte> payload(22, std::byte{0x5A}); std::size_t completed = 0;
        const auto hook = [](std::string_view stage) { if (stage == "after-encrypted-original-accept") ExitProcess(86); return true; };
        const auto written = runtime->Write(21, 0, payload, completed, error, hook);
        Check(written && completed == payload.size(), ("TransitionDataActualWrite:" + error).c_str());
        Check(false, "TransitionDataAcceptanceCutNotReached");
    }
    if (step == TransitionDataStep::FreshRecovery) {
        const auto status = runtime->CachedStatus();
        Check(status.image.checkpoint_xid == 10 && !status.recovery_required && !status.image.recovery_required &&
            status.accepted && status.accepted == status.durable && status.durable == status.cleaned && runtime->CachedPersistenceStateValid(),
            "TransitionDataFreshUnlockReplayedOriginalAndCleaned");
        c::EncryptedReadError read{}; auto view = runtime->OpenReadView(read); std::vector<std::byte> actual;
        Check(view && view->ReadFile(21, 0, 22, actual) == c::EncryptedReadError::None && actual == std::vector<std::byte>(22, std::byte{0x5A}),
            "TransitionDataFreshRecoveredPayloadExact");
        view->Close(); view.reset();
        std::cout << "{\"actualPostTransitionData\":true,\"freshUnlockBeforeStageReplay\":true,\"xid\":10,\"accepted\":"
            << status.accepted << ",\"durable\":" << status.durable << ",\"cleaned\":" << status.cleaned << "}\n";
    } else {
        c::PasswordUnlockBudget decrypt_budget;
        const auto decrypted = runtime->Decrypt(password, decrypt_budget, error);
        Check(decrypted, ("TransitionDataFinalDecrypt:" + error).c_str());
        const auto status = runtime->CachedStatus();
        Check(status.image.checkpoint_xid == 11 && status.image.phase == c::EncryptedImageWritePhase::Locked &&
            !status.image.key_present && !status.recovery_required && !status.image.recovery_required &&
            status.accepted == status.durable && status.durable == status.cleaned && runtime->CachedPersistenceStateValid(),
            "TransitionDataFinalPlainCleanLockedEndpoint");
        std::cout << "{\"actualPostDataDecryption\":true,\"xid\":11,\"accepted\":" << status.accepted
            << ",\"durable\":" << status.durable << ",\"cleaned\":" << status.cleaned << "}\n";
    }
    password.Clear(); runtime->Close(); return 0;
}
int TransitionDataDriver(const std::filesystem::path& executable, const std::filesystem::path& run)
{
    Check(run.wstring().starts_with(std::wstring(transition_root) + L"\\run-") && std::filesystem::create_directory(run),
        "TransitionDataPrivateRun");
    const auto original = std::filesystem::path(fixtures) / Profile{false}.Name(), image = run / Profile{false}.Name();
    Check(DigestFile(original) == Profile{false}.Pin() && CopyFileW(original.c_str(), image.c_str(), TRUE), "TransitionDataAuthenticCopy");
    auto password = NoteCredential(Profile{false}), fresh = RandomCredential();
    Check(Child(executable, L"transition-runtime-decrypt " + Quoted(run), password.Bytes(), run / L"decrypt.log") == 0,
        "TransitionDataFirstActualDecrypt");
    Check(Child(executable, L"transition-plain-oracle " + Quoted(run), {}, run / L"first-plain-oracle.log") == 0,
        "TransitionDataIndependentFirstPlainPayloads");
    Check(Child(executable, L"transition-runtime-encrypt " + Quoted(run), fresh.Bytes(), run / L"encrypt.log") == 0,
        "TransitionDataFreshActualEncrypt");
    Check(Child(executable, L"transition-encrypted-oracle " + Quoted(run), fresh.Bytes(), run / L"new-key-oracle.log") == 0,
        "TransitionDataIndependentNewKeyPayloads");
    Check(Child(executable, L"transition-old-oracle " + Quoted(run), password.Bytes(), run / L"old-password-oracle.log") == 0,
        "TransitionDataIndependentOldCredentialRefused");
    {
        std::ifstream before(run / L"expected-files.txt"); std::ofstream after(run / L"expected-plain-write-files.txt");
        std::string magic; std::size_t count = 0; before >> magic >> count;
        Check(before && magic == "E06FILES1" && count == 6, "TransitionDataOriginalInventory");
        after << magic << '\n' << count << '\n'; const std::vector<std::byte> payload(22, std::byte{0x5A});
        for (std::size_t i = 0; i < count; ++i) {
            ExpectedFile file; before >> file.inode >> file.bytes >> file.sha256;
            Check(static_cast<bool>(before), "TransitionDataCompleteSiblingInventory");
            after << file.inode << ' ' << file.bytes << ' ' << (file.inode == 21 ? Digest(payload) : file.sha256) << '\n';
        }
        Check(static_cast<bool>(after), "TransitionDataExpectedPostWriteManifest");
    }
    Check(Child(executable, L"transition-data-cut " + Quoted(run), fresh.Bytes(), run / L"data-accept-cut.log") == 86,
        "TransitionDataActualAcceptedBeforeStageProcessExit");
    Check(Child(executable, L"transition-data-recover " + Quoted(run), fresh.Bytes(), run / L"data-recover.log") == 0,
        "TransitionDataFreshUnlockTypedRecovery");
    Check(Child(executable, L"transition-data-encrypted-oracle " + Quoted(run), fresh.Bytes(), run / L"data-oracle.log") == 0,
        "TransitionDataIndependentChangedAndUnchangedFiles");
    Check(Child(executable, L"transition-data-final-decrypt " + Quoted(run), fresh.Bytes(), run / L"final-decrypt.log") == 0,
        "TransitionDataActualDecryptAfterWrite");
    Check(Child(executable, L"transition-plain-write-oracle " + Quoted(run), {}, run / L"final-plain-oracle.log") == 0,
        "TransitionDataIndependentFinalPlainFiles");
    for (const auto& file : std::filesystem::recursive_directory_iterator(run)) if (file.is_regular_file())
        Absent(file.path(), password.Bytes(), fresh.Bytes());
    Check(DigestFile(original) == Profile{false}.Pin(), "TransitionDataOriginalPreserved");
    std::cout << "TRANSITION_RUNTIME_NEW_KEY_DATA_AND_BEFORE_STAGE_RECOVERY_PASS\n"; return 0;
}
}
