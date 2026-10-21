namespace
{
int TransitionPasswordEraStep(const std::filesystem::path& run, bool change_password)
{
    Credentials credentials;
    if (change_password) credentials = ReceivePair();
    else credentials.new_password = Receive();
    c::EncryptedImageRuntime::Options options;
    options.image = {(run / Profile{false}.Name()).wstring(), 20480, 4153344, 1026};
    options.recovery_directory = run / L"runtime"; options.payload_bytes = 1ull << 20;
    std::string error;
    auto runtime = c::EncryptedImageRuntime::Open(options, error);
    Check(static_cast<bool>(runtime), ("TransitionPasswordEraRuntimeOpen:" + error).c_str());
    if (change_password) {
        c::PasswordUnlockBudget unlock_budget;
        const bool unlocked = runtime->Unlock(credentials.old_password, unlock_budget, error);
        Check(unlocked, ("TransitionPasswordEraOriginalUnlock:" + error).c_str());
        c::EncryptedReadError read{}; auto view = runtime->OpenReadView(read);
        std::vector<c::EncryptedFileInfo> files;
        Check(view && view->ListFiles(files) == c::EncryptedReadError::None && files.size() == 6,
            "TransitionPasswordEraCompleteBaseline");
        std::ofstream expected(run / L"expected-files.txt"); expected << "E06FILES1\n" << files.size() << '\n';
        for (const auto& file : files) {
            std::vector<std::byte> bytes;
            Check(view->ReadFile(file.inode_id, 0, static_cast<std::size_t>(file.size), bytes) == c::EncryptedReadError::None,
                "TransitionPasswordEraBaselineBytes");
            expected << file.inode_id << ' ' << file.size << ' ' << Digest(bytes) << '\n';
            SecureZeroMemory(bytes.data(), bytes.size());
        }
        Check(static_cast<bool>(expected), "TransitionPasswordEraBaselineManifest");
        view->Close(); view.reset();
    }
    c::PasswordUnlockBudget budget;
    const auto published = change_password
        ? runtime->ChangePassword(credentials.old_password, credentials.new_password, budget, error)
        : runtime->Decrypt(credentials.new_password, budget, error);
    credentials.old_password.Clear(); credentials.new_password.Clear();
    Check(published, ("TransitionPasswordEraActualPublication:" + error).c_str());
    const auto status = runtime->CachedStatus();
    const auto expected_xid = change_password ? 8u : 9u;
    Check(status.image.checkpoint_xid == expected_xid && status.image.phase == c::EncryptedImageWritePhase::Locked &&
        !status.image.key_present && !status.image.recovery_required && !status.recovery_required && status.accepted &&
        status.accepted == status.durable && status.durable == status.cleaned && runtime->CachedPersistenceStateValid(),
        "TransitionPasswordEraCleanLockedEndpoint");
    runtime->Close(); runtime.reset();
    std::cout << "{\"passwordEraTransition\":true,\"passwordChange\":" << (change_password ? "true" : "false")
        << ",\"xid\":" << expected_xid << ",\"accepted\":" << status.accepted << ",\"durable\":" << status.durable
        << ",\"cleaned\":" << status.cleaned << ",\"freshLockedEndpoint\":true}\n";
    return 0;
}
int TransitionPasswordEraDriver(const std::filesystem::path& executable, const std::filesystem::path& run)
{
    Check(run.wstring().starts_with(std::wstring(transition_root) + L"\\run-") && std::filesystem::create_directory(run),
        "TransitionPasswordEraPrivateRun");
    const auto original = std::filesystem::path(fixtures) / Profile{false}.Name(), image = run / Profile{false}.Name();
    Check(DigestFile(original) == Profile{false}.Pin() && CopyFileW(original.c_str(), image.c_str(), TRUE),
        "TransitionPasswordEraAuthenticCopy");
    auto old_password = NoteCredential(Profile{false}), new_password = RandomCredential();
    auto pair = Pair(old_password.Bytes(), new_password.Bytes());
    Check(Child(executable, L"transition-password-era-change " + Quoted(run), pair.Bytes(), run / L"password-change.log") == 0,
        "TransitionPasswordEraChangeChild");
    pair.Clear();
    Check(Child(executable, L"transition-encrypted-oracle " + Quoted(run), new_password.Bytes(), run / L"new-password-oracle.log") == 0,
        "TransitionPasswordEraIndependentNewPassword");
    Check(Child(executable, L"transition-old-oracle " + Quoted(run), old_password.Bytes(), run / L"old-password-oracle.log") == 0,
        "TransitionPasswordEraIndependentOldPasswordRefusal");
    Check(Child(executable, L"transition-password-era-decrypt " + Quoted(run), new_password.Bytes(), run / L"decrypt.log") == 0,
        "TransitionPasswordEraFreshDirectDecryptChild");
    Check(Child(executable, L"transition-plain-oracle " + Quoted(run), {}, run / L"plain-oracle.log") == 0,
        "TransitionPasswordEraIndependentPlainFiles");
    for (const auto& item : std::filesystem::recursive_directory_iterator(run)) if (item.is_regular_file())
        Absent(item.path(), old_password.Bytes(), new_password.Bytes());
    Check(DigestFile(original) == Profile{false}.Pin(), "TransitionPasswordEraOriginalPreserved");
    std::cout << "TRANSITION_PASSWORD_ERA_TWO_PUBLICATIONS_PASS\n";
    return 0;
}
}
