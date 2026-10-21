namespace
{
int KeyRotationRuntimeStep(const std::filesystem::path& run, unsigned step, bool second_rotation = false)
{
    auto pair = step == 0 ? ReceivePair() : Credentials{};
    auto password = step ? Receive() : k::SecureBytes{};
    c::EncryptedImageRuntime::Options options;
    options.image = {(run / Profile{false}.Name()).wstring(), 20480, 4153344, 1026};
    options.recovery_directory = run / L"runtime"; options.payload_bytes = 1ull << 20;
    std::string error; auto runtime = c::EncryptedImageRuntime::Open(options, error);
    if (step == 4) {
        bool unlocked = false;
        if (runtime) { c::PasswordUnlockBudget budget; unlocked = runtime->Unlock(password, budget, error); runtime->Close(); }
        Check(!unlocked, "KeyRotationMissingPrivateAuthorizationRefuses");
        std::cout << "{\"missingPrivateAuthorizationRefused\":true,\"publicationSuccess\":false}\n"; return 0;
    }
    Check(static_cast<bool>(runtime), ("KeyRotationRuntimeOpen:" + error).c_str());
    c::PasswordUnlockBudget budget; c::ImageKeyManagementEndpoint observed;
    if (step == 0) {
        Check(runtime->Unlock(pair.old_password, budget, error), ("KeyRotationOriginalUnlock:" + error).c_str());
        Check(runtime->ObserveKeyManagementEndpoint(observed, error) && observed.checkpoint_xid == (second_rotation ? 8u : 7u) &&
            observed.mode == c::SoftwareVolumeMode::OneKeyGenerationZero && observed.encrypted_selection,
            "KeyRotationHeldCanonicalBeforeEndpoint");
        c::EncryptedReadError read{}; auto view = runtime->OpenReadView(read); std::vector<c::EncryptedFileInfo> files;
        Check(view && view->ListFiles(files) == c::EncryptedReadError::None && files.size() == 6, "KeyRotationBaselineWholeInventory");
        std::ofstream manifest(run / L"expected-files.txt"); manifest << "E06FILES1\n" << files.size() << '\n';
        for (const auto& file : files) {
            std::vector<std::byte> data;
            Check(view->ReadFile(file.inode_id, 0, static_cast<std::size_t>(file.size), data) == c::EncryptedReadError::None,
                "KeyRotationBaselineWholeFile");
            manifest << file.inode_id << ' ' << file.size << ' ' << Digest(data) << '\n'; SecureZeroMemory(data.data(), data.size());
        }
        view->Close(); view.reset(); manifest.close();
        Sleep(250);
        const auto rotated = runtime->RotateVolumeKey(pair.old_password, pair.new_password, budget, error,
            [](std::string_view stage) { if (stage == "after-encrypted-original-accept") ExitProcess(86); return true; });
        Check(rotated, ("KeyRotationActualPublicRotation:" + error).c_str());
        throw std::runtime_error("KeyRotationExpectedAcceptedCutNotReached");
    }
    // No explicit Recover: new-password admission must route the authenticated v8 original.
    Check(runtime->Unlock(password, budget, error), ("KeyRotationFreshNewPasswordUnlock:" + error).c_str());
    if (step == 2) {
        std::vector<std::byte> bytes(22, std::byte{0x5A}); std::size_t completed = 0;
        Check(runtime->Write(21, 0, bytes, completed, error) && completed == bytes.size(), ("KeyRotationFollowingActualData:" + error).c_str());
        std::ifstream before(run / L"expected-files.txt"); std::ofstream after(run / L"expected-plain-write-files.txt");
        std::string magic; std::size_t count = 0; before >> magic >> count;
        Check(before && magic == "E06FILES1" && count == 6, "KeyRotationFollowingInventory"); after << magic << '\n' << count << '\n';
        for (std::size_t i = 0; i < count; ++i) {
            ExpectedFile file; before >> file.inode >> file.bytes >> file.sha256;
            Check(static_cast<bool>(before), "KeyRotationFollowingSiblingManifest");
            after << file.inode << ' ' << file.bytes << ' ' << (file.inode == 21 ? Digest(bytes) : file.sha256) << '\n';
        }
    }
    if (step == 3) {
        Sleep(250);
        Check(runtime->Decrypt(password, budget, error), ("KeyRotationFollowingActualDecrypt:" + error).c_str());
    }
    password.Clear(); runtime->Lock();
    const auto status = runtime->CachedStatus();
    Check(runtime->ObserveKeyManagementEndpoint(observed, error) && observed.checkpoint_xid == 7 + step + (second_rotation ? 1u : 0u) &&
        observed.mode == (step == 3 ? c::SoftwareVolumeMode::Plain : c::SoftwareVolumeMode::OneKeyGenerationZero) &&
        observed.encrypted_selection.has_value() == (step != 3) && runtime->CachedPersistenceStateValid() &&
        status.accepted && status.accepted == status.durable && status.accepted == status.cleaned &&
        !status.recovery_required && !status.image.recovery_required && !status.image.key_present && !runtime->UnlockedSelection(),
        "KeyRotationFreshCleanObservedEndpoint");
    runtime->Close();
    Check(runtime->CachedStatus().closed && !runtime->CachedStatus().image.key_present, "KeyRotationExactOwnerClosed");
    std::cout << "{\"actualRotationStep\":" << step << ",\"xid\":" << observed.checkpoint_xid << ",\"accepted\":" << status.accepted
        << ",\"durable\":" << status.durable << ",\"cleaned\":" << status.cleaned << ",\"freshEndpoint\":true,\"keyRevoked\":true}\n"; return 0;
}
int KeyRotationRuntimeDriver(const std::filesystem::path& executable, const std::filesystem::path& run)
{
    Check(run.wstring().starts_with(std::wstring(transition_root) + L"\\run-") && std::filesystem::create_directory(run), "KeyRotationPrivateRun");
    const auto original = std::filesystem::path(fixtures) / Profile{false}.Name(), image = run / Profile{false}.Name();
    Check(DigestFile(original) == Profile{false}.Pin() && CopyFileW(original.c_str(), image.c_str(), TRUE), "KeyRotationAuthenticPrivateCopy");
    auto old = NoteCredential(Profile{false}), fresh = RandomCredential(); auto pair = Pair(old.Bytes(), fresh.Bytes());
    Check(Child(executable, L"key-rotation-accept-cut " + Quoted(run), pair.Bytes(), run / L"rotation-accept-cut.log") == 86,
        "KeyRotationActualPrivateAcceptBeforeStageExit");
    const auto witness = run / L"runtime" / L"witness.wal", wal = run / L"runtime" / L"original.wal";
    const auto image_before = DigestFile(image), original_before = DigestFile(wal), witness_before = DigestFile(witness);
    const auto saved = run / L"rotation-authorized-witness.wal";
    Check(CopyFileW(witness.c_str(), saved.c_str(), TRUE), "KeyRotationPreservePrivateAuthorization");
    {
        Handle file(CreateFileW(witness.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr)); LARGE_INTEGER zero{};
        Check(file.h != INVALID_HANDLE_VALUE && SetFilePointerEx(file.h, zero, nullptr, FILE_BEGIN) && SetEndOfFile(file.h) && FlushFileBuffers(file.h),
            "KeyRotationInjectMissingAuthorization");
    }
    const auto empty = DigestFile(witness);
    Check(Child(executable, L"key-rotation-missing-auth " + Quoted(run), fresh.Bytes(), run / L"missing-auth.log") == 0 &&
        DigestFile(image) == image_before && DigestFile(wal) == original_before && DigestFile(witness) == empty,
        "KeyRotationMissingAuthPreservesImageOriginalWitness");
    Check(CopyFileW(saved.c_str(), witness.c_str(), FALSE) && DigestFile(witness) == witness_before, "KeyRotationRestoreExactInjectedAuthorization");
    Check(Child(executable, L"key-rotation-fresh-unlock " + Quoted(run), fresh.Bytes(), run / L"rotation-fresh-unlock.log") == 0,
        "KeyRotationActualFreshDirectUnlockRecovery");
    Check(Child(executable, L"transition-encrypted-oracle " + Quoted(run), fresh.Bytes(), run / L"rotation-new-oracle.log") == 0,
        "KeyRotationIndependentNewPasswordWholeInventory");
    Check(Child(executable, L"transition-old-oracle " + Quoted(run), old.Bytes(), run / L"rotation-old-oracle.log") == 0,
        "KeyRotationIndependentOldPasswordRefusal");
    Check(Child(executable, L"key-rotation-following-data " + Quoted(run), fresh.Bytes(), run / L"rotation-following-data.log") == 0,
        "KeyRotationActualFreshFollowingData");
    Check(Child(executable, L"transition-data-encrypted-oracle " + Quoted(run), fresh.Bytes(), run / L"rotation-data-oracle.log") == 0,
        "KeyRotationIndependentChangedAndUnchangedWholeFiles");
    Check(Child(executable, L"key-rotation-following-decrypt " + Quoted(run), fresh.Bytes(), run / L"rotation-following-decrypt.log") == 0,
        "KeyRotationActualFreshFollowingDecrypt");
    Check(Child(executable, L"transition-plain-write-oracle " + Quoted(run), {}, run / L"rotation-plain-oracle.log") == 0,
        "KeyRotationIndependentFinalPlainInventory");
    for (const auto& entry : std::filesystem::recursive_directory_iterator(run))
        if (entry.is_regular_file()) Absent(entry.path(), old.Bytes(), fresh.Bytes());
    Check(DigestFile(original) == Profile{false}.Pin(), "KeyRotationOriginalPreserved");
    std::cout << "KEY_ROTATION_PUBLIC_RUNTIME_RECOVERY_DATA_DECRYPT_PASS\n"; return 0;
}

int KeyRotationContinuationData(const std::filesystem::path& run, bool fresh)
{
    auto password = Receive(); c::EncryptedImageRuntime::Options options;
    options.image = {(run / Profile{false}.Name()).wstring(), 20480, 4153344, 1026};
    options.recovery_directory = run / L"runtime"; options.payload_bytes = 1ull << 20;
    std::string error; auto runtime = c::EncryptedImageRuntime::Open(options, error);
    Check(static_cast<bool>(runtime), ("V8CertificateActualRuntimeOpen:" + error).c_str());
    c::PasswordUnlockBudget budget; const auto unlocked = runtime->Unlock(password, budget, error);
    Check(unlocked, ("V8CertificateFreshCanonicalUnlock:" + error).c_str());
    unsigned continuations = 0; const auto writes = fresh ? 1u : 9u;
    std::vector<std::byte> payload(22);
    for (unsigned i = 0; i < writes; ++i) {
        std::fill(payload.begin(), payload.end(), static_cast<std::byte>(fresh ? 0x79 : 0x60 + i));
        std::size_t completed = 0;
        const auto hook = [&](std::string_view stage) {
            if (stage == "continuation-after-ready-receipt") ++continuations;
            return true;
        };
        const auto written = runtime->Write(21, 0, payload, completed, error, hook);
        Check(written && completed == payload.size(), ("V8CertificateActualFollowingWrite:" + error).c_str());
        const auto status = runtime->CachedStatus();
        Check(status.image.checkpoint_xid == (fresh ? 18 : 9 + i) && status.accepted &&
            status.accepted == status.durable && status.accepted == status.cleaned &&
            !status.recovery_required && !status.image.recovery_required && runtime->CachedPersistenceStateValid(),
            "V8CertificateEveryActualWriteIsPublishedAndClean");
    }
    if (!fresh) Check(continuations == 1, "V8CertificateActualContinuationDurableReadyBoundary");
    for (const auto suffix : {L".jcont.certificate", L".jcont.done", L".jcont.ready"})
        Check(std::filesystem::is_regular_file(run / L"runtime" / (std::wstring(L"original.wal") + suffix)),
            "V8CertificateActualProtectedDurableControlFiles");
    std::ifstream before(run / L"expected-files.txt"); std::ofstream after(run / L"expected-plain-write-files.txt");
    std::string magic; std::size_t count = 0; before >> magic >> count;
    Check(before && magic == "E06FILES1" && count == 6, "V8CertificateCompleteOriginalInventory");
    after << magic << '\n' << count << '\n';
    for (std::size_t i = 0; i < count; ++i) {
        ExpectedFile file; before >> file.inode >> file.bytes >> file.sha256;
        after << file.inode << ' ' << file.bytes << ' ' << (file.inode == 21 ? Digest(payload) : file.sha256) << '\n';
    }
    Check(before && after, "V8CertificateExactFinalManifest");
    password.Clear(); runtime->Close();
    std::cout << "{\"v8PublicContinuationData\":true,\"freshAfterCertificate\":" << (fresh ? "true" : "false")
        << ",\"actualWrites\":" << writes << ",\"checkpoint\":" << (fresh ? 18 : 17) << ",\"allClean\":true}\n";
    return 0;
}

int KeyRotationContinuationDriver(const std::filesystem::path& executable, const std::filesystem::path& run)
{
    Check(run.wstring().starts_with(std::wstring(transition_root) + L"\\run-") && std::filesystem::create_directory(run),
        "V8CertificatePrivateRun");
    const auto original = std::filesystem::path(fixtures) / Profile{false}.Name(), image = run / Profile{false}.Name();
    Check(DigestFile(original) == Profile{false}.Pin() && CopyFileW(original.c_str(), image.c_str(), TRUE), "V8CertificateAuthenticCopy");
    auto old = NoteCredential(Profile{false}), fresh = RandomCredential(); auto pair = Pair(old.Bytes(), fresh.Bytes());
    Check(Child(executable, L"key-rotation-accept-cut " + Quoted(run), pair.Bytes(), run / L"rotation-accept.log") == 86 &&
        Child(executable, L"key-rotation-fresh-unlock " + Quoted(run), fresh.Bytes(), run / L"rotation-fresh-unlock.log") == 0,
        "V8CertificateActualPrivateRotationAndFreshRecovery");
    Check(Child(executable, L"key-rotation-continuation-data " + Quoted(run), fresh.Bytes(), run / L"continuation-data.log") == 0 &&
        Child(executable, L"transition-data-encrypted-oracle " + Quoted(run), fresh.Bytes(), run / L"continuation-oracle.log") == 0,
        "V8CertificateActualContinuationAndIndependentPayloads");
    Check(Child(executable, L"key-rotation-certificate-fresh-data " + Quoted(run), fresh.Bytes(), run / L"certificate-fresh-data.log") == 0 &&
        Child(executable, L"transition-data-encrypted-oracle " + Quoted(run), fresh.Bytes(), run / L"fresh-certificate-oracle.log") == 0 &&
        Child(executable, L"transition-old-oracle " + Quoted(run), old.Bytes(), run / L"certificate-old-refusal.log") == 0,
        "V8CertificateFreshRestoredAuthorityActualDataAndIndependentCredentials");
    for (const auto& file : std::filesystem::recursive_directory_iterator(run)) if (file.is_regular_file())
        Absent(file.path(), old.Bytes(), fresh.Bytes());
    Check(DigestFile(original) == Profile{false}.Pin(), "V8CertificateOriginalPreserved");
    std::cout << "V8_PUBLIC_CONTINUATION_FRESH_CERTIFICATE_DATA_PASS\n"; return 0;
}
}
