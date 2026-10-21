namespace
{
std::string ProductUuid(std::string value)
{
    Check(value.size() == 32, "ProductCanonicalUuid");
    return value.substr(0, 8) + '-' + value.substr(8, 4) + '-' + value.substr(12, 4) + '-' + value.substr(16, 4) + '-' + value.substr(20);
}
std::filesystem::path ProductRequest(const std::filesystem::path& run, const std::string& action,
    const std::wstring& name, std::uint64_t expected, bool wrong = false)
{
    std::array<std::byte, 16> random{};
    Check(BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(random.data()), static_cast<ULONG>(random.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0,
        "ProductPublicOperationIdentity");
    const auto operation = ProductUuid(c::BytesToHexLower(random.data(), random.size()));
    const auto request = run / (name + L"-request.json"), image = run / Profile{false}.Name();
    auto source = std::make_shared<TransitionSource>(image); std::string error;
    auto checkpoint = c::LoadContainerCheckpointView(*source, 0, source->SizeBytes(), error);
    auto view = checkpoint ? c::LoadAppleReadOnlyVolumeView(*source, *checkpoint, error) : std::nullopt;
    Check(view && view->volumes.size() == 1 && checkpoint->superblock.xid == expected && view->volumes.front().superblock.object_id == 1026,
        "ProductExpectedCanonicalReadOnlySelectors");
    const auto encrypted = view->volumes.front().superblock.fs_flags == c::kFsFlagOneKey;
    Check(encrypted || view->volumes.front().superblock.fs_flags == c::kFsFlagUnencrypted, "ProductKnownObservedMode");
    std::ofstream output(request);
    output << "{\"operationId\":" << std::quoted(operation) << ",\"action\":" << std::quoted(action) << ",\"expected\":{\"imagePath\":"
        << std::quoted(image.string()) << ",\"sourceId\":" << std::quoted(source->SourceIdentity())
        << ",\"storeOffset\":20480,\"storeSize\":4153344,\"containerUuid\":" << std::quoted(ProductUuid(checkpoint->superblock.uuid_hex))
        << ",\"volumeUuid\":" << std::quoted(ProductUuid(view->volumes.front().superblock.uuid_hex))
        << ",\"volumeObjectId\":1026,\"checkpointXid\":" << expected + (wrong ? 1 : 0) << ",\"mode\":"
        << std::quoted(encrypted ? "SoftwareOneKeyGenerationZero" : "Plain") << ",\"keybag\":";
    if (!encrypted) output << "null";
    else {
        c::UnlockError reason{}; auto metadata = c::InspectPasswordKeybagMetadata(*source, 1026, c::KeybagLength::IncludesHeader, reason);
        Check(metadata && metadata->users.size() == 1, "ProductActualCanonicalBagSelectors");
        const auto& bag = metadata->selection;
        output << "{\"containerBagOid\":" << bag.container_bag.oid << ",\"containerBagXid\":" << bag.container_bag.xid
            << ",\"volumeBagOid\":" << bag.volume_bag.oid << ",\"volumeBagXid\":" << bag.volume_bag.xid << ",\"userUuid\":"
            << std::quoted(ProductUuid(c::BytesToHexLower(metadata->users.front().data(), 16))) << ",\"bagLength\":\"includes-header\"}";
    }
    output << "}}\n"; output.close(); Check(static_cast<bool>(output), "ProductPublicExpectationFile"); return request;
}
int KeyManagementProductDriver(const std::filesystem::path& executable, const std::filesystem::path& run,
    const std::filesystem::path& dotnet, const std::filesystem::path& probe, bool complete = false, bool e05_only = false)
{
    Check(run.wstring().starts_with(std::wstring(transition_root) + L"\\run-") && std::filesystem::create_directory(run), "ProductPrivateRun");
    const auto original = std::filesystem::path(fixtures) / Profile{false}.Name(), image = run / Profile{false}.Name();
    Check(DigestFile(original) == Profile{false}.Pin() && CopyFileW(original.c_str(), image.c_str(), TRUE), "ProductAuthenticPrivateImageCopy");
    const auto recovery = std::filesystem::path(L"D:\\ApfsAccessScratch\\WindowsClosure") / (L"km-" + run.filename().wstring().substr(4));
    Check(std::filesystem::create_directory(recovery) && std::filesystem::create_directory(run / L"operations"), "ProductPrivateProtectedStorage");
    auto old = NoteCredential(Profile{false}), first = RandomCredential(), latest = RandomCredential(), changed = RandomCredential();
    {
        auto source = std::make_shared<TransitionSource>(image);
        c::PasswordUnlockBudget budget; c::EncryptedReadError read{}; c::UnlockError unlock{};
        auto metadata = c::InspectPasswordKeybagMetadata(*source, 1026, c::KeybagLength::IncludesHeader, unlock);
        Check(metadata && metadata->users.size() == 1, "ProductBaselineSourceBagSelection");
        auto selection = metadata->selection; selection.user_uuid = metadata->users.front();
        auto session = c::ApfsEncryptedReadSession::Unlock(source, source->SourceIdentity(), source->Revision(), selection, old.Bytes(), budget, read, unlock);
        Check(static_cast<bool>(session), "ProductBaselineAuthenticPassword");
        std::vector<c::EncryptedFileInfo> files; Check(session->ListFiles(files) == c::EncryptedReadError::None && files.size() == 6, "ProductBaselineWholeInventory");
        std::ofstream manifest(run / L"expected-files.txt"); manifest << "E06FILES1\n" << files.size() << '\n';
        for (const auto& file : files) {
            std::vector<std::byte> data;
            Check(session->ReadFile(file.inode_id, 0, static_cast<std::size_t>(file.size), data) == c::EncryptedReadError::None, "ProductBaselineWholeFile");
            manifest << file.inode_id << ' ' << file.size << ' ' << Digest(data) << '\n'; SecureZeroMemory(data.data(), data.size());
        }
        session->Close();
    }
    const auto tool = executable.parent_path().parent_path() / L"ApfsAccess.ApfsImageKeyManagementTool.exe";
    Check(std::filesystem::exists(tool) && std::filesystem::exists(probe), "ProductRealLinkedExecutables");
    const auto call = [&](const std::filesystem::path& request, const std::wstring& name, Bytes password, Bytes second = {}) {
        return Child(dotnet, Quoted(probe) + L" " + Quoted(request) + L" " + Quoted(tool) + L" " + Quoted(recovery) + L" " +
            Quoted(run / L"operations") + L" " + Quoted(run / (name + L"-receipt.json")), password, run / (name + L"-managed.log"), second);
    };
    const auto shift = complete ? std::uint64_t{1} : std::uint64_t{0};
    const auto observe = [&](const std::wstring& name, std::uint64_t xid) {
        const auto before = DigestFile(image);
        Check(call(ProductRequest(run, "Observe", name, xid), name, {}) == 0 && DigestFile(image) == before,
            "ProductCredentiallessCurrentEndpointDoesNotPublish");
    };
    if (complete) {
        observe(L"observe-original", 7);
        Check(call(ProductRequest(run, "ChangePassword", L"change", 7), L"change", old.Bytes(), changed.Bytes()) == 0,
            "ProductActualPublicPasswordChange");
        Check(Child(executable, L"transition-encrypted-oracle " + Quoted(run), changed.Bytes(), run / L"change-new-oracle.log") == 0 &&
            Child(executable, L"transition-old-oracle " + Quoted(run), old.Bytes(), run / L"change-old-oracle.log") == 0,
            "ProductIndependentPasswordChangeCredentialsAndWholeFiles");
        observe(L"observe-changed", 8);
    }
    Check(call(ProductRequest(run, "RotateVolumeKey", L"rotate", 7 + shift), L"rotate", complete ? changed.Bytes() : old.Bytes(), first.Bytes()) == 0,
        "ProductActualManagedNativeRotation");
    Check(Child(executable, L"transition-encrypted-oracle " + Quoted(run), first.Bytes(), run / L"rotate-new-oracle.log") == 0 &&
        Child(executable, L"transition-old-oracle " + Quoted(run), old.Bytes(), run / L"rotate-old-oracle.log") == 0, "ProductIndependentRotationCredentialsAndFiles");
    std::vector<std::filesystem::path> roots;
    for (const auto& entry : std::filesystem::directory_iterator(recovery / L"encrypted")) if (entry.is_directory()) roots.push_back(entry.path());
    Check(roots.size() == 1, "ProductExactOriginalJournalRoot");
    const auto before = DigestFile(image), wal = DigestFile(roots.front() / L"original.wal"), witness = DigestFile(roots.front() / L"witness.wal");
    if (complete) observe(L"observe-rotated", 8 + shift);
    Check(call(ProductRequest(run, "Decrypt", L"wrong-xid", 8 + shift, true), L"wrong-xid", first.Bytes()) != 0 &&
        DigestFile(image) == before && DigestFile(roots.front() / L"original.wal") == wal && DigestFile(roots.front() / L"witness.wal") == witness,
        "ProductWrongExpectedCheckpointPreservesImageAndJournals");
    if (e05_only) {
        Check(complete && Child(executable, L"transition-old-oracle " + Quoted(run), changed.Bytes(),
            run / L"rotate-intermediate-oracle.log") == 0, "ProductIndependentIntermediateCredentialRefusal");
        for (const auto& storage : {run, recovery}) for (const auto& entry : std::filesystem::recursive_directory_iterator(storage))
            if (entry.is_regular_file()) { Absent(entry.path(), old.Bytes(), first.Bytes()); Absent(entry.path(), latest.Bytes(), changed.Bytes()); }
        Check(DigestFile(original) == Profile{false}.Pin(), "ProductE05OriginalPreserved");
        std::cout << "E05_PUBLIC_CLI_SERVICE_CURRENT_NATIVE_CHANGE_ROTATE_PASS\n"; return 0;
    }
    Check(call(ProductRequest(run, "Decrypt", L"decrypt", 8 + shift), L"decrypt", first.Bytes()) == 0 &&
        Child(executable, L"transition-plain-oracle " + Quoted(run), {}, run / L"decrypt-plain-oracle.log") == 0, "ProductActualManagedNativeDecrypt");
    if (complete) observe(L"observe-plain", 9 + shift);
    Check(call(ProductRequest(run, "Encrypt", L"encrypt", 9 + shift), L"encrypt", latest.Bytes()) == 0, "ProductActualManagedNativeEncrypt");
    Check(Child(executable, L"transition-encrypted-oracle " + Quoted(run), latest.Bytes(), run / L"encrypt-latest-oracle.log") == 0 &&
        Child(executable, L"transition-old-oracle " + Quoted(run), first.Bytes(), run / L"encrypt-intermediate-oracle.log") == 0 &&
        Child(executable, L"transition-old-oracle " + Quoted(run), old.Bytes(), run / L"encrypt-original-oracle.log") == 0,
        "ProductIndependentLatestIntermediateOriginalCredentials");
    if (complete) {
        Check(Child(executable, L"transition-old-oracle " + Quoted(run), changed.Bytes(), run / L"encrypt-changed-oracle.log") == 0,
            "ProductChangedEraPasswordAlsoRefused");
        observe(L"observe-latest", 10 + shift);
    }
    for (const auto& storage : {run, recovery}) for (const auto& entry : std::filesystem::recursive_directory_iterator(storage))
        if (entry.is_regular_file()) { Absent(entry.path(), old.Bytes(), first.Bytes()); Absent(entry.path(), latest.Bytes(), changed.Bytes()); }
    Check(DigestFile(original) == Profile{false}.Pin(), "ProductOriginalPreserved");
    std::cout << (complete ? "PRODUCT_PUBLIC_CHANGE_ROTATE_DECRYPT_ENCRYPT_OBSERVE_PASS\n" :
        "PRODUCT_MANAGED_NATIVE_ROTATE_DECRYPT_ENCRYPT_PASS\n"); return 0;
}
}
