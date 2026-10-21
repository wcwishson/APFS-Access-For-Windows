namespace
{
int TransitionHeldPlainRuntimeStep(const std::filesystem::path& run, std::wstring_view cut, std::uint64_t expected)
{
    c::EncryptedImageRuntime::Options options;
    options.image = {(run / Profile{false}.Name()).wstring(), 20480, 4153344, 1026};
    options.recovery_directory = run / L"runtime"; options.payload_bytes = 1ull << 20;
    const std::atomic<bool> cancelled{false};
    std::string error; auto runtime = apfsaccess::transport::OpenKeyManagementImageRuntime(options, cancelled, error);
    Check(static_cast<bool>(runtime), ("TransitionHeldPlainRuntimeOpen:" + error).c_str());
    if (cut.empty()) {
        const auto recovered = runtime->Recover(error);
        Check(recovered, ("TransitionHeldPlainRuntimeFreshRecovery:" + error).c_str());
    } else {
        const auto stage = cut == L"accepted" ? "after-software-plain-original-accept" :
            cut == L"switch" ? "before-apple-checkpoint-switch" : "after-software-plain-publication";
        std::vector<std::byte> payload(22, std::byte{0x5A}); std::size_t completed = 0;
        const auto hook = [&](std::string_view actual) { if (actual == stage) ExitProcess(86); return true; };
        const auto written = runtime->Write(21, 0, payload, completed, error, hook);
        Check(written && completed == payload.size(), ("TransitionHeldPlainRuntimeActualWrite:" + error).c_str());
        Check(false, "TransitionHeldPlainRuntimeSelectedCutNotReached");
    }
    const auto status = runtime->CachedStatus();
    Check(status.image.checkpoint_xid == expected && status.image.phase == c::EncryptedImageWritePhase::Locked &&
        !status.image.key_present && !status.image.recovery_required && !status.recovery_required &&
        status.accepted && status.accepted == status.durable && status.durable == status.cleaned && runtime->CachedPersistenceStateValid(),
        "TransitionHeldPlainRuntimeRecoveredCleanEndpoint");
    runtime->Close();
    std::cout << "{\"actualHeldPlainRuntimeRecovery\":true,\"xid\":" << expected << ",\"accepted\":" << status.accepted
        << ",\"durable\":" << status.durable << ",\"cleaned\":" << status.cleaned << "}\n"; return 0;
}

void TransitionHeldPlainCompletedNegative(const std::filesystem::path& executable, const std::filesystem::path& run)
{
    const auto image = run / Profile{false}.Name(); std::string error, identity;
    std::uint64_t block = 0; std::vector<std::byte> original;
    {
        auto source = std::make_shared<TransitionSource>(image); identity = source->SourceIdentity();
        auto checkpoint = c::LoadContainerCheckpointView(*source, 0, source->SizeBytes(), error);
        Check(checkpoint && checkpoint->superblock.xid == 11 && checkpoint->superblock_physical_block,
            "TransitionHeldPlainNegativeActualCanonicalPostimage");
        block = checkpoint->superblock_physical_block; original = checkpoint->superblock_bytes;
    }
    auto damaged = original; damaged.back() ^= std::byte{1};
    Check(r::FinalizeAppleObjectChecksum(damaged, error) && c::ParseNxSuperblock(damaged).has_value(),
        "TransitionHeldPlainNegativeChecksumAndParsedNxsbRemainValid");
    {
        TransitionTarget target(image, identity);
        Check(target.WriteBlock(block, damaged) && target.Flush(), "TransitionHeldPlainNegativePrivateFaultSetup");
    }
    const auto image_fault = DigestFile(image), wal = DigestFile(run / L"runtime" / L"original.wal"), witness = DigestFile(run / L"runtime" / L"witness.wal");
    const auto result = Child(executable, L"transition-held-plain-recover11 " + Quoted(run), {},
        run / (L"held-completed-negative-" + std::to_wstring(GetTickCount64()) + L".log"));
    const auto unchanged = DigestFile(image) == image_fault && DigestFile(run / L"runtime" / L"original.wal") == wal &&
        DigestFile(run / L"runtime" / L"witness.wal") == witness;
    {
        TransitionTarget target(image, identity);
        Check(target.WriteBlock(block, original) && target.Flush(), "TransitionHeldPlainNegativeRestoreOnlyInjectedBytes");
    }
    Check(result != 0 && unchanged, "TransitionHeldPlainNegativeNoCheckpointOnlyCompletionAuthority");
    std::cout << "{\"checksumValidAlteredPostimageRefused\":true,\"imageOriginalWitnessPreserved\":true}\n";
}

void TransitionHeldPlainTornSwitch(const std::filesystem::path& executable, const std::filesystem::path& run,
    const std::map<std::uint64_t, std::vector<std::byte>>& predecessor, const std::filesystem::path& logs)
{
    const auto image = run / Profile{false}.Name(); std::string identity, error;
    std::uint64_t block = 0; std::vector<std::byte> complete;
    {
        TransitionSource source(image); identity = source.SourceIdentity();
        auto checkpoint = c::LoadContainerCheckpointView(source, 0, source.SizeBytes(), error);
        Check(checkpoint && checkpoint->superblock.xid == 11, "TransitionHeldPlainTornActualPublication");
        block = checkpoint->superblock_physical_block; complete = checkpoint->superblock_bytes;
    }
    const auto old = predecessor.find(block);
    Check(old != predecessor.end() && old->second.size() == complete.size(), "TransitionHeldPlainTornExactPreviousSlot");
    auto torn = old->second; std::copy_n(complete.begin(), 64, torn.begin());
    Check(torn != complete && !c::ParseNxSuperblock(torn), "TransitionHeldPlainTornProperPrefixRefusesChecksum");
    const auto full_image = DigestFile(image);
    auto malformed = torn; malformed.back() ^= std::byte{1};
    {
        TransitionTarget target(image, identity);
        Check(target.WriteBlock(block, malformed) && target.Flush(), "TransitionHeldPlainInjectMalformedSwitch");
    }
    const auto malformed_image = DigestFile(image), original_wal = DigestFile(run / L"runtime" / L"original.wal"),
        original_witness = DigestFile(run / L"runtime" / L"witness.wal");
    const auto rejected = Child(executable, L"transition-held-plain-recover11 " + Quoted(run), {}, logs / L"malformed-switch-negative.log");
    const auto preserved = DigestFile(image) == malformed_image && DigestFile(run / L"runtime" / L"original.wal") == original_wal &&
        DigestFile(run / L"runtime" / L"witness.wal") == original_witness;
    {
        TransitionTarget target(image, identity);
        Check(target.WriteBlock(block, complete) && target.Flush(), "TransitionHeldPlainRestoreOnlyMalformedSwitchBytes");
    }
    Check(rejected != 0 && preserved, "TransitionHeldPlainMalformedSwitchCannotAuthorizeReplay");
    std::cout << "{\"malformedTornSwitchRefused\":true,\"imageOriginalWitnessPreserved\":true}\n";
    {
        TransitionTarget target(image, identity);
        Check(target.WriteBlock(block, torn) && target.Flush(), "TransitionHeldPlainInjectOnlyTornSwitch");
    }
    const auto result = Child(executable, L"transition-held-plain-recover11 " + Quoted(run), {}, logs / L"torn-switch-recover.log");
    if (result != 0) {
        TransitionTarget target(image, identity);
        Check(target.WriteBlock(block, complete) && target.Flush(), "TransitionHeldPlainRestoreOnlyInjectedTornBytes");
    }
    Check(result == 0 && DigestFile(image) == full_image, "TransitionHeldPlainActualTornSwitchExactRecovery");
    std::cout << "{\"actualPlainWriteTornNxsbRecovered\":true,\"exactPublishedImageRestored\":true}\n";
}

int TransitionHeldPlainRuntimeDriver(const std::filesystem::path& executable, const std::filesystem::path& run,
    bool resume = false, unsigned first_xid = 9, bool torn_switch = false)
{
    Check(run.wstring().starts_with(std::wstring(transition_root) + L"\\run-") &&
        (resume ? std::filesystem::is_directory(run) : std::filesystem::create_directory(run)),
        "TransitionHeldPlainRuntimePrivateRun");
    const auto original = std::filesystem::path(fixtures) / Profile{false}.Name(), image = run / Profile{false}.Name();
    Check(DigestFile(original) == Profile{false}.Pin() && (resume ? std::filesystem::exists(image) : CopyFileW(original.c_str(), image.c_str(), TRUE)),
        "TransitionHeldPlainRuntimeAuthenticPrivateCopy");
    auto password = NoteCredential(Profile{false});
    const auto logs = run / (L"held-proof-" + std::to_wstring(GetTickCount64()));
    Check(std::filesystem::create_directory(logs), "TransitionHeldPlainRuntimeFreshLogNamespace");
    if (!resume) Check(Child(executable, L"transition-runtime-decrypt " + Quoted(run), password.Bytes(), logs / L"held-decrypt.log") == 0,
        "TransitionHeldPlainRuntimeActualDecrypt");
    {
        std::ifstream before(run / L"expected-files.txt"); std::ofstream after(run / L"expected-plain-write-files.txt");
        std::string magic; std::size_t count = 0; before >> magic >> count;
        Check(before && magic == "E06FILES1" && count == 6, "TransitionHeldPlainRuntimeOriginalInventory");
        const std::vector<std::byte> payload(22, std::byte{0x5A}); after << magic << '\n' << count << '\n';
        for (std::size_t i = 0; i < count; ++i) {
            ExpectedFile file; before >> file.inode >> file.bytes >> file.sha256;
            Check(static_cast<bool>(before), "TransitionHeldPlainRuntimeSiblingInventory");
            after << file.inode << ' ' << file.bytes << ' ' << (file.inode == 21 ? Digest(payload) : file.sha256) << '\n';
        }
        Check(static_cast<bool>(after), "TransitionHeldPlainRuntimeExpectedPostimage");
    }
    for (const auto& [cut, xid] : {std::pair{L"accepted", 9u}, {L"switch", 10u}, {L"published", 11u}}) {
        if (xid < first_xid) continue;
        std::map<std::uint64_t, std::vector<std::byte>> predecessor;
        if (xid == 11 && torn_switch) {
            TransitionSource source(image); std::string error;
            auto checkpoint = c::LoadContainerCheckpointView(source, 0, source.SizeBytes(), error);
            Check(checkpoint && checkpoint->superblock.xid == 10 && checkpoint->superblock.xp_desc_block_count <= 256,
                "TransitionHeldPlainTornBoundedPredecessorRing");
            for (std::uint64_t i = 0; i < checkpoint->superblock.xp_desc_block_count; ++i) {
                const auto block = checkpoint->superblock.xp_desc_base_block + i;
                Check(source.Read(block * 4096, 4096, predecessor[block]), "TransitionHeldPlainTornCaptureExactDescriptorBytes");
            }
        }
        Check(Child(executable, L"transition-held-plain-cut-" + std::wstring(cut) + L" " + Quoted(run), {}, logs / (std::wstring(cut) + L"-cut.log")) == 86,
            "TransitionHeldPlainRuntimeActualBoundaryExit");
        if (xid == 11) {
            if (torn_switch) TransitionHeldPlainTornSwitch(executable, run, predecessor, logs);
            else TransitionHeldPlainCompletedNegative(executable, run);
        }
        const auto image_before = xid == 11 ? DigestFile(image) : std::string{};
        Check(Child(executable, L"transition-held-plain-recover" + std::to_wstring(xid) + L" " + Quoted(run), {}, logs / (std::wstring(cut) + L"-recover.log")) == 0,
            "TransitionHeldPlainRuntimeActualFreshRecovery");
        if (xid == 11) Check(DigestFile(image) == image_before, "TransitionHeldPlainRuntimeCompletedProofNoImageWrites");
        Check(Child(executable, L"transition-plain-write-oracle " + Quoted(run), {}, logs / (std::wstring(cut) + L"-oracle.log")) == 0,
            "TransitionHeldPlainRuntimeIndependentAllFiles");
    }
    for (const auto& item : std::filesystem::recursive_directory_iterator(run))
        if (item.is_regular_file()) Absent(item.path(), password.Bytes(), password.Bytes());
    Check(DigestFile(original) == Profile{false}.Pin(), "TransitionHeldPlainRuntimeOriginalPreserved");
    std::cout << "TRANSITION_HELD_RUNTIME_PLAIN_WRITE_THREE_CUTS_AND_COMPLETED_PROOF_PASS\n"; return 0;
}

int TransitionHeldPlainCompletedDriver(const std::filesystem::path& executable, const std::filesystem::path& run)
{
    Check(run.wstring().starts_with(std::wstring(transition_root) + L"\\run-") && std::filesystem::is_directory(run),
        "TransitionHeldPlainCompletedPrivateRun");
    const auto logs = run / (L"completed-proof-" + std::to_wstring(GetTickCount64()));
    Check(std::filesystem::create_directory(logs), "TransitionHeldPlainCompletedUniqueLogs");
    TransitionHeldPlainCompletedNegative(executable, run);
    const auto image = run / Profile{false}.Name();
    const auto before = DigestFile(image);
    Check(Child(executable, L"transition-held-plain-recover11 " + Quoted(run), {}, logs / L"recover.log") == 0 &&
        DigestFile(image) == before, "TransitionHeldPlainCompletedExactProofNoImageWrites");
    Check(Child(executable, L"transition-plain-write-oracle " + Quoted(run), {}, logs / L"oracle.log") == 0,
        "TransitionHeldPlainCompletedIndependentWholeFiles");
    std::cout << "TRANSITION_HELD_PLAIN_COMPLETED_PROOF_AND_ALTERED_POSTIMAGE_REFUSAL_PASS\n"; return 0;
}

int TransitionHeldPlainRetearDriver(const std::filesystem::path& executable, const std::filesystem::path& run,
    const std::filesystem::path& fault_predecessor)
{
    Check(run.wstring().starts_with(std::wstring(transition_root) + L"\\run-") &&
        fault_predecessor.wstring().starts_with(std::wstring(transition_root) + L"\\release-epoch-tests-"),
        "TransitionHeldPlainRetearOwnedEvidenceOnly");
    const auto logs = run / (L"torn-proof-" + std::to_wstring(GetTickCount64()));
    Check(std::filesystem::create_directory(logs), "TransitionHeldPlainRetearUniqueLogs");
    std::map<std::uint64_t, std::vector<std::byte>> ring;
    {
        TransitionSource before(fault_predecessor); std::string error;
        auto checkpoint = c::LoadContainerCheckpointView(before, 0, before.SizeBytes(), error);
        Check(checkpoint && checkpoint->superblock.xid == 9 && checkpoint->superblock.xp_desc_block_count <= 256,
            "TransitionHeldPlainRetearExactFaultPredecessor");
        for (std::uint64_t i = 0; i < checkpoint->superblock.xp_desc_block_count; ++i) {
            const auto block = checkpoint->superblock.xp_desc_base_block + i;
            Check(before.Read(block * 4096, 4096, ring[block]), "TransitionHeldPlainRetearFaultBytes");
        }
    }
    TransitionHeldPlainTornSwitch(executable, run, ring, logs);
    Check(Child(executable, L"transition-plain-write-oracle " + Quoted(run), {}, logs / L"oracle.log") == 0,
        "TransitionHeldPlainRetearIndependentWholeFiles");
    std::cout << "ACTUAL_PLAIN_TORN_SWITCH_RECOVERY_AND_WHOLE_FILES_PASS\n"; return 0;
}

int TransitionHeldPlainEpochStep(const std::filesystem::path& run, unsigned step)
{
    auto password = step < 3 ? Receive() : k::SecureBytes{};
    c::EncryptedImageRuntime::Options options;
    options.image = {(run / Profile{false}.Name()).wstring(), 20480, 4153344, 1026};
    options.recovery_directory = run / L"runtime"; options.payload_bytes = 1ull << 20;
    const std::atomic<bool> cancelled{false};
    std::string error; auto runtime = apfsaccess::transport::OpenKeyManagementImageRuntime(options, cancelled, error);
    Check(static_cast<bool>(runtime), ("TransitionHeldEpochRuntimeOpen:" + error).c_str());
    c::PasswordUnlockBudget budget;
    if (step == 0) {
        const auto encrypted = runtime->Encrypt(password, budget, error);
        if (!encrypted) {
            const auto status = runtime->CachedStatus();
            std::cerr << "{\"encryptRefused\":true,\"accepted\":" << status.accepted << ",\"durable\":" << status.durable
                << ",\"cleaned\":" << status.cleaned << ",\"xid\":" << status.image.checkpoint_xid
                << ",\"recoveryRequired\":" << (status.recovery_required ? "true" : "false") << "}\n";
        }
        Check(encrypted, ("TransitionHeldEpochActualFreshEncrypt:" + error).c_str());
    }
    if (step == 2) Check(runtime->Decrypt(password, budget, error), ("TransitionHeldEpochActualFreshDecrypt:" + error).c_str());
    if (step == 1 || step == 3) {
        if (step == 1) Check(runtime->Unlock(password, budget, error), ("TransitionHeldEpochActualFreshUnlock:" + error).c_str());
        const std::vector<std::byte> payload(22, step == 1 ? std::byte{0x4B} : std::byte{0x6C});
        std::size_t completed = 0;
        Check(runtime->Write(21, 0, payload, completed, error) && completed == payload.size(),
            ("TransitionHeldEpochActualFollowingWrite:" + error).c_str());
        std::ifstream before(run / L"expected-files.txt"); std::ofstream after(run / L"expected-plain-write-files.txt");
        std::string magic; std::size_t count = 0; before >> magic >> count;
        Check(before && magic == "E06FILES1" && count == 6, "TransitionHeldEpochWholeInventory");
        after << magic << '\n' << count << '\n';
        for (std::size_t i = 0; i < count; ++i) {
            ExpectedFile file; before >> file.inode >> file.bytes >> file.sha256;
            Check(static_cast<bool>(before), "TransitionHeldEpochSiblingInventory");
            after << file.inode << ' ' << file.bytes << ' ' << (file.inode == 21 ? Digest(payload) : file.sha256) << '\n';
        }
        Check(static_cast<bool>(after), "TransitionHeldEpochUpdatedWholeInventory");
    }
    password.Clear(); runtime->Lock();
    c::ImageKeyManagementEndpoint endpoint;
    const auto status = runtime->CachedStatus();
    Check(runtime->ObserveKeyManagementEndpoint(endpoint, error) && endpoint.checkpoint_xid == 12 + step &&
        endpoint.mode == (step < 2 ? c::SoftwareVolumeMode::OneKeyGenerationZero : c::SoftwareVolumeMode::Plain) &&
        status.accepted && status.accepted == status.durable && status.durable == status.cleaned &&
        runtime->CachedPersistenceStateValid() && !status.image.key_present && !status.recovery_required &&
        !status.image.recovery_required, "TransitionHeldEpochExactCleanEndpoint");
    runtime->Close();
    Check(runtime->CachedStatus().closed && !runtime->CachedStatus().image.key_present, "TransitionHeldEpochNormalOwnerRetired");
    std::cout << "{\"actualTransitionEpochStep\":" << step << ",\"xid\":" << endpoint.checkpoint_xid
        << ",\"accepted\":" << status.accepted << ",\"durable\":" << status.durable << ",\"cleaned\":" << status.cleaned
        << ",\"keyRevoked\":true,\"ownerClosed\":true}\n"; return 0;
}

void TransitionHeldPlainRetiredTemplateNegative(const std::filesystem::path& executable,
    const std::filesystem::path& run, Bytes password, const std::filesystem::path& logs)
{
    std::uint64_t block = 0; std::vector<std::byte> original;
    {
        TransitionSource source(std::filesystem::path(fixtures) / Profile{false}.Name()); std::string error;
        auto checkpoint = c::LoadContainerCheckpointView(source, 0, source.SizeBytes(), error);
        auto view = checkpoint ? c::LoadAppleReadOnlyVolumeView(source, *checkpoint, error) : std::nullopt;
        Check(view && view->volumes.size() == 1, "TransitionHeldEpochAuthenticRetiredVolumeOwner");
        block = view->volumes.front().superblock_object.physical_block;
        Check(source.Read(block * 4096, 4096, original) && original.size() == 4096, "TransitionHeldEpochAuthenticRetiredRawGuard");
    }
    const auto image = run / Profile{false}.Name(); std::string identity;
    {
        TransitionSource source(image); identity = source.SourceIdentity(); std::vector<std::byte> bytes;
        Check(source.Read(block * 4096, 4096, bytes) && bytes == original, "TransitionHeldEpochRetiredGuardStillActual");
    }
    auto altered = original; altered.back() ^= std::byte{1}; std::string error;
    Check(r::FinalizeAppleObjectChecksum(altered, error) && c::ParseApsb(altered).has_value(),
        "TransitionHeldEpochAlteredRetiredApsbStillParses");
    {
        TransitionTarget target(image, identity);
        Check(target.WriteBlock(block, altered) && target.Flush(), "TransitionHeldEpochPrivateRetiredGuardFault");
    }
    const auto before = DigestFile(image), wal = DigestFile(run / L"runtime" / L"original.wal"),
        witness = DigestFile(run / L"runtime" / L"witness.wal");
    const auto result = Child(executable, L"transition-held-epoch-encrypt " + Quoted(run), password, logs / L"retired-guard-negative.log");
    const auto unchanged = DigestFile(image) == before && DigestFile(run / L"runtime" / L"original.wal") == wal &&
        DigestFile(run / L"runtime" / L"witness.wal") == witness;
    {
        TransitionTarget target(image, identity);
        Check(target.WriteBlock(block, original) && target.Flush(), "TransitionHeldEpochRestoreOnlyInjectedRetiredBytes");
    }
    Check(result != 0 && unchanged, "TransitionHeldEpochRetiredTemplateCannotInventCanonicalGraph");
    std::cout << "{\"checksummedRetiredGraphSubstitutionRefused\":true,\"imageOriginalWitnessPreserved\":true}\n";
}

int TransitionHeldPlainEpochDriver(const std::filesystem::path& executable, const std::filesystem::path& run, bool resume = false)
{
    if (!resume) Check(TransitionHeldPlainRuntimeDriver(executable, run) == 0, "TransitionHeldEpochAllPlainRecoveryCuts");
    else Check(run.wstring().starts_with(std::wstring(transition_root) + L"\\run-") && std::filesystem::is_directory(run),
        "TransitionHeldEpochExistingPrivateRun");
    const auto logs = run / (L"epoch-proof-" + std::to_wstring(GetTickCount64()));
    Check(std::filesystem::create_directory(logs), "TransitionHeldEpochUniqueLogs");
    auto old = NoteCredential(Profile{false}), fresh = RandomCredential();
    TransitionHeldPlainRetiredTemplateNegative(executable, run, fresh.Bytes(), logs);
    Check(Child(executable, L"transition-held-epoch-encrypt " + Quoted(run), fresh.Bytes(), logs / L"encrypt.log") == 0 &&
        Child(executable, L"transition-data-encrypted-oracle " + Quoted(run), fresh.Bytes(), logs / L"encrypt-oracle.log") == 0 &&
        Child(executable, L"transition-old-oracle " + Quoted(run), old.Bytes(), logs / L"old-refusal.log") == 0,
        "TransitionHeldEpochPublicEncryptIndependentCredentialsAndWholeFiles");
    Check(Child(executable, L"transition-held-epoch-data " + Quoted(run), fresh.Bytes(), logs / L"data.log") == 0 &&
        Child(executable, L"transition-data-encrypted-oracle " + Quoted(run), fresh.Bytes(), logs / L"data-oracle.log") == 0,
        "TransitionHeldEpochFreshEncryptedDataAndIndependentWholeFiles");
    Check(Child(executable, L"transition-held-epoch-decrypt " + Quoted(run), fresh.Bytes(), logs / L"decrypt.log") == 0 &&
        Child(executable, L"transition-plain-write-oracle " + Quoted(run), {}, logs / L"decrypt-oracle.log") == 0,
        "TransitionHeldEpochPublicDecryptIndependentWholeFiles");
    Check(Child(executable, L"transition-held-epoch-plain " + Quoted(run), {}, logs / L"final-plain.log") == 0 &&
        Child(executable, L"transition-plain-write-oracle " + Quoted(run), {}, logs / L"final-plain-oracle.log") == 0,
        "TransitionHeldEpochFinalFreshPlainWriteAndIndependentWholeFiles");
    for (const auto& entry : std::filesystem::recursive_directory_iterator(run))
        if (entry.is_regular_file()) Absent(entry.path(), old.Bytes(), fresh.Bytes());
    Check(DigestFile(std::filesystem::path(fixtures) / Profile{false}.Name()) == Profile{false}.Pin(), "TransitionHeldEpochOriginalPreserved");
    std::cout << "E06_PUBLIC_RUNTIME_PLAIN_CUTS_ENCRYPT_DATA_DECRYPT_PLAIN_WRITE_PASS\n"; return 0;
}
}
