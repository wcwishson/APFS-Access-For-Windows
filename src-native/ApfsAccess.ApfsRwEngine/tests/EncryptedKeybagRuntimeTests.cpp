#define APFS_KEYBAG_ERA_MAIN KeybagEraMain
#include "EncryptedKeybagEraTests.cpp"
#include "EncryptedImageRuntime.h"
#include <map>
#include <thread>

namespace
{
using Runtime = c::EncryptedImageRuntime;
constexpr wchar_t runtime_root[] = L"D:\\ApfsAccessScratch\\WindowsClosure\\software-keybag-runtime-20261017";
Runtime::Options RuntimeOptions(const std::filesystem::path& run)
{
    Check(run.wstring().starts_with(std::wstring(runtime_root) + L"\\run-"), "RuntimePrivateRun");
    Runtime::Options options;
    options.image = {(run / Profile{false}.Name()).wstring(), 20480, 4153344, 1026};
    options.recovery_directory = run / L"rt";
    options.payload_bytes = 1ull << 20;
    return options;
}
std::unique_ptr<Runtime> RuntimeOpenObserved(const Runtime::Options& options, std::string& error)
{
    for (unsigned attempt = 0; attempt < 4; ++attempt) {
        auto runtime = Runtime::Open(options, error);
        if (runtime || error.find("stage=FileOpen:win32=32:") == error.npos) return runtime;
        std::cout << "ADMISSION sharing-refusal attempt=" << attempt << '\n';
        Sleep(500);
    }
    return {};
}
std::vector<std::byte> RuntimePayload(Runtime& runtime)
{
    c::EncryptedReadError error{}; auto view = runtime.OpenReadView(error);
    Check(static_cast<bool>(view), "RuntimePayloadView");
    c::EncryptedNodeInfo info;
    Check(view->GetMetadata(21, info) == c::EncryptedReadError::None && info.size > 0 && info.size <= 8192,
        "RuntimePayloadLength");
    std::vector<std::byte> result;
    Check(view->ReadFile(21, 0, static_cast<std::size_t>(info.size), result) == c::EncryptedReadError::None,
        "RuntimePayloadRead");
    view->Close(); return result;
}
void RuntimeClean(const Runtime::Status& status, unsigned phase, bool maintenance)
{
    Check(status.image.checkpoint_xid == 7 + phase && status.accepted && status.accepted == status.durable &&
        status.durable == status.cleaned && !status.recovery_required && !status.image.recovery_required,
        "RuntimeActualCleanPublication");
    Check(status.image.phase == (maintenance ? c::EncryptedImageWritePhase::Locked : c::EncryptedImageWritePhase::Ready) &&
        status.image.key_present != maintenance, "RuntimePostPublicationKeyState");
}
Wal::Options RuntimeOriginalOptions(const std::filesystem::path& run, std::string volume,
    const std::array<std::byte, 32>& binding)
{
    const auto options = RuntimeOptions(run);
    const std::string_view domain = "apfs-encrypted-runtime-original-v1";
    const auto digest = Sha(std::as_bytes(std::span(domain))); std::array<std::byte, 32> identity{};
    std::transform(digest.begin(), digest.end(), identity.begin(), [](auto value) { return std::byte(value); });
    return {options.recovery_directory / L"original.wal", volume, options.journal_bytes,
        Wal::ProtectedPersistence{options.recovery_directory / L"original-keys", binding, identity,
            {options.journal_bytes, 65536}, 256ull << 20}};
}
Wal::Options RuntimeOriginalOptions(const std::filesystem::path& run, const c::ApfsEncryptedImageWriteSession& owner)
{
    return RuntimeOriginalOptions(run, "apfs-vol:" + owner.ContainerUuid() + ":" + std::to_string(owner.VolumeObjectId()), owner.SourceBinding());
}
Wal::Options RuntimeCapturedOriginalOptions(const std::filesystem::path& run, unsigned phase)
{
    std::ifstream input(run / (PhaseName(phase) + L"-scope.txt"));
    std::string source, container, volume; std::uint64_t oid = 0;
    input >> std::quoted(source) >> std::quoted(container) >> std::quoted(volume) >> oid;
    Check(input && source.size() < 8192 && container.size() == 32 && volume.size() == 32 && oid == 1026,
        "RuntimeActualCapturedPublicScope");
    const auto domain = "apfs-image-writer-binding-v2:" + source + ":" + container + ":" + std::to_string(oid) + ":" + volume;
    const auto digest = Sha(std::as_bytes(std::span(domain))); std::array<std::byte, 32> binding{};
    std::transform(digest.begin(), digest.end(), binding.begin(), [](auto value) { return std::byte(value); });
    return RuntimeOriginalOptions(run, "apfs-vol:" + container + ":" + std::to_string(oid), binding);
}
void RuntimeOpenDiagnostic(const std::filesystem::path& run)
{
    std::string error; const auto options = RuntimeOptions(run);
    auto owner = c::ApfsEncryptedImageWriteSession::Open(options.image, error);
    if (!owner) { std::cout << "OPEN_DIAG owner=false error=" << error << '\n'; return; }
    const auto wal_options = RuntimeOriginalOptions(run, *owner);
    Wal wal(wal_options); const auto ordinary = wal.ReadAll(); const auto exclusive = wal.ReadAllWithExclusiveWriterLease();
    std::cout << "OPEN_DIAG owner=true volume=" << wal_options.volume_identity << " readonly=" << static_cast<unsigned>(ordinary.status)
        << " exclusive=" << static_cast<unsigned>(exclusive.status) << " lastWin32=" << GetLastError()
        << " limit=" << options.journal_bytes << '\n';
}
int RuntimeInspectOriginal(const std::filesystem::path& run, unsigned phase)
{
    std::string error;
    Wal wal(RuntimeCapturedOriginalOptions(run, phase)); auto read = wal.ReadAll();
    Check(read.status == Wal::ReadStatus::Ok, "RuntimeOriginalProtectedRead");
    const Wal::Record* accepted = nullptr;
    for (const auto& record : read.records)
        if (record.operation == Wal::OperationKind::TransactionMarker && record.state == Wal::RecordState::Accepted &&
            (!accepted || record.sequence > accepted->sequence)) accepted = &record;
    Check(accepted && accepted->object_id == 6 + phase, "RuntimeOriginalExactPreimageXid");
    std::size_t count = 0; std::uint64_t length = 0;
    for (const auto& record : read.records) if (record.transaction_id == accepted->transaction_id && record.state == Wal::RecordState::Prepared) {
        Check(record.operation == Wal::OperationKind::Write && record.parent_object_id == accepted->object_id,
            "RuntimeOriginalGenerationAuthority");
        if (phase & 1) {
            Check(record.path_utf8 == Tx::WideToUtf8(std::wstring(Journal::MaintenanceAcceptancePath)) && record.object_id == 1026 &&
                !record.inline_payload.empty() && record.inline_payload.size() <= 4096 && record.logical_offset == length &&
                record.logical_length == record.inline_payload.size() && Wal::InlinePayloadIsConsistent(record), "RuntimeOriginalInlineCiphertextChunks");
        } else Check(record.path_utf8 == "encrypted-data" && record.object_id == 21 && record.logical_offset == 3 &&
            record.inline_payload.empty() && record.payload_length == 4097 && record.logical_length == 4097 &&
            record.payload_spool_id == record.sequence, "RuntimeOriginalActualProtectedSpoolReference");
        length += record.payload_length; ++count;
    }
    Check((phase & 1) ? count > 1 : count == 1, "RuntimeOriginalRecordSetShape");
    std::cout << "{\"authenticatedOriginal\":true,\"phase\":" << phase << ",\"preimageXid\":" << accepted->object_id
        << ",\"accepted\":" << accepted->sequence << ",\"records\":" << count << ",\"payloadBytes\":" << length
        << ",\"spooled\":" << ((phase & 1) ? "false" : "true") << "}\n";
    auto lease = std::make_shared<t::WindowsImageLease>(RuntimeOptions(run).image.path);
    t::OwnedEncryptedImageSource source(lease, 20480, 4153344);
    auto current = c::LoadContainerCheckpointView(source, 0, 4153344, error);
    Check(current && current->superblock.xid == 7 + phase && current->superblock.xp_desc_block_count <= 256,
        "RuntimeBagObservationCurrentCheckpoint");
    std::set<std::uint64_t> xids{current->superblock.xid};
    for (std::uint64_t i = 0; i < current->superblock.xp_desc_block_count; ++i) {
        std::vector<std::byte> block;
        Check(source.Read((current->superblock.xp_desc_base_block + i) * 4096, 4096, block), "RuntimeBagObservationRingRead");
        auto nx = c::ParseNxSuperblock(block);
        if (nx && nx->uuid_hex == current->superblock.uuid_hex && nx->xid < current->superblock.xid) xids.insert(nx->xid);
    }
    std::map<std::uint64_t, std::string> bags;
    for (auto xid : xids) {
        if (!c::LoadContainerCheckpointView(source, 0, 4153344, error, xid)) continue;
        c::UnlockError status{}; std::uint64_t container = 0, volume = 0;
        auto metadata = c::InspectPasswordKeybagMetadataAtCheckpoint(source, 1026, c::KeybagLength::IncludesHeader,
            xid, status, container, volume);
        Check(metadata && metadata->users.size() == 1, "RuntimeCanonicalHistoricalBagsValid");
        for (auto address : {container, volume}) {
            std::vector<std::byte> bytes; Check(source.Read(address * 4096, 4096, bytes), "RuntimeBagCiphertextRead");
            bags[address] = Digest(bytes);
        }
    }
    Check(bags.size() >= 4 && bags.size() <= 8, "RuntimeRetainedBagOwnerCount");
    std::ofstream bag_file(run / (PhaseName(phase) + L"-bags.txt"));
    bag_file << "E05RUNTIMEBAGS1\n" << bags.size() << '\n';
    for (const auto& [block, digest] : bags) bag_file << block << ' ' << digest << '\n';
    Check(static_cast<bool>(bag_file), "RuntimeBagObservationWrite");
    return 0;
}
int RuntimeRefusal(const std::filesystem::path& run, bool wrong_source)
{
    auto options = RuntimeOptions(run); const auto image = std::filesystem::path(options.image.path);
    const auto original = options.recovery_directory / L"original.wal", witness = options.recovery_directory / L"witness.wal";
    const auto before = DigestFile(image), original_before = DigestFile(original), witness_before = DigestFile(witness);
    std::string error;
    if (wrong_source) {
        options.image.path = (run / L"wrong-source.dmg").wstring();
        const auto other_before = DigestFile(options.image.path);
        auto runtime = RuntimeOpenObserved(options, error);
        Check(!runtime && error == "ProtectedJournalEvidenceInvalid", "RuntimeWrongSourceRefused");
        std::unique_ptr<c::ApfsEncryptedImageWriteSession> owner;
        for (unsigned attempt = 0; attempt < 4; ++attempt) {
            owner = c::ApfsEncryptedImageWriteSession::Open(options.image, error);
            if (owner || error.find("stage=FileOpen:win32=32:") == error.npos) break;
            Sleep(500);
        }
        Check(static_cast<bool>(owner), "RuntimeWrongSourceDiagnosticOwner");
        Wal wal(RuntimeOriginalOptions(run, *owner)); auto read = wal.ReadAll();
        Check(read.status == Wal::ReadStatus::VolumeMismatch, "RuntimeWrongSourceAuthenticatedBindingMismatch");
        owner->Close();
        Check(DigestFile(options.image.path) == other_before, "RuntimeWrongSourceImageUnchanged");
    } else {
        auto runtime = RuntimeOpenObserved(options, error); Check(static_cast<bool>(runtime), "RuntimeMissingAuthorityOwner");
        Check(!runtime->Recover(error) && !error.empty() && runtime->CachedStatus().recovery_required &&
            runtime->CachedStatus().accepted > runtime->CachedStatus().durable && !runtime->CachedStatus().image.key_present,
            "RuntimeMissingPrivateAuthorizationRefused");
        runtime->Close();
    }
    Check(DigestFile(image) == before && DigestFile(original) == original_before && DigestFile(witness) == witness_before,
        "RuntimeRefusalPreservesImageOriginalWitness");
    std::cout << "{\"refused\":true,\"wrongSource\":" << (wrong_source ? "true" : "false")
        << ",\"targetCalls\":0,\"imageOriginalWitnessUnchanged\":true}\n"; return 0;
}
int RuntimePhase(const std::filesystem::path& run, unsigned phase, std::wstring_view mode)
{
    Check(phase >= 1 && phase <= 4, "RuntimeDeclaredPhase");
    const bool maintenance = (phase & 1) != 0;
    std::string error; auto runtime = RuntimeOpenObserved(RuntimeOptions(run), error);
    if (!runtime) RuntimeOpenDiagnostic(run);
    Check(static_cast<bool>(runtime), ("RuntimeOpen:" + error).c_str());
    auto pair = maintenance ? ReceivePair() : Credentials{};
    auto single = maintenance ? k::SecureBytes{} : Receive();
    const auto& credential = maintenance ? pair.old_password : single;
    c::PasswordUnlockBudget unlock_budget;
    Check(runtime->Unlock(credential, unlock_budget, error), ("RuntimeFreshUnlock:" + error).c_str());
    auto expected = RuntimePayload(*runtime);
    const auto before = runtime->CachedStatus();
    Check(before.image.checkpoint_xid == 6 + phase && !before.recovery_required, "RuntimeFreshPreimageCheckpoint");
    {
        std::ofstream scope(run / (PhaseName(phase) + L"-scope.txt"));
        scope << std::quoted(runtime->SourceIdentity()) << '\n' << std::quoted(runtime->ContainerUuid()) << '\n'
            << std::quoted(runtime->VolumeUuid()) << '\n' << runtime->VolumeObjectId() << '\n';
        Check(static_cast<bool>(scope), "RuntimeCaptureActualPublicOwnerScope");
    }
    c::EncryptedReadError read{}; auto stale = runtime->OpenReadView(read);
    Check(static_cast<bool>(stale), "RuntimeRetainedOldView");
    std::atomic<std::uint64_t> polls{0}; std::atomic<bool> invalid{false};
    std::jthread observer([&](std::stop_token stop) {
        while (!stop.stop_requested() && polls.load() < 20000) {
            const auto status = runtime->CachedStatus();
            if (status.cleaned > status.durable || status.durable > status.accepted ||
                (status.image.phase == c::EncryptedImageWritePhase::Locked && status.image.key_present)) invalid.store(true);
            ++polls; std::this_thread::yield();
        }
    });
    if (maintenance && phase == 1 && mode == L"wrong-old") {
        auto wrong = RandomCredential(); c::PasswordUnlockBudget budget;
        Check(!runtime->ChangePassword(wrong, pair.new_password, budget, error), "RuntimeWrongOldRefused");
        const auto refused = runtime->CachedStatus();
        Check(refused.image.phase == c::EncryptedImageWritePhase::Ready && !refused.recovery_required &&
            refused.accepted == before.accepted && refused.image.checkpoint_xid == before.image.checkpoint_xid,
            "RuntimeWrongOldNoAcceptedDebt");
    }
    bool cut_seen = false, accepted_health = false;
    const auto hook = [&](std::string_view stage) {
        if (maintenance && stage == "after-encrypted-original-accept") {
            const auto status = runtime->CachedStatus();
            accepted_health = status.recovery_required && status.accepted > status.durable &&
                !status.image.key_present && status.image.phase == c::EncryptedImageWritePhase::Locked;
            std::vector<std::byte> bytes;
            const auto revoked = stale->ReadFile(21, 0, 1, bytes);
            Check((revoked == c::EncryptedReadError::Closed || revoked == c::EncryptedReadError::Cancelled) && bytes.empty(),
                "RuntimeAcceptedReaderRevoked");
        }
        if ((phase == 1 && mode == L"direct-unlock" && stage == "after-encrypted-original-accept") ||
            (phase == 3 && (((mode == L"before-stage" || mode == L"witness-eof" || mode == L"wrong-source" || mode == L"missing-authority" || mode == L"recovery-chain") && stage == "after-encrypted-original-accept") ||
            mode == L"torn-chain" && stage == "after-encrypted-original-accept" ||
            mode == L"before-switch" && stage == "before-apple-checkpoint-switch" ||
            mode == L"after-switch" && stage == "before-apple-final-flush")) ||
            (phase == 4 && (mode == L"data-before-switch" || mode == L"recovery-chain" || mode == L"torn-chain") && stage == "before-apple-checkpoint-switch")) { cut_seen = true; return false; }
        return true;
    };
    bool changed = false;
    if (maintenance) {
        c::PasswordUnlockBudget budget;
        changed = runtime->ChangePassword(pair.old_password, pair.new_password, budget, error, hook);
        Check(accepted_health, "RuntimeAcceptedCachedHealth");
    } else {
        std::vector<std::byte> payload(4097);
        for (std::size_t i = 0; i < payload.size(); ++i) payload[i] = std::byte((i * 29 + i / 97 + 61 + phase) % 251);
        expected.resize(4100); std::copy(payload.begin(), payload.end(), expected.begin() + 3);
        std::size_t completed = 0;
        changed = runtime->Write(21, 3, payload, completed, error, hook);
        Check(cut_seen ? !changed && !completed : changed && completed == payload.size(), ("RuntimeFreshSpooledWrite:" + error).c_str());
    }
    SaveEraExpected(run, phase, Digest(expected));
    std::ofstream length(run / (PhaseName(phase) + L"-length.txt")); length << expected.size() << '\n'; length.close();
    const auto status = runtime->CachedStatus();
    if (cut_seen) {
        Check(!changed && status.recovery_required && status.accepted > status.durable && (!maintenance || !status.image.key_present),
            "RuntimeMaintenanceCutPreservesDebt");
    } else {
        Check(changed, ("RuntimeMaintenancePublication:" + error).c_str()); RuntimeClean(status, phase, maintenance);
        if (maintenance) {
            std::size_t completed = 0; const std::byte byte{0x33};
            Check(!runtime->Write(21, 0, std::span(&byte, 1), completed, error) && !completed,
                "RuntimeFreshUnlockRequiredAfterPasswordChange");
            Check(!runtime->OpenReadView(read), "RuntimePostChangeReaderLocked");
        } else Check(Sha(RuntimePayload(*runtime)) == Sha(expected), "RuntimeActualChangedPayload");
    }
    observer.request_stop(); observer.join();
    Check(polls.load() > 0 && !invalid.load(), "RuntimeCachedHealthConcurrentPolling");
    pair.old_password.Clear(); pair.new_password.Clear(); single.Clear(); runtime->Close();
    std::cout << "{\"phase\":" << phase << ",\"published\":" << (changed ? "true" : "false")
        << ",\"cut\":" << (cut_seen ? "true" : "false") << ",\"xid\":" << status.image.checkpoint_xid
        << ",\"accepted\":" << status.accepted << ",\"durable\":" << status.durable << ",\"cleaned\":" << status.cleaned
        << ",\"cachedPolls\":" << polls.load() << ",\"postChangeLocked\":" << (maintenance ? "true" : "false") << "}\n";
    return 0;
}
int RuntimeRecover(const std::filesystem::path& run, unsigned phase)
{
    std::string error; auto runtime = RuntimeOpenObserved(RuntimeOptions(run), error);
    Check(static_cast<bool>(runtime), ("RuntimeRecoveryOpen:" + error).c_str());
    Check(runtime->CachedStatus().recovery_required && !runtime->CachedStatus().image.key_present,
        "RuntimeFreshRecoveryNoKey");
    Check(runtime->Recover(error), ("RuntimeKeylessMaintenanceRecovery:" + error).c_str());
    RuntimeClean(runtime->CachedStatus(), phase, true);
    Check(runtime->Recover(error), "RuntimeMaintenanceRecoveryIdempotent");
    const auto status = runtime->CachedStatus(); runtime->Close();
    std::cout << "{\"keylessRecovered\":true,\"xid\":" << status.image.checkpoint_xid << ",\"accepted\":" << status.accepted
        << ",\"durable\":" << status.durable << ",\"cleaned\":" << status.cleaned << "}\n"; return 0;
}
int RuntimeRecoveryCut(const std::filesystem::path& run, std::string_view barrier)
{
    std::string error; auto runtime = RuntimeOpenObserved(RuntimeOptions(run), error);
    Check(runtime && runtime->CachedStatus().recovery_required && !runtime->CachedStatus().image.key_present,
        "RuntimeKeylessCutOwner");
    bool seen = false;
    const bool recovered = runtime->Recover(error, [&](std::string_view stage) {
        if (stage == barrier) { seen = true; return false; } return true;
    });
    const auto status = runtime->CachedStatus();
    Check(!recovered && seen && status.recovery_required && status.accepted > status.durable && !status.image.key_present,
        "RuntimeKeylessCutRetainsAcceptedDebt");
    runtime->Close();
    std::cout << "{\"keylessRecoveryCut\":true,\"stage\":\"" << barrier << "\",\"accepted\":" << status.accepted
        << ",\"durable\":" << status.durable << ",\"cleaned\":" << status.cleaned << "}\n"; return 0;
}
void RuntimeWitnessTear(const std::filesystem::path& run)
{
    const auto witness = run / L"rt" / L"witness.wal";
    Check(CopyFileW(witness.c_str(), (run / L"witness-complete.wal").c_str(), TRUE), "RuntimePreserveCompleteWitness");
    const auto size = std::filesystem::file_size(witness); Check(size > 65536, "RuntimeRealAuthorizationWitnessSize");
    std::filesystem::resize_file(witness, size - 1);
    Check(CopyFileW(witness.c_str(), (run / L"witness-damaged.wal").c_str(), TRUE), "RuntimePreserveActualEofTear");
}
void RuntimeTornSwitch(const std::filesystem::path& run, unsigned phase)
{
    const auto image = run / Profile{false}.Name();
    std::uint64_t physical_block = 0; std::vector<std::byte> planned;
    {
        auto lease = std::make_shared<t::WindowsImageLease>(image.wstring());
        t::OwnedEncryptedImageSource source(lease, 20480, 4153344);
        std::string error; auto current = c::LoadContainerCheckpointView(source, 0, 4153344, error);
        Check(current && current->superblock.xid == 7 + phase && current->superblock_physical_block,
            "RuntimeWrittenSwitchBeforeWatermark");
        physical_block = current->superblock_physical_block; planned = current->superblock_bytes;
    }
    std::vector<std::byte> prior(4096);
    std::ifstream preimage(run / (PhaseName(phase) + L"-preimage.dmg"), std::ios::binary);
    preimage.seekg(static_cast<std::streamoff>(20480 + physical_block * 4096));
    preimage.read(reinterpret_cast<char*>(prior.data()), 4096);
    Check(preimage && planned.size() == 4096, "RuntimeExactOldSwitchSlot");
    auto torn = prior; std::copy_n(planned.begin(), 32, torn.begin());
    Check(torn != prior && torn != planned && !c::ParseNxSuperblock(torn), "RuntimeProperSwitchPrefixOutcome");
    Check(CopyFileW(image.c_str(), (run / (PhaseName(phase) + L"-switch-complete.dmg")).c_str(), TRUE),
        "RuntimePreserveWrittenSwitchImage");
    {
        Handle file(CreateFileW(image.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        Check(file.h != INVALID_HANDLE_VALUE, "RuntimePrivateSwitchOutcomeHandle");
        LARGE_INTEGER at{}; at.QuadPart = static_cast<LONGLONG>(20480 + physical_block * 4096); DWORD written = 0;
        Check(SetFilePointerEx(file.h, at, nullptr, FILE_BEGIN) && WriteFile(file.h, torn.data(), 4096, &written, nullptr) &&
            written == 4096 && FlushFileBuffers(file.h), "RuntimePersistExactTornSwitchOutcome");
    }
    Check(CopyFileW(image.c_str(), (run / (PhaseName(phase) + L"-switch-torn.dmg")).c_str(), TRUE), "RuntimePreserveTornSwitchImage");
    std::ofstream evidence(run / (PhaseName(phase) + L"-switch-tear.json"));
    evidence << "{\"simulatedPrefixBytes\":32,\"physicalBlock\":" << physical_block << ",\"plannedSha256\":\"" << Digest(planned)
        << "\",\"oldSlotSha256\":\"" << Digest(prior) << "\",\"tornSha256\":\"" << Digest(torn) << "\"}\n";
    Check(static_cast<bool>(evidence), "RuntimeSwitchOutcomeEvidence");
}
DWORD RuntimePhaseChild(const std::filesystem::path& executable, const std::wstring& arguments,
    Bytes credential, const std::filesystem::path& run, unsigned phase)
{
    const auto image = run / Profile{false}.Name(); const auto before = DigestFile(image);
    for (unsigned attempt = 0; attempt < 4; ++attempt) {
        const auto log = run / (PhaseName(phase) + L"-attempt-" + std::to_wstring(attempt) + L".log");
        const auto code = Child(executable, arguments, credential, log);
        if (!code) {
            Check(CopyFileW(log.c_str(), (run / (PhaseName(phase) + L"-runtime.log")).c_str(), TRUE), "RuntimePreserveSuccessfulAttempt");
            return 0;
        }
        std::ifstream input(log); const std::string reason((std::istreambuf_iterator<char>(input)), {});
        const bool sharing = reason.size() < 4096 && reason.find("stage=FileOpen:win32=32:") != reason.npos;
        const auto recovery = RuntimeOptions(run).recovery_directory;
        if (!sharing || std::filesystem::exists(recovery / L"original.wal") || std::filesystem::exists(recovery / L"witness.wal") ||
            DigestFile(image) != before) return code;
        Sleep(500);
    }
    return 1;
}
int RuntimeDirectUnlock(const std::filesystem::path& run, bool missing_authority, bool old_credential)
{
    const auto options = RuntimeOptions(run); const auto image = std::filesystem::path(options.image.path);
    const auto original = options.recovery_directory / L"original.wal", witness = options.recovery_directory / L"witness.wal";
    const auto image_before = DigestFile(image), original_before = DigestFile(original), witness_before = DigestFile(witness);
    std::string error; auto runtime = RuntimeOpenObserved(options, error);
    Check(static_cast<bool>(runtime), ("RuntimeDirectUnlockOpen:" + error).c_str());
    const auto before = runtime->CachedStatus();
    Check(!before.image.key_present && (old_credential ? before.accepted == 60 && before.durable == 60 && before.cleaned == 60 :
        before.recovery_required && before.accepted > before.durable), "RuntimeDirectUnlockInitialDebt");
    auto password = Receive(); c::PasswordUnlockBudget budget;
    const bool unlocked = runtime->Unlock(password, budget, error); password.Clear();
    const auto status = runtime->CachedStatus();
    if (missing_authority || old_credential) {
        Check(!unlocked && !error.empty() && !status.image.key_present &&
            (old_credential ? status.accepted == before.accepted && status.durable == before.durable && status.cleaned == before.cleaned :
                status.recovery_required && status.accepted > status.durable),
            "RuntimeDirectUnlockRefused");
        runtime->Close();
        Check(DigestFile(image) == image_before && DigestFile(original) == original_before && DigestFile(witness) == witness_before,
            "RuntimeDirectUnlockRefusalPreservesImageOriginalWitness");
    } else {
        Check(unlocked, ("RuntimeDirectUnlockRecovered:" + error).c_str()); RuntimeClean(status, 1, false);
        Check(status.accepted == 60 && Digest(RuntimePayload(*runtime)) == EraExpected(run, 1), "RuntimeDirectUnlockLatestPayload");
    }
    runtime->Close();
    std::cout << "{\"directUnlock\":true,\"unlocked\":" << (unlocked ? "true" : "false")
        << ",\"missingAuthorization\":" << (missing_authority ? "true" : "false") << ",\"oldCredential\":" << (old_credential ? "true" : "false")
        << ",\"xid\":" << status.image.checkpoint_xid << ",\"accepted\":" << status.accepted << ",\"durable\":" << status.durable
        << ",\"cleaned\":" << status.cleaned << ",\"explicitRecoverCalled\":false,\"refusalBytesPreserved\":"
        << (missing_authority || old_credential ? "true" : "false") << "}\n"; return 0;
}
int RuntimeDirectUnlockDriver(const std::filesystem::path& executable)
{
    const Profile profile{false}; const auto original = std::filesystem::path(fixtures) / profile.Name();
    const auto run = std::filesystem::path(runtime_root) / (L"run-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64()));
    Check(std::filesystem::create_directory(run), "RuntimeDirectUnlockPrivateDirectory");
    const auto image = run / profile.Name();
    Check(DigestFile(original) == profile.Pin() && CopyFileW(original.c_str(), image.c_str(), TRUE) &&
        CopyFileW(image.c_str(), (run / L"phase-1-preimage.dmg").c_str(), TRUE), "RuntimeDirectUnlockAuthenticCopy");
    auto old_password = NoteCredential(profile), new_password = RandomCredential();
    auto pair = Pair(old_password.Bytes(), new_password.Bytes());
    Check(RuntimePhaseChild(executable, L"runtime-phase " + Quoted(run) + L" 1 direct-unlock", pair.Bytes(), run, 1) == 0,
        "RuntimeDirectUnlockAcceptedBeforeStage"); pair.Clear();
    const auto witness = run / L"rt" / L"witness.wal";
    Check(CopyFileW(witness.c_str(), (run / L"witness-authentic.wal").c_str(), TRUE), "RuntimeDirectUnlockPreserveAuthorization");
    std::filesystem::resize_file(witness, 0);
    Check(Child(executable, L"runtime-direct-missing " + Quoted(run), new_password.Bytes(), run / L"direct-missing.log") == 0,
        "RuntimeDirectUnlockMissingAuthorityControl");
    Check(CopyFileW((run / L"witness-authentic.wal").c_str(), witness.c_str(), FALSE), "RuntimeDirectUnlockRestoreExactAuthorization");
    Check(Child(executable, L"runtime-direct-unlock " + Quoted(run), new_password.Bytes(), run / L"direct-unlock.log") == 0,
        "RuntimeFreshDirectUnlockChild");
    Check(Child(executable, L"runtime-direct-old " + Quoted(run), old_password.Bytes(), run / L"direct-old-refusal.log") == 0,
        "RuntimeFreshDirectOldCredentialRefusal");
    Check(Child(executable, L"runtime-inspect " + Quoted(run) + L" 1", {}, run / L"phase-1-original.log") == 0 &&
        CopyFileW(image.c_str(), (run / L"phase-1-postimage.dmg").c_str(), TRUE), "RuntimeDirectUnlockCanonicalEvidence");
    const auto expected = EraExpected(run, 1);
    Check(Child(executable, L"runtime-oracle " + Quoted(image) + L" " + std::wstring(expected.begin(), expected.end()) + L" 22",
        new_password.Bytes(), run / L"phase-1-oracle-active.log") == 0, "RuntimeDirectUnlockIndependentNewPassword");
    Check(Child(executable, L"runtime-oracle " + Quoted(image) + L" refuse 22", old_password.Bytes(),
        run / L"phase-1-oracle-initial-refused.log") == 0, "RuntimeDirectUnlockIndependentOldRefusal");
    for (const auto& item : std::filesystem::recursive_directory_iterator(run)) if (item.is_regular_file())
        Absent(item.path(), old_password.Bytes(), new_password.Bytes());
    Check(DigestFile(original) == profile.Pin(), "RuntimeDirectUnlockOriginalPreserved");
    std::cout << "{\"actualRuntimePublications\":1,\"independentCredentialPayloadChecks\":2,\"directUnlockRecovered\":true,\"allCredentialBytesAbsent\":true}\n";
    std::wcout << L"EVIDENCE " << run.wstring() << '\n'; return 0;
}
int RuntimeDriver(const std::filesystem::path& executable, std::wstring_view mode)
{
    if (mode == L"direct-unlock") return RuntimeDirectUnlockDriver(executable);
    Check(mode == L"normal" || mode == L"wrong-old" || mode == L"before-stage" || mode == L"before-switch" ||
        mode == L"after-switch" || mode == L"witness-eof" || mode == L"wrong-source" || mode == L"missing-authority" ||
        mode == L"data-before-switch" || mode == L"recovery-chain" || mode == L"torn-chain", "RuntimeDeclaredCase");
    const Profile profile{false}; const auto original = std::filesystem::path(fixtures) / profile.Name();
    const auto run = std::filesystem::path(runtime_root) / (L"run-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
        std::to_wstring(GetTickCount64()));
    Check(std::filesystem::create_directory(run), "RuntimePrivateDirectory");
    const auto image = run / profile.Name();
    Check(DigestFile(original) == profile.Pin() && CopyFileW(original.c_str(), image.c_str(), TRUE), "RuntimeAuthenticPrivateCopy");
    Sleep(300);
    auto initial = NoteCredential(profile), first = RandomCredential(), latest = RandomCredential();
    for (unsigned phase = 1; phase <= 4; ++phase) {
        const auto tag = PhaseName(phase); const auto args = Quoted(run) + L" " + std::to_wstring(phase);
        Check(CopyFileW(image.c_str(), (run / (tag + L"-preimage.dmg")).c_str(), TRUE), "RuntimePreservePreimage");
        if (phase & 1) {
            auto pair = Pair(phase == 1 ? initial.Bytes() : first.Bytes(), phase == 1 ? first.Bytes() : latest.Bytes());
            Check(RuntimePhaseChild(executable, L"runtime-phase " + args + L" " + std::wstring(mode), pair.Bytes(), run, phase) == 0,
                "RuntimeActualMaintenanceChild");
        } else Check(RuntimePhaseChild(executable, L"runtime-phase " + args + L" " + std::wstring(mode), phase == 2 ? first.Bytes() : latest.Bytes(),
            run, phase) == 0, "RuntimeActualFreshDataChild");
        if ((phase == 3 && mode != L"normal" && mode != L"wrong-old" && mode != L"data-before-switch") ||
            (phase == 4 && (mode == L"data-before-switch" || mode == L"recovery-chain" || mode == L"torn-chain"))) {
            if (mode == L"wrong-source" || (mode == L"recovery-chain" && phase == 3)) {
                Check(CopyFileW(image.c_str(), (run / L"wrong-source.dmg").c_str(), TRUE), "RuntimePrivateWrongSourceCopy");
                Check(Child(executable, L"runtime-source-refusal " + Quoted(run), {}, run / L"source-refusal.log") == 0,
                    "RuntimeWrongSourceRefusalChild");
            }
            if (mode == L"missing-authority" || (mode == L"recovery-chain" && phase == 3)) {
                const auto witness = run / L"rt" / L"witness.wal";
                Check(CopyFileW(witness.c_str(), (run / L"witness-authentic.wal").c_str(), TRUE), "RuntimePreserveAuthenticPrivateAuthorization");
                std::filesystem::resize_file(witness, 0);
                Check(Child(executable, L"runtime-authority-refusal " + Quoted(run), {}, run / L"authority-refusal.log") == 0,
                    "RuntimeMissingAuthorizationRefusalChild");
                Check(CopyFileW((run / L"witness-authentic.wal").c_str(), witness.c_str(), FALSE), "RuntimeRestoreExactPreservedAuthorization");
            }
            if (mode == L"witness-eof" || (mode == L"recovery-chain" && phase == 3)) RuntimeWitnessTear(run);
            if (mode == L"recovery-chain" || mode == L"torn-chain") {
                const std::vector<std::wstring> barriers = phase == 3 && mode == L"recovery-chain"
                    ? std::vector<std::wstring>{L"before-apple-device-write", L"before-apple-checkpoint-switch", L"before-apple-final-flush"}
                    : std::vector<std::wstring>{L"before-apple-final-flush"};
                for (std::size_t i = 0; i < barriers.size(); ++i)
                    Check(Child(executable, L"runtime-recover-cut " + Quoted(run) + L" " + barriers[i], {},
                        run / (tag + L"-recover-cut-" + std::to_wstring(i) + L".log")) == 0, "RuntimeFreshKeylessDeclaredCut");
                if (mode == L"torn-chain") RuntimeTornSwitch(run, phase);
            }
            Check(Child(executable, L"runtime-recover " + args, {}, run / (tag + L"-recovery.log")) == 0,
                "RuntimeFreshKeylessRecoveryChild");
        }
        Check(Child(executable, L"runtime-inspect " + args, {}, run / (tag + L"-original.log")) == 0,
            "RuntimeActualAuthenticatedOriginalChild");
        Check(CopyFileW(image.c_str(), (run / (tag + L"-postimage.dmg")).c_str(), TRUE), "RuntimePreservePostimage");
        std::size_t length = 0; std::ifstream lengths(run / (tag + L"-length.txt")); lengths >> length;
        Check(length > 0 && length <= 8192, "RuntimeExpectedPublicLength");
        const auto expected = EraExpected(run, phase);
        const auto base = L"runtime-oracle " + Quoted(image) + L" " + std::wstring(expected.begin(), expected.end()) + L" " + std::to_wstring(length);
        const auto& active = phase <= 2 ? first : latest;
        Check(Child(executable, base, active.Bytes(), run / (tag + L"-oracle-active.log")) == 0, "RuntimeIndependentActiveAndPayload");
        Check(Child(executable, L"runtime-oracle " + Quoted(image) + L" refuse " + std::to_wstring(length), initial.Bytes(),
            run / (tag + L"-oracle-initial-refused.log")) == 0, "RuntimeIndependentOldRefused");
        if (phase >= 3) Check(Child(executable, L"runtime-oracle " + Quoted(image) + L" refuse " + std::to_wstring(length), first.Bytes(),
            run / (tag + L"-oracle-intermediate-refused.log")) == 0, "RuntimeIndependentIntermediateRefused");
        for (const auto& entry : std::filesystem::recursive_directory_iterator(run)) if (entry.is_regular_file()) {
            Absent(entry.path(), initial.Bytes(), first.Bytes()); Absent(entry.path(), initial.Bytes(), latest.Bytes());
        }
    }
    Check(DigestFile(original) == profile.Pin(), "RuntimeOriginalPreserved");
    std::cout << "{\"actualRuntimePublications\":4,\"independentCredentialPayloadChecks\":10,\"allCredentialBytesAbsent\":true,\"e05Complete\":false}\n";
    std::wcout << L"EVIDENCE " << run.wstring() << '\n'; return 0;
}
}
int wmain(int argc, wchar_t** argv)
{
    try {
        if (argc == 3 && std::wstring_view(argv[1]) == L"drive-keybag-runtime") return RuntimeDriver(argv[0], argv[2]);
        if (argc == 5 && std::wstring_view(argv[1]) == L"runtime-phase") return RuntimePhase(argv[2], static_cast<unsigned>(std::stoul(argv[3])), argv[4]);
        if (argc == 4 && std::wstring_view(argv[1]) == L"runtime-recover") return RuntimeRecover(argv[2], static_cast<unsigned>(std::stoul(argv[3])));
        if (argc == 4 && std::wstring_view(argv[1]) == L"runtime-recover-cut") return RuntimeRecoveryCut(argv[2], Tx::WideToUtf8(argv[3]));
        if (argc == 4 && std::wstring_view(argv[1]) == L"runtime-inspect") return RuntimeInspectOriginal(argv[2], static_cast<unsigned>(std::stoul(argv[3])));
        if (argc == 3 && std::wstring_view(argv[1]) == L"runtime-source-refusal") return RuntimeRefusal(argv[2], true);
        if (argc == 3 && std::wstring_view(argv[1]) == L"runtime-authority-refusal") return RuntimeRefusal(argv[2], false);
        if (argc == 3 && std::wstring_view(argv[1]) == L"runtime-direct-unlock") return RuntimeDirectUnlock(argv[2], false, false);
        if (argc == 3 && std::wstring_view(argv[1]) == L"runtime-direct-missing") return RuntimeDirectUnlock(argv[2], true, false);
        if (argc == 3 && std::wstring_view(argv[1]) == L"runtime-direct-old") return RuntimeDirectUnlock(argv[2], false, true);
        if (argc == 5 && std::wstring_view(argv[1]) == L"runtime-oracle") return EraOracle(argv[2], Tx::WideToUtf8(argv[3]), std::stoull(argv[4]));
        return KeybagEraMain(argc, argv);
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
