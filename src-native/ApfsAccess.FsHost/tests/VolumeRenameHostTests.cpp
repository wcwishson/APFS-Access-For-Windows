#define main UnusedFullSemanticsMain587
#include "FsHostSemanticsTests.cpp"
#undef main

namespace
{
unsigned rename_checks = 0;
void RenameCheck(bool value, const char* message)
{
    ++rename_checks;
    if (!value) throw std::runtime_error(message);
}
bool RenameRootMetadataIsolation()
{
    MountContext c{}; c.native_write_enabled = true; SeedRoot(c);
    c.api.AddDir = [](FSP_FSCTL_DIR_INFO*, PVOID, ULONG, PULONG) -> BOOLEAN { return TRUE; };
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:BAG:BAD:P(A;;FR;;;WD)",
            SDDL_REVISION_1, &sd, nullptr)) return false;
    ScopeExit free_sd{[&] { LocalFree(sd); }};
    c.sd = sd; c.sd_size = GetSecurityDescriptorLength(sd);
    auto fs = BuildFileSystem(&c);
    std::unique_lock metadata(c.metadata_mutex);
    auto query = std::async(std::launch::async, [&] {
        UINT32 attrs = 0; SIZE_T size = c.sd_size; std::vector<std::byte> security(size);
        const auto security_status = CB_GetSecurityByName(&fs, const_cast<PWSTR>(L"\\"), &attrs, security.data(), &size);
        if (security_status != STATUS_SUCCESS)
        { std::cerr << "root security=" << std::hex << security_status << "\n"; return false; }
        PVOID handle = nullptr; FSP_FSCTL_FILE_INFO info{};
        const auto attributes_open = CB_Open(&fs, const_cast<PWSTR>(L"\\"), (FILE_OPEN << 24) | FILE_DIRECTORY_FILE,
            FILE_READ_ATTRIBUTES | SYNCHRONIZE, &handle, &info);
        if (attributes_open != STATUS_SUCCESS) return false;
        const auto attributes_query = CB_GetFileInfo(&fs, handle, &info);
        CB_Cleanup(&fs, handle, nullptr, FspCleanupSetLastAccessTime); CB_Close(&fs, handle);
        if (attributes_query != STATUS_SUCCESS) return false;
        handle = nullptr;
        const auto open_status = CB_Open(&fs, const_cast<PWSTR>(L"\\"), (FILE_OPEN << 24) | FILE_DIRECTORY_FILE,
                FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY, &handle, &info);
        if (open_status != STATUS_SUCCESS)
        { std::cerr << "root open=" << std::hex << open_status << "\n"; return false; }
        const auto status = CB_GetFileInfo(&fs, handle, &info);
        std::array<std::byte, 1024> entries{}; ULONG done = 0;
        const auto listing = CB_ReadDirectory(&fs, handle, nullptr, nullptr, entries.data(), static_cast<ULONG>(entries.size()), &done);
        CB_Cleanup(&fs, handle, nullptr, 0); CB_Close(&fs, handle);
        // An empty root intentionally returns EOF directly (no dot entries).
        return status == STATUS_SUCCESS && listing == STATUS_NO_MORE_FILES;
    });
    const bool responsive = query.wait_for(std::chrono::milliseconds(250)) == std::future_status::ready;
    metadata.unlock();
    if (!responsive) std::cerr << "root metadata callback waited on metadata lock\n";
    return query.get() && responsive;
}
void RunRenameHostCase(std::string_view scenario)
{
    if (scenario == "shell-isolation")
    {
        RenameCheck(TestVolumeInfoDoesNotWaitOnMetadataMutex(), "cached volume query isolation");
        RenameCheck(RenameRootMetadataIsolation(), "root metadata isolation with a valid security descriptor");
        RenameCheck(TestMetadataOnlyRegularFileDoesNotWaitOnCommit(), "regular-file metadata isolation");
        return;
    }
    NativeCloneHost500Fixture fixture;
    RenameCheck(fixture.Initialize(false, false, 0, false, false, true), "native manifest fixture initializes");
    auto& c = *fixture.fixture.context;
    c.label = L"Alpha";
    c.args.status_file = (c.session_root / "rename-status.json").wstring();
    const auto original_args = c.args.volume;
    const auto original_identity = c.payload_spool_volume_identity;
    const auto original_session = c.session_root, original_marker = c.recovery_marker_file;
    const auto preimage = c.metadata_store->CheckpointXid();
    const auto original = ReadFileBytes(fixture.fixture.image.path);
    FSP_FSCTL_VOLUME_INFO info{};
    if (scenario == "container-status")
    {
        auto label = std::wstring(35, L'R') + L"\"quoted";
        RenameCheck(CB_SetVolumeLabel(&fixture.fs, label.data(), &info) == STATUS_SUCCESS,
            "publish authoritative label longer than Explorer display limit");
        c.args.volume = L"stale display hint";
        std::vector<std::unique_ptr<MountContext>> contexts;
        contexts.push_back(std::move(fixture.fixture.context));
        ScopeExit restore{[&] { fixture.fixture.context = std::move(contexts.front()); }};
        RenameCheck(WriteContainerStatusFile(c.args, *fixture.fixture.coordinator, contexts),
            "publish container status from admitted native session");
        const auto bytes = ReadFileBytes(c.args.status_file);
        const std::string status(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        RenameCheck(status.find("\"volumeLabel\":\"" + EscapeJson(WideToUtf8(label)) + "\"") != std::string::npos &&
            status.find("stale display hint") == std::string::npos,
            "full escaped durable name survives container status independently of launch hint");
        return;
    }
    if (scenario == "shutdown")
    {
        std::promise<void> accepted, release;
        auto release_gate = release.get_future().share();
        bool signaled = false;
        c.tx_manager->SetJournalFaultInjectionHook([&](std::string_view stage) {
            if (stage == "durable-flush" && !signaled)
            {
                signaled = true; accepted.set_value(); release_gate.wait();
            }
            return false;
        });
        auto rename = std::async(std::launch::async, [&] {
            auto input = std::wstring(L"ShutdownSafe");
            return CB_SetVolumeLabel(&fixture.fs, input.data(), &info);
        });
        const bool reached = accepted.get_future().wait_for(std::chrono::seconds(5)) == std::future_status::ready;
        if (!reached) { release.set_value(); (void)rename.get(); RenameCheck(false, "rename reaches acceptance"); }
        auto successor = std::async(std::launch::async, [&] {
            const bool acquired = c.mutation_callback_mutex.try_lock();
            if (acquired) c.mutation_callback_mutex.unlock();
            return !acquired;
        });
        const bool isolated = successor.get();
        auto shutdown = std::async(std::launch::async, [&] { return BeginMutationShutdownDrain(&c); });
        const auto deadline = GetTickCount64() + 2000;
        while (!MutationAdmissionIsDraining(c.mutation_admission_state.load()) && GetTickCount64() < deadline)
            std::this_thread::yield();
        const bool draining = MutationAdmissionIsDraining(c.mutation_admission_state.load());
        const bool waiting = shutdown.wait_for(std::chrono::milliseconds(100)) != std::future_status::ready;
        auto refused_label = std::wstring(L"TooLate"); FSP_FSCTL_VOLUME_INFO ignored{};
        const auto refused = draining ? CB_SetVolumeLabel(&fixture.fs, refused_label.data(), &ignored) : STATUS_UNSUCCESSFUL;
        release.set_value();
        const auto status = rename.get(); const bool drained = shutdown.get();
        RenameCheck(isolated && draining && waiting && refused == STATUS_VOLUME_DISMOUNTED,
            "rename retains mutation ownership and shutdown rejects new callbacks while waiting for it");
        RenameCheck(status == STATUS_SUCCESS && drained && c.label == L"ShutdownSafe" &&
            c.tx_manager->Watermarks().accepted_sequence == c.tx_manager->Watermarks().cleanup_sequence,
            "shutdown drain finishes only after durable rename and cleanup");
        return;
    }
    if (scenario == "label-isolation" || scenario == "refresh-isolation")
    {
        // Namespace work can include slow filesystem operations. Neither the
        // cached volume query nor label publication may join that lock chain.
        std::unique_lock names(c.mutex);
        auto query = std::async(std::launch::async, [&] {
            if (scenario == "label-isolation")
                return CB_GetVolumeInfo(&fixture.fs, &info) == STATUS_SUCCESS;
            std::lock_guard commit(c.commit_mutex);
            std::unique_lock reads(c.committed_read_gate);
            std::lock_guard metadata(c.metadata_mutex);
            std::lock_guard journal(c.tx_mutex);
            return RefreshNativeVolumeLabel(c, false);
        });
        const bool responsive = query.wait_for(std::chrono::milliseconds(250)) == std::future_status::ready;
        names.unlock();
        const bool succeeded = query.get();
        RenameCheck(succeeded && responsive, "volume label access must not wait on namespace work");
        return;
    }
    if (scenario == "display-boundary")
    {
        for (const auto& [label, expected] : std::vector<std::pair<std::wstring, std::wstring>>{
                {std::wstring(32, L'x'), std::wstring(31, L'x')},
                {std::wstring(30, L'x') + L"🚀", std::wstring(30, L'x')},
                {std::wstring(29, L'x') + L"🚀", std::wstring(29, L'x') + L"🚀"}})
        {
            auto input = label;
            RenameCheck(CB_SetVolumeLabel(&fixture.fs, input.data(), &info) == STATUS_SUCCESS,
                "long valid label durably renames");
            RenameCheck(info.VolumeLabelLength <= 31 * sizeof(WCHAR) &&
                std::wstring(info.VolumeLabel, info.VolumeLabelLength / sizeof(WCHAR)) == expected && c.label == label,
                "31 WCHAR display limit preserves full durable label and complete surrogate pairs");
        }
        return;
    }
    if (scenario == "invalid")
    {
        for (const auto& label : std::vector<std::wstring>{L"", std::wstring(256, L'x'), std::wstring(1, wchar_t(0xd800)), std::wstring(100, L'研')})
        {
            auto input = label;
            RenameCheck(CB_SetVolumeLabel(&fixture.fs, input.data(), &info) == STATUS_OBJECT_NAME_INVALID, "invalid UTF-16/long label refused");
            RenameCheck(c.label == L"Alpha" && c.metadata_store->CheckpointXid() == preimage &&
                c.tx_manager->Watermarks().accepted_sequence == 0 && ReadFileBytes(fixture.fixture.image.path) == original,
                "invalid callback leaves label/image/acceptance unchanged");
        }
        return;
    }
    bool old_at_acceptance = false;
    if (scenario == "success")
    {
        RenameCheck(fixture.Open(), "open native handle before rename");
        std::vector<std::byte> payload(fixture.original.size()); ULONG done = 0;
        RenameCheck(CB_Read(&fixture.fs, fixture.source, payload.data(), 0, static_cast<ULONG>(payload.size()), &done) == STATUS_SUCCESS &&
            done == payload.size() && payload == fixture.original, "prime existing read cache before rename");
    }
    c.tx_manager->SetJournalFaultInjectionHook([&](std::string_view stage) {
        if (stage == "durable-flush" && !old_at_acceptance)
        {
            RenameCheck(c.label == L"Alpha" && c.metadata_store->CheckpointXid() == preimage, "label hidden before durable publication");
            old_at_acceptance = true;
        }
        return scenario == "acceptance-failure" && stage == "durable-flush";
    });
    if (scenario == "publication-failure")
        c.metadata_store->SetCommitStageHook([](std::string_view stage) { return stage != "before-apple-checkpoint-switch"; });
    auto label = std::wstring(L"研究资料 🚀");
    const auto result = CB_SetVolumeLabel(&fixture.fs, label.data(), &info);
    if (scenario != "success")
    {
        RenameCheck(!NT_SUCCESS(result) && c.label == L"Alpha" && c.recovery_active && !IsMutationWriteEnabled(&c),
            "failed callback preserves display and latches canonical recovery");
        RenameCheck(c.tx_manager->Watermarks().cleanup_sequence == 0 && c.metadata_store->CheckpointXid() == preimage,
            "failed callback never cleans accepted preimage");
        // Restart the actual host bootstrap with its original journal and marker.
        auto restarted = std::make_unique<MountContext>();
        restarted->args = c.args; restarted->session_root = c.session_root; restarted->cache_root = c.cache_root;
        restarted->args.write_crash_replay_mode = L"ReplayIfSafe";
        restarted->recovery_marker_file = c.recovery_marker_file;
        ResetRecoveryMarkerCache(&c);
        fixture.fixture.context.reset(); fixture.fixture.coordinator.reset();
        fixture.fixture.context = std::move(restarted);
        auto& r = *fixture.fixture.context;
        r.native_write_enabled = true; SeedRoot(r); std::array<std::byte, 16> security{}; SeedSecurity(r, security);
        const auto marker = LoadRecoveryMarkerAtStartup(r);
        RenameCheck(marker.load_status == RecoveryMarkerLoadStatus::Loaded && marker.state.dirty &&
            marker.action == LoadedRecoveryMarkerAction::ReplayIfSafe && r.native_write_enabled && !HasBlockedRecoveryEvidence(r),
            "ReplayIfSafe dirty-marker startup remains eligible for accepted replay");
        r.tx_manager = std::make_unique<apfsaccess::rw::TransactionManager>(L"Conservative");
        r.tx_manager->SetVolumeIdentity(L"directory-symlink-volume");
        r.tx_manager->SetJournalPath((r.session_root / "accepted.wal").wstring());
        std::string error; std::wstring mount_error;
        fixture.fixture.coordinator = apfsaccess::catalog::ContainerMountCoordinator::Open(fixture.fixture.image.path.string(), 0,
            error, apfsaccess::catalog::CatalogLoadPolicy::StrictApple, true, true);
        std::vector<std::uint64_t> pins;
        RenameCheck(fixture.fixture.coordinator && MountManifestSession(*fixture.fixture.coordinator, r.args, r, mount_error) &&
            r.tx_manager->LoadRequiredCheckpointXidsSinceCleanup(pins) &&
            fixture.fixture.coordinator->InitializeRequiredCheckpointCensus({{101, pins, true}, {102, {}, false}}, error),
            "restart reconstructs exact canonical ownership");
        r.container_session_contexts = {&r};
        const auto accepted_sequence = r.tx_manager->Watermarks().accepted_sequence;
        RenameCheck(ArmRecoveryMarkerForPendingWriteAheadLog(r, marker.state.dirty) && ReplayAcceptedWriteAheadLogAfterMetadataBootstrap(r),
            "actual host startup replays accepted rename");
        RenameCheck(r.label == label && r.runtime_volume_label == label && !r.recovery_active &&
            IsMutationWriteEnabled(&r) && !r.tx_manager->HasUnappliedAcceptedWork() && accepted_sequence != 0 &&
            r.tx_manager->Watermarks().apfs_durable_sequence == accepted_sequence &&
            r.tx_manager->Watermarks().cleanup_sequence == accepted_sequence &&
            preimage && r.metadata_store->CheckpointXid() == *preimage + 1,
            "startup refreshes durable label and resolves recovery");
        fixture.fs = BuildFileSystem(&r);
        return;
    }
    if (!NT_SUCCESS(result)) std::wcerr << L"rename callback status=" << std::hex << result << L" " << c.runtime_recovery_reason << L"\n";
    RenameCheck(result == STATUS_SUCCESS && old_at_acceptance && c.label == label && c.runtime_volume_label == label,
        "CB_SetVolumeLabel durably publishes Unicode label");
    RenameCheck(std::wstring(info.VolumeLabel, info.VolumeLabelLength / sizeof(wchar_t)) == label,
        "callback returns refreshed native volume info");
    RenameCheck(c.args.volume == original_args && c.payload_spool_volume_identity == original_identity &&
        c.session_root == original_session && c.recovery_marker_file == original_marker,
        "rename leaves all existing recovery identities and paths unchanged");
    RenameCheck(c.runtime_last_commit_xid == c.metadata_store->CheckpointXid() && c.runtime_last_commit_xid > preimage &&
        c.tx_manager->Watermarks().accepted_sequence == c.tx_manager->Watermarks().cleanup_sequence,
        "status checkpoint and journal durable state refreshed");
    RenameCheck(WriteHostStatusFileLocked(c, false, c.runtime_last_commit_xid), "status file refresh succeeds");
    const auto status = ReadFileBytes(c.args.status_file);
    const std::string json(reinterpret_cast<const char*>(status.data()), status.size());
    RenameCheck(json.find("\"volumeLabel\":\"" + WideToUtf8(label) + "\"") != std::string::npos,
        "status exposes new durable display label");
    RenameCheck(fixture.source != nullptr, "existing native handle survives rename");
    std::vector<std::byte> payload(fixture.original.size()); ULONG done = 0;
    RenameCheck(CB_Read(&fixture.fs, fixture.source, payload.data(), 0, static_cast<ULONG>(payload.size()), &done) == STATUS_SUCCESS &&
        done == payload.size() && payload == fixture.original, "existing host inode reads unchanged bytes after rename");
}
}
#ifndef APFSACCESS_RENAME_LATENCY_TEST
int main(int argc, char** argv)
{
    try
    {
        if (argc != 2) return 2;
        RunRenameHostCase(argv[1]);
        std::cout << "PASS host " << argv[1] << " " << rename_checks << " checks\n"; return 0;
    }
    catch (const std::exception& error) { std::cerr << "FAIL host after " << rename_checks << " checks: " << error.what() << "\n"; return 1; }
}
#endif
