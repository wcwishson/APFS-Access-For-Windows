#define APFSACCESS_RENAME_LATENCY_TEST
#include "VolumeRenameHostTests.cpp"

namespace
{
bool HasEvent(const auto& events, std::string_view name)
{
    return std::any_of(events.begin(), events.end(), [&](const auto& e) { return e.id && e.name == name; });
}
LatencyTrace::Snapshot TraceSnapshot(MountContext& c)
{
    LatencyTrace::Snapshot s;
    RenameCheck(c.latency_trace.Capture(s), "diagnostic snapshot available");
    return s;
}
void TraceBounds()
{
    LatencyTrace trace;
    std::array<std::uint64_t, LatencyTrace::ActiveLimit + 5> tokens{};
    for (auto& token : tokens) token = trace.Begin("test", 0, GetCurrentThreadId());
    LatencyTrace::Snapshot s;
    RenameCheck(trace.Capture(s) && s.dropped == 5, "active capacity loss is explicit");
    for (const auto token : tokens) trace.End(token);
    for (unsigned i = 0; i != 700; ++i) { auto token = trace.Begin("test", 0, 1); trace.End(token); }
    RenameCheck(trace.Capture(s) && s.completed == LatencyTrace::ActiveLimit + 700 &&
        std::none_of(s.active.begin(), s.active.end(), [](const auto& e) { return e.id; }),
        "bounded completion history retires all slots");
    RenameCheck(std::count_if(s.history.begin(), s.history.end(), [](const auto& e) { return e.id != 0; }) ==
        LatencyTrace::HistoryLimit, "ring retains exactly the configured history limit");
    std::atomic<bool> run{true};
    auto exporter = std::async(std::launch::async, [&] {
        while (run.load()) { LatencyTrace::Snapshot copy; (void)trace.Capture(copy); }
    });
    for (unsigned i = 0; i != 10000; ++i) { auto token = trace.Begin("contended", 0, 1); trace.End(token); }
    run = false; exporter.get();
    RenameCheck(trace.Capture(s) && std::none_of(s.active.begin(), s.active.end(),
        [](const auto& e) { return e.id; }), "contended exporter cannot strand completed spans");
    std::ostringstream json; LatencyTrace::Write(json, s);
    RenameCheck(json.str().size() < 150000, "diagnostic export remains bounded");
}

// Models the documented WinFsp fine-grained guard using a stack-only filesystem.
// This test does not load a driver, create a WinFsp filesystem or mount anything.
NTSTATUS TestGuardEnter(FSP_FILE_SYSTEM* fs, FSP_FSCTL_TRANSACT_REQ* request, FSP_FSCTL_TRANSACT_RSP*)
{
    if (request->Kind == FspFsctlTransactSetVolumeInformationKind) AcquireSRWLockExclusive(&fs->OpGuardLock);
    else AcquireSRWLockShared(&fs->OpGuardLock);
    return STATUS_SUCCESS;
}
NTSTATUS TestGuardLeave(FSP_FILE_SYSTEM* fs, FSP_FSCTL_TRANSACT_REQ* request, FSP_FSCTL_TRANSACT_RSP*)
{
    if (request->Kind == FspFsctlTransactSetVolumeInformationKind) ReleaseSRWLockExclusive(&fs->OpGuardLock);
    else ReleaseSRWLockShared(&fs->OpGuardLock);
    return STATUS_SUCCESS;
}
void SlowRename(bool publication)
{
    NativeCloneHost500Fixture f;
    RenameCheck(f.Initialize(false, false, 0, false, false, true), "private canonical fixture");
    auto& c = *f.fixture.context;
    c.label = L"Alpha";
    const auto xid = c.metadata_store->CheckpointXid();
    f.fs.EnterOperation = TestGuardEnter; f.fs.LeaveOperation = TestGuardLeave;
    InstallOperationDiagnostics(&f.fs);
    std::promise<void> reached, release;
    auto gate = release.get_future().share();
    std::atomic<bool> signaled{false};
    const auto pause = [&] {
        if (!signaled.exchange(true)) { reached.set_value(); gate.wait(); }
    };
    if (publication) c.metadata_store->SetCommitStageHook([&](std::string_view stage) {
        if (stage == "before-apple-checkpoint-switch") pause(); return true;
    });
    else c.tx_manager->SetJournalFaultInjectionHook([&](std::string_view stage) {
        if (stage == "durable-flush") pause(); return false;
    });
    auto renamed = std::async(std::launch::async, [&] {
        FSP_FSCTL_TRANSACT_REQ request; FSP_FSCTL_TRANSACT_RSP response;
        std::memset(&request, 0, sizeof(request)); std::memset(&response, 0, sizeof(response));
        request.Kind = FspFsctlTransactSetVolumeInformationKind;
        (void)ObserveOperationEnter(&f.fs, &request, &response);
        auto label = std::wstring(L"Latency618-研究"); FSP_FSCTL_VOLUME_INFO info{};
        const auto status = CB_SetVolumeLabel(&f.fs, label.data(), &info);
        (void)ObserveOperationLeave(&f.fs, &request, &response);
        return status;
    });
    const bool ready = reached.get_future().wait_for(std::chrono::seconds(5)) == std::future_status::ready;
    if (!ready) { release.set_value(); (void)renamed.get(); RenameCheck(false, "rename reaches controlled I/O stage"); }
    auto root = std::async(std::launch::async, [&] {
        FSP_FSCTL_TRANSACT_REQ request; FSP_FSCTL_TRANSACT_RSP response;
        std::memset(&request, 0, sizeof(request)); std::memset(&response, 0, sizeof(response));
        request.Kind = FspFsctlTransactQueryVolumeInformationKind;
        (void)ObserveOperationEnter(&f.fs, &request, &response);
        FSP_FSCTL_VOLUME_INFO info{};
        const auto status = CB_GetVolumeInfo(&f.fs, &info);
        (void)ObserveOperationLeave(&f.fs, &request, &response);
        return status;
    });
    const bool blocked = root.wait_for(std::chrono::milliseconds(120)) != std::future_status::ready;
    const auto active = TraceSnapshot(c);
    // Snapshot/export runs while rename owns commit/read/metadata/journal locks.
    const auto base = (c.session_root / "latency618-status").wstring();
    auto exported = std::async(std::launch::async, [&] { WriteCallbackWatchdogFile(c, base); });
    const bool responsive = exported.wait_for(std::chrono::milliseconds(500)) == std::future_status::ready;
    FSP_FSCTL_VOLUME_INFO cached{};
    const auto direct = CB_GetVolumeInfo(&f.fs, &cached);
    const bool pending = renamed.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready;
    release.set_value();
    const auto status = renamed.get(); const auto root_status = root.get(); exported.get();
    c.tx_manager->SetJournalFaultInjectionHook({}); c.metadata_store->SetCommitStageHook({});
    RenameCheck(blocked && pending && direct == STATUS_SUCCESS && responsive,
        "guard blocks new metadata operation while cached callback and diagnostic exporter remain responsive");
    RenameCheck(HasEvent(active.active, "guard.wait") && HasEvent(active.active,
        publication ? "rename.publication" : "rename.acceptance"), "active history identifies exact slow stage and guard wait");
    RenameCheck(status == STATUS_SUCCESS && root_status == STATUS_SUCCESS && c.label == L"Latency618-研究" &&
        c.metadata_store->CheckpointXid() > xid &&
        c.tx_manager->Watermarks().accepted_sequence == c.tx_manager->Watermarks().cleanup_sequence,
        "success follows real canonical publication and WAL cleanup");
    WriteCallbackWatchdogFile(c, base);
    const auto bytes = ReadFileBytes(base + L".callback.json");
    const std::string json(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    RenameCheck(json.find("rename.finalize") != std::string::npos && json.find("guard.wait") != std::string::npos,
        "completed stages retained after active callbacks exit");
    std::cout << "diagnostic=" << WideToUtf8(base + L".callback.json") << '\n';
    std::cout << "diagnosticJSON=" << json << '\n';
}

void NoopAndAtime()
{
    NativeCloneHost500Fixture f;
    RenameCheck(f.Initialize(false, false, 0, false, false, true) &&
        f.Open(FILE_READ_DATA | FILE_READ_ATTRIBUTES, FILE_READ_ATTRIBUTES), "private atime fixture");
    auto& c = *f.fixture.context;
    auto* o = static_cast<OpenContext*>(f.source);
    // Queue actual automatic atime under its required mutation ownership.
    { MutationCallbackScope mutation(&c); RenameCheck(TryDeferAutomaticAccessTime(&c, o), "deferred atime queued"); }
    CB_Cleanup(&f.fs, f.source, nullptr, 0); CB_Close(&f.fs, f.source); f.source = nullptr;
    CB_Close(&f.fs, f.directory); f.directory = nullptr;
    RenameCheck(f.Open(FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES, FILE_READ_ATTRIBUTES),
        "probe-shaped write-attributes handle opens after queued read atime");
    const auto original = ReadFileBytes(f.fixture.image.path);
    const auto xid = c.metadata_store->CheckpointXid();
    FSP_FSCTL_FILE_INFO info{};
    {
        std::unique_lock gate(c.mutation_callback_mutex);
        auto noops = std::async(std::launch::async, [&] {
            for (unsigned i = 0; i != 16; ++i)
                if (CB_SetBasicInfo(&f.fs, f.source, INVALID_FILE_ATTRIBUTES, 0, 0, 0, 0, &info) != STATUS_SUCCESS) return false;
            return CB_SetBasicInfo(&f.fs, f.source, INVALID_FILE_ATTRIBUTES, 0, UINT64_MAX, 0, 0, &info) == STATUS_INVALID_PARAMETER;
        });
        const bool fast = noops.wait_for(std::chrono::milliseconds(500)) == std::future_status::ready;
        gate.unlock();
        RenameCheck(noops.get() && fast, "documented no-op bypasses mutation gate; literal all-ones is rejected");
    }
    RenameCheck(c.deferred_access_times.size() == 1 && c.metadata_store->CheckpointXid() == xid &&
        ReadFileBytes(f.fixture.image.path) == original, "suppression-shaped no-ops create no commits and do not drain queued atime");
    auto label = std::wstring(L"Atime618"); FSP_FSCTL_VOLUME_INFO volume{};
    RenameCheck(CB_SetVolumeLabel(&f.fs, label.data(), &volume) == STATUS_SUCCESS && c.deferred_access_times.empty(),
        "rename drains earlier automatic atime before durable label publication");
    const auto trace = TraceSnapshot(c);
    RenameCheck(HasEvent(trace.history, "atime.batch") && HasEvent(trace.history, "basic.noop") &&
        HasEvent(trace.history, "rename.finalize"), "trace identifies no-op and atime predecessor work");
    RenameCheck(c.tx_manager->Watermarks().accepted_sequence == c.tx_manager->Watermarks().cleanup_sequence,
        "atime and rename preserve exact final durability");
}
}

int main(int argc, char** argv)
{
    try
    {
        if (argc != 2) return 2;
        SetEnvironmentVariableW(L"APFSACCESS_PERF_COUNTERS", L"1");
        const std::string_view name = argv[1];
        if (name == "trace-bounds") TraceBounds();
        else if (name == "slow-acceptance") SlowRename(false);
        else if (name == "slow-publication") SlowRename(true);
        else if (name == "noop-atime") NoopAndAtime();
        else if (name == "worker-barrier") RenameCheck(TestDeferredAccessTimeEarlierCommitWorker562(true), "worker preclaims atime before barrier");
        else RunRenameHostCase(name);
        std::cout << "PASS latency618 " << name << " " << rename_checks << " checks\n";
        return 0;
    }
    catch (const std::exception& e) { std::cerr << "FAIL latency618: " << e.what() << '\n'; return 1; }
}
