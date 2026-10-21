#pragma once

// Include after ContainerFixtureFile, OpenContainerFixtureCoordinator and
// ManifestSessionArgs in FsHostSemanticsTests.cpp.
namespace root_observation_guard_tests
{
constexpr UINT32 ObservationAccess = FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE;
constexpr auto FixedRequestSize = offsetof(FSP_FSCTL_TRANSACT_REQ, Buffer);

struct Request
{
    alignas(FSP_FSCTL_TRANSACT_REQ)
        std::array<std::byte, FSP_FSCTL_TRANSACT_REQ_SIZEMAX> storage{};

    Request()
    {
        auto& r = *reinterpret_cast<FSP_FSCTL_TRANSACT_REQ*>(storage.data());
        r.Kind = FspFsctlTransactCreateKind;
        r.Req.Create.CreateOptions = (FILE_OPEN << 24) | FILE_DIRECTORY_FILE;
        r.Req.Create.DesiredAccess = ObservationAccess;
        r.Req.Create.GrantedAccess = ObservationAccess;
        Name(L"\\");
    }

    FSP_FSCTL_TRANSACT_REQ& Get()
    {
        return *reinterpret_cast<FSP_FSCTL_TRANSACT_REQ*>(storage.data());
    }

    void Name(const wchar_t* name, UINT16 offset = 0)
    {
        auto& r = Get();
        r.FileName.Offset = offset;
        r.FileName.Size = static_cast<UINT16>((std::wcslen(name) + 1) * sizeof(WCHAR));
        r.Size = static_cast<UINT16>(FixedRequestSize + offset + r.FileName.Size);
        std::memcpy(r.Buffer + offset, name, r.FileName.Size);
    }
};

enum class LockMode { None, Shared, Exclusive };

// Model the FINE contract in vendored winfsp.h: Open/GetVolumeInfo/listing
// share the namespace lock; Create/rename/delete cleanup/volume flush and label
// changes take it exclusively; file I/O and file metadata queries take none.
// These stubs use actual SRW locks without loading WinFsp or mounting a volume.
LockMode OriginalMode(const FSP_FILE_SYSTEM& fs, const FSP_FSCTL_TRANSACT_REQ& r)
{
    if (fs.OpGuardStrategy == FSP_FILE_SYSTEM_OPERATION_GUARD_STRATEGY_COARSE)
        return LockMode::Exclusive;
    switch (r.Kind)
    {
    case FspFsctlTransactCreateKind:
        return (r.Req.Create.CreateOptions >> 24) == FILE_OPEN
            ? LockMode::Shared : LockMode::Exclusive;
    case FspFsctlTransactQueryVolumeInformationKind:
    case FspFsctlTransactQueryDirectoryKind:
        return LockMode::Shared;
    case FspFsctlTransactSetVolumeInformationKind:
        return LockMode::Exclusive;
    case FspFsctlTransactCleanupKind:
        return r.Req.Cleanup.Delete ? LockMode::Exclusive : LockMode::None;
    case FspFsctlTransactFlushBuffersKind:
        return !r.Req.FlushBuffers.UserContext && !r.Req.FlushBuffers.UserContext2
            ? LockMode::Exclusive : LockMode::None;
    case FspFsctlTransactSetInformationKind:
        // FILE_INFORMATION_CLASS values from the WinFsp transaction protocol.
        if (r.Req.SetInformation.FileInformationClass == 10 ||
            r.Req.SetInformation.FileInformationClass == 65) return LockMode::Exclusive;
        if (r.Req.SetInformation.FileInformationClass == 13 ||
            r.Req.SetInformation.FileInformationClass == 64) return LockMode::Shared;
        return LockMode::None;
    default:
        return LockMode::None;
    }
}

struct OriginalCalls
{
    std::atomic<unsigned> enters{0}, leaves{0}, shared{0}, exclusive{0}, unguarded{0}, unmatched{0};
    NTSTATUS enter_status = STATUS_SUCCESS;
    NTSTATUS leave_status = STATUS_SUCCESS;
};

struct HeldOperation
{
    FSP_FILE_SYSTEM* fs;
    FSP_FSCTL_TRANSACT_REQ* request;
    LockMode mode;
};

thread_local OriginalCalls* current_calls = nullptr;
thread_local std::vector<HeldOperation> held_operations;

struct UseOriginalCalls
{
    OriginalCalls* previous;
    explicit UseOriginalCalls(OriginalCalls& calls) : previous(current_calls) { current_calls = &calls; }
    ~UseOriginalCalls() { current_calls = previous; }
};

NTSTATUS OriginalEnter(FSP_FILE_SYSTEM* fs, FSP_FSCTL_TRANSACT_REQ* r, FSP_FSCTL_TRANSACT_RSP*)
{
    if (!current_calls) return STATUS_INTERNAL_ERROR;
    ++current_calls->enters;
    if (!NT_SUCCESS(current_calls->enter_status)) return current_calls->enter_status;
    const auto mode = OriginalMode(*fs, *r);
    // Allocate before acquisition so an allocation failure cannot strand a lock.
    held_operations.push_back({fs, r, mode});
    if (mode == LockMode::Shared) { ++current_calls->shared; AcquireSRWLockShared(&fs->OpGuardLock); }
    else if (mode == LockMode::Exclusive) { ++current_calls->exclusive; AcquireSRWLockExclusive(&fs->OpGuardLock); }
    else ++current_calls->unguarded;
    return current_calls->enter_status;
}

NTSTATUS OriginalLeave(FSP_FILE_SYSTEM* fs, FSP_FSCTL_TRANSACT_REQ* r, FSP_FSCTL_TRANSACT_RSP*)
{
    if (!current_calls) return STATUS_INTERNAL_ERROR;
    ++current_calls->leaves;
    // Report an erroneous Leave instead of releasing an unowned SRW lock.
    if (held_operations.empty() || held_operations.back().fs != fs || held_operations.back().request != r)
    {
        ++current_calls->unmatched;
        return STATUS_INVALID_PARAMETER;
    }
    const auto mode = held_operations.back().mode;
    held_operations.pop_back();
    if (mode == LockMode::Shared) ReleaseSRWLockShared(&fs->OpGuardLock);
    else if (mode == LockMode::Exclusive) ReleaseSRWLockExclusive(&fs->OpGuardLock);
    return current_calls->leave_status;
}

bool RestoreOriginalDepth(std::size_t depth)
{
    const bool balanced = held_operations.size() == depth;
    while (held_operations.size() > depth)
    {
        ++current_calls->unmatched;
        const auto held = held_operations.back();
        held_operations.pop_back();
        if (held.mode == LockMode::Shared) ReleaseSRWLockShared(&held.fs->OpGuardLock);
        else if (held.mode == LockMode::Exclusive) ReleaseSRWLockExclusive(&held.fs->OpGuardLock);
    }
    return balanced;
}

template <typename Work>
bool Guarded(FSP_FILE_SYSTEM& fs, Request& request, Work work)
{
    auto& r = request.Get();
    alignas(FSP_FSCTL_TRANSACT_RSP) std::array<std::byte, FSP_FSCTL_TRANSACT_RSP_SIZEMAX> response_storage{};
    auto& response = *reinterpret_cast<FSP_FSCTL_TRANSACT_RSP*>(response_storage.data());
    const auto depth = held_operations.size();
    ScopeExit restore_locks{[&] { (void)RestoreOriginalDepth(depth); }};
    if (fs.EnterOperation(&fs, &r, &response) != STATUS_SUCCESS) return false;
    bool left = false;
    ScopeExit leave_on_error{[&] { if (!left) (void)fs.LeaveOperation(&fs, &r, &response); }};
    const bool result = work();
    const auto status = fs.LeaveOperation(&fs, &r, &response);
    left = true;
    return RestoreOriginalDepth(depth) && result && status == STATUS_SUCCESS;
}

struct ExclusiveGuard
{
    SRWLOCK* lock;
    explicit ExclusiveGuard(FSP_FILE_SYSTEM& fs) : lock(&fs.OpGuardLock) { AcquireSRWLockExclusive(lock); }
    void Release() { if (lock) { ReleaseSRWLockExclusive(lock); lock = nullptr; } }
    ~ExclusiveGuard() { Release(); }
};

template <typename Work>
bool WhileExclusive(FSP_FILE_SYSTEM& fs, OriginalCalls& calls, Work work, bool expect_fast, const char* message)
{
    std::promise<void> started;
    auto start = started.get_future();
    // Destruction also releases the lock before joining if launch/wait throws.
    std::future<bool> result;
    ExclusiveGuard guard(fs);
    const auto enters_before = calls.enters.load();
    result = std::async(std::launch::async, [&] {
        UseOriginalCalls use(calls);
        started.set_value();
        return work();
    });
    const bool launched = start.wait_for(std::chrono::seconds(2)) == std::future_status::ready;
    const bool fast = launched && result.wait_for(std::chrono::milliseconds(200)) == std::future_status::ready;
    const bool attempted = expect_fast || calls.enters > enters_before;
    guard.Release();
    const bool succeeded = result.get();
    if (!launched || fast != expect_fast || !attempted || !succeeded)
        std::cerr << "[INFO] root guard: " << message << " launched=" << launched
                  << " ready_while_exclusive=" << fast << " original_attempted=" << attempted
                  << " succeeded=" << succeeded << '\n';
    return Require(launched && fast == expect_fast && attempted && succeeded, message);
}

bool CheckRequest(MountContext& c, FSP_FILE_SYSTEM& fs, OriginalCalls& calls,
    Request& request, bool eligible, const char* message)
{
    const auto enters = calls.enters.load(), leaves = calls.leaves.load();
    const bool classified = IsCachedRootObservationRequest(c, fs, request.Get()) == eligible;
    const bool succeeded = Guarded(fs, request, [] { return true; });
    const auto delegated = eligible ? 0u : 1u;
    return Require(classified && succeeded && calls.enters == enters + delegated &&
        calls.leaves == leaves + delegated && calls.unmatched == 0, message);
}

bool Classifications(MountContext& c, FSP_FILE_SYSTEM& fs, OriginalCalls& calls)
{
    bool ok = true;
    const auto check = [&](const char* name, auto change, bool eligible = false) {
        Request request;
        change(request);
        ok &= CheckRequest(c, fs, calls, request, eligible, name);
    };
    const UINT32 allowed[] = {0, FILE_READ_ATTRIBUTES, READ_CONTROL, SYNCHRONIZE, ObservationAccess};
    for (const auto desired : allowed)
        for (const auto granted : allowed)
            check("root guard: narrow DesiredAccess and GrantedAccess combinations bypass", [&](Request& r) {
                r.Get().Req.Create.DesiredAccess = desired;
                r.Get().Req.Create.GrantedAccess = granted;
            }, true);

    const UINT32 excluded[] = {FILE_LIST_DIRECTORY, FILE_READ_EA, FILE_TRAVERSE, GENERIC_READ,
        GENERIC_EXECUTE, FILE_WRITE_DATA, FILE_APPEND_DATA, FILE_WRITE_EA, FILE_WRITE_ATTRIBUTES,
        FILE_DELETE_CHILD, DELETE, WRITE_DAC, WRITE_OWNER, MAXIMUM_ALLOWED, GENERIC_WRITE,
        GENERIC_ALL, ACCESS_SYSTEM_SECURITY, FILE_ALL_ACCESS};
    for (const auto access : excluded)
        for (const bool desired : {false, true})
            check("root guard: excluded access in either mask delegates", [&](Request& r) {
                if (desired) r.Get().Req.Create.DesiredAccess |= access;
                else r.Get().Req.Create.GrantedAccess |= access;
            });
    for (const UINT32 disposition : {FILE_SUPERSEDE, FILE_CREATE, FILE_OPEN_IF, FILE_OVERWRITE, FILE_OVERWRITE_IF})
        check("root guard: dispositions that may mutate delegate", [&](Request& r) {
            r.Get().Req.Create.CreateOptions = (disposition << 24) | FILE_DIRECTORY_FILE;
        });
    check("root guard: delete-on-close delegates", [](Request& r) { r.Get().Req.Create.CreateOptions |= FILE_DELETE_ON_CLOSE; });
    check("root guard: target-directory open delegates", [](Request& r) { r.Get().Req.Create.OpenTargetDirectory = 1; });
    check("root guard: named stream flag delegates", [](Request& r) { r.Get().Req.Create.NamedStream = 1; });
    check("root guard: EA buffer delegates", [](Request& r) { r.Get().Req.Create.Ea.Size = 1; });
    check("root guard: security descriptor buffer delegates", [](Request& r) { r.Get().Req.Create.SecurityDescriptor.Size = 1; });
    check("root guard: allocation request delegates", [](Request& r) { r.Get().Req.Create.AllocationSize = 4096; });
    check("root guard: empty name delegates", [](Request& r) { r.Name(L""); });
    check("root guard: nonroot metadata open delegates", [](Request& r) { r.Name(L"\\metadata.bin"); });
    check("root guard: doubled root separator delegates", [](Request& r) { r.Name(L"\\\\"); });
    check("root guard: root stream name delegates", [](Request& r) { r.Name(L"\\:stream"); });
    check("root guard: root dot alias delegates", [](Request& r) { r.Name(L"\\."); });
    check("root guard: forward slash delegates", [](Request& r) { r.Name(L"/"); });
    check("root guard: root name without terminator delegates", [](Request& r) { r.Get().FileName.Size = sizeof(WCHAR); });
    check("root guard: oversized root name delegates", [](Request& r) { r.Get().FileName.Size += sizeof(WCHAR); });
    check("root guard: missing filename delegates", [](Request& r) { r.Get().FileName.Size = 0; });
    check("root guard: non-NUL second WCHAR delegates", [](Request& r) {
        const WCHAR name[] = {L'\\', L'x'};
        std::memcpy(r.Get().Buffer, name, sizeof name);
    });
    check("root guard: fixed request truncated delegates", [](Request& r) { r.Get().Size = static_cast<UINT16>(FixedRequestSize - 1); });
    check("root guard: zero request size delegates", [](Request& r) { r.Get().Size = 0; });
    check("root guard: no filename bytes delegates", [](Request& r) { r.Get().Size = static_cast<UINT16>(FixedRequestSize); });
    check("root guard: last filename byte outside request delegates", [](Request& r) { --r.Get().Size; });
    check("root guard: unaligned filename offset delegates", [](Request& r) { r.Name(L"\\", 1); });
    check("root guard: offset at end of request delegates", [](Request& r) { r.Get().FileName.Offset = r.Get().FileName.Size; });
    check("root guard: huge offset cannot wrap past request bounds", [](Request& r) { r.Get().FileName.Offset = 0xfffe; });
    check("root guard: huge filename size cannot wrap past request bounds", [](Request& r) { r.Get().FileName.Size = 0xfffe; });
    check("root guard: aligned root at nonzero buffer offset delegates", [](Request& r) { r.Name(L"\\", 16); });
    check("root guard: nonroot dispatcher name cannot hide a root at a later offset", [](Request& r) {
        constexpr WCHAR other[] = L"\\other";
        std::memcpy(r.Get().Buffer, other, sizeof other);
        r.Name(L"\\", 16);
    });
    for (const UINT32 kind : {FspFsctlTransactWriteKind, FspFsctlTransactQueryInformationKind,
            FspFsctlTransactSetInformationKind, FspFsctlTransactSetEaKind,
            FspFsctlTransactSetSecurityKind, FspFsctlTransactQueryDirectoryKind,
            FspFsctlTransactSetVolumeInformationKind, FspFsctlTransactFlushBuffersKind})
        check("root guard: other request kinds retain original guard", [&](Request& r) { r.Get().Kind = kind; });
    check("root guard: cached volume query bypasses independently of filename", [](Request& r) {
        r.Get().Kind = FspFsctlTransactQueryVolumeInformationKind;
        r.Get().Size = static_cast<UINT16>(FixedRequestSize);
        r.Get().FileName.Offset = 0xffff;
        r.Get().FileName.Size = 0xffff;
    }, true);
    check("root guard: truncated volume query delegates", [](Request& r) {
        r.Get().Kind = FspFsctlTransactQueryVolumeInformationKind;
        r.Get().Size = static_cast<UINT16>(FixedRequestSize - 1);
    });
    return ok;
}

bool ProfileDelegation(MountContext& c, FSP_FILE_SYSTEM& fs, OriginalCalls& calls)
{
    bool ok = true;
    const auto check = [&] {
        Request root, volume;
        volume.Get().Kind = FspFsctlTransactQueryVolumeInformationKind;
        ok &= CheckRequest(c, fs, calls, root, false, "root guard: excluded profile delegates root");
        ok &= CheckRequest(c, fs, calls, volume, false, "root guard: excluded profile delegates volume query");
    };
    const auto args = c.args;
    ScopeExit restore{[&] { c.args = args; fs.OpGuardStrategy = FSP_FILE_SYSTEM_OPERATION_GUARD_STRATEGY_FINE; }};
    c.args.encrypted.enabled = true; check(); c.args = args;
    c.args.fusion.enabled = true; check(); c.args = args;
    c.args.snapshot_xid = 20; check(); c.args = args;
    c.args.snapshot_name = L"guard-snapshot"; check(); c.args = args;
    fs.OpGuardStrategy = FSP_FILE_SYSTEM_OPERATION_GUARD_STRATEGY_COARSE;
    check();
    fs.OpGuardStrategy = FSP_FILE_SYSTEM_OPERATION_GUARD_STRATEGY_FINE;
    const auto oid = c.container_volume_oid;
    c.container_volume_oid = 0;
    { ScopeExit restore_oid{[&] { c.container_volume_oid = oid; }}; check(); }
    auto* coordinator = c.container_coordinator;
    c.container_coordinator = nullptr;
    { ScopeExit restore_coordinator{[&] { c.container_coordinator = coordinator; }}; check(); }
    return ok;
}

bool CallbackRoundTrip(MountContext& c, FSP_FILE_SYSTEM& fs, const std::vector<std::byte>& security)
{
    Request create;
    PVOID handle = nullptr;
    ScopeExit close_on_error{[&] { if (handle) CB_Close(&fs, handle); }};
    FSP_FSCTL_FILE_INFO opened{}, queried{};
    UINT32 attributes = 0;
    const auto root = c.nodes.at(Key(&c, L"\\"));
    const auto before_times = VisibleInodeTimes(*root);
    if (!Guarded(fs, create, [&] {
        std::vector<std::byte> actual(security.size());
        SIZE_T size = actual.size();
        auto* name = reinterpret_cast<PWSTR>(create.Get().Buffer);
        return CB_GetSecurityByName(&fs, name, &attributes, actual.data(), &size) == STATUS_SUCCESS &&
            size == security.size() && actual == security &&
            CB_Open(&fs, name, create.Get().Req.Create.CreateOptions, ObservationAccess, &handle, &opened) == STATUS_SUCCESS;
    })) return false;
    Request query;
    query.Get().Kind = FspFsctlTransactQueryInformationKind;
    const bool queried_ok = Guarded(fs, query, [&] { return CB_GetFileInfo(&fs, handle, &queried) == STATUS_SUCCESS; });
    Request cleanup;
    cleanup.Get().Kind = FspFsctlTransactCleanupKind;
    cleanup.Get().Req.Cleanup = {};
    cleanup.Get().Req.Cleanup.SetLastAccessTime = 1;
    const bool cleaned = Guarded(fs, cleanup, [&] { CB_Cleanup(&fs, handle, nullptr, FspCleanupSetLastAccessTime); return true; });
    Request close;
    close.Get().Kind = FspFsctlTransactCloseKind;
    const bool closed = Guarded(fs, close, [&] { CB_Close(&fs, handle); handle = nullptr; return true; });
    return queried_ok && cleaned && closed && (attributes & FILE_ATTRIBUTE_DIRECTORY) &&
        (opened.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) && (queried.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
        opened.IndexNumber == queried.IndexNumber && opened.FileSize == queried.FileSize &&
        VisibleInodeTimes(*root) == before_times;
}

bool BalanceAndDelegation(MountContext& c, FSP_FILE_SYSTEM& fs, OriginalCalls& calls)
{
    bool ok = true;
    for (const UINT32 kind : {FspFsctlTransactCreateKind, FspFsctlTransactQueryVolumeInformationKind})
    {
        Request request;
        request.Get().Kind = kind;
        const auto enters = calls.enters.load(), leaves = calls.leaves.load();
        ok &= Guarded(fs, request, [&] {
            // Leave must match the saved pair, not rerun the predicate.
            request.Get().Kind = FspFsctlTransactSetVolumeInformationKind;
            request.Get().Req.Create.DesiredAccess = GENERIC_ALL;
            request.Get().FileName.Size = 0;
            return true;
        });
        ok &= Require(calls.enters == enters && calls.leaves == leaves && calls.unmatched == 0,
            "root guard: mutated fast request never releases an unacquired original guard");
    }

    Request outer, nested;
    nested.Get().Kind = FspFsctlTransactQueryInformationKind;
    const auto enters = calls.enters.load(), leaves = calls.leaves.load();
    ok &= Guarded(fs, outer, [&] {
        const bool inner_ok = Guarded(fs, nested, [] { return true; });
        return inner_ok && calls.enters == enters + 1 && calls.leaves == leaves + 1;
    });
    ok &= Require(calls.enters == enters + 1 && calls.leaves == leaves + 1 && calls.unmatched == 0,
        "root guard: nested nonfast request delegates without consuming outer bypass");

    // Another filesystem sharing a context still has a distinct lock/pair.
    auto other = BuildFileSystem(&c);
    other.EnterOperation = fs.EnterOperation;
    other.LeaveOperation = fs.LeaveOperation;
    Request outer_again;
    const auto shared = calls.shared.load();
    ok &= Guarded(fs, outer_again, [&] { return Guarded(other, outer_again, [] { return true; }); });
    ok &= Require(calls.shared == shared + 1 && calls.unmatched == 0,
        "root guard: the same request on a different filesystem cannot consume the outer bypass");

    Request thread_outer;
    const auto thread_enters = calls.enters.load(), thread_leaves = calls.leaves.load();
    ok &= Guarded(fs, thread_outer, [&] {
        return WhileExclusive(fs, calls, [&] {
            Request concurrent;
            return Guarded(fs, concurrent, [] { return true; });
        }, true, "root guard: another thread has its own bypass while an outer request remains active");
    });
    ok &= Require(calls.enters == thread_enters && calls.leaves == thread_leaves,
        "root guard: bypass tracking is thread local");

    Request failed;
    failed.Name(L"\\ordinary.bin");
    alignas(FSP_FSCTL_TRANSACT_RSP) std::array<std::byte, FSP_FSCTL_TRANSACT_RSP_SIZEMAX> response_storage{};
    auto& response = *reinterpret_cast<FSP_FSCTL_TRANSACT_RSP*>(response_storage.data());
    const auto failed_leaves = calls.leaves.load();
    calls.enter_status = STATUS_ACCESS_DENIED;
    const auto failure = fs.EnterOperation(&fs, &failed.Get(), &response);
    calls.enter_status = STATUS_SUCCESS;
    ok &= Require(failure == STATUS_ACCESS_DENIED && calls.leaves == failed_leaves,
        "root guard: original Enter failure propagates without a synthetic Leave");
    if (NT_SUCCESS(failure)) (void)fs.LeaveOperation(&fs, &failed.Get(), &response);
    calls.leave_status = STATUS_UNSUCCESSFUL;
    const auto status = fs.EnterOperation(&fs, &failed.Get(), &response);
    const auto leave_status = NT_SUCCESS(status) ? fs.LeaveOperation(&fs, &failed.Get(), &response) : status;
    calls.leave_status = STATUS_SUCCESS;
    ok &= Require(status == STATUS_SUCCESS && leave_status == STATUS_UNSUCCESSFUL,
        "root guard: original Leave status propagates");
    Request next;
    ok &= CheckRequest(c, fs, calls, next, true, "root guard: bypass state is reusable after nested and failed requests");
    return ok;
}
} // namespace root_observation_guard_tests

bool TestCachedRootObservationGuard()
{
    using namespace root_observation_guard_tests;
    ContainerFixtureFile fixture("root-observation-guard", true, true);
    std::string error;
    auto coordinator = OpenContainerFixtureCoordinator(fixture, error);
    if (!Require(coordinator != nullptr, "root guard: real container fixture opens")) return false;
    MountContext context{};
    context.args = ManifestSessionArgs(fixture.path, 101, Utf8ToWide(coordinator->ContainerUuidHex()), L"private-root-observation", true);
    context.native_write_enabled = true;
    std::wstring mount_error;
    if (!Require(MountManifestSession(*coordinator, context.args, context, mount_error) && IsManifestSession(&context),
            "root guard: real coordinator supplies an ordinary manifest session")) return false;
    SeedRoot(context);
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!Require(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:BAG:BAD:P(A;;FR;;;WD)",
            SDDL_REVISION_1, &sd, nullptr) != FALSE, "root guard: valid cached root security")) return false;
    ScopeExit release_sd{[&] { context.sd = nullptr; context.sd_size = 0; LocalFree(sd); }};
    context.sd = sd;
    context.sd_size = GetSecurityDescriptorLength(sd);
    const auto* first = reinterpret_cast<const std::byte*>(sd);
    const std::vector<std::byte> security(first, first + context.sd_size);

    const auto env_length = GetEnvironmentVariableW(L"APFSACCESS_PERF_COUNTERS", nullptr, 0);
    std::vector<wchar_t> saved_env(env_length ? env_length : 1);
    if (env_length) GetEnvironmentVariableW(L"APFSACCESS_PERF_COUNTERS", saved_env.data(), env_length);
    ScopeExit restore_env{[&] { SetEnvironmentVariableW(L"APFSACCESS_PERF_COUNTERS", env_length ? saved_env.data() : nullptr); }};
    bool ok = true;
    for (const auto* perf : {L"0", L"1"})
    {
        if (!Require(SetEnvironmentVariableW(L"APFSACCESS_PERF_COUNTERS", perf) != FALSE,
                "root guard: select diagnostics mode")) return false;
        OriginalCalls calls;
        UseOriginalCalls use(calls);
        auto fs = BuildFileSystem(&context);
        InitializeSRWLock(&fs.OpGuardLock);
        fs.OpGuardStrategy = FSP_FILE_SYSTEM_OPERATION_GUARD_STRATEGY_FINE;
        fs.EnterOperation = OriginalEnter;
        fs.LeaveOperation = OriginalLeave;
        InstallOperationDiagnostics(&fs);
        const auto enter = fs.EnterOperation, leave = fs.LeaveOperation;
        InstallOperationDiagnostics(&fs);
        if (!Require(enter != OriginalEnter && leave != OriginalLeave && enter == fs.EnterOperation && leave == fs.LeaveOperation &&
                fs.OpGuardStrategy == FSP_FILE_SYSTEM_OPERATION_GUARD_STRATEGY_FINE &&
                context.root_observation_original_operation_enter == OriginalEnter &&
                context.root_observation_original_operation_leave == OriginalLeave,
                "root guard: installation is unconditional, idempotent and retains original functions")) return false;

        ok &= Classifications(context, fs, calls);
        ok &= ProfileDelegation(context, fs, calls);
        const auto before_enters = calls.enters.load(), before_leaves = calls.leaves.load();
        const auto before_none = calls.unguarded.load();
        ok &= WhileExclusive(fs, calls, [&] { return CallbackRoundTrip(context, fs, security); }, true,
            "root security/open/file-info/cleanup/close through installed guard finish within 200 ms under exclusive guard");
        ok &= Require(calls.enters == before_enters + 3 && calls.leaves == before_leaves + 3 && calls.unguarded == before_none + 3,
            "root guard: only file-info/cleanup/close delegate, all using original no-lock semantics");
        FSP_FSCTL_VOLUME_INFO before{};
        ok &= Require(CB_GetVolumeInfo(&fs, &before) == STATUS_SUCCESS, "root guard: cached volume baseline");
        const auto volume_enters = calls.enters.load(), volume_leaves = calls.leaves.load();
        ok &= WhileExclusive(fs, calls, [&] {
            Request request;
            request.Get().Kind = FspFsctlTransactQueryVolumeInformationKind;
            return Guarded(fs, request, [&] {
                FSP_FSCTL_VOLUME_INFO info{};
                return CB_GetVolumeInfo(&fs, &info) == STATUS_SUCCESS && info.TotalSize == before.TotalSize &&
                    info.FreeSize == before.FreeSize && info.VolumeLabelLength == before.VolumeLabelLength &&
                    std::memcmp(info.VolumeLabel, before.VolumeLabel, before.VolumeLabelLength) == 0;
            });
        }, true, "cached volume query through installed guard finishes within 200 ms under exclusive guard");
        ok &= Require(calls.enters == volume_enters && calls.leaves == volume_leaves,
            "root guard: eligible volume query never calls original guard");

        for (const bool write_access : {false, true})
        {
            const auto shared_before = calls.shared.load();
            ok &= WhileExclusive(fs, calls, [&] {
                Request request;
                request.Name(L"\\ordinary.bin");
                if (write_access) request.Get().Req.Create.DesiredAccess |= FILE_WRITE_DATA;
                return Guarded(fs, request, [] { return true; });
            }, false, "nonroot metadata/write opens retain original shared guard and wait for the writer");
            ok &= Require(calls.shared == shared_before + 1, "root guard: nonroot open uses original shared lock");
        }
        const auto exclusive_before = calls.exclusive.load();
        ok &= WhileExclusive(fs, calls, [&] {
            Request request;
            request.Get().Kind = FspFsctlTransactSetVolumeInformationKind;
            return Guarded(fs, request, [] { return true; });
        }, false, "volume mutation retains original exclusive guard and waits for the writer");
        ok &= Require(calls.exclusive == exclusive_before + 1, "root guard: mutation uses original exclusive lock");
        ok &= BalanceAndDelegation(context, fs, calls);
        ok &= Require(calls.unmatched == 0 && held_operations.empty(), "root guard: all original acquisitions balance");
        const bool lock_free = TryAcquireSRWLockExclusive(&fs.OpGuardLock) != FALSE;
        if (lock_free) ReleaseSRWLockExclusive(&fs.OpGuardLock);
        ok &= Require(lock_free, "root guard: no original shared or exclusive acquisition remains held");
        std::cout << "ROOT_OBSERVATION_GUARD perf=" << WideToUtf8(perf)
                  << " original_enter=" << calls.enters << " original_leave=" << calls.leaves
                  << " shared=" << calls.shared << " exclusive=" << calls.exclusive << '\n';
    }
    return ok;
}
