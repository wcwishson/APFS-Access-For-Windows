#pragma once

// Include after RootObservationGuardTests.h and the container fixture helpers.
namespace root_observation_sdk_tests
{
using root_observation_guard_tests::ObservationAccess;
using root_observation_guard_tests::Request;

constexpr wchar_t DllPath[] = L"C:\\Program Files (x86)\\WinFsp\\bin\\winfsp-x64.dll";

struct Sdk
{
    HMODULE module = nullptr;
    FSP_FILE_SYSTEM_OPERATION *create = nullptr, *cleanup = nullptr, *close = nullptr, *volume = nullptr;
    FSP_FILE_SYSTEM_OPERATION_GUARD *enter = nullptr, *leave = nullptr;
    decltype(&FspFileSystemGetOperationContext) get_context = nullptr;

    ~Sdk() { if (module) FreeLibrary(module); }
    bool Load()
    {
        module = LoadLibraryW(DllPath);
        if (!module) return Require(false, "SDK root: load exact installed WinFsp DLL");
        wchar_t actual[32768]{};
        if (!Require(GetModuleFileNameW(module, actual, static_cast<DWORD>(std::size(actual))) &&
                _wcsicmp(actual, DllPath) == 0, "SDK root: loaded module has exact requested path")) return false;
        create = reinterpret_cast<FSP_FILE_SYSTEM_OPERATION*>(GetProcAddress(module, "FspFileSystemOpCreate"));
        cleanup = reinterpret_cast<FSP_FILE_SYSTEM_OPERATION*>(GetProcAddress(module, "FspFileSystemOpCleanup"));
        close = reinterpret_cast<FSP_FILE_SYSTEM_OPERATION*>(GetProcAddress(module, "FspFileSystemOpClose"));
        volume = reinterpret_cast<FSP_FILE_SYSTEM_OPERATION*>(GetProcAddress(module, "FspFileSystemOpQueryVolumeInformation"));
        enter = reinterpret_cast<FSP_FILE_SYSTEM_OPERATION_GUARD*>(GetProcAddress(module, "FspFileSystemOpEnter"));
        leave = reinterpret_cast<FSP_FILE_SYSTEM_OPERATION_GUARD*>(GetProcAddress(module, "FspFileSystemOpLeave"));
        get_context = reinterpret_cast<decltype(get_context)>(GetProcAddress(module, "FspFileSystemGetOperationContext"));
        return Require(create && cleanup && close && volume && enter && leave && get_context,
            "SDK root: bind real operation, guard and context exports");
    }
};

struct Calls
{
    unsigned security = 0, opens = 0, published = 0;
    bool nonroot_name = false, nonroot_bypass = false, context_mismatch = false;
    unsigned sdk_contexts = 0, absent_sdk_contexts = 0;
    Sdk* sdk = nullptr;
};

thread_local Calls* current_calls = nullptr;

void Observe(FSP_FILE_SYSTEM* fs, PWSTR name)
{
    auto& calls = *current_calls;
    if (name && std::wstring_view(name) != L"\\")
    {
        calls.nonroot_name = true;
        calls.nonroot_bypass |= g_root_observation_guard_bypass.fs == fs;
    }
    const auto* sdk_context = calls.sdk->get_context();
    if (sdk_context)
    {
        ++calls.sdk_contexts;
        calls.context_mismatch |= sdk_context->Request != g_root_observation_guard_bypass.request;
    }
    else ++calls.absent_sdk_contexts;
}

NTSTATUS Security(FSP_FILE_SYSTEM* fs, PWSTR name, PUINT32 attrs, PSECURITY_DESCRIPTOR sd, SIZE_T* size)
{
    ++current_calls->security;
    Observe(fs, name);
    return CB_GetSecurityByName(fs, name, attrs, sd, size);
}

NTSTATUS Open(FSP_FILE_SYSTEM* fs, PWSTR name, UINT32 options, UINT32 access,
    PVOID* context, FSP_FSCTL_FILE_INFO* info)
{
    ++current_calls->opens;
    Observe(fs, name);
    const auto status = CB_Open(fs, name, options, access, context, info);
    if (NT_SUCCESS(status) && *context) ++current_calls->published;
    return status;
}

// Contain an unsupported SDK-context dereference without inventing a context.
// Any exception is recorded and causes the corresponding assertion to fail.
NTSTATUS Invoke(FSP_FILE_SYSTEM_OPERATION* operation, FSP_FILE_SYSTEM* fs,
    FSP_FSCTL_TRANSACT_REQ* request, FSP_FSCTL_TRANSACT_RSP* response, DWORD* exception)
{
    __try { return operation(fs, request, response); }
    __except(EXCEPTION_EXECUTE_HANDLER) { *exception = GetExceptionCode(); return STATUS_UNSUCCESSFUL; }
}

struct Result
{
    alignas(FSP_FSCTL_TRANSACT_RSP) std::array<std::byte, FSP_FSCTL_TRANSACT_RSP_SIZEMAX> bytes{};
    NTSTATUS enter = STATUS_UNSUCCESSFUL, operation = STATUS_UNSUCCESSFUL, leave = STATUS_UNSUCCESSFUL;
    DWORD exception = 0;
    bool bypass = false, cleared = false;
    unsigned leaves = 0;
    FSP_FSCTL_TRANSACT_RSP& Response() { return *reinterpret_cast<FSP_FSCTL_TRANSACT_RSP*>(bytes.data()); }
};

Result Dispatch(FSP_FILE_SYSTEM& fs, Request& request, Calls& calls)
{
    Result result;
    auto& r = request.Get();
    auto& response = result.Response();
    response.Size = sizeof response;
    response.Kind = r.Kind;
    response.Hint = r.Hint;
    const auto previous = current_calls;
    current_calls = &calls;
    ScopeExit restore{[&] { current_calls = previous; }};
    result.enter = fs.EnterOperation(&fs, &r, &response);
    if (NT_SUCCESS(result.enter))
    {
        ScopeExit leave{[&] {
            result.leave = fs.LeaveOperation(&fs, &r, &response);
            ++result.leaves;
            result.cleared = !g_root_observation_guard_bypass.fs && !g_root_observation_guard_bypass.request;
        }};
        result.bypass = g_root_observation_guard_bypass.fs == &fs && g_root_observation_guard_bypass.request == &r;
        result.operation = Invoke(fs.Operations[r.Kind], &fs, &r, &response, &result.exception);
        response.IoStatus.Status = result.operation;
    }
    return result;
}

bool Balanced(const Result& result)
{
    return result.enter == STATUS_SUCCESS && result.leave == STATUS_SUCCESS &&
        result.leaves == 1 && result.cleared && result.exception == 0;
}

bool UnderWriter(FSP_FILE_SYSTEM& fs, Request& request, Calls& calls, bool expect_fast,
    Result& result, const char* message)
{
    std::promise<void> started;
    auto start = started.get_future();
    std::future<Result> pending;
    root_observation_guard_tests::ExclusiveGuard writer(fs);
    pending = std::async(std::launch::async, [&] {
        started.set_value();
        return Dispatch(fs, request, calls);
    });
    const bool launched = start.wait_for(std::chrono::seconds(2)) == std::future_status::ready;
    const bool ready = launched && pending.wait_for(std::chrono::milliseconds(200)) == std::future_status::ready;
    // Future completion before this release proves completion under the same lock.
    writer.Release();
    result = pending.get();
    const bool free = TryAcquireSRWLockExclusive(&fs.OpGuardLock) != FALSE;
    if (free) ReleaseSRWLockExclusive(&fs.OpGuardLock);
    std::cout << "SDK_ROOT_CASE " << message << " ready_under_writer=" << ready
              << " bypass=" << result.bypass << " status=" << WideToUtf8(FormatNtStatus(result.operation))
              << " leave_count=" << result.leaves << " cleared=" << result.cleared
              << " exception=" << result.exception << '\n';
    return Require(launched && ready == expect_fast && free && Balanced(result), message);
}

void PrepareOpen(Request& request, HANDLE token)
{
    auto& r = request.Get();
    r.Req.Create.DesiredAccess = ObservationAccess;
    r.Req.Create.GrantedAccess = 0;
    r.Req.Create.UserMode = 1;
    r.Req.Create.ShareAccess = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    r.Req.Create.AccessToken = (static_cast<UINT64>(GetCurrentProcessId()) << 32) |
        static_cast<UINT32>(reinterpret_cast<UINT_PTR>(token));
}

bool Release(FSP_FILE_SYSTEM& fs, Calls& calls, UINT64 handle, bool cleanup)
{
    bool ok = true;
    if (cleanup)
    {
        Request request;
        request.Get().Kind = FspFsctlTransactCleanupKind;
        request.Get().Req = {};
        request.Get().Req.Cleanup.UserContext = handle;
        request.Get().Req.Cleanup.SetLastAccessTime = 1;
        request.Get().FileName = {};
        const auto result = Dispatch(fs, request, calls);
        ok &= Require(Balanced(result) && result.operation == STATUS_SUCCESS && !result.bypass,
            "SDK root: real Cleanup operation balances the original SDK guard");
    }
    Request request;
    request.Get().Kind = FspFsctlTransactCloseKind;
    request.Get().Req = {};
    request.Get().Req.Close.UserContext = handle;
    request.Get().FileName = {};
    const auto result = Dispatch(fs, request, calls);
    return Require(Balanced(result) && result.operation == STATUS_SUCCESS && !result.bypass,
        "SDK root: real Close operation balances the original SDK guard") && ok;
}
} // namespace root_observation_sdk_tests

bool TestCachedRootObservationSdk()
{
    using namespace root_observation_sdk_tests;
    Sdk sdk;
    if (!sdk.Load()) return false;
    HANDLE primary = nullptr, token = nullptr;
    if (!Require(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &primary) != FALSE,
            "SDK root: open current process token")) return false;
    ScopeExit close_primary{[&] { CloseHandle(primary); }};
    if (!Require(DuplicateTokenEx(primary, TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_DUPLICATE, nullptr,
            SecurityImpersonation, TokenImpersonation, &token) != FALSE,
            "SDK root: real impersonation token for SDK AccessCheck")) return false;
    ScopeExit close_token{[&] { CloseHandle(token); }};
    Request encoded;
    PrepareOpen(encoded, token);
    if (!Require(FSP_FSCTL_TRANSACT_REQ_TOKEN_HANDLE(encoded.Get().Req.Create.AccessToken) == token &&
            FSP_FSCTL_TRANSACT_REQ_TOKEN_PID(encoded.Get().Req.Create.AccessToken) == GetCurrentProcessId(),
            "SDK root: transaction token macros recover the valid handle and PID")) return false;

    ContainerFixtureFile fixture("root-observation-sdk", true, true);
    std::string error;
    auto coordinator = OpenContainerFixtureCoordinator(fixture, error);
    if (!Require(coordinator != nullptr, "SDK root: software container fixture opens")) return false;
    MountContext context{};
    context.args = ManifestSessionArgs(fixture.path, 101, Utf8ToWide(coordinator->ContainerUuidHex()),
        L"private-root-observation-sdk", true);
    context.native_write_enabled = true;
    std::wstring mount_error;
    if (!Require(MountManifestSession(*coordinator, context.args, context, mount_error) && IsManifestSession(&context),
            "SDK root: ordinary manifest context uses only a software image")) return false;
    SeedRoot(context);
    const auto root = context.nodes.at(Key(&context, L"\\"));
    const auto initial_times = VisibleInodeTimes(*root);
    const auto initial_open = root->open_handle_count, initial_live = root->live_context_count;
    const auto initial_closing = root->closing_context_count;
    PSECURITY_DESCRIPTOR allow = nullptr, deny = nullptr;
    ScopeExit free_security{[&] { context.sd = nullptr; context.sd_size = 0; if (allow) LocalFree(allow); if (deny) LocalFree(deny); }};
    if (!Require(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:BAG:BAD:P(A;;FRFX;;;WD)",
            SDDL_REVISION_1, &allow, nullptr) &&
            ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:BAG:BAD:P(D;;0x120080;;;WD)(A;;FA;;;WD)",
            SDDL_REVISION_1, &deny, nullptr) && IsValidSecurityDescriptor(allow) && IsValidSecurityDescriptor(deny),
            "SDK root: valid allow and explicit read-deny security descriptors")) return false;

    const DWORD env_length = GetEnvironmentVariableW(L"APFSACCESS_PERF_COUNTERS", nullptr, 0);
    std::vector<wchar_t> saved(env_length ? env_length : 1);
    if (env_length) GetEnvironmentVariableW(L"APFSACCESS_PERF_COUNTERS", saved.data(), env_length);
    ScopeExit restore_env{[&] { SetEnvironmentVariableW(L"APFSACCESS_PERF_COUNTERS", env_length ? saved.data() : nullptr); }};
    bool ok = true;
    unsigned absent_contexts = 0;
    for (const auto* perf : {L"0", L"1"})
    {
        if (!Require(SetEnvironmentVariableW(L"APFSACCESS_PERF_COUNTERS", perf) != FALSE,
                "SDK root: select diagnostics mode")) return false;
        Calls calls;
        calls.sdk = &sdk;
        FSP_FILE_SYSTEM_INTERFACE callbacks{};
        callbacks.GetSecurityByName = Security;
        callbacks.Open = Open;
        callbacks.Create = CB_Create;
        callbacks.Overwrite = CB_Overwrite;
        callbacks.GetVolumeInfo = CB_GetVolumeInfo;
        callbacks.Cleanup = CB_Cleanup;
        callbacks.Close = CB_Close;
        auto fs = BuildFileSystem(&context);
        fs.Version = sizeof fs;
        fs.Interface = &callbacks;
        fs.OpGuardStrategy = FSP_FILE_SYSTEM_OPERATION_GUARD_STRATEGY_FINE;
        InitializeSRWLock(&fs.OpGuardLock);
        fs.EnterOperation = sdk.enter;
        fs.LeaveOperation = sdk.leave;
        fs.Operations[FspFsctlTransactCreateKind] = sdk.create;
        fs.Operations[FspFsctlTransactCleanupKind] = sdk.cleanup;
        fs.Operations[FspFsctlTransactCloseKind] = sdk.close;
        fs.Operations[FspFsctlTransactQueryVolumeInformationKind] = sdk.volume;
        InstallOperationDiagnostics(&fs);
        if (!Require(context.root_observation_original_operation_enter == sdk.enter &&
                context.root_observation_original_operation_leave == sdk.leave,
                "SDK root: installed production policy retains exact SDK guard exports")) return false;
        context.sd = allow;
        context.sd_size = GetSecurityDescriptorLength(allow);
        for (const bool cleanup : {false, true})
        {
            Request request;
            PrepareOpen(request, token);
            Result result;
            const auto opens = calls.opens, published = calls.published, security = calls.security;
            ok &= UnderWriter(fs, request, calls, true, result, "allowed exact root FILE_OPEN");
            auto& response = result.Response();
            auto* opened = reinterpret_cast<OpenContext*>(static_cast<UINT_PTR>(response.Rsp.Create.Opened.UserContext));
            ScopeExit retire{[&] { if (opened) (void)Release(fs, calls, response.Rsp.Create.Opened.UserContext, cleanup); }};
            FSP_FSCTL_FILE_INFO expected{};
            {
                std::lock_guard<std::mutex> lock(context.mutex);
                FillInfo(*root, ReportsReadOnly(&context), &expected);
                ok &= Require(result.operation == STATUS_SUCCESS && result.bypass && opened &&
                    calls.opens == opens + 1 && calls.published == published + 1 && calls.security > security &&
                    opened->cached_root_observation && opened->node == root && opened->lifetime_accounted &&
                    opened->file == INVALID_HANDLE_VALUE && !opened->named_stream && !opened->native_xattr &&
                    !opened->allow_read_data && !opened->allow_write_data && !opened->allow_append_data && !opened->allow_delete &&
                    root->open_handle_count == initial_open + 1 && root->live_context_count == initial_live + 1 &&
                    response.IoStatus.Information == FILE_OPENED && response.Rsp.Create.Opened.GrantedAccess == ObservationAccess &&
                    std::memcmp(&expected, &response.Rsp.Create.Opened.FileInfo, sizeof expected) == 0,
                    "SDK root: authorized SDK response contains real restricted context, accounting and cached file info");
            }
            if (opened)
            {
                ok &= Release(fs, calls, response.Rsp.Create.Opened.UserContext, cleanup);
                opened = nullptr;
            }
            ok &= Require(root->open_handle_count == initial_open && root->live_context_count == initial_live &&
                root->closing_context_count == initial_closing && VisibleInodeTimes(*root) == initial_times,
                "SDK root: Cleanup/Close and Close-only restore counts without changing visible times");
        }

        context.sd = deny;
        context.sd_size = GetSecurityDescriptorLength(deny);
        Request denied;
        PrepareOpen(denied, token);
        Result denied_result;
        const auto opens = calls.opens, published = calls.published, security = calls.security;
        ok &= UnderWriter(fs, denied, calls, true, denied_result, "explicit root SD read denial");
        ok &= Require(denied_result.operation == STATUS_ACCESS_DENIED && denied_result.bypass &&
            calls.security > security && calls.opens == opens && calls.published == published &&
            denied_result.Response().Rsp.Create.Opened.UserContext == 0 &&
            root->open_handle_count == initial_open && root->live_context_count == initial_live,
            "SDK root: real user-mode SD access denial reaches no Open and publishes no handle");

        context.sd = allow;
        context.sd_size = GetSecurityDescriptorLength(allow);
        Request offset;
        PrepareOpen(offset, token);
        constexpr WCHAR prefix[] = L"\\sdk-missing";
        std::memcpy(offset.Get().Buffer, prefix, sizeof prefix);
        offset.Name(L"\\", 64);
        Result offset_result;
        ok &= Require(!IsCachedRootObservationRequest(context, fs, offset.Get()),
            "SDK root: nonroot Buffer and later root offset are rejected by classifier");
        ok &= UnderWriter(fs, offset, calls, false, offset_result, "nonroot prefix with later root offset");
        ok &= Require(!offset_result.bypass && calls.nonroot_name && !calls.nonroot_bypass &&
            offset_result.operation == STATUS_OBJECT_NAME_NOT_FOUND && calls.opens == opens && calls.published == published,
            "SDK root: actual SDK sees nonroot Buffer only after original namespace guard releases");

        FSP_FSCTL_VOLUME_INFO expected_volume{};
        ok &= Require(CB_GetVolumeInfo(&fs, &expected_volume) == STATUS_SUCCESS, "SDK root: cached volume comparison");
        Request volume;
        volume.Get().Kind = FspFsctlTransactQueryVolumeInformationKind;
        volume.Get().Size = static_cast<UINT16>(root_observation_guard_tests::FixedRequestSize);
        Result volume_result;
        ok &= UnderWriter(fs, volume, calls, true, volume_result, "actual SDK cached volume operation");
        ok &= Require(volume_result.operation == STATUS_SUCCESS && volume_result.bypass &&
            std::memcmp(&expected_volume, &volume_result.Response().Rsp.QueryVolumeInformation.VolumeInfo, sizeof expected_volume) == 0,
            "SDK root: volume export copies cached callback geometry and label");
        ok &= Require(!calls.context_mismatch, "SDK root: no mismatched SDK operation context");
        absent_contexts += calls.absent_sdk_contexts;
        std::cout << "SDK_ROOT_MODE perf=" << WideToUtf8(perf) << " security_calls=" << calls.security
                  << " open_calls=" << calls.opens << " publications=" << calls.published
                  << " sdk_tls_contexts=" << calls.sdk_contexts << " sdk_tls_absent=" << calls.absent_sdk_contexts << '\n';
    }
    if (absent_contexts)
        std::cout << "SDK_ROOT_LIMITATION: SDK operation TLS is absent on this software worker thread. "
            "No context was fabricated. Real exported operations and AccessCheck ran with explicit requests; "
            "the SDK driver-backed dispatcher and its TLS setup remain for the isolated physical gate.\n";
    std::cout << "SDK_ROOT_EXPORTED_OPERATIONS=" << (ok ? "PASS" : "FAIL") << '\n';
    return ok;
}
