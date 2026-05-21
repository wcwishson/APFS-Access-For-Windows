#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <objbase.h>
#include <memory>
#include <mutex>
#include <limits>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <windows.h>
#include <winternl.h>
#include <sddl.h>
#include <shlobj.h>
#ifndef PNTSTATUS
typedef NTSTATUS* PNTSTATUS;
#endif
#include <winfsp/winfsp.h>

#ifdef APFSACCESS_HAS_RW_ENGINE
#include "MetadataStore.h"
#include "TransactionManager.h"
#endif

namespace
{
struct Arguments
{
    std::wstring device;
    std::wstring volume;
    std::wstring mount;
    std::wstring lifetime_file;
    std::wstring status_file;
    std::uint64_t device_offset_bytes = 0;
    std::wstring write_safety_level = L"Conservative";
    std::wstring write_backend = L"Disabled";
    int write_commit_timeout_seconds = 15;
    int write_max_dirty_transactions = 128;
    std::wstring write_recovery_policy = L"FailClosed";
    std::wstring write_crash_replay_mode = L"FailClosed";
    bool write_require_canonical_commit = true;
    bool write_integrity_check_on_mount = true;
    bool allow_raw_physical_write = false;
    bool allow_legacy_scaffold_for_fixtures = true;
    bool write_disallow_scaffold_commit_on_non_fixture = true;
    bool write_reject_scaffold_replay_blob_on_non_fixture = true;
    bool write_require_canonical_replay_candidate_on_non_fixture = true;
    int validation_crash_fault_passes = 0;
    int validation_crash_stage_matrix_passes = 0;
    int validation_hardware_pilot_passes = 0;
    int validation_hot_unplug_passes = 0;
    int validation_macos_validation_passes = 0;
    int validation_macos_consistency_passes = 0;
    int validation_power_loss_replay_passes = 0;
    bool validation_power_loss_pass_verified = false;
    std::wstring validation_last_validated_utc;
    std::wstring validation_last_profile_id;
    bool readonly = false;
    bool readwrite = false;
};

struct DirEntry
{
    bool is_directory = false;
    std::wstring name;
    std::uint64_t file_size = 0;
};

struct Node
{
    std::wstring path;
    std::wstring apfs_path;
    bool is_directory = false;
    std::uint64_t file_size = 0;
    FILETIME timestamp{};
    bool loaded = false;
    std::vector<std::wstring> children;
    std::uint32_t open_handle_count = 0;
    std::uint32_t write_handle_count = 0;
    std::uint32_t delete_intent_count = 0;
    bool delete_latched = false;
    bool delete_pending = false;
};

struct OpenContext
{
    std::shared_ptr<Node> node;
    HANDLE file = INVALID_HANDLE_VALUE;
    UINT32 granted_access = 0;
    bool allow_read_data = false;
    bool allow_list_directory = false;
    bool allow_write_data = false;
    bool allow_append_data = false;
    bool allow_set_basic_info = false;
    bool allow_set_file_size = false;
    bool allow_delete = false;
    bool allow_delete_child = false;
    bool write_open = false;
    bool delete_on_cleanup = false;
    bool metadata_read_fallback = false;
    bool cleanup_seen = false;
};

struct WinFspApi
{
    using PFN_Create = NTSTATUS (*)(PWSTR, const FSP_FSCTL_VOLUME_PARAMS *, const FSP_FILE_SYSTEM_INTERFACE *, FSP_FILE_SYSTEM **);
    using PFN_Delete = VOID (*)(FSP_FILE_SYSTEM *);
    using PFN_SetMount = NTSTATUS (*)(FSP_FILE_SYSTEM *, PWSTR);
    using PFN_Start = NTSTATUS (*)(FSP_FILE_SYSTEM *, ULONG);
    using PFN_Stop = VOID (*)(FSP_FILE_SYSTEM *);
    using PFN_AddDir = BOOLEAN (*)(FSP_FSCTL_DIR_INFO *, PVOID, ULONG, PULONG);

    HMODULE dll = nullptr;
    PFN_Create Create = nullptr;
    PFN_Delete Delete = nullptr;
    PFN_SetMount SetMount = nullptr;
    PFN_Start Start = nullptr;
    PFN_Stop Stop = nullptr;
    PFN_AddDir AddDir = nullptr;

    bool Load(std::wstring& err)
    {
        const wchar_t* candidates[] = {
            L"winfsp-x64.dll",
            L"C:\\Program Files (x86)\\WinFsp\\bin\\winfsp-x64.dll",
            L"C:\\Program Files\\WinFsp\\bin\\winfsp-x64.dll",
        };
        for (const auto* c : candidates)
        {
            dll = LoadLibraryW(c);
            if (dll != nullptr)
            {
                break;
            }
        }
        if (!dll)
        {
            err = L"Cannot load winfsp-x64.dll.";
            return false;
        }
        auto load = [&](auto& fn, const char* n)
        {
            fn = reinterpret_cast<std::remove_reference_t<decltype(fn)>>(GetProcAddress(dll, n));
            return fn != nullptr;
        };
        if (!load(Create, "FspFileSystemCreate") ||
            !load(Delete, "FspFileSystemDelete") ||
            !load(SetMount, "FspFileSystemSetMountPoint") ||
            !load(Start, "FspFileSystemStartDispatcher") ||
            !load(Stop, "FspFileSystemStopDispatcher") ||
            !load(AddDir, "FspFileSystemAddDirInfo"))
        {
            err = L"winfsp-x64.dll missing required exports.";
            return false;
        }
        return true;
    }
};

struct ScopeExit
{
    std::function<void()> callback;

    ~ScopeExit()
    {
        if (callback)
        {
            callback();
        }
    }
};

struct MountContext
{
    Arguments args;
    WinFspApi api;
    FSP_FILE_SYSTEM* fs = nullptr;
    std::wstring label;
    PSECURITY_DESCRIPTOR sd = nullptr;
    ULONG sd_size = 0;
    std::filesystem::path session_root;
    std::filesystem::path cache_root;
    bool overlay_write_enabled = false;
    bool native_write_enabled = false;
    std::filesystem::path recovery_marker_file;
    bool recovery_active = false;
    bool write_degraded = false;
    bool pending_native_writes = false;
    std::optional<std::uint64_t> runtime_last_commit_xid;
    std::wstring runtime_recovery_reason;
    std::wstring runtime_last_recovery_action;
    std::string last_status_write_contents;
    std::optional<bool> last_recovery_marker_dirty;
    std::optional<std::uint64_t> last_recovery_marker_commit_xid;
    std::uint32_t reported_allocation_unit_bytes = 4096;
    std::optional<std::uint64_t> reported_total_size_bytes;
    std::optional<std::uint64_t> reported_free_size_bytes;
    std::atomic<bool> mount_ready{false};
    std::mutex mutex;
    std::atomic<bool> shutdown_drain_active{false};
    std::atomic<std::uint32_t> active_external_mutation_callbacks{0};
    // Serialize mutating callback flows to avoid namespace/delete-intent interleaving races.
    std::mutex mutation_callback_mutex;
    std::unordered_map<std::wstring, std::shared_ptr<Node>> nodes;
#ifdef APFSACCESS_HAS_RW_ENGINE
    mutable std::mutex metadata_mutex;
    mutable std::mutex commit_mutex;
    std::atomic<std::uint64_t> commit_deadline_tick_ms{0};
    std::atomic<bool> commit_timeout_latched{false};
    mutable std::mutex tx_mutex;
    std::unique_ptr<apfsaccess::rw::TransactionManager> tx_manager;
    std::filesystem::path tx_journal_file;
    std::unique_ptr<apfsaccess::rw::MetadataStore> metadata_store;
#endif
};

#ifdef APFSACCESS_HAS_RW_ENGINE
bool MergeCommittedInodeStateIntoNodeIndex(MountContext* c);
#endif

struct MutationCallbackScope
{
    explicit MutationCallbackScope(MountContext* context)
        : lock_(context
                    ? std::unique_lock<std::mutex>(context->mutation_callback_mutex)
                    : std::unique_lock<std::mutex>())
    {
    }

private:
    std::unique_lock<std::mutex> lock_;
};

bool WriteHostStatusFile(
    MountContext& context,
    bool recovery_active = false,
    std::optional<std::uint64_t> last_commit_xid = std::nullopt
);

struct ExternalMutationRequestScope
{
    explicit ExternalMutationRequestScope(MountContext* context)
        : context_(context),
          acquired_(TryEnter(context_))
    {
    }

    ~ExternalMutationRequestScope()
    {
        if (acquired_ && context_)
        {
            context_->active_external_mutation_callbacks.fetch_sub(1, std::memory_order_acq_rel);
            (void)WriteHostStatusFile(*context_, context_->recovery_active, context_->runtime_last_commit_xid);
        }
    }

    bool Acquired() const noexcept
    {
        return acquired_;
    }

private:
    static bool TryEnter(MountContext* context)
    {
        if (!context)
        {
            return false;
        }

        if (context->shutdown_drain_active.load(std::memory_order_acquire))
        {
            return false;
        }

        context->active_external_mutation_callbacks.fetch_add(1, std::memory_order_acq_rel);
        if (context->shutdown_drain_active.load(std::memory_order_acquire))
        {
            context->active_external_mutation_callbacks.fetch_sub(1, std::memory_order_acq_rel);
            return false;
        }

        return true;
    }

    MountContext* context_ = nullptr;
    bool acquired_ = false;
};

bool IsMutationWriteEnabled(const MountContext* c);
NTSTATUS HandleMutationWriteDisabled(MountContext* c, const wchar_t* operation);
#ifdef APFSACCESS_HAS_RW_ENGINE
void RefreshReportedVolumeInfoFromMetadata(MountContext& ctx);
#endif

std::atomic<bool> g_exit{false};

bool IsOption(const wchar_t* a, const wchar_t* n) { return a && _wcsicmp(a, n) == 0; }

bool IsHostCommitTraceEnabled()
{
    static const bool enabled = []()
    {
        wchar_t value[8]{};
        const auto chars = GetEnvironmentVariableW(L"APFSACCESS_TRACE_COMMITS", value, static_cast<DWORD>(std::size(value)));
        return chars > 0 && value[0] != L'\0' && value[0] != L'0';
    }();
    return enabled;
}

std::wstring NextArgValue(int& i, int argc, wchar_t** argv)
{
    if (i + 1 >= argc)
    {
        return L"";
    }
    ++i;
    return argv[i] ? argv[i] : L"";
}

std::string WideToUtf8(const std::wstring& in)
{
    if (in.empty())
    {
        return {};
    }
    int n = WideCharToMultiByte(CP_UTF8, 0, in.c_str(), (int)in.size(), nullptr, 0, nullptr, nullptr);
    if (n <= 0)
    {
        return {};
    }
    std::string out((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, in.c_str(), (int)in.size(), out.data(), n, nullptr, nullptr);
    return out;
}

std::wstring Utf8ToWide(const std::string& in)
{
    if (in.empty())
    {
        return {};
    }
    int n = MultiByteToWideChar(CP_UTF8, 0, in.c_str(), (int)in.size(), nullptr, 0);
    if (n <= 0)
    {
        return {};
    }
    std::wstring out((size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, in.c_str(), (int)in.size(), out.data(), n);
    return out;
}

std::wstring QuoteArg(const std::wstring& arg)
{
    if (arg.empty())
    {
        return L"\"\"";
    }
    if (arg.find_first_of(L" \t\"") == std::wstring::npos)
    {
        return arg;
    }
    std::wstring out = L"\"";
    int bs = 0;
    for (wchar_t ch : arg)
    {
        if (ch == L'\\')
        {
            ++bs;
            continue;
        }
        if (ch == L'"')
        {
            out.append((size_t)(bs * 2 + 1), L'\\');
            out.push_back(ch);
            bs = 0;
            continue;
        }
        out.append((size_t)bs, L'\\');
        bs = 0;
        out.push_back(ch);
    }
    out.append((size_t)(bs * 2), L'\\');
    out.push_back(L'"');
    return out;
}

std::wstring BuildCommandLine(const std::wstring& exe, const std::vector<std::wstring>& args)
{
    std::wstring cmd = QuoteArg(exe);
    for (const auto& a : args)
    {
        cmd.push_back(L' ');
        cmd += QuoteArg(a);
    }
    return cmd;
}

bool RunProcessCapture(const std::wstring& exe, const std::vector<std::wstring>& args, std::string& output, DWORD& exit_code)
{
    output.clear();
    exit_code = (DWORD)-1;

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE rp = nullptr, wp = nullptr;
    if (!CreatePipe(&rp, &wp, &sa, 0))
    {
        return false;
    }
    SetHandleInformation(rp, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = wp;
    si.hStdError = wp;

    PROCESS_INFORMATION pi{};
    auto cmd = BuildCommandLine(exe, args);
    BOOL ok = CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(wp);
    if (!ok)
    {
        CloseHandle(rp);
        return false;
    }

    char buf[4096];
    DWORD read = 0;
    while (ReadFile(rp, buf, sizeof(buf), &read, nullptr) && read > 0)
    {
        output.append(buf, buf + read);
    }
    CloseHandle(rp);
    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}

bool RunProcessToFile(const std::wstring& exe, const std::vector<std::wstring>& args, const std::filesystem::path& file, DWORD& exit_code)
{
    exit_code = (DWORD)-1;
    std::filesystem::create_directories(file.parent_path());
    HANDLE fh = CreateFileW(file.wstring().c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (fh == INVALID_HANDLE_VALUE)
    {
        return false;
    }
    HANDLE nh = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (nh == INVALID_HANDLE_VALUE)
    {
        CloseHandle(fh);
        return false;
    }
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = fh;
    si.hStdError = nh;
    PROCESS_INFORMATION pi{};
    auto cmd = BuildCommandLine(exe, args);
    BOOL ok = CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(fh);
    CloseHandle(nh);
    if (!ok)
    {
        return false;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}

std::wstring NormalizePath(const std::wstring& in)
{
    if (in.empty())
    {
        return L"\\";
    }
    std::wstring p = in;
    std::replace(p.begin(), p.end(), L'/', L'\\');
    if (p.size() >= 2 &&
        ((p[0] >= L'A' && p[0] <= L'Z') || (p[0] >= L'a' && p[0] <= L'z')) &&
        p[1] == L':')
    {
        p.erase(0, 2);
        if (p.empty())
        {
            return L"\\";
        }
    }
    if (p.front() != L'\\')
    {
        p.insert(p.begin(), L'\\');
    }
    while (p.size() > 1 && p.back() == L'\\')
    {
        p.pop_back();
    }
    return p;
}

std::wstring Key(std::wstring p)
{
    p = NormalizePath(p);
    std::transform(p.begin(), p.end(), p.begin(), [](wchar_t c) { return (wchar_t)towlower(c); });
    return p;
}

bool IsDescendantPath(const std::wstring& candidate_path, const std::wstring& ancestor_path)
{
    auto candidate_key = Key(candidate_path);
    auto ancestor_key = Key(ancestor_path);
    if (candidate_key.empty() || ancestor_key.empty())
    {
        return false;
    }
    if (candidate_key == ancestor_key)
    {
        return false;
    }

    if (ancestor_key.size() == 1 && ancestor_key.front() == L'\\')
    {
        return candidate_key.size() > 1 && candidate_key.front() == L'\\';
    }

    auto ancestor_prefix = ancestor_key;
    if (ancestor_prefix.back() != L'\\')
    {
        ancestor_prefix.push_back(L'\\');
    }

    return candidate_key.rfind(ancestor_prefix, 0) == 0;
}

bool IsRecycleBinPath(const std::wstring& path)
{
    const auto key = Key(path);
    constexpr const wchar_t* kRecycleBinRoot = L"\\$recycle.bin";
    return key == kRecycleBinRoot ||
           key.rfind(std::wstring(kRecycleBinRoot) + L"\\", 0) == 0;
}

UINT32 BuildFileAttributes(const Node& node, bool read_only)
{
    UINT32 attributes = node.is_directory
        ? FILE_ATTRIBUTE_DIRECTORY
        : FILE_ATTRIBUTE_ARCHIVE;

    if (IsRecycleBinPath(node.path))
    {
        attributes |= FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM;
    }

    if (!node.is_directory && read_only)
    {
        attributes |= FILE_ATTRIBUTE_READONLY;
    }

    return attributes;
}

std::uint32_t StableHashUtf16(std::uint32_t hash, const std::wstring& value)
{
    // FNV-1a over UTF-16 code units is enough for a stable Windows volume serial.
    constexpr std::uint32_t kFnvPrime = 16777619u;
    for (const auto ch : value)
    {
        const auto code = static_cast<std::uint32_t>(ch);
        hash ^= (code & 0xffu);
        hash *= kFnvPrime;
        hash ^= ((code >> 8) & 0xffu);
        hash *= kFnvPrime;
    }
    return hash;
}

std::uint32_t BuildStableVolumeSerial(const Arguments& args)
{
    constexpr std::uint32_t kFnvOffset = 2166136261u;
    constexpr std::uint32_t kFnvPrime = 16777619u;

    auto hash = StableHashUtf16(kFnvOffset, args.device);
    hash ^= L'|';
    hash *= kFnvPrime;
    hash = StableHashUtf16(hash, args.volume);
    for (int shift = 0; shift < 64; shift += 8)
    {
        hash ^= static_cast<std::uint32_t>((args.device_offset_bytes >> shift) & 0xffu);
        hash *= kFnvPrime;
    }

    return hash == 0 ? 1u : hash;
}

bool EqualsIgnoreCase(const std::wstring& a, const std::wstring& b)
{
    return _wcsicmp(a.c_str(), b.c_str()) == 0;
}

std::wstring SanitizeFileComponent(std::wstring value)
{
    if (value.empty())
    {
        return L"apfs";
    }

    constexpr wchar_t kInvalid[] = L"<>:\"/\\|?*";
    for (auto& ch : value)
    {
        if (ch < 0x20 || std::wcschr(kInvalid, ch))
        {
            ch = L'_';
        }
    }
    return value;
}

bool IsWriteBackendMode(const std::wstring& value, const wchar_t* expected)
{
    return expected && !_wcsicmp(value.c_str(), expected);
}

bool IsRecoveryPolicyFailClosed(const std::wstring& value)
{
    if (value.empty())
    {
        return true;
    }

    return !_wcsicmp(value.c_str(), L"FailClosed");
}

bool IsCrashReplayModeReplayIfSafe(const std::wstring& value)
{
    return !_wcsicmp(value.c_str(), L"ReplayIfSafe");
}

bool ParseBoolToken(const std::wstring& value, bool fallback)
{
    if (value.empty())
    {
        return fallback;
    }

    if (!_wcsicmp(value.c_str(), L"1") ||
        !_wcsicmp(value.c_str(), L"true") ||
        !_wcsicmp(value.c_str(), L"yes") ||
        !_wcsicmp(value.c_str(), L"on"))
    {
        return true;
    }

    if (!_wcsicmp(value.c_str(), L"0") ||
        !_wcsicmp(value.c_str(), L"false") ||
        !_wcsicmp(value.c_str(), L"no") ||
        !_wcsicmp(value.c_str(), L"off"))
    {
        return false;
    }

    return fallback;
}

UINT32 NormalizeGrantedAccess(UINT32 granted_access)
{
    UINT32 normalized = granted_access;
    if ((granted_access & GENERIC_ALL) != 0)
    {
        normalized |= FILE_ALL_ACCESS;
    }
    if ((granted_access & GENERIC_READ) != 0)
    {
        normalized |= FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE;
    }
    if ((granted_access & GENERIC_WRITE) != 0)
    {
        normalized |= FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE;
    }
    if ((granted_access & GENERIC_EXECUTE) != 0)
    {
        normalized |= FILE_EXECUTE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE;
    }
    return normalized;
}

bool HasGrantedMutationAccess(UINT32 granted_access)
{
    constexpr UINT32 kMutationMask =
        FILE_WRITE_DATA |
        FILE_APPEND_DATA |
        FILE_WRITE_EA |
        FILE_WRITE_ATTRIBUTES |
        DELETE |
        FILE_DELETE_CHILD;

    const UINT32 normalized = NormalizeGrantedAccess(granted_access);
    return (normalized & kMutationMask) != 0;
}

bool HasOpenMutationIntent(UINT32 granted_access, UINT32 create_options)
{
    if (HasGrantedMutationAccess(granted_access))
    {
        return true;
    }

    // Delete-on-close mutates namespace state even when requested access bits are
    // minimal; treat it as mutation intent for shutdown-drain and write-mode gates.
    return (create_options & FILE_DELETE_ON_CLOSE) != 0;
}

bool HasConflictingCreateTypeOptions(UINT32 create_options)
{
    return ((create_options & FILE_DIRECTORY_FILE) != 0) &&
           ((create_options & FILE_NON_DIRECTORY_FILE) != 0);
}

DWORD ResolveHydrationDesiredAccess(bool mutation_enabled, UINT32 granted_access, bool force_write_intent)
{
    const UINT32 normalized = NormalizeGrantedAccess(granted_access);
    constexpr UINT32 kReadMask =
        FILE_READ_DATA |
        FILE_READ_EA |
        FILE_READ_ATTRIBUTES |
        FILE_EXECUTE;

    const auto write_intent = mutation_enabled && (force_write_intent || HasGrantedMutationAccess(granted_access));
    const auto read_intent = !write_intent || (normalized & kReadMask) != 0;

    DWORD desired_access = 0;
    if (read_intent)
    {
        desired_access |= GENERIC_READ;
    }
    if (write_intent)
    {
        desired_access |= GENERIC_WRITE;
    }
    if (desired_access == 0)
    {
        desired_access = GENERIC_READ;
    }
    return desired_access;
}

DWORD ResolveHydrationShareMode(bool mutation_enabled, UINT32 granted_access, bool write_open)
{
    UNREFERENCED_PARAMETER(mutation_enabled);
    UNREFERENCED_PARAMETER(granted_access);
    UNREFERENCED_PARAMETER(write_open);

    // User-mode APFS writes are staged through the host before being committed
    // to the physical device. Keep the local hydration handle maximally
    // shareable so shell previewers, indexers and Office lock-file probes do
    // not mistake the staging handle for an application-level file lock.
    return FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
}

void InitializeOpenAccess(OpenContext* open_ctx, UINT32 granted_access)
{
    if (!open_ctx)
    {
        return;
    }

    const UINT32 normalized = NormalizeGrantedAccess(granted_access);
    open_ctx->granted_access = normalized;
    open_ctx->allow_read_data = (normalized & (FILE_READ_DATA | FILE_EXECUTE)) != 0;
    open_ctx->allow_list_directory = (normalized & FILE_LIST_DIRECTORY) != 0;
    open_ctx->allow_write_data = (normalized & FILE_WRITE_DATA) != 0;
    open_ctx->allow_append_data = (normalized & FILE_APPEND_DATA) != 0;
    open_ctx->allow_set_basic_info = (normalized & FILE_WRITE_ATTRIBUTES) != 0;
    open_ctx->allow_set_file_size = open_ctx->allow_write_data || open_ctx->allow_append_data;
    open_ctx->allow_delete = (normalized & DELETE) != 0;
    open_ctx->allow_delete_child = (normalized & FILE_DELETE_CHILD) != 0;
}

PSECURITY_DESCRIPTOR BuildWritableVolumeSecurityDescriptor(ULONG* descriptor_size)
{
    if (descriptor_size)
    {
        *descriptor_size = 0;
    }

    PSECURITY_DESCRIPTOR descriptor = nullptr;
    // APFS does not persist Windows ACLs. Present a permissive removable-drive
    // style descriptor so Explorer and Office shell extensions can create
    // files/templates without interpreting the mount as read-only to the user.
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;BU)(A;;FA;;;AU)(A;;FA;;;WD)",
            SDDL_REVISION_1,
            &descriptor,
            descriptor_size))
    {
        return nullptr;
    }

    return descriptor;
}

struct RecoveryMarkerState
{
    bool dirty = false;
    std::optional<std::uint64_t> last_commit_xid;
};

bool TryLoadRecoveryMarkerState(const std::filesystem::path& marker_path, RecoveryMarkerState& state)
{
    state = RecoveryMarkerState{};
    std::error_code ec;
    if (!std::filesystem::exists(marker_path, ec) || ec)
    {
        return false;
    }

    std::ifstream in(marker_path, std::ios::binary);
    if (!in.good())
    {
        return false;
    }

    std::string line;
    while (std::getline(in, line))
    {
        auto split = line.find('=');
        if (split == std::string::npos)
        {
            continue;
        }

        auto key = line.substr(0, split);
        auto value = line.substr(split + 1);
        if (key == "dirty")
        {
            state.dirty = (value == "1" || value == "true" || value == "True");
            continue;
        }

        if (key == "lastCommitXid" && !value.empty())
        {
            try
            {
                state.last_commit_xid = static_cast<std::uint64_t>(std::stoull(value));
            }
            catch (...)
            {
                // Ignore malformed persisted xid.
            }
        }
    }

    return true;
}

bool PersistRecoveryMarkerState(MountContext* context, const std::filesystem::path& marker_path, const RecoveryMarkerState& state)
{
    if (context &&
        context->last_recovery_marker_dirty.has_value() &&
        context->last_recovery_marker_dirty.value() == state.dirty &&
        context->last_recovery_marker_commit_xid == state.last_commit_xid)
    {
        return true;
    }

    try
    {
        if (marker_path.has_parent_path())
        {
            std::filesystem::create_directories(marker_path.parent_path());
        }

        std::ofstream out(marker_path, std::ios::binary | std::ios::trunc);
        if (!out.good())
        {
            return false;
        }

        out << "dirty=" << (state.dirty ? "1" : "0") << "\n";
        out << "lastCommitXid=";
        if (state.last_commit_xid.has_value())
        {
            out << *state.last_commit_xid;
        }
        out << "\n";
        if (!out.good())
        {
            return false;
        }

        if (context)
        {
            context->last_recovery_marker_dirty = state.dirty;
            context->last_recovery_marker_commit_xid = state.last_commit_xid;
        }
        return true;
    }
    catch (...)
    {
        return false;
    }
}

std::string EscapeJson(const std::string& value)
{
    std::string out;
    out.reserve(value.size());
    for (const char ch : value)
    {
        switch (ch)
        {
        case '\\': out += "\\\\"; break;
        case '"': out += "\\\""; break;
        case '\r': out += "\\r"; break;
        case '\n': out += "\\n"; break;
        case '\t': out += "\\t"; break;
        default:
            if (static_cast<unsigned char>(ch) < 0x20)
            {
                out += '?';
            }
            else
            {
                out.push_back(ch);
            }
            break;
        }
    }
    return out;
}

std::wstring ResolveWriteBackendStatus(const MountContext& context)
{
    if (!context.args.readwrite)
    {
        return L"Disabled";
    }

    if (context.native_write_enabled)
    {
        return L"Native";
    }

    if (context.overlay_write_enabled)
    {
        return L"Overlay";
    }

    return L"Disabled";
}

bool RequiresCanonicalMutationGate(const Arguments& args);

std::wstring ResolveNativeWriteReadinessStatus(const MountContext& context)
{
    if (!context.args.readwrite)
    {
        return L"Unavailable";
    }

    if (context.write_degraded)
    {
        return L"Degraded";
    }

    if (context.overlay_write_enabled)
    {
        return L"MutationReady";
    }

    if (!context.native_write_enabled)
    {
        return L"Unavailable";
    }

#ifdef APFSACCESS_HAS_RW_ENGINE
    {
        std::lock_guard<std::mutex> metadata_lock(context.metadata_mutex);
        if (!context.metadata_store)
        {
            return L"Unavailable";
        }

        if (context.metadata_store->IsRecoveryRequired() || context.recovery_active)
        {
            return L"RecoveryMode";
        }

        if (RequiresCanonicalMutationGate(context.args) &&
            context.metadata_store->IsCommitPathReady() &&
            !context.metadata_store->IsCanonicalCommitReady())
        {
            return L"MutationReady";
        }

        if (context.metadata_store->IsCommitPathReady())
        {
            return L"CommitReady";
        }

        if (context.metadata_store->IsNativeWriteReady())
        {
            return L"MutationReady";
        }

        if (context.metadata_store->IsContainerLoaded())
        {
            return L"BootstrapReady";
        }
    }
#endif

    return L"Unavailable";
}

std::wstring ResolveRecoveryReasonStatus(const MountContext& context, bool recovery_active)
{
    if (!recovery_active)
    {
        return L"";
    }

    if (!context.runtime_recovery_reason.empty())
    {
        return context.runtime_recovery_reason;
    }

#ifdef APFSACCESS_HAS_RW_ENGINE
    std::lock_guard<std::mutex> metadata_lock(context.metadata_mutex);
    if (context.metadata_store && context.metadata_store->IsRecoveryRequired())
    {
        const auto reason = context.metadata_store->RecoveryReason();
        if (!reason.empty())
        {
            return reason;
        }
    }
#endif

    return L"RecoveryActive";
}

bool IsCanonicalGateFailureReason(const std::wstring& reason)
{
    if (reason.empty())
    {
        return false;
    }

    return !_wcsicmp(reason.c_str(), L"CanonicalPathNotActive") ||
           !_wcsicmp(reason.c_str(), L"CanonicalStateNotLoaded") ||
           !_wcsicmp(reason.c_str(), L"CanonicalVolumeStateLoadFailed") ||
           !_wcsicmp(reason.c_str(), L"CanonicalObjectMapStateInvalid") ||
           !_wcsicmp(reason.c_str(), L"CanonicalSpacemanStateInvalid") ||
           !_wcsicmp(reason.c_str(), L"CanonicalVolumeTreeStateInvalid") ||
           !_wcsicmp(reason.c_str(), L"NativeWriteNotReady") ||
           !_wcsicmp(reason.c_str(), L"WriteDeviceNotAllowed") ||
           !_wcsicmp(reason.c_str(), L"CommitPathNotReady") ||
           !_wcsicmp(reason.c_str(), L"CanonicalCommitNotReady");
}

bool IsFixtureLegacyFallbackReason(const std::wstring& reason)
{
    return !reason.empty() &&
           !_wcsicmp(reason.c_str(), L"FixtureLegacyFallbackActive");
}

bool IsFixtureCompatibilityPathReason(const std::wstring& reason)
{
    return !reason.empty() &&
           !_wcsicmp(reason.c_str(), L"FixtureCompatibilityPathActive");
}

bool IsScaffoldCommitBlobReason(const std::wstring& reason)
{
    return !reason.empty() &&
           !_wcsicmp(reason.c_str(), L"ScaffoldCommitBlobActive");
}

std::wstring ResolveNativeWriteCommitModelStatus(const MountContext& context)
{
    if (!context.args.readwrite)
    {
        return L"ScaffoldCheckpoint";
    }

    const auto write_backend = ResolveWriteBackendStatus(context);
    if (_wcsicmp(write_backend.c_str(), L"Native") != 0)
    {
        return L"ScaffoldCheckpoint";
    }

#ifdef APFSACCESS_HAS_RW_ENGINE
    std::lock_guard<std::mutex> metadata_lock(context.metadata_mutex);
    if (context.metadata_store &&
        context.metadata_store->ActiveCommitModel() ==
            apfsaccess::rw::MetadataStore::NativeWriteCommitModel::CanonicalApfsCheckpoint)
    {
        return L"CanonicalApfsCheckpoint";
    }
#endif

    return L"ScaffoldCheckpoint";
}

std::wstring ResolveNativeWriteValidationStateStatus(const MountContext& context)
{
    if (!context.args.readwrite)
    {
        return L"Scaffold";
    }

    const auto write_backend = ResolveWriteBackendStatus(context);
    if (_wcsicmp(write_backend.c_str(), L"Native") != 0)
    {
        return L"Scaffold";
    }

#ifdef APFSACCESS_HAS_RW_ENGINE
    {
        std::lock_guard<std::mutex> metadata_lock(context.metadata_mutex);
        if (context.metadata_store)
        {
            switch (context.metadata_store->ValidationState())
            {
            case apfsaccess::rw::MetadataStore::NativeWriteValidationState::Stable:
                return L"Stable";
            case apfsaccess::rw::MetadataStore::NativeWriteValidationState::CrossOsValidated:
                return L"CrossOsValidated";
            case apfsaccess::rw::MetadataStore::NativeWriteValidationState::HardwarePilotValidated:
                return L"HardwarePilotValidated";
            case apfsaccess::rw::MetadataStore::NativeWriteValidationState::CanonicalImageValidated:
                return L"CanonicalImageValidated";
            case apfsaccess::rw::MetadataStore::NativeWriteValidationState::Scaffold:
            default:
                break;
            }
        }
    }
#endif

    return L"Scaffold";
}

bool ResolveFixtureLegacyFallbackStatus(const MountContext& context)
{
    if (!context.args.readwrite)
    {
        return false;
    }

    const auto write_backend = ResolveWriteBackendStatus(context);
    if (_wcsicmp(write_backend.c_str(), L"Native") != 0)
    {
        // Preserve explicit fail-closed fixture fallback reasons after native
        // runtime downgrades write backend to Disabled.
        if (IsFixtureLegacyFallbackReason(context.runtime_recovery_reason))
        {
            return true;
        }
        return false;
    }

#ifdef APFSACCESS_HAS_RW_ENGINE
    std::lock_guard<std::mutex> metadata_lock(context.metadata_mutex);
    if (context.metadata_store)
    {
        return context.metadata_store->IsFixtureLegacyFallbackActive();
    }
#endif

    return false;
}

bool ResolveFixtureCompatibilityPathStatus(const MountContext& context)
{
    if (!context.args.readwrite)
    {
        return false;
    }

    const auto write_backend = ResolveWriteBackendStatus(context);
    if (_wcsicmp(write_backend.c_str(), L"Native") != 0)
    {
        // Preserve explicit compatibility-path fail-closed reasons after
        // native runtime downgrade.
        if (IsFixtureCompatibilityPathReason(context.runtime_recovery_reason))
        {
            return true;
        }
        return false;
    }

#ifdef APFSACCESS_HAS_RW_ENGINE
    std::lock_guard<std::mutex> metadata_lock(context.metadata_mutex);
    if (context.metadata_store)
    {
        return context.metadata_store->IsFixtureCompatibilityPathActive();
    }
#endif

    return false;
}

bool ResolveUsesScaffoldCommitBlobStatus(const MountContext& context)
{
    if (!context.args.readwrite)
    {
        return false;
    }

    const auto write_backend = ResolveWriteBackendStatus(context);
    if (_wcsicmp(write_backend.c_str(), L"Native") != 0)
    {
        // Preserve scaffold commit-blob fail-closed reason visibility after
        // native runtime downgrade.
        if (IsScaffoldCommitBlobReason(context.runtime_recovery_reason))
        {
            return true;
        }
        return false;
    }

#ifdef APFSACCESS_HAS_RW_ENGINE
    std::lock_guard<std::mutex> metadata_lock(context.metadata_mutex);
    if (context.metadata_store)
    {
        return context.metadata_store->UsesScaffoldCommitBlob();
    }
#endif

    return false;
}

std::optional<bool> ResolveCanonicalPathActiveStatus(const MountContext& context)
{
    if (!context.args.readwrite)
    {
        return std::nullopt;
    }

    const auto write_backend = ResolveWriteBackendStatus(context);
    if (_wcsicmp(write_backend.c_str(), L"Native") != 0)
    {
        // When native mode was already fail-closed to Disabled, preserve explicit
        // canonical gate proof failure as `canonicalPathActive=false` so downstream
        // policy mapping remains specific instead of appearing unknown.
        if (IsCanonicalGateFailureReason(context.runtime_recovery_reason))
        {
            return false;
        }
        return std::nullopt;
    }

#ifdef APFSACCESS_HAS_RW_ENGINE
    std::lock_guard<std::mutex> metadata_lock(context.metadata_mutex);
    if (context.metadata_store)
    {
        return context.metadata_store->IsProductionCanonicalPathActive();
    }
#endif

    return std::nullopt;
}

std::wstring ResolveCanonicalGateFailureStatus(const MountContext& context)
{
    if (!context.args.readwrite)
    {
        return L"";
    }

    const auto write_backend = ResolveWriteBackendStatus(context);
    if (_wcsicmp(write_backend.c_str(), L"Native") != 0)
    {
        if (IsCanonicalGateFailureReason(context.runtime_recovery_reason))
        {
            return context.runtime_recovery_reason;
        }
        return L"";
    }

#ifdef APFSACCESS_HAS_RW_ENGINE
    std::lock_guard<std::mutex> metadata_lock(context.metadata_mutex);
    if (context.metadata_store)
    {
        const auto gate_failure = context.metadata_store->LastCanonicalGateFailure();
        if (!gate_failure.empty())
        {
            return gate_failure;
        }

        const auto recovery_reason = context.metadata_store->RecoveryReason();
        if (IsCanonicalGateFailureReason(recovery_reason))
        {
            return recovery_reason;
        }
    }
#endif

    if (IsCanonicalGateFailureReason(context.runtime_recovery_reason))
    {
        return context.runtime_recovery_reason;
    }

    return L"";
}

std::optional<bool> ResolveReplayCheckpointCandidatePresentStatus(const MountContext& context)
{
    if (!context.args.readwrite)
    {
        return std::nullopt;
    }

    const auto write_backend = ResolveWriteBackendStatus(context);
    if (_wcsicmp(write_backend.c_str(), L"Native") != 0)
    {
        return std::nullopt;
    }

#ifdef APFSACCESS_HAS_RW_ENGINE
    std::lock_guard<std::mutex> metadata_lock(context.metadata_mutex);
    if (context.metadata_store)
    {
        return context.metadata_store->LastReplayCheckpointCandidatePresent();
    }
#endif

    return std::nullopt;
}

std::optional<bool> ResolveReplayCheckpointPendingWindowStatus(const MountContext& context)
{
    if (!context.args.readwrite)
    {
        return std::nullopt;
    }

    const auto write_backend = ResolveWriteBackendStatus(context);
    if (_wcsicmp(write_backend.c_str(), L"Native") != 0)
    {
        return std::nullopt;
    }

#ifdef APFSACCESS_HAS_RW_ENGINE
    std::lock_guard<std::mutex> metadata_lock(context.metadata_mutex);
    if (context.metadata_store)
    {
        return context.metadata_store->LastReplayCheckpointPendingWindow();
    }
#endif

    return std::nullopt;
}

std::string ResolveCommitStageStatus(const MountContext& context)
{
#ifdef APFSACCESS_HAS_RW_ENGINE
    std::lock_guard<std::mutex> metadata_lock(context.metadata_mutex);
    if (context.metadata_store)
    {
        return context.metadata_store->LastCommitStage();
    }
#else
    (void)context;
#endif
    return {};
}

std::string ResolveReplayStageStatus(const MountContext& context)
{
#ifdef APFSACCESS_HAS_RW_ENGINE
    std::lock_guard<std::mutex> metadata_lock(context.metadata_mutex);
    if (context.metadata_store)
    {
        return context.metadata_store->LastReplayStage();
    }
#else
    (void)context;
#endif
    return {};
}

std::string ResolveCommitBlobMagicStatus(const MountContext& context)
{
#ifdef APFSACCESS_HAS_RW_ENGINE
    std::lock_guard<std::mutex> metadata_lock(context.metadata_mutex);
    if (context.metadata_store)
    {
        return context.metadata_store->LastCommitBlobMagic();
    }
#else
    (void)context;
#endif
    return {};
}

std::wstring ResolveIntegrityFailureReasonStatus(const MountContext& context)
{
#ifdef APFSACCESS_HAS_RW_ENGINE
    std::lock_guard<std::mutex> metadata_lock(context.metadata_mutex);
    if (context.metadata_store)
    {
        return context.metadata_store->LastIntegrityFailureReason();
    }
#else
    (void)context;
#endif
    return {};
}

std::optional<std::uint64_t> ResolveIntegrityFailureObjectIdStatus(const MountContext& context)
{
#ifdef APFSACCESS_HAS_RW_ENGINE
    std::lock_guard<std::mutex> metadata_lock(context.metadata_mutex);
    if (context.metadata_store)
    {
        return context.metadata_store->LastIntegrityFailureObjectId();
    }
#else
    (void)context;
#endif
    return std::nullopt;
}

std::wstring ResolveNativeWriteSafetyStateStatus(const MountContext& context)
{
    if (!context.args.readwrite)
    {
        return L"ReadOnlyFallback";
    }

    const auto write_backend = ResolveWriteBackendStatus(context);
    if (!_wcsicmp(write_backend.c_str(), L"Disabled"))
    {
        return L"ReadOnlyFallback";
    }

    if (context.write_degraded || context.recovery_active)
    {
        return L"RecoveryBlocked";
    }

    if (!IsMutationWriteEnabled(&context))
    {
        return L"ReadOnlyFallback";
    }

    const auto readiness = ResolveNativeWriteReadinessStatus(context);
    if (!_wcsicmp(readiness.c_str(), L"RecoveryMode") || !_wcsicmp(readiness.c_str(), L"Degraded"))
    {
        return L"RecoveryBlocked";
    }

    if (!_wcsicmp(context.args.write_safety_level.c_str(), L"Stable"))
    {
        return L"StableReadWrite";
    }

    return L"PilotReadWrite";
}

std::wstring ResolveLastRecoveryActionStatus(const MountContext& context)
{
    if (!context.runtime_last_recovery_action.empty())
    {
        return context.runtime_last_recovery_action;
    }

    if (context.runtime_recovery_reason.empty())
    {
        return L"";
    }

    if (!_wcsicmp(context.runtime_recovery_reason.c_str(), L"CommitTimedOut"))
    {
        return L"DowngradedAfterCommitTimeout";
    }

    if (!_wcsicmp(context.runtime_recovery_reason.c_str(), L"RecoveryMarkerDirty"))
    {
        return L"RecoveryMarkerDetected";
    }

    if (!_wcsicmp(context.runtime_recovery_reason.c_str(), L"RecoveryRequired"))
    {
        return L"RecoveryRequiredBlock";
    }

    return L"RecoveryBlocked";
}

int ResolveDirtyTransactionCountStatus(const MountContext& context)
{
#ifdef APFSACCESS_HAS_RW_ENGINE
    int tx_pending = 0;
    int metadata_pending = 0;
    {
        std::lock_guard<std::mutex> tx_lock(context.tx_mutex);
        if (context.tx_manager)
        {
            tx_pending = static_cast<int>(context.tx_manager->PendingMutationCount());
        }
    }
    {
        std::lock_guard<std::mutex> metadata_lock(context.metadata_mutex);
        if (context.metadata_store)
        {
            metadata_pending = static_cast<int>(context.metadata_store->PendingMutationCount());
        }
    }

    return std::max(tx_pending, metadata_pending);
#else
    return 0;
#endif
}

struct NativeMetadataCounts
{
    std::size_t committed_objects = 0;
    std::size_t committed_inodes = 0;
    std::size_t committed_btree_records = 0;
    std::size_t committed_allocations = 0;
    std::size_t committed_free_extents = 0;
};

NativeMetadataCounts ResolveNativeMetadataCounts(const MountContext& context)
{
    NativeMetadataCounts counts{};
#ifdef APFSACCESS_HAS_RW_ENGINE
    std::lock_guard<std::mutex> metadata_lock(context.metadata_mutex);
    if (context.metadata_store)
    {
        counts.committed_objects = context.metadata_store->CommittedObjectCount();
        counts.committed_inodes = context.metadata_store->CommittedInodeCount();
        counts.committed_btree_records = context.metadata_store->CommittedBtreeRecordCount();
        counts.committed_allocations = context.metadata_store->CommittedAllocationCount();
        counts.committed_free_extents = context.metadata_store->CommittedFreeExtentCount();
    }
#else
    (void)context;
#endif
    return counts;
}

bool WriteHostStatusFile(
    MountContext& context,
    bool recovery_active,
    std::optional<std::uint64_t> last_commit_xid
)
{
    if (context.args.status_file.empty())
    {
        return true;
    }
    try
    {
        std::ostringstream buffer;
        const auto write_backend = EscapeJson(WideToUtf8(ResolveWriteBackendStatus(context)));
        const auto commit_model = EscapeJson(WideToUtf8(ResolveNativeWriteCommitModelStatus(context)));
        const auto readiness = EscapeJson(WideToUtf8(ResolveNativeWriteReadinessStatus(context)));
        const auto validation_state = EscapeJson(WideToUtf8(ResolveNativeWriteValidationStateStatus(context)));
        const auto fixture_legacy_fallback_active = ResolveFixtureLegacyFallbackStatus(context);
        const auto fixture_compatibility_path_active = ResolveFixtureCompatibilityPathStatus(context);
        const auto uses_scaffold_commit_blob = ResolveUsesScaffoldCommitBlobStatus(context);
        const auto canonical_path_active = ResolveCanonicalPathActiveStatus(context);
        const auto canonical_gate_failure = ResolveCanonicalGateFailureStatus(context);
        const auto replay_checkpoint_candidate_present = ResolveReplayCheckpointCandidatePresentStatus(context);
        const auto replay_checkpoint_pending_window = ResolveReplayCheckpointPendingWindowStatus(context);
        const auto commit_stage = ResolveCommitStageStatus(context);
        const auto replay_stage = ResolveReplayStageStatus(context);
        const auto commit_blob_magic = ResolveCommitBlobMagicStatus(context);
        const auto integrity_failure_reason = ResolveIntegrityFailureReasonStatus(context);
        const auto integrity_failure_object_id = ResolveIntegrityFailureObjectIdStatus(context);
        const auto safety_state = EscapeJson(WideToUtf8(ResolveNativeWriteSafetyStateStatus(context)));
        const auto recovery_reason = ResolveRecoveryReasonStatus(context, recovery_active);
        const auto recovery_action = ResolveLastRecoveryActionStatus(context);
        const auto dirty_tx = ResolveDirtyTransactionCountStatus(context);
        const auto metadata_counts = ResolveNativeMetadataCounts(context);
        const auto mount_ready = context.mount_ready.load(std::memory_order_acquire);
        const auto shutdown_drain_active = context.shutdown_drain_active.load(std::memory_order_acquire);
        const auto in_flight_mutations = context.active_external_mutation_callbacks.load(std::memory_order_acquire);
        const auto host_pid = static_cast<unsigned long>(GetCurrentProcessId());
        buffer << "{\"writeBackend\":\"" << write_backend
               << "\",\"commitModel\":\"" << commit_model
               << "\",\"nativeWriteReadiness\":\"" << readiness
               << "\",\"nativeWriteValidationState\":\"" << validation_state
               << "\",\"fixtureLegacyFallbackActive\":" << (fixture_legacy_fallback_active ? "true" : "false")
               << ",\"fixtureCompatibilityPathActive\":" << (fixture_compatibility_path_active ? "true" : "false")
               << ",\"usesScaffoldCommitBlob\":" << (uses_scaffold_commit_blob ? "true" : "false")
               << ",\"canonicalPathActive\":";

        if (canonical_path_active.has_value())
        {
            buffer << (canonical_path_active.value() ? "true" : "false");
        }
        else
        {
            buffer << "null";
        }

        buffer << ",\"canonicalGateFailure\":";
        if (!canonical_gate_failure.empty())
        {
            buffer << "\"" << EscapeJson(WideToUtf8(canonical_gate_failure)) << "\"";
        }
        else
        {
            buffer << "null";
        }

        buffer << ",\"replayCheckpointCandidatePresent\":";
        if (replay_checkpoint_candidate_present.has_value())
        {
            buffer << (replay_checkpoint_candidate_present.value() ? "true" : "false");
        }
        else
        {
            buffer << "null";
        }

        buffer << ",\"replayCheckpointPendingWindow\":";
        if (replay_checkpoint_pending_window.has_value())
        {
            buffer << (replay_checkpoint_pending_window.value() ? "true" : "false");
        }
        else
        {
            buffer << "null";
        }

        buffer << ",\"commitStage\":";
        if (!commit_stage.empty())
        {
            buffer << "\"" << EscapeJson(commit_stage) << "\"";
        }
        else
        {
            buffer << "null";
        }

        buffer << ",\"replayStage\":";
        if (!replay_stage.empty())
        {
            buffer << "\"" << EscapeJson(replay_stage) << "\"";
        }
        else
        {
            buffer << "null";
        }

        buffer << ",\"commitBlobMagic\":";
        if (!commit_blob_magic.empty())
        {
            buffer << "\"" << EscapeJson(commit_blob_magic) << "\"";
        }
        else
        {
            buffer << "null";
        }

        buffer << ",\"integrityFailureReason\":";
        if (!integrity_failure_reason.empty())
        {
            buffer << "\"" << EscapeJson(WideToUtf8(integrity_failure_reason)) << "\"";
        }
        else
        {
            buffer << "null";
        }

        buffer << ",\"integrityFailureObjectId\":";
        if (integrity_failure_object_id.has_value())
        {
            buffer << *integrity_failure_object_id;
        }
        else
        {
            buffer << "null";
        }

        buffer
            << ",\"nativeWriteSafetyState\":\"" << safety_state
            << "\",\"recoveryActive\":" << (recovery_active ? "true" : "false")
            << ",\"recoveryReason\":";

        if (!recovery_reason.empty())
        {
            buffer << "\"" << EscapeJson(WideToUtf8(recovery_reason)) << "\"";
        }
        else
        {
            buffer << "null";
        }

        buffer << ",\"lastRecoveryAction\":";
        if (!recovery_action.empty())
        {
            buffer << "\"" << EscapeJson(WideToUtf8(recovery_action)) << "\"";
        }
        else
        {
            buffer << "null";
        }

        buffer << ",\"lastCommitXid\":";

        if (last_commit_xid.has_value())
        {
            buffer << *last_commit_xid;
        }
        else
        {
            buffer << "null";
        }

        buffer << ",\"committedObjectCount\":" << metadata_counts.committed_objects;
        buffer << ",\"committedInodeCount\":" << metadata_counts.committed_inodes;
        buffer << ",\"committedBtreeRecordCount\":" << metadata_counts.committed_btree_records;
        buffer << ",\"committedAllocationCount\":" << metadata_counts.committed_allocations;
        buffer << ",\"committedFreeExtentCount\":" << metadata_counts.committed_free_extents;
        buffer << ",\"dirtyTransactionCount\":" << std::max(0, dirty_tx);
        buffer << ",\"mountReady\":" << (mount_ready ? "true" : "false");
        buffer << ",\"shutdownDrainActive\":" << (shutdown_drain_active ? "true" : "false");
        buffer << ",\"inFlightMutationCallbacks\":" << in_flight_mutations;
        buffer << ",\"hostPid\":" << host_pid;
        const auto crash_fault_passes = std::max(0, context.args.validation_crash_fault_passes);
        const auto crash_stage_matrix_passes = std::max(0, context.args.validation_crash_stage_matrix_passes);
        const auto hardware_pilot_passes = std::max(0, context.args.validation_hardware_pilot_passes);
        const auto hot_unplug_passes = std::max(0, context.args.validation_hot_unplug_passes);
        const auto macos_validation_passes = std::max(0, context.args.validation_macos_validation_passes);
        const auto macos_consistency_passes = std::max(0, context.args.validation_macos_consistency_passes);
        const auto power_loss_replay_passes = std::max(0, context.args.validation_power_loss_replay_passes);
        const auto power_loss_pass_verified = context.args.validation_power_loss_pass_verified;
        const auto has_last_validated_utc = !context.args.validation_last_validated_utc.empty();
        const auto has_last_profile_id = !context.args.validation_last_profile_id.empty();
        const auto has_validation_evidence = crash_fault_passes > 0 ||
            crash_stage_matrix_passes > 0 ||
            hardware_pilot_passes > 0 ||
            hot_unplug_passes > 0 ||
            macos_validation_passes > 0 ||
            macos_consistency_passes > 0 ||
            power_loss_replay_passes > 0 ||
            power_loss_pass_verified ||
            has_last_validated_utc ||
            has_last_profile_id;

        if (has_validation_evidence)
        {
            buffer << ",\"validationCrashFaultPasses\":" << crash_fault_passes;
            buffer << ",\"validationCrashStageMatrixPasses\":" << crash_stage_matrix_passes;
            buffer << ",\"validationHardwarePilotPasses\":" << hardware_pilot_passes;
            buffer << ",\"validationHotUnplugPasses\":" << hot_unplug_passes;
            buffer << ",\"validationMacOsValidationPasses\":" << macos_validation_passes;
            buffer << ",\"validationMacOsConsistencyPasses\":" << macos_consistency_passes;
            buffer << ",\"validationPowerLossReplayPasses\":" << power_loss_replay_passes;
            buffer << ",\"validationPowerLossPassVerified\":" << (power_loss_pass_verified ? "true" : "false");
            buffer << ",\"validationLastValidatedUtc\":";
            if (has_last_validated_utc)
            {
                buffer << "\"" << EscapeJson(WideToUtf8(context.args.validation_last_validated_utc)) << "\"";
            }
            else
            {
                buffer << "null";
            }
            buffer << ",\"validationLastValidationProfileId\":";
            if (has_last_profile_id)
            {
                buffer << "\"" << EscapeJson(WideToUtf8(context.args.validation_last_profile_id)) << "\"";
            }
            else
            {
                buffer << "null";
            }
        }
        buffer << "}";
        const auto contents = buffer.str();
        if (context.last_status_write_contents == contents)
        {
            return true;
        }

        auto status_path = std::filesystem::path(context.args.status_file);
        if (status_path.has_parent_path())
        {
            std::filesystem::create_directories(status_path.parent_path());
        }

        std::ofstream out(status_path, std::ios::binary | std::ios::trunc);
        if (!out.good())
        {
            return false;
        }

        out.write(contents.data(), static_cast<std::streamsize>(contents.size()));
        if (!out.good())
        {
            return false;
        }

        context.last_status_write_contents = contents;
        return true;
    }
    catch (...)
    {
        return false;
    }
}

FILETIME UtcNow()
{
    FILETIME now{};
    GetSystemTimeAsFileTime(&now);
    return now;
}

std::uint64_t ToFileTimeValue(const FILETIME& value)
{
    ULARGE_INTEGER stamp{ value.dwLowDateTime, value.dwHighDateTime };
    return stamp.QuadPart;
}

FILETIME ToFileTime(std::uint64_t value)
{
    ULARGE_INTEGER stamp{};
    stamp.QuadPart = value;
    FILETIME file_time{};
    file_time.dwLowDateTime = stamp.LowPart;
    file_time.dwHighDateTime = stamp.HighPart;
    return file_time;
}

std::wstring Parent(const std::wstring& path)
{
    auto p = NormalizePath(path);
    if (p == L"\\")
    {
        return p;
    }
    auto pos = p.find_last_of(L'\\');
    if (pos <= 0 || pos == std::wstring::npos)
    {
        return L"\\";
    }
    return p.substr(0, pos);
}

std::wstring Join(const std::wstring& parent, const std::wstring& name)
{
    auto p = NormalizePath(parent);
    return p == L"\\" ? L"\\" + name : p + L"\\" + name;
}

std::wstring NormalizeRenameTargetPath(const std::wstring& source_path, const std::wstring& raw_target)
{
    std::wstring target = raw_target;
    std::replace(target.begin(), target.end(), L'/', L'\\');
    while (target.size() > 1 && target.back() == L'\\')
    {
        target.pop_back();
    }
    if (target.empty())
    {
        return L"\\";
    }
    if (target.front() == L'\\')
    {
        return NormalizePath(target);
    }

    return NormalizePath(Join(Parent(source_path), target));
}

std::wstring LeafName(const std::wstring& path)
{
    auto normalized = NormalizePath(path);
    if (normalized == L"\\")
    {
        return L"";
    }

    auto pos = normalized.find_last_of(L'\\');
    if (pos == std::wstring::npos || pos + 1 >= normalized.size())
    {
        return normalized;
    }
    return normalized.substr(pos + 1);
}

std::wstring ApfsRoot(const Arguments& a)
{
    std::wstring p = a.device;
    if (!p.empty() && p.back() != L'/' && p.back() != L'\\')
    {
        p.push_back(L'/');
    }
    p += L"ApfsAccess_Volumes/";
    p += a.volume;
    return p;
}

std::wstring ApfsChild(const std::wstring& parent, const std::wstring& name)
{
    std::wstring p = parent;
    if (!p.empty() && p.back() != L'/' && p.back() != L'\\')
    {
        p.push_back(L'/');
    }
    p += name;
    return p;
}

std::string TrimAscii(std::string v)
{
    while (!v.empty() && (v.back() == '\r' || v.back() == '\n' || std::isspace((unsigned char)v.back())))
    {
        v.pop_back();
    }
    size_t i = 0;
    while (i < v.size() && std::isspace((unsigned char)v[i]))
    {
        ++i;
    }
    return v.substr(i);
}

bool ParseEnumLine(const std::string& line, DirEntry& e)
{
    auto t = TrimAscii(line);
    if (t.empty())
    {
        return false;
    }
    char k = t[0];
    if (!(k == 'd' || k == '-' || k == 'l' || k == 's' || k == 'b' || k == 'c'))
    {
        return false;
    }
    std::istringstream ss(t);
    std::string a, m, h, u, g, size;
    if (!(ss >> a >> m >> h >> u >> g >> size))
    {
        return false;
    }
    std::string n;
    std::getline(ss, n);
    n = TrimAscii(n);
    if (n.empty() || n == "." || n == "..")
    {
        return false;
    }
    auto arrow = n.find(" -> ");
    if (arrow != std::string::npos)
    {
        n = n.substr(0, arrow);
    }
    e.name = Utf8ToWide(n);
    e.is_directory = (k == 'd');
    try { e.file_size = (std::uint64_t)std::stoull(size); } catch (...) { e.file_size = 0; }
    return !e.name.empty();
}

void FillInfo(const Node& n, bool read_only, FSP_FSCTL_FILE_INFO* i)
{
    std::memset(i, 0, sizeof(*i));
    i->FileAttributes = BuildFileAttributes(n, read_only);
    i->FileSize = n.is_directory ? 0 : n.file_size;
    i->AllocationSize = n.is_directory ? 0 : ((n.file_size + 4095ull) / 4096ull) * 4096ull;
    const auto timestamp = ToFileTimeValue(n.timestamp);
    i->CreationTime = timestamp;
    i->LastAccessTime = timestamp;
    i->LastWriteTime = timestamp;
    i->ChangeTime = timestamp;
}

std::optional<UINT16> DirectoryInfoSizeForName(const std::wstring& name)
{
    const size_t name_bytes = name.size() * sizeof(WCHAR);
    const size_t entry_size = FIELD_OFFSET(FSP_FSCTL_DIR_INFO, FileNameBuf) + name_bytes;
    if (entry_size > static_cast<size_t>(std::numeric_limits<UINT16>::max()))
    {
        return std::nullopt;
    }

    return static_cast<UINT16>(entry_size);
}

void FillDirectoryInfo(FSP_FSCTL_DIR_INFO* dir_info, const Node& node, const std::wstring& name, bool read_only)
{
    if (!dir_info)
    {
        return;
    }

    const auto size = DirectoryInfoSizeForName(name);
    if (!size)
    {
        return;
    }

    dir_info->Size = *size;
    FillInfo(node, read_only, &dir_info->FileInfo);
    const size_t name_bytes = name.size() * sizeof(WCHAR);
    if (name_bytes > 0)
    {
        std::memcpy(dir_info->FileNameBuf, name.data(), name_bytes);
    }
    dir_info->FileNameBuf[name.size()] = L'\0';
}

std::vector<unsigned char> BuildDirectoryInfoBuffer(const Node& node, const std::wstring& name, bool read_only)
{
    const auto size = DirectoryInfoSizeForName(name);
    if (!size)
    {
        return {};
    }

    std::vector<unsigned char> buffer(static_cast<size_t>(*size) + sizeof(WCHAR), 0);
    FillDirectoryInfo(reinterpret_cast<FSP_FSCTL_DIR_INFO*>(buffer.data()), node, name, read_only);
    return buffer;
}

std::shared_ptr<Node> TryGetNodeLocked(MountContext* c, const std::wstring& path)
{
    auto it = c->nodes.find(Key(path));
    return it == c->nodes.end() ? std::shared_ptr<Node>{} : it->second;
}

bool IsDeleteBlockedStateLocked(const std::shared_ptr<Node>& node)
{
    if (!node)
    {
        return false;
    }

    return node->delete_pending || node->delete_latched || node->delete_intent_count > 0;
}

bool HasDeletePendingAncestorLocked(MountContext* c, const std::wstring& path)
{
    if (!c)
    {
        return false;
    }

    auto cursor = Parent(path);
    while (true)
    {
        auto ancestor = TryGetNodeLocked(c, cursor);
        if (IsDeleteBlockedStateLocked(ancestor))
        {
            return true;
        }

        if (cursor == L"\\")
        {
            break;
        }

        auto next = Parent(cursor);
        if (next == cursor)
        {
            break;
        }
        cursor = std::move(next);
    }

    return false;
}

std::shared_ptr<Node> TryGetVisibleNodeLocked(MountContext* c, const std::wstring& path)
{
    auto node = TryGetNodeLocked(c, path);
    if (!node || IsDeleteBlockedStateLocked(node) || HasDeletePendingAncestorLocked(c, path))
    {
        return {};
    }
    return node;
}

bool HasChildName(const std::vector<std::wstring>& children, const std::wstring& name)
{
    return std::any_of(children.begin(), children.end(), [&](const std::wstring& existing)
    {
        return EqualsIgnoreCase(existing, name);
    });
}

void AddChildName(std::vector<std::wstring>& children, const std::wstring& name)
{
    auto it = std::lower_bound(children.begin(), children.end(), name, [](const std::wstring& a, const std::wstring& b)
    {
        return _wcsicmp(a.c_str(), b.c_str()) < 0;
    });
    if (it == children.end() || !EqualsIgnoreCase(*it, name))
    {
        children.insert(it, name);
    }
}

void RemoveChildName(std::vector<std::wstring>& children, const std::wstring& name)
{
    auto it = std::lower_bound(children.begin(), children.end(), name, [](const std::wstring& a, const std::wstring& b)
    {
        return _wcsicmp(a.c_str(), b.c_str()) < 0;
    });
    if (it != children.end() && EqualsIgnoreCase(*it, name))
    {
        children.erase(it);
    }
}

void UpdateDeletePendingVisibilityLocked(MountContext* c, const std::shared_ptr<Node>& node)
{
    if (!c || !node || node->path == L"\\")
    {
        return;
    }

    auto parent = TryGetNodeLocked(c, Parent(node->path));
    if (!parent || !parent->is_directory)
    {
        return;
    }

    const auto leaf = LeafName(node->path);
    if (leaf.empty())
    {
        return;
    }

    if (node->delete_pending)
    {
        RemoveChildName(parent->children, leaf);
    }
    else
    {
        AddChildName(parent->children, leaf);
    }
}

void RefreshDeletePendingStateLocked(MountContext* c, const std::shared_ptr<Node>& node)
{
    if (!node)
    {
        return;
    }

    const auto pending = node->delete_latched || node->delete_intent_count > 0;
    if (node->delete_pending == pending)
    {
        return;
    }

    node->delete_pending = pending;
    UpdateDeletePendingVisibilityLocked(c, node);
}

void SetDeleteIntentLocked(MountContext* c, OpenContext* open_ctx, bool enable_delete)
{
    if (!c || !open_ctx || !open_ctx->node)
    {
        return;
    }

    auto& node = open_ctx->node;
    if (enable_delete)
    {
        if (!open_ctx->delete_on_cleanup)
        {
            open_ctx->delete_on_cleanup = true;
            ++node->delete_intent_count;
        }
    }
    else
    {
        if (open_ctx->delete_on_cleanup)
        {
            open_ctx->delete_on_cleanup = false;
            if (node->delete_intent_count > 0)
            {
                --node->delete_intent_count;
            }
        }
    }

    RefreshDeletePendingStateLocked(c, node);
}

void LatchDeleteOnCleanupLocked(MountContext* c, OpenContext* open_ctx)
{
    if (!c || !open_ctx || !open_ctx->node)
    {
        return;
    }

    auto& node = open_ctx->node;
    if (!open_ctx->delete_on_cleanup)
    {
        open_ctx->delete_on_cleanup = true;
        ++node->delete_intent_count;
    }
    node->delete_latched = true;
    RefreshDeletePendingStateLocked(c, node);
}

void ReleaseOpenContextAccountingLocked(MountContext* c, OpenContext* open_ctx)
{
    if (!c || !open_ctx || !open_ctx->node || open_ctx->cleanup_seen)
    {
        return;
    }

    if (open_ctx->node->open_handle_count > 0)
    {
        --open_ctx->node->open_handle_count;
    }
    if (open_ctx->write_open && open_ctx->node->write_handle_count > 0)
    {
        --open_ctx->node->write_handle_count;
    }

    open_ctx->cleanup_seen = true;
    RefreshDeletePendingStateLocked(c, open_ctx->node);
}

NTSTATUS ValidateDeleteEligibilityLocked(
    MountContext* c,
    const std::shared_ptr<Node>& node,
    const OpenContext* current_open)
{
    if (!c || !node)
    {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    if (node->path == L"\\")
    {
        return STATUS_ACCESS_DENIED;
    }
    if (IsDeleteBlockedStateLocked(node) &&
        !(current_open && current_open->node == node && current_open->delete_on_cleanup))
    {
        return STATUS_DELETE_PENDING;
    }
    if (node->is_directory && !node->children.empty())
    {
        return STATUS_DIRECTORY_NOT_EMPTY;
    }

    return STATUS_SUCCESS;
}

bool IsDirectChildPath(const std::wstring& parent_path, const std::wstring& candidate_path)
{
    if (candidate_path == L"\\")
    {
        return false;
    }

    if (parent_path == L"\\")
    {
        if (candidate_path.empty() || candidate_path.front() != L'\\')
        {
            return false;
        }
        return candidate_path.find(L'\\', 1) == std::wstring::npos;
    }

    if (!IsDescendantPath(candidate_path, parent_path))
    {
        return false;
    }

    const auto parent_len = parent_path.size();
    if (candidate_path.size() <= parent_len + 1)
    {
        return false;
    }

    const auto relative = candidate_path.substr(parent_len + 1);
    return relative.find(L'\\') == std::wstring::npos;
}

bool HasDeletePermissionForTarget(const OpenContext* open_ctx, const std::wstring& target_path)
{
    if (!open_ctx || !open_ctx->node)
    {
        return false;
    }

    if (Key(open_ctx->node->path) == Key(target_path))
    {
        return open_ctx->allow_delete;
    }

    return open_ctx->node->is_directory &&
        open_ctx->allow_delete_child &&
        IsDirectChildPath(open_ctx->node->path, target_path);
}

bool HasDirectoryInsertPermission(const OpenContext* open_ctx, bool inserting_directory)
{
    if (!open_ctx || !open_ctx->node || !open_ctx->node->is_directory)
    {
        return false;
    }

    if (inserting_directory)
    {
        return open_ctx->allow_append_data;
    }

    return open_ctx->allow_write_data;
}

bool EnsureDirectoryLoaded(MountContext* c, const std::shared_ptr<Node>& dir)
{
    if (!dir || !dir->is_directory)
    {
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(c->mutex);
        if (dir->loaded)
        {
            return true;
        }
    }

#ifdef APFSACCESS_HAS_RW_ENGINE
    if (c->metadata_store)
    {
        (void)MergeCommittedInodeStateIntoNodeIndex(c);
        std::lock_guard<std::mutex> lock(c->mutex);
        return dir->loaded;
    }
#endif

    return false;
}

std::shared_ptr<Node> FindNode(MountContext* c, const std::wstring& path)
{
    auto p = NormalizePath(path);
    {
        std::lock_guard<std::mutex> lock(c->mutex);
        if (auto n = TryGetVisibleNodeLocked(c, p))
        {
            return n;
        }
        if (TryGetNodeLocked(c, p))
        {
            return {};
        }
    }
    if (p == L"\\")
    {
        return {};
    }
    auto parent = FindNode(c, Parent(p));
    if (!parent || !EnsureDirectoryLoaded(c, parent))
    {
        return {};
    }
    std::lock_guard<std::mutex> lock(c->mutex);
    return TryGetVisibleNodeLocked(c, p);
}

std::filesystem::path HydrationPath(MountContext* c, const Node& n)
{
    auto key = Key(n.path) + L"|" + c->args.device + L"|" + c->args.volume;
    auto hash = (unsigned long long)std::hash<std::wstring>{}(key);
    auto root = c && !c->cache_root.empty()
        ? c->cache_root
        : (std::filesystem::temp_directory_path() / "ApfsAccess" / "hydrate");
    std::error_code ec;
    std::filesystem::create_directories(root, ec);
    return root / (std::to_wstring(hash) + L".bin");
}

bool EnsureHydrated(MountContext* c, const std::shared_ptr<Node>& n, bool allow_empty_placeholder = false)
{
    if (!n || n->is_directory)
    {
        return false;
    }

    auto file = HydrationPath(c, *n);
    if (std::filesystem::exists(file))
    {
        return true;
    }

    const auto hydrate_from_bytes = [&](const std::vector<std::byte>& payload) -> bool
    {
        std::filesystem::create_directories(file.parent_path());
        std::ofstream out(file, std::ios::binary | std::ios::trunc);
        if (!out.good())
        {
            return false;
        }

        if (!payload.empty())
        {
            out.write(reinterpret_cast<const char*>(payload.data()), static_cast<std::streamsize>(payload.size()));
        }
        return out.good();
    };

#ifdef APFSACCESS_HAS_RW_ENGINE
    const auto try_hydrate_from_metadata = [&]() -> bool
    {
        if (!c->metadata_store)
        {
            return false;
        }

        std::vector<std::byte> payload;
        std::uint64_t logical_size = 0;
        {
            std::lock_guard<std::mutex> metadata_lock(c->metadata_mutex);
            auto inode = c->metadata_store->LookupCommittedInodeByPath(n->path);
            if (!inode.has_value() || inode->is_directory)
            {
                return false;
            }

            logical_size = inode->logical_size;
            if (logical_size == 0)
            {
                payload.clear();
            }
            else if (logical_size <= static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
            {
                if (!c->metadata_store->ReadCommittedFileRange(
                    n->path,
                    0,
                    static_cast<std::size_t>(logical_size),
                    payload))
                {
                    return false;
                }
            }
            else
            {
                return false;
            }
        }

        return hydrate_from_bytes(payload);
    };
#endif

#ifdef APFSACCESS_HAS_RW_ENGINE
    if (try_hydrate_from_metadata())
    {
        return true;
    }
#endif

    if (!allow_empty_placeholder)
    {
        return false;
    }

    std::filesystem::create_directories(file.parent_path());
    std::ofstream out(file, std::ios::binary | std::ios::trunc);
    return out.good();
}

#ifdef APFSACCESS_HAS_RW_ENGINE
std::optional<std::vector<std::byte>> LoadHydratedPayloadForPath(
    MountContext* c,
    const std::wstring& path,
    std::uint64_t logical_size,
    bool hydrate_if_missing = true)
{
    if (!c || logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
    {
        return std::nullopt;
    }

    auto node = FindNode(c, path);
    if (!node || node->is_directory)
    {
        return std::nullopt;
    }

    auto hydrated_file = HydrationPath(c, *node);
    if (hydrate_if_missing)
    {
        if (!EnsureHydrated(c, node, false))
        {
            return std::nullopt;
        }
    }
    else
    {
        std::error_code exists_ec;
        if (!std::filesystem::exists(hydrated_file, exists_ec) || exists_ec)
        {
            return std::nullopt;
        }
    }

    std::ifstream input(hydrated_file, std::ios::binary | std::ios::ate);
    if (!input.good())
    {
        return std::nullopt;
    }

    const auto file_end = input.tellg();
    if (file_end < 0)
    {
        return std::nullopt;
    }

    const auto file_bytes = static_cast<std::uint64_t>(file_end);
    const auto read_bytes = static_cast<std::size_t>(std::min<std::uint64_t>(file_bytes, logical_size));
    std::vector<std::byte> payload(read_bytes, std::byte{0});

    if (read_bytes > 0)
    {
        input.seekg(0, std::ios::beg);
        input.read(reinterpret_cast<char*>(payload.data()), static_cast<std::streamsize>(read_bytes));
        if (static_cast<std::size_t>(input.gcount()) != read_bytes)
        {
            return std::nullopt;
        }
    }

    if (logical_size > payload.size())
    {
        payload.resize(static_cast<std::size_t>(logical_size), std::byte{0});
    }

    return payload;
}

bool MergeCommittedInodeStateIntoNodeIndex(MountContext* c)
{
    if (!c || !c->metadata_store)
    {
        return false;
    }

    std::vector<apfsaccess::rw::MetadataStore::InodeRecord> committed_inodes;
    {
        std::lock_guard<std::mutex> metadata_lock(c->metadata_mutex);
        committed_inodes = c->metadata_store->SnapshotCommittedInodes();
    }

    if (committed_inodes.empty())
    {
        return false;
    }

    const auto now = UtcNow();
    std::lock_guard<std::mutex> lock(c->mutex);

    std::function<std::shared_ptr<Node>(const std::wstring&)> ensure_directory_node;
    ensure_directory_node = [&](const std::wstring& path) -> std::shared_ptr<Node>
    {
        if (path.empty())
        {
            return {};
        }

        auto normalized = NormalizePath(path);
        auto existing = TryGetNodeLocked(c, normalized);
        if (existing)
        {
            if (!existing->is_directory)
            {
                existing->is_directory = true;
                existing->file_size = 0;
                existing->delete_pending = false;
            }
            if (normalized == L"\\" && existing->apfs_path.empty())
            {
                existing->apfs_path = ApfsRoot(c->args);
            }
            return existing;
        }

        auto created = std::make_shared<Node>();
        created->path = normalized;
        created->is_directory = true;
        created->file_size = 0;
        created->timestamp = now;
        created->loaded = true;
        created->delete_pending = false;

        if (normalized == L"\\")
        {
            created->apfs_path = ApfsRoot(c->args);
        }
        else
        {
            auto parent = ensure_directory_node(Parent(normalized));
            if (parent && !parent->apfs_path.empty())
            {
                created->apfs_path = ApfsChild(parent->apfs_path, LeafName(normalized));
            }
        }

        c->nodes.emplace(Key(normalized), created);
        return created;
    };

    std::size_t applied_entries = 0;
    for (const auto& inode : committed_inodes)
    {
        auto normalized_path = NormalizePath(inode.full_path);
        if (normalized_path.empty())
        {
            continue;
        }

        auto parent_path = Parent(normalized_path);
        if (normalized_path != L"\\")
        {
            (void)ensure_directory_node(parent_path);
        }

        auto node = TryGetNodeLocked(c, normalized_path);
        if (!node)
        {
            node = std::make_shared<Node>();
            c->nodes.emplace(Key(normalized_path), node);
        }

        node->path = normalized_path;
        node->is_directory = inode.is_directory;
        node->file_size = inode.is_directory ? 0 : inode.logical_size;
        node->timestamp = inode.timestamp_utc != 0 ? ToFileTime(inode.timestamp_utc) : now;
        node->delete_pending = false;

        if (normalized_path == L"\\")
        {
            node->apfs_path = ApfsRoot(c->args);
            node->loaded = true;
        }
        else if (auto parent = TryGetNodeLocked(c, parent_path); parent && !parent->apfs_path.empty())
        {
            node->apfs_path = ApfsChild(parent->apfs_path, LeafName(normalized_path));
            if (node->is_directory)
            {
                node->loaded = true;
            }
        }
        else
        {
            node->apfs_path.clear();
            if (node->is_directory)
            {
                node->loaded = true;
            }
        }

        ++applied_entries;
    }

    for (auto& [_, node] : c->nodes)
    {
        if (!node->is_directory)
        {
            continue;
        }

        node->children.clear();
        if (node->apfs_path.empty())
        {
            node->loaded = true;
        }
    }

    for (const auto& [_, node] : c->nodes)
    {
        if (IsDeleteBlockedStateLocked(node) || node->path == L"\\")
        {
            continue;
        }

        auto parent = TryGetNodeLocked(c, Parent(node->path));
        if (!parent || !parent->is_directory)
        {
            continue;
        }

        AddChildName(parent->children, LeafName(node->path));
    }

    return applied_entries > 0;
}
#endif

bool IsOverlayWriteEnabled(const MountContext* c)
{
    return c && c->overlay_write_enabled;
}

bool IsNativeWriteEnabled(const MountContext* c)
{
    return c && c->native_write_enabled;
}

bool IsRawPhysicalDevicePath(const std::wstring& device_path)
{
    if (device_path.empty())
    {
        return false;
    }

    return !_wcsnicmp(device_path.c_str(), L"\\\\.\\PhysicalDrive", 17) ||
           !_wcsnicmp(device_path.c_str(), L"\\\\?\\PhysicalDrive", 17);
}

bool IsFixtureImagePathForCanonicalGate(const std::wstring& device_path)
{
    if (device_path.empty() || IsRawPhysicalDevicePath(device_path))
    {
        return false;
    }

    std::wstring normalized = device_path;
    std::transform(normalized.begin(), normalized.end(), normalized.begin(), towlower);
    std::replace(normalized.begin(), normalized.end(), L'/', L'\\');

    const auto has_suffix = [&](const wchar_t* suffix) -> bool
    {
        if (!suffix)
        {
            return false;
        }
        const std::wstring suffix_view(suffix);
        if (normalized.size() < suffix_view.size())
        {
            return false;
        }
        return normalized.compare(normalized.size() - suffix_view.size(), suffix_view.size(), suffix_view) == 0;
    };

    if (has_suffix(L".apfs.img") || has_suffix(L".img") || has_suffix(L".apfs.fixture"))
    {
        return true;
    }

    const auto last_dot = normalized.find_last_of(L'.');
    if (last_dot != std::wstring::npos)
    {
        const auto extension = normalized.substr(last_dot);
        if (extension == L".img" || extension == L".apfs" || extension == L".fixture")
        {
            return true;
        }
    }

    // Fixture detection is explicit-pattern only. Parent directory names like
    // "fixtures" or "synthetic" must not relax canonical non-fixture safety gates.
    return false;
}

bool RequiresCanonicalMutationGate(const Arguments& args)
{
    if (args.device.empty() || !IsFixtureImagePathForCanonicalGate(args.device))
    {
        // Non-fixture/unknown media must always require canonical mutation gating.
        return true;
    }

    // Treat strict non-fixture scaffold controls as canonical gate requirements.
    return args.write_require_canonical_commit ||
           args.write_disallow_scaffold_commit_on_non_fixture ||
           args.write_reject_scaffold_replay_blob_on_non_fixture ||
           args.write_require_canonical_replay_candidate_on_non_fixture;
}

void ApplyNonFixtureCanonicalSafetyOverrides(Arguments& args)
{
    if (args.device.empty() || !IsFixtureImagePathForCanonicalGate(args.device))
    {
        args.allow_legacy_scaffold_for_fixtures = false;
        args.write_require_canonical_commit = true;
        args.write_disallow_scaffold_commit_on_non_fixture = true;
        args.write_reject_scaffold_replay_blob_on_non_fixture = true;
        args.write_require_canonical_replay_candidate_on_non_fixture = true;
    }
}

bool IsNativeMutationWriteEnabled(const MountContext* c)
{
    if (!c || !c->native_write_enabled)
    {
        return false;
    }

#ifdef APFSACCESS_HAS_RW_ENGINE
    std::lock_guard<std::mutex> metadata_lock(c->metadata_mutex);
    if (!c->metadata_store)
    {
        return false;
    }

    if (!c->metadata_store->IsCommitPathReady())
    {
        return false;
    }

    if (RequiresCanonicalMutationGate(c->args))
    {
        return c->metadata_store->IsCanonicalCommitReady();
    }

    return true;
#else
    return false;
#endif
}

bool IsMutationWriteEnabled(const MountContext* c)
{
    return IsOverlayWriteEnabled(c) || IsNativeMutationWriteEnabled(c);
}

void BeginMutationShutdownDrain(MountContext* c)
{
    if (!c)
    {
        return;
    }

    c->shutdown_drain_active.store(true, std::memory_order_release);
    const auto initial_pending = c->active_external_mutation_callbacks.load(std::memory_order_acquire);
    if (initial_pending == 0)
    {
        return;
    }

    int drain_timeout_seconds = c->args.write_commit_timeout_seconds;
    if (drain_timeout_seconds < 1)
    {
        drain_timeout_seconds = 1;
    }
    else if (drain_timeout_seconds > 60)
    {
        drain_timeout_seconds = 60;
    }

    std::wcerr << L"[FsHost] Shutdown drain: waiting for "
        << initial_pending
        << L" in-flight external mutation callback(s)." << std::endl;

    const auto drain_started = static_cast<std::uint64_t>(GetTickCount64());
    while (c->active_external_mutation_callbacks.load(std::memory_order_acquire) > 0)
    {
        const auto now = static_cast<std::uint64_t>(GetTickCount64());
        if (now - drain_started >= static_cast<std::uint64_t>(drain_timeout_seconds) * 1000ull)
        {
            const auto pending = c->active_external_mutation_callbacks.load(std::memory_order_acquire);
            std::wcerr << L"[FsHost] Shutdown drain timeout after "
                << drain_timeout_seconds
                << L"s with "
                << pending
                << L" in-flight mutation callback(s); continuing shutdown." << std::endl;
            return;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }

    std::wcerr << L"[FsHost] Shutdown drain complete." << std::endl;
}

bool InitializeSessionPaths(MountContext* c)
{
    if (!c)
    {
        return false;
    }

    std::error_code ec;
    auto session_root = std::filesystem::temp_directory_path(ec);
    if (ec)
    {
        return false;
    }

    session_root /= "ApfsAccess";
    session_root /= "sessions";
    auto session_id = SanitizeFileComponent(c->args.volume);
    if (session_id.empty())
    {
        session_id = L"apfs";
    }
    session_id += L"_";
    session_id += SanitizeFileComponent(c->args.mount.empty() ? L"mount" : c->args.mount);
    session_id += L"_";
    session_id += std::to_wstring(GetCurrentProcessId());
    session_id += L"_";
    session_id += std::to_wstring(GetTickCount64());

    c->session_root = session_root / session_id;
    c->cache_root = c->session_root / "hydrate";

    std::filesystem::create_directories(c->cache_root, ec);
    if (ec)
    {
        c->session_root.clear();
        c->cache_root.clear();
        return false;
    }

    return true;
}

#ifdef APFSACCESS_HAS_RW_ENGINE
std::filesystem::path BuildRecoveryMarkerPath(const Arguments& args)
{
    auto recovery_root = std::filesystem::temp_directory_path() / "ApfsAccess" / "recovery";
    auto marker_name = SanitizeFileComponent(args.device) + L"_" +
                       SanitizeFileComponent(args.volume) + L"_" +
                       SanitizeFileComponent(args.write_backend) + L".state";
    return recovery_root / marker_name;
}

void ArmCommitDeadline(MountContext* c)
{
    if (!c)
    {
        return;
    }

    const auto timeout_seconds = static_cast<std::uint64_t>(std::max(1, c->args.write_commit_timeout_seconds));
    const auto timeout_ms = timeout_seconds * 1000ull;
    const auto now = static_cast<std::uint64_t>(GetTickCount64());
    std::uint64_t deadline = now;
    if (timeout_ms > (std::numeric_limits<std::uint64_t>::max() - now))
    {
        deadline = std::numeric_limits<std::uint64_t>::max();
    }
    else
    {
        deadline = now + timeout_ms;
    }

    c->commit_timeout_latched.store(false, std::memory_order_relaxed);
    c->commit_deadline_tick_ms.store(deadline, std::memory_order_relaxed);
}

void ClearCommitDeadline(MountContext* c)
{
    if (!c)
    {
        return;
    }

    c->commit_deadline_tick_ms.store(0, std::memory_order_relaxed);
}

bool UpdateRecoveryMarkerBestEffort(MountContext* c, bool dirty)
{
    if (!c || c->recovery_marker_file.empty())
    {
        return true;
    }

    c->pending_native_writes = dirty;
    RecoveryMarkerState marker{};
    marker.dirty = c->pending_native_writes;
    marker.last_commit_xid = c->runtime_last_commit_xid;
    return PersistRecoveryMarkerState(c, c->recovery_marker_file, marker);
}

void LatchDirtyTransactionLimitExceeded(MountContext* c, std::size_t dirty_limit)
{
    if (!c)
    {
        return;
    }

    c->recovery_active = true;
    c->runtime_recovery_reason = L"DirtyTransactionLimitExceeded";
    c->runtime_last_recovery_action = L"DowngradedAfterDirtyTransactionLimit";
    if (IsRecoveryPolicyFailClosed(c->args.write_recovery_policy))
    {
        c->write_degraded = true;
        c->native_write_enabled = false;
        c->overlay_write_enabled = false;
    }

    std::wcerr << L"[FsHost] RW native-mutation warning: pending mutation limit reached ("
        << dirty_limit
        << L") and write path was downgraded for safety."
        << std::endl;
    (void)UpdateRecoveryMarkerBestEffort(c, true);
    (void)WriteHostStatusFile(*c, c->recovery_active, c->runtime_last_commit_xid);
}

bool RecordNativeMutationBestEffort(
    MountContext* c,
    apfsaccess::rw::MetadataStore::MutationOperation operation,
    const std::wstring& path,
    const std::wstring& secondary_path = L"",
    std::uint64_t offset = 0,
    std::uint64_t length = 0,
    bool replace_if_exists = false,
    std::uint64_t timestamp_utc = 0)
{
    if (!IsNativeWriteEnabled(c) || !c || !c->metadata_store)
    {
        return true;
    }

    apfsaccess::rw::MetadataStore::MutationRequest request{};
    request.operation = operation;
    request.path = path;
    request.secondary_path = secondary_path;
    request.offset = offset;
    request.length = length;
    request.replace_if_exists = replace_if_exists;
    request.timestamp_utc = timestamp_utc;

    apfsaccess::rw::MetadataStore::MutationStatus status = apfsaccess::rw::MetadataStore::MutationStatus::NotReady;
    std::wstring failure_reason;
    {
        std::lock_guard<std::mutex> metadata_lock(c->metadata_mutex);
        const auto dirty_limit = static_cast<std::size_t>(std::max(1, c->args.write_max_dirty_transactions));
        if (c->metadata_store->PendingMutationCount() >= dirty_limit)
        {
            LatchDirtyTransactionLimitExceeded(c, dirty_limit);
            return false;
        }

        status = c->metadata_store->StageMutation(request);
        if (status != apfsaccess::rw::MetadataStore::MutationStatus::Applied)
        {
            failure_reason = c->metadata_store->LastMutationFailureReason();
        }
    }

    if (status != apfsaccess::rw::MetadataStore::MutationStatus::Applied)
    {
        const wchar_t* status_text = L"unknown";
        switch (status)
        {
        case apfsaccess::rw::MetadataStore::MutationStatus::NotReady:
            status_text = L"not-ready";
            break;
        case apfsaccess::rw::MetadataStore::MutationStatus::InvalidRequest:
            status_text = L"invalid-request";
            break;
        case apfsaccess::rw::MetadataStore::MutationStatus::AllocationFailed:
            status_text = L"allocation-failed";
            break;
        case apfsaccess::rw::MetadataStore::MutationStatus::UnsupportedOperation:
            status_text = L"unsupported-operation";
            break;
        default:
            break;
        }

        std::wcerr << L"[FsHost] RW native-mutation warning: failed to apply mutation operation for path '"
            << path
            << L"' (status="
            << status_text;
        if (!failure_reason.empty())
        {
            std::wcerr << L", reason=" << failure_reason;
        }
        std::wcerr << L")."
            << std::endl;
        return false;
    }

    if (!UpdateRecoveryMarkerBestEffort(c, true))
    {
        std::wcerr << L"[FsHost] RW native-mutation warning: failed to persist recovery marker state." << std::endl;
    }
    return true;
}

NTSTATUS BlockNativeMutationAfterStagingFailure(MountContext* c, const wchar_t* operation)
{
    if (!c)
    {
        return STATUS_MEDIA_WRITE_PROTECTED;
    }

    c->recovery_active = true;
    c->runtime_recovery_reason = L"NativeMutationStagingFailed";
    c->runtime_last_recovery_action = L"DowngradedAfterMutationStagingFailure";
    if (IsRecoveryPolicyFailClosed(c->args.write_recovery_policy))
    {
        c->write_degraded = true;
        c->native_write_enabled = false;
        c->overlay_write_enabled = false;
    }

    std::wcerr << L"[FsHost] RW mutation blocked";
    if (operation && *operation)
    {
        std::wcerr << L" (" << operation << L")";
    }
    std::wcerr << L": native APFS metadata staging failed; live write was rejected to avoid non-persistent Explorer-only state."
               << std::endl;

    (void)UpdateRecoveryMarkerBestEffort(c, true);
    (void)WriteHostStatusFile(*c, c->recovery_active, c->runtime_last_commit_xid);
    return STATUS_MEDIA_WRITE_PROTECTED;
}
#endif

#ifdef APFSACCESS_HAS_RW_ENGINE
bool RecordMutationBestEffort(
    MountContext* c,
    apfsaccess::rw::TransactionManager::MutationKind kind,
    const std::wstring& path,
    const std::wstring& secondary_path = L"",
    std::uint64_t offset = 0,
    std::uint64_t length = 0,
    bool replace_if_exists = false)
{
    if (!c || !c->tx_manager)
    {
        return true;
    }

    apfsaccess::rw::TransactionManager::MutationIntent mutation{};
    mutation.kind = kind;
    mutation.path = path;
    mutation.secondary_path = secondary_path;
    mutation.offset = offset;
    mutation.length = length;
    mutation.replace_if_exists = replace_if_exists;

    std::lock_guard<std::mutex> lock(c->tx_mutex);
    auto& tx = *c->tx_manager;

    if (tx.CurrentState() == apfsaccess::rw::TransactionManager::State::Committing)
    {
        std::wcerr << L"[FsHost] RW journal warning: transaction is already committing; mutation was deferred for path '" << path << L"'." << std::endl;
        return false;
    }

    if (tx.CurrentState() == apfsaccess::rw::TransactionManager::State::Failed)
    {
        (void)tx.Abort();
    }

    if (tx.CurrentState() == apfsaccess::rw::TransactionManager::State::Idle && !tx.Begin())
    {
        std::wcerr << L"[FsHost] RW journal warning: Begin() failed for mutation path '" << path << L"'." << std::endl;
        return false;
    }
    if (!tx.RecordMutation(mutation))
    {
        (void)tx.Abort();
        std::wcerr << L"[FsHost] RW journal warning: RecordMutation() failed for path '" << path << L"'." << std::endl;
        return false;
    }

    const auto dirty_limit = static_cast<std::size_t>(std::max(1, c->args.write_max_dirty_transactions));
    if (tx.PendingMutationCount() >= dirty_limit && !tx.Commit())
    {
        (void)tx.Abort();
        std::wcerr << L"[FsHost] RW journal warning: Commit() failed after hitting dirty transaction limit for path '" << path << L"'." << std::endl;
        return false;
    }
    return true;
}

bool CommitMutationJournalBestEffort(MountContext* c)
{
    if (!c || !c->tx_manager)
    {
        return true;
    }

    std::lock_guard<std::mutex> lock(c->tx_mutex);
    auto& tx = *c->tx_manager;
    if (tx.CurrentState() == apfsaccess::rw::TransactionManager::State::Idle)
    {
        return true;
    }

    if (tx.CurrentState() == apfsaccess::rw::TransactionManager::State::Failed)
    {
        (void)tx.Abort();
        return false;
    }

    if (!tx.Commit())
    {
        (void)tx.Abort();
        return false;
    }

    return true;
}

NTSTATUS CommitNativeMutationsBestEffort(MountContext* c, const wchar_t* origin)
{
    if (!c || !IsNativeWriteEnabled(c) || !c->metadata_store)
    {
        return STATUS_SUCCESS;
    }

    std::lock_guard<std::mutex> commit_lock(c->commit_mutex);

    apfsaccess::rw::MetadataStore::CommitStatus commit_status = apfsaccess::rw::MetadataStore::CommitStatus::NotReady;
    std::optional<std::uint64_t> committed_xid = std::nullopt;
    std::wstring metadata_recovery_reason;
    bool metadata_recovery_required = false;
    bool canonical_ready_before_commit = false;
    bool require_canonical_gate = false;
    std::string final_commit_stage;
    const auto commit_started_tick = static_cast<std::uint64_t>(GetTickCount64());
    {
        std::lock_guard<std::mutex> metadata_lock(c->metadata_mutex);
        ArmCommitDeadline(c);
        require_canonical_gate = RequiresCanonicalMutationGate(c->args);
        canonical_ready_before_commit = c->metadata_store->IsCanonicalCommitReady();
        commit_status = require_canonical_gate
            ? c->metadata_store->CommitCanonicalTransaction()
            : c->metadata_store->CommitTransaction();
        final_commit_stage = c->metadata_store->LastCommitStage();
        committed_xid = c->metadata_store->LastCommittedXid();
        metadata_recovery_reason = c->metadata_store->RecoveryReason();
        metadata_recovery_required = c->metadata_store->IsRecoveryRequired();
        if (metadata_recovery_reason.empty() &&
            require_canonical_gate &&
            !canonical_ready_before_commit &&
            commit_status == apfsaccess::rw::MetadataStore::CommitStatus::NotWritable)
        {
            metadata_recovery_reason = L"CommitModelNotCanonical";
        }
        ClearCommitDeadline(c);
    }
    const auto commit_finished_tick = static_cast<std::uint64_t>(GetTickCount64());
    const auto commit_duration_ms = commit_finished_tick >= commit_started_tick
        ? commit_finished_tick - commit_started_tick
        : 0;
    const auto commit_timed_out = c->commit_timeout_latched.exchange(false, std::memory_order_relaxed);
    if (IsHostCommitTraceEnabled())
    {
        std::wcerr << L"[FsHost] RW native-commit timing"
                   << L" origin=" << origin
                   << L" status=" << static_cast<int>(commit_status)
                   << L" durationMs=" << commit_duration_ms
                   << L" canonicalGate=" << (require_canonical_gate ? L"true" : L"false")
                   << L" finalStage=" << Utf8ToWide(final_commit_stage)
                   << std::endl;
    }
    if (commit_timed_out &&
        commit_status != apfsaccess::rw::MetadataStore::CommitStatus::Committed &&
        commit_status != apfsaccess::rw::MetadataStore::CommitStatus::NothingToCommit)
    {
        std::wcerr << L"[FsHost] RW native-commit warning (" << origin << L"): commit stage exceeded timeout ("
            << c->args.write_commit_timeout_seconds
            << L"s)."
            << std::endl;
        c->recovery_active = true;
        c->runtime_recovery_reason = L"CommitTimedOut";
        c->runtime_last_recovery_action = L"DowngradedAfterCommitTimeout";
        if (IsRecoveryPolicyFailClosed(c->args.write_recovery_policy))
        {
            c->write_degraded = true;
            c->native_write_enabled = false;
            c->overlay_write_enabled = false;
        }
        (void)UpdateRecoveryMarkerBestEffort(c, true);
        (void)WriteHostStatusFile(*c, c->recovery_active, c->runtime_last_commit_xid);
        return STATUS_IO_TIMEOUT;
    }

    switch (commit_status)
    {
    case apfsaccess::rw::MetadataStore::CommitStatus::Committed:
        if (committed_xid.has_value())
        {
            c->runtime_last_commit_xid = committed_xid;
        }
        c->recovery_active = false;
        c->write_degraded = false;
        c->runtime_recovery_reason.clear();
        c->runtime_last_recovery_action.clear();
        (void)UpdateRecoveryMarkerBestEffort(c, false);
        (void)WriteHostStatusFile(*c, c->recovery_active, c->runtime_last_commit_xid);
        return STATUS_SUCCESS;
    case apfsaccess::rw::MetadataStore::CommitStatus::NothingToCommit:
        if (c->recovery_active || c->pending_native_writes)
        {
            c->recovery_active = false;
            c->write_degraded = false;
            c->runtime_recovery_reason.clear();
            c->runtime_last_recovery_action.clear();
            (void)UpdateRecoveryMarkerBestEffort(c, false);
            (void)WriteHostStatusFile(*c, c->recovery_active, c->runtime_last_commit_xid);
        }
        return STATUS_SUCCESS;
    case apfsaccess::rw::MetadataStore::CommitStatus::NotWritable:
        std::wcerr << L"[FsHost] RW native-commit warning (" << origin << L"): write path is not writable; native commit remains blocked." << std::endl;
        c->recovery_active = true;
        c->runtime_recovery_reason = metadata_recovery_reason.empty() ? L"CommitNotWritable" : metadata_recovery_reason;
        c->runtime_last_recovery_action =
            !_wcsicmp(c->runtime_recovery_reason.c_str(), L"CommitModelNotCanonical")
            ? L"DowngradedAfterCommitModelMismatch"
            : L"DowngradedAfterNotWritable";
        if (IsRecoveryPolicyFailClosed(c->args.write_recovery_policy))
        {
            c->write_degraded = true;
            c->native_write_enabled = false;
            c->overlay_write_enabled = false;
        }
        (void)UpdateRecoveryMarkerBestEffort(c, true);
        (void)WriteHostStatusFile(*c, c->recovery_active, c->runtime_last_commit_xid);
        return STATUS_MEDIA_WRITE_PROTECTED;
    case apfsaccess::rw::MetadataStore::CommitStatus::NotReady:
        std::wcerr << L"[FsHost] RW native-commit warning (" << origin << L"): metadata store is not ready for commit." << std::endl;
        c->recovery_active = true;
        c->runtime_recovery_reason = metadata_recovery_reason.empty() ? L"CommitNotReady" : metadata_recovery_reason;
        c->runtime_last_recovery_action = L"DowngradedAfterNotReady";
        if (IsRecoveryPolicyFailClosed(c->args.write_recovery_policy))
        {
            c->write_degraded = true;
            c->native_write_enabled = false;
            c->overlay_write_enabled = false;
        }
        (void)UpdateRecoveryMarkerBestEffort(c, true);
        (void)WriteHostStatusFile(*c, c->recovery_active, c->runtime_last_commit_xid);
        return STATUS_UNSUCCESSFUL;
    case apfsaccess::rw::MetadataStore::CommitStatus::AllocationFailed:
        std::wcerr << L"[FsHost] RW native-commit warning (" << origin << L"): extent allocation failed during commit." << std::endl;
        c->recovery_active = true;
        c->runtime_recovery_reason = metadata_recovery_reason.empty() ? L"CommitAllocationFailed" : metadata_recovery_reason;
        c->runtime_last_recovery_action = L"DowngradedAfterAllocationFailure";
        if (IsRecoveryPolicyFailClosed(c->args.write_recovery_policy))
        {
            c->write_degraded = true;
            c->native_write_enabled = false;
            c->overlay_write_enabled = false;
        }
        (void)UpdateRecoveryMarkerBestEffort(c, true);
        (void)WriteHostStatusFile(*c, c->recovery_active, c->runtime_last_commit_xid);
        return STATUS_DISK_FULL;
    case apfsaccess::rw::MetadataStore::CommitStatus::InvariantFailed:
        std::wcerr << L"[FsHost] RW native-commit warning (" << origin << L"): pending mutation invariants failed preflight validation." << std::endl;
        c->recovery_active = true;
        c->runtime_recovery_reason = metadata_recovery_reason.empty() ? L"CommitInvariantFailed" : metadata_recovery_reason;
        c->runtime_last_recovery_action = L"DowngradedAfterInvariantFailure";
        if (IsRecoveryPolicyFailClosed(c->args.write_recovery_policy))
        {
            c->write_degraded = true;
            c->native_write_enabled = false;
            c->overlay_write_enabled = false;
        }
        (void)UpdateRecoveryMarkerBestEffort(c, true);
        (void)WriteHostStatusFile(*c, c->recovery_active, c->runtime_last_commit_xid);
        return STATUS_UNSUCCESSFUL;
    case apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed:
    case apfsaccess::rw::MetadataStore::CommitStatus::FlushFailed:
        std::wcerr << L"[FsHost] RW native-commit warning (" << origin << L"): failed to persist commit records." << std::endl;
        c->recovery_active = true;
        c->runtime_recovery_reason = metadata_recovery_reason.empty() ? L"CommitPersistOrFlushFailed" : metadata_recovery_reason;
        c->runtime_last_recovery_action = L"DowngradedAfterPersistFailure";
        if (IsRecoveryPolicyFailClosed(c->args.write_recovery_policy))
        {
            c->write_degraded = true;
            c->native_write_enabled = false;
            c->overlay_write_enabled = false;
        }
        (void)UpdateRecoveryMarkerBestEffort(c, true);
        (void)WriteHostStatusFile(*c, c->recovery_active, c->runtime_last_commit_xid);
        return metadata_recovery_required ? STATUS_MEDIA_WRITE_PROTECTED : STATUS_UNSUCCESSFUL;
    default:
        return STATUS_UNSUCCESSFUL;
    }
}

bool HasPendingNativeMutations(MountContext* c)
{
    if (!c || !c->metadata_store)
    {
        return false;
    }

    std::lock_guard<std::mutex> metadata_lock(c->metadata_mutex);
    return c->metadata_store->PendingMutationCount() > 0;
}

NTSTATUS CommitNativeMutationsOnFlushBestEffort(MountContext* c)
{
    if (!c || !IsNativeWriteEnabled(c) || !c->metadata_store)
    {
        return STATUS_SUCCESS;
    }

    if (!HasPendingNativeMutations(c))
    {
        return STATUS_SUCCESS;
    }

    return CommitNativeMutationsBestEffort(c, L"Flush");
}

void FinalizeMutationJournalBestEffort(MountContext* c, const wchar_t* origin)
{
    if (!CommitMutationJournalBestEffort(c))
    {
        std::wcerr << L"[FsHost] RW journal warning: failed to finalize transaction journal during " << origin << L"." << std::endl;
    }
    if (c)
    {
        (void)WriteHostStatusFile(*c, c->recovery_active, c->runtime_last_commit_xid);
    }
}
#endif

NTSTATUS HandleMutationWriteDisabled(MountContext* c, const wchar_t* operation)
{
    if (!c)
    {
        return STATUS_MEDIA_WRITE_PROTECTED;
    }

#ifdef APFSACCESS_HAS_RW_ENGINE
    const auto native_backend_selected = c->native_write_enabled && !c->overlay_write_enabled;
    if (native_backend_selected)
    {
        std::wstring reason = L"CommitNotReady";
        {
            std::lock_guard<std::mutex> metadata_lock(c->metadata_mutex);
            if (!c->metadata_store)
            {
                reason = L"NativeWriteUnavailable";
            }
            else if (c->metadata_store->IsRecoveryRequired())
            {
                reason = c->metadata_store->RecoveryReason();
                if (reason.empty())
                {
                    reason = L"RecoveryRequired";
                }
            }
            else if (!c->metadata_store->IsCommitPathReady())
            {
                reason = L"CommitNotReady";
            }
            else if (RequiresCanonicalMutationGate(c->args) &&
                     !c->metadata_store->IsCanonicalCommitReady())
            {
                reason = L"CommitModelNotCanonical";
            }
        }

        const auto previous_reason = c->runtime_recovery_reason;
        const auto previous_recovery = c->recovery_active;

        c->recovery_active = true;
        c->runtime_recovery_reason = reason;
        c->runtime_last_recovery_action =
            !_wcsicmp(reason.c_str(), L"CommitModelNotCanonical")
            ? L"DowngradedAfterCommitModelMismatch"
            : L"DowngradedAfterNotReady";

        if (IsRecoveryPolicyFailClosed(c->args.write_recovery_policy))
        {
            c->write_degraded = true;
            c->native_write_enabled = false;
            c->overlay_write_enabled = false;
        }

        if (!previous_recovery || _wcsicmp(previous_reason.c_str(), reason.c_str()) != 0)
        {
            std::wcerr << L"[FsHost] RW mutation blocked";
            if (operation && *operation)
            {
                std::wcerr << L" (" << operation << L")";
            }
            std::wcerr << L": native write path is unavailable (reason=" << reason << L")." << std::endl;
        }

        (void)UpdateRecoveryMarkerBestEffort(c, true);
        (void)WriteHostStatusFile(*c, c->recovery_active, c->runtime_last_commit_xid);
    }
#else
    (void)operation;
#endif

    return STATUS_MEDIA_WRITE_PROTECTED;
}

bool EnsureParentDirectoryLoaded(MountContext* c, const std::wstring& path)
{
    if (!c)
    {
        return false;
    }
    auto parent = FindNode(c, Parent(path));
    if (!parent || !parent->is_directory)
    {
        return false;
    }
    return EnsureDirectoryLoaded(c, parent);
}

bool CanRemoveNodeRecursiveLocked(MountContext* c, const std::shared_ptr<Node>& node, bool allow_open_file_node = false)
{
    if (!c || !node)
    {
        return false;
    }
    if (node->open_handle_count != 0 && !(allow_open_file_node && !node->is_directory))
    {
        return false;
    }
    if (!node->is_directory)
    {
        return true;
    }
    for (const auto& child_name : node->children)
    {
        auto child = TryGetNodeLocked(c, Join(node->path, child_name));
        if (child && !CanRemoveNodeRecursiveLocked(c, child, false))
        {
            return false;
        }
    }
    return true;
}

bool HasRenameOpenHandleConflictLocked(
    MountContext* c,
    const std::shared_ptr<Node>& source,
    const OpenContext* current_open)
{
    if (!c || !source)
    {
        return true;
    }
    if (!source->is_directory)
    {
        return false;
    }

    for (const auto& [_, candidate] : c->nodes)
    {
        if (!candidate || candidate->open_handle_count == 0)
        {
            continue;
        }

        const auto is_source = candidate == source;
        const auto is_descendant = IsDescendantPath(candidate->path, source->path);
        if (!is_source && !is_descendant)
        {
            continue;
        }

        const std::uint32_t allowed_handles =
            (current_open && current_open->node == candidate) ? 1u : 0u;
        if (candidate->open_handle_count > allowed_handles)
        {
            return true;
        }
    }

    return false;
}

bool RemoveNodeRecursiveLocked(MountContext* c, const std::shared_ptr<Node>& node, bool allow_open_file_node = false)
{
    if (!c || !node)
    {
        return false;
    }
    if (!CanRemoveNodeRecursiveLocked(c, node, allow_open_file_node))
    {
        return false;
    }
    if (node->is_directory)
    {
        for (const auto& child_name : node->children)
        {
            auto child = TryGetNodeLocked(c, Join(node->path, child_name));
            if (child)
            {
                RemoveNodeRecursiveLocked(c, child, false);
            }
        }
    }
    if (!node->is_directory)
    {
        std::error_code ec;
        std::filesystem::remove(HydrationPath(c, *node), ec);
    }
    c->nodes.erase(Key(node->path));
    return true;
}

void ReindexNodePathsLocked(MountContext* c, const std::shared_ptr<Node>& node, const std::wstring& old_path, const std::wstring& new_path)
{
    if (!c || !node)
    {
        return;
    }

    const auto old_key = Key(old_path);
    const auto new_key = Key(new_path);

    if (auto current = c->nodes.find(old_key); current != c->nodes.end())
    {
        c->nodes.erase(current);
    }

    node->path = new_path;
    c->nodes[new_key] = node;

    if (!node->is_directory)
    {
        std::error_code ec;
        Node old_node{};
        old_node.path = old_path;
        auto old_h = HydrationPath(c, old_node);
        auto new_h = HydrationPath(c, *node);
        if (std::filesystem::exists(old_h, ec))
        {
            std::filesystem::create_directories(new_h.parent_path(), ec);
            std::filesystem::rename(old_h, new_h, ec);
        }
    }

    if (!node->is_directory)
    {
        return;
    }

    for (const auto& child_name : node->children)
    {
        auto child_old_path = Join(old_path, child_name);
        auto child_new_path = Join(new_path, child_name);
        auto child = TryGetNodeLocked(c, child_old_path);
        if (child)
        {
            ReindexNodePathsLocked(c, child, child_old_path, child_new_path);
        }
    }
}

MountContext* Ctx(FSP_FILE_SYSTEM* fs) { return fs ? (MountContext*)fs->UserContext : nullptr; }

std::wstring BuildExplorerVolumeLabel(const std::wstring& volume)
{
    auto label = volume.empty() ? std::wstring(L"APFS") : volume;
    if (label.size() > 31)
    {
        label.resize(31);
    }
    return label;
}

std::uint64_t AlignDownToAllocationUnit(std::uint64_t value, std::uint64_t allocation_unit)
{
    if (allocation_unit <= 1 || value == 0)
    {
        return value;
    }
    return value - (value % allocation_unit);
}

NTSTATUS CB_GetVolumeInfo(FSP_FILE_SYSTEM* fs, FSP_FSCTL_VOLUME_INFO* v)
{
    auto* c = Ctx(fs);
    if (!c || !v) return STATUS_INVALID_PARAMETER;
#ifdef APFSACCESS_HAS_RW_ENGINE
    RefreshReportedVolumeInfoFromMetadata(*c);
#endif
    std::memset(v, 0, sizeof(*v));
    std::optional<std::uint64_t> total_size = c->reported_total_size_bytes;
    std::optional<std::uint64_t> free_size = c->reported_free_size_bytes;
    std::uint64_t allocation_unit = c->reported_allocation_unit_bytes != 0
        ? c->reported_allocation_unit_bytes
        : 4096;
#ifdef APFSACCESS_HAS_RW_ENGINE
    {
        std::lock_guard<std::mutex> metadata_lock(c->metadata_mutex);
        if (c->metadata_store)
        {
            if (const auto block_size = c->metadata_store->BlockSizeBytes();
                block_size.has_value() && block_size.value() != 0)
            {
                allocation_unit = block_size.value();
            }
            if (const auto metadata_total_size = c->metadata_store->TotalSizeBytes();
                metadata_total_size.has_value())
            {
                total_size = metadata_total_size;
            }
            if (const auto metadata_free_size = c->metadata_store->FreeSizeBytes();
                metadata_free_size.has_value() && metadata_free_size.value() > 0)
            {
                free_size = metadata_free_size;
            }
        }
    }
#endif

    if (total_size.has_value())
    {
        total_size = AlignDownToAllocationUnit(total_size.value(), allocation_unit);
    }
    if (free_size.has_value())
    {
        free_size = AlignDownToAllocationUnit(free_size.value(), allocation_unit);
    }
    if (total_size.has_value() && free_size.has_value() && free_size.value() > total_size.value())
    {
        free_size = total_size;
    }
    if (total_size.has_value() && (!free_size.has_value() || free_size.value() == 0))
    {
        // Prefer a usable Explorer capacity bar over reporting an unknown/zero
        // free space while the richer APFS spaceman state is still unavailable.
        free_size = total_size;
    }

    v->TotalSize = total_size.value_or(0);
    v->FreeSize = free_size.value_or(0);
    auto label = c->label.substr(0, 31);
    v->VolumeLabelLength = (UINT16)(label.size() * sizeof(WCHAR));
    if (!label.empty()) std::memcpy(v->VolumeLabel, label.data(), label.size() * sizeof(WCHAR));
    return STATUS_SUCCESS;
}

NTSTATUS CB_SetVolumeLabel(FSP_FILE_SYSTEM*, PWSTR, FSP_FSCTL_VOLUME_INFO*)
{
    return STATUS_MEDIA_WRITE_PROTECTED;
}

NTSTATUS CB_Create(FSP_FILE_SYSTEM* fs, PWSTR file_name, UINT32 create_options, UINT32 granted_access, UINT32, PSECURITY_DESCRIPTOR, UINT64, PVOID* out_ctx, FSP_FSCTL_FILE_INFO* info)
{
    auto* c = Ctx(fs);
    if (!c || !out_ctx || !info)
    {
        return STATUS_INVALID_PARAMETER;
    }
    ExternalMutationRequestScope mutation_request_scope(c);
    if (!mutation_request_scope.Acquired())
    {
        return STATUS_VOLUME_DISMOUNTED;
    }
    MutationCallbackScope mutation_scope(c);
    if (!IsMutationWriteEnabled(c))
    {
        return HandleMutationWriteDisabled(c, L"Create");
    }
    if (HasConflictingCreateTypeOptions(create_options))
    {
        return STATUS_INVALID_PARAMETER;
    }

    auto path = NormalizePath(file_name ? std::wstring(file_name) : L"\\");
    if (path == L"\\")
    {
        return STATUS_OBJECT_NAME_COLLISION;
    }
    if (!EnsureParentDirectoryLoaded(c, path))
    {
        std::lock_guard<std::mutex> lock(c->mutex);
        if (HasDeletePendingAncestorLocked(c, path))
        {
            return STATUS_DELETE_PENDING;
        }

        auto hidden_parent = TryGetNodeLocked(c, Parent(path));
        if (IsDeleteBlockedStateLocked(hidden_parent))
        {
            return STATUS_DELETE_PENDING;
        }
        return STATUS_OBJECT_PATH_NOT_FOUND;
    }

    auto parent_path = Parent(path);
    auto parent_name_pos = path.find_last_of(L'\\');
    auto name = parent_name_pos == std::wstring::npos ? path : path.substr(parent_name_pos + 1);
    if (name.empty())
    {
        return STATUS_OBJECT_NAME_INVALID;
    }

    auto parent_node = FindNode(c, parent_path);
    if (!parent_node || !parent_node->is_directory)
    {
        std::lock_guard<std::mutex> lock(c->mutex);
        if (HasDeletePendingAncestorLocked(c, parent_path))
        {
            return STATUS_DELETE_PENDING;
        }

        auto hidden_parent = TryGetNodeLocked(c, parent_path);
        if (IsDeleteBlockedStateLocked(hidden_parent))
        {
            return STATUS_DELETE_PENDING;
        }
        return STATUS_OBJECT_PATH_NOT_FOUND;
    }

    const bool request_directory = (create_options & FILE_DIRECTORY_FILE) != 0;
    const bool request_non_directory = (create_options & FILE_NON_DIRECTORY_FILE) != 0;

    std::shared_ptr<Node> node;
    {
        std::lock_guard<std::mutex> lock(c->mutex);
        if (HasDeletePendingAncestorLocked(c, path))
        {
            return STATUS_DELETE_PENDING;
        }

        auto existing = TryGetNodeLocked(c, path);
        if (existing)
        {
            if (IsDeleteBlockedStateLocked(existing))
            {
                return STATUS_DELETE_PENDING;
            }
            if (request_directory && !existing->is_directory)
            {
                return STATUS_NOT_A_DIRECTORY;
            }
            if (request_non_directory && existing->is_directory)
            {
                return STATUS_FILE_IS_A_DIRECTORY;
            }
            return STATUS_OBJECT_NAME_COLLISION;
        }

        node = std::make_shared<Node>();
        node->path = path;
        node->apfs_path.clear();
        node->is_directory = request_directory;
        node->file_size = 0;
        node->timestamp = UtcNow();
        node->loaded = request_directory;
        c->nodes.emplace(Key(path), node);
        AddChildName(parent_node->children, name);
    }

    auto* o = new (std::nothrow) OpenContext();
    if (!o)
    {
        std::lock_guard<std::mutex> lock(c->mutex);
        RemoveChildName(parent_node->children, name);
        c->nodes.erase(Key(path));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    o->node = node;
    InitializeOpenAccess(o, granted_access);
    o->write_open = true;
    if (!node->is_directory)
    {
        if (!EnsureHydrated(c, node, true))
        {
            delete o;
            std::lock_guard<std::mutex> lock(c->mutex);
            RemoveChildName(parent_node->children, name);
            c->nodes.erase(Key(path));
            return STATUS_UNSUCCESSFUL;
        }
        auto hydrated = HydrationPath(c, *node);
        const auto desired_access = ResolveHydrationDesiredAccess(
            IsMutationWriteEnabled(c),
            granted_access,
            true);
        o->file = CreateFileW(
            hydrated.wstring().c_str(),
            desired_access,
            ResolveHydrationShareMode(IsMutationWriteEnabled(c), granted_access, o->write_open),
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (o->file == INVALID_HANDLE_VALUE)
        {
            delete o;
            std::lock_guard<std::mutex> lock(c->mutex);
            RemoveChildName(parent_node->children, name);
            c->nodes.erase(Key(path));
            return STATUS_UNSUCCESSFUL;
        }
    }

#ifdef APFSACCESS_HAS_RW_ENGINE
    if (IsNativeWriteEnabled(c) &&
        !RecordNativeMutationBestEffort(
            c,
            request_directory
                ? apfsaccess::rw::MetadataStore::MutationOperation::CreateDirectory
                : apfsaccess::rw::MetadataStore::MutationOperation::CreateFile,
            path))
    {
        if (!node->is_directory && o->file != INVALID_HANDLE_VALUE)
        {
            CloseHandle(o->file);
            o->file = INVALID_HANDLE_VALUE;
        }
        delete o;
        std::lock_guard<std::mutex> lock(c->mutex);
        RemoveChildName(parent_node->children, name);
        std::error_code ec;
        std::filesystem::remove(HydrationPath(c, *node), ec);
        c->nodes.erase(Key(path));
        return BlockNativeMutationAfterStagingFailure(c, L"Create");
    }
#endif

    {
        std::lock_guard<std::mutex> lock(c->mutex);
        ++node->open_handle_count;
        if (o->write_open)
        {
            ++node->write_handle_count;
        }
    }

    FillInfo(*node, !IsMutationWriteEnabled(c), info);
    *out_ctx = o;
#ifdef APFSACCESS_HAS_RW_ENGINE
    RecordMutationBestEffort(
        c,
        request_directory
            ? apfsaccess::rw::TransactionManager::MutationKind::CreateDirectory
            : apfsaccess::rw::TransactionManager::MutationKind::CreateFile,
        path);
#endif
    return STATUS_SUCCESS;
}

NTSTATUS CB_Overwrite(FSP_FILE_SYSTEM* fs, PVOID ctx, UINT32, BOOLEAN, UINT64 allocation_size, FSP_FSCTL_FILE_INFO* info)
{
    auto* c = Ctx(fs);
    auto* o = (OpenContext*)ctx;
    if (!c || !o || !o->node || !info)
    {
        return STATUS_INVALID_PARAMETER;
    }
    ExternalMutationRequestScope mutation_request_scope(c);
    if (!mutation_request_scope.Acquired())
    {
        return STATUS_VOLUME_DISMOUNTED;
    }
    MutationCallbackScope mutation_scope(c);
    if (!IsMutationWriteEnabled(c))
    {
        return HandleMutationWriteDisabled(c, L"Overwrite");
    }
    if (o->node->is_directory || o->file == INVALID_HANDLE_VALUE)
    {
        return STATUS_FILE_IS_A_DIRECTORY;
    }
    if (!o->allow_set_file_size)
    {
        return STATUS_ACCESS_DENIED;
    }

#ifdef APFSACCESS_HAS_RW_ENGINE
    if (IsNativeWriteEnabled(c) &&
        !RecordNativeMutationBestEffort(
            c,
            apfsaccess::rw::MetadataStore::MutationOperation::SetFileSize,
            o->node->path,
            L"",
            0,
            allocation_size))
    {
        return BlockNativeMutationAfterStagingFailure(c, L"Overwrite");
    }
#endif

    LARGE_INTEGER target{};
    target.QuadPart = allocation_size;
    if (!SetFilePointerEx(o->file, target, nullptr, FILE_BEGIN) || !SetEndOfFile(o->file))
    {
#ifdef APFSACCESS_HAS_RW_ENGINE
        if (IsNativeWriteEnabled(c))
        {
            (void)BlockNativeMutationAfterStagingFailure(c, L"Overwrite");
        }
#endif
        return STATUS_UNSUCCESSFUL;
    }

    {
        std::lock_guard<std::mutex> lock(c->mutex);
        o->node->file_size = allocation_size;
        o->node->timestamp = UtcNow();
        FillInfo(*o->node, !IsMutationWriteEnabled(c), info);
    }
#ifdef APFSACCESS_HAS_RW_ENGINE
    RecordMutationBestEffort(
        c,
        apfsaccess::rw::TransactionManager::MutationKind::SetFileSize,
        o->node->path,
        L"",
        0,
        allocation_size);
#endif
    return STATUS_SUCCESS;
}

NTSTATUS CB_Write(FSP_FILE_SYSTEM* fs, PVOID ctx, PVOID buf, UINT64 off, ULONG len, BOOLEAN write_to_end_of_file, BOOLEAN constrained_io, PULONG done, FSP_FSCTL_FILE_INFO* info)
{
    auto* c = Ctx(fs);
    auto* o = (OpenContext*)ctx;
    if (!c || !o || !o->node || o->node->is_directory || o->file == INVALID_HANDLE_VALUE || !buf || !done)
    {
        return STATUS_INVALID_PARAMETER;
    }
    ExternalMutationRequestScope mutation_request_scope(c);
    if (!mutation_request_scope.Acquired())
    {
        return STATUS_VOLUME_DISMOUNTED;
    }
    MutationCallbackScope mutation_scope(c);
    if (!IsMutationWriteEnabled(c))
    {
        return HandleMutationWriteDisabled(c, L"Write");
    }
    if (!o->allow_write_data && !o->allow_append_data)
    {
        return STATUS_ACCESS_DENIED;
    }

    auto current_size = o->node->file_size;
    if (write_to_end_of_file)
    {
        off = current_size;
    }
    else if (!o->allow_write_data && o->allow_append_data)
    {
        return STATUS_ACCESS_DENIED;
    }

    if (off > (std::numeric_limits<std::uint64_t>::max() - static_cast<std::uint64_t>(len)))
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (constrained_io && off >= current_size)
    {
        *done = 0;
        if (info)
        {
            FillInfo(*o->node, !IsMutationWriteEnabled(c), info);
        }
        return STATUS_SUCCESS;
    }

    ULONG write_len = len;
    if (constrained_io && (off + static_cast<std::uint64_t>(len)) > current_size)
    {
        write_len = (ULONG)(current_size - off);
    }

#ifdef APFSACCESS_HAS_RW_ENGINE
    if (IsNativeWriteEnabled(c) &&
        !RecordNativeMutationBestEffort(
            c,
            apfsaccess::rw::MetadataStore::MutationOperation::Write,
            o->node->path,
            L"",
            off,
            write_len))
    {
        *done = 0;
        return BlockNativeMutationAfterStagingFailure(c, L"Write");
    }
#endif

    OVERLAPPED ov{};
    ov.Offset = (DWORD)(off & 0xffffffffull);
    ov.OffsetHigh = (DWORD)(off >> 32);
    DWORD written = 0;
    if (!WriteFile(o->file, buf, write_len, &written, &ov))
    {
        *done = 0;
#ifdef APFSACCESS_HAS_RW_ENGINE
        if (IsNativeWriteEnabled(c))
        {
            (void)BlockNativeMutationAfterStagingFailure(c, L"Write");
        }
#endif
        return STATUS_UNSUCCESSFUL;
    }

    {
        const auto write_end = off + static_cast<std::uint64_t>(written);
        std::lock_guard<std::mutex> lock(c->mutex);
        o->node->file_size = std::max<std::uint64_t>(o->node->file_size, write_end);
        o->node->timestamp = UtcNow();
        if (info)
        {
            FillInfo(*o->node, !IsMutationWriteEnabled(c), info);
        }
    }
    *done = written;
#ifdef APFSACCESS_HAS_RW_ENGINE
    RecordMutationBestEffort(
        c,
        apfsaccess::rw::TransactionManager::MutationKind::Write,
        o->node->path,
        L"",
        off,
        written);
#endif
    return STATUS_SUCCESS;
}

NTSTATUS CB_SetBasicInfo(FSP_FILE_SYSTEM* fs, PVOID ctx, UINT32, UINT64 creation_time, UINT64 last_access_time, UINT64 last_write_time, UINT64 change_time, FSP_FSCTL_FILE_INFO* info)
{
    auto* c = Ctx(fs);
    auto* o = (OpenContext*)ctx;
    if (!c || !o || !o->node || !info)
    {
        return STATUS_INVALID_PARAMETER;
    }
    ExternalMutationRequestScope mutation_request_scope(c);
    if (!mutation_request_scope.Acquired())
    {
        return STATUS_VOLUME_DISMOUNTED;
    }
    MutationCallbackScope mutation_scope(c);
    if (!IsMutationWriteEnabled(c))
    {
        return HandleMutationWriteDisabled(c, L"SetBasicInfo");
    }
    if (!o->allow_set_basic_info)
    {
        return STATUS_ACCESS_DENIED;
    }

    ULARGE_INTEGER stamp{};
    if (last_write_time != 0)
    {
        stamp.QuadPart = last_write_time;
    }
    else if (change_time != 0)
    {
        stamp.QuadPart = change_time;
    }
    else if (last_access_time != 0)
    {
        stamp.QuadPart = last_access_time;
    }
    else if (creation_time != 0)
    {
        stamp.QuadPart = creation_time;
    }
    else
    {
        FILETIME now = UtcNow();
        stamp.LowPart = now.dwLowDateTime;
        stamp.HighPart = now.dwHighDateTime;
    }

#ifdef APFSACCESS_HAS_RW_ENGINE
    if (IsNativeWriteEnabled(c) &&
        !RecordNativeMutationBestEffort(
            c,
            apfsaccess::rw::MetadataStore::MutationOperation::SetBasicInfo,
            o->node->path,
            L"",
            0,
            0,
            false,
            stamp.QuadPart))
    {
        return BlockNativeMutationAfterStagingFailure(c, L"SetBasicInfo");
    }
#endif

    {
        std::lock_guard<std::mutex> lock(c->mutex);
        o->node->timestamp.dwLowDateTime = stamp.LowPart;
        o->node->timestamp.dwHighDateTime = stamp.HighPart;
        FillInfo(*o->node, !IsMutationWriteEnabled(c), info);
    }
#ifdef APFSACCESS_HAS_RW_ENGINE
    RecordMutationBestEffort(
        c,
        apfsaccess::rw::TransactionManager::MutationKind::SetBasicInfo,
        o->node->path);
    FinalizeMutationJournalBestEffort(c, L"SetBasicInfo");
#endif
    return STATUS_SUCCESS;
}

NTSTATUS CB_SetFileSize(FSP_FILE_SYSTEM* fs, PVOID ctx, UINT64 size, BOOLEAN, FSP_FSCTL_FILE_INFO* info)
{
    auto* c = Ctx(fs);
    auto* o = (OpenContext*)ctx;
    if (!c || !o || !o->node || o->node->is_directory || !info)
    {
        return STATUS_INVALID_PARAMETER;
    }
    ExternalMutationRequestScope mutation_request_scope(c);
    if (!mutation_request_scope.Acquired())
    {
        return STATUS_VOLUME_DISMOUNTED;
    }
    MutationCallbackScope mutation_scope(c);
    if (!IsMutationWriteEnabled(c))
    {
        return HandleMutationWriteDisabled(c, L"SetFileSize");
    }
    if (!o->allow_set_file_size)
    {
        return STATUS_ACCESS_DENIED;
    }
    if (o->file == INVALID_HANDLE_VALUE)
    {
        return STATUS_UNSUCCESSFUL;
    }

#ifdef APFSACCESS_HAS_RW_ENGINE
    if (IsNativeWriteEnabled(c) &&
        !RecordNativeMutationBestEffort(
            c,
            apfsaccess::rw::MetadataStore::MutationOperation::SetFileSize,
            o->node->path,
            L"",
            0,
            size))
    {
        return BlockNativeMutationAfterStagingFailure(c, L"SetFileSize");
    }
#endif

    LARGE_INTEGER target{};
    target.QuadPart = size;
    if (!SetFilePointerEx(o->file, target, nullptr, FILE_BEGIN) || !SetEndOfFile(o->file))
    {
#ifdef APFSACCESS_HAS_RW_ENGINE
        if (IsNativeWriteEnabled(c))
        {
            (void)BlockNativeMutationAfterStagingFailure(c, L"SetFileSize");
        }
#endif
        return STATUS_UNSUCCESSFUL;
    }

    {
        std::lock_guard<std::mutex> lock(c->mutex);
        o->node->file_size = size;
        o->node->timestamp = UtcNow();
        FillInfo(*o->node, !IsMutationWriteEnabled(c), info);
    }
#ifdef APFSACCESS_HAS_RW_ENGINE
    RecordMutationBestEffort(
        c,
        apfsaccess::rw::TransactionManager::MutationKind::SetFileSize,
        o->node->path,
        L"",
        0,
        size);
    const auto native_commit_status = CommitNativeMutationsBestEffort(c, L"SetFileSize");
    if (!NT_SUCCESS(native_commit_status))
    {
        return native_commit_status;
    }
    FinalizeMutationJournalBestEffort(c, L"SetFileSize");
#endif
    return STATUS_SUCCESS;
}

NTSTATUS CB_CanDelete(FSP_FILE_SYSTEM* fs, PVOID ctx, PWSTR file_name)
{
    auto* c = Ctx(fs);
    if (!c)
    {
        return STATUS_INVALID_PARAMETER;
    }
    ExternalMutationRequestScope mutation_request_scope(c);
    if (!mutation_request_scope.Acquired())
    {
        return STATUS_VOLUME_DISMOUNTED;
    }
    MutationCallbackScope mutation_scope(c);
    if (!IsMutationWriteEnabled(c))
    {
        return HandleMutationWriteDisabled(c, L"CanDelete");
    }

    auto* o = (OpenContext*)ctx;
    std::wstring target = NormalizePath(file_name ? std::wstring(file_name) : (o && o->node ? o->node->path : L"\\"));
    if (o && !HasDeletePermissionForTarget(o, target))
    {
        return STATUS_ACCESS_DENIED;
    }
    auto node = FindNode(c, target);
    if (!node)
    {
        std::lock_guard<std::mutex> lock(c->mutex);
        auto hidden = TryGetNodeLocked(c, target);
        if ((hidden && IsDeleteBlockedStateLocked(hidden)) || HasDeletePendingAncestorLocked(c, target))
        {
            return STATUS_DELETE_PENDING;
        }
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    if (IsDeleteBlockedStateLocked(node))
    {
        return STATUS_DELETE_PENDING;
    }
    if (node->is_directory && !EnsureDirectoryLoaded(c, node))
    {
        return STATUS_UNSUCCESSFUL;
    }

    std::lock_guard<std::mutex> lock(c->mutex);
    auto locked = TryGetNodeLocked(c, target);
    if (!locked)
    {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    return ValidateDeleteEligibilityLocked(c, locked, o);
}

NTSTATUS CB_SetDelete(FSP_FILE_SYSTEM* fs, PVOID ctx, PWSTR file_name, BOOLEAN delete_file)
{
    auto* c = Ctx(fs);
    auto* o = (OpenContext*)ctx;
    if (!c)
    {
        return STATUS_INVALID_PARAMETER;
    }
    ExternalMutationRequestScope mutation_request_scope(c);
    if (!mutation_request_scope.Acquired())
    {
        return STATUS_VOLUME_DISMOUNTED;
    }
    MutationCallbackScope mutation_scope(c);
    if (!IsMutationWriteEnabled(c))
    {
        return HandleMutationWriteDisabled(c, L"SetDelete");
    }

    std::wstring target = NormalizePath(file_name ? std::wstring(file_name) : (o && o->node ? o->node->path : L"\\"));
    if (!delete_file && o && o->node && Key(o->node->path) == Key(target))
    {
        std::lock_guard<std::mutex> lock(c->mutex);
        auto locked = TryGetNodeLocked(c, target);
        if (!locked)
        {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
        if (locked != o->node)
        {
            return STATUS_INVALID_PARAMETER;
        }
        SetDeleteIntentLocked(c, o, false);
        return STATUS_SUCCESS;
    }

    auto node = FindNode(c, target);
    if (!node && o && o->node && Key(o->node->path) == Key(target))
    {
        node = o->node;
    }
    if (!node)
    {
        std::lock_guard<std::mutex> lock(c->mutex);
        auto hidden = TryGetNodeLocked(c, target);
        if ((hidden && IsDeleteBlockedStateLocked(hidden)) || HasDeletePendingAncestorLocked(c, target))
        {
            return STATUS_DELETE_PENDING;
        }
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    if (node->is_directory && !EnsureDirectoryLoaded(c, node))
    {
        return STATUS_UNSUCCESSFUL;
    }

    std::lock_guard<std::mutex> lock(c->mutex);
    auto locked = TryGetNodeLocked(c, target);
    if (!locked)
    {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    if (o && o->node != locked)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (delete_file)
    {
        if (!o || !o->allow_delete)
        {
            return STATUS_ACCESS_DENIED;
        }
        const auto status = ValidateDeleteEligibilityLocked(c, locked, o);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        SetDeleteIntentLocked(c, o, true);
    }
    else if (o)
    {
        SetDeleteIntentLocked(c, o, false);
    }

    return STATUS_SUCCESS;
}

NTSTATUS CB_Rename(FSP_FILE_SYSTEM* fs, PVOID ctx, PWSTR old_name, PWSTR new_name, BOOLEAN replace_if_exists)
{
    auto* c = Ctx(fs);
    if (!c || !old_name || !new_name)
    {
        return STATUS_INVALID_PARAMETER;
    }
    ExternalMutationRequestScope mutation_request_scope(c);
    if (!mutation_request_scope.Acquired())
    {
        return STATUS_VOLUME_DISMOUNTED;
    }
    MutationCallbackScope mutation_scope(c);
    if (!IsMutationWriteEnabled(c))
    {
        return HandleMutationWriteDisabled(c, L"Rename");
    }

    auto old_path = NormalizePath(old_name);
    auto new_path = NormalizeRenameTargetPath(old_path, new_name);
    if (old_path == L"\\" || new_path == L"\\")
    {
        return STATUS_ACCESS_DENIED;
    }
    auto* current_open = (OpenContext*)ctx;
    if (old_path == new_path)
    {
        std::lock_guard<std::mutex> lock(c->mutex);
        if (HasDeletePendingAncestorLocked(c, old_path))
        {
            return STATUS_DELETE_PENDING;
        }

        auto existing = TryGetNodeLocked(c, old_path);
        if (!existing)
        {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
        if (IsDeleteBlockedStateLocked(existing))
        {
            return STATUS_DELETE_PENDING;
        }

        const auto old_parent_path = Parent(old_path);
        const bool has_open_context = current_open && current_open->node;
        const bool context_is_source = has_open_context && current_open->node == existing;
        const bool context_is_old_parent =
            has_open_context &&
            current_open->node->is_directory &&
            Key(current_open->node->path) == Key(old_parent_path);
        if (has_open_context && !context_is_source && !context_is_old_parent)
        {
            return STATUS_INVALID_PARAMETER;
        }
        if (context_is_source && !current_open->allow_delete)
        {
            return STATUS_ACCESS_DENIED;
        }
        if (context_is_old_parent && !current_open->allow_delete_child)
        {
            return STATUS_ACCESS_DENIED;
        }

        return STATUS_SUCCESS;
    }
    {
        std::lock_guard<std::mutex> lock(c->mutex);
        if (HasDeletePendingAncestorLocked(c, old_path) || HasDeletePendingAncestorLocked(c, new_path))
        {
            return STATUS_DELETE_PENDING;
        }

        auto old_hidden = TryGetNodeLocked(c, old_path);
        if (IsDeleteBlockedStateLocked(old_hidden))
        {
            return STATUS_DELETE_PENDING;
        }

        auto new_hidden = TryGetNodeLocked(c, new_path);
        if (IsDeleteBlockedStateLocked(new_hidden))
        {
            return STATUS_DELETE_PENDING;
        }
    }
    if (!EnsureParentDirectoryLoaded(c, old_path) || !EnsureParentDirectoryLoaded(c, new_path))
    {
        return STATUS_OBJECT_PATH_NOT_FOUND;
    }

    auto existing_before_lock = FindNode(c, new_path);
    if (existing_before_lock && existing_before_lock->is_directory && !EnsureDirectoryLoaded(c, existing_before_lock))
    {
        return STATUS_UNSUCCESSFUL;
    }

    auto old_parent_path = Parent(old_path);
    auto new_parent_path = Parent(new_path);
    auto old_leaf = old_path.substr(old_path.find_last_of(L'\\') + 1);
    auto new_leaf = new_path.substr(new_path.find_last_of(L'\\') + 1);

    {
        std::lock_guard<std::mutex> lock(c->mutex);
        auto node = TryGetNodeLocked(c, old_path);
        if (!node)
        {
            node = current_open ? current_open->node : nullptr;
        }
        if (!node)
        {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
        if (Key(node->path) != Key(old_path))
        {
            // Prevent stale source-handle fallback from renaming an unrelated node.
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
        const bool has_open_context = current_open && current_open->node;
        const bool context_is_source = has_open_context && current_open->node == node;
        const bool context_is_old_parent =
            has_open_context &&
            current_open->node->is_directory &&
            Key(current_open->node->path) == Key(old_parent_path);
        const bool context_is_new_parent =
            has_open_context &&
            current_open->node->is_directory &&
            Key(current_open->node->path) == Key(new_parent_path);

        if (has_open_context &&
            !context_is_source &&
            !context_is_old_parent &&
            !context_is_new_parent)
        {
            return STATUS_INVALID_PARAMETER;
        }

        if (context_is_source)
        {
            if (!current_open->allow_delete)
            {
                return STATUS_ACCESS_DENIED;
            }
        }
        else if (context_is_old_parent)
        {
            if (!current_open->allow_delete_child)
            {
                return STATUS_ACCESS_DENIED;
            }
            if (!context_is_new_parent)
            {
                return STATUS_ACCESS_DENIED;
            }
            if (!HasDirectoryInsertPermission(current_open, node->is_directory))
            {
                return STATUS_ACCESS_DENIED;
            }
        }
        else if (context_is_new_parent)
        {
            if (!HasDirectoryInsertPermission(current_open, node->is_directory))
            {
                return STATUS_ACCESS_DENIED;
            }
            if (replace_if_exists && !current_open->allow_delete_child)
            {
                return STATUS_ACCESS_DENIED;
            }
        }
        if (IsDeleteBlockedStateLocked(node))
        {
            return STATUS_DELETE_PENDING;
        }
        if (node->path == L"\\")
        {
            return STATUS_ACCESS_DENIED;
        }
        if (node->is_directory &&
            (Key(new_parent_path) == Key(old_path) || IsDescendantPath(new_parent_path, old_path)))
        {
            return STATUS_ACCESS_DENIED;
        }
        if (HasRenameOpenHandleConflictLocked(c, node, current_open))
        {
            return STATUS_SHARING_VIOLATION;
        }

        auto old_parent = TryGetNodeLocked(c, old_parent_path);
        auto new_parent = TryGetNodeLocked(c, new_parent_path);
        if (!old_parent || !new_parent || !old_parent->is_directory || !new_parent->is_directory)
        {
            return STATUS_OBJECT_PATH_NOT_FOUND;
        }
        if (IsDeleteBlockedStateLocked(old_parent) || IsDeleteBlockedStateLocked(new_parent))
        {
            return STATUS_DELETE_PENDING;
        }

        auto existing = TryGetNodeLocked(c, new_path);
        if (existing && existing != node)
        {
            if (has_open_context)
            {
                const bool can_replace_with_context =
                    context_is_new_parent &&
                    current_open->allow_delete_child &&
                    IsDirectChildPath(current_open->node->path, new_path);
                if (!can_replace_with_context)
                {
                    return STATUS_ACCESS_DENIED;
                }
            }
            if (IsDeleteBlockedStateLocked(existing))
            {
                return STATUS_DELETE_PENDING;
            }
            if (!replace_if_exists)
            {
                return STATUS_OBJECT_NAME_COLLISION;
            }
            if (existing->is_directory != node->is_directory)
            {
                return STATUS_ACCESS_DENIED;
            }
            if (existing->is_directory && !existing->loaded)
            {
                return STATUS_UNSUCCESSFUL;
            }
            if (existing->is_directory && !existing->children.empty())
            {
                return STATUS_DIRECTORY_NOT_EMPTY;
            }
            if (existing->is_directory && !CanRemoveNodeRecursiveLocked(c, existing))
            {
                return STATUS_SHARING_VIOLATION;
            }
        }

#ifdef APFSACCESS_HAS_RW_ENGINE
        if (IsNativeWriteEnabled(c) &&
            !RecordNativeMutationBestEffort(
                c,
                apfsaccess::rw::MetadataStore::MutationOperation::Rename,
                old_path,
                new_path,
                0,
                0,
                replace_if_exists != FALSE))
        {
            return BlockNativeMutationAfterStagingFailure(c, L"Rename");
        }
#endif

        if (existing && existing != node)
        {
            RemoveNodeRecursiveLocked(c, existing);
            RemoveChildName(new_parent->children, new_leaf);
        }

        RemoveChildName(old_parent->children, old_leaf);
        AddChildName(new_parent->children, new_leaf);
        ReindexNodePathsLocked(c, node, old_path, new_path);
        node->timestamp = UtcNow();
    }
#ifdef APFSACCESS_HAS_RW_ENGINE
    RecordMutationBestEffort(
        c,
        apfsaccess::rw::TransactionManager::MutationKind::Rename,
        old_path,
        new_path,
        0,
        0,
        replace_if_exists != FALSE);
    const auto native_commit_status = CommitNativeMutationsBestEffort(c, L"Rename");
    if (!NT_SUCCESS(native_commit_status))
    {
        return native_commit_status;
    }
    FinalizeMutationJournalBestEffort(c, L"Rename");
#endif
    return STATUS_SUCCESS;
}

NTSTATUS CB_SetSecurity(FSP_FILE_SYSTEM* fs, PVOID, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR)
{
    auto* c = Ctx(fs);
    if (!c)
    {
        return STATUS_INVALID_PARAMETER;
    }

    ExternalMutationRequestScope mutation_request_scope(c);
    if (!mutation_request_scope.Acquired())
    {
        return STATUS_VOLUME_DISMOUNTED;
    }

    if (!IsMutationWriteEnabled(c))
    {
        return HandleMutationWriteDisabled(c, L"SetSecurity");
    }

    // APFS Access does not persist Windows ACLs into APFS metadata. Treat ACL
    // writes as a supported no-op so common shell/Office workflows do not fall
    // back to read-only behavior after copying files onto the mount.
    return STATUS_SUCCESS;
}

VOID CB_Cleanup(FSP_FILE_SYSTEM* fs, PVOID ctx, PWSTR file_name, ULONG flags)
{
    auto* c = Ctx(fs);
    auto* o = (OpenContext*)ctx;
    if (!c || !o || !o->node)
    {
        return;
    }
    MutationCallbackScope mutation_scope(c);

    if (o->file != INVALID_HANDLE_VALUE)
    {
        CloseHandle(o->file);
        o->file = INVALID_HANDLE_VALUE;
    }

    {
        std::lock_guard<std::mutex> lock(c->mutex);
        ReleaseOpenContextAccountingLocked(c, o);
    }

    if ((flags & FspCleanupDelete) != 0 && IsMutationWriteEnabled(c))
    {
        if (c->shutdown_drain_active.load(std::memory_order_acquire))
        {
            return;
        }

        if (!o->allow_delete)
        {
            return;
        }

        auto path = NormalizePath(!o->node->path.empty() ? o->node->path : (file_name ? std::wstring(file_name) : L"\\"));
        if (path != L"\\" && EnsureParentDirectoryLoaded(c, path))
        {
            auto found = FindNode(c, path);
            if (!found)
            {
                return;
            }
            if (found->is_directory && !EnsureDirectoryLoaded(c, found))
            {
                return;
            }

            std::lock_guard<std::mutex> lock(c->mutex);
            auto node = TryGetNodeLocked(c, path);
            if (node)
            {
                if (IsDeleteBlockedStateLocked(node) && !o->delete_on_cleanup)
                {
                    return;
                }
                if (node->path == L"\\")
                {
                    return;
                }
                if (node->is_directory && !node->children.empty())
                {
                    return;
                }
                LatchDeleteOnCleanupLocked(c, o);
            }
        }
    }
}

VOID CB_Close(FSP_FILE_SYSTEM* fs, PVOID ctx)
{
    auto* c = Ctx(fs);
    auto* o = (OpenContext*)ctx;
    if (!o)
    {
        return;
    }
    MutationCallbackScope mutation_scope(c);
    if (o->file != INVALID_HANDLE_VALUE)
    {
        CloseHandle(o->file);
        o->file = INVALID_HANDLE_VALUE;
    }

    bool emit_delete_mutation = false;
    bool had_delete_on_cleanup = false;
    std::wstring deleted_path;
    if (c && o->node)
    {
        std::lock_guard<std::mutex> lock(c->mutex);
        const bool remove_requested_on_close = o->delete_on_cleanup || o->node->delete_latched;
        if (o->delete_on_cleanup)
        {
            had_delete_on_cleanup = true;
            if (o->node->delete_intent_count > 0)
            {
                --o->node->delete_intent_count;
            }
            o->delete_on_cleanup = false;
        }
        ReleaseOpenContextAccountingLocked(c, o);
        RefreshDeletePendingStateLocked(c, o->node);

        const bool can_remove_now = o->node->path != L"\\" &&
            CanRemoveNodeRecursiveLocked(c, o->node);
        if (remove_requested_on_close && can_remove_now)
        {
            deleted_path = o->node->path;
#ifdef APFSACCESS_HAS_RW_ENGINE
            bool native_delete_staged = true;
            if (IsNativeWriteEnabled(c))
            {
                native_delete_staged = RecordNativeMutationBestEffort(
                    c,
                    apfsaccess::rw::MetadataStore::MutationOperation::Delete,
                    deleted_path);
            }
            if (!native_delete_staged)
            {
                (void)BlockNativeMutationAfterStagingFailure(c, L"Delete");
                o->node->delete_latched = false;
                o->node->delete_pending = false;
                RefreshDeletePendingStateLocked(c, o->node);
            }
            else
#endif
            {
            auto parent_path = Parent(deleted_path);
            auto leaf = deleted_path.substr(deleted_path.find_last_of(L'\\') + 1);
            auto parent = TryGetNodeLocked(c, parent_path);
            if (parent && parent->is_directory)
            {
                RemoveChildName(parent->children, leaf);
            }
            emit_delete_mutation = RemoveNodeRecursiveLocked(c, o->node);
            if (emit_delete_mutation)
            {
                o->node->delete_latched = false;
                o->node->delete_pending = false;
                o->node->delete_intent_count = 0;
            }
            }
        }
    }

#ifdef APFSACCESS_HAS_RW_ENGINE
    if (emit_delete_mutation && c && IsMutationWriteEnabled(c))
    {
        RecordMutationBestEffort(
            c,
            apfsaccess::rw::TransactionManager::MutationKind::Delete,
            deleted_path);
    }

    if (c && IsMutationWriteEnabled(c) && emit_delete_mutation)
    {
        const auto close_commit_status = CommitNativeMutationsBestEffort(c, L"Close");
        if (!NT_SUCCESS(close_commit_status))
        {
            std::wcerr << L"[FsHost] RW native-commit warning (Close): finalize-on-close commit failed with status 0x"
                << std::hex << static_cast<unsigned long>(close_commit_status) << std::dec
                << L"." << std::endl;
        }
        FinalizeMutationJournalBestEffort(c, L"Close");
    }
#endif
    delete o;
}

NTSTATUS CB_Read(FSP_FILE_SYSTEM* fs, PVOID ctx, PVOID buf, UINT64 off, ULONG len, PULONG done)
{
    auto* c = Ctx(fs);
    auto* o = (OpenContext*)ctx;
    if (!o || !o->node || o->node->is_directory || !buf || !done)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (!o->allow_read_data)
    {
        return STATUS_ACCESS_DENIED;
    }

    if (o->file != INVALID_HANDLE_VALUE)
    {
        OVERLAPPED ov{}; ov.Offset = (DWORD)(off & 0xffffffffull); ov.OffsetHigh = (DWORD)(off >> 32);
        DWORD read = 0;
        if (!ReadFile(o->file, buf, len, &read, &ov))
        {
            auto e = GetLastError();
            *done = 0;
            if (e == ERROR_HANDLE_EOF)
            {
                return STATUS_SUCCESS;
            }
            return STATUS_UNSUCCESSFUL;
        }
        *done = read;
        return STATUS_SUCCESS;
    }

#ifdef APFSACCESS_HAS_RW_ENGINE
    if (o->metadata_read_fallback && c && c->metadata_store)
    {
        std::vector<std::byte> payload;
        bool read_ok = false;
        {
            std::lock_guard<std::mutex> metadata_lock(c->metadata_mutex);
            read_ok = c->metadata_store->ReadCommittedFileRange(
                o->node->path,
                off,
                static_cast<std::size_t>(len),
                payload);
        }

        if (!read_ok)
        {
            *done = 0;
            return STATUS_UNSUCCESSFUL;
        }

        if (!payload.empty())
        {
            std::memcpy(buf, payload.data(), payload.size());
        }
        *done = static_cast<ULONG>(payload.size());
        return STATUS_SUCCESS;
    }
#endif

    *done = 0;
    return STATUS_INVALID_PARAMETER;
}

NTSTATUS CB_GetFileInfo(FSP_FILE_SYSTEM* fs, PVOID ctx, FSP_FSCTL_FILE_INFO* info)
{
    auto* c = Ctx(fs);
    auto* o = (OpenContext*)ctx;
    if (!c || !o || !o->node || !info) return STATUS_INVALID_PARAMETER;
    FillInfo(*o->node, !IsMutationWriteEnabled(c), info);
    return STATUS_SUCCESS;
}

NTSTATUS CB_Flush(FSP_FILE_SYSTEM* fs, PVOID ctx, FSP_FSCTL_FILE_INFO* info)
{
    auto* c = Ctx(fs);
    auto* o = (OpenContext*)ctx;
    if (!o) return STATUS_SUCCESS;
    if (!c || !o->node || !info) return STATUS_INVALID_PARAMETER;
    MutationCallbackScope mutation_scope(c);
    std::optional<ExternalMutationRequestScope> mutation_request_scope;
    if (IsMutationWriteEnabled(c))
    {
        mutation_request_scope.emplace(c);
        if (!mutation_request_scope->Acquired())
        {
            return STATUS_VOLUME_DISMOUNTED;
        }
    }

    FillInfo(*o->node, !IsMutationWriteEnabled(c), info);
    return STATUS_SUCCESS;
}

NTSTATUS CB_GetSecurityByName(FSP_FILE_SYSTEM* fs, PWSTR file_name, PUINT32 attrs, PSECURITY_DESCRIPTOR sd, SIZE_T* sz)
{
    auto* c = Ctx(fs);
    if (!c || !sz) return STATUS_INVALID_PARAMETER;
    auto p = NormalizePath(file_name ? std::wstring(file_name) : L"\\");
    auto n = FindNode(c, p);
    if (!n)
    {
        std::lock_guard<std::mutex> lock(c->mutex);
        auto hidden = TryGetNodeLocked(c, p);
        if ((hidden && IsDeleteBlockedStateLocked(hidden)) || HasDeletePendingAncestorLocked(c, p))
        {
            return STATUS_DELETE_PENDING;
        }
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    if (attrs)
    {
        *attrs = BuildFileAttributes(*n, !IsMutationWriteEnabled(c));
    }
    if (!sd || *sz < c->sd_size) { *sz = c->sd_size; return STATUS_BUFFER_OVERFLOW; }
    std::memcpy(sd, c->sd, c->sd_size);
    *sz = c->sd_size;
    return STATUS_SUCCESS;
}

NTSTATUS CB_GetSecurity(FSP_FILE_SYSTEM* fs, PVOID, PSECURITY_DESCRIPTOR sd, SIZE_T* sz)
{
    auto* c = Ctx(fs);
    if (!c || !sz) return STATUS_INVALID_PARAMETER;
    if (!sd || *sz < c->sd_size) { *sz = c->sd_size; return STATUS_BUFFER_OVERFLOW; }
    std::memcpy(sd, c->sd, c->sd_size);
    *sz = c->sd_size;
    return STATUS_SUCCESS;
}

NTSTATUS CB_Open(FSP_FILE_SYSTEM* fs, PWSTR file_name, UINT32 create_options, UINT32 granted_access, PVOID* out_ctx, FSP_FSCTL_FILE_INFO* info)
{
    auto* c = Ctx(fs);
    if (!c || !out_ctx || !info)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (HasConflictingCreateTypeOptions(create_options))
    {
        return STATUS_INVALID_PARAMETER;
    }

    auto p = NormalizePath(file_name ? std::wstring(file_name) : L"\\");
    auto n = FindNode(c, p);
    if (!n)
    {
        std::lock_guard<std::mutex> lock(c->mutex);
        auto hidden = TryGetNodeLocked(c, p);
        if ((hidden && IsDeleteBlockedStateLocked(hidden)) || HasDeletePendingAncestorLocked(c, p))
        {
            return STATUS_DELETE_PENDING;
        }
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    if (IsDeleteBlockedStateLocked(n))
    {
        return STATUS_DELETE_PENDING;
    }

    if (n->is_directory && (create_options & FILE_NON_DIRECTORY_FILE) != 0)
    {
        return STATUS_FILE_IS_A_DIRECTORY;
    }
    if (!n->is_directory && (create_options & FILE_DIRECTORY_FILE) != 0)
    {
        return STATUS_NOT_A_DIRECTORY;
    }

    const auto mutation_enabled = IsMutationWriteEnabled(c);
    const auto mutation_access_requested = HasOpenMutationIntent(granted_access, create_options);
    std::optional<ExternalMutationRequestScope> mutation_request_scope;
    if (mutation_access_requested)
    {
        mutation_request_scope.emplace(c);
        if (!mutation_request_scope->Acquired())
        {
            return STATUS_VOLUME_DISMOUNTED;
        }
    }

    if (!mutation_enabled && mutation_access_requested)
    {
        return HandleMutationWriteDisabled(c, L"Open");
    }

    auto* o = new (std::nothrow) OpenContext();
    if (!o)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    o->node = n;
    InitializeOpenAccess(o, granted_access);
    if (!n->is_directory)
    {
        const auto desired_access = ResolveHydrationDesiredAccess(
            mutation_enabled,
            granted_access,
            false);
        o->write_open = mutation_enabled && mutation_access_requested;

        if (EnsureHydrated(c, n, false))
        {
            auto pth = HydrationPath(c, *n);
            o->file = CreateFileW(
                pth.wstring().c_str(),
                desired_access,
                ResolveHydrationShareMode(mutation_enabled, granted_access, o->write_open),
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                nullptr);
        }

        if (o->file == INVALID_HANDLE_VALUE && !mutation_enabled)
        {
#ifdef APFSACCESS_HAS_RW_ENGINE
            bool can_read_from_metadata = false;
            if (c->metadata_store)
            {
                std::vector<std::byte> probe_bytes;
                {
                    std::lock_guard<std::mutex> metadata_lock(c->metadata_mutex);
                    can_read_from_metadata = c->metadata_store->ReadCommittedFileRange(
                        n->path,
                        0,
                        static_cast<std::size_t>(0),
                        probe_bytes);
                }
            }

            if (can_read_from_metadata)
            {
                o->metadata_read_fallback = true;
            }
            else
            {
                delete o;
                return STATUS_IO_DEVICE_ERROR;
            }
#else
            delete o;
            return STATUS_IO_DEVICE_ERROR;
#endif
        }
        else if (o->file == INVALID_HANDLE_VALUE)
        {
            delete o;
            return STATUS_IO_DEVICE_ERROR;
        }
    }

    {
        std::lock_guard<std::mutex> lock(c->mutex);
        ++n->open_handle_count;
        if (o->write_open)
        {
            ++n->write_handle_count;
        }
    }

    FillInfo(*n, !IsMutationWriteEnabled(c), info);
    *out_ctx = o;
    return STATUS_SUCCESS;
}

NTSTATUS CB_ReadDirectory(FSP_FILE_SYSTEM* fs, PVOID dir_ctx, PWSTR, PWSTR marker, PVOID buffer, ULONG length, PULONG done)
{
    auto* c = Ctx(fs);
    auto* o = (OpenContext*)dir_ctx;
    if (!c || !o || !o->node || !o->node->is_directory || !done)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (!o->allow_list_directory)
    {
        return STATUS_ACCESS_DENIED;
    }
    *done = 0;
    if (!EnsureDirectoryLoaded(c, o->node))
    {
        return STATUS_NO_SUCH_FILE;
    }

    struct DirectoryEntrySnapshot
    {
        std::wstring name;
        std::shared_ptr<Node> node;
    };

    std::vector<DirectoryEntrySnapshot> entries;
    {
        std::lock_guard<std::mutex> lock(c->mutex);
        entries.reserve(o->node->children.size());
        for (const auto& name : o->node->children)
        {
            auto child = TryGetNodeLocked(c, Join(o->node->path, name));
            if (child)
            {
                entries.push_back({ name, child });
            }
        }
    }

    auto mk = marker ? std::wstring(marker) : std::wstring();
    const auto read_only = !IsMutationWriteEnabled(c);
    auto start_it = entries.begin();
    if (!mk.empty())
    {
        start_it = std::lower_bound(entries.begin(), entries.end(), mk, [](const DirectoryEntrySnapshot& entry, const std::wstring& value)
        {
            return _wcsicmp(entry.name.c_str(), value.c_str()) < 0;
        });
        while (start_it != entries.end() && _wcsicmp(start_it->name.c_str(), mk.c_str()) <= 0)
        {
            ++start_it;
        }
    }

    for (auto it = start_it; it != entries.end(); ++it)
    {
        auto tmp = BuildDirectoryInfoBuffer(*it->node, it->name, read_only);
        if (tmp.empty())
        {
            continue;
        }
        auto* d = (FSP_FSCTL_DIR_INFO*)tmp.data();
        if (!c->api.AddDir(d, buffer, length, done))
        {
            return STATUS_SUCCESS;
        }
    }
    c->api.AddDir(nullptr, buffer, length, done);
    return STATUS_SUCCESS;
}

bool ParseArgs(int argc, wchar_t** argv, Arguments& a)
{
    for (int i = 1; i < argc; ++i)
    {
        auto* arg = argv[i];
        if (IsOption(arg, L"--device")) a.device = NextArgValue(i, argc, argv);
        else if (IsOption(arg, L"--volume")) a.volume = NextArgValue(i, argc, argv);
        else if (IsOption(arg, L"--mount")) a.mount = NextArgValue(i, argc, argv);
        else if (IsOption(arg, L"--lifetime-file")) a.lifetime_file = NextArgValue(i, argc, argv);
        else if (IsOption(arg, L"--status-file")) a.status_file = NextArgValue(i, argc, argv);
        else if (IsOption(arg, L"--device-offset")) { try { a.device_offset_bytes = static_cast<std::uint64_t>(std::stoull(NextArgValue(i, argc, argv))); } catch (...) { return false; } }
        else if (IsOption(arg, L"--readonly")) a.readonly = true;
        else if (IsOption(arg, L"--readwrite")) a.readwrite = true;
        else if (IsOption(arg, L"--write-safety-level")) a.write_safety_level = NextArgValue(i, argc, argv);
        else if (IsOption(arg, L"--write-backend")) a.write_backend = NextArgValue(i, argc, argv);
        else if (IsOption(arg, L"--write-commit-timeout")) { try { a.write_commit_timeout_seconds = std::max(1, std::stoi(NextArgValue(i, argc, argv))); } catch (...) { return false; } }
        else if (IsOption(arg, L"--write-max-dirty-transactions")) { try { a.write_max_dirty_transactions = std::max(1, std::stoi(NextArgValue(i, argc, argv))); } catch (...) { return false; } }
        else if (IsOption(arg, L"--write-recovery-policy")) a.write_recovery_policy = NextArgValue(i, argc, argv);
        else if (IsOption(arg, L"--write-crash-replay-mode")) a.write_crash_replay_mode = NextArgValue(i, argc, argv);
        else if (IsOption(arg, L"--write-require-canonical-commit")) a.write_require_canonical_commit = ParseBoolToken(NextArgValue(i, argc, argv), true);
        else if (IsOption(arg, L"--write-integrity-check-on-mount")) a.write_integrity_check_on_mount = ParseBoolToken(NextArgValue(i, argc, argv), true);
        else if (IsOption(arg, L"--allow-legacy-scaffold-for-fixtures")) a.allow_legacy_scaffold_for_fixtures = ParseBoolToken(NextArgValue(i, argc, argv), true);
        else if (IsOption(arg, L"--write-disallow-scaffold-commit-on-non-fixture")) a.write_disallow_scaffold_commit_on_non_fixture = ParseBoolToken(NextArgValue(i, argc, argv), true);
        else if (IsOption(arg, L"--write-reject-scaffold-replay-blob-on-non-fixture")) a.write_reject_scaffold_replay_blob_on_non_fixture = ParseBoolToken(NextArgValue(i, argc, argv), true);
        else if (IsOption(arg, L"--write-require-canonical-replay-candidate-on-non-fixture")) a.write_require_canonical_replay_candidate_on_non_fixture = ParseBoolToken(NextArgValue(i, argc, argv), true);
        else if (IsOption(arg, L"--validation-crash-fault-passes")) { try { a.validation_crash_fault_passes = std::max(0, std::stoi(NextArgValue(i, argc, argv))); } catch (...) { return false; } }
        else if (IsOption(arg, L"--validation-crash-stage-matrix-passes")) { try { a.validation_crash_stage_matrix_passes = std::max(0, std::stoi(NextArgValue(i, argc, argv))); } catch (...) { return false; } }
        else if (IsOption(arg, L"--validation-hardware-pilot-passes")) { try { a.validation_hardware_pilot_passes = std::max(0, std::stoi(NextArgValue(i, argc, argv))); } catch (...) { return false; } }
        else if (IsOption(arg, L"--validation-hot-unplug-passes")) { try { a.validation_hot_unplug_passes = std::max(0, std::stoi(NextArgValue(i, argc, argv))); } catch (...) { return false; } }
        else if (IsOption(arg, L"--validation-macos-validation-passes")) { try { a.validation_macos_validation_passes = std::max(0, std::stoi(NextArgValue(i, argc, argv))); } catch (...) { return false; } }
        else if (IsOption(arg, L"--validation-macos-consistency-passes")) { try { a.validation_macos_consistency_passes = std::max(0, std::stoi(NextArgValue(i, argc, argv))); } catch (...) { return false; } }
        else if (IsOption(arg, L"--validation-power-loss-replay-passes")) { try { a.validation_power_loss_replay_passes = std::max(0, std::stoi(NextArgValue(i, argc, argv))); } catch (...) { return false; } }
        else if (IsOption(arg, L"--validation-power-loss-pass-verified")) a.validation_power_loss_pass_verified = ParseBoolToken(NextArgValue(i, argc, argv), true);
        else if (IsOption(arg, L"--validation-last-validated-utc")) a.validation_last_validated_utc = NextArgValue(i, argc, argv);
        else if (IsOption(arg, L"--validation-last-profile-id")) a.validation_last_profile_id = NextArgValue(i, argc, argv);
        else if (IsOption(arg, L"--allow-raw-physical-write")) a.allow_raw_physical_write = true;
    }
    if (!a.mount.empty() && a.mount.size() >= 2 && a.mount[1] == L':') a.mount = std::wstring(1, (wchar_t)towupper(a.mount[0])) + L":";
    bool has_mode = a.readonly || a.readwrite;
    return !a.device.empty() && !a.volume.empty() && !a.mount.empty() && has_mode && !(a.readonly && a.readwrite);
}

bool IsDriveLetterMountPoint(const std::wstring& mount)
{
    return mount.size() == 2 &&
           mount[1] == L':' &&
           std::iswalpha(mount[0]) != 0;
}

std::wstring BuildWinFspMountPoint(const std::wstring& mount)
{
    if (IsDriveLetterMountPoint(mount))
    {
        // A plain "X:" mount created by an elevated process is local to that
        // elevated logon namespace. Use Mount Manager syntax so normal Explorer
        // windows see the drive under This PC.
        return L"\\\\.\\" + std::wstring(1, static_cast<wchar_t>(std::towupper(mount[0]))) + L":";
    }

    return mount;
}

void NotifyShellDriveAdded(const std::wstring& mount)
{
    if (!IsDriveLetterMountPoint(mount))
    {
        return;
    }

    const auto letter_index = static_cast<unsigned int>(std::towupper(mount[0]) - L'A');
    if (letter_index >= 26)
    {
        return;
    }

    const ULONG_PTR drive_mask = static_cast<ULONG_PTR>(1) << letter_index;
    const std::wstring root_path = std::wstring(1, static_cast<wchar_t>(std::towupper(mount[0]))) + L":\\";
    SHChangeNotify(SHCNE_DRIVEADD, SHCNF_DWORD, reinterpret_cast<LPCVOID>(drive_mask), nullptr);
    SHChangeNotify(SHCNE_DRIVEADDGUI, SHCNF_DWORD, reinterpret_cast<LPCVOID>(drive_mask), nullptr);
    SHChangeNotify(SHCNE_MEDIAINSERTED, SHCNF_DWORD, reinterpret_cast<LPCVOID>(drive_mask), nullptr);
    SHChangeNotify(SHCNE_FREESPACE, SHCNF_DWORD, reinterpret_cast<LPCVOID>(drive_mask), nullptr);
    SHChangeNotify(SHCNE_UPDATEDIR, SHCNF_PATHW | SHCNF_FLUSHNOWAIT, root_path.c_str(), nullptr);
    SHChangeNotify(SHCNE_UPDATEITEM, SHCNF_PATHW | SHCNF_FLUSH, root_path.c_str(), nullptr);
    SHChangeNotify(SHCNE_FREESPACE, SHCNF_DWORD | SHCNF_FLUSH, reinterpret_cast<LPCVOID>(drive_mask), nullptr);
    SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nullptr, nullptr);
    SHChangeNotify(SHCNE_UPDATEDIR, SHCNF_PATHW | SHCNF_FLUSH, L"::{20D04FE0-3AEA-1069-A2D8-08002B30309D}", nullptr);
}

void NotifyShellDriveRemoved(const std::wstring& mount)
{
    if (!IsDriveLetterMountPoint(mount))
    {
        return;
    }

    const auto letter_index = static_cast<unsigned int>(std::towupper(mount[0]) - L'A');
    if (letter_index >= 26)
    {
        return;
    }

    const ULONG_PTR drive_mask = static_cast<ULONG_PTR>(1) << letter_index;
    const std::wstring root_path = std::wstring(1, static_cast<wchar_t>(std::towupper(mount[0]))) + L":\\";
    SHChangeNotify(SHCNE_MEDIAREMOVED, SHCNF_DWORD, reinterpret_cast<LPCVOID>(drive_mask), nullptr);
    SHChangeNotify(SHCNE_DRIVEREMOVED, SHCNF_DWORD | SHCNF_FLUSH, reinterpret_cast<LPCVOID>(drive_mask), nullptr);
    SHChangeNotify(SHCNE_UPDATEDIR, SHCNF_PATHW | SHCNF_FLUSH, root_path.c_str(), nullptr);
    SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nullptr, nullptr);
    SHChangeNotify(SHCNE_UPDATEDIR, SHCNF_PATHW | SHCNF_FLUSH, L"::{20D04FE0-3AEA-1069-A2D8-08002B30309D}", nullptr);
}

#ifdef APFSACCESS_HAS_RW_ENGINE
std::optional<std::uint64_t> ResolveCleanRecoveryCheckpointXid(
    std::optional<std::uint64_t> committed_xid,
    std::optional<std::uint64_t> checkpoint_xid)
{
    if (committed_xid.has_value() && checkpoint_xid.has_value())
    {
        return std::max(committed_xid.value(), checkpoint_xid.value());
    }

    if (committed_xid.has_value())
    {
        return committed_xid;
    }

    return checkpoint_xid;
}

std::optional<std::uint64_t> ResolveCleanRecoveryCheckpointXid(
    const apfsaccess::rw::MetadataStore& metadata_store)
{
    return ResolveCleanRecoveryCheckpointXid(
        metadata_store.LastCommittedXid(),
        metadata_store.CheckpointXid());
}

void ClearRecoveredMarkerIfClean(MountContext& ctx, const std::wstring& action)
{
    if (!ctx.pending_native_writes || !ctx.metadata_store)
    {
        return;
    }

    if (ctx.metadata_store->IsRecoveryRequired())
    {
        return;
    }

    auto committed_xid = ResolveCleanRecoveryCheckpointXid(*ctx.metadata_store);
    if (!committed_xid.has_value())
    {
        return;
    }

    if (ctx.runtime_last_commit_xid.has_value() &&
        ctx.runtime_last_commit_xid.value() > committed_xid.value())
    {
        return;
    }

    ctx.pending_native_writes = false;
    ctx.recovery_active = false;
    ctx.write_degraded = false;
    ctx.runtime_recovery_reason.clear();
    ctx.runtime_last_recovery_action = action;
    ctx.runtime_last_commit_xid = committed_xid;
    if (ctx.args.readwrite && IsWriteBackendMode(ctx.args.write_backend, L"Native"))
    {
        ctx.native_write_enabled = true;
        ctx.overlay_write_enabled = false;
    }

    (void)UpdateRecoveryMarkerBestEffort(&ctx, false);
    std::wcerr << L"[FsHost] Recovery marker reconciled against APFS checkpoint xid "
        << committed_xid.value()
        << L"; native write path may proceed."
        << std::endl;
}

void RefreshReportedVolumeInfoFromMetadata(MountContext& ctx)
{
    std::lock_guard<std::mutex> metadata_lock(ctx.metadata_mutex);
    if (!ctx.metadata_store)
    {
        return;
    }

    if (const auto block_size = ctx.metadata_store->BlockSizeBytes();
        block_size.has_value() && block_size.value() != 0)
    {
        ctx.reported_allocation_unit_bytes = block_size.value();
    }
    if (const auto total_size = ctx.metadata_store->TotalSizeBytes();
        total_size.has_value())
    {
        ctx.reported_total_size_bytes = total_size;
    }
    if (const auto free_size = ctx.metadata_store->FreeSizeBytes();
        free_size.has_value())
    {
        ctx.reported_free_size_bytes = free_size;
    }
}
#endif

void PrintUsage()
{
    std::wcerr << L"Usage: ApfsAccess.FsHost --device <path> [--device-offset <bytes>] --volume <name-or-id> --mount <X:> (--readonly|--readwrite) [--lifetime-file <file>] [--status-file <file>] [--write-backend <Disabled|Overlay|Native>] [--write-safety-level <mode>] [--write-commit-timeout <seconds>] [--write-max-dirty-transactions <count>] [--write-recovery-policy <mode>] [--write-crash-replay-mode <FailClosed|ReplayIfSafe>] [--write-require-canonical-commit <true|false>] [--write-integrity-check-on-mount <true|false>] [--allow-legacy-scaffold-for-fixtures <true|false>] [--write-disallow-scaffold-commit-on-non-fixture <true|false>] [--write-reject-scaffold-replay-blob-on-non-fixture <true|false>] [--write-require-canonical-replay-candidate-on-non-fixture <true|false>] [--validation-crash-fault-passes <count>] [--validation-crash-stage-matrix-passes <count>] [--validation-hardware-pilot-passes <count>] [--validation-hot-unplug-passes <count>] [--validation-macos-validation-passes <count>] [--validation-macos-consistency-passes <count>] [--validation-power-loss-replay-passes <count>] [--validation-power-loss-pass-verified <true|false>] [--validation-last-validated-utc <iso-8601>] [--validation-last-profile-id <id>] [--allow-raw-physical-write]" << std::endl;
}

BOOL WINAPI CtrlHandler(DWORD type)
{
    switch (type)
    {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        g_exit.store(true);
        return TRUE;
    default:
        return FALSE;
    }
}
} // namespace

#ifndef APFSACCESS_FSHOST_UNIT_TEST
int wmain(int argc, wchar_t** argv)
{
    Arguments args;
    if (!ParseArgs(argc, argv, args))
    {
        PrintUsage();
        return 2;
    }
    ApplyNonFixtureCanonicalSafetyOverrides(args);
    if (args.readwrite &&
        !IsWriteBackendMode(args.write_backend, L"Overlay") &&
        !IsWriteBackendMode(args.write_backend, L"Native"))
    {
        std::wcerr << L"[FsHost] --readwrite requires --write-backend Overlay or Native in this build." << std::endl;
        return 6;
    }
#ifndef APFSACCESS_HAS_RW_ENGINE
    if (args.readwrite && IsWriteBackendMode(args.write_backend, L"Native"))
    {
        std::wcerr << L"[FsHost] Native write backend requires APFSACCESS_HAS_RW_ENGINE build support." << std::endl;
        return 6;
    }
#endif
    MountContext ctx{};
    ctx.args = args;
    if (!InitializeSessionPaths(&ctx))
    {
        std::wcerr << L"[FsHost] Unable to initialize host session cache paths." << std::endl;
        return 9;
    }
    ScopeExit session_cleanup
    {
        [&ctx]()
        {
            if (ctx.session_root.empty())
            {
                return;
            }

            std::error_code ec;
            std::filesystem::remove_all(ctx.session_root, ec);
        }
    };
    ctx.overlay_write_enabled = args.readwrite && IsWriteBackendMode(args.write_backend, L"Overlay");
    ctx.native_write_enabled = args.readwrite && IsWriteBackendMode(args.write_backend, L"Native");
    if (ctx.overlay_write_enabled)
    {
        std::wcerr << L"[FsHost] Experimental overlay write mode is active. Writes are not persisted to APFS media." << std::endl;
    }
    if (ctx.native_write_enabled)
    {
        std::wcerr << L"[FsHost] Experimental native write mode is active. APFS metadata mutation is still under active development." << std::endl;
    }
    if (args.readwrite)
    {
        std::wcerr << L"[FsHost] Write controls: safetyLevel=" << args.write_safety_level
            << L", commitTimeoutSec=" << args.write_commit_timeout_seconds
            << L", maxDirtyTransactions=" << args.write_max_dirty_transactions
            << L", recoveryPolicy=" << args.write_recovery_policy
            << L", crashReplayMode=" << args.write_crash_replay_mode
            << L", requireCanonicalCommit=" << (args.write_require_canonical_commit ? L"true" : L"false")
            << L", integrityCheckOnMount=" << (args.write_integrity_check_on_mount ? L"true" : L"false")
            << L", allowLegacyScaffoldForFixtures=" << (args.allow_legacy_scaffold_for_fixtures ? L"true" : L"false")
            << L", disallowScaffoldCommitOnNonFixture=" << (args.write_disallow_scaffold_commit_on_non_fixture ? L"true" : L"false")
            << L", rejectScaffoldReplayBlobOnNonFixture=" << (args.write_reject_scaffold_replay_blob_on_non_fixture ? L"true" : L"false")
            << L", requireCanonicalReplayCandidateOnNonFixture=" << (args.write_require_canonical_replay_candidate_on_non_fixture ? L"true" : L"false")
            << L", allowRawPhysicalWrite=" << (args.allow_raw_physical_write ? L"true" : L"false")
            << std::endl;
    }

#ifdef APFSACCESS_HAS_RW_ENGINE
    if (args.readwrite)
    {
        ctx.recovery_marker_file = BuildRecoveryMarkerPath(args);
        RecoveryMarkerState marker_state{};
        if (TryLoadRecoveryMarkerState(ctx.recovery_marker_file, marker_state))
        {
            ctx.pending_native_writes = marker_state.dirty;
            ctx.runtime_last_commit_xid = marker_state.last_commit_xid;
            ctx.last_recovery_marker_dirty = marker_state.dirty;
            ctx.last_recovery_marker_commit_xid = marker_state.last_commit_xid;

            if (marker_state.dirty)
            {
                ctx.recovery_active = true;
                ctx.runtime_recovery_reason = L"RecoveryMarkerDirty";
                ctx.runtime_last_recovery_action = L"RecoveryMarkerDetected";
                std::wcerr << L"[FsHost] Recovery marker detected: previous write session was not finalized cleanly." << std::endl;
                const auto replay_if_safe = IsCrashReplayModeReplayIfSafe(args.write_crash_replay_mode);
                if (ctx.native_write_enabled &&
                    IsRecoveryPolicyFailClosed(args.write_recovery_policy) &&
                    !replay_if_safe)
                {
                    ctx.write_degraded = true;
                    ctx.native_write_enabled = false;
                    ctx.overlay_write_enabled = false;
                    std::wcerr << L"[FsHost] Recovery policy is FailClosed; mounting in degraded read-only mode." << std::endl;
                }
                else if (ctx.native_write_enabled && replay_if_safe)
                {
                    std::wcerr << L"[FsHost] Recovery policy is FailClosed with ReplayIfSafe; native recovery will be attempted before write mode is downgraded." << std::endl;
                }
                else if (ctx.native_write_enabled)
                {
                    std::wcerr << L"[FsHost] Recovery policy is BestEffort; native write path remains enabled with recovery-active status." << std::endl;
                }
            }
        }
    }
#endif

    (void)WriteHostStatusFile(ctx, ctx.recovery_active, ctx.runtime_last_commit_xid);

#ifdef APFSACCESS_HAS_RW_ENGINE
    if (args.readwrite)
    {
        ctx.tx_manager = std::make_unique<apfsaccess::rw::TransactionManager>(args.write_safety_level);
        auto journal_root = std::filesystem::temp_directory_path() / "ApfsAccess" / "rw-journal";
        std::filesystem::create_directories(journal_root);
        const auto file_name = SanitizeFileComponent(args.volume) + L"_" + std::to_wstring(GetTickCount64()) + L".jsonl";
        ctx.tx_journal_file = journal_root / file_name;
        ctx.tx_manager->SetJournalPath(ctx.tx_journal_file.wstring());
        std::wcerr << L"[FsHost] RW journal path: " << ctx.tx_journal_file.wstring() << std::endl;
    }
#endif

#ifdef APFSACCESS_HAS_RW_ENGINE
    {
        apfsaccess::rw::MetadataStore::VolumeContext rw_context
        {
            args.device,
            args.volume,
            args.allow_raw_physical_write,
            args.write_integrity_check_on_mount,
            args.write_crash_replay_mode,
            args.allow_legacy_scaffold_for_fixtures,
            args.write_disallow_scaffold_commit_on_non_fixture,
            args.write_reject_scaffold_replay_blob_on_non_fixture,
            args.write_require_canonical_replay_candidate_on_non_fixture,
            args.device_offset_bytes
        };
        ctx.metadata_store = std::make_unique<apfsaccess::rw::MetadataStore>(std::move(rw_context));
        ctx.metadata_store->SetFilePayloadProvider(
            [&ctx](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                // Commit callbacks run under metadata locks; avoid on-demand
                // hydration fallback paths here to prevent lock re-entry.
                return LoadHydratedPayloadForPath(&ctx, path, logical_size, false);
            });
        ctx.metadata_store->SetCommitStageHook(
            [&ctx](std::string_view stage) -> bool
            {
                const auto deadline = ctx.commit_deadline_tick_ms.load(std::memory_order_relaxed);
                if (deadline == 0)
                {
                    return true;
                }

                const auto now = static_cast<std::uint64_t>(GetTickCount64());
                if (now <= deadline)
                {
                    return true;
                }

                const auto timed_out_already = ctx.commit_timeout_latched.exchange(true, std::memory_order_relaxed);
                if (!timed_out_already)
                {
                    std::wcerr << L"[FsHost] RW native-commit stage timeout at '"
                        << Utf8ToWide(std::string(stage))
                        << L"' (timeout="
                        << ctx.args.write_commit_timeout_seconds
                        << L"s)."
                        << std::endl;
                }
                return false;
            });
        if (!ctx.metadata_store->LoadContainerState())
        {
            std::wcerr << L"[FsHost] RW engine bootstrap warning: unable to parse APFS container superblock from device path '" << args.device << L"'." << std::endl;
        }
        else
        {
            const auto block_size = ctx.metadata_store->BlockSizeBytes().value_or(0);
            const auto total_blocks = ctx.metadata_store->TotalBlocks().value_or(0);
            const auto checkpoint_xid = ctx.metadata_store->CheckpointXid().value_or(0);
            RefreshReportedVolumeInfoFromMetadata(ctx);
            std::wcerr << L"[FsHost] RW engine bootstrap ready (blockSize=" << block_size
                << L", totalBlocks=" << total_blocks
                << L", checkpointXid=" << checkpoint_xid << L")." << std::endl;

            if (!ctx.metadata_store->LoadVolumeState())
            {
                RefreshReportedVolumeInfoFromMetadata(ctx);
                ctx.recovery_active = true;
                ctx.runtime_recovery_reason = ctx.metadata_store->RecoveryReason();
                if (ctx.runtime_recovery_reason.empty())
                {
                    ctx.runtime_recovery_reason = L"VolumeStateLoadFailed";
                }
                ctx.runtime_last_recovery_action = L"BootstrapVolumeStateUnavailable";
                std::wcerr << L"[FsHost] RW engine bootstrap warning: volume state not ready (reason="
                    << ctx.runtime_recovery_reason
                    << L"); native APFS metadata enumeration remains unavailable."
                    << std::endl;
            }
            else if (!args.readwrite)
            {
                RefreshReportedVolumeInfoFromMetadata(ctx);
            }
            else if (ctx.native_write_enabled && !ctx.metadata_store->PrepareNativeWritePath())
            {
                RefreshReportedVolumeInfoFromMetadata(ctx);
                ctx.recovery_active = true;
                ctx.runtime_recovery_reason = ctx.metadata_store->RecoveryReason();
                if (ctx.runtime_recovery_reason.empty())
                {
                    ctx.runtime_recovery_reason = L"NativeWriteBootstrapFailed";
                }
                ctx.runtime_last_recovery_action = L"BootstrapFailed";
                std::wcerr << L"[FsHost] RW native write bootstrap warning: metadata write path is not ready; mutating operations will remain blocked." << std::endl;
                if (IsRecoveryPolicyFailClosed(args.write_recovery_policy))
                {
                    ctx.write_degraded = true;
                    ctx.native_write_enabled = false;
                    ctx.overlay_write_enabled = false;
                    ctx.runtime_last_recovery_action = L"BootstrapFailClosed";
                    std::wcerr << L"[FsHost] Recovery policy is FailClosed; bootstrap failure downgraded mount to read-only mode." << std::endl;
                }
            }
            else
            {
                RefreshReportedVolumeInfoFromMetadata(ctx);
                const auto recovery_before_replay = ctx.metadata_store->IsRecoveryRequired();
                const auto replay_result = ctx.metadata_store->ReplayOrRecover();
                if (!replay_result)
                {
                    if (ctx.metadata_store->IsRecoveryRequired() || recovery_before_replay)
                    {
                        ctx.recovery_active = true;
                        ctx.runtime_recovery_reason = ctx.metadata_store->RecoveryReason();
                        if (ctx.runtime_recovery_reason.empty())
                        {
                            ctx.runtime_recovery_reason = L"RecoveryReplayFailed";
                        }
                        ctx.runtime_last_recovery_action = IsRecoveryPolicyFailClosed(args.write_recovery_policy)
                            ? L"ReplaySkippedFailClosed"
                            : L"ReplaySkipped";
                        std::wcerr << L"[FsHost] RW recovery warning: replay/recovery could not clear recovery-required state." << std::endl;
                        if (ctx.native_write_enabled && IsRecoveryPolicyFailClosed(args.write_recovery_policy))
                        {
                            ctx.write_degraded = true;
                            ctx.native_write_enabled = false;
                            ctx.overlay_write_enabled = false;
                            std::wcerr << L"[FsHost] Recovery policy is FailClosed; replay failure downgraded mount to read-only mode." << std::endl;
                        }
                    }
                }
                else if (recovery_before_replay && !ctx.metadata_store->IsRecoveryRequired())
                {
                    ctx.recovery_active = false;
                    ctx.runtime_recovery_reason.clear();
                    ctx.runtime_last_recovery_action = L"ReplayApplied";
                    std::wcerr << L"[FsHost] RW recovery replay applied successfully; checkpoint state reconciled." << std::endl;
                    ClearRecoveredMarkerIfClean(ctx, L"RecoveryMarkerClearedAfterReplay");
                }
                else if (replay_result)
                {
                    ClearRecoveredMarkerIfClean(ctx, L"RecoveryMarkerClearedAfterReplay");
                }

                if (ctx.metadata_store->IsRecoveryRequired())
                {
                    ctx.recovery_active = true;
                    ctx.runtime_recovery_reason = ctx.metadata_store->RecoveryReason();
                    ctx.runtime_last_recovery_action = L"RecoveryRequiredBlock";
                    std::wcerr << L"[FsHost] RW recovery reconciliation: metadata store reported recovery-required state (reason="
                        << ctx.metadata_store->RecoveryReason()
                        << L")."
                        << std::endl;

                    if (ctx.native_write_enabled && IsRecoveryPolicyFailClosed(args.write_recovery_policy))
                    {
                        ctx.write_degraded = true;
                        ctx.native_write_enabled = false;
                        ctx.overlay_write_enabled = false;
                        std::wcerr << L"[FsHost] Recovery policy is FailClosed; mounting in degraded read-only mode." << std::endl;
                    }
                }
            }
        }

        if (ctx.metadata_store)
        {
            auto committed_xid = ResolveCleanRecoveryCheckpointXid(*ctx.metadata_store);
            if (committed_xid.has_value())
            {
                ctx.runtime_last_commit_xid = committed_xid;
            }
        }
        (void)WriteHostStatusFile(ctx, ctx.recovery_active, ctx.runtime_last_commit_xid);
    }
#endif

    if (!ctx.api.Load(ctx.label))
    {
        std::wcerr << L"[FsHost] " << ctx.label << std::endl;
        return 4;
    }

    ctx.sd = BuildWritableVolumeSecurityDescriptor(&ctx.sd_size);
    if (!ctx.sd)
    {
        std::wcerr << L"[FsHost] Failed to build security descriptor." << std::endl;
        return 5;
    }

    FILETIME now{}; GetSystemTimeAsFileTime(&now);
    auto root = std::make_shared<Node>();
    root->path = L"\\";
    root->apfs_path = ApfsRoot(args);
    root->is_directory = true;
    root->timestamp = now;
    ctx.nodes.emplace(Key(root->path), root);

#ifdef APFSACCESS_HAS_RW_ENGINE
    if (ctx.metadata_store && MergeCommittedInodeStateIntoNodeIndex(&ctx))
    {
        std::size_t committed_inode_count = 0;
        {
            std::lock_guard<std::mutex> metadata_lock(ctx.metadata_mutex);
            committed_inode_count = ctx.metadata_store->CommittedInodeCount();
        }
        std::wcerr << L"[FsHost] Applied native metadata overlay for "
            << committed_inode_count
            << L" committed inode entries."
            << std::endl;
    }
#endif

    if (!EnsureDirectoryLoaded(&ctx, root))
    {
        if (ctx.runtime_recovery_reason.empty())
        {
#ifdef APFSACCESS_HAS_RW_ENGINE
            if (ctx.metadata_store)
            {
                ctx.runtime_recovery_reason = ctx.metadata_store->RecoveryReason();
            }
#endif
            if (ctx.runtime_recovery_reason.empty())
            {
                ctx.runtime_recovery_reason = L"RootEnumerationUnavailable";
            }
        }
        ctx.recovery_active = true;
        if (ctx.runtime_last_recovery_action.empty())
        {
            ctx.runtime_last_recovery_action = L"MountStartupBlocked";
        }
        (void)WriteHostStatusFile(ctx, ctx.recovery_active, ctx.runtime_last_commit_xid);
        std::wcerr << L"[FsHost] Unable to enumerate APFS root path from native metadata state (reason="
            << ctx.runtime_recovery_reason
            << L")."
            << std::endl;
        if (ctx.sd) LocalFree(ctx.sd);
        return 5;
    }

    ctx.label = BuildExplorerVolumeLabel(args.volume);

    FSP_FSCTL_VOLUME_PARAMS vp{};
    vp.Version = sizeof(FSP_FSCTL_VOLUME_PARAMS);
    vp.SectorSize = static_cast<UINT16>(ctx.reported_allocation_unit_bytes != 0
        ? ctx.reported_allocation_unit_bytes
        : 4096);
    vp.SectorsPerAllocationUnit = 1;
    vp.MaxComponentLength = 255;
    vp.VolumeCreationTime = ((UINT64)now.dwHighDateTime << 32) | now.dwLowDateTime;
    vp.VolumeSerialNumber = BuildStableVolumeSerial(ctx.args);
    vp.FileInfoTimeout = 2000;
    vp.VolumeInfoTimeoutValid = 1;
    vp.VolumeInfoTimeout = 2000;
    vp.DirInfoTimeoutValid = 1;
    vp.DirInfoTimeout = 2000;
    vp.SecurityTimeoutValid = 1;
    vp.SecurityTimeout = 2000;
    vp.CaseSensitiveSearch = 0;
    vp.CasePreservedNames = 1;
    vp.UnicodeOnDisk = 1;
    vp.PersistentAcls = 0;
    vp.SupportsPosixUnlinkRename = 1;
    vp.ReadOnlyVolume = IsMutationWriteEnabled(&ctx) ? 0 : 1;
    vp.PostCleanupWhenModifiedOnly = 0;
    vp.FlushAndPurgeOnCleanup = 1;
    vp.PostDispositionWhenNecessaryOnly = 1;
    vp.UmFileContextIsUserContext2 = 1;
    wcscpy_s(vp.FileSystemName, sizeof(vp.FileSystemName) / sizeof(WCHAR), L"APFS");

    FSP_FILE_SYSTEM_INTERFACE iface{};
    iface.GetVolumeInfo = CB_GetVolumeInfo;
    iface.SetVolumeLabel = CB_SetVolumeLabel;
    iface.GetSecurityByName = CB_GetSecurityByName;
    iface.Create = CB_Create;
    iface.Open = CB_Open;
    iface.Overwrite = CB_Overwrite;
    iface.Cleanup = CB_Cleanup;
    iface.Close = CB_Close;
    iface.Read = CB_Read;
    iface.Write = CB_Write;
    iface.Flush = CB_Flush;
    iface.GetFileInfo = CB_GetFileInfo;
    iface.SetBasicInfo = CB_SetBasicInfo;
    iface.SetFileSize = CB_SetFileSize;
    iface.CanDelete = CB_CanDelete;
    iface.Rename = CB_Rename;
    iface.GetSecurity = CB_GetSecurity;
    iface.SetSecurity = CB_SetSecurity;
    iface.SetDelete = CB_SetDelete;
    iface.ReadDirectory = CB_ReadDirectory;

    NTSTATUS st = ctx.api.Create(const_cast<PWSTR>(L"" FSP_FSCTL_DISK_DEVICE_NAME), &vp, &iface, &ctx.fs);
    if (!NT_SUCCESS(st) || !ctx.fs)
    {
        std::wcerr << L"[FsHost] FspFileSystemCreate failed: 0x" << std::hex << (unsigned long)st << std::endl;
        return 6;
    }

    ctx.fs->UserContext = &ctx;
    auto m = BuildWinFspMountPoint(args.mount);
    st = ctx.api.SetMount(ctx.fs, m.data());
    if (!NT_SUCCESS(st))
    {
        std::wcerr << L"[FsHost] FspFileSystemSetMountPoint failed: 0x" << std::hex << (unsigned long)st << std::endl;
        ctx.api.Delete(ctx.fs);
        return 7;
    }
    st = ctx.api.Start(ctx.fs, 1);
    if (!NT_SUCCESS(st))
    {
        std::wcerr << L"[FsHost] FspFileSystemStartDispatcher failed: 0x" << std::hex << (unsigned long)st << std::endl;
        ctx.api.Delete(ctx.fs);
        return 8;
    }
    ctx.mount_ready.store(true, std::memory_order_release);
    (void)WriteHostStatusFile(ctx, ctx.recovery_active, ctx.runtime_last_commit_xid);
    NotifyShellDriveAdded(args.mount);

    if (args.lifetime_file.empty())
    {
        args.lifetime_file = (std::filesystem::temp_directory_path() / "ApfsAccess" / "host.alive").wstring();
    }
    std::filesystem::create_directories(std::filesystem::path(args.lifetime_file).parent_path());
    { std::ofstream out(args.lifetime_file, std::ios::trunc); out << "alive"; }

    SetConsoleCtrlHandler(CtrlHandler, TRUE);
    while (!g_exit.load())
    {
        if (!std::filesystem::exists(args.lifetime_file))
        {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }

    BeginMutationShutdownDrain(&ctx);
    ctx.api.Stop(ctx.fs);
#ifdef APFSACCESS_HAS_RW_ENGINE
    if (args.readwrite)
    {
        const auto shutdown_commit_status = CommitNativeMutationsBestEffort(&ctx, L"Shutdown");
        if (!NT_SUCCESS(shutdown_commit_status))
        {
            std::wcerr << L"[FsHost] RW native-commit warning (Shutdown): final commit failed with status 0x"
                << std::hex << static_cast<unsigned long>(shutdown_commit_status) << std::dec
                << L"." << std::endl;
        }
        FinalizeMutationJournalBestEffort(&ctx, L"Shutdown");
    }
#endif
    ctx.api.Delete(ctx.fs);
    NotifyShellDriveRemoved(args.mount);
    if (ctx.sd) LocalFree(ctx.sd);
    return 0;
}
#endif
