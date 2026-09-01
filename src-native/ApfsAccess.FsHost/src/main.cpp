#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <cwctype>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <objbase.h>
#include <memory>
#include <mutex>
#include <limits>
#include <optional>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <shared_mutex>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <windows.h>
#include <winioctl.h>
#include <winver.h>
#include <winternl.h>
#include <sddl.h>
#include <shlobj.h>
#ifndef PNTSTATUS
typedef NTSTATUS* PNTSTATUS;
#endif
#include <winfsp/winfsp.h>

#ifndef STATUS_NOT_SAME_DEVICE
#define STATUS_NOT_SAME_DEVICE ((NTSTATUS)0xC00000D4L)
#endif

#ifdef APFSACCESS_HAS_RW_ENGINE
#include "MetadataStore.h"
#include "PayloadSpool.h"
#include "TransactionManager.h"
#include "WritePipeline.h"
#endif

namespace
{
constexpr std::uint64_t kWriteCommitTimeoutPayloadExtensionMaxSeconds = 180;
constexpr std::uint64_t kWriteCommitTimeoutPayloadBytesPerSecond = 32ull * 1024ull * 1024ull;
// A canonical checkpoint also pays fixed metadata/WAL flush latency. Keep a
// bounded margin so a progressing payload commit is not downgraded simply
// because that fixed cost is larger than the payload-only estimate.
constexpr std::uint64_t kWriteCommitTimeoutPayloadHeadroomSeconds = 10;
constexpr std::uint64_t kPayloadSpoolMaxBytes = 4ull * 1024ull * 1024ull * 1024ull;
constexpr std::uint64_t kPayloadSpoolForegroundFlushBytes = 512ull * 1024ull * 1024ull;
constexpr std::uint64_t kPayloadSpoolForegroundFlushAppends = 8192;
constexpr std::chrono::milliseconds kDeferredCloseCommitBaseQuietPeriod{150};
constexpr std::chrono::milliseconds kDeferredCloseCommitBurstQuietPeriod{350};
constexpr std::uint16_t kMinimumSafeWinFspMajor = 2;
constexpr std::uint16_t kMinimumSafeWinFspMinor = 2;
constexpr std::uint16_t kMinimumSafeWinFspBuild = 26215;
constexpr std::chrono::milliseconds kStartupAuthorizationTimeout{10'000};
constexpr std::chrono::milliseconds kStartupAuthorizationPollInterval{20};
constexpr std::size_t kWinFspServiceStartProbeAttempts = 100;
constexpr std::chrono::milliseconds kWinFspServiceStartProbeInterval{20};
constexpr std::uint32_t kGroupedDeferredAcceptanceWindowMs = 25;
constexpr std::uint32_t kGroupedDeferredAcceptanceMaxParticipants = 32;
constexpr std::chrono::milliseconds kDeferredCommitMutationMutexRetryPeriod{10};
constexpr std::uint64_t kDeferredCloseCommitBurstThreshold = 32;
constexpr std::uint64_t kDeferredCloseCommitPayloadBytesThreshold = 512ull * 1024ull * 1024ull;
constexpr std::uint64_t kCallbackStatusWriteMinIntervalMs = 500;
constexpr DWORD kHydrationCacheFileAttributes = FILE_ATTRIBUTE_TEMPORARY | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;
constexpr DWORD kHydrationReadWaitTimeoutMs = 30'000;
constexpr DWORD kHydrationReadCancelWaitTimeoutMs = 5'000;
constexpr DWORD kHydrationReadFinalWaitTimeoutMs = 5'000;
constexpr UINT kUncancelableHydrationIoExitCode = 0xE3;
constexpr std::uintmax_t kRecoveryMarkerMaxBytes = 4096;
constexpr std::uint64_t kRecoveryMarkerDeepValidationIntervalMs = 1000;
std::atomic<std::uint64_t> g_recovery_marker_temp_sequence{1};
std::atomic<std::uint64_t> g_hydration_temp_sequence{1};

[[noreturn]] void FailClosedForUncancelableHydrationIo() noexcept
{
    OutputDebugStringW(L"[ApfsAccess] hydration I/O could not be cancelled before its safety deadline.\n");
    if (!TerminateProcess(GetCurrentProcess(), kUncancelableHydrationIoExitCode))
    {
        ExitProcess(kUncancelableHydrationIoExitCode);
    }
    std::abort();
}

bool WaitForHydrationRead(
    HANDLE handle,
    OVERLAPPED& overlapped,
    DWORD& bytes_read)
{
    if (GetOverlappedResultEx(
            handle,
            &overlapped,
            &bytes_read,
            kHydrationReadWaitTimeoutMs,
            FALSE))
    {
        return true;
    }

    auto error = GetLastError();
    if (error != WAIT_TIMEOUT && error != ERROR_IO_INCOMPLETE)
    {
        return false;
    }

    (void)CancelIoEx(handle, &overlapped);
    if (GetOverlappedResultEx(
            handle,
            &overlapped,
            &bytes_read,
            kHydrationReadCancelWaitTimeoutMs,
            FALSE))
    {
        return true;
    }

    error = GetLastError();
    if (error != WAIT_TIMEOUT && error != ERROR_IO_INCOMPLETE)
    {
        return false;
    }

    if (GetOverlappedResultEx(
            handle,
            &overlapped,
            &bytes_read,
            kHydrationReadFinalWaitTimeoutMs,
            FALSE))
    {
        return true;
    }

    error = GetLastError();
    if (error == WAIT_TIMEOUT || error == ERROR_IO_INCOMPLETE)
    {
        FailClosedForUncancelableHydrationIo();
    }
    return false;
}

constexpr std::chrono::milliseconds DeferredCloseCommitQuietPeriodForBurst(
    std::uint64_t burst_count,
    bool active_write_handles) noexcept
{
    return active_write_handles && burst_count >= kDeferredCloseCommitBurstThreshold
        ? kDeferredCloseCommitBurstQuietPeriod
        : kDeferredCloseCommitBaseQuietPeriod;
}

#ifdef APFSACCESS_FSHOST_UNIT_TEST
std::uint64_t g_child_name_linear_scan_count_for_test = 0;
std::uint64_t g_can_remove_node_visit_count_for_test = 0;
std::uint64_t g_remove_node_child_lookup_count_for_test = 0;
std::uint64_t g_stage_delete_child_lookup_count_for_test = 0;
std::uint64_t g_ancestor_child_delete_mark_count_for_test = 0;
std::uint64_t g_child_node_cached_lookup_count_for_test = 0;
std::uint64_t g_child_node_cached_lookup_fallback_count_for_test = 0;
std::uint64_t g_experimental_rename_committed_source_probe_count_for_test = 0;
std::uint64_t g_normalize_path_call_count_for_test = 0;
std::uint64_t g_deferred_delete_rollback_plan_probe_count_for_test = 0;
    std::uint64_t g_create_parent_reuse_count_for_test = 0;
    std::uint64_t g_delete_context_node_reuse_count_for_test = 0;
    std::uint64_t g_directory_enumeration_sort_count_for_test = 0;
    std::uint64_t g_host_status_file_build_count_for_test = 0;
    std::uint64_t g_native_dirty_status_snapshot_count_for_test = 0;
std::uint64_t g_hydrated_range_zero_fill_bytes_for_test = 0;
std::uint64_t g_payload_identity_lookup_count_for_test = 0;
struct MountContext;
void (*g_mutation_admission_pause_hook)(MountContext*) = nullptr;
void (*g_hydration_read_before_io_hook)(MountContext*) = nullptr;
void (*g_hydration_materialization_before_publish_hook)(MountContext*) = nullptr;
#endif

struct Arguments
{
    std::wstring device;
    std::wstring volume;
    std::wstring recovery_identity;
    std::wstring mount;
    std::wstring lifetime_file;
    std::wstring startup_gate_file;
    std::wstring startup_gate_token;
    std::wstring status_file;
    std::uint32_t parent_pid = 0;
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
    std::wstring path_key;
    std::wstring apfs_path;
    std::wstring hydration_key;
    std::wstring committed_read_path;
    bool is_directory = false;
    std::uint64_t file_size = 0;
    FILETIME timestamp{};
    bool loaded = false;
    std::vector<std::wstring> children;
    // Directory callbacks can be paged by WinFsp with a marker. Keep the
    // case-insensitively sorted name snapshot until namespace mutation.
    std::vector<std::wstring> sorted_children;
    bool sorted_children_valid = false;
    std::unordered_map<std::wstring, std::size_t> child_index_by_name_key;
    std::uint32_t open_handle_count = 0;
    std::uint32_t write_handle_count = 0;
    std::uint32_t delete_intent_count = 0;
    bool delete_latched = false;
    bool delete_pending = false;
    bool delete_requested_after_children = false;
    bool caller_delete_retry_required = false;
    bool child_delete_observed_while_open = false;
    std::uint64_t last_child_delete_tick_ms = 0;
};

struct OpenContext
{
    std::shared_ptr<Node> node;
    HANDLE file = INVALID_HANDLE_VALUE;
    UINT32 granted_access = 0;
    bool named_stream = false;
    std::wstring stream_name;
    std::uint64_t stream_size = 0;
    bool allow_read_data = false;
    bool allow_list_directory = false;
    bool allow_write_data = false;
    bool allow_append_data = false;
    bool allow_set_basic_info = false;
    bool allow_set_file_size = false;
    bool allow_delete = false;
    bool allow_delete_child = false;
    bool write_open = false;
    std::uint64_t last_write_offset = 0;
    std::uint64_t last_write_length = 0;
    bool has_last_write = false;
    bool delete_on_cleanup = false;
    bool delete_on_close_requested = false;
    bool directory_delete_probe_failed_not_empty = false;
    bool metadata_read_fallback = false;
    bool cleanup_seen = false;
    std::atomic<bool> mutation_observed{false};
#ifdef APFSACCESS_HAS_RW_ENGINE
    // A dirty read may be issued many times against one open handle. Keep the
    // path-to-spool identity snapshot local to that handle, but invalidate it
    // whenever the working metadata generation changes.
    mutable std::shared_mutex payload_identity_cache_mutex;
    std::uint64_t payload_identity_cache_epoch = 0;
    std::wstring payload_identity_visible_path_key;
    std::wstring payload_identity_committed_path_key;
    std::optional<apfsaccess::rw::MetadataStore::PayloadIdentity> payload_identity_visible;
    std::optional<apfsaccess::rw::MetadataStore::PayloadIdentity> payload_identity_committed;
#endif
};

struct LocalFileRollbackSnapshot
{
    std::wstring path_key;
    bool has_named_streams = false;
    std::unordered_map<std::wstring, std::uint64_t> named_streams;
    bool hydration_moved = false;
    bool hydration_preserved_in_place = false;
    std::filesystem::path hydration_path;
    std::filesystem::path hydration_backup_path;
};

struct DeleteRollbackSubtreeEntry
{
    std::shared_ptr<Node> node;
    LocalFileRollbackSnapshot file_snapshot;
};

struct RenameDescendantReadPathSnapshot
{
    std::shared_ptr<Node> node;
    std::wstring old_path;
    std::wstring old_committed_read_path;
};

struct DeferredDeleteRollbackPlan
{
    bool emit = false;
    std::wstring path;
    std::shared_ptr<Node> node;
    std::shared_ptr<Node> parent;
    std::wstring leaf;
    LocalFileRollbackSnapshot file_snapshot;
    std::vector<DeleteRollbackSubtreeEntry> subtree_snapshots;
};

struct RenameLocalSnapshot
{
    std::shared_ptr<Node> node;
    std::wstring old_path;
    std::wstring new_path;
    std::wstring old_hydration_key;
    std::wstring old_committed_read_path;
    FILETIME old_timestamp{};
    std::shared_ptr<Node> old_parent;
    std::shared_ptr<Node> new_parent;
    std::wstring old_leaf;
    std::wstring new_leaf;
    std::shared_ptr<Node> replaced_node;
    bool replaced_node_was_present = false;
    bool node_reindexed = false;
    LocalFileRollbackSnapshot replaced_file_snapshot;
    std::vector<RenameDescendantReadPathSnapshot> descendant_committed_read_paths;
};

struct NamedStreamPath
{
    std::wstring base_path;
    std::wstring stream_name;
    bool is_named_stream = false;
};

bool IsSafeWinFspRuntimeVersion(
    std::uint16_t major,
    std::uint16_t minor,
    std::uint16_t build)
{
    if (major != kMinimumSafeWinFspMajor)
    {
        return major > kMinimumSafeWinFspMajor;
    }
    if (minor != kMinimumSafeWinFspMinor)
    {
        return minor > kMinimumSafeWinFspMinor;
    }
    return build >= kMinimumSafeWinFspBuild;
}

bool IsSafeWinFspRuntimePair(
    std::uint16_t dll_major,
    std::uint16_t dll_minor,
    std::uint16_t dll_build,
    std::uint16_t driver_major,
    std::uint16_t driver_minor,
    std::uint16_t driver_build,
    std::uint16_t service_major,
    std::uint16_t service_minor)
{
    return IsSafeWinFspRuntimeVersion(dll_major, dll_minor, dll_build) &&
        IsSafeWinFspRuntimeVersion(driver_major, driver_minor, driver_build) &&
        dll_major == driver_major &&
        dll_minor == driver_minor &&
        dll_build == driver_build &&
        service_major == driver_major &&
        service_minor == driver_minor;
}

bool IsSafeWinFspRuntimeFilePair(
    std::uint16_t dll_major,
    std::uint16_t dll_minor,
    std::uint16_t dll_build,
    std::uint16_t dll_revision,
    std::uint16_t driver_major,
    std::uint16_t driver_minor,
    std::uint16_t driver_build,
    std::uint16_t driver_revision) noexcept
{
    return IsSafeWinFspRuntimeVersion(dll_major, dll_minor, dll_build) &&
        IsSafeWinFspRuntimeVersion(driver_major, driver_minor, driver_build) &&
        dll_major == driver_major &&
        dll_minor == driver_minor &&
        dll_build == driver_build &&
        dll_revision == driver_revision;
}

bool IsExactWinFspBinarySet(
    std::uint16_t dll_major,
    std::uint16_t dll_minor,
    std::uint16_t dll_build,
    std::uint16_t dll_revision,
    std::uint16_t driver_major,
    std::uint16_t driver_minor,
    std::uint16_t driver_build,
    std::uint16_t driver_revision,
    std::uint16_t active_major,
    std::uint16_t active_minor,
    std::uint16_t active_build,
    std::uint16_t active_revision) noexcept
{
    return dll_major == driver_major &&
        dll_minor == driver_minor &&
        dll_build == driver_build &&
        dll_revision == driver_revision &&
        dll_major == active_major &&
        dll_minor == active_minor &&
        dll_build == active_build &&
        dll_revision == active_revision;
}

std::uint64_t FileTimeTicks(const FILETIME& value) noexcept
{
    ULARGE_INTEGER ticks{};
    ticks.LowPart = value.dwLowDateTime;
    ticks.HighPart = value.dwHighDateTime;
    return ticks.QuadPart;
}

bool TryReadFileCreationTimeTicks(
    const std::filesystem::path& file_path,
    std::uint64_t& creation_time_ticks) noexcept
{
    WIN32_FILE_ATTRIBUTE_DATA attributes{};
    if (!GetFileAttributesExW(
            file_path.c_str(),
            GetFileExInfoStandard,
            &attributes))
    {
        return false;
    }

    creation_time_ticks = FileTimeTicks(attributes.ftCreationTime);
    return creation_time_ticks != 0;
}

std::uint64_t CurrentBootFileTimeTicks() noexcept
{
    FILETIME now_file_time{};
    GetSystemTimeAsFileTime(&now_file_time);
    const auto now_ticks = FileTimeTicks(now_file_time);
    const auto uptime_ticks = GetTickCount64() * 10'000ull;
    return now_ticks > uptime_ticks ? now_ticks - uptime_ticks : 0;
}

bool RequiresRestartForWinFspRuntimeFileTimes(
    std::uint64_t dll_creation_time_ticks,
    std::uint64_t driver_creation_time_ticks,
    std::uint64_t boot_time_ticks) noexcept
{
    return boot_time_ticks != 0 &&
        (dll_creation_time_ticks >= boot_time_ticks ||
         driver_creation_time_ticks >= boot_time_ticks);
}

std::array<std::filesystem::path, 2> WinFspRuntimeDllCandidates()
{
    return {
        std::filesystem::path(L"C:\\Program Files\\WinFsp\\bin\\winfsp-x64.dll"),
        std::filesystem::path(L"C:\\Program Files (x86)\\WinFsp\\bin\\winfsp-x64.dll"),
    };
}

bool TryReadFileVersion(
    const std::filesystem::path& file_path,
    std::uint16_t& major,
    std::uint16_t& minor,
    std::uint16_t& build,
    std::uint16_t& revision)
{
    const auto version_module = LoadLibraryW(L"version.dll");
    if (!version_module)
    {
        return false;
    }

    using GetVersionSize = DWORD (WINAPI *)(LPCWSTR, LPDWORD);
    using GetVersionInfo = BOOL (WINAPI *)(LPCWSTR, DWORD, DWORD, LPVOID);
    using QueryVersionValue = BOOL (WINAPI *)(LPCVOID, LPCWSTR, LPVOID *, PUINT);
    const auto get_version_size = reinterpret_cast<GetVersionSize>(
        GetProcAddress(version_module, "GetFileVersionInfoSizeW"));
    const auto get_version_info = reinterpret_cast<GetVersionInfo>(
        GetProcAddress(version_module, "GetFileVersionInfoW"));
    const auto query_version_value = reinterpret_cast<QueryVersionValue>(
        GetProcAddress(version_module, "VerQueryValueW"));
    if (!get_version_size || !get_version_info || !query_version_value)
    {
        FreeLibrary(version_module);
        return false;
    }

    DWORD ignored = 0;
    const auto version_size = get_version_size(file_path.c_str(), &ignored);
    if (version_size == 0)
    {
        FreeLibrary(version_module);
        return false;
    }

    std::vector<std::byte> version_info(version_size);
    if (!get_version_info(file_path.c_str(), 0, version_size, version_info.data()))
    {
        FreeLibrary(version_module);
        return false;
    }

    VS_FIXEDFILEINFO* fixed_info = nullptr;
    UINT fixed_info_size = 0;
    const auto query_ok = query_version_value(
        version_info.data(),
        L"\\",
        reinterpret_cast<void**>(&fixed_info),
        &fixed_info_size);
    if (!query_ok || !fixed_info || fixed_info_size < sizeof(VS_FIXEDFILEINFO))
    {
        FreeLibrary(version_module);
        return false;
    }

    major = HIWORD(fixed_info->dwFileVersionMS);
    minor = LOWORD(fixed_info->dwFileVersionMS);
    build = HIWORD(fixed_info->dwFileVersionLS);
    revision = LOWORD(fixed_info->dwFileVersionLS);
    FreeLibrary(version_module);
    return true;
}

bool TryReadModuleFileVersion(
    HMODULE module,
    std::uint16_t& major,
    std::uint16_t& minor,
    std::uint16_t& build,
    std::uint16_t& revision)
{
    std::array<wchar_t, 32768> module_path{};
    const auto module_path_chars = GetModuleFileNameW(
        module,
        module_path.data(),
        static_cast<DWORD>(module_path.size()));
    if (module_path_chars == 0 || module_path_chars >= module_path.size())
    {
        return false;
    }
    return TryReadFileVersion(
        std::filesystem::path(module_path.data()),
        major,
        minor,
        build,
        revision);
}

std::filesystem::path NormalizeDriverBinaryPath(const wchar_t* raw_path)
{
    if (!raw_path || *raw_path == L'\0')
    {
        return {};
    }

    std::wstring path(raw_path);
    if (path.front() == L'"')
    {
        const auto closing_quote = path.find(L'"', 1);
        if (closing_quote == std::wstring::npos)
        {
            return {};
        }
        path = path.substr(1, closing_quote - 1);
    }
    if (path.rfind(L"\\??\\", 0) == 0)
    {
        path.erase(0, 4);
    }
    else if (path.size() >= 11 &&
             CompareStringOrdinal(path.data(), 11, L"\\SystemRoot", 11, TRUE) == CSTR_EQUAL)
    {
        std::array<wchar_t, 32768> windows_directory{};
        const auto length = GetWindowsDirectoryW(
            windows_directory.data(),
            static_cast<UINT>(windows_directory.size()));
        if (length == 0 || length >= windows_directory.size())
        {
            return {};
        }
        path = std::wstring(windows_directory.data(), length) + path.substr(11);
    }

    const auto expanded_size = ExpandEnvironmentStringsW(path.c_str(), nullptr, 0);
    if (expanded_size > 1)
    {
        std::vector<wchar_t> expanded(expanded_size);
        if (ExpandEnvironmentStringsW(path.c_str(), expanded.data(), expanded_size) == expanded_size)
        {
            path.assign(expanded.data());
        }
    }
    return std::filesystem::path(path);
}

bool AreWinFspDriverBinariesIdentical(
    const std::filesystem::path& expected_path,
    const std::filesystem::path& active_path)
{
    if (expected_path.empty() || active_path.empty())
    {
        return false;
    }

    std::error_code ec;
    const auto expected_size = std::filesystem::file_size(expected_path, ec);
    if (ec)
    {
        return false;
    }
    const auto active_size = std::filesystem::file_size(active_path, ec);
    if (ec || expected_size != active_size)
    {
        return false;
    }

    std::ifstream expected(expected_path, std::ios::binary);
    std::ifstream active(active_path, std::ios::binary);
    if (!expected.is_open() || !active.is_open())
    {
        return false;
    }

    std::array<char, 64 * 1024> expected_buffer{};
    std::array<char, 64 * 1024> active_buffer{};
    while (true)
    {
        expected.read(expected_buffer.data(), expected_buffer.size());
        active.read(active_buffer.data(), active_buffer.size());
        const auto expected_count = expected.gcount();
        const auto active_count = active.gcount();
        if (expected_count != active_count ||
            (expected_count > 0 &&
             std::memcmp(expected_buffer.data(), active_buffer.data(), static_cast<std::size_t>(expected_count)) != 0))
        {
            return false;
        }
        if (expected_count == 0)
        {
            return !expected.bad() && !active.bad();
        }
    }
}

bool IsWinFspDriverServiceName(const wchar_t* service_name) noexcept
{
    return service_name &&
        std::wcslen(service_name) >= 6 &&
        CompareStringOrdinal(service_name, 6, L"WinFsp", 6, TRUE) == CSTR_EQUAL;
}

enum class ActiveWinFspDriverProbeResult
{
    NotFound,
    Found,
    Failed,
};

ActiveWinFspDriverProbeResult ProbeActiveWinFspDriverVersion(
    std::uint16_t& major,
    std::uint16_t& minor,
    std::uint16_t& build,
    std::uint16_t& revision,
    std::filesystem::path& binary_path,
    const std::filesystem::path& expected_binary_path)
{
    const auto manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!manager)
    {
        return ActiveWinFspDriverProbeResult::Failed;
    }

    DWORD bytes_needed = 0;
    DWORD service_count = 0;
    DWORD resume_handle = 0;
    SetLastError(ERROR_SUCCESS);
    const auto initial_query = EnumServicesStatusExW(
        manager,
        SC_ENUM_PROCESS_INFO,
        SERVICE_DRIVER,
        SERVICE_ACTIVE,
        nullptr,
        0,
        &bytes_needed,
        &service_count,
        &resume_handle,
        nullptr);
    const auto initial_error = GetLastError();
    if (!initial_query && initial_error != ERROR_MORE_DATA)
    {
        CloseServiceHandle(manager);
        return ActiveWinFspDriverProbeResult::Failed;
    }
    if (bytes_needed == 0)
    {
        CloseServiceHandle(manager);
        return ActiveWinFspDriverProbeResult::NotFound;
    }

    std::vector<std::byte> services_buffer(bytes_needed);
    resume_handle = 0;
    if (!EnumServicesStatusExW(
            manager,
            SC_ENUM_PROCESS_INFO,
            SERVICE_DRIVER,
            SERVICE_ACTIVE,
            reinterpret_cast<LPBYTE>(services_buffer.data()),
            static_cast<DWORD>(services_buffer.size()),
            &bytes_needed,
            &service_count,
            &resume_handle,
            nullptr))
    {
        CloseServiceHandle(manager);
        return ActiveWinFspDriverProbeResult::Failed;
    }

    bool found = false;
    const auto* services = reinterpret_cast<const ENUM_SERVICE_STATUS_PROCESSW*>(services_buffer.data());
    for (DWORD index = 0; index < service_count; ++index)
    {
        if (!IsWinFspDriverServiceName(services[index].lpServiceName))
        {
            continue;
        }

        const auto service = OpenServiceW(
            manager,
            services[index].lpServiceName,
            SERVICE_QUERY_CONFIG);
        if (!service)
        {
            CloseServiceHandle(manager);
            return ActiveWinFspDriverProbeResult::Failed;
        }

        DWORD config_size = 0;
        (void)QueryServiceConfigW(service, nullptr, 0, &config_size);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || config_size == 0)
        {
            CloseServiceHandle(service);
            CloseServiceHandle(manager);
            return ActiveWinFspDriverProbeResult::Failed;
        }
        std::vector<std::byte> config_buffer(config_size);
        auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(config_buffer.data());
        if (!QueryServiceConfigW(service, config, config_size, &config_size))
        {
            CloseServiceHandle(service);
            CloseServiceHandle(manager);
            return ActiveWinFspDriverProbeResult::Failed;
        }
        CloseServiceHandle(service);

        const auto candidate_path = NormalizeDriverBinaryPath(config->lpBinaryPathName);
        std::uint16_t candidate_major = 0;
        std::uint16_t candidate_minor = 0;
        std::uint16_t candidate_build = 0;
        std::uint16_t candidate_revision = 0;
        if (candidate_path.empty() ||
            !TryReadFileVersion(
                candidate_path,
                candidate_major,
                candidate_minor,
                candidate_build,
                candidate_revision) ||
            !AreWinFspDriverBinariesIdentical(expected_binary_path, candidate_path))
        {
            CloseServiceHandle(manager);
            return ActiveWinFspDriverProbeResult::Failed;
        }

        if (found &&
            (major != candidate_major ||
             minor != candidate_minor ||
             build != candidate_build ||
             revision != candidate_revision))
        {
            CloseServiceHandle(manager);
            return ActiveWinFspDriverProbeResult::Failed;
        }
        found = true;
        major = candidate_major;
        minor = candidate_minor;
        build = candidate_build;
        revision = candidate_revision;
        binary_path = candidate_path;
    }

    CloseServiceHandle(manager);
    return found
        ? ActiveWinFspDriverProbeResult::Found
        : ActiveWinFspDriverProbeResult::NotFound;
}

using ActiveWinFspDriverProbe = ActiveWinFspDriverProbeResult (*)(
    std::uint16_t&,
    std::uint16_t&,
    std::uint16_t&,
    std::uint16_t&,
    std::filesystem::path&,
    const std::filesystem::path&);
using WinFspServiceStarter = NTSTATUS (*)();

ActiveWinFspDriverProbeResult EnsureActiveWinFspDriverAvailable(
    ActiveWinFspDriverProbeResult initial_result,
    ActiveWinFspDriverProbe probe,
    WinFspServiceStarter start_service,
    const std::filesystem::path& expected_binary_path,
    std::uint16_t& major,
    std::uint16_t& minor,
    std::uint16_t& build,
    std::uint16_t& revision,
    std::filesystem::path& binary_path,
    std::size_t max_probe_attempts = kWinFspServiceStartProbeAttempts,
    std::chrono::milliseconds probe_interval = kWinFspServiceStartProbeInterval)
{
    if (initial_result == ActiveWinFspDriverProbeResult::Found)
    {
        return initial_result;
    }
    if (initial_result != ActiveWinFspDriverProbeResult::NotFound ||
        !probe ||
        !start_service ||
        !NT_SUCCESS(start_service()))
    {
        return ActiveWinFspDriverProbeResult::Failed;
    }

    for (std::size_t attempt = 0; attempt < max_probe_attempts; ++attempt)
    {
        const auto result = probe(
            major,
            minor,
            build,
            revision,
            binary_path,
            expected_binary_path);
        if (result != ActiveWinFspDriverProbeResult::NotFound)
        {
            return result;
        }
        if (attempt + 1 < max_probe_attempts && probe_interval.count() > 0)
        {
            std::this_thread::sleep_for(probe_interval);
        }
    }
    return ActiveWinFspDriverProbeResult::Failed;
}

bool IsPreexistingActiveWinFspDriverSafe(
    ActiveWinFspDriverProbeResult probe_result,
    std::uint16_t dll_major,
    std::uint16_t dll_minor,
    std::uint16_t dll_build,
    std::uint16_t dll_revision,
    std::uint16_t driver_major,
    std::uint16_t driver_minor,
    std::uint16_t driver_build,
    std::uint16_t driver_revision,
    std::uint16_t active_major,
    std::uint16_t active_minor,
    std::uint16_t active_build,
    std::uint16_t active_revision) noexcept
{
    if (probe_result == ActiveWinFspDriverProbeResult::NotFound)
    {
        return true;
    }
    return probe_result == ActiveWinFspDriverProbeResult::Found &&
        IsExactWinFspBinarySet(
            dll_major,
            dll_minor,
            dll_build,
            dll_revision,
            driver_major,
            driver_minor,
            driver_build,
            driver_revision,
            active_major,
            active_minor,
            active_build,
            active_revision);
}

struct WinFspApi
{
    using PFN_Create = NTSTATUS (*)(PWSTR, const FSP_FSCTL_VOLUME_PARAMS *, const FSP_FILE_SYSTEM_INTERFACE *, FSP_FILE_SYSTEM **);
    using PFN_Delete = VOID (*)(FSP_FILE_SYSTEM *);
    using PFN_SetMount = NTSTATUS (*)(FSP_FILE_SYSTEM *, PWSTR);
    using PFN_RemoveMount = VOID (*)(FSP_FILE_SYSTEM *);
    using PFN_Start = NTSTATUS (*)(FSP_FILE_SYSTEM *, ULONG);
    using PFN_Stop = VOID (*)(FSP_FILE_SYSTEM *);
    using PFN_AddDir = BOOLEAN (*)(FSP_FSCTL_DIR_INFO *, PVOID, ULONG, PULONG);
    using PFN_AddStream = BOOLEAN (*)(FSP_FSCTL_STREAM_INFO *, PVOID, ULONG, PULONG);
    using PFN_ServiceVersion = NTSTATUS (*)(PUINT32);
    using PFN_StartService = NTSTATUS (*)();

    HMODULE dll = nullptr;
    PFN_Create Create = nullptr;
    PFN_Delete Delete = nullptr;
    PFN_SetMount SetMount = nullptr;
    PFN_RemoveMount RemoveMount = nullptr;
    PFN_Start Start = nullptr;
    PFN_Stop Stop = nullptr;
    PFN_AddDir AddDir = nullptr;
    PFN_AddStream AddStream = nullptr;
    PFN_ServiceVersion ServiceVersion = nullptr;
    PFN_StartService StartService = nullptr;

    bool Load(std::wstring& err)
    {
        const auto candidates = WinFspRuntimeDllCandidates();
        const auto boot_time_ticks = CurrentBootFileTimeTicks();
        for (const auto& candidate : candidates)
        {
            std::uint64_t dll_creation_time_ticks = 0;
            std::uint64_t driver_creation_time_ticks = 0;
            (void)TryReadFileCreationTimeTicks(candidate, dll_creation_time_ticks);
            (void)TryReadFileCreationTimeTicks(
                candidate.parent_path() / L"winfsp-x64.sys",
                driver_creation_time_ticks);
            if (RequiresRestartForWinFspRuntimeFileTimes(
                    dll_creation_time_ticks,
                    driver_creation_time_ticks,
                    boot_time_ticks))
            {
                err = L"WinFsp was installed or updated after Windows started. Restart Windows before mounting an APFS volume.";
                return false;
            }
        }

        std::wstring last_error = L"Cannot load winfsp-x64.dll from an installed WinFsp directory.";
        const auto reset_candidate = [&]()
        {
            if (dll)
            {
                FreeLibrary(dll);
            }
            dll = nullptr;
            Create = nullptr;
            Delete = nullptr;
            SetMount = nullptr;
            RemoveMount = nullptr;
            Start = nullptr;
            Stop = nullptr;
            AddDir = nullptr;
            AddStream = nullptr;
            ServiceVersion = nullptr;
            StartService = nullptr;
        };

        for (const auto& candidate : candidates)
        {
            dll = LoadLibraryW(candidate.c_str());
            if (!dll)
            {
                continue;
            }

            const auto load = [&](auto& fn, const char* name)
            {
                fn = reinterpret_cast<std::remove_reference_t<decltype(fn)>>(GetProcAddress(dll, name));
                return fn != nullptr;
            };
            if (!load(Create, "FspFileSystemCreate") ||
                !load(Delete, "FspFileSystemDelete") ||
                !load(SetMount, "FspFileSystemSetMountPoint") ||
                !load(RemoveMount, "FspFileSystemRemoveMountPoint") ||
                !load(Start, "FspFileSystemStartDispatcher") ||
                !load(Stop, "FspFileSystemStopDispatcher") ||
                !load(AddDir, "FspFileSystemAddDirInfo") ||
                !load(ServiceVersion, "FspFsctlServiceVersion") ||
                !load(StartService, "FspFsctlStartService"))
            {
                last_error = L"An installed winfsp-x64.dll is missing required exports.";
                reset_candidate();
                continue;
            }

            std::uint16_t major = 0;
            std::uint16_t minor = 0;
            std::uint16_t build = 0;
            std::uint16_t revision = 0;
            std::uint16_t driver_major = 0;
            std::uint16_t driver_minor = 0;
            std::uint16_t driver_build = 0;
            std::uint16_t driver_revision = 0;
            std::uint16_t active_driver_major = 0;
            std::uint16_t active_driver_minor = 0;
            std::uint16_t active_driver_build = 0;
            std::uint16_t active_driver_revision = 0;
            std::filesystem::path active_driver_path;
            UINT32 service_version = 0;
            const auto driver_path = candidate.parent_path() / L"winfsp-x64.sys";
            if (!TryReadModuleFileVersion(dll, major, minor, build, revision) ||
                !TryReadFileVersion(
                    driver_path,
                    driver_major,
                    driver_minor,
                    driver_build,
                    driver_revision))
            {
                last_error = L"Unable to verify an installed WinFsp runtime and driver pair.";
                reset_candidate();
                continue;
            }

            if (!IsSafeWinFspRuntimeFilePair(
                    major,
                    minor,
                    build,
                    revision,
                    driver_major,
                    driver_minor,
                    driver_build,
                    driver_revision))
            {
                last_error = L"The installed WinFsp runtime files are unsafe or mismatched. Install WinFsp 2.2.26215 or newer, then restart Windows before mounting.";
                reset_candidate();
                continue;
            }

            auto active_driver_probe = ProbeActiveWinFspDriverVersion(
                    active_driver_major,
                    active_driver_minor,
                    active_driver_build,
                    active_driver_revision,
                    active_driver_path,
                    driver_path);
            if (!IsPreexistingActiveWinFspDriverSafe(
                    active_driver_probe,
                    major,
                    minor,
                    build,
                    revision,
                    driver_major,
                    driver_minor,
                    driver_build,
                    driver_revision,
                    active_driver_major,
                    active_driver_minor,
                    active_driver_build,
                    active_driver_revision))
            {
                last_error = L"The active WinFsp driver does not match the verified runtime files. Restart Windows before mounting.";
                reset_candidate();
                continue;
            }

            active_driver_probe = EnsureActiveWinFspDriverAvailable(
                active_driver_probe,
                ProbeActiveWinFspDriverVersion,
                StartService,
                driver_path,
                active_driver_major,
                active_driver_minor,
                active_driver_build,
                active_driver_revision,
                active_driver_path);
            if (active_driver_probe != ActiveWinFspDriverProbeResult::Found ||
                !IsExactWinFspBinarySet(
                    major,
                    minor,
                    build,
                    revision,
                    driver_major,
                    driver_minor,
                    driver_build,
                    driver_revision,
                    active_driver_major,
                    active_driver_minor,
                    active_driver_build,
                    active_driver_revision))
            {
                last_error = L"Unable to start and verify the selected WinFsp driver service.";
                reset_candidate();
                continue;
            }

            if (!NT_SUCCESS(ServiceVersion(&service_version)))
            {
                last_error = L"Unable to query the verified WinFsp driver service version.";
                reset_candidate();
                continue;
            }

            active_driver_probe = ProbeActiveWinFspDriverVersion(
                active_driver_major,
                active_driver_minor,
                active_driver_build,
                active_driver_revision,
                active_driver_path,
                driver_path);
            if (active_driver_probe != ActiveWinFspDriverProbeResult::Found ||
                !IsExactWinFspBinarySet(
                    major,
                    minor,
                    build,
                    revision,
                    driver_major,
                    driver_minor,
                    driver_build,
                    driver_revision,
                    active_driver_major,
                    active_driver_minor,
                    active_driver_build,
                    active_driver_revision))
            {
                last_error = L"The active WinFsp driver does not match the verified runtime files. Restart Windows before mounting.";
                reset_candidate();
                continue;
            }

            const auto service_major = static_cast<std::uint16_t>(service_version >> 16);
            const auto service_minor = static_cast<std::uint16_t>(service_version & 0xffffu);
            if (!IsSafeWinFspRuntimePair(
                    major,
                    minor,
                    build,
                    driver_major,
                    driver_minor,
                    driver_build,
                    service_major,
                    service_minor))
            {
                std::wstringstream message;
                message << L"WinFsp " << major << L'.' << minor << L'.' << build << L'.' << revision
                        << L" (driver file " << driver_major << L'.' << driver_minor << L'.' << driver_build << L'.' << driver_revision
                        << L", active driver " << active_driver_major << L'.' << active_driver_minor << L'.' << active_driver_build << L'.' << active_driver_revision
                        << L", service " << service_major << L'.' << service_minor << L") is unsafe for APFS Access. "
                        << L"Install WinFsp 2.2.26215 or newer before mounting.";
                last_error = message.str();
                reset_candidate();
                continue;
            }

            (void)load(AddStream, "FspFileSystemAddStreamInfo");
            return true;
        }

        err = last_error;
        return false;
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

struct WinHandleCloser
{
    void operator()(void* value) const noexcept
    {
        if (value && value != INVALID_HANDLE_VALUE)
        {
            CloseHandle(static_cast<HANDLE>(value));
        }
    }
};

using UniqueWinHandle = std::unique_ptr<void, WinHandleCloser>;

UniqueWinHandle TakeWinHandle(HANDLE handle)
{
    return handle == INVALID_HANDLE_VALUE
        ? UniqueWinHandle{}
        : UniqueWinHandle(handle);
}

struct HydrationReadCacheState
{
    UniqueWinHandle handle;
    std::wstring path;
    std::uint64_t object_id = 0;
    std::uint64_t generation = 0;
    std::uint64_t file_size = 0;
};

struct PerfCounter
{
    static constexpr std::size_t kLatencyBucketCount = 32;

    std::atomic<std::uint64_t> count{0};
    std::atomic<std::uint64_t> total_us{0};
    std::atomic<std::uint64_t> max_us{0};
    std::atomic<std::uint64_t> last_us{0};
    std::array<std::atomic<std::uint64_t>, kLatencyBucketCount> latency_buckets{};

    static void SaturatingAdd(
        std::atomic<std::uint64_t>& target,
        std::uint64_t increment) noexcept
    {
        auto current = target.load(std::memory_order_relaxed);
        while (current != (std::numeric_limits<std::uint64_t>::max)())
        {
            const auto desired = increment > (std::numeric_limits<std::uint64_t>::max)() - current
                ? (std::numeric_limits<std::uint64_t>::max)()
                : current + increment;
            if (target.compare_exchange_weak(current, desired, std::memory_order_relaxed))
            {
                return;
            }
        }
    }

    static std::uint64_t SaturatingSum(
        std::uint64_t lhs,
        std::uint64_t rhs) noexcept
    {
        return rhs > (std::numeric_limits<std::uint64_t>::max)() - lhs
            ? (std::numeric_limits<std::uint64_t>::max)()
            : lhs + rhs;
    }

    void Observe(std::uint64_t elapsed_us) noexcept
    {
        SaturatingAdd(count, 1);
        SaturatingAdd(total_us, elapsed_us);
        last_us.store(elapsed_us, std::memory_order_relaxed);

        auto current_max = max_us.load(std::memory_order_relaxed);
        while (elapsed_us > current_max &&
               !max_us.compare_exchange_weak(current_max, elapsed_us, std::memory_order_relaxed))
        {
        }

        std::size_t bucket = 0;
        auto bucket_value = elapsed_us;
        while (bucket_value > 1 && bucket + 1 < kLatencyBucketCount)
        {
            bucket_value >>= 1;
            ++bucket;
        }
        SaturatingAdd(latency_buckets[bucket], 1);
    }

    [[nodiscard]] std::uint64_t ApproxP50Us() const noexcept
    {
        const auto observed = count.load(std::memory_order_relaxed);
        if (observed == 0)
        {
            return 0;
        }

        const auto maximum = max_us.load(std::memory_order_relaxed);
        if (maximum == 0)
        {
            return 0;
        }

        const auto target = observed / 2 + observed % 2;
        std::uint64_t cumulative = 0;
        for (std::size_t bucket = 0; bucket < kLatencyBucketCount; ++bucket)
        {
            cumulative = SaturatingSum(
                cumulative,
                latency_buckets[bucket].load(std::memory_order_relaxed));
            if (cumulative >= target)
            {
                return (std::min)(1ull << bucket, maximum);
            }
        }
        return maximum;
    }

    [[nodiscard]] std::uint64_t ApproxP95Us() const noexcept
    {
        const auto observed = count.load(std::memory_order_relaxed);
        if (observed == 0)
        {
            return 0;
        }

        const auto maximum = max_us.load(std::memory_order_relaxed);
        if (maximum == 0)
        {
            return 0;
        }

        const auto target =
            (observed / 20) * 19 + (((observed % 20) * 19 + 19) / 20);
        std::uint64_t cumulative = 0;
        for (std::size_t bucket = 0; bucket < kLatencyBucketCount; ++bucket)
        {
            cumulative = SaturatingSum(
                cumulative,
                latency_buckets[bucket].load(std::memory_order_relaxed));
            if (cumulative >= target)
            {
                return (std::min)(1ull << bucket, maximum);
            }
        }
        return maximum;
    }
};

struct NativeCommitOriginCounter
{
    std::atomic<std::uint64_t> attempts{0};
    std::atomic<std::uint64_t> committed{0};
    std::atomic<std::uint64_t> nothing_to_commit{0};
    std::atomic<std::uint64_t> failed{0};
    std::atomic<std::uint64_t> total_ms{0};
    std::atomic<std::uint64_t> max_ms{0};
    std::atomic<std::uint64_t> last_ms{0};
    std::atomic<std::uint64_t> pending_mutations_before{0};
    std::atomic<std::uint64_t> payload_bytes_before{0};

    void Observe(
        bool did_commit,
        bool did_nothing,
        std::uint64_t elapsed_ms,
        std::uint64_t pending_before,
        std::uint64_t payload_before) noexcept
    {
        attempts.fetch_add(1, std::memory_order_relaxed);
        if (did_commit)
        {
            committed.fetch_add(1, std::memory_order_relaxed);
        }
        else if (did_nothing)
        {
            nothing_to_commit.fetch_add(1, std::memory_order_relaxed);
        }
        else
        {
            failed.fetch_add(1, std::memory_order_relaxed);
        }
        total_ms.fetch_add(elapsed_ms, std::memory_order_relaxed);
        last_ms.store(elapsed_ms, std::memory_order_relaxed);
        pending_mutations_before.store(pending_before, std::memory_order_relaxed);
        payload_bytes_before.store(payload_before, std::memory_order_relaxed);

        auto current_max = max_ms.load(std::memory_order_relaxed);
        while (elapsed_ms > current_max &&
               !max_ms.compare_exchange_weak(current_max, elapsed_ms, std::memory_order_relaxed))
        {
        }
    }
};

bool IsPerfCountersEnabled()
{
#ifdef APFSACCESS_FSHOST_UNIT_TEST
    wchar_t value[8]{};
    const auto chars = GetEnvironmentVariableW(L"APFSACCESS_PERF_COUNTERS", value, static_cast<DWORD>(std::size(value)));
    if (chars > 0 && value[0] != L'\0')
    {
        return value[0] != L'0';
    }

    return false;
#else
    static const bool enabled = []()
    {
        wchar_t value[8]{};
        const auto chars = GetEnvironmentVariableW(L"APFSACCESS_PERF_COUNTERS", value, static_cast<DWORD>(std::size(value)));
        if (chars > 0 && value[0] != L'\0')
        {
            return value[0] != L'0';
        }

        std::error_code ec;
        auto marker = std::filesystem::temp_directory_path(ec);
        if (ec)
        {
            return false;
        }
        marker /= "ApfsAccess";
        marker /= "perf-counters.enabled";
        return std::filesystem::exists(marker, ec) && !ec;
    }();
    return enabled;
#endif
}

constexpr std::uint32_t kDefaultDispatcherThreadCount = 4;
constexpr std::uint32_t kMaxDispatcherThreadCount = 8;

std::uint32_t ResolveDispatcherThreadCount()
{
    wchar_t value[16]{};
    const auto chars = GetEnvironmentVariableW(
        L"APFSACCESS_FSHOST_DISPATCHER_THREADS",
        value,
        static_cast<DWORD>(std::size(value)));
    if (chars == 0 || chars >= std::size(value))
    {
        return kDefaultDispatcherThreadCount;
    }

    for (DWORD index = 0; index < chars; ++index)
    {
        if (value[index] < L'0' || value[index] > L'9')
        {
            return kDefaultDispatcherThreadCount;
        }
    }

    std::uint32_t parsed = 0;
    for (DWORD index = 0; index < chars; ++index)
    {
        const auto digit = static_cast<std::uint32_t>(value[index] - L'0');
        if (parsed <= kMaxDispatcherThreadCount)
        {
            parsed = (std::min)(parsed * 10 + digit, kMaxDispatcherThreadCount);
        }
    }

    return parsed == 0
        ? kDefaultDispatcherThreadCount
        : (std::min)(parsed, kMaxDispatcherThreadCount);
}

NTSTATUS StartDispatcherWithResolvedThreadCount(
    WinFspApi::PFN_Start start,
    FSP_FILE_SYSTEM* file_system,
    std::uint32_t& resolved_thread_count)
{
    resolved_thread_count = ResolveDispatcherThreadCount();
    return start(file_system, resolved_thread_count);
}

bool IsDeferCloseCommitsEnabled()
{
#ifdef APFSACCESS_FSHOST_UNIT_TEST
    wchar_t disabled[8]{};
    const auto disabled_chars = GetEnvironmentVariableW(L"APFSACCESS_DISABLE_CONTENT_WRITEBACK", disabled, static_cast<DWORD>(std::size(disabled)));
    if (disabled_chars > 0 && disabled[0] != L'\0' && disabled[0] != L'0')
    {
        return false;
    }

    wchar_t value[8]{};
        const auto chars = GetEnvironmentVariableW(
            L"APFSACCESS_DEFER_CLOSE_COMMITS",
            value,
            static_cast<DWORD>(std::size(value)));
    if (chars == 0)
    {
        return true;
    }
    return value[0] != L'\0' && value[0] != L'0';
#else
    static const bool enabled = []()
    {
        wchar_t disabled[8]{};
        const auto disabled_chars = GetEnvironmentVariableW(L"APFSACCESS_DISABLE_CONTENT_WRITEBACK", disabled, static_cast<DWORD>(std::size(disabled)));
        if (disabled_chars > 0 && disabled[0] != L'\0' && disabled[0] != L'0')
        {
            return false;
        }

        wchar_t value[8]{};
        const auto chars = GetEnvironmentVariableW(
            L"APFSACCESS_DEFER_CLOSE_COMMITS",
            value,
            static_cast<DWORD>(std::size(value)));
        if (chars == 0)
        {
            return true;
        }
        return value[0] != L'\0' && value[0] != L'0';
    }();
    return enabled;
#endif
}

bool IsGroupedDeferredAcceptanceEnabled()
{
    if (!IsDeferCloseCommitsEnabled())
    {
        return false;
    }

    wchar_t enabled[8]{};
    const auto enabled_chars = GetEnvironmentVariableW(
        L"APFSACCESS_ENABLE_GROUPED_DEFERRED_ACCEPTANCE",
        enabled,
        static_cast<DWORD>(std::size(enabled)));
    if (enabled_chars != 0 && enabled[0] == L'0')
    {
        return false;
    }

    wchar_t disabled[8]{};
    const auto disabled_chars = GetEnvironmentVariableW(
        L"APFSACCESS_DISABLE_GROUPED_DEFERRED_ACCEPTANCE",
        disabled,
        static_cast<DWORD>(std::size(disabled)));
    return disabled_chars == 0 || disabled[0] == L'0';
}

bool IsDeferredPayloadIndexPersistenceEnabled()
{
    if (!IsDeferCloseCommitsEnabled())
    {
        return false;
    }

    wchar_t value[8]{};
    const auto chars = GetEnvironmentVariableW(
        L"APFSACCESS_DISABLE_DEFERRED_INDEX_PERSISTENCE",
        value,
        static_cast<DWORD>(std::size(value)));
    return chars == 0 || value[0] == L'0';
}

bool IsInlineAcceptancePayloadEnabled()
{
#ifdef APFSACCESS_FSHOST_UNIT_TEST
    wchar_t value[8]{};
    const auto chars = GetEnvironmentVariableW(
        L"APFSACCESS_DISABLE_INLINE_ACCEPTANCE_PAYLOAD",
        value,
        static_cast<DWORD>(std::size(value)));
    return chars == 0 || value[0] == L'0';
#else
    static const bool enabled = []()
    {
        wchar_t value[8]{};
        const auto chars = GetEnvironmentVariableW(
            L"APFSACCESS_DISABLE_INLINE_ACCEPTANCE_PAYLOAD",
            value,
            static_cast<DWORD>(std::size(value)));
        return chars == 0 || value[0] == L'0';
    }();
    return enabled;
#endif
}

bool IsFinalizationCoverageCacheEnabled()
{
#ifdef APFSACCESS_FSHOST_UNIT_TEST
    wchar_t value[8]{};
    const auto chars = GetEnvironmentVariableW(
        L"APFSACCESS_DISABLE_FINALIZATION_COVERAGE_CACHE",
        value,
        static_cast<DWORD>(std::size(value)));
    return chars == 0 || value[0] == L'0';
#else
    static const bool enabled = []()
    {
        wchar_t value[8]{};
        const auto chars = GetEnvironmentVariableW(
            L"APFSACCESS_DISABLE_FINALIZATION_COVERAGE_CACHE",
            value,
            static_cast<DWORD>(std::size(value)));
        return chars == 0 || value[0] == L'0';
    }();
    return enabled;
#endif
}

bool IsExperimentalDualHydrationMirrorEnabled()
{
    wchar_t value[8]{};
    const auto chars = GetEnvironmentVariableW(
        L"APFSACCESS_EXPERIMENTAL_DUAL_HYDRATION_MIRROR",
        value,
        static_cast<DWORD>(std::size(value)));
    return chars > 0 && chars < std::size(value) && value[0] != L'\0' && value[0] != L'0';
}

constexpr std::uint64_t kPostCheckpointHydrationPromotionMinimumBytes = 8ull * 1024ull * 1024ull;
constexpr std::uint64_t kPostCheckpointHydrationPromotionSessionBudgetBytes = 1024ull * 1024ull * 1024ull;

bool IsExperimentalPostCheckpointHydrationPromotionEnabled()
{
    wchar_t value[8]{};
    const auto chars = GetEnvironmentVariableW(
        L"APFSACCESS_EXPERIMENTAL_POST_CHECKPOINT_HYDRATION_PROMOTION",
        value,
        static_cast<DWORD>(std::size(value)));
    return chars == 0 ||
           (chars < std::size(value) && value[0] != L'\0' && value[0] != L'0');
}

std::uint64_t ResolvePostCheckpointHydrationPromotionMinimumBytes()
{
    wchar_t value[32]{};
    const auto chars = GetEnvironmentVariableW(
        L"APFSACCESS_POST_CHECKPOINT_HYDRATION_MIN_BYTES",
        value,
        static_cast<DWORD>(std::size(value)));
    if (chars == 0 || chars >= std::size(value))
    {
        return kPostCheckpointHydrationPromotionMinimumBytes;
    }

    std::uint64_t parsed = 0;
    for (DWORD index = 0; index < chars; ++index)
    {
        if (value[index] < L'0' || value[index] > L'9')
        {
            return kPostCheckpointHydrationPromotionMinimumBytes;
        }
        const auto digit = static_cast<std::uint64_t>(value[index] - L'0');
        if (parsed > ((std::numeric_limits<std::uint64_t>::max)() - digit) / 10)
        {
            return kPostCheckpointHydrationPromotionMinimumBytes;
        }
        parsed = parsed * 10 + digit;
    }
    return parsed == 0 ? kPostCheckpointHydrationPromotionMinimumBytes : parsed;
}

constexpr bool kExperimentalNamespaceWriteBackDefault = false;

bool IsExperimentalNamespaceWriteBackEnabled()
{
#ifdef APFSACCESS_FSHOST_UNIT_TEST
    wchar_t disabled[8]{};
    const auto disabled_chars = GetEnvironmentVariableW(
        L"APFSACCESS_DISABLE_NAMESPACE_WRITEBACK",
        disabled,
        static_cast<DWORD>(std::size(disabled)));
    if (disabled_chars > 0 && disabled[0] != L'\0' && disabled[0] != L'0')
    {
        return false;
    }

    wchar_t value[8]{};
    const auto chars = GetEnvironmentVariableW(
        L"APFSACCESS_EXPERIMENTAL_NAMESPACE_WRITEBACK",
        value,
        static_cast<DWORD>(std::size(value)));
    if (chars > 0)
    {
        return value[0] != L'\0' && value[0] != L'0';
    }

    return kExperimentalNamespaceWriteBackDefault;
#else
    static const bool enabled = []()
    {
        wchar_t disabled[8]{};
        const auto disabled_chars = GetEnvironmentVariableW(
            L"APFSACCESS_DISABLE_NAMESPACE_WRITEBACK",
            disabled,
            static_cast<DWORD>(std::size(disabled)));
        if (disabled_chars > 0 && disabled[0] != L'\0' && disabled[0] != L'0')
        {
            return false;
        }

        wchar_t value[8]{};
        const auto chars = GetEnvironmentVariableW(
            L"APFSACCESS_EXPERIMENTAL_NAMESPACE_WRITEBACK",
            value,
            static_cast<DWORD>(std::size(value)));
        if (chars > 0)
        {
            return value[0] != L'\0' && value[0] != L'0';
        }

        std::error_code ec;
        auto marker = std::filesystem::temp_directory_path(ec);
        if (ec)
        {
            return false;
        }
        marker /= "ApfsAccess";
        marker /= "experimental-namespace-writeback.enabled";
        if (std::filesystem::exists(marker, ec) && !ec)
        {
            return true;
        }

        return kExperimentalNamespaceWriteBackDefault;
    }();
    return enabled;
#endif
}

std::uint64_t ElapsedMicroseconds(std::chrono::steady_clock::time_point started)
{
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - started).count());
}

void AppendPerfCounterJson(std::ostringstream& buffer, const char* name, const PerfCounter& counter)
{
    const auto count = counter.count.load(std::memory_order_relaxed);
    const auto total_us = counter.total_us.load(std::memory_order_relaxed);
    const auto max_us = counter.max_us.load(std::memory_order_relaxed);
    const auto last_us = counter.last_us.load(std::memory_order_relaxed);
    buffer << "\"" << name << "\":{\"count\":" << count
           << ",\"totalUs\":" << total_us
           << ",\"maxUs\":" << max_us
           << ",\"lastUs\":" << last_us
           << ",\"p50Us\":" << counter.ApproxP50Us()
           << ",\"p95Us\":" << counter.ApproxP95Us()
           << "}";
}

void AppendNativeCommitOriginCounterJson(
    std::ostringstream& buffer,
    const char* name,
    const NativeCommitOriginCounter& counter)
{
    buffer << "\"" << name << "\":{\"attempts\":" << counter.attempts.load(std::memory_order_relaxed)
           << ",\"committed\":" << counter.committed.load(std::memory_order_relaxed)
           << ",\"nothingToCommit\":" << counter.nothing_to_commit.load(std::memory_order_relaxed)
           << ",\"failed\":" << counter.failed.load(std::memory_order_relaxed)
           << ",\"totalMs\":" << counter.total_ms.load(std::memory_order_relaxed)
           << ",\"maxMs\":" << counter.max_ms.load(std::memory_order_relaxed)
           << ",\"lastMs\":" << counter.last_ms.load(std::memory_order_relaxed)
           << ",\"pendingMutationsBefore\":" << counter.pending_mutations_before.load(std::memory_order_relaxed)
           << ",\"payloadBytesBefore\":" << counter.payload_bytes_before.load(std::memory_order_relaxed)
           << "}";
}

struct ScopedPerfTimer
{
    PerfCounter* counter = nullptr;
    std::chrono::steady_clock::time_point started{};
    bool enabled = false;

    explicit ScopedPerfTimer(PerfCounter* perf_counter) noexcept
        : counter(perf_counter)
        , enabled(perf_counter != nullptr && IsPerfCountersEnabled())
    {
        if (enabled)
        {
            started = std::chrono::steady_clock::now();
        }
    }

    ~ScopedPerfTimer()
    {
        if (enabled && counter)
        {
            counter->Observe(ElapsedMicroseconds(started));
        }
    }
};

std::unique_lock<std::mutex> AcquireObservedMutex(std::mutex& mutex, PerfCounter* counter)
{
    const auto started = counter && IsPerfCountersEnabled()
        ? std::chrono::steady_clock::now()
        : std::chrono::steady_clock::time_point{};
    std::unique_lock<std::mutex> lock(mutex);
    if (started != std::chrono::steady_clock::time_point{})
    {
        counter->Observe(ElapsedMicroseconds(started));
    }
    return lock;
}

void LockObserved(std::unique_lock<std::mutex>& lock, PerfCounter* counter)
{
    const auto started = counter && IsPerfCountersEnabled()
        ? std::chrono::steady_clock::now()
        : std::chrono::steady_clock::time_point{};
    lock.lock();
    if (started != std::chrono::steady_clock::time_point{})
    {
        counter->Observe(ElapsedMicroseconds(started));
    }
}

class ObservedMutexGuard
{
public:
    ObservedMutexGuard(
        std::mutex& mutex,
        PerfCounter* wait_counter,
        PerfCounter* hold_counter)
        : wait_counter_(wait_counter)
        , hold_counter_(hold_counter)
        , lock_(mutex, std::defer_lock)
    {
        const auto wait_started = IsPerfCountersEnabled()
            ? std::chrono::steady_clock::now()
            : std::chrono::steady_clock::time_point{};
        lock_.lock();
        if (wait_started != std::chrono::steady_clock::time_point{} && wait_counter_)
        {
            wait_counter_->Observe(ElapsedMicroseconds(wait_started));
        }
        hold_started_ = hold_counter_ && IsPerfCountersEnabled()
            ? std::chrono::steady_clock::now()
            : std::chrono::steady_clock::time_point{};
    }

    ~ObservedMutexGuard()
    {
        unlock_if_owned();
    }

    void lock()
    {
        const auto wait_started = IsPerfCountersEnabled()
            ? std::chrono::steady_clock::now()
            : std::chrono::steady_clock::time_point{};
        lock_.lock();
        if (wait_started != std::chrono::steady_clock::time_point{} && wait_counter_)
        {
            wait_counter_->Observe(ElapsedMicroseconds(wait_started));
        }
        hold_started_ = hold_counter_ && IsPerfCountersEnabled()
            ? std::chrono::steady_clock::now()
            : std::chrono::steady_clock::time_point{};
    }

    void unlock()
    {
        unlock_if_owned();
    }

    bool owns_lock() const noexcept
    {
        return lock_.owns_lock();
    }

    ObservedMutexGuard(const ObservedMutexGuard&) = delete;
    ObservedMutexGuard& operator=(const ObservedMutexGuard&) = delete;

private:
    void unlock_if_owned()
    {
        if (lock_.owns_lock())
        {
            if (hold_started_ != std::chrono::steady_clock::time_point{} && hold_counter_)
            {
                hold_counter_->Observe(ElapsedMicroseconds(hold_started_));
            }
            hold_started_ = std::chrono::steady_clock::time_point{};
            lock_.unlock();
        }
    }

    PerfCounter* wait_counter_ = nullptr;
    PerfCounter* hold_counter_ = nullptr;
    std::unique_lock<std::mutex> lock_;
    std::chrono::steady_clock::time_point hold_started_{};
};

void LockObserved(ObservedMutexGuard& lock, PerfCounter*)
{
    lock.lock();
}

struct CallbackStatusSnapshot
{
    bool readwrite = false;
    bool overlay_write_enabled = false;
    bool native_write_enabled = false;
    bool recovery_active = false;
    bool write_degraded = false;
    bool pending_native_writes = false;
    bool mount_ready = false;
    bool shutdown_drain_active = false;
    bool close_commit_deferred = false;
    bool payload_spool_index_dirty = false;
    bool payload_spool_recovery_required = false;
    bool has_last_commit_xid = false;
    std::uint64_t last_commit_xid = 0;
    std::uint64_t transaction_journal_pending_count = 0;
    std::uint64_t metadata_pending_count = 0;
    std::uint64_t dirty_transaction_count = 0;
    std::uint64_t deferred_close_commit_count = 0;
    std::uint64_t deferred_rename_commit_count = 0;
    std::uint32_t in_flight_mutation_callbacks = 0;
    bool deferred_commit_requested = false;
    bool deferred_commit_in_flight = false;
    bool deferred_commit_force_now = false;
    std::uint64_t deferred_commit_requested_target = 0;
    std::uint64_t deferred_commit_completed_target = 0;
    std::uint64_t deferred_commit_failed_target = 0;
    std::uint64_t deferred_commit_in_flight_target = 0;
    std::uint64_t deferred_commit_first_request_tick_ms = 0;
    std::uint64_t deferred_commit_deadline_tick_ms = 0;
    NTSTATUS deferred_commit_last_status = STATUS_SUCCESS;
    std::uint64_t payload_spool_bytes = 0;
    std::size_t payload_spool_dirty_range_count = 0;
    std::uint64_t payload_spool_cleanup_failures = 0;
    std::uint64_t payload_spool_bytes_since_sync = 0;
    std::uint64_t payload_spool_appends_since_sync = 0;
    std::uint64_t payload_spool_append_direct_count = 0;
    std::uint64_t payload_spool_append_merged_count = 0;
    std::uint64_t payload_spool_append_stream_open_count = 0;
    std::uint64_t payload_spool_append_stream_flush_count = 0;
    std::uint64_t wal_accepted_sequence = 0;
    std::uint64_t wal_apfs_durable_sequence = 0;
    std::uint64_t wal_cleanup_sequence = 0;
    bool wal_recovery_state_valid = true;
    std::wstring runtime_recovery_reason;
    std::wstring runtime_last_recovery_action;
    std::wstring last_native_mutation_failure_operation;
    std::wstring last_native_mutation_failure_path;
    std::wstring last_native_mutation_failure_secondary_path;
    std::wstring last_native_mutation_failure_reason;
    std::wstring last_native_mutation_failure_status;
    std::uint64_t payload_range_provider_call_count = 0;
    std::uint64_t payload_range_provider_failure_count = 0;
    std::wstring last_payload_range_provider_failure;
};

struct ReportedVolumeInfoSnapshot
{
    std::uint32_t allocation_unit_bytes = 4096;
    std::optional<std::uint64_t> total_size_bytes;
    std::optional<std::uint64_t> free_size_bytes;
};

enum class GroupedDeferredAcceptanceFailureReason : std::uint32_t
{
    None = 0,
    TransactionInactiveOrChanged = 1,
    PayloadFlushFailed = 2,
    WalAcceptanceFailed = 3,
    AcceptedSequenceBelowBatchRequirement = 4,
    SealedFollowerUncovered = 5,
};

const char* GroupedDeferredAcceptanceFailureReasonName(
    GroupedDeferredAcceptanceFailureReason reason)
{
    switch (reason)
    {
    case GroupedDeferredAcceptanceFailureReason::None:
        return "None";
    case GroupedDeferredAcceptanceFailureReason::TransactionInactiveOrChanged:
        return "TransactionInactiveOrChanged";
    case GroupedDeferredAcceptanceFailureReason::PayloadFlushFailed:
        return "PayloadFlushFailed";
    case GroupedDeferredAcceptanceFailureReason::WalAcceptanceFailed:
        return "WalAcceptanceFailed";
    case GroupedDeferredAcceptanceFailureReason::AcceptedSequenceBelowBatchRequirement:
        return "AcceptedSequenceBelowBatchRequirement";
    case GroupedDeferredAcceptanceFailureReason::SealedFollowerUncovered:
        return "SealedFollowerUncovered";
    default:
        return "Unknown";
    }
}

// Mutation admission/shutdown-drain synchronization domain. Bit 63 of the
// combined state is the drain flag; the low 63 bits hold the in-flight
// external mutation callback count. Both writers use CAS loops, so the domain
// is linearizable: a callback is admitted exactly when its increment CAS
// succeeds, and the drain begins exactly when its flag-set CAS succeeds.
static constexpr std::uint64_t kMutationAdmissionDrainFlag = (std::uint64_t{1} << 63);
static constexpr std::uint64_t kMutationAdmissionCountMask = kMutationAdmissionDrainFlag - 1;

inline bool MutationAdmissionIsDraining(std::uint64_t state) noexcept
{
    return (state & kMutationAdmissionDrainFlag) != 0;
}

inline std::uint32_t MutationAdmissionCount(std::uint64_t state) noexcept
{
    return static_cast<std::uint32_t>(state & kMutationAdmissionCountMask);
}

struct GroupedDeferredAcceptanceBatch
{
    mutable std::mutex mutex;
    std::condition_variable cv;
    std::chrono::steady_clock::time_point deadline{};
    std::uint64_t generation = 0;
    std::uint64_t participant_count = 0;
    std::uint64_t transaction_id = 0;
    std::uint64_t required_sequence = 0;
    std::uint64_t initial_accepted_sequence = 0;
    bool finish_requested = false;
    bool finishing = false;
    bool completed = false;
    bool success = false;
    bool absorbed_by_boundary = false;
    bool deferred_request_scheduled = false;
    bool failure_handled = false;
    std::uint64_t accepted_sequence = 0;
    NTSTATUS status = STATUS_SUCCESS;
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
    mutable std::mutex hydration_read_cache_mutex;
    std::shared_ptr<HydrationReadCacheState> hydration_read_cache_state;
    std::uint64_t hydration_read_cache_open_count = 0;
    std::uint64_t hydration_read_cache_hit_count = 0;
    std::atomic<bool> overlay_write_enabled{false};
    std::atomic<bool> native_write_enabled{false};
    std::filesystem::path recovery_marker_file;
    std::atomic<bool> recovery_active{false};
    std::atomic<bool> write_degraded{false};
    std::atomic<bool> recovery_identity_blocked{false};
    std::atomic<bool> recovery_marker_blocked{false};
    std::atomic<bool> pending_native_writes{false};
    std::atomic<bool> unjournaled_native_mutation{false};
    std::optional<std::uint64_t> runtime_last_commit_xid;
    std::wstring runtime_recovery_reason;
    std::wstring runtime_last_recovery_action;
    std::wstring last_native_mutation_failure_operation;
    std::wstring last_native_mutation_failure_path;
    std::wstring last_native_mutation_failure_secondary_path;
    std::wstring last_native_mutation_failure_reason;
    std::wstring last_native_mutation_failure_status;
    std::uint64_t payload_range_provider_call_count = 0;
    std::uint64_t payload_range_provider_failure_count = 0;
    std::wstring last_payload_range_provider_failure;
    mutable std::mutex payload_range_provider_diagnostics_mutex;
    std::string last_status_write_contents;
    mutable std::recursive_mutex runtime_state_mutex;
    std::mutex status_file_mutex;
    std::atomic<std::uint64_t> last_callback_status_write_tick_ms{0};
    std::atomic<bool> callback_status_publish_pending{false};
    std::mutex callback_status_snapshot_mutex;
    std::optional<CallbackStatusSnapshot> last_callback_status_snapshot;
    std::atomic<std::uint32_t> active_callback_count{0};
    std::atomic<std::uint32_t> peak_callback_count{0};
    // WinFsp does not expose its internal request queue. These counters are a
    // conservative host-side saturation estimate: active callbacks at or
    // above the configured dispatcher count indicate that all workers are
    // busy, and the excess is the estimated queued depth.
    std::atomic<std::uint64_t> callback_dispatcher_saturation_count{0};
    std::atomic<std::uint32_t> callback_queue_depth_peak{0};
    std::atomic<std::uint64_t> active_callback_started_tick_ms{0};
    mutable std::mutex callback_activity_mutex;
    std::string active_callback_name;
    std::string last_callback_name;
    std::optional<bool> last_recovery_marker_dirty;
    std::optional<std::uint64_t> last_recovery_marker_commit_xid;
    std::uint64_t recovery_marker_last_deep_validation_tick_ms = 0;
    UniqueWinHandle recovery_marker_cache_handle;
    std::filesystem::path recovery_marker_cache_path;
    std::uint64_t recovery_marker_cache_size = 0;
    std::int64_t recovery_marker_cache_last_write_time = 0;
    std::int64_t recovery_marker_cache_change_time = 0;
    std::uint32_t reported_allocation_unit_bytes = 4096;
    std::optional<std::uint64_t> reported_total_size_bytes;
    std::optional<std::uint64_t> reported_free_size_bytes;
    mutable std::mutex reported_volume_info_mutex;
    std::atomic<bool> mount_ready{false};
    std::uint32_t dispatcher_thread_count = kDefaultDispatcherThreadCount;
    std::mutex mutex;
    // One synchronization domain for external mutation admission and shutdown
    // draining. Bit 63 is the drain flag; the low 63 bits are the in-flight
    // external mutation callback count. TryEnter linearizes at its successful
    // increment CAS and BeginMutationShutdownDrain linearizes at its flag-set
    // CAS, so the two cannot interleave into a lost update: after the flag is
    // set no increment can be admitted (a concurrent increment CAS reads a
    // state without the flag and fails against the flagged state), and every
    // admitted callback is counted before the drain flag CAS can succeed.
    std::atomic<std::uint64_t> mutation_admission_state{0};
    std::atomic<std::uint32_t> active_foreground_mutation_callbacks{0};
    std::atomic<std::uint64_t> last_foreground_mutation_tick_ms{0};
    std::atomic<std::uint32_t> open_write_handle_count{0};
    // Serialize mutating callback flows to avoid namespace/delete-intent interleaving races.
    std::mutex mutation_callback_mutex;
    mutable std::mutex grouped_acceptance_mutex;
    std::shared_ptr<GroupedDeferredAcceptanceBatch> grouped_acceptance_batch;
    std::unordered_map<std::wstring, std::shared_ptr<Node>> nodes;
    std::unordered_map<std::wstring, std::unordered_map<std::wstring, std::uint64_t>> named_stream_sizes;
    std::unordered_set<std::wstring> stale_hydration_keys;
    std::vector<DeferredDeleteRollbackPlan> deferred_delete_rollback_plans;
    std::unordered_set<std::wstring> deferred_delete_rollback_path_keys;
    bool deferred_delete_rollback_has_descendant_paths = false;
    std::vector<RenameLocalSnapshot> deferred_rename_rollback_plans;
    std::atomic<std::uint64_t> deferred_rename_commit_count{0};
    PerfCounter perf_set_volume_label;
    PerfCounter perf_create;
    PerfCounter perf_open;
    PerfCounter perf_overwrite;
    PerfCounter perf_write;
    PerfCounter perf_set_basic_info;
    PerfCounter perf_set_file_size;
    PerfCounter perf_can_delete;
    PerfCounter perf_set_delete;
    PerfCounter perf_rename;
    PerfCounter perf_cleanup;
    PerfCounter perf_close;
    PerfCounter perf_read;
    PerfCounter perf_flush;
    PerfCounter perf_read_directory;
    PerfCounter perf_ensure_directory_loaded;
    PerfCounter perf_merge_committed_inodes;
    PerfCounter perf_commit_native;
    PerfCounter perf_get_volume_info;
    PerfCounter perf_get_security_by_name;
    PerfCounter perf_get_security;
    PerfCounter perf_set_security;
    PerfCounter perf_get_file_info;
    PerfCounter perf_get_stream_info;
    PerfCounter perf_mutation_callback_lock;
    PerfCounter perf_mutation_admission_wait;
    // These counters intentionally cover only wait/hold intervals routed
    // through the selected native-write timing helpers, not every mutex
    // acquisition.
    PerfCounter perf_tx_mutex_wait;
    PerfCounter perf_tx_mutex_hold;
    PerfCounter perf_metadata_mutex_wait;
    PerfCounter perf_commit_mutex_wait;
    PerfCounter perf_commit_mutex_hold;
    PerfCounter perf_namespace_mutex_wait;
    PerfCounter perf_namespace_mutex_hold;
    PerfCounter perf_metadata_stage;
    PerfCounter perf_metadata_mutex_hold;
    PerfCounter perf_payload_spool_append;
    PerfCounter perf_wal_append;
    PerfCounter perf_acceptance_wait;
    PerfCounter perf_cleanup_stage;
    PerfCounter perf_post_checkpoint_hydration;
    PerfCounter perf_recovery_marker;
    std::atomic<std::uint64_t> post_checkpoint_hydration_candidate_count{0};
    std::atomic<std::uint64_t> post_checkpoint_hydration_promoted_count{0};
    std::atomic<std::uint64_t> post_checkpoint_hydration_failure_count{0};
    std::atomic<std::uint64_t> post_checkpoint_hydration_partial_skip_count{0};
    std::atomic<std::uint64_t> post_checkpoint_hydration_open_skip_count{0};
    std::atomic<std::uint64_t> post_checkpoint_hydration_budget_skip_count{0};
    std::atomic<std::uint64_t> post_checkpoint_hydration_promoted_bytes{0};
    NativeCommitOriginCounter perf_commit_origin_close;
    NativeCommitOriginCounter perf_commit_origin_flush;
    NativeCommitOriginCounter perf_commit_origin_rename;
    NativeCommitOriginCounter perf_commit_origin_close_deferred;
    NativeCommitOriginCounter perf_commit_origin_shutdown;
    NativeCommitOriginCounter perf_commit_origin_dirty_limit;
    NativeCommitOriginCounter perf_commit_origin_other;
#ifdef APFSACCESS_HAS_RW_ENGINE
    mutable std::mutex metadata_mutex;
    // Readers may perform bounded device I/O concurrently, but a committed
    // checkpoint must not change or reuse the snapshotted physical extents
    // until every reader using them has finished.
    mutable std::shared_mutex committed_read_gate;
    mutable std::mutex commit_mutex;
    std::vector<apfsaccess::rw::MetadataStore::CommittedInodeChange> last_committed_inode_changes;
    std::optional<std::uint64_t> last_committed_inode_changes_xid;
    std::atomic<std::uint64_t> commit_deadline_tick_ms{0};
    std::atomic<bool> commit_timeout_latched{false};
    mutable std::mutex deferred_commit_mutex;
    std::condition_variable deferred_commit_cv;
    std::thread deferred_commit_thread;
    bool deferred_commit_thread_stop = false;
    bool deferred_commit_worker_done = true;
    std::uint64_t deferred_commit_stop_generation = 0;
    bool deferred_commit_requested = false;
    std::chrono::steady_clock::time_point deferred_commit_deadline{};
    std::uint64_t deferred_commit_deadline_tick_ms = 0;
    std::uint64_t deferred_commit_first_request_tick_ms = 0;
    std::uint64_t deferred_commit_burst_count = 0;
    std::uint64_t deferred_commit_requested_target = 0;
    std::uint64_t deferred_commit_completed_target = 0;
    std::uint64_t deferred_commit_failed_target = 0;
    std::uint64_t deferred_commit_in_flight_target = 0;
    NTSTATUS deferred_commit_last_status = STATUS_SUCCESS;
    bool deferred_commit_in_flight = false;
    bool deferred_commit_force_now = false;
    std::atomic<bool> close_commit_deferred{false};
    std::atomic<bool> deferred_close_status_publish_pending{false};
    std::atomic<std::uint64_t> deferred_close_commit_count{0};
    std::atomic<std::uint64_t> deferred_commit_worker_claim_attempt_count{0};
    std::atomic<std::uint64_t> deferred_commit_worker_mutex_contention_count{0};
    std::atomic<std::uint32_t> grouped_acceptance_waiting_participants{0};
    std::atomic<std::uint64_t> grouped_acceptance_batch_count{0};
    std::atomic<std::uint64_t> grouped_acceptance_participant_count{0};
    std::atomic<std::uint64_t> grouped_acceptance_max_cohort_size{0};
    std::atomic<std::uint64_t> grouped_acceptance_last_target{0};
    std::atomic<std::uint64_t> grouped_acceptance_next_generation{1};
    std::atomic<std::uint64_t> grouped_acceptance_rollover_count{0};
    std::atomic<std::uint64_t> grouped_acceptance_last_rollover_required_sequence{0};
    std::atomic<std::uint64_t> grouped_acceptance_last_rollover_result_sequence{0};
    std::atomic<std::uint32_t> grouped_acceptance_last_failure_reason{
        static_cast<std::uint32_t>(GroupedDeferredAcceptanceFailureReason::None)};
    std::atomic<std::uint64_t> grouped_acceptance_last_failure_transaction_id{0};
    std::atomic<std::uint64_t> grouped_acceptance_last_failure_required_sequence{0};
    std::atomic<std::uint64_t> grouped_acceptance_last_failure_batch_required_sequence{0};
    std::atomic<std::uint64_t> grouped_acceptance_last_failure_result_sequence{0};
    std::atomic<std::uint64_t> grouped_acceptance_last_failure_observed_transaction_id{0};
    std::atomic<std::uint64_t> grouped_acceptance_last_failure_observed_accepted_sequence{0};
    std::atomic<std::uint64_t> grouped_acceptance_last_failure_batch_generation{0};
    std::atomic<bool> grouped_acceptance_last_failure_batch_sealed{false};
    mutable std::mutex tx_mutex;
    std::unique_ptr<apfsaccess::rw::TransactionManager> tx_manager;
    std::filesystem::path tx_journal_file;
    std::unique_ptr<apfsaccess::rw::PayloadSpool> payload_spool;
    std::string payload_spool_volume_identity;
    std::unique_ptr<apfsaccess::rw::MetadataStore> metadata_store;
    std::atomic<std::uint64_t> payload_identity_cache_epoch{1};
#ifdef APFSACCESS_FSHOST_UNIT_TEST
    bool test_force_native_mutation_staging_success = false;
    bool test_force_recovery_identity_scan_exception = false;
    std::optional<apfsaccess::rw::MetadataStore::CommitStatus> test_forced_native_commit_status;
    std::optional<bool> test_forced_native_mutations_pending;
    std::optional<bool> test_forced_native_mutations_continue_deferred_close;
    std::wstring test_forced_native_commit_recovery_reason;
    bool test_forced_native_commit_recovery_required = false;
    std::uint32_t test_forced_native_mutation_count = 0;
    std::uint64_t test_forced_native_payload_bytes = 0;
    bool test_forced_native_mutations_content_only = false;
    std::uint32_t test_native_commit_attempt_count = 0;
    std::uint32_t test_grouped_acceptance_window_ms = 0;
    bool test_force_grouped_acceptance_flush_failure = false;
    bool test_force_recovery_marker_finalize_failure = false;
    std::atomic<bool> test_pause_after_recovery_marker_arm{false};
    std::atomic<bool> test_recovery_marker_arm_paused{false};
    std::atomic<bool> test_release_recovery_marker_arm{false};
    std::uint32_t test_grouped_acceptance_failure_recovery_count = 0;
    bool test_throw_deferred_worker_exception_after_claim = false;
    std::atomic<bool> test_pause_deferred_worker_after_wal_flush{false};
    std::atomic<bool> test_deferred_worker_paused_after_wal_flush{false};
    std::atomic<bool> test_release_deferred_worker_after_wal_flush{false};
    std::atomic<bool> test_pause_runtime_transition{false};
    std::atomic<bool> test_runtime_transition_paused{false};
    std::atomic<bool> test_release_runtime_transition{false};
#endif
#endif
};

#ifdef APFSACCESS_HAS_RW_ENGINE
void InvalidatePayloadIdentityCache(MountContext* context) noexcept
{
    if (context)
    {
        context->payload_identity_cache_epoch.fetch_add(1, std::memory_order_acq_rel);
    }
}
#endif

ReportedVolumeInfoSnapshot CaptureReportedVolumeInfo(const MountContext& context)
{
    std::lock_guard<std::mutex> lock(context.reported_volume_info_mutex);
    return {
        context.reported_allocation_unit_bytes,
        context.reported_total_size_bytes,
        context.reported_free_size_bytes,
    };
}

void RequestCallbackStatusPublish(MountContext* context) noexcept
{
    if (context)
    {
        context->callback_status_publish_pending.store(true, std::memory_order_release);
    }
}

bool IsHostMoveTraceEnabled();

std::wstring FormatNtStatus(NTSTATUS status)
{
    std::wostringstream buffer;
    buffer << L"0x" << std::hex << std::uppercase << static_cast<unsigned long>(status);
    return buffer.str();
}

std::wstring SanitizeTraceToken(std::wstring value)
{
    if (value.empty())
    {
        return L"unknown";
    }

    for (auto& ch : value)
    {
        if (!iswalnum(ch))
        {
            ch = L'_';
        }
    }
    return value;
}

void TraceMove(MountContext* c, const std::wstring& message)
{
    if (!IsHostMoveTraceEnabled())
    {
        return;
    }

    static std::mutex trace_mutex;
    std::lock_guard<std::mutex> lock(trace_mutex);

    std::error_code ec;
    auto trace_root = std::filesystem::temp_directory_path(ec);
    if (ec)
    {
        trace_root = std::filesystem::current_path(ec);
    }
    trace_root /= "ApfsAccess";
    trace_root /= "move-trace";
    std::filesystem::create_directories(trace_root, ec);

    auto mount_token = c ? c->args.mount : std::wstring{};
    auto trace_path = trace_root /
        (L"fshost_" + SanitizeTraceToken(mount_token) + L"_" + std::to_wstring(GetCurrentProcessId()) + L".log");
    std::wofstream out(trace_path, std::ios::app);
    if (!out.good())
    {
        return;
    }

    out << GetTickCount64()
        << L" pid=" << GetCurrentProcessId();
    if (c)
    {
        out << L" mount='" << c->args.mount << L"'";
    }
    out << L" " << message << std::endl;
}

#ifdef APFSACCESS_HAS_RW_ENGINE
bool MergeCommittedInodeStateIntoNodeIndex(MountContext* c);
bool MergeLastCommittedInodeChangesIntoNodeIndex(MountContext* c);
bool MergeCommittedDirectoryChildrenIntoNodeIndex(MountContext* c, const std::shared_ptr<Node>& dir);
#endif

bool WriteHostStatusFileLocked(
    MountContext& context,
    bool recovery_active = false,
    std::optional<std::uint64_t> last_commit_xid = std::nullopt
);

bool WriteHostStatusFile(MountContext& context);

bool WriteHostStatusFile(
    MountContext& context,
    bool recovery_active,
    std::optional<std::uint64_t> last_commit_xid
);

bool TryAcquireCallbackStatusWriteSlot(MountContext& context)
{
    const auto now = static_cast<std::uint64_t>(GetTickCount64());
    auto previous = context.last_callback_status_write_tick_ms.load(std::memory_order_acquire);
    for (;;)
    {
        if (previous != 0 &&
            now >= previous &&
            now - previous < kCallbackStatusWriteMinIntervalMs)
        {
            return false;
        }

        if (context.last_callback_status_write_tick_ms.compare_exchange_weak(
                previous,
                now,
                std::memory_order_acq_rel,
                std::memory_order_acquire))
        {
            return true;
        }
    }
}

bool CanAttemptCallbackStatusWriteSlot(const MountContext& context)
{
    const auto now = static_cast<std::uint64_t>(GetTickCount64());
    const auto previous = context.last_callback_status_write_tick_ms.load(std::memory_order_acquire);
    return previous == 0 ||
           now < previous ||
           now - previous >= kCallbackStatusWriteMinIntervalMs;
}

bool ShouldWriteHostStatusFileForCallback(MountContext& context, CallbackStatusSnapshot& snapshot);

bool TryAcquireCallbackStatusWriteSlot(MountContext& context, bool force_publish)
{
    if (force_publish)
    {
        context.last_callback_status_write_tick_ms.store(
            static_cast<std::uint64_t>(GetTickCount64()),
            std::memory_order_release);
        return true;
    }

    return TryAcquireCallbackStatusWriteSlot(context);
}

void WriteHostStatusFileForCallback(MountContext* context, bool force_publish = false)
{
    if (!context || context->args.status_file.empty())
    {
        return;
    }

    // WinFsp callbacks must never take the status/runtime/metadata locks or
    // perform filesystem I/O. The host loop will publish the coalesced state
    // after the callback returns.
    if (context->active_callback_count.load(std::memory_order_acquire) != 0)
    {
        RequestCallbackStatusPublish(context);
        return;
    }

    RequestCallbackStatusPublish(context);
    if (!force_publish && !CanAttemptCallbackStatusWriteSlot(*context))
    {
        return;
    }

        context->callback_status_publish_pending.store(false, std::memory_order_release);
    CallbackStatusSnapshot snapshot{};
    if (!ShouldWriteHostStatusFileForCallback(*context, snapshot))
    {
        return;
    }

    if (!TryAcquireCallbackStatusWriteSlot(*context, force_publish))
    {
        context->callback_status_publish_pending.store(true, std::memory_order_release);
        return;
    }

    if (!WriteHostStatusFile(*context))
    {
        context->callback_status_publish_pending.store(true, std::memory_order_release);
    }
}

std::string EscapeJson(const std::string& value);

void WriteCallbackWatchdogFile(MountContext& context)
{
    if (context.args.status_file.empty())
    {
        return;
    }

    std::string active_name;
    std::string last_name;
    {
        std::lock_guard<std::mutex> lock(context.callback_activity_mutex);
        active_name = context.active_callback_name;
        last_name = context.last_callback_name;
    }

    std::ostringstream contents;
    contents << "{\"activeCallbacks\":"
             << context.active_callback_count.load(std::memory_order_acquire)
             << ",\"peakCallbacks\":"
             << context.peak_callback_count.load(std::memory_order_acquire)
             << ",\"callbackDispatcherSaturationCount\":"
             << context.callback_dispatcher_saturation_count.load(std::memory_order_acquire)
             << ",\"callbackQueueDepthEstimate\":"
             << (context.active_callback_count.load(std::memory_order_acquire) >
                     (std::max)(1u, context.dispatcher_thread_count)
                 ? context.active_callback_count.load(std::memory_order_acquire) -
                     (std::max)(1u, context.dispatcher_thread_count)
                 : 0u)
             << ",\"callbackQueueDepthPeakEstimate\":"
             << context.callback_queue_depth_peak.load(std::memory_order_acquire)
             << ",\"activeCallbackStartedTickMs\":"
             << context.active_callback_started_tick_ms.load(std::memory_order_acquire)
             << ",\"activeCallback\":\"" << EscapeJson(active_name)
             << "\",\"lastCallback\":\"" << EscapeJson(last_name) << "\"}";

    try
    {
        const auto diagnostic_path = std::filesystem::path(context.args.status_file + L".callback.json");
        const auto temp_path = std::filesystem::path(diagnostic_path.wstring() + L".tmp");
        if (diagnostic_path.has_parent_path())
        {
            std::filesystem::create_directories(diagnostic_path.parent_path());
        }
        {
            std::ofstream out(temp_path, std::ios::binary | std::ios::trunc);
            if (!out.good())
            {
                return;
            }
            const auto text = contents.str();
            out.write(text.data(), static_cast<std::streamsize>(text.size()));
            out.flush();
            if (!out.good())
            {
                std::error_code ignored;
                std::filesystem::remove(temp_path, ignored);
                return;
            }
        }
        (void)MoveFileExW(
            temp_path.c_str(),
            diagnostic_path.c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
    }
    catch (...)
    {
    }
}

#ifdef APFSACCESS_FSHOST_UNIT_TEST
std::function<void()> g_shutdown_stage_file_test_hook;
#endif

void WriteShutdownStageFile(MountContext& context, const char* stage)
{
#ifdef APFSACCESS_FSHOST_UNIT_TEST
    if (g_shutdown_stage_file_test_hook)
    {
        g_shutdown_stage_file_test_hook();
    }
#endif
    if (context.args.status_file.empty())
    {
        return;
    }

    std::string active_name;
    std::string last_name;
    {
        std::lock_guard<std::mutex> lock(context.callback_activity_mutex);
        active_name = context.active_callback_name;
        last_name = context.last_callback_name;
    }

    const auto admission_state = context.mutation_admission_state.load(std::memory_order_acquire);
    std::ostringstream contents;
    contents << "{\"stage\":\"" << EscapeJson(stage ? stage : "unknown")
             << "\",\"processId\":" << GetCurrentProcessId()
             << ",\"tickMs\":" << GetTickCount64()
             << ",\"activeCallbacks\":"
             << context.active_callback_count.load(std::memory_order_acquire)
             << ",\"peakCallbacks\":"
             << context.peak_callback_count.load(std::memory_order_acquire)
             << ",\"activeCallbackStartedTickMs\":"
             << context.active_callback_started_tick_ms.load(std::memory_order_acquire)
             << ",\"activeCallback\":\"" << EscapeJson(active_name)
             << "\",\"lastCallback\":\"" << EscapeJson(last_name)
             << "\",\"mutationAdmissionState\":" << admission_state
             << ",\"mutationAdmissionCount\":" << MutationAdmissionCount(admission_state)
             << ",\"shutdownDrainActive\":"
             << (MutationAdmissionIsDraining(admission_state) ? "true" : "false")
             << ",\"foregroundMutationCallbacks\":"
             << context.active_foreground_mutation_callbacks.load(std::memory_order_acquire)
             << ",\"openWriteHandles\":"
             << context.open_write_handle_count.load(std::memory_order_acquire)
             << ",\"performance\":{";
    AppendPerfCounterJson(contents, "setVolumeLabel", context.perf_set_volume_label);
    contents << ",";
    AppendPerfCounterJson(contents, "open", context.perf_open);
    contents << ",";
    AppendPerfCounterJson(contents, "overwrite", context.perf_overwrite);
    contents << ",";
    AppendPerfCounterJson(contents, "canDelete", context.perf_can_delete);
    contents << ",";
    AppendPerfCounterJson(contents, "setSecurity", context.perf_set_security);
    contents << ",";
    AppendPerfCounterJson(contents, "cleanup", context.perf_cleanup);
    contents << ",";
    AppendPerfCounterJson(contents, "close", context.perf_close);
    contents << ",";
    AppendPerfCounterJson(contents, "readDirectory", context.perf_read_directory);
    contents << ",";
    AppendPerfCounterJson(contents, "getVolumeInfo", context.perf_get_volume_info);
    contents << ",";
    AppendPerfCounterJson(contents, "getSecurityByName", context.perf_get_security_by_name);
    contents << ",";
    AppendPerfCounterJson(contents, "getSecurity", context.perf_get_security);
    contents << ",";
    AppendPerfCounterJson(contents, "getFileInfo", context.perf_get_file_info);
    contents << ",";
    AppendPerfCounterJson(contents, "getStreamInfo", context.perf_get_stream_info);
    contents << ",";
    AppendPerfCounterJson(contents, "namespaceMutexWait", context.perf_namespace_mutex_wait);
    contents << ",";
    AppendPerfCounterJson(contents, "namespaceMutexHold", context.perf_namespace_mutex_hold);
    contents << ",";
    AppendPerfCounterJson(contents, "metadataMutexWait", context.perf_metadata_mutex_wait);
    contents << ",";
    AppendPerfCounterJson(contents, "metadataMutexHold", context.perf_metadata_mutex_hold);
    contents << ",";
    AppendPerfCounterJson(contents, "commitMutexWait", context.perf_commit_mutex_wait);
    contents << ",";
    AppendPerfCounterJson(contents, "commitMutexHold", context.perf_commit_mutex_hold);
    contents << ",";
    AppendPerfCounterJson(contents, "txMutexWait", context.perf_tx_mutex_wait);
    contents << ",";
    AppendPerfCounterJson(contents, "txMutexHold", context.perf_tx_mutex_hold);
    contents << ",";
    AppendPerfCounterJson(contents, "recoveryMarker", context.perf_recovery_marker);
    contents << "}}";

    try
    {
        const auto diagnostic_path = std::filesystem::path(context.args.status_file + L".shutdown.json");
        const auto temp_path = std::filesystem::path(diagnostic_path.wstring() + L".tmp");
        if (diagnostic_path.has_parent_path())
        {
            std::filesystem::create_directories(diagnostic_path.parent_path());
        }
        {
            std::ofstream out(temp_path, std::ios::binary | std::ios::trunc);
            if (!out.good())
            {
                return;
            }
            const auto text = contents.str();
            out.write(text.data(), static_cast<std::streamsize>(text.size()));
            out.flush();
            if (!out.good())
            {
                std::error_code ignored;
                std::filesystem::remove(temp_path, ignored);
                return;
            }
        }
        (void)MoveFileExW(
            temp_path.c_str(),
            diagnostic_path.c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
    }
    catch (...)
    {
    }
}

struct ScopedCallbackActivity
{
    ScopedCallbackActivity(MountContext* context, const char* name)
        : context_(context)
        , name_(name ? name : "unknown")
    {
        if (!context_)
        {
            return;
        }

        const auto active = context_->active_callback_count.fetch_add(
            1,
            std::memory_order_acq_rel) + 1;
        auto peak = context_->peak_callback_count.load(std::memory_order_relaxed);
        while (active > peak &&
               !context_->peak_callback_count.compare_exchange_weak(
                   peak,
                   active,
                   std::memory_order_relaxed))
        {
        }
        const auto dispatcher_threads = (std::max)(1u, context_->dispatcher_thread_count);
        const auto queue_depth = active > dispatcher_threads
            ? active - dispatcher_threads
            : 0u;
        if (active >= dispatcher_threads)
        {
            context_->callback_dispatcher_saturation_count.fetch_add(
                1,
                std::memory_order_relaxed);
        }
        auto peak_queue_depth = context_->callback_queue_depth_peak.load(std::memory_order_relaxed);
        while (queue_depth > peak_queue_depth &&
               !context_->callback_queue_depth_peak.compare_exchange_weak(
                   peak_queue_depth,
                   queue_depth,
                   std::memory_order_relaxed))
        {
        }
        if (active == 1)
        {
            context_->active_callback_started_tick_ms.store(
                static_cast<std::uint64_t>(GetTickCount64()),
                std::memory_order_release);
        }
        {
            std::lock_guard<std::mutex> lock(context_->callback_activity_mutex);
            context_->active_callback_name = name_;
            context_->last_callback_name = name_;
        }
        context_->callback_status_publish_pending.store(true, std::memory_order_release);
    }

    ~ScopedCallbackActivity()
    {
        if (!context_)
        {
            return;
        }

        const auto previous = context_->active_callback_count.fetch_sub(
            1,
            std::memory_order_acq_rel);
        if (previous == 1)
        {
            context_->active_callback_started_tick_ms.store(0, std::memory_order_release);
            std::lock_guard<std::mutex> lock(context_->callback_activity_mutex);
            context_->active_callback_name.clear();
            context_->last_callback_name = name_;
        }
        context_->callback_status_publish_pending.store(true, std::memory_order_release);
    }

private:
    MountContext* context_ = nullptr;
    const char* name_ = "unknown";
};

struct MutationCallbackScope
{
    explicit MutationCallbackScope(
        MountContext* context,
        bool track_foreground = true,
        bool try_lock = false)
        : context_(context)
        , track_foreground_(context != nullptr && track_foreground)
    {
        if (track_foreground_)
        {
            context_->active_foreground_mutation_callbacks.fetch_add(1, std::memory_order_acq_rel);
            context_->last_foreground_mutation_tick_ms.store(
                static_cast<std::uint64_t>(GetTickCount64()),
                std::memory_order_release);
        }
        const auto lock_wait_started = context_ && IsPerfCountersEnabled()
            ? std::chrono::steady_clock::now()
            : std::chrono::steady_clock::time_point{};
        if (context_)
        {
            if (try_lock)
            {
                lock_ = std::unique_lock<std::mutex>(
                    context_->mutation_callback_mutex,
                    std::defer_lock);
                (void)lock_.try_lock();
            }
            else
            {
                lock_ = std::unique_lock<std::mutex>(context_->mutation_callback_mutex);
            }
        }
        if (context_ && lock_wait_started != std::chrono::steady_clock::time_point{})
        {
            context_->perf_mutation_callback_lock.Observe(ElapsedMicroseconds(lock_wait_started));
        }
    }

    ~MutationCallbackScope()
    {
        if (track_foreground_ && context_)
        {
            context_->last_foreground_mutation_tick_ms.store(
                static_cast<std::uint64_t>(GetTickCount64()),
                std::memory_order_release);
            const auto previous =
                context_->active_foreground_mutation_callbacks.fetch_sub(1, std::memory_order_acq_rel);
            if (previous == 1)
            {
                RequestCallbackStatusPublish(context_);
            }
        }
    }

    void Unlock()
    {
        if (lock_.owns_lock())
        {
            lock_.unlock();
        }
    }

    void Lock()
    {
        if (context_ && !lock_.owns_lock())
        {
            lock_.lock();
        }
    }

    [[nodiscard]] bool OwnsLock() const noexcept
    {
        return lock_.owns_lock();
    }

private:
    MountContext* context_ = nullptr;
    bool track_foreground_ = false;
    std::unique_lock<std::mutex> lock_;
};

struct ExternalMutationRequestScope
{
    explicit ExternalMutationRequestScope(MountContext* context, bool track_foreground = true)
        : context_(context),
          track_foreground_(context != nullptr && track_foreground),
          acquired_(TryEnter(context_, track_foreground_))
    {
    }

    ~ExternalMutationRequestScope()
    {
        if (acquired_ && context_)
        {
            const auto previous =
                context_->mutation_admission_state.fetch_sub(1, std::memory_order_acq_rel);
            if (MutationAdmissionCount(previous) == 1)
            {
                RequestCallbackStatusPublish(context_);
            }
        }
    }

    bool Acquired() const noexcept
    {
        return acquired_;
    }

private:
    static bool TryEnter(MountContext* context, bool track_foreground)
    {
        if (!context)
        {
            return false;
        }

        const auto wait_started = IsPerfCountersEnabled()
            ? std::chrono::steady_clock::now()
            : std::chrono::steady_clock::time_point{};
        const auto observe_wait = [&]()
        {
            if (wait_started != std::chrono::steady_clock::time_point{})
            {
                context->perf_mutation_admission_wait.Observe(ElapsedMicroseconds(wait_started));
            }
        };
        auto state = context->mutation_admission_state.load(std::memory_order_seq_cst);
        for (;;)
        {
            if (MutationAdmissionIsDraining(state))
            {
                observe_wait();
                return false;
            }
            if (context->mutation_admission_state.compare_exchange_weak(
                    state,
                    state + 1,
                    std::memory_order_seq_cst,
                    std::memory_order_seq_cst))
            {
                if (track_foreground)
                {
                    context->last_foreground_mutation_tick_ms.store(
                        static_cast<std::uint64_t>(GetTickCount64()),
                        std::memory_order_release);
                }
#ifdef APFSACCESS_FSHOST_UNIT_TEST
                if (g_mutation_admission_pause_hook != nullptr)
                {
                    g_mutation_admission_pause_hook(context);
                }
#endif
                observe_wait();
                return true;
            }
        }
    }

    MountContext* context_ = nullptr;
    bool track_foreground_ = false;
    bool acquired_ = false;
};

bool IsMutationWriteEnabled(const MountContext* c);
NTSTATUS HandleMutationWriteDisabled(MountContext* c, const wchar_t* operation);
std::shared_ptr<Node> TryGetNodeLocked(MountContext* c, const std::wstring& path);
std::shared_ptr<Node> FindNodeNormalized(MountContext* c, const std::wstring& normalized_path);
std::shared_ptr<Node> TryGetVisibleNodeLockedNormalized(MountContext* c, const std::wstring& normalized_path);
bool HasBlockedRecoveryEvidence(const MountContext& context);
std::string WideToUtf8(const std::wstring& in);
std::string EscapeJson(const std::string& value);
#ifdef APFSACCESS_HAS_RW_ENGINE
void RefreshReportedVolumeInfoFromMetadata(MountContext& ctx);
void ConfigureVolumeParamsForExplorer(MountContext& ctx, const FILETIME& now, FSP_FSCTL_VOLUME_PARAMS& vp);
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

bool IsHostMoveTraceEnabled()
{
    static const bool enabled = []()
    {
        wchar_t value[16]{};
        const auto chars = GetEnvironmentVariableW(L"APFSACCESS_TRACE_MOVES", value, static_cast<DWORD>(std::size(value)));
        if (chars > 0 && value[0] != L'\0')
        {
            return _wcsicmp(value, L"0") != 0 &&
                   _wcsicmp(value, L"false") != 0 &&
                   _wcsicmp(value, L"no") != 0;
        }

        std::error_code ec;
        auto marker = std::filesystem::temp_directory_path(ec);
        if (ec)
        {
            return false;
        }
        marker /= "ApfsAccess";
        marker /= "trace-moves.enabled";
        return std::filesystem::exists(marker, ec) && !ec;
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
#ifdef APFSACCESS_FSHOST_UNIT_TEST
    ++g_normalize_path_call_count_for_test;
#endif
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

std::wstring LowerPathKey(std::wstring p)
{
    std::transform(p.begin(), p.end(), p.begin(), [](wchar_t c) { return (wchar_t)towlower(c); });
    return p;
}

std::wstring Key(std::wstring p)
{
    return LowerPathKey(NormalizePath(p));
}

void SetNodePath(Node& node, const std::wstring& path)
{
    node.path = NormalizePath(path);
    node.path_key = LowerPathKey(node.path);
}

void SetNodePathNormalized(Node& node, const std::wstring& path)
{
    node.path = path;
    node.path_key = LowerPathKey(node.path);
}

const std::wstring& EnsureNodePathKey(Node& node)
{
    if (node.path_key.empty())
    {
        node.path_key = Key(node.path);
    }
    return node.path_key;
}

std::wstring NodePathKey(const Node& node)
{
    return node.path_key.empty() ? Key(node.path) : node.path_key;
}

void IndexNodeLocked(MountContext* c, const std::shared_ptr<Node>& node)
{
    if (!c || !node)
    {
        return;
    }
    c->nodes[EnsureNodePathKey(*node)] = node;
}

void EmplaceNodeLocked(MountContext* c, const std::shared_ptr<Node>& node)
{
    if (!c || !node)
    {
        return;
    }
    c->nodes.emplace(EnsureNodePathKey(*node), node);
}

void EraseIndexedNodeLocked(MountContext* c, const std::shared_ptr<Node>& node)
{
    if (!c || !node)
    {
        return;
    }
    c->nodes.erase(EnsureNodePathKey(*node));
}

std::wstring ToLowerInvariant(std::wstring value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](wchar_t c) { return (wchar_t)towlower(c); });
    return value;
}

std::wstring CanonicalStreamName(std::wstring stream_name)
{
    if (stream_name.empty())
    {
        return L"";
    }

    if (stream_name.front() != L':')
    {
        stream_name.insert(stream_name.begin(), L':');
    }

    const std::wstring lower = ToLowerInvariant(stream_name);
    constexpr const wchar_t* kDataSuffix = L":$DATA";
    constexpr std::size_t kDataSuffixLength = 6;
    const std::wstring data_suffix_lower = ToLowerInvariant(kDataSuffix);
    if (lower.size() < kDataSuffixLength ||
        lower.compare(lower.size() - kDataSuffixLength, kDataSuffixLength, data_suffix_lower) != 0)
    {
        stream_name += kDataSuffix;
    }

    return stream_name;
}

std::wstring StreamNameForWin32Path(const std::wstring& canonical_stream_name)
{
    auto name = canonical_stream_name;
    if (!name.empty() && name.front() == L':')
    {
        name.erase(name.begin());
    }

    const std::wstring lower = ToLowerInvariant(name);
    constexpr const wchar_t* kDataSuffix = L":$DATA";
    constexpr std::size_t kDataSuffixLength = 6;
    const std::wstring data_suffix_lower = ToLowerInvariant(kDataSuffix);
    if (lower.size() >= kDataSuffixLength &&
        lower.compare(lower.size() - kDataSuffixLength, kDataSuffixLength, data_suffix_lower) == 0)
    {
        name.resize(name.size() - kDataSuffixLength);
    }

    return name;
}

NamedStreamPath SplitNamedStreamPathNormalized(const std::wstring& path)
{
    NamedStreamPath result{};
    const auto leaf_start = path.find_last_of(L'\\');
    const auto search_start = leaf_start == std::wstring::npos ? 0 : leaf_start + 1;
    const auto colon = path.find(L':', search_start);
    if (colon == std::wstring::npos)
    {
        result.base_path = path;
        return result;
    }

    const auto stream_name = path.substr(colon);
    const auto canonical_stream_name = CanonicalStreamName(stream_name);
    if (canonical_stream_name.empty() || canonical_stream_name == L"::$DATA")
    {
        result.base_path = path.substr(0, colon);
        return result;
    }

    result.base_path = path.substr(0, colon);
    result.stream_name = canonical_stream_name;
    result.is_named_stream = true;
    return result;
}

NamedStreamPath SplitNamedStreamPath(const std::wstring& raw_path)
{
    return SplitNamedStreamPathNormalized(NormalizePath(raw_path));
}

bool LooksLikeNamedStreamArtifactName(const std::wstring& name)
{
    return SplitNamedStreamPath(L"\\" + name).is_named_stream;
}

bool LooksLikeNamedStreamArtifactNameFromLeaf(const std::wstring& leaf_name)
{
    if (leaf_name.empty())
    {
        return false;
    }

    const auto colon = leaf_name.find(L':');
    if (colon == std::wstring::npos)
    {
        return false;
    }

    const auto canonical_stream_name = CanonicalStreamName(leaf_name.substr(colon));
    return !canonical_stream_name.empty() && canonical_stream_name != L"::$DATA";
}

bool IsDescendantPathNormalized(const std::wstring& candidate_path, const std::wstring& ancestor_path)
{
    auto candidate_key = LowerPathKey(candidate_path);
    auto ancestor_key = LowerPathKey(ancestor_path);
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

bool IsDescendantPath(const std::wstring& candidate_path, const std::wstring& ancestor_path)
{
    return IsDescendantPathNormalized(NormalizePath(candidate_path), NormalizePath(ancestor_path));
}

bool IsRecycleBinPathNormalized(const std::wstring& path)
{
    const auto key = LowerPathKey(path);
    constexpr const wchar_t* kRecycleBinRoot = L"\\$recycle.bin";
    return key == kRecycleBinRoot ||
           key.rfind(std::wstring(kRecycleBinRoot) + L"\\", 0) == 0;
}

bool IsRecycleBinPath(const std::wstring& path)
{
    return IsRecycleBinPathNormalized(NormalizePath(path));
}

UINT32 BuildFileAttributes(const Node& node, bool read_only)
{
    UINT32 attributes = node.is_directory
        ? FILE_ATTRIBUTE_DIRECTORY
        : FILE_ATTRIBUTE_ARCHIVE;

    if (IsRecycleBinPathNormalized(node.path))
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

    if (!args.recovery_identity.empty())
    {
        const auto identity_hash = StableHashUtf16(kFnvOffset, args.recovery_identity);
        return identity_hash == 0 ? 1u : identity_hash;
    }

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

bool IsValidRecoveryIdentity(const std::wstring& value)
{
    constexpr wchar_t kPrefix[] = L"apfs-recovery-v1-";
    constexpr std::size_t kPrefixLength = 17;
    constexpr std::size_t kSha256Base64UrlLength = 43;
    constexpr wchar_t kCanonicalTailCharacters[] = L"AEIMQUYcgkosw048";
    if (value.size() != kPrefixLength + kSha256Base64UrlLength ||
        value.compare(0, kPrefixLength, kPrefix) != 0)
    {
        return false;
    }

    const auto digest_begin = value.begin() + static_cast<std::ptrdiff_t>(kPrefixLength);
    if (!std::all_of(
            digest_begin,
            value.end(),
            [](wchar_t ch)
            {
                return (ch >= L'A' && ch <= L'Z') ||
                       (ch >= L'a' && ch <= L'z') ||
                       (ch >= L'0' && ch <= L'9') ||
                       ch == L'-' ||
                       ch == L'_';
            }))
    {
        return false;
    }

    return std::wcschr(kCanonicalTailCharacters, value.back()) != nullptr;
}

std::wstring BuildLegacyWalVolumeIdentity(const Arguments& args)
{
    std::wostringstream identity;
    identity << L"device=" << args.device
             << L"|offset=" << args.device_offset_bytes
             << L"|volume=" << args.volume
             << L"|serial=" << BuildStableVolumeSerial(args);
    return identity.str();
}

std::wstring BuildWalVolumeIdentity(const Arguments& args)
{
    return args.recovery_identity.empty()
        ? BuildLegacyWalVolumeIdentity(args)
        : args.recovery_identity;
}

std::wstring BuildRecoveryStorageKey(const Arguments& args)
{
    constexpr std::size_t kRecoveryIdentityPrefixLength = 17;
    if (!IsValidRecoveryIdentity(args.recovery_identity))
    {
        throw std::invalid_argument("recovery identity is not canonical");
    }

    return L"apfs_recovery_v1_" +
        args.recovery_identity.substr(kRecoveryIdentityPrefixLength);
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

#ifdef APFSACCESS_HAS_RW_ENGINE
std::filesystem::path BuildLegacyPayloadSpoolSessionRoot(
    const Arguments& args,
    const std::filesystem::path& base_root)
{
    auto legacy_args = args;
    legacy_args.recovery_identity.clear();
    const auto spool_session = SanitizeFileComponent(args.device) +
        L"_" +
        SanitizeFileComponent(args.volume) +
        L"_" +
        std::to_wstring(args.device_offset_bytes) +
        L"_" +
        std::to_wstring(BuildStableVolumeSerial(legacy_args));
    return base_root / spool_session;
}

std::filesystem::path BuildPayloadSpoolSessionRoot(
    const Arguments& args,
    const std::filesystem::path& base_root)
{
    if (!args.recovery_identity.empty())
    {
        return base_root / BuildRecoveryStorageKey(args);
    }

    return BuildLegacyPayloadSpoolSessionRoot(args, base_root);
}
#endif

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

bool HasPayloadWriteIntent(const OpenContext* open_ctx)
{
    return open_ctx &&
           (open_ctx->allow_write_data ||
            open_ctx->allow_append_data ||
            open_ctx->allow_set_file_size);
}

bool HasConflictingCreateTypeOptions(UINT32 create_options)
{
    return ((create_options & FILE_DIRECTORY_FILE) != 0) &&
           ((create_options & FILE_NON_DIRECTORY_FILE) != 0);
}

bool IsReservedWin32DeviceName(const std::wstring& component)
{
    if (component.empty())
    {
        return false;
    }

    auto base = component;
    const auto dot = base.find(L'.');
    if (dot != std::wstring::npos)
    {
        base.resize(dot);
    }

    while (!base.empty() && (base.back() == L' ' || base.back() == L'.'))
    {
        base.pop_back();
    }

    if (base.empty())
    {
        return false;
    }

    if (!_wcsicmp(base.c_str(), L"CON") ||
        !_wcsicmp(base.c_str(), L"PRN") ||
        !_wcsicmp(base.c_str(), L"AUX") ||
        !_wcsicmp(base.c_str(), L"NUL"))
    {
        return true;
    }

    if (base.size() == 4)
    {
        const auto prefix = base.substr(0, 3);
        const auto suffix = base[3];
        if ((suffix >= L'1' && suffix <= L'9') &&
            (!_wcsicmp(prefix.c_str(), L"COM") || !_wcsicmp(prefix.c_str(), L"LPT")))
        {
            return true;
        }
    }

    return false;
}

bool IsValidWin32PathComponentForMutation(const std::wstring& component)
{
    if (component.empty() || component == L"." || component == L"..")
    {
        return false;
    }
    if (component.size() > 255)
    {
        return false;
    }
    if (component.back() == L' ' || component.back() == L'.')
    {
        return false;
    }
    if (IsReservedWin32DeviceName(component))
    {
        return false;
    }

    constexpr wchar_t kInvalid[] = L"<>:\"/\\|?*";
    for (const auto ch : component)
    {
        if (ch < 0x20 || std::wcschr(kInvalid, ch))
        {
            return false;
        }
    }

    return true;
}

bool IsValidNormalizedWin32PathForMutation(const std::wstring& path)
{
    if (path == L"\\")
    {
        return true;
    }
    if (path.empty() || path.front() != L'\\')
    {
        return false;
    }

    std::size_t start = 1;
    while (start <= path.size())
    {
        const auto end = path.find(L'\\', start);
        const auto component = path.substr(
            start,
            end == std::wstring::npos ? std::wstring::npos : end - start);
        if (!IsValidWin32PathComponentForMutation(component))
        {
            return false;
        }
        if (end == std::wstring::npos)
        {
            break;
        }
        start = end + 1;
    }

    return true;
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

void MarkOpenContextMutation(OpenContext* open_ctx) noexcept
{
    if (open_ctx)
    {
        open_ctx->mutation_observed.store(true, std::memory_order_release);
    }
}

bool RequiresHydrationHandleForOpen(const OpenContext* open_ctx)
{
    if (!open_ctx)
    {
        return true;
    }

    return open_ctx->allow_read_data ||
           open_ctx->allow_write_data ||
           open_ctx->allow_append_data ||
           open_ctx->allow_set_file_size ||
           open_ctx->named_stream;
}

bool CanUseMetadataReadFallbackForOpen(
    const OpenContext* open_ctx,
    UINT32 create_options,
    bool has_metadata_store)
{
    if (!open_ctx)
    {
        return false;
    }

    const bool payload_write_requested =
        open_ctx->allow_write_data ||
        open_ctx->allow_append_data ||
        open_ctx->allow_set_file_size;
    const bool metadata_only_write_requested =
        open_ctx->allow_set_basic_info &&
        !payload_write_requested;
    const bool sequential_move_source_probe =
        payload_write_requested &&
        open_ctx->allow_set_basic_info &&
        (create_options & FILE_SEQUENTIAL_ONLY) != 0;
    return has_metadata_store &&
           open_ctx->allow_read_data &&
           !open_ctx->named_stream &&
           (!payload_write_requested ||
            open_ctx->allow_delete ||
            metadata_only_write_requested ||
            sequential_move_source_probe);
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

enum class RecoveryMarkerLoadStatus
{
    Missing,
    Loaded,
    Invalid,
};

RecoveryMarkerLoadStatus LoadRecoveryMarkerState(
    const std::filesystem::path& marker_path,
    RecoveryMarkerState& state)
{
    state = RecoveryMarkerState{};
    std::error_code ec;
    const auto exists = std::filesystem::exists(marker_path, ec);
    if (!exists && !ec)
    {
        return RecoveryMarkerLoadStatus::Missing;
    }
    if (ec)
    {
        return RecoveryMarkerLoadStatus::Invalid;
    }

    const auto regular_file = std::filesystem::is_regular_file(marker_path, ec);
    if (ec || !regular_file)
    {
        return RecoveryMarkerLoadStatus::Invalid;
    }
    const auto marker_size = std::filesystem::file_size(marker_path, ec);
    if (ec || marker_size > kRecoveryMarkerMaxBytes)
    {
        return RecoveryMarkerLoadStatus::Invalid;
    }

    std::ifstream in(marker_path, std::ios::binary);
    if (!in.good())
    {
        return RecoveryMarkerLoadStatus::Invalid;
    }

    bool dirty_seen = false;
    bool commit_xid_seen = false;
    std::string line;
    while (std::getline(in, line))
    {
        if (!line.empty() && line.back() == '\r')
        {
            line.pop_back();
        }
        if (line.empty())
        {
            return RecoveryMarkerLoadStatus::Invalid;
        }
        auto split = line.find('=');
        if (split == std::string::npos)
        {
            return RecoveryMarkerLoadStatus::Invalid;
        }

        auto key = line.substr(0, split);
        auto value = line.substr(split + 1);
        if (key == "dirty")
        {
            if (dirty_seen ||
                (value != "0" && value != "1" &&
                 value != "true" && value != "false" &&
                 value != "True" && value != "False"))
            {
                return RecoveryMarkerLoadStatus::Invalid;
            }
            dirty_seen = true;
            state.dirty = (value == "1" || value == "true" || value == "True");
            continue;
        }

        if (key == "lastCommitXid")
        {
            if (commit_xid_seen)
            {
                return RecoveryMarkerLoadStatus::Invalid;
            }
            commit_xid_seen = true;
            if (value.empty())
            {
                state.last_commit_xid.reset();
                continue;
            }
            if (!std::all_of(value.begin(), value.end(), [](char ch)
                {
                    return ch >= '0' && ch <= '9';
                }))
            {
                return RecoveryMarkerLoadStatus::Invalid;
            }
            try
            {
                std::size_t consumed = 0;
                const auto parsed = std::stoull(value, &consumed);
                if (consumed != value.size())
                {
                    return RecoveryMarkerLoadStatus::Invalid;
                }
                state.last_commit_xid = static_cast<std::uint64_t>(parsed);
            }
            catch (...)
            {
                return RecoveryMarkerLoadStatus::Invalid;
            }
            continue;
        }

        return RecoveryMarkerLoadStatus::Invalid;
    }

    if (in.bad() || !dirty_seen || !commit_xid_seen)
    {
        return RecoveryMarkerLoadStatus::Invalid;
    }
    return RecoveryMarkerLoadStatus::Loaded;
}

bool TryLoadRecoveryMarkerState(
    const std::filesystem::path& marker_path,
    RecoveryMarkerState& state)
{
    return LoadRecoveryMarkerState(marker_path, state) == RecoveryMarkerLoadStatus::Loaded;
}

void ResetRecoveryMarkerCache(MountContext* context)
{
    if (!context)
    {
        return;
    }

    context->recovery_marker_cache_handle.reset();
    context->recovery_marker_cache_path.clear();
    context->recovery_marker_cache_size = 0;
    context->recovery_marker_cache_last_write_time = 0;
    context->recovery_marker_cache_change_time = 0;
    context->recovery_marker_last_deep_validation_tick_ms = 0;
}

bool RefreshRecoveryMarkerCache(
    MountContext* context,
    const std::filesystem::path& marker_path)
{
    if (!context)
    {
        return false;
    }

    HANDLE handle = CreateFileW(
        marker_path.wstring().c_str(),
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (handle == INVALID_HANDLE_VALUE)
    {
        ResetRecoveryMarkerCache(context);
        return false;
    }

    FILE_STANDARD_INFO standard_info{};
    FILE_BASIC_INFO basic_info{};
    if (!GetFileInformationByHandleEx(
            handle,
            FileStandardInfo,
            &standard_info,
            sizeof(standard_info)) ||
        !GetFileInformationByHandleEx(
            handle,
            FileBasicInfo,
            &basic_info,
            sizeof(basic_info)) ||
        standard_info.DeletePending ||
        standard_info.EndOfFile.QuadPart < 0)
    {
        CloseHandle(handle);
        ResetRecoveryMarkerCache(context);
        return false;
    }

    context->recovery_marker_cache_handle = TakeWinHandle(handle);
    context->recovery_marker_cache_path = marker_path;
    context->recovery_marker_cache_size =
        static_cast<std::uint64_t>(standard_info.EndOfFile.QuadPart);
    context->recovery_marker_cache_last_write_time = basic_info.LastWriteTime.QuadPart;
    context->recovery_marker_cache_change_time = basic_info.ChangeTime.QuadPart;
    return true;
}

bool RecoveryMarkerCacheIsValid(
    MountContext* context,
    const std::filesystem::path& marker_path)
{
    if (!context ||
        !context->recovery_marker_cache_handle ||
        context->recovery_marker_cache_path != marker_path)
    {
        return false;
    }

    FILE_STANDARD_INFO standard_info{};
    FILE_BASIC_INFO basic_info{};
    FILE_ID_INFO cached_id{};
    const auto handle = static_cast<HANDLE>(context->recovery_marker_cache_handle.get());
    if (!GetFileInformationByHandleEx(
            handle,
            FileStandardInfo,
            &standard_info,
            sizeof(standard_info)) ||
        !GetFileInformationByHandleEx(
            handle,
            FileBasicInfo,
            &basic_info,
            sizeof(basic_info)) ||
        !GetFileInformationByHandleEx(
            handle,
            FileIdInfo,
            &cached_id,
            sizeof(cached_id)) ||
        standard_info.DeletePending ||
        standard_info.EndOfFile.QuadPart < 0)
    {
        return false;
    }

    auto path_handle = TakeWinHandle(CreateFileW(
        marker_path.wstring().c_str(),
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr));
    if (!path_handle)
    {
        return false;
    }

    FILE_ID_INFO path_id{};
    if (!GetFileInformationByHandleEx(
            static_cast<HANDLE>(path_handle.get()),
            FileIdInfo,
            &path_id,
            sizeof(path_id)))
    {
        return false;
    }

    return static_cast<std::uint64_t>(standard_info.EndOfFile.QuadPart) ==
               context->recovery_marker_cache_size &&
           basic_info.LastWriteTime.QuadPart ==
               context->recovery_marker_cache_last_write_time &&
           basic_info.ChangeTime.QuadPart ==
               context->recovery_marker_cache_change_time &&
           cached_id.VolumeSerialNumber == path_id.VolumeSerialNumber &&
           std::memcmp(
               cached_id.FileId.Identifier,
               path_id.FileId.Identifier,
               sizeof(cached_id.FileId.Identifier)) == 0;
}

bool RecoveryMarkerFastPathFileIsPresent(const std::filesystem::path& marker_path)
{
    const auto attributes = GetFileAttributesW(marker_path.wstring().c_str());
    return attributes != INVALID_FILE_ATTRIBUTES &&
           (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0 &&
           (attributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0;
}

bool PersistRecoveryMarkerState(MountContext* context, const std::filesystem::path& marker_path, const RecoveryMarkerState& state)
{
    ScopedPerfTimer perf_scope(context ? &context->perf_recovery_marker : nullptr);
    if (context &&
        context->last_recovery_marker_dirty.has_value() &&
        context->last_recovery_marker_dirty.value() == state.dirty &&
        context->last_recovery_marker_commit_xid == state.last_commit_xid &&
        RecoveryMarkerCacheIsValid(context, marker_path))
    {
        return true;
    }

    try
    {
        std::error_code ec;
        if (marker_path.has_parent_path())
        {
            std::filesystem::create_directories(marker_path.parent_path(), ec);
            if (ec)
            {
                return false;
            }
        }

        std::ostringstream serialized;
        serialized << "dirty=" << (state.dirty ? "1" : "0") << "\n";
        serialized << "lastCommitXid=";
        if (state.last_commit_xid.has_value())
        {
            serialized << *state.last_commit_xid;
        }
        serialized << "\n";
        const auto bytes = serialized.str();

        const auto sequence = g_recovery_marker_temp_sequence.fetch_add(
            1,
            std::memory_order_relaxed);
        const auto file_name = marker_path.filename().wstring().empty()
            ? std::wstring(L"recovery.marker")
            : marker_path.filename().wstring();
        const auto temp_path = marker_path.parent_path() /
            (file_name + L".tmp." +
             std::to_wstring(GetCurrentProcessId()) + L"." +
             std::to_wstring(GetCurrentThreadId()) + L"." +
             std::to_wstring(sequence));

        HANDLE temp_handle = CreateFileW(
            temp_path.wstring().c_str(),
            GENERIC_WRITE,
            0,
            nullptr,
            CREATE_NEW,
            FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_WRITE_THROUGH,
            nullptr);
        if (temp_handle == INVALID_HANDLE_VALUE)
        {
            return false;
        }
        ScopeExit remove_temp{[&]()
        {
            if (temp_handle != INVALID_HANDLE_VALUE)
            {
                CloseHandle(temp_handle);
            }
            std::error_code remove_ec;
            std::filesystem::remove(temp_path, remove_ec);
        }};

        const auto* data = reinterpret_cast<const std::byte*>(bytes.data());
        std::size_t remaining = bytes.size();
        while (remaining > 0)
        {
            const auto chunk = static_cast<DWORD>(std::min<std::size_t>(remaining, 1u << 20));
            DWORD written = 0;
            if (!WriteFile(
                    temp_handle,
                    data,
                    chunk,
                    &written,
                    nullptr) ||
                written != chunk)
            {
                return false;
            }
            data += written;
            remaining -= written;
        }
#ifdef APFSACCESS_FSHOST_UNIT_TEST
        if (context && context->test_force_recovery_marker_finalize_failure)
        {
            return false;
        }
#endif
        if (!FlushFileBuffers(temp_handle) || !CloseHandle(temp_handle))
        {
            return false;
        }
        temp_handle = INVALID_HANDLE_VALUE;

        if (context)
        {
            ResetRecoveryMarkerCache(context);
        }
        if (!MoveFileExW(
                temp_path.wstring().c_str(),
                marker_path.wstring().c_str(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        {
            if (context)
            {
                (void)RefreshRecoveryMarkerCache(context, marker_path);
            }
            return false;
        }

        if (context)
        {
            context->last_recovery_marker_dirty = state.dirty;
            context->last_recovery_marker_commit_xid = state.last_commit_xid;
            (void)RefreshRecoveryMarkerCache(context, marker_path);
        }
        return true;
    }
    catch (...)
    {
        return false;
    }
}

enum class LoadedRecoveryMarkerAction
{
    Clean,
    NativeWriteUnavailable,
    FailClosed,
    ReplayIfSafe,
    BestEffort,
};

LoadedRecoveryMarkerAction ApplyLoadedRecoveryMarkerState(
    MountContext& context,
    const RecoveryMarkerState& marker_state)
{
    std::lock_guard<std::recursive_mutex> runtime_lock(context.runtime_state_mutex);
    context.pending_native_writes = marker_state.dirty;
    context.runtime_last_commit_xid = marker_state.last_commit_xid;
    context.last_recovery_marker_dirty = marker_state.dirty;
    context.last_recovery_marker_commit_xid = marker_state.last_commit_xid;
    if (!marker_state.dirty)
    {
        return LoadedRecoveryMarkerAction::Clean;
    }

    context.recovery_active = true;
    context.runtime_recovery_reason = L"RecoveryMarkerDirty";
    context.runtime_last_recovery_action = L"RecoveryMarkerDetected";
    if (!context.native_write_enabled)
    {
        return LoadedRecoveryMarkerAction::NativeWriteUnavailable;
    }

    if (IsCrashReplayModeReplayIfSafe(context.args.write_crash_replay_mode))
    {
        return LoadedRecoveryMarkerAction::ReplayIfSafe;
    }
    if (IsRecoveryPolicyFailClosed(context.args.write_recovery_policy))
    {
        context.write_degraded = true;
        context.native_write_enabled = false;
        context.overlay_write_enabled = false;
        return LoadedRecoveryMarkerAction::FailClosed;
    }
    return LoadedRecoveryMarkerAction::BestEffort;
}

struct RecoveryMarkerStartupResult
{
    RecoveryMarkerLoadStatus load_status = RecoveryMarkerLoadStatus::Missing;
    RecoveryMarkerState state{};
    LoadedRecoveryMarkerAction action = LoadedRecoveryMarkerAction::Clean;
};

RecoveryMarkerStartupResult LoadRecoveryMarkerAtStartup(MountContext& context)
{
    RecoveryMarkerStartupResult result{};
    result.load_status = LoadRecoveryMarkerState(
        context.recovery_marker_file,
        result.state);
    if (result.load_status == RecoveryMarkerLoadStatus::Loaded)
    {
        result.action = ApplyLoadedRecoveryMarkerState(context, result.state);
        (void)RefreshRecoveryMarkerCache(&context, context.recovery_marker_file);
    }
    else if (result.load_status == RecoveryMarkerLoadStatus::Invalid)
    {
        std::lock_guard<std::recursive_mutex> runtime_lock(context.runtime_state_mutex);
        ResetRecoveryMarkerCache(&context);
        context.recovery_marker_blocked = true;
        context.pending_native_writes = true;
        context.recovery_active = true;
        context.write_degraded = true;
        context.native_write_enabled = false;
        context.overlay_write_enabled = false;
        context.runtime_recovery_reason = L"RecoveryMarkerInvalid";
        context.runtime_last_recovery_action = L"RecoveryMarkerInvalidAtStartup";
        result.action = LoadedRecoveryMarkerAction::FailClosed;
    }
    return result;
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

NativeCommitOriginCounter& ResolveNativeCommitOriginCounter(MountContext& context, const wchar_t* origin)
{
    if (origin && !_wcsicmp(origin, L"Close"))
    {
        return context.perf_commit_origin_close;
    }
    if (origin && !_wcsicmp(origin, L"CloseDeferred"))
    {
        return context.perf_commit_origin_close_deferred;
    }
    if (origin && !_wcsicmp(origin, L"Flush"))
    {
        return context.perf_commit_origin_flush;
    }
    if (origin && !_wcsicmp(origin, L"Rename"))
    {
        return context.perf_commit_origin_rename;
    }
    if (origin && !_wcsicmp(origin, L"Shutdown"))
    {
        return context.perf_commit_origin_shutdown;
    }
    if (origin && !_wcsicmp(origin, L"DirtyLimit"))
    {
        return context.perf_commit_origin_dirty_limit;
    }
    return context.perf_commit_origin_other;
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

std::wstring ResolveCommitFailureReasonStatus(const MountContext& context)
{
#ifdef APFSACCESS_HAS_RW_ENGINE
    std::lock_guard<std::mutex> metadata_lock(context.metadata_mutex);
    if (context.metadata_store)
    {
        return context.metadata_store->LastCommitFailureReason();
    }
#else
    (void)context;
#endif
    return {};
}

std::wstring ResolveCommitFailureDetailStatus(const MountContext& context)
{
#ifdef APFSACCESS_HAS_RW_ENGINE
    std::lock_guard<std::mutex> metadata_lock(context.metadata_mutex);
    if (context.metadata_store)
    {
        return context.metadata_store->LastCommitFailureDetail();
    }
#else
    (void)context;
#endif
    return {};
}

std::optional<std::uint64_t> ResolveCommitFailureObjectIdStatus(const MountContext& context)
{
#ifdef APFSACCESS_HAS_RW_ENGINE
    std::lock_guard<std::mutex> metadata_lock(context.metadata_mutex);
    if (context.metadata_store)
    {
        return context.metadata_store->LastCommitFailureObjectId();
    }
#else
    (void)context;
#endif
    return std::nullopt;
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

std::wstring ResolveMetadataRecoveryReasonOrFallback(
    const MountContext& context,
    const std::wstring& fallback)
{
#ifdef APFSACCESS_HAS_RW_ENGINE
    if (context.metadata_store)
    {
        const auto reason = context.metadata_store->RecoveryReason();
        if (!reason.empty())
        {
            return reason;
        }
    }
#else
    (void)context;
#endif

    return fallback;
}

void RecordVolumeStateBootstrapFailure(MountContext& context)
{
    const auto reason = ResolveMetadataRecoveryReasonOrFallback(context, L"VolumeStateLoadFailed");

    if (!context.args.readwrite)
    {
        std::wcerr << L"[FsHost] RW engine bootstrap notice: volume state not ready in read-only mode (reason="
            << reason
            << L"); native metadata overlay is unavailable, but read-only filesystem enumeration may continue."
            << std::endl;
        return;
    }

    if (HasBlockedRecoveryEvidence(context))
    {
        std::wcerr << L"[FsHost] RW engine bootstrap warning: volume state not ready; preserving blocked recovery evidence."
            << std::endl;
        return;
    }

    {
        std::lock_guard<std::recursive_mutex> runtime_lock(context.runtime_state_mutex);
        context.recovery_active = true;
        context.runtime_recovery_reason = reason;
        context.runtime_last_recovery_action = L"BootstrapVolumeStateUnavailable";
    }
    std::wcerr << L"[FsHost] RW engine bootstrap warning: volume state not ready (reason="
        << reason
        << L"); native APFS metadata enumeration remains unavailable."
        << std::endl;
}

struct NativeDirtyStatus
{
    std::uint64_t transaction_journal_pending_count = 0;
    std::uint64_t metadata_pending_count = 0;
    std::uint64_t dirty_transaction_count = 0;
    bool has_pending_metadata_mutations = false;
    bool has_any_dirty_work = false;
    bool shutdown_drain_active = false;
    bool close_commit_deferred = false;
    std::uint64_t deferred_close_commit_count = 0;
    std::uint32_t in_flight_mutation_callbacks = 0;
    std::uint64_t wal_accepted_sequence = 0;
    std::uint64_t wal_apfs_durable_sequence = 0;
    std::uint64_t wal_cleanup_sequence = 0;
    bool wal_recovery_state_valid = true;
    std::uint64_t wal_durable_append_count = 0;
    std::uint64_t wal_durable_append_microseconds = 0;
    std::uint64_t wal_durable_append_max_microseconds = 0;
    std::uint64_t wal_finalization_coverage_cache_hit_count = 0;
    std::uint64_t wal_finalization_coverage_scan_count = 0;
    std::uint64_t wal_finalization_coverage_scan_microseconds = 0;
    bool deferred_commit_requested = false;
    bool deferred_commit_in_flight = false;
    bool deferred_commit_force_now = false;
    std::uint64_t deferred_commit_requested_target = 0;
    std::uint64_t deferred_commit_completed_target = 0;
    std::uint64_t deferred_commit_failed_target = 0;
    std::uint64_t deferred_commit_in_flight_target = 0;
    std::uint64_t deferred_commit_first_request_tick_ms = 0;
    std::uint64_t deferred_commit_deadline_tick_ms = 0;
    NTSTATUS deferred_commit_last_status = STATUS_SUCCESS;
};

NativeDirtyStatus SnapshotNativeDirtyStatus(const MountContext& context)
{
#ifdef APFSACCESS_FSHOST_UNIT_TEST
    ++g_native_dirty_status_snapshot_count_for_test;
#endif
#ifdef APFSACCESS_HAS_RW_ENGINE
    std::uint64_t tx_pending = 0;
    std::uint64_t metadata_pending = 0;
    apfsaccess::rw::TransactionManager::DurabilityWatermarks watermarks{};
    bool wal_recovery_state_valid = true;
    std::uint64_t wal_durable_append_count = 0;
    std::uint64_t wal_durable_append_microseconds = 0;
    std::uint64_t wal_durable_append_max_microseconds = 0;
    std::uint64_t wal_finalization_coverage_cache_hit_count = 0;
    std::uint64_t wal_finalization_coverage_scan_count = 0;
    std::uint64_t wal_finalization_coverage_scan_microseconds = 0;
    bool deferred_commit_requested = false;
    bool deferred_commit_in_flight = false;
    bool deferred_commit_force_now = false;
    std::uint64_t deferred_commit_requested_target = 0;
    std::uint64_t deferred_commit_completed_target = 0;
    std::uint64_t deferred_commit_failed_target = 0;
    std::uint64_t deferred_commit_in_flight_target = 0;
    std::uint64_t deferred_commit_first_request_tick_ms = 0;
    std::uint64_t deferred_commit_deadline_tick_ms = 0;
    NTSTATUS deferred_commit_last_status = STATUS_SUCCESS;
    {
        std::lock_guard<std::mutex> tx_lock(context.tx_mutex);
        if (context.tx_manager)
        {
            tx_pending = static_cast<std::uint64_t>(context.tx_manager->PendingMutationCount());
            watermarks = context.tx_manager->Watermarks();
            if (watermarks.accepted_sequence > watermarks.apfs_durable_sequence ||
                watermarks.apfs_durable_sequence > watermarks.cleanup_sequence)
            {
                tx_pending = (std::max)(tx_pending, std::uint64_t{1});
            }
            wal_recovery_state_valid = context.tx_manager->RecoveryStateValid();
            wal_durable_append_count = context.tx_manager->DurableJournalAppendCount();
            wal_durable_append_microseconds = context.tx_manager->DurableJournalAppendMicroseconds();
            wal_durable_append_max_microseconds = context.tx_manager->DurableJournalAppendMaxMicroseconds();
            wal_finalization_coverage_cache_hit_count = context.tx_manager->FinalizationCoverageCacheHitCount();
            wal_finalization_coverage_scan_count = context.tx_manager->FinalizationCoverageWalScanCount();
            wal_finalization_coverage_scan_microseconds = context.tx_manager->FinalizationCoverageWalScanMicroseconds();
        }
    }
    {
        std::lock_guard<std::mutex> metadata_lock(context.metadata_mutex);
        if (context.metadata_store)
        {
            metadata_pending = static_cast<std::uint64_t>(context.metadata_store->PendingMutationCount());
        }
    }
    {
        std::lock_guard<std::mutex> deferred_lock(context.deferred_commit_mutex);
        deferred_commit_requested = context.deferred_commit_requested;
        deferred_commit_in_flight = context.deferred_commit_in_flight;
        deferred_commit_force_now = context.deferred_commit_force_now;
        deferred_commit_requested_target = context.deferred_commit_requested_target;
        deferred_commit_completed_target = context.deferred_commit_completed_target;
        deferred_commit_failed_target = context.deferred_commit_failed_target;
        deferred_commit_in_flight_target = context.deferred_commit_in_flight_target;
        deferred_commit_first_request_tick_ms = context.deferred_commit_first_request_tick_ms;
        deferred_commit_deadline_tick_ms = context.deferred_commit_deadline_tick_ms;
        deferred_commit_last_status = context.deferred_commit_last_status;
    }

    const auto admission_state =
        context.mutation_admission_state.load(std::memory_order_acquire);
    const auto snapshot = apfsaccess::rw::WritePipeline::SnapshotDirtyStatus({
        tx_pending,
        metadata_pending,
        MutationAdmissionIsDraining(admission_state),
        context.close_commit_deferred.load(std::memory_order_acquire),
        context.deferred_close_commit_count.load(std::memory_order_acquire),
        MutationAdmissionCount(admission_state),
    });

    return {
        snapshot.transaction_journal_pending_count,
        snapshot.metadata_pending_count,
        snapshot.dirty_transaction_count,
        snapshot.has_pending_metadata_mutations,
        snapshot.has_any_dirty_work,
        snapshot.shutdown_drain_active,
        snapshot.close_commit_deferred,
        snapshot.deferred_close_commit_count,
        snapshot.in_flight_mutation_callbacks,
        watermarks.accepted_sequence,
        watermarks.apfs_durable_sequence,
        watermarks.cleanup_sequence,
        wal_recovery_state_valid,
        wal_durable_append_count,
        wal_durable_append_microseconds,
        wal_durable_append_max_microseconds,
        wal_finalization_coverage_cache_hit_count,
        wal_finalization_coverage_scan_count,
        wal_finalization_coverage_scan_microseconds,
        deferred_commit_requested,
        deferred_commit_in_flight,
        deferred_commit_force_now,
        deferred_commit_requested_target,
        deferred_commit_completed_target,
        deferred_commit_failed_target,
        deferred_commit_in_flight_target,
        deferred_commit_first_request_tick_ms,
        deferred_commit_deadline_tick_ms,
        deferred_commit_last_status,
    };
#else
    NativeDirtyStatus fallback{};
    const auto admission_state =
        context.mutation_admission_state.load(std::memory_order_acquire);
    fallback.shutdown_drain_active = MutationAdmissionIsDraining(admission_state);
    fallback.in_flight_mutation_callbacks = MutationAdmissionCount(admission_state);
    return fallback;
#endif
}

struct PayloadSpoolStatusCounters
{
    std::uint64_t spool_bytes = 0;
    std::size_t dirty_range_count = 0;
    std::uint64_t oldest_dirty_age_ms = 0;
    std::uint64_t cleanup_failures = 0;
    std::uint64_t mutex_wait_count = 0;
    std::uint64_t mutex_wait_microseconds = 0;
    std::uint64_t mutex_wait_max_microseconds = 0;
    std::uint64_t mutex_wait_p50_microseconds = 0;
    std::uint64_t mutex_wait_p95_microseconds = 0;
    std::uint64_t bytes_since_sync = 0;
    std::uint64_t appends_since_sync = 0;
    std::uint64_t append_direct_count = 0;
    std::uint64_t append_merged_count = 0;
    std::uint64_t append_stream_open_count = 0;
    std::uint64_t append_stream_flush_count = 0;
    std::uint64_t payload_only_flush_count = 0;
    std::uint64_t payload_only_flush_microseconds = 0;
    std::uint64_t payload_only_flush_max_microseconds = 0;
    std::uint64_t durable_flush_count = 0;
    std::uint64_t durable_flush_microseconds = 0;
    std::uint64_t durable_flush_max_microseconds = 0;
    std::uint64_t spool_sync_count = 0;
    std::uint64_t spool_sync_microseconds = 0;
    std::uint64_t spool_sync_max_microseconds = 0;
    std::uint64_t spool_sync_handle_flush_count = 0;
    std::uint64_t spool_sync_reopen_count = 0;
    std::uint64_t index_persist_count = 0;
    std::uint64_t index_persist_bytes = 0;
    std::uint64_t index_persist_microseconds = 0;
    std::uint64_t index_persist_max_microseconds = 0;
    bool index_dirty = false;
    bool recovery_required = false;
};

PayloadSpoolStatusCounters SnapshotPayloadSpoolStatusCounters(const MountContext& context)
{
#ifdef APFSACCESS_HAS_RW_ENGINE
    if (!context.payload_spool)
    {
        return {};
    }
    const auto counters = context.payload_spool->SnapshotCounters();
    return {
        counters.spool_bytes,
        counters.dirty_range_count,
        counters.oldest_dirty_age_ms,
        counters.cleanup_failures,
        counters.mutex_wait_count,
        counters.mutex_wait_microseconds,
        counters.mutex_wait_max_microseconds,
        counters.mutex_wait_p50_microseconds,
        counters.mutex_wait_p95_microseconds,
        counters.bytes_since_sync,
        counters.appends_since_sync,
        counters.append_direct_count,
        counters.append_merged_count,
        counters.append_stream_open_count,
        counters.append_stream_flush_count,
        counters.payload_only_flush_count,
        counters.payload_only_flush_microseconds,
        counters.payload_only_flush_max_microseconds,
        counters.durable_flush_count,
        counters.durable_flush_microseconds,
        counters.durable_flush_max_microseconds,
        counters.spool_sync_count,
        counters.spool_sync_microseconds,
        counters.spool_sync_max_microseconds,
        counters.spool_sync_handle_flush_count,
        counters.spool_sync_reopen_count,
        counters.index_persist_count,
        counters.index_persist_bytes,
        counters.index_persist_microseconds,
        counters.index_persist_max_microseconds,
        counters.index_dirty,
        counters.recovery_required,
    };
#else
    (void)context;
    return {};
#endif
}

CallbackStatusSnapshot BuildCallbackStatusSnapshot(
    const MountContext& context,
    const NativeDirtyStatus& dirty_status,
    const PayloadSpoolStatusCounters& payload_spool,
    bool recovery_active,
    std::optional<std::uint64_t> last_commit_xid)
{
    CallbackStatusSnapshot snapshot{};
    snapshot.readwrite = context.args.readwrite;
    snapshot.overlay_write_enabled = context.overlay_write_enabled;
    snapshot.native_write_enabled = context.native_write_enabled;
    snapshot.recovery_active = recovery_active;
    snapshot.write_degraded = context.write_degraded;
    snapshot.pending_native_writes = context.pending_native_writes;
    snapshot.mount_ready = context.mount_ready.load(std::memory_order_acquire);
    snapshot.shutdown_drain_active = dirty_status.shutdown_drain_active;
    snapshot.close_commit_deferred = dirty_status.close_commit_deferred;
    snapshot.payload_spool_index_dirty = payload_spool.index_dirty;
    snapshot.payload_spool_recovery_required = payload_spool.recovery_required;
    snapshot.has_last_commit_xid = last_commit_xid.has_value();
    snapshot.last_commit_xid = last_commit_xid.value_or(0);
    snapshot.transaction_journal_pending_count = dirty_status.transaction_journal_pending_count;
    snapshot.metadata_pending_count = dirty_status.metadata_pending_count;
    snapshot.dirty_transaction_count = dirty_status.dirty_transaction_count;
    snapshot.deferred_close_commit_count = dirty_status.deferred_close_commit_count;
    snapshot.deferred_rename_commit_count =
        context.deferred_rename_commit_count.load(std::memory_order_relaxed);
    snapshot.in_flight_mutation_callbacks = dirty_status.in_flight_mutation_callbacks;
    snapshot.deferred_commit_requested = dirty_status.deferred_commit_requested;
    snapshot.deferred_commit_in_flight = dirty_status.deferred_commit_in_flight;
    snapshot.deferred_commit_force_now = dirty_status.deferred_commit_force_now;
    snapshot.deferred_commit_requested_target = dirty_status.deferred_commit_requested_target;
    snapshot.deferred_commit_completed_target = dirty_status.deferred_commit_completed_target;
    snapshot.deferred_commit_failed_target = dirty_status.deferred_commit_failed_target;
    snapshot.deferred_commit_in_flight_target = dirty_status.deferred_commit_in_flight_target;
    snapshot.deferred_commit_first_request_tick_ms = dirty_status.deferred_commit_first_request_tick_ms;
    snapshot.deferred_commit_deadline_tick_ms = dirty_status.deferred_commit_deadline_tick_ms;
    snapshot.deferred_commit_last_status = dirty_status.deferred_commit_last_status;
    snapshot.payload_spool_bytes = payload_spool.spool_bytes;
    snapshot.payload_spool_dirty_range_count = payload_spool.dirty_range_count;
    snapshot.payload_spool_cleanup_failures = payload_spool.cleanup_failures;
    snapshot.payload_spool_bytes_since_sync = payload_spool.bytes_since_sync;
    snapshot.payload_spool_appends_since_sync = payload_spool.appends_since_sync;
    snapshot.payload_spool_append_direct_count = payload_spool.append_direct_count;
    snapshot.payload_spool_append_merged_count = payload_spool.append_merged_count;
    snapshot.payload_spool_append_stream_open_count = payload_spool.append_stream_open_count;
    snapshot.payload_spool_append_stream_flush_count = payload_spool.append_stream_flush_count;
    snapshot.wal_accepted_sequence = dirty_status.wal_accepted_sequence;
    snapshot.wal_apfs_durable_sequence = dirty_status.wal_apfs_durable_sequence;
    snapshot.wal_cleanup_sequence = dirty_status.wal_cleanup_sequence;
    snapshot.wal_recovery_state_valid = dirty_status.wal_recovery_state_valid;
    snapshot.runtime_recovery_reason = context.runtime_recovery_reason;
    snapshot.runtime_last_recovery_action = context.runtime_last_recovery_action;
    snapshot.last_native_mutation_failure_operation = context.last_native_mutation_failure_operation;
    snapshot.last_native_mutation_failure_path = context.last_native_mutation_failure_path;
    snapshot.last_native_mutation_failure_secondary_path =
        context.last_native_mutation_failure_secondary_path;
    snapshot.last_native_mutation_failure_reason = context.last_native_mutation_failure_reason;
    snapshot.last_native_mutation_failure_status = context.last_native_mutation_failure_status;
    {
        std::lock_guard<std::mutex> diagnostics_lock(context.payload_range_provider_diagnostics_mutex);
        snapshot.payload_range_provider_call_count = context.payload_range_provider_call_count;
        snapshot.payload_range_provider_failure_count = context.payload_range_provider_failure_count;
        snapshot.last_payload_range_provider_failure = context.last_payload_range_provider_failure;
    }
    return snapshot;
}

CallbackStatusSnapshot CaptureCallbackStatusSnapshot(MountContext& context)
{
    std::lock_guard<std::recursive_mutex> runtime_lock(context.runtime_state_mutex);
    const auto dirty_status = SnapshotNativeDirtyStatus(context);
    const auto payload_spool = SnapshotPayloadSpoolStatusCounters(context);
    return BuildCallbackStatusSnapshot(
        context,
        dirty_status,
        payload_spool,
        context.recovery_active,
        context.runtime_last_commit_xid);
}

bool CallbackStatusSnapshotsEqual(
    const CallbackStatusSnapshot& lhs,
    const CallbackStatusSnapshot& rhs)
{
    return lhs.readwrite == rhs.readwrite &&
           lhs.overlay_write_enabled == rhs.overlay_write_enabled &&
           lhs.native_write_enabled == rhs.native_write_enabled &&
           lhs.recovery_active == rhs.recovery_active &&
           lhs.write_degraded == rhs.write_degraded &&
           lhs.pending_native_writes == rhs.pending_native_writes &&
           lhs.mount_ready == rhs.mount_ready &&
           lhs.shutdown_drain_active == rhs.shutdown_drain_active &&
           lhs.close_commit_deferred == rhs.close_commit_deferred &&
           lhs.payload_spool_index_dirty == rhs.payload_spool_index_dirty &&
           lhs.payload_spool_recovery_required == rhs.payload_spool_recovery_required &&
           lhs.has_last_commit_xid == rhs.has_last_commit_xid &&
           lhs.last_commit_xid == rhs.last_commit_xid &&
           lhs.transaction_journal_pending_count == rhs.transaction_journal_pending_count &&
           lhs.metadata_pending_count == rhs.metadata_pending_count &&
           lhs.dirty_transaction_count == rhs.dirty_transaction_count &&
           lhs.deferred_close_commit_count == rhs.deferred_close_commit_count &&
           lhs.deferred_rename_commit_count == rhs.deferred_rename_commit_count &&
           lhs.in_flight_mutation_callbacks == rhs.in_flight_mutation_callbacks &&
           lhs.deferred_commit_requested == rhs.deferred_commit_requested &&
           lhs.deferred_commit_in_flight == rhs.deferred_commit_in_flight &&
           lhs.deferred_commit_force_now == rhs.deferred_commit_force_now &&
           lhs.deferred_commit_requested_target == rhs.deferred_commit_requested_target &&
           lhs.deferred_commit_completed_target == rhs.deferred_commit_completed_target &&
           lhs.deferred_commit_failed_target == rhs.deferred_commit_failed_target &&
           lhs.deferred_commit_in_flight_target == rhs.deferred_commit_in_flight_target &&
           lhs.deferred_commit_first_request_tick_ms == rhs.deferred_commit_first_request_tick_ms &&
           lhs.deferred_commit_deadline_tick_ms == rhs.deferred_commit_deadline_tick_ms &&
           lhs.deferred_commit_last_status == rhs.deferred_commit_last_status &&
           lhs.payload_spool_bytes == rhs.payload_spool_bytes &&
           lhs.payload_spool_dirty_range_count == rhs.payload_spool_dirty_range_count &&
           lhs.payload_spool_cleanup_failures == rhs.payload_spool_cleanup_failures &&
           lhs.payload_spool_bytes_since_sync == rhs.payload_spool_bytes_since_sync &&
           lhs.payload_spool_appends_since_sync == rhs.payload_spool_appends_since_sync &&
           lhs.payload_spool_append_direct_count == rhs.payload_spool_append_direct_count &&
           lhs.payload_spool_append_merged_count == rhs.payload_spool_append_merged_count &&
           lhs.payload_spool_append_stream_open_count == rhs.payload_spool_append_stream_open_count &&
           lhs.payload_spool_append_stream_flush_count == rhs.payload_spool_append_stream_flush_count &&
           lhs.wal_accepted_sequence == rhs.wal_accepted_sequence &&
           lhs.wal_apfs_durable_sequence == rhs.wal_apfs_durable_sequence &&
           lhs.wal_cleanup_sequence == rhs.wal_cleanup_sequence &&
           lhs.wal_recovery_state_valid == rhs.wal_recovery_state_valid &&
           lhs.runtime_recovery_reason == rhs.runtime_recovery_reason &&
           lhs.runtime_last_recovery_action == rhs.runtime_last_recovery_action &&
           lhs.last_native_mutation_failure_operation == rhs.last_native_mutation_failure_operation &&
           lhs.last_native_mutation_failure_path == rhs.last_native_mutation_failure_path &&
           lhs.last_native_mutation_failure_secondary_path ==
                rhs.last_native_mutation_failure_secondary_path &&
           lhs.last_native_mutation_failure_reason == rhs.last_native_mutation_failure_reason &&
           lhs.last_native_mutation_failure_status == rhs.last_native_mutation_failure_status &&
           lhs.payload_range_provider_call_count == rhs.payload_range_provider_call_count &&
           lhs.payload_range_provider_failure_count == rhs.payload_range_provider_failure_count &&
           lhs.last_payload_range_provider_failure == rhs.last_payload_range_provider_failure;
}

void StoreCallbackStatusSnapshot(MountContext& context, CallbackStatusSnapshot snapshot)
{
    std::lock_guard<std::mutex> lock(context.callback_status_snapshot_mutex);
    context.last_callback_status_snapshot = std::move(snapshot);
}

bool ShouldWriteHostStatusFileForCallback(MountContext& context, CallbackStatusSnapshot& snapshot)
{
    snapshot = CaptureCallbackStatusSnapshot(context);
    if (IsPerfCountersEnabled())
    {
        return true;
    }

    std::lock_guard<std::mutex> lock(context.callback_status_snapshot_mutex);
    return !context.last_callback_status_snapshot.has_value() ||
           !CallbackStatusSnapshotsEqual(*context.last_callback_status_snapshot, snapshot);
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

bool PersistHostStatusContentsLocked(
    MountContext& context,
    const std::string& contents,
    bool force_write)
{
    if (!force_write && context.last_status_write_contents == contents)
    {
        return true;
    }

    auto status_path = std::filesystem::path(context.args.status_file);
    if (status_path.has_parent_path())
    {
        std::filesystem::create_directories(status_path.parent_path());
    }

    const auto temp_path = std::filesystem::path(status_path.wstring() + L".tmp");
    {
        std::ofstream out(temp_path, std::ios::binary | std::ios::trunc);
        if (!out.good())
        {
            return false;
        }

        out.write(contents.data(), static_cast<std::streamsize>(contents.size()));
        out.flush();
        if (!out.good())
        {
            std::error_code ignored;
            std::filesystem::remove(temp_path, ignored);
            return false;
        }
    }

    bool replaced = false;
    for (int attempt = 0; attempt < 10; ++attempt)
    {
        if (MoveFileExW(
                temp_path.c_str(),
                status_path.c_str(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        {
            replaced = true;
            break;
        }

        Sleep(5);
    }
    if (!replaced)
    {
        std::error_code ignored;
        std::filesystem::remove(temp_path, ignored);
        return false;
    }

    context.last_status_write_contents = contents;
    return true;
}

bool WriteHostStatusFileLocked(
    MountContext& context,
    bool recovery_active,
    std::optional<std::uint64_t> last_commit_xid
)
{
    std::lock_guard<std::recursive_mutex> runtime_lock(context.runtime_state_mutex);
    if (context.args.status_file.empty())
    {
        return true;
    }
    try
    {
#ifdef APFSACCESS_FSHOST_UNIT_TEST
        ++g_host_status_file_build_count_for_test;
#endif
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
        const auto commit_failure_reason = ResolveCommitFailureReasonStatus(context);
        const auto commit_failure_detail = ResolveCommitFailureDetailStatus(context);
        const auto commit_failure_object_id = ResolveCommitFailureObjectIdStatus(context);
        const auto replay_stage = ResolveReplayStageStatus(context);
        const auto commit_blob_magic = ResolveCommitBlobMagicStatus(context);
        const auto integrity_failure_reason = ResolveIntegrityFailureReasonStatus(context);
        const auto integrity_failure_object_id = ResolveIntegrityFailureObjectIdStatus(context);
        const auto safety_state = EscapeJson(WideToUtf8(ResolveNativeWriteSafetyStateStatus(context)));
        const auto recovery_reason = ResolveRecoveryReasonStatus(context, recovery_active);
        const auto recovery_action = ResolveLastRecoveryActionStatus(context);
        const auto dirty_status = SnapshotNativeDirtyStatus(context);
        const auto payload_spool = SnapshotPayloadSpoolStatusCounters(context);
        const auto callback_snapshot = BuildCallbackStatusSnapshot(
            context,
            dirty_status,
            payload_spool,
            recovery_active,
            last_commit_xid);
        const auto metadata_counts = ResolveNativeMetadataCounts(context);
        const auto mount_ready = context.mount_ready.load(std::memory_order_acquire);
        const auto host_pid = static_cast<unsigned long>(GetCurrentProcessId());
        std::string active_callback_name;
        std::string last_callback_name;
        {
            std::lock_guard<std::mutex> callback_lock(context.callback_activity_mutex);
            active_callback_name = context.active_callback_name;
            last_callback_name = context.last_callback_name;
        }
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

        buffer << ",\"commitFailureReason\":";
        if (!commit_failure_reason.empty())
        {
            buffer << "\"" << EscapeJson(WideToUtf8(commit_failure_reason)) << "\"";
        }
        else
        {
            buffer << "null";
        }

        buffer << ",\"commitFailureDetail\":";
        if (!commit_failure_detail.empty())
        {
            buffer << "\"" << EscapeJson(WideToUtf8(commit_failure_detail)) << "\"";
        }
        else
        {
            buffer << "null";
        }

        buffer << ",\"commitFailureObjectId\":";
        if (commit_failure_object_id.has_value())
        {
            buffer << *commit_failure_object_id;
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

        buffer << ",\"lastNativeMutationFailure\":";
        if (!context.last_native_mutation_failure_operation.empty() ||
            !context.last_native_mutation_failure_path.empty() ||
            !context.last_native_mutation_failure_reason.empty() ||
            !context.last_native_mutation_failure_status.empty())
        {
            buffer
                << "{\"operation\":\"" << EscapeJson(WideToUtf8(context.last_native_mutation_failure_operation))
                << "\",\"path\":\"" << EscapeJson(WideToUtf8(context.last_native_mutation_failure_path))
                << "\",\"secondaryPath\":";
            if (!context.last_native_mutation_failure_secondary_path.empty())
            {
                buffer << "\"" << EscapeJson(WideToUtf8(context.last_native_mutation_failure_secondary_path)) << "\"";
            }
            else
            {
                buffer << "null";
            }
            buffer
                << ",\"status\":\"" << EscapeJson(WideToUtf8(context.last_native_mutation_failure_status))
                << "\",\"reason\":";
            if (!context.last_native_mutation_failure_reason.empty())
            {
                buffer << "\"" << EscapeJson(WideToUtf8(context.last_native_mutation_failure_reason)) << "\"";
            }
            else
            {
                buffer << "null";
            }
            buffer << "}";
        }
        else
        {
            buffer << "null";
        }

        buffer << ",\"payloadRangeProviderCallCount\":" << callback_snapshot.payload_range_provider_call_count;
        buffer << ",\"payloadRangeProviderFailureCount\":" << callback_snapshot.payload_range_provider_failure_count;
        buffer << ",\"lastPayloadRangeProviderFailure\":";
        if (!callback_snapshot.last_payload_range_provider_failure.empty())
        {
            buffer << "\"" << EscapeJson(WideToUtf8(callback_snapshot.last_payload_range_provider_failure)) << "\"";
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
        buffer << ",\"dirtyTransactionCount\":" << dirty_status.dirty_transaction_count;
        buffer << ",\"mountReady\":" << (mount_ready ? "true" : "false");
        buffer << ",\"shutdownDrainActive\":" << (dirty_status.shutdown_drain_active ? "true" : "false");
        buffer << ",\"closeCommitDeferred\":" << (dirty_status.close_commit_deferred ? "true" : "false");
        buffer << ",\"deferredCloseCommitCount\":" << dirty_status.deferred_close_commit_count;
        buffer << ",\"deferredCloseCommitsEnabled\":" << (IsDeferCloseCommitsEnabled() ? "true" : "false");
        buffer << ",\"groupedDeferredAcceptanceEnabled\":" << (IsGroupedDeferredAcceptanceEnabled() ? "true" : "false");
        buffer << ",\"deferredPayloadIndexPersistenceEnabled\":" << (IsDeferredPayloadIndexPersistenceEnabled() ? "true" : "false");
        buffer << ",\"inlineAcceptancePayloadEnabled\":" << (IsInlineAcceptancePayloadEnabled() ? "true" : "false");
        buffer << ",\"finalizationCoverageCacheEnabled\":" << (IsFinalizationCoverageCacheEnabled() ? "true" : "false");
#ifdef APFSACCESS_HAS_RW_ENGINE
        buffer << ",\"groupedAcceptanceWaitingParticipants\":" << context.grouped_acceptance_waiting_participants.load(std::memory_order_relaxed);
        buffer << ",\"groupedAcceptanceBatchCount\":" << context.grouped_acceptance_batch_count.load(std::memory_order_relaxed);
        buffer << ",\"groupedAcceptanceParticipantCount\":" << context.grouped_acceptance_participant_count.load(std::memory_order_relaxed);
        buffer << ",\"groupedAcceptanceMaxCohortSize\":" << context.grouped_acceptance_max_cohort_size.load(std::memory_order_relaxed);
        buffer << ",\"groupedAcceptanceLastTarget\":" << context.grouped_acceptance_last_target.load(std::memory_order_relaxed);
        buffer << ",\"groupedAcceptanceRolloverCount\":" << context.grouped_acceptance_rollover_count.load(std::memory_order_relaxed);
        buffer << ",\"groupedAcceptanceLastRolloverRequiredSequence\":" << context.grouped_acceptance_last_rollover_required_sequence.load(std::memory_order_relaxed);
        buffer << ",\"groupedAcceptanceLastRolloverResultSequence\":" << context.grouped_acceptance_last_rollover_result_sequence.load(std::memory_order_relaxed);
        buffer << ",\"groupedAcceptanceLastFailureReason\":\""
               << GroupedDeferredAcceptanceFailureReasonName(
                      static_cast<GroupedDeferredAcceptanceFailureReason>(
                          context.grouped_acceptance_last_failure_reason.load(std::memory_order_relaxed)))
               << "\"";
        buffer << ",\"groupedAcceptanceLastFailureTransactionId\":" << context.grouped_acceptance_last_failure_transaction_id.load(std::memory_order_relaxed);
        buffer << ",\"groupedAcceptanceLastFailureRequiredSequence\":" << context.grouped_acceptance_last_failure_required_sequence.load(std::memory_order_relaxed);
        buffer << ",\"groupedAcceptanceLastFailureBatchRequiredSequence\":" << context.grouped_acceptance_last_failure_batch_required_sequence.load(std::memory_order_relaxed);
        buffer << ",\"groupedAcceptanceLastFailureResultSequence\":" << context.grouped_acceptance_last_failure_result_sequence.load(std::memory_order_relaxed);
        buffer << ",\"groupedAcceptanceLastFailureObservedTransactionId\":" << context.grouped_acceptance_last_failure_observed_transaction_id.load(std::memory_order_relaxed);
        buffer << ",\"groupedAcceptanceLastFailureObservedAcceptedSequence\":" << context.grouped_acceptance_last_failure_observed_accepted_sequence.load(std::memory_order_relaxed);
        buffer << ",\"groupedAcceptanceLastFailureBatchGeneration\":" << context.grouped_acceptance_last_failure_batch_generation.load(std::memory_order_relaxed);
        buffer << ",\"groupedAcceptanceLastFailureBatchSealed\":" << (context.grouped_acceptance_last_failure_batch_sealed.load(std::memory_order_relaxed) ? "true" : "false");
#else
        buffer << ",\"groupedAcceptanceWaitingParticipants\":0";
        buffer << ",\"groupedAcceptanceBatchCount\":0";
        buffer << ",\"groupedAcceptanceParticipantCount\":0";
        buffer << ",\"groupedAcceptanceMaxCohortSize\":0";
        buffer << ",\"groupedAcceptanceLastTarget\":0";
        buffer << ",\"groupedAcceptanceRolloverCount\":0";
        buffer << ",\"groupedAcceptanceLastRolloverRequiredSequence\":0";
        buffer << ",\"groupedAcceptanceLastRolloverResultSequence\":0";
        buffer << ",\"groupedAcceptanceLastFailureReason\":\"None\"";
        buffer << ",\"groupedAcceptanceLastFailureTransactionId\":0";
        buffer << ",\"groupedAcceptanceLastFailureRequiredSequence\":0";
        buffer << ",\"groupedAcceptanceLastFailureBatchRequiredSequence\":0";
        buffer << ",\"groupedAcceptanceLastFailureResultSequence\":0";
        buffer << ",\"groupedAcceptanceLastFailureObservedTransactionId\":0";
        buffer << ",\"groupedAcceptanceLastFailureObservedAcceptedSequence\":0";
        buffer << ",\"groupedAcceptanceLastFailureBatchGeneration\":0";
        buffer << ",\"groupedAcceptanceLastFailureBatchSealed\":false";
#endif
        buffer << ",\"experimentalNamespaceWriteBack\":" << (IsExperimentalNamespaceWriteBackEnabled() ? "true" : "false");
        buffer << ",\"experimentalPostCheckpointHydrationPromotion\":"
               << (IsExperimentalPostCheckpointHydrationPromotionEnabled() ? "true" : "false");
        buffer << ",\"postCheckpointHydrationMinimumBytes\":"
               << ResolvePostCheckpointHydrationPromotionMinimumBytes();
        buffer << ",\"postCheckpointHydrationSessionBudgetBytes\":"
               << kPostCheckpointHydrationPromotionSessionBudgetBytes;
        buffer << ",\"postCheckpointHydrationCandidateCount\":"
               << context.post_checkpoint_hydration_candidate_count.load(std::memory_order_relaxed);
        buffer << ",\"postCheckpointHydrationPromotedCount\":"
               << context.post_checkpoint_hydration_promoted_count.load(std::memory_order_relaxed);
        buffer << ",\"postCheckpointHydrationFailureCount\":"
               << context.post_checkpoint_hydration_failure_count.load(std::memory_order_relaxed);
        buffer << ",\"postCheckpointHydrationPartialSkipCount\":"
               << context.post_checkpoint_hydration_partial_skip_count.load(std::memory_order_relaxed);
        buffer << ",\"postCheckpointHydrationOpenSkipCount\":"
               << context.post_checkpoint_hydration_open_skip_count.load(std::memory_order_relaxed);
        buffer << ",\"postCheckpointHydrationBudgetSkipCount\":"
               << context.post_checkpoint_hydration_budget_skip_count.load(std::memory_order_relaxed);
        buffer << ",\"postCheckpointHydrationPromotedBytes\":"
               << context.post_checkpoint_hydration_promoted_bytes.load(std::memory_order_relaxed);
        buffer << ",\"deferredRenameCommitCount\":" << context.deferred_rename_commit_count.load(std::memory_order_relaxed);
        buffer << ",\"inFlightMutationCallbacks\":" << dirty_status.in_flight_mutation_callbacks;
        buffer << ",\"activeCallbackCount\":" << context.active_callback_count.load(std::memory_order_acquire);
        buffer << ",\"peakCallbackCount\":" << context.peak_callback_count.load(std::memory_order_acquire);
        buffer << ",\"callbackDispatcherSaturationCount\":"
               << context.callback_dispatcher_saturation_count.load(std::memory_order_acquire);
        const auto active_callbacks = context.active_callback_count.load(std::memory_order_acquire);
        const auto dispatcher_threads = (std::max)(1u, context.dispatcher_thread_count);
        buffer << ",\"callbackQueueDepthEstimate\":"
               << (active_callbacks > dispatcher_threads ? active_callbacks - dispatcher_threads : 0u);
        buffer << ",\"callbackQueueDepthPeakEstimate\":"
               << context.callback_queue_depth_peak.load(std::memory_order_acquire);
        buffer << ",\"activeCallbackStartedTickMs\":" << context.active_callback_started_tick_ms.load(std::memory_order_acquire);
        buffer << ",\"activeCallback\":\"" << EscapeJson(active_callback_name) << "\"";
        buffer << ",\"lastCallback\":\"" << EscapeJson(last_callback_name) << "\"";
        buffer << ",\"deferredCommitRequested\":" << (dirty_status.deferred_commit_requested ? "true" : "false");
        buffer << ",\"deferredCommitInFlight\":" << (dirty_status.deferred_commit_in_flight ? "true" : "false");
        buffer << ",\"deferredCommitForceNow\":" << (dirty_status.deferred_commit_force_now ? "true" : "false");
        buffer << ",\"deferredCommitRequestedTarget\":" << dirty_status.deferred_commit_requested_target;
        buffer << ",\"deferredCommitCompletedTarget\":" << dirty_status.deferred_commit_completed_target;
        buffer << ",\"deferredCommitFailedTarget\":" << dirty_status.deferred_commit_failed_target;
        buffer << ",\"deferredCommitInFlightTarget\":" << dirty_status.deferred_commit_in_flight_target;
        buffer << ",\"deferredCommitFirstRequestTickMs\":" << dirty_status.deferred_commit_first_request_tick_ms;
        buffer << ",\"deferredCommitDeadlineTickMs\":" << dirty_status.deferred_commit_deadline_tick_ms;
        buffer << ",\"deferredCommitLastStatus\":"
               << static_cast<std::uint32_t>(dirty_status.deferred_commit_last_status);
        buffer << ",\"payloadSpoolBytes\":" << payload_spool.spool_bytes;
        buffer << ",\"payloadSpoolDirtyRangeCount\":" << payload_spool.dirty_range_count;
        buffer << ",\"payloadSpoolOldestDirtyAgeMs\":" << payload_spool.oldest_dirty_age_ms;
        buffer << ",\"payloadSpoolCleanupFailures\":" << payload_spool.cleanup_failures;
        buffer << ",\"payloadSpoolBytesSinceSync\":" << payload_spool.bytes_since_sync;
        buffer << ",\"payloadSpoolAppendsSinceSync\":" << payload_spool.appends_since_sync;
        buffer << ",\"payloadSpoolAppendDirectCount\":" << payload_spool.append_direct_count;
        buffer << ",\"payloadSpoolAppendMergedCount\":" << payload_spool.append_merged_count;
        buffer << ",\"payloadSpoolAppendStreamOpenCount\":" << payload_spool.append_stream_open_count;
        buffer << ",\"payloadSpoolAppendStreamFlushCount\":" << payload_spool.append_stream_flush_count;
        buffer << ",\"payloadSpoolPayloadOnlyFlushCount\":" << payload_spool.payload_only_flush_count;
        buffer << ",\"payloadSpoolPayloadOnlyFlushMicroseconds\":" << payload_spool.payload_only_flush_microseconds;
        buffer << ",\"payloadSpoolPayloadOnlyFlushMaxMicroseconds\":" << payload_spool.payload_only_flush_max_microseconds;
        buffer << ",\"payloadSpoolDurableFlushCount\":" << payload_spool.durable_flush_count;
        buffer << ",\"payloadSpoolDurableFlushMicroseconds\":" << payload_spool.durable_flush_microseconds;
        buffer << ",\"payloadSpoolDurableFlushMaxMicroseconds\":" << payload_spool.durable_flush_max_microseconds;
        buffer << ",\"payloadSpoolSyncCount\":" << payload_spool.spool_sync_count;
        buffer << ",\"payloadSpoolSyncMicroseconds\":" << payload_spool.spool_sync_microseconds;
        buffer << ",\"payloadSpoolSyncMaxMicroseconds\":" << payload_spool.spool_sync_max_microseconds;
        buffer << ",\"payloadSpoolSyncHandleFlushCount\":" << payload_spool.spool_sync_handle_flush_count;
        buffer << ",\"payloadSpoolSyncReopenCount\":" << payload_spool.spool_sync_reopen_count;
        buffer << ",\"payloadSpoolIndexPersistCount\":" << payload_spool.index_persist_count;
        buffer << ",\"payloadSpoolIndexPersistBytes\":" << payload_spool.index_persist_bytes;
        buffer << ",\"payloadSpoolIndexPersistMicroseconds\":" << payload_spool.index_persist_microseconds;
        buffer << ",\"payloadSpoolIndexPersistMaxMicroseconds\":" << payload_spool.index_persist_max_microseconds;
        buffer << ",\"payloadSpoolIndexDirty\":" << (payload_spool.index_dirty ? "true" : "false");
        buffer << ",\"payloadSpoolRecoveryRequired\":" << (payload_spool.recovery_required ? "true" : "false");
        buffer << ",\"walAcceptedSequence\":" << dirty_status.wal_accepted_sequence;
        buffer << ",\"walApfsDurableSequence\":" << dirty_status.wal_apfs_durable_sequence;
        buffer << ",\"walCleanupSequence\":" << dirty_status.wal_cleanup_sequence;
        buffer << ",\"walRecoveryStateValid\":" << (dirty_status.wal_recovery_state_valid ? "true" : "false");
        buffer << ",\"walDurableAppendCount\":" << dirty_status.wal_durable_append_count;
        buffer << ",\"walDurableAppendMicroseconds\":" << dirty_status.wal_durable_append_microseconds;
        buffer << ",\"walDurableAppendMaxMicroseconds\":" << dirty_status.wal_durable_append_max_microseconds;
        buffer << ",\"walFinalizationCoverageCacheHitCount\":" << dirty_status.wal_finalization_coverage_cache_hit_count;
        buffer << ",\"walFinalizationCoverageScanCount\":" << dirty_status.wal_finalization_coverage_scan_count;
        buffer << ",\"walFinalizationCoverageScanMicroseconds\":" << dirty_status.wal_finalization_coverage_scan_microseconds;
        buffer << ",\"hostPid\":" << host_pid;
        buffer << ",\"dispatcherThreadCount\":" << context.dispatcher_thread_count;
        if (IsPerfCountersEnabled())
        {
            buffer << ",\"payloadSpoolMutexWaitCount\":" << payload_spool.mutex_wait_count;
            buffer << ",\"payloadSpoolMutexWaitMicroseconds\":" << payload_spool.mutex_wait_microseconds;
            buffer << ",\"payloadSpoolMutexWaitMaxMicroseconds\":" << payload_spool.mutex_wait_max_microseconds;
            buffer << ",\"payloadSpoolMutexWaitP50Microseconds\":" << payload_spool.mutex_wait_p50_microseconds;
            buffer << ",\"payloadSpoolMutexWaitP95Microseconds\":" << payload_spool.mutex_wait_p95_microseconds;
            buffer << ",\"performance\":{\"callbacks\":{";
            AppendPerfCounterJson(buffer, "setVolumeLabel", context.perf_set_volume_label);
            buffer << ",";
            AppendPerfCounterJson(buffer, "create", context.perf_create);
            buffer << ",";
            AppendPerfCounterJson(buffer, "open", context.perf_open);
            buffer << ",";
            AppendPerfCounterJson(buffer, "overwrite", context.perf_overwrite);
            buffer << ",";
            AppendPerfCounterJson(buffer, "write", context.perf_write);
            buffer << ",";
            AppendPerfCounterJson(buffer, "setBasicInfo", context.perf_set_basic_info);
            buffer << ",";
            AppendPerfCounterJson(buffer, "setFileSize", context.perf_set_file_size);
            buffer << ",";
            AppendPerfCounterJson(buffer, "canDelete", context.perf_can_delete);
            buffer << ",";
            AppendPerfCounterJson(buffer, "setDelete", context.perf_set_delete);
            buffer << ",";
            AppendPerfCounterJson(buffer, "rename", context.perf_rename);
            buffer << ",";
            AppendPerfCounterJson(buffer, "cleanup", context.perf_cleanup);
            buffer << ",";
            AppendPerfCounterJson(buffer, "close", context.perf_close);
            buffer << ",";
            AppendPerfCounterJson(buffer, "read", context.perf_read);
            buffer << ",";
            AppendPerfCounterJson(buffer, "flush", context.perf_flush);
            buffer << ",";
            AppendPerfCounterJson(buffer, "readDirectory", context.perf_read_directory);
            buffer << ",";
            AppendPerfCounterJson(buffer, "ensureDirectoryLoaded", context.perf_ensure_directory_loaded);
            buffer << ",";
            AppendPerfCounterJson(buffer, "mergeCommittedInodes", context.perf_merge_committed_inodes);
            buffer << ",";
            AppendPerfCounterJson(buffer, "commitNative", context.perf_commit_native);
            buffer << ",";
            AppendPerfCounterJson(buffer, "getVolumeInfo", context.perf_get_volume_info);
            buffer << ",";
            AppendPerfCounterJson(buffer, "getSecurityByName", context.perf_get_security_by_name);
            buffer << ",";
            AppendPerfCounterJson(buffer, "getSecurity", context.perf_get_security);
            buffer << ",";
            AppendPerfCounterJson(buffer, "setSecurity", context.perf_set_security);
            buffer << ",";
            AppendPerfCounterJson(buffer, "getFileInfo", context.perf_get_file_info);
            buffer << ",";
            AppendPerfCounterJson(buffer, "getStreamInfo", context.perf_get_stream_info);
            buffer << "},\"stages\":{";
             AppendPerfCounterJson(buffer, "mutationCallbackLock", context.perf_mutation_callback_lock);
             buffer << ",";
             AppendPerfCounterJson(buffer, "mutationAdmissionWait", context.perf_mutation_admission_wait);
             buffer << ",";
             AppendPerfCounterJson(buffer, "selectedNativeWriteTxMutexWait", context.perf_tx_mutex_wait);
             buffer << ",";
             AppendPerfCounterJson(buffer, "selectedNativeWriteTxMutexHold", context.perf_tx_mutex_hold);
             buffer << ",";
             AppendPerfCounterJson(buffer, "selectedNativeWriteMetadataMutexWait", context.perf_metadata_mutex_wait);
             buffer << ",";
            AppendPerfCounterJson(buffer, "selectedNativeCommitMutexWait", context.perf_commit_mutex_wait);
            buffer << ",";
            AppendPerfCounterJson(buffer, "selectedNativeCommitMutexHold", context.perf_commit_mutex_hold);
            buffer << ",";
            AppendPerfCounterJson(buffer, "namespaceMutexWait", context.perf_namespace_mutex_wait);
            buffer << ",";
            AppendPerfCounterJson(buffer, "namespaceMutexHold", context.perf_namespace_mutex_hold);
            buffer << ",";
            AppendPerfCounterJson(buffer, "metadataStage", context.perf_metadata_stage);
            buffer << ",";
            AppendPerfCounterJson(buffer, "metadataMutexHold", context.perf_metadata_mutex_hold);
             buffer << ",";
             AppendPerfCounterJson(buffer, "payloadSpoolAppend", context.perf_payload_spool_append);
             buffer << ",";
             AppendPerfCounterJson(buffer, "walAppend", context.perf_wal_append);
             buffer << ",";
             AppendPerfCounterJson(buffer, "acceptanceWait", context.perf_acceptance_wait);
             buffer << ",";
             AppendPerfCounterJson(buffer, "cleanupStage", context.perf_cleanup_stage);
             buffer << ",";
             AppendPerfCounterJson(buffer, "postCheckpointHydration", context.perf_post_checkpoint_hydration);
             buffer << ",";
             AppendPerfCounterJson(buffer, "recoveryMarker", context.perf_recovery_marker);
             buffer << "},\"commitOrigins\":{";
            AppendNativeCommitOriginCounterJson(buffer, "Close", context.perf_commit_origin_close);
            buffer << ",";
            AppendNativeCommitOriginCounterJson(buffer, "CloseDeferred", context.perf_commit_origin_close_deferred);
            buffer << ",";
            AppendNativeCommitOriginCounterJson(buffer, "Flush", context.perf_commit_origin_flush);
            buffer << ",";
            AppendNativeCommitOriginCounterJson(buffer, "Rename", context.perf_commit_origin_rename);
            buffer << ",";
            AppendNativeCommitOriginCounterJson(buffer, "Shutdown", context.perf_commit_origin_shutdown);
            buffer << ",";
            AppendNativeCommitOriginCounterJson(buffer, "DirtyLimit", context.perf_commit_origin_dirty_limit);
            buffer << ",";
            AppendNativeCommitOriginCounterJson(buffer, "Other", context.perf_commit_origin_other);
            buffer << "}";
#ifdef APFSACCESS_HAS_RW_ENGINE
            if (context.metadata_store)
            {
                buffer << ",\"metadata\":" << context.metadata_store->PerformanceJson();
            }
#endif
            buffer << "}";
        }
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

        std::lock_guard<std::mutex> status_file_lock(context.status_file_mutex);
        if (!PersistHostStatusContentsLocked(context, contents, false))
        {
            return false;
        }
        StoreCallbackStatusSnapshot(context, callback_snapshot);
        return true;
    }
    catch (...)
    {
        return false;
    }
}

bool RequiresNativeApfsCheckpoint(const MountContext* context)
{
    if (!context)
    {
        return false;
    }

    const auto dirty = SnapshotNativeDirtyStatus(*context);
    return dirty.has_pending_metadata_mutations ||
           dirty.wal_accepted_sequence > dirty.wal_apfs_durable_sequence;
}

bool WriteHostStatusFile(MountContext& context)
{
    if (context.active_callback_count.load(std::memory_order_acquire) != 0)
    {
        RequestCallbackStatusPublish(&context);
        return true;
    }
    std::lock_guard<std::recursive_mutex> runtime_lock(context.runtime_state_mutex);
    return WriteHostStatusFileLocked(
        context,
        context.recovery_active,
        context.runtime_last_commit_xid);
}

bool WriteHostStatusFile(
    MountContext& context,
    bool recovery_active,
    std::optional<std::uint64_t> last_commit_xid)
{
    if (context.active_callback_count.load(std::memory_order_acquire) != 0)
    {
        RequestCallbackStatusPublish(&context);
        return true;
    }
    std::lock_guard<std::recursive_mutex> runtime_lock(context.runtime_state_mutex);
    return WriteHostStatusFileLocked(context, recovery_active, last_commit_xid);
}

bool WriteTerminalMountNotReadyStatusFile(MountContext& context)
{
    if (context.args.status_file.empty())
    {
        return true;
    }

    try
    {
        std::lock_guard<std::mutex> status_file_lock(context.status_file_mutex);
        auto contents = context.last_status_write_contents;
        if (contents.empty())
        {
            std::ifstream status_in(context.args.status_file, std::ios::binary);
            if (!status_in.good())
            {
                return false;
            }
            contents.assign(
                std::istreambuf_iterator<char>(status_in),
                std::istreambuf_iterator<char>());
        }

        constexpr std::string_view field = "\"mountReady\":";
        const auto field_position = contents.find(field);
        if (field_position == std::string::npos ||
            contents.find(field, field_position + field.size()) != std::string::npos)
        {
            return false;
        }

        const auto value_position = field_position + field.size();
        if (contents.compare(value_position, 4, "true") == 0)
        {
            contents.replace(value_position, 4, "false");
        }
        else if (contents.compare(value_position, 5, "false") != 0)
        {
            return false;
        }

        return PersistHostStatusContentsLocked(context, contents, true);
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

std::wstring ParentOfNormalizedPath(const std::wstring& normalized_path)
{
    if (normalized_path == L"\\")
    {
        return normalized_path;
    }

    const auto pos = normalized_path.find_last_of(L'\\');
    if (pos <= 0 || pos == std::wstring::npos)
    {
        return L"\\";
    }
    return normalized_path.substr(0, pos);
}

std::wstring LeafNameOfNormalizedPath(const std::wstring& normalized_path)
{
    if (normalized_path == L"\\")
    {
        return L"";
    }

    const auto pos = normalized_path.find_last_of(L'\\');
    if (pos == std::wstring::npos || pos + 1 >= normalized_path.size())
    {
        return normalized_path;
    }
    return normalized_path.substr(pos + 1);
}

std::wstring JoinFromNormalizedPath(const std::wstring& normalized_parent, const std::wstring& name)
{
    return normalized_parent == L"\\" ? L"\\" + name : normalized_parent + L"\\" + name;
}

std::optional<wchar_t> TryExtractDriveLetter(const std::wstring& value)
{
    const auto extract_at = [&](std::size_t index) -> std::optional<wchar_t>
    {
        if (value.size() <= index + 1)
        {
            return std::nullopt;
        }

        const auto letter = value[index];
        if (((letter >= L'A' && letter <= L'Z') || (letter >= L'a' && letter <= L'z')) &&
            value[index + 1] == L':')
        {
            return static_cast<wchar_t>(towupper(letter));
        }

        return std::nullopt;
    };

    if (auto drive = extract_at(0))
    {
        return drive;
    }
    if (value.rfind(L"\\??\\", 0) == 0)
    {
        return extract_at(4);
    }
    if (value.rfind(L"\\\\?\\", 0) == 0)
    {
        return extract_at(4);
    }

    return std::nullopt;
}

bool IsDifferentDriveRenameTarget(const MountContext* c, const std::wstring& raw_target)
{
    if (!c)
    {
        return false;
    }

    const auto target_drive = TryExtractDriveLetter(raw_target);
    const auto mount_drive = TryExtractDriveLetter(c->args.mount);
    return target_drive.has_value() &&
           mount_drive.has_value() &&
           target_drive.value() != mount_drive.value();
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

    return NormalizePath(JoinFromNormalizedPath(ParentOfNormalizedPath(source_path), target));
}

std::wstring LeafName(const std::wstring& path)
{
    return LeafNameOfNormalizedPath(NormalizePath(path));
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

void FillDirectoryInfo(FSP_FSCTL_DIR_INFO* dir_info, const Node& node, const std::wstring& name, bool read_only, UINT16 size)
{
    if (!dir_info)
    {
        return;
    }

    dir_info->Size = size;
    FillInfo(node, read_only, &dir_info->FileInfo);
    const size_t name_bytes = name.size() * sizeof(WCHAR);
    if (name_bytes > 0)
    {
        std::memcpy(dir_info->FileNameBuf, name.data(), name_bytes);
    }
    dir_info->FileNameBuf[name.size()] = L'\0';
}

bool AddDirectoryEntry(
    const WinFspApi& api,
    const Node& node,
    const std::wstring& name,
    bool read_only,
    PVOID buffer,
    ULONG length,
    PULONG done,
    std::vector<unsigned char>& scratch
)
{
    const auto size = DirectoryInfoSizeForName(name);
    if (!size)
    {
        return true;
    }

    const auto required_size = static_cast<size_t>(*size) + sizeof(WCHAR);
    if (scratch.size() < required_size)
    {
        scratch.resize(required_size);
    }
    auto* dir_info = reinterpret_cast<FSP_FSCTL_DIR_INFO*>(scratch.data());
    FillDirectoryInfo(dir_info, node, name, read_only, *size);
    return api.AddDir(dir_info, buffer, length, done);
}

std::shared_ptr<Node> TryGetNodeLocked(MountContext* c, const std::wstring& path)
{
    auto it = c->nodes.find(Key(path));
    return it == c->nodes.end() ? std::shared_ptr<Node>{} : it->second;
}

std::shared_ptr<Node> TryGetNodeLockedNormalized(MountContext* c, const std::wstring& normalized_path)
{
    auto it = c->nodes.find(LowerPathKey(normalized_path));
    return it == c->nodes.end() ? std::shared_ptr<Node>{} : it->second;
}

std::shared_ptr<Node> TryReuseOpenContextNodeLockedNormalized(
    MountContext* c,
    const OpenContext* open_ctx,
    const std::wstring& normalized_path)
{
    if (!c || !open_ctx || !open_ctx->node)
    {
        return {};
    }

    const auto path_key = LowerPathKey(normalized_path);
    if (NodePathKey(*open_ctx->node) != path_key)
    {
        return {};
    }

    const auto it = c->nodes.find(path_key);
    if (it == c->nodes.end() || it->second != open_ctx->node)
    {
        return {};
    }

#ifdef APFSACCESS_FSHOST_UNIT_TEST
    ++g_delete_context_node_reuse_count_for_test;
#endif
    return it->second;
}

std::shared_ptr<Node> TryGetChildNodeByParentKeyLocked(
    MountContext* c,
    const std::wstring& parent_key,
    const std::wstring& normalized_parent_path,
    const std::wstring& child_name)
{
    if (!c || parent_key.empty() || child_name.empty())
    {
        return {};
    }

#ifdef APFSACCESS_FSHOST_UNIT_TEST
    ++g_child_node_cached_lookup_count_for_test;
#endif

    const auto child_key = ToLowerInvariant(child_name);
    std::wstring lookup_key;
    lookup_key.reserve(parent_key.size() + child_key.size() + 1);
    lookup_key.append(parent_key);
    if (lookup_key != L"\\")
    {
        lookup_key.push_back(L'\\');
    }
    lookup_key.append(child_key);

    auto it = c->nodes.find(lookup_key);
    if (it != c->nodes.end())
    {
        return it->second;
    }

#ifdef APFSACCESS_FSHOST_UNIT_TEST
    ++g_child_node_cached_lookup_fallback_count_for_test;
#endif
    return TryGetNodeLockedNormalized(c, JoinFromNormalizedPath(normalized_parent_path, child_name));
}

std::shared_ptr<Node> TryGetChildNodeLocked(
    MountContext* c,
    const std::shared_ptr<Node>& parent,
    const std::wstring& child_name)
{
    if (!parent)
    {
        return {};
    }

    return TryGetChildNodeByParentKeyLocked(c, NodePathKey(*parent), parent->path, child_name);
}

bool IsDeleteBlockedStateLocked(const std::shared_ptr<Node>& node)
{
    if (!node)
    {
        return false;
    }

    return node->delete_pending || node->delete_latched || node->delete_intent_count > 0;
}

bool HasDeletePendingAncestorLockedNormalized(MountContext* c, const std::wstring& normalized_path)
{
    if (!c)
    {
        return false;
    }

    auto cursor = normalized_path;
    while (true)
    {
        auto ancestor = TryGetNodeLockedNormalized(c, cursor);
        if (IsDeleteBlockedStateLocked(ancestor))
        {
            return true;
        }

        if (cursor == L"\\")
        {
            break;
        }

        auto next = ParentOfNormalizedPath(cursor);
        if (next == cursor)
        {
            break;
        }
        cursor = std::move(next);
    }

    return false;
}

bool HasDeletePendingAncestorLocked(MountContext* c, const std::wstring& path)
{
    return HasDeletePendingAncestorLockedNormalized(c, NormalizePath(path));
}

std::shared_ptr<Node> TryGetVisibleNodeLocked(MountContext* c, const std::wstring& path)
{
    return TryGetVisibleNodeLockedNormalized(c, NormalizePath(path));
}

std::shared_ptr<Node> TryGetVisibleNodeLockedNormalized(MountContext* c, const std::wstring& normalized_path)
{
    if (LooksLikeNamedStreamArtifactNameFromLeaf(LeafNameOfNormalizedPath(normalized_path)))
    {
        return {};
    }

    auto node = TryGetNodeLockedNormalized(c, normalized_path);
    if (!node ||
        IsDeleteBlockedStateLocked(node) ||
        HasDeletePendingAncestorLockedNormalized(c, normalized_path))
    {
        return {};
    }
    return node;
}

std::shared_ptr<Node> TryGetVisibleChildNodeLocked(
    MountContext* c,
    const std::shared_ptr<Node>& parent,
    const std::wstring& child_name)
{
    if (!c || !parent || LooksLikeNamedStreamArtifactNameFromLeaf(child_name))
    {
        return {};
    }

    auto node = TryGetChildNodeLocked(c, parent, child_name);
    if (!node ||
        IsDeleteBlockedStateLocked(node) ||
        HasDeletePendingAncestorLockedNormalized(c, node->path))
    {
        return {};
    }
    return node;
}

bool HasChildName(const std::vector<std::wstring>& children, const std::wstring& name)
{
#ifdef APFSACCESS_FSHOST_UNIT_TEST
    ++g_child_name_linear_scan_count_for_test;
#endif
    return std::any_of(children.begin(), children.end(), [&](const std::wstring& existing)
    {
        return EqualsIgnoreCase(existing, name);
    });
}

void AddChildName(std::vector<std::wstring>& children, const std::wstring& name)
{
    if (!HasChildName(children, name))
    {
        children.push_back(name);
    }
}

void RemoveChildName(std::vector<std::wstring>& children, const std::wstring& name)
{
    auto it = std::find_if(children.begin(), children.end(), [&](const std::wstring& existing)
    {
        return EqualsIgnoreCase(existing, name);
    });
    if (it != children.end())
    {
        children.erase(it);
    }
}

std::wstring ChildNameKey(const std::wstring& name)
{
    return ToLowerInvariant(name);
}

void RebuildChildNameIndex(Node& directory)
{
    directory.sorted_children_valid = false;
    directory.child_index_by_name_key.clear();
    for (std::size_t index = 0; index < directory.children.size();)
    {
        const auto key = ChildNameKey(directory.children[index]);
        if (directory.child_index_by_name_key.emplace(key, index).second)
        {
            ++index;
            continue;
        }

        directory.children.erase(directory.children.begin() + static_cast<std::ptrdiff_t>(index));
    }
}

void ClearChildNames(Node& directory)
{
    directory.children.clear();
    directory.sorted_children.clear();
    directory.sorted_children_valid = true;
    directory.child_index_by_name_key.clear();
}

void EnsureSortedChildNamesLocked(Node& directory)
{
    if (directory.sorted_children_valid)
    {
        return;
    }

    directory.sorted_children = directory.children;
    std::sort(
        directory.sorted_children.begin(),
        directory.sorted_children.end(),
        [](const std::wstring& left, const std::wstring& right)
        {
            const auto comparison = _wcsicmp(left.c_str(), right.c_str());
            return comparison < 0 || (comparison == 0 && left < right);
        });
    directory.sorted_children_valid = true;
#ifdef APFSACCESS_FSHOST_UNIT_TEST
    ++g_directory_enumeration_sort_count_for_test;
#endif
}

void AddChildName(Node& directory, const std::wstring& name)
{
    const auto key = ChildNameKey(name);
    if (directory.child_index_by_name_key.size() != directory.children.size())
    {
        RebuildChildNameIndex(directory);
    }
    if (directory.child_index_by_name_key.find(key) != directory.child_index_by_name_key.end())
    {
        return;
    }

    directory.child_index_by_name_key.emplace(key, directory.children.size());
    directory.children.push_back(name);
    directory.sorted_children_valid = false;
}

void RemoveChildName(Node& directory, const std::wstring& name)
{
    if (directory.child_index_by_name_key.size() != directory.children.size())
    {
        RebuildChildNameIndex(directory);
    }

    const auto key = ChildNameKey(name);
    auto it = directory.child_index_by_name_key.find(key);
    if (it == directory.child_index_by_name_key.end())
    {
        return;
    }

    const auto index = it->second;
    const auto last_index = directory.children.size() - 1;
    directory.child_index_by_name_key.erase(it);
    if (index != last_index)
    {
        directory.children[index] = std::move(directory.children[last_index]);
        directory.child_index_by_name_key[ChildNameKey(directory.children[index])] = index;
    }
    directory.children.pop_back();
    directory.sorted_children_valid = false;
}

#ifdef APFSACCESS_FSHOST_UNIT_TEST
std::uint64_t DebugChildNameLinearScanCountForTest()
{
    return g_child_name_linear_scan_count_for_test;
}

std::uint64_t DebugCanRemoveNodeVisitCountForTest()
{
    return g_can_remove_node_visit_count_for_test;
}

std::uint64_t DebugRemoveNodeChildLookupCountForTest()
{
    return g_remove_node_child_lookup_count_for_test;
}

std::uint64_t DebugStageDeleteChildLookupCountForTest()
{
    return g_stage_delete_child_lookup_count_for_test;
}

std::uint64_t DebugAncestorChildDeleteMarkCountForTest()
{
    return g_ancestor_child_delete_mark_count_for_test;
}

std::uint64_t DebugChildNodeCachedLookupCountForTest()
{
    return g_child_node_cached_lookup_count_for_test;
}

std::uint64_t DebugChildNodeCachedLookupFallbackCountForTest()
{
    return g_child_node_cached_lookup_fallback_count_for_test;
}

std::uint64_t DebugExperimentalRenameCommittedSourceProbeCountForTest()
{
    return g_experimental_rename_committed_source_probe_count_for_test;
}

std::uint64_t DebugDeferredDeleteRollbackPlanProbeCountForTest()
{
    return g_deferred_delete_rollback_plan_probe_count_for_test;
}

std::uint64_t DebugCreateParentReuseCountForTest()
{
    return g_create_parent_reuse_count_for_test;
}

std::uint64_t DebugDeleteContextNodeReuseCountForTest()
{
    return g_delete_context_node_reuse_count_for_test;
}

std::uint64_t DebugDirectoryEnumerationSortCountForTest()
{
    return g_directory_enumeration_sort_count_for_test;
}

void ResetChildNameDebugCountersForTest()
{
    g_child_name_linear_scan_count_for_test = 0;
    g_can_remove_node_visit_count_for_test = 0;
    g_remove_node_child_lookup_count_for_test = 0;
    g_stage_delete_child_lookup_count_for_test = 0;
    g_ancestor_child_delete_mark_count_for_test = 0;
    g_child_node_cached_lookup_count_for_test = 0;
    g_child_node_cached_lookup_fallback_count_for_test = 0;
    g_experimental_rename_committed_source_probe_count_for_test = 0;
    g_normalize_path_call_count_for_test = 0;
    g_deferred_delete_rollback_plan_probe_count_for_test = 0;
    g_create_parent_reuse_count_for_test = 0;
    g_delete_context_node_reuse_count_for_test = 0;
    g_directory_enumeration_sort_count_for_test = 0;
}
#endif

void UpdateDeletePendingVisibilityLocked(MountContext* c, const std::shared_ptr<Node>& node)
{
    if (!c || !node || node->path == L"\\")
    {
        return;
    }

    auto parent = TryGetNodeLockedNormalized(c, ParentOfNormalizedPath(node->path));
    if (!parent || !parent->is_directory)
    {
        return;
    }

    const auto leaf = LeafNameOfNormalizedPath(node->path);
    if (leaf.empty())
    {
        return;
    }

    if (node->delete_pending)
    {
        RemoveChildName(*parent, leaf);
    }
    else
    {
        AddChildName(*parent, leaf);
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

void MarkAncestorChildDeleteLockedNormalized(MountContext* c, const std::wstring& deleted_path)
{
    if (!c || deleted_path == L"\\")
    {
        return;
    }

#ifdef APFSACCESS_FSHOST_UNIT_TEST
    ++g_ancestor_child_delete_mark_count_for_test;
#endif

    const auto now = static_cast<std::uint64_t>(GetTickCount64());
    auto cursor = ParentOfNormalizedPath(deleted_path);
    while (!cursor.empty())
    {
        auto ancestor = TryGetNodeLockedNormalized(c, cursor);
        if (ancestor && ancestor->is_directory)
        {
            ancestor->last_child_delete_tick_ms = now;
            if (ancestor->open_handle_count > 0)
            {
                ancestor->child_delete_observed_while_open = true;
            }
        }

        if (cursor == L"\\")
        {
            break;
        }

        auto next = ParentOfNormalizedPath(cursor);
        if (next == cursor)
        {
            break;
        }
        cursor = std::move(next);
    }
}

void MarkAncestorChildDeleteLocked(MountContext* c, const std::wstring& deleted_path)
{
    MarkAncestorChildDeleteLockedNormalized(c, NormalizePath(deleted_path));
}

bool HasRecentChildDeleteLocked(const std::shared_ptr<Node>& node)
{
    if (!node || node->last_child_delete_tick_ms == 0)
    {
        return false;
    }

    const auto now = static_cast<std::uint64_t>(GetTickCount64());
    return now >= node->last_child_delete_tick_ms &&
        (now - node->last_child_delete_tick_ms) <= 30000;
}

bool HasRecentOpenChildDeleteLocked(const std::shared_ptr<Node>& node)
{
    return node && node->child_delete_observed_while_open && HasRecentChildDeleteLocked(node);
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
        auto current = c->open_write_handle_count.load(std::memory_order_relaxed);
        while (current > 0 &&
               !c->open_write_handle_count.compare_exchange_weak(
                   current,
                   current - 1,
                   std::memory_order_relaxed,
                   std::memory_order_relaxed))
        {
        }
    }

    open_ctx->cleanup_seen = true;
    RefreshDeletePendingStateLocked(c, open_ctx->node);
}

void AcquireOpenContextAccountingLocked(
    MountContext* c,
    const std::shared_ptr<Node>& node,
    const OpenContext* open_ctx)
{
    if (!c || !node || !open_ctx)
    {
        return;
    }

    ++node->open_handle_count;
    if (open_ctx->write_open)
    {
        ++node->write_handle_count;
        c->open_write_handle_count.fetch_add(1, std::memory_order_relaxed);
    }
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

bool IsDirectChildPathNormalized(const std::wstring& parent_path, const std::wstring& candidate_path)
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

    if (!IsDescendantPathNormalized(candidate_path, parent_path))
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

bool IsDirectChildPath(const std::wstring& parent_path, const std::wstring& candidate_path)
{
    return IsDirectChildPathNormalized(NormalizePath(parent_path), NormalizePath(candidate_path));
}

bool HasDeletePermissionForTargetNormalized(const OpenContext* open_ctx, const std::wstring& target_path)
{
    if (!open_ctx || !open_ctx->node)
    {
        return false;
    }

    if (NodePathKey(*open_ctx->node) == LowerPathKey(target_path))
    {
        return open_ctx->allow_delete;
    }

    return open_ctx->node->is_directory &&
        open_ctx->allow_delete_child &&
        IsDirectChildPathNormalized(open_ctx->node->path, target_path);
}

bool HasDeletePermissionForTarget(const OpenContext* open_ctx, const std::wstring& target_path)
{
    return HasDeletePermissionForTargetNormalized(open_ctx, NormalizePath(target_path));
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
    ScopedPerfTimer perf_scope(c ? &c->perf_ensure_directory_loaded : nullptr);

    if (!dir || !dir->is_directory)
    {
        return false;
    }

    {
        ObservedMutexGuard lock(
            c->mutex,
            &c->perf_namespace_mutex_wait,
            &c->perf_namespace_mutex_hold);
        if (dir->loaded)
        {
            return true;
        }
    }

#ifdef APFSACCESS_HAS_RW_ENGINE
    if (c->metadata_store)
    {
        (void)MergeLastCommittedInodeChangesIntoNodeIndex(c);
        {
            ObservedMutexGuard lock(
                c->mutex,
                &c->perf_namespace_mutex_wait,
                &c->perf_namespace_mutex_hold);
            if (dir->loaded)
            {
                return true;
            }
        }
        (void)MergeCommittedDirectoryChildrenIntoNodeIndex(c, dir);
        {
            ObservedMutexGuard lock(
                c->mutex,
                &c->perf_namespace_mutex_wait,
                &c->perf_namespace_mutex_hold);
            if (dir->loaded)
            {
                return true;
            }
        }
        (void)MergeCommittedInodeStateIntoNodeIndex(c);
        ObservedMutexGuard lock(
            c->mutex,
            &c->perf_namespace_mutex_wait,
            &c->perf_namespace_mutex_hold);
        return dir->loaded;
    }
#endif

    return false;
}

std::shared_ptr<Node> FindNode(MountContext* c, const std::wstring& path)
{
    return FindNodeNormalized(c, NormalizePath(path));
}

std::shared_ptr<Node> FindNodeNormalized(MountContext* c, const std::wstring& normalized_path)
{
    {
        ObservedMutexGuard lock(
            c->mutex,
            &c->perf_namespace_mutex_wait,
            &c->perf_namespace_mutex_hold);
        if (auto n = TryGetVisibleNodeLockedNormalized(c, normalized_path))
        {
            return n;
        }
        if (TryGetNodeLockedNormalized(c, normalized_path))
        {
            return {};
        }
    }
    if (normalized_path == L"\\")
    {
        return {};
    }
    auto parent = FindNodeNormalized(c, ParentOfNormalizedPath(normalized_path));
    if (!parent || !EnsureDirectoryLoaded(c, parent))
    {
        return {};
    }
    ObservedMutexGuard lock(
        c->mutex,
        &c->perf_namespace_mutex_wait,
        &c->perf_namespace_mutex_hold);
    return TryGetVisibleNodeLockedNormalized(c, normalized_path);
}

std::filesystem::path HydrationPath(MountContext* c, const Node& n)
{
    const auto node_key = n.hydration_key.empty() ? Key(n.path) : n.hydration_key;
    auto key = node_key + L"|" + c->args.device + L"|" + c->args.volume;
    auto hash = (unsigned long long)std::hash<std::wstring>{}(key);
    const bool session_cache_root = c && !c->cache_root.empty();
    auto root = session_cache_root
        ? c->cache_root
        : (std::filesystem::temp_directory_path() / "ApfsAccess" / "hydrate");
    if (!session_cache_root)
    {
        std::error_code ec;
        std::filesystem::create_directories(root, ec);
    }
    return root / (std::to_wstring(hash) + L".bin");
}

std::wstring CommittedReadPathForNodeLocked(const Node& n)
{
    return n.committed_read_path.empty() ? n.path : n.committed_read_path;
}

std::wstring SnapshotCommittedReadPathForNode(MountContext* c, const std::shared_ptr<Node>& n)
{
    if (!n)
    {
        return {};
    }
    if (!c)
    {
        return CommittedReadPathForNodeLocked(*n);
    }

    std::lock_guard<std::mutex> lock(c->mutex);
    return CommittedReadPathForNodeLocked(*n);
}

bool HasCommittedReadPathMismatch(MountContext* c, const std::shared_ptr<Node>& n)
{
    if (!c || !n || n->is_directory)
    {
        return false;
    }

    std::lock_guard<std::mutex> lock(c->mutex);
    return !n->committed_read_path.empty() &&
           Key(n->committed_read_path) != Key(n->path);
}

std::wstring HydrationStreamPath(MountContext* c, const Node& n, const std::wstring& canonical_stream_name)
{
    auto stream_name = StreamNameForWin32Path(canonical_stream_name);
    if (stream_name.empty())
    {
        return L"";
    }

    return HydrationPath(c, n).wstring() + L":" + stream_name;
}

std::uint64_t FileSizeFromHandle(HANDLE file)
{
    if (file == INVALID_HANDLE_VALUE)
    {
        return 0;
    }

    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size) || size.QuadPart < 0)
    {
        return 0;
    }

    return static_cast<std::uint64_t>(size.QuadPart);
}

void RememberNamedStreamSizeLocked(
    MountContext* c,
    const std::wstring& base_path,
    const std::wstring& canonical_stream_name,
    std::uint64_t size)
{
    if (!c)
    {
        return;
    }

    const auto stream_key = CanonicalStreamName(canonical_stream_name);
    if (stream_key.empty())
    {
        return;
    }

    auto& streams = c->named_stream_sizes[Key(base_path)];
    const auto stream_key_lower = ToLowerInvariant(stream_key);
    for (auto it = streams.begin(); it != streams.end(); ++it)
    {
        if (ToLowerInvariant(it->first) == stream_key_lower)
        {
            if (it->first != stream_key)
            {
                streams.erase(it);
                streams[stream_key] = size;
            }
            else
            {
                it->second = size;
            }
            return;
        }
    }

    streams[stream_key] = size;
}

std::uint64_t RememberNamedStreamSizeFromHandleLocked(
    MountContext* c,
    const std::shared_ptr<Node>& node,
    const std::wstring& canonical_stream_name,
    HANDLE file)
{
    const auto size = FileSizeFromHandle(file);
    if (node)
    {
        RememberNamedStreamSizeLocked(c, node->path, canonical_stream_name, size);
    }

    return size;
}

void ForgetNamedStreamsLocked(MountContext* c, const std::wstring& base_path)
{
    if (!c)
    {
        return;
    }

    c->named_stream_sizes.erase(Key(base_path));
}

bool EnsureHydrationSidecarExistsForNamedStream(MountContext* c, const std::shared_ptr<Node>& node)
{
    if (!c || !node || node->is_directory)
    {
        return false;
    }

    const auto file = HydrationPath(c, *node);
    std::error_code ec;
    if (std::filesystem::exists(file, ec) && !ec)
    {
        return true;
    }

    std::filesystem::create_directories(file.parent_path(), ec);
    if (ec)
    {
        return false;
    }

    HANDLE sidecar = CreateFileW(
        file.wstring().c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_ALWAYS,
        kHydrationCacheFileAttributes,
        nullptr);
    if (sidecar == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    CloseHandle(sidecar);
    return true;
}

bool IsHydrationStaleLocked(MountContext* c, const std::shared_ptr<Node>& node)
{
    return c &&
           node &&
           !node->is_directory &&
           c->stale_hydration_keys.find(NodePathKey(*node)) != c->stale_hydration_keys.end();
}

void InvalidateHydrationReadHandle(MountContext* c)
{
    if (!c)
    {
        return;
    }

    std::lock_guard<std::mutex> cache_lock(c->hydration_read_cache_mutex);
    c->hydration_read_cache_state.reset();
}

void MarkHydrationStaleLocked(MountContext* c, const std::shared_ptr<Node>& node)
{
    if (c && node && !node->is_directory)
    {
        InvalidateHydrationReadHandle(c);
        c->stale_hydration_keys.insert(NodePathKey(*node));
    }
}

void ClearHydrationStaleLocked(MountContext* c, const std::wstring& path)
{
    if (c)
    {
        InvalidateHydrationReadHandle(c);
        c->stale_hydration_keys.erase(Key(path));
    }
}

void ClearHydrationStaleLockedNormalized(MountContext* c, const std::wstring& normalized_path)
{
    if (c)
    {
        InvalidateHydrationReadHandle(c);
        c->stale_hydration_keys.erase(LowerPathKey(normalized_path));
    }
}

bool MoveFileAsideForRollbackLocked(
    MountContext* c,
    const std::shared_ptr<Node>& node,
    const wchar_t* tag,
    LocalFileRollbackSnapshot& snapshot,
    bool preserve_hydration_in_place = false)
{
    if (!c || !node || node->is_directory)
    {
        return true;
    }

    snapshot.path_key = NodePathKey(*node);
    auto stream_it = c->named_stream_sizes.find(snapshot.path_key);
    if (stream_it != c->named_stream_sizes.end())
    {
        snapshot.has_named_streams = true;
        snapshot.named_streams = stream_it->second;
    }

    snapshot.hydration_path = HydrationPath(c, *node);
    InvalidateHydrationReadHandle(c);
    std::error_code ec;
    const auto hydration_exists = std::filesystem::exists(snapshot.hydration_path, ec);
    if (!hydration_exists || ec)
    {
        return !ec;
    }

    if (preserve_hydration_in_place)
    {
        snapshot.hydration_preserved_in_place = true;
        return true;
    }

    const auto backup_name = snapshot.hydration_path.filename().wstring() +
        L"." +
        (tag && *tag ? std::wstring(tag) : std::wstring(L"rollback")) +
        L"." +
        std::to_wstring(GetTickCount64()) +
        L".tmp";
    snapshot.hydration_backup_path = snapshot.hydration_path.parent_path() / backup_name;
    std::filesystem::rename(
        snapshot.hydration_path,
        snapshot.hydration_backup_path,
        ec);
    if (ec)
    {
        snapshot.hydration_backup_path.clear();
        return false;
    }
    snapshot.hydration_moved = true;
    return true;
}

void IndexDeferredDeleteRollbackPlanLocked(MountContext* c, const DeferredDeleteRollbackPlan& plan)
{
    if (!c)
    {
        return;
    }

    if (!plan.path.empty())
    {
        c->deferred_delete_rollback_path_keys.insert(LowerPathKey(plan.path));
    }
    if (!plan.subtree_snapshots.empty() || (plan.node && plan.node->is_directory))
    {
        c->deferred_delete_rollback_has_descendant_paths = true;
    }
    if (!plan.file_snapshot.path_key.empty())
    {
        c->deferred_delete_rollback_path_keys.insert(plan.file_snapshot.path_key);
    }
    for (const auto& entry : plan.subtree_snapshots)
    {
        if (entry.node)
        {
            c->deferred_delete_rollback_path_keys.insert(NodePathKey(*entry.node));
        }
        if (!entry.file_snapshot.path_key.empty())
        {
            c->deferred_delete_rollback_path_keys.insert(entry.file_snapshot.path_key);
        }
    }
}

void AppendDeferredDeleteRollbackPlanLocked(MountContext* c, DeferredDeleteRollbackPlan plan)
{
    if (!c)
    {
        return;
    }

    IndexDeferredDeleteRollbackPlanLocked(c, plan);
    c->deferred_delete_rollback_plans.push_back(std::move(plan));
}

void RebuildDeferredDeleteRollbackPathKeysLocked(MountContext* c)
{
    if (!c)
    {
        return;
    }

    c->deferred_delete_rollback_path_keys.clear();
    c->deferred_delete_rollback_has_descendant_paths = false;
    for (const auto& plan : c->deferred_delete_rollback_plans)
    {
        IndexDeferredDeleteRollbackPlanLocked(c, plan);
    }
}

bool HasDeferredDeleteRollbackPlanForPathLocked(
    MountContext* c,
    const std::wstring& normalized_path)
{
    if (!c)
    {
        return false;
    }

#ifdef APFSACCESS_FSHOST_UNIT_TEST
    ++g_deferred_delete_rollback_plan_probe_count_for_test;
#endif
    if (!c->deferred_delete_rollback_plans.empty() &&
        c->deferred_delete_rollback_path_keys.empty())
    {
        RebuildDeferredDeleteRollbackPathKeysLocked(c);
    }

    return c->deferred_delete_rollback_path_keys.find(LowerPathKey(normalized_path)) !=
        c->deferred_delete_rollback_path_keys.end();
}

bool HasDeferredDeleteRollbackPlanForPathOrAncestorLocked(
    MountContext* c,
    const std::wstring& normalized_path)
{
    if (!c)
    {
        return false;
    }

    if (!c->deferred_delete_rollback_has_descendant_paths)
    {
        return HasDeferredDeleteRollbackPlanForPathLocked(c, normalized_path);
    }

    auto cursor = normalized_path;
    for (;;)
    {
        if (HasDeferredDeleteRollbackPlanForPathLocked(c, cursor))
        {
            return true;
        }
        if (cursor == L"\\")
        {
            return false;
        }
        cursor = ParentOfNormalizedPath(cursor);
    }
}

void RestoreFileRollbackSnapshotLocked(MountContext* c, const LocalFileRollbackSnapshot& snapshot)
{
    if (!c || snapshot.path_key.empty())
    {
        return;
    }

    InvalidateHydrationReadHandle(c);

    if (snapshot.has_named_streams)
    {
        c->named_stream_sizes[snapshot.path_key] = snapshot.named_streams;
    }
    else
    {
        c->named_stream_sizes.erase(snapshot.path_key);
    }

    std::error_code ec;
    if (snapshot.hydration_moved && !snapshot.hydration_backup_path.empty())
    {
        std::filesystem::create_directories(snapshot.hydration_path.parent_path(), ec);
        ec.clear();
        std::filesystem::remove(snapshot.hydration_path, ec);
        ec.clear();
        std::filesystem::rename(
            snapshot.hydration_backup_path,
            snapshot.hydration_path,
            ec);
    }

    c->stale_hydration_keys.erase(snapshot.path_key);
}

void DiscardFileRollbackSnapshot(
    const LocalFileRollbackSnapshot& snapshot,
    bool remove_preserved_hydration = false)
{
    if (!snapshot.hydration_backup_path.empty())
    {
        std::error_code ec;
        std::filesystem::remove(snapshot.hydration_backup_path, ec);
    }
    else if (remove_preserved_hydration &&
             snapshot.hydration_preserved_in_place &&
             !snapshot.hydration_path.empty())
    {
        std::error_code ec;
        std::filesystem::remove(snapshot.hydration_path, ec);
    }
}

bool CaptureDeleteRollbackSubtreeLocked(
    MountContext* c,
    const std::vector<std::shared_ptr<Node>>& postorder,
    bool preserve_hydration_in_place,
    std::vector<DeleteRollbackSubtreeEntry>& snapshots)
{
    snapshots.clear();
    snapshots.reserve(postorder.size());
    for (const auto& node : postorder)
    {
        if (!node)
        {
            snapshots.clear();
            return false;
        }

        DeleteRollbackSubtreeEntry entry{};
        entry.node = node;
        if (!node->is_directory &&
            !MoveFileAsideForRollbackLocked(
                c,
                node,
                L"delete-close",
                entry.file_snapshot,
                preserve_hydration_in_place))
        {
            for (const auto& captured : snapshots)
            {
                RestoreFileRollbackSnapshotLocked(c, captured.file_snapshot);
                DiscardFileRollbackSnapshot(captured.file_snapshot);
            }
            snapshots.clear();
            return false;
        }
        snapshots.push_back(std::move(entry));
    }
    return true;
}

void DiscardDeleteRollbackPlanSnapshots(
    const DeferredDeleteRollbackPlan& plan,
    bool remove_preserved_hydration)
{
    if (plan.subtree_snapshots.empty())
    {
        DiscardFileRollbackSnapshot(plan.file_snapshot, remove_preserved_hydration);
        return;
    }

    for (const auto& entry : plan.subtree_snapshots)
    {
        DiscardFileRollbackSnapshot(entry.file_snapshot, remove_preserved_hydration);
    }
}

void RestoreDeleteRollbackPlanLocked(MountContext* c, DeferredDeleteRollbackPlan& plan)
{
    if (!c || !plan.emit || !plan.node || plan.path == L"\\")
    {
        return;
    }

    if (plan.subtree_snapshots.empty())
    {
        plan.node->delete_latched = false;
        plan.node->delete_pending = false;
        plan.node->delete_intent_count = 0;
        plan.node->delete_requested_after_children = false;
        plan.node->caller_delete_retry_required = false;
        SetNodePath(*plan.node, plan.path);
        IndexNodeLocked(c, plan.node);
        if (plan.parent && plan.parent->is_directory)
        {
            AddChildName(*plan.parent, plan.leaf);
        }
        RestoreFileRollbackSnapshotLocked(c, plan.file_snapshot);
        return;
    }

    for (auto it = plan.subtree_snapshots.rbegin(); it != plan.subtree_snapshots.rend(); ++it)
    {
        auto& entry = *it;
        if (!entry.node)
        {
            continue;
        }

        entry.node->delete_latched = false;
        entry.node->delete_pending = false;
        entry.node->delete_intent_count = 0;
        entry.node->delete_requested_after_children = false;
        entry.node->caller_delete_retry_required = false;
        SetNodePath(*entry.node, entry.node->path);
        IndexNodeLocked(c, entry.node);
        if (entry.node->path != L"\\")
        {
            auto parent = TryGetNodeLockedNormalized(c, ParentOfNormalizedPath(entry.node->path));
            if (parent && parent->is_directory)
            {
                AddChildName(*parent, LeafNameOfNormalizedPath(entry.node->path));
            }
        }
        RestoreFileRollbackSnapshotLocked(c, entry.file_snapshot);
    }
}

struct SetFileSizeRollbackSnapshot
{
    std::uint64_t previous_size = 0;
    FILETIME previous_timestamp{};
    std::uint64_t tail_offset = 0;
    std::filesystem::path tail_backup_path;
};

bool CaptureSetFileSizeRollbackTail(
    HANDLE file,
    const std::filesystem::path& hydration_path,
    std::uint64_t previous_size,
    std::uint64_t new_size,
    SetFileSizeRollbackSnapshot& snapshot)
{
    snapshot.previous_size = previous_size;
    snapshot.tail_offset = new_size;
    if (file == INVALID_HANDLE_VALUE || new_size >= previous_size)
    {
        return true;
    }

    const auto backup_name = hydration_path.filename().wstring() +
        L".set-size-tail." +
        std::to_wstring(GetTickCount64()) +
        L".tmp";
    snapshot.tail_backup_path = hydration_path.parent_path() / backup_name;

    std::error_code ec;
    std::filesystem::create_directories(snapshot.tail_backup_path.parent_path(), ec);
    if (ec)
    {
        snapshot.tail_backup_path.clear();
        return false;
    }

    HANDLE backup = CreateFileW(
        snapshot.tail_backup_path.wstring().c_str(),
        GENERIC_WRITE,
        FILE_SHARE_READ,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_TEMPORARY | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED,
        nullptr);
    if (backup == INVALID_HANDLE_VALUE)
    {
        snapshot.tail_backup_path.clear();
        return false;
    }

    std::vector<std::byte> buffer(1024 * 1024);
    std::uint64_t remaining = previous_size - new_size;
    std::uint64_t offset = new_size;
    bool ok = true;
    while (remaining > 0)
    {
        const auto chunk = static_cast<DWORD>(std::min<std::uint64_t>(remaining, buffer.size()));
        OVERLAPPED read_ov{};
        read_ov.Offset = static_cast<DWORD>(offset & 0xffffffffull);
        read_ov.OffsetHigh = static_cast<DWORD>(offset >> 32);
        DWORD read = 0;
        if (!ReadFile(file, buffer.data(), chunk, &read, &read_ov) || read != chunk)
        {
            ok = false;
            break;
        }

        DWORD written = 0;
        if (!WriteFile(backup, buffer.data(), read, &written, nullptr) || written != read)
        {
            ok = false;
            break;
        }

        remaining -= read;
        offset += read;
    }

    CloseHandle(backup);
    if (!ok)
    {
        std::filesystem::remove(snapshot.tail_backup_path, ec);
        snapshot.tail_backup_path.clear();
    }
    return ok;
}

void RestoreSetFileSizeRollbackTail(HANDLE file, const SetFileSizeRollbackSnapshot& snapshot)
{
    if (file == INVALID_HANDLE_VALUE || snapshot.tail_backup_path.empty())
    {
        return;
    }

    HANDLE backup = CreateFileW(
        snapshot.tail_backup_path.wstring().c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (backup == INVALID_HANDLE_VALUE)
    {
        return;
    }

    std::vector<std::byte> buffer(1024 * 1024);
    std::uint64_t offset = snapshot.tail_offset;
    while (true)
    {
        DWORD read = 0;
        if (!ReadFile(backup, buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr) || read == 0)
        {
            break;
        }

        OVERLAPPED write_ov{};
        write_ov.Offset = static_cast<DWORD>(offset & 0xffffffffull);
        write_ov.OffsetHigh = static_cast<DWORD>(offset >> 32);
        DWORD written = 0;
        if (!WriteFile(file, buffer.data(), read, &written, &write_ov) || written != read)
        {
            break;
        }
        offset += written;
    }

    CloseHandle(backup);
}

void DiscardSetFileSizeRollbackTail(const SetFileSizeRollbackSnapshot& snapshot)
{
    if (!snapshot.tail_backup_path.empty())
    {
        std::error_code ec;
        std::filesystem::remove(snapshot.tail_backup_path, ec);
    }
}

#ifdef APFSACCESS_HAS_RW_ENGINE
bool ReadCommittedFileRangeWithoutMetadataLock(
    MountContext* c,
    const std::wstring& canonical_path_key,
    const std::wstring& trace_path,
    std::uint64_t offset,
    std::size_t bytes_to_read,
    std::byte* destination,
    std::size_t destination_size,
    std::size_t& out_bytes_read);
#endif

bool EnsureHydrated(MountContext* c, const std::shared_ptr<Node>& n, bool allow_empty_placeholder = false)
{
    if (!c || !n || n->is_directory)
    {
        return false;
    }

    auto file = HydrationPath(c, *n);
    bool stale_hydration = false;
    std::uint64_t logical_size = 0;
    std::wstring committed_read_path;
    {
        std::lock_guard<std::mutex> lock(c->mutex);
        stale_hydration = IsHydrationStaleLocked(c, n);
        logical_size = n->file_size;
        committed_read_path = CommittedReadPathForNodeLocked(*n);
    }
    const auto committed_read_path_key = LowerPathKey(committed_read_path);
    if (!stale_hydration)
    {
        WIN32_FILE_ATTRIBUTE_DATA hydration_attributes{};
        if (GetFileAttributesExW(
                file.wstring().c_str(),
                GetFileExInfoStandard,
                &hydration_attributes))
        {
            const bool is_directory =
                (hydration_attributes.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            const auto cached_size =
                (static_cast<std::uint64_t>(hydration_attributes.nFileSizeHigh) << 32) |
                static_cast<std::uint64_t>(hydration_attributes.nFileSizeLow);
            if (!is_directory && cached_size == logical_size)
            {
                return true;
            }

            InvalidateHydrationReadHandle(c);
            std::error_code remove_ec;
            std::filesystem::remove(file, remove_ec);
        }
        else
        {
            const auto error = GetLastError();
            if (error != ERROR_FILE_NOT_FOUND &&
                error != ERROR_PATH_NOT_FOUND &&
                error != ERROR_INVALID_NAME)
            {
                // Match the old error-code path: an indeterminate cache probe
                // must not remove a file that may still be usable.
            }
        }
    }
    else
    {
        InvalidateHydrationReadHandle(c);
        std::error_code ec;
        std::filesystem::remove(file, ec);
    }

#ifdef APFSACCESS_HAS_RW_ENGINE
    const auto try_hydrate_from_metadata = [&]() -> bool
    {
        if (!c->metadata_store)
        {
            return false;
        }

        {
            std::lock_guard<std::mutex> metadata_lock(c->metadata_mutex);
            auto inode = c->metadata_store->LookupCommittedInodeByPath(committed_read_path);
            if (!inode.has_value() || inode->is_directory)
            {
                return false;
            }

            logical_size = inode->logical_size;
        }

        if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<LONGLONG>::max()))
        {
            return false;
        }

        std::filesystem::create_directories(file.parent_path());
        const auto sequence = g_hydration_temp_sequence.fetch_add(
            1,
            std::memory_order_relaxed);
        const auto temp_file = file.parent_path() /
            (file.filename().wstring() + L".tmp." +
             std::to_wstring(GetCurrentProcessId()) + L"." +
             std::to_wstring(GetCurrentThreadId()) + L"." +
             std::to_wstring(sequence));
        HANDLE hydrated = CreateFileW(
            temp_file.wstring().c_str(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            CREATE_NEW,
            kHydrationCacheFileAttributes,
            nullptr);
        if (hydrated == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        bool published = false;
        ScopeExit cleanup_hydrated
        {
            [&]()
            {
                if (hydrated != INVALID_HANDLE_VALUE)
                {
                    CloseHandle(hydrated);
                }
                if (!published)
                {
                    std::error_code remove_ec;
                    std::filesystem::remove(temp_file, remove_ec);
                }
            }
        };

        DWORD ignored_bytes_returned = 0;
        (void)DeviceIoControl(
            hydrated,
            FSCTL_SET_SPARSE,
            nullptr,
            0,
            nullptr,
            0,
            &ignored_bytes_returned,
            nullptr);

        constexpr std::size_t kHydrationChunkBytes = 64 * 1024;
        std::vector<std::byte> chunk(kHydrationChunkBytes);
        std::uint64_t offset = 0;
        while (offset < logical_size)
        {
            const auto remaining = logical_size - offset;
            const auto chunk_bytes = static_cast<std::size_t>(std::min<std::uint64_t>(
                remaining,
                static_cast<std::uint64_t>(kHydrationChunkBytes)));
            std::size_t bytes_read = 0;
            // Snapshot the committed extents under metadata_mutex, then keep
            // that mutex free while the bounded device read runs. The helper
            // pins the snapshot with committed_read_gate so a checkpoint
            // cannot reuse its physical extents during the read.
            if (!ReadCommittedFileRangeWithoutMetadataLock(
                    c,
                    committed_read_path_key,
                    committed_read_path,
                    offset,
                    chunk_bytes,
                    chunk.data(),
                    chunk.size(),
                    bytes_read))
            {
                return false;
            }
            if (bytes_read > chunk_bytes)
            {
                return false;
            }
            if (bytes_read < chunk_bytes)
            {
                std::fill(
                    chunk.begin() + static_cast<std::ptrdiff_t>(bytes_read),
                    chunk.begin() + static_cast<std::ptrdiff_t>(chunk_bytes),
                    std::byte{0});
            }

            const auto has_non_zero = std::any_of(
                chunk.begin(),
                chunk.begin() + static_cast<std::ptrdiff_t>(chunk_bytes),
                [](std::byte value)
                {
                    return value != std::byte{0};
                });
            if (has_non_zero)
            {
                LARGE_INTEGER target{};
                target.QuadPart = static_cast<LONGLONG>(offset);
                if (!SetFilePointerEx(hydrated, target, nullptr, FILE_BEGIN))
                {
                    return false;
                }

                DWORD written = 0;
                if (!WriteFile(
                        hydrated,
                        chunk.data(),
                        static_cast<DWORD>(chunk_bytes),
                        &written,
                        nullptr) ||
                    written != chunk_bytes)
                {
                    return false;
                }
            }

            offset += chunk_bytes;
        }

        LARGE_INTEGER target_size{};
        target_size.QuadPart = static_cast<LONGLONG>(logical_size);
        if (!SetFilePointerEx(hydrated, target_size, nullptr, FILE_BEGIN) ||
            !SetEndOfFile(hydrated))
        {
            return false;
        }
        if (!FlushFileBuffers(hydrated))
        {
            return false;
        }
        if (!CloseHandle(hydrated))
        {
            hydrated = INVALID_HANDLE_VALUE;
            return false;
        }
        hydrated = INVALID_HANDLE_VALUE;
        if (!MoveFileExW(
                temp_file.wstring().c_str(),
                file.wstring().c_str(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        {
            return false;
        }
        published = true;
        {
            std::lock_guard<std::mutex> lock(c->mutex);
            ClearHydrationStaleLockedNormalized(c, n->path);
        }
        return true;
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

    if (logical_size != 0)
    {
        return false;
    }

    std::filesystem::create_directories(file.parent_path());
    std::ofstream out(file, std::ios::binary | std::ios::trunc);
    const auto created = out.good();
    if (created)
    {
        std::lock_guard<std::mutex> lock(c->mutex);
        ClearHydrationStaleLockedNormalized(c, n->path);
    }
    return created;
}

#ifdef APFSACCESS_HAS_RW_ENGINE
struct PayloadSpoolReadIdentities
{
    std::optional<apfsaccess::rw::MetadataStore::PayloadIdentity> visible;
    std::optional<apfsaccess::rw::MetadataStore::PayloadIdentity> committed;
    bool same_path = true;
};

bool SamePayloadSpoolIdentity(
    const std::optional<apfsaccess::rw::MetadataStore::PayloadIdentity>& left,
    const std::optional<apfsaccess::rw::MetadataStore::PayloadIdentity>& right)
{
    return left.has_value() &&
        right.has_value() &&
        left->object_id == right->object_id &&
        left->generation == right->generation;
}

PayloadSpoolReadIdentities ResolvePayloadSpoolIdentities(
    MountContext* c,
    const std::wstring& visible_path,
    const std::wstring& committed_read_path);

PayloadSpoolReadIdentities ResolvePayloadSpoolIdentitiesForCanonicalKeys(
    MountContext* c,
    const std::wstring& visible_path,
    const std::wstring& visible_path_key,
    const std::wstring& committed_read_path,
    const std::wstring& committed_read_path_key,
    OpenContext* open_context = nullptr);

std::optional<apfsaccess::rw::MetadataStore::PayloadIdentity> ResolvePayloadSpoolIdentity(
    MountContext* c,
    const std::wstring& path);

bool OverlayPayloadSpoolBestEffort(
    MountContext* c,
    const std::wstring& path,
    const apfsaccess::rw::MetadataStore::PayloadIdentity& identity,
    std::uint64_t offset,
    std::byte* destination,
    std::size_t destination_size,
    std::size_t* bytes_overlayed = nullptr);

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

    if (!hydrate_if_missing)
    {
        std::lock_guard<std::mutex> lock(c->mutex);
        if (IsHydrationStaleLocked(c, node))
        {
            return std::nullopt;
        }
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

void RecordPayloadRangeProviderCall(MountContext* c)
{
    if (!c)
    {
        return;
    }

    std::lock_guard<std::mutex> lock(c->payload_range_provider_diagnostics_mutex);
    ++c->payload_range_provider_call_count;
}

void RecordPayloadRangeProviderFailure(
    MountContext* c,
    std::wstring_view phase,
    const std::wstring& path,
    const apfsaccess::rw::MetadataStore::PayloadIdentity& identity,
    std::uint64_t offset,
    std::size_t bytes,
    bool hydration_stale,
    const std::wstring& committed_read_path,
    DWORD win32_error = ERROR_SUCCESS)
{
    if (!c)
    {
        return;
    }

    std::wostringstream detail;
    detail << phase
           << L";path=" << path
           << L";committedPath=" << committed_read_path
           << L";object=" << identity.object_id
           << L";generation=" << identity.generation
           << L";offset=" << offset
           << L";bytes=" << bytes
           << L";hydrationStale=" << (hydration_stale ? L"true" : L"false");
    if (win32_error != ERROR_SUCCESS)
    {
        detail << L";win32=" << win32_error;
    }

    std::lock_guard<std::mutex> lock(c->payload_range_provider_diagnostics_mutex);
    ++c->payload_range_provider_failure_count;
    c->last_payload_range_provider_failure = detail.str();
}

void TracePayloadRangeProviderResult(
    MountContext* c,
    std::wstring_view phase,
    const std::wstring& path,
    const apfsaccess::rw::MetadataStore::PayloadIdentity& identity,
    std::uint64_t offset,
    std::size_t bytes,
    bool hydration_stale,
    const std::wstring& committed_read_path,
    std::wstring_view base_source,
    bool base_read_ok,
    bool overlay_ok,
    std::size_t bytes_overlayed)
{
    if (!c || !IsHostCommitTraceEnabled())
    {
        return;
    }

    std::wcerr << L"[FsHost] RW payload-range result phase=" << phase
               << L" path=" << path
               << L" committedPath=" << committed_read_path
               << L" object=" << identity.object_id
               << L" generation=" << identity.generation
               << L" offset=" << offset
               << L" bytes=" << bytes
               << L" hydrationStale=" << (hydration_stale ? L"true" : L"false")
               << L" base=" << base_source
               << L" baseRead=" << (base_read_ok ? L"true" : L"false")
               << L" overlay=" << (overlay_ok ? L"true" : L"false")
               << L" overlayBytes=" << bytes_overlayed
               << std::endl;
}

bool TryReadNativeCommitHydrationBaseRange(
    MountContext* c,
    const std::shared_ptr<Node>& node,
    const apfsaccess::rw::MetadataStore::PayloadIdentity& identity,
    std::uint64_t logical_size,
    std::uint64_t offset,
    std::span<std::byte> destination)
{
    if (!c || !node || node->is_directory || destination.empty() ||
        logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()) ||
        offset > logical_size ||
        destination.size() > static_cast<std::size_t>(logical_size - offset))
    {
        return false;
    }

    const auto hydration_path = HydrationPath(c, *node);
    std::shared_ptr<HydrationReadCacheState> cache_state;
    {
        std::lock_guard<std::mutex> cache_lock(c->hydration_read_cache_mutex);
        const auto cache_matches = c->hydration_read_cache_state &&
            c->hydration_read_cache_state->path == hydration_path.wstring() &&
            c->hydration_read_cache_state->object_id == identity.object_id &&
            c->hydration_read_cache_state->generation == identity.generation &&
            c->hydration_read_cache_state->file_size == logical_size;
        if (cache_matches)
        {
            cache_state = c->hydration_read_cache_state;
            ++c->hydration_read_cache_hit_count;
        }
        else
        {
            const auto opened = CreateFileW(
                hydration_path.wstring().c_str(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED | FILE_FLAG_RANDOM_ACCESS,
                nullptr);
            if (opened == INVALID_HANDLE_VALUE)
            {
                return false;
            }

            auto opened_state = std::make_shared<HydrationReadCacheState>();
            opened_state->handle = TakeWinHandle(opened);
            LARGE_INTEGER file_size{};
            if (!GetFileSizeEx(
                    static_cast<HANDLE>(opened_state->handle.get()),
                    &file_size) ||
                file_size.QuadPart < 0 ||
                static_cast<std::uint64_t>(file_size.QuadPart) != logical_size)
            {
                return false;
            }

            opened_state->path = hydration_path.wstring();
            opened_state->object_id = identity.object_id;
            opened_state->generation = identity.generation;
            opened_state->file_size = logical_size;
            c->hydration_read_cache_state = std::move(opened_state);
            cache_state = c->hydration_read_cache_state;
            ++c->hydration_read_cache_open_count;
        }
    }

    OVERLAPPED overlapped{};
    overlapped.Offset = static_cast<DWORD>(offset & 0xffffffffull);
    overlapped.OffsetHigh = static_cast<DWORD>(offset >> 32);
    DWORD bytes_read = 0;
    auto read_ok = ReadFile(
        static_cast<HANDLE>(cache_state->handle.get()),
        destination.data(),
        static_cast<DWORD>(destination.size()),
        &bytes_read,
        &overlapped);
    if (!read_ok && GetLastError() == ERROR_IO_PENDING)
    {
        read_ok = WaitForHydrationRead(
            static_cast<HANDLE>(cache_state->handle.get()),
            overlapped,
            bytes_read);
    }
    if (!read_ok || bytes_read != destination.size())
    {
        std::lock_guard<std::mutex> cache_lock(c->hydration_read_cache_mutex);
        if (c->hydration_read_cache_state == cache_state)
        {
            c->hydration_read_cache_state.reset();
        }
        return false;
    }

    return true;
}

bool ReadHydratedPayloadRangeForPath(
    MountContext* c,
    const std::wstring& path,
    const apfsaccess::rw::MetadataStore::PayloadIdentity& identity,
    std::uint64_t offset,
    std::span<std::byte> destination)
{
    if (!c || destination.empty())
    {
        return c != nullptr;
    }

    RecordPayloadRangeProviderCall(c);

    // MetadataStore supplies normalized inode paths. Avoid normalizing the
    // same path again for every bounded commit-range callback.
    std::shared_ptr<Node> node;
    bool read_state_captured = false;
    bool hydration_stale = false;
    std::wstring committed_read_path;
    {
        ObservedMutexGuard lock(
            c->mutex,
            &c->perf_namespace_mutex_wait,
            &c->perf_namespace_mutex_hold);
        node = TryGetVisibleNodeLockedNormalized(c, path);
        if (node)
        {
            hydration_stale = IsHydrationStaleLocked(c, node);
            committed_read_path = CommittedReadPathForNodeLocked(*node);
            read_state_captured = true;
        }
    }
    if (!node)
    {
        node = FindNodeNormalized(c, path);
    }
    if (!node || node->is_directory)
    {
        RecordPayloadRangeProviderFailure(
            c,
            L"node-missing-or-directory",
            path,
            identity,
            offset,
            destination.size(),
            false,
            std::wstring());
        return false;
    }

    if (!read_state_captured)
    {
        std::lock_guard<std::mutex> lock(c->mutex);
        hydration_stale = IsHydrationStaleLocked(c, node);
        committed_read_path = CommittedReadPathForNodeLocked(*node);
    }
    const auto committed_read_path_for_lookup = committed_read_path.empty() ? path : committed_read_path;
    const auto committed_read_path_key = LowerPathKey(committed_read_path_for_lookup);

    const auto overlay_spool = [&](bool require_full_coverage, std::wstring_view base_source) -> bool
    {
        std::size_t bytes_overlayed = 0;
        const auto overlay_ok = OverlayPayloadSpoolBestEffort(
                c,
                path,
                identity,
                offset,
                destination.data(),
                destination.size(),
                &bytes_overlayed);
        TracePayloadRangeProviderResult(
            c,
            L"commit-range-overlay",
            path,
            identity,
            offset,
            destination.size(),
            hydration_stale,
            committed_read_path,
            base_source,
            !require_full_coverage,
            overlay_ok,
            bytes_overlayed);
        if (!overlay_ok)
        {
            return false;
        }

        // A successful committed read provides the unchanged base bytes, so
        // the spool only needs to cover the dirty ranges. If that base read
        // failed, accept only a fully covered spool to remain fail-closed.
        return !require_full_coverage || bytes_overlayed == destination.size();
    };

    if (hydration_stale)
    {
        std::uint64_t logical_size = 0;
        {
            std::lock_guard<std::mutex> lock(c->mutex);
            logical_size = node->file_size;
        }

        // Native foreground writes leave the hydration sidecar as an exact
        // committed snapshot while dirty bytes live in the payload spool.
        // Reuse that local snapshot during commit-range materialization; the
        // raw APFS read below remains the fail-closed fallback for missing,
        // incomplete, or unrelated stale caches.
        const auto can_use_hydration_base =
            c->metadata_store != nullptr &&
            c->payload_spool != nullptr &&
            c->pending_native_writes.load(std::memory_order_acquire);
        if (can_use_hydration_base &&
            TryReadNativeCommitHydrationBaseRange(
                c,
                node,
                identity,
                logical_size,
                offset,
                destination))
        {
            const auto final_overlay_ok = overlay_spool(false, L"hydration-sidecar");
            if (!final_overlay_ok)
            {
                RecordPayloadRangeProviderFailure(
                    c,
                    L"stale-hydration-base-spool-overlay",
                    path,
                    identity,
                    offset,
                    destination.size(),
                    hydration_stale,
                    committed_read_path);
            }
            return final_overlay_ok;
        }

        bool committed_read_ok = false;
        if (c->metadata_store)
        {
            std::size_t committed_bytes_read = 0;
            // The range provider is invoked while metadata_mutex is held by
            // the commit path, so call the store directly without re-locking.
            committed_read_ok = c->metadata_store->ReadCommittedFileRangeIntoCanonicalPathKey(
                committed_read_path_key,
                committed_read_path_for_lookup,
                offset,
                destination.size(),
                destination.data(),
                destination.size(),
                committed_bytes_read);
        }
        if (!committed_read_ok)
        {
            std::fill(destination.begin(), destination.end(), std::byte{0});
        }
        const auto final_overlay_ok = overlay_spool(
            !committed_read_ok,
            committed_read_ok ? L"committed-apfs" : L"zero-fill");
        if (!final_overlay_ok)
        {
            RecordPayloadRangeProviderFailure(
                c,
                committed_read_ok
                    ? L"stale-spool-overlay-after-committed-read"
                    : L"stale-spool-overlay-after-committed-read-failure",
                path,
                identity,
                offset,
                destination.size(),
                hydration_stale,
                committed_read_path);
        }
        return final_overlay_ok;
    }

    const auto hydrated_file = HydrationPath(c, *node);
    const auto hydration_path_string = hydrated_file.wstring();
    std::shared_ptr<HydrationReadCacheState> cache_state;
    DWORD cache_error = ERROR_SUCCESS;
    enum class CacheOpenFailure
    {
        None,
        Open,
        Size,
    } cache_open_failure = CacheOpenFailure::None;
    {
        std::lock_guard<std::mutex> hydration_cache_lock(c->hydration_read_cache_mutex);
        cache_state = c->hydration_read_cache_state;
        const auto cache_matches = cache_state &&
            cache_state->path == hydration_path_string &&
            cache_state->object_id == identity.object_id &&
            cache_state->generation == identity.generation;
        if (!cache_matches)
        {
            const auto opened = CreateFileW(
                hydration_path_string.c_str(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED | FILE_FLAG_RANDOM_ACCESS,
                nullptr);
            if (opened == INVALID_HANDLE_VALUE)
            {
                cache_error = GetLastError();
                cache_open_failure = CacheOpenFailure::Open;
            }
            else
            {
                auto opened_state = std::make_shared<HydrationReadCacheState>();
                opened_state->handle = TakeWinHandle(opened);
                LARGE_INTEGER file_size{};
                if (!GetFileSizeEx(
                        static_cast<HANDLE>(opened_state->handle.get()),
                        &file_size) ||
                    file_size.QuadPart < 0)
                {
                    cache_error = GetLastError();
                    cache_open_failure = CacheOpenFailure::Size;
                }
                else
                {
                    opened_state->path = hydration_path_string;
                    opened_state->object_id = identity.object_id;
                    opened_state->generation = identity.generation;
                    opened_state->file_size = static_cast<std::uint64_t>(file_size.QuadPart);
                    c->hydration_read_cache_state = std::move(opened_state);
                    cache_state = c->hydration_read_cache_state;
                    ++c->hydration_read_cache_open_count;
                }
            }
        }
        else
        {
            ++c->hydration_read_cache_hit_count;
        }
    }

    if (cache_open_failure != CacheOpenFailure::None)
    {
        if (cache_open_failure == CacheOpenFailure::Open &&
            (cache_error == ERROR_FILE_NOT_FOUND || cache_error == ERROR_PATH_NOT_FOUND))
        {
            std::fill(destination.begin(), destination.end(), std::byte{0});
            const auto overlay_ok = overlay_spool(true, L"zero-fill");
            if (!overlay_ok)
            {
                RecordPayloadRangeProviderFailure(
                    c,
                    L"missing-hydration-spool-overlay",
                    path,
                    identity,
                    offset,
                    destination.size(),
                    hydration_stale,
                    committed_read_path,
                    cache_error);
            }
            return overlay_ok;
        }
        RecordPayloadRangeProviderFailure(
            c,
            cache_open_failure == CacheOpenFailure::Size ? L"hydration-size" : L"hydration-open",
            path,
            identity,
            offset,
            destination.size(),
            hydration_stale,
            committed_read_path,
            cache_error);
        return false;
    }

    const auto file = static_cast<HANDLE>(cache_state->handle.get());
    const auto file_bytes = cache_state->file_size;
    const auto available_bytes = offset < file_bytes
        ? file_bytes - offset
        : 0;
    const auto bytes_to_read = static_cast<std::size_t>(std::min<std::uint64_t>(
        static_cast<std::uint64_t>(destination.size()),
        available_bytes));
    if (bytes_to_read < destination.size())
    {
        std::fill(
            destination.begin() + static_cast<std::ptrdiff_t>(bytes_to_read),
            destination.end(),
            std::byte{0});
#ifdef APFSACCESS_FSHOST_UNIT_TEST
        g_hydrated_range_zero_fill_bytes_for_test += destination.size() - bytes_to_read;
#endif
    }

#ifdef APFSACCESS_FSHOST_UNIT_TEST
    if (g_hydration_read_before_io_hook != nullptr)
    {
        g_hydration_read_before_io_hook(c);
    }
#endif

    if (bytes_to_read > 0)
    {
        auto remaining = bytes_to_read;
        std::size_t destination_offset = 0;
        auto file_offset = offset;
        while (remaining > 0)
        {
            const auto bytes_this_read = static_cast<DWORD>(std::min<std::size_t>(
                remaining,
                static_cast<std::size_t>(std::numeric_limits<DWORD>::max())));
            OVERLAPPED ov{};
            ov.Offset = static_cast<DWORD>(file_offset & 0xffffffffull);
            ov.OffsetHigh = static_cast<DWORD>(file_offset >> 32);
            DWORD bytes_read = 0;
            auto read_ok = ReadFile(
                    file,
                    destination.data() + static_cast<std::ptrdiff_t>(destination_offset),
                    bytes_this_read,
                    &bytes_read,
                    &ov);
            DWORD error = read_ok ? ERROR_SUCCESS : GetLastError();
            if (!read_ok && error == ERROR_IO_PENDING)
            {
                read_ok = WaitForHydrationRead(file, ov, bytes_read);
                if (!read_ok)
                {
                    error = GetLastError();
                }
            }
            if (!read_ok || bytes_read != bytes_this_read)
            {
                if (read_ok && bytes_read != bytes_this_read)
                {
                    error = ERROR_HANDLE_EOF;
                }
                {
                    std::lock_guard<std::mutex> hydration_cache_lock(c->hydration_read_cache_mutex);
                    if (c->hydration_read_cache_state == cache_state)
                    {
                        c->hydration_read_cache_state.reset();
                    }
                }
                RecordPayloadRangeProviderFailure(
                    c,
                    L"hydration-read",
                    path,
                    identity,
                    offset,
                    destination.size(),
                    hydration_stale,
                    committed_read_path,
                    error);
                return false;
            }

            destination_offset += bytes_read;
            file_offset += bytes_read;
            remaining -= bytes_read;
        }
    }

    std::size_t bytes_overlayed = 0;
    const auto overlay_ok = OverlayPayloadSpoolBestEffort(
        c,
        path,
        identity,
        offset,
        destination.data(),
        destination.size(),
        &bytes_overlayed);
    TracePayloadRangeProviderResult(
        c,
        L"hydration-handle-overlay",
        path,
        identity,
        offset,
        destination.size(),
        hydration_stale,
        committed_read_path,
        L"hydration-handle",
        true,
        overlay_ok,
        bytes_overlayed);
    if (!overlay_ok)
    {
        RecordPayloadRangeProviderFailure(
            c,
            L"hydration-spool-overlay",
            path,
            identity,
            offset,
            destination.size(),
            hydration_stale,
            committed_read_path);
    }
    return overlay_ok;
}

bool ReadHydratedPayloadRangeForPath(
    MountContext* c,
    const std::wstring& path,
    std::uint64_t offset,
    std::span<std::byte> destination)
{
    if (!c || destination.empty())
    {
        return c != nullptr;
    }

    const auto identity = ResolvePayloadSpoolIdentity(c, path);
    if (!identity.has_value())
    {
        return ReadHydratedPayloadRangeForPath(
            c,
            path,
            apfsaccess::rw::MetadataStore::PayloadIdentity{},
            offset,
            destination);
    }

    return ReadHydratedPayloadRangeForPath(c, path, *identity, offset, destination);
}

bool MergeCommittedInodeStateIntoNodeIndex(MountContext* c)
{
    ScopedPerfTimer perf_scope(c ? &c->perf_merge_committed_inodes : nullptr);

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

    const auto set_node_path_from_normalized = [](Node& node, const std::wstring& normalized_path)
    {
        node.path = normalized_path;
        node.path_key = LowerPathKey(normalized_path);
    };
    const auto normalized_path_key = [](const std::wstring& normalized_path) -> std::wstring
    {
        return LowerPathKey(normalized_path);
    };
    const auto parent_of_normalized = [](const std::wstring& normalized_path) -> std::wstring
    {
        if (normalized_path == L"\\")
        {
            return normalized_path;
        }

        const auto pos = normalized_path.find_last_of(L'\\');
        if (pos <= 0 || pos == std::wstring::npos)
        {
            return L"\\";
        }
        return normalized_path.substr(0, pos);
    };
    const auto leaf_of_normalized = [](const std::wstring& normalized_path) -> std::wstring
    {
        if (normalized_path == L"\\")
        {
            return L"\\";
        }

        const auto pos = normalized_path.find_last_of(L'\\');
        if (pos == std::wstring::npos || pos + 1 >= normalized_path.size())
        {
            return normalized_path;
        }
        return normalized_path.substr(pos + 1);
    };
    const auto try_get_node_by_normalized_path = [&](const std::wstring& normalized_path) -> std::shared_ptr<Node>
    {
        const auto it = c->nodes.find(normalized_path_key(normalized_path));
        return it == c->nodes.end() ? std::shared_ptr<Node>{} : it->second;
    };
    const auto ensure_directory_node = [&](const std::wstring& normalized_path) -> std::shared_ptr<Node>
    {
        if (normalized_path.empty())
        {
            return {};
        }

        auto existing = try_get_node_by_normalized_path(normalized_path);
        if (existing)
        {
            if (!existing->is_directory)
            {
                existing->is_directory = true;
                existing->file_size = 0;
                existing->delete_pending = false;
            }
            if (normalized_path == L"\\" && existing->apfs_path.empty())
            {
                existing->apfs_path = ApfsRoot(c->args);
            }
            return existing;
        }

        auto created = std::make_shared<Node>();
        set_node_path_from_normalized(*created, normalized_path);
        created->hydration_key = created->path_key;
        created->is_directory = true;
        created->file_size = 0;
        created->timestamp = now;
        created->loaded = true;
        created->delete_pending = false;

        if (normalized_path == L"\\")
        {
            created->apfs_path = ApfsRoot(c->args);
        }
        else
        {
            auto parent = try_get_node_by_normalized_path(parent_of_normalized(normalized_path));
            if (parent && !parent->apfs_path.empty())
            {
                created->apfs_path = ApfsChild(parent->apfs_path, leaf_of_normalized(normalized_path));
            }
        }

        EmplaceNodeLocked(c, created);
        return created;
    };

    std::size_t applied_entries = 0;
    for (const auto& inode : committed_inodes)
    {
        const auto& normalized_path = inode.full_path;
        if (normalized_path.empty())
        {
            continue;
        }

        const auto parent_path = parent_of_normalized(normalized_path);
        if (normalized_path != L"\\")
        {
            (void)ensure_directory_node(parent_path);
        }

        auto node = try_get_node_by_normalized_path(normalized_path);
        if (!node)
        {
            node = std::make_shared<Node>();
            set_node_path_from_normalized(*node, normalized_path);
            EmplaceNodeLocked(c, node);
        }

        set_node_path_from_normalized(*node, normalized_path);
        node->hydration_key = node->path_key;
        node->is_directory = inode.is_directory;
        node->file_size = inode.is_directory ? 0 : inode.logical_size;
        node->timestamp = inode.timestamp_utc != 0 ? ToFileTime(inode.timestamp_utc) : now;
        node->delete_pending = false;

        if (normalized_path == L"\\")
        {
            node->apfs_path = ApfsRoot(c->args);
            node->loaded = true;
        }
        else if (auto parent = try_get_node_by_normalized_path(parent_path); parent && !parent->apfs_path.empty())
        {
            node->apfs_path = ApfsChild(parent->apfs_path, leaf_of_normalized(normalized_path));
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

        if (normalized_path != L"\\")
        {
            if (auto parent = try_get_node_by_normalized_path(parent_path); parent && parent->is_directory)
            {
                AddChildName(*parent, leaf_of_normalized(normalized_path));
            }
        }

        ++applied_entries;
    }

    return applied_entries > 0;
}

bool MergeCommittedDirectoryChildrenIntoNodeIndex(MountContext* c, const std::shared_ptr<Node>& dir)
{
    ScopedPerfTimer perf_scope(c ? &c->perf_merge_committed_inodes : nullptr);

    if (!c || !c->metadata_store || !dir || !dir->is_directory)
    {
        return false;
    }

    std::wstring directory_path;
    {
        std::lock_guard<std::mutex> lock(c->mutex);
        if (!dir->is_directory)
        {
            return false;
        }
        directory_path = dir->path;
    }
    if (directory_path.empty())
    {
        return false;
    }

    std::optional<apfsaccess::rw::MetadataStore::InodeRecord> committed_directory;
    std::optional<std::vector<apfsaccess::rw::MetadataStore::InodeRecord>> committed_children;
    {
        std::lock_guard<std::mutex> metadata_lock(c->metadata_mutex);
        committed_directory = c->metadata_store->LookupCommittedInodeByPath(directory_path);
        if (!committed_directory.has_value() || !committed_directory->is_directory)
        {
            return false;
        }
        committed_children = c->metadata_store->SnapshotCommittedDirectoryChildInodes(committed_directory->object_id);
    }

    if (!committed_children.has_value())
    {
        return false;
    }

    const auto now = UtcNow();
    std::lock_guard<std::mutex> lock(c->mutex);

    const auto set_node_path_from_normalized = [](Node& node, const std::wstring& normalized_path)
    {
        node.path = normalized_path;
        node.path_key = LowerPathKey(normalized_path);
    };
    const auto normalized_path_key = [](const std::wstring& normalized_path) -> std::wstring
    {
        return LowerPathKey(normalized_path);
    };
    const auto try_get_node_by_normalized_path = [&](const std::wstring& normalized_path) -> std::shared_ptr<Node>
    {
        const auto it = c->nodes.find(normalized_path_key(normalized_path));
        return it == c->nodes.end() ? std::shared_ptr<Node>{} : it->second;
    };

    auto parent = try_get_node_by_normalized_path(committed_directory->full_path);
    if (!parent || !parent->is_directory)
    {
        return false;
    }

    const auto parent_apfs_path = parent->apfs_path;

    std::size_t applied_entries = 0;
    for (const auto& inode : *committed_children)
    {
        const auto& normalized_path = inode.full_path;
        if (normalized_path.empty() || inode.parent_object_id != committed_directory->object_id)
        {
            continue;
        }

        auto node = try_get_node_by_normalized_path(normalized_path);
        if (!node)
        {
            node = std::make_shared<Node>();
            set_node_path_from_normalized(*node, normalized_path);
            EmplaceNodeLocked(c, node);
        }

        set_node_path_from_normalized(*node, normalized_path);
        node->hydration_key = node->path_key;
        node->is_directory = inode.is_directory;
        node->file_size = inode.is_directory ? 0 : inode.logical_size;
        node->timestamp = inode.timestamp_utc != 0 ? ToFileTime(inode.timestamp_utc) : now;
        node->delete_pending = false;
        const auto leaf_name = LeafNameOfNormalizedPath(normalized_path);
        node->apfs_path = parent_apfs_path.empty()
            ? std::wstring{}
            : ApfsChild(parent_apfs_path, leaf_name);
        if (node->is_directory)
        {
            node->loaded = false;
        }
        AddChildName(*parent, leaf_name);
        ++applied_entries;
    }

    if (applied_entries != committed_children->size())
    {
        return false;
    }

    parent->loaded = true;
    parent->delete_pending = false;
    return true;
}

bool MergeLastCommittedInodeChangesIntoNodeIndex(MountContext* c)
{
    ScopedPerfTimer perf_scope(c ? &c->perf_merge_committed_inodes : nullptr);

    if (!c || !c->metadata_store)
    {
        return false;
    }

    std::vector<apfsaccess::rw::MetadataStore::CommittedInodeChange> drained_changes;
    std::optional<std::uint64_t> committed_xid;
    {
        std::lock_guard<std::mutex> metadata_lock(c->metadata_mutex);
        committed_xid = c->metadata_store->LastCommittedXid();
        drained_changes = c->metadata_store->TakeLastCommittedInodeChanges();
    }

    std::lock_guard<std::mutex> lock(c->mutex);

    if (!committed_xid.has_value() ||
        c->last_committed_inode_changes_xid != committed_xid ||
        !drained_changes.empty())
    {
        c->last_committed_inode_changes = std::move(drained_changes);
        c->last_committed_inode_changes_xid = committed_xid;
    }

    const auto& changes = c->last_committed_inode_changes;
    if (changes.empty())
    {
        return true;
    }

    const auto now = UtcNow();

    const auto set_node_path_from_normalized = [](Node& node, const std::wstring& normalized_path)
    {
        node.path = normalized_path;
        node.path_key = LowerPathKey(normalized_path);
    };
    const auto normalized_path_key = [](const std::wstring& normalized_path) -> std::wstring
    {
        return LowerPathKey(normalized_path);
    };
    const auto parent_of_normalized = [](const std::wstring& normalized_path) -> std::wstring
    {
        if (normalized_path == L"\\")
        {
            return normalized_path;
        }

        const auto pos = normalized_path.find_last_of(L'\\');
        if (pos <= 0 || pos == std::wstring::npos)
        {
            return L"\\";
        }
        return normalized_path.substr(0, pos);
    };
    const auto leaf_of_normalized = [](const std::wstring& normalized_path) -> std::wstring
    {
        if (normalized_path == L"\\")
        {
            return L"\\";
        }

        const auto pos = normalized_path.find_last_of(L'\\');
        if (pos == std::wstring::npos || pos + 1 >= normalized_path.size())
        {
            return normalized_path;
        }
        return normalized_path.substr(pos + 1);
    };
    const auto try_get_node_by_normalized_path = [&](const std::wstring& normalized_path) -> std::shared_ptr<Node>
    {
        const auto it = c->nodes.find(normalized_path_key(normalized_path));
        return it == c->nodes.end() ? std::shared_ptr<Node>{} : it->second;
    };
    const auto ensure_directory_node = [&](const std::wstring& normalized_path) -> std::shared_ptr<Node>
    {
        auto existing = try_get_node_by_normalized_path(normalized_path);
        if (existing)
        {
            if (!existing->is_directory)
            {
                existing->is_directory = true;
                existing->file_size = 0;
                existing->delete_pending = false;
            }
            if (normalized_path == L"\\" && existing->apfs_path.empty())
            {
                existing->apfs_path = ApfsRoot(c->args);
            }
            return existing;
        }

        auto created = std::make_shared<Node>();
        set_node_path_from_normalized(*created, normalized_path);
        created->hydration_key = created->path_key;
        created->is_directory = true;
        created->file_size = 0;
        created->timestamp = now;
        created->loaded = true;
        created->delete_pending = false;

        if (normalized_path == L"\\")
        {
            created->apfs_path = ApfsRoot(c->args);
        }
        else
        {
            auto parent = try_get_node_by_normalized_path(parent_of_normalized(normalized_path));
            if (parent && !parent->apfs_path.empty())
            {
                created->apfs_path = ApfsChild(parent->apfs_path, leaf_of_normalized(normalized_path));
            }
        }

        EmplaceNodeLocked(c, created);
        return created;
    };

    std::size_t applied_entries = 0;
    for (const auto& change : changes)
    {
        if (!change.previous_path.empty())
        {
            const auto& previous_path = change.previous_path;
            if (auto previous_parent = try_get_node_by_normalized_path(parent_of_normalized(previous_path));
                previous_parent && previous_parent->is_directory)
            {
                RemoveChildName(*previous_parent, leaf_of_normalized(previous_path));
            }

            if (!change.current.has_value() ||
                normalized_path_key(previous_path) != normalized_path_key(change.current->full_path))
            {
                if (auto old_node = try_get_node_by_normalized_path(previous_path))
                {
                    EraseIndexedNodeLocked(c, old_node);
                }
            }
        }

        if (!change.current.has_value())
        {
            ++applied_entries;
            continue;
        }

        const auto& inode = change.current.value();
        const auto& normalized_path = inode.full_path;
        if (normalized_path.empty())
        {
            continue;
        }

        const auto parent_path = parent_of_normalized(normalized_path);
        if (normalized_path != L"\\")
        {
            (void)ensure_directory_node(parent_path);
        }

        auto node = try_get_node_by_normalized_path(normalized_path);
        if (!node)
        {
            node = std::make_shared<Node>();
            set_node_path_from_normalized(*node, normalized_path);
            EmplaceNodeLocked(c, node);
        }

        set_node_path_from_normalized(*node, normalized_path);
        node->hydration_key = node->path_key;
        node->is_directory = inode.is_directory;
        node->file_size = inode.is_directory ? 0 : inode.logical_size;
        node->timestamp = inode.timestamp_utc != 0 ? ToFileTime(inode.timestamp_utc) : now;
        node->delete_pending = false;

        if (normalized_path == L"\\")
        {
            node->apfs_path = ApfsRoot(c->args);
            node->loaded = true;
        }
        else if (auto parent = try_get_node_by_normalized_path(parent_path); parent && !parent->apfs_path.empty())
        {
            const auto leaf_name = leaf_of_normalized(normalized_path);
            node->apfs_path = ApfsChild(parent->apfs_path, leaf_name);
            AddChildName(*parent, leaf_name);
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

    return applied_entries > 0;
}
#endif

bool IsOverlayWriteEnabled(const MountContext* c)
{
    if (!c)
    {
        return false;
    }
    std::lock_guard<std::recursive_mutex> runtime_lock(c->runtime_state_mutex);
    return c->overlay_write_enabled && !c->recovery_active;
}

bool IsNativeWriteEnabled(const MountContext* c)
{
    if (!c)
    {
        return false;
    }
    std::lock_guard<std::recursive_mutex> runtime_lock(c->runtime_state_mutex);
    return c->native_write_enabled;
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
    if (!c)
    {
        return false;
    }
    {
        std::lock_guard<std::recursive_mutex> runtime_lock(c->runtime_state_mutex);
        if (!c->native_write_enabled || c->recovery_active)
        {
            return false;
        }
    }

#ifdef APFSACCESS_HAS_RW_ENGINE
#ifdef APFSACCESS_FSHOST_UNIT_TEST
    if (c->test_force_native_mutation_staging_success)
    {
        return true;
    }
#endif

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

bool HasRequiredRecoveryIdentityForNativeWrite(const Arguments& args)
{
    if (args.readwrite &&
        IsWriteBackendMode(args.write_backend, L"Native") &&
        IsRawPhysicalDevicePath(args.device))
    {
        return IsValidRecoveryIdentity(args.recovery_identity);
    }

    return true;
}

void RequestGroupedDeferredAcceptanceFinish(MountContext* c);

bool BeginMutationShutdownDrain(MountContext* c)
{
    if (!c)
    {
        return false;
    }

    // Linearization point of the drain: the CAS that sets the flag inside the
    // combined admission domain. Every callback whose admission increment
    // linearized before this point is visible in the in-flight count; every
    // later increment attempt observes the flagged state and is refused.
    auto admission_state = c->mutation_admission_state.load(std::memory_order_seq_cst);
    for (;;)
    {
        const auto next_state = admission_state | kMutationAdmissionDrainFlag;
        if (c->mutation_admission_state.compare_exchange_weak(
                admission_state,
                next_state,
                std::memory_order_seq_cst,
                std::memory_order_seq_cst))
        {
            break;
        }
    }
    RequestGroupedDeferredAcceptanceFinish(c);
    const auto admission_state_after_flag =
        c->mutation_admission_state.load(std::memory_order_acquire);
    const auto initial_external = MutationAdmissionCount(admission_state_after_flag);
    const auto initial_foreground =
        c->active_foreground_mutation_callbacks.load(std::memory_order_acquire);
    if (initial_external == 0 && initial_foreground == 0)
    {
        return true;
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
        << initial_external
        << L" external and "
        << initial_foreground
        << L" foreground mutation callback(s)." << std::endl;

    const auto drain_started = static_cast<std::uint64_t>(GetTickCount64());
    while (MutationAdmissionCount(c->mutation_admission_state.load(std::memory_order_acquire)) > 0 ||
           c->active_foreground_mutation_callbacks.load(std::memory_order_acquire) > 0)
    {
        const auto now = static_cast<std::uint64_t>(GetTickCount64());
        if (now - drain_started >= static_cast<std::uint64_t>(drain_timeout_seconds) * 1000ull)
        {
            const auto pending_external =
                MutationAdmissionCount(c->mutation_admission_state.load(std::memory_order_acquire));
            const auto pending_foreground =
                c->active_foreground_mutation_callbacks.load(std::memory_order_acquire);
            std::wcerr << L"[FsHost] Shutdown drain timeout after "
                << drain_timeout_seconds
                << L"s with "
                << pending_external
                << L" external and "
                << pending_foreground
                << L" foreground mutation callback(s); continuing shutdown." << std::endl;
            return false;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }

    std::wcerr << L"[FsHost] Shutdown drain complete." << std::endl;
    return true;
}

[[noreturn]] void AwaitExternalGuardianTermination() noexcept
{
    // The managed parent owns the bounded timeout and exact-process quarantine.
    // Do not start another WinFsp call or unwind MountContext while a worker can
    // still reference it.
    for (;;)
    {
        Sleep(INFINITE);
    }
}

void DeleteWinFspFileSystemOwned(MountContext* c) noexcept
{
    if (!c || !c->fs || !c->api.Delete)
    {
        return;
    }

    c->api.Delete(c->fs);
    c->fs = nullptr;
}

void TeardownWinFspFileSystemOwned(MountContext* c) noexcept
{
    if (!c || !c->fs)
    {
        return;
    }

    c->mount_ready.store(false, std::memory_order_release);
    if (c->api.Stop)
    {
        c->api.Stop(c->fs);
    }
    if (c->api.RemoveMount)
    {
        c->api.RemoveMount(c->fs);
    }
    DeleteWinFspFileSystemOwned(c);
}

int ResolveFsHostShutdownExitCode(bool callback_drain_ok, NTSTATUS commit_status, bool journal_finalize_ok)
{
    if (!callback_drain_ok)
    {
        return 9;
    }
    if (!NT_SUCCESS(commit_status))
    {
        return 10;
    }
    return journal_finalize_ok ? 0 : 11;
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
    auto session_identity = SanitizeFileComponent(c->args.volume);
    if (session_identity.empty())
    {
        session_identity = L"apfs";
    }
    session_identity += L"_";
    session_identity += SanitizeFileComponent(c->args.mount.empty() ? L"mount" : c->args.mount);

    const auto build_session_id = [](const std::wstring& identity)
    {
        return identity + L"_" +
            std::to_wstring(GetCurrentProcessId()) + L"_" +
            std::to_wstring(GetTickCount64());
    };
    auto session_id = build_session_id(session_identity);
    constexpr std::size_t kHydrationAtomicPathReserve = 80;
    auto candidate_cache_root = session_root / session_id / "hydrate";
    if (candidate_cache_root.native().size() + kHydrationAtomicPathReserve >= MAX_PATH)
    {
        std::wostringstream compact_identity;
        compact_identity << L"session_" << std::hex
                         << static_cast<unsigned long long>(std::hash<std::wstring>{}(
                                c->args.volume + L"\n" + c->args.mount));
        session_id = build_session_id(compact_identity.str());
        candidate_cache_root = session_root / session_id / "hydrate";
    }
    if (candidate_cache_root.native().size() + kHydrationAtomicPathReserve >= MAX_PATH)
    {
        return false;
    }

    c->session_root = session_root / session_id;
    c->cache_root = std::move(candidate_cache_root);

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
std::filesystem::path BuildLegacyRecoveryMarkerPath(
    const Arguments& args,
    const std::filesystem::path& recovery_root)
{
    auto marker_name = SanitizeFileComponent(args.device) + L"_" +
                       SanitizeFileComponent(args.volume) + L"_" +
                       SanitizeFileComponent(args.write_backend) + L".state";
    return recovery_root / marker_name;
}

std::filesystem::path ReadEnvironmentPath(const wchar_t* variable_name)
{
    if (variable_name == nullptr || *variable_name == L'\0')
    {
        return {};
    }

    std::array<wchar_t, 512> value{};
    auto copied = GetEnvironmentVariableW(
        variable_name,
        value.data(),
        static_cast<DWORD>(value.size()));
    if (copied == 0)
    {
        return {};
    }
    if (copied < value.size())
    {
        return std::filesystem::path(std::wstring(value.data(), copied));
    }

    // GetEnvironmentVariableW returns the required character count without
    // the terminator when the initial buffer is too small. Allocate one extra
    // slot so the retry has room for that terminator.
    std::wstring expanded(static_cast<std::size_t>(copied) + 1, L'\0');
    copied = GetEnvironmentVariableW(
        variable_name,
        expanded.data(),
        static_cast<DWORD>(expanded.size()));
    if (copied == 0 || copied >= expanded.size())
    {
        return {};
    }
    expanded.resize(copied);
    return std::filesystem::path(expanded);
}

std::filesystem::path ResolveRecoveryRoot()
{
    if (const auto configured = ReadEnvironmentPath(L"APFSACCESS_RECOVERY_ROOT");
        !configured.empty())
    {
        return configured;
    }

    if (const auto local_app_data = ReadEnvironmentPath(L"LOCALAPPDATA");
        !local_app_data.empty())
    {
        return local_app_data / "ApfsAccess" / "Recovery";
    }

    std::error_code ec;
    const auto temporary = std::filesystem::temp_directory_path(ec);
    return ec ? std::filesystem::path{} : temporary / "ApfsAccess" / "recovery";
}

std::filesystem::path BuildRecoveryMarkerPath(const Arguments& args)
{
    const auto recovery_root = ResolveRecoveryRoot();
    if (!args.recovery_identity.empty())
    {
        return recovery_root /
            (BuildRecoveryStorageKey(args) + L"_" +
             SanitizeFileComponent(args.write_backend) + L".state");
    }

    return BuildLegacyRecoveryMarkerPath(args, recovery_root);
}

#ifdef APFSACCESS_HAS_RW_ENGINE
bool EndsWithIgnoreCase(const std::wstring& value, const std::wstring& suffix)
{
    return value.size() >= suffix.size() &&
           _wcsicmp(
               value.c_str() + (value.size() - suffix.size()),
               suffix.c_str()) == 0;
}

bool LegacyWalIdentityMatchesVolume(const std::string& raw_identity, const Arguments& args)
{
    const auto identity = Utf8ToWide(raw_identity);
    constexpr wchar_t kOffsetMarker[] = L"|offset=";
    constexpr wchar_t kVolumeMarker[] = L"|volume=";
    constexpr wchar_t kSerialMarker[] = L"|serial=";
    if (identity.rfind(L"device=", 0) != 0)
    {
        return false;
    }

    const auto offset_pos = identity.find(kOffsetMarker);
    const auto volume_pos = identity.find(kVolumeMarker);
    const auto serial_pos = identity.rfind(kSerialMarker);
    if (offset_pos == std::wstring::npos ||
        volume_pos == std::wstring::npos ||
        serial_pos == std::wstring::npos ||
        offset_pos >= volume_pos ||
        volume_pos >= serial_pos)
    {
        return false;
    }

    const auto offset_begin = offset_pos + std::wcslen(kOffsetMarker);
    const auto volume_begin = volume_pos + std::wcslen(kVolumeMarker);
    try
    {
        const auto offset = std::stoull(
            identity.substr(offset_begin, volume_pos - offset_begin));
        return offset == args.device_offset_bytes &&
               identity.substr(volume_begin, serial_pos - volume_begin) == args.volume;
    }
    catch (...)
    {
        return false;
    }
}

bool LegacySpoolDirectoryNameMatchesVolume(
    const std::filesystem::path& root,
    const Arguments& args)
{
    const auto name = root.filename().wstring();
    const auto marker = L"_" + SanitizeFileComponent(args.volume) + L"_" +
        std::to_wstring(args.device_offset_bytes) + L"_";
    const auto marker_pos = name.rfind(marker);
    if (marker_pos == std::wstring::npos)
    {
        return false;
    }

    const auto serial_begin = marker_pos + marker.size();
    return serial_begin < name.size() &&
           std::all_of(
               name.begin() + static_cast<std::ptrdiff_t>(serial_begin),
               name.end(),
               [](wchar_t ch) { return std::iswdigit(ch) != 0; });
}

bool LegacySpoolRootHasAmbiguousEvidence(
    const std::filesystem::path& root,
    const Arguments& args)
{
    const auto wal_path = root / "write-ahead.wal";
    std::error_code ec;
    const auto wal_exists = std::filesystem::is_regular_file(wal_path, ec) && !ec;
    if (!wal_exists)
    {
        ec.clear();
        const auto spool_path = root / "payload-spool.bin";
        const auto spool_size = std::filesystem::is_regular_file(spool_path, ec) && !ec
            ? std::filesystem::file_size(spool_path, ec)
            : 0;
        return !ec && spool_size > 0 && LegacySpoolDirectoryNameMatchesVolume(root, args);
    }

    const auto wal = apfsaccess::rw::WriteAheadLog::ReadAll(wal_path, "");
    if (wal.status != apfsaccess::rw::WriteAheadLog::ReadStatus::Ok)
    {
        return LegacySpoolDirectoryNameMatchesVolume(root, args);
    }

    std::string legacy_identity;
    bool mixed_identities = false;
    bool matching_identity_seen = false;
    for (const auto& record : wal.records)
    {
        if (record.volume_identity.empty())
        {
            return LegacySpoolDirectoryNameMatchesVolume(root, args);
        }
        matching_identity_seen = matching_identity_seen ||
            LegacyWalIdentityMatchesVolume(record.volume_identity, args);
        if (legacy_identity.empty())
        {
            legacy_identity = record.volume_identity;
        }
        else if (legacy_identity != record.volume_identity)
        {
            mixed_identities = true;
        }
    }

    if (legacy_identity.empty())
    {
        return false;
    }
    if (mixed_identities)
    {
        return matching_identity_seen;
    }
    if (!matching_identity_seen)
    {
        return false;
    }

    try
    {
        apfsaccess::rw::TransactionManager tx(args.write_safety_level);
        tx.SetVolumeIdentity(Utf8ToWide(legacy_identity));
        tx.SetJournalPath(wal_path.wstring());
        const auto watermarks = tx.Watermarks();
        if (!tx.RecoveryStateValid() ||
            tx.HasUnappliedAcceptedWork() ||
            watermarks.cleanup_sequence < watermarks.apfs_durable_sequence)
        {
            return true;
        }

        apfsaccess::rw::PayloadSpool spool({
            root,
            legacy_identity,
            kPayloadSpoolMaxBytes,
            kPayloadSpoolForegroundFlushBytes,
            kPayloadSpoolForegroundFlushAppends,
        });
        const auto counters = spool.SnapshotCounters();
        return counters.recovery_required ||
               counters.dirty_range_count > 0 ||
               counters.spool_bytes > 0 ||
               counters.index_dirty;
    }
    catch (...)
    {
        return true;
    }
}

bool TryLoadLegacyRecoveryMarkerStrict(
    const std::filesystem::path& marker_path,
    RecoveryMarkerState& state)
{
    if (!TryLoadRecoveryMarkerState(marker_path, state))
    {
        return false;
    }

    std::ifstream input(marker_path, std::ios::binary);
    std::size_t dirty_field_count = 0;
    std::string line;
    while (std::getline(input, line))
    {
        if (line == "dirty=0" || line == "dirty=1" ||
            line == "dirty=true" || line == "dirty=false" ||
            line == "dirty=True" || line == "dirty=False")
        {
            ++dirty_field_count;
            if (dirty_field_count > 1)
            {
                return false;
            }
        }
    }
    return dirty_field_count == 1;
}

std::optional<std::filesystem::path> FindAmbiguousLegacyRecoveryEvidence(
    const Arguments& args,
    const std::filesystem::path& spool_base_root,
    const std::filesystem::path& recovery_root)
{
    if (args.recovery_identity.empty())
    {
        return std::nullopt;
    }

    std::error_code ec;
    const auto stable_spool_root = BuildPayloadSpoolSessionRoot(args, spool_base_root);
    const auto spool_base_path_exists = std::filesystem::exists(spool_base_root, ec);
    if (ec == std::errc::no_such_file_or_directory)
    {
        ec.clear();
    }
    if (ec)
    {
        return spool_base_root;
    }
    const auto spool_base_exists = spool_base_path_exists &&
        std::filesystem::is_directory(spool_base_root, ec);
    if (ec || (spool_base_path_exists && !spool_base_exists))
    {
        return spool_base_root;
    }
    if (spool_base_exists)
    {
        for (std::filesystem::directory_iterator it(spool_base_root, ec), end;
             !ec && it != end;
             it.increment(ec))
        {
            if (!it->is_directory(ec) || ec || it->path() == stable_spool_root)
            {
                ec.clear();
                continue;
            }
            if (LegacySpoolRootHasAmbiguousEvidence(it->path(), args))
            {
                return it->path();
            }
        }
        if (ec)
        {
            return spool_base_root;
        }
    }

    const auto stable_marker = BuildRecoveryMarkerPath(args);
    const auto marker_suffix = L"_" + SanitizeFileComponent(args.volume) + L"_" +
        SanitizeFileComponent(args.write_backend) + L".state";
    ec.clear();
    const auto recovery_root_path_exists = std::filesystem::exists(recovery_root, ec);
    if (ec == std::errc::no_such_file_or_directory)
    {
        ec.clear();
    }
    if (ec)
    {
        return recovery_root;
    }
    const auto recovery_root_exists = recovery_root_path_exists &&
        std::filesystem::is_directory(recovery_root, ec);
    if (ec || (recovery_root_path_exists && !recovery_root_exists))
    {
        return recovery_root;
    }
    if (recovery_root_exists)
    {
        for (std::filesystem::directory_iterator it(recovery_root, ec), end;
             !ec && it != end;
             it.increment(ec))
        {
            if (!it->is_regular_file(ec) || ec || it->path() == stable_marker ||
                !EndsWithIgnoreCase(it->path().filename().wstring(), marker_suffix))
            {
                ec.clear();
                continue;
            }

            RecoveryMarkerState state{};
            if (!TryLoadLegacyRecoveryMarkerStrict(it->path(), state) || state.dirty)
            {
                return it->path();
            }
        }
    }
    return ec ? std::optional<std::filesystem::path>(recovery_root) : std::nullopt;
}

void LatchRecoveryIdentityStartupBlock(
    MountContext& ctx,
    const std::wstring& reason,
    const std::wstring& action,
    bool pending_recovery_evidence)
{
    std::lock_guard<std::recursive_mutex> runtime_lock(ctx.runtime_state_mutex);
    ctx.recovery_identity_blocked = true;
    ctx.recovery_active = true;
    ctx.write_degraded = true;
    ctx.native_write_enabled = false;
    ctx.overlay_write_enabled = false;
    ctx.pending_native_writes = pending_recovery_evidence;
    ctx.runtime_recovery_reason = reason;
    ctx.runtime_last_recovery_action = action;
}

bool EnforceRecoveryIdentityStartupPolicy(
    MountContext& ctx,
    const std::filesystem::path& spool_base_root,
    const std::filesystem::path& recovery_root)
{
    if (!ctx.args.readwrite ||
        !IsWriteBackendMode(ctx.args.write_backend, L"Native") ||
        !IsRawPhysicalDevicePath(ctx.args.device))
    {
        return true;
    }

    if (ctx.args.recovery_identity.empty())
    {
        LatchRecoveryIdentityStartupBlock(
            ctx,
            L"ImmutableRecoveryIdentityMissing",
            L"StartupBlockedByMissingRecoveryIdentity",
            false);
        return false;
    }
    if (!IsValidRecoveryIdentity(ctx.args.recovery_identity))
    {
        LatchRecoveryIdentityStartupBlock(
            ctx,
            L"ImmutableRecoveryIdentityInvalid",
            L"StartupBlockedByInvalidRecoveryIdentity",
            false);
        return false;
    }

    std::optional<std::filesystem::path> ambiguous_evidence;
    try
    {
#ifdef APFSACCESS_FSHOST_UNIT_TEST
        if (ctx.test_force_recovery_identity_scan_exception)
        {
            throw std::runtime_error("forced recovery identity scan failure");
        }
#endif
        ambiguous_evidence = FindAmbiguousLegacyRecoveryEvidence(
            ctx.args,
            spool_base_root,
            recovery_root);
    }
    catch (const std::exception& error)
    {
        LatchRecoveryIdentityStartupBlock(
            ctx,
            L"LegacyRecoveryEvidenceAmbiguous",
            L"StartupBlockedByLegacyRecoveryEvidence",
            true);
        std::wcerr << L"[FsHost] Recovery storage inspection failed ('"
            << Utf8ToWide(error.what())
            << L"'); retaining all evidence and mounting read-only."
            << std::endl;
        return false;
    }
    catch (...)
    {
        LatchRecoveryIdentityStartupBlock(
            ctx,
            L"LegacyRecoveryEvidenceAmbiguous",
            L"StartupBlockedByLegacyRecoveryEvidence",
            true);
        std::wcerr << L"[FsHost] Recovery storage inspection failed; retaining all evidence and mounting read-only."
            << std::endl;
        return false;
    }
    if (!ambiguous_evidence.has_value())
    {
        return true;
    }

    LatchRecoveryIdentityStartupBlock(
        ctx,
        L"LegacyRecoveryEvidenceAmbiguous",
        L"StartupBlockedByLegacyRecoveryEvidence",
        true);
    std::wcerr << L"[FsHost] Ambiguous legacy recovery evidence at '"
        << ambiguous_evidence->wstring()
        << L"'; retaining it and mounting read-only."
        << std::endl;
    return false;
}
#endif

std::uint64_t ComputeWriteCommitTimeoutBudgetSeconds(
    int configured_timeout_seconds,
    std::uint64_t pending_payload_bytes) noexcept
{
    const auto base_timeout_seconds = static_cast<std::uint64_t>(std::max(1, configured_timeout_seconds));
    std::uint64_t timeout_seconds = base_timeout_seconds;
    if (pending_payload_bytes > 0)
    {
        const auto payload_seconds =
            (pending_payload_bytes / kWriteCommitTimeoutPayloadBytesPerSecond) +
            ((pending_payload_bytes % kWriteCommitTimeoutPayloadBytesPerSecond) == 0 ? 0 : 1);
        const auto payload_extension_seconds =
            payload_seconds > (std::numeric_limits<std::uint64_t>::max() - kWriteCommitTimeoutPayloadHeadroomSeconds)
                ? std::numeric_limits<std::uint64_t>::max()
                : payload_seconds + kWriteCommitTimeoutPayloadHeadroomSeconds;
        const auto payload_timeout_seconds =
            base_timeout_seconds > (std::numeric_limits<std::uint64_t>::max() - payload_extension_seconds)
                ? std::numeric_limits<std::uint64_t>::max()
                : base_timeout_seconds + payload_extension_seconds;
        timeout_seconds = std::max(timeout_seconds, payload_timeout_seconds);
    }

    return std::max(
        base_timeout_seconds,
        std::min<std::uint64_t>(timeout_seconds, kWriteCommitTimeoutPayloadExtensionMaxSeconds));
}

void ArmCommitDeadline(MountContext* c, std::uint64_t pending_payload_bytes)
{
    if (!c)
    {
        return;
    }

    const auto timeout_seconds = ComputeWriteCommitTimeoutBudgetSeconds(
        c->args.write_commit_timeout_seconds,
        pending_payload_bytes);
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

void LatchRecoveryMarkerPersistenceFailure(
    MountContext* c,
    const wchar_t* action)
{
    if (!c)
    {
        return;
    }

    std::lock_guard<std::recursive_mutex> runtime_lock(c->runtime_state_mutex);
    c->recovery_active = true;
    c->write_degraded = true;
    c->native_write_enabled = false;
    c->overlay_write_enabled = false;
    c->runtime_recovery_reason = L"RecoveryMarkerPersistFailed";
    c->runtime_last_recovery_action = action && *action
        ? action
        : L"RecoveryMarkerPersistFailed";
}

bool UpdateRecoveryMarkerBestEffort(MountContext* c, bool dirty)
{
    if (!c)
    {
        return true;
    }

    std::lock_guard<std::recursive_mutex> runtime_lock(c->runtime_state_mutex);
    if (c->recovery_marker_file.empty())
    {
        c->pending_native_writes = dirty;
        return true;
    }

    const auto now_tick_ms = GetTickCount64();
    const auto state_matches_cache =
        c->last_recovery_marker_dirty.has_value() &&
        c->last_recovery_marker_dirty.value() == dirty &&
        c->last_recovery_marker_commit_xid == c->runtime_last_commit_xid;
    const auto deep_validation_due =
        c->recovery_marker_last_deep_validation_tick_ms == 0 ||
        now_tick_ms < c->recovery_marker_last_deep_validation_tick_ms ||
        now_tick_ms - c->recovery_marker_last_deep_validation_tick_ms >=
            kRecoveryMarkerDeepValidationIntervalMs;

    // Mutation bursts repeatedly publish the same marker state. Keep the
    // normal path to one cheap existence/type check, but periodically route
    // through the fully validating persistence primitive to repair replacement
    // or corruption and to preserve the fail-closed marker contract.
    if (state_matches_cache &&
        !deep_validation_due &&
        RecoveryMarkerFastPathFileIsPresent(c->recovery_marker_file))
    {
        c->pending_native_writes = dirty;
        return true;
    }

    RecoveryMarkerState marker{};
    marker.dirty = dirty;
    marker.last_commit_xid = c->runtime_last_commit_xid;
    if (!PersistRecoveryMarkerState(c, c->recovery_marker_file, marker))
    {
        LatchRecoveryMarkerPersistenceFailure(c, L"RecoveryMarkerPersistFailed");
        return false;
    }
    c->recovery_marker_last_deep_validation_tick_ms = now_tick_ms;
    c->pending_native_writes = dirty;
    return true;
}

bool ArmRecoveryMarkerForPendingWriteAheadLog(
    MountContext& context,
    bool write_ahead_log_recovery_pending)
{
    if (!write_ahead_log_recovery_pending)
    {
        return true;
    }

    if (!UpdateRecoveryMarkerBestEffort(&context, true))
    {
        std::wcerr << L"[FsHost] Pending write-ahead log recovery could not durably arm the recovery marker; RW remains blocked."
            << std::endl;
        return false;
    }

    std::wcerr << L"[FsHost] Pending write-ahead log recovery durably re-armed the recovery marker before metadata replay."
        << std::endl;
    return true;
}

NTSTATUS CommitNativeMutationsBestEffort(MountContext* c, const wchar_t* origin);
bool HasPendingNativeMutations(MountContext* c);
bool HasUnappliedAcceptedWorkBestEffort(MountContext* c);
bool CanClearNativeRecoveryStateBestEffort(MountContext* c);
bool PendingNativeMutationsCanDelayClose(MountContext* c);
bool PendingNativeMutationsCanContinueDeferredClose(MountContext* c);
void RequestDeferredCloseCommit(MountContext* c, std::uint64_t accepted_target = 0);
bool BeginDeferredCommitBarrier(
    MountContext* c,
    bool from_worker,
    std::uint64_t required_target = 0);
bool CompleteDeferredCommitBarrier(
    MountContext* c,
    bool success,
    NTSTATUS status,
    bool* effective_success = nullptr);
bool DeferredCommitPressureReached(MountContext* c);
bool DrainNativeMutationsForDeferredPressure(MountContext* c);

bool HasBlockedRecoveryEvidence(const MountContext& context)
{
    return context.recovery_identity_blocked.load(std::memory_order_acquire) ||
           context.recovery_marker_blocked.load(std::memory_order_acquire);
}

bool ShouldRunNativeShutdownFinalDrain(const MountContext& context)
{
    return context.args.readwrite &&
           !HasBlockedRecoveryEvidence(context);
}
void DiscardDeferredDeleteRollbackPlans(MountContext* c);
void RestoreDeferredDeleteRollbackPlans(MountContext* c);
NTSTATUS DrainNativeMutationsByPolicy(
    MountContext* c,
    const wchar_t* origin,
    bool has_delete_plans = false,
    bool namespace_boundary = false);
void RollbackRenameLocalStateLocked(MountContext* c, const RenameLocalSnapshot& snapshot);
void DiscardDeferredRenameRollbackPlans(MountContext* c);
void RestoreDeferredRenameRollbackPlans(MountContext* c);
bool FinalizeMutationJournalBestEffort(MountContext* c, const wchar_t* origin);
bool FlushPayloadSpoolForAcceptedBoundaryBestEffort(MountContext* c, const wchar_t* origin);
bool AcceptMutationJournalForDeferredCommitBestEffort(
    MountContext* c,
    const wchar_t* origin,
    std::uint64_t* accepted_sequence = nullptr,
    GroupedDeferredAcceptanceFailureReason* failure_reason = nullptr,
    MutationCallbackScope* callback_scope = nullptr,
    bool wait_for_durability = true);
bool AcceptMutationJournalForGroupedDeferredCommitBestEffort(
    MountContext* c,
    MutationCallbackScope& mutation_scope,
    const wchar_t* origin,
    std::uint64_t* accepted_sequence = nullptr,
    bool* grouped_attempted = nullptr,
    bool* grouped_failure_handled = nullptr);
void AbortMutationJournalBestEffort(MountContext* c, const wchar_t* origin);
void StartDeferredCommitWorker(MountContext* c);
bool StopDeferredCommitWorker(MountContext* c);
NTSTATUS LatchDeferredWalAcceptanceFailureBeforeApfsCommit(
    MountContext* c,
    const wchar_t* origin);
bool NodePathCommittedForExperimentalRename(MountContext* c, const std::wstring& path, bool require_directory);

#ifdef APFSACCESS_HAS_RW_ENGINE
using NativeCommitUrgency = apfsaccess::rw::WritePipeline::CommitUrgency;
#else
enum class NativeCommitUrgency
{
    None,
    MetadataOnlyCanDelay,
    FileContentCloseCanDelay,
    DirtyLimitMustCommit,
    UserFlushMustCommit,
    NamespaceBoundaryMustCommit,
    DeleteBoundaryMustCommit,
    ShutdownMustCommit,
};
#endif

NativeCommitUrgency ClassifyNativeCommitRequest(
    MountContext* c,
    const wchar_t* origin,
    bool has_delete_plans,
    bool namespace_boundary);

void LatchDirtyTransactionLimitExceeded(MountContext* c, std::size_t dirty_limit)
{
    if (!c)
    {
        return;
    }

    const auto fail_closed = apfsaccess::rw::WritePipeline::AbortOrFailClosed({
        true,
        IsRecoveryPolicyFailClosed(c->args.write_recovery_policy),
    });
    {
        std::lock_guard<std::recursive_mutex> runtime_lock(c->runtime_state_mutex);
        c->recovery_active = true;
        c->runtime_recovery_reason = L"DirtyTransactionLimitExceeded";
        c->runtime_last_recovery_action = L"DowngradedAfterDirtyTransactionLimit";
        if (fail_closed.should_fail_closed)
        {
            c->write_degraded = true;
            c->native_write_enabled = false;
            c->overlay_write_enabled = false;
        }
    }

    std::wcerr << L"[FsHost] RW native-mutation warning: pending mutation limit reached ("
        << dirty_limit
        << L") and write path was downgraded for safety."
        << std::endl;
    (void)UpdateRecoveryMarkerBestEffort(c, true);
    (void)WriteHostStatusFile(*c);
}

bool DrainNativeMutationsForDirtyLimit(MountContext* c, std::size_t dirty_limit, const wchar_t* origin)
{
    if (!c || !IsNativeWriteEnabled(c) || !c->metadata_store)
    {
        return true;
    }

    std::wcerr << L"[FsHost] RW native-mutation: pending mutation limit reached ("
        << dirty_limit
        << L"); draining commit before accepting more writes."
        << std::endl;

    const auto status = DrainNativeMutationsByPolicy(c, origin);
    if (NT_SUCCESS(status))
    {
        return FinalizeMutationJournalBestEffort(c, origin);
    }

    std::wcerr << L"[FsHost] RW native-mutation warning: dirty-limit drain failed with status 0x"
        << std::hex << static_cast<unsigned long>(status) << std::dec
        << L"."
        << std::endl;
    RestoreDeferredDeleteRollbackPlans(c);
    RestoreDeferredRenameRollbackPlans(c);
    LatchDirtyTransactionLimitExceeded(c, dirty_limit);
    return false;
}

bool DrainNativeMutationsForDeferredPressure(MountContext* c)
{
    if (!c ||
        !IsDeferCloseCommitsEnabled() ||
        !IsNativeWriteEnabled(c))
    {
        return true;
    }

    const auto status = DrainNativeMutationsByPolicy(c, L"DirtyLimit");
    if (!NT_SUCCESS(status))
    {
        RestoreDeferredDeleteRollbackPlans(c);
        RestoreDeferredRenameRollbackPlans(c);
        AbortMutationJournalBestEffort(c, L"DirtyLimit");
        return false;
    }

    return FinalizeMutationJournalBestEffort(c, L"DirtyLimit");
}

bool RecordNativeMutationBestEffort(
    MountContext* c,
    apfsaccess::rw::MetadataStore::MutationOperation operation,
    const std::wstring& path,
    const std::wstring& secondary_path = L"",
    std::uint64_t offset = 0,
    std::uint64_t length = 0,
    bool replace_if_exists = false,
    std::uint64_t timestamp_utc = 0,
    apfsaccess::rw::MetadataStore::PayloadIdentity* staged_payload_identity = nullptr,
    bool* metadata_staged = nullptr)
{
    if (metadata_staged)
    {
        *metadata_staged = false;
    }
    if (staged_payload_identity)
    {
        *staged_payload_identity = {};
    }
    if (!c || !IsNativeWriteEnabled(c))
    {
        return true;
    }

#ifdef APFSACCESS_FSHOST_UNIT_TEST
    if (c->test_force_native_mutation_staging_success)
    {
        const auto pressure_reached =
            c->test_forced_native_payload_bytes >= kDeferredCloseCommitPayloadBytesThreshold ||
            c->test_forced_native_mutation_count >= kDeferredCloseCommitBurstThreshold;
        if (pressure_reached && !DrainNativeMutationsForDeferredPressure(c))
        {
            return false;
        }
        const auto next_mutation_count = c->test_forced_native_mutation_count + 1;
        const auto content_only = next_mutation_count == 1
            ? operation == apfsaccess::rw::MetadataStore::MutationOperation::Write
            : c->test_forced_native_mutations_content_only &&
                operation == apfsaccess::rw::MetadataStore::MutationOperation::Write;
        if (!UpdateRecoveryMarkerBestEffort(c, true))
        {
            return false;
        }
        c->test_forced_native_mutation_count = next_mutation_count;
        c->test_forced_native_mutations_pending = true;
        c->test_forced_native_mutations_content_only = content_only;
        if (staged_payload_identity)
        {
            *staged_payload_identity = { 1, 1 };
        }
        if (metadata_staged)
        {
            *metadata_staged = true;
        }
        InvalidatePayloadIdentityCache(c);
        return true;
    }
#endif

    if (!c->metadata_store)
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
    const auto dirty_limit = static_cast<std::size_t>(std::max(1, c->args.write_max_dirty_transactions));
    bool drained_for_dirty_limit = false;
    bool drained_for_deferred_pressure = false;
    bool recovery_marker_armed = false;
    bool recovery_marker_was_clean = false;
    for (;;)
    {
        bool should_drain_dirty_limit = false;
        bool should_drain_deferred_pressure = false;
        bool should_arm_recovery_marker = false;
        {
            auto metadata_lock = AcquireObservedMutex(c->metadata_mutex, &c->perf_metadata_mutex_wait);
            should_drain_deferred_pressure =
                IsDeferCloseCommitsEnabled() &&
                (c->metadata_store->PendingPayloadDirtyByteEstimate() >=
                    kDeferredCloseCommitPayloadBytesThreshold ||
                 c->metadata_store->PendingPayloadObjectSummaryCount() >=
                    kDeferredCloseCommitBurstThreshold);
            if (!should_drain_deferred_pressure)
            {
                const auto decision = apfsaccess::rw::WritePipeline::StageForegroundMutation({
                    IsNativeWriteEnabled(c),
                    c->metadata_store != nullptr,
                    c->metadata_store->PendingMutationCount(),
                    dirty_limit,
                });
                if (decision.should_stage)
                {
                    if (!recovery_marker_armed)
                    {
                        should_arm_recovery_marker = true;
                    }
                    else
                    {
                        ScopedPerfTimer metadata_stage_scope(&c->perf_metadata_stage);
                        status = c->metadata_store->StageMutation(request, staged_payload_identity);
                        if (status != apfsaccess::rw::MetadataStore::MutationStatus::Applied)
                        {
                            failure_reason = c->metadata_store->LastMutationFailureReason();
                        }
                        break;
                    }
                }
                else
                {
                    should_drain_dirty_limit = decision.should_drain_dirty_limit;
                }
            }
        }

        if (should_arm_recovery_marker)
        {
            {
                std::lock_guard<std::recursive_mutex> runtime_lock(c->runtime_state_mutex);
                recovery_marker_was_clean = !c->pending_native_writes.load(std::memory_order_relaxed);
            }
            if (!UpdateRecoveryMarkerBestEffort(c, true))
            {
                std::wcerr << L"[FsHost] RW native-mutation warning: failed to persist recovery marker before staging." << std::endl;
                return false;
            }
            recovery_marker_armed = true;
#ifdef APFSACCESS_FSHOST_UNIT_TEST
            if (c->test_pause_after_recovery_marker_arm.load(std::memory_order_acquire))
            {
                c->test_recovery_marker_arm_paused.store(true, std::memory_order_release);
                while (!c->test_release_recovery_marker_arm.load(std::memory_order_acquire))
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                }
            }
#endif
            continue;
        }

        if (should_drain_deferred_pressure)
        {
            if (drained_for_deferred_pressure ||
                !DrainNativeMutationsForDeferredPressure(c))
            {
                return false;
            }
            drained_for_deferred_pressure = true;
            recovery_marker_armed = false;
            continue;
        }

        if (!should_drain_dirty_limit || drained_for_dirty_limit)
        {
            LatchDirtyTransactionLimitExceeded(c, dirty_limit);
            return false;
        }
        if (!DrainNativeMutationsForDirtyLimit(c, dirty_limit, L"DirtyLimit"))
        {
            return false;
        }
        drained_for_dirty_limit = true;
        recovery_marker_armed = false;
    }

    const auto rollback_recovery_marker_if_newly_armed = [&]()
    {
        if (recovery_marker_armed && recovery_marker_was_clean &&
            !UpdateRecoveryMarkerBestEffort(c, false))
        {
            std::wcerr << L"[FsHost] RW native-mutation warning: failed to roll back the recovery marker after mutation rejection." << std::endl;
        }
    };

    if (status != apfsaccess::rw::MetadataStore::MutationStatus::Applied)
    {
        const wchar_t* status_text = L"unknown";
        const wchar_t* operation_text = L"Unknown";
        switch (operation)
        {
        case apfsaccess::rw::MetadataStore::MutationOperation::CreateFile:
            operation_text = L"CreateFile";
            break;
        case apfsaccess::rw::MetadataStore::MutationOperation::CreateDirectory:
            operation_text = L"CreateDirectory";
            break;
        case apfsaccess::rw::MetadataStore::MutationOperation::Write:
            operation_text = L"Write";
            break;
        case apfsaccess::rw::MetadataStore::MutationOperation::SetFileSize:
            operation_text = L"SetFileSize";
            break;
        case apfsaccess::rw::MetadataStore::MutationOperation::Rename:
            operation_text = L"Rename";
            break;
        case apfsaccess::rw::MetadataStore::MutationOperation::Delete:
            operation_text = L"Delete";
            break;
        case apfsaccess::rw::MetadataStore::MutationOperation::SetBasicInfo:
            operation_text = L"SetBasicInfo";
            break;
        default:
            break;
        }
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

        if (operation == apfsaccess::rw::MetadataStore::MutationOperation::Delete &&
            !_wcsicmp(failure_reason.c_str(), L"DeleteTargetMissing"))
        {
            rollback_recovery_marker_if_newly_armed();
            std::wcerr << L"[FsHost] RW native-mutation info: delete target '"
                << path
                << L"' is already absent from native APFS metadata; treating duplicate delete as idempotent."
                << std::endl;
            return true;
        }

        {
            std::lock_guard<std::recursive_mutex> runtime_lock(c->runtime_state_mutex);
            c->last_native_mutation_failure_operation = operation_text;
            c->last_native_mutation_failure_path = path;
            c->last_native_mutation_failure_secondary_path = secondary_path;
            c->last_native_mutation_failure_reason = failure_reason;
            c->last_native_mutation_failure_status = status_text;
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
        rollback_recovery_marker_if_newly_armed();
        return false;
    }

    if (metadata_staged)
    {
        *metadata_staged = true;
    }
    InvalidatePayloadIdentityCache(c);
    return true;
}

PayloadSpoolReadIdentities ResolvePayloadSpoolIdentities(
    MountContext* c,
    const std::wstring& visible_path,
    const std::wstring& committed_read_path)
{
    return ResolvePayloadSpoolIdentitiesForCanonicalKeys(
        c,
        visible_path,
        Key(visible_path),
        committed_read_path,
        Key(committed_read_path));
}

PayloadSpoolReadIdentities ResolvePayloadSpoolIdentitiesForCanonicalKeys(
    MountContext* c,
    const std::wstring& visible_path,
    const std::wstring& visible_path_key,
    const std::wstring& committed_read_path,
    const std::wstring& committed_read_path_key,
    OpenContext* open_context)
{
    PayloadSpoolReadIdentities identities{};
    identities.same_path = visible_path_key == committed_read_path_key;
    if (!c || !c->metadata_store)
    {
        return identities;
    }

    const auto cache_epoch = c->payload_identity_cache_epoch.load(std::memory_order_acquire);
    if (open_context)
    {
        std::shared_lock cache_lock(open_context->payload_identity_cache_mutex);
        if (open_context->payload_identity_cache_epoch == cache_epoch &&
            open_context->payload_identity_visible_path_key == visible_path_key &&
            open_context->payload_identity_committed_path_key == committed_read_path_key)
        {
            identities.visible = open_context->payload_identity_visible;
            identities.committed = open_context->payload_identity_committed;
            return identities;
        }
    }

    auto metadata_lock = AcquireObservedMutex(c->metadata_mutex, &c->perf_metadata_mutex_wait);
    const auto lookup = [&](const std::wstring& path, const std::wstring& path_key)
    {
#ifdef APFSACCESS_FSHOST_UNIT_TEST
        ++g_payload_identity_lookup_count_for_test;
#endif
        (void)path;
        return c->metadata_store->LookupWorkingPayloadIdentityByCanonicalPathKey(path_key);
    };
    identities.visible = lookup(visible_path, visible_path_key);
    identities.committed = identities.same_path
        ? identities.visible
        : lookup(committed_read_path, committed_read_path_key);

    if (open_context &&
        c->payload_identity_cache_epoch.load(std::memory_order_acquire) == cache_epoch)
    {
        std::unique_lock cache_lock(open_context->payload_identity_cache_mutex);
        open_context->payload_identity_cache_epoch = cache_epoch;
        open_context->payload_identity_visible_path_key = visible_path_key;
        open_context->payload_identity_committed_path_key = committed_read_path_key;
        open_context->payload_identity_visible = identities.visible;
        open_context->payload_identity_committed = identities.committed;
    }
    return identities;
}

std::optional<apfsaccess::rw::MetadataStore::PayloadIdentity> ResolvePayloadSpoolIdentity(
    MountContext* c,
    const std::wstring& path)
{
    const auto path_key = Key(path);
    return ResolvePayloadSpoolIdentitiesForCanonicalKeys(
        c,
        path,
        path_key,
        path,
        path_key).visible;
}

bool AppendPayloadSpoolForIdentityBestEffort(
    MountContext* c,
    const std::wstring& path,
    const apfsaccess::rw::MetadataStore::PayloadIdentity& identity,
    std::uint64_t offset,
    const void* payload,
    std::uint32_t payload_bytes,
    std::uint64_t wal_sequence,
    apfsaccess::rw::PayloadSpool::AppendResult* append_result = nullptr)
{
    if (!c ||
        !c->payload_spool ||
        c->payload_spool_volume_identity.empty() ||
        !payload ||
        payload_bytes == 0)
    {
        return true;
    }

    ScopedPerfTimer payload_spool_scope(&c->perf_payload_spool_append);
    const auto status = c->payload_spool->AppendWithStatus({
        c->payload_spool_volume_identity,
        identity.object_id,
        identity.generation,
        offset,
        wal_sequence,
        std::span<const std::byte>(
            static_cast<const std::byte*>(payload),
            static_cast<std::size_t>(payload_bytes)),
        }, append_result);
    const auto staged = status == apfsaccess::rw::PayloadSpool::AppendStatus::Succeeded;
    if (!staged && IsHostCommitTraceEnabled())
    {
        std::wcerr << L"[FsHost] RW payload-spool warning: failed to stage dirty range for '"
            << path
            << L"' at offset "
            << offset
            << L" (bytes="
            << payload_bytes
            << L")."
            << std::endl;
    }
    return staged;
}

enum class PayloadSpoolCapacityOutcome
{
    Ready,
    CapacityExceeded,
    UnsafeFailure,
};

PayloadSpoolCapacityOutcome EnsurePayloadSpoolCapacityBeforeNativeWriteBestEffort(
    MountContext* c,
    std::uint32_t payload_bytes)
{
    if (!c || !c->payload_spool || payload_bytes == 0)
    {
        return PayloadSpoolCapacityOutcome::Ready;
    }

    const auto initial_status = c->payload_spool->CheckAppendCapacityFast(payload_bytes);
    if (initial_status == apfsaccess::rw::PayloadSpool::AppendStatus::Succeeded)
    {
        return PayloadSpoolCapacityOutcome::Ready;
    }
    if (initial_status != apfsaccess::rw::PayloadSpool::AppendStatus::QuotaExceeded)
    {
        return PayloadSpoolCapacityOutcome::UnsafeFailure;
    }

    const auto dirty_status = SnapshotNativeDirtyStatus(*c);
    const bool has_drainable_work =
        dirty_status.transaction_journal_pending_count > 0 ||
        dirty_status.metadata_pending_count > 0 ||
        dirty_status.wal_accepted_sequence > dirty_status.wal_apfs_durable_sequence;
    if (!has_drainable_work)
    {
        std::wcerr << L"[FsHost] RW payload-spool capacity is exhausted and no prior work can be drained."
            << std::endl;
        return PayloadSpoolCapacityOutcome::CapacityExceeded;
    }

    const auto drain_status = DrainNativeMutationsByPolicy(c, L"PayloadSpoolQuota");
    if (!NT_SUCCESS(drain_status))
    {
        RestoreDeferredDeleteRollbackPlans(c);
        RestoreDeferredRenameRollbackPlans(c);
        std::wcerr << L"[FsHost] RW payload-spool warning: quota drain failed with status 0x"
            << std::hex << static_cast<unsigned long>(drain_status) << std::dec << L"."
            << std::endl;
        return PayloadSpoolCapacityOutcome::UnsafeFailure;
    }
    if (!FinalizeMutationJournalBestEffort(c, L"PayloadSpoolQuota"))
    {
        return PayloadSpoolCapacityOutcome::UnsafeFailure;
    }

    const auto retry_status = c->payload_spool->CheckAppendCapacityFast(payload_bytes);
    if (retry_status == apfsaccess::rw::PayloadSpool::AppendStatus::QuotaExceeded)
    {
        std::wcerr << L"[FsHost] RW payload-spool capacity remains exhausted after one durable drain."
            << std::endl;
        return PayloadSpoolCapacityOutcome::CapacityExceeded;
    }
    return retry_status == apfsaccess::rw::PayloadSpool::AppendStatus::Succeeded
        ? PayloadSpoolCapacityOutcome::Ready
        : PayloadSpoolCapacityOutcome::UnsafeFailure;
}

bool OverlayPayloadSpoolBestEffort(
    MountContext* c,
    const std::wstring& path,
    const apfsaccess::rw::MetadataStore::PayloadIdentity& identity,
    std::uint64_t offset,
    std::byte* destination,
    std::size_t destination_size,
    std::size_t* bytes_overlayed)
{
    if (bytes_overlayed)
    {
        *bytes_overlayed = 0;
    }
    if (!c ||
        !c->payload_spool ||
        c->payload_spool_volume_identity.empty() ||
        identity.object_id == 0 ||
        !destination ||
        destination_size == 0)
    {
        return true;
    }

    std::size_t overlaid = 0;
    const auto ok = c->payload_spool->OverlayDirtyRanges({
        c->payload_spool_volume_identity,
        identity.object_id,
        identity.generation,
        offset,
        std::span<std::byte>(destination, destination_size),
    }, overlaid);
    if (ok && bytes_overlayed)
    {
        *bytes_overlayed = overlaid;
    }
    if (!ok)
    {
        std::wcerr << L"[FsHost] RW payload-spool warning: dirty range checksum/read failed for '"
            << path
            << L"'; refusing stale metadata fallback bytes."
            << std::endl;
    }
    return ok;
}

bool OverlayPayloadSpoolBestEffort(
    MountContext* c,
    const std::wstring& path,
    std::uint64_t offset,
    std::byte* destination,
    std::size_t destination_size)
{
    if (!c ||
        !c->payload_spool ||
        c->payload_spool_volume_identity.empty() ||
        !destination ||
        destination_size == 0)
    {
        return true;
    }

    const auto identity = ResolvePayloadSpoolIdentity(c, path);
    if (!identity.has_value())
    {
        return true;
    }

    return OverlayPayloadSpoolBestEffort(c, path, *identity, offset, destination, destination_size);
}

bool HasReadablePayloadSpoolRange(
    MountContext* c,
    const std::wstring& path,
    std::uint64_t offset,
    std::size_t bytes_to_read)
{
    if (!c || !c->payload_spool || bytes_to_read == 0)
    {
        return false;
    }

    const auto identity = ResolvePayloadSpoolIdentity(c, path);
    if (!identity.has_value())
    {
        return false;
    }

    return c->payload_spool->IsRangeFullyCovered(
        c->payload_spool_volume_identity,
        identity->object_id,
        identity->generation,
        offset,
        static_cast<std::uint64_t>(bytes_to_read));
}

bool HasReadablePayloadSpoolRangeWithIdentity(
    MountContext* c,
    const std::optional<apfsaccess::rw::MetadataStore::PayloadIdentity>& identity,
    std::uint64_t offset,
    std::size_t bytes_to_read)
{
    if (!c || !c->payload_spool || !identity.has_value() || bytes_to_read == 0)
    {
        return false;
    }

    return c->payload_spool->IsRangeFullyCovered(
        c->payload_spool_volume_identity,
        identity->object_id,
        identity->generation,
        offset,
        static_cast<std::uint64_t>(bytes_to_read));
}

std::uint64_t PayloadSpoolLogicalEndBestEffort(MountContext* c, const std::wstring& path)
{
    if (!c || !c->payload_spool)
    {
        return 0;
    }

    const auto identity = ResolvePayloadSpoolIdentity(c, path);
    if (!identity.has_value())
    {
        return 0;
    }

    return c->payload_spool->MaxDirtyRangeEnd(
        c->payload_spool_volume_identity,
        identity->object_id,
        identity->generation);
}

std::uint64_t PayloadSpoolLogicalEndWithIdentity(
    MountContext* c,
    const std::optional<apfsaccess::rw::MetadataStore::PayloadIdentity>& identity)
{
    if (!c || !c->payload_spool || !identity.has_value())
    {
        return 0;
    }

    return c->payload_spool->MaxDirtyRangeEnd(
        c->payload_spool_volume_identity,
        identity->object_id,
        identity->generation);
}

bool ReadPayloadSpoolRangeIfFullyCovered(
    MountContext* c,
    const std::wstring& path,
    std::uint64_t file_size,
    std::uint64_t offset,
    ULONG requested_bytes,
    std::byte* destination,
    std::size_t& bytes_read)
{
    bytes_read = 0;
    const auto spool_logical_end = PayloadSpoolLogicalEndBestEffort(c, path);
    const auto logical_size = std::max(file_size, spool_logical_end);
    if (!c || !destination || requested_bytes == 0 || offset >= logical_size)
    {
        return c != nullptr && destination != nullptr;
    }

    const auto available_u64 = logical_size - offset;
    const auto bytes_to_read = static_cast<std::size_t>(std::min<std::uint64_t>(
        static_cast<std::uint64_t>(requested_bytes),
        available_u64));
    std::fill_n(destination, bytes_to_read, std::byte{0});

    const auto identity = ResolvePayloadSpoolIdentity(c, path);
    if (!identity.has_value())
    {
        return false;
    }

    std::size_t bytes_overlayed = 0;
    if (!OverlayPayloadSpoolBestEffort(
            c,
            path,
            *identity,
            offset,
            destination,
            bytes_to_read,
            &bytes_overlayed))
    {
        return false;
    }
    if (bytes_overlayed != bytes_to_read)
    {
        return false;
    }

    bytes_read = bytes_to_read;
    return true;
}

bool ReadPayloadSpoolRangeIfFullyCoveredWithIdentity(
    MountContext* c,
    const std::wstring&,
    const std::optional<apfsaccess::rw::MetadataStore::PayloadIdentity>& identity,
    std::uint64_t file_size,
    std::uint64_t offset,
    ULONG requested_bytes,
    std::byte* destination,
    std::size_t& bytes_read)
{
    bytes_read = 0;
    const auto request_fits_file = requested_bytes == 0 ||
        (offset <= (std::numeric_limits<std::uint64_t>::max)() - static_cast<std::uint64_t>(requested_bytes) &&
         offset + static_cast<std::uint64_t>(requested_bytes) <= file_size);
    const auto spool_logical_end = request_fits_file
        ? 0
        : PayloadSpoolLogicalEndWithIdentity(c, identity);
    const auto logical_size = std::max(file_size, spool_logical_end);
    if (!c ||
        !c->payload_spool ||
        !destination ||
        requested_bytes == 0 ||
        offset >= logical_size)
    {
        return c != nullptr && c->payload_spool != nullptr && destination != nullptr;
    }

    const auto available_u64 = logical_size - offset;
    const auto bytes_to_read = static_cast<std::size_t>(std::min<std::uint64_t>(
        static_cast<std::uint64_t>(requested_bytes),
        available_u64));
    if (!identity.has_value())
    {
        return false;
    }

    std::size_t bytes_overlayed = 0;
    if (!c->payload_spool->ReadFullyCoveredRange({
            c->payload_spool_volume_identity,
            identity->object_id,
            identity->generation,
            offset,
            std::span<std::byte>(destination, bytes_to_read),
        }, bytes_overlayed))
    {
        return false;
    }
    if (bytes_overlayed != bytes_to_read)
    {
        return false;
    }

    bytes_read = bytes_to_read;
    return true;
}

bool IsSameNormalizedPath(const std::wstring& left, const std::wstring& right)
{
    return Key(left) == Key(right);
}

std::uint64_t PayloadSpoolLogicalEndForReadPathsWithIdentities(
    MountContext* c,
    const PayloadSpoolReadIdentities& identities)
{
    auto logical_end = PayloadSpoolLogicalEndWithIdentity(c, identities.visible);
    if (!identities.same_path && !SamePayloadSpoolIdentity(identities.visible, identities.committed))
    {
        logical_end = std::max(
            logical_end,
            PayloadSpoolLogicalEndWithIdentity(c, identities.committed));
    }
    return logical_end;
}

bool HasReadablePayloadSpoolRangeForReadPathsWithIdentities(
    MountContext* c,
    const PayloadSpoolReadIdentities& identities,
    std::uint64_t offset,
    std::size_t bytes_to_read)
{
    const auto visible_readable = HasReadablePayloadSpoolRangeWithIdentity(
               c,
               identities.visible,
               offset,
               bytes_to_read);
    return visible_readable ||
        (!identities.same_path &&
         !SamePayloadSpoolIdentity(identities.visible, identities.committed) &&
            HasReadablePayloadSpoolRangeWithIdentity(
                c,
                identities.committed,
                offset,
                bytes_to_read));
}

bool OverlayPayloadSpoolForReadPathsWithIdentities(
    MountContext* c,
    const std::wstring& visible_path,
    const PayloadSpoolReadIdentities& identities,
    std::uint64_t offset,
    std::byte* destination,
    std::size_t destination_size)
{
    if (identities.visible.has_value() &&
        !OverlayPayloadSpoolBestEffort(
            c,
            visible_path,
            *identities.visible,
            offset,
            destination,
            destination_size))
    {
        return false;
    }
    if (!identities.same_path &&
        !SamePayloadSpoolIdentity(identities.visible, identities.committed) &&
        identities.committed.has_value())
    {
        return OverlayPayloadSpoolBestEffort(
            c,
            visible_path,
            *identities.committed,
            offset,
            destination,
            destination_size);
    }
    return true;
}

bool OverlayPayloadSpoolForReadPathsWithIdentitiesAndLogicalEnd(
    MountContext* c,
    const std::wstring& visible_path,
    const PayloadSpoolReadIdentities& identities,
    std::uint64_t offset,
    std::byte* destination,
    std::size_t destination_size,
    std::uint64_t& logical_end)
{
    logical_end = 0;
    if (!c || !c->payload_spool)
    {
        return true;
    }

    const auto overlay_identity = [&, destination, destination_size](
        const std::optional<apfsaccess::rw::MetadataStore::PayloadIdentity>& identity) -> bool
    {
        if (!identity.has_value())
        {
            return true;
        }

        std::size_t bytes_overlayed = 0;
        std::uint64_t identity_logical_end = 0;
        if (!c->payload_spool->OverlayDirtyRangesWithLogicalEnd(
                {
                    c->payload_spool_volume_identity,
                    identity->object_id,
                    identity->generation,
                    offset,
                    std::span<std::byte>(destination, destination_size),
                },
                bytes_overlayed,
                identity_logical_end))
        {
            std::wcerr << L"[FsHost] RW payload-spool warning: dirty range checksum/read failed for '"
                << visible_path
                << L"'; refusing stale metadata fallback bytes."
                << std::endl;
            return false;
        }
        logical_end = (std::max)(logical_end, identity_logical_end);
        return true;
    };

    return overlay_identity(identities.visible) &&
        (identities.same_path ||
         SamePayloadSpoolIdentity(identities.visible, identities.committed) ||
         overlay_identity(identities.committed));
}

bool ReadPayloadSpoolRangeIfFullyCoveredForReadPathsWithIdentities(
    MountContext* c,
    const std::wstring& visible_path,
    const PayloadSpoolReadIdentities& identities,
    std::uint64_t file_size,
    std::uint64_t offset,
    ULONG requested_bytes,
    std::byte* destination,
    std::size_t& bytes_read)
{
    if (ReadPayloadSpoolRangeIfFullyCoveredWithIdentity(
            c,
            visible_path,
            identities.visible,
            file_size,
            offset,
            requested_bytes,
            destination,
            bytes_read))
    {
        return true;
    }
    if (identities.same_path ||
        SamePayloadSpoolIdentity(identities.visible, identities.committed))
    {
        return false;
    }
    return ReadPayloadSpoolRangeIfFullyCoveredWithIdentity(
        c,
        visible_path,
        identities.committed,
        file_size,
        offset,
        requested_bytes,
        destination,
        bytes_read);
}

bool HasReadablePayloadSpoolRangeForReadPaths(
    MountContext* c,
    const std::wstring& visible_path,
    const std::wstring& committed_read_path,
    std::uint64_t offset,
    std::size_t bytes_to_read)
{
    return HasReadablePayloadSpoolRange(c, visible_path, offset, bytes_to_read) ||
        (!IsSameNormalizedPath(visible_path, committed_read_path) &&
            HasReadablePayloadSpoolRange(c, committed_read_path, offset, bytes_to_read));
}

std::uint64_t PayloadSpoolLogicalEndForReadPaths(
    MountContext* c,
    const std::wstring& visible_path,
    const std::wstring& committed_read_path)
{
    auto logical_end = PayloadSpoolLogicalEndBestEffort(c, visible_path);
    if (!IsSameNormalizedPath(visible_path, committed_read_path))
    {
        logical_end = std::max(logical_end, PayloadSpoolLogicalEndBestEffort(c, committed_read_path));
    }
    return logical_end;
}

bool OverlayPayloadSpoolForReadPathsBestEffort(
    MountContext* c,
    const std::wstring& visible_path,
    const std::wstring& committed_read_path,
    std::uint64_t offset,
    std::byte* destination,
    std::size_t destination_size)
{
    if (!OverlayPayloadSpoolBestEffort(c, visible_path, offset, destination, destination_size))
    {
        return false;
    }
    if (!IsSameNormalizedPath(visible_path, committed_read_path))
    {
        return OverlayPayloadSpoolBestEffort(c, committed_read_path, offset, destination, destination_size);
    }
    return true;
}

bool ReadPayloadSpoolRangeIfFullyCoveredForReadPaths(
    MountContext* c,
    const std::wstring& visible_path,
    const std::wstring& committed_read_path,
    std::uint64_t file_size,
    std::uint64_t offset,
    ULONG requested_bytes,
    std::byte* destination,
    std::size_t& bytes_read)
{
    if (ReadPayloadSpoolRangeIfFullyCovered(
            c,
            visible_path,
            file_size,
            offset,
            requested_bytes,
            destination,
            bytes_read))
    {
        return true;
    }
    if (IsSameNormalizedPath(visible_path, committed_read_path))
    {
        return false;
    }
    return ReadPayloadSpoolRangeIfFullyCovered(
        c,
        committed_read_path,
        file_size,
        offset,
        requested_bytes,
        destination,
        bytes_read);
}

bool TryHydrateFromCurrentPayloadOverlay(
    MountContext* c,
    const std::shared_ptr<Node>& node,
    std::optional<std::uint64_t> required_payload_epoch = std::nullopt,
    bool require_closed_node = false)
{
    if (!c || !node || node->is_directory || !c->metadata_store)
    {
        return false;
    }

    std::uint64_t logical_size = 0;
    std::wstring visible_path;
    std::wstring visible_path_key;
    std::wstring committed_read_path;
    {
        std::lock_guard<std::mutex> lock(c->mutex);
        if (TryGetNodeLockedNormalized(c, node->path) != node ||
            (required_payload_epoch.has_value() &&
             c->payload_identity_cache_epoch.load(std::memory_order_acquire) !=
                 required_payload_epoch.value()) ||
            (require_closed_node &&
             (node->open_handle_count != 0 || node->write_handle_count != 0 ||
              node->delete_intent_count != 0 || node->delete_latched ||
              node->delete_pending || node->delete_requested_after_children ||
              node->caller_delete_retry_required)))
        {
            return false;
        }
        logical_size = node->file_size;
        visible_path = node->path;
        visible_path_key = NodePathKey(*node);
        committed_read_path = CommittedReadPathForNodeLocked(*node);
    }
    const auto committed_read_path_key = LowerPathKey(committed_read_path);

    if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<LONGLONG>::max()))
    {
        return false;
    }

    const auto hydrated_file = HydrationPath(c, *node);
    InvalidateHydrationReadHandle(c);
    std::error_code ec;
    std::filesystem::create_directories(hydrated_file.parent_path(), ec);
    if (ec)
    {
        return false;
    }

    HANDLE hydrated = CreateFileW(
        hydrated_file.wstring().c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        CREATE_ALWAYS,
        kHydrationCacheFileAttributes,
        nullptr);
    if (hydrated == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    bool hydrated_ok = false;
    ScopeExit cleanup_hydration{[&]()
    {
        CloseHandle(hydrated);
        if (!hydrated_ok)
        {
            std::error_code remove_ec;
            std::filesystem::remove(hydrated_file, remove_ec);
        }
    }};

    DWORD ignored_bytes_returned = 0;
    (void)DeviceIoControl(
        hydrated,
        FSCTL_SET_SPARSE,
        nullptr,
        0,
        nullptr,
        0,
        &ignored_bytes_returned,
        nullptr);

    constexpr std::size_t kHydrationChunkBytes = 1024 * 1024;
    std::vector<std::byte> chunk(kHydrationChunkBytes);
    std::uint64_t offset = 0;
    while (offset < logical_size)
    {
        const auto chunk_bytes = static_cast<std::size_t>(std::min<std::uint64_t>(
            logical_size - offset,
            static_cast<std::uint64_t>(kHydrationChunkBytes)));
        std::fill_n(chunk.data(), chunk_bytes, std::byte{0});

        // Resolve the visible/committed identities once for this chunk. The
        // old path performed the same metadata lookup separately for logical
        // end, full-range coverage, and overlay, while retaining the same
        // per-chunk mutation observation boundary.
        const auto payload_spool_identities = c->payload_spool
            ? ResolvePayloadSpoolIdentitiesForCanonicalKeys(
                c,
                visible_path,
                visible_path_key,
                committed_read_path,
                committed_read_path_key)
            : PayloadSpoolReadIdentities{};

        std::size_t spool_bytes_read = 0;
        const bool fully_spooled = ReadPayloadSpoolRangeIfFullyCoveredForReadPathsWithIdentities(
            c,
            visible_path,
            payload_spool_identities,
            logical_size,
            offset,
            static_cast<ULONG>(chunk_bytes),
            chunk.data(),
            spool_bytes_read) &&
            spool_bytes_read == chunk_bytes;

        if (!fully_spooled)
        {
            std::size_t committed_bytes_read = 0;
            const bool committed_read_ok = ReadCommittedFileRangeWithoutMetadataLock(
                c,
                committed_read_path_key,
                committed_read_path,
                offset,
                chunk_bytes,
                chunk.data(),
                chunk_bytes,
                committed_bytes_read);
            if (!committed_read_ok)
            {
                return false;
            }
            if (committed_bytes_read < chunk_bytes)
            {
                std::fill(
                    chunk.begin() + static_cast<std::ptrdiff_t>(committed_bytes_read),
                    chunk.begin() + static_cast<std::ptrdiff_t>(chunk_bytes),
                    std::byte{0});
            }
            if (!OverlayPayloadSpoolForReadPathsWithIdentities(
                    c,
                    visible_path,
                    payload_spool_identities,
                    offset,
                    chunk.data(),
                    chunk_bytes))
            {
                return false;
            }
        }

        const auto has_non_zero = std::any_of(
            chunk.begin(),
            chunk.begin() + static_cast<std::ptrdiff_t>(chunk_bytes),
            [](std::byte value)
            {
                return value != std::byte{0};
            });
        if (has_non_zero)
        {
            OVERLAPPED ov{};
            ov.Offset = static_cast<DWORD>(offset & 0xffffffffull);
            ov.OffsetHigh = static_cast<DWORD>(offset >> 32);
            DWORD written = 0;
            if (!WriteFile(
                    hydrated,
                    chunk.data(),
                    static_cast<DWORD>(chunk_bytes),
                    &written,
                    &ov) ||
                written != chunk_bytes)
            {
                return false;
            }
        }

        offset += chunk_bytes;
    }

    LARGE_INTEGER target_size{};
    target_size.QuadPart = static_cast<LONGLONG>(logical_size);
    if (!SetFilePointerEx(hydrated, target_size, nullptr, FILE_BEGIN) ||
        !SetEndOfFile(hydrated))
    {
        return false;
    }

#ifdef APFSACCESS_FSHOST_UNIT_TEST
    if (g_hydration_materialization_before_publish_hook != nullptr)
    {
        g_hydration_materialization_before_publish_hook(c);
    }
#endif

    {
        std::lock_guard<std::mutex> lock(c->mutex);
        if (TryGetNodeLockedNormalized(c, visible_path) != node ||
            NodePathKey(*node) != visible_path_key ||
            node->file_size != logical_size ||
            (required_payload_epoch.has_value() &&
             c->payload_identity_cache_epoch.load(std::memory_order_acquire) !=
                 required_payload_epoch.value()) ||
            (require_closed_node &&
             (node->open_handle_count != 0 || node->write_handle_count != 0 ||
              node->delete_intent_count != 0 || node->delete_latched ||
              node->delete_pending || node->delete_requested_after_children ||
              node->caller_delete_retry_required)))
        {
            return false;
        }
        ClearHydrationStaleLockedNormalized(c, visible_path);
    }
    hydrated_ok = true;
    return true;
}

void PromoteFullySpooledHydrationAfterCheckpointBestEffort(
    MountContext* c,
    std::uint64_t committed_sequence)
{
    if (!c || !c->payload_spool || !c->metadata_store ||
        committed_sequence == 0 ||
        !IsExperimentalPostCheckpointHydrationPromotionEnabled())
    {
        return;
    }

    const auto payload_epoch =
        c->payload_identity_cache_epoch.load(std::memory_order_acquire);
    if (c->tx_manager)
    {
        std::lock_guard<std::mutex> tx_lock(c->tx_mutex);
        const auto watermarks = c->tx_manager->Watermarks();
        if (c->tx_manager->CurrentState() !=
                apfsaccess::rw::TransactionManager::State::Idle ||
            c->tx_manager->HasUnappliedAcceptedWork() ||
            watermarks.accepted_sequence > committed_sequence ||
            c->payload_identity_cache_epoch.load(std::memory_order_acquire) !=
                payload_epoch)
        {
            return;
        }
    }

    const auto minimum_bytes = ResolvePostCheckpointHydrationPromotionMinimumBytes();
    const auto already_promoted = c->post_checkpoint_hydration_promoted_bytes.load(std::memory_order_relaxed);
    if (already_promoted >= kPostCheckpointHydrationPromotionSessionBudgetBytes)
    {
        return;
    }

    std::vector<std::shared_ptr<Node>> candidates;
    {
        std::lock_guard<std::mutex> lock(c->mutex);
        candidates.reserve(c->stale_hydration_keys.size());
        for (const auto& path_key : c->stale_hydration_keys)
        {
            const auto node_it = c->nodes.find(path_key);
            const auto node = node_it == c->nodes.end()
                ? std::shared_ptr<Node>{}
                : node_it->second;
            if (!node || node->is_directory || NodePathKey(*node) != path_key ||
                node->file_size < minimum_bytes || node->file_size == 0)
            {
                continue;
            }
            if (node->open_handle_count != 0 || node->write_handle_count != 0)
            {
                c->post_checkpoint_hydration_open_skip_count.fetch_add(1, std::memory_order_relaxed);
                continue;
            }
            if (node->delete_intent_count != 0 || node->delete_latched || node->delete_pending ||
                node->delete_requested_after_children || node->caller_delete_retry_required)
            {
                continue;
            }
            candidates.push_back(node);
        }
    }

    std::sort(
        candidates.begin(),
        candidates.end(),
        [](const std::shared_ptr<Node>& left, const std::shared_ptr<Node>& right)
        {
            return left && right && left->file_size > right->file_size;
        });

    for (const auto& node : candidates)
    {
        if (c->payload_identity_cache_epoch.load(std::memory_order_acquire) != payload_epoch)
        {
            break;
        }

        std::uint64_t logical_size = 0;
        std::wstring visible_path;
        std::wstring visible_path_key;
        std::wstring committed_read_path;
        {
            std::lock_guard<std::mutex> lock(c->mutex);
            if (!node || TryGetNodeLockedNormalized(c, node->path) != node ||
                !IsHydrationStaleLocked(c, node) || node->open_handle_count != 0 ||
                node->write_handle_count != 0 || node->delete_intent_count != 0 ||
                node->delete_latched || node->delete_pending || node->delete_requested_after_children)
            {
                continue;
            }
            logical_size = node->file_size;
            visible_path = node->path;
            visible_path_key = NodePathKey(*node);
            committed_read_path = CommittedReadPathForNodeLocked(*node);
        }

        if (logical_size > static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)()))
        {
            continue;
        }
        const auto promoted_bytes = c->post_checkpoint_hydration_promoted_bytes.load(std::memory_order_relaxed);
        if (logical_size > kPostCheckpointHydrationPromotionSessionBudgetBytes -
                (std::min)(promoted_bytes, kPostCheckpointHydrationPromotionSessionBudgetBytes))
        {
            c->post_checkpoint_hydration_budget_skip_count.fetch_add(1, std::memory_order_relaxed);
            continue;
        }

        const auto committed_read_path_key = LowerPathKey(committed_read_path);
        const auto identities = ResolvePayloadSpoolIdentitiesForCanonicalKeys(
            c,
            visible_path,
            visible_path_key,
            committed_read_path,
            committed_read_path_key);
        if (!HasReadablePayloadSpoolRangeForReadPathsWithIdentities(
                c,
                identities,
                0,
                static_cast<std::size_t>(logical_size)))
        {
            c->post_checkpoint_hydration_partial_skip_count.fetch_add(1, std::memory_order_relaxed);
            continue;
        }

        c->post_checkpoint_hydration_candidate_count.fetch_add(1, std::memory_order_relaxed);
        ScopedPerfTimer promotion_scope(&c->perf_post_checkpoint_hydration);
        if (TryHydrateFromCurrentPayloadOverlay(c, node, payload_epoch, true))
        {
            c->post_checkpoint_hydration_promoted_count.fetch_add(1, std::memory_order_relaxed);
            c->post_checkpoint_hydration_promoted_bytes.fetch_add(logical_size, std::memory_order_relaxed);
        }
        else
        {
            c->post_checkpoint_hydration_failure_count.fetch_add(1, std::memory_order_relaxed);
            if (IsHostCommitTraceEnabled())
            {
                std::wcerr << L"[FsHost] RW hydration-cache warning: post-checkpoint promotion failed for '"
                    << visible_path
                    << L"'; the APFS checkpoint remains authoritative."
                    << std::endl;
            }
        }
    }
}

bool CleanupPayloadSpoolAfterCheckpointBestEffort(MountContext* c, std::uint64_t committed_sequence)
{
    if (!c || !c->payload_spool || committed_sequence == 0)
    {
        return true;
    }

    // Promotion is strictly non-authoritative. It runs only after the APFS
    // checkpoint is durable and before the spool source is discarded; failure
    // leaves hydration stale and cannot turn a successful commit into failure.
    PromoteFullySpooledHydrationAfterCheckpointBestEffort(c, committed_sequence);

    if (!c->payload_spool->CleanupThroughSequence(committed_sequence))
    {
        if (IsHostCommitTraceEnabled())
        {
            std::wcerr << L"[FsHost] RW payload-spool warning: cleanup after native checkpoint failed."
                << std::endl;
        }
        return false;
    }
    return true;
}

bool FlushPayloadSpoolDirtyStateBestEffort(MountContext* c, const wchar_t* origin)
{
    if (!c || !c->payload_spool)
    {
        return true;
    }

    if (c->payload_spool->FlushDirtyState())
    {
        return true;
    }

    std::wcerr << L"[FsHost] RW payload-spool warning: failed to flush dirty spool state during "
        << (origin ? origin : L"commit")
        << L"."
        << std::endl;
    return false;
}

void SetRuntimeRecoveryReason(MountContext& ctx, std::wstring reason)
{
    std::lock_guard<std::recursive_mutex> runtime_lock(ctx.runtime_state_mutex);
    ctx.runtime_recovery_reason = std::move(reason);
}

void LatchPayloadSpoolRecoveryRequired(MountContext& ctx)
{
    {
        std::lock_guard<std::recursive_mutex> runtime_lock(ctx.runtime_state_mutex);
        ctx.recovery_active = true;
        ctx.runtime_recovery_reason = L"PayloadSpoolRecoveryRequired";
        ctx.runtime_last_recovery_action = L"DowngradedAfterPayloadSpoolRecoveryRequired";
        if (ctx.native_write_enabled &&
            IsRecoveryPolicyFailClosed(ctx.args.write_recovery_policy))
        {
            ctx.write_degraded = true;
            ctx.native_write_enabled = false;
            ctx.overlay_write_enabled = false;
        }
    }
}

bool HasPayloadSpoolRecoveryEvidence(MountContext& ctx)
{
    if (!ctx.payload_spool)
    {
        return false;
    }

    const auto counters = ctx.payload_spool->SnapshotCounters();
    return counters.recovery_required ||
           counters.dirty_range_count > 0 ||
           counters.spool_bytes > 0 ||
           counters.index_dirty;
}

std::optional<std::uint64_t> ResolveCleanRecoveryCheckpointXid(
    const apfsaccess::rw::MetadataStore& metadata_store);
void ClearRecoveredMarkerIfClean(
    MountContext& ctx,
    const std::wstring& action,
    bool defer_payload_spool_latch = false);

bool CanClearDirtyMarkerAgainstCleanCheckpoint(const MountContext& ctx, std::optional<std::uint64_t> clean_checkpoint_xid)
{
    std::lock_guard<std::recursive_mutex> runtime_lock(ctx.runtime_state_mutex);
    if (!ctx.pending_native_writes ||
        !ctx.metadata_store ||
        ctx.metadata_store->IsRecoveryRequired() ||
        !ctx.runtime_last_commit_xid.has_value() ||
        ctx.runtime_last_commit_xid.value() == 0 ||
        !clean_checkpoint_xid.has_value())
    {
        return false;
    }

    if (ctx.runtime_last_commit_xid.value() > clean_checkpoint_xid.value())
    {
        return false;
    }

    return true;
}

void ReconcilePayloadSpoolRecoveryAfterMetadataBootstrap(MountContext& ctx, bool payload_spool_recovery_pending)
{
    if (!payload_spool_recovery_pending ||
        !ctx.payload_spool ||
        !HasPayloadSpoolRecoveryEvidence(ctx))
    {
        return;
    }

    bool wal_proves_no_accepted_work = false;
    if (!HasBlockedRecoveryEvidence(ctx) &&
        ctx.native_write_enabled &&
        ctx.metadata_store &&
        !ctx.metadata_store->IsRecoveryRequired() &&
        ctx.metadata_store->IsCommitPathReady() &&
        ctx.tx_manager)
    {
        std::lock_guard<std::mutex> tx_lock(ctx.tx_mutex);
        std::vector<apfsaccess::rw::TransactionManager::AcceptedTransaction> accepted_transactions;
        std::string load_failure;
        wal_proves_no_accepted_work =
            ctx.tx_manager->RecoveryStateValid() &&
            ctx.tx_manager->CanClearRecoveryState() &&
            ctx.tx_manager->PendingMutationCount() == 0 &&
            ctx.tx_manager->LoadAcceptedTransactionsSinceCleanup(
                accepted_transactions,
                &load_failure) &&
            load_failure.empty() &&
            accepted_transactions.empty();
    }

    if (wal_proves_no_accepted_work &&
        ctx.payload_spool->ResolveUnindexedPayloadRecovery(true))
    {
        std::wcerr << L"[FsHost] Discarded unindexed payload bytes that a valid clean WAL proved were interrupted before acceptance."
            << std::endl;
        ClearRecoveredMarkerIfClean(
            ctx,
            L"RecoveryMarkerClearedAfterPreAcceptancePayloadDiscard");
        if (!ctx.pending_native_writes &&
            !ctx.recovery_active &&
            !HasPayloadSpoolRecoveryEvidence(ctx))
        {
            return;
        }
    }

    LatchPayloadSpoolRecoveryRequired(ctx);
    std::wcerr << L"[FsHost] RW payload spool recovery is required; recovered payload bytes are retained until replay can prove their checkpoint state."
        << std::endl;
}

bool BuildAcceptedReplayMutationRequest(
    const apfsaccess::rw::WriteAheadLog::Record& record,
    apfsaccess::rw::MetadataStore::MutationRequest& request)
{
    request = {};
    request.path = Utf8ToWide(record.path_utf8);
    request.secondary_path = Utf8ToWide(record.secondary_path_utf8);
    request.object_id = record.object_id;
    request.generation = record.parent_object_id;
    request.replace_if_exists = (record.flags & 0x4u) != 0;
    switch (record.operation)
    {
    case apfsaccess::rw::WriteAheadLog::OperationKind::CreateFile:
        request.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        break;
    case apfsaccess::rw::WriteAheadLog::OperationKind::CreateDirectory:
        request.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateDirectory;
        break;
    case apfsaccess::rw::WriteAheadLog::OperationKind::Write:
        request.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        request.offset = record.logical_offset;
        request.length = record.logical_length;
        break;
    case apfsaccess::rw::WriteAheadLog::OperationKind::SetFileSize:
        request.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetFileSize;
        request.length = record.logical_length;
        break;
    case apfsaccess::rw::WriteAheadLog::OperationKind::Rename:
        request.operation = apfsaccess::rw::MetadataStore::MutationOperation::Rename;
        break;
    case apfsaccess::rw::WriteAheadLog::OperationKind::Delete:
        request.operation = apfsaccess::rw::MetadataStore::MutationOperation::Delete;
        break;
    case apfsaccess::rw::WriteAheadLog::OperationKind::SetBasicInfo:
        request.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetBasicInfo;
        request.timestamp_utc = record.logical_offset;
        break;
    default:
        return false;
    }
    if (request.path.empty() ||
        (request.operation == apfsaccess::rw::MetadataStore::MutationOperation::Rename && request.secondary_path.empty()))
    {
        return false;
    }
    return true;
}

bool AcceptedReplayMutationRequiresIdentity(
    apfsaccess::rw::MetadataStore::MutationOperation operation) noexcept
{
    switch (operation)
    {
    case apfsaccess::rw::MetadataStore::MutationOperation::CreateFile:
    case apfsaccess::rw::MetadataStore::MutationOperation::CreateDirectory:
    case apfsaccess::rw::MetadataStore::MutationOperation::Write:
    case apfsaccess::rw::MetadataStore::MutationOperation::SetFileSize:
    case apfsaccess::rw::MetadataStore::MutationOperation::Rename:
    case apfsaccess::rw::MetadataStore::MutationOperation::Delete:
    case apfsaccess::rw::MetadataStore::MutationOperation::SetBasicInfo:
        return true;
    default:
        return false;
    }
}

bool ReadAcceptedReplayPayload(
    MountContext& ctx,
    const apfsaccess::rw::WriteAheadLog::Record& record,
    std::vector<std::byte>& payload)
{
    payload.clear();
    if (record.operation != apfsaccess::rw::WriteAheadLog::OperationKind::Write ||
        record.object_id == 0 ||
        record.payload_spool_id != record.sequence ||
        record.payload_length == 0 ||
        record.payload_length != record.logical_length)
    {
        return false;
    }
    if (!record.inline_payload.empty())
    {
        if (!apfsaccess::rw::WriteAheadLog::InlinePayloadIsConsistent(record))
        {
            return false;
        }
        payload = record.inline_payload;
        return true;
    }
    if (!ctx.payload_spool)
    {
        return false;
    }
    return ctx.payload_spool->ReadPersistedRange({
        ctx.payload_spool_volume_identity,
        record.object_id,
        record.parent_object_id,
        record.logical_offset,
        record.payload_length,
        record.payload_offset,
        record.payload_spool_id,
        record.payload_sha256,
    }, payload);
}

bool VerifyAcceptedReplayMutationApplied(
    MountContext& ctx,
    const apfsaccess::rw::WriteAheadLog::Record& record)
{
    if (!ctx.metadata_store)
    {
        return false;
    }
    apfsaccess::rw::MetadataStore::MutationRequest request{};
    if (!BuildAcceptedReplayMutationRequest(record, request))
    {
        return false;
    }
    if (AcceptedReplayMutationRequiresIdentity(request.operation) &&
        (record.object_id == 0 || record.parent_object_id == 0))
    {
        return false;
    }

    const auto matches_recorded_identity = [&](
        const std::optional<apfsaccess::rw::MetadataStore::InodeRecord>& inode)
    {
        if (!inode.has_value() ||
            record.object_id == 0 ||
            record.parent_object_id == 0 ||
            inode->object_id != record.object_id)
        {
            return false;
        }

        const auto committed_generation = inode->xid == 0
            ? inode->object_id
            : inode->xid;
        return committed_generation == record.parent_object_id;
    };

    if (request.operation == apfsaccess::rw::MetadataStore::MutationOperation::Write)
    {
        std::vector<std::byte> expected;
        const auto inode = ctx.metadata_store->LookupCommittedInodeByObjectId(record.object_id);
        if (!matches_recorded_identity(inode) || inode->is_directory)
        {
            return false;
        }
        if (!ReadAcceptedReplayPayload(ctx, record, expected))
        {
            // The payload can only be missing when the spool already cleaned the
            // range, which happens strictly after the write became APFS-durable;
            // a committed inode with the recorded identity and full extent then
            // proves the write is already applied.
            return inode->logical_size >= record.logical_offset + record.payload_length;
        }
        std::vector<std::byte> actual;
        return ctx.metadata_store->ReadCommittedFileRange(
                   inode->full_path,
                   record.logical_offset,
                   expected.size(),
                   actual) &&
               actual == expected;
    }

    const auto inode = ctx.metadata_store->LookupCommittedInodeByPath(request.path);
    switch (request.operation)
    {
    case apfsaccess::rw::MetadataStore::MutationOperation::CreateFile:
        return matches_recorded_identity(inode) && !inode->is_directory;
    case apfsaccess::rw::MetadataStore::MutationOperation::CreateDirectory:
        return matches_recorded_identity(inode) && inode->is_directory;
    case apfsaccess::rw::MetadataStore::MutationOperation::SetFileSize:
        return matches_recorded_identity(inode) &&
               !inode->is_directory &&
               inode->logical_size == request.length;
    case apfsaccess::rw::MetadataStore::MutationOperation::SetBasicInfo:
        return matches_recorded_identity(inode) &&
               inode->timestamp_utc == request.timestamp_utc;
    case apfsaccess::rw::MetadataStore::MutationOperation::Rename:
        return !inode.has_value() &&
               matches_recorded_identity(
                   ctx.metadata_store->LookupCommittedInodeByPath(request.secondary_path));
    case apfsaccess::rw::MetadataStore::MutationOperation::Delete:
    {
        if (inode.has_value())
        {
            return false;
        }
        const auto object_inode =
            ctx.metadata_store->LookupCommittedInodeByObjectId(record.object_id);
        return !object_inode.has_value();
    }
    default:
        return false;
    }
}

bool VerifyAcceptedReplayTransactionApplied(
    MountContext& ctx,
    const apfsaccess::rw::TransactionManager::AcceptedTransaction& transaction,
    const std::unordered_set<std::uint64_t>* later_terminal_deletes)
{
    std::unordered_set<std::uint64_t> deleted_in_batch;
    if (later_terminal_deletes != nullptr)
    {
        deleted_in_batch = *later_terminal_deletes;
    }
    for (auto it = transaction.mutations.rbegin(); it != transaction.mutations.rend(); ++it)
    {
        const auto& record = *it;
        if (record.operation == apfsaccess::rw::WriteAheadLog::OperationKind::Delete)
        {
            deleted_in_batch.insert(record.object_id);
        }
        else if (deleted_in_batch.find(record.object_id) != deleted_in_batch.end())
        {
            continue;
        }

        if (!VerifyAcceptedReplayMutationApplied(ctx, record))
        {
            return false;
        }
    }
    return true;
}

bool RebuildPayloadSpoolIndexFromAcceptedWalBestEffort(MountContext& ctx)
{
    if (!ctx.payload_spool || !ctx.payload_spool->RecoveryRequired() || !ctx.tx_manager)
    {
        return true;
    }

    std::vector<apfsaccess::rw::TransactionManager::AcceptedTransaction> accepted_transactions;
    std::string load_failure;
    if (!ctx.tx_manager->LoadAcceptedTransactionsSinceCleanup(accepted_transactions, &load_failure))
    {
        SetRuntimeRecoveryReason(ctx, L"AcceptedWritePayloadIndexRebuildWalInvalid");
        std::wcerr << L"[FsHost] Payload-spool index rebuild could not load accepted WAL references: "
            << Utf8ToWide(load_failure)
            << L"."
            << std::endl;
        return false;
    }

    std::vector<apfsaccess::rw::PayloadSpool::PersistedRangeReference> references;
    std::vector<apfsaccess::rw::PayloadSpool::PersistedRangeReference> discardable_references;
    const auto apfs_durable_sequence =
        ctx.tx_manager->Watermarks().apfs_durable_sequence;
    for (const auto& transaction : accepted_transactions)
    {
        const auto transaction_is_apfs_durable =
            transaction.accepted_sequence <= apfs_durable_sequence;
        for (const auto& record : transaction.mutations)
        {
            if (record.operation != apfsaccess::rw::WriteAheadLog::OperationKind::Write)
            {
                if (record.payload_length != 0 || record.payload_spool_id != 0)
                {
                    SetRuntimeRecoveryReason(ctx, L"AcceptedWritePayloadIndexRebuildRecordInvalid");
                    return false;
                }
                continue;
            }

            if (record.object_id == 0 ||
                record.payload_spool_id != record.sequence ||
                record.payload_length == 0 ||
                record.payload_length != record.logical_length ||
                std::all_of(
                    record.payload_sha256.begin(),
                    record.payload_sha256.end(),
                    [](std::uint8_t byte) { return byte == 0; }))
            {
                SetRuntimeRecoveryReason(ctx, L"AcceptedWritePayloadIndexRebuildRecordInvalid");
                return false;
            }

            const apfsaccess::rw::PayloadSpool::PersistedRangeReference reference{
                ctx.payload_spool_volume_identity,
                record.object_id,
                record.parent_object_id,
                record.logical_offset,
                record.payload_length,
                record.payload_offset,
                record.payload_spool_id,
                record.payload_sha256,
            };
            if (!record.inline_payload.empty())
            {
                if (!apfsaccess::rw::WriteAheadLog::InlinePayloadIsConsistent(record))
                {
                    SetRuntimeRecoveryReason(ctx, L"AcceptedWritePayloadIndexRebuildRecordInvalid");
                    return false;
                }
                discardable_references.push_back(reference);
                continue;
            }

            if (transaction_is_apfs_durable)
            {
                discardable_references.push_back(reference);
            }
            else
            {
                references.push_back(reference);
            }
        }
    }

    if (!ctx.payload_spool->RebuildIndexFromReferences(
            std::span<const apfsaccess::rw::PayloadSpool::PersistedRangeReference>(
                references.data(),
                references.size()),
            apfs_durable_sequence,
            std::span<const apfsaccess::rw::PayloadSpool::PersistedRangeReference>(
                discardable_references.data(),
                discardable_references.size())))
    {
        SetRuntimeRecoveryReason(ctx, L"AcceptedWritePayloadIndexRebuildFailed");
        std::wcerr << L"[FsHost] Payload-spool index rebuild from accepted WAL references failed; retaining recovery-required state."
            << std::endl;
        return false;
    }
    return true;
}

bool ReplayAcceptedWriteAheadLogAfterMetadataBootstrap(MountContext& ctx)
{
    if (HasBlockedRecoveryEvidence(ctx))
    {
        return false;
    }

    if (!ctx.tx_manager || !ctx.metadata_store || !ctx.tx_manager->RecoveryStateValid())
    {
        SetRuntimeRecoveryReason(ctx, L"AcceptedWriteReplayValidationFailed");
        return false;
    }

    if (!RebuildPayloadSpoolIndexFromAcceptedWalBestEffort(ctx))
    {
        return false;
    }

    std::vector<apfsaccess::rw::TransactionManager::AcceptedTransaction> transactions;
    std::string load_failure;
    if (!ctx.tx_manager->LoadUnappliedAcceptedTransactions(transactions, &load_failure))
    {
        SetRuntimeRecoveryReason(ctx, L"AcceptedWriteReplayValidationFailed");
        std::wcerr << L"[FsHost] Accepted-write replay validation failed: "
            << Utf8ToWide(load_failure)
            << L"."
            << std::endl;
        return false;
    }

    struct ReplayMutationPlan
    {
        const apfsaccess::rw::WriteAheadLog::Record* record = nullptr;
        apfsaccess::rw::MetadataStore::MutationRequest request{};
    };
    struct ReplayTransactionPlan
    {
        const apfsaccess::rw::TransactionManager::AcceptedTransaction* transaction = nullptr;
        std::vector<ReplayMutationPlan> mutations;
        bool already_applied = false;
        std::unordered_set<std::uint64_t> later_terminal_deletes;
    };

    // Validate every accepted transaction before changing the working
    // metadata state. This prevents a later bad WAL record from leaving an
    // earlier transaction partially staged for replay.
    std::vector<ReplayTransactionPlan> replay_plans;
    replay_plans.reserve(transactions.size());
    std::vector<std::byte> replay_payload;
    for (std::size_t index = 0; index < transactions.size(); ++index)
    {
        const auto& transaction = transactions[index];
        ReplayTransactionPlan plan{};
        plan.transaction = &transaction;
        plan.mutations.reserve(transaction.mutations.size());
        for (const auto& record : transaction.mutations)
        {
            ReplayMutationPlan mutation{};
            mutation.record = &record;
            if (!BuildAcceptedReplayMutationRequest(record, mutation.request))
            {
                SetRuntimeRecoveryReason(ctx, L"AcceptedWriteReplayUnsupportedMutation");
                return false;
            }

            if (AcceptedReplayMutationRequiresIdentity(mutation.request.operation) &&
                (mutation.request.object_id == 0 || mutation.request.generation == 0))
            {
                const auto namespace_replay =
                    mutation.request.operation == apfsaccess::rw::MetadataStore::MutationOperation::Rename ||
                    mutation.request.operation == apfsaccess::rw::MetadataStore::MutationOperation::Delete;
                SetRuntimeRecoveryReason(
                    ctx,
                    namespace_replay
                        ? L"AcceptedNamespaceReplayIdentityMissing"
                        : L"AcceptedReplayIdentityMissing");
                return false;
            }

            if (mutation.request.operation == apfsaccess::rw::MetadataStore::MutationOperation::Write &&
                !ReadAcceptedReplayPayload(ctx, record, replay_payload))
            {
                SetRuntimeRecoveryReason(ctx, L"AcceptedWriteReplayPayloadMismatch");
                return false;
            }
            plan.mutations.push_back(std::move(mutation));
        }

        {
            std::lock_guard<std::mutex> metadata_lock(ctx.metadata_mutex);
            // Collect terminal deletes from later accepted transactions so an
            // earlier mutation of an object deleted later in the batch is
            // treated as applied (the later delete dominates it). The
            // per-transaction view cannot see a delete in a later transaction;
            // deletes inside the current transaction are discovered while
            // iterating its records in reverse.
            std::unordered_set<std::uint64_t> later_terminal_deletes_by_index;
            for (std::size_t later_index = index + 1; later_index < transactions.size(); ++later_index)
            {
                const auto& later_transaction = transactions[later_index];
                for (auto it = later_transaction.mutations.rbegin();
                     it != later_transaction.mutations.rend();
                     ++it)
                {
                    if (it->operation == apfsaccess::rw::WriteAheadLog::OperationKind::Delete)
                    {
                        later_terminal_deletes_by_index.insert(it->object_id);
                    }
                }
            }
            plan.later_terminal_deletes = std::move(later_terminal_deletes_by_index);
            const auto already_applied = VerifyAcceptedReplayTransactionApplied(
                ctx, transaction, &plan.later_terminal_deletes);
            plan.already_applied = already_applied;
            if (already_applied)
            {
                continue;
            }
        }
        replay_plans.push_back(std::move(plan));
    }

    const auto has_unapplied_transactions = std::any_of(
        replay_plans.begin(),
        replay_plans.end(),
        [](const ReplayTransactionPlan& plan) { return !plan.already_applied; });
    if (has_unapplied_transactions)
    {
        std::wstring replay_failure;
        replay_payload.clear();
        for (const auto& plan : replay_plans)
        {
            if (plan.already_applied)
            {
                continue;
            }

            for (const auto& mutation : plan.mutations)
            {
                if (mutation.request.operation == apfsaccess::rw::MetadataStore::MutationOperation::Write &&
                    !ReadAcceptedReplayPayload(ctx, *mutation.record, replay_payload))
                {
                    replay_failure = L"AcceptedWriteReplayPayloadMismatch";
                    break;
                }

                {
                    std::lock_guard<std::mutex> metadata_lock(ctx.metadata_mutex);
                    apfsaccess::rw::MetadataStore::PayloadIdentity replay_identity{};
                    const auto replay_status = ctx.metadata_store->StageMutation(
                        mutation.request,
                        &replay_identity);
                    if (replay_status != apfsaccess::rw::MetadataStore::MutationStatus::Applied)
                    {
                        std::wcerr << L"[FsHost] Accepted-write replay staging failed (sequence="
                            << mutation.record->sequence
                            << L", operation="
                            << static_cast<std::uint32_t>(mutation.record->operation)
                            << L", path='"
                            << mutation.request.path
                            << L"', reason="
                            << ctx.metadata_store->LastMutationFailureReason()
                            << L")."
                            << std::endl;
                        replay_failure =
                            mutation.request.object_id != 0 && mutation.request.generation != 0
                                ? L"AcceptedWriteReplayIdentityMismatch"
                                : L"AcceptedWriteReplayMutationFailed";
                        break;
                    }
                    InvalidatePayloadIdentityCache(&ctx);
                    if (mutation.request.operation == apfsaccess::rw::MetadataStore::MutationOperation::Write &&
                        (replay_identity.object_id != mutation.record->object_id ||
                         replay_identity.generation != mutation.record->parent_object_id ||
                         !ctx.metadata_store->WritePreparedFileRange(
                             mutation.request.path,
                             mutation.request.offset,
                             std::span<const std::byte>(
                                 replay_payload.data(),
                                 replay_payload.size()))))
                    {
                        replay_failure = L"AcceptedWriteReplayIdentityMismatch";
                    }
                }
                if (!replay_failure.empty())
                {
                    break;
                }
            }
            if (!replay_failure.empty())
            {
                break;
            }
        }
        if (!replay_failure.empty())
        {
            SetRuntimeRecoveryReason(ctx, std::move(replay_failure));
            return false;
        }

        apfsaccess::rw::MetadataStore::CommitStatus commit_status{};
        std::optional<std::uint64_t> replay_commit_xid;
        {
            std::lock_guard<std::mutex> metadata_lock(ctx.metadata_mutex);
            commit_status = RequiresCanonicalMutationGate(ctx.args)
                ? ctx.metadata_store->CommitCanonicalTransaction()
                : ctx.metadata_store->CommitTransaction();
            replay_commit_xid = ctx.metadata_store->LastCommittedXid();
        }
        {
            std::lock_guard<std::recursive_mutex> runtime_lock(ctx.runtime_state_mutex);
            ctx.runtime_last_commit_xid = replay_commit_xid;
        }
        if (commit_status != apfsaccess::rw::MetadataStore::CommitStatus::Committed &&
            commit_status != apfsaccess::rw::MetadataStore::CommitStatus::NothingToCommit)
        {
            SetRuntimeRecoveryReason(ctx, L"AcceptedWriteReplayCommitFailed");
            std::wcerr << L"[FsHost] Accepted-write replay batch commit failed (status="
                << static_cast<int>(commit_status)
                << L", stage="
                << Utf8ToWide(ctx.metadata_store->LastCommitStage())
                << L", reason="
                << ctx.metadata_store->LastCommitFailureReason()
                << L")."
                << std::endl;
            return false;
        }
    }

    // Verify the complete accepted prefix after the single checkpoint. The
    // verification remains intentionally strict on recovery paths.
    {
        std::lock_guard<std::mutex> metadata_lock(ctx.metadata_mutex);
        for (const auto& plan : replay_plans)
        {
            if (!VerifyAcceptedReplayTransactionApplied(
                    ctx, *plan.transaction, &plan.later_terminal_deletes))
            {
                SetRuntimeRecoveryReason(ctx, L"AcceptedWriteReplayVerificationFailed");
                return false;
            }
        }
    }

    const auto durable_target_sequence = !replay_plans.empty()
        ? replay_plans.back().transaction->accepted_sequence
        : (transactions.empty()
               ? ctx.tx_manager->Watermarks().apfs_durable_sequence
               : transactions.back().accepted_sequence);
    if (!ctx.tx_manager->MarkApfsDurableThrough(durable_target_sequence))
    {
        SetRuntimeRecoveryReason(ctx, L"AcceptedWriteReplayWatermarkFailed");
        return false;
    }

    const auto durable_sequence = ctx.tx_manager->Watermarks().apfs_durable_sequence;
    if (ctx.payload_spool && !ctx.payload_spool->CleanupThroughSequence(durable_sequence))
    {
        SetRuntimeRecoveryReason(ctx, L"AcceptedWriteReplayCleanupFailed");
        return false;
    }
    if (!ctx.tx_manager->MarkCleanedThrough(durable_sequence))
    {
        SetRuntimeRecoveryReason(ctx, L"AcceptedWriteReplayCleanupWatermarkFailed");
        return false;
    }

    if (!UpdateRecoveryMarkerBestEffort(&ctx, false))
    {
        {
            std::lock_guard<std::recursive_mutex> runtime_lock(ctx.runtime_state_mutex);
            ctx.pending_native_writes = true;
            ctx.recovery_active = true;
            ctx.runtime_recovery_reason = L"AcceptedWriteReplayRecoveryMarkerPersistFailed";
            ctx.runtime_last_recovery_action = L"AcceptedWriteReplayBlockedByRecoveryMarker";
        }
        std::wcerr << L"[FsHost] Accepted-write replay completed on APFS, but the clean recovery marker could not be persisted; RW remains blocked."
            << std::endl;
        return false;
    }
    {
        std::lock_guard<std::recursive_mutex> runtime_lock(ctx.runtime_state_mutex);
        ctx.pending_native_writes = false;
        ctx.recovery_active = false;
        ctx.write_degraded = false;
        ctx.runtime_recovery_reason.clear();
        ctx.runtime_last_recovery_action = L"AcceptedWriteReplayApplied";
    }
    return true;
}

void ReconcileWriteAheadLogRecoveryAfterMetadataBootstrap(
    MountContext& ctx,
    bool write_ahead_log_recovery_pending)
{
    if (!write_ahead_log_recovery_pending || !ctx.tx_manager)
    {
        return;
    }

    {
        std::lock_guard<std::recursive_mutex> runtime_lock(ctx.runtime_state_mutex);
        ctx.recovery_active = true;
        ctx.pending_native_writes = true;
        if (!ctx.tx_manager->RecoveryStateValid())
        {
            ctx.runtime_recovery_reason = L"WriteAheadLogInvalid";
            ctx.runtime_last_recovery_action = L"DowngradedAfterWriteAheadLogValidationFailure";
        }
        else if (ctx.runtime_recovery_reason.empty())
        {
            ctx.runtime_recovery_reason = L"AcceptedWriteReplayRequired";
            ctx.runtime_last_recovery_action = L"DowngradedUntilAcceptedWriteReplay";
        }
        if (ctx.native_write_enabled &&
            IsRecoveryPolicyFailClosed(ctx.args.write_recovery_policy))
        {
            ctx.write_degraded = true;
            ctx.native_write_enabled = false;
            ctx.overlay_write_enabled = false;
        }
    }
    std::wcerr << L"[FsHost] RW write-ahead log recovery is required; accepted writes are retained and RW stays blocked until replay completes."
        << std::endl;
}

void RemoveStaleHydrationFilesAfterCheckpointBestEffort(MountContext* c)
{
    if (!c)
    {
        return;
    }

    InvalidateHydrationReadHandle(c);

    std::vector<std::pair<std::filesystem::path, std::wstring>> stale_files;
    {
        std::lock_guard<std::mutex> lock(c->mutex);
        stale_files.reserve(c->stale_hydration_keys.size());
        for (const auto& path_key : c->stale_hydration_keys)
        {
            auto node_it = c->nodes.find(path_key);
            auto node = node_it == c->nodes.end()
                ? std::shared_ptr<Node>{}
                : node_it->second;
            if (!node || node->is_directory || node->write_handle_count != 0)
            {
                continue;
            }

            stale_files.emplace_back(HydrationPath(c, *node), path_key);
        }
    }

    for (const auto& [hydration_path, path_key] : stale_files)
    {
        std::error_code ec;
        std::filesystem::remove(hydration_path, ec);
        if (ec && IsHostCommitTraceEnabled())
        {
            std::wcerr << L"[FsHost] RW hydration-cache warning: failed to remove stale cache file '"
                << hydration_path.wstring()
                << L"'."
                << std::endl;
        }
    }
}

void DiscardPayloadSpoolSequenceBestEffort(MountContext* c, std::uint64_t wal_sequence)
{
    if (!c || !c->payload_spool || wal_sequence == 0)
    {
        return;
    }

    if (!c->payload_spool->DiscardSequence(wal_sequence) &&
        IsHostCommitTraceEnabled())
    {
        std::wcerr << L"[FsHost] RW payload-spool warning: failed to discard aborted dirty range."
            << std::endl;
    }
}

bool StageNativeDeleteSubtreeBestEffort(
    MountContext* c,
    const std::shared_ptr<Node>& node,
    std::wstring* failed_path = nullptr,
    bool* metadata_staged = nullptr)
{
    if (!c || !node || !IsNativeWriteEnabled(c))
    {
        return true;
    }

    if (node->is_directory)
    {
        std::vector<std::shared_ptr<Node>> children;
        {
            std::lock_guard<std::mutex> lock(c->mutex);
            children.reserve(node->children.size());
            for (const auto& child_name : node->children)
            {
#ifdef APFSACCESS_FSHOST_UNIT_TEST
                ++g_stage_delete_child_lookup_count_for_test;
#endif
                auto child = TryGetChildNodeLocked(c, node, child_name);
                if (child)
                {
                    children.push_back(std::move(child));
                }
            }
        }

        for (const auto& child : children)
        {
            if (!StageNativeDeleteSubtreeBestEffort(c, child, failed_path, metadata_staged))
            {
                return false;
            }
        }
    }

    bool current_metadata_staged = false;
    if (!RecordNativeMutationBestEffort(
            c,
            apfsaccess::rw::MetadataStore::MutationOperation::Delete,
            node->path,
            L"",
            0,
            0,
            false,
            0,
            nullptr,
            &current_metadata_staged))
    {
        if (metadata_staged)
        {
            *metadata_staged = *metadata_staged || current_metadata_staged;
        }
        if (failed_path)
        {
            *failed_path = node->path;
        }
        return false;
    }
    if (metadata_staged)
    {
        *metadata_staged = *metadata_staged || current_metadata_staged;
    }

    return true;
}

bool StageNativeDeletePostorderBestEffort(
    MountContext* c,
    const std::vector<std::shared_ptr<Node>>& postorder,
    std::wstring* failed_path = nullptr,
    apfsaccess::rw::MetadataStore::PayloadIdentity* staged_root_identity = nullptr,
    bool* metadata_staged = nullptr)
{
    if (metadata_staged)
    {
        *metadata_staged = false;
    }
    if (staged_root_identity)
    {
        *staged_root_identity = {};
    }
    if (!c || !IsNativeWriteEnabled(c))
    {
        return true;
    }

    for (const auto& node : postorder)
    {
        if (!node)
        {
            continue;
        }

        apfsaccess::rw::MetadataStore::PayloadIdentity staged_identity{};
        bool current_metadata_staged = false;
        if (!RecordNativeMutationBestEffort(
                c,
                apfsaccess::rw::MetadataStore::MutationOperation::Delete,
                node->path,
                L"",
                0,
                0,
                false,
                0,
                &staged_identity,
                &current_metadata_staged))
        {
            if (metadata_staged)
            {
                *metadata_staged = *metadata_staged || current_metadata_staged;
            }
            if (failed_path)
            {
                *failed_path = node->path;
            }
            return false;
        }
        if (metadata_staged)
        {
            *metadata_staged = *metadata_staged || current_metadata_staged;
        }

        if (staged_root_identity)
        {
            *staged_root_identity = staged_identity;
        }
    }

    return true;
}

bool IsBenignStaleDeletedSetBasicInfoFailure(MountContext* c, const std::shared_ptr<Node>& node)
{
    if (!c || !node)
    {
        return false;
    }

    std::wstring failure_path;
    {
        std::lock_guard<std::recursive_mutex> runtime_lock(c->runtime_state_mutex);
        if (_wcsicmp(c->last_native_mutation_failure_operation.c_str(), L"SetBasicInfo") ||
            _wcsicmp(c->last_native_mutation_failure_reason.c_str(), L"SetBasicInfoTargetMissing") ||
            !EqualsIgnoreCase(c->last_native_mutation_failure_path, node->path))
        {
            return false;
        }

        failure_path = c->last_native_mutation_failure_path;
    }

    bool missing_from_native_metadata = false;
#ifdef APFSACCESS_HAS_RW_ENGINE
    if (c->metadata_store)
    {
        std::lock_guard<std::mutex> metadata_lock(c->metadata_mutex);
        missing_from_native_metadata = !c->metadata_store->LookupCommittedInodeByPath(failure_path).has_value();
    }
#endif

    bool stale_node_removed = false;
    bool same_node_delete_pending = false;
    bool active_node_delete_hidden = false;
    bool hidden_by_delete_pending_ancestor = false;
    {
        std::lock_guard<std::mutex> lock(c->mutex);
        auto active = TryGetNodeLockedNormalized(c, node->path);
        stale_node_removed = !active;
        same_node_delete_pending = active == node && IsDeleteBlockedStateLocked(node);
        active_node_delete_hidden = active && IsDeleteBlockedStateLocked(active);
        hidden_by_delete_pending_ancestor = HasDeletePendingAncestorLockedNormalized(c, node->path);
    }

    if (!stale_node_removed &&
        !same_node_delete_pending &&
        !active_node_delete_hidden &&
        !hidden_by_delete_pending_ancestor &&
        !missing_from_native_metadata)
    {
        return false;
    }

    {
        std::lock_guard<std::recursive_mutex> runtime_lock(c->runtime_state_mutex);
        c->last_native_mutation_failure_operation.clear();
        c->last_native_mutation_failure_path.clear();
        c->last_native_mutation_failure_secondary_path.clear();
        c->last_native_mutation_failure_reason.clear();
        c->last_native_mutation_failure_status.clear();
    }
    return true;
}

bool IsBenignStaleDeletedDeleteFailure(MountContext* c, const std::shared_ptr<Node>& node)
{
    if (!c || !node)
    {
        return false;
    }

    {
        std::lock_guard<std::recursive_mutex> runtime_lock(c->runtime_state_mutex);
        if (_wcsicmp(c->last_native_mutation_failure_operation.c_str(), L"Delete") ||
            _wcsicmp(c->last_native_mutation_failure_reason.c_str(), L"DeleteTargetMissing") ||
            !EqualsIgnoreCase(c->last_native_mutation_failure_path, node->path))
        {
            return false;
        }
    }

    bool stale_node_removed = false;
    bool same_node_delete_pending = false;
    bool active_node_delete_hidden = false;
    bool hidden_by_delete_pending_ancestor = false;
    {
        std::lock_guard<std::mutex> lock(c->mutex);
        auto active = TryGetNodeLockedNormalized(c, node->path);
        stale_node_removed = !active;
        same_node_delete_pending = active == node && IsDeleteBlockedStateLocked(node);
        active_node_delete_hidden = active && IsDeleteBlockedStateLocked(active);
        hidden_by_delete_pending_ancestor = HasDeletePendingAncestorLockedNormalized(c, node->path);
    }
    if (!stale_node_removed &&
        !same_node_delete_pending &&
        !active_node_delete_hidden &&
        !hidden_by_delete_pending_ancestor)
    {
        return false;
    }

    {
        std::lock_guard<std::recursive_mutex> runtime_lock(c->runtime_state_mutex);
        c->last_native_mutation_failure_operation.clear();
        c->last_native_mutation_failure_path.clear();
        c->last_native_mutation_failure_secondary_path.clear();
        c->last_native_mutation_failure_reason.clear();
        c->last_native_mutation_failure_status.clear();
    }
    return true;
}

NTSTATUS BlockNativeMutationAfterStagingFailure(
    MountContext* c,
    const wchar_t* operation,
    bool metadata_staged = false)
{
    if (!c)
    {
        return STATUS_MEDIA_WRITE_PROTECTED;
    }

    {
        std::lock_guard<std::recursive_mutex> runtime_lock(c->runtime_state_mutex);
        if (metadata_staged)
        {
            c->unjournaled_native_mutation.store(true, std::memory_order_release);
        }
        c->recovery_active = true;
        c->pending_native_writes = true;
        c->write_degraded = true;
        c->native_write_enabled = false;
        c->overlay_write_enabled = false;
        if (c->runtime_recovery_reason.empty())
        {
            c->runtime_recovery_reason = metadata_staged
                ? L"UnjournaledNativeMutation"
                : L"NativeMutationStagingFailed";
        }
        if (c->runtime_last_recovery_action.empty())
        {
            c->runtime_last_recovery_action = metadata_staged
                ? L"DowngradedAfterPostStageFailure"
                : L"DowngradedAfterMutationStagingFailure";
        }
    }

    std::wcerr << L"[FsHost] RW mutation blocked";
    if (operation && *operation)
    {
        std::wcerr << L" (" << operation << L")";
    }
    std::wcerr << (metadata_staged
            ? L": native APFS metadata was staged but could not be recorded for recovery; the live write was rejected."
            : L": native APFS metadata staging failed; live write was rejected to avoid non-persistent Explorer-only state.")
               << std::endl;

    (void)UpdateRecoveryMarkerBestEffort(c, true);
    (void)WriteHostStatusFile(*c);
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
    bool replace_if_exists = false,
    std::uint64_t wal_sequence = 0,
    std::uint64_t timestamp_utc = 0,
    const apfsaccess::rw::MetadataStore::PayloadIdentity* identity = nullptr)
{
    if (!c || !c->tx_manager)
    {
        return true;
    }

    ScopedPerfTimer wal_append_scope(&c->perf_wal_append);

    if (IsNativeWriteEnabled(c) &&
        (!identity || identity->object_id == 0 || identity->generation == 0))
    {
        // Native records without identity cannot be replayed safely after a
        // restart. Keep the mutation out of the recovery journal rather than
        // allowing a path-reused object to be changed later.
        return false;
    }

    apfsaccess::rw::TransactionManager::MutationIntent mutation{};
    mutation.kind = kind;
    mutation.path = path;
    mutation.secondary_path = secondary_path;
    mutation.offset = offset;
    mutation.length = length;
    mutation.wal_sequence = wal_sequence;
    mutation.replace_if_exists = replace_if_exists;
    mutation.timestamp_utc = timestamp_utc;
    if (identity && identity->object_id != 0 && identity->generation != 0)
    {
        mutation.object_id = identity->object_id;
        mutation.generation = identity->generation;
    }

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

    InvalidatePayloadIdentityCache(c);
    return true;
}

bool RecordPayloadWriteMutationBestEffort(
    MountContext* c,
    const std::wstring& path,
    std::uint64_t offset,
    const void* payload,
    std::uint32_t payload_bytes,
    const apfsaccess::rw::MetadataStore::PayloadIdentity* staged_identity = nullptr)
{
    if (!c || !c->tx_manager)
    {
        return true;
    }

    ScopedPerfTimer wal_append_scope(&c->perf_wal_append);

    std::optional<apfsaccess::rw::MetadataStore::PayloadIdentity> identity;
    if (staged_identity && staged_identity->object_id != 0)
    {
        identity = *staged_identity;
    }
    else
    {
        identity = ResolvePayloadSpoolIdentity(c, path);
    }
    if (c->payload_spool && c->payload_spool_volume_identity.empty())
    {
        return !IsNativeWriteEnabled(c);
    }
    if (c->payload_spool && !identity.has_value())
    {
        return !IsNativeWriteEnabled(c);
    }

    apfsaccess::rw::TransactionManager::MutationIntent mutation{};
    mutation.kind = apfsaccess::rw::TransactionManager::MutationKind::Write;
    mutation.path = path;
    mutation.offset = offset;
    mutation.length = payload_bytes;

    ObservedMutexGuard lock(
        c->tx_mutex,
        &c->perf_tx_mutex_wait,
        &c->perf_tx_mutex_hold);
    auto& tx = *c->tx_manager;

    if (tx.CurrentState() == apfsaccess::rw::TransactionManager::State::Committing)
    {
        std::wcerr << L"[FsHost] RW journal warning: transaction is already committing; write mutation was deferred for path '" << path << L"'." << std::endl;
        return false;
    }

    if (tx.CurrentState() == apfsaccess::rw::TransactionManager::State::Failed)
    {
        (void)tx.Abort();
    }

    if (tx.CurrentState() == apfsaccess::rw::TransactionManager::State::Idle && !tx.Begin())
    {
        std::wcerr << L"[FsHost] RW journal warning: Begin() failed for write mutation path '" << path << L"'." << std::endl;
        return false;
    }

    mutation.wal_sequence = tx.NextMutationSequence();
    apfsaccess::rw::PayloadSpool::AppendResult spool_reference{};
    if (c->payload_spool && identity.has_value() &&
        !AppendPayloadSpoolForIdentityBestEffort(
            c,
            path,
            *identity,
            offset,
            payload,
            payload_bytes,
            mutation.wal_sequence,
            &spool_reference))
    {
        (void)tx.Abort();
        return false;
    }

    if (c->payload_spool && identity.has_value())
    {
        mutation.object_id = spool_reference.object_id;
        mutation.generation = spool_reference.generation;
        mutation.offset = spool_reference.logical_offset;
        mutation.length = spool_reference.payload_length;
        mutation.payload_spool_offset = spool_reference.spool_offset;
        mutation.payload_length = spool_reference.payload_length;
        mutation.payload_checksum = spool_reference.payload_sha256;
    }
    if (IsDeferCloseCommitsEnabled() &&
        IsInlineAcceptancePayloadEnabled() &&
        payload != nullptr &&
        tx.CanAddInlinePayload(payload_bytes))
    {
        const auto* payload_begin = static_cast<const std::byte*>(payload);
        mutation.inline_payload.assign(payload_begin, payload_begin + payload_bytes);
    }

    if (!tx.RecordMutation(mutation))
    {
        DiscardPayloadSpoolSequenceBestEffort(c, mutation.wal_sequence);
        (void)tx.Abort();
        std::wcerr << L"[FsHost] RW journal warning: RecordMutation() failed for write path '" << path << L"'." << std::endl;
        return false;
    }

    InvalidatePayloadIdentityCache(c);
    return true;
}

bool CommitMutationJournalBestEffort(
    MountContext* c,
    std::uint64_t* committed_sequence = nullptr,
    std::uint64_t* transaction_id = nullptr)
{
    if (transaction_id)
    {
        *transaction_id = 0;
    }
    if (!c || !c->tx_manager)
    {
        return true;
    }

    ObservedMutexGuard lock(
        c->tx_mutex,
        &c->perf_tx_mutex_wait,
        &c->perf_tx_mutex_hold);
    auto& tx = *c->tx_manager;
    if (transaction_id && tx.CurrentState() == apfsaccess::rw::TransactionManager::State::Active)
    {
        *transaction_id = tx.CurrentTransactionId();
    }
    const auto should_use_durable_acceptance =
        tx.HasUnappliedAcceptedWork() ||
        (IsDeferCloseCommitsEnabled() &&
         tx.CurrentState() == apfsaccess::rw::TransactionManager::State::Active);
    if (tx.CurrentState() == apfsaccess::rw::TransactionManager::State::Idle &&
        !tx.HasUnappliedAcceptedWork())
    {
        if (committed_sequence)
        {
            const auto watermarks = tx.Watermarks();
            *committed_sequence =
                watermarks.cleanup_sequence < watermarks.apfs_durable_sequence
                    ? watermarks.apfs_durable_sequence
                    : 0;
        }
        return true;
    }

    if (tx.CurrentState() == apfsaccess::rw::TransactionManager::State::Failed)
    {
        (void)tx.Abort();
        return false;
    }

    if (should_use_durable_acceptance)
    {
        if (tx.CurrentState() == apfsaccess::rw::TransactionManager::State::Active && !tx.Accept())
        {
            (void)tx.Abort();
            return false;
        }
        const auto target_sequence = tx.Watermarks().accepted_sequence;
        if (!tx.MarkApfsDurableThrough(target_sequence))
        {
            return false;
        }
        if (committed_sequence)
        {
            *committed_sequence = target_sequence;
        }
        return true;
    }

    if (!tx.Commit())
    {
        (void)tx.Abort();
        return false;
    }

    if (committed_sequence)
    {
        *committed_sequence = tx.LastCommittedSequence();
    }
    return true;
}

bool AcceptMutationJournalForDeferredCommitBestEffort(
    MountContext* c,
    const wchar_t* origin,
    std::uint64_t* accepted_sequence,
    GroupedDeferredAcceptanceFailureReason* failure_reason,
    MutationCallbackScope* callback_scope,
    bool wait_for_durability)
{
    if (accepted_sequence)
    {
        *accepted_sequence = 0;
    }
    if (failure_reason)
    {
        *failure_reason = GroupedDeferredAcceptanceFailureReason::None;
    }
    if (!c || !c->tx_manager)
    {
        return true;
    }

    const auto accept_and_wait_locked =
        [&](ObservedMutexGuard& lock,
            apfsaccess::rw::TransactionManager& tx,
            bool require_durability) -> bool
    {
        std::uint64_t deferred_sequence = 0;
        if (!tx.AcceptForDeferredCommit(&deferred_sequence))
        {
            if (failure_reason)
            {
                *failure_reason = GroupedDeferredAcceptanceFailureReason::WalAcceptanceFailed;
            }
            return false;
        }

        if (!require_durability)
        {
            if (accepted_sequence)
            {
                *accepted_sequence = deferred_sequence;
            }
            return true;
        }

        // The WAL bytes are already appended before releasing these locks.
        // Let the next Explorer callback append into the same bounded flush
        // cohort while this caller waits for the shared durability barrier.
        lock.unlock();
        if (callback_scope)
        {
            callback_scope->Unlock();
        }
        ScopedPerfTimer acceptance_wait_scope(&c->perf_acceptance_wait);
        const bool durable =
            tx.WaitForDeferredAcceptanceDurability(deferred_sequence);
        if (callback_scope)
        {
            callback_scope->Lock();
        }
        LockObserved(lock, &c->perf_tx_mutex_wait);
        if (!durable)
        {
            tx.MarkDeferredAcceptanceDurabilityFailure();
            if (failure_reason)
            {
                *failure_reason = GroupedDeferredAcceptanceFailureReason::WalAcceptanceFailed;
            }
            return false;
        }
        if (accepted_sequence)
        {
            *accepted_sequence = deferred_sequence;
        }
        return true;
    };

    {
        ObservedMutexGuard lock(
            c->tx_mutex,
            &c->perf_tx_mutex_wait,
            &c->perf_tx_mutex_hold);
        auto& tx = *c->tx_manager;
        if (tx.CurrentState() == apfsaccess::rw::TransactionManager::State::Idle)
        {
            const auto existing_sequence = tx.Watermarks().accepted_sequence;
            if (wait_for_durability && existing_sequence != 0)
            {
                lock.unlock();
                if (callback_scope)
                {
                    callback_scope->Unlock();
                }
                ScopedPerfTimer acceptance_wait_scope(&c->perf_acceptance_wait);
                const bool durable =
                    tx.WaitForDeferredAcceptanceDurability(existing_sequence);
                if (callback_scope)
                {
                    callback_scope->Lock();
                }
                LockObserved(lock, &c->perf_tx_mutex_wait);
                if (!durable)
                {
                    tx.MarkDeferredAcceptanceDurabilityFailure();
                    if (failure_reason)
                    {
                        *failure_reason = GroupedDeferredAcceptanceFailureReason::WalAcceptanceFailed;
                    }
                    return false;
                }
            }
            if (accepted_sequence)
            {
                *accepted_sequence = existing_sequence;
            }
            return true;
        }
        if (tx.CurrentState() == apfsaccess::rw::TransactionManager::State::Failed)
        {
            (void)tx.Abort();
            if (failure_reason)
            {
                *failure_reason = GroupedDeferredAcceptanceFailureReason::WalAcceptanceFailed;
            }
            return false;
        }
        if (IsInlineAcceptancePayloadEnabled() &&
            tx.CurrentState() == apfsaccess::rw::TransactionManager::State::Active &&
            tx.CanAcceptWithoutPayloadSpoolFlush())
        {
            return accept_and_wait_locked(lock, tx, wait_for_durability);
        }
    }
    if (!FlushPayloadSpoolForAcceptedBoundaryBestEffort(c, origin))
    {
        if (failure_reason)
        {
            *failure_reason = GroupedDeferredAcceptanceFailureReason::PayloadFlushFailed;
        }
        return false;
    }

    ObservedMutexGuard lock(
        c->tx_mutex,
        &c->perf_tx_mutex_wait,
        &c->perf_tx_mutex_hold);
    auto& tx = *c->tx_manager;
    if (tx.CurrentState() == apfsaccess::rw::TransactionManager::State::Idle)
    {
        if (accepted_sequence)
        {
            *accepted_sequence = tx.Watermarks().accepted_sequence;
        }
        return true;
    }
    if (tx.CurrentState() == apfsaccess::rw::TransactionManager::State::Failed)
    {
        (void)tx.Abort();
        if (failure_reason)
        {
            *failure_reason = GroupedDeferredAcceptanceFailureReason::WalAcceptanceFailed;
        }
        return false;
    }
    // Queue-only acceptance is reserved for the positively proven inline
    // branch above. Spool-backed or otherwise incomplete recovery proof must
    // cross the existing synchronous WAL durability barrier before return.
    return accept_and_wait_locked(lock, tx, true);
}

NativeCommitUrgency ClassifyNativeCommitRequest(
    MountContext* c,
    const wchar_t* origin,
    bool has_delete_plans,
    bool namespace_boundary)
{
    if (!c || !IsNativeWriteEnabled(c))
    {
        return NativeCommitUrgency::None;
    }
    bool has_pending_mutations = false;
#ifdef APFSACCESS_FSHOST_UNIT_TEST
    if (c->test_force_native_mutation_staging_success &&
        c->test_forced_native_commit_status.has_value())
    {
        has_pending_mutations = true;
    }
    else
#endif
    {
        has_pending_mutations = SnapshotNativeDirtyStatus(*c).has_any_dirty_work;
    }

#ifdef APFSACCESS_HAS_RW_ENGINE
    return apfsaccess::rw::WritePipeline::RequestBarrier({
        true,
        has_pending_mutations,
        has_delete_plans,
        namespace_boundary,
        origin ? std::wstring_view(origin) : std::wstring_view(),
    }).urgency;
#else
    if (!has_pending_mutations)
    {
        return NativeCommitUrgency::None;
    }
    if (has_delete_plans)
    {
        return NativeCommitUrgency::DeleteBoundaryMustCommit;
    }
    if (namespace_boundary)
    {
        return NativeCommitUrgency::NamespaceBoundaryMustCommit;
    }
    if (origin && !_wcsicmp(origin, L"Flush"))
    {
        return NativeCommitUrgency::UserFlushMustCommit;
    }
    if (origin && !_wcsicmp(origin, L"Shutdown"))
    {
        return NativeCommitUrgency::ShutdownMustCommit;
    }
    if (origin && !_wcsicmp(origin, L"DirtyLimit"))
    {
        return NativeCommitUrgency::DirtyLimitMustCommit;
    }
    if (origin && !_wcsicmp(origin, L"Close"))
    {
        return NativeCommitUrgency::FileContentCloseCanDelay;
    }
    return NativeCommitUrgency::MetadataOnlyCanDelay;
#endif
}

NTSTATUS CommitNativeMutationsBestEffort(MountContext* c, const wchar_t* origin)
{
    ScopedPerfTimer perf_scope(c ? &c->perf_commit_native : nullptr);

    if (!c)
    {
        return STATUS_SUCCESS;
    }
    if (c->unjournaled_native_mutation.load(std::memory_order_acquire))
    {
        CompleteDeferredCommitBarrier(c, false, STATUS_MEDIA_WRITE_PROTECTED);
        return STATUS_MEDIA_WRITE_PROTECTED;
    }
    if (!IsNativeWriteEnabled(c))
    {
        if (RequiresNativeApfsCheckpoint(c))
        {
            CompleteDeferredCommitBarrier(c, false, STATUS_MEDIA_WRITE_PROTECTED);
            return STATUS_MEDIA_WRITE_PROTECTED;
        }
        return STATUS_SUCCESS;
    }

#ifdef APFSACCESS_FSHOST_UNIT_TEST
    const bool forced_commit_status = c->test_forced_native_commit_status.has_value();
    if (!forced_commit_status && !c->metadata_store)
    {
        return STATUS_SUCCESS;
    }
#else
    if (!c->metadata_store)
    {
        return STATUS_SUCCESS;
    }
#endif

    ObservedMutexGuard commit_lock(
        c->commit_mutex,
        &c->perf_commit_mutex_wait,
        &c->perf_commit_mutex_hold);
#ifdef APFSACCESS_HAS_RW_ENGINE
    std::unique_lock<std::shared_mutex> committed_write_gate(c->committed_read_gate);
#endif
#ifdef APFSACCESS_FSHOST_UNIT_TEST
    ++c->test_native_commit_attempt_count;
#endif

    apfsaccess::rw::MetadataStore::CommitStatus commit_status = apfsaccess::rw::MetadataStore::CommitStatus::NotReady;
    std::optional<std::uint64_t> committed_xid = std::nullopt;
    std::wstring metadata_recovery_reason;
    bool metadata_recovery_required = false;
    bool canonical_ready_before_commit = false;
    bool require_canonical_gate = false;
    std::string final_commit_stage;
    std::uint64_t commit_timeout_budget_seconds = 0;
    std::uint64_t pending_mutations_before = 0;
    std::uint64_t pending_payload_bytes_before = 0;
    const auto commit_started_tick = static_cast<std::uint64_t>(GetTickCount64());
    {
        auto metadata_lock = AcquireObservedMutex(c->metadata_mutex, &c->perf_metadata_mutex_wait);
        const auto pending_payload_bytes = c->metadata_store
            ? c->metadata_store->PendingPayloadByteEstimate()
            : 0;
        pending_payload_bytes_before = pending_payload_bytes;
        pending_mutations_before = c->metadata_store
            ? static_cast<std::uint64_t>(c->metadata_store->PendingMutationCount())
            : 0;
        commit_timeout_budget_seconds = ComputeWriteCommitTimeoutBudgetSeconds(
            c->args.write_commit_timeout_seconds,
            pending_payload_bytes);
        ArmCommitDeadline(c, pending_payload_bytes);
#ifdef APFSACCESS_FSHOST_UNIT_TEST
        if (forced_commit_status)
        {
            commit_status = *c->test_forced_native_commit_status;
            metadata_recovery_reason = c->test_forced_native_commit_recovery_reason;
            metadata_recovery_required = c->test_forced_native_commit_recovery_required;
            final_commit_stage = "unit-test-forced";
        }
        else
#endif
        {
            require_canonical_gate = RequiresCanonicalMutationGate(c->args);
            canonical_ready_before_commit = c->metadata_store->IsCanonicalCommitReady();
            commit_status = require_canonical_gate
                ? c->metadata_store->CommitCanonicalTransaction()
                : c->metadata_store->CommitTransaction();
            final_commit_stage = c->metadata_store->LastCommitStage();
            committed_xid = c->metadata_store->LastCommittedXid();
            metadata_recovery_reason = c->metadata_store->RecoveryReason();
            metadata_recovery_required = c->metadata_store->IsRecoveryRequired();
        }
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
    if (IsPerfCountersEnabled())
    {
        ResolveNativeCommitOriginCounter(*c, origin).Observe(
            commit_status == apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            commit_status == apfsaccess::rw::MetadataStore::CommitStatus::NothingToCommit,
            commit_duration_ms,
            pending_mutations_before,
            pending_payload_bytes_before);
    }
    const auto commit_timed_out = c->commit_timeout_latched.exchange(false, std::memory_order_relaxed);
    const auto latch_commit_failure = [&](std::wstring reason, std::wstring action)
    {
        std::lock_guard<std::recursive_mutex> runtime_lock(c->runtime_state_mutex);
        c->recovery_active = true;
        c->runtime_recovery_reason = std::move(reason);
        c->runtime_last_recovery_action = std::move(action);
        if (IsRecoveryPolicyFailClosed(c->args.write_recovery_policy))
        {
            c->write_degraded = true;
            c->native_write_enabled = false;
            c->overlay_write_enabled = false;
        }
    };
    if (IsHostCommitTraceEnabled())
    {
        std::wcerr << L"[FsHost] RW native-commit timing"
                   << L" origin=" << origin
                   << L" status=" << static_cast<int>(commit_status)
                   << L" durationMs=" << commit_duration_ms
                   << L" timeoutSec=" << commit_timeout_budget_seconds
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
        latch_commit_failure(L"CommitTimedOut", L"DowngradedAfterCommitTimeout");
        (void)UpdateRecoveryMarkerBestEffort(c, true);
        (void)WriteHostStatusFile(*c);
        return STATUS_IO_TIMEOUT;
    }

    switch (commit_status)
    {
    case apfsaccess::rw::MetadataStore::CommitStatus::Committed:
    {
#ifdef APFSACCESS_FSHOST_UNIT_TEST
        if (forced_commit_status)
        {
            c->test_forced_native_mutations_pending = false;
        }
#endif
        if (!MergeLastCommittedInodeChangesIntoNodeIndex(c))
        {
            (void)MergeCommittedInodeStateIntoNodeIndex(c);
        }
        const bool can_clear_recovery_state = CanClearNativeRecoveryStateBestEffort(c);
        {
            std::lock_guard<std::recursive_mutex> runtime_lock(c->runtime_state_mutex);
            if (committed_xid.has_value())
            {
                c->runtime_last_commit_xid = committed_xid;
            }
            if (can_clear_recovery_state)
            {
                c->recovery_active = false;
                c->write_degraded = false;
                c->runtime_recovery_reason.clear();
                c->runtime_last_recovery_action.clear();
            }
        }
        (void)UpdateRecoveryMarkerBestEffort(c, !can_clear_recovery_state);
        (void)WriteHostStatusFile(*c);
        return STATUS_SUCCESS;
    }
    case apfsaccess::rw::MetadataStore::CommitStatus::NothingToCommit:
        {
            if (!CanClearNativeRecoveryStateBestEffort(c))
            {
                return STATUS_SUCCESS;
            }
            bool cleared_recovery_state = false;
            {
                std::lock_guard<std::recursive_mutex> runtime_lock(c->runtime_state_mutex);
                if (c->recovery_active || c->pending_native_writes)
                {
                    c->recovery_active = false;
                    c->write_degraded = false;
                    c->runtime_recovery_reason.clear();
                    c->runtime_last_recovery_action.clear();
                    cleared_recovery_state = true;
                }
            }
            if (!cleared_recovery_state)
            {
                return STATUS_SUCCESS;
            }
            (void)UpdateRecoveryMarkerBestEffort(c, false);
            (void)WriteHostStatusFile(*c);
        }
        return STATUS_SUCCESS;
    case apfsaccess::rw::MetadataStore::CommitStatus::NotWritable:
        std::wcerr << L"[FsHost] RW native-commit warning (" << origin << L"): write path is not writable; native commit remains blocked." << std::endl;
        metadata_recovery_reason = metadata_recovery_reason.empty()
            ? L"CommitNotWritable"
            : metadata_recovery_reason;
        latch_commit_failure(
            metadata_recovery_reason,
            !_wcsicmp(metadata_recovery_reason.c_str(), L"CommitModelNotCanonical")
                ? L"DowngradedAfterCommitModelMismatch"
                : L"DowngradedAfterNotWritable");
        (void)UpdateRecoveryMarkerBestEffort(c, true);
        (void)WriteHostStatusFile(*c);
        return STATUS_MEDIA_WRITE_PROTECTED;
    case apfsaccess::rw::MetadataStore::CommitStatus::NotReady:
        std::wcerr << L"[FsHost] RW native-commit warning (" << origin << L"): metadata store is not ready for commit." << std::endl;
        latch_commit_failure(
            metadata_recovery_reason.empty() ? L"CommitNotReady" : metadata_recovery_reason,
            L"DowngradedAfterNotReady");
        (void)UpdateRecoveryMarkerBestEffort(c, true);
        (void)WriteHostStatusFile(*c);
        return STATUS_UNSUCCESSFUL;
    case apfsaccess::rw::MetadataStore::CommitStatus::AllocationFailed:
        std::wcerr << L"[FsHost] RW native-commit warning (" << origin << L"): extent allocation failed during commit." << std::endl;
        latch_commit_failure(
            metadata_recovery_reason.empty() ? L"CommitAllocationFailed" : metadata_recovery_reason,
            L"DowngradedAfterAllocationFailure");
        (void)UpdateRecoveryMarkerBestEffort(c, true);
        (void)WriteHostStatusFile(*c);
        return STATUS_DISK_FULL;
    case apfsaccess::rw::MetadataStore::CommitStatus::InvariantFailed:
        std::wcerr << L"[FsHost] RW native-commit warning (" << origin << L"): pending mutation invariants failed preflight validation." << std::endl;
        latch_commit_failure(
            metadata_recovery_reason.empty() ? L"CommitInvariantFailed" : metadata_recovery_reason,
            L"DowngradedAfterInvariantFailure");
        (void)UpdateRecoveryMarkerBestEffort(c, true);
        (void)WriteHostStatusFile(*c);
        return STATUS_UNSUCCESSFUL;
    case apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed:
    case apfsaccess::rw::MetadataStore::CommitStatus::FlushFailed:
        std::wcerr << L"[FsHost] RW native-commit warning (" << origin << L"): failed to persist commit records." << std::endl;
        latch_commit_failure(
            metadata_recovery_reason.empty() ? L"CommitPersistOrFlushFailed" : metadata_recovery_reason,
            L"DowngradedAfterPersistFailure");
        (void)UpdateRecoveryMarkerBestEffort(c, true);
        (void)WriteHostStatusFile(*c);
        return metadata_recovery_required ? STATUS_MEDIA_WRITE_PROTECTED : STATUS_UNSUCCESSFUL;
    default:
        return STATUS_UNSUCCESSFUL;
    }
}

bool HasPendingNativeMutations(MountContext* c)
{
#ifdef APFSACCESS_FSHOST_UNIT_TEST
    if (c && c->test_force_native_mutation_staging_success && c->pending_native_writes)
    {
        return !c->test_forced_native_mutations_pending.has_value() ||
               *c->test_forced_native_mutations_pending;
    }
#endif
    if (!c || !c->metadata_store)
    {
        return false;
    }

    return SnapshotNativeDirtyStatus(*c).has_any_dirty_work;
}

bool HasUnappliedAcceptedWorkBestEffort(MountContext* c)
{
#ifdef APFSACCESS_HAS_RW_ENGINE
    if (!c || !c->tx_manager)
    {
        return false;
    }

    std::lock_guard<std::mutex> lock(c->tx_mutex);
    return c->tx_manager->HasUnappliedAcceptedWork();
#else
    (void)c;
    return false;
#endif
}

bool CanClearNativeRecoveryStateBestEffort(MountContext* c)
{
#ifdef APFSACCESS_HAS_RW_ENGINE
    if (!c || !c->tx_manager)
    {
        return true;
    }

    std::lock_guard<std::mutex> lock(c->tx_mutex);
    return c->tx_manager->CanClearRecoveryState();
#else
    (void)c;
    return true;
#endif
}

bool PendingNativeMutationsCanDelayClose(MountContext* c)
{
    if (!c)
    {
        return false;
    }

#ifdef APFSACCESS_FSHOST_UNIT_TEST
    if (c->test_force_native_mutation_staging_success &&
        c->pending_native_writes &&
        !c->metadata_store)
    {
        return c->test_forced_native_mutation_count > 0 &&
               c->test_forced_native_mutations_content_only;
    }
#endif

    if (!c->metadata_store)
    {
        return false;
    }

    std::lock_guard<std::mutex> metadata_lock(c->metadata_mutex);
    return c->metadata_store->PendingMutationsCanDelayClose();
}

bool PendingNativeMutationsAreDeletesOnly(MountContext* c)
{
    if (!c)
    {
        return false;
    }

#ifdef APFSACCESS_FSHOST_UNIT_TEST
    if (c->test_force_native_mutation_staging_success &&
        c->pending_native_writes &&
        !c->metadata_store)
    {
        return c->test_forced_native_mutation_count > 0 &&
               !c->test_forced_native_mutations_content_only;
    }
#endif

    if (!c->metadata_store)
    {
        return false;
    }

    std::lock_guard<std::mutex> metadata_lock(c->metadata_mutex);
    return c->metadata_store->PendingMutationsAreDeletesOnly();
}

bool PendingNativeMutationsCanContinueDeferredClose(MountContext* c)
{
    if (!c)
    {
        return false;
    }

#ifdef APFSACCESS_FSHOST_UNIT_TEST
    if (c->test_force_native_mutation_staging_success && c->pending_native_writes)
    {
        return c->test_forced_native_mutation_count > 0 &&
            (!c->test_forced_native_mutations_continue_deferred_close.has_value() ||
             *c->test_forced_native_mutations_continue_deferred_close);
    }
#endif

    if (!c->metadata_store)
    {
        return false;
    }

    std::lock_guard<std::mutex> metadata_lock(c->metadata_mutex);
    return c->metadata_store->PendingMutationsCanContinueDeferredClose();
}

bool HasOpenWriteHandles(MountContext* c)
{
    if (!c)
    {
        return false;
    }

    if (c->open_write_handle_count.load(std::memory_order_relaxed) > 0)
    {
        return true;
    }

#ifdef APFSACCESS_FSHOST_UNIT_TEST
    std::lock_guard<std::mutex> lock(c->mutex);
    for (const auto& [_, node] : c->nodes)
    {
        if (node && node->write_handle_count > 0)
        {
            return true;
        }
    }

#endif
    return false;
}

bool HasActiveOrRecentForegroundMutationsAfter(MountContext* c, std::uint64_t recent_cutoff_tick_ms)
{
    if (!c)
    {
        return false;
    }

    if (c->active_foreground_mutation_callbacks.load(std::memory_order_acquire) > 0)
    {
        return true;
    }
    if (MutationAdmissionCount(c->mutation_admission_state.load(std::memory_order_acquire)) > 0)
    {
        return true;
    }

    const auto last_tick = c->last_foreground_mutation_tick_ms.load(std::memory_order_acquire);
    if (last_tick == 0)
    {
        return false;
    }

    const auto now = static_cast<std::uint64_t>(GetTickCount64());
    if (recent_cutoff_tick_ms != 0 && last_tick <= recent_cutoff_tick_ms)
    {
        return false;
    }
    return now >= last_tick &&
           (now - last_tick) < static_cast<std::uint64_t>(kDeferredCloseCommitBaseQuietPeriod.count());
}

void TouchForegroundMutationTick(MountContext* c)
{
    if (!c)
    {
        return;
    }

    c->last_foreground_mutation_tick_ms.store(
        static_cast<std::uint64_t>(GetTickCount64()),
        std::memory_order_release);
}

bool ClearStaleNativeDirtyMarkerIfClean(MountContext* c)
{
    if (!c ||
        c->unjournaled_native_mutation.load(std::memory_order_acquire) ||
        HasBlockedRecoveryEvidence(*c) ||
        HasPendingNativeMutations(c) ||
        !CanClearNativeRecoveryStateBestEffort(c) ||
        HasUnappliedAcceptedWorkBestEffort(c))
    {
        return false;
    }

    bool was_deferred = false;
    {
        std::lock_guard<std::mutex> lock(c->deferred_commit_mutex);
        if (!c->deferred_commit_in_flight)
        {
            c->deferred_commit_requested = false;
            c->deferred_commit_requested_target = 0;
            c->deferred_commit_first_request_tick_ms = 0;
            c->deferred_commit_force_now = false;
            c->deferred_commit_burst_count = 0;
            c->deferred_commit_deadline_tick_ms = 0;
            was_deferred = c->close_commit_deferred.exchange(false, std::memory_order_acq_rel);
        }
        else
        {
            was_deferred = true;
        }
    }
    {
        std::lock_guard<std::recursive_mutex> runtime_lock(c->runtime_state_mutex);
        if (!c->pending_native_writes &&
            !c->recovery_active &&
            !c->write_degraded &&
            c->runtime_recovery_reason.empty() &&
            c->runtime_last_recovery_action.empty() &&
            !was_deferred)
        {
            return true;
        }
        c->recovery_active = false;
        c->write_degraded = false;
        c->runtime_recovery_reason.clear();
        c->runtime_last_recovery_action.clear();
    }
    (void)UpdateRecoveryMarkerBestEffort(c, false);
    (void)WriteHostStatusFile(*c);
    return true;
}

bool DeferredCommitPressureReached(MountContext* c)
{
    if (!c)
    {
        return false;
    }

    std::uint64_t pending_payload_bytes = 0;
    std::size_t pending_payload_files = 0;
#ifdef APFSACCESS_FSHOST_UNIT_TEST
    if (c->test_force_native_mutation_staging_success)
    {
        pending_payload_files = c->test_forced_native_mutation_count;
        pending_payload_bytes = c->test_forced_native_payload_bytes;
    }
#endif
    {
        std::lock_guard<std::mutex> lock(c->metadata_mutex);
        if (c->metadata_store)
        {
            pending_payload_bytes = c->metadata_store->PendingPayloadDirtyByteEstimate();
            pending_payload_files = (std::max)(
                pending_payload_files,
                c->metadata_store->PendingPayloadObjectSummaryCount());
        }
    }
    if (c->payload_spool)
    {
        const auto counters = c->payload_spool->SnapshotCounters();
        pending_payload_bytes = (std::max)(pending_payload_bytes, counters.bytes_since_sync);
        pending_payload_files = (std::max)(pending_payload_files, counters.dirty_object_count);
    }

    return pending_payload_bytes >= kDeferredCloseCommitPayloadBytesThreshold ||
        pending_payload_files >= kDeferredCloseCommitBurstThreshold;
}

bool BeginDeferredCommitBarrier(
    MountContext* c,
    bool from_worker,
    std::uint64_t required_target)
{
    if (!c)
    {
        return true;
    }

    std::unique_lock<std::mutex> lock(c->deferred_commit_mutex);
    const auto stop_generation_at_entry = c->deferred_commit_stop_generation;
    const auto target_at_entry = required_target != 0
        ? required_target
        : (std::max)(
            c->deferred_commit_in_flight_target,
            c->deferred_commit_requested_target);
    const bool waited_for_worker = !from_worker && c->deferred_commit_in_flight;
    if (!from_worker)
    {
        c->deferred_commit_cv.wait(lock, [&]()
        {
            return !c->deferred_commit_in_flight ||
                c->deferred_commit_thread_stop ||
                c->deferred_commit_stop_generation != stop_generation_at_entry;
        });
    }
    else if (!c->deferred_commit_in_flight)
    {
        return false;
    }

    if (c->deferred_commit_thread_stop ||
        c->deferred_commit_stop_generation != stop_generation_at_entry)
    {
        return false;
    }
    if (from_worker)
    {
        return true;
    }
    if (waited_for_worker && !NT_SUCCESS(c->deferred_commit_last_status))
    {
        return false;
    }
    if (c->deferred_commit_failed_target != 0 &&
        (target_at_entry == 0 || c->deferred_commit_failed_target <= target_at_entry))
    {
        return false;
    }
    if (target_at_entry != 0 &&
        c->deferred_commit_completed_target < target_at_entry &&
        !c->deferred_commit_requested &&
        !c->deferred_commit_in_flight)
    {
        return false;
    }
    if (!c->deferred_commit_requested)
    {
        return NT_SUCCESS(c->deferred_commit_last_status);
    }

    c->deferred_commit_requested = false;
    c->deferred_commit_first_request_tick_ms = 0;
    c->deferred_commit_force_now = false;
    c->deferred_commit_in_flight = true;
    c->deferred_commit_in_flight_target = c->deferred_commit_requested_target;
    c->deferred_commit_requested_target = 0;
    return true;
}

bool CompleteDeferredCommitBarrier(
    MountContext* c,
    bool success,
    NTSTATUS status,
    bool* effective_success)
{
    if (effective_success)
    {
        *effective_success = false;
    }
    if (!c)
    {
        return false;
    }

    {
        std::scoped_lock lock(c->deferred_commit_mutex, c->tx_mutex);
        if (!c->deferred_commit_in_flight)
        {
            return false;
        }

        const auto durable_sequence = c->tx_manager
            ? c->tx_manager->Watermarks().apfs_durable_sequence
            : 0;
        const auto target = c->deferred_commit_in_flight_target;
        if (success &&
            c->deferred_commit_failed_target != 0 &&
            (target == 0 || c->deferred_commit_failed_target <= target))
        {
            success = false;
            status = STATUS_UNSUCCESSFUL;
        }
        if (success && target != 0 && durable_sequence < target)
        {
            success = false;
            status = STATUS_UNSUCCESSFUL;
        }
        if (effective_success)
        {
            *effective_success = success;
        }
        c->deferred_commit_last_status = status;
        if (success)
        {
            c->deferred_commit_completed_target = (std::max)(
                c->deferred_commit_completed_target,
                target == 0 ? durable_sequence : target);
        }
        else if (target != 0 &&
                 (c->deferred_commit_failed_target == 0 ||
                  target < c->deferred_commit_failed_target))
        {
            // Preserve the first unresolved gap. A later failed target must
            // never hide an earlier failure from an ordered barrier.
            c->deferred_commit_failed_target = target;
        }
        c->deferred_commit_in_flight_target = 0;
        c->deferred_commit_in_flight = false;
        if (!c->deferred_commit_requested)
        {
            c->close_commit_deferred.store(false, std::memory_order_release);
        }
        c->deferred_commit_cv.notify_all();
    }

    (void)WriteHostStatusFile(*c);
    return true;
}

void RequestDeferredCloseCommit(MountContext* c, std::uint64_t accepted_target)
{
    if (!c)
    {
        return;
    }

    const bool active_write_handles = HasOpenWriteHandles(c);
    const bool active_mutation_callbacks =
        c->active_foreground_mutation_callbacks.load(std::memory_order_acquire) > 0 ||
        MutationAdmissionCount(c->mutation_admission_state.load(std::memory_order_acquire)) > 0;
    const auto now_tick_ms = static_cast<std::uint64_t>(GetTickCount64());
    const auto pressure_reached = DeferredCommitPressureReached(c);
    c->close_commit_deferred.store(true, std::memory_order_release);
    c->deferred_close_commit_count.fetch_add(1, std::memory_order_relaxed);
    {
        std::lock_guard<std::mutex> lock(c->deferred_commit_mutex);
        if (!c->deferred_commit_requested)
        {
            c->deferred_commit_burst_count = 0;
        }
        if (c->deferred_commit_burst_count < std::numeric_limits<std::uint64_t>::max())
        {
            ++c->deferred_commit_burst_count;
        }
        if (!c->deferred_commit_requested)
        {
            c->deferred_commit_first_request_tick_ms = now_tick_ms;
        }
        c->deferred_commit_requested_target = (std::max)(
            c->deferred_commit_requested_target,
            accepted_target);
        c->deferred_commit_requested = true;
        c->deferred_commit_force_now = c->deferred_commit_force_now || pressure_reached;
        if (c->deferred_commit_force_now)
        {
            c->deferred_commit_deadline = std::chrono::steady_clock::now();
            c->deferred_commit_deadline_tick_ms = now_tick_ms;
        }
        else
        {
            const auto quiet_period = DeferredCloseCommitQuietPeriodForBurst(
                c->deferred_commit_burst_count,
                active_write_handles);
            const auto first_request_age_ms =
                c->deferred_commit_first_request_tick_ms != 0 &&
                now_tick_ms >= c->deferred_commit_first_request_tick_ms
                    ? now_tick_ms - c->deferred_commit_first_request_tick_ms
                    : 0;
            const auto maximum_age_ms = static_cast<std::uint64_t>(
                kDeferredCloseCommitBurstQuietPeriod.count());
            const auto remaining_age_ms = first_request_age_ms >= maximum_age_ms
                ? 0
                : maximum_age_ms - first_request_age_ms;
            // A WAL barrier may already have completed while an active
            // writer/callback still holds the mount busy. Preserve a quiet
            // retry window for that busy cohort; applying the age clamp here
            // would turn a later close into an immediate retry loop.
            const auto bounded_delay = active_write_handles || active_mutation_callbacks
                ? quiet_period
                : (std::min)(quiet_period, std::chrono::milliseconds(remaining_age_ms));
            c->deferred_commit_deadline =
                std::chrono::steady_clock::now() +
                bounded_delay;
            c->deferred_commit_deadline_tick_ms =
                now_tick_ms +
                static_cast<std::uint64_t>(bounded_delay.count());
        }
    }
    c->deferred_commit_cv.notify_one();
    c->deferred_close_status_publish_pending.store(true, std::memory_order_release);
}

void DiscardDeferredDeleteRollbackPlans(MountContext* c)
{
    if (!c)
    {
        return;
    }

    std::vector<DeferredDeleteRollbackPlan> plans;
    {
        std::lock_guard<std::mutex> lock(c->mutex);
        plans.swap(c->deferred_delete_rollback_plans);
        c->deferred_delete_rollback_path_keys.clear();
        c->deferred_delete_rollback_has_descendant_paths = false;
    }

    for (const auto& plan : plans)
    {
        DiscardDeleteRollbackPlanSnapshots(plan, true);
    }
}

void RestoreDeferredDeleteRollbackPlans(MountContext* c)
{
    if (!c)
    {
        return;
    }

    std::vector<DeferredDeleteRollbackPlan> plans;
    {
        std::lock_guard<std::mutex> lock(c->mutex);
        plans.swap(c->deferred_delete_rollback_plans);
        c->deferred_delete_rollback_path_keys.clear();
        c->deferred_delete_rollback_has_descendant_paths = false;
        for (auto it = plans.rbegin(); it != plans.rend(); ++it)
        {
            RestoreDeleteRollbackPlanLocked(c, *it);
        }
    }

    for (const auto& plan : plans)
    {
        DiscardDeleteRollbackPlanSnapshots(plan, false);
    }
}

void ClearRenameCommittedReadPathsLocked(const RenameLocalSnapshot& plan)
{
    if (plan.node && !plan.node->is_directory)
    {
        plan.node->committed_read_path.clear();
    }
    for (const auto& entry : plan.descendant_committed_read_paths)
    {
        if (entry.node && !entry.node->is_directory)
        {
            entry.node->committed_read_path.clear();
        }
    }
}

void DiscardDeferredRenameRollbackPlans(MountContext* c)
{
    if (!c)
    {
        return;
    }

    std::vector<RenameLocalSnapshot> plans;
    {
        std::lock_guard<std::mutex> lock(c->mutex);
        for (const auto& plan : c->deferred_rename_rollback_plans)
        {
            ClearRenameCommittedReadPathsLocked(plan);
        }
        plans.swap(c->deferred_rename_rollback_plans);
    }

    for (const auto& plan : plans)
    {
        DiscardFileRollbackSnapshot(plan.replaced_file_snapshot);
    }
}

void RestoreDeferredRenameRollbackPlans(MountContext* c)
{
    if (!c)
    {
        return;
    }

    std::vector<RenameLocalSnapshot> plans;
    {
        std::lock_guard<std::mutex> lock(c->mutex);
        plans.swap(c->deferred_rename_rollback_plans);
        for (auto it = plans.rbegin(); it != plans.rend(); ++it)
        {
            RollbackRenameLocalStateLocked(c, *it);
        }
    }

    for (const auto& plan : plans)
    {
        DiscardFileRollbackSnapshot(plan.replaced_file_snapshot);
    }
}

bool CollectDeferredDirectoryRenameReadPathsLocked(
    MountContext* c,
    const std::shared_ptr<Node>& root,
    const OpenContext* current_open,
    std::vector<RenameDescendantReadPathSnapshot>& snapshots)
{
    snapshots.clear();
    if (!c || !root || !root->is_directory || !root->loaded)
    {
        return false;
    }
    if (!c->deferred_rename_rollback_plans.empty())
    {
        return false;
    }

    const auto allowed_open_handles = [&](const std::shared_ptr<Node>& node) -> std::uint32_t
    {
        return current_open && current_open->node == node ? 1u : 0u;
    };

    const std::function<bool(const std::shared_ptr<Node>&)> collect =
        [&](const std::shared_ptr<Node>& directory) -> bool
    {
        if (!directory ||
            !directory->is_directory ||
            !directory->loaded ||
            IsDeleteBlockedStateLocked(directory) ||
            directory->delete_requested_after_children ||
            directory->open_handle_count > allowed_open_handles(directory))
        {
            return false;
        }

        for (const auto& child_name : directory->children)
        {
            auto child = TryGetChildNodeLocked(c, directory, child_name);
            if (!child ||
                IsDeleteBlockedStateLocked(child) ||
                child->delete_requested_after_children ||
                child->open_handle_count > allowed_open_handles(child))
            {
                return false;
            }

            if (!child->committed_read_path.empty())
            {
                return false;
            }

            snapshots.push_back(RenameDescendantReadPathSnapshot{
                child,
                child->path,
                child->committed_read_path,
            });

            if (child->is_directory && !collect(child))
            {
                return false;
            }
        }

        return true;
    };

    return collect(root);
}

bool RenameDescendantReadPathSnapshotsEqual(
    const std::vector<RenameDescendantReadPathSnapshot>& lhs,
    const std::vector<RenameDescendantReadPathSnapshot>& rhs)
{
    if (lhs.size() != rhs.size())
    {
        return false;
    }

    for (std::size_t index = 0; index < lhs.size(); ++index)
    {
        if (lhs[index].node != rhs[index].node ||
            !IsSameNormalizedPath(lhs[index].old_path, rhs[index].old_path) ||
            !IsSameNormalizedPath(lhs[index].old_committed_read_path, rhs[index].old_committed_read_path))
        {
            return false;
        }
    }

    return true;
}

bool TryCoalesceDeferredRenameRollbackPlanLocked(
    MountContext* c,
    const RenameLocalSnapshot& snapshot)
{
    if (!c ||
        c->deferred_rename_rollback_plans.empty() ||
        !snapshot.node ||
        !snapshot.node_reindexed ||
        snapshot.node->is_directory ||
        !snapshot.descendant_committed_read_paths.empty() ||
        snapshot.replaced_node_was_present ||
        snapshot.replaced_node)
    {
        return false;
    }

    if (snapshot.old_path.empty() || snapshot.new_path.empty())
    {
        return false;
    }

    const auto touches_snapshot_path = [&](const RenameLocalSnapshot& plan)
    {
        return IsSameNormalizedPath(plan.old_path, snapshot.old_path) ||
               IsSameNormalizedPath(plan.old_path, snapshot.new_path) ||
               IsSameNormalizedPath(plan.new_path, snapshot.old_path) ||
               IsSameNormalizedPath(plan.new_path, snapshot.new_path);
    };

    for (auto it = c->deferred_rename_rollback_plans.rbegin();
         it != c->deferred_rename_rollback_plans.rend();
         ++it)
    {
        auto& previous = *it;
        if (!previous.node ||
            !previous.node_reindexed ||
            previous.node->is_directory ||
            !previous.descendant_committed_read_paths.empty() ||
            previous.replaced_node_was_present ||
            previous.replaced_node)
        {
            return false;
        }

        if (previous.node != snapshot.node)
        {
            if (touches_snapshot_path(previous))
            {
                return false;
            }
            continue;
        }

        if (previous.new_path.empty() ||
            previous.new_parent != snapshot.old_parent ||
            previous.new_leaf != snapshot.old_leaf ||
            !IsSameNormalizedPath(previous.new_path, snapshot.old_path) ||
            IsSameNormalizedPath(previous.old_path, snapshot.new_path))
        {
            return false;
        }

        const auto expected_committed_read_path =
            previous.old_committed_read_path.empty()
                ? previous.old_path
                : previous.old_committed_read_path;
        if (!snapshot.old_committed_read_path.empty() &&
            !IsSameNormalizedPath(snapshot.old_committed_read_path, expected_committed_read_path))
        {
            return false;
        }

        previous.new_path = snapshot.new_path;
        previous.new_parent = snapshot.new_parent;
        previous.new_leaf = snapshot.new_leaf;
        return true;
    }

    return false;
}

bool FlushPayloadSpoolForAcceptedBoundaryBestEffort(MountContext* c, const wchar_t* origin)
{
    if (!c || !c->payload_spool)
    {
        return true;
    }

#ifdef APFSACCESS_FSHOST_UNIT_TEST
    if (c->test_force_grouped_acceptance_flush_failure)
    {
        return false;
    }
#endif

    const auto flushed = IsDeferredPayloadIndexPersistenceEnabled()
        ? c->payload_spool->FlushPayloadBytes()
        : c->payload_spool->FlushDirtyState();
    if (flushed)
    {
        return true;
    }

    std::wcerr << L"[FsHost] RW payload-spool warning: failed to flush durable payload bytes during accepted boundary "
        << (origin ? origin : L"commit")
        << L"."
        << std::endl;
    return false;
}

void RequestGroupedDeferredAcceptanceFinish(MountContext* c)
{
    if (!c)
    {
        return;
    }

    std::shared_ptr<GroupedDeferredAcceptanceBatch> batch;
    {
        std::lock_guard<std::mutex> lock(c->grouped_acceptance_mutex);
        batch = c->grouped_acceptance_batch;
    }
    if (!batch)
    {
        return;
    }

    {
        std::lock_guard<std::mutex> lock(batch->mutex);
        if (!batch->completed)
        {
            batch->finish_requested = true;
        }
    }
    batch->cv.notify_all();
}

bool SnapshotGroupedAcceptanceRequirement(
    MountContext* c,
    std::uint64_t* transaction_id,
    std::uint64_t* required_sequence,
    std::uint64_t* accepted_sequence)
{
    if (transaction_id)
    {
        *transaction_id = 0;
    }
    if (required_sequence)
    {
        *required_sequence = 0;
    }
    if (accepted_sequence)
    {
        *accepted_sequence = 0;
    }
    if (!c || !c->tx_manager)
    {
        return false;
    }

    std::lock_guard<std::mutex> lock(c->tx_mutex);
    auto& tx = *c->tx_manager;
    if (tx.CurrentState() != apfsaccess::rw::TransactionManager::State::Active ||
        tx.PendingMutationCount() == 0 ||
        tx.NextMutationSequence() == 0)
    {
        return false;
    }

    if (required_sequence)
    {
        *required_sequence = tx.NextMutationSequence() - 1;
    }
    if (transaction_id)
    {
        *transaction_id = tx.CurrentTransactionId();
    }
    if (accepted_sequence)
    {
        *accepted_sequence = tx.Watermarks().accepted_sequence;
    }
    return (transaction_id == nullptr || *transaction_id != 0) &&
        (required_sequence == nullptr || *required_sequence != 0);
}

void UpdateAtomicMaximum(std::atomic<std::uint64_t>& target, std::uint64_t value)
{
    auto current = target.load(std::memory_order_relaxed);
    while (current < value &&
           !target.compare_exchange_weak(
               current,
               value,
               std::memory_order_relaxed,
               std::memory_order_relaxed))
    {
    }
}

bool PublishGroupedDeferredAcceptanceResult(
    MountContext* c,
    const std::shared_ptr<GroupedDeferredAcceptanceBatch>& batch,
    std::uint64_t transaction_id,
    bool success,
    bool absorbed_by_boundary,
    bool deferred_request_scheduled,
    bool failure_handled,
    std::uint64_t accepted_sequence,
    NTSTATUS status)
{
    if (!c || !batch || transaction_id == 0)
    {
        return false;
    }

    std::uint64_t participant_count = 0;
    {
        std::lock_guard<std::mutex> lock(batch->mutex);
        if (batch->completed || batch->transaction_id != transaction_id)
        {
            return false;
        }
        participant_count = batch->participant_count;
        batch->success = success;
        batch->absorbed_by_boundary = success && absorbed_by_boundary;
        batch->deferred_request_scheduled = success && deferred_request_scheduled;
        batch->failure_handled = !success && failure_handled;
        batch->accepted_sequence = accepted_sequence;
        batch->status = success ? STATUS_SUCCESS : status;
        batch->completed = true;
    }

    c->grouped_acceptance_batch_count.fetch_add(1, std::memory_order_relaxed);
    c->grouped_acceptance_participant_count.store(participant_count, std::memory_order_release);
    UpdateAtomicMaximum(c->grouped_acceptance_max_cohort_size, participant_count);
    c->grouped_acceptance_last_target.store(accepted_sequence, std::memory_order_release);
    batch->cv.notify_all();
    return true;
}

void LatchGroupedDeferredAcceptanceFailure(
    MountContext* c,
    const wchar_t* origin,
    GroupedDeferredAcceptanceFailureReason reason =
        GroupedDeferredAcceptanceFailureReason::WalAcceptanceFailed,
    std::uint64_t transaction_id = 0,
    std::uint64_t required_sequence = 0,
    std::uint64_t batch_required_sequence = 0,
    std::uint64_t result_sequence = 0,
    std::uint64_t observed_transaction_id = 0,
    std::uint64_t observed_accepted_sequence = 0,
    std::uint64_t batch_generation = 0,
    bool batch_sealed = false)
{
    if (!c)
    {
        return;
    }

    std::lock_guard<std::recursive_mutex> runtime_lock(c->runtime_state_mutex);

    c->grouped_acceptance_last_failure_reason.store(
        static_cast<std::uint32_t>(reason),
        std::memory_order_release);
    c->grouped_acceptance_last_failure_transaction_id.store(
        transaction_id,
        std::memory_order_release);
    c->grouped_acceptance_last_failure_required_sequence.store(
        required_sequence,
        std::memory_order_release);
    c->grouped_acceptance_last_failure_batch_required_sequence.store(
        batch_required_sequence,
        std::memory_order_release);
    c->grouped_acceptance_last_failure_result_sequence.store(
        result_sequence,
        std::memory_order_release);
    c->grouped_acceptance_last_failure_observed_transaction_id.store(
        observed_transaction_id,
        std::memory_order_release);
    c->grouped_acceptance_last_failure_observed_accepted_sequence.store(
        observed_accepted_sequence,
        std::memory_order_release);
    c->grouped_acceptance_last_failure_batch_generation.store(
        batch_generation,
        std::memory_order_release);
    c->grouped_acceptance_last_failure_batch_sealed.store(
        batch_sealed,
        std::memory_order_release);

#ifdef APFSACCESS_FSHOST_UNIT_TEST
    ++c->test_grouped_acceptance_failure_recovery_count;
#endif
    c->recovery_active = true;
#ifdef APFSACCESS_FSHOST_UNIT_TEST
    if (c->test_pause_runtime_transition.load(std::memory_order_acquire))
    {
        c->test_runtime_transition_paused.store(true, std::memory_order_release);
        while (!c->test_release_runtime_transition.load(std::memory_order_acquire))
        {
            std::this_thread::yield();
        }
    }
#endif
    c->runtime_recovery_reason = L"DeferredAcceptanceFailed";
    c->runtime_last_recovery_action = L"RetainedAfterDeferredAcceptanceFailure";
    if (IsRecoveryPolicyFailClosed(c->args.write_recovery_policy))
    {
        c->write_degraded = true;
        c->native_write_enabled = false;
        c->overlay_write_enabled = false;
    }
    std::wcerr << L"[FsHost] RW deferred-acceptance warning: durable payload/WAL acceptance failed during "
        << (origin ? origin : L"CloseDeferredAccept")
        << L" (reason="
        << GroupedDeferredAcceptanceFailureReasonName(reason)
        << L", transaction="
        << transaction_id
        << L", required="
        << required_sequence
        << L", batchRequired="
        << batch_required_sequence
        << L", result="
        << result_sequence
        << L", observedTransaction="
        << observed_transaction_id
        << L", observedAccepted="
        << observed_accepted_sequence
        << L", batchGeneration="
        << batch_generation
        << L", batchSealed="
        << (batch_sealed ? L"true" : L"false")
        << L"); retained evidence and blocked further writes."
        << std::endl;
    (void)UpdateRecoveryMarkerBestEffort(c, true);
    (void)WriteHostStatusFile(*c);
}

std::shared_ptr<GroupedDeferredAcceptanceBatch> CaptureGroupedDeferredAcceptanceBatch(
    MountContext* c)
{
    if (!c)
    {
        return nullptr;
    }

    std::lock_guard<std::mutex> lock(c->grouped_acceptance_mutex);
    return c->grouped_acceptance_batch;
}

void CompleteGroupedDeferredAcceptanceAfterBoundary(
    MountContext* c,
    const std::shared_ptr<GroupedDeferredAcceptanceBatch>& batch,
    std::uint64_t transaction_id,
    std::uint64_t accepted_sequence,
    bool success)
{
    if (!c || transaction_id == 0)
    {
        return;
    }

    (void)PublishGroupedDeferredAcceptanceResult(
        c,
        batch,
        transaction_id,
        success,
        success,
        false,
        !success,
        accepted_sequence,
        success ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL);
}

bool FinishGroupedDeferredAcceptanceBatchLocked(
    MountContext* c,
    const std::shared_ptr<GroupedDeferredAcceptanceBatch>& batch,
    const wchar_t* origin,
    bool schedule_deferred_worker,
    MutationCallbackScope& mutation_scope)
{
    if (!c || !batch)
    {
        return false;
    }

    std::uint64_t transaction_id = 0;
    std::uint64_t required_sequence = 0;
    {
        std::lock_guard<std::mutex> lock(batch->mutex);
        if (batch->completed)
        {
            return batch->success;
        }
        batch->finishing = true;
        transaction_id = batch->transaction_id;
        required_sequence = batch->required_sequence;
    }

    bool success = false;
    std::uint64_t accepted_sequence = 0;
    NTSTATUS status = STATUS_SUCCESS;
    bool transaction_active = false;
    std::uint64_t observed_transaction_id = 0;
    std::uint64_t observed_accepted_sequence = 0;
    auto failure_reason = GroupedDeferredAcceptanceFailureReason::None;
    {
        std::lock_guard<std::mutex> lock(c->tx_mutex);
        if (!c->tx_manager)
        {
            status = STATUS_UNSUCCESSFUL;
            failure_reason = GroupedDeferredAcceptanceFailureReason::TransactionInactiveOrChanged;
        }
        else
        {
            auto& tx = *c->tx_manager;
            const auto state = tx.CurrentState();
            observed_transaction_id = tx.CurrentTransactionId();
            observed_accepted_sequence = tx.Watermarks().accepted_sequence;
            if (state == apfsaccess::rw::TransactionManager::State::Active &&
                observed_transaction_id == transaction_id)
            {
                transaction_active = true;
            }
            else if (state == apfsaccess::rw::TransactionManager::State::Idle)
            {
                const auto exact_accepted_sequence =
                    tx.AcceptedSequenceForTransaction(transaction_id);
                if (exact_accepted_sequence.has_value() &&
                    (required_sequence == 0 || *exact_accepted_sequence >= required_sequence))
                {
                    accepted_sequence = *exact_accepted_sequence;
                    success = true;
                }
                else
                {
                    status = STATUS_UNSUCCESSFUL;
                    failure_reason = GroupedDeferredAcceptanceFailureReason::TransactionInactiveOrChanged;
                }
            }
            else
            {
                status = STATUS_UNSUCCESSFUL;
                failure_reason = GroupedDeferredAcceptanceFailureReason::TransactionInactiveOrChanged;
            }
        }
    }

    if (transaction_active)
    {
        success = AcceptMutationJournalForDeferredCommitBestEffort(
            c,
            origin,
            &accepted_sequence,
            &failure_reason,
            &mutation_scope);
        {
            std::lock_guard<std::mutex> lock(c->tx_mutex);
            if (c->tx_manager)
            {
                observed_transaction_id = c->tx_manager->CurrentTransactionId();
                observed_accepted_sequence = c->tx_manager->Watermarks().accepted_sequence;
            }
        }
        if (success && (required_sequence == 0 || accepted_sequence < required_sequence))
        {
            success = false;
            status = STATUS_UNSUCCESSFUL;
            failure_reason =
                GroupedDeferredAcceptanceFailureReason::AcceptedSequenceBelowBatchRequirement;
        }
        if (!success)
        {
            status = STATUS_UNSUCCESSFUL;
        }
    }

    if (!success)
    {
        LatchGroupedDeferredAcceptanceFailure(
            c,
            origin,
            failure_reason,
            transaction_id,
            required_sequence,
            required_sequence,
            accepted_sequence,
            observed_transaction_id,
            observed_accepted_sequence,
            batch->generation,
            true);
        if (transaction_active)
        {
            AbortMutationJournalBestEffort(c, origin);
        }
        (void)PublishGroupedDeferredAcceptanceResult(
            c,
            batch,
            transaction_id,
            false,
            false,
            false,
            true,
            0,
            status);
        return false;
    }

    bool deferred_request_scheduled = false;
    bool absorbed_by_boundary = false;
    if (c->tx_manager)
    {
        std::lock_guard<std::mutex> lock(c->tx_mutex);
        const auto watermarks = c->tx_manager->Watermarks();
        absorbed_by_boundary = absorbed_by_boundary ||
            watermarks.apfs_durable_sequence >= accepted_sequence;
        deferred_request_scheduled = schedule_deferred_worker &&
            accepted_sequence != 0 &&
            watermarks.apfs_durable_sequence < accepted_sequence;
    }
    if (deferred_request_scheduled)
    {
        RequestDeferredCloseCommit(c, accepted_sequence);
    }

    (void)PublishGroupedDeferredAcceptanceResult(
        c,
        batch,
        transaction_id,
        true,
        absorbed_by_boundary,
        deferred_request_scheduled,
        false,
        accepted_sequence,
        STATUS_SUCCESS);
    return true;
}

bool AcceptMutationJournalForGroupedDeferredCommitBestEffort(
    MountContext* c,
    MutationCallbackScope& mutation_scope,
    const wchar_t* origin,
    std::uint64_t* accepted_sequence,
    bool* grouped_attempted,
    bool* grouped_failure_handled)
{
    if (accepted_sequence)
    {
        *accepted_sequence = 0;
    }
    if (grouped_attempted)
    {
        *grouped_attempted = false;
    }
    if (grouped_failure_handled)
    {
        *grouped_failure_handled = false;
    }
    if (!c || !mutation_scope.OwnsLock() || !IsGroupedDeferredAcceptanceEnabled())
    {
        return AcceptMutationJournalForDeferredCommitBestEffort(c, origin, accepted_sequence);
    }

    // A lone close should retain the low-latency path. Grouping is useful only
    // while another write handle can contribute a participant to this window.
    // The deferred commit worker still coalesces already-accepted serial work.
    bool has_active_grouped_batch = false;
    {
        std::lock_guard<std::mutex> coordinator_lock(c->grouped_acceptance_mutex);
        const auto batch = c->grouped_acceptance_batch;
        if (batch)
        {
            std::lock_guard<std::mutex> batch_lock(batch->mutex);
            has_active_grouped_batch = !batch->completed;
        }
    }
    if (!HasOpenWriteHandles(c) &&
        !has_active_grouped_batch &&
        PendingNativeMutationsCanDelayClose(c))
    {
        return AcceptMutationJournalForDeferredCommitBestEffort(
            c,
            origin,
            accepted_sequence,
            nullptr,
            nullptr,
            false);
    }

    std::uint64_t transaction_id = 0;
    std::uint64_t required_sequence = 0;
    std::uint64_t initial_accepted_sequence = 0;
    if (!SnapshotGroupedAcceptanceRequirement(
            c,
            &transaction_id,
            &required_sequence,
            &initial_accepted_sequence))
    {
        return AcceptMutationJournalForDeferredCommitBestEffort(c, origin, accepted_sequence);
    }

    bool proof_retained = false;
    {
        std::lock_guard<std::mutex> lock(c->tx_mutex);
        proof_retained = c->tx_manager &&
            c->tx_manager->RetainAcceptedSequenceProof(transaction_id);
    }
    if (!proof_retained)
    {
        return AcceptMutationJournalForDeferredCommitBestEffort(c, origin, accepted_sequence);
    }
    ScopeExit release_acceptance_proof{[c, transaction_id]()
    {
        std::lock_guard<std::mutex> lock(c->tx_mutex);
        if (c->tx_manager)
        {
            c->tx_manager->ReleaseAcceptedSequenceProof(transaction_id);
        }
    }};

    bool success = false;
    std::uint64_t result_sequence = 0;
    bool request_handled = false;
    bool failure_handled = false;
    bool waiting_participant_registered = false;
    for (;;)
    {
        std::shared_ptr<GroupedDeferredAcceptanceBatch> batch;
        bool joined_batch = false;
        for (;;)
        {
            bool retry = false;
            {
                std::lock_guard<std::mutex> coordinator_lock(c->grouped_acceptance_mutex);
                batch = c->grouped_acceptance_batch;
                if (!batch)
                {
                    batch = std::make_shared<GroupedDeferredAcceptanceBatch>();
#ifdef APFSACCESS_FSHOST_UNIT_TEST
                    const auto window_ms = c->test_grouped_acceptance_window_ms == 0
                        ? kGroupedDeferredAcceptanceWindowMs
                        : c->test_grouped_acceptance_window_ms;
#else
                    constexpr std::uint32_t window_ms = kGroupedDeferredAcceptanceWindowMs;
#endif
                    batch->deadline = std::chrono::steady_clock::now() +
                        std::chrono::milliseconds(window_ms);
                    batch->generation = c->grouped_acceptance_next_generation.fetch_add(
                        1,
                        std::memory_order_relaxed);
                    batch->transaction_id = transaction_id;
                    c->grouped_acceptance_batch = batch;
                }

                std::lock_guard<std::mutex> batch_lock(batch->mutex);
                if (batch->completed || batch->transaction_id != transaction_id)
                {
                    if (c->grouped_acceptance_batch == batch)
                    {
                        c->grouped_acceptance_batch.reset();
                    }
                    retry = true;
                }
                else
                {
                    if (!batch->finish_requested &&
                        !batch->finishing &&
                        batch->participant_count < kGroupedDeferredAcceptanceMaxParticipants)
                    {
                        batch->required_sequence = (std::max)(batch->required_sequence, required_sequence);
                        ++batch->participant_count;
                        joined_batch = true;
                        if (batch->participant_count == 1)
                        {
                            batch->initial_accepted_sequence = initial_accepted_sequence;
                        }
                    }
                    if (batch->participant_count >= kGroupedDeferredAcceptanceMaxParticipants)
                    {
                        batch->finish_requested = true;
                    }
                }
            }
            if (!retry)
            {
                break;
            }
        }

        if (!waiting_participant_registered)
        {
            c->grouped_acceptance_waiting_participants.fetch_add(1, std::memory_order_acq_rel);
            waiting_participant_registered = true;
        }
        mutation_scope.Unlock();
        batch->cv.notify_all();

        bool is_finisher = false;
        {
            std::unique_lock<std::mutex> lock(batch->mutex);
            for (;;)
            {
                if (batch->completed)
                {
                    break;
                }
                const auto deadline_reached = std::chrono::steady_clock::now() >= batch->deadline;
                if (!batch->finishing && (batch->finish_requested || deadline_reached))
                {
                    batch->finishing = true;
                    is_finisher = true;
                    break;
                }
                if (batch->finishing)
                {
                    batch->cv.wait(lock, [&]() { return batch->completed; });
                    break;
                }
                batch->cv.wait_until(lock, batch->deadline, [&]()
                {
                    return batch->completed || batch->finishing || batch->finish_requested;
                });
            }
        }

        if (is_finisher)
        {
            // The first finisher must reacquire the mutation queue before the
            // payload and WAL barriers, so no new write can land between them.
            mutation_scope.Lock();
            (void)FinishGroupedDeferredAcceptanceBatchLocked(
                c,
                batch,
                origin,
                true,
                mutation_scope);
        }

        std::uint64_t batch_required_sequence = 0;
        std::uint64_t batch_generation = 0;
        bool batch_sealed = false;
        {
            std::unique_lock<std::mutex> lock(batch->mutex);
            batch->cv.wait(lock, [&]() { return batch->completed; });
            success = batch->success;
            result_sequence = batch->accepted_sequence;
            request_handled = batch->deferred_request_scheduled || batch->absorbed_by_boundary;
            failure_handled = batch->failure_handled;
            batch_required_sequence = batch->required_sequence;
            batch_generation = batch->generation;
            batch_sealed = batch->finish_requested || batch->finishing;
        }
        mutation_scope.Lock();

        if (!success || result_sequence >= required_sequence)
        {
            break;
        }

        if (joined_batch)
        {
            LatchGroupedDeferredAcceptanceFailure(
                c,
                origin,
                GroupedDeferredAcceptanceFailureReason::AcceptedSequenceBelowBatchRequirement,
                transaction_id,
                required_sequence,
                batch_required_sequence,
                result_sequence,
                transaction_id,
                initial_accepted_sequence,
                batch_generation,
                batch_sealed);
            success = false;
            request_handled = false;
            failure_handled = true;
            break;
        }

        std::uint64_t observed_transaction_id = 0;
        std::uint64_t observed_required_sequence = 0;
        std::uint64_t observed_accepted_sequence = 0;
        bool can_roll_over = false;
        {
            std::lock_guard<std::mutex> lock(c->tx_mutex);
            if (c->tx_manager)
            {
                auto& tx = *c->tx_manager;
                observed_transaction_id = tx.CurrentTransactionId();
                observed_accepted_sequence = tx.Watermarks().accepted_sequence;
                if (tx.CurrentState() == apfsaccess::rw::TransactionManager::State::Active &&
                    observed_transaction_id == transaction_id &&
                    tx.PendingMutationCount() > 0 &&
                    tx.NextMutationSequence() > 0)
                {
                    observed_required_sequence = tx.NextMutationSequence() - 1;
                    can_roll_over = observed_required_sequence >= required_sequence;
                }
            }
        }
        if (!can_roll_over)
        {
            LatchGroupedDeferredAcceptanceFailure(
                c,
                origin,
                GroupedDeferredAcceptanceFailureReason::SealedFollowerUncovered,
                transaction_id,
                required_sequence,
                batch_required_sequence,
                result_sequence,
                observed_transaction_id,
                observed_accepted_sequence,
                batch_generation,
                batch_sealed);
            success = false;
            request_handled = false;
            failure_handled = true;
            break;
        }

        c->grouped_acceptance_rollover_count.fetch_add(1, std::memory_order_relaxed);
        c->grouped_acceptance_last_rollover_required_sequence.store(
            required_sequence,
            std::memory_order_release);
        c->grouped_acceptance_last_rollover_result_sequence.store(
            result_sequence,
            std::memory_order_release);
        required_sequence = observed_required_sequence;
        initial_accepted_sequence = observed_accepted_sequence;
    }
    if (waiting_participant_registered)
    {
        c->grouped_acceptance_waiting_participants.fetch_sub(1, std::memory_order_acq_rel);
    }
    if (accepted_sequence)
    {
        *accepted_sequence = result_sequence;
    }
    if (grouped_attempted)
    {
        *grouped_attempted = success && request_handled;
    }
    if (grouped_failure_handled)
    {
        *grouped_failure_handled = !success && failure_handled;
    }
    return success;
}

bool NodePathCommittedForExperimentalRename(MountContext* c, const std::wstring& path, bool require_directory)
{
#ifdef APFSACCESS_HAS_RW_ENGINE
#ifdef APFSACCESS_FSHOST_UNIT_TEST
    if (c && c->test_force_native_mutation_staging_success && !c->metadata_store)
    {
        std::lock_guard<std::mutex> lock(c->mutex);
        const auto node = TryGetNodeLockedNormalized(c, path);
        return node &&
               node->is_directory == require_directory &&
               node->committed_read_path.empty();
    }
#endif
    if (!c || !c->metadata_store)
    {
        return false;
    }

    std::lock_guard<std::mutex> metadata_lock(c->metadata_mutex);
    const auto inode = c->metadata_store->LookupCommittedInodeByPath(path);
    return inode.has_value() && inode->is_directory == require_directory;
#else
    (void)c;
    (void)path;
    (void)require_directory;
    return false;
#endif
}

bool DeferredDirectoryRenameDescendantsCommitted(
    MountContext* c,
    const std::vector<RenameDescendantReadPathSnapshot>& snapshots)
{
#ifdef APFSACCESS_HAS_RW_ENGINE
#ifdef APFSACCESS_FSHOST_UNIT_TEST
    if (c && c->test_force_native_mutation_staging_success && !c->metadata_store)
    {
        return true;
    }
#endif
    if (!c || !c->metadata_store)
    {
        return false;
    }

    std::lock_guard<std::mutex> metadata_lock(c->metadata_mutex);
    for (const auto& entry : snapshots)
    {
        if (!entry.node || !entry.old_committed_read_path.empty())
        {
            return false;
        }

        const auto inode = c->metadata_store->LookupCommittedInodeByPath(entry.old_path);
        if (!inode.has_value() || inode->is_directory != entry.node->is_directory)
        {
            return false;
        }
    }

    return true;
#else
    (void)c;
    (void)snapshots;
    return false;
#endif
}

bool SourcePathCommittedForExperimentalRename(MountContext* c, const std::wstring& path)
{
#ifdef APFSACCESS_HAS_RW_ENGINE
#ifdef APFSACCESS_FSHOST_UNIT_TEST
    ++g_experimental_rename_committed_source_probe_count_for_test;
#endif
    return NodePathCommittedForExperimentalRename(c, path, false);
#else
    (void)c;
    (void)path;
    return false;
#endif
}

bool SourceNodeCarriesCommittedReadPathForExperimentalRename(
    MountContext* c,
    const std::shared_ptr<Node>& node,
    const std::wstring& source_path)
{
#ifdef APFSACCESS_HAS_RW_ENGINE
    if (!c || !node || node->is_directory || node->committed_read_path.empty())
    {
        return false;
    }

    if (NodePathKey(*node) != LowerPathKey(source_path))
    {
        return false;
    }

#ifdef APFSACCESS_FSHOST_UNIT_TEST
    if (c->test_force_native_mutation_staging_success && !c->metadata_store)
    {
        return true;
    }
#endif

    return SourcePathCommittedForExperimentalRename(c, node->committed_read_path);
#else
    (void)c;
    (void)node;
    (void)source_path;
    return false;
#endif
}

void DeferredCommitWorkerLoop(MountContext* c)
{
    if (!c)
    {
        return;
    }

    std::unique_lock<std::mutex> lock(c->deferred_commit_mutex);
    for (;;)
    {
        c->deferred_commit_cv.wait(lock, [&]()
        {
            return c->deferred_commit_thread_stop || c->deferred_commit_requested;
        });
        if (c->deferred_commit_thread_stop)
        {
            break;
        }

        const auto deadline = c->deferred_commit_deadline;
        const auto deadline_tick_ms = c->deferred_commit_deadline_tick_ms;
        if (c->deferred_commit_cv.wait_until(lock, deadline, [&]()
            {
                return c->deferred_commit_thread_stop ||
                    !c->deferred_commit_requested ||
                    c->deferred_commit_deadline != deadline;
            }))
        {
            if (c->deferred_commit_thread_stop)
            {
                break;
            }
            continue;
        }

        lock.unlock();
        const bool active_write_handles = HasOpenWriteHandles(c);
        const bool active_callbacks =
            c->active_foreground_mutation_callbacks.load(std::memory_order_acquire) > 0 ||
            MutationAdmissionCount(c->mutation_admission_state.load(std::memory_order_acquire)) > 0;
        const auto now_tick_ms = static_cast<std::uint64_t>(GetTickCount64());
        lock.lock();
        if (c->deferred_commit_thread_stop)
        {
            break;
        }
        if (!c->deferred_commit_requested || c->deferred_commit_deadline != deadline)
        {
            continue;
        }

        // WAL durability has a bounded deadline independent of APFS
        // quiescence. Flush the accepted target under the transaction/WAL
        // append serialization, then keep waiting for a safe checkpoint
        // boundary if handles or callbacks remain active.
        const auto wal_target = c->deferred_commit_requested_target;
        lock.unlock();
        bool wal_durable = true;
        {
            std::lock_guard<std::mutex> tx_lock(c->tx_mutex);
            if (c->tx_manager && wal_target != 0)
            {
                wal_durable = c->tx_manager->FlushDeferredAcceptanceDurabilityNow(wal_target);
                if (!wal_durable)
                {
                    c->tx_manager->MarkDeferredAcceptanceDurabilityFailure();
                }
            }
        }
        lock.lock();
        if (!wal_durable)
        {
            if (!c->deferred_commit_in_flight)
            {
                c->deferred_commit_in_flight = true;
                c->deferred_commit_in_flight_target = (std::max)(
                    wal_target,
                    c->deferred_commit_requested_target);
            }
            c->deferred_commit_requested = false;
            c->deferred_commit_requested_target = 0;
            c->deferred_commit_first_request_tick_ms = 0;
            c->deferred_commit_force_now = false;
            c->deferred_commit_burst_count = 0;
            c->deferred_commit_deadline_tick_ms = 0;
            lock.unlock();
            (void)LatchDeferredWalAcceptanceFailureBeforeApfsCommit(
                c,
                L"CloseDeferredWalDurability");
            lock.lock();
            continue;
        }
        if (c->deferred_commit_thread_stop)
        {
            break;
        }
        if (!c->deferred_commit_requested || c->deferred_commit_deadline != deadline)
        {
            continue;
        }
#ifdef APFSACCESS_FSHOST_UNIT_TEST
        if (c->test_pause_deferred_worker_after_wal_flush.load(std::memory_order_acquire))
        {
            c->test_deferred_worker_paused_after_wal_flush.store(true, std::memory_order_release);
            lock.unlock();
            // Keep the fault-injection pause cancellable. The old spin loop
            // ignored the production stop signal and could make a test or
            // shutdown worker appear orphaned until the harness released it.
            for (;;)
            {
                std::unique_lock<std::mutex> pause_lock(c->deferred_commit_mutex);
                c->deferred_commit_cv.wait_for(
                    pause_lock,
                    std::chrono::milliseconds(25),
                    [&]()
                    {
                        return c->test_release_deferred_worker_after_wal_flush.load(std::memory_order_acquire) ||
                            c->deferred_commit_thread_stop;
                    });
                if (c->test_release_deferred_worker_after_wal_flush.load(std::memory_order_acquire) ||
                    c->deferred_commit_thread_stop)
                {
                    break;
                }
            }
            lock.lock();
            c->test_deferred_worker_paused_after_wal_flush.store(false, std::memory_order_release);
            if (c->deferred_commit_thread_stop)
            {
                break;
            }
            if (!c->deferred_commit_requested || c->deferred_commit_deadline != deadline)
            {
                continue;
            }
        }
#endif
        c->deferred_commit_first_request_tick_ms = now_tick_ms;
        const bool age_expired =
            c->deferred_commit_first_request_tick_ms != 0 &&
            now_tick_ms >= c->deferred_commit_first_request_tick_ms &&
            now_tick_ms - c->deferred_commit_first_request_tick_ms >=
                static_cast<std::uint64_t>(kDeferredCloseCommitBurstQuietPeriod.count());
        const bool active_or_recent_foreground =
            HasActiveOrRecentForegroundMutationsAfter(c, deadline_tick_ms);
        if (active_write_handles ||
            active_callbacks ||
            (!c->deferred_commit_force_now && !age_expired && active_or_recent_foreground))
        {
            const auto quiet_period = DeferredCloseCommitQuietPeriodForBurst(
                c->deferred_commit_burst_count,
                active_write_handles);
            c->deferred_commit_deadline =
                std::chrono::steady_clock::now() +
                quiet_period;
            c->deferred_commit_deadline_tick_ms =
                static_cast<std::uint64_t>(GetTickCount64()) +
                static_cast<std::uint64_t>(quiet_period.count());
            continue;
        }

        lock.unlock();

        c->deferred_commit_worker_claim_attempt_count.fetch_add(1, std::memory_order_relaxed);
        MutationCallbackScope mutation_scope(c, false, true);

        lock.lock();
        if (c->deferred_commit_thread_stop)
        {
            break;
        }
        if (!c->deferred_commit_requested || c->deferred_commit_deadline != deadline)
        {
            continue;
        }

        if (!mutation_scope.OwnsLock())
        {
            c->deferred_commit_worker_mutex_contention_count.fetch_add(1, std::memory_order_relaxed);
            const auto retry_period = kDeferredCommitMutationMutexRetryPeriod;
            c->deferred_commit_deadline = std::chrono::steady_clock::now() + retry_period;
            c->deferred_commit_deadline_tick_ms =
                static_cast<std::uint64_t>(GetTickCount64()) +
                static_cast<std::uint64_t>(retry_period.count());
            continue;
        }

        const bool admitted_write_handles = HasOpenWriteHandles(c);
        const bool admitted_callbacks =
            c->active_foreground_mutation_callbacks.load(std::memory_order_acquire) > 0 ||
            MutationAdmissionCount(c->mutation_admission_state.load(std::memory_order_acquire)) > 0;
        if (admitted_write_handles || admitted_callbacks)
        {
            const auto retry_period = DeferredCloseCommitQuietPeriodForBurst(
                c->deferred_commit_burst_count,
                admitted_write_handles);
            c->deferred_commit_deadline = std::chrono::steady_clock::now() + retry_period;
            c->deferred_commit_deadline_tick_ms =
                static_cast<std::uint64_t>(GetTickCount64()) +
                static_cast<std::uint64_t>(retry_period.count());
            continue;
        }

        const auto publish_deferred_status =
            c->deferred_close_status_publish_pending.exchange(false, std::memory_order_acq_rel);
        c->deferred_commit_in_flight = true;
        c->deferred_commit_in_flight_target = c->deferred_commit_requested_target;
        c->deferred_commit_requested_target = 0;
        c->deferred_commit_requested = false;
        c->deferred_commit_first_request_tick_ms = 0;
        c->deferred_commit_force_now = false;
        c->deferred_commit_burst_count = 0;
        c->deferred_commit_deadline_tick_ms = 0;
        lock.unlock();
        if (publish_deferred_status)
        {
    (void)WriteHostStatusFile(*c);
        }
        c->close_commit_deferred.store(false, std::memory_order_release);

#ifdef APFSACCESS_FSHOST_UNIT_TEST
        if (c->test_throw_deferred_worker_exception_after_claim)
        {
            throw std::runtime_error("injected deferred worker failure");
        }
#endif
        const auto status = DrainNativeMutationsByPolicy(c, L"CloseDeferred");
        if (!NT_SUCCESS(status))
        {
            std::wcerr << L"[FsHost] RW native-commit warning (CloseDeferred): deferred close commit failed with status 0x"
                << std::hex << static_cast<unsigned long>(status) << std::dec
                << L"." << std::endl;
            RestoreDeferredDeleteRollbackPlans(c);
            RestoreDeferredRenameRollbackPlans(c);
            CompleteDeferredCommitBarrier(c, false, status);
            AbortMutationJournalBestEffort(c, L"CloseDeferred");
        }
        else
        {
            const auto finalized = FinalizeMutationJournalBestEffort(c, L"CloseDeferred");
            if (!finalized)
            {
                std::wcerr << L"[FsHost] RW journal warning (CloseDeferred): finalization failure was surfaced and recovery evidence was retained." << std::endl;
            }
        }
        lock.lock();
    }
}

void HandleDeferredCommitWorkerException(MountContext* c, const char* detail) noexcept
{
    if (!c)
    {
        return;
    }

    try
    {
        RestoreDeferredDeleteRollbackPlans(c);
    }
    catch (...)
    {
    }
    try
    {
        RestoreDeferredRenameRollbackPlans(c);
    }
    catch (...)
    {
    }

    try
    {
        std::lock_guard<std::recursive_mutex> runtime_lock(c->runtime_state_mutex);
        c->recovery_active = true;
        c->write_degraded = true;
        c->native_write_enabled = false;
        c->overlay_write_enabled = false;
        c->pending_native_writes = true;
        c->runtime_recovery_reason = L"DeferredCommitWorkerException";
        c->runtime_last_recovery_action = L"RetainedAfterDeferredCommitWorkerException";
    }
    catch (...)
    {
    }

    try
    {
        const auto batch = CaptureGroupedDeferredAcceptanceBatch(c);
        std::uint64_t transaction_id = 0;
        std::uint64_t accepted_sequence = 0;
        if (batch)
        {
            std::lock_guard<std::mutex> batch_lock(batch->mutex);
            transaction_id = batch->transaction_id;
            accepted_sequence = batch->initial_accepted_sequence;
        }
        if (transaction_id != 0)
        {
            (void)PublishGroupedDeferredAcceptanceResult(
                c,
                batch,
                transaction_id,
                false,
                false,
                false,
                true,
                accepted_sequence,
                STATUS_UNSUCCESSFUL);
        }
    }
    catch (...)
    {
    }

    try
    {
        (void)UpdateRecoveryMarkerBestEffort(c, true);
    }
    catch (...)
    {
    }
    try
    {
        (void)CompleteDeferredCommitBarrier(c, false, STATUS_UNSUCCESSFUL);
    }
    catch (...)
    {
    }

    try
    {
        std::lock_guard<std::mutex> lock(c->deferred_commit_mutex);
        const auto target = (std::max)(
            c->deferred_commit_in_flight_target,
            c->deferred_commit_requested_target);
        if (target != 0 &&
            (c->deferred_commit_failed_target == 0 || target < c->deferred_commit_failed_target))
        {
            c->deferred_commit_failed_target = target;
        }
        c->deferred_commit_last_status = STATUS_UNSUCCESSFUL;
        c->deferred_commit_in_flight = false;
        c->deferred_commit_in_flight_target = 0;
        c->deferred_commit_requested = false;
        c->deferred_commit_requested_target = 0;
        c->deferred_commit_first_request_tick_ms = 0;
        c->deferred_commit_force_now = false;
        c->deferred_commit_burst_count = 0;
        c->deferred_commit_deadline_tick_ms = 0;
        c->deferred_commit_thread_stop = true;
        ++c->deferred_commit_stop_generation;
    }
    catch (...)
    {
    }
    c->close_commit_deferred.store(false, std::memory_order_release);
    c->deferred_commit_cv.notify_all();

    try
    {
        (void)WriteHostStatusFile(*c);
    }
    catch (...)
    {
    }

    std::cerr << "[FsHost] RW deferred-commit worker exception: "
        << (detail ? detail : "unknown")
        << "; retained recovery evidence and blocked further writes."
        << std::endl;
}

void DeferredCommitWorkerMain(MountContext* c) noexcept
{
    try
    {
        DeferredCommitWorkerLoop(c);
    }
    catch (const std::exception& ex)
    {
        HandleDeferredCommitWorkerException(c, ex.what());
    }
    catch (...)
    {
        HandleDeferredCommitWorkerException(c, "non-standard exception");
    }

    if (c)
    {
        {
            std::lock_guard<std::mutex> lock(c->deferred_commit_mutex);
            c->deferred_commit_worker_done = true;
        }
        c->deferred_commit_cv.notify_all();
    }
}

void StartDeferredCommitWorker(MountContext* c)
{
    if (!c || !IsDeferCloseCommitsEnabled())
    {
        return;
    }

    {
        std::lock_guard<std::mutex> lock(c->deferred_commit_mutex);
        c->deferred_commit_thread_stop = false;
        c->deferred_commit_worker_done = false;
    }
    c->deferred_commit_thread = std::thread(DeferredCommitWorkerMain, c);
}

bool StopDeferredCommitWorker(MountContext* c)
{
    if (!c)
    {
        return true;
    }
    {
        std::lock_guard<std::mutex> lock(c->deferred_commit_mutex);
        c->deferred_commit_thread_stop = true;
        ++c->deferred_commit_stop_generation;
        c->deferred_commit_requested = false;
        c->deferred_commit_requested_target = 0;
        c->deferred_commit_first_request_tick_ms = 0;
        c->deferred_commit_force_now = false;
        c->deferred_commit_burst_count = 0;
        c->deferred_commit_deadline_tick_ms = 0;
    }
    c->deferred_commit_cv.notify_all();

    int stop_timeout_seconds = c->args.write_commit_timeout_seconds;
    if (stop_timeout_seconds < 1)
    {
        stop_timeout_seconds = 1;
    }
    else if (stop_timeout_seconds > 60)
    {
        stop_timeout_seconds = 60;
    }

    bool worker_stopped = !c->deferred_commit_thread.joinable();
    if (!worker_stopped)
    {
        // Wait on the native thread handle as the final deadline. The worker
        // completion flag is useful for diagnostics, but a condition-variable
        // wake does not prove that the thread has exited and is joinable.
        const auto native_thread = reinterpret_cast<HANDLE>(c->deferred_commit_thread.native_handle());
        const auto wait_result = WaitForSingleObject(
            native_thread,
            static_cast<DWORD>(stop_timeout_seconds * 1000));
        worker_stopped = wait_result == WAIT_OBJECT_0;
    }
    if (!worker_stopped)
    {
        std::wcerr << L"[FsHost] Shutdown deferred-commit worker timeout after "
            << stop_timeout_seconds
            << L"s; refusing to destroy MountContext while the worker is still active." << std::endl;
        return false;
    }

    if (c->deferred_commit_thread.joinable())
    {
        c->deferred_commit_thread.join();
    }
    {
        std::lock_guard<std::mutex> lock(c->deferred_commit_mutex);
        c->deferred_commit_worker_done = true;
    }
    // A worker may have been stopped after claiming a target but before it
    // reached the commit/finalization path. Wake waiters with a durable
    // failure rather than leaving the target permanently in flight.
    CompleteDeferredCommitBarrier(c, false, STATUS_UNSUCCESSFUL);
    {
        std::lock_guard<std::mutex> lock(c->deferred_commit_mutex);
        c->deferred_commit_thread_stop = false;
    }
    c->deferred_commit_cv.notify_all();
    c->close_commit_deferred.store(false, std::memory_order_release);
    return true;
}

bool EnsureDeferredWalAcceptanceDurableBeforeApfsCommitBestEffort(
    MountContext* c,
    const wchar_t* origin)
{
    if (!c || !c->tx_manager)
    {
        return true;
    }

    bool active_transaction = false;
    {
        std::lock_guard<std::mutex> lock(c->tx_mutex);
        const auto state = c->tx_manager->CurrentState();
        if (state == apfsaccess::rw::TransactionManager::State::Failed ||
            state == apfsaccess::rw::TransactionManager::State::Committing)
        {
            return false;
        }
        active_transaction = state == apfsaccess::rw::TransactionManager::State::Active;
    }

    if (active_transaction &&
        !AcceptMutationJournalForDeferredCommitBestEffort(c, origin))
    {
        return false;
    }

    ObservedMutexGuard lock(
        c->tx_mutex,
        &c->perf_tx_mutex_wait,
        &c->perf_tx_mutex_hold);
    auto& tx = *c->tx_manager;
    if (tx.CurrentState() != apfsaccess::rw::TransactionManager::State::Idle)
    {
        return false;
    }
    const auto target_sequence = tx.Watermarks().accepted_sequence;
    if (tx.FlushDeferredAcceptanceDurabilityNow(target_sequence))
    {
        return true;
    }

    tx.MarkDeferredAcceptanceDurabilityFailure();
    return false;
}

NTSTATUS LatchDeferredWalAcceptanceFailureBeforeApfsCommit(
    MountContext* c,
    const wchar_t* origin)
{
    if (!c)
    {
        return STATUS_MEDIA_WRITE_PROTECTED;
    }

    {
        std::lock_guard<std::recursive_mutex> runtime_lock(c->runtime_state_mutex);
        c->recovery_active = true;
        c->pending_native_writes = true;
        c->runtime_recovery_reason = L"DeferredAcceptanceDurabilityFailedBeforeCommit";
        c->runtime_last_recovery_action = L"RetainedBeforeApfsCommit";
        if (IsRecoveryPolicyFailClosed(c->args.write_recovery_policy))
        {
            c->write_degraded = true;
            c->native_write_enabled = false;
            c->overlay_write_enabled = false;
        }
    }
    std::wcerr << L"[FsHost] RW journal warning ("
        << (origin ? origin : L"commit")
        << L"): deferred WAL acceptance could not be made durable before the APFS checkpoint; writes are blocked."
        << std::endl;
    (void)UpdateRecoveryMarkerBestEffort(c, true);
    (void)WriteHostStatusFile(*c);
    CompleteDeferredCommitBarrier(c, false, STATUS_MEDIA_WRITE_PROTECTED);
    return STATUS_MEDIA_WRITE_PROTECTED;
}

NTSTATUS DrainNativeMutationsByPolicy(
    MountContext* c,
    const wchar_t* origin,
    bool has_delete_plans,
    bool namespace_boundary)
{
#ifdef APFSACCESS_HAS_RW_ENGINE
    const bool native_write_enabled = c && IsNativeWriteEnabled(c);
    if (c &&
        (c->unjournaled_native_mutation.load(std::memory_order_acquire) ||
         (!native_write_enabled && RequiresNativeApfsCheckpoint(c))))
    {
        // Accepted WAL/spool evidence is still the recovery source of truth.
        // A failed APFS commit must not be converted into a successful stale
        // marker clear or a synthetic APFS-durable watermark during shutdown.
        CompleteDeferredCommitBarrier(c, false, STATUS_MEDIA_WRITE_PROTECTED);
        return STATUS_MEDIA_WRITE_PROTECTED;
    }

    bool has_pending_mutations = false;
#ifdef APFSACCESS_FSHOST_UNIT_TEST
    if (c &&
        c->test_force_native_mutation_staging_success &&
        c->test_forced_native_commit_status.has_value())
    {
        has_pending_mutations = true;
    }
    else
#endif
    if (c && IsNativeWriteEnabled(c))
    {
        has_pending_mutations = SnapshotNativeDirtyStatus(*c).has_any_dirty_work;
    }

    const auto barrier = apfsaccess::rw::WritePipeline::RequestBarrier({
        c && IsNativeWriteEnabled(c),
        has_pending_mutations,
        has_delete_plans,
        namespace_boundary,
        origin ? std::wstring_view(origin) : std::wstring_view(),
    });
    const auto drain = apfsaccess::rw::WritePipeline::DrainNow(barrier);
    if (drain.should_commit_now && c)
    {
        RequestGroupedDeferredAcceptanceFinish(c);
    }
    if (drain.clear_stale_dirty_marker)
    {
        (void)ClearStaleNativeDirtyMarkerIfClean(c);
        return STATUS_SUCCESS;
    }
    const bool from_deferred_worker = origin && !_wcsicmp(origin, L"CloseDeferred");
    if (drain.should_commit_now && c && !from_deferred_worker &&
        !BeginDeferredCommitBarrier(c, false))
    {
        return STATUS_UNSUCCESSFUL;
    }
    if (drain.cancel_deferred_close && c)
    {
        std::lock_guard<std::mutex> lock(c->deferred_commit_mutex);
        if (!c->deferred_commit_in_flight)
        {
            c->deferred_commit_requested = false;
            c->deferred_commit_requested_target = 0;
            c->deferred_commit_first_request_tick_ms = 0;
            c->deferred_commit_force_now = false;
            c->deferred_commit_burst_count = 0;
            c->deferred_commit_deadline_tick_ms = 0;
            c->close_commit_deferred.store(false, std::memory_order_release);
        }
    }
#else
    const auto urgency = ClassifyNativeCommitRequest(c, origin, has_delete_plans, namespace_boundary);
    if (urgency == NativeCommitUrgency::None)
    {
        (void)ClearStaleNativeDirtyMarkerIfClean(c);
        return STATUS_SUCCESS;
    }
    const auto should_cancel_deferred_close =
#ifdef APFSACCESS_HAS_RW_ENGINE
        apfsaccess::rw::WritePipeline::ShouldCancelDeferredCloseBeforeDrain(urgency);
#else
        urgency != NativeCommitUrgency::None &&
        urgency != NativeCommitUrgency::FileContentCloseCanDelay;
#endif
    if (should_cancel_deferred_close)
    {
        std::lock_guard<std::mutex> lock(c->deferred_commit_mutex);
        c->deferred_commit_requested = false;
        c->deferred_commit_burst_count = 0;
        c->deferred_commit_deadline_tick_ms = 0;
        c->close_commit_deferred.store(false, std::memory_order_release);
    }
#endif

    if (!EnsureDeferredWalAcceptanceDurableBeforeApfsCommitBestEffort(c, origin))
    {
        return LatchDeferredWalAcceptanceFailureBeforeApfsCommit(c, origin);
    }

    const auto status = CommitNativeMutationsBestEffort(c, origin);
    if (!NT_SUCCESS(status) && c && !from_deferred_worker)
    {
        CompleteDeferredCommitBarrier(c, false, status);
    }
    if (NT_SUCCESS(status) && c)
    {
        bool target_pending = false;
        {
            std::lock_guard<std::mutex> lock(c->deferred_commit_mutex);
            target_pending = c->deferred_commit_in_flight &&
                c->deferred_commit_in_flight_target != 0;
        }
        if (!target_pending)
        {
            CompleteDeferredCommitBarrier(c, true, STATUS_SUCCESS);
        }
    }
    return status;
}

NTSTATUS CommitNativeMutationsOnFlushBestEffort(MountContext* c)
{
    return DrainNativeMutationsByPolicy(c, L"Flush");
}

NTSTATUS DrainDeferredNativeMutationsBeforePayloadOpen(MountContext* c, const OpenContext* open_ctx)
{
#ifdef APFSACCESS_HAS_RW_ENGINE
    if (!c ||
        !open_ctx ||
        open_ctx->named_stream ||
        !HasPayloadWriteIntent(open_ctx))
    {
        return STATUS_SUCCESS;
    }

    MutationCallbackScope mutation_scope(c);
    if (!IsMutationWriteEnabled(c) ||
        !HasPendingNativeMutations(c) ||
        HasOpenWriteHandles(c))
    {
        return STATUS_SUCCESS;
    }

    const auto status = DrainNativeMutationsByPolicy(c, L"Open");
    if (!NT_SUCCESS(status))
    {
        RestoreDeferredDeleteRollbackPlans(c);
        RestoreDeferredRenameRollbackPlans(c);
        AbortMutationJournalBestEffort(c, L"Open");
        return status;
    }
    if (!FinalizeMutationJournalBestEffort(c, L"Open"))
    {
        return c->write_degraded ? STATUS_MEDIA_WRITE_PROTECTED : STATUS_UNSUCCESSFUL;
    }
#endif
    return STATUS_SUCCESS;
}

NTSTATUS DrainDeferredDeleteRollbackBeforePathReuse(MountContext* c, const std::wstring& normalized_path, const wchar_t* origin)
{
#ifdef APFSACCESS_HAS_RW_ENGINE
    if (!c || !IsNativeWriteEnabled(c))
    {
        return STATUS_SUCCESS;
    }

    bool path_has_deferred_delete = false;
    {
        std::lock_guard<std::mutex> lock(c->mutex);
        path_has_deferred_delete = HasDeferredDeleteRollbackPlanForPathOrAncestorLocked(c, normalized_path);
    }
    if (!path_has_deferred_delete)
    {
        return STATUS_SUCCESS;
    }

    const auto drain_origin = origin && *origin ? origin : L"PathReuse";
    const auto status = DrainNativeMutationsByPolicy(c, drain_origin, true, true);
    if (!NT_SUCCESS(status))
    {
        RestoreDeferredDeleteRollbackPlans(c);
        RestoreDeferredRenameRollbackPlans(c);
        AbortMutationJournalBestEffort(c, drain_origin);
        return status;
    }

    if (!FinalizeMutationJournalBestEffort(c, drain_origin))
    {
        return c->write_degraded ? STATUS_MEDIA_WRITE_PROTECTED : STATUS_UNSUCCESSFUL;
    }
#else
    (void)c;
    (void)normalized_path;
    (void)origin;
#endif
    return STATUS_SUCCESS;
}

NTSTATUS DrainDeferredDeleteRollbackBeforeNamespaceMutation(
    MountContext* c,
    const wchar_t* origin)
{
#ifdef APFSACCESS_HAS_RW_ENGINE
    if (!c || !IsNativeWriteEnabled(c))
    {
        return STATUS_SUCCESS;
    }

    bool has_deferred_delete_plans = false;
    {
        std::lock_guard<std::mutex> lock(c->mutex);
        has_deferred_delete_plans = !c->deferred_delete_rollback_plans.empty();
    }
    if (!has_deferred_delete_plans)
    {
        return STATUS_SUCCESS;
    }

    const auto drain_origin = origin && *origin ? origin : L"NamespaceMutation";
    const auto status = DrainNativeMutationsByPolicy(c, drain_origin, true, true);
    if (!NT_SUCCESS(status))
    {
        RestoreDeferredDeleteRollbackPlans(c);
        RestoreDeferredRenameRollbackPlans(c);
        AbortMutationJournalBestEffort(c, drain_origin);
        return status;
    }

    if (!FinalizeMutationJournalBestEffort(c, drain_origin))
    {
        return c->write_degraded ? STATUS_MEDIA_WRITE_PROTECTED : STATUS_UNSUCCESSFUL;
    }
#else
    (void)c;
    (void)origin;
#endif
    return STATUS_SUCCESS;
}

void RetainJournalFinalizationFailureState(MountContext* c)
{
    if (!c)
    {
        return;
    }

    {
        std::lock_guard<std::recursive_mutex> runtime_lock(c->runtime_state_mutex);
        c->recovery_active = true;
        c->pending_native_writes = true;
        c->runtime_recovery_reason = L"JournalFinalizationFailed";
        c->runtime_last_recovery_action = L"RetainedAfterJournalFinalizationFailure";
        if (IsRecoveryPolicyFailClosed(c->args.write_recovery_policy))
        {
            c->write_degraded = true;
            c->native_write_enabled = false;
            c->overlay_write_enabled = false;
        }
    }
    (void)UpdateRecoveryMarkerBestEffort(c, true);
}

bool FinalizeMutationJournalBestEffort(MountContext* c, const wchar_t* origin)
{
    ScopedPerfTimer cleanup_stage_scope(c ? &c->perf_cleanup_stage : nullptr);
    if (c && c->args.readwrite &&
        (c->unjournaled_native_mutation.load(std::memory_order_acquire) ||
         (!IsNativeWriteEnabled(c) && RequiresNativeApfsCheckpoint(c))))
    {
        // No APFS checkpoint has been proven for this accepted boundary. Keep
        // WAL/spool evidence intact and force the caller to report failure.
        CompleteDeferredCommitBarrier(c, false, STATUS_MEDIA_WRITE_PROTECTED);
        return false;
    }

    std::uint64_t committed_sequence = 0;
    std::uint64_t transaction_id = 0;
    bool can_skip_payload_spool_flush = false;
    bool finalization_coverage_valid = true;
    if (c && c->tx_manager && IsInlineAcceptancePayloadEnabled())
    {
        std::lock_guard<std::mutex> lock(c->tx_mutex);
        can_skip_payload_spool_flush = c->tx_manager->CanFinalizeWithoutPayloadSpoolFlush(
            IsFinalizationCoverageCacheEnabled());
        finalization_coverage_valid = c->tx_manager->RecoveryStateValid();
    }
    if (!finalization_coverage_valid)
    {
        std::wcerr << L"[FsHost] RW journal warning: WAL validation failed before finalization during "
                   << origin << L"." << std::endl;
        RetainJournalFinalizationFailureState(c);
        DiscardDeferredDeleteRollbackPlans(c);
        DiscardDeferredRenameRollbackPlans(c);
        const auto completed_deferred_barrier = CompleteDeferredCommitBarrier(
            c,
            false,
            STATUS_UNSUCCESSFUL);
        if (c && !completed_deferred_barrier)
        {
            (void)WriteHostStatusFile(*c);
        }
        return false;
    }
    if (!can_skip_payload_spool_flush &&
        !FlushPayloadSpoolDirtyStateBestEffort(c, origin))
    {
        DiscardDeferredDeleteRollbackPlans(c);
        DiscardDeferredRenameRollbackPlans(c);
        AbortMutationJournalBestEffort(c, origin);
        CompleteDeferredCommitBarrier(c, false, STATUS_UNSUCCESSFUL);
        return false;
    }
    const auto grouped_acceptance_batch = CaptureGroupedDeferredAcceptanceBatch(c);
    const auto finalized = CommitMutationJournalBestEffort(
        c,
        &committed_sequence,
        &transaction_id);
    bool cleaned = finalized;
    bool cleanup_marked = finalized;
    if (!finalized)
    {
        std::wcerr << L"[FsHost] RW journal warning: failed to finalize transaction journal during " << origin << L"." << std::endl;
        RetainJournalFinalizationFailureState(c);
    }
    else
    {
        cleaned = CleanupPayloadSpoolAfterCheckpointBestEffort(c, committed_sequence);
        if (cleaned && c && c->tx_manager)
        {
            std::lock_guard<std::mutex> lock(c->tx_mutex);
            const auto watermarks = c->tx_manager->Watermarks();
            if (watermarks.apfs_durable_sequence >= committed_sequence &&
                watermarks.cleanup_sequence < committed_sequence)
            {
                cleanup_marked = c->tx_manager->MarkCleanedThrough(committed_sequence);
            }
        }
        if (cleaned && cleanup_marked)
        {
            RemoveStaleHydrationFilesAfterCheckpointBestEffort(c);
        }
        else
        {
            std::wcerr << L"[FsHost] RW journal warning: APFS checkpoint is durable but payload cleanup watermark was not completed during "
                << origin << L"." << std::endl;
            if (c)
            {
                {
                    std::lock_guard<std::recursive_mutex> runtime_lock(c->runtime_state_mutex);
                    c->recovery_active = true;
                    c->runtime_recovery_reason = L"PayloadSpoolCleanupFailed";
                    c->runtime_last_recovery_action = L"RetainedAfterPayloadSpoolCleanupFailure";
                    if (IsRecoveryPolicyFailClosed(c->args.write_recovery_policy))
                    {
                        c->write_degraded = true;
                        c->native_write_enabled = false;
                        c->overlay_write_enabled = false;
                    }
                }
                (void)UpdateRecoveryMarkerBestEffort(c, true);
            }
        }
    }
    DiscardDeferredDeleteRollbackPlans(c);
    DiscardDeferredRenameRollbackPlans(c);
    const auto success = finalized && cleaned && cleanup_marked;
    bool barrier_effective_success = success;
    const auto completed_deferred_barrier = CompleteDeferredCommitBarrier(
        c,
        success,
        success ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL,
        &barrier_effective_success);
    const auto finalization_success = success &&
        (!completed_deferred_barrier || barrier_effective_success);
    if (completed_deferred_barrier && success && !barrier_effective_success && c)
    {
        {
            std::lock_guard<std::recursive_mutex> runtime_lock(c->runtime_state_mutex);
            c->recovery_active = true;
            c->pending_native_writes = true;
            c->runtime_recovery_reason = L"DeferredCommitDurabilityNotReached";
            c->runtime_last_recovery_action = L"RetainedAfterDeferredCommitDurabilityFailure";
            if (IsRecoveryPolicyFailClosed(c->args.write_recovery_policy))
            {
                c->write_degraded = true;
                c->native_write_enabled = false;
                c->overlay_write_enabled = false;
            }
        }
        (void)UpdateRecoveryMarkerBestEffort(c, true);
        (void)WriteHostStatusFile(*c);
    }
    CompleteGroupedDeferredAcceptanceAfterBoundary(
        c,
        grouped_acceptance_batch,
        transaction_id,
        committed_sequence,
        finalization_success);
    if (c && finalization_success)
    {
        (void)ClearStaleNativeDirtyMarkerIfClean(c);
    }
    else if (c && !completed_deferred_barrier)
    {
        (void)WriteHostStatusFile(*c);
    }
    InvalidatePayloadIdentityCache(c);
    return finalization_success;
}

void AbortMutationJournalBestEffort(MountContext* c, const wchar_t* origin)
{
    if (!c || !c->tx_manager)
    {
        return;
    }

    InvalidatePayloadIdentityCache(c);

    const auto grouped_acceptance_batch = CaptureGroupedDeferredAcceptanceBatch(c);
    bool aborted = false;
    std::uint64_t transaction_id = 0;
    {
        std::lock_guard<std::mutex> lock(c->tx_mutex);
        const auto state = c->tx_manager->CurrentState();
        if (state != apfsaccess::rw::TransactionManager::State::Idle)
        {
            transaction_id = c->tx_manager->CurrentTransactionId();
            aborted = c->tx_manager->Abort();
        }
    }

    if (!aborted)
    {
        std::wcerr << L"[FsHost] RW journal warning: failed to abort transaction journal during " << origin << L"." << std::endl;
    }
    if (transaction_id != 0)
    {
        CompleteGroupedDeferredAcceptanceAfterBoundary(
            c,
            grouped_acceptance_batch,
            transaction_id,
            0,
            false);
    }
}

int RunFsHostShutdownDrain(MountContext* c)
{
    if (!c)
    {
        return ResolveFsHostShutdownExitCode(false, STATUS_UNSUCCESSFUL, false);
    }

    WriteShutdownStageFile(*c, "begin-callback-drain");
    const auto callback_drain_ok = BeginMutationShutdownDrain(c);
    WriteShutdownStageFile(*c, callback_drain_ok
        ? "callback-drain-complete"
        : "callback-drain-timeout");
#ifdef APFSACCESS_HAS_RW_ENGINE
    WriteShutdownStageFile(*c, "begin-deferred-worker-stop");
    const auto deferred_worker_stop_ok = StopDeferredCommitWorker(c);
    if (!deferred_worker_stop_ok)
    {
        WriteShutdownStageFile(*c, "deferred-worker-stop-timeout");
        // The worker still owns MountContext. Terminate the host rather than
        // destroying the context or detaching a thread that can use it.
        AwaitExternalGuardianTermination();
    }
    WriteShutdownStageFile(*c, "deferred-worker-stop-complete");
#endif
    NTSTATUS shutdown_commit_status = STATUS_SUCCESS;
    bool journal_finalize_ok = true;
#ifdef APFSACCESS_HAS_RW_ENGINE
    if (callback_drain_ok && ShouldRunNativeShutdownFinalDrain(*c))
    {
        shutdown_commit_status = DrainNativeMutationsByPolicy(c, L"Shutdown");
        if (!NT_SUCCESS(shutdown_commit_status))
        {
            RestoreDeferredDeleteRollbackPlans(c);
            RestoreDeferredRenameRollbackPlans(c);
        }
        if (NT_SUCCESS(shutdown_commit_status))
        {
            journal_finalize_ok = FinalizeMutationJournalBestEffort(c, L"Shutdown");
        }
        else
        {
            AbortMutationJournalBestEffort(c, L"Shutdown");
        }
    }
#endif
    c->mount_ready.store(false, std::memory_order_release);
    const auto terminal_status_ok = WriteTerminalMountNotReadyStatusFile(*c);
    WriteShutdownStageFile(*c, "begin-winfsp-stop");
    TeardownWinFspFileSystemOwned(c);

    const auto shutdown_exit = ResolveFsHostShutdownExitCode(
        callback_drain_ok,
        shutdown_commit_status,
        journal_finalize_ok);
    return !terminal_status_ok && shutdown_exit == 0 ? 12 : shutdown_exit;
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

        std::wstring previous_reason;
        bool previous_recovery = false;
        {
            std::lock_guard<std::recursive_mutex> runtime_lock(c->runtime_state_mutex);
            previous_reason = c->runtime_recovery_reason;
            previous_recovery = c->recovery_active;
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
        (void)WriteHostStatusFile(*c);
    }
#else
    (void)operation;
#endif

    return STATUS_MEDIA_WRITE_PROTECTED;
}

std::shared_ptr<Node> EnsureDirectoryLoadedNodeNormalized(MountContext* c, const std::wstring& path)
{
    if (!c)
    {
        return {};
    }
    auto node = FindNodeNormalized(c, path);
    if (!node || !node->is_directory)
    {
        return {};
    }
    return EnsureDirectoryLoaded(c, node) ? node : std::shared_ptr<Node>{};
}

std::shared_ptr<Node> EnsureParentDirectoryLoadedNodeNormalized(MountContext* c, const std::wstring& path)
{
    return EnsureDirectoryLoadedNodeNormalized(c, ParentOfNormalizedPath(path));
}

bool EnsureParentDirectoryLoadedNormalized(MountContext* c, const std::wstring& path)
{
    return static_cast<bool>(EnsureParentDirectoryLoadedNodeNormalized(c, path));
}

bool EnsureParentDirectoryLoaded(MountContext* c, const std::wstring& path)
{
    return EnsureParentDirectoryLoadedNormalized(c, NormalizePath(path));
}

bool CanRemoveNodeRecursiveLocked(MountContext* c, const std::shared_ptr<Node>& node, bool allow_open_file_node = false)
{
#ifdef APFSACCESS_FSHOST_UNIT_TEST
    ++g_can_remove_node_visit_count_for_test;
#endif
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
        auto child = TryGetChildNodeLocked(c, node, child_name);
        if (child && !CanRemoveNodeRecursiveLocked(c, child, false))
        {
            return false;
        }
    }
    return true;
}

bool CollectRemovableNodePostorderLocked(
    MountContext* c,
    const std::shared_ptr<Node>& node,
    std::vector<std::shared_ptr<Node>>& postorder,
    bool allow_open_file_node = false)
{
#ifdef APFSACCESS_FSHOST_UNIT_TEST
    ++g_can_remove_node_visit_count_for_test;
#endif
    if (!c || !node)
    {
        return false;
    }
    if (node->open_handle_count != 0 && !(allow_open_file_node && !node->is_directory))
    {
        return false;
    }
    if (node->is_directory)
    {
        for (const auto& child_name : node->children)
        {
            auto child = TryGetChildNodeLocked(c, node, child_name);
            if (child &&
                !CollectRemovableNodePostorderLocked(c, child, postorder, false))
            {
                return false;
            }
        }
    }

    postorder.push_back(node);
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
        const auto is_descendant = IsDescendantPathNormalized(candidate->path, source->path);
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

bool RemoveNodeRecursiveValidatedLocked(MountContext* c, const std::shared_ptr<Node>& node)
{
    if (!c || !node)
    {
        return false;
    }
    if (node->is_directory)
    {
        for (const auto& child_name : node->children)
        {
#ifdef APFSACCESS_FSHOST_UNIT_TEST
            ++g_remove_node_child_lookup_count_for_test;
#endif
            auto child = TryGetChildNodeLocked(c, node, child_name);
            if (child)
            {
                RemoveNodeRecursiveValidatedLocked(c, child);
            }
        }
    }
    if (!node->is_directory)
    {
        InvalidateHydrationReadHandle(c);
        std::error_code ec;
        std::filesystem::remove(HydrationPath(c, *node), ec);
        ForgetNamedStreamsLocked(c, node->path);
        ClearHydrationStaleLockedNormalized(c, node->path);
    }
    const auto removed_path = node->path;
    EraseIndexedNodeLocked(c, node);
    MarkAncestorChildDeleteLockedNormalized(c, removed_path);
    return true;
}

bool RemoveNodePostorderValidatedLocked(
    MountContext* c,
    const std::vector<std::shared_ptr<Node>>& postorder,
    const std::shared_ptr<Node>& preserved_hydration_node = nullptr,
    const std::unordered_set<std::wstring>* preserved_hydration_keys = nullptr)
{
    if (!c)
    {
        return false;
    }

    for (const auto& node : postorder)
    {
        if (!node)
        {
            return false;
        }
        if (!node->is_directory)
        {
            const auto preserve_file_hydration =
                node == preserved_hydration_node ||
                (preserved_hydration_keys &&
                    preserved_hydration_keys->find(NodePathKey(*node)) != preserved_hydration_keys->end());
            if (!preserve_file_hydration)
            {
                InvalidateHydrationReadHandle(c);
                std::error_code ec;
                std::filesystem::remove(HydrationPath(c, *node), ec);
            }
            ForgetNamedStreamsLocked(c, node->path);
            ClearHydrationStaleLockedNormalized(c, node->path);
        }
        EraseIndexedNodeLocked(c, node);
    }

    if (!postorder.empty() && postorder.back())
    {
        MarkAncestorChildDeleteLockedNormalized(c, postorder.back()->path);
    }

    return true;
}

bool RemoveNodeRecursiveLocked(MountContext* c, const std::shared_ptr<Node>& node, bool allow_open_file_node = false)
{
    if (!CanRemoveNodeRecursiveLocked(c, node, allow_open_file_node))
    {
        return false;
    }

    return RemoveNodeRecursiveValidatedLocked(c, node);
}

std::shared_ptr<Node> FindRemovableDeferredDirectoryDeleteLockedNormalized(MountContext* c, const std::wstring& child_path)
{
    if (!c || child_path == L"\\")
    {
        return {};
    }

    auto cursor = ParentOfNormalizedPath(child_path);
    while (cursor != L"\\")
    {
        auto candidate = TryGetNodeLockedNormalized(c, cursor);
        if (candidate &&
            candidate->is_directory &&
            candidate->delete_requested_after_children &&
            !candidate->caller_delete_retry_required)
        {
            if (candidate->open_handle_count == 0 &&
                CanRemoveNodeRecursiveLocked(c, candidate))
            {
                return candidate;
            }
            return {};
        }

        auto next = ParentOfNormalizedPath(cursor);
        if (next == cursor)
        {
            break;
        }
        cursor = std::move(next);
    }

    return {};
}

std::shared_ptr<Node> FindRemovableDeferredDirectoryDeleteLocked(MountContext* c, const std::wstring& child_path)
{
    return FindRemovableDeferredDirectoryDeleteLockedNormalized(c, NormalizePath(child_path));
}

std::shared_ptr<Node> FindRemovableDeferredDirectoryDeletePostorderLocked(
    MountContext* c,
    const std::wstring& child_path,
    std::vector<std::shared_ptr<Node>>& postorder)
{
    postorder.clear();
    if (!c || child_path == L"\\")
    {
        return {};
    }

    auto cursor = ParentOfNormalizedPath(child_path);
    while (cursor != L"\\")
    {
        auto candidate = TryGetNodeLockedNormalized(c, cursor);
        if (candidate &&
            candidate->is_directory &&
            candidate->delete_requested_after_children &&
            !candidate->caller_delete_retry_required)
        {
            if (candidate->open_handle_count == 0 &&
                CollectRemovableNodePostorderLocked(c, candidate, postorder))
            {
                return candidate;
            }
            postorder.clear();
            return {};
        }

        auto next = ParentOfNormalizedPath(cursor);
        if (next == cursor)
        {
            break;
        }
        cursor = std::move(next);
    }

    return {};
}

bool TryFastCloseNonMutatingContext(MountContext* c, OpenContext* o)
{
    if (!c ||
        !o ||
        !o->node ||
        !IsMutationWriteEnabled(c) ||
        o->named_stream ||
        o->mutation_observed.load(std::memory_order_acquire) ||
        o->delete_on_cleanup ||
        o->delete_on_close_requested)
    {
        return false;
    }
    if (o->file != INVALID_HANDLE_VALUE)
    {
        CloseHandle(o->file);
        o->file = INVALID_HANDLE_VALUE;
    }

    std::lock_guard<std::mutex> lock(c->mutex);
    if (IsDeleteBlockedStateLocked(o->node) ||
        o->node->delete_requested_after_children ||
        HasDeletePendingAncestorLockedNormalized(c, o->node->path) ||
        FindRemovableDeferredDirectoryDeleteLockedNormalized(c, o->node->path))
    {
        return false;
    }

    ReleaseOpenContextAccountingLocked(c, o);
    return true;
}

void RestoreNodeRecursiveLocked(MountContext* c, const std::shared_ptr<Node>& node)
{
    if (!c || !node)
    {
        return;
    }

    IndexNodeLocked(c, node);
    if (node->path != L"\\")
    {
        auto parent = TryGetNodeLockedNormalized(c, ParentOfNormalizedPath(node->path));
        if (parent && parent->is_directory)
        {
            AddChildName(*parent, LeafNameOfNormalizedPath(node->path));
        }
    }

    if (!node->is_directory)
    {
        return;
    }

    for (const auto& child_name : node->children)
    {
        auto child = TryGetNodeLockedNormalized(c, JoinFromNormalizedPath(node->path, child_name));
        if (!child)
        {
            continue;
        }

        RestoreNodeRecursiveLocked(c, child);
    }
}

bool ReindexNodePathsLocked(MountContext* c, const std::shared_ptr<Node>& node, const std::wstring& old_path, const std::wstring& new_path)
{
    if (!c || !node)
    {
        return false;
    }

    InvalidateHydrationReadHandle(c);

    const auto old_key = LowerPathKey(old_path);
    const auto new_key = LowerPathKey(new_path);
    const auto old_hydration_key = node->hydration_key;
    const auto target_hydration_key =
        (node->hydration_key.empty() || node->hydration_key == old_key)
            ? new_key
            : node->hydration_key;

    if (!node->is_directory)
    {
        std::error_code ec;
        Node old_node{};
        old_node.path = old_path;
        old_node.hydration_key = old_hydration_key.empty() ? old_key : old_hydration_key;
        Node new_node{};
        new_node.path = new_path;
        new_node.hydration_key = target_hydration_key;
        auto old_h = HydrationPath(c, old_node);
        auto new_h = HydrationPath(c, new_node);
        if (old_h != new_h && std::filesystem::exists(old_h, ec))
        {
            std::filesystem::create_directories(new_h.parent_path(), ec);
            if (std::filesystem::exists(new_h, ec))
            {
                std::filesystem::remove(new_h, ec);
                if (ec)
                {
                    return false;
                }
            }
            std::filesystem::rename(old_h, new_h, ec);
            if (ec)
            {
                ec.clear();
                std::filesystem::copy_file(old_h, new_h, std::filesystem::copy_options::overwrite_existing, ec);
                if (ec)
                {
                    return false;
                }
                else
                {
                    std::filesystem::remove(old_h, ec);
                }
            }
        }
    }

    if (auto current = c->nodes.find(old_key); current != c->nodes.end())
    {
        c->nodes.erase(current);
    }

    node->hydration_key = target_hydration_key;
    SetNodePathNormalized(*node, new_path);
    IndexNodeLocked(c, node);

    if (!node->is_directory)
    {
        auto stream_map = c->named_stream_sizes.find(old_key);
        if (stream_map != c->named_stream_sizes.end())
        {
            auto streams = std::move(stream_map->second);
            c->named_stream_sizes.erase(stream_map);
            c->named_stream_sizes[new_key] = std::move(streams);
        }
        if (auto stale = c->stale_hydration_keys.find(old_key);
            stale != c->stale_hydration_keys.end())
        {
            c->stale_hydration_keys.erase(stale);
            c->stale_hydration_keys.insert(new_key);
        }
    }

    if (!node->is_directory)
    {
        return true;
    }

    for (const auto& child_name : node->children)
    {
        auto child_old_path = JoinFromNormalizedPath(old_path, child_name);
        auto child_new_path = JoinFromNormalizedPath(new_path, child_name);
        auto child = TryGetChildNodeByParentKeyLocked(c, old_key, old_path, child_name);
        if (child)
        {
            if (!ReindexNodePathsLocked(c, child, child_old_path, child_new_path))
            {
                return false;
            }
        }
    }
    return true;
}

void RollbackRenameLocalStateLocked(MountContext* c, const RenameLocalSnapshot& snapshot)
{
    if (!c || !snapshot.node || !snapshot.node_reindexed)
    {
        return;
    }

    (void)ReindexNodePathsLocked(c, snapshot.node, snapshot.new_path, snapshot.old_path);
    snapshot.node->hydration_key = snapshot.old_hydration_key;
    snapshot.node->committed_read_path = snapshot.old_committed_read_path;
    snapshot.node->timestamp = snapshot.old_timestamp;
    for (const auto& entry : snapshot.descendant_committed_read_paths)
    {
        if (entry.node)
        {
            entry.node->committed_read_path = entry.old_committed_read_path;
        }
    }
    if (snapshot.old_parent && snapshot.old_parent->is_directory)
    {
        AddChildName(*snapshot.old_parent, snapshot.old_leaf);
    }
    if (snapshot.new_parent && snapshot.new_parent->is_directory)
    {
        RemoveChildName(*snapshot.new_parent, snapshot.new_leaf);
    }

    if (snapshot.replaced_node_was_present && snapshot.replaced_node)
    {
        RestoreNodeRecursiveLocked(c, snapshot.replaced_node);
        RestoreFileRollbackSnapshotLocked(c, snapshot.replaced_file_snapshot);
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
    ScopedCallbackActivity callback_scope(c, "GetVolumeInfo");
    ScopedPerfTimer perf_scope(c ? &c->perf_get_volume_info : nullptr);
    if (!c || !v) return STATUS_INVALID_PARAMETER;
    std::memset(v, 0, sizeof(*v));
    const auto reported_volume_info = CaptureReportedVolumeInfo(*c);
    std::optional<std::uint64_t> total_size = reported_volume_info.total_size_bytes;
    std::optional<std::uint64_t> free_size = reported_volume_info.free_size_bytes;
    std::uint64_t allocation_unit = reported_volume_info.allocation_unit_bytes != 0
        ? reported_volume_info.allocation_unit_bytes
        : 4096;

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

NTSTATUS CB_SetVolumeLabel(FSP_FILE_SYSTEM* fs, PWSTR, FSP_FSCTL_VOLUME_INFO*)
{
    auto* c = Ctx(fs);
    ScopedCallbackActivity callback_scope(c, "SetVolumeLabel");
    ScopedPerfTimer perf_scope(c ? &c->perf_set_volume_label : nullptr);
    return STATUS_MEDIA_WRITE_PROTECTED;
}

NTSTATUS CB_GetStreamInfo(FSP_FILE_SYSTEM* fs, PVOID ctx, PVOID buffer, ULONG length, PULONG transferred)
{
    auto* c = Ctx(fs);
    ScopedCallbackActivity callback_scope(c, "GetStreamInfo");
    ScopedPerfTimer perf_scope(c ? &c->perf_get_stream_info : nullptr);
    if (!buffer || !transferred)
    {
        return STATUS_INVALID_PARAMETER;
    }

    *transferred = 0;
    auto* o = static_cast<OpenContext*>(ctx);
    if (!c || !o || !o->node)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (o->node->is_directory)
    {
        return STATUS_SUCCESS;
    }

    const auto add_stream_info = [&](FSP_FSCTL_STREAM_INFO* stream_info) -> bool
    {
#ifdef APFSACCESS_FSHOST_UNIT_TEST
        if (!stream_info)
        {
            return true;
        }
        if (stream_info->Size == 0 ||
            stream_info->Size < sizeof(FSP_FSCTL_STREAM_INFO) ||
            stream_info->Size > (std::numeric_limits<ULONG>::max() - *transferred) ||
            *transferred > length ||
            stream_info->Size > (length - *transferred))
        {
            return false;
        }

        std::memcpy(static_cast<std::byte*>(buffer) + *transferred, stream_info, stream_info->Size);
        *transferred += stream_info->Size;
        return true;
#else
        if (!c->api.AddStream)
        {
            return false;
        }
        return !!c->api.AddStream(stream_info, buffer, length, transferred);
#endif
    };

    const auto add_named_stream = [&](const std::wstring& stream_name, std::uint64_t stream_size) -> bool
    {
        const auto name_bytes = stream_name.size() * sizeof(WCHAR);
        const auto entry_size = sizeof(FSP_FSCTL_STREAM_INFO) + name_bytes;
        if (entry_size > static_cast<std::size_t>(std::numeric_limits<UINT16>::max()))
        {
            return false;
        }

        std::vector<std::byte> stream_storage(entry_size);
        auto* stream_info = reinterpret_cast<FSP_FSCTL_STREAM_INFO*>(stream_storage.data());
        stream_info->Size = static_cast<UINT16>(entry_size);
        stream_info->StreamSize = stream_size;
        stream_info->StreamAllocationSize = ((stream_size + 4095ull) / 4096ull) * 4096ull;
        if (name_bytes > 0)
        {
            std::memcpy(stream_info->StreamNameBuf, stream_name.data(), name_bytes);
        }

        return add_stream_info(stream_info);
    };

    if (!add_named_stream(L"::$DATA", o->node->file_size))
    {
        return STATUS_BUFFER_OVERFLOW;
    }

    std::vector<std::pair<std::wstring, std::uint64_t>> streams;
    {
        std::lock_guard<std::mutex> lock(c->mutex);
        const auto stream_bucket = c->named_stream_sizes.find(NodePathKey(*o->node));
        if (stream_bucket != c->named_stream_sizes.end())
        {
            for (const auto& [stream_name, stream_size] : stream_bucket->second)
            {
                streams.emplace_back(CanonicalStreamName(stream_name), stream_size);
            }
        }
    }

    for (const auto& [stream_name, stream_size] : streams)
    {
        if (!add_named_stream(stream_name, stream_size))
        {
            return STATUS_BUFFER_OVERFLOW;
        }
    }

    if (!add_stream_info(nullptr))
    {
        return STATUS_BUFFER_OVERFLOW;
    }

    return STATUS_SUCCESS;
}

void ConfigureVolumeParamsForExplorer(MountContext& ctx, const FILETIME& now, FSP_FSCTL_VOLUME_PARAMS& vp)
{
    const auto reported_volume_info = CaptureReportedVolumeInfo(ctx);
    vp = {};
    vp.Version = sizeof(FSP_FSCTL_VOLUME_PARAMS);
    vp.SectorSize = static_cast<UINT16>(reported_volume_info.allocation_unit_bytes != 0
        ? reported_volume_info.allocation_unit_bytes
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
    vp.StreamInfoTimeoutValid = 1;
    vp.StreamInfoTimeout = 2000;
    vp.CaseSensitiveSearch = 0;
    vp.CasePreservedNames = 1;
    vp.UnicodeOnDisk = 1;
    vp.PersistentAcls = 0;
    vp.NamedStreams = 1;
    vp.SupportsPosixUnlinkRename = 1;
    vp.ReadOnlyVolume = IsMutationWriteEnabled(&ctx) ? 0 : 1;
    vp.PostCleanupWhenModifiedOnly = 0;
    vp.FlushAndPurgeOnCleanup = 1;
    vp.PostDispositionWhenNecessaryOnly = 0;
    vp.UmFileContextIsUserContext2 = 1;
    wcscpy_s(vp.FileSystemName, sizeof(vp.FileSystemName) / sizeof(WCHAR), L"APFS");
}

NTSTATUS CB_Create(FSP_FILE_SYSTEM* fs, PWSTR file_name, UINT32 create_options, UINT32 granted_access, UINT32, PSECURITY_DESCRIPTOR, UINT64, PVOID* out_ctx, FSP_FSCTL_FILE_INFO* info)
{
    auto* c = Ctx(fs);
    ScopedCallbackActivity callback_scope(c, "Create");
    ScopedPerfTimer perf_scope(c ? &c->perf_create : nullptr);

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
    auto stream_path = SplitNamedStreamPathNormalized(path);
    if (stream_path.is_named_stream)
    {
        if (!IsValidNormalizedWin32PathForMutation(stream_path.base_path))
        {
            return STATUS_OBJECT_NAME_INVALID;
        }
        if ((create_options & FILE_DIRECTORY_FILE) != 0)
        {
            return STATUS_NOT_A_DIRECTORY;
        }

        auto base_node = FindNode(c, stream_path.base_path);
        if (!base_node)
        {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
        if (IsDeleteBlockedStateLocked(base_node))
        {
            return STATUS_DELETE_PENDING;
        }
        if (base_node->is_directory)
        {
            return STATUS_FILE_IS_A_DIRECTORY;
        }
        if (!EnsureHydrationSidecarExistsForNamedStream(c, base_node))
        {
            return STATUS_UNSUCCESSFUL;
        }

        auto* o = new (std::nothrow) OpenContext();
        if (!o)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        o->node = base_node;
        o->named_stream = true;
        o->stream_name = stream_path.stream_name;
        InitializeOpenAccess(o, granted_access);
        o->write_open = true;
        const auto desired_access = ResolveHydrationDesiredAccess(
            IsMutationWriteEnabled(c),
            granted_access,
            true);
        const auto stream_storage_path = HydrationStreamPath(c, *base_node, stream_path.stream_name);
        o->file = CreateFileW(
            stream_storage_path.c_str(),
            desired_access,
            ResolveHydrationShareMode(IsMutationWriteEnabled(c), granted_access, o->write_open),
            nullptr,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (o->file == INVALID_HANDLE_VALUE)
        {
            delete o;
            return STATUS_UNSUCCESSFUL;
        }

        {
            std::lock_guard<std::mutex> lock(c->mutex);
            AcquireOpenContextAccountingLocked(c, base_node, o);
            o->stream_size = RememberNamedStreamSizeFromHandleLocked(c, base_node, stream_path.stream_name, o->file);
            FillInfo(*base_node, !IsMutationWriteEnabled(c), info);
        }

        *out_ctx = o;
        MarkOpenContextMutation(o);
        return STATUS_SUCCESS;
    }

    if (path == L"\\")
    {
        return STATUS_OBJECT_NAME_COLLISION;
    }
    if (!IsValidNormalizedWin32PathForMutation(path))
    {
        return STATUS_OBJECT_NAME_INVALID;
    }

    // A new namespace entry has no deferred-create rollback plan. Drain any
    // queued file-delete evidence before staging it, even when the target is
    // unrelated to the deleted paths.
    const auto namespace_delete_status =
        DrainDeferredDeleteRollbackBeforeNamespaceMutation(c, L"Create");
    if (!NT_SUCCESS(namespace_delete_status))
    {
        return namespace_delete_status;
    }

    const auto path_reuse_status = DrainDeferredDeleteRollbackBeforePathReuse(c, path, L"Create");
    if (!NT_SUCCESS(path_reuse_status))
    {
        return path_reuse_status;
    }

    auto parent_path = ParentOfNormalizedPath(path);
    auto parent_node = EnsureDirectoryLoadedNodeNormalized(c, parent_path);
    if (!parent_node)
    {
        std::lock_guard<std::mutex> lock(c->mutex);
        if (HasDeletePendingAncestorLockedNormalized(c, path))
        {
            return STATUS_DELETE_PENDING;
        }

        auto hidden_parent = TryGetNodeLockedNormalized(c, parent_path);
        if (IsDeleteBlockedStateLocked(hidden_parent))
        {
            return STATUS_DELETE_PENDING;
        }
        return STATUS_OBJECT_PATH_NOT_FOUND;
    }

    auto parent_name_pos = path.find_last_of(L'\\');
    auto name = parent_name_pos == std::wstring::npos ? path : path.substr(parent_name_pos + 1);
    if (name.empty())
    {
        return STATUS_OBJECT_NAME_INVALID;
    }

    const bool request_directory = (create_options & FILE_DIRECTORY_FILE) != 0;
    const bool request_non_directory = (create_options & FILE_NON_DIRECTORY_FILE) != 0;

    std::shared_ptr<Node> node;
    {
        std::lock_guard<std::mutex> lock(c->mutex);
        if (TryGetVisibleNodeLockedNormalized(c, parent_path) != parent_node || !parent_node->is_directory)
        {
            if (HasDeletePendingAncestorLockedNormalized(c, parent_path) ||
                IsDeleteBlockedStateLocked(TryGetNodeLockedNormalized(c, parent_path)))
            {
                return STATUS_DELETE_PENDING;
            }
            return STATUS_OBJECT_PATH_NOT_FOUND;
        }
#ifdef APFSACCESS_FSHOST_UNIT_TEST
        ++g_create_parent_reuse_count_for_test;
#endif
        if (HasDeletePendingAncestorLockedNormalized(c, path))
        {
            return STATUS_DELETE_PENDING;
        }

        auto existing = TryGetNodeLockedNormalized(c, path);
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
        SetNodePathNormalized(*node, path);
        node->apfs_path.clear();
        node->hydration_key = node->path_key;
        node->is_directory = request_directory;
        node->file_size = 0;
        node->timestamp = UtcNow();
        node->loaded = request_directory;
        EmplaceNodeLocked(c, node);
        AddChildName(*parent_node, name);
    }

    auto* o = new (std::nothrow) OpenContext();
    if (!o)
    {
        std::lock_guard<std::mutex> lock(c->mutex);
        RemoveChildName(*parent_node, name);
        EraseIndexedNodeLocked(c, node);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    o->node = node;
    InitializeOpenAccess(o, granted_access);
    o->write_open = true;
    if (!node->is_directory)
    {
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
            CREATE_ALWAYS,
            kHydrationCacheFileAttributes,
            nullptr);
        if (o->file == INVALID_HANDLE_VALUE && GetLastError() == ERROR_PATH_NOT_FOUND)
        {
            std::error_code ec;
            std::filesystem::create_directories(hydrated.parent_path(), ec);
            if (!ec)
            {
                o->file = CreateFileW(
                    hydrated.wstring().c_str(),
                    desired_access,
                    ResolveHydrationShareMode(IsMutationWriteEnabled(c), granted_access, o->write_open),
                    nullptr,
                    CREATE_ALWAYS,
                    kHydrationCacheFileAttributes,
                    nullptr);
            }
        }
        if (o->file == INVALID_HANDLE_VALUE)
        {
            delete o;
            std::lock_guard<std::mutex> lock(c->mutex);
            RemoveChildName(*parent_node, name);
            EraseIndexedNodeLocked(c, node);
            return STATUS_UNSUCCESSFUL;
        }
        {
            std::lock_guard<std::mutex> lock(c->mutex);
            ClearHydrationStaleLockedNormalized(c, node->path);
        }
    }

#ifdef APFSACCESS_HAS_RW_ENGINE
    apfsaccess::rw::MetadataStore::PayloadIdentity staged_create_identity{};
    bool native_create_metadata_staged = false;
    bool native_create_journaled = true;
    if (IsNativeWriteEnabled(c))
    {
        const auto native_create_operation = request_directory
            ? apfsaccess::rw::MetadataStore::MutationOperation::CreateDirectory
            : apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        native_create_journaled = RecordNativeMutationBestEffort(
            c,
            native_create_operation,
            path,
            L"",
            0,
            0,
            false,
            0,
            &staged_create_identity,
            &native_create_metadata_staged);
        if (native_create_journaled)
        {
            native_create_journaled = RecordMutationBestEffort(
                c,
                request_directory
                    ? apfsaccess::rw::TransactionManager::MutationKind::CreateDirectory
                    : apfsaccess::rw::TransactionManager::MutationKind::CreateFile,
                path,
                L"",
                0,
                0,
                false,
                0,
                0,
                &staged_create_identity);
        }
    }
    if (!native_create_journaled)
    {
        if (!node->is_directory && o->file != INVALID_HANDLE_VALUE)
        {
            CloseHandle(o->file);
            o->file = INVALID_HANDLE_VALUE;
        }
        delete o;
        std::lock_guard<std::mutex> lock(c->mutex);
        RemoveChildName(*parent_node, name);
        std::error_code ec;
        std::filesystem::remove(HydrationPath(c, *node), ec);
        EraseIndexedNodeLocked(c, node);
        return BlockNativeMutationAfterStagingFailure(
            c,
            L"Create",
            native_create_metadata_staged);
    }
#endif

    {
        std::lock_guard<std::mutex> lock(c->mutex);
        AcquireOpenContextAccountingLocked(c, node, o);
    }

    FillInfo(*node, !IsMutationWriteEnabled(c), info);
    *out_ctx = o;
    MarkOpenContextMutation(o);
#ifdef APFSACCESS_HAS_RW_ENGINE
    if (!IsNativeWriteEnabled(c))
    {
        (void)RecordMutationBestEffort(
            c,
            request_directory
                ? apfsaccess::rw::TransactionManager::MutationKind::CreateDirectory
                : apfsaccess::rw::TransactionManager::MutationKind::CreateFile,
            path,
            L"",
            0,
            0,
            false,
            0,
            0,
            &staged_create_identity);
    }
#endif
    return STATUS_SUCCESS;
}

NTSTATUS CB_Overwrite(FSP_FILE_SYSTEM* fs, PVOID ctx, UINT32, BOOLEAN, UINT64 allocation_size, FSP_FSCTL_FILE_INFO* info)
{
    auto* c = Ctx(fs);
    ScopedCallbackActivity callback_scope(c, "Overwrite");
    ScopedPerfTimer perf_scope(c ? &c->perf_overwrite : nullptr);
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

    if (o->named_stream)
    {
        LARGE_INTEGER target{};
        target.QuadPart = allocation_size;
        if (!SetFilePointerEx(o->file, target, nullptr, FILE_BEGIN) || !SetEndOfFile(o->file))
        {
            return STATUS_UNSUCCESSFUL;
        }

        {
            std::lock_guard<std::mutex> lock(c->mutex);
            o->stream_size = allocation_size;
            RememberNamedStreamSizeLocked(c, o->node->path, o->stream_name, allocation_size);
            FillInfo(*o->node, !IsMutationWriteEnabled(c), info);
        }
        MarkOpenContextMutation(o);
        return STATUS_SUCCESS;
    }

#ifdef APFSACCESS_HAS_RW_ENGINE
    apfsaccess::rw::MetadataStore::PayloadIdentity staged_overwrite_identity{};
    bool native_overwrite_metadata_staged = false;
    bool native_overwrite_journaled = true;
    if (IsNativeWriteEnabled(c))
    {
        native_overwrite_journaled = RecordNativeMutationBestEffort(
            c,
            apfsaccess::rw::MetadataStore::MutationOperation::SetFileSize,
            o->node->path,
            L"",
            0,
            allocation_size,
            false,
            0,
            &staged_overwrite_identity,
            &native_overwrite_metadata_staged);
        if (native_overwrite_journaled)
        {
            native_overwrite_journaled = RecordMutationBestEffort(
                c,
                apfsaccess::rw::TransactionManager::MutationKind::SetFileSize,
                o->node->path,
                L"",
                0,
                allocation_size,
                false,
                0,
                0,
                &staged_overwrite_identity);
        }
    }
    if (!native_overwrite_journaled)
    {
        return BlockNativeMutationAfterStagingFailure(
            c,
            L"Overwrite",
            native_overwrite_metadata_staged);
    }
#endif

    LARGE_INTEGER target{};
    target.QuadPart = allocation_size;
    if (!SetFilePointerEx(o->file, target, nullptr, FILE_BEGIN) || !SetEndOfFile(o->file))
    {
#ifdef APFSACCESS_HAS_RW_ENGINE
        if (IsNativeWriteEnabled(c))
        {
            (void)BlockNativeMutationAfterStagingFailure(
                c,
                L"Overwrite",
                native_overwrite_metadata_staged);
        }
#endif
        return STATUS_UNSUCCESSFUL;
    }

    InvalidateHydrationReadHandle(c);

    {
        std::lock_guard<std::mutex> lock(c->mutex);
        o->node->file_size = allocation_size;
        o->node->timestamp = UtcNow();
        FillInfo(*o->node, !IsMutationWriteEnabled(c), info);
    }
#ifdef APFSACCESS_HAS_RW_ENGINE
    if (!IsNativeWriteEnabled(c))
    {
        (void)RecordMutationBestEffort(
            c,
            apfsaccess::rw::TransactionManager::MutationKind::SetFileSize,
            o->node->path,
            L"",
            0,
            allocation_size,
            false,
            0,
            0,
            &staged_overwrite_identity);
    }
#endif
    MarkOpenContextMutation(o);
    return STATUS_SUCCESS;
}

NTSTATUS CB_Write(FSP_FILE_SYSTEM* fs, PVOID ctx, PVOID buf, UINT64 off, ULONG len, BOOLEAN write_to_end_of_file, BOOLEAN constrained_io, PULONG done, FSP_FSCTL_FILE_INFO* info)
{
    auto* c = Ctx(fs);
    ScopedCallbackActivity callback_scope(c, "Write");
    ScopedPerfTimer perf_scope(c ? &c->perf_write : nullptr);

    auto* o = (OpenContext*)ctx;
    if (!c || !o || !o->node || o->node->is_directory || !buf || !done)
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
    if (o->file == INVALID_HANDLE_VALUE)
    {
        *done = 0;
        return o->metadata_read_fallback ? STATUS_ACCESS_DENIED : STATUS_INVALID_PARAMETER;
    }

    auto current_size = o->named_stream ? o->stream_size : o->node->file_size;
    if (write_to_end_of_file)
    {
        off = current_size;
        // CopyFileEx-style copies pre-size the destination to the source size,
        // stream every chunk with explicit offsets, then re-issue the final
        // buffer once more as a write-to-end append. On a pre-sized file that
        // duplicate would extend the file by one extra chunk, which forces the
        // engine into a full re-materialization of the file at commit time.
        // Coalesce it back onto the chunk it duplicates. Only for generic
        // write handles whose immediately preceding write ended exactly at
        // EOF with the same length; append-only handles are excluded so real
        // sequential appends are never affected.
        if (!o->named_stream && o->allow_write_data && o->has_last_write &&
            current_size > 0 && off == current_size &&
            o->last_write_offset + o->last_write_length == current_size &&
            static_cast<std::uint64_t>(len) == o->last_write_length)
        {
            off = current_size - len;
        }
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

    if (o->named_stream)
    {
        OVERLAPPED ov{};
        ov.Offset = (DWORD)(off & 0xffffffffull);
        ov.OffsetHigh = (DWORD)(off >> 32);
        DWORD written = 0;
        if (!WriteFile(o->file, buf, write_len, &written, &ov))
        {
            *done = 0;
            return STATUS_UNSUCCESSFUL;
        }

        {
            const auto write_end = off + static_cast<std::uint64_t>(written);
            std::lock_guard<std::mutex> lock(c->mutex);
            o->stream_size = std::max<std::uint64_t>(o->stream_size, write_end);
            o->last_write_offset = off;
            o->last_write_length = written;
            o->has_last_write = true;
            RememberNamedStreamSizeLocked(c, o->node->path, o->stream_name, o->stream_size);
            if (info)
            {
                FillInfo(*o->node, !IsMutationWriteEnabled(c), info);
            }
        }
        *done = written;
        if (written != 0)
        {
            MarkOpenContextMutation(o);
        }
        return STATUS_SUCCESS;
    }

#ifdef APFSACCESS_HAS_RW_ENGINE
    const bool native_write_active = IsNativeWriteEnabled(c);
    const auto storage_plan = apfsaccess::rw::WritePipeline::PlanForegroundPayloadStorage({
        native_write_active,
        c->metadata_store != nullptr,
        c->payload_spool != nullptr &&
            c->tx_manager != nullptr &&
            !c->payload_spool_volume_identity.empty(),
        buf != nullptr,
        o->named_stream,
        write_len,
        IsExperimentalDualHydrationMirrorEnabled(),
    });
    const auto payload_spool_capacity = storage_plan.should_stage_payload_spool
        ? EnsurePayloadSpoolCapacityBeforeNativeWriteBestEffort(c, write_len)
        : PayloadSpoolCapacityOutcome::Ready;
    if (payload_spool_capacity != PayloadSpoolCapacityOutcome::Ready)
    {
        *done = 0;
        if (payload_spool_capacity == PayloadSpoolCapacityOutcome::CapacityExceeded)
        {
            return STATUS_DISK_FULL;
        }
        return BlockNativeMutationAfterStagingFailure(c, L"WritePayloadSpool");
    }

    apfsaccess::rw::MetadataStore::PayloadIdentity staged_payload_identity{};
    bool write_metadata_staged = false;
    if (native_write_active &&
        !RecordNativeMutationBestEffort(
            c,
            apfsaccess::rw::MetadataStore::MutationOperation::Write,
            o->node->path,
            L"",
            off,
            write_len,
            false,
            0,
            &staged_payload_identity,
            &write_metadata_staged))
    {
        *done = 0;
        return BlockNativeMutationAfterStagingFailure(c, L"Write", write_metadata_staged);
    }
#endif
    DWORD written = write_len;
    bool staged_payload_spool = false;
#ifdef APFSACCESS_HAS_RW_ENGINE
    if (storage_plan.should_stage_payload_spool)
    {
        if (!RecordPayloadWriteMutationBestEffort(
                c,
                o->node->path,
                off,
                buf,
                written,
                &staged_payload_identity))
        {
            *done = 0;
            return BlockNativeMutationAfterStagingFailure(c, L"Write", write_metadata_staged);
        }
        staged_payload_spool = true;
    }
    if (storage_plan.should_write_hydration_file)
#else
    if (true)
#endif
    {
        OVERLAPPED ov{};
        ov.Offset = (DWORD)(off & 0xffffffffull);
        ov.OffsetHigh = (DWORD)(off >> 32);
        if (!WriteFile(o->file, buf, write_len, &written, &ov))
        {
            *done = 0;
#ifdef APFSACCESS_HAS_RW_ENGINE
            if (IsNativeWriteEnabled(c))
            {
                (void)BlockNativeMutationAfterStagingFailure(c, L"Write", write_metadata_staged);
            }
#endif
            return STATUS_UNSUCCESSFUL;
        }
    }

    {
        const auto write_end = off + static_cast<std::uint64_t>(written);
        std::lock_guard<std::mutex> lock(c->mutex);
        o->node->file_size = std::max<std::uint64_t>(o->node->file_size, write_end);
        o->last_write_offset = off;
        o->last_write_length = written;
        o->has_last_write = true;
        o->node->timestamp = UtcNow();
        if (staged_payload_spool && !storage_plan.should_write_hydration_file)
        {
            MarkHydrationStaleLocked(c, o->node);
        }
        else
        {
            ClearHydrationStaleLockedNormalized(c, o->node->path);
        }
        if (info)
        {
            FillInfo(*o->node, !IsMutationWriteEnabled(c), info);
        }
    }
    *done = written;
#ifdef APFSACCESS_HAS_RW_ENGINE
    if (native_write_active && !staged_payload_spool)
    {
        if (!RecordPayloadWriteMutationBestEffort(
                c,
                o->node->path,
                off,
                buf,
                written,
                &staged_payload_identity))
        {
            *done = 0;
            return BlockNativeMutationAfterStagingFailure(c, L"Write", write_metadata_staged);
        }
    }
    else if (!native_write_active)
    {
        RecordMutationBestEffort(
            c,
            apfsaccess::rw::TransactionManager::MutationKind::Write,
            o->node->path,
            L"",
            off,
            written);
    }
#endif
    if (written != 0)
    {
        MarkOpenContextMutation(o);
    }
    return STATUS_SUCCESS;
}

NTSTATUS CB_SetBasicInfo(FSP_FILE_SYSTEM* fs, PVOID ctx, UINT32, UINT64 creation_time, UINT64 last_access_time, UINT64 last_write_time, UINT64 change_time, FSP_FSCTL_FILE_INFO* info)
{
    auto* c = Ctx(fs);
    ScopedCallbackActivity callback_scope(c, "SetBasicInfo");
    ScopedPerfTimer perf_scope(c ? &c->perf_set_basic_info : nullptr);

    auto* o = (OpenContext*)ctx;
    if (!c || !o || !o->node || !info)
    {
        return STATUS_INVALID_PARAMETER;
    }
    const bool no_timestamp_change =
        creation_time == 0 &&
        last_access_time == 0 &&
        last_write_time == 0 &&
        change_time == 0;
    if (no_timestamp_change)
    {
        ExternalMutationRequestScope no_op_request_scope(c, false);
        if (!no_op_request_scope.Acquired())
        {
            return STATUS_VOLUME_DISMOUNTED;
        }
        if (!IsMutationWriteEnabled(c))
        {
            return HandleMutationWriteDisabled(c, L"SetBasicInfo");
        }
        if (!o->allow_set_basic_info)
        {
            return STATUS_ACCESS_DENIED;
        }

        std::lock_guard<std::mutex> lock(c->mutex);
        FillInfo(*o->node, !IsMutationWriteEnabled(c), info);
        return STATUS_SUCCESS;
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
    if (o->named_stream)
    {
        FillInfo(*o->node, !IsMutationWriteEnabled(c), info);
        return STATUS_SUCCESS;
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

    {
        std::lock_guard<std::mutex> lock(c->mutex);
        if (o->node->timestamp.dwLowDateTime == stamp.LowPart &&
            o->node->timestamp.dwHighDateTime == stamp.HighPart)
        {
            FillInfo(*o->node, !IsMutationWriteEnabled(c), info);
            return STATUS_SUCCESS;
        }
    }

#ifdef APFSACCESS_HAS_RW_ENGINE
    apfsaccess::rw::MetadataStore::PayloadIdentity staged_basic_info_identity{};
    bool native_set_basic_info_metadata_staged = false;
    bool native_set_basic_info_staged = true;
    if (IsNativeWriteEnabled(c))
    {
        native_set_basic_info_staged = RecordNativeMutationBestEffort(
            c,
            apfsaccess::rw::MetadataStore::MutationOperation::SetBasicInfo,
            o->node->path,
            L"",
            0,
            0,
            false,
            stamp.QuadPart,
            &staged_basic_info_identity,
            &native_set_basic_info_metadata_staged);
    }
    if (!native_set_basic_info_staged)
    {
        if (!IsBenignStaleDeletedSetBasicInfoFailure(c, o->node))
        {
            return BlockNativeMutationAfterStagingFailure(
                c,
                L"SetBasicInfo",
                native_set_basic_info_metadata_staged);
        }
    }
    if (native_set_basic_info_staged &&
        IsNativeWriteEnabled(c) &&
        !RecordMutationBestEffort(
            c,
            apfsaccess::rw::TransactionManager::MutationKind::SetBasicInfo,
            o->node->path,
            L"",
            0,
            0,
            false,
            0,
            stamp.QuadPart,
            &staged_basic_info_identity))
    {
        return BlockNativeMutationAfterStagingFailure(c, L"SetBasicInfo", true);
    }
#endif

    {
        std::lock_guard<std::mutex> lock(c->mutex);
        o->node->timestamp.dwLowDateTime = stamp.LowPart;
        o->node->timestamp.dwHighDateTime = stamp.HighPart;
        FillInfo(*o->node, !IsMutationWriteEnabled(c), info);
    }
#ifdef APFSACCESS_HAS_RW_ENGINE
    if (!IsNativeWriteEnabled(c))
    {
        (void)RecordMutationBestEffort(
            c,
            apfsaccess::rw::TransactionManager::MutationKind::SetBasicInfo,
            o->node->path,
            L"",
            0,
            0,
            false,
            0,
            stamp.QuadPart,
            &staged_basic_info_identity);
    }
#endif
    MarkOpenContextMutation(o);
    return STATUS_SUCCESS;
}

NTSTATUS CB_SetFileSize(FSP_FILE_SYSTEM* fs, PVOID ctx, UINT64 size, BOOLEAN, FSP_FSCTL_FILE_INFO* info)
{
    auto* c = Ctx(fs);
    ScopedCallbackActivity callback_scope(c, "SetFileSize");
    ScopedPerfTimer perf_scope(c ? &c->perf_set_file_size : nullptr);

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

    if (o->named_stream)
    {
        LARGE_INTEGER target{};
        target.QuadPart = size;
        if (!SetFilePointerEx(o->file, target, nullptr, FILE_BEGIN) || !SetEndOfFile(o->file))
        {
            return STATUS_UNSUCCESSFUL;
        }

        {
            std::lock_guard<std::mutex> lock(c->mutex);
            o->stream_size = size;
            RememberNamedStreamSizeLocked(c, o->node->path, o->stream_name, size);
            FillInfo(*o->node, !IsMutationWriteEnabled(c), info);
        }
        MarkOpenContextMutation(o);
        return STATUS_SUCCESS;
    }

    SetFileSizeRollbackSnapshot rollback_snapshot{};
    {
        std::lock_guard<std::mutex> lock(c->mutex);
        rollback_snapshot.previous_size = o->node->file_size;
        rollback_snapshot.previous_timestamp = o->node->timestamp;
    }
    const auto hydration_path = HydrationPath(c, *o->node);
    if (!CaptureSetFileSizeRollbackTail(o->file, hydration_path, rollback_snapshot.previous_size, size, rollback_snapshot))
    {
        return STATUS_UNSUCCESSFUL;
    }

#ifdef APFSACCESS_HAS_RW_ENGINE
    apfsaccess::rw::MetadataStore::PayloadIdentity staged_file_size_identity{};
    bool native_file_size_metadata_staged = false;
    bool native_file_size_journaled = true;
    if (IsNativeWriteEnabled(c))
    {
        native_file_size_journaled = RecordNativeMutationBestEffort(
            c,
            apfsaccess::rw::MetadataStore::MutationOperation::SetFileSize,
            o->node->path,
            L"",
            0,
            size,
            false,
            0,
            &staged_file_size_identity,
            &native_file_size_metadata_staged);
        if (native_file_size_journaled)
        {
            native_file_size_journaled = RecordMutationBestEffort(
                c,
                apfsaccess::rw::TransactionManager::MutationKind::SetFileSize,
                o->node->path,
                L"",
                0,
                size,
                false,
                0,
                0,
                &staged_file_size_identity);
        }
    }
    if (!native_file_size_journaled)
    {
        DiscardSetFileSizeRollbackTail(rollback_snapshot);
        return BlockNativeMutationAfterStagingFailure(
            c,
            L"SetFileSize",
            native_file_size_metadata_staged);
    }
#endif

    LARGE_INTEGER target{};
    target.QuadPart = size;
    if (!SetFilePointerEx(o->file, target, nullptr, FILE_BEGIN) || !SetEndOfFile(o->file))
    {
#ifdef APFSACCESS_HAS_RW_ENGINE
        if (IsNativeWriteEnabled(c))
        {
            (void)BlockNativeMutationAfterStagingFailure(
                c,
                L"SetFileSize",
                native_file_size_metadata_staged);
        }
#endif
        DiscardSetFileSizeRollbackTail(rollback_snapshot);
        return STATUS_UNSUCCESSFUL;
    }

    InvalidateHydrationReadHandle(c);

    {
        std::lock_guard<std::mutex> lock(c->mutex);
        o->node->file_size = size;
        o->node->timestamp = UtcNow();
        FillInfo(*o->node, !IsMutationWriteEnabled(c), info);
    }
#ifdef APFSACCESS_HAS_RW_ENGINE
    if (!IsNativeWriteEnabled(c))
    {
        (void)RecordMutationBestEffort(
            c,
            apfsaccess::rw::TransactionManager::MutationKind::SetFileSize,
            o->node->path,
            L"",
            0,
            size,
            false,
            0,
            0,
            &staged_file_size_identity);
    }
#endif
    DiscardSetFileSizeRollbackTail(rollback_snapshot);
    MarkOpenContextMutation(o);
    return STATUS_SUCCESS;
}

NTSTATUS CB_CanDelete(FSP_FILE_SYSTEM* fs, PVOID ctx, PWSTR file_name)
{
    auto* c = Ctx(fs);
    ScopedCallbackActivity callback_scope(c, "CanDelete");
    ScopedPerfTimer perf_scope(c ? &c->perf_can_delete : nullptr);
    const auto trace_return = [&](NTSTATUS status, const std::wstring& detail = std::wstring()) -> NTSTATUS
    {
        if (IsHostMoveTraceEnabled())
        {
            auto* o = (OpenContext*)ctx;
            std::wostringstream message;
            message << L"CanDelete status=" << FormatNtStatus(status)
                    << L" file='" << (file_name ? std::wstring(file_name) : std::wstring()) << L"'";
            if (o && o->node)
            {
                message << L" ctxPath='" << o->node->path << L"'"
                        << L" allowDelete=" << (o->allow_delete ? L"1" : L"0");
            }
            if (!detail.empty())
            {
                message << L" detail='" << detail << L"'";
            }
            TraceMove(c, message.str());
        }
        return status;
    };
    if (!c)
    {
        return trace_return(STATUS_INVALID_PARAMETER, L"missing-context");
    }
    ExternalMutationRequestScope mutation_request_scope(c);
    if (!mutation_request_scope.Acquired())
    {
        return trace_return(STATUS_VOLUME_DISMOUNTED, L"shutdown-drain");
    }
    MutationCallbackScope mutation_scope(c);
    if (!IsMutationWriteEnabled(c))
    {
        return trace_return(HandleMutationWriteDisabled(c, L"CanDelete"), L"write-disabled");
    }

    auto* o = (OpenContext*)ctx;
    std::wstring target = file_name
        ? NormalizePath(std::wstring(file_name))
        : (o && o->node && !o->node->path.empty() ? o->node->path : L"\\");
    if (o && !HasDeletePermissionForTargetNormalized(o, target))
    {
        return trace_return(STATUS_ACCESS_DENIED, L"permission");
    }
    if (o && o->node && !o->node->is_directory)
    {
        std::lock_guard<std::mutex> lock(c->mutex);
        if (auto context_node = TryReuseOpenContextNodeLockedNormalized(c, o, target))
        {
            if (HasDeletePendingAncestorLockedNormalized(c, target))
            {
                return trace_return(STATUS_DELETE_PENDING, L"context-node-delete-pending");
            }
            return trace_return(
                ValidateDeleteEligibilityLocked(c, context_node, o),
                L"context-node-validated");
        }
    }
    auto node = FindNodeNormalized(c, target);
    if (!node)
    {
        std::lock_guard<std::mutex> lock(c->mutex);
        auto hidden = TryGetNodeLockedNormalized(c, target);
        if ((hidden && IsDeleteBlockedStateLocked(hidden)) || HasDeletePendingAncestorLockedNormalized(c, target))
        {
            return trace_return(STATUS_DELETE_PENDING, L"hidden-delete-pending");
        }
        return trace_return(STATUS_OBJECT_NAME_NOT_FOUND, L"missing");
    }
    if (IsDeleteBlockedStateLocked(node))
    {
        return trace_return(STATUS_DELETE_PENDING, L"delete-blocked");
    }
    if (node->is_directory && !EnsureDirectoryLoaded(c, node))
    {
        return trace_return(STATUS_UNSUCCESSFUL, L"dir-load");
    }

    std::lock_guard<std::mutex> lock(c->mutex);
    auto locked = TryGetNodeLockedNormalized(c, target);
    if (!locked)
    {
        return trace_return(STATUS_OBJECT_NAME_NOT_FOUND, L"missing-locked");
    }
    const auto status = ValidateDeleteEligibilityLocked(c, locked, o);
    if (status == STATUS_DIRECTORY_NOT_EMPTY && locked->is_directory)
    {
        locked->delete_requested_after_children = true;
        locked->caller_delete_retry_required = true;
        if (o)
        {
            o->directory_delete_probe_failed_not_empty = true;
        }
    }
    return trace_return(status, L"validated");
}

NTSTATUS CB_SetDelete(FSP_FILE_SYSTEM* fs, PVOID ctx, PWSTR file_name, BOOLEAN delete_file)
{
    auto* c = Ctx(fs);
    ScopedCallbackActivity callback_scope(c, "SetDelete");
    ScopedPerfTimer perf_scope(c ? &c->perf_set_delete : nullptr);

    auto* o = (OpenContext*)ctx;
    const auto trace_return = [&](NTSTATUS status, const std::wstring& detail = std::wstring()) -> NTSTATUS
    {
        if (IsHostMoveTraceEnabled())
        {
            std::wostringstream message;
            message << L"SetDelete status=" << FormatNtStatus(status)
                    << L" delete=" << (delete_file ? L"1" : L"0")
                    << L" file='" << (file_name ? std::wstring(file_name) : std::wstring()) << L"'";
            if (o && o->node)
            {
                message << L" ctxPath='" << o->node->path << L"'"
                        << L" allowDelete=" << (o->allow_delete ? L"1" : L"0");
            }
            if (!detail.empty())
            {
                message << L" detail='" << detail << L"'";
            }
            TraceMove(c, message.str());
        }
        return status;
    };
    if (!c)
    {
        return trace_return(STATUS_INVALID_PARAMETER, L"missing-context");
    }
    ExternalMutationRequestScope mutation_request_scope(c);
    if (!mutation_request_scope.Acquired())
    {
        return trace_return(STATUS_VOLUME_DISMOUNTED, L"shutdown-drain");
    }
    MutationCallbackScope mutation_scope(c);
    if (!IsMutationWriteEnabled(c))
    {
        return trace_return(HandleMutationWriteDisabled(c, L"SetDelete"), L"write-disabled");
    }

    std::wstring target = file_name
        ? NormalizePath(std::wstring(file_name))
        : (o && o->node && !o->node->path.empty() ? o->node->path : L"\\");
    if (!delete_file && o && o->node && NodePathKey(*o->node) == LowerPathKey(target))
    {
        std::lock_guard<std::mutex> lock(c->mutex);
        auto locked = TryGetNodeLockedNormalized(c, target);
        if (!locked)
        {
            return trace_return(STATUS_OBJECT_NAME_NOT_FOUND, L"clear-missing");
        }
        if (locked != o->node)
        {
            return trace_return(STATUS_INVALID_PARAMETER, L"clear-stale-context");
        }
        SetDeleteIntentLocked(c, o, false);
        return trace_return(STATUS_SUCCESS, L"clear");
    }

    if (delete_file && o && o->node && !o->node->is_directory)
    {
        std::lock_guard<std::mutex> lock(c->mutex);
        if (auto context_node = TryReuseOpenContextNodeLockedNormalized(c, o, target))
        {
            if (!o->allow_delete)
            {
                return trace_return(STATUS_ACCESS_DENIED, L"context-node-permission");
            }
            const auto status = ValidateDeleteEligibilityLocked(c, context_node, o);
            if (!NT_SUCCESS(status))
            {
                return trace_return(status, L"context-node-validate");
            }
            context_node->caller_delete_retry_required = false;
            SetDeleteIntentLocked(c, o, true);
            return trace_return(STATUS_SUCCESS, L"context-node-set");
        }
    }

    auto node = FindNodeNormalized(c, target);
    if (!node && o && o->node && NodePathKey(*o->node) == LowerPathKey(target))
    {
        node = o->node;
    }
    if (!node)
    {
        std::lock_guard<std::mutex> lock(c->mutex);
        auto hidden = TryGetNodeLockedNormalized(c, target);
        if ((hidden && IsDeleteBlockedStateLocked(hidden)) || HasDeletePendingAncestorLockedNormalized(c, target))
        {
            return trace_return(STATUS_DELETE_PENDING, L"hidden-delete-pending");
        }
        return trace_return(STATUS_OBJECT_NAME_NOT_FOUND, L"missing");
    }
    if (node->is_directory && !EnsureDirectoryLoaded(c, node))
    {
        return trace_return(STATUS_UNSUCCESSFUL, L"dir-load");
    }

    std::lock_guard<std::mutex> lock(c->mutex);
    auto locked = TryGetNodeLockedNormalized(c, target);
    if (!locked)
    {
        return trace_return(STATUS_OBJECT_NAME_NOT_FOUND, L"missing-locked");
    }
    if (o && o->node != locked)
    {
        return trace_return(STATUS_INVALID_PARAMETER, L"stale-context");
    }

    if (delete_file)
    {
        if (!o || !o->allow_delete)
        {
            return trace_return(STATUS_ACCESS_DENIED, L"permission");
        }
        const auto status = ValidateDeleteEligibilityLocked(c, locked, o);
        if (status == STATUS_DIRECTORY_NOT_EMPTY && locked->is_directory)
        {
            locked->delete_requested_after_children = true;
            locked->caller_delete_retry_required = true;
            o->directory_delete_probe_failed_not_empty = true;
            return trace_return(status, L"directory-not-empty");
        }
        if (!NT_SUCCESS(status))
        {
            return trace_return(status, L"validate");
        }
        locked->caller_delete_retry_required = false;
        SetDeleteIntentLocked(c, o, true);
    }
    else if (o)
    {
        SetDeleteIntentLocked(c, o, false);
    }

    return trace_return(STATUS_SUCCESS, delete_file ? L"set" : L"clear");
}

NTSTATUS CB_Rename(FSP_FILE_SYSTEM* fs, PVOID ctx, PWSTR old_name, PWSTR new_name, BOOLEAN replace_if_exists)
{
    auto* c = Ctx(fs);
    ScopedCallbackActivity callback_scope(c, "Rename");
    ScopedPerfTimer perf_scope(c ? &c->perf_rename : nullptr);
    const auto trace_return = [&](NTSTATUS status, const std::wstring& detail = std::wstring()) -> NTSTATUS
    {
        if (IsHostMoveTraceEnabled())
        {
            auto* current_open = (OpenContext*)ctx;
            std::wostringstream message;
            const auto raw_new = new_name ? std::wstring(new_name) : std::wstring();
            const auto raw_old = old_name ? std::wstring(old_name) : std::wstring();
            message << L"Rename status=" << FormatNtStatus(status)
                    << L" old='" << raw_old << L"'"
                    << L" new='" << raw_new << L"'"
                    << L" normalizedOld='" << NormalizePath(raw_old) << L"'"
                    << L" normalizedNew='" << NormalizeRenameTargetPath(NormalizePath(raw_old), raw_new) << L"'"
                    << L" targetDrive='";
            const auto target_drive = TryExtractDriveLetter(raw_new);
            if (target_drive.has_value())
            {
                message << target_drive.value();
            }
            message << L"' mountDrive='";
            const auto mount_drive = c ? TryExtractDriveLetter(c->args.mount) : std::nullopt;
            if (mount_drive.has_value())
            {
                message << mount_drive.value();
            }
            message << L"' replace=" << (replace_if_exists ? L"1" : L"0");
            if (current_open && current_open->node)
            {
                message << L" ctxPath='" << current_open->node->path << L"'"
                        << L" allowDelete=" << (current_open->allow_delete ? L"1" : L"0")
                        << L" allowDeleteChild=" << (current_open->allow_delete_child ? L"1" : L"0");
            }
            if (!detail.empty())
            {
                message << L" detail='" << detail << L"'";
            }
            TraceMove(c, message.str());
        }
        return status;
    };

    if (!c || !old_name || !new_name)
    {
        return trace_return(STATUS_INVALID_PARAMETER, L"invalid-args");
    }
    ExternalMutationRequestScope mutation_request_scope(c);
    if (!mutation_request_scope.Acquired())
    {
        return trace_return(STATUS_VOLUME_DISMOUNTED, L"shutdown-drain");
    }
    MutationCallbackScope mutation_scope(c);
    if (!IsMutationWriteEnabled(c))
    {
        return trace_return(HandleMutationWriteDisabled(c, L"Rename"), L"write-disabled");
    }

    auto old_path = NormalizePath(old_name);
    if (IsDifferentDriveRenameTarget(c, new_name ? std::wstring(new_name) : std::wstring()))
    {
        return trace_return(STATUS_NOT_SAME_DEVICE, L"different-drive");
    }
    auto new_path = NormalizeRenameTargetPath(old_path, new_name);
    if (old_path == L"\\" || new_path == L"\\")
    {
        return trace_return(STATUS_ACCESS_DENIED, L"root");
    }
    if (!IsValidNormalizedWin32PathForMutation(old_path) ||
        !IsValidNormalizedWin32PathForMutation(new_path))
    {
        return trace_return(STATUS_OBJECT_NAME_INVALID, L"invalid-path");
    }
    auto* current_open = (OpenContext*)ctx;
    if (old_path == new_path)
    {
        std::lock_guard<std::mutex> lock(c->mutex);
        if (HasDeletePendingAncestorLockedNormalized(c, old_path))
        {
            return trace_return(STATUS_DELETE_PENDING, L"same-path-delete-ancestor");
        }

        auto existing = TryGetNodeLockedNormalized(c, old_path);
        if (!existing)
        {
            return trace_return(STATUS_OBJECT_NAME_NOT_FOUND, L"same-path-missing");
        }
        if (IsDeleteBlockedStateLocked(existing))
        {
            return trace_return(STATUS_DELETE_PENDING, L"same-path-delete-blocked");
        }

        const auto old_parent_path = ParentOfNormalizedPath(old_path);
        const bool has_open_context = current_open && current_open->node;
        const bool context_is_source = has_open_context && current_open->node == existing;
        const bool context_is_old_parent =
            has_open_context &&
            current_open->node->is_directory &&
            NodePathKey(*current_open->node) == LowerPathKey(old_parent_path);
        if (has_open_context && !context_is_source && !context_is_old_parent)
        {
            return trace_return(STATUS_INVALID_PARAMETER, L"same-path-stale-context");
        }
        if (context_is_source && !current_open->allow_delete)
        {
            return trace_return(STATUS_ACCESS_DENIED, L"same-path-source-permission");
        }
        if (context_is_old_parent && !current_open->allow_delete_child)
        {
            return trace_return(STATUS_ACCESS_DENIED, L"same-path-parent-permission");
        }

        return trace_return(STATUS_SUCCESS, L"same-path");
    }

    const auto target_reuse_status = DrainDeferredDeleteRollbackBeforePathReuse(c, new_path, L"RenamePathReuse");
    if (!NT_SUCCESS(target_reuse_status))
    {
        return trace_return(target_reuse_status, L"delete-rollback-target");
    }

    {
        std::lock_guard<std::mutex> lock(c->mutex);
        if (HasDeletePendingAncestorLockedNormalized(c, old_path) || HasDeletePendingAncestorLockedNormalized(c, new_path))
        {
            return trace_return(STATUS_DELETE_PENDING, L"delete-ancestor");
        }

        auto old_hidden = TryGetNodeLockedNormalized(c, old_path);
        if (IsDeleteBlockedStateLocked(old_hidden))
        {
            return trace_return(STATUS_DELETE_PENDING, L"old-delete-blocked");
        }

        auto new_hidden = TryGetNodeLockedNormalized(c, new_path);
        if (IsDeleteBlockedStateLocked(new_hidden))
        {
            return trace_return(STATUS_DELETE_PENDING, L"new-delete-blocked");
        }
    }
    if (!EnsureParentDirectoryLoadedNormalized(c, old_path) || !EnsureParentDirectoryLoadedNormalized(c, new_path))
    {
        return trace_return(STATUS_OBJECT_PATH_NOT_FOUND, L"parent-load");
    }

    const bool experimental_namespace_writeback =
        IsExperimentalNamespaceWriteBackEnabled() &&
        IsDeferCloseCommitsEnabled();
    auto source_before_lock = FindNodeNormalized(c, old_path);
    auto existing_before_lock = FindNodeNormalized(c, new_path);
    const bool simple_file_rename_can_join_existing_deferred_batch =
        experimental_namespace_writeback &&
        source_before_lock &&
        !source_before_lock->is_directory &&
        replace_if_exists == FALSE &&
        !existing_before_lock;
    const bool simple_directory_rename_can_start_deferred_batch =
        experimental_namespace_writeback &&
        source_before_lock &&
        source_before_lock->is_directory &&
        source_before_lock->loaded &&
        replace_if_exists == FALSE &&
        !existing_before_lock;
    bool can_continue_existing_deferred_namespace_batch = false;
#ifdef APFSACCESS_HAS_RW_ENGINE
    const bool has_pending_native_mutations_before_rename =
        IsNativeWriteEnabled(c) && HasPendingNativeMutations(c);
    if (has_pending_native_mutations_before_rename &&
        simple_file_rename_can_join_existing_deferred_batch &&
        c->close_commit_deferred.load(std::memory_order_acquire) &&
        PendingNativeMutationsCanContinueDeferredClose(c))
    {
        can_continue_existing_deferred_namespace_batch = true;
    }
#else
    const bool has_pending_native_mutations_before_rename = false;
#endif
    const bool should_probe_committed_source_for_experimental_rename =
        simple_file_rename_can_join_existing_deferred_batch &&
        !can_continue_existing_deferred_namespace_batch;
    const bool source_committed_for_experimental_rename =
        should_probe_committed_source_for_experimental_rename &&
        SourcePathCommittedForExperimentalRename(c, old_path);
    const bool source_chained_from_deferred_rename =
        should_probe_committed_source_for_experimental_rename &&
        SourceNodeCarriesCommittedReadPathForExperimentalRename(c, source_before_lock, old_path);
    const bool current_rename_can_use_experimental_namespace_batch =
        simple_file_rename_can_join_existing_deferred_batch &&
        (source_committed_for_experimental_rename || source_chained_from_deferred_rename);
    const bool committed_directory_source_for_experimental_rename =
        simple_directory_rename_can_start_deferred_batch &&
        !has_pending_native_mutations_before_rename &&
        NodePathCommittedForExperimentalRename(c, old_path, true);

#ifdef APFSACCESS_HAS_RW_ENGINE
    if (has_pending_native_mutations_before_rename)
    {
        if (!can_continue_existing_deferred_namespace_batch)
        {
            const auto pending_commit_status = DrainNativeMutationsByPolicy(c, L"Rename", false, true);
            if (!NT_SUCCESS(pending_commit_status))
            {
                RestoreDeferredDeleteRollbackPlans(c);
                RestoreDeferredRenameRollbackPlans(c);
                AbortMutationJournalBestEffort(c, L"Rename");
                return trace_return(pending_commit_status, L"pre-drain");
            }
            if (!FinalizeMutationJournalBestEffort(c, L"Rename"))
            {
                return trace_return(
                    c->write_degraded ? STATUS_MEDIA_WRITE_PROTECTED : STATUS_UNSUCCESSFUL,
                    L"pre-finalize");
            }
        }
    }
#endif

    if (existing_before_lock && existing_before_lock->is_directory && !EnsureDirectoryLoaded(c, existing_before_lock))
    {
        return trace_return(STATUS_UNSUCCESSFUL, L"target-dir-load");
    }

    auto old_parent_path = ParentOfNormalizedPath(old_path);
    auto new_parent_path = ParentOfNormalizedPath(new_path);
    auto old_leaf = old_path.substr(old_path.find_last_of(L'\\') + 1);
    auto new_leaf = new_path.substr(new_path.find_last_of(L'\\') + 1);
    RenameLocalSnapshot rename_snapshot{};
    std::shared_ptr<Node> deferred_directory_candidate;
    std::vector<RenameDescendantReadPathSnapshot> deferred_directory_read_paths;
    bool defer_native_rename_commit = false;
    bool directory_rename_committed_descendants = false;
    bool directory_rename_can_defer = false;
    apfsaccess::rw::MetadataStore::PayloadIdentity staged_rename_identity{};
    bool rename_metadata_staged = false;

    if (committed_directory_source_for_experimental_rename)
    {
        {
            std::lock_guard<std::mutex> lock(c->mutex);
            deferred_directory_candidate = TryGetNodeLockedNormalized(c, old_path);
            if (deferred_directory_candidate)
            {
                (void)CollectDeferredDirectoryRenameReadPathsLocked(
                    c,
                    deferred_directory_candidate,
                    current_open,
                    deferred_directory_read_paths);
            }
        }

        directory_rename_committed_descendants =
            DeferredDirectoryRenameDescendantsCommitted(c, deferred_directory_read_paths);
    }

    {
        std::lock_guard<std::mutex> lock(c->mutex);
        auto node = TryGetNodeLockedNormalized(c, old_path);
        if (!node)
        {
            node = current_open ? current_open->node : nullptr;
        }
        if (!node)
        {
            return trace_return(STATUS_OBJECT_NAME_NOT_FOUND, L"missing");
        }
        if (NodePathKey(*node) != LowerPathKey(old_path))
        {
            // Prevent stale source-handle fallback from renaming an unrelated node.
            return trace_return(STATUS_OBJECT_NAME_NOT_FOUND, L"stale-source");
        }
        const bool has_open_context = current_open && current_open->node;
        const bool context_is_source = has_open_context && current_open->node == node;
        const bool context_is_old_parent =
            has_open_context &&
            current_open->node->is_directory &&
            NodePathKey(*current_open->node) == LowerPathKey(old_parent_path);
        const bool context_is_new_parent =
            has_open_context &&
            current_open->node->is_directory &&
            NodePathKey(*current_open->node) == LowerPathKey(new_parent_path);

        if (has_open_context &&
            !context_is_source &&
            !context_is_old_parent &&
            !context_is_new_parent)
        {
            return trace_return(STATUS_INVALID_PARAMETER, L"invalid-context");
        }

        if (context_is_source)
        {
            if (!current_open->allow_delete)
            {
                return trace_return(STATUS_ACCESS_DENIED, L"source-permission");
            }
        }
        else if (context_is_old_parent)
        {
            if (!current_open->allow_delete_child)
            {
                return trace_return(STATUS_ACCESS_DENIED, L"old-parent-delete-child");
            }
            if (!context_is_new_parent)
            {
                return trace_return(STATUS_ACCESS_DENIED, L"cross-parent-parent-context");
            }
            if (!HasDirectoryInsertPermission(current_open, node->is_directory))
            {
                return trace_return(STATUS_ACCESS_DENIED, L"old-parent-insert");
            }
        }
        else if (context_is_new_parent)
        {
            if (!HasDirectoryInsertPermission(current_open, node->is_directory))
            {
                return trace_return(STATUS_ACCESS_DENIED, L"new-parent-insert");
            }
            if (replace_if_exists && !current_open->allow_delete_child)
            {
                return trace_return(STATUS_ACCESS_DENIED, L"replace-delete-child");
            }
        }
        if (IsDeleteBlockedStateLocked(node))
        {
            return trace_return(STATUS_DELETE_PENDING, L"source-delete-blocked");
        }
        if (node->path == L"\\")
        {
            return trace_return(STATUS_ACCESS_DENIED, L"root-node");
        }
        if (node->is_directory &&
            (LowerPathKey(new_parent_path) == LowerPathKey(old_path) || IsDescendantPathNormalized(new_parent_path, old_path)))
        {
            return trace_return(STATUS_ACCESS_DENIED, L"directory-descendant");
        }
        if (HasRenameOpenHandleConflictLocked(c, node, current_open))
        {
            return trace_return(STATUS_SHARING_VIOLATION, L"open-conflict");
        }

        auto old_parent = TryGetNodeLockedNormalized(c, old_parent_path);
        auto new_parent = TryGetNodeLockedNormalized(c, new_parent_path);
        if (!old_parent || !new_parent || !old_parent->is_directory || !new_parent->is_directory)
        {
            return trace_return(STATUS_OBJECT_PATH_NOT_FOUND, L"parent-missing");
        }
        if (IsDeleteBlockedStateLocked(old_parent) || IsDeleteBlockedStateLocked(new_parent))
        {
            return trace_return(STATUS_DELETE_PENDING, L"parent-delete-blocked");
        }

        auto existing = TryGetNodeLockedNormalized(c, new_path);
        if (existing && existing != node)
        {
            if (has_open_context)
            {
                const bool can_replace_with_context =
                    context_is_new_parent &&
                    current_open->allow_delete_child &&
                    IsDirectChildPathNormalized(current_open->node->path, new_path);
                if (!can_replace_with_context)
                {
                    return trace_return(STATUS_ACCESS_DENIED, L"replace-context");
                }
            }
            if (IsDeleteBlockedStateLocked(existing))
            {
                return trace_return(STATUS_DELETE_PENDING, L"target-delete-blocked");
            }
            if (!replace_if_exists)
            {
                return trace_return(STATUS_OBJECT_NAME_COLLISION, L"collision");
            }
            if (existing->is_directory != node->is_directory)
            {
                return trace_return(STATUS_ACCESS_DENIED, L"replace-type");
            }
            if (existing->is_directory && !existing->loaded)
            {
                return trace_return(STATUS_UNSUCCESSFUL, L"replace-dir-not-loaded");
            }
            if (existing->is_directory && !existing->children.empty())
            {
                return trace_return(STATUS_DIRECTORY_NOT_EMPTY, L"replace-dir-not-empty");
            }
            const bool allow_open_file_replace = !existing->is_directory;
            if (!CanRemoveNodeRecursiveLocked(c, existing, allow_open_file_replace))
            {
                return trace_return(STATUS_SHARING_VIOLATION, L"replace-open-conflict");
            }
        }

        rename_snapshot.node = node;
        rename_snapshot.old_path = old_path;
        rename_snapshot.new_path = new_path;
        rename_snapshot.old_hydration_key = node->hydration_key;
        rename_snapshot.old_committed_read_path = node->committed_read_path;
        rename_snapshot.old_timestamp = node->timestamp;
        rename_snapshot.old_parent = old_parent;
        rename_snapshot.new_parent = new_parent;
        rename_snapshot.old_leaf = old_leaf;
        rename_snapshot.new_leaf = new_leaf;
        if (directory_rename_committed_descendants &&
            deferred_directory_candidate == node &&
            !existing)
        {
            std::vector<RenameDescendantReadPathSnapshot> current_directory_read_paths;
            if (CollectDeferredDirectoryRenameReadPathsLocked(
                    c,
                    node,
                    current_open,
                    current_directory_read_paths) &&
                RenameDescendantReadPathSnapshotsEqual(
                    current_directory_read_paths,
                    deferred_directory_read_paths))
            {
                rename_snapshot.descendant_committed_read_paths = std::move(current_directory_read_paths);
                directory_rename_can_defer = true;
            }
        }
        if (existing && existing != node)
        {
            rename_snapshot.replaced_node = existing;
            rename_snapshot.replaced_node_was_present = true;
            if (!MoveFileAsideForRollbackLocked(c, existing, L"rename-replaced", rename_snapshot.replaced_file_snapshot))
            {
                return trace_return(STATUS_UNSUCCESSFUL, L"rollback-snapshot");
            }
        }
        defer_native_rename_commit =
            (current_rename_can_use_experimental_namespace_batch ||
                can_continue_existing_deferred_namespace_batch ||
                directory_rename_can_defer) &&
            IsNativeWriteEnabled(c) &&
            replace_if_exists == FALSE &&
            (!existing || existing == node);

#ifdef APFSACCESS_HAS_RW_ENGINE
        if (IsNativeWriteEnabled(c) &&
            !RecordNativeMutationBestEffort(
                c,
                apfsaccess::rw::MetadataStore::MutationOperation::Rename,
                old_path,
                new_path,
                0,
                0,
                replace_if_exists != FALSE,
                0,
                &staged_rename_identity,
                &rename_metadata_staged))
        {
            RestoreFileRollbackSnapshotLocked(c, rename_snapshot.replaced_file_snapshot);
            DiscardFileRollbackSnapshot(rename_snapshot.replaced_file_snapshot);
            return trace_return(
                BlockNativeMutationAfterStagingFailure(c, L"Rename", rename_metadata_staged),
                L"stage-native");
        }
#endif

        if (existing && existing != node)
        {
            const bool allow_open_file_replace = !existing->is_directory;
            if (!RemoveNodeRecursiveLocked(c, existing, allow_open_file_replace))
            {
                RestoreFileRollbackSnapshotLocked(c, rename_snapshot.replaced_file_snapshot);
                DiscardFileRollbackSnapshot(rename_snapshot.replaced_file_snapshot);
                return trace_return(STATUS_SHARING_VIOLATION, L"remove-replaced");
            }
            RemoveChildName(*new_parent, new_leaf);
        }

        RemoveChildName(*old_parent, old_leaf);
        AddChildName(*new_parent, new_leaf);
        if (!ReindexNodePathsLocked(c, node, old_path, new_path))
        {
            AddChildName(*old_parent, old_leaf);
            RemoveChildName(*new_parent, new_leaf);
            if (existing && existing != node)
            {
                RestoreNodeRecursiveLocked(c, existing);
                RestoreFileRollbackSnapshotLocked(c, rename_snapshot.replaced_file_snapshot);
            }
            DiscardFileRollbackSnapshot(rename_snapshot.replaced_file_snapshot);
            return trace_return(STATUS_UNSUCCESSFUL, L"reindex");
        }
        node->timestamp = UtcNow();
        rename_snapshot.node_reindexed = true;
    }
#ifdef APFSACCESS_HAS_RW_ENGINE
    const bool rename_journal_recorded = RecordMutationBestEffort(
        c,
        apfsaccess::rw::TransactionManager::MutationKind::Rename,
        old_path,
        new_path,
        0,
        0,
        replace_if_exists != FALSE,
        0,
        0,
        &staged_rename_identity);
    const bool rename_identity_recorded =
        staged_rename_identity.object_id != 0 &&
        staged_rename_identity.generation != 0;
    if (rename_metadata_staged && (!rename_journal_recorded || !rename_identity_recorded))
    {
        {
            std::lock_guard<std::mutex> lock(c->mutex);
            RollbackRenameLocalStateLocked(c, rename_snapshot);
        }
        RestoreDeferredDeleteRollbackPlans(c);
        RestoreDeferredRenameRollbackPlans(c);
        AbortMutationJournalBestEffort(c, L"Rename");
        DiscardFileRollbackSnapshot(rename_snapshot.replaced_file_snapshot);
        return trace_return(
            BlockNativeMutationAfterStagingFailure(c, L"Rename", true),
            L"journal-native");
    }
    std::uint64_t deferred_rename_target = 0;
    if (defer_native_rename_commit &&
        AcceptMutationJournalForDeferredCommitBestEffort(c, L"RenameDeferredAccept", &deferred_rename_target))
    {
        {
            std::lock_guard<std::mutex> lock(c->mutex);
            if (rename_snapshot.node &&
                !rename_snapshot.node->is_directory &&
                rename_snapshot.node->committed_read_path.empty())
            {
                rename_snapshot.node->committed_read_path =
                    rename_snapshot.old_committed_read_path.empty()
                        ? rename_snapshot.old_path
                        : rename_snapshot.old_committed_read_path;
            }
            for (const auto& entry : rename_snapshot.descendant_committed_read_paths)
            {
                if (entry.node &&
                    !entry.node->is_directory &&
                    entry.node->committed_read_path.empty())
                {
                    entry.node->committed_read_path = entry.old_path;
                }
            }
            if (!TryCoalesceDeferredRenameRollbackPlanLocked(c, rename_snapshot))
            {
                c->deferred_rename_rollback_plans.push_back(rename_snapshot);
            }
        }
        c->deferred_rename_commit_count.fetch_add(1, std::memory_order_relaxed);
        RequestDeferredCloseCommit(c, deferred_rename_target);
        MarkOpenContextMutation(current_open);
        return trace_return(STATUS_SUCCESS, L"renamed-deferred");
    }

    const auto native_commit_status = DrainNativeMutationsByPolicy(c, L"Rename", false, true);
    if (!NT_SUCCESS(native_commit_status))
    {
        {
            std::lock_guard<std::mutex> lock(c->mutex);
            RollbackRenameLocalStateLocked(c, rename_snapshot);
        }
        RestoreDeferredDeleteRollbackPlans(c);
        RestoreDeferredRenameRollbackPlans(c);
        DiscardFileRollbackSnapshot(rename_snapshot.replaced_file_snapshot);
        return trace_return(native_commit_status, L"post-commit");
    }
    if (!FinalizeMutationJournalBestEffort(c, L"Rename"))
    {
        return c->write_degraded ? STATUS_MEDIA_WRITE_PROTECTED : STATUS_UNSUCCESSFUL;
    }
#endif
    DiscardFileRollbackSnapshot(rename_snapshot.replaced_file_snapshot);
    MarkOpenContextMutation(current_open);
    return trace_return(STATUS_SUCCESS, L"renamed");
}

NTSTATUS CB_SetSecurity(FSP_FILE_SYSTEM* fs, PVOID, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR)
{
    auto* c = Ctx(fs);
    ScopedCallbackActivity callback_scope(c, "SetSecurity");
    ScopedPerfTimer perf_scope(c ? &c->perf_set_security : nullptr);
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
    ScopedCallbackActivity callback_scope(c, "Cleanup");
    ScopedPerfTimer perf_scope(c ? &c->perf_cleanup : nullptr);

    auto* o = (OpenContext*)ctx;
    if (IsHostMoveTraceEnabled())
    {
        std::wostringstream message;
        message << L"Cleanup flags=0x" << std::hex << flags << std::dec
                << L" file='" << (file_name ? std::wstring(file_name) : std::wstring()) << L"'";
        if (o && o->node)
        {
            message << L" ctxPath='" << o->node->path << L"'"
                    << L" deleteOnCleanup=" << (o->delete_on_cleanup ? L"1" : L"0")
                    << L" deleteOnCloseRequested=" << (o->delete_on_close_requested ? L"1" : L"0")
                    << L" metadataFallback=" << (o->metadata_read_fallback ? L"1" : L"0")
                    << L" fileHandle=" << (o->file != INVALID_HANDLE_VALUE ? L"1" : L"0");
        }
        TraceMove(c, message.str());
    }

    if (!c || !o || !o->node)
    {
        return;
    }
    const bool cleanup_may_delete =
        IsMutationWriteEnabled(c) &&
        (((flags & FspCleanupDelete) != 0) || o->delete_on_close_requested);
    std::optional<MutationCallbackScope> mutation_scope;
    if (cleanup_may_delete)
    {
        mutation_scope.emplace(c);
    }

    if (o->file != INVALID_HANDLE_VALUE)
    {
        if (o->named_stream)
        {
            std::lock_guard<std::mutex> lock(c->mutex);
            o->stream_size = RememberNamedStreamSizeFromHandleLocked(c, o->node, o->stream_name, o->file);
        }
        CloseHandle(o->file);
        o->file = INVALID_HANDLE_VALUE;
    }

    {
        std::lock_guard<std::mutex> lock(c->mutex);
        ReleaseOpenContextAccountingLocked(c, o);
    }

    if (cleanup_may_delete)
    {
        if (MutationAdmissionIsDraining(
                c->mutation_admission_state.load(std::memory_order_acquire)))
        {
            return;
        }

        auto path = !o->node->path.empty()
            ? o->node->path
            : NormalizePath(file_name ? std::wstring(file_name) : L"\\");
        if (path != L"\\" && EnsureParentDirectoryLoadedNormalized(c, path))
        {
            auto found = FindNodeNormalized(c, path);
            if (!found)
            {
                return;
            }
            if (found->is_directory && !EnsureDirectoryLoaded(c, found))
            {
                return;
            }

            std::lock_guard<std::mutex> lock(c->mutex);
            auto node = TryGetNodeLockedNormalized(c, path);
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
                    node->delete_requested_after_children = true;
                    return;
                }
                LatchDeleteOnCleanupLocked(c, o);
            }
        }
    }
    else if (o->mutation_observed.load(std::memory_order_acquire))
    {
        TouchForegroundMutationTick(c);
    }
}

VOID CB_Close(FSP_FILE_SYSTEM* fs, PVOID ctx)
{
    auto* c = Ctx(fs);
    ScopedCallbackActivity callback_scope(c, "Close");
    ScopedPerfTimer perf_scope(c ? &c->perf_close : nullptr);

    auto* o = (OpenContext*)ctx;
    if (!o)
    {
        return;
    }
    if (TryFastCloseNonMutatingContext(c, o))
    {
        delete o;
        return;
    }

    ExternalMutationRequestScope mutation_request_scope(c);
    if (!mutation_request_scope.Acquired())
    {
        if (o->file != INVALID_HANDLE_VALUE)
        {
            CloseHandle(o->file);
            o->file = INVALID_HANDLE_VALUE;
        }
        if (c && o->node)
        {
            std::lock_guard<std::mutex> lock(c->mutex);
            ReleaseOpenContextAccountingLocked(c, o);
            if (o->delete_on_cleanup)
            {
                if (o->node->delete_intent_count > 0)
                {
                    --o->node->delete_intent_count;
                }
                o->delete_on_cleanup = false;
            }
            o->delete_on_close_requested = false;
            o->node->delete_latched = false;
            o->node->delete_requested_after_children = false;
            o->node->caller_delete_retry_required = false;
            RefreshDeletePendingStateLocked(c, o->node);
        }
        delete o;
        return;
    }

    MutationCallbackScope mutation_scope(c);
    if (o->file != INVALID_HANDLE_VALUE)
    {
        if (o->named_stream)
        {
            std::lock_guard<std::mutex> lock(c->mutex);
            o->stream_size = RememberNamedStreamSizeFromHandleLocked(c, o->node, o->stream_name, o->file);
        }
        CloseHandle(o->file);
        o->file = INVALID_HANDLE_VALUE;
    }

    bool had_delete_on_cleanup = false;
    struct DeleteClosePlan
    {
        bool emit = false;
        std::wstring path;
        std::shared_ptr<Node> node;
        std::shared_ptr<Node> parent;
        std::wstring leaf;
        LocalFileRollbackSnapshot file_snapshot;
        std::vector<DeleteRollbackSubtreeEntry> subtree_snapshots;
        apfsaccess::rw::MetadataStore::PayloadIdentity staged_identity{};
        bool metadata_staged = false;
        bool journal_recorded = false;
    };
    std::vector<DeleteClosePlan> delete_plans;
    bool remove_requested_on_close = false;
    bool can_remove_on_close = false;
    std::shared_ptr<Node> delete_root;
    std::vector<std::shared_ptr<Node>> delete_postorder;
    apfsaccess::rw::MetadataStore::PayloadIdentity delete_identity{};
    std::shared_ptr<Node> deferred_delete_root;
    std::vector<std::shared_ptr<Node>> deferred_delete_postorder;
    apfsaccess::rw::MetadataStore::PayloadIdentity deferred_delete_identity{};
    const auto release_delete_on_cleanup_locked = [&]()
    {
        if (o->delete_on_cleanup)
        {
            if (o->node && o->node->delete_intent_count > 0)
            {
                --o->node->delete_intent_count;
            }
            o->delete_on_cleanup = false;
            RefreshDeletePendingStateLocked(c, o->node);
        }
    };
    if (c && o->node)
    {
        std::lock_guard<std::mutex> lock(c->mutex);
        remove_requested_on_close =
            o->delete_on_cleanup ||
            o->node->delete_latched ||
            (o->node->is_directory &&
                o->node->delete_requested_after_children &&
                !o->node->caller_delete_retry_required);
        if (o->delete_on_cleanup)
        {
            had_delete_on_cleanup = true;
        }
        ReleaseOpenContextAccountingLocked(c, o);
        RefreshDeletePendingStateLocked(c, o->node);

        can_remove_on_close =
            remove_requested_on_close &&
            o->node->path != L"\\" &&
            CollectRemovableNodePostorderLocked(c, o->node, delete_postorder);
        if (remove_requested_on_close && can_remove_on_close)
        {
            delete_root = o->node;
        }
        else
        {
            delete_postorder.clear();
            release_delete_on_cleanup_locked();
        }
    }

    if (c && delete_root && remove_requested_on_close && can_remove_on_close)
    {
#ifdef APFSACCESS_HAS_RW_ENGINE
        bool native_delete_staged = true;
        bool native_delete_metadata_staged = false;
        bool benign_stale_native_delete = false;
        if (IsNativeWriteEnabled(c))
        {
            native_delete_staged = StageNativeDeletePostorderBestEffort(
                c,
                delete_postorder,
                nullptr,
                &delete_identity,
                &native_delete_metadata_staged);
        }
        if (!native_delete_staged)
        {
            benign_stale_native_delete = IsBenignStaleDeletedDeleteFailure(c, delete_root);
            if (!benign_stale_native_delete)
            {
                (void)BlockNativeMutationAfterStagingFailure(
                    c,
                    L"Delete",
                    native_delete_metadata_staged);
                std::lock_guard<std::mutex> lock(c->mutex);
                release_delete_on_cleanup_locked();
                delete_root->delete_latched = false;
                delete_root->delete_pending = false;
                delete_root->caller_delete_retry_required = false;
                RefreshDeletePendingStateLocked(c, delete_root);
            }
        }
        if (native_delete_staged || benign_stale_native_delete)
#endif
        {
            bool local_delete_completed = false;
            std::lock_guard<std::mutex> lock(c->mutex);
            if (TryGetNodeLockedNormalized(c, delete_root->path) == delete_root)
            {
                const auto plan_path = delete_root->path;
                auto parent_path = ParentOfNormalizedPath(plan_path);
                auto leaf = LeafNameOfNormalizedPath(plan_path);
                auto parent = TryGetNodeLockedNormalized(c, parent_path);
                DeleteClosePlan plan;
#ifdef APFSACCESS_HAS_RW_ENGINE
                const bool preserve_hydration_in_place =
                    IsNativeWriteEnabled(c);
#else
                const bool preserve_hydration_in_place = false;
#endif
                if (!CaptureDeleteRollbackSubtreeLocked(
                        c,
                        delete_postorder,
                        preserve_hydration_in_place,
                        plan.subtree_snapshots))
                {
                    delete_root->delete_latched = false;
                    delete_root->delete_pending = false;
                    delete_root->delete_requested_after_children = false;
                    delete_root->caller_delete_retry_required = false;
                    RefreshDeletePendingStateLocked(c, delete_root);
                    delete o;
                    return;
                }
                if (parent && parent->is_directory)
                {
                    RemoveChildName(*parent, leaf);
                }
                std::unordered_set<std::wstring> preserved_hydration_keys;
                if (preserve_hydration_in_place)
                {
                    for (const auto& entry : plan.subtree_snapshots)
                    {
                        if (entry.file_snapshot.hydration_preserved_in_place &&
                            !entry.file_snapshot.path_key.empty())
                        {
                            preserved_hydration_keys.insert(entry.file_snapshot.path_key);
                        }
                    }
                }
                plan.emit = RemoveNodePostorderValidatedLocked(
                    c,
                    delete_postorder,
                    nullptr,
                    preserved_hydration_keys.empty() ? nullptr : &preserved_hydration_keys);
                if (plan.emit)
                {
                    delete_root->delete_latched = false;
                    delete_root->delete_pending = false;
                    delete_root->delete_intent_count = 0;
                    delete_root->delete_requested_after_children = false;
                    delete_root->caller_delete_retry_required = false;
                    plan.path = plan_path;
                    plan.node = delete_root;
                    plan.parent = parent;
                    plan.leaf = leaf;
                    plan.staged_identity = delete_identity;
                    plan.metadata_staged = native_delete_metadata_staged;
                    if (plan.subtree_snapshots.size() == 1)
                    {
                        plan.file_snapshot = plan.subtree_snapshots.front().file_snapshot;
                        plan.subtree_snapshots.clear();
                    }
                    delete_plans.push_back(std::move(plan));
                    local_delete_completed = true;
                }
            }
            if (!local_delete_completed)
            {
                release_delete_on_cleanup_locked();
            }
        }
    }

    bool should_probe_deferred_directory_delete = false;
    if (c && o->node)
    {
        std::lock_guard<std::mutex> lock(c->mutex);
        should_probe_deferred_directory_delete =
            had_delete_on_cleanup ||
            remove_requested_on_close ||
            !delete_plans.empty() ||
            HasRecentOpenChildDeleteLocked(o->node) ||
            (o->node->is_directory &&
                (o->node->delete_requested_after_children ||
                    o->node->delete_latched ||
                    HasRecentChildDeleteLocked(o->node)));
    }

    if (c && o->node && should_probe_deferred_directory_delete)
    {
        {
            std::lock_guard<std::mutex> lock(c->mutex);
            deferred_delete_root = FindRemovableDeferredDirectoryDeletePostorderLocked(
                c,
                o->node->path,
                deferred_delete_postorder);
        }
        if (deferred_delete_root)
        {
#ifdef APFSACCESS_HAS_RW_ENGINE
            bool native_delete_staged = true;
            bool native_delete_metadata_staged = false;
            bool benign_stale_native_delete = false;
            if (IsNativeWriteEnabled(c))
            {
                native_delete_staged = StageNativeDeletePostorderBestEffort(
                    c,
                    deferred_delete_postorder,
                    nullptr,
                    &deferred_delete_identity,
                    &native_delete_metadata_staged);
            }
            if (!native_delete_staged)
            {
                benign_stale_native_delete = IsBenignStaleDeletedDeleteFailure(c, deferred_delete_root);
                if (!benign_stale_native_delete)
                {
                    (void)BlockNativeMutationAfterStagingFailure(
                        c,
                        L"Delete",
                        native_delete_metadata_staged);
                    std::lock_guard<std::mutex> lock(c->mutex);
                    deferred_delete_root->delete_requested_after_children = false;
                    deferred_delete_root->caller_delete_retry_required = false;
                    deferred_delete_root->delete_latched = false;
                    deferred_delete_root->delete_pending = false;
                    RefreshDeletePendingStateLocked(c, deferred_delete_root);
                }
            }
            if (native_delete_staged || benign_stale_native_delete)
#endif
            {
                std::lock_guard<std::mutex> lock(c->mutex);
                if (TryGetNodeLockedNormalized(c, deferred_delete_root->path) == deferred_delete_root)
                {
                    const auto plan_path = deferred_delete_root->path;
                    auto parent_path = ParentOfNormalizedPath(plan_path);
                    auto leaf = LeafNameOfNormalizedPath(plan_path);
                    auto parent = TryGetNodeLockedNormalized(c, parent_path);
                    DeleteClosePlan plan;
                    const bool preserve_hydration_in_place = IsNativeWriteEnabled(c);
                    if (!CaptureDeleteRollbackSubtreeLocked(
                            c,
                            deferred_delete_postorder,
                            preserve_hydration_in_place,
                            plan.subtree_snapshots))
                    {
                        deferred_delete_root->delete_requested_after_children = false;
                        deferred_delete_root->caller_delete_retry_required = false;
                        deferred_delete_root->delete_latched = false;
                        deferred_delete_root->delete_pending = false;
                        RefreshDeletePendingStateLocked(c, deferred_delete_root);
                        delete o;
                        return;
                    }
                    if (parent && parent->is_directory)
                    {
                        RemoveChildName(*parent, leaf);
                    }
                    std::unordered_set<std::wstring> preserved_hydration_keys;
                    if (preserve_hydration_in_place)
                    {
                        for (const auto& entry : plan.subtree_snapshots)
                        {
                            if (entry.file_snapshot.hydration_preserved_in_place &&
                                !entry.file_snapshot.path_key.empty())
                            {
                                preserved_hydration_keys.insert(entry.file_snapshot.path_key);
                            }
                        }
                    }
                    plan.emit = RemoveNodePostorderValidatedLocked(
                        c,
                        deferred_delete_postorder,
                        nullptr,
                        preserved_hydration_keys.empty() ? nullptr : &preserved_hydration_keys);
                    if (plan.emit)
                    {
                        deferred_delete_root->delete_latched = false;
                        deferred_delete_root->delete_pending = false;
                        deferred_delete_root->delete_intent_count = 0;
                        deferred_delete_root->delete_requested_after_children = false;
                        deferred_delete_root->caller_delete_retry_required = false;
                        plan.path = plan_path;
                        plan.node = deferred_delete_root;
                        plan.parent = parent;
                        plan.leaf = leaf;
                        plan.staged_identity = deferred_delete_identity;
                        plan.metadata_staged = native_delete_metadata_staged;
                        if (plan.subtree_snapshots.size() == 1)
                        {
                            plan.file_snapshot = plan.subtree_snapshots.front().file_snapshot;
                            plan.subtree_snapshots.clear();
                        }
                        delete_plans.push_back(std::move(plan));
                    }
                }
            }
        }
    }

#ifdef APFSACCESS_HAS_RW_ENGINE
    bool delete_journal_failed = false;
    if (!delete_plans.empty() && c)
    {
        const bool mutation_write_enabled = IsMutationWriteEnabled(c);
        for (auto& plan : delete_plans)
        {
            if (!plan.metadata_staged)
            {
                plan.journal_recorded = true;
                continue;
            }
            if (!mutation_write_enabled)
            {
                delete_journal_failed = true;
                continue;
            }
            const bool has_identity =
                plan.staged_identity.object_id != 0 &&
                plan.staged_identity.generation != 0;
            plan.journal_recorded = has_identity && RecordMutationBestEffort(
                c,
                apfsaccess::rw::TransactionManager::MutationKind::Delete,
                plan.path,
                L"",
                0,
                0,
                false,
                0,
                0,
                &plan.staged_identity);
            delete_journal_failed = delete_journal_failed || !plan.journal_recorded;
        }
    }
    if (delete_journal_failed)
    {
        (void)BlockNativeMutationAfterStagingFailure(c, L"Delete", true);
        {
            std::lock_guard<std::mutex> lock(c->mutex);
            for (auto it = delete_plans.rbegin(); it != delete_plans.rend(); ++it)
            {
                DeferredDeleteRollbackPlan rollback_plan{};
                rollback_plan.emit = it->emit;
                rollback_plan.path = std::move(it->path);
                rollback_plan.node = std::move(it->node);
                rollback_plan.parent = std::move(it->parent);
                rollback_plan.leaf = std::move(it->leaf);
                rollback_plan.file_snapshot = std::move(it->file_snapshot);
                rollback_plan.subtree_snapshots = std::move(it->subtree_snapshots);
                RestoreDeleteRollbackPlanLocked(c, rollback_plan);
                DiscardDeleteRollbackPlanSnapshots(rollback_plan, false);
            }
        }
        AbortMutationJournalBestEffort(c, L"Close");
        delete o;
        return;
    }

    // A file-only delete already has a complete local rollback plan and a
    // durable WAL record. Keep that evidence until the canonical checkpoint,
    // so a burst of independent file deletes does not pay one full APFS
    // checkpoint per handle close. Directory/subtree deletes and mixed
    // transactions remain synchronous barriers.
    const bool can_defer_file_delete_close =
        c &&
        IsMutationWriteEnabled(c) &&
        IsDeferCloseCommitsEnabled() &&
        !delete_plans.empty() &&
        !HasOpenWriteHandles(c) &&
        PendingNativeMutationsAreDeletesOnly(c) &&
        std::all_of(
            delete_plans.begin(),
            delete_plans.end(),
            [](const DeleteClosePlan& plan)
            {
                return plan.node && !plan.node->is_directory;
            });
    if (can_defer_file_delete_close)
    {
        std::uint64_t deferred_delete_target = 0;
        if (!AcceptMutationJournalForDeferredCommitBestEffort(
                c,
                L"DeleteDeferredAccept",
                &deferred_delete_target,
                nullptr,
                &mutation_scope))
        {
            (void)BlockNativeMutationAfterStagingFailure(c, L"Delete", true);
            {
                std::lock_guard<std::mutex> lock(c->mutex);
                for (auto it = delete_plans.rbegin(); it != delete_plans.rend(); ++it)
                {
                    DeferredDeleteRollbackPlan rollback_plan{};
                    rollback_plan.emit = it->emit;
                    rollback_plan.path = std::move(it->path);
                    rollback_plan.node = std::move(it->node);
                    rollback_plan.parent = std::move(it->parent);
                    rollback_plan.leaf = std::move(it->leaf);
                    rollback_plan.file_snapshot = std::move(it->file_snapshot);
                    rollback_plan.subtree_snapshots = std::move(it->subtree_snapshots);
                    RestoreDeleteRollbackPlanLocked(c, rollback_plan);
                    DiscardDeleteRollbackPlanSnapshots(rollback_plan, false);
                }
            }
            AbortMutationJournalBestEffort(c, L"DeleteDeferredAccept");
            delete o;
            return;
        }

        {
            std::lock_guard<std::mutex> lock(c->mutex);
            for (auto& plan : delete_plans)
            {
                DeferredDeleteRollbackPlan rollback_plan{};
                rollback_plan.emit = plan.emit;
                rollback_plan.path = std::move(plan.path);
                rollback_plan.node = std::move(plan.node);
                rollback_plan.parent = std::move(plan.parent);
                rollback_plan.leaf = std::move(plan.leaf);
                rollback_plan.file_snapshot = std::move(plan.file_snapshot);
                rollback_plan.subtree_snapshots = std::move(plan.subtree_snapshots);
                AppendDeferredDeleteRollbackPlanLocked(c, std::move(rollback_plan));
            }
        }
        RequestDeferredCloseCommit(c, deferred_delete_target);
        delete o;
        return;
    }

    const bool read_fallback_close_without_mutation =
        o->metadata_read_fallback && delete_plans.empty();
    if (c && IsMutationWriteEnabled(c) && !read_fallback_close_without_mutation)
    {
        const auto close_barrier = apfsaccess::rw::WritePipeline::RequestBarrier({
            IsMutationWriteEnabled(c),
            HasPendingNativeMutations(c),
            !delete_plans.empty(),
            false,
            L"Close",
        });
        const auto close_drain = apfsaccess::rw::WritePipeline::DrainNow(close_barrier);
        std::uint64_t deferred_close_target = 0;
        bool deferred_close_accepted = false;
        bool grouped_deferred_request_handled = false;
        bool grouped_deferred_failure_handled = false;
        if (close_barrier.urgency == NativeCommitUrgency::FileContentCloseCanDelay &&
            delete_plans.empty() &&
            (PendingNativeMutationsCanDelayClose(c) ||
                (c->close_commit_deferred.load(std::memory_order_acquire) &&
                    PendingNativeMutationsCanContinueDeferredClose(c))) &&
            IsDeferCloseCommitsEnabled())
        {
            if (PendingNativeMutationsCanDelayClose(c))
            {
                deferred_close_accepted = AcceptMutationJournalForGroupedDeferredCommitBestEffort(
                    c,
                    mutation_scope,
                    L"CloseDeferredAccept",
                    &deferred_close_target,
                    &grouped_deferred_request_handled,
                    &grouped_deferred_failure_handled);
            }
        }
        if (!close_drain.should_commit_now)
        {
            (void)ClearStaleNativeDirtyMarkerIfClean(c);
        }
        else if (deferred_close_accepted)
        {
            if (!grouped_deferred_request_handled)
            {
                RequestDeferredCloseCommit(c, deferred_close_target);
            }
        }
        else if (grouped_deferred_failure_handled)
        {
            // The grouped finisher already retained evidence and failed the mount closed.
        }
        else
        {
            const auto close_commit_status = DrainNativeMutationsByPolicy(c, L"Close", !delete_plans.empty(), false);
            if (!NT_SUCCESS(close_commit_status))
            {
                std::wcerr << L"[FsHost] RW native-commit warning (Close): finalize-on-close commit failed with status 0x"
                    << std::hex << static_cast<unsigned long>(close_commit_status) << std::dec
                    << L"." << std::endl;
                std::lock_guard<std::mutex> lock(c->mutex);
                for (auto it = delete_plans.rbegin(); it != delete_plans.rend(); ++it)
                {
                    DeferredDeleteRollbackPlan rollback_plan{};
                    rollback_plan.emit = it->emit;
                    rollback_plan.path = std::move(it->path);
                    rollback_plan.node = std::move(it->node);
                    rollback_plan.parent = std::move(it->parent);
                    rollback_plan.leaf = std::move(it->leaf);
                    rollback_plan.file_snapshot = std::move(it->file_snapshot);
                    rollback_plan.subtree_snapshots = std::move(it->subtree_snapshots);
                    RestoreDeleteRollbackPlanLocked(c, rollback_plan);
                    DiscardDeleteRollbackPlanSnapshots(rollback_plan, false);
                }
                AbortMutationJournalBestEffort(c, L"Close");
                delete o;
                return;
            }
            const auto finalized = FinalizeMutationJournalBestEffort(c, L"Close");
            if (!finalized)
            {
                std::wcerr << L"[FsHost] RW journal warning (Close): finalization failure was surfaced and recovery evidence was retained." << std::endl;
            }
            for (auto& plan : delete_plans)
            {
                DeferredDeleteRollbackPlan cleanup_plan{};
                cleanup_plan.file_snapshot = std::move(plan.file_snapshot);
                cleanup_plan.subtree_snapshots = std::move(plan.subtree_snapshots);
                DiscardDeleteRollbackPlanSnapshots(cleanup_plan, true);
            }
        }
    }
#endif
    delete o;
}

#ifdef APFSACCESS_HAS_RW_ENGINE
bool ReadCommittedFileRangeWithoutMetadataLock(
    MountContext* c,
    const std::wstring& canonical_path_key,
    const std::wstring& trace_path,
    std::uint64_t offset,
    std::size_t bytes_to_read,
    std::byte* destination,
    std::size_t destination_size,
    std::size_t& out_bytes_read)
{
    out_bytes_read = 0;
    if (!c || !c->metadata_store)
    {
        return false;
    }

    // The shared gate pins the committed physical extents while the plan is
    // copied and while the device read runs. Commit takes the exclusive side
    // of the same gate before changing or reusing those extents.
    std::shared_lock<std::shared_mutex> read_gate(c->committed_read_gate);
    std::optional<apfsaccess::rw::MetadataStore::CommittedFileReadPlan> plan;
    {
        ObservedMutexGuard metadata_lock(
            c->metadata_mutex,
            &c->perf_metadata_mutex_wait,
            &c->perf_metadata_mutex_hold);
        plan = c->metadata_store->SnapshotCommittedFileReadPlan(canonical_path_key);
    }
    if (!plan.has_value())
    {
        return false;
    }

#ifdef APFSACCESS_FSHOST_UNIT_TEST
    if (g_hydration_read_before_io_hook != nullptr)
    {
        g_hydration_read_before_io_hook(c);
    }
#endif

    return c->metadata_store->ReadCommittedFileRangeFromPlan(
        *plan,
        trace_path,
        offset,
        bytes_to_read,
        destination,
        destination_size,
        out_bytes_read);
}
#endif

NTSTATUS CB_Read(FSP_FILE_SYSTEM* fs, PVOID ctx, PVOID buf, UINT64 off, ULONG len, PULONG done)
{
    auto* c = Ctx(fs);
    ScopedCallbackActivity callback_scope(c, "Read");
    ScopedPerfTimer perf_scope(c ? &c->perf_read : nullptr);

    auto* o = (OpenContext*)ctx;
    const auto trace_return = [&](NTSTATUS status, const std::wstring& detail = std::wstring()) -> NTSTATUS
    {
        if (IsHostMoveTraceEnabled())
        {
            std::wostringstream message;
            message << L"Read status=" << FormatNtStatus(status)
                    << L" off=" << off
                    << L" len=" << len
                    << L" done=" << (done ? *done : 0);
            if (o && o->node)
            {
                message << L" path='" << o->node->path << L"'"
                        << L" allowRead=" << (o->allow_read_data ? L"1" : L"0")
                        << L" metadataFallback=" << (o->metadata_read_fallback ? L"1" : L"0")
                        << L" fileHandle=" << (o->file != INVALID_HANDLE_VALUE ? L"1" : L"0");
            }
            if (!detail.empty())
            {
                message << L" detail='" << detail << L"'";
            }
            TraceMove(c, message.str());
        }
        return status;
    };
    if (!o || !o->node || o->node->is_directory || !buf || !done)
    {
        return trace_return(STATUS_INVALID_PARAMETER, L"invalid-args");
    }
    if (!o->allow_read_data)
    {
        return trace_return(STATUS_ACCESS_DENIED, L"permission");
    }

#ifdef APFSACCESS_HAS_RW_ENGINE
    if (!o->named_stream && c && c->metadata_store)
    {
        const auto is_hydration_stale = [&]()
        {
            std::lock_guard<std::mutex> lock(c->mutex);
            return IsHydrationStaleLocked(c, o->node);
        };
        const auto has_dirty_payload_read_state = [&]()
        {
            return o->metadata_read_fallback ||
                c->pending_native_writes.load(std::memory_order_acquire) ||
                c->recovery_active.load(std::memory_order_acquire) ||
                c->write_degraded.load(std::memory_order_acquire) ||
                c->unjournaled_native_mutation.load(std::memory_order_acquire) ||
                is_hydration_stale();
        };
        if (has_dirty_payload_read_state())
        {
            const auto serve_stale_or_deferred_spool_read = [&]() -> std::optional<std::size_t>
            {
                const auto committed_read_path = SnapshotCommittedReadPathForNode(c, o->node);
                const auto visible_path_key = NodePathKey(*o->node);
                const auto committed_read_path_key = LowerPathKey(committed_read_path);
                const auto payload_spool_identities = ResolvePayloadSpoolIdentitiesForCanonicalKeys(
                    c,
                    o->node->path,
                    visible_path_key,
                    committed_read_path,
                    committed_read_path_key,
                    o);
                std::size_t bytes_read = 0;
                if (ReadPayloadSpoolRangeIfFullyCoveredForReadPathsWithIdentities(
                        c,
                        o->node->path,
                        payload_spool_identities,
                        o->node->file_size,
                        off,
                        len,
                        reinterpret_cast<std::byte*>(buf),
                        bytes_read))
                {
                    return bytes_read;
                }

                bool read_ok = false;
                read_ok = ReadCommittedFileRangeWithoutMetadataLock(
                    c,
                    committed_read_path_key,
                    committed_read_path,
                    off,
                    static_cast<std::size_t>(len),
                    reinterpret_cast<std::byte*>(buf),
                    static_cast<std::size_t>(len),
                    bytes_read);
                if (!read_ok)
                {
                    return std::nullopt;
                }

                const auto committed_bytes_read = bytes_read;
                if (committed_bytes_read < static_cast<std::size_t>(len))
                {
                    std::fill(
                        reinterpret_cast<std::byte*>(buf) + static_cast<std::ptrdiff_t>(committed_bytes_read),
                        reinterpret_cast<std::byte*>(buf) + static_cast<std::ptrdiff_t>(len),
                        std::byte{0});
                }
                std::uint64_t spool_logical_end = 0;
                if (!OverlayPayloadSpoolForReadPathsWithIdentitiesAndLogicalEnd(
                        c,
                        o->node->path,
                        payload_spool_identities,
                        off,
                        reinterpret_cast<std::byte*>(buf),
                        static_cast<std::size_t>(len),
                        spool_logical_end))
                {
                    return std::nullopt;
                }
                const auto requested_end = off + static_cast<std::uint64_t>(len);
                bytes_read = committed_bytes_read;
                if (spool_logical_end > static_cast<std::uint64_t>(committed_bytes_read) + off &&
                    requested_end > static_cast<std::uint64_t>(committed_bytes_read) + off)
                {
                    const auto extended_bytes = static_cast<std::size_t>(std::min<std::uint64_t>(
                        requested_end,
                        spool_logical_end) - off);
                    if (extended_bytes <= static_cast<std::size_t>(len))
                    {
                        bytes_read = extended_bytes;
                    }
                }

            return bytes_read;
            };

            const auto hydration_stale = is_hydration_stale();
            if (hydration_stale)
            {
                const auto bytes_read = serve_stale_or_deferred_spool_read();
                if (bytes_read.has_value())
                {
                    *done = static_cast<ULONG>(*bytes_read);
                    return trace_return(STATUS_SUCCESS, L"stale-or-deferred");
                }
            }

            if (o->metadata_read_fallback)
            {
                const auto bytes_read = serve_stale_or_deferred_spool_read();
                if (!bytes_read.has_value())
                {
                    *done = 0;
                    return trace_return(STATUS_UNSUCCESSFUL, L"metadata-fallback-miss");
                }

                *done = static_cast<ULONG>(*bytes_read);
                return trace_return(STATUS_SUCCESS, L"metadata-fallback");
            }
        }
    }
#endif

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
                return trace_return(STATUS_SUCCESS, L"eof");
            }
            return trace_return(STATUS_UNSUCCESSFUL, L"readfile");
        }
        const auto needs_payload_overlay = c &&
            (o->metadata_read_fallback ||
             c->pending_native_writes.load(std::memory_order_acquire) ||
             c->recovery_active.load(std::memory_order_acquire) ||
             c->write_degraded.load(std::memory_order_acquire) ||
             c->unjournaled_native_mutation.load(std::memory_order_acquire));
        if (!o->named_stream &&
            needs_payload_overlay &&
            [&]()
            {
                const auto visible_path_key = NodePathKey(*o->node);
                const auto payload_spool_identity = ResolvePayloadSpoolIdentitiesForCanonicalKeys(
                    c,
                    o->node->path,
                    visible_path_key,
                    o->node->path,
                    visible_path_key,
                    o).visible;
                return payload_spool_identity.has_value() &&
                    !OverlayPayloadSpoolBestEffort(
                        c,
                        o->node->path,
                        *payload_spool_identity,
                        off,
                        reinterpret_cast<std::byte*>(buf),
                        static_cast<std::size_t>(read));
            }())
        {
            *done = 0;
            return trace_return(STATUS_UNSUCCESSFUL, L"spool-overlay");
        }
        *done = read;
        return trace_return(STATUS_SUCCESS, L"hydration");
    }

    *done = 0;
    return trace_return(STATUS_INVALID_PARAMETER, L"no-handle");
}

NTSTATUS CB_GetFileInfo(FSP_FILE_SYSTEM* fs, PVOID ctx, FSP_FSCTL_FILE_INFO* info)
{
    auto* c = Ctx(fs);
    ScopedCallbackActivity callback_scope(c, "GetFileInfo");
    ScopedPerfTimer perf_scope(c ? &c->perf_get_file_info : nullptr);
    auto* o = (OpenContext*)ctx;
    if (!c || !o || !o->node || !info) return STATUS_INVALID_PARAMETER;
    FillInfo(*o->node, !IsMutationWriteEnabled(c), info);
    return STATUS_SUCCESS;
}

NTSTATUS CB_Flush(FSP_FILE_SYSTEM* fs, PVOID ctx, FSP_FSCTL_FILE_INFO* info)
{
    auto* c = Ctx(fs);
    ScopedCallbackActivity callback_scope(c, "Flush");
    ScopedPerfTimer perf_scope(c ? &c->perf_flush : nullptr);

    auto* o = (OpenContext*)ctx;
    const bool volume_flush = o == nullptr;
    if (!c || (!volume_flush && (!o->node || !info))) return STATUS_INVALID_PARAMETER;
    MutationCallbackScope mutation_scope(c);

    if (!volume_flush && o->named_stream)
    {
        if (o->file != INVALID_HANDLE_VALUE)
        {
            FlushFileBuffers(o->file);
            std::lock_guard<std::mutex> lock(c->mutex);
            o->stream_size = RememberNamedStreamSizeFromHandleLocked(c, o->node, o->stream_name, o->file);
        }
        FillInfo(*o->node, !IsMutationWriteEnabled(c), info);
        return STATUS_SUCCESS;
    }

    std::optional<ExternalMutationRequestScope> mutation_request_scope;
    if (IsMutationWriteEnabled(c))
    {
        mutation_request_scope.emplace(c);
        if (!mutation_request_scope->Acquired())
        {
            return STATUS_VOLUME_DISMOUNTED;
        }
    }

#ifdef APFSACCESS_HAS_RW_ENGINE
    if (c && IsMutationWriteEnabled(c))
    {
        const auto native_commit_status = CommitNativeMutationsOnFlushBestEffort(c);
        if (!NT_SUCCESS(native_commit_status))
        {
            RestoreDeferredDeleteRollbackPlans(c);
            RestoreDeferredRenameRollbackPlans(c);
            AbortMutationJournalBestEffort(c, L"Flush");
            return native_commit_status;
        }
        if (!FinalizeMutationJournalBestEffort(c, L"Flush"))
        {
            return c->write_degraded ? STATUS_MEDIA_WRITE_PROTECTED : STATUS_UNSUCCESSFUL;
        }
    }
#endif
    if (!volume_flush)
    {
        FillInfo(*o->node, !IsMutationWriteEnabled(c), info);
    }
    return STATUS_SUCCESS;
}

NTSTATUS CB_GetSecurityByName(FSP_FILE_SYSTEM* fs, PWSTR file_name, PUINT32 attrs, PSECURITY_DESCRIPTOR sd, SIZE_T* sz)
{
    auto* c = Ctx(fs);
    ScopedCallbackActivity callback_scope(c, "GetSecurityByName");
    ScopedPerfTimer perf_scope(c ? &c->perf_get_security_by_name : nullptr);
    if (!c || !sz) return STATUS_INVALID_PARAMETER;
    auto p = NormalizePath(file_name ? std::wstring(file_name) : L"\\");
    auto stream_path = SplitNamedStreamPathNormalized(p);
    auto lookup_path = stream_path.is_named_stream ? stream_path.base_path : p;
    auto n = FindNodeNormalized(c, lookup_path);
    if (!n)
    {
        ObservedMutexGuard lock(
            c->mutex,
            &c->perf_namespace_mutex_wait,
            &c->perf_namespace_mutex_hold);
        auto hidden = TryGetNodeLockedNormalized(c, lookup_path);
        if (hidden && IsDeleteBlockedStateLocked(hidden))
        {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
        if (HasDeletePendingAncestorLockedNormalized(c, lookup_path))
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
    ScopedCallbackActivity callback_scope(c, "GetSecurity");
    ScopedPerfTimer perf_scope(c ? &c->perf_get_security : nullptr);
    if (!c || !sz) return STATUS_INVALID_PARAMETER;
    if (!sd || *sz < c->sd_size) { *sz = c->sd_size; return STATUS_BUFFER_OVERFLOW; }
    std::memcpy(sd, c->sd, c->sd_size);
    *sz = c->sd_size;
    return STATUS_SUCCESS;
}

NTSTATUS CB_Open(FSP_FILE_SYSTEM* fs, PWSTR file_name, UINT32 create_options, UINT32 granted_access, PVOID* out_ctx, FSP_FSCTL_FILE_INFO* info)
{
    auto* c = Ctx(fs);
    ScopedCallbackActivity callback_scope(c, "Open");
    ScopedPerfTimer perf_scope(c ? &c->perf_open : nullptr);
    const auto trace_return = [&](NTSTATUS status, const std::wstring& detail = std::wstring(), const OpenContext* open_ctx = nullptr) -> NTSTATUS
    {
        if (IsHostMoveTraceEnabled())
        {
            std::wostringstream message;
            message << L"Open status=" << FormatNtStatus(status)
                    << L" file='" << (file_name ? std::wstring(file_name) : std::wstring()) << L"'"
                    << L" createOptions=0x" << std::hex << create_options
                    << L" granted=0x" << granted_access << std::dec;
            if (open_ctx && open_ctx->node)
            {
                message << L" ctxPath='" << open_ctx->node->path << L"'"
                        << L" allowRead=" << (open_ctx->allow_read_data ? L"1" : L"0")
                        << L" allowWrite=" << (open_ctx->allow_write_data ? L"1" : L"0")
                        << L" allowAppend=" << (open_ctx->allow_append_data ? L"1" : L"0")
                        << L" allowDelete=" << (open_ctx->allow_delete ? L"1" : L"0")
                        << L" metadataFallback=" << (open_ctx->metadata_read_fallback ? L"1" : L"0")
                        << L" fileHandle=" << (open_ctx->file != INVALID_HANDLE_VALUE ? L"1" : L"0");
            }
            if (!detail.empty())
            {
                message << L" detail='" << detail << L"'";
            }
            TraceMove(c, message.str());
        }
        return status;
    };
    if (!c || !out_ctx || !info)
    {
        return trace_return(STATUS_INVALID_PARAMETER, L"invalid-args");
    }
    if (HasConflictingCreateTypeOptions(create_options))
    {
        return trace_return(STATUS_INVALID_PARAMETER, L"conflicting-create-type");
    }

    auto p = NormalizePath(file_name ? std::wstring(file_name) : L"\\");
    auto stream_path = SplitNamedStreamPathNormalized(p);
    auto lookup_path = stream_path.is_named_stream ? stream_path.base_path : p;
    auto n = FindNodeNormalized(c, lookup_path);
    if (!n)
    {
        std::lock_guard<std::mutex> lock(c->mutex);
        auto hidden = TryGetNodeLockedNormalized(c, lookup_path);
        if ((hidden && IsDeleteBlockedStateLocked(hidden)) || HasDeletePendingAncestorLockedNormalized(c, lookup_path))
        {
            return trace_return(STATUS_DELETE_PENDING, L"hidden-delete-pending");
        }
        return trace_return(STATUS_OBJECT_NAME_NOT_FOUND, L"missing");
    }
    if (IsDeleteBlockedStateLocked(n))
    {
        return trace_return(STATUS_DELETE_PENDING, L"delete-blocked");
    }

    if (n->is_directory && (create_options & FILE_NON_DIRECTORY_FILE) != 0)
    {
        return trace_return(STATUS_FILE_IS_A_DIRECTORY, L"directory-as-file");
    }
    if (!n->is_directory && (create_options & FILE_DIRECTORY_FILE) != 0)
    {
        return trace_return(STATUS_NOT_A_DIRECTORY, L"file-as-directory");
    }

    const auto mutation_enabled = IsMutationWriteEnabled(c);
    const auto mutation_access_requested = HasOpenMutationIntent(granted_access, create_options);
    std::optional<ExternalMutationRequestScope> mutation_request_scope;
    if (mutation_access_requested)
    {
        {
            std::lock_guard<std::mutex> admission_gate(c->mutation_callback_mutex);
            mutation_request_scope.emplace(c);
        }
        if (!mutation_request_scope->Acquired())
        {
            return trace_return(STATUS_VOLUME_DISMOUNTED, L"shutdown-drain");
        }
    }

    if (!mutation_enabled && mutation_access_requested)
    {
        return trace_return(HandleMutationWriteDisabled(c, L"Open"), L"write-disabled");
    }

#ifdef APFSACCESS_HAS_RW_ENGINE
    const auto normalized_access = NormalizeGrantedAccess(granted_access);
    const bool read_payload_access_requested =
        (normalized_access & (FILE_READ_DATA | FILE_EXECUTE)) != 0;
#endif

    auto* o = new (std::nothrow) OpenContext();
    if (!o)
    {
        return trace_return(STATUS_INSUFFICIENT_RESOURCES, L"alloc");
    }
    o->node = n;
    o->named_stream = stream_path.is_named_stream;
    o->stream_name = stream_path.stream_name;
    InitializeOpenAccess(o, granted_access);
    o->delete_on_close_requested = (create_options & FILE_DELETE_ON_CLOSE) != 0;
    if (n->is_directory && o->allow_delete)
    {
        std::lock_guard<std::mutex> lock(c->mutex);
        if (TryGetNodeLockedNormalized(c, n->path) == n &&
            n->children.empty() &&
            HasRecentChildDeleteLocked(n))
        {
            SetDeleteIntentLocked(c, o, true);
        }
    }
    if (!n->is_directory)
    {
        const auto requires_hydration_handle = RequiresHydrationHandleForOpen(o);
        const auto desired_access = ResolveHydrationDesiredAccess(
            mutation_enabled,
            granted_access,
            false);
        o->write_open = mutation_enabled && mutation_access_requested;
        bool can_read_from_metadata = false;
        bool can_read_from_spool = false;
        const auto can_use_metadata_read_fallback = CanUseMetadataReadFallbackForOpen(
            o,
            create_options,
            c->metadata_store != nullptr);
        const auto has_valid_existing_hydration = [&]()
        {
            if (!requires_hydration_handle || o->named_stream)
            {
                return false;
            }

            std::uint64_t logical_size = 0;
            {
                std::lock_guard<std::mutex> lock(c->mutex);
                if (IsHydrationStaleLocked(c, n))
                {
                    return false;
                }
                logical_size = n->file_size;
            }

            WIN32_FILE_ATTRIBUTE_DATA hydration_attributes{};
            if (!GetFileAttributesExW(
                    HydrationPath(c, *n).wstring().c_str(),
                    GetFileExInfoStandard,
                    &hydration_attributes) ||
                (hydration_attributes.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
            {
                return false;
            }

            const auto cached_size =
                (static_cast<std::uint64_t>(hydration_attributes.nFileSizeHigh) << 32) |
                static_cast<std::uint64_t>(hydration_attributes.nFileSizeLow);
            return cached_size == logical_size;
        }();

#ifdef APFSACCESS_HAS_RW_ENGINE
        const auto probe_metadata_or_spool = [&]()
        {
            const auto committed_read_path = SnapshotCommittedReadPathForNode(c, n);
            const auto visible_path_key = NodePathKey(*n);
            const auto committed_read_path_key = LowerPathKey(committed_read_path);
            const auto payload_spool_identities = ResolvePayloadSpoolIdentitiesForCanonicalKeys(
                c,
                n->path,
                visible_path_key,
                committed_read_path,
                committed_read_path_key,
                o);
            const auto probe_bytes = n->file_size == 0
                ? 0
                : static_cast<std::size_t>(std::min<std::uint64_t>(n->file_size, 1));
            if (probe_bytes > 0)
            {
                std::array<std::byte, 1> probe_payload{};
                std::size_t bytes_read = 0;
                can_read_from_metadata = ReadCommittedFileRangeWithoutMetadataLock(
                    c,
                    committed_read_path_key,
                    committed_read_path,
                    0,
                    probe_bytes,
                    probe_payload.data(),
                    probe_payload.size(),
                    bytes_read) &&
                    bytes_read == probe_bytes;
                can_read_from_spool = !can_read_from_metadata &&
                    HasReadablePayloadSpoolRangeForReadPathsWithIdentities(
                        c,
                        payload_spool_identities,
                        0,
                        probe_bytes);
            }
            else
            {
                can_read_from_spool = PayloadSpoolLogicalEndForReadPathsWithIdentities(
                    c,
                    payload_spool_identities) > 0;
                can_read_from_metadata = !can_read_from_spool;
            }
        };

        if (can_use_metadata_read_fallback && !has_valid_existing_hydration)
        {
            probe_metadata_or_spool();
        }
#endif

        if (!requires_hydration_handle)
        {
            o->metadata_read_fallback = false;
        }
        else if (can_read_from_metadata || can_read_from_spool)
        {
            o->metadata_read_fallback = true;
        }
        else
        {
#ifdef APFSACCESS_HAS_RW_ENGINE
            if (!stream_path.is_named_stream &&
                read_payload_access_requested &&
                !mutation_access_requested &&
                HasPendingNativeMutations(c) &&
                HasCommittedReadPathMismatch(c, n))
            {
                MutationCallbackScope mutation_scope(c);
                const auto drain_status = DrainNativeMutationsByPolicy(c, L"Open", false, true);
                if (!NT_SUCCESS(drain_status))
                {
                    RestoreDeferredRenameRollbackPlans(c);
                    AbortMutationJournalBestEffort(c, L"Open");
                    delete o;
                    return trace_return(drain_status, L"rename-read-drain");
                }
                if (!FinalizeMutationJournalBestEffort(c, L"Open"))
                {
                    delete o;
                    return trace_return(
                        c->write_degraded ? STATUS_MEDIA_WRITE_PROTECTED : STATUS_UNSUCCESSFUL,
                        L"rename-read-finalize");
                }
            }
#endif

#ifdef APFSACCESS_HAS_RW_ENGINE
            bool hydrated_from_deferred_overlay = false;
            if (!stream_path.is_named_stream &&
                mutation_access_requested &&
                HasPayloadWriteIntent(o) &&
                IsNativeWriteEnabled(c) &&
                HasPendingNativeMutations(c) &&
                c->close_commit_deferred.load(std::memory_order_acquire) &&
                PendingNativeMutationsCanContinueDeferredClose(c))
            {
                hydrated_from_deferred_overlay = TryHydrateFromCurrentPayloadOverlay(c, n);
            }
            if (!hydrated_from_deferred_overlay)
#endif
            {
                const auto pre_open_drain_status = DrainDeferredNativeMutationsBeforePayloadOpen(c, o);
                if (!NT_SUCCESS(pre_open_drain_status))
                {
                    delete o;
                    return trace_return(pre_open_drain_status, L"pre-open-drain");
                }
            }

            if ((o->named_stream && EnsureHydrationSidecarExistsForNamedStream(c, n)) ||
                (!o->named_stream && EnsureHydrated(c, n, false)))
            {
                auto pth = o->named_stream
                    ? std::filesystem::path(HydrationStreamPath(c, *n, o->stream_name))
                    : HydrationPath(c, *n);
                const auto creation_disposition = (o->named_stream && mutation_access_requested)
                    ? OPEN_ALWAYS
                    : OPEN_EXISTING;
                o->file = CreateFileW(
                    pth.wstring().c_str(),
                    desired_access,
                    ResolveHydrationShareMode(mutation_enabled, granted_access, o->write_open),
                    nullptr,
                    creation_disposition,
                    FILE_ATTRIBUTE_NORMAL,
                    nullptr);
            }
        }

        if (!requires_hydration_handle)
        {
            // Attribute/delete-only handles do not need a local payload cache.
            // During deferred write-back the newest bytes can exist only in the
            // payload spool, so forcing hydration here makes normal copy tools
            // see a false I/O-device error while setting timestamps.
        }
        else if (o->named_stream &&
            o->file == INVALID_HANDLE_VALUE &&
            !mutation_access_requested)
        {
            const auto error = GetLastError();
            delete o;
            if (error == ERROR_FILE_NOT_FOUND ||
                error == ERROR_PATH_NOT_FOUND ||
                error == ERROR_INVALID_NAME)
            {
                return trace_return(STATUS_OBJECT_NAME_NOT_FOUND, L"named-stream-missing");
            }
            return trace_return(STATUS_IO_DEVICE_ERROR, L"named-stream-open");
        }

        if (requires_hydration_handle && o->file == INVALID_HANDLE_VALUE && !mutation_access_requested)
        {
#ifdef APFSACCESS_HAS_RW_ENGINE
            if (!can_read_from_metadata &&
                !can_read_from_spool &&
                can_use_metadata_read_fallback)
            {
                probe_metadata_or_spool();
            }

            if (can_read_from_metadata || can_read_from_spool)
            {
                o->metadata_read_fallback = true;
            }
            else
            {
                delete o;
                return trace_return(STATUS_IO_DEVICE_ERROR, L"read-fallback-unavailable");
            }
#else
            delete o;
            return trace_return(STATUS_IO_DEVICE_ERROR, L"hydration-missing");
#endif
        }
        else if (requires_hydration_handle && o->file == INVALID_HANDLE_VALUE && !o->metadata_read_fallback)
        {
            delete o;
            return trace_return(STATUS_IO_DEVICE_ERROR, L"open-no-handle");
        }

        if (o->named_stream)
        {
            std::lock_guard<std::mutex> lock(c->mutex);
            o->stream_size = RememberNamedStreamSizeFromHandleLocked(c, n, o->stream_name, o->file);
        }
    }

    {
        std::lock_guard<std::mutex> lock(c->mutex);
        AcquireOpenContextAccountingLocked(c, n, o);
    }

    FillInfo(*n, !IsMutationWriteEnabled(c), info);
    *out_ctx = o;
    return trace_return(STATUS_SUCCESS, L"opened", o);
}

NTSTATUS CB_ReadDirectory(FSP_FILE_SYSTEM* fs, PVOID dir_ctx, PWSTR, PWSTR marker, PVOID buffer, ULONG length, PULONG done)
{
    auto* c = Ctx(fs);
    ScopedCallbackActivity callback_scope(c, "ReadDirectory");
    ScopedPerfTimer perf_scope(c ? &c->perf_read_directory : nullptr);

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

    const auto mk = marker ? std::wstring(marker) : std::wstring();
    const auto read_only = !IsMutationWriteEnabled(c);
    std::vector<DirectoryEntrySnapshot> entries;
    {
        ObservedMutexGuard lock(
            c->mutex,
            &c->perf_namespace_mutex_wait,
            &c->perf_namespace_mutex_hold);
        EnsureSortedChildNamesLocked(*o->node);
        const auto& sorted_children = o->node->sorted_children;
        std::size_t first_child_index = 0;
        if (!mk.empty())
        {
            const auto marker_it = std::lower_bound(
                sorted_children.begin(),
                sorted_children.end(),
                mk,
                [](const std::wstring& name, const std::wstring& value)
                {
                    return _wcsicmp(name.c_str(), value.c_str()) < 0;
                });
            first_child_index = static_cast<std::size_t>(
                std::distance(sorted_children.begin(), marker_it));
            while (first_child_index < sorted_children.size() &&
                   _wcsicmp(sorted_children[first_child_index].c_str(), mk.c_str()) <= 0)
            {
                ++first_child_index;
            }
        }

        entries.reserve(sorted_children.size() - first_child_index);
        for (std::size_t index = first_child_index; index < sorted_children.size(); ++index)
        {
            const auto& name = sorted_children[index];
            auto child = TryGetVisibleChildNodeLocked(c, o->node, name);
            if (child)
            {
                entries.push_back({ name, child });
            }
        }
    }

    std::vector<unsigned char> dir_info_scratch;
    for (auto it = entries.begin(); it != entries.end(); ++it)
    {
        if (!AddDirectoryEntry(
            c->api,
            *it->node,
            it->name,
            read_only,
            buffer,
            length,
            done,
            dir_info_scratch))
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
        else if (IsOption(arg, L"--recovery-identity")) a.recovery_identity = NextArgValue(i, argc, argv);
        else if (IsOption(arg, L"--mount")) a.mount = NextArgValue(i, argc, argv);
        else if (IsOption(arg, L"--lifetime-file")) a.lifetime_file = NextArgValue(i, argc, argv);
        else if (IsOption(arg, L"--startup-gate-file")) a.startup_gate_file = NextArgValue(i, argc, argv);
        else if (IsOption(arg, L"--startup-gate-token")) a.startup_gate_token = NextArgValue(i, argc, argv);
        else if (IsOption(arg, L"--status-file")) a.status_file = NextArgValue(i, argc, argv);
        else if (IsOption(arg, L"--parent-pid"))
        {
            try
            {
                const auto value = NextArgValue(i, argc, argv);
                std::size_t consumed = 0;
                const auto parsed = std::stoull(value, &consumed);
                if (consumed != value.size() ||
                    parsed == 0 ||
                    parsed > std::numeric_limits<std::uint32_t>::max())
                {
                    return false;
                }
                a.parent_pid = static_cast<std::uint32_t>(parsed);
            }
            catch (...)
            {
                return false;
            }
        }
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
    if (a.mount.size() == 2 &&
        std::iswalpha(a.mount[0]) != 0 &&
        a.mount[1] == L':')
    {
        a.mount = std::wstring(1, static_cast<wchar_t>(towupper(a.mount[0]))) + L":";
    }
    bool has_mode = a.readonly || a.readwrite;
    return !a.device.empty() &&
           !a.volume.empty() &&
           !a.mount.empty() &&
           a.parent_pid != 0 &&
           !a.lifetime_file.empty() &&
           !a.startup_gate_file.empty() &&
           !a.startup_gate_token.empty() &&
           has_mode &&
           !(a.readonly && a.readwrite) &&
           (a.recovery_identity.empty() || IsValidRecoveryIdentity(a.recovery_identity));
}

bool IsDriveLetterMountPoint(const std::wstring& mount)
{
    return mount.size() == 2 &&
           mount[1] == L':' &&
           std::iswalpha(mount[0]) != 0;
}

bool IsDriveLetterRootMountPoint(const std::wstring& mount)
{
    return mount.size() == 3 &&
           mount[1] == L':' &&
           (mount[2] == L'\\' || mount[2] == L'/') &&
           std::iswalpha(mount[0]) != 0;
}

std::wstring BuildWinFspMountPoint(const std::wstring& mount)
{
    if (IsDriveLetterMountPoint(mount) || IsDriveLetterRootMountPoint(mount))
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

void ClearRecoveredMarkerIfClean(
    MountContext& ctx,
    const std::wstring& action,
    bool defer_payload_spool_latch)
{
    if (HasBlockedRecoveryEvidence(ctx))
    {
        return;
    }

    if (!ctx.pending_native_writes || !ctx.metadata_store)
    {
        return;
    }

    if (HasUnappliedAcceptedWorkBestEffort(&ctx) ||
        !CanClearNativeRecoveryStateBestEffort(&ctx))
    {
        return;
    }

    if (ctx.metadata_store->IsRecoveryRequired())
    {
        if (HasPayloadSpoolRecoveryEvidence(ctx))
        {
            LatchPayloadSpoolRecoveryRequired(ctx);
        }
        return;
    }

    auto committed_xid = ResolveCleanRecoveryCheckpointXid(*ctx.metadata_store);
    if (!CanClearDirtyMarkerAgainstCleanCheckpoint(ctx, committed_xid))
    {
        if (HasPayloadSpoolRecoveryEvidence(ctx))
        {
            LatchPayloadSpoolRecoveryRequired(ctx);
        }
        return;
    }

    if (!FlushPayloadSpoolDirtyStateBestEffort(&ctx, action.c_str()))
    {
        return;
    }

    if (HasPayloadSpoolRecoveryEvidence(ctx))
    {
        if (!defer_payload_spool_latch)
        {
            LatchPayloadSpoolRecoveryRequired(ctx);
        }
        return;
    }

    RecoveryMarkerState clean_marker{};
    clean_marker.dirty = false;
    clean_marker.last_commit_xid = committed_xid;
    if (!ctx.recovery_marker_file.empty() &&
        !PersistRecoveryMarkerState(&ctx, ctx.recovery_marker_file, clean_marker))
    {
        std::lock_guard<std::recursive_mutex> runtime_lock(ctx.runtime_state_mutex);
        ctx.pending_native_writes = true;
        ctx.recovery_active = true;
        ctx.write_degraded = true;
        ctx.native_write_enabled = false;
        ctx.overlay_write_enabled = false;
        if (ctx.runtime_recovery_reason.empty())
        {
            ctx.runtime_recovery_reason = L"RecoveryMarkerClearPersistFailed";
        }
        ctx.runtime_last_recovery_action = L"RecoveryMarkerClearBlocked";
        std::wcerr << L"[FsHost] Recovery checkpoint is clean, but the clean recovery marker could not be persisted; RW remains blocked."
            << std::endl;
        return;
    }

    {
        std::lock_guard<std::recursive_mutex> runtime_lock(ctx.runtime_state_mutex);
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
    }

    std::wcerr << L"[FsHost] Recovery marker reconciled against APFS checkpoint xid "
        << committed_xid.value()
        << L"; native write path may proceed."
        << std::endl;
}

void RefreshReportedVolumeInfoFromMetadata(MountContext& ctx)
{
    std::uint32_t allocation_unit_bytes = 0;
    std::optional<std::uint64_t> total_size_bytes;
    std::optional<std::uint64_t> free_size_bytes;
    {
        ObservedMutexGuard metadata_lock(
            ctx.metadata_mutex,
            &ctx.perf_metadata_mutex_wait,
            &ctx.perf_metadata_mutex_hold);
        if (!ctx.metadata_store)
        {
            return;
        }

        if (const auto block_size = ctx.metadata_store->BlockSizeBytes();
            block_size.has_value() && block_size.value() != 0)
        {
            allocation_unit_bytes = block_size.value();
        }
        if (const auto total_size = ctx.metadata_store->TotalSizeBytes();
            total_size.has_value())
        {
            total_size_bytes = total_size;
        }
        if (const auto free_size = ctx.metadata_store->FreeSizeBytes();
            free_size.has_value())
        {
            free_size_bytes = free_size;
        }
    }

    {
        std::lock_guard<std::mutex> volume_info_lock(ctx.reported_volume_info_mutex);
        if (allocation_unit_bytes != 0)
        {
            ctx.reported_allocation_unit_bytes = allocation_unit_bytes;
        }
        if (total_size_bytes.has_value())
        {
            ctx.reported_total_size_bytes = total_size_bytes;
        }
        if (free_size_bytes.has_value())
        {
            ctx.reported_free_size_bytes = free_size_bytes;
        }
    }
}

#endif

void PrintUsage()
{
    std::wcerr << L"Usage: ApfsAccess.FsHost --device <path> [--device-offset <bytes>] --volume <name-or-id> [--recovery-identity <immutable-id>] --mount <X:|directory> (--readonly|--readwrite) --parent-pid <pid> --lifetime-file <file> --startup-gate-file <file> --startup-gate-token <token> [--status-file <file>] [--write-backend <Disabled|Overlay|Native>] [--write-safety-level <mode>] [--write-commit-timeout <seconds>] [--write-max-dirty-transactions <count>] [--write-recovery-policy <mode>] [--write-crash-replay-mode <FailClosed|ReplayIfSafe>] [--write-require-canonical-commit <true|false>] [--write-integrity-check-on-mount <true|false>] [--allow-legacy-scaffold-for-fixtures <true|false>] [--write-disallow-scaffold-commit-on-non-fixture <true|false>] [--write-reject-scaffold-replay-blob-on-non-fixture <true|false>] [--write-require-canonical-replay-candidate-on-non-fixture <true|false>] [--validation-crash-fault-passes <count>] [--validation-crash-stage-matrix-passes <count>] [--validation-hardware-pilot-passes <count>] [--validation-hot-unplug-passes <count>] [--validation-macos-validation-passes <count>] [--validation-macos-consistency-passes <count>] [--validation-power-loss-replay-passes <count>] [--validation-power-loss-pass-verified <true|false>] [--validation-last-validated-utc <iso-8601>] [--validation-last-profile-id <id>] [--allow-raw-physical-write]" << std::endl;
}

HANDLE OpenOwningParentProcess(std::uint32_t parent_pid) noexcept
{
    if (parent_pid == 0 || parent_pid == GetCurrentProcessId())
    {
        return nullptr;
    }
    return OpenProcess(SYNCHRONIZE, FALSE, parent_pid);
}

bool OwningParentIsAlive(HANDLE parent_process) noexcept
{
    return parent_process != nullptr &&
        WaitForSingleObject(parent_process, 0) == WAIT_TIMEOUT;
}

bool WaitForStartupAuthorization(
    const Arguments& args,
    HANDLE parent_process,
    std::chrono::milliseconds timeout = kStartupAuthorizationTimeout,
    std::chrono::milliseconds poll_interval = kStartupAuthorizationPollInterval)
{
    if (args.startup_gate_file.empty() ||
        args.startup_gate_token.empty() ||
        !OwningParentIsAlive(parent_process))
    {
        return false;
    }

    const auto expected_token = WideToUtf8(args.startup_gate_token);
    const auto deadline = std::chrono::steady_clock::now() + std::max(timeout, std::chrono::milliseconds::zero());
    const auto effective_poll = std::max(poll_interval, std::chrono::milliseconds(1));
    while (true)
    {
        if (!OwningParentIsAlive(parent_process))
        {
            return false;
        }

        std::error_code ec;
        if (!std::filesystem::exists(args.startup_gate_file, ec) || ec)
        {
            return false;
        }

        const auto size = std::filesystem::file_size(args.startup_gate_file, ec);
        if (!ec && size <= 256)
        {
            std::ifstream gate(std::filesystem::path(args.startup_gate_file), std::ios::binary);
            std::string token(
                (std::istreambuf_iterator<char>(gate)),
                std::istreambuf_iterator<char>());
            if (gate.good() || gate.eof())
            {
                if (token == expected_token)
                {
                    gate.close();
                    ec.clear();
                    return OwningParentIsAlive(parent_process) &&
                        std::filesystem::remove(args.startup_gate_file, ec) &&
                        !ec;
                }
            }
        }

        if (std::chrono::steady_clock::now() >= deadline)
        {
            return false;
        }
        std::this_thread::sleep_for(effective_poll);
    }
}

bool LifetimeFileExists(const Arguments& args) noexcept
{
    if (args.lifetime_file.empty())
    {
        return false;
    }

    std::error_code ec;
    const auto exists = std::filesystem::exists(args.lifetime_file, ec);
    return !ec && exists;
}

bool PrepareLifetimeFile(const Arguments& args)
{
    // FsHost never creates its own sentinel. The owner holds a delete-on-close
    // lease so process death removes the file without child cooperation.
    return !args.lifetime_file.empty() && LifetimeFileExists(args);
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
    HANDLE parent_process = OpenOwningParentProcess(args.parent_pid);
    if (!parent_process)
    {
        std::wcerr << L"[FsHost] The owning parent process is unavailable; mount initialization cancelled."
                   << std::endl;
        return 15;
    }
    ScopeExit close_parent_process{[parent_process]()
    {
        CloseHandle(parent_process);
    }};
    if (!WaitForStartupAuthorization(args, parent_process))
    {
        std::wcerr << L"[FsHost] Parent startup authorization was not received; mount initialization cancelled."
                   << std::endl;
        return 14;
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
#ifdef APFSACCESS_HAS_RW_ENGINE
    if (args.readwrite &&
        IsWriteBackendMode(args.write_backend, L"Native") &&
        IsRawPhysicalDevicePath(args.device))
    {
        bool identity_policy_allowed = false;
        auto recovery_root = ResolveRecoveryRoot();
        if (recovery_root.empty())
        {
            LatchRecoveryIdentityStartupBlock(
                ctx,
                L"LegacyRecoveryEvidenceAmbiguous",
                L"StartupBlockedByLegacyRecoveryEvidence",
                true);
        }
        else
        {
            recovery_root /= "ApfsAccess";
            recovery_root /= "recovery";
            identity_policy_allowed = EnforceRecoveryIdentityStartupPolicy(
                ctx,
                apfsaccess::rw::PayloadSpool::ResolveDefaultRoot(),
                recovery_root);
        }

        if (!identity_policy_allowed)
        {
            std::wcerr << L"[FsHost] Immutable recovery identity policy blocked native RW startup (reason="
                << ctx.runtime_recovery_reason
                << L"); the volume will remain mounted read-only."
                << std::endl;
        }
    }
#endif
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
    if (args.readwrite && !ctx.recovery_identity_blocked.load(std::memory_order_acquire))
    {
        ctx.recovery_marker_file = BuildRecoveryMarkerPath(args);
        const auto marker_result = LoadRecoveryMarkerAtStartup(ctx);
        if (marker_result.load_status == RecoveryMarkerLoadStatus::Invalid)
        {
            std::wcerr << L"[FsHost] Recovery marker is malformed or unreadable; mounting in degraded read-only mode." << std::endl;
        }
        else if (marker_result.load_status == RecoveryMarkerLoadStatus::Loaded)
        {
            if (marker_result.state.dirty)
            {
                std::wcerr << L"[FsHost] Recovery marker detected: previous write session was not finalized cleanly." << std::endl;
                if (marker_result.action == LoadedRecoveryMarkerAction::FailClosed)
                {
                    std::wcerr << L"[FsHost] Recovery policy is FailClosed; mounting in degraded read-only mode." << std::endl;
                }
                else if (marker_result.action == LoadedRecoveryMarkerAction::ReplayIfSafe)
                {
                    std::wcerr << L"[FsHost] Recovery policy is FailClosed with ReplayIfSafe; native recovery will be attempted before write mode is downgraded." << std::endl;
                }
                else if (marker_result.action == LoadedRecoveryMarkerAction::BestEffort)
                {
                    std::wcerr << L"[FsHost] Recovery policy is BestEffort; native write path remains enabled with recovery-active status." << std::endl;
                }
            }
        }
    }
#endif

        (void)WriteHostStatusFile(ctx);

#ifdef APFSACCESS_HAS_RW_ENGINE
    bool payload_spool_recovery_pending = false;
    bool write_ahead_log_recovery_pending = false;
    if (args.readwrite && !ctx.recovery_identity_blocked.load(std::memory_order_acquire))
    {
        const auto wal_volume_identity = BuildWalVolumeIdentity(args);
        const auto spool_root = BuildPayloadSpoolSessionRoot(
            args,
            apfsaccess::rw::PayloadSpool::ResolveDefaultRoot());
        ctx.tx_journal_file = spool_root / "write-ahead.wal";
        ctx.tx_manager = std::make_unique<apfsaccess::rw::TransactionManager>(args.write_safety_level);
        ctx.tx_manager->SetVolumeIdentity(wal_volume_identity);
        ctx.tx_manager->SetJournalPath(ctx.tx_journal_file.wstring());
        const auto recovered_watermarks = ctx.tx_manager->Watermarks();
        write_ahead_log_recovery_pending =
            !ctx.tx_manager->RecoveryStateValid() ||
            ctx.tx_manager->HasUnappliedAcceptedWork() ||
            recovered_watermarks.cleanup_sequence < recovered_watermarks.apfs_durable_sequence;
        (void)ArmRecoveryMarkerForPendingWriteAheadLog(
            ctx,
            write_ahead_log_recovery_pending);
        std::wcerr << L"[FsHost] RW journal path: " << ctx.tx_journal_file.wstring() << std::endl;

        ctx.payload_spool_volume_identity = WideToUtf8(wal_volume_identity);
        ctx.payload_spool = std::make_unique<apfsaccess::rw::PayloadSpool>(
            apfsaccess::rw::PayloadSpool::Options{
                spool_root,
                ctx.payload_spool_volume_identity,
                kPayloadSpoolMaxBytes,
                kPayloadSpoolForegroundFlushBytes,
                kPayloadSpoolForegroundFlushAppends,
            });
        if (ctx.payload_spool->RecoveryRequired())
        {
            payload_spool_recovery_pending = true;
            std::wcerr << L"[FsHost] RW payload spool recovery was detected; metadata bootstrap will attempt clean-checkpoint reconciliation before downgrading."
                << std::endl;
        }
        std::wcerr << L"[FsHost] RW payload spool path: "
            << ctx.payload_spool->SpoolFilePath().wstring()
            << std::endl;
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
        ctx.metadata_store->SetFilePayloadRangeProvider(
            [&ctx](
                const std::wstring& path,
                apfsaccess::rw::MetadataStore::PayloadIdentity identity,
                std::uint64_t offset,
                std::span<std::byte> destination) -> bool
            {
                // Commit callbacks run under metadata locks; read only the
                // requested hydrated range and let sparse tail bytes stay zero.
                return ReadHydratedPayloadRangeForPath(&ctx, path, identity, offset, destination);
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
            },
            false);
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
                RecordVolumeStateBootstrapFailure(ctx);
            }
            else if (!args.readwrite)
            {
                RefreshReportedVolumeInfoFromMetadata(ctx);
            }
            else if (HasBlockedRecoveryEvidence(ctx))
            {
                RefreshReportedVolumeInfoFromMetadata(ctx);
            }
            else if (ctx.native_write_enabled && !ctx.metadata_store->PrepareNativeWritePath())
            {
                RefreshReportedVolumeInfoFromMetadata(ctx);
                auto recovery_reason = ctx.metadata_store->RecoveryReason();
                if (recovery_reason.empty())
                {
                    recovery_reason = L"NativeWriteBootstrapFailed";
                }
                const auto fail_closed = IsRecoveryPolicyFailClosed(args.write_recovery_policy);
                {
                    std::lock_guard<std::recursive_mutex> runtime_lock(ctx.runtime_state_mutex);
                    ctx.recovery_active = true;
                    ctx.runtime_recovery_reason = std::move(recovery_reason);
                    ctx.runtime_last_recovery_action = fail_closed
                        ? L"BootstrapFailClosed"
                        : L"BootstrapFailed";
                    if (fail_closed)
                    {
                        ctx.write_degraded = true;
                        ctx.native_write_enabled = false;
                        ctx.overlay_write_enabled = false;
                    }
                }
                std::wcerr << L"[FsHost] RW native write bootstrap warning: metadata write path is not ready; mutating operations will remain blocked." << std::endl;
                if (fail_closed)
                {
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
                    const auto recovery_still_required =
                        ctx.metadata_store->IsRecoveryRequired() || recovery_before_replay;
                    if (recovery_still_required)
                    {
                        auto recovery_reason = ctx.metadata_store->RecoveryReason();
                        if (recovery_reason.empty())
                        {
                            recovery_reason = L"RecoveryReplayFailed";
                        }
                        const auto fail_closed =
                            ctx.native_write_enabled &&
                            IsRecoveryPolicyFailClosed(args.write_recovery_policy);
                        {
                            std::lock_guard<std::recursive_mutex> runtime_lock(ctx.runtime_state_mutex);
                            ctx.recovery_active = true;
                            ctx.runtime_recovery_reason = std::move(recovery_reason);
                            ctx.runtime_last_recovery_action =
                                IsRecoveryPolicyFailClosed(args.write_recovery_policy)
                                ? L"ReplaySkippedFailClosed"
                                : L"ReplaySkipped";
                            if (fail_closed)
                            {
                                ctx.write_degraded = true;
                                ctx.native_write_enabled = false;
                                ctx.overlay_write_enabled = false;
                            }
                        }
                        std::wcerr << L"[FsHost] RW recovery warning: replay/recovery could not clear recovery-required state." << std::endl;
                        if (fail_closed)
                        {
                            std::wcerr << L"[FsHost] Recovery policy is FailClosed; replay failure downgraded mount to read-only mode." << std::endl;
                        }
                    }
                }
                else if (recovery_before_replay && !ctx.metadata_store->IsRecoveryRequired())
                {
                    {
                        std::lock_guard<std::recursive_mutex> runtime_lock(ctx.runtime_state_mutex);
                        ctx.recovery_active = false;
                        ctx.runtime_recovery_reason.clear();
                        ctx.runtime_last_recovery_action = L"ReplayApplied";
                    }
                    std::wcerr << L"[FsHost] RW recovery replay applied successfully; checkpoint state reconciled." << std::endl;
                    ClearRecoveredMarkerIfClean(
                        ctx,
                        L"RecoveryMarkerClearedAfterReplay",
                        payload_spool_recovery_pending);
                }
                else if (replay_result)
                {
                    ClearRecoveredMarkerIfClean(
                        ctx,
                        L"RecoveryMarkerClearedAfterReplay",
                        payload_spool_recovery_pending);
                }

                if (ctx.metadata_store->IsRecoveryRequired())
                {
                    const auto recovery_reason = ctx.metadata_store->RecoveryReason();
                    const auto fail_closed =
                        ctx.native_write_enabled &&
                        IsRecoveryPolicyFailClosed(args.write_recovery_policy);
                    {
                        std::lock_guard<std::recursive_mutex> runtime_lock(ctx.runtime_state_mutex);
                        ctx.recovery_active = true;
                        ctx.runtime_recovery_reason = recovery_reason;
                        ctx.runtime_last_recovery_action = L"RecoveryRequiredBlock";
                        if (fail_closed)
                        {
                            ctx.write_degraded = true;
                            ctx.native_write_enabled = false;
                            ctx.overlay_write_enabled = false;
                        }
                    }
                    std::wcerr << L"[FsHost] RW recovery reconciliation: metadata store reported recovery-required state (reason="
                        << recovery_reason
                        << L")."
                        << std::endl;

                    if (fail_closed)
                    {
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
                std::lock_guard<std::recursive_mutex> runtime_lock(ctx.runtime_state_mutex);
                ctx.runtime_last_commit_xid = committed_xid;
            }
        }
        if (write_ahead_log_recovery_pending &&
            ctx.native_write_enabled &&
            ReplayAcceptedWriteAheadLogAfterMetadataBootstrap(ctx))
        {
            write_ahead_log_recovery_pending = false;
            payload_spool_recovery_pending = ctx.payload_spool && ctx.payload_spool->RecoveryRequired();
            std::wcerr << L"[FsHost] Accepted-write replay completed and cleanup watermarks converged."
                << std::endl;
        }
        ReconcilePayloadSpoolRecoveryAfterMetadataBootstrap(ctx, payload_spool_recovery_pending);
        ReconcileWriteAheadLogRecoveryAfterMetadataBootstrap(ctx, write_ahead_log_recovery_pending);
        (void)WriteHostStatusFile(ctx);
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
    SetNodePath(*root, L"\\");
    root->hydration_key = root->path_key;
    root->apfs_path = ApfsRoot(args);
    root->is_directory = true;
    root->timestamp = now;
    EmplaceNodeLocked(&ctx, root);

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
        std::wstring root_failure_reason;
        {
            std::lock_guard<std::recursive_mutex> runtime_lock(ctx.runtime_state_mutex);
            root_failure_reason = ctx.runtime_recovery_reason;
        }
#ifdef APFSACCESS_HAS_RW_ENGINE
        if (root_failure_reason.empty() && ctx.metadata_store)
        {
            root_failure_reason = ctx.metadata_store->RecoveryReason();
        }
#endif
        {
            std::lock_guard<std::recursive_mutex> runtime_lock(ctx.runtime_state_mutex);
            if (ctx.runtime_recovery_reason.empty())
            {
                ctx.runtime_recovery_reason = root_failure_reason.empty()
                    ? L"RootEnumerationUnavailable"
                    : root_failure_reason;
            }
            ctx.recovery_active = true;
            if (ctx.runtime_last_recovery_action.empty())
            {
                ctx.runtime_last_recovery_action = L"MountStartupBlocked";
            }
            root_failure_reason = ctx.runtime_recovery_reason;
        }
        (void)WriteHostStatusFile(ctx);
        std::wcerr << L"[FsHost] Unable to enumerate APFS root path from native metadata state (reason="
            << root_failure_reason
            << L")."
            << std::endl;
        if (ctx.sd) LocalFree(ctx.sd);
        return 5;
    }

    ctx.label = BuildExplorerVolumeLabel(args.volume);

    FSP_FSCTL_VOLUME_PARAMS vp{};
    ConfigureVolumeParamsForExplorer(ctx, now, vp);

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
    iface.GetStreamInfo = CB_GetStreamInfo;
    iface.ReadDirectory = CB_ReadDirectory;

    if (!OwningParentIsAlive(parent_process) || !PrepareLifetimeFile(args))
    {
        if (ctx.sd) LocalFree(ctx.sd);
        std::wcerr << L"[FsHost] Mount startup was cancelled before publication." << std::endl;
        return 0;
    }

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
        DeleteWinFspFileSystemOwned(&ctx);
        return 7;
    }
    st = StartDispatcherWithResolvedThreadCount(
        ctx.api.Start,
        ctx.fs,
        ctx.dispatcher_thread_count);
    if (!NT_SUCCESS(st))
    {
        std::wcerr << L"[FsHost] FspFileSystemStartDispatcher failed: 0x" << std::hex << (unsigned long)st << std::endl;
        DeleteWinFspFileSystemOwned(&ctx);
        return 8;
    }
#ifdef APFSACCESS_HAS_RW_ENGINE
    StartDeferredCommitWorker(&ctx);
#endif
    bool shell_drive_announced = false;
    if (OwningParentIsAlive(parent_process) && LifetimeFileExists(args))
    {
        ctx.mount_ready.store(true, std::memory_order_release);
        (void)WriteHostStatusFile(ctx);
        WriteShutdownStageFile(ctx, "running");
        if (OwningParentIsAlive(parent_process) && LifetimeFileExists(args))
        {
            NotifyShellDriveAdded(args.mount);
            shell_drive_announced = true;
        }
        else
        {
            ctx.mount_ready.store(false, std::memory_order_release);
            (void)WriteHostStatusFile(ctx);
        }
    }

    SetConsoleCtrlHandler(CtrlHandler, TRUE);
    while (!g_exit.load())
    {
        if (!OwningParentIsAlive(parent_process) || !LifetimeFileExists(args))
        {
            break;
        }
        if (ctx.callback_status_publish_pending.load(std::memory_order_acquire))
        {
            WriteCallbackWatchdogFile(ctx);
            WriteHostStatusFileForCallback(&ctx);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }

    const auto shutdown_exit = RunFsHostShutdownDrain(&ctx);
    if (shell_drive_announced)
    {
        NotifyShellDriveRemoved(args.mount);
    }
    if (ctx.sd) LocalFree(ctx.sd);
    return shutdown_exit;
}
#endif
