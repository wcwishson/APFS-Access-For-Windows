#include "BlockDevice.h"
#include "SoftwareTransitionHeldImageAuthority.h"
#include "VolumePhysicalInstanceInternal.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <cstdio>
#include <filesystem>
#include <limits>
#include <memory>
#include <memory_resource>
#include <optional>
#include <span>
#include <sstream>
#include <string_view>
#include <utility>

#include <winioctl.h>
#include <setupapi.h>
#include <winternl.h>

namespace apfsaccess::rw
{
namespace
{
constexpr std::uint64_t kMaxMergedBatchBytes = 1024ull * 1024ull;
constexpr std::uint64_t kMaxDirectAsyncChunkBytes = 2ull * 1024ull * 1024ull;
constexpr std::uint64_t kMinAsyncSingleWriteBytes = 4ull * 1024ull * 1024ull;
constexpr std::uint64_t kMinAsyncDirectAdjacentSpanBytes = 64ull * 1024ull;
constexpr std::uint64_t kMaxRmwGroupBytes = 64ull * 1024ull;
constexpr std::uint64_t kMaxRmwGroupGapBytes = 16ull * 1024ull;
constexpr std::size_t kMaxRmwGroupWrites = 8;
constexpr std::size_t kDefaultAsyncBlockIoQueueDepth = 4;
constexpr std::size_t kMaxAsyncBlockIoQueueDepth = 16;
constexpr DWORD kOverlappedIoWaitTimeoutMs = 30'000;
constexpr DWORD kOverlappedIoCancelWaitTimeoutMs = 5'000;
constexpr DWORD kOverlappedIoFinalWaitTimeoutMs = 5'000;
constexpr UINT kUncancelableIoExitCode = 0xE1;
constexpr std::size_t kReadCacheMaxWindowBytes = 64 * 1024;
constexpr std::size_t kReadCacheMaxBytes = 8 * 1024 * 1024;
constexpr std::size_t kReadCacheMaxEntries = 2048;
constexpr std::size_t kReadThreadLocalScratchMaxBytes = 1024 * 1024;
constexpr std::uint64_t kRawPresenceProbeCacheMs = 250;

bool IsRawPhysicalDevicePath(std::wstring_view path) noexcept
{
    constexpr std::array<std::wstring_view, 2> prefixes = {
        LR"(\\.\PhysicalDrive)",
        LR"(\\?\PhysicalDrive)",
    };
    for (const auto prefix : prefixes)
    {
        if (path.size() <= prefix.size() ||
            _wcsnicmp(path.data(), prefix.data(), prefix.size()) != 0)
        {
            continue;
        }

        return std::all_of(
            path.begin() + static_cast<std::ptrdiff_t>(prefix.size()),
            path.end(),
            [](wchar_t ch) { return std::iswdigit(ch) != 0; });
    }
    return false;
}

std::optional<DWORD> TryParsePhysicalDriveNumber(std::wstring_view path) noexcept
{
    constexpr std::array<std::wstring_view, 2> prefixes = {
        LR"(\\.\PhysicalDrive)",
        LR"(\\?\PhysicalDrive)",
    };
    std::wstring_view prefix;
    for (const auto candidate : prefixes)
    {
        if (path.size() > candidate.size() &&
            _wcsnicmp(path.data(), candidate.data(), candidate.size()) == 0)
        {
            prefix = candidate;
            break;
        }
    }
    if (prefix.empty())
    {
        return std::nullopt;
    }

    DWORD value = 0;
    for (const auto ch : path.substr(prefix.size()))
    {
        if (!std::iswdigit(ch))
        {
            return std::nullopt;
        }
        const auto digit = static_cast<DWORD>(ch - L'0');
        if (value > (std::numeric_limits<DWORD>::max() - digit) / 10)
        {
            return std::nullopt;
        }
        value = value * 10 + digit;
    }
    return value;
}

struct DiskInterfaceIdentity
{
    std::wstring instance;
    std::wstring path;
    DWORD devinst = 0;
};

struct DeviceInfoSet
{
    HDEVINFO value;
    ~DeviceInfoSet() { if (value != INVALID_HANDLE_VALUE) SetupDiDestroyDeviceInfoList(value); }
};

bool SameInterfacePath(std::wstring_view left, std::wstring_view right)
{
    return left.size() <= 4096 && right.size() <= 4096 && !left.empty() &&
        CompareStringOrdinal(left.data(), static_cast<int>(left.size()),
            right.data(), static_cast<int>(right.size()), TRUE) == CSTR_EQUAL;
}

bool ReadDiskInterface(HDEVINFO devices, SP_DEVICE_INTERFACE_DATA& item,
    DiskInterfaceIdentity& out, DWORD& error)
{
    if (!(item.Flags & SPINT_ACTIVE) || (item.Flags & SPINT_REMOVED))
    {
        error = ERROR_DEVICE_NOT_CONNECTED;
        return false;
    }
    DWORD size = 0;
    (void)SetupDiGetDeviceInterfaceDetailW(devices, &item, nullptr, 0, &size, nullptr);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER ||
        size < sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W) || size > 65536)
    {
        error = ERROR_INVALID_DATA;
        return false;
    }
    std::vector<std::byte> storage(size);
    auto* detail = reinterpret_cast<SP_DEVICE_INTERFACE_DETAIL_DATA_W*>(storage.data());
    detail->cbSize = sizeof(*detail);
    SP_DEVINFO_DATA device{};
    device.cbSize = sizeof(device);
    if (!SetupDiGetDeviceInterfaceDetailW(devices, &item, detail, size, nullptr, &device))
    {
        error = GetLastError();
        return false;
    }
    const auto maximum = (size - offsetof(SP_DEVICE_INTERFACE_DETAIL_DATA_W, DevicePath)) / sizeof(wchar_t);
    const auto length = wcsnlen(detail->DevicePath, maximum);
    wchar_t instance[401]{};
    if (!length || length == maximum || length > 4096 ||
        !SetupDiGetDeviceInstanceIdW(devices, &device, instance, 401, nullptr))
    {
        error = ERROR_INVALID_DATA;
        return false;
    }
    const auto instance_length = wcsnlen(instance, 401);
    if (!instance_length || instance_length == 401)
    {
        error = ERROR_INVALID_DATA;
        return false;
    }
    out.instance.assign(instance, instance_length);
    if (!physical_instance::Normalize(out.instance))
    {
        error = ERROR_INVALID_DATA;
        return false;
    }
    out.path.assign(detail->DevicePath, length);
    out.devinst = device.DevInst;
    return true;
}

bool FindPresentDiskInterface(const std::wstring& instance, std::wstring_view exact_path,
    DiskInterfaceIdentity& out, DWORD& error)
{
    DeviceInfoSet devices{SetupDiGetClassDevsW(
        &GUID_DEVINTERFACE_DISK,
        instance.c_str(),
        nullptr,
        DIGCF_PRESENT | DIGCF_DEVICEINTERFACE)};
    if (devices.value == INVALID_HANDLE_VALUE)
    {
        error = GetLastError();
        return false;
    }

    unsigned matches = 0;
    for (DWORD index = 0; index < 64; ++index)
    {
        SP_DEVICE_INTERFACE_DATA interface_data{};
        interface_data.cbSize = sizeof(interface_data);
        if (!SetupDiEnumDeviceInterfaces(
                devices.value, nullptr, &GUID_DEVINTERFACE_DISK, index, &interface_data))
        {
            const auto enumeration_error = GetLastError();
            if (enumeration_error == ERROR_NO_MORE_ITEMS && matches == 1) return true;
            error = enumeration_error == ERROR_NO_MORE_ITEMS ? ERROR_DEVICE_NOT_CONNECTED : enumeration_error;
            return false;
        }
        DiskInterfaceIdentity candidate;
        if (!ReadDiskInterface(devices.value, interface_data, candidate, error)) return false;
        if (candidate.instance != instance)
        {
            error = ERROR_INVALID_DATA;
            return false;
        }
        if (!exact_path.empty() && !SameInterfacePath(candidate.path, exact_path)) continue;
        if (++matches != 1) { error = ERROR_DUP_NAME; return false; }
        out = std::move(candidate);
    }
    error = ERROR_MORE_DATA;
    return false;
}

bool ResolveRawDiskInterface(std::wstring_view path, DiskInterfaceIdentity& out, DWORD& error)
{
    if (const auto number = TryParsePhysicalDriveNumber(path))
    {
        std::wstring instance;
        const auto selected = L"\\\\.\\PhysicalDrive" + std::to_wstring(*number);
        if (!physical_instance::Selected(selected, instance))
        {
            error = ERROR_DEVICE_NOT_CONNECTED;
            return false;
        }
        return FindPresentDiskInterface(instance, {}, out, error);
    }
    DeviceInfoSet devices{SetupDiCreateDeviceInfoList(nullptr, nullptr)};
    SP_DEVICE_INTERFACE_DATA item{};
    item.cbSize = sizeof(item);
    const std::wstring exact_path(path);
    if (devices.value == INVALID_HANDLE_VALUE ||
        !SetupDiOpenDeviceInterfaceW(devices.value, exact_path.c_str(), 0, &item))
    {
        error = GetLastError();
        return false;
    }
    DiskInterfaceIdentity selected;
    return ReadDiskInterface(devices.value, item, selected, error) &&
        SameInterfacePath(selected.path, path) &&
        FindPresentDiskInterface(selected.instance, path, out, error);
}

bool IsPresentDiskInterface(const DiskInterfaceIdentity& selected, DWORD& error)
{
    DiskInterfaceIdentity current;
    if (!FindPresentDiskInterface(selected.instance, selected.path, current, error)) return false;
    if (current.devinst != selected.devinst)
    {
        error = ERROR_DEVICE_NOT_CONNECTED;
        return false;
    }
    return true;
}

bool IsProbeUnsupportedError(DWORD error) noexcept
{
    return error == ERROR_INVALID_FUNCTION ||
        error == ERROR_NOT_SUPPORTED ||
        error == ERROR_INVALID_PARAMETER;
}

bool QueryRegularFileIdentity(HANDLE handle, FILE_ID_INFO& identity)
{
    FILE_STANDARD_INFO standard{};
    FILE_BASIC_INFO basic{};
    if (handle == INVALID_HANDLE_VALUE || GetFileType(handle) != FILE_TYPE_DISK ||
        !GetFileInformationByHandleEx(handle, FileStandardInfo, &standard, sizeof(standard)) ||
        standard.Directory || standard.DeletePending || standard.NumberOfLinks == 0 ||
        !GetFileInformationByHandleEx(handle, FileBasicInfo, &basic, sizeof(basic)) ||
        (basic.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_DEVICE |
            FILE_ATTRIBUTE_REPARSE_POINT)) != 0 ||
        !GetFileInformationByHandleEx(handle, FileIdInfo, &identity, sizeof(identity)))
    {
        return false;
    }

    // A disk-type handle alone can also be a raw volume/device. Require a
    // named file inside a local filesystem volume, from the opened handle.
    constexpr DWORD flags = FILE_NAME_NORMALIZED | VOLUME_NAME_GUID;
    const auto length = GetFinalPathNameByHandleW(handle, nullptr, 0, flags);
    if (length == 0 || length > 32768)
    {
        return false;
    }
    std::wstring final_path(length, L'\0');
    const auto copied = GetFinalPathNameByHandleW(handle, final_path.data(), length, flags);
    if (copied == 0 || copied >= length)
    {
        return false;
    }
    final_path.resize(copied);
    const auto volume_end = final_path.find(L"}\\");
    return final_path.starts_with(LR"(\\?\Volume{)") &&
        volume_end != std::wstring::npos && volume_end + 2 < final_path.size() &&
        final_path.find(L':', volume_end + 2) == std::wstring::npos;
}

bool QueryHeldReadWriteHandle(HANDLE handle, ULONG expected_handles)
{
    using QueryObject = NTSTATUS (NTAPI*)(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG);
    static const auto query_object = reinterpret_cast<QueryObject>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryObject"));
    PUBLIC_OBJECT_BASIC_INFORMATION information{};
    constexpr ACCESS_MASK access = FILE_READ_DATA | FILE_WRITE_DATA;
    return query_object != nullptr &&
        query_object(handle, ObjectBasicInformation, &information, sizeof(information), nullptr) >= 0 &&
        (information.GrantedAccess & access) == access &&
        information.HandleCount == expected_handles;
}

bool IsExclusiveRepairImageHandle(HANDLE handle)
{
    if (!QueryHeldReadWriteHandle(handle, 1)) return false;
    // Only ordinary files reach this check. Probe the held object at adoption,
    // never a pathname, and accept only an explicit sharing refusal.
    for (const DWORD access : std::array<DWORD, 3>{FILE_READ_DATA, FILE_WRITE_DATA, DELETE})
    {
        const auto probe = ReOpenFile(handle, access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_FLAG_OVERLAPPED);
        if (probe != INVALID_HANDLE_VALUE)
        {
            CloseHandle(probe);
            return false;
        }
        if (GetLastError() != ERROR_SHARING_VIOLATION) return false;
    }
    return true;
}

struct ThreadLocalOverlappedEvent
{
    ~ThreadLocalOverlappedEvent()
    {
        if (handle != nullptr)
        {
            (void)CloseHandle(handle);
        }
    }

    HANDLE Ensure()
    {
        if (handle == nullptr)
        {
            handle = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        }
        return handle;
    }

    HANDLE handle = nullptr;
};

ThreadLocalOverlappedEvent& CurrentBlockIoEvent()
{
    static thread_local ThreadLocalOverlappedEvent event;
    return event;
}

std::optional<std::wstring> ReadEnvironmentValue(const wchar_t* variable_name)
{
    if (variable_name == nullptr || *variable_name == L'\0')
    {
        return std::nullopt;
    }

    constexpr DWORD kStackBufferChars = 256;
    wchar_t stack_value[kStackBufferChars] = {};
    DWORD copied = GetEnvironmentVariableW(variable_name, stack_value, kStackBufferChars);
    if (copied == 0)
    {
        return std::nullopt;
    }

    if (copied < kStackBufferChars)
    {
        return std::wstring(stack_value, stack_value + copied);
    }

    std::wstring value;
    value.resize(copied);
    copied = GetEnvironmentVariableW(variable_name, value.data(), static_cast<DWORD>(value.size()));
    if (copied == 0 || copied >= value.size())
    {
        return std::nullopt;
    }

    value.resize(copied);
    return value;
}

std::size_t ReadCacheEntryBudget()
{
    const auto value = ReadEnvironmentValue(L"APFSACCESS_BLOCK_READ_CACHE_ENTRIES");
    if (value == L"256") return 256;
    if (value == L"512") return 512;
    if (value == L"1024") return 1024;
    if (value == L"2048") return 2048;
    return kReadCacheMaxEntries;
}

[[noreturn]] void FailClosedForUncancelableIo() noexcept
{
    // Returning while the kernel still owns an overlapped caller buffer would
    // be a use-after-free risk. Terminating the FsHost is the bounded safety
    // boundary; its existing recovery marker/checkpoint protocol treats this
    // exactly like an interrupted physical I/O operation.
    OutputDebugStringW(L"[ApfsAccess] overlapped I/O could not be cancelled before its safety deadline.\n");
    if (!TerminateProcess(GetCurrentProcess(), kUncancelableIoExitCode))
    {
        ExitProcess(kUncancelableIoExitCode);
    }
    std::abort();
}

void TrimLeadingWhitespace(std::wstring& value)
{
    const auto first_non_whitespace = value.find_first_not_of(L" \t");
    if (first_non_whitespace == std::wstring::npos)
    {
        value.clear();
        return;
    }
    if (first_non_whitespace > 0)
    {
        value.erase(0, first_non_whitespace);
    }
}

bool IsFaultSwitchEnabled(const wchar_t* variable_name)
{
    auto value = ReadEnvironmentValue(variable_name);
    if (!value.has_value())
    {
        return false;
    }

    TrimLeadingWhitespace(*value);
    return !value->empty() &&
           _wcsicmp(value->c_str(), L"1") == 0 ||
           _wcsicmp(value->c_str(), L"true") == 0 ||
           _wcsicmp(value->c_str(), L"yes") == 0;
}

std::optional<std::wstring> ReadFaultMode(const wchar_t* variable_name)
{
    auto value = ReadEnvironmentValue(variable_name);
    if (!value.has_value())
    {
        return std::nullopt;
    }

    TrimLeadingWhitespace(*value);
    if (value->empty() ||
        _wcsicmp(value->c_str(), L"0") == 0 ||
        _wcsicmp(value->c_str(), L"false") == 0 ||
        _wcsicmp(value->c_str(), L"no") == 0)
    {
        return std::nullopt;
    }

    return value;
}

bool IsFaultMode(std::wstring_view actual, const wchar_t* expected)
{
    if (expected == nullptr)
    {
        return false;
    }

    const auto expected_length = std::wcslen(expected);
    return actual.size() == expected_length &&
           _wcsnicmp(actual.data(), expected, expected_length) == 0;
}

bool IsPerfCountersEnabled()
{
    static const bool enabled = []()
    {
        std::error_code ec;
        auto marker = std::filesystem::temp_directory_path(ec);
        if (!ec)
        {
            marker /= "ApfsAccess";
            marker /= "perf-counters.enabled";
            if (std::filesystem::exists(marker, ec) && !ec)
            {
                return true;
            }
        }

        wchar_t* raw_value = nullptr;
        std::size_t raw_length = 0;
        if (_wdupenv_s(&raw_value, &raw_length, L"APFSACCESS_PERF_COUNTERS") == 0 && raw_value != nullptr)
        {
            std::unique_ptr<wchar_t, decltype(&std::free)> guard(raw_value, &std::free);
            const auto* value = raw_value;
            while (*value == L' ' || *value == L'\t')
            {
                ++value;
            }

            return *value != L'\0' &&
                   _wcsicmp(value, L"0") != 0 &&
                   _wcsicmp(value, L"false") != 0 &&
                   _wcsicmp(value, L"no") != 0;
        }

        return false;
    }();
    return enabled;
}

std::size_t ReadPositiveSizeEnv(const wchar_t* variable_name, std::size_t fallback, std::size_t maximum)
{
    if (variable_name == nullptr || *variable_name == L'\0')
    {
        return fallback;
    }

    wchar_t* raw_value = nullptr;
    std::size_t raw_length = 0;
    if (_wdupenv_s(&raw_value, &raw_length, variable_name) != 0 || raw_value == nullptr)
    {
        return fallback;
    }
    std::unique_ptr<wchar_t, decltype(&std::free)> guard(raw_value, &std::free);
    wchar_t* end = nullptr;
    const auto parsed = std::wcstoull(raw_value, &end, 10);
    if (end == raw_value || parsed == 0)
    {
        return fallback;
    }

    return static_cast<std::size_t>(std::min<std::uint64_t>(parsed, maximum));
}

std::optional<std::size_t> ReadOptionalPositiveSizeEnv(
    const wchar_t* variable_name,
    std::size_t maximum)
{
    auto value = ReadEnvironmentValue(variable_name);
    if (!value.has_value())
    {
        return std::nullopt;
    }

    TrimLeadingWhitespace(*value);
    wchar_t* end = nullptr;
    const auto parsed = std::wcstoull(value->c_str(), &end, 10);
    if (end == value->c_str() || parsed == 0)
    {
        return std::nullopt;
    }

    return static_cast<std::size_t>(std::min<std::uint64_t>(parsed, maximum));
}

bool IsAsyncBlockIoEnabled()
{
    return !IsFaultSwitchEnabled(L"APFSACCESS_DISABLE_ASYNC_BLOCK_IO");
}

bool IsExperimentalBlockReadCacheEnabled()
{
    return IsFaultSwitchEnabled(L"APFSACCESS_EXPERIMENTAL_BLOCK_READ_CACHE");
}

std::size_t AsyncBlockIoQueueDepth()
{
    static const std::size_t depth = ReadPositiveSizeEnv(
        L"APFSACCESS_ASYNC_BLOCK_IO_DEPTH",
        kDefaultAsyncBlockIoQueueDepth,
        kMaxAsyncBlockIoQueueDepth);
    return std::max<std::size_t>(1, depth);
}

std::uint64_t ElapsedMicroseconds(std::chrono::steady_clock::time_point started)
{
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - started).count());
}

std::uint64_t AlignDown(std::uint64_t value, std::uint64_t alignment)
{
    if (alignment == 0)
    {
        return value;
    }

    return value - (value % alignment);
}

std::uint64_t AlignUp(std::uint64_t value, std::uint64_t alignment)
{
    if (alignment == 0)
    {
        return value;
    }
    if (value == 0)
    {
        return 0;
    }
    if (value > (std::numeric_limits<std::uint64_t>::max() - (alignment - 1)))
    {
        return 0;
    }

    return AlignDown(value + alignment - 1, alignment);
}

bool AddOffsetToPointer(const std::byte* base, std::uint64_t offset, const std::byte*& result)
{
    if (offset > static_cast<std::uint64_t>((std::numeric_limits<std::ptrdiff_t>::max)()))
    {
        return false;
    }

    result = base + static_cast<std::ptrdiff_t>(offset);
    return true;
}

void UpdateAtomicMax(std::atomic<std::uint64_t>& target, std::uint64_t value) noexcept
{
    auto current = target.load(std::memory_order_relaxed);
    while (value > current &&
           !target.compare_exchange_weak(current, value, std::memory_order_relaxed))
    {
    }
}

std::size_t LatencyBucketIndex(std::uint64_t elapsed_us, std::size_t bucket_count) noexcept
{
    if (elapsed_us == 0 || bucket_count == 0)
    {
        return 0;
    }

    std::size_t index = 1;
    std::uint64_t upper_bound = 1;
    while (elapsed_us > upper_bound && index + 1 < bucket_count)
    {
        ++index;
        if (upper_bound > (std::numeric_limits<std::uint64_t>::max() / 2))
        {
            return index;
        }
        upper_bound *= 2;
    }
    return index;
}

std::uint64_t LatencyBucketUpperBoundUs(
    std::size_t index,
    std::size_t bucket_count,
    std::uint64_t max_observed_us) noexcept
{
    if (index == 0)
    {
        return 0;
    }
    if (index + 1 >= bucket_count)
    {
        return max_observed_us;
    }
    return std::min<std::uint64_t>(1ull << (index - 1), max_observed_us);
}
} // namespace

struct BlockDevice::RawPresenceIdentity
{
    DiskInterfaceIdentity selected;
    DWORD disk_number = MAXDWORD;
};

BlockDevice::BlockDevice(std::wstring path, std::uint64_t base_offset_bytes)
    : path_(std::move(path))
    , base_offset_bytes_(base_offset_bytes)
    // Raw APFS containers repeatedly reread immutable checkpoint metadata
    // during one owner-serialized commit. Keep the cache scoped to physical
    // handles so image fixtures retain their exact uncached behavior; writes
    // advance the cache epoch before publication and therefore invalidate it.
    , read_cache_enabled_(IsExperimentalBlockReadCacheEnabled() ||
        IsRawPhysicalDevicePath(path_))
    , read_cache_max_entries_(ReadCacheEntryBudget())
{
}

DWORD BlockDevice::WriteHandleShareMode(std::wstring_view path) noexcept
{
    return IsRawPhysicalDevicePath(path)
        ? FILE_SHARE_READ
        : FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
}

struct BlockDevice::ScopedPerfTimer
{
    PerfCounter& primary;
    PerfCounter* secondary = nullptr;
    std::chrono::steady_clock::time_point started{};
    std::uint64_t byte_count = 0;
    bool enabled = false;
    bool observe_secondary = false;

    ScopedPerfTimer(PerfCounter& primary_counter, std::uint64_t bytes = 0) noexcept
        : primary(primary_counter)
        , byte_count(bytes)
        , enabled(IsPerfCountersEnabled())
    {
        if (enabled)
        {
            started = std::chrono::steady_clock::now();
        }
    }

    void SetSecondary(PerfCounter& secondary_counter) noexcept
    {
        secondary = &secondary_counter;
    }

    void MarkSecondary() noexcept
    {
        observe_secondary = true;
    }

    ~ScopedPerfTimer()
    {
        if (!enabled)
        {
            return;
        }

        const auto elapsed_us = ElapsedMicroseconds(started);
        primary.Observe(elapsed_us, byte_count);
        if (observe_secondary && secondary)
        {
            secondary->Observe(elapsed_us, byte_count);
        }
    }
};

struct BlockDevice::WriteSourceAdmission
{
    explicit WriteSourceAdmission(BlockDevice& owner)
        : owner_(owner)
    {
        owner_.BeginWriteSourceAdmission();
    }

    ~WriteSourceAdmission() noexcept
    {
        owner_.EndWriteSourceAdmission();
    }

    WriteSourceAdmission(const WriteSourceAdmission&) = delete;
    WriteSourceAdmission& operator=(const WriteSourceAdmission&) = delete;

private:
    BlockDevice& owner_;
};

struct BlockDevice::ReadCacheWriteEpoch
{
    ReadCacheWriteEpoch(BlockDevice& owner, std::span<const WriteSpan> writes)
        : owner_(owner)
        , epoch_lock_(owner.write_epoch_mutex_)
    {
        owner_.BeginReadCacheWriteEpoch(writes);
    }

    ~ReadCacheWriteEpoch() noexcept
    {
        owner_.EndReadCacheWriteEpoch();
    }

    ReadCacheWriteEpoch(const ReadCacheWriteEpoch&) = delete;
    ReadCacheWriteEpoch& operator=(const ReadCacheWriteEpoch&) = delete;

private:
    BlockDevice& owner_;
    std::unique_lock<std::mutex> epoch_lock_;
};

struct BlockDevice::ReadCacheWriteAdmission
{
    explicit ReadCacheWriteAdmission(BlockDevice& owner)
        : owner_(owner)
    {
        owner_.BeginReadCacheWriteAdmission();
    }

    ~ReadCacheWriteAdmission() noexcept
    {
        owner_.EndReadCacheWriteAdmission();
    }

    ReadCacheWriteAdmission(const ReadCacheWriteAdmission&) = delete;
    ReadCacheWriteAdmission& operator=(const ReadCacheWriteAdmission&) = delete;

private:
    BlockDevice& owner_;
};

void BlockDevice::PerfCounter::Observe(std::uint64_t elapsed_us, std::uint64_t byte_count) noexcept
{
    UpdateAtomicMax(max_us, elapsed_us);

    const auto bucket_index = LatencyBucketIndex(elapsed_us, latency_buckets.size());
    latency_buckets[bucket_index].fetch_add(1, std::memory_order_relaxed);
    count.fetch_add(1, std::memory_order_relaxed);
    bytes.fetch_add(byte_count, std::memory_order_relaxed);
    total_us.fetch_add(elapsed_us, std::memory_order_relaxed);
    last_us.store(elapsed_us, std::memory_order_relaxed);
}

std::uint64_t BlockDevice::PerfCounter::ApproxP50Us() const noexcept
{
    return ApproxPercentileUs(1, 2);
}

std::uint64_t BlockDevice::PerfCounter::ApproxP95Us() const noexcept
{
    return ApproxPercentileUs(95, 100);
}

std::uint64_t BlockDevice::PerfCounter::ApproxPercentileUs(
    std::uint64_t numerator,
    std::uint64_t denominator) const noexcept
{
    std::uint64_t total = 0;
    std::array<std::uint64_t, kLatencyBucketCount> snapshot{};
    for (std::size_t index = 0; index < latency_buckets.size(); ++index)
    {
        snapshot[index] = latency_buckets[index].load(std::memory_order_relaxed);
        total += snapshot[index];
    }
    if (total == 0)
    {
        return 0;
    }

    const auto whole = total / denominator;
    const auto remainder = total % denominator;
    const auto target_rank =
        (whole * numerator) +
        ((remainder * numerator + denominator - 1) / denominator);
    std::uint64_t cumulative = 0;
    const auto max_observed_us = max_us.load(std::memory_order_relaxed);
    for (std::size_t index = 0; index < snapshot.size(); ++index)
    {
        cumulative += snapshot[index];
        if (cumulative >= target_rank)
        {
            return LatencyBucketUpperBoundUs(index, snapshot.size(), max_observed_us);
        }
    }
    return max_observed_us;
}

std::string BlockDevice::PerformanceJson() const
{
    const auto append_counter = [](std::ostringstream& buffer, const char* name, const PerfCounter& counter)
    {
        const auto count = counter.count.load(std::memory_order_relaxed);
        const auto bytes = counter.bytes.load(std::memory_order_relaxed);
        const auto total_us = counter.total_us.load(std::memory_order_relaxed);
        const auto max_us = counter.max_us.load(std::memory_order_relaxed);
        const auto last_us = counter.last_us.load(std::memory_order_relaxed);
        const auto p50_us = counter.ApproxP50Us();
        const auto p95_us = counter.ApproxP95Us();
        buffer << "\"" << name << "\":{\"count\":" << count
               << ",\"bytes\":" << bytes
               << ",\"totalUs\":" << total_us
               << ",\"maxUs\":" << max_us
               << ",\"lastUs\":" << last_us
               << ",\"p50Us\":" << p50_us
               << ",\"p95Us\":" << p95_us
               << "}";
    };

    std::ostringstream buffer;
    buffer << "{";
    append_counter(buffer, "read", read_perf_);
    buffer << ",";
    append_counter(buffer, "rawRead", raw_read_perf_);
    buffer << ",";
    append_counter(buffer, "write", write_perf_);
    buffer << ",";
    append_counter(buffer, "unalignedWrite", unaligned_write_perf_);
    buffer << ",";
    append_counter(buffer, "batchWrite", batch_write_perf_);
    buffer << ",";
    append_counter(buffer, "mergedBatchWrite", merged_batch_write_perf_);
    buffer << ",";
    append_counter(buffer, "rmwGroupWrite", rmw_group_write_perf_);
    buffer << ",";
    append_counter(buffer, "contiguousBatchWrite", contiguous_batch_write_perf_);
    buffer << ",";
    append_counter(buffer, "asyncBatchWrite", async_batch_write_perf_);
    buffer << ",";
    append_counter(buffer, "flush", flush_perf_);
    buffer << ",";
    append_counter(buffer, "writeQueueWait", write_queue_wait_perf_);
    buffer << ",";
    append_counter(buffer, "flushQueueWait", flush_queue_wait_perf_);
    buffer << ",\"asyncMaxQueueDepth\":"
           << async_max_queue_depth_.load(std::memory_order_relaxed)
           << ",\"asyncEventCreateCount\":"
           << async_event_create_count_.load(std::memory_order_relaxed)
           << ",\"asyncEventPoolMaxDepth\":"
           << async_event_pool_max_depth_.load(std::memory_order_relaxed)
           << ",\"asyncWaitTimeoutCount\":"
           << async_wait_timeout_count_.load(std::memory_order_relaxed)
           << ",\"asyncCancelCount\":"
           << async_cancel_count_.load(std::memory_order_relaxed)
           << ",\"asyncCancelWaitTimeoutCount\":"
           << async_cancel_wait_timeout_count_.load(std::memory_order_relaxed)
           << ",\"mergedBatchDirectFill\":{\"count\":"
           << merged_batch_direct_fill_count_.load(std::memory_order_relaxed)
           << ",\"bytes\":"
           << merged_batch_direct_fill_bytes_.load(std::memory_order_relaxed)
           << "}"
           << ",\"mergedBatchScratch\":{\"resizeCount\":"
           << merged_batch_scratch_resize_count_.load(std::memory_order_relaxed)
           << ",\"maxBytes\":"
           << merged_batch_scratch_max_bytes_.load(std::memory_order_relaxed)
           << "}"
           << ",\"asyncRequestStackWindows\":"
           << async_request_stack_window_count_.load(std::memory_order_relaxed)
           << ",\"asyncDirectAdjacentSpans\":{\"count\":"
           << async_direct_adjacent_span_count_.load(std::memory_order_relaxed)
           << ",\"bytes\":"
           << async_direct_adjacent_span_bytes_.load(std::memory_order_relaxed)
           << "}"
           << ",\"batchSortCount\":"
           << batch_sort_count_.load(std::memory_order_relaxed)
           << ",\"scratch\":{\"readResizeCount\":"
           << read_scratch_resize_count_.load(std::memory_order_relaxed)
           << ",\"readMaxBytes\":"
           << read_scratch_max_bytes_.load(std::memory_order_relaxed)
           << ",\"readThreadLocalUseCount\":"
           << read_thread_local_scratch_use_count_.load(std::memory_order_relaxed)
           << ",\"writeResizeCount\":"
           << write_scratch_resize_count_.load(std::memory_order_relaxed)
           << ",\"writeMaxBytes\":"
           << write_scratch_max_bytes_.load(std::memory_order_relaxed)
           << "}"
           << ",\"readCache\":{\"hits\":"
           << read_cache_hit_count_.load(std::memory_order_relaxed)
           << ",\"containedHits\":"
           << read_cache_contained_hit_count_.load(std::memory_order_relaxed)
           << ",\"misses\":"
           << read_cache_miss_count_.load(std::memory_order_relaxed)
           << ",\"invalidations\":"
           << read_cache_invalidation_count_.load(std::memory_order_relaxed)
           << ",\"bytes\":"
           << read_cache_bytes_.load(std::memory_order_relaxed)
           << ",\"maxEntries\":" << read_cache_max_entries_
           << ",\"maxBytes\":" << kReadCacheMaxBytes
           << ",\"evictions\":" << read_cache_eviction_count_.load(std::memory_order_relaxed)
           << ",\"evictedBytes\":" << read_cache_evicted_bytes_.load(std::memory_order_relaxed)
           << "},\"lastIoError\":"
           << last_io_error_.load(std::memory_order_relaxed);
    buffer << "}";
    return buffer.str();
}

BlockDevice::~BlockDevice()
{
    std::lock_guard<std::mutex> lock(handle_mutex_);
    CloseHandlesLocked();
    CloseAsyncEventPoolLocked();
}

void BlockDevice::SetReadCacheMissHookForTests(std::function<void()> hook)
{
    std::lock_guard<std::mutex> hook_lock(test_hook_mutex_);
    read_cache_miss_hook_for_tests_ = std::move(hook);
}

void BlockDevice::SetWriteCacheInvalidationHookForTests(std::function<void()> hook)
{
    std::lock_guard<std::mutex> hook_lock(test_hook_mutex_);
    write_cache_invalidation_hook_for_tests_ = std::move(hook);
    write_cache_invalidation_hook_installed_.store(
        static_cast<bool>(write_cache_invalidation_hook_for_tests_),
        std::memory_order_release);
}

void BlockDevice::InvokeWriteCacheInvalidationHookForTests()
{
    if (!write_cache_invalidation_hook_installed_.load(std::memory_order_acquire))
    {
        return;
    }

    std::function<void()> hook;
    {
        std::lock_guard<std::mutex> hook_lock(test_hook_mutex_);
        hook = write_cache_invalidation_hook_for_tests_;
    }
    if (hook)
    {
        hook();
    }
}

void BlockDevice::BeginReadCacheWriteAdmission()
{
    if (!read_cache_enabled_)
    {
        return;
    }

    std::lock_guard<std::mutex> cache_lock(read_cache_mutex_);
    ++read_cache_write_admissions_;
}

void BlockDevice::EndReadCacheWriteAdmission() noexcept
{
    if (!read_cache_enabled_)
    {
        return;
    }

    std::lock_guard<std::mutex> cache_lock(read_cache_mutex_);
    if (read_cache_write_admissions_ > 0)
    {
        --read_cache_write_admissions_;
    }
}

void BlockDevice::BeginWriteSourceAdmission()
{
    std::lock_guard<std::mutex> source_lock(write_source_mutex_);
    AdvanceWriteSourceGenerationLocked();
    if (write_source_admissions_ == std::numeric_limits<std::uint64_t>::max())
    {
        write_source_generation_exhausted_ = true;
    }
    else
    {
        ++write_source_admissions_;
    }
}

void BlockDevice::EndWriteSourceAdmission() noexcept
{
    std::lock_guard<std::mutex> source_lock(write_source_mutex_);
    AdvanceWriteSourceGenerationLocked();
    if (write_source_admissions_ > 0)
    {
        --write_source_admissions_;
    }
}

void BlockDevice::AdvanceWriteSourceGenerationLocked() const noexcept
{
    if (write_source_generation_ == std::numeric_limits<std::uint64_t>::max())
    {
        write_source_generation_exhausted_ = true;
    }
    else
    {
        ++write_source_generation_;
    }
}

void BlockDevice::InvalidateWriteSourceHandlesLocked() const
{
    // The caller holds handle_mutex_; source admission never holds it in reverse.
    InvalidateReadCache();
    std::lock_guard<std::mutex> source_lock(write_source_mutex_);
    AdvanceWriteSourceGenerationLocked();
    write_source_handles_retired_ = true;
    RetireRawSnapshotLeaseLocked();
}

void BlockDevice::RetireRawSnapshotLeaseLocked() const noexcept
{
    raw_snapshot_lease_retired_ = true;
    if (raw_snapshot_retirement_epoch_ == std::numeric_limits<std::uint64_t>::max())
        raw_snapshot_epoch_exhausted_ = true;
    else
        ++raw_snapshot_retirement_epoch_;
}

void BlockDevice::BeginReadCacheWriteEpoch()
{
    if (!read_cache_enabled_)
    {
        return;
    }

    std::lock_guard<std::mutex> cache_lock(read_cache_mutex_);
    ++read_cache_generation_;
    if (!read_cache_.empty())
    {
        read_cache_.clear();
        read_cache_bytes_.store(0, std::memory_order_relaxed);
        read_cache_invalidation_count_.fetch_add(1, std::memory_order_relaxed);
    }
}

void BlockDevice::BeginReadCacheWriteEpoch(std::span<const WriteSpan> writes)
{
    if (!read_cache_enabled_)
    {
        return;
    }

    // Resolve geometry before taking the cache lock (geometry can open a handle).
    const auto block_size = static_cast<std::uint64_t>(LogicalBlockSize());
    const auto range_for = [&](const WriteSpan& write, std::uint64_t& start, std::uint64_t& size)
    {
        const auto bytes = static_cast<std::uint64_t>(write.buffer.size());
        const auto maximum = (std::numeric_limits<std::uint64_t>::max)();
        if (bytes == 0 || bytes > (std::numeric_limits<DWORD>::max)() ||
            write.offset_bytes > maximum - base_offset_bytes_)
        {
            return false;
        }
        const auto absolute = write.offset_bytes + base_offset_bytes_;
        start = AlignDown(absolute, block_size);
        if (absolute > maximum - bytes)
        {
            return false;
        }
        const auto end = AlignUp(absolute + bytes, block_size);
        if (end == 0 || end <= start ||
            end > static_cast<std::uint64_t>((std::numeric_limits<LONGLONG>::max)()))
        {
            return false;
        }
        size = end - start;
        return size <= (std::numeric_limits<DWORD>::max)() &&
            RawWriteSpanAllowed(start, size);
    };

    // An unprovable interval keeps the original full-invalidation behavior.
    for (const auto& write : writes)
    {
        std::uint64_t start = 0, size = 0;
        if (!write.buffer.empty() && !range_for(write, start, size))
        {
            BeginReadCacheWriteEpoch();
            return;
        }
    }
    if (writes.empty())
    {
        BeginReadCacheWriteEpoch();
        return;
    }

    std::lock_guard<std::mutex> cache_lock(read_cache_mutex_);
    ++read_cache_generation_;
    bool invalidated = false;
    for (const auto& write : writes)
    {
        if (!write.buffer.empty())
        {
            const auto absolute = write.offset_bytes + base_offset_bytes_;
            const auto start = AlignDown(absolute, block_size);
            const auto end = AlignUp(absolute + write.buffer.size(), block_size);
            invalidated |= InvalidateReadCacheRangeLocked(start, end - start);
        }
    }
    if (invalidated)
    {
        read_cache_invalidation_count_.fetch_add(1, std::memory_order_relaxed);
    }
}

bool BlockDevice::InvalidateReadCacheRangeLocked(
    std::uint64_t absolute_offset_bytes, std::uint64_t size_bytes) const
{
    bool invalidated = false;
    for (auto entry = read_cache_.begin(); entry != read_cache_.end();)
    {
        const auto cached_offset = entry->first.offset_bytes;
        const auto cached_size = static_cast<std::uint64_t>(entry->first.size_bytes);
        const bool overlaps = cached_offset >= absolute_offset_bytes
            ? cached_offset - absolute_offset_bytes < size_bytes
            : absolute_offset_bytes - cached_offset < cached_size;
        if (overlaps)
        {
            read_cache_bytes_.fetch_sub(entry->second.bytes.size(), std::memory_order_relaxed);
            entry = read_cache_.erase(entry);
            invalidated = true;
        }
        else
        {
            ++entry;
        }
    }
    return invalidated;
}

void BlockDevice::InvalidateReadCache() const
{
    if (!read_cache_enabled_)
    {
        return;
    }
    std::lock_guard<std::mutex> cache_lock(read_cache_mutex_);
    // Reject pre-retirement misses without changing an active writer's parity.
    read_cache_generation_ += 2;
    if (!read_cache_.empty())
    {
        read_cache_.clear();
        read_cache_bytes_.store(0, std::memory_order_relaxed);
        read_cache_invalidation_count_.fetch_add(1, std::memory_order_relaxed);
    }
}

void BlockDevice::EndReadCacheWriteEpoch()
{
    if (!read_cache_enabled_)
    {
        return;
    }

    std::lock_guard<std::mutex> cache_lock(read_cache_mutex_);
    ++read_cache_generation_;
}

void BlockDevice::InsertReadCacheEntryLocked(
    std::uint64_t offset_bytes,
    std::size_t size_bytes,
    std::vector<std::byte> bytes) const
{
    if (size_bytes == 0 || bytes.size() != size_bytes)
    {
        return;
    }

    const ReadCacheKey key{offset_bytes, size_bytes};
    auto existing = read_cache_.find(key);
    if (existing != read_cache_.end())
    {
        read_cache_bytes_.fetch_sub(
            static_cast<std::uint64_t>(existing->second.bytes.size()),
            std::memory_order_relaxed);
        existing->second.bytes = std::move(bytes);
        existing->second.last_use = ++read_cache_use_;
    }
    else
    {
        ReadCacheEntry entry{};
        entry.bytes = std::move(bytes);
        entry.last_use = ++read_cache_use_;
        read_cache_.emplace(key, std::move(entry));
    }
    read_cache_bytes_.fetch_add(static_cast<std::uint64_t>(size_bytes), std::memory_order_relaxed);

    while (read_cache_.size() > read_cache_max_entries_ ||
           read_cache_bytes_.load(std::memory_order_relaxed) > kReadCacheMaxBytes)
    {
        const auto oldest = std::min_element(
            read_cache_.begin(),
            read_cache_.end(),
            [](const auto& left, const auto& right)
            {
                return left.second.last_use < right.second.last_use;
            });
        if (oldest == read_cache_.end())
        {
            break;
        }
        const auto evicted_bytes = static_cast<std::uint64_t>(oldest->second.bytes.size());
        read_cache_bytes_.fetch_sub(evicted_bytes, std::memory_order_relaxed);
        read_cache_eviction_count_.fetch_add(1, std::memory_order_relaxed);
        read_cache_evicted_bytes_.fetch_add(evicted_bytes, std::memory_order_relaxed);
        read_cache_.erase(oldest);
    }
}

const std::wstring& BlockDevice::Path() const noexcept
{
    return path_;
}

bool BlockDevice::IsRegularFile() const
{
    return EnsureReadHandle() != INVALID_HANDLE_VALUE &&
        regular_file_.load(std::memory_order_acquire);
}

bool BlockDevice::IsWritable() const
{
    if (!writable_.load(std::memory_order_acquire))
    {
        (void)EnsureWriteHandle();
    }
    return writable_.load(std::memory_order_acquire);
}

bool BlockDevice::IsRawWriterAccepted() const noexcept
{
    return raw_writer_accepted_.load(std::memory_order_acquire);
}

std::uint64_t BlockDevice::RawWriteLimitBytes() const noexcept
{
    return raw_write_limit_bytes_.load(std::memory_order_acquire);
}

const std::string& BlockDevice::RawWriterIdentity() const noexcept
{
    return raw_writer_identity_;
}

bool BlockDevice::RawWriteRangeAllowed(
    std::uint64_t limit_bytes, std::uint64_t offset_bytes, std::uint64_t size_bytes) noexcept
{
    if (limit_bytes == 0 || size_bytes > limit_bytes ||
        offset_bytes > limit_bytes - size_bytes)
    {
        return false;
    }
    return true;
}

bool BlockDevice::RawWriteSpanAllowed(
    std::uint64_t absolute_offset_bytes, std::uint64_t size_bytes) const noexcept
{
    if (!raw_writer_accepted_.load(std::memory_order_acquire))
    {
        return true;
    }
    if (absolute_offset_bytes < base_offset_bytes_)
    {
        return false;
    }
    return RawWriteRangeAllowed(
        raw_write_limit_bytes_.load(std::memory_order_acquire),
        absolute_offset_bytes - base_offset_bytes_,
        size_bytes);
}

bool BlockDevice::IsDeviceUnavailableError(std::uint32_t error) noexcept
{
    switch (error)
    {
    case ERROR_DEVICE_NOT_CONNECTED:
    case ERROR_DEVICE_REMOVED:
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:
    case ERROR_INVALID_HANDLE:
    case ERROR_NO_SUCH_DEVICE:
    case ERROR_NOT_READY:
    case ERROR_GEN_FAILURE:
    case ERROR_IO_DEVICE:
    case ERROR_DEVICE_HARDWARE_ERROR:
    case ERROR_WRITE_FAULT:
    case ERROR_SEM_TIMEOUT:
        return true;
    default:
        return false;
    }
}

bool BlockDevice::ProbeUnderlyingDevice(bool force) const
{
    if (!raw_writer_accepted_.load(std::memory_order_acquire))
    {
        return true;
    }

    const auto now = static_cast<std::uint64_t>(GetTickCount64());
    const auto previous = raw_presence_probe_tick_ms_.load(std::memory_order_acquire);
    if (!force && previous != 0 && now >= previous &&
        now - previous < kRawPresenceProbeCacheMs)
    {
        return raw_presence_probe_result_.load(std::memory_order_acquire);
    }

    std::lock_guard<std::mutex> probe_lock(raw_presence_probe_mutex_);
    const auto locked_previous = raw_presence_probe_tick_ms_.load(std::memory_order_relaxed);
    const auto locked_now = static_cast<std::uint64_t>(GetTickCount64());
    if (!force && locked_previous != 0 && locked_now >= locked_previous &&
        locked_now - locked_previous < kRawPresenceProbeCacheMs)
    {
        return raw_presence_probe_result_.load(std::memory_order_relaxed);
    }

    DWORD error = ERROR_SUCCESS;
    bool present = false;
    bool unbuffered_probe = true;
    if (!raw_presence_probe_result_.load(std::memory_order_acquire))
    {
        // Retirement is one-way, including forced probes after a later replug.
        error = raw_presence_probe_error_.load(std::memory_order_acquire);
    }
    else if (raw_presence_probe_hook_for_tests_)
    {
        try { present = raw_presence_probe_hook_for_tests_(error); }
        catch (...) { error = ERROR_GEN_FAILURE; }
    }
    else if (!raw_presence_identity_ ||
        !IsPresentDiskInterface(raw_presence_identity_->selected, error))
    {
        // A PnP-removed disk may keep an already-open raw handle usable until
        // the next I/O. Require a currently present disk interface before the
        // handle-level checks so logical removal cannot become a phantom write.
    }
    else
    {
        auto probe_handle = CreateFileW(
            raw_presence_identity_->selected.path.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_NO_BUFFERING,
            nullptr);
        if (probe_handle == INVALID_HANDLE_VALUE &&
            GetLastError() == ERROR_INVALID_PARAMETER)
        {
            // Some virtual image providers reject NO_BUFFERING even though they
            // still support the storage verification IOCTLs. Keep the image fast
            // path usable while retaining the transport read for real devices.
            unbuffered_probe = false;
            probe_handle = CreateFileW(
                raw_presence_identity_->selected.path.c_str(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                nullptr);
        }
        if (probe_handle == INVALID_HANDLE_VALUE)
        {
            error = GetLastError();
        }
        else if (GetFileType(probe_handle) != FILE_TYPE_DISK)
        {
            error = ERROR_INVALID_HANDLE;
            CloseHandle(probe_handle);
        }
        else
        {
            DWORD returned = 0;
            STORAGE_DEVICE_NUMBER number{};
            present = DeviceIoControl(probe_handle, IOCTL_STORAGE_GET_DEVICE_NUMBER,
                nullptr, 0, &number, sizeof(number), &returned, nullptr) != FALSE;
            error = present ? ERROR_SUCCESS : GetLastError();
            if (present && !physical_instance::WholeDisk(number, returned, raw_presence_identity_->disk_number))
            {
                present = false;
                error = ERROR_DEVICE_NOT_CONNECTED;
            }
            const bool number_matches = present;
            if (present)
            {
                present = DeviceIoControl(
                    probe_handle,
                    IOCTL_STORAGE_CHECK_VERIFY2,
                    nullptr,
                    0,
                    nullptr,
                    0,
                    &returned,
                    nullptr) != FALSE;
                error = present ? ERROR_SUCCESS : GetLastError();
            }

            // A few storage bridges do not implement CHECK_VERIFY2. A successful
            // geometry query still proves that the device object is live; an
            // actual transport/media error remains a hard failure.
            if (!present && number_matches && IsProbeUnsupportedError(error))
            {
                DISK_GEOMETRY_EX geometry{};
                present = DeviceIoControl(
                    probe_handle,
                    IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                    nullptr,
                    0,
                    &geometry,
                    sizeof(geometry),
                    &returned,
                    nullptr) != FALSE;
                error = present ? ERROR_SUCCESS : GetLastError();
            }

            if (present && unbuffered_probe)
            {
                // CHECK_VERIFY can remain successful for a short period after a
                // surprise removal on USB bridges. Read the first physical sector
                // through the fresh handle to force the transport to answer.
                void* aligned_buffer = VirtualAlloc(
                    nullptr,
                    4096,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE);
                if (aligned_buffer == nullptr)
                {
                    present = false;
                    error = ERROR_NOT_ENOUGH_MEMORY;
                }
                else
                {
                    DWORD bytes_read = 0;
                    const auto read_ok = ReadFile(
                        probe_handle,
                        aligned_buffer,
                        4096,
                        &bytes_read,
                        nullptr);
                    if (!read_ok || bytes_read != 4096)
                    {
                        error = read_ok ? ERROR_IO_DEVICE : GetLastError();
                        if (!IsProbeUnsupportedError(error) || !read_ok)
                            present = false;
                    }
                    VirtualFree(aligned_buffer, 0, MEM_RELEASE);
                }
            }
            if (present && !IsPresentDiskInterface(raw_presence_identity_->selected, error))
                present = false;
            CloseHandle(probe_handle);
        }
    }

    {
        std::lock_guard<std::mutex> source_lock(write_source_mutex_);
        if (!present && !write_source_handles_retired_)
        {
            AdvanceWriteSourceGenerationLocked();
            write_source_handles_retired_ = true;
            RetireRawSnapshotLeaseLocked();
        }
        raw_presence_probe_result_.store(present, std::memory_order_release);
    }
    raw_presence_probe_error_.store(present ? ERROR_SUCCESS : error, std::memory_order_release);
    raw_presence_probe_tick_ms_.store(
        static_cast<std::uint64_t>(GetTickCount64()), std::memory_order_release);
    if (!present)
    {
        InvalidateReadCache();
        last_io_error_.store(error == ERROR_SUCCESS ? ERROR_DEVICE_NOT_CONNECTED : error,
            std::memory_order_relaxed);
        // Do not let an already-open raw handle keep serving as a phantom
        // device after PnP removal. Writes and flushes already hold
        // write_mutex_ when they call this method, so use try_to_lock here:
        // the background monitor closes handles as soon as the current I/O
        // finishes, while an in-flight write can never be invalidated under
        // its feet.
        std::unique_lock<std::mutex> write_guard(write_mutex_, std::try_to_lock);
        if (write_guard.owns_lock())
        {
            std::lock_guard<std::mutex> handle_lock(handle_mutex_);
            CloseHandlesLocked();
        }
    }
    else
    {
        last_io_error_.store(ERROR_SUCCESS, std::memory_order_relaxed);
    }
    return present;
}

bool BlockDevice::HasWriteHandle() const noexcept
{
    return write_handle_.load(std::memory_order_acquire) != INVALID_HANDLE_VALUE;
}

BlockDevice::Geometry BlockDevice::GetGeometry() const
{
    std::lock_guard<std::mutex> lock(geometry_mutex_);
    if (geometry_cached_)
    {
        return geometry_cache_;
    }

    Geometry geometry{};
    HANDLE handle = EnsureReadHandle();
    if (handle == INVALID_HANDLE_VALUE)
    {
        return geometry;
    }

    if (QueryGeometryLocked(handle, geometry))
    {
        geometry_cache_ = geometry;
        geometry_cached_ = true;
        logical_block_size_cache_.store(
            (std::max)(std::uint32_t{512}, geometry.logical_block_size),
            std::memory_order_release);
    }

    return geometry_cache_;
}

bool BlockDevice::Read(std::uint64_t offset_bytes, std::size_t size_bytes, std::vector<std::byte>& out_buffer) const
{
    out_buffer.clear();
    if (size_bytes == 0)
    {
        return true;
    }
    out_buffer.resize(size_bytes);

    std::size_t bytes_read = 0;
    if (!ReadInto(offset_bytes, out_buffer.data(), out_buffer.size(), bytes_read))
    {
        out_buffer.clear();
        return false;
    }

    out_buffer.resize(bytes_read);
    return true;
}

bool BlockDevice::ReadForVerification(
    std::uint64_t offset_bytes, std::size_t size_bytes, std::vector<std::byte>& out_buffer) const
{
    out_buffer.clear();
    if (size_bytes == 0) return true;
    if (size_bytes > static_cast<std::size_t>((std::numeric_limits<DWORD>::max)()) ||
        offset_bytes > (std::numeric_limits<std::uint64_t>::max)() - base_offset_bytes_)
    {
        last_io_error_.store(ERROR_INVALID_PARAMETER, std::memory_order_relaxed);
        return false;
    }
    const auto absolute_offset = base_offset_bytes_ + offset_bytes;
    if (size_bytes > (std::numeric_limits<std::uint64_t>::max)() - absolute_offset)
    {
        last_io_error_.store(ERROR_INVALID_PARAMETER, std::memory_order_relaxed);
        return false;
    }

    // Pin the original reader without reopening or changing source identity.
    std::lock_guard<std::mutex> write_lock(write_mutex_);
    std::lock_guard<std::mutex> handle_lock(handle_mutex_);
    const auto held_reader = read_handle_.load(std::memory_order_acquire);
    if (held_reader == nullptr || held_reader == INVALID_HANDLE_VALUE)
    {
        last_io_error_.store(ERROR_INVALID_HANDLE, std::memory_order_relaxed);
        return false;
    }
    auto logical_block_size = logical_block_size_cache_.load(std::memory_order_acquire);
    if (logical_block_size == 0)
    {
        Geometry geometry{};
        if (!QueryGeometryLocked(held_reader, geometry))
        {
            last_io_error_.store(ERROR_READ_FAULT, std::memory_order_relaxed);
            return false;
        }
        logical_block_size = geometry.logical_block_size;
    }
    const auto block_size = (std::max)(std::uint32_t{512}, logical_block_size);
    // Buffered images align APFS blocks within their selected source window.
    // Raw devices still require alignment in the physical address space.
    const auto aligned_offset = regular_file_.load(std::memory_order_acquire) ? offset_bytes : absolute_offset;
    if (aligned_offset % block_size != 0 || size_bytes % block_size != 0)
    {
        last_io_error_.store(ERROR_INVALID_PARAMETER, std::memory_order_relaxed);
        return false;
    }

    std::lock_guard<std::mutex> source_lock(write_source_mutex_);
    const bool raw = raw_writer_accepted_.load(std::memory_order_acquire);
    if (write_source_admissions_ != 0 ||
        ((raw || exclusive_write_image_) && write_source_handles_retired_) ||
        (stable_read_only_image_ && !RevalidateStableReadOnlyImage()) ||
        (!regular_file_.load(std::memory_order_acquire) && !raw) ||
        (raw && (stable_read_only_image_ || regular_file_.load(std::memory_order_acquire) ||
            !writable_.load(std::memory_order_acquire) ||
            write_handle_.load(std::memory_order_acquire) == INVALID_HANDLE_VALUE ||
            !raw_presence_probe_result_.load(std::memory_order_acquire) || raw_writer_identity_.empty() ||
            RawWriteLimitBytes() == 0 || RawWriteLimitBytes() > raw_write_source_size_bytes_)) ||
        !RawWriteSpanAllowed(absolute_offset, size_bytes))
    {
        last_io_error_.store(ERROR_ACCESS_DENIED, std::memory_order_relaxed);
        return false;
    }

    out_buffer.resize(size_bytes);
    DWORD bytes_read = 0;
    if (!ReadAt(held_reader, absolute_offset, out_buffer.data(), static_cast<DWORD>(size_bytes), bytes_read))
    {
        out_buffer.clear();
        return false;
    }
    if (bytes_read != size_bytes)
    {
        out_buffer.clear();
        last_io_error_.store(ERROR_HANDLE_EOF, std::memory_order_relaxed);
        return false;
    }
    last_io_error_.store(ERROR_SUCCESS, std::memory_order_relaxed);
    return true;
}

bool BlockDevice::ReadInto(
    std::uint64_t offset_bytes,
    std::byte* destination,
    std::size_t destination_size,
    std::size_t& out_bytes_read) const
{
    ScopedPerfTimer perf_scope(read_perf_, static_cast<std::uint64_t>(destination_size));

    out_bytes_read = 0;
    if (destination_size == 0)
    {
        return true;
    }
    if (destination == nullptr)
    {
        return false;
    }
    if (destination_size > static_cast<std::size_t>(std::numeric_limits<DWORD>::max()))
    {
        return false;
    }

    HANDLE handle = EnsureReadHandle();
    if (handle == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    if (offset_bytes > (std::numeric_limits<std::uint64_t>::max() - base_offset_bytes_))
    {
        return false;
    }
    offset_bytes += base_offset_bytes_;

    const auto block_size = static_cast<std::uint64_t>(LogicalBlockSize());
    const auto aligned_offset = AlignDown(offset_bytes, block_size);
    const auto prefix_bytes = static_cast<std::size_t>(offset_bytes - aligned_offset);
    if (destination_size > (std::numeric_limits<std::uint64_t>::max() - static_cast<std::uint64_t>(prefix_bytes)))
    {
        return false;
    }
    const auto requested_window = static_cast<std::uint64_t>(prefix_bytes) + static_cast<std::uint64_t>(destination_size);
    const auto aligned_size_u64 = AlignUp(requested_window, block_size);
    if (aligned_size_u64 == 0 || aligned_size_u64 > static_cast<std::uint64_t>(std::numeric_limits<DWORD>::max()))
    {
        return false;
    }
    const auto aligned_size = static_cast<std::size_t>(aligned_size_u64);
    const bool already_aligned =
        prefix_bytes == 0 &&
        static_cast<std::uint64_t>(destination_size) == aligned_size_u64;

    const bool cacheable = read_cache_enabled_ && aligned_size <= kReadCacheMaxWindowBytes;
    std::uint64_t read_cache_generation = 0;
    if (cacheable)
    {
        std::lock_guard<std::mutex> cache_lock(read_cache_mutex_);
        read_cache_generation = read_cache_generation_;
        if (read_cache_write_admissions_ == 0 &&
            (read_cache_generation & 1ull) == 0)
        {
            auto cached = read_cache_.find(ReadCacheKey{aligned_offset, aligned_size});
            std::size_t cached_offset = 0;
            bool contained_hit = false;
            if (cached == read_cache_.end())
            {
                auto best = read_cache_.end();
                std::size_t best_size = (std::numeric_limits<std::size_t>::max)();
                for (auto candidate = read_cache_.begin(); candidate != read_cache_.end(); ++candidate)
                {
                    const auto candidate_offset = candidate->first.offset_bytes;
                    const auto candidate_size = candidate->first.size_bytes;
                    if (candidate_size < aligned_size ||
                        candidate_offset > aligned_offset ||
                        candidate->second.bytes.size() != candidate_size)
                    {
                        continue;
                    }

                    const auto relative_offset = aligned_offset - candidate_offset;
                    if (relative_offset > candidate_size - aligned_size ||
                        candidate_size >= best_size)
                    {
                        continue;
                    }

                    best = candidate;
                    best_size = candidate_size;
                    cached_offset = static_cast<std::size_t>(relative_offset);
                }
                if (best != read_cache_.end())
                {
                    cached = best;
                    contained_hit = true;
                }
            }
            if (cached != read_cache_.end() &&
                cached_offset <= cached->second.bytes.size() &&
                aligned_size <= cached->second.bytes.size() - cached_offset)
            {
                cached->second.last_use = ++read_cache_use_;
                std::copy_n(
                    cached->second.bytes.data() + cached_offset + prefix_bytes,
                    destination_size,
                    destination);
                out_bytes_read = destination_size;
                read_cache_hit_count_.fetch_add(1, std::memory_order_relaxed);
                if (contained_hit)
                {
                    read_cache_contained_hit_count_.fetch_add(1, std::memory_order_relaxed);
                }
                return true;
            }
            read_cache_miss_count_.fetch_add(1, std::memory_order_relaxed);
        }
    }

    DWORD bytes_read = 0;
    if (already_aligned)
    {
        if (!ReadAt(handle, aligned_offset, destination, static_cast<DWORD>(destination_size), bytes_read))
        {
            return false;
        }
        out_bytes_read = static_cast<std::size_t>(bytes_read);
        if (cacheable && bytes_read == aligned_size)
        {
            std::function<void()> hook;
            {
                std::lock_guard<std::mutex> hook_lock(test_hook_mutex_);
                hook = read_cache_miss_hook_for_tests_;
            }
            if (hook)
            {
                hook();
            }
            std::lock_guard<std::mutex> cache_lock(read_cache_mutex_);
            if (read_cache_generation != read_cache_generation_ ||
                read_cache_write_admissions_ != 0 ||
                (read_cache_generation & 1ull) != 0)
            {
                return true;
            }
            InsertReadCacheEntryLocked(
                aligned_offset,
                aligned_size,
                std::vector<std::byte>(destination, destination + aligned_size));
        }
        return true;
    }

    std::vector<std::byte> cache_bytes;
    static thread_local std::vector<std::byte> thread_local_read_scratch;
    std::unique_lock<std::mutex> shared_scratch_lock(read_scratch_mutex_, std::defer_lock);
    auto* scratch = &thread_local_read_scratch;
    if (aligned_size <= kReadThreadLocalScratchMaxBytes)
    {
        read_thread_local_scratch_use_count_.fetch_add(1, std::memory_order_relaxed);
    }
    else
    {
        shared_scratch_lock.lock();
        scratch = &read_scratch_;
    }

    if (scratch->size() < aligned_size)
    {
        scratch->resize(aligned_size);
        read_scratch_resize_count_.fetch_add(1, std::memory_order_relaxed);
        UpdateAtomicMax(read_scratch_max_bytes_, static_cast<std::uint64_t>(scratch->size()));
    }
    if (!ReadAt(handle, aligned_offset, scratch->data(), static_cast<DWORD>(aligned_size), bytes_read))
    {
        return false;
    }
    if (bytes_read < prefix_bytes)
    {
        return false;
    }

    const auto available = static_cast<std::size_t>(bytes_read) - prefix_bytes;
    const auto bytes_to_copy = std::min(destination_size, available);
    std::copy_n(
        scratch->data() + prefix_bytes,
        bytes_to_copy,
        destination);
    out_bytes_read = bytes_to_copy;
    if (cacheable && bytes_read == aligned_size)
    {
        cache_bytes.assign(
            scratch->begin(),
            scratch->begin() + static_cast<std::ptrdiff_t>(aligned_size));
    }
    if (shared_scratch_lock.owns_lock())
    {
        shared_scratch_lock.unlock();
    }
    if (!cache_bytes.empty())
    {
        std::function<void()> hook;
        {
            std::lock_guard<std::mutex> hook_lock(test_hook_mutex_);
            hook = read_cache_miss_hook_for_tests_;
        }
        if (hook)
        {
            hook();
        }
        std::lock_guard<std::mutex> cache_lock(read_cache_mutex_);
        if (read_cache_generation != read_cache_generation_ ||
            read_cache_write_admissions_ != 0 ||
            (read_cache_generation & 1ull) != 0)
        {
            return true;
        }
        InsertReadCacheEntryLocked(aligned_offset, aligned_size, std::move(cache_bytes));
    }
    return true;
}

bool BlockDevice::Write(std::uint64_t offset_bytes, const std::vector<std::byte>& buffer)
{
    return Write(offset_bytes, std::span<const std::byte>(buffer.data(), buffer.size()));
}

bool BlockDevice::Write(std::uint64_t offset_bytes, std::span<const std::byte> buffer)
{
    if (stable_read_only_image_) return false;
    ScopedPerfTimer perf_scope(write_perf_, static_cast<std::uint64_t>(buffer.size()));
    perf_scope.SetSecondary(unaligned_write_perf_);

    if (buffer.empty())
    {
        return true;
    }
    if (buffer.size() > static_cast<std::size_t>(std::numeric_limits<DWORD>::max()))
    {
        return false;
    }
    const auto fault_mode = ReadFaultMode(L"APFSACCESS_RW_FAULT_WRITE");

    if (offset_bytes > (std::numeric_limits<std::uint64_t>::max() - base_offset_bytes_))
    {
        return false;
    }
    offset_bytes += base_offset_bytes_;

    WriteSourceAdmission source_admission(*this);
    ReadCacheWriteAdmission write_admission(*this);
    InvokeWriteCacheInvalidationHookForTests();
    const WriteSpan cache_write{offset_bytes - base_offset_bytes_, buffer};
    ReadCacheWriteEpoch write_epoch(*this, std::span<const WriteSpan>(&cache_write, 1));

    std::unique_lock<std::mutex> write_lock(write_mutex_, std::defer_lock);
    {
        ScopedPerfTimer queue_wait_scope(write_queue_wait_perf_);
        write_lock.lock();
    }
    if (!ProbeUnderlyingDevice())
    {
        return false;
    }
    HANDLE handle = EnsureWriteHandle();
    if (handle == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    bool was_unaligned = false;
    const auto ok = WriteLocked(handle, offset_bytes, buffer, fault_mode, was_unaligned);
    if (was_unaligned)
    {
        perf_scope.MarkSecondary();
    }
    return ok;
}

bool BlockDevice::WriteBatch(std::span<const WriteSpan> writes)
{
    if (stable_read_only_image_) return false;
    last_io_error_.store(ERROR_SUCCESS, std::memory_order_relaxed);
    std::uint64_t total_bytes = 0;
    const WriteSpan* single_non_empty_write = nullptr;
    std::size_t non_empty_write_count = 0;
    for (const auto& write : writes)
    {
        if (write.buffer.empty())
        {
            continue;
        }
        single_non_empty_write = &write;
        ++non_empty_write_count;
        if (write.buffer.size() > static_cast<std::size_t>(std::numeric_limits<DWORD>::max()) ||
            write.offset_bytes > (std::numeric_limits<std::uint64_t>::max() - base_offset_bytes_))
        {
            last_io_error_.store(ERROR_INVALID_PARAMETER, std::memory_order_relaxed);
            return false;
        }
        const auto write_bytes = static_cast<std::uint64_t>(write.buffer.size());
        if (total_bytes <= (std::numeric_limits<std::uint64_t>::max() - write_bytes))
        {
            total_bytes += write_bytes;
        }
        else
        {
            total_bytes = std::numeric_limits<std::uint64_t>::max();
        }
    }

    ScopedPerfTimer perf_scope(batch_write_perf_, total_bytes);
    if (writes.empty() || total_bytes == 0)
    {
        return true;
    }

    WriteSourceAdmission source_admission(*this);
    const auto fault_mode = ReadFaultMode(L"APFSACCESS_RW_FAULT_WRITE");
    if (fault_mode.has_value())
    {
        for (const auto& write : writes)
        {
            if (!write.buffer.empty() && !Write(write.offset_bytes, write.buffer))
            {
                return false;
            }
        }
        return true;
    }

    const bool async_block_io_enabled = IsAsyncBlockIoEnabled();
    const bool may_split_single_write_async =
        single_non_empty_write != nullptr &&
        single_non_empty_write->buffer.size() >= kMinAsyncSingleWriteBytes &&
        async_block_io_enabled;
    if (non_empty_write_count == 1 &&
        single_non_empty_write != nullptr &&
        !may_split_single_write_async)
    {
        ReadCacheWriteAdmission write_admission(*this);
        InvokeWriteCacheInvalidationHookForTests();
        ReadCacheWriteEpoch write_epoch(*this, writes);
        std::unique_lock<std::mutex> write_lock(write_mutex_, std::defer_lock);
        {
            ScopedPerfTimer queue_wait_scope(write_queue_wait_perf_);
            write_lock.lock();
        }
        if (!ProbeUnderlyingDevice())
        {
            return false;
        }
        HANDLE handle = EnsureWriteHandle();
        if (handle == INVALID_HANDLE_VALUE)
        {
            const auto error = GetLastError();
            last_io_error_.store(error == ERROR_SUCCESS ? ERROR_INVALID_HANDLE : error, std::memory_order_relaxed);
            return false;
        }

        bool was_unaligned = false;
        const auto ok = WriteLocked(
            handle,
            single_non_empty_write->offset_bytes + base_offset_bytes_,
            single_non_empty_write->buffer,
            std::nullopt,
            was_unaligned);
        if (was_unaligned && IsPerfCountersEnabled())
        {
            unaligned_write_perf_.Observe(
                0,
                static_cast<std::uint64_t>(single_non_empty_write->buffer.size()));
        }
        return ok;
    }

    struct PendingWrite
    {
        std::uint64_t absolute_offset = 0;
        std::span<const std::byte> buffer{};
        const void* merge_token = nullptr;
    };
    constexpr std::size_t kInlinePendingWriteCount = 8;
    alignas(PendingWrite) std::array<std::byte, sizeof(PendingWrite) * kInlinePendingWriteCount>
        pending_inline_storage{};
    std::pmr::monotonic_buffer_resource pending_resource(
        pending_inline_storage.data(),
        pending_inline_storage.size());
    const std::pmr::polymorphic_allocator<PendingWrite> pending_allocator(&pending_resource);
    std::pmr::vector<PendingWrite> pending(pending_allocator);
    pending.reserve(non_empty_write_count);
    for (const auto& write : writes)
    {
        if (write.buffer.empty())
        {
            continue;
        }
        pending.push_back(PendingWrite{write.offset_bytes + base_offset_bytes_, write.buffer, write.merge_token});
    }
    if (pending.empty())
    {
        return true;
    }
    if (pending.size() > 1)
    {
        bool already_ordered_non_overlapping = true;
        std::uint64_t previous_end = 0;
        bool have_previous = false;
        for (const auto& write : pending)
        {
            const auto write_bytes = static_cast<std::uint64_t>(write.buffer.size());
            if (write.absolute_offset > (std::numeric_limits<std::uint64_t>::max() - write_bytes))
            {
                already_ordered_non_overlapping = false;
                break;
            }
            const auto write_end = write.absolute_offset + write_bytes;
            if (have_previous && write.absolute_offset < previous_end)
            {
                already_ordered_non_overlapping = false;
                break;
            }
            previous_end = write_end;
            have_previous = true;
        }

        if (!already_ordered_non_overlapping)
        {
            std::pmr::vector<PendingWrite> sorted_pending(pending, pending_allocator);
            std::stable_sort(
                sorted_pending.begin(),
                sorted_pending.end(),
                [](const PendingWrite& left, const PendingWrite& right)
                {
                    return left.absolute_offset < right.absolute_offset;
                });
            batch_sort_count_.fetch_add(1, std::memory_order_relaxed);

            bool can_reorder = true;
            previous_end = 0;
            have_previous = false;
            for (const auto& write : sorted_pending)
            {
                const auto write_bytes = static_cast<std::uint64_t>(write.buffer.size());
                if (write.absolute_offset > (std::numeric_limits<std::uint64_t>::max() - write_bytes))
                {
                    can_reorder = false;
                    break;
                }
                const auto write_end = write.absolute_offset + write_bytes;
                if (have_previous && write.absolute_offset < previous_end)
                {
                    can_reorder = false;
                    break;
                }
                previous_end = write_end;
                have_previous = true;
            }
            if (can_reorder)
            {
                pending = std::move(sorted_pending);
            }
        }
    }

    ReadCacheWriteAdmission write_admission(*this);
    InvokeWriteCacheInvalidationHookForTests();
    ReadCacheWriteEpoch write_epoch(*this, writes);
    std::unique_lock<std::mutex> write_lock(write_mutex_, std::defer_lock);
    {
        ScopedPerfTimer queue_wait_scope(write_queue_wait_perf_);
        write_lock.lock();
    }
    if (!ProbeUnderlyingDevice())
    {
        return false;
    }
    HANDLE handle = EnsureWriteHandle();
    if (handle == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    const auto try_async_batch = [&]() -> std::optional<bool>
    {
        const bool single_large_write =
            pending.size() == 1 &&
            pending.front().buffer.size() >= kMinAsyncSingleWriteBytes;
        if (!async_block_io_enabled || (pending.size() < 2 && !single_large_write))
        {
            return std::nullopt;
        }

        const auto block_size = static_cast<std::uint64_t>(LogicalBlockSize());
        std::uint64_t previous_end = 0;
        bool have_previous = false;
        for (const auto& write : pending)
        {
            const auto write_bytes = static_cast<std::uint64_t>(write.buffer.size());
            if (write_bytes == 0 ||
                write.absolute_offset % block_size != 0 ||
                write_bytes % block_size != 0 ||
                write.absolute_offset > (std::numeric_limits<std::uint64_t>::max() - write_bytes))
            {
                return std::nullopt;
            }

            const auto write_end = write.absolute_offset + write_bytes;
            if (have_previous && write.absolute_offset < previous_end)
            {
                return std::nullopt;
            }
            previous_end = write_end;
            have_previous = true;
        }

        struct AsyncChunk
        {
            std::uint64_t absolute_offset = 0;
            std::span<const std::byte> buffer{};
            bool contiguous_view = false;
            std::size_t merged_storage_offset = 0;
            std::size_t merged_storage_bytes = 0;
        };
        // All copied chunks live in one backing store until every overlapped
        // request has completed. This avoids one heap allocation per merged
        // group while keeping each outstanding request's buffer stable.
        std::size_t merged_storage_bytes = 0;
        std::vector<AsyncChunk> chunks;
        chunks.reserve(pending.size());
        for (std::size_t index = 0; index < pending.size();)
        {
            const auto& first = pending[index];
            const auto first_bytes = static_cast<std::uint64_t>(first.buffer.size());
            if (first_bytes > kMaxMergedBatchBytes)
            {
                std::uint64_t chunk_offset = 0;
                while (chunk_offset < first_bytes)
                {
                    const auto chunk_bytes_u64 = std::min<std::uint64_t>(
                        kMaxDirectAsyncChunkBytes,
                        first_bytes - chunk_offset);
                    if (chunk_bytes_u64 > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                    {
                        return std::optional<bool>{false};
                    }
                    const auto chunk_bytes = static_cast<std::size_t>(chunk_bytes_u64);
                    const auto span_offset = static_cast<std::size_t>(chunk_offset);
                    chunks.push_back(AsyncChunk{
                        first.absolute_offset + chunk_offset,
                        first.buffer.subspan(span_offset, chunk_bytes),
                        false,
                    });
                    chunk_offset += chunk_bytes_u64;
                }
                ++index;
                continue;
            }

            auto physical_end = first.absolute_offset + first_bytes;
            std::size_t merge_end = index + 1;
            while (merge_end < pending.size())
            {
                const auto& next = pending[merge_end];
                const auto next_bytes = static_cast<std::uint64_t>(next.buffer.size());
                if (next.absolute_offset != physical_end ||
                    next_bytes > (std::numeric_limits<std::uint64_t>::max() - physical_end))
                {
                    break;
                }
                const auto next_physical_end = physical_end + next_bytes;
                if ((next_physical_end - first.absolute_offset) > kMaxMergedBatchBytes)
                {
                    break;
                }
                physical_end = next_physical_end;
                ++merge_end;
            }

            if (merge_end == index + 1)
            {
                chunks.push_back(AsyncChunk{first.absolute_offset, first.buffer, false});
                index = merge_end;
                continue;
            }

            const auto chunk_bytes_u64 = physical_end - first.absolute_offset;
            if (chunk_bytes_u64 > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
            {
                return std::optional<bool>{false};
            }
            bool can_write_adjacent_spans_directly = true;
            std::uint64_t adjacent_span_bytes = 0;
            for (std::size_t current = index; current < merge_end; ++current)
            {
                const auto span_bytes = static_cast<std::uint64_t>(pending[current].buffer.size());
                if (span_bytes < kMinAsyncDirectAdjacentSpanBytes)
                {
                    can_write_adjacent_spans_directly = false;
                    break;
                }
                adjacent_span_bytes += span_bytes;
            }
            if (can_write_adjacent_spans_directly)
            {
                for (std::size_t current = index; current < merge_end; ++current)
                {
                    chunks.push_back(AsyncChunk{pending[current].absolute_offset, pending[current].buffer, false});
                }
                async_direct_adjacent_span_count_.fetch_add(
                    static_cast<std::uint64_t>(merge_end - index),
                    std::memory_order_relaxed);
                async_direct_adjacent_span_bytes_.fetch_add(adjacent_span_bytes, std::memory_order_relaxed);
                index = merge_end;
                continue;
            }
            bool contiguous_view = false;
            if (first.merge_token != nullptr)
            {
                const auto* base_data = first.buffer.data();
                contiguous_view = base_data != nullptr;
                for (std::size_t current = index + 1; contiguous_view && current < merge_end; ++current)
                {
                    const auto expected_offset = pending[current].absolute_offset - first.absolute_offset;
                    const std::byte* expected_data = nullptr;
                    contiguous_view =
                        pending[current].merge_token == first.merge_token &&
                        AddOffsetToPointer(base_data, expected_offset, expected_data) &&
                        pending[current].buffer.data() == expected_data;
                }
            }
            if (contiguous_view)
            {
                chunks.push_back(AsyncChunk{
                    first.absolute_offset,
                    std::span<const std::byte>(first.buffer.data(), static_cast<std::size_t>(chunk_bytes_u64)),
                    true,
                });
                index = merge_end;
                continue;
            }

            const auto merged_bytes = static_cast<std::size_t>(chunk_bytes_u64);
            const auto merged_offset = merged_storage_bytes;
            if (merged_bytes > (std::numeric_limits<std::size_t>::max() - merged_offset))
            {
                return std::optional<bool>{false};
            }
            const auto required_storage_bytes = merged_offset + merged_bytes;
            if (!EnsureMergedBatchScratch(required_storage_bytes, merged_storage_bytes))
            {
                return std::optional<bool>{false};
            }
            merged_storage_bytes = required_storage_bytes;
            auto* merged = merged_batch_scratch_.get() + static_cast<std::ptrdiff_t>(merged_offset);
            std::size_t copied_bytes = 0;
            for (std::size_t current = index; current < merge_end; ++current)
            {
                const auto& source = pending[current].buffer;
                if (source.size() > (merged_bytes - copied_bytes))
                {
                    return std::optional<bool>{false};
                }

                std::copy_n(
                    source.data(),
                    source.size(),
                    merged + static_cast<std::ptrdiff_t>(copied_bytes));
                copied_bytes += source.size();
            }
            if (copied_bytes != merged_bytes)
            {
                return std::optional<bool>{false};
            }
            merged_batch_direct_fill_count_.fetch_add(1, std::memory_order_relaxed);
            merged_batch_direct_fill_bytes_.fetch_add(chunk_bytes_u64, std::memory_order_relaxed);
            chunks.push_back(AsyncChunk{
                first.absolute_offset,
                {},
                false,
                merged_offset,
                merged_bytes,
            });
            index = merge_end;
        }

        for (auto& chunk : chunks)
        {
            if (chunk.merged_storage_bytes == 0)
            {
                continue;
            }
            if (chunk.merged_storage_offset > merged_storage_bytes ||
                chunk.merged_storage_bytes > (merged_storage_bytes - chunk.merged_storage_offset))
            {
                last_io_error_.store(ERROR_INVALID_PARAMETER, std::memory_order_relaxed);
                return std::optional<bool>{false};
            }
            chunk.buffer = std::span<const std::byte>(
                merged_batch_scratch_.get() + static_cast<std::ptrdiff_t>(chunk.merged_storage_offset),
                chunk.merged_storage_bytes);
        }

        if (chunks.size() < 2)
        {
            return std::nullopt;
        }

        struct AsyncRequest
        {
            OVERLAPPED overlapped{};
            HANDLE event = INVALID_HANDLE_VALUE;
            DWORD expected_bytes = 0;
            bool issued = false;
        };

        const bool observe_perf = IsPerfCountersEnabled();
        const auto started = observe_perf ? std::chrono::steady_clock::now() : std::chrono::steady_clock::time_point{};
        std::uint64_t async_bytes = 0;
        std::uint64_t contiguous_bytes = 0;
        std::size_t max_window_depth = 0;
        std::size_t total_issued = 0;
        const auto queue_depth = AsyncBlockIoQueueDepth();
        const auto fail_after_issues = ReadOptionalPositiveSizeEnv(
            L"APFSACCESS_RW_FAULT_ASYNC_BATCH_AFTER_ISSUES",
            std::numeric_limits<std::size_t>::max());
        if (!EnsureAsyncEventPool(queue_depth))
        {
            const auto error = GetLastError();
            last_io_error_.store(error == ERROR_SUCCESS ? ERROR_NOT_ENOUGH_MEMORY : error, std::memory_order_relaxed);
            return std::optional<bool>{false};
        }
        for (std::size_t cursor = 0; cursor < chunks.size();)
        {
            const auto window_depth = std::min<std::size_t>(queue_depth, chunks.size() - cursor);
            max_window_depth = std::max(max_window_depth, window_depth);
            std::array<AsyncRequest, kMaxAsyncBlockIoQueueDepth> requests{};
            async_request_stack_window_count_.fetch_add(1, std::memory_order_relaxed);
            bool window_ok = true;
            std::size_t issued = 0;

            for (; issued < window_depth; ++issued)
            {
                if (fail_after_issues.has_value() && total_issued >= fail_after_issues.value())
                {
                    last_io_error_.store(ERROR_OPERATION_ABORTED, std::memory_order_relaxed);
                    window_ok = false;
                    break;
                }

                const auto& chunk = chunks[cursor + issued];
                if (chunk.buffer.size() > static_cast<std::size_t>(std::numeric_limits<DWORD>::max()))
                {
                    window_ok = false;
                    break;
                }

                auto& request = requests[issued];
                request.expected_bytes = static_cast<DWORD>(chunk.buffer.size());
                request.event = async_event_pool_[issued];
                if (request.event == INVALID_HANDLE_VALUE ||
                    !ResetEvent(request.event))
                {
                    const auto error = GetLastError();
                    last_io_error_.store(error == ERROR_SUCCESS ? ERROR_INVALID_HANDLE : error, std::memory_order_relaxed);
                    window_ok = false;
                    break;
                }
                request.overlapped.Offset = static_cast<DWORD>(chunk.absolute_offset & 0xffffffffull);
                request.overlapped.OffsetHigh = static_cast<DWORD>(chunk.absolute_offset >> 32);
                request.overlapped.hEvent = request.event;

                if (!RawWriteSpanAllowed(chunk.absolute_offset, chunk.buffer.size()))
                {
                    // Admitted raw range breached: fail the batch before issuing.
                    last_io_error_.store(ERROR_ACCESS_DENIED, std::memory_order_relaxed);
                    window_ok = false;
                    break;
                }
                if (WriteFile(
                        handle,
                        chunk.buffer.data(),
                        request.expected_bytes,
                        nullptr,
                        &request.overlapped))
                {
                    request.issued = true;
                    ++total_issued;
                    async_bytes += request.expected_bytes;
                    if (chunk.contiguous_view)
                    {
                        contiguous_bytes += request.expected_bytes;
                    }
                    continue;
                }

                const auto error = GetLastError();
                if (error != ERROR_IO_PENDING)
                {
                    last_io_error_.store(error == ERROR_SUCCESS ? ERROR_WRITE_FAULT : error, std::memory_order_relaxed);
                    window_ok = false;
                    break;
                }

                request.issued = true;
                ++total_issued;
                async_bytes += request.expected_bytes;
                if (chunk.contiguous_view)
                {
                    contiguous_bytes += request.expected_bytes;
                }
            }

            for (std::size_t index = 0; index < issued; ++index)
            {
                auto& request = requests[index];
                DWORD bytes_written = 0;
                if (!request.issued)
                {
                    continue;
                }
                DWORD completion_error = ERROR_SUCCESS;
                if (!WaitForOverlappedCompletion(
                        handle,
                        request.overlapped,
                        bytes_written,
                        completion_error))
                {
                    last_io_error_.store(
                        completion_error == ERROR_SUCCESS ? ERROR_WRITE_FAULT : completion_error,
                        std::memory_order_relaxed);
                    window_ok = false;
                }
                else if (bytes_written != request.expected_bytes)
                {
                    last_io_error_.store(ERROR_WRITE_FAULT, std::memory_order_relaxed);
                    window_ok = false;
                }
            }

            if (!window_ok)
            {
                return std::optional<bool>{false};
            }

            cursor += window_depth;
        }

        UpdateAtomicMax(async_max_queue_depth_, static_cast<std::uint64_t>(max_window_depth));
        if (observe_perf)
        {
            async_batch_write_perf_.Observe(ElapsedMicroseconds(started), async_bytes);
        }
        if (contiguous_bytes > 0)
        {
            contiguous_batch_write_perf_.Observe(0, contiguous_bytes);
        }
        return std::optional<bool>{true};
    };

    if (auto async_result = try_async_batch())
    {
        return *async_result;
    }

    const bool observe_perf = IsPerfCountersEnabled();

    // A small group of nearby unaligned spans can share one aligned read-modify-write
    // window. The bounded window keeps read amplification predictable while applying
    // spans in caller order so overlapping writes retain last-writer-wins semantics.
    const auto try_rmw_group = [&](std::size_t begin, std::size_t& out_end) -> std::optional<bool>
    {
        out_end = begin;
        if (begin >= pending.size())
        {
            return std::nullopt;
        }

        const auto& first = pending[begin];
        const auto first_bytes = static_cast<std::uint64_t>(first.buffer.size());
        if (first_bytes == 0 ||
            first.absolute_offset > (std::numeric_limits<std::uint64_t>::max() - first_bytes))
        {
            return std::nullopt;
        }

        const auto block_size = static_cast<std::uint64_t>(LogicalBlockSize());
        const auto first_end = first.absolute_offset + first_bytes;
        const bool first_aligned =
            first.absolute_offset % block_size == 0 &&
            first_bytes % block_size == 0;
        if (first_aligned)
        {
            return std::nullopt;
        }

        auto group_start = AlignDown(first.absolute_offset, block_size);
        auto group_physical_end = AlignUp(first_end, block_size);
        if (group_physical_end == 0 || group_physical_end < group_start ||
            (group_physical_end - group_start) > kMaxRmwGroupBytes)
        {
            return std::nullopt;
        }

        auto actual_start = first.absolute_offset;
        auto actual_end = first_end;
        auto previous_write_end = first_end;
        std::uint64_t payload_bytes = first_bytes;
        std::size_t group_end = begin + 1;
        bool has_non_contiguous_span = false;
        for (; group_end < pending.size() &&
               (group_end - begin) < kMaxRmwGroupWrites;
             ++group_end)
        {
            const auto& candidate = pending[group_end];
            const auto candidate_bytes = static_cast<std::uint64_t>(candidate.buffer.size());
            if (candidate_bytes == 0 ||
                candidate.absolute_offset > (std::numeric_limits<std::uint64_t>::max() - candidate_bytes))
            {
                return std::nullopt;
            }

            const auto candidate_end = candidate.absolute_offset + candidate_bytes;
            const auto gap = candidate.absolute_offset >= actual_end
                ? candidate.absolute_offset - actual_end
                : candidate_end <= actual_start
                    ? actual_start - candidate_end
                    : 0;
            if (gap > kMaxRmwGroupGapBytes)
            {
                break;
            }

            const auto next_actual_start = (std::min)(actual_start, candidate.absolute_offset);
            const auto next_actual_end = (std::max)(actual_end, candidate_end);
            const auto next_group_start = AlignDown(next_actual_start, block_size);
            const auto next_group_end = AlignUp(next_actual_end, block_size);
            if (next_group_end == 0 || next_group_end < next_group_start ||
                (next_group_end - next_group_start) > kMaxRmwGroupBytes)
            {
                break;
            }
            if (payload_bytes > (std::numeric_limits<std::uint64_t>::max() - candidate_bytes))
            {
                return std::nullopt;
            }

            has_non_contiguous_span |= candidate.absolute_offset != previous_write_end;
            group_start = next_group_start;
            group_physical_end = next_group_end;
            actual_start = next_actual_start;
            actual_end = next_actual_end;
            previous_write_end = candidate_end;
            payload_bytes += candidate_bytes;
        }

        if (group_end == begin + 1 || !has_non_contiguous_span)
        {
            return std::nullopt;
        }

        const auto group_bytes_u64 = group_physical_end - group_start;
        if (group_bytes_u64 == 0 ||
            group_bytes_u64 > static_cast<std::uint64_t>(std::numeric_limits<DWORD>::max()) ||
            group_bytes_u64 > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
        {
            return std::nullopt;
        }
        const auto group_bytes = static_cast<std::size_t>(group_bytes_u64);
        ScopedPerfTimer rmw_perf(rmw_group_write_perf_, payload_bytes);
        if (write_scratch_.size() < group_bytes)
        {
            write_scratch_.resize(group_bytes);
            write_scratch_resize_count_.fetch_add(1, std::memory_order_relaxed);
            UpdateAtomicMax(write_scratch_max_bytes_, static_cast<std::uint64_t>(write_scratch_.size()));
        }

        DWORD bytes_read = 0;
        if (!ReadAt(handle, group_start, write_scratch_.data(), static_cast<DWORD>(group_bytes), bytes_read) ||
            bytes_read != group_bytes)
        {
            return false;
        }

        for (std::size_t current = begin; current < group_end; ++current)
        {
            const auto& write = pending[current];
            const auto write_bytes = write.buffer.size();
            if (write.absolute_offset < group_start ||
                write.absolute_offset - group_start > group_bytes_u64 ||
                write_bytes > group_bytes - static_cast<std::size_t>(write.absolute_offset - group_start))
            {
                last_io_error_.store(ERROR_INVALID_PARAMETER, std::memory_order_relaxed);
                return false;
            }
            std::copy(
                write.buffer.begin(),
                write.buffer.end(),
                write_scratch_.begin() + static_cast<std::ptrdiff_t>(write.absolute_offset - group_start));
        }

        // Grouped RMW also rewrites gaps between the validated caller spans.
        if (read_cache_enabled_)
        {
            std::lock_guard<std::mutex> cache_lock(read_cache_mutex_);
            if (InvalidateReadCacheRangeLocked(group_start, group_bytes_u64))
            {
                read_cache_invalidation_count_.fetch_add(1, std::memory_order_relaxed);
            }
        }
        DWORD bytes_written = 0;
        if (!WriteAt(handle, group_start, write_scratch_.data(), static_cast<DWORD>(group_bytes), bytes_written) ||
            bytes_written != group_bytes)
        {
            return false;
        }
        if (observe_perf)
        {
            unaligned_write_perf_.Observe(0, payload_bytes);
        }
        out_end = group_end;
        return true;
    };

    for (std::size_t index = 0; index < pending.size();)
    {
        std::size_t rmw_group_end = index;
        if (auto rmw_result = try_rmw_group(index, rmw_group_end))
        {
            if (!*rmw_result)
            {
                return false;
            }
            index = rmw_group_end;
            continue;
        }

        const auto& first = pending[index];
        const auto first_bytes = static_cast<std::uint64_t>(first.buffer.size());
        if (first.absolute_offset > (std::numeric_limits<std::uint64_t>::max() - first_bytes))
        {
            return false;
        }

        auto physical_end = first.absolute_offset + first_bytes;
        std::size_t merge_end = index + 1;
        while (merge_end < pending.size())
        {
            const auto& next = pending[merge_end];
            const auto next_bytes = static_cast<std::uint64_t>(next.buffer.size());
            if (next.absolute_offset != physical_end ||
                next_bytes > (std::numeric_limits<std::uint64_t>::max() - physical_end))
            {
                break;
            }
            const auto next_physical_end = physical_end + next_bytes;
            if ((next_physical_end - first.absolute_offset) > static_cast<std::uint64_t>(std::numeric_limits<DWORD>::max()))
            {
                break;
            }
            physical_end = next_physical_end;
            ++merge_end;
        }

        bool was_unaligned = false;
        if (merge_end == index + 1)
        {
            if (!WriteLocked(handle, first.absolute_offset, first.buffer, std::nullopt, was_unaligned))
            {
                return false;
            }
            if (was_unaligned && observe_perf)
            {
                unaligned_write_perf_.Observe(0, static_cast<std::uint64_t>(first.buffer.size()));
            }
            index = merge_end;
            continue;
        }

        std::size_t chunk_begin = index;
        while (chunk_begin < merge_end)
        {
            std::uint64_t chunk_bytes_u64 = 0;
            std::size_t chunk_end = chunk_begin;
            while (chunk_end < merge_end)
            {
                const auto write_bytes = static_cast<std::uint64_t>(pending[chunk_end].buffer.size());
                if (write_bytes > kMaxMergedBatchBytes)
                {
                    if (chunk_end == chunk_begin)
                    {
                        ++chunk_end;
                    }
                    break;
                }
                if (chunk_bytes_u64 > (kMaxMergedBatchBytes - write_bytes))
                {
                    break;
                }
                chunk_bytes_u64 += write_bytes;
                ++chunk_end;
            }

            if (chunk_end == chunk_begin)
            {
                return false;
            }
            if (chunk_end == chunk_begin + 1)
            {
                const auto& write = pending[chunk_begin];
                if (!WriteLocked(handle, write.absolute_offset, write.buffer, std::nullopt, was_unaligned))
                {
                    return false;
                }
                if (was_unaligned && observe_perf)
                {
                    unaligned_write_perf_.Observe(0, static_cast<std::uint64_t>(write.buffer.size()));
                }
                chunk_begin = chunk_end;
                continue;
            }
            if (chunk_bytes_u64 > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
            {
                return false;
            }

            const auto chunk_bytes = static_cast<std::size_t>(chunk_bytes_u64);
            bool contiguous_view = false;
            if (pending[chunk_begin].merge_token != nullptr)
            {
                const auto* base_data = pending[chunk_begin].buffer.data();
                contiguous_view = base_data != nullptr;
                for (std::size_t current = chunk_begin + 1; contiguous_view && current < chunk_end; ++current)
                {
                    const auto expected_offset = pending[current].absolute_offset - pending[chunk_begin].absolute_offset;
                    const std::byte* expected_data = nullptr;
                    contiguous_view =
                        pending[current].merge_token == pending[chunk_begin].merge_token &&
                        AddOffsetToPointer(base_data, expected_offset, expected_data) &&
                        pending[current].buffer.data() == expected_data;
                }
            }
            if (contiguous_view)
            {
                const auto merged_view = std::span<const std::byte>(pending[chunk_begin].buffer.data(), chunk_bytes);
                if (!WriteLocked(handle, pending[chunk_begin].absolute_offset, merged_view, std::nullopt, was_unaligned))
                {
                    return false;
                }
                if (observe_perf)
                {
                    contiguous_batch_write_perf_.Observe(0, chunk_bytes_u64);
                    if (was_unaligned)
                    {
                        unaligned_write_perf_.Observe(0, chunk_bytes_u64);
                    }
                }
                chunk_begin = chunk_end;
                continue;
            }

            if (!EnsureMergedBatchScratch(chunk_bytes))
            {
                return false;
            }

            std::size_t copied_bytes = 0;
            for (std::size_t current = chunk_begin; current < chunk_end; ++current)
            {
                const auto& source = pending[current].buffer;
                if (source.size() > (merged_batch_scratch_capacity_ - copied_bytes))
                {
                    return false;
                }

                std::copy_n(
                    source.data(),
                    source.size(),
                    merged_batch_scratch_.get() + static_cast<std::ptrdiff_t>(copied_bytes));
                copied_bytes += source.size();
            }
            if (copied_bytes != chunk_bytes ||
                !WriteLocked(
                    handle,
                    pending[chunk_begin].absolute_offset,
                    std::span<const std::byte>(merged_batch_scratch_.get(), chunk_bytes),
                    std::nullopt,
                    was_unaligned))
            {
                return false;
            }
            merged_batch_direct_fill_count_.fetch_add(1, std::memory_order_relaxed);
            merged_batch_direct_fill_bytes_.fetch_add(chunk_bytes_u64, std::memory_order_relaxed);
            if (observe_perf)
            {
                merged_batch_write_perf_.Observe(0, chunk_bytes_u64);
                if (was_unaligned)
                {
                    unaligned_write_perf_.Observe(0, chunk_bytes_u64);
                }
            }
            chunk_begin = chunk_end;
        }
        index = merge_end;
    }

    return true;
}

bool BlockDevice::Flush()
{
    if (stable_read_only_image_) return false;
    ScopedPerfTimer perf_scope(flush_perf_);

    if (IsFaultSwitchEnabled(L"APFSACCESS_RW_FAULT_FLUSH"))
    {
        return false;
    }

    std::unique_lock<std::mutex> write_lock(write_mutex_, std::defer_lock);
    {
        ScopedPerfTimer queue_wait_scope(flush_queue_wait_perf_);
        write_lock.lock();
    }
    if (!ProbeUnderlyingDevice(true))
    {
        return false;
    }
    HANDLE handle = EnsureWriteHandle();
    if (handle == INVALID_HANDLE_VALUE)
    {
        const auto error = GetLastError();
        last_io_error_.store(error == ERROR_SUCCESS ? ERROR_INVALID_HANDLE : error, std::memory_order_relaxed);
        return false;
    }

    if (FlushFileBuffers(handle) == FALSE)
    {
        const auto error = GetLastError();
        last_io_error_.store(error == ERROR_SUCCESS ? ERROR_WRITE_FAULT : error, std::memory_order_relaxed);
        return false;
    }

    last_io_error_.store(ERROR_SUCCESS, std::memory_order_relaxed);
    return true;
}

bool BlockDevice::WriteLocked(
    HANDLE handle,
    std::uint64_t absolute_offset_bytes,
    std::span<const std::byte> buffer,
    const std::optional<std::wstring>& fault_mode,
    bool& out_was_unaligned)
{
    out_was_unaligned = false;
    if (handle == INVALID_HANDLE_VALUE)
    {
        last_io_error_.store(ERROR_INVALID_HANDLE, std::memory_order_relaxed);
        return false;
    }
    if (buffer.empty())
    {
        return true;
    }
    if (buffer.size() > static_cast<std::size_t>(std::numeric_limits<DWORD>::max()))
    {
        last_io_error_.store(ERROR_INVALID_PARAMETER, std::memory_order_relaxed);
        return false;
    }
    if (fault_mode.has_value() &&
        (IsFaultMode(*fault_mode, L"1") ||
         IsFaultMode(*fault_mode, L"true") ||
         IsFaultMode(*fault_mode, L"yes") ||
         IsFaultMode(*fault_mode, L"fail")))
    {
        last_io_error_.store(ERROR_WRITE_FAULT, std::memory_order_relaxed);
        return false;
    }

    const auto block_size = static_cast<std::uint64_t>(LogicalBlockSize());
    const auto aligned_offset = AlignDown(absolute_offset_bytes, block_size);
    const auto prefix_bytes = static_cast<std::size_t>(absolute_offset_bytes - aligned_offset);
    if (buffer.size() > (std::numeric_limits<std::uint64_t>::max() - static_cast<std::uint64_t>(prefix_bytes)))
    {
        last_io_error_.store(ERROR_INVALID_PARAMETER, std::memory_order_relaxed);
        return false;
    }
    const auto requested_window = static_cast<std::uint64_t>(prefix_bytes) + static_cast<std::uint64_t>(buffer.size());
    const auto aligned_size_u64 = AlignUp(requested_window, block_size);
    if (aligned_size_u64 == 0 || aligned_size_u64 > static_cast<std::uint64_t>(std::numeric_limits<DWORD>::max()))
    {
        last_io_error_.store(ERROR_INVALID_PARAMETER, std::memory_order_relaxed);
        return false;
    }
    const auto aligned_size = static_cast<std::size_t>(aligned_size_u64);
    if (!RawWriteSpanAllowed(aligned_offset, aligned_size_u64))
    {
        // Admitted raw range breached (including RMW alignment spill):
        // fail closed, never write outside the bound container.
        last_io_error_.store(ERROR_ACCESS_DENIED, std::memory_order_relaxed);
        return false;
    }

    const bool already_aligned =
        prefix_bytes == 0 &&
        static_cast<std::uint64_t>(buffer.size()) == aligned_size_u64;
    out_was_unaligned = !already_aligned;

    const auto write_once = [&](const std::byte* write_buffer, std::size_t write_size) -> bool
    {
        DWORD bytes_written = 0;
        if (!WriteAt(handle, aligned_offset, write_buffer, static_cast<DWORD>(write_size), bytes_written))
        {
            return false;
        }

        return bytes_written == write_size;
    };

    if (!fault_mode.has_value())
    {
        if (already_aligned)
        {
            return write_once(buffer.data(), buffer.size());
        }

        if (write_scratch_.size() < aligned_size)
        {
            write_scratch_.resize(aligned_size);
            write_scratch_resize_count_.fetch_add(1, std::memory_order_relaxed);
            UpdateAtomicMax(write_scratch_max_bytes_, static_cast<std::uint64_t>(write_scratch_.size()));
        }
        DWORD bytes_read = 0;
        if (!ReadAt(handle, aligned_offset, write_scratch_.data(), static_cast<DWORD>(aligned_size), bytes_read) ||
            bytes_read != aligned_size)
        {
            return false;
        }
        std::copy(buffer.begin(), buffer.end(), write_scratch_.begin() + static_cast<std::ptrdiff_t>(prefix_bytes));
        return write_once(write_scratch_.data(), aligned_size);
    }

    if (IsFaultMode(*fault_mode, L"zero-bytes"))
    {
        return false;
    }

    if (IsFaultMode(*fault_mode, L"first-sector") ||
        IsFaultMode(*fault_mode, L"first-half") ||
        IsFaultMode(*fault_mode, L"all-except-last-sector") ||
        IsFaultMode(*fault_mode, L"corrupt-one-byte"))
    {
        const std::byte* write_buffer = buffer.data();
        std::size_t write_size = buffer.size();
        if (!already_aligned)
        {
            if (write_scratch_.size() < aligned_size)
            {
                write_scratch_.resize(aligned_size);
                write_scratch_resize_count_.fetch_add(1, std::memory_order_relaxed);
                UpdateAtomicMax(write_scratch_max_bytes_, static_cast<std::uint64_t>(write_scratch_.size()));
            }
            DWORD bytes_read = 0;
            if (!ReadAt(handle, aligned_offset, write_scratch_.data(), static_cast<DWORD>(aligned_size), bytes_read) ||
                bytes_read != aligned_size)
            {
                return false;
            }
            std::copy(buffer.begin(), buffer.end(), write_scratch_.begin() + static_cast<std::ptrdiff_t>(prefix_bytes));
            write_buffer = write_scratch_.data();
            write_size = aligned_size;
        }

        std::vector<std::byte> fault_buffer(write_buffer, write_buffer + write_size);
        std::size_t fault_write_size = fault_buffer.size();
        if (IsFaultMode(*fault_mode, L"first-sector"))
        {
            fault_write_size = std::min<std::size_t>(fault_write_size, static_cast<std::size_t>(block_size));
        }
        else if (IsFaultMode(*fault_mode, L"first-half"))
        {
            fault_write_size = std::max<std::size_t>(1, fault_write_size / 2);
        }
        else if (IsFaultMode(*fault_mode, L"all-except-last-sector"))
        {
            if (fault_write_size <= static_cast<std::size_t>(block_size))
            {
                fault_write_size = 0;
            }
            else
            {
                fault_write_size -= static_cast<std::size_t>(block_size);
            }
        }
        else
        {
            fault_buffer.front() ^= std::byte{0xff};
        }

        DWORD bytes_written = 0;
        if (fault_write_size > 0 &&
            !WriteAt(handle, aligned_offset, fault_buffer.data(), static_cast<DWORD>(fault_write_size), bytes_written))
        {
            return false;
        }
        return false;
    }

    return false;
}

bool BlockDevice::EnsureMergedBatchScratch(std::size_t bytes, std::size_t preserve_bytes)
{
    if (bytes == 0)
    {
        return true;
    }
    if (merged_batch_scratch_capacity_ >= bytes && merged_batch_scratch_)
    {
        return true;
    }

    auto scratch = std::make_unique_for_overwrite<std::byte[]>(bytes);
    if (preserve_bytes > 0 && merged_batch_scratch_)
    {
        const auto bytes_to_preserve = std::min(
            preserve_bytes,
            std::min(bytes, merged_batch_scratch_capacity_));
        std::copy_n(merged_batch_scratch_.get(), bytes_to_preserve, scratch.get());
    }
    merged_batch_scratch_ = std::move(scratch);
    merged_batch_scratch_capacity_ = bytes;
    merged_batch_scratch_resize_count_.fetch_add(1, std::memory_order_relaxed);
    UpdateAtomicMax(merged_batch_scratch_max_bytes_, static_cast<std::uint64_t>(bytes));
    return true;
}

bool BlockDevice::EnsureAsyncEventPool(std::size_t count)
{
    if (count == 0)
    {
        return true;
    }

    if (async_event_pool_.size() >= count)
    {
        return true;
    }

    async_event_pool_.reserve(count);
    while (async_event_pool_.size() < count)
    {
        HANDLE event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (event == nullptr)
        {
            return false;
        }

        async_event_pool_.push_back(event);
        async_event_create_count_.fetch_add(1, std::memory_order_relaxed);
        UpdateAtomicMax(async_event_pool_max_depth_, static_cast<std::uint64_t>(async_event_pool_.size()));
    }

    return true;
}

std::shared_ptr<BlockDevice> BlockDevice::OpenStableReadOnlyImage(
    std::wstring path, std::string& error)
{
    error.clear();
    // Reject device, UNC and alternate-stream spellings before any open.
    if (path.size() < 3 || !std::iswalpha(path[0]) || path[1] != L':' ||
        (path[2] != L'\\' && path[2] != L'/') || path.find(L':', 2) != std::wstring::npos)
    {
        error = "SnapshotSourceRequiresAbsoluteLocalImage";
        return {};
    }
    auto device = std::make_shared<BlockDevice>(std::move(path));
    device->stable_read_only_image_ = true;
    const auto handle = CreateFileW(device->path_.c_str(), GENERIC_READ,
        FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (handle == INVALID_HANDLE_VALUE)
    {
        error = "SnapshotStableImageOpenFailed:" + std::to_string(GetLastError());
        return {};
    }
    device->read_handle_.store(handle, std::memory_order_release);
    if (!QueryRegularFileIdentity(handle, device->stable_image_identity_))
    {
        error = "SnapshotSourceNotRegularLocalImage";
        return {};
    }
    device->regular_file_.store(true, std::memory_order_release);
    return device;
}

std::shared_ptr<BlockDevice> BlockDevice::AdoptExclusiveRepairImage(
    std::wstring path, HANDLE handle, std::string& error)
{
    auto device = std::make_shared<BlockDevice>(std::move(path), 0);
    device->read_handle_.store(handle);
    FILE_ID_INFO identity{}; FILE_STANDARD_INFO standard{};
    if (!QueryRegularFileIdentity(handle, identity) ||
        !GetFileInformationByHandleEx(handle, FileStandardInfo, &standard, sizeof(standard)) ||
        standard.DeletePending || standard.NumberOfLinks != 1 || standard.EndOfFile.QuadPart <= 0 ||
        standard.EndOfFile.QuadPart > 256ll * 1024 * 1024) {
        error = "Exclusive bounded ordinary image required"; return nullptr;
    }
    const bool exclusive_source = IsExclusiveRepairImageHandle(handle);
    HANDLE writer = INVALID_HANDLE_VALUE;
    if (!DuplicateHandle(GetCurrentProcess(), handle, GetCurrentProcess(), &writer,
        0, FALSE, DUPLICATE_SAME_ACCESS)) {
        error = "Cannot duplicate held repair image"; return nullptr;
    }
    device->write_handle_.store(writer);
    device->regular_file_.store(true); device->writable_.store(true);
    device->AdvanceWriteSourceGenerationLocked();
    device->exclusive_write_image_identity_ = identity;
    device->exclusive_write_image_size_bytes_ = static_cast<std::uint64_t>(standard.EndOfFile.QuadPart);
    device->exclusive_write_image_ = exclusive_source;
    return device;
}

#include "BlockDeviceSoftwareTransitionImage.inc"

bool BlockDevice::RevalidateStableReadOnlyImage() const
{
    FILE_ID_INFO identity{};
    return stable_read_only_image_ && !HasWriteHandle() &&
        QueryRegularFileIdentity(read_handle_.load(std::memory_order_acquire), identity) &&
        identity.VolumeSerialNumber == stable_image_identity_.VolumeSerialNumber &&
        std::memcmp(identity.FileId.Identifier, stable_image_identity_.FileId.Identifier,
            sizeof(identity.FileId.Identifier)) == 0;
}

std::shared_ptr<BlockDevice> BlockDevice::OpenExclusiveManagementImage(
    std::wstring path, std::uint64_t offset, std::string& error)
{
    error.clear();
    if (path.size()<3 || !std::iswalpha(path[0]) || path[1]!=L':' ||
        (path[2]!=L'\\' && path[2]!=L'/') || path.find(L':',2)!=std::wstring::npos) {
        error="VolumeManagementRequiresAbsoluteLocalImage"; return {};
    }
    auto device=std::make_shared<BlockDevice>(std::move(path),offset);
    const auto handle=CreateFileW(device->path_.c_str(),GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OVERLAPPED|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    if(handle==INVALID_HANDLE_VALUE){error="VolumeManagementExclusiveImageOpenFailed:"+std::to_string(GetLastError());return {};}
    device->read_handle_.store(handle,std::memory_order_release);
    FILE_ID_INFO identity{};
    FILE_STANDARD_INFO standard{};
    if(!QueryRegularFileIdentity(handle,identity) ||
        !GetFileInformationByHandleEx(handle,FileStandardInfo,&standard,sizeof(standard)) ||
        standard.EndOfFile.QuadPart < 0){error="VolumeManagementSourceNotRegularImage";return {};}
    HANDLE writer=INVALID_HANDLE_VALUE;
    if(!DuplicateHandle(GetCurrentProcess(),handle,GetCurrentProcess(),&writer,0,FALSE,DUPLICATE_SAME_ACCESS)) {
        error="VolumeManagementDuplicateLeaseFailed";return {};
    }
    device->write_handle_.store(writer,std::memory_order_release);
    device->regular_file_.store(true,std::memory_order_release);
    device->writable_.store(true,std::memory_order_release);
    device->AdvanceWriteSourceGenerationLocked();
    device->exclusive_write_image_identity_ = identity;
    device->exclusive_write_image_size_bytes_ = static_cast<std::uint64_t>(standard.EndOfFile.QuadPart);
    device->exclusive_write_image_ = true;
    return device;
}

namespace
{
// APFS GPT partition type {7C3457EF-0000-11AA-AA11-00306543ECAC}.
constexpr GUID kApfsGptPartitionType =
    {0x7C3457EF, 0x0000, 0x11AA, {0xAA, 0x11, 0x00, 0x30, 0x65, 0x43, 0xEC, 0xAC}};

std::string FormatGuidLower(const GUID& value)
{
    char text[64] = {};
    std::snprintf(text, sizeof(text),
        "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        value.Data1, value.Data2, value.Data3,
        value.Data4[0], value.Data4[1], value.Data4[2], value.Data4[3],
        value.Data4[4], value.Data4[5], value.Data4[6], value.Data4[7]);
    return std::string(text);
}

struct ExclusiveHandleGuard
{
    HANDLE value = INVALID_HANDLE_VALUE;
    ExclusiveHandleGuard() = default;
    ~ExclusiveHandleGuard()
    {
        if (value != INVALID_HANDLE_VALUE)
        {
            CloseHandle(value);
        }
    }
    ExclusiveHandleGuard(const ExclusiveHandleGuard&) = delete;
    ExclusiveHandleGuard& operator=(const ExclusiveHandleGuard&) = delete;
};
} // namespace

bool BlockDevice::AdmitExclusiveRawWriter(std::uint64_t limit_bytes, std::string& error)
{
    return AdmitExclusiveRawWriterImpl(limit_bytes, error, false);
}

bool BlockDevice::AdmitExclusiveRawWriterImpl(std::uint64_t limit_bytes, std::string& error,
    bool qualified_interface)
{
    std::lock_guard<std::mutex> probe_lock(raw_presence_probe_mutex_);
    error.clear();
    const auto fail = [&](const std::string& reason) {
        error = reason;
        return false;
    };
    if (limit_bytes == 0 || (limit_bytes % 4096ull) != 0 ||
        base_offset_bytes_ > std::numeric_limits<std::uint64_t>::max() - limit_bytes)
    {
        return fail("RawWriterLimitInvalid");
    }
    if ((base_offset_bytes_ % 512ull) != 0)
    {
        return fail("RawWriterBaseUnaligned");
    }
    if (!IsRawPhysicalDevicePath(path_) && !qualified_interface)
    {
        return fail("RawWriterPathNotPhysicalDrive");
    }
    if (qualified_interface && (path_.size() > 4096 || path_.find(L'\0') != std::wstring::npos ||
        path_.size() <= 12 || _wcsnicmp(path_.c_str(), L"\\\\?\\USBSTOR#", 12) != 0))
        return fail("RawWriterQualifiedInterfaceInvalid");
    if (write_handle_.load(std::memory_order_acquire) != INVALID_HANDLE_VALUE ||
        raw_writer_accepted_.load(std::memory_order_acquire))
    {
        return fail("RawWriterAlreadyAdmitted");
    }
    auto presence = std::make_unique<RawPresenceIdentity>();
    DWORD presence_error = ERROR_SUCCESS;
    if (!ResolveRawDiskInterface(path_, presence->selected, presence_error))
        return fail("RawWriterSelectedInterfaceUnavailable:" + std::to_string(presence_error));
    // Release our own shared lazy handles first: a share-deny-all open
    // conflicts even with handles this same process already holds.
    {
        std::lock_guard<std::mutex> lock(handle_mutex_);
        if (write_handle_.load(std::memory_order_acquire) != INVALID_HANDLE_VALUE ||
            raw_writer_accepted_.load(std::memory_order_acquire))
        {
            return fail("RawWriterAlreadyAdmitted");
        }
        InvalidateWriteSourceHandlesLocked();
        const auto previous_read =
            read_handle_.exchange(INVALID_HANDLE_VALUE, std::memory_order_acq_rel);
        if (previous_read != INVALID_HANDLE_VALUE)
        {
            CloseHandle(previous_read);
        }
        const auto previous_write =
            write_handle_.exchange(INVALID_HANDLE_VALUE, std::memory_order_acq_rel);
        if (previous_write != INVALID_HANDLE_VALUE)
        {
            CloseHandle(previous_write);
        }
    }
    // Deny-write sharing: any later open requesting write/delete access
    // fails, so no second writer (ours, a filesystem mounter, or a format
    // tool) can join mid-session. Pure readers (our own earlier handles are
    // already closed above; system inventory readers) stay admitted, which is
    // also what makes this open succeed on a live Windows disk where a
    // share-deny-all open is refused while system readers exist.
    ExclusiveHandleGuard exclusive;
    exclusive.value = CreateFileW(presence->selected.path.c_str(), GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, nullptr);
    if (exclusive.value == INVALID_HANDLE_VALUE)
    {
        return fail("RawWriterExclusiveOpenFailed:" + std::to_string(GetLastError()));
    }
    DWORD file_type = GetFileType(exclusive.value);
    if (file_type != FILE_TYPE_DISK)
    {
        return fail("RawWriterNotDiskDevice");
    }
    STORAGE_DEVICE_NUMBER source_number{};
    DWORD number_bytes = 0;
    const auto selected_number = TryParsePhysicalDriveNumber(path_);
    if (!DeviceIoControl(exclusive.value, IOCTL_STORAGE_GET_DEVICE_NUMBER, nullptr, 0,
            &source_number, sizeof(source_number), &number_bytes, nullptr) ||
        source_number.DeviceNumber == MAXDWORD ||
        !physical_instance::WholeDisk(source_number, number_bytes,
            selected_number.value_or(source_number.DeviceNumber)))
        return fail("RawWriterSelectedDeviceNumberMismatch");
    presence->disk_number = source_number.DeviceNumber;
    DWORD layout_bytes = 4096;
    std::vector<std::byte> layout_buffer(static_cast<std::size_t>(layout_bytes));
    DWORD returned = 0;
    bool layout_ok = false;
    for (int attempt = 0; attempt < 4; ++attempt)
    {
        if (DeviceIoControl(exclusive.value, IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
                nullptr, 0, layout_buffer.data(), layout_bytes, &returned, nullptr))
        {
            layout_ok = true;
            break;
        }
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || layout_bytes >= 65536)
        {
            break;
        }
        layout_bytes *= 2;
        layout_buffer.assign(static_cast<std::size_t>(layout_bytes), std::byte{0});
    }
    if (!layout_ok)
    {
        return fail("RawWriterLayoutUnreadable:" + std::to_string(GetLastError()));
    }
    constexpr auto layout_header_bytes = offsetof(DRIVE_LAYOUT_INFORMATION_EX, PartitionEntry);
    if (returned < layout_header_bytes || returned > layout_buffer.size())
    {
        return fail("RawWriterLayoutTruncated");
    }
    const auto* layout =
        reinterpret_cast<const DRIVE_LAYOUT_INFORMATION_EX*>(layout_buffer.data());
    if (layout->PartitionCount > (returned - layout_header_bytes) / sizeof(PARTITION_INFORMATION_EX))
    {
        return fail("RawWriterLayoutTruncated");
    }
    if (layout->PartitionStyle != PARTITION_STYLE_GPT)
    {
        return fail("RawWriterDiskNotGpt");
    }
    bool contained = false;
    for (DWORD index = 0; index < layout->PartitionCount; ++index)
    {
        const auto& entry = layout->PartitionEntry[index];
        if (entry.StartingOffset.QuadPart < 0 || entry.PartitionLength.QuadPart <= 0 ||
            entry.PartitionStyle != PARTITION_STYLE_GPT ||
            std::memcmp(&entry.Gpt.PartitionType, &kApfsGptPartitionType, sizeof(GUID)) != 0)
        {
            continue;
        }
        const auto start = static_cast<std::uint64_t>(entry.StartingOffset.QuadPart);
        const auto length = static_cast<std::uint64_t>(entry.PartitionLength.QuadPart);
        if (base_offset_bytes_ >= start && limit_bytes <= length &&
            base_offset_bytes_ - start <= length - limit_bytes)
        {
            contained = true;
            break;
        }
    }
    if (!contained)
    {
        return fail("RawWriterRangeNotInApfsPartition");
    }
    Geometry source_geometry{};
    const bool fixed_size = QueryGeometryLocked(exclusive.value, source_geometry) &&
        limit_bytes <= source_geometry.total_bytes;
    std::string identity = "gpt:" + FormatGuidLower(layout->Gpt.DiskId) +
        "|base:" + std::to_string(base_offset_bytes_) +
        "|limit:" + std::to_string(limit_bytes);
    if (selected_number)
    {
        std::wstring current;
        if (!physical_instance::Selected(L"\\\\.\\PhysicalDrive" + std::to_wstring(*selected_number), current) ||
            current != presence->selected.instance)
            return fail("RawWriterSelectedInstanceChanged");
    }
    if (!IsPresentDiskInterface(presence->selected, presence_error))
        return fail("RawWriterSelectedInterfaceChanged:" + std::to_string(presence_error));
    HANDLE writer = INVALID_HANDLE_VALUE;
    if (!DuplicateHandle(GetCurrentProcess(), exclusive.value, GetCurrentProcess(),
            &writer, 0, FALSE, DUPLICATE_SAME_ACCESS))
    {
        return fail("RawWriterDuplicateLeaseFailed:" + std::to_string(GetLastError()));
    }
    {
        std::lock_guard<std::mutex> lock(handle_mutex_);
        InvalidateWriteSourceHandlesLocked();
        const auto previous_read = read_handle_.exchange(exclusive.value, std::memory_order_acq_rel);
        if (previous_read != INVALID_HANDLE_VALUE)
        {
            CloseHandle(previous_read);
        }
        exclusive.value = INVALID_HANDLE_VALUE;
        const auto previous_write = write_handle_.exchange(writer, std::memory_order_acq_rel);
        if (previous_write != INVALID_HANDLE_VALUE)
        {
            CloseHandle(previous_write);
        }
        regular_file_.store(false, std::memory_order_release);
        writable_.store(true, std::memory_order_release);
        raw_write_limit_bytes_.store(limit_bytes, std::memory_order_release);
        raw_writer_identity_ = std::move(identity);
        raw_write_source_size_bytes_ = fixed_size ? source_geometry.total_bytes : 0;
        raw_presence_identity_ = std::move(presence);
        raw_presence_probe_result_.store(true, std::memory_order_relaxed);
        raw_presence_probe_error_.store(ERROR_SUCCESS, std::memory_order_relaxed);
        raw_presence_probe_tick_ms_.store(0, std::memory_order_relaxed);
        {
            std::lock_guard<std::mutex> source_lock(write_source_mutex_);
            write_source_handles_retired_ = false;
            raw_snapshot_lease_retired_ = false;
            raw_snapshot_descriptors_attempted_ = false;
            raw_snapshot_descriptors_complete_ = false;
            raw_snapshot_descriptors_ = {};
            raw_snapshot_descriptors_error_.clear();
        }
        raw_writer_accepted_.store(true, std::memory_order_release);
    }
    return true;
}

bool BlockDevice::QueryRegularImageIdentity(std::string& out) const
{
    out.clear();
    if (!IsRegularFile()) return false;
    const auto handle = EnsureReadHandle();
    FILE_ID_INFO id{}; FILE_STANDARD_INFO info{};
    if (handle == INVALID_HANDLE_VALUE ||
        !GetFileInformationByHandleEx(handle, FileIdInfo, &id, sizeof(id)) ||
        !GetFileInformationByHandleEx(handle, FileStandardInfo, &info, sizeof(info)) ||
        info.Directory || info.DeletePending || info.EndOfFile.QuadPart <= 0) return false;
    const char hex[] = "0123456789abcdef";
    const auto append = [&](std::uint64_t n) { for (int i=15; i>=0; --i) out.push_back(hex[(n>>(i*4))&15]); };
    append(id.VolumeSerialNumber);
    for (auto b : id.FileId.Identifier) { out.push_back(hex[b>>4]); out.push_back(hex[b&15]); }
    append(base_offset_bytes_); append(static_cast<std::uint64_t>(info.EndOfFile.QuadPart));
    return true;
}

bool BlockDevice::QueryStableReadOnlyImageIdentity(StableImageIdentity& out) const
{
    out = {};
    FILE_ID_INFO id{};
    FILE_STANDARD_INFO standard{};
    FILE_BASIC_INFO basic{};
    const auto handle = read_handle_.load(std::memory_order_acquire);
    if (!stable_read_only_image_ || HasWriteHandle() ||
        !QueryRegularFileIdentity(handle, id) ||
        id.VolumeSerialNumber != stable_image_identity_.VolumeSerialNumber ||
        std::memcmp(id.FileId.Identifier, stable_image_identity_.FileId.Identifier, 16) != 0 ||
        !GetFileInformationByHandleEx(handle, FileStandardInfo, &standard, sizeof(standard)) ||
        standard.EndOfFile.QuadPart < 0 || standard.DeletePending ||
        !GetFileInformationByHandleEx(handle, FileBasicInfo, &basic, sizeof(basic)))
        return false;
    out.volume_serial = id.VolumeSerialNumber;
    std::memcpy(out.file_id.data(), id.FileId.Identifier, out.file_id.size());
    out.size_bytes = static_cast<std::uint64_t>(standard.EndOfFile.QuadPart);
    out.creation_time = static_cast<std::uint64_t>(basic.CreationTime.QuadPart);
    out.write_time = static_cast<std::uint64_t>(basic.LastWriteTime.QuadPart);
    return true;
}

bool BlockDevice::QueryHeldImageIdentity(StableImageIdentity& out) const
{
    out = {};
    FILE_ID_INFO id{}; FILE_STANDARD_INFO standard{}; FILE_BASIC_INFO basic{};
    const auto handle = read_handle_.load(std::memory_order_acquire);
    if (!QueryRegularFileIdentity(handle, id) ||
        !GetFileInformationByHandleEx(handle, FileStandardInfo, &standard, sizeof(standard)) ||
        standard.EndOfFile.QuadPart < 0 || standard.DeletePending ||
        !GetFileInformationByHandleEx(handle, FileBasicInfo, &basic, sizeof(basic))) return false;
    out.volume_serial = id.VolumeSerialNumber;
    std::memcpy(out.file_id.data(), id.FileId.Identifier, out.file_id.size());
    out.size_bytes = static_cast<std::uint64_t>(standard.EndOfFile.QuadPart);
    out.creation_time = static_cast<std::uint64_t>(basic.CreationTime.QuadPart);
    out.write_time = static_cast<std::uint64_t>(basic.LastWriteTime.QuadPart);
    return true;
}

std::optional<BlockDevice::WriteSourceObservation> BlockDevice::CaptureExclusiveWriteSourceObservation() const
{
    std::lock_guard<std::mutex> handle_lock(handle_mutex_);
    std::lock_guard<std::mutex> source_lock(write_source_mutex_);
    const auto reader = read_handle_.load(std::memory_order_acquire);
    const auto writer = write_handle_.load(std::memory_order_acquire);
    DWORD flags = 0;
    if (stable_read_only_image_ || write_source_generation_exhausted_ || write_source_handles_retired_ ||
        write_source_admissions_ != 0 || !writable_.load(std::memory_order_acquire) ||
        (!exclusive_write_image_ && !raw_writer_accepted_.load(std::memory_order_acquire)))
    {
        return std::nullopt;
    }
    const auto retire = [&]() -> std::optional<WriteSourceObservation> {
        AdvanceWriteSourceGenerationLocked();
        write_source_handles_retired_ = true;
        RetireRawSnapshotLeaseLocked();
        return std::nullopt;
    };
    if (reader == INVALID_HANDLE_VALUE || writer == INVALID_HANDLE_VALUE ||
        !GetHandleInformation(reader, &flags) || !GetHandleInformation(writer, &flags))
    {
        return retire();
    }

    WriteSourceObservation observation;
    observation.device_ = this;
    observation.lifetime_ = write_source_lifetime_;
    observation.read_handle_ = reader;
    observation.write_handle_ = writer;
    observation.generation_ = write_source_generation_;
    observation.base_offset_bytes_ = base_offset_bytes_;
    if (raw_writer_accepted_.load(std::memory_order_acquire))
    {
        Geometry source_geometry{};
        observation.limit_bytes_ = raw_write_limit_bytes_.load(std::memory_order_acquire);
        if (observation.limit_bytes_ == 0 || raw_writer_identity_.empty() ||
            raw_writer_identity_.size() > observation.raw_identity_.size() ||
            regular_file_.load(std::memory_order_acquire) ||
            !raw_presence_probe_result_.load(std::memory_order_acquire) ||
            GetFileType(reader) != FILE_TYPE_DISK || GetFileType(writer) != FILE_TYPE_DISK ||
            raw_write_source_size_bytes_ == 0 ||
            !QueryGeometryLocked(reader, source_geometry) ||
            source_geometry.total_bytes != raw_write_source_size_bytes_ ||
            observation.limit_bytes_ > source_geometry.total_bytes)
        {
            return retire();
        }
        observation.raw_identity_size_ = raw_writer_identity_.size();
        std::copy(raw_writer_identity_.begin(), raw_writer_identity_.end(), observation.raw_identity_.begin());
    }
    else if (exclusive_write_image_ && regular_file_.load(std::memory_order_acquire))
    {
        FILE_ID_INFO reader_id{}, writer_id{};
        FILE_STANDARD_INFO standard{};
        const auto held_handles = SoftwareTransitionHeldImageAuthority::ExpectedHandleCount(*this, reader, writer);
        if (!held_handles || !QueryHeldReadWriteHandle(reader, *held_handles) || !QueryHeldReadWriteHandle(writer, *held_handles) ||
            !GetFileInformationByHandleEx(reader, FileIdInfo, &reader_id, sizeof(reader_id)) ||
            !GetFileInformationByHandleEx(writer, FileIdInfo, &writer_id, sizeof(writer_id)) ||
            reader_id.VolumeSerialNumber != exclusive_write_image_identity_.VolumeSerialNumber ||
            writer_id.VolumeSerialNumber != reader_id.VolumeSerialNumber ||
            std::memcmp(reader_id.FileId.Identifier, exclusive_write_image_identity_.FileId.Identifier, 16) != 0 ||
            std::memcmp(writer_id.FileId.Identifier, reader_id.FileId.Identifier, 16) != 0 ||
            !GetFileInformationByHandleEx(reader, FileStandardInfo, &standard, sizeof(standard)) ||
            standard.Directory || standard.DeletePending || standard.NumberOfLinks == 0 ||
            standard.EndOfFile.QuadPart <= 0 ||
            static_cast<std::uint64_t>(standard.EndOfFile.QuadPart) != exclusive_write_image_size_bytes_ ||
            base_offset_bytes_ >= static_cast<std::uint64_t>(standard.EndOfFile.QuadPart))
        {
            return retire();
        }
        observation.image_identity_.volume_serial = reader_id.VolumeSerialNumber;
        std::memcpy(observation.image_identity_.file_id.data(), reader_id.FileId.Identifier, 16);
        observation.image_identity_.size_bytes = static_cast<std::uint64_t>(standard.EndOfFile.QuadPart);
        observation.limit_bytes_ = observation.image_identity_.size_bytes - base_offset_bytes_;
    }
    else
    {
        return std::nullopt;
    }
    return observation;
}

bool BlockDevice::IsExclusiveWriteSourceObservationCurrent(const WriteSourceObservation& observation) const
{
    if (observation.device_ != this || observation.lifetime_ != write_source_lifetime_)
    {
        return false;
    }
    const auto current = CaptureExclusiveWriteSourceObservation();
    return current && *current == observation;
}

bool BlockDevice::IsHeldRawSnapshotLeaseCurrentLocked(const RawSnapshotLease& lease) const
{
    const auto reader = read_handle_.load(std::memory_order_acquire);
    const auto writer = write_handle_.load(std::memory_order_acquire);
    const auto limit = raw_write_limit_bytes_.load(std::memory_order_acquire);
    return lease.device_ == this && lease.lifetime_ == write_source_lifetime_ &&
        !raw_snapshot_epoch_exhausted_ && !raw_snapshot_lease_retired_ && !write_source_handles_retired_ &&
        lease.retirement_epoch_ == raw_snapshot_retirement_epoch_ &&
        reader != nullptr && reader != INVALID_HANDLE_VALUE &&
        writer != nullptr && writer != INVALID_HANDLE_VALUE &&
        lease.read_handle_ == reader && lease.write_handle_ == writer &&
        lease.base_offset_bytes_ == base_offset_bytes_ && lease.limit_bytes_ == limit &&
        raw_writer_accepted_.load(std::memory_order_acquire) && writable_.load(std::memory_order_acquire) &&
        !regular_file_.load(std::memory_order_acquire) && !stable_read_only_image_ &&
        raw_presence_probe_result_.load(std::memory_order_acquire) && !raw_writer_identity_.empty() &&
        limit != 0 && limit <= raw_write_source_size_bytes_;
}

std::optional<BlockDevice::RawSnapshotLease> BlockDevice::CaptureHeldRawSnapshotLease() const
{
    std::lock_guard<std::mutex> source_lock(write_source_mutex_);
    RawSnapshotLease lease;
    lease.device_ = this;
    lease.lifetime_ = write_source_lifetime_;
    lease.read_handle_ = read_handle_.load(std::memory_order_acquire);
    lease.write_handle_ = write_handle_.load(std::memory_order_acquire);
    lease.retirement_epoch_ = raw_snapshot_retirement_epoch_;
    lease.base_offset_bytes_ = base_offset_bytes_;
    lease.limit_bytes_ = raw_write_limit_bytes_.load(std::memory_order_acquire);
    if (!IsHeldRawSnapshotLeaseCurrentLocked(lease)) return std::nullopt;
    return lease;
}

bool BlockDevice::IsHeldRawSnapshotLeaseCurrent(const RawSnapshotLease& lease) const
{
    std::lock_guard<std::mutex> source_lock(write_source_mutex_);
    return IsHeldRawSnapshotLeaseCurrentLocked(lease);
}

bool BlockDevice::RawSnapshotIoctl(
    HANDLE handle, DWORD code, void* input, DWORD input_bytes,
    void* output, DWORD output_bytes, DWORD& returned, DWORD& error) const
{
    returned = 0;
    error = ERROR_SUCCESS;
    ExclusiveHandleGuard event;
    event.value = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!event.value)
    {
        error = GetLastError();
        event.value = INVALID_HANDLE_VALUE;
        return false;
    }
    OVERLAPPED overlapped{};
    overlapped.hEvent = event.value;
    if (DeviceIoControl(handle, code, input, input_bytes, output, output_bytes, &returned, &overlapped))
        return true;
    error = GetLastError();
    if (error != ERROR_IO_PENDING) return false;
    return WaitForOverlappedCompletion(handle, overlapped, returned, error);
}

bool BlockDevice::QueryRawSnapshotProperty(
    HANDLE handle, STORAGE_PROPERTY_ID property, std::vector<std::byte>& out, DWORD& error) const
{
    out.clear();
    STORAGE_PROPERTY_QUERY query{};
    query.PropertyId = property;
    query.QueryType = PropertyStandardQuery;
    STORAGE_DESCRIPTOR_HEADER header{};
    DWORD returned = 0;
    if (!RawSnapshotIoctl(handle, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query),
            &header, sizeof(header), returned, error)) return false;
    if (returned != sizeof(header) || header.Size < sizeof(header) ||
        header.Size > kRawSnapshotDescriptorMaxBytes || header.Version < sizeof(header) || header.Version > header.Size)
    {
        error = ERROR_INVALID_DATA;
        return false;
    }
    std::vector<std::byte> bytes(header.Size);
    if (!RawSnapshotIoctl(handle, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query),
            bytes.data(), static_cast<DWORD>(bytes.size()), returned, error)) return false;
    STORAGE_DESCRIPTOR_HEADER actual{};
    if (returned > bytes.size() || !raw_snapshot_detail::Load(std::span<const std::byte>(bytes).first(returned), 0, actual) ||
        actual.Size != header.Size || actual.Version != header.Version || returned < actual.Size)
    {
        error = ERROR_INVALID_DATA;
        return false;
    }
    bytes.resize(actual.Size);
    out = std::move(bytes);
    return true;
}

bool BlockDevice::QueryHeldRawSnapshotDescriptors(
    const RawSnapshotLease& lease, RawSnapshotDescriptors& out, std::string& error) const
{
    out = {};
    error.clear();
    // Pin original handles through pending I/O, but leave the leaf source lock
    // available for cached continuity checks, writes and known retirement.
    std::lock_guard<std::mutex> handle_lock(handle_mutex_);
    {
        std::lock_guard<std::mutex> source_lock(write_source_mutex_);
        if (!IsHeldRawSnapshotLeaseCurrentLocked(lease))
            return raw_snapshot_detail::Refuse(error, "RawSnapshotLeaseNotCurrent");
    }
    if (!raw_snapshot_descriptors_attempted_)
    {
        // A query exception also consumes this attempt; a retry never reopens or
        // manufactures replacement evidence for the original held lifetime.
        const auto query = [&]() -> bool {
            raw_snapshot_descriptors_error_ = "RawSnapshotDescriptorQueryIncomplete";
            RawSnapshotDescriptors descriptors;
            const auto reader = lease.read_handle_;
            DWORD io_error = ERROR_SUCCESS, returned = 0;
            const auto io_failure = [&](const char* operation) {
                raw_snapshot_descriptors_error_ = std::string(operation) + ":" + std::to_string(io_error);
                if (IsDeviceUnavailableError(io_error))
                {
                    std::lock_guard<std::mutex> source_lock(write_source_mutex_);
                    RetireRawSnapshotLeaseLocked();
                }
                return false;
            };
            std::vector<std::byte> device_bytes, id_bytes, alignment_bytes, geometry_bytes;
            if (!QueryRawSnapshotProperty(reader, StorageDeviceProperty, device_bytes, io_error))
                return io_failure("RawHardwareDescriptorUnavailable");
            if (!ParseRawDeviceDescriptor(device_bytes, descriptors.device, raw_snapshot_descriptors_error_)) return false;
            if (QueryRawSnapshotProperty(reader, StorageDeviceIdProperty, id_bytes, io_error))
            {
                if (!ParseRawDeviceIdDescriptor(id_bytes, descriptors.identifiers, raw_snapshot_descriptors_error_)) return false;
                descriptors.device_id_available = true;
            }
            else if (io_error != ERROR_NOT_SUPPORTED && io_error != ERROR_INVALID_FUNCTION && io_error != ERROR_INVALID_PARAMETER)
                return io_failure("RawHardwareIdentifierUnavailable");
            if (!QueryRawSnapshotProperty(reader, StorageAccessAlignmentProperty, alignment_bytes, io_error))
            {
                if (io_error != ERROR_NOT_SUPPORTED && io_error != ERROR_INVALID_FUNCTION && io_error != ERROR_INVALID_PARAMETER)
                    return io_failure("RawSnapshotAlignmentUnavailable");
                DISK_GEOMETRY geometry{};
                if (!RawSnapshotIoctl(reader,IOCTL_DISK_GET_DRIVE_GEOMETRY,nullptr,0,
                        &geometry,sizeof(geometry),returned,io_error)) return io_failure("RawSnapshotLogicalGeometryUnavailable");
                if (returned!=sizeof(geometry))
                    return raw_snapshot_detail::Refuse(raw_snapshot_descriptors_error_,"RawSnapshotLogicalGeometryTruncated");
                const auto bytes=std::as_bytes(std::span(&geometry,1));
                geometry_bytes.assign(bytes.begin(),bytes.end());
            }
            GET_LENGTH_INFORMATION length{};
            if (!RawSnapshotIoctl(reader, IOCTL_DISK_GET_LENGTH_INFO, nullptr, 0,
                    &length, sizeof(length), returned, io_error)) return io_failure("RawSnapshotDiskLengthUnavailable");
            if (returned != sizeof(length))
                return raw_snapshot_detail::Refuse(raw_snapshot_descriptors_error_, "RawSnapshotDiskLengthTruncated");
            std::vector<std::byte> layout_bytes(4096);
            for (;;)
            {
                if (RawSnapshotIoctl(reader, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, nullptr, 0,
                        layout_bytes.data(), static_cast<DWORD>(layout_bytes.size()), returned, io_error)) break;
                if ((io_error != ERROR_INSUFFICIENT_BUFFER && io_error != ERROR_MORE_DATA) ||
                    layout_bytes.size() >= kRawSnapshotDescriptorMaxBytes) return io_failure("RawSnapshotLayoutUnavailable");
                layout_bytes.resize(layout_bytes.size() * 2);
            }
            if (returned > layout_bytes.size())
                return raw_snapshot_detail::Refuse(raw_snapshot_descriptors_error_, "RawSnapshotLayoutTruncated");
            layout_bytes.resize(returned);
            const auto length_span = std::as_bytes(std::span(&length, 1));
            if (!ParseRawSnapshotMediaBinding(layout_bytes, length_span, alignment_bytes,
                    lease.base_offset_bytes_, lease.limit_bytes_, descriptors.media, raw_snapshot_descriptors_error_,geometry_bytes)) return false;
            DRIVE_LAYOUT_INFORMATION_EX layout{};
            std::memcpy(&layout, layout_bytes.data(), offsetof(DRIVE_LAYOUT_INFORMATION_EX, PartitionEntry));
            const auto expected_identity = "gpt:" + FormatGuidLower(layout.Gpt.DiskId) +
                "|base:" + std::to_string(lease.base_offset_bytes_) + "|limit:" + std::to_string(lease.limit_bytes_);
            if (expected_identity != raw_writer_identity_ ||
                descriptors.media.disk_size_bytes - base_offset_bytes_ != raw_write_source_size_bytes_)
            {
                std::lock_guard<std::mutex> source_lock(write_source_mutex_);
                RetireRawSnapshotLeaseLocked();
                return raw_snapshot_detail::Refuse(raw_snapshot_descriptors_error_, "RawSnapshotAdmittedMediaChanged");
            }
            {
                std::lock_guard<std::mutex> source_lock(write_source_mutex_);
                if (!IsHeldRawSnapshotLeaseCurrentLocked(lease))
                    return raw_snapshot_detail::Refuse(raw_snapshot_descriptors_error_, "RawSnapshotLeaseNotCurrent");
            }
            raw_snapshot_descriptors_ = std::move(descriptors);
            raw_snapshot_descriptors_error_.clear();
            return true;
        };
        raw_snapshot_detail::AttemptDescriptorCacheOnce(raw_snapshot_descriptors_attempted_,
            raw_snapshot_descriptors_complete_,query);
    }
    {
        std::lock_guard<std::mutex> source_lock(write_source_mutex_);
        if (!IsHeldRawSnapshotLeaseCurrentLocked(lease))
            return raw_snapshot_detail::Refuse(error, "RawSnapshotLeaseNotCurrent");
    }
    if (!raw_snapshot_descriptors_complete_ || !raw_snapshot_descriptors_error_.empty())
    {
        error = raw_snapshot_descriptors_error_.empty() ? "RawSnapshotDescriptorQueryIncomplete" : raw_snapshot_descriptors_error_;
        return false;
    }
    out = raw_snapshot_descriptors_;
    return true;
}

bool BlockDevice::QueryHeldRawSnapshotBinding(
    const RawSnapshotLease& lease, const RawHardwareQualification& qualification,
    RawSnapshotBinding& out, std::string& error) const
{
    out = {};
    RawSnapshotDescriptors descriptors;
    if (!QueryHeldRawSnapshotDescriptors(lease, descriptors, error)) return false;
    RawSnapshotBinding binding;
    if (!QualifyRawSnapshotBinding(descriptors, qualification, binding, error)) return false;
    if (!IsHeldRawSnapshotLeaseCurrent(lease))
        return raw_snapshot_detail::Refuse(error, "RawSnapshotLeaseNotCurrent");
    out = std::move(binding);
    return true;
}

HANDLE BlockDevice::EnsureReadHandle() const
{
    auto handle = read_handle_.load(std::memory_order_acquire);
    if (handle != INVALID_HANDLE_VALUE)
    {
        return handle;
    }

    std::lock_guard<std::mutex> lock(handle_mutex_);
    handle = read_handle_.load(std::memory_order_relaxed);
    if (handle != INVALID_HANDLE_VALUE)
    {
        return handle;
    }

    if (raw_writer_accepted_.load(std::memory_order_acquire) ||
        stable_read_only_image_ || exclusive_write_image_)
    {
        last_io_error_.store(ERROR_INVALID_HANDLE, std::memory_order_relaxed);
        return INVALID_HANDLE_VALUE;
    }
    handle = CreateFileW(
        path_.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
        nullptr);
    FILE_ID_INFO identity{};
    InvalidateWriteSourceHandlesLocked();
    regular_file_.store(QueryRegularFileIdentity(handle, identity), std::memory_order_release);
    read_handle_.store(handle, std::memory_order_release);
    return handle;
}

HANDLE BlockDevice::EnsureWriteHandle() const
{
    if (stable_read_only_image_)
    {
        last_io_error_.store(ERROR_WRITE_PROTECT, std::memory_order_relaxed);
        return INVALID_HANDLE_VALUE;
    }
    auto handle = write_handle_.load(std::memory_order_acquire);
    if (handle != INVALID_HANDLE_VALUE)
    {
        return handle;
    }

    const auto read_handle = EnsureReadHandle();
    FILE_ID_INFO read_identity{};
    if (!QueryRegularFileIdentity(read_handle, read_identity))
    {
        // Physical/unknown sources remain read-only until independent native
        // writer acceptance. No path spelling or test override bypasses this.
        last_io_error_.store(ERROR_NOT_SUPPORTED, std::memory_order_relaxed);
        return INVALID_HANDLE_VALUE;
    }

    std::lock_guard<std::mutex> lock(handle_mutex_);
    handle = write_handle_.load(std::memory_order_relaxed);
    if (handle != INVALID_HANDLE_VALUE)
    {
        return handle;
    }

    handle = ReOpenFile(
        read_handle,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_FLAG_OVERLAPPED);
    if (handle == INVALID_HANDLE_VALUE)
    {
        last_io_error_.store(GetLastError(), std::memory_order_relaxed);
        return INVALID_HANDLE_VALUE;
    }
    FILE_ID_INFO write_identity{};
    if (!QueryRegularFileIdentity(handle, write_identity) ||
        read_identity.VolumeSerialNumber != write_identity.VolumeSerialNumber ||
        std::memcmp(read_identity.FileId.Identifier, write_identity.FileId.Identifier,
            sizeof(read_identity.FileId.Identifier)) != 0)
    {
        CloseHandle(handle);
        last_io_error_.store(ERROR_NOT_SUPPORTED, std::memory_order_relaxed);
        return INVALID_HANDLE_VALUE;
    }
    InvalidateWriteSourceHandlesLocked();
    write_handle_.store(handle, std::memory_order_release);
    writable_.store(handle != INVALID_HANDLE_VALUE, std::memory_order_release);
    return handle;
}

void BlockDevice::CloseAsyncEventPoolLocked()
{
    for (HANDLE event : async_event_pool_)
    {
        if (event != INVALID_HANDLE_VALUE)
        {
            CloseHandle(event);
        }
    }
    async_event_pool_.clear();
}

void BlockDevice::CloseHandlesLocked() const
{
    InvalidateWriteSourceHandlesLocked();
    const auto read_handle = read_handle_.exchange(INVALID_HANDLE_VALUE, std::memory_order_acq_rel);
    if (read_handle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(read_handle);
    }
    const auto write_handle = write_handle_.exchange(INVALID_HANDLE_VALUE, std::memory_order_acq_rel);
    if (write_handle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(write_handle);
    }
    writable_.store(false, std::memory_order_release);
    regular_file_.store(false, std::memory_order_release);
}

bool BlockDevice::QueryGeometryLocked(HANDLE handle, Geometry& geometry) const
{
    geometry = Geometry{};

    LARGE_INTEGER file_size{};
    if (GetFileSizeEx(handle, &file_size))
    {
        geometry.total_bytes = static_cast<std::uint64_t>(file_size.QuadPart);
    }

    DWORD bytes_returned = 0;
    DISK_GEOMETRY_EX disk_geometry{};
    if (DeviceIoControl(
        handle,
        IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
        nullptr,
        0,
        &disk_geometry,
        sizeof(disk_geometry),
        &bytes_returned,
        nullptr))
    {
        geometry.total_bytes = static_cast<std::uint64_t>(disk_geometry.DiskSize.QuadPart);
        geometry.logical_block_size = std::max<std::uint32_t>(512u, disk_geometry.Geometry.BytesPerSector);
        geometry.physical_block_size = geometry.logical_block_size;
        if (geometry.total_bytes > base_offset_bytes_)
        {
            geometry.total_bytes -= base_offset_bytes_;
        }
        else
        {
            geometry.total_bytes = 0;
        }
        return geometry.total_bytes > 0;
    }

    GET_LENGTH_INFORMATION length_info{};
    if (DeviceIoControl(
        handle,
        IOCTL_DISK_GET_LENGTH_INFO,
        nullptr,
        0,
        &length_info,
        sizeof(length_info),
        &bytes_returned,
        nullptr))
    {
        geometry.total_bytes = static_cast<std::uint64_t>(length_info.Length.QuadPart);
        if (geometry.total_bytes > base_offset_bytes_)
        {
            geometry.total_bytes -= base_offset_bytes_;
        }
        else
        {
            geometry.total_bytes = 0;
        }
        return geometry.total_bytes > 0;
    }

    if (geometry.total_bytes > base_offset_bytes_)
    {
        geometry.total_bytes -= base_offset_bytes_;
    }
    else
    {
        geometry.total_bytes = 0;
    }

    return geometry.total_bytes > 0;
}

std::uint32_t BlockDevice::LogicalBlockSize() const
{
    auto cached_block_size = logical_block_size_cache_.load(std::memory_order_acquire);
    if (cached_block_size != 0)
    {
        return (std::max)(std::uint32_t{512}, cached_block_size);
    }

    std::lock_guard<std::mutex> lock(geometry_mutex_);
    cached_block_size = logical_block_size_cache_.load(std::memory_order_relaxed);
    if (cached_block_size != 0)
    {
        return (std::max)(std::uint32_t{512}, cached_block_size);
    }

    if (!geometry_cached_)
    {
        Geometry geometry{};
        HANDLE handle = EnsureReadHandle();
        if (handle != INVALID_HANDLE_VALUE && QueryGeometryLocked(handle, geometry))
        {
            geometry_cache_ = geometry;
            geometry_cached_ = true;
        }
    }

    const auto block_size = (std::max)(std::uint32_t{512}, geometry_cache_.logical_block_size);
    if (geometry_cached_)
    {
        logical_block_size_cache_.store(block_size, std::memory_order_release);
    }
    return block_size;
}

bool BlockDevice::ReadAt(
    HANDLE handle,
    std::uint64_t offset_bytes,
    void* buffer,
    DWORD bytes_to_read,
    DWORD& bytes_read) const
{
    ScopedPerfTimer perf_scope(raw_read_perf_, bytes_to_read);
    bytes_read = 0;
    const auto completion_event = CurrentBlockIoEvent().Ensure();
    if (completion_event == nullptr || !ResetEvent(completion_event))
    {
        const auto error = GetLastError();
        last_io_error_.store(error == ERROR_SUCCESS ? ERROR_NOT_ENOUGH_MEMORY : error, std::memory_order_relaxed);
        return false;
    }
    OVERLAPPED overlapped{};
    overlapped.Offset = static_cast<DWORD>(offset_bytes & 0xffffffffull);
    overlapped.OffsetHigh = static_cast<DWORD>(offset_bytes >> 32);
    overlapped.hEvent = completion_event;
    if (ReadFile(handle, buffer, bytes_to_read, &bytes_read, &overlapped))
    {
        return true;
    }

    const auto error = GetLastError();
    if (error != ERROR_IO_PENDING)
    {
        last_io_error_.store(error, std::memory_order_relaxed);
        return false;
    }

    DWORD completion_error = ERROR_SUCCESS;
    const auto completed = WaitForOverlappedCompletion(
        handle,
        overlapped,
        bytes_read,
        completion_error);
    if (!completed)
    {
        last_io_error_.store(
            completion_error == ERROR_SUCCESS ? ERROR_READ_FAULT : completion_error,
            std::memory_order_relaxed);
    }
    return completed;
}

bool BlockDevice::WriteAt(
    HANDLE handle,
    std::uint64_t offset_bytes,
    const void* buffer,
    DWORD bytes_to_write,
    DWORD& bytes_written) const
{
    bytes_written = 0;
    if (!RawWriteSpanAllowed(offset_bytes, bytes_to_write))
    {
        last_io_error_.store(ERROR_ACCESS_DENIED, std::memory_order_relaxed);
        return false;
    }
    const auto completion_event = CurrentBlockIoEvent().Ensure();
    if (completion_event == nullptr || !ResetEvent(completion_event))
    {
        const auto error = GetLastError();
        last_io_error_.store(error == ERROR_SUCCESS ? ERROR_NOT_ENOUGH_MEMORY : error, std::memory_order_relaxed);
        return false;
    }
    OVERLAPPED overlapped{};
    overlapped.Offset = static_cast<DWORD>(offset_bytes & 0xffffffffull);
    overlapped.OffsetHigh = static_cast<DWORD>(offset_bytes >> 32);
    overlapped.hEvent = completion_event;
    if (WriteFile(handle, buffer, bytes_to_write, &bytes_written, &overlapped))
    {
        if (bytes_written == bytes_to_write)
        {
            return true;
        }
        last_io_error_.store(ERROR_WRITE_FAULT, std::memory_order_relaxed);
        return false;
    }

    const auto error = GetLastError();
    if (error != ERROR_IO_PENDING)
    {
        last_io_error_.store(error, std::memory_order_relaxed);
        return false;
    }

    DWORD completion_error = ERROR_SUCCESS;
    const auto completed = WaitForOverlappedCompletion(
        handle,
        overlapped,
        bytes_written,
        completion_error);
    if (!completed)
    {
        last_io_error_.store(
            completion_error == ERROR_SUCCESS ? ERROR_WRITE_FAULT : completion_error,
            std::memory_order_relaxed);
    }
    else if (bytes_written != bytes_to_write)
    {
        last_io_error_.store(ERROR_WRITE_FAULT, std::memory_order_relaxed);
        return false;
    }
    return completed;
}

bool BlockDevice::WaitForOverlappedCompletion(
    HANDLE handle,
    OVERLAPPED& overlapped,
    DWORD& transferred,
    DWORD& completion_error) const
{
    transferred = 0;
    completion_error = ERROR_SUCCESS;

    if (GetOverlappedResultEx(
            handle,
            &overlapped,
            &transferred,
            kOverlappedIoWaitTimeoutMs,
            FALSE))
    {
        return true;
    }

    const auto wait_error = GetLastError();
    if (wait_error != WAIT_TIMEOUT && wait_error != ERROR_IO_INCOMPLETE)
    {
        completion_error = wait_error == ERROR_SUCCESS ? ERROR_OPERATION_ABORTED : wait_error;
        return false;
    }

    async_wait_timeout_count_.fetch_add(1, std::memory_order_relaxed);
    (void)CancelIoEx(handle, &overlapped);
    async_cancel_count_.fetch_add(1, std::memory_order_relaxed);

    if (GetOverlappedResultEx(
            handle,
            &overlapped,
            &transferred,
            kOverlappedIoCancelWaitTimeoutMs,
            FALSE))
    {
        return true;
    }

    const auto cancel_wait_error = GetLastError();
    if (cancel_wait_error == WAIT_TIMEOUT || cancel_wait_error == ERROR_IO_INCOMPLETE)
    {
        async_cancel_wait_timeout_count_.fetch_add(1, std::memory_order_relaxed);
        // Never return while the caller-owned buffer can still be referenced
        // by the kernel. Cancellation is requested above; this final wait is
        // the safety boundary for the buffer lifetime, not a normal path. A
        // second deadline avoids leaving the host stuck forever; if the kernel
        // still owns the buffer, fail closed at the process boundary instead
        // of returning into a potentially invalid caller buffer.
        if (GetOverlappedResultEx(
                handle,
                &overlapped,
                &transferred,
                kOverlappedIoFinalWaitTimeoutMs,
                FALSE))
        {
            completion_error = ERROR_OPERATION_ABORTED;
        }
        else
        {
            const auto final_error = GetLastError();
            if (final_error == WAIT_TIMEOUT || final_error == ERROR_IO_INCOMPLETE)
            {
                FailClosedForUncancelableIo();
            }
            completion_error = final_error == ERROR_SUCCESS
                ? ERROR_OPERATION_ABORTED
                : final_error;
        }
        return false;
    }

    completion_error = cancel_wait_error == ERROR_SUCCESS
        ? ERROR_OPERATION_ABORTED
        : cancel_wait_error;
    return false;
}
} // namespace apfsaccess::rw
