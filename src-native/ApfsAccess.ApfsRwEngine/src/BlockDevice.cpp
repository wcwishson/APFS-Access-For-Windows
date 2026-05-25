#include "BlockDevice.h"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cwchar>
#include <limits>
#include <memory>
#include <optional>
#include <sstream>
#include <string_view>
#include <utility>

#include <winioctl.h>

namespace apfsaccess::rw
{
namespace
{
bool IsFaultSwitchEnabled(const wchar_t* variable_name)
{
    if (variable_name == nullptr || *variable_name == L'\0')
    {
        return false;
    }

    wchar_t* raw_value = nullptr;
    std::size_t raw_length = 0;
    if (_wdupenv_s(&raw_value, &raw_length, variable_name) != 0 || raw_value == nullptr)
    {
        return false;
    }
    std::unique_ptr<wchar_t, decltype(&std::free)> guard(raw_value, &std::free);
    const auto* value = raw_value;

    while (*value == L' ' || *value == L'\t')
    {
        ++value;
    }

    return _wcsicmp(value, L"1") == 0 ||
           _wcsicmp(value, L"true") == 0 ||
           _wcsicmp(value, L"yes") == 0;
}

std::optional<std::wstring> ReadFaultMode(const wchar_t* variable_name)
{
    if (variable_name == nullptr || *variable_name == L'\0')
    {
        return std::nullopt;
    }

    wchar_t* raw_value = nullptr;
    std::size_t raw_length = 0;
    if (_wdupenv_s(&raw_value, &raw_length, variable_name) != 0 || raw_value == nullptr)
    {
        return std::nullopt;
    }
    std::unique_ptr<wchar_t, decltype(&std::free)> guard(raw_value, &std::free);
    const auto* value = raw_value;

    while (*value == L' ' || *value == L'\t')
    {
        ++value;
    }
    if (*value == L'\0' ||
        _wcsicmp(value, L"0") == 0 ||
        _wcsicmp(value, L"false") == 0 ||
        _wcsicmp(value, L"no") == 0)
    {
        return std::nullopt;
    }

    return std::wstring(value);
}

bool IsFaultMode(std::wstring_view actual, const wchar_t* expected)
{
    return _wcsicmp(std::wstring(actual).c_str(), expected) == 0;
}

bool IsPerfCountersEnabled()
{
    static const bool enabled = []()
    {
        wchar_t* raw_value = nullptr;
        std::size_t raw_length = 0;
        if (_wdupenv_s(&raw_value, &raw_length, L"APFSACCESS_PERF_COUNTERS") != 0 || raw_value == nullptr)
        {
            return false;
        }

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
    }();
    return enabled;
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
} // namespace

BlockDevice::BlockDevice(std::wstring path, std::uint64_t base_offset_bytes)
    : path_(std::move(path))
    , base_offset_bytes_(base_offset_bytes)
{
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

void BlockDevice::PerfCounter::Observe(std::uint64_t elapsed_us, std::uint64_t byte_count) noexcept
{
    count.fetch_add(1, std::memory_order_relaxed);
    bytes.fetch_add(byte_count, std::memory_order_relaxed);
    total_us.fetch_add(elapsed_us, std::memory_order_relaxed);
    last_us.store(elapsed_us, std::memory_order_relaxed);

    auto current_max = max_us.load(std::memory_order_relaxed);
    while (elapsed_us > current_max &&
           !max_us.compare_exchange_weak(current_max, elapsed_us, std::memory_order_relaxed))
    {
    }
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
        buffer << "\"" << name << "\":{\"count\":" << count
               << ",\"bytes\":" << bytes
               << ",\"totalUs\":" << total_us
               << ",\"maxUs\":" << max_us
               << ",\"lastUs\":" << last_us
               << "}";
    };

    std::ostringstream buffer;
    buffer << "{";
    append_counter(buffer, "read", read_perf_);
    buffer << ",";
    append_counter(buffer, "write", write_perf_);
    buffer << ",";
    append_counter(buffer, "unalignedWrite", unaligned_write_perf_);
    buffer << ",";
    append_counter(buffer, "flush", flush_perf_);
    buffer << "}";
    return buffer.str();
}

BlockDevice::~BlockDevice()
{
    std::lock_guard<std::mutex> lock(mutex_);
    CloseHandleLocked();
}

const std::wstring& BlockDevice::Path() const noexcept
{
    return path_;
}

bool BlockDevice::IsWritable() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!writable_)
    {
        (void)EnsureHandle(true);
    }
    return writable_;
}

BlockDevice::Geometry BlockDevice::GetGeometry() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (geometry_cached_)
    {
        return geometry_cache_;
    }

    Geometry geometry{};
    if (!EnsureHandle(false))
    {
        return geometry;
    }

    if (QueryGeometryLocked(geometry))
    {
        geometry_cache_ = geometry;
        geometry_cached_ = true;
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

    std::lock_guard<std::mutex> lock(mutex_);
    if (!EnsureHandle(false))
    {
        return false;
    }

    if (offset_bytes > (std::numeric_limits<std::uint64_t>::max() - base_offset_bytes_))
    {
        return false;
    }
    offset_bytes += base_offset_bytes_;

    const auto block_size = static_cast<std::uint64_t>(LogicalBlockSizeLocked());
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

    LARGE_INTEGER target{};
    target.QuadPart = static_cast<LONGLONG>(aligned_offset);
    if (!SetFilePointerEx(handle_, target, nullptr, FILE_BEGIN))
    {
        return false;
    }

    DWORD bytes_read = 0;
    if (already_aligned)
    {
        if (!ReadFile(handle_, destination, static_cast<DWORD>(destination_size), &bytes_read, nullptr))
        {
            return false;
        }
        out_bytes_read = static_cast<std::size_t>(bytes_read);
        return true;
    }

    read_scratch_buffer_.resize(aligned_size);
    if (!ReadFile(handle_, read_scratch_buffer_.data(), static_cast<DWORD>(read_scratch_buffer_.size()), &bytes_read, nullptr))
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
        read_scratch_buffer_.data() + prefix_bytes,
        bytes_to_copy,
        destination);
    out_bytes_read = bytes_to_copy;
    return true;
}

bool BlockDevice::Write(std::uint64_t offset_bytes, const std::vector<std::byte>& buffer)
{
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
    if (fault_mode.has_value() &&
        (IsFaultMode(*fault_mode, L"1") ||
         IsFaultMode(*fault_mode, L"true") ||
         IsFaultMode(*fault_mode, L"yes") ||
         IsFaultMode(*fault_mode, L"fail")))
    {
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (!EnsureHandle(true))
    {
        return false;
    }

    if (offset_bytes > (std::numeric_limits<std::uint64_t>::max() - base_offset_bytes_))
    {
        return false;
    }
    offset_bytes += base_offset_bytes_;

    const auto block_size = static_cast<std::uint64_t>(LogicalBlockSizeLocked());
    const auto aligned_offset = AlignDown(offset_bytes, block_size);
    const auto prefix_bytes = static_cast<std::size_t>(offset_bytes - aligned_offset);
    if (buffer.size() > (std::numeric_limits<std::uint64_t>::max() - static_cast<std::uint64_t>(prefix_bytes)))
    {
        return false;
    }
    const auto requested_window = static_cast<std::uint64_t>(prefix_bytes) + static_cast<std::uint64_t>(buffer.size());
    const auto aligned_size_u64 = AlignUp(requested_window, block_size);
    if (aligned_size_u64 == 0 || aligned_size_u64 > static_cast<std::uint64_t>(std::numeric_limits<DWORD>::max()))
    {
        return false;
    }
    const auto aligned_size = static_cast<std::size_t>(aligned_size_u64);

    const bool already_aligned =
        prefix_bytes == 0 &&
        static_cast<std::uint64_t>(buffer.size()) == aligned_size_u64;
    if (!already_aligned)
    {
        perf_scope.MarkSecondary();
    }
    LARGE_INTEGER target{};
    target.QuadPart = static_cast<LONGLONG>(aligned_offset);
    if (!SetFilePointerEx(handle_, target, nullptr, FILE_BEGIN))
    {
        return false;
    }

    const std::byte* write_buffer = buffer.data();
    std::size_t write_size = buffer.size();
    if (!already_aligned)
    {
        write_scratch_buffer_.resize(aligned_size);
        DWORD bytes_read = 0;
        if (!ReadFile(handle_, write_scratch_buffer_.data(), static_cast<DWORD>(write_scratch_buffer_.size()), &bytes_read, nullptr) ||
            bytes_read != write_scratch_buffer_.size())
        {
            return false;
        }
        std::copy(buffer.begin(), buffer.end(), write_scratch_buffer_.begin() + static_cast<std::vector<std::byte>::difference_type>(prefix_bytes));
        write_buffer = write_scratch_buffer_.data();
        write_size = write_scratch_buffer_.size();

        target.QuadPart = static_cast<LONGLONG>(aligned_offset);
        if (!SetFilePointerEx(handle_, target, nullptr, FILE_BEGIN))
        {
            return false;
        }
    }

    const auto write_failure = [&]() -> bool
    {
        DWORD bytes_written = 0;
        if (!WriteFile(handle_, write_buffer, static_cast<DWORD>(write_size), &bytes_written, nullptr))
        {
            return false;
        }

        return bytes_written == write_size;
    };

    if (!fault_mode.has_value())
    {
        return write_failure();
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
            !WriteFile(handle_, fault_buffer.data(), static_cast<DWORD>(fault_write_size), &bytes_written, nullptr))
        {
            return false;
        }
        return false;
    }

    return false;
}

bool BlockDevice::Flush()
{
    ScopedPerfTimer perf_scope(flush_perf_);

    if (IsFaultSwitchEnabled(L"APFSACCESS_RW_FAULT_FLUSH"))
    {
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (!EnsureHandle(true))
    {
        return false;
    }

    return FlushFileBuffers(handle_) != FALSE;
}

bool BlockDevice::EnsureHandle(bool write_access) const
{
    if (handle_ != INVALID_HANDLE_VALUE)
    {
        if (!write_access || writable_)
        {
            return true;
        }

        // Upgrade from read-only handle to read-write handle when a write path is requested.
        CloseHandleLocked();
    }

    const auto open_handle = [&](DWORD desired_access) -> HANDLE
    {
        return CreateFileW(
            path_.c_str(),
            desired_access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
    };

    if (write_access)
    {
        handle_ = open_handle(GENERIC_READ | GENERIC_WRITE);
        if (handle_ != INVALID_HANDLE_VALUE)
        {
            writable_ = true;
            geometry_cached_ = false;
            return true;
        }
    }

    handle_ = open_handle(GENERIC_READ);
    if (handle_ == INVALID_HANDLE_VALUE)
    {
        writable_ = false;
        return false;
    }

    writable_ = false;
    geometry_cached_ = false;
    return !write_access;
}

void BlockDevice::CloseHandleLocked() const
{
    if (handle_ != INVALID_HANDLE_VALUE)
    {
        CloseHandle(handle_);
        handle_ = INVALID_HANDLE_VALUE;
    }
    writable_ = false;
}

bool BlockDevice::QueryGeometryLocked(Geometry& geometry) const
{
    geometry = Geometry{};

    LARGE_INTEGER file_size{};
    if (GetFileSizeEx(handle_, &file_size))
    {
        geometry.total_bytes = static_cast<std::uint64_t>(file_size.QuadPart);
    }

    DWORD bytes_returned = 0;
    DISK_GEOMETRY_EX disk_geometry{};
    if (DeviceIoControl(
        handle_,
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
        handle_,
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

std::uint32_t BlockDevice::LogicalBlockSizeLocked() const
{
    if (!geometry_cached_)
    {
        Geometry geometry{};
        if (QueryGeometryLocked(geometry))
        {
            geometry_cache_ = geometry;
            geometry_cached_ = true;
        }
    }

    return std::max<std::uint32_t>(512u, geometry_cache_.logical_block_size);
}
} // namespace apfsaccess::rw
