#include "BlockDevice.h"

#include <algorithm>
#include <cstdlib>
#include <cwchar>
#include <limits>
#include <memory>
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
    if (size_bytes > static_cast<std::size_t>(std::numeric_limits<DWORD>::max()))
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
    if (size_bytes > (std::numeric_limits<std::uint64_t>::max() - static_cast<std::uint64_t>(prefix_bytes)))
    {
        return false;
    }
    const auto requested_window = static_cast<std::uint64_t>(prefix_bytes) + static_cast<std::uint64_t>(size_bytes);
    const auto aligned_size_u64 = AlignUp(requested_window, block_size);
    if (aligned_size_u64 == 0 || aligned_size_u64 > static_cast<std::uint64_t>(std::numeric_limits<DWORD>::max()))
    {
        return false;
    }
    const auto aligned_size = static_cast<std::size_t>(aligned_size_u64);
    const bool already_aligned =
        prefix_bytes == 0 &&
        static_cast<std::uint64_t>(size_bytes) == aligned_size_u64;

    LARGE_INTEGER target{};
    target.QuadPart = static_cast<LONGLONG>(aligned_offset);
    if (!SetFilePointerEx(handle_, target, nullptr, FILE_BEGIN))
    {
        return false;
    }

    DWORD bytes_read = 0;
    if (already_aligned)
    {
        out_buffer.resize(size_bytes);
        if (!ReadFile(handle_, out_buffer.data(), static_cast<DWORD>(out_buffer.size()), &bytes_read, nullptr))
        {
            out_buffer.clear();
            return false;
        }
        out_buffer.resize(static_cast<std::size_t>(bytes_read));
        return true;
    }

    read_scratch_buffer_.resize(aligned_size);
    if (!ReadFile(handle_, read_scratch_buffer_.data(), static_cast<DWORD>(read_scratch_buffer_.size()), &bytes_read, nullptr))
    {
        out_buffer.clear();
        return false;
    }
    if (bytes_read < prefix_bytes)
    {
        return false;
    }

    const auto available = static_cast<std::size_t>(bytes_read) - prefix_bytes;
    const auto bytes_to_copy = std::min(size_bytes, available);
    out_buffer.assign(
        read_scratch_buffer_.begin() + static_cast<std::vector<std::byte>::difference_type>(prefix_bytes),
        read_scratch_buffer_.begin() + static_cast<std::vector<std::byte>::difference_type>(prefix_bytes + bytes_to_copy));
    return true;
}

bool BlockDevice::Write(std::uint64_t offset_bytes, const std::vector<std::byte>& buffer)
{
    if (buffer.empty())
    {
        return true;
    }
    if (buffer.size() > static_cast<std::size_t>(std::numeric_limits<DWORD>::max()))
    {
        return false;
    }
    if (IsFaultSwitchEnabled(L"APFSACCESS_RW_FAULT_WRITE"))
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

    DWORD bytes_written = 0;
    if (!WriteFile(handle_, write_buffer, static_cast<DWORD>(write_size), &bytes_written, nullptr))
    {
        return false;
    }

    return bytes_written == write_size;
}

bool BlockDevice::Flush()
{
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
