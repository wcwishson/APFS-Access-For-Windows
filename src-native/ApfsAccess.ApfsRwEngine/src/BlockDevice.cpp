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
} // namespace

BlockDevice::BlockDevice(std::wstring path)
    : path_(std::move(path))
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

    out_buffer.resize(size_bytes, std::byte{});
    OVERLAPPED overlapped{};
    overlapped.Offset = static_cast<DWORD>(offset_bytes & 0xFFFFFFFFull);
    overlapped.OffsetHigh = static_cast<DWORD>(offset_bytes >> 32);

    DWORD bytes_read = 0;
    if (!ReadFile(handle_, out_buffer.data(), static_cast<DWORD>(size_bytes), &bytes_read, &overlapped))
    {
        out_buffer.clear();
        return false;
    }

    if (bytes_read != size_bytes)
    {
        out_buffer.resize(bytes_read);
    }
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

    OVERLAPPED overlapped{};
    overlapped.Offset = static_cast<DWORD>(offset_bytes & 0xFFFFFFFFull);
    overlapped.OffsetHigh = static_cast<DWORD>(offset_bytes >> 32);

    DWORD bytes_written = 0;
    if (!WriteFile(handle_, buffer.data(), static_cast<DWORD>(buffer.size()), &bytes_written, &overlapped))
    {
        return false;
    }

    return bytes_written == buffer.size();
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
        return geometry.total_bytes > 0;
    }

    return geometry.total_bytes > 0;
}
} // namespace apfsaccess::rw
