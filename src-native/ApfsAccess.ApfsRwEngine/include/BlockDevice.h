#pragma once

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

namespace apfsaccess::rw
{
class BlockDevice
{
public:
    struct Geometry
    {
        std::uint64_t total_bytes = 0;
        std::uint32_t logical_block_size = 4096;
        std::uint32_t physical_block_size = 4096;
    };

    explicit BlockDevice(std::wstring path, std::uint64_t base_offset_bytes = 0);
    ~BlockDevice();

    BlockDevice(const BlockDevice&) = delete;
    BlockDevice& operator=(const BlockDevice&) = delete;
    BlockDevice(BlockDevice&&) = delete;
    BlockDevice& operator=(BlockDevice&&) = delete;

    [[nodiscard]] const std::wstring& Path() const noexcept;
    [[nodiscard]] Geometry GetGeometry() const;
    [[nodiscard]] bool IsWritable() const;

    [[nodiscard]] bool Read(std::uint64_t offset_bytes, std::size_t size_bytes, std::vector<std::byte>& out_buffer) const;
    [[nodiscard]] bool Write(std::uint64_t offset_bytes, const std::vector<std::byte>& buffer);
    [[nodiscard]] bool Flush();

private:
    [[nodiscard]] bool EnsureHandle(bool write_access) const;
    void CloseHandleLocked() const;
    [[nodiscard]] bool QueryGeometryLocked(Geometry& geometry) const;
    [[nodiscard]] std::uint32_t LogicalBlockSizeLocked() const;

    std::wstring path_;
    std::uint64_t base_offset_bytes_ = 0;
    mutable HANDLE handle_ = INVALID_HANDLE_VALUE;
    mutable bool writable_ = false;
    mutable bool geometry_cached_ = false;
    mutable Geometry geometry_cache_{};
    mutable std::vector<std::byte> read_scratch_buffer_;
    mutable std::vector<std::byte> write_scratch_buffer_;
    mutable std::mutex mutex_;
};
} // namespace apfsaccess::rw
