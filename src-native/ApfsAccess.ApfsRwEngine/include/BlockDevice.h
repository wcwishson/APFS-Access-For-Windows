#pragma once

#include <cstddef>
#include <cstdint>
#include <atomic>
#include <mutex>
#include <span>
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
    [[nodiscard]] bool ReadInto(
        std::uint64_t offset_bytes,
        std::byte* destination,
        std::size_t destination_size,
        std::size_t& bytes_read) const;
    [[nodiscard]] bool Write(std::uint64_t offset_bytes, std::span<const std::byte> buffer);
    [[nodiscard]] bool Write(std::uint64_t offset_bytes, const std::vector<std::byte>& buffer);
    [[nodiscard]] bool Flush();
    [[nodiscard]] std::string PerformanceJson() const;

private:
    struct PerfCounter
    {
        std::atomic<std::uint64_t> count{0};
        std::atomic<std::uint64_t> bytes{0};
        std::atomic<std::uint64_t> total_us{0};
        std::atomic<std::uint64_t> max_us{0};
        std::atomic<std::uint64_t> last_us{0};

        void Observe(std::uint64_t elapsed_us, std::uint64_t byte_count = 0) noexcept;
    };
    struct ScopedPerfTimer;

    [[nodiscard]] HANDLE EnsureReadHandle() const;
    [[nodiscard]] HANDLE EnsureWriteHandle() const;
    void CloseHandlesLocked() const;
    [[nodiscard]] bool QueryGeometryLocked(HANDLE handle, Geometry& geometry) const;
    [[nodiscard]] std::uint32_t LogicalBlockSize() const;
    [[nodiscard]] bool ReadAt(HANDLE handle, std::uint64_t offset_bytes, void* buffer, DWORD bytes_to_read, DWORD& bytes_read) const;
    [[nodiscard]] bool WriteAt(HANDLE handle, std::uint64_t offset_bytes, const void* buffer, DWORD bytes_to_write, DWORD& bytes_written) const;

    std::wstring path_;
    std::uint64_t base_offset_bytes_ = 0;
    mutable HANDLE read_handle_ = INVALID_HANDLE_VALUE;
    mutable HANDLE write_handle_ = INVALID_HANDLE_VALUE;
    mutable bool writable_ = false;
    mutable bool geometry_cached_ = false;
    mutable Geometry geometry_cache_{};
    mutable PerfCounter read_perf_;
    mutable PerfCounter write_perf_;
    mutable PerfCounter unaligned_write_perf_;
    mutable PerfCounter flush_perf_;
    mutable std::mutex handle_mutex_;
    mutable std::mutex geometry_mutex_;
    mutable std::mutex write_mutex_;
};
} // namespace apfsaccess::rw
