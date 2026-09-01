#include "BlockDevice.h"
#include "MetadataStore.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <cstdint>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <stdexcept>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>
#include <windows.h>

namespace
{
constexpr std::size_t kContainerBytes = 16 * 1024 * 1024;
constexpr std::uint32_t kBlockSize = 4096;
constexpr std::uint64_t kTotalBlocks = kContainerBytes / kBlockSize;
constexpr std::uint64_t kInitialCheckpointXid = 7;
constexpr std::uint64_t kSpacemanObjectId = 0x2A;
constexpr std::uint64_t kVolumeRootObject = 0x54;
constexpr std::uint32_t kNxsbMagic = 0x4253584E; // NXSB
constexpr std::uint64_t kNativeCheckpointBandBlocks = 128;
constexpr std::uint64_t kNativeCheckpointBandStart = kTotalBlocks - kNativeCheckpointBandBlocks;
constexpr std::uint64_t kNativeObjectMapCheckpointOffset = 0;
constexpr std::uint64_t kNativeSpacemanCheckpointOffset = 4;
constexpr std::uint64_t kNativeInodeCheckpointOffset = 8;
constexpr std::uint64_t kNativeBtreeCheckpointOffset = 24;
constexpr std::uint64_t kNativeReplayCheckpointOffset = 64;
constexpr std::uint64_t kNativeOverflowCheckpointOffset = kNativeReplayCheckpointOffset + 2;
constexpr std::uint64_t kNativeObjectMapOverflowBlocks = 48;
constexpr std::uint64_t kNativeInodeOverflowOffset = kNativeOverflowCheckpointOffset + kNativeObjectMapOverflowBlocks;
constexpr std::uint64_t kNativeSpacemanExtensionBlocks = 32;
constexpr std::uint64_t kNativeInodeExtensionBlocks = 192;
constexpr std::uint64_t kNativeBtreeExtensionBlocks = 384;
constexpr std::uint64_t kNativeMetadataExtensionBlocks =
    kNativeInodeExtensionBlocks + kNativeBtreeExtensionBlocks;
constexpr std::uint64_t kNativeCheckpointExtensionBlocks =
    kNativeSpacemanExtensionBlocks + kNativeMetadataExtensionBlocks;
constexpr std::uint64_t kNativeMinimumSpacemanExtensionStartBlock = 1024;
constexpr std::uint64_t kNativeMinimumMetadataExtensionStartBlock = 1024;
constexpr std::uint64_t kNativeSpacemanExtensionOffset = 0;
constexpr std::uint64_t kNativeInodeExtensionOffset = 0;
constexpr std::uint64_t kNativeBtreeExtensionOffset = kNativeInodeExtensionBlocks;

bool Require(bool condition, const std::string& message);

std::optional<std::uint64_t> ExtractNestedUnsignedValue(
    const std::string& json,
    const std::string& object_name,
    const std::string& value_name)
{
    const auto object_key = "\"" + object_name + "\":{";
    auto object_pos = json.find(object_key);
    if (object_pos == std::string::npos)
    {
        return std::nullopt;
    }

    const auto key = "\"" + value_name + "\":";
    auto pos = json.find(key, object_pos + object_key.size());
    if (pos == std::string::npos)
    {
        return std::nullopt;
    }

    pos += key.size();
    auto end = pos;
    while (end < json.size() && json[end] >= '0' && json[end] <= '9')
    {
        ++end;
    }
    if (end == pos)
    {
        return std::nullopt;
    }

    return std::stoull(json.substr(pos, end - pos));
}

class ScopedEnvironmentVariable
{
public:
    ScopedEnvironmentVariable(const wchar_t* name, const wchar_t* value)
        : name_(name == nullptr ? L"" : name)
    {
        if (name_.empty())
        {
            return;
        }

        const auto required_chars = GetEnvironmentVariableW(name_.c_str(), nullptr, 0);
        if (required_chars > 0)
        {
            previous_value_.resize(required_chars);
            const auto copied_chars = GetEnvironmentVariableW(
                name_.c_str(),
                previous_value_.data(),
                required_chars);
            if (copied_chars > 0 && copied_chars < required_chars)
            {
                previous_value_.resize(copied_chars);
                had_previous_value_ = true;
            }
            else
            {
                previous_value_.clear();
            }
        }

        (void)_wputenv_s(name_.c_str(), value == nullptr ? L"" : value);
    }

    ~ScopedEnvironmentVariable()
    {
        if (name_.empty())
        {
            return;
        }

        if (had_previous_value_)
        {
            (void)_wputenv_s(name_.c_str(), previous_value_.c_str());
        }
        else
        {
            (void)_wputenv_s(name_.c_str(), L"");
        }
    }

    ScopedEnvironmentVariable(const ScopedEnvironmentVariable&) = delete;
    ScopedEnvironmentVariable& operator=(const ScopedEnvironmentVariable&) = delete;

private:
    std::wstring name_;
    std::wstring previous_value_;
    bool had_previous_value_ = false;
};

void WriteLe32(std::vector<std::byte>& buffer, std::size_t offset, std::uint32_t value)
{
    if (offset + 4 > buffer.size())
    {
        return;
    }

    buffer[offset + 0] = static_cast<std::byte>(value & 0xffu);
    buffer[offset + 1] = static_cast<std::byte>((value >> 8) & 0xffu);
    buffer[offset + 2] = static_cast<std::byte>((value >> 16) & 0xffu);
    buffer[offset + 3] = static_cast<std::byte>((value >> 24) & 0xffu);
}

void WriteLe64(std::vector<std::byte>& buffer, std::size_t offset, std::uint64_t value)
{
    if (offset + 8 > buffer.size())
    {
        return;
    }

    for (int i = 0; i < 8; ++i)
    {
        buffer[offset + static_cast<std::size_t>(i)] = static_cast<std::byte>((value >> (i * 8)) & 0xffu);
    }
}

bool HasValidApfsObjectChecksum(const std::vector<std::byte>& block)
{
    constexpr std::uint64_t kModulus = std::numeric_limits<std::uint32_t>::max();
    if (block.size() < 12 || ((block.size() - 8) % sizeof(std::uint32_t)) != 0)
    {
        return false;
    }

    std::uint64_t sum1 = 0;
    std::uint64_t sum2 = 0;
    const auto add_word = [&](std::size_t offset)
    {
        const auto value =
            static_cast<std::uint32_t>(std::to_integer<unsigned char>(block[offset + 0])) |
            (static_cast<std::uint32_t>(std::to_integer<unsigned char>(block[offset + 1])) << 8) |
            (static_cast<std::uint32_t>(std::to_integer<unsigned char>(block[offset + 2])) << 16) |
            (static_cast<std::uint32_t>(std::to_integer<unsigned char>(block[offset + 3])) << 24);
        sum1 = (sum1 + value) % kModulus;
        sum2 = (sum2 + sum1) % kModulus;
    };

    for (std::size_t offset = 8; offset < block.size(); offset += sizeof(std::uint32_t))
    {
        add_word(offset);
    }
    add_word(0);
    add_word(4);
    return sum1 == 0 && sum2 == 0;
}

bool CreateSyntheticContainer(const std::filesystem::path& image_path)
{
    std::vector<std::byte> bytes(kContainerBytes, std::byte{0});
    const auto write_superblock = [&](std::size_t base_offset, std::uint64_t checkpoint_xid)
    {
        WriteLe64(bytes, base_offset + 0x10, checkpoint_xid);
        WriteLe32(bytes, base_offset + 0x20, kNxsbMagic);
        WriteLe32(bytes, base_offset + 0x24, kBlockSize);
        WriteLe64(bytes, base_offset + 0x28, kTotalBlocks);
        WriteLe64(bytes, base_offset + 0x98, kSpacemanObjectId);
        WriteLe64(bytes, base_offset + 0xA0, kVolumeRootObject);
    };

    write_superblock(0, kInitialCheckpointXid);
    write_superblock(static_cast<std::size_t>(kBlockSize), kInitialCheckpointXid);

    std::ofstream out(image_path, std::ios::binary | std::ios::trunc);
    if (!out.good())
    {
        return false;
    }

    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    return out.good();
}

std::vector<std::byte> BuildPatternPayload(std::size_t bytes, unsigned char seed)
{
    std::vector<std::byte> payload(bytes, std::byte{0});
    for (std::size_t i = 0; i < payload.size(); ++i)
    {
        payload[i] = static_cast<std::byte>((seed + static_cast<unsigned char>(i & 0xffu)) & 0xffu);
    }
    return payload;
}

bool ReadBytesFromImage(
    const std::filesystem::path& image_path,
    std::uint64_t offset_bytes,
    std::size_t size_bytes,
    std::vector<std::byte>& out)
{
    out.assign(size_bytes, std::byte{0});
    if (size_bytes == 0)
    {
        return true;
    }

    std::ifstream input(image_path, std::ios::binary);
    if (!input.good())
    {
        out.clear();
        return false;
    }

    input.seekg(static_cast<std::streamoff>(offset_bytes), std::ios::beg);
    if (!input.good())
    {
        out.clear();
        return false;
    }

    input.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(size_bytes));
    if (static_cast<std::size_t>(input.gcount()) != size_bytes)
    {
        out.clear();
        return false;
    }

    return true;
}

bool WriteBytesToImage(
    const std::filesystem::path& image_path,
    std::uint64_t offset_bytes,
    const std::vector<std::byte>& bytes)
{
    if (bytes.empty())
    {
        return true;
    }

    std::fstream io(image_path, std::ios::binary | std::ios::in | std::ios::out);
    if (!io.good())
    {
        return false;
    }

    io.seekp(static_cast<std::streamoff>(offset_bytes), std::ios::beg);
    if (!io.good())
    {
        return false;
    }

    io.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    return io.good();
}

bool TestBlockDeviceOffsetIo(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "block_device_offset_io.bin";
    std::vector<std::byte> seed(64 * 1024, std::byte{0});
    for (std::size_t i = 0; i < seed.size(); ++i)
    {
        seed[i] = static_cast<std::byte>(i & 0xffu);
    }
    {
        std::ofstream out(image_path, std::ios::binary | std::ios::trunc);
        if (!out.good())
        {
            return Require(false, "BlockDevice offset I/O test should create image");
        }
        out.write(reinterpret_cast<const char*>(seed.data()), static_cast<std::streamsize>(seed.size()));
        if (!out.good())
        {
            return Require(false, "BlockDevice offset I/O test should seed image");
        }
    }

    apfsaccess::rw::BlockDevice device(image_path.wstring());
    bool ok = true;

    const auto aligned_payload = BuildPatternPayload(4096, 0x51);
    ok &= Require(device.Write(8192, aligned_payload), "BlockDevice offset I/O aligned write should succeed");

    std::vector<std::byte> aligned_read;
    ok &= Require(device.Read(8192, aligned_payload.size(), aligned_read), "BlockDevice offset I/O aligned read should succeed");
    ok &= Require(aligned_read == aligned_payload, "BlockDevice offset I/O aligned read should match write");

    const auto span_source = BuildPatternPayload(2048, 0x6D);
    const std::span<const std::byte> span_payload(span_source.data() + 256, 1024);
    ok &= Require(device.Write(12288 + 512, span_payload), "BlockDevice offset I/O span write should succeed");

    std::vector<std::byte> span_read;
    ok &= Require(device.Read(12288, 4096, span_read), "BlockDevice offset I/O span block read should succeed");
    if (span_read.size() == 4096)
    {
        ok &= Require(
            std::equal(span_payload.begin(), span_payload.end(), span_read.begin() + 512),
            "BlockDevice offset I/O span payload should land at requested offset");
        ok &= Require(
            std::equal(seed.begin() + 12288, seed.begin() + 12800, span_read.begin()),
            "BlockDevice offset I/O span write should preserve block prefix");
        ok &= Require(
            std::equal(seed.begin() + 13824, seed.begin() + 16384, span_read.begin() + 1536),
            "BlockDevice offset I/O span write should preserve block suffix");
    }
    else
    {
        ok &= Require(false, "BlockDevice offset I/O span block read should return full block");
    }

    const auto unaligned_payload = BuildPatternPayload(1000, 0xA4);
    ok &= Require(device.Write(8192 + 123, unaligned_payload), "BlockDevice offset I/O unaligned write should succeed");

    std::vector<std::byte> whole_block;
    ok &= Require(device.Read(8192, 4096, whole_block), "BlockDevice offset I/O block read after RMW should succeed");
    if (whole_block.size() == 4096)
    {
        ok &= Require(
            std::equal(unaligned_payload.begin(), unaligned_payload.end(), whole_block.begin() + 123),
            "BlockDevice offset I/O unaligned payload should land at requested offset");
        ok &= Require(
            std::equal(aligned_payload.begin(), aligned_payload.begin() + 123, whole_block.begin()),
            "BlockDevice offset I/O unaligned write should preserve block prefix");
        ok &= Require(
            std::equal(
                aligned_payload.begin() + 1123,
                aligned_payload.end(),
                whole_block.begin() + 1123),
            "BlockDevice offset I/O unaligned write should preserve block suffix");
    }
    else
    {
        ok &= Require(false, "BlockDevice offset I/O block read should return full block");
    }

    std::vector<std::byte> disjoint_read;
    ok &= Require(device.Read(16384, 4096, disjoint_read), "BlockDevice offset I/O disjoint read should succeed");
    ok &= Require(disjoint_read.size() == 4096, "BlockDevice offset I/O disjoint read should return full block");
    if (disjoint_read.size() == 4096)
    {
        ok &= Require(
            std::equal(seed.begin() + 16384, seed.begin() + 20480, disjoint_read.begin()),
            "BlockDevice offset I/O disjoint read should not depend on previous seek position");
    }

    const auto before_flush_perf = device.PerformanceJson();
    ok &= Require(
        ExtractNestedUnsignedValue(before_flush_perf, "flush", "count").value_or(1) == 0,
        "BlockDevice offset I/O should report no flushes before explicit flush");
    ok &= Require(
        ExtractNestedUnsignedValue(before_flush_perf, "flush", "p95Us").has_value(),
        "BlockDevice offset I/O flush counter should report p95 latency before first flush");
    ok &= Require(
        ExtractNestedUnsignedValue(before_flush_perf, "flush", "p50Us").has_value(),
        "BlockDevice offset I/O flush counter should report p50 latency before first flush");
    ok &= Require(
        ExtractNestedUnsignedValue(before_flush_perf, "writeQueueWait", "count").value_or(0) >= 3,
        "BlockDevice offset I/O should report serialized write queue waits");
    ok &= Require(
        ExtractNestedUnsignedValue(before_flush_perf, "flushQueueWait", "count").value_or(1) == 0,
        "BlockDevice offset I/O should report no flush queue waits before explicit flush");

    ok &= Require(device.Flush(), "BlockDevice offset I/O flush should succeed");
    const auto after_flush_perf = device.PerformanceJson();
    const auto flush_count = ExtractNestedUnsignedValue(after_flush_perf, "flush", "count");
    const auto flush_max_us = ExtractNestedUnsignedValue(after_flush_perf, "flush", "maxUs");
    const auto flush_p50_us = ExtractNestedUnsignedValue(after_flush_perf, "flush", "p50Us");
    const auto flush_p95_us = ExtractNestedUnsignedValue(after_flush_perf, "flush", "p95Us");
    const auto flush_queue_count = ExtractNestedUnsignedValue(after_flush_perf, "flushQueueWait", "count");
    ok &= Require(
        flush_count.value_or(0) == 1,
        "BlockDevice offset I/O should report one explicit flush");
    ok &= Require(
        flush_p95_us.has_value(),
        "BlockDevice offset I/O flush counter should keep reporting p95 latency after flush");
    ok &= Require(
        flush_queue_count.value_or(0) == 1,
        "BlockDevice offset I/O should report one explicit flush queue wait");
    if (flush_max_us.has_value() && flush_p50_us.has_value() && flush_p95_us.has_value())
    {
        ok &= Require(
            *flush_p50_us <= *flush_p95_us,
            "BlockDevice offset I/O flush p50 latency should not exceed p95 latency");
        ok &= Require(
            *flush_p95_us <= *flush_max_us,
            "BlockDevice offset I/O flush p95 latency should not exceed max latency");
    }
    return ok;
}

bool TestBlockDeviceConcurrentUnalignedReadsUseThreadLocalScratch(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "block_device_concurrent_unaligned_reads.bin";
    const auto seed = BuildPatternPayload(256 * 1024, 0x37);
    {
        std::ofstream out(image_path, std::ios::binary | std::ios::trunc);
        if (!out.good())
        {
            return Require(false, "BlockDevice concurrent read test should create image");
        }
        out.write(reinterpret_cast<const char*>(seed.data()), static_cast<std::streamsize>(seed.size()));
        if (!out.good())
        {
            return Require(false, "BlockDevice concurrent read test should seed image");
        }
    }

    apfsaccess::rw::BlockDevice device(image_path.wstring());
    constexpr std::size_t kReaderCount = 4;
    constexpr std::uint64_t kOffsetStride = 4096;
    constexpr std::uint64_t kReadOffset = 37;
    constexpr std::size_t kReadBytes = 4096;
    std::array<std::vector<std::byte>, kReaderCount> results;
    std::array<bool, kReaderCount> read_ok{};
    std::array<std::thread, kReaderCount> readers;
    for (std::size_t index = 0; index < kReaderCount; ++index)
    {
        readers[index] = std::thread(
            [&device, &results, &read_ok, index, kOffsetStride, kReadOffset, kReadBytes]()
            {
                read_ok[index] = device.Read(
                    kReadOffset + index * kOffsetStride,
                    kReadBytes,
                    results[index]);
            });
    }
    for (auto& reader : readers)
    {
        reader.join();
    }

    bool ok = true;
    for (std::size_t index = 0; index < kReaderCount; ++index)
    {
        ok &= Require(read_ok[index], "BlockDevice concurrent unaligned read should succeed");
        const auto expected_begin = seed.begin() + static_cast<std::ptrdiff_t>(kReadOffset + index * kOffsetStride);
        ok &= Require(
            results[index].size() == kReadBytes &&
                std::equal(expected_begin, expected_begin + kReadBytes, results[index].begin()),
            "BlockDevice concurrent unaligned read should preserve source bytes");
    }
    const auto perf = device.PerformanceJson();
    ok &= Require(
        ExtractNestedUnsignedValue(perf, "scratch", "readThreadLocalUseCount").value_or(0) >= kReaderCount,
        "BlockDevice small unaligned reads should use thread-local scratch");
    return ok;
}

bool TestBlockDeviceReadCacheInvalidatesAfterWrite(const std::filesystem::path& run_root)
{
    ScopedEnvironmentVariable read_cache_opt_in(
        L"APFSACCESS_EXPERIMENTAL_BLOCK_READ_CACHE",
        L"1");
    const auto image_path = run_root / "block_device_read_cache.bin";
    const auto seed = BuildPatternPayload(64 * 1024, 0x2D);
    {
        std::ofstream out(image_path, std::ios::binary | std::ios::trunc);
        if (!out.good())
        {
            return Require(false, "BlockDevice read-cache test should create image");
        }
        out.write(reinterpret_cast<const char*>(seed.data()), static_cast<std::streamsize>(seed.size()));
        if (!out.good())
        {
            return Require(false, "BlockDevice read-cache test should seed image");
        }
    }

    apfsaccess::rw::BlockDevice device(image_path.wstring());
    constexpr std::uint64_t offset = 123;
    constexpr std::size_t bytes = 4096;
    std::vector<std::byte> first;
    std::vector<std::byte> second;
    bool ok = true;
    ok &= Require(device.Read(offset, bytes, first), "BlockDevice read-cache first read should succeed");
    ok &= Require(device.Read(offset, bytes, second), "BlockDevice read-cache repeated read should succeed");
    ok &= Require(first == second, "BlockDevice read-cache repeated read should preserve bytes");
    if (first.size() == bytes)
    {
        ok &= Require(
            std::equal(seed.begin() + static_cast<std::ptrdiff_t>(offset),
                       seed.begin() + static_cast<std::ptrdiff_t>(offset + bytes),
                       first.begin()),
            "BlockDevice read-cache first read should match source bytes");
    }

    const auto before_write = device.PerformanceJson();
    const auto hits_before_write = ExtractNestedUnsignedValue(before_write, "readCache", "hits");
    const auto misses_before_write = ExtractNestedUnsignedValue(before_write, "readCache", "misses");
    ok &= Require(hits_before_write.value_or(0) >= 1, "BlockDevice read-cache should report a repeated-read hit");
    ok &= Require(misses_before_write.value_or(0) >= 1, "BlockDevice read-cache should report the initial miss");

    const auto replacement = BuildPatternPayload(64, 0xE1);
    ok &= Require(device.Write(offset, replacement), "BlockDevice read-cache invalidation write should succeed");

    std::vector<std::byte> after_write;
    ok &= Require(device.Read(offset, bytes, after_write), "BlockDevice read-cache post-write read should succeed");
    if (after_write.size() == bytes)
    {
        ok &= Require(
            std::equal(replacement.begin(), replacement.end(), after_write.begin()),
            "BlockDevice read-cache must not return stale bytes after a write");
    }

    const auto after = device.PerformanceJson();
    const auto invalidations = ExtractNestedUnsignedValue(after, "readCache", "invalidations");
    const auto misses_after_write = ExtractNestedUnsignedValue(after, "readCache", "misses");
    ok &= Require(
        invalidations.value_or(0) >= 1,
        "BlockDevice read-cache should report invalidation after a write");
    ok &= Require(
        misses_after_write.value_or(0) > misses_before_write.value_or(0),
        "BlockDevice read-cache post-write read should miss after invalidation");
    return ok;
}

bool TestBlockDeviceReadCacheMissDoesNotReinsertAfterConcurrentWrite(const std::filesystem::path& run_root)
{
    ScopedEnvironmentVariable read_cache_opt_in(
        L"APFSACCESS_EXPERIMENTAL_BLOCK_READ_CACHE",
        L"1");
    const auto image_path = run_root / "block_device_read_cache_race.bin";
    const auto seed = BuildPatternPayload(64 * 1024, 0x2D);
    {
        std::ofstream out(image_path, std::ios::binary | std::ios::trunc);
        if (!out.good())
        {
            return Require(false, "BlockDevice read-cache race test should create image");
        }
        out.write(reinterpret_cast<const char*>(seed.data()), static_cast<std::streamsize>(seed.size()));
        if (!out.good())
        {
            return Require(false, "BlockDevice read-cache race test should seed image");
        }
    }

    apfsaccess::rw::BlockDevice device(image_path.wstring());
    constexpr std::uint64_t offset = 123;
    constexpr std::size_t bytes = 4096;
    const auto replacement = BuildPatternPayload(64, 0xE1);

    std::mutex hook_mutex;
    std::condition_variable hook_cv;
    bool miss_read_reached = false;
    bool allow_miss_read_to_finish = false;
    bool hook_armed = true;
    device.SetReadCacheMissHookForTests(
        [&]()
        {
            std::unique_lock lock(hook_mutex);
            if (!hook_armed)
            {
                return;
            }
            hook_armed = false;
            miss_read_reached = true;
            hook_cv.notify_one();
            hook_cv.wait(lock, [&]() { return allow_miss_read_to_finish; });
        });

    std::vector<std::byte> reader_result;
    bool reader_ok = false;
    std::thread reader(
        [&]()
        {
            reader_ok = device.Read(offset, bytes, reader_result);
        });

    bool reached = false;
    {
        std::unique_lock lock(hook_mutex);
        reached = hook_cv.wait_for(lock, std::chrono::seconds(10), [&]() { return miss_read_reached; });
    }

    if (!reached)
    {
        {
            std::lock_guard lock(hook_mutex);
            allow_miss_read_to_finish = true;
        }
        hook_cv.notify_one();
        reader.join();
        device.SetReadCacheMissHookForTests({});
        return Require(false, "BlockDevice read-cache race test should reach the post-read synchronization hook");
    }

    bool writer_ok = false;
    std::thread writer(
        [&]()
        {
            writer_ok = device.Write(offset, replacement);
        });
    writer.join();

    {
        std::lock_guard lock(hook_mutex);
        allow_miss_read_to_finish = true;
    }
    hook_cv.notify_one();
    reader.join();
    device.SetReadCacheMissHookForTests({});

    bool ok = true;
    ok &= Require(reader_ok, "BlockDevice read-cache race reader should succeed");
    ok &= Require(writer_ok, "BlockDevice read-cache race writer should succeed");
    if (reader_result.size() == bytes)
    {
        ok &= Require(
            std::equal(seed.begin() + static_cast<std::ptrdiff_t>(offset),
                       seed.begin() + static_cast<std::ptrdiff_t>(offset + bytes),
                       reader_result.begin()),
            "BlockDevice read-cache race reader should capture the pre-write bytes");
    }
    else
    {
        ok &= Require(false, "BlockDevice read-cache race reader should return the full miss window");
    }

    std::vector<std::byte> after_write;
    ok &= Require(
        device.Read(offset, bytes, after_write),
        "BlockDevice read-cache race post-write read should succeed");
    if (after_write.size() == bytes)
    {
        std::vector<std::byte> expected(seed.begin() + static_cast<std::ptrdiff_t>(offset),
                                        seed.begin() + static_cast<std::ptrdiff_t>(offset + bytes));
        std::copy(replacement.begin(), replacement.end(), expected.begin());
        ok &= Require(
            after_write == expected,
            "BlockDevice read-cache race post-write read must not return the stale miss result");
    }
    else
    {
        ok &= Require(false, "BlockDevice read-cache race post-write read should return the full window");
    }
    return ok;
}

bool TestBlockDeviceReadCacheMissStartedDuringWriteDoesNotSurvive(const std::filesystem::path& run_root)
{
    ScopedEnvironmentVariable read_cache_opt_in(
        L"APFSACCESS_EXPERIMENTAL_BLOCK_READ_CACHE",
        L"1");
    const auto image_path = run_root / "block_device_read_cache_write_window.bin";
    const auto seed = BuildPatternPayload(64 * 1024, 0x2D);
    {
        std::ofstream out(image_path, std::ios::binary | std::ios::trunc);
        if (!out.good())
        {
            return Require(false, "BlockDevice read-cache write-window test should create image");
        }
        out.write(reinterpret_cast<const char*>(seed.data()), static_cast<std::streamsize>(seed.size()));
        if (!out.good())
        {
            return Require(false, "BlockDevice read-cache write-window test should seed image");
        }
    }

    apfsaccess::rw::BlockDevice device(image_path.wstring());
    constexpr std::uint64_t offset = 123;
    constexpr std::size_t bytes = 4096;
    const auto replacement = BuildPatternPayload(64, 0xE1);

    std::mutex sync_mutex;
    std::condition_variable sync_cv;
    bool write_invalidation_reached = false;
    bool allow_write_to_finish = false;
    bool miss_read_reached = false;
    bool allow_miss_read_to_finish = false;
    device.SetWriteCacheInvalidationHookForTests(
        [&]()
        {
            std::unique_lock lock(sync_mutex);
            write_invalidation_reached = true;
            sync_cv.notify_all();
            sync_cv.wait(lock, [&]() { return allow_write_to_finish; });
        });
    device.SetReadCacheMissHookForTests(
        [&]()
        {
            std::unique_lock lock(sync_mutex);
            miss_read_reached = true;
            sync_cv.notify_all();
            sync_cv.wait(lock, [&]() { return allow_miss_read_to_finish; });
        });

    bool writer_ok = false;
    std::thread writer(
        [&]()
        {
            writer_ok = device.Write(offset, replacement);
        });

    bool reached = false;
    {
        std::unique_lock lock(sync_mutex);
        reached = sync_cv.wait_for(
            lock,
            std::chrono::seconds(10),
            [&]() { return write_invalidation_reached; });
    }
    if (!reached)
    {
        {
            std::lock_guard lock(sync_mutex);
            allow_write_to_finish = true;
        }
        sync_cv.notify_all();
        writer.join();
        device.SetReadCacheMissHookForTests({});
        device.SetWriteCacheInvalidationHookForTests({});
        return Require(false, "BlockDevice read-cache write-window test should reach write invalidation hook");
    }

    std::vector<std::byte> reader_result;
    bool reader_ok = false;
    std::thread reader(
        [&]()
        {
            reader_ok = device.Read(offset, bytes, reader_result);
        });

    bool miss_reached = false;
    {
        std::unique_lock lock(sync_mutex);
        miss_reached = sync_cv.wait_for(
            lock,
            std::chrono::seconds(10),
            [&]() { return miss_read_reached; });
    }
    if (!miss_reached)
    {
        {
            std::lock_guard lock(sync_mutex);
            allow_miss_read_to_finish = true;
            allow_write_to_finish = true;
        }
        sync_cv.notify_all();
        reader.join();
        writer.join();
        device.SetReadCacheMissHookForTests({});
        device.SetWriteCacheInvalidationHookForTests({});
        return Require(false, "BlockDevice read-cache write-window test should reach read miss hook");
    }

    {
        std::lock_guard lock(sync_mutex);
        allow_miss_read_to_finish = true;
    }
    sync_cv.notify_all();
    reader.join();

    {
        std::lock_guard lock(sync_mutex);
        allow_write_to_finish = true;
    }
    sync_cv.notify_all();
    writer.join();
    device.SetReadCacheMissHookForTests({});
    device.SetWriteCacheInvalidationHookForTests({});

    bool ok = true;
    ok &= Require(reader_ok, "BlockDevice read-cache write-window reader should succeed");
    ok &= Require(writer_ok, "BlockDevice read-cache write-window writer should succeed");
    if (reader_result.size() == bytes)
    {
        ok &= Require(
            std::equal(seed.begin() + static_cast<std::ptrdiff_t>(offset),
                       seed.begin() + static_cast<std::ptrdiff_t>(offset + bytes),
                       reader_result.begin()),
            "BlockDevice read-cache write-window reader should capture the pre-write bytes");
    }
    else
    {
        ok &= Require(false, "BlockDevice read-cache write-window reader should return the full miss window");
    }

    std::vector<std::byte> after_write;
    ok &= Require(
        device.Read(offset, bytes, after_write),
        "BlockDevice read-cache write-window post-write read should succeed");
    if (after_write.size() == bytes)
    {
        std::vector<std::byte> expected(seed.begin() + static_cast<std::ptrdiff_t>(offset),
                                        seed.begin() + static_cast<std::ptrdiff_t>(offset + bytes));
        std::copy(replacement.begin(), replacement.end(), expected.begin());
        ok &= Require(
            after_write == expected,
            "BlockDevice read-cache miss begun during a write must not survive write completion");
    }
    else
    {
        ok &= Require(false, "BlockDevice read-cache write-window post-write read should return the full window");
    }
    return ok;
}

bool TestBlockDeviceReadCacheDisabledByDefault(const std::filesystem::path& run_root)
{
    ScopedEnvironmentVariable read_cache_opt_out(
        L"APFSACCESS_EXPERIMENTAL_BLOCK_READ_CACHE",
        L"");
    const auto image_path = run_root / "block_device_read_cache_disabled.bin";
    const auto seed = BuildPatternPayload(64 * 1024, 0x4B);
    {
        std::ofstream out(image_path, std::ios::binary | std::ios::trunc);
        if (!out.good())
        {
            return Require(false, "BlockDevice disabled read-cache test should create image");
        }
        out.write(reinterpret_cast<const char*>(seed.data()), static_cast<std::streamsize>(seed.size()));
        if (!out.good())
        {
            return Require(false, "BlockDevice disabled read-cache test should seed image");
        }
    }

    apfsaccess::rw::BlockDevice device(image_path.wstring());
    std::vector<std::byte> first;
    std::vector<std::byte> second;
    bool ok = true;
    ok &= Require(device.Read(123, 4096, first), "BlockDevice disabled read-cache first read should succeed");
    ok &= Require(device.Read(123, 4096, second), "BlockDevice disabled read-cache second read should succeed");
    ok &= Require(first == second, "BlockDevice disabled read-cache reads should preserve bytes");

    const auto perf = device.PerformanceJson();
    ok &= Require(
        ExtractNestedUnsignedValue(perf, "readCache", "hits").value_or(1) == 0,
        "BlockDevice disabled read-cache should report zero hits");
    ok &= Require(
        ExtractNestedUnsignedValue(perf, "readCache", "misses").value_or(1) == 0,
        "BlockDevice disabled read-cache should report zero misses");
    ok &= Require(
        ExtractNestedUnsignedValue(perf, "readCache", "bytes").value_or(1) == 0,
        "BlockDevice disabled read-cache should report zero cached bytes");
    ok &= Require(
        ExtractNestedUnsignedValue(perf, "rawRead", "count").value_or(0) >= 2,
        "BlockDevice disabled read-cache should perform raw reads for every request");
    ok &= Require(
        ExtractNestedUnsignedValue(perf, "rawRead", "p50Us").has_value() &&
        ExtractNestedUnsignedValue(perf, "rawRead", "p95Us").has_value() &&
        ExtractNestedUnsignedValue(perf, "rawRead", "maxUs").has_value(),
        "BlockDevice raw-read counter should expose p50, p95, and max latency");
    return ok;
}

bool TestBlockDeviceReadCacheRejectsNonOptInValues(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "block_device_read_cache_negative_opt_in.bin";
    const auto seed = BuildPatternPayload(64 * 1024, 0x53);
    {
        std::ofstream out(image_path, std::ios::binary | std::ios::trunc);
        if (!out.good())
        {
            return Require(false, "BlockDevice negative opt-in test should create image");
        }
        out.write(reinterpret_cast<const char*>(seed.data()), static_cast<std::streamsize>(seed.size()));
    }

    constexpr std::array<const wchar_t*, 7> rejected_values{
        L"0",
        L"false",
        L"no",
        L"2",
        L"on",
        L"enabled",
        L"1x",
    };
    bool ok = true;
    for (const auto* value : rejected_values)
    {
        ScopedEnvironmentVariable read_cache_value(
            L"APFSACCESS_EXPERIMENTAL_BLOCK_READ_CACHE",
            value);
        apfsaccess::rw::BlockDevice device(image_path.wstring());
        std::vector<std::byte> first;
        std::vector<std::byte> second;
        ok &= Require(device.Read(123, 4096, first), "BlockDevice rejected opt-in first read should succeed");
        ok &= Require(device.Read(123, 4096, second), "BlockDevice rejected opt-in second read should succeed");
        ok &= Require(first == second, "BlockDevice rejected opt-in reads should preserve bytes");
        const auto perf = device.PerformanceJson();
        ok &= Require(
            ExtractNestedUnsignedValue(perf, "readCache", "hits").value_or(1) == 0,
            "BlockDevice rejected opt-in should report zero cache hits");
        ok &= Require(
            ExtractNestedUnsignedValue(perf, "readCache", "bytes").value_or(1) == 0,
            "BlockDevice rejected opt-in should report zero cached bytes");
        ok &= Require(
            ExtractNestedUnsignedValue(perf, "rawRead", "count").value_or(0) == 2,
            "BlockDevice rejected opt-in should perform both reads through raw I/O");
    }
    return ok;
}

bool TestBlockDeviceWriteBatchMissDoesNotReinsertAfterConcurrentWrite(const std::filesystem::path& run_root)
{
    ScopedEnvironmentVariable read_cache_opt_in(
        L"APFSACCESS_EXPERIMENTAL_BLOCK_READ_CACHE",
        L"1");
    ScopedEnvironmentVariable synchronous_batch(
        L"APFSACCESS_DISABLE_ASYNC_BLOCK_IO",
        L"1");
    const auto image_path = run_root / "block_device_write_batch_read_cache_race.bin";
    const auto seed = BuildPatternPayload(64 * 1024, 0x5A);
    {
        std::ofstream out(image_path, std::ios::binary | std::ios::trunc);
        if (!out.good())
        {
            return Require(false, "BlockDevice WriteBatch cache race should create image");
        }
        out.write(reinterpret_cast<const char*>(seed.data()), static_cast<std::streamsize>(seed.size()));
    }

    apfsaccess::rw::BlockDevice device(image_path.wstring());
    constexpr std::uint64_t offset = 123;
    constexpr std::size_t bytes = 4096;
    const auto first_replacement = BuildPatternPayload(64, 0xC4);
    const auto second_replacement = BuildPatternPayload(128, 0xD5);
    std::mutex sync_mutex;
    std::condition_variable sync_cv;
    bool miss_reached = false;
    bool release_miss = false;
    device.SetReadCacheMissHookForTests(
        [&]()
        {
            std::unique_lock lock(sync_mutex);
            miss_reached = true;
            sync_cv.notify_all();
            sync_cv.wait(lock, [&]() { return release_miss; });
        });

    bool read_ok = false;
    std::vector<std::byte> read_result;
    std::thread reader([&]() { read_ok = device.Read(offset, bytes, read_result); });
    bool reached = false;
    {
        std::unique_lock lock(sync_mutex);
        reached = sync_cv.wait_for(lock, std::chrono::seconds(10), [&]() { return miss_reached; });
    }
    if (!reached)
    {
        {
            std::lock_guard lock(sync_mutex);
            release_miss = true;
        }
        sync_cv.notify_all();
        reader.join();
        device.SetReadCacheMissHookForTests({});
        return Require(false, "BlockDevice WriteBatch cache race should reach read miss hook");
    }

    const std::array<apfsaccess::rw::BlockDevice::WriteSpan, 2> writes{
        apfsaccess::rw::BlockDevice::WriteSpan{
            16384,
            std::span<const std::byte>(second_replacement.data(), second_replacement.size())},
        apfsaccess::rw::BlockDevice::WriteSpan{
            offset,
            std::span<const std::byte>(first_replacement.data(), first_replacement.size())},
    };
    const bool write_ok = device.WriteBatch(writes);
    {
        std::lock_guard lock(sync_mutex);
        release_miss = true;
    }
    sync_cv.notify_all();
    reader.join();
    device.SetReadCacheMissHookForTests({});

    std::vector<std::byte> after_write;
    bool ok = true;
    ok &= Require(read_ok, "BlockDevice WriteBatch cache race reader should succeed");
    ok &= Require(write_ok, "BlockDevice WriteBatch cache race writer should succeed");
    ok &= Require(device.Read(offset, bytes, after_write), "BlockDevice WriteBatch cache race reread should succeed");
    if (after_write.size() == bytes)
    {
        std::vector<std::byte> expected(seed.begin() + static_cast<std::ptrdiff_t>(offset),
                                        seed.begin() + static_cast<std::ptrdiff_t>(offset + bytes));
        std::copy(first_replacement.begin(), first_replacement.end(), expected.begin());
        ok &= Require(after_write == expected, "BlockDevice WriteBatch cache race must not return stale bytes");
    }
    std::vector<std::byte> second_after_write;
    ok &= Require(
        device.Read(16384, second_replacement.size(), second_after_write),
        "BlockDevice multi-span cache race second-span read should succeed");
    ok &= Require(
        second_after_write == second_replacement,
        "BlockDevice multi-span cache race should preserve the second span");
    const auto perf = device.PerformanceJson();
    ok &= Require(
        perf.find("\"batchSortCount\":1") != std::string::npos,
        "BlockDevice cache race should exercise the out-of-order multi-span batch path");
    return ok;
}

bool TestBlockDeviceReadCacheHookExceptionRecoversEpoch(const std::filesystem::path& run_root)
{
    ScopedEnvironmentVariable read_cache_opt_in(
        L"APFSACCESS_EXPERIMENTAL_BLOCK_READ_CACHE",
        L"1");
    const auto image_path = run_root / "block_device_read_cache_hook_exception.bin";
    const auto seed = BuildPatternPayload(64 * 1024, 0x61);
    {
        std::ofstream out(image_path, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(seed.data()), static_cast<std::streamsize>(seed.size()));
    }

    apfsaccess::rw::BlockDevice device(image_path.wstring());
    bool throw_once = true;
    device.SetWriteCacheInvalidationHookForTests(
        [&]()
        {
            if (throw_once)
            {
                throw_once = false;
                throw std::runtime_error("test hook failure");
            }
        });
    bool threw = false;
    try
    {
        (void)device.Write(123, BuildPatternPayload(64, 0xD2));
    }
    catch (const std::runtime_error&)
    {
        threw = true;
    }
    device.SetWriteCacheInvalidationHookForTests({});
    constexpr std::uint64_t write_offset = 123;
    constexpr std::size_t read_size = 4096;
    const auto replacement = BuildPatternPayload(64, 0xD2);
    const bool recovered_write = device.Write(123, replacement);
    const auto hits_before_recovery_reads = ExtractNestedUnsignedValue(
        device.PerformanceJson(),
        "readCache",
        "hits").value_or(0);
    std::vector<std::byte> recovered_read;
    std::vector<std::byte> recovered_cached_read;
    const bool recovered_read_ok = device.Read(write_offset, read_size, recovered_read);
    const bool recovered_cached_read_ok = device.Read(write_offset, read_size, recovered_cached_read);
    bool ok = true;
    ok &= Require(threw, "BlockDevice cache hook exception test should observe the injected exception");
    ok &= Require(recovered_write, "BlockDevice cache hook exception should not strand the write epoch");
    ok &= Require(recovered_read_ok, "BlockDevice cache hook exception recovery read should succeed");
    ok &= Require(recovered_cached_read_ok, "BlockDevice cache hook exception recovery cache hit should succeed");
    if (recovered_read.size() == read_size)
    {
        std::vector<std::byte> expected(
            seed.begin() + static_cast<std::ptrdiff_t>(write_offset),
            seed.begin() + static_cast<std::ptrdiff_t>(write_offset + read_size));
        std::copy(replacement.begin(), replacement.end(), expected.begin());
        ok &= Require(recovered_read == expected, "BlockDevice write-hook recovery should return committed bytes");
        ok &= Require(recovered_cached_read == expected, "BlockDevice write-hook recovery cache hit should return committed bytes");
    }
    const auto hits_after_recovery_reads = ExtractNestedUnsignedValue(
        device.PerformanceJson(),
        "readCache",
        "hits").value_or(0);
    ok &= Require(
        hits_after_recovery_reads == hits_before_recovery_reads + 1,
        "BlockDevice write-hook exception recovery should restore even-generation cache admission");

    bool read_hook_threw_once = false;
    device.SetReadCacheMissHookForTests(
        [&]()
        {
            if (!read_hook_threw_once)
            {
                read_hook_threw_once = true;
                throw std::runtime_error("read miss hook failure");
            }
        });
    bool read_hook_threw = false;
    try
    {
        std::vector<std::byte> ignored;
        (void)device.Read(16384, 4096, ignored);
    }
    catch (const std::runtime_error&)
    {
        read_hook_threw = true;
    }
    device.SetReadCacheMissHookForTests({});
    const auto hits_before_read_hook_recovery = ExtractNestedUnsignedValue(
        device.PerformanceJson(),
        "readCache",
        "hits").value_or(0);
    std::vector<std::byte> read_hook_recovery;
    std::vector<std::byte> read_hook_cached;
    ok &= Require(device.Read(16384, 4096, read_hook_recovery), "BlockDevice read-hook recovery read should succeed");
    ok &= Require(device.Read(16384, 4096, read_hook_cached), "BlockDevice read-hook recovery cache hit should succeed");
    ok &= Require(read_hook_threw, "BlockDevice read-miss hook exception should propagate without poisoning cache state");
    ok &= Require(
        read_hook_recovery == read_hook_cached &&
        std::equal(seed.begin() + 16384, seed.begin() + 20480, read_hook_recovery.begin()),
        "BlockDevice read-hook recovery should cache the correct source bytes");
    const auto hits_after_read_hook_recovery = ExtractNestedUnsignedValue(
        device.PerformanceJson(),
        "readCache",
        "hits").value_or(0);
    ok &= Require(
        hits_after_read_hook_recovery == hits_before_read_hook_recovery + 1,
        "BlockDevice read-hook exception recovery should restore cache admission");
    return ok;
}

bool TestBlockDeviceWriteInvalidationHookRunsWithoutProductionLocks(const std::filesystem::path& run_root)
{
    ScopedEnvironmentVariable read_cache_opt_in(
        L"APFSACCESS_EXPERIMENTAL_BLOCK_READ_CACHE",
        L"1");
    const auto image_path = run_root / "block_device_write_hook_reentrant.bin";
    const auto seed = BuildPatternPayload(64 * 1024, 0x69);
    {
        std::ofstream out(image_path, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(seed.data()), static_cast<std::streamsize>(seed.size()));
    }

    apfsaccess::rw::BlockDevice device(image_path.wstring());
    const auto outer_payload = BuildPatternPayload(4096, 0xA4);
    const auto nested_payload = BuildPatternPayload(4096, 0xB5);
    std::mutex sync_mutex;
    std::condition_variable sync_cv;
    bool nested_done = false;
    bool nested_ok = false;
    bool nested_completed_while_hook_active = false;
    std::thread nested_writer;
    device.SetWriteCacheInvalidationHookForTests(
        [&]()
        {
            device.SetWriteCacheInvalidationHookForTests({});
            nested_writer = std::thread(
                [&]()
                {
                    const auto result = device.Write(8192, nested_payload);
                    {
                        std::lock_guard lock(sync_mutex);
                        nested_ok = result;
                        nested_done = true;
                    }
                    sync_cv.notify_all();
                });
            std::unique_lock lock(sync_mutex);
            nested_completed_while_hook_active = sync_cv.wait_for(
                lock,
                std::chrono::seconds(2),
                [&]() { return nested_done; });
        });

    const auto outer_ok = device.Write(0, outer_payload);
    if (nested_writer.joinable())
    {
        nested_writer.join();
    }
    device.SetWriteCacheInvalidationHookForTests({});

    std::vector<std::byte> outer_read;
    std::vector<std::byte> nested_read;
    bool ok = true;
    ok &= Require(outer_ok, "BlockDevice lock-free write hook outer write should succeed");
    ok &= Require(nested_ok, "BlockDevice lock-free write hook nested write should succeed");
    ok &= Require(
        nested_completed_while_hook_active,
        "BlockDevice write invalidation hook must not hold a production write or epoch lock");
    ok &= Require(device.Read(0, outer_payload.size(), outer_read), "BlockDevice lock-free write hook outer read should succeed");
    ok &= Require(device.Read(8192, nested_payload.size(), nested_read), "BlockDevice lock-free write hook nested read should succeed");
    ok &= Require(outer_read == outer_payload, "BlockDevice lock-free write hook should preserve outer bytes");
    ok &= Require(nested_read == nested_payload, "BlockDevice lock-free write hook should preserve nested bytes");
    return ok;
}

bool TestBlockDeviceReadCacheHitIsNotAdmittedDuringWrite(const std::filesystem::path& run_root)
{
    ScopedEnvironmentVariable read_cache_opt_in(
        L"APFSACCESS_EXPERIMENTAL_BLOCK_READ_CACHE",
        L"1");
    const auto image_path = run_root / "block_device_read_cache_hit_during_write.bin";
    const auto seed = BuildPatternPayload(64 * 1024, 0x81);
    {
        std::ofstream out(image_path, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(seed.data()), static_cast<std::streamsize>(seed.size()));
    }

    apfsaccess::rw::BlockDevice device(image_path.wstring());
    constexpr std::uint64_t offset = 123;
    constexpr std::size_t bytes = 4096;
    std::vector<std::byte> primed;
    bool ok = true;
    ok &= Require(device.Read(offset, bytes, primed), "BlockDevice active-write cache test should prime the cache");
    const auto before = device.PerformanceJson();
    const auto hits_before = ExtractNestedUnsignedValue(before, "readCache", "hits").value_or(0);

    std::mutex sync_mutex;
    std::condition_variable sync_cv;
    bool write_started = false;
    bool release_write = false;
    device.SetWriteCacheInvalidationHookForTests(
        [&]()
        {
            std::unique_lock lock(sync_mutex);
            write_started = true;
            sync_cv.notify_all();
            sync_cv.wait(lock, [&]() { return release_write; });
        });

    const auto replacement = BuildPatternPayload(64, 0xF0);
    bool write_ok = false;
    std::thread writer([&]() { write_ok = device.Write(offset, replacement); });
    bool reached = false;
    {
        std::unique_lock lock(sync_mutex);
        reached = sync_cv.wait_for(lock, std::chrono::seconds(10), [&]() { return write_started; });
    }
    if (!reached)
    {
        {
            std::lock_guard lock(sync_mutex);
            release_write = true;
        }
        sync_cv.notify_all();
        writer.join();
        device.SetWriteCacheInvalidationHookForTests({});
        return Require(false, "BlockDevice active-write cache test should reach the write epoch");
    }

    std::vector<std::byte> during_write;
    const bool read_ok = device.Read(offset, bytes, during_write);
    const auto during = device.PerformanceJson();
    const auto hits_during = ExtractNestedUnsignedValue(during, "readCache", "hits").value_or(0);
    {
        std::lock_guard lock(sync_mutex);
        release_write = true;
    }
    sync_cv.notify_all();
    writer.join();
    device.SetWriteCacheInvalidationHookForTests({});

    ok &= Require(read_ok, "BlockDevice active-write cache read should succeed");
    ok &= Require(write_ok, "BlockDevice active-write cache writer should succeed");
    ok &= Require(hits_during == hits_before, "BlockDevice must not admit a cache hit during an active write");
    if (during_write.size() == bytes)
    {
        ok &= Require(
            std::equal(seed.begin() + static_cast<std::ptrdiff_t>(offset),
                       seed.begin() + static_cast<std::ptrdiff_t>(offset + bytes),
                       during_write.begin()),
            "BlockDevice active-write cache read should observe the pre-write bytes");
    }
    return ok;
}

bool TestBlockDeviceReadCacheQuotaIsBounded(const std::filesystem::path& run_root)
{
    ScopedEnvironmentVariable read_cache_opt_in(
        L"APFSACCESS_EXPERIMENTAL_BLOCK_READ_CACHE",
        L"1");
    const auto entry_image_path = run_root / "block_device_read_cache_entry_quota.bin";
    const auto entry_seed = BuildPatternPayload(2 * 1024 * 1024, 0x73);
    {
        std::ofstream out(entry_image_path, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(entry_seed.data()), static_cast<std::streamsize>(entry_seed.size()));
    }

    constexpr std::size_t entry_size = 4096;
    constexpr std::size_t entry_reads = 300;
    constexpr std::uint64_t expected_entry_quota_bytes = 256ull * entry_size;
    apfsaccess::rw::BlockDevice entry_device(entry_image_path.wstring());
    bool ok = true;
    for (std::size_t index = 0; index < entry_reads; ++index)
    {
        std::vector<std::byte> read;
        ok &= Require(
            entry_device.Read(static_cast<std::uint64_t>(index * entry_size), entry_size, read),
            "BlockDevice entry-quota reads should succeed");
    }
    auto entry_perf = entry_device.PerformanceJson();
    ok &= Require(
        ExtractNestedUnsignedValue(entry_perf, "readCache", "bytes").value_or(0) == expected_entry_quota_bytes,
        "BlockDevice entry quota should retain exactly 256 four-KiB entries");
    ok &= Require(
        ExtractNestedUnsignedValue(entry_perf, "readCache", "misses").value_or(0) == entry_reads,
        "BlockDevice entry-quota fill should report every unique read as a miss");
    std::vector<std::byte> evicted_entry;
    ok &= Require(entry_device.Read(0, entry_size, evicted_entry), "BlockDevice entry-quota evicted reread should succeed");
    entry_perf = entry_device.PerformanceJson();
    ok &= Require(
        ExtractNestedUnsignedValue(entry_perf, "readCache", "misses").value_or(0) == entry_reads + 1,
        "BlockDevice entry quota should evict the oldest entry");
    ok &= Require(
        ExtractNestedUnsignedValue(entry_perf, "readCache", "bytes").value_or(0) == expected_entry_quota_bytes,
        "BlockDevice entry quota should preserve exact bytes after eviction and replacement");

    constexpr std::size_t byte_window = 64 * 1024;
    constexpr std::size_t byte_reads = 129;
    constexpr std::uint64_t expected_byte_quota = 8ull * 1024ull * 1024ull;
    const auto byte_image_path = run_root / "block_device_read_cache_byte_quota.bin";
    const auto byte_seed = BuildPatternPayload(byte_reads * byte_window, 0x84);
    {
        std::ofstream out(byte_image_path, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(byte_seed.data()), static_cast<std::streamsize>(byte_seed.size()));
    }
    apfsaccess::rw::BlockDevice byte_device(byte_image_path.wstring());
    for (std::size_t index = 0; index < byte_reads; ++index)
    {
        std::vector<std::byte> read;
        ok &= Require(
            byte_device.Read(static_cast<std::uint64_t>(index * byte_window), byte_window, read),
            "BlockDevice byte-quota reads should succeed");
    }
    auto byte_perf = byte_device.PerformanceJson();
    ok &= Require(
        ExtractNestedUnsignedValue(byte_perf, "readCache", "bytes").value_or(0) == expected_byte_quota,
        "BlockDevice byte quota should retain exactly eight MiB after crossing the limit");
    ok &= Require(
        ExtractNestedUnsignedValue(byte_perf, "readCache", "misses").value_or(0) == byte_reads,
        "BlockDevice byte-quota fill should report every unique read as a miss");
    std::vector<std::byte> evicted_window;
    ok &= Require(byte_device.Read(0, byte_window, evicted_window), "BlockDevice byte-quota evicted reread should succeed");
    byte_perf = byte_device.PerformanceJson();
    ok &= Require(
        ExtractNestedUnsignedValue(byte_perf, "readCache", "misses").value_or(0) == byte_reads + 1,
        "BlockDevice byte quota should evict the oldest 64-KiB window");
    ok &= Require(
        ExtractNestedUnsignedValue(byte_perf, "readCache", "bytes").value_or(0) == expected_byte_quota,
        "BlockDevice byte quota should preserve exact eight-MiB accounting after replacement");
    return ok;
}

bool TestBlockDeviceReadCacheServesContainedRange(const std::filesystem::path& run_root)
{
    ScopedEnvironmentVariable read_cache_opt_in(
        L"APFSACCESS_EXPERIMENTAL_BLOCK_READ_CACHE",
        L"1");
    const auto image_path = run_root / "block_device_read_cache_contained_range.bin";
    const auto seed = BuildPatternPayload(128 * 1024, 0x96);
    {
        std::ofstream out(image_path, std::ios::binary | std::ios::trunc);
        if (!out.good())
        {
            return Require(false, "BlockDevice contained-range cache test should create image");
        }
        out.write(reinterpret_cast<const char*>(seed.data()), static_cast<std::streamsize>(seed.size()));
        if (!out.good())
        {
            return Require(false, "BlockDevice contained-range cache test should seed image");
        }
    }

    apfsaccess::rw::BlockDevice device(image_path.wstring());
    constexpr std::size_t wide_window = 64 * 1024;
    constexpr std::uint64_t narrow_offset = 16 * 1024 + 123;
    constexpr std::size_t narrow_size = 4096;
    std::vector<std::byte> wide_read;
    std::vector<std::byte> narrow_read;
    bool ok = true;
    ok &= Require(device.Read(0, wide_window, wide_read), "BlockDevice contained-range wide read should succeed");
    ok &= Require(device.Read(narrow_offset, narrow_size, narrow_read), "BlockDevice contained-range narrow read should succeed");
    if (wide_read.size() == wide_window)
    {
        ok &= Require(
            std::equal(seed.begin(), seed.begin() + static_cast<std::ptrdiff_t>(wide_window), wide_read.begin()),
            "BlockDevice contained-range wide read should preserve bytes");
    }
    else
    {
        ok &= Require(false, "BlockDevice contained-range wide read should return the requested bytes");
    }
    const auto expected_narrow_begin = seed.begin() + static_cast<std::ptrdiff_t>(narrow_offset);
    if (narrow_read.size() == narrow_size)
    {
        ok &= Require(
            std::equal(
                expected_narrow_begin,
                expected_narrow_begin + static_cast<std::ptrdiff_t>(narrow_size),
                narrow_read.begin()),
            "BlockDevice contained-range narrow read should preserve bytes");
    }
    else
    {
        ok &= Require(false, "BlockDevice contained-range narrow read should return the requested bytes");
    }

    const auto perf = device.PerformanceJson();
    ok &= Require(
        ExtractNestedUnsignedValue(perf, "readCache", "misses").value_or(0) == 1,
        "BlockDevice contained-range read should need only the initial cache miss");
    ok &= Require(
        ExtractNestedUnsignedValue(perf, "readCache", "hits").value_or(0) == 1,
        "BlockDevice contained-range read should serve the narrow request from the wide cache entry");
    ok &= Require(
        ExtractNestedUnsignedValue(perf, "readCache", "containedHits").value_or(0) == 1,
        "BlockDevice contained-range read should report the contained-range hit");
    ok &= Require(
        ExtractNestedUnsignedValue(perf, "rawRead", "count").value_or(0) == 1,
        "BlockDevice contained-range read should issue only one raw read");
    return ok;
}

bool TestBlockDeviceWriteBatchMergesAdjacentWrites(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "block_device_write_batch.bin";
    std::vector<std::byte> seed(64 * 1024, std::byte{0});
    for (std::size_t i = 0; i < seed.size(); ++i)
    {
        seed[i] = static_cast<std::byte>((i * 17u) & 0xffu);
    }
    {
        std::ofstream out(image_path, std::ios::binary | std::ios::trunc);
        if (!out.good())
        {
            return Require(false, "BlockDevice write batch test should create image");
        }
        out.write(reinterpret_cast<const char*>(seed.data()), static_cast<std::streamsize>(seed.size()));
        if (!out.good())
        {
            return Require(false, "BlockDevice write batch test should seed image");
        }
    }

    apfsaccess::rw::BlockDevice device(image_path.wstring());
    bool ok = true;

    const auto first = BuildPatternPayload(4096, 0x21);
    const auto second = BuildPatternPayload(4096, 0x42);
    const auto third = BuildPatternPayload(4096, 0x63);
    const std::array<apfsaccess::rw::BlockDevice::WriteSpan, 3> writes =
    {
        apfsaccess::rw::BlockDevice::WriteSpan{8192, std::span<const std::byte>(first.data(), first.size())},
        apfsaccess::rw::BlockDevice::WriteSpan{12288, std::span<const std::byte>(second.data(), second.size())},
        apfsaccess::rw::BlockDevice::WriteSpan{24576, std::span<const std::byte>(third.data(), third.size())},
    };

    ok &= Require(device.WriteBatch(writes), "BlockDevice write batch should succeed");
    auto perf = device.PerformanceJson();
    ok &= Require(
        perf.find("\"batchSortCount\":0") != std::string::npos,
        "BlockDevice sorted write batch should skip sort/copy");

    std::vector<std::byte> merged_read;
    ok &= Require(device.Read(8192, 8192, merged_read), "BlockDevice write batch adjacent read should succeed");
    if (merged_read.size() == 8192)
    {
        ok &= Require(
            std::equal(first.begin(), first.end(), merged_read.begin()),
            "BlockDevice write batch should write first adjacent segment");
        ok &= Require(
            std::equal(second.begin(), second.end(), merged_read.begin() + 4096),
            "BlockDevice write batch should write second adjacent segment");
    }
    else
    {
        ok &= Require(false, "BlockDevice write batch adjacent read should return full range");
    }

    std::vector<std::byte> disjoint_read;
    ok &= Require(device.Read(24576, third.size(), disjoint_read), "BlockDevice write batch disjoint read should succeed");
    ok &= Require(disjoint_read == third, "BlockDevice write batch should write disjoint segment");

    std::vector<std::byte> untouched_read;
    ok &= Require(device.Read(16384, 4096, untouched_read), "BlockDevice write batch untouched read should succeed");
    if (untouched_read.size() == 4096)
    {
        ok &= Require(
            std::equal(seed.begin() + 16384, seed.begin() + 20480, untouched_read.begin()),
            "BlockDevice write batch should preserve gap between ranges");
    }
    else
    {
        ok &= Require(false, "BlockDevice write batch untouched read should return full block");
    }

    const auto fourth = BuildPatternPayload(4096, 0x84);
    const auto fifth = BuildPatternPayload(4096, 0xA5);
    const std::array<apfsaccess::rw::BlockDevice::WriteSpan, 2> out_of_order_adjacent_writes =
    {
        apfsaccess::rw::BlockDevice::WriteSpan{36864, std::span<const std::byte>(fifth.data(), fifth.size())},
        apfsaccess::rw::BlockDevice::WriteSpan{32768, std::span<const std::byte>(fourth.data(), fourth.size())},
    };

    ok &= Require(
        device.WriteBatch(out_of_order_adjacent_writes),
        "BlockDevice write batch should accept out-of-order adjacent spans");
    perf = device.PerformanceJson();
    ok &= Require(
        perf.find("\"batchSortCount\":1") != std::string::npos,
        "BlockDevice out-of-order non-overlapping write batch should sort once");

    std::vector<std::byte> sorted_merge_read;
    ok &= Require(
        device.Read(32768, 8192, sorted_merge_read),
        "BlockDevice write batch sorted adjacent read should succeed");
    if (sorted_merge_read.size() == 8192)
    {
        ok &= Require(
            std::equal(fourth.begin(), fourth.end(), sorted_merge_read.begin()),
            "BlockDevice write batch should place lower out-of-order span first");
        ok &= Require(
            std::equal(fifth.begin(), fifth.end(), sorted_merge_read.begin() + 4096),
            "BlockDevice write batch should place higher out-of-order span second");
    }
    else
    {
        ok &= Require(false, "BlockDevice write batch sorted adjacent read should return full range");
    }

    const auto overlap_high = BuildPatternPayload(4096, 0x91);
    const auto overlap_low = BuildPatternPayload(4096, 0xB2);
    const std::array<apfsaccess::rw::BlockDevice::WriteSpan, 2> overlapping_writes =
    {
        apfsaccess::rw::BlockDevice::WriteSpan{43008, std::span<const std::byte>(overlap_high.data(), overlap_high.size())},
        apfsaccess::rw::BlockDevice::WriteSpan{40960, std::span<const std::byte>(overlap_low.data(), overlap_low.size())},
    };

    ok &= Require(device.WriteBatch(overlapping_writes), "BlockDevice write batch should accept overlapping spans");
    perf = device.PerformanceJson();
    ok &= Require(
        perf.find("\"batchSortCount\":2") != std::string::npos,
        "BlockDevice overlapping write batch should attempt sort but preserve original ordering");

    std::vector<std::byte> overlap_read;
    ok &= Require(device.Read(40960, 6144, overlap_read), "BlockDevice write batch overlap read should succeed");
    if (overlap_read.size() == 6144)
    {
        ok &= Require(
            std::equal(overlap_low.begin(), overlap_low.end(), overlap_read.begin()),
            "BlockDevice write batch overlap should preserve later lower-offset write");
        ok &= Require(
            std::equal(overlap_high.begin() + 2048, overlap_high.end(), overlap_read.begin() + 4096),
            "BlockDevice write batch overlap should preserve original-order high-offset tail");
    }
    else
    {
        ok &= Require(false, "BlockDevice write batch overlap read should return full range");
    }

    ok &= Require(device.Flush(), "BlockDevice write batch flush should succeed");
    return ok;
}

bool TestBlockDeviceWriteBatchGroupsNearbyUnalignedSpans(const std::filesystem::path& run_root)
{
    ScopedEnvironmentVariable disable_async(
        L"APFSACCESS_DISABLE_ASYNC_BLOCK_IO",
        L"1");

    const auto image_path = run_root / "block_device_nearby_unaligned_group.bin";
    const auto seed = BuildPatternPayload(128 * 1024, 0x19);
    {
        std::ofstream out(image_path, std::ios::binary | std::ios::trunc);
        if (!out.good())
        {
            return Require(false, "BlockDevice RMW group test should create image");
        }
        out.write(reinterpret_cast<const char*>(seed.data()), static_cast<std::streamsize>(seed.size()));
        if (!out.good())
        {
            return Require(false, "BlockDevice RMW group test should seed image");
        }
    }

    apfsaccess::rw::BlockDevice device(image_path.wstring());
    const auto first = BuildPatternPayload(64, 0x31);
    const auto second = BuildPatternPayload(64, 0x52);
    const auto third = BuildPatternPayload(64, 0x73);
    const std::array<apfsaccess::rw::BlockDevice::WriteSpan, 3> nearby_writes =
    {
        apfsaccess::rw::BlockDevice::WriteSpan{123, std::span<const std::byte>(first.data(), first.size())},
        apfsaccess::rw::BlockDevice::WriteSpan{4096 + 77, std::span<const std::byte>(second.data(), second.size())},
        apfsaccess::rw::BlockDevice::WriteSpan{8192 + 33, std::span<const std::byte>(third.data(), third.size())},
    };

    bool ok = true;
    ok &= Require(
        device.WriteBatch(nearby_writes),
        "BlockDevice nearby unaligned write batch should succeed");
    auto perf = device.PerformanceJson();
    ok &= Require(
        perf.find("\"rmwGroupWrite\":{\"count\":1") != std::string::npos,
        "BlockDevice nearby unaligned spans should use one bounded RMW group");

    std::vector<std::byte> expected(seed.begin(), seed.begin() + 12288);
    std::copy(first.begin(), first.end(), expected.begin() + 123);
    std::copy(second.begin(), second.end(), expected.begin() + 4096 + 77);
    std::copy(third.begin(), third.end(), expected.begin() + 8192 + 33);
    std::vector<std::byte> actual;
    ok &= Require(
        device.Read(0, expected.size(), actual),
        "BlockDevice nearby unaligned RMW group readback should succeed");
    ok &= Require(
        actual == expected,
        "BlockDevice nearby unaligned RMW group should preserve all untouched bytes");

    const auto overlap_first = BuildPatternPayload(512, 0x84);
    const auto overlap_second = BuildPatternPayload(500, 0xA5);
    const std::array<apfsaccess::rw::BlockDevice::WriteSpan, 2> overlapping_writes =
    {
        apfsaccess::rw::BlockDevice::WriteSpan{24876, std::span<const std::byte>(overlap_first.data(), overlap_first.size())},
        apfsaccess::rw::BlockDevice::WriteSpan{24676, std::span<const std::byte>(overlap_second.data(), overlap_second.size())},
    };
    ok &= Require(
        device.WriteBatch(overlapping_writes),
        "BlockDevice overlapping unaligned RMW group should succeed");
    perf = device.PerformanceJson();
    ok &= Require(
        perf.find("\"rmwGroupWrite\":{\"count\":2") != std::string::npos,
        "BlockDevice overlapping unaligned spans should use a second RMW group");

    expected.assign(seed.begin() + 24576, seed.begin() + 28672);
    std::copy(
        overlap_first.begin(),
        overlap_first.end(),
        expected.begin() + static_cast<std::ptrdiff_t>(24876 - 24576));
    std::copy(
        overlap_second.begin(),
        overlap_second.end(),
        expected.begin() + static_cast<std::ptrdiff_t>(24676 - 24576));
    actual.clear();
    ok &= Require(
        device.Read(24576, expected.size(), actual),
        "BlockDevice overlapping unaligned RMW group readback should succeed");
    ok &= Require(
        actual == expected,
        "BlockDevice overlapping RMW group should preserve original write ordering");
    ok &= Require(device.Flush(), "BlockDevice RMW group flush should succeed");
    return ok;
}

bool TestBlockDeviceWriteBatchAvoidsLargeMergedBuffer(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "block_device_large_batch.bin";
    const std::size_t large_span_bytes = 2 * 1024 * 1024;
    std::vector<std::byte> seed(6 * 1024 * 1024, std::byte{0});
    {
        std::ofstream out(image_path, std::ios::binary | std::ios::trunc);
        if (!out.good())
        {
            return Require(false, "BlockDevice large batch test should create image");
        }
        out.write(reinterpret_cast<const char*>(seed.data()), static_cast<std::streamsize>(seed.size()));
        if (!out.good())
        {
            return Require(false, "BlockDevice large batch test should seed image");
        }
    }

    apfsaccess::rw::BlockDevice device(image_path.wstring());
    const auto first = BuildPatternPayload(large_span_bytes, 0x35);
    const auto second = BuildPatternPayload(large_span_bytes, 0x6A);
    const std::array<apfsaccess::rw::BlockDevice::WriteSpan, 2> writes =
    {
        apfsaccess::rw::BlockDevice::WriteSpan{0, std::span<const std::byte>(first.data(), first.size())},
        apfsaccess::rw::BlockDevice::WriteSpan{static_cast<std::uint64_t>(first.size()), std::span<const std::byte>(second.data(), second.size())},
    };

    bool ok = true;
    ok &= Require(device.WriteBatch(writes), "BlockDevice large adjacent write batch should succeed");

    std::vector<std::byte> read;
    ok &= Require(device.Read(0, first.size() + second.size(), read), "BlockDevice large adjacent read should succeed");
    if (read.size() == first.size() + second.size())
    {
        ok &= Require(std::equal(first.begin(), first.end(), read.begin()), "BlockDevice large batch should write first span");
        ok &= Require(
            std::equal(second.begin(), second.end(), read.begin() + static_cast<std::ptrdiff_t>(first.size())),
            "BlockDevice large batch should write second span");
    }
    else
    {
        ok &= Require(false, "BlockDevice large adjacent read should return full range");
    }

    const auto perf = device.PerformanceJson();
    ok &= Require(
        perf.find("\"mergedBatchWrite\":{\"count\":0") != std::string::npos,
        "BlockDevice large adjacent batch should avoid allocating a merged write buffer");
    return ok;
}

bool TestBlockDeviceWriteBatchMergesSmallAdjacentRunInBoundedChunks(const std::filesystem::path& run_root)
{
    ScopedEnvironmentVariable disable_async(
        L"APFSACCESS_DISABLE_ASYNC_BLOCK_IO",
        L"1");

    const auto image_path = run_root / "block_device_small_run_batch.bin";
    constexpr std::size_t span_count = 300;
    constexpr std::size_t span_bytes = 4096;
    constexpr std::size_t total_bytes = span_count * span_bytes;
    std::vector<std::byte> seed(total_bytes + span_bytes, std::byte{0});
    {
        std::ofstream out(image_path, std::ios::binary | std::ios::trunc);
        if (!out.good())
        {
            return Require(false, "BlockDevice small-run batch test should create image");
        }
        out.write(reinterpret_cast<const char*>(seed.data()), static_cast<std::streamsize>(seed.size()));
        if (!out.good())
        {
            return Require(false, "BlockDevice small-run batch test should seed image");
        }
    }

    apfsaccess::rw::BlockDevice device(image_path.wstring());
    std::vector<std::vector<std::byte>> payloads;
    payloads.reserve(span_count);
    std::vector<apfsaccess::rw::BlockDevice::WriteSpan> writes;
    writes.reserve(span_count);
    for (std::size_t index = 0; index < span_count; ++index)
    {
        payloads.push_back(BuildPatternPayload(span_bytes, static_cast<unsigned char>(index)));
        writes.push_back(apfsaccess::rw::BlockDevice::WriteSpan{
            static_cast<std::uint64_t>(index * span_bytes),
            std::span<const std::byte>(payloads.back().data(), payloads.back().size()),
        });
    }

    bool ok = true;
    ok &= Require(device.WriteBatch(writes), "BlockDevice small adjacent write run should succeed");
    ok &= Require(device.WriteBatch(writes), "BlockDevice repeated small adjacent write run should succeed");

    std::vector<std::byte> read;
    ok &= Require(device.Read(0, total_bytes, read), "BlockDevice small adjacent run read should succeed");
    if (read.size() == total_bytes)
    {
        for (std::size_t index = 0; index < span_count; ++index)
        {
            ok &= Require(
                std::equal(
                    payloads[index].begin(),
                    payloads[index].end(),
                    read.begin() + static_cast<std::ptrdiff_t>(index * span_bytes)),
                "BlockDevice small adjacent run should preserve span payload order");
        }
    }
    else
    {
        ok &= Require(false, "BlockDevice small adjacent run read should return full range");
    }

    const auto perf = device.PerformanceJson();
    ok &= Require(
        perf.find("\"mergedBatchWrite\":{\"count\":4,\"bytes\":2457600") != std::string::npos,
        "BlockDevice repeated small adjacent run should merge into bounded write chunks");
    ok &= Require(
        perf.find("\"mergedBatchDirectFill\":{\"count\":4,\"bytes\":2457600") != std::string::npos,
        "BlockDevice repeated small adjacent run should direct-fill merged write chunks");
    ok &= Require(
        perf.find("\"mergedBatchScratch\":{\"resizeCount\":1,\"maxBytes\":1048576") != std::string::npos,
        "BlockDevice repeated small adjacent run should reuse merged write scratch");
    return ok;
}

bool TestBlockDeviceWriteBatchUsesContiguousMergeView(const std::filesystem::path& run_root)
{
    ScopedEnvironmentVariable disable_async(
        L"APFSACCESS_DISABLE_ASYNC_BLOCK_IO",
        L"1");

    const auto image_path = run_root / "block_device_contiguous_merge_batch.bin";
    constexpr std::size_t span_count = 4;
    constexpr std::size_t span_bytes = 4096;
    constexpr std::size_t total_bytes = span_count * span_bytes;
    std::vector<std::byte> seed(total_bytes, std::byte{0});
    {
        std::ofstream out(image_path, std::ios::binary | std::ios::trunc);
        if (!out.good())
        {
            return Require(false, "BlockDevice contiguous merge test should create image");
        }
        out.write(reinterpret_cast<const char*>(seed.data()), static_cast<std::streamsize>(seed.size()));
        if (!out.good())
        {
            return Require(false, "BlockDevice contiguous merge test should seed image");
        }
    }

    apfsaccess::rw::BlockDevice device(image_path.wstring());
    auto payload = BuildPatternPayload(total_bytes, 0x77);
    std::vector<apfsaccess::rw::BlockDevice::WriteSpan> writes;
    writes.reserve(span_count);
    for (std::size_t index = 0; index < span_count; ++index)
    {
        const auto offset = index * span_bytes;
        writes.push_back(apfsaccess::rw::BlockDevice::WriteSpan{
            static_cast<std::uint64_t>(offset),
            std::span<const std::byte>(
                payload.data() + static_cast<std::ptrdiff_t>(offset),
                span_bytes),
            &payload,
        });
    }

    bool ok = true;
    ok &= Require(device.WriteBatch(writes), "BlockDevice contiguous merge batch should succeed");

    std::vector<std::byte> read;
    ok &= Require(device.Read(0, total_bytes, read), "BlockDevice contiguous merge read should succeed");
    ok &= Require(read == payload, "BlockDevice contiguous merge should preserve payload bytes");

    const auto perf = device.PerformanceJson();
    ok &= Require(
        perf.find("\"contiguousBatchWrite\":{\"count\":1,\"bytes\":16384") != std::string::npos,
        "BlockDevice contiguous merge should write through one no-copy view");
    ok &= Require(
        perf.find("\"mergedBatchWrite\":{\"count\":0") != std::string::npos,
        "BlockDevice contiguous merge should avoid copied merge buffer");
    return ok;
}

bool TestBlockDeviceWriteBatchAsyncWritesAlignedDisjointSpans(const std::filesystem::path& run_root)
{
    ScopedEnvironmentVariable enable_experimental_async(
        L"APFSACCESS_EXPERIMENTAL_ASYNC_BLOCK_IO",
        L"1");
    ScopedEnvironmentVariable allow_async(
        L"APFSACCESS_DISABLE_ASYNC_BLOCK_IO",
        L"");
    ScopedEnvironmentVariable async_depth(
        L"APFSACCESS_ASYNC_BLOCK_IO_DEPTH",
        L"4");

    const auto image_path = run_root / "block_device_async_batch.bin";
    constexpr std::size_t span_count = 8;
    constexpr std::size_t span_bytes = 16 * 1024;
    constexpr std::size_t stride_bytes = 32 * 1024;
    std::vector<std::byte> seed(span_count * stride_bytes, std::byte{0});
    {
        std::ofstream out(image_path, std::ios::binary | std::ios::trunc);
        if (!out.good())
        {
            return Require(false, "BlockDevice async batch test should create image");
        }
        out.write(reinterpret_cast<const char*>(seed.data()), static_cast<std::streamsize>(seed.size()));
        if (!out.good())
        {
            return Require(false, "BlockDevice async batch test should seed image");
        }
    }

    apfsaccess::rw::BlockDevice device(image_path.wstring());
    std::vector<std::vector<std::byte>> payloads;
    payloads.reserve(span_count);
    std::vector<apfsaccess::rw::BlockDevice::WriteSpan> writes;
    writes.reserve(span_count);
    for (std::size_t index = 0; index < span_count; ++index)
    {
        payloads.push_back(BuildPatternPayload(span_bytes, static_cast<unsigned char>(0x30 + index)));
        writes.push_back(apfsaccess::rw::BlockDevice::WriteSpan{
            static_cast<std::uint64_t>(index * stride_bytes),
            std::span<const std::byte>(payloads.back().data(), payloads.back().size()),
        });
    }

    bool ok = true;
    ok &= Require(device.WriteBatch(writes), "BlockDevice async write batch should succeed");
    ok &= Require(device.Flush(), "BlockDevice async write batch flush should succeed");

    for (std::size_t index = 0; index < span_count; ++index)
    {
        std::vector<std::byte> read;
        ok &= Require(
            device.Read(static_cast<std::uint64_t>(index * stride_bytes), span_bytes, read),
            "BlockDevice async write batch read should succeed");
        ok &= Require(read == payloads[index], "BlockDevice async write batch should preserve each span payload");

        std::vector<std::byte> gap_read;
        ok &= Require(
            device.Read(static_cast<std::uint64_t>(index * stride_bytes + span_bytes), span_bytes, gap_read),
            "BlockDevice async write batch gap read should succeed");
        ok &= Require(
            std::all_of(gap_read.begin(), gap_read.end(), [](std::byte value) { return value == std::byte{0}; }),
            "BlockDevice async write batch should preserve gaps between spans");
    }

    const auto perf = device.PerformanceJson();
    ok &= Require(
        perf.find("\"asyncBatchWrite\":{\"count\":1") != std::string::npos,
        "BlockDevice async write batch should report one async batch");
    ok &= Require(
        perf.find("\"asyncMaxQueueDepth\":4") != std::string::npos,
        "BlockDevice async write batch should report the configured queue depth");
    ok &= Require(
        perf.find("\"asyncEventCreateCount\":4") != std::string::npos,
        "BlockDevice async write batch should create one reusable event per queue slot");
    ok &= Require(
        perf.find("\"asyncEventPoolMaxDepth\":4") != std::string::npos,
        "BlockDevice async write batch should report the reusable event pool depth");
    ok &= Require(
        perf.find("\"asyncRequestStackWindows\":2") != std::string::npos,
        "BlockDevice async write batch should use bounded stack request windows");
    return ok;
}

bool TestBlockDeviceWriteBatchAsyncReusesMergedScratch(const std::filesystem::path& run_root)
{
    ScopedEnvironmentVariable enable_experimental_async(
        L"APFSACCESS_EXPERIMENTAL_ASYNC_BLOCK_IO",
        L"1");
    ScopedEnvironmentVariable allow_async(
        L"APFSACCESS_DISABLE_ASYNC_BLOCK_IO",
        L"");
    ScopedEnvironmentVariable async_depth(
        L"APFSACCESS_ASYNC_BLOCK_IO_DEPTH",
        L"4");

    const auto image_path = run_root / "block_device_async_merged_scratch.bin";
    constexpr std::size_t group_count = 2;
    constexpr std::size_t spans_per_group = 4;
    constexpr std::size_t span_bytes = 4096;
    constexpr std::size_t group_bytes = spans_per_group * span_bytes;
    constexpr std::size_t group_stride = 32 * 1024;
    constexpr std::size_t image_bytes = group_count * group_stride;
    std::vector<std::byte> seed(image_bytes, std::byte{0});
    {
        std::ofstream out(image_path, std::ios::binary | std::ios::trunc);
        if (!out.good())
        {
            return Require(false, "BlockDevice async merged scratch test should create image");
        }
        out.write(reinterpret_cast<const char*>(seed.data()), static_cast<std::streamsize>(seed.size()));
        if (!out.good())
        {
            return Require(false, "BlockDevice async merged scratch test should seed image");
        }
    }

    apfsaccess::rw::BlockDevice device(image_path.wstring());
    std::vector<std::vector<std::byte>> payloads;
    payloads.reserve(group_count * spans_per_group);
    std::vector<apfsaccess::rw::BlockDevice::WriteSpan> writes;
    writes.reserve(group_count * spans_per_group);
    for (std::size_t group = 0; group < group_count; ++group)
    {
        const auto group_offset = group * group_stride;
        for (std::size_t span = 0; span < spans_per_group; ++span)
        {
            payloads.push_back(BuildPatternPayload(
                span_bytes,
                static_cast<unsigned char>(0x40 + group * spans_per_group + span)));
            writes.push_back(apfsaccess::rw::BlockDevice::WriteSpan{
                static_cast<std::uint64_t>(group_offset + span * span_bytes),
                std::span<const std::byte>(payloads.back().data(), payloads.back().size()),
            });
        }
    }

    const auto verify_groups = [&]() -> bool
    {
        bool result = true;
        for (std::size_t group = 0; group < group_count; ++group)
        {
            const auto group_offset = group * group_stride;
            std::vector<std::byte> read;
            result &= Require(
                device.Read(group_offset, group_bytes, read),
                "BlockDevice async merged scratch group read should succeed");
            for (std::size_t span = 0; span < spans_per_group && read.size() == group_bytes; ++span)
            {
                const auto payload_index = group * spans_per_group + span;
                result &= Require(
                    std::equal(
                        payloads[payload_index].begin(),
                        payloads[payload_index].end(),
                        read.begin() + static_cast<std::ptrdiff_t>(span * span_bytes)),
                    "BlockDevice async merged scratch should preserve group payload order");
            }
        }
        return result;
    };

    bool ok = true;
    ok &= Require(device.WriteBatch(writes), "BlockDevice async merged scratch batch should succeed");
    ok &= verify_groups();
    ok &= Require(device.WriteBatch(writes), "BlockDevice repeated async merged scratch batch should succeed");
    ok &= Require(device.Flush(), "BlockDevice async merged scratch flush should succeed");
    ok &= verify_groups();

    const auto perf = device.PerformanceJson();
    ok &= Require(
        perf.find("\"asyncBatchWrite\":{\"count\":2") != std::string::npos,
        "BlockDevice async merged scratch should use the async batch path twice");
    ok &= Require(
        perf.find("\"mergedBatchDirectFill\":{\"count\":4,\"bytes\":65536") != std::string::npos,
        "BlockDevice async merged scratch should copy both groups per batch");
    ok &= Require(
        perf.find("\"mergedBatchScratch\":{\"resizeCount\":2,\"maxBytes\":32768") != std::string::npos,
        "BlockDevice async merged scratch should reuse the existing bounded scratch");
    return ok;
}

bool TestBlockDeviceWriteBatchUsesAsyncForAlignedDefaultBatch(const std::filesystem::path& run_root)
{
    ScopedEnvironmentVariable keep_experimental_async_disabled(
        L"APFSACCESS_EXPERIMENTAL_ASYNC_BLOCK_IO",
        L"");
    ScopedEnvironmentVariable allow_async(
        L"APFSACCESS_DISABLE_ASYNC_BLOCK_IO",
        L"");
    ScopedEnvironmentVariable async_depth(
        L"APFSACCESS_ASYNC_BLOCK_IO_DEPTH",
        L"4");

    const auto image_path = run_root / "block_device_async_default.bin";
    constexpr std::size_t span_count = 8;
    constexpr std::size_t span_bytes = 16 * 1024;
    constexpr std::size_t stride_bytes = 32 * 1024;
    std::vector<std::byte> seed(span_count * stride_bytes, std::byte{0});
    {
        std::ofstream out(image_path, std::ios::binary | std::ios::trunc);
        if (!out.good())
        {
            return Require(false, "BlockDevice default async test should create image");
        }
        out.write(reinterpret_cast<const char*>(seed.data()), static_cast<std::streamsize>(seed.size()));
        if (!out.good())
        {
            return Require(false, "BlockDevice default async test should seed image");
        }
    }

    apfsaccess::rw::BlockDevice device(image_path.wstring());
    std::vector<std::vector<std::byte>> payloads;
    payloads.reserve(span_count);
    std::vector<apfsaccess::rw::BlockDevice::WriteSpan> writes;
    writes.reserve(span_count);
    for (std::size_t index = 0; index < span_count; ++index)
    {
        payloads.push_back(BuildPatternPayload(span_bytes, static_cast<unsigned char>(0x50 + index)));
        writes.push_back(apfsaccess::rw::BlockDevice::WriteSpan{
            static_cast<std::uint64_t>(index * stride_bytes),
            std::span<const std::byte>(payloads.back().data(), payloads.back().size()),
        });
    }

    bool ok = true;
    ok &= Require(device.WriteBatch(writes), "BlockDevice default write batch should succeed");
    ok &= Require(device.Flush(), "BlockDevice default write batch flush should succeed");

    for (std::size_t index = 0; index < span_count; ++index)
    {
        std::vector<std::byte> read;
        ok &= Require(
            device.Read(static_cast<std::uint64_t>(index * stride_bytes), span_bytes, read),
            "BlockDevice default write batch read should succeed");
        ok &= Require(read == payloads[index], "BlockDevice default write batch should preserve each span payload");
    }

    const auto perf = device.PerformanceJson();
    ok &= Require(
        perf.find("\"asyncBatchWrite\":{\"count\":1") != std::string::npos,
        "BlockDevice aligned default write batch should use async raw I/O");
    ok &= Require(
        perf.find("\"asyncMaxQueueDepth\":4") != std::string::npos,
        "BlockDevice aligned default write batch should report the configured queue depth");
    ok &= Require(
        perf.find("\"asyncEventCreateCount\":4") != std::string::npos,
        "BlockDevice aligned default write batch should create one reusable event per queue slot");
    ok &= Require(
        perf.find("\"asyncRequestStackWindows\":2") != std::string::npos,
        "BlockDevice aligned default write batch should use bounded stack request windows");
    return ok;
}

bool TestBlockDeviceWriteBatchAsyncWritesLargeAdjacentSpansDirectly(const std::filesystem::path& run_root)
{
    ScopedEnvironmentVariable allow_async(
        L"APFSACCESS_DISABLE_ASYNC_BLOCK_IO",
        L"");
    ScopedEnvironmentVariable async_depth(
        L"APFSACCESS_ASYNC_BLOCK_IO_DEPTH",
        L"4");

    const auto image_path = run_root / "block_device_async_direct_adjacent.bin";
    constexpr std::size_t span_count = 4;
    constexpr std::size_t span_bytes = 256 * 1024;
    constexpr std::size_t total_bytes = span_count * span_bytes;
    std::vector<std::byte> seed(total_bytes, std::byte{0});
    {
        std::ofstream out(image_path, std::ios::binary | std::ios::trunc);
        if (!out.good())
        {
            return Require(false, "BlockDevice direct-adjacent async test should create image");
        }
        out.write(reinterpret_cast<const char*>(seed.data()), static_cast<std::streamsize>(seed.size()));
        if (!out.good())
        {
            return Require(false, "BlockDevice direct-adjacent async test should seed image");
        }
    }

    apfsaccess::rw::BlockDevice device(image_path.wstring());
    std::vector<std::vector<std::byte>> payloads;
    payloads.reserve(span_count);
    std::vector<apfsaccess::rw::BlockDevice::WriteSpan> writes;
    writes.reserve(span_count);
    for (std::size_t index = 0; index < span_count; ++index)
    {
        payloads.push_back(BuildPatternPayload(span_bytes, static_cast<unsigned char>(0x80 + index)));
        writes.push_back(apfsaccess::rw::BlockDevice::WriteSpan{
            static_cast<std::uint64_t>(index * span_bytes),
            std::span<const std::byte>(payloads.back().data(), payloads.back().size()),
        });
    }

    bool ok = true;
    ok &= Require(device.WriteBatch(writes), "BlockDevice direct-adjacent async write batch should succeed");
    ok &= Require(device.Flush(), "BlockDevice direct-adjacent async flush should succeed");

    for (std::size_t index = 0; index < span_count; ++index)
    {
        std::vector<std::byte> read;
        ok &= Require(
            device.Read(static_cast<std::uint64_t>(index * span_bytes), span_bytes, read),
            "BlockDevice direct-adjacent async read should succeed");
        ok &= Require(read == payloads[index], "BlockDevice direct-adjacent async should preserve each span payload");
    }

    const auto perf = device.PerformanceJson();
    ok &= Require(
        perf.find("\"asyncBatchWrite\":{\"count\":1") != std::string::npos,
        "BlockDevice direct-adjacent write batch should use async raw I/O");
    ok &= Require(
        perf.find("\"mergedBatchDirectFill\":{\"count\":0") != std::string::npos,
        "BlockDevice direct-adjacent async path should avoid copied merge buffers");
    ok &= Require(
        perf.find("\"asyncDirectAdjacentSpans\":{\"count\":4,\"bytes\":1048576") != std::string::npos,
        "BlockDevice direct-adjacent async path should report direct adjacent spans");
    return ok;
}

bool TestBlockDeviceWriteBatchDisableSwitchKeepsSynchronousBatch(const std::filesystem::path& run_root)
{
    ScopedEnvironmentVariable keep_experimental_async_disabled(
        L"APFSACCESS_EXPERIMENTAL_ASYNC_BLOCK_IO",
        L"");
    ScopedEnvironmentVariable disable_async(
        L"APFSACCESS_DISABLE_ASYNC_BLOCK_IO",
        L"1");
    ScopedEnvironmentVariable async_depth(
        L"APFSACCESS_ASYNC_BLOCK_IO_DEPTH",
        L"4");

    const auto image_path = run_root / "block_device_async_disabled.bin";
    constexpr std::size_t span_count = 4;
    constexpr std::size_t span_bytes = 16 * 1024;
    constexpr std::size_t stride_bytes = 32 * 1024;
    std::vector<std::byte> seed(span_count * stride_bytes, std::byte{0});
    {
        std::ofstream out(image_path, std::ios::binary | std::ios::trunc);
        if (!out.good())
        {
            return Require(false, "BlockDevice async disable-switch test should create image");
        }
        out.write(reinterpret_cast<const char*>(seed.data()), static_cast<std::streamsize>(seed.size()));
        if (!out.good())
        {
            return Require(false, "BlockDevice async disable-switch test should seed image");
        }
    }

    apfsaccess::rw::BlockDevice device(image_path.wstring());
    std::vector<std::vector<std::byte>> payloads;
    payloads.reserve(span_count);
    std::vector<apfsaccess::rw::BlockDevice::WriteSpan> writes;
    writes.reserve(span_count);
    for (std::size_t index = 0; index < span_count; ++index)
    {
        payloads.push_back(BuildPatternPayload(span_bytes, static_cast<unsigned char>(0x50 + index)));
        writes.push_back(apfsaccess::rw::BlockDevice::WriteSpan{
            static_cast<std::uint64_t>(index * stride_bytes),
            std::span<const std::byte>(payloads.back().data(), payloads.back().size()),
        });
    }

    bool ok = true;
    ok &= Require(device.WriteBatch(writes), "BlockDevice disabled async write batch should succeed");
    ok &= Require(device.Flush(), "BlockDevice disabled async write batch flush should succeed");

    for (std::size_t index = 0; index < span_count; ++index)
    {
        std::vector<std::byte> read;
        ok &= Require(
            device.Read(static_cast<std::uint64_t>(index * stride_bytes), span_bytes, read),
            "BlockDevice disabled async write batch read should succeed");
        ok &= Require(read == payloads[index], "BlockDevice disabled async write batch should preserve each span payload");
    }

    const auto perf = device.PerformanceJson();
    ok &= Require(
        perf.find("\"asyncBatchWrite\":{\"count\":0") != std::string::npos,
        "BlockDevice async disable switch should keep default batch synchronous");
    ok &= Require(
        perf.find("\"asyncMaxQueueDepth\":0") != std::string::npos,
        "BlockDevice async disable switch should report no async queue use");
    ok &= Require(
        perf.find("\"asyncEventCreateCount\":0") != std::string::npos,
        "BlockDevice async disable switch should not create events");
    ok &= Require(
        perf.find("\"asyncRequestStackWindows\":0") != std::string::npos,
        "BlockDevice async disable switch should not use stack request windows");
    return ok;
}

bool TestBlockDeviceWriteBatchAsyncSplitsSingleLargeSpan(const std::filesystem::path& run_root)
{
    ScopedEnvironmentVariable enable_experimental_async(
        L"APFSACCESS_EXPERIMENTAL_ASYNC_BLOCK_IO",
        L"1");
    ScopedEnvironmentVariable allow_async(
        L"APFSACCESS_DISABLE_ASYNC_BLOCK_IO",
        L"");
    ScopedEnvironmentVariable async_depth(
        L"APFSACCESS_ASYNC_BLOCK_IO_DEPTH",
        L"4");

    const auto image_path = run_root / "block_device_async_single_large.bin";
    constexpr std::size_t payload_bytes = 8 * 1024 * 1024;
    std::vector<std::byte> seed(payload_bytes, std::byte{0});
    {
        std::ofstream out(image_path, std::ios::binary | std::ios::trunc);
        if (!out.good())
        {
            return Require(false, "BlockDevice async single-large test should create image");
        }
        out.write(reinterpret_cast<const char*>(seed.data()), static_cast<std::streamsize>(seed.size()));
        if (!out.good())
        {
            return Require(false, "BlockDevice async single-large test should seed image");
        }
    }

    apfsaccess::rw::BlockDevice device(image_path.wstring());
    const auto payload = BuildPatternPayload(payload_bytes, 0x72);
    const std::array<apfsaccess::rw::BlockDevice::WriteSpan, 1> writes =
    {
        apfsaccess::rw::BlockDevice::WriteSpan{0, std::span<const std::byte>(payload.data(), payload.size())},
    };

    bool ok = true;
    ok &= Require(device.WriteBatch(writes), "BlockDevice async single-large write batch should succeed");
    ok &= Require(device.Flush(), "BlockDevice async single-large flush should succeed");
    ok &= Require(device.WriteBatch(writes), "BlockDevice second async single-large write batch should succeed");
    ok &= Require(device.Flush(), "BlockDevice second async single-large flush should succeed");

    std::vector<std::byte> read;
    ok &= Require(device.Read(0, payload.size(), read), "BlockDevice async single-large read should succeed");
    ok &= Require(read == payload, "BlockDevice async single-large should preserve payload bytes");

    const auto perf = device.PerformanceJson();
    ok &= Require(
        perf.find("\"asyncBatchWrite\":{\"count\":2") != std::string::npos,
        "BlockDevice async single-large write should report both async batches");
    ok &= Require(
        perf.find("\"asyncMaxQueueDepth\":4") != std::string::npos,
        "BlockDevice async single-large write should report the configured queue depth");
    ok &= Require(
        perf.find("\"asyncEventCreateCount\":4") != std::string::npos,
        "BlockDevice repeated async single-large writes should reuse the first event pool");
    ok &= Require(
        perf.find("\"asyncEventPoolMaxDepth\":4") != std::string::npos,
        "BlockDevice repeated async single-large writes should keep the event pool bounded");
    ok &= Require(
        perf.find("\"asyncRequestStackWindows\":2") != std::string::npos,
        "BlockDevice repeated async single-large writes should use larger direct chunks");
    return ok;
}

bool TestBlockDeviceAsyncFailureStopsLaterWrites(const std::filesystem::path& run_root)
{
    ScopedEnvironmentVariable allow_async(
        L"APFSACCESS_DISABLE_ASYNC_BLOCK_IO",
        L"");
    ScopedEnvironmentVariable async_depth(
        L"APFSACCESS_ASYNC_BLOCK_IO_DEPTH",
        L"2");
    ScopedEnvironmentVariable fail_after_first_issue(
        L"APFSACCESS_RW_FAULT_ASYNC_BATCH_AFTER_ISSUES",
        L"1");

    const auto image_path = run_root / "block_device_async_partial_failure.bin";
    constexpr std::size_t span_count = 4;
    constexpr std::size_t span_bytes = 16 * 1024;
    constexpr std::size_t stride_bytes = 32 * 1024;
    std::vector<std::byte> seed(span_count * stride_bytes, std::byte{0});
    {
        std::ofstream out(image_path, std::ios::binary | std::ios::trunc);
        if (!out.good())
        {
            return Require(false, "BlockDevice async failure test should create image");
        }
        out.write(reinterpret_cast<const char*>(seed.data()), static_cast<std::streamsize>(seed.size()));
        if (!out.good())
        {
            return Require(false, "BlockDevice async failure test should seed image");
        }
    }

    apfsaccess::rw::BlockDevice device(image_path.wstring());
    std::vector<std::vector<std::byte>> payloads;
    payloads.reserve(span_count);
    std::vector<apfsaccess::rw::BlockDevice::WriteSpan> writes;
    writes.reserve(span_count);
    for (std::size_t index = 0; index < span_count; ++index)
    {
        payloads.push_back(BuildPatternPayload(span_bytes, static_cast<unsigned char>(0x90 + index)));
        writes.push_back(apfsaccess::rw::BlockDevice::WriteSpan{
            static_cast<std::uint64_t>(index * stride_bytes),
            std::span<const std::byte>(payloads.back().data(), payloads.back().size()),
        });
    }

    bool ok = true;
    ok &= Require(!device.WriteBatch(writes), "BlockDevice async partial issue should report failure");
    ok &= Require(
        device.LastIoError() != ERROR_SUCCESS,
        "BlockDevice async partial issue should preserve a diagnostic error code");
    ok &= Require(device.Flush(), "BlockDevice async partial issue should allow completed writes to flush");

    for (std::size_t index = 0; index < span_count; ++index)
    {
        std::vector<std::byte> read;
        ok &= Require(
            device.Read(static_cast<std::uint64_t>(index * stride_bytes), span_bytes, read),
            "BlockDevice async partial issue read should succeed");
        if (index == 0)
        {
            ok &= Require(read == payloads[index], "BlockDevice should drain the one issued request before returning failure");
        }
        else
        {
            ok &= Require(
                std::all_of(read.begin(), read.end(), [](std::byte value) { return value == std::byte{0}; }),
                "BlockDevice should not issue writes after the injected async failure boundary");
        }
    }
    return ok;
}

bool RunBlockDeviceBenchmarkWorkload(
    const std::filesystem::path& run_root,
    bool async_enabled,
    const char* workload,
    std::size_t span_count,
    std::size_t span_bytes,
    std::size_t stride_bytes,
    unsigned char seed)
{
    ScopedEnvironmentVariable async_switch(
        L"APFSACCESS_DISABLE_ASYNC_BLOCK_IO",
        async_enabled ? L"" : L"1");
    ScopedEnvironmentVariable async_depth(
        L"APFSACCESS_ASYNC_BLOCK_IO_DEPTH",
        L"4");
    ScopedEnvironmentVariable clear_async_fault(
        L"APFSACCESS_RW_FAULT_ASYNC_BATCH_AFTER_ISSUES",
        L"");

    if (span_count == 0 || span_bytes == 0 || stride_bytes < span_bytes ||
        span_count > (std::numeric_limits<std::size_t>::max() / stride_bytes))
    {
        return Require(false, "BlockDevice benchmark dimensions should be valid");
    }

    const auto image_path = run_root /
        (std::string("block_device_benchmark_") + workload + (async_enabled ? "_async.bin" : "_sync.bin"));
    {
        std::ofstream out(image_path, std::ios::binary | std::ios::trunc);
        if (!out.good())
        {
            return Require(false, "BlockDevice benchmark should create image");
        }
    }
    std::error_code resize_ec;
    std::filesystem::resize_file(image_path, span_count * stride_bytes, resize_ec);
    if (resize_ec)
    {
        return Require(false, "BlockDevice benchmark should size image");
    }

    if (span_count > (std::numeric_limits<std::size_t>::max() / span_bytes))
    {
        return Require(false, "BlockDevice benchmark payload size should be valid");
    }
    auto payload = BuildPatternPayload(span_count * span_bytes, seed);
    std::vector<apfsaccess::rw::BlockDevice::WriteSpan> writes;
    writes.reserve(span_count);
    const void* merge_token = stride_bytes == span_bytes ? payload.data() : nullptr;
    for (std::size_t index = 0; index < span_count; ++index)
    {
        writes.push_back(apfsaccess::rw::BlockDevice::WriteSpan{
            static_cast<std::uint64_t>(index * stride_bytes),
            std::span<const std::byte>(payload.data() + (index * span_bytes), span_bytes),
            merge_token,
        });
    }

    apfsaccess::rw::BlockDevice device(image_path.wstring());
    const auto started = std::chrono::steady_clock::now();
    const bool write_ok = device.WriteBatch(writes);
    const bool flush_ok = write_ok && device.Flush();
    const auto elapsed = std::chrono::steady_clock::now() - started;
    if (!Require(write_ok && flush_ok, "BlockDevice benchmark write and durable flush should succeed"))
    {
        return false;
    }

    std::ifstream input(image_path, std::ios::binary);
    if (!input.good())
    {
        return Require(false, "BlockDevice benchmark verification should open image");
    }
    std::vector<std::byte> actual(span_bytes);
    for (std::size_t index = 0; index < span_count; ++index)
    {
        input.seekg(static_cast<std::streamoff>(index * stride_bytes), std::ios::beg);
        input.read(reinterpret_cast<char*>(actual.data()), static_cast<std::streamsize>(actual.size()));
        if (static_cast<std::size_t>(input.gcount()) != actual.size() ||
            !std::equal(
                actual.begin(),
                actual.end(),
                payload.begin() + static_cast<std::ptrdiff_t>(index * span_bytes)))
        {
            return Require(false, "BlockDevice benchmark should preserve every written span");
        }
    }

    const auto elapsed_us = std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count();
    const auto total_bytes = static_cast<double>(payload.size());
    const auto mib_per_second = elapsed_us > 0
        ? (total_bytes / (1024.0 * 1024.0)) / (static_cast<double>(elapsed_us) / 1000000.0)
        : 0.0;
    std::cout << std::fixed << std::setprecision(3)
              << "[BENCH] {\"kind\":\"block-io\",\"mode\":\""
              << (async_enabled ? "async" : "sync")
              << "\",\"workload\":\"" << workload
              << "\",\"bytes\":" << payload.size()
              << ",\"spans\":" << span_count
              << ",\"elapsedUs\":" << elapsed_us
              << ",\"mibPerSecond\":" << mib_per_second
              << ",\"devicePerf\":" << device.PerformanceJson()
              << "}" << std::endl;
    return true;
}

bool RunBlockDeviceBenchmarks(const std::filesystem::path& run_root, bool async_enabled)
{
    return RunBlockDeviceBenchmarkWorkload(
               run_root,
               async_enabled,
               "large-adjacent",
               256,
               256 * 1024,
               256 * 1024,
               0x31) &&
           RunBlockDeviceBenchmarkWorkload(
               run_root,
               async_enabled,
               "small-disjoint",
               4096,
               16 * 1024,
               32 * 1024,
               0x62);
}

bool RunBlockDeviceReadCacheBenchmark(const std::filesystem::path& run_root, bool enabled)
{
    ScopedEnvironmentVariable read_cache_opt_in(
        L"APFSACCESS_EXPERIMENTAL_BLOCK_READ_CACHE",
        enabled ? L"1" : L"");
    const auto image_path = run_root /
        (std::string("block_device_read_cache_benchmark_") + (enabled ? "enabled.bin" : "disabled.bin"));
    constexpr std::size_t window_bytes = 64 * 1024;
    constexpr std::size_t window_count = 128;
    constexpr std::size_t operation_count = 20000;
    const auto seed = BuildPatternPayload(window_bytes * window_count, 0xA7);
    {
        std::ofstream out(image_path, std::ios::binary | std::ios::trunc);
        if (!out.good())
        {
            return Require(false, "BlockDevice read-cache benchmark should create image");
        }
        out.write(reinterpret_cast<const char*>(seed.data()), static_cast<std::streamsize>(seed.size()));
        if (!out.good())
        {
            return Require(false, "BlockDevice read-cache benchmark should seed image");
        }
    }

    apfsaccess::rw::BlockDevice device(image_path.wstring());
    for (std::size_t window = 0; window < window_count; ++window)
    {
        std::vector<std::byte> wide_read;
        const auto expected_begin = seed.begin() + static_cast<std::ptrdiff_t>(window * window_bytes);
        if (!device.Read(static_cast<std::uint64_t>(window * window_bytes), window_bytes, wide_read) ||
            wide_read.size() != window_bytes ||
            !std::equal(
                expected_begin,
                expected_begin + static_cast<std::ptrdiff_t>(window_bytes),
                wide_read.begin()))
        {
            return Require(false, "BlockDevice read-cache benchmark warm-up should preserve wide-window bytes");
        }
    }

    std::uint64_t checksum = 0;
    const auto started = std::chrono::steady_clock::now();
    for (std::size_t operation = 0; operation < operation_count; ++operation)
    {
        const auto window = (operation * 53) % window_count;
        const auto block = (operation * 29) % (window_bytes / kBlockSize);
        const auto offset = (window * window_bytes) + (block * kBlockSize) + 123;
        std::vector<std::byte> read;
        if (!device.Read(offset, kBlockSize, read) || read.size() != kBlockSize)
        {
            return Require(false, "BlockDevice read-cache benchmark random read should succeed");
        }
        const auto expected = seed.begin() + static_cast<std::ptrdiff_t>(offset);
        if (!std::equal(expected, expected + static_cast<std::ptrdiff_t>(kBlockSize), read.begin()))
        {
            return Require(false, "BlockDevice read-cache benchmark random read should preserve bytes");
        }
        checksum = (checksum << 7) ^ std::to_integer<unsigned char>(read[operation % read.size()]);
    }
    const auto elapsed = std::chrono::steady_clock::now() - started;
    const auto elapsed_us = std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count();
    const auto total_bytes = static_cast<double>(operation_count * kBlockSize);
    const auto mib_per_second = elapsed_us > 0
        ? (total_bytes / (1024.0 * 1024.0)) / (static_cast<double>(elapsed_us) / 1000000.0)
        : 0.0;
    const auto perf = device.PerformanceJson();
    std::cout << std::fixed << std::setprecision(3)
              << "[BENCH] {\"kind\":\"block-read-cache\",\"mode\":\""
              << (enabled ? "enabled" : "disabled")
              << "\",\"bytes\":" << total_bytes
              << ",\"operations\":" << operation_count
              << ",\"elapsedUs\":" << elapsed_us
              << ",\"mibPerSecond\":" << mib_per_second
              << ",\"checksum\":" << checksum
              << ",\"devicePerf\":" << perf
              << "}" << std::endl;
    return true;
}

std::optional<std::uint32_t> ReadLe32FromBytes(const std::vector<std::byte>& bytes, std::size_t offset)
{
    if (offset + sizeof(std::uint32_t) > bytes.size())
    {
        return std::nullopt;
    }

    std::uint32_t value = 0;
    for (std::size_t i = 0; i < sizeof(std::uint32_t); ++i)
    {
        value |= static_cast<std::uint32_t>(std::to_integer<unsigned char>(bytes[offset + i])) << (i * 8);
    }
    return value;
}

std::optional<std::uint64_t> ReadLe64FromBytes(const std::vector<std::byte>& bytes, std::size_t offset)
{
    if (offset + sizeof(std::uint64_t) > bytes.size())
    {
        return std::nullopt;
    }

    std::uint64_t value = 0;
    for (std::size_t i = 0; i < sizeof(std::uint64_t); ++i)
    {
        value |= static_cast<std::uint64_t>(std::to_integer<unsigned char>(bytes[offset + i])) << (i * 8);
    }
    return value;
}

std::optional<std::uint64_t> ReadLe64FromImage(const std::filesystem::path& image_path, std::uint64_t offset_bytes)
{
    std::vector<std::byte> bytes;
    if (!ReadBytesFromImage(image_path, offset_bytes, sizeof(std::uint64_t), bytes) ||
        bytes.size() != sizeof(std::uint64_t))
    {
        return std::nullopt;
    }

    std::uint64_t value = 0;
    for (std::size_t i = 0; i < sizeof(std::uint64_t); ++i)
    {
        value |= static_cast<std::uint64_t>(std::to_integer<unsigned char>(bytes[i])) << (i * 8);
    }
    return value;
}

struct ObjectMapCheckpointSummary
{
    std::uint64_t checkpoint_xid = 0;
    std::uint32_t entry_count = 0;
};

struct SpacemanCheckpointSummary
{
    std::uint64_t checkpoint_xid = 0;
    std::uint32_t allocation_count = 0;
    std::uint32_t free_extent_count = 0;
};

struct InodeCheckpointSummary
{
    std::uint64_t checkpoint_xid = 0;
    std::uint32_t inode_count = 0;
};

struct BtreeCheckpointSummary
{
    std::uint64_t checkpoint_xid = 0;
    std::uint32_t record_count = 0;
};

std::optional<ObjectMapCheckpointSummary> ReadObjectMapCheckpointSummary(
    const std::filesystem::path& image_path,
    std::uint64_t block_index)
{
    constexpr std::array<char, 12> kMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'O', 'M', 'A', 'P', '3', '\0'
    };

    std::vector<std::byte> block;
    if (!ReadBytesFromImage(image_path, block_index * static_cast<std::uint64_t>(kBlockSize), kBlockSize, block))
    {
        return std::nullopt;
    }

    if (block.size() < 32)
    {
        return std::nullopt;
    }

    for (std::size_t index = 0; index < kMagic.size(); ++index)
    {
        if (std::to_integer<unsigned char>(block[index]) != static_cast<unsigned char>(kMagic[index]))
        {
            return std::nullopt;
        }
    }

    auto xid = ReadLe64FromBytes(block, 12);
    auto entry_count = ReadLe32FromBytes(block, 20);
    if (!xid.has_value() || !entry_count.has_value())
    {
        return std::nullopt;
    }

    return ObjectMapCheckpointSummary
    {
        xid.value(),
        entry_count.value()
    };
}

std::optional<SpacemanCheckpointSummary> ReadSpacemanCheckpointSummary(
    const std::filesystem::path& image_path,
    std::uint64_t block_index)
{
    constexpr std::array<char, 12> kMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'S', 'P', 'M', '3', '\0', '\0'
    };

    std::vector<std::byte> block;
    if (!ReadBytesFromImage(image_path, block_index * static_cast<std::uint64_t>(kBlockSize), kBlockSize, block))
    {
        return std::nullopt;
    }

    if (block.size() < 32)
    {
        return std::nullopt;
    }

    for (std::size_t index = 0; index < kMagic.size(); ++index)
    {
        if (std::to_integer<unsigned char>(block[index]) != static_cast<unsigned char>(kMagic[index]))
        {
            return std::nullopt;
        }
    }

    auto xid = ReadLe64FromBytes(block, 12);
    auto allocation_count = ReadLe32FromBytes(block, 20);
    auto free_extent_count = ReadLe32FromBytes(block, 24);
    if (!xid.has_value() || !allocation_count.has_value() || !free_extent_count.has_value())
    {
        return std::nullopt;
    }

    return SpacemanCheckpointSummary
    {
        xid.value(),
        allocation_count.value(),
        free_extent_count.value()
    };
}

std::optional<InodeCheckpointSummary> ReadInodeCheckpointSummary(
    const std::filesystem::path& image_path,
    std::uint64_t block_index)
{
    constexpr std::array<char, 12> kMagicV4 =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'I', 'N', 'O', 'D', '4', '\0'
    };
    constexpr std::array<char, 12> kMagicV5 =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'I', 'N', 'O', 'D', '5', '\0'
    };
    constexpr std::array<char, 12> kMagicV6 =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'I', 'N', 'O', 'D', '6', '\0'
    };

    std::vector<std::byte> block;
    if (!ReadBytesFromImage(image_path, block_index * static_cast<std::uint64_t>(kBlockSize), kBlockSize, block))
    {
        return std::nullopt;
    }

    if (block.size() < 32)
    {
        return std::nullopt;
    }

    const auto matches_magic = [&](const std::array<char, 12>& magic)
    {
        for (std::size_t index = 0; index < magic.size(); ++index)
        {
            if (std::to_integer<unsigned char>(block[index]) != static_cast<unsigned char>(magic[index]))
            {
                return false;
            }
        }
        return true;
    };
    if (!matches_magic(kMagicV4) && !matches_magic(kMagicV5) && !matches_magic(kMagicV6))
    {
        return std::nullopt;
    }

    auto xid = ReadLe64FromBytes(block, 12);
    auto inode_count = ReadLe32FromBytes(block, 20);
    if (!xid.has_value() || !inode_count.has_value())
    {
        return std::nullopt;
    }

    return InodeCheckpointSummary
    {
        xid.value(),
        inode_count.value()
    };
}

std::optional<BtreeCheckpointSummary> ReadBtreeCheckpointSummary(
    const std::filesystem::path& image_path,
    std::uint64_t block_index)
{
    constexpr std::array<char, 12> kMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'B', 'T', 'R', '5', '\0', '\0'
    };

    std::vector<std::byte> block;
    if (!ReadBytesFromImage(image_path, block_index * static_cast<std::uint64_t>(kBlockSize), kBlockSize, block))
    {
        return std::nullopt;
    }

    if (block.size() < 32)
    {
        return std::nullopt;
    }

    for (std::size_t index = 0; index < kMagic.size(); ++index)
    {
        if (std::to_integer<unsigned char>(block[index]) != static_cast<unsigned char>(kMagic[index]))
        {
            return std::nullopt;
        }
    }

    auto xid = ReadLe64FromBytes(block, 12);
    auto record_count = ReadLe32FromBytes(block, 20);
    if (!xid.has_value() || !record_count.has_value())
    {
        return std::nullopt;
    }

    return BtreeCheckpointSummary
    {
        xid.value(),
        record_count.value()
    };
}

template <typename Summary, typename Reader>
std::vector<std::pair<std::uint64_t, Summary>> CollectCheckpointSummaries(
    const std::filesystem::path& image_path,
    std::uint64_t first_block,
    std::uint64_t last_block,
    Reader reader)
{
    std::vector<std::pair<std::uint64_t, Summary>> results;
    if (first_block > last_block)
    {
        return results;
    }

    for (std::uint64_t block = first_block; block <= last_block; ++block)
    {
        auto summary = reader(image_path, block);
        if (summary.has_value())
        {
            results.emplace_back(block, summary.value());
        }
        if (block == std::numeric_limits<std::uint64_t>::max())
        {
            break;
        }
    }

    return results;
}

template <typename Summary, typename Reader>
void AppendCheckpointSummaries(
    std::vector<std::pair<std::uint64_t, Summary>>& summaries,
    const std::filesystem::path& image_path,
    std::uint64_t first_block,
    std::uint64_t last_block,
    Reader reader)
{
    auto next = CollectCheckpointSummaries<Summary>(
        image_path,
        first_block,
        last_block,
        reader);
    summaries.insert(summaries.end(), next.begin(), next.end());
}

std::vector<std::pair<std::uint64_t, ObjectMapCheckpointSummary>> CollectObjectMapCheckpointSummaries(
    const std::filesystem::path& image_path,
    std::uint64_t total_blocks)
{
    std::vector<std::pair<std::uint64_t, ObjectMapCheckpointSummary>> summaries;
    if (total_blocks == 0)
    {
        return summaries;
    }

    const auto band_start = total_blocks > kNativeCheckpointBandBlocks
        ? total_blocks - kNativeCheckpointBandBlocks
        : 0;
    AppendCheckpointSummaries(
        summaries,
        image_path,
        band_start + kNativeObjectMapCheckpointOffset,
        std::min<std::uint64_t>(total_blocks - 1, band_start + kNativeSpacemanCheckpointOffset - 1),
        ReadObjectMapCheckpointSummary);
    AppendCheckpointSummaries(
        summaries,
        image_path,
        band_start + kNativeOverflowCheckpointOffset,
        std::min<std::uint64_t>(total_blocks - 1, band_start + kNativeOverflowCheckpointOffset + kNativeObjectMapOverflowBlocks - 1),
        ReadObjectMapCheckpointSummary);
    return summaries;
}

std::vector<std::pair<std::uint64_t, InodeCheckpointSummary>> CollectInodeCheckpointSummaries(
    const std::filesystem::path& image_path,
    std::uint64_t total_blocks,
    std::uint64_t fallback_start)
{
    std::vector<std::pair<std::uint64_t, InodeCheckpointSummary>> summaries;
    if (total_blocks == 0)
    {
        return summaries;
    }

    if (total_blocks > kNativeCheckpointBandBlocks)
    {
        const auto band_start = total_blocks - kNativeCheckpointBandBlocks;
        AppendCheckpointSummaries(
            summaries,
            image_path,
            band_start + kNativeInodeCheckpointOffset,
            std::min<std::uint64_t>(total_blocks - 1, band_start + kNativeBtreeCheckpointOffset - 1),
            ReadInodeCheckpointSummary);
        AppendCheckpointSummaries(
            summaries,
            image_path,
            band_start + kNativeInodeOverflowOffset,
            std::min<std::uint64_t>(total_blocks - 1, band_start + kNativeCheckpointBandBlocks - 1),
            ReadInodeCheckpointSummary);
        if (band_start >= kNativeMetadataExtensionBlocks)
        {
            const auto extension_start = band_start - kNativeMetadataExtensionBlocks;
            if (extension_start >= kNativeMinimumMetadataExtensionStartBlock)
            {
                AppendCheckpointSummaries(
                    summaries,
                    image_path,
                    extension_start + kNativeInodeExtensionOffset,
                    std::min<std::uint64_t>(
                        band_start - 1,
                        extension_start + kNativeInodeExtensionOffset + kNativeInodeExtensionBlocks - 1),
                    ReadInodeCheckpointSummary);
            }
        }
    }
    else
    {
        AppendCheckpointSummaries(
            summaries,
            image_path,
            fallback_start,
            std::min<std::uint64_t>(total_blocks - 1, fallback_start + 11),
            ReadInodeCheckpointSummary);
    }
    return summaries;
}

std::vector<std::pair<std::uint64_t, BtreeCheckpointSummary>> CollectBtreeCheckpointSummaries(
    const std::filesystem::path& image_path,
    std::uint64_t total_blocks)
{
    std::vector<std::pair<std::uint64_t, BtreeCheckpointSummary>> summaries;
    if (total_blocks <= kNativeCheckpointBandBlocks)
    {
        return summaries;
    }

    const auto band_start = total_blocks - kNativeCheckpointBandBlocks;
    AppendCheckpointSummaries(
        summaries,
        image_path,
        band_start + kNativeBtreeCheckpointOffset,
        std::min<std::uint64_t>(total_blocks - 1, band_start + kNativeReplayCheckpointOffset - 1),
        ReadBtreeCheckpointSummary);
    if (band_start >= kNativeMetadataExtensionBlocks)
    {
        const auto extension_start = band_start - kNativeMetadataExtensionBlocks;
        if (extension_start >= kNativeMinimumMetadataExtensionStartBlock)
        {
            AppendCheckpointSummaries(
                summaries,
                image_path,
                extension_start + kNativeBtreeExtensionOffset,
                std::min<std::uint64_t>(
                    band_start - 1,
                    extension_start + kNativeBtreeExtensionOffset + kNativeBtreeExtensionBlocks - 1),
                ReadBtreeCheckpointSummary);
        }
    }

    return summaries;
}

template <typename Summary, typename XidAccessor>
std::optional<std::pair<std::uint64_t, Summary>> SelectLatestCheckpointSummary(
    const std::vector<std::pair<std::uint64_t, Summary>>& summaries,
    XidAccessor xid_accessor)
{
    if (summaries.empty())
    {
        return std::nullopt;
    }

    auto latest = summaries.front();
    auto latest_xid = xid_accessor(latest.second);
    for (std::size_t index = 1; index < summaries.size(); ++index)
    {
        const auto candidate_xid = xid_accessor(summaries[index].second);
        if (candidate_xid > latest_xid)
        {
            latest = summaries[index];
            latest_xid = candidate_xid;
        }
    }
    return latest;
}

bool CorruptInodeCheckpointBlocks(
    const std::filesystem::path& image_path,
    std::uint64_t volume_root_block,
    std::uint64_t total_blocks,
    std::size_t& out_corrupted_blocks)
{
    out_corrupted_blocks = 0;
    if (volume_root_block == 0 || total_blocks == 0)
    {
        return false;
    }

    const auto fallback_start = std::min<std::uint64_t>(total_blocks - 1, volume_root_block + 1);
    auto inode_checkpoints = CollectInodeCheckpointSummaries(
        image_path,
        total_blocks,
        fallback_start);
    if (inode_checkpoints.empty())
    {
        return false;
    }

    for (const auto& [block_index, _] : inode_checkpoints)
    {
        std::vector<std::byte> block;
        if (!ReadBytesFromImage(
                image_path,
                block_index * static_cast<std::uint64_t>(kBlockSize),
                kBlockSize,
                block))
        {
            continue;
        }
        if (block.empty())
        {
            continue;
        }

        block[0] = static_cast<std::byte>(0x00);
        if (WriteBytesToImage(
                image_path,
                block_index * static_cast<std::uint64_t>(kBlockSize),
                block))
        {
            ++out_corrupted_blocks;
        }
    }

    return out_corrupted_blocks > 0;
}

bool CorruptLatestObjectMapCheckpointBlocks(
    const std::filesystem::path& image_path,
    std::uint64_t total_blocks,
    std::size_t& out_corrupted_blocks,
    std::uint64_t& out_corrupted_xid)
{
    out_corrupted_blocks = 0;
    out_corrupted_xid = 0;
    if (total_blocks == 0)
    {
        return false;
    }

    auto object_map_checkpoints = CollectObjectMapCheckpointSummaries(
        image_path,
        total_blocks);
    auto latest = SelectLatestCheckpointSummary(
        object_map_checkpoints,
        [](const ObjectMapCheckpointSummary& summary)
        {
            return summary.checkpoint_xid;
        });
    if (!latest.has_value() || latest->second.checkpoint_xid == 0)
    {
        return false;
    }

    out_corrupted_xid = latest->second.checkpoint_xid;
    for (const auto& [block_index, summary] : object_map_checkpoints)
    {
        if (summary.checkpoint_xid != out_corrupted_xid)
        {
            continue;
        }

        std::vector<std::byte> block;
        if (!ReadBytesFromImage(
                image_path,
                block_index * static_cast<std::uint64_t>(kBlockSize),
                kBlockSize,
                block) ||
            block.empty())
        {
            continue;
        }

        block[0] = static_cast<std::byte>(0x00);
        if (WriteBytesToImage(
                image_path,
                block_index * static_cast<std::uint64_t>(kBlockSize),
                block))
        {
            ++out_corrupted_blocks;
        }
    }

    return out_corrupted_blocks > 0;
}

bool WriteRootOnlyInodeCheckpointBlocks(
    const std::filesystem::path& image_path,
    std::uint64_t volume_root_object_id,
    std::uint64_t total_blocks,
    std::size_t& out_rewritten_blocks)
{
    out_rewritten_blocks = 0;
    if (volume_root_object_id == 0 || total_blocks == 0)
    {
        return false;
    }

    const auto fallback_start = std::min<std::uint64_t>(total_blocks - 1, volume_root_object_id + 1);
    auto inode_checkpoints = CollectInodeCheckpointSummaries(
        image_path,
        total_blocks,
        fallback_start);
    if (inode_checkpoints.empty())
    {
        return false;
    }

    constexpr std::array<char, 12> kMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'I', 'N', 'O', 'D', '4', '\0'
    };
    constexpr std::size_t kHeaderBytes = 32;
    constexpr std::size_t kRecordFixedBytes = 52;
    constexpr std::uint32_t kDirectoryFlag = 0x1u;

    for (const auto& [block_index, summary] : inode_checkpoints)
    {
        std::vector<std::byte> block(kBlockSize, std::byte{0});
        for (std::size_t index = 0; index < kMagic.size(); ++index)
        {
            block[index] = static_cast<std::byte>(kMagic[index]);
        }

        const auto payload_bytes = static_cast<std::uint32_t>(kRecordFixedBytes + sizeof(wchar_t));
        WriteLe64(block, 12, summary.checkpoint_xid);
        WriteLe32(block, 20, 1);
        WriteLe32(block, 24, payload_bytes);

        std::size_t cursor = kHeaderBytes;
        WriteLe64(block, cursor + 0, volume_root_object_id);
        WriteLe64(block, cursor + 8, volume_root_object_id);
        WriteLe64(block, cursor + 16, 0);
        WriteLe64(block, cursor + 24, 0);
        WriteLe64(block, cursor + 32, summary.checkpoint_xid);
        WriteLe32(block, cursor + 40, kDirectoryFlag);
        WriteLe32(block, cursor + 44, 0);
        WriteLe32(block, cursor + 48, 1);
        cursor += kRecordFixedBytes;

        const wchar_t root_path_char = L'\\';
        const auto* root_path_bytes = reinterpret_cast<const unsigned char*>(&root_path_char);
        for (std::size_t index = 0; index < sizeof(wchar_t); ++index)
        {
            block[cursor + index] = static_cast<std::byte>(root_path_bytes[index]);
        }

        if (WriteBytesToImage(
                image_path,
                block_index * static_cast<std::uint64_t>(kBlockSize),
                block))
        {
            ++out_rewritten_blocks;
        }
    }

    return out_rewritten_blocks > 0;
}

std::uint64_t StableObjectIdFromPathForState(const std::wstring& path)
{
    constexpr std::uint64_t kFnvOffset = 1469598103934665603ull;
    constexpr std::uint64_t kFnvPrime = 1099511628211ull;

    std::uint64_t hash = kFnvOffset;
    for (const auto ch : path)
    {
        const auto lower = static_cast<std::uint16_t>(std::towlower(ch));
        const auto lo = static_cast<std::uint8_t>(lower & 0xffu);
        const auto hi = static_cast<std::uint8_t>((lower >> 8) & 0xffu);
        hash ^= lo;
        hash *= kFnvPrime;
        hash ^= hi;
        hash *= kFnvPrime;
    }

    return hash == 0 ? 1 : hash;
}

std::filesystem::path BuildPersistentStatePathForTest(const apfsaccess::rw::MetadataStore::VolumeContext& context)
{
    std::error_code ec;
    auto root = std::filesystem::temp_directory_path(ec);
    if (ec)
    {
        return {};
    }

    root /= "ApfsAccess";
    root /= "rw-state";
    const auto key = context.device_path + L"|" + context.volume_name;
    const auto stable_id = StableObjectIdFromPathForState(key);
    return root / (std::to_wstring(stable_id) + L".bin");
}

std::optional<std::uint64_t> ResolveInodeCheckpointBlockForTest(
    std::uint64_t volume_root_block,
    std::uint64_t spaceman_block,
    std::uint64_t total_blocks)
{
    if (volume_root_block == 0)
    {
        return std::nullopt;
    }

    for (std::uint64_t delta = 1; delta <= 32; ++delta)
    {
        if (volume_root_block > (std::numeric_limits<std::uint64_t>::max() - delta))
        {
            return std::nullopt;
        }

        const auto candidate = volume_root_block + delta;
        if (candidate == 0 || candidate == volume_root_block || candidate == spaceman_block)
        {
            continue;
        }
        if (total_blocks != 0 && candidate >= total_blocks)
        {
            break;
        }
        return candidate;
    }

    return std::nullopt;
}

bool Require(bool condition, const std::string& message)
{
    if (!condition)
    {
        std::cerr << "[FAIL] " << message << std::endl;
        return false;
    }

    return true;
}

const char* CommitStatusToString(apfsaccess::rw::MetadataStore::CommitStatus status)
{
    using CommitStatus = apfsaccess::rw::MetadataStore::CommitStatus;
    switch (status)
    {
    case CommitStatus::Committed:
        return "Committed";
    case CommitStatus::NothingToCommit:
        return "NothingToCommit";
    case CommitStatus::NotReady:
        return "NotReady";
    case CommitStatus::NotWritable:
        return "NotWritable";
    case CommitStatus::AllocationFailed:
        return "AllocationFailed";
    case CommitStatus::InvariantFailed:
        return "InvariantFailed";
    case CommitStatus::PersistFailed:
        return "PersistFailed";
    case CommitStatus::FlushFailed:
        return "FlushFailed";
    default:
        return "Unknown";
    }
}

bool TestLargeSpacemanCheckpointUsesExtension(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "large_spaceman_checkpoint.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "LargeSpacemanCheckpoint: unable to create synthetic APFS container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"LargeSpacemanCheckpoint",
    };
    const auto persistent_state_path = BuildPersistentStatePathForTest(context);
    if (!persistent_state_path.empty())
    {
        std::error_code remove_ec;
        std::filesystem::remove(persistent_state_path, remove_ec);
    }

    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "LargeSpacemanCheckpoint: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "LargeSpacemanCheckpoint: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "LargeSpacemanCheckpoint: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "LargeSpacemanCheckpoint: PrepareNativeWritePath should succeed");

    const auto before_json = store.PerformanceJson();
    const auto before_free_full = ExtractNestedUnsignedValue(before_json, "committedSpacemanApply", "freeFull");
    const auto before_free_local = ExtractNestedUnsignedValue(before_json, "committedSpacemanApply", "freeLocal");
    ok &= Require(
        before_free_full.has_value() && before_free_local.has_value(),
        "LargeSpacemanCheckpoint: committed free-list apply counters should exist");

    constexpr std::uint64_t kInjectedFreeExtentCount = 1100;
    constexpr std::uint64_t kFirstFreeBlock = 512;
    for (std::uint64_t index = 0; index < kInjectedFreeExtentCount; ++index)
    {
        const auto physical_address = (kFirstFreeBlock + (index * 2ull)) * static_cast<std::uint64_t>(kBlockSize);
        ok &= Require(
            store.FreeExtent(physical_address, kBlockSize),
            "LargeSpacemanCheckpoint: synthetic fragmented free extent should be accepted");
    }

    apfsaccess::rw::MetadataStore::MutationRequest create_directory{};
    create_directory.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateDirectory;
    create_directory.path = L"\\large-spaceman-checkpoint";
    ok &= Require(
        store.ApplyMutation(create_directory) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "LargeSpacemanCheckpoint: metadata mutation should apply");

    const auto commit_status = store.CommitPendingMutations();
    if (commit_status != apfsaccess::rw::MetadataStore::CommitStatus::Committed)
    {
        std::cerr << "[DEBUG] LargeSpacemanCheckpoint commit status: "
                  << CommitStatusToString(commit_status) << std::endl;
        std::cerr << "[DEBUG] LargeSpacemanCheckpoint commit stage: "
                  << store.LastCommitStage() << std::endl;
        const auto recovery_reason = store.RecoveryReason();
        if (!recovery_reason.empty())
        {
            std::wcerr << L"[DEBUG] LargeSpacemanCheckpoint recovery reason: " << recovery_reason << std::endl;
        }
    }
    ok &= Require(
        commit_status == apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "LargeSpacemanCheckpoint: commit should persist a spaceman checkpoint larger than the compact band slots");
    const auto after_json = store.PerformanceJson();
    const auto after_free_full = ExtractNestedUnsignedValue(after_json, "committedSpacemanApply", "freeFull");
    const auto after_free_local = ExtractNestedUnsignedValue(after_json, "committedSpacemanApply", "freeLocal");
    ok &= Require(
        after_free_full.has_value() && after_free_local.has_value(),
        "LargeSpacemanCheckpoint: committed free-list apply counters should exist after commit");
    if (before_free_full.has_value() && after_free_full.has_value())
    {
        ok &= Require(
            after_free_full.value() == before_free_full.value() + 1,
            "LargeSpacemanCheckpoint: direct free-list injection should use full committed free-list replacement");
    }
    if (before_free_local.has_value() && after_free_local.has_value())
    {
        ok &= Require(
            after_free_local.value() == before_free_local.value(),
            "LargeSpacemanCheckpoint: direct free-list injection should not use local free-list delta");
    }

    apfsaccess::rw::MetadataStore remounted(context);
    ok &= Require(remounted.LoadContainerSuperblocks(), "LargeSpacemanCheckpoint: remount LoadContainerSuperblocks should succeed");
    ok &= Require(remounted.LoadObjectMap(), "LargeSpacemanCheckpoint: remount LoadObjectMap should succeed");
    ok &= Require(remounted.LoadSpacemanState(), "LargeSpacemanCheckpoint: remount LoadSpacemanState should succeed");
    ok &= Require(
        remounted.CommittedFreeExtentCount() >= kInjectedFreeExtentCount - 1,
        "LargeSpacemanCheckpoint: remount should recover large spaceman free ledger");

    return ok;
}

bool TestSingleExtentPreparedWriteUsesDirectFastPath(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "single_extent_prepared_write_fast_path.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "SingleExtentPreparedWrite: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"SingleExtentPreparedWriteFastPath",
    };
    const auto persistent_state_path = BuildPersistentStatePathForTest(context);
    if (!persistent_state_path.empty())
    {
        std::error_code remove_ec;
        std::filesystem::remove(persistent_state_path, remove_ec);
    }

    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "SingleExtentPreparedWrite: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "SingleExtentPreparedWrite: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "SingleExtentPreparedWrite: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "SingleExtentPreparedWrite: PrepareNativeWritePath should succeed");

    const std::wstring path = L"\\single-extent.bin";
    const auto initial_payload = BuildPatternPayload(8192, 0x31);
    store.SetFilePayloadProvider(
        [&initial_payload, &path](const std::wstring& requested_path, std::uint64_t logical_size)
            -> std::optional<std::vector<std::byte>>
        {
            if (requested_path != path || logical_size > initial_payload.size())
            {
                return std::nullopt;
            }
            return std::vector<std::byte>(
                initial_payload.begin(),
                initial_payload.begin() + static_cast<std::ptrdiff_t>(logical_size));
        });

    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_file.path = path;
    ok &= Require(
        store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "SingleExtentPreparedWrite: create file should apply");

    apfsaccess::rw::MetadataStore::MutationRequest write_file{};
    write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_file.path = path;
    write_file.length = initial_payload.size();
    ok &= Require(
        store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "SingleExtentPreparedWrite: initial file write should apply");
    ok &= Require(
        store.CommitPendingMutations() == apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "SingleExtentPreparedWrite: initial file commit should succeed");

    const auto replacement = BuildPatternPayload(37, 0xA7);
    constexpr std::uint64_t replacement_offset = 123;
    ok &= Require(
        store.WritePreparedFileRange(path, replacement_offset, replacement),
        "SingleExtentPreparedWrite: prepared overwrite should succeed");

    const auto performance = store.PerformanceJson();
    const auto direct_fast_path_count = ExtractNestedUnsignedValue(
        performance,
        "preparedPayloadRangeWrites",
        "singleExtentDirect");
    ok &= Require(
        direct_fast_path_count.has_value() && direct_fast_path_count.value() == 1,
        "SingleExtentPreparedWrite: one-extent overwrite should use the direct fast path");

    std::vector<std::byte> readback;
    ok &= Require(
        store.ReadCommittedFileRange(path, replacement_offset, replacement.size(), readback),
        "SingleExtentPreparedWrite: prepared overwrite should be readable immediately");
    ok &= Require(
        readback == replacement,
        "SingleExtentPreparedWrite: prepared overwrite should preserve replacement bytes");
    return ok;
}
} // namespace

int main(int argc, char** argv)
{
    _wputenv_s(L"APFSACCESS_PERF_COUNTERS", L"1");

    std::error_code ec;
    const auto run_root = std::filesystem::temp_directory_path(ec) / ("ApfsAccessRwEngineTests_" + std::to_string(GetCurrentProcessId()));
    if (ec)
    {
        std::cerr << "[FAIL] unable to access temporary directory" << std::endl;
        return 1;
    }

    std::filesystem::remove_all(run_root, ec);
    ec.clear();
    std::filesystem::create_directories(run_root, ec);
    if (ec)
    {
        std::cerr << "[FAIL] unable to create test directory" << std::endl;
        return 1;
    }

    if (argc == 3 && std::string_view(argv[1]) == "--benchmark-block-io")
    {
        const std::string_view mode(argv[2]);
        if (mode != "async" && mode != "sync")
        {
            std::cerr << "Usage: --benchmark-block-io <async|sync>" << std::endl;
            return 2;
        }
        return RunBlockDeviceBenchmarks(run_root, mode == "async") ? 0 : 1;
    }

    if (argc == 3 && std::string_view(argv[1]) == "--benchmark-read-cache")
    {
        const std::string_view mode(argv[2]);
        if (mode != "enabled" && mode != "disabled")
        {
            std::cerr << "Usage: --benchmark-read-cache <enabled|disabled>" << std::endl;
            return 2;
        }
        return RunBlockDeviceReadCacheBenchmark(run_root, mode == "enabled") ? 0 : 1;
    }

    bool ok = true;
    ok &= TestSingleExtentPreparedWriteUsesDirectFastPath(run_root);
    ok &= TestLargeSpacemanCheckpointUsesExtension(run_root);

    const auto image_path = run_root / "container.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"Main",
    };
    const auto persistent_state_path = BuildPersistentStatePathForTest(context);
    if (!persistent_state_path.empty())
    {
        std::error_code remove_ec;
        std::filesystem::remove(persistent_state_path, remove_ec);
    }
    constexpr std::uint64_t kCheckpointXidOffset = 0x10;
    constexpr std::uint64_t kSecondaryCheckpointXidOffset = kBlockSize + kCheckpointXidOffset;
    constexpr std::uint64_t kRenamedTimestampUtc = 133444736000000000ull;
    const auto renamed_payload = BuildPatternPayload(8192, 0x21);
    const auto reuse_payload = BuildPatternPayload(777, 0x57);
    const auto resized_reuse_payload = BuildPatternPayload(1024, 0x7C);

    ScopedEnvironmentVariable perf_counters(L"APFSACCESS_PERF_COUNTERS", L"1");

    ok &= TestBlockDeviceOffsetIo(run_root);
    ok &= TestBlockDeviceConcurrentUnalignedReadsUseThreadLocalScratch(run_root);
    ok &= TestBlockDeviceReadCacheDisabledByDefault(run_root);
    ok &= TestBlockDeviceReadCacheRejectsNonOptInValues(run_root);
    ok &= TestBlockDeviceReadCacheInvalidatesAfterWrite(run_root);
    ok &= TestBlockDeviceReadCacheMissDoesNotReinsertAfterConcurrentWrite(run_root);
    ok &= TestBlockDeviceReadCacheMissStartedDuringWriteDoesNotSurvive(run_root);
    ok &= TestBlockDeviceWriteBatchMissDoesNotReinsertAfterConcurrentWrite(run_root);
    ok &= TestBlockDeviceReadCacheHookExceptionRecoversEpoch(run_root);
    ok &= TestBlockDeviceWriteInvalidationHookRunsWithoutProductionLocks(run_root);
    ok &= TestBlockDeviceReadCacheHitIsNotAdmittedDuringWrite(run_root);
    ok &= TestBlockDeviceReadCacheQuotaIsBounded(run_root);
    ok &= TestBlockDeviceReadCacheServesContainedRange(run_root);
    ok &= TestBlockDeviceWriteBatchMergesAdjacentWrites(run_root);
    ok &= TestBlockDeviceWriteBatchGroupsNearbyUnalignedSpans(run_root);
    ok &= TestBlockDeviceWriteBatchAvoidsLargeMergedBuffer(run_root);
    ok &= TestBlockDeviceWriteBatchMergesSmallAdjacentRunInBoundedChunks(run_root);
    ok &= TestBlockDeviceWriteBatchUsesContiguousMergeView(run_root);
    ok &= TestBlockDeviceWriteBatchUsesAsyncForAlignedDefaultBatch(run_root);
    ok &= TestBlockDeviceWriteBatchAsyncWritesLargeAdjacentSpansDirectly(run_root);
    ok &= TestBlockDeviceWriteBatchAsyncReusesMergedScratch(run_root);
    ok &= TestBlockDeviceWriteBatchDisableSwitchKeepsSynchronousBatch(run_root);
    ok &= TestBlockDeviceWriteBatchAsyncWritesAlignedDisjointSpans(run_root);
    ok &= TestBlockDeviceWriteBatchAsyncSplitsSingleLargeSpan(run_root);
    ok &= TestBlockDeviceAsyncFailureStopsLaterWrites(run_root);
    std::uint64_t final_committed_xid = 0;
    std::uint64_t previous_committed_xid = 0;
    {
        apfsaccess::rw::MetadataStore store(context);
        ok &= Require(store.LoadContainerSuperblocks(), "LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "PrepareNativeWritePath should succeed");
        ok &= Require(
            !store.FreeExtent(static_cast<std::uint64_t>(kBlockSize), static_cast<std::uint64_t>(kBlockSize)),
            "FreeExtent should reject ranges that overlap reserved metadata blocks");
        ok &= Require(
            !store.FreeExtent(static_cast<std::uint64_t>(kBlockSize) + 1, static_cast<std::uint64_t>(kBlockSize)),
            "FreeExtent should reject non-aligned physical offsets");
        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }
                const auto target_size = static_cast<std::size_t>(logical_size);
                if (payload.size() < target_size)
                {
                    payload.resize(target_size, std::byte{0});
                }
                else if (payload.size() > target_size)
                {
                    payload.resize(target_size);
                }
                return payload;
            });

        apfsaccess::rw::MetadataStore::MutationRequest create_request{};
        create_request.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateDirectory;
        create_request.path = L"\\docs";
        ok &= Require(
            store.ApplyMutation(create_request) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "CreateDirectory mutation should apply");

        create_request.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateDirectory;
        create_request.path = L"\\docs\\nested";
        ok &= Require(
            store.ApplyMutation(create_request) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Nested directory create mutation should apply");

        apfsaccess::rw::MetadataStore::MutationRequest invalid_cycle_rename{};
        invalid_cycle_rename.operation = apfsaccess::rw::MetadataStore::MutationOperation::Rename;
        invalid_cycle_rename.path = L"\\docs";
        invalid_cycle_rename.secondary_path = L"\\docs\\nested\\docs";
        ok &= Require(
            store.ApplyMutation(invalid_cycle_rename) == apfsaccess::rw::MetadataStore::MutationStatus::InvalidRequest,
            "Renaming directory into its own descendant should be rejected");

        create_request.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_request.path = L"\\docs\\smoke.txt";
        ok &= Require(
            store.ApplyMutation(create_request) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "CreateFile mutation should apply");

        apfsaccess::rw::MetadataStore::MutationRequest duplicate_case_create{};
        duplicate_case_create.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        duplicate_case_create.path = L"\\DOCS\\SMOKE.TXT";
        ok &= Require(
            store.ApplyMutation(duplicate_case_create) == apfsaccess::rw::MetadataStore::MutationStatus::InvalidRequest,
            "Case-insensitive duplicate create should be rejected");

        apfsaccess::rw::MetadataStore::MutationRequest write_request{};
        write_request.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_request.path = L"\\DOCS\\SMOKE.TXT";
        write_request.offset = 0;
        write_request.length = 8192;
        ok &= Require(
            store.ApplyMutation(write_request) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Write mutation should apply");

        apfsaccess::rw::MetadataStore::MutationRequest rename_request{};
        rename_request.operation = apfsaccess::rw::MetadataStore::MutationOperation::Rename;
        rename_request.path = L"\\DoCs\\SmOkE.TxT";
        rename_request.secondary_path = L"\\docs\\renamed.txt";
        ok &= Require(
            store.ApplyMutation(rename_request) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Rename mutation should apply");

        apfsaccess::rw::MetadataStore::MutationRequest case_only_rename{};
        case_only_rename.operation = apfsaccess::rw::MetadataStore::MutationOperation::Rename;
        case_only_rename.path = L"\\docs\\renamed.txt";
        case_only_rename.secondary_path = L"\\DOCS\\RENAMED.TXT";
        ok &= Require(
            store.ApplyMutation(case_only_rename) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Case-only rename mutation should apply");

        apfsaccess::rw::MetadataStore::MutationRequest set_basic_info{};
        set_basic_info.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetBasicInfo;
        set_basic_info.path = L"\\DOCS\\RENAMED.TXT";
        set_basic_info.timestamp_utc = kRenamedTimestampUtc;
        ok &= Require(
            store.ApplyMutation(set_basic_info) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "SetBasicInfo mutation should apply to renamed file");

        apfsaccess::rw::MetadataStore::MutationRequest scratch_file{};
        scratch_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        scratch_file.path = L"\\scratch.tmp";
        ok &= Require(
            store.ApplyMutation(scratch_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Scratch create mutation should apply");

        apfsaccess::rw::MetadataStore::MutationRequest delete_request{};
        delete_request.operation = apfsaccess::rw::MetadataStore::MutationOperation::Delete;
        delete_request.path = L"\\scratch.tmp";
        ok &= Require(
            store.ApplyMutation(delete_request) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Delete mutation should apply");
        ok &= Require(store.PendingBtreeRecordCount() > 0, "Pending btree records should be staged before commit");
        staged_payloads[L"\\docs\\renamed.txt"] = renamed_payload;
        staged_payloads[L"\\DOCS\\RENAMED.TXT"] = renamed_payload;

        const auto first_commit = store.CommitPendingMutations();
        if (first_commit != apfsaccess::rw::MetadataStore::CommitStatus::Committed)
        {
            std::cerr << "[DEBUG] first commit status: " << CommitStatusToString(first_commit) << std::endl;
        }
        ok &= Require(
            first_commit == apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "CommitPendingMutations should commit");
        ok &= Require(store.LastCommittedXid().has_value(), "LastCommittedXid should be set");
        ok &= Require(store.LastCommittedXid().value_or(0) == (kInitialCheckpointXid + 1), "Committed xid should advance");
        ok &= Require(store.CommittedObjectCount() > 0, "Committed object map should have entries");
        ok &= Require(store.CommittedAllocationCount() > 0, "Committed allocations should have entries");
        const auto committed_allocations_after_first_commit = store.CommittedAllocationCount();
        ok &= Require(store.CommittedInodeCount() >= 4, "Committed inode table should include root/docs/nested/renamed");
        ok &= Require(store.PendingBtreeRecordCount() == 0, "Pending btree records should be cleared after commit");
        ok &= Require(store.CommittedBtreeRecordCount() > 0, "Committed btree record list should have entries");
        ok &= Require(!store.LookupCommittedInodeByPath(L"\\docs\\smoke.txt").has_value(), "Original pre-rename path should not exist");
        auto renamed = store.LookupCommittedInodeByPath(L"\\docs\\renamed.txt");
        ok &= Require(renamed.has_value(), "Renamed file path should exist");
        ok &= Require(
            store.LookupCommittedInodeByPath(L"\\DOCS\\RENAMED.TXT").has_value(),
            "LookupCommittedInodeByPath should be case-insensitive");
        ok &= Require(
            renamed->full_path == L"\\DOCS\\RENAMED.TXT",
            "Case-only rename should preserve requested destination casing");
        ok &= Require(!renamed->is_directory, "Renamed entry should be file inode");
        ok &= Require(renamed->logical_size >= 8192, "Renamed file logical size should persist");
        ok &= Require(
            renamed->timestamp_utc == kRenamedTimestampUtc,
            "SetBasicInfo timestamp should persist in committed inode state");
        {
            std::vector<std::byte> persisted_payload;
            ok &= Require(
                ReadBytesFromImage(image_path, renamed->data_physical_address, renamed_payload.size(), persisted_payload),
                "Renamed file payload should be readable from committed extent");
            ok &= Require(
                persisted_payload == renamed_payload,
                "Renamed file payload bytes should persist in committed extent");
        }
        {
            const auto committed_snapshot = store.SnapshotCommittedInodes();
            ok &= Require(
                std::any_of(
                    committed_snapshot.begin(),
                    committed_snapshot.end(),
                    [](const apfsaccess::rw::MetadataStore::InodeRecord& inode)
                    {
                        return inode.full_path == L"\\DOCS\\RENAMED.TXT" && !inode.is_directory;
                    }),
                "Committed inode snapshot should include renamed file");

            std::vector<std::byte> payload_window;
            ok &= Require(
                store.ReadCommittedFileRange(L"\\docs\\renamed.txt", 1024, 2048, payload_window),
                "ReadCommittedFileRange should succeed for renamed file window");
            ok &= Require(payload_window.size() == 2048, "ReadCommittedFileRange should return requested window size");
            ok &= Require(
                std::equal(payload_window.begin(), payload_window.end(), renamed_payload.begin() + 1024),
                "ReadCommittedFileRange window should match persisted renamed payload bytes");

            std::vector<std::byte> beyond_eof;
            ok &= Require(
                store.ReadCommittedFileRange(L"\\docs\\renamed.txt", 999999, 64, beyond_eof),
                "ReadCommittedFileRange should succeed past EOF with empty payload");
            ok &= Require(beyond_eof.empty(), "ReadCommittedFileRange past EOF should return empty payload");
        }
        ok &= Require(!store.LookupCommittedInodeByPath(L"\\scratch.tmp").has_value(), "Deleted scratch path should not exist");

        apfsaccess::rw::MetadataStore::MutationRequest ephemeral_create{};
        ephemeral_create.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        ephemeral_create.path = L"\\temp.bin";
        ok &= Require(
            store.ApplyMutation(ephemeral_create) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Ephemeral file create mutation should apply");

        apfsaccess::rw::MetadataStore::MutationRequest ephemeral_write{};
        ephemeral_write.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        ephemeral_write.path = L"\\temp.bin";
        ephemeral_write.offset = 0;
        ephemeral_write.length = 1234;
        ok &= Require(
            store.ApplyMutation(ephemeral_write) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Ephemeral file write mutation should apply");
        const auto pending_allocations_before_ephemeral_delete = store.PendingAllocationCount();
        ok &= Require(
            pending_allocations_before_ephemeral_delete > 0,
            "Ephemeral file write should stage pending storage before delete");

        apfsaccess::rw::MetadataStore::MutationRequest ephemeral_delete{};
        ephemeral_delete.operation = apfsaccess::rw::MetadataStore::MutationOperation::Delete;
        ephemeral_delete.path = L"\\temp.bin";
        ok &= Require(
            store.ApplyMutation(ephemeral_delete) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Ephemeral file delete mutation should apply");
        ok &= Require(
            store.PendingAllocationCount() == 0,
            "Ephemeral file delete should release never-committed pending storage before second commit");
        ok &= Require(
            store.PendingSpacemanAllocationIndexCount() == 0,
            "Ephemeral file delete should keep pending storage index empty before second commit");
        ok &= Require(
            store.PendingDeallocationCount() == 0,
            "Ephemeral file delete should not stage media deallocation for never-committed storage");
        ok &= Require(
            store.PendingPayloadByteEstimate() == 0,
            "Ephemeral file delete should clear pending payload accounting before second commit");

        const auto second_commit = store.CommitPendingMutations();
        if (second_commit != apfsaccess::rw::MetadataStore::CommitStatus::Committed)
        {
            std::cerr << "[DEBUG] second commit status: " << CommitStatusToString(second_commit) << std::endl;
        }
        ok &= Require(
            second_commit == apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "Second CommitPendingMutations should commit");
        ok &= Require(
            store.CommittedAllocationCount() >= committed_allocations_after_first_commit,
            "Second commit should preserve committed allocation accounting after ephemeral file delete");
        ok &= Require(!store.LookupCommittedInodeByPath(L"\\temp.bin").has_value(), "Ephemeral file should not persist after delete");

        apfsaccess::rw::MetadataStore::MutationRequest reuse_create{};
        reuse_create.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        reuse_create.path = L"\\reuse.bin";
        ok &= Require(
            store.ApplyMutation(reuse_create) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Reuse file create mutation should apply");

        apfsaccess::rw::MetadataStore::MutationRequest reuse_write{};
        reuse_write.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        reuse_write.path = L"\\reuse.bin";
        reuse_write.offset = 0;
        reuse_write.length = 777;
        ok &= Require(
            store.ApplyMutation(reuse_write) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Reuse file write mutation should apply");
        staged_payloads[L"\\reuse.bin"] = reuse_payload;

        const auto third_commit = store.CommitPendingMutations();
        if (third_commit != apfsaccess::rw::MetadataStore::CommitStatus::Committed)
        {
            std::cerr << "[DEBUG] third commit status: " << CommitStatusToString(third_commit) << std::endl;
        }
        ok &= Require(
            third_commit == apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "Third CommitPendingMutations should commit");
        ok &= Require(
            store.CommittedAllocationCount() > 0,
            "Third commit should keep committed allocation coverage after coalescing records");
        auto reuse_inode = store.LookupCommittedInodeByPath(L"\\reuse.bin");
        ok &= Require(reuse_inode.has_value(), "Reuse file should persist");
        ok &= Require(reuse_inode->logical_size >= 777, "Reuse file logical size should persist");
        {
            std::vector<std::byte> persisted_payload;
            ok &= Require(
                ReadBytesFromImage(image_path, reuse_inode->data_physical_address, reuse_payload.size(), persisted_payload),
                "Reuse file payload should be readable from committed extent");
        ok &= Require(
            persisted_payload == reuse_payload,
            "Reuse file payload bytes should persist in committed extent");
        }

        for (int index = 0; index < 2600; ++index)
        {
            auto path = L"\\storm-" + std::to_wstring(index) + L".bin";

            apfsaccess::rw::MetadataStore::MutationRequest storm_create{};
            storm_create.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateDirectory;
            storm_create.path = path;
            ok &= Require(
                store.ApplyMutation(storm_create) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
                "Storm directory create mutation should apply");
        }
        const auto storm_commit = store.CommitPendingMutations();
        if (storm_commit != apfsaccess::rw::MetadataStore::CommitStatus::Committed)
        {
            std::cerr << "[DEBUG] metadata-only storm commit status: " << CommitStatusToString(storm_commit) << std::endl;
            std::cerr << "[DEBUG] metadata-only storm commit stage: " << store.LastCommitStage() << std::endl;
            const auto recovery_reason = store.RecoveryReason();
            if (!recovery_reason.empty())
            {
                std::wcerr << L"[DEBUG] metadata-only storm recovery reason: " << recovery_reason << std::endl;
            }
        }
        ok &= Require(
            storm_commit == apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "Metadata-only storm CommitPendingMutations should commit past compact checkpoint capacity");
        ok &= Require(
            store.CommittedAllocationCount() < 128,
            "Storm metadata-only commits should avoid data allocation churn");
        const auto free_size_after_storm = store.FreeSizeBytes();
        ok &= Require(
            free_size_after_storm.has_value(),
            "Storm FreeSizeBytes should remain available for Explorer volume info");
        ok &= Require(
            free_size_after_storm.value_or(0) > (kContainerBytes / 2),
            "Storm FreeSizeBytes should report remaining container headroom, not only reusable freed extents");

        apfsaccess::rw::MetadataStore::MutationRequest resize_reuse{};
        resize_reuse.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetFileSize;
        resize_reuse.path = L"\\reuse.bin";
        resize_reuse.length = static_cast<std::uint64_t>(resized_reuse_payload.size());
        ok &= Require(
            store.ApplyMutation(resize_reuse) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Reuse file resize mutation should apply");
        staged_payloads[L"\\reuse.bin"] = resized_reuse_payload;

        const auto fourth_commit = store.CommitPendingMutations();
        if (fourth_commit != apfsaccess::rw::MetadataStore::CommitStatus::Committed)
        {
            std::cerr << "[DEBUG] fourth commit status: " << CommitStatusToString(fourth_commit) << std::endl;
        }
        ok &= Require(
            fourth_commit == apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "Fourth CommitPendingMutations should commit");
        final_committed_xid = store.LastCommittedXid().value_or(0);
        previous_committed_xid = final_committed_xid > 0 ? final_committed_xid - 1 : 0;
        auto resized_reuse_inode = store.LookupCommittedInodeByPath(L"\\reuse.bin");
        ok &= Require(resized_reuse_inode.has_value(), "Resized reuse file should persist");
        ok &= Require(
            resized_reuse_inode->logical_size == static_cast<std::uint64_t>(resized_reuse_payload.size()),
            "Resized reuse file logical size should persist");
        {
            std::vector<std::byte> persisted_payload;
            ok &= Require(
                ReadBytesFromImage(
                    image_path,
                    resized_reuse_inode->data_physical_address,
                    resized_reuse_payload.size(),
                    persisted_payload),
                "Resized reuse payload should be readable from committed extent");
            ok &= Require(
                persisted_payload == resized_reuse_payload,
                "Resized reuse payload bytes should persist in committed extent");
        }

        const auto object_map_checkpoints = CollectObjectMapCheckpointSummaries(
            image_path,
            kTotalBlocks);
        ok &= Require(
            !object_map_checkpoints.empty(),
            "Object-map checkpoint block should be persisted to the native checkpoint band");
        auto object_map_latest = SelectLatestCheckpointSummary(
            object_map_checkpoints,
            [](const ObjectMapCheckpointSummary& summary)
            {
                return summary.checkpoint_xid;
            });
        ok &= Require(object_map_latest.has_value(), "Object-map latest checkpoint should be discoverable");
        if (object_map_latest.has_value())
        {
            ok &= Require(
                object_map_latest->second.checkpoint_xid == store.LastCommittedXid().value_or(0),
                "Object-map checkpoint xid should match last committed xid");
            ok &= Require(
                object_map_latest->second.entry_count == static_cast<std::uint32_t>(store.CommittedObjectCount()),
                "Object-map checkpoint entry count should match committed object map size");
        }
        ok &= Require(
            object_map_checkpoints.size() >= 1,
            "Object-map checkpoint slot rotation should persist latest slot copy");
        if (object_map_latest.has_value() && object_map_latest->second.checkpoint_xid > 0)
        {
            bool has_previous_slot = false;
            for (const auto& checkpoint : object_map_checkpoints)
            {
                if (checkpoint.second.checkpoint_xid + 1 == object_map_latest->second.checkpoint_xid)
                {
                    has_previous_slot = true;
                    break;
                }
            }
            ok &= Require(
                has_previous_slot,
                "Object-map checkpoint slot rotation should retain previous xid copy");
        }

        const auto spaceman_scan_end = std::min<std::uint64_t>(kTotalBlocks - 1, kNativeCheckpointBandStart + kNativeInodeCheckpointOffset - 1);
        auto spaceman_checkpoints = CollectCheckpointSummaries<SpacemanCheckpointSummary>(
            image_path,
            kNativeCheckpointBandStart + kNativeSpacemanCheckpointOffset,
            spaceman_scan_end,
            ReadSpacemanCheckpointSummary);
        if constexpr (kNativeCheckpointBandStart >= kNativeCheckpointExtensionBlocks)
        {
            const auto extension_start = kNativeCheckpointBandStart - kNativeCheckpointExtensionBlocks;
            if constexpr (extension_start >= kNativeMinimumSpacemanExtensionStartBlock)
            {
                AppendCheckpointSummaries(
                    spaceman_checkpoints,
                    image_path,
                    extension_start + kNativeSpacemanExtensionOffset,
                    std::min<std::uint64_t>(
                        kTotalBlocks - 1,
                        extension_start + kNativeSpacemanExtensionOffset + kNativeSpacemanExtensionBlocks - 1),
                    ReadSpacemanCheckpointSummary);
            }
        }
        ok &= Require(
            !spaceman_checkpoints.empty(),
            "Spaceman checkpoint block should be persisted to the native checkpoint band");
        auto spaceman_latest = SelectLatestCheckpointSummary(
            spaceman_checkpoints,
            [](const SpacemanCheckpointSummary& summary)
            {
                return summary.checkpoint_xid;
            });
        ok &= Require(spaceman_latest.has_value(), "Spaceman latest checkpoint should be discoverable");
        if (spaceman_latest.has_value())
        {
            ok &= Require(
                spaceman_latest->second.checkpoint_xid == store.LastCommittedXid().value_or(0),
                "Spaceman checkpoint xid should match last committed xid");
            ok &= Require(
                spaceman_latest->second.allocation_count == static_cast<std::uint32_t>(store.CommittedAllocationCount()),
                "Spaceman checkpoint allocation count should match committed allocation list");
            ok &= Require(
                spaceman_latest->second.free_extent_count == static_cast<std::uint32_t>(store.CommittedFreeExtentCount()),
                "Spaceman checkpoint free extent count should match committed free extent list");
        }
        ok &= Require(
            spaceman_checkpoints.size() >= 1,
            "Spaceman checkpoint slot rotation should persist latest slot copy");

        const auto inode_checkpoints = CollectInodeCheckpointSummaries(
            image_path,
            kTotalBlocks,
            kVolumeRootObject + 1);
        ok &= Require(
            !inode_checkpoints.empty(),
            "Inode checkpoint block should be persisted to the native checkpoint band");
        auto inode_latest = SelectLatestCheckpointSummary(
            inode_checkpoints,
            [](const InodeCheckpointSummary& summary)
            {
                return summary.checkpoint_xid;
            });
        ok &= Require(inode_latest.has_value(), "Inode latest checkpoint should be discoverable");
        if (inode_latest.has_value())
        {
            ok &= Require(
                inode_latest->second.checkpoint_xid == store.LastCommittedXid().value_or(0),
                "Inode checkpoint xid should match last committed xid");
            ok &= Require(
                inode_latest->second.inode_count == static_cast<std::uint32_t>(store.CommittedInodeCount()),
                "Inode checkpoint count should match committed inode table size");
        }
        ok &= Require(
            inode_checkpoints.size() >= 1,
            "Inode checkpoint slot rotation should persist latest slot copy");

        const auto btree_checkpoints = CollectBtreeCheckpointSummaries(
            image_path,
            kTotalBlocks);
        ok &= Require(
            !btree_checkpoints.empty(),
            "Btree checkpoint block should be persisted to the native checkpoint band");
        auto btree_latest = SelectLatestCheckpointSummary(
            btree_checkpoints,
            [](const BtreeCheckpointSummary& summary)
            {
                return summary.checkpoint_xid;
            });
        ok &= Require(btree_latest.has_value(), "Btree latest checkpoint should be discoverable");
        if (btree_latest.has_value())
        {
            ok &= Require(
                btree_latest->second.checkpoint_xid == store.LastCommittedXid().value_or(0),
                "Btree checkpoint xid should match last committed xid");
            ok &= Require(
                btree_latest->second.record_count == static_cast<std::uint32_t>(store.CommittedBtreeRecordCount()),
                "Btree checkpoint record count should match committed btree record list size");
        }
        ok &= Require(
            btree_checkpoints.size() >= 1,
            "Btree checkpoint slot rotation should persist latest slot copy");
    }

    {
        apfsaccess::rw::MetadataStore remounted(context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "Remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "Remount PrepareNativeWritePath should succeed");
        ok &= Require(!remounted.IsRecoveryRequired(), "Remount should not require recovery in clean path");
        ok &= Require(remounted.IsCommitPathReady(), "Remount commit path should remain ready in clean path");
        ok &= Require(remounted.LastCommittedXid().has_value(), "Remount should load committed xid");
        ok &= Require(remounted.LastCommittedXid().value_or(0) == final_committed_xid, "Remount xid should persist");
        ok &= Require(remounted.CommittedObjectCount() > 0, "Remount object map state should persist");
        ok &= Require(remounted.CommittedAllocationCount() > 0, "Remount spaceman state should persist");
        ok &= Require(remounted.CommittedInodeCount() >= 4, "Remount inode table should persist");
        ok &= Require(remounted.CommittedBtreeRecordCount() > 0, "Remount btree record list should persist");
        ok &= Require(!remounted.LookupCommittedInodeByPath(L"\\docs\\smoke.txt").has_value(), "Remount old pre-rename path should stay absent");
        auto remounted_renamed = remounted.LookupCommittedInodeByPath(L"\\docs\\renamed.txt");
        ok &= Require(remounted_renamed.has_value(), "Remount renamed file path should persist");
        ok &= Require(
            remounted.LookupCommittedInodeByPath(L"\\DOCS\\RENAMED.TXT").has_value(),
            "Remount case-insensitive lookup for renamed file should succeed");
        ok &= Require(
            remounted_renamed->full_path == L"\\DOCS\\RENAMED.TXT",
            "Remount should preserve case-only rename destination casing");
        ok &= Require(
            remounted_renamed->timestamp_utc == kRenamedTimestampUtc,
            "Remount should preserve SetBasicInfo timestamp");
        auto remounted_reuse = remounted.LookupCommittedInodeByPath(L"\\reuse.bin");
        ok &= Require(remounted_reuse.has_value(), "Remount reuse file should persist");
        {
            auto committed_snapshot = remounted.SnapshotCommittedInodes();
            ok &= Require(
                !committed_snapshot.empty(),
                "Remount committed inode snapshot should not be empty");
            ok &= Require(
                std::any_of(
                    committed_snapshot.begin(),
                    committed_snapshot.end(),
                    [](const apfsaccess::rw::MetadataStore::InodeRecord& inode)
                    {
                        return inode.full_path == L"\\DOCS\\RENAMED.TXT";
                    }),
                "Remount committed inode snapshot should include renamed file");
        }
        {
            std::vector<std::byte> persisted_payload;
            ok &= Require(
                ReadBytesFromImage(image_path, remounted_renamed->data_physical_address, renamed_payload.size(), persisted_payload),
                "Remount renamed payload should be readable from committed extent");
            ok &= Require(
                persisted_payload == renamed_payload,
                "Remount renamed payload bytes should remain intact");
        }
        {
            std::vector<std::byte> remounted_window;
            ok &= Require(
                remounted.ReadCommittedFileRange(L"\\docs\\renamed.txt", 512, 1536, remounted_window),
                "Remount ReadCommittedFileRange should succeed for renamed file");
            ok &= Require(remounted_window.size() == 1536, "Remount ReadCommittedFileRange should return requested window size");
            ok &= Require(
                std::equal(remounted_window.begin(), remounted_window.end(), renamed_payload.begin() + 512),
                "Remount ReadCommittedFileRange bytes should match renamed payload window");
        }
        {
            std::vector<std::byte> persisted_payload;
            ok &= Require(
                ReadBytesFromImage(image_path, remounted_reuse->data_physical_address, resized_reuse_payload.size(), persisted_payload),
                "Remount reuse payload should be readable from committed extent");
            ok &= Require(
                persisted_payload == resized_reuse_payload,
                "Remount reuse payload bytes should reflect resized payload");
        }
        ok &= Require(!remounted.LookupCommittedInodeByPath(L"\\scratch.tmp").has_value(), "Remount deleted file path should stay absent");
        ok &= Require(!remounted.LookupCommittedInodeByPath(L"\\temp.bin").has_value(), "Remount ephemeral file path should stay absent");
        ok &= Require(
            remounted.CheckpointXid().has_value() &&
                remounted.CheckpointXid().value_or(0) == final_committed_xid,
            "Remount checkpoint xid should persist");
        auto raw_checkpoint_xid = ReadLe64FromImage(image_path, kCheckpointXidOffset);
        ok &= Require(raw_checkpoint_xid.has_value(), "Checkpoint xid should be readable from container image");
        auto raw_checkpoint_xid_secondary = ReadLe64FromImage(image_path, kSecondaryCheckpointXidOffset);
        ok &= Require(raw_checkpoint_xid_secondary.has_value(), "Secondary checkpoint xid should be readable from container image");
        ok &= Require(
            std::max(raw_checkpoint_xid.value_or(0), raw_checkpoint_xid_secondary.value_or(0)) == final_committed_xid,
            "Highest container superblock checkpoint xid should be updated on commit");
        ok &= Require(
            std::min(raw_checkpoint_xid.value_or(0), raw_checkpoint_xid_secondary.value_or(0)) == previous_committed_xid,
            "Checkpoint switch scaffold should alternate superblock slots");
        std::vector<std::byte> primary_superblock;
        std::vector<std::byte> secondary_superblock;
        const auto primary_read = ReadBytesFromImage(image_path, 0, kBlockSize, primary_superblock);
        const auto secondary_read = ReadBytesFromImage(
            image_path,
            static_cast<std::uint64_t>(kBlockSize),
            kBlockSize,
            secondary_superblock);
        ok &= Require(primary_read && secondary_read, "Container superblocks should be readable for checksum validation");
        if (primary_read && secondary_read)
        {
            const auto& latest_superblock = raw_checkpoint_xid.value_or(0) >= raw_checkpoint_xid_secondary.value_or(0)
                ? primary_superblock
                : secondary_superblock;
            ok &= Require(
                HasValidApfsObjectChecksum(latest_superblock),
                "Newest container superblock should carry a valid APFS object checksum");
        }
    }

    const auto disk_state_only_image_path = run_root / "container_disk_state_only.apfs.img";
    if (!CreateSyntheticContainer(disk_state_only_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for disk-state-only scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext disk_state_only_context
    {
        disk_state_only_image_path.wstring(),
        L"DiskStateOnly",
    };
    std::size_t disk_state_only_committed_object_count = 0;
    std::size_t disk_state_only_committed_allocation_count = 0;
    std::size_t disk_state_only_committed_free_extent_count = 0;
    std::size_t disk_state_only_committed_inode_count = 0;
    std::size_t disk_state_only_committed_btree_count = 0;
    const auto disk_state_only_payload = BuildPatternPayload(1024, 0xB4);
    {
        apfsaccess::rw::MetadataStore store(disk_state_only_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Disk-state-only LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Disk-state-only LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Disk-state-only LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Disk-state-only PrepareNativeWritePath should succeed");

        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }
                const auto target_size = static_cast<std::size_t>(logical_size);
                if (payload.size() < target_size)
                {
                    payload.resize(target_size, std::byte{0});
                }
                else if (payload.size() > target_size)
                {
                    payload.resize(target_size);
                }
                return payload;
            });

        apfsaccess::rw::MetadataStore::MutationRequest create_file{};
        create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_file.path = L"\\diskonly.bin";
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Disk-state-only create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\diskonly.bin";
        write_file.length = 1024;
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Disk-state-only write file should apply");
        staged_payloads[L"\\diskonly.bin"] = disk_state_only_payload;

        const auto disk_state_only_commit = store.CommitPendingMutations();
        ok &= Require(
            disk_state_only_commit == apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "Disk-state-only commit should succeed");
        ok &= Require(
            store.LastCommittedXid().value_or(0) == (kInitialCheckpointXid + 1),
            "Disk-state-only commit should advance xid");

        disk_state_only_committed_object_count = store.CommittedObjectCount();
        disk_state_only_committed_allocation_count = store.CommittedAllocationCount();
        disk_state_only_committed_free_extent_count = store.CommittedFreeExtentCount();
        disk_state_only_committed_inode_count = store.CommittedInodeCount();
        disk_state_only_committed_btree_count = store.CommittedBtreeRecordCount();
    }

    const auto disk_state_only_path = BuildPersistentStatePathForTest(disk_state_only_context);
    if (!disk_state_only_path.empty())
    {
        std::error_code remove_ec;
        std::filesystem::remove(disk_state_only_path, remove_ec);
    }

    {
        apfsaccess::rw::MetadataStore remounted_disk_state_only(disk_state_only_context);
        ok &= Require(remounted_disk_state_only.LoadContainerSuperblocks(), "Disk-state-only remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted_disk_state_only.PrepareNativeWritePath(), "Disk-state-only remount PrepareNativeWritePath should succeed");
        ok &= Require(!remounted_disk_state_only.IsRecoveryRequired(), "Disk-state-only remount should not require recovery");
        ok &= Require(remounted_disk_state_only.IsCommitPathReady(), "Disk-state-only remount commit path should remain ready");
        ok &= Require(
            remounted_disk_state_only.LastCommittedXid().value_or(0) == (kInitialCheckpointXid + 1),
            "Disk-state-only remount should preserve xid from on-disk checkpoints");
        ok &= Require(
            remounted_disk_state_only.CommittedObjectCount() == disk_state_only_committed_object_count,
            "Disk-state-only remount should preserve committed object-map count from checkpoint block");
        ok &= Require(
            remounted_disk_state_only.CommittedAllocationCount() == disk_state_only_committed_allocation_count,
            "Disk-state-only remount should preserve committed allocation count from checkpoint block");
        ok &= Require(
            remounted_disk_state_only.CommittedFreeExtentCount() == disk_state_only_committed_free_extent_count,
            "Disk-state-only remount should preserve committed free-extent count from checkpoint block");
        ok &= Require(
            remounted_disk_state_only.CommittedInodeCount() == disk_state_only_committed_inode_count,
            "Disk-state-only remount should preserve committed inode count from checkpoint block");
        ok &= Require(
            remounted_disk_state_only.CommittedBtreeRecordCount() == disk_state_only_committed_btree_count,
            "Disk-state-only remount should preserve committed btree record count from checkpoint block");
        auto disk_state_only_inode = remounted_disk_state_only.LookupCommittedInodeByPath(L"\\diskonly.bin");
        ok &= Require(
            disk_state_only_inode.has_value(),
            "Disk-state-only remount should preserve inode path exposure from checkpoint block");
        if (disk_state_only_inode.has_value())
        {
            std::vector<std::byte> disk_state_only_window;
            ok &= Require(
                remounted_disk_state_only.ReadCommittedFileRange(L"\\diskonly.bin", 0, disk_state_only_payload.size(), disk_state_only_window),
                "Disk-state-only remount should read persisted payload range");
            ok &= Require(
                disk_state_only_window == disk_state_only_payload,
                "Disk-state-only remount payload should match committed bytes");
        }
    }

    const auto canonical_non_fixture_disk_authoritative_fixture_image_path =
        run_root / "container_canonical_nonfixture_disk_authoritative_fixture.apfs.img";
    if (!CreateSyntheticContainer(canonical_non_fixture_disk_authoritative_fixture_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for canonical-nonfixture-disk-authoritative scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext canonical_non_fixture_disk_authoritative_fixture_context
    {
        canonical_non_fixture_disk_authoritative_fixture_image_path.wstring(),
        L"CanonicalNonFixtureDiskAuthoritativeFixture",
    };
    const auto canonical_non_fixture_first_payload = BuildPatternPayload(768, 0x93);
    const auto canonical_non_fixture_second_payload = BuildPatternPayload(1536, 0xA6);
    const auto canonical_non_fixture_sidecar_snapshot_path =
        run_root / "canonical_nonfixture_disk_authoritative_stale_state.bin";

    {
        apfsaccess::rw::MetadataStore store(canonical_non_fixture_disk_authoritative_fixture_context);
        ok &= Require(
            store.LoadContainerSuperblocks(),
            "Canonical-nonfixture-disk-authoritative fixture LoadContainerSuperblocks should succeed");
        ok &= Require(
            store.LoadObjectMap(),
            "Canonical-nonfixture-disk-authoritative fixture LoadObjectMap should succeed");
        ok &= Require(
            store.LoadSpacemanState(),
            "Canonical-nonfixture-disk-authoritative fixture LoadSpacemanState should succeed");
        ok &= Require(
            store.PrepareNativeWritePath(),
            "Canonical-nonfixture-disk-authoritative fixture PrepareNativeWritePath should succeed");

        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }
                const auto target_size = static_cast<std::size_t>(logical_size);
                if (payload.size() < target_size)
                {
                    payload.resize(target_size, std::byte{0});
                }
                else if (payload.size() > target_size)
                {
                    payload.resize(target_size);
                }
                return payload;
            });

        apfsaccess::rw::MetadataStore::MutationRequest create_first{};
        create_first.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_first.path = L"\\first.bin";
        ok &= Require(
            store.ApplyMutation(create_first) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Canonical-nonfixture-disk-authoritative first create should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_first{};
        write_first.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_first.path = L"\\first.bin";
        write_first.length = static_cast<std::uint64_t>(canonical_non_fixture_first_payload.size());
        ok &= Require(
            store.ApplyMutation(write_first) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Canonical-nonfixture-disk-authoritative first write should apply");
        staged_payloads[L"\\first.bin"] = canonical_non_fixture_first_payload;

        const auto first_commit = store.CommitPendingMutations();
        ok &= Require(
            first_commit == apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "Canonical-nonfixture-disk-authoritative first commit should succeed");

        const auto fixture_sidecar_path =
            BuildPersistentStatePathForTest(canonical_non_fixture_disk_authoritative_fixture_context);
        ok &= Require(
            !fixture_sidecar_path.empty(),
            "Canonical-nonfixture-disk-authoritative should resolve fixture sidecar path");
        if (!fixture_sidecar_path.empty())
        {
            std::error_code snapshot_ec;
            std::filesystem::copy_file(
                fixture_sidecar_path,
                canonical_non_fixture_sidecar_snapshot_path,
                std::filesystem::copy_options::overwrite_existing,
                snapshot_ec);
            ok &= Require(
                !snapshot_ec,
                "Canonical-nonfixture-disk-authoritative should snapshot stale sidecar after first commit");
        }

        apfsaccess::rw::MetadataStore::MutationRequest create_second{};
        create_second.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_second.path = L"\\second.bin";
        ok &= Require(
            store.ApplyMutation(create_second) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Canonical-nonfixture-disk-authoritative second create should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_second{};
        write_second.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_second.path = L"\\second.bin";
        write_second.length = static_cast<std::uint64_t>(canonical_non_fixture_second_payload.size());
        ok &= Require(
            store.ApplyMutation(write_second) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Canonical-nonfixture-disk-authoritative second write should apply");
        staged_payloads[L"\\second.bin"] = canonical_non_fixture_second_payload;

        const auto second_commit = store.CommitPendingMutations();
        ok &= Require(
            second_commit == apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "Canonical-nonfixture-disk-authoritative second commit should succeed");
        ok &= Require(
            store.LastCommittedXid().value_or(0) == (kInitialCheckpointXid + 2),
            "Canonical-nonfixture-disk-authoritative second commit should advance xid");
    }

    const auto canonical_non_fixture_disk_authoritative_non_fixture_image_path =
        run_root / "container_canonical_nonfixture_disk_authoritative.bin";
    {
        std::error_code copy_ec;
        std::filesystem::copy_file(
            canonical_non_fixture_disk_authoritative_fixture_image_path,
            canonical_non_fixture_disk_authoritative_non_fixture_image_path,
            std::filesystem::copy_options::overwrite_existing,
            copy_ec);
        ok &= Require(
            !copy_ec,
            "Canonical-nonfixture-disk-authoritative should copy fixture image to non-fixture path");
    }

    apfsaccess::rw::MetadataStore::VolumeContext canonical_non_fixture_disk_authoritative_non_fixture_context
    {
        canonical_non_fixture_disk_authoritative_non_fixture_image_path.wstring(),
        L"CanonicalNonFixtureDiskAuthoritative",
    };
    std::filesystem::path canonical_non_fixture_injected_sidecar_path;
    {
        const auto non_fixture_sidecar_path =
            BuildPersistentStatePathForTest(canonical_non_fixture_disk_authoritative_non_fixture_context);
        canonical_non_fixture_injected_sidecar_path = non_fixture_sidecar_path;
        ok &= Require(
            !non_fixture_sidecar_path.empty(),
            "Canonical-nonfixture-disk-authoritative should resolve non-fixture sidecar path");
        if (!non_fixture_sidecar_path.empty())
        {
            std::error_code copy_sidecar_ec;
            std::filesystem::create_directories(non_fixture_sidecar_path.parent_path(), copy_sidecar_ec);
            copy_sidecar_ec.clear();
            std::filesystem::copy_file(
                canonical_non_fixture_sidecar_snapshot_path,
                non_fixture_sidecar_path,
                std::filesystem::copy_options::overwrite_existing,
                copy_sidecar_ec);
            ok &= Require(
                !copy_sidecar_ec,
                "Canonical-nonfixture-disk-authoritative should inject stale sidecar into non-fixture context");

            std::ofstream corrupt_sidecar(non_fixture_sidecar_path, std::ios::binary | std::ios::trunc);
            ok &= Require(
                corrupt_sidecar.good(),
                "Canonical-nonfixture-disk-authoritative should open non-fixture sidecar for corruption test");
            if (corrupt_sidecar.good())
            {
                constexpr std::array<char, 16> kCorruptMagic =
                {
                    'N', 'O', 'T', '_', 'A', 'P', 'F', 'S',
                    '_', 'S', 'T', 'A', 'T', 'E', '_', 'X',
                };
                corrupt_sidecar.write(kCorruptMagic.data(), static_cast<std::streamsize>(kCorruptMagic.size()));
                ok &= Require(
                    corrupt_sidecar.good(),
                    "Canonical-nonfixture-disk-authoritative should persist corrupted sidecar magic");
            }
        }
    }

    {
        apfsaccess::rw::MetadataStore remounted(canonical_non_fixture_disk_authoritative_non_fixture_context);
        ok &= Require(
            remounted.LoadContainerSuperblocks(),
            "Canonical-nonfixture-disk-authoritative remount LoadContainerSuperblocks should succeed");
        ok &= Require(
            remounted.PrepareNativeWritePath(),
            "Canonical-nonfixture-disk-authoritative remount PrepareNativeWritePath should succeed");
        ok &= Require(
            !remounted.IsRecoveryRequired(),
            "Canonical-nonfixture-disk-authoritative remount should ignore stale sidecar-behind state");
        ok &= Require(
            remounted.IsCommitPathReady(),
            "Canonical-nonfixture-disk-authoritative remount should keep commit path ready");
        ok &= Require(
            remounted.LastCommittedXid().value_or(0) == (kInitialCheckpointXid + 2),
            "Canonical-nonfixture-disk-authoritative remount should keep on-disk xid");
        ok &= Require(
            remounted.LookupCommittedInodeByPath(L"\\first.bin").has_value(),
            "Canonical-nonfixture-disk-authoritative remount should keep first committed file");
        ok &= Require(
            remounted.LookupCommittedInodeByPath(L"\\second.bin").has_value(),
            "Canonical-nonfixture-disk-authoritative remount should keep second committed file from disk checkpoints");
        std::vector<std::byte> second_payload_window;
        ok &= Require(
            remounted.ReadCommittedFileRange(
                L"\\second.bin",
                0,
                canonical_non_fixture_second_payload.size(),
                second_payload_window),
            "Canonical-nonfixture-disk-authoritative remount should read second file payload");
        ok &= Require(
            second_payload_window == canonical_non_fixture_second_payload,
            "Canonical-nonfixture-disk-authoritative remount should use disk-checkpoint payload, not stale sidecar snapshot");

        if (!canonical_non_fixture_injected_sidecar_path.empty())
        {
            std::error_code sidecar_ec;
            ok &= Require(
                std::filesystem::exists(canonical_non_fixture_injected_sidecar_path, sidecar_ec),
                "Canonical-nonfixture-disk-authoritative remount should not consume non-fixture sidecar file");
            auto corrupt_suffix = canonical_non_fixture_injected_sidecar_path;
            corrupt_suffix += L".corrupt";
            sidecar_ec.clear();
            ok &= Require(
                !std::filesystem::exists(corrupt_suffix, sidecar_ec),
                "Canonical-nonfixture-disk-authoritative remount should not create .corrupt sidecar marker for non-fixture path");
        }
    }

    const auto coherent_rollback_fixture_image_path =
        run_root / "container_coherent_checkpoint_rollback_fixture.apfs.img";
    if (!CreateSyntheticContainer(coherent_rollback_fixture_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for coherent-checkpoint rollback scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext coherent_rollback_fixture_context
    {
        coherent_rollback_fixture_image_path.wstring(),
        L"CoherentCheckpointRollbackFixture",
    };
    const auto coherent_rollback_first_payload = BuildPatternPayload(640, 0x4A);
    const auto coherent_rollback_second_payload = BuildPatternPayload(896, 0x6E);
    {
        const auto fixture_sidecar_path = BuildPersistentStatePathForTest(coherent_rollback_fixture_context);
        if (!fixture_sidecar_path.empty())
        {
            std::error_code remove_ec;
            std::filesystem::remove(fixture_sidecar_path, remove_ec);
        }
    }
    {
        apfsaccess::rw::MetadataStore store(coherent_rollback_fixture_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Coherent-rollback setup LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Coherent-rollback setup LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Coherent-rollback setup LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Coherent-rollback setup PrepareNativeWritePath should succeed");

        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }
                const auto target_size = static_cast<std::size_t>(logical_size);
                if (payload.size() < target_size)
                {
                    payload.resize(target_size, std::byte{0});
                }
                else if (payload.size() > target_size)
                {
                    payload.resize(target_size);
                }
                return payload;
            });

        apfsaccess::rw::MetadataStore::MutationRequest create_first{};
        create_first.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_first.path = L"\\first_only_after_rollback.bin";
        ok &= Require(
            store.ApplyMutation(create_first) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Coherent-rollback first create should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_first{};
        write_first.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_first.path = L"\\first_only_after_rollback.bin";
        write_first.length = static_cast<std::uint64_t>(coherent_rollback_first_payload.size());
        ok &= Require(
            store.ApplyMutation(write_first) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Coherent-rollback first write should apply");
        staged_payloads[L"\\first_only_after_rollback.bin"] = coherent_rollback_first_payload;

        const auto first_commit = store.CommitPendingMutations();
        ok &= Require(
            first_commit == apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "Coherent-rollback first commit should succeed");
        ok &= Require(
            store.LastCommittedXid().value_or(0) == (kInitialCheckpointXid + 1),
            "Coherent-rollback first commit should advance xid");

        apfsaccess::rw::MetadataStore::MutationRequest create_second{};
        create_second.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_second.path = L"\\lost_latest_generation.bin";
        ok &= Require(
            store.ApplyMutation(create_second) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Coherent-rollback second create should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_second{};
        write_second.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_second.path = L"\\lost_latest_generation.bin";
        write_second.length = static_cast<std::uint64_t>(coherent_rollback_second_payload.size());
        ok &= Require(
            store.ApplyMutation(write_second) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Coherent-rollback second write should apply");
        staged_payloads[L"\\lost_latest_generation.bin"] = coherent_rollback_second_payload;

        const auto second_commit = store.CommitPendingMutations();
        ok &= Require(
            second_commit == apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "Coherent-rollback second commit should succeed");
        ok &= Require(
            store.LastCommittedXid().value_or(0) == (kInitialCheckpointXid + 2),
            "Coherent-rollback second commit should advance xid");
    }

    std::size_t coherent_rollback_corrupted_blocks = 0;
    std::uint64_t coherent_rollback_corrupted_xid = 0;
    ok &= Require(
        CorruptLatestObjectMapCheckpointBlocks(
            coherent_rollback_fixture_image_path,
            kTotalBlocks,
            coherent_rollback_corrupted_blocks,
            coherent_rollback_corrupted_xid),
        "Coherent-rollback should corrupt latest object-map checkpoint block");
    ok &= Require(
        coherent_rollback_corrupted_blocks >= 1,
        "Coherent-rollback should corrupt at least one object-map checkpoint block");
    ok &= Require(
        coherent_rollback_corrupted_xid == (kInitialCheckpointXid + 2),
        "Coherent-rollback should target latest xid object-map checkpoint");

    const auto coherent_rollback_non_fixture_image_path =
        run_root / "container_coherent_checkpoint_rollback.bin";
    {
        std::error_code copy_ec;
        std::filesystem::copy_file(
            coherent_rollback_fixture_image_path,
            coherent_rollback_non_fixture_image_path,
            std::filesystem::copy_options::overwrite_existing,
            copy_ec);
        ok &= Require(
            !copy_ec,
            "Coherent-rollback should copy corrupted fixture image to non-fixture path");
    }

    apfsaccess::rw::MetadataStore::VolumeContext coherent_rollback_non_fixture_context
    {
        coherent_rollback_non_fixture_image_path.wstring(),
        L"CoherentCheckpointRollback",
    };
    {
        const auto non_fixture_sidecar_path = BuildPersistentStatePathForTest(coherent_rollback_non_fixture_context);
        if (!non_fixture_sidecar_path.empty())
        {
            std::error_code remove_ec;
            std::filesystem::remove(non_fixture_sidecar_path, remove_ec);
        }
    }
    {
        apfsaccess::rw::MetadataStore remounted(coherent_rollback_non_fixture_context);
        ok &= Require(
            remounted.LoadContainerSuperblocks(),
            "Coherent-rollback remount LoadContainerSuperblocks should succeed");
        ok &= Require(
            remounted.PrepareNativeWritePath(),
            "Coherent-rollback remount PrepareNativeWritePath should succeed after rolling back to prior coherent xid");
        ok &= Require(
            !remounted.IsRecoveryRequired(),
            "Coherent-rollback remount should not require recovery after selecting prior coherent xid");
        ok &= Require(
            remounted.IsCommitPathReady(),
            "Coherent-rollback remount should keep commit path ready after coherent rollback");
        ok &= Require(
            remounted.LastCommittedXid().value_or(0) == (kInitialCheckpointXid + 1),
            "Coherent-rollback remount should roll back to previous coherent xid");
        ok &= Require(
            remounted.LookupCommittedInodeByPath(L"\\first_only_after_rollback.bin").has_value(),
            "Coherent-rollback remount should preserve prior coherent file");
        ok &= Require(
            !remounted.LookupCommittedInodeByPath(L"\\lost_latest_generation.bin").has_value(),
            "Coherent-rollback remount should not expose latest-generation inode without matching object map");

        std::vector<std::byte> first_window;
        ok &= Require(
            remounted.ReadCommittedFileRange(
                L"\\first_only_after_rollback.bin",
                0,
                coherent_rollback_first_payload.size(),
                first_window),
            "Coherent-rollback remount should read prior coherent payload");
        ok &= Require(
            first_window == coherent_rollback_first_payload,
            "Coherent-rollback remount prior coherent payload should match");
    }

    const auto btree_rebuild_image_path = run_root / "container_btree_rebuild_inode_state.apfs.img";
    if (!CreateSyntheticContainer(btree_rebuild_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for btree-rebuild scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext btree_rebuild_context
    {
        btree_rebuild_image_path.wstring(),
        L"BtreeRebuildInodeState",
    };
    const auto btree_rebuild_state_path = BuildPersistentStatePathForTest(btree_rebuild_context);
    if (!btree_rebuild_state_path.empty())
    {
        std::error_code remove_ec;
        std::filesystem::remove(btree_rebuild_state_path, remove_ec);
    }

    const auto btree_rebuild_payload = BuildPatternPayload(1536, 0xD2);
    std::size_t btree_rebuild_expected_inodes = 0;
    std::size_t btree_rebuild_expected_btree_records = 0;
    {
        apfsaccess::rw::MetadataStore store(btree_rebuild_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Btree-rebuild LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Btree-rebuild LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Btree-rebuild LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Btree-rebuild PrepareNativeWritePath should succeed");

        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }
                const auto target_size = static_cast<std::size_t>(logical_size);
                if (payload.size() < target_size)
                {
                    payload.resize(target_size, std::byte{0});
                }
                else if (payload.size() > target_size)
                {
                    payload.resize(target_size);
                }
                return payload;
            });

        apfsaccess::rw::MetadataStore::MutationRequest create_dir{};
        create_dir.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateDirectory;
        create_dir.path = L"\\rebuild";
        ok &= Require(
            store.ApplyMutation(create_dir) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Btree-rebuild directory create should apply");

        apfsaccess::rw::MetadataStore::MutationRequest create_file{};
        create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_file.path = L"\\rebuild\\from_btree.bin";
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Btree-rebuild file create should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\rebuild\\from_btree.bin";
        write_file.length = static_cast<std::uint64_t>(btree_rebuild_payload.size());
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Btree-rebuild file write should apply");
        staged_payloads[L"\\rebuild\\from_btree.bin"] = btree_rebuild_payload;

        const auto commit_status = store.CommitPendingMutations();
        ok &= Require(
            commit_status == apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "Btree-rebuild setup commit should succeed");

        btree_rebuild_expected_inodes = store.CommittedInodeCount();
        btree_rebuild_expected_btree_records = store.CommittedBtreeRecordCount();
    }

    if (!btree_rebuild_state_path.empty())
    {
        std::error_code remove_ec;
        std::filesystem::remove(btree_rebuild_state_path, remove_ec);
    }

    std::size_t corrupted_inode_checkpoint_blocks = 0;
    ok &= Require(
        CorruptInodeCheckpointBlocks(
            btree_rebuild_image_path,
            kVolumeRootObject,
            kTotalBlocks,
            corrupted_inode_checkpoint_blocks),
        "Btree-rebuild scenario should locate inode checkpoint blocks for corruption");
    ok &= Require(
        corrupted_inode_checkpoint_blocks >= 1,
        "Btree-rebuild scenario should corrupt at least one inode checkpoint block");

    {
        apfsaccess::rw::MetadataStore remounted_btree_rebuild(btree_rebuild_context);
        ok &= Require(remounted_btree_rebuild.LoadContainerSuperblocks(), "Btree-rebuild remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted_btree_rebuild.PrepareNativeWritePath(), "Btree-rebuild remount PrepareNativeWritePath should succeed");
        ok &= Require(!remounted_btree_rebuild.IsRecoveryRequired(), "Btree-rebuild remount should remain clean (no recovery)");
        ok &= Require(remounted_btree_rebuild.IsCommitPathReady(), "Btree-rebuild remount should keep commit path ready");
        ok &= Require(
            remounted_btree_rebuild.CommittedInodeCount() == btree_rebuild_expected_inodes,
            "Btree-rebuild remount should reconstruct inode count from btree checkpoint records");
        ok &= Require(
            remounted_btree_rebuild.CommittedBtreeRecordCount() == btree_rebuild_expected_btree_records,
            "Btree-rebuild remount should preserve btree checkpoint record count");
        ok &= Require(
            remounted_btree_rebuild.LookupCommittedInodeByPath(L"\\REBUILD\\FROM_BTREE.BIN").has_value(),
            "Btree-rebuild remount should expose reconstructed path case-insensitively");

        std::vector<std::byte> rebuilt_window;
        ok &= Require(
            remounted_btree_rebuild.ReadCommittedFileRange(
                L"\\rebuild\\from_btree.bin",
                0,
                btree_rebuild_payload.size(),
                rebuilt_window),
            "Btree-rebuild remount should read payload via reconstructed inode state");
        ok &= Require(
            rebuilt_window == btree_rebuild_payload,
            "Btree-rebuild remount payload should match committed bytes");
    }

    const auto btree_rebuild_partial_inode_image_path = run_root / "container_btree_rebuild_partial_inode_state.apfs.img";
    if (!CreateSyntheticContainer(btree_rebuild_partial_inode_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for partial-inode btree-rebuild scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext btree_rebuild_partial_inode_context
    {
        btree_rebuild_partial_inode_image_path.wstring(),
        L"BtreeRebuildPartialInodeState",
    };
    const auto btree_rebuild_partial_inode_state_path = BuildPersistentStatePathForTest(btree_rebuild_partial_inode_context);
    if (!btree_rebuild_partial_inode_state_path.empty())
    {
        std::error_code remove_ec;
        std::filesystem::remove(btree_rebuild_partial_inode_state_path, remove_ec);
    }

    const auto btree_rebuild_partial_inode_payload = BuildPatternPayload(2048, 0xB4);
    std::size_t btree_rebuild_partial_inode_expected_inodes = 0;
    std::size_t btree_rebuild_partial_inode_expected_btree_records = 0;
    {
        apfsaccess::rw::MetadataStore store(btree_rebuild_partial_inode_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Partial-inode btree-rebuild LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Partial-inode btree-rebuild LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Partial-inode btree-rebuild LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Partial-inode btree-rebuild PrepareNativeWritePath should succeed");

        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }
                const auto target_size = static_cast<std::size_t>(logical_size);
                if (payload.size() < target_size)
                {
                    payload.resize(target_size, std::byte{0});
                }
                else if (payload.size() > target_size)
                {
                    payload.resize(target_size);
                }
                return payload;
            });

        apfsaccess::rw::MetadataStore::MutationRequest create_dir{};
        create_dir.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateDirectory;
        create_dir.path = L"\\partial";
        ok &= Require(
            store.ApplyMutation(create_dir) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Partial-inode btree-rebuild directory create should apply");

        apfsaccess::rw::MetadataStore::MutationRequest create_file{};
        create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_file.path = L"\\partial\\from_btree.bin";
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Partial-inode btree-rebuild file create should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\partial\\from_btree.bin";
        write_file.length = static_cast<std::uint64_t>(btree_rebuild_partial_inode_payload.size());
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Partial-inode btree-rebuild file write should apply");
        staged_payloads[L"\\partial\\from_btree.bin"] = btree_rebuild_partial_inode_payload;

        const auto commit_status = store.CommitPendingMutations();
        ok &= Require(
            commit_status == apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "Partial-inode btree-rebuild setup commit should succeed");

        btree_rebuild_partial_inode_expected_inodes = store.CommittedInodeCount();
        btree_rebuild_partial_inode_expected_btree_records = store.CommittedBtreeRecordCount();
    }

    if (!btree_rebuild_partial_inode_state_path.empty())
    {
        std::error_code remove_ec;
        std::filesystem::remove(btree_rebuild_partial_inode_state_path, remove_ec);
    }

    std::size_t rewritten_root_only_inode_checkpoint_blocks = 0;
    ok &= Require(
        WriteRootOnlyInodeCheckpointBlocks(
            btree_rebuild_partial_inode_image_path,
            kVolumeRootObject,
            kTotalBlocks,
            rewritten_root_only_inode_checkpoint_blocks),
        "Partial-inode btree-rebuild scenario should rewrite inode checkpoints to root-only state");
    ok &= Require(
        rewritten_root_only_inode_checkpoint_blocks >= 1,
        "Partial-inode btree-rebuild scenario should rewrite at least one inode checkpoint");

    {
        apfsaccess::rw::MetadataStore remounted_btree_rebuild(btree_rebuild_partial_inode_context);
        ok &= Require(remounted_btree_rebuild.LoadContainerSuperblocks(), "Partial-inode btree-rebuild remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted_btree_rebuild.PrepareNativeWritePath(), "Partial-inode btree-rebuild remount PrepareNativeWritePath should succeed");
        ok &= Require(!remounted_btree_rebuild.IsRecoveryRequired(), "Partial-inode btree-rebuild remount should remain clean (no recovery)");
        ok &= Require(remounted_btree_rebuild.IsCommitPathReady(), "Partial-inode btree-rebuild remount should keep commit path ready");
        ok &= Require(
            remounted_btree_rebuild.CommittedInodeCount() == btree_rebuild_partial_inode_expected_inodes,
            "Partial-inode btree-rebuild remount should replace root-only inode checkpoint with btree reconstruction");
        ok &= Require(
            remounted_btree_rebuild.CommittedBtreeRecordCount() == btree_rebuild_partial_inode_expected_btree_records,
            "Partial-inode btree-rebuild remount should preserve btree checkpoint record count");
        ok &= Require(
            remounted_btree_rebuild.LookupCommittedInodeByPath(L"\\PARTIAL\\FROM_BTREE.BIN").has_value(),
            "Partial-inode btree-rebuild remount should expose reconstructed path case-insensitively");

        std::vector<std::byte> rebuilt_window;
        ok &= Require(
            remounted_btree_rebuild.ReadCommittedFileRange(
                L"\\partial\\from_btree.bin",
                0,
                btree_rebuild_partial_inode_payload.size(),
                rebuilt_window),
            "Partial-inode btree-rebuild remount should read payload via reconstructed inode state");
        ok &= Require(
            rebuilt_window == btree_rebuild_partial_inode_payload,
            "Partial-inode btree-rebuild remount payload should match committed bytes");
    }

    const auto non_fixture_partial_inode_fixture_image_path =
        run_root / "container_non_fixture_partial_inode_state_seed.apfs.img";
    if (!CreateSyntheticContainer(non_fixture_partial_inode_fixture_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for non-fixture partial-inode scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext non_fixture_partial_inode_fixture_context
    {
        non_fixture_partial_inode_fixture_image_path.wstring(),
        L"NonFixturePartialInodeSeed",
    };
    const auto non_fixture_partial_inode_fixture_state_path =
        BuildPersistentStatePathForTest(non_fixture_partial_inode_fixture_context);
    if (!non_fixture_partial_inode_fixture_state_path.empty())
    {
        std::error_code remove_ec;
        std::filesystem::remove(non_fixture_partial_inode_fixture_state_path, remove_ec);
    }

    const auto non_fixture_partial_inode_payload = BuildPatternPayload(4096, 0x7C);
    std::size_t non_fixture_partial_inode_expected_inodes = 0;
    std::size_t non_fixture_partial_inode_expected_btree_records = 0;
    {
        apfsaccess::rw::MetadataStore store(non_fixture_partial_inode_fixture_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Non-fixture partial-inode LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Non-fixture partial-inode LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Non-fixture partial-inode LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Non-fixture partial-inode PrepareNativeWritePath should succeed");

        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }
                const auto target_size = static_cast<std::size_t>(logical_size);
                if (payload.size() < target_size)
                {
                    payload.resize(target_size, std::byte{0});
                }
                else if (payload.size() > target_size)
                {
                    payload.resize(target_size);
                }
                return payload;
            });

        apfsaccess::rw::MetadataStore::MutationRequest create_dir{};
        create_dir.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateDirectory;
        create_dir.path = L"\\strict";
        ok &= Require(
            store.ApplyMutation(create_dir) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Non-fixture partial-inode directory create should apply");

        apfsaccess::rw::MetadataStore::MutationRequest create_file{};
        create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_file.path = L"\\strict\\from_btree.bin";
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Non-fixture partial-inode file create should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\strict\\from_btree.bin";
        write_file.length = static_cast<std::uint64_t>(non_fixture_partial_inode_payload.size());
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Non-fixture partial-inode file write should apply");
        staged_payloads[L"\\strict\\from_btree.bin"] = non_fixture_partial_inode_payload;

        const auto commit_status = store.CommitPendingMutations();
        ok &= Require(
            commit_status == apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "Non-fixture partial-inode setup commit should succeed");

        non_fixture_partial_inode_expected_inodes = store.CommittedInodeCount();
        non_fixture_partial_inode_expected_btree_records = store.CommittedBtreeRecordCount();
    }

    const auto non_fixture_partial_inode_image_path = run_root / "container_non_fixture_partial_inode_state.bin";
    {
        std::error_code copy_ec;
        std::filesystem::copy_file(
            non_fixture_partial_inode_fixture_image_path,
            non_fixture_partial_inode_image_path,
            std::filesystem::copy_options::overwrite_existing,
            copy_ec);
        ok &= Require(
            !copy_ec,
            "Non-fixture partial-inode scenario should copy fixture seed image to non-fixture path");
    }

    apfsaccess::rw::MetadataStore::VolumeContext non_fixture_partial_inode_context
    {
        non_fixture_partial_inode_image_path.wstring(),
        L"NonFixturePartialInodeState",
    };
    const auto non_fixture_partial_inode_state_path = BuildPersistentStatePathForTest(non_fixture_partial_inode_context);
    if (!non_fixture_partial_inode_state_path.empty())
    {
        std::error_code remove_ec;
        std::filesystem::remove(non_fixture_partial_inode_state_path, remove_ec);
    }

    std::size_t non_fixture_rewritten_root_only_inode_blocks = 0;
    ok &= Require(
        WriteRootOnlyInodeCheckpointBlocks(
            non_fixture_partial_inode_image_path,
            kVolumeRootObject,
            kTotalBlocks,
            non_fixture_rewritten_root_only_inode_blocks),
        "Non-fixture partial-inode scenario should rewrite inode checkpoints to root-only state");
    ok &= Require(
        non_fixture_rewritten_root_only_inode_blocks >= 1,
        "Non-fixture partial-inode scenario should rewrite at least one inode checkpoint");

    {
        apfsaccess::rw::MetadataStore remounted(non_fixture_partial_inode_context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "Non-fixture partial-inode remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "Non-fixture partial-inode remount PrepareNativeWritePath should succeed via btree reconstruction");
        ok &= Require(!remounted.IsRecoveryRequired(), "Non-fixture partial-inode remount should remain clean after btree reconstruction");
        ok &= Require(remounted.IsCommitPathReady(), "Non-fixture partial-inode remount should keep commit path ready");
        ok &= Require(
            remounted.CommittedInodeCount() == non_fixture_partial_inode_expected_inodes,
            "Non-fixture partial-inode remount should replace root-only inode checkpoint with btree reconstruction");
        ok &= Require(
            remounted.CommittedBtreeRecordCount() == non_fixture_partial_inode_expected_btree_records,
            "Non-fixture partial-inode remount should preserve btree checkpoint record count");
        ok &= Require(
            remounted.LookupCommittedInodeByPath(L"\\STRICT\\FROM_BTREE.BIN").has_value(),
            "Non-fixture partial-inode remount should expose reconstructed path case-insensitively");

        std::vector<std::byte> rebuilt_window;
        ok &= Require(
            remounted.ReadCommittedFileRange(
                L"\\strict\\from_btree.bin",
                0,
                non_fixture_partial_inode_payload.size(),
                rebuilt_window),
            "Non-fixture partial-inode remount should read payload via reconstructed inode state");
        ok &= Require(
            rebuilt_window == non_fixture_partial_inode_payload,
            "Non-fixture partial-inode remount payload should match committed bytes");
    }

    if (!persistent_state_path.empty())
    {
        std::error_code remove_ec;
        std::filesystem::remove(persistent_state_path, remove_ec);
    }
    std::filesystem::remove_all(run_root, ec);
    if (!ok)
    {
        return 1;
    }

    std::cout << "[PASS] MetadataStorePersistenceTests" << std::endl;
    return 0;
}
