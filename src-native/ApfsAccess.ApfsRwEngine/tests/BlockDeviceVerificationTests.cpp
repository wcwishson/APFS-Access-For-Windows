#include "BlockDevice.h"

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace apfsaccess::rw
{
// Existing friend accessor, limited to retained real regular-file handles.
struct BlockDeviceRawSnapshotTestPeer
{
    static void UseImageAsRawReadFixture(BlockDevice& device, std::uint64_t limit)
    {
        std::lock_guard<std::mutex> handle_lock(device.handle_mutex_);
        std::lock_guard<std::mutex> source_lock(device.write_source_mutex_);
        if (!device.exclusive_write_image_ || device.read_handle_ == INVALID_HANDLE_VALUE ||
            device.write_handle_ == INVALID_HANDLE_VALUE) throw std::runtime_error("Held image required");
        device.regular_file_ = false;
        device.raw_writer_accepted_ = true;
        device.raw_write_limit_bytes_ = limit;
        device.raw_write_source_size_bytes_ = limit;
        device.raw_writer_identity_ = "verification-real-file-only";
        device.raw_snapshot_lease_retired_ = false;
        device.write_source_handles_retired_ = false;
    }
    static void SetProbeResult(BlockDevice& device, bool present)
    {
        std::lock_guard<std::mutex> lock(device.write_source_mutex_);
        device.raw_presence_probe_result_ = present;
    }
    static void Retire(BlockDevice& device)
    {
        std::lock_guard<std::mutex> lock(device.handle_mutex_);
        device.InvalidateWriteSourceHandlesLocked();
    }
    static std::uint64_t Generation(const BlockDevice& device)
    {
        std::lock_guard<std::mutex> lock(device.write_source_mutex_);
        return device.write_source_generation_;
    }
    static bool HasReader(const BlockDevice& device)
    {
        return device.read_handle_.load() != INVALID_HANDLE_VALUE;
    }
    static bool LogicalGeometryIsCold(const BlockDevice& device)
    {
        return device.logical_block_size_cache_.load() == 0;
    }
    static std::unique_lock<std::mutex> LockGeometry(BlockDevice& device)
    {
        return std::unique_lock<std::mutex>(device.geometry_mutex_);
    }
};
}

namespace
{
using Device = apfsaccess::rw::BlockDevice;
using Peer = apfsaccess::rw::BlockDeviceRawSnapshotTestPeer;
constexpr std::size_t kBlock = 4096;
unsigned checks = 0, failures = 0;

bool Check(bool value, const char* message)
{
    ++checks;
    if (!value) { ++failures; std::cerr << "[FAIL] " << message << '\n'; }
    return value;
}

class CacheSetting
{
public:
    CacheSetting()
    {
        const auto length = GetEnvironmentVariableW(name, nullptr, 0);
        existed = length != 0;
        if (existed)
        {
            previous.resize(length);
            previous.resize(GetEnvironmentVariableW(name, previous.data(), length));
        }
        if (!SetEnvironmentVariableW(name, L"1")) throw std::runtime_error("Cannot enable test cache");
    }
    ~CacheSetting() { SetEnvironmentVariableW(name, existed ? previous.c_str() : nullptr); }
private:
    static constexpr auto name = L"APFSACCESS_EXPERIMENTAL_BLOCK_READ_CACHE";
    bool existed = false;
    std::wstring previous;
};

void Seed(const std::filesystem::path& path, const std::vector<std::byte>& bytes)
{
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    file.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    if (!file.good()) throw std::runtime_error("Cannot seed private fixture");
}

bool ExternalWrite(const std::filesystem::path& path, std::uint64_t offset,
    const std::vector<std::byte>& bytes)
{
    const auto writer = CreateFileW(path.c_str(), GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (writer == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER position{};
    position.QuadPart = offset;
    DWORD done = 0;
    const bool ok = SetFilePointerEx(writer, position, nullptr, FILE_BEGIN) &&
        WriteFile(writer, bytes.data(), static_cast<DWORD>(bytes.size()), &done, nullptr) &&
        done == bytes.size() && FlushFileBuffers(writer);
    CloseHandle(writer);
    return ok;
}

void CacheBypass(const std::filesystem::path& root)
{
    const auto path = root / "cached.img";
    const std::vector<std::byte> original(4 * kBlock, std::byte{0x11});
    const std::vector<std::byte> replacement(kBlock, std::byte{0x72});
    Seed(path, original);
    Device device(path.wstring(), kBlock);
    const Device& reader = device;
    std::vector<std::byte> bytes;
    if (!Check(reader.Read(0, kBlock, bytes) && bytes == std::vector<std::byte>(kBlock, std::byte{0x11}),
            "ordinary Read warms real nonzero-base cache")) return;
    if (!Check(ExternalWrite(path, kBlock, replacement), "fixture writer changes and flushes held-file bytes")) return;
    const auto generation = Peer::Generation(device);
    Check(reader.Read(0, kBlock, bytes) && bytes == std::vector<std::byte>(kBlock, std::byte{0x11}),
        "ordinary Read is demonstrably stale after external writer");
    Check(reader.ReadForVerification(0, kBlock, bytes) && bytes == replacement,
        "verification reads new bytes through held reader despite warmed stale cache");
    Check(reader.Read(0, kBlock, bytes) && bytes == std::vector<std::byte>(kBlock, std::byte{0x11}),
        "verification neither inserts nor invalidates ordinary cache");
    Check(Peer::Generation(device) == generation && !device.HasWriteHandle(),
        "verification neither changes source generation nor acquires writer");

    // A cold verification read must not create an ordinary cache entry either.
    Check(reader.ReadForVerification(kBlock, kBlock, bytes) && bytes == std::vector<std::byte>(kBlock, std::byte{0x11}),
        "verification directly reads a cold block");
    Check(ExternalWrite(path, 2 * kBlock, replacement), "fixture writer changes cold verification block");
    Check(reader.Read(kBlock, kBlock, bytes) && bytes == replacement,
        "ordinary Read sees later external change because verification did not insert cache");
    std::cout << "[INFO] cache bypass: old ordinary bytes and new verification bytes on actual D: file\n";
}

void HeldIdentity(const std::filesystem::path& root)
{
    const auto path = root / "held-name.img";
    const auto moved = root / "original-held.img";
    const std::vector<std::byte> original(kBlock, std::byte{0x17});
    Seed(path, original);
    Device device(path.wstring());
    std::vector<std::byte> bytes;
    if (!Check(device.Read(0, kBlock, bytes), "path identity fixture holds original reader")) return;
    const auto generation = Peer::Generation(device);
    if (!Check(MoveFileExW(path.c_str(), moved.c_str(), MOVEFILE_REPLACE_EXISTING) != FALSE,
            "rename original ordinary file while original handle remains held")) return;
    Seed(path, std::vector<std::byte>(kBlock, std::byte{0x61}));
    Check(device.ReadForVerification(0, kBlock, bytes) && bytes == original,
        "verification remains bound to original held file after path replacement");
    Check(Peer::Generation(device) == generation && !device.HasWriteHandle(),
        "path-replacement verification neither changes source generation nor acquires writer");
}

void SectorOffsetWindow(const std::filesystem::path& root)
{
    const auto path = root / "sector-offset.img";
    constexpr std::size_t base = 5 * kBlock + 512;
    std::vector<std::byte> image(base + 2 * kBlock + 37, std::byte{0x5a});
    const std::vector<std::byte> original(kBlock, std::byte{0x2a});
    std::copy(original.begin(), original.end(), image.begin() + base);
    Seed(path, image);
    Device reader(path.wstring(), base);
    std::vector<std::byte> out;
    if (!Check(reader.Read(0, kBlock, out) && out == original,
            "sector-offset image window warms ordinary cache")) return;
    const std::vector<std::byte> replacement(kBlock, std::byte{0x73});
    if (!Check(ExternalWrite(path, base, replacement), "sector-offset fixture is changed and flushed")) return;
    const auto generation = Peer::Generation(reader);
    Check(reader.ReadForVerification(0, kBlock, out) && out == replacement,
        "verification rereads exact APFS block at sector-aligned non-block image base");
    Check(reader.Read(0, kBlock, out) && out == original,
        "sector-offset verification leaves stale ordinary cache untouched");
    out.assign(9, std::byte{0x7f});
    Check(!reader.ReadForVerification(1, kBlock, out) && out.empty(),
        "image-relative misalignment still refuses");
    Check(Peer::Generation(reader) == generation && !reader.HasWriteHandle(),
        "sector-offset verification preserves held source and read-only access");

    const auto raw_path = root / "raw-sector-offset.img";
    Seed(raw_path, image);
    std::string error;
    auto raw = Device::OpenExclusiveManagementImage(raw_path.wstring(), base, error);
    if (!Check(!!raw, "raw alignment control holds only a regular D file")) return;
    Peer::UseImageAsRawReadFixture(*raw, kBlock);
    out.assign(9, std::byte{0x7f});
    Check(!raw->ReadForVerification(0, kBlock, out) && out.empty(),
        "raw control retains absolute physical block alignment refusal");
}

void Refusals(const std::filesystem::path& root)
{
    const auto path = root / "bounds.img";
    Seed(path, std::vector<std::byte>(3 * kBlock + 123, std::byte{0x34}));
    Device device(path.wstring(), kBlock);
    std::vector<std::byte> out;
    if (!Check(device.Read(0, kBlock, out), "bounds fixture holds an ordinary reader")) return;
    const auto refused = [&](const Device& target, std::uint64_t offset, std::size_t length, const char* label) {
        out.assign(9, std::byte{0x7f});
        Check(!target.ReadForVerification(offset, length, out) && out.empty(), label);
    };
    const auto generation = Peer::Generation(device);
    refused(device, (std::numeric_limits<std::uint64_t>::max)() - kBlock + 1, kBlock,
        "base-plus-offset overflow refuses with empty output");
    Device end_overflow(path.wstring());
    Check(end_overflow.Read(0, kBlock, out), "absolute-end overflow fixture holds reader");
    refused(end_overflow, (std::numeric_limits<std::uint64_t>::max)() - kBlock + 1, kBlock,
        "absolute-end overflow refuses with empty output");
    refused(device, 0, static_cast<std::size_t>((std::numeric_limits<DWORD>::max)()) + 1,
        "larger-than-DWORD length refuses before allocation");
    refused(device, 1, kBlock, "misaligned absolute offset refuses with empty output");
    refused(device, 0, kBlock - 1, "misaligned length refuses with empty output");
    refused(device, 2 * kBlock, kBlock, "actual partial last-block read refuses and discards partial bytes");
    refused(device, 3 * kBlock, kBlock, "actual EOF refuses and clears preexisting output");
    Device unopened(path.wstring());
    const auto unopened_generation = Peer::Generation(unopened);
    refused(unopened, 0, kBlock, "verification refuses without an already-held reader");
    Check(!Peer::HasReader(unopened) && Peer::Generation(unopened) == unopened_generation,
        "refused unopened verification does not open a path or change generation");
    out.assign(9, std::byte{0x7f});
    Check(device.ReadForVerification(0, 0, out) && out.empty(), "empty verification succeeds without data");
    Check(Peer::Generation(device) == generation, "all failed verification ranges preserve generation");
    Check(device.Read(2 * kBlock, kBlock, out) && out.size() == 123,
        "ordinary Read retains existing successful partial-read behavior");
}

void FlushReadback(const std::filesystem::path& root)
{
    const auto path = root / "flush.img";
    std::vector<std::byte> payload(1024 * 1024);
    for (std::size_t i = 0; i < payload.size(); ++i) payload[i] = std::byte((i * 19 + i / kBlock) & 255);
    Seed(path, std::vector<std::byte>(payload.size() + kBlock));
    std::string error;
    auto device = Device::OpenExclusiveManagementImage(path.wstring(), kBlock, error);
    if (!Check(!!device, "exclusive real-file writer opens for flush readback")) return;
    if (!Check(device->Write(0, payload) && device->Flush(), "normal writer flushes actual 1 MiB batch")) return;
    const auto observation = device->CaptureExclusiveWriteSourceObservation();
    const auto generation = Peer::Generation(*device);
    std::vector<std::byte> readback;
    Check(observation.has_value(), "flushed exclusive writer supplies source observation");
    Check(device->ReadForVerification(0, payload.size(), readback) && readback == payload,
        "verification accepts and exactly matches 1 MiB flush readback");
    Check(device->CaptureExclusiveWriteSourceObservation() == observation && Peer::Generation(*device) == generation,
        "verification preserves exclusive source observation and generation");
    std::vector<std::byte> ordinary;
    Check(device->Read(0, payload.size(), ordinary) && ordinary == readback,
        "ordinary Read agrees with successful normal-write readback");
    device.reset();
    auto stable = Device::OpenStableReadOnlyImage(path.wstring(), error);
    Check(stable && stable->ReadForVerification(0, kBlock, readback) &&
            readback == std::vector<std::byte>(kBlock) && stable->RevalidateStableReadOnlyImage() && !stable->HasWriteHandle(),
        "stable read-only image retains held identity and never acquires a writer");
}

void ColdHeldReaderWithConcurrentGeometry(const std::filesystem::path& root)
{
    const auto path = root / "cold-held-geometry.img";
    const std::vector<std::byte> original(4 * kBlock, std::byte{0x29});
    Seed(path, original);
    std::string error;
    auto device = Device::OpenExclusiveManagementImage(path.wstring(), kBlock, error);
    if (!Check(device && Peer::HasReader(*device) && Peer::LogicalGeometryIsCold(*device),
            "cold geometry case starts with actual held reader and uninitialized logical geometry")) return;
    const auto generation = Peer::Generation(*device);
    auto geometry_lock = Peer::LockGeometry(*device);
    std::mutex mutex;
    std::condition_variable condition;
    bool geometry_started = false, finished = false, read_ok = false;
    Device::Geometry geometry;
    std::vector<std::byte> bytes;
    std::thread geometry_reader([&] {
        {
            std::lock_guard<std::mutex> lock(mutex);
            geometry_started = true;
        }
        condition.notify_one();
        geometry = device->GetGeometry();
    });
    {
        std::unique_lock<std::mutex> lock(mutex);
        condition.wait(lock, [&] { return geometry_started; });
    }
    std::thread verification_reader([&] {
        const auto ok = device->ReadForVerification(0, kBlock, bytes);
        {
            std::lock_guard<std::mutex> lock(mutex);
            read_ok = ok;
            finished = true;
        }
        condition.notify_one();
    });
    bool completed_while_geometry_locked = false;
    {
        std::unique_lock<std::mutex> lock(mutex);
        completed_while_geometry_locked = condition.wait_for(lock, std::chrono::seconds(5), [&] { return finished; });
    }
    const bool cache_still_cold = Peer::LogicalGeometryIsCold(*device);
    geometry_lock.unlock();
    verification_reader.join();
    geometry_reader.join();
    Check(completed_while_geometry_locked && read_ok && bytes == std::vector<std::byte>(kBlock, std::byte{0x29}),
        "cold held-reader verification completes while geometry mutex is held and actual GetGeometry is concurrent");
    Check(cache_still_cold, "cold verification uses local geometry without changing shared logical geometry cache");
    Check(geometry.total_bytes == original.size() - kBlock &&
            geometry.logical_block_size == kBlock && !Peer::LogicalGeometryIsCold(*device),
        "concurrent GetGeometry completes and initializes its own cache after geometry lock release");
    Check(Peer::Generation(*device) == generation,
        "cold verification and concurrent geometry preserve source generation");
    std::cout << "[INFO] cold held-reader: completedWhileGeometryLocked=" << completed_while_geometry_locked
        << " sharedGeometryCold=" << cache_still_cold << " readOk=" << read_ok
        << " concurrentGetGeometryJoined=1\n";
}

void RawBoundsOnFile(const std::filesystem::path& root)
{
    const auto path = root / "raw-limit-file.img";
    Seed(path, std::vector<std::byte>(4 * kBlock, std::byte{0x53}));
    std::string error;
    auto device = Device::OpenExclusiveManagementImage(path.wstring(), kBlock, error);
    if (!Check(!!device, "raw-bound state test uses actual exclusive regular-file handles")) return;
    Peer::UseImageAsRawReadFixture(*device, 2 * kBlock);
    std::vector<std::byte> out;
    const auto generation = Peer::Generation(*device);
    Check(device->ReadForVerification(kBlock, kBlock, out) && out == std::vector<std::byte>(kBlock, std::byte{0x53}),
        "admitted-range endpoint reads through original image handles");
    out.assign(9, std::byte{0x7f});
    Check(!device->ReadForVerification(2 * kBlock, kBlock, out) && out.empty(),
        "verification refuses beyond admitted limit despite real bytes existing in file");
    Peer::SetProbeResult(*device, false);
    out.assign(9, std::byte{0x7f});
    Check(!device->ReadForVerification(0, kBlock, out) && out.empty(),
        "failed existing presence probe cannot be bypassed by verification");
    Check(Peer::Generation(*device) == generation, "raw-bound verification and refusal do not change source generation");
    Peer::SetProbeResult(*device, true);
    Peer::Retire(*device);
    const auto retired_generation = Peer::Generation(*device);
    out.assign(9, std::byte{0x7f});
    Check(!device->ReadForVerification(0, kBlock, out) && out.empty() &&
            Peer::Generation(*device) == retired_generation,
        "retired ownership refuses without reopening or changing generation");
    std::cout << "[INFO] raw limits/probe/retirement tested only on retained D: regular-file handles\n";
}
}

int main(int argc, char** argv)
{
    try
    {
        if (argc != 2) throw std::runtime_error("Explicit D: fixture directory required");
        const std::filesystem::path root(argv[1]);
        if (!root.is_absolute() || root.root_name() != "D:") throw std::runtime_error("D: fixtures required");
        std::filesystem::create_directories(root);
        CacheSetting cache;
        CacheBypass(root);
        HeldIdentity(root);
        SectorOffsetWindow(root);
        Refusals(root);
        FlushReadback(root);
        RawBoundsOnFile(root);
        ColdHeldReaderWithConcurrentGeometry(root);
        std::cout << (failures ? "[FAIL]" : "[PASS]") << " BlockDevice verification reads: checks="
            << checks << " failures=" << failures << '\n';
        return failures ? 1 : 0;
    }
    catch (const std::exception& e)
    {
        std::cerr << "[FAIL] " << e.what() << '\n';
        return 1;
    }
}
