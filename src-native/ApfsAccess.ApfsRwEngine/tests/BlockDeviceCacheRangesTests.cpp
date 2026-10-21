#include "BlockDevice.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <thread>

namespace apfsaccess::rw
{
struct BlockDeviceRawSnapshotTestPeer
{
    struct Stats
    {
        std::uint64_t generation, admissions, hits, raw_reads, raw_bytes, bytes, entries;
    };
    static Stats Get(const BlockDevice& d)
    {
        std::lock_guard lock(d.read_cache_mutex_);
        return {d.read_cache_generation_, d.read_cache_write_admissions_,
            d.read_cache_hit_count_.load(), d.raw_read_perf_.count.load(),
            d.raw_read_perf_.bytes.load(), d.read_cache_bytes_.load(), d.read_cache_.size()};
    }
    static bool Contains(const BlockDevice& d, std::uint64_t absolute, std::size_t bytes)
    {
        std::lock_guard lock(d.read_cache_mutex_);
        return d.read_cache_.contains(BlockDevice::ReadCacheKey{absolute, bytes});
    }
    static auto LockEpoch(BlockDevice& d) { return std::unique_lock(d.write_epoch_mutex_); }
    static auto LockWrite(BlockDevice& d) { return std::unique_lock(d.write_mutex_); }
    static void Close(BlockDevice& d)
    {
        std::lock_guard lock(d.handle_mutex_);
        d.CloseHandlesLocked();
    }
    static void UnknownEpoch(BlockDevice& d)
    {
        auto lock = LockEpoch(d);
        d.BeginReadCacheWriteEpoch();
        d.EndReadCacheWriteEpoch();
    }
    static void RestrictToHeldFile(BlockDevice& d, std::uint64_t size)
    {
        // No device path or open: range enforcement on the existing ordinary file.
        d.raw_write_limit_bytes_ = size;
        d.raw_write_source_size_bytes_ = size;
        d.raw_writer_accepted_ = true;
    }
    static void InstallPresenceLoss(BlockDevice& d)
    {
        d.raw_presence_probe_hook_for_tests_ = [](DWORD& error) {
            error = ERROR_DEVICE_NOT_CONNECTED;
            return false;
        };
        d.regular_file_ = false;
    }
};
}

namespace
{
using Device = apfsaccess::rw::BlockDevice;
using Peer = apfsaccess::rw::BlockDeviceRawSnapshotTestPeer;
constexpr std::size_t B = 4096;
unsigned checks = 0;
bool selective = true;

void Check(bool value, const char* message)
{
    ++checks;
    if (!value) throw std::runtime_error(message);
}

class Env
{
public:
    Env(const wchar_t* key, const wchar_t* value) : key_(key)
    {
        const auto size = GetEnvironmentVariableW(key, nullptr, 0);
        if (size)
        {
            old_.emplace(size, L'\0');
            old_->resize(GetEnvironmentVariableW(key, old_->data(), size));
        }
        Check(SetEnvironmentVariableW(key, value) != FALSE, "set private process environment");
    }
    ~Env() { SetEnvironmentVariableW(key_.c_str(), old_ ? old_->c_str() : nullptr); }
private:
    std::wstring key_;
    std::optional<std::wstring> old_;
};

void Seed(const std::filesystem::path& path, const std::vector<std::byte>& bytes)
{
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    Check(out.good(), "seed private regular file");
}

struct Fixture
{
    std::filesystem::path path;
    std::size_t base;
    std::vector<std::byte> expected;
    std::shared_ptr<Device> device;
    Fixture(const std::filesystem::path& root, const char* name,
        std::size_t blocks = 64, std::size_t offset = 2 * B) : path(root / name), base(offset),
        expected(base + blocks * B)
    {
        for (std::size_t i = 0; i < expected.size(); ++i)
            expected[i] = static_cast<std::byte>((i * 17 + i / B * 31) & 255);
        Seed(path, expected);
        std::string error;
        device = Device::OpenExclusiveManagementImage(path.wstring(), base, error);
        Check(device && device->IsRegularFile() && device->HasWriteHandle(), "exclusive real file fixture");
    }
    void Apply(std::size_t offset, const std::vector<std::byte>& bytes)
    {
        std::copy(bytes.begin(), bytes.end(), expected.begin() + base + offset);
    }
    void Read(std::size_t offset, std::size_t bytes)
    {
        std::vector<std::byte> actual;
        Check(device->Read(offset, bytes, actual) && actual.size() == bytes &&
            std::equal(actual.begin(), actual.end(), expected.begin() + base + offset), "exact file read bytes");
    }
    void Retained(std::size_t offset, std::size_t bytes)
    {
        const auto before = Peer::Get(*device);
        Read(offset, bytes);
        const auto after = Peer::Get(*device);
        Check(after.hits - before.hits == (selective ? 1 : 0), "untouched window retention differential");
        Check(after.raw_reads - before.raw_reads == (selective ? 0 : 1), "untouched window raw-read differential");
    }
    void Fresh(std::size_t offset, std::size_t bytes)
    {
        const auto before = Peer::Get(*device);
        Read(offset, bytes);
        const auto after = Peer::Get(*device);
        Check(after.raw_reads == before.raw_reads + 1 && after.hits == before.hits,
            "overlapping window requires fresh I/O");
    }
};

void Windows(const std::filesystem::path& root)
{
    Fixture f(root, "windows.bin");
    f.Read(3 * B, B);
    f.Read(2 * B, 4 * B);
    f.Read(12 * B, B);
    f.Read(0, B);
    const auto generation = Peer::Get(*f.device).generation;
    const std::vector<std::byte> patch(200, std::byte{0x71});
    Check(f.device->Write(3 * B + 100, patch), "unaligned single write");
    f.Apply(3 * B + 100, patch);
    Check(Peer::Get(*f.device).generation == generation + 2, "single write advances both epoch edges");
    Check(!Peer::Contains(*f.device, f.base + 2 * B, 4 * B) &&
        !Peer::Contains(*f.device, f.base + 3 * B, B), "wide and contained overlapping keys removed");
    f.Retained(12 * B, B);
    f.Retained(0, B);
    f.Fresh(3 * B, B);
    f.Fresh(2 * B, 4 * B);
    const auto before = Peer::Get(*f.device);
    f.Read(4 * B + 17, 97);
    Check(Peer::Get(*f.device).hits == before.hits + 1, "fresh wide window still serves contained hit");
    const std::vector<std::byte> cover(6 * B, std::byte{0x48});
    Check(f.device->Write(B, cover), "write fully contains cached windows");
    f.Apply(B, cover);
    f.Fresh(3 * B, B);
    f.Retained(12 * B, B);
}

void Alignment(const std::filesystem::path& root)
{
    Fixture f(root, "alignment.bin", 16, 512);
    f.Read(0, 512);
    f.Read(B - 512, B);
    f.Read(2 * B - 512, B);
    const std::vector<std::byte> one(1, std::byte{0x83});
    Check(f.device->Write(0, one), "sector-base RMW writes absolute aligned sector");
    f.Apply(0, one);
    f.Fresh(0, 512);
    f.Retained(B - 512, B);
    const std::vector<std::byte> cross(2, std::byte{0x92});
    Check(f.device->Write(B - 512 - 1, cross), "write crosses physical alignment boundary");
    f.Apply(B - 512 - 1, cross);
    f.Fresh(0, 512);
    f.Fresh(B - 512, B);
    f.Retained(2 * B - 512, B);
}

void Batches(const std::filesystem::path& root)
{
    Env sync(L"APFSACCESS_DISABLE_ASYNC_BLOCK_IO", L"1");
    Fixture f(root, "batches.bin");
    const std::vector<std::byte> a(B, std::byte{0x31}), b(B, std::byte{0x42});
    for (auto offset : {4 * B, 12 * B, 20 * B}) f.Read(offset, B);
    const auto generation = Peer::Get(*f.device).generation;
    const std::array<Device::WriteSpan, 3> writes{{{20 * B, b},
        {(std::numeric_limits<std::uint64_t>::max)(), {}}, {4 * B, a}}};
    Check(f.device->WriteBatch(writes), "unordered disjoint multi-span synchronous batch");
    f.Apply(20 * B, b);
    f.Apply(4 * B, a);
    Check(Peer::Get(*f.device).generation == generation + 2, "multi-span batch is one epoch");
    f.Fresh(4 * B, B);
    f.Fresh(20 * B, B);
    f.Retained(12 * B, B);
    const std::array<Device::WriteSpan, 2> single{{{8 * B, a}, {0, {}}}};
    Check(f.device->WriteBatch(single), "one-nonempty fast batch");
    f.Apply(8 * B, a);
    f.Retained(12 * B, B);
    f.Fresh(8 * B, B);

    Fixture gaps(root, "rmw-gap.bin");
    gaps.Read(2 * B, B);
    gaps.Read(3 * B, B);
    gaps.Read(10 * B, B);
    const std::vector<std::byte> tiny(16, std::byte{0x64});
    const std::array<Device::WriteSpan, 2> holes{{{B + 7, tiny}, {4 * B + 11, tiny}}};
    Check(gaps.device->WriteBatch(holes), "grouped RMW with intervening full-block gap");
    gaps.Apply(B + 7, tiny);
    gaps.Apply(4 * B + 11, tiny);
    Check(gaps.device->PerformanceJson().find("\"rmwGroupWrite\":{\"count\":1") != std::string::npos,
        "grouped RMW path actually ran");
    gaps.Fresh(2 * B, B);
    gaps.Fresh(3 * B, B);
    gaps.Retained(10 * B, B);
    const std::vector<std::byte> first(800, std::byte{0x75}), last(900, std::byte{0x86});
    const std::array<Device::WriteSpan, 2> overlap{{{2 * B + 100, first}, {2 * B + 30, last}}};
    Check(gaps.device->WriteBatch(overlap), "overlapping batch preserves caller order");
    gaps.Apply(2 * B + 100, first);
    gaps.Apply(2 * B + 30, last);
    gaps.Fresh(2 * B, B);
    gaps.Retained(10 * B, B);

    Fixture contiguous(root, "contiguous.bin");
    const std::vector<std::byte> backing(2 * B, std::byte{0x97});
    contiguous.Read(2 * B, 2 * B);
    contiguous.Read(10 * B, B);
    const std::array<Device::WriteSpan, 2> adjacent{{{2 * B, {backing.data(), B}, backing.data()},
        {3 * B, {backing.data() + B, B}, backing.data()}}};
    Check(contiguous.device->WriteBatch(adjacent), "contiguous merge-token batch");
    contiguous.Apply(2 * B, backing);
    contiguous.Fresh(2 * B, 2 * B);
    contiguous.Retained(10 * B, B);
}

void Async(const std::filesystem::path& root)
{
    Env async(L"APFSACCESS_DISABLE_ASYNC_BLOCK_IO", L"0");
    for (bool fail : {false, true})
    {
        Fixture f(root, fail ? "async-fail.bin" : "async.bin");
        const std::vector<std::byte> a(B, std::byte{0xa1}), b(B, std::byte{0xb2});
        for (auto offset : {B, 10 * B, 20 * B}) f.Read(offset, B);
        const std::array<Device::WriteSpan, 2> writes{{{B, a}, {20 * B, b}}};
        Env fault(L"APFSACCESS_RW_FAULT_ASYNC_BATCH_AFTER_ISSUES", fail ? L"1" : nullptr);
        Check(f.device->WriteBatch(writes) == !fail, "async completion/failure result");
        f.Apply(B, a);
        if (!fail) f.Apply(20 * B, b);
        f.Fresh(B, B);
        f.Fresh(20 * B, B);
        f.Retained(10 * B, B);
        if (!fail) Check(f.device->PerformanceJson().find("\"asyncBatchWrite\":{\"count\":1") !=
            std::string::npos, "async path actually ran");
    }
    Fixture large(root, "async-split.bin", 1536);
    large.Read(0, B);
    large.Read(1200 * B, B);
    const std::vector<std::byte> data(4 * 1024 * 1024, std::byte{0xc3});
    const std::array<Device::WriteSpan, 1> writes{{{0, data}}};
    Check(large.device->WriteBatch(writes), "single large batch splits into async chunks");
    large.Apply(0, data);
    large.Fresh(0, B);
    large.Retained(1200 * B, B);
}

void Faults(const std::filesystem::path& root)
{
    const std::array<const wchar_t*, 6> modes{L"fail", L"zero-bytes", L"first-sector",
        L"first-half", L"all-except-last-sector", L"corrupt-one-byte"};
    unsigned index = 0;
    for (auto mode : modes)
    {
        const auto name = "fault-" + std::to_string(index++) + ".bin";
        Fixture f(root, name.c_str());
        f.Read(2 * B, 2 * B);
        f.Read(10 * B, B);
        const std::vector<std::byte> data(2 * B, std::byte{0xd4});
        {
            Env fault(L"APFSACCESS_RW_FAULT_WRITE", mode);
            Check(!f.device->Write(2 * B, data), "fault write reports failure");
        }
        const auto m = std::wstring_view(mode);
        if (m == L"corrupt-one-byte")
        {
            auto corrupt = data;
            corrupt.front() ^= std::byte{0xff};
            f.Apply(2 * B, corrupt);
        }
        else if (m != L"fail" && m != L"zero-bytes")
            f.Apply(2 * B, std::vector<std::byte>(data.begin(), data.begin() + B));
        f.Fresh(2 * B, 2 * B);
        f.Retained(10 * B, B);
    }
    Fixture batch(root, "fault-batch.bin");
    batch.Read(2 * B, 2 * B);
    batch.Read(10 * B, B);
    const std::vector<std::byte> data(2 * B, std::byte{0xe5});
    const std::array<Device::WriteSpan, 2> writes{{{2 * B, data}, {20 * B, data}}};
    {
        Env fault(L"APFSACCESS_RW_FAULT_WRITE", L"first-half");
        Check(!batch.device->WriteBatch(writes), "fault batch stops after partial first span");
    }
    batch.Apply(2 * B, std::vector<std::byte>(data.begin(), data.begin() + B));
    batch.Fresh(2 * B, 2 * B);
    batch.Retained(10 * B, B);
    batch.Read(20 * B, 2 * B);

    Fixture rmw(root, "fault-rmw.bin", 32, 512);
    rmw.Read(0, 3 * B - 512);
    rmw.Read(3 * B - 512, B);
    const std::vector<std::byte> unaligned(2 * B, std::byte{0xf6});
    {
        Env fault(L"APFSACCESS_RW_FAULT_WRITE", L"first-half");
        Check(!rmw.device->Write(200, unaligned), "unaligned partial RMW reports failure");
    }
    std::copy_n(unaligned.begin(), 3 * B / 2 - (512 + 200), rmw.expected.begin() + 512 + 200);
    rmw.Fresh(0, 3 * B - 512);
    rmw.Retained(3 * B - 512, B);
}

struct Gate
{
    std::mutex mutex;
    std::condition_variable cv;
    unsigned arrived = 0;
    bool released = false;
    void Stop()
    {
        std::unique_lock lock(mutex);
        ++arrived;
        cv.notify_all();
        if (!cv.wait_for(lock, std::chrono::seconds(15), [&] { return released; }))
            throw std::runtime_error("bounded hook wait timed out");
    }
    bool Wait(unsigned count)
    {
        std::unique_lock lock(mutex);
        return cv.wait_for(lock, std::chrono::seconds(10), [&] { return arrived >= count; });
    }
    void Release()
    {
        std::lock_guard lock(mutex);
        released = true;
        cv.notify_all();
    }
};

void PredatingMiss(const std::filesystem::path& root)
{
    for (bool aligned : {true, false}) for (bool overlap : {true, false})
    {
        const auto name = "miss-" + std::to_string(aligned) + std::to_string(overlap) + ".bin";
        Fixture f(root, name.c_str());
        const auto offset = aligned ? B : B + 71;
        const auto count = aligned ? B : B - 131;
        Gate gate;
        f.device->SetReadCacheMissHookForTests([&] { gate.Stop(); });
        bool ok = false;
        std::vector<std::byte> old;
        std::exception_ptr error;
        std::thread reader([&] {
            try { ok = f.device->Read(offset, count, old); }
            catch (...) { error = std::current_exception(); }
        });
        const bool reached = gate.Wait(1);
        const std::vector<std::byte> data(B, std::byte{0x56});
        const auto target = overlap ? B : 10 * B;
        const bool written = reached && f.device->Write(target, data);
        gate.Release();
        reader.join();
        f.device->SetReadCacheMissHookForTests({});
        if (error) std::rethrow_exception(error);
        Check(reached && ok && written, "bounded pre-write miss interleave completed");
        Check(std::equal(old.begin(), old.end(), f.expected.begin() + f.base + offset),
            "reader captured old bytes before writer");
        f.Apply(target, data);
        Check(Peer::Get(*f.device).entries == 0, "predating miss cannot insert even after unrelated write");
        f.Fresh(offset, count);
    }
}

void Admissions(const std::filesystem::path& root)
{
    Fixture f(root, "admissions.bin");
    f.Read(10 * B, B);
    Gate gate;
    f.device->SetWriteCacheInvalidationHookForTests([&] { gate.Stop(); });
    auto epoch = Peer::LockEpoch(*f.device);
    const auto generation = Peer::Get(*f.device).generation;
    const std::vector<std::byte> data(B, std::byte{0x67});
    bool first = false, second = false;
    std::thread a([&] { first = f.device->Write(B, data); });
    std::thread b([&] { second = f.device->Write(2 * B, data); });
    const bool arrived = gate.Wait(2);
    const auto during = Peer::Get(*f.device);
    const auto raw = during.raw_reads;
    f.Read(10 * B, B);
    const bool bypassed = Peer::Get(*f.device).raw_reads == raw + 1;
    gate.Release();
    epoch.unlock();
    a.join();
    b.join();
    f.device->SetWriteCacheInvalidationHookForTests({});
    Check(arrived && during.admissions == 2 && bypassed && first && second,
        "both queued admissions fence otherwise-valid hits");
    f.Apply(B, data);
    f.Apply(2 * B, data);
    const auto after = Peer::Get(*f.device);
    Check(after.generation == generation + 4 && after.admissions == 0,
        "consecutive serialized writers close both epochs and admissions");
    f.Retained(10 * B, B);

    auto write = Peer::LockWrite(*f.device);
    bool written = false;
    std::thread writer([&] { written = f.device->Write(3 * B, data); });
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while ((Peer::Get(*f.device).generation & 1) == 0 && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    const bool odd = (Peer::Get(*f.device).generation & 1) != 0;
    f.Read(15 * B, B);
    const bool not_inserted = !Peer::Contains(*f.device, f.base + 15 * B, B);
    write.unlock();
    writer.join();
    Check(odd && written && not_inserted, "miss starting inside odd epoch cannot survive");
    f.Apply(3 * B, data);
    f.Fresh(15 * B, B);

    f.device->SetWriteCacheInvalidationHookForTests([] { throw std::runtime_error("admission unwind"); });
    bool threw = false;
    try { (void)f.device->Write(4 * B, data); } catch (const std::runtime_error&) { threw = true; }
    f.device->SetWriteCacheInvalidationHookForTests({});
    Check(threw && Peer::Get(*f.device).admissions == 0 &&
        (Peer::Get(*f.device).generation & 1) == 0, "exception restores cache admission and epoch");
    Check(f.device->Write(4 * B, data), "writer works after hook unwind");
    f.Apply(4 * B, data);
    f.Fresh(4 * B, B);
}

void BoundsAndLifecycle(const std::filesystem::path& root)
{
    Fixture f(root, "bounds.bin", 32, 0);
    f.Read(B, B);
    const std::vector<std::byte> bytes(64, std::byte{0x78});
    Check(!f.device->Write((std::numeric_limits<std::uint64_t>::max)() - 31, bytes),
        "overflowed write fails without mutation");
    Check(Peer::Get(*f.device).entries == 0, "overflowed interval falls back to full clear");
    f.Read(B, B);
    Check(!f.device->Write((std::numeric_limits<std::uint64_t>::max)() - 511, bytes),
        "alignment rounding overflow fails without mutation");
    Check(Peer::Get(*f.device).entries == 0, "alignment overflow falls back to full clear");
    f.Read(B, B);
    const auto before = Peer::Get(*f.device);
    Check(f.device->Write(0, std::span<const std::byte>{}) &&
        f.device->WriteBatch(std::array<Device::WriteSpan, 1>{{{0, {}}}}), "empty writes are no-ops");
    Check(Peer::Get(*f.device).generation == before.generation &&
        Peer::Get(*f.device).entries == before.entries, "empty writes preserve generation and cache");
    Peer::UnknownEpoch(*f.device);
    Check(Peer::Get(*f.device).entries == 0, "retained no-argument unknown epoch clears all");
    f.Read(B, B);
    Peer::RestrictToHeldFile(*f.device, 32 * B);
    Check(!f.device->Write(32 * B - 1, bytes), "aligned RMW outside admitted file bound rejected");
    Check(Peer::Get(*f.device).entries == 0, "unvalidated bound uses full invalidation");

    if (selective)
    {
        Fixture loss(root, "presence-loss.bin", 32, 0);
        loss.Read(B, B);
        loss.Read(10 * B, B);
        Peer::RestrictToHeldFile(*loss.device, 32 * B);
        Peer::InstallPresenceLoss(*loss.device);
        Check(!loss.device->Flush(), "flush detects simulated loss on held ordinary file");
        Check(Peer::Get(*loss.device).entries == 0, "presence loss fully invalidates even with busy write mutex");
        Fixture close(root, "close.bin");
        close.Read(B, B);
        const auto generation = Peer::Get(*close.device).generation;
        Peer::Close(*close.device);
        Check(Peer::Get(*close.device).entries == 0 &&
            Peer::Get(*close.device).generation == generation + 2, "handle retirement fully clears and fences misses");
        std::vector<std::byte> refused;
        Check(!close.device->Read(B, B, refused), "retired exclusive image keeps existing refusal to reopen");

        const auto path = root / "ordinary-retirement.bin";
        const std::vector<std::byte> old(16 * B, std::byte{0x28}), newer(16 * B, std::byte{0x39});
        Seed(path, old);
        Device ordinary(path.wstring());
        Gate gate;
        ordinary.SetReadCacheMissHookForTests([&] { gate.Stop(); });
        std::vector<std::byte> captured;
        bool read_ok = false;
        std::thread reader([&] { read_ok = ordinary.Read(B, B, captured); });
        const bool reached = gate.Wait(1);
        Peer::Close(ordinary);
        Seed(path, newer);
        gate.Release();
        reader.join();
        ordinary.SetReadCacheMissHookForTests({});
        Check(reached && read_ok && captured == std::vector<std::byte>(B, std::byte{0x28}),
            "old ordinary-file read finished before controlled handle retirement");
        Check(Peer::Get(ordinary).entries == 0, "pre-retirement miss cannot insert stale bytes");
        Check(ordinary.Read(B, B, captured) && captured == std::vector<std::byte>(B, std::byte{0x39}),
            "ordinary reopen reads replacement backing bytes");
    }
}

bool ExternalWrite(const std::filesystem::path& path, std::size_t offset, const std::vector<std::byte>& data)
{
    const auto h = CreateFileW(path.c_str(), GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER position{};
    position.QuadPart = offset;
    DWORD done = 0;
    const bool ok = SetFilePointerEx(h, position, nullptr, FILE_BEGIN) &&
        WriteFile(h, data.data(), static_cast<DWORD>(data.size()), &done, nullptr) &&
        done == data.size() && FlushFileBuffers(h);
    CloseHandle(h);
    return ok;
}

void VerificationAndFlush(const std::filesystem::path& root)
{
    const auto path = root / "verification-loss.bin";
    const std::vector<std::byte> original(32 * B, std::byte{0x19});
    Seed(path, original);
    Device d(path.wstring());
    const std::vector<std::byte> first(B, std::byte{0x2a}), second(B, std::byte{0x3b});
    Check(d.Write(B, first) && d.Write(B, second), "consecutive writes before verification");
    std::vector<std::byte> actual;
    Check(d.Read(B, B, actual) && actual == second, "warm published candidate bytes");
    const auto before = Peer::Get(d);
    {
        Env fault(L"APFSACCESS_RW_FAULT_FLUSH", L"1");
        Check(!d.Flush(), "injected flush failure remains failure");
    }
    Check(Peer::Get(d).generation == before.generation, "flush failure cannot mint a new cache epoch");
    Check(d.Flush(), "actual private file flush succeeds after fault removed");
    const std::vector<std::byte> lost(B, std::byte{0x19});
    Check(ExternalWrite(path, B, lost), "simulate lost bytes on private regular file only");
    const auto verify_before = Peer::Get(d);
    Check(d.ReadForVerification(B, B, actual) && actual == lost && actual != second,
        "verification bypass exposes lost bytes despite warm candidate cache");
    Check(Peer::Get(d).hits == verify_before.hits && Peer::Get(d).raw_reads == verify_before.raw_reads + 1,
        "verification uses actual held-file I/O");
    Check(d.Read(B, B, actual) && actual == second, "verification does not repair ordinary cache");
    Check(d.ReadForVerification(10 * B, B, actual), "cold verification succeeds");
    Check(!Peer::Contains(d, 10 * B, B), "verification does not populate cold ordinary cache");
    Check(ExternalWrite(path, 10 * B, first), "change cold verification block");
    Check(d.Read(10 * B, B, actual) && actual == first, "ordinary read after cold verification remains fresh");
}

void Measure(const std::filesystem::path& root)
{
    constexpr std::size_t entries = 1721;
    Fixture f(root, "working-set.bin", entries + 8);
    for (std::size_t block = 0; block < entries; ++block) f.Read(block * B, B);
    Check(Peer::Get(*f.device).entries == entries && Peer::Get(*f.device).bytes == entries * B,
        "measured-shape working set fits the existing 8 MiB/2048 cache");
    const auto before = Peer::Get(*f.device);
    const auto started = std::chrono::steady_clock::now();
    for (std::size_t publication = 0; publication < 8; ++publication)
    {
        const auto offset = (100 + 2 * publication) * B;
        const std::vector<std::byte> data(B, static_cast<std::byte>(0x40 + publication));
        Check(f.device->Write(offset, data), "publication single write");
        f.Apply(offset, data);
        const std::array<Device::WriteSpan, 1> writes{{{offset + B, data}}};
        Check(f.device->WriteBatch(writes), "publication batch write");
        f.Apply(offset + B, data);
        Check(f.device->Flush(), "publication flush");
        std::vector<std::byte> verification;
        Check(f.device->ReadForVerification(offset, 2 * B, verification) &&
            std::equal(verification.begin(), verification.end(), f.expected.begin() + f.base + offset),
            "publication uncached verification bytes");
        for (std::size_t block = 0; block < entries; ++block) f.Read(block * B, B);
    }
    const auto after = Peer::Get(*f.device);
    const auto raw = after.raw_reads - before.raw_reads;
    Check(raw == (selective ? 24 : entries * 8 + 8), "deterministic raw-read count across eight publications");
    Check(after.generation == before.generation + 32, "all sixteen writes retain global epoch bumps");
    const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - started).count();
    std::cout << "[MEASURE] {\"mode\":\"" << (selective ? "candidate" : "baseline")
        << "\",\"entries\":" << entries << ",\"workingSetBytes\":" << entries * B
        << ",\"publications\":8,\"writes\":16,\"rawReads\":" << raw
        << ",\"rawBytes\":" << after.raw_bytes - before.raw_bytes
        << ",\"hits\":" << after.hits - before.hits << ",\"elapsedUs\":" << elapsed << "}\n";
}
}

int main(int argc, char** argv)
{
    try
    {
        if (argc != 2) throw std::runtime_error("Fresh absolute fixture directory required");
        const std::filesystem::path root(argv[1]);
        Check(root.is_absolute() && root != root.root_path() && !std::filesystem::exists(root),
            "fixture requires a fresh non-root directory");
        std::filesystem::create_directories(root);
        Env cache(L"APFSACCESS_EXPERIMENTAL_BLOCK_READ_CACHE", L"1");
        Env budget(L"APFSACCESS_BLOCK_READ_CACHE_ENTRIES", L"2048");
        Env perf(L"APFSACCESS_PERF_COUNTERS", L"1");
        Env fault(L"APFSACCESS_RW_FAULT_WRITE", nullptr);
        Env flush(L"APFSACCESS_RW_FAULT_FLUSH", nullptr);
        Env async_fault(L"APFSACCESS_RW_FAULT_ASYNC_BATCH_AFTER_ISSUES", nullptr);
        const std::array<std::pair<const char*, void(*)(const std::filesystem::path&)>, 10> tests{{
            {"windows", Windows}, {"alignment", Alignment}, {"batches", Batches}, {"async", Async},
            {"faults", Faults}, {"predating misses", PredatingMiss}, {"admissions", Admissions},
            {"bounds and lifecycle", BoundsAndLifecycle}, {"verification and flush", VerificationAndFlush},
            {"working-set differential", Measure}}};
        for (const auto& [name, test] : tests)
        {
            test(root);
            std::cout << "[PASS] " << name << '\n';
        }
        std::cout << "[PASS] " << checks << " checks; mode=" << (selective ? "candidate" : "baseline") << '\n';
        return 0;
    }
    catch (const std::exception& e)
    {
        std::cerr << "[FAIL] after " << checks << " checks: " << e.what() << '\n';
        return 1;
    }
}
