#define NOMINMAX
#include <windows.h>
#include "NativeStandardLocks.h"
#include <array>
#include <filesystem>
#include <iostream>
#include <stdexcept>
using namespace apfsaccess::fshost::standard_mount;
unsigned checks = 0;
void Check(bool value, const char* message) { ++checks; if (!value) throw std::runtime_error(message); }
struct File
{
    HANDLE value = INVALID_HANDLE_VALUE;
    ~File() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};
bool Lock(HANDLE file, std::uint64_t offset, std::uint64_t length, bool exclusive)
{
    OVERLAPPED over{}; over.Offset = static_cast<DWORD>(offset); over.OffsetHigh = static_cast<DWORD>(offset >> 32);
    return !!LockFileEx(file, LOCKFILE_FAIL_IMMEDIATELY | (exclusive ? LOCKFILE_EXCLUSIVE_LOCK : 0), 0,
        static_cast<DWORD>(length), static_cast<DWORD>(length >> 32), &over);
}
bool Unlock(HANDLE file, std::uint64_t offset, std::uint64_t length)
{
    OVERLAPPED over{}; over.Offset = static_cast<DWORD>(offset); over.OffsetHigh = static_cast<DWORD>(offset >> 32);
    return !!UnlockFileEx(file, 0, static_cast<DWORD>(length), static_cast<DWORD>(length >> 32), &over);
}
bool Io(HANDLE file, std::uint64_t offset, DWORD length, bool write)
{
    LARGE_INTEGER at{}; at.QuadPart = static_cast<LONGLONG>(offset);
    if (!SetFilePointerEx(file, at, nullptr, FILE_BEGIN)) throw std::runtime_error("seek");
    std::array<std::byte, 32> buffer{}; DWORD done = 0;
    return !!(write ? WriteFile(file, buffer.data(), length, &done, nullptr) : ReadFile(file, buffer.data(), length, &done, nullptr));
}
int wmain(int argc, wchar_t** argv)
{
    if (argc != 2) return 2;
    const auto root = std::filesystem::path(argv[1]);
    try
    {
        Check(root.is_absolute() && root.filename().wstring().starts_with(L"standard-native-lock-") && !std::filesystem::exists(root), "Fresh owned test root");
        Check(std::filesystem::create_directories(root), "Create root");
        for (const bool first_exclusive : {false, true})
        for (const bool second_exclusive : {false, true})
        for (const bool same_handle : {false, true})
        for (const unsigned scenario : {0u, 1u, 2u, 3u})
        {
            const auto path = root / (std::to_wstring(checks) + L".bin");
            File first, second;
            first.value = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 7, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
            second.value = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 7, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            Check(first.value != INVALID_HANDLE_VALUE && second.value != INVALID_HANDLE_VALUE, "Real NTFS handles");
            std::array<std::byte, 256> seed{}; DWORD written = 0;
            Check(WriteFile(first.value, seed.data(), static_cast<DWORD>(seed.size()), &written, nullptr) && written == seed.size(), "Real NTFS payload");
            RangeLocks table;
            Check(Lock(first.value, 32, 32, first_exclusive) && table.Acquire(1, 17, L"", 32, 32, first_exclusive) == LockAdmission::Allowed, "Initial real lock");
            const auto target = same_handle ? first.value : second.value;
            const auto owner = same_handle ? 1u : 2u;
            const std::uint64_t offset = scenario == 0 ? 0 : scenario == 1 ? 48 : scenario == 2 ? 64 : 32;
            const std::uint64_t length = scenario == 3 ? 32 : 16;
            const auto native_second = Lock(target, offset, length, second_exclusive);
            const auto admitted = table.Acquire(owner, 17, L"", offset, length, second_exclusive);
            if (native_second != (admitted == LockAdmission::Allowed))
                std::cerr << "firstExclusive=" << first_exclusive << " secondExclusive=" << second_exclusive <<
                    " sameHandle=" << same_handle << " scenario=" << scenario << " native=" << native_second <<
                    " admission=" << static_cast<unsigned>(admitted) << '\n';
            Check(native_second == (admitted == LockAdmission::Allowed), "Lock overlap agrees with NTFS");
            for (const unsigned actor : {1u, 2u})
            for (const bool write : {false, true})
            for (const std::uint64_t io_offset : {0ull, 31ull, 32ull, 48ull, 63ull, 64ull, 80ull})
                Check(Io(actor == 1 ? first.value : second.value, io_offset, 2, write) == table.AllowsIo(actor, 17, L"", io_offset, 2, write), "I/O lock behavior agrees with NTFS");
            if (native_second) Check(Unlock(target, offset, length) && table.Release(owner, offset, length) == LockAdmission::Allowed, "Exact second unlock");
            for (const unsigned actor : {1u, 2u})
            for (const bool write : {false, true})
                Check(Io(actor == 1 ? first.value : second.value, 48, 2, write) == table.AllowsIo(actor, 17, L"", 48, 2, write), "One-unlock residual locks agree with NTFS");
            Check(Unlock(first.value, 32, 32) && table.Release(1, 32, 32) == LockAdmission::Allowed, "Exact first unlock");
            Check(!Unlock(first.value, 32, 32) && table.Release(1, 32, 32) == LockAdmission::NotLocked, "Repeated unlock refuses");
            CloseHandle(first.value); first.value = INVALID_HANDLE_VALUE; CloseHandle(second.value); second.value = INVALID_HANDLE_VALUE;
            Check(DeleteFileW(path.c_str()), "Closed own fixture removed");
        }
        std::filesystem::remove(root);
        std::cout << "PASS " << checks << " actual NTFS oracle checks\n"; return 0;
    }
    catch (const std::exception& error) { std::cerr << error.what() << " after " << checks << " checks\n"; return 1; }
}
