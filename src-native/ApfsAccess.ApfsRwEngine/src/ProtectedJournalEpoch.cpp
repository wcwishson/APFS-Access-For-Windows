#include "ProtectedJournalEpoch.h"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#include <dpapi.h>
#include <algorithm>
#include <cstring>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#ifdef APFSACCESS_PROTECTED_JOURNAL_TESTING
namespace apfsaccess::journal::testing { thread_local EpochHooks hooks; }
#endif

namespace apfsaccess::journal
{
namespace
{
using Error = JournalError;
constexpr std::size_t kSlotHeader = 72, kSlotChecksum = 32, kProtectedBytes = 88, kAadBytes = 140;
constexpr char kSlotMagic[] = "APFSEPK1", kRecordMagic[] = "APFSREC1", kKeyDomain[] = "APFSKEY1";
JournalStatus Fail(Error error, DWORD os = 0) noexcept { return {error, os, crypto::CryptoError::None}; }
JournalStatus FromCrypto(const crypto::CryptoResult& r) noexcept
{
    return {r.error == crypto::CryptoError::IntegrityFailure ? Error::IntegrityFailure : Error::CryptoFailure,
        r.os_status, r.error};
}
bool Zero(std::span<const std::byte> bytes) noexcept
{ return std::all_of(bytes.begin(), bytes.end(), [](auto b) { return b == std::byte{}; }); }
bool Same(std::span<const std::byte> a, std::span<const std::byte> b) noexcept
{
    if (a.size() != b.size()) return false;
    volatile unsigned difference = 0;
    for (std::size_t i = 0; i < a.size(); ++i) difference = difference | std::to_integer<unsigned>(a[i] ^ b[i]);
    return difference == 0;
}
PUCHAR Data(std::span<const std::byte> b) noexcept
{ return reinterpret_cast<PUCHAR>(const_cast<std::byte*>(b.data())); }
void Put(std::span<std::byte> b, std::size_t at, std::uint64_t n, unsigned bytes) noexcept
{ for (unsigned i = 0; i < bytes; ++i) b[at + i] = static_cast<std::byte>((n >> (8 * i)) & 255); }
std::uint32_t U32(std::span<const std::byte> b, std::size_t at) noexcept
{
    std::uint32_t n = 0;
    for (unsigned i = 0; i < 4; ++i) n |= std::to_integer<std::uint32_t>(b[at + i]) << (8 * i);
    return n;
}
bool Magic(std::span<const std::byte> b, const char* magic) noexcept
{ return b.size() >= 8 && std::memcmp(b.data(), magic, 8) == 0; }
bool Binding(std::span<const std::byte> b) noexcept { return b.size() == 32 && !Zero(b); }
bool Context(const JournalRecordContext& c) noexcept { return c.purpose != 0 && !Zero(c.operation); }
JournalStatus Checksum(std::span<const std::byte> input, std::span<std::byte> digest) noexcept
{
    // Encoding checksum only: reject noncanonical/corrupt DPAPI encodings even
    // if Windows ignores a changed blob field. DPAPI and the record GCM tag,
    // not this unkeyed checksum, provide adversarial authenticity.
    const auto status = BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0, Data(input),
        static_cast<ULONG>(input.size()), reinterpret_cast<PUCHAR>(digest.data()), static_cast<ULONG>(digest.size()));
    return status < 0 ? JournalStatus{Error::CryptoFailure, static_cast<std::uint32_t>(status), crypto::CryptoError::ProviderFailure} : JournalStatus{};
}

class Handle final
{
public:
    HANDLE value = INVALID_HANDLE_VALUE;
    Handle() noexcept = default;
    explicit Handle(HANDLE h) noexcept : value(h) {}
    ~Handle() noexcept { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    Handle(Handle&& h) noexcept : value(std::exchange(h.value, INVALID_HANDLE_VALUE)) {}
    Handle& operator=(Handle&& h) noexcept
    {
        if (this != &h) { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); value = std::exchange(h.value, INVALID_HANDLE_VALUE); }
        return *this;
    }
};

// Same local path/ancestor sharing-denial pattern as ApfsFusionStore::LockedImage.
bool PathSyntax(std::wstring_view p) noexcept
{
    if (p.size() < 4 || p.size() > 240 || !((p[0] >= L'A' && p[0] <= L'Z') ||
        (p[0] >= L'a' && p[0] <= L'z')) || p[1] != L':' || p[2] != L'\\' ||
        p.back() == L'\\' || p.find_first_of(L":/*?\"<>|", 3) != p.npos) return false;
    for (auto c : p) if (c < 32) return false;
    for (std::size_t at = 3; at < p.size();)
    {
        auto end = p.find(L'\\', at); if (end == p.npos) end = p.size();
        const auto part = p.substr(at, end - at);
        if (part.empty() || part == L"." || part == L".." || part.back() == L'.' || part.back() == L' ') return false;
        auto stem = part.substr(0, part.find(L'.'));
        const auto is = [&](std::wstring_view s) {
            return stem.size() == s.size() && CompareStringOrdinal(stem.data(), static_cast<int>(stem.size()), s.data(), static_cast<int>(s.size()), TRUE) == CSTR_EQUAL;
        };
        if (is(L"CON") || is(L"PRN") || is(L"AUX") || is(L"NUL") || is(L"CONIN$") || is(L"CONOUT$")) return false;
        if (stem.size() == 4 && (CompareStringOrdinal(stem.data(), 3, L"COM", 3, TRUE) == CSTR_EQUAL ||
            CompareStringOrdinal(stem.data(), 3, L"LPT", 3, TRUE) == CSTR_EQUAL)) return false;
        at = end + 1;
    }
    return true;
}
bool ExactHandle(HANDLE h, const std::wstring& expected, bool directory)
{
    BY_HANDLE_FILE_INFORMATION info{};
    if (GetFileType(h) != FILE_TYPE_DISK || !GetFileInformationByHandle(h, &info) ||
        (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
        ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) != directory ||
        (!directory && info.nNumberOfLinks != 1)) return false;
    std::wstring actual(512, L'\0');
    const auto n = GetFinalPathNameByHandleW(h, actual.data(), static_cast<DWORD>(actual.size()), FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (!n || n >= actual.size()) return false;
    actual.resize(n);
    const auto target = L"\\\\?\\" + expected;
    return CompareStringOrdinal(actual.c_str(), -1, target.c_str(), -1, TRUE) == CSTR_EQUAL;
}
struct Directory
{
    std::wstring path;
    std::vector<Handle> pins;
    JournalStatus Pin(std::wstring_view p)
    {
        if (!PathSyntax(p)) return Fail(Error::UnsafePath);
        path = p;
        if (GetDriveTypeW(path.substr(0, 3).c_str()) != DRIVE_FIXED) return Fail(Error::UnsafePath);
        for (std::size_t end = 2;;)
        {
            const auto prefix = path.substr(0, end == 2 ? 3 : end);
            Handle h(CreateFileW(prefix.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ, nullptr,
                OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
            if (h.value == INVALID_HANDLE_VALUE) return Fail(Error::IoFailure, GetLastError());
            if (!ExactHandle(h.value, prefix, true)) return Fail(Error::UnsafePath);
            pins.push_back(std::move(h));
            if (end == path.size()) break;
            end = path.find(L'\\', end + 1);
            if (end == path.npos) end = path.size();
        }
        return {};
    }
    std::wstring Child(std::wstring_view name) const { return path + L"\\" + std::wstring(name); }
};
std::wstring SlotName(const JournalEpochId& id)
{
    constexpr wchar_t hex[] = L"0123456789abcdef";
    std::wstring name = L"epoch-";
    for (auto b : id) { const auto n = std::to_integer<unsigned>(b); name += hex[n >> 4]; name += hex[n & 15]; }
    return name + L".key";
}
JournalStatus Read(HANDLE h, std::size_t max, std::vector<std::byte>& out)
{
    LARGE_INTEGER size{}, zero{};
    if (!GetFileSizeEx(h, &size)) return Fail(Error::IoFailure, GetLastError());
    if (size.QuadPart < 0 || static_cast<std::uint64_t>(size.QuadPart) > max) return Fail(Error::ResourceLimit);
    out.resize(static_cast<std::size_t>(size.QuadPart));
    if (!SetFilePointerEx(h, zero, nullptr, FILE_BEGIN)) return Fail(Error::IoFailure, GetLastError());
    DWORD got = 0;
    if (!ReadFile(h, out.data(), static_cast<DWORD>(out.size()), &got, nullptr)) return Fail(Error::IoFailure, GetLastError());
    if (got != out.size()) return Fail(Error::IoFailure, ERROR_HANDLE_EOF);
    return {};
}

#ifdef APFSACCESS_PROTECTED_JOURNAL_TESTING
bool Inject(testing::EpochFault point) noexcept
{
    if (testing::hooks.fault != point || testing::hooks.triggered) return false;
    testing::hooks.triggered = true;
    return true;
}
#define EPOCH_FAULT(point) Inject(testing::EpochFault::point)
#else
#define EPOCH_FAULT(point) false
#endif

struct DpapiBuffer
{
    DATA_BLOB blob{};
    SIZE_T allocation = 0;
    bool locked = false;
    ~DpapiBuffer() noexcept
    {
        if (!blob.pbData) return;
        // LocalSize covers allocator padding too, including error-return buffers.
        const auto bytes = allocation ? allocation : LocalSize(blob.pbData);
        SecureZeroMemory(blob.pbData, bytes ? bytes : blob.cbData);
#ifdef APFSACCESS_PROTECTED_JOURNAL_TESTING
        ++testing::hooks.dpapi_wipes;
        for (SIZE_T i = 0; i < (bytes ? bytes : blob.cbData); ++i)
            if (blob.pbData[i]) testing::hooks.dpapi_released_zero = false;
#endif
        if (locked) {
            VirtualUnlock(blob.pbData, allocation);
#ifdef APFSACCESS_PROTECTED_JOURNAL_TESTING
            ++testing::hooks.dpapi_unlocks;
#endif
        }
        LocalFree(blob.pbData);
#ifdef APFSACCESS_PROTECTED_JOURNAL_TESTING
        ++testing::hooks.dpapi_releases;
#endif
    }
};
void Envelope(std::span<std::byte> b, const JournalEpochId& id, std::span<const std::byte> binding) noexcept
{
    std::memcpy(b.data(), kKeyDomain, 8);
    std::memcpy(b.data() + 8, id.data(), id.size());
    std::memcpy(b.data() + 24, binding.data(), binding.size());
}
JournalStatus Protect(std::span<const std::byte> key, const JournalEpochId& id,
    std::span<const std::byte> binding, std::vector<std::byte>& slot)
{
    auto plain = crypto::SecureBytes::Allocate(kProtectedBytes);
    if (!plain) return FromCrypto(plain);
    Envelope(plain.bytes.Bytes(), id, binding);
    std::memcpy(plain.bytes.Bytes().data() + 56, key.data(), 32);
    DATA_BLOB input{static_cast<DWORD>(kProtectedBytes), Data(plain.bytes.Bytes())};
    DATA_BLOB entropy{56, input.pbData};
    DpapiBuffer wrapped;
    const bool ok = CryptProtectData(&input, nullptr, &entropy, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &wrapped.blob) != FALSE;
    const auto error = ok ? ERROR_SUCCESS : GetLastError();
    if (!ok) return Fail(Error::ProtectionFailure, error);
    if (EPOCH_FAULT(ProtectAfter)) return Fail(Error::ProtectionFailure, ERROR_INVALID_DATA);
    if (!wrapped.blob.pbData || wrapped.blob.cbData == 0 || wrapped.blob.cbData > kMaxJournalKeySlotBytes - kSlotHeader - kSlotChecksum)
        return Fail(Error::ResourceLimit);
    slot.resize(kSlotHeader + wrapped.blob.cbData + kSlotChecksum);
    std::memcpy(slot.data(), kSlotMagic, 8);
    Put(slot, 8, 1, 4); Put(slot, 12, kSlotHeader, 4);
    Put(slot, 16, slot.size(), 4); Put(slot, 20, wrapped.blob.cbData, 4);
    std::memcpy(slot.data() + 24, id.data(), 16);
    std::memcpy(slot.data() + 40, binding.data(), 32);
    std::memcpy(slot.data() + kSlotHeader, wrapped.blob.pbData, wrapped.blob.cbData);
    return Checksum(std::span(slot).first(slot.size() - kSlotChecksum), std::span(slot).last(kSlotChecksum));
}
JournalStatus Unprotect(std::span<const std::byte> slot, const JournalEpochId& id,
    std::span<const std::byte> binding, crypto::SecureBytes& key)
{
    if (slot.size() < kSlotHeader + kSlotChecksum || slot.size() > kMaxJournalKeySlotBytes || !Magic(slot, kSlotMagic) ||
        U32(slot, 8) != 1 || U32(slot, 12) != kSlotHeader || U32(slot, 16) != slot.size() ||
        U32(slot, 20) != slot.size() - kSlotHeader - kSlotChecksum || U32(slot, 20) == 0 || !Same(slot.subspan(24, 16), id))
        return Fail(Error::InvalidFrame);
    if (!Same(slot.subspan(40, 32), binding)) return Fail(Error::BindingMismatch);
    std::array<std::byte, kSlotChecksum> checksum{};
    const auto checked = Checksum(slot.first(slot.size() - kSlotChecksum), checksum);
    if (!checked) return checked;
    if (!Same(checksum, slot.last(kSlotChecksum))) return Fail(Error::InvalidFrame);
    auto expected = crypto::SecureBytes::Allocate(56);
    if (!expected) return FromCrypto(expected);
    Envelope(expected.bytes.Bytes(), id, binding);
    DATA_BLOB entropy{56, Data(expected.bytes.Bytes())};
    DATA_BLOB input{static_cast<DWORD>(slot.size() - kSlotHeader - kSlotChecksum), Data(slot.subspan(kSlotHeader))};
    DpapiBuffer plain;
    const bool ok = CryptUnprotectData(&input, nullptr, &entropy, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &plain.blob) != FALSE;
    const auto error = ok ? ERROR_SUCCESS : GetLastError();
    if (!ok) return Fail(Error::ProtectionFailure, error);
    if (EPOCH_FAULT(UnprotectAfter)) return Fail(Error::ProtectionFailure, ERROR_INVALID_DATA);
    if (!plain.blob.pbData || plain.blob.cbData != kProtectedBytes) return Fail(Error::ProtectionFailure, ERROR_INVALID_DATA);
    plain.allocation = LocalSize(plain.blob.pbData);
    if (plain.allocation < kProtectedBytes) return Fail(Error::ProtectionFailure, ERROR_INVALID_DATA);
    if (!VirtualLock(plain.blob.pbData, plain.allocation))
        return {Error::CryptoFailure, GetLastError(), crypto::CryptoError::MemoryLockFailed};
    plain.locked = true;
    if (!Same({reinterpret_cast<const std::byte*>(plain.blob.pbData), 56}, expected.bytes.Bytes()))
        return Fail(Error::ProtectionFailure, ERROR_INVALID_DATA);
    auto storage = crypto::SecureBytes::Allocate(32);
    if (!storage) return FromCrypto(storage);
    std::memcpy(storage.bytes.Bytes().data(), plain.blob.pbData + 56, 32);
    key = std::move(storage.bytes);
    return {};
}
crypto::CryptoResult Aad(std::span<const std::byte> header, std::span<const std::byte> binding,
    const JournalRecordContext& c) noexcept
{
    auto result = crypto::SecureBytes::Allocate(kAadBytes);
    if (!result) return result;
    const auto b = result.bytes.Bytes();
    std::memcpy(b.data(), header.data(), kJournalRecordHeaderBytes);
    std::memcpy(b.data() + 64, binding.data(), 32);
    Put(b, 96, c.purpose, 4);
    std::memcpy(b.data() + 100, c.operation.data(), 32);
    Put(b, 132, c.chunk, 8);
    return result;
}
} // namespace

struct ProtectedJournalEpoch::Impl
{
    Directory directory;
    Handle lease, slot;
    JournalDigest binding{};
    JournalEpochId id{};
    crypto::SecureBytes key;
    std::mutex mutex;
    std::array<std::byte, 12> next{};
    std::uint64_t attempts = 0;
    bool exhausted = false;
};
ProtectedJournalEpoch::ProtectedJournalEpoch(std::unique_ptr<Impl> impl) noexcept : impl_(std::move(impl)) {}
ProtectedJournalEpoch::~ProtectedJournalEpoch() noexcept = default;
JournalEpochId ProtectedJournalEpoch::Id() const noexcept { return impl_->id; }

JournalEpochAcquisition ProtectedJournalEpoch::AcquireWriter(std::wstring_view directory,
    std::span<const std::byte> binding) noexcept
{
    try
    {
        if (!Binding(binding)) return {Fail(Error::InvalidArgument), {}};
        auto state = std::make_unique<Impl>();
        auto status = state->directory.Pin(directory);
        if (!status) return {status, {}};
        std::memcpy(state->binding.data(), binding.data(), 32);
        const auto leasePath = state->directory.Child(L"writer.lease");
        state->lease = Handle(CreateFileW(leasePath.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
            nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        if (state->lease.value == INVALID_HANDLE_VALUE)
        {
            const auto error = GetLastError();
            return {Fail(error == ERROR_SHARING_VIOLATION ? Error::Busy : Error::IoFailure, error), {}};
        }
        if (!ExactHandle(state->lease.value, leasePath, false)) return {Fail(Error::UnsafePath), {}};
        LARGE_INTEGER size{};
        if (!GetFileSizeEx(state->lease.value, &size)) return {Fail(Error::IoFailure, GetLastError()), {}};
        if (size.QuadPart != 0) return {Fail(Error::InvalidFrame), {}};
        OVERLAPPED range{};
        if (!LockFileEx(state->lease.value, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, MAXDWORD, MAXDWORD, &range))
            return {Fail(Error::Busy, GetLastError()), {}};
        auto storage = crypto::SecureBytes::Allocate(32);
        if (!storage) return {FromCrypto(storage), {}};
        state->key = std::move(storage.bytes);
        if (EPOCH_FAULT(Random)) return {Fail(Error::CryptoFailure, ERROR_GEN_FAILURE), {}};
        auto rng = BCryptGenRandom(nullptr, Data(state->key.Bytes()), 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (rng < 0) return {{Error::CryptoFailure, static_cast<std::uint32_t>(rng), crypto::CryptoError::ProviderFailure}, {}};
        rng = BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(state->id.data()), 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (rng < 0) return {{Error::CryptoFailure, static_cast<std::uint32_t>(rng), crypto::CryptoError::ProviderFailure}, {}};
#ifdef APFSACCESS_PROTECTED_JOURNAL_TESTING
        if (testing::hooks.key_override.size() == 32) std::memcpy(state->key.Bytes().data(), testing::hooks.key_override.data(), 32);
        if (testing::hooks.id_override.size() == 16) std::memcpy(state->id.data(), testing::hooks.id_override.data(), 16);
#endif
        std::vector<std::byte> slot;
        status = Protect(state->key.Bytes(), state->id, binding, slot);
        if (!status) return {status, {}};
        const auto slotPath = state->directory.Child(SlotName(state->id));
        if (EPOCH_FAULT(SlotCreate)) return {Fail(Error::IoFailure, ERROR_WRITE_FAULT), {}};
        state->slot = Handle(CreateFileW(slotPath.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
            nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH, nullptr));
        if (state->slot.value == INVALID_HANDLE_VALUE) return {Fail(Error::IoFailure, GetLastError()), {}};
        if (!ExactHandle(state->slot.value, slotPath, false)) return {Fail(Error::UnsafePath), {}};
        DWORD written = 0;
        if (EPOCH_FAULT(SlotWrite))
        {
            (void)WriteFile(state->slot.value, slot.data(), 13, &written, nullptr);
            return {Fail(Error::IoFailure, ERROR_WRITE_FAULT), {}};
        }
        if (!WriteFile(state->slot.value, slot.data(), static_cast<DWORD>(slot.size()), &written, nullptr))
            return {Fail(Error::IoFailure, GetLastError()), {}};
        if (written != slot.size()) return {Fail(Error::IoFailure, ERROR_WRITE_FAULT), {}};
        if (EPOCH_FAULT(SlotFlush)) return {Fail(Error::IoFailure, ERROR_WRITE_FAULT), {}};
        if (!FlushFileBuffers(state->slot.value)) return {Fail(Error::IoFailure, GetLastError()), {}};
        if (EPOCH_FAULT(SlotReadback)) return {Fail(Error::IoFailure, ERROR_READ_FAULT), {}};
        std::vector<std::byte> readback;
        status = Read(state->slot.value, kMaxJournalKeySlotBytes, readback);
        if (!status) return {status, {}};
        if (!Same(slot, readback)) return {Fail(Error::InvalidFrame), {}};
        crypto::SecureBytes recovered;
        status = Unprotect(readback, state->id, binding, recovered);
        if (!status) return {status, {}};
        if (!Same(recovered.Bytes(), state->key.Bytes())) return {Fail(Error::ProtectionFailure), {}};
        if (EPOCH_FAULT(AfterPublication)) return {Fail(Error::IoFailure, ERROR_WRITE_FAULT), {}};
        return {{}, std::unique_ptr<ProtectedJournalEpoch>(new ProtectedJournalEpoch(std::move(state)))};
    }
    catch (const std::bad_alloc&) { return {Fail(Error::ResourceLimit), {}}; }
    catch (...) { return {Fail(Error::IoFailure, ERROR_UNHANDLED_EXCEPTION), {}}; }
}

JournalRecordResult ProtectedJournalEpoch::Seal(const JournalRecordContext& context,
    std::span<const std::byte> plaintext) noexcept
{
    try
    {
        if (!Context(context)) return {Fail(Error::InvalidArgument), {}};
        if (plaintext.size() > kMaxJournalPlaintextBytes) return {Fail(Error::ResourceLimit), {}};
        std::lock_guard lock(impl_->mutex);
        if (impl_->exhausted || impl_->attempts >= kMaxJournalEpochRecords) return {Fail(Error::NonceExhausted), {}};
        const auto nonce = impl_->next;
        ++impl_->attempts;
        bool carry = true;
        for (std::size_t i = nonce.size(); i && carry;)
        {
            --i;
            const auto n = std::to_integer<unsigned>(impl_->next[i]) + 1;
            impl_->next[i] = static_cast<std::byte>(n & 255);
            carry = n == 256;
        }
        impl_->exhausted = carry;
        auto frame = crypto::SecureBytes::Allocate(kJournalRecordHeaderBytes + plaintext.size() + crypto::kGcmTagBytes);
        if (!frame) return {FromCrypto(frame), {}};
        const auto b = frame.bytes.Bytes();
        std::memcpy(b.data(), kRecordMagic, 8);
        Put(b, 8, 1, 4); Put(b, 12, kJournalRecordHeaderBytes, 4);
        Put(b, 16, b.size(), 4); Put(b, 20, b.size() - kJournalRecordHeaderBytes, 4);
        std::memcpy(b.data() + 24, impl_->id.data(), 16);
        std::memcpy(b.data() + 40, nonce.data(), 12);
        auto aad = Aad(b.first(kJournalRecordHeaderBytes), impl_->binding, context);
        if (!aad) return {FromCrypto(aad), {}};
        auto sealed = crypto::Aes256GcmSeal(impl_->key.Bytes(), nonce, plaintext, aad.bytes.Bytes());
        if (!sealed) return {FromCrypto(sealed), {}};
        std::memcpy(b.data() + kJournalRecordHeaderBytes, sealed.bytes.Bytes().data(), sealed.bytes.Size());
        return {{}, std::move(frame.bytes)};
    }
    catch (const std::bad_alloc&) { return {Fail(Error::ResourceLimit), {}}; }
    catch (...) { return {Fail(Error::IoFailure, ERROR_UNHANDLED_EXCEPTION), {}}; }
}
JournalRecordResult ProtectedJournalEpoch::Open(std::wstring_view directory,
    std::span<const std::byte> binding, const JournalRecordContext& expected_context,
    std::span<const std::byte> record) noexcept
{
    try
    {
        if (!Binding(binding) || !Context(expected_context)) return {Fail(Error::InvalidArgument), {}};
        if (record.size() > kMaxJournalRecordBytes) return {Fail(Error::ResourceLimit), {}};
        if (record.size() < kJournalRecordHeaderBytes + crypto::kGcmTagBytes || !Magic(record, kRecordMagic) ||
            U32(record, 8) != 1 || U32(record, 12) != kJournalRecordHeaderBytes || U32(record, 16) != record.size() ||
            U32(record, 20) != record.size() - kJournalRecordHeaderBytes || !Zero(record.subspan(52, 12)))
            return {Fail(Error::InvalidFrame), {}};
        JournalEpochId id{};
        std::memcpy(id.data(), record.data() + 24, 16);
        Directory pinned;
        auto status = pinned.Pin(directory);
        if (!status) return {status, {}};
        const auto path = pinned.Child(SlotName(id));
        Handle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        if (file.value == INVALID_HANDLE_VALUE)
        {
            const auto error = GetLastError();
            return {Fail(error == ERROR_FILE_NOT_FOUND ? Error::MissingKey : Error::IoFailure, error), {}};
        }
        if (!ExactHandle(file.value, path, false)) return {Fail(Error::UnsafePath), {}};
        std::vector<std::byte> slot;
        status = Read(file.value, kMaxJournalKeySlotBytes, slot);
        if (!status) return {status, {}};
        crypto::SecureBytes key;
        status = Unprotect(slot, id, binding, key);
        if (!status) return {status, {}};
        auto aad = Aad(record.first(kJournalRecordHeaderBytes), binding, expected_context);
        if (!aad) return {FromCrypto(aad), {}};
        auto plain = crypto::Aes256GcmOpen(key.Bytes(), record.subspan(40, 12), record.subspan(kJournalRecordHeaderBytes), aad.bytes.Bytes());
        if (!plain) return {FromCrypto(plain), {}};
        return {{}, std::move(plain.bytes)};
    }
    catch (const std::bad_alloc&) { return {Fail(Error::ResourceLimit), {}}; }
    catch (...) { return {Fail(Error::IoFailure, ERROR_UNHANDLED_EXCEPTION), {}}; }
}
struct ProtectedJournalReadPass::Impl
{
    Directory directory;
    JournalDigest binding{};
    JournalEpochId id{};
    crypto::SecureBytes key;
    std::vector<std::byte> slot;
    std::mutex mutex;
    void Clear() noexcept { key.Clear(); slot.clear(); id = {}; }
};
ProtectedJournalReadPass::ProtectedJournalReadPass(std::unique_ptr<Impl> impl) noexcept : impl_(std::move(impl)) {}
ProtectedJournalReadPass::~ProtectedJournalReadPass() noexcept = default;
JournalReadPassAcquisition ProtectedJournalReadPass::Acquire(std::wstring_view directory,
    std::span<const std::byte> binding) noexcept
{
    try
    {
        if (!Binding(binding)) return {Fail(Error::InvalidArgument), {}};
        auto state = std::make_unique<Impl>();
        const auto status = state->directory.Pin(directory);
        if (!status) return {status, {}};
        std::memcpy(state->binding.data(), binding.data(), state->binding.size());
        return {{}, std::unique_ptr<ProtectedJournalReadPass>(new ProtectedJournalReadPass(std::move(state)))};
    }
    catch (const std::bad_alloc&) { return {Fail(Error::ResourceLimit), {}}; }
    catch (...) { return {Fail(Error::IoFailure, ERROR_UNHANDLED_EXCEPTION), {}}; }
}
JournalRecordResult ProtectedJournalReadPass::Open(const JournalRecordContext& expected_context,
    std::span<const std::byte> record) noexcept
{
    try
    {
        std::lock_guard lock(impl_->mutex);
        struct FailureCleanup
        {
            Impl& state; bool succeeded = false;
            ~FailureCleanup() { if (!succeeded) state.Clear(); }
        } cleanup{*impl_};
        if (!Context(expected_context)) return {Fail(Error::InvalidArgument), {}};
        if (record.size() > kMaxJournalRecordBytes) return {Fail(Error::ResourceLimit), {}};
        if (record.size() < kJournalRecordHeaderBytes + crypto::kGcmTagBytes || !Magic(record, kRecordMagic) ||
            U32(record, 8) != 1 || U32(record, 12) != kJournalRecordHeaderBytes || U32(record, 16) != record.size() ||
            U32(record, 20) != record.size() - kJournalRecordHeaderBytes || !Zero(record.subspan(52, 12)))
            return {Fail(Error::InvalidFrame), {}};
        JournalEpochId id{}; std::memcpy(id.data(), record.data() + 24, id.size());
        const auto path = impl_->directory.Child(SlotName(id));
        Handle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        if (file.value == INVALID_HANDLE_VALUE)
        {
            const auto error = GetLastError();
            return {Fail(error == ERROR_FILE_NOT_FOUND ? Error::MissingKey : Error::IoFailure, error), {}};
        }
        if (!ExactHandle(file.value, path, false)) return {Fail(Error::UnsafePath), {}};
        std::vector<std::byte> slot;
        auto status = Read(file.value, kMaxJournalKeySlotBytes, slot);
        if (!status) return {status, {}};
        if (impl_->key.Size() != 32 || impl_->id != id || impl_->slot != slot)
        {
            impl_->Clear();
            crypto::SecureBytes key;
            status = Unprotect(slot, id, impl_->binding, key);
            if (!status) return {status, {}};
            impl_->slot = std::move(slot); impl_->key = std::move(key); impl_->id = id;
        }
        auto aad = Aad(record.first(kJournalRecordHeaderBytes), impl_->binding, expected_context);
        if (!aad) return {FromCrypto(aad), {}};
        auto plain = crypto::Aes256GcmOpen(impl_->key.Bytes(), record.subspan(40, 12),
            record.subspan(kJournalRecordHeaderBytes), aad.bytes.Bytes());
        if (!plain) return {FromCrypto(plain), {}};
        cleanup.succeeded = true;
        return {{}, std::move(plain.bytes)};
    }
    catch (const std::bad_alloc&) { return {Fail(Error::ResourceLimit), {}}; }
    catch (...) { return {Fail(Error::IoFailure, ERROR_UNHANDLED_EXCEPTION), {}}; }
}
#ifdef APFSACCESS_PROTECTED_JOURNAL_TESTING
void ProtectedJournalEpoch::TestSetNextNonce(std::array<std::byte, 12> next, std::uint64_t attempts) noexcept
{
    std::lock_guard lock(impl_->mutex);
    impl_->next = next; impl_->attempts = attempts; impl_->exhausted = false;
}
#endif
} // namespace apfsaccess::journal
