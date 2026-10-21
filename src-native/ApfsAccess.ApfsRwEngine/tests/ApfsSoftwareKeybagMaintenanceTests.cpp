#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#include <sddl.h>
#include "ApfsSoftwareKeybagMaintenance.h"
#include "ApfsEncryptedReadSession.h"
#include "EncryptedReadTransport.h"
#include "ApfsKeybagUnlockVectors.h"
#include <algorithm>
#include <array>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <stdexcept>

namespace c = apfsaccess::catalog;
namespace k = apfsaccess::crypto;
namespace t = apfsaccess::transport;
using Bytes = std::span<const std::byte>;
namespace
{
constexpr wchar_t root[] = L"D:\\ApfsAccessScratch\\WindowsClosure\\software-keybag-maintenance-20261016";
constexpr wchar_t fixtures[] = L"D:\\ApfsAccessScratch\\WindowsClosure\\encrypted-fixtures-20261008-173132";
constexpr wchar_t oracle[] = L"D:\\ApfsAccessScratch\\WindowsClosure\\independent-apfs-reader-20261016\\bin\\libfsapfs.dll";
void Check(bool value, const char* why) { if (!value) throw std::runtime_error(why); }
struct Handle
{
    HANDLE h = INVALID_HANDLE_VALUE;
    explicit Handle(HANDLE value = INVALID_HANDLE_VALUE) : h(value) {}
    ~Handle() { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); }
    Handle(const Handle&) = delete;
    void Close() { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); h = INVALID_HANDLE_VALUE; }
};
struct Hash
{
    BCRYPT_ALG_HANDLE a{}; BCRYPT_HASH_HANDLE h{};
    Hash() {
        Check(BCryptOpenAlgorithmProvider(&a, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0, "HashProvider");
        Check(BCryptCreateHash(a, &h, nullptr, 0, nullptr, 0, 0) >= 0, "HashCreate");
    }
    ~Hash() { if (h) BCryptDestroyHash(h); if (a) BCryptCloseAlgorithmProvider(a, 0); }
    void Add(Bytes bytes) { Check(BCryptHashData(h, reinterpret_cast<PUCHAR>(const_cast<std::byte*>(bytes.data())),
        static_cast<ULONG>(bytes.size()), 0) >= 0, "HashData"); }
    std::string Finish() {
        std::array<unsigned char, 32> result{};
        Check(BCryptFinishHash(h, result.data(), 32, 0) >= 0, "HashFinish");
        std::string text; constexpr char hex[] = "0123456789abcdef";
        for (auto byte : result) { text += hex[byte >> 4]; text += hex[byte & 15]; }
        return text;
    }
};
std::string Digest(Bytes bytes) { Hash h; h.Add(bytes); return h.Finish(); }
std::string DigestFile(const std::filesystem::path& path)
{
    Handle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
    const auto failure = GetLastError();
    Check(file.h != INVALID_HANDLE_VALUE, ("HashFileOpen:" + path.filename().string() + ":win32=" + std::to_string(failure)).c_str()); Hash hash;
    std::array<std::byte, 65536> bytes{}; DWORD got = 0;
    do { Check(::ReadFile(file.h, bytes.data(), static_cast<DWORD>(bytes.size()), &got, nullptr), "HashFileRead");
        hash.Add(Bytes(bytes).first(got)); } while (got);
    return hash.Finish();
}
struct Profile
{
    bool native;
    std::uint64_t Base() const { return native ? 0 : 20480; }
    std::uint64_t Size() const { return native ? 134176768 : 4153344; }
    std::uint64_t Inode() const { return native ? 16 : 21; }
    std::size_t Length() const { return native ? 46 : 22; }
    std::wstring Name() const { return native ? L"native-filevault.raw" : L"dfvfs-apfs-encrypted.dmg"; }
    std::wstring Note() const { return native ? L"native-filevault.raw.gz.source-notes" : L"dfvfs-apfs-encrypted.dmg.source-notes"; }
    std::string Pin() const { return native ? "1a46eb22cdab37ae553c5c70b7b172419c9cda7285de7f5b4fd3129c73e29171"
        : "33fe6f183aeb1a95fec68efdab17d59aedbad3d8ef1a117d411117376d9d8485"; }
};
k::SecureBytes Locked(std::size_t count)
{
    auto result = k::SecureBytes::Allocate(count); Check(static_cast<bool>(result), "SecureAllocate");
    return std::move(result.bytes);
}
k::SecureBytes NoteCredential(const Profile& profile)
{
    const auto path = std::filesystem::path(fixtures) / profile.Note();
    Handle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    Check(file.h != INVALID_HANDLE_VALUE, "NoteOpen"); LARGE_INTEGER length{};
    Check(GetFileSizeEx(file.h, &length) && length.QuadPart > 0 && length.QuadPart < 65536, "NoteBounds");
    auto note = Locked(static_cast<std::size_t>(length.QuadPart)); DWORD got = 0;
    Check(::ReadFile(file.h, note.Bytes().data(), static_cast<DWORD>(note.Size()), &got, nullptr) && got == note.Size(), "NoteRead");
    const std::string_view marker = profile.native ? "-passphrase '" : "_APFS_PASSWORD = \"";
    const auto pattern = std::as_bytes(std::span(marker));
    const auto start = std::search(note.Bytes().begin(), note.Bytes().end(), pattern.begin(), pattern.end());
    Check(start != note.Bytes().end(), "NoteSelector");
    const auto first = start + marker.size();
    const auto last = std::find(first, note.Bytes().end(), profile.native ? std::byte{'\''} : std::byte{'"'});
    Check(last != note.Bytes().end() && last > first && last - first <= 512, "NoteCredentialBounds");
    auto result = Locked(static_cast<std::size_t>(last - first));
    std::copy(first, last, result.Bytes().begin()); return result;
}
k::SecureBytes RandomCredential()
{
    auto bytes = Locked(32);
    Check(BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(bytes.Bytes().data()), 32,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0, "CredentialRandom");
    for (auto& byte : bytes.Bytes()) byte = static_cast<std::byte>('!' + (std::to_integer<unsigned>(byte) & 63));
    return bytes;
}
std::wstring Quoted(const std::filesystem::path& path) { return L"\"" + path.wstring() + L"\""; }
DWORD Child(const std::filesystem::path& executable, const std::wstring& arguments,
    Bytes password, const std::filesystem::path& log, Bytes second = {})
{
    Handle token; Check(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token.h), "TokenOpen");
    DWORD length = 0; GetTokenInformation(token.h, TokenUser, nullptr, 0, &length);
    std::vector<std::byte> token_bytes(length);
    Check(GetTokenInformation(token.h, TokenUser, token_bytes.data(), length, &length), "TokenUser");
    LPWSTR sid = nullptr;
    Check(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(token_bytes.data())->User.Sid, &sid), "UserSid");
    const auto sddl = L"O:" + std::wstring(sid) + L"D:P(A;;GA;;;SY)(A;;GA;;;" + sid + L")";
    LocalFree(sid); PSECURITY_DESCRIPTOR descriptor = nullptr;
    Check(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr), "PipeDacl");
    SECURITY_ATTRIBUTES security{sizeof(security), descriptor, TRUE};
    Handle read, write; const bool pipe = CreatePipe(&read.h, &write.h, &security, 4096) != FALSE;
    LocalFree(descriptor); Check(pipe, "PipeCreate");
    Check(SetHandleInformation(write.h, HANDLE_FLAG_INHERIT, 0), "PipeWriterPrivate");
    SECURITY_ATTRIBUTES inherited{sizeof(inherited), nullptr, TRUE};
    Handle output(CreateFileW(log.c_str(), GENERIC_WRITE, FILE_SHARE_READ, &inherited, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
    Check(output.h != INVALID_HANDLE_VALUE, "LogCreate");
    SIZE_T attribute_bytes = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attribute_bytes);
    std::vector<std::byte> attributes(attribute_bytes);
    STARTUPINFOEXW startup{}; startup.StartupInfo.cb = sizeof(startup);
    startup.lpAttributeList = reinterpret_cast<PPROC_THREAD_ATTRIBUTE_LIST>(attributes.data());
    Check(InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, &attribute_bytes), "ChildAttributes");
    HANDLE handles[]{read.h, output.h};
    Check(UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        handles, sizeof(handles), nullptr, nullptr), "ChildHandles");
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = read.h; startup.StartupInfo.hStdOutput = output.h; startup.StartupInfo.hStdError = output.h;
    auto command = Quoted(executable) + L" " + arguments; PROCESS_INFORMATION process{};
    const bool created = CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, TRUE,
        CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, nullptr, root, &startup.StartupInfo, &process) != FALSE;
    DeleteProcThreadAttributeList(startup.lpAttributeList); Check(created, "ChildCreate");
    Handle running(process.hProcess), thread(process.hThread); read.Close();
    const auto frame = [&](Bytes value) {
        std::array<std::byte, 8> header{std::byte{'A'}, std::byte{'P'}, std::byte{'C'}, std::byte{'1'}};
        for (unsigned i = 0; i < 4; ++i) header[4 + i] = static_cast<std::byte>((value.size() >> (8 * i)) & 255);
        DWORD written = 0;
        Check(WriteFile(write.h, header.data(), 8, &written, nullptr) && written == 8, "FrameHeader");
        Check(WriteFile(write.h, value.data(), static_cast<DWORD>(value.size()), &written, nullptr) && written == value.size(), "FramePayload");
    };
    frame(password); if (!second.empty()) frame(second);
#ifndef APFS_KEYBAG_CHILD_DEADLINE_MS
#define APFS_KEYBAG_CHILD_DEADLINE_MS 90000
#endif
    write.Close(); Check(WaitForSingleObject(running.h, APFS_KEYBAG_CHILD_DEADLINE_MS) == WAIT_OBJECT_0, "ChildDeadline");
    DWORD exit = 0; Check(GetExitCodeProcess(running.h, &exit), "ChildExit"); return exit;
}
k::SecureBytes Receive()
{
    const auto input = GetStdHandle(STD_INPUT_HANDLE); SetStdHandle(STD_INPUT_HANDLE, nullptr);
    const std::atomic<bool> cancelled{false};
    auto result = t::ReceiveCredential(input, std::chrono::seconds(10), cancelled);
    Check(static_cast<bool>(result), t::CredentialErrorName(result.error)); return std::move(result.bytes);
}
struct Credentials { k::SecureBytes old_password, new_password; };
Credentials ReceivePair()
{
    auto pair = Receive(); Check(pair.Size() > 36, "PairBounds");
    std::size_t count = 0;
    for (unsigned i = 0; i < 4; ++i) {
        const auto value = std::to_integer<unsigned>(pair.Bytes()[i]);
        Check(value >= '0' && value <= '9', "PairLength"); count = count * 10 + value - '0';
    }
    Check(count > 0 && count + 36 == pair.Size(), "PairExact");
    Credentials result{Locked(count), Locked(32)};
    std::copy_n(pair.Bytes().begin() + 4, count, result.old_password.Bytes().begin());
    std::copy_n(pair.Bytes().begin() + 4 + count, 32, result.new_password.Bytes().begin());
    return result;
}
k::SecureBytes Pair(Bytes old_password, Bytes new_password)
{
    Check(new_password.size() == 32 && old_password.size() < 1000, "PairInputs");
    auto result = Locked(4 + old_password.size() + new_password.size()); auto length = old_password.size();
    for (int i = 3; i >= 0; --i) { result.Bytes()[i] = static_cast<std::byte>('0' + length % 10); length /= 10; }
    std::copy(old_password.begin(), old_password.end(), result.Bytes().begin() + 4);
    std::copy(new_password.begin(), new_password.end(), result.Bytes().begin() + 4 + old_password.size());
    return result;
}
k::SecureBytes Hex(std::string_view input)
{
    Check(!input.empty() && input.size() % 2 == 0, "HexBounds"); auto result = Locked(input.size() / 2);
    const auto nibble = [](char value) { return value <= '9' ? value - '0' : value - 'a' + 10; };
    for (std::size_t i = 0; i < result.Size(); ++i)
        result.Bytes()[i] = static_cast<std::byte>((nibble(input[i * 2]) << 4) | nibble(input[i * 2 + 1]));
    return result;
}
int RecordControls()
{
    namespace f = apfsaccess::keybag_fixture;
    auto credentials = ReceivePair(); unsigned positives = 0, refusals = 0;
    for (const auto& pair : {std::pair{f::Vek, f::Kek}, std::pair{f::Vek, f::Kek16},
        std::pair{f::Class2Vek, f::Kek}, std::pair{f::Class2VekUnderClass2Kek, f::Class2Kek},
        std::pair{f::VekUnderClass2Kek, f::Class2Kek}}) {
        auto vek = Hex(pair.first), kek = Hex(pair.second); c::PasswordUnlockBudget budget;
        auto changed = c::RewrapPasswordKeyRecords(vek.Bytes(), kek.Bytes(), credentials.old_password, credentials.new_password, budget);
        Check(static_cast<bool>(changed), "RecordRewrapClass");
        c::PasswordUnlockBudget old_budget, new_budget, expected_budget;
        auto original = c::DecodePasswordKeyRecords(vek.Bytes(), kek.Bytes(), credentials.old_password.Bytes(), expected_budget);
        auto replacement = c::DecodePasswordKeyRecords(vek.Bytes(), changed.kek_der, credentials.new_password.Bytes(), new_budget);
        auto refused = c::DecodePasswordKeyRecords(vek.Bytes(), changed.kek_der, credentials.old_password.Bytes(), old_budget);
        Check(original && replacement && std::equal(original.xts_key.Bytes().begin(), original.xts_key.Bytes().end(), replacement.xts_key.Bytes().begin()) &&
            !refused && refused.error == c::UnlockError::CredentialOrKeyMismatch && refused.xts_key.Size() == 0, "RecordCredentialSemantics");
        auto retry = c::RewrapPasswordKeyRecords(vek.Bytes(), kek.Bytes(), credentials.old_password, credentials.new_password, budget);
        Check(!retry && retry.error == c::UnlockError::RateLimited && retry.kek_der.empty(), "RecordRetryLimit"); ++positives; ++refusals;
    }
    auto vek = Hex(f::Vek), kek = Hex(f::Kek);
    for (auto bad : {f::UnknownKek, f::Class2PaddedKek, f::ShortInfo, f::NegativeInteger,
        f::NonminimalInteger, f::ZeroIterations, f::OverIterations, f::BadKekWrap, f::ExtraField}) {
        auto bytes = Hex(bad); c::PasswordUnlockBudget budget;
        auto result = c::RewrapPasswordKeyRecords(vek.Bytes(), bytes.Bytes(), credentials.old_password, credentials.new_password, budget);
        Check(!result && result.kek_der.empty(), "RecordMalformedRefusal"); ++refusals;
    }
    c::PasswordUnlockBudget exhausted;
    Check(exhausted.Charge(2'000'000), "ExhaustBudget");
    auto denied = c::RewrapPasswordKeyRecords(vek.Bytes(), kek.Bytes(), credentials.old_password, credentials.new_password, exhausted);
    Check(!denied && denied.error == c::UnlockError::ResourceLimit && denied.kek_der.empty(), "RecordKdfBudget"); ++refusals;
    kek.Bytes().back() ^= std::byte{1}; c::PasswordUnlockBudget bad_hmac;
    denied = c::RewrapPasswordKeyRecords(vek.Bytes(), kek.Bytes(), credentials.old_password, credentials.new_password, bad_hmac);
    Check(!denied && denied.error == c::UnlockError::IntegrityFailure && denied.kek_der.empty(), "RecordHmacRefusal"); ++refusals;
    std::cout << "{\"recordClassesPassed\":" << positives << ",\"refusalControlsPassed\":" << refusals << "}\n";
    return 0;
}
std::unique_ptr<c::ApfsEncryptedReadSession> Open(
    const std::shared_ptr<t::OwnedEncryptedImageSource>& source, Bytes password)
{
    c::UnlockError status; c::EncryptedReadError read_error; c::PasswordUnlockBudget attempts;
    auto selected = c::InspectPasswordKeybagMetadata(*source, 1026, c::KeybagLength::IncludesHeader, status);
    Check(selected && selected->users.size() == 1, "NativeSelection");
    auto request = selected->selection; request.user_uuid = selected->users.front();
    return c::ApfsEncryptedReadSession::Unlock(source, source->SourceIdentity(), source->Revision(),
        request, password, attempts, read_error, status);
}
std::string NativeRead(const std::filesystem::path& image, const Profile& profile, Bytes password, bool success)
{
    auto lease = std::make_shared<t::WindowsImageLease>(image.wstring());
    auto source = std::make_shared<t::OwnedEncryptedImageSource>(lease, profile.Base(), profile.Size());
    auto session = Open(source, password); Check(static_cast<bool>(session) == success, "NativeCredentialOutcome");
    if (!success) return {};
    std::vector<std::byte> bytes;
    Check(session->ReadFile(profile.Inode(), 0, profile.Length(), bytes) == c::EncryptedReadError::None, "NativeKnownRead");
    const auto hash = Digest(bytes); SecureZeroMemory(bytes.data(), bytes.size()); return hash;
}

template<class Signature> Signature Export(HMODULE module, const char* name)
{
    const auto value = GetProcAddress(module, name); Check(value != nullptr, "OracleExport");
    return reinterpret_cast<Signature>(value);
}
int Oracle(const std::filesystem::path& image, const Profile& profile, bool success)
{
    auto password = Receive();
    Check(DigestFile(oracle) == "3d0d4b68e651506ec7fc0c06944f488a0e465bf35a067a9d91ebf3611fdbf83b", "OraclePin");
    HMODULE module = LoadLibraryExW(oracle, nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    Check(module != nullptr, "OracleLoad");
    using P = void*;
    const auto version = Export<const char* (*)()>(module, "libfsapfs_get_version");
    Check(std::string_view(version()) == "20260923", "OracleVersion");
    P error{}, handle{}, container{}, volume{}, file{};
    Check(Export<int (*)(P*, P*)>(module, "libbfio_file_range_initialize")(&handle, &error) == 1, "OracleRangeInit");
    Check(Export<int (*)(P, const wchar_t*, size_t, P*)>(module, "libbfio_file_range_set_name_wide")(
        handle, image.c_str(), image.wstring().size(), &error) == 1, "OracleRangeName");
    Check(Export<int (*)(P, int64_t, uint64_t, P*)>(module, "libbfio_file_range_set")(
        handle, static_cast<int64_t>(profile.Base()), profile.Size(), &error) == 1, "OracleRangeBounds");
    Check(Export<int (*)(P*, P*)>(module, "libfsapfs_container_initialize")(&container, &error) == 1, "OracleContainerInit");
    Check(Export<int (*)(P, P, int, P*)>(module, "libfsapfs_container_open_file_io_handle")(container, handle, 1, &error) == 1, "OracleOpen");
    Check(Export<int (*)(P, int, P*, P*)>(module, "libfsapfs_container_get_volume_by_index")(container, 0, &volume, &error) == 1, "OracleVolume");
    Check(Export<int (*)(P, P*)>(module, "libfsapfs_volume_is_locked")(volume, &error) == 1, "OracleInitiallyLocked");
    Check(Export<int (*)(P, const uint8_t*, size_t, P*)>(module, "libfsapfs_volume_set_utf8_password")(
        volume, reinterpret_cast<const uint8_t*>(password.Bytes().data()), password.Size(), &error) == 1, "OracleSetCredential");
    const auto unlocked = Export<int (*)(P, P*)>(module, "libfsapfs_volume_unlock")(volume, &error);
    Check(unlocked == (success ? 1 : 0), "OracleCredentialOutcome"); password.Clear();
    if (success) {
        Check(Export<int (*)(P, uint64_t, P*, P*)>(module, "libfsapfs_volume_get_file_entry_by_identifier")(
            volume, profile.Inode(), &file, &error) == 1, "OracleFile");
        uint64_t size = 0;
        Check(Export<int (*)(P, uint64_t*, P*)>(module, "libfsapfs_file_entry_get_size")(file, &size, &error) == 1 && size == profile.Length(), "OracleFileSize");
        auto bytes = Locked(profile.Length());
        Check(Export<intptr_t (*)(P, void*, size_t, int64_t, P*)>(module, "libfsapfs_file_entry_read_buffer_at_offset")(
            file, bytes.Bytes().data(), bytes.Size(), 0, &error) == static_cast<intptr_t>(bytes.Size()), "OracleRead");
        const std::string_view known = profile.native ? "APFS-FILEVAULT-GROUND-TRUTH-MARKER-0123456789\n" : "This is another file.\n";
        if (!profile.native) Check(Digest(bytes.Bytes()) == Digest(std::as_bytes(std::span(known))), "OracleKnownAnswer");
        std::cout << "{\"unlocked\":true,\"sha256\":\"" << Digest(bytes.Bytes()) << "\"}\n";
    } else std::cout << "{\"oldCredentialRefused\":true,\"unlockReturn\":0}\n";
    if (file) Export<int (*)(P*, P*)>(module, "libfsapfs_file_entry_free")(&file, nullptr);
    Export<int (*)(P*, P*)>(module, "libfsapfs_volume_free")(&volume, nullptr);
    Export<int (*)(P, P*)>(module, "libfsapfs_container_close")(container, nullptr);
    Export<int (*)(P*, P*)>(module, "libfsapfs_container_free")(&container, nullptr);
    Export<int (*)(P*, P*)>(module, "libbfio_handle_free")(&handle, nullptr);
    if (error) Export<void (*)(P*)>(module, "libfsapfs_error_free")(&error);
    FreeLibrary(module); return 0;
}

int Semantic(const std::filesystem::path& image, const Profile& profile)
{
    auto credentials = ReceivePair();
    auto& old_password = credentials.old_password;
    auto& new_password = credentials.new_password;
    const auto expected = NativeRead(image, profile, old_password.Bytes(), true);
    auto lease = std::make_shared<t::WindowsImageLease>(image.wstring());
    const auto original_identity = lease->Identity();
    auto source = std::make_shared<t::OwnedEncryptedImageSource>(lease, profile.Base(), profile.Size());
    c::UnlockError status; c::PasswordUnlockBudget wrong_identity, wrong_revision, wrong_password, same_password, attempts;
    Check(!c::SoftwareKeybagRewrap::Prepare(source, "wrong-source", source->Revision(), 1026,
        c::KeybagLength::IncludesHeader, old_password, new_password, wrong_identity, status) && status == c::UnlockError::IdentityMismatch, "WrongSource");
    Check(!c::SoftwareKeybagRewrap::Prepare(source, source->SourceIdentity(), source->Revision() + 1, 1026,
        c::KeybagLength::IncludesHeader, old_password, new_password, wrong_revision, status) && status == c::UnlockError::IdentityMismatch, "WrongRevision");
    Check(!c::SoftwareKeybagRewrap::Prepare(source, source->SourceIdentity(), source->Revision(), 1026,
        c::KeybagLength::IncludesHeader, new_password, old_password, wrong_password, status) && status == c::UnlockError::CredentialOrKeyMismatch, "WrongCredential");
    Check(!c::SoftwareKeybagRewrap::Prepare(source, source->SourceIdentity(), source->Revision(), 1026,
        c::KeybagLength::IncludesHeader, old_password, old_password, same_password, status) && status == c::UnlockError::InvalidArgument, "SameCredential");
    auto prepared = c::SoftwareKeybagRewrap::Prepare(source, source->SourceIdentity(), source->Revision(), 1026,
        c::KeybagLength::IncludesHeader, old_password, new_password, attempts, status);
    Check(static_cast<bool>(prepared), "SourceBoundRewrap");
    const auto block = prepared->VolumeBagBlock(), xid = prepared->CheckpointXid();
    std::vector<std::byte> before(prepared->OriginalVolumeBagCiphertext().begin(), prepared->OriginalVolumeBagCiphertext().end());
    std::vector<std::byte> after(prepared->RewrappedVolumeBagCiphertext().begin(), prepared->RewrappedVolumeBagCiphertext().end());
    Check(before.size() == 4096 && after.size() == 4096 && before != after, "ChangedCiphertext");
    prepared.reset();
    Check(source.use_count() == 1, "SourceOwnerRelease"); source.reset();
    Check(lease.use_count() == 1, "LeaseOwnerRelease"); lease.reset();
    Check(image.wstring().starts_with(std::wstring(root) + L"\\run-"), "PrivateDiagnosticPath");
    {
        // Diagnostic-only in-place replacement. This deliberately does not claim
        // canonical publication, retained history safety or lost-switch recovery.
        Handle file(CreateFileW(image.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
            OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_RANDOM_ACCESS, nullptr));
        if (file.h == INVALID_HANDLE_VALUE) throw std::runtime_error("DiagnosticExclusiveOpen:" + std::to_string(GetLastError()));
        BY_HANDLE_FILE_INFORMATION id{};
        Check(GetFileType(file.h) == FILE_TYPE_DISK && GetFileInformationByHandle(file.h, &id) &&
            !(id.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_DEVICE)), "DiagnosticRegularFile");
        const auto identity = "windows-file:" + std::to_string(id.dwVolumeSerialNumber) + ":" +
            std::to_string((uint64_t(id.nFileIndexHigh) << 32) | id.nFileIndexLow) + ":" +
            std::to_string((uint64_t(id.nFileSizeHigh) << 32) | id.nFileSizeLow) + ":" +
            std::to_string((uint64_t(id.ftLastWriteTime.dwHighDateTime) << 32) | id.ftLastWriteTime.dwLowDateTime);
        Check(identity == original_identity, "DiagnosticIdentity");
        LARGE_INTEGER at{}; at.QuadPart = static_cast<LONGLONG>(profile.Base() + block * 4096); DWORD got = 0;
        std::array<std::byte, 4096> guard{};
        Check(SetFilePointerEx(file.h, at, nullptr, FILE_BEGIN) && ::ReadFile(file.h, guard.data(), 4096, &got, nullptr) && got == 4096 &&
            std::equal(guard.begin(), guard.end(), before.begin()), "DiagnosticGuard");
        Check(SetFilePointerEx(file.h, at, nullptr, FILE_BEGIN) && WriteFile(file.h, after.data(), 4096, &got, nullptr) && got == 4096 &&
            FlushFileBuffers(file.h), "DiagnosticWrite");
    }
    Check(NativeRead(image, profile, new_password.Bytes(), true) == expected, "NativeUnchangedVekPayload");
    NativeRead(image, profile, old_password.Bytes(), false);
    std::cout << "{\"sourceBoundRewrap\":true,\"oneKeyGenerationZeroAdmission\":true,\"xid\":" << xid
        << ",\"volumeBagBlock\":" << block << ",\"freshNativeNewSuccess\":true,\"freshNativeOldRefusal\":true,"
        << "\"canonicalPublication\":false,\"lostSwitchRecovery\":false,\"unchangedPayloadSha256\":\"" << expected << "\"}\n";
    return 0;
}
void Absent(const std::filesystem::path& path, Bytes old_password, Bytes new_password)
{
    Handle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
    Check(file.h != INVALID_HANDLE_VALUE, "SecretAuditOpen");
    std::vector<std::byte> bytes(65536 + 1024); std::size_t retained = 0; DWORD got = 0;
    do {
        Check(::ReadFile(file.h, bytes.data() + retained, 65536, &got, nullptr), "SecretAuditRead");
        const Bytes window(bytes.data(), retained + got);
        for (auto needle : {old_password, new_password})
            Check(std::search(window.begin(), window.end(), needle.begin(), needle.end()) == window.end(), "PlaintextCredentialFound");
        retained = (std::min)(window.size(), std::size_t{1024});
        std::copy(window.end() - retained, window.end(), bytes.begin());
    } while (got);
}
int Driver(const std::filesystem::path& executable)
{
    const auto run = std::filesystem::path(root) / (L"run-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64()));
    std::filesystem::create_directory(run);
    {
        auto old_password = Hex(apfsaccess::keybag_fixture::Password), new_password = RandomCredential();
        auto pair = Pair(old_password.Bytes(), new_password.Bytes());
        Check(Child(executable, L"records dfvfs unused", pair.Bytes(), run / L"record-controls.log") == 0, "RecordControlsChild");
        Absent(run / L"record-controls.log", old_password.Bytes(), new_password.Bytes());
    }
    for (bool native : {false, true}) {
        const Profile profile{native}; const auto original = std::filesystem::path(fixtures) / profile.Name();
        Check(DigestFile(original) == profile.Pin(), "OriginalFixturePin");
        const auto image = run / profile.Name(); Check(CopyFileW(original.c_str(), image.c_str(), TRUE), "PrivateCopy");
        auto old_password = NoteCredential(profile), new_password = RandomCredential();
        auto pair = Pair(old_password.Bytes(), new_password.Bytes());
        const auto args = (native ? L" native " : L" dfvfs ") + Quoted(image);
        const auto name = native ? L"native" : L"dfvfs";
        Check(Child(executable, L"oracle-pass" + args, old_password.Bytes(), run / (std::wstring(name) + L"-before.log")) == 0, "OracleBaseline");
        Check(Child(executable, L"semantic" + args, pair.Bytes(), run / (std::wstring(name) + L"-semantic.log")) == 0, "SemanticChild"); pair.Clear();
        Check(Child(executable, L"oracle-pass" + args, new_password.Bytes(), run / (std::wstring(name) + L"-new.log")) == 0, "OracleNew");
        Check(Child(executable, L"oracle-refuse" + args, old_password.Bytes(), run / (std::wstring(name) + L"-old.log")) == 0, "OracleOld");
        Check(DigestFile(original) == profile.Pin(), "OriginalPreserved");
        for (const auto& entry : std::filesystem::directory_iterator(run)) if (entry.is_regular_file())
            Absent(entry.path(), old_password.Bytes(), new_password.Bytes());
        std::cout << (native ? "native" : "dfvfs") << ": authenticated source rewrap and independent new/old semantics passed; canonical publication pending\n";
    }
    std::wcout << L"EVIDENCE " << run.wstring() << L"\n"; return 0;
}
}
int wmain(int argc, wchar_t** argv)
{
    try {
        if (argc == 2 && std::wstring_view(argv[1]) == L"drive") return Driver(argv[0]);
        Check(argc == 4, "Arguments"); const std::wstring_view mode(argv[1]);
        const Profile profile{std::wstring_view(argv[2]) == L"native"};
        if (mode == L"records") return RecordControls();
        if (mode == L"semantic") return Semantic(argv[3], profile);
        Check(mode == L"oracle-pass" || mode == L"oracle-refuse", "Mode");
        return Oracle(argv[3], profile, mode == L"oracle-pass");
    }
    catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
