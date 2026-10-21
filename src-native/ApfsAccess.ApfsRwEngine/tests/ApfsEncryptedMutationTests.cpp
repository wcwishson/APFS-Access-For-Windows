#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include "ApfsEncryptedReadSession.h"
#include "AppleVolumeTransaction.h"
#include "EncryptedReadTransport.h"
#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <map>
#include <stdexcept>

namespace c = apfsaccess::catalog;
namespace r = apfsaccess::rw;
namespace t = apfsaccess::transport;
void Require(bool value, const char* why) { if (!value) throw std::runtime_error(why); }
std::string Hex(std::span<const std::uint8_t> bytes)
{
    std::string text; constexpr char digits[] = "0123456789abcdef";
    for (const auto byte : bytes) { text += digits[byte >> 4]; text += digits[byte & 15]; }
    return text;
}
std::string Hash(std::span<const std::byte> bytes)
{
    BCRYPT_ALG_HANDLE algorithm = nullptr; std::array<std::uint8_t, 32> digest{};
    Require(bytes.size() <= ULONG_MAX && BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0, "HashProvider");
    const auto status = BCryptHash(algorithm, nullptr, 0, reinterpret_cast<PUCHAR>(const_cast<std::byte*>(bytes.data())),
        static_cast<ULONG>(bytes.size()), digest.data(), static_cast<ULONG>(digest.size()));
    BCryptCloseAlgorithmProvider(algorithm, 0); Require(status >= 0, "HashResult"); return Hex(digest);
}
struct SensitiveBytes
{
    std::vector<std::byte> data;
    ~SensitiveBytes() { SecureZeroMemory(data.data(), data.size()); }
};
bool SameNonPermissionIntent(const c::EncryptedCowOverwrite& a, const c::EncryptedCowOverwrite& b)
{
    return a.SourceIdentity() == b.SourceIdentity() && a.IntentKind() == b.IntentKind() &&
        a.RequestedInode() == b.RequestedInode() && a.RequestedOffset() == b.RequestedOffset() &&
        a.ReplacementLength() == b.ReplacementLength() && a.ReplacementSha256() == b.ReplacementSha256() &&
        a.IntentInode() == b.IntentInode() && a.IntentOffset() == b.IntentOffset() &&
        a.IntentLength() == b.IntentLength() && a.IntentSha256() == b.IntentSha256() &&
        a.IntentParent() == b.IntentParent() && a.IntentDestinationParent() == b.IntentDestinationParent() &&
        a.IntentNameSha256() == b.IntentNameSha256() && a.IntentDestinationNameSha256() == b.IntentDestinationNameSha256() &&
        a.ResultSize() == b.ResultSize() && a.SourceCheckpointXid() == b.SourceCheckpointXid() &&
        a.PublishedCheckpointXid() == b.PublishedCheckpointXid() && a.VolumeObjectId() == b.VolumeObjectId() &&
        a.VolumeUuid() == b.VolumeUuid() && a.RequiredCheckpointXids() == b.RequiredCheckpointXids();
}
struct Target final : r::AppleCheckpointWriteTarget
{
    HANDLE handle = INVALID_HANDLE_VALUE;
    std::uint64_t base, size; std::size_t writes = 0, flushes = 0, lease_retries = 0;
    Target(const std::wstring& path, std::uint64_t offset, std::uint64_t length, const std::string& expected)
        : base(offset), size(length)
    {
        Require(path.starts_with(L"D:\\ApfsAccessScratch\\WindowsClosure\\encrypted-mutations-20261016\\") ||
            path.starts_with(L"D:\\ApfsAccessScratch\\WindowsClosure\\encrypted-permission-intent-20261016\\"), "PrivateDImageRequired");
        for (;;) {
            handle = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_RANDOM_ACCESS, nullptr);
            if (handle != INVALID_HANDLE_VALUE) break;
            const auto last_error = GetLastError();
            if ((last_error != ERROR_SHARING_VIOLATION && last_error != ERROR_LOCK_VIOLATION) || lease_retries == 40)
                throw std::runtime_error("ExclusiveLease:" + std::to_string(last_error));
            ++lease_retries; Sleep(25);
        }
        BY_HANDLE_FILE_INFORMATION id{};
        Require(GetFileType(handle) == FILE_TYPE_DISK && GetFileInformationByHandle(handle, &id) &&
            !(id.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DEVICE)), "RegularFileRequired");
        const auto bytes = (std::uint64_t(id.nFileSizeHigh) << 32) | id.nFileSizeLow;
        const auto identity = "windows-file:" + std::to_string(id.dwVolumeSerialNumber) + ":" +
            std::to_string((std::uint64_t(id.nFileIndexHigh) << 32) | id.nFileIndexLow) + ":" + std::to_string(bytes) + ":" +
            std::to_string((std::uint64_t(id.ftLastWriteTime.dwHighDateTime) << 32) | id.ftLastWriteTime.dwLowDateTime);
        if (identity != expected || base > bytes || size > bytes - base) {
            CloseHandle(handle); handle = INVALID_HANDLE_VALUE; throw std::runtime_error("IdentityMismatch");
        }
    }
    ~Target() override { if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle); }
    bool ReadBlock(std::uint64_t block, std::uint32_t bs, std::vector<std::byte>& out) override
    {
        out.clear(); if (bs != 4096 || block >= size / bs) return false;
        LARGE_INTEGER at{}; at.QuadPart = static_cast<LONGLONG>(base + block * bs); DWORD count = 0; out.resize(bs);
        return SetFilePointerEx(handle, at, nullptr, FILE_BEGIN) && ReadFile(handle, out.data(), bs, &count, nullptr) && count == bs;
    }
    bool WriteBlock(std::uint64_t block, std::span<const std::byte> bytes) override
    {
        if (bytes.size() != 4096 || block >= size / 4096) return false;
        LARGE_INTEGER at{}; at.QuadPart = static_cast<LONGLONG>(base + block * 4096); DWORD count = 0;
        if (!SetFilePointerEx(handle, at, nullptr, FILE_BEGIN) || !WriteFile(handle, bytes.data(), 4096, &count, nullptr) || count != 4096) return false;
        ++writes; return true;
    }
    bool Flush() override { ++flushes; return FlushFileBuffers(handle) != FALSE; }
};
std::unique_ptr<c::ApfsEncryptedReadSession> Open(const std::shared_ptr<t::OwnedEncryptedImageSource>& source,
    std::span<const std::byte> password)
{
    c::UnlockError unlock; c::EncryptedReadError error; c::PasswordUnlockBudget attempts;
    auto selector = c::InspectPasswordKeybagMetadata(*source, 1026, c::KeybagLength::IncludesHeader, unlock);
    Require(selector && selector->users.size() == 1, "Selectors");
    auto request = selector->selection; request.user_uuid = selector->users.front();
    auto result = c::ApfsEncryptedReadSession::Unlock(source, source->SourceIdentity(), source->Revision(), request, password, attempts, error, unlock);
    Require(static_cast<bool>(result), "ProtectedUnlock"); return result;
}
void WipeEntries(std::vector<c::EncryptedDirectoryEntry>& entries)
{
    for (auto& entry : entries) {
        SecureZeroMemory(entry.name_utf8.data(), entry.name_utf8.size());
        SecureZeroMemory(entry.windows_name.data(), entry.windows_name.size() * sizeof(wchar_t));
    }
}
int wmain(int argc, wchar_t** argv)
{
    try {
        Require(argc == 5, "Arguments");
        const bool native = std::wstring_view(argv[1]) == L"native";
        const std::wstring path = argv[2], mode = argv[3];
        const bool permission_pair = mode == L"create-0600" || mode == L"create-0644";
        const auto target_id = static_cast<std::uint64_t>(std::wcstoull(argv[4], nullptr, 10));
        const auto base = native ? 0ULL : 20480ULL, size = native ? 134176768ULL : 4153344ULL;
        auto lease = std::make_shared<t::WindowsImageLease>(path);
        auto source = std::make_shared<t::OwnedEncryptedImageSource>(lease, base, size);
        const auto identity = lease->Identity();
        const auto source_identity = source->SourceIdentity();
        const std::atomic<bool> cancelled{false};
        const auto input = GetStdHandle(STD_INPUT_HANDLE); SetStdHandle(STD_INPUT_HANDLE, nullptr);
        auto password = t::ReceiveCredential(input, std::chrono::milliseconds(5000), cancelled);
        Require(static_cast<bool>(password), "ProtectedCredential");
        auto session = Open(source, password.bytes.Bytes());
        c::EncryptedReadError read_error;
        auto context = session->CreateMetadataReadContext(read_error);
        std::string error;
        auto current = c::LoadAppleCheckpointView(*source, 0, size, error, *context);
        Require(static_cast<bool>(current), "CurrentCanonical");
        const auto xid = current->container.superblock.xid;
        struct Fact { c::EncryptedNodeInfo metadata; std::string hash; };
        std::map<std::uint64_t, Fact> before;
        std::vector<c::EncryptedFileInfo> files;
        Require(session->ListFiles(files) == c::EncryptedReadError::None, "BeforeFiles");
        SensitiveBytes expected, payload;
        for (const auto& file : files) {
            c::EncryptedNodeInfo metadata; SensitiveBytes contents;
            Require(session->GetMetadata(file.inode_id, metadata) == c::EncryptedReadError::None &&
                session->ReadFile(file.inode_id, 0, static_cast<std::size_t>(file.size), contents.data) == c::EncryptedReadError::None, "BeforeRead");
            before.emplace(file.inode_id, Fact{metadata, Hash(contents.data)});
            if (file.inode_id == target_id) expected.data = contents.data;
        }
        c::EncryptedMutationRequest request;
        request.inode = target_id;
        std::string source_name;
        if (mode == L"overwrite") {
            request.kind = c::EncryptedMutationKind::Overwrite; request.offset = 3; payload.data.resize(7);
        } else if (mode == L"create" || mode == L"create-empty" || mode == L"create-pin" || permission_pair) {
            request.kind = c::EncryptedMutationKind::Create; request.inode = 0; request.parent = 2; request.name = "e03-created.bin";
            payload.data.resize(mode == L"create-empty" || permission_pair ? 0 : 12325);
            if (permission_pair) request.permissions = mode == L"create-0600" ? 0600 : 0644;
        } else if (mode == L"write" || mode == L"append" || mode == L"write-gap") {
            request.kind = c::EncryptedMutationKind::Write;
            request.offset = mode == L"append" ? expected.data.size() : mode == L"write-gap" ? 20000 : 3000;
            payload.data.resize(5003);
        } else if (mode == L"grow" || mode == L"shrink" || mode == L"zero" || mode == L"max-size") {
            request.kind = c::EncryptedMutationKind::Resize;
            request.size = mode == L"grow" ? 12543 : mode == L"shrink" ? 10 : mode == L"max-size" ? 65536 : 0;
        } else if (mode == L"rename" || mode == L"move" || mode == L"unlink") {
            Require(before.contains(target_id), "TargetFile");
            request.parent = before.at(target_id).metadata.parent_id;
            std::vector<c::EncryptedDirectoryEntry> entries;
            Require(session->ListDirectory(request.parent, entries) == c::EncryptedReadError::None, "SourceDirectory");
            for (const auto& entry : entries) if (entry.inode_id == target_id) source_name = entry.name_utf8;
            WipeEntries(entries); Require(!source_name.empty(), "SourceName");
            request.name = source_name;
            request.kind = mode == L"unlink" ? c::EncryptedMutationKind::Unlink : c::EncryptedMutationKind::Rename;
            if (mode != L"unlink") {
                request.destination_parent = mode == L"move" ? 2 : request.parent;
                request.destination_name = "e03-renamed.bin";
            }
        } else if (mode == L"refusals" || mode == L"changed-pin" || mode == L"oldest-pin") {
            request.kind = c::EncryptedMutationKind::Write; payload.data.resize(7);
        } else throw std::runtime_error("UnknownMode");
        for (std::size_t i = 0; i < payload.data.size(); ++i) payload.data[i] = static_cast<std::byte>((i * 37 + 19) % 251);
        request.data = payload.data;
        const auto refuse = [&](const c::EncryptedMutationRequest& invalid) {
            auto bad = session->PrepareMutation(*source, xid, invalid, error);
            Require(!bad && !error.empty(), "InvalidMutationAdmitted");
        };
        if (mode == L"refusals") {
            std::size_t refused = 0;
            const auto reject = [&](const c::EncryptedMutationRequest& invalid) { refuse(invalid); ++refused; };
            auto invalid = request; invalid.offset = 65536; reject(invalid);
            invalid = request; invalid.offset = UINT64_MAX; reject(invalid);
            invalid = request; invalid.data = {}; reject(invalid);
            invalid = request; invalid.inode = UINT64_MAX; reject(invalid);
            invalid = request; invalid.kind = static_cast<c::EncryptedMutationKind>(999); reject(invalid);
            invalid = request; invalid.kind = c::EncryptedMutationKind::Resize; reject(invalid);
            invalid.data = {}; invalid.size = 65537; reject(invalid);
            invalid = {}; invalid.kind = c::EncryptedMutationKind::Create; invalid.parent = 999; invalid.name = "file"; reject(invalid);
            invalid.parent = 2; invalid.name = "../file"; reject(invalid);
            invalid.name = "."; reject(invalid);
            invalid.name = ".."; reject(invalid);
            invalid.name = std::string_view("a\0b", 3); reject(invalid);
            invalid.name = "file"; invalid.inode = 42; reject(invalid);
            invalid.inode = 0; invalid.permissions = 04755; reject(invalid);
            invalid.permissions = 0644;
            std::vector<c::EncryptedDirectoryEntry> root_entries;
            Require(session->ListDirectory(2, root_entries) == c::EncryptedReadError::None && !root_entries.empty(), "RootEntries");
            invalid.inode = 0; invalid.name = root_entries.front().name_utf8; reject(invalid);
            WipeEntries(root_entries);
            invalid = request; invalid.kind = c::EncryptedMutationKind::Unlink; invalid.data = {}; invalid.parent = 2; invalid.name = "wrong-name"; reject(invalid);
            const auto unavailable_pin = xid + 1;
            Require(!session->PrepareMutation(*source, xid, request, error, std::span(&unavailable_pin, 1)) &&
                error == "EncryptedCowRequiredGenerationUnavailable", "UnavailablePinAdmitted"); ++refused;
            session->Cancel(); reject(request);
            std::cout << "{\"refusals\":" << refused << ",\"published\":false}\n"; return 0;
        }
        if (mode == L"changed-pin" || mode == L"oldest-pin") {
            const auto pin = mode == L"changed-pin" ? xid - 1 : 4;
            auto rejected = session->PrepareMutation(*source, xid, request, error, std::span(&pin, 1));
            Require(!rejected && error == (mode == L"changed-pin" ? "EncryptedCowChangedRecoveryGenerationUnsupported" : "AppleSpacemanCibFutureXid:retained-xid-4"),
                "HistoricalPinRefusal");
            std::cout << "{\"published\":false,\"requiredPinRefused\":true,\"error\":" << std::quoted(error) << "}\n"; return 0;
        }
        auto wrong = std::make_shared<t::OwnedEncryptedImageSource>(lease, base, size);
        Require(!session->PrepareMutation(*wrong, xid, request, error), "WrongSource"); wrong.reset();
        Require(!session->PrepareMutation(*source, xid + 1, request, error), "WrongGeneration");
        if (request.kind == c::EncryptedMutationKind::Create) expected.data = payload.data;
        else if (request.kind == c::EncryptedMutationKind::Write || request.kind == c::EncryptedMutationKind::Overwrite) {
            expected.data.resize((std::max)(expected.data.size(), static_cast<std::size_t>(request.offset + payload.data.size())));
            std::copy(payload.data.begin(), payload.data.end(), expected.data.begin() + request.offset);
        } else if (request.kind == c::EncryptedMutationKind::Resize) expected.data.resize(static_cast<std::size_t>(request.size));
        const auto data_hash = Hash(payload.data);
        const auto previous_xid = xid - 1;
        auto prepared = mode == L"overwrite" ? session->PrepareCowOverwrite(*source, xid, target_id, request.offset, payload.data, error) :
            session->PrepareMutation(*source, xid, request, error, mode == L"create-pin" ? std::span(&previous_xid, 1) : std::span<const std::uint64_t>{});
        if (!prepared) { std::cout << "{\"prepared\":false,\"error\":" << std::quoted(error) << "}\n"; return 2; }
        const auto inode = prepared->RequestedInode();
        const auto expected_inode = request.kind == c::EncryptedMutationKind::Create ? current->volumes.front().superblock.next_object_id : request.inode;
        const auto expected_size = request.kind == c::EncryptedMutationKind::Unlink ? 0 : expected.data.size();
        const auto expected_mode = request.kind == c::EncryptedMutationKind::Create ? static_cast<std::uint16_t>(0100000 | request.permissions) : before.at(request.inode).metadata.mode;
        Require(inode == expected_inode && prepared->ResultSize() == expected_size &&
            prepared->IntentParent() == request.parent && prepared->IntentDestinationParent() == request.destination_parent &&
            prepared->RequestedPermissions() == request.permissions && prepared->EffectiveMode() == expected_mode &&
            prepared->EffectivePermissions() == (expected_mode & 07777) &&
            prepared->RequestedOffset() == request.offset && prepared->ReplacementLength() == payload.data.size() &&
            Hex(prepared->ReplacementSha256()) == data_hash && prepared->IntentKind() == request.kind &&
            prepared->SourceCheckpointXid() == xid && prepared->PublishedCheckpointXid() == current->container.superblock.next_xid &&
            prepared->VolumeObjectId() == 1026 && prepared->VolumeUuid() == current->volumes.front().superblock.uuid_hex &&
            prepared->SourceContainer().uuid_hex == prepared->PublishedContainer().uuid_hex && prepared->SourceIdentity() == source_identity &&
            Hex(prepared->IntentNameSha256()) == Hash(std::as_bytes(std::span(request.name))) &&
            Hex(prepared->IntentDestinationNameSha256()) == Hash(std::as_bytes(std::span(request.destination_name))), "IntentBinding");
        const auto expected_pins = mode == L"create-pin" ? std::vector<std::uint64_t>{previous_xid, xid} : std::vector<std::uint64_t>{xid};
        Require(prepared->RequiredCheckpointXids() == expected_pins &&
            prepared->RequiredGenerationsProved() == prepared->RequiredCheckpointXids().size(), "ProvedCheckpointSet");
        if (permission_pair) {
            auto alternate_request = request;
            alternate_request.permissions = request.permissions == 0600 ? 0644 : 0600;
            auto alternate = session->PrepareMutation(*source, xid, alternate_request, error);
            Require(alternate && SameNonPermissionIntent(*prepared, *alternate), "PermissionPairSourceAndIntentMismatch");
            Require(alternate->RequestedPermissions() == alternate_request.permissions &&
                alternate->EffectiveMode() == static_cast<std::uint16_t>(0100000 | alternate_request.permissions) &&
                alternate->EffectivePermissions() == alternate_request.permissions &&
                alternate->RequestedPermissions() != prepared->RequestedPermissions() &&
                alternate->EffectiveMode() != prepared->EffectiveMode(), "PermissionIntentAmbiguous");
        }
        session->Close();
        Require(!session->PrepareMutation(*source, xid, request, error), "ClosedPreparation");
        context.reset(); session.reset(); source.reset(); lease.reset();
        std::size_t writes = 0, flushes = 0, lease_retries = 0;
        { Target target(path, base, size, identity);
          Require(r::ExecuteAppleCheckpointPublication(target, prepared->Publication(), error), "CanonicalPublication");
          writes = target.writes; flushes = target.flushes; lease_retries = target.lease_retries; }
        auto fresh_lease = std::make_shared<t::WindowsImageLease>(path);
        auto fresh_source = std::make_shared<t::OwnedEncryptedImageSource>(fresh_lease, base, size);
        auto fresh = Open(fresh_source, password.bytes.Bytes()); password.bytes.Clear();
        std::vector<c::EncryptedFileInfo> after_files;
        Require(fresh->ListFiles(after_files) == c::EncryptedReadError::None, "FreshFiles");
        const bool create = request.kind == c::EncryptedMutationKind::Create, unlink = request.kind == c::EncryptedMutationKind::Unlink;
        Require(after_files.size() == before.size() + (create ? 1 : 0) - (unlink ? 1 : 0), "FileCount");
        std::cout << "{\"prepared\":true,\"published\":true,\"freshNative\":true,\"intentVerified\":true,\"inode\":" << inode
            << ",\"oldXid\":" << xid << ",\"newXid\":" << prepared->PublishedCheckpointXid() << ",\"resultSize\":" << prepared->ResultSize()
            << ",\"requiredGenerationsProved\":" << prepared->RequiredGenerationsProved() << ",\"metadataSurvivorsWalked\":" << prepared->MetadataSurvivorsWalked()
            << ",\"requestedPermissions\":" << prepared->RequestedPermissions() << ",\"effectiveMode\":" << prepared->EffectiveMode()
            << ",\"permissionPairVerified\":" << (permission_pair ? "true" : "false")
            << ",\"writes\":" << writes << ",\"flushes\":" << flushes << ",\"leaseRetries\":" << lease_retries
            << ",\"sourceParent\":" << request.parent << ",\"destinationParent\":" << request.destination_parent << ",\"files\":[";
        bool first = true;
        for (const auto& file : after_files) {
            c::EncryptedNodeInfo metadata; SensitiveBytes contents;
            Require(fresh->GetMetadata(file.inode_id, metadata) == c::EncryptedReadError::None &&
                fresh->ReadFile(file.inode_id, 0, static_cast<std::size_t>(file.size), contents.data) == c::EncryptedReadError::None, "FreshRead");
            const auto hash = Hash(contents.data);
            Require(hash == (file.inode_id == inode ? Hash(expected.data) : before.at(file.inode_id).hash), "FreshBytes");
            if (file.inode_id == inode) Require(metadata.mode == expected_mode && metadata.mode == prepared->EffectiveMode(), "FreshEffectiveMode");
            if (before.contains(file.inode_id)) {
                const auto& old = before.at(file.inode_id).metadata;
                Require(metadata.mode == old.mode && metadata.uid == old.uid && metadata.gid == old.gid &&
                    metadata.private_id == old.private_id && metadata.internal_flags == old.internal_flags && metadata.bsd_flags == old.bsd_flags &&
                    metadata.protection_class == old.protection_class && metadata.create_time == old.create_time &&
                    metadata.modification_time == old.modification_time && metadata.change_time == old.change_time && metadata.access_time == old.access_time,
                    "PreservedMetadata");
            }
            if (!first) std::cout << ','; first = false;
            std::cout << "{\"inode\":" << file.inode_id << ",\"size\":" << file.size << ",\"sha256\":" << std::quoted(hash) << '}';
        }
        if (unlink) {
            c::EncryptedNodeInfo missing;
            Require(fresh->GetMetadata(inode, missing) == c::EncryptedReadError::FileNotFound, "UnlinkInodePresent");
        }
        if (create || request.kind == c::EncryptedMutationKind::Rename) {
            c::EncryptedDirectoryEntry entry;
            const auto parent = create ? request.parent : request.destination_parent;
            const auto name = create ? request.name : request.destination_name;
            Require(fresh->Lookup(parent, name, entry) == c::EncryptedReadError::None && entry.inode_id == inode, "FreshName");
            SecureZeroMemory(entry.name_utf8.data(), entry.name_utf8.size());
            SecureZeroMemory(entry.windows_name.data(), entry.windows_name.size() * sizeof(wchar_t));
        }
        if (unlink || request.kind == c::EncryptedMutationKind::Rename) {
            c::EncryptedDirectoryEntry absent;
            Require(fresh->Lookup(request.parent, request.name, absent) == c::EncryptedReadError::FileNotFound, "OldNamePresent");
        }
        auto fresh_context = fresh->CreateMetadataReadContext(read_error);
        auto reopened = c::LoadAppleCheckpointView(*fresh_source, 0, size, error, *fresh_context);
        Require(reopened && reopened->container.superblock.xid == prepared->PublishedCheckpointXid() &&
            reopened->volumes.front().superblock.file_count == current->volumes.front().superblock.file_count + (create ? 1 : 0) - (unlink ? 1 : 0), "FreshCanonical");
        const auto data_blocks = request.kind == c::EncryptedMutationKind::Rename || unlink ? 0 : (prepared->ResultSize() + 4095) / 4096;
        Require(reopened->volumes.front().superblock.space.allocated_block_count ==
            current->volumes.front().superblock.space.allocated_block_count + 5 + data_blocks, "VolumeAllocationCharge");
        std::cout << "],\"plannedBlocks\":["; first = true;
        for (const auto& write : prepared->Publication().before_superblock_writes) {
            if (!first) std::cout << ','; first = false;
            std::cout << "{\"block\":" << write.physical_block << ",\"sha256\":" << std::quoted(Hash(write.bytes)) << '}';
        }
        const auto& final = prepared->Publication().superblock_write;
        std::cout << ",{\"block\":" << final.physical_block << ",\"sha256\":" << std::quoted(Hash(final.bytes)) << "}]}\n";
        SecureZeroMemory(source_name.data(), source_name.size()); return 0;
    } catch (const std::exception& exception) { std::cerr << "FAIL " << exception.what() << '\n'; return 1; }
}
