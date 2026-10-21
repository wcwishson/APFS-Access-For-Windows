#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#undef CreateFile
#undef CreateDirectory
#include "EncryptedPublicationJournal.h"
#include "ApfsEncryptedReadSession.h"
#include "EncryptedReadTransport.h"
#include "PayloadSpool.h"
#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <stdexcept>
#undef CreateFile
#undef CreateDirectory

namespace
{
namespace c = apfsaccess::catalog;
namespace r = apfsaccess::rw;
namespace t = apfsaccess::transport;
namespace fs = std::filesystem;
using Tx = r::TransactionManager;
using Wal = r::WriteAheadLog;
using Journal = r::EncryptedPublicationJournal;
using Spool = r::PayloadSpool;
constexpr std::uint64_t base = 20480, container_size = 4153344, inode = 21, patch_offset = 3;
constexpr std::string_view patch = "E04-WAL";
constexpr std::wstring_view volume = L"encrypted-publication-dfvfs-original";
constexpr std::wstring_view private_prefix = L"D:\\ApfsAccessScratch\\WindowsClosure\\encrypted-publication-journal-tests-20261016\\";
std::size_t checks = 0;
bool retry_sharing = false;
struct OwnerCounts { long lease = 0, source = 0; unsigned session = 0, context = 0; };
struct AcquisitionAttempt { DWORD error = 0; OwnerCounts owners; };
struct Acquisition { bool preimage = false; std::vector<AcquisitionAttempt> attempts; };
std::vector<Acquisition> acquisitions;
void EmitAcquisitions(std::ostream& out)
{
    out << '['; bool first = true;
    for (const auto& acquisition : acquisitions) {
        if (!first) out << ','; first = false;
        out << "{\"preimage\":" << (acquisition.preimage ? "true" : "false") << ",\"attempts\":[";
        bool first_attempt = true;
        for (const auto& attempt : acquisition.attempts) {
            if (!first_attempt) out << ','; first_attempt = false;
            out << "{\"win32\":" << attempt.error << ",\"leaseOwners\":" << attempt.owners.lease
                << ",\"sourceOwners\":" << attempt.owners.source << ",\"sessionOwners\":" << attempt.owners.session
                << ",\"contextOwners\":" << attempt.owners.context << '}';
        }
        out << "]}";
    }
    out << ']';
}
void Check(bool value, const char* why)
{ ++checks; if (!value) throw std::runtime_error(why); }
std::array<std::uint8_t, 32> Hash(std::span<const std::byte> bytes)
{
    std::array<std::uint8_t, 32> digest{};
    Check(bytes.size() <= ULONG_MAX && BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0,
        reinterpret_cast<PUCHAR>(const_cast<std::byte*>(bytes.data())), static_cast<ULONG>(bytes.size()),
        digest.data(), static_cast<ULONG>(digest.size())) >= 0, "Sha256");
    return digest;
}
std::array<std::byte, 32> Binding(std::string_view text)
{
    const auto hash = Hash(std::as_bytes(std::span(text)));
    std::array<std::byte, 32> out{};
    std::transform(hash.begin(), hash.end(), out.begin(), [](auto b) { return static_cast<std::byte>(b); });
    return out;
}
std::string Hex(std::span<const std::uint8_t> bytes)
{
    std::string out;
    for (auto b : bytes) { out += "0123456789abcdef"[b >> 4]; out += "0123456789abcdef"[b & 15]; }
    return out;
}
std::vector<std::byte> Read(const fs::path& path)
{
    Check(fs::file_size(path) <= (64ull << 20), "BoundedEvidence");
    std::vector<std::byte> bytes(static_cast<std::size_t>(fs::file_size(path)));
    std::ifstream input(path, std::ios::binary);
    input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    Check(input && static_cast<std::size_t>(input.gcount()) == bytes.size(), "ReadEvidence");
    return bytes;
}
std::string Identity(const BY_HANDLE_FILE_INFORMATION& id)
{
    return "windows-file:" + std::to_string(id.dwVolumeSerialNumber) + ":" +
        std::to_string((std::uint64_t(id.nFileIndexHigh) << 32) | id.nFileIndexLow) + ":" +
        std::to_string((std::uint64_t(id.nFileSizeHigh) << 32) | id.nFileSizeLow) + ":" +
        std::to_string((std::uint64_t(id.ftLastWriteTime.dwHighDateTime) << 32) | id.ftLastWriteTime.dwLowDateTime);
}
std::string StableIdentity(std::string identity)
{ identity.resize(identity.rfind(':')); return identity; }
class Target final : public r::EncryptedPublicationTarget
{
    HANDLE file_ = INVALID_HANDLE_VALUE;
    std::array<std::byte, 32> binding_{};
public:
    std::size_t writes = 0, attempts = 0, flushes = 0;
    std::size_t fail_after = SIZE_MAX;
    std::optional<std::uint64_t> tear_block, corrupt_on_flush;
    std::size_t corrupt_flush_number = 1, torn_bytes = 0;
    std::vector<std::uint64_t> injected_blocks;
    std::function<void()> before_write;
    std::function<void(std::size_t)> after_flush;
    bool cut_hit = false;
    Target(const fs::path& path, const std::string& expected, bool first,
        std::array<std::byte, 32> binding, const std::function<OwnerCounts()>& observe) : binding_(binding)
    {
        const auto normalized = fs::absolute(path).lexically_normal().wstring();
        Check(normalized.starts_with(private_prefix), "PrivateOrdinaryImageOnly");
        acquisitions.push_back({first, {}});
        auto& acquisition = acquisitions.back();
        constexpr DWORD delays[] = {25, 50, 100, 200};
        for (std::size_t attempt = 0;; ++attempt) {
            const auto owners = observe();
            file_ = CreateFileW(normalized.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_RANDOM_ACCESS, nullptr);
            const auto error = file_ == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
            acquisition.attempts.push_back({error, owners});
            const bool own_handle = owners.lease || owners.source || owners.session || owners.context;
            if (file_ != INVALID_HANDLE_VALUE) {
                if (own_handle) { CloseHandle(file_); file_ = INVALID_HANDLE_VALUE; }
                Check(!own_handle, "RetainedOwnImageOwnerAtExclusiveAcquisition"); break;
            }
            if (!retry_sharing || own_handle || (error != ERROR_SHARING_VIOLATION && error != ERROR_LOCK_VIOLATION) ||
                attempt >= std::size(delays))
                throw std::runtime_error("ExclusiveSameFileLease:win32=" + std::to_string(error));
            Sleep(delays[attempt]);
        }
        BY_HANDLE_FILE_INFORMATION id{};
        const bool ordinary = GetFileType(file_) == FILE_TYPE_DISK && GetFileInformationByHandle(file_, &id) &&
            !(id.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DEVICE));
        if (!ordinary || StableIdentity(Identity(id)) != StableIdentity(expected) ||
            (first && Identity(id) != expected) ||
            ((std::uint64_t(id.nFileSizeHigh) << 32) | id.nFileSizeLow) < base + container_size) {
            CloseHandle(file_); file_ = INVALID_HANDLE_VALUE;
            Check(false, "ExclusiveFileIdentityAndGeometry");
        }
    }
    ~Target() override { if (file_ != INVALID_HANDLE_VALUE) CloseHandle(file_); }
    std::array<std::byte, 32> SourceBinding() const noexcept override { return binding_; }
    bool ReadBlock(std::uint64_t block, std::uint32_t size, std::vector<std::byte>& out) override
    {
        out.clear(); if (size != 4096 || block >= container_size / size) return false;
        LARGE_INTEGER at{}; at.QuadPart = static_cast<LONGLONG>(base + block * size);
        out.resize(size); DWORD got = 0;
        return SetFilePointerEx(file_, at, nullptr, FILE_BEGIN) &&
            ReadFile(file_, out.data(), size, &got, nullptr) && got == size;
    }
    bool WriteBlock(std::uint64_t block, std::span<const std::byte> bytes) override
    {
        ++attempts;
        if (before_write) before_write();
        if (writes == fail_after) { cut_hit = true; return false; }
        if (bytes.size() != 4096 || block >= container_size / 4096) return false;
        LARGE_INTEGER at{}; at.QuadPart = static_cast<LONGLONG>(base + block * 4096); DWORD put = 0;
        if (tear_block == block) {
            std::vector<std::byte> torn(bytes.begin(), bytes.begin() + 128);
            torn.front() ^= std::byte{1};
            if (!SetFilePointerEx(file_, at, nullptr, FILE_BEGIN) ||
                !WriteFile(file_, torn.data(), 128, &put, nullptr) || put != 128) return false;
            torn_bytes = put; cut_hit = true; return false;
        }
        if (!SetFilePointerEx(file_, at, nullptr, FILE_BEGIN) ||
            !WriteFile(file_, bytes.data(), 4096, &put, nullptr) || put != 4096) return false;
        ++writes; return true;
    }
    void InjectCorruption(std::uint64_t block)
    {
        std::vector<std::byte> bytes;
        Check(ReadBlock(block, 4096, bytes), "PrivateCorruptionRead");
        bytes.front() ^= std::byte{1};
        LARGE_INTEGER at{}; at.QuadPart = static_cast<LONGLONG>(base + block * 4096); DWORD put = 0;
        Check(SetFilePointerEx(file_, at, nullptr, FILE_BEGIN) &&
            WriteFile(file_, bytes.data(), 4096, &put, nullptr) && put == 4096 &&
            FlushFileBuffers(file_), "PrivateCorruptionPersisted");
        injected_blocks.push_back(block);
    }
    bool Flush() override
    {
        ++flushes;
        if (!FlushFileBuffers(file_)) return false;
        if (corrupt_on_flush && flushes == corrupt_flush_number) InjectCorruption(*corrupt_on_flush);
        if (after_flush) after_flush(flushes);
        return true;
    }
};
Wal::ProtectedPersistence Protection(const fs::path& directory,
    std::array<std::byte, 32> binding, std::string_view stream)
{
    return {directory / (std::string(stream) + "-keys"), binding, Binding(stream),
        {64ull << 20, 65536}, 256ull << 20};
}
std::unique_ptr<Tx> OpenTx(const fs::path& path, const Wal::ProtectedPersistence& protection)
{
    auto tx = std::make_unique<Tx>(L"Conservative"); std::string error;
    Check(tx->OpenProtectedJournal(path.wstring(), std::wstring(volume), protection, error), "OriginalProtectedTxOpen");
    Check(tx->RecoveryStateValid(), "OriginalRecoveryValid");
    return tx;
}
std::uint64_t Accept(Tx& tx, std::uint64_t xid, bool wrong = false, bool deferred = false,
    std::span<const std::byte> replacement = {}, std::uint64_t requested_offset = patch_offset)
{
    Tx::MutationIntent intent;
    intent.kind = Tx::MutationKind::Write; intent.path = L"\\journal-image-test";
    intent.object_id = inode; intent.offset = requested_offset;
    const auto bytes = replacement.empty() ? std::as_bytes(std::span(patch)) : replacement;
    intent.inline_payload.assign(bytes.begin(), bytes.end());
    if (wrong) intent.inline_payload.front() ^= std::byte{1};
    intent.length = intent.payload_length = intent.inline_payload.size();
    intent.payload_checksum = Hash(intent.inline_payload);
    const auto previous_durable = tx.Watermarks().apfs_durable_sequence;
    Check(tx.Begin() && tx.RecordMutation(intent), "OneProtectedOverwriteIntent");
    std::uint64_t deferred_sequence = 0;
    SetLastError(ERROR_SUCCESS);
    const bool accepted = deferred ? tx.AcceptForDeferredCommit(&deferred_sequence, xid) : tx.Accept(xid);
    const auto acceptance_error = GetLastError();
    if (!accepted) std::cerr << "ProtectedAcceptanceFailure payloadBytes=" << bytes.size()
        << " win32=" << acceptance_error << " state=" << static_cast<unsigned>(tx.CurrentState()) << '\n';
    Check(accepted, "OneProtectedAcceptedOverwrite");
    if (deferred) Check(deferred_sequence == tx.Watermarks().accepted_sequence &&
        tx.DeferredWalGroupFlushCount() == 0, "ActualDeferredAcceptanceHasNoGroupFlush");
    SecureZeroMemory(intent.inline_payload.data(), intent.inline_payload.size());
    Check(tx.Watermarks().accepted_sequence > previous_durable && tx.Watermarks().apfs_durable_sequence == previous_durable &&
        tx.HasUnappliedAcceptedWork(), "AcceptedNotYetApfsDurable");
    return tx.Watermarks().accepted_sequence;
}
std::unique_ptr<c::ApfsEncryptedReadSession> Unlock(
    const std::shared_ptr<t::OwnedEncryptedImageSource>& source, std::span<const std::byte> password)
{
    c::UnlockError unlock; c::EncryptedReadError error; c::PasswordUnlockBudget budget;
    auto selectors = c::InspectPasswordKeybagMetadata(*source, 1026, c::KeybagLength::IncludesHeader, unlock);
    Check(selectors && selectors->users.size() == 1, "AuthenticFixtureSelector");
    auto selection = selectors->selection; selection.user_uuid = selectors->users.front();
    auto session = c::ApfsEncryptedReadSession::Unlock(source, source->SourceIdentity(), source->Revision(),
        selection, password, budget, error, unlock);
    Check(static_cast<bool>(session), "ProtectedAuthenticUnlock"); return session;
}
struct Fact { c::EncryptedNodeInfo metadata; std::array<std::uint8_t, 32> hash{}; };
bool SameMetadata(const c::EncryptedNodeInfo& a, const c::EncryptedNodeInfo& b)
{
    return a.inode_id == b.inode_id && a.private_id == b.private_id && a.size == b.size &&
        a.allocated_size == b.allocated_size && a.default_crypto_id == b.default_crypto_id &&
        a.mode == b.mode && a.uid == b.uid && a.gid == b.gid && a.internal_flags == b.internal_flags &&
        a.bsd_flags == b.bsd_flags && a.protection_class == b.protection_class &&
        a.write_generation == b.write_generation && a.create_time == b.create_time &&
        a.modification_time == b.modification_time && a.change_time == b.change_time && a.access_time == b.access_time;
}
// Decode the persisted witness independently, comparing every scalar and byte.
class WitnessReader
{
    std::span<const std::byte> rest_;
public:
    explicit WitnessReader(std::span<const std::byte> bytes) : rest_(bytes) {}
    std::uint64_t Number()
    {
        Check(rest_.size() >= 8, "WitnessInteger"); std::uint64_t n = 0;
        for (unsigned i = 0; i < 8; ++i) n |= std::to_integer<std::uint64_t>(rest_[i]) << (i * 8);
        rest_ = rest_.subspan(8); return n;
    }
    void Data(std::span<const std::byte> expected)
    {
        Check(Number() == expected.size() && rest_.size() >= expected.size(), "WitnessByteLength");
        Check(std::equal(expected.begin(), expected.end(), rest_.begin()), "ExactWitnessBytes");
        rest_ = rest_.subspan(expected.size());
    }
    void Text(std::string_view expected) { Data(std::as_bytes(std::span(expected))); }
    void Write(const r::AppleCheckpointPlannedWrite& write)
    {
        Check(Number() == static_cast<std::uint64_t>(write.kind) && Number() == write.physical_block &&
            Number() == write.object_id, "WitnessWriteAddressAndKind"); Data(write.bytes);
    }
    bool Empty() const { return rest_.empty(); }
};
void VerifyWitness(const Journal::Options& options, const r::AppleCheckpointPublicationPlan& plan,
    std::uint64_t sequence, std::uint64_t transaction, const std::array<std::uint8_t, 32>& replacement,
    std::uint64_t requested_offset = patch_offset, std::uint64_t replacement_length = patch.size(),
    const c::EncryptedCowOverwrite* prepared = nullptr)
{
    Wal reader(options.witness); auto records = reader.ReadAllWithExclusiveWriterLease();
    Check(records.status == Wal::ReadStatus::Ok && records.records.size() > 2, "AuthenticatedChunkedWitness");
    for (std::size_t index = 0; index < records.records.size(); ++index)
        Check(records.records[index].sequence == index + 1, "WitnessWholeStreamContiguousSequence");
    const auto first = std::find_if(records.records.begin(), records.records.end(),
        [&](const auto& row) { return row.parent_object_id == sequence; });
    Check(first != records.records.end(), "WitnessSelectedOriginalBoundaryPresent");
    const auto last = std::find_if(first, records.records.end(),
        [&](const auto& row) { return row.parent_object_id != sequence; });
    Check(std::none_of(last, records.records.end(), [&](const auto& row) { return row.parent_object_id == sequence; }),
        "WitnessSelectedGroupIsContiguous");
    const auto first_index = static_cast<std::size_t>(first - records.records.begin());
    const auto rows = std::span<const Wal::Record>(&*first, static_cast<std::size_t>(last - first));
    Check(rows.size() > 2, "WitnessSelectedChunkedGroup");
    std::vector<std::byte> body;
    const auto count = rows.size() - 1;
    for (std::size_t index = 0; index < rows.size(); ++index) {
        const auto& row = rows[index];
        Check(row.sequence == first_index + index + 1 && row.parent_object_id == sequence && row.transaction_id == transaction &&
            row.object_id == (prepared ? prepared->IntentInode() : inode) && row.operation == Wal::OperationKind::Write && row.state == Wal::RecordState::Prepared &&
            Wal::InlinePayloadIsConsistent(row), "ChunkOriginalBoundaryAndIndependentSequence");
        if (index < count) {
            Check(row.path_utf8 == "\\encrypted-publication-chunk-v2" && row.logical_offset == body.size() &&
                !row.inline_payload.empty() && row.inline_payload.size() <= 4096 &&
                (index + 1 == count || row.inline_payload.size() == 4096), "ChunkOffsetsAndBoundedLockedRecord");
            body.insert(body.end(), row.inline_payload.begin(), row.inline_payload.end());
        } else {
            Check(row.path_utf8 == "\\encrypted-publication-end-v2" && row.logical_offset == 0, "WitnessTerminalEnvelope");
            WitnessReader terminal(row.inline_payload);
            Check(terminal.Number() == 2 && terminal.Number() == sequence && terminal.Number() == transaction &&
                terminal.Number() == (prepared ? prepared->IntentInode() : inode) && terminal.Number() == count && terminal.Number() == body.size(), "WitnessTerminalCountAndIdentity");
            const auto digest = Hash(body);
            terminal.Data(std::as_bytes(std::span(digest))); Check(terminal.Empty(), "WitnessTerminalDigestAndNoTrailingData");
        }
    }
    WitnessReader d(body);
    Check(d.Number() == (prepared ? 2 : 1) && d.Number() == sequence && d.Number() == transaction &&
        d.Number() == (prepared ? prepared->IntentInode() : inode) &&
        d.Number() == requested_offset && d.Number() == replacement_length, "WitnessOriginalIntent");
    d.Data(std::as_bytes(std::span(replacement))); d.Text(options.preimage_source_identity);
    if (prepared) {
        Check(d.Number() == static_cast<std::uint64_t>(prepared->IntentKind()) + 1 &&
            d.Number() == prepared->IntentParent() && d.Number() == prepared->IntentDestinationParent() &&
            d.Number() == prepared->ResultSize() && d.Number() == prepared->RequestedPermissions() &&
            d.Number() == prepared->EffectiveMode() && d.Number() == options.volume_object_id,
            "WitnessExactTypedIntentAndSelectedVolume");
        d.Text(options.volume_uuid); d.Data(std::as_bytes(std::span(prepared->IntentNameSha256())));
        d.Data(std::as_bytes(std::span(prepared->IntentDestinationNameSha256())));
    }
    Check(d.Number() == container_size, "WitnessGeometry"); d.Text(options.container_uuid);
    Check(d.Number() == plan.block_size && d.Number() == plan.expected_checkpoint_xid &&
        d.Number() == plan.transaction_xid && d.Number() == plan.next_object_id &&
        d.Number() == plan.guard_blocks.size(), "WitnessCheckpointAndGuards");
    for (const auto& guard : plan.guard_blocks) { Check(d.Number() == guard.physical_block, "WitnessGuardAddress"); d.Data(guard.bytes); }
    Check(d.Number() == plan.before_superblock_writes.size(), "WitnessWriteCount");
    for (const auto& write : plan.before_superblock_writes) d.Write(write);
    d.Write(plan.superblock_write); Check(d.Empty(), "WitnessNoTrailingData");
    for (auto& row : records.records) SecureZeroMemory(row.inline_payload.data(), row.inline_payload.size());
    SecureZeroMemory(body.data(), body.size());
}
void Tamper(const fs::path& path)
{
    auto bytes = Read(path); Check(bytes.size() > 80, "ProtectedWitnessPresent");
    bytes[bytes.size() / 2] ^= std::byte{1};
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    out.flush(); Check(static_cast<bool>(out), "TamperPrivateWitness");
}
void VerifyPlan(Target& target, const r::AppleCheckpointPublicationPlan& plan)
{
    auto exact = [&](const auto& row) {
        std::vector<std::byte> actual;
        Check(target.ReadBlock(row.physical_block, 4096, actual) && actual == row.bytes, "ExactPublishedCiphertext");
    };
    for (const auto& row : plan.before_superblock_writes) exact(row);
    exact(plan.superblock_write);
}
std::uint64_t UnchangedGuard(const r::AppleCheckpointPublicationPlan& plan, std::uint64_t old_data_block)
{
    std::set<std::uint64_t> destinations{plan.superblock_write.physical_block};
    for (const auto& write : plan.before_superblock_writes) destinations.insert(write.physical_block);
    for (const auto& guard : plan.guard_blocks) {
        if (guard.physical_block == old_data_block && !destinations.contains(guard.physical_block)) return guard.physical_block;
    }
    throw std::runtime_error("FixtureNeedsGuardedSupersededCiphertextBlock");
}
struct WitnessEncoding
{
    std::vector<std::byte> bytes;
    void Number(std::uint64_t n) { for (unsigned i = 0; i < 8; ++i) bytes.push_back(static_cast<std::byte>((n >> (i * 8)) & 255)); }
    void Data(std::span<const std::byte> data) { Number(data.size()); bytes.insert(bytes.end(), data.begin(), data.end()); }
    void Text(std::string_view text) { Data(std::as_bytes(std::span(text))); }
    void Write(const r::AppleCheckpointPlannedWrite& write)
    { Number(static_cast<std::uint64_t>(write.kind)); Number(write.physical_block); Number(write.object_id); Data(write.bytes); }
};
struct WitnessCapacity { std::uint64_t bytes = 104, admission_bytes = 0, allocation = 0; std::size_t records = 0; };
WitnessCapacity ExpectedCapacity(const Journal::Options& options, const r::AppleCheckpointPublicationPlan& plan,
    std::uint64_t accepted, std::uint64_t transaction, const c::EncryptedCowOverwrite& prepared)
{
    WitnessEncoding body;
    for (const auto n : {2ULL, accepted, transaction, prepared.IntentInode(), prepared.IntentOffset(), prepared.IntentLength()}) body.Number(n);
    body.Data(std::as_bytes(std::span(prepared.IntentSha256()))); body.Text(options.preimage_source_identity);
    body.Number(static_cast<std::uint64_t>(prepared.IntentKind()) + 1);
    for (const auto n : {prepared.IntentParent(), prepared.IntentDestinationParent(), prepared.ResultSize(),
            static_cast<std::uint64_t>(prepared.RequestedPermissions()), static_cast<std::uint64_t>(prepared.EffectiveMode()),
            options.volume_object_id}) body.Number(n);
    body.Text(options.volume_uuid); body.Data(std::as_bytes(std::span(prepared.IntentNameSha256())));
    body.Data(std::as_bytes(std::span(prepared.IntentDestinationNameSha256())));
    body.Number(container_size); body.Text(options.container_uuid);
    body.Number(plan.block_size); body.Number(plan.expected_checkpoint_xid); body.Number(plan.transaction_xid);
    body.Number(plan.next_object_id); body.Number(plan.guard_blocks.size());
    for (const auto& guard : plan.guard_blocks) { body.Number(guard.physical_block); body.Data(guard.bytes); }
    body.Number(plan.before_superblock_writes.size());
    for (const auto& write : plan.before_superblock_writes) body.Write(write);
    body.Write(plan.superblock_write);
    WitnessCapacity capacity;
    Wal::Record row;
    row.volume_identity = options.witness.volume_identity; row.sequence = 1; row.transaction_id = transaction;
    row.object_id = inode; row.parent_object_id = accepted;
    row.operation = Wal::OperationKind::Write; row.state = Wal::RecordState::Prepared;
    auto count = [&] {
        row.payload_length = row.logical_length = row.inline_payload.size(); row.payload_sha256 = Hash(row.inline_payload);
        const auto encoded = Wal::EncodeForTest(row); Check(!encoded.empty(), "CapacityUsesActualWalEncoding");
        capacity.bytes += encoded.size() + 80; ++capacity.records; ++row.sequence;
    };
    for (std::size_t offset = 0; offset < body.bytes.size(); offset += 4096) {
        const auto take = (std::min)(body.bytes.size() - offset, std::size_t{4096});
        row.path_utf8 = "\\encrypted-publication-chunk-v2"; row.logical_offset = offset;
        row.inline_payload.assign(body.bytes.begin() + offset, body.bytes.begin() + offset + take); count();
    }
    WitnessEncoding terminal;
    for (const auto n : {2ULL, accepted, transaction, inode, static_cast<std::uint64_t>(capacity.records),
            static_cast<std::uint64_t>(body.bytes.size())}) terminal.Number(n);
    const auto digest = Hash(body.bytes); terminal.Data(std::as_bytes(std::span(digest)));
    row.path_utf8 = "\\encrypted-publication-end-v2"; row.logical_offset = 0; row.inline_payload = std::move(terminal.bytes); count();
    capacity.admission_bytes = capacity.bytes + 4096 - 104;
    capacity.allocation = capacity.admission_bytes * 4 + capacity.records * (2 * sizeof(Wal::Record) + 4);
    return capacity;
}
std::uint64_t ObserveCheckpoint(Target& target)
{
    struct Source final : c::RandomAccessSource
    {
        Target& target;
        explicit Source(Target& value) : target(value) {}
        std::uint64_t SizeBytes() const override { return container_size; }
        bool Read(std::uint64_t offset, std::size_t count, std::vector<std::byte>& out) const override
        {
            out.clear();
            if (offset > container_size || count > container_size - offset) return false;
            while (out.size() < count) {
                std::vector<std::byte> block;
                const auto position = offset + out.size();
                if (!target.ReadBlock(position / 4096, 4096, block)) return false;
                const auto start = static_cast<std::size_t>(position % 4096);
                const auto take = (std::min)(count - out.size(), 4096 - start);
                out.insert(out.end(), block.begin() + start, block.begin() + start + take);
            }
            return true;
        }
    } source(target);
    std::string error;
    auto view = c::LoadContainerCheckpointView(source, 0, container_size, error);
    Check(static_cast<bool>(view), ("ActualTargetCheckpoint:" + error).c_str());
    return view->superblock.xid;
}
std::string DiagnoseWholeBlockAdapter(Target& target)
{
    struct Source final : c::RandomAccessSource
    {
        Target& target;
        mutable std::uint64_t rejected_offset = 0;
        mutable std::size_t rejected_length = 0, rejected_count = 0;
        explicit Source(Target& value) : target(value) {}
        std::uint64_t SizeBytes() const override { return container_size; }
        bool Read(std::uint64_t offset, std::size_t count, std::vector<std::byte>& out) const override
        {
            out.clear();
            if (!count || offset % 4096 || count % 4096 || offset > container_size || count > container_size - offset) {
                if (!rejected_count) { rejected_offset = offset; rejected_length = count; }
                ++rejected_count; return false;
            }
            for (std::size_t i = 0; i < count; i += 4096) {
                std::vector<std::byte> block;
                if (!target.ReadBlockRangeForVerification((offset + i) / 4096, 4096, 1, block) || block.size() != 4096) return false;
                out.insert(out.end(), block.begin(), block.end());
            }
            return true;
        }
    } source(target);
    std::string error;
    const auto checkpoint = c::LoadContainerCheckpointView(source, 0, container_size, error);
    return ":wholeBlockProbe=" + std::string(checkpoint ? "selected" : error) +
        ":firstRejectedOffset=" + std::to_string(source.rejected_offset) +
        ":firstRejectedLength=" + std::to_string(source.rejected_length) +
        ":rejectedRequests=" + std::to_string(source.rejected_count);
}
void WitnessFault(Journal& journal, Wal::FaultInjectionHook hook)
{
    journal.SetWitnessFaultInjectionHook(std::move(hook));
}
struct BootstrapResult
{
    std::array<std::byte, 32> binding{};
    std::vector<r::AppleCheckpointPlannedWrite> writes;
};
void BindSelectedVolume(Journal::Options& options, const c::AppleCheckpointView& checkpoint)
{
    Check(checkpoint.volumes.size() == 1, "SingleCanonicalSelectedVolume");
    const auto& selected = checkpoint.volumes.front().superblock;
    Check(selected.object_id != 0 && selected.uuid_hex.size() == 32, "CanonicalSelectedVolumeIdentity");
    options.volume_object_id = selected.object_id; options.volume_uuid = selected.uuid_hex;
}
BootstrapResult PublishUncleanedPredecessor(const fs::path& image, const fs::path& directory,
    std::span<const std::byte> password)
{
    auto lease = std::make_shared<t::WindowsImageLease>(image.wstring());
    const auto identity = lease->Identity();
    auto source = std::make_shared<t::OwnedEncryptedImageSource>(lease, base, container_size);
    const std::weak_ptr<t::WindowsImageLease> lease_watch = lease;
    const std::weak_ptr<t::OwnedEncryptedImageSource> source_watch = source;
    auto session = Unlock(source, password); c::EncryptedReadError read_error;
    auto context = session->CreateMetadataReadContext(read_error); std::string error;
    const auto observe = [&] { return OwnerCounts{lease_watch.use_count(), source_watch.use_count(),
        session ? 1u : 0u, context ? 1u : 0u}; };
    auto current = c::LoadAppleCheckpointView(*source, 0, container_size, error, *context);
    Check(static_cast<bool>(current), "BootstrapActualCheckpoint");
    BootstrapResult result;
    result.binding = Binding(source->SourceIdentity() + ":dfvfs:20480:4153344:" + current->container.superblock.uuid_hex);
    auto original = Protection(directory, result.binding, "original");
    auto witness = Protection(directory, result.binding, "bootstrap");
    Check(fs::create_directory(original.key_directory) && fs::create_directory(witness.key_directory), "BootstrapSeparateEpochRoots");
    auto tx = OpenTx(directory / "original.wal", original);
    constexpr std::string_view old_patch = "PIN-OLD";
    const auto replacement = std::as_bytes(std::span(old_patch));
    const auto accepted = Accept(*tx, current->container.superblock.xid, false, false, replacement);
    auto prepared = session->PrepareCowOverwrite(*source, current->container.superblock.xid, inode,
        patch_offset, replacement, error);
    Check(static_cast<bool>(prepared), "BootstrapActualCow");
    const auto plan = prepared->Publication();
    Journal::Options options;
    options.container_bytes = container_size; options.container_uuid = current->container.superblock.uuid_hex;
    options.preimage_source_identity = source->SourceIdentity();
    BindSelectedVolume(options, *current);
    options.witness = {directory / "bootstrap.wal", "encrypted-publication-bootstrap", 64ull << 20, witness};
    auto journal = std::make_unique<Journal>(options);
    const bool staged = journal->Stage(*tx, accepted, *prepared, error);
    Check(staged, ("BootstrapStage:" + error).c_str());
    session->Close(); context.reset(); session.reset(); source.reset(); lease.reset(); prepared.reset();
    {
        Target target(image, identity, true, result.binding, observe);
        const bool published = journal->PublishOrRecover(*tx, accepted, target, error);
        Check(published, ("BootstrapPublication:" + error).c_str()); VerifyPlan(target, plan);
    }
    Check(tx->Watermarks().apfs_durable_sequence == accepted && tx->Watermarks().cleanup_sequence == 0,
        "PredecessorActuallyPublishedButUncleaned");
    std::vector<std::uint64_t> pins;
    Check(tx->LoadRequiredCheckpointXidsSinceCleanup(pins, &error) &&
        std::find(pins.begin(), pins.end(), plan.expected_checkpoint_xid) != pins.end(), "PredecessorActualWalStillPinsOldCheckpoint");
    result.writes = plan.before_superblock_writes; result.writes.push_back(plan.superblock_write);
    return result;
}
struct NamespaceSnapshot
{
    c::EncryptedNamespaceInfo info;
    std::map<std::uint64_t, c::EncryptedNodeInfo> nodes;
    std::map<std::uint64_t, std::map<std::string, std::uint64_t>> directories;
    std::map<std::uint64_t, Fact> files;
    std::vector<std::byte> target_bytes;
};
NamespaceSnapshot SnapshotNamespace(c::ApfsEncryptedReadSession& session)
{
    NamespaceSnapshot result;
    Check(session.GetNamespaceInfo(result.info) == c::EncryptedReadError::None, "TypedCompleteNamespaceInfo");
    std::vector<std::uint64_t> pending{result.info.root_inode_id};
    for (std::size_t index = 0; index < pending.size(); ++index) {
        const auto parent = pending[index];
        Check(!result.directories.contains(parent), "TypedNoDirectoryCycle");
        c::EncryptedNodeInfo metadata;
        Check(session.GetMetadata(parent, metadata) == c::EncryptedReadError::None && metadata.IsDirectory(), "TypedDirectoryMetadata");
        result.nodes[parent] = metadata;
        std::vector<c::EncryptedDirectoryEntry> entries;
        Check(session.ListDirectory(parent, entries) == c::EncryptedReadError::None, "TypedExactDirectoryInventory");
        auto& directory = result.directories[parent];
        for (const auto& entry : entries) {
            Check(entry.parent_id == parent && directory.emplace(entry.name_utf8, entry.inode_id).second, "TypedUniqueCanonicalLeaf");
            c::EncryptedNodeInfo node;
            Check(session.GetMetadata(entry.inode_id, node) == c::EncryptedReadError::None, "TypedEntryMetadata");
            result.nodes[entry.inode_id] = node;
            if (node.IsDirectory()) pending.push_back(entry.inode_id);
        }
    }
    std::vector<c::EncryptedFileInfo> files;
    Check(session.ListFiles(files) == c::EncryptedReadError::None, "TypedRegularFileInventory");
    for (const auto& file : files) {
        std::vector<std::byte> bytes;
        Check(session.ReadFile(file.inode_id, 0, static_cast<std::size_t>(file.size), bytes) == c::EncryptedReadError::None, "TypedExactRegularBytes");
        result.files[file.inode_id] = {result.nodes.at(file.inode_id), Hash(bytes)};
        if (file.inode_id == inode) result.target_bytes = bytes;
        SecureZeroMemory(bytes.data(), bytes.size());
    }
    return result;
}
void EmitNamespace(const std::map<std::uint64_t, std::map<std::string, std::uint64_t>>& directories)
{
    std::cout << '['; bool first = true;
    for (const auto& [parent, entries] : directories) {
        if (!first) std::cout << ','; first = false;
        std::cout << "{\"parent\":" << parent << ",\"entries\":["; bool first_entry = true;
        for (const auto& [name, id] : entries) {
            if (!first_entry) std::cout << ','; first_entry = false;
            std::cout << "{\"name\":" << std::quoted(name) << ",\"inode\":" << id << '}';
        }
        std::cout << "]}";
    }
    std::cout << ']';
}
void AppendLegacyWitness(const Journal::Options& options, const c::EncryptedCowOverwrite& prepared,
    std::uint64_t accepted, std::uint64_t transaction)
{
    const auto& plan = prepared.Publication(); WitnessEncoding body;
    for (const auto value : {1ULL, accepted, transaction, prepared.IntentInode(), prepared.IntentOffset(), prepared.IntentLength()}) body.Number(value);
    body.Data(std::as_bytes(std::span(prepared.IntentSha256()))); body.Text(options.preimage_source_identity);
    body.Number(options.container_bytes); body.Text(options.container_uuid); body.Number(plan.block_size);
    body.Number(plan.expected_checkpoint_xid); body.Number(plan.transaction_xid); body.Number(plan.next_object_id);
    body.Number(plan.guard_blocks.size());
    for (const auto& guard : plan.guard_blocks) { body.Number(guard.physical_block); body.Data(guard.bytes); }
    body.Number(plan.before_superblock_writes.size());
    for (const auto& write : plan.before_superblock_writes) body.Write(write);
    body.Write(plan.superblock_write);
    Wal wal(options.witness); Wal::Record row;
    row.sequence = 1; row.transaction_id = transaction; row.object_id = prepared.IntentInode(); row.parent_object_id = accepted;
    row.volume_identity = options.witness.volume_identity; row.operation = Wal::OperationKind::Write; row.state = Wal::RecordState::Prepared;
    auto append = [&] {
        row.logical_length = row.payload_length = row.inline_payload.size(); row.payload_sha256 = Hash(row.inline_payload);
        Check(wal.Append(row, false), "TypedAuthenticatedHistoricalWitnessAppend"); ++row.sequence;
    };
    for (std::size_t offset = 0; offset < body.bytes.size(); offset += 4096) {
        const auto length = (std::min)(std::size_t{4096}, body.bytes.size() - offset);
        row.path_utf8 = "\\encrypted-publication-chunk-v2"; row.logical_offset = offset;
        row.inline_payload.assign(body.bytes.begin() + offset, body.bytes.begin() + offset + length); append();
    }
    WitnessEncoding end;
    for (const auto value : {2ULL, accepted, transaction, prepared.IntentInode(), row.sequence - 1,
            static_cast<std::uint64_t>(body.bytes.size())}) end.Number(value);
    const auto digest = Hash(body.bytes); end.Data(std::as_bytes(std::span(digest)));
    row.path_utf8 = "\\encrypted-publication-end-v2"; row.logical_offset = 0; row.inline_payload = std::move(end.bytes); append();
    Check(wal.FlushPendingAppends(), "TypedHistoricalWitnessDurable");
}
int JournaledNamespace(const fs::path& image, const fs::path& directory,
    std::span<const std::byte> password, std::wstring_view mode)
{
    const bool create = mode.starts_with(L"typed-create"), resize = mode.starts_with(L"typed-resize"),
        rename = mode.starts_with(L"typed-rename") || mode.starts_with(L"typed-move"),
        unlink = mode.starts_with(L"typed-unlink"), move = mode.starts_with(L"typed-move"),
        legacy = mode.ends_with(L"-legacy-v1"), refusal = legacy || mode.find(L"-bad-") != std::wstring_view::npos,
        recover = mode.ends_with(L"-recover"), torn = mode.ends_with(L"-torn-switch"),
        watermark = mode.ends_with(L"-watermark");
    const bool reopen_bad_volume = mode.find(L"-reopen-bad-") != std::wstring_view::npos;
    auto lease = std::make_shared<t::WindowsImageLease>(image.wstring()); const auto identity = lease->Identity();
    auto source = std::make_shared<t::OwnedEncryptedImageSource>(lease, base, container_size);
    const std::weak_ptr<t::WindowsImageLease> lease_watch = lease;
    const std::weak_ptr<t::OwnedEncryptedImageSource> source_watch = source;
    auto session = Unlock(source, password); c::EncryptedReadError read_error;
    auto context = session->CreateMetadataReadContext(read_error); std::string error;
    const auto observe = [&] { return OwnerCounts{lease_watch.use_count(), source_watch.use_count(), session ? 1u : 0u, context ? 1u : 0u}; };
    auto current = c::LoadAppleCheckpointView(*source, 0, container_size, error, *context);
    Check(static_cast<bool>(current), "TypedCanonicalPreimage");
    auto before = SnapshotNamespace(*session);
    Check(before.files.size() == 6 && before.target_bytes.size() == 22, "TypedAuthenticBaseline");
    const auto source_parent = before.nodes.at(inode).parent_id;
    std::string source_name;
    for (const auto& [name, id] : before.directories.at(source_parent)) if (id == inode) {
        Check(source_name.empty(), "TypedSingleOriginalLink"); source_name = name;
    }
    Check(!source_name.empty(), "TypedOriginalCanonicalName");
    std::uint64_t destination_parent = source_parent;
    if (move) {
        for (const auto& [parent, entries] : before.directories) { (void)entries; if (parent != source_parent) { destination_parent = parent; break; } }
        Check(destination_parent != source_parent, "TypedActualCrossDirectoryMove");
    }
    const bool special = mode.ends_with(L"-special");
    const std::string created_name = special ? "journal:v2\\created.bin" : "journal-v2-created.bin",
        renamed_name = special ? "journal:v2\\renamed.bin" : "journal-v2-renamed.bin";
    std::vector<std::byte> payload((create && mode.find(L"empty") == std::wstring_view::npos) || (!create && !resize && !rename && !unlink) ? 31 : 0);
    for (std::size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<std::byte>((i * 37 + 19) % 251);
    c::EncryptedMutationRequest request;
    request.kind = create ? c::EncryptedMutationKind::Create : resize ? c::EncryptedMutationKind::Resize :
        rename ? c::EncryptedMutationKind::Rename : unlink ? c::EncryptedMutationKind::Unlink : c::EncryptedMutationKind::Write;
    request.inode = create ? 0 : inode; request.data = payload; request.permissions = create ? 0601 : 0644;
    if (create) { request.parent = source_parent; request.name = created_name; }
    if (resize) request.size = mode.find(L"shrink") != std::wstring_view::npos ? 5 : mode.find(L"zero") != std::wstring_view::npos ? 0 : 8197;
    if (rename || unlink) { request.parent = source_parent; request.name = source_name; }
    if (rename) { request.destination_parent = destination_parent; request.destination_name = renamed_name; }
    if (request.kind == c::EncryptedMutationKind::Write) request.offset = 3;
    auto prepared = session->PrepareMutation(*source, current->container.superblock.xid, request, error);
    Check(static_cast<bool>(prepared), ("TypedPrivatePreparation:" + error).c_str());
    const auto target_inode = prepared->IntentInode(); const auto plan = prepared->Publication();
    Journal::Options options;
    options.container_bytes = container_size; options.container_uuid = current->container.superblock.uuid_hex;
    options.preimage_source_identity = source->SourceIdentity(); BindSelectedVolume(options, *current);
    Check(prepared->VolumeObjectId() == options.volume_object_id && prepared->VolumeUuid() == options.volume_uuid,
        "TypedCapabilityMatchesTrustedCatalogVolume");
    Check(prepared->IntentKind() == request.kind && prepared->IntentParent() == request.parent &&
        prepared->IntentDestinationParent() == request.destination_parent && prepared->RequestedPermissions() == request.permissions &&
        prepared->IntentNameSha256() == Hash(std::as_bytes(std::span(request.name))) &&
        prepared->IntentDestinationNameSha256() == Hash(std::as_bytes(std::span(request.destination_name))), "TypedPrivateRequestFields");
    const auto binding = Binding(source->SourceIdentity() + ":dfvfs:20480:4153344:" + options.container_uuid);
    auto original_protection = Protection(directory, binding, "original"), witness_protection = Protection(directory, binding, "witness");
    Check(fs::create_directory(original_protection.key_directory) && fs::create_directory(witness_protection.key_directory), "TypedSeparateProtectedStreams");
    options.witness = {directory / "publication.wal", "encrypted-publication-witness", 64ull << 20, witness_protection};
    Tx::MutationIntent mutation;
    mutation.object_id = target_inode; mutation.path = L"journal-v2-write";
    mutation.kind = create ? Tx::MutationKind::CreateFile : resize ? Tx::MutationKind::SetFileSize :
        rename ? Tx::MutationKind::Rename : unlink ? Tx::MutationKind::Delete : Tx::MutationKind::Write;
    mutation.generation = request.parent; mutation.offset = rename ? destination_parent : create ? request.permissions : request.offset;
    mutation.length = resize ? request.size : payload.size();
    if (create || request.kind == c::EncryptedMutationKind::Write) {
        mutation.inline_payload = payload; mutation.payload_length = payload.size(); mutation.payload_checksum = Hash(payload);
    }
    if (create || rename || unlink) mutation.path.assign(request.name.begin(), request.name.end());
    if (rename) mutation.secondary_path.assign(request.destination_name.begin(), request.destination_name.end());
    if (mode.ends_with(L"-bad-mode")) mutation.offset ^= 4;
    if (mode.ends_with(L"-bad-name")) mutation.path += L".wrong";
    if (mode.ends_with(L"-bad-destination-name")) mutation.secondary_path += L".wrong";
    if (mode.ends_with(L"-bad-parent")) ++mutation.generation;
    if (mode.ends_with(L"-bad-destination-parent")) ++mutation.offset;
    if (mode.ends_with(L"-bad-eof")) ++mutation.length;
    if (mode.ends_with(L"-bad-op")) mutation.kind = Tx::MutationKind::SetBasicInfo;
    if (mode.ends_with(L"-bad-flag")) mutation.replace_if_exists = true;
    if (mode.ends_with(L"-bad-secondary")) mutation.secondary_path = L"forbidden";
    if (mode == L"typed-write-inline-xid") mutation.generation = current->container.superblock.xid;
    if (mode.ends_with(L"-bad-hash")) mutation.payload_checksum.front() ^= 1;
    if (!reopen_bad_volume && mode.ends_with(L"-bad-volume")) ++options.volume_object_id;
    if (!reopen_bad_volume && mode.ends_with(L"-bad-volume-uuid")) options.volume_uuid.front() = options.volume_uuid.front() == '0' ? '1' : '0';
    auto tx = OpenTx(directory / "original.wal", original_protection);
    Check(tx->Begin(), "TypedBeginOriginalTransaction");
    Spool::Options spool_options;
    const bool spool_payload = create && !payload.empty();
    if (spool_payload) {
        spool_options.root = directory / "payload"; spool_options.volume_identity = Tx::WideToUtf8(std::wstring(volume));
        spool_options.protected_persistence = true; spool_options.protected_binding = binding;
        spool_options.protected_key_directory = directory / "payload-keys";
        spool_options.durable_flush_bytes = spool_options.durable_flush_appends = 0;
        Check(fs::create_directory(spool_options.root) && fs::create_directory(spool_options.protected_key_directory), "TypedSeparateProtectedCreatePayloadRoots");
        Spool spool(spool_options); Spool::AppendResult reference;
        const auto spool_offset = mutation.kind == Tx::MutationKind::SetBasicInfo ? 0 : mutation.offset;
        Check(spool.Append({spool_options.volume_identity, target_inode, mutation.generation, spool_offset,
            tx->NextMutationSequence(), payload}, &reference) && spool.FlushPayloadBytes(), "TypedCreatePayloadDurableBeforeAcceptance");
        mutation.inline_payload.clear(); mutation.wal_sequence = reference.wal_sequence; mutation.payload_spool_offset = reference.spool_offset;
    }
    Check(tx->RecordMutation(mutation), "TypedRecordOriginalMutation");
    SetLastError(ERROR_SUCCESS); const bool accepted_ok = tx->Accept(current->container.superblock.xid); const auto acceptance_error = GetLastError();
    if (!accepted_ok) std::cerr << "TypedAcceptanceFailure operation=" << static_cast<unsigned>(mutation.kind)
        << " payloadBytes=" << payload.size() << " win32=" << acceptance_error << '\n';
    Check(accepted_ok, "TypedActualOriginalAcceptance");
    const auto accepted = tx->Watermarks().accepted_sequence;
    std::vector<Tx::AcceptedTransaction> accepted_rows;
    Check(tx->LoadUnappliedAcceptedTransactions(accepted_rows) && accepted_rows.size() == 1 && accepted_rows[0].mutations.size() == 1,
        "TypedOriginalAcceptedBoundary");
    const auto accepted_transaction = accepted_rows[0].transaction_id;
    if (spool_payload) {
        tx.reset(); tx = OpenTx(directory / "original.wal", original_protection);
        accepted_rows.clear();
        Check(tx->LoadUnappliedAcceptedTransactions(accepted_rows) && accepted_rows.size() == 1 && accepted_rows[0].mutations.size() == 1,
            "TypedReopenedOriginalCreateReference");
        const auto& record = accepted_rows[0].mutations[0];
        Spool::PersistedRangeReference reference{spool_options.volume_identity, record.object_id, record.parent_object_id,
            record.logical_offset, record.payload_length, record.payload_offset, record.payload_spool_id, record.payload_sha256};
        Spool spool(spool_options); std::vector<std::byte> recovered;
        Check(spool.RebuildIndexFromReferences(std::span(&reference, 1), 0) && spool.ReadPersistedRange(reference, recovered) &&
            recovered == payload, "TypedFreshCreatePayloadOwnerExactOriginalWalReference");
        SecureZeroMemory(recovered.data(), recovered.size());
    }
    const auto baseline_image = Hash(Read(image)), original_wal = Hash(Read(directory / "original.wal"));
    bool staged = false; std::string stage_error;
    if (legacy) AppendLegacyWitness(options, *prepared, accepted, accepted_transaction);
    else {
        Journal journal(options); staged = journal.Stage(*tx, accepted, *prepared, error); stage_error = error;
        Check(staged == (!refusal || reopen_bad_volume), ("TypedStageBindsExactAcceptedIntent:" + error).c_str());
        if (refusal && !reopen_bad_volume) Check(!fs::exists(options.witness.path), "TypedRejectedIntentHasNoWitnessFile");
    }
    Check(Hash(Read(image)) == baseline_image && Hash(Read(directory / "original.wal")) == original_wal, "TypedStagePreservesImageAndOriginalWal");
    if (staged) VerifyWitness(options, plan, accepted, accepted_transaction, prepared->IntentSha256(), prepared->IntentOffset(), prepared->IntentLength(), prepared.get());
    if (legacy) VerifyWitness(options, plan, accepted, accepted_transaction, prepared->IntentSha256(), prepared->IntentOffset(), prepared->IntentLength());
    const auto result_size = prepared->ResultSize(); const auto effective_mode = prepared->EffectiveMode();
    session->Close(); context.reset(); session.reset(); source.reset(); lease.reset(); prepared.reset(); tx.reset();
    if (reopen_bad_volume) {
        if (mode.ends_with(L"-bad-volume")) ++options.volume_object_id;
        else options.volume_uuid.front() = options.volume_uuid.front() == '0' ? '1' : '0';
    }
    std::size_t first_writes = 0, recovery_writes = 0, original_flushes = 0, witness_flushes = 0;
    bool cut_hit = false, image_flushed = false, watermark_fault = false; std::string first_error;
    tx = OpenTx(directory / "original.wal", original_protection);
    tx->SetJournalFaultInjectionHook([&](std::string_view stage) {
        if (stage == "durable-flush") { ++original_flushes; if (watermark && image_flushed) { watermark_fault = true; return true; } }
        return false;
    });
    auto journal = std::make_unique<Journal>(options);
    WitnessFault(*journal, [&](std::string_view stage) { if (stage == "durable-flush") ++witness_flushes; return false; });
    {
        Target target(image, identity, true, binding, observe);
        target.before_write = [&] { Check(original_flushes && witness_flushes, "TypedBothWalBarriersBeforeImageWrite"); };
        target.after_flush = [&](std::size_t count) { if (count == 3) image_flushed = true; };
        if (recover) target.fail_after = 1;
        if (torn) target.tear_block = plan.superblock_write.physical_block;
        const bool published = journal->PublishOrRecover(*tx, accepted, target, error); first_error = error;
        Check(published == (!refusal && !recover && !torn && !watermark), ("TypedFirstPublicationOutcome:" + error).c_str());
        first_writes = target.writes; cut_hit = target.cut_hit;
        if (refusal) Check(target.attempts == 0 && target.writes == 0 && target.flushes == 0, "TypedRefusalBeforeImageWritesOrFlush");
        if (legacy) Check(error == "EncryptedPublicationLegacyWitnessNeedsOriginalOwner", "TypedSelectedLegacyWitnessExplicitRefusal");
        if (recover) Check(cut_hit && first_writes == 1 && target.attempts == 2, "TypedActualInterruptedBlockWrite");
        if (torn) Check(cut_hit && target.torn_bytes == 128 && first_writes == plan.before_superblock_writes.size(), "TypedActualTornNxsb");
        if (watermark) Check(image_flushed && watermark_fault && tx->Watermarks().apfs_durable_sequence == 0, "TypedCompleteCheckpointMarkerFlushAmbiguity");
    }
    journal.reset(); tx.reset();
    tx = OpenTx(directory / "original.wal", original_protection);
    if (watermark) Check(tx->Watermarks().apfs_durable_sequence == accepted, "TypedFreshOwnerReadsCompleteCheckpointMarker");
    if (!refusal) {
        original_flushes = witness_flushes = 0;
        tx->SetJournalFaultInjectionHook([&](std::string_view stage) { if (stage == "durable-flush") ++original_flushes; return false; });
        journal = std::make_unique<Journal>(options);
        WitnessFault(*journal, [&](std::string_view stage) { if (stage == "durable-flush") ++witness_flushes; return false; });
        {
            Target target(image, identity, false, binding, observe);
            Check(journal->PublishOrRecover(*tx, accepted, target, error), ("TypedFreshOwnersRecoverSelectedBoundary:" + error).c_str());
            VerifyPlan(target, plan); recovery_writes = target.writes;
            Check(original_flushes && witness_flushes && target.flushes > 0, "TypedFreshRecoveryUnconditionalEvidenceBarriers");
            Check((recover || torn) ? recovery_writes > 0 : recovery_writes == 0, "TypedRecoveryWritesMatchSelectedCheckpointState");
        }
        journal.reset(); tx.reset(); tx = OpenTx(directory / "original.wal", original_protection);
    } else Check(Hash(Read(image)) == baseline_image && Hash(Read(directory / "original.wal")) == original_wal, "TypedRefusalPreservesWholeImageAndOriginalWal");
    Check(tx->Watermarks().accepted_sequence == accepted && tx->Watermarks().apfs_durable_sequence == (refusal ? 0 : accepted) &&
        tx->Watermarks().cleanup_sequence == 0 && tx->HasUnappliedAcceptedWork() == refusal, "TypedOriginalRestartWatermarks"); tx.reset();
    auto fresh_lease = std::make_shared<t::WindowsImageLease>(image.wstring());
    auto fresh_source = std::make_shared<t::OwnedEncryptedImageSource>(fresh_lease, base, container_size); auto fresh = Unlock(fresh_source, password);
    auto after = SnapshotNamespace(*fresh); auto expected_directories = before.directories; auto expected_files = before.files;
    auto fresh_context = fresh->CreateMetadataReadContext(read_error);
    auto after_checkpoint = c::LoadAppleCheckpointView(*fresh_source, 0, container_size, error, *fresh_context);
    Check(after_checkpoint && after_checkpoint->container.superblock.xid ==
        (refusal ? plan.expected_checkpoint_xid : plan.transaction_xid), "TypedFreshCanonicalSelectedCheckpoint");
    if (special) {
        c::EncryptedDirectoryEntry native, projected;
        const auto parent = create ? source_parent : destination_parent;
        const auto& name = create ? created_name : renamed_name;
        Check(fresh->Lookup(parent, name, native) == c::EncryptedReadError::None && native.inode_id == target_inode &&
            native.windows_name != std::wstring(name.begin(), name.end()) &&
            fresh->LookupWindows(parent, native.windows_name, projected) == c::EncryptedReadError::None &&
            projected.inode_id == target_inode && projected.name_utf8 == name, "TypedNativeSpecialLeafCodecRoundTrip");
    }
    auto expected = before.target_bytes;
    if (!refusal) {
        if (create) { expected = payload; expected_directories[source_parent][created_name] = target_inode; }
        if (resize) expected.resize(static_cast<std::size_t>(request.size));
        if (request.kind == c::EncryptedMutationKind::Write) {
            expected.resize((std::max)(expected.size(), static_cast<std::size_t>(request.offset + payload.size())));
            std::copy(payload.begin(), payload.end(), expected.begin() + request.offset);
        }
        if (rename || unlink) expected_directories[source_parent].erase(source_name);
        if (rename) expected_directories[destination_parent][renamed_name] = target_inode;
        if (unlink) expected_files.erase(target_inode);
        else {
            Fact fact = create ? Fact{} : before.files.at(target_inode);
            fact.metadata.size = expected.size(); fact.metadata.allocated_size = ((expected.size() + 4095) / 4096) * 4096;
            if (create) { fact.metadata.inode_id = target_inode; fact.metadata.parent_id = source_parent; fact.metadata.mode = 0100000 | request.permissions; }
            if (rename) fact.metadata.parent_id = destination_parent;
            fact.hash = Hash(expected); expected_files[target_inode] = fact;
        }
    }
    Check(after.directories == expected_directories && after.files.size() == expected_files.size(), "TypedExactNamespaceAndFileInventory");
    const auto delta = refusal ? 0 : create ? 1 : unlink ? -1 : 0;
    Check(static_cast<std::int64_t>(after.info.inode_count) == static_cast<std::int64_t>(before.info.inode_count) + delta &&
        static_cast<std::int64_t>(after.info.entry_count) == static_cast<std::int64_t>(before.info.entry_count) + delta, "TypedNamespaceInodeAndDentryCounts");
    for (const auto& [id, fact] : expected_files) {
        const auto& actual = after.files.at(id);
        Check(actual.hash == fact.hash && actual.metadata.size == fact.metadata.size, "TypedTargetAndAllPeerBytes");
        if (!refusal && create && id == target_inode) Check(actual.metadata.mode == (0100000 | request.permissions) &&
            actual.metadata.parent_id == source_parent && actual.metadata.allocated_size == fact.metadata.allocated_size &&
            actual.metadata.uid == before.nodes.at(source_parent).uid && actual.metadata.gid == before.nodes.at(source_parent).gid &&
            actual.metadata.protection_class == before.nodes.at(source_parent).protection_class && actual.metadata.children_or_links == 1,
            "TypedCreateExactModeOwnershipParentAndAllocation");
        else Check(SameMetadata(actual.metadata, fact.metadata) && actual.metadata.parent_id == fact.metadata.parent_id &&
            actual.metadata.children_or_links == fact.metadata.children_or_links, "TypedPreservedRegularMetadata");
    }
    for (const auto& [parent, entries] : expected_directories) {
        auto expected_parent = before.nodes.at(parent); const auto& actual = after.nodes.at(parent);
        const auto difference = static_cast<std::int64_t>(entries.size()) - static_cast<std::int64_t>(before.directories.at(parent).size());
        Check(static_cast<std::int64_t>(actual.children_or_links) == static_cast<std::int64_t>(expected_parent.children_or_links) + difference &&
            SameMetadata(actual, expected_parent) && actual.parent_id == expected_parent.parent_id, "TypedExactParentCountsAndPreservedDirectoryMetadata");
    }
    if (!refusal && unlink) { c::EncryptedNodeInfo missing; Check(fresh->GetMetadata(target_inode, missing) == c::EncryptedReadError::FileNotFound, "TypedUnlinkedInodeAbsent"); }
    std::cout << "{\"passed\":true,\"checks\":" << checks << ",\"typedNamespace\":true,\"staged\":" << (staged ? "true" : "false")
        << ",\"refused\":" << (refusal ? "true" : "false") << ",\"expectedNew\":" << (refusal ? "false" : "true")
        << ",\"bootstrapPublished\":false,\"corruptionInjected\":false,\"exactWitness\":" << (staged || legacy ? "true" : "false")
        << ",\"freshNative\":true,\"originalRestart\":true,\"targetInode\":" << target_inode << ",\"kind\":" << static_cast<unsigned>(request.kind)
        << ",\"sourceParent\":" << source_parent << ",\"destinationParent\":" << destination_parent << ",\"sourceName\":" << std::quoted(source_name)
        << ",\"createdName\":" << std::quoted(created_name) << ",\"renamedName\":" << std::quoted(renamed_name)
        << ",\"specialProjection\":" << (special ? "true" : "false") << ",\"protectedSpoolPayload\":" << (spool_payload ? "true" : "false")
        << ",\"requestedPermissions\":" << request.permissions << ",\"effectiveMode\":" << effective_mode << ",\"resultSize\":" << result_size
        << ",\"expectedEof\":" << (refusal ? 22 : expected.size()) << ",\"payloadLength\":" << payload.size() << ",\"writeOffset\":" << request.offset
        << ",\"originalTargetHex\":" << std::quoted(Hex(std::span(reinterpret_cast<const std::uint8_t*>(before.target_bytes.data()), before.target_bytes.size())))
        << ",\"volumeObjectId\":" << options.volume_object_id << ",\"volumeUuid\":" << std::quoted(options.volume_uuid)
        << ",\"stageError\":" << std::quoted(stage_error) << ",\"firstError\":" << std::quoted(first_error) << ",\"firstWrites\":" << first_writes
        << ",\"recoveryWrites\":" << recovery_writes << ",\"cutHit\":" << (cut_hit ? "true" : "false")
        << ",\"watermarkFault\":" << (watermark_fault ? "true" : "false") << ",\"acceptedSequence\":" << accepted
        << ",\"baselineImageSha256\":" << std::quoted(Hex(baseline_image)) << ",\"switchBlock\":" << plan.superblock_write.physical_block
        << ",\"beforeNamespace\":"; EmitNamespace(before.directories); std::cout << ",\"expectedNamespace\":"; EmitNamespace(expected_directories);
    std::cout << ",\"files\":["; bool first = true;
    for (const auto& [id, fact] : expected_files) { if (!first) std::cout << ','; first = false;
        std::cout << "{\"inode\":" << id << ",\"size\":" << fact.metadata.size << ",\"expectedSha256\":" << std::quoted(Hex(fact.hash)) << '}'; }
    std::cout << "],\"plannedBlocks\":["; first = true;
    auto emit = [&](const auto& row) { if (!first) std::cout << ','; first = false; std::cout << "{\"block\":" << row.physical_block << ",\"sha256\":" << std::quoted(Hex(Hash(row.bytes))) << '}'; };
    for (const auto& row : plan.before_superblock_writes) emit(row); emit(plan.superblock_write);
    std::cout << "],\"bootstrapBlocks\":[],\"injectedBlocks\":[],\"acquisitions\":"; EmitAcquisitions(std::cout); std::cout << "}\n";
    return 0;
}
int SequentialPublication(const fs::path& image, const fs::path& directory,
    std::span<const std::byte> password, bool second)
{
    std::uint64_t first_accepted = 0;
    const auto original_path = directory / "original.wal", witness_path = directory / "publication.wal";
    if (second) {
        const auto gate = Read(directory / "verification.gate");
        constexpr std::string_view magic = "EPJSEQ01";
        Check(gate.size() == 144 && std::equal(std::as_bytes(std::span(magic)).begin(),
            std::as_bytes(std::span(magic)).end(), gate.begin()), "SequenceIndependentVerificationGate");
        WitnessReader boundary(std::span<const std::byte>(gate).subspan(8, 8)); first_accepted = boundary.Number();
        auto exact = [&](std::size_t offset, const auto& digest) {
            return std::equal(std::as_bytes(std::span(digest)).begin(), std::as_bytes(std::span(digest)).end(), gate.begin() + offset);
        };
        Check(first_accepted && exact(16, Hash(Read(image))) && exact(48, Hash(Read(original_path))) &&
            exact(80, Hash(Read(witness_path))) && exact(112, Hash(Read(directory / "source-identity.first"))),
            "SequenceImageAndBothOriginalStreamsUnchangedSinceIndependentVerification");
    }
    auto lease = std::make_shared<t::WindowsImageLease>(image.wstring()); const auto identity = lease->Identity();
    auto source = std::make_shared<t::OwnedEncryptedImageSource>(lease, base, container_size);
    const std::weak_ptr<t::WindowsImageLease> lease_watch = lease;
    const std::weak_ptr<t::OwnedEncryptedImageSource> source_watch = source;
    auto session = Unlock(source, password); c::EncryptedReadError read_error;
    auto context = session->CreateMetadataReadContext(read_error); std::string error;
    const auto observe = [&] { return OwnerCounts{lease_watch.use_count(), source_watch.use_count(), session ? 1u : 0u, context ? 1u : 0u}; };
    auto current = c::LoadAppleCheckpointView(*source, 0, container_size, error, *context);
    Check(static_cast<bool>(current), "SequenceCanonicalPreimage");
    auto before = SnapshotNamespace(*session);
    Check(before.files.size() == 6 && before.target_bytes.size() == (second ? 34 : 22), "SequenceActualPriorBytesAndPeers");
    Journal::Options options;
    options.container_bytes = container_size; options.container_uuid = current->container.superblock.uuid_hex;
    options.preimage_source_identity = source->SourceIdentity(); BindSelectedVolume(options, *current);
    const auto source_hash = Hash(std::as_bytes(std::span(options.preimage_source_identity)));
    // Binding is owner-known stable file/geometry/volume identity. The per-plan
    // preimage identity still includes this fresh immutable lease's write time.
    const auto binding = Binding(StableIdentity(identity) + ":20480:4153344:" + options.container_uuid +
        ":" + std::to_string(options.volume_object_id) + ":" + options.volume_uuid);
    const auto original_protection = Protection(directory, binding, "original"), witness_protection = Protection(directory, binding, "witness");
    if (second) Check(fs::is_directory(original_protection.key_directory) && fs::is_directory(witness_protection.key_directory), "SequenceSameExistingKeyDirectories");
    else {
        Check(fs::create_directory(original_protection.key_directory) && fs::create_directory(witness_protection.key_directory), "SequenceOriginalProtectedEpochRoots");
        std::ofstream saved(directory / "source-identity.first", std::ios::binary | std::ios::trunc);
        saved.write(options.preimage_source_identity.data(), static_cast<std::streamsize>(options.preimage_source_identity.size()));
        saved.flush(); Check(static_cast<bool>(saved), "SequenceRetainFirstPreimageIdentityForStaleOwnerNegative");
    }
    options.witness = {witness_path, "encrypted-publication-witness", 64ull << 20, witness_protection};
    const auto prior_witness = second ? Read(witness_path) : std::vector<std::byte>{};
    auto tx = OpenTx(original_path, original_protection);
    if (second) {
        Check(tx->Watermarks().accepted_sequence == first_accepted && tx->Watermarks().apfs_durable_sequence == first_accepted &&
            tx->Watermarks().cleanup_sequence == 0 && !tx->HasUnappliedAcceptedWork(), "SequenceFirstActuallyApfsDurableBeforeCleanup");
        std::vector<Tx::AcceptedTransaction> first;
        Check(tx->LoadAcceptedTransactionsSinceCleanup(first, &error) && first.size() == 1 && first.front().accepted_sequence == first_accepted &&
            first.front().mutations.size() == 1 && first.front().mutations.front().object_id == inode &&
            current->container.superblock.xid == first.front().preimage_checkpoint_xid + 1, "SequenceOriginalFirstAcceptanceStillRetained");
        Check(tx->MarkCleanedThrough(first_accepted) && tx->Watermarks().cleanup_sequence == first_accepted, "SequenceCleanupOnlyAfterParentAndFreshNativeVerification");
        std::vector<std::uint64_t> pins;
        Check(tx->LoadRequiredCheckpointXidsSinceCleanup(pins, &error) && pins.empty(), "SequenceCleanedOriginalNoLongerPinsFirstPreimage");
    }
    const auto previous_durable = tx->Watermarks().apfs_durable_sequence;
    std::vector<std::byte> payload(second ? 0 : 31);
    for (std::size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<std::byte>((i * 37 + 19) % 251);
    const auto parent = before.nodes.at(inode).parent_id;
    const auto destination = before.info.root_inode_id;
    std::string name;
    for (const auto& [leaf, id] : before.directories.at(parent)) if (id == inode) { Check(name.empty(), "SequenceSingleSourceLeaf"); name = leaf; }
    Check(!name.empty() && parent != destination, "SequenceActualCrossDirectoryNamespaceChange");
    constexpr std::string_view renamed = "sequence-v2-renamed.bin";
    c::EncryptedMutationRequest request;
    request.kind = second ? c::EncryptedMutationKind::Rename : c::EncryptedMutationKind::Write;
    request.inode = inode; request.data = payload;
    if (second) { request.parent = parent; request.destination_parent = destination; request.name = name; request.destination_name = renamed; }
    else request.offset = 3;
    auto prepared = session->PrepareMutation(*source, current->container.superblock.xid, request, error);
    Check(static_cast<bool>(prepared), ("SequencePrivatePreparation:" + error).c_str());
    Check(prepared->RequiredCheckpointXids() == std::vector<std::uint64_t>{current->container.superblock.xid}, "SequenceExactCurrentPinSetAfterCleanup");
    const auto plan = prepared->Publication();
    Tx::MutationIntent mutation;
    mutation.object_id = inode;
    if (second) {
        mutation.kind = Tx::MutationKind::Rename; mutation.generation = parent; mutation.offset = destination;
        mutation.path.assign(name.begin(), name.end()); mutation.secondary_path.assign(renamed.begin(), renamed.end());
    } else {
        mutation.kind = Tx::MutationKind::Write; mutation.path = L"sequence-data"; mutation.offset = 3;
        mutation.inline_payload = payload; mutation.payload_length = mutation.length = payload.size(); mutation.payload_checksum = Hash(payload);
    }
    Check(tx->Begin() && tx->RecordMutation(mutation) && tx->Accept(current->container.superblock.xid), "SequenceOriginalProtectedAcceptance");
    const auto accepted = tx->Watermarks().accepted_sequence;
    Check(accepted > previous_durable && tx->Watermarks().cleanup_sequence == (second ? first_accepted : 0), "SequenceMonotonicOriginalBoundary");
    tx.reset(); tx = OpenTx(original_path, original_protection);
    std::vector<Tx::AcceptedTransaction> accepted_rows;
    Check(tx->LoadAcceptedTransactionsSinceCleanup(accepted_rows, &error) && accepted_rows.size() == 1 && accepted_rows.front().accepted_sequence == accepted,
        "SequenceFreshOriginalSelectsOnlySecondUncleanedBoundary");
    const auto accepted_transaction = accepted_rows.front().transaction_id;
    const auto baseline_image = Hash(Read(image)); bool stale_refused = false;
    if (second) {
        const auto saved = Read(directory / "source-identity.first");
        const std::string old_identity(reinterpret_cast<const char*>(saved.data()), saved.size());
        Check(old_identity != options.preimage_source_identity, "SequenceFreshPreimageIdentityChangedAfterOwnWrites");
        auto stale = options; stale.preimage_source_identity = old_identity;
        Journal old_owner(stale);
        stale_refused = !old_owner.Stage(*tx, accepted, *prepared, error);
        Check(stale_refused && error == "EncryptedPublicationPreparedScopeMismatch" && Read(witness_path) == prior_witness &&
            Hash(Read(image)) == baseline_image, "SequenceStalePreimageOwnerRefusesBeforeAppendingOrImageWrite");
    }
    auto journal = std::make_unique<Journal>(options);
    const bool staged = journal->Stage(*tx, accepted, *prepared, error);
    if (!staged) throw std::runtime_error("SequenceStage:" + error + ":priorWitnessBytes=" + std::to_string(prior_witness.size()));
    Check(Hash(Read(image)) == baseline_image, "SequenceStageNeverWritesImage"); journal.reset();
    const auto staged_witness = Read(witness_path);
    Check(staged_witness.size() > prior_witness.size() && std::equal(prior_witness.begin(), prior_witness.end(), staged_witness.begin()),
        "SequencePriorWitnessRetainedByteExactWithoutReset");
    VerifyWitness(options, plan, accepted, accepted_transaction, prepared->IntentSha256(), prepared->IntentOffset(), prepared->IntentLength(), prepared.get());
    std::size_t witness_records = 0, witness_groups = 0;
    {
        Wal wal(options.witness); auto records = wal.ReadAllWithExclusiveWriterLease();
        Check(records.status == Wal::ReadStatus::Ok, "SequenceSameProtectedWitnessReopened"); witness_records = records.records.size();
        for (const auto& record : records.records) if (record.path_utf8 == "\\encrypted-publication-end-v2") ++witness_groups;
        Check(witness_groups == (second ? 2u : 1u) && witness_records <= 4096, "SequenceBothActualGroupsWithinUnchangedRecordLimit");
    }
    session->Close(); context.reset(); session.reset(); source.reset(); lease.reset(); prepared.reset(); tx.reset();
    std::size_t first_writes = 0, recovery_writes = 0, original_flushes = 0, witness_flushes = 0; bool cut_hit = false;
    tx = OpenTx(original_path, original_protection);
    tx->SetJournalFaultInjectionHook([&](std::string_view stage) { if (stage == "durable-flush") ++original_flushes; return false; });
    journal = std::make_unique<Journal>(options);
    WitnessFault(*journal, [&](std::string_view stage) { if (stage == "durable-flush") ++witness_flushes; return false; });
    {
        Target target(image, identity, true, binding, observe);
        target.before_write = [&] { Check(original_flushes && witness_flushes, "SequenceBothBarriersBeforePublicationWrites"); };
        const bool published = journal->PublishOrRecover(*tx, accepted, target, error, [&](std::string_view stage) {
            if (second && stage == "before-apple-checkpoint-switch") { cut_hit = true; return false; } return true;
        });
        Check(published != second, ("SequenceFirstPublicationOutcome:" + error).c_str()); first_writes = target.writes;
        if (second) Check(cut_hit && first_writes == plan.before_superblock_writes.size() &&
            ObserveCheckpoint(target) == plan.expected_checkpoint_xid && tx->Watermarks().apfs_durable_sequence == previous_durable,
            "SequenceSecondRealPreSwitchInterruptionKeepsFirstCheckpointSelected");
        else VerifyPlan(target, plan);
    }
    journal.reset(); tx.reset();
    tx = OpenTx(original_path, original_protection);
    if (second) {
        Check(tx->Watermarks().apfs_durable_sequence == first_accepted && tx->Watermarks().cleanup_sequence == first_accepted &&
            tx->Watermarks().accepted_sequence == accepted, "SequenceFreshOwnersRetainFirstDurableSecondPending");
        original_flushes = witness_flushes = 0;
        tx->SetJournalFaultInjectionHook([&](std::string_view stage) { if (stage == "durable-flush") ++original_flushes; return false; });
        journal = std::make_unique<Journal>(options);
        WitnessFault(*journal, [&](std::string_view stage) { if (stage == "durable-flush") ++witness_flushes; return false; });
        {
            Target target(image, identity, false, binding, observe);
            Check(journal->PublishOrRecover(*tx, accepted, target, error), ("SequenceSecondFreshRecovery:" + error).c_str());
            VerifyPlan(target, plan); recovery_writes = target.writes;
            Check(original_flushes && witness_flushes && target.flushes > 0 && recovery_writes > 0, "SequenceSecondBothBarriersAndActualReplay");
        }
        journal.reset(); tx.reset(); tx = OpenTx(original_path, original_protection);
    }
    Check(tx->Watermarks().accepted_sequence == accepted && tx->Watermarks().apfs_durable_sequence == accepted &&
        tx->Watermarks().cleanup_sequence == (second ? first_accepted : 0) && !tx->HasUnappliedAcceptedWork(), "SequenceOriginalFinalRestartWatermarks"); tx.reset();
    auto fresh_lease = std::make_shared<t::WindowsImageLease>(image.wstring());
    auto fresh_source = std::make_shared<t::OwnedEncryptedImageSource>(fresh_lease, base, container_size); auto fresh = Unlock(fresh_source, password);
    const auto after = SnapshotNamespace(*fresh); auto expected_directories = before.directories; auto expected_files = before.files;
    auto expected_bytes = before.target_bytes;
    if (second) { expected_directories.at(parent).erase(name); expected_directories.at(destination)[std::string(renamed)] = inode; expected_files.at(inode).metadata.parent_id = destination; }
    else { expected_bytes.resize(34); std::copy(payload.begin(), payload.end(), expected_bytes.begin() + 3);
        expected_files.at(inode).metadata.size = 34; expected_files.at(inode).hash = Hash(expected_bytes); }
    Check(after.directories == expected_directories && after.files.size() == expected_files.size() &&
        after.info.inode_count == before.info.inode_count && after.info.entry_count == before.info.entry_count, "SequenceExactNamespaceAndCounts");
    for (const auto& [id, fact] : expected_files) {
        const auto& actual = after.files.at(id);
        Check(actual.hash == fact.hash && SameMetadata(actual.metadata, fact.metadata) && actual.metadata.parent_id == fact.metadata.parent_id &&
            actual.metadata.children_or_links == fact.metadata.children_or_links, "SequenceExpectedDataMetadataAndAllUnchangedPeers");
    }
    for (const auto& [id, entries] : expected_directories) {
        const auto& actual = after.nodes.at(id); const auto& old = before.nodes.at(id);
        const auto difference = static_cast<std::int64_t>(entries.size()) - static_cast<std::int64_t>(before.directories.at(id).size());
        Check(SameMetadata(actual, old) && actual.parent_id == old.parent_id &&
            static_cast<std::int64_t>(actual.children_or_links) == static_cast<std::int64_t>(old.children_or_links) + difference,
            "SequenceParentCountsAndDirectoryMetadata");
    }
    auto fresh_context = fresh->CreateMetadataReadContext(read_error);
    auto final_checkpoint = c::LoadAppleCheckpointView(*fresh_source, 0, container_size, error, *fresh_context);
    Check(final_checkpoint && final_checkpoint->container.superblock.xid == plan.transaction_xid, "SequenceFreshCanonicalFinalCheckpoint");
    std::cout << "{\"passed\":true,\"sequence\":true,\"second\":" << (second ? "true" : "false") << ",\"checks\":" << checks
        << ",\"kind\":" << static_cast<unsigned>(request.kind) << ",\"refused\":false,\"specialProjection\":false,\"targetInode\":21,\"sourceParent\":" << parent
        << ",\"destinationParent\":" << (second ? destination : parent) << ",\"sourceName\":" << std::quoted(name)
        << ",\"renamedName\":" << std::quoted(renamed) << ",\"createdName\":\"\",\"requestedPermissions\":420,\"firstAccepted\":" << first_accepted
        << ",\"acceptedSequence\":" << accepted << ",\"apfsDurableSequence\":" << accepted << ",\"cleanupSequence\":" << (second ? first_accepted : 0)
        << ",\"preimageCheckpoint\":" << plan.expected_checkpoint_xid << ",\"publishedCheckpoint\":" << plan.transaction_xid
        << ",\"preimageIdentitySha256\":" << std::quoted(Hex(source_hash)) << ",\"stableBinding\":"
        << std::quoted(Hex(std::span(reinterpret_cast<const std::uint8_t*>(binding.data()), binding.size())))
        << ",\"originalTargetHex\":" << std::quoted(Hex(std::span(reinterpret_cast<const std::uint8_t*>(before.target_bytes.data()), before.target_bytes.size())))
        << ",\"stalePreimageRefused\":" << (stale_refused ? "true" : "false") << ",\"witnessRecords\":" << witness_records << ",\"witnessGroups\":" << witness_groups
        << ",\"priorWitnessBytes\":" << prior_witness.size() << ",\"witnessBytes\":" << staged_witness.size()
        << ",\"firstWrites\":" << first_writes << ",\"recoveryWrites\":" << recovery_writes << ",\"cutHit\":" << (cut_hit ? "true" : "false")
        << ",\"exactWitness\":true,\"freshNative\":true,\"originalRestart\":true,\"beforeNamespace\":"; EmitNamespace(before.directories);
    std::cout << ",\"expectedNamespace\":"; EmitNamespace(expected_directories); std::cout << ",\"files\":["; bool first = true;
    for (const auto& [id, fact] : expected_files) { if (!first) std::cout << ','; first = false;
        std::cout << "{\"inode\":" << id << ",\"size\":" << fact.metadata.size << ",\"expectedSha256\":" << std::quoted(Hex(fact.hash)) << '}'; }
    std::cout << "],\"plannedBlocks\":["; first = true;
    auto emit = [&](const auto& row) { if (!first) std::cout << ','; first = false; std::cout << "{\"block\":" << row.physical_block << ",\"sha256\":" << std::quoted(Hex(Hash(row.bytes))) << '}'; };
    for (const auto& row : plan.before_superblock_writes) emit(row); emit(plan.superblock_write);
    std::cout << "],\"acquisitions\":"; EmitAcquisitions(std::cout); std::cout << "}\n"; return 0;
}
int JournaledWrite(const fs::path& image, const fs::path& directory,
    std::span<const std::byte> password, std::wstring_view mode)
{
    const bool spool_payload = mode.starts_with(L"write-64k-spool");
    const bool bad_generation = mode == L"write-64k-spool-wrong-generation";
    const bool maximum = mode == L"write-64k" || spool_payload, multi_block = mode == L"multi-block-write";
    const std::uint64_t offset = maximum ? 0 : multi_block ? 3 : 8197;
    std::vector<std::byte> payload(maximum ? 65536 : multi_block ? 5003 : 31);
    for (std::size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<std::byte>((i * 37 + 19) % 251);
    const auto payload_hash = Hash(payload);
    auto lease = std::make_shared<t::WindowsImageLease>(image.wstring());
    const auto identity = lease->Identity();
    auto source = std::make_shared<t::OwnedEncryptedImageSource>(lease, base, container_size);
    const std::weak_ptr<t::WindowsImageLease> lease_watch = lease;
    const std::weak_ptr<t::OwnedEncryptedImageSource> source_watch = source;
    auto session = Unlock(source, password); c::EncryptedReadError read_error;
    auto context = session->CreateMetadataReadContext(read_error); std::string error;
    const auto observe = [&] { return OwnerCounts{lease_watch.use_count(), source_watch.use_count(),
        session ? 1u : 0u, context ? 1u : 0u}; };
    auto current = c::LoadAppleCheckpointView(*source, 0, container_size, error, *context);
    Check(static_cast<bool>(current), "R2OriginalCheckpoint");
    const auto binding = Binding(source->SourceIdentity() + ":dfvfs:20480:4153344:" + current->container.superblock.uuid_hex);
    auto original_protection = Protection(directory, binding, "original");
    auto witness_protection = Protection(directory, binding, "witness");
    Check(fs::create_directory(original_protection.key_directory) && fs::create_directory(witness_protection.key_directory), "R2SeparateEpochRoots");
    Journal::Options options;
    options.container_bytes = container_size; options.container_uuid = current->container.superblock.uuid_hex;
    options.preimage_source_identity = source->SourceIdentity();
    BindSelectedVolume(options, *current);
    options.witness = {directory / "publication.wal", "encrypted-publication-witness", 64ull << 20, witness_protection};
    std::map<std::uint64_t, Fact> before;
    std::vector<c::EncryptedFileInfo> files; std::vector<std::byte> original, expected;
    Check(session->ListFiles(files) == c::EncryptedReadError::None, "R2OriginalInventory");
    for (const auto& file : files) {
        Fact fact; std::vector<std::byte> bytes;
        Check(session->GetMetadata(file.inode_id, fact.metadata) == c::EncryptedReadError::None &&
            session->ReadFile(file.inode_id, 0, static_cast<std::size_t>(file.size), bytes) == c::EncryptedReadError::None,
            "R2OriginalNativeBytes");
        fact.hash = Hash(bytes); before.emplace(file.inode_id, fact);
        if (file.inode_id == inode) original = bytes;
        SecureZeroMemory(bytes.data(), bytes.size());
    }
    Check(original.size() == 22 && before.size() == 6, "R2PinnedFixtureInventory");
    expected = original; expected.resize(static_cast<std::size_t>((std::max)(std::uint64_t{22}, offset + payload.size())));
    std::copy(payload.begin(), payload.end(), expected.begin() + offset);
    auto expected_hash = Hash(expected);
    auto expected_size = expected.size();
    auto tx = OpenTx(directory / "original.wal", original_protection);
    Spool::Options spool_options;
    std::uint64_t accepted = 0;
    const auto spool_generation = mode == L"write-64k-spool" ? 1 : current->container.superblock.xid + (bad_generation ? 1 : 0);
    if (spool_payload) {
        spool_options.root = directory / "payload";
        spool_options.volume_identity = Tx::WideToUtf8(std::wstring(volume));
        spool_options.protected_persistence = true; spool_options.protected_binding = binding;
        spool_options.protected_key_directory = directory / "payload-keys";
        spool_options.durable_flush_bytes = spool_options.durable_flush_appends = 0;
        Check(fs::create_directory(spool_options.root) && fs::create_directory(spool_options.protected_key_directory),
            "R2SeparateProtectedPayloadRoots");
        Check(tx->Begin(), "R2BeginProtectedSpoolWrite");
        {
            Spool spool(spool_options); Spool::AppendResult reference;
            SetLastError(ERROR_SUCCESS);
            const auto status = spool.AppendWithStatus({spool_options.volume_identity, inode, spool_generation, offset,
                tx->NextMutationSequence(), payload}, &reference);
            const auto append_error = GetLastError();
            if (status != Spool::AppendStatus::Succeeded) std::cerr << "ProtectedSpoolAppendFailure status="
                << static_cast<unsigned>(status) << " win32=" << append_error << '\n';
            Check(status == Spool::AppendStatus::Succeeded, "R2AppendProtected64KiBPayload");
            Check(spool.FlushPayloadBytes(), "R2ProtectedPayloadDurableBeforeOriginalAcceptance");
            Tx::MutationIntent mutation;
            mutation.kind = Tx::MutationKind::Write; mutation.path = L"\\journal-image-test";
            mutation.object_id = inode; mutation.generation = reference.generation;
            mutation.offset = offset; mutation.length = payload.size(); mutation.wal_sequence = reference.wal_sequence;
            mutation.payload_spool_offset = reference.spool_offset; mutation.payload_length = reference.payload_length;
            mutation.payload_checksum = reference.payload_sha256;
            Check(tx->RecordMutation(mutation) && tx->Accept(current->container.superblock.xid), "R2AcceptOriginalProtectedSpoolReference");
            Check(!tx->CanFinalizeWithoutPayloadSpoolFlush(), "R2ExternalPayloadNeedsSeparateDurabilityProof");
            accepted = tx->Watermarks().accepted_sequence;
        }
        tx.reset(); tx = OpenTx(directory / "original.wal", original_protection);
    } else accepted = Accept(*tx, current->container.superblock.xid, false, false, payload, offset);
    std::vector<Tx::AcceptedTransaction> accepted_rows;
    Check(tx->LoadUnappliedAcceptedTransactions(accepted_rows) && accepted_rows.size() == 1 && accepted_rows[0].mutations.size() == 1,
        "R2OriginalAcceptedWrite");
    const auto transaction = accepted_rows[0].transaction_id;
    const auto& intent = accepted_rows[0].mutations[0];
    Check(intent.operation == Wal::OperationKind::Write && intent.object_id == inode && intent.logical_offset == offset &&
        intent.logical_length == payload.size() && intent.payload_sha256 == payload_hash, "R2OriginalExactWriteIntent");
    if (spool_payload) {
        Check(intent.inline_payload.empty() && intent.payload_length == payload.size() && intent.payload_spool_id != 0,
            "R2OriginalAuthenticatedExternalPayloadReference");
        Check(intent.parent_object_id == spool_generation, "OriginalSpoolGenerationRetainedExactly");
        Spool::PersistedRangeReference reference{spool_options.volume_identity, intent.object_id, intent.parent_object_id,
            intent.logical_offset, intent.payload_length, intent.payload_offset, intent.payload_spool_id, intent.payload_sha256};
        Spool spool(spool_options); std::vector<std::byte> recovered;
        Check(spool.RecoveryRequired() && !spool.ReadPersistedRange(reference, recovered) && recovered.empty(),
            "R2UnprovedAdvisoryPayloadIndexRefuses");
        Check(spool.RebuildIndexFromReferences(std::span(&reference, 1), 0) && spool.ReadPersistedRange(reference, recovered) &&
            recovered == payload, "R2FreshPayloadOwnerRecoversExactOriginalAcceptedBytes");
        SecureZeroMemory(recovered.data(), recovered.size());
    }
    c::EncryptedMutationRequest request;
    request.kind = c::EncryptedMutationKind::Write; request.inode = inode; request.offset = offset; request.data = payload;
    auto prepared = session->PrepareMutation(*source, current->container.superblock.xid, request, error);
    Check(static_cast<bool>(prepared), ("R2PrepareWrite:" + error).c_str());
    Check(prepared->IntentKind() == c::EncryptedMutationKind::Write && prepared->RequestedInode() == inode &&
        prepared->RequestedOffset() == offset && prepared->ReplacementLength() == payload.size() &&
        prepared->ReplacementSha256() == payload_hash && prepared->ResultSize() == expected_size &&
        prepared->RequiredCheckpointXids() == std::vector<std::uint64_t>{current->container.superblock.xid}, "R2PrivateCanonicalWriteCapability");
    const auto plan = prepared->Publication(); const auto baseline_image = Hash(Read(image));
    auto journal = std::make_unique<Journal>(options);
    const bool staged = journal->Stage(*tx, accepted, *prepared, error);
    const auto stage_error = error;
    Check(staged != bad_generation, ("R2StageWrite:" + error).c_str());
    Check(Hash(Read(image)) == baseline_image && tx->Watermarks().apfs_durable_sequence == 0, "R2StageHasNoImageWrite");
    journal.reset();
    if (staged) VerifyWitness(options, plan, accepted, transaction, payload_hash, offset, payload.size(), prepared.get());
    else {
        Check(error == "EncryptedPublicationAcceptedIntentMismatch" && !fs::exists(options.witness.path), "WrongNonzeroSpoolGenerationRefusesBeforeWitnessWrites");
        expected = original; expected_size = original.size(); expected_hash = Hash(original);
    }
    session->Close(); context.reset(); session.reset(); source.reset(); lease.reset(); prepared.reset(); tx.reset();
    std::size_t writes = 0, recovery_writes = 0, original_flushes = 0, witness_flushes = 0;
    tx = OpenTx(directory / "original.wal", original_protection);
    tx->SetJournalFaultInjectionHook([&](std::string_view stage) { if (stage == "durable-flush") ++original_flushes; return false; });
    journal = std::make_unique<Journal>(options);
    WitnessFault(*journal, [&](std::string_view stage) { if (stage == "durable-flush") ++witness_flushes; return false; });
    {
        Target target(image, identity, true, binding, observe);
        target.before_write = [&] { Check(original_flushes && witness_flushes, "R2BothJournalBarriersBeforeImageWrite"); };
        const bool published = journal->PublishOrRecover(*tx, accepted, target, error);
        Check(published != bad_generation, ("R2PublishWrite:" + error).c_str());
        if (bad_generation) Check(target.attempts == 0 && target.writes == 0 && target.flushes == 0, "WrongSpoolGenerationRefusesBeforeImageWritesOrFlush");
        else VerifyPlan(target, plan);
        writes = target.writes;
    }
    journal.reset(); tx.reset();
    tx = OpenTx(directory / "original.wal", original_protection);
    Check(tx->Watermarks().apfs_durable_sequence == (bad_generation ? 0 : accepted) && tx->Watermarks().cleanup_sequence == 0 &&
        tx->HasUnappliedAcceptedWork() == bad_generation, "R2OriginalRestartDurable");
    journal = std::make_unique<Journal>(options);
    {
        Target target(image, identity, false, binding, observe);
        const bool recovered = journal->PublishOrRecover(*tx, accepted, target, error);
        Check(recovered != bad_generation && target.writes == 0 && target.flushes == (bad_generation ? 0 : 1), ("R2FreshPostSwitchRecovery:" + error).c_str());
        if (!bad_generation) VerifyPlan(target, plan);
        recovery_writes = target.writes;
    }
    journal.reset(); tx.reset();
    auto fresh_lease = std::make_shared<t::WindowsImageLease>(image.wstring());
    auto fresh_source = std::make_shared<t::OwnedEncryptedImageSource>(fresh_lease, base, container_size);
    auto fresh = Unlock(fresh_source, password); std::vector<c::EncryptedFileInfo> after_files;
    Check(fresh->ListFiles(after_files) == c::EncryptedReadError::None && after_files.size() == before.size(), "R2FreshInventory");
    for (const auto& file : after_files) {
        auto fact = before.at(file.inode_id); c::EncryptedNodeInfo metadata; std::vector<std::byte> bytes;
        Check(fresh->GetMetadata(file.inode_id, metadata) == c::EncryptedReadError::None &&
            fresh->ReadFile(file.inode_id, 0, static_cast<std::size_t>(file.size), bytes) == c::EncryptedReadError::None, "R2FreshNativeRead");
        if (file.inode_id == inode) {
            fact.metadata.size = expected_size; fact.metadata.allocated_size = ((expected_size + 4095) / 4096) * 4096;
            Check(bytes == expected && metadata.size == expected_size, "R2ExpectedEofGapAndExactBytes");
        }
        Check(SameMetadata(metadata, fact.metadata) && Hash(bytes) == (file.inode_id == inode ? expected_hash : fact.hash), "R2TargetMetadataAndUnchangedPeers");
        SecureZeroMemory(bytes.data(), bytes.size());
    }
    auto fresh_context = fresh->CreateMetadataReadContext(read_error);
    auto after = c::LoadAppleCheckpointView(*fresh_source, 0, container_size, error, *fresh_context);
    Check(after && after->container.superblock.xid == (bad_generation ? plan.expected_checkpoint_xid : plan.transaction_xid), "R2FreshCanonicalCheckpoint");
    std::cout << "{\"passed\":true,\"checks\":" << checks << ",\"r2Write\":true,\"staged\":" << (staged ? "true" : "false")
        << ",\"refused\":" << (bad_generation ? "true" : "false") << ",\"expectedNew\":" << (bad_generation ? "false" : "true")
        << ",\"bootstrapPublished\":false,\"corruptionInjected\":false,\"exactWitness\":" << (staged ? "true" : "false") << ",\"freshNative\":true,\"originalRestart\":true,"
        "\"writeOffset\":" << offset << ",\"payloadLength\":" << payload.size() << ",\"expectedEof\":" << expected_size
        << ",\"payloadSha256\":" << std::quoted(Hex(payload_hash)) << ",\"originalTargetHex\":"
        << std::quoted(Hex(std::span(reinterpret_cast<const std::uint8_t*>(original.data()), original.size())))
        << ",\"protectedSpoolPayload\":" << (spool_payload ? "true" : "false")
        << ",\"spoolGeneration\":" << (spool_payload ? spool_generation : 0) << ",\"preimageCheckpoint\":" << plan.expected_checkpoint_xid
        << ",\"stageError\":" << std::quoted(stage_error) << ",\"baselineImageSha256\":" << std::quoted(Hex(baseline_image))
        << ",\"firstWrites\":" << writes << ",\"recoveryWrites\":" << recovery_writes << ",\"acceptedSequence\":" << accepted
        << ",\"switchBlock\":" << plan.superblock_write.physical_block << ",\"files\":[";
    bool first = true;
    for (const auto& [id, fact] : before) {
        if (!first) std::cout << ','; first = false;
        std::cout << "{\"inode\":" << id << ",\"size\":" << (id == inode ? expected_size : fact.metadata.size)
            << ",\"expectedSha256\":" << std::quoted(Hex(id == inode ? expected_hash : fact.hash)) << '}';
    }
    std::cout << "],\"plannedBlocks\":["; first = true;
    auto emit = [&](const auto& row) { if (!first) std::cout << ','; first = false;
        std::cout << "{\"block\":" << row.physical_block << ",\"sha256\":" << std::quoted(Hex(Hash(row.bytes))) << '}'; };
    for (const auto& row : plan.before_superblock_writes) emit(row); emit(plan.superblock_write);
    std::cout << "],\"bootstrapBlocks\":[],\"injectedBlocks\":[],\"acquisitions\":"; EmitAcquisitions(std::cout); std::cout << "}\n";
    SecureZeroMemory(payload.data(), payload.size()); SecureZeroMemory(original.data(), original.size());
    SecureZeroMemory(expected.data(), expected.size()); return 0;
}
}

int wmain(int argc, wchar_t** argv)
{
    try {
        Check(argc == 4 || argc == 5, "ArgumentsImageNewCaseDirectoryMode");
        if (argc == 5) { Check(std::wstring_view(argv[4]) == L"--retry-sharing", "KnownAcquisitionOption"); retry_sharing = true; }
        const fs::path image = fs::absolute(argv[1]).lexically_normal();
        const fs::path directory = fs::absolute(argv[2]).lexically_normal();
        const std::wstring mode = argv[3];
        const std::vector<std::wstring> modes{L"commit", L"before-apple-device-write", L"mid-data-writes",
            L"before-apple-checkpoint-switch", L"before-apple-final-flush", L"lost-watermark",
            L"bad-target-binding", L"bad-tx-binding", L"wrong-sequence", L"wrong-original",
            L"tamper-witness", L"stage-wrong-sequence", L"stage-wrong-intent", L"stage-wrong-xid",
            L"deferred-commit", L"deferred-original-flush-failure", L"reopened-original-flush-failure",
            L"reopened-witness-flush-failure", L"omitted-old-pin", L"torn-nxsb",
            L"post-switch-guard-corruption", L"collateral-at-flush", L"capacity-record-limit",
            L"capacity-byte-limit", L"capacity-read-byte-limit", L"capacity-allocation-limit", L"capacity-exact",
            L"watermark-flush-failure", L"gap-write", L"multi-block-write", L"write-64k", L"write-64k-spool", L"write-64k-spool-xid", L"write-64k-spool-wrong-generation",
            L"typed-create", L"typed-create-empty", L"typed-create-special", L"typed-rename-special", L"typed-resize-grow", L"typed-resize-shrink", L"typed-resize-zero",
            L"typed-rename", L"typed-move", L"typed-unlink", L"typed-write", L"typed-create-recover",
            L"typed-resize-grow-recover", L"typed-rename-recover", L"typed-unlink-recover", L"typed-move-torn-switch",
            L"typed-rename-watermark", L"typed-create-bad-mode", L"typed-create-bad-name", L"typed-create-bad-parent",
            L"typed-create-bad-op", L"typed-create-bad-flag", L"typed-create-bad-volume", L"typed-move-bad-volume-uuid",
            L"typed-create-reopen-bad-volume", L"typed-move-reopen-bad-volume-uuid",
            L"typed-rename-bad-name", L"typed-rename-bad-destination-name", L"typed-move-bad-destination-parent",
            L"typed-unlink-bad-parent", L"typed-unlink-bad-secondary", L"typed-resize-grow-bad-eof",
            L"typed-resize-grow-bad-op", L"typed-resize-grow-bad-hash", L"typed-write-bad-parent",
            L"typed-write-bad-flag", L"typed-write-bad-secondary", L"typed-write-legacy-v1", L"typed-write-inline-xid", L"sequence-first", L"sequence-second"};
        Check(std::find(modes.begin(), modes.end(), mode) != modes.end(), "KnownCase");
        Check(image.wstring().starts_with(private_prefix) && directory.wstring().starts_with(private_prefix), "PrivateDPaths");
        Check(mode == L"sequence-second" ? fs::is_directory(directory) : fs::create_directory(directory), "FreshPrivateCaseDirectoryOrExactContinuation");
        const auto input = GetStdHandle(STD_INPUT_HANDLE); SetStdHandle(STD_INPUT_HANDLE, nullptr);
        const std::atomic<bool> cancelled{false};
        auto credential = t::ReceiveCredential(input, std::chrono::milliseconds(5000), cancelled);
        Check(static_cast<bool>(credential), "ProtectedParentPipeCredential");
        if (mode == L"sequence-first" || mode == L"sequence-second")
            return SequentialPublication(image, directory, credential.bytes.Bytes(), mode == L"sequence-second");
        if (mode.starts_with(L"typed-")) return JournaledNamespace(image, directory, credential.bytes.Bytes(), mode);
        if (mode == L"gap-write" || mode == L"multi-block-write" || mode == L"write-64k" || mode.starts_with(L"write-64k-spool"))
            return JournaledWrite(image, directory, credential.bytes.Bytes(), mode);
        const bool omitted_pin = mode == L"omitted-old-pin";
        const bool deferred = mode == L"deferred-commit" || mode == L"deferred-original-flush-failure";
        const bool post_corruption = mode == L"post-switch-guard-corruption";
        const bool collateral_corruption = mode == L"collateral-at-flush";
        const bool corruption = post_corruption || collateral_corruption;
        const bool capacity_case = mode.starts_with(L"capacity-");
        const bool capacity_refusal = capacity_case && mode != L"capacity-exact";
        const auto bootstrap = omitted_pin ? PublishUncleanedPredecessor(image, directory, credential.bytes.Bytes()) : BootstrapResult{};
        auto lease = std::make_shared<t::WindowsImageLease>(image.wstring());
        const auto identity = lease->Identity();
        auto source = std::make_shared<t::OwnedEncryptedImageSource>(lease, base, container_size);
        const std::weak_ptr<t::WindowsImageLease> lease_watch = lease;
        const std::weak_ptr<t::OwnedEncryptedImageSource> source_watch = source;
        const auto preimage_identity = source->SourceIdentity();
        auto session = Unlock(source, credential.bytes.Bytes());
        c::EncryptedReadError read_error;
        auto context = session->CreateMetadataReadContext(read_error); std::string error;
        const auto observe = [&] { return OwnerCounts{lease_watch.use_count(), source_watch.use_count(),
            session ? 1u : 0u, context ? 1u : 0u}; };
        auto current = c::LoadAppleCheckpointView(*source, 0, container_size, error, *context);
        Check(current && current->container.superblock.block_count == 1014, "ActualContainerCheckpoint");
        const auto old_xid = current->container.superblock.xid;
        const auto source_binding = omitted_pin ? bootstrap.binding : Binding(preimage_identity + ":dfvfs:20480:4153344:" + current->container.superblock.uuid_hex);
        auto original_protection = Protection(directory, source_binding, "original");
        auto witness_protection = Protection(directory, source_binding, "witness");
        Check((omitted_pin ? fs::is_directory(original_protection.key_directory) : fs::create_directory(original_protection.key_directory)) &&
            fs::create_directory(witness_protection.key_directory), "SeparateProtectedEpochRoots");
        Journal::Options options;
        options.container_bytes = container_size; options.container_uuid = current->container.superblock.uuid_hex;
        options.preimage_source_identity = preimage_identity;
        BindSelectedVolume(options, *current);
        options.witness = {directory / "publication.wal", "encrypted-publication-witness", 64ull << 20, witness_protection};
        auto tx = OpenTx(directory / "original.wal", original_protection);
        const auto previous_durable = tx->Watermarks().apfs_durable_sequence;
        const auto accepted = Accept(*tx, mode == L"stage-wrong-xid" ? old_xid + 1 : old_xid,
            mode == L"stage-wrong-intent", deferred);
        std::vector<Tx::AcceptedTransaction> accepted_rows;
        Check(tx->LoadUnappliedAcceptedTransactions(accepted_rows) && accepted_rows.size() == 1 &&
            accepted_rows.front().mutations.size() == 1, "OriginalAcceptedBoundaryLoaded");
        const auto accepted_transaction = accepted_rows.front().transaction_id;
        std::map<std::uint64_t, Fact> before;
        std::array<std::uint8_t, 32> expected_hash{};
        std::vector<c::EncryptedFileInfo> files;
        Check(session->ListFiles(files) == c::EncryptedReadError::None, "ActualFileInventory");
        for (const auto& file : files) {
            Fact fact; std::vector<std::byte> bytes;
            Check(session->GetMetadata(file.inode_id, fact.metadata) == c::EncryptedReadError::None &&
                session->ReadFile(file.inode_id, 0, static_cast<std::size_t>(file.size), bytes) == c::EncryptedReadError::None, "ActualBaselineRead");
            fact.hash = Hash(bytes); before.emplace(file.inode_id, fact);
            if (file.inode_id == inode) {
                Check(bytes.size() == 22 && patch_offset + patch.size() <= bytes.size(), "AuthenticTargetBounds");
                auto replacement = std::as_bytes(std::span(patch));
                std::copy(replacement.begin(), replacement.end(), bytes.begin() + patch_offset); expected_hash = Hash(bytes);
            }
            SecureZeroMemory(bytes.data(), bytes.size());
        }
        Check(before.contains(inode) && before.size() > 1, "TargetAndUnchangedPeers");
        auto prepared = session->PrepareCowOverwrite(*source, old_xid, inode, patch_offset, std::as_bytes(std::span(patch)), error);
        Check(static_cast<bool>(prepared), "ActualEncryptedCowPrepared");
        Check(prepared->RequestedInode() == inode && prepared->RequestedOffset() == patch_offset &&
            prepared->ReplacementLength() == patch.size() && prepared->ReplacementSha256() == Hash(std::as_bytes(std::span(patch))), "PrivateIntentGetters");
        auto plan = prepared->Publication();
        Check(plan.before_superblock_writes.size() > 1 && !plan.fusion_tier2_anchor_write, "BoundedSingleStorePlan");
        const auto new_data_block = prepared->NewPhysicalBlock();
        const auto old_data_block = prepared->OldPhysicalBlock();
        const auto data_write = std::find_if(plan.before_superblock_writes.begin(), plan.before_superblock_writes.end(),
            [&](const auto& write) { return write.physical_block == new_data_block; });
        Check(data_write != plan.before_superblock_writes.end(), "PrivatelyPreparedDataWriteInPublication");
        const auto data_prefix = static_cast<std::size_t>(std::distance(plan.before_superblock_writes.begin(), data_write)) + 1;
        Check(data_prefix < plan.before_superblock_writes.size(), "DataCutHasFollowingActualWrite");
        if (omitted_pin) {
            std::vector<std::uint64_t> pins;
            Check(previous_durable > 0 && tx->LoadRequiredCheckpointXidsSinceCleanup(pins, &error) &&
                std::find(pins.begin(), pins.end(), old_xid - 1) != pins.end(), "ActualUncleanedOlderPinPresent");
            Check(prepared->RequiredGenerationsProved() == 1, "SecondCapabilityOmitsOlderPinProof");
        }
        WitnessCapacity capacity;
        if (capacity_case) {
            capacity = ExpectedCapacity(options, plan, accepted, accepted_transaction, *prepared);
            if (mode == L"capacity-record-limit") options.witness.protected_persistence->read_limits.records = capacity.records - 1;
            if (mode == L"capacity-byte-limit") options.witness.max_bytes = capacity.admission_bytes - 1;
            if (mode == L"capacity-read-byte-limit") {
                options.witness.max_bytes = capacity.admission_bytes - 1;
                options.witness.protected_persistence->read_limits.bytes = capacity.admission_bytes - 1;
            }
            if (mode == L"capacity-allocation-limit") options.witness.protected_persistence->max_allocation_bytes = capacity.allocation - 1;
            if (mode == L"capacity-exact") {
                options.witness.max_bytes = capacity.admission_bytes;
                options.witness.protected_persistence->read_limits.bytes = capacity.admission_bytes;
                options.witness.protected_persistence->read_limits.records = capacity.records;
            }
        }
        auto journal = std::make_unique<Journal>(options);
        const auto image_before = Hash(Read(image));
        const bool stage_refusal = mode.starts_with(L"stage-") || omitted_pin || capacity_refusal;
        const bool staged = journal->Stage(*tx, mode == L"stage-wrong-sequence" ? accepted + 1 : accepted, *prepared, error);
        if (!staged && !stage_refusal) throw std::runtime_error("Stage:" + error);
        Check(staged != stage_refusal, ("StageMatchesOriginalAcceptedIntent:" + error).c_str());
        const auto stage_error = error;
        if (capacity_refusal) {
            const auto expected_error = mode == L"capacity-record-limit" ? "EncryptedPublicationWitnessRecordCapacity" :
                mode == L"capacity-allocation-limit" ? "EncryptedPublicationWitnessAllocationCapacity" : "EncryptedPublicationWitnessByteCapacity";
            Check(error == expected_error && !fs::exists(options.witness.path), ("WholeGroupCapacityRefusesBeforeWitnessMaterialization:" + error).c_str());
        }
        Check(Hash(Read(image)) == image_before, "StagePerformsNoImageWrites");
        Check(tx->Watermarks().apfs_durable_sequence == previous_durable, "StageDoesNotAdvanceOriginalWatermark");
        journal.reset();
        if (staged) VerifyWitness(options, plan, accepted, accepted_transaction, prepared->ReplacementSha256(), patch_offset, patch.size(), prepared.get());
        else Check(!fs::exists(options.witness.path) || fs::file_size(options.witness.path) == 0, "RefusedStageHasNoWitness");
        if (mode == L"capacity-exact") Check(fs::file_size(options.witness.path) == capacity.bytes, "ExactSufficientEncodedByteBoundary");
        const HANDLE denied = CreateFileW(image.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (denied != INVALID_HANDLE_VALUE) CloseHandle(denied);
        Check(denied == INVALID_HANDLE_VALUE, "ImmutableLeaseExcludesPublication");
        session->Close(); context.reset(); session.reset(); source.reset(); lease.reset(); prepared.reset();
        if (!deferred) tx.reset();
        const auto original_before_publish = Hash(Read(directory / "original.wal"));
        const bool refusal = stage_refusal || mode == L"bad-target-binding" || mode == L"bad-tx-binding" ||
            mode == L"wrong-sequence" || mode == L"wrong-original" || mode == L"tamper-witness" ||
            mode == L"deferred-original-flush-failure" || mode == L"reopened-original-flush-failure" ||
            mode == L"reopened-witness-flush-failure" || corruption;
        const bool expected_new = !refusal || corruption;
        const bool first_success = mode == L"commit" || mode == L"deferred-commit" || mode == L"capacity-exact";
        std::size_t first_writes = 0, first_flushes = 0, recovery_writes = 0, recovery_flushes = 0;
        bool cut_hit = false, watermark_fault_hit = false, original_flush_fault_hit = false, witness_flush_fault_hit = false;
        bool image_publication_flushed = false, watermark_flush_fault_hit = false;
        bool readable_watermark_before_recovery = false;
        std::size_t original_flush_events = 0, witness_flush_events = 0, torn_bytes = 0;
        std::size_t recovery_original_flush_events = 0, recovery_witness_flush_events = 0;
        std::vector<std::uint64_t> injected_blocks;
        std::string first_error, recovery_error;
        if (!stage_refusal) {
            if (mode == L"tamper-witness") Tamper(options.witness.path);
            auto binding = source_binding;
            if (mode == L"bad-target-binding") binding.front() ^= std::byte{1};
            auto tx_protection = original_protection;
            if (mode == L"bad-tx-binding" || mode == L"wrong-original") {
                if (mode == L"bad-tx-binding") tx_protection.source_binding.front() ^= std::byte{1};
                tx = OpenTx(directory / "other-original.wal", tx_protection);
                Check(Accept(*tx, old_xid, mode == L"wrong-original") == accepted, "OtherOriginalSameAcceptedSequence");
            } else if (!tx) tx = OpenTx(directory / "original.wal", original_protection);
            tx->SetJournalFaultInjectionHook([&](std::string_view stage) {
                if (stage == "durable-flush") {
                    ++original_flush_events;
                    if (mode == L"watermark-flush-failure" && image_publication_flushed) {
                        watermark_flush_fault_hit = true; return true;
                    }
                    if (mode == L"deferred-original-flush-failure" || mode == L"reopened-original-flush-failure") {
                        original_flush_fault_hit = true; return true;
                    }
                }
                if (stage == "protected-before-write" && mode == L"lost-watermark") {
                    watermark_fault_hit = true; return true;
                }
                return false;
            });
            journal = std::make_unique<Journal>(options);
            WitnessFault(*journal, [&](std::string_view stage) {
                if (stage == "durable-flush") {
                    ++witness_flush_events;
                    if (mode == L"reopened-witness-flush-failure") { witness_flush_fault_hit = true; return true; }
                }
                return false;
            });
            {
                Target target(image, identity, true, binding, observe);
                Check(ObserveCheckpoint(target) == old_xid, "ExclusiveHandoffStillHasExactOriginalCheckpoint");
                target.before_write = [&] {
                    Check(original_flush_events > 0 && witness_flush_events > 0, "BothActualWalFlushBarriersBeforeFirstImageWrite");
                };
                target.after_flush = [&](std::size_t flush) {
                    if (flush == 3) image_publication_flushed = true;
                };
                // A complete ciphertext block persists, then the next real target write fails.
                if (mode == L"mid-data-writes") target.fail_after = data_prefix;
                if (mode == L"torn-nxsb") target.tear_block = plan.superblock_write.physical_block;
                if (collateral_corruption) {
                    target.corrupt_on_flush = UnchangedGuard(plan, old_data_block);
                    target.corrupt_flush_number = 3;
                }
                const bool result = journal->PublishOrRecover(*tx, mode == L"wrong-sequence" ? accepted + 1 : accepted,
                    target, error, [&](std::string_view stage) {
                        const std::wstring wide(stage.begin(), stage.end());
                        if (post_corruption && stage == "before-apple-final-flush") { cut_hit = true; return false; }
                        if (wide == mode) { cut_hit = true; return false; } return true;
                    });
                first_error = error;
                first_writes = target.writes; first_flushes = target.flushes;
                torn_bytes = target.torn_bytes; injected_blocks = target.injected_blocks;
                cut_hit = cut_hit || target.cut_hit;
                const auto diagnosis = !result && first_success ? DiagnoseWholeBlockAdapter(target) : std::string{};
                Check(result == first_success, ("FirstPublicationExpectedOutcome:" + error + diagnosis).c_str());
                if (refusal && !corruption) Check(target.writes == 0 && target.attempts == 0 && target.flushes == 0, "RefusalBeforeAnyImageWriteOrFlush");
                if (original_flush_fault_hit) Check(!tx->RecoveryStateValid() && error == "EncryptedPublicationOriginalAcceptanceFlushFailed",
                    "OriginalWalBarrierFailurePoisonsOwner");
                if (mode == L"reopened-witness-flush-failure") Check(witness_flush_fault_hit &&
                    original_flush_events > 0 && error == "EncryptedPublicationWitnessFlushFailed", "ReopenedWitnessActualFlushFaultReached");
                if (mode == L"deferred-original-flush-failure" || mode == L"reopened-original-flush-failure")
                    Check(original_flush_fault_hit, "OriginalActualFlushFaultReached");
                if (mode == L"mid-data-writes") {
                    std::vector<std::byte> persisted_data;
                    Check(target.writes == data_prefix && target.attempts == data_prefix + 1 && target.cut_hit &&
                        target.ReadBlock(new_data_block, 4096, persisted_data) && persisted_data == data_write->bytes,
                        "ActualEncryptedDataPersistedBeforeNextWriteCut");
                }
                if (mode == L"torn-nxsb") {
                    std::vector<std::byte> torn;
                    Check(target.torn_bytes == 128 && target.writes == plan.before_superblock_writes.size() &&
                        target.ReadBlock(plan.superblock_write.physical_block, 4096, torn) &&
                        torn != plan.superblock_write.bytes && !c::ParseNxSuperblock(torn), "ActualPartialNxsbInvalidChecksum");
                    Check(ObserveCheckpoint(target) == old_xid, "TornNxsbLeavesOldCheckpointSelected");
                }
                if (collateral_corruption) Check(target.injected_blocks.size() == 1 && target.flushes == 3 &&
                    target.writes == plan.before_superblock_writes.size() + 1 &&
                    tx->Watermarks().apfs_durable_sequence == 0 && error == "EncryptedPublicationDurableBytesMismatch" &&
                    ObserveCheckpoint(target) == plan.transaction_xid, "CollateralWriteAtRecoveryFlushPreventsWatermark");
                if (mode == L"before-apple-device-write") Check(cut_hit && target.writes == 0, "BeforeWriteCutActuallyReached");
                if (mode == L"before-apple-checkpoint-switch") Check(cut_hit && target.writes == plan.before_superblock_writes.size(), "BeforeSwitchCutActuallyReached");
                if (mode == L"before-apple-final-flush") Check(cut_hit && target.writes == plan.before_superblock_writes.size() + 1, "BeforeFinalFlushCutActuallyReached");
                if (mode == L"lost-watermark") {
                    Check(watermark_fault_hit && error == "EncryptedPublicationWatermarkFailed" && target.writes > 0 &&
                        tx->Watermarks().apfs_durable_sequence == 0, "RealOriginalTmWatermarkAppendLost");
                    VerifyPlan(target, plan);
                }
                if (mode == L"watermark-flush-failure") {
                    Check(image_publication_flushed && watermark_flush_fault_hit && target.flushes == 3 &&
                        target.writes == plan.before_superblock_writes.size() + 1 &&
                        error == "EncryptedPublicationWatermarkFailed" && tx->Watermarks().apfs_durable_sequence == 0,
                        "CompleteCheckpointedAppendThenActualOriginalWalFlushFails");
                    VerifyPlan(target, plan);
                }
            }
            journal.reset(); tx.reset();
        }
        if (!refusal || corruption) {
            tx = OpenTx(directory / "original.wal", original_protection);
            Check(tx->Watermarks().accepted_sequence == accepted && tx->Watermarks().apfs_durable_sequence ==
                (first_success || mode == L"watermark-flush-failure" ? accepted : previous_durable), "FreshOriginalBeforeRecoveryWatermarks");
            if (mode == L"watermark-flush-failure") {
                readable_watermark_before_recovery = tx->Watermarks().apfs_durable_sequence == accepted;
                Check(readable_watermark_before_recovery && !tx->HasUnappliedAcceptedWork(), "FreshOwnerReadsCompleteAuthenticatedCheckpointedMarker");
            }
            tx->SetJournalFaultInjectionHook([&](std::string_view stage) {
                if (stage == "durable-flush") ++recovery_original_flush_events;
                return false;
            });
            journal = std::make_unique<Journal>(options);
            WitnessFault(*journal, [&](std::string_view stage) {
                if (stage == "durable-flush") ++recovery_witness_flush_events;
                return false;
            });
            {
                Target target(image, identity, false, source_binding, observe);
                if (post_corruption) {
                    target.InjectCorruption(UnchangedGuard(plan, old_data_block));
                    injected_blocks = target.injected_blocks;
                }
                const bool recovered = journal->PublishOrRecover(*tx, accepted, target, error);
                recovery_error = error;
                Check(recovered != corruption, ("FreshOwnersRecoverExactStagedPublication:" + error).c_str());
                if (corruption) {
                    Check(target.writes == 0 && target.attempts == 0 && target.flushes == 0 &&
                        tx->Watermarks().apfs_durable_sequence == previous_durable, "FreshCorruptedGuardRefusesBeforeWritesOrWatermark");
                    Check(ObserveCheckpoint(target) == plan.transaction_xid, "GuardCorruptionDoesNotMaskPublishedCheckpoint");
                } else VerifyPlan(target, plan);
                recovery_writes = target.writes; recovery_flushes = target.flushes;
                if (first_success || mode == L"lost-watermark" || mode == L"before-apple-final-flush" || mode == L"watermark-flush-failure")
                    Check(target.writes == 0 && target.flushes > 0, "PostSwitchRecoveryFlushesWithoutReplayWrites");
                if (mode == L"watermark-flush-failure") Check(recovery_original_flush_events >= 1 &&
                    recovery_witness_flush_events >= 1 && target.writes == 0 && target.flushes == 1,
                    "ReadableWatermarkStillRequiresBothWalBarriersAndExactImageFlush");
            }
            journal.reset(); tx.reset();
        } else {
            Check(Hash(Read(image)) == image_before, "RefusalLeavesWholeImageUnchanged");
            Check(Hash(Read(directory / "original.wal")) == original_before_publish, "RefusalLeavesOriginalAcceptedWalUnchanged");
        }
        tx = OpenTx(directory / "original.wal", original_protection);
        Check(tx->Watermarks().accepted_sequence == accepted && tx->Watermarks().apfs_durable_sequence == (refusal ? previous_durable : accepted) &&
            tx->Watermarks().cleanup_sequence == 0 && tx->HasUnappliedAcceptedWork() == refusal, "OriginalRestartWatermarksAndPendingWork");
        const auto final_marks = tx->Watermarks();
        tx.reset();
        auto fresh_lease = std::make_shared<t::WindowsImageLease>(image.wstring());
        auto fresh_source = std::make_shared<t::OwnedEncryptedImageSource>(fresh_lease, base, container_size);
        auto fresh = Unlock(fresh_source, credential.bytes.Bytes()); credential.bytes.Clear();
        std::vector<c::EncryptedFileInfo> fresh_files;
        Check(fresh->ListFiles(fresh_files) == c::EncryptedReadError::None && fresh_files.size() == before.size(), "FreshNativeSameInventory");
        for (const auto& file : fresh_files) {
            const auto& fact = before.at(file.inode_id); c::EncryptedNodeInfo metadata; std::vector<std::byte> bytes;
            Check(fresh->GetMetadata(file.inode_id, metadata) == c::EncryptedReadError::None &&
                fresh->ReadFile(file.inode_id, 0, static_cast<std::size_t>(file.size), bytes) == c::EncryptedReadError::None, "FreshNativeActualBytes");
            Check(SameMetadata(metadata, fact.metadata), "FreshNativeUnchangedInodeMetadata");
            Check(Hash(bytes) == (file.inode_id == inode && expected_new ? expected_hash : fact.hash), "FreshNativeExpectedContentAndUnchangedPeers");
            SecureZeroMemory(bytes.data(), bytes.size());
        }
        auto fresh_context = fresh->CreateMetadataReadContext(read_error);
        auto after = c::LoadAppleCheckpointView(*fresh_source, 0, container_size, error, *fresh_context);
        Check(after && after->container.superblock.xid == (expected_new ? plan.transaction_xid : old_xid), "FreshCanonicalCheckpoint");
        std::cout << "{\"passed\":true,\"checks\":" << checks << ",\"staged\":" << (staged ? "true" : "false")
            << ",\"refused\":" << (refusal ? "true" : "false") << ",\"exactWitness\":" << (staged ? "true" : "false")
            << ",\"freshNative\":true,\"originalRestart\":true,\"firstWrites\":" << first_writes
            << ",\"firstFlushes\":" << first_flushes << ",\"recoveryWrites\":" << recovery_writes
            << ",\"recoveryFlushes\":" << recovery_flushes << ",\"cutHit\":" << (cut_hit ? "true" : "false")
            << ",\"watermarkFaultHit\":" << (watermark_fault_hit ? "true" : "false")
            << ",\"watermarkFlushFaultHit\":" << (watermark_flush_fault_hit ? "true" : "false")
            << ",\"readableWatermarkBeforeRecovery\":" << (readable_watermark_before_recovery ? "true" : "false")
            << ",\"recoveryOriginalFlushEvents\":" << recovery_original_flush_events
            << ",\"recoveryWitnessFlushEvents\":" << recovery_witness_flush_events
            << ",\"originalFlushFaultHit\":" << (original_flush_fault_hit ? "true" : "false")
            << ",\"witnessFlushFaultHit\":" << (witness_flush_fault_hit ? "true" : "false")
            << ",\"originalFlushEvents\":" << original_flush_events << ",\"witnessFlushEvents\":" << witness_flush_events
            << ",\"tornBytes\":" << torn_bytes << ",\"expectedNew\":" << (expected_new ? "true" : "false")
            << ",\"acceptedSequence\":" << final_marks.accepted_sequence
            << ",\"previousDurableSequence\":" << previous_durable
            << ",\"finalDurableSequence\":" << final_marks.apfs_durable_sequence
            << ",\"cleanupSequence\":" << final_marks.cleanup_sequence
            << ",\"bootstrapPublished\":" << (omitted_pin ? "true" : "false")
            << ",\"corruptionInjected\":" << (corruption ? "true" : "false")
            << ",\"baselineImageSha256\":" << std::quoted(Hex(image_before))
            << ",\"switchBlock\":" << plan.superblock_write.physical_block
            << ",\"newDataBlock\":" << new_data_block << ",\"dataWritePrefix\":" << data_prefix
            << ",\"capacityRecords\":" << capacity.records << ",\"capacityBytes\":" << capacity.bytes
            << ",\"capacityAdmissionBytes\":" << capacity.admission_bytes
            << ",\"capacityAllocation\":" << capacity.allocation << ",\"stageError\":" << std::quoted(stage_error)
            << ",\"firstError\":" << std::quoted(first_error) << ",\"recoveryError\":" << std::quoted(recovery_error)
            << ",\"checkpoint\":" << after->container.superblock.xid
            << ",\"files\":[";
        bool first = true;
        for (const auto& [id, fact] : before) {
            if (!first) std::cout << ','; first = false;
            std::cout << "{\"inode\":" << id << ",\"size\":" << fact.metadata.size << ",\"expectedSha256\":"
                << std::quoted(Hex(id == inode && expected_new ? expected_hash : fact.hash)) << '}';
        }
        std::cout << "],\"plannedBlocks\":["; first = true;
        auto emit = [&](const auto& row) {
            if (!first) std::cout << ','; first = false;
            std::cout << "{\"block\":" << row.physical_block << ",\"sha256\":" << std::quoted(Hex(Hash(row.bytes))) << '}';
        };
        for (const auto& row : plan.before_superblock_writes) emit(row);
        emit(plan.superblock_write); std::cout << "],\"bootstrapBlocks\":["; first = true;
        for (const auto& row : bootstrap.writes) emit(row);
        std::cout << "],\"injectedBlocks\":["; first = true;
        for (const auto block : injected_blocks) { if (!first) std::cout << ','; first = false; std::cout << block; }
        std::cout << "],\"retrySharingEnabled\":" << (retry_sharing ? "true" : "false") << ",\"acquisitions\":";
        EmitAcquisitions(std::cout); std::cout << "}\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "{\"passed\":false,\"checks\":" << checks << ",\"error\":" << std::quoted(error.what())
            << ",\"retrySharingEnabled\":" << (retry_sharing ? "true" : "false") << ",\"acquisitions\":";
        EmitAcquisitions(std::cerr); std::cerr << "}\n"; return 1;
    }
}
