#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#include "ApfsEncryptedImageWriteSession.h"
#include "PayloadSpool.h"
#include "ApfsFormat.h"
#include "EncryptedReadTransport.h"
#include <algorithm>
#include <chrono>
#include <filesystem>
#include <future>
#include <fstream>
#include <iostream>
#include <map>
#include <stdexcept>
#include <thread>
#undef CreateFile

namespace
{
namespace c = apfsaccess::catalog;
namespace r = apfsaccess::rw;
namespace t = apfsaccess::transport;
namespace fs = std::filesystem;
using Owner = c::ApfsEncryptedImageWriteSession;
using Phase = c::EncryptedImageWritePhase;
using Error = c::EncryptedReadError;
std::size_t checks = 0;
void Check(bool ok, const std::string& why) { ++checks; if (!ok) throw std::runtime_error(why); }
std::array<std::uint8_t, 32> Hash(std::span<const std::byte> bytes)
{
    std::array<std::uint8_t, 32> out{};
    Check(BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0,
        reinterpret_cast<PUCHAR>(const_cast<std::byte*>(bytes.data())), static_cast<ULONG>(bytes.size()),
        out.data(), static_cast<ULONG>(out.size())) >= 0, "Hash");
    return out;
}
std::string Hex(std::span<const std::uint8_t> bytes)
{
    std::string out;
    for (auto b : bytes) { out += "0123456789abcdef"[b >> 4]; out += "0123456789abcdef"[b & 15]; }
    return out;
}
std::array<std::byte, 32> Binding(std::string_view text)
{
    const auto hash = Hash(std::as_bytes(std::span(text)));
    std::array<std::byte, 32> out{};
    std::transform(hash.begin(), hash.end(), out.begin(), [](auto b) { return static_cast<std::byte>(b); });
    return out;
}
bool ExternalOpen(const fs::path& path)
{
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    CloseHandle(file); return true;
}
r::WriteAheadLog::ProtectedPersistence Protection(const fs::path& directory,
    const std::array<std::byte, 32>& binding, std::string_view stream)
{
    auto keys = directory / (std::string(stream) + "-keys");
    fs::create_directories(keys);
    return {keys, binding, Binding(stream), {64ull << 20, 65536}, 256ull << 20};
}
struct Fact { std::uint64_t size; std::array<std::uint8_t, 32> hash; };
std::map<std::uint64_t, Fact> Inventory(c::ApfsEncryptedReadSession& view)
{
    std::vector<c::EncryptedFileInfo> files;
    Check(view.ListFiles(files) == Error::None, "ListFiles");
    std::map<std::uint64_t, Fact> facts;
    for (const auto& file : files)
    {
        std::vector<std::byte> bytes;
        Check(view.ReadFile(file.inode_id, 0, static_cast<std::size_t>(file.size), bytes) == Error::None, "ReadAllFiles");
        facts.emplace(file.inode_id, Fact{file.size, Hash(bytes)});
        SecureZeroMemory(bytes.data(), bytes.size());
    }
    return facts;
}
void TogglePrivateSelectionUuid(const fs::path& image)
{
    std::vector<std::byte> apsb;
    std::uint64_t physical = 0;
    {
        auto lease = std::make_shared<t::WindowsImageLease>(image.wstring());
        t::OwnedEncryptedImageSource source(lease, 20480, 4153344);
        std::string error;
        const auto cp = c::LoadContainerCheckpointView(source, 0, source.SizeBytes(), error);
        const auto volumes = cp ? c::LoadAppleReadOnlyVolumeView(source, *cp, error) : std::nullopt;
        Check(volumes && volumes->volumes.size() == 1, "BindingControlSingleAuthenticVolume");
        physical = volumes->volumes.front().superblock_object.physical_block;
        Check(source.Read(physical * 4096, 4096, apsb), "BindingControlReadApsb");
    }
    // Deliberate metadata-only identity perturbation on a private copy. This is
    // a binding refusal control, never a second-volume unlock/publication claim.
    apsb[0xF0] ^= std::byte{1};
    const auto sum = c::Fletcher64(apsb.data() + 8, apsb.size() - 8);
    Check(sum.has_value(), "BindingControlChecksum");
    for (unsigned i = 0; i != 8; ++i) apsb[i] = static_cast<std::byte>(*sum >> (i * 8));
    Check(c::ParseApsb(apsb).has_value(), "BindingControlStructurallyValidSelection");
    std::fstream stream(image, std::ios::binary | std::ios::in | std::ios::out);
    stream.seekp(static_cast<std::streamoff>(20480 + physical * 4096));
    stream.write(reinterpret_cast<const char*>(apsb.data()), static_cast<std::streamsize>(apsb.size()));
    stream.flush(); Check(static_cast<bool>(stream), "BindingControlWritePrivateApsb");
}
}
int wmain(int argc, wchar_t** argv)
{
    try
    {
        Check(argc == 5, "Arguments:image,journal-directory,count,mode");
        const fs::path image = fs::absolute(argv[1]).lexically_normal();
        const fs::path directory = fs::absolute(argv[2]).lexically_normal();
        const std::wstring mode = argv[4];
        const bool native = mode == L"native-refusal", wrong = mode == L"wrong-password";
        Check(image.wstring().starts_with(L"D:\\ApfsAccessScratch\\WindowsClosure\\encrypted-image-owner-20261016\\") &&
            directory.wstring().starts_with(L"D:\\ApfsAccessScratch\\WindowsClosure\\encrypted-image-owner-20261016\\"), "PrivatePaths");
        const auto count = std::stoul(argv[3]); Check(count <= 64, "BoundedCount");
        const auto inode = native ? 16ULL : 21ULL;
        std::string error; Error read_error{};
        auto owner = Owner::Open({image.wstring(), native ? 0ULL : 20480ULL,
            native ? 134176768ULL : 4153344ULL, 1026}, error);
        Check(static_cast<bool>(owner), "OwnerOpen:" + error);
        const auto identity = owner->SourceIdentity(); const auto binding = owner->SourceBinding();
        const auto initial_xid = owner->CachedStatus().checkpoint_xid;
        Check(!ExternalOpen(image) && !owner->OpenReadView(read_error) && read_error == Error::Closed, "LockedExclusiveOwner");
        std::atomic<bool> cancelled{false};
        auto credential = t::ReceiveCredential(GetStdHandle(STD_INPUT_HANDLE), std::chrono::seconds(5), cancelled);
        SetStdHandle(STD_INPUT_HANDLE, nullptr);
        Check(static_cast<bool>(credential), "CredentialPipe");
        c::PasswordUnlockBudget attempts;
        const bool unlocked = owner->Unlock(credential.bytes, attempts, error);
        credential.bytes.Clear();
        if (wrong)
        {
            Check(!unlocked && owner->CachedStatus().phase == Phase::Locked && !owner->CachedStatus().key_present, "WrongPasswordNoKey");
            owner->Close(); Check(ExternalOpen(image), "WrongPasswordClose");
            std::cout << "{\"status\":\"PASS\",\"refusal\":\"wrong-password\",\"checks\":" << checks << "}\n"; return 0;
        }
        Check(unlocked && owner->CachedStatus().key_present, "Unlock:" + error);
        Check(credential.bytes.Size() == 0 && owner->CachedStatus().phase == Phase::Ready && !ExternalOpen(image), "UnlockedNoPasswordExclusive");
        if (mode == L"selection-binding")
        {
            const auto frame = "apfs-image-writer-binding-v2:" + identity + ":" + owner->ContainerUuid() + ":1026:" + owner->VolumeUuid();
            Check(Binding(frame) == binding, "ExactSelectionBindingFrame");
            const auto original_uuid = owner->VolumeUuid();
            const auto original_container = owner->ContainerUuid();
            auto protection = Protection(directory, binding, "binding-control");
            {
                r::TransactionManager original(L"Conservative");
                Check(original.OpenProtectedJournal((directory / "binding.wal").wstring(), L"owner-binding", protection, error), "BindingStreamOriginalOpen");
                r::TransactionManager::MutationIntent intent;
                intent.kind = r::TransactionManager::MutationKind::Write; intent.path = L"\\binding-control";
                intent.object_id = inode; intent.length = intent.payload_length = 1;
                intent.generation = initial_xid;
                intent.inline_payload = {std::byte{0x41}}; intent.payload_checksum = Hash(intent.inline_payload);
                Check(original.Begin() && original.RecordMutation(intent) && original.Accept(initial_xid), "BindingStreamOriginalAccepted");
            }
            owner->Close(); TogglePrivateSelectionUuid(image);
            auto second = Owner::Open({image.wstring(), 20480, 4153344, 1026}, error);
            Check(second && second->SourceIdentity() == identity && second->ContainerUuid() == original_container &&
                second->VolumeUuid() != original_uuid && second->SourceBinding() != binding, "SameFileTwoObservedSelectionsDifferentBindings");
            Check(second->SourceBinding() == Binding("apfs-image-writer-binding-v2:" + identity + ":" +
                original_container + ":1026:" + second->VolumeUuid()), "SecondExactBindingFrame");
            protection.source_binding = second->SourceBinding();
            {
                r::TransactionManager rejected(L"Conservative");
                Check(!rejected.OpenProtectedJournal((directory / "binding.wal").wstring(), L"owner-binding", protection, error) ||
                    !rejected.RecoveryStateValid(), "ProtectedStreamSelectionMismatchRefused");
            }
            second->Close(); TogglePrivateSelectionUuid(image);
            auto restored = Owner::Open({image.wstring(), 20480, 4153344, 1026}, error);
            Check(restored && restored->SourceBinding() == binding && restored->VolumeUuid() == original_uuid, "RestoredSelectionBindingStable");
            restored->Close();
            Check(!Owner::Open({image.wstring(), 20480, 4153344, 1027}, error), "UnavailableVolumeSelectionRefused");
            std::cout << "{\"status\":\"PASS\",\"refusal\":\"selection-binding\",\"checks\":" << checks
                << ",\"syntheticSelectionControl\":true,\"protectedStreamMismatchRefused\":true}\n";
            return 0;
        }
        auto view = owner->OpenReadView(read_error); auto sibling = owner->OpenReadView(read_error);
        Check(view && sibling, "TwoReadViews");
        auto baseline = Inventory(*view);
        std::vector<std::byte> expected;
        Check(view->ReadFile(inode, 0, static_cast<std::size_t>(baseline.at(inode).size), expected) == Error::None, "ExpectedInitial");
        view->Close(); Check(sibling->ReadFile(inode, 0, 0, expected) == Error::None, "CloseOnlyOwnView");
        Check(sibling->ReadFile(inode, 0, static_cast<std::size_t>(baseline.at(inode).size), expected) == Error::None, "RestoreExpected");
        sibling.reset(); view.reset();
        std::vector<std::shared_ptr<c::ApfsEncryptedReadSession>> held;
        for (unsigned i = 0; i != 4; ++i) { auto v = owner->OpenReadView(read_error); Check(static_cast<bool>(v), "ViewCapacityPositive"); held.push_back(std::move(v)); }
        Check(!owner->OpenReadView(read_error) && read_error == Error::ResourceLimit, "ViewCapacityTruthful");
        held.clear();
        fs::create_directories(directory);
        r::TransactionManager tx(L"Conservative");
        const bool original_open = tx.OpenProtectedJournal((directory / "original.wal").wstring(), L"image-owner-dfvfs",
            Protection(directory, binding, "original"), error);
        Check(original_open, "OriginalJournal:" + error);
        r::EncryptedPublicationJournal::Options options;
        options.container_bytes = owner->CachedStatus().container_bytes; options.container_uuid = owner->ContainerUuid();
        options.preimage_source_identity = identity;
        options.volume_object_id = owner->VolumeObjectId(); options.volume_uuid = owner->VolumeUuid();
        Check(options.volume_object_id == 1026 && options.volume_uuid.size() == 32 &&
            owner->CachedStatus().next_inode_id >= 16, "ObservedVolumeAndNextInode");
        options.witness = {directory / "witness.wal", "image-owner-witness", 64ull << 20, Protection(directory, binding, "witness")};
        auto journal = std::make_unique<r::EncryptedPublicationJournal>(options);
        std::unique_ptr<r::PayloadSpool> spool;
        if (mode == L"spooled")
        {
            r::PayloadSpool::Options spool_options;
            spool_options.root = directory / "payload"; spool_options.volume_identity = "image-owner-dfvfs";
            spool_options.protected_persistence = true; spool_options.protected_binding = binding;
            spool_options.protected_key_directory = directory / "payload-keys";
            spool_options.durable_flush_bytes = spool_options.durable_flush_appends = 0;
            fs::create_directories(spool_options.root); fs::create_directories(spool_options.protected_key_directory);
            spool = std::make_unique<r::PayloadSpool>(spool_options);
        }
        std::uint64_t previous_free = owner->CachedStatus().free_bytes;
        unsigned recovered = 0, liveness = 0, spooled_writes = 0;
        for (unsigned index = 0; index != count; ++index)
        {
            auto old = owner->OpenReadView(read_error); Check(static_cast<bool>(old), "PrecommitReadView");
            std::vector<std::byte> before;
            Check(old->ReadFile(inode, 0, expected.size(), before) == Error::None && before == expected, "OldViewExact");
            const auto xid = owner->CachedStatus().checkpoint_xid;
            const bool spooled = mode == L"spooled";
            const auto write_offset = spooled ? 0ULL : 3ULL;
            std::vector<std::byte> payload(spooled ? 65536 : 7);
            for (unsigned j = 0; j != payload.size(); ++j) payload[j] = static_cast<std::byte>('A' + (index + j) % 26);
            r::TransactionManager::MutationIntent intent;
            intent.kind = r::TransactionManager::MutationKind::Write; intent.path = L"\\image-owner-test";
            intent.object_id = inode; intent.offset = write_offset; intent.length = intent.payload_length = payload.size();
            intent.generation = xid;
            intent.inline_payload.assign(payload.begin(), payload.end()); intent.payload_checksum = Hash(payload);
            const bool resize = mode == L"resize";
            c::EncryptedMutationRequest request;
            request.inode = inode;
            if (resize)
            {
                request.kind = c::EncryptedMutationKind::Resize; request.size = index ? 4099 : 12345;
                intent.kind = r::TransactionManager::MutationKind::SetFileSize;
                intent.generation = 0;
                intent.offset = 0; intent.length = request.size;
                intent.payload_length = 0; intent.inline_payload.clear(); intent.payload_checksum = {};
            }
            else
            {
                request.kind = c::EncryptedMutationKind::Write; request.offset = write_offset; request.data = payload;
            }
            Check(tx.Begin(), "ActualBeginWrite");
            if (spooled)
            {
                r::PayloadSpool::AppendResult reference;
                Check(spool->Append({"image-owner-dfvfs", inode, xid, write_offset,
                    tx.NextMutationSequence(), payload}, &reference) && spool->FlushPayloadBytes(), "ProtectedSpoolDurableBeforeAcceptance");
                intent.inline_payload.clear(); intent.generation = reference.generation;
                intent.wal_sequence = reference.wal_sequence; intent.payload_spool_offset = reference.spool_offset;
                intent.payload_length = reference.payload_length; intent.payload_checksum = reference.payload_sha256;
            }
            Check(tx.RecordMutation(intent) && tx.Accept(xid), "ActualAcceptedWrite");
            const auto sequence = tx.Watermarks().accepted_sequence;
            if (spooled)
            {
                std::vector<r::TransactionManager::AcceptedTransaction> accepted;
                Check(tx.LoadAcceptedTransactionsSinceCleanup(accepted, &error) && accepted.size() == 1 &&
                    accepted.front().mutations.size() == 1, "AcceptedSpoolCensus:" + error);
                const auto& record = accepted.front().mutations.front();
                Check(record.inline_payload.empty() && record.payload_spool_id != 0 &&
                    record.payload_length == payload.size() && record.parent_object_id == xid &&
                    accepted.front().preimage_checkpoint_xid == xid, "ExactPreimageSpoolGeneration");
                ++spooled_writes;
            }
            Check(!owner->CommitAcceptedOverwrite(tx, *journal, sequence, xid + 1, inode, 3, payload, error) &&
                owner->CachedStatus().phase == Phase::Ready, "WrongXidNoWrite");
            bool fault_hit = false; std::thread status_thread;
            std::promise<bool> status_result; auto status_future = status_result.get_future();
            const bool locked_recovery = mode == L"locked-recovery" || mode == L"restart-recovery";
            const bool before_write = mode == L"before-write";
            const bool fault = (mode == L"failure" || mode == L"final-flush" || before_write || locked_recovery) && index == 0;
            auto hook = [&](std::string_view stage) {
                if (stage == "before-apple-device-write")
                {
                    std::vector<std::byte> closed;
                    Check(old->ReadFile(inode, 0, 1, closed) == Error::Closed && closed.empty(), "RevokedBeforeFirstWrite");
                    if (fault && before_write) { fault_hit = true; return false; }
                }
                if (stage == "before-apple-prepublication-flush" && index == 0)
                {
                    status_thread = std::thread([&] {
                        bool good = true;
                        for (unsigned n = 0; n != 10000; ++n) {
                            const auto cached = owner->CachedStatus();
                            good = good && cached.phase == Phase::Publishing && cached.checkpoint_xid == xid &&
                                cached.free_bytes == previous_free && cached.container_bytes == options.container_bytes;
                        }
                        status_result.set_value(good);
                    });
                    const bool ready = status_future.wait_for(std::chrono::seconds(2)) == std::future_status::ready;
                    if (ready && status_future.get()) ++liveness;
                    if (!ready) return false;
                    if (fault && mode != L"final-flush") { fault_hit = true; return false; }
                }
                if (stage == "before-apple-final-flush" && fault && mode == L"final-flush")
                { fault_hit = true; return false; }
                return true;
            };
            const std::array<std::uint64_t, 1> supplied_pins{xid};
            if (resize || spooled || mode == L"generalized")
            {
                const std::array<std::uint64_t, 1> unavailable{xid + 1};
                Check(!owner->CommitAcceptedMutation(tx, *journal, sequence, xid, request, error, unavailable) &&
                    error == "EncryptedCowRequiredGenerationUnavailable" && owner->CachedStatus().phase == Phase::Ready,
                    "ExplicitPinRefusalBeforeStaging:" + error);
            }
            const bool committed = resize || spooled || mode == L"generalized"
                ? owner->CommitAcceptedMutation(tx, *journal, sequence, xid, request, error, supplied_pins, hook)
                : owner->CommitAcceptedOverwrite(tx, *journal, sequence, xid, inode, 3, payload, error, hook);
            if (status_thread.joinable()) status_thread.join();
            if (native)
            {
                Check(!committed && error == "AppleEncryptedVolumeBindingMismatch:retained-xid-6" &&
                    owner->CachedStatus().phase == Phase::Ready && tx.Watermarks().apfs_durable_sequence < sequence, "NativeRollingRefusal:" + error);
                owner->Close(); Check(ExternalOpen(image), "NativeClose");
                std::cout << "{\"status\":\"PASS\",\"refusal\":\"retained-xid-6\",\"checks\":" << checks << "}\n"; return 0;
            }
            if (fault)
            {
                Check(!committed && fault_hit && owner->CachedStatus().recovery_required &&
                    tx.Watermarks().apfs_durable_sequence < sequence, "FailureRequiresRecovery:" + error);
                Check(!owner->OpenReadView(read_error), "NoViewsDuringRecovery");
                if (locked_recovery)
                {
                    Check(count == 1, "OneLockedRecovery");
                    owner->Lock();
                    Check(!owner->CachedStatus().key_present && owner->CachedStatus().recovery_required, "RecoveryLockWipesKey");
                    if (mode == L"restart-recovery")
                    {
                        owner->Close(); Check(ExternalOpen(image), "RecoveryCloseReleases");
                        owner = Owner::Open({image.wstring(), 20480, 4153344, 1026}, error);
                        Check(owner && owner->SourceIdentity() == identity && !owner->CachedStatus().key_present, "RecoveryReopenWithoutPassword");
                    }
                }
                journal.reset(); journal = std::make_unique<r::EncryptedPublicationJournal>(options);
                Check(owner->RecoverAccepted(tx, *journal, sequence, error), "SameHandleRecovery:" + error); ++recovered;
                if (locked_recovery)
                {
                    const auto recovered_status = owner->CachedStatus();
                    Check(recovered_status.phase == Phase::Locked && !recovered_status.key_present &&
                        !recovered_status.recovery_required && recovered_status.checkpoint_xid == xid + 1 &&
                        !recovered_status.free_space_valid && recovered_status.free_bytes == 0, "LockedRecoveryCacheTruthful");
                    Check(!owner->OpenReadView(read_error) && !ExternalOpen(image) && tx.MarkCleanedThrough(sequence), "LockedRecoveryExclusive");
                    std::copy(payload.begin(), payload.end(), expected.begin() + write_offset);
                    baseline.at(inode).hash = Hash(expected);
                    owner->Close(); Check(ExternalOpen(image), "LockedRecoveryClose");
                    std::cout << "{\"status\":\"PASS\",\"commits\":1,\"checks\":" << checks
                        << ",\"recoveries\":1,\"statusCallsWhileBlocked\":" << liveness * 10000 << ",\"files\":[";
                    bool first = true;
                    for (const auto& [id, fact] : baseline) {
                        if (!first) std::cout << ','; first = false;
                        std::cout << "{\"inode\":" << id << ",\"size\":" << fact.size << ",\"sha256\":\"" << Hex(fact.hash) << "\"}";
                    }
                    std::cout << "]}\n";
                    SecureZeroMemory(expected.data(), expected.size());
                    return 0;
                }
            }
            else Check(committed, "Commit:" + error);
            Check(liveness == (before_write ? 0U : 1U) && tx.Watermarks().apfs_durable_sequence == sequence &&
                owner->CachedStatus().checkpoint_xid == xid + 1 && owner->CachedStatus().phase == Phase::Ready, "DurableReboundStatus");
            Check(owner->CachedStatus().free_bytes < previous_free && owner->SourceIdentity() == identity && owner->SourceBinding() == binding,
                "AllocatorChargeStableOwnership");
            previous_free = owner->CachedStatus().free_bytes;
            if (resize) expected.resize(static_cast<std::size_t>(request.size), std::byte{});
            else {
                expected.resize((std::max)(expected.size(), static_cast<std::size_t>(write_offset + payload.size())), std::byte{});
                std::copy(payload.begin(), payload.end(), expected.begin() + write_offset);
            }
            auto fresh = owner->OpenReadView(read_error); Check(static_cast<bool>(fresh), "FreshViewNoKdf");
            const auto facts = Inventory(*fresh);
            Check(facts.size() == baseline.size() && facts.at(inode).hash == Hash(expected), "NewBytesExact");
            for (const auto& [id, fact] : baseline) if (id != inode)
                Check(facts.at(id).size == fact.size && facts.at(id).hash == fact.hash, "OtherFilesUnchanged");
            std::vector<std::byte> closed;
            Check(old->ReadFile(inode, 0, 1, closed) == Error::Closed, "OldViewNeverRebound");
            Check(tx.MarkCleanedThrough(sequence), "CallerOwnsCleanup");
        }
        auto stale = owner->OpenReadView(read_error); Check(static_cast<bool>(stale), "BeforeLockView");
        owner->Lock();
        std::vector<std::byte> closed;
        Check(!owner->CachedStatus().key_present && owner->CachedStatus().phase == Phase::Locked && !ExternalOpen(image) &&
            stale->ReadFile(inode, 0, 1, closed) == Error::Closed && !owner->OpenReadView(read_error), "LockWipesRevokesKeepsHandle");
        owner->Close(); Check(ExternalOpen(image), "CloseReleasesFile");
        auto reopened = Owner::Open({image.wstring(), 20480, 4153344, 1026}, error);
        Check(reopened && reopened->SourceIdentity() == identity && reopened->SourceBinding() == binding &&
            reopened->CachedStatus().phase == Phase::Locked && !reopened->CachedStatus().key_present &&
            reopened->CachedStatus().checkpoint_xid == initial_xid + count, "ReopenSameFileNeedsUnlock");
        reopened->Close();
        std::cout << "{\"status\":\"PASS\",\"checks\":" << checks << ",\"commits\":" << count
            << ",\"initialXid\":" << initial_xid << ",\"finalXid\":" << initial_xid + count
            << ",\"statusCallsWhileBlocked\":" << liveness * 10000 << ",\"recoveries\":" << recovered
            << ",\"spooledWrites\":" << spooled_writes << ",\"files\":[";
        bool first = true;
        for (const auto& [id, fact] : baseline) {
            if (!first) std::cout << ','; first = false;
            std::cout << "{\"inode\":" << id << ",\"size\":" << (id == inode ? expected.size() : fact.size) << ",\"sha256\":\""
                << Hex(id == inode ? Hash(expected) : fact.hash) << "\"}";
        }
        std::cout << "]}\n";
        SecureZeroMemory(expected.data(), expected.size());
        return 0;
    }
    catch (const std::exception& ex) { std::cerr << "ImageOwnerTestFailure:" << ex.what() << '\n'; return 1; }
}
