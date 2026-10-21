#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#undef CreateFile
#include "ApfsEncryptedImageWriteSession.h"
#include "EncryptedReadTransport.h"
#include "PayloadSpool.h"
#include <algorithm>
#include <chrono>
#include <filesystem>
#include <future>
#include <iostream>
#include <stdexcept>
#include <thread>
#undef CreateFile
namespace c = apfsaccess::catalog;
namespace r = apfsaccess::rw;
namespace t = apfsaccess::transport;
namespace fs = std::filesystem;
using Owner = c::ApfsEncryptedImageWriteSession;
using Phase = c::EncryptedImageWritePhase;
using Journal = r::EncryptedPublicationJournal;
unsigned checks = 0;
void Check(bool value, const std::string& error) { ++checks; if (!value) throw std::runtime_error(error); }
struct Bytes
{
    std::vector<std::byte> data;
    ~Bytes() { SecureZeroMemory(data.data(), data.size()); }
};
std::array<std::uint8_t, 32> Hash(std::span<const std::byte> bytes)
{
    std::array<std::uint8_t, 32> result{};
    Check(bytes.size() <= ULONG_MAX && BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0,
        reinterpret_cast<PUCHAR>(const_cast<std::byte*>(bytes.data())), static_cast<ULONG>(bytes.size()),
        result.data(), static_cast<ULONG>(result.size())) >= 0, "Hash");
    return result;
}
std::string Hex(std::span<const std::uint8_t> bytes)
{
    std::string result;
    for (auto b : bytes) { result += "0123456789abcdef"[b >> 4]; result += "0123456789abcdef"[b & 15]; }
    return result;
}
std::array<std::byte, 32> Stream(std::string_view text)
{
    const auto digest = Hash(std::as_bytes(std::span(text)));
    std::array<std::byte, 32> result{};
    std::transform(digest.begin(), digest.end(), result.begin(), [](auto b) { return static_cast<std::byte>(b); });
    return result;
}
r::WriteAheadLog::ProtectedPersistence Protection(const fs::path& directory,
    std::array<std::byte, 32> binding, std::string_view stream)
{
    auto keys = directory / (std::string(stream) + "-keys"); fs::create_directories(keys);
    return {keys, binding, Stream(stream), {64ull << 20, 65536}, 256ull << 20};
}
void Unlock(Owner& owner)
{
    std::atomic<bool> cancelled{false};
    auto password = t::ReceiveCredential(GetStdHandle(STD_INPUT_HANDLE), std::chrono::seconds(5), cancelled);
    SetStdHandle(STD_INPUT_HANDLE, nullptr); Check(static_cast<bool>(password), "Credential");
    c::PasswordUnlockBudget attempts; std::string error;
    const bool ok = owner.Unlock(password.bytes, attempts, error); password.bytes.Clear(); Check(ok, "Unlock:" + error);
}
std::unique_ptr<Owner> Open(const fs::path& image)
{
    std::string error;
    auto owner = Owner::Open({image.wstring(), 20480, 4153344, 1026}, error);
    Check(owner && owner->CachedStatus().phase == Phase::Locked, "Open:" + error); return owner;
}
std::unique_ptr<r::PayloadSpool> Spool(const fs::path& directory, const std::array<std::byte, 32>& binding)
{
    r::PayloadSpool::Options options;
    options.root = directory / "payload"; options.volume_identity = "owner-reprepare-dfvfs";
    options.protected_persistence = true; options.protected_binding = binding;
    options.protected_key_directory = directory / "payload-keys";
    options.durable_flush_bytes = options.durable_flush_appends = 0;
    fs::create_directories(options.root); fs::create_directories(options.protected_key_directory);
    return std::make_unique<r::PayloadSpool>(options);
}
bool Same(r::TransactionManager::DurabilityWatermarks a, r::TransactionManager::DurabilityWatermarks b)
{ return a.accepted_sequence == b.accepted_sequence && a.apfs_durable_sequence == b.apfs_durable_sequence && a.cleanup_sequence == b.cleanup_sequence; }
void ReconcileOriginalSpool(r::TransactionManager& tx, r::PayloadSpool& spool, std::string& error)
{
    const auto before = tx.Watermarks();
    r::WriteAheadLog::ProtectedHistoryHead head;
    const bool captured = tx.CaptureProtectedOriginalHistoryHead(head, error);
    Check(captured, "CaptureOriginalSpoolHistory:" + error);
    const auto reconciled = tx.ReconcileProtectedPayloadSpool(spool, head, error);
#ifdef APFSACCESS_PROTECTED_SPOOL_TESTING
    if (reconciled != r::PayloadSpool::ProtectedMaintenanceResult::Succeeded) {
        for (const auto& event : r::protected_spool_testing::hooks.maintenance_events) std::cerr << "SpoolEvent:" << event << '\n';
        auto frame = apfsaccess::crypto::SecureBytes::Allocate(65536 + 80);
        auto plain = apfsaccess::crypto::SecureBytes::Allocate(65536);
        std::cerr << "DefaultLockedFrame=" << static_cast<bool>(frame) << ":" << frame.os_status
            << ":Plain=" << static_cast<bool>(plain) << ":" << plain.os_status << '\n';
    }
#endif
    Check(reconciled == r::PayloadSpool::ProtectedMaintenanceResult::Succeeded && Same(before, tx.Watermarks()),
        "ReconcileOnlyAuthenticatedOriginalSpoolHistory:" + error);
}
void Admission(const fs::path& image)
{
    const Owner::Image selection{image.wstring(), 20480, 4153344, 1026};
    std::string error;
    {
        const auto held = CreateFileW(image.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        Check(held != INVALID_HANDLE_VALUE, "AdmissionHeldReader");
        const auto start = std::chrono::steady_clock::now();
        auto refused = Owner::Open(selection, error);
        const auto elapsed = std::chrono::steady_clock::now() - start;
        CloseHandle(held);
        Check(!refused && error == "ImageWriterExclusiveSingleLinkRegularFileRequired:stage=FileOpen:win32=32:attempts=4",
            "PersistentShareRefusal:" + error);
        Check(elapsed >= std::chrono::milliseconds(175) && elapsed < std::chrono::seconds(5), "BoundedOpenRetry");
        std::cout << "AdmissionPersistent:" << error << '\n';
    }
    {
        const auto held = CreateFileW(image.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        Check(held != INVALID_HANDLE_VALUE, "AdmissionTransientReader");
        std::jthread release([held] { Sleep(50); CloseHandle(held); });
        auto admitted = Owner::Open(selection, error);
        Check(admitted && error.empty() && admitted->CachedStatus().phase == Phase::Locked &&
            !admitted->CachedStatus().key_present, "TransientShareAdmission:" + error);
        admitted->Close();
    }
    {
        const auto alias = fs::path(image.wstring() + L".admission-link");
        Check(CreateHardLinkW(alias.c_str(), image.c_str(), nullptr) != FALSE, "AdmissionPrivateHardLink");
        struct Unlink { fs::path path; ~Unlink() { DeleteFileW(path.c_str()); } } unlink{alias};
        auto refused = Owner::Open(selection, error);
        Check(!refused && error.starts_with("ImageWriterExclusiveSingleLinkRegularFileRequired:stage=FileProperties:attributes=") &&
            error.ends_with(":directory=0:deletePending=0:links=2") && error.find("win32=") == error.npos,
            "DistinctLinkPropertiesRefusal:" + error);
        std::cout << "AdmissionLinks:" << error << '\n';
    }
    {
        auto absent = selection; absent.path += L".missing";
        auto refused = Owner::Open(absent, error);
        Check(!refused && error == "ImageWriterExclusiveSingleLinkRegularFileRequired:stage=FileOpen:win32=2:attempts=1",
            "MissingFileNoRetry:" + error);
        Check(error.find(':', error.find("stage=")) != error.npos && error.find("D:") == error.npos &&
            error.find("\\") == error.npos, "AdmissionDiagnosticHasNoPath");
        std::cout << "AdmissionMissing:" << error << '\n';
    }
    auto admitted = Open(image); admitted->Close();
    std::cout << "{\"status\":\"PASS\",\"admission\":true,\"checks\":" << checks << "}\n";
}
int wmain(int argc, wchar_t** argv)
{
    try {
        Check(argc == 7, "Arguments:image,journal,phase,operation,inode,control");
        const auto image = fs::absolute(argv[1]).lexically_normal(), directory = fs::absolute(argv[2]).lexically_normal();
        const std::wstring prefix = L"D:\\ApfsAccessScratch\\WindowsClosure\\encrypted-owner-delta-20261016\\reprepare-20261016\\";
        const std::wstring short_prefix = L"D:\\ApfsAccessScratch\\BOY6\\";
        Check((image.wstring().starts_with(prefix) && directory.wstring().starts_with(prefix)) ||
            (image.wstring().starts_with(short_prefix) && directory.wstring().starts_with(short_prefix)), "PrivateDOnly");
        const std::wstring phase = argv[3], operation = argv[4], control = argv[6];
        if (phase == L"admission") { Admission(image); return 0; }
        auto inode = std::stoull(argv[5]);
        auto owner = Open(image); const auto identity = owner->SourceIdentity(); const auto binding = owner->SourceBinding();
        fs::create_directories(directory); std::string error;
        auto original_binding = binding; if (operation == L"source") original_binding[0] ^= std::byte{1};
        auto tx = std::make_unique<r::TransactionManager>(L"Conservative");
        Check(tx->OpenProtectedJournal((directory / "original.wal").wstring(), L"owner-reprepare-dfvfs",
            Protection(directory, original_binding, "original-v2"), error), "OriginalOpen:" + error);
        Journal::Options options;
        options.container_bytes = owner->CachedStatus().container_bytes; options.container_uuid = owner->ContainerUuid();
        options.preimage_source_identity = identity; options.volume_object_id = owner->VolumeObjectId(); options.volume_uuid = owner->VolumeUuid();
        options.witness = {directory / "witness.wal", "owner-reprepare-witness-v2", 64ull << 20, Protection(directory, binding, "witness-v2")};
        auto journal = std::make_unique<Journal>(options);
        if (phase == L"accept" || phase == L"prepared" || phase == L"preflight") {
            Unlock(*owner); c::EncryptedReadError re{};
            auto view = owner->OpenReadView(re); Check(static_cast<bool>(view), "AcceptView");
            const auto xid = owner->CachedStatus().checkpoint_xid;
            r::TransactionManager::MutationIntent intent; Bytes payload;
            intent.object_id = inode; intent.path = L"typed-original-write";
            intent.kind = r::TransactionManager::MutationKind::Write;
            intent.generation = operation == L"spool" ? xid : 0; intent.offset = 70000;
            payload.data = {std::byte{0xC1}, std::byte{0xD2}, std::byte{0xE3}};
            const bool create = operation == L"create600" || operation == L"create644" || operation == L"empty" || operation == L"create-inode";
            if (create) {
                inode = owner->CachedStatus().next_inode_id; intent.object_id = inode + (operation == L"create-inode" ? 1 : 0);
                intent.kind = r::TransactionManager::MutationKind::CreateFile; intent.generation = 2;
                intent.offset = operation == L"create644" ? 0644 : 0600;
                intent.path = operation == L"create644" ? L"reprepared-644.bin" : operation == L"empty" ? L"reprepared-empty.bin" : L"reprepared-600.bin";
                if (operation == L"empty" || operation == L"create-inode") payload.data.clear();
            } else if (operation == L"spool") {
                c::EncryptedNodeInfo metadata; Check(view->GetMetadata(inode, metadata) == c::EncryptedReadError::None, "SpoolTarget");
                intent.offset = metadata.size; payload.data.resize(65536);
                for (std::size_t i = 0; i < payload.data.size(); ++i) payload.data[i] = static_cast<std::byte>((i * 29 + 41) % 251);
            } else if (operation == L"shrink" || operation == L"grow") {
                c::EncryptedNodeInfo metadata; Check(view->GetMetadata(inode, metadata) == c::EncryptedReadError::None, "ResizeTarget");
                intent.kind = r::TransactionManager::MutationKind::SetFileSize; intent.generation = intent.offset = 0;
                intent.length = operation == L"shrink" ? metadata.size - 7 : metadata.size + 13; payload.data.clear();
            } else if (operation == L"rename" || operation == L"unlink") {
                intent.kind = operation == L"rename" ? r::TransactionManager::MutationKind::Rename : r::TransactionManager::MutationKind::Delete;
                intent.generation = 2; intent.offset = operation == L"rename" ? 2 : 0;
                intent.path = operation == L"rename" ? L"owner-large.bin" : L"owner-reprepared.bin";
                if (operation == L"rename") intent.secondary_path = L"owner-reprepared.bin";
                payload.data.clear();
            } else if (operation == L"opaque") intent.path = L"\\$apfs-keybag-rewrap-v2";
            else if (operation == L"flags") intent.replace_if_exists = true;
            if (intent.kind == r::TransactionManager::MutationKind::Write || create) {
                intent.length = intent.payload_length = payload.data.size(); intent.inline_payload = payload.data; intent.payload_checksum = Hash(payload.data);
            }
            if (phase == L"preflight") {
                const auto before = tx->Watermarks();
                c::EncryptedMutationRequest bad;
                bad.inode = inode;
                Check(!owner->PrepareMutation(xid, bad, error), "EmptyWriteRejectedBeforeAccept");
                bad.data = payload.data;
                Check(!owner->PrepareMutation(xid + 1, bad, error), "WrongXidRejectedBeforeAccept");
                bad.offset = UINT64_MAX;
                Check(!owner->PrepareMutation(xid, bad, error), "OverflowRejectedBeforeAccept");
                bad = {}; bad.kind = c::EncryptedMutationKind::Create; bad.parent = 2;
                bad.name = "invalid-mode.bin"; bad.permissions = 010000;
                Check(!owner->PrepareMutation(xid, bad, error), "ModeRejectedBeforeAccept");
                bad.permissions = 0600; bad.name = "owner-large.bin";
                Check(!owner->PrepareMutation(xid, bad, error), "ExistingNameRejectedBeforeAccept");
                Check(Same(before, tx->Watermarks()) && !tx->HasUnappliedAcceptedWork() &&
                    tx->CurrentState() == r::TransactionManager::State::Idle && owner->CachedStatus().phase == Phase::Ready,
                    "PreflightPreservesReadyAndNoAcceptedDebt");
                owner->Close();
                std::cout << "{\"status\":\"PASS\",\"invalidPreparations\":5,\"checks\":" << checks << "}\n"; return 0;
            }
            std::unique_ptr<Owner::PreparedMutation> prepared;
            if (phase == L"prepared") {
                c::EncryptedMutationRequest request;
                request.kind = c::EncryptedMutationKind::Write; request.inode = inode;
                request.offset = intent.offset; request.data = payload.data;
                prepared = owner->PrepareMutation(xid, request, error);
                Check(prepared && prepared->Intent().RequestedInode() == inode &&
                    prepared->Intent().SourceCheckpointXid() == xid && tx->CurrentState() == r::TransactionManager::State::Idle,
                    "PrivatePreparationBeforeAcceptance:" + error);
            }
            std::unique_ptr<r::PayloadSpool> spool;
            if (operation == L"spool" || (create && !payload.data.empty())) {
                spool = Spool(directory, binding);
                if (tx->NextMutationSequence() > 1) ReconcileOriginalSpool(*tx, *spool, error);
            }
            Check(tx->Begin(), "Begin");
            if (spool) {
                r::PayloadSpool::AppendResult ref;
                const auto appended = spool->AppendWithStatus({"owner-reprepare-dfvfs", inode, intent.generation,
                    intent.offset, tx->NextMutationSequence(), payload.data}, &ref);
                Check(appended == r::PayloadSpool::AppendStatus::Succeeded, "AppendProtectedOriginal:" + std::to_string(static_cast<int>(appended)));
                Check(spool->FlushPayloadBytes(), "FlushProtectedOriginal");
                intent.inline_payload.clear(); intent.wal_sequence = ref.wal_sequence; intent.payload_spool_offset = ref.spool_offset;
                intent.payload_checksum = ref.payload_sha256; Check(ref.generation == intent.generation, "SpoolGeneration");
            }
            Check(tx->RecordMutation(intent), "RecordOriginalMutation");
            Check(tx->Accept(operation == L"preimage" ? xid + 1 : xid), "AcceptOriginalMutation");
            if (operation == L"multiple") Check(tx->Begin() && tx->RecordMutation(intent) && tx->Accept(xid), "SecondBoundary");
            const auto wm = tx->Watermarks(); Check(wm.accepted_sequence > wm.apfs_durable_sequence, "UnpublishedDebt");
            bool inline_sequence_id = false;
            if (!payload.data.empty() && operation != L"spool" && !create) {
                std::vector<r::TransactionManager::AcceptedTransaction> observed;
                Check(tx->LoadAcceptedTransactionsSinceCleanup(observed, &error) && !observed.empty() &&
                    !observed.back().mutations.empty(), "AuthenticInlineOriginal");
                const auto& record = observed.back().mutations.front();
                inline_sequence_id = record.payload_spool_id == record.sequence && record.sequence &&
                    record.inline_payload == payload.data && record.parent_object_id == intent.generation;
                Check(inline_sequence_id && r::WriteAheadLog::InlinePayloadIsConsistent(record), "CanonicalInlineSequenceId");
                for (auto& row : observed) for (auto& record_to_wipe : row.mutations)
                    SecureZeroMemory(record_to_wipe.inline_payload.data(), record_to_wipe.inline_payload.size());
            }
            if (phase == L"prepared") {
                if (control == L"lock") owner->Lock();
                unsigned writes = 0; bool drained = true;
                const bool committed = owner->CommitAcceptedPrepared(*tx, *journal, wm.accepted_sequence, xid,
                    std::move(prepared), error, [&](std::string_view stage) {
                        if (stage == "before-apple-device-write") {
                            ++writes; c::EncryptedNamespaceInfo ignored;
                            drained = drained && view->GetNamespaceInfo(ignored) == c::EncryptedReadError::Closed;
                        }
                        return true;
                    });
                Check(!prepared, "CapabilityConsumed");
                if (control == L"lock") {
                    Check(!committed && writes == 0 && Same(wm, tx->Watermarks()) &&
                        owner->CachedStatus().recovery_required, "LockedPreparationRefusesBeforeStage:" + error);
                } else {
                    Check(committed && writes && drained && tx->Watermarks().apfs_durable_sequence == wm.accepted_sequence &&
                        owner->CachedStatus().checkpoint_xid == xid + 1, "PublishExactPreparedCapability:" + error);
                    Check(tx->MarkCleanedThrough(wm.accepted_sequence), "PreparedCallerCleanup");
                }
                const auto final_xid = owner->CachedStatus().checkpoint_xid; owner->Close();
                std::cout << "{\"status\":\"PASS\",\"preparedConsumed\":true,\"refused\":" << (control == L"lock" ? "true" : "false")
                    << ",\"xid\":" << final_xid << ",\"checks\":" << checks << "}\n"; return 0;
            }
            owner->Close();
            std::cout << "{\"status\":\"PASS\",\"inode\":" << inode << ",\"xid\":" << xid
                << ",\"sequence\":" << wm.accepted_sequence << ",\"inlineSequenceId\":" << (inline_sequence_id ? "true" : "false")
                << ",\"checks\":" << checks << "}\n";
            return 0;
        }
        std::vector<r::TransactionManager::AcceptedTransaction> rows;
        Check(tx->LoadAcceptedTransactionsSinceCleanup(rows, &error) && !rows.empty(), "OriginalRows:" + error);
        struct Wipe { decltype(rows)& value; ~Wipe() { for (auto& row : value) for (auto& m : row.mutations) SecureZeroMemory(m.inline_payload.data(), m.inline_payload.size()); } } wipe{rows};
        const auto before = tx->Watermarks(); const auto sequence = before.accepted_sequence, xid = owner->CachedStatus().checkpoint_xid;
        if (phase != L"refuse-witness" && control != L"original") {
            Journal::AcceptedDataRecovery disposition;
            const bool classified = journal->InspectAcceptedDataRecovery(*tx, sequence, disposition, error);
            Check(classified &&
                disposition == (phase == L"replay" ? Journal::AcceptedDataRecovery::CompleteWitness :
                    Journal::AcceptedDataRecovery::TypedReprepareAllowed), "ExactRecoveryClassification:" + error +
                    ":originalVolume=" + rows.front().mutations.front().volume_identity +
                    ":inline=" + std::to_string(rows.front().mutations.front().inline_payload.size()) +
                    ":spool=" + std::to_string(rows.front().mutations.front().payload_spool_id));
        }
        unsigned writes = 0, status_calls = 0; bool hit = false, status_ok = true;
        auto no_write = [&](std::string_view stage) { if (stage == "before-apple-device-write") ++writes; return true; };
        if (phase == L"refuse-witness" || control == L"locked") {
            Check(!owner->RecoverAcceptedMutation(*tx, *journal, sequence, {}, error, {}, no_write) && writes == 0 &&
                Same(before, tx->Watermarks()) && owner->CachedStatus().recovery_required, "LockedOrWitnessRefusal:" + error);
            owner->Close();
            std::cout << "{\"status\":\"PASS\",\"refused\":true,\"sequence\":" << sequence << ",\"checks\":" << checks << "}\n"; return 0;
        }
        Bytes payload;
        std::unique_ptr<r::PayloadSpool> recovery_spool;
        r::PayloadSpool::PersistedRangeReference reference{};
        const auto& record = rows.back().mutations.front();
        if (phase != L"replay") {
            Unlock(*owner);
            if (record.inline_payload.empty() && record.payload_length && record.payload_spool_id) {
                recovery_spool = Spool(directory, binding);
                ReconcileOriginalSpool(*tx, *recovery_spool, error);
                reference = {"owner-reprepare-dfvfs", record.object_id, record.parent_object_id,
                    record.logical_offset, record.payload_length, record.payload_offset, record.payload_spool_id, record.payload_sha256};
                if (control == L"reference") {
                    ++reference.generation;
                    bool called = false; std::string borrow_error;
                    Check(!recovery_spool->WithProtectedPersistedRange(reference, 64 * 4096,
                        [&](std::span<const std::byte>) { called = true; return true; }, borrow_error) && !called,
                        "WrongSpoolGenerationRefused:" + borrow_error);
                }
            }
        }
        const bool refuse = control == L"payload" || control == L"missing" || control == L"reference" || control == L"pin" || control == L"original";
        std::array<std::uint64_t, 1> pins{xid};
        if (control == L"payload") payload.data.assign(record.payload_length ? record.payload_length : 1, std::byte{0x11});
        if (control == L"missing") payload.data.clear();
        if (control == L"pin") pins[0] = xid + 1;
        unsigned appends = 0;
        if (control == L"partial") journal->SetWitnessFaultInjectionHook([&](std::string_view stage) {
            if (stage == "protected-before-write" && ++appends == 2) { hit = true; return true; } return false;
        });
        std::thread status_thread; std::promise<bool> promise; auto future = promise.get_future();
        c::EncryptedReadError read_error{};
        auto old = phase == L"replay" ? std::shared_ptr<c::ApfsEncryptedReadSession>{} : owner->OpenReadView(read_error);
        Check(phase == L"replay" || static_cast<bool>(old), "PreRecoveryView");
        bool drained = true;
        auto hook = [&](std::string_view stage) {
            if (stage == "before-apple-device-write") {
                ++writes;
                if (old) { c::EncryptedNamespaceInfo ignored; drained = drained && old->GetNamespaceInfo(ignored) == c::EncryptedReadError::Closed; }
                if (control == L"complete") { hit = true; return false; }
            }
            if (stage == "before-apple-prepublication-flush" && !status_thread.joinable()) {
                status_thread = std::thread([&] { bool ok = true; for (unsigned i = 0; i < 10000; ++i) ok = ok && owner->CachedStatus().phase == Phase::Publishing; promise.set_value(ok); });
                status_ok = future.wait_for(std::chrono::seconds(2)) == std::future_status::ready;
                if (status_ok) status_ok = future.get(); status_calls += 10000;
            }
            return status_ok;
        };
        bool recovered = false;
        if (recovery_spool && control != L"payload" && control != L"missing" && control != L"reference") {
            bool called = false; std::string borrow_error;
            const bool borrowed = recovery_spool->WithProtectedPersistedRange(reference, 64 * 4096,
                [&](std::span<const std::byte> locked_payload) {
                    called = true;
                    recovered = owner->RecoverAcceptedMutation(*tx, *journal, sequence, locked_payload, error, pins, hook);
                    return true;
                }, borrow_error);
            Check(borrowed && called, "ExactOriginalLockedSpoolBorrow:" + borrow_error);
        } else recovered = owner->RecoverAcceptedMutation(*tx, *journal, sequence, payload.data, error, pins, hook);
        if (status_thread.joinable()) status_thread.join();
        if (refuse || control == L"partial" || control == L"complete") {
            Check(!recovered && Same(before, tx->Watermarks()) && owner->CachedStatus().recovery_required, "DebtRetained:" + error);
            Check((control == L"complete" ? writes == 1 : writes == 0) && (!hit || control == L"partial" || control == L"complete"), "NoPublicationOnRefusal");
            if (control == L"partial" || control == L"complete") Check(hit, "ExactFaultHit");
            owner->Close();
            std::cout << "{\"status\":\"PASS\",\"refused\":true,\"faultHit\":" << (hit ? "true" : "false")
                << ",\"sequence\":" << sequence << ",\"checks\":" << checks << "}\n"; return 0;
        }
        Check(recovered && writes && drained && status_ok && status_calls == 10000, "RecoverAcceptedMutation:" + error);
        Check(tx->Watermarks().apfs_durable_sequence == sequence && tx->Watermarks().cleanup_sequence == before.cleanup_sequence &&
            owner->CachedStatus().checkpoint_xid == rows.front().preimage_checkpoint_xid + 1 &&
            owner->SourceIdentity() == identity && owner->SourceBinding() == binding, "OriginalDebtDurableOnSameSource");
        if (phase == L"replay") Check(owner->CachedStatus().phase == Phase::Locked && !owner->CachedStatus().key_present &&
            !owner->CachedStatus().free_space_valid, "KeylessNewRecoveryRoute");
        else {
            Check(owner->CachedStatus().phase == Phase::Ready && owner->CachedStatus().key_present, "ReboundWithoutRetainedPassword");
            c::EncryptedReadError re{}; auto view = owner->OpenReadView(re); Check(static_cast<bool>(view), "ReboundView");
            if (record.operation == r::WriteAheadLog::OperationKind::CreateFile) {
                c::EncryptedNodeInfo metadata; Check(view->GetMetadata(record.object_id, metadata) == c::EncryptedReadError::None &&
                    metadata.mode == (0100000 | record.logical_offset) && metadata.size == record.payload_length, "OriginalCreateModeAndSize");
            }
        }
        Check(tx->MarkCleanedThrough(sequence), "CallerCleanupAfterDurability");
        const auto final_xid = owner->CachedStatus().checkpoint_xid; owner->Lock(); Check(!owner->CachedStatus().key_present, "LockWipesKey"); owner->Close();
        owner = Open(image); Check(owner->CachedStatus().checkpoint_xid == final_xid && owner->SourceBinding() == binding &&
            !owner->CachedStatus().key_present, "FreshLockedReopen"); owner->Close();
        std::cout << "{\"status\":\"PASS\",\"sequence\":" << sequence << ",\"xid\":" << final_xid
            << ",\"statusCalls\":" << status_calls << ",\"checks\":" << checks << "}\n";
        return 0;
    } catch (const std::exception& ex) { std::cerr << "OwnerTypedRecoveryFailure:" << ex.what() << '\n'; return 1; }
}
