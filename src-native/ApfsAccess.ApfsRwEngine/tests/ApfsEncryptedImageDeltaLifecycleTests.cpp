#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#undef CreateFile
#include "ApfsEncryptedImageWriteSession.h"
#include "ApfsFormat.h"
#include "EncryptedReadTransport.h"
#include "PayloadSpool.h"
#include <algorithm>
#include <chrono>
#include <filesystem>
#include <future>
#include <iostream>
#include <map>
#include <stdexcept>
#include <thread>
#undef CreateFile
namespace c = apfsaccess::catalog;
namespace r = apfsaccess::rw;
namespace t = apfsaccess::transport;
namespace fs = std::filesystem;
using Owner = c::ApfsEncryptedImageWriteSession;
using Phase = c::EncryptedImageWritePhase;
using Error = c::EncryptedReadError;
unsigned checks = 0;
void Check(bool ok, const std::string& why) { ++checks; if (!ok) throw std::runtime_error(why); }
std::array<std::uint8_t, 32> Hash(std::span<const std::byte> bytes)
{
    std::array<std::uint8_t, 32> hash{};
    Check(bytes.size() <= ULONG_MAX && BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0,
        reinterpret_cast<PUCHAR>(const_cast<std::byte*>(bytes.data())), static_cast<ULONG>(bytes.size()),
        hash.data(), static_cast<ULONG>(hash.size())) >= 0, "Hash");
    return hash;
}
std::string Hex(std::span<const std::uint8_t> bytes)
{
    std::string out;
    for (auto byte : bytes) { out += "0123456789abcdef"[byte >> 4]; out += "0123456789abcdef"[byte & 15]; }
    return out;
}
std::array<std::byte, 32> StreamBinding(std::string_view text)
{
    const auto hash = Hash(std::as_bytes(std::span(text)));
    std::array<std::byte, 32> out{};
    std::transform(hash.begin(), hash.end(), out.begin(), [](auto value) { return static_cast<std::byte>(value); });
    return out;
}
r::WriteAheadLog::ProtectedPersistence Protection(const fs::path& directory,
    const std::array<std::byte, 32>& binding, std::string_view stream)
{
    auto keys = directory / (std::string(stream) + "-keys");
    fs::create_directories(keys);
    return {keys, binding, StreamBinding(stream), {64ull << 20, 65536}, 256ull << 20};
}
struct Bytes
{
    std::vector<std::byte> data;
    Bytes() = default;
    Bytes(Bytes&&) noexcept = default;
    Bytes& operator=(Bytes&&) noexcept = default;
    Bytes(const Bytes&) = delete;
    Bytes& operator=(const Bytes&) = delete;
    ~Bytes() { SecureZeroMemory(data.data(), data.size()); }
};
Bytes ReadAll(c::ApfsEncryptedReadSession& view, std::uint64_t inode, std::uint64_t size)
{
    Check(size <= 2ull << 20, "PrivateFixtureFileBound");
    Bytes result;
    for (std::uint64_t offset = 0; offset < size;) {
        Bytes chunk; const auto count = static_cast<std::size_t>((std::min)(size - offset, 65536ULL));
        Check(view.ReadFile(inode, offset, count, chunk.data) == Error::None && chunk.data.size() == count, "ChunkRead");
        result.data.insert(result.data.end(), chunk.data.begin(), chunk.data.end()); offset += count;
    }
    return result;
}
struct Fact { std::uint64_t size = 0; std::uint16_t mode = 0; std::array<std::uint8_t, 32> hash{}; };
std::map<std::uint64_t, Fact> Inventory(c::ApfsEncryptedReadSession& view)
{
    std::vector<c::EncryptedFileInfo> files; Check(view.ListFiles(files) == Error::None, "ListFiles");
    std::map<std::uint64_t, Fact> out;
    for (const auto& file : files) {
        c::EncryptedNodeInfo metadata; Check(view.GetMetadata(file.inode_id, metadata) == Error::None, "Metadata");
        auto bytes = ReadAll(view, file.inode_id, file.size);
        out.emplace(file.inode_id, Fact{file.size, metadata.mode, Hash(bytes.data)});
    }
    return out;
}
std::string Name(c::ApfsEncryptedReadSession& view, std::uint64_t inode)
{
    std::vector<c::EncryptedDirectoryEntry> entries;
    Check(view.ListDirectory(2, entries) == Error::None, "RootDirectory");
    std::string result;
    for (const auto& entry : entries) if (entry.inode_id == inode) { Check(result.empty(), "ExclusiveName"); result = entry.name_utf8; }
    return result;
}
struct Shape { std::size_t fs_nodes = 0, omap_nodes = 0; std::uint64_t xid = 0; };
Shape ObserveClosedImage(const fs::path& image)
{
    auto lease = std::make_shared<t::WindowsImageLease>(image.wstring());
    auto source = std::make_shared<t::OwnedEncryptedImageSource>(lease, 20480, 4153344);
    std::string error;
    auto cp = c::LoadContainerCheckpointView(*source, 0, source->SizeBytes(), error);
    auto catalog = cp ? c::LoadAppleReadOnlyVolumeView(*source, *cp, error) : std::nullopt;
    Check(catalog && catalog->volumes.size() == 1 && catalog->volumes.front().superblock.object_id == 1026, "ClosedCatalog:" + error);
    const auto omap = catalog->volumes.front().superblock.omap_oid;
    std::vector<std::byte> object;
    Check(omap && source->Read(omap * 4096, 4096, object) && c::VerifyObjectChecksum(object, 4096) &&
        c::ReadU64LE(object, 8) == omap && c::ReadU32LE(object, 24) == (c::kObjectPhysical | c::kObjectTypeOmap), "ClosedOmapObject");
    const auto tree_block = c::ReadU64LE(object, 0x30).value_or(0);
    Check(tree_block != 0, "ClosedOmapRoot");
    c::BtreeReadPolicy policy;
    policy.enforce_object_identity = true; policy.require_complete_traversal = true; policy.reject_unsupported_flags = true;
    policy.root_object_id = tree_block; policy.storage_type = c::kObjectPhysical; policy.subtype = c::kObjectTypeOmap;
    std::vector<std::uint64_t> nodes; policy.visited_physical_blocks = &nodes;
    std::vector<c::BtreeRecord> records;
    const bool walked = c::ReadBtreeLeafRecords(*source, 4096, tree_block, true, 0, cp->superblock.xid, policy, records, error);
    Check(walked, "ClosedMappings:" + error);
    Shape result; result.xid = cp->superblock.xid; result.omap_nodes = nodes.size();
    for (const auto& record : records) if (c::ReadU32LE(record.value, 0) == 4) ++result.fs_nodes;
    return result;
}
int wmain(int argc, wchar_t** argv)
{
    try {
        Check(argc == 5, "Arguments:image,journals,mode,inode");
        const auto image = fs::absolute(argv[1]).lexically_normal();
        const auto directory = fs::absolute(argv[2]).lexically_normal();
        const std::wstring prefix = L"D:\\ApfsAccessScratch\\WindowsClosure\\encrypted-owner-delta-20261016\\";
        Check(image.wstring().starts_with(prefix) && directory.wstring().starts_with(prefix), "PrivateDOnly");
        const std::wstring mode = argv[3]; std::uint64_t inode = std::stoull(argv[4]);
        const bool seed = mode == L"seed", recovery = mode == L"recover-patch", unlink = mode == L"unlink";
        std::string error;
        auto owner = Owner::Open({image.wstring(), 20480, 4153344, 1026}, error);
        Check(owner && owner->CachedStatus().phase == Phase::Locked, "OpenLocked");
        const auto binding = owner->SourceBinding(); const auto identity = owner->SourceIdentity();
        const auto uuid = owner->ContainerUuid(); const auto volume_uuid = owner->VolumeUuid();
        Check(owner->VolumeObjectId() == 1026 && uuid.size() == 32 && volume_uuid.size() == 32, "TypedSelection");
        std::atomic<bool> cancelled{false};
        auto credential = t::ReceiveCredential(GetStdHandle(STD_INPUT_HANDLE), std::chrono::seconds(5), cancelled);
        SetStdHandle(STD_INPUT_HANDLE, nullptr); Check(static_cast<bool>(credential), "Credential");
        c::PasswordUnlockBudget attempts;
        const bool unlocked = owner->Unlock(credential.bytes, attempts, error);
        credential.bytes.Clear(); Check(unlocked, "Unlock:" + error);
        Error read_error{};
        auto initial = owner->OpenReadView(read_error); Check(static_cast<bool>(initial), "InitialView");
        const auto baseline = Inventory(*initial);
        Bytes expected;
        std::string current_name;
        if (!seed) {
            Check(baseline.contains(inode), "LargeTargetExists");
            expected = ReadAll(*initial, inode, baseline.at(inode).size); current_name = Name(*initial, inode);
            Check(expected.data.size() >= 1ull << 20 && !current_name.empty(), "LargeTarget");
        } else Check(inode == 0, "SeedNoTarget");
        initial->Close(); initial.reset();
        fs::create_directories(directory);
        r::TransactionManager tx(L"Conservative");
        Check(tx.OpenProtectedJournal((directory / "original.wal").wstring(), L"owner-delta-dfvfs",
            Protection(directory, binding, "owner-delta-original-v2"), error), "OriginalOpen:" + error);
        r::EncryptedPublicationJournal::Options options;
        options.container_bytes = owner->CachedStatus().container_bytes; options.container_uuid = uuid;
        options.preimage_source_identity = identity; options.volume_object_id = owner->VolumeObjectId(); options.volume_uuid = volume_uuid;
        options.witness = {directory / "witness.wal", "owner-delta-witness-v2", 64ull << 20,
            Protection(directory, binding, "owner-delta-witness-v2")};
        auto journal = std::make_unique<r::EncryptedPublicationJournal>(options);
        std::unique_ptr<r::PayloadSpool> spool;
        if (seed) {
            r::PayloadSpool::Options spool_options;
            spool_options.root = directory / "payload"; spool_options.volume_identity = "owner-delta-dfvfs";
            spool_options.protected_persistence = true; spool_options.protected_binding = binding;
            spool_options.protected_key_directory = directory / "payload-keys";
            spool_options.durable_flush_bytes = spool_options.durable_flush_appends = 0;
            fs::create_directories(spool_options.root); fs::create_directories(spool_options.protected_key_directory);
            spool = std::make_unique<r::PayloadSpool>(spool_options);
        }
        const auto initial_xid = owner->CachedStatus().checkpoint_xid;
        unsigned commits = 0, spooled = 0, status_calls = 0;
        const unsigned count = seed ? 17 : 1;
        for (unsigned index = 0; index < count; ++index) {
            auto old = owner->OpenReadView(read_error); Check(static_cast<bool>(old), "PrecommitView");
            const auto before_status = owner->CachedStatus(); const auto xid = before_status.checkpoint_xid;
            c::EncryptedMutationRequest request; Bytes payload;
            if (seed && index == 0) {
                request.kind = c::EncryptedMutationKind::Create; request.parent = 2;
                request.name = "owner-large.bin"; request.permissions = 0600; inode = before_status.next_inode_id;
                Check(inode >= 16, "ObservedCreateInode");
            } else if (seed || mode == L"append") {
                request.kind = c::EncryptedMutationKind::Write; request.inode = inode; request.offset = expected.data.size();
                payload.data.resize(seed ? 65536 : 123);
                for (std::size_t i = 0; i < payload.data.size(); ++i) {
                    const auto at = request.offset + i; payload.data[i] = static_cast<std::byte>((at * 17 + at / 4096 * 11 + 53) % 251);
                }
            } else if (mode == L"patch" || recovery) {
                request.kind = c::EncryptedMutationKind::Write; request.inode = inode;
                request.offset = recovery ? 70000 : 65535;
                payload.data = recovery ? std::vector{std::byte{0xEA}, std::byte{0xEB}} : std::vector{std::byte{0xFE}, std::byte{0xFD}};
            } else if (mode == L"shrink" || mode == L"grow") {
                request.kind = c::EncryptedMutationKind::Resize; request.inode = inode;
                request.size = mode == L"shrink" ? expected.data.size() - 17 : expected.data.size() + 10;
            } else if (mode == L"rename" || unlink) {
                request.kind = unlink ? c::EncryptedMutationKind::Unlink : c::EncryptedMutationKind::Rename;
                request.inode = inode; request.parent = 2; request.name = current_name;
                if (!unlink) { request.destination_parent = 2; request.destination_name = "owner-large-renamed.bin"; }
            } else throw std::runtime_error("UnknownMode");
            request.data = payload.data;
            r::TransactionManager::MutationIntent intent;
            intent.object_id = inode;
            intent.kind = request.kind == c::EncryptedMutationKind::Create ? r::TransactionManager::MutationKind::CreateFile :
                request.kind == c::EncryptedMutationKind::Resize ? r::TransactionManager::MutationKind::SetFileSize :
                request.kind == c::EncryptedMutationKind::Rename ? r::TransactionManager::MutationKind::Rename :
                request.kind == c::EncryptedMutationKind::Unlink ? r::TransactionManager::MutationKind::Delete : r::TransactionManager::MutationKind::Write;
            const bool names = request.kind == c::EncryptedMutationKind::Create || request.kind == c::EncryptedMutationKind::Rename || unlink;
            intent.path = names ? std::wstring(request.name.begin(), request.name.end()) : L"owner-delta-write";
            intent.secondary_path.assign(request.destination_name.begin(), request.destination_name.end());
            intent.generation = names ? request.parent : request.kind == c::EncryptedMutationKind::Write ? xid : 0;
            intent.offset = request.kind == c::EncryptedMutationKind::Create ? request.permissions :
                request.kind == c::EncryptedMutationKind::Rename ? request.destination_parent : request.offset;
            intent.length = request.kind == c::EncryptedMutationKind::Resize ? request.size : payload.data.size();
            if (request.kind == c::EncryptedMutationKind::Write || request.kind == c::EncryptedMutationKind::Create) {
                intent.payload_length = payload.data.size(); intent.payload_checksum = Hash(payload.data); intent.inline_payload = payload.data;
            }
            Check(tx.Begin(), "BeginOriginal");
            if (payload.data.size() > 4096) {
                r::PayloadSpool::AppendResult reference;
                Check(spool && spool->Append({"owner-delta-dfvfs", inode, xid, request.offset,
                    tx.NextMutationSequence(), payload.data}, &reference) && spool->FlushPayloadBytes(), "DurableProtectedSpool");
                intent.inline_payload.clear(); intent.wal_sequence = reference.wal_sequence;
                intent.payload_spool_offset = reference.spool_offset; intent.payload_length = reference.payload_length;
                intent.payload_checksum = reference.payload_sha256; intent.generation = reference.generation; ++spooled;
            }
            Check(tx.RecordMutation(intent) && tx.Accept(xid), "AcceptExactIntent");
            const auto sequence = tx.Watermarks().accepted_sequence;
            std::vector<r::TransactionManager::AcceptedTransaction> accepted;
            Check(tx.LoadAcceptedTransactionsSinceCleanup(accepted, &error) && accepted.size() == 1 &&
                accepted.front().accepted_sequence == sequence && accepted.front().preimage_checkpoint_xid == xid &&
                accepted.front().mutations.size() == 1, "AcceptedBoundary:" + error);
            if (payload.data.size() > 4096) {
                const auto& record = accepted.front().mutations.front();
                Check(record.inline_payload.empty() && record.payload_spool_id && record.parent_object_id == xid &&
                    record.payload_length == payload.data.size(), "ExactSpoolGeneration");
            }
            bool old_closed = true, fault_hit = false, status_ok = true, status_started = false;
            std::thread status_thread; std::promise<bool> promise; auto future = promise.get_future();
            auto hook = [&](std::string_view stage) {
                if (stage == "before-apple-device-write") {
                    c::EncryptedNamespaceInfo ignored;
                    old_closed = old_closed && old->GetNamespaceInfo(ignored) == Error::Closed;
                    if (!old_closed) return false;
                }
                if (stage == "before-apple-prepublication-flush") {
                    if (!status_started) {
                        status_started = true;
                        status_thread = std::thread([&] {
                            bool ok = true;
                            for (unsigned i = 0; i < 10000; ++i) ok = ok && owner->CachedStatus().phase == Phase::Publishing;
                            promise.set_value(ok);
                        });
                        status_ok = future.wait_for(std::chrono::seconds(2)) == std::future_status::ready;
                        if (status_ok) status_ok = future.get();
                        if (!status_ok) return false;
                    }
                    if (recovery) { fault_hit = true; return false; }
                }
                return true;
            };
            const auto pins = std::array{xid};
            const bool committed = owner->CommitAcceptedMutation(tx, *journal, sequence, xid, request, error, pins, hook);
            if (status_thread.joinable()) status_thread.join();
            Check(old_closed && status_ok && status_started, "ViewsDrainedAndStatusResponsive"); status_calls += 10000;
            if (recovery) {
                Check(!committed && fault_hit && owner->CachedStatus().phase == Phase::RecoveryRequired &&
                    !owner->OpenReadView(read_error) && tx.Watermarks().apfs_durable_sequence < sequence, "InterruptedLargePublication:" + error);
                owner->Lock(); Check(!owner->CachedStatus().key_present, "RecoveryLockWipesKey");
                owner->Close(); owner = Owner::Open({image.wstring(), 20480, 4153344, 1026}, error);
                Check(owner && !owner->CachedStatus().key_present && owner->SourceIdentity() == identity && owner->SourceBinding() == binding,
                    "SameBoundOwnerReopenLocked");
                journal.reset(); journal = std::make_unique<r::EncryptedPublicationJournal>(options);
                Check(owner->RecoverAccepted(tx, *journal, sequence, error), "LargeWitnessRecovery:" + error);
                Check(owner->CachedStatus().phase == Phase::Locked && !owner->CachedStatus().key_present &&
                    !owner->CachedStatus().free_space_valid && owner->CachedStatus().free_bytes == 0, "RecoveredWithoutPasswordOrKey");
            } else Check(committed, "CommitAcceptedMutation:" + error);
            Check(tx.Watermarks().apfs_durable_sequence == sequence && owner->CachedStatus().checkpoint_xid == xid + 1 &&
                owner->SourceIdentity() == identity && owner->SourceBinding() == binding, "DurableExactBoundImage");
            if (request.kind == c::EncryptedMutationKind::Write) {
                expected.data.resize((std::max)(expected.data.size(), static_cast<std::size_t>(request.offset + payload.data.size())), std::byte{});
                std::copy(payload.data.begin(), payload.data.end(), expected.data.begin() + request.offset);
            } else if (request.kind == c::EncryptedMutationKind::Resize) expected.data.resize(static_cast<std::size_t>(request.size), std::byte{});
            if (request.kind == c::EncryptedMutationKind::Create) current_name = std::string(request.name);
            if (request.kind == c::EncryptedMutationKind::Rename) current_name = std::string(request.destination_name);
            if (!recovery) {
                Check(owner->CachedStatus().phase == Phase::Ready && owner->CachedStatus().free_bytes < before_status.free_bytes,
                    "CanonicalRebindAndAllocatorCharge");
                auto fresh = owner->OpenReadView(read_error); Check(static_cast<bool>(fresh), "FreshViewNoNewPassword");
                const auto facts = Inventory(*fresh);
                Check(facts.size() == baseline.size() + (seed ? 1 : 0) - (unlink ? 1 : 0), "ExactNamespaceCount");
                if (unlink) Check(!facts.contains(inode) && Name(*fresh, inode).empty(), "UnlinkedLargeFile");
                else Check(facts.contains(inode) && facts.at(inode).size == expected.data.size() && facts.at(inode).mode == 0100600 &&
                    facts.at(inode).hash == Hash(expected.data) && Name(*fresh, inode) == current_name, "ExactLargeBytesModeAndName");
                for (const auto& [id, fact] : baseline) if (id != inode)
                    Check(facts.contains(id) && facts.at(id).size == fact.size && facts.at(id).mode == fact.mode &&
                        facts.at(id).hash == fact.hash, "UnchangedOriginalFile");
            }
            Check(tx.MarkCleanedThrough(sequence), "CallerCleanupAfterDurability"); ++commits;
            std::cerr << "accepted delta " << commits << " xid=" << owner->CachedStatus().checkpoint_xid << '\n';
        }
        const auto final_xid = owner->CachedStatus().checkpoint_xid;
        owner->Lock(); Check(!owner->CachedStatus().key_present && !owner->OpenReadView(read_error), "FinalLockRevokes");
        owner->Close();
        const auto shape = ObserveClosedImage(image);
        Check(shape.xid == final_xid && final_xid == initial_xid + commits && (unlink || shape.fs_nodes > 1), "ActualMultiNodeImage");
        auto reopened = Owner::Open({image.wstring(), 20480, 4153344, 1026}, error);
        Check(reopened && reopened->CachedStatus().checkpoint_xid == final_xid && !reopened->CachedStatus().key_present &&
            reopened->SourceIdentity() == identity && reopened->SourceBinding() == binding, "FinalReopenRequiresUnlock");
        reopened->Close();
        std::cout << "{\"status\":\"PASS\",\"inode\":" << inode << ",\"size\":" << (unlink ? 0 : expected.data.size())
            << ",\"sha256\":\"" << Hex(Hash(unlink ? std::span<const std::byte>{} : std::span<const std::byte>(expected.data)))
            << "\",\"commits\":" << commits << ",\"initialXid\":" << initial_xid << ",\"finalXid\":" << final_xid
            << ",\"fsNodes\":" << shape.fs_nodes << ",\"omapNodes\":" << shape.omap_nodes
            << ",\"spooledWrites\":" << spooled << ",\"statusCallsWhileBlocked\":" << status_calls
            << ",\"lockedRecovery\":" << (recovery ? "true" : "false") << ",\"checks\":" << checks << "}\n";
        return 0;
    } catch (const std::exception& ex) { std::cerr << "OwnerDeltaFailure:" << ex.what() << '\n'; return 1; }
}
