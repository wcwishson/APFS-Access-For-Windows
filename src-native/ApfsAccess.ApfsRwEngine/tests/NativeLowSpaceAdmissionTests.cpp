#include "ContainerMountCoordinator.h"
#include "MetadataStore.h"
#include "TransactionManager.h"
#include "PayloadSpool.h"
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <stdexcept>

using Store = apfsaccess::rw::MetadataStore;
using Owner = apfsaccess::catalog::ContainerMountCoordinator;
namespace {
unsigned checks = 0;
void Check(bool value, const std::string& reason) {
    ++checks;
    if (!value) throw std::runtime_error(reason);
}
std::vector<std::byte> Read(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    Check(bool(in), "open private regular image");
    const std::vector<char> raw((std::istreambuf_iterator<char>(in)), {});
    std::vector<std::byte> bytes(raw.size());
    std::transform(raw.begin(), raw.end(), bytes.begin(), [](unsigned char c) { return std::byte(c); });
    return bytes;
}
std::unique_ptr<Owner> Open(const std::filesystem::path& path, std::uint64_t accepted_preimage = 0) {
    std::string error;
    auto owner = Owner::Open(path.string(), 0, error, apfsaccess::catalog::CatalogLoadPolicy::StrictApple,
        true, true, true);
    Check(bool(owner), "exclusive generated ordinary image owner: " + error);
    const std::vector<std::uint64_t> pins = accepted_preimage
        ? std::vector<std::uint64_t>{accepted_preimage} : std::vector<std::uint64_t>{};
    Check(owner->InitializeRequiredCheckpointCensus({{101, pins, accepted_preimage != 0}}, error), "complete one-volume census: " + error);
    apfsaccess::catalog::ContainerVolumeSession session;
    session.volume_object_id = 101;
    session.container_uuid_hex = owner->ContainerUuidHex();
    session.requested_write = session.use_canonical_transaction = true;
    session.metadata_context.allow_native_snapshot_runtime = true;
    session.metadata_context.allow_legacy_scaffold_for_fixtures = false;
    Check(owner->MountVolume(session, error), "ordinary snapshot-aware native writer: " + error);
    return owner;
}
void ActualLowSpace(const std::filesystem::path& original) {
    const auto path = std::filesystem::absolute("low-space.apfs");
    Check(!std::filesystem::exists(path), "fresh private image name");
    Check(std::filesystem::file_size(original) == 4u * 1024u * 1024u, "bounded generated four-MiB input");
    std::filesystem::copy_file(original, path);
    auto owner = Open(path);
    auto* store = owner->FindSessionStore(101);
    const auto inode = store->LookupCommittedInodeByPath(L"\\space-pressure.bin");
    Check(inode && inode->logical_size == 393216, "actual six-chunk failed-run preimage");
    std::vector<std::byte> expected;
    Check(store->ReadCommittedFileRange(L"\\space-pressure.bin", 0, inode->logical_size, expected), "original accepted payload reads");
    for (unsigned i = 0; i < 6; ++i)
        Check(std::all_of(expected.begin() + i * 65536, expected.begin() + (i + 1) * 65536,
            [i](auto byte) { return byte == std::byte((i * 31 + 9) & 255); }), "independent six-chunk expected bytes");
    std::vector<std::byte> before;
    Check(owner->Device().ReadForVerification(0, 4u << 20, before), "held pre-refusal image bytes");
    const auto initial_xid = owner->CheckpointXid();
    std::map<std::uint64_t, std::vector<std::byte>> historical;
    std::ifstream pins("pins.txt");
    std::uint64_t block = 0;
    while (pins >> block) {
        Check(block < before.size() / 4096, "historical pin within original geometry");
        historical.emplace(block, std::vector<std::byte>(before.begin() + block * 4096, before.begin() + (block + 1) * 4096));
    }
    Check(historical.size() == 49, "all independently retained original-run historical pins loaded");
    apfsaccess::rw::TransactionManager tx(L"Strict");
    tx.SetVolumeIdentity(L"ordinary-lowspace-original");
    tx.SetJournalPath(std::filesystem::absolute("original.wal").wstring());
    apfsaccess::rw::PayloadSpool spool({std::filesystem::absolute("original-spool"), "ordinary-lowspace-original"});
    std::vector<std::byte> replacement;
    unsigned accepts = 0;
    const auto binder = [&](const auto& requests, const auto& identities, auto preimage, auto& required, auto&) {
        ++accepts; Check(tx.Begin(), "begin actual original acceptance");
        for (std::size_t i = 0; i < requests.size(); ++i) {
            const auto& request = requests[i];
            apfsaccess::rw::TransactionManager::MutationIntent intent;
            intent.kind = request.operation == Store::MutationOperation::Write ? apfsaccess::rw::TransactionManager::MutationKind::Write :
                request.operation == Store::MutationOperation::Delete ? apfsaccess::rw::TransactionManager::MutationKind::Delete :
                apfsaccess::rw::TransactionManager::MutationKind::CreateFile;
            intent.path = request.path; intent.offset = request.offset; intent.length = request.length;
            intent.object_id = identities[i].object_id; intent.generation = identities[i].generation;
            intent.unlink_outcome = request.expected_unlink_outcome;
            if (request.operation == Store::MutationOperation::Write) {
                Check(replacement.size() == request.length, "original exact replacement length");
                intent.wal_sequence = tx.NextMutationSequence();
                apfsaccess::rw::PayloadSpool::AppendResult reference;
                Check(spool.Append({"ordinary-lowspace-original", intent.object_id, intent.generation,
                    request.offset, intent.wal_sequence, replacement}, &reference), "actual immutable original spool append");
                intent.payload_length = reference.payload_length; intent.payload_spool_offset = reference.spool_offset;
                intent.payload_checksum = reference.payload_sha256;
            }
            Check(tx.RecordMutation(intent), "actual typed original WAL mutation");
        }
        Check(spool.FlushDirtyState() && tx.Accept(preimage), "actual payload and original acceptance flush");
        required.push_back(preimage);
        return true;
    };
    const auto finalize = [&] {
        const auto sequence = tx.Watermarks().accepted_sequence;
        Check(sequence && tx.MarkApfsDurableThrough(sequence) && tx.MarkCleanedThrough(sequence), "publication precedes durable original markers");
        Check(spool.CleanupThroughSequence(sequence), "original payload cleanup follows durability");
        std::string error;
        Check(owner->UpdateRequiredCheckpointXids(101, {}, error), "release only cleaned original checkpoint pin: " + error);
    };
    const auto payload = [&](const std::vector<std::byte>& bytes, const std::wstring& path) {
        const auto snapshot = std::make_shared<const std::vector<std::byte>>(bytes);
        store->SetFilePayloadRangeProvider([snapshot, path](const auto& name, auto, auto offset, std::span<std::byte> out) {
            if (name != path || offset > snapshot->size() || out.size() > snapshot->size() - offset) return false;
            std::copy_n(snapshot->begin() + offset, out.size(), out.begin()); return true;
        });
    };
    Store::MutationRequest write;
    write.operation = Store::MutationOperation::Write;
    write.path = L"\\space-pressure.bin";
    write.length = 65536;
    apfsaccess::catalog::ContainerCommitResult result;
    unsigned additional_writes = 0;
    std::uint64_t xid = initial_xid;
    for (unsigned attempt = 0; attempt < 16; ++attempt) {
        write.offset = expected.size();
        replacement.assign(65536, std::byte(((6 + attempt) * 31 + 9) & 255));
        auto postimage = expected; postimage.insert(postimage.end(), replacement.begin(), replacement.end());
        payload(postimage, write.path);
        accepts = 0; xid = owner->CheckpointXid();
        Check(owner->Device().ReadForVerification(0, before.size(), before), "current immutable refusal boundary");
        result = owner->Commit(101, {write}, binder);
        if (!result.committed) break;
        Check(accepts == 1, "one original acceptance per actual successful write");
        finalize(); expected = std::move(postimage); ++additional_writes;
        std::vector<std::byte> actual;
        Check(store->ReadCommittedFileRange(write.path, 0, expected.size(), actual) && actual == expected,
            "actual additional publication exact bytes before true exhaustion");
    }
    std::cout << "LOW_SPACE status=" << result.commit_status_code << " stage=" << result.commit_stage
        << " error=" << result.error << " clean=" << result.clean_prepublication_refusal
        << " recovery=" << result.commit_recovery_required << " accepts=" << accepts
        << " additionalWrites=" << additional_writes << " bytes=" << expected.size() << '\n';
    std::vector<std::byte> after;
    Check(!result.committed && !accepts && owner->Device().ReadForVerification(0, before.size(), after) && before == after,
        "actual refusal occurs before acceptance and device writes");
    Check(owner->CheckpointXid() == xid && store->PendingMutationCount() == 0 && !store->IsRecoveryRequired(),
        "original checkpoint and clean writer remain after rollback");
    const bool planner_capacity = result.commit_status_code == static_cast<int>(Store::CommitStatus::CapacityBlocked);
    const bool extent_allocation = result.mutation_staging_status == Store::MutationStatus::AllocationFailed &&
        result.commit_stage == "mutation-staging";
    Check((planner_capacity || extent_allocation) &&
        result.clean_prepublication_refusal && !result.commit_recovery_required,
        "actual allocator refusal has typed clean retryable capacity result");
    Check(additional_writes > 0, "previous six-chunk geometry refusal is repaired before genuine allocator exhaustion");
    Check(extent_allocation || result.error.find("AppleSpacemanMainPoolExhausted") != std::string::npos,
        "no generic planner or structural error is relabeled as capacity");
    Check(tx.CanClearRecoveryState() && !owner->IsRecoveryRequired(), "no accepted/debt/recovery state after clean DiskFull");
    Store::MutationRequest remove; remove.operation = Store::MutationOperation::Delete; remove.path = write.path;
    const auto reclaimed = owner->Commit(101, {remove}, binder);
    std::cout << "RECLAIM committed=" << reclaimed.committed << " error=" << reclaimed.error << '\n';
    Check(reclaimed.committed, "ordinary writer remains admitted for deleting filler"); finalize();
    Store::MutationRequest create; create.operation = Store::MutationOperation::CreateFile; create.path = L"\\after-space.bin";
    Check(owner->Commit(101, {create}, binder).committed, "create after space-releasing publication"); finalize();
    replacement.assign(65536, std::byte{0x6d}); payload(replacement, create.path);
    write.path = create.path; write.offset = 0;
    Check(owner->Commit(101, {write}, binder).committed, "subsequent actual 64-KiB write succeeds after reclaim"); finalize();
    std::vector<std::byte> recovered;
    Check(store->ReadCommittedFileRange(write.path, 0, replacement.size(), recovered) && recovered == replacement,
        "subsequent reclaimed-space payload exact");
    for (const auto& [at, bytes] : historical) {
        std::vector<std::byte> actual;
        Check(owner->Device().ReadForVerification(at * 4096, 4096, actual) && actual == bytes, "all 49 historical pins remain exact");
    }
    // A real accepted delete followed by a publication cut must retain debt.
    store->SetCommitStageHook([](std::string_view stage) { return stage != "before-apple-publish"; });
    remove.path = write.path; accepts = 0;
    const auto interrupted = owner->Commit(101, {remove}, binder);
    std::cout << "ACCEPTED_CUT status=" << interrupted.commit_status_code << " recovery=" << interrupted.commit_recovery_required
        << " reason=" << interrupted.error << '\n';
    Check(!interrupted.committed && accepts == 1 && !interrupted.clean_prepublication_refusal &&
        interrupted.commit_recovery_required && owner->IsRecoveryRequired() && tx.HasUnappliedAcceptedWork(),
        "real acceptance/publication failure remains recovery-required with original debt");
    const auto accepted_preimage = owner->CheckpointXid();
    owner.reset();
    owner = Open(path, accepted_preimage);
    store = owner->FindSessionStore(101);
    Check(store->PendingMutationCount() == 0, "fresh accepted-replay owner initially has empty staging");
    Check(owner->Device().ReadForVerification(0, before.size(), before), "fresh replay preimage bytes");
    store->SetCommitStageHook([](std::string_view stage) { return stage != "before-apple-publish"; });
    const auto replay = owner->Commit(101, {remove}, {}, {}, {}, true, accepted_preimage);
    std::cout << "REPLAY_CUT status=" << replay.commit_status_code << " recovery=" << replay.commit_recovery_required
        << " reason=" << replay.error << '\n';
    Check(!replay.committed && !replay.clean_prepublication_refusal && replay.commit_recovery_required &&
        owner->IsRecoveryRequired() && tx.HasUnappliedAcceptedWork(), "fresh authenticated accepted replay failure retains recovery debt");
    Check(owner->Device().ReadForVerification(0, before.size(), after) && before == after,
        "both before-publication cuts leave exact durable image unchanged");
}
}
int main(int argc, char** argv) {
    try {
        Check(argc == 2, "exact preserved generated image input required");
        const std::filesystem::path original(argv[1]);
        Check(original.is_absolute() && original.root_name() == L"D:" &&
            std::filesystem::current_path().root_name() == L"D:", "private D inputs and outputs only");
        ActualLowSpace(original);
        std::cout << "RESULT PASS checks=" << checks << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "RESULT FAIL checks=" << checks << " error=" << error.what() << '\n';
        return 1;
    }
}
