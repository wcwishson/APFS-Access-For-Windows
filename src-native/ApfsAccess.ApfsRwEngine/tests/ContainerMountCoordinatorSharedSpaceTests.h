#pragma once

#include <cstdlib>
#include <new>

// Only the explicitly armed committing thread fails one allocation. Arming at
// the existing postpublication verifier isolates the snapshot make_shared;
// native publication/WAL allocations have already completed. All other test
// allocations preserve normal new-handler behavior.
namespace shared_space_allocation_test
{
thread_local bool fail_next = false;
thread_local unsigned failures = 0;
}

void* operator new(std::size_t size)
{
    if (shared_space_allocation_test::fail_next)
    {
        shared_space_allocation_test::fail_next = false;
        ++shared_space_allocation_test::failures;
        throw std::bad_alloc();
    }
    for (;;)
    {
        if (void* allocation = std::malloc(size ? size : 1)) return allocation;
        const auto handler = std::get_new_handler();
        if (!handler) throw std::bad_alloc();
        handler();
    }
}

void operator delete(void* allocation) noexcept { std::free(allocation); }
void operator delete(void* allocation, std::size_t) noexcept { std::free(allocation); }

// Included in the existing coordinator test translation unit, after its
// canonical fixture helpers. All I/O targets that suite's private temp images.
namespace shared_space_tests
{
using apfsaccess::catalog::ContainerMountCoordinator;
using apfsaccess::catalog::ContainerVolumeSession;
using apfsaccess::rw::MetadataStore;

std::unique_ptr<ContainerMountCoordinator> Open(const char* name, bool mount = true)
{
    const auto image = MakeRunDir(name) / "two.raw";
    if (!Require(WriteAuthoritativeTwoVolumeImage(image), "shared-space: canonical two-volume fixture"))
        return nullptr;
    std::string error;
    auto coordinator = ContainerMountCoordinator::Open(image.string(), 0, error);
    if (!Require(coordinator != nullptr, "shared-space: strict open")) return nullptr;
    if (mount)
    {
        for (const auto oid : {101ULL, 102ULL})
        {
            ContainerVolumeSession session{};
            session.volume_object_id = oid;
            session.container_uuid_hex = coordinator->ContainerUuidHex();
            session.requested_write = true;
            session.use_canonical_transaction = true;
            if (!Require(coordinator->MountVolume(session, error), "shared-space: mount sibling")) return nullptr;
        }
    }
    return coordinator;
}

MetadataStore::MutationRequest Create(const wchar_t* path)
{
    MetadataStore::MutationRequest request{};
    request.operation = MetadataStore::MutationOperation::CreateFile;
    request.path = path;
    return request;
}

bool TestIdentitiesAndLegacy()
{
    auto coordinator = Open("shared-space-identities", false);
    if (!coordinator) return false;
    const auto uuid = coordinator->ContainerUuidHex();
    const auto alpha = coordinator->LookupSharedSpace(uuid, 101);
    const auto beta = coordinator->LookupSharedSpace(uuid, 102);
    bool ok = Require(alpha && beta, "shared-space: available at authoritative open before mount");
    if (!ok) return false;
    const auto facade = apfsaccess::catalog::LookupContainerSharedSpace(coordinator.get(), uuid, 101);
    ok &= Require(facade && facade->checkpoint_xid == alpha->checkpoint_xid &&
        facade->available_bytes == alpha->available_bytes &&
        !apfsaccess::catalog::LookupContainerSharedSpace(nullptr, uuid, 101),
        "shared-space: opaque C++17 facade matches member lookup and accepts a null owner");
    ok &= Require(alpha->volume_object_id == 101 && beta->volume_object_id == 102 &&
        alpha->checkpoint_xid == 20 && beta->checkpoint_xid == 20 &&
        alpha->total_bytes == 512ULL * 4096 && alpha->allocation_unit_bytes == 4096 &&
        alpha->available_bytes == beta->available_bytes && alpha->available_bytes <= alpha->total_bytes,
        "shared-space: one shared total and container-qualified per-volume observations");
    auto upper = uuid;
    for (auto& ch : upper) if (ch >= 'a' && ch <= 'f') ch -= 'a' - 'A';
    ok &= Require(coordinator->LookupSharedSpace(upper, 101).has_value(), "shared-space: UUID case accepted");
    auto wrong_uuid = uuid;
    wrong_uuid[0] = wrong_uuid[0] == '0' ? '1' : '0';
    ok &= Require(!coordinator->LookupSharedSpace(wrong_uuid, 101) &&
        !coordinator->LookupSharedSpace(std::string(32, 'z'), 101) &&
        !coordinator->LookupSharedSpace({}, 101) && !coordinator->LookupSharedSpace(uuid + "0", 101) &&
        !coordinator->LookupSharedSpace(uuid, 0) && !coordinator->LookupSharedSpace(uuid, 999),
        "shared-space: missing, malformed, wrong-container and unknown-volume identities are unknown");
    const auto legacy_image = MakeRunDir("shared-space-legacy") / "legacy.raw";
    if (!Require(WriteTwoVolumeImage(legacy_image), "shared-space: legacy fixture")) return false;
    std::string error;
    auto legacy = OpenFixtureCoordinator(legacy_image, error);
    ok &= Require(legacy && !legacy->LookupSharedSpace(legacy->ContainerUuidHex(), 101),
        "shared-space: private legacy accounting remains unknown");
    return ok;
}

bool TestSiblingPublicationAndStaleRefresh()
{
    auto coordinator = Open("shared-space-sibling");
    if (!coordinator) return false;
    const auto uuid = coordinator->ContainerUuidHex();
    auto* alpha_store = coordinator->FindSessionStore(101);
    auto* beta_store = coordinator->FindSessionStore(102);
    const auto beta_loaded_xid = beta_store->CheckpointXid();
    const auto before = coordinator->LookupSharedSpace(uuid, 102);
    if (!Require(before.has_value(), "shared-space: mounted snapshot exists")) return false;
    const auto created = coordinator->Commit(101, {Create(L"\\capacity.bin")});
    alpha_store->SetFilePayloadProvider([](const std::wstring&, std::uint64_t size)
        -> std::optional<std::vector<std::byte>> { return std::vector<std::byte>(size, std::byte{0x4a}); });
    MetadataStore::MutationRequest write{};
    write.operation = MetadataStore::MutationOperation::Write;
    write.path = L"\\capacity.bin";
    write.length = 8192;
    const auto committed = coordinator->Commit(101, {write});
    bool ok = Require(created.committed && committed.committed &&
        committed.commit_status_code == static_cast<int>(MetadataStore::CommitStatus::Committed),
        "shared-space: real canonical allocation commits");
    const auto alpha = coordinator->LookupSharedSpace(uuid, 101);
    const auto beta = coordinator->LookupSharedSpace(uuid, 102);
    if (!Require(alpha && beta, "shared-space: both observations refreshed")) return false;
    ok &= Require(alpha->checkpoint_xid == committed.committed_xid &&
        beta->checkpoint_xid == alpha->checkpoint_xid && alpha->available_bytes == beta->available_bytes &&
        beta->available_bytes < before->available_bytes && beta_store->CheckpointXid() == beta_loaded_xid,
        "shared-space: sibling sees reduced free pool without reloading its store");
    apfsaccess::catalog::ApfsSharedSpaceProjection expected;
    std::string error;
    ok &= Require(apfsaccess::catalog::TryProjectAppleSharedSpace(
        *alpha_store->AuthoritativeAppleCheckpointView(), expected, error) &&
        alpha->total_bytes == expected.total.bytes && alpha->available_bytes == expected.volumes[0].available.bytes,
        "shared-space: exactly reuses checked projection");
    ok &= Require(coordinator->RefreshCheckpointFromSession(102, error), "shared-space: stale refresh retains existing contract");
    const auto after_stale = coordinator->LookupSharedSpace(uuid, 101);
    ok &= Require(after_stale && after_stale->checkpoint_xid == alpha->checkpoint_xid &&
        after_stale->available_bytes == alpha->available_bytes,
        "shared-space: stale sibling cannot regress checkpoint or space");
    ok &= Require(coordinator->RefreshSessionForRecovery(102, error) &&
        beta_store->CheckpointXid() == alpha->checkpoint_xid,
        "shared-space: explicit recovery reload observes current checkpoint");
    ok &= Require(coordinator->UnmountVolume(101, error) && coordinator->LookupSharedSpace(uuid, 102).has_value(),
        "shared-space: removing one session preserves sibling observation");
    ok &= Require(coordinator->UnmountVolume(102, error) && !coordinator->LookupSharedSpace(uuid, 102),
        "shared-space: last-session cleanup invalidates observations");
    ContainerVolumeSession remount{};
    remount.volume_object_id = 102; remount.container_uuid_hex = uuid; remount.use_canonical_transaction = true;
    ok &= Require(coordinator->MountVolume(remount, error) && coordinator->LookupSharedSpace(uuid, 102).has_value(),
        "shared-space: fresh authoritative remount restores observations");
    ok &= Require(coordinator->DrainAndStop(std::chrono::seconds(2)).clean &&
        !coordinator->LookupSharedSpace(uuid, 101) && !coordinator->LookupSharedSpace(uuid, 102),
        "shared-space: shutdown returns unknown for every volume");
    return ok;
}

bool TestHeldCommitLookup(bool drain)
{
    auto coordinator = Open(drain ? "shared-space-held-drain" : "shared-space-held-commit");
    if (!coordinator) return false;
    const auto uuid = coordinator->ContainerUuidHex();
    std::promise<void> entered_promise, release_promise;
    auto entered = entered_promise.get_future();
    auto release = release_promise.get_future().share();
    std::atomic<bool> announced{false};
    coordinator->FindSessionStore(101)->SetCommitStageHook([&](std::string_view stage) {
        if (stage == "before-apple-publish" && !announced.exchange(true))
        {
            entered_promise.set_value();
            release.wait();
        }
        return true;
    });
    auto commit = std::async(std::launch::async, [&] { return coordinator->Commit(101, {Create(L"\\held.bin")}); });
    if (!Require(entered.wait_for(std::chrono::seconds(5)) == std::future_status::ready,
        "shared-space: commit deliberately held at publication hook"))
    {
        release_promise.set_value();
        commit.wait();
        return false;
    }
    bool ok = true;
    if (drain)
        ok &= Require(!coordinator->DrainAndStop(std::chrono::milliseconds(20)).clean,
            "shared-space: active commit causes bounded drain timeout");
    auto lookup = std::async(std::launch::async, [&] {
        for (int i = 0; i < 1000; ++i)
            if (coordinator->LookupSharedSpace(uuid, 101) || coordinator->LookupSharedSpace(uuid, 102)) return false;
        return true;
    });
    const bool prompt = lookup.wait_for(std::chrono::milliseconds(250)) == std::future_status::ready;
    // Release before collecting a failing future so a regression cannot hang
    // the test runner waiting for the same commit lock it is trying to test.
    release_promise.set_value();
    const auto result = commit.get();
    ok &= Require(prompt, "shared-space: 2000 lookups complete while commit lock is held");
    ok &= Require(lookup.get(), "shared-space: publication boundary exposes conservative unknown");
    ok &= Require(result.committed, "shared-space: held commit remains durable");
    if (drain)
    {
        ok &= Require(!coordinator->LookupSharedSpace(uuid, 101), "shared-space: completed in-flight commit cannot revive drained cache");
        ok &= Require(coordinator->DrainAndStop(std::chrono::seconds(2)).clean, "shared-space: final drain completes");
    }
    else
    {
        const auto alpha = coordinator->LookupSharedSpace(uuid, 101);
        const auto beta = coordinator->LookupSharedSpace(uuid, 102);
        ok &= Require(alpha && beta && alpha->checkpoint_xid == result.committed_xid &&
            beta->checkpoint_xid == result.committed_xid, "shared-space: completion publishes one sibling generation");
    }
    return ok;
}

bool TestFailedPublicationCannotRestoreStaleSession(int mode)
{
    const bool verifier_failure = mode == 2;
    auto coordinator = Open(verifier_failure ? "shared-space-verifier-failure" : "shared-space-publication-failure");
    if (!coordinator) return false;
    const auto uuid = coordinator->ContainerUuidHex();
    if (!verifier_failure)
        coordinator->FindSessionStore(101)->SetCommitStageHook([mode](std::string_view stage) {
            return stage != (mode == 0 ? "before-apple-publish" : "before-apple-final-flush");
        });
    apfsaccess::catalog::ContainerPostpublicationVerifierHook verifier;
    if (verifier_failure) verifier = [](const MetadataStore&, std::uint64_t, std::string&) { return false; };
    const auto result = coordinator->Commit(101, {Create(L"\\uncertain.bin")}, {}, {}, {}, false,
        std::nullopt, {}, verifier);
    bool ok = Require(result.commit_recovery_required == (mode != 0) && result.committed == verifier_failure,
        "shared-space: preserves failed or durable-but-unverified commit outcome");
    ok &= Require(!coordinator->LookupSharedSpace(uuid, 101) && !coordinator->LookupSharedSpace(uuid, 102),
        "shared-space: uncertain publication invalidates every sibling");
    std::string error;
    (void)coordinator->RefreshCheckpointFromSession(102, error);
    ok &= Require(!coordinator->LookupSharedSpace(uuid, 102), "shared-space: stale refresh cannot undo invalidation");
    if (mode == 0)
    {
        coordinator->FindSessionStore(101)->SetCommitStageHook({});
        const auto resumed = coordinator->Commit(102, {Create(L"\\resumed.bin")});
        const auto alpha = coordinator->LookupSharedSpace(uuid, 101);
        const auto beta = coordinator->LookupSharedSpace(uuid, 102);
        ok &= Require(resumed.committed && alpha && beta && alpha->checkpoint_xid == resumed.committed_xid &&
            beta->checkpoint_xid == resumed.committed_xid,
            "shared-space: subsequent successful sibling commit restores the new generation");
    }
    return ok;
}

bool TestSnapshotAllocationFailurePreservesDurableResult()
{
    auto coordinator = Open("shared-space-allocation-failure");
    if (!coordinator) return false;
    const auto uuid = coordinator->ContainerUuidHex();
    const auto failures_before = shared_space_allocation_test::failures;
    apfsaccess::catalog::ContainerCommitResult result;
    bool threw = false;
    try
    {
        result = coordinator->Commit(101, {Create(L"\\durable.bin")}, {}, {}, {}, false, std::nullopt, {},
            [](const MetadataStore&, std::uint64_t, std::string&) {
                shared_space_allocation_test::fail_next = true;
                return true;
            });
    }
    catch (...)
    {
        threw = true;
    }
    shared_space_allocation_test::fail_next = false;
    bool ok = Require(!threw && shared_space_allocation_test::failures == failures_before + 1 &&
        result.committed && result.commit_status_code == static_cast<int>(MetadataStore::CommitStatus::Committed) &&
        !result.commit_recovery_required && !coordinator->IsRecoveryRequired(),
        "shared-space: snapshot allocation failure does not throw or change durable commit/recovery result");
    ok &= Require(coordinator->FindSessionStore(101)->LookupCommittedInodeByPath(L"\\durable.bin").has_value() &&
        !coordinator->LookupSharedSpace(uuid, 101) && !coordinator->LookupSharedSpace(uuid, 102),
        "shared-space: durable namespace retained while both space observations are unknown");
    std::string error;
    ok &= Require(coordinator->RefreshCheckpointFromSession(102, error) && !coordinator->LookupSharedSpace(uuid, 102),
        "shared-space: stale session cannot resurrect cache after allocation failure");
    ok &= Require(coordinator->RefreshCheckpointFromSession(101, error) && !coordinator->LookupSharedSpace(uuid, 101),
        "shared-space: borrowed current session also cannot certify freshness after invalidation");
    ok &= Require(coordinator->RefreshSessionForRecovery(102, error), "shared-space: recovery obtains a fresh authoritative view");
    const auto refreshed = coordinator->LookupSharedSpace(uuid, 102);
    ok &= Require(refreshed && refreshed->checkpoint_xid == result.committed_xid,
        "shared-space: authoritative recovery reload restores the durable generation");
    return ok;
}
} // namespace shared_space_tests
