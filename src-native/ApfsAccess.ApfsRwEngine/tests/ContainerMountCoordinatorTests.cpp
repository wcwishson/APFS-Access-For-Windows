// RED: ContainerMountCoordinator does not exist yet. Each test names the
// seam or API it pins; link failure is the RED signal until GREEN.

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "ContainerMountCoordinator.h"
#include "MetadataStore.h"
#include "TestFixtureBuilder.h"
#include "../tools/Sha256.h"

namespace
{

namespace testfixture = apfsaccess::testfixture;

int g_failures = 0;
std::mutex g_run_dirs_mutex;
std::vector<std::filesystem::path> g_run_dirs;

bool Require(bool condition, const char* message)
{
    if (!condition)
    {
        ++g_failures;
        std::fprintf(stderr, "[FAIL] %s\n", message);
    }
    return condition;
}

void TraceCommittedPaths(
    const char* label, const apfsaccess::rw::MetadataStore* store)
{
    if (store == nullptr)
    {
        std::fprintf(stderr, "[INFO] %s: store missing\n", label);
        return;
    }
    const auto inodes = store->SnapshotCommittedInodes();
    std::fprintf(stderr, "[INFO] %s: %zu committed inode(s)\n", label, inodes.size());
    for (const auto& inode : inodes)
    {
        std::string path;
        path.reserve(inode.full_path.size());
        for (const wchar_t ch : inode.full_path)
        {
            path.push_back(ch >= 0 && ch <= 0x7f ? static_cast<char>(ch) : '?');
        }
        std::fprintf(
            stderr,
            "[INFO] %s: oid=%llu path=%s\n",
            label,
            static_cast<unsigned long long>(inode.object_id),
            path.c_str());
    }
}

std::filesystem::path MakeRunDir(const char* name)
{
    // Unique per process invocation: the store persists sidecars keyed by
    // device path, so reusing a fixed fixture path across runs with a
    // truncated image would (correctly) trip fail-closed divergence.
    // Every directory created here is removed at process end (see main), so
    // repeated runs cannot pollute the temp volume.
    static std::atomic<unsigned> s_counter{0};
    const auto unique = std::string(name) + "-" +
        std::to_string(
            static_cast<unsigned long long>(
                std::chrono::steady_clock::now().time_since_epoch().count())) +
        "-" + std::to_string(s_counter.fetch_add(1));
    auto dir = std::filesystem::temp_directory_path() / "apfs-coord" / unique;
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
    std::filesystem::create_directories(dir, ec);
    {
        std::lock_guard<std::mutex> lock(g_run_dirs_mutex);
        g_run_dirs.push_back(dir);
    }
    return dir;
}

bool RemovePersistentStateSidecars()
{
    std::error_code ec;
    auto root = std::filesystem::temp_directory_path(ec);
    if (ec)
    {
        return false;
    }
    root /= "ApfsAccess";
    root /= "rw-state";
    std::filesystem::remove_all(root, ec);
    return !ec;
}

bool WriteTwoVolumeImage(
    const std::filesystem::path& path, bool duplicate_names = false)
{
    testfixture::BuilderVolume alpha;
    alpha.oid = 101;
    alpha.name = "Alpha";
    alpha.projectable = true;
    testfixture::BuilderVolume beta;
    beta.oid = 102;
    beta.name = duplicate_names ? "Alpha" : "Beta";
    beta.projectable = true;
    testfixture::BuilderStore store;
    store.volumes = {alpha, beta};
    store.spaceman_oid = 8;
    store.spaceman_block = 60;
    // The store's ephemeral allocator starts past the first 1 MiB of
    // metadata room; a 64-block toy container would leave it no room.
    store.block_count = 512;
    const auto bytes = testfixture::BuildStoreImage(store);
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out.good())
    {
        return false;
    }
    out.write(
        reinterpret_cast<const char*>(bytes.data()),
        static_cast<std::streamsize>(bytes.size()));
    return static_cast<bool>(out);
}

bool WriteAuthoritativeTwoVolumeImage(
    const std::filesystem::path& path,
    std::uint64_t main_free_blocks = 0)
{
    testfixture::BuilderVolume alpha;
    alpha.oid = 101;
    alpha.name = "Alpha";
    testfixture::BuilderVolume beta;
    beta.oid = 102;
    beta.name = "Beta";
    testfixture::BuilderStore store;
    store.authoritative_checkpoint = true;
    store.dual_checkpoint = false;
    store.xid = 20;
    store.block_count = 512;
    store.authoritative_main_free_blocks = main_free_blocks;
    store.volumes = {alpha, beta};
    const auto bytes = testfixture::BuildStoreImage(store);
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out.good())
    {
        return false;
    }
    out.write(
        reinterpret_cast<const char*>(bytes.data()),
        static_cast<std::streamsize>(bytes.size()));
    return static_cast<bool>(out);
}

std::unique_ptr<apfsaccess::catalog::ContainerMountCoordinator>
OpenFixtureCoordinator(
    const std::filesystem::path& image,
    std::string& error)
{
    return apfsaccess::catalog::ContainerMountCoordinator::Open(
        image.string(),
        0,
        error,
        apfsaccess::catalog::CatalogLoadPolicy::AllowLegacySynthetic);
}

bool TestCoordinatorAcquiresWritableLeaseBeforeServing()
{
    const auto run_root = MakeRunDir("writable-lease-at-open");
    const auto image = run_root / "container.apfs.img";
    if (!WriteTwoVolumeImage(image))
    {
        return Require(false, "writable lease: create fixture");
    }

    std::string error;
    auto coordinator = apfsaccess::catalog::ContainerMountCoordinator::Open(
        image.string(),
        0,
        error,
        apfsaccess::catalog::CatalogLoadPolicy::AllowLegacySynthetic,
        true);
    return Require(coordinator != nullptr, "writable lease: open coordinator") &&
        Require(error.empty(), "writable lease: no open error") &&
        Require(
            coordinator->Device().HasWriteHandle(),
            "writable lease: write handle is acquired before any session is served");
}

std::vector<std::byte> ReadFileBytes(const std::filesystem::path& path)
{
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input.good())
    {
        return {};
    }
    const auto length = input.tellg();
    if (length <= 0)
    {
        return {};
    }
    std::vector<std::byte> bytes(static_cast<std::size_t>(length));
    input.seekg(0, std::ios::beg);
    input.read(
        reinterpret_cast<char*>(bytes.data()),
        static_cast<std::streamsize>(bytes.size()));
    return input.good() ? bytes : std::vector<std::byte>{};
}

bool WriteFileBytes(
    const std::filesystem::path& path, const std::vector<std::byte>& bytes)
{
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(
        reinterpret_cast<const char*>(bytes.data()),
        static_cast<std::streamsize>(bytes.size()));
    return static_cast<bool>(output);
}

std::uint32_t ReadLe32(
    const std::vector<std::byte>& bytes, std::size_t offset)
{
    if (offset > bytes.size() || sizeof(std::uint32_t) > bytes.size() - offset)
    {
        return 0;
    }
    return static_cast<std::uint32_t>(std::to_integer<unsigned char>(bytes[offset])) |
        (static_cast<std::uint32_t>(std::to_integer<unsigned char>(bytes[offset + 1])) << 8) |
        (static_cast<std::uint32_t>(std::to_integer<unsigned char>(bytes[offset + 2])) << 16) |
        (static_cast<std::uint32_t>(std::to_integer<unsigned char>(bytes[offset + 3])) << 24);
}

std::uint64_t ReadLe64(
    const std::vector<std::byte>& bytes, std::size_t offset)
{
    std::uint64_t value = 0;
    if (offset > bytes.size() || sizeof(value) > bytes.size() - offset)
    {
        return 0;
    }
    for (int index = 0; index < 8; ++index)
    {
        value |= static_cast<std::uint64_t>(
            std::to_integer<unsigned char>(bytes[offset + index])) << (8 * index);
    }
    return value;
}

void WriteLe32(
    std::vector<std::byte>& bytes, std::size_t offset, std::uint32_t value)
{
    for (int index = 0; index < 4; ++index)
    {
        bytes[offset + index] =
            static_cast<std::byte>((value >> (8 * index)) & 0xffu);
    }
}

void WriteLe64(
    std::vector<std::byte>& bytes, std::size_t offset, std::uint64_t value)
{
    for (int index = 0; index < 8; ++index)
    {
        bytes[offset + index] =
            static_cast<std::byte>((value >> (8 * index)) & 0xffu);
    }
}

std::uint32_t Fnv1a(
    const std::vector<std::byte>& bytes, std::size_t offset, std::size_t length)
{
    std::uint32_t hash = 2166136261u;
    for (std::size_t index = 0; index < length; ++index)
    {
        hash ^= static_cast<std::uint32_t>(
            std::to_integer<unsigned char>(bytes[offset + index]));
        hash *= 16777619u;
    }
    return hash;
}

std::optional<std::size_t> FindMagic(
    const std::vector<std::byte>& bytes, const std::array<char, 13>& magic)
{
    const auto found = std::search(
        bytes.begin(), bytes.end(), magic.begin(), magic.end(),
        [](std::byte left, char right)
        {
            return std::to_integer<unsigned char>(left) ==
                static_cast<unsigned char>(right);
        });
    if (found == bytes.end())
    {
        return std::nullopt;
    }
    return static_cast<std::size_t>(std::distance(bytes.begin(), found));
}

std::optional<std::size_t> SharedCommitBlobPayloadEnd(
    const std::vector<std::byte>& bytes, std::size_t blob_offset)
{
    constexpr std::size_t kPayloadOffsetV4 = 125;
    if (blob_offset > bytes.size() || kPayloadOffsetV4 > bytes.size() - blob_offset)
    {
        return std::nullopt;
    }
    const auto object_maps = ReadLe32(bytes, blob_offset + 33);
    const auto allocations = ReadLe32(bytes, blob_offset + 37);
    const auto deallocations = ReadLe32(bytes, blob_offset + 41);
    const auto btree_records = ReadLe32(bytes, blob_offset + 45);
    std::size_t cursor = blob_offset + kPayloadOffsetV4;
    const auto advance = [&](std::size_t count, std::size_t width) -> bool
    {
        if (count != 0 && width > (bytes.size() - cursor) / count)
        {
            return false;
        }
        cursor += count * width;
        return cursor <= bytes.size();
    };
    if (!advance(object_maps, 32) ||
        !advance(allocations, 16) ||
        !advance(deallocations, 16))
    {
        return std::nullopt;
    }
    for (std::uint32_t index = 0; index < btree_records; ++index)
    {
        if (!advance(1, 16))
        {
            return std::nullopt;
        }
        const auto key_size = ReadLe32(bytes, cursor - 8);
        const auto value_size = ReadLe32(bytes, cursor - 4);
        if (key_size > bytes.size() - cursor ||
            value_size > bytes.size() - cursor - key_size)
        {
            return std::nullopt;
        }
        cursor += static_cast<std::size_t>(key_size) + value_size;
    }
    return cursor;
}

std::size_t PersistentStateSidecarCount()
{
    std::error_code ec;
    auto root = std::filesystem::temp_directory_path(ec);
    if (ec)
    {
        return 0;
    }
    root /= "ApfsAccess";
    root /= "rw-state";
    if (!std::filesystem::exists(root, ec) || ec)
    {
        return 0;
    }
    std::size_t count = 0;
    for (std::filesystem::directory_iterator it(root, ec), end;
         !ec && it != end;
         it.increment(ec))
    {
        if (it->is_regular_file(ec) && !ec)
        {
            ++count;
        }
    }
    return ec ? 0 : count;
}

// T_shared_lease: two sessions on one container must share a single raw
// lease (identical BlockDevice identity). RED while each MetadataStore owns
// a private device.
bool TestSessionsShareOneRawLease()
{
    const auto dir = MakeRunDir("shared-lease");
    const auto image = dir / "two.apfs.img";
    if (!Require(WriteTwoVolumeImage(image), "shared-lease: build fixture"))
    {
        return false;
    }
    apfsaccess::rw::MetadataStore::VolumeContext alpha_ctx{};
    alpha_ctx.device_path = image.wstring();
    alpha_ctx.volume_name = L"Alpha";
    alpha_ctx.volume_object_id = 101;
    apfsaccess::rw::MetadataStore::VolumeContext beta_ctx{};
    beta_ctx.device_path = image.wstring();
    beta_ctx.volume_name = L"Beta";
    beta_ctx.volume_object_id = 102;
    // The seam under test: both sessions share one externally owned lease.
    auto lease = std::make_shared<apfsaccess::rw::BlockDevice>(
        image.wstring(), 0);
    apfsaccess::rw::MetadataStore alpha(std::move(alpha_ctx), lease);
    apfsaccess::rw::MetadataStore beta(std::move(beta_ctx), lease);
    if (!Require(alpha.LoadContainerState(), "shared-lease: alpha load") ||
        !Require(beta.LoadContainerState(), "shared-lease: beta load"))
    {
        return false;
    }
    return Require(
        &alpha.Device() == &beta.Device(),
        "shared-lease: sessions must share one BlockDevice lease");
}

// T_coordinator_opens_container: single lease, one container identity,
// current-process ownership, zero mounts.
bool TestCoordinatorOpensSingleContainer()
{
    const auto dir = MakeRunDir("open");
    const auto image = dir / "two.apfs.img";
    if (!Require(WriteTwoVolumeImage(image), "open: build fixture"))
    {
        return false;
    }
    std::string error;
    auto coordinator = OpenFixtureCoordinator(image, error);
    if (!Require(coordinator != nullptr, "open: coordinator must open"))
    {
        std::fprintf(stderr, "[INFO] open error: %s\n", error.c_str());
        return false;
    }
    bool ok = true;
    ok &= Require(coordinator->RawLeaseHeld(), "open: raw lease held");
    ok &= Require(
        coordinator->MountedVolumeCount() == 0, "open: zero mounts at open");
    ok &= Require(
        coordinator->CheckpointXid() != 0, "open: checkpoint xid captured");
    ok &= Require(
        !coordinator->ContainerUuidHex().empty(), "open: container uuid known");
    ok &= Require(
        !coordinator->IsRecoveryRequired(), "open: no recovery latched");
    return ok;
}

// T_coordinator_mounts_two_volumes: container-qualified sessions, shared
// device identity, independent mount entries.
bool TestCoordinatorMountsTwoVolumes()
{
    const auto dir = MakeRunDir("mount-two");
    const auto image = dir / "two.apfs.img";
    if (!Require(WriteTwoVolumeImage(image), "mount-two: build fixture"))
    {
        return false;
    }
    std::string error;
    auto coordinator = OpenFixtureCoordinator(image, error);
    if (!Require(coordinator != nullptr, "mount-two: open"))
    {
        return false;
    }
    const std::string uuid = coordinator->ContainerUuidHex();
    apfsaccess::catalog::ContainerVolumeSession alpha{};
    alpha.volume_object_id = 101;
    alpha.container_uuid_hex = uuid;
    alpha.mount_point = "A:\\mnt\\Alpha";
    alpha.requested_write = true;
    apfsaccess::catalog::ContainerVolumeSession beta{};
    beta.volume_object_id = 102;
    beta.container_uuid_hex = uuid;
    beta.mount_point = "A:\\mnt\\Beta";
    bool ok = true;
    ok &= Require(
        coordinator->MountVolume(alpha, error), "mount-two: mount Alpha");
    if (!ok)
    {
        std::fprintf(stderr, "[INFO] mount error: %s\n", error.c_str());
        return false;
    }
    ok &= Require(
        coordinator->MountVolume(beta, error), "mount-two: mount Beta");
    ok &= Require(
        coordinator->MountedVolumeCount() == 2, "mount-two: two sessions");
    return ok;
}

// T_coordinator_rejects_mismatch: unknown OID, wrong container UUID, and
// duplicate mount all fail closed.
bool TestCoordinatorRejectsMismatch()
{
    const auto dir = MakeRunDir("reject");
    const auto image = dir / "two.apfs.img";
    if (!Require(WriteTwoVolumeImage(image), "reject: build fixture"))
    {
        return false;
    }
    std::string error;
    auto coordinator = OpenFixtureCoordinator(image, error);
    if (!Require(coordinator != nullptr, "reject: open"))
    {
        return false;
    }
    const std::string uuid = coordinator->ContainerUuidHex();
    bool ok = true;
    apfsaccess::catalog::ContainerVolumeSession unknown{};
    unknown.volume_object_id = 999;
    unknown.container_uuid_hex = uuid;
    ok &= Require(
        !coordinator->MountVolume(unknown, error), "reject: unknown OID");
    apfsaccess::catalog::ContainerVolumeSession wrong_container{};
    wrong_container.volume_object_id = 101;
    wrong_container.container_uuid_hex =
        "00000000000000000000000000000000";
    ok &= Require(
        !coordinator->MountVolume(wrong_container, error),
        "reject: container mismatch");
    apfsaccess::catalog::ContainerVolumeSession alpha{};
    alpha.volume_object_id = 101;
    alpha.container_uuid_hex = uuid;
    ok &= Require(
        coordinator->MountVolume(alpha, error), "reject: first mount");
    ok &= Require(
        !coordinator->MountVolume(alpha, error), "reject: duplicate mount");
    ok &= Require(
        coordinator->MountedVolumeCount() == 1, "reject: count unchanged");
    return ok;
}

bool TestRejectedCommitNeverReportsCommittedStatus()
{
    const auto root = MakeRunDir("rejected-status");
    const auto image = root / "two.apfs.img";
    if (!Require(WriteTwoVolumeImage(image), "rejected-status: build fixture"))
    {
        return false;
    }
    std::string error;
    auto coordinator = OpenFixtureCoordinator(image, error);
    bool ok = Require(coordinator != nullptr, "rejected-status: open");
    if (!coordinator)
    {
        std::filesystem::remove_all(root);
        return false;
    }

    const auto result = coordinator->Commit(999999, {});
    ok &= Require(!result.committed, "rejected-status: not committed");
    ok &= Require(
        result.commit_status_code == static_cast<int>(
            apfsaccess::rw::MetadataStore::CommitStatus::NotReady),
        "rejected-status: not-ready status");
    ok &= Require(
        result.error == "VolumeNotMounted", "rejected-status: error");

    const auto shutdown = coordinator->DrainAndStop(
        std::chrono::seconds(2));
    ok &= Require(shutdown.clean, "rejected-status: shutdown");
    std::filesystem::remove_all(root);
    return ok;
}

// T_coordinator_unmount_sibling_safe: unmounting one session leaves the
// sibling and shared state untouched; unknown OIDs fail closed.
bool TestCoordinatorUnmountSiblingSafe()
{
    const auto dir = MakeRunDir("unmount");
    const auto image = dir / "two.apfs.img";
    if (!Require(WriteTwoVolumeImage(image), "unmount: build fixture"))
    {
        return false;
    }
    std::string error;
    auto coordinator = OpenFixtureCoordinator(image, error);
    if (!Require(coordinator != nullptr, "unmount: open"))
    {
        return false;
    }
    const std::string uuid = coordinator->ContainerUuidHex();
    apfsaccess::catalog::ContainerVolumeSession alpha{};
    alpha.volume_object_id = 101;
    alpha.container_uuid_hex = uuid;
    apfsaccess::catalog::ContainerVolumeSession beta{};
    beta.volume_object_id = 102;
    beta.container_uuid_hex = uuid;
    bool ok = true;
    ok &= Require(
        coordinator->MountVolume(alpha, error), "unmount: mount Alpha");
    ok &= Require(
        coordinator->MountVolume(beta, error), "unmount: mount Beta");
    if (!ok)
    {
        return false;
    }
    ok &= Require(
        !coordinator->UnmountVolume(999, error), "unmount: unknown fails");
    ok &= Require(
        coordinator->UnmountVolume(101, error), "unmount: unmount Alpha");
    ok &= Require(
        coordinator->MountedVolumeCount() == 1, "unmount: sibling survives");
    ok &= Require(coordinator->RawLeaseHeld(), "unmount: lease survives");
    ok &= Require(
        coordinator->MountVolume(alpha, error), "unmount: remount works");
    ok &= Require(
        coordinator->MountedVolumeCount() == 2, "unmount: both back");
    return ok;
}

// T_coordinator_serialized_commits: concurrent commits on sibling sessions
// never overlap (max observed concurrency 1) and all succeed.
bool TestCoordinatorSerializesCommits()
{
    const auto dir = MakeRunDir("commits");
    const auto image = dir / "two.apfs.img";
    if (!Require(WriteTwoVolumeImage(image), "commits: build fixture"))
    {
        return false;
    }
    std::string error;
    auto coordinator = OpenFixtureCoordinator(image, error);
    if (!Require(coordinator != nullptr, "commits: open"))
    {
        return false;
    }
    const std::string uuid = coordinator->ContainerUuidHex();
    bool ok = true;
    for (const std::uint64_t oid : {101ULL, 102ULL})
    {
        apfsaccess::catalog::ContainerVolumeSession session{};
        session.volume_object_id = oid;
        session.container_uuid_hex = uuid;
        session.requested_write = true;
        ok &= Require(
            coordinator->MountVolume(session, error), "commits: mount");
    }
    if (!ok)
    {
        std::fprintf(stderr, "[INFO] commits mount error: %s\n", error.c_str());
        return false;
    }
    std::atomic<int> failures{0};
    auto worker = [&](std::uint64_t oid, const wchar_t* name) {
        for (int i = 0; i < 4; ++i)
        {
            apfsaccess::rw::MetadataStore::MutationRequest m{};
            m.operation = apfsaccess::rw::MetadataStore::MutationOperation::
                CreateFile;
            m.path = std::wstring(L"\\t") + name + std::to_wstring(i) +
                L".bin";
            auto result = coordinator->Commit(oid, {m});
            if (!result.committed)
            {
                ++failures;
                std::fprintf(
                    stderr, "[INFO] commit failed: %s\n",
                    result.error.c_str());
            }
        }
    };
    std::thread first(worker, 101ULL, L"a");
    std::thread second(worker, 102ULL, L"b");
    first.join();
    second.join();
    ok &= Require(failures.load() == 0, "commits: all commits succeed");
    ok &= Require(
        !coordinator->IsRecoveryRequired(),
        "commits: no ledger overlap or refresh failure latched");
    ok &= Require(
        coordinator->MaxObservedCommitConcurrency() <= 1,
        "commits: serialized (max concurrency 1)");
    return ok;
}

// Every sibling commit must start from the latest container checkpoint. Two
// per-volume stores may not independently reuse the same target XID.
bool TestCoordinatorAdvancesOneGlobalCheckpointSequence()
{
    const auto dir = MakeRunDir("global-xid");
    const auto image = dir / "two.apfs.img";
    if (!Require(WriteTwoVolumeImage(image), "global-xid: build fixture"))
    {
        return false;
    }
    std::string error;
    auto coordinator = OpenFixtureCoordinator(image, error);
    if (!Require(coordinator != nullptr, "global-xid: open"))
    {
        return false;
    }
    const auto initial_xid = coordinator->CheckpointXid();
    const std::string uuid = coordinator->ContainerUuidHex();
    for (const std::uint64_t oid : {101ULL, 102ULL})
    {
        apfsaccess::catalog::ContainerVolumeSession session{};
        session.volume_object_id = oid;
        session.container_uuid_hex = uuid;
        session.requested_write = true;
        if (!Require(
                coordinator->MountVolume(session, error),
                "global-xid: mount sibling"))
        {
            return false;
        }
    }

    std::vector<std::uint64_t> committed_xids;
    for (int index = 0; index < 8; ++index)
    {
        const std::uint64_t oid = index % 2 == 0 ? 101ULL : 102ULL;
        apfsaccess::rw::MetadataStore::MutationRequest mutation{};
        mutation.operation =
            apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        mutation.path = L"\\global-xid-" + std::to_wstring(index) + L".bin";
        const auto result = coordinator->Commit(oid, {mutation});
        if (!Require(result.committed, "global-xid: commit succeeds"))
        {
            std::fprintf(
                stderr, "[INFO] global-xid commit failed: %s\n",
                result.error.c_str());
            return false;
        }
        committed_xids.push_back(result.committed_xid);
    }

    std::sort(committed_xids.begin(), committed_xids.end());
    bool ok = true;
    for (std::size_t index = 0; index < committed_xids.size(); ++index)
    {
        ok &= Require(
            committed_xids[index] == initial_xid + index + 1,
            "global-xid: commits consume unique contiguous XIDs");
    }
    ok &= Require(
        coordinator->CheckpointXid() == initial_xid + committed_xids.size(),
        "global-xid: coordinator tracks the final checkpoint");
    return ok;
}

// Alternating commits must survive a complete owner restart without merging
// sibling namespaces. This is the unit-level counterpart to the physical
// crash/remount gate in Task 2 Step 5.
bool TestCoordinatorPreservesAlternatingNamespacesAcrossRemount()
{
    const auto dir = MakeRunDir("alternating-remount");
    const auto image = dir / "two.apfs.img";
    if (!Require(
            WriteTwoVolumeImage(image), "alternating-remount: build fixture"))
    {
        return false;
    }
    std::string error;
    auto coordinator = OpenFixtureCoordinator(image, error);
    if (!Require(coordinator != nullptr, "alternating-remount: open"))
    {
        return false;
    }
    const std::string uuid = coordinator->ContainerUuidHex();
    for (const std::uint64_t oid : {101ULL, 102ULL})
    {
        apfsaccess::catalog::ContainerVolumeSession session{};
        session.volume_object_id = oid;
        session.container_uuid_hex = uuid;
        session.requested_write = true;
        if (!Require(
                coordinator->MountVolume(session, error),
                "alternating-remount: mount sibling"))
        {
            return false;
        }
    }

    bool ok = true;
    for (int index = 0; index < 6; ++index)
    {
        const std::uint64_t oid = index % 2 == 0 ? 101ULL : 102ULL;
        apfsaccess::rw::MetadataStore::MutationRequest mutation{};
        mutation.operation =
            apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        mutation.path = (oid == 101 ? L"\\alpha-" : L"\\beta-") +
            std::to_wstring(index) + L".bin";
        ok &= Require(
            coordinator->Commit(oid, {mutation}).committed,
            "alternating-remount: alternating commit succeeds");
    }
    ok &= Require(
        coordinator->DrainAndStop(std::chrono::seconds(5)).clean,
        "alternating-remount: first owner drains");
    ok &= Require(
        RemovePersistentStateSidecars(),
        "alternating-remount: remove sidecars before media-only remount");

    auto remounted = OpenFixtureCoordinator(image, error);
    if (!Require(remounted != nullptr, "alternating-remount: reopen"))
    {
        return false;
    }
    for (const std::uint64_t oid : {101ULL, 102ULL})
    {
        apfsaccess::catalog::ContainerVolumeSession session{};
        session.volume_object_id = oid;
        session.container_uuid_hex = remounted->ContainerUuidHex();
        session.requested_write = true;
        if (!Require(
                remounted->MountVolume(session, error),
                "alternating-remount: remount sibling"))
        {
            return false;
        }
    }
    auto* alpha = remounted->FindSessionStore(101);
    auto* beta = remounted->FindSessionStore(102);
    if (!Require(
            alpha != nullptr && beta != nullptr,
            "alternating-remount: both stores restored"))
    {
        return false;
    }
    for (int index = 0; index < 6; ++index)
    {
        const bool alpha_index = index % 2 == 0;
        const std::wstring path = (alpha_index ? L"\\alpha-" : L"\\beta-") +
            std::to_wstring(index) + L".bin";
        const bool alpha_has =
            alpha->LookupCommittedInodeByPath(path).has_value();
        const bool beta_has = beta->LookupCommittedInodeByPath(path).has_value();
        if (alpha_has != alpha_index || beta_has != !alpha_index)
        {
            std::fprintf(
                stderr,
                "[INFO] alternating-remount mismatch index=%d alphaHas=%d betaHas=%d\n",
                index,
                alpha_has ? 1 : 0,
                beta_has ? 1 : 0);
            TraceCommittedPaths("alternating Alpha", alpha);
            TraceCommittedPaths("alternating Beta", beta);
        }
        ok &= Require(
            alpha_has == alpha_index,
            "alternating-remount: Alpha namespace remains isolated");
        ok &= Require(
            beta_has == !alpha_index,
            "alternating-remount: Beta namespace remains isolated");
    }
    return ok;
}

bool TestAppleCoordinatorPreservesAlternatingVolumesAcrossRemount()
{
    const auto dir = MakeRunDir("apple-alternating-remount");
    const auto image = dir / "two-volume.raw";
    if (!Require(WriteAuthoritativeTwoVolumeImage(image),
            "apple-alternating-remount: build authoritative fixture"))
    {
        return false;
    }

    std::string error;
    auto coordinator = apfsaccess::catalog::ContainerMountCoordinator::Open(
        image.string(), 0, error);
    if (!Require(coordinator != nullptr,
            "apple-alternating-remount: open strict coordinator"))
    {
        std::fprintf(stderr, "[INFO] apple coordinator open: %s\n", error.c_str());
        return false;
    }
    const auto initial_xid = coordinator->CheckpointXid();
    const auto uuid = coordinator->ContainerUuidHex();
    for (const std::uint64_t oid : {101ULL, 102ULL})
    {
        apfsaccess::catalog::ContainerVolumeSession session{};
        session.volume_object_id = oid;
        session.container_uuid_hex = uuid;
        session.requested_write = true;
        session.use_canonical_transaction = true;
        session.metadata_context.integrity_check_on_mount = false;
        if (!Require(coordinator->MountVolume(session, error),
                "apple-alternating-remount: mount sibling"))
        {
            std::fprintf(stderr, "[INFO] apple sibling mount: %s\n", error.c_str());
            return false;
        }
    }

    std::vector<std::byte> alpha_payload(7000);
    std::vector<std::byte> beta_payload(9137);
    for (std::size_t index = 0; index < alpha_payload.size(); ++index)
    {
        alpha_payload[index] = static_cast<std::byte>((index * 29u + 3u) & 0xffu);
    }
    for (std::size_t index = 0; index < beta_payload.size(); ++index)
    {
        beta_payload[index] = static_cast<std::byte>((index * 43u + 5u) & 0xffu);
    }
    auto* alpha = coordinator->FindSessionStore(101);
    auto* beta = coordinator->FindSessionStore(102);
    if (!Require(alpha != nullptr && beta != nullptr,
            "apple-alternating-remount: stores available"))
    {
        return false;
    }
    alpha->SetFilePayloadProvider(
        [&alpha_payload](const std::wstring& path, std::uint64_t size)
            -> std::optional<std::vector<std::byte>>
        {
            return path == L"\\alpha.bin" && size == alpha_payload.size()
                ? std::optional<std::vector<std::byte>>(alpha_payload)
                : std::nullopt;
        });
    beta->SetFilePayloadProvider(
        [&beta_payload](const std::wstring& path, std::uint64_t size)
            -> std::optional<std::vector<std::byte>>
        {
            return path == L"\\beta.bin" && size == beta_payload.size()
                ? std::optional<std::vector<std::byte>>(beta_payload)
                : std::nullopt;
        });

    const auto create_and_write = [](const std::wstring& path, std::uint64_t size)
    {
        apfsaccess::rw::MetadataStore::MutationRequest create{};
        create.operation =
            apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create.path = path;
        apfsaccess::rw::MetadataStore::MutationRequest write{};
        write.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write.path = path;
        write.length = size;
        return std::vector<apfsaccess::rw::MetadataStore::MutationRequest>{
            create, write};
    };
    bool ok = true;
    const auto alpha_commit = coordinator->Commit(
        101, create_and_write(L"\\alpha.bin", alpha_payload.size()));
    ok &= Require(alpha_commit.committed,
        "apple-alternating-remount: Alpha commit succeeds");
    const auto beta_commit = coordinator->Commit(
        102, create_and_write(L"\\beta.bin", beta_payload.size()));
    ok &= Require(beta_commit.committed,
        "apple-alternating-remount: Beta commit succeeds");
    ok &= Require(alpha_commit.committed_xid == initial_xid + 1 &&
            beta_commit.committed_xid == initial_xid + 2 &&
            coordinator->CheckpointXid() == initial_xid + 2,
        "apple-alternating-remount: one contiguous container XID sequence");
    ok &= Require(coordinator->DrainAndStop(std::chrono::seconds(5)).clean,
        "apple-alternating-remount: first owner drains");

    auto remounted = apfsaccess::catalog::ContainerMountCoordinator::Open(
        image.string(), 0, error);
    if (!Require(remounted != nullptr,
            "apple-alternating-remount: reopen strict coordinator"))
    {
        std::fprintf(stderr, "[INFO] apple coordinator reopen: %s\n", error.c_str());
        return false;
    }
    for (const std::uint64_t oid : {101ULL, 102ULL})
    {
        apfsaccess::catalog::ContainerVolumeSession session{};
        session.volume_object_id = oid;
        session.container_uuid_hex = remounted->ContainerUuidHex();
        session.use_canonical_transaction = true;
        session.metadata_context.integrity_check_on_mount = false;
        if (!Require(remounted->MountVolume(session, error),
                "apple-alternating-remount: remount sibling"))
        {
            std::fprintf(stderr, "[INFO] apple sibling remount: %s\n", error.c_str());
            return false;
        }
    }
    alpha = remounted->FindSessionStore(101);
    beta = remounted->FindSessionStore(102);
    std::vector<std::byte> actual;
    ok &= Require(alpha != nullptr &&
            alpha->ReadCommittedFileRange(
                L"\\alpha.bin", 0, alpha_payload.size(), actual) &&
            actual == alpha_payload,
        "apple-alternating-remount: Alpha payload survives exactly");
    actual.clear();
    ok &= Require(beta != nullptr &&
            beta->ReadCommittedFileRange(
                L"\\beta.bin", 0, beta_payload.size(), actual) &&
            actual == beta_payload,
        "apple-alternating-remount: Beta payload survives exactly");
    ok &= Require(alpha != nullptr &&
            !alpha->LookupCommittedInodeByPath(L"\\beta.bin").has_value() &&
            beta != nullptr &&
            !beta->LookupCommittedInodeByPath(L"\\alpha.bin").has_value(),
        "apple-alternating-remount: sibling namespaces stay isolated");
    return ok;
}

// Duplicate display names are legal. Host-side state must therefore include
// the selected volume OID rather than collapsing siblings onto one sidecar.
bool TestCoordinatorSeparatesDuplicateNameSidecars()
{
    const auto dir = MakeRunDir("duplicate-name-sidecars");
    const auto image = dir / "two.apfs.img";
    if (!Require(
            RemovePersistentStateSidecars(),
            "duplicate-name-sidecars: clear prior sidecars") ||
        !Require(
            WriteTwoVolumeImage(image, true),
            "duplicate-name-sidecars: build fixture"))
    {
        return false;
    }
    std::string error;
    auto coordinator = OpenFixtureCoordinator(image, error);
    if (!Require(coordinator != nullptr, "duplicate-name-sidecars: open"))
    {
        return false;
    }
    const auto uuid = coordinator->ContainerUuidHex();
    for (const std::uint64_t oid : {101ULL, 102ULL})
    {
        apfsaccess::catalog::ContainerVolumeSession session{};
        session.volume_object_id = oid;
        session.container_uuid_hex = uuid;
        session.requested_write = true;
        if (!Require(
                coordinator->MountVolume(session, error),
                "duplicate-name-sidecars: mount sibling"))
        {
            return false;
        }
        apfsaccess::rw::MetadataStore::MutationRequest mutation{};
        mutation.operation =
            apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        mutation.path = L"\\volume-" + std::to_wstring(oid) + L".bin";
        if (!Require(
                coordinator->Commit(oid, {mutation}).committed,
                "duplicate-name-sidecars: commit sibling"))
        {
            return false;
        }
    }
    return Require(
        PersistentStateSidecarCount() == 2,
        "duplicate-name-sidecars: one sidecar per selected volume OID");
}

// A quiet volume's local tree can lag the shared container checkpoint by many
// sibling commits. Canonical disk-authoritative reload must combine that local
// generation with the newest shared spaceman generation without sidecars.
bool TestCanonicalReloadKeepsQuietSiblingNamespace()
{
    const auto dir = MakeRunDir("canonical-quiet-sibling");
    const auto fixture_image = dir / "two.apfs.img";
    const auto canonical_image = dir / "two.apfs.bin";
    if (!Require(
            WriteTwoVolumeImage(fixture_image),
            "canonical-quiet-sibling: build fixture"))
    {
        return false;
    }
    std::string error;
    auto coordinator = OpenFixtureCoordinator(fixture_image, error);
    if (!Require(coordinator != nullptr, "canonical-quiet-sibling: open"))
    {
        return false;
    }
    const auto uuid = coordinator->ContainerUuidHex();
    for (const std::uint64_t oid : {101ULL, 102ULL})
    {
        apfsaccess::catalog::ContainerVolumeSession session{};
        session.volume_object_id = oid;
        session.container_uuid_hex = uuid;
        session.requested_write = true;
        if (!Require(
                coordinator->MountVolume(session, error),
                "canonical-quiet-sibling: mount sibling"))
        {
            return false;
        }
    }

    apfsaccess::rw::MetadataStore::MutationRequest alpha_mutation{};
    alpha_mutation.operation =
        apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    alpha_mutation.path = L"\\alpha-only.bin";
    if (!Require(
            coordinator->Commit(101, {alpha_mutation}).committed,
            "canonical-quiet-sibling: commit quiet volume"))
    {
        return false;
    }
    for (int index = 0; index < 12; ++index)
    {
        apfsaccess::rw::MetadataStore::MutationRequest beta_mutation{};
        beta_mutation.operation =
            apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        beta_mutation.path = L"\\beta-" + std::to_wstring(index) + L".bin";
        if (!Require(
                coordinator->Commit(102, {beta_mutation}).committed,
                "canonical-quiet-sibling: advance active sibling"))
        {
            return false;
        }
    }
    const auto final_xid = coordinator->CheckpointXid();
    if (!Require(
            coordinator->DrainAndStop(std::chrono::seconds(5)).clean,
            "canonical-quiet-sibling: drain fixture owner") ||
        !Require(
            RemovePersistentStateSidecars(),
            "canonical-quiet-sibling: remove sidecars"))
    {
        return false;
    }
    std::error_code copy_ec;
    std::filesystem::copy_file(
        fixture_image,
        canonical_image,
        std::filesystem::copy_options::overwrite_existing,
        copy_ec);
    if (!Require(!copy_ec, "canonical-quiet-sibling: copy canonical image"))
    {
        return false;
    }

    auto lease = std::make_shared<apfsaccess::rw::BlockDevice>(
        canonical_image.wstring(), 0);
    apfsaccess::rw::MetadataStore::VolumeContext alpha_context{};
    alpha_context.device_path = canonical_image.wstring();
    alpha_context.volume_name = L"Alpha";
    alpha_context.volume_object_id = 101;
    alpha_context.shared_container_session = true;
    alpha_context.container_volume_slot_index = 0;
    alpha_context.container_volume_slot_count = 2;
    alpha_context.allow_legacy_private_checkpoint_writer_for_tests = true;
    auto beta_context = alpha_context;
    beta_context.volume_name = L"Beta";
    beta_context.volume_object_id = 102;
    beta_context.container_volume_slot_index = 1;

    apfsaccess::rw::MetadataStore alpha(alpha_context, lease);
    apfsaccess::rw::MetadataStore beta(beta_context, lease);
    bool ok = true;
    ok &= Require(
        alpha.PrepareNativeWritePath(),
        "canonical-quiet-sibling: alpha canonical reload");
    ok &= Require(
        beta.PrepareNativeWritePath(),
        "canonical-quiet-sibling: beta canonical reload");
    if (!ok)
    {
        std::fwprintf(
            stderr,
            L"[INFO] canonical reload reasons alpha=%ls beta=%ls\n",
            alpha.RecoveryReason().c_str(),
            beta.RecoveryReason().c_str());
        return false;
    }
    ok &= Require(
        alpha.CheckpointXid().value_or(0) == final_xid &&
            beta.CheckpointXid().value_or(0) == final_xid,
        "canonical-quiet-sibling: both sessions adopt global checkpoint XID");
    ok &= Require(
        alpha.LookupCommittedInodeByPath(L"\\alpha-only.bin").has_value(),
        "canonical-quiet-sibling: quiet Alpha tree retained");
    ok &= Require(
        !beta.LookupCommittedInodeByPath(L"\\alpha-only.bin").has_value(),
        "canonical-quiet-sibling: Alpha tree absent from Beta");
    for (int index = 0; index < 12; ++index)
    {
        const auto path = L"\\beta-" + std::to_wstring(index) + L".bin";
        ok &= Require(
            beta.LookupCommittedInodeByPath(path).has_value(),
            "canonical-quiet-sibling: active Beta tree retained");
        ok &= Require(
            !alpha.LookupCommittedInodeByPath(path).has_value(),
            "canonical-quiet-sibling: Beta tree absent from Alpha");
    }
    return ok;
}

// A replay checkpoint is container-global storage but volume-local recovery.
// If Beta is interrupted after durable metadata persistence, mounting Alpha
// first must neither offer Beta's replay to Alpha nor leak Beta's namespace.
bool TestInterruptedReplayTargetsExactVolume()
{
    const auto dir = MakeRunDir("replay-volume-identity");
    const auto image = dir / "two.apfs.img";
    if (!Require(
            WriteTwoVolumeImage(image),
            "replay-volume-identity: build fixture"))
    {
        return false;
    }

    std::string error;
    auto coordinator = OpenFixtureCoordinator(image, error);
    if (!Require(coordinator != nullptr, "replay-volume-identity: open"))
    {
        return false;
    }
    const auto uuid = coordinator->ContainerUuidHex();
    for (const std::uint64_t oid : {101ULL, 102ULL})
    {
        apfsaccess::catalog::ContainerVolumeSession session{};
        session.volume_object_id = oid;
        session.container_uuid_hex = uuid;
        session.requested_write = true;
        session.metadata_context.crash_replay_mode = L"ReplayIfSafe";
        if (!Require(
                coordinator->MountVolume(session, error),
                "replay-volume-identity: mount sibling"))
        {
            return false;
        }
    }

    auto* beta_before_crash = coordinator->FindSessionStore(102);
    if (!Require(
            beta_before_crash != nullptr,
            "replay-volume-identity: find Beta store"))
    {
        return false;
    }
    beta_before_crash->SetCommitStageHook([](std::string_view stage)
    {
        return stage != "before-checkpoint-switch";
    });
    apfsaccess::rw::MetadataStore::MutationRequest mutation{};
    mutation.operation =
        apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    mutation.path = L"\\beta-interrupted.bin";
    const auto interrupted = coordinator->Commit(102, {mutation});
    bool ok = true;
    ok &= Require(
        !interrupted.committed && interrupted.commit_recovery_required,
        "replay-volume-identity: interrupted Beta commit requires recovery");
    ok &= Require(
        coordinator->RecoveryVolumeObjectId() == std::optional<std::uint64_t>{102},
        "replay-volume-identity: coordinator identifies Beta as recovery source");
    ok &= Require(
        !coordinator->RecoveryReason().empty(),
        "replay-volume-identity: coordinator records a recovery reason");
    coordinator.reset();
    ok &= Require(
        RemovePersistentStateSidecars(),
        "replay-volume-identity: remove sidecars before media-only remount");

    auto remounted = OpenFixtureCoordinator(image, error);
    if (!Require(remounted != nullptr, "replay-volume-identity: reopen"))
    {
        return false;
    }
    for (const std::uint64_t oid : {101ULL, 102ULL})
    {
        apfsaccess::catalog::ContainerVolumeSession session{};
        session.volume_object_id = oid;
        session.container_uuid_hex = remounted->ContainerUuidHex();
        session.requested_write = false;
        session.metadata_context.crash_replay_mode = L"ReplayIfSafe";
        if (!Require(
                remounted->MountVolume(session, error),
                "replay-volume-identity: remount sibling read-only"))
        {
            std::fprintf(stderr, "[INFO] replay remount error: %s\n", error.c_str());
            return false;
        }
    }
    auto* alpha = remounted->FindSessionStore(101);
    auto* beta = remounted->FindSessionStore(102);
    if (!Require(
            alpha != nullptr && beta != nullptr,
            "replay-volume-identity: restored both stores"))
    {
        return false;
    }

    ok &= Require(
        alpha->PrepareNativeWritePath(),
        "replay-volume-identity: prepare Alpha");
    if (alpha->IsRecoveryRequired())
    {
        std::fwprintf(
            stderr,
            L"[INFO] replay-volume-identity Alpha recovery: %ls\n",
            alpha->RecoveryReason().c_str());
    }
    ok &= Require(
        !alpha->IsRecoveryRequired(),
        "replay-volume-identity: Alpha must not inherit Beta recovery");
    ok &= Require(
        !alpha->LookupCommittedInodeByPath(L"\\beta-interrupted.bin").has_value(),
        "replay-volume-identity: Beta path must stay absent from Alpha");

    ok &= Require(
        beta->PrepareNativeWritePath(),
        "replay-volume-identity: prepare Beta");
    ok &= Require(
        beta->IsRecoveryRequired(),
        "replay-volume-identity: Beta must discover its pending replay");
    const bool beta_replayed = beta->ReplayOrRecover();
    if (!beta_replayed)
    {
        std::fwprintf(
            stderr,
            L"[INFO] replay-volume-identity Beta recovery: %ls candidate=%d pending=%d stage=%hs\n",
            beta->RecoveryReason().c_str(),
            beta->LastReplayCheckpointCandidatePresent() ? 1 : 0,
            beta->LastReplayCheckpointPendingWindow() ? 1 : 0,
            beta->LastReplayStage().c_str());
    }
    ok &= Require(
        beta_replayed,
        "replay-volume-identity: Beta replay succeeds");
    ok &= Require(
        !beta->IsRecoveryRequired() &&
            beta->LookupCommittedInodeByPath(L"\\beta-interrupted.bin").has_value(),
        "replay-volume-identity: Beta alone publishes recovered namespace");
    return ok;
}

// A shared replay record is not enough by itself: the referenced commit blob
// must carry the same exact volume identity under its checksum. Otherwise a
// valid blob from a sibling could be replayed through a corrupted pointer.
bool TestSharedReplayCommitBlobBindsVolumeIdentity()
{
    constexpr std::array<char, 13> kScaffoldMagicV4 =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'S', 'C', 'A', 'F', 'F', '4', '\0'
    };
    constexpr std::size_t kChecksumOffset = 49;
    constexpr std::size_t kIdentityOffset = 53;
    constexpr std::size_t kVolumeOidOffset = kIdentityOffset;
    constexpr std::size_t kContainerUuidOffset = kVolumeOidOffset + 8;
    constexpr std::size_t kVolumeUuidOffset = kContainerUuidOffset + 32;

    const auto dir = MakeRunDir("commit-blob-volume-identity");
    const auto image = dir / "two.apfs.img";
    if (!Require(
            WriteTwoVolumeImage(image),
            "commit-blob-identity: build fixture"))
    {
        return false;
    }

    std::string error;
    auto coordinator = OpenFixtureCoordinator(image, error);
    if (!Require(coordinator != nullptr, "commit-blob-identity: open"))
    {
        return false;
    }
    apfsaccess::catalog::ContainerVolumeSession beta{};
    beta.volume_object_id = 102;
    beta.container_uuid_hex = coordinator->ContainerUuidHex();
    beta.requested_write = true;
    beta.metadata_context.crash_replay_mode = L"ReplayIfSafe";
    if (!Require(
            coordinator->MountVolume(beta, error),
            "commit-blob-identity: mount Beta"))
    {
        return false;
    }

    auto* store = coordinator->FindSessionStore(102);
    if (!Require(store != nullptr, "commit-blob-identity: find Beta store"))
    {
        return false;
    }
    store->SetCommitStageHook([](std::string_view stage)
    {
        return stage != "before-checkpoint-switch";
    });
    apfsaccess::rw::MetadataStore::MutationRequest mutation{};
    mutation.operation =
        apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    mutation.path = L"\\identity-bound.bin";
    const auto interrupted = coordinator->Commit(102, {mutation});
    bool ok = true;
    ok &= Require(
        !interrupted.committed && interrupted.commit_recovery_required,
        "commit-blob-identity: interrupted commit leaves replay candidate");
    ok &= Require(
        store->LastCommitBlobMagic() == "APFSRWSCAFF4",
        "commit-blob-identity: shared session emits V4 blob");
    const auto context = store->Context();
    coordinator.reset();

    auto image_bytes = ReadFileBytes(image);
    const auto blob_offset = FindMagic(image_bytes, kScaffoldMagicV4);
    ok &= Require(
        blob_offset.has_value(),
        "commit-blob-identity: V4 blob is present on media");
    if (!blob_offset.has_value())
    {
        return false;
    }
    const auto payload_end = SharedCommitBlobPayloadEnd(
        image_bytes, blob_offset.value());
    ok &= Require(
        payload_end.has_value(),
        "commit-blob-identity: V4 payload is structurally bounded");
    if (!payload_end.has_value())
    {
        return false;
    }
    const auto base = blob_offset.value();
    ok &= Require(
        ReadLe64(image_bytes, base + kVolumeOidOffset) == 102,
        "commit-blob-identity: selected volume OID persisted");
    const std::string container_uuid(
        reinterpret_cast<const char*>(image_bytes.data() + base + kContainerUuidOffset),
        32);
    const std::string volume_uuid(
        reinterpret_cast<const char*>(image_bytes.data() + base + kVolumeUuidOffset),
        32);
    ok &= Require(
        container_uuid == context.container_uuid_hex,
        "commit-blob-identity: container UUID persisted");
    ok &= Require(
        volume_uuid == context.volume_uuid_hex,
        "commit-blob-identity: volume UUID persisted");
    const auto checksum_length = payload_end.value() - (base + kIdentityOffset);
    ok &= Require(
        ReadLe32(image_bytes, base + kChecksumOffset) ==
            Fnv1a(image_bytes, base + kIdentityOffset, checksum_length),
        "commit-blob-identity: checksum covers identity and mutations");

    // Substitute Alpha's OID and recompute the checksum. Recovery must reject
    // this structurally valid blob because its identity no longer matches Beta.
    WriteLe64(image_bytes, base + kVolumeOidOffset, 101);
    WriteLe32(
        image_bytes,
        base + kChecksumOffset,
        Fnv1a(image_bytes, base + kIdentityOffset, checksum_length));
    if (!Require(
            WriteFileBytes(image, image_bytes),
            "commit-blob-identity: persist tampered blob") ||
        !Require(
            RemovePersistentStateSidecars(),
            "commit-blob-identity: remove sidecars"))
    {
        return false;
    }

    auto remounted = OpenFixtureCoordinator(image, error);
    if (!Require(remounted != nullptr, "commit-blob-identity: reopen"))
    {
        return false;
    }
    beta.container_uuid_hex = remounted->ContainerUuidHex();
    beta.requested_write = false;
    if (!Require(
            remounted->MountVolume(beta, error),
            "commit-blob-identity: remount Beta"))
    {
        return false;
    }
    auto* beta_after = remounted->FindSessionStore(102);
    if (!Require(
            beta_after != nullptr,
            "commit-blob-identity: find remounted Beta"))
    {
        return false;
    }
    ok &= Require(
        beta_after->PrepareNativeWritePath(),
        "commit-blob-identity: prepare recovery probe");
    ok &= Require(
        beta_after->IsRecoveryRequired(),
        "commit-blob-identity: tampered candidate requires recovery");
    ok &= Require(
        !beta_after->ReplayOrRecover(),
        "commit-blob-identity: sibling identity cannot replay");
    return ok;
}

// A rejected request later in a batch must discard earlier staged requests.
// Otherwise one bad callback wedges every later commit until remount.
bool TestCoordinatorRollsBackPartiallyStagedBatch()
{
    const auto dir = MakeRunDir("batch-rollback");
    const auto image = dir / "two.apfs.img";
    if (!Require(
            WriteTwoVolumeImage(image), "batch-rollback: build fixture"))
    {
        return false;
    }
    std::string error;
    auto coordinator = OpenFixtureCoordinator(image, error);
    if (!Require(coordinator != nullptr, "batch-rollback: open"))
    {
        return false;
    }
    apfsaccess::catalog::ContainerVolumeSession session{};
    session.volume_object_id = 101;
    session.container_uuid_hex = coordinator->ContainerUuidHex();
    session.requested_write = true;
    if (!Require(
            coordinator->MountVolume(session, error),
            "batch-rollback: mount"))
    {
        return false;
    }

    apfsaccess::rw::MetadataStore::MutationRequest valid{};
    valid.operation =
        apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    valid.path = L"\\batch-first.bin";
    apfsaccess::rw::MetadataStore::MutationRequest invalid{};
    invalid.operation =
        apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    invalid.path.clear();
    const auto rejected = coordinator->Commit(101, {valid, invalid});

    bool ok = true;
    ok &= Require(!rejected.committed, "batch-rollback: batch is rejected");
    auto* store = coordinator->FindSessionStore(101);
    ok &= Require(store != nullptr, "batch-rollback: session remains mounted");
    if (store != nullptr)
    {
        ok &= Require(
            store->PendingMutationCount() == 0,
            "batch-rollback: partial staging is discarded");
    }

    apfsaccess::rw::MetadataStore::MutationRequest retry{};
    retry.operation =
        apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    retry.path = L"\\batch-retry.bin";
    const auto retried = coordinator->Commit(101, {retry});
    ok &= Require(
        retried.committed,
        "batch-rollback: subsequent valid commit succeeds without remount");
    return ok;
}

// A host must bind the staged APFS identity to durable recovery evidence
// before any checkpoint bytes are published. Rejecting that boundary must
// leave both the raw image and the reusable session unchanged.
bool TestCoordinatorPrepublicationHookRejectsWithoutMediaChange()
{
    const auto dir = MakeRunDir("prepublication-hook");
    const auto image = dir / "two.raw";
    if (!Require(
            WriteAuthoritativeTwoVolumeImage(image),
            "prepublication-hook: build authoritative fixture"))
    {
        return false;
    }

    std::string error;
    auto coordinator = apfsaccess::catalog::ContainerMountCoordinator::Open(
        image.string(),
        0,
        error,
        apfsaccess::catalog::CatalogLoadPolicy::StrictApple);
    if (!Require(coordinator != nullptr, "prepublication-hook: open"))
    {
        return false;
    }

    apfsaccess::catalog::ContainerVolumeSession session{};
    session.volume_object_id = 101;
    session.container_uuid_hex = coordinator->ContainerUuidHex();
    session.requested_write = true;
    session.use_canonical_transaction = true;
    if (!Require(
            coordinator->MountVolume(session, error),
            "prepublication-hook: mount"))
    {
        return false;
    }

    const auto before = ReadFileBytes(image);
    apfsaccess::rw::MetadataStore::MutationRequest create{};
    create.operation =
        apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create.path = L"\\must-not-publish.bin";

    bool hook_called = false;
    const auto rejected = coordinator->Commit(
        101,
        {create},
        [&](const auto& requests, const auto& identities, std::string& hook_error)
        {
            hook_called = requests.size() == 1 && identities.size() == 1 &&
                identities.front().object_id != 0 &&
                identities.front().generation != 0;
            hook_error = "InjectedRecoveryEvidenceFailure";
            return false;
        });
    const auto after = ReadFileBytes(image);

    bool ok = true;
    ok &= Require(hook_called, "prepublication-hook: receives staged identity");
    ok &= Require(!rejected.committed, "prepublication-hook: commit rejected");
    ok &= Require(
        rejected.commit_stage == "before-checkpoint-publication",
        "prepublication-hook: exact rejection stage reported");
    ok &= Require(before == after, "prepublication-hook: raw image unchanged");
    auto* store = coordinator->FindSessionStore(101);
    ok &= Require(store != nullptr, "prepublication-hook: session remains mounted");
    if (store != nullptr)
    {
        ok &= Require(
            store->PendingMutationCount() == 0,
            "prepublication-hook: staged state rolled back");
        ok &= Require(
            !store->LookupCommittedInodeByPath(create.path).has_value(),
            "prepublication-hook: rejected inode remains absent");
    }

    create.path = L"\\retry-after-hook.bin";
    const auto ready_before_retry = store != nullptr && store->IsNativeWriteReady();
    const auto commit_ready_before_retry =
        store != nullptr && store->IsCommitPathReady();
    const auto canonical_ready_before_retry =
        store != nullptr && store->IsCanonicalCommitReady();
    const auto recovery_before_retry =
        store != nullptr && store->IsRecoveryRequired();
    const auto retry = coordinator->Commit(101, {create});
    if (!retry.committed)
    {
        std::fprintf(
            stderr,
            "[INFO] prepublication retry: ready=%d commitReady=%d canonicalReady=%d storeRecovery=%d status=%d stage=%s error=%s recovery=%d reason=%ls\n",
            ready_before_retry ? 1 : 0,
            commit_ready_before_retry ? 1 : 0,
            canonical_ready_before_retry ? 1 : 0,
            recovery_before_retry ? 1 : 0,
            retry.commit_status_code,
            retry.commit_stage.c_str(),
            retry.error.c_str(),
            retry.commit_recovery_required ? 1 : 0,
            retry.commit_recovery_reason.c_str());
    }
    ok &= Require(
        retry.committed,
        "prepublication-hook: clean retry succeeds without remount");
    return ok;
}

// Session lifetime changes share the commit serialization boundary. This
// prevents teardown from destroying a store used by an active commit and
// prevents mount-time reads from observing a half-written checkpoint.
bool TestCoordinatorSerializesSessionTransitionsWithCommit()
{
    const auto dir = MakeRunDir("session-transition");
    const auto image = dir / "two.apfs.img";
    if (!Require(
            WriteTwoVolumeImage(image), "session-transition: build fixture"))
    {
        return false;
    }
    std::string error;
    auto coordinator = OpenFixtureCoordinator(image, error);
    if (!Require(coordinator != nullptr, "session-transition: open"))
    {
        return false;
    }
    const std::string uuid = coordinator->ContainerUuidHex();
    apfsaccess::catalog::ContainerVolumeSession alpha{};
    alpha.volume_object_id = 101;
    alpha.container_uuid_hex = uuid;
    alpha.requested_write = true;
    apfsaccess::catalog::ContainerVolumeSession beta{};
    beta.volume_object_id = 102;
    beta.container_uuid_hex = uuid;
    if (!Require(
            coordinator->MountVolume(alpha, error),
            "session-transition: mount Alpha"))
    {
        return false;
    }

    auto* alpha_store = coordinator->FindSessionStore(101);
    if (!Require(alpha_store != nullptr, "session-transition: find Alpha"))
    {
        return false;
    }
    std::promise<void> commit_paused_promise;
    auto commit_paused = commit_paused_promise.get_future();
    std::promise<void> release_commit_promise;
    auto release_commit = release_commit_promise.get_future().share();
    std::atomic<bool> pause_reported{false};
    alpha_store->SetCommitStageHook(
        [&](std::string_view stage)
        {
            if (stage == "before-device-write" &&
                !pause_reported.exchange(true))
            {
                commit_paused_promise.set_value();
                release_commit.wait();
            }
            return true;
        },
        false);

    apfsaccess::rw::MetadataStore::MutationRequest mutation{};
    mutation.operation =
        apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    mutation.path = L"\\session-transition.bin";
    auto commit = std::async(std::launch::async, [&]()
    {
        return coordinator->Commit(101, {mutation});
    });
    if (!Require(
            commit_paused.wait_for(std::chrono::seconds(5)) ==
                std::future_status::ready,
            "session-transition: commit reaches paused device-write stage"))
    {
        release_commit_promise.set_value();
        (void)commit.get();
        return false;
    }

    auto mount = std::async(std::launch::async, [&]()
    {
        std::string mount_error;
        return coordinator->MountVolume(beta, mount_error);
    });
    bool ok = true;
    ok &= Require(
        mount.wait_for(std::chrono::milliseconds(150)) !=
            std::future_status::ready,
        "session-transition: sibling mount waits for active commit");
    release_commit_promise.set_value();
    const auto commit_result = commit.get();
    ok &= Require(commit_result.committed, "session-transition: commit succeeds");
    ok &= Require(mount.get(), "session-transition: sibling mount then succeeds");

    std::promise<void> second_pause_promise;
    auto second_pause = second_pause_promise.get_future();
    std::promise<void> second_release_promise;
    auto second_release = second_release_promise.get_future().share();
    pause_reported.store(false);
    alpha_store->SetCommitStageHook(
        [&](std::string_view stage)
        {
            if (stage == "before-device-write" &&
                !pause_reported.exchange(true))
            {
                second_pause_promise.set_value();
                second_release.wait();
            }
            return true;
        },
        false);
    mutation.path = L"\\session-transition-two.bin";
    auto second_commit = std::async(std::launch::async, [&]()
    {
        return coordinator->Commit(101, {mutation});
    });
    if (!Require(
            second_pause.wait_for(std::chrono::seconds(5)) ==
                std::future_status::ready,
            "session-transition: second commit reaches paused stage"))
    {
        second_release_promise.set_value();
        (void)second_commit.get();
        return false;
    }
    auto unmount = std::async(std::launch::async, [&]()
    {
        std::string unmount_error;
        return coordinator->UnmountVolume(102, unmount_error);
    });
    ok &= Require(
        unmount.wait_for(std::chrono::milliseconds(150)) !=
            std::future_status::ready,
        "session-transition: sibling unmount waits for active commit");
    second_release_promise.set_value();
    ok &= Require(
        second_commit.get().committed,
        "session-transition: second commit succeeds");
    ok &= Require(
        unmount.get(), "session-transition: sibling unmount then succeeds");
    return ok;
}

// A failure before any device write belongs to the selected volume only. The
// sibling must still commit, and a fresh coordinator must observe exactly the
// surviving on-disk namespace.
bool TestCoordinatorIsolatesPreWriteFailureAcrossVolumes()
{
    const auto dir = MakeRunDir("prewrite-isolation");
    const auto image = dir / "two.raw";
    if (!Require(
            WriteAuthoritativeTwoVolumeImage(image),
            "prewrite-isolation: build authoritative fixture"))
    {
        return false;
    }
    std::string error;
    auto coordinator = apfsaccess::catalog::ContainerMountCoordinator::Open(
        image.string(), 0, error);
    if (!Require(
            coordinator != nullptr, "prewrite-isolation: open strict coordinator"))
    {
        return false;
    }
    const std::string uuid = coordinator->ContainerUuidHex();
    for (const std::uint64_t oid : {101ULL, 102ULL})
    {
        apfsaccess::catalog::ContainerVolumeSession session{};
        session.volume_object_id = oid;
        session.container_uuid_hex = uuid;
        session.requested_write = true;
        session.use_canonical_transaction = true;
        session.metadata_context.integrity_check_on_mount = false;
        if (!Require(
                coordinator->MountVolume(session, error),
                "prewrite-isolation: mount sibling"))
        {
            return false;
        }
    }

    auto* alpha = coordinator->FindSessionStore(101);
    if (!Require(alpha != nullptr, "prewrite-isolation: find Alpha"))
    {
        return false;
    }
    alpha->SetCommitStageHook([](std::string_view stage)
    {
        return stage != "before-apple-publish";
    });
    apfsaccess::rw::MetadataStore::MutationRequest alpha_create{};
    alpha_create.operation =
        apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    alpha_create.path = L"\\alpha-failed.bin";
    const auto failed = coordinator->Commit(101, {alpha_create});
    alpha->SetCommitStageHook({});

    bool ok = true;
    ok &= Require(
        !failed.committed && !failed.commit_recovery_required,
        "prewrite-isolation: pre-write failure is rejected without recovery latch");
    ok &= Require(
        alpha->PendingMutationCount() == 0,
        "prewrite-isolation: selected session rolls back after clean failure");
    ok &= Require(
        !coordinator->IsRecoveryRequired(),
        "prewrite-isolation: container remains writable after pre-write failure");

    apfsaccess::rw::MetadataStore::MutationRequest beta_create{};
    beta_create.operation =
        apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    beta_create.path = L"\\beta-survives.bin";
    const auto survived = coordinator->Commit(102, {beta_create});
    if (!survived.committed)
    {
        auto* beta_store = coordinator->FindSessionStore(102);
        std::fprintf(stderr,
            "[INFO] prewrite Beta failure: %s stage=%s recovery=%d canonicalReady=%d nativeReady=%d storeRecovery=%d reason=%ls\n",
            survived.error.c_str(), survived.commit_stage.c_str(),
            survived.commit_recovery_required ? 1 : 0,
            beta_store != nullptr && beta_store->IsCanonicalCommitReady() ? 1 : 0,
            beta_store != nullptr && beta_store->IsNativeWriteReady() ? 1 : 0,
            beta_store != nullptr && beta_store->IsRecoveryRequired() ? 1 : 0,
            beta_store != nullptr ? beta_store->RecoveryReason().c_str() : L"");
    }
    ok &= Require(
        survived.committed,
        "prewrite-isolation: sibling commit succeeds after selected-volume failure");

    apfsaccess::rw::MetadataStore::MutationRequest alpha_retry{};
    alpha_retry.operation =
        apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    alpha_retry.path = L"\\alpha-retry.bin";
    const auto retried = coordinator->Commit(101, {alpha_retry});
    if (!retried.committed)
    {
        std::fprintf(stderr,
            "[INFO] prewrite Alpha retry failure: %s stage=%s recovery=%d canonicalReady=%d nativeReady=%d storeRecovery=%d reason=%ls\n",
            retried.error.c_str(), retried.commit_stage.c_str(),
            retried.commit_recovery_required ? 1 : 0,
            alpha->IsCanonicalCommitReady() ? 1 : 0,
            alpha->IsNativeWriteReady() ? 1 : 0,
            alpha->IsRecoveryRequired() ? 1 : 0,
            alpha->RecoveryReason().c_str());
    }
    ok &= Require(
        retried.committed,
        "prewrite-isolation: selected volume remains writable after clean rollback");
    ok &= Require(
        coordinator->DrainAndStop(std::chrono::seconds(5)).clean,
        "prewrite-isolation: first coordinator drains");

    auto remounted = apfsaccess::catalog::ContainerMountCoordinator::Open(
        image.string(), 0, error);
    if (!Require(remounted != nullptr, "prewrite-isolation: reopen"))
    {
        return false;
    }
    for (const std::uint64_t oid : {101ULL, 102ULL})
    {
        apfsaccess::catalog::ContainerVolumeSession session{};
        session.volume_object_id = oid;
        session.container_uuid_hex = remounted->ContainerUuidHex();
        session.requested_write = true;
        session.use_canonical_transaction = true;
        session.metadata_context.integrity_check_on_mount = false;
        if (!Require(
                remounted->MountVolume(session, error),
                "prewrite-isolation: remount sibling"))
        {
            return false;
        }
    }
    auto* alpha_after = remounted->FindSessionStore(101);
    auto* beta_after = remounted->FindSessionStore(102);
    if (alpha_after != nullptr && beta_after != nullptr &&
        (!beta_after->LookupCommittedInodeByPath(L"\\beta-survives.bin").has_value() ||
         alpha_after->LookupCommittedInodeByPath(L"\\alpha-failed.bin").has_value()))
    {
        TraceCommittedPaths("prewrite Alpha", alpha_after);
        TraceCommittedPaths("prewrite Beta", beta_after);
    }
    ok &= Require(
        alpha_after != nullptr &&
            !alpha_after->LookupCommittedInodeByPath(L"\\alpha-failed.bin").has_value() &&
            alpha_after->LookupCommittedInodeByPath(L"\\alpha-retry.bin").has_value(),
        "prewrite-isolation: remount contains only the successful Alpha retry");
    ok &= Require(
        beta_after != nullptr &&
            beta_after->LookupCommittedInodeByPath(L"\\beta-survives.bin").has_value(),
        "prewrite-isolation: Beta mutation survives remount");
    return ok;
}

// Shared-space exhaustion must be an atomic staging failure, not a container
// poison pill. Earlier mutations in the same batch are discarded and a
// sibling can still consume a later valid allocation.
bool TestCoordinatorHandlesSharedSpaceExhaustionAtomically()
{
    const auto dir = MakeRunDir("space-exhaustion");
    const auto image = dir / "two.raw";
    if (!Require(
            WriteAuthoritativeTwoVolumeImage(image, 16),
            "space-exhaustion: build constrained Apple fixture"))
    {
        return false;
    }
    std::string error;
    auto coordinator = apfsaccess::catalog::ContainerMountCoordinator::Open(
        image.string(), 0, error);
    if (!Require(coordinator != nullptr, "space-exhaustion: open strict coordinator"))
    {
        return false;
    }
    const std::string uuid = coordinator->ContainerUuidHex();
    for (const std::uint64_t oid : {101ULL, 102ULL})
    {
        apfsaccess::catalog::ContainerVolumeSession session{};
        session.volume_object_id = oid;
        session.container_uuid_hex = uuid;
        session.requested_write = true;
        session.use_canonical_transaction = true;
        session.metadata_context.integrity_check_on_mount = false;
        if (!Require(
                coordinator->MountVolume(session, error),
                "space-exhaustion: mount sibling"))
        {
            return false;
        }
    }

    apfsaccess::rw::MetadataStore::MutationRequest create{};
    create.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create.path = L"\\too-large.bin";
    apfsaccess::rw::MetadataStore::MutationRequest oversized{};
    oversized.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    oversized.path = create.path;
    oversized.length = 17 * 4096;
    auto* alpha = coordinator->FindSessionStore(101);
    if (!Require(alpha != nullptr, "space-exhaustion: find Alpha"))
    {
        return false;
    }
    const std::vector<std::byte> oversized_payload(
        static_cast<std::size_t>(oversized.length), std::byte{0x5a});
    alpha->SetFilePayloadProvider(
        [&oversized_payload](const std::wstring& path, std::uint64_t size)
            -> std::optional<std::vector<std::byte>>
        {
            return path == L"\\too-large.bin" &&
                    size == oversized_payload.size()
                ? std::optional<std::vector<std::byte>>(oversized_payload)
                : std::nullopt;
        });
    const auto exhausted = coordinator->Commit(101, {create, oversized});
    if (exhausted.committed ||
        exhausted.error.find("CommitStageFailed") != 0)
    {
        std::fprintf(stderr,
            "[INFO] space Alpha result: committed=%d error=%s stage=%s recovery=%d\n",
            exhausted.committed ? 1 : 0, exhausted.error.c_str(),
            exhausted.commit_stage.c_str(),
            exhausted.commit_recovery_required ? 1 : 0);
    }

    bool ok = true;
    ok &= Require(
        !exhausted.committed &&
            exhausted.error.find("CommitStageFailed") == 0,
        "space-exhaustion: authoritative Apple free space rejects the oversized payload before publication");
    ok &= Require(
        alpha != nullptr && alpha->PendingMutationCount() == 0,
        "space-exhaustion: clean Apple allocation refusal rolls back the session");
    ok &= Require(
        !coordinator->IsRecoveryRequired(),
        "space-exhaustion: clean allocation refusal does not require recovery");

    apfsaccess::rw::MetadataStore::MutationRequest sibling_create{};
    sibling_create.operation =
        apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    sibling_create.path = L"\\beta-after-exhaustion.bin";
    const auto sibling = coordinator->Commit(102, {sibling_create});
    if (!sibling.committed)
    {
        std::fprintf(stderr,
            "[INFO] space Beta failure: %s stage=%s recovery=%d\n",
            sibling.error.c_str(), sibling.commit_stage.c_str(),
            sibling.commit_recovery_required ? 1 : 0);
    }
    ok &= Require(
        sibling.committed,
        "space-exhaustion: sibling remains writable after clean refusal");
    ok &= Require(
        coordinator->DrainAndStop(std::chrono::seconds(5)).clean,
        "space-exhaustion: coordinator drains");

    auto remounted = apfsaccess::catalog::ContainerMountCoordinator::Open(
        image.string(), 0, error);
    if (!Require(remounted != nullptr, "space-exhaustion: reopen"))
    {
        return false;
    }
    apfsaccess::catalog::ContainerVolumeSession beta{};
    beta.volume_object_id = 102;
    beta.container_uuid_hex = remounted->ContainerUuidHex();
    beta.requested_write = true;
    beta.use_canonical_transaction = true;
    beta.metadata_context.integrity_check_on_mount = false;
    if (!Require(
            remounted->MountVolume(beta, error),
            "space-exhaustion: remount Beta"))
    {
        return false;
    }
    auto* beta_after = remounted->FindSessionStore(102);
    if (beta_after != nullptr && !beta_after->LookupCommittedInodeByPath(
            L"\\beta-after-exhaustion.bin").has_value())
    {
        TraceCommittedPaths("space Beta", beta_after);
    }
    ok &= Require(
        beta_after != nullptr && beta_after->LookupCommittedInodeByPath(
            L"\\beta-after-exhaustion.bin").has_value(),
        "space-exhaustion: sibling commit survives remount");
    return ok;
}

// Canonical transactions reserve from the container's Apple spaceman, not
// from each volume store's compatibility extent ledger. Two sibling payload
// writes must therefore commit without a false cross-volume overlap latch.
bool TestAppleCoordinatorUsesSharedSpacemanForSiblingPayloads()
{
    const auto dir = MakeRunDir("apple-shared-spaceman-payloads");
    const auto image = dir / "two.raw";
    if (!Require(
            WriteAuthoritativeTwoVolumeImage(image),
            "apple-shared-spaceman: build authoritative fixture"))
    {
        return false;
    }

    std::string error;
    auto coordinator = apfsaccess::catalog::ContainerMountCoordinator::Open(
        image.string(), 0, error);
    if (!Require(
            coordinator != nullptr,
            "apple-shared-spaceman: open strict coordinator"))
    {
        return false;
    }

    for (const std::uint64_t oid : {101ULL, 102ULL})
    {
        apfsaccess::catalog::ContainerVolumeSession session{};
        session.volume_object_id = oid;
        session.container_uuid_hex = coordinator->ContainerUuidHex();
        session.requested_write = true;
        session.use_canonical_transaction = true;
        session.metadata_context.integrity_check_on_mount = true;
        if (!Require(
                coordinator->MountVolume(session, error),
                "apple-shared-spaceman: mount sibling"))
        {
            return false;
        }
    }

    const std::vector<std::byte> alpha_payload(8192, std::byte{0x2a});
    const std::vector<std::byte> beta_payload(12288, std::byte{0x6b});
    const auto commit_payload = [&](std::uint64_t oid,
                                    const std::wstring& path,
                                    const std::vector<std::byte>& payload)
    {
        auto* store = coordinator->FindSessionStore(oid);
        if (store == nullptr)
        {
            return apfsaccess::catalog::ContainerCommitResult{};
        }
        store->SetFilePayloadProvider(
            [&path, &payload](const std::wstring& requested, std::uint64_t size)
                -> std::optional<std::vector<std::byte>>
            {
                return requested == path && size == payload.size()
                    ? std::optional<std::vector<std::byte>>(payload)
                    : std::nullopt;
            });

        apfsaccess::rw::MetadataStore::MutationRequest create{};
        create.operation =
            apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create.path = path;
        const auto created = coordinator->Commit(oid, {create});
        if (!created.committed ||
            created.commit_status_code != static_cast<int>(
                apfsaccess::rw::MetadataStore::CommitStatus::Committed))
        {
            return created;
        }

        apfsaccess::rw::MetadataStore::MutationRequest write{};
        write.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write.path = path;
        write.length = payload.size();
        return coordinator->Commit(oid, {write});
    };

    const auto alpha = commit_payload(101, L"\\alpha-source.tmp", alpha_payload);
    apfsaccess::rw::MetadataStore::MutationRequest rename{};
    rename.operation = apfsaccess::rw::MetadataStore::MutationOperation::Rename;
    rename.path = L"\\alpha-source.tmp";
    rename.secondary_path = L"\\alpha-payload.bin";
    const auto renamed = coordinator->Commit(101, {rename});
    const std::vector<std::byte> disposable_payload(1024, std::byte{0x17});
    const auto disposable = commit_payload(
        101, L"\\delete-me.tmp", disposable_payload);
    apfsaccess::rw::MetadataStore::MutationRequest remove{};
    remove.operation = apfsaccess::rw::MetadataStore::MutationOperation::Delete;
    remove.path = L"\\delete-me.tmp";
    const auto removed = coordinator->Commit(101, {remove});
    const auto beta = commit_payload(102, L"\\beta-payload.bin", beta_payload);
    bool ok = true;
    ok &= Require(
        alpha.committed &&
            alpha.commit_status_code == static_cast<int>(
                apfsaccess::rw::MetadataStore::CommitStatus::Committed),
        "apple-shared-spaceman: Alpha payload commits");
    ok &= Require(
        renamed.committed && disposable.committed && removed.committed,
        "apple-shared-spaceman: Alpha rename and delete sequence commits");
    ok &= Require(
        beta.committed &&
            beta.commit_status_code == static_cast<int>(
                apfsaccess::rw::MetadataStore::CommitStatus::Committed),
        "apple-shared-spaceman: Beta payload commits without false overlap");
    ok &= Require(
        !coordinator->IsRecoveryRequired(),
        "apple-shared-spaceman: sibling payloads do not latch recovery");

    coordinator.reset();
    auto remounted = apfsaccess::catalog::ContainerMountCoordinator::Open(
        image.string(), 0, error);
    if (!Require(
            remounted != nullptr,
            "apple-shared-spaceman: reopen committed container"))
    {
        return false;
    }
    for (const std::uint64_t oid : {101ULL, 102ULL})
    {
        apfsaccess::catalog::ContainerVolumeSession session{};
        session.volume_object_id = oid;
        session.container_uuid_hex = remounted->ContainerUuidHex();
        session.use_canonical_transaction = true;
        session.metadata_context.integrity_check_on_mount = true;
        if (!Require(
                remounted->MountVolume(session, error),
                "apple-shared-spaceman: remount sibling"))
        {
            return false;
        }
    }

    const auto verify_payload = [&](std::uint64_t oid,
                                    const std::wstring& path,
                                    const std::vector<std::byte>& expected)
    {
        auto* store = remounted->FindSessionStore(oid);
        std::vector<std::byte> actual;
        return store != nullptr &&
            store->ReadCommittedFileRange(path, 0, expected.size(), actual) &&
            actual == expected;
    };
    ok &= Require(
        verify_payload(101, L"\\alpha-payload.bin", alpha_payload),
        "apple-shared-spaceman: Alpha payload survives remount");
    ok &= Require(
        verify_payload(102, L"\\beta-payload.bin", beta_payload),
        "apple-shared-spaceman: Beta payload survives remount");
    return ok;
}

// Publication interruption must select one complete generation. Before the
// NXSB switch the old graph wins; after the NXSB write the new graph wins.
// In both cases recovery attribution remains volume-local.
bool TestAppleCoordinatorCrashBoundariesSelectCompleteGeneration()
{
    const auto run_case = [](
        const char* name, const char* blocked_stage, bool expect_new) -> bool
    {
        const auto dir = MakeRunDir(name);
        const auto image = dir / "two.raw";
        if (!Require(WriteAuthoritativeTwoVolumeImage(image),
                "apple-crash-boundary: build authoritative fixture"))
        {
            return false;
        }
        std::string error;
        auto coordinator = apfsaccess::catalog::ContainerMountCoordinator::Open(
            image.string(), 0, error);
        if (!Require(coordinator != nullptr,
                "apple-crash-boundary: open strict coordinator"))
        {
            return false;
        }
        const auto initial_xid = coordinator->CheckpointXid();
        for (const std::uint64_t oid : {101ULL, 102ULL})
        {
            apfsaccess::catalog::ContainerVolumeSession session{};
            session.volume_object_id = oid;
            session.container_uuid_hex = coordinator->ContainerUuidHex();
            session.requested_write = true;
            session.use_canonical_transaction = true;
            session.metadata_context.integrity_check_on_mount = false;
            if (!Require(coordinator->MountVolume(session, error),
                    "apple-crash-boundary: mount sibling"))
            {
                return false;
            }
        }
        auto* beta = coordinator->FindSessionStore(102);
        if (!Require(beta != nullptr, "apple-crash-boundary: find Beta"))
        {
            return false;
        }
        beta->SetCommitStageHook([blocked_stage](std::string_view stage)
        {
            return stage != blocked_stage;
        });
        apfsaccess::rw::MetadataStore::MutationRequest create{};
        create.operation =
            apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create.path = L"\\beta-boundary.bin";
        const auto interrupted = coordinator->Commit(102, {create});
        if (interrupted.committed ||
            interrupted.commit_stage != blocked_stage)
        {
            std::fprintf(stderr,
                "[INFO] apple crash result stage=%s: committed=%d error=%s actualStage=%s recovery=%d\n",
                blocked_stage, interrupted.committed ? 1 : 0,
                interrupted.error.c_str(), interrupted.commit_stage.c_str(),
                interrupted.commit_recovery_required ? 1 : 0);
        }
        bool ok = true;
        ok &= Require(!interrupted.committed &&
                interrupted.commit_recovery_required &&
                interrupted.commit_stage == blocked_stage,
            "apple-crash-boundary: exact durability boundary fails closed");
        ok &= Require(
            coordinator->RecoveryVolumeObjectId() ==
                std::optional<std::uint64_t>{102},
            "apple-crash-boundary: recovery source identifies Beta only");

        // Simulate abrupt owner loss: do not call DrainAndStop.
        coordinator.reset();
        auto remounted = apfsaccess::catalog::ContainerMountCoordinator::Open(
            image.string(), 0, error);
        if (!Require(remounted != nullptr,
                "apple-crash-boundary: strict reopen selects a complete graph"))
        {
            std::fprintf(stderr, "[INFO] apple crash reopen: %s\n", error.c_str());
            return false;
        }
        ok &= Require(
            remounted->CheckpointXid() == initial_xid + (expect_new ? 1 : 0),
            "apple-crash-boundary: selected checkpoint is exactly old or new");
        for (const std::uint64_t oid : {101ULL, 102ULL})
        {
            apfsaccess::catalog::ContainerVolumeSession session{};
            session.volume_object_id = oid;
            session.container_uuid_hex = remounted->ContainerUuidHex();
            session.use_canonical_transaction = true;
            session.metadata_context.integrity_check_on_mount = false;
            if (!Require(remounted->MountVolume(session, error),
                    "apple-crash-boundary: remount sibling"))
            {
                return false;
            }
        }
        auto* alpha_after = remounted->FindSessionStore(101);
        auto* beta_after = remounted->FindSessionStore(102);
        ok &= Require(alpha_after != nullptr && beta_after != nullptr &&
                !alpha_after->LookupCommittedInodeByPath(
                    L"\\beta-boundary.bin").has_value(),
            "apple-crash-boundary: Beta mutation never leaks into Alpha");
        ok &= Require(beta_after != nullptr &&
                beta_after->LookupCommittedInodeByPath(
                    L"\\beta-boundary.bin").has_value() == expect_new,
            "apple-crash-boundary: Beta namespace matches selected generation");
        ok &= Require(
            remounted->DrainAndStop(std::chrono::seconds(5)).clean,
            "apple-crash-boundary: remounted owner drains cleanly");
        return ok;
    };

    bool ok = true;
    ok &= run_case("apple-before-switch",
        "before-apple-checkpoint-switch", false);
    ok &= run_case("apple-before-final-flush",
        "before-apple-final-flush", true);
    return ok;
}

// A container-wide stop begins while a canonical commit owns the funnel. It
// must wait for that commit, reject queued work, then drop every session and
// the sole raw lease within its deadline.
bool TestAppleCoordinatorDrainWaitsForActiveCommit()
{
    const auto dir = MakeRunDir("apple-active-drain");
    const auto image = dir / "two.raw";
    if (!Require(WriteAuthoritativeTwoVolumeImage(image),
            "apple-active-drain: build authoritative fixture"))
    {
        return false;
    }
    std::string error;
    auto coordinator = apfsaccess::catalog::ContainerMountCoordinator::Open(
        image.string(), 0, error);
    if (!Require(coordinator != nullptr,
            "apple-active-drain: open strict coordinator"))
    {
        return false;
    }
    for (const std::uint64_t oid : {101ULL, 102ULL})
    {
        apfsaccess::catalog::ContainerVolumeSession session{};
        session.volume_object_id = oid;
        session.container_uuid_hex = coordinator->ContainerUuidHex();
        session.requested_write = true;
        session.use_canonical_transaction = true;
        session.metadata_context.integrity_check_on_mount = false;
        if (!Require(coordinator->MountVolume(session, error),
                "apple-active-drain: mount sibling"))
        {
            return false;
        }
    }
    auto* alpha = coordinator->FindSessionStore(101);
    if (!Require(alpha != nullptr, "apple-active-drain: find Alpha"))
    {
        return false;
    }
    std::promise<void> entered_promise;
    auto entered = entered_promise.get_future();
    std::promise<void> release_promise;
    auto release = release_promise.get_future().share();
    std::atomic<bool> announced{false};
    alpha->SetCommitStageHook(
        [&entered_promise, &release, &announced](std::string_view stage)
        {
            if (stage == "before-apple-publish" && !announced.exchange(true))
            {
                entered_promise.set_value();
                release.wait();
            }
            return true;
        });
    apfsaccess::rw::MetadataStore::MutationRequest alpha_create{};
    alpha_create.operation =
        apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    alpha_create.path = L"\\alpha-active.bin";
    auto active_commit = std::async(std::launch::async,
        [&coordinator, alpha_create]
        {
            return coordinator->Commit(101, {alpha_create});
        });
    if (!Require(entered.wait_for(std::chrono::seconds(5)) ==
            std::future_status::ready,
            "apple-active-drain: canonical commit reaches publish boundary"))
    {
        release_promise.set_value();
        return false;
    }
    auto drain = std::async(std::launch::async, [&coordinator]
    {
        return coordinator->DrainAndStop(std::chrono::seconds(5));
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    apfsaccess::rw::MetadataStore::MutationRequest beta_create{};
    beta_create.operation =
        apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    beta_create.path = L"\\beta-too-late.bin";
    auto queued_commit = std::async(std::launch::async,
        [&coordinator, beta_create]
        {
            return coordinator->Commit(102, {beta_create});
        });
    bool ok = true;
    ok &= Require(drain.wait_for(std::chrono::milliseconds(100)) ==
            std::future_status::timeout,
        "apple-active-drain: stop waits for the active commit");
    release_promise.set_value();
    const auto committed = active_commit.get();
    const auto stopped = drain.get();
    const auto rejected = queued_commit.get();
    ok &= Require(committed.committed,
        "apple-active-drain: in-flight commit reaches a durable boundary");
    ok &= Require(stopped.clean,
        "apple-active-drain: stop completes within the lifecycle deadline");
    ok &= Require(!rejected.committed && rejected.error == "ContainerDraining",
        "apple-active-drain: queued commit is rejected after stop admission");
    ok &= Require(coordinator->MountedVolumeCount() == 0 &&
            !coordinator->RawLeaseHeld(),
        "apple-active-drain: stop drops every session and the sole raw lease");
    return ok;
}

// T_coordinator_drain: DrainAndStop rejects new work, drops sessions and the
// lease, and reports clean.
bool TestCoordinatorDrainAndStop()
{
    const auto dir = MakeRunDir("drain");
    const auto image = dir / "two.apfs.img";
    if (!Require(WriteTwoVolumeImage(image), "drain: build fixture"))
    {
        return false;
    }
    std::string error;
    auto coordinator = OpenFixtureCoordinator(image, error);
    if (!Require(coordinator != nullptr, "drain: open"))
    {
        return false;
    }
    apfsaccess::catalog::ContainerVolumeSession alpha{};
    alpha.volume_object_id = 101;
    alpha.container_uuid_hex = coordinator->ContainerUuidHex();
    bool ok = true;
    ok &= Require(
        coordinator->MountVolume(alpha, error), "drain: mount Alpha");
    if (!ok)
    {
        return false;
    }
    const auto shutdown =
        coordinator->DrainAndStop(std::chrono::milliseconds(5000));
    ok &= Require(shutdown.clean, "drain: clean shutdown");
    ok &= Require(
        coordinator->MountedVolumeCount() == 0, "drain: sessions dropped");
    ok &= Require(!coordinator->RawLeaseHeld(), "drain: lease dropped");
    ok &= Require(
        !coordinator->MountVolume(alpha, error), "drain: mounts rejected");
    return ok;
}

// T_ledger_overlap_predicate: the shared-ledger overlap heart: overlap,
// adjacency (no overlap), containment, and overflow-safe rejection.
bool TestLedgerOverlapPredicate()
{
    using Coordinator = apfsaccess::catalog::ContainerMountCoordinator;
    using Range = Coordinator::ExtentRange;
    bool ok = true;
    ok &= Require(
        Coordinator::RangesOverlap({100, 50}, {120, 50}),
        "overlap: partial");
    ok &= Require(
        Coordinator::RangesOverlap({100, 200}, {120, 20}),
        "overlap: containment");
    ok &= Require(
        !Coordinator::RangesOverlap({100, 50}, {150, 50}),
        "overlap: adjacent is disjoint");
    ok &= Require(
        !Coordinator::RangesOverlap({100, 50}, {200, 50}),
        "overlap: separate");
    ok &= Require(
        !Coordinator::RangesOverlap({100, 0}, {100, 50}),
        "overlap: empty range never overlaps");
    ok &= Require(
        Coordinator::RangesOverlap(
            {UINT64_MAX - 10, 20}, {UINT64_MAX - 5, 5}),
        "overlap: overflow treated as overlap (fail closed)");
    return ok;
}

// Deallocated ranges leave the coordinator ledger before new allocations are
// checked. This permits legitimate APFS reuse while retaining overlap checks
// against both prior and same-batch allocations.
bool TestLedgerAppliesDeallocationBeforeReuse()
{
    using Coordinator = apfsaccess::catalog::ContainerMountCoordinator;
    using Range = Coordinator::ExtentRange;
    std::vector<Range> ledger{{100, 100}, {300, 50}};
    std::string error;
    bool ok = true;
    ok &= Require(
        Coordinator::ApplyExtentDelta(
            ledger,
            {},
            std::vector<Range>{{120, 40}},
            error),
        "ledger-delta: deallocation is applied");
    ok &= Require(ledger.size() == 3, "ledger-delta: ranges normalize");
    if (ledger.size() == 3)
    {
        ok &= Require(
            ledger[0].address == 100 && ledger[0].bytes == 20,
            "ledger-delta: left remainder retained");
        ok &= Require(
            ledger[1].address == 160 && ledger[1].bytes == 40,
            "ledger-delta: right remainder retained");
        ok &= Require(
            ledger[2].address == 300 && ledger[2].bytes == 50,
            "ledger-delta: unrelated range retained");
    }
    ok &= Require(
        Coordinator::ApplyExtentDelta(
            ledger,
            std::vector<Range>{{120, 40}, {350, 25}},
            {},
            error),
        "ledger-delta: freed range may be reused");
    ok &= Require(
        ledger.size() == 2 && ledger[0].address == 100 &&
            ledger[0].bytes == 100 && ledger[1].address == 300 &&
            ledger[1].bytes == 75,
        "ledger-delta: adjacent ranges merge after reuse");

    const auto before_rejection = ledger;
    ok &= Require(
        !Coordinator::ApplyExtentDelta(
            ledger,
            std::vector<Range>{{110, 20}, {500, 10}},
            {},
            error),
        "ledger-delta: overlap is rejected");
    ok &= Require(
        ledger.size() == before_rejection.size() &&
            std::equal(
                ledger.begin(), ledger.end(), before_rejection.begin(),
                [](const Range& left, const Range& right)
                {
                    return left.address == right.address &&
                        left.bytes == right.bytes;
                }),
        "ledger-delta: rejection leaves ledger unchanged");
    return ok;
}

std::string PortableSha256Hex(const std::string& bytes)
{
    std::string error;
    auto stream = apfsaccess::observer::Sha256Stream::Create(error);
    if (stream == nullptr)
    {
        return std::string();
    }
    if (!stream->Update(
            reinterpret_cast<const std::byte*>(bytes.data()), bytes.size()))
    {
        return std::string();
    }
    std::string hex;
    if (!stream->FinalHex(hex))
    {
        return std::string();
    }
    return hex;
}

// T_manifest_checksum_roundtrip: a manifest checksummed with the INDEPENDENT
// portable SHA-256 parses (cross-checks the coordinator's private SHA-256
// and pins the section-7 rule); any tampering fails closed.
bool TestManifestChecksumRoundtrip()
{
    const auto dir = MakeRunDir("manifest-ok");
    const std::string uuid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const std::string device = "D:\\fixture\\two.apfs.img";
    const std::string canonical =
        "manifest-check-v1\n" + uuid + "\n" + device + "\n0\n"
        "101\n" + uuid + "\nAlpha\nA:\\mnt\\Alpha\nW\nvol-alpha\n"
        "102\n" + uuid + "\nBeta\nA:\\mnt\\Beta\nR\nvol-beta\n";
    const std::string checksum = PortableSha256Hex(canonical);
    if (!Require(!checksum.empty(), "manifest-ok: portable sha works"))
    {
        return false;
    }
    const auto manifest_path = dir / "good.json";
    {
        std::ofstream out(manifest_path, std::ios::binary | std::ios::trunc);
        out << "{\"format\":\"apfs-access-container-manifest\",\"version\":1,"
            << "\"containerUuid\":\"" << uuid << "\",\"device\":\""
            << "D:\\\\fixture\\\\two.apfs.img\",\"deviceOffsetBytes\":0,"
            << "\"manifestSha256\":\"" << checksum << "\",\"volumes\":["
            << "{\"objectId\":101,\"containerUuid\":\"" << uuid
            << "\",\"name\":\"Alpha\",\"mount\":\"A:\\\\mnt\\\\Alpha\","
            << "\"requestedWrite\":true,\"recoveryIdentity\":\"vol-alpha\"},"
            << "{\"objectId\":\"102\",\"containerUuid\":\"" << uuid
            << "\",\"name\":\"Beta\",\"mount\":\"A:\\\\mnt\\\\Beta\","
            << "\"requestedWrite\":false,\"recoveryIdentity\":\"vol-beta\"}]}";
    }
    bool ok = true;
    apfsaccess::catalog::ContainerManifest parsed{};
    std::string error;
    ok &= Require(
        apfsaccess::catalog::ParseContainerManifest(
            manifest_path.string(), parsed, error),
        "manifest-ok: checksummed manifest parses");
    if (!ok)
    {
        std::fprintf(stderr, "[INFO] manifest error: %s\n", error.c_str());
        std::ifstream probe(manifest_path, std::ios::binary);
        std::ostringstream snapshot;
        snapshot << probe.rdbuf();
        const std::string bytes = snapshot.str();
        std::fprintf(
            stderr, "[INFO] manifest bytes=%zu head=%.80s\n", bytes.size(),
            bytes.c_str());
        return false;
    }
    ok &= Require(
        parsed.container_uuid_hex == uuid, "manifest-ok: container uuid");
    ok &= Require(
        parsed.device_path == device, "manifest-ok: device verbatim");
    ok &= Require(
        parsed.volumes.size() == 2, "manifest-ok: two volumes");
    ok &= Require(
        parsed.volumes[0].object_id == 101 &&
            parsed.volumes[0].requested_write &&
            parsed.volumes[0].recovery_identity == "vol-alpha",
        "manifest-ok: volume 101 fields");
    ok &= Require(
        parsed.volumes[1].object_id == 102 &&
            !parsed.volumes[1].requested_write &&
            parsed.volumes[1].recovery_identity == "vol-beta",
        "manifest-ok: volume 102 fields (string OID accepted)");
    const auto tampered_path = dir / "tampered.json";
    {
        std::ifstream in(manifest_path, std::ios::binary);
        std::ostringstream body;
        body << in.rdbuf();
        std::string text = body.str();
        const auto pos = text.find("Alpha");
        if (pos != std::string::npos)
        {
            text[pos] = 'B';
        }
        std::ofstream out(tampered_path, std::ios::binary | std::ios::trunc);
        out << text;
    }
    apfsaccess::catalog::ContainerManifest tampered{};
    ok &= Require(
        !apfsaccess::catalog::ParseContainerManifest(
            tampered_path.string(), tampered, error),
        "manifest-ok: tampered manifest refused");
    return ok;
}
bool TestManifestProtected()
{
    const auto dir = MakeRunDir("manifest");
    bool ok = true;
    const auto target = dir / "real.json";
    {
        std::ofstream out(target, std::ios::binary | std::ios::trunc);
        out << "{\"format\":\"apfs-access-container-manifest\"}";
    }
    const auto link = dir / "link.json";
    std::error_code ec;
    std::filesystem::create_symlink(target, link, ec);
    if (!ec)
    {
        apfsaccess::catalog::ContainerManifest parsed{};
        std::string error;
        ok &= Require(
            !apfsaccess::catalog::ParseContainerManifest(
                link.string(), parsed, error),
            "manifest: symlink refused");
    }
    const auto bad = dir / "bad.json";
    {
        std::ofstream out(bad, std::ios::binary | std::ios::trunc);
        out << "{\"format\":";
    }
    apfsaccess::catalog::ContainerManifest parsed{};
    std::string error;
    ok &= Require(
        !apfsaccess::catalog::ParseContainerManifest(
            bad.string(), parsed, error),
        "manifest: truncated schema refused");
    return ok;
}

bool TestManifestRejectsSymlinkedParent()
{
    const auto dir = MakeRunDir("manifest-parent-link");
    const auto target_dir = dir / "target";
    std::error_code ec;
    std::filesystem::create_directories(target_dir, ec);
    if (!Require(!ec, "manifest-parent-link: target directory created"))
    {
        return false;
    }
    const std::string uuid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const std::string canonical =
        "manifest-check-v1\n" + uuid + "\ndev\n0\n"
        "101\n" + uuid + "\nAlpha\nE:\\\nR\nalpha\n";
    const std::string checksum = PortableSha256Hex(canonical);
    const auto target = target_dir / "manifest.json";
    {
        std::ofstream out(target, std::ios::binary | std::ios::trunc);
        out << "{\"format\":\"apfs-access-container-manifest\",\"version\":1,"
            << "\"containerUuid\":\"" << uuid << "\",\"device\":\"dev\","
            << "\"deviceOffsetBytes\":0,\"manifestSha256\":\"" << checksum
            << "\",\"volumes\":[{\"objectId\":101,\"containerUuid\":\""
            << uuid << "\",\"name\":\"Alpha\",\"mount\":\"E:\\\\\","
            << "\"requestedWrite\":false,\"recoveryIdentity\":\"alpha\"}]}";
    }
    const auto linked_parent = dir / "linked-parent";
    std::filesystem::create_directory_symlink(target_dir, linked_parent, ec);
    if (ec)
    {
        std::fprintf(
            stderr,
            "[FAIL] manifest-parent-link: directory symlink unavailable (%s)\n",
            ec.message().c_str());
        ++g_failures;
        return false;
    }
    apfsaccess::catalog::ContainerManifest parsed{};
    std::string error;
    return Require(
        !apfsaccess::catalog::ParseContainerManifest(
            (linked_parent / "manifest.json").string(), parsed, error),
        "manifest-parent-link: symlinked parent refused");
}

// T_manifest_rejects_shared_recovery_identity: recovery/journal/spool state
// is keyed per volume, so two volumes sharing one identity fail closed.
bool TestManifestRejectsSharedRecoveryIdentity()
{
    const auto dir = MakeRunDir("manifest-dupident");
    const std::string uuid = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const std::string canonical_prefix =
        std::string("manifest-check-v1\n") + uuid + "\ndev\n0\n";
    const std::string canonical =
        canonical_prefix + "101\n" + uuid + "\nA\nmA\nR\nsame\n" + "102\n" +
        uuid + "\nB\nmB\nR\nsame\n";
    const std::string checksum = PortableSha256Hex(canonical);
    if (!Require(!checksum.empty(), "manifest-dupident: sha works"))
    {
        return false;
    }
    const auto manifest_path = dir / "dup.json";
    {
        std::ofstream out(manifest_path, std::ios::binary | std::ios::trunc);
        out << "{\"format\":\"apfs-access-container-manifest\",\"version\":1,"
            << "\"containerUuid\":\"" << uuid << "\",\"device\":\"dev\","
            << "\"deviceOffsetBytes\":0,\"manifestSha256\":\"" << checksum
            << "\",\"volumes\":["
            << "{\"objectId\":101,\"containerUuid\":\"" << uuid
            << "\",\"name\":\"A\",\"mount\":\"mA\",\"requestedWrite\":false,"
            << "\"recoveryIdentity\":\"same\"},"
            << "{\"objectId\":102,\"containerUuid\":\"" << uuid
            << "\",\"name\":\"B\",\"mount\":\"mB\",\"requestedWrite\":false,"
            << "\"recoveryIdentity\":\"same\"}]}";
    }
    apfsaccess::catalog::ContainerManifest parsed{};
    std::string error;
    return Require(
        !apfsaccess::catalog::ParseContainerManifest(
            manifest_path.string(), parsed, error),
        "manifest-dupident: shared recovery identity refused");
}

bool TestManifestRejectsMissingWritableRecoveryIdentity()
{
    const auto dir = MakeRunDir("manifest-missing-ident");
    const std::string uuid = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const std::string canonical =
        std::string("manifest-check-v1\n") + uuid + "\ndev\n0\n" +
        "101\n" + uuid + "\nA\nE:\\\nW\n\n";
    const std::string checksum = PortableSha256Hex(canonical);
    const auto manifest_path = dir / "missing.json";
    {
        std::ofstream out(manifest_path, std::ios::binary | std::ios::trunc);
        out << "{\"format\":\"apfs-access-container-manifest\",\"version\":1,"
            << "\"containerUuid\":\"" << uuid << "\",\"device\":\"dev\","
            << "\"deviceOffsetBytes\":0,\"manifestSha256\":\"" << checksum
            << "\",\"volumes\":[{\"objectId\":101,\"containerUuid\":\""
            << uuid << "\",\"name\":\"A\",\"mount\":\"E:\\\\\","
            << "\"requestedWrite\":true,\"recoveryIdentity\":\"\"}]}";
    }
    apfsaccess::catalog::ContainerManifest parsed{};
    std::string error;
    return Require(
        !apfsaccess::catalog::ParseContainerManifest(
            manifest_path.string(), parsed, error),
        "manifest-missing-ident: writable entry without recovery identity refused");
}

bool TestManifestRejectsDuplicateJsonKeys()
{
    const auto dir = MakeRunDir("manifest-dupkey");
    const std::string uuid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const std::string canonical =
        "manifest-check-v1\n" + uuid + "\ndev\n0\n"
        "101\n" + uuid + "\nAlpha\nA:\\Alpha\nW\nalpha\n";
    const std::string checksum = PortableSha256Hex(canonical);
    const auto path = dir / "duplicate-key.json";
    {
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        out << "{\"format\":\"apfs-access-container-manifest\","
            << "\"version\":1,\"containerUuid\":\"" << uuid
            << "\",\"device\":\"dev\",\"device\":\"dev\","
            << "\"deviceOffsetBytes\":0,\"manifestSha256\":\""
            << checksum << "\",\"volumes\":[{\"objectId\":101,"
            << "\"containerUuid\":\"" << uuid
            << "\",\"name\":\"Alpha\",\"mount\":\"A:\\\\Alpha\","
            << "\"requestedWrite\":true,"
            << "\"recoveryIdentity\":\"alpha\"}]}";
    }
    apfsaccess::catalog::ContainerManifest parsed{};
    std::string error;
    return Require(
        !apfsaccess::catalog::ParseContainerManifest(
            path.string(), parsed, error),
        "manifest-dupkey: duplicate object key refused");
}

bool TestManifestRejectsDuplicateMountTargets()
{
    const auto dir = MakeRunDir("manifest-dupmount");
    const std::string uuid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const std::string canonical =
        "manifest-check-v1\n" + uuid + "\ndev\n0\n"
        "101\n" + uuid + "\nAlpha\nA:\\shared\nW\nalpha\n"
        "102\n" + uuid + "\nBeta\na:/SHARED/\nR\nbeta\n";
    const std::string checksum = PortableSha256Hex(canonical);
    const auto path = dir / "duplicate-mount.json";
    {
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        out << "{\"format\":\"apfs-access-container-manifest\","
            << "\"version\":1,\"containerUuid\":\"" << uuid
            << "\",\"device\":\"dev\",\"deviceOffsetBytes\":0,"
            << "\"manifestSha256\":\"" << checksum
            << "\",\"volumes\":["
            << "{\"objectId\":101,\"containerUuid\":\"" << uuid
            << "\",\"name\":\"Alpha\",\"mount\":\"A:\\\\shared\","
            << "\"requestedWrite\":true,\"recoveryIdentity\":\"alpha\"},"
            << "{\"objectId\":102,\"containerUuid\":\"" << uuid
            << "\",\"name\":\"Beta\",\"mount\":\"a:/SHARED/\","
            << "\"requestedWrite\":false,\"recoveryIdentity\":\"beta\"}]}";
    }
    apfsaccess::catalog::ContainerManifest parsed{};
    std::string error;
    return Require(
        !apfsaccess::catalog::ParseContainerManifest(
            path.string(), parsed, error),
        "manifest-dupmount: duplicate mount target refused");
}

bool TestManifestRejectsOversizedInput()
{
    const auto dir = MakeRunDir("manifest-oversized");
    const std::string uuid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const std::string canonical =
        "manifest-check-v1\n" + uuid + "\ndev\n0\n"
        "101\n" + uuid + "\nAlpha\nA:\\Alpha\nW\nalpha\n";
    const std::string checksum = PortableSha256Hex(canonical);
    std::ostringstream json;
    json << "{\"format\":\"apfs-access-container-manifest\","
         << "\"version\":1,\"containerUuid\":\"" << uuid
         << "\",\"device\":\"dev\",\"deviceOffsetBytes\":0,"
         << "\"manifestSha256\":\"" << checksum
         << "\",\"volumes\":[{\"objectId\":101,"
         << "\"containerUuid\":\"" << uuid
         << "\",\"name\":\"Alpha\",\"mount\":\"A:\\\\Alpha\","
         << "\"requestedWrite\":true,"
         << "\"recoveryIdentity\":\"alpha\"}]}";
    std::string document = json.str();
    document.resize((1024u * 1024u) + 1u, ' ');
    const auto path = dir / "oversized.json";
    {
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        out.write(
            document.data(), static_cast<std::streamsize>(document.size()));
    }
    apfsaccess::catalog::ContainerManifest parsed{};
    std::string error;
    return Require(
        !apfsaccess::catalog::ParseContainerManifest(
            path.string(), parsed, error),
        "manifest-oversized: bounded parser refuses oversized input");
}

} // namespace

int main()
{
    bool ok = true;
    ok &= TestCoordinatorAcquiresWritableLeaseBeforeServing();
    ok &= TestSessionsShareOneRawLease();
    ok &= TestCoordinatorOpensSingleContainer();
    ok &= TestCoordinatorMountsTwoVolumes();
    ok &= TestCoordinatorRejectsMismatch();
    ok &= TestRejectedCommitNeverReportsCommittedStatus();
    ok &= TestCoordinatorUnmountSiblingSafe();
    ok &= TestCoordinatorSerializesCommits();
    ok &= TestCoordinatorAdvancesOneGlobalCheckpointSequence();
    ok &= TestCoordinatorPreservesAlternatingNamespacesAcrossRemount();
    ok &= TestAppleCoordinatorPreservesAlternatingVolumesAcrossRemount();
    ok &= TestCoordinatorSeparatesDuplicateNameSidecars();
    ok &= TestCanonicalReloadKeepsQuietSiblingNamespace();
    ok &= TestInterruptedReplayTargetsExactVolume();
    ok &= TestSharedReplayCommitBlobBindsVolumeIdentity();
    ok &= TestCoordinatorRollsBackPartiallyStagedBatch();
    ok &= TestCoordinatorPrepublicationHookRejectsWithoutMediaChange();
    ok &= TestCoordinatorSerializesSessionTransitionsWithCommit();
    ok &= TestCoordinatorIsolatesPreWriteFailureAcrossVolumes();
    ok &= TestCoordinatorHandlesSharedSpaceExhaustionAtomically();
    ok &= TestAppleCoordinatorUsesSharedSpacemanForSiblingPayloads();
    ok &= TestAppleCoordinatorCrashBoundariesSelectCompleteGeneration();
    ok &= TestAppleCoordinatorDrainWaitsForActiveCommit();
    ok &= TestCoordinatorDrainAndStop();
    ok &= TestLedgerOverlapPredicate();
    ok &= TestLedgerAppliesDeallocationBeforeReuse();
    ok &= TestManifestChecksumRoundtrip();
    ok &= TestManifestRejectsSharedRecoveryIdentity();
    ok &= TestManifestRejectsMissingWritableRecoveryIdentity();
    ok &= TestManifestRejectsDuplicateJsonKeys();
    ok &= TestManifestRejectsDuplicateMountTargets();
    ok &= TestManifestRejectsOversizedInput();
    ok &= TestManifestProtected();
    ok &= TestManifestRejectsSymlinkedParent();
    {
        std::lock_guard<std::mutex> lock(g_run_dirs_mutex);
        for (const auto& dir : g_run_dirs)
        {
            std::error_code ec;
            std::filesystem::remove_all(dir, ec);
        }
        g_run_dirs.clear();
    }
    if (ok && g_failures == 0)
    {
        std::printf("container-coordinator: all green\n");
        return 0;
    }
    std::fprintf(
        stderr, "container-coordinator: %d failure(s)\n", g_failures);
    return 1;
}
