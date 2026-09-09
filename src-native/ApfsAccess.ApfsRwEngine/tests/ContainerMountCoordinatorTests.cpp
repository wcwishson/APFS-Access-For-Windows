// RED: ContainerMountCoordinator does not exist yet. Each test names the
// seam or API it pins; link failure is the RED signal until GREEN.

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
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
#include "AppleTransactionCommit.h"
#include "ApfsExtendedRecordCodec.h"
#include "CompressionRewrite.h"
#include "InodeMetadataPatch.h"
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
    std::uint64_t main_free_blocks = 0,
    std::uint64_t internal_pool_blocks = 4,
    std::uint32_t checkpoint_ring_blocks = 8)
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
    store.authoritative_internal_pool_blocks = internal_pool_blocks;
    store.authoritative_checkpoint_ring_blocks = checkpoint_ring_blocks;
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

bool WriteCompressionPreparationImage(const std::filesystem::path& path)
{
    using namespace apfsaccess::rw;
    testfixture::BuilderStore fixture;
    fixture.authoritative_checkpoint = true;
    fixture.dual_checkpoint = false;
    fixture.xid = 20;
    fixture.block_count = 512;
    fixture.authoritative_internal_pool_blocks = 16;
    fixture.authoritative_checkpoint_ring_blocks = 32;
    testfixture::BuilderVolume alpha, beta;
    alpha.oid = 101; alpha.name = "Alpha";
    beta.oid = 102; beta.name = "Beta";
    std::string error;
    apfsaccess::catalog::BtreeRecord encoded;
    const auto append = [&](bool valid) {
        if (!Require(valid, "preparation fixture: encode native record")) return false;
        alpha.filesystem_records.push_back(std::move(encoded));
        return true;
    };
    AppleInodeRecord root;
    root.object_id = root.parent_id = root.private_id = 2;
    root.mode = 0040755; root.children_or_links = 1;
    if (!append(EncodeAppleInodeRecord(root, encoded, error))) return false;
    AppleInodeRecord file;
    file.object_id = 17; file.private_id = 117; file.parent_id = 2;
    file.mode = 0100644; file.children_or_links = 1; file.uncompressed_size = 5;
    file.bsd_flags = kAppleBsdCompressedFlag;
    AppleExtendedField stream;
    stream.type = 8; stream.data.resize(40); // Compressed default stream is empty.
    file.extended_fields.push_back(std::move(stream));
    if (!append(EncodeAppleInodeRecord(file, encoded, error))) return false;
    AppleDirectoryRecord link;
    link.parent_id = 2; link.file_id = 17; link.flags = 8; link.name_utf8 = "compressed";
    if (!append(EncodeAppleDirectoryRecord(link, encoded, error))) return false;
    std::vector<std::byte> attribute(21);
    testfixture::PutU32LE(attribute, 0, 0x636d7066);
    testfixture::PutU32LE(attribute, 4, 1); // Existing native type-1 support.
    testfixture::PutU64LE(attribute, 8, 5);
    testfixture::PutBytes(attribute, 16, "hello", 5);
    if (!append(EncodeAppleXattrRecord({17, "com.apple.decmpfs", kAppleXattrDataEmbedded, attribute},
            encoded, error)) ||
        !Require(SortAppleBtreeRecords(alpha.filesystem_records,
            AppleBtreeKeyOrder::FileSystemCaseSensitive, error), "preparation fixture: sort native records")) return false;
    fixture.volumes = {alpha, beta};
    return WriteFileBytes(path, testfixture::BuildStoreImage(fixture));
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

bool TestCoordinatorMutationStagingHookRejectsWithoutMediaChange()
{
    using Store = apfsaccess::rw::MetadataStore;

    const auto dir = MakeRunDir("mutation-staging-hook");
    const auto image = dir / "two.raw";
    if (!Require(
            WriteAuthoritativeTwoVolumeImage(image),
            "mutation-staging-hook: build authoritative fixture"))
    {
        return false;
    }
    std::string error;
    auto coordinator = apfsaccess::catalog::ContainerMountCoordinator::Open(
        image.string(),
        0,
        error,
        apfsaccess::catalog::CatalogLoadPolicy::StrictApple);
    if (!Require(coordinator != nullptr, "mutation-staging-hook: open"))
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
            "mutation-staging-hook: mount"))
    {
        return false;
    }

    Store::MutationRequest create{};
    create.operation = Store::MutationOperation::CreateFile;
    create.path = L"\\staging-source.bin";
    Store::MutationRequest rename{};
    rename.operation = Store::MutationOperation::Rename;
    rename.path = create.path;
    rename.secondary_path = L"\\staging-destination.bin";
    std::vector<std::size_t> seen_indices;
    std::uint64_t staged_object_id = 0;
    bool prepublication_called = false;
    const auto before = ReadFileBytes(image);
    const auto rejected = coordinator->Commit(
        101,
        {create, rename},
        [&](const auto&,
            const auto&,
            std::uint64_t,
            std::vector<std::uint64_t>&,
            std::string&)
        {
            prepublication_called = true;
            return true;
        },
        [&](std::size_t mutation_index,
            const Store::MutationRequest& request,
            const Store::PayloadIdentity& identity,
            std::string& hook_error)
        {
            seen_indices.push_back(mutation_index);
            if (mutation_index == 0)
            {
                staged_object_id = identity.object_id;
                return request.operation == Store::MutationOperation::CreateFile &&
                    identity.object_id != 0 && identity.generation != 0;
            }
            hook_error = "InjectedPreparedPayloadFailure";
            return false;
        });
    auto* store = coordinator->FindSessionStore(101);
    bool ok = true;
    ok &= Require(
        !rejected.committed &&
            rejected.commit_status_code ==
                static_cast<int>(Store::CommitStatus::InvariantFailed) &&
            rejected.commit_stage == "mutation-staging-hook" &&
            rejected.error.find("CommitMutationStagingHookFailed") == 0 &&
            seen_indices == std::vector<std::size_t>{0, 1} &&
            staged_object_id != 0 && !prepublication_called &&
            ReadFileBytes(image) == before && store != nullptr &&
            store->PendingMutationCount() == 0 &&
            !store->LookupCommittedInodeByPath(create.path).has_value() &&
            !store->LookupCommittedInodeByPath(rename.secondary_path).has_value(),
        "mutation-staging-hook: second-stage refusal rolls back without publication");
    const auto retried = coordinator->Commit(101, {create, rename});
    ok &= Require(
        retried.committed && store != nullptr &&
            !store->LookupCommittedInodeByPath(create.path).has_value() &&
            store->LookupCommittedInodeByPath(rename.secondary_path).has_value(),
        "mutation-staging-hook: unchanged batch retries successfully");
    return ok;
}

bool TestRequiredCheckpointCensusFailsClosedAtomically()
{
    using apfsaccess::catalog::ContainerMountCoordinator;
    using apfsaccess::catalog::ContainerVolumeSession;
    using apfsaccess::catalog::VolumeCheckpointPins;
    using Store = apfsaccess::rw::MetadataStore;

    const auto dir = MakeRunDir("required-census");
    const auto image = dir / "two.raw";
    if (!Require(
            WriteAuthoritativeTwoVolumeImage(image),
            "required-census: build authoritative fixture"))
    {
        return false;
    }
    std::string error;
    auto coordinator = ContainerMountCoordinator::Open(
        image.string(),
        0,
        error,
        apfsaccess::catalog::CatalogLoadPolicy::StrictApple,
        false,
        true);
    if (!Require(coordinator != nullptr, "required-census: open"))
    {
        return false;
    }
    bool ok = true;
    ok &= Require(
        coordinator->CheckpointCensusRequired(),
        "required-census: immutable mode accessor reports required");

    ContainerVolumeSession alpha{};
    alpha.volume_object_id = 101;
    alpha.container_uuid_hex = coordinator->ContainerUuidHex();
    alpha.requested_write = true;
    alpha.use_canonical_transaction = true;
    if (!Require(
            coordinator->MountVolume(alpha, error),
            "required-census: mount writable session"))
    {
        return false;
    }

    Store::MutationRequest create{};
    create.operation = Store::MutationOperation::CreateDirectory;
    create.path = L"\\barrier-must-not-stage";
    bool hook_called = false;
    const auto before = ReadFileBytes(image);
    const auto blocked = coordinator->Commit(
        101,
        {create},
        [&](const auto&,
            const auto&,
            std::uint64_t,
            std::vector<std::uint64_t>&,
            std::string&)
        {
            hook_called = true;
            return true;
        });
    const auto after = ReadFileBytes(image);
    auto* store = coordinator->FindSessionStore(101);
    ok &= Require(
        !blocked.committed &&
            blocked.commit_status_code ==
                static_cast<int>(Store::CommitStatus::NotReady) &&
            blocked.error == "RequiredCheckpointCensusIncomplete" &&
            !hook_called && before == after && store != nullptr &&
            store->PendingMutationCount() == 0,
        "required-census: incomplete barrier rejects before hook, staging, or image I/O");

    const std::uint64_t checkpoint_xid = coordinator->CheckpointXid();
    const auto rejects = [&](const std::vector<VolumeCheckpointPins>& pins,
                             const char* diagnostic,
                             const char* message)
    {
        std::string census_error;
        return Require(
            !coordinator->InitializeRequiredCheckpointCensus(
                pins, census_error) &&
                census_error.find(diagnostic) == 0,
            message);
    };
    ok &= rejects(
        {{101, {}}, {999, {}}},
        "RequiredCheckpointCensusVolumeUnknown",
        "required-census: unknown catalog volume refused");
    ok &= rejects(
        {{101, {}}, {101, {}}},
        "RequiredCheckpointCensusVolumeDuplicate",
        "required-census: duplicate catalog volume refused");
    ok &= rejects(
        {{101, {}}},
        "RequiredCheckpointCensusIncomplete",
        "required-census: unrepresented catalog sibling refused");
    ok &= rejects(
        {{101, {0}}, {102, {}}},
        "RequiredCheckpointXidZero",
        "required-census: zero checkpoint XID refused");
    ok &= rejects(
        {{101, {}, true}, {102, {}}},
        "RequiredCheckpointUnappliedSourceMissing",
        "required-census: unapplied accepted work cannot lack a retained source");
    ok &= rejects(
        {{101, {checkpoint_xid, checkpoint_xid}}, {102, {}}},
        "RequiredCheckpointXidDuplicate",
        "required-census: duplicate checkpoint XID refused");
    ok &= rejects(
        {{101, {checkpoint_xid + 1}}, {102, {}}},
        "RequiredCheckpointXidFuture",
        "required-census: future checkpoint XID refused");
    ok &= Require(
        ReadFileBytes(image) == before,
        "required-census: failed census attempts do not mutate the image");

    error.clear();
    ok &= Require(
        coordinator->InitializeRequiredCheckpointCensus(
            {{102, {}}, {101, {}}}, error) && error.empty(),
        "required-census: complete out-of-order census installs atomically");
    ok &= Require(!coordinator->UpdateRequiredCheckpointXids(102, {}, error, true) &&
            error == "RequiredCheckpointUnappliedSourceMissing",
        "required-census: invalid pending-work refresh preserves the previous census");
    error.clear();
    ok &= Require(
        !coordinator->InitializeRequiredCheckpointCensus(
            {{101, {checkpoint_xid}}, {102, {}}}, error) &&
            error == "RequiredCheckpointCensusAlreadyInitialized",
        "required-census: successful initialization occurs only once");

    std::uint64_t hook_preimage = 0;
    create.path = L"\\barrier-open";
    const auto committed = coordinator->Commit(
        101,
        {create},
        [&](const auto&,
            const auto&,
            std::uint64_t preimage,
            std::vector<std::uint64_t>& pins,
            std::string&)
        {
            hook_preimage = preimage;
            return pins.empty();
        });
    ok &= Require(
        committed.committed && hook_preimage == checkpoint_xid,
        "required-census: valid census opens commit and supplies current preimage");
    return ok;
}

bool TestRequiredCheckpointHookUsesReloadedSiblingPreimage()
{
    using apfsaccess::catalog::ContainerMountCoordinator;
    using apfsaccess::catalog::ContainerVolumeSession;
    using Store = apfsaccess::rw::MetadataStore;

    const auto dir = MakeRunDir("required-preimage");
    const auto image = dir / "two.raw";
    if (!Require(
            WriteAuthoritativeTwoVolumeImage(image),
            "required-preimage: build authoritative fixture"))
    {
        return false;
    }
    std::string error;
    auto coordinator = ContainerMountCoordinator::Open(
        image.string(),
        0,
        error,
        apfsaccess::catalog::CatalogLoadPolicy::StrictApple,
        false,
        true);
    if (!Require(coordinator != nullptr, "required-preimage: open") ||
        !Require(
            coordinator->InitializeRequiredCheckpointCensus(
                {{101, {}}, {102, {}}}, error),
            "required-preimage: initialize census"))
    {
        return false;
    }
    for (const std::uint64_t oid : {101ull, 102ull})
    {
        ContainerVolumeSession session{};
        session.volume_object_id = oid;
        session.container_uuid_hex = coordinator->ContainerUuidHex();
        session.requested_write = true;
        session.use_canonical_transaction = true;
        if (!Require(
                coordinator->MountVolume(session, error),
                "required-preimage: mount sibling"))
        {
            return false;
        }
    }

    Store::MutationRequest alpha{};
    alpha.operation = Store::MutationOperation::CreateDirectory;
    alpha.path = L"\\alpha-advances-container";
    const auto alpha_commit = coordinator->Commit(101, {alpha});
    if (!Require(
            alpha_commit.committed,
            "required-preimage: first sibling commit succeeds"))
    {
        return false;
    }

    Store::MutationRequest beta{};
    beta.operation = Store::MutationOperation::CreateDirectory;
    beta.path = L"\\beta-reloads-container";
    std::uint64_t seen_preimage = 0;
    const auto beta_commit = coordinator->Commit(
        102,
        {beta},
        [&](const auto&,
            const auto&,
            std::uint64_t preimage,
            std::vector<std::uint64_t>& pins,
            std::string&)
        {
            seen_preimage = preimage;
            return pins.empty();
        });
    return Require(
        beta_commit.committed &&
            seen_preimage == alpha_commit.checkpoint_xid &&
            seen_preimage != 0,
        "required-preimage: hook receives session XID after sibling reload");
}

std::unique_ptr<apfsaccess::catalog::ContainerMountCoordinator>
OpenDiagnosticsCoordinator(const char* name, std::filesystem::path& image)
{
    image = MakeRunDir(name) / "two.raw";
    if (!Require(WriteAuthoritativeTwoVolumeImage(image, 0, 32, 32),
            "diagnostics: build authoritative fixture")) return nullptr;
    std::string error;
    auto coordinator = apfsaccess::catalog::ContainerMountCoordinator::Open(image.string(), 0, error);
    if (!Require(coordinator != nullptr, "diagnostics: open owner")) return nullptr;
    for (const auto oid : {101ULL, 102ULL})
    {
        apfsaccess::catalog::ContainerVolumeSession session;
        session.volume_object_id = oid;
        session.container_uuid_hex = coordinator->ContainerUuidHex();
        session.requested_write = true;
        session.use_canonical_transaction = true;
        if (!Require(coordinator->MountVolume(session, error), "diagnostics: mount volume")) return nullptr;
    }
    return coordinator;
}

bool RequireDiagnosticTotals(const apfsaccess::catalog::ContainerCommitDiagnostics& counters)
{
    return Require(counters.commit_attempts == counters.commit_successes +
            counters.commit_noops + counters.commit_failures &&
        counters.commit_total_us == counters.commit_wait_total_us + counters.commit_hold_total_us &&
        counters.commit_max_us <= counters.commit_total_us &&
        counters.reload_attempts == counters.precommit_reload_attempts +
            counters.rollback_reload_attempts + counters.recovery_reload_attempts &&
        counters.reload_failures <= counters.reload_attempts &&
        counters.reload_max_us <= counters.reload_total_us && counters.reload_reuses == 0,
        "diagnostics: consistent outcome/phase totals and conservative zero reuse");
}

bool TestCoordinatorDiagnosticsCountsAndReloads()
{
    using Store = apfsaccess::rw::MetadataStore;
    std::filesystem::path image;
    auto coordinator = OpenDiagnosticsCoordinator("diagnostics-counts", image);
    if (!coordinator) return false;
    auto before = coordinator->DiagnosticsSnapshot();
    bool ok = Require(before.commit_attempts == 0 && before.reload_attempts == 0,
        "diagnostics: mount work is excluded");
    const auto original_xid = coordinator->CheckpointXid();
    std::uint64_t hook_calls = 0;
    auto* alpha = coordinator->FindSessionStore(101);
    alpha->SetCommitStageHook([&](std::string_view stage)
    {
        if (stage == "before-apple-publish")
        {
            // Sampling while Commit holds its mutex must remain safe. Only
            // completed scopes appear; the current precommit reload is done.
            const auto sample = coordinator->DiagnosticsSnapshot(101);
            ok &= Require(sample.precommit_reload_attempts > sample.commit_attempts,
                "diagnostics: hook observes reload before active commit is counted");
            ++hook_calls;
        }
        return true;
    });
    std::uint64_t publications = 0;
    for (const auto oid : {101ULL, 101ULL, 102ULL, 101ULL})
    {
        Store::MutationRequest create;
        create.operation = Store::MutationOperation::CreateDirectory;
        create.path = L"\\diagnostic-" + std::to_wstring(publications);
        const auto result = coordinator->Commit(oid, {create});
        if (!Require(result.committed && result.commit_status_code ==
                static_cast<int>(Store::CommitStatus::Committed), "diagnostics: publish repeated/sibling batch"))
            return false;
        ++publications;
        ok &= Require(result.checkpoint_xid == original_xid + publications,
            "diagnostics: each publication uses current shared checkpoint");
    }
    alpha->SetCommitStageHook({});
    const auto bytes = ReadFileBytes(image);
    const auto noop = coordinator->Commit(101, {});
    ok &= Require(noop.committed && noop.commit_status_code ==
            static_cast<int>(Store::CommitStatus::NothingToCommit) &&
            ReadFileBytes(image) == bytes && coordinator->CheckpointXid() == original_xid + 4,
        "diagnostics: empty batch reports no-op without publication");
    const auto total = coordinator->DiagnosticsSnapshot();
    const auto a = coordinator->DiagnosticsSnapshot(101);
    const auto b = coordinator->DiagnosticsSnapshot(102);
    ok &= Require(total.commit_attempts == 5 && total.commit_successes == 4 &&
            total.commit_noops == 1 && total.commit_failures == 0 &&
            total.precommit_reload_attempts == 5 && total.reload_attempts == 5 &&
            a.commit_attempts == 4 && a.commit_successes == 3 && a.commit_noops == 1 &&
            b.commit_attempts == 1 && b.commit_successes == 1 && hook_calls == 3 &&
            total.reload_total_us == a.reload_total_us + b.reload_total_us &&
            total.commit_total_us == a.commit_total_us + b.commit_total_us,
        "diagnostics: exact same-volume, sibling, no-op and per-volume counts");
    ok &= RequireDiagnosticTotals(total);
    std::string error;
    ok &= Require(coordinator->UnmountVolume(101, error), "diagnostics: unmount counted volume");
    apfsaccess::catalog::ContainerVolumeSession remount;
    remount.volume_object_id = 101;
    remount.container_uuid_hex = coordinator->ContainerUuidHex();
    remount.requested_write = true;
    remount.use_canonical_transaction = true;
    if (!Require(coordinator->MountVolume(remount, error), "diagnostics: remount counted volume")) return false;
    ok &= Require(coordinator->Commit(101, {}).committed &&
            coordinator->DiagnosticsSnapshot(101).precommit_reload_attempts == 5,
        "diagnostics: remount retains counters and next commit reloads");
    ok &= Require(!coordinator->Commit(999, {}).committed &&
            coordinator->DiagnosticsSnapshot(999).commit_attempts == 0 &&
            coordinator->DiagnosticsSnapshot().commit_failures == 1,
        "diagnostics: unknown volume rejection belongs only to container totals");
    ok &= Require(coordinator->DrainAndStop(std::chrono::seconds(5)).clean &&
            !coordinator->Commit(101, {}).committed &&
            coordinator->DiagnosticsSnapshot(101).commit_attempts == 6 &&
            coordinator->DiagnosticsSnapshot(101).commit_failures == 1 &&
            coordinator->DiagnosticsSnapshot(101).reload_attempts == 5,
        "diagnostics: counters survive drain and count rejection without reloading");
    return RequireDiagnosticTotals(coordinator->DiagnosticsSnapshot()) && ok;
}

bool TestCoordinatorDiagnosticsFailureAndBorrowedStore()
{
    using Store = apfsaccess::rw::MetadataStore;
    std::filesystem::path image;
    auto coordinator = OpenDiagnosticsCoordinator("diagnostics-borrowed", image);
    if (!coordinator) return false;
    auto* store = coordinator->FindSessionStore(101);
    Store::MutationRequest create;
    create.operation = Store::MutationOperation::CreateDirectory;
    create.path = L"\\retry";
    const auto before_failure = ReadFileBytes(image);
    store->SetCommitStageHook([](std::string_view stage) { return stage != "before-apple-publish"; });
    const auto failed = coordinator->Commit(101, {create});
    store->SetCommitStageHook({});
    auto counters = coordinator->DiagnosticsSnapshot(101);
    bool ok = Require(!failed.committed && !failed.commit_recovery_required &&
            ReadFileBytes(image) == before_failure && store->PendingMutationCount() == 0 &&
            counters.commit_failures == 1 && counters.precommit_reload_attempts == 1 &&
            counters.rollback_reload_attempts == 1 && counters.reload_failures == 0,
        "diagnostics: clean publication refusal records precommit and rollback reloads");
    if (!Require(coordinator->Commit(101, {create}).committed, "diagnostics: clean retry succeeds")) return false;
    counters = coordinator->DiagnosticsSnapshot(101);
    ok &= Require(counters.commit_successes == 1 && counters.precommit_reload_attempts == 2 &&
            counters.reload_attempts == 3, "diagnostics: retry performs full reload");

    create.path = L"\\borrowed-unpublished";
    if (!Require(store->StageMutation(create) == Store::MutationStatus::Applied,
            "diagnostics: simulate mutation through borrowed mutable store")) return false;
    const auto staged_xid = store->CheckpointXid();
    const auto staged_bytes = ReadFileBytes(image);
    const auto rejected = coordinator->Commit(101, {});
    std::string error;
    ok &= Require(!rejected.committed && rejected.error == "CommitUnexpectedPendingState" &&
            !coordinator->RefreshSessionForRecovery(101, error) &&
            error == "RecoveryRefreshUnexpectedPendingState" &&
            store->PendingMutationCount() == 1 && ReadFileBytes(image) == staged_bytes &&
            coordinator->DiagnosticsSnapshot(101).reload_attempts == 3,
        "diagnostics: borrowed staging is refused without discard or reload");
    // A retained pointer can reset working state without changing XID or
    // leaving pending mutations. No coordinator notification is emitted.
    if (!Require(store->PrepareNativeWritePath() && store->PendingMutationCount() == 0 &&
            store->CheckpointXid() == staged_xid, "diagnostics: borrowed reset bypasses coordinator")) return false;
    ok &= Require(coordinator->Commit(101, {}).committed &&
            !store->LookupCommittedInodeByPath(create.path) &&
            coordinator->DiagnosticsSnapshot(101).reload_attempts == 4,
        "diagnostics: same-XID zero-pending borrowed reset still takes full reload");

    // Deliberately exercise the documented direct-commit bypass as a negative
    // contract witness. This is not an endorsed host commit path.
    create.path = L"\\borrowed-published";
    if (!Require(store->StageMutation(create) == Store::MutationStatus::Applied &&
            store->CommitCanonicalTransaction() == Store::CommitStatus::Committed &&
            store->PendingMutationCount() == 0 && store->CheckpointXid() !=
                std::optional<std::uint64_t>{coordinator->CheckpointXid()},
            "diagnostics: direct borrowed publication bypasses coordinator checkpoint")) return false;
    const auto before_sync = coordinator->DiagnosticsSnapshot();
    ok &= Require(coordinator->RefreshCheckpointFromSession(101, error) &&
            coordinator->RefreshSessionForRecovery(102, error) &&
            coordinator->Commit(102, {}).committed &&
            coordinator->DiagnosticsSnapshot().precommit_reload_attempts == before_sync.precommit_reload_attempts + 1 &&
            coordinator->DiagnosticsSnapshot().recovery_reload_attempts == 1 &&
            coordinator->FindSessionStore(102)->CheckpointXid() == store->CheckpointXid(),
        "diagnostics: checkpoint sync and recovery refresh cannot elide next reload");
    ok &= RequireDiagnosticTotals(coordinator->DiagnosticsSnapshot());

    // Existing regular-image sharing permits an external in-place change.
    // Destroy this private fixture's source so the next reload must fail.
    auto damaged = ReadFileBytes(image);
    std::fill(damaged.begin(), damaged.end(), std::byte{0});
    if (!Require(WriteFileBytes(image, damaged), "diagnostics: inject unreadable canonical source")) return false;
    const auto before_reload_failure = coordinator->DiagnosticsSnapshot();
    const auto reload_failed = coordinator->Commit(101, {});
    counters = coordinator->DiagnosticsSnapshot();
    ok &= Require(!reload_failed.committed &&
            reload_failed.error.find("CommitCommitterReloadFailed") == 0 &&
            counters.reload_failures == before_reload_failure.reload_failures + 1 &&
            counters.precommit_reload_attempts == before_reload_failure.precommit_reload_attempts + 1 &&
            counters.commit_failures == before_reload_failure.commit_failures + 1,
        "diagnostics: detected external damage counts failed reload and commit");
    return RequireDiagnosticTotals(counters) && ok;
}

bool TestAcceptedSiblingRecoveryAdmissionPreservesPins()
{
    using apfsaccess::catalog::ContainerMountCoordinator;
    using apfsaccess::catalog::ContainerVolumeSession;
    using Store = apfsaccess::rw::MetadataStore;

    const auto dir = MakeRunDir("accepted-sibling-recovery");
    const auto image = dir / "two.raw";
    if (!Require(
            WriteAuthoritativeTwoVolumeImage(image, 0, 32, 32),
            "accepted-sibling: build authoritative fixture"))
    {
        return false;
    }
    std::string error;
    auto coordinator = ContainerMountCoordinator::Open(
        image.string(),
        0,
        error,
        apfsaccess::catalog::CatalogLoadPolicy::StrictApple,
        false,
        true);
    if (!Require(coordinator != nullptr, "accepted-sibling: open"))
    {
        return false;
    }
    for (const std::uint64_t oid : {101ull, 102ull})
    {
        ContainerVolumeSession session{};
        session.volume_object_id = oid;
        session.container_uuid_hex = coordinator->ContainerUuidHex();
        session.requested_write = true;
        session.use_canonical_transaction = true;
        session.metadata_context.integrity_check_on_mount = false;
        if (!Require(
                coordinator->MountVolume(session, error),
                "accepted-sibling: mount sibling"))
        {
            return false;
        }
    }

    const auto source_xid = coordinator->CheckpointXid();
    if (!Require(
            coordinator->InitializeRequiredCheckpointCensus(
                {{101, {source_xid}, true}, {102, {source_xid}, true}}, error),
            "accepted-sibling: initialize dual-pending census"))
    {
        return false;
    }
    auto* alpha = coordinator->FindSessionStore(101);
    auto* beta = coordinator->FindSessionStore(102);
    if (!Require(alpha != nullptr && beta != nullptr,
            "accepted-sibling: stores available"))
    {
        return false;
    }

    const std::wstring alpha_path = L"\\alpha-recovered.bin";
    const std::wstring beta_path = L"\\beta-recovered.bin";
    std::vector<std::byte> alpha_payload(6144);
    std::vector<std::byte> beta_payload(7168);
    for (std::size_t index = 0; index < alpha_payload.size(); ++index)
        alpha_payload[index] = static_cast<std::byte>((index * 17u + 3u) & 0xffu);
    for (std::size_t index = 0; index < beta_payload.size(); ++index)
        beta_payload[index] = static_cast<std::byte>((index * 31u + 5u) & 0xffu);
    alpha->SetFilePayloadProvider(
        [&](const std::wstring& path, std::uint64_t size)
            -> std::optional<std::vector<std::byte>>
        {
            return path == alpha_path && size == alpha_payload.size()
                ? std::optional(alpha_payload) : std::nullopt;
        });
    beta->SetFilePayloadProvider(
        [&](const std::wstring& path, std::uint64_t size)
            -> std::optional<std::vector<std::byte>>
        {
            return path == beta_path && size == beta_payload.size()
                ? std::optional(beta_payload) : std::nullopt;
        });
    const auto create_and_write = [](const std::wstring& path, std::uint64_t size)
    {
        Store::MutationRequest create{};
        create.operation = Store::MutationOperation::CreateFile;
        create.path = path;
        Store::MutationRequest write{};
        write.operation = Store::MutationOperation::Write;
        write.path = path;
        write.length = size;
        return std::vector<Store::MutationRequest>{create, write};
    };

    bool ok = true;
    const auto original = ReadFileBytes(image);
    Store::MutationRequest fresh{};
    fresh.operation = Store::MutationOperation::CreateDirectory;
    fresh.path = L"\\fresh-must-wait";
    const auto ordinary_blocked = coordinator->Commit(101, {fresh});
    ok &= Require(
        !ordinary_blocked.committed &&
            ordinary_blocked.error == "VolumeAcceptedRecoveryPending: oid=101" &&
            ReadFileBytes(image) == original,
        "accepted-sibling: ordinary work remains blocked before staging and I/O");

    const auto failed = coordinator->Commit(
        101,
        create_and_write(alpha_path, alpha_payload.size()),
        [](const auto&, const auto&, std::uint64_t,
            std::vector<std::uint64_t>&, std::string& hook_error)
        {
            hook_error = "InjectedReplayPublicationRefusal";
            return false;
        },
        {},
        {},
        true);
    const auto after_failed = ReadFileBytes(image);
    const auto still_pending = coordinator->Commit(101, {fresh});
    ok &= Require(
        !failed.committed && after_failed == original &&
            coordinator->CheckpointXid() == source_xid &&
            !still_pending.committed &&
            still_pending.error == "VolumeAcceptedRecoveryPending: oid=101",
        "accepted-sibling: failed publication retains target pin and pending authority");

    const auto before_replay_diagnostics = coordinator->DiagnosticsSnapshot(101);
    const auto alpha_first = coordinator->Commit(
        101, create_and_write(alpha_path, alpha_payload.size()), {}, {}, {}, true);
    Store::MutationRequest alpha_second_request{};
    alpha_second_request.operation = Store::MutationOperation::CreateDirectory;
    alpha_second_request.path = L"\\alpha-second-accepted";
    const auto alpha_second = coordinator->Commit(
        101, {alpha_second_request}, {}, {}, {}, true);
    for (const auto* outcome : {&alpha_first, &alpha_second})
        if (!outcome->committed)
            std::fprintf(stderr, "[DIAG] accepted Alpha replay: %s stage=%s reason=%ls\n",
                outcome->error.c_str(), outcome->commit_stage.c_str(), alpha->LastCommitFailureReason().c_str());
    const auto alpha_object_id = alpha_first.staged_identities.empty()
        ? 0 : alpha_first.staged_identities.front().object_id;
    ok &= Require(
        alpha_first.committed && alpha_object_id != 0 &&
            alpha_first.committed_xid == source_xid + 1 &&
            alpha_second.committed && alpha_second.committed_xid == source_xid + 2,
        "accepted-sibling: one pending target remains authorized across replay chunks");
    const auto after_replay_diagnostics = coordinator->DiagnosticsSnapshot(101);
    ok &= Require(after_replay_diagnostics.commit_successes == before_replay_diagnostics.commit_successes + 2 &&
            after_replay_diagnostics.precommit_reload_attempts == before_replay_diagnostics.precommit_reload_attempts + 2 &&
            after_replay_diagnostics.reload_attempts == before_replay_diagnostics.reload_attempts + 2 &&
            after_replay_diagnostics.reload_reuses == 0,
        "accepted-sibling: each accepted replay chunk retains full precommit reload");
    ok &= RequireDiagnosticTotals(after_replay_diagnostics);
    const auto alpha_pending_after_publish = coordinator->Commit(101, {fresh});
    ok &= Require(
        !alpha_pending_after_publish.committed &&
            alpha_pending_after_publish.error == "VolumeAcceptedRecoveryPending: oid=101",
        "accepted-sibling: replay publication cannot clear pending state before WAL cleanup");

    ok &= Require(
        coordinator->UpdateRequiredCheckpointXids(101, {}, error, false),
        "accepted-sibling: Alpha cleanup releases only Alpha state");
    const auto before_forged = ReadFileBytes(image);
    const auto forged = coordinator->Commit(101, {fresh}, {}, {}, {}, true);
    ok &= Require(
        !forged.committed && forged.error == "SiblingAcceptedRecoveryPending: oid=102" &&
            ReadFileBytes(image) == before_forged,
        "accepted-sibling: clean Alpha cannot forge replay around pending Beta");

    const auto stale_beta_xid = beta->CheckpointXid().value_or(0);
    std::uint64_t staged_object_id = 0;
    std::uint64_t staged_generation = 0;
    bool saw_reloaded_beta = false;
    const auto beta_replay = coordinator->Commit(
        102,
        create_and_write(beta_path, beta_payload.size()),
        {},
        [&](std::size_t index, const auto&, const auto& identity, std::string&)
        {
            saw_reloaded_beta = beta->CheckpointXid().value_or(0) == source_xid + 2;
            if (index == 0)
            {
                staged_object_id = identity.object_id;
                staged_generation = identity.generation;
            }
            return identity.object_id == staged_object_id &&
                identity.generation == staged_generation;
        },
        {},
        true);
    if (!beta_replay.committed)
        std::fprintf(stderr, "[DIAG] accepted Beta replay: %s stage=%s reason=%ls\n",
            beta_replay.error.c_str(), beta_replay.commit_stage.c_str(), beta->LastCommitFailureReason().c_str());
    ok &= Require(
        stale_beta_xid == source_xid && saw_reloaded_beta &&
            staged_object_id != 0 && staged_generation == source_xid + 3 &&
            beta_replay.committed && beta_replay.committed_xid == source_xid + 3,
        "accepted-sibling: stale Beta rebases to a fresh XID with stable OID");
    const auto beta_pending_after_publish = coordinator->Commit(101, {fresh});
    ok &= Require(
        !beta_pending_after_publish.committed &&
            beta_pending_after_publish.error == "SiblingAcceptedRecoveryPending: oid=102",
        "accepted-sibling: sibling pin remains until Beta cleanup");
    ok &= Require(
        coordinator->UpdateRequiredCheckpointXids(102, {}, error, false) &&
            coordinator->Commit(101, {fresh}).committed,
        "accepted-sibling: fresh ordinary work resumes only after all cleanup updates");

    if (!Require(
            coordinator->DrainAndStop(std::chrono::seconds(5)).clean,
            "accepted-sibling: drain first owner"))
    {
        return false;
    }
    auto remounted = ContainerMountCoordinator::Open(image.string(), 0, error);
    if (!Require(remounted != nullptr, "accepted-sibling: reopen image"))
    {
        return false;
    }
    for (const std::uint64_t oid : {101ull, 102ull})
    {
        ContainerVolumeSession session{};
        session.volume_object_id = oid;
        session.container_uuid_hex = remounted->ContainerUuidHex();
        session.use_canonical_transaction = true;
        session.metadata_context.integrity_check_on_mount = false;
        if (!Require(remounted->MountVolume(session, error),
                "accepted-sibling: remount sibling"))
        {
            return false;
        }
    }
    alpha = remounted->FindSessionStore(101);
    beta = remounted->FindSessionStore(102);
    std::uint64_t remounted_alpha_object_id = 0;
    std::uint64_t remounted_beta_object_id = 0;
    if (alpha)
    {
        if (const auto inode = alpha->LookupCommittedInodeByPath(alpha_path))
            remounted_alpha_object_id = inode->object_id;
    }
    if (beta)
    {
        if (const auto inode = beta->LookupCommittedInodeByPath(beta_path))
            remounted_beta_object_id = inode->object_id;
    }
    std::vector<std::byte> actual;
    ok &= Require(
        alpha != nullptr && remounted_alpha_object_id == alpha_object_id &&
            alpha->ReadCommittedFileRange(alpha_path, 0, alpha_payload.size(), actual) &&
            actual == alpha_payload &&
            !alpha->LookupCommittedInodeByPath(beta_path).has_value(),
        "accepted-sibling: Alpha OID bytes and namespace survive fresh mount");
    actual.clear();
    ok &= Require(
        beta != nullptr && remounted_beta_object_id == staged_object_id &&
            beta->ReadCommittedFileRange(beta_path, 0, beta_payload.size(), actual) &&
            actual == beta_payload &&
            !beta->LookupCommittedInodeByPath(alpha_path).has_value(),
        "accepted-sibling: Beta OID bytes and namespace survive fresh mount");
    return ok;
}

bool TestVolumeReplayBoundaryFollowsOnlyUnchangedSiblings()
{
    using namespace apfsaccess;
    using Store = rw::MetadataStore;
    const auto image = MakeRunDir("volume-replay-boundary") / "two.raw";
    if (!Require(WriteAuthoritativeTwoVolumeImage(image, 0, 32, 32),
            "replay boundary: build strict two-volume image")) return false;
    std::string error;
    auto coordinator = catalog::ContainerMountCoordinator::Open(image.string(), 0, error,
        catalog::CatalogLoadPolicy::StrictApple, false, true);
    if (!Require(coordinator != nullptr, "replay boundary: open owner")) return false;
    const auto original = coordinator->CheckpointXid();
    if (!Require(coordinator->InitializeRequiredCheckpointCensus({{101, {original}}, {102, {original}}}, error),
            "replay boundary: pin original history")) return false;
    for (const auto oid : {101ULL, 102ULL})
    {
        catalog::ContainerVolumeSession session;
        session.volume_object_id = oid;
        session.container_uuid_hex = coordinator->ContainerUuidHex();
        session.requested_write = true;
        session.use_canonical_transaction = true;
        if (!Require(coordinator->MountVolume(session, error), "replay boundary: mount selected volume")) return false;
    }
    const auto inspect = [&](std::uint64_t oid, std::uint64_t preimage, std::uint64_t expected,
                             std::optional<std::uint64_t> changed) {
        const auto bytes = ReadFileBytes(image);
        catalog::VectorRandomAccessSource source(bytes);
        const auto checkpoint = catalog::LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
        rw::AppleVolumeReplayBoundary boundary;
        const bool found = checkpoint && rw::FindAppleVolumeReplayBoundary(
            source, *checkpoint, oid, preimage, boundary, error);
        if (!found) std::fprintf(stderr, "[INFO] replay boundary: %s\n", error.c_str());
        return Require(found && boundary.preimage_checkpoint_xid == expected &&
                boundary.first_changed_checkpoint_xid == changed && ReadFileBytes(image) == bytes,
            "replay boundary: exact unchanged chain and first changed checkpoint, without writes");
    };
    if (!inspect(102, original, original, {})) return false;
    Store::MutationRequest create;
    create.operation = Store::MutationOperation::CreateDirectory;
    create.path = L"\\alpha-first";
    if (!Require(coordinator->Commit(101, {create}).committed, "replay boundary: first sibling publication")) return false;
    bool ok = inspect(102, original, original + 1, {});
    ok &= inspect(101, original, original, original + 1);
    create.path = L"\\alpha-second";
    if (!Require(coordinator->Commit(101, {create}).committed, "replay boundary: second sibling publication")) return false;
    ok &= inspect(102, original, original + 2, {});
    create.path = L"\\beta-first";
    if (!Require(coordinator->Commit(102, {create}).committed, "replay boundary: selected volume publication")) return false;
    ok &= inspect(102, original, original + 2, original + 3);
    ok &= inspect(101, original, original, original + 1);
    const auto before_refresh_diagnostics = coordinator->DiagnosticsSnapshot(101);
    if (!Require(coordinator->RefreshSessionForRecovery(101, error),
            "replay boundary: refresh unchanged volume after sibling publication")) return false;
    const auto after_refresh_diagnostics = coordinator->DiagnosticsSnapshot(101);
    ok &= Require(after_refresh_diagnostics.recovery_reload_attempts ==
            before_refresh_diagnostics.recovery_reload_attempts + 1 &&
            after_refresh_diagnostics.commit_attempts == before_refresh_diagnostics.commit_attempts,
        "replay boundary: recovery refresh records a reload outside commit totals");
    const auto alpha = coordinator->FindSessionStore(101)->LookupCommittedInodeByPath(L"\\alpha-second");
    ok &= Require(alpha && alpha->xid == original + 2 && coordinator->CheckpointXid() == original + 3,
        "replay boundary: reader retains volume generation independently of container generation");
    const auto before_stale = ReadFileBytes(image);
    create.path = L"\\stale-replay";
    const auto stale = coordinator->Commit(101, {create}, {}, {}, {}, true, original + 2);
    ok &= Require(!stale.committed && stale.error == "AcceptedReplayPreimageAdvanced" &&
            ReadFileBytes(image) == before_stale && coordinator->FindSessionStore(101)->PendingMutationCount() == 0,
        "replay boundary: container lock rejects a stale replay boundary before staging or writes");
    const auto after_stale_diagnostics = coordinator->DiagnosticsSnapshot(101);
    ok &= Require(after_stale_diagnostics.precommit_reload_attempts ==
            after_refresh_diagnostics.precommit_reload_attempts + 1 &&
            after_stale_diagnostics.commit_failures == after_refresh_diagnostics.commit_failures + 1 &&
            after_stale_diagnostics.reload_reuses == 0,
        "replay boundary: prior recovery refresh cannot skip stale-replay reload");
    ok &= RequireDiagnosticTotals(after_stale_diagnostics);
    auto bytes = ReadFileBytes(image);
    catalog::VectorRandomAccessSource source(bytes);
    const auto checkpoint = catalog::LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
    if (!Require(checkpoint.has_value(), "replay boundary: reload final raw checkpoint")) return false;
    rw::AppleVolumeReplayBoundary boundary;
    for (const auto bad : {0ULL, static_cast<unsigned long long>(original - 1),
                           static_cast<unsigned long long>(checkpoint->container.superblock.xid + 1)})
    {
        boundary.preimage_checkpoint_xid = 999;
        boundary.first_changed_checkpoint_xid = 999;
        ok &= Require(!rw::FindAppleVolumeReplayBoundary(source, *checkpoint, 102, bad, boundary, error) &&
                boundary.preimage_checkpoint_xid == 0 && !boundary.first_changed_checkpoint_xid,
            "replay boundary: invalid or unavailable preimage refuses and clears output");
    }
    ok &= Require(!rw::FindAppleVolumeReplayBoundary(source, *checkpoint, 999, original, boundary, error),
        "replay boundary: wrong volume cannot inherit another volume's history");
    auto malformed = *checkpoint;
    malformed.volumes.push_back(malformed.volumes.back());
    ok &= Require(!rw::FindAppleVolumeReplayBoundary(source, malformed, 102, original, boundary, error),
        "replay boundary: duplicate volume identity refuses");
    malformed = *checkpoint;
    malformed.volumes.back().superblock.uuid_hex = "ffffffffffffffffffffffffffffffff";
    ok &= Require(!rw::FindAppleVolumeReplayBoundary(source, malformed, 102, original, boundary, error),
        "replay boundary: changed volume UUID refuses");
    return ok;
}

bool TestRequiredCheckpointPinsSurviveUnmountAndRetryLifecycle()
{
    using apfsaccess::catalog::ContainerMountCoordinator;
    using apfsaccess::catalog::ContainerVolumeSession;
    using Store = apfsaccess::rw::MetadataStore;

    bool ok = true;
    const auto internal_pool_dir = MakeRunDir("required-internal-pool-retention");
    const auto internal_pool_image = internal_pool_dir / "two.raw";
    if (!Require(
            WriteAuthoritativeTwoVolumeImage(internal_pool_image),
            "required-internal-pool-retention: build four-block fixture"))
    {
        return false;
    }
    std::string error;
    auto internal_pool = ContainerMountCoordinator::Open(
        internal_pool_image.string(),
        0,
        error,
        apfsaccess::catalog::CatalogLoadPolicy::StrictApple,
        false,
        true);
    if (!Require(
            internal_pool != nullptr,
            "required-internal-pool-retention: open"))
    {
        return false;
    }
    const std::uint64_t internal_pool_pin = internal_pool->CheckpointXid();
    if (!Require(
            internal_pool->InitializeRequiredCheckpointCensus(
                {{101, {}}, {102, {internal_pool_pin}}}, error),
            "required-internal-pool-retention: initialize pinned census"))
    {
        return false;
    }
    ContainerVolumeSession internal_pool_alpha{};
    internal_pool_alpha.volume_object_id = 101;
    internal_pool_alpha.container_uuid_hex = internal_pool->ContainerUuidHex();
    internal_pool_alpha.requested_write = true;
    internal_pool_alpha.use_canonical_transaction = true;
    if (!Require(
            internal_pool->MountVolume(internal_pool_alpha, error),
            "required-internal-pool-retention: mount writer"))
    {
        return false;
    }
    Store::MutationRequest internal_pool_first{};
    internal_pool_first.operation = Store::MutationOperation::CreateDirectory;
    internal_pool_first.path = L"\\internal-pool-first";
    if (!Require(
            internal_pool->Commit(101, {internal_pool_first}).committed,
            "required-internal-pool-retention: first pinned generation commits"))
    {
        return false;
    }
    Store::MutationRequest internal_pool_blocked_request{};
    internal_pool_blocked_request.operation =
        Store::MutationOperation::CreateDirectory;
    internal_pool_blocked_request.path = L"\\internal-pool-blocked";
    const auto internal_pool_before = ReadFileBytes(internal_pool_image);
    const auto internal_pool_blocked =
        internal_pool->Commit(101, {internal_pool_blocked_request});
    auto* internal_pool_store = internal_pool->FindSessionStore(101);
    ok &= Require(
        !internal_pool_blocked.committed &&
            internal_pool_blocked.commit_status_code ==
                static_cast<int>(Store::CommitStatus::RetentionBlocked) &&
            internal_pool_blocked.commit_stage ==
                "apple-plan-retention-blocked" &&
            !internal_pool_blocked.commit_recovery_required &&
            !internal_pool->IsRecoveryRequired() &&
            internal_pool_store != nullptr &&
            internal_pool_store->LastCommitFailureDetail() ==
                L"AppleSpacemanInternalPoolRetentionExhausted" &&
            ReadFileBytes(internal_pool_image) == internal_pool_before,
        "required-internal-pool-retention: pin-caused exhaustion is retryable and no-I/O");
    std::string internal_pool_update_error;
    ok &= Require(
        internal_pool->UpdateRequiredCheckpointXids(
            102, {}, internal_pool_update_error),
        "required-internal-pool-retention: cleanup releases sibling pin");
    ok &= Require(
        internal_pool->Commit(101, {internal_pool_blocked_request}).committed,
        "required-internal-pool-retention: exact restaged request commits without pins");

    const auto sibling_dir = MakeRunDir("required-sibling-retention");
    const auto sibling_image = sibling_dir / "two.raw";
    if (!Require(
            WriteAuthoritativeTwoVolumeImage(sibling_image, 0, 16),
            "required-sibling-retention: build authoritative fixture"))
    {
        return false;
    }
    auto sibling = ContainerMountCoordinator::Open(
        sibling_image.string(),
        0,
        error,
        apfsaccess::catalog::CatalogLoadPolicy::StrictApple,
        false,
        true);
    if (!Require(sibling != nullptr, "required-sibling-retention: open"))
    {
        return false;
    }
    const std::uint64_t retained_xid = sibling->CheckpointXid();
    if (!Require(
            sibling->InitializeRequiredCheckpointCensus(
                {{101, {}}, {102, {retained_xid}}}, error),
            "required-sibling-retention: initialize census"))
    {
        return false;
    }
    ContainerVolumeSession beta_read_only{};
    beta_read_only.volume_object_id = 102;
    beta_read_only.container_uuid_hex = sibling->ContainerUuidHex();
    beta_read_only.use_canonical_transaction = true;
    if (!Require(
            sibling->MountVolume(beta_read_only, error) &&
                sibling->UnmountVolume(102, error),
            "required-sibling-retention: read-only sibling unmounts"))
    {
        return false;
    }
    ContainerVolumeSession alpha{};
    alpha.volume_object_id = 101;
    alpha.container_uuid_hex = sibling->ContainerUuidHex();
    alpha.requested_write = true;
    alpha.use_canonical_transaction = true;
    if (!Require(
            sibling->MountVolume(alpha, error),
            "required-sibling-retention: mount writer"))
    {
        return false;
    }

    Store::MutationRequest first{};
    first.operation = Store::MutationOperation::CreateDirectory;
    first.path = L"\\retained-first";
    if (!Require(
            sibling->Commit(101, {first}).committed,
            "required-sibling-retention: one generation publishes with sibling pin"))
    {
        return false;
    }
    Store::MutationRequest blocked_request{};
    blocked_request.operation = Store::MutationOperation::CreateDirectory;
    blocked_request.path = L"\\retained-blocked";
    const auto before_block = ReadFileBytes(sibling_image);
    const auto blocked = sibling->Commit(101, {blocked_request});
    auto* alpha_store = sibling->FindSessionStore(101);
    const bool blocked_image_unchanged =
        ReadFileBytes(sibling_image) == before_block;
    if (blocked.commit_status_code !=
            static_cast<int>(Store::CommitStatus::RetentionBlocked))
    {
        std::fprintf(
            stderr,
            "[INFO] sibling retention first refusal: status=%d committed=%d stage=%s error=%s checkpoint=%llu pending=%zu recovery=%d storeReason=%ls storeDetail=%ls imageUnchanged=%d\n",
            blocked.commit_status_code,
            blocked.committed ? 1 : 0,
            blocked.commit_stage.c_str(),
            blocked.error.c_str(),
            static_cast<unsigned long long>(sibling->CheckpointXid()),
            alpha_store != nullptr ? alpha_store->PendingMutationCount() : 0,
            sibling->IsRecoveryRequired() ? 1 : 0,
            alpha_store != nullptr
                ? alpha_store->LastCommitFailureReason().c_str()
                : L"store-missing",
            alpha_store != nullptr
                ? alpha_store->LastCommitFailureDetail().c_str()
                : L"store-missing",
            blocked_image_unchanged ? 1 : 0);
    }
    ok &= Require(
        !blocked.committed &&
            blocked.commit_status_code ==
                static_cast<int>(Store::CommitStatus::RetentionBlocked) &&
            blocked.error.find("CommitRetentionBlocked") == 0 &&
            !blocked.commit_recovery_required &&
            !sibling->IsRecoveryRequired() &&
            alpha_store != nullptr && alpha_store->PendingMutationCount() == 0 &&
            blocked_image_unchanged,
        "required-sibling-retention: unmounted read-only sibling pin causes retryable no-I/O refusal");

    const std::uint64_t current_xid = sibling->CheckpointXid();
    std::string update_error;
    ok &= Require(
        !sibling->UpdateRequiredCheckpointXids(999, {}, update_error) &&
            update_error.find("RequiredCheckpointVolumeUnknown") == 0,
        "required-sibling-retention: unknown update volume refused");
    ok &= Require(
        !sibling->UpdateRequiredCheckpointXids(102, {0}, update_error) &&
            update_error == "RequiredCheckpointXidZero",
        "required-sibling-retention: zero update XID refused");
    ok &= Require(
        !sibling->UpdateRequiredCheckpointXids(
            102, {retained_xid, retained_xid}, update_error) &&
            update_error == "RequiredCheckpointXidDuplicate",
        "required-sibling-retention: duplicate update XID refused");
    ok &= Require(
        !sibling->UpdateRequiredCheckpointXids(
            102, {current_xid + 1}, update_error) &&
            update_error.find("RequiredCheckpointXidFuture") == 0,
        "required-sibling-retention: future update XID refused");
    const auto still_blocked = sibling->Commit(101, {blocked_request});
    if (still_blocked.commit_status_code !=
            static_cast<int>(Store::CommitStatus::RetentionBlocked))
    {
        std::fprintf(
            stderr,
            "[INFO] sibling retention after invalid updates: status=%d committed=%d stage=%s error=%s checkpoint=%llu recovery=%d imageUnchanged=%d\n",
            still_blocked.commit_status_code,
            still_blocked.committed ? 1 : 0,
            still_blocked.commit_stage.c_str(),
            still_blocked.error.c_str(),
            static_cast<unsigned long long>(sibling->CheckpointXid()),
            sibling->IsRecoveryRequired() ? 1 : 0,
            ReadFileBytes(sibling_image) == before_block ? 1 : 0);
    }
    ok &= Require(
        still_blocked.commit_status_code ==
                static_cast<int>(Store::CommitStatus::RetentionBlocked) &&
            ReadFileBytes(sibling_image) == before_block,
        "required-sibling-retention: invalid updates preserve the sibling pin");
    ok &= Require(
        sibling->UpdateRequiredCheckpointXids(102, {}, update_error),
        "required-sibling-retention: durable cleanup releases sibling pin");
    ok &= Require(
        sibling->Commit(101, {blocked_request}).committed,
        "required-sibling-retention: caller restages and retry succeeds after cleanup release");

    const auto hook_dir = MakeRunDir("required-hook-retention");
    const auto hook_image = hook_dir / "two.raw";
    if (!Require(
            WriteAuthoritativeTwoVolumeImage(hook_image, 0, 16),
            "required-hook-retention: build authoritative fixture"))
    {
        return false;
    }
    auto hooked = ContainerMountCoordinator::Open(
        hook_image.string(),
        0,
        error,
        apfsaccess::catalog::CatalogLoadPolicy::StrictApple,
        false,
        true);
    if (!Require(hooked != nullptr, "required-hook-retention: open") ||
        !Require(
            hooked->InitializeRequiredCheckpointCensus(
                {{101, {}}, {102, {}}}, error),
            "required-hook-retention: initialize census"))
    {
        return false;
    }
    alpha.container_uuid_hex = hooked->ContainerUuidHex();
    if (!Require(
            hooked->MountVolume(alpha, error),
            "required-hook-retention: mount writer"))
    {
        return false;
    }

    Store::MutationRequest accepted_then_failed{};
    accepted_then_failed.operation = Store::MutationOperation::CreateDirectory;
    accepted_then_failed.path = L"\\accepted-hook-refusal";
    const auto before_hook = ReadFileBytes(hook_image);
    std::uint64_t accepted_preimage = 0;
    const auto hook_refusal = hooked->Commit(
        101,
        {accepted_then_failed},
        [&](const auto&,
            const auto&,
            std::uint64_t preimage,
            std::vector<std::uint64_t>& refreshed_pins,
            std::string& hook_error)
        {
            accepted_preimage = preimage;
            refreshed_pins.push_back(preimage);
            hook_error = "InjectedFailureAfterAcceptance";
            return false;
        });
    ok &= Require(
        !hook_refusal.committed && accepted_preimage != 0 &&
            !hook_refusal.commit_recovery_required &&
            ReadFileBytes(hook_image) == before_hook,
        "required-hook-retention: failed hook retains accepted pin without publication");
    ok &= Require(
        hooked->UpdateRequiredCheckpointXids(101, {}, update_error),
        "required-hook-retention: simulated cleanup releases returned pin");

    Store::MutationRequest failed_scan{};
    failed_scan.operation = Store::MutationOperation::CreateDirectory;
    failed_scan.path = L"\\accepted-hook-scan-failure";
    std::uint64_t conservative_preimage = 0;
    const auto failed_scan_refusal = hooked->Commit(
        101,
        {failed_scan},
        [&](const auto&,
            const auto&,
            std::uint64_t preimage,
            std::vector<std::uint64_t>&,
            std::string& hook_error)
        {
            conservative_preimage = preimage;
            hook_error = "InjectedPostAcceptanceScanFailure";
            return false;
        });
    ok &= Require(
        !failed_scan_refusal.committed &&
            conservative_preimage == accepted_preimage &&
            !failed_scan_refusal.commit_recovery_required &&
            ReadFileBytes(hook_image) == before_hook,
        "required-hook-retention: failed post-acceptance scan conservatively pins preimage");

    Store::MutationRequest hook_first{};
    hook_first.operation = Store::MutationOperation::CreateDirectory;
    hook_first.path = L"\\hook-retained-first";
    const auto unresolved = hooked->Commit(101, {hook_first});
    ok &= Require(!unresolved.committed && unresolved.error == "VolumeAcceptedRecoveryPending: oid=101" &&
            ReadFileBytes(hook_image) == before_hook,
        "required-hook-retention: unknown acceptance blocks new work until journal reconciliation");
    ok &= Require(hooked->UpdateRequiredCheckpointXids(101, {conservative_preimage}, update_error, false),
        "required-hook-retention: simulate a valid rescan with no unapplied work and still-retained pins");
    bool saw_retained_pin = false;
    const auto hook_first_commit = hooked->Commit(
        101,
        {hook_first},
        [&](const auto&,
            const auto&,
            std::uint64_t,
            std::vector<std::uint64_t>& refreshed_pins,
            std::string&)
        {
            saw_retained_pin =
                refreshed_pins ==
                    std::vector<std::uint64_t>{conservative_preimage};
            refreshed_pins.clear();
            return true;
        });
    if (!Require(
            hook_first_commit.committed && saw_retained_pin,
            "required-hook-retention: retry hook sees pin and cannot release it"))
    {
        return false;
    }
    Store::MutationRequest hook_blocked_request{};
    hook_blocked_request.operation = Store::MutationOperation::CreateDirectory;
    hook_blocked_request.path = L"\\hook-retained-blocked";
    const auto hook_before_block = ReadFileBytes(hook_image);
    const auto hook_blocked = hooked->Commit(101, {hook_blocked_request});
    if (hook_blocked.commit_status_code !=
            static_cast<int>(Store::CommitStatus::RetentionBlocked))
    {
        auto* hook_store = hooked->FindSessionStore(101);
        std::fprintf(
            stderr,
            "[INFO] hook retention refusal: status=%d committed=%d stage=%s error=%s checkpoint=%llu pending=%zu recovery=%d storeReason=%ls storeDetail=%ls imageUnchanged=%d\n",
            hook_blocked.commit_status_code,
            hook_blocked.committed ? 1 : 0,
            hook_blocked.commit_stage.c_str(),
            hook_blocked.error.c_str(),
            static_cast<unsigned long long>(hooked->CheckpointXid()),
            hook_store != nullptr ? hook_store->PendingMutationCount() : 0,
            hooked->IsRecoveryRequired() ? 1 : 0,
            hook_store != nullptr
                ? hook_store->LastCommitFailureReason().c_str()
                : L"store-missing",
            hook_store != nullptr
                ? hook_store->LastCommitFailureDetail().c_str()
                : L"store-missing",
            ReadFileBytes(hook_image) == hook_before_block ? 1 : 0);
    }
    ok &= Require(
        hook_blocked.commit_status_code ==
                static_cast<int>(Store::CommitStatus::RetentionBlocked) &&
            !hooked->IsRecoveryRequired() &&
            ReadFileBytes(hook_image) == hook_before_block,
        "required-hook-retention: accepted pin survives failure and hook reduction attempt");
    ok &= Require(
        hooked->UpdateRequiredCheckpointXids(101, {}, update_error) &&
            hooked->Commit(101, {hook_blocked_request}).committed,
        "required-hook-retention: explicit cleanup release permits restaged retry");
    return ok;
}

// A host must bind the staged APFS identity to durable recovery evidence
// before any checkpoint bytes are published. Rejecting that boundary must
// leave both the raw image and the reusable session unchanged.
bool TestRetentionCleanupRetryOwnsOnePublication()
{
    using Store = apfsaccess::rw::MetadataStore;
    bool ok = true;
    for (const std::string mode : {"release", "unchanged", "foreign-pin", "pending-pin",
            "throw", "refuse", "success-with-error", "sibling-pin", "retry-failure", "serialize"})
    {
        const auto image = MakeRunDir(("retention-cleanup-" + mode).c_str()) / "two.raw";
        if (!Require(WriteAuthoritativeTwoVolumeImage(image), "cleanup retry: build strict image")) return false;
        std::string error;
        auto coordinator = apfsaccess::catalog::ContainerMountCoordinator::Open(image.string(), 0, error,
            apfsaccess::catalog::CatalogLoadPolicy::StrictApple, false, true);
        if (!Require(coordinator != nullptr && coordinator->InitializeRequiredCheckpointCensus(
                {{101, {20}}, {102, mode == "sibling-pin" ? std::vector<std::uint64_t>{20} : std::vector<std::uint64_t>{}}}, error),
                "cleanup retry: initialize retained history")) return false;
        apfsaccess::catalog::ContainerVolumeSession alpha;
        alpha.volume_object_id = 101; alpha.container_uuid_hex = coordinator->ContainerUuidHex();
        alpha.requested_write = true; alpha.use_canonical_transaction = true;
        if (!Require(coordinator->MountVolume(alpha, error), "cleanup retry: mount selected volume")) return false;
        Store::MutationRequest first;
        first.operation = Store::MutationOperation::CreateDirectory; first.path = L"\\first";
        if (!Require(coordinator->Commit(101, {first}).committed, "cleanup retry: publish retained prefix")) return false;
        const auto before = ReadFileBytes(image);
        const auto source_xid = coordinator->CheckpointXid();
        auto* store = coordinator->FindSessionStore(101);
        unsigned plans = 0, publications = 0, acceptances = 0, cleanups = 0, stages = 0, preparations = 0, verifications = 0;
        store->SetCommitStageHook([&](std::string_view stage) {
            if (stage == "before-apple-plan")
            {
                ++plans;
                if (mode == "retry-failure" && plans == 2) return false;
            }
            if (stage == "before-apple-publish") ++publications;
            return true;
        });
        Store::MutationRequest next;
        next.operation = Store::MutationOperation::CreateDirectory; next.path = L"\\next";
        std::future<bool> competitor;
        const auto before_diagnostics = coordinator->DiagnosticsSnapshot(101);
        const auto result = coordinator->Commit(101, {},
            [&](const auto&, const auto&, auto source, auto& pins, auto&) {
                ++acceptances;
                pins.push_back(source);
                return true;
            },
            [&](auto, const auto&, const auto&, auto&) { ++stages; return true; },
            [&](auto& pins, std::string& failure) {
                ++cleanups;
                ok &= Require(ReadFileBytes(image) == before && store->PendingMutationCount() == 1,
                    "cleanup retry: no device I/O and original staged mutation survives pressure");
                if (mode == "serialize")
                {
                    std::promise<void> entered;
                    auto ready = entered.get_future();
                    competitor = std::async(std::launch::async, [&, signal = std::move(entered)]() mutable {
                        signal.set_value();
                        std::string sibling_error;
                        return coordinator->UpdateRequiredCheckpointXids(102, {}, sibling_error);
                    });
                    ready.wait();
                    ok &= Require(competitor.wait_for(std::chrono::milliseconds(30)) == std::future_status::timeout,
                        "cleanup retry: sibling cannot cross container ownership during cleanup");
                }
                if (mode == "throw") throw 1;
                if (mode == "refuse") { failure = "test-cleanup-refused"; return false; }
                if (mode == "success-with-error") failure = "test-ambiguous-cleanup";
                if (mode == "unchanged") return true;
                if (mode == "pending-pin") pins.clear();
                else if (mode == "foreign-pin") pins = {19, source_xid};
                else pins = {source_xid};
                return true;
            }, false, std::nullopt,
            [&](const Store& live, auto& requests, auto&) {
                ++preparations;
                ok &= Require(live.CheckpointXid() == source_xid && live.PendingMutationCount() == 0,
                    "cleanup retry: preparation captures source before the original staging pass");
                requests = {next};
                return true;
            },
            [&](const Store& live, auto xid, auto&) {
                ++verifications;
                ok &= Require(xid == source_xid + 1 && live.CheckpointXid() == xid &&
                        live.LookupCommittedInodeByPath(next.path).has_value() && publications == 1,
                    "cleanup retry: verifier sees the single published successor after retry");
                return true;
            });
        if (competitor.valid())
            ok &= Require(competitor.get(), "cleanup retry: sibling resumes after publication returns");
        store->SetCommitStageHook({});
        const bool success = mode == "release" || mode == "serialize";
        ok &= Require(verifications == (success ? 1u : 0u),
            "cleanup retry: verifier runs once only after successful publication");
        const auto after_diagnostics = coordinator->DiagnosticsSnapshot(101);
        ok &= Require(after_diagnostics.commit_attempts == before_diagnostics.commit_attempts + 1 &&
                after_diagnostics.precommit_reload_attempts == before_diagnostics.precommit_reload_attempts + 1,
            "cleanup retry: internal retry counts as one coordinator commit and one precommit reload");
        ok &= RequireDiagnosticTotals(after_diagnostics);
        const bool retry = success || mode == "sibling-pin" || mode == "retry-failure";
        ok &= Require(preparations == 1 && acceptances == 1 && stages == 1 && cleanups == 1 && plans == (retry ? 2u : 1u),
            "cleanup retry: bounded attempt without repeated staging or WAL acceptance");
        if (success)
        {
            ok &= Require(result.committed && publications == 1 &&
                    coordinator->CheckpointXid() == source_xid + 1 &&
                    store->LookupCommittedInodeByPath(next.path).has_value(),
                "cleanup retry: exactly one complete successor checkpoint");
        }
        else
        {
            ok &= Require(!result.committed && publications == 0 && ReadFileBytes(image) == before &&
                    coordinator->CheckpointXid() == source_xid && store->PendingMutationCount() == 0 &&
                    !store->LookupCommittedInodeByPath(next.path).has_value(),
                "cleanup retry: failed cleanup or retry cannot publish or keep scratch staging");
            const bool capacity = mode == "unchanged" || mode == "sibling-pin";
            ok &= Require(result.commit_status_code == static_cast<int>(capacity
                        ? Store::CommitStatus::RetentionBlocked : Store::CommitStatus::InvariantFailed),
                "cleanup retry: unchanged pressure remains distinct from invalid cleanup");
            if (mode == "sibling-pin")
            {
                ok &= Require(coordinator->UpdateRequiredCheckpointXids(102, {}, error),
                    "cleanup retry: explicit sibling cleanup releases only its historical pin");
                const auto fresh_attempt = coordinator->Commit(101, {next});
                ok &= Require(!fresh_attempt.committed && fresh_attempt.error == "VolumeAcceptedRecoveryPending: oid=101" &&
                        ReadFileBytes(image) == before && coordinator->Commit(101, {next}, {}, {}, {}, true).committed,
                    "cleanup retry: after sibling cleanup the original accepted batch needs explicit replay");
            }
        }
    }
    return ok;
}

bool TestCompressionPreparationUsesSerializedFreshPreimage()
{
    using namespace apfsaccess::rw;
    using namespace apfsaccess::catalog;
    using Store = MetadataStore;
    const auto image = MakeRunDir("compression-preparation-fresh") / "two.raw";
    if (!Require(WriteCompressionPreparationImage(image), "preparation: canonical compressed image")) return false;
    std::string error;
    auto coordinator = ContainerMountCoordinator::Open(image.string(), 0, error,
        CatalogLoadPolicy::StrictApple, false, true);
    if (!Require(coordinator && coordinator->InitializeRequiredCheckpointCensus({{101, {20}}, {102, {}}}, error),
            "preparation: initialize source retention")) return false;
    ContainerVolumeSession session;
    session.container_uuid_hex = coordinator->ContainerUuidHex();
    session.requested_write = true; session.use_canonical_transaction = true;
    for (const auto oid : {101u, 102u})
    {
        session.volume_object_id = oid;
        if (!Require(coordinator->MountVolume(session, error), "preparation: mount canonical session")) return false;
    }
    auto* alpha = coordinator->FindSessionStore(101);
    Store::MutationRequest stale;
    if (!Require(alpha->PrepareCompressionRewrite(L"\\compressed", stale), "preparation: capture borrowed stale candidate")) return false;
    Store::MutationRequest sibling;
    sibling.operation = Store::MutationOperation::CreateDirectory; sibling.path = L"\\sibling-before";
    if (!Require(coordinator->Commit(102, {sibling}).committed &&
            coordinator->CheckpointXid() == 21 && alpha->CheckpointXid() == 20,
            "preparation: ordinary default route publishes sibling while borrowed source stays stale")) return false;
    const auto before = ReadFileBytes(image);
    unsigned preparations = 0, stages = 0, wal_hooks = 0, verifications = 0;
    unsigned stale_preparations = 0, stale_wal_hooks = 0;
    const auto stale_result = coordinator->Commit(101, {stale},
        [&](const auto&, const auto&, auto, auto&, auto&) { ++stale_wal_hooks; return true; },
        {}, {}, false, std::nullopt,
        [&](const Store&, auto&, auto&) { ++stale_preparations; return true; });
    if (!Require(!stale_result.committed && stale_result.error.find("CommitStageFailed") == 0 &&
            stale_preparations == 1 && stale_wal_hooks == 0 && alpha->PendingMutationCount() == 0 &&
            ReadFileBytes(image) == before,
            "preparation: returning cached CRW1 after sibling publication fails before WAL or media writes")) return false;
    const auto expected = testfixture::HexToBytes("68586c6c6f");
    alpha->SetFilePayloadRangeProvider([&](const auto&, auto owner, auto offset, std::span<std::byte> bytes) {
        if (owner.object_id != 17 || owner.generation != 22 || offset > expected.size() ||
            bytes.size() > expected.size() - offset) return false;
        std::copy_n(expected.begin() + offset, bytes.size(), bytes.begin());
        return true;
    });
    struct ResetPayloadProvider
    {
        Store* store;
        ~ResetPayloadProvider() { store->SetFilePayloadRangeProvider({}); }
    } reset_payload_provider{alpha};
    std::vector<Store::MutationRequest> evidence;
    std::future<ContainerCommitResult> competitor;
    bool ok = true;
    const auto result = coordinator->Commit(101, {},
        [&](const auto& requests, const auto& identities, auto source, auto& pins, auto&) {
            ++wal_hooks;
            CompressionRewrite proof;
            ok &= Require(requests.size() == 3 && identities.size() == 3 && source == 21 &&
                    DecodeCompressionRewrite(requests.front().inline_payload, proof) && proof.checkpoint == source &&
                    requests.front().inline_payload == evidence.front().inline_payload &&
                    identities[0].object_id == 17 && identities[1].object_id == 17 && identities[2].object_id == 17 &&
                    identities[0].generation == 22 && identities[1].generation == 22 && identities[2].generation == 22 &&
                    pins == std::vector<std::uint64_t>{20} &&
                    ReadFileBytes(image) == before,
                "preparation: WAL receives exact fresh CRW1 and three same-owner identities before publication");
            pins.push_back(source);
            return true;
        },
        [&](auto index, const auto& request, const auto&, auto&) {
            ++stages;
            ok &= Require(index < evidence.size() && request.operation == evidence[index].operation &&
                    request.inline_payload == evidence[index].inline_payload,
                "preparation: original prepared order and bytes reach staging");
            return true;
        }, {}, false, std::nullopt,
        [&](const Store& live, auto& requests, auto&) {
            ++preparations;
            Store::MutationRequest rewrite;
            if (!Require(live.CheckpointXid() == 21 && live.PendingMutationCount() == 0 &&
                    live.PrepareCompressionRewrite(L"\\compressed", rewrite),
                    "preparation: native source builder runs after reload and before mutation")) return false;
            CompressionRewrite proof;
            ok &= Require(DecodeCompressionRewrite(rewrite.inline_payload, proof) && proof.checkpoint == 21 &&
                    proof.volume == 101 && proof.object == 17 && proof.size == 5 &&
                    rewrite.inline_payload != stale.inline_payload,
                "preparation: CRW1 authenticates actual shared checkpoint, not borrowed checkpoint");
            InodeMetadataPatch times;
            times.mask = InodeMetadataPatch::ModificationTime | InodeMetadataPatch::ChangeTime;
            times.modification_time_utc = times.change_time_utc = InodeMetadataPatch::UnixEpochTicks + 123456789;
            Store::MutationRequest touch;
            touch.operation = Store::MutationOperation::SetInodeMetadata; touch.path = rewrite.path;
            touch.object_id = rewrite.object_id; touch.generation = proof.checkpoint + 1;
            if (!Require(EncodeInodeMetadataPatch(times, touch.inline_payload), "preparation: encode content times")) return false;
            touch.length = touch.inline_payload.size();
            Store::MutationRequest write;
            write.operation = Store::MutationOperation::Write; write.path = rewrite.path;
            write.object_id = rewrite.object_id; write.generation = proof.checkpoint + 1;
            // Ordinary write bytes use the existing payload provider; only
            // CRW1 and the metadata patch carry native inline request payloads.
            write.offset = 1; write.length = 1;
            requests = {rewrite, touch, write};
            evidence = requests;
            std::promise<void> entered;
            auto ready = entered.get_future();
            competitor = std::async(std::launch::async, [&, signal = std::move(entered)]() mutable {
                auto next = sibling; next.path = L"\\sibling-during";
                signal.set_value();
                return coordinator->Commit(102, {next});
            });
            ready.wait();
            ok &= Require(competitor.wait_for(std::chrono::milliseconds(30)) == std::future_status::timeout &&
                    coordinator->CheckpointXid() == 21 && ReadFileBytes(image) == before,
                "preparation: sibling publication waits for serialized preparation ownership");
            return true;
        },
        [&](const Store& live, auto xid, std::string& failure) {
            ++verifications;
            std::vector<std::byte> actual;
            Store::VolumeContext context;
            context.device_path = image.wstring(); context.volume_object_id = 101;
            context.allow_legacy_scaffold_for_fixtures = false;
            Store reopened(context);
            const bool verified = xid == 22 && live.CheckpointXid() == xid &&
                live.PendingMutationCount() == 0 &&
                live.ReadCommittedFileRange(L"\\compressed", 0, 5, actual) && actual == expected &&
                !live.LookupCommittedExtendedAttribute(17, "com.apple.decmpfs") &&
                reopened.PrepareNativeWritePath() && reopened.CheckpointXid() == xid &&
                reopened.ReadCommittedFileRange(L"\\compressed", 0, 5, actual) && actual == expected &&
                !reopened.LookupCommittedExtendedAttribute(17, "com.apple.decmpfs");
            ok &= Require(verified, "postpublication: live and independently reopened native compressed rewrite agree");
            ok &= Require(competitor.valid() &&
                    competitor.wait_for(std::chrono::milliseconds(30)) == std::future_status::timeout,
                "postpublication: queued sibling still cannot publish while verifying immediate image");
            if (!verified) failure = "compressed-image-verification-failed";
            return verified;
        });
    if (competitor.valid())
        ok &= Require(competitor.get().committed, "preparation: queued sibling publishes after selected transaction");
    ok &= Require(result.committed && result.committed_xid == 22 && preparations == 1 && stages == 3 && wal_hooks == 1 && verifications == 1 &&
            coordinator->CheckpointXid() == 23 && ReadFileBytes(image) != before,
        "preparation: one builder and one canonical successor, followed by sibling successor");
    Store::VolumeContext context;
    context.device_path = image.wstring(); context.volume_object_id = 101;
    context.allow_legacy_scaffold_for_fixtures = false;
    Store reopened(context);
    std::vector<std::byte> actual;
    ok &= Require(reopened.PrepareNativeWritePath() && reopened.CheckpointXid() == 23 &&
            reopened.ReadCommittedFileRange(L"\\compressed", 0, 5, actual) && actual == expected &&
            !reopened.LookupCommittedExtendedAttribute(17, "com.apple.decmpfs") &&
            reopened.ValidateRequiredRecoveryCheckpoints({20, 21}, error),
        "preparation: independently reopened image contains edited bytes and retained source checkpoints");
    const auto inode = reopened.LookupCommittedInodeByPath(L"\\compressed");
    ok &= Require(inode && inode->modification_time_utc == InodeMetadataPatch::UnixEpochTicks + 123456789 &&
            inode->change_time_utc == InodeMetadataPatch::UnixEpochTicks + 123456789,
        "preparation: independently reopened image contains the same-owner content times");
    return ok;
}

bool TestPostpublicationVerificationOwnsSiblingPublication()
{
    using namespace apfsaccess::catalog;
    using Store = apfsaccess::rw::MetadataStore;
    bool ok = true;
    for (const std::string mode : {"success", "refuse", "throw", "success-with-error"})
    {
        const auto image = MakeRunDir(("postpublication-" + mode).c_str()) / "two.raw";
        if (!Require(WriteAuthoritativeTwoVolumeImage(image, 0, 32, 32), "postpublication: build native fixture")) return false;
        std::string error;
        auto coordinator = ContainerMountCoordinator::Open(image.string(), 0, error,
            CatalogLoadPolicy::StrictApple, false, true);
        if (!Require(coordinator && coordinator->InitializeRequiredCheckpointCensus(
                {{101, {20}}, {102, {20}}}, error), "postpublication: initialize both source pins")) return false;
        ContainerVolumeSession session;
        session.container_uuid_hex = coordinator->ContainerUuidHex();
        session.requested_write = true; session.use_canonical_transaction = true;
        for (const auto oid : {101u, 102u})
        {
            session.volume_object_id = oid;
            if (!Require(coordinator->MountVolume(session, error), "postpublication: mount sibling sessions")) return false;
        }
        auto* selected_store = coordinator->FindSessionStore(101);
        auto* sibling_store = coordinator->FindSessionStore(102);
        std::atomic<unsigned> publications{0}, sibling_publications{0};
        selected_store->SetCommitStageHook([&](std::string_view stage) {
            if (stage == "before-apple-publish") ++publications;
            return true;
        });
        sibling_store->SetCommitStageHook([&](std::string_view stage) {
            if (stage == "before-apple-publish") ++sibling_publications;
            return true;
        });
        struct ResetStageHooks
        {
            Store* selected;
            Store* sibling;
            ~ResetStageHooks() { selected->SetCommitStageHook({}); sibling->SetCommitStageHook({}); }
        } reset_hooks{selected_store, sibling_store};
        Store::MutationRequest selected;
        selected.operation = Store::MutationOperation::CreateDirectory; selected.path = L"\\verified";
        auto sibling = selected; sibling.path = L"\\queued-sibling";
        const auto before = ReadFileBytes(image);
        const auto diagnostics_before = coordinator->DiagnosticsSnapshot(101);
        std::promise<void> verifier_entered, release_verifier, sibling_entered, sibling_done;
        auto verifier_ready = verifier_entered.get_future();
        auto release = release_verifier.get_future();
        auto sibling_ready = sibling_entered.get_future();
        auto sibling_finished = sibling_done.get_future();
        ContainerCommitResult result, sibling_result;
        std::exception_ptr publisher_exception, sibling_exception;
        unsigned verifications = 0, acceptances = 0;
        Store::PayloadIdentity accepted_identity{};
        bool verified_image = false, release_received = false, accepted_census = false;
        std::thread publisher, competitor;
        // Release precedes joining on every exit, including assertion failures
        // and exceptions. The callback itself also has a bounded wait.
        struct ReleaseAndJoin
        {
            std::promise<void>& release;
            std::thread& publisher;
            std::thread& competitor;
            bool released = false;
            void Release() { if (!released) { release.set_value(); released = true; } }
            void Join()
            {
                Release();
                if (publisher.joinable()) publisher.join();
                if (competitor.joinable()) competitor.join();
            }
            ~ReleaseAndJoin() { Join(); }
        } threads{release_verifier, publisher, competitor};
        publisher = std::thread([&] {
            try
            {
                result = coordinator->Commit(101, {selected},
                    [&](const auto& requests, const auto& identities, auto source, auto& pins, auto&) {
                        ++acceptances;
                        accepted_census = source == 20 && pins == std::vector<std::uint64_t>{20} &&
                            requests.size() == 1 && requests.front().operation == selected.operation &&
                            requests.front().path == selected.path && identities.size() == 1 &&
                            identities.front().object_id != 0 && identities.front().generation == 21;
                        if (!accepted_census) return false;
                        accepted_identity = identities.front();
                        // The hook returns a census, not an append-only WAL
                        // record list. Source 20 is already retained.
                        pins = {source};
                        return true;
                    }, {}, {}, false, std::nullopt, {},
                    [&](const Store& live, auto xid, std::string& failure) {
                        ++verifications;
                        Store::VolumeContext context;
                        context.device_path = image.wstring(); context.volume_object_id = 101;
                        context.allow_legacy_scaffold_for_fixtures = false;
                        Store reopened(context);
                        std::string retained_error;
                        const auto live_inode = live.LookupCommittedInodeByPath(selected.path);
                        const bool reopened_ready = reopened.PrepareNativeWritePath();
                        const auto reopened_inode = reopened.LookupCommittedInodeByPath(selected.path);
                        verified_image = &live == selected_store && xid == 21 &&
                            live.CheckpointXid() == xid && live.LastCommittedXid() == xid &&
                            live.PendingMutationCount() == 0 &&
                            live_inode && live_inode->object_id == accepted_identity.object_id &&
                            live_inode->xid == accepted_identity.generation &&
                            reopened_ready && reopened.CheckpointXid() == xid &&
                            reopened_inode && reopened_inode->object_id == accepted_identity.object_id &&
                            reopened_inode->xid == accepted_identity.generation &&
                            reopened.ValidateRequiredRecoveryCheckpoints({20}, retained_error);
                        verifier_entered.set_value();
                        release_received = release.wait_for(std::chrono::seconds(10)) == std::future_status::ready;
                        if (mode == "throw") throw 240;
                        if (mode == "success-with-error") failure = "ambiguous-verification";
                        return verified_image && release_received && mode != "refuse";
                    });
            }
            catch (...) { publisher_exception = std::current_exception(); }
        });
        const bool entered = verifier_ready.wait_for(std::chrono::seconds(3)) == std::future_status::ready;
        ok &= Require(entered, "postpublication: verifier reaches bounded rendezvous");
        std::vector<std::byte> published;
        if (entered)
        {
            published = ReadFileBytes(image);
            competitor = std::thread([&] {
                sibling_entered.set_value();
                try { sibling_result = coordinator->Commit(102, {sibling}); }
                catch (...) { sibling_exception = std::current_exception(); }
                sibling_done.set_value();
            });
            ok &= Require(sibling_ready.wait_for(std::chrono::seconds(3)) == std::future_status::ready &&
                    sibling_finished.wait_for(std::chrono::milliseconds(30)) == std::future_status::timeout &&
                    sibling_publications.load() == 0 && coordinator->CheckpointXid() == 21 &&
                    published != before && ReadFileBytes(image) == published,
                "postpublication: rendezvoused sibling cannot publish until verifier releases ownership");
        }
        threads.Join();
        const bool success = mode == "success";
        if (!entered || !result.error.empty())
            std::fprintf(stderr, "[INFO] postpublication %s: committed=%d status=%d stage=%s error=%s\n",
                mode.c_str(), result.committed ? 1 : 0, result.commit_status_code,
                result.commit_stage.c_str(), result.error.c_str());
        ok &= Require(!publisher_exception && !sibling_exception && verified_image && release_received &&
                accepted_census && acceptances == 1 && verifications == 1 && publications.load() == 1 &&
                result.committed && result.committed_xid == 21 && result.checkpoint_xid == 21 &&
                result.staged_identities.size() == 1 &&
                result.staged_identities.front().object_id == accepted_identity.object_id &&
                result.staged_identities.front().generation == accepted_identity.generation &&
                selected_store->PendingMutationCount() == 0 &&
                selected_store->LookupCommittedInodeByPath(selected.path).has_value(),
            "postpublication: verifier sees actual committed store once and preserves published identity");
        const auto census = coordinator->CheckpointCensusSnapshot();
        ok &= Require(census.size() == 2 && census[0].volume_object_id == 101 &&
                census[0].required_checkpoint_xids == std::vector<std::uint64_t>{20} &&
                census[0].unapplied_accepted_work == !success && census[1].volume_object_id == 102 &&
                census[1].required_checkpoint_xids == std::vector<std::uint64_t>{20} &&
                !census[1].unapplied_accepted_work,
            "postpublication: exact accepted census survives failure; success resolves work while retaining both pins");
        const auto diagnostics_after = coordinator->DiagnosticsSnapshot(101);
        ok &= Require(diagnostics_after.rollback_reload_attempts == diagnostics_before.rollback_reload_attempts &&
                diagnostics_after.precommit_reload_attempts == diagnostics_before.precommit_reload_attempts + 1,
            "postpublication: neither verification outcome reloads a rollback or retries the commit");
        if (success)
        {
            ok &= Require(result.error.empty() && !result.commit_recovery_required &&
                    result.commit_status_code == static_cast<int>(Store::CommitStatus::Committed) &&
                    sibling_result.committed && sibling_publications.load() == 1 && coordinator->CheckpointXid() == 22 &&
                    !coordinator->IsRecoveryRequired(),
                "postpublication: successful verification releases the next sibling publication");
        }
        else
        {
            ok &= Require(result.commit_stage == "postpublication-verifier" &&
                    result.commit_status_code == static_cast<int>(Store::CommitStatus::InvariantFailed) &&
                    result.commit_recovery_required && !result.commit_recovery_reason.empty() &&
                    result.error.find("CommitPostpublicationVerificationFailed") == 0 &&
                    coordinator->IsRecoveryRequired() && coordinator->RecoveryVolumeObjectId() == 101 &&
                    coordinator->CheckpointXid() == 21 && selected_store->CheckpointXid() == 21 &&
                    !sibling_result.committed && sibling_result.commit_recovery_required &&
                    sibling_result.error.find("ContainerRecoveryRequired") == 0 && sibling_publications.load() == 0 &&
                    ReadFileBytes(image) == published &&
                    diagnostics_after.commit_failures == diagnostics_before.commit_failures + 1 &&
                    diagnostics_after.last_failure_stage == "postpublication-verifier",
                "postpublication: false/throw/ambiguous success preserves publication and fences queued sibling");
            const auto retry = coordinator->Commit(101, {selected}, {}, {}, {}, true);
            ok &= Require(!retry.committed && retry.commit_recovery_required && publications.load() == 1 &&
                    ReadFileBytes(image) == published,
                "postpublication: even accepted replay cannot retry publication after failed verification");
        }
        Store::VolumeContext context;
        context.device_path = image.wstring(); context.volume_object_id = 101;
        context.allow_legacy_scaffold_for_fixtures = false;
        Store reopened(context);
        ok &= Require(reopened.PrepareNativeWritePath() && reopened.CheckpointXid() == (success ? 22u : 21u) &&
                reopened.LookupCommittedInodeByPath(selected.path).has_value() &&
                reopened.ValidateRequiredRecoveryCheckpoints({20}, error),
            "postpublication: independent reopen retains actual successor and accepted source checkpoint");
    }
    return ok;
}

bool TestPostpublicationVerifierSkipsUnpublishedOperations()
{
    using namespace apfsaccess::catalog;
    using Store = apfsaccess::rw::MetadataStore;
    bool ok = true;
    for (const std::string mode : {"preparation", "staging", "acceptance", "plan", "noop", "read-only"})
    {
        const auto image = MakeRunDir(("postpublication-skip-" + mode).c_str()) / "two.raw";
        if (!Require(WriteAuthoritativeTwoVolumeImage(image), "postpublication skip: native fixture")) return false;
        std::string error;
        auto coordinator = ContainerMountCoordinator::Open(image.string(), 0, error,
            CatalogLoadPolicy::StrictApple, false, true);
        if (!Require(coordinator && coordinator->InitializeRequiredCheckpointCensus(
                {{101, {20}}, {102, {20}}}, error), "postpublication skip: source census")) return false;
        ContainerVolumeSession session;
        session.volume_object_id = 101; session.container_uuid_hex = coordinator->ContainerUuidHex();
        session.requested_write = mode != "read-only"; session.use_canonical_transaction = true;
        if (!Require(coordinator->MountVolume(session, error), "postpublication skip: mount")) return false;
        auto* store = coordinator->FindSessionStore(101);
        unsigned plans = 0, publications = 0, preparations = 0, stages = 0, acceptances = 0;
        store->SetCommitStageHook([&](std::string_view stage) {
            if (stage == "before-apple-plan") ++plans;
            if (stage == "before-apple-publish") ++publications;
            return mode != "plan" || stage != "before-apple-plan";
        });
        struct ResetStageHook
        {
            Store* store;
            ~ResetStageHook() { store->SetCommitStageHook({}); }
        } reset_hook{store};
        Store::MutationRequest request;
        request.operation = Store::MutationOperation::CreateDirectory; request.path = L"\\unpublished";
        unsigned verifications = 0;
        const auto before = ReadFileBytes(image);
        ContainerMutationPreparationHook preparation;
        if (mode == "preparation") preparation = [&](const Store&, auto&, auto&) {
            ++preparations;
            return false;
        };
        const auto result = coordinator->Commit(101,
            mode == "noop" ? std::vector<Store::MutationRequest>{} : std::vector<Store::MutationRequest>{request},
            [&](const auto&, const auto&, auto source, auto& pins, auto&) {
                ++acceptances;
                ok &= Require(source == 20 && pins == std::vector<std::uint64_t>{20},
                    "postpublication skip: acceptance receives exact source census");
                // A rescan reports each required generation once, including
                // for a no-op. Duplicates must still fail closed in production.
                pins = {source};
                return mode != "acceptance";
            },
            [&](auto, const auto&, const auto&, auto&) { ++stages; return mode != "staging"; },
            {}, false, std::nullopt, preparation,
            [&](const Store&, auto, auto&) { ++verifications; return false; });
        const bool noop = mode == "noop";
        const bool reached_staging = mode == "staging" || mode == "acceptance" || mode == "plan";
        const bool reached_acceptance = mode == "acceptance" || mode == "plan" || noop;
        const auto expected_status = noop ? Store::CommitStatus::NothingToCommit :
            mode == "read-only" ? Store::CommitStatus::NotWritable : Store::CommitStatus::InvariantFailed;
        const std::string expected_stage = mode == "preparation" ? "mutation-preparation-hook" :
            mode == "staging" ? "mutation-staging-hook" :
            mode == "acceptance" ? "before-checkpoint-publication" :
            mode == "plan" ? "apple-plan-stage-blocked" : noop ? "nothing-to-commit" : "";
        const bool expected_boundary = preparations == (mode == "preparation" ? 1u : 0u) &&
            stages == (reached_staging ? 1u : 0u) && acceptances == (reached_acceptance ? 1u : 0u) &&
            plans == (mode == "plan" ? 1u : 0u) && publications == 0 &&
            result.commit_status_code == static_cast<int>(expected_status) && result.commit_stage == expected_stage &&
            !result.commit_recovery_required && !coordinator->IsRecoveryRequired();
        if (!expected_boundary || result.committed != noop)
            std::fprintf(stderr, "[INFO] postpublication skip %s: committed=%d status=%d stage=%s error=%s\n",
                mode.c_str(), result.committed ? 1 : 0, result.commit_status_code,
                result.commit_stage.c_str(), result.error.c_str());
        ok &= Require(expected_boundary,
            "postpublication skip: each case reaches its intended rejection or no-op boundary");
        const auto census = coordinator->CheckpointCensusSnapshot();
        ok &= Require(census.size() == 2 && census[0].volume_object_id == 101 &&
                census[0].required_checkpoint_xids == std::vector<std::uint64_t>{20} &&
                census[0].unapplied_accepted_work == (mode == "acceptance" || mode == "plan") &&
                census[1].volume_object_id == 102 &&
                census[1].required_checkpoint_xids == std::vector<std::uint64_t>{20} &&
                !census[1].unapplied_accepted_work,
            "postpublication skip: only acceptance and later failures retain unresolved WAL work");
        ok &= Require(verifications == 0 && coordinator->CheckpointXid() == 20 && ReadFileBytes(image) == before &&
                !store->LookupCommittedInodeByPath(request.path).has_value() &&
                result.committed == noop && (!noop || (result.error.empty() &&
                    result.checkpoint_xid == 20 && result.committed_xid == 20)),
            "postpublication skip: failure, no-op and read-only calls never invoke verifier or publish");
    }
    return ok;
}

bool TestCompressionPreparationFailuresPreserveSource()
{
    using namespace apfsaccess::rw;
    using namespace apfsaccess::catalog;
    using Store = MetadataStore;
    bool ok = true;
    for (const std::string mode : {"refuse", "throw", "error", "stage", "allocate", "checkpoint", "identity",
            "empty", "oversized", "payload", "path"})
    {
        const auto image = MakeRunDir(("compression-preparation-" + mode).c_str()) / "two.raw";
        if (!Require(WriteCompressionPreparationImage(image), "preparation failure: canonical image")) return false;
        std::string error;
        auto coordinator = ContainerMountCoordinator::Open(image.string(), 0, error,
            CatalogLoadPolicy::StrictApple, false, true);
        if (!Require(coordinator && coordinator->InitializeRequiredCheckpointCensus({{101, {20}}, {102, {20}}}, error),
                "preparation failure: retain both volumes' source pins")) return false;
        ContainerVolumeSession session;
        session.volume_object_id = 101; session.container_uuid_hex = coordinator->ContainerUuidHex();
        session.requested_write = true; session.use_canonical_transaction = true;
        if (!Require(coordinator->MountVolume(session, error), "preparation failure: mount")) return false;
        auto* store = coordinator->FindSessionStore(101);
        Store::MutationRequest source;
        if (!Require(store->PrepareCompressionRewrite(L"\\compressed", source), "preparation failure: native source evidence")) return false;
        const std::vector<Store::MutationRequest> input{source};
        const auto before = ReadFileBytes(image);
        unsigned preparations = 0, wal_hooks = 0, stages = 0, publications = 0;
        store->SetCommitStageHook([&](std::string_view stage) {
            if (stage == "before-apple-publish") ++publications;
            return true;
        });
        const auto result = coordinator->Commit(101, input,
            [&](const auto&, const auto&, auto, auto&, auto&) { ++wal_hooks; return true; },
            [&](auto, const auto&, const auto&, auto&) { ++stages; return true; },
            {}, false, std::nullopt,
            [&](const Store& live, auto& requests, std::string& failure) {
                ++preparations;
                if (mode == "refuse") { failure = "source-refused"; return false; }
                if (mode == "throw") throw 1;
                if (mode == "error") failure = "ambiguous-success";
                // Deliberately violate the const-builder contract through an
                // existing borrowed alias, to exercise defensive rejection.
                if (mode == "stage")
                {
                    Store::MutationRequest illegal;
                    illegal.operation = Store::MutationOperation::CreateDirectory; illegal.path = L"\\illegal";
                    ok &= Require(store->StageMutation(illegal) == Store::MutationStatus::Applied,
                        "preparation failure: actually mutate working native namespace");
                }
                if (mode == "allocate")
                    ok &= Require(store->AllocateExtent(4096).has_value(), "preparation failure: actually allocate scratch extent");
                if (mode == "checkpoint")
                    const_cast<AppleCheckpointView*>(live.AuthoritativeAppleCheckpointView())->container.superblock_bytes[0] ^= std::byte{1};
                if (mode == "identity")
                    const_cast<Store::VolumeContext&>(live.Context()).volume_object_id = 102;
                if (mode == "empty") requests.clear();
                if (mode == "oversized") requests.resize(ContainerPreparedMutationLimit + 1, source);
                if (mode == "payload") requests.front().inline_payload.resize(ContainerPreparedInlineByteLimit + 1);
                if (mode == "path") requests.front().path.resize(ContainerPreparedPathCharLimit + 1, L'x');
                return true;
            });
        ok &= Require(!result.committed && result.commit_stage == "mutation-preparation-hook" && preparations == 1 &&
                wal_hooks == 0 && stages == 0 && publications == 0 && result.staged_identities.empty() &&
                coordinator->CheckpointXid() == 20 && ReadFileBytes(image) == before &&
                input.front().inline_payload == source.inline_payload,
            "preparation failure: no staging/WAL/publication, caller evidence and exact image survive");
        if (mode == "identity")
        {
            ok &= Require(result.commit_recovery_required && coordinator->IsRecoveryRequired(),
                "preparation failure: changed routing identity stays closed without reloading another volume");
            continue;
        }
        Store::MutationRequest restored;
        ok &= Require(store->PendingMutationCount() == 0 && store->PendingAllocationCount() == 0 &&
                store->PrepareCompressionRewrite(source.path, restored) && restored.inline_payload == source.inline_payload &&
                store->ValidateRequiredRecoveryCheckpoints({20}, error),
            "preparation failure: rollback restores exact native compressed source and retained history");
        // A subsequent preparation failure may not consume existing pins. The
        // prepublication census must still contain the original source pin.
        Store::MutationRequest ordinary;
        ordinary.operation = Store::MutationOperation::CreateDirectory; ordinary.path = L"\\ordinary";
        const auto ordinary_result = coordinator->Commit(101, {ordinary},
            [&](const auto&, const auto&, auto, auto& pins, auto&) {
                ok &= Require(pins == std::vector<std::uint64_t>{20}, "preparation failure: existing census unchanged");
                return true;
            });
        ok &= Require(ordinary_result.committed && store->LookupCommittedInodeByPath(ordinary.path).has_value(),
            "preparation failure: default route still publishes after clean rollback");
    }
    return ok;
}

bool TestPreparationRespectsAdmissionAndDrain()
{
    using namespace apfsaccess::catalog;
    using Store = apfsaccess::rw::MetadataStore;
    const auto image = MakeRunDir("preparation-admission") / "two.raw";
    if (!Require(WriteCompressionPreparationImage(image), "preparation admission: canonical image")) return false;
    std::string error;
    auto coordinator = ContainerMountCoordinator::Open(image.string(), 0, error,
        CatalogLoadPolicy::StrictApple, false, true);
    if (!Require(coordinator != nullptr, "preparation admission: open")) return false;
    ContainerVolumeSession session;
    session.volume_object_id = 101; session.container_uuid_hex = coordinator->ContainerUuidHex();
    session.requested_write = true; session.use_canonical_transaction = true;
    if (!Require(coordinator->MountVolume(session, error), "preparation admission: mount")) return false;
    const auto before = ReadFileBytes(image);
    unsigned preparations = 0;
    Store::MutationRequest request;
    request.operation = Store::MutationOperation::CreateDirectory; request.path = L"\\admitted";
    const ContainerMutationPreparationHook builder = [&](const Store&, auto& requests, auto&) {
        ++preparations;
        requests = {request};
        return true;
    };
    const auto census_rejected = coordinator->Commit(101, {}, {}, {}, {}, false, std::nullopt, builder);
    bool ok = Require(!census_rejected.committed && census_rejected.error == "RequiredCheckpointCensusIncomplete" &&
            preparations == 0 && ReadFileBytes(image) == before,
        "preparation admission: census rejection precedes builder");
    if (!Require(coordinator->InitializeRequiredCheckpointCensus({{101, {20}, true}, {102, {20}, true}}, error),
            "preparation admission: unresolved accepted sources")) return false;
    const auto pending_rejected = coordinator->Commit(101, {}, {}, {}, {}, false, std::nullopt, builder);
    const auto preimage_rejected = coordinator->Commit(101, {}, {}, {}, {}, true, 19, builder);
    ok &= Require(!pending_rejected.committed && pending_rejected.commit_stage == "awaiting-accepted-recovery" &&
            !preimage_rejected.committed && preimage_rejected.error == "AcceptedReplayPreimageAdvanced" &&
            preparations == 0 && ReadFileBytes(image) == before,
        "preparation admission: unresolved work and stale replay preimage reject without invoking builder");
    if (!Require(coordinator->UpdateRequiredCheckpointXids(101, {20}, error) &&
            coordinator->UpdateRequiredCheckpointXids(102, {20}, error), "preparation admission: resolve accepted work")) return false;
    const auto admitted = coordinator->Commit(101, {}, {}, {}, {}, false, std::nullopt,
        [&](const Store& live, auto& requests, auto&) {
            ++preparations;
            // Drain sets its admission flag while this already-admitted Commit
            // holds ownership. It may time out, but cannot destroy the source.
            auto drain = std::async(std::launch::async, [&] {
                return coordinator->DrainAndStop(std::chrono::milliseconds(1));
            });
            const auto stopped = drain.get();
            ok &= Require(!stopped.clean && stopped.error == "ContainerDrainTimeout" &&
                    live.CheckpointXid() == 20 && ReadFileBytes(image) == before,
                "preparation admission: active preparation retains source and ownership during drain");
            requests = {request};
            return true;
        });
    const auto published = ReadFileBytes(image);
    const auto draining_rejected = coordinator->Commit(101, {}, {}, {}, {}, false, std::nullopt, builder);
    ok &= Require(admitted.committed && coordinator->CheckpointXid() == 21 && published != before &&
            coordinator->FindSessionStore(101)->LookupCommittedInodeByPath(request.path).has_value() &&
            !draining_rejected.committed && draining_rejected.error == "ContainerDraining" &&
            preparations == 1 && ReadFileBytes(image) == published &&
            coordinator->DrainAndStop(std::chrono::milliseconds(100)).clean,
        "preparation admission: admitted commit completes, subsequent builder is rejected, final drain succeeds");
    return ok;
}

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
        [&](const auto& requests,
            const auto& identities,
            std::uint64_t,
            std::vector<std::uint64_t>&,
            std::string& hook_error)
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
    if (!retry.committed || !store) return false;
    const auto original = store->LookupCommittedInodeByPath(create.path);
    if (!Require(original.has_value(), "unlink hook: committed source exists")) return false;
    const auto image_before_delete = ReadFileBytes(image);
    apfsaccess::rw::MetadataStore::MutationRequest remove;
    remove.operation = apfsaccess::rw::MetadataStore::MutationOperation::Delete;
    remove.path = create.path;
    std::optional<apfsaccess::rw::UnlinkOutcome> seen;
    const auto rejected_delete = coordinator->Commit(101, {remove},
        [&](const auto& requests,
            const auto& identities,
            std::uint64_t,
            std::vector<std::uint64_t>&,
            std::string& hook_error)
        {
            if (requests.size() == 1 && identities.size() == 1 &&
                identities[0].object_id == original->object_id && identities[0].generation == original->xid)
                seen = requests[0].expected_unlink_outcome;
            hook_error = "InjectedUnlinkWalRefusal";
            return false;
        });
    ok &= Require(!rejected_delete.committed && seen && seen->object_id == original->object_id &&
            seen->generation_before == original->xid && seen->parent_object_id == original->parent_object_id &&
            seen->links_before == 1 && seen->links_after == 0 && seen->path_utf8 == "\\retry-after-hook.bin" &&
            ReadFileBytes(image) == image_before_delete && store->PendingMutationCount() == 0 &&
            store->LookupCommittedInodeByPath(create.path),
        "unlink hook: exact outcome supplied before publication, rejection preserves media and namespace");
    bool retry_outcome_matches = false;
    const auto delete_retry = coordinator->Commit(101, {remove},
        [&](const auto& requests,
            const auto&,
            std::uint64_t,
            std::vector<std::uint64_t>&,
            std::string&)
        {
            retry_outcome_matches = requests.size() == 1 && seen && requests[0].expected_unlink_outcome == seen;
            return retry_outcome_matches;
        });
    ok &= Require(delete_retry.committed && retry_outcome_matches &&
            !store->LookupCommittedInodeByPath(create.path) &&
            !store->LookupCommittedInodeByObjectId(original->object_id),
        "unlink hook: a clean retry publishes the same selected-volume outcome");
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

#include "ContainerMountCoordinatorSharedSpaceTests.h"

int main(int argc, char** argv)
{
    bool ok = true;
    const bool diagnostics_only = argc == 2 && std::string(argv[1]) == "--test-coordinator-diagnostics";
    const bool reload_boundaries_only = argc == 2 && std::string(argv[1]) == "--test-coordinator-reload-boundaries";
    const bool shared_space_only = argc == 2 && std::string(argv[1]) == "--test-coordinator-shared-space";
    if (argc != 1 && !diagnostics_only && !reload_boundaries_only && !shared_space_only)
    {
        std::fprintf(stderr, "unknown coordinator test selector\n");
        return 2;
    }
    if (argc == 1 || shared_space_only)
    {
        ok &= shared_space_tests::TestIdentitiesAndLegacy();
        ok &= shared_space_tests::TestSiblingPublicationAndStaleRefresh();
        ok &= shared_space_tests::TestHeldCommitLookup(false);
        ok &= shared_space_tests::TestHeldCommitLookup(true);
        ok &= shared_space_tests::TestFailedPublicationCannotRestoreStaleSession(0);
        ok &= shared_space_tests::TestFailedPublicationCannotRestoreStaleSession(1);
        ok &= shared_space_tests::TestFailedPublicationCannotRestoreStaleSession(2);
        ok &= shared_space_tests::TestSnapshotAllocationFailurePreservesDurableResult();
    }
    if (argc == 1 || diagnostics_only || reload_boundaries_only)
    {
        ok &= TestCoordinatorDiagnosticsCountsAndReloads();
        ok &= TestCoordinatorDiagnosticsFailureAndBorrowedStore();
    }
    if (reload_boundaries_only)
    {
        ok &= TestPostpublicationVerificationOwnsSiblingPublication();
        ok &= TestPostpublicationVerifierSkipsUnpublishedOperations();
        ok &= TestCompressionPreparationUsesSerializedFreshPreimage();
        ok &= TestCompressionPreparationFailuresPreserveSource();
        ok &= TestPreparationRespectsAdmissionAndDrain();
        ok &= TestAcceptedSiblingRecoveryAdmissionPreservesPins();
        ok &= TestVolumeReplayBoundaryFollowsOnlyUnchangedSiblings();
        ok &= TestCoordinatorRollsBackPartiallyStagedBatch();
        ok &= TestCoordinatorMutationStagingHookRejectsWithoutMediaChange();
        ok &= TestCoordinatorIsolatesPreWriteFailureAcrossVolumes();
        ok &= TestRetentionCleanupRetryOwnsOnePublication();
    }
    if (argc == 1)
    {
        ok &= TestPostpublicationVerificationOwnsSiblingPublication();
        ok &= TestPostpublicationVerifierSkipsUnpublishedOperations();
        ok &= TestCompressionPreparationUsesSerializedFreshPreimage();
        ok &= TestCompressionPreparationFailuresPreserveSource();
        ok &= TestPreparationRespectsAdmissionAndDrain();
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
        ok &= TestCoordinatorMutationStagingHookRejectsWithoutMediaChange();
        ok &= TestRequiredCheckpointCensusFailsClosedAtomically();
        ok &= TestRequiredCheckpointHookUsesReloadedSiblingPreimage();
        ok &= TestAcceptedSiblingRecoveryAdmissionPreservesPins();
        ok &= TestVolumeReplayBoundaryFollowsOnlyUnchangedSiblings();
        ok &= TestRequiredCheckpointPinsSurviveUnmountAndRetryLifecycle();
        ok &= TestRetentionCleanupRetryOwnsOnePublication();
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
    }
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
        std::printf("container-coordinator: %s green\n", argc == 1 ? "all" : argv[1]);
        return 0;
    }
    std::fprintf(
        stderr, "container-coordinator: %d failure(s)\n", g_failures);
    return 1;
}
