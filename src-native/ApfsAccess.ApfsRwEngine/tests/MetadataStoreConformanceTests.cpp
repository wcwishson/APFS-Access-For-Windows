#include "MetadataStore.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>
#include <windows.h>

namespace
{
constexpr std::size_t kContainerBytes = 4 * 1024 * 1024;
constexpr std::uint32_t kBlockSize = 4096;
constexpr std::uint64_t kTotalBlocks = 1024;
constexpr std::uint64_t kInitialCheckpointXid = 7;
constexpr std::uint64_t kSpacemanObjectId = 0x2A;
constexpr std::uint64_t kVolumeRootObject = 0x54;
constexpr std::uint32_t kNxsbMagic = 0x4253584E; // NXSB

void WriteLe32(std::vector<std::byte>& buffer, std::size_t offset, std::uint32_t value)
{
    if (offset + 4 > buffer.size())
    {
        return;
    }

    buffer[offset + 0] = static_cast<std::byte>(value & 0xffu);
    buffer[offset + 1] = static_cast<std::byte>((value >> 8) & 0xffu);
    buffer[offset + 2] = static_cast<std::byte>((value >> 16) & 0xffu);
    buffer[offset + 3] = static_cast<std::byte>((value >> 24) & 0xffu);
}

void WriteLe64(std::vector<std::byte>& buffer, std::size_t offset, std::uint64_t value)
{
    if (offset + 8 > buffer.size())
    {
        return;
    }

    for (int i = 0; i < 8; ++i)
    {
        buffer[offset + static_cast<std::size_t>(i)] = static_cast<std::byte>((value >> (i * 8)) & 0xffu);
    }
}

bool CreateSyntheticContainer(const std::filesystem::path& image_path)
{
    std::vector<std::byte> bytes(kContainerBytes, std::byte{0});
    const auto write_superblock = [&](std::size_t base_offset, std::uint64_t checkpoint_xid)
    {
        WriteLe64(bytes, base_offset + 0x10, checkpoint_xid);
        WriteLe32(bytes, base_offset + 0x20, kNxsbMagic);
        WriteLe32(bytes, base_offset + 0x24, kBlockSize);
        WriteLe64(bytes, base_offset + 0x28, kTotalBlocks);
        WriteLe64(bytes, base_offset + 0x98, kSpacemanObjectId);
        WriteLe64(bytes, base_offset + 0xA0, kVolumeRootObject);
    };

    write_superblock(0, kInitialCheckpointXid);
    write_superblock(static_cast<std::size_t>(kBlockSize), kInitialCheckpointXid);

    std::ofstream out(image_path, std::ios::binary | std::ios::trunc);
    if (!out.good())
    {
        return false;
    }

    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    return out.good();
}

bool ReadBytesFromImage(
    const std::filesystem::path& image_path,
    std::uint64_t offset_bytes,
    std::size_t size_bytes,
    std::vector<std::byte>& out)
{
    out.assign(size_bytes, std::byte{0});
    if (size_bytes == 0)
    {
        return true;
    }

    std::ifstream input(image_path, std::ios::binary);
    if (!input.good())
    {
        out.clear();
        return false;
    }

    input.seekg(static_cast<std::streamoff>(offset_bytes), std::ios::beg);
    if (!input.good())
    {
        out.clear();
        return false;
    }

    input.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(size_bytes));
    if (static_cast<std::size_t>(input.gcount()) != size_bytes)
    {
        out.clear();
        return false;
    }

    return true;
}

bool WriteBytesToImage(
    const std::filesystem::path& image_path,
    std::uint64_t offset_bytes,
    const std::vector<std::byte>& bytes)
{
    if (bytes.empty())
    {
        return true;
    }

    std::fstream io(image_path, std::ios::binary | std::ios::in | std::ios::out);
    if (!io.good())
    {
        return false;
    }

    io.seekp(static_cast<std::streamoff>(offset_bytes), std::ios::beg);
    if (!io.good())
    {
        return false;
    }

    io.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    return io.good();
}

std::vector<std::byte> BuildPatternPayload(std::size_t bytes, unsigned char seed)
{
    std::vector<std::byte> payload(bytes, std::byte{0});
    for (std::size_t i = 0; i < payload.size(); ++i)
    {
        payload[i] = static_cast<std::byte>((seed + static_cast<unsigned char>(i & 0xffu)) & 0xffu);
    }
    return payload;
}

bool Require(bool condition, const std::string& message)
{
    if (!condition)
    {
        std::cerr << "[FAIL] " << message << std::endl;
        return false;
    }
    return true;
}

const char* MutationStatusToString(apfsaccess::rw::MetadataStore::MutationStatus status)
{
    using MutationStatus = apfsaccess::rw::MetadataStore::MutationStatus;
    switch (status)
    {
    case MutationStatus::Applied:
        return "Applied";
    case MutationStatus::NotReady:
        return "NotReady";
    case MutationStatus::InvalidRequest:
        return "InvalidRequest";
    case MutationStatus::AllocationFailed:
        return "AllocationFailed";
    case MutationStatus::UnsupportedOperation:
        return "UnsupportedOperation";
    default:
        return "Unknown";
    }
}

const char* CommitStatusToString(apfsaccess::rw::MetadataStore::CommitStatus status)
{
    using CommitStatus = apfsaccess::rw::MetadataStore::CommitStatus;
    switch (status)
    {
    case CommitStatus::Committed:
        return "Committed";
    case CommitStatus::NothingToCommit:
        return "NothingToCommit";
    case CommitStatus::NotReady:
        return "NotReady";
    case CommitStatus::NotWritable:
        return "NotWritable";
    case CommitStatus::AllocationFailed:
        return "AllocationFailed";
    case CommitStatus::InvariantFailed:
        return "InvariantFailed";
    case CommitStatus::PersistFailed:
        return "PersistFailed";
    case CommitStatus::FlushFailed:
        return "FlushFailed";
    default:
        return "Unknown";
    }
}

bool ExpectMutationStatus(
    apfsaccess::rw::MetadataStore& store,
    const apfsaccess::rw::MetadataStore::MutationRequest& request,
    apfsaccess::rw::MetadataStore::MutationStatus expected,
    const std::string& message)
{
    const auto status = store.ApplyMutation(request);
    if (status != expected)
    {
        std::cerr << "[DEBUG] mutation status for '" << message << "': "
                  << MutationStatusToString(status) << std::endl;
        return Require(false, message);
    }
    return true;
}

bool ExpectCommitStatus(
    apfsaccess::rw::MetadataStore& store,
    apfsaccess::rw::MetadataStore::CommitStatus expected,
    const std::string& message)
{
    const auto status = store.CommitPendingMutations();
    if (status != expected)
    {
        std::cerr << "[DEBUG] commit status for '" << message << "': "
                  << CommitStatusToString(status) << std::endl;
        std::cerr << "[DEBUG] commit stage for '" << message << "': "
                  << store.LastCommitStage() << std::endl;
        const auto recovery_reason = store.RecoveryReason();
        if (!recovery_reason.empty())
        {
            std::wcerr << L"[DEBUG] recovery reason: " << recovery_reason << std::endl;
        }
        return Require(false, message);
    }
    return true;
}

void ConfigurePayloadProvider(
    apfsaccess::rw::MetadataStore& store,
    std::unordered_map<std::wstring, std::vector<std::byte>>& staged_payloads)
{
    store.SetFilePayloadProvider(
        [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
        {
            auto pending = staged_payloads.find(path);
            if (pending == staged_payloads.end())
            {
                return std::nullopt;
            }

            auto payload = pending->second;
            if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
            {
                return std::nullopt;
            }

            const auto target_size = static_cast<std::size_t>(logical_size);
            if (payload.size() < target_size)
            {
                payload.resize(target_size, std::byte{0});
            }
            else if (payload.size() > target_size)
            {
                payload.resize(target_size);
            }

            return payload;
        });
}

bool TestRenameReplaceConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "rename_replace.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "TestRenameReplaceConformance: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"RenameReplace",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "RenameReplace: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "RenameReplace: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "RenameReplace: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "RenameReplace: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    store.SetFilePayloadProvider(
        [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
        {
            auto pending = staged_payloads.find(path);
            if (pending == staged_payloads.end())
            {
                return std::nullopt;
            }

            auto payload = pending->second;
            if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
            {
                return std::nullopt;
            }

            const auto target_size = static_cast<std::size_t>(logical_size);
            if (payload.size() < target_size)
            {
                payload.resize(target_size, std::byte{0});
            }
            else if (payload.size() > target_size)
            {
                payload.resize(target_size);
            }

            return payload;
        });

    apfsaccess::rw::MetadataStore::MutationRequest create_dir{};
    create_dir.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateDirectory;
    create_dir.path = L"\\docs";
    ok &= ExpectMutationStatus(
        store,
        create_dir,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "RenameReplace: CreateDirectory docs should apply");

    apfsaccess::rw::MetadataStore::MutationRequest create_source{};
    create_source.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_source.path = L"\\docs\\source.txt";
    ok &= ExpectMutationStatus(
        store,
        create_source,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "RenameReplace: CreateFile source should apply");

    apfsaccess::rw::MetadataStore::MutationRequest write_source{};
    write_source.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_source.path = L"\\docs\\source.txt";
    write_source.offset = 0;
    write_source.length = 2048;
    ok &= ExpectMutationStatus(
        store,
        write_source,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "RenameReplace: Write source should apply");

    apfsaccess::rw::MetadataStore::MutationRequest create_target{};
    create_target.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_target.path = L"\\docs\\target.txt";
    ok &= ExpectMutationStatus(
        store,
        create_target,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "RenameReplace: CreateFile target should apply");

    apfsaccess::rw::MetadataStore::MutationRequest write_target{};
    write_target.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_target.path = L"\\docs\\target.txt";
    write_target.offset = 0;
    write_target.length = 1024;
    ok &= ExpectMutationStatus(
        store,
        write_target,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "RenameReplace: Write target should apply");

    const auto source_payload = BuildPatternPayload(2048, 0x31);
    const auto target_payload = BuildPatternPayload(1024, 0x89);
    staged_payloads[L"\\docs\\source.txt"] = source_payload;
    staged_payloads[L"\\docs\\target.txt"] = target_payload;

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "RenameReplace: first commit should succeed");

    const auto source_before = store.LookupCommittedInodeByPath(L"\\docs\\source.txt");
    const auto target_before = store.LookupCommittedInodeByPath(L"\\docs\\target.txt");
    ok &= Require(source_before.has_value(), "RenameReplace: source inode should exist after first commit");
    ok &= Require(target_before.has_value(), "RenameReplace: target inode should exist after first commit");
    if (!source_before.has_value() || !target_before.has_value())
    {
        return false;
    }
    const auto source_before_object_id = source_before->object_id;
    const auto target_before_object_id = target_before->object_id;

    apfsaccess::rw::MetadataStore::MutationRequest rename_without_replace{};
    rename_without_replace.operation = apfsaccess::rw::MetadataStore::MutationOperation::Rename;
    rename_without_replace.path = L"\\docs\\source.txt";
    rename_without_replace.secondary_path = L"\\docs\\target.txt";
    rename_without_replace.replace_if_exists = false;
    ok &= ExpectMutationStatus(
        store,
        rename_without_replace,
        apfsaccess::rw::MetadataStore::MutationStatus::InvalidRequest,
        "RenameReplace: rename collision without replace should fail");

    apfsaccess::rw::MetadataStore::MutationRequest rename_with_replace = rename_without_replace;
    rename_with_replace.replace_if_exists = true;
    ok &= ExpectMutationStatus(
        store,
        rename_with_replace,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "RenameReplace: rename collision with replace should apply");

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "RenameReplace: second commit should succeed");

    ok &= Require(
        !store.LookupCommittedInodeByPath(L"\\docs\\source.txt").has_value(),
        "RenameReplace: source path should be absent after replacement rename");

    const auto target_after = store.LookupCommittedInodeByPath(L"\\docs\\target.txt");
    ok &= Require(target_after.has_value(), "RenameReplace: target path should exist after replacement rename");
    if (!target_after.has_value())
    {
        return false;
    }

    ok &= Require(
        target_after->object_id == source_before_object_id,
        "RenameReplace: target path should now reference the source inode object");
    ok &= Require(
        target_after->object_id != target_before_object_id,
        "RenameReplace: original target inode object should be replaced");
    ok &= Require(
        target_after->logical_size == static_cast<std::uint64_t>(source_payload.size()),
        "RenameReplace: replacement target logical size should match source payload");
    ok &= Require(
        store.CommittedFreeExtentCount() > 0,
        "RenameReplace: replacing target should free at least one previously allocated extent");

    std::vector<std::byte> persisted_payload;
    ok &= Require(
        ReadBytesFromImage(
            image_path,
            target_after->data_physical_address,
            source_payload.size(),
            persisted_payload),
        "RenameReplace: replacement target payload should be readable");
    ok &= Require(
        persisted_payload == source_payload,
        "RenameReplace: replacement target payload should match source payload bytes");

    return ok;
}

bool TestDirectoryAndDeleteConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "directory_delete.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "TestDirectoryAndDeleteConformance: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"DirectoryDelete",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "DirectoryDelete: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "DirectoryDelete: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "DirectoryDelete: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "DirectoryDelete: PrepareNativeWritePath should succeed");

    apfsaccess::rw::MetadataStore::MutationRequest create_tree{};
    create_tree.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateDirectory;
    create_tree.path = L"\\tree";
    ok &= ExpectMutationStatus(
        store,
        create_tree,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "DirectoryDelete: CreateDirectory tree should apply");

    apfsaccess::rw::MetadataStore::MutationRequest create_leaf = create_tree;
    create_leaf.path = L"\\tree\\leaf";
    ok &= ExpectMutationStatus(
        store,
        create_leaf,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "DirectoryDelete: CreateDirectory tree\\leaf should apply");

    apfsaccess::rw::MetadataStore::MutationRequest delete_non_empty{};
    delete_non_empty.operation = apfsaccess::rw::MetadataStore::MutationOperation::Delete;
    delete_non_empty.path = L"\\tree";
    ok &= ExpectMutationStatus(
        store,
        delete_non_empty,
        apfsaccess::rw::MetadataStore::MutationStatus::InvalidRequest,
        "DirectoryDelete: deleting non-empty directory should fail");

    apfsaccess::rw::MetadataStore::MutationRequest rename_cycle{};
    rename_cycle.operation = apfsaccess::rw::MetadataStore::MutationOperation::Rename;
    rename_cycle.path = L"\\tree";
    rename_cycle.secondary_path = L"\\tree\\leaf\\tree";
    ok &= ExpectMutationStatus(
        store,
        rename_cycle,
        apfsaccess::rw::MetadataStore::MutationStatus::InvalidRequest,
        "DirectoryDelete: renaming directory into descendant should fail");

    apfsaccess::rw::MetadataStore::MutationRequest create_empty_a = create_tree;
    create_empty_a.path = L"\\emptyA";
    ok &= ExpectMutationStatus(
        store,
        create_empty_a,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "DirectoryDelete: CreateDirectory emptyA should apply");

    apfsaccess::rw::MetadataStore::MutationRequest create_empty_b = create_tree;
    create_empty_b.path = L"\\emptyB";
    ok &= ExpectMutationStatus(
        store,
        create_empty_b,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "DirectoryDelete: CreateDirectory emptyB should apply");

    apfsaccess::rw::MetadataStore::MutationRequest rename_collision{};
    rename_collision.operation = apfsaccess::rw::MetadataStore::MutationOperation::Rename;
    rename_collision.path = L"\\emptyA";
    rename_collision.secondary_path = L"\\emptyB";
    rename_collision.replace_if_exists = false;
    ok &= ExpectMutationStatus(
        store,
        rename_collision,
        apfsaccess::rw::MetadataStore::MutationStatus::InvalidRequest,
        "DirectoryDelete: rename collision without replace should fail");

    rename_collision.replace_if_exists = true;
    ok &= ExpectMutationStatus(
        store,
        rename_collision,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "DirectoryDelete: rename collision with replace should apply");

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "DirectoryDelete: commit should succeed");

    ok &= Require(
        !store.LookupCommittedInodeByPath(L"\\emptyA").has_value(),
        "DirectoryDelete: emptyA should be absent after replacement rename");
    const auto empty_b = store.LookupCommittedInodeByPath(L"\\emptyB");
    ok &= Require(empty_b.has_value(), "DirectoryDelete: emptyB should exist after replacement rename");
    if (empty_b.has_value())
    {
        ok &= Require(empty_b->is_directory, "DirectoryDelete: emptyB should remain a directory");
    }

    return ok;
}

bool TestTruncateConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "truncate.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "TestTruncateConformance: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"Truncate",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "Truncate: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "Truncate: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "Truncate: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "Truncate: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    store.SetFilePayloadProvider(
        [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
        {
            auto pending = staged_payloads.find(path);
            if (pending == staged_payloads.end())
            {
                return std::nullopt;
            }

            auto payload = pending->second;
            if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
            {
                return std::nullopt;
            }

            const auto target_size = static_cast<std::size_t>(logical_size);
            if (payload.size() < target_size)
            {
                payload.resize(target_size, std::byte{0});
            }
            else if (payload.size() > target_size)
            {
                payload.resize(target_size);
            }
            return payload;
        });

    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_file.path = L"\\truncate.bin";
    ok &= ExpectMutationStatus(
        store,
        create_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "Truncate: CreateFile truncate.bin should apply");

    apfsaccess::rw::MetadataStore::MutationRequest write_file{};
    write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_file.path = L"\\truncate.bin";
    write_file.offset = 0;
    write_file.length = 3072;
    ok &= ExpectMutationStatus(
        store,
        write_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "Truncate: Write truncate.bin should apply");

    const auto initial_payload = BuildPatternPayload(3072, 0x4D);
    staged_payloads[L"\\truncate.bin"] = initial_payload;
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "Truncate: initial commit should succeed");

    const auto truncate_before = store.LookupCommittedInodeByPath(L"\\truncate.bin");
    ok &= Require(truncate_before.has_value(), "Truncate: truncate.bin should exist after initial commit");
    if (!truncate_before.has_value())
    {
        return false;
    }
    ok &= Require(
        truncate_before->logical_size == static_cast<std::uint64_t>(initial_payload.size()),
        "Truncate: logical size should match initial payload");
    const auto free_extents_before = store.CommittedFreeExtentCount();

    apfsaccess::rw::MetadataStore::MutationRequest truncate_file{};
    truncate_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetFileSize;
    truncate_file.path = L"\\truncate.bin";
    truncate_file.length = 0;
    ok &= ExpectMutationStatus(
        store,
        truncate_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "Truncate: SetFileSize to zero should apply");

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "Truncate: truncate commit should succeed");

    const auto truncate_after = store.LookupCommittedInodeByPath(L"\\truncate.bin");
    ok &= Require(truncate_after.has_value(), "Truncate: truncate.bin should persist after truncate");
    if (truncate_after.has_value())
    {
        ok &= Require(truncate_after->logical_size == 0, "Truncate: logical size should be zero after truncate");
        ok &= Require(truncate_after->data_physical_address == 0, "Truncate: physical extent should clear after truncate");
    }
    ok &= Require(
        store.CommittedFreeExtentCount() > free_extents_before,
        "Truncate: truncate should increase committed free extent count");

    return ok;
}

bool TestDirectorySubtreeRenameObjectMapConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "directory_subtree_rename.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "TestDirectorySubtreeRenameObjectMapConformance: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"DirectorySubtreeRename",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "DirectorySubtreeRename: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "DirectorySubtreeRename: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "DirectorySubtreeRename: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "DirectorySubtreeRename: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    apfsaccess::rw::MetadataStore::MutationRequest create_directory{};
    create_directory.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateDirectory;
    create_directory.path = L"\\A";
    ok &= ExpectMutationStatus(
        store,
        create_directory,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "DirectorySubtreeRename: create \\A should apply");

    create_directory.path = L"\\A\\B";
    ok &= ExpectMutationStatus(
        store,
        create_directory,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "DirectorySubtreeRename: create \\A\\B should apply");

    apfsaccess::rw::MetadataStore::MutationRequest create_leaf{};
    create_leaf.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_leaf.path = L"\\A\\B\\leaf.bin";
    ok &= ExpectMutationStatus(
        store,
        create_leaf,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "DirectorySubtreeRename: create leaf should apply");

    apfsaccess::rw::MetadataStore::MutationRequest write_leaf{};
    write_leaf.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_leaf.path = L"\\A\\B\\leaf.bin";
    write_leaf.length = 1536;
    ok &= ExpectMutationStatus(
        store,
        write_leaf,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "DirectorySubtreeRename: write leaf should apply");

    const auto leaf_payload = BuildPatternPayload(1536, 0x6B);
    staged_payloads[L"\\A\\B\\leaf.bin"] = leaf_payload;

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "DirectorySubtreeRename: baseline commit should succeed");

    const auto baseline_xid = store.LastCommittedXid().value_or(0);
    ok &= Require(
        baseline_xid == (kInitialCheckpointXid + 1),
        "DirectorySubtreeRename: baseline commit should advance xid");

    const auto a_before = store.LookupCommittedInodeByPath(L"\\A");
    const auto b_before = store.LookupCommittedInodeByPath(L"\\A\\B");
    const auto leaf_before = store.LookupCommittedInodeByPath(L"\\A\\B\\leaf.bin");
    ok &= Require(a_before.has_value(), "DirectorySubtreeRename: \\A inode should exist after baseline commit");
    ok &= Require(b_before.has_value(), "DirectorySubtreeRename: \\A\\B inode should exist after baseline commit");
    ok &= Require(leaf_before.has_value(), "DirectorySubtreeRename: leaf inode should exist after baseline commit");
    if (!a_before.has_value() || !b_before.has_value() || !leaf_before.has_value())
    {
        return false;
    }

    const auto leaf_object_before = store.LookupCommittedObject(leaf_before->object_id);
    ok &= Require(
        leaf_object_before.has_value(),
        "DirectorySubtreeRename: leaf object-map entry should exist after baseline commit");
    if (leaf_object_before.has_value())
    {
        ok &= Require(
            leaf_object_before->xid == baseline_xid,
            "DirectorySubtreeRename: leaf object-map xid should match baseline xid");
    }

    apfsaccess::rw::MetadataStore::MutationRequest rename_subtree{};
    rename_subtree.operation = apfsaccess::rw::MetadataStore::MutationOperation::Rename;
    rename_subtree.path = L"\\A";
    rename_subtree.secondary_path = L"\\RenamedA";
    ok &= ExpectMutationStatus(
        store,
        rename_subtree,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "DirectorySubtreeRename: subtree rename should apply");

    staged_payloads[L"\\RenamedA\\B\\leaf.bin"] = leaf_payload;
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "DirectorySubtreeRename: subtree rename commit should succeed");

    const auto rename_xid = store.LastCommittedXid().value_or(0);
    ok &= Require(
        rename_xid == (baseline_xid + 1),
        "DirectorySubtreeRename: rename commit should advance xid");

    ok &= Require(
        !store.LookupCommittedInodeByPath(L"\\A").has_value() &&
            !store.LookupCommittedInodeByPath(L"\\A\\B").has_value() &&
            !store.LookupCommittedInodeByPath(L"\\A\\B\\leaf.bin").has_value(),
        "DirectorySubtreeRename: old subtree paths should be absent after rename");

    const auto a_after = store.LookupCommittedInodeByPath(L"\\RenamedA");
    const auto b_after = store.LookupCommittedInodeByPath(L"\\RenamedA\\B");
    const auto leaf_after = store.LookupCommittedInodeByPath(L"\\RenamedA\\B\\leaf.bin");
    ok &= Require(a_after.has_value(), "DirectorySubtreeRename: renamed root inode should exist");
    ok &= Require(b_after.has_value(), "DirectorySubtreeRename: renamed child directory inode should exist");
    ok &= Require(leaf_after.has_value(), "DirectorySubtreeRename: renamed leaf inode should exist");
    if (!a_after.has_value() || !b_after.has_value() || !leaf_after.has_value())
    {
        return false;
    }

    ok &= Require(
        a_after->object_id == a_before->object_id &&
            b_after->object_id == b_before->object_id &&
            leaf_after->object_id == leaf_before->object_id,
        "DirectorySubtreeRename: subtree rename should preserve inode object ids");

    const auto a_object_after = store.LookupCommittedObject(a_after->object_id);
    const auto b_object_after = store.LookupCommittedObject(b_after->object_id);
    const auto leaf_object_after = store.LookupCommittedObject(leaf_after->object_id);
    ok &= Require(a_object_after.has_value(), "DirectorySubtreeRename: renamed root object-map entry should exist");
    ok &= Require(b_object_after.has_value(), "DirectorySubtreeRename: renamed child object-map entry should exist");
    ok &= Require(leaf_object_after.has_value(), "DirectorySubtreeRename: renamed leaf object-map entry should exist");
    if (a_object_after.has_value() && b_object_after.has_value() && leaf_object_after.has_value())
    {
        ok &= Require(
            a_object_after->xid == rename_xid &&
                b_object_after->xid == rename_xid &&
                leaf_object_after->xid == rename_xid,
            "DirectorySubtreeRename: renamed subtree object-map xid projection should match rename commit xid");
    }

    std::vector<std::byte> persisted_leaf_payload;
    ok &= Require(
        store.ReadCommittedFileRange(
            L"\\RenamedA\\B\\leaf.bin",
            0,
            leaf_payload.size(),
            persisted_leaf_payload),
        "DirectorySubtreeRename: renamed leaf payload should be readable");
    ok &= Require(
        persisted_leaf_payload == leaf_payload,
        "DirectorySubtreeRename: renamed leaf payload should remain unchanged");

    return ok;
}

bool TestPendingWriteDirectoryRenamePersistenceConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "pending_write_directory_rename.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "PendingWriteDirectoryRename: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"PendingWriteDirectoryRename",
    };
    bool ok = true;
    const auto baseline_payload = BuildPatternPayload(1024, 0x34);
    const auto renamed_payload = BuildPatternPayload(2048, 0x9A);

    {
        apfsaccess::rw::MetadataStore store(context);
        ok &= Require(store.LoadContainerSuperblocks(), "PendingWriteDirectoryRename: LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "PendingWriteDirectoryRename: LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "PendingWriteDirectoryRename: LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "PendingWriteDirectoryRename: PrepareNativeWritePath should succeed");

        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        ConfigurePayloadProvider(store, staged_payloads);

        apfsaccess::rw::MetadataStore::MutationRequest create_directory{};
        create_directory.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateDirectory;
        create_directory.path = L"\\Source";
        ok &= ExpectMutationStatus(
            store,
            create_directory,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "PendingWriteDirectoryRename: create \\Source should apply");

        create_directory.path = L"\\Source\\Nested";
        ok &= ExpectMutationStatus(
            store,
            create_directory,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "PendingWriteDirectoryRename: create nested directory should apply");

        apfsaccess::rw::MetadataStore::MutationRequest create_file{};
        create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_file.path = L"\\Source\\Nested\\dirty.bin";
        ok &= ExpectMutationStatus(
            store,
            create_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "PendingWriteDirectoryRename: create dirty file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\Source\\Nested\\dirty.bin";
        write_file.length = baseline_payload.size();
        ok &= ExpectMutationStatus(
            store,
            write_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "PendingWriteDirectoryRename: initial write should apply");
        staged_payloads[L"\\Source\\Nested\\dirty.bin"] = baseline_payload;

        ok &= ExpectCommitStatus(
            store,
            apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "PendingWriteDirectoryRename: baseline commit should succeed");

        staged_payloads.clear();
        write_file.length = renamed_payload.size();
        ok &= ExpectMutationStatus(
            store,
            write_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "PendingWriteDirectoryRename: overwrite before rename should apply");
        staged_payloads[L"\\Source\\Nested\\dirty.bin"] = renamed_payload;

        apfsaccess::rw::MetadataStore::MutationRequest rename_directory{};
        rename_directory.operation = apfsaccess::rw::MetadataStore::MutationOperation::Rename;
        rename_directory.path = L"\\Source";
        rename_directory.secondary_path = L"\\Moved";
        ok &= ExpectMutationStatus(
            store,
            rename_directory,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "PendingWriteDirectoryRename: directory rename should apply");

        staged_payloads[L"\\Moved\\Nested\\dirty.bin"] = renamed_payload;
        staged_payloads.erase(L"\\Source\\Nested\\dirty.bin");

        ok &= ExpectCommitStatus(
            store,
            apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "PendingWriteDirectoryRename: rename commit should succeed");

        ok &= Require(
            !store.LookupCommittedInodeByPath(L"\\Source\\Nested\\dirty.bin").has_value(),
            "PendingWriteDirectoryRename: old path should be absent after rename commit");
        auto renamed_inode = store.LookupCommittedInodeByPath(L"\\Moved\\Nested\\dirty.bin");
        ok &= Require(renamed_inode.has_value(), "PendingWriteDirectoryRename: renamed file should exist after commit");
        if (renamed_inode.has_value())
        {
            ok &= Require(
                renamed_inode->logical_size == renamed_payload.size(),
                "PendingWriteDirectoryRename: renamed file logical size should match overwrite");
        }

        std::vector<std::byte> committed_payload;
        ok &= Require(
            store.ReadCommittedFileRange(
                L"\\Moved\\Nested\\dirty.bin",
                0,
                renamed_payload.size(),
                committed_payload),
            "PendingWriteDirectoryRename: committed payload should be readable after rename");
        ok &= Require(
            committed_payload == renamed_payload,
            "PendingWriteDirectoryRename: committed payload should follow renamed descendant");
    }

    {
        apfsaccess::rw::MetadataStore remounted(context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "PendingWriteDirectoryRename: remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "PendingWriteDirectoryRename: remount PrepareNativeWritePath should succeed");
        ok &= Require(!remounted.IsRecoveryRequired(), "PendingWriteDirectoryRename: remount should not require recovery");
        ok &= Require(remounted.IsCommitPathReady(), "PendingWriteDirectoryRename: remount commit path should remain ready");
        ok &= Require(
            !remounted.LookupCommittedInodeByPath(L"\\Source\\Nested\\dirty.bin").has_value(),
            "PendingWriteDirectoryRename: remount old path should stay absent");
        auto remounted_inode = remounted.LookupCommittedInodeByPath(L"\\Moved\\Nested\\dirty.bin");
        ok &= Require(remounted_inode.has_value(), "PendingWriteDirectoryRename: remount renamed file should exist");
        if (remounted_inode.has_value())
        {
            ok &= Require(
                remounted_inode->logical_size == renamed_payload.size(),
                "PendingWriteDirectoryRename: remount logical size should match overwrite");
        }

        std::vector<std::byte> remounted_payload;
        ok &= Require(
            remounted.ReadCommittedFileRange(
                L"\\Moved\\Nested\\dirty.bin",
                0,
                renamed_payload.size(),
                remounted_payload),
            "PendingWriteDirectoryRename: remount payload should be readable");
        ok &= Require(
            remounted_payload == renamed_payload,
            "PendingWriteDirectoryRename: remount payload should preserve renamed descendant bytes");
    }

    return ok;
}

bool TestBtreeCanonicalizationConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "btree_canonical.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "TestBtreeCanonicalizationConformance: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"BtreeCanonical",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "BtreeCanonical: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "BtreeCanonical: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "BtreeCanonical: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "BtreeCanonical: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_file.path = L"\\canonical.txt";
    ok &= ExpectMutationStatus(
        store,
        create_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "BtreeCanonical: create file should apply");

    apfsaccess::rw::MetadataStore::MutationRequest write_file{};
    write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_file.path = L"\\canonical.txt";
    write_file.length = 640;
    ok &= ExpectMutationStatus(
        store,
        write_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "BtreeCanonical: write file should apply");
    staged_payloads[L"\\canonical.txt"] = BuildPatternPayload(640, 0x5C);

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "BtreeCanonical: initial commit should succeed");
    const auto record_count_after_create = store.CommittedBtreeRecordCount();
    ok &= Require(record_count_after_create > 0, "BtreeCanonical: initial commit should persist btree records");

    apfsaccess::rw::MetadataStore::MutationRequest set_basic_info{};
    set_basic_info.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetBasicInfo;
    set_basic_info.path = L"\\canonical.txt";
    ok &= ExpectMutationStatus(
        store,
        set_basic_info,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "BtreeCanonical: set basic info should apply");
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "BtreeCanonical: set basic info commit should succeed");
    ok &= Require(
        store.CommittedBtreeRecordCount() == record_count_after_create,
        "BtreeCanonical: set basic info should overwrite existing inode key rather than grow canonical record set");

    apfsaccess::rw::MetadataStore::MutationRequest rename_file{};
    rename_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Rename;
    rename_file.path = L"\\canonical.txt";
    rename_file.secondary_path = L"\\renamed-canonical.txt";
    ok &= ExpectMutationStatus(
        store,
        rename_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "BtreeCanonical: rename should apply");
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "BtreeCanonical: rename commit should succeed");
    const auto record_count_after_rename = store.CommittedBtreeRecordCount();
    ok &= Require(
        record_count_after_rename == record_count_after_create,
        "BtreeCanonical: rename should maintain canonical btree cardinality");

    apfsaccess::rw::MetadataStore::MutationRequest delete_file{};
    delete_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Delete;
    delete_file.path = L"\\renamed-canonical.txt";
    ok &= ExpectMutationStatus(
        store,
        delete_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "BtreeCanonical: delete should apply");
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "BtreeCanonical: delete commit should succeed");
    ok &= Require(
        store.CommittedBtreeRecordCount() < record_count_after_rename,
        "BtreeCanonical: delete tombstones should compact canonical btree record set");
    ok &= Require(
        !store.LookupCommittedInodeByPath(L"\\canonical.txt").has_value() &&
            !store.LookupCommittedInodeByPath(L"\\renamed-canonical.txt").has_value(),
        "BtreeCanonical: deleted file path should not remain in committed inode projection");

    return ok;
}

bool TestCommittedReadExtentsConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "read_extents.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "ReadExtents: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"ReadExtents",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "ReadExtents: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "ReadExtents: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "ReadExtents: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "ReadExtents: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_file.path = L"\\fragmented.bin";
    ok &= ExpectMutationStatus(
        store,
        create_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "ReadExtents: create file should apply");

    apfsaccess::rw::MetadataStore::MutationRequest write_file{};
    write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_file.path = L"\\fragmented.bin";
    write_file.length = 8192;
    ok &= ExpectMutationStatus(
        store,
        write_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "ReadExtents: write file should apply");

    const auto placeholder_payload = BuildPatternPayload(8192, 0x8A);
    staged_payloads[L"\\fragmented.bin"] = placeholder_payload;
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "ReadExtents: commit should succeed");

    auto inode = store.LookupCommittedInodeByPath(L"\\fragmented.bin");
    ok &= Require(inode.has_value(), "ReadExtents: committed inode should exist");
    if (!inode.has_value())
    {
        return false;
    }

    constexpr std::uint64_t first_extent_address = 700ull * kBlockSize;
    constexpr std::uint64_t second_extent_address = 702ull * kBlockSize;
    const auto first_payload = BuildPatternPayload(1024, 0x10);
    const auto second_payload = BuildPatternPayload(2048, 0x70);
    ok &= Require(
        WriteBytesToImage(image_path, first_extent_address, first_payload),
        "ReadExtents: first payload extent should be written to fixture");
    ok &= Require(
        WriteBytesToImage(image_path, second_extent_address, second_payload),
        "ReadExtents: second payload extent should be written to fixture");
    ok &= Require(
        store.SetCommittedReadExtents(
            inode->object_id,
            {
                { 0, first_extent_address, first_payload.size() },
                { 0, first_extent_address, first_payload.size() },
                { 4096, second_extent_address, second_payload.size() },
            }),
        "ReadExtents: committed read extent table should accept sorted fragments and exact duplicates");

    std::vector<std::byte> whole;
    ok &= Require(
        store.ReadCommittedFileRange(L"\\fragmented.bin", 0, 6144, whole),
        "ReadExtents: fragmented range should read successfully");
    ok &= Require(whole.size() == 6144, "ReadExtents: fragmented read should preserve requested logical length");
    ok &= Require(
        std::equal(first_payload.begin(), first_payload.end(), whole.begin()),
        "ReadExtents: first extent bytes should match");
    ok &= Require(
        std::all_of(whole.begin() + 1024, whole.begin() + 4096, [](std::byte value)
        {
            return value == std::byte{0};
        }),
        "ReadExtents: sparse gap should be zero-filled");
    ok &= Require(
        std::equal(second_payload.begin(), second_payload.end(), whole.begin() + 4096),
        "ReadExtents: second extent bytes should match");

    std::vector<std::byte> second_window;
    ok &= Require(
        store.ReadCommittedFileRange(L"\\fragmented.bin", 4608, 512, second_window),
        "ReadExtents: read wholly inside second extent should succeed");
    ok &= Require(
        second_window.size() == 512 &&
            std::equal(second_window.begin(), second_window.end(), second_payload.begin() + 512),
        "ReadExtents: second extent window should match");

    std::vector<std::byte> eof_window;
    ok &= Require(
        store.ReadCommittedFileRange(L"\\fragmented.bin", 6144, 4096, eof_window),
        "ReadExtents: EOF-clamped fragmented read should succeed");
    ok &= Require(eof_window.size() == 2048, "ReadExtents: EOF read should clamp to logical file size");
    ok &= Require(
        std::all_of(eof_window.begin(), eof_window.end(), [](std::byte value)
        {
            return value == std::byte{0};
        }),
        "ReadExtents: missing tail extent should zero-fill within logical size");

    return ok;
}

bool TestCommittedZeroReadExtentConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "zero_read_extents.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "ZeroReadExtents: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"ZeroReadExtents",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "ZeroReadExtents: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "ZeroReadExtents: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "ZeroReadExtents: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "ZeroReadExtents: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_file.path = L"\\zero-backed.bin";
    ok &= ExpectMutationStatus(
        store,
        create_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "ZeroReadExtents: create file should apply");

    apfsaccess::rw::MetadataStore::MutationRequest write_file{};
    write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_file.path = L"\\zero-backed.bin";
    write_file.length = 4096;
    ok &= ExpectMutationStatus(
        store,
        write_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "ZeroReadExtents: write file should apply");

    staged_payloads[L"\\zero-backed.bin"] = BuildPatternPayload(4096, 0x11);
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "ZeroReadExtents: commit should succeed");

    auto inode = store.LookupCommittedInodeByPath(L"\\zero-backed.bin");
    ok &= Require(inode.has_value(), "ZeroReadExtents: committed inode should exist");
    if (!inode.has_value())
    {
        return false;
    }

    ok &= Require(
        store.SetCommittedReadExtents(
            inode->object_id,
            {
                { 0, 0, 4096 },
            }),
        "ZeroReadExtents: committed read extent table should accept zero physical address extents");

    std::vector<std::byte> payload;
    ok &= Require(
        store.ReadCommittedFileRange(L"\\zero-backed.bin", 0, 4096, payload),
        "ZeroReadExtents: zero physical extent should read successfully");
    ok &= Require(payload.size() == 4096, "ZeroReadExtents: zero extent should preserve logical length");
    ok &= Require(
        std::all_of(payload.begin(), payload.end(), [](std::byte value)
        {
            return value == std::byte{0};
        }),
        "ZeroReadExtents: zero physical extent should return zero-filled bytes");

    return ok;
}

bool TestObjectMapDeltaCanonicalizationConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "object_map_delta_canonical.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "TestObjectMapDeltaCanonicalizationConformance: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"ObjectMapDeltaCanonical",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "ObjectMapDelta: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "ObjectMapDelta: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "ObjectMapDelta: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "ObjectMapDelta: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_file.path = L"\\delta.bin";
    ok &= ExpectMutationStatus(
        store,
        create_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "ObjectMapDelta: create file should apply");

    apfsaccess::rw::MetadataStore::MutationRequest write_file{};
    write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_file.path = L"\\delta.bin";
    write_file.length = 1024;
    ok &= ExpectMutationStatus(
        store,
        write_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "ObjectMapDelta: initial write should apply");
    staged_payloads[L"\\delta.bin"] = BuildPatternPayload(1024, 0x63);

    apfsaccess::rw::MetadataStore::MutationRequest resize_file{};
    resize_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetFileSize;
    resize_file.path = L"\\delta.bin";
    resize_file.length = 2048;
    ok &= ExpectMutationStatus(
        store,
        resize_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "ObjectMapDelta: resize should apply");
    staged_payloads[L"\\delta.bin"] = BuildPatternPayload(2048, 0x71);

    apfsaccess::rw::MetadataStore::MutationRequest set_basic_info{};
    set_basic_info.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetBasicInfo;
    set_basic_info.path = L"\\delta.bin";
    ok &= ExpectMutationStatus(
        store,
        set_basic_info,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "ObjectMapDelta: set basic info should apply");

    ok &= Require(
        store.PendingObjectMapUpdateCount() == 1,
        "ObjectMapDelta: pending object-map updates should be canonicalized to one entry per object");

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "ObjectMapDelta: commit should succeed");

    const auto committed = store.LookupCommittedInodeByPath(L"\\delta.bin");
    ok &= Require(committed.has_value(), "ObjectMapDelta: committed inode should exist");
    if (committed.has_value())
    {
        ok &= Require(
            committed->logical_size == 2048,
            "ObjectMapDelta: committed inode size should match final resize");
    }

    return ok;
}

bool TestEphemeralCreateDeleteConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "ephemeral_create_delete.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "TestEphemeralCreateDeleteConformance: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"EphemeralCreateDelete",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "EphemeralCreateDelete: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "EphemeralCreateDelete: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "EphemeralCreateDelete: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "EphemeralCreateDelete: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_file.path = L"\\ephemeral.bin";
    ok &= ExpectMutationStatus(
        store,
        create_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "EphemeralCreateDelete: create file should apply");

    apfsaccess::rw::MetadataStore::MutationRequest write_file{};
    write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_file.path = L"\\ephemeral.bin";
    write_file.length = 4096;
    ok &= ExpectMutationStatus(
        store,
        write_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "EphemeralCreateDelete: write file should apply");
    staged_payloads[L"\\ephemeral.bin"] = BuildPatternPayload(4096, 0x2C);

    apfsaccess::rw::MetadataStore::MutationRequest delete_file{};
    delete_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Delete;
    delete_file.path = L"\\ephemeral.bin";
    ok &= ExpectMutationStatus(
        store,
        delete_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "EphemeralCreateDelete: delete file should apply");
    staged_payloads.erase(L"\\ephemeral.bin");

    ok &= Require(
        store.PendingAllocationCount() > 0 && store.PendingDeallocationCount() > 0,
        "EphemeralCreateDelete: pending allocation/deallocation deltas should both be present before commit");

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "EphemeralCreateDelete: commit should succeed");
    ok &= Require(
        !store.LookupCommittedInodeByPath(L"\\ephemeral.bin").has_value(),
        "EphemeralCreateDelete: committed view should not contain ephemeral file");

    return ok;
}

bool TestObjectIdMonotonicAllocationConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "object_id_monotonic.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "TestObjectIdMonotonicAllocationConformance: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"ObjectIdMonotonic",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "ObjectIdMonotonic: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "ObjectIdMonotonic: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "ObjectIdMonotonic: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "ObjectIdMonotonic: PrepareNativeWritePath should succeed");

    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_file.path = L"\\monotonic.txt";
    ok &= ExpectMutationStatus(
        store,
        create_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "ObjectIdMonotonic: first create should apply");
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "ObjectIdMonotonic: first create commit should succeed");

    const auto first_inode = store.LookupCommittedInodeByPath(L"\\monotonic.txt");
    ok &= Require(first_inode.has_value(), "ObjectIdMonotonic: first inode should exist");

    apfsaccess::rw::MetadataStore::MutationRequest delete_file{};
    delete_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Delete;
    delete_file.path = L"\\monotonic.txt";
    ok &= ExpectMutationStatus(
        store,
        delete_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "ObjectIdMonotonic: delete should apply");
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "ObjectIdMonotonic: delete commit should succeed");
    ok &= Require(
        !store.LookupCommittedInodeByPath(L"\\monotonic.txt").has_value(),
        "ObjectIdMonotonic: file should be absent after delete commit");

    ok &= ExpectMutationStatus(
        store,
        create_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "ObjectIdMonotonic: second create should apply");
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "ObjectIdMonotonic: second create commit should succeed");

    const auto second_inode = store.LookupCommittedInodeByPath(L"\\monotonic.txt");
    ok &= Require(second_inode.has_value(), "ObjectIdMonotonic: second inode should exist");
    if (first_inode.has_value() && second_inode.has_value())
    {
        ok &= Require(
            second_inode->object_id != first_inode->object_id,
            "ObjectIdMonotonic: recreated file should not reuse deleted inode object id");
        ok &= Require(
            second_inode->object_id > first_inode->object_id,
            "ObjectIdMonotonic: recreated file should allocate a monotonically increasing object id");
    }

    return ok;
}

bool TestEphemeralReplayRecoveryConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "ephemeral_replay_recovery.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "TestEphemeralReplayRecoveryConformance: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"EphemeralReplayRecovery",
    };
    context.crash_replay_mode = L"ReplayIfSafe";

    bool ok = true;
    {
        apfsaccess::rw::MetadataStore store(context);
        ok &= Require(store.LoadContainerSuperblocks(), "EphemeralReplayRecovery: LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "EphemeralReplayRecovery: LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "EphemeralReplayRecovery: LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "EphemeralReplayRecovery: PrepareNativeWritePath should succeed");

        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        ConfigurePayloadProvider(store, staged_payloads);

        apfsaccess::rw::MetadataStore::MutationRequest create_file{};
        create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_file.path = L"\\ephemeral_replay.bin";
        ok &= ExpectMutationStatus(
            store,
            create_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "EphemeralReplayRecovery: create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\ephemeral_replay.bin";
        write_file.length = 4096;
        ok &= ExpectMutationStatus(
            store,
            write_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "EphemeralReplayRecovery: write file should apply");
        staged_payloads[L"\\ephemeral_replay.bin"] = BuildPatternPayload(4096, 0x3F);

        apfsaccess::rw::MetadataStore::MutationRequest delete_file{};
        delete_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Delete;
        delete_file.path = L"\\ephemeral_replay.bin";
        ok &= ExpectMutationStatus(
            store,
            delete_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "EphemeralReplayRecovery: delete file should apply");
        staged_payloads.erase(L"\\ephemeral_replay.bin");

        ok &= Require(
            store.PendingAllocationCount() > 0 && store.PendingDeallocationCount() > 0,
            "EphemeralReplayRecovery: pending allocation/deallocation deltas should both be present before interrupted commit");

        store.SetCommitStageHook([](const auto& stage)
        {
            return stage != "before-checkpoint-switch";
        });

        ok &= ExpectCommitStatus(
            store,
            apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "EphemeralReplayRecovery: interrupted commit should fail at before-checkpoint-switch");
        ok &= Require(
            store.IsRecoveryRequired(),
            "EphemeralReplayRecovery: interrupted commit should latch recovery-required state");
        ok &= Require(
            store.RecoveryReason() == L"CommitInterruptedBeforeCheckpointSwitch",
            "EphemeralReplayRecovery: interrupted commit should store checkpoint-switch recovery reason");
    }

    {
        apfsaccess::rw::MetadataStore remounted(context);
        ok &= Require(
            remounted.LoadContainerSuperblocks(),
            "EphemeralReplayRecovery: remount LoadContainerSuperblocks should succeed");
        ok &= Require(
            remounted.PrepareNativeWritePath(),
            "EphemeralReplayRecovery: remount PrepareNativeWritePath should succeed");
        ok &= Require(
            remounted.IsRecoveryRequired(),
            "EphemeralReplayRecovery: remount should require recovery before replay");
        ok &= Require(
            remounted.ReplayOrRecover(),
            "EphemeralReplayRecovery: remount replay should succeed for exact overlap alloc/dealloc semantics");
        ok &= Require(
            !remounted.IsRecoveryRequired(),
            "EphemeralReplayRecovery: remount should clear recovery state after replay");
        ok &= Require(
            remounted.IsCommitPathReady(),
            "EphemeralReplayRecovery: remount should restore commit path after replay");
        ok &= Require(
            !remounted.LookupCommittedInodeByPath(L"\\ephemeral_replay.bin").has_value(),
            "EphemeralReplayRecovery: committed view should remain without ephemeral file after replay");
    }

    return ok;
}
} // namespace

int main()
{
    bool ok = true;
    std::error_code ec;
    const auto unique_id = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto run_root = std::filesystem::temp_directory_path(ec) /
        ("ApfsAccessRwEngineConformance_" +
         std::to_string(GetCurrentProcessId()) +
         "_" +
         std::to_string(unique_id));
    if (ec)
    {
        std::cerr << "[FAIL] unable to access temporary directory for conformance tests" << std::endl;
        return 1;
    }

    std::filesystem::remove_all(run_root, ec);
    ec.clear();
    std::filesystem::create_directories(run_root, ec);
    if (ec)
    {
        std::cerr << "[FAIL] unable to create conformance run directory" << std::endl;
        return 1;
    }

    ok &= TestRenameReplaceConformance(run_root);
    ok &= TestDirectoryAndDeleteConformance(run_root);
    ok &= TestTruncateConformance(run_root);
    ok &= TestDirectorySubtreeRenameObjectMapConformance(run_root);
    ok &= TestPendingWriteDirectoryRenamePersistenceConformance(run_root);
    ok &= TestBtreeCanonicalizationConformance(run_root);
    ok &= TestCommittedReadExtentsConformance(run_root);
    ok &= TestCommittedZeroReadExtentConformance(run_root);
    ok &= TestObjectMapDeltaCanonicalizationConformance(run_root);
    ok &= TestEphemeralCreateDeleteConformance(run_root);
    ok &= TestObjectIdMonotonicAllocationConformance(run_root);
    ok &= TestEphemeralReplayRecoveryConformance(run_root);

    std::filesystem::remove_all(run_root, ec);
    if (!ok)
    {
        return 1;
    }

    std::cout << "[PASS] MetadataStoreConformanceTests" << std::endl;
    return 0;
}
