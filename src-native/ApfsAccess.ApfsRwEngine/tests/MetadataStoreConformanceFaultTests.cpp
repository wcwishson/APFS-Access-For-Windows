#include "MetadataStore.h"

#include <array>
#include <chrono>
#include <cstdint>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

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

std::optional<std::uint64_t> ReadLe64FromImage(
    const std::filesystem::path& image_path,
    std::uint64_t offset_bytes)
{
    std::array<unsigned char, 8> raw{};
    std::ifstream input(image_path, std::ios::binary);
    if (!input.good())
    {
        return std::nullopt;
    }

    input.seekg(static_cast<std::streamoff>(offset_bytes), std::ios::beg);
    if (!input.good())
    {
        return std::nullopt;
    }

    input.read(reinterpret_cast<char*>(raw.data()), static_cast<std::streamsize>(raw.size()));
    if (static_cast<std::size_t>(input.gcount()) != raw.size())
    {
        return std::nullopt;
    }

    std::uint64_t value = 0;
    for (std::size_t i = 0; i < raw.size(); ++i)
    {
        value |= static_cast<std::uint64_t>(raw[i]) << (i * 8);
    }

    return value;
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

std::uint64_t StableObjectIdFromPathForState(const std::wstring& path)
{
    constexpr std::uint64_t kFnvOffset = 1469598103934665603ull;
    constexpr std::uint64_t kFnvPrime = 1099511628211ull;

    std::uint64_t hash = kFnvOffset;
    for (const auto ch : path)
    {
        const auto lower = static_cast<std::uint16_t>(std::towlower(ch));
        const auto lo = static_cast<std::uint8_t>(lower & 0xffu);
        const auto hi = static_cast<std::uint8_t>((lower >> 8) & 0xffu);
        hash ^= lo;
        hash *= kFnvPrime;
        hash ^= hi;
        hash *= kFnvPrime;
    }

    return hash == 0 ? 1 : hash;
}

std::filesystem::path BuildPersistentStatePathForTest(const apfsaccess::rw::MetadataStore::VolumeContext& context)
{
    std::error_code ec;
    auto root = std::filesystem::temp_directory_path(ec);
    if (ec)
    {
        return {};
    }

    root /= "ApfsAccess";
    root /= "rw-state";
    const auto key = context.device_path + L"|" + context.volume_name;
    const auto stable_id = StableObjectIdFromPathForState(key);
    return root / (std::to_wstring(stable_id) + L".bin");
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

bool TestRenameReplaceRollbackBeforePersist(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "rename_replace_fault.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "RenameReplaceFault: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"RenameReplaceFault",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "RenameReplaceFault: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "RenameReplaceFault: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "RenameReplaceFault: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "RenameReplaceFault: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    apfsaccess::rw::MetadataStore::MutationRequest create_docs{};
    create_docs.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateDirectory;
    create_docs.path = L"\\docs";
    ok &= ExpectMutationStatus(
        store,
        create_docs,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "RenameReplaceFault: create docs should apply");

    apfsaccess::rw::MetadataStore::MutationRequest create_source{};
    create_source.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_source.path = L"\\docs\\source.txt";
    ok &= ExpectMutationStatus(
        store,
        create_source,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "RenameReplaceFault: create source should apply");

    apfsaccess::rw::MetadataStore::MutationRequest write_source{};
    write_source.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_source.path = L"\\docs\\source.txt";
    write_source.length = 1536;
    ok &= ExpectMutationStatus(
        store,
        write_source,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "RenameReplaceFault: write source should apply");

    apfsaccess::rw::MetadataStore::MutationRequest create_target{};
    create_target.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_target.path = L"\\docs\\target.txt";
    ok &= ExpectMutationStatus(
        store,
        create_target,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "RenameReplaceFault: create target should apply");

    apfsaccess::rw::MetadataStore::MutationRequest write_target{};
    write_target.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_target.path = L"\\docs\\target.txt";
    write_target.length = 640;
    ok &= ExpectMutationStatus(
        store,
        write_target,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "RenameReplaceFault: write target should apply");

    const auto source_payload = BuildPatternPayload(1536, 0x12);
    const auto target_payload = BuildPatternPayload(640, 0xA5);
    staged_payloads[L"\\docs\\source.txt"] = source_payload;
    staged_payloads[L"\\docs\\target.txt"] = target_payload;

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "RenameReplaceFault: baseline commit should succeed");
    ok &= Require(
        store.LastCommittedXid().value_or(0) == (kInitialCheckpointXid + 1),
        "RenameReplaceFault: baseline commit should advance xid");

    const auto source_before = store.LookupCommittedInodeByPath(L"\\docs\\source.txt");
    const auto target_before = store.LookupCommittedInodeByPath(L"\\docs\\target.txt");
    ok &= Require(source_before.has_value(), "RenameReplaceFault: source inode should exist before replacement");
    ok &= Require(target_before.has_value(), "RenameReplaceFault: target inode should exist before replacement");
    if (!source_before.has_value() || !target_before.has_value())
    {
        return false;
    }

    apfsaccess::rw::MetadataStore::MutationRequest rename_replace{};
    rename_replace.operation = apfsaccess::rw::MetadataStore::MutationOperation::Rename;
    rename_replace.path = L"\\docs\\source.txt";
    rename_replace.secondary_path = L"\\docs\\target.txt";
    rename_replace.replace_if_exists = true;
    ok &= ExpectMutationStatus(
        store,
        rename_replace,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "RenameReplaceFault: replacement rename mutation should apply");
    staged_payloads[L"\\docs\\target.txt"] = source_payload;

    store.SetCommitStageHook([](std::string_view stage)
    {
        return stage != "before-state-persist";
    });
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
        "RenameReplaceFault: commit should fail before-state-persist");
    store.SetCommitStageHook({});

    ok &= Require(
        store.LastCommittedXid().value_or(0) == (kInitialCheckpointXid + 1),
        "RenameReplaceFault: failed persist should not advance xid");
    ok &= Require(
        store.LookupCommittedInodeByPath(L"\\docs\\source.txt").has_value(),
        "RenameReplaceFault: source path should remain visible after rollback");
    const auto target_after_failure = store.LookupCommittedInodeByPath(L"\\docs\\target.txt");
    ok &= Require(target_after_failure.has_value(), "RenameReplaceFault: target should remain visible after rollback");
    if (target_after_failure.has_value())
    {
        ok &= Require(
            target_after_failure->object_id == target_before->object_id,
            "RenameReplaceFault: target object should not change on before-state-persist rollback");
        ok &= Require(
            target_after_failure->logical_size == target_before->logical_size,
            "RenameReplaceFault: target size should be unchanged on rollback");
    }

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "RenameReplaceFault: retry commit should succeed after rollback");
    ok &= Require(
        store.LastCommittedXid().value_or(0) == (kInitialCheckpointXid + 2),
        "RenameReplaceFault: retry commit should advance xid");
    ok &= Require(
        !store.LookupCommittedInodeByPath(L"\\docs\\source.txt").has_value(),
        "RenameReplaceFault: source path should be gone after replacement success");

    const auto target_after_success = store.LookupCommittedInodeByPath(L"\\docs\\target.txt");
    ok &= Require(target_after_success.has_value(), "RenameReplaceFault: target should exist after replacement success");
    if (target_after_success.has_value())
    {
        ok &= Require(
            target_after_success->object_id == source_before->object_id,
            "RenameReplaceFault: target path should adopt source object after replacement");
        ok &= Require(
            target_after_success->logical_size == static_cast<std::uint64_t>(source_payload.size()),
            "RenameReplaceFault: target size should match source payload after replacement");
    }

    return ok;
}

bool TestTruncateCheckpointWriteRecovery(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "truncate_checkpoint_fault.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "TruncateCheckpointFault: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"TruncateCheckpointFault",
    };
    bool ok = true;
    {
        apfsaccess::rw::MetadataStore store(context);
        ok &= Require(store.LoadContainerSuperblocks(), "TruncateCheckpointFault: LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "TruncateCheckpointFault: LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "TruncateCheckpointFault: LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "TruncateCheckpointFault: PrepareNativeWritePath should succeed");

        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        ConfigurePayloadProvider(store, staged_payloads);

        apfsaccess::rw::MetadataStore::MutationRequest create_file{};
        create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_file.path = L"\\truncate.bin";
        ok &= ExpectMutationStatus(
            store,
            create_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "TruncateCheckpointFault: create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\truncate.bin";
        write_file.length = 2048;
        ok &= ExpectMutationStatus(
            store,
            write_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "TruncateCheckpointFault: write file should apply");
        staged_payloads[L"\\truncate.bin"] = BuildPatternPayload(2048, 0x44);

        ok &= ExpectCommitStatus(
            store,
            apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "TruncateCheckpointFault: baseline commit should succeed");
        ok &= Require(
            store.LastCommittedXid().value_or(0) == (kInitialCheckpointXid + 1),
            "TruncateCheckpointFault: baseline commit should advance xid");

        apfsaccess::rw::MetadataStore::MutationRequest truncate{};
        truncate.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetFileSize;
        truncate.path = L"\\truncate.bin";
        truncate.length = 0;
        ok &= ExpectMutationStatus(
            store,
            truncate,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "TruncateCheckpointFault: truncate mutation should apply");

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-checkpoint-write";
        });
        ok &= ExpectCommitStatus(
            store,
            apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "TruncateCheckpointFault: commit should fail before-checkpoint-write");
        store.SetCommitStageHook({});

        ok &= Require(
            store.LastCommittedXid().value_or(0) == (kInitialCheckpointXid + 2),
            "TruncateCheckpointFault: promoted xid should remain visible after checkpoint-write fault");
        const auto truncated_inode = store.LookupCommittedInodeByPath(L"\\truncate.bin");
        ok &= Require(
            truncated_inode.has_value(),
            "TruncateCheckpointFault: truncated inode should remain visible after checkpoint-write fault");
        if (truncated_inode.has_value())
        {
            ok &= Require(
                truncated_inode->logical_size == 0,
                "TruncateCheckpointFault: truncate result should persist in in-memory committed state");
            ok &= Require(
                truncated_inode->data_physical_address == 0,
                "TruncateCheckpointFault: truncate should clear data extent in committed state");
        }
        ok &= Require(
            store.IsRecoveryRequired(),
            "TruncateCheckpointFault: checkpoint-write fault should latch recovery-required state");
        ok &= Require(
            !store.IsCommitPathReady(),
            "TruncateCheckpointFault: checkpoint-write fault should block commit path");
        ok &= Require(
            store.RecoveryReason() == L"CommitCheckpointWriteFailed",
            "TruncateCheckpointFault: checkpoint-write fault should set recovery reason");
        ok &= Require(
            store.LastCanonicalGateFailure() == L"CommitCheckpointWriteFailed",
            "TruncateCheckpointFault: canonical gate failure should expose checkpoint-write reason");
        ok &= Require(
            store.PendingMutationCount() > 0,
            "TruncateCheckpointFault: checkpoint-write fault should keep pending mutations");

        ok &= ExpectCommitStatus(
            store,
            apfsaccess::rw::MetadataStore::CommitStatus::NotWritable,
            "TruncateCheckpointFault: retry should fail closed while recovery is latched");
    }

    {
        apfsaccess::rw::MetadataStore remounted(context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "TruncateCheckpointFault: remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "TruncateCheckpointFault: remount PrepareNativeWritePath should succeed");
        ok &= Require(
            remounted.IsRecoveryRequired(),
            "TruncateCheckpointFault: remount should detect recovery-required state");
        ok &= Require(
            !remounted.IsCommitPathReady(),
            "TruncateCheckpointFault: remount commit path should remain blocked");
        ok &= Require(
            remounted.RecoveryReason() == L"PersistentStateAheadOfSuperblock",
            "TruncateCheckpointFault: remount recovery reason should indicate state ahead of superblock");
        ok &= Require(
            remounted.LastCanonicalGateFailure() == L"PersistentStateAheadOfSuperblock",
            "TruncateCheckpointFault: remount canonical gate failure should preserve persisted recovery reason");
        ok &= Require(
            remounted.LastCommittedXid().value_or(0) == (kInitialCheckpointXid + 2),
            "TruncateCheckpointFault: remount should preserve promoted xid");
    }

    return ok;
}

bool TestDeleteDirectoryRollbackOnDeviceWriteFault(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "delete_directory_fault.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "DeleteDirectoryFault: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"DeleteDirectoryFault",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "DeleteDirectoryFault: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "DeleteDirectoryFault: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "DeleteDirectoryFault: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "DeleteDirectoryFault: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    apfsaccess::rw::MetadataStore::MutationRequest create_tree{};
    create_tree.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateDirectory;
    create_tree.path = L"\\tree";
    ok &= ExpectMutationStatus(
        store,
        create_tree,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "DeleteDirectoryFault: create tree should apply");

    apfsaccess::rw::MetadataStore::MutationRequest create_leaf{};
    create_leaf.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_leaf.path = L"\\tree\\leaf.bin";
    ok &= ExpectMutationStatus(
        store,
        create_leaf,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "DeleteDirectoryFault: create leaf should apply");

    apfsaccess::rw::MetadataStore::MutationRequest write_leaf{};
    write_leaf.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_leaf.path = L"\\tree\\leaf.bin";
    write_leaf.length = 512;
    ok &= ExpectMutationStatus(
        store,
        write_leaf,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "DeleteDirectoryFault: write leaf should apply");
    staged_payloads[L"\\tree\\leaf.bin"] = BuildPatternPayload(512, 0x73);

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "DeleteDirectoryFault: baseline commit should succeed");
    ok &= Require(
        store.LastCommittedXid().value_or(0) == (kInitialCheckpointXid + 1),
        "DeleteDirectoryFault: baseline commit should advance xid");

    apfsaccess::rw::MetadataStore::MutationRequest delete_tree{};
    delete_tree.operation = apfsaccess::rw::MetadataStore::MutationOperation::Delete;
    delete_tree.path = L"\\tree";
    ok &= ExpectMutationStatus(
        store,
        delete_tree,
        apfsaccess::rw::MetadataStore::MutationStatus::InvalidRequest,
        "DeleteDirectoryFault: deleting non-empty tree should fail");

    apfsaccess::rw::MetadataStore::MutationRequest delete_leaf{};
    delete_leaf.operation = apfsaccess::rw::MetadataStore::MutationOperation::Delete;
    delete_leaf.path = L"\\tree\\leaf.bin";
    ok &= ExpectMutationStatus(
        store,
        delete_leaf,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "DeleteDirectoryFault: deleting leaf should apply");

    ok &= ExpectMutationStatus(
        store,
        delete_tree,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "DeleteDirectoryFault: deleting now-empty tree should apply");

    store.SetCommitStageHook([](std::string_view stage)
    {
        return stage != "before-device-write";
    });
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
        "DeleteDirectoryFault: commit should fail before-device-write");
    store.SetCommitStageHook({});

    ok &= Require(
        store.LastCommittedXid().value_or(0) == (kInitialCheckpointXid + 1),
        "DeleteDirectoryFault: before-device-write failure should not advance xid");
    ok &= Require(
        store.LookupCommittedInodeByPath(L"\\tree").has_value(),
        "DeleteDirectoryFault: tree should remain after rollback");
    ok &= Require(
        store.LookupCommittedInodeByPath(L"\\tree\\leaf.bin").has_value(),
        "DeleteDirectoryFault: leaf should remain after rollback");

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "DeleteDirectoryFault: retry commit should succeed");
    ok &= Require(
        store.LastCommittedXid().value_or(0) == (kInitialCheckpointXid + 2),
        "DeleteDirectoryFault: retry commit should advance xid");
    ok &= Require(
        !store.LookupCommittedInodeByPath(L"\\tree").has_value(),
        "DeleteDirectoryFault: tree should be removed after successful retry");
    ok &= Require(
        !store.LookupCommittedInodeByPath(L"\\tree\\leaf.bin").has_value(),
        "DeleteDirectoryFault: leaf should be removed after successful retry");

    return ok;
}

bool TestOversizedWriteMutationIsAtomic(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "oversized_write_atomic.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "OversizedWriteAtomic: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"OversizedWriteAtomic",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "OversizedWriteAtomic: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "OversizedWriteAtomic: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "OversizedWriteAtomic: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "OversizedWriteAtomic: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    apfsaccess::rw::MetadataStore::MutationRequest create_baseline{};
    create_baseline.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_baseline.path = L"\\baseline.bin";
    ok &= ExpectMutationStatus(
        store,
        create_baseline,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "OversizedWriteAtomic: create baseline file should apply");

    apfsaccess::rw::MetadataStore::MutationRequest write_baseline{};
    write_baseline.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_baseline.path = L"\\baseline.bin";
    write_baseline.length = 1024;
    ok &= ExpectMutationStatus(
        store,
        write_baseline,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "OversizedWriteAtomic: write baseline file should apply");
    staged_payloads[L"\\baseline.bin"] = BuildPatternPayload(1024, 0x48);

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "OversizedWriteAtomic: baseline commit should succeed");
    ok &= Require(
        store.LastCommittedXid().value_or(0) == (kInitialCheckpointXid + 1),
        "OversizedWriteAtomic: baseline commit should advance xid");

    apfsaccess::rw::MetadataStore::MutationRequest create_pending{};
    create_pending.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_pending.path = L"\\pending.bin";
    ok &= ExpectMutationStatus(
        store,
        create_pending,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "OversizedWriteAtomic: create pending file should apply");

    const auto pending_mutations_before = store.PendingMutationCount();
    const auto pending_omap_before = store.PendingObjectMapUpdateCount();
    const auto pending_alloc_before = store.PendingAllocationCount();
    const auto pending_dealloc_before = store.PendingDeallocationCount();
    const auto pending_btree_before = store.PendingBtreeRecordCount();

    apfsaccess::rw::MetadataStore::MutationRequest oversized_write{};
    oversized_write.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    oversized_write.path = L"\\pending.bin";
    oversized_write.length = static_cast<std::uint64_t>(kContainerBytes) + (2ull * static_cast<std::uint64_t>(kBlockSize));
    ok &= ExpectMutationStatus(
        store,
        oversized_write,
        apfsaccess::rw::MetadataStore::MutationStatus::AllocationFailed,
        "OversizedWriteAtomic: oversized write should fail with allocation failure");

    ok &= Require(
        store.PendingMutationCount() == pending_mutations_before &&
            store.PendingObjectMapUpdateCount() == pending_omap_before &&
            store.PendingAllocationCount() == pending_alloc_before &&
            store.PendingDeallocationCount() == pending_dealloc_before &&
            store.PendingBtreeRecordCount() == pending_btree_before,
        "OversizedWriteAtomic: failed oversized write should not mutate pending state");

    const auto pending_mutations_before_overflow = store.PendingMutationCount();
    const auto pending_omap_before_overflow = store.PendingObjectMapUpdateCount();
    const auto pending_alloc_before_overflow = store.PendingAllocationCount();
    const auto pending_dealloc_before_overflow = store.PendingDeallocationCount();
    const auto pending_btree_before_overflow = store.PendingBtreeRecordCount();

    apfsaccess::rw::MetadataStore::MutationRequest overflow_write{};
    overflow_write.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    overflow_write.path = L"\\pending.bin";
    overflow_write.offset = (std::numeric_limits<std::uint64_t>::max() - 2048ull);
    overflow_write.length = 4096;
    ok &= ExpectMutationStatus(
        store,
        overflow_write,
        apfsaccess::rw::MetadataStore::MutationStatus::InvalidRequest,
        "OversizedWriteAtomic: overflowed write should fail with invalid request");

    ok &= Require(
        store.PendingMutationCount() == pending_mutations_before_overflow &&
            store.PendingObjectMapUpdateCount() == pending_omap_before_overflow &&
            store.PendingAllocationCount() == pending_alloc_before_overflow &&
            store.PendingDeallocationCount() == pending_dealloc_before_overflow &&
            store.PendingBtreeRecordCount() == pending_btree_before_overflow,
        "OversizedWriteAtomic: failed overflowed write should not mutate pending state");

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "OversizedWriteAtomic: commit after oversized-write failure should still succeed for prior staged mutation");
    ok &= Require(
        store.LastCommittedXid().value_or(0) == (kInitialCheckpointXid + 2),
        "OversizedWriteAtomic: commit should advance xid after applying prior staged mutation");

    const auto pending_inode = store.LookupCommittedInodeByPath(L"\\pending.bin");
    ok &= Require(
        pending_inode.has_value(),
        "OversizedWriteAtomic: pending file should exist after commit");
    if (pending_inode.has_value())
    {
        ok &= Require(
            !pending_inode->is_directory,
            "OversizedWriteAtomic: pending inode should be a file");
        ok &= Require(
            pending_inode->logical_size == 0 && pending_inode->data_physical_address == 0,
            "OversizedWriteAtomic: failed oversized write should not persist file extent payload");
    }

    return ok;
}

bool TestCheckpointFlushFailureRemountSync(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "checkpoint_flush_sync.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "CheckpointFlushSync: unable to create synthetic container");
    }

    constexpr std::uint64_t kCheckpointXidOffset = 0x10;
    constexpr std::uint64_t kSecondaryCheckpointXidOffset =
        static_cast<std::uint64_t>(kBlockSize) + kCheckpointXidOffset;

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"CheckpointFlushSync",
    };
    context.crash_replay_mode = L"ReplayIfSafe";

    bool ok = true;
    {
        apfsaccess::rw::MetadataStore store(context);
        ok &= Require(store.LoadContainerSuperblocks(), "CheckpointFlushSync: LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "CheckpointFlushSync: LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "CheckpointFlushSync: LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "CheckpointFlushSync: PrepareNativeWritePath should succeed");

        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        ConfigurePayloadProvider(store, staged_payloads);

        apfsaccess::rw::MetadataStore::MutationRequest create_file{};
        create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_file.path = L"\\sync.bin";
        ok &= ExpectMutationStatus(
            store,
            create_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "CheckpointFlushSync: create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\sync.bin";
        write_file.length = 1024;
        ok &= ExpectMutationStatus(
            store,
            write_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "CheckpointFlushSync: write file should apply");
        staged_payloads[L"\\sync.bin"] = BuildPatternPayload(1024, 0x2E);

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-checkpoint-flush";
        });
        ok &= ExpectCommitStatus(
            store,
            apfsaccess::rw::MetadataStore::CommitStatus::FlushFailed,
            "CheckpointFlushSync: commit should fail before-checkpoint-flush");
        store.SetCommitStageHook({});

        ok &= Require(
            store.IsRecoveryRequired(),
            "CheckpointFlushSync: in-session state should require recovery after flush-stage interruption");
        ok &= Require(
            !store.IsCommitPathReady(),
            "CheckpointFlushSync: in-session commit path should be blocked after flush-stage interruption");
        ok &= Require(
            store.RecoveryReason() == L"CommitInterruptedBeforeCheckpointFlush",
            "CheckpointFlushSync: in-session recovery reason should match flush-stage interruption");
        ok &= Require(
            store.LastCommittedXid().value_or(0) == (kInitialCheckpointXid + 1),
            "CheckpointFlushSync: promoted xid should be retained after flush-stage interruption");
    }

    const auto primary_after_failure = ReadLe64FromImage(image_path, kCheckpointXidOffset);
    const auto secondary_after_failure = ReadLe64FromImage(image_path, kSecondaryCheckpointXidOffset);
    ok &= Require(
        primary_after_failure.has_value() && secondary_after_failure.has_value(),
        "CheckpointFlushSync: checkpoint xids should be readable after flush-stage interruption");
    if (primary_after_failure.has_value() && secondary_after_failure.has_value())
    {
        ok &= Require(
            std::max(primary_after_failure.value(), secondary_after_failure.value()) == (kInitialCheckpointXid + 1),
            "CheckpointFlushSync: one checkpoint slot should already expose promoted xid despite flush-stage interruption");
    }

    {
        apfsaccess::rw::MetadataStore remounted(context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "CheckpointFlushSync: remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "CheckpointFlushSync: remount PrepareNativeWritePath should succeed");
        ok &= Require(
            !remounted.IsRecoveryRequired(),
            "CheckpointFlushSync: remount should not remain recovery-required when persistent state matches superblock xid");
        ok &= Require(
            remounted.IsCommitPathReady(),
            "CheckpointFlushSync: remount commit path should be ready when no recovery is required");
        ok &= Require(
            remounted.ReplayOrRecover(),
            "CheckpointFlushSync: ReplayOrRecover should succeed on synchronized remount");
        ok &= Require(
            !remounted.IsRecoveryRequired() && remounted.IsCommitPathReady(),
            "CheckpointFlushSync: ReplayOrRecover should keep remount writable and non-recovery");
        const auto inode_after_remount = remounted.LookupCommittedInodeByPath(L"\\sync.bin");
        ok &= Require(
            inode_after_remount.has_value(),
            "CheckpointFlushSync: committed file should remain visible after synchronized remount");
        if (inode_after_remount.has_value())
        {
            ok &= Require(
                inode_after_remount->logical_size == 1024,
                "CheckpointFlushSync: committed file size should remain intact after synchronized remount");
        }
    }

    return ok;
}

bool TestCanonicalCheckpointRequiredWhenLegacyFixtureFallbackDisabled(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "canonical_checkpoint_required.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "CanonicalCheckpointRequired: unable to create synthetic container");
    }

    bool ok = true;

    apfsaccess::rw::MetadataStore::VolumeContext strict_context
    {
        image_path.wstring(),
        L"CanonicalCheckpointRequiredStrict",
    };
    strict_context.allow_legacy_scaffold_for_fixtures = false;

    {
        apfsaccess::rw::MetadataStore store(strict_context);
        ok &= Require(store.LoadContainerSuperblocks(), "CanonicalCheckpointRequired: strict LoadContainerSuperblocks should succeed");
        ok &= Require(!store.LoadObjectMap(), "CanonicalCheckpointRequired: strict LoadObjectMap should fail without canonical checkpoint");
        ok &= Require(store.IsRecoveryRequired(), "CanonicalCheckpointRequired: strict LoadObjectMap failure should require recovery");
        ok &= Require(
            store.RecoveryReason() == L"CanonicalObjectMapCheckpointMissing",
            "CanonicalCheckpointRequired: strict LoadObjectMap failure should report canonical object-map checkpoint missing");
    }

    {
        apfsaccess::rw::MetadataStore store(strict_context);
        ok &= Require(store.LoadContainerSuperblocks(), "CanonicalCheckpointRequired: strict-spaceman LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadSpacemanState(), "CanonicalCheckpointRequired: strict LoadSpacemanState should still load canonical spaceman metadata");
        ok &= Require(
            !store.IsRecoveryRequired(),
            "CanonicalCheckpointRequired: strict LoadSpacemanState should not force recovery when canonical spaceman metadata is available");
    }

    apfsaccess::rw::MetadataStore::VolumeContext fixture_context
    {
        image_path.wstring(),
        L"CanonicalCheckpointRequiredFixtureFallback",
    };
    fixture_context.allow_legacy_scaffold_for_fixtures = true;

    {
        apfsaccess::rw::MetadataStore store(fixture_context);
        ok &= Require(store.LoadContainerSuperblocks(), "CanonicalCheckpointRequired: fixture LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "CanonicalCheckpointRequired: fixture LoadObjectMap should allow legacy fallback");
        ok &= Require(store.LoadSpacemanState(), "CanonicalCheckpointRequired: fixture LoadSpacemanState should allow legacy fallback");
    }

    const auto non_fixture_path = run_root / "canonical_nonfixture_checkpoint_required.bin";
    if (!CreateSyntheticContainer(non_fixture_path))
    {
        return Require(false, "CanonicalCheckpointRequired: unable to create non-fixture synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext non_fixture_context
    {
        non_fixture_path.wstring(),
        L"CanonicalCheckpointRequiredNonFixture",
    };
    non_fixture_context.allow_legacy_scaffold_for_fixtures = true;

    {
        apfsaccess::rw::MetadataStore store(non_fixture_context);
        ok &= Require(store.LoadContainerSuperblocks(), "CanonicalCheckpointRequired: non-fixture LoadContainerSuperblocks should succeed");
        ok &= Require(!store.LoadObjectMap(), "CanonicalCheckpointRequired: non-fixture LoadObjectMap should reject legacy fallback");
        ok &= Require(store.IsRecoveryRequired(), "CanonicalCheckpointRequired: non-fixture LoadObjectMap failure should require recovery");
        ok &= Require(
            store.RecoveryReason() == L"CanonicalObjectMapCheckpointMissing",
            "CanonicalCheckpointRequired: non-fixture LoadObjectMap failure should report canonical object-map checkpoint missing");
    }

    const auto non_fixture_token_path = run_root / "canonical_nonfixture_token_checkpoint_required.bin";
    if (!CreateSyntheticContainer(non_fixture_token_path))
    {
        return Require(false, "CanonicalCheckpointRequired: unable to create non-fixture-token synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext non_fixture_token_context
    {
        non_fixture_token_path.wstring(),
        L"CanonicalCheckpointRequiredNonFixtureToken",
    };
    non_fixture_token_context.allow_legacy_scaffold_for_fixtures = true;

    {
        apfsaccess::rw::MetadataStore store(non_fixture_token_context);
        ok &= Require(store.LoadContainerSuperblocks(), "CanonicalCheckpointRequired: non-fixture-token LoadContainerSuperblocks should succeed");
        ok &= Require(!store.LoadObjectMap(), "CanonicalCheckpointRequired: non-fixture-token LoadObjectMap should reject legacy fallback");
        ok &= Require(store.IsRecoveryRequired(), "CanonicalCheckpointRequired: non-fixture-token LoadObjectMap failure should require recovery");
        ok &= Require(
            store.RecoveryReason() == L"CanonicalObjectMapCheckpointMissing",
            "CanonicalCheckpointRequired: non-fixture-token LoadObjectMap failure should report canonical object-map checkpoint missing");
    }

    const auto non_fixture_segment_path = run_root / "fixtures" / "canonical_nonfixture_segment_checkpoint_required.bin";
    std::error_code segment_dir_error;
    std::filesystem::create_directories(non_fixture_segment_path.parent_path(), segment_dir_error);
    if (segment_dir_error)
    {
        return Require(false, "CanonicalCheckpointRequired: unable to create non-fixture-segment directory");
    }
    if (!CreateSyntheticContainer(non_fixture_segment_path))
    {
        return Require(false, "CanonicalCheckpointRequired: unable to create non-fixture-segment synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext non_fixture_segment_context
    {
        non_fixture_segment_path.wstring(),
        L"CanonicalCheckpointRequiredNonFixtureSegment",
    };
    non_fixture_segment_context.allow_legacy_scaffold_for_fixtures = true;

    {
        apfsaccess::rw::MetadataStore store(non_fixture_segment_context);
        ok &= Require(store.LoadContainerSuperblocks(), "CanonicalCheckpointRequired: non-fixture-segment LoadContainerSuperblocks should succeed");
        ok &= Require(!store.LoadObjectMap(), "CanonicalCheckpointRequired: non-fixture-segment LoadObjectMap should reject legacy fallback from parent-directory naming");
        ok &= Require(store.IsRecoveryRequired(), "CanonicalCheckpointRequired: non-fixture-segment LoadObjectMap failure should require recovery");
        ok &= Require(
            store.RecoveryReason() == L"CanonicalObjectMapCheckpointMissing",
            "CanonicalCheckpointRequired: non-fixture-segment LoadObjectMap failure should report canonical object-map checkpoint missing");
    }

    return ok;
}

bool TestNonFixtureBootstrapTelemetryDefaults(const std::filesystem::path& run_root)
{
    const auto non_fixture_path = run_root / "bootstrap_commit_mode_defaults.bin";
    if (!CreateSyntheticContainer(non_fixture_path))
    {
        return Require(false, "NonFixtureBootstrapTelemetry: unable to create synthetic non-fixture container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        non_fixture_path.wstring(),
        L"NonFixtureBootstrapTelemetry",
    };
    context.allow_legacy_scaffold_for_fixtures = true;

    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(
        !store.UsesScaffoldCommitBlob(),
        "NonFixtureBootstrapTelemetry: non-fixture constructor state should not report scaffold commit-blob mode");
    ok &= Require(
        store.ActiveCommitModel() == apfsaccess::rw::MetadataStore::NativeWriteCommitModel::CanonicalApfsCheckpoint,
        "NonFixtureBootstrapTelemetry: non-fixture constructor state should report canonical commit model independent of readiness");
    ok &= Require(
        !store.IsFixtureCompatibilityPathActive(),
        "NonFixtureBootstrapTelemetry: non-fixture constructor state should not report fixture compatibility path activity");
    ok &= Require(
        store.LastCommitBlobMagic() == "APFSRWCANON3",
        "NonFixtureBootstrapTelemetry: non-fixture constructor state should default commit-blob telemetry to canonical magic");
    return ok;
}

bool TestCommitBlobModeSeparationBetweenFixtureAndNonFixture(const std::filesystem::path& run_root)
{
    bool ok = true;

    // Scenario 1: non-fixture replay path must remain canonical and recover successfully.
    const auto canonical_fixture_seed_path = run_root / "canonical_commit_seed.apfs.img";
    if (!CreateSyntheticContainer(canonical_fixture_seed_path))
    {
        return Require(false, "CommitBlobModeSeparation: unable to create canonical fixture seed container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext canonical_fixture_context
    {
        canonical_fixture_seed_path.wstring(),
        L"CommitBlobModeCanonicalFixtureSeed",
    };
    canonical_fixture_context.allow_legacy_scaffold_for_fixtures = true;
    canonical_fixture_context.crash_replay_mode = L"ReplayIfSafe";

    {
        apfsaccess::rw::MetadataStore store(canonical_fixture_context);
        ok &= Require(store.LoadContainerSuperblocks(), "CommitBlobModeSeparation: canonical fixture seed LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "CommitBlobModeSeparation: canonical fixture seed LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "CommitBlobModeSeparation: canonical fixture seed LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "CommitBlobModeSeparation: canonical fixture seed PrepareNativeWritePath should succeed");
        ok &= Require(
            !store.IsCanonicalCommitReady(),
            "CommitBlobModeSeparation: fixture seed should not report canonical commit readiness");
        ok &= Require(
            store.ActiveCommitModel() == apfsaccess::rw::MetadataStore::NativeWriteCommitModel::ScaffoldCheckpoint,
            "CommitBlobModeSeparation: fixture seed should report scaffold commit model before canonical promotion");

        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        ConfigurePayloadProvider(store, staged_payloads);

        apfsaccess::rw::MetadataStore::MutationRequest create_file{};
        create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_file.path = L"\\canonical.bin";
        ok &= ExpectMutationStatus(
            store,
            create_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "CommitBlobModeSeparation: canonical fixture seed create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\canonical.bin";
        write_file.length = 1024;
        ok &= ExpectMutationStatus(
            store,
            write_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "CommitBlobModeSeparation: canonical fixture seed write file should apply");
        staged_payloads[L"\\canonical.bin"] = BuildPatternPayload(1024, 0x61);

        ok &= ExpectCommitStatus(
            store,
            apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "CommitBlobModeSeparation: canonical fixture seed baseline commit should succeed");
        ok &= Require(
            store.UsesScaffoldCommitBlob(),
            "CommitBlobModeSeparation: fixture seed commit should run in scaffold commit-blob mode");
    }

    {
        apfsaccess::rw::MetadataStore remounted_fixture(canonical_fixture_context);
        ok &= Require(
            remounted_fixture.LoadContainerSuperblocks(),
            "CommitBlobModeSeparation: canonical fixture remount LoadContainerSuperblocks should succeed");
        ok &= Require(
            remounted_fixture.LoadObjectMap(),
            "CommitBlobModeSeparation: canonical fixture remount LoadObjectMap should succeed");
        ok &= Require(
            remounted_fixture.LoadSpacemanState(),
            "CommitBlobModeSeparation: canonical fixture remount LoadSpacemanState should succeed");
        ok &= Require(
            remounted_fixture.PrepareNativeWritePath(),
            "CommitBlobModeSeparation: canonical fixture remount PrepareNativeWritePath should succeed");
        ok &= Require(
            !remounted_fixture.IsFixtureLegacyFallbackActive(),
            "CommitBlobModeSeparation: canonical fixture remount should clear legacy fallback once canonical checkpoints exist");
        ok &= Require(
            remounted_fixture.IsCanonicalCommitReady(),
            "CommitBlobModeSeparation: canonical fixture remount should become canonical commit-ready after checkpoint hydration");
        ok &= Require(
            !remounted_fixture.UsesScaffoldCommitBlob(),
            "CommitBlobModeSeparation: canonical fixture remount should no longer force scaffold commit blobs when fallback is inactive");

        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        ConfigurePayloadProvider(remounted_fixture, staged_payloads);
        staged_payloads[L"\\canonical.bin"] = BuildPatternPayload(2048, 0x67);

        apfsaccess::rw::MetadataStore::MutationRequest append_file{};
        append_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        append_file.path = L"\\canonical.bin";
        append_file.offset = 1024;
        append_file.length = 1024;
        ok &= ExpectMutationStatus(
            remounted_fixture,
            append_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "CommitBlobModeSeparation: canonical fixture remount append should apply");
        ok &= ExpectCommitStatus(
            remounted_fixture,
            apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "CommitBlobModeSeparation: canonical fixture remount canonical commit should succeed");
        ok &= Require(
            !remounted_fixture.UsesScaffoldCommitBlob(),
            "CommitBlobModeSeparation: canonical fixture remount commit should stay in canonical commit-blob mode");
    }

    const auto canonical_non_fixture_path = run_root / "canonical_commit_seed.bin";
    std::error_code ec;
    std::filesystem::copy_file(
        canonical_fixture_seed_path,
        canonical_non_fixture_path,
        std::filesystem::copy_options::overwrite_existing,
        ec);
    ok &= Require(
        !ec,
        "CommitBlobModeSeparation: unable to copy canonical seed image to non-fixture path");

    apfsaccess::rw::MetadataStore::VolumeContext canonical_non_fixture_context
    {
        canonical_non_fixture_path.wstring(),
        L"CommitBlobModeCanonicalNonFixture",
    };
    canonical_non_fixture_context.allow_legacy_scaffold_for_fixtures = true;
    canonical_non_fixture_context.crash_replay_mode = L"ReplayIfSafe";

    {
        apfsaccess::rw::MetadataStore store(canonical_non_fixture_context);
        ok &= Require(store.LoadContainerSuperblocks(), "CommitBlobModeSeparation: canonical non-fixture LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "CommitBlobModeSeparation: canonical non-fixture LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "CommitBlobModeSeparation: canonical non-fixture LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "CommitBlobModeSeparation: canonical non-fixture PrepareNativeWritePath should succeed");
        ok &= Require(
            store.IsCanonicalCommitReady(),
            "CommitBlobModeSeparation: canonical non-fixture should report canonical commit readiness");
        ok &= Require(
            !store.UsesScaffoldCommitBlob(),
            "CommitBlobModeSeparation: canonical non-fixture should not run in scaffold commit-blob mode");
        ok &= Require(
            store.LastCommitBlobMagic() == "APFSRWCANON3",
            "CommitBlobModeSeparation: canonical non-fixture should report canonical commit-blob magic before first commit");

        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        ConfigurePayloadProvider(store, staged_payloads);
        staged_payloads[L"\\canonical.bin"] = BuildPatternPayload(2048, 0x71);

        apfsaccess::rw::MetadataStore::MutationRequest append_file{};
        append_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        append_file.path = L"\\canonical.bin";
        append_file.offset = 1024;
        append_file.length = 1024;
        ok &= ExpectMutationStatus(
            store,
            append_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "CommitBlobModeSeparation: canonical non-fixture append should apply");
        ok &= ExpectCommitStatus(
            store,
            apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "CommitBlobModeSeparation: canonical non-fixture baseline canonical commit should succeed");
        ok &= Require(
            !store.UsesScaffoldCommitBlob(),
            "CommitBlobModeSeparation: canonical non-fixture baseline commit should remain non-scaffold mode");

        staged_payloads[L"\\canonical.bin"] = BuildPatternPayload(3072, 0x72);
        append_file.offset = 2048;
        append_file.length = 1024;
        ok &= ExpectMutationStatus(
            store,
            append_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "CommitBlobModeSeparation: canonical non-fixture second append should apply");

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-checkpoint-switch";
        });
        ok &= ExpectCommitStatus(
            store,
            apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "CommitBlobModeSeparation: canonical non-fixture commit should fail before checkpoint switch");
        store.SetCommitStageHook({});
        ok &= Require(
            store.IsRecoveryRequired(),
            "CommitBlobModeSeparation: canonical non-fixture interrupted commit should require recovery");
        ok &= Require(
            !store.UsesScaffoldCommitBlob(),
            "CommitBlobModeSeparation: canonical non-fixture interrupted commit should remain non-scaffold mode");
    }

    {
        apfsaccess::rw::MetadataStore remounted(canonical_non_fixture_context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "CommitBlobModeSeparation: canonical replay remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "CommitBlobModeSeparation: canonical replay remount PrepareNativeWritePath should succeed");
        ok &= Require(
            remounted.IsRecoveryRequired(),
            "CommitBlobModeSeparation: canonical replay remount should require recovery before replay");
        ok &= Require(
            remounted.RecoveryReason() == L"ReplayCheckpointPendingWindow",
            "CommitBlobModeSeparation: canonical replay remount should prioritize pending replay-checkpoint recovery reason");
        ok &= Require(
            !remounted.UsesScaffoldCommitBlob(),
            "CommitBlobModeSeparation: canonical replay remount should remain in non-scaffold mode before replay");
        const auto canonical_replay_ok = remounted.ReplayOrRecover();
        ok &= Require(
            canonical_replay_ok,
            "CommitBlobModeSeparation: canonical replay remount should replay successfully in canonical non-fixture mode");
        ok &= Require(
            !remounted.IsRecoveryRequired() && remounted.IsCommitPathReady(),
            "CommitBlobModeSeparation: canonical replay remount should clear recovery and restore commit-ready state");
    }

    // Scenario 2: scaffold commit blobs generated in fixture mode must be rejected on non-fixture replay.
    const auto scaffold_fixture_seed_path = run_root / "scaffold_commit_seed.apfs.img";
    if (!CreateSyntheticContainer(scaffold_fixture_seed_path))
    {
        return Require(false, "CommitBlobModeSeparation: unable to create scaffold fixture seed container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext scaffold_fixture_context
    {
        scaffold_fixture_seed_path.wstring(),
        L"CommitBlobModeScaffoldFixtureSeed",
    };
    scaffold_fixture_context.allow_legacy_scaffold_for_fixtures = true;
    scaffold_fixture_context.crash_replay_mode = L"ReplayIfSafe";

    {
        apfsaccess::rw::MetadataStore store(scaffold_fixture_context);
        ok &= Require(store.LoadContainerSuperblocks(), "CommitBlobModeSeparation: scaffold fixture seed LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "CommitBlobModeSeparation: scaffold fixture seed LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "CommitBlobModeSeparation: scaffold fixture seed LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "CommitBlobModeSeparation: scaffold fixture seed PrepareNativeWritePath should succeed");

        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        ConfigurePayloadProvider(store, staged_payloads);

        apfsaccess::rw::MetadataStore::MutationRequest create_file{};
        create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_file.path = L"\\scaffold.bin";
        ok &= ExpectMutationStatus(
            store,
            create_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "CommitBlobModeSeparation: scaffold fixture seed create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\scaffold.bin";
        write_file.length = 1024;
        ok &= ExpectMutationStatus(
            store,
            write_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "CommitBlobModeSeparation: scaffold fixture seed write file should apply");
        staged_payloads[L"\\scaffold.bin"] = BuildPatternPayload(1024, 0x41);

        ok &= ExpectCommitStatus(
            store,
            apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "CommitBlobModeSeparation: scaffold fixture seed baseline commit should succeed");
        ok &= Require(
            store.UsesScaffoldCommitBlob(),
            "CommitBlobModeSeparation: scaffold fixture seed baseline should use scaffold commit-blob mode");

        apfsaccess::rw::MetadataStore::MutationRequest append_file{};
        append_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        append_file.path = L"\\scaffold.bin";
        append_file.offset = 1024;
        append_file.length = 1024;
        ok &= ExpectMutationStatus(
            store,
            append_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "CommitBlobModeSeparation: scaffold fixture seed append should apply");
        staged_payloads[L"\\scaffold.bin"] = BuildPatternPayload(2048, 0x52);

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-checkpoint-switch";
        });
        ok &= ExpectCommitStatus(
            store,
            apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "CommitBlobModeSeparation: scaffold fixture seed interrupted commit should fail before checkpoint switch");
        store.SetCommitStageHook({});
        ok &= Require(
            store.IsRecoveryRequired(),
            "CommitBlobModeSeparation: scaffold fixture seed interrupted commit should require recovery");
        ok &= Require(
            store.UsesScaffoldCommitBlob(),
            "CommitBlobModeSeparation: scaffold fixture seed interrupted commit should remain scaffold mode");
    }

    const auto scaffold_non_fixture_path = run_root / "scaffold_commit_seed.bin";
    ec.clear();
    std::filesystem::copy_file(
        scaffold_fixture_seed_path,
        scaffold_non_fixture_path,
        std::filesystem::copy_options::overwrite_existing,
        ec);
    ok &= Require(
        !ec,
        "CommitBlobModeSeparation: unable to copy scaffold seed image to non-fixture path");

    apfsaccess::rw::MetadataStore::VolumeContext scaffold_non_fixture_context
    {
        scaffold_non_fixture_path.wstring(),
        L"CommitBlobModeScaffoldNonFixture",
    };
    scaffold_non_fixture_context.allow_legacy_scaffold_for_fixtures = true;
    scaffold_non_fixture_context.crash_replay_mode = L"ReplayIfSafe";

    {
        apfsaccess::rw::MetadataStore remounted(scaffold_non_fixture_context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "CommitBlobModeSeparation: scaffold replay remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "CommitBlobModeSeparation: scaffold replay remount PrepareNativeWritePath should succeed");
        ok &= Require(
            remounted.IsRecoveryRequired(),
            "CommitBlobModeSeparation: scaffold replay remount should require recovery before replay");
        ok &= Require(
            !remounted.UsesScaffoldCommitBlob(),
            "CommitBlobModeSeparation: non-fixture replay remount should not pre-authorize scaffold commit blobs");
        ok &= Require(
            !remounted.IsFixtureCompatibilityPathActive(),
            "CommitBlobModeSeparation: non-fixture replay remount should not report fixture-compatibility activity");
        const auto scaffold_replay_ok = remounted.ReplayOrRecover();
        ok &= Require(
            !scaffold_replay_ok,
            "CommitBlobModeSeparation: non-fixture replay remount should reject fixture scaffold commit blob");
        ok &= Require(
            remounted.IsRecoveryRequired() && !remounted.IsCommitPathReady(),
            "CommitBlobModeSeparation: scaffold replay rejection should remain fail-closed");
        ok &= Require(
            remounted.RecoveryReason() == L"ScaffoldCommitBlobActive" ||
            remounted.RecoveryReason() == L"ReplayCommitBlobInvalid" ||
            remounted.RecoveryReason() == L"ReplayMetadataStateMissing" ||
            remounted.RecoveryReason() == L"ReplayCanonicalCandidateMissing" ||
            remounted.RecoveryReason() == L"ReplayCheckpointNotPendingWindow",
            "CommitBlobModeSeparation: scaffold replay rejection should report replay commit-blob or replay-metadata rejection");
        if (remounted.RecoveryReason() == L"ScaffoldCommitBlobActive")
        {
            ok &= Require(
                remounted.UsesScaffoldCommitBlob(),
                "CommitBlobModeSeparation: scaffold replay rejection should surface observed scaffold replay blob telemetry");
            ok &= Require(
                remounted.LastCommitBlobMagic() == "APFSRWSCAFF2" ||
                remounted.LastCommitBlobMagic() == "APFSRWSCAFF3",
                "CommitBlobModeSeparation: scaffold replay rejection should publish scaffold commit-blob magic telemetry");
        }
        else
        {
            ok &= Require(
                !remounted.UsesScaffoldCommitBlob(),
                "CommitBlobModeSeparation: non-scaffold replay rejection reasons should not force scaffold telemetry");
        }
        ok &= Require(
            !remounted.IsFixtureCompatibilityPathActive(),
            "CommitBlobModeSeparation: scaffold replay rejection should not report fixture-compatibility activity on non-fixture media");
    }

    // Scenario 3: scaffold replay compatibility is fixture-only, even when non-fixture relax flags are disabled.
    auto relaxed_scaffold_non_fixture_context = scaffold_non_fixture_context;
    relaxed_scaffold_non_fixture_context.disallow_scaffold_commit_on_non_fixture = false;
    relaxed_scaffold_non_fixture_context.reject_scaffold_replay_blob_on_non_fixture = false;
    relaxed_scaffold_non_fixture_context.require_canonical_replay_candidate_on_non_fixture = false;

    {
        apfsaccess::rw::MetadataStore remounted(relaxed_scaffold_non_fixture_context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "CommitBlobModeSeparation: relaxed scaffold replay remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "CommitBlobModeSeparation: relaxed scaffold replay remount PrepareNativeWritePath should succeed");
        ok &= Require(
            remounted.IsRecoveryRequired(),
            "CommitBlobModeSeparation: relaxed scaffold replay remount should still detect recovery-required state before replay");
        const auto scaffold_replay_ok = remounted.ReplayOrRecover();
        ok &= Require(
            !scaffold_replay_ok,
            "CommitBlobModeSeparation: relaxed non-fixture replay should still reject fixture scaffold commit blob");
        ok &= Require(
            remounted.IsRecoveryRequired() && !remounted.IsCommitPathReady(),
            "CommitBlobModeSeparation: relaxed scaffold replay rejection should remain fail-closed");
        if (remounted.RecoveryReason() == L"ScaffoldCommitBlobActive")
        {
            ok &= Require(
                remounted.UsesScaffoldCommitBlob(),
                "CommitBlobModeSeparation: relaxed scaffold replay rejection should surface observed scaffold replay blob telemetry");
            ok &= Require(
                remounted.LastCommitBlobMagic() == "APFSRWSCAFF2" ||
                remounted.LastCommitBlobMagic() == "APFSRWSCAFF3",
                "CommitBlobModeSeparation: relaxed scaffold replay rejection should publish scaffold commit-blob magic telemetry");
        }
        else
        {
            ok &= Require(
                !remounted.UsesScaffoldCommitBlob(),
                "CommitBlobModeSeparation: relaxed non-scaffold replay rejection reasons should not force scaffold telemetry");
        }
        ok &= Require(
            !remounted.IsFixtureCompatibilityPathActive(),
            "CommitBlobModeSeparation: relaxed scaffold replay rejection should not report fixture-compatibility activity on non-fixture media");
    }

    // Scenario 4: canonical replay-candidate strict mode also rejects scaffold replay (defense in depth).
    const auto canonical_priority_non_fixture_path = run_root / "scaffold_commit_seed_canonical_priority.bin";
    ec.clear();
    std::filesystem::copy_file(
        scaffold_fixture_seed_path,
        canonical_priority_non_fixture_path,
        std::filesystem::copy_options::overwrite_existing,
        ec);
    ok &= Require(
        !ec,
        "CommitBlobModeSeparation: unable to copy scaffold seed image to canonical-priority non-fixture path");

    auto canonical_priority_non_fixture_context = relaxed_scaffold_non_fixture_context;
    canonical_priority_non_fixture_context.device_path = canonical_priority_non_fixture_path.wstring();
    canonical_priority_non_fixture_context.volume_name = L"CommitBlobModeScaffoldCanonicalPriority";
    canonical_priority_non_fixture_context.require_canonical_replay_candidate_on_non_fixture = true;
    {
        apfsaccess::rw::MetadataStore remounted(canonical_priority_non_fixture_context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "CommitBlobModeSeparation: canonical-priority remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "CommitBlobModeSeparation: canonical-priority remount PrepareNativeWritePath should succeed");
        ok &= Require(
            remounted.IsRecoveryRequired(),
            "CommitBlobModeSeparation: canonical-priority remount should detect recovery-required state before replay");
        const auto replay_ok = remounted.ReplayOrRecover();
        ok &= Require(
            !replay_ok,
            "CommitBlobModeSeparation: canonical-priority remount should reject scaffold replay despite relaxed scaffold toggles");
        ok &= Require(
            remounted.IsRecoveryRequired() && !remounted.IsCommitPathReady(),
            "CommitBlobModeSeparation: canonical-priority scaffold replay rejection should remain fail-closed");
        ok &= Require(
            remounted.RecoveryReason() == L"ScaffoldCommitBlobActive" ||
            remounted.RecoveryReason() == L"ReplayCommitBlobInvalid" ||
            remounted.RecoveryReason() == L"ReplayMetadataStateMissing" ||
            remounted.RecoveryReason() == L"ReplayCanonicalCandidateMissing" ||
            remounted.RecoveryReason() == L"ReplayCheckpointNotPendingWindow",
            "CommitBlobModeSeparation: canonical-priority scaffold replay rejection should report replay commit-blob or replay-metadata rejection");
    }

    return ok;
}

bool TestCanonicalNonFixtureStatePersistIsBestEffort(const std::filesystem::path& run_root)
{
    bool ok = true;
    std::error_code ec;

    const auto fixture_seed_path = run_root / "canonical_nonfixture_statepersist_seed.apfs.img";
    if (!CreateSyntheticContainer(fixture_seed_path))
    {
        return Require(false, "CanonicalNonFixtureStatePersistBestEffort: unable to create fixture seed container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext fixture_seed_context
    {
        fixture_seed_path.wstring(),
        L"CanonicalNonFixtureStatePersistFixtureSeed",
    };
    fixture_seed_context.allow_legacy_scaffold_for_fixtures = true;

    {
        apfsaccess::rw::MetadataStore store(fixture_seed_context);
        ok &= Require(store.LoadContainerSuperblocks(), "CanonicalNonFixtureStatePersistBestEffort: fixture seed LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "CanonicalNonFixtureStatePersistBestEffort: fixture seed LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "CanonicalNonFixtureStatePersistBestEffort: fixture seed LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "CanonicalNonFixtureStatePersistBestEffort: fixture seed PrepareNativeWritePath should succeed");

        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        ConfigurePayloadProvider(store, staged_payloads);

        apfsaccess::rw::MetadataStore::MutationRequest create_file{};
        create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_file.path = L"\\statepersist.bin";
        ok &= ExpectMutationStatus(
            store,
            create_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "CanonicalNonFixtureStatePersistBestEffort: fixture seed create should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\statepersist.bin";
        write_file.length = 1024;
        ok &= ExpectMutationStatus(
            store,
            write_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "CanonicalNonFixtureStatePersistBestEffort: fixture seed write should apply");
        staged_payloads[L"\\statepersist.bin"] = BuildPatternPayload(1024, 0x33);

        ok &= ExpectCommitStatus(
            store,
            apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "CanonicalNonFixtureStatePersistBestEffort: fixture seed baseline commit should succeed");
    }

    const auto non_fixture_path = run_root / "canonical_nonfixture_statepersist_seed.bin";
    ec.clear();
    std::filesystem::copy_file(
        fixture_seed_path,
        non_fixture_path,
        std::filesystem::copy_options::overwrite_existing,
        ec);
    ok &= Require(
        !ec,
        "CanonicalNonFixtureStatePersistBestEffort: unable to copy fixture seed image to non-fixture path");

    apfsaccess::rw::MetadataStore::VolumeContext non_fixture_context
    {
        non_fixture_path.wstring(),
        L"CanonicalNonFixtureStatePersistNonFixture",
    };
    non_fixture_context.allow_legacy_scaffold_for_fixtures = true;
    const auto non_fixture_sidecar_path =
        BuildPersistentStatePathForTest(non_fixture_context);
    if (!non_fixture_sidecar_path.empty())
    {
        std::error_code remove_ec;
        std::filesystem::remove(non_fixture_sidecar_path, remove_ec);
    }

    {
        apfsaccess::rw::MetadataStore store(non_fixture_context);
        ok &= Require(store.LoadContainerSuperblocks(), "CanonicalNonFixtureStatePersistBestEffort: non-fixture LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "CanonicalNonFixtureStatePersistBestEffort: non-fixture LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "CanonicalNonFixtureStatePersistBestEffort: non-fixture LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "CanonicalNonFixtureStatePersistBestEffort: non-fixture PrepareNativeWritePath should succeed");
        ok &= Require(
            store.IsCanonicalCommitReady(),
            "CanonicalNonFixtureStatePersistBestEffort: non-fixture path should be canonical commit-ready");
        ok &= Require(
            !store.UsesScaffoldCommitBlob(),
            "CanonicalNonFixtureStatePersistBestEffort: non-fixture path should not use scaffold commit blobs");

        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        ConfigurePayloadProvider(store, staged_payloads);
        staged_payloads[L"\\statepersist.bin"] = BuildPatternPayload(2048, 0x44);

        apfsaccess::rw::MetadataStore::MutationRequest append_file{};
        append_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        append_file.path = L"\\statepersist.bin";
        append_file.offset = 1024;
        append_file.length = 1024;
        ok &= ExpectMutationStatus(
            store,
            append_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "CanonicalNonFixtureStatePersistBestEffort: non-fixture append should apply");

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-state-persist";
        });
        const auto commit_status = store.CommitPendingMutations();
        store.SetCommitStageHook({});
        ok &= Require(
            commit_status == apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "CanonicalNonFixtureStatePersistBestEffort: non-fixture commit should stay committed when state persist stage is faulted");
        ok &= Require(
            store.LastCommittedXid().value_or(0) == (kInitialCheckpointXid + 2),
            "CanonicalNonFixtureStatePersistBestEffort: non-fixture commit should advance xid despite state-persist fault");
        ok &= Require(
            !store.IsRecoveryRequired() && store.IsCommitPathReady(),
            "CanonicalNonFixtureStatePersistBestEffort: non-fixture commit should remain recovery-clear and commit-ready");
        ok &= Require(
            !store.UsesScaffoldCommitBlob(),
            "CanonicalNonFixtureStatePersistBestEffort: non-fixture commit should remain canonical commit-blob mode");

        const auto inode = store.LookupCommittedInodeByPath(L"\\statepersist.bin");
        ok &= Require(inode.has_value(), "CanonicalNonFixtureStatePersistBestEffort: committed inode should exist after successful non-fixture commit");
        if (inode.has_value())
        {
            ok &= Require(
                inode->logical_size == 2048,
                "CanonicalNonFixtureStatePersistBestEffort: committed file size should reflect appended payload");
        }
    }

    if (!non_fixture_sidecar_path.empty())
    {
        std::error_code exists_ec;
        ok &= Require(
            !std::filesystem::exists(non_fixture_sidecar_path, exists_ec),
            "CanonicalNonFixtureStatePersistBestEffort: non-fixture commit should not persist sidecar state payload");
    }

    return ok;
}
} // namespace

int main()
{
    bool ok = true;
    std::error_code ec;
    const auto unique_id = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto run_root = std::filesystem::temp_directory_path(ec) / ("ApfsAccessRwConformanceFaultTests_" + std::to_string(unique_id));
    if (ec)
    {
        std::cerr << "[FAIL] unable to access temporary directory for conformance-fault tests" << std::endl;
        return 1;
    }

    std::filesystem::remove_all(run_root, ec);
    ec.clear();
    std::filesystem::create_directories(run_root, ec);
    if (ec)
    {
        std::cerr << "[FAIL] unable to create conformance-fault test directory" << std::endl;
        return 1;
    }

    ok &= TestRenameReplaceRollbackBeforePersist(run_root);
    ok &= TestTruncateCheckpointWriteRecovery(run_root);
    ok &= TestDeleteDirectoryRollbackOnDeviceWriteFault(run_root);
    ok &= TestOversizedWriteMutationIsAtomic(run_root);
    ok &= TestCheckpointFlushFailureRemountSync(run_root);
    ok &= TestNonFixtureBootstrapTelemetryDefaults(run_root);
    ok &= TestCommitBlobModeSeparationBetweenFixtureAndNonFixture(run_root);
    ok &= TestCanonicalNonFixtureStatePersistIsBestEffort(run_root);
    ok &= TestCanonicalCheckpointRequiredWhenLegacyFixtureFallbackDisabled(run_root);

    std::filesystem::remove_all(run_root, ec);
    if (!ok)
    {
        return 1;
    }

    std::cout << "[PASS] MetadataStoreConformanceFaultTests" << std::endl;
    return 0;
}
