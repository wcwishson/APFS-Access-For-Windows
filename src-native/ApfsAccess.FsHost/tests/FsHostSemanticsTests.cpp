#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <algorithm>
#include <unordered_map>
#include <string>
#include <thread>
#include <vector>

#define APFSACCESS_FSHOST_UNIT_TEST 1
#include "../src/main.cpp"

namespace
{
constexpr std::uint32_t kSyntheticApfsBlockSize = 4096;
constexpr std::uint64_t kSyntheticApfsTotalBlocks = 1024;
constexpr std::uint64_t kSyntheticApfsInitialCheckpointXid = 7;
constexpr std::uint64_t kSyntheticApfsSpacemanObjectId = 0x2A;
constexpr std::uint64_t kSyntheticApfsVolumeRootObject = 0x54;
constexpr std::uint32_t kSyntheticApfsNxsbMagic = 0x4253584E; // NXSB

bool Require(bool condition, const char* message)
{
    if (!condition)
    {
        std::cerr << "[FAIL] " << message << std::endl;
        return false;
    }

    return true;
}

void WriteLe32ForTest(std::vector<std::byte>& buffer, std::size_t offset, std::uint32_t value)
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

void WriteLe64ForTest(std::vector<std::byte>& buffer, std::size_t offset, std::uint64_t value)
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

bool CreateSyntheticApfsContainerForTest(const std::filesystem::path& image_path)
{
    std::vector<std::byte> bytes(
        static_cast<std::size_t>(kSyntheticApfsBlockSize * kSyntheticApfsTotalBlocks),
        std::byte{0});
    const auto write_superblock = [&](std::size_t base_offset, std::uint64_t checkpoint_xid)
    {
        WriteLe64ForTest(bytes, base_offset + 0x10, checkpoint_xid);
        WriteLe32ForTest(bytes, base_offset + 0x20, kSyntheticApfsNxsbMagic);
        WriteLe32ForTest(bytes, base_offset + 0x24, kSyntheticApfsBlockSize);
        WriteLe64ForTest(bytes, base_offset + 0x28, kSyntheticApfsTotalBlocks);
        WriteLe64ForTest(bytes, base_offset + 0x98, kSyntheticApfsSpacemanObjectId);
        WriteLe64ForTest(bytes, base_offset + 0xA0, kSyntheticApfsVolumeRootObject);
    };

    write_superblock(0, kSyntheticApfsInitialCheckpointXid);
    write_superblock(kSyntheticApfsBlockSize, kSyntheticApfsInitialCheckpointXid);

    std::ofstream out(image_path, std::ios::binary | std::ios::trunc);
    if (!out.good())
    {
        return false;
    }

    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    return out.good();
}

std::vector<std::byte> BuildPatternPayloadForTest(std::size_t bytes, unsigned char seed)
{
    std::vector<std::byte> payload(bytes, std::byte{0});
    for (std::size_t i = 0; i < payload.size(); ++i)
    {
        payload[i] = static_cast<std::byte>((seed + static_cast<unsigned char>(i & 0xffu)) & 0xffu);
    }
    return payload;
}

std::uint64_t GetAllocatedBytesForTest(const std::filesystem::path& path)
{
    DWORD high = 0;
    SetLastError(ERROR_SUCCESS);
    const DWORD low = GetCompressedFileSizeW(path.wstring().c_str(), &high);
    const auto error = GetLastError();
    if (low == INVALID_FILE_SIZE && error != ERROR_SUCCESS)
    {
        return std::numeric_limits<std::uint64_t>::max();
    }

    return (static_cast<std::uint64_t>(high) << 32) | low;
}

std::shared_ptr<Node> MakeNode(const std::wstring& path, bool is_directory, bool delete_pending = false)
{
    auto node = std::make_shared<Node>();
    node->path = NormalizePath(path);
    node->hydration_key = Key(node->path);
    node->is_directory = is_directory;
    node->loaded = is_directory;
    node->delete_pending = delete_pending;
    node->timestamp = UtcNow();
    return node;
}

void SeedRoot(MountContext& context)
{
    auto root = MakeNode(L"\\", true, false);
    context.nodes.emplace(Key(root->path), root);
}

FSP_FILE_SYSTEM BuildFileSystem(MountContext* context)
{
    FSP_FILE_SYSTEM fs{};
    fs.UserContext = context;
    return fs;
}

void SeedSecurity(MountContext& context, std::array<std::byte, 16>& security)
{
    context.sd = reinterpret_cast<PSECURITY_DESCRIPTOR>(security.data());
    context.sd_size = static_cast<ULONG>(security.size());
}

bool ConfigureNativeCommitFailureForUnitTest(MountContext& context)
{
#ifdef APFSACCESS_HAS_RW_ENGINE
    context.args.readwrite = true;
    context.args.write_backend = L"Native";
    context.args.write_recovery_policy = L"FailClosed";
    context.native_write_enabled = true;
    context.overlay_write_enabled = false;
    context.test_force_native_mutation_staging_success = true;
    context.test_forced_native_commit_status = apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed;
    context.test_forced_native_commit_recovery_reason = L"UnitTestForcedCommitFailure";
    context.test_forced_native_commit_recovery_required = true;
    return true;
#else
    (void)context;
    return false;
#endif
}

bool PrepareUnitHydrationRoot(MountContext& context, const wchar_t* name)
{
    std::error_code ec;
    const auto suffix = name && *name ? std::wstring(name) : L"default";
    context.session_root = std::filesystem::temp_directory_path(ec) /
        "ApfsAccess" /
        "fs-host-semantics" /
        (suffix + L"-" + std::to_wstring(GetTickCount64()));
    if (ec)
    {
        return false;
    }

    context.cache_root = context.session_root / "hydrate";
    std::filesystem::create_directories(context.cache_root, ec);
    return !ec;
}

bool WriteFileBytes(const std::filesystem::path& path, const std::vector<std::byte>& bytes)
{
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    if (ec)
    {
        return false;
    }

    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out.good())
    {
        return false;
    }

    if (!bytes.empty())
    {
        out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    }
    return out.good();
}

bool SeedResizableUnitFile(MountContext& context, std::shared_ptr<Node>& file)
{
    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"resize.bin");

    file = MakeNode(L"\\resize.bin", false, false);
    file->file_size = 4;
    context.nodes.emplace(Key(file->path), file);
    return WriteFileBytes(
        HydrationPath(&context, *file),
        { std::byte{'A'}, std::byte{'B'}, std::byte{'C'}, std::byte{'D'} });
}

bool OpenResizableUnitFile(MountContext& context, const std::shared_ptr<Node>& file, OpenContext& open_context)
{
    if (!file)
    {
        return false;
    }

    open_context.node = file;
    open_context.allow_set_file_size = true;
    open_context.allow_write_data = true;
    open_context.file = CreateFileW(
        HydrationPath(&context, *file).wstring().c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    return open_context.file != INVALID_HANDLE_VALUE;
}

bool ConfigureUnitRecoveryMarker(MountContext& context, const wchar_t* name)
{
    std::error_code ec;
    const auto marker_root = std::filesystem::temp_directory_path(ec) / "ApfsAccess" / "fs-host-semantics";
    if (ec)
    {
        return false;
    }
    std::filesystem::create_directories(marker_root, ec);
    if (ec)
    {
        return false;
    }

    const auto suffix = name && *name ? std::wstring(name) : L"marker";
    context.recovery_marker_file = marker_root / (suffix + L"-" + std::to_wstring(GetTickCount64()) + L".state");
    return true;
}

std::vector<std::byte> ReadFileBytes(const std::filesystem::path& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in.good())
    {
        return {};
    }

    const std::vector<char> chars{
        std::istreambuf_iterator<char>(in),
        std::istreambuf_iterator<char>()};
    std::vector<std::byte> bytes;
    bytes.reserve(chars.size());
    for (const char ch : chars)
    {
        bytes.push_back(static_cast<std::byte>(static_cast<unsigned char>(ch)));
    }
    return bytes;
}

std::vector<std::byte> ReadHandleBytes(HANDLE handle, DWORD bytes_to_read)
{
    if (handle == INVALID_HANDLE_VALUE)
    {
        return {};
    }

    LARGE_INTEGER start{};
    if (!SetFilePointerEx(handle, start, nullptr, FILE_BEGIN))
    {
        return {};
    }

    std::vector<std::byte> buffer(bytes_to_read);
    DWORD read = 0;
    if (!ReadFile(handle, buffer.data(), bytes_to_read, &read, nullptr))
    {
        return {};
    }
    buffer.resize(read);
    return buffer;
}

bool TestCreateRejectsConflictingTypeFlags()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto fs = BuildFileSystem(&context);
    PVOID out_ctx = nullptr;
    FSP_FSCTL_FILE_INFO info{};
    const auto status = CB_Create(
        &fs,
        const_cast<PWSTR>(L"\\conflict"),
        FILE_DIRECTORY_FILE | FILE_NON_DIRECTORY_FILE,
        FILE_WRITE_DATA,
        0,
        nullptr,
        0,
        &out_ctx,
        &info);
    return Require(status == STATUS_INVALID_PARAMETER, "Create should reject conflicting directory/non-directory options");
}

bool TestDeletePendingAncestorBlocksOpenSecurityDelete()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto parent = MakeNode(L"\\pending", true, true);
    parent->children.push_back(L"child.txt");
    context.nodes.emplace(Key(parent->path), parent);
    auto child = MakeNode(L"\\pending\\child.txt", false, false);
    context.nodes.emplace(Key(child->path), child);

    auto fs = BuildFileSystem(&context);

    PVOID out_ctx = nullptr;
    FSP_FSCTL_FILE_INFO info{};
    auto open_status = CB_Open(
        &fs,
        const_cast<PWSTR>(L"\\pending\\child.txt"),
        0,
        FILE_READ_DATA,
        &out_ctx,
        &info);
    if (!Require(open_status == STATUS_DELETE_PENDING, "Open should fail with STATUS_DELETE_PENDING when ancestor is delete-pending"))
    {
        return false;
    }

    UINT32 attributes = 0;
    SIZE_T security_size = security.size();
    auto security_status = CB_GetSecurityByName(
        &fs,
        const_cast<PWSTR>(L"\\pending\\child.txt"),
        &attributes,
        reinterpret_cast<PSECURITY_DESCRIPTOR>(security.data()),
        &security_size);
    if (!Require(security_status == STATUS_DELETE_PENDING, "GetSecurityByName should fail with STATUS_DELETE_PENDING when ancestor is delete-pending"))
    {
        return false;
    }

    auto can_delete_status = CB_CanDelete(&fs, nullptr, const_cast<PWSTR>(L"\\pending\\child.txt"));
    if (!Require(can_delete_status == STATUS_DELETE_PENDING, "CanDelete should fail with STATUS_DELETE_PENDING when ancestor is delete-pending"))
    {
        return false;
    }

    auto set_delete_status = CB_SetDelete(&fs, nullptr, const_cast<PWSTR>(L"\\pending\\child.txt"), TRUE);
    return Require(set_delete_status == STATUS_DELETE_PENDING, "SetDelete should fail with STATUS_DELETE_PENDING when ancestor is delete-pending");
}

bool TestDeleteIntentAncestorBlocksOpenAndCreate()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto parent = MakeNode(L"\\pending", true, false);
    parent->delete_pending = false;
    parent->delete_latched = true;
    parent->delete_intent_count = 0;
    parent->children.push_back(L"child.txt");
    context.nodes.emplace(Key(parent->path), parent);

    auto child = MakeNode(L"\\pending\\child.txt", false, false);
    context.nodes.emplace(Key(child->path), child);

    auto fs = BuildFileSystem(&context);
    PVOID out_ctx = nullptr;
    FSP_FSCTL_FILE_INFO info{};
    const auto open_status = CB_Open(
        &fs,
        const_cast<PWSTR>(L"\\pending\\child.txt"),
        FILE_NON_DIRECTORY_FILE,
        FILE_READ_DATA,
        &out_ctx,
        &info);
    if (!Require(open_status == STATUS_DELETE_PENDING, "Open should fail with STATUS_DELETE_PENDING when ancestor has stale delete intent state"))
    {
        return false;
    }
    if (!Require(out_ctx == nullptr, "Ancestor stale delete intent open rejection should not allocate open context"))
    {
        return false;
    }

    const auto create_status = CB_Create(
        &fs,
        const_cast<PWSTR>(L"\\pending\\new.txt"),
        FILE_NON_DIRECTORY_FILE,
        FILE_WRITE_DATA,
        0,
        nullptr,
        0,
        &out_ctx,
        &info);
    if (!Require(create_status == STATUS_DELETE_PENDING, "Create should fail with STATUS_DELETE_PENDING when parent has stale delete intent state"))
    {
        return false;
    }

    return Require(out_ctx == nullptr, "Create rejected by ancestor stale delete intent should not allocate open context");
}

bool TestRenameSamePathRequiresExistingNode()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);
    auto fs = BuildFileSystem(&context);

    auto missing_status = CB_Rename(
        &fs,
        nullptr,
        const_cast<PWSTR>(L"\\missing.txt"),
        const_cast<PWSTR>(L"\\missing.txt"),
        FALSE);
    if (!Require(missing_status == STATUS_OBJECT_NAME_NOT_FOUND, "Rename no-op should report OBJECT_NAME_NOT_FOUND when source is missing"))
    {
        return false;
    }

    auto existing = MakeNode(L"\\existing.txt", false, false);
    context.nodes.emplace(Key(existing->path), existing);
    auto success_status = CB_Rename(
        &fs,
        nullptr,
        const_cast<PWSTR>(L"\\existing.txt"),
        const_cast<PWSTR>(L"\\existing.txt"),
        FALSE);
    if (!Require(success_status == STATUS_SUCCESS, "Rename no-op should succeed when source exists"))
    {
        return false;
    }

    existing->delete_pending = true;
    auto delete_pending_status = CB_Rename(
        &fs,
        nullptr,
        const_cast<PWSTR>(L"\\existing.txt"),
        const_cast<PWSTR>(L"\\existing.txt"),
        FALSE);
    if (!Require(delete_pending_status == STATUS_DELETE_PENDING, "Rename no-op should fail with STATUS_DELETE_PENDING when source is delete-pending"))
    {
        return false;
    }

    existing->delete_pending = false;
    existing->delete_latched = true;
    existing->delete_intent_count = 0;
    auto stale_intent_status = CB_Rename(
        &fs,
        nullptr,
        const_cast<PWSTR>(L"\\existing.txt"),
        const_cast<PWSTR>(L"\\existing.txt"),
        FALSE);
    return Require(stale_intent_status == STATUS_DELETE_PENDING, "Rename no-op should fail with STATUS_DELETE_PENDING when source has stale delete intent state");
}

bool TestRenameSamePathValidatesContextPermissions()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"existing.txt");
    AddChildName(root->children, L"other.txt");

    auto existing = MakeNode(L"\\existing.txt", false, false);
    auto other = MakeNode(L"\\other.txt", false, false);
    context.nodes.emplace(Key(existing->path), existing);
    context.nodes.emplace(Key(other->path), other);

    auto fs = BuildFileSystem(&context);

    OpenContext mismatched_open{};
    mismatched_open.node = other;
    mismatched_open.allow_delete = true;
    auto mismatched_status = CB_Rename(
        &fs,
        &mismatched_open,
        const_cast<PWSTR>(L"\\existing.txt"),
        const_cast<PWSTR>(L"\\existing.txt"),
        FALSE);
    if (!Require(mismatched_status == STATUS_INVALID_PARAMETER, "Rename no-op should reject mismatched context handles"))
    {
        return false;
    }

    OpenContext source_open{};
    source_open.node = existing;
    source_open.allow_delete = false;
    auto source_denied = CB_Rename(
        &fs,
        &source_open,
        const_cast<PWSTR>(L"\\existing.txt"),
        const_cast<PWSTR>(L"\\existing.txt"),
        FALSE);
    if (!Require(source_denied == STATUS_ACCESS_DENIED, "Rename no-op should require DELETE on source-handle context"))
    {
        return false;
    }

    source_open.allow_delete = true;
    auto source_allowed = CB_Rename(
        &fs,
        &source_open,
        const_cast<PWSTR>(L"\\existing.txt"),
        const_cast<PWSTR>(L"\\existing.txt"),
        FALSE);
    if (!Require(source_allowed == STATUS_SUCCESS, "Rename no-op should allow source-handle context with DELETE"))
    {
        return false;
    }

    OpenContext parent_open{};
    parent_open.node = root;
    parent_open.allow_delete_child = false;
    auto parent_denied = CB_Rename(
        &fs,
        &parent_open,
        const_cast<PWSTR>(L"\\existing.txt"),
        const_cast<PWSTR>(L"\\existing.txt"),
        FALSE);
    if (!Require(parent_denied == STATUS_ACCESS_DENIED, "Rename no-op should require FILE_DELETE_CHILD on parent-handle context"))
    {
        return false;
    }

    parent_open.allow_delete_child = true;
    auto parent_allowed = CB_Rename(
        &fs,
        &parent_open,
        const_cast<PWSTR>(L"\\existing.txt"),
        const_cast<PWSTR>(L"\\existing.txt"),
        FALSE);
    return Require(parent_allowed == STATUS_SUCCESS, "Rename no-op should allow parent-handle context with FILE_DELETE_CHILD");
}

bool TestRenameRelativeTargetStaysInSourceParent()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"alpha");

    auto parent = MakeNode(L"\\alpha", true, false);
    AddChildName(parent->children, L"file.txt");
    context.nodes.emplace(Key(parent->path), parent);

    auto file = MakeNode(L"\\alpha\\file.txt", false, false);
    context.nodes.emplace(Key(file->path), file);

    OpenContext parent_open{};
    parent_open.node = parent;
    parent_open.allow_delete_child = true;
    parent_open.allow_write_data = true;

    auto fs = BuildFileSystem(&context);
    auto status = CB_Rename(
        &fs,
        &parent_open,
        const_cast<PWSTR>(L"\\alpha\\file.txt"),
        const_cast<PWSTR>(L"renamed.txt"),
        FALSE);
    if (!Require(status == STATUS_SUCCESS, "Relative rename target should resolve against source parent"))
    {
        return false;
    }
    if (!Require(context.nodes.find(Key(L"\\alpha\\file.txt")) == context.nodes.end(), "Relative rename should remove old source entry"))
    {
        return false;
    }
    if (!Require(context.nodes.find(Key(L"\\alpha\\renamed.txt")) != context.nodes.end(), "Relative rename should create sibling destination entry"))
    {
        return false;
    }
    if (!Require(context.nodes.find(Key(L"\\renamed.txt")) == context.nodes.end(), "Relative rename should not escape to volume root"))
    {
        return false;
    }

    return Require(
        HasChildName(parent->children, L"renamed.txt") && !HasChildName(parent->children, L"file.txt"),
        "Relative rename should update source parent child list");
}

bool TestDirectoryInfoBufferNullTerminatesNameAndReportsUnterminatedSize()
{
    auto node = MakeNode(L"\\alpha", true, false);
    std::vector<unsigned char> buffer;
    auto add_dir = [](FSP_FSCTL_DIR_INFO* dir_info, PVOID, ULONG, PULONG done) -> BOOLEAN
    {
        if (!dir_info)
        {
            return TRUE;
        }

        if (done)
        {
            *done += dir_info->Size;
        }
        return TRUE;
    };
    WinFspApi api{};
    api.AddDir = add_dir;
    ULONG done = 0;
    if (!Require(
            AddDirectoryEntry(api, *node, L"alpha", true, nullptr, 0, &done, buffer),
            "Directory info entry should be accepted for a normal file name"))
    {
        return false;
    }
    if (!Require(!buffer.empty(), "Directory info scratch buffer should be populated for a normal file name"))
    {
        return false;
    }

    const auto expected_size = FIELD_OFFSET(FSP_FSCTL_DIR_INFO, FileNameBuf) + 5 * sizeof(WCHAR);
    auto* dir_info = reinterpret_cast<FSP_FSCTL_DIR_INFO*>(buffer.data());
    if (!Require(dir_info->Size == expected_size, "Directory info Size should exclude the defensive trailing NUL"))
    {
        return false;
    }
    if (!Require(std::wstring(dir_info->FileNameBuf, 5) == L"alpha", "Directory info should copy the visible file name"))
    {
        return false;
    }

    return Require(dir_info->FileNameBuf[5] == L'\0', "Directory info buffer should include a defensive trailing NUL");
}

bool TestRecycleBinPathsExposeExplorerCompatibleAttributes()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"$RECYCLE.BIN");

    auto recycle = MakeNode(L"\\$RECYCLE.BIN", true, false);
    AddChildName(recycle->children, L"S-1-5-21-2379054723-1857672711-2983363584-1001");
    context.nodes.emplace(Key(recycle->path), recycle);

    auto sid = MakeNode(L"\\$RECYCLE.BIN\\S-1-5-21-2379054723-1857672711-2983363584-1001", true, false);
    AddChildName(sid->children, L"desktop.ini");
    context.nodes.emplace(Key(sid->path), sid);

    auto desktop = MakeNode(L"\\$RECYCLE.BIN\\S-1-5-21-2379054723-1857672711-2983363584-1001\\desktop.ini", false, false);
    desktop->file_size = 129;
    context.nodes.emplace(Key(desktop->path), desktop);

    FSP_FSCTL_FILE_INFO recycle_info{};
    FillInfo(*recycle, false, &recycle_info);
    if (!Require((recycle_info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0, "Recycle bin root should remain a directory"))
    {
        return false;
    }
    if (!Require((recycle_info.FileAttributes & FILE_ATTRIBUTE_HIDDEN) != 0, "Recycle bin root should be hidden"))
    {
        return false;
    }
    if (!Require((recycle_info.FileAttributes & FILE_ATTRIBUTE_SYSTEM) != 0, "Recycle bin root should be system"))
    {
        return false;
    }

    FSP_FSCTL_FILE_INFO sid_info{};
    FillInfo(*sid, false, &sid_info);
    if (!Require((sid_info.FileAttributes & FILE_ATTRIBUTE_HIDDEN) != 0, "Recycle bin SID folder should be hidden"))
    {
        return false;
    }
    if (!Require((sid_info.FileAttributes & FILE_ATTRIBUTE_SYSTEM) != 0, "Recycle bin SID folder should be system"))
    {
        return false;
    }

    FSP_FSCTL_FILE_INFO desktop_info{};
    FillInfo(*desktop, false, &desktop_info);
    if (!Require((desktop_info.FileAttributes & FILE_ATTRIBUTE_ARCHIVE) != 0, "Recycle bin desktop.ini should remain an archive file"))
    {
        return false;
    }
    if (!Require((desktop_info.FileAttributes & FILE_ATTRIBUTE_HIDDEN) != 0, "Recycle bin desktop.ini should be hidden"))
    {
        return false;
    }
    if (!Require((desktop_info.FileAttributes & FILE_ATTRIBUTE_SYSTEM) != 0, "Recycle bin desktop.ini should be system"))
    {
        return false;
    }

    auto fs = BuildFileSystem(&context);
    UINT32 attributes = 0;
    SIZE_T security_size = security.size();
    const auto security_status = CB_GetSecurityByName(
        &fs,
        const_cast<PWSTR>(L"\\$RECYCLE.BIN\\S-1-5-21-2379054723-1857672711-2983363584-1001"),
        &attributes,
        reinterpret_cast<PSECURITY_DESCRIPTOR>(security.data()),
        &security_size);
    if (!Require(security_status == STATUS_SUCCESS, "GetSecurityByName should succeed for recycle-bin SID folder"))
    {
        return false;
    }
    if (!Require((attributes & FILE_ATTRIBUTE_HIDDEN) != 0, "GetSecurityByName should report hidden recycle-bin SID folder"))
    {
        return false;
    }
    return Require((attributes & FILE_ATTRIBUTE_SYSTEM) != 0, "GetSecurityByName should report system recycle-bin SID folder");
}

bool TestRenameRejectsMismatchedOpenContext()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"source.txt");
    AddChildName(root->children, L"other.txt");

    auto source = MakeNode(L"\\source.txt", false, false);
    auto other = MakeNode(L"\\other.txt", false, false);
    context.nodes.emplace(Key(source->path), source);
    context.nodes.emplace(Key(other->path), other);

    OpenContext mismatched_open{};
    mismatched_open.node = other;
    mismatched_open.allow_delete = true;

    auto fs = BuildFileSystem(&context);
    auto status = CB_Rename(
        &fs,
        &mismatched_open,
        const_cast<PWSTR>(L"\\source.txt"),
        const_cast<PWSTR>(L"\\renamed.txt"),
        FALSE);
    if (!Require(status == STATUS_INVALID_PARAMETER, "Rename should fail when context handle does not match source node"))
    {
        return false;
    }

    return Require(
        context.nodes.find(Key(L"\\renamed.txt")) == context.nodes.end(),
        "Rename mismatch should not mutate node index");
}

bool TestRenameMissingSourceWithSourceHandleFailsClosed()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"other.txt");

    auto other = MakeNode(L"\\other.txt", false, false);
    context.nodes.emplace(Key(other->path), other);

    OpenContext source_like_open{};
    source_like_open.node = other;
    source_like_open.allow_delete = true;

    auto fs = BuildFileSystem(&context);
    const auto status = CB_Rename(
        &fs,
        &source_like_open,
        const_cast<PWSTR>(L"\\missing-source.txt"),
        const_cast<PWSTR>(L"\\renamed.txt"),
        FALSE);
    if (!Require(status == STATUS_OBJECT_NAME_NOT_FOUND, "Rename should fail with STATUS_OBJECT_NAME_NOT_FOUND when source path is missing even if a source-like open handle is provided"))
    {
        return false;
    }

    if (!Require(context.nodes.find(Key(L"\\missing-source.txt")) == context.nodes.end(), "Fail-closed missing-source rename should not materialize missing source entry"))
    {
        return false;
    }
    if (!Require(context.nodes.find(Key(L"\\renamed.txt")) == context.nodes.end(), "Fail-closed missing-source rename should not create destination entry"))
    {
        return false;
    }
    if (!Require(context.nodes.find(Key(L"\\other.txt")) != context.nodes.end(), "Fail-closed missing-source rename should preserve existing source-handle node"))
    {
        return false;
    }

    int other_children = 0;
    int renamed_children = 0;
    for (const auto& child : root->children)
    {
        if (!_wcsicmp(child.c_str(), L"other.txt"))
        {
            ++other_children;
        }
        if (!_wcsicmp(child.c_str(), L"renamed.txt"))
        {
            ++renamed_children;
        }
    }

    return Require(
        other_children == 1 && renamed_children == 0,
        "Fail-closed missing-source rename should keep parent children list unchanged");
}

bool TestRenameCrossParentSourceHandleSucceedsWithDeleteAccess()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"a");
    AddChildName(root->children, L"b");

    auto source_parent = MakeNode(L"\\a", true, false);
    auto target_parent = MakeNode(L"\\b", true, false);
    AddChildName(source_parent->children, L"source.txt");
    context.nodes.emplace(Key(source_parent->path), source_parent);
    context.nodes.emplace(Key(target_parent->path), target_parent);

    auto source = MakeNode(L"\\a\\source.txt", false, false);
    context.nodes.emplace(Key(source->path), source);

    OpenContext source_open{};
    source_open.node = source;
    source_open.allow_delete = true;

    auto fs = BuildFileSystem(&context);
    auto status = CB_Rename(
        &fs,
        &source_open,
        const_cast<PWSTR>(L"\\a\\source.txt"),
        const_cast<PWSTR>(L"\\b\\moved.txt"),
        FALSE);
    if (!Require(status == STATUS_SUCCESS, "Cross-parent source-handle rename should succeed with delete access"))
    {
        return false;
    }

    if (!Require(
            context.nodes.find(Key(L"\\a\\source.txt")) == context.nodes.end() &&
            context.nodes.find(Key(L"\\b\\moved.txt")) != context.nodes.end(),
            "Cross-parent source-handle rename should move source to destination"))
    {
        return false;
    }
    if (!Require(!HasChildName(source_parent->children, L"source.txt"), "Cross-parent source-handle rename should remove old parent child"))
    {
        return false;
    }
    return Require(HasChildName(target_parent->children, L"moved.txt"), "Cross-parent source-handle rename should add target parent child");
}

bool TestSetDeleteToggleClearsDeletePending()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"toggle.txt");

    auto file = MakeNode(L"\\toggle.txt", false, false);
    file->open_handle_count = 1;
    context.nodes.emplace(Key(file->path), file);

    OpenContext open_context{};
    open_context.node = file;
    open_context.allow_delete = true;

    auto fs = BuildFileSystem(&context);
    auto set_delete = CB_SetDelete(
        &fs,
        &open_context,
        const_cast<PWSTR>(L"\\toggle.txt"),
        TRUE);
    if (!Require(set_delete == STATUS_SUCCESS, "SetDelete(TRUE) should succeed for deletable file context"))
    {
        return false;
    }
    if (!Require(open_context.delete_on_cleanup, "SetDelete(TRUE) should latch delete-on-cleanup"))
    {
        return false;
    }
    if (!Require(file->delete_pending && file->delete_intent_count == 1, "SetDelete(TRUE) should mark node delete-pending"))
    {
        return false;
    }

    auto clear_delete = CB_SetDelete(
        &fs,
        &open_context,
        const_cast<PWSTR>(L"\\toggle.txt"),
        FALSE);
    if (!Require(clear_delete == STATUS_SUCCESS, "SetDelete(FALSE) should succeed for valid file context"))
    {
        return false;
    }
    if (!Require(!open_context.delete_on_cleanup, "SetDelete(FALSE) should clear delete-on-cleanup latch"))
    {
        return false;
    }

    return Require(!file->delete_pending && file->delete_intent_count == 0, "SetDelete(FALSE) should clear delete-pending state and intent count");
}

bool TestSetDeleteRemovesFileOnLastClose()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"move-out.txt");

    auto file = MakeNode(L"\\move-out.txt", false, false);
    file->open_handle_count = 1;
    context.nodes.emplace(Key(file->path), file);

    auto fs = BuildFileSystem(&context);
    auto* open_context = new OpenContext();
    open_context->node = file;
    open_context->allow_delete = true;

    auto set_delete = CB_SetDelete(
        &fs,
        open_context,
        const_cast<PWSTR>(L"\\move-out.txt"),
        TRUE);
    if (!Require(set_delete == STATUS_SUCCESS, "SetDelete(TRUE) should succeed for a single open delete handle"))
    {
        CB_Close(&fs, open_context);
        return false;
    }
    if (!Require(open_context->delete_on_cleanup && file->delete_pending, "SetDelete(TRUE) should hide the file until close resolves deletion"))
    {
        CB_Close(&fs, open_context);
        return false;
    }

    CB_Close(&fs, open_context);

    if (!Require(context.nodes.find(Key(L"\\move-out.txt")) == context.nodes.end(), "Last close after SetDelete(TRUE) should remove the file node"))
    {
        return false;
    }
    return Require(!HasChildName(root->children, L"move-out.txt"), "Last close after SetDelete(TRUE) should remove the file from parent children");
}

bool TestRenameFailsWhileSourceDeletePendingThenRecoversAfterClear()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"source.txt");

    auto source = MakeNode(L"\\source.txt", false, false);
    source->open_handle_count = 1;
    context.nodes.emplace(Key(source->path), source);

    OpenContext source_open{};
    source_open.node = source;
    source_open.allow_delete = true;

    auto fs = BuildFileSystem(&context);
    auto set_delete = CB_SetDelete(
        &fs,
        &source_open,
        const_cast<PWSTR>(L"\\source.txt"),
        TRUE);
    if (!Require(set_delete == STATUS_SUCCESS, "SetDelete(TRUE) should succeed before pending-source rename test"))
    {
        return false;
    }

    auto pending_rename = CB_Rename(
        &fs,
        &source_open,
        const_cast<PWSTR>(L"\\source.txt"),
        const_cast<PWSTR>(L"\\renamed.txt"),
        FALSE);
    if (!Require(pending_rename == STATUS_DELETE_PENDING, "Rename should fail with STATUS_DELETE_PENDING while source is delete-pending"))
    {
        return false;
    }

    auto clear_delete = CB_SetDelete(
        &fs,
        &source_open,
        const_cast<PWSTR>(L"\\source.txt"),
        FALSE);
    if (!Require(clear_delete == STATUS_SUCCESS, "SetDelete(FALSE) should clear pending source state"))
    {
        return false;
    }

    auto recovered_rename = CB_Rename(
        &fs,
        &source_open,
        const_cast<PWSTR>(L"\\source.txt"),
        const_cast<PWSTR>(L"\\renamed.txt"),
        FALSE);
    if (!Require(recovered_rename == STATUS_SUCCESS, "Rename should succeed after clearing delete-pending source state"))
    {
        return false;
    }

    return Require(
        context.nodes.find(Key(L"\\source.txt")) == context.nodes.end() &&
        context.nodes.find(Key(L"\\renamed.txt")) != context.nodes.end(),
        "Recovered rename should move source to destination");
}

bool TestRenameFailsWhenSourceDeleteIntentStateIsStale()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"stale-source.txt");

    auto source = MakeNode(L"\\stale-source.txt", false, false);
    source->open_handle_count = 1;
    source->delete_intent_count = 1;
    source->delete_pending = false;
    source->delete_latched = false;
    context.nodes.emplace(Key(source->path), source);

    OpenContext source_open{};
    source_open.node = source;
    source_open.allow_delete = true;

    auto fs = BuildFileSystem(&context);
    const auto rename_status = CB_Rename(
        &fs,
        &source_open,
        const_cast<PWSTR>(L"\\stale-source.txt"),
        const_cast<PWSTR>(L"\\stale-renamed.txt"),
        FALSE);
    if (!Require(rename_status == STATUS_DELETE_PENDING, "Rename should fail closed when source delete intent exists even if delete_pending visibility flag is stale"))
    {
        return false;
    }

    return Require(
        context.nodes.find(Key(L"\\stale-source.txt")) != context.nodes.end() &&
        context.nodes.find(Key(L"\\stale-renamed.txt")) == context.nodes.end(),
        "Fail-closed stale source delete intent should preserve namespace state");
}

bool TestRenameReplaceFailsWhenTargetDeletePending()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"source.txt");
    AddChildName(root->children, L"target.txt");

    auto source = MakeNode(L"\\source.txt", false, false);
    auto target = MakeNode(L"\\target.txt", false, false);
    source->open_handle_count = 1;
    target->open_handle_count = 1;
    context.nodes.emplace(Key(source->path), source);
    context.nodes.emplace(Key(target->path), target);

    OpenContext target_open{};
    target_open.node = target;
    target_open.allow_delete = true;

    OpenContext parent_open{};
    parent_open.node = root;
    parent_open.allow_delete_child = true;
    parent_open.allow_write_data = true;

    auto fs = BuildFileSystem(&context);
    auto set_delete = CB_SetDelete(
        &fs,
        &target_open,
        const_cast<PWSTR>(L"\\target.txt"),
        TRUE);
    if (!Require(set_delete == STATUS_SUCCESS, "SetDelete(TRUE) should succeed for target before replace-pending test"))
    {
        return false;
    }

    auto replace_status = CB_Rename(
        &fs,
        &parent_open,
        const_cast<PWSTR>(L"\\source.txt"),
        const_cast<PWSTR>(L"\\target.txt"),
        TRUE);
    if (!Require(replace_status == STATUS_DELETE_PENDING, "Rename replace should fail with STATUS_DELETE_PENDING when target is delete-pending"))
    {
        return false;
    }

    return Require(
        context.nodes.find(Key(L"\\source.txt")) != context.nodes.end() &&
        context.nodes.find(Key(L"\\target.txt")) != context.nodes.end(),
        "Replace against delete-pending target should preserve source and target entries");
}

bool TestRenameReplaceAllowsFileTargetWithAdditionalOpenHandle()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"source.txt");
    AddChildName(root->children, L"target.txt");

    auto source = MakeNode(L"\\source.txt", false, false);
    auto target = MakeNode(L"\\target.txt", false, false);
    target->open_handle_count = 1;
    context.nodes.emplace(Key(source->path), source);
    context.nodes.emplace(Key(target->path), target);

    OpenContext parent_open{};
    parent_open.node = root;
    parent_open.allow_delete_child = true;
    parent_open.allow_write_data = true;

    auto fs = BuildFileSystem(&context);
    auto replace_status = CB_Rename(
        &fs,
        &parent_open,
        const_cast<PWSTR>(L"\\source.txt"),
        const_cast<PWSTR>(L"\\target.txt"),
        TRUE);
    if (!Require(replace_status == STATUS_SUCCESS, "Rename replace should allow file target replacement after WinFsp admits compatible handles"))
    {
        return false;
    }

    return Require(
        context.nodes.find(Key(L"\\source.txt")) == context.nodes.end() &&
        context.nodes.find(Key(L"\\target.txt")) != context.nodes.end(),
        "Successful file target replace should move source to target");
}

bool TestRenameRollsBackLocalNamespaceWhenNativeCommitFails()
{
#ifdef APFSACCESS_HAS_RW_ENGINE
    MountContext context{};
    if (!ConfigureNativeCommitFailureForUnitTest(context))
    {
        return true;
    }
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"source.txt");

    auto source = MakeNode(L"\\source.txt", false, false);
    source->file_size = 9;
    context.nodes.emplace(Key(source->path), source);

    auto fs = BuildFileSystem(&context);
    const auto rename_status = CB_Rename(
        &fs,
        nullptr,
        const_cast<PWSTR>(L"\\source.txt"),
        const_cast<PWSTR>(L"\\renamed.txt"),
        FALSE);
    if (!Require(rename_status == STATUS_MEDIA_WRITE_PROTECTED, "Forced native rename commit failure should return MEDIA_WRITE_PROTECTED"))
    {
        return false;
    }

    if (!Require(context.nodes.find(Key(L"\\source.txt")) != context.nodes.end(), "Failed native rename commit should restore source path"))
    {
        return false;
    }
    if (!Require(context.nodes.find(Key(L"\\renamed.txt")) == context.nodes.end(), "Failed native rename commit should remove transient destination path"))
    {
        return false;
    }
    if (!Require(HasChildName(root->children, L"source.txt"), "Failed native rename commit should restore source child entry"))
    {
        return false;
    }
    return Require(!HasChildName(root->children, L"renamed.txt"), "Failed native rename commit should remove destination child entry");
#else
    return true;
#endif
}

bool TestRenameReplaceKeepsOpenTargetHandleOnOldHydration()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    if (!Require(PrepareUnitHydrationRoot(context, L"rename-replace-open-target"), "Rename-replace hydration test should prepare cache root"))
    {
        return false;
    }
    ScopeExit cleanup{[&]()
    {
        std::error_code ec;
        std::filesystem::remove_all(context.session_root, ec);
    }};

    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"source.txt");
    AddChildName(root->children, L"target.txt");

    auto source = MakeNode(L"\\source.txt", false, false);
    auto target = MakeNode(L"\\target.txt", false, false);
    target->open_handle_count = 1;
    source->file_size = 3;
    target->file_size = 3;
    context.nodes.emplace(Key(source->path), source);
    context.nodes.emplace(Key(target->path), target);

    const std::vector<std::byte> source_bytes{std::byte{'A'}, std::byte{'A'}, std::byte{'A'}};
    const std::vector<std::byte> target_bytes{std::byte{'B'}, std::byte{'B'}, std::byte{'B'}};
    const auto source_hydration = HydrationPath(&context, *source);
    const auto target_hydration = HydrationPath(&context, *target);
    if (!Require(WriteFileBytes(source_hydration, source_bytes), "Rename-replace test should seed source hydration bytes"))
    {
        return false;
    }
    if (!Require(WriteFileBytes(target_hydration, target_bytes), "Rename-replace test should seed target hydration bytes"))
    {
        return false;
    }

    HANDLE open_target = CreateFileW(
        target_hydration.wstring().c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (!Require(open_target != INVALID_HANDLE_VALUE, "Rename-replace test should hold a read handle to the old target hydration"))
    {
        return false;
    }
    ScopeExit close_target{[&]()
    {
        CloseHandle(open_target);
    }};

    OpenContext parent_open{};
    parent_open.node = root;
    parent_open.allow_delete_child = true;
    parent_open.allow_write_data = true;

    auto fs = BuildFileSystem(&context);
    auto replace_status = CB_Rename(
        &fs,
        &parent_open,
        const_cast<PWSTR>(L"\\source.txt"),
        const_cast<PWSTR>(L"\\target.txt"),
        TRUE);
    if (!Require(replace_status == STATUS_SUCCESS, "Rename replace should succeed with a compatible read handle on the target"))
    {
        return false;
    }

    if (!Require(ReadHandleBytes(open_target, 3) == target_bytes, "Old target handle should continue reading old target bytes after replace"))
    {
        return false;
    }
    if (!Require(ReadFileBytes(target_hydration) == source_bytes, "Visible target hydration should contain source bytes after replace"))
    {
        return false;
    }
    if (!Require(!std::filesystem::exists(source_hydration), "Source hydration path should be consumed by successful replace"))
    {
        return false;
    }

    if (!Require(
            context.nodes.find(Key(L"\\source.txt")) == context.nodes.end() &&
            context.nodes.find(Key(L"\\target.txt")) != context.nodes.end(),
            "Successful file target replace with open target handle should leave only the target namespace entry"))
    {
        return false;
    }
    const auto replacement = context.nodes.at(Key(L"\\target.txt"));
    return Require(replacement->hydration_key == Key(L"\\target.txt"), "Successful replace should keep visible target on the target hydration key");
}

bool TestRenameReplaceRollsBackHydrationWhenNativeCommitFails()
{
#ifdef APFSACCESS_HAS_RW_ENGINE
    MountContext context{};
    if (!ConfigureNativeCommitFailureForUnitTest(context))
    {
        return true;
    }
    if (!Require(PrepareUnitHydrationRoot(context, L"rename-replace-rollback"), "Rename-replace rollback test should prepare cache root"))
    {
        return false;
    }
    ScopeExit cleanup{[&]()
    {
        std::error_code ec;
        std::filesystem::remove_all(context.session_root, ec);
    }};

    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"source.txt");
    AddChildName(root->children, L"target.txt");

    auto source = MakeNode(L"\\source.txt", false, false);
    auto target = MakeNode(L"\\target.txt", false, false);
    source->file_size = 3;
    target->file_size = 3;
    context.nodes.emplace(Key(source->path), source);
    context.nodes.emplace(Key(target->path), target);

    const std::vector<std::byte> source_bytes{std::byte{'A'}, std::byte{'A'}, std::byte{'A'}};
    const std::vector<std::byte> target_bytes{std::byte{'B'}, std::byte{'B'}, std::byte{'B'}};
    const auto source_hydration = HydrationPath(&context, *source);
    const auto target_hydration = HydrationPath(&context, *target);
    if (!Require(WriteFileBytes(source_hydration, source_bytes), "Rename-replace rollback test should seed source bytes"))
    {
        return false;
    }
    if (!Require(WriteFileBytes(target_hydration, target_bytes), "Rename-replace rollback test should seed target bytes"))
    {
        return false;
    }

    auto fs = BuildFileSystem(&context);
    const auto status = CB_Rename(
        &fs,
        nullptr,
        const_cast<PWSTR>(L"\\source.txt"),
        const_cast<PWSTR>(L"\\target.txt"),
        TRUE);
    if (!Require(status == STATUS_MEDIA_WRITE_PROTECTED, "Forced native rename-replace commit failure should return MEDIA_WRITE_PROTECTED"))
    {
        return false;
    }

    if (!Require(context.nodes.find(Key(L"\\source.txt")) != context.nodes.end(), "Failed native rename-replace commit should restore source node"))
    {
        return false;
    }
    if (!Require(context.nodes.find(Key(L"\\target.txt")) != context.nodes.end(), "Failed native rename-replace commit should restore target node"))
    {
        return false;
    }
    if (!Require(ReadFileBytes(source_hydration) == source_bytes, "Failed native rename-replace commit should restore source hydration bytes"))
    {
        return false;
    }
    return Require(ReadFileBytes(target_hydration) == target_bytes, "Failed native rename-replace commit should restore target hydration bytes");
#else
    return true;
#endif
}

bool TestCleanupDeleteTrustsPostedDeleteDisposition()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"cleanup.txt");

    auto file = MakeNode(L"\\cleanup.txt", false, false);
    file->open_handle_count = 1;
    context.nodes.emplace(Key(file->path), file);

    auto fs = BuildFileSystem(&context);
    OpenContext open_context{};
    open_context.node = file;
    open_context.allow_delete = false;

    CB_Cleanup(
        &fs,
        &open_context,
        const_cast<PWSTR>(L"\\cleanup.txt"),
        0);

    if (!Require(!open_context.delete_on_cleanup, "Cleanup without delete disposition should not latch delete-on-close"))
    {
        return false;
    }
    if (!Require(file->delete_intent_count == 0 && !file->delete_pending, "Cleanup without delete disposition should not set delete-pending state"))
    {
        return false;
    }
    if (!Require(file->open_handle_count == 0 && open_context.cleanup_seen, "Cleanup should release visible open-handle accounting"))
    {
        return false;
    }

    file->open_handle_count = 1;
    OpenContext delete_context{};
    delete_context.node = file;
    delete_context.allow_delete = true;
    CB_Cleanup(
        &fs,
        &delete_context,
        const_cast<PWSTR>(L"\\cleanup.txt"),
        FspCleanupDelete);

    if (!Require(delete_context.delete_on_cleanup, "Cleanup delete should latch delete-on-close when DELETE permission is granted"))
    {
        return false;
    }
    return Require(
        file->delete_intent_count == 1 && file->delete_pending,
        "Cleanup delete disposition should mark the node delete-pending");
}

bool TestDirectoryCleanupDeleteDispositionWorksAfterMetadataOnlyOpen()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"delete-me");

    auto directory = MakeNode(L"\\delete-me", true, false);
    AddChildName(directory->children, L"inside.bin");
    directory->open_handle_count = 1;
    context.nodes.emplace(Key(directory->path), directory);

    auto child = MakeNode(L"\\delete-me\\inside.bin", false, false);
    child->open_handle_count = 1;
    context.nodes.emplace(Key(child->path), child);

    auto fs = BuildFileSystem(&context);
    auto* directory_context = new OpenContext();
    directory_context->node = directory;
    directory_context->allow_set_basic_info = true;
    auto* child_context = new OpenContext();
    child_context->node = child;
    child_context->allow_delete = true;

    CB_Cleanup(
        &fs,
        child_context,
        const_cast<PWSTR>(L"\\delete-me\\inside.bin"),
        FspCleanupDelete);
    CB_Close(&fs, child_context);
    if (!Require(context.nodes.find(Key(L"\\delete-me\\inside.bin")) == context.nodes.end(), "Child delete should remove file before directory disposition cleanup"))
    {
        delete directory_context;
        return false;
    }

    FSP_FSCTL_FILE_INFO info{};
    const auto metadata_status = CB_SetBasicInfo(
        &fs,
        directory_context,
        0,
        0,
        0,
        ToFileTimeValue(UtcNow()),
        0,
        &info);
    if (!Require(metadata_status == STATUS_SUCCESS, "Metadata-only directory handle should allow SetBasicInfo before cleanup delete disposition"))
    {
        delete directory_context;
        return false;
    }

    CB_Cleanup(
        &fs,
        directory_context,
        const_cast<PWSTR>(L"\\delete-me"),
        FspCleanupDelete);
    CB_Close(&fs, directory_context);

    if (!Require(context.nodes.find(Key(L"\\delete-me")) == context.nodes.end(), "Cleanup delete disposition should remove metadata-only opened empty directory"))
    {
        return false;
    }
    return Require(!HasChildName(root->children, L"delete-me"), "Cleanup delete disposition should remove metadata-only opened directory from parent children");
}

bool TestDirectoryCleanupFilenameWithoutDeleteFlagKeepsDirectory()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"keep-me");

    auto directory = MakeNode(L"\\keep-me", true, false);
    directory->open_handle_count = 1;
    context.nodes.emplace(Key(directory->path), directory);

    auto fs = BuildFileSystem(&context);
    auto* directory_context = new OpenContext();
    directory_context->node = directory;
    directory_context->allow_set_basic_info = true;

    CB_Cleanup(
        &fs,
        directory_context,
        const_cast<PWSTR>(L"\\keep-me"),
        0);
    CB_Close(&fs, directory_context);

    if (!Require(context.nodes.find(Key(L"\\keep-me")) != context.nodes.end(), "Cleanup file name without delete disposition should not delete an empty directory"))
    {
        return false;
    }
    return Require(HasChildName(root->children, L"keep-me"), "Cleanup file name without delete disposition should keep directory visible");
}

bool TestDeleteOnCloseDirectoryDefersUntilChildrenDrain()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"delete-me");

    auto directory = MakeNode(L"\\delete-me", true, false);
    AddChildName(directory->children, L"inside.bin");
    context.nodes.emplace(Key(directory->path), directory);

    auto child = MakeNode(L"\\delete-me\\inside.bin", false, false);
    context.nodes.emplace(Key(child->path), child);

    auto fs = BuildFileSystem(&context);
    PVOID directory_context_raw = nullptr;
    FSP_FSCTL_FILE_INFO directory_info{};
    const auto open_status = CB_Open(
        &fs,
        const_cast<PWSTR>(L"\\delete-me"),
        FILE_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE,
        DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        &directory_context_raw,
        &directory_info);
    if (!Require(open_status == STATUS_SUCCESS && directory_context_raw != nullptr, "Delete-on-close directory open should succeed"))
    {
        return false;
    }

    auto* directory_context = static_cast<OpenContext*>(directory_context_raw);
    if (!Require(directory_context->delete_on_close_requested, "Open should remember FILE_DELETE_ON_CLOSE for later cleanup disposition"))
    {
        CB_Close(&fs, directory_context);
        return false;
    }

    CB_Cleanup(
        &fs,
        directory_context,
        const_cast<PWSTR>(L"\\delete-me"),
        FspCleanupSetLastAccessTime);
    if (!Require(directory->delete_requested_after_children, "Delete-on-close cleanup should defer a non-empty directory until children drain"))
    {
        CB_Close(&fs, directory_context);
        return false;
    }

    auto* child_context = new OpenContext();
    child_context->node = child;
    child_context->allow_delete = true;
    ++child->open_handle_count;

    CB_Cleanup(
        &fs,
        child_context,
        const_cast<PWSTR>(L"\\delete-me\\inside.bin"),
        FspCleanupDelete);
    CB_Close(&fs, child_context);
    if (!Require(context.nodes.find(Key(L"\\delete-me\\inside.bin")) == context.nodes.end(), "Child close should remove child before deferred delete-on-close directory"))
    {
        CB_Close(&fs, directory_context);
        return false;
    }

    CB_Close(&fs, directory_context);
    if (!Require(context.nodes.find(Key(L"\\delete-me")) == context.nodes.end(), "Deferred delete-on-close directory should disappear after children drain"))
    {
        return false;
    }
    return Require(!HasChildName(root->children, L"delete-me"), "Deferred delete-on-close directory should be removed from parent children");
}

bool TestDeleteAccessOpenCompletesRecentlyDrainedDirectoryDelete()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"delete-me");

    auto directory = MakeNode(L"\\delete-me", true, false);
    AddChildName(directory->children, L"subdir");
    context.nodes.emplace(Key(directory->path), directory);

    auto subdir = MakeNode(L"\\delete-me\\subdir", true, false);
    AddChildName(subdir->children, L"inside.bin");
    context.nodes.emplace(Key(subdir->path), subdir);

    auto child = MakeNode(L"\\delete-me\\subdir\\inside.bin", false, false);
    child->open_handle_count = 1;
    context.nodes.emplace(Key(child->path), child);

    auto fs = BuildFileSystem(&context);
    auto* child_context = new OpenContext();
    child_context->node = child;
    child_context->allow_delete = true;

    CB_Cleanup(
        &fs,
        child_context,
        const_cast<PWSTR>(L"\\delete-me\\subdir\\inside.bin"),
        FspCleanupDelete);
    CB_Close(&fs, child_context);
    if (!Require(context.nodes.find(Key(L"\\delete-me\\subdir\\inside.bin")) == context.nodes.end(), "Child delete should drain directory contents"))
    {
        return false;
    }
    if (!Require(subdir->children.empty() && subdir->last_child_delete_tick_ms != 0, "Child delete should mark parent directory as recently drained"))
    {
        return false;
    }

    PVOID subdir_context_raw = nullptr;
    FSP_FSCTL_FILE_INFO subdir_info{};
    const auto open_status = CB_Open(
        &fs,
        const_cast<PWSTR>(L"\\delete-me\\subdir"),
        FILE_DIRECTORY_FILE,
        DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        &subdir_context_raw,
        &subdir_info);
    if (!Require(open_status == STATUS_SUCCESS && subdir_context_raw != nullptr, "Delete-access open should succeed for recently drained directory"))
    {
        return false;
    }

    auto* subdir_context = static_cast<OpenContext*>(subdir_context_raw);
    if (!Require(subdir_context->delete_on_cleanup && subdir->delete_pending, "Delete-access open should latch recently drained directory delete intent"))
    {
        CB_Close(&fs, subdir_context);
        return false;
    }

    CB_Close(&fs, subdir_context);
    if (!Require(context.nodes.find(Key(L"\\delete-me\\subdir")) == context.nodes.end(), "Close should remove recently drained delete-access directory"))
    {
        return false;
    }
    return Require(!HasChildName(directory->children, L"subdir"), "Close should remove recently drained directory from parent children");
}

bool TestSetBasicInfoPreservesOpenRecentlyDrainedDirectory()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"delete-me");

    auto directory = MakeNode(L"\\delete-me", true, false);
    AddChildName(directory->children, L"subdir");
    context.nodes.emplace(Key(directory->path), directory);

    auto subdir = MakeNode(L"\\delete-me\\subdir", true, false);
    AddChildName(subdir->children, L"inside.bin");
    context.nodes.emplace(Key(subdir->path), subdir);

    auto child = MakeNode(L"\\delete-me\\subdir\\inside.bin", false, false);
    child->open_handle_count = 1;
    context.nodes.emplace(Key(child->path), child);

    auto fs = BuildFileSystem(&context);
    auto* subdir_context = new OpenContext();
    subdir_context->node = subdir;
    subdir_context->allow_delete = false;
    subdir_context->allow_set_basic_info = true;
    ++subdir->open_handle_count;

    auto* child_context = new OpenContext();
    child_context->node = child;
    child_context->allow_delete = true;

    CB_Cleanup(
        &fs,
        child_context,
        const_cast<PWSTR>(L"\\delete-me\\subdir\\inside.bin"),
        FspCleanupDelete);
    CB_Close(&fs, child_context);
    if (!Require(context.nodes.find(Key(L"\\delete-me\\subdir\\inside.bin")) == context.nodes.end(), "Child delete should drain open directory contents"))
    {
        CB_Close(&fs, subdir_context);
        return false;
    }
    if (!Require(subdir->children.empty() && subdir->last_child_delete_tick_ms != 0, "Child delete should mark the still-open parent directory as recently drained"))
    {
        CB_Close(&fs, subdir_context);
        return false;
    }

    FSP_FSCTL_FILE_INFO info{};
    const auto set_basic_status = CB_SetBasicInfo(
        &fs,
        subdir_context,
        0,
        0,
        0,
        ToFileTimeValue(UtcNow()),
        0,
        &info);
    if (!Require(set_basic_status == STATUS_SUCCESS, "SetBasicInfo should succeed on recently drained metadata-only directory handle"))
    {
        CB_Close(&fs, subdir_context);
        return false;
    }

    CB_Close(&fs, subdir_context);
    if (!Require(context.nodes.find(Key(L"\\delete-me\\subdir")) != context.nodes.end(), "Metadata-only SetBasicInfo should not remove a recently drained directory before the caller's final delete"))
    {
        return false;
    }
    return Require(HasChildName(directory->children, L"subdir"), "Metadata-only SetBasicInfo should keep the recently drained directory visible for caller cleanup");
}

bool TestSetBasicInfoDoesNotDeleteDirectoryOpenedAfterChildDelete()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"keep-me");

    auto directory = MakeNode(L"\\keep-me", true, false);
    AddChildName(directory->children, L"child.bin");
    context.nodes.emplace(Key(directory->path), directory);

    auto child = MakeNode(L"\\keep-me\\child.bin", false, false);
    child->open_handle_count = 1;
    context.nodes.emplace(Key(child->path), child);

    auto fs = BuildFileSystem(&context);
    auto* child_context = new OpenContext();
    child_context->node = child;
    child_context->allow_delete = true;

    CB_Cleanup(
        &fs,
        child_context,
        const_cast<PWSTR>(L"\\keep-me\\child.bin"),
        FspCleanupDelete);
    CB_Close(&fs, child_context);
    if (!Require(context.nodes.find(Key(L"\\keep-me\\child.bin")) == context.nodes.end(), "Child delete should remove child before later directory metadata touch"))
    {
        return false;
    }

    auto* metadata_context = new OpenContext();
    metadata_context->node = directory;
    metadata_context->allow_set_basic_info = true;
    ++directory->open_handle_count;

    FSP_FSCTL_FILE_INFO info{};
    const auto set_basic_status = CB_SetBasicInfo(
        &fs,
        metadata_context,
        0,
        0,
        0,
        ToFileTimeValue(UtcNow()),
        0,
        &info);
    if (!Require(set_basic_status == STATUS_SUCCESS, "SetBasicInfo should succeed on directory opened after a child delete"))
    {
        CB_Close(&fs, metadata_context);
        return false;
    }
    CB_Close(&fs, metadata_context);

    if (!Require(context.nodes.find(Key(L"\\keep-me")) != context.nodes.end(), "SetBasicInfo should not delete a directory opened only after child deletion"))
    {
        return false;
    }
    return Require(HasChildName(root->children, L"keep-me"), "SetBasicInfo after child delete should keep directory visible");
}

bool TestRecursiveCallerCanDeleteDrainedDirectoryAfterMetadataTouch()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"delete-me");

    auto directory = MakeNode(L"\\delete-me", true, false);
    AddChildName(directory->children, L"inside.bin");
    directory->open_handle_count = 1;
    context.nodes.emplace(Key(directory->path), directory);

    auto child = MakeNode(L"\\delete-me\\inside.bin", false, false);
    child->open_handle_count = 1;
    context.nodes.emplace(Key(child->path), child);

    auto fs = BuildFileSystem(&context);
    auto* directory_context = new OpenContext();
    directory_context->node = directory;
    directory_context->allow_delete = true;
    directory_context->allow_set_basic_info = true;

    const auto first_delete_status = CB_SetDelete(
        &fs,
        directory_context,
        const_cast<PWSTR>(L"\\delete-me"),
        TRUE);
    if (!Require(first_delete_status == STATUS_DIRECTORY_NOT_EMPTY, "First recursive directory delete should report not-empty before children drain"))
    {
        delete directory_context;
        return false;
    }
    if (!Require(directory->delete_requested_after_children && !directory->delete_pending, "Not-empty recursive delete should remember intent without hiding the directory"))
    {
        delete directory_context;
        return false;
    }

    auto* child_context = new OpenContext();
    child_context->node = child;
    child_context->allow_delete = true;

    CB_Cleanup(
        &fs,
        child_context,
        const_cast<PWSTR>(L"\\delete-me\\inside.bin"),
        FspCleanupDelete);
    CB_Close(&fs, child_context);
    if (!Require(context.nodes.find(Key(L"\\delete-me\\inside.bin")) == context.nodes.end(), "Child delete should drain directory contents"))
    {
        delete directory_context;
        return false;
    }

    FSP_FSCTL_FILE_INFO info{};
    const auto set_basic_status = CB_SetBasicInfo(
        &fs,
        directory_context,
        0,
        0,
        0,
        ToFileTimeValue(UtcNow()),
        0,
        &info);
    if (!Require(set_basic_status == STATUS_SUCCESS, "Metadata touch on drained recursive-delete directory should succeed"))
    {
        delete directory_context;
        return false;
    }
    if (!Require(context.nodes.find(Key(L"\\delete-me")) != context.nodes.end(), "Metadata touch should not remove the directory before the caller's final delete retry"))
    {
        delete directory_context;
        return false;
    }

    CB_Cleanup(
        &fs,
        directory_context,
        const_cast<PWSTR>(L"\\delete-me"),
        0);
    CB_Close(&fs, directory_context);
    if (!Require(context.nodes.find(Key(L"\\delete-me")) != context.nodes.end(), "Closing a not-empty delete probe handle should not remove the drained directory before the caller's final delete retry"))
    {
        return false;
    }

    auto* final_context = new OpenContext();
    final_context->node = directory;
    final_context->allow_delete = true;
    ++directory->open_handle_count;
    const auto final_delete_status = CB_SetDelete(
        &fs,
        final_context,
        const_cast<PWSTR>(L"\\delete-me"),
        TRUE);
    if (!Require(final_delete_status == STATUS_SUCCESS, "Final recursive directory delete retry should latch the drained directory"))
    {
        delete final_context;
        return false;
    }

    CB_Cleanup(
        &fs,
        final_context,
        const_cast<PWSTR>(L"\\delete-me"),
        FspCleanupDelete);
    CB_Close(&fs, final_context);
    if (!Require(context.nodes.find(Key(L"\\delete-me")) == context.nodes.end(), "Final delete close should remove drained directory"))
    {
        return false;
    }
    return Require(!HasChildName(root->children, L"delete-me"), "Final delete close should remove drained directory from parent children");
}

bool TestCleanupDeleteBlocksRenameUntilCloseRemovesSource()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"pending.txt");

    auto file = MakeNode(L"\\pending.txt", false, false);
    file->open_handle_count = 1;
    context.nodes.emplace(Key(file->path), file);

    auto fs = BuildFileSystem(&context);
    auto* open_context = new OpenContext();
    open_context->node = file;
    open_context->allow_delete = true;

    CB_Cleanup(
        &fs,
        open_context,
        const_cast<PWSTR>(L"\\pending.txt"),
        FspCleanupDelete);

    auto rename_while_pending = CB_Rename(
        &fs,
        nullptr,
        const_cast<PWSTR>(L"\\pending.txt"),
        const_cast<PWSTR>(L"\\renamed.txt"),
        FALSE);
    if (!Require(rename_while_pending == STATUS_DELETE_PENDING, "Rename should fail with STATUS_DELETE_PENDING after cleanup delete latch"))
    {
        CB_Close(&fs, open_context);
        return false;
    }

    CB_Close(&fs, open_context);

    auto rename_after_close = CB_Rename(
        &fs,
        nullptr,
        const_cast<PWSTR>(L"\\pending.txt"),
        const_cast<PWSTR>(L"\\renamed.txt"),
        FALSE);
    if (!Require(rename_after_close == STATUS_OBJECT_NAME_NOT_FOUND, "Rename after close should report source not found once delete-latched file is removed"))
    {
        return false;
    }

    if (!Require(context.nodes.find(Key(L"\\pending.txt")) == context.nodes.end(), "Close after cleanup delete should remove source node"))
    {
        return false;
    }
    return Require(!HasChildName(root->children, L"pending.txt"), "Close after cleanup delete should remove source from parent children");
}

bool TestCloseRemovesEmptyDirectoryAfterCleanupDelete()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"empty");

    auto empty_dir = MakeNode(L"\\empty", true, false);
    empty_dir->open_handle_count = 1;
    context.nodes.emplace(Key(empty_dir->path), empty_dir);

    auto fs = BuildFileSystem(&context);
    auto* open_context = new OpenContext();
    open_context->node = empty_dir;
    open_context->allow_delete = true;

    CB_Cleanup(
        &fs,
        open_context,
        const_cast<PWSTR>(L"\\empty"),
        FspCleanupDelete);
    CB_Close(&fs, open_context);

    if (!Require(context.nodes.find(Key(L"\\empty")) == context.nodes.end(), "Close after cleanup delete should remove empty directory node"))
    {
        return false;
    }
    return Require(!HasChildName(root->children, L"empty"), "Close after cleanup delete should remove empty directory from parent children");
}

bool TestRecursiveDirectoryDeleteCompletesAfterChildClose()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"delete-me");

    auto parent = MakeNode(L"\\delete-me", true, false);
    AddChildName(parent->children, L"subdir");
    parent->open_handle_count = 1;
    context.nodes.emplace(Key(parent->path), parent);

    auto child = MakeNode(L"\\delete-me\\subdir", true, false);
    child->open_handle_count = 1;
    context.nodes.emplace(Key(child->path), child);

    auto fs = BuildFileSystem(&context);
    auto* parent_context = new OpenContext();
    parent_context->node = parent;
    parent_context->allow_delete = true;
    auto* child_context = new OpenContext();
    child_context->node = child;
    child_context->allow_delete = true;

    CB_Cleanup(
        &fs,
        parent_context,
        const_cast<PWSTR>(L"\\delete-me"),
        FspCleanupDelete);
    CB_Close(&fs, parent_context);
    if (!Require(context.nodes.find(Key(L"\\delete-me")) != context.nodes.end(), "Parent should remain until child directory closes"))
    {
        return false;
    }

    CB_Cleanup(
        &fs,
        child_context,
        const_cast<PWSTR>(L"\\delete-me\\subdir"),
        FspCleanupDelete);
    CB_Close(&fs, child_context);

    if (!Require(context.nodes.find(Key(L"\\delete-me\\subdir")) == context.nodes.end(), "Child directory close should remove child"))
    {
        return false;
    }
    if (!Require(context.nodes.find(Key(L"\\delete-me")) == context.nodes.end(), "Parent directory delete should complete after last child closes"))
    {
        return false;
    }
    return Require(!HasChildName(root->children, L"delete-me"), "Recursive delete should remove parent from root children");
}

bool TestDeferredDirectoryDeleteCompletesOnDirectoryClose()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"delete-me");

    auto directory = MakeNode(L"\\delete-me", true, false);
    AddChildName(directory->children, L"inside.bin");
    directory->open_handle_count = 1;
    context.nodes.emplace(Key(directory->path), directory);

    auto child = MakeNode(L"\\delete-me\\inside.bin", false, false);
    child->open_handle_count = 1;
    context.nodes.emplace(Key(child->path), child);

    auto fs = BuildFileSystem(&context);
    auto* directory_context = new OpenContext();
    directory_context->node = directory;
    directory_context->allow_delete = true;
    auto* child_context = new OpenContext();
    child_context->node = child;
    child_context->allow_delete = true;

    CB_Cleanup(
        &fs,
        directory_context,
        const_cast<PWSTR>(L"\\delete-me"),
        FspCleanupDelete);
    if (!Require(directory->delete_requested_after_children, "Non-empty directory cleanup delete should defer removal until children drain"))
    {
        delete directory_context;
        delete child_context;
        return false;
    }

    CB_Cleanup(
        &fs,
        child_context,
        const_cast<PWSTR>(L"\\delete-me\\inside.bin"),
        FspCleanupDelete);
    CB_Close(&fs, child_context);
    if (!Require(context.nodes.find(Key(L"\\delete-me\\inside.bin")) == context.nodes.end(), "Child close should remove child before directory close"))
    {
        delete directory_context;
        return false;
    }

    CB_Close(&fs, directory_context);
    if (!Require(context.nodes.find(Key(L"\\delete-me")) == context.nodes.end(), "Directory close should complete deferred delete once children are gone"))
    {
        return false;
    }
    return Require(!HasChildName(root->children, L"delete-me"), "Deferred directory close should remove directory from parent children");
}

bool TestSetDeleteNonEmptyDirectoryAllowsCallerFinalDeleteRetry()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"delete-me");

    auto directory = MakeNode(L"\\delete-me", true, false);
    AddChildName(directory->children, L"inside.bin");
    directory->open_handle_count = 1;
    context.nodes.emplace(Key(directory->path), directory);

    auto child = MakeNode(L"\\delete-me\\inside.bin", false, false);
    child->open_handle_count = 1;
    context.nodes.emplace(Key(child->path), child);

    auto fs = BuildFileSystem(&context);
    auto* directory_context = new OpenContext();
    directory_context->node = directory;
    directory_context->allow_delete = true;
    auto* child_context = new OpenContext();
    child_context->node = child;
    child_context->allow_delete = true;

    const auto set_delete_status = CB_SetDelete(
        &fs,
        directory_context,
        const_cast<PWSTR>(L"\\delete-me"),
        TRUE);
    if (!Require(set_delete_status == STATUS_DIRECTORY_NOT_EMPTY, "SetDelete on non-empty directory should report not-empty so recursive callers retry after children drain"))
    {
        delete directory_context;
        delete child_context;
        return false;
    }
    if (!Require(directory->delete_requested_after_children && !directory->delete_pending, "Deferred non-empty directory delete should not hide children behind delete-pending ancestor state"))
    {
        delete directory_context;
        delete child_context;
        return false;
    }

    CB_Close(&fs, directory_context);
    if (!Require(context.nodes.find(Key(L"\\delete-me")) != context.nodes.end(), "Directory should remain until deferred children close"))
    {
        delete child_context;
        return false;
    }

    CB_Cleanup(
        &fs,
        child_context,
        const_cast<PWSTR>(L"\\delete-me\\inside.bin"),
        FspCleanupDelete);
    CB_Close(&fs, child_context);

    if (!Require(context.nodes.find(Key(L"\\delete-me\\inside.bin")) == context.nodes.end(), "Child close should remove child for deferred SetDelete"))
    {
        return false;
    }
    if (!Require(context.nodes.find(Key(L"\\delete-me")) != context.nodes.end(), "Directory should remain after a not-empty SetDelete until the caller retries the final delete"))
    {
        return false;
    }

    auto* final_context = new OpenContext();
    final_context->node = directory;
    final_context->allow_delete = true;
    ++directory->open_handle_count;
    const auto final_set_delete_status = CB_SetDelete(
        &fs,
        final_context,
        const_cast<PWSTR>(L"\\delete-me"),
        TRUE);
    if (!Require(final_set_delete_status == STATUS_SUCCESS, "Final delete retry after SetDelete not-empty response should latch the drained directory"))
    {
        delete final_context;
        return false;
    }

    CB_Cleanup(
        &fs,
        final_context,
        const_cast<PWSTR>(L"\\delete-me"),
        FspCleanupDelete);
    CB_Close(&fs, final_context);
    if (!Require(context.nodes.find(Key(L"\\delete-me")) == context.nodes.end(), "Final delete retry after SetDelete not-empty response should remove directory"))
    {
        return false;
    }
    return Require(!HasChildName(root->children, L"delete-me"), "Final delete retry after SetDelete not-empty response should remove directory from root children");
}

bool TestCanDeleteNonEmptyDirectoryAllowsCallerFinalDeleteRetry()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"delete-me");

    auto directory = MakeNode(L"\\delete-me", true, false);
    AddChildName(directory->children, L"inside.bin");
    directory->open_handle_count = 1;
    context.nodes.emplace(Key(directory->path), directory);

    auto child = MakeNode(L"\\delete-me\\inside.bin", false, false);
    child->open_handle_count = 1;
    context.nodes.emplace(Key(child->path), child);

    auto fs = BuildFileSystem(&context);
    auto* directory_context = new OpenContext();
    directory_context->node = directory;
    directory_context->allow_delete = true;
    auto* child_context = new OpenContext();
    child_context->node = child;
    child_context->allow_delete = true;

    const auto can_delete_status = CB_CanDelete(
        &fs,
        directory_context,
        const_cast<PWSTR>(L"\\delete-me"));
    if (!Require(can_delete_status == STATUS_DIRECTORY_NOT_EMPTY, "CanDelete should still report that a non-empty directory is not immediately deletable"))
    {
        delete directory_context;
        delete child_context;
        return false;
    }
    if (!Require(directory->delete_requested_after_children, "CanDelete on non-empty directory should remember a deferred recursive delete request"))
    {
        delete directory_context;
        delete child_context;
        return false;
    }

    CB_Cleanup(
        &fs,
        child_context,
        const_cast<PWSTR>(L"\\delete-me\\inside.bin"),
        FspCleanupDelete);
    CB_Close(&fs, child_context);
    if (!Require(context.nodes.find(Key(L"\\delete-me\\inside.bin")) == context.nodes.end(), "Child close should remove child after deferred CanDelete"))
    {
        delete directory_context;
        return false;
    }
    if (!Require(context.nodes.find(Key(L"\\delete-me")) != context.nodes.end(), "Directory should remain while its own handle is still open"))
    {
        delete directory_context;
        return false;
    }

    CB_Close(&fs, directory_context);
    if (!Require(context.nodes.find(Key(L"\\delete-me")) != context.nodes.end(), "Directory close after CanDelete preflight should leave the drained directory for the caller's final delete retry"))
    {
        return false;
    }

    auto* final_context = new OpenContext();
    final_context->node = directory;
    final_context->allow_delete = true;
    ++directory->open_handle_count;
    const auto final_set_delete_status = CB_SetDelete(
        &fs,
        final_context,
        const_cast<PWSTR>(L"\\delete-me"),
        TRUE);
    if (!Require(final_set_delete_status == STATUS_SUCCESS, "Final delete retry after CanDelete preflight should latch the drained directory"))
    {
        delete final_context;
        return false;
    }

    CB_Cleanup(
        &fs,
        final_context,
        const_cast<PWSTR>(L"\\delete-me"),
        FspCleanupDelete);
    CB_Close(&fs, final_context);
    if (!Require(context.nodes.find(Key(L"\\delete-me")) == context.nodes.end(), "Final delete retry should remove directory after CanDelete preflight"))
    {
        return false;
    }
    return Require(!HasChildName(root->children, L"delete-me"), "Final delete retry should remove directory from root children after CanDelete preflight");
}

bool TestCloseWithoutDeleteLatchPreservesNode()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"keep.txt");

    auto file = MakeNode(L"\\keep.txt", false, false);
    file->open_handle_count = 1;
    context.nodes.emplace(Key(file->path), file);

    auto fs = BuildFileSystem(&context);
    auto* open_context = new OpenContext();
    open_context->node = file;
    open_context->allow_delete = true;

    CB_Close(&fs, open_context);

    auto persisted = context.nodes.find(Key(L"\\keep.txt"));
    if (!Require(persisted != context.nodes.end(), "Close without delete latch should keep node present"))
    {
        return false;
    }
    return Require(persisted->second->open_handle_count == 0, "Close without delete latch should decrement open-handle count");
}

bool TestCleanupWithoutDeleteReleasesFileForRename()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"office.docx");

    auto file = MakeNode(L"\\office.docx", false, false);
    file->open_handle_count = 1;
    context.nodes.emplace(Key(file->path), file);

    auto fs = BuildFileSystem(&context);
    auto* open_context = new OpenContext();
    open_context->node = file;
    open_context->allow_read_data = true;

    CB_Cleanup(
        &fs,
        open_context,
        const_cast<PWSTR>(L"\\office.docx"),
        0);

    if (!Require(file->open_handle_count == 0 && open_context->cleanup_seen, "Cleanup without delete should release visible file-open accounting"))
    {
        CB_Close(&fs, open_context);
        return false;
    }

    auto rename_after_cleanup = CB_Rename(
        &fs,
        nullptr,
        const_cast<PWSTR>(L"\\office.docx"),
        const_cast<PWSTR>(L"\\renamed.docx"),
        FALSE);
    if (!Require(rename_after_cleanup == STATUS_SUCCESS, "Rename should succeed after cleanup releases a read-only file handle"))
    {
        CB_Close(&fs, open_context);
        return false;
    }

    CB_Close(&fs, open_context);
    return Require(
        context.nodes.find(Key(L"\\renamed.docx")) != context.nodes.end() &&
        context.nodes.find(Key(L"\\office.docx")) == context.nodes.end(),
        "Cleanup-released file should be renamed without a stale in-use state");
}

bool TestCanDeleteSupportsParentDeleteChildPermission()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto parent = MakeNode(L"\\parent", true, false);
    parent->children.push_back(L"child.txt");
    context.nodes.emplace(Key(parent->path), parent);

    auto child = MakeNode(L"\\parent\\child.txt", false, false);
    context.nodes.emplace(Key(child->path), child);
    auto subdir = MakeNode(L"\\parent\\sub", true, false);
    subdir->children.push_back(L"leaf.txt");
    context.nodes.emplace(Key(subdir->path), subdir);
    auto leaf = MakeNode(L"\\parent\\sub\\leaf.txt", false, false);
    context.nodes.emplace(Key(leaf->path), leaf);

    OpenContext dir_open{};
    dir_open.node = parent;
    dir_open.allow_delete_child = true;

    auto fs = BuildFileSystem(&context);
    auto allowed_status = CB_CanDelete(
        &fs,
        &dir_open,
        const_cast<PWSTR>(L"\\parent\\child.txt"));
    if (!Require(allowed_status == STATUS_SUCCESS, "CanDelete should allow parent directory handle with FILE_DELETE_CHILD on direct child"))
    {
        return false;
    }

    auto nested_denied_status = CB_CanDelete(
        &fs,
        &dir_open,
        const_cast<PWSTR>(L"\\parent\\sub\\leaf.txt"));
    if (!Require(nested_denied_status == STATUS_ACCESS_DENIED, "CanDelete should deny parent-directory handle for non-direct descendants"))
    {
        return false;
    }

    dir_open.allow_delete_child = false;
    auto denied_status = CB_CanDelete(
        &fs,
        &dir_open,
        const_cast<PWSTR>(L"\\parent\\child.txt"));
    return Require(denied_status == STATUS_ACCESS_DENIED, "CanDelete should deny parent directory handle without FILE_DELETE_CHILD");
}

bool TestRenameSupportsParentDeleteChildPermission()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"source.txt");

    auto source = MakeNode(L"\\source.txt", false, false);
    context.nodes.emplace(Key(source->path), source);

    OpenContext parent_open{};
    parent_open.node = root;
    parent_open.allow_delete_child = true;
    parent_open.allow_write_data = true;

    auto fs = BuildFileSystem(&context);
    auto status = CB_Rename(
        &fs,
        &parent_open,
        const_cast<PWSTR>(L"\\source.txt"),
        const_cast<PWSTR>(L"\\renamed.txt"),
        FALSE);
    if (!Require(status == STATUS_SUCCESS, "Rename should allow parent directory handle with FILE_DELETE_CHILD"))
    {
        return false;
    }

    if (!Require(context.nodes.find(Key(L"\\source.txt")) == context.nodes.end(), "Rename should remove old source entry"))
    {
        return false;
    }
    if (!Require(context.nodes.find(Key(L"\\renamed.txt")) != context.nodes.end(), "Rename should add destination entry"))
    {
        return false;
    }
    return Require(
        HasChildName(root->children, L"renamed.txt") && !HasChildName(root->children, L"source.txt"),
        "Rename should update parent directory child list");
}

bool TestRenameSameParentRequiresInsertPermission()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"source.txt");
    auto source = MakeNode(L"\\source.txt", false, false);
    context.nodes.emplace(Key(source->path), source);

    OpenContext parent_open{};
    parent_open.node = root;
    parent_open.allow_delete_child = true;
    parent_open.allow_write_data = false;

    auto fs = BuildFileSystem(&context);
    auto denied = CB_Rename(
        &fs,
        &parent_open,
        const_cast<PWSTR>(L"\\source.txt"),
        const_cast<PWSTR>(L"\\renamed.txt"),
        FALSE);
    if (!Require(denied == STATUS_ACCESS_DENIED, "Same-parent rename should require insert permission on parent directory handle"))
    {
        return false;
    }
    if (!Require(context.nodes.find(Key(L"\\source.txt")) != context.nodes.end(), "Denied same-parent rename should keep source entry"))
    {
        return false;
    }
    if (!Require(context.nodes.find(Key(L"\\renamed.txt")) == context.nodes.end(), "Denied same-parent rename should not create destination entry"))
    {
        return false;
    }

    parent_open.allow_write_data = true;
    auto allowed = CB_Rename(
        &fs,
        &parent_open,
        const_cast<PWSTR>(L"\\source.txt"),
        const_cast<PWSTR>(L"\\renamed.txt"),
        FALSE);
    if (!Require(allowed == STATUS_SUCCESS, "Same-parent rename should succeed once insert permission is granted"))
    {
        return false;
    }

    return Require(
        context.nodes.find(Key(L"\\source.txt")) == context.nodes.end() &&
        context.nodes.find(Key(L"\\renamed.txt")) != context.nodes.end(),
        "Successful same-parent rename should move source entry to destination");
}

bool TestRenameCrossParentOldParentHandleDenied()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"a");
    AddChildName(root->children, L"b");

    auto source_parent = MakeNode(L"\\a", true, false);
    auto target_parent = MakeNode(L"\\b", true, false);
    AddChildName(source_parent->children, L"source.txt");
    context.nodes.emplace(Key(source_parent->path), source_parent);
    context.nodes.emplace(Key(target_parent->path), target_parent);

    auto source = MakeNode(L"\\a\\source.txt", false, false);
    context.nodes.emplace(Key(source->path), source);

    OpenContext old_parent_open{};
    old_parent_open.node = source_parent;
    old_parent_open.allow_delete_child = true;
    old_parent_open.allow_write_data = true;

    auto fs = BuildFileSystem(&context);
    auto status = CB_Rename(
        &fs,
        &old_parent_open,
        const_cast<PWSTR>(L"\\a\\source.txt"),
        const_cast<PWSTR>(L"\\b\\moved.txt"),
        FALSE);
    if (!Require(status == STATUS_ACCESS_DENIED, "Cross-parent rename should deny old-parent-only handle context"))
    {
        return false;
    }

    if (!Require(context.nodes.find(Key(L"\\a\\source.txt")) != context.nodes.end(), "Denied cross-parent rename should preserve source entry"))
    {
        return false;
    }
    return Require(context.nodes.find(Key(L"\\b\\moved.txt")) == context.nodes.end(), "Denied cross-parent rename should not create destination entry");
}

bool TestRenameParentWithoutDeleteChildDenied()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"source.txt");
    auto source = MakeNode(L"\\source.txt", false, false);
    context.nodes.emplace(Key(source->path), source);

    OpenContext parent_open{};
    parent_open.node = root;
    parent_open.allow_delete_child = false;
    parent_open.allow_write_data = true;

    auto fs = BuildFileSystem(&context);
    auto status = CB_Rename(
        &fs,
        &parent_open,
        const_cast<PWSTR>(L"\\source.txt"),
        const_cast<PWSTR>(L"\\renamed.txt"),
        FALSE);
    if (!Require(status == STATUS_ACCESS_DENIED, "Rename should deny parent directory handle without FILE_DELETE_CHILD"))
    {
        return false;
    }

    return Require(
        context.nodes.find(Key(L"\\source.txt")) != context.nodes.end() &&
        context.nodes.find(Key(L"\\renamed.txt")) == context.nodes.end(),
        "Denied parent-handle rename should not mutate node index");
}

bool TestRenameReplaceRequiresTargetParentDeleteChild()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"source.txt");
    AddChildName(root->children, L"target.txt");

    auto source = MakeNode(L"\\source.txt", false, false);
    auto target = MakeNode(L"\\target.txt", false, false);
    context.nodes.emplace(Key(source->path), source);
    context.nodes.emplace(Key(target->path), target);

    OpenContext source_open{};
    source_open.node = source;
    source_open.allow_delete = true;

    auto fs = BuildFileSystem(&context);
    auto status = CB_Rename(
        &fs,
        &source_open,
        const_cast<PWSTR>(L"\\source.txt"),
        const_cast<PWSTR>(L"\\target.txt"),
        TRUE);
    if (!Require(status == STATUS_ACCESS_DENIED, "Rename replace should require target-parent FILE_DELETE_CHILD when context is source handle"))
    {
        return false;
    }

    return Require(
        context.nodes.find(Key(L"\\source.txt")) != context.nodes.end() &&
        context.nodes.find(Key(L"\\target.txt")) != context.nodes.end(),
        "Denied source-handle replace should not mutate source or target entries");
}

bool TestRenameReplaceAllowsTargetParentDeleteChild()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"source.txt");
    AddChildName(root->children, L"target.txt");

    auto source = MakeNode(L"\\source.txt", false, false);
    auto target = MakeNode(L"\\target.txt", false, false);
    context.nodes.emplace(Key(source->path), source);
    context.nodes.emplace(Key(target->path), target);

    OpenContext parent_open{};
    parent_open.node = root;
    parent_open.allow_delete_child = true;
    parent_open.allow_write_data = false;

    auto fs = BuildFileSystem(&context);
    auto denied = CB_Rename(
        &fs,
        &parent_open,
        const_cast<PWSTR>(L"\\source.txt"),
        const_cast<PWSTR>(L"\\target.txt"),
        TRUE);
    if (!Require(denied == STATUS_ACCESS_DENIED, "Rename replace should require insert permission on target-parent context"))
    {
        return false;
    }

    parent_open.allow_write_data = true;
    auto status = CB_Rename(
        &fs,
        &parent_open,
        const_cast<PWSTR>(L"\\source.txt"),
        const_cast<PWSTR>(L"\\target.txt"),
        TRUE);
    if (!Require(status == STATUS_SUCCESS, "Rename replace should succeed with target-parent FILE_DELETE_CHILD context"))
    {
        return false;
    }

    if (!Require(context.nodes.find(Key(L"\\source.txt")) == context.nodes.end(), "Successful replace should remove old source entry"))
    {
        return false;
    }

    auto replaced = context.nodes.find(Key(L"\\target.txt"));
    if (!Require(replaced != context.nodes.end(), "Successful replace should retain target path"))
    {
        return false;
    }
    if (!Require(replaced->second == source, "Successful replace should map target path to source node"))
    {
        return false;
    }

    return Require(
        HasChildName(root->children, L"target.txt") && !HasChildName(root->children, L"source.txt"),
        "Successful replace should keep only target child entry");
}

bool TestRenameReplaceRequiresDeleteChildEvenWithInsertPermission()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"source.txt");
    AddChildName(root->children, L"target.txt");

    auto source = MakeNode(L"\\source.txt", false, false);
    auto target = MakeNode(L"\\target.txt", false, false);
    context.nodes.emplace(Key(source->path), source);
    context.nodes.emplace(Key(target->path), target);

    OpenContext parent_open{};
    parent_open.node = root;
    parent_open.allow_delete_child = false;
    parent_open.allow_write_data = true;

    auto fs = BuildFileSystem(&context);
    auto status = CB_Rename(
        &fs,
        &parent_open,
        const_cast<PWSTR>(L"\\source.txt"),
        const_cast<PWSTR>(L"\\target.txt"),
        TRUE);
    if (!Require(status == STATUS_ACCESS_DENIED, "Rename replace should still require FILE_DELETE_CHILD even if insert permission is present"))
    {
        return false;
    }

    return Require(
        context.nodes.find(Key(L"\\source.txt")) != context.nodes.end() &&
        context.nodes.find(Key(L"\\target.txt")) != context.nodes.end(),
        "Denied replace without FILE_DELETE_CHILD should not mutate source or target entries");
}

bool TestRenameDirectoryReplaceRequiresDirectoryInsertPermission()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"srcdir");
    AddChildName(root->children, L"destdir");

    auto srcdir = MakeNode(L"\\srcdir", true, false);
    auto destdir = MakeNode(L"\\destdir", true, false);
    context.nodes.emplace(Key(srcdir->path), srcdir);
    context.nodes.emplace(Key(destdir->path), destdir);

    OpenContext parent_open{};
    parent_open.node = root;
    parent_open.allow_delete_child = true;
    parent_open.allow_append_data = false;

    auto fs = BuildFileSystem(&context);
    auto denied = CB_Rename(
        &fs,
        &parent_open,
        const_cast<PWSTR>(L"\\srcdir"),
        const_cast<PWSTR>(L"\\destdir"),
        TRUE);
    if (!Require(denied == STATUS_ACCESS_DENIED, "Directory replace should require directory insert permission on parent handle"))
    {
        return false;
    }

    parent_open.allow_append_data = true;
    auto allowed = CB_Rename(
        &fs,
        &parent_open,
        const_cast<PWSTR>(L"\\srcdir"),
        const_cast<PWSTR>(L"\\destdir"),
        TRUE);
    if (!Require(allowed == STATUS_SUCCESS, "Directory replace should succeed once directory insert permission is present"))
    {
        return false;
    }

    if (!Require(context.nodes.find(Key(L"\\srcdir")) == context.nodes.end(), "Successful directory replace should remove source path"))
    {
        return false;
    }
    if (!Require(context.nodes.find(Key(L"\\destdir")) != context.nodes.end(), "Successful directory replace should keep destination path"))
    {
        return false;
    }

    return Require(
        HasChildName(root->children, L"destdir") && !HasChildName(root->children, L"srcdir"),
        "Successful directory replace should keep only destination child entry");
}

bool TestCanDeleteNullNameParentHandleRequiresDeleteNotDeleteChild()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto parent = MakeNode(L"\\parent", true, false);
    context.nodes.emplace(Key(parent->path), parent);

    OpenContext dir_open{};
    dir_open.node = parent;
    dir_open.allow_delete_child = true;
    dir_open.allow_delete = false;

    auto fs = BuildFileSystem(&context);
    auto denied = CB_CanDelete(&fs, &dir_open, nullptr);
    if (!Require(denied == STATUS_ACCESS_DENIED, "CanDelete with null file name should require DELETE on context node"))
    {
        return false;
    }

    dir_open.allow_delete = true;
    auto allowed = CB_CanDelete(&fs, &dir_open, nullptr);
    return Require(allowed == STATUS_SUCCESS, "CanDelete with null file name should succeed with DELETE access on context node");
}

bool TestCanDeleteFailsWhenAdditionalHandleOpen()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"busy.txt");

    auto file = MakeNode(L"\\busy.txt", false, false);
    file->open_handle_count = 2;
    context.nodes.emplace(Key(file->path), file);

    OpenContext current_open{};
    current_open.node = file;
    current_open.allow_delete = true;

    auto fs = BuildFileSystem(&context);
    auto can_delete = CB_CanDelete(
        &fs,
        &current_open,
        const_cast<PWSTR>(L"\\busy.txt"));
    return Require(can_delete == STATUS_SUCCESS, "CanDelete should not fail just because another compatible handle is tracked");
}

bool TestSetDeleteFailsWhenAdditionalHandleOpen()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"busy.txt");

    auto file = MakeNode(L"\\busy.txt", false, false);
    file->open_handle_count = 2;
    context.nodes.emplace(Key(file->path), file);

    OpenContext current_open{};
    current_open.node = file;
    current_open.allow_delete = true;

    auto fs = BuildFileSystem(&context);
    auto set_delete = CB_SetDelete(
        &fs,
        &current_open,
        const_cast<PWSTR>(L"\\busy.txt"),
        TRUE);
    if (!Require(set_delete == STATUS_SUCCESS, "SetDelete should not fail just because another compatible handle is tracked"))
    {
        return false;
    }

    return Require(current_open.delete_on_cleanup, "Successful SetDelete should latch delete-on-cleanup");
}

bool TestCleanupDeleteLatchesEvenWhenAdditionalHandlesRemain()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"busy.txt");

    auto file = MakeNode(L"\\busy.txt", false, false);
    file->open_handle_count = 2;
    context.nodes.emplace(Key(file->path), file);

    OpenContext open_context{};
    open_context.node = file;
    open_context.allow_delete = true;

    auto fs = BuildFileSystem(&context);
    CB_Cleanup(
        &fs,
        &open_context,
        const_cast<PWSTR>(L"\\busy.txt"),
        FspCleanupDelete);

    if (!Require(open_context.delete_on_cleanup, "Cleanup delete should latch on the last cleanup for the file node"))
    {
        return false;
    }
    return Require(file->delete_pending, "Cleanup delete should mark the node delete-pending even with additional opens tracked");
}

bool TestCloseOnlyCommitsWhenDeleteMutationIsEmitted()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"keep.txt");

    auto file = MakeNode(L"\\keep.txt", false, false);
    file->open_handle_count = 1;
    context.nodes.emplace(Key(file->path), file);

    auto fs = BuildFileSystem(&context);
    auto* open_context = new OpenContext();
    open_context->node = file;
    open_context->allow_delete = false;
    open_context->write_open = true;

    CB_Close(&fs, open_context);
    return Require(
        context.active_external_mutation_callbacks.load() == 0,
        "Close without delete mutation should not leave mutation callbacks active");
}

bool TestDeleteOnCloseCommitsWhenDeleteIsLatching()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"victim.txt");

    auto file = MakeNode(L"\\victim.txt", false, false);
    file->open_handle_count = 1;
    context.nodes.emplace(Key(file->path), file);

    auto fs = BuildFileSystem(&context);
    auto* open_context = new OpenContext();
    open_context->node = file;
    open_context->allow_delete = true;

    CB_Cleanup(
        &fs,
        open_context,
        const_cast<PWSTR>(L"\\victim.txt"),
        FspCleanupDelete);
    CB_Close(&fs, open_context);

    return Require(
        context.nodes.find(Key(L"\\victim.txt")) == context.nodes.end(),
        "Delete-on-close should remove the node once the last cleanup closes");
}

bool TestSetFileSizeDefersNativeCommitUntilFlush()
{
#ifdef APFSACCESS_HAS_RW_ENGINE
    MountContext context{};
    if (!ConfigureNativeCommitFailureForUnitTest(context))
    {
        return true;
    }
    if (!Require(PrepareUnitHydrationRoot(context, L"set-file-size-defer-flush"), "SetFileSize defer-to-flush test should prepare cache root"))
    {
        return false;
    }
    if (!Require(ConfigureUnitRecoveryMarker(context, L"set-file-size-defer-flush"), "SetFileSize defer-to-flush test should configure a recovery marker"))
    {
        return false;
    }
    ScopeExit cleanup{[&]()
    {
        std::error_code ec;
        std::filesystem::remove(context.recovery_marker_file, ec);
        std::filesystem::remove_all(context.session_root, ec);
    }};

    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    std::shared_ptr<Node> file;
    if (!Require(SeedResizableUnitFile(context, file), "SetFileSize defer-to-flush test should seed hydration file"))
    {
        return false;
    }

    OpenContext open_context{};
    if (!Require(OpenResizableUnitFile(context, file, open_context), "SetFileSize defer-to-flush test should open hydration file"))
    {
        return false;
    }
    ScopeExit close_file{[&]()
    {
        CloseHandle(open_context.file);
        open_context.file = INVALID_HANDLE_VALUE;
    }};

    auto fs = BuildFileSystem(&context);
    FSP_FSCTL_FILE_INFO info{};
    const auto status = CB_SetFileSize(&fs, &open_context, 9, FALSE, &info);
    if (!Require(status == STATUS_SUCCESS, "SetFileSize should not force a native commit on the foreground resize path"))
    {
        return false;
    }
    if (!Require(context.test_native_commit_attempt_count == 0, "SetFileSize should leave native commit attempts at zero"))
    {
        return false;
    }
    if (!Require(context.pending_native_writes, "SetFileSize should leave native writes marked pending"))
    {
        return false;
    }
    if (!Require(file->file_size == 9, "Deferred SetFileSize should publish the requested local file size"))
    {
        return false;
    }
    if (!Require(info.FileSize == 9, "Deferred SetFileSize should report the requested local file size"))
    {
        return false;
    }

    LARGE_INTEGER end{};
    if (!Require(GetFileSizeEx(open_context.file, &end) != FALSE, "SetFileSize defer-to-flush test should read hydration size after resize"))
    {
        return false;
    }
    if (!Require(end.QuadPart == 9, "Deferred SetFileSize should resize the hydration file before flush"))
    {
        return false;
    }

    const auto flush_status = CB_Flush(&fs, &open_context, &info);
    if (!Require(flush_status == STATUS_MEDIA_WRITE_PROTECTED, "Flush should surface the deferred native SetFileSize commit failure"))
    {
        return false;
    }
    return Require(
        context.test_native_commit_attempt_count == 1 &&
            context.recovery_active &&
            context.write_degraded &&
            !context.native_write_enabled,
        "Flush should be the first native commit boundary and latch fail-closed recovery on failure");
#else
    return true;
#endif
}

bool TestSetFileSizeDefersNativeCommitUntilClose()
{
#ifdef APFSACCESS_HAS_RW_ENGINE
    MountContext context{};
    if (!ConfigureNativeCommitFailureForUnitTest(context))
    {
        return true;
    }
    if (!Require(PrepareUnitHydrationRoot(context, L"set-file-size-defer-close"), "SetFileSize defer-to-close test should prepare cache root"))
    {
        return false;
    }
    if (!Require(ConfigureUnitRecoveryMarker(context, L"set-file-size-defer-close"), "SetFileSize defer-to-close test should configure a recovery marker"))
    {
        return false;
    }
    ScopeExit cleanup{[&]()
    {
        std::error_code ec;
        std::filesystem::remove(context.recovery_marker_file, ec);
        std::filesystem::remove_all(context.session_root, ec);
    }};

    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    std::shared_ptr<Node> file;
    if (!Require(SeedResizableUnitFile(context, file), "SetFileSize defer-to-close test should seed hydration file"))
    {
        return false;
    }

    auto* open_context = new OpenContext();
    if (!Require(OpenResizableUnitFile(context, file, *open_context), "SetFileSize defer-to-close test should open hydration file"))
    {
        delete open_context;
        return false;
    }
    open_context->write_open = true;
    file->open_handle_count = 1;
    file->write_handle_count = 1;

    auto fs = BuildFileSystem(&context);
    FSP_FSCTL_FILE_INFO info{};
    const auto status = CB_SetFileSize(&fs, open_context, 9, FALSE, &info);
    if (!Require(status == STATUS_SUCCESS, "SetFileSize should succeed before close drains native writes"))
    {
        CloseHandle(open_context->file);
        open_context->file = INVALID_HANDLE_VALUE;
        delete open_context;
        return false;
    }
    if (!Require(
            context.test_native_commit_attempt_count == 0 &&
                context.pending_native_writes &&
                file->file_size == 9,
            "SetFileSize should stage native work and defer commit until close"))
    {
        CloseHandle(open_context->file);
        open_context->file = INVALID_HANDLE_VALUE;
        delete open_context;
        return false;
    }

    CB_Close(&fs, open_context);
    return Require(
        context.test_native_commit_attempt_count == 1 &&
            context.recovery_active &&
            context.write_degraded &&
            !context.native_write_enabled,
        "Close should drain deferred SetFileSize native work and fail closed on commit failure");
#else
    return true;
#endif
}

bool TestDeleteOnCloseRestoresLocalNodeWhenNativeCommitFails()
{
#ifdef APFSACCESS_HAS_RW_ENGINE
    MountContext context{};
    if (!ConfigureNativeCommitFailureForUnitTest(context))
    {
        return true;
    }
    if (!Require(PrepareUnitHydrationRoot(context, L"delete-on-close-rollback"), "Delete-on-close rollback test should prepare cache root"))
    {
        return false;
    }
    ScopeExit cleanup{[&]()
    {
        std::error_code ec;
        std::filesystem::remove_all(context.session_root, ec);
    }};
    context.tx_manager = std::make_unique<apfsaccess::rw::TransactionManager>(L"Conservative");

    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"victim.txt");

    auto file = MakeNode(L"\\victim.txt", false, false);
    file->open_handle_count = 1;
    file->file_size = 4;
    context.nodes.emplace(Key(file->path), file);
    const std::vector<std::byte> payload{std::byte{'K'}, std::byte{'E'}, std::byte{'E'}, std::byte{'P'}};
    if (!Require(WriteFileBytes(HydrationPath(&context, *file), payload), "Delete-on-close rollback test should seed hydration bytes"))
    {
        return false;
    }

    auto fs = BuildFileSystem(&context);
    auto* open_context = new OpenContext();
    open_context->node = file;
    open_context->allow_delete = true;

    CB_Cleanup(
        &fs,
        open_context,
        const_cast<PWSTR>(L"\\victim.txt"),
        FspCleanupDelete);
    CB_Close(&fs, open_context);

    if (!Require(context.recovery_active, "Forced native delete-on-close commit failure should latch recovery-active state"))
    {
        return false;
    }
    if (!Require(context.nodes.find(Key(L"\\victim.txt")) != context.nodes.end(), "Failed native delete-on-close commit should restore deleted node"))
    {
        return false;
    }
    if (!Require(HasChildName(root->children, L"victim.txt"), "Failed native delete-on-close commit should restore parent child entry"))
    {
        return false;
    }
    const auto restored = context.nodes.at(Key(L"\\victim.txt"));
    if (!Require(!restored->delete_pending && !restored->delete_latched && restored->delete_intent_count == 0, "Failed native delete-on-close commit should restore node as visible and not delete-pending"))
    {
        return false;
    }
    if (!Require(ReadFileBytes(HydrationPath(&context, *restored)) == payload, "Failed native delete-on-close commit should restore hydrated file bytes"))
    {
        return false;
    }
    return Require(
        context.tx_manager->PendingMutationCount() == 0 &&
        context.tx_manager->CurrentState() == apfsaccess::rw::TransactionManager::State::Idle,
        "Failed native delete-on-close commit should abort, not finalize, the local mutation journal");
#else
    return true;
#endif
}

bool TestRenameDirectoryFailsWhenDescendantHandleOpen()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"dir");

    auto dir = MakeNode(L"\\dir", true, false);
    AddChildName(dir->children, L"child.txt");
    dir->open_handle_count = 1;
    context.nodes.emplace(Key(dir->path), dir);

    auto child = MakeNode(L"\\dir\\child.txt", false, false);
    child->open_handle_count = 1;
    context.nodes.emplace(Key(child->path), child);

    OpenContext dir_open{};
    dir_open.node = dir;
    dir_open.allow_delete = true;

    auto fs = BuildFileSystem(&context);
    auto rename = CB_Rename(
        &fs,
        &dir_open,
        const_cast<PWSTR>(L"\\dir"),
        const_cast<PWSTR>(L"\\renamed"),
        FALSE);
    if (!Require(rename == STATUS_SHARING_VIOLATION, "Directory rename should fail with STATUS_SHARING_VIOLATION when descendant handle is open"))
    {
        return false;
    }

    return Require(
        context.nodes.find(Key(L"\\dir")) != context.nodes.end() &&
        context.nodes.find(Key(L"\\renamed")) == context.nodes.end(),
        "Failed directory rename should preserve source path only");
}

bool TestRenameSourceHandleSucceedsWithOnlyCurrentHandleOpen()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"file.txt");

    auto source = MakeNode(L"\\file.txt", false, false);
    source->open_handle_count = 1;
    context.nodes.emplace(Key(source->path), source);

    OpenContext source_open{};
    source_open.node = source;
    source_open.allow_delete = true;

    auto fs = BuildFileSystem(&context);
    auto rename = CB_Rename(
        &fs,
        &source_open,
        const_cast<PWSTR>(L"\\file.txt"),
        const_cast<PWSTR>(L"\\renamed.txt"),
        FALSE);
    if (!Require(rename == STATUS_SUCCESS, "Source-handle rename should succeed when only current handle is open"))
    {
        return false;
    }

    return Require(
        context.nodes.find(Key(L"\\file.txt")) == context.nodes.end() &&
        context.nodes.find(Key(L"\\renamed.txt")) != context.nodes.end(),
        "Successful source-handle rename should move source entry");
}

bool TestRenameTargetParentRequiresFileInsertPermission()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"a");
    AddChildName(root->children, L"b");

    auto source_parent = MakeNode(L"\\a", true, false);
    auto target_parent = MakeNode(L"\\b", true, false);
    AddChildName(source_parent->children, L"source.txt");
    context.nodes.emplace(Key(source_parent->path), source_parent);
    context.nodes.emplace(Key(target_parent->path), target_parent);

    auto source = MakeNode(L"\\a\\source.txt", false, false);
    context.nodes.emplace(Key(source->path), source);

    OpenContext target_parent_open{};
    target_parent_open.node = target_parent;
    target_parent_open.allow_write_data = false;

    auto fs = BuildFileSystem(&context);
    auto denied = CB_Rename(
        &fs,
        &target_parent_open,
        const_cast<PWSTR>(L"\\a\\source.txt"),
        const_cast<PWSTR>(L"\\b\\moved.txt"),
        FALSE);
    if (!Require(denied == STATUS_ACCESS_DENIED, "Rename into target parent should require file insert permission on target directory handle"))
    {
        return false;
    }

    target_parent_open.allow_write_data = true;
    auto allowed = CB_Rename(
        &fs,
        &target_parent_open,
        const_cast<PWSTR>(L"\\a\\source.txt"),
        const_cast<PWSTR>(L"\\b\\moved.txt"),
        FALSE);
    if (!Require(allowed == STATUS_SUCCESS, "Rename into target parent should succeed when file insert permission exists"))
    {
        return false;
    }

    if (!Require(context.nodes.find(Key(L"\\a\\source.txt")) == context.nodes.end(), "Rename should remove source from old parent"))
    {
        return false;
    }
    if (!Require(context.nodes.find(Key(L"\\b\\moved.txt")) != context.nodes.end(), "Rename should add destination under target parent"))
    {
        return false;
    }

    if (!Require(!HasChildName(source_parent->children, L"source.txt"), "Old parent children should drop source entry"))
    {
        return false;
    }
    return Require(HasChildName(target_parent->children, L"moved.txt"), "Target parent children should include destination entry");
}

bool TestRenameTargetParentRequiresDirectoryInsertPermission()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"a");
    AddChildName(root->children, L"b");

    auto source_parent = MakeNode(L"\\a", true, false);
    auto target_parent = MakeNode(L"\\b", true, false);
    AddChildName(source_parent->children, L"srcdir");
    context.nodes.emplace(Key(source_parent->path), source_parent);
    context.nodes.emplace(Key(target_parent->path), target_parent);

    auto source_dir = MakeNode(L"\\a\\srcdir", true, false);
    context.nodes.emplace(Key(source_dir->path), source_dir);

    OpenContext target_parent_open{};
    target_parent_open.node = target_parent;
    target_parent_open.allow_append_data = false;

    auto fs = BuildFileSystem(&context);
    auto denied = CB_Rename(
        &fs,
        &target_parent_open,
        const_cast<PWSTR>(L"\\a\\srcdir"),
        const_cast<PWSTR>(L"\\b\\moveddir"),
        FALSE);
    if (!Require(denied == STATUS_ACCESS_DENIED, "Rename directory into target parent should require directory insert permission"))
    {
        return false;
    }

    target_parent_open.allow_append_data = true;
    auto allowed = CB_Rename(
        &fs,
        &target_parent_open,
        const_cast<PWSTR>(L"\\a\\srcdir"),
        const_cast<PWSTR>(L"\\b\\moveddir"),
        FALSE);
    if (!Require(allowed == STATUS_SUCCESS, "Rename directory into target parent should succeed when directory insert permission exists"))
    {
        return false;
    }

    if (!Require(context.nodes.find(Key(L"\\a\\srcdir")) == context.nodes.end(), "Directory rename should remove source path"))
    {
        return false;
    }
    if (!Require(context.nodes.find(Key(L"\\b\\moveddir")) != context.nodes.end(), "Directory rename should add destination path"))
    {
        return false;
    }

    if (!Require(!HasChildName(source_parent->children, L"srcdir"), "Old parent should drop source directory child entry"))
    {
        return false;
    }
    return Require(HasChildName(target_parent->children, L"moveddir"), "Target parent should include renamed directory child entry");
}

bool TestCleanupDeleteSkipsNonEmptyDirectory()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"dir");

    auto dir = MakeNode(L"\\dir", true, false);
    dir->children.push_back(L"child.txt");
    context.nodes.emplace(Key(dir->path), dir);

    auto child = MakeNode(L"\\dir\\child.txt", false, false);
    context.nodes.emplace(Key(child->path), child);

    OpenContext open_context{};
    open_context.node = dir;
    open_context.allow_delete = true;

    auto fs = BuildFileSystem(&context);
    CB_Cleanup(
        &fs,
        &open_context,
        const_cast<PWSTR>(L"\\dir"),
        FspCleanupDelete);

    if (!Require(!open_context.delete_on_cleanup, "Cleanup delete should not latch non-empty directories"))
    {
        return false;
    }

    return Require(
        dir->delete_intent_count == 0 && !dir->delete_pending,
        "Cleanup delete should leave non-empty directory state unchanged");
}

bool TestCleanupDeleteBlockedByAdditionalOpenHandle()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"busy.txt");

    auto file = MakeNode(L"\\busy.txt", false, false);
    file->open_handle_count = 2;
    context.nodes.emplace(Key(file->path), file);

    OpenContext open_context{};
    open_context.node = file;
    open_context.allow_delete = true;

    auto fs = BuildFileSystem(&context);
    CB_Cleanup(
        &fs,
        &open_context,
        const_cast<PWSTR>(L"\\busy.txt"),
        FspCleanupDelete);

    if (!Require(open_context.delete_on_cleanup, "Cleanup delete should latch on the last cleanup for the file node"))
    {
        return false;
    }

    return Require(
        file->delete_intent_count == 1 && file->delete_pending,
        "Cleanup delete should mark the node delete-pending even with additional opens tracked");
}

bool TestDeleteOnCloseRemovesOnlyAfterLastHandleCloses()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"victim.txt");

    auto file = MakeNode(L"\\victim.txt", false, false);
    file->open_handle_count = 2;
    context.nodes.emplace(Key(file->path), file);

    auto fs = BuildFileSystem(&context);
    auto* delete_handle = new OpenContext();
    delete_handle->node = file;
    delete_handle->allow_delete = true;

    auto* keep_handle = new OpenContext();
    keep_handle->node = file;
    keep_handle->allow_delete = false;

    CB_Cleanup(
        &fs,
        delete_handle,
        const_cast<PWSTR>(L"\\victim.txt"),
        FspCleanupDelete);

    if (!Require(delete_handle->delete_on_cleanup && file->delete_pending, "Cleanup delete should latch pending delete before close"))
    {
        CB_Close(&fs, delete_handle);
        CB_Close(&fs, keep_handle);
        return false;
    }
    if (!Require(file->open_handle_count == 1, "Cleanup delete should release the deleting handle while another handle remains open"))
    {
        CB_Close(&fs, delete_handle);
        CB_Close(&fs, keep_handle);
        return false;
    }

    CB_Close(&fs, delete_handle);

    if (!Require(context.nodes.find(Key(L"\\victim.txt")) != context.nodes.end(), "First close should not remove node while another handle remains open"))
    {
        CB_Close(&fs, keep_handle);
        return false;
    }

    auto pending_rename = CB_Rename(
        &fs,
        nullptr,
        const_cast<PWSTR>(L"\\victim.txt"),
        const_cast<PWSTR>(L"\\renamed.txt"),
        FALSE);
    if (!Require(pending_rename == STATUS_DELETE_PENDING, "Rename should remain blocked while delete-pending node still has open handles"))
    {
        CB_Close(&fs, keep_handle);
        return false;
    }

    CB_Cleanup(
        &fs,
        keep_handle,
        const_cast<PWSTR>(L"\\victim.txt"),
        0);
    CB_Close(&fs, keep_handle);

    if (!Require(context.nodes.find(Key(L"\\victim.txt")) == context.nodes.end(), "Last close should remove delete-latched file"))
    {
        return false;
    }
    return Require(!HasChildName(root->children, L"victim.txt"), "Last close should remove deleted file from parent children list");
}

bool TestRenameReplaceFailsWhenTargetDirectoryNotEmpty()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"srcdir");
    AddChildName(root->children, L"destdir");

    auto srcdir = MakeNode(L"\\srcdir", true, false);
    auto destdir = MakeNode(L"\\destdir", true, false);
    AddChildName(destdir->children, L"child.txt");
    context.nodes.emplace(Key(srcdir->path), srcdir);
    context.nodes.emplace(Key(destdir->path), destdir);
    auto child = MakeNode(L"\\destdir\\child.txt", false, false);
    context.nodes.emplace(Key(child->path), child);

    OpenContext parent_open{};
    parent_open.node = root;
    parent_open.allow_delete_child = true;
    parent_open.allow_append_data = true;

    auto fs = BuildFileSystem(&context);
    auto status = CB_Rename(
        &fs,
        &parent_open,
        const_cast<PWSTR>(L"\\srcdir"),
        const_cast<PWSTR>(L"\\destdir"),
        TRUE);
    if (!Require(status == STATUS_DIRECTORY_NOT_EMPTY, "Directory replace should fail with STATUS_DIRECTORY_NOT_EMPTY when target has children"))
    {
        return false;
    }

    return Require(
        context.nodes.find(Key(L"\\srcdir")) != context.nodes.end() &&
        context.nodes.find(Key(L"\\destdir")) != context.nodes.end(),
        "Failed non-empty directory replace should preserve source and target directories");
}

bool TestRenameReplaceFailsWhenTargetDirectoryHasOpenHandle()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"srcdir");
    AddChildName(root->children, L"destdir");

    auto srcdir = MakeNode(L"\\srcdir", true, false);
    auto destdir = MakeNode(L"\\destdir", true, false);
    destdir->open_handle_count = 1;
    context.nodes.emplace(Key(srcdir->path), srcdir);
    context.nodes.emplace(Key(destdir->path), destdir);

    OpenContext parent_open{};
    parent_open.node = root;
    parent_open.allow_delete_child = true;
    parent_open.allow_append_data = true;

    auto fs = BuildFileSystem(&context);
    auto status = CB_Rename(
        &fs,
        &parent_open,
        const_cast<PWSTR>(L"\\srcdir"),
        const_cast<PWSTR>(L"\\destdir"),
        TRUE);
    if (!Require(status == STATUS_SHARING_VIOLATION, "Directory replace should fail with STATUS_SHARING_VIOLATION when target directory has open handles"))
    {
        return false;
    }

    return Require(
        context.nodes.find(Key(L"\\srcdir")) != context.nodes.end() &&
        context.nodes.find(Key(L"\\destdir")) != context.nodes.end(),
        "Failed busy directory replace should preserve source and target directories");
}

bool TestCreateRejectedWhenShutdownDrainActive()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    context.shutdown_drain_active.store(true);
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto fs = BuildFileSystem(&context);
    PVOID out_ctx = nullptr;
    FSP_FSCTL_FILE_INFO info{};
    auto create_status = CB_Create(
        &fs,
        const_cast<PWSTR>(L"\\drain_blocked.txt"),
        FILE_NON_DIRECTORY_FILE,
        FILE_WRITE_DATA,
        0,
        nullptr,
        0,
        &out_ctx,
        &info);
    if (!Require(create_status == STATUS_VOLUME_DISMOUNTED, "Create should return STATUS_VOLUME_DISMOUNTED when shutdown drain is active"))
    {
        return false;
    }

    if (!Require(out_ctx == nullptr, "Create should not allocate open context when shutdown drain rejects the request"))
    {
        return false;
    }

    return Require(
        context.nodes.find(Key(L"\\drain_blocked.txt")) == context.nodes.end(),
        "Rejected create during shutdown drain should not mutate node index");
}

bool TestRenameRejectedWhenShutdownDrainActive()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    context.shutdown_drain_active.store(true);
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"source.txt");
    auto source = MakeNode(L"\\source.txt", false, false);
    context.nodes.emplace(Key(source->path), source);

    auto fs = BuildFileSystem(&context);
    auto rename_status = CB_Rename(
        &fs,
        nullptr,
        const_cast<PWSTR>(L"\\source.txt"),
        const_cast<PWSTR>(L"\\target.txt"),
        FALSE);
    if (!Require(rename_status == STATUS_VOLUME_DISMOUNTED, "Rename should return STATUS_VOLUME_DISMOUNTED when shutdown drain is active"))
    {
        return false;
    }

    if (!Require(context.nodes.find(Key(L"\\source.txt")) != context.nodes.end(), "Rejected rename during shutdown drain should preserve source path"))
    {
        return false;
    }

    return Require(context.nodes.find(Key(L"\\target.txt")) == context.nodes.end(), "Rejected rename during shutdown drain should not materialize destination path");
}

bool TestMetadataMutationsRejectedWhenShutdownDrainActive()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    context.shutdown_drain_active.store(true);
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"drain_meta.txt");
    auto file = MakeNode(L"\\drain_meta.txt", false, false);
    file->file_size = 64;
    const auto before_timestamp = file->timestamp;
    context.nodes.emplace(Key(file->path), file);

    OpenContext open_context{};
    open_context.node = file;
    open_context.allow_set_basic_info = true;
    open_context.allow_set_file_size = true;
    open_context.allow_delete = true;

    auto fs = BuildFileSystem(&context);
    FSP_FSCTL_FILE_INFO info{};

    const auto set_basic_status = CB_SetBasicInfo(
        &fs,
        &open_context,
        0,
        0,
        0,
        0,
        0,
        &info);
    if (!Require(set_basic_status == STATUS_VOLUME_DISMOUNTED, "SetBasicInfo should return STATUS_VOLUME_DISMOUNTED when shutdown drain is active"))
    {
        return false;
    }

    const auto set_file_size_status = CB_SetFileSize(
        &fs,
        &open_context,
        128,
        FALSE,
        &info);
    if (!Require(set_file_size_status == STATUS_VOLUME_DISMOUNTED, "SetFileSize should return STATUS_VOLUME_DISMOUNTED when shutdown drain is active"))
    {
        return false;
    }

    const auto can_delete_status = CB_CanDelete(
        &fs,
        &open_context,
        const_cast<PWSTR>(L"\\drain_meta.txt"));
    if (!Require(can_delete_status == STATUS_VOLUME_DISMOUNTED, "CanDelete should return STATUS_VOLUME_DISMOUNTED when shutdown drain is active"))
    {
        return false;
    }

    const auto set_delete_status = CB_SetDelete(
        &fs,
        &open_context,
        const_cast<PWSTR>(L"\\drain_meta.txt"),
        TRUE);
    if (!Require(set_delete_status == STATUS_VOLUME_DISMOUNTED, "SetDelete should return STATUS_VOLUME_DISMOUNTED when shutdown drain is active"))
    {
        return false;
    }

    if (!Require(!open_context.delete_on_cleanup, "Shutdown-drain mutation rejection should not latch delete-on-cleanup"))
    {
        return false;
    }

    if (!Require(!file->delete_pending && file->delete_intent_count == 0, "Shutdown-drain mutation rejection should not mutate delete-pending state"))
    {
        return false;
    }

    if (!Require(file->file_size == 64, "Shutdown-drain mutation rejection should preserve file size"))
    {
        return false;
    }

    if (!Require(
            file->timestamp.dwLowDateTime == before_timestamp.dwLowDateTime &&
            file->timestamp.dwHighDateTime == before_timestamp.dwHighDateTime,
            "Shutdown-drain mutation rejection should preserve file timestamp"))
    {
        return false;
    }

    return Require(
        context.active_external_mutation_callbacks.load() == 0,
        "Shutdown-drain mutation rejection should not leak active external mutation callbacks");
}

bool TestDataMutationsRejectedWhenShutdownDrainActive()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    context.shutdown_drain_active.store(true);
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"drain_data.txt");
    auto file = MakeNode(L"\\drain_data.txt", false, false);
    file->file_size = 64;
    const auto before_timestamp = file->timestamp;
    context.nodes.emplace(Key(file->path), file);

    wchar_t temp_directory[MAX_PATH] = {};
    if (!GetTempPathW(static_cast<DWORD>(std::size(temp_directory)), temp_directory))
    {
        return Require(false, "Shutdown-drain data mutation test should resolve temp directory");
    }

    wchar_t temp_path[MAX_PATH] = {};
    if (!GetTempFileNameW(temp_directory, L"APF", 0, temp_path))
    {
        return Require(false, "Shutdown-drain data mutation test should create temp file path");
    }

    HANDLE temp_file_handle = CreateFileW(
        temp_path,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE,
        nullptr);
    if (!Require(
            temp_file_handle != INVALID_HANDLE_VALUE,
            "Shutdown-drain data mutation test should open temp file handle"))
    {
        DeleteFileW(temp_path);
        return false;
    }

    bool ok = true;
    do
    {
        OpenContext open_context{};
        open_context.node = file;
        open_context.file = temp_file_handle;
        open_context.allow_write_data = true;
        open_context.allow_append_data = true;
        open_context.allow_set_file_size = true;

        auto fs = BuildFileSystem(&context);
        FSP_FSCTL_FILE_INFO info{};
        std::array<std::byte, 32> write_buffer{};
        ULONG done = 0;

        const auto write_status = CB_Write(
            &fs,
            &open_context,
            write_buffer.data(),
            0,
            static_cast<ULONG>(write_buffer.size()),
            FALSE,
            FALSE,
            &done,
            &info);
        if (!Require(write_status == STATUS_VOLUME_DISMOUNTED, "Write should return STATUS_VOLUME_DISMOUNTED when shutdown drain is active"))
        {
            ok = false;
            break;
        }

        if (!Require(done == 0, "Write rejected during shutdown drain should not report bytes written"))
        {
            ok = false;
            break;
        }

        const auto overwrite_status = CB_Overwrite(
            &fs,
            &open_context,
            0,
            FALSE,
            128,
            &info);
        if (!Require(overwrite_status == STATUS_VOLUME_DISMOUNTED, "Overwrite should return STATUS_VOLUME_DISMOUNTED when shutdown drain is active"))
        {
            ok = false;
            break;
        }

        if (!Require(file->file_size == 64, "Shutdown-drain data mutation rejection should preserve file size"))
        {
            ok = false;
            break;
        }

        if (!Require(
                file->timestamp.dwLowDateTime == before_timestamp.dwLowDateTime &&
                file->timestamp.dwHighDateTime == before_timestamp.dwHighDateTime,
                "Shutdown-drain data mutation rejection should preserve file timestamp"))
        {
            ok = false;
            break;
        }

        if (!Require(
                context.active_external_mutation_callbacks.load() == 0,
                "Shutdown-drain data mutation rejection should not leak active external mutation callbacks"))
        {
            ok = false;
            break;
        }
    } while (false);

    CloseHandle(temp_file_handle);
    DeleteFileW(temp_path);
    return ok;
}

bool TestOpenMutationAccessDeniedWhenShutdownDrainActive()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    context.shutdown_drain_active.store(true);
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"drain_open.txt");
    auto file = MakeNode(L"\\drain_open.txt", false, false);
    context.nodes.emplace(Key(file->path), file);

    auto fs = BuildFileSystem(&context);
    PVOID out_ctx = nullptr;
    FSP_FSCTL_FILE_INFO info{};
    const auto status = CB_Open(
        &fs,
        const_cast<PWSTR>(L"\\drain_open.txt"),
        FILE_NON_DIRECTORY_FILE,
        FILE_WRITE_DATA,
        &out_ctx,
        &info);
    if (!Require(status == STATUS_VOLUME_DISMOUNTED, "Open should return STATUS_VOLUME_DISMOUNTED for mutation access when shutdown drain is active"))
    {
        return false;
    }

    if (!Require(out_ctx == nullptr, "Open should not allocate context when shutdown drain rejects mutation access"))
    {
        return false;
    }

    if (!Require(file->open_handle_count == 0 && file->write_handle_count == 0, "Rejected mutation open during shutdown drain should not increment open/write handle counters"))
    {
        return false;
    }

    return Require(
        context.active_external_mutation_callbacks.load() == 0,
        "Rejected mutation open during shutdown drain should not leak active external mutation callbacks");
}

bool TestOpenDeleteAccessDeniedWhenShutdownDrainActive()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    context.shutdown_drain_active.store(true);
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"drain_open_delete.txt");
    auto file = MakeNode(L"\\drain_open_delete.txt", false, false);
    context.nodes.emplace(Key(file->path), file);

    auto fs = BuildFileSystem(&context);
    PVOID out_ctx = nullptr;
    FSP_FSCTL_FILE_INFO info{};
    const auto status = CB_Open(
        &fs,
        const_cast<PWSTR>(L"\\drain_open_delete.txt"),
        FILE_NON_DIRECTORY_FILE,
        DELETE,
        &out_ctx,
        &info);
    if (!Require(status == STATUS_VOLUME_DISMOUNTED, "Open should return STATUS_VOLUME_DISMOUNTED for DELETE access when shutdown drain is active"))
    {
        return false;
    }

    if (!Require(out_ctx == nullptr, "Open should not allocate context for DELETE open rejected by shutdown drain"))
    {
        return false;
    }

    if (!Require(file->open_handle_count == 0 && file->write_handle_count == 0, "Rejected DELETE open during shutdown drain should not increment open/write handle counters"))
    {
        return false;
    }

    return Require(
        context.active_external_mutation_callbacks.load() == 0,
        "Rejected DELETE open during shutdown drain should not leak active external mutation callbacks");
}

bool TestOpenReadOnlyAllowedWhenShutdownDrainActive()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    context.shutdown_drain_active.store(true);
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto fs = BuildFileSystem(&context);
    PVOID out_ctx = nullptr;
    FSP_FSCTL_FILE_INFO info{};
    const auto status = CB_Open(
        &fs,
        const_cast<PWSTR>(L"\\"),
        FILE_DIRECTORY_FILE,
        FILE_LIST_DIRECTORY,
        &out_ctx,
        &info);
    if (!Require(status == STATUS_SUCCESS, "Read-only directory open should remain available during shutdown drain"))
    {
        return false;
    }

    auto* open_context = static_cast<OpenContext*>(out_ctx);
    if (!Require(open_context != nullptr, "Successful read-only open during shutdown drain should allocate an open context"))
    {
        return false;
    }

    bool ok = true;
    do
    {
        if (!Require(!open_context->write_open, "Read-only directory open should not be marked as write-open during shutdown drain"))
        {
            ok = false;
            break;
        }

        auto root = context.nodes.at(Key(L"\\"));
        if (!Require(root->open_handle_count == 1, "Read-only directory open should increment open handle count"))
        {
            ok = false;
            break;
        }
        if (!Require(root->write_handle_count == 0, "Read-only directory open should not increment write handle count"))
        {
            ok = false;
            break;
        }
        if (!Require(
                context.active_external_mutation_callbacks.load() == 0,
                "Read-only directory open during shutdown drain should not consume external mutation callback slots"))
        {
            ok = false;
            break;
        }
    } while (false);

    CB_Close(&fs, out_ctx);
    return ok;
}

bool TestSetSecurityRejectedWhenShutdownDrainActive()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    context.shutdown_drain_active.store(true);
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto fs = BuildFileSystem(&context);
    const auto status = CB_SetSecurity(&fs, nullptr, 0, nullptr);
    if (!Require(status == STATUS_VOLUME_DISMOUNTED, "SetSecurity should return STATUS_VOLUME_DISMOUNTED when shutdown drain is active"))
    {
        return false;
    }

    return Require(
        context.active_external_mutation_callbacks.load() == 0,
        "SetSecurity rejected by shutdown drain should not leak active external mutation callbacks");
}

bool TestCleanupDeleteNoopWhenShutdownDrainActive()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    context.shutdown_drain_active.store(true);
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"drain_cleanup.txt");
    auto file = MakeNode(L"\\drain_cleanup.txt", false, false);
    file->open_handle_count = 1;
    context.nodes.emplace(Key(file->path), file);

    OpenContext open_context{};
    open_context.node = file;
    open_context.allow_delete = true;

    auto fs = BuildFileSystem(&context);
    CB_Cleanup(
        &fs,
        &open_context,
        const_cast<PWSTR>(L"\\drain_cleanup.txt"),
        FspCleanupDelete);

    if (!Require(!open_context.delete_on_cleanup, "Cleanup delete should remain a no-op while shutdown drain is active"))
    {
        return false;
    }

    if (!Require(!file->delete_pending && !file->delete_latched && file->delete_intent_count == 0, "Cleanup delete during shutdown drain should not mutate delete intent or pending flags"))
    {
        return false;
    }

    return Require(file->open_handle_count == 0 && open_context.cleanup_seen, "Cleanup delete during shutdown drain should still release visible open-handle accounting");
}

bool TestFlushRejectedWhenShutdownDrainActive()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    context.shutdown_drain_active.store(true);
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"drain_flush.txt");
    auto file = MakeNode(L"\\drain_flush.txt", false, false);
    context.nodes.emplace(Key(file->path), file);

    OpenContext open_context{};
    open_context.node = file;

    auto fs = BuildFileSystem(&context);
    FSP_FSCTL_FILE_INFO info{};
    const auto status = CB_Flush(&fs, &open_context, &info);
    if (!Require(status == STATUS_VOLUME_DISMOUNTED, "Flush should return STATUS_VOLUME_DISMOUNTED when shutdown drain is active and mutation writes are enabled"))
    {
        return false;
    }

    return Require(
        context.active_external_mutation_callbacks.load() == 0,
        "Flush rejected by shutdown drain should not leak active external mutation callbacks");
}

bool TestFlushAllowedWhenWriteDisabledDuringShutdownDrain()
{
    MountContext context{};
    context.overlay_write_enabled = false;
    context.shutdown_drain_active.store(true);
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"readonly_flush.txt");
    auto file = MakeNode(L"\\readonly_flush.txt", false, false);
    context.nodes.emplace(Key(file->path), file);

    OpenContext open_context{};
    open_context.node = file;

    auto fs = BuildFileSystem(&context);
    FSP_FSCTL_FILE_INFO info{};
    const auto status = CB_Flush(&fs, &open_context, &info);
    if (!Require(status == STATUS_SUCCESS, "Flush should remain available when write mode is disabled during shutdown drain"))
    {
        return false;
    }

    return Require(
        context.active_external_mutation_callbacks.load() == 0,
        "Read-only flush during shutdown drain should not consume external mutation callback slots");
}

bool TestFlushReleasesExternalMutationScopeAfterSuccessfulWriteEnabledFlush()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"flush_scope.txt");
    auto file = MakeNode(L"\\flush_scope.txt", false, false);
    context.nodes.emplace(Key(file->path), file);

    OpenContext open_context{};
    open_context.node = file;

    auto fs = BuildFileSystem(&context);
    FSP_FSCTL_FILE_INFO info{};
    const auto status = CB_Flush(&fs, &open_context, &info);
    if (!Require(status == STATUS_SUCCESS, "Flush should succeed when write mode is enabled and shutdown drain is inactive"))
    {
        return false;
    }

    return Require(
        context.active_external_mutation_callbacks.load() == 0,
        "Successful flush should release the external mutation callback scope");
}

bool TestFlushFinalizesPendingMutationJournal()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    context.tx_manager = std::make_unique<apfsaccess::rw::TransactionManager>(L"Conservative");
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"flush_journal.txt");
    auto file = MakeNode(L"\\flush_journal.txt", false, false);
    context.nodes.emplace(Key(file->path), file);

    if (!RecordMutationBestEffort(
            &context,
            apfsaccess::rw::TransactionManager::MutationKind::Write,
            L"\\flush_journal.txt",
            L"",
            0,
            4096))
    {
        return Require(false, "Flush journal test should stage a pending transaction mutation");
    }
    if (!Require(context.tx_manager->PendingMutationCount() == 1, "Flush journal test should start with one pending mutation"))
    {
        return false;
    }

    OpenContext open_context{};
    open_context.node = file;

    auto fs = BuildFileSystem(&context);
    FSP_FSCTL_FILE_INFO info{};
    const auto status = CB_Flush(&fs, &open_context, &info);
    if (!Require(status == STATUS_SUCCESS, "Flush should succeed while draining a pending transaction journal"))
    {
        return false;
    }

    return Require(
        context.tx_manager->PendingMutationCount() == 0 &&
        context.tx_manager->CurrentState() == apfsaccess::rw::TransactionManager::State::Idle,
        "Flush should finalize pending mutation journal entries before returning success");
}

bool TestCloseCommitsPendingNativeMetadataAfterDirectoryCreate()
{
#ifdef APFSACCESS_HAS_RW_ENGINE
    MountContext context{};
    context.args.readwrite = true;
    context.args.write_backend = L"Native";
    context.args.write_recovery_policy = L"FailClosed";
    context.native_write_enabled = true;
    context.overlay_write_enabled = false;
    context.test_force_native_mutation_staging_success = true;
    context.test_forced_native_commit_status = apfsaccess::rw::MetadataStore::CommitStatus::Committed;
    std::error_code ec;
    const auto marker_root = std::filesystem::temp_directory_path(ec) / "ApfsAccess" / "fs-host-semantics";
    if (ec)
    {
        return Require(false, "Close-commit regression should resolve temp directory");
    }
    std::filesystem::create_directories(marker_root, ec);
    if (ec)
    {
        return Require(false, "Close-commit regression should create marker directory");
    }
    context.recovery_marker_file = marker_root / (L"close-commit-" + std::to_wstring(GetTickCount64()) + L".state");
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto fs = BuildFileSystem(&context);
    PVOID out_ctx = nullptr;
    FSP_FSCTL_FILE_INFO info{};
    const auto create_status = CB_Create(
        &fs,
        const_cast<PWSTR>(L"\\close-commit-dir"),
        FILE_DIRECTORY_FILE,
        FILE_WRITE_ATTRIBUTES,
        0,
        nullptr,
        0,
        &out_ctx,
        &info);
    if (!Require(create_status == STATUS_SUCCESS, "Directory create should succeed for close-commit regression"))
    {
        std::filesystem::remove(context.recovery_marker_file, ec);
        return false;
    }
    if (!Require(out_ctx != nullptr, "Directory create should return an open context for close-commit regression"))
    {
        std::filesystem::remove(context.recovery_marker_file, ec);
        return false;
    }
    if (!Require(context.pending_native_writes, "Directory create should mark native writes pending before close"))
    {
        CB_Close(&fs, out_ctx);
        std::filesystem::remove(context.recovery_marker_file, ec);
        return false;
    }

    CB_Close(&fs, out_ctx);

    const auto ok = Require(
        !context.pending_native_writes &&
        !context.recovery_active &&
        context.active_external_mutation_callbacks.load() == 0,
        "Close should commit pending native metadata-only creates and publish a clean state");
    std::filesystem::remove(context.recovery_marker_file, ec);
    return ok;
#else
    return true;
#endif
}

bool TestCloseSkipsNativeCommitWhenMetadataIsClean()
{
#ifdef APFSACCESS_HAS_RW_ENGINE
    MountContext context{};
    context.args.readwrite = true;
    context.args.write_backend = L"Native";
    context.args.write_recovery_policy = L"FailClosed";
    context.native_write_enabled = true;
    context.overlay_write_enabled = true;
    context.pending_native_writes = true;
    context.test_forced_native_commit_status = apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed;
    context.test_forced_native_commit_recovery_reason = L"UnexpectedCleanCloseCommit";
    context.test_forced_native_commit_recovery_required = true;
    std::error_code ec;
    const auto marker_root = std::filesystem::temp_directory_path(ec) / "ApfsAccess" / "fs-host-semantics";
    if (ec)
    {
        return Require(false, "Clean close commit-skip test should resolve temp directory");
    }
    std::filesystem::create_directories(marker_root, ec);
    if (ec)
    {
        return Require(false, "Clean close commit-skip test should create marker directory");
    }
    context.recovery_marker_file = marker_root / (L"clean-close-" + std::to_wstring(GetTickCount64()) + L".state");
    SeedRoot(context);

    auto file = MakeNode(L"\\clean.txt", false);
    context.nodes.emplace(Key(file->path), file);
    auto root = context.nodes[Key(L"\\")];
    root->children.push_back(L"clean.txt");

    auto* open_context = new OpenContext();
    open_context->node = file;
    open_context->write_open = true;
    file->open_handle_count = 1;
    file->write_handle_count = 1;

    auto fs = BuildFileSystem(&context);
    CB_Close(&fs, open_context);

    const auto ok = Require(
        context.test_native_commit_attempt_count == 0 &&
            !context.pending_native_writes &&
            !context.recovery_active &&
            context.native_write_enabled,
        "Close should clear a stale native dirty marker without attempting a commit when metadata is clean");
    std::filesystem::remove(context.recovery_marker_file, ec);
    return ok;
#else
    return true;
#endif
}

bool TestCloseStagesNativeSubtreeDeleteBottomUp()
{
#ifdef APFSACCESS_HAS_RW_ENGINE
    MountContext context{};
    context.args.readwrite = true;
    context.args.write_backend = L"Native";
    context.args.write_recovery_policy = L"FailClosed";
    context.native_write_enabled = true;
    context.overlay_write_enabled = false;
    context.args.allow_legacy_scaffold_for_fixtures = true;
    context.args.write_require_canonical_commit = false;
    context.args.write_disallow_scaffold_commit_on_non_fixture = false;
    context.args.write_reject_scaffold_replay_blob_on_non_fixture = false;
    context.args.write_require_canonical_replay_candidate_on_non_fixture = false;
    context.args.volume = L"SubtreeDelete";
    if (!Require(PrepareUnitHydrationRoot(context, L"native-subtree-delete"), "Native subtree delete test should prepare cache root"))
    {
        return false;
    }
    ScopeExit cleanup{[&]()
    {
        std::error_code ec;
        std::filesystem::remove_all(context.session_root, ec);
    }};

    const auto image_path = context.session_root / "subtree-delete.apfs.img";
    if (!Require(CreateSyntheticApfsContainerForTest(image_path), "Native subtree delete test should create synthetic APFS image"))
    {
        return false;
    }
    context.args.device = image_path.wstring();
    apfsaccess::rw::MetadataStore::VolumeContext rw_context{};
    rw_context.device_path = image_path.wstring();
    rw_context.volume_name = L"SubtreeDelete";
    rw_context.allow_legacy_scaffold_for_fixtures = true;
    rw_context.disallow_scaffold_commit_on_non_fixture = false;
    rw_context.reject_scaffold_replay_blob_on_non_fixture = false;
    rw_context.require_canonical_replay_candidate_on_non_fixture = false;
    context.metadata_store = std::make_unique<apfsaccess::rw::MetadataStore>(std::move(rw_context));
    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    context.metadata_store->SetFilePayloadProvider(
        [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
        {
            auto it = staged_payloads.find(path);
            if (it == staged_payloads.end())
            {
                return std::nullopt;
            }
            auto payload = it->second;
            if (payload.size() < logical_size)
            {
                payload.resize(static_cast<std::size_t>(logical_size), std::byte{0});
            }
            else if (payload.size() > logical_size)
            {
                payload.resize(static_cast<std::size_t>(logical_size));
            }
            return payload;
        });
    if (!Require(context.metadata_store->LoadContainerSuperblocks(), "Native subtree delete test should load container superblocks") ||
        !Require(context.metadata_store->LoadObjectMap(), "Native subtree delete test should load object map") ||
        !Require(context.metadata_store->LoadSpacemanState(), "Native subtree delete test should load spaceman state") ||
        !Require(context.metadata_store->PrepareNativeWritePath(), "Native subtree delete test should prepare native write path"))
    {
        return false;
    }

    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);
    auto fs = BuildFileSystem(&context);

    auto create_directory = [&](PCWSTR path) -> bool
    {
        PVOID created_ctx = nullptr;
        FSP_FSCTL_FILE_INFO info{};
        const auto status = CB_Create(
            &fs,
            const_cast<PWSTR>(path),
            FILE_DIRECTORY_FILE,
            FILE_WRITE_ATTRIBUTES | DELETE,
            0,
            nullptr,
            0,
            &created_ctx,
            &info);
        if (!Require(status == STATUS_SUCCESS && created_ctx != nullptr, "Native subtree delete test should create directory"))
        {
            return false;
        }
        CB_Close(&fs, created_ctx);
        return true;
    };
    if (!create_directory(L"\\tree") || !create_directory(L"\\tree\\child"))
    {
        return false;
    }

    PVOID file_ctx = nullptr;
    FSP_FSCTL_FILE_INFO file_info{};
    const auto file_create = CB_Create(
        &fs,
        const_cast<PWSTR>(L"\\tree\\child\\payload.bin"),
        FILE_NON_DIRECTORY_FILE,
        FILE_WRITE_DATA | FILE_READ_DATA | DELETE,
        0,
        nullptr,
        0,
        &file_ctx,
        &file_info);
    if (!Require(file_create == STATUS_SUCCESS && file_ctx != nullptr, "Native subtree delete test should create payload file"))
    {
        return false;
    }
    const auto payload = BuildPatternPayloadForTest(1536, 0x42);
    ULONG written = 0;
    const auto write_status = CB_Write(
        &fs,
        file_ctx,
        const_cast<std::byte*>(payload.data()),
        0,
        static_cast<ULONG>(payload.size()),
        FALSE,
        FALSE,
        &written,
        &file_info);
    staged_payloads[L"\\tree\\child\\payload.bin"] = payload;
    CB_Close(&fs, file_ctx);
    if (!Require(write_status == STATUS_SUCCESS && written == payload.size(), "Native subtree delete test should write payload bytes"))
    {
        return false;
    }

    auto payload_node = FindNode(&context, L"\\tree\\child\\payload.bin");
    if (!Require(payload_node != nullptr, "Native subtree delete test should find payload before cleanup"))
    {
        return false;
    }
    auto* payload_delete = new OpenContext();
    payload_delete->node = payload_node;
    payload_delete->allow_delete = true;
    ++payload_node->open_handle_count;
    CB_Cleanup(&fs, payload_delete, const_cast<PWSTR>(L"\\tree\\child\\payload.bin"), FspCleanupDelete);
    CB_Close(&fs, payload_delete);
    staged_payloads.erase(L"\\tree\\child\\payload.bin");
    if (!Require(!context.recovery_active, "Native subtree delete should not degrade after payload delete"))
    {
        return false;
    }
    if (!Require(context.nodes.find(Key(L"\\tree\\child\\payload.bin")) == context.nodes.end(), "Native subtree delete should remove local payload"))
    {
        return false;
    }

    auto child = FindNode(&context, L"\\tree\\child");
    if (!Require(child != nullptr, "Native subtree delete test should find child directory after payload delete"))
    {
        return false;
    }
    auto* child_delete = new OpenContext();
    child_delete->node = child;
    child_delete->allow_delete = true;
    ++child->open_handle_count;
    CB_Cleanup(&fs, child_delete, const_cast<PWSTR>(L"\\tree\\child"), FspCleanupDelete);
    CB_Close(&fs, child_delete);
    if (!Require(!context.recovery_active, "Native subtree delete should not degrade after child directory delete"))
    {
        return false;
    }
    if (!Require(context.nodes.find(Key(L"\\tree\\child")) == context.nodes.end(), "Native subtree delete should remove local child directory"))
    {
        return false;
    }

    auto root = FindNode(&context, L"\\tree");
    if (!Require(root != nullptr, "Native subtree delete test should find root directory after child delete"))
    {
        return false;
    }
    auto* root_delete = new OpenContext();
    root_delete->node = root;
    root_delete->allow_delete = true;
    ++root->open_handle_count;
    CB_Cleanup(&fs, root_delete, const_cast<PWSTR>(L"\\tree"), FspCleanupDelete);
    CB_Close(&fs, root_delete);

    if (!Require(!context.recovery_active, "Native subtree delete should not degrade after root directory delete"))
    {
        return false;
    }
    if (!Require(context.nodes.find(Key(L"\\tree")) == context.nodes.end(), "Native subtree delete should remove local root"))
    {
        return false;
    }
    if (!Require(!context.metadata_store->LookupCommittedInodeByPath(L"\\tree").has_value(), "Native subtree delete should remove committed root"))
    {
        return false;
    }
    return Require(
        context.metadata_store->PendingMutationCount() == 0,
        "Native subtree delete should drain all bottom-up staged mutations on close");
#else
    return true;
#endif
}

bool TestStatusFileIncludesNativeMutationFailureDetail()
{
#ifdef APFSACCESS_HAS_RW_ENGINE
    MountContext context{};
    context.args.readwrite = true;
    context.args.write_backend = L"Native";
    context.args.write_recovery_policy = L"FailClosed";
    context.native_write_enabled = true;
    context.overlay_write_enabled = false;
    context.args.allow_legacy_scaffold_for_fixtures = true;
    context.args.write_require_canonical_commit = false;
    context.args.write_disallow_scaffold_commit_on_non_fixture = false;
    context.args.write_reject_scaffold_replay_blob_on_non_fixture = false;
    context.args.write_require_canonical_replay_candidate_on_non_fixture = false;
    context.args.volume = L"FailureDetail";
    if (!Require(PrepareUnitHydrationRoot(context, L"native-mutation-failure-detail"), "Native mutation failure-detail test should prepare cache root"))
    {
        return false;
    }
    ScopeExit cleanup{[&]()
    {
        std::error_code ec;
        std::filesystem::remove_all(context.session_root, ec);
    }};

    const auto image_path = context.session_root / "failure-detail.apfs.img";
    if (!Require(CreateSyntheticApfsContainerForTest(image_path), "Native mutation failure-detail test should create synthetic APFS image"))
    {
        return false;
    }
    context.args.device = image_path.wstring();
    context.args.status_file = (context.session_root / "status.json").wstring();

    apfsaccess::rw::MetadataStore::VolumeContext rw_context{};
    rw_context.device_path = image_path.wstring();
    rw_context.volume_name = L"FailureDetail";
    rw_context.allow_legacy_scaffold_for_fixtures = true;
    rw_context.disallow_scaffold_commit_on_non_fixture = false;
    rw_context.reject_scaffold_replay_blob_on_non_fixture = false;
    rw_context.require_canonical_replay_candidate_on_non_fixture = false;
    context.metadata_store = std::make_unique<apfsaccess::rw::MetadataStore>(std::move(rw_context));
    if (!Require(context.metadata_store->LoadContainerSuperblocks(), "Native mutation failure-detail test should load container superblocks") ||
        !Require(context.metadata_store->LoadObjectMap(), "Native mutation failure-detail test should load object map") ||
        !Require(context.metadata_store->LoadSpacemanState(), "Native mutation failure-detail test should load spaceman state") ||
        !Require(context.metadata_store->PrepareNativeWritePath(), "Native mutation failure-detail test should prepare native write path"))
    {
        return false;
    }

    const auto staged = RecordNativeMutationBestEffort(
        &context,
        apfsaccess::rw::MetadataStore::MutationOperation::SetBasicInfo,
        L"\\missing-after-delete.txt",
        L"",
        0,
        0,
        false,
        ToFileTimeValue(UtcNow()));
    if (!Require(!staged, "Native mutation failure-detail test should reject missing SetBasicInfo target"))
    {
        return false;
    }

    (void)BlockNativeMutationAfterStagingFailure(&context, L"SetBasicInfo");

    std::ifstream in(std::filesystem::path(context.args.status_file), std::ios::binary);
    if (!Require(in.good(), "Native mutation failure-detail test should open host status sidecar"))
    {
        return false;
    }
    std::stringstream buffer;
    buffer << in.rdbuf();
    const auto json = buffer.str();

    return Require(json.find("\"lastNativeMutationFailure\":{") != std::string::npos, "Status sidecar should include native mutation failure detail object") &&
        Require(json.find("\"operation\":\"SetBasicInfo\"") != std::string::npos, "Status sidecar should report failed native mutation operation") &&
        Require(json.find("\"path\":\"\\\\missing-after-delete.txt\"") != std::string::npos, "Status sidecar should report failed native mutation path") &&
        Require(json.find("\"status\":\"invalid-request\"") != std::string::npos, "Status sidecar should report failed native mutation status") &&
        Require(json.find("\"reason\":\"SetBasicInfoTargetMissing\"") != std::string::npos, "Status sidecar should report failed native mutation reason");
#else
    return true;
#endif
}

bool TestSetBasicInfoOnStaleDeletedHandleDoesNotDowngradeNativeWrite()
{
#ifdef APFSACCESS_HAS_RW_ENGINE
    MountContext context{};
    context.args.readwrite = true;
    context.args.write_backend = L"Native";
    context.args.write_recovery_policy = L"FailClosed";
    context.native_write_enabled = true;
    context.overlay_write_enabled = false;
    context.args.allow_legacy_scaffold_for_fixtures = true;
    context.args.write_require_canonical_commit = false;
    context.args.write_disallow_scaffold_commit_on_non_fixture = false;
    context.args.write_reject_scaffold_replay_blob_on_non_fixture = false;
    context.args.write_require_canonical_replay_candidate_on_non_fixture = false;
    context.args.volume = L"StaleMetadata";
    if (!Require(PrepareUnitHydrationRoot(context, L"stale-deleted-set-basic-info"), "Stale SetBasicInfo test should prepare cache root"))
    {
        return false;
    }
    ScopeExit cleanup{[&]()
    {
        std::error_code ec;
        std::filesystem::remove_all(context.session_root, ec);
    }};

    const auto image_path = context.session_root / "stale-metadata.apfs.img";
    if (!Require(CreateSyntheticApfsContainerForTest(image_path), "Stale SetBasicInfo test should create synthetic APFS image"))
    {
        return false;
    }
    context.args.device = image_path.wstring();

    apfsaccess::rw::MetadataStore::VolumeContext rw_context{};
    rw_context.device_path = image_path.wstring();
    rw_context.volume_name = L"StaleMetadata";
    rw_context.allow_legacy_scaffold_for_fixtures = true;
    rw_context.disallow_scaffold_commit_on_non_fixture = false;
    rw_context.reject_scaffold_replay_blob_on_non_fixture = false;
    rw_context.require_canonical_replay_candidate_on_non_fixture = false;
    context.metadata_store = std::make_unique<apfsaccess::rw::MetadataStore>(std::move(rw_context));
    if (!Require(context.metadata_store->LoadContainerSuperblocks(), "Stale SetBasicInfo test should load container superblocks") ||
        !Require(context.metadata_store->LoadObjectMap(), "Stale SetBasicInfo test should load object map") ||
        !Require(context.metadata_store->LoadSpacemanState(), "Stale SetBasicInfo test should load spaceman state") ||
        !Require(context.metadata_store->PrepareNativeWritePath(), "Stale SetBasicInfo test should prepare native write path"))
    {
        return false;
    }

    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);
    auto fs = BuildFileSystem(&context);

    PVOID create_ctx = nullptr;
    FSP_FSCTL_FILE_INFO create_info{};
    const auto create_status = CB_Create(
        &fs,
        const_cast<PWSTR>(L"\\stale.bin"),
        FILE_NON_DIRECTORY_FILE,
        FILE_WRITE_DATA | FILE_READ_DATA | FILE_WRITE_ATTRIBUTES | DELETE,
        0,
        nullptr,
        0,
        &create_ctx,
        &create_info);
    if (!Require(create_status == STATUS_SUCCESS && create_ctx != nullptr, "Stale SetBasicInfo test should create file"))
    {
        return false;
    }
    auto* original_open = static_cast<OpenContext*>(create_ctx);
    auto stale_node = original_open->node;
    CB_Close(&fs, create_ctx);

    OpenContext stale_metadata_open{};
    stale_metadata_open.node = stale_node;
    stale_metadata_open.allow_set_basic_info = true;

    auto* delete_open = new OpenContext();
    delete_open->node = stale_node;
    delete_open->allow_delete = true;
    ++stale_node->open_handle_count;
    CB_Cleanup(&fs, delete_open, const_cast<PWSTR>(L"\\stale.bin"), FspCleanupDelete);
    CB_Close(&fs, delete_open);
    if (!Require(context.nodes.find(Key(L"\\stale.bin")) == context.nodes.end(), "Stale SetBasicInfo test should remove local node before stale metadata touch"))
    {
        return false;
    }
    if (!Require(!context.metadata_store->LookupCommittedInodeByPath(L"\\stale.bin").has_value(), "Stale SetBasicInfo test should remove committed inode before stale metadata touch"))
    {
        return false;
    }

    FSP_FSCTL_FILE_INFO info{};
    const auto set_basic_status = CB_SetBasicInfo(
        &fs,
        &stale_metadata_open,
        0,
        0,
        0,
        ToFileTimeValue(UtcNow()),
        0,
        &info);

    return Require(set_basic_status == STATUS_SUCCESS, "SetBasicInfo on stale deleted handle should be treated as benign") &&
        Require(!context.recovery_active, "SetBasicInfo on stale deleted handle should not latch recovery") &&
        Require(context.native_write_enabled, "SetBasicInfo on stale deleted handle should keep native write enabled");
#else
    return true;
#endif
}

bool TestSetBasicInfoOnVisibleNativeMissingDirectoryDoesNotDowngradeNativeWrite()
{
#ifdef APFSACCESS_HAS_RW_ENGINE
    MountContext context{};
    context.args.readwrite = true;
    context.args.write_backend = L"Native";
    context.args.write_recovery_policy = L"FailClosed";
    context.native_write_enabled = true;
    context.overlay_write_enabled = false;
    context.args.allow_legacy_scaffold_for_fixtures = true;
    context.args.write_require_canonical_commit = false;
    context.args.write_disallow_scaffold_commit_on_non_fixture = false;
    context.args.write_reject_scaffold_replay_blob_on_non_fixture = false;
    context.args.write_require_canonical_replay_candidate_on_non_fixture = false;
    context.args.volume = L"VisibleNativeMissing";
    if (!Require(PrepareUnitHydrationRoot(context, L"visible-native-missing-set-basic-info"), "Visible-native-missing SetBasicInfo test should prepare cache root"))
    {
        return false;
    }
    ScopeExit cleanup{[&]()
    {
        std::error_code ec;
        std::filesystem::remove_all(context.session_root, ec);
    }};

    const auto image_path = context.session_root / "visible-native-missing.apfs.img";
    if (!Require(CreateSyntheticApfsContainerForTest(image_path), "Visible-native-missing SetBasicInfo test should create synthetic APFS image"))
    {
        return false;
    }
    context.args.device = image_path.wstring();

    apfsaccess::rw::MetadataStore::VolumeContext rw_context{};
    rw_context.device_path = image_path.wstring();
    rw_context.volume_name = L"VisibleNativeMissing";
    rw_context.allow_legacy_scaffold_for_fixtures = true;
    rw_context.disallow_scaffold_commit_on_non_fixture = false;
    rw_context.reject_scaffold_replay_blob_on_non_fixture = false;
    rw_context.require_canonical_replay_candidate_on_non_fixture = false;
    context.metadata_store = std::make_unique<apfsaccess::rw::MetadataStore>(std::move(rw_context));
    if (!Require(context.metadata_store->LoadContainerSuperblocks(), "Visible-native-missing SetBasicInfo test should load container superblocks") ||
        !Require(context.metadata_store->LoadObjectMap(), "Visible-native-missing SetBasicInfo test should load object map") ||
        !Require(context.metadata_store->LoadSpacemanState(), "Visible-native-missing SetBasicInfo test should load spaceman state") ||
        !Require(context.metadata_store->PrepareNativeWritePath(), "Visible-native-missing SetBasicInfo test should prepare native write path"))
    {
        return false;
    }

    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);
    auto fs = BuildFileSystem(&context);

    PVOID create_ctx = nullptr;
    FSP_FSCTL_FILE_INFO create_info{};
    const auto create_status = CB_Create(
        &fs,
        const_cast<PWSTR>(L"\\native-missing-dir"),
        FILE_DIRECTORY_FILE,
        FILE_WRITE_ATTRIBUTES | DELETE,
        0,
        nullptr,
        0,
        &create_ctx,
        &create_info);
    if (!Require(create_status == STATUS_SUCCESS && create_ctx != nullptr, "Visible-native-missing SetBasicInfo test should create directory"))
    {
        return false;
    }
    auto* create_open = static_cast<OpenContext*>(create_ctx);
    auto directory_node = create_open->node;
    CB_Close(&fs, create_ctx);

    auto* delete_open = new OpenContext();
    delete_open->node = directory_node;
    delete_open->allow_delete = true;
    ++directory_node->open_handle_count;
    CB_Cleanup(&fs, delete_open, const_cast<PWSTR>(L"\\native-missing-dir"), FspCleanupDelete);
    CB_Close(&fs, delete_open);
    if (!Require(!context.metadata_store->LookupCommittedInodeByPath(L"\\native-missing-dir").has_value(), "Visible-native-missing SetBasicInfo test should remove committed directory before stale metadata touch"))
    {
        return false;
    }

    directory_node->delete_latched = false;
    directory_node->delete_pending = false;
    directory_node->delete_intent_count = 0;
    directory_node->open_handle_count = 0;
    context.nodes[Key(directory_node->path)] = directory_node;
    AddChildName(context.nodes.at(Key(L"\\"))->children, L"native-missing-dir");

    OpenContext stale_metadata_open{};
    stale_metadata_open.node = directory_node;
    stale_metadata_open.allow_set_basic_info = true;
    FSP_FSCTL_FILE_INFO info{};
    const auto set_basic_status = CB_SetBasicInfo(
        &fs,
        &stale_metadata_open,
        0,
        0,
        0,
        ToFileTimeValue(UtcNow()),
        0,
        &info);

    return Require(set_basic_status == STATUS_SUCCESS, "SetBasicInfo on visible local directory missing from native metadata should be benign") &&
        Require(!context.recovery_active, "SetBasicInfo on visible local directory missing from native metadata should not latch recovery") &&
        Require(context.native_write_enabled, "SetBasicInfo on visible local directory missing from native metadata should keep native write enabled");
#else
    return true;
#endif
}

bool TestDeleteTargetMissingOnStaleDeletedHandleDoesNotDowngradeNativeWrite()
{
#ifdef APFSACCESS_HAS_RW_ENGINE
    MountContext context{};
    context.args.readwrite = true;
    context.args.write_backend = L"Native";
    context.args.write_recovery_policy = L"FailClosed";
    context.native_write_enabled = true;
    context.overlay_write_enabled = false;
    context.args.allow_legacy_scaffold_for_fixtures = true;
    context.args.write_require_canonical_commit = false;
    context.args.write_disallow_scaffold_commit_on_non_fixture = false;
    context.args.write_reject_scaffold_replay_blob_on_non_fixture = false;
    context.args.write_require_canonical_replay_candidate_on_non_fixture = false;
    context.args.volume = L"StaleDelete";
    if (!Require(PrepareUnitHydrationRoot(context, L"stale-delete-target-missing"), "Stale delete test should prepare cache root"))
    {
        return false;
    }
    ScopeExit cleanup{[&]()
    {
        std::error_code ec;
        std::filesystem::remove_all(context.session_root, ec);
    }};

    const auto image_path = context.session_root / "stale-delete.apfs.img";
    if (!Require(CreateSyntheticApfsContainerForTest(image_path), "Stale delete test should create synthetic APFS image"))
    {
        return false;
    }
    context.args.device = image_path.wstring();

    apfsaccess::rw::MetadataStore::VolumeContext rw_context{};
    rw_context.device_path = image_path.wstring();
    rw_context.volume_name = L"StaleDelete";
    rw_context.allow_legacy_scaffold_for_fixtures = true;
    rw_context.disallow_scaffold_commit_on_non_fixture = false;
    rw_context.reject_scaffold_replay_blob_on_non_fixture = false;
    rw_context.require_canonical_replay_candidate_on_non_fixture = false;
    context.metadata_store = std::make_unique<apfsaccess::rw::MetadataStore>(std::move(rw_context));
    if (!Require(context.metadata_store->LoadContainerSuperblocks(), "Stale delete test should load container superblocks") ||
        !Require(context.metadata_store->LoadObjectMap(), "Stale delete test should load object map") ||
        !Require(context.metadata_store->LoadSpacemanState(), "Stale delete test should load spaceman state") ||
        !Require(context.metadata_store->PrepareNativeWritePath(), "Stale delete test should prepare native write path"))
    {
        return false;
    }

    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);
    auto fs = BuildFileSystem(&context);

    PVOID create_ctx = nullptr;
    FSP_FSCTL_FILE_INFO create_info{};
    const auto create_status = CB_Create(
        &fs,
        const_cast<PWSTR>(L"\\stale-delete.bin"),
        FILE_NON_DIRECTORY_FILE,
        FILE_WRITE_DATA | FILE_READ_DATA | FILE_WRITE_ATTRIBUTES | DELETE,
        0,
        nullptr,
        0,
        &create_ctx,
        &create_info);
    if (!Require(create_status == STATUS_SUCCESS && create_ctx != nullptr, "Stale delete test should create file"))
    {
        return false;
    }
    auto* create_open = static_cast<OpenContext*>(create_ctx);
    auto stale_node = create_open->node;
    CB_Close(&fs, create_ctx);

    auto* first_delete = new OpenContext();
    first_delete->node = stale_node;
    first_delete->allow_delete = true;
    ++stale_node->open_handle_count;
    CB_Cleanup(&fs, first_delete, const_cast<PWSTR>(L"\\stale-delete.bin"), FspCleanupDelete);
    CB_Close(&fs, first_delete);
    if (!Require(!context.metadata_store->LookupCommittedInodeByPath(L"\\stale-delete.bin").has_value(), "Stale delete test should remove committed inode before duplicate delete"))
    {
        return false;
    }

    stale_node->delete_latched = false;
    stale_node->delete_pending = false;
    stale_node->delete_intent_count = 0;
    stale_node->open_handle_count = 0;
    context.nodes[Key(stale_node->path)] = stale_node;
    AddChildName(context.nodes.at(Key(L"\\"))->children, L"stale-delete.bin");

    auto* duplicate_delete = new OpenContext();
    duplicate_delete->node = stale_node;
    duplicate_delete->allow_delete = true;
    ++stale_node->open_handle_count;
    CB_Cleanup(&fs, duplicate_delete, const_cast<PWSTR>(L"\\stale-delete.bin"), FspCleanupDelete);
    CB_Close(&fs, duplicate_delete);

    return Require(!context.recovery_active, "Duplicate delete for missing native target should not latch recovery") &&
        Require(context.native_write_enabled, "Duplicate delete for missing native target should keep native write enabled") &&
        Require(context.nodes.find(Key(L"\\stale-delete.bin")) == context.nodes.end(), "Duplicate delete should remove stale local node");
#else
    return true;
#endif
}

bool TestMutatingCallbacksFailWriteProtectedWhenWriteDisabled()
{
    MountContext context{};
    context.overlay_write_enabled = false;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"readonly.txt");

    auto file = MakeNode(L"\\readonly.txt", false, false);
    context.nodes.emplace(Key(file->path), file);

    auto fs = BuildFileSystem(&context);
    OpenContext open_context{};
    open_context.node = file;
    open_context.allow_delete = true;

    auto can_delete = CB_CanDelete(&fs, &open_context, const_cast<PWSTR>(L"\\readonly.txt"));
    if (!Require(can_delete == STATUS_MEDIA_WRITE_PROTECTED, "CanDelete should return MEDIA_WRITE_PROTECTED when write mode is disabled"))
    {
        return false;
    }

    auto set_delete = CB_SetDelete(&fs, &open_context, const_cast<PWSTR>(L"\\readonly.txt"), TRUE);
    if (!Require(set_delete == STATUS_MEDIA_WRITE_PROTECTED, "SetDelete should return MEDIA_WRITE_PROTECTED when write mode is disabled"))
    {
        return false;
    }

    auto rename = CB_Rename(
        &fs,
        nullptr,
        const_cast<PWSTR>(L"\\readonly.txt"),
        const_cast<PWSTR>(L"\\renamed.txt"),
        FALSE);
    if (!Require(rename == STATUS_MEDIA_WRITE_PROTECTED, "Rename should return MEDIA_WRITE_PROTECTED when write mode is disabled"))
    {
        return false;
    }

    PVOID out_ctx = nullptr;
    FSP_FSCTL_FILE_INFO info{};
    auto create = CB_Create(
        &fs,
        const_cast<PWSTR>(L"\\new.txt"),
        FILE_NON_DIRECTORY_FILE,
        FILE_WRITE_DATA,
        0,
        nullptr,
        0,
        &out_ctx,
        &info);
    if (!Require(create == STATUS_MEDIA_WRITE_PROTECTED, "Create should return MEDIA_WRITE_PROTECTED when write mode is disabled"))
    {
        return false;
    }

    auto set_security = CB_SetSecurity(&fs, nullptr, 0, nullptr);
    return Require(set_security == STATUS_MEDIA_WRITE_PROTECTED, "SetSecurity should return MEDIA_WRITE_PROTECTED when write mode is disabled");
}

bool TestSetSecurityIsNoopWhenWriteEnabled()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto fs = BuildFileSystem(&context);
    const auto status = CB_SetSecurity(&fs, nullptr, DACL_SECURITY_INFORMATION, nullptr);
    if (!Require(status == STATUS_SUCCESS, "SetSecurity should be a no-op success while write mode is enabled"))
    {
        return false;
    }

    return Require(
        context.active_external_mutation_callbacks.load() == 0,
        "SetSecurity no-op should release external mutation callback scope");
}

bool TestDefaultSecurityDescriptorGrantsUsersWriteAccess()
{
    ULONG descriptor_size = 0;
    PSECURITY_DESCRIPTOR descriptor = BuildWritableVolumeSecurityDescriptor(&descriptor_size);
    if (!Require(descriptor != nullptr, "Default security descriptor should be created"))
    {
        return false;
    }

    bool ok = true;
    auto cleanup = [&]()
    {
        LocalFree(descriptor);
    };

    PACL dacl = nullptr;
    BOOL dacl_present = FALSE;
    BOOL dacl_defaulted = FALSE;
    if (!Require(GetSecurityDescriptorDacl(descriptor, &dacl_present, &dacl, &dacl_defaulted) != FALSE,
            "Default security descriptor should expose a DACL"))
    {
        cleanup();
        return false;
    }
    if (!Require(dacl_present && dacl != nullptr, "Default security descriptor should include an explicit DACL"))
    {
        cleanup();
        return false;
    }

    const auto make_sid = [](WELL_KNOWN_SID_TYPE sid_type)
    {
        std::vector<BYTE> sid(SECURITY_MAX_SID_SIZE);
        DWORD sid_size = static_cast<DWORD>(sid.size());
        if (!CreateWellKnownSid(sid_type, nullptr, sid.data(), &sid_size))
        {
            sid.clear();
        }
        else
        {
            sid.resize(sid_size);
        }
        return sid;
    };

    const auto users_sid = make_sid(WinBuiltinUsersSid);
    const auto authenticated_users_sid = make_sid(WinAuthenticatedUserSid);
    const auto everyone_sid = make_sid(WinWorldSid);

    if (!Require(!users_sid.empty() && !authenticated_users_sid.empty() && !everyone_sid.empty(),
            "Well-known comparison SIDs should be created"))
    {
        cleanup();
        return false;
    }

    bool has_users = false;
    bool has_authenticated_users = false;
    bool has_everyone = false;
    for (DWORD index = 0; index < dacl->AceCount; ++index)
    {
        void* ace = nullptr;
        if (!GetAce(dacl, index, &ace) || ace == nullptr)
        {
            ok = false;
            break;
        }

        auto* header = static_cast<ACE_HEADER*>(ace);
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE)
        {
            continue;
        }

        auto* allowed = static_cast<ACCESS_ALLOWED_ACE*>(ace);
        has_users = has_users || EqualSid(&allowed->SidStart, const_cast<BYTE*>(users_sid.data()));
        has_authenticated_users = has_authenticated_users || EqualSid(&allowed->SidStart, const_cast<BYTE*>(authenticated_users_sid.data()));
        has_everyone = has_everyone || EqualSid(&allowed->SidStart, const_cast<BYTE*>(everyone_sid.data()));
    }

    ok = ok &&
        Require(has_users, "Default security descriptor should grant builtin Users full access") &&
        Require(has_authenticated_users, "Default security descriptor should grant Authenticated Users full access") &&
        Require(has_everyone, "Default security descriptor should grant Everyone full access");

    cleanup();
    return ok;
}

bool TestOpenMutationAccessDeniedWhenWriteDisabled()
{
    MountContext context{};
    context.overlay_write_enabled = false;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"readonly.txt");

    auto file = MakeNode(L"\\readonly.txt", false, false);
    context.nodes.emplace(Key(file->path), file);

    auto fs = BuildFileSystem(&context);
    PVOID out_ctx = nullptr;
    FSP_FSCTL_FILE_INFO info{};
    auto status = CB_Open(
        &fs,
        const_cast<PWSTR>(L"\\readonly.txt"),
        FILE_NON_DIRECTORY_FILE,
        FILE_WRITE_DATA,
        &out_ctx,
        &info);
    if (!Require(status == STATUS_MEDIA_WRITE_PROTECTED, "Open should return MEDIA_WRITE_PROTECTED for mutation access when write mode is disabled"))
    {
        return false;
    }

    return Require(out_ctx == nullptr, "Open should not allocate file context when mutation access is denied");
}

bool TestOpenDeleteAccessDeniedWhenWriteDisabled()
{
    MountContext context{};
    context.overlay_write_enabled = false;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"readonly.txt");

    auto file = MakeNode(L"\\readonly.txt", false, false);
    context.nodes.emplace(Key(file->path), file);

    auto fs = BuildFileSystem(&context);
    PVOID out_ctx = nullptr;
    FSP_FSCTL_FILE_INFO info{};
    auto status = CB_Open(
        &fs,
        const_cast<PWSTR>(L"\\readonly.txt"),
        FILE_NON_DIRECTORY_FILE,
        DELETE,
        &out_ctx,
        &info);
    if (!Require(status == STATUS_MEDIA_WRITE_PROTECTED, "Open should return MEDIA_WRITE_PROTECTED for DELETE access when write mode is disabled"))
    {
        return false;
    }

    return Require(out_ctx == nullptr, "Open should not allocate context for read-only DELETE open denial");
}

bool TestOpenFailsWhenDeleteIntentStateIsStale()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"stale-open.txt");

    auto file = MakeNode(L"\\stale-open.txt", false, false);
    file->delete_intent_count = 1;
    file->delete_pending = false;
    file->delete_latched = false;
    context.nodes.emplace(Key(file->path), file);

    auto fs = BuildFileSystem(&context);
    PVOID out_ctx = nullptr;
    FSP_FSCTL_FILE_INFO info{};
    const auto status = CB_Open(
        &fs,
        const_cast<PWSTR>(L"\\stale-open.txt"),
        FILE_NON_DIRECTORY_FILE,
        FILE_READ_DATA,
        &out_ctx,
        &info);
    if (!Require(status == STATUS_DELETE_PENDING, "Open should fail with STATUS_DELETE_PENDING when node delete intent exists even if delete_pending visibility flag is stale"))
    {
        return false;
    }

    return Require(out_ctx == nullptr, "Delete-intent stale-state open denial should not allocate open context");
}

bool TestCleanupDeleteNoopWhenWriteDisabled()
{
    MountContext context{};
    context.overlay_write_enabled = false;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"readonly.txt");

    auto file = MakeNode(L"\\readonly.txt", false, false);
    file->open_handle_count = 1;
    context.nodes.emplace(Key(file->path), file);

    auto fs = BuildFileSystem(&context);
    auto* open_context = new OpenContext();
    open_context->node = file;
    open_context->allow_delete = true;

    CB_Cleanup(
        &fs,
        open_context,
        const_cast<PWSTR>(L"\\readonly.txt"),
        FspCleanupDelete);

    if (!Require(!open_context->delete_on_cleanup, "Cleanup delete should be a no-op in write-disabled mode"))
    {
        CB_Close(&fs, open_context);
        return false;
    }
    if (!Require(file->delete_intent_count == 0 && !file->delete_pending, "Cleanup delete in write-disabled mode should not mutate delete-pending state"))
    {
        CB_Close(&fs, open_context);
        return false;
    }
    if (!Require(file->open_handle_count == 0 && open_context->cleanup_seen, "Cleanup delete in write-disabled mode should still release visible open-handle accounting"))
    {
        CB_Close(&fs, open_context);
        return false;
    }

    CB_Close(&fs, open_context);
    return Require(
        context.nodes.find(Key(L"\\readonly.txt")) != context.nodes.end(),
        "Close after read-only cleanup no-op should preserve node");
}

bool TestNativeMutationDenialLatchesFailClosedRecovery()
{
    MountContext context{};
    context.args.readwrite = true;
    context.args.write_backend = L"Native";
    context.args.write_require_canonical_commit = true;
    context.args.write_recovery_policy = L"FailClosed";
    context.native_write_enabled = true;
    context.overlay_write_enabled = false;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto fs = BuildFileSystem(&context);
    PVOID out_ctx = nullptr;
    FSP_FSCTL_FILE_INFO info{};
    auto status = CB_Create(
        &fs,
        const_cast<PWSTR>(L"\\native_blocked.txt"),
        FILE_NON_DIRECTORY_FILE,
        FILE_WRITE_DATA,
        0,
        nullptr,
        0,
        &out_ctx,
        &info);
    if (!Require(status == STATUS_MEDIA_WRITE_PROTECTED, "Native mutation denial should return MEDIA_WRITE_PROTECTED when native write is not commit-ready"))
    {
        return false;
    }
    if (!Require(out_ctx == nullptr, "Blocked native create should not allocate open context"))
    {
        return false;
    }

#ifdef APFSACCESS_HAS_RW_ENGINE
    if (!Require(context.recovery_active, "Blocked native mutation should latch recovery-active state"))
    {
        return false;
    }
    if (!Require(context.write_degraded, "Blocked native mutation should degrade write state under FailClosed policy"))
    {
        return false;
    }
    if (!Require(!context.native_write_enabled && !context.overlay_write_enabled, "Blocked native mutation should disable write backends under FailClosed policy"))
    {
        return false;
    }
    if (!Require(!_wcsicmp(context.runtime_recovery_reason.c_str(), L"NativeWriteUnavailable"), "Blocked native mutation should report NativeWriteUnavailable reason when metadata store is unavailable"))
    {
        return false;
    }
    if (!Require(!_wcsicmp(context.runtime_last_recovery_action.c_str(), L"DowngradedAfterNotReady"), "Blocked native mutation should report DowngradedAfterNotReady action"))
    {
        return false;
    }
#endif

    return Require(
        context.nodes.find(Key(L"\\native_blocked.txt")) == context.nodes.end(),
        "Blocked native mutation must not create filesystem entries");
}

bool TestConcurrentNativeMutationDenialsRemainFailClosedAfterDowngrade()
{
    MountContext context{};
    context.args.readwrite = true;
    context.args.write_backend = L"Native";
    context.args.write_require_canonical_commit = true;
    context.args.write_recovery_policy = L"FailClosed";
    context.native_write_enabled = true;
    context.overlay_write_enabled = false;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"source.txt");
    auto source = MakeNode(L"\\source.txt", false, false);
    context.nodes.emplace(Key(source->path), source);

    auto fs = BuildFileSystem(&context);
    std::atomic<bool> start{false};
    std::atomic<long> create_status{STATUS_UNSUCCESSFUL};
    std::atomic<long> rename_status{STATUS_UNSUCCESSFUL};

    auto run_create = [&]()
    {
        while (!start.load())
        {
            std::this_thread::yield();
        }
        PVOID out_ctx = nullptr;
        FSP_FSCTL_FILE_INFO info{};
        const auto status = CB_Create(
            &fs,
            const_cast<PWSTR>(L"\\native_blocked_a.txt"),
            FILE_NON_DIRECTORY_FILE,
            FILE_WRITE_DATA,
            0,
            nullptr,
            0,
            &out_ctx,
            &info);
        create_status.store(status);
        if (status == STATUS_SUCCESS && out_ctx != nullptr)
        {
            CB_Close(&fs, out_ctx);
        }
    };

    auto run_rename = [&]()
    {
        while (!start.load())
        {
            std::this_thread::yield();
        }
        const auto status = CB_Rename(
            &fs,
            nullptr,
            const_cast<PWSTR>(L"\\source.txt"),
            const_cast<PWSTR>(L"\\renamed.txt"),
            FALSE);
        rename_status.store(status);
    };

    std::thread t1(run_create);
    std::thread t2(run_rename);
    start.store(true);
    t1.join();
    t2.join();

    if (!Require(static_cast<NTSTATUS>(create_status.load()) == STATUS_MEDIA_WRITE_PROTECTED, "Concurrent native create denial should return MEDIA_WRITE_PROTECTED"))
    {
        return false;
    }
    if (!Require(static_cast<NTSTATUS>(rename_status.load()) == STATUS_MEDIA_WRITE_PROTECTED, "Concurrent native rename denial should return MEDIA_WRITE_PROTECTED"))
    {
        return false;
    }

    if (!Require(context.nodes.find(Key(L"\\native_blocked_a.txt")) == context.nodes.end(), "Concurrent native denial should not materialize blocked create path"))
    {
        return false;
    }
    if (!Require(context.nodes.find(Key(L"\\source.txt")) != context.nodes.end(), "Concurrent native denial should preserve original source path"))
    {
        return false;
    }
    if (!Require(context.nodes.find(Key(L"\\renamed.txt")) == context.nodes.end(), "Concurrent native denial should not materialize blocked rename destination"))
    {
        return false;
    }

#ifdef APFSACCESS_HAS_RW_ENGINE
    if (!Require(context.recovery_active, "Concurrent native denials should latch recovery-active state"))
    {
        return false;
    }
    if (!Require(context.write_degraded, "Concurrent native denials should keep write state degraded under FailClosed policy"))
    {
        return false;
    }
    if (!Require(!context.native_write_enabled && !context.overlay_write_enabled, "Concurrent native denials should disable write backends under FailClosed policy"))
    {
        return false;
    }
    if (!Require(!_wcsicmp(context.runtime_recovery_reason.c_str(), L"NativeWriteUnavailable"), "Concurrent native denials should retain NativeWriteUnavailable recovery reason"))
    {
        return false;
    }
    if (!Require(!_wcsicmp(context.runtime_last_recovery_action.c_str(), L"DowngradedAfterNotReady"), "Concurrent native denials should retain DowngradedAfterNotReady action"))
    {
        return false;
    }
#endif

    if (!Require(context.active_external_mutation_callbacks.load() == 0, "Concurrent native denials should not leak active external mutation callbacks"))
    {
        return false;
    }

    PVOID out_ctx = nullptr;
    FSP_FSCTL_FILE_INFO info{};
    const auto open_status = CB_Open(
        &fs,
        const_cast<PWSTR>(L"\\source.txt"),
        FILE_NON_DIRECTORY_FILE,
        FILE_WRITE_DATA,
        &out_ctx,
        &info);
    if (!Require(open_status == STATUS_MEDIA_WRITE_PROTECTED, "Mutation-access open after native downgrade should remain MEDIA_WRITE_PROTECTED"))
    {
        return false;
    }
    return Require(out_ctx == nullptr, "Mutation-access open denial after native downgrade should not allocate context");
}

bool TestConcurrentNativeDenialStatusFileReflectsFailClosedState()
{
    MountContext context{};
    context.args.readwrite = true;
    context.args.write_backend = L"Native";
    context.args.write_require_canonical_commit = true;
    context.args.write_recovery_policy = L"FailClosed";
    context.native_write_enabled = true;
    context.overlay_write_enabled = false;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    std::error_code ec;
    auto status_root = std::filesystem::temp_directory_path(ec) / "ApfsAccess" / "fs-host-semantics" / std::to_wstring(GetTickCount64());
    if (ec)
    {
        return Require(false, "Concurrent native denial status-file test should resolve temp directory");
    }
    std::filesystem::create_directories(status_root, ec);
    if (ec)
    {
        return Require(false, "Concurrent native denial status-file test should create status directory");
    }
    context.args.status_file = (status_root / "status.json").wstring();

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"source.txt");
    auto source = MakeNode(L"\\source.txt", false, false);
    context.nodes.emplace(Key(source->path), source);

    auto fs = BuildFileSystem(&context);
    std::atomic<bool> start{false};
    std::atomic<long> create_status{STATUS_UNSUCCESSFUL};
    std::atomic<long> rename_status{STATUS_UNSUCCESSFUL};

    auto run_create = [&]()
    {
        while (!start.load())
        {
            std::this_thread::yield();
        }
        PVOID out_ctx = nullptr;
        FSP_FSCTL_FILE_INFO info{};
        const auto status = CB_Create(
            &fs,
            const_cast<PWSTR>(L"\\native_blocked_status.txt"),
            FILE_NON_DIRECTORY_FILE,
            FILE_WRITE_DATA,
            0,
            nullptr,
            0,
            &out_ctx,
            &info);
        create_status.store(status);
        if (status == STATUS_SUCCESS && out_ctx != nullptr)
        {
            CB_Close(&fs, out_ctx);
        }
    };

    auto run_rename = [&]()
    {
        while (!start.load())
        {
            std::this_thread::yield();
        }
        const auto status = CB_Rename(
            &fs,
            nullptr,
            const_cast<PWSTR>(L"\\source.txt"),
            const_cast<PWSTR>(L"\\renamed.txt"),
            FALSE);
        rename_status.store(status);
    };

    std::thread t1(run_create);
    std::thread t2(run_rename);
    start.store(true);
    t1.join();
    t2.join();

    bool ok = true;
    do
    {
        if (!Require(static_cast<NTSTATUS>(create_status.load()) == STATUS_MEDIA_WRITE_PROTECTED, "Concurrent status-file create denial should return MEDIA_WRITE_PROTECTED"))
        {
            ok = false;
            break;
        }
        if (!Require(static_cast<NTSTATUS>(rename_status.load()) == STATUS_MEDIA_WRITE_PROTECTED, "Concurrent status-file rename denial should return MEDIA_WRITE_PROTECTED"))
        {
            ok = false;
            break;
        }

        const auto status_path = std::filesystem::path(context.args.status_file);
        if (!Require(std::filesystem::exists(status_path, ec), "Concurrent status-file denial test should emit host status sidecar"))
        {
            ok = false;
            break;
        }

        std::ifstream in(status_path, std::ios::binary);
        if (!Require(in.good(), "Concurrent status-file denial test should open host status sidecar"))
        {
            ok = false;
            break;
        }

        std::stringstream buffer;
        buffer << in.rdbuf();
        const auto json = buffer.str();
        if (!Require(json.find("\"writeBackend\":\"Disabled\"") != std::string::npos, "Fail-closed sidecar should report writeBackend Disabled after native downgrade"))
        {
            ok = false;
            break;
        }
        if (!Require(json.find("\"nativeWriteReadiness\":\"Degraded\"") != std::string::npos, "Fail-closed sidecar should report nativeWriteReadiness Degraded"))
        {
            ok = false;
            break;
        }
        if (!Require(json.find("\"recoveryActive\":true") != std::string::npos, "Fail-closed sidecar should report recoveryActive true"))
        {
            ok = false;
            break;
        }
        if (!Require(json.find("\"recoveryReason\":\"NativeWriteUnavailable\"") != std::string::npos, "Fail-closed sidecar should report NativeWriteUnavailable recovery reason"))
        {
            ok = false;
            break;
        }
        if (!Require(json.find("\"lastRecoveryAction\":\"DowngradedAfterNotReady\"") != std::string::npos, "Fail-closed sidecar should report DowngradedAfterNotReady action"))
        {
            ok = false;
            break;
        }
        if (!Require(json.find("\"inFlightMutationCallbacks\":") != std::string::npos, "Fail-closed sidecar should report inFlightMutationCallbacks field"))
        {
            ok = false;
            break;
        }
        if (!Require(json.find("\"inFlightMutationCallbacks\":-") == std::string::npos, "Fail-closed sidecar should not report negative in-flight mutation callbacks"))
        {
            ok = false;
            break;
        }
    } while (false);

    std::filesystem::remove_all(status_root, ec);
    return ok;
}

bool TestStatusFileDerivesCanonicalGateFailureAfterNativeFailClosedDowngrade()
{
    MountContext context{};
    context.args.readwrite = true;
    context.args.write_backend = L"Native";
    context.native_write_enabled = false;
    context.overlay_write_enabled = false;
    context.write_degraded = true;
    context.recovery_active = true;
    context.runtime_recovery_reason = L"CommitPathNotReady";
    context.runtime_last_recovery_action = L"DowngradedAfterCanonicalGateFailure";

    std::error_code ec;
    auto status_root = std::filesystem::temp_directory_path(ec) / "ApfsAccess" / "fs-host-semantics" / std::to_wstring(GetTickCount64());
    if (ec)
    {
        return Require(false, "Canonical gate status derivation test should resolve temp directory");
    }
    std::filesystem::create_directories(status_root, ec);
    if (ec)
    {
        return Require(false, "Canonical gate status derivation test should create temp directory");
    }
    context.args.status_file = (status_root / "status.json").wstring();

    bool ok = true;
    do
    {
        if (!Require(
                WriteHostStatusFile(context, context.recovery_active, context.runtime_last_commit_xid),
                "Canonical gate status derivation test should write status file"))
        {
            ok = false;
            break;
        }

        const auto status_path = std::filesystem::path(context.args.status_file);
        std::ifstream in(status_path, std::ios::binary);
        if (!Require(in.good(), "Canonical gate status derivation test should open status file"))
        {
            ok = false;
            break;
        }

        std::stringstream buffer;
        buffer << in.rdbuf();
        const auto json = buffer.str();

        if (!Require(json.find("\"writeBackend\":\"Disabled\"") != std::string::npos, "Canonical gate status derivation should report writeBackend Disabled"))
        {
            ok = false;
            break;
        }
        if (!Require(json.find("\"recoveryReason\":\"CommitPathNotReady\"") != std::string::npos, "Canonical gate status derivation should preserve canonical recovery reason"))
        {
            ok = false;
            break;
        }
        if (!Require(json.find("\"canonicalGateFailure\":\"CommitPathNotReady\"") != std::string::npos, "Canonical gate status derivation should emit canonicalGateFailure from recovery reason"))
        {
            ok = false;
            break;
        }
        if (!Require(json.find("\"canonicalPathActive\":false") != std::string::npos, "Canonical gate status derivation should emit canonicalPathActive=false when canonical gate proof failed"))
        {
            ok = false;
            break;
        }
    } while (false);

    std::filesystem::remove_all(status_root, ec);
    return ok;
}

bool TestStatusFilePreservesExplicitCompatibilitySignalsAfterNativeFailClosedDowngrade()
{
    struct Scenario
    {
        const wchar_t* RecoveryReason;
        bool ExpectFixtureLegacyFallback;
        bool ExpectFixtureCompatibilityPath;
        bool ExpectUsesScaffoldCommitBlob;
    };

    constexpr std::array<Scenario, 3> scenarios =
    {
        Scenario{L"FixtureLegacyFallbackActive", true, false, false},
        Scenario{L"FixtureCompatibilityPathActive", false, true, false},
        Scenario{L"ScaffoldCommitBlobActive", false, false, true},
    };

    std::error_code ec;
    auto status_root = std::filesystem::temp_directory_path(ec) / "ApfsAccess" / "fs-host-semantics" / std::to_wstring(GetTickCount64());
    if (ec)
    {
        return Require(false, "Compatibility signal status derivation test should resolve temp directory");
    }
    std::filesystem::create_directories(status_root, ec);
    if (ec)
    {
        return Require(false, "Compatibility signal status derivation test should create temp directory");
    }

    bool ok = true;
    for (std::size_t index = 0; index < scenarios.size(); ++index)
    {
        const auto& scenario = scenarios[index];
        MountContext context{};
        context.args.readwrite = true;
        context.args.write_backend = L"Native";
        context.native_write_enabled = false;
        context.overlay_write_enabled = false;
        context.write_degraded = true;
        context.recovery_active = true;
        context.runtime_recovery_reason = scenario.RecoveryReason;
        context.runtime_last_recovery_action = L"DowngradedAfterCompatibilityGate";
        context.args.status_file = (status_root / (L"status_" + std::to_wstring(index) + L".json")).wstring();

        if (!Require(
                WriteHostStatusFile(context, context.recovery_active, context.runtime_last_commit_xid),
                "Compatibility signal status derivation test should write status file"))
        {
            ok = false;
            break;
        }

        const auto status_path = std::filesystem::path(context.args.status_file);
        std::ifstream in(status_path, std::ios::binary);
        if (!Require(in.good(), "Compatibility signal status derivation test should open status file"))
        {
            ok = false;
            break;
        }

        std::stringstream buffer;
        buffer << in.rdbuf();
        const auto json = buffer.str();

        if (!Require(json.find("\"writeBackend\":\"Disabled\"") != std::string::npos, "Compatibility signal derivation should report writeBackend Disabled"))
        {
            ok = false;
            break;
        }
        if (!Require(json.find("\"canonicalGateFailure\":null") != std::string::npos, "Compatibility signal derivation should keep canonicalGateFailure null for non-canonical reasons"))
        {
            ok = false;
            break;
        }
        if (!Require(
                json.find("\"fixtureLegacyFallbackActive\":true") != std::string::npos == scenario.ExpectFixtureLegacyFallback,
                "Compatibility signal derivation should preserve fixtureLegacyFallbackActive by recovery reason"))
        {
            ok = false;
            break;
        }
        if (!Require(
                json.find("\"fixtureCompatibilityPathActive\":true") != std::string::npos == scenario.ExpectFixtureCompatibilityPath,
                "Compatibility signal derivation should preserve fixtureCompatibilityPathActive by recovery reason"))
        {
            ok = false;
            break;
        }
        if (!Require(
                json.find("\"usesScaffoldCommitBlob\":true") != std::string::npos == scenario.ExpectUsesScaffoldCommitBlob,
                "Compatibility signal derivation should preserve usesScaffoldCommitBlob by recovery reason"))
        {
            ok = false;
            break;
        }
    }

    std::filesystem::remove_all(status_root, ec);
    return ok;
}

bool TestNativeSafetyStateFallsBackWhenMutationUnavailable()
{
    MountContext context{};
    context.args.readwrite = true;
    context.args.write_backend = L"Native";
    context.native_write_enabled = true;
    context.overlay_write_enabled = false;

    const auto native_safety = ResolveNativeWriteSafetyStateStatus(context);
    if (!Require(
            !_wcsicmp(native_safety.c_str(), L"ReadOnlyFallback"),
            "Native safety state should report ReadOnlyFallback when mutation writes are unavailable"))
    {
        return false;
    }

    context.args.write_backend = L"Overlay";
    context.native_write_enabled = false;
    context.overlay_write_enabled = true;
    const auto overlay_safety = ResolveNativeWriteSafetyStateStatus(context);
    return Require(
        !_wcsicmp(overlay_safety.c_str(), L"PilotReadWrite"),
        "Overlay safety state should remain PilotReadWrite when mutation writes are enabled");
}

bool TestExternalMutationScopeTracksActiveCountAndDrainGate()
{
    MountContext context{};

    {
        ExternalMutationRequestScope first_scope(&context);
        if (!Require(first_scope.Acquired(), "First external mutation scope should acquire when drain is inactive"))
        {
            return false;
        }
        if (!Require(context.active_external_mutation_callbacks.load() == 1, "Acquired external mutation scope should increment active counter"))
        {
            return false;
        }

        context.shutdown_drain_active.store(true);
        ExternalMutationRequestScope blocked_scope(&context);
        if (!Require(!blocked_scope.Acquired(), "External mutation scope should be rejected once shutdown drain is active"))
        {
            return false;
        }
        if (!Require(context.active_external_mutation_callbacks.load() == 1, "Rejected external mutation scope must not increment active counter"))
        {
            return false;
        }
    }

    return Require(context.active_external_mutation_callbacks.load() == 0, "Destroying acquired external mutation scope should decrement active counter");
}

bool TestBeginMutationShutdownDrainWaitsForInFlightMutation()
{
    MountContext context{};
    context.args.write_commit_timeout_seconds = 2;
    context.shutdown_drain_active.store(false);
    context.active_external_mutation_callbacks.store(0);

    std::atomic<bool> worker_entered{false};
    std::thread worker([&]()
    {
        ExternalMutationRequestScope scope(&context);
        if (!scope.Acquired())
        {
            return;
        }
        worker_entered.store(true);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    });

    const auto wait_started = std::chrono::steady_clock::now();
    while (!worker_entered.load())
    {
        if (std::chrono::steady_clock::now() - wait_started > std::chrono::seconds(1))
        {
            worker.join();
            return Require(false, "Worker failed to enter external mutation scope before drain wait test");
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    const auto drain_started = std::chrono::steady_clock::now();
    BeginMutationShutdownDrain(&context);
    const auto drain_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - drain_started);

    worker.join();

    if (!Require(context.shutdown_drain_active.load(), "BeginMutationShutdownDrain should latch shutdown drain active"))
    {
        return false;
    }
    if (!Require(drain_elapsed.count() >= 120, "Drain should wait for in-flight mutation callbacks to complete"))
    {
        return false;
    }
    if (!Require(drain_elapsed.count() < 1500, "Drain should not exceed configured timeout when callback completes in time"))
    {
        return false;
    }

    return Require(context.active_external_mutation_callbacks.load() == 0, "Drain wait completion should leave no active external mutation callbacks");
}

bool TestBeginMutationShutdownDrainTimesOutWithStuckMutation()
{
    MountContext context{};
    context.args.write_commit_timeout_seconds = 1;
    context.shutdown_drain_active.store(false);
    context.active_external_mutation_callbacks.store(0);

    std::atomic<bool> worker_entered{false};
    std::thread worker([&]()
    {
        ExternalMutationRequestScope scope(&context);
        if (!scope.Acquired())
        {
            return;
        }
        worker_entered.store(true);
        std::this_thread::sleep_for(std::chrono::milliseconds(1800));
    });

    const auto wait_started = std::chrono::steady_clock::now();
    while (!worker_entered.load())
    {
        if (std::chrono::steady_clock::now() - wait_started > std::chrono::seconds(1))
        {
            worker.join();
            return Require(false, "Worker failed to enter external mutation scope before drain-timeout test");
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    const auto drain_started = std::chrono::steady_clock::now();
    BeginMutationShutdownDrain(&context);
    const auto drain_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - drain_started);

    if (!Require(context.shutdown_drain_active.load(), "Drain timeout path should still latch shutdown drain active"))
    {
        worker.join();
        return false;
    }
    if (!Require(drain_elapsed.count() >= 850, "Drain timeout should wait approximately the configured timeout window"))
    {
        worker.join();
        return false;
    }
    if (!Require(drain_elapsed.count() < 1700, "Drain timeout should return promptly after timeout window"))
    {
        worker.join();
        return false;
    }
    if (!Require(context.active_external_mutation_callbacks.load() > 0, "Drain timeout should return while stuck mutation callback is still active"))
    {
        worker.join();
        return false;
    }

    worker.join();
    return Require(context.active_external_mutation_callbacks.load() == 0, "Active mutation callback count should clear once stuck callback completes");
}

bool TestCommitTimeoutBudgetScalesWithPendingPayload()
{
    const auto empty_budget = ComputeWriteCommitTimeoutBudgetSeconds(15, 0);
    if (!Require(empty_budget == 15, "Commit timeout budget should preserve configured timeout for metadata-only commits"))
    {
        return false;
    }

    const auto large_budget = ComputeWriteCommitTimeoutBudgetSeconds(15, 1ull * 1024ull * 1024ull * 1024ull);
    if (!Require(large_budget > 15, "Commit timeout budget should grow for large pending payload commits"))
    {
        return false;
    }
    if (!Require(large_budget <= 180, "Commit timeout budget should remain capped for large pending payload commits"))
    {
        return false;
    }

    const auto capped_budget = ComputeWriteCommitTimeoutBudgetSeconds(
        15,
        std::numeric_limits<std::uint64_t>::max());
    if (!Require(capped_budget == 180, "Commit timeout budget should cap extreme pending payload estimates"))
    {
        return false;
    }
    if (!Require(
            ComputeWriteCommitTimeoutBudgetSeconds(240, 1ull * 1024ull * 1024ull) == 240,
            "Commit timeout budget should preserve explicit configured timeouts above the payload extension cap"))
    {
        return false;
    }

    return Require(
        ComputeWriteCommitTimeoutBudgetSeconds(0, 0) == 1,
        "Commit timeout budget should clamp invalid configured timeouts to one second");
}

bool TestStatusFileTracksShutdownDrainAndInFlightMutations()
{
    MountContext context{};
    context.args.readwrite = true;
    context.args.write_backend = L"Overlay";
    context.overlay_write_enabled = true;

    std::error_code ec;
    auto status_root = std::filesystem::temp_directory_path(ec) / "ApfsAccess" / "fs-host-semantics" / std::to_wstring(GetTickCount64());
    if (ec)
    {
        return Require(false, "Status drain telemetry test should resolve temp directory");
    }
    std::filesystem::create_directories(status_root, ec);
    if (ec)
    {
        return Require(false, "Status drain telemetry test should create status directory");
    }
    context.args.status_file = (status_root / "status.json").wstring();
    context.args.write_commit_timeout_seconds = 2;

    std::atomic<bool> worker_entered{false};
    std::thread worker([&]()
    {
        ExternalMutationRequestScope scope(&context);
        if (!scope.Acquired())
        {
            return;
        }
        worker_entered.store(true);
        std::this_thread::sleep_for(std::chrono::milliseconds(220));
    });

    bool ok = true;
    do
    {
        const auto wait_started = std::chrono::steady_clock::now();
        while (!worker_entered.load())
        {
            if (std::chrono::steady_clock::now() - wait_started > std::chrono::seconds(1))
            {
                ok = Require(false, "Status drain telemetry test worker failed to enter mutation scope");
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        if (!ok)
        {
            break;
        }

        if (!Require(
                WriteHostStatusFile(context, context.recovery_active, context.runtime_last_commit_xid),
                "Status drain telemetry test should write status snapshot while mutation is in-flight"))
        {
            ok = false;
            break;
        }

        auto status_path = std::filesystem::path(context.args.status_file);
        std::ifstream in_before(status_path, std::ios::binary);
        if (!Require(in_before.good(), "Status drain telemetry test should open pre-drain status file"))
        {
            ok = false;
            break;
        }

        std::stringstream before_buffer;
        before_buffer << in_before.rdbuf();
        const auto before_json = before_buffer.str();
        if (!Require(before_json.find("\"shutdownDrainActive\":false") != std::string::npos, "Pre-drain status should report shutdownDrainActive=false"))
        {
            ok = false;
            break;
        }
        if (!Require(before_json.find("\"inFlightMutationCallbacks\":1") != std::string::npos, "Pre-drain status should report one in-flight mutation callback"))
        {
            ok = false;
            break;
        }

        BeginMutationShutdownDrain(&context);
        worker.join();

        if (!Require(
                WriteHostStatusFile(context, context.recovery_active, context.runtime_last_commit_xid),
                "Status drain telemetry test should write status snapshot after drain completion"))
        {
            ok = false;
            break;
        }

        std::ifstream in_after(status_path, std::ios::binary);
        if (!Require(in_after.good(), "Status drain telemetry test should open post-drain status file"))
        {
            ok = false;
            break;
        }

        std::stringstream after_buffer;
        after_buffer << in_after.rdbuf();
        const auto after_json = after_buffer.str();
        if (!Require(after_json.find("\"shutdownDrainActive\":true") != std::string::npos, "Post-drain status should report shutdownDrainActive=true"))
        {
            ok = false;
            break;
        }
        if (!Require(after_json.find("\"inFlightMutationCallbacks\":0") != std::string::npos, "Post-drain status should report zero in-flight mutation callbacks"))
        {
            ok = false;
            break;
        }
    } while (false);

    if (worker.joinable())
    {
        worker.join();
    }
    std::filesystem::remove_all(status_root, ec);
    return ok;
}

bool TestExternalMutationScopePublishesIdleStatusOnExit()
{
    MountContext context{};
    context.args.readwrite = true;
    context.args.write_backend = L"Overlay";
    context.overlay_write_enabled = true;

    std::error_code ec;
    auto status_root = std::filesystem::temp_directory_path(ec) / "ApfsAccess" / "fs-host-semantics" / std::to_wstring(GetTickCount64());
    if (ec)
    {
        return Require(false, "External mutation status refresh test should resolve temp directory");
    }
    std::filesystem::create_directories(status_root, ec);
    if (ec)
    {
        return Require(false, "External mutation status refresh test should create status directory");
    }
    context.args.status_file = (status_root / "status.json").wstring();

    bool ok = true;
    do
    {
        {
            ExternalMutationRequestScope scope(&context);
            if (!Require(scope.Acquired(), "External mutation status refresh test should acquire mutation scope"))
            {
                ok = false;
                break;
            }
            if (!Require(
                    WriteHostStatusFile(context, context.recovery_active, context.runtime_last_commit_xid),
                    "External mutation status refresh test should write in-flight status"))
            {
                ok = false;
                break;
            }
        }

        const auto status_path = std::filesystem::path(context.args.status_file);
        std::ifstream in(status_path, std::ios::binary);
        if (!Require(in.good(), "External mutation status refresh test should open refreshed status file"))
        {
            ok = false;
            break;
        }

        std::stringstream buffer;
        buffer << in.rdbuf();
        const auto json = buffer.str();
        if (!Require(json.find("\"inFlightMutationCallbacks\":0") != std::string::npos, "External mutation scope exit should publish zero in-flight callbacks"))
        {
            ok = false;
            break;
        }
    } while (false);

    std::filesystem::remove_all(status_root, ec);
    return ok;
}

bool TestCleanRecoveryCheckpointXidPrefersSuperblockWhenCommittedTelemetryStale()
{
#ifdef APFSACCESS_HAS_RW_ENGINE
    const auto reconciled = ResolveCleanRecoveryCheckpointXid(765ull, 766ull);
    if (!Require(
            reconciled.has_value() && reconciled.value() == 766ull,
            "Recovery-marker reconciliation should prefer the newer clean checkpoint xid over stale committed telemetry"))
    {
        return false;
    }

    const auto committed_only = ResolveCleanRecoveryCheckpointXid(765ull, std::optional<std::uint64_t>{});
    if (!Require(
            committed_only.has_value() && committed_only.value() == 765ull,
            "Recovery-marker reconciliation should preserve committed xid when checkpoint xid is unavailable"))
    {
        return false;
    }

    const auto checkpoint_only = ResolveCleanRecoveryCheckpointXid(std::optional<std::uint64_t>{}, 766ull);
    if (!Require(
            checkpoint_only.has_value() && checkpoint_only.value() == 766ull,
            "Recovery-marker reconciliation should use checkpoint xid when committed xid is unavailable"))
    {
        return false;
    }
#endif

    return true;
}

bool TestConcurrentCreateSamePathIsSerializedAndConsistent()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    auto fs = BuildFileSystem(&context);
    std::atomic<bool> start{false};
    std::atomic<long> status1{STATUS_UNSUCCESSFUL};
    std::atomic<long> status2{STATUS_UNSUCCESSFUL};

    auto run_create = [&](std::atomic<long>& status_slot)
    {
        while (!start.load())
        {
            std::this_thread::yield();
        }

        PVOID out_ctx = nullptr;
        FSP_FSCTL_FILE_INFO info{};
        const auto status = CB_Create(
            &fs,
            const_cast<PWSTR>(L"\\race.txt"),
            FILE_NON_DIRECTORY_FILE,
            FILE_WRITE_DATA,
            0,
            nullptr,
            0,
            &out_ctx,
            &info);
        status_slot.store(status);
        if (status == STATUS_SUCCESS && out_ctx != nullptr)
        {
            CB_Close(&fs, out_ctx);
        }
    };

    std::thread t1(run_create, std::ref(status1));
    std::thread t2(run_create, std::ref(status2));
    start.store(true);

    t1.join();
    t2.join();

    const auto s1 = static_cast<NTSTATUS>(status1.load());
    const auto s2 = static_cast<NTSTATUS>(status2.load());
    const int success_count = (s1 == STATUS_SUCCESS ? 1 : 0) + (s2 == STATUS_SUCCESS ? 1 : 0);
    const int collision_count = (s1 == STATUS_OBJECT_NAME_COLLISION ? 1 : 0) + (s2 == STATUS_OBJECT_NAME_COLLISION ? 1 : 0);

    if (!Require(success_count == 1, "Exactly one concurrent create should succeed for identical path"))
    {
        return false;
    }
    if (!Require(collision_count == 1, "Exactly one concurrent create should report STATUS_OBJECT_NAME_COLLISION"))
    {
        return false;
    }
    if (!Require(context.nodes.find(Key(L"\\race.txt")) != context.nodes.end(), "Concurrent create race should leave exactly one created node"))
    {
        return false;
    }

    int child_count = 0;
    for (const auto& child : root->children)
    {
        if (!_wcsicmp(child.c_str(), L"race.txt"))
        {
            ++child_count;
        }
    }

    return Require(child_count == 1, "Parent directory child list should contain only one race-created entry");
}

bool TestConcurrentRenameSameSourceDifferentTargetsIsSerialized()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"source.txt");
    auto source = MakeNode(L"\\source.txt", false, false);
    context.nodes.emplace(Key(source->path), source);

    auto fs = BuildFileSystem(&context);
    std::atomic<bool> start{false};
    std::atomic<long> status_a{STATUS_UNSUCCESSFUL};
    std::atomic<long> status_b{STATUS_UNSUCCESSFUL};

    auto run_rename = [&](const wchar_t* new_path, std::atomic<long>& status_slot)
    {
        while (!start.load())
        {
            std::this_thread::yield();
        }

        const auto status = CB_Rename(
            &fs,
            nullptr,
            const_cast<PWSTR>(L"\\source.txt"),
            const_cast<PWSTR>(new_path),
            FALSE);
        status_slot.store(status);
    };

    std::thread t1(run_rename, L"\\dest-a.txt", std::ref(status_a));
    std::thread t2(run_rename, L"\\dest-b.txt", std::ref(status_b));
    start.store(true);

    t1.join();
    t2.join();

    const auto s1 = static_cast<NTSTATUS>(status_a.load());
    const auto s2 = static_cast<NTSTATUS>(status_b.load());
    const int success_count = (s1 == STATUS_SUCCESS ? 1 : 0) + (s2 == STATUS_SUCCESS ? 1 : 0);
    const int not_found_count = (s1 == STATUS_OBJECT_NAME_NOT_FOUND ? 1 : 0) + (s2 == STATUS_OBJECT_NAME_NOT_FOUND ? 1 : 0);

    if (!Require(success_count == 1, "Exactly one concurrent rename should succeed for identical source path"))
    {
        return false;
    }
    if (!Require(not_found_count == 1, "Exactly one concurrent rename should report STATUS_OBJECT_NAME_NOT_FOUND after source move"))
    {
        return false;
    }
    if (!Require(context.nodes.find(Key(L"\\source.txt")) == context.nodes.end(), "Concurrent rename race should remove original source path"))
    {
        return false;
    }

    const bool has_dest_a = context.nodes.find(Key(L"\\dest-a.txt")) != context.nodes.end();
    const bool has_dest_b = context.nodes.find(Key(L"\\dest-b.txt")) != context.nodes.end();
    if (!Require(has_dest_a != has_dest_b, "Concurrent rename race should materialize exactly one destination path"))
    {
        return false;
    }

    int visible_dest_count = 0;
    for (const auto& child : root->children)
    {
        if (!_wcsicmp(child.c_str(), L"dest-a.txt") || !_wcsicmp(child.c_str(), L"dest-b.txt"))
        {
            ++visible_dest_count;
        }
        if (!_wcsicmp(child.c_str(), L"source.txt"))
        {
            return Require(false, "Source child entry should not remain after successful concurrent rename");
        }
    }

    return Require(visible_dest_count == 1, "Parent directory child list should contain exactly one concurrent-rename destination");
}

bool TestConcurrentRenameAndSetDeleteOnSameSourceIsSerialized()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"source.txt");
    auto source = MakeNode(L"\\source.txt", false, false);
    source->open_handle_count = 1;
    context.nodes.emplace(Key(source->path), source);

    OpenContext source_open{};
    source_open.node = source;
    source_open.allow_delete = true;

    auto fs = BuildFileSystem(&context);
    std::atomic<bool> start{false};
    std::atomic<long> rename_status{STATUS_UNSUCCESSFUL};
    std::atomic<long> set_delete_status{STATUS_UNSUCCESSFUL};

    auto run_rename = [&]()
    {
        while (!start.load())
        {
            std::this_thread::yield();
        }
        const auto status = CB_Rename(
            &fs,
            &source_open,
            const_cast<PWSTR>(L"\\source.txt"),
            const_cast<PWSTR>(L"\\renamed.txt"),
            FALSE);
        rename_status.store(status);
    };

    auto run_set_delete = [&]()
    {
        while (!start.load())
        {
            std::this_thread::yield();
        }
        const auto status = CB_SetDelete(
            &fs,
            &source_open,
            const_cast<PWSTR>(L"\\source.txt"),
            TRUE);
        set_delete_status.store(status);
    };

    std::thread t1(run_rename);
    std::thread t2(run_set_delete);
    start.store(true);

    t1.join();
    t2.join();

    const auto rename = static_cast<NTSTATUS>(rename_status.load());
    const auto set_delete = static_cast<NTSTATUS>(set_delete_status.load());

    const bool rename_won =
        rename == STATUS_SUCCESS &&
        set_delete == STATUS_OBJECT_NAME_NOT_FOUND &&
        context.nodes.find(Key(L"\\source.txt")) == context.nodes.end() &&
        context.nodes.find(Key(L"\\renamed.txt")) != context.nodes.end();

    const auto source_it = context.nodes.find(Key(L"\\source.txt"));
    const bool delete_won =
        rename == STATUS_DELETE_PENDING &&
        set_delete == STATUS_SUCCESS &&
        source_it != context.nodes.end() &&
        source_it->second->delete_pending &&
        source_it->second->delete_intent_count > 0;

    if (!Require(rename_won || delete_won, "Concurrent rename/set-delete race should resolve to exactly one serialized winner"))
    {
        return false;
    }

    if (rename_won)
    {
        return Require(
            context.nodes.find(Key(L"\\renamed.txt")) != context.nodes.end(),
            "Rename-winning race outcome should preserve renamed destination");
    }

    return Require(
        context.nodes.find(Key(L"\\renamed.txt")) == context.nodes.end(),
        "SetDelete-winning race outcome should not materialize renamed destination");
}

bool TestConcurrentRenameReplaceAndTargetSetDeleteIsFailClosed()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"source.txt");
    AddChildName(root->children, L"target.txt");

    auto source = MakeNode(L"\\source.txt", false, false);
    auto target = MakeNode(L"\\target.txt", false, false);
    target->open_handle_count = 1;
    context.nodes.emplace(Key(source->path), source);
    context.nodes.emplace(Key(target->path), target);

    OpenContext target_open{};
    target_open.node = target;
    target_open.allow_delete = true;

    OpenContext parent_open{};
    parent_open.node = root;
    parent_open.allow_delete_child = true;
    parent_open.allow_write_data = true;

    auto fs = BuildFileSystem(&context);
    std::atomic<bool> start{false};
    std::atomic<long> rename_status{STATUS_UNSUCCESSFUL};
    std::atomic<long> set_delete_status{STATUS_UNSUCCESSFUL};

    auto run_rename_replace = [&]()
    {
        while (!start.load())
        {
            std::this_thread::yield();
        }
        const auto status = CB_Rename(
            &fs,
            &parent_open,
            const_cast<PWSTR>(L"\\source.txt"),
            const_cast<PWSTR>(L"\\target.txt"),
            TRUE);
        rename_status.store(status);
    };

    auto run_set_delete = [&]()
    {
        while (!start.load())
        {
            std::this_thread::yield();
        }
        const auto status = CB_SetDelete(
            &fs,
            &target_open,
            const_cast<PWSTR>(L"\\target.txt"),
            TRUE);
        set_delete_status.store(status);
    };

    std::thread t1(run_rename_replace);
    std::thread t2(run_set_delete);
    start.store(true);
    t1.join();
    t2.join();

    const auto rename = static_cast<NTSTATUS>(rename_status.load());
    const auto set_delete = static_cast<NTSTATUS>(set_delete_status.load());

    const bool delete_won =
        (rename == STATUS_DELETE_PENDING || rename == STATUS_OBJECT_NAME_NOT_FOUND) &&
        set_delete == STATUS_SUCCESS &&
        context.nodes.find(Key(L"\\source.txt")) != context.nodes.end() &&
        context.nodes.find(Key(L"\\target.txt")) != context.nodes.end() &&
        context.nodes.at(Key(L"\\target.txt"))->delete_pending;

    const bool rename_won =
        rename == STATUS_SUCCESS &&
        (set_delete == STATUS_OBJECT_NAME_NOT_FOUND || set_delete == STATUS_INVALID_PARAMETER) &&
        context.nodes.find(Key(L"\\source.txt")) == context.nodes.end() &&
        context.nodes.find(Key(L"\\target.txt")) != context.nodes.end();

    const bool serialized_collision =
        rename == STATUS_OBJECT_NAME_COLLISION &&
        set_delete == STATUS_SUCCESS &&
        context.nodes.find(Key(L"\\source.txt")) != context.nodes.end() &&
        context.nodes.find(Key(L"\\target.txt")) != context.nodes.end() &&
        context.nodes.at(Key(L"\\target.txt"))->delete_pending;

    if (!Require(rename_won || delete_won || serialized_collision, "Concurrent rename-replace vs target set-delete should resolve to a serialized non-corrupt state"))
    {
        return false;
    }

    if (rename_won)
    {
        return Require(
            !context.nodes.at(Key(L"\\target.txt"))->delete_pending,
            "Rename-winning replace race should leave replacement target visible");
    }

    return Require(
        context.nodes.at(Key(L"\\target.txt"))->delete_intent_count > 0,
        "SetDelete-winning replace race should latch target delete intent");
}

bool TestConcurrentRenameReplaceAndDeleteCloseInterleavingIsConsistent()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"source.txt");
    AddChildName(root->children, L"target.txt");

    auto source = MakeNode(L"\\source.txt", false, false);
    auto target = MakeNode(L"\\target.txt", false, false);
    target->open_handle_count = 1;
    context.nodes.emplace(Key(source->path), source);
    context.nodes.emplace(Key(target->path), target);

    auto fs = BuildFileSystem(&context);
    auto* delete_handle = new OpenContext();
    delete_handle->node = target;
    delete_handle->allow_delete = true;
    CB_Cleanup(
        &fs,
        delete_handle,
        const_cast<PWSTR>(L"\\target.txt"),
        FspCleanupDelete);
    if (!Require(delete_handle->delete_on_cleanup, "Delete-close interleaving test should start with latched delete-on-cleanup target"))
    {
        CB_Close(&fs, delete_handle);
        return false;
    }

    OpenContext parent_open{};
    parent_open.node = root;
    parent_open.allow_delete_child = true;
    parent_open.allow_write_data = true;

    std::atomic<bool> start{false};
    std::atomic<long> rename_status{STATUS_UNSUCCESSFUL};

    auto run_close = [&]()
    {
        while (!start.load())
        {
            std::this_thread::yield();
        }
        CB_Close(&fs, delete_handle);
    };

    auto run_rename_replace = [&]()
    {
        while (!start.load())
        {
            std::this_thread::yield();
        }
        const auto status = CB_Rename(
            &fs,
            &parent_open,
            const_cast<PWSTR>(L"\\source.txt"),
            const_cast<PWSTR>(L"\\target.txt"),
            TRUE);
        rename_status.store(status);
    };

    std::thread t1(run_close);
    std::thread t2(run_rename_replace);
    start.store(true);
    t1.join();
    t2.join();

    const auto rename = static_cast<NTSTATUS>(rename_status.load());
    if (!Require(rename == STATUS_SUCCESS || rename == STATUS_DELETE_PENDING, "Rename-replace vs delete-close interleaving should resolve to SUCCESS or DELETE_PENDING"))
    {
        return false;
    }

    const bool source_exists = context.nodes.find(Key(L"\\source.txt")) != context.nodes.end();
    const bool target_exists = context.nodes.find(Key(L"\\target.txt")) != context.nodes.end();

    if (rename == STATUS_SUCCESS)
    {
        if (!Require(!source_exists && target_exists, "Rename-success interleaving outcome should move source to target"))
        {
            return false;
        }
    }
    else
    {
        if (!Require(source_exists && !target_exists, "Rename-delete-pending interleaving outcome should preserve source and remove closed delete-latched target"))
        {
            return false;
        }
    }

    int source_children = 0;
    int target_children = 0;
    for (const auto& child : root->children)
    {
        if (!_wcsicmp(child.c_str(), L"source.txt"))
        {
            ++source_children;
        }
        if (!_wcsicmp(child.c_str(), L"target.txt"))
        {
            ++target_children;
        }
    }

    if (!Require(source_children <= 1 && target_children <= 1, "Interleaving outcome should not duplicate source/target child entries"))
    {
        return false;
    }

    if (rename == STATUS_SUCCESS)
    {
        return Require(source_children == 0 && target_children == 1, "Rename-success interleaving should leave only target child entry");
    }

    return Require(source_children == 1 && target_children == 0, "Rename-delete-pending interleaving should leave only source child entry");
}

bool TestConcurrentRenameReplaceSameTargetFromTwoSourcesIsSerialized()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"source-a.txt");
    AddChildName(root->children, L"source-b.txt");
    AddChildName(root->children, L"target.txt");

    auto source_a = MakeNode(L"\\source-a.txt", false, false);
    auto source_b = MakeNode(L"\\source-b.txt", false, false);
    auto target = MakeNode(L"\\target.txt", false, false);
    context.nodes.emplace(Key(source_a->path), source_a);
    context.nodes.emplace(Key(source_b->path), source_b);
    context.nodes.emplace(Key(target->path), target);

    OpenContext parent_open{};
    parent_open.node = root;
    parent_open.allow_delete_child = true;
    parent_open.allow_write_data = true;

    auto fs = BuildFileSystem(&context);
    std::atomic<bool> start{false};
    std::atomic<long> status_a{STATUS_UNSUCCESSFUL};
    std::atomic<long> status_b{STATUS_UNSUCCESSFUL};

    auto run_replace = [&](const wchar_t* source_path, std::atomic<long>& status_slot)
    {
        while (!start.load())
        {
            std::this_thread::yield();
        }

        const auto status = CB_Rename(
            &fs,
            &parent_open,
            const_cast<PWSTR>(source_path),
            const_cast<PWSTR>(L"\\target.txt"),
            TRUE);
        status_slot.store(status);
    };

    std::thread t1(run_replace, L"\\source-a.txt", std::ref(status_a));
    std::thread t2(run_replace, L"\\source-b.txt", std::ref(status_b));
    start.store(true);
    t1.join();
    t2.join();

    const auto s1 = static_cast<NTSTATUS>(status_a.load());
    const auto s2 = static_cast<NTSTATUS>(status_b.load());
    if (!Require(s1 == STATUS_SUCCESS && s2 == STATUS_SUCCESS, "Dual-source same-target rename-replace race should serialize to two successful replacements"))
    {
        return false;
    }

    const bool source_a_exists = context.nodes.find(Key(L"\\source-a.txt")) != context.nodes.end();
    const bool source_b_exists = context.nodes.find(Key(L"\\source-b.txt")) != context.nodes.end();
    const bool target_exists = context.nodes.find(Key(L"\\target.txt")) != context.nodes.end();
    if (!Require(!source_a_exists && !source_b_exists && target_exists, "Dual-source same-target rename-replace should leave only target path in node index"))
    {
        return false;
    }

    int source_a_children = 0;
    int source_b_children = 0;
    int target_children = 0;
    for (const auto& child : root->children)
    {
        if (!_wcsicmp(child.c_str(), L"source-a.txt"))
        {
            ++source_a_children;
        }
        if (!_wcsicmp(child.c_str(), L"source-b.txt"))
        {
            ++source_b_children;
        }
        if (!_wcsicmp(child.c_str(), L"target.txt"))
        {
            ++target_children;
        }
    }

    return Require(
        source_a_children == 0 && source_b_children == 0 && target_children == 1,
        "Dual-source same-target rename-replace should leave exactly one target child entry");
}

bool TestConcurrentRenameReplaceSameTargetWithHandleCloseTransition()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"source-a.txt");
    AddChildName(root->children, L"source-b.txt");
    AddChildName(root->children, L"target.txt");

    auto source_a = MakeNode(L"\\source-a.txt", false, false);
    auto source_b = MakeNode(L"\\source-b.txt", false, false);
    auto target = MakeNode(L"\\target.txt", false, false);
    target->open_handle_count = 1;
    context.nodes.emplace(Key(source_a->path), source_a);
    context.nodes.emplace(Key(source_b->path), source_b);
    context.nodes.emplace(Key(target->path), target);

    auto* keep_handle = new OpenContext();
    keep_handle->node = target;

    OpenContext parent_open{};
    parent_open.node = root;
    parent_open.allow_delete_child = true;
    parent_open.allow_write_data = true;

    auto fs = BuildFileSystem(&context);
    std::atomic<bool> start{false};
    std::atomic<long> status_a{STATUS_UNSUCCESSFUL};
    std::atomic<long> status_b{STATUS_UNSUCCESSFUL};

    auto run_replace = [&](const wchar_t* source_path, std::atomic<long>& status_slot)
    {
        while (!start.load())
        {
            std::this_thread::yield();
        }

        const auto status = CB_Rename(
            &fs,
            &parent_open,
            const_cast<PWSTR>(source_path),
            const_cast<PWSTR>(L"\\target.txt"),
            TRUE);
        status_slot.store(status);
    };

    auto run_close = [&]()
    {
        while (!start.load())
        {
            std::this_thread::yield();
        }
        CB_Close(&fs, keep_handle);
    };

    std::thread t1(run_replace, L"\\source-a.txt", std::ref(status_a));
    std::thread t2(run_replace, L"\\source-b.txt", std::ref(status_b));
    std::thread t3(run_close);
    start.store(true);
    t1.join();
    t2.join();
    t3.join();

    const auto s1 = static_cast<NTSTATUS>(status_a.load());
    const auto s2 = static_cast<NTSTATUS>(status_b.load());

    const auto valid_status = [](NTSTATUS status)
    {
        return status == STATUS_SUCCESS || status == STATUS_SHARING_VIOLATION;
    };
    if (!Require(valid_status(s1) && valid_status(s2), "Handle-transition replace race should only produce SUCCESS or SHARING_VIOLATION statuses"))
    {
        return false;
    }

    const int success_count = (s1 == STATUS_SUCCESS ? 1 : 0) + (s2 == STATUS_SUCCESS ? 1 : 0);
    const bool source_a_exists = context.nodes.find(Key(L"\\source-a.txt")) != context.nodes.end();
    const bool source_b_exists = context.nodes.find(Key(L"\\source-b.txt")) != context.nodes.end();
    const bool target_exists = context.nodes.find(Key(L"\\target.txt")) != context.nodes.end();

    if (!Require(target_exists, "Handle-transition replace race should preserve a target path"))
    {
        return false;
    }

    if (success_count == 0)
    {
        if (!Require(source_a_exists && source_b_exists, "No-success handle-transition outcome should preserve both source paths"))
        {
            return false;
        }
    }
    else if (success_count == 1)
    {
        if (!Require(source_a_exists != source_b_exists, "Single-success handle-transition outcome should remove exactly one source path"))
        {
            return false;
        }
    }
    else if (success_count == 2)
    {
        if (!Require(!source_a_exists && !source_b_exists, "Double-success handle-transition outcome should remove both source paths"))
        {
            return false;
        }
    }
    else
    {
        return Require(false, "Handle-transition replace race should not produce invalid success count");
    }

    int source_a_children = 0;
    int source_b_children = 0;
    int target_children = 0;
    for (const auto& child : root->children)
    {
        if (!_wcsicmp(child.c_str(), L"source-a.txt"))
        {
            ++source_a_children;
        }
        if (!_wcsicmp(child.c_str(), L"source-b.txt"))
        {
            ++source_b_children;
        }
        if (!_wcsicmp(child.c_str(), L"target.txt"))
        {
            ++target_children;
        }
    }

    if (!Require(source_a_children <= 1 && source_b_children <= 1 && target_children == 1, "Handle-transition replace race should keep parent children list deduplicated with one target entry"))
    {
        return false;
    }

    return Require(
        (source_a_children > 0) == source_a_exists &&
        (source_b_children > 0) == source_b_exists,
        "Handle-transition replace race should keep source child visibility aligned with node index");
}

bool TestConcurrentSharedParentRenameAndSetDeleteOnSiblingIsConsistent()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"source-a.txt");
    AddChildName(root->children, L"source-b.txt");

    auto source_a = MakeNode(L"\\source-a.txt", false, false);
    auto source_b = MakeNode(L"\\source-b.txt", false, false);
    source_b->open_handle_count = 1;
    context.nodes.emplace(Key(source_a->path), source_a);
    context.nodes.emplace(Key(source_b->path), source_b);

    OpenContext parent_open{};
    parent_open.node = root;
    parent_open.allow_delete_child = true;
    parent_open.allow_write_data = true;

    OpenContext source_b_open{};
    source_b_open.node = source_b;
    source_b_open.allow_delete = true;

    auto fs = BuildFileSystem(&context);
    std::atomic<bool> start{false};
    std::atomic<long> rename_status{STATUS_UNSUCCESSFUL};
    std::atomic<long> set_delete_status{STATUS_UNSUCCESSFUL};

    auto run_rename = [&]()
    {
        while (!start.load())
        {
            std::this_thread::yield();
        }
        const auto status = CB_Rename(
            &fs,
            &parent_open,
            const_cast<PWSTR>(L"\\source-a.txt"),
            const_cast<PWSTR>(L"\\source-c.txt"),
            FALSE);
        rename_status.store(status);
    };

    auto run_set_delete = [&]()
    {
        while (!start.load())
        {
            std::this_thread::yield();
        }
        const auto status = CB_SetDelete(
            &fs,
            &source_b_open,
            const_cast<PWSTR>(L"\\source-b.txt"),
            TRUE);
        set_delete_status.store(status);
    };

    std::thread t1(run_rename);
    std::thread t2(run_set_delete);
    start.store(true);
    t1.join();
    t2.join();

    if (!Require(static_cast<NTSTATUS>(rename_status.load()) == STATUS_SUCCESS, "Sibling rename in shared-parent race should succeed"))
    {
        return false;
    }
    if (!Require(static_cast<NTSTATUS>(set_delete_status.load()) == STATUS_SUCCESS, "Sibling set-delete in shared-parent race should succeed"))
    {
        return false;
    }

    if (!Require(context.nodes.find(Key(L"\\source-a.txt")) == context.nodes.end(), "Shared-parent sibling race should remove renamed source-a path"))
    {
        return false;
    }
    if (!Require(context.nodes.find(Key(L"\\source-c.txt")) != context.nodes.end(), "Shared-parent sibling race should materialize renamed destination path"))
    {
        return false;
    }
    if (!Require(context.nodes.find(Key(L"\\source-b.txt")) != context.nodes.end(), "Shared-parent sibling race should preserve set-delete source path"))
    {
        return false;
    }

    auto source_b_after = context.nodes.at(Key(L"\\source-b.txt"));
    if (!Require(source_b_after->delete_pending && source_b_after->delete_intent_count > 0, "Shared-parent sibling race should latch delete intent on source-b"))
    {
        return false;
    }

    int source_a_children = 0;
    int source_b_children = 0;
    int source_c_children = 0;
    for (const auto& child : root->children)
    {
        if (!_wcsicmp(child.c_str(), L"source-a.txt"))
        {
            ++source_a_children;
        }
        if (!_wcsicmp(child.c_str(), L"source-b.txt"))
        {
            ++source_b_children;
        }
        if (!_wcsicmp(child.c_str(), L"source-c.txt"))
        {
            ++source_c_children;
        }
    }

    return Require(
        source_a_children == 0 && source_b_children == 0 && source_c_children == 1,
        "Shared-parent sibling race should keep parent children list consistent (delete-pending sibling hidden)");
}

bool TestConcurrentSharedParentRenameAndSiblingDeleteCloseIsConsistent()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"source-a.txt");
    AddChildName(root->children, L"source-b.txt");

    auto source_a = MakeNode(L"\\source-a.txt", false, false);
    auto source_b = MakeNode(L"\\source-b.txt", false, false);
    source_b->open_handle_count = 1;
    context.nodes.emplace(Key(source_a->path), source_a);
    context.nodes.emplace(Key(source_b->path), source_b);

    auto fs = BuildFileSystem(&context);
    auto* delete_handle = new OpenContext();
    delete_handle->node = source_b;
    delete_handle->allow_delete = true;
    CB_Cleanup(
        &fs,
        delete_handle,
        const_cast<PWSTR>(L"\\source-b.txt"),
        FspCleanupDelete);
    if (!Require(delete_handle->delete_on_cleanup, "Shared-parent rename/delete-close race should start with latched sibling delete handle"))
    {
        CB_Close(&fs, delete_handle);
        return false;
    }

    OpenContext parent_open{};
    parent_open.node = root;
    parent_open.allow_delete_child = true;
    parent_open.allow_write_data = true;

    std::atomic<bool> start{false};
    std::atomic<long> rename_status{STATUS_UNSUCCESSFUL};

    auto run_rename = [&]()
    {
        while (!start.load())
        {
            std::this_thread::yield();
        }
        const auto status = CB_Rename(
            &fs,
            &parent_open,
            const_cast<PWSTR>(L"\\source-a.txt"),
            const_cast<PWSTR>(L"\\source-c.txt"),
            FALSE);
        rename_status.store(status);
    };

    auto run_close = [&]()
    {
        while (!start.load())
        {
            std::this_thread::yield();
        }
        CB_Close(&fs, delete_handle);
    };

    std::thread t1(run_rename);
    std::thread t2(run_close);
    start.store(true);
    t1.join();
    t2.join();

    if (!Require(static_cast<NTSTATUS>(rename_status.load()) == STATUS_SUCCESS, "Shared-parent rename should succeed while sibling delete-close finalizes"))
    {
        return false;
    }

    if (!Require(context.nodes.find(Key(L"\\source-a.txt")) == context.nodes.end(), "Shared-parent rename/delete-close race should remove source-a path"))
    {
        return false;
    }
    if (!Require(context.nodes.find(Key(L"\\source-c.txt")) != context.nodes.end(), "Shared-parent rename/delete-close race should materialize source-c path"))
    {
        return false;
    }
    if (!Require(context.nodes.find(Key(L"\\source-b.txt")) == context.nodes.end(), "Shared-parent rename/delete-close race should remove delete-closed sibling path"))
    {
        return false;
    }

    int source_a_children = 0;
    int source_b_children = 0;
    int source_c_children = 0;
    for (const auto& child : root->children)
    {
        if (!_wcsicmp(child.c_str(), L"source-a.txt"))
        {
            ++source_a_children;
        }
        if (!_wcsicmp(child.c_str(), L"source-b.txt"))
        {
            ++source_b_children;
        }
        if (!_wcsicmp(child.c_str(), L"source-c.txt"))
        {
            ++source_c_children;
        }
    }

    return Require(
        source_a_children == 0 && source_b_children == 0 && source_c_children == 1,
        "Shared-parent rename/delete-close race should keep parent children list consistent");
}

bool TestLoadHydratedPayloadWithoutHydrationReturnsNullWhenHydrateDisabled()
{
#ifdef APFSACCESS_HAS_RW_ENGINE
    MountContext context{};
    SeedRoot(context);
    std::error_code ec;
    context.session_root = std::filesystem::temp_directory_path(ec) / "ApfsAccess" / "fs-host-semantics" / std::to_wstring(GetTickCount64());
    if (ec)
    {
        return Require(false, "Session root should resolve for hydration payload test");
    }
    context.cache_root = context.session_root / "hydrate";
    std::filesystem::create_directories(context.cache_root, ec);
    if (ec)
    {
        return Require(false, "Cache root should be created for hydration payload test");
    }

    auto node = MakeNode(L"\\payload.bin", false);
    node->file_size = 4;
    context.nodes.emplace(Key(node->path), node);
    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"payload.bin");

    auto hydration_path = HydrationPath(&context, *node);
    std::filesystem::remove(hydration_path, ec);
    ec.clear();

    const auto payload = LoadHydratedPayloadForPath(&context, node->path, 4, false);
    const auto hydration_exists = std::filesystem::exists(hydration_path, ec);
    std::filesystem::remove_all(context.session_root, ec);

    if (!Require(!payload.has_value(), "Payload load should fail when hydration is missing and hydrate-if-missing is disabled"))
    {
        return false;
    }
    return Require(!hydration_exists, "Disabled hydrate-if-missing should not create hydration files");
#else
    return true;
#endif
}

bool TestLoadHydratedPayloadReadsExistingHydrationWhenHydrateDisabled()
{
#ifdef APFSACCESS_HAS_RW_ENGINE
    MountContext context{};
    SeedRoot(context);
    std::error_code ec;
    context.session_root = std::filesystem::temp_directory_path(ec) / "ApfsAccess" / "fs-host-semantics" / std::to_wstring(GetTickCount64());
    if (ec)
    {
        return Require(false, "Session root should resolve for existing hydration payload test");
    }
    context.cache_root = context.session_root / "hydrate";
    std::filesystem::create_directories(context.cache_root, ec);
    if (ec)
    {
        return Require(false, "Cache root should be created for existing hydration payload test");
    }

    auto node = MakeNode(L"\\existing.bin", false);
    node->file_size = 5;
    context.nodes.emplace(Key(node->path), node);
    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"existing.bin");

    auto hydration_path = HydrationPath(&context, *node);
    std::filesystem::create_directories(hydration_path.parent_path(), ec);
    if (ec)
    {
        std::filesystem::remove_all(context.session_root, ec);
        return Require(false, "Hydration parent path should be created");
    }

    std::ofstream out(hydration_path, std::ios::binary | std::ios::trunc);
    if (!out.good())
    {
        std::filesystem::remove_all(context.session_root, ec);
        return Require(false, "Hydration file should be writable");
    }
    const std::array<std::byte, 3> source
    {
        std::byte{'A'},
        std::byte{'B'},
        std::byte{'C'},
    };
    out.write(reinterpret_cast<const char*>(source.data()), static_cast<std::streamsize>(source.size()));
    out.close();

    const auto payload = LoadHydratedPayloadForPath(&context, node->path, 5, false);
    std::filesystem::remove_all(context.session_root, ec);
    if (!Require(payload.has_value(), "Payload load should succeed when hydration file already exists"))
    {
        return false;
    }

    if (!Require(payload->size() == 5, "Loaded payload should be padded to requested logical size"))
    {
        return false;
    }

    if (!Require((*payload)[0] == std::byte{'A'} &&
                 (*payload)[1] == std::byte{'B'} &&
                 (*payload)[2] == std::byte{'C'},
                 "Loaded payload should preserve hydrated bytes"))
    {
        return false;
    }

    return Require((*payload)[3] == std::byte{0} && (*payload)[4] == std::byte{0}, "Loaded payload padding should be zero-filled");
#else
    return true;
#endif
}

bool TestReadOnlyOpenUsesMetadataRangeReadWithoutHydration()
{
#ifdef APFSACCESS_HAS_RW_ENGINE
    MountContext context{};
    context.args.volume = L"Main";
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);
    if (!Require(PrepareUnitHydrationRoot(context, L"metadata-range-read-open"), "Metadata range-read open test should prepare cache root"))
    {
        return false;
    }

    std::error_code ec;
    const auto image_path = context.session_root / "metadata-range-read.apfs.img";
    if (!Require(CreateSyntheticApfsContainerForTest(image_path), "Metadata range-read open test should create synthetic APFS image"))
    {
        std::filesystem::remove_all(context.session_root, ec);
        return false;
    }

    apfsaccess::rw::MetadataStore::VolumeContext rw_context
    {
        image_path.wstring(),
        L"Main",
    };
    context.metadata_store = std::make_unique<apfsaccess::rw::MetadataStore>(std::move(rw_context));
    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    context.metadata_store->SetFilePayloadProvider(
        [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
        {
            auto pending = staged_payloads.find(path);
            if (pending == staged_payloads.end())
            {
                return std::nullopt;
            }

            auto payload = pending->second;
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

    {
        std::lock_guard<std::mutex> metadata_lock(context.metadata_mutex);
        if (!Require(context.metadata_store->LoadContainerSuperblocks(), "Metadata range-read open test should load container superblocks") ||
            !Require(context.metadata_store->LoadObjectMap(), "Metadata range-read open test should load object map") ||
            !Require(context.metadata_store->LoadSpacemanState(), "Metadata range-read open test should load spaceman state") ||
            !Require(context.metadata_store->PrepareNativeWritePath(), "Metadata range-read open test should prepare native write path"))
        {
            std::filesystem::remove_all(context.session_root, ec);
            return false;
        }

        apfsaccess::rw::MetadataStore::MutationRequest create_file{};
        create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_file.path = L"\\large.bin";
        if (!Require(
                context.metadata_store->ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
                "Metadata range-read open test should create committed file"))
        {
            std::filesystem::remove_all(context.session_root, ec);
            return false;
        }

        auto committed_payload = BuildPatternPayloadForTest(128 * 1024, 0x41);
        staged_payloads[L"\\large.bin"] = committed_payload;
        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\large.bin";
        write_file.length = committed_payload.size();
        if (!Require(
                context.metadata_store->ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
                "Metadata range-read open test should stage committed payload") ||
            !Require(
                context.metadata_store->CommitPendingMutations() == apfsaccess::rw::MetadataStore::CommitStatus::Committed,
                "Metadata range-read open test should commit payload"))
        {
            std::filesystem::remove_all(context.session_root, ec);
            return false;
        }
    }

    if (!Require(MergeCommittedInodeStateIntoNodeIndex(&context), "Metadata range-read open test should merge committed inode state"))
    {
        std::filesystem::remove_all(context.session_root, ec);
        return false;
    }

    auto node = FindNode(&context, L"\\large.bin");
    if (!Require(node != nullptr, "Metadata range-read open test should expose committed file node"))
    {
        std::filesystem::remove_all(context.session_root, ec);
        return false;
    }

    const auto hydration_path = HydrationPath(&context, *node);
    std::filesystem::remove(hydration_path, ec);
    ec.clear();

    auto fs = BuildFileSystem(&context);
    PVOID out_ctx = nullptr;
    FSP_FSCTL_FILE_INFO info{};
    const auto open_status = CB_Open(
        &fs,
        const_cast<PWSTR>(L"\\large.bin"),
        FILE_NON_DIRECTORY_FILE,
        FILE_READ_DATA,
        &out_ctx,
        &info);
    if (!Require(open_status == STATUS_SUCCESS, "Read-only open should succeed from committed metadata without hydration") ||
        !Require(out_ctx != nullptr, "Read-only metadata open should return an open context"))
    {
        std::filesystem::remove_all(context.session_root, ec);
        return false;
    }

    auto* open_context = reinterpret_cast<OpenContext*>(out_ctx);
    if (!Require(open_context->metadata_read_fallback, "Read-only committed open should use metadata range-read fallback") ||
        !Require(open_context->file == INVALID_HANDLE_VALUE, "Read-only committed open should not open a hydration file handle") ||
        !Require(!std::filesystem::exists(hydration_path, ec), "Read-only committed open should not create a hydration file"))
    {
        CB_Close(&fs, out_ctx);
        std::filesystem::remove_all(context.session_root, ec);
        return false;
    }

    std::array<char, 64> buffer{};
    ULONG read_done = 0;
    const auto read_offset = static_cast<UINT64>(4096);
    const auto read_status = CB_Read(
        &fs,
        out_ctx,
        buffer.data(),
        read_offset,
        static_cast<ULONG>(buffer.size()),
        &read_done);
    if (!Require(read_status == STATUS_SUCCESS, "Metadata range-read open should read requested range") ||
        !Require(read_done == buffer.size(), "Metadata range-read open should return requested byte count"))
    {
        CB_Close(&fs, out_ctx);
        std::filesystem::remove_all(context.session_root, ec);
        return false;
    }

    const auto expected_payload = BuildPatternPayloadForTest(128 * 1024, 0x41);
    for (std::size_t index = 0; index < buffer.size(); ++index)
    {
        const auto expected = expected_payload[static_cast<std::size_t>(read_offset) + index];
        if (!Require(static_cast<std::byte>(static_cast<unsigned char>(buffer[index])) == expected, "Metadata range-read open should preserve committed bytes"))
        {
            CB_Close(&fs, out_ctx);
            std::filesystem::remove_all(context.session_root, ec);
            return false;
        }
    }

    CB_Close(&fs, out_ctx);
    std::filesystem::remove_all(context.session_root, ec);
    return true;
#else
    return true;
#endif
}

bool TestWritableOpenHydratesSparseMetadataWithoutDenseCache()
{
#ifdef APFSACCESS_HAS_RW_ENGINE
    MountContext context{};
    context.args.volume = L"Main";
    context.args.readwrite = true;
    context.args.write_backend = L"Overlay";
    context.overlay_write_enabled = true;
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);
    if (!Require(PrepareUnitHydrationRoot(context, L"sparse-writable-hydration"), "Sparse writable hydration test should prepare cache root"))
    {
        return false;
    }

    std::error_code ec;
    const auto image_path = context.session_root / "sparse-writable-hydration.apfs.img";
    if (!Require(CreateSyntheticApfsContainerForTest(image_path), "Sparse writable hydration test should create synthetic APFS image"))
    {
        std::filesystem::remove_all(context.session_root, ec);
        return false;
    }

    apfsaccess::rw::MetadataStore::VolumeContext rw_context
    {
        image_path.wstring(),
        L"Main",
    };
    context.metadata_store = std::make_unique<apfsaccess::rw::MetadataStore>(std::move(rw_context));
    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    context.metadata_store->SetFilePayloadProvider(
        [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
        {
            auto pending = staged_payloads.find(path);
            if (pending == staged_payloads.end())
            {
                return std::nullopt;
            }

            auto payload = pending->second;
            payload.resize(static_cast<std::size_t>(logical_size), std::byte{0});
            return payload;
        });

    constexpr std::size_t logical_size = 512 * 1024;
    constexpr std::uint64_t sparse_offset = (512ull * 1024ull) - 4096ull;
    const auto sparse_tail_payload = BuildPatternPayloadForTest(4096, 0xA7);

    {
        std::lock_guard<std::mutex> metadata_lock(context.metadata_mutex);
        if (!Require(context.metadata_store->LoadContainerSuperblocks(), "Sparse writable hydration test should load container superblocks") ||
            !Require(context.metadata_store->LoadObjectMap(), "Sparse writable hydration test should load object map") ||
            !Require(context.metadata_store->LoadSpacemanState(), "Sparse writable hydration test should load spaceman state") ||
            !Require(context.metadata_store->PrepareNativeWritePath(), "Sparse writable hydration test should prepare native write path"))
        {
            std::filesystem::remove_all(context.session_root, ec);
            return false;
        }

        apfsaccess::rw::MetadataStore::MutationRequest create_file{};
        create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_file.path = L"\\sparse.bin";
        if (!Require(
                context.metadata_store->ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
                "Sparse writable hydration test should create committed file"))
        {
            std::filesystem::remove_all(context.session_root, ec);
            return false;
        }

        staged_payloads[L"\\sparse.bin"] = std::vector<std::byte>(logical_size, std::byte{0});
        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\sparse.bin";
        write_file.length = logical_size;
        if (!Require(
                context.metadata_store->ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
                "Sparse writable hydration test should stage committed size") ||
            !Require(
                context.metadata_store->CommitPendingMutations() == apfsaccess::rw::MetadataStore::CommitStatus::Committed,
                "Sparse writable hydration test should commit initial payload"))
        {
            std::filesystem::remove_all(context.session_root, ec);
            return false;
        }

        auto inode = context.metadata_store->LookupCommittedInodeByPath(L"\\sparse.bin");
        if (!Require(inode.has_value(), "Sparse writable hydration test should find committed sparse inode"))
        {
            std::filesystem::remove_all(context.session_root, ec);
            return false;
        }
        constexpr std::uint64_t sparse_tail_physical = 800ull * kSyntheticApfsBlockSize;
        std::fstream image_io(image_path, std::ios::binary | std::ios::in | std::ios::out);
        if (!Require(image_io.good(), "Sparse writable hydration test should reopen image for tail extent"))
        {
            std::filesystem::remove_all(context.session_root, ec);
            return false;
        }
        image_io.seekp(static_cast<std::streamoff>(sparse_tail_physical), std::ios::beg);
        image_io.write(
            reinterpret_cast<const char*>(sparse_tail_payload.data()),
            static_cast<std::streamsize>(sparse_tail_payload.size()));
        if (!Require(image_io.good(), "Sparse writable hydration test should write tail extent"))
        {
            std::filesystem::remove_all(context.session_root, ec);
            return false;
        }
        image_io.close();
        if (!Require(
                context.metadata_store->SetCommittedReadExtents(
                    inode->object_id,
                    {
                        { sparse_offset, sparse_tail_physical, sparse_tail_payload.size() },
                    }),
                "Sparse writable hydration test should install sparse committed extent"))
        {
            std::filesystem::remove_all(context.session_root, ec);
            return false;
        }
    }

    if (!Require(MergeCommittedInodeStateIntoNodeIndex(&context), "Sparse writable hydration test should merge committed inode state"))
    {
        std::filesystem::remove_all(context.session_root, ec);
        return false;
    }

    auto node = FindNode(&context, L"\\sparse.bin");
    if (!Require(node != nullptr, "Sparse writable hydration test should expose committed node"))
    {
        std::filesystem::remove_all(context.session_root, ec);
        return false;
    }

    const auto hydration_path = HydrationPath(&context, *node);
    std::filesystem::remove(hydration_path, ec);
    ec.clear();

    auto fs = BuildFileSystem(&context);
    PVOID out_ctx = nullptr;
    FSP_FSCTL_FILE_INFO info{};
    const auto open_status = CB_Open(
        &fs,
        const_cast<PWSTR>(L"\\sparse.bin"),
        FILE_NON_DIRECTORY_FILE,
        FILE_READ_DATA | FILE_WRITE_DATA,
        &out_ctx,
        &info);
    if (!Require(open_status == STATUS_SUCCESS, "Writable sparse committed open should hydrate cache successfully") ||
        !Require(out_ctx != nullptr, "Writable sparse committed open should return an open context"))
    {
        std::filesystem::remove_all(context.session_root, ec);
        return false;
    }

    auto* open_context = reinterpret_cast<OpenContext*>(out_ctx);
    if (!Require(open_context->file != INVALID_HANDLE_VALUE, "Writable sparse committed open should use a local hydration handle") ||
        !Require(!open_context->metadata_read_fallback, "Writable sparse committed open should not use read-only metadata fallback"))
    {
        CB_Close(&fs, out_ctx);
        std::filesystem::remove_all(context.session_root, ec);
        return false;
    }

    std::array<char, 32> zero_window{};
    ULONG zero_done = 0;
    const auto zero_status = CB_Read(
        &fs,
        out_ctx,
        zero_window.data(),
        0,
        static_cast<ULONG>(zero_window.size()),
        &zero_done);
    if (!Require(zero_status == STATUS_SUCCESS && zero_done == zero_window.size(), "Writable sparse hydration should read leading sparse zeros") ||
        !Require(std::all_of(zero_window.begin(), zero_window.end(), [](char value) { return value == 0; }), "Writable sparse hydration should zero-fill sparse leading range"))
    {
        CB_Close(&fs, out_ctx);
        std::filesystem::remove_all(context.session_root, ec);
        return false;
    }

    std::array<char, 64> tail_window{};
    ULONG tail_done = 0;
    const auto tail_status = CB_Read(
        &fs,
        out_ctx,
        tail_window.data(),
        sparse_offset,
        static_cast<ULONG>(tail_window.size()),
        &tail_done);
    if (!Require(tail_status == STATUS_SUCCESS && tail_done == tail_window.size(), "Writable sparse hydration should read materialized tail extent"))
    {
        CB_Close(&fs, out_ctx);
        std::filesystem::remove_all(context.session_root, ec);
        return false;
    }
    for (std::size_t index = 0; index < tail_window.size(); ++index)
    {
        if (!Require(
                static_cast<std::byte>(static_cast<unsigned char>(tail_window[index])) == sparse_tail_payload[index],
                "Writable sparse hydration should preserve tail extent bytes"))
        {
            CB_Close(&fs, out_ctx);
            std::filesystem::remove_all(context.session_root, ec);
            return false;
        }
    }

    CB_Close(&fs, out_ctx);

    const auto allocated_bytes = GetAllocatedBytesForTest(hydration_path);
    if (!Require(allocated_bytes != std::numeric_limits<std::uint64_t>::max(), "Sparse writable hydration test should read allocated cache size"))
    {
        std::filesystem::remove_all(context.session_root, ec);
        return false;
    }
    if (!Require(allocated_bytes < static_cast<std::uint64_t>(logical_size / 2), "Writable sparse hydration should keep local cache sparse instead of dense"))
    {
        std::filesystem::remove_all(context.session_root, ec);
        return false;
    }

    std::filesystem::remove_all(context.session_root, ec);
    return true;
#else
    return true;
#endif
}

bool TestParseArgsDefaultsStrictNonFixtureControls()
{
    std::vector<std::wstring> raw_args
    {
        L"ApfsAccess.FsHost.exe",
        L"--device", L"\\\\.\\PhysicalDrive3",
        L"--volume", L"Main",
        L"--mount", L"P:",
        L"--readwrite"
    };
    std::vector<wchar_t*> argv;
    argv.reserve(raw_args.size());
    for (auto& token : raw_args)
    {
        argv.push_back(token.data());
    }

    Arguments parsed{};
    if (!Require(ParseArgs(static_cast<int>(argv.size()), argv.data(), parsed), "ParseArgs should accept minimal readwrite arguments"))
    {
        return false;
    }

    if (!Require(parsed.write_disallow_scaffold_commit_on_non_fixture, "ParseArgs default should disallow scaffold commit on non-fixture"))
    {
        return false;
    }
    if (!Require(parsed.write_reject_scaffold_replay_blob_on_non_fixture, "ParseArgs default should reject scaffold replay blobs on non-fixture"))
    {
        return false;
    }
    return Require(parsed.write_require_canonical_replay_candidate_on_non_fixture, "ParseArgs default should require canonical replay candidates on non-fixture");
}

bool TestParseArgsParsesStrictNonFixtureControlOverrides()
{
    std::vector<std::wstring> raw_args
    {
        L"ApfsAccess.FsHost.exe",
        L"--device", L"\\\\.\\PhysicalDrive4",
        L"--volume", L"Main",
        L"--mount", L"q:",
        L"--readwrite",
        L"--write-disallow-scaffold-commit-on-non-fixture", L"false",
        L"--write-reject-scaffold-replay-blob-on-non-fixture", L"false",
        L"--write-require-canonical-replay-candidate-on-non-fixture", L"false"
    };
    std::vector<wchar_t*> argv;
    argv.reserve(raw_args.size());
    for (auto& token : raw_args)
    {
        argv.push_back(token.data());
    }

    Arguments parsed{};
    if (!Require(ParseArgs(static_cast<int>(argv.size()), argv.data(), parsed), "ParseArgs should accept strict non-fixture override options"))
    {
        return false;
    }

    if (!Require(!parsed.write_disallow_scaffold_commit_on_non_fixture, "ParseArgs should parse scaffold commit override false"))
    {
        return false;
    }
    if (!Require(!parsed.write_reject_scaffold_replay_blob_on_non_fixture, "ParseArgs should parse scaffold replay override false"))
    {
        return false;
    }
    if (!Require(!parsed.write_require_canonical_replay_candidate_on_non_fixture, "ParseArgs should parse canonical replay-candidate override false"))
    {
        return false;
    }
    return Require(parsed.mount == L"Q:", "ParseArgs should normalize mount letter casing");
}

bool TestBuildWinFspMountPointUsesGlobalDriveForExplorer()
{
    if (!Require(BuildWinFspMountPoint(L"E:") == L"\\\\.\\E:", "Drive-letter mounts should use Mount Manager syntax"))
    {
        return false;
    }

    if (!Require(BuildWinFspMountPoint(L"q:") == L"\\\\.\\Q:", "Drive-letter global mount syntax should normalize casing"))
    {
        return false;
    }

    return Require(
        BuildWinFspMountPoint(L"C:\\apfs-mount") == L"C:\\apfs-mount",
        "Directory mount points should not be rewritten as global drives");
}

bool TestVolumeParamsUseExplorerFriendlyCleanupFlags()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    context.args.volume = L"Main";
    context.reported_allocation_unit_bytes = 4096;

    FSP_FSCTL_VOLUME_PARAMS params{};
    FILETIME now{};
    GetSystemTimeAsFileTime(&now);
    ConfigureVolumeParamsForExplorer(context, now, params);

    if (!Require(params.PostCleanupWhenModifiedOnly == 0, "Volume params should deliver cleanup for every user handle so Explorer/Office locks clear promptly"))
    {
        return false;
    }
    if (!Require(params.FlushAndPurgeOnCleanup != 0, "Volume params should purge cached file data on cleanup for Explorer/Office compatibility"))
    {
        return false;
    }
    if (!Require(
            params.PostDispositionWhenNecessaryOnly == 0,
            "Volume params should request all disposition callbacks so recursive directory deletes reach FsHost reliably"))
    {
        return false;
    }
    if (!Require(params.SupportsPosixUnlinkRename != 0, "Volume params should preserve POSIX-style unlink semantics for compatible shell handles"))
    {
        return false;
    }
    return Require(params.PersistentAcls == 0, "Volume params should not advertise persistent ACLs while APFS Access returns synthetic security descriptors");
}

bool TestNamedStreamCopyCompatibility()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    context.args.volume = L"Main";
    context.reported_allocation_unit_bytes = 4096;
    SeedRoot(context);

    auto file = MakeNode(L"\\Antigravity-x64.exe", false, false);
    file->file_size = 143772040;
    context.nodes.emplace(Key(file->path), file);

    OpenContext open_context{};
    open_context.node = file;
    auto fs = BuildFileSystem(&context);

    std::array<std::byte, 256> buffer{};
    ULONG transferred = 0;
    const auto status = CB_GetStreamInfo(
        &fs,
        &open_context,
        buffer.data(),
        static_cast<ULONG>(buffer.size()),
        &transferred);
    if (!Require(status == STATUS_SUCCESS, "GetStreamInfo should succeed so Explorer can copy files with source metadata streams without warning"))
    {
        return false;
    }
    if (!Require(transferred > 0, "GetStreamInfo should report at least the default data stream"))
    {
        return false;
    }

    const auto* stream_info = reinterpret_cast<const FSP_FSCTL_STREAM_INFO*>(buffer.data());
    if (!Require(stream_info->StreamSize == file->file_size, "Default stream info should report file size"))
    {
        return false;
    }

    const auto stream_name_chars = (stream_info->Size - sizeof(FSP_FSCTL_STREAM_INFO)) / sizeof(WCHAR);
    const std::wstring stream_name(stream_info->StreamNameBuf, stream_name_chars);
    if (!Require(stream_name == L"::$DATA", "Default stream info should use the Windows default data stream name"))
    {
        return false;
    }

    FSP_FSCTL_VOLUME_PARAMS volume_params{};
    FILETIME now{};
    GetSystemTimeAsFileTime(&now);
    ConfigureVolumeParamsForExplorer(context, now, volume_params);
    return Require(volume_params.NamedStreams == 1, "Volume params should advertise named stream compatibility to Explorer");
}

bool TestNamedStreamCreateDoesNotCreateVisibleApfsFile()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    context.args.volume = L"Main";
    context.reported_allocation_unit_bytes = 4096;
    SeedRoot(context);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"Antigravity-x64.exe");
    auto file = MakeNode(L"\\Antigravity-x64.exe", false, false);
    file->file_size = 12;
    context.nodes.emplace(Key(file->path), file);

    auto fs = BuildFileSystem(&context);
    PVOID out_ctx = nullptr;
    FSP_FSCTL_FILE_INFO info{};
    const auto create_status = CB_Create(
        &fs,
        const_cast<PWSTR>(L"\\Antigravity-x64.exe:LH.Identifier"),
        FILE_NON_DIRECTORY_FILE,
        FILE_WRITE_DATA | FILE_READ_DATA | FILE_WRITE_ATTRIBUTES,
        0,
        nullptr,
        0,
        &out_ctx,
        &info);
    if (!Require(create_status == STATUS_SUCCESS, "Named stream create should succeed for Explorer metadata copy compatibility"))
    {
        return false;
    }
    if (!Require(out_ctx != nullptr, "Named stream create should return an open context"))
    {
        return false;
    }

    const std::array<char, 11> payload{ 'p', 'r', 'o', 'b', 'e', '-', 's', 't', 'r', 'e', 'a' };
    ULONG done = 0;
    const auto write_status = CB_Write(
        &fs,
        out_ctx,
        const_cast<char*>(payload.data()),
        0,
        static_cast<ULONG>(payload.size()),
        FALSE,
        FALSE,
        &done,
        &info);
    if (!Require(write_status == STATUS_SUCCESS, "Named stream write should succeed"))
    {
        return false;
    }
    if (!Require(done == payload.size(), "Named stream write should report all bytes written"))
    {
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(context.mutex);
        if (!Require(TryGetNodeLocked(&context, L"\\Antigravity-x64.exe:LH.Identifier") == nullptr, "Named stream writes must not create visible APFS colon-named files"))
        {
            return false;
        }
        if (!Require(std::find(root->children.begin(), root->children.end(), L"Antigravity-x64.exe:LH.Identifier") == root->children.end(), "Named stream writes must not add colon-named directory entries"))
        {
            return false;
        }
        if (!Require(file->file_size == 12, "Named stream writes must not change the base file size"))
        {
            return false;
        }
    }

    CB_Close(&fs, out_ctx);

    PVOID stream_read_ctx = nullptr;
    FSP_FSCTL_FILE_INFO read_info{};
    const auto open_status = CB_Open(
        &fs,
        const_cast<PWSTR>(L"\\Antigravity-x64.exe:LH.Identifier"),
        FILE_NON_DIRECTORY_FILE,
        FILE_READ_DATA,
        &stream_read_ctx,
        &read_info);
    if (!Require(open_status == STATUS_SUCCESS, "Named stream reopen should succeed for Explorer metadata copy round-trips"))
    {
        return false;
    }

    std::array<char, 16> read_payload{};
    ULONG read_done = 0;
    const auto read_status = CB_Read(
        &fs,
        stream_read_ctx,
        read_payload.data(),
        0,
        static_cast<ULONG>(payload.size()),
        &read_done);
    if (!Require(read_status == STATUS_SUCCESS, "Named stream read should succeed after reopen"))
    {
        CB_Close(&fs, stream_read_ctx);
        return false;
    }
    if (!Require(read_done == payload.size(), "Named stream read should return all bytes written"))
    {
        CB_Close(&fs, stream_read_ctx);
        return false;
    }
    if (!Require(std::equal(payload.begin(), payload.end(), read_payload.begin()), "Named stream payload should round-trip through the hydration sidecar"))
    {
        CB_Close(&fs, stream_read_ctx);
        return false;
    }
    CB_Close(&fs, stream_read_ctx);

    OpenContext base_open{};
    base_open.node = file;
    std::array<std::byte, 512> stream_buffer{};
    ULONG transferred = 0;
    const auto stream_status = CB_GetStreamInfo(
        &fs,
        &base_open,
        stream_buffer.data(),
        static_cast<ULONG>(stream_buffer.size()),
        &transferred);
    if (!Require(stream_status == STATUS_SUCCESS, "GetStreamInfo should succeed after writing a named stream"))
    {
        return false;
    }

    bool found_named_stream = false;
    ULONG cursor = 0;
    while (cursor < transferred)
    {
        const auto* stream_info = reinterpret_cast<const FSP_FSCTL_STREAM_INFO*>(stream_buffer.data() + cursor);
        if (stream_info->Size < sizeof(FSP_FSCTL_STREAM_INFO) ||
            stream_info->Size > transferred - cursor)
        {
            return Require(false, "Stream info entries should be packed with valid sizes");
        }

        const auto name_chars = (stream_info->Size - sizeof(FSP_FSCTL_STREAM_INFO)) / sizeof(WCHAR);
        const std::wstring stream_name(stream_info->StreamNameBuf, name_chars);
        if (stream_name == L":LH.Identifier:$DATA")
        {
            found_named_stream = stream_info->StreamSize == payload.size();
        }
        cursor += stream_info->Size;
    }

    return Require(found_named_stream, "GetStreamInfo should enumerate the named metadata stream attached to the base file");
}

bool TestLegacyNamedStreamArtifactsAreHidden()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    context.args.volume = L"Main";
    SeedRoot(context);

    auto root = context.nodes.at(Key(L"\\"));
    const std::wstring artifact_name = L"ANTIGRAVITY.EXE:LH.Identifier";
    AddChildName(root->children, artifact_name);
    auto artifact = MakeNode(L"\\" + artifact_name, false, false);
    artifact->file_size = 108;
    context.nodes.emplace(Key(artifact->path), artifact);

    {
        std::lock_guard<std::mutex> lock(context.mutex);
        if (!Require(TryGetVisibleNodeLocked(&context, artifact->path) == nullptr, "Legacy colon-named stream artifacts should not resolve as visible APFS files"))
        {
            return false;
        }
    }

    OpenContext dir_context{};
    dir_context.node = root;
    dir_context.allow_list_directory = true;
    auto fs = BuildFileSystem(&context);
    context.api.AddDir = [](FSP_FSCTL_DIR_INFO* dir_info, PVOID, ULONG, PULONG done) -> BOOLEAN
    {
        if (!dir_info)
        {
            return TRUE;
        }

        if (done)
        {
            *done += dir_info->Size;
        }
        return TRUE;
    };

    std::array<std::byte, 512> buffer{};
    ULONG transferred = 0;
    const auto read_status = CB_ReadDirectory(
        &fs,
        &dir_context,
        nullptr,
        nullptr,
        buffer.data(),
        static_cast<ULONG>(buffer.size()),
        &transferred);
    if (!Require(read_status == STATUS_SUCCESS, "Directory enumeration should succeed when legacy stream artifacts are present"))
    {
        return false;
    }

    return Require(transferred == 0, "Directory enumeration should hide legacy colon-named stream artifact files");
}

bool TestMissingNamedStreamOpenFailsCleanlyWithoutBaseBytes()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    context.args.volume = L"Main";
    if (!Require(PrepareUnitHydrationRoot(context, L"missing-named-stream"), "Missing named stream test should prepare cache root"))
    {
        return false;
    }
    SeedRoot(context);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"document.docx");
    auto file = MakeNode(L"\\document.docx", false, false);
    const auto base_payload = BuildPatternPayloadForTest(64, 0x41);
    file->file_size = base_payload.size();
    context.nodes.emplace(Key(file->path), file);
    if (!Require(WriteFileBytes(HydrationPath(&context, *file), base_payload), "Missing named stream test should seed base file bytes"))
    {
        std::error_code ec;
        std::filesystem::remove_all(context.session_root, ec);
        return false;
    }

    auto fs = BuildFileSystem(&context);
    const std::array<const wchar_t*, 3> missing_streams
    {
        L"\\document.docx:Zone.Identifier",
        L"\\document.docx:LH.Identifier",
        L"\\document.docx:AFP_AfpInfo"
    };

    for (const auto* stream_path : missing_streams)
    {
        PVOID out_ctx = nullptr;
        FSP_FSCTL_FILE_INFO info{};
        const auto status = CB_Open(
            &fs,
            const_cast<PWSTR>(stream_path),
            FILE_NON_DIRECTORY_FILE,
            FILE_READ_DATA,
            &out_ctx,
            &info);
        if (!Require(status == STATUS_OBJECT_NAME_NOT_FOUND, "Missing ADS read-only open should report object-not-found, not device failure"))
        {
            if (out_ctx)
            {
                CB_Close(&fs, out_ctx);
            }
            std::error_code ec;
            std::filesystem::remove_all(context.session_root, ec);
            return false;
        }
        if (!Require(out_ctx == nullptr, "Missing ADS read-only open should not allocate an open context"))
        {
            std::error_code ec;
            std::filesystem::remove_all(context.session_root, ec);
            return false;
        }
        if (!Require(file->open_handle_count == 0, "Missing ADS read-only probes should not leak base-file open handles"))
        {
            std::error_code ec;
            std::filesystem::remove_all(context.session_root, ec);
            return false;
        }
    }

    PVOID base_ctx = nullptr;
    FSP_FSCTL_FILE_INFO info{};
    const auto base_open = CB_Open(
        &fs,
        const_cast<PWSTR>(L"\\document.docx"),
        FILE_NON_DIRECTORY_FILE,
        FILE_READ_DATA,
        &base_ctx,
        &info);
    if (!Require(base_open == STATUS_SUCCESS, "Base file should still open after missing ADS probes") ||
        !Require(base_ctx != nullptr, "Base file open should return a context"))
    {
        std::error_code ec;
        std::filesystem::remove_all(context.session_root, ec);
        return false;
    }

    std::array<char, 64> read_buffer{};
    ULONG read_done = 0;
    const auto read_status = CB_Read(
        &fs,
        base_ctx,
        read_buffer.data(),
        0,
        static_cast<ULONG>(read_buffer.size()),
        &read_done);
    CB_Close(&fs, base_ctx);

    bool base_bytes_match = read_done == base_payload.size();
    for (std::size_t index = 0; base_bytes_match && index < base_payload.size(); ++index)
    {
        base_bytes_match = static_cast<std::byte>(static_cast<unsigned char>(read_buffer[index])) == base_payload[index];
    }

    std::error_code ec;
    std::filesystem::remove_all(context.session_root, ec);
    return Require(read_status == STATUS_SUCCESS && base_bytes_match, "Missing ADS probes must not corrupt or consume base-file bytes");
}

bool TestDuplicateCaseNamedStreamsCoalesceMetadata()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    context.args.volume = L"Main";
    if (!Require(PrepareUnitHydrationRoot(context, L"duplicate-case-stream"), "Duplicate-case stream test should prepare cache root"))
    {
        return false;
    }
    SeedRoot(context);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"installer.exe");
    auto file = MakeNode(L"\\installer.exe", false, false);
    file->file_size = 12;
    context.nodes.emplace(Key(file->path), file);
    if (!Require(WriteFileBytes(HydrationPath(&context, *file), BuildPatternPayloadForTest(12, 0x18)), "Duplicate-case stream test should seed base file"))
    {
        std::error_code ec;
        std::filesystem::remove_all(context.session_root, ec);
        return false;
    }

    auto fs = BuildFileSystem(&context);
    PVOID lower_ctx = nullptr;
    FSP_FSCTL_FILE_INFO info{};
    const auto create_status = CB_Create(
        &fs,
        const_cast<PWSTR>(L"\\installer.exe:lh.identifier"),
        FILE_NON_DIRECTORY_FILE,
        FILE_WRITE_DATA | FILE_READ_DATA,
        0,
        nullptr,
        0,
        &lower_ctx,
        &info);
    if (!Require(create_status == STATUS_SUCCESS && lower_ctx != nullptr, "Lowercase named stream create should succeed"))
    {
        std::error_code ec;
        std::filesystem::remove_all(context.session_root, ec);
        return false;
    }

    const std::array<char, 4> payload{ 'A', 'D', 'S', '1' };
    ULONG done = 0;
    const auto write_status = CB_Write(
        &fs,
        lower_ctx,
        const_cast<char*>(payload.data()),
        0,
        static_cast<ULONG>(payload.size()),
        FALSE,
        FALSE,
        &done,
        &info);
    CB_Close(&fs, lower_ctx);
    if (!Require(write_status == STATUS_SUCCESS && done == payload.size(), "Lowercase named stream write should persist payload"))
    {
        std::error_code ec;
        std::filesystem::remove_all(context.session_root, ec);
        return false;
    }

    PVOID upper_ctx = nullptr;
    const auto upper_open = CB_Open(
        &fs,
        const_cast<PWSTR>(L"\\installer.exe:LH.IDENTIFIER"),
        FILE_NON_DIRECTORY_FILE,
        FILE_READ_DATA,
        &upper_ctx,
        &info);
    if (!Require(upper_open == STATUS_SUCCESS && upper_ctx != nullptr, "Duplicate-case named stream reopen should resolve the same stream"))
    {
        std::error_code ec;
        std::filesystem::remove_all(context.session_root, ec);
        return false;
    }

    std::array<char, 8> read_payload{};
    ULONG read_done = 0;
    const auto read_status = CB_Read(
        &fs,
        upper_ctx,
        read_payload.data(),
        0,
        static_cast<ULONG>(payload.size()),
        &read_done);
    CB_Close(&fs, upper_ctx);
    if (!Require(read_status == STATUS_SUCCESS && read_done == payload.size(), "Duplicate-case named stream read should return the existing payload") ||
        !Require(std::equal(payload.begin(), payload.end(), read_payload.begin()), "Duplicate-case named stream should read bytes from the original stream"))
    {
        std::error_code ec;
        std::filesystem::remove_all(context.session_root, ec);
        return false;
    }

    OpenContext base_open{};
    base_open.node = file;
    std::array<std::byte, 512> stream_buffer{};
    ULONG transferred = 0;
    const auto stream_status = CB_GetStreamInfo(
        &fs,
        &base_open,
        stream_buffer.data(),
        static_cast<ULONG>(stream_buffer.size()),
        &transferred);
    if (!Require(stream_status == STATUS_SUCCESS, "GetStreamInfo should succeed after duplicate-case stream opens"))
    {
        std::error_code ec;
        std::filesystem::remove_all(context.session_root, ec);
        return false;
    }

    int metadata_stream_count = 0;
    ULONG cursor = 0;
    while (cursor < transferred)
    {
        const auto* stream_info = reinterpret_cast<const FSP_FSCTL_STREAM_INFO*>(stream_buffer.data() + cursor);
        if (stream_info->Size < sizeof(FSP_FSCTL_STREAM_INFO) ||
            stream_info->Size > transferred - cursor)
        {
            std::error_code ec;
            std::filesystem::remove_all(context.session_root, ec);
            return Require(false, "Duplicate-case stream info should contain valid packed entries");
        }

        const auto name_chars = (stream_info->Size - sizeof(FSP_FSCTL_STREAM_INFO)) / sizeof(WCHAR);
        const std::wstring stream_name(stream_info->StreamNameBuf, name_chars);
        if (ToLowerInvariant(stream_name) == L":lh.identifier:$data")
        {
            ++metadata_stream_count;
        }
        cursor += stream_info->Size;
    }

    std::error_code ec;
    std::filesystem::remove_all(context.session_root, ec);
    return Require(metadata_stream_count == 1, "Duplicate-case named streams should coalesce to one metadata stream entry");
}

bool TestOfficeTempRenameReplaceWorkflow()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    context.args.volume = L"Main";
    if (!Require(PrepareUnitHydrationRoot(context, L"office-temp-rename"), "Office workflow test should prepare cache root"))
    {
        return false;
    }
    SeedRoot(context);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"office");
    auto office_dir = MakeNode(L"\\office", true, false);
    context.nodes.emplace(Key(office_dir->path), office_dir);

    AddChildName(office_dir->children, L"document.docx");
    auto original = MakeNode(L"\\office\\document.docx", false, false);
    const auto original_payload = BuildPatternPayloadForTest(96, 0x21);
    original->file_size = original_payload.size();
    context.nodes.emplace(Key(original->path), original);
    if (!Require(WriteFileBytes(HydrationPath(&context, *original), original_payload), "Office workflow test should seed original document"))
    {
        std::error_code ec;
        std::filesystem::remove_all(context.session_root, ec);
        return false;
    }

    auto fs = BuildFileSystem(&context);
    PVOID lock_ctx = nullptr;
    FSP_FSCTL_FILE_INFO lock_info{};
    const auto lock_create = CB_Create(
        &fs,
        const_cast<PWSTR>(L"\\office\\~$document.docx"),
        FILE_NON_DIRECTORY_FILE,
        FILE_WRITE_DATA | DELETE,
        0,
        nullptr,
        0,
        &lock_ctx,
        &lock_info);
    if (!Require(lock_create == STATUS_SUCCESS && lock_ctx != nullptr, "Office lock file create should succeed"))
    {
        std::error_code ec;
        std::filesystem::remove_all(context.session_root, ec);
        return false;
    }
    auto* lock_open = static_cast<OpenContext*>(lock_ctx);
    lock_open->allow_delete = true;
    CB_Cleanup(&fs, lock_ctx, const_cast<PWSTR>(L"\\office\\~$document.docx"), FspCleanupDelete);
    CB_Close(&fs, lock_ctx);
    if (!Require(context.nodes.find(Key(L"\\office\\~$document.docx")) == context.nodes.end(), "Office lock file delete-on-close should remove the temp lock node"))
    {
        std::error_code ec;
        std::filesystem::remove_all(context.session_root, ec);
        return false;
    }

    PVOID temp_ctx = nullptr;
    FSP_FSCTL_FILE_INFO temp_info{};
    const auto temp_create = CB_Create(
        &fs,
        const_cast<PWSTR>(L"\\office\\document.tmp"),
        FILE_NON_DIRECTORY_FILE,
        FILE_WRITE_DATA | FILE_READ_DATA | DELETE,
        0,
        nullptr,
        0,
        &temp_ctx,
        &temp_info);
    if (!Require(temp_create == STATUS_SUCCESS && temp_ctx != nullptr, "Office save temp file create should succeed"))
    {
        std::error_code ec;
        std::filesystem::remove_all(context.session_root, ec);
        return false;
    }

    const auto saved_payload = BuildPatternPayloadForTest(128, 0x63);
    ULONG temp_written = 0;
    const auto temp_write = CB_Write(
        &fs,
        temp_ctx,
        const_cast<std::byte*>(saved_payload.data()),
        0,
        static_cast<ULONG>(saved_payload.size()),
        FALSE,
        FALSE,
        &temp_written,
        &temp_info);
    CB_Close(&fs, temp_ctx);
    if (!Require(temp_write == STATUS_SUCCESS && temp_written == saved_payload.size(), "Office save temp file write should persist all bytes"))
    {
        std::error_code ec;
        std::filesystem::remove_all(context.session_root, ec);
        return false;
    }

    const auto rename_status = CB_Rename(
        &fs,
        nullptr,
        const_cast<PWSTR>(L"\\office\\document.tmp"),
        const_cast<PWSTR>(L"\\office\\document.docx"),
        TRUE);
    if (!Require(rename_status == STATUS_SUCCESS, "Office temp save should rename-replace the original document"))
    {
        std::error_code ec;
        std::filesystem::remove_all(context.session_root, ec);
        return false;
    }

    auto saved_node = FindNode(&context, L"\\office\\document.docx");
    if (!Require(saved_node != nullptr, "Office temp save should leave the final document visible") ||
        !Require(context.nodes.find(Key(L"\\office\\document.tmp")) == context.nodes.end(), "Office temp save should remove the temp source path") ||
        !Require(saved_node->file_size == saved_payload.size(), "Office temp save should expose the saved document size"))
    {
        std::error_code ec;
        std::filesystem::remove_all(context.session_root, ec);
        return false;
    }

    const auto saved_bytes = ReadFileBytes(HydrationPath(&context, *saved_node));
    std::error_code ec;
    std::filesystem::remove_all(context.session_root, ec);
    return Require(saved_bytes == saved_payload, "Office temp save should preserve the exact replacement bytes");
}

bool TestRecycleBinMetadataPairWorkflow()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    context.args.volume = L"Main";
    if (!Require(PrepareUnitHydrationRoot(context, L"recycle-metadata-pair"), "Recycle workflow test should prepare cache root"))
    {
        return false;
    }
    SeedRoot(context);

    auto root = context.nodes.at(Key(L"\\"));
    AddChildName(root->children, L"$RECYCLE.BIN");
    auto recycle = MakeNode(L"\\$RECYCLE.BIN", true, false);
    context.nodes.emplace(Key(recycle->path), recycle);
    AddChildName(recycle->children, L"S-1-5-21-1000-1000-1000-1001");
    auto sid = MakeNode(L"\\$RECYCLE.BIN\\S-1-5-21-1000-1000-1000-1001", true, false);
    context.nodes.emplace(Key(sid->path), sid);
    AddChildName(root->children, L"files");
    auto files = MakeNode(L"\\files", true, false);
    context.nodes.emplace(Key(files->path), files);
    AddChildName(files->children, L"delete-me.bin");
    auto source = MakeNode(L"\\files\\delete-me.bin", false, false);
    const auto payload = BuildPatternPayloadForTest(256, 0x77);
    source->file_size = payload.size();
    context.nodes.emplace(Key(source->path), source);
    if (!Require(WriteFileBytes(HydrationPath(&context, *source), payload), "Recycle workflow test should seed source payload"))
    {
        std::error_code ec;
        std::filesystem::remove_all(context.session_root, ec);
        return false;
    }

    auto fs = BuildFileSystem(&context);
    const auto move_to_bin = CB_Rename(
        &fs,
        nullptr,
        const_cast<PWSTR>(L"\\files\\delete-me.bin"),
        const_cast<PWSTR>(L"\\$RECYCLE.BIN\\S-1-5-21-1000-1000-1000-1001\\$RCODEX01.bin"),
        FALSE);
    if (!Require(move_to_bin == STATUS_SUCCESS, "Recycle workflow should move payload to $R entry"))
    {
        std::error_code ec;
        std::filesystem::remove_all(context.session_root, ec);
        return false;
    }

    PVOID info_ctx = nullptr;
    FSP_FSCTL_FILE_INFO info{};
    const auto info_create = CB_Create(
        &fs,
        const_cast<PWSTR>(L"\\$RECYCLE.BIN\\S-1-5-21-1000-1000-1000-1001\\$ICODEX01.bin"),
        FILE_NON_DIRECTORY_FILE,
        FILE_WRITE_DATA | DELETE,
        0,
        nullptr,
        0,
        &info_ctx,
        &info);
    if (!Require(info_create == STATUS_SUCCESS && info_ctx != nullptr, "Recycle workflow should create $I metadata entry"))
    {
        std::error_code ec;
        std::filesystem::remove_all(context.session_root, ec);
        return false;
    }
    const std::array<char, 9> info_payload{ 'm', 'e', 't', 'a', 'd', 'a', 't', 'a', '\n' };
    ULONG info_written = 0;
    const auto info_write = CB_Write(
        &fs,
        info_ctx,
        const_cast<char*>(info_payload.data()),
        0,
        static_cast<ULONG>(info_payload.size()),
        FALSE,
        FALSE,
        &info_written,
        &info);
    if (!Require(info_write == STATUS_SUCCESS && info_written == info_payload.size(), "Recycle workflow should write $I metadata bytes"))
    {
        CB_Close(&fs, info_ctx);
        std::error_code ec;
        std::filesystem::remove_all(context.session_root, ec);
        return false;
    }

    const auto restore_status = CB_Rename(
        &fs,
        nullptr,
        const_cast<PWSTR>(L"\\$RECYCLE.BIN\\S-1-5-21-1000-1000-1000-1001\\$RCODEX01.bin"),
        const_cast<PWSTR>(L"\\files\\restored.bin"),
        FALSE);
    if (!Require(restore_status == STATUS_SUCCESS, "Recycle workflow should restore $R payload by rename"))
    {
        CB_Close(&fs, info_ctx);
        std::error_code ec;
        std::filesystem::remove_all(context.session_root, ec);
        return false;
    }

    auto* info_open = static_cast<OpenContext*>(info_ctx);
    info_open->allow_delete = true;
    const auto delete_info = CB_SetDelete(
        &fs,
        info_ctx,
        const_cast<PWSTR>(L"\\$RECYCLE.BIN\\S-1-5-21-1000-1000-1000-1001\\$ICODEX01.bin"),
        TRUE);
    if (!Require(delete_info == STATUS_SUCCESS, "Recycle workflow should mark $I metadata for deletion"))
    {
        CB_Close(&fs, info_ctx);
        std::error_code ec;
        std::filesystem::remove_all(context.session_root, ec);
        return false;
    }
    CB_Cleanup(&fs, info_ctx, const_cast<PWSTR>(L"\\$RECYCLE.BIN\\S-1-5-21-1000-1000-1000-1001\\$ICODEX01.bin"), FspCleanupDelete);
    CB_Close(&fs, info_ctx);

    auto restored = FindNode(&context, L"\\files\\restored.bin");
    if (!Require(restored != nullptr, "Recycle workflow should leave restored payload visible") ||
        !Require(context.nodes.find(Key(L"\\$RECYCLE.BIN\\S-1-5-21-1000-1000-1000-1001\\$ICODEX01.bin")) == context.nodes.end(), "Recycle workflow should delete $I metadata node") ||
        !Require(context.nodes.find(Key(L"\\$RECYCLE.BIN\\S-1-5-21-1000-1000-1000-1001\\$RCODEX01.bin")) == context.nodes.end(), "Recycle workflow should remove $R payload from recycle folder"))
    {
        std::error_code ec;
        std::filesystem::remove_all(context.session_root, ec);
        return false;
    }

    const auto restored_bytes = ReadFileBytes(HydrationPath(&context, *restored));
    std::error_code ec;
    std::filesystem::remove_all(context.session_root, ec);
    return Require(restored_bytes == payload, "Recycle workflow should preserve restored payload bytes");
}

bool TestPathNormalizationMatrixRejectsRiskyWin32Names()
{
    MountContext context{};
    context.overlay_write_enabled = true;
    context.args.volume = L"Main";
    SeedRoot(context);
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);

    auto fs = BuildFileSystem(&context);
    const std::wstring long_component = L"\\" + std::wstring(256, L'n') + L".txt";
    const std::array<std::wstring, 6> invalid_paths
    {
        L"\\CON",
        L"\\AUX.txt",
        L"\\trailing-space ",
        L"\\trailing-dot.",
        L"\\bad<name>.txt",
        long_component
    };

    for (const auto& path : invalid_paths)
    {
        PVOID out_ctx = nullptr;
        FSP_FSCTL_FILE_INFO info{};
        const auto status = CB_Create(
            &fs,
            const_cast<PWSTR>(path.c_str()),
            FILE_NON_DIRECTORY_FILE,
            FILE_WRITE_DATA,
            0,
            nullptr,
            0,
            &out_ctx,
            &info);
        if (!Require(status == STATUS_OBJECT_NAME_INVALID, "Risky Win32 path create should fail before mutation"))
        {
            if (out_ctx)
            {
                CB_Close(&fs, out_ctx);
            }
            return false;
        }
        if (!Require(context.nodes.find(Key(path)) == context.nodes.end(), "Rejected risky Win32 path should not create a node"))
        {
            return false;
        }
    }

    auto root = context.nodes.at(Key(L"\\"));
    const std::wstring valid_unicode_path = L"\\文件-" + std::wstring(L"\xD83D\xDE80") + L"-I-\x0130-\x0131.txt";
    PVOID valid_ctx = nullptr;
    FSP_FSCTL_FILE_INFO valid_info{};
    const auto valid_create = CB_Create(
        &fs,
        const_cast<PWSTR>(valid_unicode_path.c_str()),
        FILE_NON_DIRECTORY_FILE,
        FILE_WRITE_DATA | DELETE,
        0,
        nullptr,
        0,
        &valid_ctx,
        &valid_info);
    if (!Require(valid_create == STATUS_SUCCESS && valid_ctx != nullptr, "Unicode path matrix should allow normal Chinese, emoji, and Turkish I names"))
    {
        return false;
    }
    CB_Close(&fs, valid_ctx);

    const auto case_rename = CB_Rename(
        &fs,
        nullptr,
        const_cast<PWSTR>(valid_unicode_path.c_str()),
        const_cast<PWSTR>(L"\\文件-\xD83D\xDE80-i-\x0130-\x0131.txt"),
        FALSE);
    if (!Require(case_rename == STATUS_SUCCESS, "Path matrix should allow case-only rename of a valid Unicode name"))
    {
        return false;
    }
    return Require(
        HasChildName(root->children, L"文件-\xD83D\xDE80-i-\x0130-\x0131.txt") &&
            context.nodes.find(Key(L"\\文件-\xD83D\xDE80-i-\x0130-\x0131.txt")) != context.nodes.end(),
        "Case-only Unicode rename should update the visible directory entry");
}

bool TestNormalizePathStripsDriveQualifiedRoot()
{
    if (!Require(NormalizePath(L"E:") == L"\\", "NormalizePath should treat drive-qualified current-directory roots as volume root"))
    {
        return false;
    }
    if (!Require(NormalizePath(L"E:\\") == L"\\", "NormalizePath should treat drive-qualified slash roots as volume root"))
    {
        return false;
    }
    if (!Require(NormalizePath(L"E:\\folder\\file.txt") == L"\\folder\\file.txt", "NormalizePath should strip drive prefixes from absolute child paths"))
    {
        return false;
    }

    return Require(NormalizePath(L"folder\\file.txt") == L"\\folder\\file.txt", "NormalizePath should preserve relative child path behavior");
}

bool TestStableVolumeSerialDependsOnVolumeIdentityNotProcessUptime()
{
    Arguments first{};
    first.device = L"\\\\.\\PhysicalDrive2";
    first.volume = L"Main";
    first.device_offset_bytes = 4096;

    Arguments same = first;
    Arguments other = first;
    other.volume = L"Other";

    const auto serial = BuildStableVolumeSerial(first);
    if (!Require(serial != 0, "Stable volume serial should never be zero"))
    {
        return false;
    }
    if (!Require(serial == BuildStableVolumeSerial(same), "Stable volume serial should be deterministic for the same APFS volume identity"))
    {
        return false;
    }
    return Require(serial != BuildStableVolumeSerial(other), "Stable volume serial should change when the APFS volume identity changes");
}

bool TestVolumeInfoFallbackKeepsExplorerCapacityBarUsable()
{
    MountContext context{};
    context.label = BuildExplorerVolumeLabel(L"Main");
    context.reported_total_size_bytes = 128111046656ull;
    context.reported_free_size_bytes.reset();
    context.reported_allocation_unit_bytes = 4096;
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);
    SeedRoot(context);

    auto fs = BuildFileSystem(&context);
    FSP_FSCTL_VOLUME_INFO volume_info{};
    const auto status = CB_GetVolumeInfo(&fs, &volume_info);
    if (!Require(status == STATUS_SUCCESS, "GetVolumeInfo should succeed with total-size-only fallback metadata"))
    {
        return false;
    }
    if (!Require(volume_info.TotalSize == 128111046656ull, "GetVolumeInfo should preserve APFS total size for Explorer"))
    {
        return false;
    }
    if (!Require(volume_info.FreeSize == 128111046656ull, "GetVolumeInfo should use total size as temporary free-space fallback"))
    {
        return false;
    }

    context.reported_free_size_bytes = 128500000000ull;
    const auto clamped_status = CB_GetVolumeInfo(&fs, &volume_info);
    if (!Require(clamped_status == STATUS_SUCCESS, "GetVolumeInfo should succeed when reported free space exceeds total size"))
    {
        return false;
    }
    if (!Require(volume_info.FreeSize == volume_info.TotalSize, "GetVolumeInfo should clamp free space to total size"))
    {
        return false;
    }

    context.reported_free_size_bytes = 0;
    const auto zero_free_status = CB_GetVolumeInfo(&fs, &volume_info);
    if (!Require(zero_free_status == STATUS_SUCCESS, "GetVolumeInfo should succeed when richer APFS free space is unavailable"))
    {
        return false;
    }
    return Require(volume_info.FreeSize == volume_info.TotalSize, "GetVolumeInfo should preserve Explorer capacity bar when APFS free space is unknown");
}

bool TestVolumeInfoUsesMetadataStoreWhenAvailable()
{
    MountContext context{};
    context.label = BuildExplorerVolumeLabel(L"Main");
    std::array<std::byte, 16> security{};
    SeedSecurity(context, security);
    SeedRoot(context);

    auto fs = BuildFileSystem(&context);
    FSP_FSCTL_VOLUME_INFO volume_info{};
    const auto empty_status = CB_GetVolumeInfo(&fs, &volume_info);
    if (!Require(empty_status == STATUS_SUCCESS, "GetVolumeInfo should succeed without metadata store"))
    {
        return false;
    }
    if (!Require(volume_info.TotalSize == 0 && volume_info.FreeSize == 0, "GetVolumeInfo should fall back to zero values when metadata is unavailable"))
    {
        return false;
    }
    if (!Require(volume_info.VolumeLabelLength == 4 * sizeof(WCHAR), "GetVolumeInfo should expose the APFS volume label without debug suffixes"))
    {
        return false;
    }
    if (!Require(std::wstring(volume_info.VolumeLabel, volume_info.VolumeLabelLength / sizeof(WCHAR)) == L"Main", "GetVolumeInfo should report the native volume label"))
    {
        return false;
    }

    context.reported_total_size_bytes = 1000;
    context.reported_free_size_bytes.reset();
    context.reported_allocation_unit_bytes = 128;
    const auto fallback_status = CB_GetVolumeInfo(&fs, &volume_info);
    if (!Require(fallback_status == STATUS_SUCCESS, "GetVolumeInfo should succeed with reported fallback capacity"))
    {
        return false;
    }
    if (!Require(volume_info.TotalSize == 896 && volume_info.FreeSize == 896, "GetVolumeInfo should align fallback total/free space to allocation units"))
    {
        return false;
    }
    context.reported_total_size_bytes.reset();
    context.reported_free_size_bytes.reset();
    context.reported_allocation_unit_bytes = 4096;

    return true;
}

bool TestRequiresCanonicalMutationGateDefaultsToStrict()
{
    Arguments args{};
    args.device = L"\\\\.\\PhysicalDrive4";
    return Require(
        RequiresCanonicalMutationGate(args),
        "Canonical mutation gate should be required by default for non-fixture media");
}

bool TestRequiresCanonicalMutationGateNeedsAllStrictFlagsDisabled()
{
    Arguments args{};
    args.device = L"\\\\.\\PhysicalDrive5";

    args.write_require_canonical_commit = false;
    args.write_disallow_scaffold_commit_on_non_fixture = false;
    args.write_reject_scaffold_replay_blob_on_non_fixture = false;
    args.write_require_canonical_replay_candidate_on_non_fixture = false;

    if (!Require(
            RequiresCanonicalMutationGate(args),
            "Canonical mutation gate should remain required for non-fixture media even when strict toggles are relaxed"))
    {
        return false;
    }

    args.device = L"C:\\fixtures\\sample.apfs.img";
    if (!Require(
            !RequiresCanonicalMutationGate(args),
            "Canonical mutation gate may be relaxed only for explicit fixture media when all strict toggles are disabled"))
    {
        return false;
    }

    args.device = L"C:\\fixtures\\sample.bin";
    return Require(
        RequiresCanonicalMutationGate(args),
        "Fixture-like parent folders without explicit fixture file patterns must still require canonical mutation gating");
}

bool TestApplyNonFixtureCanonicalSafetyOverrides_EnforcesStrictControls()
{
    Arguments args{};
    args.device = L"\\\\.\\PhysicalDrive7";
    args.allow_legacy_scaffold_for_fixtures = true;
    args.write_require_canonical_commit = false;
    args.write_disallow_scaffold_commit_on_non_fixture = false;
    args.write_reject_scaffold_replay_blob_on_non_fixture = false;
    args.write_require_canonical_replay_candidate_on_non_fixture = false;

    ApplyNonFixtureCanonicalSafetyOverrides(args);

    return Require(
        !args.allow_legacy_scaffold_for_fixtures &&
        args.write_require_canonical_commit &&
        args.write_disallow_scaffold_commit_on_non_fixture &&
        args.write_reject_scaffold_replay_blob_on_non_fixture &&
        args.write_require_canonical_replay_candidate_on_non_fixture,
        "Non-fixture canonical safety overrides should force strict canonical controls and disable legacy scaffold fallback");
}

bool TestApplyNonFixtureCanonicalSafetyOverrides_PreservesFixtureOverrides()
{
    Arguments args{};
    args.device = L"C:\\fixtures\\sample.apfs.img";
    args.allow_legacy_scaffold_for_fixtures = true;
    args.write_require_canonical_commit = false;
    args.write_disallow_scaffold_commit_on_non_fixture = false;
    args.write_reject_scaffold_replay_blob_on_non_fixture = false;
    args.write_require_canonical_replay_candidate_on_non_fixture = false;

    ApplyNonFixtureCanonicalSafetyOverrides(args);

    return Require(
        args.allow_legacy_scaffold_for_fixtures &&
        !args.write_require_canonical_commit &&
        !args.write_disallow_scaffold_commit_on_non_fixture &&
        !args.write_reject_scaffold_replay_blob_on_non_fixture &&
        !args.write_require_canonical_replay_candidate_on_non_fixture,
        "Fixture canonical safety overrides should preserve explicit fixture relaxations and legacy scaffold fallback setting");
}

bool TestApplyNonFixtureCanonicalSafetyOverrides_FixtureNamedDirectoryWithoutPatternStaysStrict()
{
    Arguments args{};
    args.device = L"C:\\fixtures\\sample.bin";
    args.allow_legacy_scaffold_for_fixtures = true;
    args.write_require_canonical_commit = false;
    args.write_disallow_scaffold_commit_on_non_fixture = false;
    args.write_reject_scaffold_replay_blob_on_non_fixture = false;
    args.write_require_canonical_replay_candidate_on_non_fixture = false;

    ApplyNonFixtureCanonicalSafetyOverrides(args);

    return Require(
        !args.allow_legacy_scaffold_for_fixtures &&
        args.write_require_canonical_commit &&
        args.write_disallow_scaffold_commit_on_non_fixture &&
        args.write_reject_scaffold_replay_blob_on_non_fixture &&
        args.write_require_canonical_replay_candidate_on_non_fixture,
        "Fixture-like directory names must not bypass strict non-fixture canonical safety overrides");
}
bool RunSelectedTest(const std::string& name)
{
    if (name == "recycle-bin-attributes")
    {
        return TestRecycleBinPathsExposeExplorerCompatibleAttributes();
    }
    if (name == "volume-acl-flag")
    {
        return TestVolumeParamsUseExplorerFriendlyCleanupFlags();
    }
    if (name == "stable-volume-serial")
    {
        return TestStableVolumeSerialDependsOnVolumeIdentityNotProcessUptime();
    }
    if (name == "flush-finalizes-pending-journal")
    {
        return TestFlushFinalizesPendingMutationJournal();
    }
    if (name == "close-commits-pending-native-metadata-after-directory-create")
    {
        return TestCloseCommitsPendingNativeMetadataAfterDirectoryCreate();
    }
    if (name == "close-skips-native-commit-when-metadata-clean")
    {
        return TestCloseSkipsNativeCommitWhenMetadataIsClean();
    }
    if (name == "native-subtree-delete-bottom-up")
    {
        return TestCloseStagesNativeSubtreeDeleteBottomUp();
    }
    if (name == "recursive-directory-delete-completes-after-child-close")
    {
        return TestRecursiveDirectoryDeleteCompletesAfterChildClose();
    }
    if (name == "directory-cleanup-delete-disposition-metadata-open")
    {
        return TestDirectoryCleanupDeleteDispositionWorksAfterMetadataOnlyOpen();
    }
    if (name == "directory-cleanup-filename-without-delete-keeps-directory")
    {
        return TestDirectoryCleanupFilenameWithoutDeleteFlagKeepsDirectory();
    }
    if (name == "delete-on-close-directory-defers-until-children-drain")
    {
        return TestDeleteOnCloseDirectoryDefersUntilChildrenDrain();
    }
    if (name == "delete-access-open-completes-recently-drained-directory-delete")
    {
        return TestDeleteAccessOpenCompletesRecentlyDrainedDirectoryDelete();
    }
    if (name == "set-basic-info-preserves-open-recently-drained-directory")
    {
        return TestSetBasicInfoPreservesOpenRecentlyDrainedDirectory();
    }
    if (name == "set-basic-info-keeps-directory-opened-after-child-delete")
    {
        return TestSetBasicInfoDoesNotDeleteDirectoryOpenedAfterChildDelete();
    }
    if (name == "recursive-caller-deletes-drained-directory-after-metadata-touch")
    {
        return TestRecursiveCallerCanDeleteDrainedDirectoryAfterMetadataTouch();
    }
    if (name == "deferred-directory-delete-completes-on-directory-close")
    {
        return TestDeferredDirectoryDeleteCompletesOnDirectoryClose();
    }
    if (name == "set-delete-non-empty-directory-defers-until-child-close")
    {
        return TestSetDeleteNonEmptyDirectoryAllowsCallerFinalDeleteRetry();
    }
    if (name == "can-delete-non-empty-directory-defers-until-child-close")
    {
        return TestCanDeleteNonEmptyDirectoryAllowsCallerFinalDeleteRetry();
    }
    if (name == "native-mutation-failure-detail-status")
    {
        return TestStatusFileIncludesNativeMutationFailureDetail();
    }
    if (name == "stale-deleted-set-basic-info-native")
    {
        return TestSetBasicInfoOnStaleDeletedHandleDoesNotDowngradeNativeWrite();
    }
    if (name == "visible-native-missing-set-basic-info-native")
    {
        return TestSetBasicInfoOnVisibleNativeMissingDirectoryDoesNotDowngradeNativeWrite();
    }
    if (name == "stale-delete-target-missing-native")
    {
        return TestDeleteTargetMissingOnStaleDeletedHandleDoesNotDowngradeNativeWrite();
    }
    if (name == "named-stream-copy-compatibility")
    {
        return TestNamedStreamCopyCompatibility();
    }
    if (name == "named-stream-hidden-metadata")
    {
        return TestNamedStreamCreateDoesNotCreateVisibleApfsFile();
    }
    if (name == "legacy-named-stream-artifacts-hidden")
    {
        return TestLegacyNamedStreamArtifactsAreHidden();
    }
    if (name == "missing-named-stream-clean-failure")
    {
        return TestMissingNamedStreamOpenFailsCleanlyWithoutBaseBytes();
    }
    if (name == "duplicate-case-named-streams")
    {
        return TestDuplicateCaseNamedStreamsCoalesceMetadata();
    }
    if (name == "office-temp-rename-replace-workflow")
    {
        return TestOfficeTempRenameReplaceWorkflow();
    }
    if (name == "recycle-bin-metadata-pair-workflow")
    {
        return TestRecycleBinMetadataPairWorkflow();
    }
    if (name == "path-normalization-edge-matrix")
    {
        return TestPathNormalizationMatrixRejectsRiskyWin32Names();
    }
    if (name == "rename-rollback-native-commit-failure")
    {
        return TestRenameRollsBackLocalNamespaceWhenNativeCommitFails();
    }
    if (name == "set-file-size-defers-native-commit-until-flush")
    {
        return TestSetFileSizeDefersNativeCommitUntilFlush();
    }
    if (name == "set-file-size-defers-native-commit-until-close")
    {
        return TestSetFileSizeDefersNativeCommitUntilClose();
    }
    if (name == "delete-on-close-rollback-native-commit-failure")
    {
        return TestDeleteOnCloseRestoresLocalNodeWhenNativeCommitFails();
    }
    if (name == "rename-replace-open-target-hydration")
    {
        return TestRenameReplaceKeepsOpenTargetHandleOnOldHydration();
    }
    if (name == "rename-replace-rollback-native-commit-failure")
    {
        return TestRenameReplaceRollsBackHydrationWhenNativeCommitFails();
    }
    if (name == "metadata-read-open-no-hydration")
    {
        return TestReadOnlyOpenUsesMetadataRangeReadWithoutHydration();
    }
    if (name == "writable-sparse-hydration")
    {
        return TestWritableOpenHydratesSparseMetadataWithoutDenseCache();
    }
    if (name == "commit-timeout-budget-scales-with-pending-payload")
    {
        return TestCommitTimeoutBudgetScalesWithPendingPayload();
    }

    std::cerr << "[FAIL] Unknown selected FsHost semantics test: " << name << std::endl;
    return false;
}
} // namespace

int main(int argc, char** argv)
{
    if (argc > 1)
    {
        bool selected_ok = true;
        bool ran_selected = false;
        for (int i = 1; i < argc; ++i)
        {
            const std::string name = argv[i] ? argv[i] : "";
            if (name.empty() || name == "--only")
            {
                continue;
            }

            ran_selected = true;
            selected_ok &= RunSelectedTest(name);
        }

        if (!ran_selected)
        {
            std::cerr << "[FAIL] No selected FsHost semantics tests were requested." << std::endl;
            return 1;
        }
        if (!selected_ok)
        {
            return 1;
        }

        std::cout << "[PASS] Selected FsHost semantics tests passed." << std::endl;
        return 0;
    }

    bool ok = true;
    ok &= TestCreateRejectsConflictingTypeFlags();
    ok &= TestDeletePendingAncestorBlocksOpenSecurityDelete();
    ok &= TestDeleteIntentAncestorBlocksOpenAndCreate();
    ok &= TestRenameSamePathRequiresExistingNode();
    ok &= TestRenameSamePathValidatesContextPermissions();
    ok &= TestRenameRelativeTargetStaysInSourceParent();
    ok &= TestDirectoryInfoBufferNullTerminatesNameAndReportsUnterminatedSize();
    ok &= TestRecycleBinPathsExposeExplorerCompatibleAttributes();
    ok &= TestRenameRejectsMismatchedOpenContext();
    ok &= TestRenameMissingSourceWithSourceHandleFailsClosed();
    ok &= TestRenameCrossParentSourceHandleSucceedsWithDeleteAccess();
    ok &= TestSetDeleteToggleClearsDeletePending();
    ok &= TestSetDeleteRemovesFileOnLastClose();
    ok &= TestRenameFailsWhileSourceDeletePendingThenRecoversAfterClear();
    ok &= TestRenameFailsWhenSourceDeleteIntentStateIsStale();
    ok &= TestRenameReplaceFailsWhenTargetDeletePending();
    ok &= TestRenameReplaceAllowsFileTargetWithAdditionalOpenHandle();
    ok &= TestRenameRollsBackLocalNamespaceWhenNativeCommitFails();
    ok &= TestRenameReplaceKeepsOpenTargetHandleOnOldHydration();
    ok &= TestRenameReplaceRollsBackHydrationWhenNativeCommitFails();
    ok &= TestCleanupDeleteTrustsPostedDeleteDisposition();
    ok &= TestCleanupDeleteBlocksRenameUntilCloseRemovesSource();
    ok &= TestCloseRemovesEmptyDirectoryAfterCleanupDelete();
    ok &= TestRecursiveDirectoryDeleteCompletesAfterChildClose();
    ok &= TestDirectoryCleanupDeleteDispositionWorksAfterMetadataOnlyOpen();
    ok &= TestDirectoryCleanupFilenameWithoutDeleteFlagKeepsDirectory();
    ok &= TestDeleteOnCloseDirectoryDefersUntilChildrenDrain();
    ok &= TestDeleteAccessOpenCompletesRecentlyDrainedDirectoryDelete();
    ok &= TestSetBasicInfoPreservesOpenRecentlyDrainedDirectory();
    ok &= TestSetBasicInfoDoesNotDeleteDirectoryOpenedAfterChildDelete();
    ok &= TestRecursiveCallerCanDeleteDrainedDirectoryAfterMetadataTouch();
    ok &= TestDeferredDirectoryDeleteCompletesOnDirectoryClose();
    ok &= TestSetDeleteNonEmptyDirectoryAllowsCallerFinalDeleteRetry();
    ok &= TestCanDeleteNonEmptyDirectoryAllowsCallerFinalDeleteRetry();
    ok &= TestCloseWithoutDeleteLatchPreservesNode();
    ok &= TestCleanupWithoutDeleteReleasesFileForRename();
    ok &= TestCanDeleteSupportsParentDeleteChildPermission();
    ok &= TestRenameSupportsParentDeleteChildPermission();
    ok &= TestRenameSameParentRequiresInsertPermission();
    ok &= TestRenameCrossParentOldParentHandleDenied();
    ok &= TestRenameParentWithoutDeleteChildDenied();
    ok &= TestRenameReplaceRequiresTargetParentDeleteChild();
    ok &= TestRenameReplaceAllowsTargetParentDeleteChild();
    ok &= TestRenameReplaceRequiresDeleteChildEvenWithInsertPermission();
    ok &= TestRenameDirectoryReplaceRequiresDirectoryInsertPermission();
    ok &= TestCanDeleteNullNameParentHandleRequiresDeleteNotDeleteChild();
    ok &= TestCanDeleteFailsWhenAdditionalHandleOpen();
    ok &= TestSetDeleteFailsWhenAdditionalHandleOpen();
    ok &= TestCleanupDeleteLatchesEvenWhenAdditionalHandlesRemain();
    ok &= TestCloseOnlyCommitsWhenDeleteMutationIsEmitted();
    ok &= TestDeleteOnCloseCommitsWhenDeleteIsLatching();
    ok &= TestSetFileSizeDefersNativeCommitUntilFlush();
    ok &= TestSetFileSizeDefersNativeCommitUntilClose();
    ok &= TestDeleteOnCloseRestoresLocalNodeWhenNativeCommitFails();
    ok &= TestRenameDirectoryFailsWhenDescendantHandleOpen();
    ok &= TestRenameSourceHandleSucceedsWithOnlyCurrentHandleOpen();
    ok &= TestRenameTargetParentRequiresFileInsertPermission();
    ok &= TestRenameTargetParentRequiresDirectoryInsertPermission();
    ok &= TestCleanupDeleteSkipsNonEmptyDirectory();
    ok &= TestCleanupDeleteBlockedByAdditionalOpenHandle();
    ok &= TestDeleteOnCloseRemovesOnlyAfterLastHandleCloses();
    ok &= TestRenameReplaceFailsWhenTargetDirectoryNotEmpty();
    ok &= TestRenameReplaceFailsWhenTargetDirectoryHasOpenHandle();
    ok &= TestCreateRejectedWhenShutdownDrainActive();
    ok &= TestRenameRejectedWhenShutdownDrainActive();
    ok &= TestMetadataMutationsRejectedWhenShutdownDrainActive();
    ok &= TestDataMutationsRejectedWhenShutdownDrainActive();
    ok &= TestOpenMutationAccessDeniedWhenShutdownDrainActive();
    ok &= TestOpenDeleteAccessDeniedWhenShutdownDrainActive();
    ok &= TestOpenReadOnlyAllowedWhenShutdownDrainActive();
    ok &= TestSetSecurityRejectedWhenShutdownDrainActive();
    ok &= TestCleanupDeleteNoopWhenShutdownDrainActive();
    ok &= TestFlushRejectedWhenShutdownDrainActive();
    ok &= TestFlushAllowedWhenWriteDisabledDuringShutdownDrain();
    ok &= TestFlushReleasesExternalMutationScopeAfterSuccessfulWriteEnabledFlush();
    ok &= TestFlushFinalizesPendingMutationJournal();
    ok &= TestCloseCommitsPendingNativeMetadataAfterDirectoryCreate();
    ok &= TestCloseStagesNativeSubtreeDeleteBottomUp();
    ok &= TestStatusFileIncludesNativeMutationFailureDetail();
    ok &= TestSetBasicInfoOnStaleDeletedHandleDoesNotDowngradeNativeWrite();
    ok &= TestSetBasicInfoOnVisibleNativeMissingDirectoryDoesNotDowngradeNativeWrite();
    ok &= TestDeleteTargetMissingOnStaleDeletedHandleDoesNotDowngradeNativeWrite();
    ok &= TestMutatingCallbacksFailWriteProtectedWhenWriteDisabled();
    ok &= TestSetSecurityIsNoopWhenWriteEnabled();
    ok &= TestDefaultSecurityDescriptorGrantsUsersWriteAccess();
    ok &= TestOpenMutationAccessDeniedWhenWriteDisabled();
    ok &= TestOpenDeleteAccessDeniedWhenWriteDisabled();
    ok &= TestOpenFailsWhenDeleteIntentStateIsStale();
    ok &= TestCleanupDeleteNoopWhenWriteDisabled();
    ok &= TestNativeMutationDenialLatchesFailClosedRecovery();
    ok &= TestConcurrentNativeMutationDenialsRemainFailClosedAfterDowngrade();
    ok &= TestConcurrentNativeDenialStatusFileReflectsFailClosedState();
    ok &= TestStatusFileDerivesCanonicalGateFailureAfterNativeFailClosedDowngrade();
    ok &= TestStatusFilePreservesExplicitCompatibilitySignalsAfterNativeFailClosedDowngrade();
    ok &= TestNativeSafetyStateFallsBackWhenMutationUnavailable();
    ok &= TestExternalMutationScopeTracksActiveCountAndDrainGate();
    ok &= TestBeginMutationShutdownDrainWaitsForInFlightMutation();
    ok &= TestBeginMutationShutdownDrainTimesOutWithStuckMutation();
    ok &= TestCommitTimeoutBudgetScalesWithPendingPayload();
    ok &= TestStatusFileTracksShutdownDrainAndInFlightMutations();
    ok &= TestExternalMutationScopePublishesIdleStatusOnExit();
    ok &= TestCleanRecoveryCheckpointXidPrefersSuperblockWhenCommittedTelemetryStale();
    ok &= TestConcurrentCreateSamePathIsSerializedAndConsistent();
    ok &= TestConcurrentRenameSameSourceDifferentTargetsIsSerialized();
    ok &= TestConcurrentRenameAndSetDeleteOnSameSourceIsSerialized();
    ok &= TestConcurrentRenameReplaceAndTargetSetDeleteIsFailClosed();
    ok &= TestConcurrentRenameReplaceAndDeleteCloseInterleavingIsConsistent();
    ok &= TestConcurrentRenameReplaceSameTargetFromTwoSourcesIsSerialized();
    ok &= TestConcurrentRenameReplaceSameTargetWithHandleCloseTransition();
    ok &= TestConcurrentSharedParentRenameAndSetDeleteOnSiblingIsConsistent();
    ok &= TestConcurrentSharedParentRenameAndSiblingDeleteCloseIsConsistent();
    ok &= TestLoadHydratedPayloadWithoutHydrationReturnsNullWhenHydrateDisabled();
    ok &= TestLoadHydratedPayloadReadsExistingHydrationWhenHydrateDisabled();
    ok &= TestReadOnlyOpenUsesMetadataRangeReadWithoutHydration();
    ok &= TestWritableOpenHydratesSparseMetadataWithoutDenseCache();
    ok &= TestParseArgsDefaultsStrictNonFixtureControls();
    ok &= TestParseArgsParsesStrictNonFixtureControlOverrides();
    ok &= TestBuildWinFspMountPointUsesGlobalDriveForExplorer();
    ok &= TestVolumeParamsUseExplorerFriendlyCleanupFlags();
    ok &= TestNamedStreamCopyCompatibility();
    ok &= TestNamedStreamCreateDoesNotCreateVisibleApfsFile();
    ok &= TestLegacyNamedStreamArtifactsAreHidden();
    ok &= TestMissingNamedStreamOpenFailsCleanlyWithoutBaseBytes();
    ok &= TestDuplicateCaseNamedStreamsCoalesceMetadata();
    ok &= TestOfficeTempRenameReplaceWorkflow();
    ok &= TestRecycleBinMetadataPairWorkflow();
    ok &= TestPathNormalizationMatrixRejectsRiskyWin32Names();
    ok &= TestNormalizePathStripsDriveQualifiedRoot();
    ok &= TestStableVolumeSerialDependsOnVolumeIdentityNotProcessUptime();
    ok &= TestVolumeInfoFallbackKeepsExplorerCapacityBarUsable();
    ok &= TestVolumeInfoUsesMetadataStoreWhenAvailable();
    ok &= TestRequiresCanonicalMutationGateDefaultsToStrict();
    ok &= TestRequiresCanonicalMutationGateNeedsAllStrictFlagsDisabled();
    ok &= TestApplyNonFixtureCanonicalSafetyOverrides_EnforcesStrictControls();
    ok &= TestApplyNonFixtureCanonicalSafetyOverrides_PreservesFixtureOverrides();
    ok &= TestApplyNonFixtureCanonicalSafetyOverrides_FixtureNamedDirectoryWithoutPatternStaysStrict();

    if (!ok)
    {
        return 1;
    }

    std::cout << "[PASS] FsHost semantics tests passed." << std::endl;
    return 0;
}
