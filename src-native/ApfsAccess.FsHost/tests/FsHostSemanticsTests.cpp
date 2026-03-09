#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <iostream>
#include <memory>
#include <string>
#include <thread>

#define APFSACCESS_FSHOST_UNIT_TEST 1
#include "../src/main.cpp"

namespace
{
bool Require(bool condition, const char* message)
{
    if (!condition)
    {
        std::cerr << "[FAIL] " << message << std::endl;
        return false;
    }

    return true;
}

std::shared_ptr<Node> MakeNode(const std::wstring& path, bool is_directory, bool delete_pending = false)
{
    auto node = std::make_shared<Node>();
    node->path = NormalizePath(path);
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

bool TestRenameCrossParentSourceHandleDenied()
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
    if (!Require(status == STATUS_ACCESS_DENIED, "Cross-parent rename should deny source-handle context without target-parent authority"))
    {
        return false;
    }

    return Require(
        context.nodes.find(Key(L"\\a\\source.txt")) != context.nodes.end() &&
        context.nodes.find(Key(L"\\b\\moved.txt")) == context.nodes.end(),
        "Denied source-handle cross-parent rename should preserve source and destination state");
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

bool TestRenameReplaceFailsWhenTargetHasAdditionalOpenHandle()
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
    if (!Require(replace_status == STATUS_SHARING_VIOLATION, "Rename replace should fail with STATUS_SHARING_VIOLATION when target has an open handle"))
    {
        return false;
    }

    return Require(
        context.nodes.find(Key(L"\\source.txt")) != context.nodes.end() &&
        context.nodes.find(Key(L"\\target.txt")) != context.nodes.end(),
        "Replace against busy target should preserve source and target entries");
}

bool TestCleanupDeleteRequiresDeleteAccess()
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
        FspCleanupDelete);

    if (!Require(!open_context.delete_on_cleanup, "Cleanup delete should ignore handles without DELETE permission"))
    {
        return false;
    }
    if (!Require(file->delete_intent_count == 0 && !file->delete_pending, "Cleanup delete without permission should not set delete-pending state"))
    {
        return false;
    }

    open_context.allow_delete = true;
    CB_Cleanup(
        &fs,
        &open_context,
        const_cast<PWSTR>(L"\\cleanup.txt"),
        FspCleanupDelete);

    if (!Require(open_context.delete_on_cleanup, "Cleanup delete should latch delete-on-close when DELETE permission is granted"))
    {
        return false;
    }
    return Require(
        file->delete_intent_count == 1 && file->delete_pending,
        "Cleanup delete with permission should mark the node delete-pending");
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
    return Require(can_delete == STATUS_SHARING_VIOLATION, "CanDelete should fail with STATUS_SHARING_VIOLATION when another handle is open");
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
    if (!Require(set_delete == STATUS_SHARING_VIOLATION, "SetDelete should fail with STATUS_SHARING_VIOLATION when another handle is open"))
    {
        return false;
    }

    return Require(!current_open.delete_on_cleanup, "Failed SetDelete should not latch delete-on-cleanup");
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

    if (!Require(!open_context.delete_on_cleanup, "Cleanup delete should not latch when additional handles are open"))
    {
        return false;
    }

    return Require(
        file->delete_intent_count == 0 && !file->delete_pending,
        "Cleanup delete with additional handles should keep node non-pending");
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
    file->open_handle_count = 1;
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

    file->open_handle_count = 2;
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

    return Require(file->open_handle_count == 1, "Cleanup delete during shutdown drain should preserve open-handle accounting");
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

    const bool rename_blocked =
        rename == STATUS_SHARING_VIOLATION ||
        rename == STATUS_DELETE_PENDING;
    if (!Require(rename_blocked, "Concurrent rename-replace vs target set-delete should fail closed (SHARING_VIOLATION or DELETE_PENDING)"))
    {
        return false;
    }
    if (!Require(set_delete == STATUS_SUCCESS, "Concurrent target set-delete should succeed in rename-replace contention race"))
    {
        return false;
    }

    if (!Require(context.nodes.find(Key(L"\\source.txt")) != context.nodes.end(), "Failed rename-replace race should preserve source path"))
    {
        return false;
    }
    if (!Require(context.nodes.find(Key(L"\\target.txt")) != context.nodes.end(), "Failed rename-replace race should preserve target path"))
    {
        return false;
    }

    auto target_after = context.nodes.at(Key(L"\\target.txt"));
    if (!Require(target_after->delete_pending, "Target should be delete-pending after successful set-delete race"))
    {
        return false;
    }

    return Require(target_after->delete_intent_count > 0, "Target delete intent count should be latched after set-delete race");
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
} // namespace

int main()
{
    bool ok = true;
    ok &= TestCreateRejectsConflictingTypeFlags();
    ok &= TestDeletePendingAncestorBlocksOpenSecurityDelete();
    ok &= TestDeleteIntentAncestorBlocksOpenAndCreate();
    ok &= TestRenameSamePathRequiresExistingNode();
    ok &= TestRenameSamePathValidatesContextPermissions();
    ok &= TestRenameRejectsMismatchedOpenContext();
    ok &= TestRenameMissingSourceWithSourceHandleFailsClosed();
    ok &= TestRenameCrossParentSourceHandleDenied();
    ok &= TestSetDeleteToggleClearsDeletePending();
    ok &= TestRenameFailsWhileSourceDeletePendingThenRecoversAfterClear();
    ok &= TestRenameFailsWhenSourceDeleteIntentStateIsStale();
    ok &= TestRenameReplaceFailsWhenTargetDeletePending();
    ok &= TestRenameReplaceFailsWhenTargetHasAdditionalOpenHandle();
    ok &= TestCleanupDeleteRequiresDeleteAccess();
    ok &= TestCleanupDeleteBlocksRenameUntilCloseRemovesSource();
    ok &= TestCloseRemovesEmptyDirectoryAfterCleanupDelete();
    ok &= TestCloseWithoutDeleteLatchPreservesNode();
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
    ok &= TestMutatingCallbacksFailWriteProtectedWhenWriteDisabled();
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
    ok &= TestStatusFileTracksShutdownDrainAndInFlightMutations();
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
    ok &= TestParseArgsDefaultsStrictNonFixtureControls();
    ok &= TestParseArgsParsesStrictNonFixtureControlOverrides();
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
