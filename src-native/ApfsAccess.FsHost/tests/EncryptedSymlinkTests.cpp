#define APFSACCESS_FSHOST_UNIT_TEST 1
#include "../src/main.cpp"

namespace
{
unsigned checks = 0;
void Check(bool value)
{
    ++checks;
    if (!value) throw std::runtime_error("EncryptedSymlinkAssertion:" + std::to_string(checks));
}
BOOLEAN AddDirectory(FSP_FSCTL_DIR_INFO* entry, PVOID buffer, ULONG size, PULONG done)
{
    if (!entry) return TRUE;
    if (entry->Size > size - *done) return FALSE;
    std::memcpy(static_cast<std::byte*>(buffer) + *done, entry, entry->Size);
    *done += entry->Size; return TRUE;
}
void Exercise(MountContext& context, bool writable)
{
    auto& state = *context.encrypted;
    const auto& api = writable ? EncryptedWritableServeInterface() : EncryptedServeInterface();
    FSP_FILE_SYSTEM fs{}; fs.UserContext = &context;
    context.api.AddDir = AddDirectory;
    std::vector<PVOID> handles;
    ScopeExit close{[&] { for (auto h : handles) api.Close(&fs, h); }};
    const auto open = [&](std::wstring name, UINT32 options, UINT32 access, NTSTATUS expected) {
        PVOID h = nullptr; FSP_FSCTL_FILE_INFO info{};
        Check(api.Open(&fs, name.data(), options, access, &h, &info) == expected);
        Check((h != nullptr) == NT_SUCCESS(expected));
        if (h) handles.push_back(h);
        return h;
    };
    apfsaccess::catalog::EncryptedNodeInfo node;
    Check(state.session->ResolvePath(L"\\a_link", node) == EncError::None);
    Check(node.inode_id == 22 && (node.mode & 0170000) == 0120000 && node.size == 18);
    encrypted_mount::Bytes target;
    Check(state.session->ReadXattr(node.inode_id, "com.apple.fs.symlink", target) == EncError::None);
    Check(target.size() == node.size + 1 && target.back() == std::byte{});
    encrypted_mount::Bytes regular;
    Check(state.session->ReadFile(node.inode_id, 0, 1, regular) == EncError::FileNotFound && regular.empty());
    auto h = open(L"\\a_link", FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT, GENERIC_READ, STATUS_SUCCESS);
    FSP_FSCTL_FILE_INFO info{};
    Check(api.GetFileInfo(&fs, h, &info) == STATUS_SUCCESS && info.FileSize == 18 && info.IndexNumber == 22);
    Check((info.FileAttributes & FILE_ATTRIBUTE_READONLY) != 0);
    Check((info.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0);
    for (const auto offset : {0ull, 2ull, 17ull}) {
        std::array<std::byte, 64> bytes{}; bytes.fill(std::byte{0x7f}); ULONG done = 0;
        Check(api.Read(&fs, h, bytes.data(), offset, static_cast<ULONG>(bytes.size()), &done) == STATUS_SUCCESS);
        Check(done == 18 - offset);
        Check(std::equal(bytes.begin(), bytes.begin() + done, target.begin() + offset));
        Check(bytes[done] == std::byte{0x7f}); // Canonical target's NUL is not file data.
    }
    for (const auto offset : {18ull, UINT64_MAX}) {
        std::byte byte{}; ULONG done = 99;
        Check(api.Read(&fs, h, &byte, offset, 1, &done) == STATUS_END_OF_FILE && done == 0);
    }
    ULONG done = 99;
    Check(api.Read(&fs, h, nullptr, 0, 0, &done) == STATUS_SUCCESS && done == 0);
    open(L"\\a_link\\child", 0, GENERIC_READ, STATUS_NOT_A_DIRECTORY);
    auto root = open(L"\\", FILE_DIRECTORY_FILE, GENERIC_READ, STATUS_SUCCESS);
    std::array<std::byte, 8192> directory{}; done = 0;
    Check(api.ReadDirectory(&fs, root, nullptr, nullptr, directory.data(), static_cast<ULONG>(directory.size()), &done) == STATUS_SUCCESS);
    bool found = false;
    for (ULONG at = 0; at < done;) {
        const auto* entry = reinterpret_cast<const FSP_FSCTL_DIR_INFO*>(directory.data() + at);
        Check(entry->Size >= sizeof(FSP_FSCTL_DIR_INFO) && entry->Size <= done - at);
        if (entry->FileInfo.IndexNumber == 22) {
            found = true;
            Check(entry->FileInfo.FileSize == 18 && (entry->FileInfo.FileAttributes & FILE_ATTRIBUTE_READONLY));
            Check((entry->FileInfo.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0);
        }
        at += entry->Size;
    }
    Check(found);
    if (writable) {
        const auto before = state.writer->CachedStatus();
        encrypted_mount::Entries entries;
        Check(state.session->ListDirectory(2, entries) == EncError::None);
        bool regular_control = false;
        for (const auto& entry : entries) {
            apfsaccess::catalog::EncryptedNodeInfo regular_node;
            Check(state.session->GetMetadata(entry.inode_id, regular_node) == EncError::None);
            if ((regular_node.mode & 0170000) != 0100000) continue;
            auto regular_handle = open(L"\\" + entry.windows_name, 0, GENERIC_READ | GENERIC_WRITE, STATUS_SUCCESS);
            Check(api.SetFileSize(&fs, regular_handle, regular_node.size, FALSE, &info) == STATUS_SUCCESS);
            Check(api.SetBasicInfo(&fs, regular_handle, INVALID_FILE_ATTRIBUTES, 0, 0, 0, 0, &info) == STATUS_SUCCESS);
            regular_control = true; break;
        }
        Check(regular_control);
        open(L"\\a_link", 0, GENERIC_WRITE, STATUS_MEDIA_WRITE_PROTECTED);
        open(L"\\a_link", FILE_DELETE_ON_CLOSE, GENERIC_READ, STATUS_MEDIA_WRITE_PROTECTED);
        std::array<std::byte, 2> bytes{}; done = 99;
        Check(api.Write(&fs, h, bytes.data(), 0, 2, FALSE, FALSE, &done, &info) == STATUS_MEDIA_WRITE_PROTECTED && !done);
        Check(api.SetFileSize(&fs, h, 18, FALSE, &info) == STATUS_MEDIA_WRITE_PROTECTED);
        Check(api.Overwrite(&fs, h, 0, FALSE, 0, &info) == STATUS_MEDIA_WRITE_PROTECTED);
        Check(api.SetBasicInfo(&fs, h, INVALID_FILE_ATTRIBUTES, 0, 0, 0, 0, &info) == STATUS_MEDIA_WRITE_PROTECTED);
        std::wstring destination = L"\\link-must-not-move";
        Check(api.Rename(&fs, h, nullptr, destination.data(), FALSE) == STATUS_MEDIA_WRITE_PROTECTED);
        Check(api.CanDelete(&fs, h, nullptr) == STATUS_CANNOT_DELETE);
        Check(api.SetDelete(&fs, h, nullptr, TRUE) == STATUS_MEDIA_WRITE_PROTECTED);
        api.Cleanup(&fs, h, nullptr, FspCleanupDelete);
        Check(!state.failed.load() && state.pending_deletes.load() == 0);
        auto attr = open(L"\\a_link:APFS.Xattr.636F6D2E6170706C652E66732E73796D6C696E6B", 0, GENERIC_READ, STATUS_SUCCESS);
        done = 0; std::array<std::byte, 64> raw{};
        Check(api.Read(&fs, attr, raw.data(), 0, 64, &done) == STATUS_SUCCESS && done == target.size());
        Check(std::equal(raw.begin(), raw.begin() + done, target.begin()));
        Check(api.Write(&fs, attr, bytes.data(), 0, 2, FALSE, FALSE, &done, &info) == STATUS_MEDIA_WRITE_PROTECTED);
        std::wstring stream = L"\\a_link:APFS.Xattr.757365722E74657374"; PVOID created = nullptr;
        Check(api.Create(&fs, stream.data(), 0, GENERIC_WRITE, FILE_ATTRIBUTE_NORMAL, nullptr, 0, &created, &info) == STATUS_MEDIA_WRITE_PROTECTED && !created);
        const auto after = state.writer->CachedStatus();
        Check(before.accepted == after.accepted && before.durable == after.durable && before.cleaned == after.cleaned);
        Check(before.image.checkpoint_xid == after.image.checkpoint_xid && !after.recovery_required);
    }
    Check(!state.failed.load() && !state.cancelled->load());
}
}

int wmain(int argc, wchar_t** argv)
{
    try {
        Check(argc == 3);
        auto credential = apfsaccess::transport::ReceiveCredential(GetStdHandle(STD_INPUT_HANDLE),
            std::chrono::milliseconds(5000), std::atomic<bool>{false});
        Check(bool(credential));
        for (bool writable : {false, true}) {
            MountContext context; context.args.encrypted.enabled = true; context.args.readonly = !writable;
            context.encrypted = std::make_unique<encrypted_mount::State>();
            auto& state = *context.encrypted;
            using namespace apfsaccess::catalog;
            if (!writable) {
                auto lease = std::make_shared<apfsaccess::transport::WindowsImageLease>(argv[1]);
                state.source = std::make_shared<apfsaccess::transport::OwnedEncryptedImageSource>(lease, 20480, 4153344);
                UnlockError unlock_error{};
                auto bags = InspectPasswordKeybagMetadata(*state.source, 1026, KeybagLength::IncludesHeader, unlock_error);
                Check(bags.has_value() && bags->users.size() == 1);
                auto selection = bags->selection; selection.user_uuid = bags->users.front();
                PasswordUnlockBudget budget; EncError error{};
                state.session = ApfsEncryptedReadSession::Unlock(state.source, state.source->SourceIdentity(), state.source->Revision(),
                    selection, credential.bytes.Bytes(), budget, error, unlock_error, state.cancelled);
                Check(bool(state.session));
                Check(state.session->GetNamespaceInfo(state.names) == EncError::None);
            } else {
                EncryptedImageRuntime::Options options; options.image = {argv[1], 20480, 4153344, 1026};
                options.recovery_directory = argv[2]; std::string error;
                state.writer = EncryptedImageRuntime::Open(options, error);
                if (!state.writer) throw std::runtime_error(error);
                PasswordUnlockBudget budget;
                const auto unlocked = state.writer->Unlock(credential.bytes, budget, error);
                credential.bytes.Clear();
                if (!unlocked) throw std::runtime_error(error);
                Check(EncWritableRefresh(state) == STATUS_SUCCESS);
            }
            Exercise(context, writable);
            state.Close(); Check(!state.failed.load());
        }
        std::cout << "PASS " << checks << " assertions; canonical symlink target placeholder RO/RW, no follow, zero accepted mutations\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
