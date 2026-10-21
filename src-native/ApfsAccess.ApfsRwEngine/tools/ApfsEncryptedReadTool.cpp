#include "EncryptedReadTransport.h"
#include "ApfsFormat.h"
#include <charconv>
#include <iostream>
#include <map>
#include <thread>
#include <set>
#include <sstream>

using namespace apfsaccess;
namespace
{
struct PublicFailure { const char* name; int exit; };
std::atomic<bool> control_cancel{false};
BOOL WINAPI Control(DWORD event)
{
    if (event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT || event == CTRL_CLOSE_EVENT ||
        event == CTRL_LOGOFF_EVENT || event == CTRL_SHUTDOWN_EVENT) { control_cancel = true; return TRUE; }
    return FALSE;
}
std::uint64_t Number(const std::wstring& text)
{
    if (text.empty()) throw PublicFailure{"InvalidPublicNumber", 2};
    std::uint64_t value = 0;
    for (wchar_t c : text)
    {
        if (c < L'0' || c > L'9' || value > (UINT64_MAX - (c-L'0'))/10)
            throw PublicFailure{"InvalidPublicNumber", 2};
        value = value*10 + c-L'0';
    }
    return value;
}
std::string Ascii(const std::wstring& value)
{
    std::string result;
    for (wchar_t c : value)
    {
        if (c < 0x20 || c > 0x7e) throw PublicFailure{"InvalidPublicSelector", 2};
        result.push_back(static_cast<char>(c));
    }
    return result;
}
catalog::KeybagUuid Uuid(const std::wstring& text)
{
    if (text.size() != 32) throw PublicFailure{"InvalidUuid", 2};
    catalog::KeybagUuid result{};
    auto digit = [](wchar_t c) -> unsigned {
        if (c >= L'0' && c <= L'9') return c-L'0';
        if (c >= L'a' && c <= L'f') return c-L'a'+10;
        if (c >= L'A' && c <= L'F') return c-L'A'+10;
        throw PublicFailure{"InvalidUuid", 2};
    };
    for (unsigned i = 0; i < 16; ++i) result[i] = std::byte((digit(text[2*i])<<4)|digit(text[2*i+1]));
    return result;
}
const char* ReadError(catalog::EncryptedReadError error)
{
    using E = catalog::EncryptedReadError;
    switch(error) {
#define NAME(x) case E::x: return #x
    NAME(None); NAME(InvalidArgument); NAME(UnlockFailed); NAME(UnsupportedEncryptionLayout);
    NAME(SourceIdentityMismatch); NAME(ResourceLimit); NAME(ReadFailure); NAME(CryptoFailure);
    NAME(MetadataIntegrityFailure); NAME(Closed); NAME(Cancelled); NAME(FileNotFound);
    NAME(NotDirectory); NAME(XattrNotFound); NAME(NamespaceUnavailable);
#undef NAME
    }
    return "ReadFailure";
}
const char* UnlockError(catalog::UnlockError error)
{
    using E = catalog::UnlockError;
    switch(error) {
#define NAME(x) case E::x: return #x
    NAME(None); NAME(InvalidArgument); NAME(UnsupportedFormat); NAME(Malformed); NAME(IdentityMismatch);
    NAME(IntegrityFailure); NAME(CredentialOrKeyMismatch); NAME(ResourceLimit); NAME(RateLimited);
    NAME(ReadFailure); NAME(CryptoFailure);
#undef NAME
    }
    return "UnlockFailure";
}
struct Plaintext
{
    std::vector<std::byte> bytes;
    ~Plaintext() { if (!bytes.empty()) SecureZeroMemory(bytes.data(), bytes.size()); }
};
struct Handle
{
    HANDLE value = nullptr;
    ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};
// Watchdog outlives exception cleanup and final diagnostics. No buffered output.
class Operation final
{
public:
    std::shared_ptr<std::atomic<bool>> cancellation = std::make_shared<std::atomic<bool>>(false);
    Operation()
    {
        if (!DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(),
            &main_thread_.value, THREAD_TERMINATE, FALSE, 0)) throw PublicFailure{"CancellationSetupFailure",3};
        SetDeadline(30000);
        monitor_ = std::jthread([this](std::stop_token stop) {
            while (!stop.stop_requested()) {
                const auto event = external_.load();
                if (control_cancel.load() || GetTickCount64() >= deadline_.load() ||
                    (event && WaitForSingleObject(event, 0) == WAIT_OBJECT_0)) cancellation->store(true);
                if (cancellation->load()) CancelSynchronousIo(main_thread_.value);
                Sleep(5);
            }
        });
    }
    void SetDeadline(std::uint64_t ms) { deadline_.store(GetTickCount64() + ms); }
    void SetCancellationHandle(std::uint64_t value)
    {
        const auto inherited = reinterpret_cast<HANDLE>(static_cast<uintptr_t>(value));
        DWORD flags = 0;
        if (!value || value > UINTPTR_MAX || inherited == GetStdHandle(STD_INPUT_HANDLE) ||
            inherited == GetStdHandle(STD_OUTPUT_HANDLE) || inherited == GetStdHandle(STD_ERROR_HANDLE) ||
            !GetHandleInformation(inherited, &flags) || !(flags & HANDLE_FLAG_INHERIT))
            throw PublicFailure{"InvalidCancellationHandle",2};
        Handle candidate;
        if (!DuplicateHandle(GetCurrentProcess(), inherited, GetCurrentProcess(), &candidate.value,
                SYNCHRONIZE | 0x0001 /* EVENT_QUERY_STATE */, FALSE, 0)) throw PublicFailure{"InvalidCancellationHandle",2};
        // NtQueryEvent rejects non-events. NotificationEvent (0) is manual reset.
        using QueryEvent = LONG (NTAPI*)(HANDLE, int, void*, ULONG, ULONG*);
        const auto query = reinterpret_cast<QueryEvent>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryEvent"));
        struct EventInfo { LONG type, state; } info{};
        ULONG returned = 0;
        if (!query || query(candidate.value, 0, &info, sizeof(info), &returned) < 0 ||
            returned != sizeof(info) || info.type != 0) throw PublicFailure{"InvalidCancellationHandle",2};
        external_owner_.value = candidate.value; candidate.value = nullptr;
        external_.store(external_owner_.value);
        CloseHandle(inherited);
    }
    void Output(HANDLE handle, const void* data, std::size_t size)
    {
        const auto* bytes = static_cast<const std::byte*>(data);
        std::size_t done = 0;
        while (done < size) {
            if (cancellation->load()) throw PublicFailure{"Cancelled",6};
            DWORD written = 0;
            if (!WriteFile(handle, bytes+done, static_cast<DWORD>((std::min)(size-done,std::size_t{4096})), &written,nullptr) || !written)
                throw PublicFailure{cancellation->load() ? "Cancelled" : "OutputFailure", cancellation->load() ? 6 : 8};
            done += written;
        }
        if (cancellation->load()) throw PublicFailure{"Cancelled",6};
    }
    void Output(const std::string& text) { Output(GetStdHandle(STD_OUTPUT_HANDLE),text.data(),text.size()); }
    // Best effort; the watchdog remains active during this synchronous write.
    void Status(const std::string& text) noexcept
    {
        DWORD written = 0;
        WriteFile(GetStdHandle(STD_ERROR_HANDLE),text.data(),static_cast<DWORD>(text.size()),&written,nullptr);
    }
private:
    Handle main_thread_, external_owner_;
    std::atomic<HANDLE> external_{nullptr};
    std::atomic<ULONGLONG> deadline_{0};
    std::jthread monitor_; // Joins before handles/cancellation are destroyed.
};
int Run(int argc, wchar_t** argv, Operation& operation)

{
    std::map<std::wstring, std::wstring> options;
    const std::set<std::wstring> allowed{L"--mode",L"--image",L"--source-id",L"--store-offset",L"--store-size",
        L"--container-uuid",L"--volume-uuid",L"--volume-oid",L"--checkpoint-xid",L"--user-uuid",
        L"--container-bag-oid",L"--container-bag-xid",L"--volume-bag-oid",L"--volume-bag-xid",L"--bag-length",
        L"--inode",L"--offset",L"--length",L"--xattr",L"--credential-timeout-ms",L"--operation-timeout-ms",L"--cancel-handle"};
    bool binary = false;
    for (int i = 1; i < argc; ++i)
    {
        const std::wstring key(argv[i]);
        if (key == L"--password" || key.starts_with(L"--password=")) throw PublicFailure{"PasswordArgumentForbidden",2};
        if (key == L"--binary-stdout") { if (binary) throw PublicFailure{"DuplicateOption",2}; binary = true; continue; }
        if (!allowed.contains(key) || i+1 == argc || options.contains(key)) throw PublicFailure{"InvalidPublicOptions",2};
        options.emplace(key, argv[++i]);
    }
    auto get = [&](const wchar_t* key) -> const std::wstring& {
        auto it = options.find(key); if (it == options.end()) throw PublicFailure{"MissingExactSelector",2}; return it->second;
    };
    const auto mode = get(L"--mode");
    if (mode != L"source" && mode != L"selectors" && mode != L"inspect" && mode != L"read" && mode != L"metadata" && mode != L"xattr")
        throw PublicFailure{"InvalidMode",2};
    const bool bytes_output = mode == L"read" || mode == L"xattr";
    if (bytes_output != binary) throw PublicFailure{"ExplicitBinaryOutputRequired",2};
    if ((mode != L"read" && (options.contains(L"--offset") || options.contains(L"--length"))) ||
        (mode != L"read" && mode != L"metadata" && mode != L"xattr" && options.contains(L"--inode")) ||
        (mode != L"xattr" && options.contains(L"--xattr")))
        throw PublicFailure{"ReadSelectorsRequireReadMode",2};
    const auto store_offset = Number(get(L"--store-offset")), store_size = Number(get(L"--store-size"));
    const auto receive_ms = options.contains(L"--credential-timeout-ms") ? Number(get(L"--credential-timeout-ms")) : 5000;
    const auto operation_ms = options.contains(L"--operation-timeout-ms") ? Number(get(L"--operation-timeout-ms")) : 30000;
    if (receive_ms < 100 || receive_ms > 30000 || operation_ms < 100 || operation_ms > 30000)
        throw PublicFailure{"InvalidTimeout",2};
    operation.SetDeadline(operation_ms);
    if (options.contains(L"--cancel-handle")) operation.SetCancellationHandle(Number(get(L"--cancel-handle")));
    const auto cancellation = operation.cancellation;
    std::shared_ptr<transport::OwnedEncryptedImageSource> source;
    try {
        auto lease = std::make_shared<transport::WindowsImageLease>(get(L"--image"));
        source = std::make_shared<transport::OwnedEncryptedImageSource>(std::move(lease),store_offset,store_size);
    } catch (const PublicFailure&) { throw; }
      catch (...) { throw PublicFailure{"ImageLeaseOrScopeFailure",3}; }
    if (mode == L"source")
    {
        std::ostringstream output;
        output << "{\"mode\":\"source-metadata\",\"sourceId\":\"" << source->SourceIdentity()
            << "\",\"storeOffset\":\"" << store_offset << "\",\"storeSize\":\"" << store_size
            << "\",\"lease\":\"windows-read-deny-write-delete\",\"persistentUnlockedMount\":false}\n";
        operation.Output(output.str());
        return 0;
    }
    if (mode == L"selectors")
    {
        const auto profile = get(L"--bag-length");
        catalog::KeybagLength convention;
        if (profile == L"includes-header") convention = catalog::KeybagLength::IncludesHeader;
        else if (profile == L"entries-only") convention = catalog::KeybagLength::EntriesOnly;
        else throw PublicFailure{"UnsupportedBagLengthProfile",2};
        catalog::UnlockError error;
        auto metadata = catalog::InspectPasswordKeybagMetadata(*source,Number(get(L"--volume-oid")),convention,error);
        if (!metadata)
        {
            operation.Status(std::string("{\"state\":\"Locked\",\"unlockError\":\"")+UnlockError(error)+"\"}\n");
            return 5;
        }
        if (!source->VerifyUnchanged()) throw PublicFailure{"SourceIdentityMismatch",3};
        const auto& r = metadata->selection;
        std::ostringstream output;
        output << "{\"mode\":\"locked-keybag-selectors\",\"state\":\"Locked\",\"sourceId\":\"" << source->SourceIdentity()
            << "\",\"storeOffset\":" << store_offset << ",\"storeSize\":" << store_size
            << ",\"containerUuid\":\"" << catalog::BytesToHexLower(r.container_uuid.data(),16)
            << "\",\"volumeUuid\":\"" << catalog::BytesToHexLower(r.volume_uuid.data(),16)
            << "\",\"volumeOid\":" << r.volume_oid << ",\"checkpointXid\":" << r.checkpoint_xid
            << ",\"containerBagOid\":" << r.container_bag.oid << ",\"containerBagXid\":" << r.container_bag.xid
            << ",\"volumeBagOid\":" << r.volume_bag.oid << ",\"volumeBagXid\":" << r.volume_bag.xid
            << ",\"bagLength\":\"" << Ascii(profile) << "\",\"users\":[";
        for (std::size_t i=0;i<metadata->users.size();++i)
        {
            if (i) output << ',';
            output << '"' << catalog::BytesToHexLower(metadata->users[i].data(),16) << '"';
        }
        output << "],\"persistentUnlockedMount\":false,\"writeAuthorization\":false}\n";
        operation.Output(output.str());
        return 0;
    }
    const auto expected_source = Ascii(get(L"--source-id"));
    if (expected_source != source->SourceIdentity()) throw PublicFailure{"SourceIdentityMismatch",3};
    catalog::PasswordUnlockRequest request;
    request.container_uuid = Uuid(get(L"--container-uuid")); request.volume_uuid = Uuid(get(L"--volume-uuid"));
    request.user_uuid = Uuid(get(L"--user-uuid")); request.volume_oid = Number(get(L"--volume-oid"));
    request.checkpoint_xid = Number(get(L"--checkpoint-xid"));
    request.container_bag = {Number(get(L"--container-bag-oid")), Number(get(L"--container-bag-xid"))};
    request.volume_bag = {Number(get(L"--volume-bag-oid")), Number(get(L"--volume-bag-xid"))};
    const auto length_profile = get(L"--bag-length");
    if (length_profile == L"includes-header") request.length = catalog::KeybagLength::IncludesHeader;
    else if (length_profile == L"entries-only") request.length = catalog::KeybagLength::EntriesOnly;
    else throw PublicFailure{"UnsupportedBagLengthProfile",2};
    std::uint64_t inode = 0, offset = 0, length = 0;
    std::string xattr;
    if (mode == L"read" || mode == L"metadata" || mode == L"xattr")
    {
        inode = Number(get(L"--inode"));
        if (!inode) throw PublicFailure{"InvalidReadRange",2};
    }
    if (mode == L"xattr") xattr = Ascii(get(L"--xattr"));
    if (mode == L"read")
    {
        offset = Number(get(L"--offset")); length = Number(get(L"--length"));
        if (!inode || length > crypto::SecureBytes::kMaxBytes) throw PublicFailure{"InvalidReadRange",2};
    }
    if (bytes_output)
    {
        const auto type = GetFileType(GetStdHandle(STD_OUTPUT_HANDLE));
        if (type != FILE_TYPE_PIPE && type != FILE_TYPE_DISK) throw PublicFailure{"RedirectedBinaryOutputRequired",2};
    }
    // Ready is public and means the actual lease is already held; no unlock claim.
    { std::ostringstream status; status << "{\"state\":\"Locked\",\"phase\":\"AwaitingCredential\",\"leaseHeld\":true}\n"; operation.Status(status.str()); }
    HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    SetStdHandle(STD_INPUT_HANDLE, nullptr);
    auto credential = transport::ReceiveCredential(input,std::chrono::milliseconds(receive_ms),*cancellation);
    if (!credential) throw PublicFailure{transport::CredentialErrorName(credential.error),
        credential.error == transport::CredentialError::Cancelled ? 6 : 4};
    catalog::PasswordUnlockBudget attempts;
    catalog::EncryptedReadError error; catalog::UnlockError unlock_error;
    { std::ostringstream status; status << "{\"state\":\"Unlocking\"}\n"; operation.Status(status.str()); }
    auto session = catalog::ApfsEncryptedReadSession::Unlock(source,expected_source,source->Revision(),request,
        credential.bytes.Bytes(),attempts,error,unlock_error,cancellation);
    credential.bytes.Clear();
    if (!session)
    {
        { std::ostringstream status; status << "{\"state\":\"Locked\",\"readError\":\"" << ReadError(error)
            << "\",\"unlockError\":\"" << UnlockError(unlock_error) << "\"}\n"; operation.Status(status.str()); }
        return error == catalog::EncryptedReadError::Cancelled ? 6 : 5;
    }
    Plaintext plaintext;
    std::vector<catalog::EncryptedFileInfo> files;
    catalog::EncryptedNodeInfo metadata;
    if (mode == L"read") error = session->ReadFile(inode,offset,static_cast<std::size_t>(length),plaintext.bytes);
    else if (mode == L"xattr") error = session->ReadXattr(inode,xattr,plaintext.bytes);
    else if (mode == L"metadata") error = session->GetMetadata(inode,metadata);
    else error = session->ListFiles(files);
    session->Close(); session.reset(); // VEK closes before any success plaintext publication.
    if (error != catalog::EncryptedReadError::None) throw PublicFailure{ReadError(error),error == catalog::EncryptedReadError::Cancelled ? 6 : 7};
    if (cancellation->load()) throw PublicFailure{"Cancelled",6};
    if (!source->VerifyUnchanged()) throw PublicFailure{"SourceIdentityMismatch",3};
    if (mode == L"inspect")
    {
        std::ostringstream output;
        output << "{\"mode\":\"inode-metadata\",\"persistentUnlockedMount\":false,\"files\":[";
        bool first = true;
        for (const auto& file : files) {
            if (!first) output << ','; first = false;
            output << "{\"inode\":\"" << file.inode_id << "\",\"size\":\"" << file.size
                << "\",\"defaultCryptoId\":\"" << file.default_crypto_id << "\"}";
        }
        output << "]}\n";
        operation.Output(output.str());
    }
    else if (mode == L"metadata")
    {
        std::ostringstream output;
        output << "{\"mode\":\"node-metadata\",\"inode\":" << metadata.inode_id << ",\"parent\":" << metadata.parent_id
            << ",\"posixMode\":" << metadata.mode << ",\"size\":" << metadata.size << ",\"internalFlags\":" << metadata.internal_flags
            << ",\"persistentUnlockedMount\":false,\"writeAuthorization\":false,\"symlinkFollowed\":false}\n";
        operation.Output(output.str());
    }
    else
    {
        operation.Output(GetStdHandle(STD_OUTPUT_HANDLE),plaintext.bytes.data(),plaintext.bytes.size());
    }
    source.reset();
    { std::ostringstream status; status << "{\"state\":\"Locked\",\"phase\":\"Closed\",\"leaseHeld\":false,\"output\":\""
        << (mode == L"read" ? "binary-file-data" : mode == L"xattr" ? "embedded-xattr-data" : "inode-metadata") << "\"}\n"; operation.Status(status.str()); }
    if (cancellation->load()) throw PublicFailure{"Cancelled",6};
    return 0;
}
}
int wmain(int argc, wchar_t** argv)
{
    SetConsoleCtrlHandler(Control,TRUE);
    try {
        Operation operation;
        try { return Run(argc,argv,operation); }
        catch (const PublicFailure& error) {
            operation.Status(std::string("{\"state\":\"Locked\",\"error\":\"") + error.name + "\",\"leaseHeld\":false}\n");
            return error.exit;
        }
        catch (...) { operation.Status("{\"state\":\"Locked\",\"error\":\"InternalFailure\",\"leaseHeld\":false}\n"); return 9; }
    }
    catch (...) { return 9; } // Setup failed: do not risk an unmonitored diagnostic write.
}
