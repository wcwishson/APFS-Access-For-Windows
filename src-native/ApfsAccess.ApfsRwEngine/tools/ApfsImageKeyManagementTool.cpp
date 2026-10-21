#include "MaintenanceCredentialTransport.h"
#include "KeyManagementProcessLease.h"
#include "KeyManagementImageOpenRetry.h"
#include <map>
#include <set>
#include <sstream>

using namespace apfsaccess;
namespace
{
struct Refusal {};
int public_stage = 2;
void Require(bool value) { if (!value) throw Refusal{}; }
std::uint64_t Number(const std::wstring& value)
{
    Require(!value.empty() && (value.size() == 1 || value.front() != L'0'));
    std::uint64_t number = 0;
    for (const auto c : value) {
        Require(c >= L'0' && c <= L'9' && number <= (UINT64_MAX - (c - L'0')) / 10);
        number = number * 10 + c - L'0';
    }
    return number;
}
std::string Ascii(const std::wstring& value)
{
    Require(value.size() < 4096); std::string result;
    for (const auto c : value) { Require(c >= 32 && c <= 126); result.push_back(static_cast<char>(c)); }
    return result;
}
std::string Utf8(const std::wstring& value)
{
    Require(!value.empty() && value.size() < 32768);
    const auto n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    Require(n > 0); std::string result(static_cast<std::size_t>(n), '\0');
    Require(WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), result.data(), n, nullptr, nullptr) == n);
    return result;
}
std::string Quote(std::string_view text)
{
    std::string result = "\"";
    constexpr char hex[] = "0123456789abcdef";
    for (const unsigned char c : text) {
        if (c == '"' || c == '\\') { result += '\\'; result += static_cast<char>(c); }
        else if (c < 32) { result += "\\u00"; result += hex[c >> 4]; result += hex[c & 15]; }
        else result += static_cast<char>(c);
    }
    return result + '"';
}
std::string Hex(const catalog::KeybagUuid& id)
{
    constexpr char alphabet[] = "0123456789abcdef"; std::string result;
    for (const auto b : id) { const auto v = std::to_integer<unsigned>(b); result += alphabet[v >> 4]; result += alphabet[v & 15]; }
    return result;
}
catalog::KeybagUuid Uuid(const std::wstring& text)
{
    Require(text.size() == 32 && text.find_first_not_of(L"0123456789abcdef") == text.npos);
    catalog::KeybagUuid id{};
    const auto digit = [](wchar_t c) { return c <= L'9' ? c - L'0' : c - L'a' + 10; };
    for (std::size_t i = 0; i < id.size(); ++i) id[i] = std::byte((digit(text[i * 2]) << 4) | digit(text[i * 2 + 1]));
    Require(std::any_of(id.begin(), id.end(), [](auto b) { return b != std::byte{}; })); return id;
}
std::string Dashed(const std::string& id)
{
    Require(id.size() == 32);
    return id.substr(0, 8) + '-' + id.substr(8, 4) + '-' + id.substr(12, 4) + '-' + id.substr(16, 4) + '-' + id.substr(20);
}
bool SameSelection(const std::optional<catalog::PasswordUnlockRequest>& a,
    const std::optional<catalog::PasswordUnlockRequest>& b)
{
    if (a.has_value() != b.has_value()) return false;
    if (!a) return true;
    return a->checkpoint_xid == b->checkpoint_xid && a->volume_oid == b->volume_oid &&
        a->container_uuid == b->container_uuid && a->volume_uuid == b->volume_uuid && a->user_uuid == b->user_uuid &&
        a->container_bag.oid == b->container_bag.oid && a->container_bag.xid == b->container_bag.xid &&
        a->volume_bag.oid == b->volume_bag.oid && a->volume_bag.xid == b->volume_bag.xid && a->length == b->length;
}
bool SameEndpoint(const catalog::ImageKeyManagementEndpoint& a, const catalog::ImageKeyManagementEndpoint& b)
{
    return a.source_identity == b.source_identity && a.container_uuid == b.container_uuid && a.volume_uuid == b.volume_uuid &&
        a.volume_object_id == b.volume_object_id && a.checkpoint_xid == b.checkpoint_xid && a.mode == b.mode &&
        SameSelection(a.encrypted_selection, b.encrypted_selection);
}
std::string Endpoint(const catalog::ImageKeyManagementEndpoint& value,
    const catalog::EncryptedImageRuntime::Options& options)
{
    std::ostringstream out;
    out << "{\"imagePath\":" << Quote(Utf8(options.image.path)) << ",\"sourceId\":" << Quote(value.source_identity)
        << ",\"storeOffset\":" << options.image.offset << ",\"storeSize\":" << options.image.bytes
        << ",\"containerUuid\":" << Quote(Dashed(value.container_uuid)) << ",\"volumeUuid\":" << Quote(Dashed(value.volume_uuid))
        << ",\"volumeObjectId\":" << value.volume_object_id << ",\"checkpointXid\":" << value.checkpoint_xid
        << ",\"mode\":" << Quote(value.mode == catalog::SoftwareVolumeMode::Plain ? "Plain" : "SoftwareOneKeyGenerationZero")
        << ",\"keybag\":";
    if (!value.encrypted_selection) out << "null";
    else {
        const auto& bag = *value.encrypted_selection;
        out << "{\"containerBagOid\":" << bag.container_bag.oid << ",\"containerBagXid\":" << bag.container_bag.xid
            << ",\"volumeBagOid\":" << bag.volume_bag.oid << ",\"volumeBagXid\":" << bag.volume_bag.xid
            << ",\"userUuid\":" << Quote(Dashed(Hex(bag.user_uuid))) << ",\"bagLength\":"
            << Quote(bag.length == catalog::KeybagLength::IncludesHeader ? "includes-header" : "entries-only") << '}';
    }
    return out.str() + '}';
}
bool Clean(const catalog::EncryptedImageRuntime& runtime)
{
    const auto status = runtime.CachedStatus();
    return runtime.CachedPersistenceStateValid() && !status.recovery_required && !status.image.recovery_required &&
        status.accepted == status.durable && status.accepted == status.cleaned;
}
int Run(int argc, wchar_t** argv)
{
    std::map<std::wstring, std::wstring> args;
    const std::set<std::wstring> allowed{L"--action", L"--operation-id", L"--image", L"--source-id", L"--store-offset", L"--store-size",
        L"--container-uuid", L"--volume-uuid", L"--volume-oid", L"--checkpoint-xid", L"--container-bag-oid", L"--container-bag-xid",
        L"--volume-bag-oid", L"--volume-bag-xid", L"--user-uuid", L"--bag-length", L"--recovery-directory",
        L"--parent-pid", L"--lifetime-file", L"--startup-gate-file", L"--startup-gate-token", L"--receipt-file"};
    for (int i = 1; i < argc; ++i) {
        const std::wstring name(argv[i]); Require(allowed.contains(name) && i + 1 < argc && !args.contains(name));
        args.emplace(name, argv[++i]);
    }
    const auto get = [&](const wchar_t* name) -> const std::wstring& { const auto found = args.find(name); Require(found != args.end()); return found->second; };
    const auto action = Ascii(get(L"--action")), operation = Ascii(get(L"--operation-id"));
    const bool observe = action == "Observe";
    Require(observe || action == "ChangePassword" || action == "RotateVolumeKey" || action == "Encrypt" || action == "Decrypt");
    Require(operation.size() == 36 && operation[8] == '-' && operation[13] == '-' && operation[18] == '-' && operation[23] == '-');
    auto compact = operation; compact.erase(std::remove(compact.begin(), compact.end(), '-'), compact.end());
    (void)Uuid(std::wstring(compact.begin(), compact.end()));
    catalog::EncryptedImageRuntime::Options options;
    options.image.path = get(L"--image"); options.image.offset = Number(get(L"--store-offset")); options.image.bytes = Number(get(L"--store-size"));
    options.image.volume_oid = Number(get(L"--volume-oid")); options.recovery_directory = get(L"--recovery-directory");
    catalog::ImageKeyManagementEndpoint expected;
    expected.source_identity = Ascii(get(L"--source-id")); expected.container_uuid = Hex(Uuid(get(L"--container-uuid")));
    expected.volume_uuid = Hex(Uuid(get(L"--volume-uuid"))); expected.volume_object_id = options.image.volume_oid;
    expected.checkpoint_xid = Number(get(L"--checkpoint-xid"));
    Require(expected.checkpoint_xid && options.image.volume_oid && options.image.bytes && !expected.source_identity.empty());
    expected.mode = action == "Encrypt" || (observe && !args.contains(L"--container-bag-oid"))
        ? catalog::SoftwareVolumeMode::Plain : catalog::SoftwareVolumeMode::OneKeyGenerationZero;
    if (expected.mode != catalog::SoftwareVolumeMode::Plain) {
        catalog::PasswordUnlockRequest bag;
        bag.checkpoint_xid = expected.checkpoint_xid; bag.volume_oid = expected.volume_object_id;
        bag.container_uuid = Uuid(get(L"--container-uuid")); bag.volume_uuid = Uuid(get(L"--volume-uuid")); bag.user_uuid = Uuid(get(L"--user-uuid"));
        bag.container_bag = {Number(get(L"--container-bag-oid")), Number(get(L"--container-bag-xid"))};
        bag.volume_bag = {Number(get(L"--volume-bag-oid")), Number(get(L"--volume-bag-xid"))};
        const auto length = get(L"--bag-length"); Require(length == L"includes-header" || length == L"entries-only");
        bag.length = length == L"includes-header" ? catalog::KeybagLength::IncludesHeader : catalog::KeybagLength::EntriesOnly;
        options.image.keybag_length = bag.length; expected.encrypted_selection = bag;
    } else {
        for (const auto name : {L"--container-bag-oid", L"--container-bag-xid", L"--volume-bag-oid", L"--volume-bag-xid", L"--user-uuid", L"--bag-length"})
            Require(!args.contains(name));
    }
    const auto pid = Number(get(L"--parent-pid")); Require(pid && pid <= MAXDWORD);
    public_stage = 11;
    transport::KeyManagementProcessLease supervisor(static_cast<DWORD>(pid), get(L"--lifetime-file"), get(L"--startup-gate-file"),
        Ascii(get(L"--startup-gate-token")), get(L"--receipt-file"));
    if (observe) {
        public_stage = 13;
        std::string error;
        const auto require_observation = [&](bool valid, std::string_view detail) {
            if (valid) return;
            FILETIME creation{}, exit{}, kernel{}, user{};
            if (GetProcessTimes(GetCurrentProcess(), &creation, &exit, &kernel, &user)) {
                std::ostringstream failure;
                failure << "{\"schemaVersion\":1,\"hostPid\":" << GetCurrentProcessId()
                    << ",\"hostCreationTimeFileTimeUtc\":" << ((std::uint64_t(creation.dwHighDateTime) << 32) | creation.dwLowDateTime)
                    << ",\"observationId\":" << Quote(operation) << ",\"nativeExitStage\":" << public_stage
                    << ",\"refused\":true,\"errorCode\":" << Quote(std::string(detail.substr(0, 4096))) << "}\n";
                supervisor.Receipt(failure.str());
            }
            Require(false);
        };
        // Observe has no credential input. Preserve its bounded native refusal
        // through the already held receipt lease, without inventing success.
        auto runtime = transport::OpenKeyManagementImageRuntime(options, supervisor.cancelled, error);
        require_observation(static_cast<bool>(runtime), error.empty() ? "ObserveRuntimeOpenFailed" : error);
        struct DetachObservation { transport::KeyManagementProcessLease& supervisor; ~DetachObservation() { supervisor.Attach(nullptr); } } detach{supervisor};
        supervisor.Attach(runtime.get());
        require_observation(runtime->SourceIdentity() == expected.source_identity && runtime->ContainerUuid() == expected.container_uuid &&
            runtime->VolumeUuid() == expected.volume_uuid && runtime->VolumeObjectId() == expected.volume_object_id, "ObserveSourceSelectorsMismatch");
        public_stage = 14;
        const auto recovered = runtime->Recover(error);
        require_observation(recovered, error.empty() ? "ObserveRuntimeRecoveryFailed" : error);
        catalog::ImageKeyManagementEndpoint endpoint;
        public_stage = 15;
        const auto observed = runtime->ObserveKeyManagementEndpoint(endpoint, error);
        require_observation(observed, error.empty() ? "ObserveEndpointFailed" : error);
        require_observation(Clean(*runtime) &&
            endpoint.source_identity == expected.source_identity && endpoint.container_uuid == expected.container_uuid &&
            endpoint.volume_uuid == expected.volume_uuid && endpoint.volume_object_id == expected.volume_object_id &&
            endpoint.checkpoint_xid >= expected.checkpoint_xid, "ObserveCleanEndpointSelectorsMismatch");
        runtime->Lock(); const auto status = runtime->CachedStatus(); runtime->Close();
        Require(runtime->CachedStatus().closed && !runtime->CachedStatus().image.key_present && !runtime->UnlockedSelection());
        supervisor.Attach(nullptr);
        FILETIME creation{}, exit{}, kernel{}, user{}; Require(GetProcessTimes(GetCurrentProcess(), &creation, &exit, &kernel, &user));
        std::ostringstream receipt;
        receipt << "{\"schemaVersion\":1,\"hostPid\":" << GetCurrentProcessId() << ",\"hostCreationTimeFileTimeUtc\":"
            << ((std::uint64_t(creation.dwHighDateTime) << 32) | creation.dwLowDateTime) << ",\"observationId\":" << Quote(operation)
            << ",\"endpoint\":" << Endpoint(endpoint, options) << ",\"acceptedSequence\":" << status.accepted
            << ",\"durableSequence\":" << status.durable << ",\"cleanedSequence\":" << status.cleaned << ",\"ownerClosed\":true}\n";
        public_stage = 20; supervisor.Receipt(receipt.str()); return 0;
    }
    const auto count = action == "ChangePassword" || action == "RotateVolumeKey" ? std::size_t{2} : std::size_t{1};
    public_stage = 12;
    auto credentials = transport::ReceiveCredentials(GetStdHandle(STD_INPUT_HANDLE), count, std::chrono::seconds(5), supervisor.cancelled);
    Require(static_cast<bool>(credentials) && !supervisor.cancelled.load());
    std::string error;
    public_stage = 13;
    auto runtime = transport::OpenKeyManagementImageRuntime(options, supervisor.cancelled, error); Require(static_cast<bool>(runtime));
    struct Detach { transport::KeyManagementProcessLease& supervisor; ~Detach() { supervisor.Attach(nullptr); } } detach{supervisor};
    supervisor.Attach(runtime.get());
    Require(runtime->SourceIdentity() == expected.source_identity && runtime->ContainerUuid() == expected.container_uuid &&
        runtime->VolumeUuid() == expected.volume_uuid && runtime->VolumeObjectId() == expected.volume_object_id);
    // Recovery is rooted in the same held image and authenticated original history.
    catalog::PasswordUnlockBudget budget;
    public_stage = 14;
    if (expected.mode != catalog::SoftwareVolumeMode::Plain)
        Require(runtime->Unlock(credentials.credentials[0], budget, error));
    else Require(runtime->Recover(error));
    catalog::ImageKeyManagementEndpoint before;
    public_stage = 15;
    Require(runtime->ObserveKeyManagementEndpoint(before, error) && SameEndpoint(before, expected));
    // One budget covers the whole exchange, including the final new-key read check.
    std::this_thread::sleep_for(std::chrono::milliseconds(250));
    public_stage = 16;
    bool published = false;
    if (action == "ChangePassword") published = runtime->ChangePassword(credentials.credentials[0], credentials.credentials[1], budget, error);
    else if (action == "RotateVolumeKey") published = runtime->RotateVolumeKey(credentials.credentials[0], credentials.credentials[1], budget, error);
    else if (action == "Encrypt") published = runtime->Encrypt(credentials.credentials[0], budget, error);
    else published = runtime->Decrypt(credentials.credentials[0], budget, error);
    Require(published && Clean(*runtime));
    public_stage = 17;
    catalog::ImageKeyManagementEndpoint after;
    Require(runtime->ObserveKeyManagementEndpoint(after, error) && after.checkpoint_xid == before.checkpoint_xid + 1 &&
        after.source_identity == before.source_identity && after.container_uuid == before.container_uuid &&
        after.volume_uuid == before.volume_uuid && after.volume_object_id == before.volume_object_id &&
        after.mode == (action == "Decrypt" ? catalog::SoftwareVolumeMode::Plain : catalog::SoftwareVolumeMode::OneKeyGenerationZero));
    public_stage = 18;
    if (after.mode != catalog::SoftwareVolumeMode::Plain) {
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
        Require(runtime->Unlock(credentials.credentials[count - 1], budget, error) &&
            SameSelection(runtime->UnlockedSelection(), after.encrypted_selection));
    }
    public_stage = 19;
    for (auto& credential : credentials.credentials) credential.Clear();
    runtime->Lock(); Require(Clean(*runtime) && !runtime->CachedStatus().image.key_present && !runtime->UnlockedSelection());
    const auto status = runtime->CachedStatus(); runtime->Close();
    Require(runtime->CachedStatus().closed && !runtime->CachedStatus().image.key_present);
    supervisor.Attach(nullptr);
    FILETIME creation{}, exit{}, kernel{}, user{}; Require(GetProcessTimes(GetCurrentProcess(), &creation, &exit, &kernel, &user));
    std::ostringstream receipt;
    receipt << "{\"schemaVersion\":1,\"hostPid\":" << GetCurrentProcessId() << ",\"hostCreationTimeFileTimeUtc\":"
        << ((std::uint64_t(creation.dwHighDateTime) << 32) | creation.dwLowDateTime) << ",\"receipt\":{\"operationId\":" << Quote(operation)
        << ",\"action\":" << Quote(action) << ",\"before\":" << Endpoint(before, options) << ",\"after\":" << Endpoint(after, options)
        << ",\"acceptedSequence\":" << status.accepted << ",\"durableSequence\":" << status.durable << ",\"cleanedSequence\":" << status.cleaned
        << ",\"keyRevoked\":true,\"ownerClosed\":true}}\n";
    public_stage = 20;
    supervisor.Receipt(receipt.str()); return 0;
}
}
int wmain(int argc, wchar_t** argv)
{
    try { return Run(argc, argv); }
    catch (...) { return public_stage; } // Fixed public stage only; never print exception or credential text.
}
