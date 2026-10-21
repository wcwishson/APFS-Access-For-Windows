#define APFSACCESS_FSHOST_UNIT_TEST 1
#include "../src/main.cpp"

namespace
{
unsigned assertions = 0;
void Require(bool value)
{
    ++assertions;
    if (!value) throw std::runtime_error("EncryptedWriterStatusAssertion:" + std::to_string(assertions));
}
std::string ReadStatus(const MountContext& context)
{
    std::ifstream input(context.args.status_file, std::ios::binary);
    Require(bool(input));
    return {std::istreambuf_iterator<char>(input), {}};
}
void Record(const MountContext& context, const wchar_t* label)
{
    const auto target = context.args.status_file + L"." + label + L".json";
    Require(CopyFileW(context.args.status_file.c_str(), target.c_str(), TRUE));
}
void StartupDiagnosticsCases()
{
    Require(std::string_view(ClosedEncryptedStartupStage(nullptr)) == "Unknown");
    Require(std::string_view(ClosedEncryptedStartupStage("not-a-stage:credential/source")) == "Unknown");
    for (const auto* stage : {"Namespace", "NamePolicy", "ExactKeybagSelection", "InvalidFrame"})
        Require(std::string_view(ClosedEncryptedStartupStage(stage)) == stage);
    const auto directory = std::filesystem::temp_directory_path() /
        (L"startup-stages-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64()));
    Require(directory.native().starts_with(L"D:\\") || directory.native().starts_with(L"d:\\"));
    std::filesystem::create_directory(directory);
    for (bool writable : {false, true}) {
        MountContext context;
        context.args.encrypted.enabled = true;
        context.args.readonly = !writable;
        if (writable) context.args.encrypted.write_root = L"D:\\not-used";
        context.args.status_file = (directory / (writable ? L"write.json" : L"read.json")).wstring();
        // Both real preparations refuse at Arguments, before source/credential I/O.
        Require(!PrepareEncryptedMountWithDiagnostic(context, nullptr));
        Require(!context.encrypted);
        Require(std::string_view(context.encrypted_startup_failure_stage) == "Arguments");
        Require(WriteTerminalMountNotReadyStatusFile(context));
        const auto json = ReadStatus(context);
        Require(json.find("\"encryptedStartupFailureStage\":\"Arguments\"") != json.npos);
        Require(json.find("\"mountReady\":false") != json.npos);
        Require(json.find("\"encryptedSourceId\":null") != json.npos);
        Require(json.find("not-a-stage:credential/source") == json.npos);
    }
}
void Fields(const MountContext& context, std::uint64_t selection, std::uint64_t current, std::string_view health)
{
    const auto json = ReadStatus(context);
    const auto& writer = *context.encrypted->writer;
    const auto field = [&](std::string_view key, const std::string& value) {
        const auto exact = "\"" + std::string(key) + "\":" + value;
        const auto at = json.find(exact);
        Require(at != json.npos && at + exact.size() < json.size() &&
            (json[at + exact.size()] == ',' || json[at + exact.size()] == '}') &&
            json.find("\"" + std::string(key) + "\":", at + exact.size()) == json.npos);
    };
    field("encryptedSourceId", "\"" + EscapeJson(writer.SourceIdentity()) + "\"");
    field("encryptedContainerUuid", "\"" + writer.ContainerUuid() + "\"");
    field("encryptedVolumeUuid", "\"" + writer.VolumeUuid() + "\"");
    field("encryptedVolumeOid", std::to_string(writer.VolumeObjectId()));
    field("encryptedSelectionCheckpointXid", std::to_string(selection));
    field("encryptedCheckpointXid", std::to_string(current));
    field("encryptedHealth", "\"" + std::string(health) + "\"");
}
}

int wmain(int argc, wchar_t** argv)
{
    try {
        if (argc == 2 && std::wstring_view(argv[1]) == L"--startup-diagnostics") {
            StartupDiagnosticsCases();
            std::cout << "PASS " << assertions << " assertions; real readonly/writable preparation refusal stages, closed diagnostics\n";
            return 0;
        }
        Require(argc == 4);
        MountContext context;
        context.args.encrypted.enabled = true;
        context.args.encrypted.write_root = argv[2];
        context.args.status_file = argv[3];
        context.args.readonly = false;
        context.encrypted = std::make_unique<encrypted_mount::State>();
        auto& state = *context.encrypted;
        using namespace apfsaccess::catalog;
        EncryptedImageRuntime::Options options;
        options.image = {argv[1], 20480, 4153344, 1026};
        options.recovery_directory = argv[2];
        std::string error;
        state.writer = EncryptedImageRuntime::Open(options, error);
        if (!state.writer) throw std::runtime_error(error);
        auto credential = apfsaccess::transport::ReceiveCredential(GetStdHandle(STD_INPUT_HANDLE),
            std::chrono::milliseconds(5000), *state.cancelled);
        Require(bool(credential));
        PasswordUnlockBudget budget;
        const auto unlocked = state.writer->Unlock(credential.bytes, budget, error);
        credential.bytes.Clear();
        if (!unlocked) throw std::runtime_error(error);
        const auto admitted = state.writer->UnlockedSelection();
        Require(admitted.has_value());
        const auto selected_xid = admitted->checkpoint_xid;
        context.args.encrypted.checkpoint = selected_xid;
        // Mutable-looking CLI identity strings must not become status authority.
        context.args.encrypted.source_id = L"not-the-held-owner";
        context.args.container_id = std::wstring(32, L'f');
        context.args.encrypted.volume_uuid = std::wstring(32, L'e');
        context.args.volume_object_id = 999;
        context.mount_ready = true;
        Require(WriteHostStatusFile(context));
        Fields(context, selected_xid, selected_xid, "ReadWrite");
        Record(context, L"ready");
        const auto initial = ReadStatus(context);

        std::atomic<bool> entered{false}, release{false}, published{false}, status_done{false};
        std::string apply_error;
        std::uint64_t inode = 0;
        EncryptedMutationRequest request;
        request.kind = EncryptedMutationKind::Create;
        request.parent = 2;
        request.name = "writer-status-review";
        std::jthread write([&] {
            published = state.writer->Apply(request, inode, apply_error, [&](std::string_view stage) {
                if (stage == "before-encrypted-private-prepare") {
                    entered = true;
                    while (!release.load()) Sleep(1);
                }
                return true;
            });
        });
        ScopeExit release_write{[&] { release = true; if (write.joinable()) write.join(); }};
        auto deadline = GetTickCount64() + 5000;
        while (!entered.load() && GetTickCount64() < deadline) Sleep(1);
        Require(entered.load());
        std::unique_lock callbacks(state.callbacks);
        std::jthread status([&] { status_done = WriteHostStatusFile(context); });
        deadline = GetTickCount64() + 1000;
        while (!status_done.load() && GetTickCount64() < deadline) Sleep(1);
        const bool completed_under_gate = status_done.load();
        if (completed_under_gate) Record(context, L"held");
        callbacks.unlock();
        release = true;
        status.join(); write.join();
        Require(completed_under_gate);
        if (!published.load()) throw std::runtime_error(apply_error);
        Require(inode > 2);
        const auto current = state.writer->CachedStatus();
        Require(current.image.checkpoint_xid > selected_xid);
        Require(current.accepted == current.durable && current.durable == current.cleaned);
        Require(WriteHostStatusFile(context));
        Fields(context, selected_xid, current.image.checkpoint_xid, "ReadWrite");
        Record(context, L"published");
        // Force a stale cached JSON control: terminal must rebuild owner state.
        context.last_status_write_contents = initial;
        state.Close();
        Require(!state.failed.load());
        Require(WriteTerminalMountNotReadyStatusFile(context));
        Fields(context, selected_xid, current.image.checkpoint_xid, "StoppingReadWrite");
        Require(ReadStatus(context).find("\"mountReady\":false") != std::string::npos);
        Record(context, L"terminal");
        state.Fail(encrypted_mount::State::Failure::PendingDeleteAtClose);
        Require(WriteTerminalMountNotReadyStatusFile(context));
        Fields(context, selected_xid, current.image.checkpoint_xid, "FailedReadWrite");
        Require(ReadStatus(context).find("\"encryptedFailureReason\":\"PendingDeleteAtClose\"") != std::string::npos);
        std::cout << "PASS " << assertions << " assertions; one canonical publication; status completed under held Runtime/callback gates\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n'; return 1;
    }
}
