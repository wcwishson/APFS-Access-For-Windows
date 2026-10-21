// Actual host control handlers and canonical image engine; no WinFsp mount.
#define APFSACCESS_FSHOST_UNIT_TEST 1
#include "../src/main.cpp"
namespace { using BtreeRecord = apfsaccess::catalog::BtreeRecord; }
#define SNAPSHOT_RUNTIME_TEST_HELPERS_ONLY
#include "SnapshotRuntimeTests.cpp"
#include <future>

namespace {
struct HostSnapshots
{
    std::unique_ptr<Owner> owner;
    std::vector<std::unique_ptr<MountContext>> contexts;
    HostSnapshots(const std::string& image, bool enabled = true, bool census = true,
        bool production_storage = false, bool replay_if_safe = false, std::uint64_t base = 0)
    {
        std::string error;
        owner = Owner::Open(std::filesystem::absolute(image).string(), base, error,
            CatalogLoadPolicy::StrictApple, true, true);
        Check(!!owner, "host owner: " + error);
        if (production_storage)
        {
            Check(_wputenv_s(L"APFSACCESS_RECOVERY_ROOT", std::filesystem::absolute(image + ".recovery").c_str()) == 0,
                "private production marker root");
            Check(_wputenv_s(L"APFSACCESS_SPOOL_ROOT", std::filesystem::absolute(image + ".spool").c_str()) == 0,
                "private production spool root");
        }
        for (auto oid : {101ull, 102ull})
        {
            auto context = std::make_unique<MountContext>();
            auto& c = *context;
            c.args.device = std::filesystem::absolute(image).wstring();
            c.args.device_offset_bytes = base;
            c.args.container_id = Utf8ToWide(owner->ContainerUuidHex());
            c.args.recovery_identity = L"apfs-vol:" + c.args.container_id + L":" + std::to_wstring(oid);
            c.args.volume_object_id = oid;
            c.args.volume = L"Data";
            c.args.container_manifest = L"test-manifest";
            c.args.readwrite = true;
            c.args.write_backend = L"Native";
            c.args.allow_legacy_scaffold_for_fixtures = false;
            c.args.enable_image_snapshots = enabled;
            c.native_write_enabled = true;
            if (production_storage)
            {
                c.args.recovery_identity = L"apfs-recovery-v1-" + std::wstring(42, oid == 101 ? L'A' : L'B') + L"A";
                c.args.write_crash_replay_mode = replay_if_safe ? L"ReplayIfSafe" : L"FailClosed";
                c.recovery_marker_file = BuildRecoveryMarkerPath(c.args);
                (void)LoadRecoveryMarkerAtStartup(c);
            }
            c.tx_journal_file = std::filesystem::absolute(image + "." + std::to_string(oid) + ".wal");
            const auto spool_root = production_storage ? BuildPayloadSpoolSessionRoot(c.args,
                apfsaccess::rw::PayloadSpool::ResolveDefaultRoot()) : std::filesystem::path{};
            if (production_storage) c.tx_journal_file = spool_root / "write-ahead.wal";
            c.tx_manager = std::make_unique<Tx>(L"Strict");
            c.tx_manager->SetJournalPath(c.tx_journal_file.wstring());
            c.tx_manager->SetVolumeIdentity(c.args.recovery_identity);
            if (production_storage)
                Check(c.tx_manager->EnrollCanonicalJournalIdentity(L"apfs-vol:" + c.args.container_id + L":" + std::to_wstring(oid)),
                    "original configured journal canonical enrollment");
            Check(c.tx_manager->AcquireJournalOwnership(error), "journal lease: " + error);
            if (production_storage)
            {
                const auto marks = c.tx_manager->Watermarks();
                Check(ArmRecoveryMarkerForPendingWriteAheadLog(c, !c.tx_manager->RecoveryStateValid() ||
                    c.tx_manager->HasUnappliedAcceptedWork() || marks.cleanup_sequence < marks.apfs_durable_sequence), "production WAL marker arm");
                c.payload_spool_volume_identity = WideToUtf8(c.args.recovery_identity);
                c.payload_spool = std::make_unique<apfsaccess::rw::PayloadSpool>(apfsaccess::rw::PayloadSpool::Options{
                    spool_root, c.payload_spool_volume_identity, kPayloadSpoolMaxBytes,
                    kPayloadSpoolForegroundFlushBytes, kPayloadSpoolForegroundFlushAppends});
            }
            std::wstring mount_error;
            Check(MountManifestSession(*owner, c.args, c, mount_error), "host session: " + WideToUtf8(mount_error));
            contexts.push_back(std::move(context));
        }
        if (census) Check(InitializeManifestCheckpointCensus(*owner, contexts, error), "host census: " + error);
        if (production_storage && census)
        {
            for (auto& context : contexts)
            {
                auto& c = *context;
                Check(c.metadata_store->IsNativeWriteReady(), "production manifest metadata write bootstrap");
                c.runtime_last_commit_xid = ResolveCleanRecoveryCheckpointXid(*c.metadata_store);
                const auto marks = c.tx_manager->Watermarks();
                bool pending = !c.tx_manager->RecoveryStateValid() || c.tx_manager->HasUnappliedAcceptedWork() ||
                    marks.cleanup_sequence < marks.apfs_durable_sequence;
                if (pending && c.native_write_enabled && ReplayAcceptedWriteAheadLogAfterMetadataBootstrap(c)) pending = false;
                ReconcilePayloadSpoolRecoveryAfterMetadataBootstrap(c, c.payload_spool->RecoveryRequired());
                ReconcileWriteAheadLogRecoveryAfterMetadataBootstrap(c, pending);
            }
        }
    }
    MountContext& Context() { return *contexts.front(); }
    ContainerControlRequest Request(ContainerControlAction action)
    {
        ContainerControlRequest request;
        request.request_id = std::string(32, 'a');
        request.volume_object_id = 101;
        request.action = action;
        return request;
    }
    LiveSnapshotInventory Inventory()
    {
        auto result = SnapshotListForControl(Context(), *owner, Request(ContainerControlAction::SnapshotList));
        Check(result.success && result.snapshot_inventory.has_value(), "live list: " + result.code);
        return *result.snapshot_inventory;
    }
    ContainerControlActionResult Create(const std::string& name)
    {
        auto request = Request(ContainerControlAction::SnapshotCreate);
        request.snapshot_name = name;
        return SnapshotCreateForControl(Context(), *owner, request);
    }
    ContainerControlActionResult Delete(const ApfsSnapshotIdentity& identity)
    {
        auto request = Request(ContainerControlAction::SnapshotDelete);
        request.snapshot_identity = identity;
        request.has_snapshot_identity = true;
        return SnapshotDeleteForControl(Context(), *owner, request);
    }
};

std::vector<std::byte> HeldImageBytes(HostSnapshots& host)
{
    const auto& device = host.owner->Device();
    const auto size = device.GetGeometry().total_bytes;
    constexpr std::size_t window = 128 * 1024;
    Check(size >= window && size <= 256 * 1024 * 1024, "bounded full held-image proof");
    apfsaccess::rw::BlockDevice::StableImageIdentity before, after;
    Check(device.QueryHeldImageIdentity(before), "original held image identity before fresh reads");
    std::vector<std::byte> image(static_cast<std::size_t>(size)), bytes;
    for (std::uint64_t at = 0; at < size; at += window)
    {
        const auto start = (std::min)(at, size - window);
        Check(device.Read(start, window, bytes) && bytes.size() == window, "fresh held device window exceeds 64 KiB cache limit");
        std::copy(bytes.begin(), bytes.end(), image.begin() + static_cast<std::size_t>(start));
    }
    Check(device.QueryHeldImageIdentity(after) && before == after, "held image identity stable through full reads");
    return image;
}

void HostWire()
{
    const auto token = std::string(64, 'b');
    const auto envelope = "APFS-CONTROL/1\n" + std::string(32, 'a') + "\n" + token + "\nsnapshot-list\n101\n";
    ContainerControlRequest request;
    std::string error, bytes;
    Check(ParseContainerControlRequestContents(envelope, token, request, error) &&
        request.action == ContainerControlAction::SnapshotList, "list authenticated parser");
    Check(!ParseContainerControlRequestContents(envelope, std::string(64, 'c'), request, error), "wrong token");
    Check(!ParseContainerControlRequestContents(envelope + "extra\n", token, request, error), "list trailing data");
    Check(ParseContainerControlRequestContents(envelope, token, request, error), "parse reset");
    for (bool success : {false, true})
    {
        Check(BuildContainerControlResponse(request, {success, "LegacyCode"}, bytes), "legacy encode");
        Check(bytes == "APFS-CONTROL/1\n" + std::string(32, 'a') + "\n" +
            (success ? "ok\n" : "error\n") + "LegacyCode\n", "legacy bytes unchanged");
    }
    LiveSnapshotInventory inventory;
    inventory.scope = {0, 4096, std::string(32, 'a'), std::string(32, 'b'), 101, UINT64_MAX};
    ApfsSnapshotInfo info;
    info.identity.scope = inventory.scope;
    info.identity.snapshot_xid = UINT64_MAX;
    info.identity.name_utf8 = "quoted\"name\\line\n";
    inventory.snapshots.push_back(info);
    Check(BuildContainerControlResponse(request, {true, "SnapshotInventory", inventory}, bytes), "typed encode");
    Check(bytes.find("snapshot-inventory-json/1\n{\"format\":") != std::string::npos &&
        bytes.find("\"checkpointXid\":\"18446744073709551615\"") != std::string::npos &&
        bytes.find("quoted\\\"name\\\\line\\n") != std::string::npos, "typed exact integers and JSON escaping");
    inventory.snapshots.resize(65, info);
    Check(!BuildContainerControlResponse(request, {true, "SnapshotInventory", inventory}, bytes), "bounded rows");
    Check(!BuildContainerControlResponse(request, {false, "Failed", inventory}, bytes), "no error payload");
    std::cout << "PASS authenticated wire, legacy bytes, exact integers, payload bounds\n";
}

void HostImageArguments()
{
    const std::vector<std::wstring> command = {L"host", L"--container-manifest", L"D:\\container.json",
        L"--container-manifest-sha256", std::wstring(64, L'a'), L"--container-control-file", L"D:\\control",
        L"--container-control-token", std::wstring(64, L'b'), L"--status-file", L"D:\\status.json",
        L"--readwrite", L"--write-backend", L"Native", L"--parent-pid", L"123",
        L"--lifetime-file", L"D:\\life", L"--startup-gate-file", L"D:\\gate", L"--startup-gate-token", L"gate",
        L"--enable-image-snapshots"};
    const auto parse = [](std::vector<std::wstring> words, Arguments& args) {
        std::vector<wchar_t*> argv; for (auto& word : words) argv.push_back(word.data());
        return ParseArgs(static_cast<int>(argv.size()), argv.data(), args);
    };
    Arguments enabled;
    Check(parse(command, enabled) && enabled.enable_image_snapshots, "explicit image option parser");
    for (const auto& additions : std::vector<std::vector<std::wstring>>{
        {L"--allow-raw-physical-write"}, {L"--readonly"}, {L"--snapshot-xid", L"10"},
        {L"--enable-image-snapshots"}, {L"--write-require-canonical-commit", L"false"}})
    {
        auto words = command; words.insert(words.end(), additions.begin(), additions.end());
        Arguments args; Check(!parse(words, args), "incompatible image option refused");
    }
    ContainerManifest manifest;
    manifest.device_path = "D:\\ordinary.apfs";
    manifest.container_uuid_hex = std::string(32, 'a');
    ManifestVolumeEntry volume; volume.object_id = 101; volume.requested_write = true;
    manifest.volumes.push_back(volume);
    std::vector<Arguments> volumes; std::wstring error;
    Check(BuildManifestVolumeArgs(enabled, manifest, volumes, error) && volumes.front().enable_image_snapshots,
        "image manifest preserves opt-in");
    for (const auto& path : {"\\\\.\\PhysicalDrive2", "\\\\server\\image", "D:relative.apfs", "D:\\file:stream"})
    {
        manifest.device_path = path;
        Check(!BuildManifestVolumeArgs(enabled, manifest, volumes, error), "physical/network/nonordinary manifest refuses");
    }
    manifest.device_path = "D:\\ordinary.apfs"; manifest.device_offset_bytes = 4096;
    Check(!BuildManifestVolumeArgs(enabled, manifest, volumes, error), "nonzero range outside bounded image profile");
    Check(!BuildMetadataStoreVolumeContext(enabled).allow_native_snapshot_runtime, "argument alone cannot enable store");
    std::cout << "PASS explicit image arguments, physical profile and unbound context refusals\n";
}

void HostLifecycle()
{
    Fresh("host.apfs");
    HostSnapshots host("host.apfs");
    const auto capabilities = GetSnapshotControlCapabilities(host.Context(), *host.owner);
    Check(capabilities.inventory && capabilities.mutation && !host.Context().mount_ready, "capability from source gates without mount readiness");
    const auto initial = host.Inventory();
    Check(initial.snapshots.empty(), "empty live inventory");
    const auto created = host.Create("one");
    Check(created.success, "host create: " + created.code);
    const auto first = host.Inventory();
    Check(first.snapshots.size() == 1 && first.scope.checkpoint_xid == host.owner->CheckpointXid() &&
        first.snapshots.front().identity.scope == first.scope, "same owner exact checkpoint inventory");
    const auto original_payload = LiveBytes(*host.owner, L"\\clone0");
    std::string reader_error;
    auto reader = host.owner->AcquireSnapshotReader(first.snapshots.front().identity, reader_error);
    Check(!!reader, "retained historical reader: " + reader_error);
    const auto pinned_sequence = host.Context().tx_manager->Watermarks().accepted_sequence;
    const auto pinned_delete = host.Delete(first.snapshots.front().identity);
    Check(!pinned_delete.success && pinned_delete.code == "SnapshotRuntimeReaderBusy" &&
        host.Context().tx_manager->Watermarks().accepted_sequence == pinned_sequence, "retained reader blocks delete before acceptance");
    const auto second = host.Create("two");
    Check(second.success, "second host create: " + second.code);
    const auto marks = host.Context().tx_manager->Watermarks();
    const auto stale_image = HeldImageBytes(host);
    std::vector<std::vector<std::byte>> stale_journals;
    std::vector<Tx::DurabilityWatermarks> stale_watermarks;
    for (const auto& c : host.contexts)
    {
        stale_journals.push_back(Bytes(c->tx_journal_file));
        stale_watermarks.push_back(c->tx_manager->Watermarks());
    }
    const auto stale = host.Delete(first.snapshots.front().identity);
    Check(!stale.success && stale.code == "SnapshotRuntimeDeleteStaleIdentity" &&
        marks.accepted_sequence == host.Context().tx_manager->Watermarks().accepted_sequence, "stale delete before acceptance");
    Check(HeldImageBytes(host) == stale_image, "stale delete preserves full image through fresh held device reads");
    for (std::size_t i = 0; i < host.contexts.size(); ++i)
    {
        const auto after = host.contexts[i]->tx_manager->Watermarks();
        const auto before = stale_watermarks[i];
        Check(Bytes(host.contexts[i]->tx_journal_file) == stale_journals[i] &&
            after.accepted_sequence == before.accepted_sequence && after.apfs_durable_sequence == before.apfs_durable_sequence &&
            after.cleanup_sequence == before.cleanup_sequence, "stale delete preserves every original native journal and watermark");
    }
    std::vector<std::byte> historical_payload;
    Check(reader->Read(17, 0, original_payload.size(), historical_payload) && historical_payload == original_payload,
        "immutable historical bytes survive live snapshot publication");
    reader.reset();
    for (unsigned n = 0; n < 2; ++n)
    {
        const auto removed = host.Delete(host.Inventory().snapshots.front().identity);
        Check(removed.success, "host delete: " + removed.code);
    }
    Check(host.Inventory().snapshots.empty(), "live empty after delete");
    Check(LiveBytes(*host.owner, L"\\clone0") == original_payload, "deletion preserves live payload");
    // The real dispatcher consumes an authenticated file and returns typed data.
    Arguments control;
    control.container_control_file = std::filesystem::absolute("control.request").wstring();
    control.container_control_token = std::wstring(64, L'b');
    {
        std::ofstream request(control.container_control_file, std::ios::binary);
        request << "APFS-CONTROL/1\n" << std::string(32, 'a') << "\n" << std::string(64, 'b') << "\nsnapshot-list\n101\n";
    }
    Check(ProcessContainerControlRequest(control, *host.owner, host.contexts), "actual control dispatcher");
    const auto response_bytes = Bytes(control.container_control_file + L".response");
    const std::string response(reinterpret_cast<const char*>(response_bytes.data()), response_bytes.size());
    Check(response.find("ok\nSnapshotInventory\nsnapshot-inventory-json/1\n") != std::string::npos &&
        response.find("\"snapshots\":[]") != std::string::npos, "dispatcher typed inventory response");
    const auto recovered = SnapshotRecoverForControl(host.Context(), *host.owner, host.Request(ContainerControlAction::SnapshotRecover));
    Check(recovered.success && recovered.code == "SnapshotRecoverNoOp", "clean recovery noop");
    Arguments process;
    process.status_file = std::filesystem::absolute("host-status.json").wstring();
    for (auto& context : host.contexts)
    {
        context->manifest_mount_attached = true;
        context->mount_ready = true;
    }
    Check(WriteContainerStatusFile(process, *host.owner, host.contexts), "per-volume status");
    const auto status_bytes = Bytes(process.status_file);
    const std::string status(reinterpret_cast<const char*>(status_bytes.data()), status_bytes.size());
    Check(status.find("\"snapshotInventorySupported\":true") != std::string::npos &&
        status.find("\"snapshotMutationSupported\":true") != std::string::npos, "status capabilities emitted");
    // Clean older siblings read the latest published view without reloading.
    auto& sibling = *host.contexts.back();
    Check(GetSnapshotControlCapabilities(sibling, *host.owner).inventory, "clean older sibling inventory supported");
    std::promise<void> entered, release;
    auto release_signal = release.get_future().share();
    auto inspection = std::async(std::launch::async, [&] {
        std::string error;
        return host.owner->InspectCurrentSession(101, [&](const Store&, std::string&) {
            entered.set_value(); release_signal.wait(); return true;
        }, error);
    });
    entered.get_future().wait();
    auto listing = std::async(std::launch::async, [&] { return host.Inventory(); });
    const bool serialized = listing.wait_for(std::chrono::milliseconds(50)) == std::future_status::timeout;
    release.set_value();
    Check(inspection.get() && listing.get().snapshots.empty() && serialized, "inventory uses coordinator publication serializer");
    std::cout << "PASS native create/list/delete/noop, stale identity, status\n";
}

void HostNegatives()
{
    {
    Fresh("disabled.apfs");
    HostSnapshots disabled("disabled.apfs", false);
    Check(!GetSnapshotControlCapabilities(disabled.Context(), *disabled.owner).inventory &&
        !disabled.Create("no").success, "default closed");
    }
    {
    Fresh("nocensus.apfs");
    HostSnapshots census("nocensus.apfs", true, false);
    Check(!GetSnapshotControlCapabilities(census.Context(), *census.owner).mutation &&
        !census.Create("no").success, "census readiness required");
    }
    Fresh("negative-host.apfs");
    HostSnapshots host("negative-host.apfs");
    auto& c = host.Context();
    const auto source = Bytes("negative-host.apfs");
    c.recovery_active = true;
    Check(!host.Create("no").success && !GetSnapshotControlCapabilities(c, *host.owner).mutation, "host recovery refuses mutation");
    c.recovery_active = false;
    c.write_degraded = true;
    Check(!host.Create("no").success && !GetSnapshotControlCapabilities(c, *host.owner).mutation, "host degraded refuses mutation");
    c.write_degraded = false;
    c.args.snapshot_xid = 1;
    Check(!host.Create("no").success && !GetSnapshotControlCapabilities(c, *host.owner).inventory, "immutable snapshot profile refuses live control");
    c.args.snapshot_xid = 0;
    c.args.allow_raw_physical_write = true;
    Check(!host.Create("no").success && !GetSnapshotControlCapabilities(c, *host.owner).inventory, "physical profile refused");
    c.args.allow_raw_physical_write = false;
    auto journal = std::move(c.tx_manager);
    c.tx_manager = std::make_unique<Tx>(L"Strict");
    c.tx_manager->SetVolumeIdentity(journal->ConfiguredVolumeIdentity());
    Check(!host.Create("no").success && !GetSnapshotControlCapabilities(c, *host.owner).inventory, "unowned journal refuses without reacquisition");
    c.tx_manager = std::move(journal);
    std::string error;
    Check(host.owner->UnmountVolume(101, error), "remove session owner");
    Check(!host.Create("no").success && !GetSnapshotControlCapabilities(c, *host.owner).inventory, "lost session owner refuses");
    Check(Bytes("negative-host.apfs") == source, "negative gates preserve image");
    std::cout << "PASS default, census, physical profile, journal and session owner refusals\n";
}

void HostRecovery()
{
    Fresh("recover-host.apfs");
    {
        HostSnapshots host("recover-host.apfs");
        host.Context().metadata_store->SetCommitStageHook([](std::string_view stage) { return stage != "before-apple-publish"; });
        Check(!host.Create("retained").success && host.Context().tx_manager->HasUnappliedAcceptedWork(), "native accepted failure retained");
    }
    for (unsigned restart = 0; restart < 2; ++restart)
    {
        HostSnapshots host("recover-host.apfs");
        if (!restart)
        {
            auto& ctx = host.Context();
            ctx.manifest_mount_attached = true; ctx.mount_ready = true;
            Check(ctx.native_write_enabled && ctx.tx_manager->HasUnappliedAcceptedWork(),
                "actual enrolled writer retains accepted snapshot debt before status inspection");
            Arguments process; process.status_file = std::filesystem::absolute("accepted-snapshot-status.json").wstring();
            const auto image = Bytes("recover-host.apfs"), journal = Bytes(ctx.tx_journal_file);
            const auto marks = ctx.tx_manager->Watermarks();
            Check(WriteContainerStatusFile(process, *host.owner, host.contexts), "accepted recovery status");
            const auto bytes = Bytes(process.status_file);
            const std::string status(reinterpret_cast<const char*>(bytes.data()), bytes.size());
            Check(status.find("\"snapshotRecoverySupported\":true") != std::string::npos &&
                status.find("\"snapshotInventorySupported\":true") == std::string::npos &&
                status.find("\"snapshotMutationSupported\":true") == std::string::npos,
                "accepted native-eligible debt advertises recovery independently of clean capabilities");
            Check(Bytes("recover-host.apfs") == image && Bytes(ctx.tx_journal_file) == journal &&
                ctx.tx_manager->Watermarks().accepted_sequence == marks.accepted_sequence,
                "recovery capability inspection preserves accepted image and WAL");
            const auto eligible_args = ctx.args;
            const auto refused = [&] {
                Check(!GetSnapshotRecoveryCapability(ctx, *host.owner) &&
                    !SnapshotRecoverForControl(ctx, *host.owner, host.Request(ContainerControlAction::SnapshotRecover)).success,
                    "unsupported recovery source/profile refuses before replay");
                Check(Bytes("recover-host.apfs") == image && Bytes(ctx.tx_journal_file) == journal,
                    "recovery refusal preserves accepted image and WAL");
                ctx.args = eligible_args;
                Check(GetSnapshotRecoveryCapability(ctx, *host.owner), "exact accepted owner eligibility restored");
            };
            ctx.args.enable_image_snapshots = false; refused();
            ctx.args.allow_raw_physical_write = true; refused();
            ctx.args.encrypted.enabled = true; refused();
            ctx.args.fusion.enabled = true; refused();
            ctx.args.snapshot_xid = 1; refused();
            ctx.args.snapshot_name = L"view"; refused();
            ctx.args.readwrite = false; refused();
            ctx.args.write_backend = L"Overlay"; refused();
            ctx.args.device += L"-other"; refused();
            ctx.args.container_id = std::wstring(32, L'f'); refused();
            ctx.args.volume_object_id = 102; refused();
            auto wrong = host.Request(ContainerControlAction::SnapshotRecover); wrong.volume_object_id = 102;
            Check(!SnapshotRecoverForControl(ctx, *host.owner, wrong).success, "wrong selected request target refuses");
            auto& sibling = *host.contexts.back();
            wrong.volume_object_id = 102;
            Check(!GetSnapshotRecoveryCapability(sibling, *host.owner) &&
                !SnapshotRecoverForControl(sibling, *host.owner, wrong).success,
                "accepted sibling census cannot authorize recovery by another owner");
            const auto journal_path = ctx.tx_journal_file;
            ctx.tx_journal_file += L"-other";
            Check(!GetSnapshotRecoveryCapability(ctx, *host.owner) &&
                !SnapshotRecoverForControl(ctx, *host.owner, host.Request(ContainerControlAction::SnapshotRecover)).success,
                "substituted journal path refuses without reacquisition");
            ctx.tx_journal_file = journal_path;
            Check(GetSnapshotRecoveryCapability(ctx, *host.owner), "original journal lease restores eligibility");
            ReconcileWriteAheadLogRecoveryAfterMetadataBootstrap(ctx, true);
            Check(ctx.write_degraded && !ctx.native_write_enabled && ctx.recovery_active &&
                ctx.tx_manager->HasUnappliedAcceptedWork(), "production bootstrap degradation retains actual accepted debt");
            Check(WriteContainerStatusFile(process, *host.owner, host.contexts), "degraded accepted recovery status");
            const auto degraded_bytes = Bytes(process.status_file);
            const std::string degraded_status(reinterpret_cast<const char*>(degraded_bytes.data()), degraded_bytes.size());
            const auto degraded_recover = SnapshotRecoverForControl(ctx, *host.owner, host.Request(ContainerControlAction::SnapshotRecover));
            Check(degraded_status.find("\"snapshotRecoverySupported\":true") == std::string::npos &&
                !GetSnapshotRecoveryCapability(ctx, *host.owner) && !degraded_recover.success &&
                degraded_recover.code == "SnapshotRecoveryOriginalStorageRequired" &&
                Bytes("recover-host.apfs") == image && Bytes(ctx.tx_journal_file) == journal,
                "actually degraded disabled writer advertises refusal matching unchanged native authority");
            ctx.native_write_enabled = true;
            ctx.write_degraded = false;
            ctx.recovery_active = false;
            ctx.pending_native_writes = false;
            ctx.runtime_recovery_reason.clear();
            Check(GetSnapshotRecoveryCapability(ctx, *host.owner), "retained native writer restores eligibility");
            Check(!host.Create("blocked").success && !GetSnapshotControlCapabilities(ctx, *host.owner).mutation,
                "accepted debt recovery eligibility does not enable create");
            if (const auto* output = std::getenv("APFSACCESS_SNAPSHOT_RECOVERY_STATUS"))
            {
                Check(std::filesystem::path(output).wstring().starts_with(L"D:"), "private D: native status export");
                const auto* cp = ctx.metadata_store->AuthoritativeAppleCheckpointView();
                const auto volume = std::find_if(cp->volumes.begin(), cp->volumes.end(), [&](const auto& v) {
                    return v.superblock.object_id == ctx.container_volume_oid;
                });
                Check(volume != cp->volumes.end(), "native accepted status exact volume UUID");
                std::ofstream exported(output, std::ios::binary);
                exported << "{\"status\":" << status << ",\"degradedStatus\":" << degraded_status
                    << ",\"source\":\"" << EscapeJson(WideToUtf8(ctx.args.device))
                    << "\",\"volumeUuid\":\"" << volume->superblock.uuid_hex
                    << "\",\"storeSizeBytes\":" << ctx.metadata_store->Device().GetGeometry().total_bytes << "}";
                Check(!!exported, "actual accepted native status saved for managed contract checks");
            }
        }
        const auto result = SnapshotRecoverForControl(host.Context(), *host.owner, host.Request(ContainerControlAction::SnapshotRecover));
        Check(result.success && result.code == (restart ? "SnapshotRecoverNoOp" : "SnapshotRecovered"), "native host recovery: " + result.code);
        Check(host.Inventory().snapshots.size() == 1 && !host.Context().tx_manager->HasUnappliedAcceptedWork(), "recovered inventory and clean journal");
    }
    std::cout << "PASS retained native WAL recovery across two owner reopens\n";
}

void HostPeerPublication(bool ordinary_write_after_snapshot = false)
{
    Fresh("peer-publication.apfs");
    HostSnapshots host("peer-publication.apfs");
    auto& selected = host.Context();
    auto& peer = *host.contexts.back();
    const auto payload = [&](MountContext& c) {
        const auto inode = c.metadata_store->LookupCommittedInodeByPath(L"\\clone0");
        std::vector<std::byte> bytes;
        Check(inode && c.metadata_store->ReadCommittedFileRange(L"\\clone0", 0, inode->logical_size, bytes), "peer payload read");
        return bytes;
    };
    const auto selected_payload = payload(selected), peer_payload = payload(peer);
    const auto old_xid = selected.metadata_store->CheckpointXid();
    std::string error;
    const auto publish_peer = [&](const wchar_t* path) {
        Store::MutationRequest mutation;
        mutation.operation = Store::MutationOperation::CreateDirectory;
        mutation.path = path;
        Success(host.owner->Commit(102, {mutation}, [&](const auto& requests, const auto& identities, auto xid, auto& pins, std::string& detail) {
            Check(requests.size() == 1 && identities.size() == 1, "exact peer publication batch");
            Tx::MutationIntent intent;
            intent.kind = Tx::MutationKind::CreateDirectory;
            intent.path = requests.front().path;
            intent.object_id = identities.front().object_id;
            intent.generation = identities.front().generation;
            return peer.tx_manager->Begin() && peer.tx_manager->RecordMutation(intent) && peer.tx_manager->Accept(xid) &&
                peer.tx_manager->LoadRequiredCheckpointXidsSinceCleanup(pins, &detail);
        }));
        const auto sequence = peer.tx_manager->Watermarks().accepted_sequence;
        std::vector<std::uint64_t> pins;
        Check(peer.tx_manager->MarkApfsDurableThrough(sequence) && peer.tx_manager->MarkCleanedThrough(sequence) &&
            peer.tx_manager->LoadRequiredCheckpointXidsSinceCleanup(pins, &error) && pins.empty() &&
            host.owner->UpdateRequiredCheckpointXids(102, pins, error), "actual peer WAL durable cleanup: " + error);
    };
    publish_peer(L"\\peer-first");
    Check(selected.metadata_store->CheckpointXid() == old_xid && *old_xid < host.owner->CheckpointXid(), "actual clean selected peer stays older");
    Check(!host.owner->InspectCurrentSession(101, [](const auto&, auto&) { return true; }, error), "strict mutable inspection still rejects older peer");
    std::cout << "REPRO selected=" << *old_xid << " published=" << host.owner->CheckpointXid() << " strict=" << error << '\n';
    const auto image = Bytes("peer-publication.apfs");
    const auto selected_wal = Bytes(selected.tx_journal_file), peer_wal = Bytes(peer.tx_journal_file);
    const auto inventory = host.Inventory();
    const auto caps = GetSnapshotControlCapabilities(selected, *host.owner);
    Check(caps.inventory && caps.mutation && inventory.scope.checkpoint_xid == host.owner->CheckpointXid() && inventory.snapshots.empty(), "older clean peer lists current published checkpoint");
    Check(selected.metadata_store->CheckpointXid() == old_xid && Bytes("peer-publication.apfs") == image &&
        Bytes(selected.tx_journal_file) == selected_wal && Bytes(peer.tx_journal_file) == peer_wal, "read-only list/capability preserves store, image and both WALs");
    const auto created = host.Create("selected");
    Check(created.success, "older clean peer create reloads safely: " + created.code);
    Check(selected.metadata_store->CheckpointXid() == host.owner->CheckpointXid(), "mutation refreshes selected store before preparation");
    const auto snapshot = host.Inventory().snapshots.front().identity;
    // Keep the native ordinary-write refusal independently reproducible.
    if (ordinary_write_after_snapshot)
    {
        std::cout << "REPRO post-snapshot volume=102 operation=CreateDirectory path=\\peer-second selectedStore="
            << *peer.metadata_store->CheckpointXid() << " published=" << host.owner->CheckpointXid() << '\n';
        publish_peer(L"\\peer-second");
    }
    auto peer_request = host.Request(ContainerControlAction::SnapshotCreate);
    peer_request.volume_object_id = 102;
    peer_request.snapshot_name = "peer-second";
    const auto peer_created = SnapshotCreateForControl(peer, *host.owner, peer_request);
    Check(peer_created.success, "older peer snapshot publication: " + peer_created.code);
    const auto second_peer_wal = Bytes(peer.tx_journal_file);
    const auto before_stale = Bytes(selected.tx_journal_file);
    const auto stale_image = HeldImageBytes(host);
    const auto selected_marks = selected.tx_manager->Watermarks(), peer_marks = peer.tx_manager->Watermarks();
    const auto stale = host.Delete(snapshot);
    Check(!stale.success && stale.code == "SnapshotRuntimeDeleteStaleIdentity" && Bytes(selected.tx_journal_file) == before_stale,
        "peer publication makes old delete identity stale without WAL acceptance");
    const auto unchanged_marks = [](const auto& before, const auto& after) {
        return before.accepted_sequence == after.accepted_sequence && before.apfs_durable_sequence == after.apfs_durable_sequence &&
            before.cleanup_sequence == after.cleanup_sequence;
    };
    Check(HeldImageBytes(host) == stale_image && Bytes(peer.tx_journal_file) == second_peer_wal &&
        unchanged_marks(selected_marks, selected.tx_manager->Watermarks()) && unchanged_marks(peer_marks, peer.tx_manager->Watermarks()),
        "stale peer delete preserves fresh full image, both original journals and all watermarks");
    const auto latest_snapshot = host.Inventory().snapshots.front().identity;
    const auto removed = host.Delete(latest_snapshot);
    Check(removed.success && host.Inventory().snapshots.empty(), "selected peer delete after create: " + removed.code);
    Check(payload(selected) == selected_payload && payload(peer) == peer_payload && Bytes(peer.tx_journal_file) == second_peer_wal,
        "selected snapshot mutations preserve both payloads and other peer WAL");
    std::array<std::uint8_t, 32> selected_hash{}, peer_hash{};
    HashPayload(selected_payload, selected_hash); HashPayload(peer_payload, peer_hash);
    const auto print = [](const auto& hash) { for (auto b : hash) std::cout << "0123456789abcdef"[b >> 4] << "0123456789abcdef"[b & 15]; };
    std::cout << "PASS real two-peer canonical publication/list/create/delete; selected SHA256=";
    print(selected_hash); std::cout << " peer SHA256="; print(peer_hash); std::cout << '\n';
}

void HostPeerRefusals()
{
    Fresh("peer-refusals.apfs");
    HostSnapshots host("peer-refusals.apfs");
    auto& peer = *host.contexts.back();
    const auto unchanged_image = Bytes("peer-refusals.apfs");
    const auto healthy = [&] {
        const auto caps = GetSnapshotControlCapabilities(host.Context(), *host.owner);
        Check(caps.inventory && caps.mutation, "restored peer supports snapshot control");
    };
    const auto refuse = [&](const char* label) {
        const auto first = Bytes(host.Context().tx_journal_file), second = Bytes(peer.tx_journal_file);
        const auto list = SnapshotListForControl(host.Context(), *host.owner, host.Request(ContainerControlAction::SnapshotList));
        const auto caps = GetSnapshotControlCapabilities(host.Context(), *host.owner);
        Check(!list.success && !caps.inventory && !caps.mutation && !host.Create("refused").success, label);
        Check(Bytes("peer-refusals.apfs") == unchanged_image && Bytes(host.Context().tx_journal_file) == first &&
            Bytes(peer.tx_journal_file) == second, "peer refusals preserve image and both WALs");
    };
    healthy();
    for (auto* flag : {&peer.recovery_active, &peer.write_degraded}) { *flag = true; refuse("peer recovery/degradation refuses"); *flag = false; healthy(); }
    Check(peer.tx_manager->Begin(), "peer dirty journal begins");
    refuse("peer non-idle journal refuses");
    Check(peer.tx_manager->Abort(), "peer dirty journal abort");
    healthy();
    auto journal = std::move(peer.tx_manager);
    peer.tx_manager = std::make_unique<Tx>(L"Strict");
    peer.tx_manager->SetVolumeIdentity(journal->ConfiguredVolumeIdentity());
    refuse("peer lost journal lease refuses");
    peer.tx_manager = std::move(journal);
    healthy();
    std::string error;
    Check(host.owner->UpdateRequiredCheckpointXids(102, {host.owner->CheckpointXid()}, error, true), "unresolved peer census");
    refuse("peer accepted census refuses");
    Check(host.owner->UpdateRequiredCheckpointXids(102, {}, error), "restore peer census");
    healthy();
    const auto peers = host.Context().container_session_contexts;
    host.Context().container_session_contexts.pop_back();
    refuse("missing peer host gates refuse");
    host.Context().container_session_contexts = peers;
    healthy();
    for (unsigned gate = 0; gate < 4; ++gate)
    {
        std::promise<void> held, release;
        auto released = release.get_future().share();
        auto holder = std::async(std::launch::async, [&] {
            std::unique_lock<std::mutex> lock(gate == 0 ? peer.commit_mutex : gate == 2 ? peer.metadata_mutex : peer.tx_mutex, std::defer_lock);
            std::unique_lock<std::shared_mutex> read(peer.committed_read_gate, std::defer_lock);
            if (gate == 1) read.lock(); else lock.lock();
            held.set_value(); released.wait();
        });
        held.get_future().wait();
        const auto busy = SnapshotListForControl(host.Context(), *host.owner, host.Request(ContainerControlAction::SnapshotList));
        const auto mutation = host.Create("busy");
        const auto caps = GetSnapshotControlCapabilities(host.Context(), *host.owner);
        release.set_value(); holder.get();
        Check(!busy.success && busy.code == "SnapshotControlBusy" && !mutation.success && mutation.code == "SnapshotControlBusy" &&
            !caps.inventory && !caps.mutation, "every peer publication gate excludes snapshot control");
        healthy();
    }
    const auto reservation = peer.metadata_store->AllocateExtent(4096);
    Check(reservation.has_value(), "actual peer allocator reservation");
    refuse("peer allocator reservation refuses");
    std::cout << "PASS peer host gates, journal debt/lease, census, recovery and allocator refusals\n";
}

void SeedBootstrapSnapshot(const std::string& image, bool deleting, bool marker = true)
{
    auto spec = RuntimeSpec();
    std::string order_error;
    for (auto& volume : spec.volumes)
    {
        const bool ordered = apfsaccess::rw::SortAppleBtreeRecords(volume.filesystem_records,
            apfsaccess::rw::AppleBtreeKeyOrder::FileSystemHashedDirectory, order_error);
        Check(ordered, "canonical original fixture: " + order_error);
    }
    Fresh(image, spec);
    HostSnapshots host(image, true, true, true);
    if (deleting) Check(host.Create("bootstrap").success, "original snapshot for interrupted delete");
    if (marker) Check(UpdateRecoveryMarkerBestEffort(&host.Context(), true), "original production dirty marker persisted");
    host.Context().metadata_store->SetCommitStageHook([](std::string_view stage) { return stage != "before-apple-publish"; });
    const auto interrupted = deleting ? host.Delete(host.Inventory().snapshots.front().identity) : host.Create("bootstrap");
    Check(!interrupted.success && host.Context().tx_manager->HasUnappliedAcceptedWork(), "real isolated snapshot acceptance before interruption");
    Check(host.Context().tx_manager->ConfiguredVolumeIdentity() == host.Context().args.recovery_identity,
        "original configured production recovery identity retained");
}

std::string AuthenticatedRecovery(HostSnapshots& host, const std::string& name = "bootstrap-control")
{
    static unsigned request_sequence = 0;
    Arguments process;
    process.container_control_file = std::filesystem::absolute(name + "-" + std::to_string(++request_sequence)).wstring();
    process.container_control_token = std::wstring(64, L'b');
    std::ofstream request(process.container_control_file, std::ios::binary);
    request << "APFS-CONTROL/1\n" << std::string(32, 'a') << "\n" << std::string(64, 'b') << "\nsnapshot-recover\n101\n";
    request.close();
    Check(ProcessContainerControlRequest(process, *host.owner, host.contexts), "production authenticated recovery file dispatcher");
    const auto bytes = Bytes(process.container_control_file + L".response");
    return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

void VerifyBootstrapPeers(HostSnapshots& host, bool retained_snapshot = false)
{
    for (auto& context : host.contexts)
    {
        auto scope = GetVolumeVerificationCapability(*context, *host.owner);
        Check(scope.has_value(), "recovered peer exact live verification scope");
        auto request = host.Request(ContainerControlAction::VolumeVerify);
        request.volume_object_id = context->container_volume_oid;
        request.verification_scope = scope;
        const auto verified = VolumeVerifyForControl(*context, *host.owner, request);
        std::string report_json;
        if (verified.volume_verification && BuildLiveVolumeVerificationJson(*verified.volume_verification, report_json))
            std::cout << "VERIFIED " << context->container_volume_oid << ' ' << report_json << '\n';
        Check(verified.success && verified.code == "VolumeVerificationReport" && verified.volume_verification,
            "actual peer typed verification report: " + verified.code);
        const auto& report = verified.volume_verification->report;
        Check(report.outcome == apfsaccess::catalog::VerificationOutcome::Complete && report.findings.empty(),
            "actual peer covered metadata verification: " + verified.code);
        Check(!report.whole_volume_verified && !report.payload_content_hashes_verified,
            "covered snapshot verification never certifies complete history or independent payload integrity");
        if (retained_snapshot && context->container_volume_oid == 101)
            Check(host.Inventory().snapshots.size() == 1, "verification preserves the actual retained snapshot");
    }
}

void EmitInactiveMemberStatus(const std::filesystem::path& output, bool detached)
{
    Check(output.is_absolute() && output.wstring().starts_with(L"D:"), "D: detached status output required");
    Fresh("inactive-member.apfs");
    HostSnapshots host("inactive-member.apfs");
    for (auto& context : host.contexts)
    {
        context->manifest_mount_attached = true;
        context->mount_ready = true;
    }
    const auto original = HeldImageBytes(host);
    Arguments process;
    process.status_file = output.wstring() + L".before.json";
    Check(WriteContainerStatusFile(process, *host.owner, host.contexts), "initial ready cohort status");
    host.Context().manifest_mount_attached = !detached;
    host.Context().mount_ready = false;
    process.status_file = output.wstring();
    Check(WriteContainerStatusFile(process, *host.owner, host.contexts), "inactive member status");
    Check(HeldImageBytes(host) == original, "status projection preserves original APFS bytes");
    std::cout << "PASS inactive member publication preserves source and sibling\n";
}

void HostBootstrapRecovery(bool frozen_red = false)
{
    for (bool deleting : {false, true}) for (bool marker : {true, false})
    {
        const auto image = std::string(deleting ? "bootstrap-delete-" : "bootstrap-create-") + (marker ? "marker.apfs" : "missing-marker.apfs");
        SeedBootstrapSnapshot(image, deleting, marker);
        {
            HostSnapshots host(image, true, true, true);
            auto& ctx = host.Context();
            Check(!ctx.native_write_enabled && ctx.recovery_active && ctx.write_degraded && ctx.tx_manager->HasUnappliedAcceptedWork(),
                "production marker/WAL/metadata bootstrap disables writer with original accepted receipt");
            std::cout << "BOOTSTRAP " << image << " reason=" << WideToUtf8(ctx.runtime_recovery_reason) << '\n';
            const auto before = HeldImageBytes(host), wal = Bytes(ctx.tx_journal_file);
            const auto marks = ctx.tx_manager->Watermarks();
            const auto configured = ctx.tx_manager->ConfiguredVolumeIdentity();
            const auto journal_path = ctx.tx_journal_file, marker_path = ctx.recovery_marker_file;
            const auto payload = LiveBytes(*host.owner, L"\\clone0");
            auto& peer = *host.contexts.back();
            const auto peer_inode = peer.metadata_store->LookupCommittedInodeByPath(L"\\clone0");
            std::vector<std::byte> peer_payload;
            Check(peer_inode && peer.metadata_store->ReadCommittedFileRange(L"\\clone0", 0, peer_inode->logical_size, peer_payload), "original sibling payload");
            const auto peer_wal = Bytes(peer.tx_journal_file);
            Arguments status; status.status_file = std::filesystem::absolute(image + ".disabled-status.json").wstring();
            ctx.manifest_mount_attached = true; ctx.mount_ready = true;
            peer.manifest_mount_attached = true; peer.mount_ready = true;
            Check(WriteContainerStatusFile(status, *host.owner, host.contexts), "actual disabled bootstrap status");
            const bool eligible = GetSnapshotRecoveryCapability(ctx, *host.owner);
            Check(HeldImageBytes(host) == before && Bytes(ctx.tx_journal_file) == wal && ctx.tx_manager->Watermarks().accepted_sequence == marks.accepted_sequence,
                "read-only disabled recovery projection preserves held image and original receipt");
            const auto response = AuthenticatedRecovery(host, image + ".control");
            if (frozen_red)
            {
                Check(!eligible && response.find("error\nSnapshotSessionNotWritable\n") != std::string::npos &&
                    HeldImageBytes(host) == before && Bytes(ctx.tx_journal_file) == wal && !ctx.native_write_enabled,
                    "RED original production-disabled owner cannot recover through authenticated controller");
                std::cout << "RED " << image << " actual controller SnapshotSessionNotWritable\n";
                continue;
            }
            Check(eligible && response.find("ok\nSnapshotRecovered\n") != std::string::npos,
                "GREEN disabled original owner authenticated recovery: " + response);
            Check(ctx.native_write_enabled && !ctx.recovery_active && !ctx.write_degraded && !ctx.pending_native_writes &&
                ctx.tx_manager->ValidatedCleanJournalGeneration() && ctx.tx_manager->ConfiguredVolumeIdentity() == configured &&
                ctx.tx_journal_file == journal_path && ctx.recovery_marker_file == marker_path, "restoration only after original owner completion");
            const auto after = ctx.tx_manager->Watermarks();
            Check(after.accepted_sequence == marks.accepted_sequence && after.accepted_sequence == after.apfs_durable_sequence &&
                after.accepted_sequence == after.cleanup_sequence, "exact original acceptance converges without new acceptance");
            RecoveryMarkerState clean;
            Check(TryLoadRecoveryMarkerState(marker_path, clean) && !clean.dirty && clean.last_commit_xid == host.owner->CheckpointXid(),
                "original production marker durable clean checkpoint");
            Check(host.Inventory().snapshots.size() == (deleting ? 0u : 1u) && LiveBytes(*host.owner, L"\\clone0") == payload &&
                Bytes(peer.tx_journal_file) == peer_wal, "exact inventory, selected payload and original sibling journal");
            std::vector<std::byte> observed_peer;
            Check(peer.metadata_store->ReadCommittedFileRange(L"\\clone0", 0, peer_inode->logical_size, observed_peer) && observed_peer == peer_payload,
                "original sibling payload survives recovery");
            VerifyBootstrapPeers(host, !deleting);
            Check(AuthenticatedRecovery(host, image + ".lost-reply-retry").find("ok\nSnapshotRecoverNoOp\n") != std::string::npos &&
                ctx.native_write_enabled && Bytes(ctx.tx_journal_file) != wal, "lost terminal reply retries as honest healthy no-op");
        }
        if (!frozen_red)
        {
            HostSnapshots reopened(image, true, true, true);
            Check(reopened.Context().native_write_enabled && !reopened.Context().tx_manager->HasUnappliedAcceptedWork() &&
                AuthenticatedRecovery(reopened, image + ".second-open").find("ok\nSnapshotRecoverNoOp\n") != std::string::npos,
                "second original production startup and recovery honest clean no-op");
        }
    }
    if (!frozen_red)
    {
        SeedBootstrapSnapshot("bootstrap-automatic.apfs", false);
        HostSnapshots automatic("bootstrap-automatic.apfs", true, true, true, true);
        Check(automatic.Context().native_write_enabled && !automatic.Context().recovery_active &&
            !automatic.Context().tx_manager->HasUnappliedAcceptedWork() && automatic.Inventory().snapshots.size() == 1,
            "ReplayIfSafe production bootstrap uses typed snapshot dispatch");
        VerifyBootstrapPeers(automatic, true);
    }
    std::cout << (frozen_red ? "PASS frozen production RED matrix\n" : "PASS production disabled create/delete, marker/no-prior-marker, automatic replay and lost-reply recovery\n");
}

#ifdef APFSACCESS_RETAINED_SNAPSHOT_COMPLETION
void HostBootstrapNegatives()
{
    const std::vector<std::string> cases = {"opt-out","raw-profile","encrypted","fusion","view","readonly","overlay",
        "path","offset","uuid","oid","journal-path","missing-lease","peer-debt","peer-reservation","mixed-receipt",
        "invalid-marker","ahead-marker","blocked-identity","missing-peer","drain","callback","peer-degraded","spool-dirty","spool-missing"};
    for (const auto& test : cases)
    {
        const auto image = "refused-" + test + ".apfs";
        SeedBootstrapSnapshot(image, false);
        HostSnapshots host(image, true, true, true);
        auto& ctx = host.Context();
        auto& peer = *host.contexts.back();
        const auto first_path = ctx.tx_journal_file;
        std::unique_ptr<Tx> original_journal;
        if (test == "opt-out") ctx.args.enable_image_snapshots = false;
        if (test == "raw-profile") ctx.args.allow_raw_physical_write = true;
        if (test == "encrypted") ctx.args.encrypted.enabled = true;
        if (test == "fusion") ctx.args.fusion.enabled = true;
        if (test == "view") ctx.args.snapshot_xid = 7;
        if (test == "readonly") ctx.args.readwrite = false;
        if (test == "overlay") ctx.args.write_backend = L"Overlay";
        if (test == "path") ctx.args.device += L"-other";
        if (test == "offset") ctx.args.device_offset_bytes = 4096;
        if (test == "uuid") ctx.args.container_id = std::wstring(32, L'f');
        if (test == "oid") ctx.args.volume_object_id = 102;
        if (test == "journal-path") ctx.tx_journal_file += L"-other";
        if (test == "missing-lease") { original_journal = std::move(ctx.tx_manager); ctx.tx_manager = std::make_unique<Tx>(L"Strict"); }
        if (test == "peer-debt") Check(peer.tx_manager->Begin(), "real peer unaccepted journal debt");
        if (test == "peer-reservation") Check(peer.metadata_store->AllocateExtent(4096).has_value(), "real peer allocator reservation");
        if (test == "mixed-receipt")
        {
            Tx::MutationIntent other; other.kind = Tx::MutationKind::CreateDirectory; other.path = L"\\foreign-successor";
            Check(ctx.tx_manager->Begin() && ctx.tx_manager->RecordMutation(other) && ctx.tx_manager->Accept(host.owner->CheckpointXid()),
                "native valid mixed accepted suffix for refusal");
        }
        if (test == "invalid-marker" || test == "ahead-marker")
        {
            std::ofstream marker(ctx.recovery_marker_file, std::ios::binary | std::ios::trunc);
            if (test == "invalid-marker") marker << "untrusted=1\n";
            else marker << "dirty=1\nlastCommitXid=" << host.owner->CheckpointXid() + 100 << '\n';
            marker.close();
            if (test == "invalid-marker") (void)LoadRecoveryMarkerAtStartup(ctx);
        }
        if (test == "blocked-identity") ctx.recovery_identity_blocked = true;
        if (test == "missing-peer") ctx.container_session_contexts.pop_back();
        if (test == "drain") ctx.mutation_admission_state = 1ull << 63;
        if (test == "callback") ctx.mutation_admission_state = 1;
        if (test == "peer-degraded") peer.write_degraded = true;
        if (test == "spool-missing") ctx.payload_spool.reset();
        if (test == "spool-dirty")
        {
            const std::vector<std::byte> payload(4096, std::byte{0x6c});
            Check(ctx.payload_spool->Append({ctx.payload_spool_volume_identity, 17, host.owner->CheckpointXid(), 0,
                ctx.tx_manager->Watermarks().accepted_sequence + 1, payload}), "real original dirty spool evidence");
        }
        const auto before = HeldImageBytes(host);
        const auto first = Bytes(first_path), second = Bytes(peer.tx_journal_file);
        const auto marks = original_journal ? original_journal->Watermarks() : ctx.tx_manager->Watermarks();
        Check(!GetSnapshotRecoveryCapability(ctx, *host.owner), "disabled original negative capability: " + test);
        const auto response = AuthenticatedRecovery(host, test + ".control");
        const auto after = original_journal ? original_journal->Watermarks() : ctx.tx_manager->Watermarks();
        Check(response.find("\nerror\n") != std::string::npos && !ctx.native_write_enabled &&
            HeldImageBytes(host) == before && Bytes(first_path) == first && Bytes(peer.tx_journal_file) == second &&
            marks.accepted_sequence == after.accepted_sequence && marks.apfs_durable_sequence == after.apfs_durable_sequence &&
            marks.cleanup_sequence == after.cleanup_sequence, "actual authenticated refusal preserves held image, both original WALs and watermarks: " + test);
        std::cout << "PASS bootstrap refusal " << test << '\n';
    }
}

void HostBootstrapCompletionRetry()
{
    for (bool readback : {false, true})
    {
        const auto image = std::string(readback ? "marker-readback-failure.apfs" : "marker-write-failure.apfs");
        SeedBootstrapSnapshot(image, false);
        HostSnapshots host(image, true, true, true);
        auto& ctx = host.Context();
        const auto sequence = ctx.tx_manager->Watermarks().accepted_sequence;
        ctx.test_force_recovery_marker_finalize_failure = !readback;
        ctx.test_force_snapshot_marker_readback_failure = readback;
        const auto failed = AuthenticatedRecovery(host);
        Check(failed.find(readback ? "SnapshotRecoveryMarkerReadbackFailed" : "SnapshotRecoveryMarkerCompletionFailed") != std::string::npos &&
            !ctx.native_write_enabled && ctx.write_degraded && ctx.recovery_active, "injected marker failure after native Finalize remains blocked");
        const auto marks = ctx.tx_manager->Watermarks();
        Check(marks.accepted_sequence == sequence && marks.cleanup_sequence == sequence && marks.apfs_durable_sequence == sequence &&
            ctx.snapshot_recovery_completion_intent && ctx.snapshot_recovery_completion_clean_generation,
            "original typed proof retained in actual owner after receipt cleanup");
        const auto image_after = HeldImageBytes(host), wal_after = Bytes(ctx.tx_journal_file);
        ctx.test_force_recovery_marker_finalize_failure = false;
        ctx.test_force_snapshot_marker_readback_failure = false;
        Check(GetSnapshotRecoveryCapability(ctx, *host.owner), "same-owner completion retry proves clean original WAL and native publication");
        const auto retry = AuthenticatedRecovery(host, "completion-retry");
        Check(retry.find("ok\nSnapshotRecovered\n") != std::string::npos && ctx.native_write_enabled &&
            !ctx.snapshot_recovery_completion_intent && HeldImageBytes(host) == image_after && Bytes(ctx.tx_journal_file) == wal_after &&
            ctx.tx_manager->Watermarks().accepted_sequence == sequence, "same-owner marker retry restores RW without new receipt/image/WAL writes");
        VerifyBootstrapPeers(host, true);
        std::cout << "PASS original-owner " << (readback ? "marker readback" : "marker write") << " failure retry after Finalize\n";
    }
    for (bool deleting : {false, true})
    {
        const auto image = std::string(deleting ? "process-loss-delete.apfs" : "process-loss-create.apfs");
        SeedBootstrapSnapshot(image, deleting);
        std::vector<std::byte> published, original_wal;
        {
            HostSnapshots interrupted(image, true, true, true);
            auto& ctx = interrupted.Context();
            ctx.test_force_recovery_marker_finalize_failure = true;
            Check(AuthenticatedRecovery(interrupted).find("SnapshotRecoveryMarkerCompletionFailed") != std::string::npos &&
                ctx.tx_manager->CanClearRecoveryState(), "process-loss boundary: native cleanup durable, host marker incomplete");
            published = HeldImageBytes(interrupted); original_wal = Bytes(ctx.tx_journal_file);
        }
        HostSnapshots restarted(image, true, true, true);
        auto& ctx = restarted.Context();
        Check(!ctx.native_write_enabled && !ctx.snapshot_recovery_completion_intent && GetSnapshotRecoveryCapability(ctx, *restarted.owner),
            "fresh owner uses existing native terminal receipt, without retained memory or manufactured acceptance");
        Check(AuthenticatedRecovery(restarted, "process-loss-retry").find("ok\nSnapshotRecovered\n") != std::string::npos &&
            ctx.native_write_enabled && HeldImageBytes(restarted) == published && Bytes(ctx.tx_journal_file) == original_wal,
            "safe restart closes post-clean/pre-marker interruption without image or WAL mutation");
        VerifyBootstrapPeers(restarted, !deleting);
        std::cout << "PASS process-loss " << (deleting ? "delete" : "create") << " terminal original WAL marker retry\n";
    }
    for (unsigned fail_at : {1u, 2u})
    {
        const auto image = "cleanup-flush-" + std::to_string(fail_at) + ".apfs";
        SeedBootstrapSnapshot(image, false);
        {
            HostSnapshots interrupted(image, true, true, true);
            auto& ctx = interrupted.Context();
            ctx.tx_manager->SetJournalFaultInjectionHook([count=0u, fail_at](std::string_view stage) mutable {
                return stage == "durable-flush" && ++count == fail_at;
            });
            Check(AuthenticatedRecovery(interrupted).find("SnapshotRuntimeCleanupFailed") != std::string::npos && !ctx.native_write_enabled,
                "actual native watermark durable flush failure refuses writer restoration");
        }
        HostSnapshots restarted(image, true, true, true);
        Check(GetSnapshotRecoveryCapability(restarted.Context(), *restarted.owner), "safe restart revalidates original cleanup fault proof");
        Check(AuthenticatedRecovery(restarted, "cleanup-retry").find("ok\nSnapshotRecovered\n") != std::string::npos && restarted.Context().native_write_enabled,
            "actual native cleanup failure restart retry succeeds without manual flag restoration");
        std::cout << "PASS original native watermark flush " << fail_at << " failure retry\n";
    }
}

void ServeBootstrapOwner(const std::filesystem::path& handshake, bool deleting = true)
{
    Check(handshake.is_absolute() && handshake.wstring().starts_with(L"D:"), "D: real native witness handshake");
    SeedBootstrapSnapshot("service-bootstrap.bin", deleting);
    HostSnapshots host("service-bootstrap.bin", true, true, true);
    auto& ctx = host.Context();
    Check(!ctx.native_write_enabled && GetSnapshotRecoveryCapability(ctx, *host.owner), "real disabled native owner ready for Service Fix");
    for (auto& c : host.contexts) { c->manifest_mount_attached = true; c->mount_ready = true; }
    Arguments process;
    process.container_control_file = std::filesystem::absolute("service.control").wstring();
    process.container_control_token = std::wstring(64, L'b');
    process.status_file = std::filesystem::absolute("service.status.json").wstring();
    const auto stop = std::filesystem::absolute("service.stop");
    Check(WriteContainerStatusFile(process, *host.owner, host.contexts), "actual native witness initial status");
    const auto* view = ctx.metadata_store->AuthoritativeAppleCheckpointView();
    const auto volume = std::find_if(view->volumes.begin(), view->volumes.end(), [](const auto& v) { return v.superblock.object_id == 101; });
    std::ofstream ready(handshake, std::ios::binary);
    ready << "{\"source\":\"" << EscapeJson(WideToUtf8(ctx.args.device)) << "\",\"volumeUuid\":\"" << volume->superblock.uuid_hex
        << "\",\"storeSizeBytes\":" << ctx.metadata_store->Device().GetGeometry().total_bytes
        << ",\"statusFile\":\"" << EscapeJson(WideToUtf8(process.status_file))
        << "\",\"controlFile\":\"" << EscapeJson(WideToUtf8(process.container_control_file))
        << "\",\"stopFile\":\"" << EscapeJson(WideToUtf8(stop.wstring()))
        << "\",\"headless\":true}";
    ready.close();
    Check(!!ready, "actual original-owner handshake persisted");
    const auto deadline = GetTickCount64() + 180000;
    while (!std::filesystem::exists(stop) && GetTickCount64() < deadline)
    {
        (void)ProcessContainerControlRequest(process, *host.owner, host.contexts);
        Check(WriteContainerStatusFile(process, *host.owner, host.contexts), "fresh native witness owner status");
        Sleep(50);
    }
    Check(std::filesystem::exists(stop), "managed witness clean stop request within deadline");
    Check(ctx.native_write_enabled && !ctx.recovery_active && ctx.tx_manager->CanClearRecoveryState(), "witness terminal recovery/durability clean");
    VerifyBootstrapPeers(host, !deleting);
    std::cout << "PASS genuine native PID authenticated Backend/Service retained-owner chain and clean teardown\n";
}
#endif
}

#include "PhysicalSnapshotInventoryTests.h"

int main(int argc, char** argv)
{
    try
    {
        const auto root = std::filesystem::current_path() / ("live-snapshot-" + std::to_string(GetCurrentProcessId()));
        Check(root.wstring().starts_with(L"D:"), "D: test root required");
        Check(std::filesystem::create_directory(root), "fresh private test directory");
        std::filesystem::current_path(root);
        if (argc == 2 && std::string_view(argv[1]) == "--test-physical-inventory") { HostPhysicalSnapshotInventory(); HostPhysicalSnapshotInventoryAdmission(); return 0; }
        if (argc == 2 && std::string_view(argv[1]) == "--test-physical-inventory-admission") { HostPhysicalSnapshotInventoryAdmission(); return 0; }
        if (argc == 2 && std::string_view(argv[1]) == "--test-bootstrap-red") { HostBootstrapRecovery(true); return 0; }
        if (argc == 2 && std::string_view(argv[1]) == "--test-bootstrap-recovery") { HostBootstrapRecovery(); return 0; }
#ifdef APFSACCESS_RETAINED_SNAPSHOT_COMPLETION
        if (argc == 2 && std::string_view(argv[1]) == "--test-bootstrap-completion-retry") { HostBootstrapCompletionRetry(); return 0; }
        if (argc == 2 && std::string_view(argv[1]) == "--test-bootstrap-negatives") { HostBootstrapNegatives(); return 0; }
        if (argc == 3 && std::string_view(argv[1]) == "--serve-bootstrap") { ServeBootstrapOwner(Utf8ToWide(argv[2])); return 0; }
        if (argc == 3 && std::string_view(argv[1]) == "--serve-bootstrap-create") { ServeBootstrapOwner(Utf8ToWide(argv[2]), false); return 0; }
        if (argc == 3 && std::string_view(argv[1]) == "--emit-detached-status") { EmitInactiveMemberStatus(Utf8ToWide(argv[2]), true); return 0; }
        if (argc == 3 && std::string_view(argv[1]) == "--emit-unready-status") { EmitInactiveMemberStatus(Utf8ToWide(argv[2]), false); return 0; }
#endif
        if (argc == 2 && std::string_view(argv[1]) == "--test-stale-delete-bytes") { HostLifecycle(); HostPeerPublication(); return 0; }
        if (argc == 2 && std::string_view(argv[1]) == "--test-recovery-capability") { HostRecovery(); return 0; }
        if (argc == 2 && std::string_view(argv[1]) == "--test-post-snapshot-peer-write") { HostPeerPublication(true); return 0; }
        if (argc == 2 && std::string_view(argv[1]) == "--test-peer-publication") { HostPeerPublication(); HostPeerRefusals(); return 0; }
        HostWire(); HostImageArguments(); HostLifecycle(); HostNegatives(); HostRecovery(); HostPeerPublication(); HostPeerRefusals();
        std::cout << "PASS live snapshot control focused suite\n";
        return 0;
    }
    catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
