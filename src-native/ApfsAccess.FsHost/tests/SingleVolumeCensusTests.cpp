// Real ordinary-image engine and original WALs, with no device or WinFsp mounts.
#define APFSACCESS_FSHOST_UNIT_TEST 1
#include "../src/main.cpp"
namespace { using BtreeRecord = apfsaccess::catalog::BtreeRecord; }
#define SNAPSHOT_RUNTIME_TEST_HELPERS_ONLY
#include "SnapshotRuntimeTests.cpp"

namespace {
unsigned assertions = 0;
void Verify(bool ok, const std::string& why) { ++assertions; Check(ok, why); }

BuilderStore CensusSpec(unsigned count)
{
    auto spec = RuntimeSpec();
    if (count == 3) {
        auto peer = spec.volumes[1]; peer.oid = 103; peer.uuid_hex = std::string(32, 'd');
        for (auto& record : peer.filesystem_records) if (Type(record) == 8) PutU64LE(record.value, 8, 544);
        PutU64LE(peer.extentref_records[0].key, 0, (2ull << 60) | 544);
        spec.volumes.push_back(peer);
        for (unsigned i = 0; i < 4; ++i)
            spec.authoritative_seeded_main_blocks.push_back({544 + i, std::vector<std::byte>(kBlockSize, std::byte(110 + i))});
    }
    return spec;
}

struct Cohort {
    std::unique_ptr<Owner> owner;
    std::vector<std::unique_ptr<MountContext>> contexts;
    Cohort(const std::filesystem::path& image, unsigned count, bool initialize = true) {
        std::string error;
        owner = Owner::Open(image.string(), 0, error, CatalogLoadPolicy::StrictApple, true, true);
        Verify(!!owner, "ordinary owner: " + error);
        for (unsigned index = 0; index < count; ++index) {
            auto context = std::make_unique<MountContext>(); auto& c = *context;
            c.args.device = image.wstring(); c.args.volume_object_id = 101 + index;
            c.args.container_id = Utf8ToWide(owner->ContainerUuidHex()); c.args.container_manifest = L"private-fixture";
            c.args.recovery_identity = L"apfs-recovery-v1-" + std::wstring(42, wchar_t(L'A' + index)) + L"A";
            c.args.volume = L"Data"; c.args.readwrite = true; c.args.readonly = false;
            c.args.initially_active = index == 0; c.args.mount = index == 0 ? L"R:\\" : L"";
            c.args.write_backend = L"Native"; c.args.write_require_canonical_commit = true;
            c.args.allow_legacy_scaffold_for_fixtures = false; c.native_write_enabled = true;
            c.tx_journal_file = image.wstring() + L"." + std::to_wstring(101 + index) + L".wal";
            c.tx_manager = std::make_unique<Tx>(L"Strict");
            c.tx_manager->SetVolumeIdentity(c.args.recovery_identity);
            c.tx_manager->SetJournalPath(c.tx_journal_file.wstring());
            Verify(c.tx_manager->EnrollCanonicalJournalIdentity(L"apfs-vol:" + c.args.container_id + L":" + std::to_wstring(101 + index)), "canonical enrollment");
            Verify(c.tx_manager->AcquireJournalOwnership(error), "original WAL owner: " + error);
            std::wstring mount_error;
            Verify(MountManifestSession(*owner, c.args, c, mount_error), "session: " + WideToUtf8(mount_error));
            contexts.push_back(std::move(context));
        }
        if (initialize) Verify(InitializeManifestCheckpointCensus(*owner, contexts, error), "complete census: " + error);
    }
    ~Cohort() { contexts.clear(); owner.reset(); }
};

void SelectedWrite(const std::filesystem::path& root, unsigned count)
{
    auto path = root / ("selected-" + std::to_string(count) + ".img"); Fresh(path, CensusSpec(count));
    Cohort h(path, count); std::string error;
    Verify(ValidateManifestCensusAfterRecovery(*h.owner, h.contexts, error), "clean cohort admission: " + error);
    const auto before = h.owner->CheckpointXid();
    std::vector<std::vector<std::byte>> peer_payloads;
    for (unsigned i = 1; i < count; ++i) {
        auto& peer = *h.contexts[i];
        Verify(peer.args.mount.empty() && !peer.fs && !peer.manifest_mount_attached && !IsMutationWriteEnabled(&peer), "dormant no alias and mutation access denied");
        std::vector<std::byte> bytes;
        Verify(peer.metadata_store->ReadCommittedFileRange(L"\\clone0", 0, 16, bytes), "peer payload readable internally");
        peer_payloads.push_back(bytes);
    }
    Store::MutationRequest write; write.operation = Store::MutationOperation::Write;
    write.path = L"\\clone0"; write.offset = 0; write.length = 4 * kBlockSize;
    Live(*h.owner, *h.contexts[0]->tx_manager, write, std::vector<std::byte>(4 * kBlockSize, std::byte{0x42}));
    Verify(h.owner->CheckpointXid() > before, "selected write published real checkpoint");
    for (unsigned i = 1; i < count; ++i) {
        Verify(h.owner->RefreshSessionForRecovery(101 + i, error), "refresh dormant peer: " + error);
        std::vector<std::byte> bytes;
        Verify(h.contexts[i]->metadata_store->ReadCommittedFileRange(L"\\clone0", 0, 16, bytes) && bytes == peer_payloads[i - 1], "peer data unchanged across shared publication");
        Verify(h.contexts[i]->tx_manager->Watermarks().accepted_sequence == 0, "no fabricated peer transaction");
    }
    Verify(h.owner->CheckpointCensusSnapshot().size() == count, "full census retained after selected commit");
    Arguments process; process.status_file = (root / ("status-" + std::to_string(count) + ".json")).wstring();
    Verify(WriteContainerStatusFile(process, *h.owner, h.contexts), "all contexts status publication");
    std::ifstream status(std::filesystem::path{process.status_file}); std::string text((std::istreambuf_iterator<char>(status)), {});
    Verify(text.find("\"objectId\":102") != text.npos && text.find("\"mountPoint\":\"\"") != text.npos, "dormant visible in census status with empty mount");
}

void Refusals(const std::filesystem::path& root)
{
    auto path = root / "refusals.img"; Fresh(path);
    Cohort h(path, 2, false); std::string error;
    auto peer = std::move(h.contexts.back()); h.contexts.pop_back();
    Verify(!InitializeManifestCheckpointCensus(*h.owner, h.contexts, error) && error.find("Incomplete") != error.npos, "missing peer refused");
    Verify(!h.owner->Commit(101, {}).committed, "census publication guard retained");
    h.contexts.push_back(std::move(peer));
    auto saved_oid = h.contexts[1]->container_volume_oid; h.contexts[1]->container_volume_oid = 101;
    Verify(!InitializeManifestCheckpointCensus(*h.owner, h.contexts, error), "duplicate peer refused");
    h.contexts[1]->container_volume_oid = saved_oid;
    auto saved_tx = std::move(h.contexts[1]->tx_manager);
    Verify(!InitializeManifestCheckpointCensus(*h.owner, h.contexts, error) && error == "ManifestCheckpointJournalUnavailable", "missing original WAL context refused");
    h.contexts[1]->tx_manager = std::move(saved_tx);
    auto& dormant = *h.contexts[1];
    Tx::MutationIntent intent; intent.kind = Tx::MutationKind::CreateFile; intent.path = L"\\accepted-original.bin";
    Verify(dormant.tx_manager->Begin() && dormant.tx_manager->RecordMutation(intent) && dormant.tx_manager->Accept(h.owner->CheckpointXid()), "original dormant accepted WAL seeded");
    const auto image_before = Bytes(path); const auto wal_before = Bytes(dormant.tx_journal_file);
    Verify(InitializeManifestCheckpointCensus(*h.owner, h.contexts, error), "accepted debt enters census");
    Verify(!ValidateManifestCensusAfterRecovery(*h.owner, h.contexts, error) && error.find("oid=102") != error.npos, "unreconciled original debt blocks startup with peer reason");
    Verify(!h.owner->Commit(101, {}).committed, "selected publication cannot bypass peer debt");
    Verify(Bytes(path) == image_before && Bytes(dormant.tx_journal_file) == wal_before, "refusal preserves original image and journal bytes");
    Verify(dormant.tx_manager->HasUnappliedAcceptedWork(), "refusal does not acknowledge peer debt");
}

void ActivationAndDrain(const std::filesystem::path& root)
{
    auto path = root / "activation.img"; Fresh(path); Cohort h(path, 2); std::string error;
    auto& peer = *h.contexts[1]; ContainerControlRequest request;
    Verify(SnapshotCreateForControl(peer, *h.owner, request).code == "SnapshotSessionNotWritable" &&
        SnapshotDeleteForControl(peer, *h.owner, request).code == "SnapshotSessionNotWritable",
        "dormant peer rejects new snapshot mutations");
    peer.args.enable_raw_snapshots = true;
    Verify(SnapshotCreateForControl(peer, *h.owner, request).code == "SnapshotSessionNotWritable" &&
        SnapshotDeleteForControl(peer, *h.owner, request).code == "SnapshotSessionNotWritable",
        "dormant raw-profile control rejects before any media access");
    peer.args.enable_raw_snapshots = false;
    const std::string prefix = "APFS-CONTROL/1\n" + std::string(32, 'a') + "\n" + std::string(64, 'b') + "\n";
    Verify(ParseContainerControlRequestContents(prefix + "activate\n102\nT:\\\nR\n", std::string(64, 'b'), request, error), "authenticated activation selects current letter and RO mode");
    Verify(!request.activation_write && request.activation_mount == L"T:\\", "activation mode parsed exactly");
    Verify(!ParseContainerControlRequestContents(prefix + "attach\n102\nT:\\\nW\n", std::string(64, 'b'), request, error), "old attach rejects mode/target extension");
    Verify(ParseContainerControlRequestContents(prefix + "activate\n102\nT:\\\nR\n", std::string(64, 'b'), request, error), "activation reparsed");
    Verify(ValidateDormantActivation(peer, h.contexts, request, 0, error), "clean current target allowed");
    Verify(!ValidateDormantActivation(peer, h.contexts, request, DWORD{1} << (L'T' - L'A'), error), "current occupied letter refused");
    request.activation_mount = L"R:\\";
    Verify(!ValidateDormantActivation(peer, h.contexts, request, 0, error), "live sibling target refused");
    request.activation_mount = L"T:\\"; peer.write_degraded = true;
    Verify(!ValidateDormantActivation(peer, h.contexts, request, 0, error), "changed recovery admission refuses activation");
    peer.write_degraded = false;
    const auto original_identity = BuildWalVolumeIdentity(peer.args);
    const auto original_root = BuildPayloadSpoolSessionRoot(peer.args, root / "spool");
    auto activated = peer.args; activated.initially_active = true; activated.mount = L"T:\\";
    activated.readwrite = false; activated.readonly = true;
    Verify(BuildWalVolumeIdentity(activated) == original_identity &&
        BuildPayloadSpoolSessionRoot(activated, root / "spool") == original_root,
        "late RO activation retains original recovery namespace and WAL identity");
    auto original = peer.args; peer.args = activated; peer.native_write_enabled = false;
    FSP_FSCTL_VOLUME_PARAMS parameters{}; FILETIME instant{};
    ConfigureVolumeParamsForExplorer(peer, instant, parameters);
    Verify(parameters.ReadOnlyVolume && !IsMutationWriteEnabled(&peer), "late RO mode cannot inherit dormant write admission");
    Verify(SnapshotCreateForControl(peer, *h.owner, request).code == "SnapshotSessionNotWritable" &&
        SnapshotDeleteForControl(peer, *h.owner, request).code == "SnapshotSessionNotWritable",
        "late RO activation rejects new snapshot mutations");
    peer.args = original; peer.native_write_enabled = true;
    FILETIME now{};
    Verify(!AttachManifestMountForControl(h.contexts[1], now).success, "legacy attach cannot expose dormant namespace");
    FSP_FILE_SYSTEM sentinel{};
    h.contexts[0]->fs = &sentinel; h.contexts[0]->manifest_mount_attached = true;
    Verify(HasActiveManifestNamespace(h.contexts), "active selected namespace keeps owner");
    h.contexts[0]->fs = nullptr; h.contexts[0]->manifest_mount_attached = false;
    Verify(!HasActiveManifestNamespace(h.contexts), "dormant peer cannot keep last-active owner alive");
    Verify(DetachManifestMountForControl(h.contexts[1]).code == "AlreadyDetached", "dormant detach cannot claim mounted sibling proof");
    Arguments process; process.status_file = (root / "terminal.json").wstring();
    Verify(SettleFailedManifestInitialization(process, *h.owner, h.contexts), "all initialized contexts drain and release image lease");
    Verify(std::all_of(h.contexts.begin(), h.contexts.end(), [](const auto& c) { return !c->metadata_store && !c->container_coordinator && !c->fs; }), "drain cleared every borrowed context");
}

void HydrationIsolation(const std::filesystem::path& root, bool compact)
{
    const auto path = root / (compact ? "hydrate-compact.img" : "hydrate-normal.img");
    Fresh(path, CensusSpec(3)); Cohort h(path, 3);
    const auto tick = GetTickCount64();
    Node node; node.path = L"\\same-file.bin";
    std::vector<std::filesystem::path> sessions, payloads;
    for (auto& c : h.contexts) {
        c->args.volume = compact ? std::wstring(240, L'D') : L"Data";
        Verify(InitializeSessionPaths(c.get(), tick), "same-tick session paths initialized");
        sessions.push_back(c->session_root); payloads.push_back(HydrationPath(c.get(), node));
        Verify((c->session_root.filename().wstring().rfind(L"session_", 0) == 0) == compact,
            "requested normal or compact path branch exercised");
    }
    Verify(sessions[0] != sessions[1] && sessions[0] != sessions[2] && sessions[1] != sessions[2],
        "same-name same-tick three-volume session roots isolated");
    Verify(payloads[0] != payloads[1] && payloads[0] != payloads[2] && payloads[1] != payloads[2],
        "equal-path peer hydration files isolated");
    for (unsigned i = 0; i < 3; ++i) { std::ofstream file(payloads[i]); file << "volume-" << i; }
    for (unsigned i = 1; i < 3; ++i) {
        auto& peer = *h.contexts[i]; ContainerControlRequest request; std::string error;
        request.activation_mount = i == 1 ? L"T:\\" : L"U:\\"; request.activation_write = i == 2;
        Verify(ValidateDormantActivation(peer, h.contexts, request, 0, error), "current RO/RW activation admitted: " + error);
        peer.args.mount = request.activation_mount; peer.args.initially_active = true;
        peer.args.readwrite = request.activation_write; peer.args.readonly = !request.activation_write;
        peer.native_write_enabled = request.activation_write;
        Verify(peer.session_root == sessions[i] && HydrationPath(&peer, node) == payloads[i],
            "late RO/RW activation retains original hydration binding");
        MountContext repeated; repeated.args = peer.args;
        Verify(InitializeSessionPaths(&repeated, tick) && repeated.session_root == sessions[i] &&
            HydrationPath(&repeated, node) == payloads[i], "session identity independent of current mode and letter");
        Verify(IsMutationWriteEnabled(&peer) == request.activation_write && !peer.fs && !peer.manifest_mount_attached,
            "RO/RW guarantee checked without exposing a namespace");
    }
    MountContext rebound; rebound.args = h.contexts[1]->args;
    rebound.args.recovery_identity = h.contexts[2]->args.recovery_identity;
    Verify(InitializeSessionPaths(&rebound, tick) && rebound.session_root != sessions[1] &&
        rebound.session_root != sessions[2], "OID and original recovery binding each distinguish session identity");
    CleanupHydrationSession(&rebound);
    CleanupHydrationSession(h.contexts[0].get());
    for (unsigned i = 1; i < 3; ++i) {
        std::string bytes;
        { std::ifstream file(payloads[i]); file >> bytes; }
        Verify(bytes == "volume-" + std::to_string(i), "selected cleanup preserves distinct peer cache bytes");
        CleanupHydrationSession(h.contexts[i].get());
    }
    Verify(std::all_of(sessions.begin(), sessions.end(), [](const auto& p) { return !std::filesystem::exists(p); }),
        "all initialized hydration sessions drained independently");
}

void DormantOriginalReplay(const std::filesystem::path& root)
{
    const auto path = root / "replay.img"; Fresh(path); Cohort h(path, 2, false);
    auto& peer = *h.contexts[1]; std::string error;
    Store::MutationRequest create; create.operation = Store::MutationOperation::CreateFile; create.path = L"\\original-accepted";
    Store::PayloadIdentity identity;
    Verify(peer.metadata_store->StageMutation(create, &identity) == Store::MutationStatus::Applied, "seed original staged identity");
    Tx::MutationIntent intent; intent.kind = Tx::MutationKind::CreateFile; intent.path = create.path;
    intent.object_id = identity.object_id; intent.generation = identity.generation;
    Verify(peer.tx_manager->Begin() && peer.tx_manager->RecordMutation(intent) &&
        peer.tx_manager->Accept(h.owner->CheckpointXid()), "original accepted transaction");
    const auto accepted = peer.tx_manager->Watermarks().accepted_sequence;
    Verify(h.owner->UnmountVolume(102, error), "discard unpublished store for restart"); peer.metadata_store = nullptr;
    std::wstring mount_error;
    Verify(MountManifestSession(*h.owner, peer.args, peer, mount_error), "restore dormant original context");
    Verify(InitializeManifestCheckpointCensus(*h.owner, h.contexts, error), "recovery sees complete original census");
    Verify(!ValidateManifestCensusAfterRecovery(*h.owner, h.contexts, error), "accepted debt initially blocks selected startup");
    peer.args.write_crash_replay_mode = L"ReplayIfSafe";
    peer.recovery_marker_file = root / "peer-replay.marker";
    Verify(ReplayAcceptedWriteAheadLogAfterMetadataBootstrap(peer), "established original replay policy handles dormant peer");
    const auto marks = peer.tx_manager->Watermarks();
    Verify(marks.accepted_sequence == accepted && marks.apfs_durable_sequence == accepted && marks.cleanup_sequence == accepted,
        "replay converges original acceptance without accepting a new mutation");
    Verify(peer.metadata_store->LookupCommittedInodeByPath(create.path).has_value() && !peer.fs && peer.args.mount.empty(), "original transaction durable with no peer namespace");
    Verify(ValidateManifestCensusAfterRecovery(*h.owner, h.contexts, error), "selected startup admitted after original recovery: " + error);
    const auto once = Bytes(path);
    Verify(ReplayAcceptedWriteAheadLogAfterMetadataBootstrap(peer) && Bytes(path) == once, "clean original replay is idempotent");
}

void Protocol(const std::filesystem::path& root)
{
    const std::string uuid(32, 'a'), device = "D:\\never-opened.img";
    auto document = [&](unsigned version, bool inactive) {
        const std::string identity = "apfs-recovery-v1-" + std::string(43, 'A');
        std::string canonical = "manifest-check-v" + std::to_string(version) + "\n" + uuid + "\n" + device + "\n0\n";
        std::string rows;
        for (unsigned i = 0; i < 2; ++i) {
            const bool active = !inactive || i == 0;
            const std::string mount = active ? (i ? "S:\\" : "R:\\") : "";
            const auto recovery = i ? "apfs-recovery-v1-" + std::string(42, 'B') + "A" : identity;
            canonical += std::to_string(101 + i) + "\n" + uuid + "\nData\n" + mount + "\nW\n" + recovery + "\n";
            if (version == 2) canonical += active ? "A\n" : "I\n";
            if (i) rows += ',';
            rows += "{\"objectId\":" + std::to_string(101 + i) + ",\"containerUuid\":\"" + uuid +
                "\",\"name\":\"Data\",\"mount\":\"" + EscapeJson(mount) + "\",\"requestedWrite\":true,\"recoveryIdentity\":\"" + recovery + "\"";
            if (version == 2) rows += std::string(",\"initiallyActive\":") + (active ? "true" : "false");
            rows += '}';
        }
        std::array<std::uint8_t, 32> hash{};
        HashPayload(std::as_bytes(std::span(canonical)), hash);
        std::string hex; constexpr char digits[] = "0123456789abcdef";
        for (auto byte : hash) { hex += digits[byte >> 4]; hex += digits[byte & 15]; }
        return "{\"format\":\"apfs-access-container-manifest\",\"version\":" + std::to_string(version) +
            ",\"containerUuid\":\"" + uuid + "\",\"device\":\"" + EscapeJson(device) +
            "\",\"deviceOffsetBytes\":0,\"manifestSha256\":\"" + hex + "\",\"volumes\":[" + rows + "]}";
    };
    auto parse = [&](const std::string& text, ContainerManifest& manifest) {
        const auto path = root / "protocol.json"; { std::ofstream file(path); file << text; }
        std::string error; return ParseContainerManifest(path.string(), manifest, error);
    };
    ContainerManifest manifest;
    auto old = document(1, false);
    Verify(parse(old, manifest) && manifest.volumes[1].initially_active, "old v1 digest and semantics preserved");
    auto incompatible = old; incompatible.insert(incompatible.find("\"objectId\""), "\"initiallyActive\":false,");
    Verify(!parse(incompatible, manifest), "v1 rejects unbound activation field");
    auto current = document(2, true);
    Verify(parse(current, manifest) && !manifest.volumes[1].initially_active && manifest.volumes[1].mount_point.empty(), "independent v2 checksum accepts dormant row");
    auto altered = current; auto at = altered.find("\"initiallyActive\":true");
    altered.replace(at, std::string("\"initiallyActive\":true").size(), "\"initiallyActive\":false");
    Verify(!parse(altered, manifest), "activation alteration refuses");
    auto missing = current; at = missing.find(",\"initiallyActive\":false"); missing.erase(at, std::string(",\"initiallyActive\":false").size());
    Verify(!parse(missing, manifest), "v2 missing activation refuses");
    Verify(parse(current, manifest), "restore valid v2");
    Arguments process; process.readwrite = true; process.write_backend = L"Native";
    std::vector<Arguments> volumes; std::wstring error;
    Verify(BuildManifestVolumeArgs(process, manifest, volumes, error) && volumes.size() == 2 &&
        volumes[1].mount.empty() && !volumes[1].initially_active && volumes[1].readwrite, "recovery admission without peer alias: " + WideToUtf8(error));
    process.readwrite = false;
    Verify(!BuildManifestVolumeArgs(process, manifest, volumes, error), "RO owner cannot invent dormant write admission");
}
}

int main(int argc, char** argv)
{
    try {
        Verify(argc == 2, "private output directory required");
        auto root = std::filesystem::absolute(argv[1]);
        root.make_preferred();
        Verify(root.wstring().rfind(L"D:\\", 0) == 0, "D-only fixtures");
        root /= "run-" + std::to_string(GetCurrentProcessId()) + "-" + std::to_string(GetTickCount64());
        Verify(!std::filesystem::exists(root), "fresh evidence directory required");
        std::filesystem::create_directories(root);
        std::cout << "evidence=" << root.string() << '\n';
        HydrationIsolation(root, false); HydrationIsolation(root, true);
        Protocol(root); SelectedWrite(root, 2); SelectedWrite(root, 3); Refusals(root); ActivationAndDrain(root); DormantOriginalReplay(root);
        std::cout << "PASS assertions=" << assertions << " ordinaryImagesOnly=1 deviceOpens=0 visibleMounts=0\n";
        return 0;
    } catch (const std::exception& ex) { std::cerr << "FAIL assertions=" << assertions << " " << ex.what() << '\n'; return 1; }
}
