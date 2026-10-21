#pragma once

namespace {
void HostPhysicalSnapshotInventory()
{
    const std::vector<std::wstring> command = {L"host", L"--container-manifest", L"D:\\inventory-manifest",
        L"--container-manifest-sha256", std::wstring(64, L'a'), L"--container-control-file", L"D:\\inventory-control",
        L"--container-control-token", std::wstring(64, L'b'), L"--status-file", L"D:\\inventory-status",
        L"--readwrite", L"--write-backend", L"Native", L"--parent-pid", L"123",
        L"--lifetime-file", L"D:\\inventory-life", L"--startup-gate-file", L"D:\\inventory-gate", L"--startup-gate-token", L"gate",
        L"--allow-raw-physical-write", L"--enable-retained-physical-snapshot-inventory"};
    const auto parse = [](std::vector<std::wstring> words, Arguments& args) {
        std::vector<wchar_t*> argv; for (auto& word : words) argv.push_back(word.data());
        return ParseArgs(static_cast<int>(argv.size()), argv.data(), args);
    };
    Arguments physical;
    Check(!Arguments{}.enable_retained_physical_snapshot_inventory && parse(command, physical) &&
        physical.enable_retained_physical_snapshot_inventory && !physical.enable_image_snapshots,
        "separate default-off physical parser option");
    for (const auto& addition : std::vector<std::vector<std::wstring>>{{L"--enable-image-snapshots"},
        {L"--readonly"}, {L"--enable-retained-physical-snapshot-inventory"}, {L"--snapshot-xid", L"10"},
        {L"--write-require-canonical-commit", L"false"}})
    {
        auto words = command; words.insert(words.end(), addition.begin(), addition.end());
        Arguments refused; Check(!parse(words, refused), "incompatible physical inventory options refused");
    }
    ContainerManifest manifest;
    manifest.device_path = "\\\\.\\PhysicalDrive2"; manifest.device_offset_bytes = 8192;
    manifest.container_uuid_hex = std::string(32, 'a');
    ManifestVolumeEntry member; member.object_id = 101; member.requested_write = true;
    manifest.volumes.push_back(member);
    std::vector<Arguments> volumes; std::wstring manifest_error;
    Check(BuildManifestVolumeArgs(physical, manifest, volumes, manifest_error) &&
        volumes.front().enable_retained_physical_snapshot_inventory, "physical manifest preserves inventory flag");
    manifest.device_path = "D:\\image.apfs";
    Check(!BuildManifestVolumeArgs(physical, manifest, volumes, manifest_error), "physical inventory launch refuses image path");
    Check(!BuildMetadataStoreVolumeContext(physical).allow_native_snapshot_runtime, "physical inventory never enables snapshot composer");
    Fresh("inventory-seed.apfs");
    LiveSnapshotInventory seeded;
    {
        HostSnapshots seed("inventory-seed.apfs");
        Check(seed.Create("retained-history").success, "real canonical snapshot fixture");
        seeded = seed.Inventory();
    }
    std::ifstream input("inventory-seed.apfs", std::ios::binary);
    const std::vector<char> payload{std::istreambuf_iterator<char>(input), {}};
    constexpr std::uint64_t base = 8192, tail = 12288;
    std::vector<char> wrapped(base, char(0x5a));
    wrapped.insert(wrapped.end(), payload.begin(), payload.end());
    wrapped.insert(wrapped.end(), tail, char(0x6b));
    const auto read_file = [](const char* path) {
        std::ifstream file(path, std::ios::binary);
        return std::vector<char>{std::istreambuf_iterator<char>(file), {}};
    };
    { std::ofstream file("inventory-window.apfs", std::ios::binary); file.write(wrapped.data(), wrapped.size()); }
    HostSnapshots host("inventory-window.apfs", false, true, false, false, base);
    auto& ctx = host.Context();
    auto scope = GetVolumeVerificationCapability(ctx, *host.owner);
    Check(scope.has_value() && scope->exact.store_offset_bytes == base &&
        scope->exact.store_size_bytes == payload.size(), "held nonzero window identity");
    const auto& device = host.owner->Device();
    Check(device.GetGeometry().total_bytes > scope->exact.store_size_bytes, "geometry includes sentinel suffix");
    const auto before = read_file("inventory-window.apfs");
    std::vector<std::vector<char>> journals;
    for (const auto& peer : host.contexts) journals.push_back(read_file(WideToUtf8(peer->tx_journal_file.wstring()).c_str()));
    std::string error;
    LiveSnapshotInventory inventory;
    Check(EnumerateRetainedSnapshotWindow(device, scope->exact, inventory, error), "bounded retained enumeration: " + error);
    Check(inventory.scope == scope->exact && inventory.snapshots.size() == 1 &&
        inventory.snapshots[0].identity.scope == scope->exact &&
        inventory.snapshots[0].identity.name_utf8 == "retained-history", "absolute inventory and entry scope translated once");
    const auto identity = inventory.snapshots.front().identity;
    auto relative_identity = identity;
    relative_identity.scope = seeded.scope;
    Check(relative_identity == seeded.snapshots.front().identity, "APFS identity block numbers remain container-relative");
    RetainedSnapshotInventorySource source(device, scope->exact.store_size_bytes, std::chrono::steady_clock::now() + std::chrono::seconds(5));
    std::vector<std::byte> bytes;
    Check(source.SizeBytes() == payload.size() && source.Read(0, 4096, bytes) &&
        std::memcmp(bytes.data(), payload.data(), 4096) == 0, "relative zero maps exactly to container base");
    Check(!source.Read(payload.size(), 1, bytes) && bytes.empty() &&
        !source.Read(UINT64_MAX, 4096, bytes) && !source.Read(payload.size() - 1, 2, bytes), "suffix and overflow reads refused");
    RetainedSnapshotInventorySource expired(device, payload.size(), std::chrono::steady_clock::now());
    Check(!expired.Read(0, 4096, bytes), "bounded deadline refusal");
    const auto deadline = RetainedSnapshotInventorySource::Clock::now() + std::chrono::seconds(5);
    unsigned clock_calls = 0;
    RetainedSnapshotInventorySource late(device, payload.size(), deadline, [&] {
        return ++clock_calls == 1 ? deadline - std::chrono::milliseconds(1) : deadline;
    });
    Check(!late.Read(0, 4096, bytes) && bytes.empty() && clock_calls == 2 &&
        std::string_view(late.ReadBudget()->Failure()) == "SnapshotInventoryDeadlineExpired",
        "successful device read after deadline returns no bytes");
    clock_calls = 0;
    Check(EnumerateRetainedSnapshotWindow(device, scope->exact, inventory, error, deadline, [&] {
        ++clock_calls; return deadline - std::chrono::milliseconds(1);
    }), "measure the final inventory publication clock boundary");
    const auto publication_clock_call = clock_calls;
    clock_calls = 0;
    Check(publication_clock_call > 2 &&
        !EnumerateRetainedSnapshotWindow(device, scope->exact, inventory, error, deadline, [&] {
            return ++clock_calls == publication_clock_call ? deadline : deadline - std::chrono::milliseconds(1);
        }) && inventory.snapshots.empty() && inventory.scope.volume_oid == 0 &&
        error == "SnapshotInventoryDeadlineExpired", "completed inventory cannot publish after its deadline");
    source.ReadBudget()->LimitRemainingTo(0, 0, 0, 0);
    Check(!source.Read(0, 4096, bytes) && bytes.empty() && source.ReadBudget()->Failed(),
        "advertised read allowance is enforced before held-device dispatch");
    for (const auto change : {"base", "size", "overflow", "uuid", "oid", "checkpoint"})
    {
        auto wrong = scope->exact;
        if (std::string_view(change) == "base") ++wrong.store_offset_bytes;
        if (std::string_view(change) == "size") wrong.store_size_bytes = 4096;
        if (std::string_view(change) == "overflow") wrong.store_size_bytes = UINT64_MAX;
        if (std::string_view(change) == "uuid") wrong.volume_uuid_hex = std::string(32, 'f');
        if (std::string_view(change) == "oid") wrong.volume_oid = 999;
        if (std::string_view(change) == "checkpoint") ++wrong.checkpoint_xid;
        Check(!EnumerateRetainedSnapshotWindow(device, wrong, inventory, error) && inventory.snapshots.empty(),
            std::string("wrong retained scope refused: ") + change);
    }
    ctx.args.enable_retained_physical_snapshot_inventory = true;
    ctx.args.allow_raw_physical_write = true;
    MountContext unbound;
    std::wstring mount_error;
    Check(!MountManifestSession(*host.owner, ctx.args, unbound, mount_error) &&
        mount_error == L"PhysicalSnapshotInventoryOwnerRequired", "file owner cannot enroll as physical inventory owner");
    auto path_only = ctx.args;
    path_only.device = L"\\\\.\\PhysicalDrive2";
    Check(!MountManifestSession(*host.owner, path_only, unbound, mount_error), "raw path text cannot substitute held raw authority");
    // An ordinary held file is never promoted into raw hardware authority.
    Check(!GetSnapshotControlCapabilities(ctx, *host.owner).inventory &&
        !GetSnapshotRecoveryCapability(ctx, *host.owner) && !ctx.metadata_store->Context().allow_native_snapshot_runtime,
        "physical opt-in cannot manufacture raw identity or alter composer");
    auto request = host.Request(ContainerControlAction::SnapshotList);
    Check(SnapshotListForControl(ctx, *host.owner, request).code == "SnapshotInventoryScopeRequired", "physical list requires typed scope");
    request.verification_scope = scope;
    Check(!SnapshotListForControl(ctx, *host.owner, request).success, "scoped physical list refuses held image");
    Check(!host.Create("blocked").success, "raw create stays closed");
    Check(!host.Delete(identity).success, "raw delete stays closed");
    Check(!SnapshotRecoverForControl(ctx, *host.owner, host.Request(ContainerControlAction::SnapshotRecover)).success,
        "raw recovery stays closed");
    const auto token = std::string(64, 'b');
    const auto envelope = "APFS-CONTROL/1\n" + request.request_id + "\n" + token + "\nsnapshot-list\n101\n" +
        scope->exact.container_uuid_hex + "\n" + scope->exact.volume_uuid_hex + "\n" +
        std::to_string(scope->exact.checkpoint_xid) + "\n" + std::to_string(base) + "\n" +
        std::to_string(payload.size()) + "\n" + scope->source_identity + "\n";
    ContainerControlRequest parsed;
    Check(ParseContainerControlRequestContents(envelope, token, parsed, error) && parsed.verification_scope &&
        parsed.verification_scope->exact == scope->exact, "authenticated typed list scope");
    Check(!ParseContainerControlRequestContents(envelope, std::string(64, 'c'), parsed, error), "wrong owner credential refused");
    Check(!ParseContainerControlRequestContents(envelope + "extra\n", token, parsed, error), "extra scope fields refused");
    Check(read_file("inventory-window.apfs") == before && before == wrapped, "prefix, container and suffix unchanged");
    for (std::size_t i = 0; i < journals.size(); ++i)
        Check(read_file(WideToUtf8(host.contexts[i]->tx_journal_file.wstring()).c_str()) == journals[i], "all original journals unchanged");
    std::cout << "PASS bounded retained nonzero-offset snapshot inventory, exact scope, sentinels, authority and wire refusals\n";
}

// Only immutable raw eligibility facts are supplied here. The file device,
// parser, published checkpoint, host peers, owned journals and locks stay real.
std::optional<HeldPhysicalSnapshotInventoryAuthority> FixturePhysicalInventoryAuthority(
    const MountContext& ctx, apfsaccess::catalog::ContainerMountCoordinator& owner,
    const apfsaccess::rw::MetadataStore& store, const apfsaccess::catalog::AppleCheckpointView& published,
    std::string_view fault = {})
{
    apfsaccess::catalog::ApfsSnapshotScope scope;
    std::string error;
    Check(DescribePhysicalSnapshotInventoryWindow(ctx, store, published, scope, error), "fixture window: " + error);
    auto limit = scope.store_size_bytes;
    if (fault == "base") ++scope.store_offset_bytes;
    if (fault == "nx-size") --scope.store_size_bytes;
    if (fault == "limit") --limit;
    if (fault == "zero-limit") limit = 0;
    if (fault == "oid") ++scope.volume_oid;
    std::vector<HeldPhysicalSnapshotInventoryPeer> peers;
    for (const auto* peer : ctx.container_session_contexts)
    {
        if (fault == "missing-peer-fact" && peer != &ctx) continue;
        const bool changed_peer = peer != &ctx;
        auto generation = peer->tx_manager->ValidatedCleanJournalGeneration();
        if (changed_peer && fault == "zero-journal-generation") generation = 0;
        if (changed_peer && fault == "stale-journal-generation") ++generation;
        peers.push_back({changed_peer && fault == "duplicate-peer-fact" ? &ctx : peer,
            peer->metadata_store, peer->tx_manager.get(),
            changed_peer && fault == "peer-oid" ? peer->container_volume_oid + 1 : peer->container_volume_oid,
            generation, !(changed_peer && fault == "raw-profile")});
    }
    return HeldPhysicalSnapshotInventoryAuthority{fault == "owner" ? nullptr : &owner,
        fault == "device" ? nullptr : &store.Device(), fault == "store" ? nullptr : &store,
        fault == "member" ? nullptr : &ctx,
        published.container.superblock.xid + (fault == "owner-generation" ? 1 : 0), scope, limit,
        fault == "empty-source" ? "" : fault == "source" ? "fixture-held-raw:other" : "fixture-held-raw:original",
        std::move(peers)};
}

void HostPhysicalSnapshotInventoryAdmission()
{
    Fresh("physical-admission-seed.apfs");
    std::array<LiveSnapshotInventory, 2> seeded;
    {
        HostSnapshots seed("physical-admission-seed.apfs");
        Check(seed.Create("alpha-history").success, "canonical Alpha snapshot seed");
        auto create = seed.Request(ContainerControlAction::SnapshotCreate);
        create.volume_object_id = 102; create.snapshot_name = "beta-history";
        Check(SnapshotCreateForControl(*seed.contexts[1], *seed.owner, create).success, "canonical Beta snapshot seed");
        for (std::size_t i = 0; i < seeded.size(); ++i)
        {
            auto request = seed.Request(ContainerControlAction::SnapshotList);
            request.volume_object_id = seed.contexts[i]->container_volume_oid;
            auto result = SnapshotListForControl(*seed.contexts[i], *seed.owner, request);
            Check(result.success && result.snapshot_inventory && result.snapshot_inventory->snapshots.size() == 1,
                "canonical per-member seed inventory");
            seeded[i] = *result.snapshot_inventory;
        }
    }
    constexpr std::uint64_t base = 8192, tail = 12288;
    const auto payload = Bytes("physical-admission-seed.apfs");
    std::vector<std::byte> wrapped(base, std::byte{0x5a});
    wrapped.insert(wrapped.end(), payload.begin(), payload.end());
    wrapped.insert(wrapped.end(), tail, std::byte{0x6b});
    {
        std::ofstream file("physical-admission-window.apfs", std::ios::binary);
        file.write(reinterpret_cast<const char*>(wrapped.data()), static_cast<std::streamsize>(wrapped.size()));
        Check(!!file, "nonzero-window admission fixture written");
    }
    HostSnapshots host("physical-admission-window.apfs", false, true, false, false, base);
    const auto capture = [](const auto& ctx, auto& owner, const auto& store, const auto& published) {
        return FixturePhysicalInventoryAuthority(ctx, owner, store, published);
    };
    std::array<LiveVolumeVerificationScope, 2> scopes;
    std::array<std::vector<std::byte>, 2> journals;
    std::array<const Tx*, 2> writers{};
    std::array<std::uint64_t, 2> generations{}, accepted{}, durable{}, cleanup{};
    for (std::size_t i = 0; i < host.contexts.size(); ++i)
    {
        auto& peer = *host.contexts[i];
        const auto scope = GetVolumeVerificationCapability(peer, *host.owner);
        Check(scope.has_value() && scope->exact.store_offset_bytes == base && scope->exact.store_size_bytes == payload.size(),
            "real held file window before raw fixture evidence");
        scopes[i] = *scope; scopes[i].source_identity = "fixture-held-raw:original";
        peer.args.enable_retained_physical_snapshot_inventory = true;
        peer.args.allow_raw_physical_write = true;
        journals[i] = Bytes(peer.tx_journal_file);
        writers[i] = peer.tx_manager.get(); generations[i] = writers[i]->ValidatedCleanJournalGeneration();
        const auto marks = writers[i]->Watermarks();
        accepted[i] = marks.accepted_sequence; durable[i] = marks.apfs_durable_sequence; cleanup[i] = marks.cleanup_sequence;
        Check(generations[i] && accepted[i] == durable[i] && accepted[i] == cleanup[i], "original validated clean journal");
    }
    Check(host.owner->Device().GetGeometry().total_bytes > payload.size() && !host.owner->Device().IsRawWriterAccepted(),
        "file geometry retains suffix and never becomes a raw writer");
    const auto unchanged = [&] {
        Check(Bytes("physical-admission-window.apfs") == wrapped, "entire prefix/container/suffix unchanged");
        for (std::size_t i = 0; i < host.contexts.size(); ++i)
        {
            Check(Bytes(host.contexts[i]->tx_journal_file) == journals[i] &&
                writers[i]->ValidatedCleanJournalGeneration() == generations[i], "original journal bytes and generation unchanged");
            const auto marks = writers[i]->Watermarks();
            Check(marks.accepted_sequence == accepted[i] && marks.apfs_durable_sequence == durable[i] &&
                marks.cleanup_sequence == cleanup[i], "original journal watermarks unchanged");
            Check(!host.contexts[i]->metadata_store->Context().allow_native_snapshot_runtime,
                "inventory fixture never enrolls ordinary writers in snapshot runtime");
        }
    };
    const auto token = std::string(64, 'b');
    const auto envelope = [&](const ContainerControlRequest& request) {
        const auto& scope = *request.verification_scope;
        return "APFS-CONTROL/1\n" + request.request_id + "\n" + token + "\nsnapshot-list\n" +
            std::to_string(request.volume_object_id) + "\n" + scope.exact.container_uuid_hex + "\n" +
            scope.exact.volume_uuid_hex + "\n" + std::to_string(scope.exact.checkpoint_xid) + "\n" +
            std::to_string(scope.exact.store_offset_bytes) + "\n" + std::to_string(scope.exact.store_size_bytes) + "\n" +
            scope.source_identity + "\n";
    };
    std::array<ContainerControlRequest, 2> requests;
    for (std::size_t i = 0; i < requests.size(); ++i)
    {
        auto request = host.Request(ContainerControlAction::SnapshotList);
        request.volume_object_id = host.contexts[i]->container_volume_oid;
        request.request_id = std::string(32, i == 0 ? 'a' : 'd'); request.verification_scope = scopes[i];
        std::string error;
        Check(ParseContainerControlRequestContents(envelope(request), token, requests[i], error), "authenticated physical request: " + error);
    }
    const auto successful = [&] {
        for (std::size_t i = 0; i < requests.size(); ++i)
        {
            auto& ctx = *host.contexts[i];
            const auto result = SnapshotListForControlWithAuthority(ctx, *host.owner, requests[i], capture);
            Check(result.success && result.code == "SnapshotInventory" && result.snapshot_inventory,
                "successful shared physical List OID " + std::to_string(ctx.container_volume_oid) + ": " + result.code);
            const auto& inventory = *result.snapshot_inventory;
            Check(inventory.scope == scopes[i].exact && inventory.scope.checkpoint_xid == host.owner->CheckpointXid() &&
                inventory.snapshots.size() == 1 && inventory.snapshots[0].identity.scope == inventory.scope,
                "truthful current published XID and exact nonzero wire scope for both members");
            auto identity = inventory.snapshots[0].identity; identity.scope = seeded[i].scope;
            Check(identity == seeded[i].snapshots[0].identity, "real canonical snapshot identity, relative blocks and member isolation");
            std::string response;
            Check(BuildContainerControlResponse(requests[i], result, response) &&
                response.starts_with("APFS-CONTROL/1\n" + requests[i].request_id + "\nok\nSnapshotInventory\n") &&
                response.find("\"storeOffsetBytes\":\"8192\"") != std::string::npos &&
                response.find("\"volumeOid\":\"" + std::to_string(ctx.container_volume_oid) + "\"") != std::string::npos,
                "successful typed physical response preserves request and member identities");
        }
        unchanged();
    };
    const auto refused = [&](const ContainerControlActionResult& result, const char* code) {
        Check(!result.success && result.code == code && !result.snapshot_inventory,
            std::string("exact physical refusal expected ") + code + ", actual " + result.code);
        unchanged();
    };
    successful();
    for (std::size_t i = 0; i < requests.size(); ++i)
    {
        auto& ctx = *host.contexts[i];
        refused(SnapshotListForControl(ctx, *host.owner, requests[i]), "SnapshotPhysicalInventoryOwnerRequired");
        {
            SnapshotControlLocks locks(ctx, true);
            std::string error;
            Check(locks.acquired && InspectPhysicalSnapshotInventoryWithAuthority(ctx, *host.owner, nullptr,
                error, nullptr, capture, RetainedSnapshotInventorySource::Clock::now() - std::chrono::milliseconds(1)),
                "capability inspection without enumeration keeps its existing no-deadline behavior");
        }
        const auto caps = GetSnapshotControlCapabilities(ctx, *host.owner);
        Check(!caps.inventory && !caps.mutation && caps.refusal == "SnapshotPhysicalInventoryOwnerRequired",
            "production callers keep the held raw capture fixed");
        auto older = requests[i]; --older.verification_scope->exact.checkpoint_xid;
        const auto current = SnapshotListForControlWithAuthority(ctx, *host.owner, older, capture);
        Check(current.success && current.snapshot_inventory && current.snapshot_inventory->scope == scopes[i].exact,
            "older discovery XID binds stable scope and returns current owner receipt");
        for (const auto& [fault, code] : std::vector<std::pair<std::string, const char*>>{
            {"source", "SnapshotInventoryScopeChanged"}, {"empty-source", "SnapshotPhysicalInventoryOwnerRequired"},
            {"base", "SnapshotPhysicalInventoryWindowRequired"}, {"nx-size", "SnapshotPhysicalInventoryWindowRequired"},
            {"limit", "SnapshotPhysicalInventoryWindowRequired"}, {"zero-limit", "SnapshotPhysicalInventoryWindowRequired"},
            {"owner", "SnapshotPhysicalInventoryOwnerRequired"}, {"device", "SnapshotPhysicalInventoryOwnerRequired"},
            {"store", "SnapshotPhysicalInventoryOwnerRequired"}, {"owner-generation", "SnapshotPhysicalInventoryOwnerGenerationChanged"},
            {"member", "SnapshotPhysicalInventoryMemberRequired"}, {"oid", "SnapshotPhysicalInventoryMemberRequired"},
            {"peer-oid", "SnapshotPhysicalInventoryMemberRequired"}, {"missing-peer-fact", "SnapshotPhysicalInventoryMemberRequired"},
            {"duplicate-peer-fact", "SnapshotPhysicalInventoryMemberRequired"}, {"raw-profile", "SnapshotPhysicalInventoryCleanPeerRequired"},
            {"zero-journal-generation", "SnapshotPhysicalInventoryJournalGenerationChanged"},
            {"stale-journal-generation", "SnapshotPhysicalInventoryJournalGenerationChanged"}})
        {
            const auto wrong = [&](const auto& selected, auto& owner, const auto& store, const auto& published) {
                return FixturePhysicalInventoryAuthority(selected, owner, store, published, fault);
            };
            refused(SnapshotListForControlWithAuthority(ctx, *host.owner, requests[i], wrong), code);
        }
        for (const auto field : {"source", "container", "volume", "base", "size", "oid"})
        {
            auto wrong = requests[i]; auto& scope = *wrong.verification_scope;
            if (std::string_view(field) == "source") scope.source_identity += ":wrong";
            if (std::string_view(field) == "container") scope.exact.container_uuid_hex = std::string(32, 'f');
            if (std::string_view(field) == "volume") scope.exact.volume_uuid_hex = std::string(32, 'f');
            if (std::string_view(field) == "base") ++scope.exact.store_offset_bytes;
            if (std::string_view(field) == "size") --scope.exact.store_size_bytes;
            if (std::string_view(field) == "oid") ++scope.exact.volume_oid;
            refused(SnapshotListForControlWithAuthority(ctx, *host.owner, wrong, capture), "SnapshotInventoryScopeChanged");
        }
        auto missing = requests[i]; missing.verification_scope.reset();
        refused(SnapshotListForControlWithAuthority(ctx, *host.owner, missing, capture), "SnapshotInventoryScopeRequired");
        refused(SnapshotListForControlWithAuthority(ctx, *host.owner, requests[1 - i], capture), "SnapshotVolumeMismatch");
        refused(SnapshotListForControlWithAuthority(ctx, *host.owner, requests[i], capture,
            RetainedSnapshotInventorySource::Clock::now() - std::chrono::milliseconds(1)), "VolumeVerificationTimedOut");
        unsigned captures = 0;
        const auto changed_after_read = [&](const auto& selected, auto& owner, const auto& store, const auto& published) {
            return FixturePhysicalInventoryAuthority(selected, owner, store, published, ++captures == 2 ? "source" : "");
        };
        refused(SnapshotListForControlWithAuthority(ctx, *host.owner, requests[i], changed_after_read), "SnapshotInventoryScopeChanged");
        Check(captures == 2, "final held authority recheck executes after real enumeration");
    }
    auto& ctx = host.Context(); auto& peer = *host.contexts[1];
    for (const auto fault : {"missing", "null", "duplicate"})
    {
        const auto saved = ctx.container_session_contexts;
        if (std::string_view(fault) == "missing") ctx.container_session_contexts.pop_back();
        if (std::string_view(fault) == "null") ctx.container_session_contexts.back() = nullptr;
        if (std::string_view(fault) == "duplicate") ctx.container_session_contexts.back() = &ctx;
        refused(SnapshotListForControlWithAuthority(ctx, *host.owner, requests[0], capture),
            std::string_view(fault) == "missing" ? "VolumeVerificationOwnerRefused" : "SnapshotControlBusy");
        ctx.container_session_contexts = saved;
    }
    std::string error;
    Check(host.owner->UpdateRequiredCheckpointXids(102, {host.owner->CheckpointXid()}, error, true), "actual dirty peer census");
    refused(SnapshotListForControlWithAuthority(ctx, *host.owner, requests[0], capture), "VolumeVerificationOwnerRefused");
    Check(host.owner->UpdateRequiredCheckpointXids(102, {}, error), "restore original clean peer census");
    for (const auto fault : {"disabled", "image", "encrypted", "fusion", "snapshot", "pending", "writer", "deferred"})
    {
        const std::string_view name(fault);
        if (name == "disabled") peer.args.enable_retained_physical_snapshot_inventory = false;
        if (name == "image") peer.args.enable_image_snapshots = true;
        if (name == "encrypted") peer.args.encrypted.enabled = true;
        if (name == "fusion") peer.args.fusion.enabled = true;
        if (name == "snapshot") peer.args.snapshot_xid = 1;
        if (name == "pending") peer.pending_native_writes = true;
        if (name == "writer") peer.open_write_handle_count = 1;
        if (name == "deferred") peer.deferred_access_time_requested = true;
        refused(SnapshotListForControlWithAuthority(ctx, *host.owner, requests[0], capture), "SnapshotPhysicalInventoryCleanPeerRequired");
        peer.args.enable_retained_physical_snapshot_inventory = true; peer.args.enable_image_snapshots = false;
        peer.args.encrypted.enabled = false; peer.args.fusion.enabled = false; peer.args.snapshot_xid = 0;
        peer.pending_native_writes = false; peer.open_write_handle_count = 0; peer.deferred_access_time_requested = false;
    }
    auto journal = std::move(peer.tx_manager);
    peer.tx_manager = std::make_unique<Tx>(L"Strict"); peer.tx_manager->SetVolumeIdentity(journal->ConfiguredVolumeIdentity());
    refused(SnapshotListForControlWithAuthority(ctx, *host.owner, requests[0], capture), "SnapshotMaintenanceJournalNotOwned");
    peer.tx_manager = std::move(journal);
    for (unsigned gate = 0; gate < 4; ++gate)
    {
        std::promise<void> held, release; auto released = release.get_future().share();
        auto holder = std::async(std::launch::async, [&] {
            std::unique_lock<std::mutex> lock(gate == 0 ? peer.commit_mutex : gate == 2 ? peer.metadata_mutex : peer.tx_mutex, std::defer_lock);
            std::unique_lock<std::shared_mutex> read(peer.committed_read_gate, std::defer_lock);
            if (gate == 1) read.lock(); else lock.lock();
            held.set_value(); released.wait();
        });
        held.get_future().wait();
        const auto busy = SnapshotListForControlWithAuthority(ctx, *host.owner, requests[0], capture);
        release.set_value(); holder.get();
        refused(busy, "SnapshotControlBusy");
    }
    auto invalid_id = requests[0]; invalid_id.request_id = std::string(32, 'g');
    ContainerControlRequest parsed;
    Check(!ParseContainerControlRequestContents(envelope(invalid_id), token, parsed, error) &&
        error == "ControlRequestAuthenticationFailed", "request identity authentication refusal");
    Check(!ParseContainerControlRequestContents(envelope(requests[0]), std::string(64, 'c'), parsed, error) &&
        error == "ControlRequestAuthenticationFailed", "owner credential exact refusal");
    successful();
    std::cout << "PASS shared immutable physical admission and authenticated scoped List for OIDs 101/102; exact authority, peer, generation, gate and request refusals\n";
}
}
