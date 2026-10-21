// Real host control and verifier over private image fixtures; no WinFsp mount.
#define APFSACCESS_FSHOST_UNIT_TEST 1
#include "../src/main.cpp"
namespace { using BtreeRecord = apfsaccess::catalog::BtreeRecord; }
#define main EngineVerifierUnusedMain
#include "ApfsVerifierTests.cpp"
#undef main
#include <future>

namespace {
using Owner = apfsaccess::catalog::ContainerMountCoordinator;
using Tx = apfsaccess::rw::TransactionManager;

Bytes FileBytes(const std::filesystem::path& path)
{
    std::ifstream input(path, std::ios::binary);
    if (!input) return {};
    const std::vector<char> chars{std::istreambuf_iterator<char>(input), {}};
    Bytes bytes(chars.size());
    std::memcpy(bytes.data(), chars.data(), chars.size());
    return bytes;
}
void SaveBytes(const std::filesystem::path& path, const Bytes& bytes)
{
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    Check(!!out, "write fixture");
}
std::string FileText(const std::filesystem::path& path)
{
    const auto bytes = FileBytes(path);
    return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}

struct HostVerification
{
    Fixture fixture;
    std::filesystem::path image;
    std::unique_ptr<Owner> owner;
    std::vector<std::unique_ptr<MountContext>> contexts;
    explicit HostVerification(const std::string& name, std::uint64_t base = 0, bool census = true, bool sibling = false,
        bool payload = false, std::uint64_t sparse_bytes = 0)
        : image(std::filesystem::absolute(name + ".apfs"))
    {
        if (payload) fixture = PayloadFixture();
        if (sparse_bytes)
        {
            AppleInodeRecord inode; std::string error;
            Check(ApfsExtendedRecordCodec::DecodeInode(Inode(30, sparse_bytes, 1, false, fixture.bs), inode, error), error);
            inode.internal_flags |= kAppleInodeSparseFlag;
            PutU64LE(inode.extended_fields[0].data, 8, 0);
            AppleExtendedField sparse{13, 0, Bytes(8)};
            PutU64LE(sparse.data, 0, (sparse_bytes + fixture.bs - 1) / fixture.bs * fixture.bs);
            inode.extended_fields.push_back(std::move(sparse));
            fixture.fs[2] = Encode(inode, EncodeAppleInodeRecord);
            fixture.fs.erase(fixture.fs.begin() + 3);
            fixture.refs.clear();
            fixture.Rebuild();
        }
        if (sibling)
        {
            fixture.spec.volumes.push_back(BuilderVolume{});
            fixture.spec.volumes.back().oid = 102;
            fixture.spec.volumes.back().uuid_hex = std::string(32, 'c');
            fixture.Rebuild();
        }
        auto bytes = fixture.image;
        bytes.insert(bytes.begin(), base, std::byte{0xEE});
        SaveBytes(image, bytes);
        std::string error;
        owner = Owner::Open(image.string(), base, error, CatalogLoadPolicy::StrictApple, true, true);
        Check(!!owner, "retained host owner: " + error);
        for (const auto& volume : fixture.spec.volumes)
        {
            auto context = std::make_unique<MountContext>();
            auto& c = *context;
            c.args.device = image.wstring();
            c.args.device_offset_bytes = base;
            c.args.container_id = Utf8ToWide(owner->ContainerUuidHex());
            c.args.volume_object_id = volume.oid;
            c.args.container_manifest = L"test-manifest";
            c.args.readwrite = true;
            c.args.write_backend = L"Native";
            c.args.allow_legacy_scaffold_for_fixtures = false;
            c.tx_journal_file = image.wstring() + L"." + std::to_wstring(volume.oid) + L".wal";
            c.tx_manager = std::make_unique<Tx>(L"Strict");
            c.tx_manager->SetJournalPath(c.tx_journal_file.wstring());
            c.tx_manager->SetVolumeIdentity(L"apfs-vol:" + c.args.container_id + L":" + std::to_wstring(volume.oid));
            Check(c.tx_manager->AcquireJournalOwnership(error), "journal ownership: " + error);
            std::vector<Tx::AcceptedTransaction> startup_debt;
            Check(c.tx_manager->LoadAcceptedTransactionsSinceCleanup(startup_debt, &error) && startup_debt.empty(),
                "fixture startup reconciles owned journal before verification: " + error);
            Tx::MutationIntent aborted;
            aborted.kind = Tx::MutationKind::CreateFile;
            aborted.path = L"\\aborted-fixture";
            Check(c.tx_manager->Begin() && c.tx_manager->RecordMutation(aborted) &&
                c.tx_manager->FlushPreparedRecords() && c.tx_manager->Abort(), "seed real aborted WAL history");
            Check(std::filesystem::file_size(c.tx_journal_file) > 0, "nonempty fixture WAL");
            std::wstring mount_error;
            Check(MountManifestSession(*owner, c.args, c, mount_error), "native session: " + WideToUtf8(mount_error));
            c.native_write_enabled = true;
            contexts.push_back(std::move(context));
        }
        if (census) Check(InitializeManifestCheckpointCensus(*owner, contexts, error), "census: " + error);
    }
    MountContext& Context() { return *contexts.front(); }
    BlockDevice& Device() { return const_cast<BlockDevice&>(Context().metadata_store->Device()); }
    ContainerControlRequest Request()
    {
        ContainerControlRequest request;
        request.request_id = std::string(32, 'a');
        request.action = ContainerControlAction::VolumeVerify;
        request.volume_object_id = 101;
        request.verification_scope = GetVolumeVerificationCapability(Context(), *owner);
        Check(request.verification_scope.has_value(), "live verification capability");
        return request;
    }
    ContainerControlActionResult Run(const ContainerControlRequest& request)
    { return VolumeVerifyForControl(Context(), *owner, request); }
    void ReplaceBlock(std::uint64_t block)
    {
        const auto begin = fixture.image.begin() + block * fixture.bs;
        Check(Device().Write(block * fixture.bs, Bytes(begin, begin + fixture.bs)) && Device().Flush(), "inject fixture block");
    }
};

struct Unchanged
{
    HostVerification& host;
    Bytes image;
    std::vector<std::pair<bool, Bytes>> journals;
    std::vector<std::uint64_t> sequences;
    explicit Unchanged(HostVerification& h) : host(h), image(FileBytes(h.image))
    {
        for (const auto& c : h.contexts)
        {
            journals.emplace_back(std::filesystem::exists(c->tx_journal_file), FileBytes(c->tx_journal_file));
            sequences.push_back(c->tx_manager->Watermarks().accepted_sequence);
        }
    }
    void Assert()
    {
        Check(FileBytes(host.image) == image, "verification leaves image bytes unchanged");
        for (std::size_t i = 0; i < host.contexts.size(); ++i)
        {
            const auto& c = host.contexts[i];
            Check(journals[i].first == std::filesystem::exists(c->tx_journal_file) &&
                journals[i].second == FileBytes(c->tx_journal_file), "verification leaves WAL presence and bytes unchanged");
            Check(sequences[i] == c->tx_manager->Watermarks().accepted_sequence, "verification accepts no transaction");
        }
    }
};
std::string Envelope(const ContainerControlRequest& request)
{
    const auto& s = *request.verification_scope;
    const auto action = request.action == ContainerControlAction::VolumeVerifyMetadata ? "volume-verify-metadata" : "volume-verify";
    return "APFS-CONTROL/1\n" + request.request_id + "\n" + std::string(64, 'b') + "\n" + action + "\n" +
        std::to_string(request.volume_object_id) + "\n" + s.exact.container_uuid_hex + "\n" + s.exact.volume_uuid_hex + "\n" +
        std::to_string(s.exact.checkpoint_xid) + "\n" + std::to_string(s.exact.store_offset_bytes) + "\n" +
        std::to_string(s.exact.store_size_bytes) + "\n" + s.source_identity + "\n";
}
void Refused(const ContainerControlActionResult& result, const std::string& name)
{
    Check(!result.success && !result.volume_verification && !result.code.empty() &&
        result.code.find_first_of("\r\n{}") == std::string::npos, name + ": " + result.code);
}
void HealthyHost()
{
    for (const auto base : {0ull, 8192ull})
    {
        HostVerification host("healthy-" + std::to_string(base), base, true, true);
        const auto request = host.Request();
        Check(!host.Context().args.enable_image_snapshots && !host.Context().mount_ready, "verify capability independent of snapshot opt-in and mount-ready");
        Unchanged unchanged(host);
        const auto result = host.Run(request);
        Check(result.success && result.volume_verification, "real verifier: " + result.code);
        const auto& report = result.volume_verification->report;
        Check(report.outcome == VerificationOutcome::Complete && report.findings.empty(), "healthy live report: " + Detail(report));
        std::string report_json;
        Check(BuildLiveVolumeVerificationJson(*result.volume_verification, report_json), "healthy report serialization");
        { std::ofstream out("healthy-" + std::to_string(base) + ".json", std::ios::binary); out << report_json; }
        Check(report.selected && report.selected->exact == request.verification_scope->exact &&
            report.selected->root_physical_block != 0 && report.source_reads > 0 && report.source_read_bytes > 0 &&
            report.covered_filesystem_records == host.fixture.fs.size() && report.covered_physical_extents == 1,
            "real walk exact UUID/OID/XID/range and record accounting: " + report_json);
        const auto covered = [&](VerificationCheck check, bool implemented, bool required, VerificationCheckState state) {
            const auto entry = std::find_if(report.coverage.begin(), report.coverage.end(),
                [check](const auto& value) { return value.check == check; });
            Check(std::count_if(report.coverage.begin(), report.coverage.end(),
                    [check](const auto& value) { return value.check == check; }) == 1 &&
                entry->implemented == implemented && entry->required == required && entry->state == state,
                "exact healthy coverage contract for check " + std::to_string(static_cast<unsigned>(check)));
        };
        for (const auto check : {VerificationCheck::ExactSelection, VerificationCheck::OrdinaryFeatures,
            VerificationCheck::SpacemanGraph, VerificationCheck::SnapshotInventory, VerificationCheck::MetadataTreeWalk,
            VerificationCheck::LeafKeyOrder, VerificationCheck::NamespaceLinksAndStreams, VerificationCheck::PayloadReferences,
            VerificationCheck::PayloadAllocatorOwnership, VerificationCheck::SharedSpaceAndQuota,
            VerificationCheck::InternalSeparatorRouting, VerificationCheck::MetadataAllocatorOwnership,
            VerificationCheck::CrossVolumePayloadOwnership, VerificationCheck::CurrentOwnershipCensus,
            VerificationCheck::SnapshotReachableAllocation})
            covered(check, true, true, VerificationCheckState::Verified);
        for (const auto check : {VerificationCheck::CompleteAllocationAccounting, VerificationCheck::HistoricalReachability,
            VerificationCheck::PayloadContentHashes})
            covered(check, false, false, VerificationCheckState::Unproven);
        for (const auto check : {VerificationCheck::Crypto, VerificationCheck::Fusion})
            covered(check, false, false, VerificationCheckState::Unsupported);
        covered(VerificationCheck::CurrentPayloadObservation, true, true, VerificationCheckState::Verified);
        Check(report.coverage.size() == 21 && report.requested_scope.observe_payload_content && report.payload_inventory &&
            report.payload_inventory->exactComplete() && report.payload_inventory->sharedBudget == report.read_budget &&
            !report.whole_volume_verified && !report.payload_content_hashes_verified,
            "complete current observation retains existing coverage and no independent integrity authority");
        Check(report.repair.requested_identity == request.verification_scope->exact &&
            report.repair.refusal == ApfsRepairRefusal::NoIndependentReconstructionEvidence, "read-only repair refusal binding");
        Arguments process;
        process.container_control_file = std::filesystem::absolute("verify-" + std::to_string(base) + ".request").wstring();
        process.container_control_token = std::wstring(64, L'b');
        process.status_file = std::filesystem::absolute("verify-status-" + std::to_string(base) + ".json").wstring();
        { std::ofstream out(process.status_file, std::ios::binary); out << "existing-status"; }
        { std::ofstream out(process.container_control_file, std::ios::binary); out << Envelope(request); }
        Check(ProcessContainerControlRequest(process, *host.owner, host.contexts), "authenticated file dispatcher");
        Check(FileText(process.status_file) == "existing-status", "read-only dispatch does not run status maintenance");
        const auto wire = FileText(process.container_control_file + L".response");
        Check(wire.starts_with("APFS-CONTROL/1\n" + request.request_id + "\nok\nVolumeVerificationReport\nvolume-verification-json/1\n") &&
            wire.find("\"outcomeName\":\"Complete\"") != std::string::npos &&
            wire.find("\"storeOffsetBytes\":\"" + std::to_string(base) + "\"") != std::string::npos, "typed exact dispatcher response");
        unchanged.Assert();
        Pass("actual retained verifier, authenticated dispatcher, unchanged image/WAL, offset " + std::to_string(base));
    }
}
void CorruptHost()
{
    for (bool checksum : {true, false})
    {
        HostVerification host(checksum ? "checksum" : "namespace");
        const auto request = host.Request();
        if (checksum) host.fixture.Edit(7, [](auto& b) { b[0] ^= std::byte{1}; }, false);
        else { host.fixture.fs[1] = Drec(31, "file.txt"); host.fixture.Rebuild(); }
        host.ReplaceBlock(7);
        Unchanged unchanged(host);
        const auto result = host.Run(request);
        Check(result.success && result.volume_verification, "typed corrupted report: " + result.code);
        const auto& report = result.volume_verification->report;
        Check(report.outcome != VerificationOutcome::Complete &&
            Has(report, checksum ? VerificationCode::ChecksumMismatch : VerificationCode::NamespaceOrLinkInconsistent),
            "actual corruption finding: " + Detail(report));
        Check(!report.covered_filesystem_records && !report.covered_physical_extents && !report.allocation_census &&
            report.repair.refusal == ApfsRepairRefusal::VerificationNotComplete, "no partial proof or repair");
        std::string wire;
        Check(BuildContainerControlResponse(request, result, wire) && wire.find("volume-verification-json/1\n") != std::string::npos,
            "corruption is typed report, not transport failure");
        { std::ofstream out(checksum ? "checksum.response" : "namespace.response", std::ios::binary); out << wire; }
        unchanged.Assert();
        Pass(checksum ? "actual checksum corruption" : "actual checksum-valid namespace corruption");
    }
}
void RefusalHost()
{
    HostVerification host("refusals");
    const auto good = host.Request();
    Unchanged unchanged(host);
    const std::vector<std::function<void(ContainerControlRequest&)>> changes = {
        [](auto& r) { ++r.verification_scope->exact.checkpoint_xid; },
        [](auto& r) { r.verification_scope->exact.container_uuid_hex = std::string(32, 'd'); },
        [](auto& r) { r.verification_scope->exact.volume_uuid_hex = std::string(32, 'd'); },
        [](auto& r) { ++r.verification_scope->exact.volume_oid; },
        [](auto& r) { ++r.verification_scope->exact.store_offset_bytes; },
        [](auto& r) { ++r.verification_scope->exact.store_size_bytes; },
        [](auto& r) { r.verification_scope->source_identity += "-other"; }};
    for (const auto& change : changes)
    {
        auto request = good; change(request);
        const auto result = host.Run(request);
        Refused(result, "stale or substituted exact scope");
        Check(result.code == "VolumeVerificationScopeChanged", "scope refusal code");
    }
    auto& c = host.Context();
    for (auto flag : {&c.recovery_active, &c.write_degraded})
    {
        *flag = true;
        Refused(host.Run(good), "degraded owner");
        Check(!GetVolumeVerificationCapability(c, *host.owner), "degraded capability false");
        *flag = false;
    }
    c.args.allow_raw_physical_write = true;
    Refused(host.Run(good), "unadmitted physical profile");
    Check(!GetVolumeVerificationCapability(c, *host.owner), "unadmitted physical capability false");
    c.args.allow_raw_physical_write = false;
    c.args.readwrite = false;
    Refused(host.Run(good), "general read-only profile not admitted");
    c.args.readwrite = true;
    c.args.snapshot_xid = 20;
    Refused(host.Run(good), "immutable snapshot profile");
    c.args.snapshot_xid = 0;
    auto journal = std::move(c.tx_manager);
    c.tx_manager = std::make_unique<Tx>(L"Strict");
    c.tx_manager->SetVolumeIdentity(journal->ConfiguredVolumeIdentity());
    Refused(host.Run(good), "lost journal ownership without reacquisition");
    c.tx_manager = std::move(journal);
    Refused(VolumeVerifyForControl(c, *host.owner, good, std::chrono::milliseconds(0)), "expired deadline");
    for (unsigned which = 0; which < 4; ++which)
    {
        VerificationScope limits;
        if (which == 0) limits.max_reads = 1;
        if (which == 1) limits.max_read_bytes = 1;
        if (which == 2) limits.max_records = 1;
        if (which == 3) limits.max_record_bytes = 1;
        const auto result = VolumeVerifyForControl(c, *host.owner, good, std::chrono::milliseconds(5000), limits);
        Refused(result, "exhausted operation budget " + std::to_string(which));
        std::string wire;
        Check(result.code == "VolumeVerificationReportBound" && BuildContainerControlResponse(good, result, wire) &&
            wire == "APFS-CONTROL/1\n" + good.request_id + "\nerror\nVolumeVerificationReportBound\n",
            "exhausted shared allowance cannot serialize or publish a report " + std::to_string(which));
    }
    std::string error;
    Check(host.owner->UnmountVolume(101, error), "remove live owner");
    Refused(host.Run(good), "lost retained session owner");
    Check(!GetVolumeVerificationCapability(c, *host.owner), "lost owner capability false");
    unchanged.Assert();
    host.contexts.clear();
    host.owner.reset();
    HostVerification no_census("no-census", 0, false);
    Refused(no_census.Run(good), "census missing");
    Pass("exact scope, source, owner, unsupported profiles and four resource limits");
}
void ConcurrencyHost()
{
    HostVerification host("concurrency", 0, true, true);
    const auto request = host.Request();
    Unchanged unchanged(host);
    std::promise<void> held, release;
    auto signal = release.get_future().share();
    auto holder = std::async(std::launch::async, [&] {
        std::lock_guard lock(host.contexts.back()->commit_mutex);
        held.set_value(); signal.wait();
    });
    held.get_future().wait();
    const auto busy = host.Run(request);
    release.set_value(); holder.get();
    Check(!busy.success && busy.code == "VolumeVerificationBusy", "sibling commit excludes verification without waiting");
    std::promise<void> inspecting, publish;
    auto publication = publish.get_future().share();
    auto inspector = std::async(std::launch::async, [&] {
        std::string error;
        return host.owner->InspectCurrentSession(101, [&](const auto&, auto&) { inspecting.set_value(); publication.wait(); return true; }, error);
    });
    inspecting.get_future().wait();
    auto verifying = std::async(std::launch::async, [&] {
        return VolumeVerifyForControl(host.Context(), *host.owner, request, std::chrono::milliseconds(5));
    });
    const bool serialized = verifying.wait_for(std::chrono::milliseconds(40)) == std::future_status::timeout;
    publish.set_value();
    const auto expired = verifying.get();
    Check(inspector.get() && serialized && !expired.success && expired.code == "VolumeVerificationTimedOut",
        "coordinator serialization and late result discarded at cooperative deadline");
    unchanged.Assert();
    Pass("sibling publication exclusion, coordinator serialization and timeout refusal");
}
void WireAndStatus()
{
    HostVerification host("status");
    const auto request = host.Request();
    const auto envelope = Envelope(request);
    ContainerControlRequest parsed;
    std::string error, wire;
    Check(ParseContainerControlRequestContents(envelope, std::string(64, 'b'), parsed, error) &&
        parsed.action == ContainerControlAction::VolumeVerify && parsed.verification_scope->exact == request.verification_scope->exact,
        "typed scope authenticated parser");
    Check(!ParseContainerControlRequestContents(envelope, std::string(64, 'c'), parsed, error), "bad authentication");
    Check(!ParseContainerControlRequestContents(envelope + "extra\n", std::string(64, 'b'), parsed, error), "extra scope data");
    auto malformed = envelope; malformed.replace(malformed.find("\n20\n"), 4, "\n020\n");
    Check(!ParseContainerControlRequestContents(malformed, std::string(64, 'b'), parsed, error), "noncanonical XID");
    for (bool success : {false, true})
    {
        Check(BuildContainerControlResponse(request, {success, "LegacyCode"}, wire) && wire ==
            "APFS-CONTROL/1\n" + request.request_id + "\n" + (success ? "ok\n" : "error\n") + "LegacyCode\n", "legacy response bytes");
    }
    auto result = host.Run(request);
    result.success = false;
    Check(!BuildContainerControlResponse(request, result, wire) && wire.empty(), "no typed report on transport error");
    result.success = true;
    // Exercise serializer bounds rather than the already-prepared response copy.
    result.volume_verification->serialized_response.clear();
    result.volume_verification->report.findings.resize(65);
    Check(!BuildContainerControlResponse(request, result, wire), "bounded finding count");
    result = host.Run(request);
    result.volume_verification->serialized_response.clear();
    result.volume_verification->report.repair.plan_id.resize(65537, 'x');
    Check(!BuildContainerControlResponse(request, result, wire), "bounded plan identity");

    Arguments process; process.status_file = std::filesystem::absolute("container-status.json").wstring();
    auto& c = host.Context();
    const std::pair<const char*, PerfCounter*> counters[] = {
        {"setSecurity", &c.perf_set_security}, {"getSecurity", &c.perf_get_security},
        {"getSecurityByName", &c.perf_get_security_by_name}, {"getVolumeInfo", &c.perf_get_volume_info},
        {"getFileInfo", &c.perf_get_file_info}, {"getStreamInfo", &c.perf_get_stream_info},
        {"namespaceMutexWait", &c.perf_namespace_mutex_wait}, {"namespaceMutexHold", &c.perf_namespace_mutex_hold},
        {"metadataMutexWait", &c.perf_metadata_mutex_wait}, {"metadataMutexHold", &c.perf_metadata_mutex_hold},
        {"commitMutexWait", &c.perf_commit_mutex_wait}, {"commitMutexHold", &c.perf_commit_mutex_hold},
        {"txMutexWait", &c.perf_tx_mutex_wait}, {"txMutexHold", &c.perf_tx_mutex_hold}};
    SetEnvironmentVariableW(L"APFSACCESS_PERF_COUNTERS", L"1");
    Check(WriteContainerStatusFile(process, *host.owner, host.contexts), "unattached status");
    const auto unattached = FileText(process.status_file);
    Check(unattached.find("\"volumeVerificationSupported\":false,\"volumeVerificationScope\":null") != std::string::npos &&
        GetVolumeVerificationCapability(c, *host.owner).has_value(),
        "unattached status advertises no live control while internal verification authority remains available");
    c.manifest_mount_attached = true;
    c.mount_ready = true;
    unsigned elapsed = 11;
    for (const auto& [name, counter] : counters) { counter->Observe(elapsed++); counter->Observe(elapsed++); }
    Check(WriteContainerStatusFile(process, *host.owner, host.contexts), "container performance status");
    const auto status = FileText(process.status_file);
    elapsed = 11;
    for (const auto& [name, counter] : counters)
    {
        const auto expected = std::string("\"") + name + "\":{\"count\":2,\"totalUs\":" + std::to_string(2 * elapsed + 1) +
            ",\"maxUs\":" + std::to_string(elapsed + 1) + ",\"lastUs\":" + std::to_string(elapsed + 1) + ',';
        Check(status.find(expected) != std::string::npos, std::string("exact existing counter name/value: ") + name);
        Check(counter->count.load() == 2, "status does not write hot-path counter");
        elapsed += 2;
    }
    Check(status.find("\"volumeVerificationSupported\":true") != std::string::npos &&
        status.find("\"sourceIdentity\":\"" + request.verification_scope->source_identity + "\"") != std::string::npos &&
        status.find("\"snapshotInventorySupported\":false") != std::string::npos, "truthful source-derived independent capabilities");
    SetEnvironmentVariableW(L"APFSACCESS_PERF_COUNTERS", L"0");
    c.write_degraded = true;
    process.status_file = std::filesystem::absolute("degraded-status.json").wstring();
    Check(WriteContainerStatusFile(process, *host.owner, host.contexts), "degraded status");
    const auto degraded = FileText(process.status_file);
    Check(degraded.find("\"volumeVerificationSupported\":false,\"volumeVerificationScope\":null") != std::string::npos &&
        degraded.find("callbackPerformance") == std::string::npos, "degraded and diagnostics-disabled status");
    Pass("wire authentication, legacy bytes, report bounds and fourteen status counter values");
}
void RetainedReadGates()
{
    SetEnvironmentVariableW(L"APFSACCESS_EXPERIMENTAL_BLOCK_READ_CACHE", L"1");
    HostVerification host("retained-reads", 0, true, true);
    const auto request = host.Request();
    // Invalidate fixture cache without changing bytes before each observed read.
    host.ReplaceBlock(0);
    Unchanged unchanged(host);
    std::promise<void> entered, release;
    auto signal = release.get_future().share();
    std::atomic<bool> once{false};
    host.Device().SetReadCacheMissHookForTests([&] {
        if (!once.exchange(true)) { entered.set_value(); signal.wait(); }
    });
    auto verifier = std::async(std::launch::async, [&] { return host.Run(request); });
    entered.get_future().wait();
    bool excluded = true;
    for (const auto& c : host.contexts)
    {
        std::unique_lock commit(c->commit_mutex, std::try_to_lock);
        std::unique_lock read(c->committed_read_gate, std::try_to_lock);
        std::unique_lock metadata(c->metadata_mutex, std::try_to_lock);
        std::unique_lock journal(c->tx_mutex, std::try_to_lock);
        excluded &= !commit.owns_lock() && !read.owns_lock() && !metadata.owns_lock() && !journal.owns_lock();
    }
    release.set_value();
    const auto result = verifier.get();
    host.Device().SetReadCacheMissHookForTests({});
    Check(excluded && result.success && result.volume_verification->report.outcome == VerificationOutcome::Complete,
        "all host gates held across actual verifier device reads");
    unchanged.Assert();

    host.ReplaceBlock(0);
    const auto path = host.Context().args.device;
    once = false;
    host.Device().SetReadCacheMissHookForTests([&] {
        if (!once.exchange(true)) host.Context().args.device = L"substituted-source";
    });
    const auto changed = host.Run(request);
    host.Context().args.device = path;
    host.Device().SetReadCacheMissHookForTests({});
    Check(once && !changed.success && changed.code == "VolumeVerificationSourceChanged" && !changed.volume_verification,
        "source binding lost during read discards report");
    unchanged.Assert();

    host.ReplaceBlock(0);
    once = false;
    host.Device().SetReadCacheMissHookForTests([&] {
        if (!once.exchange(true)) std::this_thread::sleep_for(std::chrono::milliseconds(80));
    });
    const auto late = VolumeVerifyForControl(host.Context(), *host.owner, request, std::chrono::milliseconds(50));
    host.Device().SetReadCacheMissHookForTests({});
    Check(once && !late.success && late.code == "VolumeVerificationTimedOut" && !late.volume_verification,
        "deadline crossed during actual read returns no proof");
    unchanged.Assert();
    SetEnvironmentVariableW(L"APFSACCESS_EXPERIMENTAL_BLOCK_READ_CACHE", L"0");
    Pass("actual reads hold all publication gates, discard changed source and timed-out proof");
}
void AcceptedWorkRefusal()
{
    HostVerification host("accepted-debt");
    const auto request = host.Request();
    auto& journal = *host.Context().tx_manager;
    Tx::MutationIntent mutation;
    mutation.kind = Tx::MutationKind::CreateFile;
    mutation.path = L"\\accepted-not-published";
    Check(journal.Begin() && journal.RecordMutation(mutation) && journal.Accept(20), "actual accepted WAL fixture");
    Unchanged unchanged(host);
    Refused(host.Run(request), "accepted WAL debt refused without replay");
    Check(!GetVolumeVerificationCapability(host.Context(), *host.owner), "accepted debt capability false");
    Check(journal.HasUnappliedAcceptedWork(), "accepted debt retained");
    unchanged.Assert();
    Pass("actual accepted WAL debt preserved and refused");
}
}

#include "NativeLiveVolumeVerificationTests.h"

namespace {
void PublishedSiblingVerification()
{
    HostVerification host("published-sibling", 0, true, true);
    const auto stale_request = host.Request();
    auto& peer = *host.contexts.back();
    using Store = apfsaccess::rw::MetadataStore;
    Store::MutationRequest mutation;
    mutation.operation = Store::MutationOperation::CreateDirectory;
    mutation.path = L"\\published-peer";
    const auto result = host.owner->Commit(peer.container_volume_oid, {mutation},
        [&](const auto& requests, const auto& identities, auto xid, auto& pins, std::string& error) {
            Check(requests.size() == 1 && identities.size() == 1, "exact peer publication batch");
            Tx::MutationIntent intent;
            intent.kind = Tx::MutationKind::CreateDirectory;
            intent.path = requests.front().path;
            intent.object_id = identities.front().object_id;
            intent.generation = identities.front().generation;
            return peer.tx_manager->Begin() && peer.tx_manager->RecordMutation(intent) &&
                peer.tx_manager->Accept(xid) && peer.tx_manager->LoadRequiredCheckpointXidsSinceCleanup(pins, &error);
        });
    Check(result.committed && !result.commit_recovery_required, "real canonical peer publication: " + result.error);
    std::string error;
    const auto sequence = peer.tx_manager->Watermarks().accepted_sequence;
    std::vector<std::uint64_t> pins;
    Check(peer.tx_manager->MarkApfsDurableThrough(sequence) && peer.tx_manager->MarkCleanedThrough(sequence) &&
        peer.tx_manager->LoadRequiredCheckpointXidsSinceCleanup(pins, &error) && pins.empty() &&
        host.owner->UpdateRequiredCheckpointXids(peer.container_volume_oid, pins, error), "durable peer cleanup: " + error);
    Check(host.Context().metadata_store->CheckpointXid() < host.owner->CheckpointXid(), "selected metadata view is genuinely stale");
    const auto epoch = host.Context().metadata_store->StateEpoch();
    const auto old_xid = host.Context().metadata_store->CheckpointXid();
    const auto peer_epoch = peer.metadata_store->StateEpoch();
    VerificationJournalUnchanged unchanged(host);
    const auto fresh = host.Request();
    Check(fresh.verification_scope->exact.checkpoint_xid == host.owner->CheckpointXid(), "capability binds newest published checkpoint");
    const auto verified = host.Run(fresh);
    Check(verified.success && verified.volume_verification &&
        verified.volume_verification->report.outcome == VerificationOutcome::Complete &&
        verified.volume_verification->report.selected->exact == fresh.verification_scope->exact, "stale sibling verifies current retained bytes");
    const auto refused = host.Run(stale_request);
    Check(!refused.success && refused.code == "VolumeVerificationScopeChanged", "old checkpoint request remains refused");
    Check(GetVolumeVerificationCapability(peer, *host.owner).has_value(), "latest committing peer remains verifiable");
    Check(host.Context().metadata_store->StateEpoch() == epoch &&
        host.Context().metadata_store->CheckpointXid() == old_xid && peer.metadata_store->StateEpoch() == peer_epoch,
        "verification does not refresh or mutate either metadata store");
    unchanged.Assert();
    Check(!host.owner->InspectCurrentSession(101, [](const auto&, auto&) { return true; }, error),
        "strict maintenance inspection still refuses a stale store");
    Check(host.owner->UpdateRequiredCheckpointXids(102, {host.owner->CheckpointXid()}, error, true), "inject unresolved peer census: " + error);
    Check(!GetVolumeVerificationCapability(host.Context(), *host.owner), "accepted peer debt still refuses stale-view verification");
    Check(host.owner->UpdateRequiredCheckpointXids(102, {}, error), "restore clean peer census");
    const auto reservation = peer.metadata_store->AllocateExtent(4096);
    Check(reservation.has_value(), "real peer allocator reservation");
    VerificationJournalUnchanged reserved(host);
    Check(!GetVolumeVerificationCapability(host.Context(), *host.owner), "peer reservation still refuses verification");
    Refused(host.Run(fresh), "active peer reservation rejects verifier");
    reserved.Assert();
    Pass("current published checkpoint verifies clean stale siblings without reload or maintenance authority");
}
}

#include "Task10LiveConsumerTests.h"

int main(int argc, char** argv)
{
    try
    {
        const auto root = std::filesystem::current_path() / ("live-verification-" + std::to_string(GetCurrentProcessId()));
        Check(root.wstring().starts_with(L"D:"), "private D: test directory required");
        Check(std::filesystem::create_directory(root), "fresh test directory");
        std::filesystem::current_path(root);
        SetEnvironmentVariableW(L"APFSACCESS_EXPERIMENTAL_BLOCK_READ_CACHE", L"0");
        if (argc == 2)
        {
            const std::string_view selected(argv[1]);
            if (selected == "--test-task10-consumers") Task10LiveConsumers();
            else if (selected == "--test-task10-metadata-consumers") Task10LiveMetadataOnlyConsumers();
            else if (selected == "--test-clean-proof-direct") UncleanDirectCommitVerificationRefusal();
            else if (selected == "--test-clean-proof-receipt") CompletedReceiptVerificationRefusal();
            else if (selected == "--test-clean-proof-lease") LostJournalProofVerificationRefusal();
            else if (selected == "--test-published-sibling") PublishedSiblingVerification();
            else Check(false, "unknown focused selector");
            std::cout << "PASS focused live verification clean proof: " << checks << " checks\n";
            return 0;
        }
        HealthyHost(); CorruptHost(); RefusalHost(); ConcurrencyHost(); WireAndStatus(); RetainedReadGates(); AcceptedWorkRefusal();
        UncleanDirectCommitVerificationRefusal(); CompletedReceiptVerificationRefusal(); LostJournalProofVerificationRefusal();
        PublishedSiblingVerification();
        std::cout << "PASS live volume verification: " << cases << " cases, " << checks << " checks\n";
        return 0;
    }
    catch (const std::exception& e) { std::cerr << "FAIL " << e.what() << '\n'; return 1; }
}
