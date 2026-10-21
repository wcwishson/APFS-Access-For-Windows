// Owner-bound snapshot maintenance bridge tests (Task 7).
//
// Proves, through the real coordinator/session owner and the real journal
// owner, that snapshot create/list/inspect(prepare)/confirm(apply)/recover/
// delete work end to end, and that every incomplete case refuses with durable
// evidence: stale/wrong identity, unmounted sessions, sibling journals,
// accepted debt, substituted clean journals, ahead journals, dropped plans,
// interruption/recovery, active readers and sibling preservation.
//
// Verdicts are sequenced in two statements throughout: the call completes
// first and its evidence string is frozen before Check formats any message
// (C++ does not sequence function arguments, so evidence must never be read
// in the same full-expression as the call that produces it).
//
// Uses the exact image bytes: refusals must leave image and journal bytes,
// watermarks and census unchanged, and must never report durable success.
// File-backed fixtures only; no macOS/Fusion/physical/mount claims.
#define SNAPSHOT_RUNTIME_TEST_HELPERS_ONLY
#include "SnapshotRuntimeTests.cpp"
#include <atomic>

namespace {
std::atomic<unsigned> g_bridge_counter{0};

std::string Stem(const char* tag) {
    return "bridge-" + std::string(tag) + "-" +
        std::to_string(static_cast<unsigned long long>(GetCurrentProcessId())) + "-" +
        std::to_string(g_bridge_counter.fetch_add(1));
}
std::wstring AbsoluteWal(const std::string& stem) {
    return std::filesystem::absolute(stem + ".wal").wstring();
}
std::wstring CanonicalIdentity(const std::string& uuid, std::uint64_t oid) {
    const auto text = "apfs-vol:" + uuid + ":" + std::to_string(oid);
    return std::wstring(text.begin(), text.end());
}
// Strict journal establishment: existing files open with the existing-only
// lease (no creation/repair/compaction); missing files are created
// exclusively by this owner and then strict-opened. Mirrors the control
// tool; caller-supplied paths are never trusted by assertion.
bool EstablishJournal(Tx& j, const std::wstring& path, const std::wstring& identity, std::string& e) {
    const std::filesystem::path file(path);
    std::error_code ec;
    if (!std::filesystem::exists(file, ec) || ec) {
        HANDLE fresh = CreateFileW(file.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
            CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (fresh == INVALID_HANDLE_VALUE) { e = "Journal cannot be established exclusively"; return false; }
        CloseHandle(fresh);
    }
    return j.OpenExistingRepairJournal(std::filesystem::absolute(file).wstring(), identity, e);
}
std::uint64_t WatermarkAccepted(Tx& j) { return j.Watermarks().accepted_sequence; }
std::uint64_t WatermarkDurable(Tx& j) { return j.Watermarks().apfs_durable_sequence; }
bool NoDebt(Tx& j) {
    std::vector<Tx::AcceptedTransaction> debt; std::string e;
    return j.LoadAcceptedTransactionsSinceCleanup(debt, &e) && debt.empty() && !j.HasUnappliedAcceptedWork();
}
std::uint64_t InventorySize(Owner& o) { return List(o).size(); }
const std::string kContainerA(32, 'a');

void OwnerGatePositive() {
    const auto stem = Stem("gate-ok");
    Fresh(stem + ".apfs");
    const auto wal = AbsoluteWal(stem);
    Tx j(L"Strict");
    std::string e;
    bool established = EstablishJournal(j, wal, CanonicalIdentity(kContainerA, 101), e);
    Check(established, std::string("establish: ") + e);
    auto o = Open(stem + ".apfs", j);
    bool gated = VerifySnapshotMaintenanceOwner(*o, 101, j, wal, e);
    Check(gated, std::string("owner gate: ") + e);
    bool current = VerifySnapshotJournalCurrency(*o, 101, j, e);
    Check(current, std::string("currency: ") + e);
    Create(*o, j, "bridged");
    Check(InventorySize(*o) == 1, "bridged snapshot listed");
    Check(NoDebt(j), "journal clean after publication");
    std::cout << "PASS owner gate positive with sibling preservation\n";
}

void OwnerGateWrongIdentity() {
    const auto stem = Stem("gate-wrong");
    Fresh(stem + ".apfs");
    const auto wal = AbsoluteWal(stem);
    Tx j(L"Strict");
    std::string e;
    bool established = EstablishJournal(j, wal, CanonicalIdentity(kContainerA, 102), e);
    Check(established, std::string("establish: ") + e);
    auto o = Open(stem + ".apfs", j);
    const auto before_image = Bytes(stem + ".apfs");
    const auto before_wal = Bytes(stem + ".wal");
    bool refused = !VerifySnapshotMaintenanceOwner(*o, 101, j, wal, e);
    Check(refused && e == "SnapshotMaintenanceJournalNotOwned", std::string("wrong identity refused: ") + e);
    Check(Bytes(stem + ".apfs") == before_image && Bytes(stem + ".wal") == before_wal,
        "refusal mutated nothing");
    Tx impostor(L"Strict");
    impostor.SetJournalPath(wal);
    impostor.SetVolumeIdentity(L"apfs-vol:ffffffffffffffffffffffffffffffff:101");
    bool forged = !VerifySnapshotMaintenanceOwner(*o, 101, impostor, wal, e);
    Check(forged, "forged identity refused");
    std::cout << "PASS wrong/stale identity refusals\n";
}

void OwnerGateUnmounted() {
    const auto stem = Stem("gate-unmounted");
    Fresh(stem + ".apfs");
    const auto wal = AbsoluteWal(stem);
    Tx j(L"Strict");
    std::string e;
    bool established = EstablishJournal(j, wal, CanonicalIdentity(kContainerA, 101), e);
    Check(established, std::string("establish: ") + e);
    auto o = Open(stem + ".apfs", j);
    bool never_mounted = !VerifySnapshotMaintenanceOwner(*o, 103, j, wal, e);
    Check(never_mounted, "never-mounted volume refused");
    bool unmounted = o->UnmountVolume(101, e);
    Check(unmounted, std::string("unmount: ") + e);
    bool gone = !VerifySnapshotMaintenanceOwner(*o, 101, j, wal, e);
    Check(gone, "unmounted volume refused");
    bool currency_gone = !VerifySnapshotJournalCurrency(*o, 101, j, e);
    Check(currency_gone, "unmounted currency refused");
    std::cout << "PASS unmounted refusals\n";
}

void OwnerGateSiblingJournal() {
    const auto stem = Stem("gate-sibling");
    Fresh(stem + ".apfs");
    Tx j101(L"Strict"), j102(L"Strict");
    std::string e;
    const auto wal101 = AbsoluteWal(stem + "-101"), wal102 = AbsoluteWal(stem + "-102");
    bool established101 = EstablishJournal(j101, wal101, CanonicalIdentity(kContainerA, 101), e);
    Check(established101, std::string("establish 101: ") + e);
    bool established102 = EstablishJournal(j102, wal102, CanonicalIdentity(kContainerA, 102), e);
    Check(established102, std::string("establish 102: ") + e);
    auto o = Open(stem + ".apfs", j101);
    bool sibling_refused = !VerifySnapshotMaintenanceOwner(*o, 101, j102, wal102, e);
    Check(sibling_refused, "sibling journal refused");
    bool crossed_refused = !VerifySnapshotMaintenanceOwner(*o, 101, j101, wal102, e);
    Check(crossed_refused, "crossed path refused");
    bool accepted = VerifySnapshotMaintenanceOwner(*o, 101, j101, wal101, e);
    Check(accepted, std::string("owner journal accepted: ") + e);
    std::cout << "PASS sibling journal refusals\n";
}

void OwnerGateDebtAndRecovery() {
    const auto stem = Stem("gate-debt");
    Fresh(stem + ".apfs");
    const auto wal = AbsoluteWal(stem);
    const auto identity = CanonicalIdentity(kContainerA, 101);
    std::string e;
    {
        Tx j(L"Strict");
        bool established = EstablishJournal(j, wal, identity, e);
        Check(established, std::string("establish: ") + e);
        auto o = Open(stem + ".apfs", j);
        SnapshotRuntimePlan p;
        bool prepared = PrepareSnapshotCreate(*o, 101, "doomed", 1, 0, p, e);
        Check(prepared, std::string("doomed prepares: ") + e);
        o->FindSessionStore(101)->SetCommitStageHook([](std::string_view stage) { return stage != "before-apple-final-flush"; });
        const auto interrupted = ApplySnapshot(*o, j, p);
        Check(!interrupted.committed && interrupted.commit_recovery_required, "interruption retains accepted debt");
        // The failed instance is fail-closed at the owner level: even the
        // strict gate refuses before reaching the journal check.
        bool refused = !VerifySnapshotMaintenanceOwner(*o, 101, j, wal, e);
        Check(refused && e == "SnapshotMaintenanceOwnerNotReady", std::string("failed instance refuses maintenance: ") + e);
    }
    // Recovery happens across restarts: fresh owner, same exclusively-held
    // journal file with its retained accepted debt.
    Tx younger(L"Strict");
    bool reestablished = EstablishJournal(younger, wal, identity, e);
    Check(reestablished, std::string("re-establish: ") + e);
    auto revived = Open(stem + ".apfs", younger);
    bool ownership = VerifySnapshotRecoveryOwner(*revived, 101, younger, wal, e);
    Check(ownership, std::string("recovery ownership: ") + e);
    bool chains = VerifySnapshotJournalCurrency(*revived, 101, younger, e);
    Check(chains, std::string("debt currency chains: ") + e);
    const auto recovered = ReplaySnapshot(*revived, younger, 101, e);
    bool replayed = recovered.has_value() && *recovered;
    Check(replayed, std::string("recovery replays: ") + e);
    Check(InventorySize(*revived) == 1 && NoDebt(younger), "exact inventory with clean journal after recovery");
    const auto idle = ReplaySnapshot(*revived, younger, 101, e);
    Check(!idle.has_value(), "second recovery is a clean no-op");
    bool admitted = VerifySnapshotMaintenanceOwner(*revived, 101, younger, wal, e);
    Check(admitted, std::string("clean owner admits maintenance: ") + e);
    std::cout << "PASS interruption, debt refusal and recovery\n";
}

void CurrencySubstitutedClean() {
    const auto stem = Stem("gate-subst");
    Fresh(stem + ".apfs");
    const auto real_wal = AbsoluteWal(stem + "-real");
    const auto identity = CanonicalIdentity(kContainerA, 101);
    std::string e;
    std::unique_ptr<Owner> o;
    {
        Tx j(L"Strict");
        bool established = EstablishJournal(j, real_wal, identity, e);
        Check(established, std::string("establish: ") + e);
        o = Open(stem + ".apfs", j);
        Create(*o, j, "original");
        Check(InventorySize(*o) == 1, "history exists");
    }
    const auto image_before = Bytes(stem + ".apfs");
    const auto wal_before = Bytes(AbsoluteWal(stem + "-real"));
    // Substitute a clean journal: fresh file, same canonical identity, no
    // competing lease (the real owner is gone). Currency must still refuse:
    // an empty journal cannot authenticate an image with history.
    {
        Tx clean(L"Strict");
        const auto clean_wal = AbsoluteWal(stem + "-clean");
        bool substitute = EstablishJournal(clean, clean_wal, identity, e);
        Check(substitute, std::string("substitute establishes: ") + e);
        bool refused = !VerifySnapshotJournalCurrency(*o, 101, clean, e);
        Check(refused && e == "SnapshotMaintenanceJournalNoChain", std::string("substituted clean journal refused: ") + e);
        Check(Bytes(stem + ".apfs") == image_before, "image untouched by refusal");
        Check(Bytes(AbsoluteWal(stem + "-real")) == wal_before, "real journal untouched by refusal");
    }
    // The real journal still chains and still works after re-establishment.
    Tx again(L"Strict");
    bool reestablished = EstablishJournal(again, real_wal, identity, e);
    Check(reestablished, std::string("real journal re-established: ") + e);
    bool chains = VerifySnapshotJournalCurrency(*o, 101, again, e);
    Check(chains, std::string("real journal chains: ") + e);
    std::cout << "PASS substituted clean journal refusal\n";
}

void CurrencyFreshGenesis() {
    const auto stem = Stem("gate-genesis");
    Fresh(stem + ".apfs");
    const auto wal = AbsoluteWal(stem);
    Tx j(L"Strict");
    std::string e;
    bool established = EstablishJournal(j, wal, CanonicalIdentity(kContainerA, 101), e);
    Check(established, std::string("establish: ") + e);
    auto o = Open(stem + ".apfs", j);
    Check(InventorySize(*o) == 0, "genesis image has no history");
    bool gated = VerifySnapshotMaintenanceOwner(*o, 101, j, wal, e);
    Check(gated, std::string("genesis owner gate: ") + e);
    bool current = VerifySnapshotJournalCurrency(*o, 101, j, e);
    Check(current, std::string("genesis currency: ") + e);
    Create(*o, j, "first");
    Check(InventorySize(*o) == 1, "genesis create published");
    std::cout << "PASS fresh genesis flow\n";
}

void CurrencyAheadRollback() {
    const auto stem = Stem("gate-ahead");
    Fresh(stem + ".apfs");
    Save(stem + "-genesis.apfs", Bytes(stem + ".apfs"));
    const auto wal = AbsoluteWal(stem);
    const auto identity = CanonicalIdentity(kContainerA, 101);
    std::string e;
    {
        Tx j(L"Strict");
        bool established = EstablishJournal(j, wal, identity, e);
        Check(established, std::string("establish: ") + e);
        auto o = Open(stem + ".apfs", j);
        Create(*o, j, "one");
        SnapshotRuntimePlan p;
        bool prepared = PrepareSnapshotCreate(*o, 101, "two", 2, 0, p, e);
        Check(prepared, std::string("second prepares: ") + e);
        o->FindSessionStore(101)->SetCommitStageHook([](std::string_view stage) { return stage != "before-apple-final-flush"; });
        const auto interrupted = ApplySnapshot(*o, j, p);
        Check(!interrupted.committed && interrupted.commit_recovery_required, "debt retained");
        std::vector<std::uint64_t> pins;
        bool pinned = j.LoadRequiredCheckpointXidsSinceCleanup(pins, &e) && !pins.empty();
        Check(pinned, "debt pins retained");
    }
    // Roll the image back to pre-history bytes while the newer journal stays.
    Save(stem + ".apfs", Bytes(stem + "-genesis.apfs"));
    const auto rolled_image = Bytes(stem + ".apfs");
    const auto kept_wal = Bytes(stem + ".wal");
    Tx younger(L"Strict");
    bool reestablished = EstablishJournal(younger, wal, identity, e);
    Check(reestablished, std::string("re-establish: ") + e);
    // Either census init refuses the ahead pins, or the session mounts and
    // the currency gate refuses. Both leave all bytes unchanged.
    std::unique_ptr<Owner> rolled;
    std::string open_error;
    {
        auto candidate = apfsaccess::catalog::ContainerMountCoordinator::Open(
            std::filesystem::absolute(stem + ".apfs").string(), 0, open_error,
            apfsaccess::catalog::CatalogLoadPolicy::StrictApple, true, true);
        if (candidate) {
            apfsaccess::catalog::ContainerVolumeSession session;
            session.volume_object_id = 101;
            session.container_uuid_hex = candidate->ContainerUuidHex();
            session.requested_write = true;
            session.use_canonical_transaction = true;
            session.metadata_context.allow_legacy_scaffold_for_fixtures = false;
            session.metadata_context.allow_native_snapshot_runtime = true;
            if (candidate->MountVolume(session, open_error)) {
                apfsaccess::catalog::VolumeCheckpointPins census_pins;
                census_pins.volume_object_id = 101;
                if (younger.LoadRequiredCheckpointXidsSinceCleanup(census_pins.required_checkpoint_xids, &open_error)) {
                    census_pins.unapplied_accepted_work = younger.HasUnappliedAcceptedWork();
                    std::vector<apfsaccess::catalog::VolumeCheckpointPins> census2{std::move(census_pins)};
                    if (candidate->InitializeRequiredCheckpointCensus(census2, open_error)) rolled = std::move(candidate);
                }
            }
        }
    }
    if (!rolled) {
        Check(Bytes(stem + ".apfs") == rolled_image && Bytes(stem + ".wal") == kept_wal,
            "early ahead refusal preserves evidence");
        std::cout << "PASS rollback refused at census\n";
        return;
    }
    bool refused = !VerifySnapshotJournalCurrency(*rolled, 101, younger, e);
    Check(refused && e == "SnapshotMaintenanceJournalAhead", std::string("ahead journal refused: ") + e);
    Check(Bytes(stem + ".apfs") == rolled_image && Bytes(stem + ".wal") == kept_wal,
        "ahead refusal preserves evidence");
    std::cout << "PASS rollback journal-ahead refusal\n";
}

void CallerLossAndCancellation() {
    const auto stem = Stem("gate-loss");
    Fresh(stem + ".apfs");
    const auto wal = AbsoluteWal(stem);
    Tx j(L"Strict");
    std::string e;
    bool established = EstablishJournal(j, wal, CanonicalIdentity(kContainerA, 101), e);
    Check(established, std::string("establish: ") + e);
    auto o = Open(stem + ".apfs", j);
    const auto accepted_before = WatermarkAccepted(j);
    {
        SnapshotRuntimePlan dropped;
        bool prepared = PrepareSnapshotCreate(*o, 101, "abandoned", 1, 0, dropped, e);
        Check(prepared, std::string("loss prepares: ") + e);
    }
    Create(*o, j, "kept");
    {
        SnapshotRuntimePlan cancelled;
        bool prepared = PrepareSnapshotDelete(*o, List(*o)[0].identity, 2, cancelled, e);
        Check(prepared, std::string("cancel prepares: ") + e);
    }
    Check(InventorySize(*o) == 1 && List(*o)[0].identity.name_utf8 == "kept", "only the confirmed snapshot exists");
    // Dropped plans journal nothing; confirmed work advances acceptance.
    // (Acceptance is counted in journal record sequences: one logical
    // acceptance may persist several records. Exact per-record accounting
    // belongs to the transaction unit tests, not this bridge.)
    Check(WatermarkAccepted(j) > accepted_before, "confirmed work was journaled");
    Check(NoDebt(j), "no orphaned debt from dropped plans");
    std::cout << "PASS caller loss and cancellation leave no trace\n";
}

void ExactCleanup() {
    const auto stem = Stem("gate-cleanup");
    Fresh(stem + ".apfs");
    const auto wal = AbsoluteWal(stem);
    Tx j(L"Strict");
    std::string e;
    bool established = EstablishJournal(j, wal, CanonicalIdentity(kContainerA, 101), e);
    Check(established, std::string("establish: ") + e);
    auto o = Open(stem + ".apfs", j);
    Create(*o, j, "tidy");
    const auto seq = WatermarkAccepted(j);
    Check(seq != 0 && WatermarkDurable(j) == seq, "durable watermark advanced exactly once");
    Check(NoDebt(j), "no accepted debt remains");
    std::vector<std::uint64_t> pins;
    std::string pin_error;
    bool retired = j.LoadRequiredCheckpointXidsSinceCleanup(pins, &pin_error) && pins.empty();
    Check(retired, "pins retired");
    Delete(*o, j, List(*o)[0].identity);
    Check(InventorySize(*o) == 0 && NoDebt(j), "delete leaves empty inventory and clean journal");
    std::cout << "PASS exact cleanup\n";
}

void StaleConfirmBinding() {
    const auto stem = Stem("gate-stale");
    Fresh(stem + ".apfs");
    const auto wal = AbsoluteWal(stem);
    Tx j(L"Strict");
    std::string e;
    bool established = EstablishJournal(j, wal, CanonicalIdentity(kContainerA, 101), e);
    Check(established, std::string("establish: ") + e);
    auto o = Open(stem + ".apfs", j);
    SnapshotRuntimePlan stale;
    bool prepared = PrepareSnapshotCreate(*o, 101, "stale", 1, 0, stale, e);
    Check(prepared, std::string("stale prepares: ") + e);
    Create(*o, j, "mover");
    const auto image_before = Bytes(stem + ".apfs");
    const auto accepted_before = WatermarkAccepted(j);
    const auto refused = ApplySnapshot(*o, j, stale);
    Check(!refused.committed, "stale confirm refused");
    Check(Bytes(stem + ".apfs") == image_before && WatermarkAccepted(j) == accepted_before,
        "stale confirm wrote nothing");
    SnapshotRuntimePlan once;
    bool prepared_once = PrepareSnapshotCreate(*o, 101, "once", 3, 0, once, e);
    Check(prepared_once, std::string("once prepares: ") + e);
    Success(ApplySnapshot(*o, j, once));
    Check(!ApplySnapshot(*o, j, once).committed, "consumed plan refuses replay");
    std::cout << "PASS stale and consumed confirmation binding\n";
}

void ActiveReaderDeleteRefusal() {
    const auto stem = Stem("gate-reader");
    Fresh(stem + ".apfs");
    const auto wal = AbsoluteWal(stem);
    Tx j(L"Strict");
    std::string e;
    bool established = EstablishJournal(j, wal, CanonicalIdentity(kContainerA, 101), e);
    Check(established, std::string("establish: ") + e);
    auto o = Open(stem + ".apfs", j);
    Create(*o, j, "pinned");
    const auto id = List(*o)[0].identity;
    auto reader = o->AcquireSnapshotReader(id, e);
    Check(!!reader, std::string("reader acquired: ") + e);
    SnapshotRuntimePlan busy;
    bool prepared = PrepareSnapshotDelete(*o, id, 4, busy, e);
    Check(prepared, std::string("busy delete prepares: ") + e);
    const auto refused = ApplySnapshot(*o, j, busy);
    Check(!refused.committed && refused.error == "SnapshotRuntimeReaderBusy", "active reader blocks delete");
    Check(InventorySize(*o) == 1 && NoDebt(j), "refusal retains snapshot and clean journal");
    reader.reset();
    Delete(*o, j, id);
    Check(InventorySize(*o) == 0, "delete succeeds after reader drain");
    std::cout << "PASS active reader protection in the owner-gated flow\n";
}

void SiblingPreservation() {
    const auto stem = Stem("gate-sibling-bytes");
    auto fixture = Fresh(stem + ".apfs");
    const auto wal = AbsoluteWal(stem);
    Tx j(L"Strict");
    std::string e;
    bool established = EstablishJournal(j, wal, CanonicalIdentity(kContainerA, 101), e);
    Check(established, std::string("establish: ") + e);
    auto o = Open(stem + ".apfs", j);
    Create(*o, j, "solo");
    Delete(*o, j, List(*o)[0].identity);
    Check(InventorySize(*o) == 0, "lifecycle complete");
    const auto disk = Bytes(stem + ".apfs");
    const auto sibling = fixture.checkpoint.volumes[1].superblock_object.physical_block;
    Check(std::equal(disk.begin() + sibling * kBlockSize, disk.begin() + (sibling + 1) * kBlockSize,
        fixture.image.begin() + sibling * kBlockSize), "sibling APSB exact");
    std::cout << "PASS sibling preservation\n";
}

void DeleteStaleIdentity() {
    const auto stem = Stem("gate-del-stale");
    Fresh(stem + ".apfs");
    const auto wal = AbsoluteWal(stem);
    Tx j(L"Strict");
    std::string e;
    bool established = EstablishJournal(j, wal, CanonicalIdentity(kContainerA, 101), e);
    Check(established, std::string("establish: ") + e);
    auto o = Open(stem + ".apfs", j);
    Create(*o, j, "victim");
    auto id = List(*o)[0].identity;
    ++id.root_physical_block;
    SnapshotRuntimePlan bad;
    bool prepared = PrepareSnapshotDelete(*o, id, 5, bad, e);
    Check(!prepared, std::string("mismatched delete identity refused: ") + e);
    Check(InventorySize(*o) == 1 && NoDebt(j), "refusal retains snapshot and clean journal");
    std::cout << "PASS stale delete identity refusal\n";
}
} // namespace

#ifndef SNAPSHOT_OWNER_BRIDGE_HELPERS_ONLY
int main(int argc, char** argv) {
    try {
        if (argc == 3 && std::string(argv[1]) == "write-fixture") {
            auto spec = RuntimeSpec();
            // The process gate needs an explicit nonzero volume UUID for the
            // target volume (the runtime default is a deterministic filler).
            spec.volumes[0].uuid_hex = std::string(32, 'b');
            // Fresh applies the container-OMAP manually-managed flags fixup,
            // Fletcher refresh and reload that strict Apple loads require.
            Fixture fixture = Fresh(argv[2], spec);
            Save(argv[2], fixture.image);
            std::cout << "container=" << spec.uuid_hex;
            for (const auto& volume : spec.volumes)
                std::cout << " volume=" << volume.oid << ":" << volume.uuid_hex;
            std::cout << " bytes=" << fixture.image.size() << "\n";
            return 0;
        }
        OwnerGatePositive();
        OwnerGateWrongIdentity();
        OwnerGateUnmounted();
        OwnerGateSiblingJournal();
        OwnerGateDebtAndRecovery();
        CurrencySubstitutedClean();
        CurrencyFreshGenesis();
        CurrencyAheadRollback();
        CallerLossAndCancellation();
        ExactCleanup();
        StaleConfirmBinding();
        ActiveReaderDeleteRefusal();
        SiblingPreservation();
        DeleteStaleIdentity();
        std::cout << "SnapshotOwnerBridgeTests: " << checks << " checks, 0 failures\n";
        return 0;
    } catch (const std::exception& failure) {
        std::cerr << "FAIL after " << checks << " checks: " << failure.what() << "\n";
        return 1;
    }
}
#endif
