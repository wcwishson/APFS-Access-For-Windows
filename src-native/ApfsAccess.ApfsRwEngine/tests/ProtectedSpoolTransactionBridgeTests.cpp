#include "TransactionManager.h"
#include "PayloadSpool.h"
#include "InodeMetadataPatch.h"
#define wmain RetainedWalTestEntry
#include "ProtectedWriteAheadLogTests.cpp"
#undef wmain
#undef CreateFile
#undef CreateDirectory

namespace apfsaccess::rw
{
struct ProtectedSpoolBridgeTestAccess
{
    static WriteAheadLog& Journal(TransactionManager& tx) { return tx.journal_; }
};
}
namespace
{
using Tx = apfsaccess::rw::TransactionManager;
using Spool = apfsaccess::rw::PayloadSpool;
using Result = Spool::ProtectedMaintenanceResult;
namespace st = apfsaccess::rw::protected_spool_testing;
using Access = apfsaccess::rw::ProtectedSpoolBridgeTestAccess;
constexpr std::string_view bridgeVolume = "TM_SPOOL_VOLUME_CANARY_20261016";
constexpr std::string_view bridgePayload = "TM_SPOOL_PAYLOAD_CANARY_20261016";
constexpr std::wstring_view bridgePath = L"\\TM_SPOOL_PRIVATE_PATH_CANARY.bin";
std::vector<std::byte> Data(std::string_view s)
{ return {reinterpret_cast<const std::byte*>(s.data()), reinterpret_cast<const std::byte*>(s.data() + s.size())}; }
std::array<std::uint8_t, 32> Sha(std::span<const std::byte> bytes)
{
    std::array<std::uint8_t, 32> hash{}; CHECK(BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0,
        reinterpret_cast<PUCHAR>(const_cast<std::byte*>(bytes.data())), static_cast<ULONG>(bytes.size()), hash.data(), 32) >= 0); return hash;
}
struct Fixture
{
    fs::path base; Wal::ProtectedPersistence protection; Spool::Options options; std::mutex gate;
    explicit Fixture(fs::path p, bool create) : base(std::move(p))
    {
        if (create) { Directory(base / L"wal-keys"); Directory(base / L"spool-keys"); Directory(base / L"store"); }
        protection = {base / L"wal-keys", Digest(13), Digest(71), {64ull << 20, 65536}, 256ull << 20};
        options.root = base / L"store"; options.volume_identity = bridgeVolume;
        options.protected_persistence = true; options.protected_binding = protection.source_binding;
        options.protected_key_directory = base / L"spool-keys"; options.max_bytes = 512 * 1024;
    }
    fs::path WalPath() const { return base / L"original.wal"; }
    std::unique_ptr<Tx> Open()
    {
        auto tx = std::make_unique<Tx>(L"Conservative"); std::string error;
        CHECK(tx->OpenProtectedJournal(WalPath().wstring(), std::wstring(bridgeVolume.begin(), bridgeVolume.end()), protection, error));
        return tx;
    }
    Wal::ProtectedHistoryHead Head(Tx& tx)
    {
        std::lock_guard lock(gate); Wal::ProtectedHistoryHead h; std::string error;
        CHECK(tx.CaptureProtectedOriginalHistoryHead(h, error)); CHECK(error.empty()); return h;
    }
    Result Reconcile(Tx& tx, Spool& spool, const Wal::ProtectedHistoryHead& h)
    {
        std::lock_guard lock(gate); std::string error; const auto r = tx.ReconcileProtectedPayloadSpool(spool, h, error);
        CHECK((r == Result::Succeeded) == error.empty()); return r;
    }
    std::pair<std::uint64_t, Spool::PersistedRangeReference> AcceptWrite(Tx& tx, Spool& spool, std::uint64_t logical = 0, bool abort = false)
    {
        std::lock_guard lock(gate); CHECK(tx.Begin()); const auto seq = tx.NextMutationSequence(); const auto bytes = Data(bridgePayload);
        Spool::AppendResult out; CHECK(spool.Append({std::string(bridgeVolume), 42, 7, logical, seq, bytes}, &out)); CHECK(spool.FlushPayloadBytes());
        Tx::MutationIntent m; m.kind = Tx::MutationKind::Write; m.path = bridgePath; m.object_id = 42; m.generation = 7;
        m.offset = logical; m.length = m.payload_length = out.payload_length; m.payload_spool_offset = out.spool_offset; m.payload_checksum = out.payload_sha256;
        CHECK(tx.RecordMutation(m)); if (abort) CHECK(tx.FlushPreparedRecords());
        CHECK(abort ? tx.Abort() : tx.Accept(25));
        return {tx.Watermarks().accepted_sequence, {std::string(bridgeVolume), 42, 7, logical, out.payload_length, out.spool_offset, seq, out.payload_sha256}};
    }
    void Clean(Tx& tx, std::uint64_t s)
    { std::lock_guard lock(gate); CHECK(tx.MarkApfsDurableThrough(s)); CHECK(tx.MarkCleanedThrough(s)); }
};
void PreserveKeys(const Snapshot& before, const fs::path& directory)
{ for (const auto& [name, bytes] : before) CHECK(Read(directory / name) == bytes); }
void Lifecycle()
{
    Fixture f(Case(L"tm-spool-lifecycle"), true); Wal::ProtectedHistoryHead original_head; std::vector<std::uint8_t> original;
    Snapshot keys;
    {
        auto tx = f.Open(); jt::hooks.key_override = std::as_bytes(std::span(keyCanary, sizeof(keyCanary) - 1));
        Spool spool(f.options); jt::hooks.key_override = {}; CHECK(!spool.RecoveryRequired());
        const auto [s, ref] = f.AcceptWrite(*tx, spool); CHECK(ref.spool_offset == 0); f.Clean(*tx, s);
        original_head = f.Head(*tx); original = Read(f.WalPath()); keys = Files(f.options.protected_key_directory);
        CHECK(f.Reconcile(*tx, spool, original_head) == Result::Succeeded); CHECK(Read(spool.SpoolFilePath()).empty());
        CHECK(Read(f.WalPath()) == original); PreserveKeys(keys, f.options.protected_key_directory);
    }
    {
        auto tx = f.Open(); Spool spool(f.options); CHECK(spool.RecoveryRequired());
        CHECK(f.Head(*tx) == original_head); CHECK(f.Reconcile(*tx, spool, original_head) == Result::Succeeded);
        const auto [s, ref] = f.AcceptWrite(*tx, spool, 64); CHECK(ref.spool_offset == 0 && ref.wal_sequence > original_head.last_sequence);
        std::vector<std::byte> read; CHECK(spool.ReadPersistedRange(ref, read) && read == Data(bridgePayload));
        const auto now = Read(f.WalPath()); CHECK(std::equal(original.begin(), original.end(), now.begin()));
        f.Clean(*tx, s); const auto head = f.Head(*tx); CHECK(f.Reconcile(*tx, spool, head) == Result::Succeeded);
        CHECK(Read(spool.SpoolFilePath()).empty()); PreserveKeys(keys, f.options.protected_key_directory);
    }
    {
        auto tx = f.Open(); Spool spool(f.options); CHECK(f.Reconcile(*tx, spool, f.Head(*tx)) == Result::Succeeded);
        CHECK(spool.SnapshotCounters().dirty_range_count == 0 && !spool.RecoveryRequired());
    }
}
void PartialLive()
{
    Fixture f(Case(L"tm-spool-partial"), true); Spool::PersistedRangeReference live; std::vector<std::uint8_t> original_data;
    {
        auto tx = f.Open(); Spool spool(f.options); const auto first = f.AcceptWrite(*tx, spool);
        const auto second = f.AcceptWrite(*tx, spool, 128); live = second.second; f.Clean(*tx, first.first);
        original_data = Read(spool.SpoolFilePath()); CHECK(f.Reconcile(*tx, spool, f.Head(*tx)) == Result::Succeeded);
        CHECK(Read(spool.SpoolFilePath()) == original_data && live.spool_offset > 0 && spool.SnapshotCounters().dirty_range_count == 1);
        std::vector<std::byte> bytes; CHECK(spool.ReadPersistedRange(live, bytes) && bytes == Data(bridgePayload));
    }
    {
        auto tx = f.Open(); Spool spool(f.options); CHECK(spool.RecoveryRequired()); CHECK(f.Reconcile(*tx, spool, f.Head(*tx)) == Result::Succeeded);
        std::vector<std::byte> bytes; CHECK(spool.ReadPersistedRange(live, bytes) && bytes == Data(bridgePayload));
        CHECK(Read(spool.SpoolFilePath()) == original_data); f.Clean(*tx, tx->Watermarks().accepted_sequence);
        CHECK(f.Reconcile(*tx, spool, f.Head(*tx)) == Result::Succeeded && Read(spool.SpoolFilePath()).empty());
    }
}
void OriginalBarrierControls()
{
    for (unsigned mode = 0; mode < 3; ++mode) {
        Fixture f(Case(L"tm-spool-barrier"), true); auto tx = f.Open(); Spool spool(f.options);
        const auto [s, ref] = f.AcceptWrite(*tx, spool); (void)ref; f.Clean(*tx, s); const auto head = f.Head(*tx);
        const auto store = Files(f.options.root), keys = Files(f.options.protected_key_directory);
        const auto original = Read(f.WalPath()); bool hit = false;
        st::hooks = {};
        if (mode == 0) tx->SetJournalFaultInjectionHook([&](auto stage) { if (stage == "durable-flush") { hit = true; return true; } return false; });
        else tx->SetFaultInjectionHook([&](const auto& stage) {
            if (stage != (mode == 1 ? "protected-spool-before-original-barrier" : "protected-spool-after-original-barrier")) return;
            hit = true; Wal::Record r; r.volume_identity = bridgeVolume; r.sequence = head.last_sequence + 1;
            r.operation = Wal::OperationKind::DurabilityWatermark; r.state = Wal::RecordState::Cleaned; r.logical_offset = s;
            CHECK(Access::Journal(*tx).Append(r, false));
        });
        CHECK(f.Reconcile(*tx, spool, head) == Result::RejectedBeforeWrite); CHECK(hit && st::hooks.maintenance_events.empty());
        CHECK(Files(f.options.root) == store && Files(f.options.protected_key_directory) == keys);
        if (!mode) CHECK(Read(f.WalPath()) == original); else CHECK(Read(f.WalPath()).size() > original.size());
        CHECK(!tx->RecoveryStateValid()); st::hooks = {};
    }
}
void AuthorityAndTailControls()
{
    for (unsigned mode = 0; mode < 6; ++mode) {
        Fixture f(Case(L"tm-spool-authority"), true); auto tx = f.Open(); Spool spool(f.options);
        const auto [s, ref] = f.AcceptWrite(*tx, spool); (void)ref; f.Clean(*tx, s); auto head = f.Head(*tx);
        if (mode == 0) head.sha256[0] ^= 1;
        if (mode == 1) { auto wrong = f.options; wrong.root = f.base / L"other-store"; Directory(wrong.root); wrong.protected_binding[0] ^= std::byte{1};
            wrong.protected_key_directory = f.base / L"other-keys"; Directory(wrong.protected_key_directory); Spool other(wrong);
            const auto before = Files(wrong.root); CHECK(f.Reconcile(*tx, other, head) == Result::RejectedBeforeWrite); CHECK(Files(wrong.root) == before); continue; }
        if (mode == 2) { auto wrong = f.options; wrong.root = f.base / L"other-store"; Directory(wrong.root); wrong.volume_identity += "-wrong";
            wrong.protected_key_directory = f.base / L"other-keys"; Directory(wrong.protected_key_directory); Spool other(wrong);
            const auto before = Files(wrong.root); CHECK(f.Reconcile(*tx, other, head) == Result::RejectedBeforeWrite); CHECK(Files(wrong.root) == before); continue; }
        if (mode == 3) { const auto bytes = Data("UNKNOWN_PHYSICAL_RANGE"); CHECK(spool.Append({std::string(bridgeVolume), 42, 7, 256, head.last_sequence + 1, bytes})); CHECK(spool.FlushPayloadBytes()); }
        if (mode == 4) { CHECK(tx->Begin()); }
        if (mode == 5) { CHECK(!spool.MatchesProtectedMaintenanceAuthority(f.protection.source_binding, bridgeVolume, f.options.protected_key_directory)); }
        const auto before = Files(f.options.root), keys = Files(f.options.protected_key_directory);
        if (mode != 5) CHECK(f.Reconcile(*tx, spool, head) == Result::RejectedBeforeWrite);
        CHECK(Files(f.options.root) == before && Files(f.options.protected_key_directory) == keys);
    }
    for (unsigned mode = 0; mode < 4; ++mode) {
        Fixture f(Case(L"tm-spool-original-refusal"), true);
        { auto tx = f.Open(); Spool spool(f.options); const auto row = f.AcceptWrite(*tx, spool); f.Clean(*tx, row.first); }
        auto protection = f.protection; if (mode == 0) protection.source_binding[0] ^= std::byte{1}; if (mode == 1) protection.journal_identity[0] ^= std::byte{1};
        if (mode == 2) { auto bytes = Read(f.WalPath()); bytes.pop_back(); Write(f.WalPath(), bytes, true); }
        if (mode == 3) { Write(Side(f.WalPath(), L".wreset.intent"), std::vector<std::uint8_t>{1,2,3}); }
        const auto original = Read(f.WalPath());
        Tx tx(L"Conservative"); std::string error; CHECK(!tx.OpenProtectedJournal(f.WalPath().wstring(), std::wstring(bridgeVolume.begin(), bridgeVolume.end()), protection, error));
        Spool spool(f.options); Wal::ProtectedHistoryHead head; CHECK(!tx.CaptureProtectedOriginalHistoryHead(head, error));
        const auto store = Files(f.options.root), keys = Files(f.options.protected_key_directory);
        CHECK(f.Reconcile(tx, spool, head) == Result::RejectedBeforeWrite);
        CHECK(Read(f.WalPath()) == original && Files(f.options.root) == store && Files(f.options.protected_key_directory) == keys);
    }
}
void PendingHeadMismatch()
{
    Fixture f(Case(L"tm-spool-pending-head"), true); auto tx = f.Open(); Spool spool(f.options);
    const auto row = f.AcceptWrite(*tx, spool); f.Clean(*tx, row.first); const auto old = f.Head(*tx);
    st::hooks = {}; st::hooks.maintenance_fault = "cleanup-after-intent-readback";
    CHECK(f.Reconcile(*tx, spool, old) == Result::RecoveryRequired && st::hooks.triggered); st::hooks = {};
    const auto before = Files(f.options.root), keys = Files(f.options.protected_key_directory);
    CHECK(tx->Begin()); Tx::MutationIntent m; m.kind = Tx::MutationKind::Write; m.path = bridgePath; m.object_id = 42;
    m.inline_payload = Data(bridgePayload); m.length = m.payload_length = m.inline_payload.size();
    m.payload_checksum = Sha(std::span(m.inline_payload)); CHECK(tx->RecordMutation(m) && tx->Accept(25));
    CHECK(f.Reconcile(*tx, spool, f.Head(*tx)) == Result::RejectedBeforeWrite);
    CHECK(Files(f.options.root) == before && Files(f.options.protected_key_directory) == keys);
}
void CompactionAndIncompleteHistory()
{
    for (bool pending : {false, true}) {
        Fixture f(Case(L"tm-spool-compaction"), true); auto tx = f.Open(); Spool spool(f.options);
        const auto row = f.AcceptWrite(*tx, spool); f.Clean(*tx, row.first); const auto old = f.Head(*tx);
        if (pending) Access::Journal(*tx).SetFaultInjectionHook([](auto stage) { return stage == "pcompact-before-old-rename"; });
        Wal::ProtectedHistoryHead replacement;
        CHECK(Access::Journal(*tx).CompactProtectedWithResult(1, old, replacement) ==
            (pending ? Wal::CompactionResult::BytesMayHavePersisted : Wal::CompactionResult::Succeeded));
        const auto before = Files(f.options.root), keys = Files(f.options.protected_key_directory); st::hooks = {};
        CHECK(f.Reconcile(*tx, spool, old) == Result::RejectedBeforeWrite);
        CHECK(Files(f.options.root) == before && Files(f.options.protected_key_directory) == keys && st::hooks.maintenance_events.empty());
    }
    Fixture f(Case(L"tm-spool-incomplete-original"), true);
    { auto tx = f.Open(); Spool spool(f.options); const auto row = f.AcceptWrite(*tx, spool); f.Clean(*tx, row.first);
        CHECK(tx->Begin()); Tx::MutationIntent m; m.kind = Tx::MutationKind::CreateFile; m.path = bridgePath; m.object_id = 43;
        CHECK(tx->RecordMutation(m) && tx->FlushPreparedRecords()); }
    Tx tx(L"Conservative"); std::string error;
    CHECK(!tx.OpenProtectedJournal(f.WalPath().wstring(), std::wstring(bridgeVolume.begin(), bridgeVolume.end()), f.protection, error));
    Spool spool(f.options); const auto before = Files(f.options.root), keys = Files(f.options.protected_key_directory);
    CHECK(f.Reconcile(tx, spool, {}) == Result::RejectedBeforeWrite);
    CHECK(Files(f.options.root) == before && Files(f.options.protected_key_directory) == keys);
}
void AbortedPhysicalReferences()
{
    Fixture f(Case(L"tm-spool-aborted-physical"), true); auto tx = f.Open(); Spool spool(f.options);
    const auto aborted = f.AcceptWrite(*tx, spool, 0, true); CHECK(aborted.first == 0);
    const auto accepted = f.AcceptWrite(*tx, spool, 128); CHECK(accepted.second.spool_offset > aborted.second.spool_offset);
    f.Clean(*tx, accepted.first); const auto original = Read(f.WalPath());
    CHECK(f.Reconcile(*tx, spool, f.Head(*tx)) == Result::Succeeded); CHECK(Read(spool.SpoolFilePath()).empty());
    CHECK(Read(f.WalPath()) == original);
}
void UnloggedAbortedPhysicalRange()
{
    Fixture f(Case(L"tm-spool-unlogged-abort"), true); auto tx = f.Open(); Spool spool(f.options);
    CHECK(tx->Begin()); const auto bytes = Data(bridgePayload); Spool::AppendResult out;
    CHECK(spool.Append({std::string(bridgeVolume), 42, 7, 0, tx->NextMutationSequence(), bytes}, &out)); CHECK(spool.FlushPayloadBytes());
    Tx::MutationIntent m; m.kind = Tx::MutationKind::Write; m.path = bridgePath; m.object_id = 42; m.generation = 7;
    m.length = m.payload_length = out.payload_length; m.payload_checksum = out.payload_sha256; m.payload_spool_offset = out.spool_offset;
    CHECK(tx->RecordMutation(m) && tx->Abort()); const auto later = f.AcceptWrite(*tx, spool, 128); f.Clean(*tx, later.first);
    const auto before = Files(f.options.root), keys = Files(f.options.protected_key_directory);
    CHECK(f.Reconcile(*tx, spool, f.Head(*tx)) == Result::RejectedBeforeWrite);
    CHECK(Files(f.options.root) == before && Files(f.options.protected_key_directory) == keys);
}
void OrdinaryBridgeRefusal()
{
    const auto base = Case(L"tm-spool-ordinary"); Directory(base / L"store"); Tx tx(L"Conservative");
    tx.SetVolumeIdentity(L"bridge-ordinary"); tx.SetJournalPath((base / L"ordinary.wal").wstring());
    CHECK(tx.Begin()); Tx::MutationIntent m; m.kind = Tx::MutationKind::CreateFile; m.path = L"\\ordinary.bin"; m.object_id = 42;
    CHECK(tx.RecordMutation(m) && tx.Accept(25)); const auto s = tx.Watermarks().accepted_sequence;
    CHECK(tx.MarkApfsDurableThrough(s) && tx.MarkCleanedThrough(s));
    Spool::Options options; options.root = base / L"store"; options.volume_identity = "bridge-ordinary"; Spool spool(options);
    const auto before = Read(base / L"ordinary.wal"); Wal::ProtectedHistoryHead head; std::string error;
    CHECK(!tx.CaptureProtectedOriginalHistoryHead(head, error)); CHECK(tx.ReconcileProtectedPayloadSpool(spool, head, error) == Result::RejectedBeforeWrite);
    CHECK(Read(base / L"ordinary.wal") == before && Wal::ReadAll(base / L"ordinary.wal", "bridge-ordinary").records.size() == 4);
}
std::uint64_t AcceptInline(Fixture& f, Tx& tx, std::uint64_t generation = 0)
{
    std::lock_guard lock(f.gate); Tx::MutationIntent m;
    m.path = bridgePath; m.object_id = 42; m.generation = generation;
    m.inline_payload = Data(bridgePayload); m.length = m.payload_length = m.inline_payload.size(); m.payload_checksum = Sha(m.inline_payload);
    CHECK(tx.Begin() && tx.RecordMutation(m) && tx.Accept(25));
    auto rows = Access::Journal(tx).ReadAllWithExclusiveWriterLease(); CHECK(rows.status == Wal::ReadStatus::Ok);
    const auto& r = rows.records[rows.records.size() - 2];
    CHECK(r.operation == Wal::OperationKind::Write && r.parent_object_id == generation && r.payload_spool_id == r.sequence);
    CHECK(!r.inline_payload.empty() && Wal::InlinePayloadIsConsistent(r)); return tx.Watermarks().accepted_sequence;
}
void InlineVirginAndAmbiguity()
{
    Fixture f(Case(L"tm-spool-inline-virgin"), true); Wal::ProtectedHistoryHead head;
    {
        auto tx = f.Open(); const auto s = AcceptInline(f, *tx); f.Clean(*tx, s);
        CHECK(Files(f.options.root).empty()); jt::hooks.key_override = std::as_bytes(std::span(keyCanary, sizeof(keyCanary) - 1));
        Spool spool(f.options); jt::hooks.key_override = {}; CHECK(!spool.RecoveryRequired());
        CHECK(Read(spool.SpoolFilePath()).empty()); head = f.Head(*tx);
        CHECK(f.Reconcile(*tx, spool, head) == Result::Succeeded && !spool.RecoveryRequired());
    }
    { auto tx = f.Open(); Spool spool(f.options); CHECK(f.Head(*tx) == head);
        CHECK(f.Reconcile(*tx, spool, head) == Result::Succeeded && spool.SnapshotCounters().dirty_range_count == 0); }
    {
        Fixture a(Case(L"tm-spool-parent-inline-refusal"), true); auto tx = a.Open(); Spool spool(a.options);
        const auto s = AcceptInline(a, *tx, 25); a.Clean(*tx, s);
        const auto before = Files(a.options.root), keys = Files(a.options.protected_key_directory);
        CHECK(a.Reconcile(*tx, spool, a.Head(*tx)) == Result::Succeeded);
        CHECK(Read(spool.SpoolFilePath()).empty()); PreserveKeys(keys, a.options.protected_key_directory);
    }
    for (unsigned mode = 0; mode < 2; ++mode) {
        Fixture a(Case(L"tm-spool-inline-unknown"), true); auto tx = a.Open(); Spool spool(a.options);
        const auto bytes = Data(bridgePayload); CHECK(spool.Append({std::string(bridgeVolume), 42, 25, 0, tx->NextMutationSequence(), bytes}));
        CHECK(spool.FlushPayloadBytes()); const auto s = AcceptInline(a, *tx); a.Clean(*tx, s);
        if (mode) {
            CHECK(tx->Begin()); Tx::MutationIntent m; m.path = bridgePath; m.object_id = 43;
            m.inline_payload = bytes; m.length = m.payload_length = bytes.size(); m.payload_checksum = Sha(bytes); m.payload_spool_offset = 1;
            CHECK(tx->RecordMutation(m) && tx->Accept(25)); a.Clean(*tx, tx->Watermarks().accepted_sequence);
        }
        const auto before = Files(a.options.root), keys = Files(a.options.protected_key_directory);
        CHECK(a.Reconcile(*tx, spool, a.Head(*tx)) == Result::RejectedBeforeWrite);
        CHECK(Files(a.options.root) == before && Files(a.options.protected_key_directory) == keys);
    }
}
void MissingCanonicalRefusal()
{
    for (const auto name : {L"payload-spool.bin", L"payload-spool.idx"}) {
    Fixture missing(Case(L"tm-spool-inline-missing-canonical"), true);
    { auto tx = missing.Open(); const auto s = AcceptInline(missing, *tx); missing.Clean(*tx, s); Spool spool(missing.options); }
    const auto payload = missing.options.root / name, retained = missing.base / L"retained-missing-canonical.bin";
    CHECK(!fs::exists(retained)); CHECK(MoveFileExW(payload.c_str(), retained.c_str(), MOVEFILE_WRITE_THROUGH));
    auto tx = missing.Open(); Spool spool(missing.options); CHECK(spool.RecoveryRequired());
    const auto before = Files(missing.options.root), keys = Files(missing.options.protected_key_directory);
    CHECK(missing.Reconcile(*tx, spool, missing.Head(*tx)) == Result::RejectedBeforeWrite);
    CHECK(!fs::exists(payload) && fs::exists(retained));
    CHECK(Files(missing.options.root) == before && Files(missing.options.protected_key_directory) == keys);
    }
}
void TypedCapacity()
{
    Fixture f(Case(L"tm-spool-typed-capacity"), true); auto tx = f.Open(); Spool spool(f.options);
    const std::array kinds{Tx::MutationKind::CreateFile, Tx::MutationKind::Write, Tx::MutationKind::Write,
        Tx::MutationKind::CreateFile, Tx::MutationKind::SetFileSize, Tx::MutationKind::Rename, Tx::MutationKind::Delete};
    const std::array ops{Wal::OperationKind::CreateFile, Wal::OperationKind::Write, Wal::OperationKind::Write,
        Wal::OperationKind::CreateFile, Wal::OperationKind::SetFileSize, Wal::OperationKind::Rename, Wal::OperationKind::Delete};
    for (unsigned n = 0; n < kinds.size(); ++n) {
        Tx::MutationIntent m; m.kind = kinds[n]; m.object_id = 42 + n; m.generation = 25; m.path = bridgePath;
        auto bytes = Data(bridgePayload); std::string error;
        if (n == 1 || n == 2 || n == 3) { m.length = m.payload_length = bytes.size(); m.payload_checksum = Sha(bytes);
            if (n == 1) { m.inline_payload = bytes; m.generation = 0; } else m.wal_sequence = tx->NextMutationSequence(); }
        if (n == 3) m.offset = 0644; // Actual Create permissions occupy the WAL logical-offset field.
        if (n == 4) m.length = 1024 * 1024;
        if (n == 5) { m.secondary_path = L"\\TM_SPOOL_RENAMED_CANARY.bin"; m.offset = 3; m.replace_if_exists = true; }
        const auto store = Files(f.options.root), keys = Files(f.options.protected_key_directory), walkeys = Files(f.protection.key_directory);
        const bool existed = fs::exists(f.WalPath()); const auto before = existed ? Read(f.WalPath()) : std::vector<std::uint8_t>{};
        CHECK(tx->ProtectedMutationCapacityAvailable(m, error) && error.empty());
        CHECK(Files(f.options.root) == store && Files(f.options.protected_key_directory) == keys && Files(f.protection.key_directory) == walkeys);
        CHECK(fs::exists(f.WalPath()) == existed && (!existed || Read(f.WalPath()) == before));
        const auto seq = tx->NextMutationSequence(); CHECK(tx->Begin());
        if (n == 2 || n == 3) { Spool::AppendResult out;
            CHECK(spool.Append({std::string(bridgeVolume), m.object_id, m.generation, m.offset, seq, bytes}, &out) && spool.FlushPayloadBytes());
            m.payload_spool_offset = out.spool_offset; m.payload_checksum = out.payload_sha256; CHECK(out.wal_sequence == seq); }
        CHECK(tx->RecordMutation(m) && tx->Accept(25));
        auto read = Access::Journal(*tx).ReadAllWithExclusiveWriterLease(); CHECK(read.status == Wal::ReadStatus::Ok);
        const auto& r = read.records[read.records.size() - 2];
        CHECK(r.operation == ops[n] && r.sequence == seq && r.object_id == m.object_id && r.parent_object_id == m.generation);
        CHECK(r.logical_offset == m.offset && r.logical_length == m.length && r.payload_length == m.payload_length);
        CHECK(r.payload_spool_id == (m.payload_length ? seq : 0) && r.payload_offset == m.payload_spool_offset && r.inline_payload == m.inline_payload);
    }
    f.Clean(*tx, tx->Watermarks().accepted_sequence); CHECK(f.Reconcile(*tx, spool, f.Head(*tx)) == Result::Succeeded);
    CHECK(Read(spool.SpoolFilePath()).empty());
    Tx::MutationIntent valid; valid.path = bridgePath; valid.object_id = 42; valid.generation = 25;
    valid.inline_payload = Data(bridgePayload); valid.length = valid.payload_length = valid.inline_payload.size(); valid.payload_checksum = Sha(valid.inline_payload);
    const auto store = Files(f.options.root), keys = Files(f.options.protected_key_directory);
    const auto original = Read(f.WalPath());
    for (unsigned mode = 0; mode < 13; ++mode) {
        auto bad = valid;
        switch (mode) {
        case 0: bad.kind = Tx::MutationKind::CreateFile; break; // Frozen encoder refuses inline Create.
        case 1: bad.kind = Tx::MutationKind::CreateDirectory; break;
        case 2: bad.payload_checksum[0] ^= 1; break;
        case 3: bad.wal_sequence = tx->NextMutationSequence() + 1; break;
        case 4: bad.offset = UINT64_MAX; break;
        case 5: bad.path.assign(65537, L'x'); break;
        case 6: bad.inline_payload.clear(); bad.generation = 0; bad.wal_sequence = tx->NextMutationSequence(); break;
        case 7: bad.inline_payload.clear(); break; // External data needs explicit genuine sequence.
        case 8: bad.payload_spool_offset = 1; break;
        case 9: bad.length = bad.payload_length = 256 * 1024 + 1; bad.inline_payload.clear(); bad.wal_sequence = tx->NextMutationSequence(); break;
        case 10: bad.timestamp_utc = 1; break;
        case 11: bad.path.push_back(L'\0'); break;
        case 12: bad.kind = Tx::MutationKind::Delete; break;
        }
        std::string error; CHECK(!tx->ProtectedMutationCapacityAvailable(bad, error) && !error.empty());
        CHECK(Read(f.WalPath()) == original && Files(f.options.root) == store && Files(f.options.protected_key_directory) == keys);
    }
    auto external = valid; external.inline_payload.clear(); external.length = external.payload_length = 256 * 1024;
    external.wal_sequence = tx->NextMutationSequence(); std::string error;
    CHECK(tx->ProtectedMutationCapacityAvailable(external, error));
    external.kind = Tx::MutationKind::CreateFile; external.length = external.payload_length = 4096;
    CHECK(tx->ProtectedMutationCapacityAvailable(external, error)); external.length = external.payload_length = 4097;
    CHECK(!tx->ProtectedMutationCapacityAvailable(external, error));
    CHECK(tx->Begin()); CHECK(!tx->ProtectedMutationCapacityAvailable(valid, error)); CHECK(tx->Abort());
    tx.reset();
    for (unsigned mode = 0; mode < 4; ++mode) {
        Fixture cap(Case(L"tm-spool-capacity-reserve"), true);
        if (mode < 2) cap.protection.read_limits.records = mode ? 8 : 7;
        if (mode == 2) cap.protection.read_limits.bytes = 512;
        if (mode == 3) cap.protection.max_allocation_bytes = 1024;
        auto owner = std::make_unique<Tx>(L"Conservative"); std::string reason;
        if (mode == 2) owner->SetJournalMaxBytesForTest(512);
        CHECK(owner->OpenProtectedJournal(cap.WalPath().wstring(), std::wstring(bridgeVolume.begin(), bridgeVolume.end()), cap.protection, reason));
        CHECK(owner->ProtectedMutationCapacityAvailable(valid, reason) == (mode == 1)); CHECK(!fs::exists(cap.WalPath()));
    }
    Tx ordinary(L"Conservative"); CHECK(!ordinary.ProtectedMutationCapacityAvailable(valid, error));
}
void MaintenancePathPreflight()
{
    for (std::size_t size : {113, 114}) {
        Fixture f(Case(L"tm-spool-path-budget"), true); CHECK(f.base.wstring().size() + 1 < size);
        f.options.root = f.base / std::wstring(size - f.base.wstring().size() - 1, L'x'); Directory(f.options.root);
        Spool spool(f.options); CHECK(!spool.RecoveryRequired()); const auto before = Files(f.options.root), keys = Files(f.options.protected_key_directory);
        CHECK(spool.MatchesProtectedMaintenanceAuthority(f.protection.source_binding, bridgeVolume, f.protection.key_directory) == (size == 113));
        CHECK(Files(f.options.root) == before && Files(f.options.protected_key_directory) == keys && !fs::exists(f.WalPath()));
        if (size == 113) { auto tx = f.Open(); f.Clean(*tx, AcceptInline(f, *tx));
            CHECK(f.Reconcile(*tx, spool, f.Head(*tx)) == Result::Succeeded); }
    }
}
void DirectoryAndMetadataCapacity()
{
    Fixture f(Case(L"tm-typed-directory-metadata"), true); Wal::ProtectedHistoryHead final_head;
    {
        auto tx = f.Open(); Spool spool(f.options);
        for (unsigned kind = 0; kind < 3; ++kind) {
            Tx::MutationIntent m; m.path = bridgePath; m.object_id = 42 + kind; m.generation = 7;
            if (!kind) { m.kind = Tx::MutationKind::CreateDirectory; m.offset = 0750; }
            else {
                m.kind = Tx::MutationKind::SetInodeMetadata;
                apfsaccess::rw::InodeMetadataPatch patch; patch.mask = apfsaccess::rw::InodeMetadataPatch::Owner; patch.owner = 501;
                if (kind == 2) { patch.mask |= apfsaccess::rw::InodeMetadataPatch::BsdFlags; patch.bsd_flags = 4; }
                CHECK(apfsaccess::rw::EncodeInodeMetadataPatch(patch, m.inline_payload));
                CHECK(m.inline_payload.size() == (kind == 1 ? 52 : 56));
                m.length = m.payload_length = m.inline_payload.size(); m.payload_checksum = Sha(m.inline_payload);
            }
            std::string error; const bool exists = fs::exists(f.WalPath()); const auto before = exists ? Read(f.WalPath()) : std::vector<std::uint8_t>{};
            const auto keys = Files(f.protection.key_directory), store = Files(f.options.root);
            CHECK(tx->ProtectedMutationCapacityAvailable(m, error) && error.empty());
            CHECK(fs::exists(f.WalPath()) == exists && (!exists || Read(f.WalPath()) == before));
            CHECK(Files(f.protection.key_directory) == keys && Files(f.options.root) == store);
            const auto sequence = tx->NextMutationSequence(); CHECK(tx->Begin() && tx->RecordMutation(m) && tx->Accept(25));
            auto read = Access::Journal(*tx).ReadAllWithExclusiveWriterLease(); CHECK(read.status == Wal::ReadStatus::Ok);
            const auto& r = read.records[read.records.size() - 2];
            CHECK(r.operation == (kind ? Wal::OperationKind::SetInodeMetadata : Wal::OperationKind::CreateDirectory));
            CHECK(r.sequence == sequence && r.object_id == m.object_id && r.parent_object_id == m.generation);
            CHECK(r.logical_offset == m.offset && r.logical_length == 0 && r.payload_spool_id == 0 && r.payload_offset == 0);
            CHECK(r.payload_length == m.payload_length && r.payload_sha256 == m.payload_checksum && r.inline_payload == m.inline_payload);
            CHECK(!kind || Wal::InodeMetadataMutationIsConsistent(r));
            for (unsigned mode = 0; mode < (kind ? 14u : 8u); ++mode) {
                auto bad = m;
                switch (mode) {
                case 0: bad.generation = 0; break;
                case 1: ++bad.length; break;
                case 2: ++bad.payload_length; break;
                case 3: bad.payload_spool_offset = 1; break;
                case 4: bad.replace_if_exists = true; break;
                case 5: bad.secondary_path = L"other"; break;
                case 6: bad.payload_checksum[0] ^= 1; break;
                case 7: bad.timestamp_utc = 1; break;
                case 8: bad.offset = 1; break;
                case 9: bad.inline_payload[18] = std::byte{1}; bad.payload_checksum = Sha(bad.inline_payload); break;
                case 10: bad.inline_payload[3] = std::byte{3}; bad.payload_checksum = Sha(bad.inline_payload); break;
                case 11: bad.inline_payload.resize(53); bad.length = bad.payload_length = bad.inline_payload.size(); bad.payload_checksum = Sha(bad.inline_payload); break;
                case 12: bad.inline_payload[4] = std::byte{0}; bad.inline_payload[5] = std::byte{2}; bad.payload_checksum = Sha(bad.inline_payload); break;
                case 13: bad.wal_sequence = tx->NextMutationSequence() + 1; break;
                }
                const auto original = Read(f.WalPath()); const auto pinned_keys = Files(f.protection.key_directory);
                CHECK(!tx->ProtectedMutationCapacityAvailable(bad, error) && !error.empty());
                CHECK(Read(f.WalPath()) == original && Files(f.protection.key_directory) == pinned_keys && Files(f.options.root) == store);
            }
        }
        f.Clean(*tx, tx->Watermarks().accepted_sequence); final_head = f.Head(*tx);
        CHECK(f.Reconcile(*tx, spool, final_head) == Result::Succeeded && Read(spool.SpoolFilePath()).empty());
    }
    { auto tx = f.Open(); CHECK(f.Head(*tx) == final_head); }
    for (std::size_t limit : {7, 8}) {
        Fixture cap(Case(L"tm-typed-directory-reserve"), true); cap.protection.read_limits.records = limit; auto tx = cap.Open();
        Tx::MutationIntent m; m.kind = Tx::MutationKind::CreateDirectory; m.object_id = 43; m.generation = 2; m.offset = 0700; m.path = bridgePath;
        std::string error; CHECK(tx->ProtectedMutationCapacityAvailable(m, error) == (limit == 8) && !fs::exists(cap.WalPath()));
    }
}
void QuotaReopenReuse()
{
    Fixture f(Case(L"tm-spool-quota-reopen"), true); f.options.max_bytes = 2 * (bridgePayload.size() + 80);
    Spool::PersistedRangeReference live; Wal::ProtectedHistoryHead old; Snapshot keys;
    {
        auto tx = f.Open(); Spool spool(f.options); const auto first = f.AcceptWrite(*tx, spool);
        const auto second = f.AcceptWrite(*tx, spool, 128); live = second.second; CHECK(spool.SnapshotCounters().spool_bytes == f.options.max_bytes);
        CHECK(spool.CheckAppendCapacity(bridgePayload.size()) == Spool::AppendStatus::QuotaExceeded); f.Clean(*tx, first.first);
        old = f.Head(*tx); const auto data = Read(spool.SpoolFilePath()); keys = Files(f.options.protected_key_directory);
        CHECK(f.Reconcile(*tx, spool, old) == Result::Succeeded && Read(spool.SpoolFilePath()) == data);
        CHECK(spool.CheckAppendCapacity(bridgePayload.size()) == Spool::AppendStatus::QuotaExceeded);
    }
    {
        auto tx = f.Open(); Spool spool(f.options); CHECK(spool.RecoveryRequired());
        CHECK(f.Head(*tx) == old && f.Reconcile(*tx, spool, old) == Result::Succeeded);
        CHECK(spool.CheckAppendCapacity(bridgePayload.size()) == Spool::AppendStatus::QuotaExceeded);
        std::vector<std::byte> bytes; CHECK(spool.ReadPersistedRange(live, bytes) && bytes == Data(bridgePayload));
        f.Clean(*tx, tx->Watermarks().accepted_sequence); CHECK(f.Reconcile(*tx, spool, f.Head(*tx)) == Result::Succeeded);
        CHECK(spool.SnapshotCounters().spool_bytes == 0 && spool.CheckAppendCapacity(bridgePayload.size()) == Spool::AppendStatus::Succeeded);
        const auto row = f.AcceptWrite(*tx, spool, 256); live = row.second; CHECK(live.spool_offset == 0); PreserveKeys(keys, f.options.protected_key_directory);
    }
    { auto tx = f.Open(); Spool spool(f.options); CHECK(f.Reconcile(*tx, spool, f.Head(*tx)) == Result::Succeeded);
        std::vector<std::byte> bytes; CHECK(spool.ReadPersistedRange(live, bytes) && bytes == Data(bridgePayload)); }
}
void PrepareQuotaCut(std::string stage)
{
    Fixture f(root, true); f.options.max_bytes = bridgePayload.size() + 80; auto tx = f.Open(); Spool spool(f.options);
    const auto row = f.AcceptWrite(*tx, spool); CHECK(spool.CheckAppendCapacity(bridgePayload.size()) == Spool::AppendStatus::QuotaExceeded);
    f.Clean(*tx, row.first); const auto head = f.Head(*tx); Write(root / L"original-before.bin", Read(f.WalPath()));
    st::hooks = {}; st::hooks.maintenance_fault = stage;
    CHECK(f.Reconcile(*tx, spool, head) == Result::RecoveryRequired && st::hooks.triggered); st::hooks = {};
    const auto before = Files(f.options.root), keys = Files(f.options.protected_key_directory);
    CHECK(spool.CheckAppendCapacity(bridgePayload.size()) == Spool::AppendStatus::StorageFailure);
    CHECK(!spool.Append({std::string(bridgeVolume), 42, 7, 128, tx->NextMutationSequence(), Data(bridgePayload)}));
    auto wrong = head; wrong.sha256[0] ^= 1; CHECK(f.Reconcile(*tx, spool, wrong) == Result::RejectedBeforeWrite);
    CHECK(Files(f.options.root) == before && Files(f.options.protected_key_directory) == keys);
    CHECK(Read(root / L"original-before.bin") == Read(f.WalPath()));
}
void RecoverQuotaCut()
{
    Fixture f(root, false); f.options.max_bytes = bridgePayload.size() + 80; auto tx = f.Open(); Spool spool(f.options);
    CHECK(spool.RecoveryRequired() && spool.CheckAppendCapacity(bridgePayload.size()) == Spool::AppendStatus::StorageFailure);
    const auto before = Files(f.options.root), keys = Files(f.options.protected_key_directory); auto wrong = f.Head(*tx); ++wrong.bytes;
    CHECK(f.Reconcile(*tx, spool, wrong) == Result::RejectedBeforeWrite && Files(f.options.root) == before);
    CHECK(Files(f.options.protected_key_directory) == keys);
    CHECK(f.Reconcile(*tx, spool, f.Head(*tx)) == Result::Succeeded && Read(spool.SpoolFilePath()).empty());
    CHECK(Read(root / L"original-before.bin") == Read(f.WalPath())); PreserveKeys(keys, f.options.protected_key_directory);
    const auto row = f.AcceptWrite(*tx, spool, 128); CHECK(row.second.spool_offset == 0);
    CHECK(spool.CheckAppendCapacity(bridgePayload.size()) == Spool::AppendStatus::QuotaExceeded);
    std::vector<std::byte> bytes; CHECK(spool.ReadPersistedRange(row.second, bytes) && bytes == Data(bridgePayload));
}
std::pair<std::uint64_t, Spool::PersistedRangeReference> AcceptDual(
    Fixture& f, Tx& tx, Spool& spool, bool physical, bool create = false, std::uint64_t offset = 0)
{
    std::lock_guard lock(f.gate); const auto bytes = Data(bridgePayload); const auto seq = tx.NextMutationSequence();
    Tx::MutationIntent m; m.kind = create ? Tx::MutationKind::CreateFile : Tx::MutationKind::Write;
    m.path = bridgePath; m.object_id = 42; m.generation = 25; m.offset = offset;
    m.length = m.payload_length = bytes.size(); m.payload_checksum = Sha(bytes); m.wal_sequence = seq;
    if (!create) m.inline_payload = bytes;
    if (create) { std::string error; CHECK(tx.ProtectedMutationCapacityAvailable(m, error)); }
    CHECK(tx.Begin());
    if (physical) { Spool::AppendResult out; CHECK(spool.Append({std::string(bridgeVolume), 42, 25, offset, seq, bytes}, &out));
        CHECK(spool.FlushPayloadBytes()); m.payload_spool_offset = out.spool_offset; m.payload_checksum = out.payload_sha256; }
    CHECK(tx.RecordMutation(m) && tx.Accept(25));
    return {tx.Watermarks().accepted_sequence, {std::string(bridgeVolume), 42, 25, offset, bytes.size(), m.payload_spool_offset, seq, m.payload_checksum}};
}
void LockedRangeConsumer()
{
    Fixture f(Case(L"tm-spool-locked-consumer"), true); Spool::PersistedRangeReference ref;
    {
        auto tx = f.Open(); Spool spool(f.options); const auto row = f.AcceptWrite(*tx, spool); ref = row.second;
        CHECK(f.Reconcile(*tx, spool, f.Head(*tx)) == Result::Succeeded);
        const auto before = Files(f.options.root), keys = Files(f.options.protected_key_directory);
        std::string error; unsigned calls = 0; const auto locks = cc::testing::hooks.locks - cc::testing::hooks.unlocks;
        const auto consume = [&](std::span<const std::byte> bytes) {
            ++calls; CHECK(bytes.size() == bridgePayload.size() && std::equal(bytes.begin(), bytes.end(), Data(bridgePayload).begin()));
            CHECK(cc::testing::hooks.locks - cc::testing::hooks.unlocks > locks); return true;
        };
        const auto cng_begin = cc::testing::hooks.cng_calls;
        CHECK(spool.WithProtectedPersistedRange(ref, ref.payload_length, consume, error) && error.empty() && calls == 1);
        const auto cng_operations = cc::testing::hooks.cng_calls - cng_begin; CHECK(cng_operations > 0 && cng_operations < 32);
        for (unsigned mode = 0; mode < 11; ++mode) {
            auto bad = ref; auto bound = ref.payload_length;
            switch (mode) {
            case 0: bound = 0; break; case 1: --bound; break;
            case 2: bound = UINT64_MAX; break; case 3: ++bad.object_id; break;
            case 4: ++bad.generation; break; case 5: ++bad.logical_offset; break;
            case 6: ++bad.spool_offset; break; case 7: ++bad.wal_sequence; break;
            case 8: bad.payload_sha256[0] ^= 1; break; case 9: bad.volume_identity += "-wrong"; break;
            case 10: bad.payload_length = UINT64_MAX; break;
            }
            const auto allocations = cc::testing::hooks.allocations; const auto prior_calls = calls;
            CHECK(!spool.WithProtectedPersistedRange(bad, bound, consume, error) && !error.empty() && calls == prior_calls);
            if (mode < 3 || mode == 10) CHECK(cc::testing::hooks.allocations == allocations);
        }
        CHECK(!spool.WithProtectedPersistedRange(ref, ref.payload_length, {}, error));
        CHECK(!spool.WithProtectedPersistedRange(ref, ref.payload_length, [&](auto) { ++calls; return false; }, error));
        CHECK(calls == 2 && error == "ProtectedPayloadConsumerRejected");
        CHECK(!spool.WithProtectedPersistedRange(ref, ref.payload_length, [&](auto) -> bool { ++calls; throw std::runtime_error("consumer"); }, error));
        CHECK(calls == 3 && cc::testing::hooks.all_released_bytes_zero && jt::hooks.dpapi_released_zero);
        for (unsigned mode = 0; mode < 4; ++mode) {
            const auto prior_calls = calls;
            if (!mode) cc::testing::hooks.allocation_failure_at = cc::testing::hooks.allocations;
            if (mode == 1) cc::testing::hooks.lock_failure_at = cc::testing::hooks.locks;
            if (mode == 2) { cc::testing::hooks.cng_failure_at = cc::testing::hooks.cng_calls; cc::testing::hooks.cng_fail_after_call = true; }
            if (mode == 3) { cc::testing::hooks.cng_failure_at = cc::testing::hooks.cng_calls + cng_operations - 1; cc::testing::hooks.cng_fail_after_call = true; }
            CHECK(!spool.WithProtectedPersistedRange(ref, ref.payload_length, consume, error) && calls == prior_calls);
            cc::testing::hooks.allocation_failure_at = cc::testing::hooks.lock_failure_at = cc::testing::hooks.cng_failure_at = -1;
            cc::testing::hooks.cng_fail_after_call = false;
            CHECK(cc::testing::hooks.all_released_bytes_zero && jt::hooks.dpapi_released_zero);
        }
        CHECK(Files(f.options.root) == before && Files(f.options.protected_key_directory) == keys);
    }
    // The failed tag remains on disk as evidence; no callback can expose it.
    const auto file = f.options.root / L"payload-spool.bin"; auto damaged = Read(file); damaged.back() ^= 1; Write(file, damaged, true);
    auto tx = f.Open(); Spool spool(f.options); unsigned calls = 0; std::string error;
    CHECK(!spool.WithProtectedPersistedRange(ref, ref.payload_length, [&](auto) { ++calls; return true; }, error) && !calls);
    const auto before = Files(f.options.root); CHECK(f.Reconcile(*tx, spool, f.Head(*tx)) == Result::RejectedBeforeWrite);
    CHECK(Files(f.options.root) == before && Read(file) == damaged);
}
void CreateLockedLifecycle()
{
    Fixture f(Case(L"tm-spool-create-locked"), true); Wal::ProtectedHistoryHead head; Spool::PersistedRangeReference ref;
    { auto tx = f.Open(); Spool spool(f.options); const auto row = AcceptDual(f, *tx, spool, true, true, 0644); ref = row.second;
        CHECK(f.Reconcile(*tx, spool, f.Head(*tx)) == Result::Succeeded); std::string error; unsigned calls = 0;
        CHECK(spool.WithProtectedPersistedRange(ref, 4096, [&](auto bytes) { ++calls; return Sha(bytes) == ref.payload_sha256; }, error) && calls == 1);
        head = f.Head(*tx); }
    { auto tx = f.Open(); Spool spool(f.options); std::string error; unsigned calls = 0;
        CHECK(!spool.WithProtectedPersistedRange(ref, 4096, [&](auto) { ++calls; return true; }, error) && !calls);
        CHECK(f.Head(*tx) == head && f.Reconcile(*tx, spool, head) == Result::Succeeded);
        CHECK(spool.WithProtectedPersistedRange(ref, 4096, [&](auto bytes) { ++calls; return Sha(bytes) == ref.payload_sha256; }, error));
        f.Clean(*tx, tx->Watermarks().accepted_sequence); CHECK(f.Reconcile(*tx, spool, f.Head(*tx)) == Result::Succeeded);
        CHECK(Read(spool.SpoolFilePath()).empty()); const auto row = AcceptDual(f, *tx, spool, true, true, 0600); CHECK(row.second.spool_offset == 0); }
}
void Locked64KiB()
{
    Fixture f(Case(L"tm-spool-locked-64k"), true); auto tx = f.Open(); Spool spool(f.options);
    std::vector<std::byte> bytes(65536); for (std::size_t n = 0; n < bytes.size(); ++n) bytes[n] = std::byte(n % 251);
    Tx::MutationIntent m; m.path = bridgePath; m.object_id = 42; m.generation = 25;
    m.length = m.payload_length = bytes.size(); m.payload_checksum = Sha(bytes); m.wal_sequence = tx->NextMutationSequence();
    std::string error; CHECK(tx->ProtectedMutationCapacityAvailable(m, error) && tx->Begin()); Spool::AppendResult out;
    CHECK(spool.Append({std::string(bridgeVolume), 42, 25, 0, m.wal_sequence, bytes}, &out) && spool.FlushPayloadBytes());
    m.payload_spool_offset = out.spool_offset; CHECK(tx->RecordMutation(m) && tx->Accept(25));
    CHECK(f.Reconcile(*tx, spool, f.Head(*tx)) == Result::Succeeded);
    Spool::PersistedRangeReference ref{std::string(bridgeVolume), 42, 25, 0, bytes.size(), out.spool_offset, m.wal_sequence, out.payload_sha256};
    CHECK(spool.WithProtectedPersistedRange(ref, 65536, [&](auto plain) { return plain.size() == bytes.size() && Sha(plain) == m.payload_checksum; }, error));
}
void OptionalInlineCensus()
{
    Fixture f(Case(L"tm-spool-optional-census"), true); Spool::PersistedRangeReference live; Wal::ProtectedHistoryHead head;
    { auto tx = f.Open(); Spool spool(f.options); const auto first = AcceptDual(f, *tx, spool, true);
        const auto absent = AcceptDual(f, *tx, spool, false); (void)absent;
        const auto external = f.AcceptWrite(*tx, spool, 128); live = external.second; f.Clean(*tx, first.first);
        const auto data = Read(spool.SpoolFilePath()); CHECK(f.Reconcile(*tx, spool, f.Head(*tx)) == Result::Succeeded);
        CHECK(Read(spool.SpoolFilePath()) == data && spool.SnapshotCounters().dirty_range_count == 1); head = f.Head(*tx); }
    { auto tx = f.Open(); Spool spool(f.options); CHECK(f.Reconcile(*tx, spool, head) == Result::Succeeded);
        std::string error; CHECK(spool.WithProtectedPersistedRange(live, 65536, [&](auto bytes) { return Sha(bytes) == live.payload_sha256; }, error));
        f.Clean(*tx, tx->Watermarks().accepted_sequence); CHECK(f.Reconcile(*tx, spool, f.Head(*tx)) == Result::Succeeded && Read(spool.SpoolFilePath()).empty()); }
    for (unsigned mode = 0; mode < 3; ++mode) {
        Fixture a(Case(L"tm-spool-optional-unknown"), true); auto tx = a.Open(); Spool spool(a.options);
        const auto row = AcceptDual(a, *tx, spool, true); (void)row;
        if (mode != 2) { const auto bytes = Data("UNKNOWN_PHYSICAL_RANGE"); CHECK(spool.Append({std::string(bridgeVolume), 42, 25, 0, tx->NextMutationSequence(), bytes})); CHECK(spool.FlushPayloadBytes()); }
        const auto absent = AcceptDual(a, *tx, spool, false); a.Clean(*tx, absent.first);
        if (mode == 2) { CHECK(tx->Begin()); Tx::MutationIntent m; m.path = bridgePath; m.object_id = 77; m.generation = 25;
            m.length = m.payload_length = bridgePayload.size(); m.payload_checksum = Sha(Data(bridgePayload)); CHECK(tx->RecordMutation(m) && tx->Accept(25)); a.Clean(*tx, tx->Watermarks().accepted_sequence); }
        if (mode == 1) { tx->SetJournalFaultInjectionHook([](auto stage) { return stage == "durable-flush"; }); }
        const auto before = Files(a.options.root), keys = Files(a.options.protected_key_directory);
        CHECK(a.Reconcile(*tx, spool, a.Head(*tx)) == Result::RejectedBeforeWrite);
        CHECK(Files(a.options.root) == before && Files(a.options.protected_key_directory) == keys);
    }
}
void PrepareOptionalCut(std::string stage)
{
    Fixture f(root, true); auto tx = f.Open(); Spool spool(f.options);
    const auto row = AcceptDual(f, *tx, spool, true); const auto absent = AcceptDual(f, *tx, spool, false); (void)absent;
    // The absent optional inline record remains newer than the cleanup floor.
    // Its absence must survive a reset cut through the authenticated intent.
    f.Clean(*tx, row.first); const auto head = f.Head(*tx); Write(root / L"original-before.bin", Read(f.WalPath()));
    st::hooks = {}; st::hooks.maintenance_fault = stage;
    CHECK(f.Reconcile(*tx, spool, head) == Result::RecoveryRequired && st::hooks.triggered); st::hooks = {};
    CHECK(spool.RecoveryRequired());
}
void RecoverOptionalCut()
{
    Fixture f(root, false); auto tx = f.Open(); Spool spool(f.options); CHECK(spool.RecoveryRequired());
    const auto keys = Files(f.options.protected_key_directory), before = Files(f.options.root);
    auto bad = f.Head(*tx); bad.sha256[0] ^= 1; CHECK(f.Reconcile(*tx, spool, bad) == Result::RejectedBeforeWrite);
    CHECK(Files(f.options.root) == before && Files(f.options.protected_key_directory) == keys);
    CHECK(f.Reconcile(*tx, spool, f.Head(*tx)) == Result::Succeeded && Read(spool.SpoolFilePath()).empty());
    CHECK(Read(root / L"original-before.bin") == Read(f.WalPath())); PreserveKeys(keys, f.options.protected_key_directory);
    const auto row = f.AcceptWrite(*tx, spool, 128); CHECK(row.second.spool_offset == 0); std::string error;
    CHECK(spool.WithProtectedPersistedRange(row.second, 65536, [&](auto bytes) { return Sha(bytes) == row.second.payload_sha256; }, error));
}
void PrepareCut(std::string stage)
{
    Fixture f(root, true); auto tx = f.Open(); Spool spool(f.options); const auto row = f.AcceptWrite(*tx, spool); f.Clean(*tx, row.first);
    Write(root / L"original-before.bin", Read(f.WalPath())); st::hooks = {}; st::hooks.maintenance_fault = stage;
    CHECK(f.Reconcile(*tx, spool, f.Head(*tx)) == Result::RecoveryRequired && st::hooks.triggered);
    CHECK(Read(root / L"original-before.bin") == Read(f.WalPath())); st::hooks = {};
}
void RecoverCut()
{
    Fixture f(root, false); auto tx = f.Open(); Spool spool(f.options); const auto keys = Files(f.options.protected_key_directory);
    CHECK(f.Reconcile(*tx, spool, f.Head(*tx)) == Result::Succeeded); CHECK(Read(spool.SpoolFilePath()).empty());
    CHECK(Read(root / L"original-before.bin") == Read(f.WalPath())); PreserveKeys(keys, f.options.protected_key_directory);
    const auto row = f.AcceptWrite(*tx, spool, 128); CHECK(row.second.spool_offset == 0);
    std::vector<std::byte> bytes; CHECK(spool.ReadPersistedRange(row.second, bytes) && bytes == Data(bridgePayload));
}
}
int wmain(int argc, wchar_t** argv)
{
    try {
        CHECK(argc == 2 || argc == 3 || argc == 4); root = argv[1]; CHECK(LocalAbsolute(root));
        const auto mode = argc >= 3 ? std::wstring_view(argv[2]) : std::wstring_view{};
        const bool recovery = argc == 4 && (mode == L"--recover-cut" || mode == L"--recover-quota-cut" || mode == L"--recover-optional-cut");
        if (recovery) { Pins pins(root); if (mode == L"--recover-cut") RecoverCut(); else if (mode == L"--recover-quota-cut") RecoverQuotaCut(); else RecoverOptionalCut(); }
        else { Directory(root);
            if (argc == 4) { CHECK(mode == L"--prepare-cut" || mode == L"--prepare-quota-cut" || mode == L"--prepare-optional-cut"); const std::wstring stage = argv[3];
                if (mode == L"--prepare-cut") PrepareCut(std::string(stage.begin(), stage.end())); else if (mode == L"--prepare-quota-cut") PrepareQuotaCut(std::string(stage.begin(), stage.end())); else PrepareOptionalCut(std::string(stage.begin(), stage.end())); }
            else {
                CHECK(argc == 2 || mode == L"--runtime-contract" || mode == L"--locked-runtime" || mode == L"--typed-metadata-capacity");
                if (mode == L"--typed-metadata-capacity") {
                    Group("actual Directory and canonical 52/56-byte metadata capacity, acceptance, reopen and refusal controls", DirectoryAndMetadataCapacity);
                    Group("existing actual typed capacity profile and budgets", TypedCapacity);
                    Group("existing ordinary TM behavior", OrdinaryBridgeRefusal);
                    Group("existing ordinary WAL codec", OrdinaryCodec); Group("existing ordinary WAL persistence", OrdinaryPersistence);
                    CHECK(cc::testing::hooks.all_released_bytes_zero && jt::hooks.dpapi_released_zero);
                    std::cout << "PASS " << groups << " groups / " << checks << " assertions / " << cases << " cases\n"; return 0;
                }
                if (argc == 2 || mode == L"--locked-runtime") {
                    Group("locked synchronous exact-reference consumer bounds, failures, wiping and tamper refusal", LockedRangeConsumer);
                    Group("real external Create permissions/parent identity, locked read, reclaim and reopen/reuse", CreateLockedLifecycle);
                    Group("actual accepted 64KiB external payload is consumed through locked memory without quota changes", Locked64KiB);
                    Group("authenticated optional inline census supports actual frames, absent frames, partial live and unknown-byte refusal", OptionalInlineCensus);
                }
                Group("complete inline virgin and parent-XID no-frame histories work while unknown actual bytes refuse", InlineVirginAndAmbiguity);
                Group("actual typed capacity/prepared/accepted mapping, bounded records/bytes/allocation and seven-marker reserve", TypedCapacity);
                Group("full real quota, partial live offsets, reopen, all-clean reset and accepted offset-zero reuse", QuotaReopenReuse);
                Group("generated maintenance and failed-fragment path budgets preflight at the exact boundary", MaintenancePathPreflight);
                Group("an authenticated spool marker never authorizes recreating missing canonical files", MissingCanonicalRefusal);
                Group("unconditional original barrier and before/after-flush source mutation refuse before spool entry", OriginalBarrierControls);
                if (argc == 2) {
                Group("actual TM accepted write, durable cleanup, reset, reopen and offset-zero reuse", Lifecycle);
                Group("complete original refs preserve live physical offsets through partial cleanup/reopen", PartialLive);
                Group("wrong head/source/volume/JID, active owner, unknown physical tail and original debt refuse", AuthorityAndTailControls);
                Group("pending receipt cannot accept a changed original head or advisory substitute proof", PendingHeadMismatch);
                Group("retained checkpoint anchors, compaction debt and incomplete actual TM preparation refuse", CompactionAndIncompleteHistory);
                Group("complete refs include actual aborted physical writes before later accepted cleanup", AbortedPhysicalReferences);
                Group("an unlogged aborted physical frame stays unknown and cannot be silently retired", UnloggedAbortedPhysicalRange);
                }
                Group("ordinary TM acceptance/watermarks preserved, protected bridge refuses", OrdinaryBridgeRefusal);
                Group("existing ordinary WAL codec", OrdinaryCodec); Group("existing ordinary WAL persistence", OrdinaryPersistence);
            }
        }
        CHECK(cc::testing::hooks.all_released_bytes_zero && jt::hooks.dpapi_released_zero);
        std::cout << "PASS " << groups << " groups / " << checks << " assertions / " << cases << " cases\n"; return 0;
    } catch (const std::exception& e) { std::cerr << "FAIL " << e.what() << '\n'; return 1; }
}
