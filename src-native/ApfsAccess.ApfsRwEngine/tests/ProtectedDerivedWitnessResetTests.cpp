#define wmain RetainedProtectedWalSuiteEntry
#include "ProtectedWriteAheadLogTests.cpp"
#undef wmain

namespace apfsaccess::rw
{
struct DerivedWitnessResetTestAccess
{
    using Authority = WriteAheadLog::DerivedWitnessResetAuthority;
    using Authorizer = WriteAheadLog::DerivedWitnessAuthorizer;
    static auto Rebuild(WriteAheadLog& wal, std::span<const WriteAheadLog::Record> records,
        const Authorizer& authorize, const std::function<bool()>& barrier, WriteAheadLog::ProtectedHistoryHead& head)
    { return wal.RebuildDerivedWitnessV4(records, authorize, barrier, head); }
};
}
namespace
{
using Access = apfsaccess::rw::DerivedWitnessResetTestAccess;
using ResetResult = Wal::CompactionResult;
template<class T> concept PublicReset = requires { &T::RebuildDerivedWitnessV4; };
template<class T> concept PublicAuthority = requires { typename T::DerivedWitnessResetAuthority; };
static_assert(!PublicReset<Wal> && !PublicAuthority<Wal>);
constexpr std::string_view chunkPath = "\\encrypted-publication-chunk-v2", endPath = "\\encrypted-publication-end-v2";
constexpr std::string_view planCanary = "DERIVED_RESET_PRIVATE_PLAN_CANARY";
constexpr std::uint64_t acceptedS = 4, transactionT = 123, preimageX = 7, volumeI = 37;
void Put(std::span<std::byte> b, std::size_t at, std::uint64_t v)
{ for (unsigned n = 0; n < 8; ++n) b[at + n] = std::byte((v >> (8 * n)) & 255); }
std::uint64_t Number(std::span<const std::byte> b, std::size_t at)
{ CHECK(at <= b.size() && b.size() - at >= 8); std::uint64_t v = 0; for (unsigned n = 0; n < 8; ++n) v |= std::to_integer<std::uint64_t>(b[at + n]) << (8 * n); return v; }
std::array<std::uint8_t, 32> Sha(std::span<const std::byte> b)
{
    std::array<std::uint8_t, 32> d{}; CHECK(BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0,
        reinterpret_cast<PUCHAR>(const_cast<std::byte*>(b.data())), static_cast<ULONG>(b.size()), d.data(), 32) >= 0); return d;
}
std::vector<std::byte> Template()
{
    std::vector<std::byte> a(9000); for (std::size_t n = 88; n < a.size(); ++n) a[n] = std::byte((n * 17 + 29) & 255);
    Put(a, 0, 4); Put(a, 24, volumeI); Put(a, 48, 32);
    const auto original_journal = Digest(91); std::copy(original_journal.begin(), original_journal.end(), a.begin() + 256);
    std::memcpy(a.data() + 128, planCanary.data(), planCanary.size()); return a;
}
std::vector<Wal::Record> Rows(std::span<const std::byte> a, std::uint64_t s = acceptedS,
    std::uint64_t t = transactionT, std::uint64_t version = 4)
{
    auto body = std::vector<std::byte>(a.begin(), a.end()); Put(body, 0, version); Put(body, 8, s); Put(body, 16, t); Put(body, 40, a.size());
    const auto digest = Sha(a); std::memcpy(body.data() + 56, digest.data(), 32);
    std::vector<Wal::Record> rows;
    Wal::Record r; r.volume_identity = "ordinary-gate-volume"; r.operation = Wal::OperationKind::Write; r.state = Wal::RecordState::Prepared;
    r.parent_object_id = s; r.transaction_id = t; r.object_id = volumeI;
    for (std::size_t at = 0; at < body.size(); at += 4096) {
        r.sequence = rows.size() + 1; r.path_utf8 = chunkPath; r.logical_offset = at;
        r.inline_payload.assign(body.begin() + at, body.begin() + (std::min)(body.size(), at + 4096));
        r.payload_length = r.logical_length = r.inline_payload.size(); r.payload_sha256 = Sha(r.inline_payload); rows.push_back(r);
    }
    r.sequence = rows.size() + 1; r.path_utf8 = endPath; r.logical_offset = 0; r.inline_payload.assign(88, std::byte{});
    Put(r.inline_payload, 0, 2); Put(r.inline_payload, 8, s); Put(r.inline_payload, 16, t); Put(r.inline_payload, 24, volumeI);
    Put(r.inline_payload, 32, rows.size()); Put(r.inline_payload, 40, body.size()); Put(r.inline_payload, 48, 32);
    const auto hash = Sha(body); std::memcpy(r.inline_payload.data() + 56, hash.data(), 32);
    r.payload_length = r.logical_length = r.inline_payload.size(); r.payload_sha256 = Sha(r.inline_payload); rows.push_back(r); return rows;
}
std::vector<Wal::Record> OlderRows(std::span<const std::byte> a, bool corrupt)
{
    auto rows = Rows(a, 2, 122, 2);
    if (corrupt) {
        rows.front().inline_payload[16] ^= std::byte{1}; rows.front().payload_sha256 = Sha(rows.front().inline_payload);
        std::vector<std::byte> body; for (std::size_t n = 0; n + 1 < rows.size(); ++n) body.insert(body.end(), rows[n].inline_payload.begin(), rows[n].inline_payload.end());
        const auto hash = Sha(body); std::memcpy(rows.back().inline_payload.data() + 56, hash.data(), 32); rows.back().payload_sha256 = Sha(rows.back().inline_payload);
    }
    return rows;
}
struct Fixture
{
    fs::path base; Wal::Options witness, original;
    unsigned authorizations = 0, barriers = 0, target_calls = 0;
    unsigned mint_fault = 0;
    bool refuse_authority = false, refuse_barrier = false;
    explicit Fixture(fs::path p, bool create) : base(std::move(p))
    {
        if (create) { Directory(base / L"keys"); Directory(base / L"original-keys"); }
        witness = Ordinary(base); Wal::ProtectedPersistence protection;
        protection.key_directory = base / L"keys"; protection.source_binding = Digest(31); protection.journal_identity = Digest(71);
        witness.protected_persistence = protection;
        original = witness; original.path = base / L"original.wal"; original.volume_identity = "derived-reset-original-owner";
        original.protected_persistence->key_directory = base / L"original-keys"; original.protected_persistence->journal_identity = Digest(91);
    }
    std::vector<std::byte> Original()
    {
        Wal wal(original); const auto all = wal.ReadAllWithExclusiveWriterLease(); CHECK(all.status == Wal::ReadStatus::Ok);
        if (all.records.size() < 4) return {}; std::vector<std::byte> a;
        for (std::size_t n = 0; n < 3; ++n) {
            const auto& r = all.records[n]; CHECK(r.sequence == n + 1 && r.transaction_id == transactionT && r.object_id == volumeI);
            CHECK(r.path_utf8 == "\\$apfs-keybag-rewrap-v2" && r.payload_spool_id == preimageX && r.logical_offset == a.size());
            CHECK(r.operation == Wal::OperationKind::Write && r.state == Wal::RecordState::Prepared && Wal::InlinePayloadIsConsistent(r));
            a.insert(a.end(), r.inline_payload.begin(), r.inline_payload.end());
        }
        const auto& marker = all.records[3]; CHECK(marker.sequence == acceptedS && marker.transaction_id == transactionT &&
            marker.operation == Wal::OperationKind::TransactionMarker && marker.state == Wal::RecordState::Accepted && marker.object_id == preimageX);
        for (std::size_t n = 4; n < all.records.size(); ++n) {
            CHECK(all.records[n].operation == Wal::OperationKind::DurabilityWatermark);
            if (all.records[n].parent_object_id >= acceptedS) return {};
        }
        return a;
    }
    bool Authorize(std::span<const Wal::Record> prefix, Access::Authority& a)
    {
        ++authorizations; if (refuse_authority) return false;
        const auto original_bytes = Original(); if (original_bytes.empty()) return false;
        if (Number(original_bytes, 0) != 4 || !std::equal(original.protected_persistence->journal_identity.begin(),
            original.protected_persistence->journal_identity.end(), original_bytes.begin() + 256)) return false;
        const auto digest = Sha(original_bytes); const Wal::Record* certificate = nullptr;
        std::vector<std::byte> body; std::uint64_t group_s = 0, group_t = 0, group_i = 0, prior_s = 0, chunks = 0;
        for (const auto& r : prefix) {
            if (r.operation != Wal::OperationKind::Write || r.state != Wal::RecordState::Prepared || !Wal::InlinePayloadIsConsistent(r)) return false;
            if (!chunks) { if (r.parent_object_id <= prior_s) return false; group_s = r.parent_object_id; group_t = r.transaction_id; group_i = r.object_id; }
            if (r.parent_object_id != group_s || r.transaction_id != group_t || r.object_id != group_i) return false;
            if (r.path_utf8 == chunkPath) {
                if (r.logical_offset != body.size() || r.inline_payload.empty() || r.inline_payload.size() > 4096) return false;
                if (!chunks && group_s == acceptedS) certificate = &r;
                body.insert(body.end(), r.inline_payload.begin(), r.inline_payload.end()); ++chunks;
            } else if (r.path_utf8 == endPath) {
                if (!chunks || r.inline_payload.size() != 88 || Number(r.inline_payload, 8) != group_s || Number(r.inline_payload, 16) != group_t ||
                    Number(r.inline_payload, 24) != group_i || Number(r.inline_payload, 32) != chunks || Number(r.inline_payload, 40) != body.size() ||
                    Number(body, 8) != group_s || Number(body, 16) != group_t || Number(body, 24) != group_i) return false;
                const auto hash = Sha(body); if (std::memcmp(r.inline_payload.data() + 56, hash.data(), 32)) return false;
                prior_s = group_s; chunks = 0; body.clear();
            } else return false;
        }
        if (!certificate || !chunks || group_s != acceptedS || certificate->inline_payload.size() < 88 || Number(certificate->inline_payload, 0) != 4 ||
            Number(certificate->inline_payload, 8) != acceptedS || Number(certificate->inline_payload, 16) != transactionT ||
            Number(certificate->inline_payload, 24) != volumeI || Number(certificate->inline_payload, 40) != original_bytes.size() ||
            Number(certificate->inline_payload, 48) != 32 || std::memcmp(certificate->inline_payload.data() + 56, digest.data(), 32)) return false;
        const auto rows = Rows(original_bytes); std::vector<std::byte> complete;
        for (std::size_t n = 0; n + 1 < rows.size(); ++n) complete.insert(complete.end(), rows[n].inline_payload.begin(), rows[n].inline_payload.end());
        a.source_binding = witness.protected_persistence->source_binding; a.original_journal_identity = original.protected_persistence->journal_identity;
        a.scope_binding = Digest(111); a.accepted_sequence = acceptedS; a.transaction_id = transactionT; a.preimage_xid = preimageX; a.inode = volumeI;
        a.template_bytes = original_bytes.size(); a.template_sha256 = digest; a.body_bytes = complete.size(); a.body_sha256 = Sha(complete);
        a.authorization_bytes = certificate->inline_payload.size(); a.authorization_sha256 = Sha(certificate->inline_payload);
        if (mint_fault == 1) a.original_journal_identity[0] ^= std::byte{1};
        if (mint_fault == 2) a.scope_binding[0] ^= std::byte{1};
        if (mint_fault == 3) ++a.preimage_xid;
        if (mint_fault == 4) a.body_sha256[0] ^= 1;
        if (mint_fault == 5) a.authorization_sha256[0] ^= 1;
        if (mint_fault == 6) a.authorization_bytes = 87;
        if (mint_fault == 7) a.authorization_bytes = 4097;
        return true;
    }
    bool Barrier()
    {
        ++barriers; if (refuse_barrier || Original().empty()) return false;
        Wal wal(original); CHECK(wal.ReadAllWithExclusiveWriterLease().status == Wal::ReadStatus::Ok);
        const auto count = wal.SnapshotCounters().append_handle_flush_count; CHECK(wal.FlushPendingAppends());
        CHECK(wal.SnapshotCounters().append_handle_flush_count == count + 1); return true;
    }
    ResetResult Reset(Wal& wal, Wal::ProtectedHistoryHead& head, const std::vector<Wal::Record>* replacement_rows = nullptr)
    {
        auto rows = replacement_rows ? *replacement_rows : Expected();
        return Access::Rebuild(wal, rows, [&](auto prefix, auto& a) { return Authorize(prefix, a); }, [&] { return Barrier(); }, head);
    }
    std::vector<Wal::Record> Expected()
    {
        return Rows(Original());
    }
    void Seed(bool changed_original = false, bool separate_epoch = false, bool historical_m1 = false,
        std::uint64_t version = 4, bool wrong_original = false, bool accept = true, bool history = false)
    {
        jt::hooks = {}; auto a = Template(); Put(a, 0, version); if (wrong_original) a[256] ^= std::byte{1};
        auto rows = Rows(a, acceptedS, transactionT, version);
        if (historical_m1 || history) {
            auto older = OlderRows(a, historical_m1);
            for (auto& r : rows) r.sequence += older.size(); older.insert(older.end(), rows.begin(), rows.end()); rows = std::move(older);
        }
        // Simulate Root's private certificate being durable BEFORE acceptance.
        { Wal wal(witness); for (std::size_t n = 0; n < (separate_epoch ? 1 : rows.size()); ++n) CHECK(wal.Append(rows[n], false)); CHECK(wal.FlushPendingAppends()); }
        if (separate_epoch) { Wal wal(witness); for (std::size_t n = 1; n < rows.size(); ++n) CHECK(wal.Append(rows[n], false)); CHECK(wal.FlushPendingAppends()); }
        if (changed_original) a.back() ^= std::byte{1};
        { Wal wal(original); for (std::size_t at = 0; at < a.size(); at += 4096) {
                Wal::Record r; r.volume_identity = original.volume_identity; r.sequence = at / 4096 + 1; r.transaction_id = transactionT;
                r.object_id = volumeI; r.payload_spool_id = preimageX; r.path_utf8 = "\\$apfs-keybag-rewrap-v2"; r.logical_offset = at;
                r.inline_payload.assign(a.begin() + at, a.begin() + (std::min)(a.size(), at + 4096));
                r.payload_length = r.logical_length = r.inline_payload.size(); r.payload_sha256 = Sha(r.inline_payload); CHECK(wal.Append(r, false));
            }
            if (accept) {
                Wal::Record r; r.volume_identity = original.volume_identity; r.sequence = acceptedS; r.transaction_id = transactionT;
                r.operation = Wal::OperationKind::TransactionMarker; r.state = Wal::RecordState::Accepted; r.object_id = preimageX; CHECK(wal.Append(r));
            } else CHECK(wal.FlushPendingAppends()); }
        const auto bytes = Read(witness.path); Write(base / L"pristine.bin", bytes);
    }
    void Tear(std::size_t record, std::size_t retained)
    {
        const auto full = Read(base / L"pristine.bin"); const auto frames = Frames(full); CHECK(record < frames.size());
        const auto end = frames[record] + retained; CHECK(end < full.size()); const auto raw = std::span(full).first(end);
        Write(witness.path, raw, true); Write(base / L"damaged.bin", raw);
    }
    void Prove()
    {
        const auto damaged = Read(base / L"damaged.bin"); bool found = false;
        for (const auto& entry : fs::directory_iterator(base)) if (entry.path().filename().wstring().starts_with(L"journal.wal.wrsaved.")) {
            CHECK(Read(entry.path()) == damaged); found = true;
        }
        CHECK(found && target_calls == 0); Wal wal(witness); const auto all = wal.ReadAllWithExclusiveWriterLease(); CHECK(all.status == Wal::ReadStatus::Ok);
        const auto expected = Expected(); CHECK(all.records.size() == expected.size());
        for (std::size_t n = 0; n < expected.size(); ++n) CHECK(Wal::EncodeForTest(all.records[n]) == Wal::EncodeForTest(expected[n]));
        auto later = Rows(Template(), 8, transactionT + 1);
        for (auto& r : later) { r.sequence += expected.size(); CHECK(wal.Append(r, false)); }
        CHECK(wal.FlushPendingAppends()); CHECK(wal.ReadAll().records.size() == expected.size() + later.size());
    }
};
Fixture NewFixture(const wchar_t* label) { return Fixture(Case(label), true); }
void ExactRefusal(Fixture& f)
{
    const auto before = Files(f.base), keys = Files(f.witness.protected_persistence->key_directory), original_keys = Files(f.original.protected_persistence->key_directory);
    { Wal wal(f.witness); Wal::ProtectedHistoryHead head; CHECK(f.Reset(wal, head) == ResetResult::RejectedBeforeWrite); CHECK(head == Wal::ProtectedHistoryHead{}); }
    CHECK(Files(f.base) == before && Files(f.witness.protected_persistence->key_directory) == keys &&
        Files(f.original.protected_persistence->key_directory) == original_keys); CHECK(f.barriers == 0 && f.target_calls == 0);
}
void CertificateBoundary()
{
    for (unsigned kind = 0; kind < 5; ++kind) {
        auto f = NewFixture(L"certificate"); f.Seed(kind == 0, false, kind == 3);
        if (kind == 1) f.Tear(1, 13); else if (kind == 2) f.Tear(1, 64); else if (kind == 3) f.Tear(6, 63); else f.Tear(2, 63);
        if (kind == 4) f.refuse_authority = true;
        ExactRefusal(f); if (kind < 3) CHECK(f.authorizations == 0);
    }
    auto f = NewFixture(L"barrier"); f.Seed(); f.Tear(2, 63); f.refuse_barrier = true;
    const auto before = Files(f.base), keys = Files(f.witness.protected_persistence->key_directory);
    { Wal wal(f.witness); Wal::ProtectedHistoryHead head; CHECK(f.Reset(wal, head) == ResetResult::RejectedBeforeWrite); }
    CHECK(f.barriers == 1 && Files(f.base) == before && Files(f.witness.protected_persistence->key_directory) == keys);
}
void CertificateV4Controls()
{
    for (unsigned kind = 0; kind < 4; ++kind) {
        auto f = NewFixture(L"v4-certificate"); f.Seed(false, false, false, kind < 2 ? 3 : 4, kind == 2, kind != 3); f.Tear(2, 63);
        auto a = Template(); if (kind == 0) Put(a, 0, 3); if (kind == 2) a[256] ^= std::byte{1};
        const auto rows = Rows(a, acceptedS, transactionT, kind == 0 ? 3 : 4);
        const auto before = Files(f.base), keys = Files(f.witness.protected_persistence->key_directory);
        { Wal wal(f.witness); Wal::ProtectedHistoryHead head; CHECK(f.Reset(wal, head, &rows) == ResetResult::RejectedBeforeWrite);
            CHECK(head == Wal::ProtectedHistoryHead{}); }
        CHECK(Files(f.base) == before && Files(f.witness.protected_persistence->key_directory) == keys && f.barriers == 0 && f.target_calls == 0);
        if (kind < 2) CHECK(f.authorizations == 0);
        else CHECK(f.authorizations == 1);
        if (kind == 3) { Wal wal(f.original); CHECK(wal.ReadAll().records.size() == 3); } // Private authorization debt remains.
    }
}
void FragmentBoundaries()
{
    for (std::size_t frame = 2; frame <= 4; ++frame) for (std::size_t cut : {1u, 7u, 8u, 11u, 12u, 15u, 16u, 19u, 20u, 23u, 24u, 39u, 40u, 51u, 52u, 63u, 64u, 65u, 99999u, 99998u}) {
        auto f = NewFixture(L"fragment"); f.Seed(); const auto full = Read(f.base / L"pristine.bin"); const auto frames = Frames(full);
        const auto length = U32(full, frames[frame] + 16); const auto n = cut == 99999 ? length - 1 : cut == 99998 ? length - 16 : cut;
        f.Tear(frame, n); const auto original = Read(f.original.path); const auto old_keys = Files(f.witness.protected_persistence->key_directory);
        { Wal wal(f.witness); BadRead(wal); Wal::ProtectedHistoryHead head;
            CHECK(f.Reset(wal, head) == ResetResult::Succeeded); CHECK(head.records == 4 && head.last_sequence == 4 && f.barriers == 1); }
        CHECK(Read(f.original.path) == original); for (const auto& [name, b] : old_keys) CHECK(Read(f.witness.protected_persistence->key_directory / name) == b);
        f.Prove();
    }
}
void StrictPhysicalRefusals()
{
    for (unsigned kind = 0; kind < 7; ++kind) {
        auto f = NewFixture(L"strict"); f.Seed(); auto full = Read(f.base / L"pristine.bin"); const auto frames = Frames(full);
        if (kind == 0) full.back() ^= 1; // Full-size final bad tag remains unsupported.
        if (kind == 1) full[frames[1] + 70] ^= 1; // Interior authentication failure.
        if (kind == 2) full.push_back(0x41); // Selected terminal was complete.
        if (kind == 3) full.resize(103); // Incomplete anchor.
        if (kind == 4) full.resize(frames[2]); // Complete-record prefix belongs to normal restage.
        if (kind == 5) { full.resize(frames[2] + 64); full[frames[2] + 20] ^= 1; }
        if (kind == 6) { full.resize(frames[2] + 64); full[frames[2] + 52] = 1; }
        Write(f.witness.path, full, true); Write(f.base / L"damaged.bin", full); ExactRefusal(f);
    }
    auto missing = NewFixture(L"key"); missing.Seed(false, true); missing.Tear(2, 40);
    const auto full = Read(missing.base / L"pristine.bin"); const auto positions = Frames(full);
    constexpr wchar_t hex[] = L"0123456789abcdef"; std::wstring slot = L"epoch-";
    for (std::size_t n = positions[2] + 24; n < positions[2] + 40; ++n) { slot += hex[full[n] >> 4]; slot += hex[full[n] & 15]; }
    slot += L".key"; fs::rename(missing.witness.protected_persistence->key_directory / slot, missing.base / L"retained-slot.bin"); ExactRefusal(missing);
}
void DurableNotCleanedAndDebt()
{
    auto f = NewFixture(L"durable"); f.Seed(); f.Tear(2, 63);
    { Wal wal(f.original); auto r = Marker(5, Wal::RecordState::Cleaned); r.volume_identity = f.original.volume_identity;
        r.operation = Wal::OperationKind::DurabilityWatermark; r.object_id = acceptedS; r.parent_object_id = 0; CHECK(wal.Append(r)); }
    const auto original = Read(f.original.path);
    { Wal wal(f.witness); bool hit = false; wal.SetFaultInjectionHook([&](auto stage) { if (stage == "wreset-after-save") { hit = true; return true; } return false; });
        Wal::ProtectedHistoryHead head; CHECK(f.Reset(wal, head) == ResetResult::BytesMayHavePersisted); CHECK(hit && !fs::exists(f.witness.path)); }
    { Wal protected_reader(f.witness); BadRead(protected_reader); CHECK(!protected_reader.Append(PrivateRecord(6)));
        auto plain = f.witness; plain.protected_persistence.reset(); Wal legacy(plain); CHECK(!legacy.Append(Record(6)));
        CHECK(Wal::ReadAll(f.witness.path, f.witness.volume_identity).status != Wal::ReadStatus::Ok); }
    { Wal wal(f.witness); Wal::ProtectedHistoryHead head; CHECK(f.Reset(wal, head) == ResetResult::Succeeded); }
    CHECK(Read(f.original.path) == original); f.Prove();
    auto cleaned = NewFixture(L"cleaned"); cleaned.Seed(); cleaned.Tear(2, 63);
    { Wal wal(cleaned.original); auto r = Marker(5, Wal::RecordState::Cleaned); r.volume_identity = cleaned.original.volume_identity;
        r.operation = Wal::OperationKind::DurabilityWatermark; r.object_id = r.parent_object_id = acceptedS; CHECK(wal.Append(r)); }
    const auto expected = Rows(Template()); const auto before = Files(cleaned.base);
    { Wal wal(cleaned.witness); Wal::ProtectedHistoryHead head; CHECK(cleaned.Reset(wal, head, &expected) == ResetResult::RejectedBeforeWrite); }
    CHECK(Files(cleaned.base) == before && cleaned.barriers == 0);
}
void RecoveryAuthorityControls()
{
    auto f = NewFixture(L"receipt-authority"); f.Seed(); f.Tear(2, 63);
    { Wal wal(f.witness); wal.SetFaultInjectionHook([](auto s) { return s == "wreset-after-receipt-readback"; });
        Wal::ProtectedHistoryHead head; CHECK(f.Reset(wal, head) == ResetResult::BytesMayHavePersisted); }
    const auto before = Files(f.base), keys = Files(f.witness.protected_persistence->key_directory);
    const auto barriers = f.barriers;
    for (unsigned fault = 1; fault <= 7; ++fault) {
        f.mint_fault = fault; Wal wal(f.witness); Wal::ProtectedHistoryHead head;
        CHECK(f.Reset(wal, head) == ResetResult::BytesMayHavePersisted); CHECK(head == Wal::ProtectedHistoryHead{});
        CHECK(f.barriers == barriers && Files(f.base) == before && Files(f.witness.protected_persistence->key_directory) == keys);
    }
    f.mint_fault = 0; f.refuse_barrier = true;
    { Wal wal(f.witness); Wal::ProtectedHistoryHead head; CHECK(f.Reset(wal, head) == ResetResult::BytesMayHavePersisted); }
    CHECK(Files(f.base) == before && Files(f.witness.protected_persistence->key_directory) == keys);
    f.refuse_barrier = false;
    { Wal wal(f.witness); Wal::ProtectedHistoryHead head; CHECK(f.Reset(wal, head) == ResetResult::Succeeded); }
    f.Prove();
    auto changed = NewFixture(L"candidate-body"); changed.Seed(); changed.Tear(2, 63);
    auto rows = Rows(changed.Original()); rows[2].inline_payload.back() ^= std::byte{1}; rows[2].payload_sha256 = Sha(rows[2].inline_payload);
    std::vector<std::byte> body; for (std::size_t n = 0; n + 1 < rows.size(); ++n) body.insert(body.end(), rows[n].inline_payload.begin(), rows[n].inline_payload.end());
    const auto hash = Sha(body); std::memcpy(rows.back().inline_payload.data() + 56, hash.data(), 32); rows.back().payload_sha256 = Sha(rows.back().inline_payload);
    const auto unchanged = Files(changed.base);
    { Wal wal(changed.witness); Wal::ProtectedHistoryHead head; CHECK(changed.Reset(wal, head, &rows) == ResetResult::RejectedBeforeWrite); }
    CHECK(Files(changed.base) == unchanged && changed.barriers == 0);
    for (bool missing_key : {false, true}) {
        auto bad = NewFixture(L"receipt-corruption"); bad.Seed(); bad.Tear(2, 63);
        { Wal wal(bad.witness); wal.SetFaultInjectionHook([](auto s) { return s == "wreset-after-receipt-readback"; });
            Wal::ProtectedHistoryHead head; CHECK(bad.Reset(wal, head) == ResetResult::BytesMayHavePersisted); }
        if (missing_key) {
            const auto frame = Read(Side(bad.witness.path, L".wreset.intent")); constexpr wchar_t hex[] = L"0123456789abcdef"; std::wstring slot = L"epoch-";
            for (std::size_t n = 24; n < 40; ++n) { slot += hex[frame[n] >> 4]; slot += hex[frame[n] & 15]; } slot += L".key";
            fs::rename(bad.witness.protected_persistence->key_directory / slot, bad.base / L"retained-new-key.bin");
        } else { auto b = Read(Side(bad.witness.path, L".wreset.intent")); b.back() ^= 1; Write(Side(bad.witness.path, L".wreset.intent"), b, true); }
        const auto snapshot = Files(bad.base), key_snapshot = Files(bad.witness.protected_persistence->key_directory);
        { Wal wal(bad.witness); Wal::ProtectedHistoryHead head; CHECK(bad.Reset(wal, head) == ResetResult::BytesMayHavePersisted); }
        CHECK(Files(bad.base) == snapshot && Files(bad.witness.protected_persistence->key_directory) == key_snapshot && bad.target_calls == 0);
    }
}
void ProviderAndBudgetControls()
{
    for (unsigned kind = 0; kind < 7; ++kind) {
        auto f = NewFixture(L"provider"); f.Seed(); f.Tear(2, 63);
        const auto before = Read(f.witness.path), original = Read(f.original.path); bool injected = false;
        { Wal wal(f.witness); wal.SetFaultInjectionHook([&](auto stage) {
                if (stage != "wreset-before-epoch") return false; injected = true; auto& hooks = cc::testing::hooks;
                if (kind == 0) hooks.allocation_failure_at = hooks.allocations;
                if (kind == 1) hooks.lock_failure_at = hooks.locks;
                if (kind == 2 || kind == 3) { hooks.cng_failure_at = hooks.cng_calls; hooks.cng_fail_after_call = kind == 3; }
                if (kind == 4) jt::hooks.fault = jt::EpochFault::SlotWrite;
                if (kind == 5) jt::hooks.fault = jt::EpochFault::SlotFlush;
                if (kind == 6) jt::hooks.fault = jt::EpochFault::AfterPublication;
                return false;
            });
            Wal::ProtectedHistoryHead head; CHECK(f.Reset(wal, head) == ResetResult::BytesMayHavePersisted); CHECK(injected && head == Wal::ProtectedHistoryHead{}); }
        CHECK(Read(f.witness.path) == before && Read(f.original.path) == original && cc::testing::hooks.all_released_bytes_zero && jt::hooks.dpapi_released_zero);
        auto& hooks = cc::testing::hooks; hooks.allocation_failure_at = hooks.lock_failure_at = hooks.cng_failure_at = -1; hooks.cng_fail_after_call = false; jt::hooks.fault = jt::EpochFault::None;
        const auto evidence = Files(f.witness.protected_persistence->key_directory);
        { Wal wal(f.witness); Wal::ProtectedHistoryHead head; CHECK(f.Reset(wal, head) == ResetResult::Succeeded); }
        for (const auto& [name, b] : evidence) CHECK(Read(f.witness.protected_persistence->key_directory / name) == b);
        f.Prove();
    }
    auto budget = NewFixture(L"allocation-budget"); budget.Seed(); budget.Tear(2, 63);
    budget.witness.protected_persistence->max_allocation_bytes = 2ull << 20; ExactRefusal(budget);
    auto bounded = NewFixture(L"archive-budget"); bounded.Seed(); bounded.Tear(2, 63);
    for (unsigned n = 0; n < 33; ++n) {
        const std::vector<std::uint8_t> bytes{static_cast<std::uint8_t>(n)}; const auto hash = Hash(bytes);
        Write(fs::path(bounded.witness.path.wstring() + L".wrfail." + std::wstring(hash.begin(), hash.end()) + L".0"), bytes);
    }
    ExactRefusal(bounded);
}
void NoReplaceAndQuarantineControls()
{
    for (unsigned kind = 0; kind < 4; ++kind) {
        auto f = NewFixture(L"collision"); f.Seed(); f.Tear(2, 63);
        const auto damaged = Read(f.witness.path), original = Read(f.original.path); const auto raw_hash = Hash(damaged);
        const std::vector<std::uint8_t> sentinel{9, 8, 7, 6, 5, 4, 3, 2}; fs::path collision;
        const std::array<std::string_view, 4> stages{"wreset-before-candidate-create", "wreset-before-save", "wreset-before-promote", "wreset-before-archive"};
        bool injected = false;
        { Wal wal(f.witness); wal.SetFaultInjectionHook([&](auto stage) {
                if (stage != stages[kind]) return false;
                collision = kind == 0 ? Side(f.witness.path, L".wreset.next") : kind == 1 ? Side(f.witness.path, L".wreset.old") :
                    kind == 2 ? f.witness.path : fs::path(f.witness.path.wstring() + L".wrsaved." + std::wstring(raw_hash.begin(), raw_hash.end()));
                Write(collision, sentinel); injected = true; return false;
            });
            Wal::ProtectedHistoryHead head; CHECK(f.Reset(wal, head) == ResetResult::BytesMayHavePersisted); CHECK(injected); }
        CHECK(Read(collision) == sentinel && Read(f.original.path) == original && f.target_calls == 0);
        if (kind < 2) CHECK(Read(f.witness.path) == damaged);
        const auto before = Files(f.base), keys = Files(f.witness.protected_persistence->key_directory);
        { Wal wal(f.witness); Wal::ProtectedHistoryHead head; CHECK(f.Reset(wal, head) != ResetResult::Succeeded); }
        CHECK(Files(f.base) == before && Files(f.witness.protected_persistence->key_directory) == keys);
    }
    for (auto stage : {"wreset-before-quarantine", "wreset-after-quarantine", "wreset-quarantine-flush"}) {
        auto f = NewFixture(L"quarantine"); f.Seed(); f.Tear(2, 63);
        { Wal wal(f.witness); wal.SetFaultInjectionHook([](auto s) { return s == "wreset-partial-receipt-write"; });
            Wal::ProtectedHistoryHead head; CHECK(f.Reset(wal, head) == ResetResult::BytesMayHavePersisted); }
        const auto candidate = Read(Side(f.witness.path, L".wreset.next")), receipt = Read(Side(f.witness.path, L".wreset.intent")); bool hit = false;
        { Wal wal(f.witness); wal.SetFaultInjectionHook([&](auto s) { if (s == stage) { hit = true; return true; } return false; });
            Wal::ProtectedHistoryHead head; CHECK(f.Reset(wal, head) == ResetResult::BytesMayHavePersisted); CHECK(hit); }
        { Wal wal(f.witness); Wal::ProtectedHistoryHead head; CHECK(f.Reset(wal, head) == ResetResult::Succeeded); }
        bool kept_candidate = false, kept_receipt = false;
        for (const auto& entry : fs::directory_iterator(f.base)) if (entry.path().filename().wstring().starts_with(L"journal.wal.wrfail.")) {
            const auto bytes = Read(entry.path()); kept_candidate |= bytes == candidate; kept_receipt |= bytes == receipt;
        }
        CHECK(kept_candidate && kept_receipt); f.Prove();
    }
}
void FreshEpochAndCanaries()
{
    auto f = NewFixture(L"fresh-epoch-canaries"); f.Seed(); f.Tear(2, 63);
    const auto old_keys = Files(f.witness.protected_persistence->key_directory);
    jt::hooks.key_override = std::as_bytes(std::span(keyCanary, sizeof(keyCanary) - 1));
    { Wal wal(f.witness); wal.SetFaultInjectionHook([](auto s) { return s == "wreset-after-candidate-readback"; });
        Wal::ProtectedHistoryHead head; CHECK(f.Reset(wal, head) == ResetResult::BytesMayHavePersisted); }
    jt::hooks.key_override = {};
    const auto first = Read(Side(f.witness.path, L".wreset.next"));
    { Wal wal(f.witness); wal.SetFaultInjectionHook([](auto s) { return s == "wreset-after-receipt-readback"; });
        Wal::ProtectedHistoryHead head; CHECK(f.Reset(wal, head) == ResetResult::BytesMayHavePersisted); }
    const auto second = Read(Side(f.witness.path, L".wreset.next")), receipt = Read(Side(f.witness.path, L".wreset.intent"));
    std::vector<std::array<std::uint8_t, 28>> used;
    const auto add = [&](const std::vector<std::uint8_t>& bytes, std::size_t start) {
        std::array<std::uint8_t, 28> id_nonce{}; CHECK(start + 52 <= bytes.size());
        std::copy_n(bytes.begin() + start + 24, id_nonce.size(), id_nonce.begin());
        CHECK(std::find(used.begin(), used.end(), id_nonce) == used.end()); used.push_back(id_nonce);
    };
    const auto first_frames = Frames(first), second_frames = Frames(second); CHECK(first_frames.size() == 5 && second_frames.size() == 5);
    CHECK(!std::equal(first.begin() + first_frames[0] + 24, first.begin() + first_frames[0] + 40, second.begin() + second_frames[0] + 24));
    for (const auto at : first_frames) add(first, at); for (const auto at : second_frames) add(second, at); add(receipt, 0);
    { Wal wal(f.witness); Wal::ProtectedHistoryHead head; CHECK(f.Reset(wal, head) == ResetResult::Succeeded); }
    CHECK(Read(f.witness.path) == second);
    for (const auto& [name, bytes] : old_keys) CHECK(Read(f.witness.protected_persistence->key_directory / name) == bytes);
    bool retained_first = false;
    for (const auto& file : fs::recursive_directory_iterator(f.base)) if (file.is_regular_file()) {
        const auto bytes = Read(file.path()); retained_first |= bytes == first;
        for (const auto text : {planCanary, chunkPath, endPath, std::string_view(keyCanary),
            std::string_view("\\$apfs-keybag-rewrap-v2"), std::string_view(f.witness.volume_identity), std::string_view(f.original.volume_identity)}) {
            CHECK(std::search(bytes.begin(), bytes.end(), text.begin(), text.end()) == bytes.end());
            std::vector<std::uint8_t> wide; for (const char c : text) { wide.push_back(static_cast<std::uint8_t>(c)); wide.push_back(0); }
            CHECK(std::search(bytes.begin(), bytes.end(), wide.begin(), wide.end()) == bytes.end());
        }
    }
    CHECK(retained_first && used.size() == 11); f.Prove();
}
void HistoricalRetention()
{
    auto f = NewFixture(L"historical-retention"); f.Seed(false, false, false, 4, false, true, true); f.Tear(6, 63);
    const auto before = Files(f.base), keys = Files(f.witness.protected_persistence->key_directory);
    auto changed = f.Expected(); changed.front().inline_payload.back() ^= std::byte{1}; changed.front().payload_sha256 = Sha(changed.front().inline_payload);
    { Wal wal(f.witness); Wal::ProtectedHistoryHead head; CHECK(f.Reset(wal, head, &changed) == ResetResult::RejectedBeforeWrite); }
    CHECK(Files(f.base) == before && Files(f.witness.protected_persistence->key_directory) == keys && f.authorizations == 0 && f.barriers == 0);
    { Wal wal(f.witness); Wal::ProtectedHistoryHead head; CHECK(f.Reset(wal, head) == ResetResult::Succeeded); CHECK(head.records == 4 && head.last_sequence == 4); }
    CHECK(f.authorizations == 1 && f.barriers == 1); f.Prove();
}
void PrepareCut(std::string_view stage, bool history)
{
    Fixture f(root, true); f.Seed(false, false, false, 4, false, true, history); f.Tear(history ? 6 : 2, 63); const auto original = Read(f.original.path); bool hit = false;
    { Wal wal(f.witness); wal.SetFaultInjectionHook([&](auto s) { if (s == stage) { hit = true; return true; } return false; });
        Wal::ProtectedHistoryHead head; CHECK(f.Reset(wal, head) != ResetResult::Succeeded); CHECK(hit && head == Wal::ProtectedHistoryHead{}); }
    CHECK(Read(f.original.path) == original); std::cout << "PREPARED_CUT " << stage << " original=" << Hash(original) << " damaged=" << Hash(Read(root / L"damaged.bin")) << std::endl;
}
void RecoverCut(bool history)
{
    Fixture f(root, false); const auto original = Read(f.original.path); const auto keys = Files(f.witness.protected_persistence->key_directory);
    { Wal wal(f.witness); Wal::ProtectedHistoryHead head; CHECK(f.Reset(wal, head) == ResetResult::Succeeded); CHECK(head.records == 4 && f.authorizations == 1 && f.barriers == 1); }
    if (history) {
        const auto pristine = Read(root / L"pristine.bin"); const auto positions = Frames(pristine);
        CHECK(positions.size() == 9 && Read(root / L"damaged.bin").size() == positions[6] + 63);
    }
    CHECK(Read(f.original.path) == original); for (const auto& [name, b] : keys) CHECK(Read(f.witness.protected_persistence->key_directory / name) == b);
    f.Prove(); std::cout << "RECOVERED_CUT original=" << Hash(original) << " damaged=" << Hash(Read(root / L"damaged.bin")) << " target_calls=" << f.target_calls << std::endl;
}
}

int wmain(int argc, wchar_t** argv)
{
    try {
        CHECK(argc == 2 || argc == 3 || argc == 4); root = argv[1]; CHECK(LocalAbsolute(root));
        const bool controls = argc == 3 && std::wstring_view(argv[2]) == L"--controls";
        const bool protocol = argc == 3 && std::wstring_view(argv[2]) == L"--protocol"; CHECK(argc != 3 || controls || protocol);
        const bool history = argc == 4 && (std::wstring_view(argv[2]) == L"--prepare-history-cut" || std::wstring_view(argv[2]) == L"--recover-history-cut");
        const bool recovery = argc == 4 && (std::wstring_view(argv[2]) == L"--recover-cut" || std::wstring_view(argv[2]) == L"--recover-history-cut");
        if (recovery) { Pins validate(root); RecoverCut(history); }
        else {
            Directory(root);
            if (argc == 4) {
                CHECK(std::wstring_view(argv[2]) == L"--prepare-cut" || std::wstring_view(argv[2]) == L"--prepare-history-cut");
                const std::wstring stage = argv[3]; PrepareCut(std::string(stage.begin(), stage.end()), history);
            } else if (controls) {
                Group("v4 commitment/original journal identity, v3 rejection and preserved unaccepted authorization debt", CertificateV4Controls);
                Group("live original/certificate authority after receipt, altered body and unknown key/tag refusals", RecoveryAuthorityControls);
                Group("provider/lock/allocation/slot failure retention, fresh retry and aggregate resource refusal", ProviderAndBudgetControls);
                Group("no-replace races, one-way promotion and interrupted quarantine retention", NoReplaceAndQuarantineControls);
                Group("fresh retry epochs, unique frame nonces and protected artifact key/plan/path canaries", FreshEpochAndCanaries);
                Group("authenticated older groups retained in damaged archive, selected v4 group rebuilt", HistoricalRetention);
            } else {
                Group("v4 commitment/original journal identity, v3 rejection and preserved unaccepted authorization debt", CertificateV4Controls);
                Group("M2 independent private certificate, no-certificate/M1 and original barrier refusals", CertificateBoundary);
                Group("proper EOF header/ciphertext/tag fragment boundaries with retained old bytes and append/reopen", FragmentBoundaries);
                Group("full tag/interior/terminal/anchor/header and distinct-epoch missing-key refusals", StrictPhysicalRefusals);
                Group("already-durable/not-cleaned authority, absent canonical debt and cleaned refusal", DurableNotCleanedAndDebt);
                Group("live original/certificate authority after receipt, altered body and unknown key/tag refusals", RecoveryAuthorityControls);
                Group("provider/lock/allocation/slot failure retention, fresh retry and aggregate resource refusal", ProviderAndBudgetControls);
                Group("no-replace races, one-way promotion and interrupted quarantine retention", NoReplaceAndQuarantineControls);
                Group("fresh retry epochs, unique frame nonces and protected artifact key/plan/path canaries", FreshEpochAndCanaries);
                Group("authenticated older groups retained in damaged archive, selected v4 group rebuilt", HistoricalRetention);
                if (!protocol) {
                Group("unchanged ordinary codec and wire", OrdinaryCodec); Group("unchanged ordinary persistence", OrdinaryPersistence);
                Group("unchanged ordinary repair and bounds", OrdinaryTailAndLimits); Group("unchanged ordinary compaction", OrdinaryCompactionAndAmbiguity);
                Group("unchanged protected lifecycle", ProtectedLifecycle); Group("unchanged protected authority/mixing", AuthorityAndMixing);
                Group("unchanged protected retained-checkpoint lifecycle", MaintenanceLifecycle);
                Group("unchanged original durability barriers", MaintenanceOriginalBarrier);
                Group("unchanged explicit recovery original barriers", MaintenanceRecoveryOriginalBarrier);
                }
            }
        }
        CHECK(cc::testing::hooks.all_released_bytes_zero && jt::hooks.dpapi_released_zero);
        std::cout << "PASS " << groups << " groups / " << checks << " assertions / " << cases << " cases" << std::endl; return 0;
    } catch (const std::exception& e) { std::cerr << "FAIL " << e.what() << std::endl; return 1; }
}
