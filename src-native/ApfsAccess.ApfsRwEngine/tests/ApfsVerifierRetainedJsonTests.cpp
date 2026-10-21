#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "ApfsVerificationJson.h"
#include "../tools/WindowsImageLease.h"
#include <array>
#include <bcrypt.h>
#include <chrono>
#define APFS_RETAINED_OWNERSHIP_FIXTURES_ONLY
#include "ApfsVerifierRetainedOwnershipTests.cpp"
#undef APFS_RETAINED_OWNERSHIP_FIXTURES_ONLY

#ifdef APFSACCESS_HISTORICAL_SERIALIZER_CONTROL
// Private gates additionally compare the actual historical serializer's bytes.
namespace apfsaccess::catalog
{
bool SerializeHistoricalImageVerificationReport(const VerificationReport&, std::string_view,
    const std::function<bool()>&, std::size_t, std::string&, payload::Reason&);
bool SerializeHistoricalProtectedHistoryVerificationReport(const VerificationReport&, std::string_view,
    const std::function<bool()>&, std::size_t, std::string&, payload::Reason&);
}
#endif

namespace
{
const std::string image_label = "D:\\wire fixture\\quoted \"image\".apfs";

std::string BaselineDigest(std::string_view bytes)
{
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    Check(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0, "open independent SHA256");
    std::array<unsigned char, 32> digest{};
    const auto status = BCryptHash(algorithm, nullptr, 0,
        reinterpret_cast<PUCHAR>(const_cast<char*>(bytes.data())), static_cast<ULONG>(bytes.size()),
        digest.data(), static_cast<ULONG>(digest.size()));
    BCryptCloseAlgorithmProvider(algorithm, 0);
    Check(status >= 0, "hash encoded bytes independently");
    std::string hex;
    for (const auto byte : digest)
    { hex.push_back("0123456789ABCDEF"[byte >> 4]); hex.push_back("0123456789ABCDEF"[byte & 15]); }
    return hex;
}

void RecordedBaseline(const std::string& name, const std::string& bytes)
{
    // SHA256 and lengths of the seven independently compiled historical outputs
    // frozen 2026-10-16. No production serializer is duplicated in this target.
    struct Baseline { const char* name; std::size_t size; const char* digest; };
    static constexpr Baseline baselines[] = {
        {"legacy-v2", 5948, "86CA678DBE7CE994B5EDDC5BEB4D8121E234D94910B7AB2F7796CC3C90D020CC"},
        {"legacy-v3", 6822, "901DE2279D048696032E875C1F18F22126AE59684E01A2D2336695A595E7C928"},
        {"legacy-history-v1", 6612, "2F07C7D1A53E1BE3A7F8C124FFBF5286CC9C9FCBE0DD81D085E8A1654695AF9F"},
        {"legacy-refused-v2", 6000, "A85084B94F5F5297735FFB597F3D1109A4743EEA9C55B3EE5C38C1A56A5A8AE8"},
        {"legacy-incomplete-v2", 5543, "9D86D9E16BE76388B0E6CBF6AC64F1C53F2277EFCBFC8D3570292797230D779C"},
        {"legacy-residual-v2", 5988, "0C584D3FD87B7216DEF68C0BE101710DDCEAAA1AB4F70E774EB99FFC5A6ED396"},
        {"legacy-history-incomplete-v1", 5698, "470050D97A549C9D35C5D8B3FCB41BA4AD978A11D04B669C1384BFED59AFEDF5"}
    };
    const auto baseline = std::find_if(std::begin(baselines), std::end(baselines),
        [&](const auto& entry) { return name == entry.name; });
    Check(baseline != std::end(baselines), "recorded historical scenario exists");
    Check(bytes.size() == baseline->size && BaselineDigest(bytes) == baseline->digest,
        "exact recorded historical bytes: " + name);
}

void SaveJson(const std::filesystem::path& directory, const std::string& name, const std::string& json)
{
    std::ofstream file(directory / (name + ".json"), std::ios::binary);
    file << json; file.close(); Check(static_cast<bool>(file), "encoded evidence written: " + name);
}

std::string Encoded(const VerificationReport& report, std::string_view path = image_label)
{
    std::string output = "must clear"; payload::Reason reason = payload::Reason::None;
    const auto budget = report.read_budget;
    const bool encoded = SerializeImageVerificationReport(report, path, [] { return true; },
        MaxImageVerificationJsonBytes, output, reason);
    Check(encoded, "accounting encoding: " + std::string(payload::Name(reason)) + ":" + Detail(report));
    Check(reason == payload::Reason::None && report.read_budget == budget, "encoding uses the exact report allowance");
    return output;
}

VerificationReport Observed(Fixture& fixture)
{
    fixture.scope.account_retained_ownership = true;
    fixture.scope.observe_payload_content = true;
    const auto before = fixture.image; TracedSource source(fixture.image);
    auto report = ApfsVerifier::Verify(source, fixture.scope);
    Check(before == fixture.image, "observed accounting never changes image bytes");
    return report;
}

void LegacyCase(Fixture& fixture, const std::filesystem::path& directory, const std::string& name, bool history = false,
    VerificationOutcome expected = VerificationOutcome::Complete)
{
    TracedSource source(fixture.image); const auto report = ApfsVerifier::Verify(source, fixture.scope);
    Check(report.outcome == expected, "legacy fixture: " + Detail(report));
    std::string current; payload::Reason reason = payload::Reason::None;
    const auto encode = history ? SerializeProtectedHistoryVerificationReport : SerializeImageVerificationReport;
    Check(encode(report, image_label, [] { return true; }, MaxImageVerificationJsonBytes, current, reason), "legacy encoding");
    RecordedBaseline(name, current);
#ifdef APFSACCESS_HISTORICAL_SERIALIZER_CONTROL
    std::string historical;
    const auto baseline = history ? SerializeHistoricalProtectedHistoryVerificationReport : SerializeHistoricalImageVerificationReport;
    Check(baseline(report, image_label, [] { return true; }, MaxImageVerificationJsonBytes, historical, reason), "historical baseline encoding");
    Check(current == historical, "live historical serializer byte equality");
    SaveJson(directory, name + "-historical", historical);
#endif
    Check(current.find("retainedOwnership") == std::string::npos &&
        current.find("accountRetainedOwnership") == std::string::npos, "legacy wire bytes unchanged");
    SaveJson(directory, name, current);
    Pass(name + " recorded historical baseline");
}

void ProjectionRejections(const VerificationReport& original)
{
    const auto reject = [&](const char* name, const auto& mutate) {
        auto report = original;
        // Isolate forged-projection controls; actual spent-budget cases below
        // always keep their original allowance and may never replenish it.
        report.read_budget = std::make_shared<ApfsReadBudget>(65536, 256ull << 20, 1000000, 256ull << 20);
        mutate(report);
        std::string output = "must clear"; payload::Reason reason = payload::Reason::None;
        const bool encoded = SerializeImageVerificationReport(report, image_label, [] { return true; },
            MaxImageVerificationJsonBytes, output, reason);
        Check(!encoded && output.empty() && reason == payload::Reason::InvalidProjection,
            std::string("forged projection refused: ") + name + ":" + std::string(payload::Name(reason)));
        Pass(std::string("reject ") + name);
    };
    reject("main partition mismatch", [](auto& r) { ++r.retained_ownership->reserved_main_blocks; });
    reject("internal partition mismatch", [](auto& r) { ++r.retained_ownership->deferred_internal_blocks; });
    reject("main arithmetic overflow", [](auto& r) { r.retained_ownership->owned_main_blocks = UINT64_MAX; });
    reject("owned range total mismatch", [](auto& r) { r.retained_ownership->payload_ranges.clear(); });
    reject("metadata payload overlap", [](auto& r) { r.retained_ownership->payload_ranges = {r.retained_ownership->metadata_ranges.front()}; });
    reject("range overflow", [](auto& r) { r.retained_ownership->metadata_ranges.back() = {UINT64_MAX, 2}; });
    reject("noncanonical adjacent ranges", [](auto& r) { r.retained_ownership->metadata_ranges = {{0,1},{1,1}}; });
    reject("empty checkpoint set", [](auto& r) { r.retained_ownership->checkpoint_xids.clear(); });
    reject("duplicate retained XID", [](auto& r) { r.retained_ownership->checkpoint_xids.insert(r.retained_ownership->checkpoint_xids.begin(), 20); });
    reject("wrong endpoint XID", [](auto& r) { ++r.retained_ownership->checkpoint_xids.back(); });
    reject("invented purgeable amount", [](auto& r) { r.retained_ownership->purgeable_bytes = 0; });
    reject("invented total snapshot charge", [](auto& r) { r.retained_ownership->snapshot_total_bytes = 4096; });
    reject("snapshot byte mismatch", [](auto& r) { ++r.retained_ownership->snapshot_payload_usage.front().referenced_bytes; });
    reject("snapshot exclusivity exceeds references", [](auto& r) { r.retained_ownership->snapshot_payload_usage.front().exclusive_blocks = UINT64_MAX; });
    reject("duplicate volume usage", [](auto& r) { r.retained_ownership->snapshot_payload_usage.push_back(r.retained_ownership->snapshot_payload_usage.front()); });
    reject("selected volume usage absent", [](auto& r) { ++r.retained_ownership->snapshot_payload_usage.front().volume_oid; });
    reject("selected identity mismatch", [](auto& r) { ++r.selected->exact.volume_oid; });
    reject("duplicate coverage", [](auto& r) { r.coverage.front() = r.coverage.back(); });
    reject("coverage promotion missing proof", [](auto& r) { r.retained_ownership.reset(); });
    reject("residual orphan in complete census", [](auto& r) { r.allocation_census->unattributed_main_blocks = 1; });
    reject("whole-volume success promotion", [](auto& r) { r.whole_volume_verified = true; });
    reject("missing requested history", [](auto& r) { r.requested_scope.retained_from_xid = 20; });
    reject("accounting cannot fall back to v2", [](auto& r) { r.requested_scope.account_retained_ownership = false; });
}

void SerializerBudgets(Fixture& fixture, const std::filesystem::path& directory)
{
    const auto control = Account(fixture); Accounted(control);
    const auto encoded = Encoded(control);
    {
        const auto report = Account(fixture); const auto budget = report.read_budget;
        std::string output = "must clear"; payload::Reason reason = payload::Reason::None;
        Check(!SerializeImageVerificationReport(report, image_label, [] { return true; }, encoded.size() - 1, output, reason) &&
            output.empty() && reason == payload::Reason::OutputLimit && report.read_budget == budget && budget->Failed(),
            "one-byte output overflow has no partial JSON and keeps sticky allowance");
        Check(!SerializeImageVerificationReport(report, image_label, [] { return true; }, MaxImageVerificationJsonBytes, output, reason) &&
            output.empty() && reason == payload::Reason::SharedBudget, "retry cannot reset overflow budget");
        Pass("bounded response and sticky retry");
    }
    {
        const auto report = Account(fixture); std::string output; payload::Reason reason = payload::Reason::None;
        Check(SerializeImageVerificationReport(report, image_label, [] { return true; }, encoded.size(), output, reason) &&
            output == encoded, "exact response boundary succeeds");
        Pass("exact output boundary");
    }
    {
        const auto report = Account(fixture); report.read_budget->LimitRemainingTo(65536, 256ull << 20, 1, 1);
        std::string output = "must clear"; payload::Reason reason = payload::Reason::None;
        Check(!SerializeImageVerificationReport(report, image_label, [] { return true; }, MaxImageVerificationJsonBytes, output, reason) &&
            output.empty() && reason == payload::Reason::SharedBudget, "response allocation uses original remaining materialization budget");
        Pass("response materialization allowance");
    }
    {
        const auto report = Account(fixture); std::string output = "must clear"; payload::Reason reason = payload::Reason::None;
        Check(!SerializeImageVerificationReport(report, image_label, [] { return false; }, MaxImageVerificationJsonBytes, output, reason) &&
            output.empty() && reason == payload::Reason::Deadline, "expired response deadline");
        Pass("response deadline");
    }
    {
        const auto report = Account(fixture); unsigned calls = 0; std::string output; payload::Reason reason = payload::Reason::None;
        Check(SerializeImageVerificationReport(report, image_label, [&] { ++calls; return true; }, MaxImageVerificationJsonBytes, output, reason), "late deadline control");
        const auto late = Account(fixture); unsigned current = 0; output = "must clear";
        Check(!SerializeImageVerificationReport(late, image_label, [&] { return ++current < calls; }, MaxImageVerificationJsonBytes, output, reason) &&
            output.empty() && reason == payload::Reason::Deadline, "late encoding deadline clears allocated output");
        Pass("late encoding deadline clears partial bytes");
    }
    {
        const auto report = Account(fixture); unsigned calls = 0; std::string output = "must clear"; payload::Reason reason = payload::Reason::None;
        Check(!SerializeImageVerificationReport(report, image_label, [&] { return ++calls < 10; }, MaxImageVerificationJsonBytes, output, reason) &&
            output.empty() && reason == payload::Reason::Deadline, "validation is cooperatively bounded too");
        Pass("validation deadline");
    }
    {
        auto limited = fixture; limited.scope.max_reads = 3;
        const auto report = Account(limited); const auto budget = report.read_budget;
        Check(Has(report, VerificationCode::BudgetExceeded) && budget && budget->Failed(), "actual verification budget exhausted");
        std::string output = "must clear"; payload::Reason reason = payload::Reason::None;
        Check(!SerializeImageVerificationReport(report, image_label, [] { return true; }, MaxImageVerificationJsonBytes, output, reason) &&
            output.empty() && reason == payload::Reason::SharedBudget && budget == report.read_budget && !report.retained_ownership,
            "spent verification allowance cannot manufacture an encoded accounting report");
        SaveJson(directory, "budget-transport-result", "{\"serialized\":false,\"failure\":\"SharedBudget\",\"accountingPublished\":false}");
        Pass("actual verification budget preserves no-JSON transport contract");
    }
}

void JsonCases(const std::filesystem::path& directory)
{
    { Fixture f; LegacyCase(f, directory, "legacy-v2"); }
    { Fixture f; f.scope.observe_payload_content = true; LegacyCase(f, directory, "legacy-v3"); }
    { auto f = Ordinary(); LegacyCase(f, directory, "legacy-history-v1", true); }
    { Fixture f; f.Edit(4, [](auto& b) { PutU64LE(b, 0x108, 0); });
      LegacyCase(f, directory, "legacy-refused-v2", false, VerificationOutcome::Refused); }
    { Fixture f; f.Edit(f.checkpoint.volumes[0].root_tree.physical_block, [](auto& b) { b[0] ^= std::byte{1}; }, false);
      LegacyCase(f, directory, "legacy-incomplete-v2", false, VerificationOutcome::Incomplete); }
    { Fixture f; AllocateOrphan(f, 300); LegacyCase(f, directory, "legacy-residual-v2"); }
    { auto f = Ordinary(); BreakNextLink(f); LegacyCase(f, directory, "legacy-history-incomplete-v1", true, VerificationOutcome::Incomplete); }
    {
        auto f = Ordinary(); f.scope.retained_from_xid.reset(); f.scope.account_retained_ownership = true;
        const auto path = directory / "leased-retained.apfs";
        std::ofstream file(path, std::ios::binary);
        file.write(reinterpret_cast<const char*>(f.image.data()), f.image.size()); file.close(); Check(static_cast<bool>(file), "private leased image written");
        apfsaccess::transport::WindowsImageLease source(path.wstring()); f.scope.source_identity = source.Identity();
        const auto report = ApfsVerifier::Verify(source, f.scope); Accounted(report);
        Check(source.VerifyUnchanged(), "same held source identity before encoding");
        SaveJson(directory, "leased-v4", Encoded(report, path.string()));
        Bytes after; Check(source.Read(0, f.image.size(), after) && after == f.image && source.VerifyUnchanged(), "held image bytes and identity unchanged");
        Pass("actual held regular-image lease to encoded v4 report");
    }
    for (const auto bs : {4096u, 8192u})
    {
        auto f = Ordinary(bs); f.scope.retained_from_xid.reset();
        const auto report = Account(f); Accounted(report);
        SaveJson(directory, "retained-v4-" + std::to_string(bs), Encoded(report));
        Pass("encoded exact retained partition " + std::to_string(bs));
        if (bs == 4096) ProjectionRejections(report);
    }
    {
        Fixture f; f.Create("snapshot", {20}); f.Cow(true, {20});
        const auto report = Account(f); Accounted(report); SaveJson(directory, "snapshot-v4", Encoded(report));
        Pass("encoded actual snapshot payload amounts");
    }
    {
        Fixture f; f.Create("shared", {20}); const auto report = Account(f); Accounted(report);
        SaveJson(directory, "shared-snapshot-v4", Encoded(report)); Pass("encoded snapshot payload sharing");
    }
    {
        Fixture f; AddPeer(f, 221);
        for (const auto block : {0ull, f.checkpoint.container.superblock_physical_block}) f.Edit(block, [](auto& b) {
            PutU64LE(b, 0xB8, 102); PutU64LE(b, 0xC0, 101);
        });
        f.Reload(); const auto report = Account(f); Accounted(report);
        Check(report.retained_ownership->snapshot_payload_usage.front().volume_oid == 101, "usage normalized independently of catalog order");
        SaveJson(directory, "peers-v4", Encoded(report)); Pass("encoded peer usage has canonical order");
    }
    {
        auto f = Ordinary(); const auto report = Account(f); Accounted(report);
        const auto json = Encoded(report); SaveJson(directory, "pinned-v4", json);
        Check(json.find("\"requestedHistory\":{") != std::string::npos && json.find("\"repair\":{") != std::string::npos, "v4 preserves pin and refusal plan");
        std::string output = "must clear"; payload::Reason reason = payload::Reason::None;
        Check(!SerializeProtectedHistoryVerificationReport(report, image_label, [] { return true; }, MaxImageVerificationJsonBytes, output, reason) &&
            output.empty() && reason == payload::Reason::InvalidProjection, "protected-history v1 cannot silently drop accounting");
        auto contradictory = report;
        contradictory.requested_history->checkpoints[0].payload_ranges = {{300, 1}};
        Check(!SerializeImageVerificationReport(contradictory, image_label, [] { return true; }, MaxImageVerificationJsonBytes, output, reason) &&
            output.empty() && reason == payload::Reason::InvalidProjection, "pin ranges must belong to aggregate retained ownership");
        Pass("explicit v4 pin combination and v1 isolation");
    }
    {
        Fixture f; const auto report = Observed(f); Accounted(report); SaveJson(directory, "observed-v4", Encoded(report));
        Pass("explicit v4 current payload observation combination");
    }
    {
        Fixture f; AllocateOrphan(f, 300); const auto report = Account(f);
        Check(Has(report, VerificationCode::OrphanAllocation), Detail(report));
        SaveJson(directory, "orphan-v4", Encoded(report));
        Fixture good; auto forged = report; forged.retained_ownership = Account(good).retained_ownership;
        std::string output = "must clear"; payload::Reason reason = payload::Reason::None;
        Check(!SerializeImageVerificationReport(forged, image_label, [] { return true; }, MaxImageVerificationJsonBytes, output, reason) &&
            output.empty() && reason == payload::Reason::InvalidProjection, "orphan failure cannot carry another report's complete accounting");
        Pass("encoded orphan cannot publish complete accounting");
    }
    {
        Fixture f; AllocateOrphan(f, 300); const auto report = Observed(f);
        Check(Has(report, VerificationCode::OrphanAllocation) && report.payload_inventory->exactComplete() && !report.retained_ownership,
            "current byte observation is independent of complete retained accounting");
        SaveJson(directory, "observed-orphan-v4", Encoded(report)); Pass("encoded current observation with incomplete retained accounting");
    }
    {
        Fixture f; f.Edit(4, [](auto& bytes) { PutU64LE(bytes, 0x108, 0); }); const auto report = Account(f);
        Check(report.outcome == VerificationOutcome::Refused && Has(report, VerificationCode::CryptoUnsupported), Detail(report));
        SaveJson(directory, "refused-v4", Encoded(report)); Pass("encoded refused profile has no accounting");
    }
    {
        auto f = Ordinary(); BreakNextLink(f); const auto report = Account(f);
        Check(Has(report, VerificationCode::CheckpointUnavailable), Detail(report));
        SaveJson(directory, "history-gap-v4", Encoded(report)); Pass("encoded unavailable pin has no history or accounting");
    }
    {
        Fixture f; f.scope.require_whole_volume = true; const auto report = Account(f);
        Check(Has(report, VerificationCode::CoverageMissing) && !report.retained_ownership && !report.whole_volume_verified, Detail(report));
        SaveJson(directory, "whole-volume-incomplete-v4", Encoded(report)); Pass("encoded broader scope remains incomplete");
    }
    { Fixture f; QueueOrphan(f, 300); const auto report = Account(f); Accounted(report);
      SaveJson(directory, "deferred-v4", Encoded(report)); Pass("encoded deferred partition"); }
    { Fixture f; SerializerBudgets(f, directory); }
}
}

int main(int argc, char** argv)
{
    try
    {
        Check(argc == 1 || argc == 2, "optional absolute D: output directory");
        const std::filesystem::path directory = argc == 2 ? std::filesystem::path(argv[1]) :
            std::filesystem::path("D:/ApfsAccessScratch/WindowsClosure/retained-json-ctest") /
                std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        Check(directory.is_absolute() && directory.root_name() == "D:", "all encoded evidence stays on D:");
        std::filesystem::create_directories(directory); JsonCases(directory);
        std::cout << "PASS " << cases << " cases, " << checks << " checks\n";
        return 0;
    }
    catch (const std::exception& e) { std::cerr << "FAIL " << e.what() << '\n'; return 1; }
}
