#include "ApfsVerificationJson.h"
#include <filesystem>
#include <fstream>
#include <iostream>

using namespace apfsaccess::catalog;
namespace
{
unsigned cases = 0, checks = 0;
void Check(bool value, const char* text) { ++checks; if (!value) throw std::runtime_error(text); }
struct Fixture
{
    CurrentProfileVerificationReport report;
    VerificationScope scope;
    std::vector<VerificationStoreBinding> stores;
    std::vector<std::string> labels;
    explicit Fixture(bool fusion = true)
    {
        scope.source_identity = "exact-held-profile-source";
        scope.exact = {fusion ? 8192u : 0u, 32u * 4096, std::string(32, 'a'), std::string(32, 'b'), 101, 7};
        report.profile = fusion ? CurrentVerificationProfile::FusionCleanCache : CurrentVerificationProfile::EncryptedOneKeyGenerationZero;
        stores.push_back({fusion ? "main-id" : scope.source_identity, scope.exact.store_offset_bytes, scope.exact.store_size_bytes});
        labels.push_back("D:\\profile\\\"held\"\nimage.apfs");
        if (fusion) { stores.push_back({"tier2-id", 4096, 8u * 4096}); labels.push_back("D:\\profile\\tier2.apfs"); }
        report.requested_scope = scope; report.stores = stores;
        report.outcome = VerificationOutcome::Complete; report.selected = VerifiedCheckpointIdentity{scope.exact, 1, 2, 7, 1001, 3};
        report.allocation_unit_bytes = 4096; report.covered_volume_count = fusion ? 2 : 1;
        report.covered_filesystem_records = 10; report.covered_physical_extents = 2; report.current_metadata_blocks = 6;
        report.source_reads = 2; report.source_read_bytes = 8192;
        report.read_budget = std::make_shared<ApfsReadBudget>(scope.max_reads, scope.max_read_bytes, scope.max_records, scope.max_record_bytes);
        Check(report.read_budget->Read(8192), "test allowance");
        for (const unsigned id : {1,2,3,5,6,7,8,9,11,13,17})
            report.coverage.push_back({static_cast<VerificationCheck>(id), id != 13, id != 13,
                id == 13 ? VerificationCheckState::NotRequested : VerificationCheckState::Verified, "literal current profile proof"});
        if (fusion)
            for (const unsigned id : {16,18}) report.coverage.push_back({static_cast<VerificationCheck>(id), true, true, VerificationCheckState::Verified, "paired current proof"});
        else
        {
            report.coverage.push_back({VerificationCheck::Crypto, true, true, VerificationCheckState::Verified, "canonical session context"});
        }
    }
    void Failed(bool refused = false)
    {
        report.outcome = refused ? VerificationOutcome::Refused : VerificationOutcome::Incomplete;
        report.coverage.front().state = refused ? VerificationCheckState::Unsupported : VerificationCheckState::Inconsistent;
        report.findings.push_back({refused ? VerificationCode::UnsupportedFeature : VerificationCode::ChecksumMismatch,
            refused ? VerificationSeverity::Warning : VerificationSeverity::Error, VerificationCheck::ExactSelection,
            101, {}, {}, 7, {}, "typed failure; no complete counts"});
        report.allocation_unit_bytes = 0; report.covered_volume_count = report.covered_filesystem_records =
            report.covered_physical_extents = report.current_metadata_blocks = 0;
    }
    bool Encode(std::string& json, payload::Reason& reason, std::size_t cap = MaxImageVerificationJsonBytes,
        const std::function<bool()>& alive = [] { return true; })
    {
        return SerializeCurrentProfileVerificationReport(report, stores.size() == 2 ? CurrentVerificationProfile::FusionCleanCache :
            CurrentVerificationProfile::EncryptedOneKeyGenerationZero, scope, stores, labels, alive, cap, json, reason);
    }
};
template<class F> void Reject(const char* name, F edit, payload::Reason expected = payload::Reason::InvalidProjection)
{
    Fixture f; edit(f); std::string json = "must clear"; payload::Reason reason;
    Check(!f.Encode(json, reason) && json.empty() && reason == expected, name); ++cases;
}
void Save(const std::filesystem::path& root, const char* name, Fixture& f)
{
    std::string json; payload::Reason reason;
    Check(f.Encode(json, reason) && reason == payload::Reason::None, "positive encoding failed");
    Check(json.starts_with("{\"format\":\"apfs-access-current-profile-verification\",\"version\":1,"), "separate version contract");
    Check(json.find("\"applePurgeableBytes\":null,\"reclaimableBytes\":null") != std::string::npos, "policy amount fabricated");
    std::ofstream file(root / (std::string(name) + ".json"), std::ios::binary); file << json; file.close(); Check(static_cast<bool>(file), "evidence write"); ++cases;
}
}
int main(int argc, char** argv) try
{
    Check(argc == 2, "private JSON output directory required"); std::filesystem::create_directories(argv[1]);
    { Fixture f; Save(argv[1], "fusion", f); }
    { Fixture f(false); Save(argv[1], "encrypted", f); }
    { Fixture f(false); f.report.coverage[8] = {VerificationCheck::InternalSeparatorRouting, true, true, VerificationCheckState::Verified, "canonical routing after coordinated promotion"}; Save(argv[1], "encrypted-routed", f); }
    { Fixture f; f.Failed(); Save(argv[1], "incomplete-checksum", f); }
    { Fixture f(false); f.Failed(true); f.report.stores.clear(); f.report.selected.reset(); Save(argv[1], "refused", f); }
    Reject("foreign source", [](auto& f) { f.report.requested_scope.source_identity += "foreign"; }, payload::Reason::InvalidBinding);
    Reject("foreign profile", [](auto& f) { f.report.profile = CurrentVerificationProfile::EncryptedOneKeyGenerationZero; }, payload::Reason::InvalidBinding);
    Reject("wrong exact selector", [](auto& f) { ++f.report.selected->exact.checkpoint_xid; });
    Reject("wrong store", [](auto& f) { f.report.stores[1].store_id += "foreign"; }, payload::Reason::InvalidBinding);
    Reject("wrong allowance contract", [](auto& f) { --f.scope.max_records; }, payload::Reason::InvalidBinding);
    Reject("duplicate store identities", [](auto& f) { f.stores[1].store_id = f.stores[0].store_id; f.report.stores = f.stores; });
    Reject("capacity metadata and payload contradiction", [](auto& f) { f.report.current_metadata_blocks = 40; f.report.covered_physical_extents = 1; });
    Reject("metadata past capacity", [](auto& f) { f.report.current_metadata_blocks = 41; });
    Reject("address in encoded gap", [](auto& f) { f.report.selected->root_physical_block = 100; });
    Reject("missing allocation unit", [](auto& f) { f.report.allocation_unit_bytes = 0; });
    Reject("unsupported allocation unit", [](auto& f) { f.report.allocation_unit_bytes = 2048; });
    Reject("complete selected absent", [](auto& f) { f.report.selected.reset(); });
    Reject("complete member binding absent", [](auto& f) { f.report.stores.clear(); });
    Reject("complete required proof absent", [](auto& f) { f.report.coverage.erase(f.report.coverage.begin()); });
    Reject("duplicate proof", [](auto& f) { f.report.coverage.push_back(f.report.coverage.front()); });
    Reject("complete unproven proof", [](auto& f) { f.report.coverage.front().state = VerificationCheckState::Unproven; });
    Reject("separator unsupported cannot complete", [](auto& f) { f.report.coverage[8] = {VerificationCheck::InternalSeparatorRouting, false, false, VerificationCheckState::Unsupported, "missing canonical comparator"}; });
    Reject("broad scope complete", [](auto& f) { f.scope.account_retained_ownership = f.report.requested_scope.account_retained_ownership = true; });
    Reject("invented purgeable", [](auto& f) { f.report.apple_purgeable_bytes = 0; });
    Reject("invented reclaimable", [](auto& f) { f.report.reclaimable_bytes = 1; });
    Reject("invented snapshot charge", [](auto& f) { f.report.snapshot_allocation_charge_bytes = 1; });
    Reject("failure leaked metadata counts", [](auto& f) { f.Failed(); f.report.current_metadata_blocks = 1; });
    Reject("failure absent typed finding", [](auto& f) { f.Failed(); f.report.findings.clear(); });
    Reject("failure unsupported enum", [](auto& f) { f.Failed(); f.report.findings[0].code = static_cast<VerificationCode>(255); });
    Reject("failure mismatched state", [](auto& f) { f.Failed(); f.report.coverage.front().state = VerificationCheckState::Verified; });
    Reject("bad UTF8", [](auto& f) { f.labels[0] = "\xFF"; });
    Reject("embedded NUL", [](auto& f) { f.labels[0] = std::string("x\0y", 3); });
    Reject("missing allowance", [](auto& f) { f.report.read_budget.reset(); }, payload::Reason::InvalidBinding);
    Reject("poisoned allowance", [](auto& f) { f.report.read_budget->Refuse("test poison"); }, payload::Reason::SharedBudget);
    for (unsigned mode = 0; mode < 4; ++mode)
    {
        Fixture f; std::string json = "must clear"; payload::Reason reason; unsigned calls = 0;
        const auto alive = [&]() -> bool { ++calls; if (mode == 1) throw std::runtime_error("callback"); return mode != 0 && (mode != 2 || calls < 25); };
        Check(!f.Encode(json, reason, mode == 3 ? 32 : MaxImageVerificationJsonBytes, alive) && json.empty(), "deadline/output partial document");
        Check(reason == (mode == 1 ? payload::Reason::CallbackFailure : mode == 3 ? payload::Reason::OutputLimit : payload::Reason::Deadline), "typed deadline/output refusal"); ++cases;
    }
    std::cout << "PASS " << cases << " cases, " << checks << " checks; independent-binding current-profile JSON\n"; return 0;
}
catch (const std::exception& e) { std::cout << "FAIL " << e.what() << '\n'; return 1; }
