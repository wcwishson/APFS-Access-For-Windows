#define APFS_MARKED_REFERENCE_FIXTURES_ONLY
#include "ApfsMarkedReferenceSpaceTests.cpp"
#undef APFS_MARKED_REFERENCE_FIXTURES_ONLY
#include "AppleReadOnlyRetention.h"

namespace
{
ApfsMarkedOwnerSpaceAttribution Owners(Fixture& f, std::optional<std::uint64_t> from = {})
{
    const auto before = f.image; VectorRandomAccessSource source(f.image); std::string error;
    std::optional<ApfsMarkedOwnerSpaceAttribution> result;
    Check(TryAttributeAppleMarkedOwnerSpaceReadOnly(source, f.scope, from, result, error), error);
    Check(result && result->explicit_owner_graphs_verified && result->marked.records.complete &&
        result->from_xid == from && result->views.size() == result->marked.records.views.size(), "complete bound owner result");
    Check(f.image == before, "owner accounting changed source"); return std::move(*result);
}
void SeedHistory(Fixture& f)
{
    f.Create("first", Pins(f)); f.Cow(true, Pins(f)); f.Create("second", Pins(f)); f.Cow(true, Pins(f));
    SetMarks(f, {{30, 0x80000}}); AddReferenceRecords(f);
}
void PositiveOwners()
{
    for (const auto bs : {4096u, 8192u}) {
        Fixture f(bs); Seed(f, true, true, 3); SetMarks(f, {{30, 0x80000}, {31, 0x100000}}); AddReferenceRecords(f);
        const auto r = Owners(f); const auto& p = r.views.back().marked_payload;
        Check(p.referenced.blocks == 4 && p.shared_with_live.blocks == 3 && p.absent_from_live.blocks == 1 &&
            p.unique_in_visible_inventory.blocks == 1 && p.potential_reclaim_upper_bound.blocks == 1 &&
            r.views.back().shared_with_unmarked_in_view.blocks == 3 && r.visible_payload_union.blocks == 4,
            "unmarked clone remains a physical owner; marked external attribute is exclusive in visible graph");
        Pass("all-current unmarked clone + external attribute block=" + std::to_string(bs));
    }
    {
        Fixture f; SeedHistory(f); const auto visible = Owners(f); const auto retained = Owners(f, 20);
        Check(retained.checkpoint_xids == std::vector<std::uint64_t>({20,21,22,23,24}), "exact explicit retained chain");
        Check(visible.views[0].marked_payload.potential_reclaim_upper_bound.blocks == 1 &&
            retained.views[0].marked_payload.unique_in_visible_inventory.blocks == 1 &&
            retained.views[0].marked_payload.retained_or_peer_protected.blocks == 1 &&
            retained.views[0].marked_payload.potential_reclaim_upper_bound.blocks == 0 &&
            retained.views.back().marked_payload.potential_reclaim_upper_bound.blocks == 1,
            "retained owners suppress visible-exclusive snapshot candidates without inventing a policy charge");
        Pass("three nonempty views and explicit retained owner subtraction");
    }
    {
        Fixture f; AddPeer(f, 221); SetMarks(f, {{30, 0x80000}}); AddReferenceRecords(f); const auto r = Owners(f);
        Check(r.protected_payload == std::vector<VerificationBlockRange>{{221, 1}} && !r.protected_metadata.empty(), "independent peer owner graph");
        Pass("canonical distinct peer protection");
    }
}
void Refusals()
{
    for (unsigned fault = 0; fault < 5; ++fault) {
        Fixture f;
        if (fault == 0) AddPeer(f, 220);
        SetMarks(f, {{30, 0x80000}}); AddReferenceRecords(f, fault == 1 ? 1 : 0);
        VectorRandomAccessSource raw(f.image); std::string error;
        std::optional<ApfsMarkedOwnerSpaceAttribution> result{ApfsMarkedOwnerSpaceAttribution{}};
        auto scope = f.scope; if (fault == 3) ++scope.exact.checkpoint_xid;
        const auto from = fault == 2 ? std::optional<std::uint64_t>{19} : std::nullopt;
        Check(!TryAttributeAppleMarkedOwnerSpaceReadOnly(raw, scope, from, result, error, [fault] {return fault != 4;}) && !result,
            "alias/missing-reference/missing-parent/stale/deadline must clear result: " + error);
    }
    Pass("five complete-result refusal boundaries");
}
void Wire()
{
    for (unsigned fault = 0; fault < 13; ++fault) {
        Fixture f; SeedHistory(f); std::optional<ApfsMarkedOwnerSpaceAttribution> r = Owners(f, 20);
        auto scope = f.scope; std::string json = "must clear"; payload::Reason failure;
        if (fault == 1) r->views[0].marked_payload.potential_reclaim_upper_bound = {1, f.bs};
        if (fault == 2) r->views[0].unmarked_payload_ranges.push_back({220,1});
        if (fault == 3) r->visible_payload_union.blocks++;
        if (fault == 4) r->checkpoint_xids.erase(r->checkpoint_xids.begin());
        if (fault == 5) r->explicit_owner_graphs_verified = false;
        if (fault == 6) r->views[0].payload_ranges.clear();
        if (fault == 7) ++scope.exact.checkpoint_xid;
        if (fault == 8) r->marked.records.apple_purgeable = ApfsSpaceAmount{1,f.bs};
        if (fault == 9) (void)r->marked.records.read_budget->Refuse("deliberate shared budget refusal");
        if (fault == 11) { r->protected_metadata.push_back({511,1}); r->protected_payload.push_back({511,1}); }
        if (fault == 12) ++r->catalog_metadata.blocks;
        const bool ok = SerializeMarkedOwnerSpaceAttribution(r, scope, 20, "D:\\marked.apfs", []{return true;},
            fault == 10 ? 64 : MaxImageVerificationJsonBytes, json, failure);
        if (fault) Check(!ok && json.empty(), "invalid owner report must emit no complete document");
        else Check(ok && json.starts_with("{\"format\":\"apfs-access-marked-owner-space-attribution\"") &&
            json.find("\"checkpointXids\":[\"20\",\"21\",\"22\",\"23\",\"24\"]") != std::string::npos &&
            json.find("\"snapshotAllocationChargeBytes\":null") != std::string::npos, "exact encoded history and unknown policy");
    }
    Pass("encoded exact arithmetic and twelve inconsistent/refused reports");
}
}
int main(int argc, char** argv) try
{
    if (argc == 3 && std::string_view(argv[1]) == "--export") {
        Fixture f; SeedHistory(f); (void)Owners(f, 20);
        const auto path = std::filesystem::absolute(argv[2]).lexically_normal();
        Check(path.wstring().starts_with(L"D:\\ApfsAccessScratch\\") && !std::filesystem::exists(path), "new D-only fixture");
        std::ofstream file(path, std::ios::binary); file.write(reinterpret_cast<const char*>(f.image.data()), static_cast<std::streamsize>(f.image.size()));
        Check(static_cast<bool>(file), "owner fixture export"); return 0;
    }
    PositiveOwners(); Refusals(); Wire();
    std::cout << "PASS " << cases << " cases / " << checks << " checks; all-visible/retained marked accounting\n"; return 0;
} catch (const std::exception& error) {std::cerr << "FAIL " << error.what() << " after " << checks << " checks\n"; return 1;}
