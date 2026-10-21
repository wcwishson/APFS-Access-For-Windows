#include "ApfsSpaceAccounting.h"
#include "ApfsProfileSnapshotGraph.h"
#include <iostream>
#include <stdexcept>

using namespace apfsaccess::catalog;
namespace
{
unsigned checks = 0, cases = 0;
void Check(bool value, const std::string& reason) { ++checks; if (!value) throw std::runtime_error(reason); }
ProfileSnapshotViewGraph View(std::uint64_t volume, std::uint64_t xid, bool current,
    std::vector<VerificationBlockRange> metadata, std::vector<VerificationBlockRange> payload)
{
    ProfileSnapshotViewGraph result; result.volume_oid = volume; result.view_xid = xid; result.current = current;
    if (!current) result.name_utf8 = "snapshot-" + std::to_string(xid);
    const auto physical = current ? metadata.back().physical_block : metadata.front().physical_block;
    result.descriptor = {current ? volume : physical, xid, physical,
        current ? kObjectTypeFs : kObjectPhysical | kObjectTypeFs, 0, 4096};
    result.declared_filesystem_allocation = {17, 17 * 4096};
    result.metadata_ranges = std::move(metadata); result.payload_ranges = std::move(payload);
    result.filesystem_record_count = 5; return result;
}
ProfileSnapshotGraphReport Fixture()
{
    ProfileSnapshotGraphReport result; result.profile = CurrentVerificationProfile::FusionCleanCache;
    auto& scope = result.endpoint_scope; scope.source_identity = "held-profile-source";
    scope.exact = {0, 512ull * 4096, std::string(32, 'a'), std::string(32, 'b'), 101, 20};
    result.selected = VerifiedCheckpointIdentity{scope.exact, 2, 40, 20, 1000, 30};
    result.outcome = VerificationOutcome::Complete; result.from_xid = 18; result.chain_xids = {18, 19, 20};
    result.allocation_unit_bytes = 4096;
    result.stores = {{scope.source_identity, 0, scope.exact.store_size_bytes}, {"held-tier2", 4096, 128ull * 4096}};
    result.read_budget = std::make_shared<ApfsReadBudget>(1000, 4096000, 100000, 64ull << 20);
    for (const auto xid : {18ull, 19ull}) {
        ProfileSnapshotCheckpointGraph cp; cp.protected_graph = {xid, {{1, 2}}, {{100, 2}}};
        cp.views.push_back(View(101, xid, true, {{1, 1}}, {{100, 2}})); result.checkpoints.push_back(std::move(cp));
    }
    ProfileSnapshotCheckpointGraph cp;
    cp.protected_graph = {20, {{1, 2}, {10, 1}, {14, 1}, {20, 1}, {30, 2}, {40, 1}}, {{100, 3}, {104, 2}, {110, 1}, {120, 1}}};
    cp.views.push_back(View(101, 16, false, {{10, 1}, {30, 2}}, {{100, 2}, {104, 2}}));
    cp.views.push_back(View(101, 17, false, {{14, 1}, {30, 2}}, {{101, 2}, {110, 1}}));
    cp.views.push_back(View(101, 20, true, {{30, 1}, {40, 1}}, {{102, 1}, {104, 1}}));
    cp.views.push_back(View(102, 20, true, {{20, 1}}, {{120, 1}}));
    result.checkpoints.push_back(std::move(cp)); return result;
}
void ExactPartitions()
{
    auto graph = Fixture(); std::string error; std::optional<ApfsProfileSnapshotSpaceAttribution> result;
    Check(TryAttributeVerifiedProfileSnapshotSpace(graph, result, error, [] { return true; }), error);
    Check(result && result->complete && result->snapshots.size() == 2 && result->referenced_snapshot_metadata.blocks == 4 &&
        result->referenced_snapshot_payload.blocks == 6 && result->live_metadata.blocks == 2 && result->live_payload.blocks == 2,
        "physical unions are not per-row sums");
    const auto& a = result->snapshots[0].payload; const auto& b = result->snapshots[1].payload;
    Check(a.referenced.blocks == 4 && a.shared_with_live.blocks == 1 && a.absent_from_live.blocks == 3 &&
        a.shared_with_other_snapshots.blocks == 1 && a.unique_in_visible_inventory.blocks == 2 &&
        a.retained_or_peer_protected.blocks == 2 && a.potential_reclaim_upper_bound.blocks == 1,
        "snapshot A exact live/other/retained/release partitions");
    Check(b.referenced.blocks == 3 && b.shared_with_live.blocks == 1 && b.absent_from_live.blocks == 2 &&
        b.shared_with_other_snapshots.blocks == 1 && b.unique_in_visible_inventory.blocks == 1 &&
        b.retained_or_peer_protected.blocks == 1 && b.potential_reclaim_upper_bound.blocks == 1,
        "snapshot B independently computed partitions");
    for (const auto& row : result->snapshots) Check(row.metadata.referenced.blocks == 3 &&
        row.metadata.shared_with_live.blocks == 1 && row.metadata.shared_with_other_snapshots.blocks == 2 &&
        row.metadata.unique_in_visible_inventory.blocks == 1 && row.metadata.potential_reclaim_upper_bound.blocks == 1,
        "metadata sharing uses canonical dependencies independently of payload");
    Check(!result->snapshot_allocation_charge && !result->apple_purgeable && !result->reclaimable,
        "potential release never becomes an Apple or guaranteed release amount"); ++cases;
}
void RejectContradictions()
{
    for (unsigned fault = 0; fault < 10; ++fault)
    {
        auto graph = Fixture();
        if (fault == 0) graph.outcome = VerificationOutcome::Incomplete;
        if (fault == 1) graph.checkpoints.back().views[0].metadata_ranges = {{200, 1}};
        if (fault == 2) graph.checkpoints.back().views[0].payload_ranges = {{500, 13}};
        if (fault == 3) graph.checkpoints.back().views.back().payload_ranges = {{100, 1}};
        if (fault == 4) graph.checkpoints.back().views[0].declared_filesystem_allocation.bytes++;
        if (fault == 5) graph.chain_xids[1] = 18;
        if (fault == 6) graph.checkpoints.back().views.erase(graph.checkpoints.back().views.begin() + 2);
        if (fault == 7) graph.checkpoints.back().views[0].metadata_ranges = {{10, 1}, {11, 2}};
        if (fault == 8) graph.reclaimable_bytes = 0;
        if (fault == 9) graph.read_budget->LimitRemainingTo(0, 0, 1, 1);
        std::optional<ApfsProfileSnapshotSpaceAttribution> result{std::in_place}; std::string error;
        Check(!TryAttributeVerifiedProfileSnapshotSpace(graph, result, error, [] { return true; }) && !result && !error.empty(),
            "invalid/partial/contradictory graph must clear attribution: " + std::to_string(fault)); ++cases;
    }
}
}
#ifndef APFS_PROFILE_SNAPSHOT_ATTRIBUTION_FIXTURES_ONLY
int main() try
{ ExactPartitions(); RejectContradictions(); std::cout << "PASS " << cases << " cases / " << checks << " checks; exact finite profile attribution\n"; return 0; }
catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
#endif
