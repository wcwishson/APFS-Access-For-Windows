#include "ApfsVerificationJson.h"
#define APFS_PROFILE_SNAPSHOT_ATTRIBUTION_FIXTURES_ONLY
#include "ApfsProfileSnapshotAttributionTests.cpp"
#undef APFS_PROFILE_SNAPSHOT_ATTRIBUTION_FIXTURES_ONLY
#include <filesystem>
#include <fstream>

namespace
{
bool Encode(const ProfileSnapshotGraphReport& graph, std::string& json, payload::Reason& reason,
    std::size_t cap = MaxImageVerificationJsonBytes, const std::function<bool()>& alive = [] { return true; })
{
    return SerializeVisibleSnapshotProfileVerificationReport(graph, CurrentVerificationProfile::FusionCleanCache,
        Fixture().endpoint_scope, 18, Fixture().stores, std::vector<std::string>{"D:\\private\\main.apfs", "D:\\private\\tier.apfs"},
        alive, cap, json, reason);
}
void RunJson(const std::filesystem::path& folder)
{
    {
        auto graph = Fixture(); graph.source_reads = 3; graph.source_read_bytes = 12288;
        Check(graph.read_budget->Read(12288), "record source work");
        std::string json; payload::Reason reason; Check(Encode(graph, json, reason), "complete visible snapshot serialization");
        Check(json.starts_with("{\"format\":\"apfs-access-visible-snapshot-profile-verification\",\"version\":1,"), "distinct version identity");
        Check(json.find("\"referencedSnapshotPayload\":{\"blocks\":\"6\",\"bytes\":\"24576\"}") != std::string::npos,
            "encoded union must be six blocks, not sum seven");
        Check(json.find("\"potentialReclaimUpperBound\":{\"blocks\":\"1\",\"bytes\":\"4096\"}") != std::string::npos,
            "independently proved nonzero release upper bound is encoded");
        Check(json.find("\"snapshotAllocationChargeBytes\":null,\"applePurgeableBytes\":null,\"reclaimableBytes\":null") != std::string::npos &&
            json.find("\"hiddenOwnersComplete\":false") != std::string::npos &&
            json.find("\"independentSnapshotChargeVerified\":false") != std::string::npos, "unknown Apple policy remains explicit");
        if (!folder.empty()) { std::ofstream file(folder / "visible-snapshots.json", std::ios::binary); file << json;
            Check(static_cast<bool>(file), "write small encoded private control"); }
        ++cases;
    }
    for (const bool refused : {false, true}) {
        auto graph = Fixture(); graph.outcome = refused ? VerificationOutcome::Refused : VerificationOutcome::Incomplete;
        graph.selected.reset(); graph.stores.clear(); graph.checkpoints.clear(); graph.chain_xids.clear(); graph.allocation_unit_bytes = 0;
        graph.findings.push_back({refused ? VerificationCode::UnsupportedFeature : VerificationCode::ChecksumMismatch,
            refused ? VerificationSeverity::Warning : VerificationSeverity::Error, VerificationCheck::SnapshotReachableAllocation,
            101, {}, 80, 18, {}, refused ? "profile unsupported" : "snapshot checksum"});
        std::string json; payload::Reason reason; Check(Encode(graph, json, reason), "typed failure document");
        Check(json.find("\"selected\":null") != std::string::npos && json.find("\"graph\":null,\"attribution\":null") != std::string::npos &&
            json.find("\"visibleSnapshotNamespacesVerified\":null") != std::string::npos, "failure publishes no complete graph/counts");
        ++cases;
    }
    for (unsigned fault = 0; fault < 9; ++fault) {
        auto graph = Fixture(); graph.source_reads = 3; graph.source_read_bytes = 12288;
        if (fault == 0) graph.endpoint_scope.source_identity += "wrong";
        if (fault == 1) graph.from_xid = 17;
        if (fault == 2) graph.stores[1].offset_bytes = 0;
        if (fault == 3) graph.checkpoints.back().views[0].payload_ranges = {{500, 13}};
        if (fault == 4) graph.checkpoints.back().views[0].declared_filesystem_allocation.bytes++;
        if (fault == 5) graph.reclaimable_bytes = 0;
        if (fault == 6) graph.checkpoints.back().views[0].name_utf8 = std::string(1, '\0');
        if (fault == 7) graph.checkpoints.back().protected_graph.payload_ranges = {{100, 3}};
        if (fault == 8) (void)graph.read_budget->Refuse("shared allowance exhausted");
        std::string json = "must clear"; payload::Reason reason;
        Check(!Encode(graph, json, reason) && json.empty() && reason != payload::Reason::None,
            "wrong source/history/member/counter/graph/budget refuses output: " + std::to_string(fault)); ++cases;
    }
    for (const bool expired : {false, true}) {
        auto graph = Fixture(); graph.source_reads = 3; graph.source_read_bytes = 12288;
        std::string json = "must clear"; payload::Reason reason;
        Check(!Encode(graph, json, reason, expired ? MaxImageVerificationJsonBytes : 16, [expired] { return !expired; }) &&
            json.empty() && reason == (expired ? payload::Reason::Deadline : payload::Reason::OutputLimit), "bounded complete response is atomic");
        ++cases;
    }
}
}
int main(int argc, char** argv) try
{
    std::filesystem::path folder;
    if (argc == 2) {
        folder = std::filesystem::absolute(argv[1]).lexically_normal();
        Check(folder.wstring().starts_with(L"D:\\ApfsAccessScratch\\") && std::filesystem::create_directories(folder), "new D-only evidence directory");
    } else Check(argc == 1, "optional private output folder only");
    RunJson(folder); std::cout << "PASS " << cases << " cases / " << checks << " checks; visible snapshot profile JSON\n"; return 0;
}
catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
