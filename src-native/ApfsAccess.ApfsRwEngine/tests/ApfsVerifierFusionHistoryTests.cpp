#include "ApfsProfileHistory.h"
#define main HistoricalFusionFixtureMain
#include "ApfsFusionImageWriteSessionTests.cpp"
#undef main

namespace
{
const fs::path& MainImage(const Files& f) { return f.HistoricalFusionFixtureMain; }
VerificationScope HistoryScope(const Files& f)
{
    VerificationScope scope; scope.source_identity = "held-private-fusion-history";
    scope.exact = {f.prefix, 512ull*f.bs, f.request.container_uuid_hex, std::string(32,'c'), 101, f.request.checkpoint_xid};
    return scope;
}
std::uint64_t HistoryBlocks(const std::vector<VerificationBlockRange>& ranges)
{
    std::uint64_t sum = 0; for (const auto& r : ranges) sum += r.block_count; return sum;
}
void AdvanceUnchangedGraphs(Files& f)
{
    auto owner = f.Open(); auto plan = TransportPlan(*owner); std::string error;
    // Retain only the canonical checkpoint publication, without the transport
    // fixture's unrelated storage-only writes into unowned test blocks.
    auto& writes = plan.before_superblock_writes;
    writes.erase(std::remove_if(writes.begin(), writes.end(), [&](const auto& w) {
        return w.physical_block == 40 || w.physical_block == f.TierBlock() + 10;
    }), writes.end());
    Check(FinalizeFusionCheckpointPublication(Access::Store(*owner), plan, error), error);
    Check(Execute(*owner, plan, error), "canonical unchanged-graph publication: " + error);
    owner->Close();
    f.sources[0]->bytes = Load(MainImage(f)); f.sources[1]->bytes = Load(f.tier);
    f.Refresh(plan.transaction_xid);
}
void PublishCreate(Files& f)
{
    auto owner = f.Open(); auto plan = PlanVolume(*owner, CreateFile(*owner)); std::string error;
    Check(Execute(*owner, plan.transaction.commit.publication, error), error);
    owner->Close(); f.sources[0]->bytes = Load(MainImage(f)); f.sources[1]->bytes = Load(f.tier); f.Refresh(21);
}
void RemoveHistoricalQueueOwner(Files& f, bool free_bit)
{
    std::string error; auto store = ApfsFusionStore::BindImages(f.request, error);
    Check(static_cast<bool>(store), error); AppleSpacemanView allocation;
    Check(LoadFusionSpacemanAllocationView(*store, allocation, error), error);
    const auto chunk = allocation.chunks.front(); const auto cib = allocation.devices[0].cibs.front().object.physical_block;
    const auto spaceman = allocation.object.physical_block; store.reset();
    const auto& queue = allocation.free_queues[1];
    std::vector<AppleSpacemanFreeQueueEntry> kept; bool removed = false;
    for (const auto& e : queue.entries)
    {
        if (30 < e.physical_block || 30 >= e.physical_block + e.block_count) { kept.push_back(e); continue; }
        removed = true;
        if (e.physical_block < 30) kept.push_back({e.xid,e.physical_block,30-e.physical_block});
        if (e.physical_block + e.block_count > 31) kept.push_back({e.xid,31,e.physical_block+e.block_count-31});
    }
    Check(removed && !kept.empty(), "historical-only metadata queue entry located");
    AppleBtreeOptions options; options.block_size=f.bs; options.xid=queue.root.xid;
    options.root_object_id=queue.root.object_id; options.root_physical_block=queue.root.physical_block;
    options.storage_type=kObjectEphemeral; options.subtype=kObjectTypeSpacemanFreeQueue;
    options.tree_flags=queue.tree_flags; options.fixed_key_size=16; options.fixed_value_size=8;
    options.minimum_longest_key=queue.longest_key; options.minimum_longest_value=queue.longest_value;
    options.key_order=AppleBtreeKeyOrder::SpacemanFreeQueue;
    std::vector<apfsaccess::catalog::BtreeRecord> records; std::uint64_t blocks=0, oldest=UINT64_MAX;
    for (const auto& e : kept)
    {
        apfsaccess::catalog::BtreeRecord r; r.key.resize(16); Put(r.key,0,e.xid); Put(r.key,8,e.physical_block);
        if (e.block_count != 1) { r.value.resize(8); Put(r.value,0,e.block_count); }
        records.push_back(std::move(r)); blocks+=e.block_count; oldest=(std::min)(oldest,e.xid);
    }
    AppleSerializedBtree tree; Check(SerializeAppleBtree(records,options,tree,error) && tree.objects.size()==1,error);
    f.Place(0,queue.root.physical_block,tree.objects.front().bytes);
    if (free_bit)
    {
        auto bitmap = f.Block(0, chunk.bitmap_block); Bit(bitmap,30,false); f.Place(0,chunk.bitmap_block,bitmap);
        f.Edit(0,cib,[&](auto& bytes){Put(bytes,0x3C,chunk.free_count+1,4);});
    }
    f.Edit(0,spaceman,[&](auto& bytes){Put(bytes,0x48,allocation.devices[0].free_count+(free_bit?1:0));Put(bytes,0xF0,blocks);Put(bytes,0x100,oldest);});
    Save(MainImage(f),f.sources[0]->bytes); f.Refresh(f.request.checkpoint_xid);
}
RetainedProfileHistoryReport History(Files& f, std::uint64_t from = 20,
    const std::function<bool()>& deadline = [] { return true; })
{
    std::string error; auto store = ApfsFusionStore::BindImages(f.request, error);
    Check(static_cast<bool>(store), error);
    auto scope = HistoryScope(f);
    return VerifyFusionRetainedHistory(*store, scope,
        {"apfs-store:test-main", "apfs-store:test-tier2"}, from, deadline);
}
void FailedHistory(const RetainedProfileHistoryReport& r)
{
    Check(r.outcome != VerificationOutcome::Complete && !r.findings.empty(), "failed history completed");
    Check(r.chain_xids.empty() && r.checkpoints.empty(), "partial history escaped");
    Check(!r.apple_purgeable_bytes && !r.reclaimable_bytes && !r.snapshot_allocation_charge_bytes, "history invented charge");
}
}

int main(int argc, char** argv) try
{
    Check(argc == 2, "new private evidence directory required");
    const auto root = fs::absolute(argv[1]).lexically_normal();
    Check(root.wstring().starts_with(L"D:\\ApfsAccessScratch\\") && fs::create_directories(root), "fresh D-only history evidence");
    Run("two complete checkpoints retain exact main and tier graphs", [&] {
        Files f(root); VolumePlanFixture(f); AdvanceUnchangedGraphs(f);
        const auto before_main = Load(MainImage(f)), before_tier = Load(f.tier);
        for (unsigned repeat = 0; repeat < 2; ++repeat)
        {
            const auto r = History(f);
            Check(r.outcome == VerificationOutcome::Complete, r.findings.empty() ? "history incomplete" : r.findings.front().detail);
            Check(r.chain_xids == std::vector<std::uint64_t>{20,21} && r.checkpoints.size() == 2, "exact chain missing");
            for (const auto& g : r.checkpoints)
            {
                Check(g.metadata_ranges.size() > 0 && g.payload_ranges == std::vector<VerificationBlockRange>{{20,1},{f.TierBlock()+20,1}}, "historical graph partitions");
                Check(HistoryBlocks(g.metadata_ranges) == 7, "historical metadata footprint");
            }
            Check(!r.apple_purgeable_bytes && !r.reclaimable_bytes && !r.snapshot_allocation_charge_bytes, "policy charge promoted");
        }
        Check(Load(MainImage(f)) == before_main && Load(f.tier) == before_tier, "proof mutated images");
    });
    Run("three generations include peer and nonzero member windows", [&] {
        Files f(root, 2); VolumePlanFixture(f); AddSiblingVolume(f);
        AdvanceUnchangedGraphs(f); AdvanceUnchangedGraphs(f);
        const auto r = History(f);
        Check(r.outcome == VerificationOutcome::Complete, r.findings.empty() ? "peer history incomplete" : r.findings.front().detail);
        Check(r.chain_xids == std::vector<std::uint64_t>{20,21,22} && r.checkpoints.size() == 3 &&
            r.stores[0].offset_bytes == f.prefix && r.stores[1].offset_bytes == f.prefix, "peer chain/windows missing");
        for (const auto& g : r.checkpoints) Check(HistoryBlocks(g.metadata_ranges) == 12 && HistoryBlocks(g.payload_ranges) == 3, "peer historical ownership omitted");
    });
    Run("actual canonical file create retains distinct historical metadata", [&] {
        Files f(root); VolumePlanFixture(f); PublishCreate(f);
        const auto r = History(f);
        Check(r.outcome == VerificationOutcome::Complete, r.findings.empty() ? "created history incomplete" : r.findings.front().detail);
        Check(r.checkpoints.size() == 2 && r.checkpoints[0].metadata_ranges != r.checkpoints[1].metadata_ranges,
            "new and old metadata graphs were not distinct");
        Check(HistoryBlocks(r.checkpoints[0].payload_ranges) == 2 && HistoryBlocks(r.checkpoints[1].payload_ranges) == 3,
            "actual create historical/current payload partitions");
    });
    Run("free old-only metadata fails even when current graph verifies", [&] {
        Files f(root); VolumePlanFixture(f); PublishCreate(f); RemoveHistoricalQueueOwner(f,true);
        std::string error; auto store = ApfsFusionStore::BindImages(f.request,error); Check(static_cast<bool>(store),error);
        const auto scope = HistoryScope(f);
        const auto current = ApfsVerifier::VerifyFusionCurrent(*store,scope,{"apfs-store:test-main","apfs-store:test-tier2"},[]{return true;});
        Check(current.outcome == VerificationOutcome::Complete, current.findings.empty() ? "current graph failed" : current.findings.front().detail);
        const auto r = VerifyFusionRetainedHistory(*store,scope,{"apfs-store:test-main","apfs-store:test-tier2"},20,[]{return true;});
        FailedHistory(r); Check(r.findings.front().detail == "AppleCheckpointRetentionReclaimed", "old-only allocation loss was missed");
    });
    Run("queue disappearance cannot hide reclaim and reallocation", [&] {
        Files f(root); VolumePlanFixture(f); PublishCreate(f); AdvanceUnchangedGraphs(f); RemoveHistoricalQueueOwner(f,false);
        const auto r = History(f); FailedHistory(r);
        Check(r.findings.front().detail == "AppleCheckpointRetentionContinuityUnavailable", "queue history loss was missed");
    });
    for (unsigned mode = 0; mode < 2; ++mode) Run("older NX magic damage cannot erase a generation", [&] {
        Files f(root); VolumePlanFixture(f); AdvanceUnchangedGraphs(f);
        auto old = f.Block(0,129); Check(ReadU64LE(old,16) == 20, "old descriptor retained");
        old[0x20] ^= std::byte{1}; if (mode) Seal(old); f.Place(0,129,old);
        Save(MainImage(f),f.sources[0]->bytes); f.Refresh(21);
        const auto r = History(f); FailedHistory(r);
        Check(r.outcome == VerificationOutcome::Incomplete && r.findings.front().code ==
            (mode ? VerificationCode::StructuralInconsistency : VerificationCode::ChecksumMismatch), "descriptor damage classification");
    });
    Run("missing explicit historical endpoint refuses", [&] {
        Files f(root); VolumePlanFixture(f); AdvanceUnchangedGraphs(f);
        const auto r = History(f,19); FailedHistory(r);
        Check(r.findings.front().code == VerificationCode::CheckpointUnavailable, "missing historical checkpoint classification");
    });
    Run("broken next-XID continuity does not publish a suffix", [&] {
        Files f(root); VolumePlanFixture(f); AdvanceUnchangedGraphs(f);
        f.Edit(0,129,[](auto& bytes){Put(bytes,0x60,22);});
        Save(MainImage(f),f.sources[0]->bytes); f.Refresh(21);
        const auto r = History(f); FailedHistory(r);
        Check(r.findings.front().code == VerificationCode::CheckpointUnavailable, "broken chain classification");
    });
    Run("checksum-valid old tree corruption refuses", [&] {
        Files f(root); VolumePlanFixture(f); AdvanceUnchangedGraphs(f);
        f.Edit(0,30,[](auto& bytes){Put(bytes,8,1009);});
        Save(MainImage(f),f.sources[0]->bytes); f.Refresh(21);
        FailedHistory(History(f));
    });
    Run("expired deadline remains sticky with no partial chain", [&] {
        Files f(root); VolumePlanFixture(f); AdvanceUnchangedGraphs(f);
        FailedHistory(History(f,20,[]{return false;}));
    });
    std::cout << "PASS " << cases << " cases, " << checks << " checks; canonical paired-image retained graph history\n";
    return 0;
}
catch (const std::exception& e) { std::cerr << "FAIL " << e.what() << '\n'; return 1; }
