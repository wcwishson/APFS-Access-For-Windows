// Included only beside the Fusion planner in AppleVolumeTransaction.cpp.
namespace {
class FusionCensusSource final : public catalog::RandomAccessSource {
public:
    FusionCensusSource(const catalog::RandomAccessSource& base, std::uint32_t block_size)
        : observed_(base), block_size_(block_size) {}
    std::uint64_t SizeBytes() const override { return observed_.SizeBytes(); }
    std::shared_ptr<catalog::ApfsReadBudget> ReadBudget() const override { return observed_.ReadBudget(); }
    bool Read(std::uint64_t offset, std::size_t size, std::vector<std::byte>& out) const override {
        out.clear();
        if (!size || offset > SizeBytes() || size > SizeBytes() - offset) { failed_ = true; return false; }
        const auto end = (offset + size - 1) / block_size_;
        bool captured = true;
        for (auto b = offset / block_size_; b <= end; ++b) captured = captured && bytes_.contains(b);
        if (captured) {
            if (!ReadBudget() || !ReadBudget()->Read(size)) { failed_ = true; return false; }
            out.resize(size);
            for (auto b = offset / block_size_; b <= end; ++b) {
                const auto first = (std::max)(offset,b*block_size_);
                const auto last = (std::min)(offset+size,(b+1)*block_size_);
                std::copy_n(bytes_.at(b).begin()+(first-b*block_size_),last-first,out.begin()+(first-offset));
            }
            return true;
        }
        if (!observed_.Read(offset,size,out) || out.size() != size) { failed_ = true; return false; }
        for (auto b = offset / block_size_; b <= end; ++b) {
            blocks_.insert(b);
            if (blocks_.size() > 8192) { failed_ = true; return false; }
            const auto first = b*block_size_;
            if (first >= offset && first+block_size_ <= offset+size) {
                const auto begin = out.begin()+(first-offset);
                const auto found = bytes_.find(b);
                if (found != bytes_.end()) {
                    if (!std::equal(begin,begin+block_size_,found->second.begin())) { failed_ = true; return false; }
                } else {
                    if (!ReadBudget() || !ReadBudget()->Materialize(1,block_size_)) { failed_ = true; return false; }
                    bytes_.emplace(b,std::vector<std::byte>(begin,begin+block_size_));
                }
            }
        }
        return true;
    }
    bool Capture(std::vector<AppleCheckpointGuardBlock>& guards, std::string& error) const {
        if (failed_) return Fail(error,"FusionReclaimObservationIncomplete");
        guards.clear();
        for (auto b : blocks_) {
            const auto found = bytes_.find(b);
            if (found != bytes_.end()) guards.push_back({b,found->second});
            else if (!AddGuard(observed_,b,block_size_,guards)) return Fail(error,"FusionReclaimGuardUnreadable");
        }
        // Cached census reads are only a local immutable planning view. Every
        // original dependency is re-read and compared before it grants a plan.
        return observed_.VerifyUnchanged(error);
    }
    bool Failed() const { return failed_; }
private:
    SnapshotPlanningSource observed_;
    std::uint32_t block_size_;
    mutable std::set<std::uint64_t> blocks_;
    mutable std::map<std::uint64_t,std::vector<std::byte>> bytes_;
    mutable bool failed_ = false;
};
}

bool CollectFusionReclamationCensus(const catalog::ApfsFusionStore& store,
    FusionReclamationCensus& out, std::string& error) try
{
    out = {};
    if (!store.CheckAvailable(error)) return false;
    const auto& nx = store.Checkpoint().superblock;
    FusionCensusSource observed(store,nx.block_size);
    catalog::AppleCheckpointView current;
    if (!LoadFusionPlanningCheckpoint(store,observed,store.Checkpoint(),current,error)) return false;
    FusionReclamationCensus candidate;
    candidate.oldest_checkpoint_xid = nx.xid;
    std::set<std::uint64_t> selected;
    const auto collect = [&](const catalog::ContainerCheckpointView& container) {
        catalog::AppleCheckpointView cp;
        FusionLiveGraph graph;
        if (!LoadFusionPlanningCheckpoint(store,observed,container,cp,error) ||
            !ReadFusionLiveGraph(store,observed,cp,graph,error)) return false;
        const auto xid = cp.container.superblock.xid;
        candidate.oldest_checkpoint_xid = (std::min)(candidate.oldest_checkpoint_xid,xid);
        for (auto b : graph.metadata) {
            if (!FusionOwnedRange(store,current,b,1,xid,error)) return false;
            candidate.owners.push_back({b,1});
        }
        for (const auto& p : graph.payload) {
            if (!FusionOwnedRange(store,current,p.physical_block,p.block_count,xid,error)) return false;
            candidate.owners.push_back({p.physical_block,p.block_count});
        }
        selected.insert(xid);
        return true;
    };
    if (!collect(store.Checkpoint())) return false;
    std::vector<std::byte> block(nx.block_size);
    for (std::uint32_t i = 0; i < nx.xp_desc_block_count;) {
        std::vector<std::byte> bytes;
        const auto count = (std::min)(std::uint32_t{16},nx.xp_desc_block_count-i);
        if (!observed.Read((nx.xp_desc_base_block+i)*nx.block_size,count*nx.block_size,bytes))
            return Fail(error,"FusionReclaimHistoryUnreadable");
        for (std::uint32_t j = 0; j < count; ++j) {
            std::copy_n(bytes.begin()+j*nx.block_size,nx.block_size,block.begin());
            const auto header = catalog::ParseNxSuperblock(block);
            if (!header || !catalog::VerifyObjectChecksum(block,nx.block_size) ||
                header->xid > nx.xid || selected.contains(header->xid)) continue;
            std::string ignored;
            auto checkpoint = catalog::LoadContainerCheckpointView(observed,0,observed.SizeBytes(),ignored,header->xid);
            if (!checkpoint) {
                if (observed.Failed()) return Fail(error,"FusionReclaimHistoryUnreadable");
                if (auto budget = observed.ReadBudget(); budget && budget->Failed()) return Fail(error,budget->Failure());
                continue; // The canonical loader rejects an incomplete ring generation.
            }
            if (checkpoint->superblock.xid != header->xid || !collect(*checkpoint)) return false;
        }
        i += count;
    }
    // Union retained ranges across generations. Sharing across generations is
    // expected; collisions inside each generation were checked by the walker.
    std::sort(candidate.owners.begin(),candidate.owners.end(),[](const auto& a,const auto& b) {
        return a.physical_block < b.physical_block;
    });
    std::vector<AppleSpacemanReleaseRequest> merged;
    for (const auto& owner : candidate.owners) {
        if (!owner.block_count || owner.physical_block > UINT64_MAX-owner.block_count)
            return Fail(error,"FusionReclaimOwnerOverflow");
        if (!merged.empty() && owner.physical_block <= merged.back().physical_block+merged.back().block_count) {
            const auto end = (std::max)(owner.physical_block+owner.block_count,
                merged.back().physical_block+merged.back().block_count);
            merged.back().block_count = end-merged.back().physical_block;
        } else merged.push_back(owner);
    }
    candidate.owners = std::move(merged);
    if (!observed.Capture(candidate.guards,error) || !store.CheckAvailable(error)) return false;
    out = std::move(candidate);
    return true;
}
catch (const std::bad_alloc&) { out = {}; return Fail(error,"FusionReclaimMemoryLimit"); }
catch (const std::length_error&) { out = {}; return Fail(error,"FusionReclaimMemoryLimit"); }
