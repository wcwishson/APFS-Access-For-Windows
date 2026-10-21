bool TryAttributeVerifiedProfileSnapshotSpace(const ProfileSnapshotGraphReport& graph,
    std::optional<ApfsProfileSnapshotSpaceAttribution>& out, std::string& error,
    const std::function<bool()>& deadline)
{
    out.reset(); error.clear();
    const auto budget = graph.read_budget;
    const auto invalid = [&](const char* reason) { error = reason; return false; };
    if (!budget || !deadline || graph.outcome != VerificationOutcome::Complete || !graph.findings.empty() ||
        !graph.selected || graph.selected->exact != graph.endpoint_scope.exact ||
        graph.endpoint_scope.source_identity.empty() || graph.endpoint_scope.source_identity.size() > 1024 ||
        !graph.endpoint_scope.exact.volume_oid || !graph.endpoint_scope.exact.checkpoint_xid ||
        graph.endpoint_scope.exact.container_uuid_hex.size() != 32 || graph.endpoint_scope.exact.volume_uuid_hex.size() != 32 ||
        graph.endpoint_scope.require_whole_volume ||
        graph.endpoint_scope.require_payload_content_hashes || graph.endpoint_scope.observe_payload_content ||
        graph.endpoint_scope.account_retained_ownership || graph.endpoint_scope.retained_from_xid ||
        graph.snapshot_allocation_charge_bytes || graph.apple_purgeable_bytes || graph.reclaimable_bytes)
        return invalid("ProfileAttributionCompleteGraphRequired");
    try
    {
        AttributionWork work{budget, deadline, error};
        const bool fusion = graph.profile == CurrentVerificationProfile::FusionCleanCache;
        const auto bs = graph.allocation_unit_bytes;
        const auto& scope = graph.endpoint_scope;
        if (!work.Tick()) return false;
        if ((!fusion && graph.profile != CurrentVerificationProfile::EncryptedOneKeyGenerationZero) ||
            bs < 4096 || bs > 65536 || (bs & (bs - 1)) || graph.stores.size() != (fusion ? 2 : 1) ||
            graph.stores.front().offset_bytes != scope.exact.store_offset_bytes ||
            graph.stores.front().size_bytes != scope.exact.store_size_bytes ||
            (!fusion && (scope.exact.store_offset_bytes || graph.stores.front().store_id != scope.source_identity)) ||
            graph.checkpoints.empty() || graph.checkpoints.size() != graph.chain_xids.size() ||
            graph.chain_xids.back() != scope.exact.checkpoint_xid ||
            (graph.from_xid ? (graph.chain_xids.size() < 2 || *graph.from_xid != graph.chain_xids.front() ||
                !*graph.from_xid || *graph.from_xid >= scope.exact.checkpoint_xid) : graph.chain_xids.size() != 1))
            return invalid("ProfileAttributionGraphBindingInvalid");
        std::uint64_t capacity = 0;
        for (const auto& store : graph.stores)
        {
            if (!work.Take(1, store.store_id.size())) return false;
            if (store.store_id.empty() || !store.size_bytes || store.size_bytes % bs || store.offset_bytes % bs ||
                store.offset_bytes > UINT64_MAX - store.size_bytes || store.size_bytes / bs > UINT64_MAX - capacity)
                return invalid("ProfileAttributionMemberBindingInvalid");
            capacity += store.size_bytes / bs;
        }
        if (fusion && graph.stores[0].store_id == graph.stores[1].store_id)
            return invalid("ProfileAttributionDistinctMembersRequired");
        const auto tier = kFusionTier2ByteAddress / bs;
        const auto limit = fusion ? tier + graph.stores[1].size_bytes / bs : capacity;
        const auto address = [&](const VerificationBlockRange& range) {
            if (!range.block_count) return false;
            if (range.physical_block < graph.stores[0].size_bytes / bs)
                return range.block_count <= graph.stores[0].size_bytes / bs - range.physical_block;
            return fusion && range.physical_block >= tier && range.physical_block - tier < graph.stores[1].size_bytes / bs &&
                range.block_count <= graph.stores[1].size_bytes / bs - (range.physical_block - tier);
        };
        const auto ranges = [&](const std::vector<VerificationBlockRange>& input, std::vector<Range>& target) {
            std::uint64_t end = 0; bool first = true;
            for (const auto& range : input) {
                if (!work.Tick()) return false;
                if (!address(range) || (!first && range.physical_block <= end))
                    return invalid("ProfileAttributionNoncanonicalRange");
                if (!work.Append(target, range.physical_block, range.block_count, limit)) return false;
                end = range.physical_block + range.block_count; first = false;
            }
            return true;
        };
        const auto contained = [&](const std::vector<Range>& inner, const std::vector<Range>& outer) {
            std::vector<Range> missing;
            return work.Difference(inner, outer, missing) &&
                (missing.empty() || invalid("ProfileAttributionUnprotectedViewRange"));
        };
        const auto disjoint = [&](const std::vector<Range>& a, const std::vector<Range>& b) {
            std::size_t i = 0, j = 0;
            while (i < a.size() && j < b.size()) {
                if (!work.Take(1, 0)) return false;
                if (a[i].begin < b[j].end && b[j].begin < a[i].end)
                    return invalid("ProfileAttributionOwnerOverlap");
                if (a[i].end <= b[j].begin) ++i; else ++j;
            }
            return true;
        };
        std::vector<Range> external, union_metadata, union_payload, protected_metadata, protected_payload;
        const auto& endpoint = graph.checkpoints.back();
        std::vector<AttributionView> selected;
        std::vector<const ProfileSnapshotViewGraph*> descriptors;
        AttributionView live; bool found_live = false;
        for (std::size_t ci = 0; ci < graph.checkpoints.size(); ++ci)
        {
            const auto& checkpoint = graph.checkpoints[ci];
            const auto& protected_graph = checkpoint.protected_graph;
            if (!work.Take(1, sizeof(AttributionView))) return false;
            if (protected_graph.checkpoint_xid != graph.chain_xids[ci] ||
                (!ci ? !graph.chain_xids[ci] : graph.chain_xids[ci - 1] >= graph.chain_xids[ci]) ||
                protected_graph.metadata_ranges.empty() || checkpoint.views.empty())
                return invalid("ProfileAttributionCheckpointInvalid");
            std::vector<Range> metadata, payload, view_payload, prior_peers, peer_payload;
            if (!ranges(protected_graph.metadata_ranges, metadata) || !ranges(protected_graph.payload_ranges, payload)) return false;
            if (!work.Join(protected_metadata, metadata) || !work.Join(protected_payload, payload)) return false;
            std::uint64_t volume = 0, previous_xid = 0; bool had_live = false;
            for (const auto& view : checkpoint.views)
            {
                if (!work.Take(1, sizeof(AttributionView) + view.name_utf8.size())) return false;
                if (!view.volume_oid || (!fusion && view.volume_oid != scope.exact.volume_oid) ||
                    view.volume_oid < volume || (view.volume_oid != volume && volume && !had_live))
                    return invalid("ProfileAttributionPeerInventoryInvalid");
                if (view.volume_oid != volume) {
                    if (!work.Join(prior_peers, peer_payload)) return false;
                    peer_payload.clear(); volume = view.volume_oid; previous_xid = 0; had_live = false;
                }
                if (had_live || !view.view_xid || view.view_xid > protected_graph.checkpoint_xid ||
                    (!view.current && (view.name_utf8.empty() || view.view_xid <= previous_xid)) ||
                    (view.current && (view.view_xid != protected_graph.checkpoint_xid || !view.name_utf8.empty())) ||
                    view.metadata_ranges.empty() || !view.descriptor.object_id || !view.descriptor.xid ||
                    view.descriptor.size_bytes != bs || view.descriptor.subtype ||
                    view.descriptor.type != (view.current ? kObjectTypeFs : kObjectPhysical | kObjectTypeFs) ||
                    (!view.current && view.descriptor.object_id != view.descriptor.physical_block) ||
                    !address({view.descriptor.physical_block, 1}) ||
                    (!view.current && view.descriptor.xid < view.view_xid) || view.descriptor.xid > protected_graph.checkpoint_xid ||
                    view.declared_filesystem_allocation.blocks > capacity ||
                    view.declared_filesystem_allocation.blocks > UINT64_MAX / bs ||
                    view.declared_filesystem_allocation.bytes != view.declared_filesystem_allocation.blocks * bs)
                    return invalid("ProfileAttributionViewInvalid");
                previous_xid = view.view_xid; had_live = view.current;
                AttributionView converted;
                if (!ranges(view.metadata_ranges, converted.metadata) || !ranges(view.payload_ranges, converted.payload) ||
                    !contained(converted.metadata, metadata) || !contained(converted.payload, payload) ||
                    !contained({Range{view.descriptor.physical_block, view.descriptor.physical_block + 1}}, converted.metadata) ||
                    !disjoint(prior_peers, converted.payload) || !work.Join(peer_payload, converted.payload) ||
                    !work.Join(view_payload, converted.payload)) return false;
                if (ci + 1 == graph.checkpoints.size()) {
                    if (view.volume_oid != scope.exact.volume_oid) {
                        if (!work.Join(external, converted.metadata) || !work.Join(external, converted.payload)) return false;
                    } else if (view.current) {
                        found_live = true; live = std::move(converted);
                    } else {
                        if (!work.Take(1, sizeof(ProfileSnapshotViewGraph*))) return false;
                        selected.push_back(std::move(converted)); descriptors.push_back(&view);
                    }
                }
            }
            if (!had_live) return invalid("ProfileAttributionLiveOrPayloadCoverageMissing");
            if (!contained(payload, view_payload)) return false;
            if (ci + 1 != graph.checkpoints.size() &&
                (!work.Join(external, metadata) || !work.Join(external, payload))) return false;
        }
        if (!disjoint(protected_metadata, protected_payload)) return false;
        if (!found_live || endpoint.protected_graph.checkpoint_xid != scope.exact.checkpoint_xid)
            return invalid("ProfileAttributionSelectedLiveMissing");
        if (!work.Take(1, sizeof(ApfsProfileSnapshotSpaceAttribution) + scope.source_identity.size() +
                scope.exact.container_uuid_hex.size() + scope.exact.volume_uuid_hex.size()) ||
            !work.Take(graph.stores.size(), sizeof(VerificationStoreBinding)) ||
            !work.Take(graph.chain_xids.size(), sizeof(std::uint64_t))) return false;
        ApfsProfileSnapshotSpaceAttribution result;
        result.profile = graph.profile; result.endpoint_scope = scope; result.from_xid = graph.from_xid;
        result.stores = graph.stores; result.protected_checkpoint_xids = graph.chain_xids; result.allocation_unit_bytes = bs;
        if (!work.Count(live.metadata, bs, result.live_metadata) || !work.Count(live.payload, bs, result.live_payload)) return false;
        for (std::size_t i = 0; i < selected.size(); ++i)
        {
            std::vector<Range> other_metadata, other_payload;
            for (std::size_t j = 0; j < selected.size(); ++j) {
                if (!work.Take(1, 0)) return false;
                if (i != j && (!work.Join(other_metadata, selected[j].metadata) || !work.Join(other_payload, selected[j].payload))) return false;
            }
            const auto& view = *descriptors[i]; ApfsProfileSnapshotAttributionRow row;
            if (!work.Take(1, sizeof(row) + view.name_utf8.size())) return false;
            row.snapshot_xid = view.view_xid; row.name_utf8 = view.name_utf8; row.descriptor = view.descriptor;
            row.declared_filesystem_allocation = view.declared_filesystem_allocation;
            if (!work.Measure(selected[i].metadata, live.metadata, other_metadata, external, bs, row.metadata) ||
                !work.Measure(selected[i].payload, live.payload, other_payload, external, bs, row.payload) ||
                !work.Join(union_metadata, selected[i].metadata) || !work.Join(union_payload, selected[i].payload)) return false;
            result.snapshots.push_back(std::move(row));
        }
        if (!work.Count(union_metadata, bs, result.referenced_snapshot_metadata) ||
            !work.Count(union_payload, bs, result.referenced_snapshot_payload) || !work.Tick()) return false;
        result.complete = true; result.read_budget = budget; out = std::move(result); return true;
    }
    catch (const std::bad_alloc&) { (void)budget->Refuse("ProfileAttributionAllocationFailed"); error = budget->Failure(); }
    catch (const std::length_error&) { (void)budget->Refuse("ProfileAttributionAllocationFailed"); error = budget->Failure(); }
    catch (...) { error = "ProfileAttributionException"; }
    return false;
}
