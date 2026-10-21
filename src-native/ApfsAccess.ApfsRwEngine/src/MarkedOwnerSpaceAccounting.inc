namespace
{
bool OwnerRanges(const std::vector<Range>& input, std::vector<VerificationBlockRange>& output, AttributionWork& work)
{
    if (!work.Take(input.size(), sizeof(VerificationBlockRange))) return false;
    for (const auto& r : input) output.push_back({r.begin, r.end - r.begin});
    return true;
}

bool MeasureMarkedOwnerSets(ApfsMarkedOwnerSpaceAttribution& result, AttributionWork& work)
{
    const auto bs = result.marked.records.allocation_unit_bytes;
    if (bs < 4096 || bs > 65536 || (bs & (bs - 1)) || !result.marked.records.scope.store_size_bytes ||
        result.marked.records.scope.store_size_bytes % bs || result.views.empty() ||
        result.views.size() != result.marked.marked_file_payload.size())
    { work.error = "MarkedOwnerMeasureScopeInvalid"; return false; }
    const auto capacity = result.marked.records.scope.store_size_bytes / bs;
    const auto ranges = [&](const auto& input, auto& output) {
        std::uint64_t end = 0; bool first = true;
        for (const auto& r : input) {
            if ((!first && r.physical_block <= end) || !work.Append(output, r.physical_block, r.block_count, capacity)) return false;
            end = r.physical_block + r.block_count; first = false;
        }
        return true;
    };
    std::vector<AttributionView> views;
    if (!work.Take(result.views.size(), sizeof(AttributionView))) return false;
    for (const auto& row : result.views) {
        AttributionView view;
        if (!ranges(row.metadata_ranges, view.metadata) || !ranges(row.payload_ranges, view.payload) || view.metadata.empty()) return false;
        views.push_back(std::move(view));
    }
    std::vector<Range> external, all_metadata, all_payload, catalog_metadata;
    if (!ranges(result.catalog_metadata_ranges, catalog_metadata) || catalog_metadata.empty()) return false;
    if (!ranges(result.protected_metadata, external)) return false;
    const auto protected_metadata = external;
    std::vector<Range> protected_payload;
    if (!ranges(result.protected_payload, protected_payload) || !work.Join(external, protected_payload)) return false;
    for (std::size_t i = 0; i < views.size(); ++i) {
        auto& row = result.views[i]; const auto& view = views[i]; const bool current = i + 1 == views.size();
        std::vector<Range> marked, unmarked, other_metadata, other_payload;
        if (!ranges(result.marked.marked_file_payload[i].ranges, marked) || !ranges(row.unmarked_payload_ranges, unmarked)) return false;
        auto covered = marked; std::vector<Range> missing, extra;
        if (!work.Join(covered, unmarked) || !work.Difference(view.payload, covered, missing) ||
            !work.Difference(covered, view.payload, extra)) return false;
        if (!missing.empty() || !extra.empty()) { work.error = "MarkedOwnerPayloadPartitionIncomplete"; return false; }
        for (std::size_t j = 0; j + 1 < views.size(); ++j) {
            if (!work.Take(1, 0)) return false;
            if (i != j && (!work.Join(other_metadata, views[j].metadata) || !work.Join(other_payload, views[j].payload))) return false;
        }
        auto comparison = current ? unmarked : views.back().payload;
        if (!work.Measure(view.metadata, current ? std::vector<Range>{} : views.back().metadata, other_metadata, external, bs, row.metadata) ||
            !work.Measure(marked, comparison, other_payload, external, bs, row.marked_payload)) return false;
        std::vector<Range> absent, visible = comparison, unique, candidate;
        if (!work.Difference(marked, unmarked, absent) || !work.Count(absent, bs, row.shared_with_unmarked_in_view) ||
            !Amount(row.marked_payload.referenced.blocks - row.shared_with_unmarked_in_view.blocks, bs, row.shared_with_unmarked_in_view, work.error) ||
            !work.Join(visible, other_payload) || !work.Join(visible, unmarked) || !work.Difference(marked, visible, unique) ||
            !work.Difference(unique, external, candidate) || !work.Count(unique, bs, row.marked_payload.unique_in_visible_inventory) ||
            !work.Count(candidate, bs, row.marked_payload.potential_reclaim_upper_bound) ||
            !work.Join(all_metadata, view.metadata) || !work.Join(all_payload, view.payload)) return false;
    }
    const auto disjoint = [&](const auto& left, const auto& right) {
        std::vector<Range> difference; ApfsSpaceAmount before, after;
        if (!work.Difference(left, right, difference) || !work.Count(left, bs, before) || !work.Count(difference, bs, after)) return false;
        if (before.blocks != after.blocks) { work.error = "MarkedOwnerMetadataPayloadCollision"; return false; }
        return true;
    };
    std::vector<Range> missing_metadata;
    if (!work.Difference(all_metadata, catalog_metadata, missing_metadata) || !missing_metadata.empty()) return false;
    return disjoint(catalog_metadata, all_payload) && disjoint(catalog_metadata, protected_payload) &&
        disjoint(all_metadata, all_payload) && disjoint(protected_metadata, protected_payload) &&
        disjoint(all_metadata, protected_payload) && disjoint(all_payload, protected_metadata) &&
        work.Count(all_metadata, bs, result.visible_metadata_union) && work.Count(all_payload, bs, result.visible_payload_union) &&
        work.Count(catalog_metadata, bs, result.catalog_metadata);
}

bool BuildMarkedOwnerSpace(const RandomAccessSource& source, const AppleCheckpointView& checkpoint,
    AttributionWork& work, const AppleSnapshotCatalogRecords& catalog, const std::vector<AttributionView>& snapshots,
    const AttributionView& live, ApfsMarkedOwnerSpaceAttribution& result)
{
    const auto& nx = checkpoint.container.superblock;
    std::vector<rw::AppleRecoveryCheckpointView> history;
    const std::vector<std::uint64_t> required = result.from_xid ? std::vector<std::uint64_t>{*result.from_xid} : std::vector<std::uint64_t>{};
    if (!rw::LoadAppleReadOnlySnapshotRecoveryCheckpoints(source, checkpoint, required, history, work.error)) return false;
    std::vector<Range> external_metadata, external_payload;
    const auto validate = [&](const AppleCheckpointView& cp, const AppleVolumeCheckpointView& volume,
                              AppleSnapshotCatalogRecords& records, std::vector<AttributionView>& views, AttributionView& current) {
        std::size_t index = 0;
        const std::function<bool(const AppleSnapshotTreeRecords&)> ns = [&](const auto& tree) {
            if (!work.Tick()) return false;
            const auto& descriptor = index < records.inventory.size() ? records.inventory[index++].volume.superblock : volume.superblock;
            rw::NativeApfsVolumeProjection projection;
            return rw::NativeApfsReader::TryProjectMarkedReferenceFileSystemRecords(tree.filesystem,
                cp.container.superblock, descriptor, source.ReadBudget(), projection, work.error);
        };
        return AttributionCatalog(source, cp, volume.superblock.object_id, work, records, views, current, true, &ns);
    };
    for (const auto& parent : history)
    {
        if (!work.Take(1, sizeof(std::uint64_t))) return false;
        result.checkpoint_xids.push_back(parent.checkpoint.container.superblock.xid);
        for (const auto& volume : parent.checkpoint.volumes)
        {
            AppleSnapshotCatalogRecords records; std::vector<AttributionView> views; AttributionView current;
            if (!validate(parent.checkpoint, volume, records, views, current)) return false;
        }
        for (const auto block : parent.metadata_blocks)
            if (!work.Append(external_metadata, block, 1, nx.block_count)) return false;
        for (const auto& extent : parent.payload_extents)
            if (!work.Append(external_payload, extent.physical_block, extent.block_count, nx.block_count)) return false;
    }
    for (const auto& volume : checkpoint.volumes)
    {
        if (volume.superblock.object_id == result.marked.records.scope.volume_oid) continue;
        AppleSnapshotCatalogRecords records; std::vector<AttributionView> views; AttributionView current;
        if (!validate(checkpoint, volume, records, views, current)) return false;
        for (const auto block : records.metadata_blocks)
            if (!work.Append(external_metadata, block, 1, nx.block_count)) return false;
        if (!work.Join(external_payload, current.payload)) return false;
        for (const auto& view : views) if (!work.Join(external_payload, view.payload)) return false;
    }
    if (!work.Take(1, sizeof(std::uint64_t))) return false;
    result.checkpoint_xids.push_back(nx.xid);
    std::sort(result.checkpoint_xids.begin(), result.checkpoint_xids.end());
    if ((result.from_xid && result.checkpoint_xids.front() != *result.from_xid) ||
        (!result.from_xid && result.checkpoint_xids.size() != 1) || result.views.size() != snapshots.size() + 1)
    { work.error = "MarkedOwnerHistoryBindingInvalid"; return false; }
    if (!work.Normalize(external_metadata) || !work.Normalize(external_payload) ||
        !OwnerRanges(external_metadata, result.protected_metadata, work) ||
        !OwnerRanges(external_payload, result.protected_payload, work)) return false;
    std::vector<Range> catalog_metadata;
    for (const auto block : catalog.metadata_blocks)
        if (!work.Append(catalog_metadata, block, 1, nx.block_count)) return false;
    if (!work.Normalize(catalog_metadata) || !OwnerRanges(catalog_metadata, result.catalog_metadata_ranges, work)) return false;
    for (std::size_t i = 0; i < result.views.size(); ++i)
    {
        auto& row = result.views[i]; const bool current = i == snapshots.size();
        const auto& view = current ? live : snapshots[i];
        if (!OwnerRanges(view.metadata, row.metadata_ranges, work) || !OwnerRanges(view.payload, row.payload_ranges, work)) return false;
    }
    if (!MeasureMarkedOwnerSets(result, work)) return false;
    // Catalog/view cardinality has already been checked by the canonical loader.
    if (catalog.inventory.size() != snapshots.size()) return false;
    result.explicit_owner_graphs_verified = true; return true;
}
}

bool ValidateAppleMarkedOwnerSpaceAmounts(const ApfsMarkedOwnerSpaceAttribution& result,
    const std::function<bool()>& deadline, std::string& error)
{
    try {
        if (!result.marked.records.read_budget) return false;
        AttributionWork work{result.marked.records.read_budget, deadline, error};
        if (!work.Take(1, sizeof(result)) || !work.Take(result.protected_metadata.size() + result.protected_payload.size() +
                result.catalog_metadata_ranges.size(), sizeof(VerificationBlockRange)) ||
            !work.Take(result.checkpoint_xids.size(), sizeof(std::uint64_t))) return false;
        for (const auto& row : result.views) {
            if (!work.Take(1, sizeof(row)) || !work.Take(row.metadata_ranges.size() + row.payload_ranges.size() +
                row.unmarked_payload_ranges.size(), sizeof(VerificationBlockRange))) return false;
        }
        for (const auto& row : result.marked.marked_file_payload)
            if (!work.Take(1, sizeof(row)) || !work.Take(row.ranges.size(), sizeof(VerificationBlockRange))) return false;
        for (const auto& row : result.marked.records.views)
            if (!work.Take(1, sizeof(row)) || !work.Take(row.snapshot_name_utf8.size(), 1)) return false;
        auto measured = result;
        if (!MeasureMarkedOwnerSets(measured, work)) return false;
        const auto equal = [](const ApfsSpaceAmount& a, const ApfsSpaceAmount& b) { return a.blocks == b.blocks && a.bytes == b.bytes; };
        const auto same = [&](const ApfsSnapshotAttributionAmounts& a, const ApfsSnapshotAttributionAmounts& b) {
            return equal(a.referenced, b.referenced) && equal(a.shared_with_live, b.shared_with_live) &&
                equal(a.absent_from_live, b.absent_from_live) && equal(a.shared_with_other_snapshots, b.shared_with_other_snapshots) &&
                equal(a.unique_in_visible_inventory, b.unique_in_visible_inventory) &&
                equal(a.retained_or_peer_protected, b.retained_or_peer_protected) && equal(a.potential_reclaim_upper_bound, b.potential_reclaim_upper_bound);
        };
        if (!equal(result.visible_metadata_union, measured.visible_metadata_union) || !equal(result.visible_payload_union, measured.visible_payload_union) ||
            !equal(result.catalog_metadata, measured.catalog_metadata)) return false;
        for (std::size_t i = 0; i < result.views.size(); ++i)
            if (!same(result.views[i].metadata, measured.views[i].metadata) || !same(result.views[i].marked_payload, measured.views[i].marked_payload) ||
                !equal(result.views[i].shared_with_unmarked_in_view, measured.views[i].shared_with_unmarked_in_view)) return false;
        return true;
    } catch (...) { error = "MarkedOwnerMeasureValidationFailed"; return false; }
}
