namespace
{
void WipeSnapshotProfileParentText(AppleCheckpointView& checkpoint) noexcept
{
    const auto wipe = [](std::string& text) {
        SecureZeroMemory(text.data(), text.size()); text.clear();
    };
    wipe(checkpoint.container.superblock.uuid_hex);
    for (auto& volume : checkpoint.volumes) {
        wipe(volume.superblock.name_utf8); wipe(volume.superblock.uuid_hex); wipe(volume.superblock.group_hex);
    }
}
struct SnapshotParentTextScope
{
    AppleCheckpointView& checkpoint;
    ~SnapshotParentTextScope() { WipeSnapshotProfileParentText(checkpoint); }
};
struct SnapshotHistoryTextScope
{
    std::vector<AppleRecoveryCheckpointView>& states;
    ~SnapshotHistoryTextScope() { for (auto& state : states) WipeSnapshotProfileParentText(state.checkpoint); }
};
struct SnapshotCatalogScope
{
    AppleSnapshotCatalogRecords records;
    std::vector<AppleSnapshotMetadataClaim> owners;
    ~SnapshotCatalogScope()
    {
        const auto clear = [](auto& tree) {
            for (auto* rows : {&tree.filesystem, &tree.extentref})
                for (auto& row : *rows) {
                    SecureZeroMemory(row.key.data(), row.key.size());
                    SecureZeroMemory(row.value.data(), row.value.size());
                }
        };
        clear(records.live); for (auto& tree : records.snapshots) clear(tree);
        for (auto& row : records.inventory) {
            SecureZeroMemory(row.name_utf8.data(), row.name_utf8.size());
            auto& volume = row.volume.superblock;
            for (auto* text : {&volume.name_utf8, &volume.uuid_hex, &volume.group_hex})
                SecureZeroMemory(text->data(), text->size());
        }
    }
};

bool SnapshotProfileReserved(const AppleCheckpointView& cp, const ApfsFusionStore* fusion,
    const ApplePhysicalExtentRecord& extent)
{
    const auto& nx = cp.container.superblock;
    const auto& pool = cp.spaceman.internal_pool;
    const auto hit = [&](std::uint64_t first, std::uint64_t count) {
        return count && first < extent.physical_block + extent.block_count &&
            (first >= extent.physical_block || extent.physical_block - first < count);
    };
    return hit(0, 1) || hit(nx.xp_desc_base_block, nx.xp_desc_block_count) ||
        hit(nx.xp_data_base_block, nx.xp_data_block_count) || hit(pool.base_block, pool.block_count) ||
        hit(pool.bitmap_base_block, pool.bitmap_block_count) ||
        (fusion && (hit(kFusionTier2ByteAddress / nx.block_size, 1) || hit(nx.fusion_middle_tree_oid, 1) ||
            hit(nx.fusion_writeback_start, nx.fusion_writeback_blocks)));
}

bool AppendSnapshotProfileView(const RandomAccessSource& source, const AppleCheckpointView& cp,
    std::uint64_t volume_oid, const AppleVolumeCheckpointView& volume,
    const AppleSnapshotTreeRecords& trees, std::uint64_t xid, std::string_view name, bool current,
    const std::vector<ApplePhysicalExtentRecord>& resolved,
    const std::vector<AppleSnapshotMetadataClaim>& claims, ProfileSnapshotCheckpointGraph& graph,
    std::string& error)
{
    if (!volume.superblock_object.object_id || !volume.superblock_object.xid || !xid ||
        (!current && volume.superblock_object.xid < xid) || volume.superblock_object.xid > cp.container.superblock.xid ||
        volume.superblock.space.allocated_block_count > cp.container.superblock.block_count ||
        volume.superblock.space.allocated_block_count > UINT64_MAX / cp.container.superblock.block_size)
    { error = "VerifierSnapshotDescriptorAllocationInvalid"; return false; }
    if (!ChargeHistory(source, 1, sizeof(ProfileSnapshotViewGraph) + name.size(), error)) return false;
    ProfileSnapshotViewGraph view;
    view.volume_oid = volume_oid; view.view_xid = xid; view.current = current; view.name_utf8 = name;
    view.descriptor = volume.superblock_object;
    view.declared_filesystem_allocation = {volume.superblock.space.allocated_block_count,
        volume.superblock.space.allocated_block_count * cp.container.superblock.block_size};
    view.filesystem_record_count = trees.filesystem.size();
    if (trees.filesystem_blocks.empty() || trees.extentref_blocks.empty() ||
        !OwnershipAppend(source, view.metadata_ranges, view.descriptor.physical_block, 1, error))
    { if (error.empty()) error = "VerifierSnapshotViewMetadataCoverageMissing"; return false; }
    for (const auto* blocks : {&trees.filesystem_blocks, &trees.extentref_blocks})
        for (const auto block : *blocks)
            if (!OwnershipAppend(source, view.metadata_ranges, block, 1, error)) return false;
    bool object = false, node = false;
    for (const auto& owner : claims)
    {
        if (!ChargeHistory(source, 1, 0, error)) return false;
        if (owner.volume_oid != volume_oid || owner.view_xid != xid ||
            owner.map_oid != volume.object_map.object.object_id) continue;
        if (owner.metadata_class != AppleSnapshotMetadataClass::OmapObject &&
            owner.metadata_class != AppleSnapshotMetadataClass::OmapNode &&
            owner.metadata_class != AppleSnapshotMetadataClass::OmapSnapshotNode) continue;
        object |= owner.metadata_class == AppleSnapshotMetadataClass::OmapObject;
        node |= owner.metadata_class == AppleSnapshotMetadataClass::OmapNode;
        if (!OwnershipAppend(source, view.metadata_ranges, owner.physical_block, owner.block_count, error)) return false;
    }
    if (!object || !node) { error = "VerifierSnapshotViewOmapCoverageMissing"; return false; }
    for (const auto& extent : resolved)
        if (!OwnershipAppend(source, view.payload_ranges, extent.physical_block, extent.block_count, error)) return false;
    const auto limit = source.SizeBytes() / cp.container.superblock.block_size;
    if (!NormalizeProtectedRanges(view.metadata_ranges, limit, error) ||
        !NormalizeProtectedRanges(view.payload_ranges, limit, error)) return false;
    graph.views.push_back(std::move(view)); return true;
}

bool SnapshotProfilePeerDisjoint(const RandomAccessSource& source,
    const std::vector<std::pair<std::uint64_t, OwnershipRanges>>& peers, std::string& error)
{
    for (std::size_t a = 0; a < peers.size(); ++a) for (std::size_t b = a + 1; b < peers.size(); ++b)
    {
        const auto& left = peers[a].second; const auto& right = peers[b].second;
        std::size_t i = 0, j = 0;
        while (i < left.size() && j < right.size())
        {
            if (!ChargeHistory(source, 1, 0, error)) return false;
            if (left[i].physical_block < right[j].physical_block + right[j].block_count &&
                right[j].physical_block < left[i].physical_block + left[i].block_count)
            { error = "VerifierSnapshotProfileCrossVolumePayloadOverlap"; return false; }
            if (left[i].physical_block + left[i].block_count <= right[j].physical_block) ++i;
            else ++j;
        }
    }
    return true;
}

bool SnapshotProfileFusionCaches(const RandomAccessSource& observed, const ApfsFusionStore& fusion,
    const AppleCheckpointView& checkpoint, std::vector<CurrentOwner>& ledger, std::string& error)
{
    const auto& current = fusion.Checkpoint(); const auto& nx = checkpoint.container.superblock;
    const auto& admitted = current.superblock;
    if (nx.fusion_middle_tree_oid != admitted.fusion_middle_tree_oid ||
        nx.fusion_writeback_oid != admitted.fusion_writeback_oid ||
        nx.fusion_writeback_start != admitted.fusion_writeback_start ||
        nx.fusion_writeback_blocks != admitted.fusion_writeback_blocks)
    { error = "VerifierFusionHistoricalCacheObjectChangedUnsupported"; return false; }
    const auto find = [&](const auto& container) {
        return std::find_if(container.mappings.begin(), container.mappings.end(),
            [&](const auto& row) { return row.object_id == nx.fusion_writeback_oid; });
    };
    const auto old = find(checkpoint.container), now = find(current);
    if (old == checkpoint.container.mappings.end() || now == current.mappings.end() ||
        old->object_id != now->object_id ||
        old->type != now->type || old->subtype != now->subtype || old->file_system_oid != now->file_system_oid ||
        old->size_bytes != now->size_bytes || old->size_bytes != nx.block_size)
    { error = "VerifierFusionHistoricalCacheObjectChangedUnsupported"; return false; }
    // Each ephemeral WBC has its checkpoint's exact generation. Its immutable
    // historical mapping can differ; reuse the factory's canonical body check.
    std::vector<std::byte> bytes, checked;
    if (!observed.Read(old->physical_block * nx.block_size, nx.block_size, bytes))
    { error = "VerifierFusionCacheReadFailure"; return false; }
    const auto xid = ReadU64LE(bytes, 16).value_or(0);
    if (xid != nx.xid)
    { error = "VerifierFusionHistoricalCacheGenerationUnavailable"; return false; }
    if (!fusion.ReadMetadata(old->physical_block, old->type, old->subtype, old->object_id, xid, checked, error) ||
        bytes != checked || !CheckAppleFusionEmptyWritebackBody(checked, error)) return false;
    const AppleObjectLocation middle{nx.fusion_middle_tree_oid, 0, nx.fusion_middle_tree_oid,
        kObjectPhysical | kObjectTypeBtree, 0x15, nx.block_size};
    std::vector<BtreeRecord> records; std::vector<std::uint64_t> visited;
    if (!ReadTree(observed, checkpoint, checkpoint.volumes.front(), middle, records,
            AppleBtreeKeyOrder::Lexicographic, visited, error)) return false;
    if (!records.empty()) { error = "VerifierFusionNonemptyMiddleTreeUnsupported"; return false; }
    for (const auto block : visited)
        if (!AddCurrentOwner(observed, checkpoint, ledger, block, 1, 0, middle, true, error, &fusion)) return false;
    return fusion.CheckAvailable(error);
}

bool FinishSnapshotProfileCheckpoint(const RandomAccessSource& source, AppleCheckpointView& cp,
    const ApfsFusionStore* fusion, std::vector<AppleSnapshotMetadataClaim>& claims,
    std::vector<ApplePhysicalExtentRecord>& payload, std::vector<CurrentOwner>& ledger,
    ProfileSnapshotCheckpointGraph& graph, std::optional<std::uint64_t>& bad_block,
    std::string& error)
{
    if (cp.volumes.empty() || cp.container_object_map.snapshot_tree_oid)
    { error = "VerifierSnapshotContainerMapHistoryUnsupported"; return false; }
    // Catalog claims already include the complete container OMAP walk, with
    // actual per-node identities. Do not replace them with root-owner aliases.
    if (fusion && !SnapshotProfileFusionCaches(source, *fusion, cp, ledger, error)) return false;
    if (!ChargeHistory(source, claims.size(), sizeof(CurrentOwner), error)) return false;
    std::optional<AppleSnapshotMetadataClaim> bad;
    if (!CheckSnapshotMetadataOwners(cp, claims, bad, error, fusion))
    { if (bad) bad_block = bad->physical_block; return false; }
    for (const auto& claim : claims)
    {
        const bool tree = claim.metadata_class != AppleSnapshotMetadataClass::VolumeSuperblock &&
            claim.metadata_class != AppleSnapshotMetadataClass::OmapObject;
        if (!AddCurrentOwner(source, cp, ledger, claim.physical_block, claim.block_count, claim.volume_oid,
            {claim.object_id, claim.object_xid, claim.physical_block, claim.type, claim.subtype,
                cp.container.superblock.block_size}, tree, error, fusion)) return false;
    }
    for (const auto& queue : cp.spaceman.free_queues)
        for (const auto block : queue.tree_blocks)
            if (!AddCurrentOwner(source, cp, ledger, block, 1, 0, queue.root, true, error, fusion)) return false;
    std::optional<std::uint64_t> bad_volume, bad_object;
    VerificationCode code = VerificationCode::StructuralInconsistency;
    if (!CheckCurrentOwners(source, cp, ledger, payload, bad_volume, bad_object, bad_block, code, error, fusion)) return false;
    const auto& nx = cp.container.superblock;
    graph.protected_graph.checkpoint_xid = nx.xid;
    for (const auto& owner : ledger)
        if (!OwnershipAppend(source, graph.protected_graph.metadata_ranges, owner.begin, owner.end - owner.begin, error)) return false;
    for (const auto& extent : payload)
    {
        if (SnapshotProfileReserved(cp, fusion, extent))
        { bad_block = extent.physical_block; error = "VerifierSnapshotProfilePayloadReservedCollision"; return false; }
        if (!OwnershipAppend(source, graph.protected_graph.payload_ranges, extent.physical_block, extent.block_count, error)) return false;
    }
    const auto limit = source.SizeBytes() / nx.block_size;
    return NormalizeProtectedRanges(graph.protected_graph.metadata_ranges, limit, error) &&
        NormalizeProtectedRanges(graph.protected_graph.payload_ranges, limit, error);
}

bool SnapshotProfileRecoveryState(const RandomAccessSource& source, AppleCheckpointView&& checkpoint,
    const ProfileSnapshotCheckpointGraph& graph, std::vector<ApplePhysicalExtentRecord> payload,
    AppleRecoveryCheckpointView& state, std::string& error)
{
    state.checkpoint = std::move(checkpoint); state.payload_extents = std::move(payload);
    for (const auto& range : graph.protected_graph.metadata_ranges)
    {
        if (!ChargeHistory(source, range.block_count, sizeof(std::uint64_t), error)) return false;
        for (std::uint64_t i = 0; i < range.block_count; ++i) state.metadata_blocks.push_back(range.physical_block + i);
    }
    return true;
}

bool AppendResolvedSnapshotProfileView(const RandomAccessSource& source, const AppleCheckpointView& cp,
    const AppleVolumeCheckpointView& parent, const AppleVolumeCheckpointView& descriptor,
    const AppleSnapshotTreeRecords& trees, std::uint64_t xid, std::string_view name, bool current,
    const ApfsFusionStore* fusion, const std::vector<AppleSnapshotMetadataClaim>& claims,
    std::vector<ApplePhysicalExtentRecord>& prior,
    std::vector<ApplePhysicalExtentRecord>& historical, std::vector<ApplePhysicalExtentRecord>& payload,
    OwnershipRanges& peer, ProfileSnapshotCheckpointGraph& graph, std::string& error)
{
    for (const auto count : {prior.size(), historical.size(), trees.filesystem.size(), trees.extentref.size()})
        if (!ChargeHistory(source, count, 2048, error)) return false;
    std::vector<ApplePhysicalExtentRecord> resolved;
    if (!(fusion ? ResolveAppleFusionReadOnlySnapshotExtentLayer(*fusion, prior, historical, trees.filesystem,
                trees.extentref, resolved, error) :
            ResolveAppleEncryptedReadOnlySnapshotExtentLayer(prior, historical, trees.filesystem, trees.extentref,
                cp.container.superblock.block_size, cp.container.superblock.block_count, resolved, error)) ||
        !AppendSnapshotProfileView(source, cp, parent.superblock.object_id, descriptor, trees, xid, name,
            current, resolved, claims, graph, error) ||
        !ChargeHistory(source, resolved.size(), 2 * sizeof(ApplePhysicalExtentRecord), error)) return false;
    for (const auto& extent : resolved)
        if (!OwnershipAppend(source, peer, extent.physical_block, extent.block_count, error)) return false;
    payload.insert(payload.end(), resolved.begin(), resolved.end());
    historical.insert(historical.end(), resolved.begin(), resolved.end()); prior = std::move(resolved); return true;
}

bool CheckSnapshotProfileHistory(const RandomAccessSource& source,
    const std::vector<AppleRecoveryCheckpointView>& states, const std::vector<ProfileSnapshotCheckpointGraph>& graphs,
    bool fusion, const std::function<bool()>& allowed, std::string& error)
{
    OwnershipRanges metadata, payload;
    for (const auto& graph : graphs)
    {
        for (const auto& range : graph.protected_graph.metadata_ranges)
            if (!OwnershipAppend(source, metadata, range.physical_block, range.block_count, error)) return false;
        for (const auto& range : graph.protected_graph.payload_ranges)
            if (!OwnershipAppend(source, payload, range.physical_block, range.block_count, error)) return false;
    }
    const auto limit = source.SizeBytes() / states.back().checkpoint.container.superblock.block_size;
    if (!NormalizeProtectedRanges(metadata, limit, error) || !NormalizeProtectedRanges(payload, limit, error)) return false;
    std::size_t mi = 0, pi = 0;
    while (mi < metadata.size() && pi < payload.size())
    {
        if (!allowed() || !ChargeHistory(source, 1, 0, error)) return false;
        const auto& m = metadata[mi]; const auto& p = payload[pi];
        if (m.physical_block < p.physical_block + p.block_count && p.physical_block < m.physical_block + m.block_count)
        { error = "VerifierSnapshotHistoryPayloadMetadataConflict"; return false; }
        if (m.physical_block + m.block_count <= p.physical_block) ++mi; else ++pi;
    }
    for (const auto& state : states)
        if (!allowed() || !VerifyProfileRecoveryContinuity(source, state, states, states.back().checkpoint, fusion, error)) return false;
    return true;
}
}

ProfileSnapshotGraphReport VerifyFusionSnapshotProfile(const ApfsFusionStore& source,
    const VerificationScope& scope, const std::array<std::string, 2>& members,
    std::optional<std::uint64_t> from, const std::function<bool()>& deadline)
{
    ProfileSnapshotGraphReport out; out.endpoint_scope = scope; out.from_xid = from; out.read_budget = source.ReadBudget();
    const auto before = out.read_budget->Consumed();
    std::optional<std::uint64_t> bad_block, bad_xid;
    const auto fail = [&](std::string detail, VerificationCode code = VerificationCode::StructuralInconsistency, bool refused = false) {
        if (detail == "VerifierFusionHistoricalCacheGenerationUnavailable") code = VerificationCode::CheckpointUnavailable;
        if (code == VerificationCode::StructuralInconsistency) code = HistoryFailureCode(detail);
        if (code == VerificationCode::CryptoUnsupported && !Contains(detail, "Unsupported")) code = VerificationCode::StructuralInconsistency;
        refused = refused || code == VerificationCode::UnsupportedFeature || code == VerificationCode::CryptoUnsupported || code == VerificationCode::FusionUnsupported;
        if (out.read_budget->Failed()) { detail = out.read_budget->Failure(); code = VerificationCode::BudgetExceeded; refused = false; }
        out.selected.reset(); out.stores.clear(); out.chain_xids.clear(); out.checkpoints.clear(); out.allocation_unit_bytes = 0;
        out.outcome = refused ? VerificationOutcome::Refused : VerificationOutcome::Incomplete;
        out.findings.push_back({code, refused ? VerificationSeverity::Warning : VerificationSeverity::Error,
            VerificationCheck::SnapshotReachableAllocation, scope.exact.volume_oid, {}, bad_block, bad_xid, {}, std::move(detail)});
    };
    try
    {
        const auto run = [&] {
            const auto& bound = source.Checkpoint().superblock; const auto& exact = scope.exact;
            if (!deadline || scope.source_identity.empty() || scope.source_identity.size() > 1024 ||
                !UuidValid(exact.container_uuid_hex) || !UuidValid(exact.volume_uuid_hex) || !exact.volume_oid || !exact.checkpoint_xid ||
                scope.require_whole_volume || scope.require_payload_content_hashes || scope.observe_payload_content ||
                scope.account_retained_ownership || scope.retained_from_xid ||
                !scope.max_reads || !scope.max_read_bytes || !scope.max_records || !scope.max_record_bytes ||
                (from && (!*from || *from >= exact.checkpoint_xid)))
            { fail("VerifierSnapshotProfileScopeInvalid", VerificationCode::InvalidScope, true); return; }
            out.read_budget->LimitRemainingTo(scope.max_reads, scope.max_read_bytes, scope.max_records, scope.max_record_bytes);
            VerificationSource bounded(source, scope, deadline); SnapshotPlanningSource observed(bounded);
            const auto allowed = [&] { return bounded.WithinDeadline(); };
            std::string error;
            const auto& main = source.Binding(FusionMemberRole::Main);
            if (!source.CheckAvailable(error) || exact.container_uuid_hex != bound.uuid_hex || exact.checkpoint_xid != bound.xid ||
                exact.store_offset_bytes != main.store_offset || exact.store_size_bytes != main.store_size ||
                members[0] != source.Members()[0].stable_store_id || members[1] != source.Members()[1].stable_store_id)
            { fail(error.empty() ? "VerifierSnapshotProfileBindingMismatch" : error, VerificationCode::IdentityMismatch, true); return; }
            std::vector<std::uint64_t> xids;
            if (from)
            {
                if (!EnumerateRetainedDescriptorXids(observed, bound, allowed, xids, bad_block, bad_xid, error)) { fail(error); return; }
                const auto first = std::lower_bound(xids.begin(), xids.end(), *from);
                if (first == xids.end() || *first != *from) { fail("VerifierHistoryChainUnavailable", VerificationCode::CheckpointUnavailable); return; }
                xids.erase(xids.begin(), first);
            }
            else xids.push_back(bound.xid);
            std::vector<AppleRecoveryCheckpointView> states;
            std::vector<ProfileSnapshotCheckpointGraph> graphs;
            std::optional<VerifiedCheckpointIdentity> selected;
            for (std::size_t ci = 0; ci < xids.size(); ++ci)
            {
                bad_xid = xids[ci]; bad_block.reset();
                if (!allowed()) { fail(out.read_budget->Failure()); return; }
                auto container = LoadContainerCheckpointView(observed, 0, source.CapacityBytes(), error, xids[ci]);
                if (!container) { fail(error); return; }
                auto read = LoadAppleReadOnlyVolumeView(observed, *container, error);
                if (!read) { fail(error); return; }
                AppleCheckpointView cp; cp.container = std::move(read->container);
                cp.container_object_map = std::move(read->container_object_map); cp.volumes = std::move(read->volumes);
                if ((ci + 1 < xids.size() && cp.container.superblock.next_xid != xids[ci + 1]) ||
                    !(ci + 1 == xids.size() ? LoadFusionSpacemanAllocationView(source, cp.spaceman, error) :
                        LoadFusionPlanningAllocation(source, observed, cp.container, cp.spaceman, error)))
                { fail(error.empty() ? "VerifierHistoryChainUnavailable" : error); return; }
                const auto chosen = std::find_if(cp.volumes.begin(), cp.volumes.end(), [&](const auto& v) {
                    return v.superblock.object_id == exact.volume_oid && v.superblock.uuid_hex == exact.volume_uuid_hex;
                });
                if (chosen == cp.volumes.end()) { fail("VerifierSnapshotSelectedVolumeMissing", VerificationCode::IdentityMismatch); return; }
                if (ci + 1 == xids.size()) selected = VerifiedCheckpointIdentity{exact, cp.container.superblock_physical_block,
                    chosen->superblock_object.physical_block, chosen->superblock.xid, chosen->root_tree.object_id, chosen->root_tree.physical_block};
                ProfileSnapshotCheckpointGraph graph;
                std::vector<AppleSnapshotMetadataClaim> claims;
                std::vector<ApplePhysicalExtentRecord> payload;
                std::vector<std::pair<std::uint64_t, OwnershipRanges>> peers;
                for (const auto& volume : cp.volumes)
                {
                    SnapshotCatalogScope catalog;
                    if (!LoadAppleFusionReadOnlySnapshotCatalog(source, xids[ci], volume.superblock.object_id,
                        volume.superblock.uuid_hex, catalog.records, catalog.owners, error)) { fail(error); return; }
                    if (catalog.records.snapshots.size() != catalog.records.inventory.size()) { fail("VerifierSnapshotCatalogCountMismatch"); return; }
                    if (!ChargeHistory(observed, catalog.owners.size(), sizeof(AppleSnapshotMetadataClaim), error)) { fail(error); return; }
                    claims.insert(claims.end(), catalog.owners.begin(), catalog.owners.end());
                    std::vector<ApplePhysicalExtentRecord> prior, historical;
                    OwnershipRanges peer;
                    const auto view = [&](const AppleVolumeCheckpointView& descriptor, const AppleSnapshotTreeRecords& trees,
                        std::uint64_t xid, std::string_view name, bool current) {
                        if (!allowed() || !ApfsFusionReadSession::ValidatePlanningRecords(source, cp.container.superblock,
                            descriptor.superblock, trees.filesystem, error)) return false;
                        return AppendResolvedSnapshotProfileView(observed, cp, volume, descriptor, trees, xid, name, current,
                            &source, catalog.owners, prior, historical, payload, peer, graph, error);
                    };
                    for (std::size_t si = 0; si < catalog.records.snapshots.size(); ++si)
                        if (!view(catalog.records.inventory[si].volume, catalog.records.snapshots[si], catalog.records.inventory[si].xid,
                            catalog.records.inventory[si].name_utf8, false)) { fail(error, VerificationCode::ExtentReferenceInconsistent); return; }
                    if (!view(volume, catalog.records.live, cp.container.superblock.xid, {}, true) ||
                        !NormalizeProtectedRanges(peer, source.SizeBytes() / bound.block_size, error)) { fail(error); return; }
                    if (!ChargeHistory(observed, 1, sizeof(peers.front()), error)) { fail(error); return; }
                    peers.emplace_back(volume.superblock.object_id, std::move(peer));
                }
                if (!SnapshotProfilePeerDisjoint(observed, peers, error)) { fail(error, VerificationCode::CrossVolumePayloadOverlap); return; }
                std::vector<CurrentOwner> ledger;
                if (!FinishSnapshotProfileCheckpoint(observed, cp, &source, claims, payload, ledger, graph, bad_block, error)) { fail(error); return; }
                AppleRecoveryCheckpointView state;
                if (!SnapshotProfileRecoveryState(observed, std::move(cp), graph, std::move(payload), state, error) ||
                    !ChargeHistory(observed, 1, sizeof(state) + sizeof(graph), error)) { fail(error); return; }
                states.push_back(std::move(state)); graphs.push_back(std::move(graph));
            }
            if (!CheckSnapshotProfileHistory(observed, states, graphs, true, allowed, error))
            { fail(error.empty() ? out.read_budget->Failure() : error); return; }
            if (!observed.VerifyUnchanged(error) || !source.CheckAvailable(error) || !allowed()) { fail(error); return; }
            for (const auto role : {FusionMemberRole::Main, FusionMemberRole::Tier2}) {
                const auto& member = source.Binding(role); out.stores.push_back({member.stable_store_id, member.store_offset, member.store_size});
            }
            out.selected = std::move(selected); out.chain_xids = std::move(xids); out.checkpoints = std::move(graphs);
            out.allocation_unit_bytes = bound.block_size; out.outcome = VerificationOutcome::Complete;
        };
        run();
    }
    catch (const std::bad_alloc&) { (void)out.read_budget->Refuse("VerifierSnapshotProfileAllocationFailed"); fail(out.read_budget->Failure()); }
    catch (...) { fail("VerifierSnapshotProfileReadFailure", VerificationCode::ReadFailure); }
    const auto after = out.read_budget->Consumed();
    out.source_reads = after.reads - before.reads; out.source_read_bytes = after.read_bytes - before.read_bytes;
    return out;
}

ProfileSnapshotGraphReport VerifyEncryptedSnapshotProfile(const ApfsVerifierEncryptedSource& source,
    ApfsEncryptedReadSession& session, const VerificationScope& scope, std::optional<std::uint64_t> from,
    const std::function<bool()>& deadline)
{
    ProfileSnapshotGraphReport out; out.profile = CurrentVerificationProfile::EncryptedOneKeyGenerationZero;
    out.endpoint_scope = scope; out.from_xid = from; out.read_budget = source.ReadBudget();
    const auto before = out.read_budget->Consumed();
    std::optional<std::uint64_t> bad_block, bad_xid;
    const auto fail = [&](std::string detail, VerificationCode code = VerificationCode::StructuralInconsistency, bool refused = false) {
        if (code == VerificationCode::StructuralInconsistency) code = HistoryFailureCode(detail);
        if (code == VerificationCode::CryptoUnsupported && !Contains(detail, "Unsupported")) code = VerificationCode::StructuralInconsistency;
        refused = refused || code == VerificationCode::UnsupportedFeature || code == VerificationCode::CryptoUnsupported;
        if (out.read_budget->Failed()) { code = VerificationCode::BudgetExceeded; detail = out.read_budget->Failure(); refused = false; }
        out.selected.reset(); out.stores.clear(); out.chain_xids.clear(); out.checkpoints.clear(); out.allocation_unit_bytes = 0;
        out.outcome = refused ? VerificationOutcome::Refused : VerificationOutcome::Incomplete;
        out.findings.push_back({code, refused ? VerificationSeverity::Warning : VerificationSeverity::Error,
            VerificationCheck::SnapshotReachableAllocation, scope.exact.volume_oid, {}, bad_block, bad_xid, {}, std::move(detail)});
    };
    try
    {
        const auto run = [&] {
            const auto& exact = scope.exact;
            if (!deadline || scope.source_identity.empty() || scope.source_identity.size() > 1024 ||
                !UuidValid(exact.container_uuid_hex) || !UuidValid(exact.volume_uuid_hex) || !exact.volume_oid || !exact.checkpoint_xid ||
                exact.store_offset_bytes || exact.store_size_bytes != source.SizeBytes() ||
                scope.require_whole_volume || scope.require_payload_content_hashes || scope.observe_payload_content ||
                scope.account_retained_ownership || scope.retained_from_xid ||
                !scope.max_reads || !scope.max_read_bytes || !scope.max_records || !scope.max_record_bytes ||
                (from && (!*from || *from >= exact.checkpoint_xid)))
            { fail("VerifierEncryptedSnapshotScopeInvalid", VerificationCode::InvalidScope, true); return; }
            if (scope.source_identity != source.SourceIdentity())
            { fail("VerifierEncryptedSnapshotSourceMismatch", VerificationCode::IdentityMismatch, true); return; }
            out.read_budget->LimitRemainingTo(scope.max_reads, scope.max_read_bytes, scope.max_records, scope.max_record_bytes);
            const auto allowed = [&] {
                if (!source.CheckDeadline()) return false;
                try { if (deadline()) return true; }
                catch (...) { return out.read_budget->Refuse("VerifierEncryptedSnapshotDeadlineCallbackFailed"); }
                return out.read_budget->Refuse("VerifierEncryptedSnapshotDeadlineExceeded");
            };
            SnapshotPlanningSource observed(source);
            std::string error;
            auto latest = LoadContainerCheckpointView(observed, 0, source.SizeBytes(), error, exact.checkpoint_xid);
            if (!latest) { fail(error); return; }
            if (latest->superblock.uuid_hex != exact.container_uuid_hex)
            { fail("VerifierEncryptedSnapshotContainerMismatch", VerificationCode::IdentityMismatch, true); return; }
            std::vector<std::uint64_t> xids;
            if (from)
            {
                if (!EnumerateRetainedDescriptorXids(observed, latest->superblock, allowed, xids, bad_block, bad_xid, error)) { fail(error); return; }
                const auto first = std::lower_bound(xids.begin(), xids.end(), *from);
                if (first == xids.end() || *first != *from) { fail("VerifierHistoryChainUnavailable", VerificationCode::CheckpointUnavailable); return; }
                xids.erase(xids.begin(), first);
            }
            else xids.push_back(exact.checkpoint_xid);
            std::vector<AppleRecoveryCheckpointView> states;
            SnapshotHistoryTextScope clear_states{states};
            std::vector<ProfileSnapshotCheckpointGraph> graphs;
            std::optional<VerifiedCheckpointIdentity> selected;
            for (std::size_t ci = 0; ci < xids.size(); ++ci)
            {
                bad_xid = xids[ci]; bad_block.reset();
                if (!allowed()) { fail(out.read_budget->Failure()); return; }
                std::unique_ptr<AppleEncryptedSnapshotReadContext> context;
                if (ci + 1 == xids.size())
                {
                    EncryptedReadError status;
                    auto parent = session.CreateMetadataReadContext(status);
                    if (parent) context = session.CreateSnapshotVerificationContext(*parent, error);
                    else error = "VerifierEncryptedSnapshotCurrentContextUnavailable:" + std::to_string(static_cast<unsigned>(status));
                }
                else context = session.CreateRetainedSnapshotVerificationContext(xids[ci], error);
                if (!context) { fail(error.empty() ? "VerifierEncryptedSnapshotContextUnavailable" : error); return; }
                AppleCheckpointView cp; SnapshotCatalogScope catalog;
                SnapshotParentTextScope clear_parent{cp};
                if (!LoadAppleEncryptedSnapshotCatalog(source, *context, cp, catalog.records, catalog.owners, error)) { fail(error); return; }
                const auto& nx = cp.container.superblock;
                if (nx.xid != xids[ci] || nx.uuid_hex != exact.container_uuid_hex || cp.volumes.size() != 1 ||
                    cp.volumes.front().superblock.object_id != exact.volume_oid || cp.volumes.front().superblock.uuid_hex != exact.volume_uuid_hex ||
                    (ci + 1 < xids.size() && nx.next_xid != xids[ci + 1]) ||
                    (ci + 1 == xids.size() && cp.container.superblock_bytes != latest->superblock_bytes))
                { fail("VerifierEncryptedSnapshotSelectionMismatch", VerificationCode::IdentityMismatch); return; }
                if (!LoadAppleSpacemanOwnershipView(observed, cp.container, cp.spaceman, error)) { fail(error); return; }
                const auto& volume = cp.volumes.front();
                if (ci + 1 == xids.size()) selected = VerifiedCheckpointIdentity{exact, cp.container.superblock_physical_block,
                    volume.superblock_object.physical_block, volume.superblock.xid, volume.root_tree.object_id, volume.root_tree.physical_block};
                if (catalog.records.snapshots.size() != catalog.records.inventory.size()) { fail("VerifierSnapshotCatalogCountMismatch"); return; }
                ProfileSnapshotCheckpointGraph graph;
                std::vector<ApplePhysicalExtentRecord> prior, historical, payload;
                OwnershipRanges peer;
                for (std::size_t si = 0; si < catalog.records.snapshots.size(); ++si)
                {
                    const auto& descriptor = catalog.records.inventory[si];
                    EncryptedNamespaceInfo info;
                    if (!allowed() || session.ValidateSnapshotNamespace(*context, descriptor.xid, info, error) != EncryptedReadError::None ||
                        !AppendResolvedSnapshotProfileView(observed, cp, volume, descriptor.volume, catalog.records.snapshots[si],
                            descriptor.xid, descriptor.name_utf8, false, nullptr, catalog.owners,
                            prior, historical, payload, peer, graph, error))
                    { fail(error); return; }
                }
                EncryptedNamespaceInfo info;
                if (session.ValidateSnapshotParentNamespace(*context, info, error) != EncryptedReadError::None ||
                    !AppendResolvedSnapshotProfileView(observed, cp, volume, volume, catalog.records.live, nx.xid, {}, true,
                        nullptr, catalog.owners, prior, historical, payload, peer, graph, error)) { fail(error); return; }
                std::vector<CurrentOwner> ledger;
                if (!FinishSnapshotProfileCheckpoint(observed, cp, nullptr, catalog.owners, payload, ledger, graph, bad_block, error)) { fail(error); return; }
                UnlockError bag_error; std::uint64_t container_bag = 0, volume_bag = 0;
                auto bags = InspectPasswordKeybagMetadataAtCheckpoint(source, exact.volume_oid, KeybagLength::IncludesHeader,
                    nx.xid, bag_error, container_bag, volume_bag);
                if (!bags || bags->selection.checkpoint_xid != nx.xid || bags->selection.volume_oid != exact.volume_oid || container_bag == volume_bag)
                { fail("VerifierEncryptedSnapshotKeybagMetadataInvalid"); return; }
                for (const auto block : {container_bag, volume_bag})
                {
                    for (const auto& owner : ledger)
                    {
                        if (!ChargeHistory(observed, 1, 0, error)) { fail(error); return; }
                        if (block >= owner.begin && block < owner.end)
                        { bad_block = block; fail("VerifierEncryptedSnapshotKeybagMetadataAlias", VerificationCode::MetadataOwnerConflict); return; }
                    }
                    if (!OwnershipAppend(observed, graph.protected_graph.metadata_ranges, block, 1, error)) { fail(error); return; }
                }
                if (!NormalizeProtectedRanges(graph.protected_graph.metadata_ranges, nx.block_count, error)) { fail(error); return; }
                AppleRecoveryCheckpointView state;
                SnapshotParentTextScope clear_state{state.checkpoint};
                if (!SnapshotProfileRecoveryState(observed, std::move(cp), graph, std::move(payload), state, error) ||
                    !ChargeHistory(observed, 1, sizeof(state) + sizeof(graph), error)) { fail(error); return; }
                states.push_back(std::move(state)); graphs.push_back(std::move(graph));
            }
            if (!CheckSnapshotProfileHistory(observed, states, graphs, false, allowed, error) ||
                !observed.VerifyUnchanged(error) || !allowed()) { fail(error.empty() ? out.read_budget->Failure() : error); return; }
            out.selected = std::move(selected); out.stores.push_back({scope.source_identity, 0, source.SizeBytes()});
            out.chain_xids = std::move(xids); out.checkpoints = std::move(graphs);
            out.allocation_unit_bytes = latest->superblock.block_size; out.outcome = VerificationOutcome::Complete;
        };
        run();
    }
    catch (const std::bad_alloc&) { (void)out.read_budget->Refuse("VerifierEncryptedSnapshotAllocationFailed"); fail(out.read_budget->Failure()); }
    catch (...) { fail("VerifierEncryptedSnapshotReadFailure", VerificationCode::ReadFailure); }
    const auto after = out.read_budget->Consumed();
    out.source_reads = after.reads - before.reads; out.source_read_bytes = after.read_bytes - before.read_bytes;
    return out;
}
