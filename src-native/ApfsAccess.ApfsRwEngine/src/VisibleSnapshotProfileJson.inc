namespace
{
void ValidateVisibleSnapshotProfile(const ProfileSnapshotGraphReport& r, CurrentVerificationProfile profile,
    const VerificationScope& scope, std::optional<std::uint64_t> from,
    std::span<const VerificationStoreBinding> stores, std::span<const std::string> labels, const Writer& guard)
{
    if (r.profile != profile || !ProfileScopeEqual(r.endpoint_scope, scope) || r.from_xid != from)
        throw Stop{payload::Reason::InvalidBinding};
    const bool fusion = profile == CurrentVerificationProfile::FusionCleanCache;
    const bool complete = r.outcome == VerificationOutcome::Complete;
    const auto uuid = [](const auto& text) { return text.size() == 32 &&
        text.find_first_not_of("0123456789abcdef") == std::string::npos && text.find_first_not_of('0') != std::string::npos; };
    RequireAccounting((fusion || profile == CurrentVerificationProfile::EncryptedOneKeyGenerationZero) &&
        stores.size() == (fusion ? 2 : 1) && labels.size() == stores.size() &&
        AttributionTextValid(scope.source_identity) && scope.source_identity.size() <= 1024 &&
        uuid(scope.exact.container_uuid_hex) && uuid(scope.exact.volume_uuid_hex) && scope.exact.volume_oid && scope.exact.checkpoint_xid &&
        scope.max_reads && scope.max_read_bytes && scope.max_records && scope.max_record_bytes &&
        (!from || (*from && *from < scope.exact.checkpoint_xid)) &&
        r.source_reads <= scope.max_reads && r.source_read_bytes <= scope.max_read_bytes &&
        !r.snapshot_allocation_charge_bytes && !r.apple_purgeable_bytes && !r.reclaimable_bytes &&
        (complete || r.outcome == VerificationOutcome::Incomplete || r.outcome == VerificationOutcome::Refused) &&
        complete == r.findings.empty() && r.findings.size() <= scope.max_records);
    for (std::size_t i = 0; i < stores.size(); ++i) {
        guard.Check(); const auto& s = stores[i];
        RequireAccounting(AttributionTextValid(labels[i]) && AttributionTextValid(s.store_id) && s.store_id.size() <= 1024 &&
            s.size_bytes && !(s.offset_bytes % 4096) && !(s.size_bytes % 4096) && s.offset_bytes <= UINT64_MAX - s.size_bytes &&
            (!i || s.store_id != stores[0].store_id));
    }
    RequireAccounting(stores[0].offset_bytes == scope.exact.store_offset_bytes && stores[0].size_bytes == scope.exact.store_size_bytes &&
        (fusion || (!scope.exact.store_offset_bytes && stores[0].store_id == scope.source_identity)) &&
        (r.stores.empty() || r.stores.size() == stores.size()));
    for (std::size_t i = 0; i < r.stores.size(); ++i)
        if (r.stores[i].store_id != stores[i].store_id || r.stores[i].offset_bytes != stores[i].offset_bytes ||
            r.stores[i].size_bytes != stores[i].size_bytes) throw Stop{payload::Reason::InvalidBinding};
    for (const auto& finding : r.findings) {
        guard.Check(); RequireAccounting(static_cast<unsigned>(finding.code) >= 1 && static_cast<unsigned>(finding.code) <= 27 &&
            finding.check == VerificationCheck::SnapshotReachableAllocation && AttributionTextValid(finding.detail) &&
            finding.severity == (r.outcome == VerificationOutcome::Refused ? VerificationSeverity::Warning : VerificationSeverity::Error));
    }
    if (!complete) {
        RequireAccounting(!r.selected && r.stores.empty() && r.chain_xids.empty() && r.checkpoints.empty() && !r.allocation_unit_bytes);
        return;
    }
    RequireAccounting(!scope.require_whole_volume && !scope.require_payload_content_hashes && !scope.observe_payload_content &&
        !scope.account_retained_ownership && !scope.retained_from_xid &&
        r.selected && r.selected->exact == scope.exact && r.stores.size() == stores.size() &&
        r.source_reads && r.source_read_bytes && r.checkpoints.size() <= scope.max_records);
    const auto bs = r.allocation_unit_bytes;
    RequireAccounting(bs >= 4096 && bs <= 65536 && !(bs & (bs - 1)));
    const auto address = [&](std::uint64_t block) {
        if (block < stores[0].size_bytes / bs) return true;
        const auto tier = kFusionTier2ByteAddress / bs;
        return fusion && block >= tier && block - tier < stores[1].size_bytes / bs;
    };
    const auto& selected = *r.selected;
    RequireAccounting(selected.checkpoint_physical_block && selected.checkpoint_physical_block < stores[0].size_bytes / bs &&
        selected.volume_superblock_physical_block && address(selected.volume_superblock_physical_block) &&
        selected.root_oid && selected.root_physical_block && address(selected.root_physical_block) &&
        selected.volume_superblock_xid && selected.volume_superblock_xid <= scope.exact.checkpoint_xid);
    for (const auto& cp : r.checkpoints) for (const auto& view : cp.views) {
        guard.Check(); RequireAccounting(view.current ? view.name_utf8.empty() : AttributionTextValid(view.name_utf8));
        RequireAccounting(view.filesystem_record_count && view.filesystem_record_count <= scope.max_records);
    }
}

void EmitSnapshotDescriptor(Writer& w, const AppleObjectLocation& descriptor)
{
    w.Text("{\"objectId\":"); w.Number(descriptor.object_id); w.Text(",\"xid\":"); w.Number(descriptor.xid);
    w.Text(",\"physicalBlock\":"); w.Number(descriptor.physical_block); w.Text("}");
}
void EmitVisibleSnapshotProfile(Writer& w, const ProfileSnapshotGraphReport& r,
    const std::optional<ApfsProfileSnapshotSpaceAttribution>& attribution,
    std::span<const VerificationStoreBinding> stores, std::span<const std::string> labels)
{
    const bool fusion = r.profile == CurrentVerificationProfile::FusionCleanCache;
    w.Text("{\"format\":\"apfs-access-visible-snapshot-profile-verification\",\"version\":");
    w.Number(VisibleSnapshotProfileVerificationVersion, false); w.Text(",\"readOnly\":true,\"profile\":");
    w.String(fusion ? "fusion-clean-cache" : "encrypted-onekey-generation-zero");
    w.Text(",\"source\":{\"identity\":"); w.String(r.endpoint_scope.source_identity);
    w.Text(",\"coordinateSystem\":"); w.String(fusion ? "member-image-relative" : "container-relative"); w.Text(",\"stores\":[");
    for (std::size_t i = 0; i < stores.size(); ++i) {
        if (i) w.Text(","); w.Text("{\"role\":"); w.String(fusion ? (i ? "tier2" : "main") : "container");
        w.Text(",\"id\":"); w.String(stores[i].store_id); w.Text(",\"label\":"); w.String(labels[i]);
        w.Text(",\"offsetBytes\":"); w.Number(stores[i].offset_bytes); w.Text(",\"sizeBytes\":"); w.Number(stores[i].size_bytes); w.Text("}");
    }
    const auto& scope = r.endpoint_scope;
    w.Text("]},\"requestedScope\":{"); w.Identity(scope.exact);
    w.Text(",\"maxReads\":"); w.Number(scope.max_reads); w.Text(",\"maxReadBytes\":"); w.Number(scope.max_read_bytes);
    w.Text(",\"maxRecords\":"); w.Number(scope.max_records); w.Text(",\"maxRecordBytes\":"); w.Number(scope.max_record_bytes);
    w.Text(",\"requireWholeVolume\":"); w.Bool(scope.require_whole_volume);
    w.Text(",\"requirePayloadContentHashes\":"); w.Bool(scope.require_payload_content_hashes);
    w.Text(",\"observePayloadContent\":"); w.Bool(scope.observe_payload_content);
    w.Text(",\"accountRetainedOwnership\":"); w.Bool(scope.account_retained_ownership);
    w.Text(",\"retainedFromXid\":"); w.Optional(scope.retained_from_xid); w.Text("},\"fromXid\":");
    w.Optional(r.from_xid); w.Text(",\"selected\":"); if (r.selected) w.Selected(*r.selected); else w.Text("null");
    w.Text(",\"outcome\":"); w.Number(static_cast<unsigned>(r.outcome), false);
    w.Text(",\"outcomeName\":"); w.String(r.outcome == VerificationOutcome::Complete ? "Complete" : r.outcome == VerificationOutcome::Refused ? "Refused" : "Incomplete");
    w.Text(",\"wholeVolumeVerified\":false,\"retainedOwnershipComplete\":false,\"payloadContentHashesVerified\":false,\"visibleSnapshotNamespacesVerified\":");
    w.Text(attribution ? "true" : "null");
    w.Text(",\"sourceReads\":"); w.Number(r.source_reads); w.Text(",\"sourceReadBytes\":"); w.Number(r.source_read_bytes);
    w.Text(",\"graph\":");
    if (!attribution) w.Text("null");
    else {
        w.Text("{\"allocationUnitBytes\":"); w.Number(r.allocation_unit_bytes, false);
        w.Text(",\"snapshotOwnerScope\":\"canonical-visible-inventories-and-explicit-parents\",\"chainXids\":[");
        for (std::size_t i = 0; i < r.chain_xids.size(); ++i) { if (i) w.Text(","); w.Number(r.chain_xids[i]); }
        w.Text("],\"checkpoints\":[");
        for (std::size_t i = 0; i < r.checkpoints.size(); ++i) {
            if (i) w.Text(","); const auto& cp = r.checkpoints[i];
            w.Text("{\"checkpointXid\":"); w.Number(cp.protected_graph.checkpoint_xid);
            w.Text(",\"metadataRanges\":"); w.Ranges(cp.protected_graph.metadata_ranges);
            w.Text(",\"payloadRanges\":"); w.Ranges(cp.protected_graph.payload_ranges); w.Text(",\"views\":[");
            for (std::size_t j = 0; j < cp.views.size(); ++j) {
                if (j) w.Text(","); const auto& view = cp.views[j]; w.Text("{\"volumeOid\":"); w.Number(view.volume_oid);
                w.Text(",\"viewXid\":"); w.Number(view.view_xid); w.Text(",\"current\":"); w.Bool(view.current);
                w.Text(",\"name\":"); w.String(view.name_utf8); w.Text(",\"descriptor\":"); EmitSnapshotDescriptor(w, view.descriptor);
                w.Text(",\"declaredFilesystemAllocation\":"); AttributionAmount(w, view.declared_filesystem_allocation);
                w.Text(",\"filesystemRecordCount\":"); w.Number(view.filesystem_record_count);
                w.Text(",\"metadataRanges\":"); w.Ranges(view.metadata_ranges); w.Text(",\"payloadRanges\":"); w.Ranges(view.payload_ranges); w.Text("}");
            }
            w.Text("]}");
        }
        w.Text("]}");
    }
    w.Text(",\"attribution\":");
    if (!attribution) w.Text("null");
    else {
        const auto& amounts = *attribution;
        w.Text("{\"protectionScope\":\"explicit-checkpoint-chain-and-visible-peers\",\"hiddenOwnersComplete\":false,\"liveMetadata\":");
        AttributionAmount(w, amounts.live_metadata); w.Text(",\"livePayload\":"); AttributionAmount(w, amounts.live_payload);
        w.Text(",\"referencedSnapshotMetadata\":"); AttributionAmount(w, amounts.referenced_snapshot_metadata);
        w.Text(",\"referencedSnapshotPayload\":"); AttributionAmount(w, amounts.referenced_snapshot_payload); w.Text(",\"snapshots\":[");
        for (std::size_t i = 0; i < amounts.snapshots.size(); ++i) {
            if (i) w.Text(","); const auto& row = amounts.snapshots[i];
            w.Text("{\"snapshotXid\":"); w.Number(row.snapshot_xid); w.Text(",\"name\":"); w.String(row.name_utf8);
            w.Text(",\"descriptor\":"); EmitSnapshotDescriptor(w, row.descriptor);
            w.Text(",\"declaredFilesystemAllocation\":"); AttributionAmount(w, row.declared_filesystem_allocation);
            w.Text(",\"metadata\":"); AttributionMeasures(w, row.metadata); w.Text(",\"payload\":"); AttributionMeasures(w, row.payload); w.Text("}");
        }
        w.Text("]}");
    }
    w.Text(",\"counterMeaning\":\"parsed-apfs-fs-alloc-count-at-descriptor-xid\",\"independentSnapshotChargeVerified\":false,\"snapshotAllocationChargeBytes\":null,\"applePurgeableBytes\":null,\"reclaimableBytes\":null,\"findings\":[");
    for (std::size_t i = 0; i < r.findings.size(); ++i) {
        if (i) w.Text(","); const auto& f = r.findings[i]; w.Text("{\"code\":"); w.Number(static_cast<unsigned>(f.code), false);
        w.Text(",\"severity\":"); w.Number(static_cast<unsigned>(f.severity), false); w.Text(",\"check\":"); w.Number(static_cast<unsigned>(f.check), false);
        w.Text(",\"volumeOid\":"); w.Optional(f.volume_oid); w.Text(",\"objectId\":"); w.Optional(f.object_id);
        w.Text(",\"physicalBlock\":"); w.Optional(f.physical_block); w.Text(",\"checkpointXid\":"); w.Optional(f.checkpoint_xid);
        w.Text(",\"failedSourceOffsetBytes\":"); w.Optional(f.failed_source_offset_bytes); w.Text(",\"detail\":"); w.String(f.detail); w.Text("}");
    }
    w.Text("],\"coverage\":[{\"check\":20,\"implemented\":true,\"required\":true,\"state\":");
    w.Number(attribution ? 2 : r.outcome == VerificationOutcome::Refused ? 4 : 3, false);
    w.Text(",\"scopeDetail\":\"Canonical visible snapshot and parent namespaces, signed extent layers, metadata/payload allocation and explicit retained protection; no exhaustive hidden-owner/orphan or Apple policy proof\"}]}");
}
}

bool SerializeVisibleSnapshotProfileVerificationReport(const ProfileSnapshotGraphReport& report,
    CurrentVerificationProfile expected_profile, const VerificationScope& expected_scope,
    std::optional<std::uint64_t> expected_from_xid, std::span<const VerificationStoreBinding> expected_stores,
    std::span<const std::string> labels, const std::function<bool()>& deadline, std::size_t max_bytes,
    std::string& output, payload::Reason& failure)
{
    output.clear(); failure = payload::Reason::None;
    VerificationReport binding; binding.read_budget = report.read_budget;
    Writer count{binding, deadline, (std::min)(max_bytes, MaxImageVerificationJsonBytes)};
    try {
        count.Check(); ValidateVisibleSnapshotProfile(report, expected_profile, expected_scope, expected_from_xid, expected_stores, labels, count);
        std::optional<ApfsProfileSnapshotSpaceAttribution> attribution;
        if (report.outcome == VerificationOutcome::Complete) {
            std::string error;
            if (!TryAttributeVerifiedProfileSnapshotSpace(report, attribution, error, deadline))
                throw Stop{report.read_budget->Failed() ? payload::Reason::SharedBudget : payload::Reason::InvalidProjection};
        }
        EmitVisibleSnapshotProfile(count, report, attribution, expected_stores, labels);
        if (!report.read_budget->Materialize(1, count.size + 64)) throw Stop{payload::Reason::SharedBudget};
        output.reserve(count.size); Writer writer{binding, deadline, count.cap, 0, &output};
        EmitVisibleSnapshotProfile(writer, report, attribution, expected_stores, labels); writer.Check(); return true;
    }
    catch (const Stop& stop) { failure = stop.reason; }
    catch (const std::bad_alloc&) { failure = payload::Reason::AllocationFailure; }
    catch (const std::length_error&) { failure = payload::Reason::AllocationFailure; }
    catch (...) { failure = payload::Reason::CallbackFailure; }
    if (report.read_budget && (failure == payload::Reason::OutputLimit || failure == payload::Reason::AllocationFailure))
        (void)report.read_budget->Refuse("VisibleSnapshotProfileResponseLimitOrAllocation");
    output.clear(); return false;
}
