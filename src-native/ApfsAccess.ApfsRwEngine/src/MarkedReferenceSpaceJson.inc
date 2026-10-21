namespace
{
void ValidateMarkedReferenceSpace(const ApfsMarkedReferenceSpaceObservation& result,
    const VerificationScope& scope, std::string_view path, const Writer& guard)
{
    const auto& r = result.records; const auto& exact = scope.exact;
    if (r.source_identity != scope.source_identity || r.scope != exact) throw Stop{payload::Reason::InvalidBinding};
    const auto uuid = [](const auto& value) { return value.size() == 32 &&
        value.find_first_not_of("0123456789abcdef") == std::string::npos && value.find_first_not_of('0') != std::string::npos; };
    const std::uint64_t bs = r.allocation_unit_bytes;
    RequireAccounting(result.namespace_and_directory7_references_verified &&
        result.catalog_metadata_and_payload_allocation_verified && AttributionTextValid(path) &&
        AttributionTextValid(r.source_identity) && r.source_identity.size() <= 1024 &&
        uuid(exact.container_uuid_hex) && uuid(exact.volume_uuid_hex) && exact.volume_oid && exact.checkpoint_xid &&
        bs >= 4096 && bs <= 65536 && !(bs & (bs - 1)) && exact.store_size_bytes &&
        exact.store_size_bytes % bs == 0 && exact.store_offset_bytes % bs == 0 &&
        exact.store_offset_bytes <= UINT64_MAX - exact.store_size_bytes &&
        !scope.require_whole_volume && !scope.require_payload_content_hashes && !scope.observe_payload_content &&
        !scope.account_retained_ownership && !scope.retained_from_xid &&
        scope.max_reads && scope.max_read_bytes && scope.max_records && scope.max_record_bytes &&
        r.read_budget->Consumed().reads && !r.apple_purgeable && !r.reclaimable && !r.snapshot_allocation_charge &&
        !r.views.empty() && r.views.size() <= scope.max_records && r.views.size() == result.marked_file_payload.size());
    if (r.views.size() > guard.cap / 200) throw Stop{payload::Reason::OutputLimit};
    const auto capacity = exact.store_size_bytes / bs;
    const auto amount = [&](const ApfsSpaceAmount& a) { RequireAccounting(a.blocks <= capacity && a.bytes == a.blocks * bs); };
    amount(r.referenced_physical_union); amount(result.marked_file_payload_union);
    std::uint64_t previous = 0, literal_max = 0, literal_sum = 0;
    std::unordered_set<std::string_view> names;
    std::vector<VerificationBlockRange> all;
    if (!r.read_budget->Materialize(r.views.size(), r.views.size() * 128ull)) throw Stop{payload::Reason::SharedBudget};
    for (std::size_t i = 0; i < r.views.size(); ++i)
    {
        guard.Check(); const auto& row = r.views[i]; const auto& full = result.marked_file_payload[i];
        const bool current = i + 1 == r.views.size();
        RequireAccounting(row.current == current && row.view_xid && row.view_xid <= exact.checkpoint_xid &&
            (current ? row.view_xid == exact.checkpoint_xid && row.snapshot_name_utf8.empty() :
                row.view_xid > previous && AttributionTextValid(row.snapshot_name_utf8) && names.insert(row.snapshot_name_utf8).second) &&
            row.marked_regular_inode_count <= scope.max_records &&
            row.want_only_regular_inode_count <= scope.max_records - row.marked_regular_inode_count);
        previous = row.view_xid; amount(row.referenced_physical); amount(full.referenced_physical);
        RequireAccounting(row.referenced_physical.blocks <= full.referenced_physical.blocks &&
            (row.marked_regular_inode_count || !full.referenced_physical.blocks) &&
            AccountingRanges(full.ranges, capacity, guard) == full.referenced_physical.blocks &&
            full.ranges.size() <= scope.max_records - all.size());
        if (!r.read_budget->Materialize(full.ranges.size(), full.ranges.size() * sizeof(VerificationBlockRange) * 2))
            throw Stop{payload::Reason::SharedBudget};
        all.insert(all.end(), full.ranges.begin(), full.ranges.end());
        literal_max = (std::max)(literal_max, row.referenced_physical.blocks);
        literal_sum += (std::min)(row.referenced_physical.blocks, capacity - literal_sum);
    }
    std::sort(all.begin(), all.end(), [](const auto& a, const auto& b) { return a.physical_block < b.physical_block; });
    std::uint64_t begin = 0, end = 0, blocks = 0;
    for (const auto& range : all)
    {
        guard.Check(); const auto next_end = range.physical_block + range.block_count;
        if (range.physical_block > end) { blocks += end - begin; begin = range.physical_block; }
        end = (std::max)(end, next_end);
    }
    blocks += end - begin;
    RequireAccounting(result.marked_file_payload_union.blocks == blocks &&
        r.referenced_physical_union.blocks >= literal_max && r.referenced_physical_union.blocks <= literal_sum &&
        r.referenced_physical_union.blocks <= blocks);
}

void EmitMarkedReferenceSpace(Writer& w, const ApfsMarkedReferenceSpaceObservation& result, std::string_view path)
{
    const auto& r = result.records;
    w.Text("{\"format\":\"apfs-access-marked-reference-space\",\"version\":"); w.Number(MarkedReferenceSpaceVersion, false);
    w.Text(",\"readOnly\":true,\"complete\":true,\"source\":{\"path\":"); w.String(path);
    w.Text(",\"identity\":"); w.String(r.source_identity); w.Text("},\"scope\":{"); w.Identity(r.scope);
    w.Text("},\"allocationUnitBytes\":"); w.Number(r.allocation_unit_bytes, false);
    w.Text(",\"namespaceAndDirectory7ReferencesVerified\":true,\"catalogMetadataAndPayloadAllocationVerified\":true,"
        "\"hiddenOwnersComplete\":false,\"retainedCheckpointHistoryVerified\":false,"
        "\"recordMeaning\":\"literal-is-purgeable-private-stream-file-extent-union\","
        "\"filePayloadMeaning\":\"literal-is-purgeable-file-and-external-attribute-physical-union\",\"literalRecordUnion\":");
    AttributionAmount(w, r.referenced_physical_union); w.Text(",\"filePayloadUnion\":"); AttributionAmount(w, result.marked_file_payload_union);
    w.Text(",\"views\":[");
    for (std::size_t i = 0; i < r.views.size(); ++i)
    {
        if (i) w.Text(","); const auto& row = r.views[i]; const auto& full = result.marked_file_payload[i];
        w.Text("{\"viewXid\":"); w.Number(row.view_xid); w.Text(",\"current\":"); w.Bool(row.current);
        w.Text(",\"name\":"); w.String(row.snapshot_name_utf8); w.Text(",\"markedRegularInodes\":"); w.Number(row.marked_regular_inode_count);
        w.Text(",\"wantOnlyRegularInodes\":"); w.Number(row.want_only_regular_inode_count);
        w.Text(",\"literalRecordPayload\":"); AttributionAmount(w, row.referenced_physical);
        w.Text(",\"filePayload\":"); AttributionAmount(w, full.referenced_physical);
        w.Text(",\"filePayloadRanges\":"); w.Ranges(full.ranges); w.Text("}");
    }
    w.Text("],\"snapshotAllocationChargeBytes\":null,\"applePurgeableBytes\":null,\"reclaimableBytes\":null}");
}
}

bool SerializeMarkedReferenceSpace(const std::optional<ApfsMarkedReferenceSpaceObservation>& result,
    const VerificationScope& expected_scope, std::string_view image_path,
    const std::function<bool()>& within_deadline, std::size_t max_output_bytes,
    std::string& output, payload::Reason& failure)
{
    output.clear(); failure = payload::Reason::None;
    if (!result || !result->records.complete) { failure = payload::Reason::AdmissionNotComplete; return false; }
    const auto budget = result->records.read_budget;
    VerificationReport binding; binding.read_budget = budget; binding.requested_scope = expected_scope;
    const auto cap = (std::min)(max_output_bytes, MaxImageVerificationJsonBytes);
    Writer count{binding, within_deadline, cap};
    try
    {
        count.Check(); ValidateMarkedReferenceSpace(*result, expected_scope, image_path, count);
        EmitMarkedReferenceSpace(count, *result, image_path);
        if (!budget->Materialize(1, count.size + 64)) throw Stop{payload::Reason::SharedBudget};
        output.reserve(count.size); Writer writer{binding, within_deadline, cap, 0, &output};
        EmitMarkedReferenceSpace(writer, *result, image_path); writer.Check(); return true;
    }
    catch (const Stop& stop) { failure = stop.reason; }
    catch (const std::bad_alloc&) { failure = payload::Reason::AllocationFailure; }
    catch (const std::length_error&) { failure = payload::Reason::AllocationFailure; }
    catch (...) { failure = payload::Reason::CallbackFailure; }
    if (budget && (failure == payload::Reason::OutputLimit || failure == payload::Reason::AllocationFailure))
        budget->Refuse(failure == payload::Reason::OutputLimit ? "MarkedReferenceResponseLimit" : "MarkedReferenceResponseAllocationFailed");
    output.clear(); return false;
}
