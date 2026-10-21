namespace
{
void ValidateSnapshotAllocationCounters(const ApfsSnapshotAllocationCounters& result,
    const VerificationScope& scope, std::string_view path, const Writer& guard)
{
    if (result.source_identity != scope.source_identity || result.scope != scope.exact)
        throw Stop{payload::Reason::InvalidBinding};
    const auto uuid = [](const auto& value) {
        return value.size() == 32 && value.find_first_not_of("0123456789abcdef") == std::string::npos &&
            value.find_first_not_of('0') != std::string::npos;
    };
    const auto& exact = scope.exact;
    const std::uint64_t bs = result.allocation_unit_bytes;
    RequireAccounting(AttributionTextValid(path) && AttributionTextValid(result.source_identity) &&
        scope.source_identity.size() <= 1024 && uuid(exact.container_uuid_hex) && uuid(exact.volume_uuid_hex) &&
        exact.volume_oid && exact.checkpoint_xid && bs >= 4096 && bs <= 65536 && !(bs & (bs - 1)) &&
        exact.store_size_bytes && exact.store_size_bytes % bs == 0 && exact.store_offset_bytes % bs == 0 &&
        exact.store_offset_bytes <= UINT64_MAX - exact.store_size_bytes &&
        scope.max_reads && scope.max_read_bytes && scope.max_records && scope.max_record_bytes &&
        !scope.require_whole_volume && !scope.require_payload_content_hashes && !scope.observe_payload_content &&
        !scope.account_retained_ownership && !scope.retained_from_xid &&
        !result.snapshot_allocation_charge && !result.apple_purgeable && !result.reclaimable &&
        result.read_budget->Consumed().reads && result.snapshots.size() <= scope.max_records);
    if (result.snapshots.size() > guard.cap / 160) throw Stop{payload::Reason::OutputLimit};
    if (!result.read_budget->Materialize(result.snapshots.size(), result.snapshots.size() * 128ull))
        throw Stop{payload::Reason::SharedBudget};
    std::unordered_set<std::string_view> names;
    const auto capacity = exact.store_size_bytes / bs;
    std::uint64_t previous = 0;
    for (const auto& row : result.snapshots)
    {
        guard.Check(); const auto& descriptor = row.descriptor; const auto& amount = row.declared_filesystem_allocation;
        RequireAccounting(row.snapshot_xid > previous && row.snapshot_xid <= exact.checkpoint_xid &&
            AttributionTextValid(row.name_utf8) && names.insert(row.name_utf8).second &&
            descriptor.object_id && descriptor.object_id == descriptor.physical_block && descriptor.physical_block < capacity &&
            descriptor.xid >= row.snapshot_xid &&
            descriptor.xid <= exact.checkpoint_xid && descriptor.type == (kObjectPhysical | kObjectTypeFs) &&
            !descriptor.subtype && descriptor.size_bytes == bs && amount.blocks <= capacity && amount.bytes == amount.blocks * bs);
        previous = row.snapshot_xid;
    }
}

void EmitSnapshotAllocationCounters(Writer& writer, const ApfsSnapshotAllocationCounters& result, std::string_view path)
{
    writer.Text("{\"format\":\"apfs-access-snapshot-allocation-counters\",\"version\":");
    writer.Number(SnapshotAllocationCountersVersion, false);
    writer.Text(",\"readOnly\":true,\"complete\":true,\"source\":{\"path\":"); writer.String(path);
    writer.Text(",\"identity\":"); writer.String(result.source_identity);
    writer.Text("},\"scope\":{"); writer.Identity(result.scope);
    writer.Text("},\"allocationUnitBytes\":"); writer.Number(result.allocation_unit_bytes, false);
    writer.Text(",\"counterMeaning\":\"parsed-apfs-fs-alloc-count-at-descriptor-xid\",\"independentSnapshotChargeVerified\":false,\"snapshots\":[");
    bool first = true;
    for (const auto& row : result.snapshots)
    {
        if (!first) writer.Text(","); first = false;
        writer.Text("{\"snapshotXid\":"); writer.Number(row.snapshot_xid);
        writer.Text(",\"name\":"); writer.String(row.name_utf8);
        writer.Text(",\"descriptor\":{\"objectId\":"); writer.Number(row.descriptor.object_id);
        writer.Text(",\"xid\":"); writer.Number(row.descriptor.xid);
        writer.Text(",\"physicalBlock\":"); writer.Number(row.descriptor.physical_block);
        writer.Text("},\"declaredFilesystemAllocation\":"); AttributionAmount(writer, row.declared_filesystem_allocation);
        writer.Text("}");
    }
    writer.Text("],\"snapshotAllocationCharge\":null,\"applePurgeable\":null,\"reclaimable\":null}");
}
}

bool SerializeSnapshotAllocationCounters(const std::optional<ApfsSnapshotAllocationCounters>& result,
    const VerificationScope& expected_scope, std::string_view image_path,
    const std::function<bool()>& within_deadline, std::size_t max_output_bytes,
    std::string& output, payload::Reason& failure)
{
    output.clear(); failure = payload::Reason::None;
    if (!result || !result->complete) { failure = payload::Reason::AdmissionNotComplete; return false; }
    VerificationReport binding; binding.read_budget = result->read_budget;
    const auto cap = (std::min)(max_output_bytes, MaxImageVerificationJsonBytes);
    Writer count{binding, within_deadline, cap};
    try
    {
        count.Check(); ValidateSnapshotAllocationCounters(*result, expected_scope, image_path, count);
        EmitSnapshotAllocationCounters(count, *result, image_path);
        if (!result->read_budget->Materialize(1, count.size + 64)) throw Stop{payload::Reason::SharedBudget};
        output.reserve(count.size); Writer writer{binding, within_deadline, cap, 0, &output};
        EmitSnapshotAllocationCounters(writer, *result, image_path); writer.Check(); return true;
    }
    catch (const Stop& stop) { failure = stop.reason; }
    catch (const std::bad_alloc&) { failure = payload::Reason::AllocationFailure; }
    catch (const std::length_error&) { failure = payload::Reason::AllocationFailure; }
    catch (...) { failure = payload::Reason::CallbackFailure; }
    if (result->read_budget && (failure == payload::Reason::OutputLimit || failure == payload::Reason::AllocationFailure))
        result->read_budget->Refuse(failure == payload::Reason::OutputLimit ? "SnapshotCounterResponseLimit" : "SnapshotCounterResponseAllocationFailed");
    output.clear(); return false;
}
