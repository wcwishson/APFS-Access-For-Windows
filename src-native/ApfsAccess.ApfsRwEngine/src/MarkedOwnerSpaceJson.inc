namespace
{
void EmitMarkedOwnerSpace(Writer& w, const ApfsMarkedOwnerSpaceAttribution& r, std::string_view path)
{
    w.Text("{\"format\":\"apfs-access-marked-owner-space-attribution\",\"version\":1,\"readOnly\":true,\"complete\":true,\"fromXid\":");
    w.Optional(r.from_xid); w.Text(",\"checkpointXids\":[");
    for (std::size_t i = 0; i < r.checkpoint_xids.size(); ++i) { if (i) w.Text(","); w.Number(r.checkpoint_xids[i]); }
    w.Text("],\"protectionScope\":\"explicit-retained-checkpoints-and-visible-peers\",\"hiddenOwnersComplete\":false,\"marked\":");
    EmitMarkedReferenceSpace(w, r.marked, path);
    w.Text(",\"visibleMetadataUnion\":"); AttributionAmount(w, r.visible_metadata_union);
    w.Text(",\"visiblePayloadUnion\":"); AttributionAmount(w, r.visible_payload_union);
    w.Text(",\"catalogMetadata\":"); AttributionAmount(w, r.catalog_metadata);
    w.Text(",\"catalogMetadataRanges\":"); w.Ranges(r.catalog_metadata_ranges);
    w.Text(",\"protectedMetadataRanges\":"); w.Ranges(r.protected_metadata);
    w.Text(",\"protectedPayloadRanges\":"); w.Ranges(r.protected_payload);
    w.Text(",\"views\":[");
    for (std::size_t i = 0; i < r.views.size(); ++i) {
        if (i) w.Text(","); const auto& view = r.views[i];
        w.Text("{\"metadataRanges\":"); w.Ranges(view.metadata_ranges);
        w.Text(",\"payloadRanges\":"); w.Ranges(view.payload_ranges);
        w.Text(",\"unmarkedPayloadRanges\":"); w.Ranges(view.unmarked_payload_ranges);
        w.Text(",\"metadata\":"); AttributionMeasures(w, view.metadata);
        w.Text(",\"markedPayload\":"); AttributionMeasures(w, view.marked_payload);
        w.Text(",\"sharedWithUnmarkedInView\":"); AttributionAmount(w, view.shared_with_unmarked_in_view); w.Text("}");
    }
    w.Text("],\"snapshotAllocationChargeBytes\":null,\"applePurgeableBytes\":null,\"reclaimableBytes\":null}");
}
}

bool SerializeMarkedOwnerSpaceAttribution(const std::optional<ApfsMarkedOwnerSpaceAttribution>& result,
    const VerificationScope& scope, std::optional<std::uint64_t> from, std::string_view path,
    const std::function<bool()>& deadline, std::size_t max_bytes, std::string& output, payload::Reason& failure)
{
    output.clear(); failure = payload::Reason::None;
    if (!result || !result->marked.records.complete || !result->explicit_owner_graphs_verified)
    { failure = payload::Reason::AdmissionNotComplete; return false; }
    VerificationReport binding; binding.read_budget = result->marked.records.read_budget; binding.requested_scope = scope;
    const auto cap = (std::min)(max_bytes, MaxImageVerificationJsonBytes); Writer count{binding, deadline, cap};
    try {
        count.Check(); ValidateMarkedReferenceSpace(result->marked, scope, path, count);
        if (result->from_xid != from) throw Stop{payload::Reason::InvalidBinding};
        RequireAccounting(result->views.size() == result->marked.records.views.size() && !result->checkpoint_xids.empty() &&
            result->checkpoint_xids.size() <= scope.max_records && result->checkpoint_xids.back() == scope.exact.checkpoint_xid &&
            (from ? (*from && *from < scope.exact.checkpoint_xid && result->checkpoint_xids.size() > 1 && result->checkpoint_xids.front() == *from) : result->checkpoint_xids.size() == 1));
        std::uint64_t previous = 0;
        for (const auto xid : result->checkpoint_xids) { count.Check(); RequireAccounting(xid > previous); previous = xid; }
        std::string error;
        RequireAccounting(ValidateAppleMarkedOwnerSpaceAmounts(*result, deadline, error));
        EmitMarkedOwnerSpace(count, *result, path);
        if (!binding.read_budget->Materialize(1, count.size + 64)) throw Stop{payload::Reason::SharedBudget};
        output.reserve(count.size); Writer writer{binding, deadline, cap, 0, &output};
        EmitMarkedOwnerSpace(writer, *result, path); writer.Check(); return true;
    } catch (const Stop& stop) { failure = stop.reason; }
      catch (const std::bad_alloc&) { failure = payload::Reason::AllocationFailure; }
      catch (const std::length_error&) { failure = payload::Reason::AllocationFailure; }
      catch (...) { failure = payload::Reason::CallbackFailure; }
    output.clear(); return false;
}
