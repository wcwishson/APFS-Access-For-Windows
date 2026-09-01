#include "WritePipeline.h"

#include <cwctype>

namespace apfsaccess::rw
{
namespace
{
bool EqualsIgnoreCase(std::wstring_view lhs, std::wstring_view rhs)
{
    if (lhs.size() != rhs.size())
    {
        return false;
    }

    for (std::size_t index = 0; index < lhs.size(); ++index)
    {
        if (std::towlower(lhs[index]) != std::towlower(rhs[index]))
        {
            return false;
        }
    }

    return true;
}

WritePipeline::CommitUrgency ClassifyCommitRequestCore(const WritePipeline::CommitRequest& request)
{
    if (!request.write_pipeline_enabled)
    {
        return WritePipeline::CommitUrgency::None;
    }
    if (!request.has_pending_mutations &&
        !request.has_delete_plans &&
        !request.namespace_boundary)
    {
        return WritePipeline::CommitUrgency::None;
    }
    if (request.namespace_boundary)
    {
        return WritePipeline::CommitUrgency::NamespaceBoundaryMustCommit;
    }
    if (request.has_delete_plans)
    {
        return WritePipeline::CommitUrgency::DeleteBoundaryMustCommit;
    }
    if (EqualsIgnoreCase(request.origin, L"Flush"))
    {
        return WritePipeline::CommitUrgency::UserFlushMustCommit;
    }
    if (EqualsIgnoreCase(request.origin, L"Shutdown"))
    {
        return WritePipeline::CommitUrgency::ShutdownMustCommit;
    }
    if (EqualsIgnoreCase(request.origin, L"DirtyLimit"))
    {
        return WritePipeline::CommitUrgency::DirtyLimitMustCommit;
    }
    if (EqualsIgnoreCase(request.origin, L"Close") ||
        EqualsIgnoreCase(request.origin, L"CloseDeferred"))
    {
        return WritePipeline::CommitUrgency::FileContentCloseCanDelay;
    }
    return WritePipeline::CommitUrgency::MetadataOnlyCanDelay;
}
}

WritePipeline::StageForegroundMutationDecision WritePipeline::StageForegroundMutation(
    const StageForegroundMutationRequest& request) noexcept
{
    StageForegroundMutationDecision decision{};
    if (!request.native_write_enabled || !request.metadata_store_available)
    {
        return decision;
    }

    const bool dirty_limit_reached =
        request.dirty_limit > 0 &&
        request.pending_mutation_count >= request.dirty_limit;
    decision.should_drain_dirty_limit = dirty_limit_reached;
    decision.should_stage = !dirty_limit_reached;
    return decision;
}

WritePipeline::StagePayloadRangeDecision WritePipeline::StagePayloadRange(
    const StagePayloadRangeRequest& request) noexcept
{
    return {
        request.native_write_enabled &&
        request.metadata_store_available &&
        request.payload_available &&
        request.payload_bytes > 0 &&
        request.prepared_payload_write_through_enabled,
    };
}

WritePipeline::ForegroundPayloadStorageDecision WritePipeline::PlanForegroundPayloadStorage(
    const ForegroundPayloadStorageRequest& request) noexcept
{
    ForegroundPayloadStorageDecision decision{};
    decision.should_stage_payload_spool =
        request.native_write_enabled &&
        request.metadata_store_available &&
        request.payload_spool_available &&
        request.payload_available &&
        !request.named_stream &&
        request.payload_bytes > 0;
    decision.should_write_hydration_file =
        !decision.should_stage_payload_spool || request.mirror_hydration_file;
    return decision;
}

WritePipeline::BarrierDecision WritePipeline::RequestBarrier(const CommitRequest& request)
{
    BarrierDecision decision{};
    decision.urgency = ClassifyCommitRequestCore(request);
    decision.should_drain_now = decision.urgency != CommitUrgency::None;
    decision.cancel_deferred_close = ShouldCancelDeferredCloseBeforeDrain(decision.urgency);
    decision.can_delay =
        decision.urgency == CommitUrgency::MetadataOnlyCanDelay ||
        decision.urgency == CommitUrgency::FileContentCloseCanDelay;
    return decision;
}

WritePipeline::DrainDecision WritePipeline::DrainNow(const BarrierDecision& barrier) noexcept
{
    return {
        barrier.should_drain_now,
        !barrier.should_drain_now,
        barrier.cancel_deferred_close,
    };
}

WritePipeline::DirtyStatus WritePipeline::SnapshotDirtyStatus(const DirtyStatusInput& input) noexcept
{
    DirtyStatus status{};
    status.transaction_journal_pending_count = input.transaction_journal_pending_count;
    status.metadata_pending_count = input.metadata_pending_count;
    status.dirty_transaction_count =
        input.transaction_journal_pending_count > input.metadata_pending_count
            ? input.transaction_journal_pending_count
            : input.metadata_pending_count;
    status.has_pending_metadata_mutations = input.metadata_pending_count > 0;
    status.has_any_dirty_work = status.dirty_transaction_count > 0;
    status.shutdown_drain_active = input.shutdown_drain_active;
    status.close_commit_deferred = input.close_commit_deferred && status.has_any_dirty_work;
    status.deferred_close_commit_count = input.deferred_close_commit_count;
    status.in_flight_mutation_callbacks = input.in_flight_mutation_callbacks;
    return status;
}

WritePipeline::AbortOrFailClosedDecision WritePipeline::AbortOrFailClosed(
    const AbortOrFailClosedRequest& request) noexcept
{
    return {
        request.abort_requested,
        request.fail_closed_policy,
    };
}

WritePipeline::CommitUrgency WritePipeline::ClassifyCommitRequest(const CommitRequest& request)
{
    return ClassifyCommitRequestCore(request);
}

bool WritePipeline::ShouldCancelDeferredCloseBeforeDrain(CommitUrgency urgency) noexcept
{
    return urgency != CommitUrgency::None &&
           urgency != CommitUrgency::MetadataOnlyCanDelay &&
           urgency != CommitUrgency::FileContentCloseCanDelay;
}
}
