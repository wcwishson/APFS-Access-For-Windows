#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace apfsaccess::rw
{
class WritePipeline
{
public:
    enum class CommitUrgency
    {
        None,
        MetadataOnlyCanDelay,
        FileContentCloseCanDelay,
        DirtyLimitMustCommit,
        UserFlushMustCommit,
        NamespaceBoundaryMustCommit,
        DeleteBoundaryMustCommit,
        ShutdownMustCommit,
    };

    struct CommitRequest
    {
        bool write_pipeline_enabled = false;
        bool has_pending_mutations = false;
        bool has_delete_plans = false;
        bool namespace_boundary = false;
        std::wstring_view origin;
    };

    struct BarrierDecision
    {
        CommitUrgency urgency = CommitUrgency::None;
        bool should_drain_now = false;
        bool cancel_deferred_close = false;
        bool can_delay = false;
    };

    struct DrainDecision
    {
        bool should_commit_now = false;
        bool clear_stale_dirty_marker = false;
        bool cancel_deferred_close = false;
    };

    struct StageForegroundMutationRequest
    {
        bool native_write_enabled = false;
        bool metadata_store_available = false;
        std::size_t pending_mutation_count = 0;
        std::size_t dirty_limit = 0;
    };

    struct StageForegroundMutationDecision
    {
        bool should_stage = false;
        bool should_drain_dirty_limit = false;
    };

    struct StagePayloadRangeRequest
    {
        bool native_write_enabled = false;
        bool metadata_store_available = false;
        bool payload_available = false;
        std::uint64_t payload_bytes = 0;
        bool prepared_payload_write_through_enabled = false;
    };

    struct StagePayloadRangeDecision
    {
        bool should_write_through = false;
    };

    struct ForegroundPayloadStorageRequest
    {
        bool native_write_enabled = false;
        bool metadata_store_available = false;
        bool payload_spool_available = false;
        bool payload_available = false;
        bool named_stream = false;
        std::uint64_t payload_bytes = 0;
        bool mirror_hydration_file = false;
    };

    struct ForegroundPayloadStorageDecision
    {
        bool should_write_hydration_file = true;
        bool should_stage_payload_spool = false;
    };

    struct DirtyStatusInput
    {
        std::uint64_t transaction_journal_pending_count = 0;
        std::uint64_t metadata_pending_count = 0;
        bool shutdown_drain_active = false;
        bool close_commit_deferred = false;
        std::uint64_t deferred_close_commit_count = 0;
        std::uint32_t in_flight_mutation_callbacks = 0;
    };

    struct DirtyStatus
    {
        std::uint64_t transaction_journal_pending_count = 0;
        std::uint64_t metadata_pending_count = 0;
        std::uint64_t dirty_transaction_count = 0;
        bool has_pending_metadata_mutations = false;
        bool has_any_dirty_work = false;
        bool shutdown_drain_active = false;
        bool close_commit_deferred = false;
        std::uint64_t deferred_close_commit_count = 0;
        std::uint32_t in_flight_mutation_callbacks = 0;
    };

    struct AbortOrFailClosedRequest
    {
        bool abort_requested = false;
        bool fail_closed_policy = false;
    };

    struct AbortOrFailClosedDecision
    {
        bool should_abort = false;
        bool should_fail_closed = false;
    };

    [[nodiscard]] static StageForegroundMutationDecision StageForegroundMutation(
        const StageForegroundMutationRequest& request) noexcept;
    [[nodiscard]] static StagePayloadRangeDecision StagePayloadRange(
        const StagePayloadRangeRequest& request) noexcept;
    [[nodiscard]] static ForegroundPayloadStorageDecision PlanForegroundPayloadStorage(
        const ForegroundPayloadStorageRequest& request) noexcept;
    [[nodiscard]] static BarrierDecision RequestBarrier(const CommitRequest& request);
    [[nodiscard]] static DrainDecision DrainNow(const BarrierDecision& barrier) noexcept;
    [[nodiscard]] static DirtyStatus SnapshotDirtyStatus(const DirtyStatusInput& input) noexcept;
    [[nodiscard]] static AbortOrFailClosedDecision AbortOrFailClosed(
        const AbortOrFailClosedRequest& request) noexcept;
    [[nodiscard]] static CommitUrgency ClassifyCommitRequest(const CommitRequest& request);
    [[nodiscard]] static bool ShouldCancelDeferredCloseBeforeDrain(CommitUrgency urgency) noexcept;
};
}
