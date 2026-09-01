#include "WritePipeline.h"

#include <iostream>

namespace
{
bool Require(bool condition, const char* message)
{
    if (!condition)
    {
        std::cerr << "[FAIL] " << message << std::endl;
        return false;
    }
    return true;
}

bool TestCommitRequestClassification()
{
    using apfsaccess::rw::WritePipeline;
    using Urgency = WritePipeline::CommitUrgency;

    if (!Require(
            WritePipeline::ClassifyCommitRequest({ false, true, false, false, L"Flush" }) == Urgency::None,
            "disabled native write should not commit"))
    {
        return false;
    }
    if (!Require(
            WritePipeline::ClassifyCommitRequest({ true, false, false, false, L"Flush" }) == Urgency::None,
            "clean native write state should not commit"))
    {
        return false;
    }
    if (!Require(
            WritePipeline::ClassifyCommitRequest({ true, false, true, false, L"Close" }) == Urgency::DeleteBoundaryMustCommit,
            "delete should be a hard boundary even when pending count is not visible"))
    {
        return false;
    }
    if (!Require(
            WritePipeline::ClassifyCommitRequest({ true, false, false, true, L"Rename" }) == Urgency::NamespaceBoundaryMustCommit,
            "namespace boundary should force commit even when pending count is not visible"))
    {
        return false;
    }
    if (!Require(
            WritePipeline::ClassifyCommitRequest({ true, true, true, false, L"Close" }) == Urgency::DeleteBoundaryMustCommit,
            "delete plans on close should take precedence over close batching"))
    {
        return false;
    }
    if (!Require(
            WritePipeline::ClassifyCommitRequest({ true, true, false, true, L"Rename" }) == Urgency::NamespaceBoundaryMustCommit,
            "namespace boundary should force namespace commit"))
    {
        return false;
    }
    if (!Require(
            WritePipeline::ClassifyCommitRequest({ true, true, false, false, L"Flush" }) == Urgency::UserFlushMustCommit,
            "flush should force user-flush commit"))
    {
        return false;
    }
    if (!Require(
            WritePipeline::ClassifyCommitRequest({ true, true, false, false, L"Shutdown" }) == Urgency::ShutdownMustCommit,
            "shutdown should force shutdown commit"))
    {
        return false;
    }
    if (!Require(
            WritePipeline::ClassifyCommitRequest({ true, true, false, false, L"DirtyLimit" }) == Urgency::DirtyLimitMustCommit,
            "dirty-limit should force dirty-limit commit"))
    {
        return false;
    }
    if (!Require(
            WritePipeline::ClassifyCommitRequest({ true, true, false, false, L"Close" }) == Urgency::FileContentCloseCanDelay,
            "content close should be delayable"))
    {
        return false;
    }
    if (!Require(
            WritePipeline::ClassifyCommitRequest({ true, true, false, false, L"CloseDeferred" }) == Urgency::FileContentCloseCanDelay,
            "deferred close worker should use the close batching policy"))
    {
        return false;
    }
    return Require(
        WritePipeline::ClassifyCommitRequest({ true, true, false, false, L"SetBasicInfo" }) == Urgency::MetadataOnlyCanDelay,
        "other metadata should be metadata-only delayable");
}

bool TestDeferredCloseCancellationPolicy()
{
    using apfsaccess::rw::WritePipeline;
    using Urgency = WritePipeline::CommitUrgency;

    return Require(
               !WritePipeline::ShouldCancelDeferredCloseBeforeDrain(Urgency::None),
               "no commit should not cancel deferred close") &&
           Require(
               !WritePipeline::ShouldCancelDeferredCloseBeforeDrain(Urgency::FileContentCloseCanDelay),
               "delayable content close should not cancel deferred close") &&
           Require(
               !WritePipeline::ShouldCancelDeferredCloseBeforeDrain(Urgency::MetadataOnlyCanDelay),
               "delayable metadata-only work should not cancel deferred close") &&
           Require(
               WritePipeline::ShouldCancelDeferredCloseBeforeDrain(Urgency::UserFlushMustCommit),
               "flush should cancel deferred close") &&
           Require(
               WritePipeline::ShouldCancelDeferredCloseBeforeDrain(Urgency::NamespaceBoundaryMustCommit),
               "namespace boundary should cancel deferred close") &&
           Require(
               WritePipeline::ShouldCancelDeferredCloseBeforeDrain(Urgency::DeleteBoundaryMustCommit),
               "non-close delete boundary should cancel deferred close");
}

bool TestStagingPolicy()
{
    using apfsaccess::rw::WritePipeline;

    const auto disabled = WritePipeline::StageForegroundMutation({ false, true, 0, 128 });
    if (!Require(!disabled.should_stage && !disabled.should_drain_dirty_limit, "disabled native writes should not stage"))
    {
        return false;
    }

    const auto under_limit = WritePipeline::StageForegroundMutation({ true, true, 7, 128 });
    if (!Require(under_limit.should_stage && !under_limit.should_drain_dirty_limit, "under dirty limit should stage"))
    {
        return false;
    }

    const auto at_limit = WritePipeline::StageForegroundMutation({ true, true, 128, 128 });
    if (!Require(!at_limit.should_stage && at_limit.should_drain_dirty_limit, "dirty limit should request drain"))
    {
        return false;
    }

    const auto payload = WritePipeline::StagePayloadRange({ true, true, true, 4096, true });
    if (!Require(payload.should_write_through, "prepared payload should write through when all gates are open"))
    {
        return false;
    }

    const auto empty_payload = WritePipeline::StagePayloadRange({ true, true, true, 0, true });
    return Require(!empty_payload.should_write_through, "empty payload should not write through");
}

bool TestBarrierAndDrainPolicy()
{
    using apfsaccess::rw::WritePipeline;
    using Urgency = WritePipeline::CommitUrgency;

    const auto clean_barrier = WritePipeline::RequestBarrier({ true, false, false, false, L"Flush" });
    const auto clean_drain = WritePipeline::DrainNow(clean_barrier);
    if (!Require(clean_barrier.urgency == Urgency::None, "clean barrier should have no urgency") ||
        !Require(!clean_drain.should_commit_now, "clean barrier should not drain") ||
        !Require(clean_drain.clear_stale_dirty_marker, "clean barrier should clear stale dirty marker"))
    {
        return false;
    }

    const auto close_barrier = WritePipeline::RequestBarrier({ true, true, false, false, L"Close" });
    const auto close_drain = WritePipeline::DrainNow(close_barrier);
    if (!Require(close_barrier.urgency == Urgency::FileContentCloseCanDelay, "close barrier should be delayable") ||
        !Require(close_barrier.can_delay, "close barrier should report delayable policy") ||
        !Require(close_drain.should_commit_now, "phase 1 close drain should preserve immediate behavior") ||
        !Require(!close_drain.cancel_deferred_close, "close drain should not cancel deferred close"))
    {
        return false;
    }

    const auto metadata_barrier = WritePipeline::RequestBarrier({ true, true, false, false, L"SetBasicInfo" });
    const auto metadata_drain = WritePipeline::DrainNow(metadata_barrier);
    if (!Require(metadata_barrier.urgency == Urgency::MetadataOnlyCanDelay, "metadata-only barrier should be delayable") ||
        !Require(metadata_barrier.can_delay, "metadata-only barrier should report delayable policy") ||
        !Require(metadata_drain.should_commit_now, "metadata-only drain should preserve immediate commit behavior") ||
        !Require(!metadata_drain.cancel_deferred_close, "metadata-only drain should not cancel deferred close"))
    {
        return false;
    }

    const auto rename_barrier = WritePipeline::RequestBarrier({ true, true, false, true, L"Rename" });
    const auto rename_drain = WritePipeline::DrainNow(rename_barrier);
    return Require(rename_barrier.urgency == Urgency::NamespaceBoundaryMustCommit, "rename should be namespace barrier") &&
           Require(rename_drain.should_commit_now, "rename barrier should drain") &&
           Require(rename_drain.cancel_deferred_close, "rename barrier should cancel deferred close");
}


bool TestHydrationWritePolicy()
{
    using apfsaccess::rw::WritePipeline;

    const auto write_back_spool = WritePipeline::PlanForegroundPayloadStorage({
        true,
        true,
        true,
        true,
        false,
        64 * 1024,
    });
    if (!Require(
            !write_back_spool.should_write_hydration_file,
            "native write-back should avoid a duplicate hydration write while the durable spool owns the payload"))
    {
        return false;
    }
    if (!Require(write_back_spool.should_stage_payload_spool, "spool-backed write should stage payload"))
    {
        return false;
    }

    const auto mirrored_write_back = WritePipeline::PlanForegroundPayloadStorage({
        true,
        true,
        true,
        true,
        false,
        64 * 1024,
        true,
    });
    if (!Require(mirrored_write_back.should_stage_payload_spool,
            "hydration mirror should retain authoritative payload-spool staging") ||
        !Require(mirrored_write_back.should_write_hydration_file,
            "hydration mirror should also populate the non-authoritative hydration file"))
    {
        return false;
    }

    const auto named_stream = WritePipeline::PlanForegroundPayloadStorage({
        true,
        true,
        true,
        true,
        true,
        64 * 1024,
    });
    if (!Require(named_stream.should_write_hydration_file, "named streams should keep hydration storage"))
    {
        return false;
    }

    const auto no_spool = WritePipeline::PlanForegroundPayloadStorage({
        true,
        true,
        false,
        true,
        false,
        64 * 1024,
    });
    if (!Require(no_spool.should_write_hydration_file, "missing spool should preserve hydration source"))
    {
        return false;
    }

    const auto read_only = WritePipeline::PlanForegroundPayloadStorage({
        false,
        false,
        true,
        true,
        false,
        64 * 1024,
    });
    if (!Require(read_only.should_write_hydration_file, "non-native writes still need hydration storage"))
    {
        return false;
    }

    const auto empty = WritePipeline::PlanForegroundPayloadStorage({
        true,
        true,
        true,
        true,
        false,
        0,
    });
    return Require(!empty.should_stage_payload_spool, "empty payload should not stage spool bytes");
}
bool TestDirtyStatusSnapshot()
{
    using apfsaccess::rw::WritePipeline;

    const auto status = WritePipeline::SnapshotDirtyStatus({
        3,
        5,
        true,
        true,
        9,
        2,
    });

    return Require(status.transaction_journal_pending_count == 3, "dirty snapshot should keep tx count") &&
           Require(status.metadata_pending_count == 5, "dirty snapshot should keep metadata count") &&
           Require(status.dirty_transaction_count == 5, "dirty snapshot should expose max dirty count") &&
           Require(status.has_pending_metadata_mutations, "dirty snapshot should flag metadata mutations") &&
           Require(status.has_any_dirty_work, "dirty snapshot should flag any dirty work") &&
           Require(status.shutdown_drain_active, "dirty snapshot should keep shutdown drain state") &&
           Require(status.close_commit_deferred, "dirty snapshot should keep deferred close state") &&
           Require(status.deferred_close_commit_count == 9, "dirty snapshot should keep deferred close count") &&
           Require(status.in_flight_mutation_callbacks == 2, "dirty snapshot should keep callback count");
}

bool TestDirtyStatusSuppressesStaleDeferredCloseWhenClean()
{
    using apfsaccess::rw::WritePipeline;

    const auto status = WritePipeline::SnapshotDirtyStatus({
        0,
        0,
        false,
        true,
        3,
        0,
    });

    return Require(!status.has_any_dirty_work, "clean dirty snapshot should have no dirty work") &&
           Require(!status.close_commit_deferred, "clean dirty snapshot should suppress stale deferred-close state") &&
           Require(status.deferred_close_commit_count == 3, "clean dirty snapshot should keep cumulative deferred count");
}

bool TestAbortOrFailClosedPolicy()
{
    using apfsaccess::rw::WritePipeline;

    const auto decision = WritePipeline::AbortOrFailClosed({ true, true });
    return Require(decision.should_abort, "abort request should be preserved") &&
           Require(decision.should_fail_closed, "fail-closed policy should be preserved");
}
}

int main()
{
    if (!TestCommitRequestClassification() ||
        !TestDeferredCloseCancellationPolicy() ||
        !TestStagingPolicy() ||
        !TestBarrierAndDrainPolicy() ||
        !TestHydrationWritePolicy() ||
        !TestDirtyStatusSnapshot() ||
        !TestDirtyStatusSuppressesStaleDeferredCloseWhenClean() ||
        !TestAbortOrFailClosedPolicy())
    {
        return 1;
    }

    std::cout << "[PASS] WritePipeline tests passed." << std::endl;
    return 0;
}
