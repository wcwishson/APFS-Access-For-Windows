#pragma once
#include "NativeRawSnapshotStartupEvidence.h"
#include "BackupRetainedSource.h"
#include "TransactionManager.h"
#include <charconv>

namespace apfsaccess::fshost
{
// Retains original marker/spool ancestors across the handoff to a protected
// journal owner. The supplied source is already a checked, held G08 capability.
class BackupHeldOriginalCensus final
{
public:
    static std::unique_ptr<BackupHeldOriginalCensus> Inspect(
        const rw::BackupRetainedSource& source, rw::TransactionManager& original,
        const std::filesystem::path& original_path, const RawSnapshotStartupEvidencePaths& paths,
        std::uint64_t max_payload_bytes, std::uint64_t selected_xid, std::string& error)
    try
    {
        error.clear();
        const auto root = original_path.parent_path();
        if (!original_path.is_absolute() || original_path.filename() != L"write-ahead.wal" ||
            std::filesystem::path(paths.spool_index) != root / L"payload-spool.idx" ||
            std::filesystem::path(paths.payload) != root / L"payload-spool.bin" ||
            !max_payload_bytes || max_payload_bytes > (512ull << 20) || !selected_xid)
        { error = "BackupHeldStartupPathsInvalid"; return {}; }
        auto owner = std::unique_ptr<BackupHeldOriginalCensus>(
            new BackupHeldOriginalCensus(source, original, paths, max_payload_bytes));
        const auto actual = catalog::LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
        if (!actual || actual->container.superblock.xid != selected_xid || !source.MatchesCheckpoint(*actual) ||
            !rw::ValidateBackupImageWriterProfile(source, *actual, actual->volumes.front().superblock.object_id, error))
        { error = "BackupHeldStartupSelectedSourceMismatch"; return {}; }
        RawSnapshotStartupEvidence evidence;
        if (!owner->pins_.Verify(evidence) || !owner->OriginalCurrent())
        { error = "BackupHeldStartupOriginalUnavailable"; return {}; }
        rw::TransactionManager::RetainedAcceptedHistory history;
        if (!original.LoadRetainedAcceptedHistory(history, error, {16ull << 20, 4096}) ||
            history.coverage == rw::TransactionManager::RetainedHistoryCoverage::Unavailable || history.pending.size() > 1 ||
            !original.OwnsJournalForMaintenance(original_path.wstring(), original.ConfiguredVolumeIdentity()))
        { if (error.empty()) error = "BackupHeldStartupExistingOriginalRequired"; return {}; }
        if ((!history.cleaned.empty() && history.cleaned.back().preimage_checkpoint_xid >= selected_xid) ||
            (!history.pending.empty() && (history.pending.front().preimage_checkpoint_xid == UINT64_MAX ||
                (selected_xid != history.pending.front().preimage_checkpoint_xid &&
                    selected_xid != history.pending.front().preimage_checkpoint_xid + 1))))
        { error = "BackupHeldStartupBoundaryMismatch"; return {}; }
        owner->admitted_ = history.watermarks;
        if (owner->absent_original_ && (history.coverage != rw::TransactionManager::RetainedHistoryCoverage::NoAcceptedHistory ||
            history.watermarks.accepted_sequence || history.watermarks.apfs_durable_sequence || history.watermarks.cleanup_sequence ||
            !history.cleaned.empty() || !history.pending.empty() || evidence.marker.present || evidence.spool_index.present || evidence.payload.present))
        { error = "BackupHeldStartupAbsentOriginalHasEvidence"; return {}; }
        if (evidence.marker.present) {
            if (!ParseMarker(evidence.marker, owner->dirty_, owner->marker_xid_) || owner->marker_xid_ > selected_xid ||
                (!history.pending.empty() && !owner->dirty_ &&
                    (owner->marker_xid_ != selected_xid || history.watermarks.apfs_durable_sequence != history.watermarks.accepted_sequence)))
            { error = "BackupHeldStartupMarkerMismatch"; return {}; }
        } else if (history.watermarks.accepted_sequence || !history.cleaned.empty() || !history.pending.empty()) {
            error = "BackupHeldStartupOriginalMarkerRequired"; return {};
        }
        if (!owner->pins_.Verify() || !owner->OriginalCurrent())
        { error = "BackupHeldStartupEvidenceChanged"; return {}; }
        owner->selected_xid_ = selected_xid;
        return owner;
    }
    catch (...) { error = "BackupHeldStartupCensusFailed"; return {}; }

    // Complete census precedes this transition. Existing dirty evidence is
    // preserved while the consumer reconstructs the original accepted prefix.
    bool PromoteForRecovery(std::string& error)
    {
        if (promoted_ || !OriginalCurrent() || !SameMarks(original_.Watermarks(), admitted_) ||
            !pins_.Verify() || !pins_.PrepareMissingParents()) return Fail(error, "BackupHeldStartupHandoffRefused");
        if (absent_original_) {
            if (!original_.MaterializeAbsentProtectedStartupJournal([&] { return source_.Current() && pins_.Verify(); }, error))
                return Fail(error, "BackupHeldStartupOriginalMaterializationFailed");
            absent_original_ = false;
            if (!OriginalCurrent()) return Fail(error, "BackupHeldStartupMaterializedOriginalChanged");
        }
        const auto bytes = Marker(dirty_, marker_xid_ ? marker_xid_ : selected_xid_);
        if (!pins_.PromoteMarkerOwner(std::as_bytes(std::span(bytes))) ||
            !pins_.PromoteMutableSpoolParents() || !OriginalCurrent())
        {
            const auto detail = std::string("BackupHeldStartupMarkerOwnershipFailed:") + pins_.Failure() +
                ":Win32=" + std::to_string(pins_.Win32Error());
            return Fail(error, detail.c_str());
        }
        promoted_ = true;
        return pins_.VerifyMarkerOwner() || Fail(error, "BackupHeldStartupMarkerOwnershipChanged");
    }

    bool BeforeMutation(std::uint64_t current_xid, std::string& error)
    {
        if (dirty_) {
            const bool current = !failed_ && promoted_ && source_.Current() &&
                original_.ProtectedSourceBinding() == source_.JournalSourceBinding() &&
                original_.ProtectedJournalIdentity() &&
                rw::TransactionManager::WideToUtf8(original_.ConfiguredVolumeIdentity()) == source_.RecoveryIdentity() &&
                original_.RecoveryStateValid() && lease_ &&
                original_.ObservedJournalWriterLeaseGeneration() == lease_ &&
                original_.ObservedJournalAppendLeaseGeneration() == lease_ && pins_.VerifyMarkerOwner();
            return (current && current_xid && current_xid >= selected_xid_ && current_xid >= marker_xid_) ||
                Fail(error, "BackupHeldDirtyMarkerOwnerChanged");
        }
        if (!Settled() || !current_xid || current_xid < selected_xid_ || current_xid < marker_xid_)
            return Fail(error, "BackupHeldMutationOriginalUnsettled");
        const auto bytes = Marker(true, current_xid);
        if (!pins_.PersistOwnedMarker(std::as_bytes(std::span(bytes))) || !OriginalCurrent())
            return Fail(error, "BackupHeldMutationMarkerFailed");
        dirty_ = true;
        return true;
    }

    bool CompleteRecovery(std::uint64_t verified_xid, std::string& error)
    {
        if (!Settled() || !verified_xid || verified_xid < selected_xid_ || verified_xid < marker_xid_)
            return Fail(error, "BackupHeldRecoveryOriginalUnsettled");
        const auto actual = catalog::LoadAppleCheckpointView(source_, 0, source_.SizeBytes(), error);
        if (!actual || actual->container.superblock.xid != verified_xid || !source_.MatchesCheckpoint(*actual) ||
            !rw::ValidateBackupImageWriterProfile(source_, *actual, actual->volumes.front().superblock.object_id, error))
            return Fail(error, "BackupHeldRecoveryCheckpointUnproven");
        // Only a publication verifier may supply this XID after exact postimage
        // proof and the held flush; the original markers must already be clean.
        const auto bytes = Marker(false, verified_xid);
        if (!pins_.PersistOwnedMarker(std::as_bytes(std::span(bytes))) || !OriginalCurrent())
            return Fail(error, "BackupHeldRecoveryMarkerFailed");
        dirty_ = false; marker_xid_ = verified_xid;
        return true;
    }

    bool Ready() { return !dirty_ && Settled(); }
    bool OwnsMarkerPath(std::wstring_view path) const noexcept { return pins_.OwnsMarkerPath(path); }
    NativeRawSnapshotStartupEvidence& MarkerOwner() noexcept { return pins_; }

private:
    BackupHeldOriginalCensus(const rw::BackupRetainedSource& source, rw::TransactionManager& original,
        const RawSnapshotStartupEvidencePaths& paths, std::uint64_t limit)
        : source_(source), original_(original), pins_(paths, limit), lease_(original.ObservedJournalWriterLeaseGeneration()),
          absent_original_(!original.ObservedJournalAppendLeaseGeneration()) {}
    bool OriginalCurrent() const
    {
        return !failed_ && source_.IsPhysical() && source_.Current() && source_.JournalSourceBinding() &&
            original_.ProtectedSourceBinding() == source_.JournalSourceBinding() && original_.ProtectedJournalIdentity() &&
            rw::TransactionManager::WideToUtf8(original_.ConfiguredVolumeIdentity()) == source_.RecoveryIdentity() &&
            original_.CurrentState() == rw::TransactionManager::State::Idle && original_.RecoveryStateValid() &&
            lease_ && original_.ObservedJournalWriterLeaseGeneration() == lease_ &&
            (original_.ObservedJournalAppendLeaseGeneration() == lease_ ||
                (absent_original_ && !original_.ObservedJournalAppendLeaseGeneration() && original_.NextMutationSequence() == 1 &&
                    !original_.Watermarks().accepted_sequence && !original_.Watermarks().apfs_durable_sequence && !original_.Watermarks().cleanup_sequence));
    }
    bool Settled()
    {
        const auto marks = original_.Watermarks();
        return promoted_ && OriginalCurrent() && pins_.VerifyMarkerOwner() &&
            marks.accepted_sequence == marks.apfs_durable_sequence && marks.accepted_sequence == marks.cleanup_sequence &&
            original_.CanClearRecoveryState();
    }
    static bool SameMarks(const rw::TransactionManager::DurabilityWatermarks& a,
        const rw::TransactionManager::DurabilityWatermarks& b)
    { return a.accepted_sequence == b.accepted_sequence && a.apfs_durable_sequence == b.apfs_durable_sequence && a.cleanup_sequence == b.cleanup_sequence; }
    static std::string Marker(bool dirty, std::uint64_t xid)
    { return std::string("dirty=") + (dirty ? "1" : "0") + "\nlastCommitXid=" + std::to_string(xid) + "\n"; }
    static bool ParseMarker(const RawSnapshotStartupFileEvidence& evidence, bool& dirty, std::uint64_t& xid)
    {
        dirty = false; xid = 0;
        if (!evidence.bytes_captured || evidence.bytes.empty()) return false;
        const auto bytes = std::string_view(reinterpret_cast<const char*>(evidence.bytes.data()), evidence.bytes.size());
        if (!bytes.starts_with("dirty=0\nlastCommitXid=") && !bytes.starts_with("dirty=1\nlastCommitXid=")) return false;
        constexpr std::size_t start = sizeof("dirty=0\nlastCommitXid=") - 1;
        if (bytes.size() <= start + 1 || bytes.back() != '\n') return false;
        const auto number = bytes.substr(start, bytes.size() - start - 1);
        if (number.front() == '0') return false;
        const auto parsed = std::from_chars(number.data(), number.data() + number.size(), xid);
        dirty = bytes[6] == '1';
        return parsed.ec == std::errc{} && parsed.ptr == number.data() + number.size() && xid;
    }
    bool Fail(std::string& error, const char* reason) { failed_ = true; error = reason; return false; }
    const rw::BackupRetainedSource& source_;
    rw::TransactionManager& original_;
    NativeRawSnapshotStartupEvidence pins_;
    rw::TransactionManager::DurabilityWatermarks admitted_{};
    std::uint64_t lease_ = 0, selected_xid_ = 0, marker_xid_ = 0;
    bool promoted_ = false, dirty_ = false, failed_ = false, absent_original_ = false;
};
}
