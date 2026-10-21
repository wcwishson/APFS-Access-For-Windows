#include "SoftwareTransitionMetadataScope.h"
#include "SoftwareTransitionCompletedProofSource.h"
#include "MetadataStore.h"
#include "TransactionManager.h"
#include "BlockDevice.h"
#include "NativeApfsReader.h"
#include "BtreeMutationCodec.h"
#include <algorithm>
#include <stdexcept>

namespace apfsaccess::rw
{
#include "SoftwareTransitionControlReplay.inc"
namespace
{
bool MaterializeWriterIndex(NativeApfsVolumeProjection& projection,
    const std::shared_ptr<catalog::ApfsReadBudget>& budget, std::string& error)
{
    if (!budget || !projection.btree_records.empty() || !projection.checkpoint_xid || !projection.root_directory_inode) {
        error = "AppleSoftwareTransitionProjectionIndexScopeInvalid"; return false;
    }
    const auto append = [&](auto record) {
        if (record.key.empty() || !budget->Materialize(1, sizeof(record) + record.key.size() + record.value.size())) return false;
        projection.btree_records.push_back(std::move(record)); return true;
    };
    // These are the store's in-memory consistency rows, not APFS disk records.
    // The canonical writer still loads and preserves the exact source records.
    for (const auto& inode : projection.inodes) {
        if (inode.object_id != projection.root_directory_inode && !append(BtreeMutationCodec::EncodeInodeRecord(
            inode.object_id, inode.parent_object_id, inode.name, inode.is_directory, inode.logical_size,
            inode.data_physical_address, inode.timestamp_utc, projection.checkpoint_xid, false))) {
            error = "AppleSoftwareTransitionProjectionInodeIndexFailed"; return false;
        }
        if (inode.node_type != MetadataStore::NodeType::RegularFile || !inode.data_physical_address ||
            !(std::max)(inode.logical_size, inode.allocation_size.value_or(0))) continue;
        const auto found = projection.read_extents_by_inode.find(inode.object_id);
        if (found == projection.read_extents_by_inode.end() || found->second.empty()) {
            error = "AppleSoftwareTransitionProjectionExtentIndexMissing"; return false;
        }
        for (const auto& extent : found->second)
            if (!append(BtreeMutationCodec::EncodeExtentRecord(inode.object_id, extent.logical_offset,
                extent.physical_address, extent.bytes, projection.checkpoint_xid, false))) {
                error = "AppleSoftwareTransitionProjectionExtentIndexFailed"; return false;
            }
    }
    for (const auto& link : projection.directory_links)
        if (!append(BtreeMutationCodec::EncodeDirectoryRecord(link.parent_object_id, link.entry_name,
            link.child_object_id, projection.checkpoint_xid, false))) {
            error = "AppleSoftwareTransitionProjectionDirectoryIndexFailed"; return false;
        }
    return true;
}

class TransitionStoreSource final : public catalog::ImmutableEncryptedReadSource
{
    const BlockDevice& device_;
    BlockDevice::WriteSourceObservation observation_;
    std::uint64_t bytes_;
    std::string identity_;
    std::shared_ptr<catalog::ApfsReadBudget> budget_ = std::make_shared<catalog::ApfsReadBudget>(100000, 256ull << 20, 1000000, 256ull << 20);
public:
    TransitionStoreSource(const BlockDevice& device, std::uint64_t blocks) : device_(device), bytes_(blocks * 4096) {
        const auto observation = device.CaptureExclusiveWriteSourceObservation(); BlockDevice::StableImageIdentity actual;
        if (!blocks || blocks > UINT64_MAX / 4096 || !observation || !device.IsRegularFile() ||
            !device.QueryHeldImageIdentity(actual) || actual.size_bytes < device.BaseOffsetBytes() ||
            bytes_ > actual.size_bytes - device.BaseOffsetBytes() ||
            std::any_of(actual.file_id.begin() + 8, actual.file_id.end(), [](auto byte) { return byte != std::byte{}; }))
            throw std::runtime_error("AppleSoftwareTransitionExclusiveImageRequired");
        observation_ = *observation;
        std::uint64_t index = 0;
        for (unsigned i = 0; i < 8; ++i) index |= std::uint64_t(std::to_integer<unsigned>(actual.file_id[i])) << (8 * i);
        identity_ = "image-writer-v1:" + std::to_string(static_cast<std::uint32_t>(actual.volume_serial)) + ":" + std::to_string(index) + ":" +
            std::to_string(actual.size_bytes) + ":" + std::to_string(device.BaseOffsetBytes()) + ":" + std::to_string(bytes_);
    }
    std::uint64_t SizeBytes() const override { return bytes_; }
    std::string SourceIdentity() const override { return identity_; }
    std::uint64_t Revision() const override { return device_.IsExclusiveWriteSourceObservationCurrent(observation_) ? 1 : 0; }
    std::shared_ptr<catalog::ApfsReadBudget> ReadBudget() const override { return budget_; }
    bool Read(std::uint64_t at, std::size_t count, std::vector<std::byte>& bytes) const override {
        bytes.clear();
        if (at > bytes_ || count > bytes_ - at || !Revision()) return false;
        if (!count) return true;
        const auto first = at - at % 4096, prefix = static_cast<std::size_t>(at - first);
        if (count > SIZE_MAX - prefix - 4095) return false;
        const auto length = (prefix + count + 4095) / 4096 * 4096;
        if (length > bytes_ - first || !budget_->Read(length) || !device_.ReadForVerification(first, length, bytes) ||
            bytes.size() != length || !Revision()) { bytes.clear(); return false; }
        bytes.erase(bytes.begin(), bytes.begin() + prefix); bytes.resize(count); return true;
    }
};
}

SoftwareTransitionMetadataScope::SoftwareTransitionMetadataScope(MetadataStore& store, TransactionManager& original,
    std::shared_ptr<const catalog::SoftwareVolumeRetainedOwners> owners)
    : previous_(current_), store_(store), original_(original), owners_(std::move(owners)) { current_ = this; }
SoftwareTransitionMetadataScope::~SoftwareTransitionMetadataScope() { current_ = previous_; }
const SoftwareTransitionMetadataScope* SoftwareTransitionMetadataScope::Find(const MetadataStore* store) noexcept
{ return current_ && &current_->store_ == store ? current_ : nullptr; }
bool SoftwareTransitionMetadataScope::Verify(std::string& error) const
{
    error.clear();
    if (!owners_ || !original_.RecoveryStateValid() ||
        (original_.CurrentState() != TransactionManager::State::Idle && original_.CurrentState() != TransactionManager::State::Active) ||
        original_.ProtectedJournalIdentity() != std::optional{owners_->OriginalJournalIdentity()} ||
        original_.ProtectedSourceBinding() != std::optional{owners_->SourceBinding()} ||
        store_.Context().volume_object_id != owners_->VolumeObjectId()) {
        error = "AppleSoftwareTransitionOriginalBindingRequired"; return false;
    }
    TransitionStoreSource source(store_.Device(), owners_->ContainerBlockCount());
    std::unique_ptr<SoftwareTransitionControlReplaySource> replay;
    if (!SoftwareTransitionControlReplaySource::Capture(original_, source, *owners_, replay, error)) return false;
    std::vector<catalog::SoftwareVolumeOwnedRange> exclusions;
    return owners_->RevalidateProtectedHistory(replay ? *replay : static_cast<const catalog::ImmutableEncryptedReadSource&>(source),
        *original_.ProtectedJournalIdentity(), exclusions, error);
}
bool SoftwareTransitionMetadataScope::Plan(const catalog::AppleCheckpointView& checkpoint,
    const AppleVolumeTransactionRequest& request, AppleVolumeTransactionPlan& plan, std::string& error) const
{
    if (!Verify(error)) return false;
    TransitionStoreSource source(store_.Device(), owners_->ContainerBlockCount());
    std::unique_ptr<SoftwareTransitionControlReplaySource> replay;
    if (!SoftwareTransitionControlReplaySource::Capture(original_, source, *owners_, replay, error)) return false;
    const auto& evidence = replay ? *replay : static_cast<const catalog::ImmutableEncryptedReadSource&>(source);
    if (!PlanSoftwareTransitionPlainTransaction(evidence, checkpoint, request, owners_, *original_.ProtectedJournalIdentity(), plan, error)) return false;
    if (replay && !replay->MatchPlannedPrefix(plan.commit.publication, error)) { plan = {}; return false; }
    return true;
}
bool SoftwareTransitionMetadataScope::LoadProjection(NativeApfsVolumeProjection& projection, std::string& error) const
{
    projection = {};
    if (!Verify(error)) return false;
    TransitionStoreSource source(store_.Device(), owners_->ContainerBlockCount());
    std::unique_ptr<SoftwareTransitionControlReplaySource> replay;
    if (!SoftwareTransitionControlReplaySource::Capture(original_, source, *owners_, replay, error)) return false;
    const auto& evidence = replay ? *replay : static_cast<const catalog::ImmutableEncryptedReadSource&>(source);
    auto current = catalog::LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
    if (!current || current->volumes.size() != 1 ||
        current->volumes.front().superblock.object_id != owners_->VolumeObjectId() ||
        current->volumes.front().superblock.uuid_hex != owners_->VolumeUuid() ||
        current->volumes.front().superblock.fs_flags != catalog::kFsFlagUnencrypted) {
        if (error.empty()) error = "AppleSoftwareTransitionPlainEndpointRequired";
        return false;
    }
    const auto& volume = current->volumes.front();
    std::vector<catalog::BtreeRecord> records;
    NativeApfsVolumeProjection candidate;
    if (!catalog::ReadAppleVolumeFileSystemRecords(source, current->container, volume, records, error) ||
        !NativeApfsReader::TryProjectObservationalFileSystemRecords(records, current->container.superblock,
            volume.superblock, source.ReadBudget(), candidate, error)) return false;
    candidate.volume_superblock_block = volume.superblock_object.physical_block;
    candidate.volume_object_map_oid = volume.superblock.omap_oid;
    candidate.root_tree_oid = volume.superblock.root_oid;
    candidate.root_tree_block = volume.root_tree.physical_block;
    candidate.file_extent_tree_oid = volume.superblock.fext_tree_oid;
    candidate.incompatible_features = volume.superblock.incompatible_features;
    if (!MaterializeWriterIndex(candidate, source.ReadBudget(), error)) return false;
    std::vector<catalog::SoftwareVolumeOwnedRange> exclusions;
    if (!source.Revision() || !owners_->RevalidateProtectedHistory(evidence,
        *original_.ProtectedJournalIdentity(), exclusions, error)) return false;
    projection = std::move(candidate);
    return true;
}
bool SoftwareTransitionMetadataScope::VerifyOriginal(TransactionManager& original, std::string& error) const
{
    if (&original != &original_) { error = "AppleSoftwareTransitionOriginalOwnerMismatch"; return false; }
    return Verify(error);
}
bool SoftwareTransitionMetadataScope::ProjectCompletedPreimage(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& before, const std::shared_ptr<catalog::ApfsReadBudget>& budget,
    NativeApfsVolumeProjection& projection, std::string& error) const
{
    projection = {};
    if (!budget || !Verify(error)) return false;
    TransitionStoreSource actual(store_.Device(), owners_->ContainerBlockCount());
    auto current = catalog::LoadAppleCheckpointView(actual, 0, actual.SizeBytes(), error);
    std::vector<TransactionManager::AcceptedTransaction> rows;
    std::vector<std::byte> nx;
    if (!current || source.SizeBytes() != actual.SizeBytes() ||
        !original_.LoadAcceptedTransactionsSinceCleanup(rows, &error) || rows.size() != 1 ||
        rows.front().mutations.size() != 1 || rows.front().mutations.front().operation != WriteAheadLog::OperationKind::Write ||
        rows.front().preimage_checkpoint_xid != before.container.superblock.xid ||
        before.container.superblock.xid == UINT64_MAX ||
        current->container.superblock.xid != before.container.superblock.xid + 1 ||
        before.container.superblock.next_xid != current->container.superblock.xid ||
        before.container.superblock.uuid_hex != owners_->ContainerUuid() ||
        !actual.Read(before.container.superblock_physical_block * 4096, 4096, nx) ||
        nx != before.container.superblock_bytes) {
        if (error.empty()) error = "AppleSoftwareTransitionCompletedProjectionScopeMismatch";
        return false;
    }
    auto historical = catalog::LoadApplePlainTransitionVolumeView(source, before.container, error);
    if (!historical || historical->volumes.size() != 1 ||
        historical->volumes.front().superblock.object_id != owners_->VolumeObjectId() ||
        historical->volumes.front().superblock.uuid_hex != owners_->VolumeUuid() ||
        historical->volumes.front().superblock.fs_flags != catalog::kFsFlagUnencrypted) {
        if (error.empty()) error = "AppleSoftwareTransitionCompletedPlainPreimageRequired";
        return false;
    }
    const auto& volume = historical->volumes.front();
    std::vector<catalog::BtreeRecord> records;
    NativeApfsVolumeProjection candidate;
    if (!catalog::ReadAppleVolumeFileSystemRecords(source, historical->container, volume, records, error) ||
        !NativeApfsReader::TryProjectObservationalFileSystemRecords(records, historical->container.superblock,
            volume.superblock, budget, candidate, error)) return false;
    candidate.volume_superblock_block = volume.superblock_object.physical_block;
    candidate.volume_object_map_oid = volume.superblock.omap_oid;
    candidate.root_tree_oid = volume.superblock.root_oid;
    candidate.root_tree_block = volume.root_tree.physical_block;
    candidate.file_extent_tree_oid = volume.superblock.fext_tree_oid;
    candidate.incompatible_features = volume.superblock.incompatible_features;
    if (!MaterializeWriterIndex(candidate, budget, error) || !Verify(error)) return false;
    projection = std::move(candidate);
    return true;
}
bool SoftwareTransitionMetadataScope::WithVerificationCandidate(MetadataStore& candidate,
    const std::function<bool()>& operation, std::string& error) const
{
    if (!operation || &candidate.Device() != &store_.Device() || !Verify(error)) return false;
    SoftwareTransitionMetadataScope scope(candidate, original_, owners_);
    return scope.Verify(error) && operation();
}
bool SoftwareTransitionMetadataScope::PlanCompletedVerification(const catalog::RandomAccessSource& historical,
    const catalog::AppleCheckpointView& before, const AppleVolumeTransactionRequest& request,
    AppleVolumeTransactionPlan& plan, std::string& error) const
{
    plan = {};
    if (!Verify(error)) return false;
    TransitionStoreSource actual(store_.Device(), owners_->ContainerBlockCount());
    auto current = catalog::LoadAppleCheckpointView(actual, 0, actual.SizeBytes(), error);
    if (!current || before.container.superblock.next_xid != current->container.superblock.xid ||
        before.container.superblock.xid == UINT64_MAX ||
        current->container.superblock.xid != before.container.superblock.xid + 1 || historical.SizeBytes() != actual.SizeBytes()) {
        error = "AppleSoftwareTransitionCompletedBoundaryMismatch"; return false;
    }
    std::unique_ptr<SoftwareTransitionControlReplaySource> controls;
    if (!SoftwareTransitionControlReplaySource::CaptureForCompletedVerification(original_, actual, *owners_, controls, error) || !controls)
        return false;
    catalog::SoftwareTransitionCompletedProofSource source(historical, actual, *owners_, current->container,
        [&](std::uint64_t at, std::span<std::byte> bytes) { controls->Overlay(at, bytes); });
    AppleVolumeTransactionPlan candidate;
    if (!PlanSoftwareTransitionPlainTransaction(source, before, request, owners_, *original_.ProtectedJournalIdentity(), candidate, error) ||
        !controls->MatchCompletedPublication(candidate.commit.publication, error)) return false;
    const auto readback = [&](const auto& write) {
        std::vector<std::byte> bytes;
        return !write.bytes.empty() && write.bytes.size() % 4096 == 0 &&
            actual.Read(write.physical_block * 4096, write.bytes.size(), bytes) && bytes == write.bytes;
    };
    if (!readback(candidate.commit.publication.superblock_write) ||
        !std::all_of(candidate.commit.publication.before_superblock_writes.begin(),
            candidate.commit.publication.before_superblock_writes.end(), readback)) {
        error = "AppleSoftwareTransitionCompletedPublicationReadbackMismatch"; return false;
    }
    auto fresh = catalog::LoadAppleCheckpointView(actual, 0, actual.SizeBytes(), error);
    if (!fresh || fresh->container.superblock_bytes != current->container.superblock_bytes ||
        fresh->container.superblock_physical_block != current->container.superblock_physical_block || !Verify(error)) {
        if (error.empty()) error = "AppleSoftwareTransitionCompletedAuthorityChanged";
        return false;
    }
    plan = std::move(candidate); return true;
}
bool WithSoftwareTransitionPlainWriter(MetadataStore& store, TransactionManager& original,
    std::shared_ptr<const catalog::SoftwareVolumeRetainedOwners> owners, const std::function<bool(std::string&)>& operation, std::string& error)
{
    error.clear();
    if (!operation) { error = "AppleSoftwareTransitionOperationRequired"; return false; }
    try {
        SoftwareTransitionMetadataScope scope(store, original, std::move(owners));
        return scope.Verify(error) && operation(error);
    } catch (const std::exception& exception) { error = exception.what(); return false; }
}
}
