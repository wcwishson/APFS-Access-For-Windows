#include "MetadataStore.h"
#include "NativeCloneRange.h"
#include "TransactionManager.h"
#include <algorithm>
#include <map>
#include <set>

namespace apfsaccess::rw
{
namespace
{
template<class F> struct Finally { F call; ~Finally() { call(); } };
template<class F> Finally(F) -> Finally<F>;
bool Fail(std::string& error, const char* text) { if (error.empty()) error = text; return false; }
class Source final : public catalog::RandomAccessSource
{
public:
    explicit Source(const BlockDevice& device) : device_(device) {}
    std::uint64_t SizeBytes() const override { return device_.GetGeometry().total_bytes; }
    bool Read(std::uint64_t at, std::size_t size, std::vector<std::byte>& out) const override
    {
        out.clear(); const auto total = SizeBytes();
        if (failed_ || at > total || size > total - at || size > (1u << 20)) return false;
        if (!size) return true;
        const auto low = at / 4096 * 4096, high = (at + size + 4095) / 4096 * 4096;
        if (high > total || reads_ == 65536 || high - low > (256ull << 20) - read_bytes_) { failed_ = true; return false; }
        ++reads_; read_bytes_ += high - low;
        std::vector<std::byte> bytes;
        if (!device_.ReadForVerification(low, static_cast<std::size_t>(high - low), bytes) || bytes.size() != high - low) { failed_ = true; return false; }
        out.assign(bytes.begin() + (at - low), bytes.begin() + (at - low + size)); return true;
    }
private:
    const BlockDevice& device_;
    mutable std::uint64_t reads_ = 0, read_bytes_ = 0;
    mutable bool failed_ = false;
};
class Overlay final : public catalog::RandomAccessSource
{
public:
    explicit Overlay(const catalog::RandomAccessSource& source) : source_(source) {}
    std::map<std::uint64_t, std::vector<std::byte>> blocks;
    std::uint64_t SizeBytes() const override { return source_.SizeBytes(); }
    std::shared_ptr<catalog::ApfsReadBudget> ReadBudget() const override { return source_.ReadBudget(); }
    bool Read(std::uint64_t at, std::size_t size, std::vector<std::byte>& out) const override
    {
        out.clear();
        if (at > SizeBytes() || size > SizeBytes() - at || !source_.Read(at, size, out) || out.size() != size) return false;
        for (const auto& [block, bytes] : blocks) {
            const auto start = block * 4096, low = (std::max)(at, start), high = (std::min)(at + size, start + 4096);
            if (low < high) std::copy_n(bytes.begin() + (low - start), high - low, out.begin() + (low - at));
        }
        return true;
    }
private:
    const catalog::RandomAccessSource& source_;
};
std::shared_ptr<catalog::ApfsReadBudget> Budget()
{ return std::make_shared<catalog::ApfsReadBudget>(65536, 256ull << 20, 131072, 128ull << 20); }
bool Wide(std::string_view text, std::wstring& out)
{
    out.clear(); if (text.empty() || text.size() > 4096 || text.find('\0') != text.npos) return false;
    const auto n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (n <= 0) return false; out.resize(n);
    return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), out.data(), n) == n;
}
bool Utf8(const std::wstring& text, std::string& out)
{
    out.clear(); const auto n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    if (n <= 0 || n > 4096) return false; out.resize(n);
    return WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), out.data(), n, nullptr, nullptr) == n;
}
std::wstring Canonical(const catalog::AppleCheckpointView& checkpoint, std::uint64_t volume)
{
    const auto& uuid = checkpoint.container.superblock.uuid_hex;
    return L"apfs-vol:" + std::wstring(uuid.begin(), uuid.end()) + L":" + std::to_wstring(volume);
}
std::uint64_t Resolve(const std::vector<catalog::BtreeRecord>& records, const ApfsNamePolicy& policy, const std::wstring& path)
{
    if (path.empty() || path.front() != L'\\') return 0;
    std::uint64_t parent = 2; std::size_t at = 1;
    for (unsigned depth = 0; at < path.size() && depth < 128; ++depth) {
        auto end = path.find(L'\\', at); if (end == path.npos) end = path.size();
        const auto key = ApfsNameCodec::CanonicalWindowsComponentKey(std::wstring_view(path).substr(at, end - at), policy);
        if (!key.ok()) return 0; std::uint64_t found = 0;
        for (const auto& record : records) {
            const auto header = catalog::ReadU64LE(record.key, 0).value_or(0);
            if ((header >> 60) != 9 || (header & 0x0fffffffffffffffULL) != parent) continue;
            AppleDirectoryRecord entry; std::string error;
            if (!ApfsExtendedRecordCodec::DecodeDirectory(record, policy, entry, error)) return 0;
            const auto name = ApfsNameCodec::Decode(std::as_bytes(std::span(entry.name_utf8)), policy);
            if (!name.ok()) return 0;
            const auto candidate = ApfsNameCodec::CanonicalWindowsComponentKey(name.value->windows_display, policy);
            if (!candidate.ok()) return 0;
            if (*candidate.value == *key.value) { if (found) return 0; found = entry.file_id; }
        }
        if (!found) return 0; parent = found; at = end + 1;
    }
    return at >= path.size() ? parent : 0;
}
bool Postimages(const AppleCheckpointPublicationPlan& plan, std::uint64_t total,
    std::map<std::uint64_t, std::vector<std::byte>>& out)
{
    out.clear();
    const auto add = [&](const auto& write) {
        if (write.bytes.empty() || write.bytes.size() % 4096 || write.physical_block >= total || write.bytes.size() / 4096 > total - write.physical_block) return false;
        for (std::size_t n = 0; n < write.bytes.size() / 4096; ++n)
            if (!out.emplace(write.physical_block + n, std::vector<std::byte>(write.bytes.begin() + n * 4096, write.bytes.begin() + (n + 1) * 4096)).second ||
                out.size() > NativeCloneRangeMaxPreimages) return false;
        return true;
    };
    return plan.block_size == 4096 && !plan.fusion_tier2_anchor_write &&
        std::all_of(plan.before_superblock_writes.begin(), plan.before_superblock_writes.end(), add) && add(plan.superblock_write);
}
bool Capture(const catalog::RandomAccessSource& source, const AppleCheckpointPublicationPlan& plan,
    NativeCloneRangeProof& proof, std::string& error)
{
    std::map<std::uint64_t, std::vector<std::byte>> writes;
    if (!Postimages(plan, proof.block_count, writes)) return Fail(error, "CloneRangeDestinationCensusInvalid");
    std::set<std::uint64_t> blocks{0}; for (const auto& [block, bytes] : writes) blocks.insert(block);
    for (const auto& guard : plan.guard_blocks) {
        if (guard.bytes.empty() || guard.bytes.size() % 4096 || guard.physical_block >= proof.block_count || guard.bytes.size() / 4096 > proof.block_count - guard.physical_block)
            return Fail(error, "CloneRangeGuardCensusInvalid");
        for (std::size_t n = 0; n < guard.bytes.size() / 4096; ++n) blocks.insert(guard.physical_block + n);
        if (blocks.size() > NativeCloneRangeMaxPreimages) return Fail(error, "CloneRangePreimageQuota");
    }
    if (blocks.size() > NativeCloneRangeMaxPreimages) return Fail(error, "CloneRangePreimageQuota");
    proof.preimages.clear();
    for (const auto block : blocks) {
        std::vector<std::byte> bytes; NativeHardLinkPreimage pre; pre.physical_block = block;
        if (!source.Read(block * 4096, 4096, bytes) || bytes.size() != 4096) return Fail(error, "CloneRangePreimageUnreadable");
        std::copy(bytes.begin(), bytes.end(), pre.bytes.begin()); proof.preimages.push_back(std::move(pre));
    }
    return true;
}
bool Evidence(const BlockDevice& device, const NativeCloneRangeProof& proof,
    const AppleCheckpointPublicationPlan& plan, unsigned mode, std::string& error)
{
    std::map<std::uint64_t, std::vector<std::byte>> writes;
    if (mode > 2 || !Postimages(plan, proof.block_count, writes)) return Fail(error, "CloneRangeEvidenceCensusInvalid");
    for (const auto& pre : proof.preimages) {
        std::vector<std::byte> bytes;
        if (!device.ReadForVerification(pre.physical_block * 4096, 4096, bytes) || bytes.size() != 4096) return Fail(error, "CloneRangeEvidenceUnreadable");
        const auto next = writes.find(pre.physical_block);
        const bool old = std::equal(bytes.begin(), bytes.end(), pre.bytes.begin());
        if (next == writes.end() || mode == 0) { if (!old) return Fail(error, "CloneRangeOriginalGuardChanged"); }
        else if (mode == 2) { if (bytes != next->second) return Fail(error, "CloneRangePublishedBytesChanged"); }
        else if (!old && bytes != next->second && catalog::ParseNxSuperblock(bytes)) return Fail(error, "CloneRangeForeignValidCheckpoint");
        if (next != writes.end()) writes.erase(next);
    }
    return writes.empty() || Fail(error, "CloneRangeDestinationEvidenceMissing");
}
bool ImageMatches(const BlockDevice& device, const NativeCloneRangeProof& proof)
{
    BlockDevice::StableImageIdentity image;
    return device.IsRegularFile() && !device.BaseOffsetBytes() && device.QueryHeldImageIdentity(image) &&
        image.volume_serial == proof.image_volume_serial && image.file_id == proof.image_file_id && image.size_bytes == proof.image_size &&
        image.creation_time == proof.image_creation_time;
}
bool Build(const catalog::RandomAccessSource& source, const catalog::AppleCheckpointView& checkpoint,
    NativeCloneRangeProof& proof, AppleVolumeTransactionPlan& plan, bool recovery, std::string& error)
{
    auto observed = proof; NativeCloneRangeState before;
    const auto planner = proof.version == 1 ? PlanNativeCloneRangeTransaction : PlanNativeCloneRangeTransactionV2;
    if ((proof.version != 1 && proof.version != 2) ||
        !planner(source, checkpoint, proof.volume_oid, proof.source_inode, proof.target_inode, proof.request, before, plan, error)) return false;
    std::wstring source_path, target_path;
    const auto policy = ApfsNamePolicy::FromIncompatibleFeatures(checkpoint.volumes.front().superblock.incompatible_features);
    if (!Wide(proof.source_path_utf8, source_path) || !Wide(proof.target_path_utf8, target_path) ||
        Resolve(before.source.filesystem, policy, source_path) != proof.source_inode || Resolve(before.source.filesystem, policy, target_path) != proof.target_inode)
        return Fail(error, "CloneRangeOriginalOpenIdentityMismatch");
    observed.checkpoint = checkpoint.container.superblock.xid;
    observed.source_generation = observed.target_generation = checkpoint.volumes.front().superblock.xid;
    observed.container_uuid = checkpoint.container.superblock.uuid_hex; observed.volume_uuid = checkpoint.volumes.front().superblock.uuid_hex;
    observed.block_count = checkpoint.container.superblock.block_count;
    if (!NativeHardLinkWritesExcludePayload(plan.commit.publication, before.source.payload, observed.block_count) ||
        !NativeHardLinkRecordsHash(before.source.filesystem, observed.before_sha) || !NativeHardLinkRecordsHash(before.source.references, observed.before_refs_sha) ||
        !NativeHardLinkExtentHash(before.source.payload, observed.payload_sha) || !NativeHardLinkPublicationHash(plan.commit.publication, observed.publication_sha))
        return Fail(error, "CloneRangeBeforeProofUnavailable");
    Overlay post(source);
    if (!Postimages(plan.commit.publication, observed.block_count, post.blocks)) return Fail(error, "CloneRangePostimageQuota");
    const auto after = catalog::LoadAppleCheckpointView(post, 0, post.SizeBytes(), error); NativeSparseState target;
    if (!after || after->container.superblock.xid != plan.commit.publication.transaction_xid ||
        !ReadNativeSparseStateV2(post, *after, proof.volume_oid, proof.target_inode, target, error) ||
        !NativeHardLinkRecordsHash(target.filesystem, observed.after_sha) || !NativeHardLinkRecordsHash(target.references, observed.after_refs_sha) ||
        !Capture(source, plan.commit.publication, observed, error)) return Fail(error, "CloneRangeAfterProofUnavailable");
    if (recovery && observed != proof) return Fail(error, "CloneRangeWholeOriginalBodyMismatch");
    proof = std::move(observed); return true;
}
}
bool MetadataStore::WithNativeCloneRangeSession(const NativeHardLinkOpenEntry& source,
    const NativeHardLinkOpenEntry& target, const CloneRangeSessionConsumer& consumer, std::string& error)
{
    error.clear();
    if (!consumer || source.object_id == target.object_id || immutable_snapshot_view_ || context_.shared_container_session || context_.allow_native_snapshot_runtime ||
        !CanUseAppleTransactionWriter() || recovery_required_ || !pending_mutations_.empty() || !device_ || !device_->IsRegularFile() ||
        device_->BaseOffsetBytes() || !authoritative_apple_checkpoint_view_ || committed_directory_links_.size() > 16384)
        return Fail(error, "CloneRangeSessionOwnerUnsupported");
    const auto epoch = StateEpoch(); const auto observation = device_->CaptureExclusiveWriteSourceObservation();
    if (!observation) return Fail(error, "CloneRangeExclusiveSourceRequired");
    const auto bind = [&](const NativeHardLinkOpenEntry& entry, std::wstring& path) {
        const auto inode = committed_inodes_.find(entry.object_id);
        if (inode == committed_inodes_.end() || !entry.generation || inode->second.xid != entry.generation || inode->second.node_type != NodeType::RegularFile) return false;
        unsigned matches = 0;
        for (const auto& link : committed_directory_links_) {
            if (link.child_object_id != entry.object_id || link.parent_object_id != entry.parent_object_id || link.sibling_id != entry.sibling_id || link.entry_name_utf8 != entry.name_utf8) continue;
            const auto parent = committed_inodes_.find(link.parent_object_id);
            if (++matches != 1 || parent == committed_inodes_.end() || !parent->second.is_directory) return false;
            path = parent->second.full_path == L"\\" ? L"\\" + link.entry_name : parent->second.full_path + L"\\" + link.entry_name;
        }
        const auto* selected = path.empty() ? nullptr : LookupCommittedInodeByPathView(path);
        return matches == 1 && selected && selected->object_id == entry.object_id && selected->xid == entry.generation;
    };
    std::wstring source_path, target_path;
    if (!bind(source, source_path) || !bind(target, target_path) || StateEpoch() != epoch ||
        !device_->IsExclusiveWriteSourceObservationCurrent(*observation)) return Fail(error, "CloneRangeSessionOpenBindingMismatch");
    NativeCloneRangeSession session(this, epoch, *observation, source, target, std::move(source_path), std::move(target_path));
    Finally invalidate{[&] { session.active_ = false; }};
    try {
        const bool done = consumer(session, error);
        if (session.ambiguous_ || (session.accepted_ && !done)) {
            MarkRecoveryRequired(L"NativeCloneRangeSessionOutcomeAmbiguous"); return Fail(error, "CloneRangeSessionOutcomeAmbiguous");
        }
        return done && session.consumed_ && session.accepted_;
    } catch (...) {
        if (session.accepted_ || session.ambiguous_) MarkRecoveryRequired(L"NativeCloneRangeSessionCallbackFailed");
        return Fail(error, "CloneRangeSessionCallbackFailed");
    }
}
MetadataStore::CloneRangeAcceptance MetadataStore::AcceptNativeCloneRange(TransactionManager& journal,
    const NativeCloneRangeSession& session, const NativeCloneRangeRequest& request, CloneRangeReceipt& receipt, std::string& error)
{
    receipt = {}; error.clear(); const auto refuse = [&](const char* text) { Fail(error, text); return CloneRangeAcceptance::Refused; };
    if (session.owner_ != this || !session.active_ || session.consumed_ || StateEpoch() != session.epoch_ ||
        !device_ || !device_->IsExclusiveWriteSourceObservationCurrent(session.observation_)) return refuse("CloneRangeSessionStaleForeignOrConsumed");
    session.consumed_ = true;
    if (!NativeCloneRangeRequestIsValid(request) || journal.ProtectedSourceBinding()) return refuse("CloneRangeRequestOrOriginalProfileUnsupported");
    const auto marks = journal.Watermarks(); std::vector<TransactionManager::AcceptedTransaction> debt;
    if (journal.CurrentState() != TransactionManager::State::Idle || !journal.RecoveryStateValid() || !journal.ObservedJournalWriterLeaseGeneration() ||
        marks.accepted_sequence != marks.apfs_durable_sequence || marks.accepted_sequence != marks.cleanup_sequence ||
        !journal.LoadAcceptedTransactionsSinceCleanup(debt, &error) || !debt.empty()) return refuse("CloneRangeOriginalNotClean");
    Source raw(*device_); catalog::BudgetedRandomAccessSource source(raw, Budget());
    const auto checkpoint = catalog::LoadAppleCheckpointView(source, 0, source.SizeBytes(), error); BlockDevice::StableImageIdentity image;
    if (!checkpoint || !device_->QueryHeldImageIdentity(image) || checkpoint->container.superblock_bytes != authoritative_apple_checkpoint_view_->container.superblock_bytes ||
        checkpoint->container.superblock.xid != checkpoint_xid_ || journal.EnrolledCanonicalJournalIdentity() != Canonical(*checkpoint, context_.volume_object_id))
        return refuse("CloneRangeCanonicalOwnerMismatch");
    NativeCloneRangeProof proof;
    proof.volume_oid = context_.volume_object_id; proof.source_inode = session.source_.object_id; proof.target_inode = session.target_.object_id; proof.request = request;
    proof.image_volume_serial = image.volume_serial; proof.image_file_id = image.file_id; proof.image_size = image.size_bytes; proof.image_creation_time = image.creation_time;
    if (!Utf8(session.source_path_, proof.source_path_utf8) || !Utf8(session.target_path_, proof.target_path_utf8)) return refuse("CloneRangePathEncodingInvalid");
    AppleVolumeTransactionPlan plan;
    if (!Build(source, *checkpoint, proof, plan, false, error)) return refuse("CloneRangePlanRefused");
    auto body = EncodeNativeCloneRange(proof); if (body.empty()) return refuse("CloneRangeProofInvalid");
    // Prove both fresh-owner replan paths fit the exact finite replay allowance
    // before the first original record is accepted or a target block is touched.
    for (const bool published : {false, true}) {
        Source replay_raw(*device_); Overlay old(replay_raw), post(replay_raw);
        for (const auto& pre : proof.preimages) old.blocks.emplace(pre.physical_block, std::vector<std::byte>(pre.bytes.begin(), pre.bytes.end()));
        if (published && !Postimages(plan.commit.publication, proof.block_count, post.blocks)) return refuse("CloneRangeReplayCapacityUnproven");
        const auto budget = Budget();
        catalog::BudgetedRandomAccessSource current(published ? static_cast<const catalog::RandomAccessSource&>(post) : static_cast<const catalog::RandomAccessSource&>(replay_raw), budget), historical(old, budget);
        const auto now = catalog::LoadAppleCheckpointView(current, 0, current.SizeBytes(), error);
        const auto before = catalog::LoadAppleCheckpointView(historical, 0, historical.SizeBytes(), error);
        auto exact = proof; AppleVolumeTransactionPlan rebuilt;
        if (!now || !before || now->container.superblock_bytes != (published ? plan.commit.publication.superblock_write.bytes : checkpoint->container.superblock_bytes) ||
            !Build(historical, *before, exact, rebuilt, true, error)) return refuse("CloneRangeReplayCapacityUnproven");
    }
    TransactionManager::MutationIntent intent;
    intent.kind = TransactionManager::MutationKind::CloneRange; intent.path = session.target_path_; intent.secondary_path = session.source_path_;
    intent.object_id = proof.target_inode; intent.generation = proof.checkpoint; intent.length = intent.payload_length = body.size(); intent.inline_payload = std::move(body);
    if (!NativeHardLinkHash(intent.inline_payload, intent.payload_checksum) || !AllowCommitStage("before-native-clone-range-accept") ||
        !Evidence(*device_, proof, plan.commit.publication, 0, error) || StateEpoch() != session.epoch_ ||
        !device_->IsExclusiveWriteSourceObservationCurrent(session.observation_)) return refuse("CloneRangePreacceptanceChanged");
    if (!journal.NativeCloneRangeEvidenceCapacityAvailable(intent, error)) return refuse("CloneRangeEvidenceCapacityExceeded");
    bool complete = false;
    Finally poison{[&] { if (!complete) { session.ambiguous_ = true; MarkRecoveryRequired(L"NativeCloneRangeAcceptanceRequiresRecovery"); } }};
    const auto uncertain = [&](const char* text) { Fail(error, text); return CloneRangeAcceptance::RecoveryRequired; };
    if (!journal.Begin()) return uncertain("CloneRangeBeginFailed"); const auto transaction = journal.CurrentTransactionId();
    if (!AllowCommitStage("after-native-clone-range-begin")) return uncertain("CloneRangeAcceptanceAmbiguous");
    if (!journal.RetainAcceptedSequenceProof(transaction) || !journal.CanAddInlinePayload(intent.inline_payload.size()) ||
        !journal.RecordMutation(intent) || !AllowCommitStage("after-native-clone-range-record") ||
        !journal.Accept(proof.checkpoint)) return uncertain("CloneRangeAcceptanceAmbiguous");
    receipt = {transaction, journal.Watermarks().accepted_sequence, proof.checkpoint, proof.source_inode, proof.target_inode};
    session.accepted_ = true; complete = true; return CloneRangeAcceptance::Accepted;
}
MetadataStore::CloneRangePublication MetadataStore::PublishOrRecoverNativeCloneRange(TransactionManager& journal, std::string& error)
{ return PublishOrRecoverNativeCloneRange(journal, {}, error); }
MetadataStore::CloneRangePublication MetadataStore::PublishOrRecoverNativeCloneRange(TransactionManager& journal,
    const CloneRangePostpublicationHook& hook, std::string& error)
{
    error.clear(); const auto refuse = [&](const char* text) { Fail(error, text); return CloneRangePublication::Refused; };
    if (immutable_snapshot_view_ || context_.shared_container_session || context_.allow_native_snapshot_runtime ||
        !CanUseAppleTransactionWriter() || recovery_required_ || !pending_mutations_.empty() || !device_ || !device_->IsRegularFile() ||
        device_->BaseOffsetBytes() || !authoritative_apple_checkpoint_view_ || journal.ProtectedSourceBinding()) return refuse("CloneRangeRecoveryOwnerUnsupported");
    const auto observation = device_->CaptureExclusiveWriteSourceObservation(); std::vector<TransactionManager::AcceptedTransaction> batches;
    if (!observation || journal.CurrentState() != TransactionManager::State::Idle || !journal.RecoveryStateValid() || !journal.ObservedJournalWriterLeaseGeneration() ||
        !journal.LoadAcceptedTransactionsSinceCleanup(batches, &error) || batches.size() != 1 || batches.front().mutations.size() != 1) return refuse("CloneRangeOriginalBoundaryUnproven");
    const auto& accepted = batches.front(); const auto& record = accepted.mutations.front(); NativeCloneRangeProof proof;
    std::wstring identity, source_path, target_path;
    if (!NativeCloneRangeWalIsConsistent(record) || !DecodeNativeCloneRange(record.inline_payload, proof) ||
        !Wide(record.volume_identity, identity) || identity != journal.ConfiguredVolumeIdentity() || accepted.transaction_id != record.transaction_id ||
        !accepted.accepted_sequence || record.sequence >= accepted.accepted_sequence || accepted.preimage_checkpoint_xid != proof.checkpoint ||
        journal.Watermarks().accepted_sequence != accepted.accepted_sequence || proof.volume_oid != context_.volume_object_id || !ImageMatches(*device_, proof) ||
        !Wide(proof.source_path_utf8, source_path) || source_path != NormalizePath(source_path) ||
        !Wide(proof.target_path_utf8, target_path) || target_path != NormalizePath(target_path)) return refuse("CloneRangeOriginalBindingMismatch");
    bool complete = false; Finally poison{[&] { if (!complete) MarkRecoveryRequired(L"NativeCloneRangePublicationRequiresRecovery"); }};
    const auto failed = [&](const char* text) { Fail(error, text); return CloneRangePublication::RecoveryRequired; };
    if (!journal.FlushAcceptedEvidenceDurability(accepted.accepted_sequence)) return failed("CloneRangeOriginalBarrierFailed");
    Source raw(*device_); const auto budget = Budget(); catalog::BudgetedRandomAccessSource source(raw, budget);
    const auto current = catalog::LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
    if (!current || current->container.superblock_bytes != authoritative_apple_checkpoint_view_->container.superblock_bytes ||
        journal.EnrolledCanonicalJournalIdentity() != Canonical(*current, proof.volume_oid)) return failed("CloneRangeRecoveryEndpointMismatch");
    Overlay old(raw);
    for (const auto& pre : proof.preimages) old.blocks.emplace(pre.physical_block, std::vector<std::byte>(pre.bytes.begin(), pre.bytes.end()));
    catalog::BudgetedRandomAccessSource historical(old, budget);
    const auto before = catalog::LoadAppleCheckpointView(historical, 0, historical.SizeBytes(), error);
    if (!before || before->container.superblock.xid != proof.checkpoint) return failed("CloneRangeOriginalPreimageUnavailable");
    AppleVolumeTransactionPlan transaction;
    if (!Build(historical, *before, proof, transaction, true, error)) return failed("CloneRangeWholeOriginalPlanMismatch");
    const auto& publication = transaction.commit.publication; const auto xid = publication.transaction_xid;
    if (current->container.superblock.xid != proof.checkpoint && current->container.superblock.xid != xid) return failed("CloneRangeForeignCanonicalCheckpoint");
    const bool published = current->container.superblock.xid == xid;
    if (!Evidence(*device_, proof, publication, published ? 2 : 1, error)) return failed("CloneRangePhysicalEvidenceChanged");
    const auto verify = [&] {
        Source verify_raw(*device_); catalog::BudgetedRandomAccessSource phase(verify_raw, Budget());
        const auto checkpoint = catalog::LoadAppleCheckpointView(phase, 0, phase.SizeBytes(), error); NativeSparseState source_state, target_state;
        NativeHardLinkDigest filesystem, refs;
        return checkpoint && checkpoint->container.superblock.xid == xid && checkpoint->container.superblock.uuid_hex == proof.container_uuid &&
            checkpoint->container.superblock_physical_block == publication.superblock_write.physical_block && checkpoint->container.superblock_bytes == publication.superblock_write.bytes &&
            checkpoint->volumes.size() == 1 && checkpoint->volumes.front().superblock.uuid_hex == proof.volume_uuid &&
            Evidence(*device_, proof, publication, 2, error) &&
            ReadNativeSparseStateV2(phase, *checkpoint, proof.volume_oid, proof.source_inode, source_state, error) &&
            ReadNativeSparseStateV2(phase, *checkpoint, proof.volume_oid, proof.target_inode, target_state, error) &&
            NativeHardLinkRecordsHash(target_state.filesystem, filesystem) && filesystem == proof.after_sha &&
            NativeHardLinkRecordsHash(target_state.references, refs) && refs == proof.after_refs_sha;
    };
    if (!AllowCommitStage("before-native-clone-range-publication") || !Evidence(*device_, proof, publication, published ? 2 : 1, error) ||
        !device_->IsExclusiveWriteSourceObservationCurrent(*observation)) return failed("CloneRangePublicationInterrupted");
    if (published) { if (!device_->Flush() || !verify()) return failed("CloneRangePublishedFlushFailed"); }
    else {
        auto execution = publication; std::map<std::uint64_t, std::vector<std::byte>> writes;
        if (!Postimages(publication, proof.block_count, writes)) return failed("CloneRangeDestinationCensusInvalid");
        for (auto& guard : execution.guard_blocks) for (std::size_t n = 0; n < guard.bytes.size() / 4096; ++n) {
            if (!writes.contains(guard.physical_block + n)) continue;
            std::vector<std::byte> bytes;
            if (!device_->ReadForVerification((guard.physical_block + n) * 4096, 4096, bytes) || bytes.size() != 4096) return failed("CloneRangeReplayGuardUnreadable");
            std::copy(bytes.begin(), bytes.end(), guard.bytes.begin() + n * 4096);
        }
        if (!ExecuteAppleCheckpointPublication(*device_, execution, error, [&](auto stage) { return AllowCommitStage(stage); }) || !verify()) return failed("CloneRangePublicationFailed");
    }
    if (!PrepareNativeWritePath()) return failed("CloneRangeCommittedReloadFailed"); const auto epoch = StateEpoch();
    const auto source_inode = LookupCommittedInodeByPath(source_path), target_inode = LookupCommittedInodeByPath(target_path);
    if (!source_inode || !target_inode || source_inode->object_id != proof.source_inode || target_inode->object_id != proof.target_inode ||
        (hook && (!hook(*this, error) || StateEpoch() != epoch))) return failed("CloneRangeHostPublicationFailed");
    if (!AllowCommitStage("before-native-clone-range-durable") || !verify() || !journal.MarkApfsDurableThrough(accepted.accepted_sequence) ||
        !AllowCommitStage("before-native-clone-range-cleaned") || !verify() || !journal.MarkCleanedThrough(accepted.accepted_sequence) ||
        !journal.FlushRetainedOriginalEvidenceDurability()) return failed("CloneRangeWatermarkFailed");
    journal.ReleaseAcceptedSequenceProof(accepted.transaction_id); complete = true;
    return published ? CloneRangePublication::AlreadyPublished : CloneRangePublication::Published;
}
}
