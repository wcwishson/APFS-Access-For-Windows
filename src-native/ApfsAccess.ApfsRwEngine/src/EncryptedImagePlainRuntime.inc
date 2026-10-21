namespace
{
std::string PlainRuntimeReason(const std::wstring& value)
{
    if (value.empty()) return {};
    if (value.size() > 4096) return "NativeDiagnosticUnavailable";
    const auto count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (count <= 0) return "NativeDiagnosticUnavailable";
    std::string result(static_cast<std::size_t>(count), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()),
            result.data(), count, nullptr, nullptr) != count) return "NativeDiagnosticUnavailable";
    return result;
}
}

bool EncryptedImageRuntime::Impl::ApplyPlainWrite(const EncryptedMutationRequest& request,
    std::uint64_t& result_inode, std::string& error, const r::AppleCheckpointStageHook& hook)
{
    if ((request.kind != Op::Write && request.kind != Op::Overwrite) || request.inode < 16 ||
        request.data.empty() || request.data.size() > 4096 || request.offset > UINT64_MAX - request.data.size()) {
        error = "EncryptedRuntimePlainInlineWriteProfileRequired"; return false;
    }
    if (recovery.load() && !Recover(error, hook)) return false;
    const auto preimage = image->CachedStatus().checkpoint_xid;
    std::uint64_t sequence = 0;
    const auto success = image->WithTransitionPlainStore(*transactions, *witness,
        ApfsEncryptedImageWriteSession::PlainWriterPurpose::Mutation, 0,
        [&](r::MetadataStore& store, std::string& detail) {
            if (!store.PrepareNativeWritePath() || store.CheckpointXid() != preimage) {
                detail = "EncryptedRuntimePlainPreimageRequired:" + PlainRuntimeReason(store.LastCanonicalGateFailure()); return false;
            }
            const auto inode = store.LookupCommittedInodeByObjectId(request.inode);
            if (!inode || request.offset || request.data.size() != inode->logical_size) {
                detail = "EncryptedRuntimePlainExistingFileRangeRequired"; return false;
            }
            r::MetadataStore::MutationRequest write;
            write.path = inode->full_path; write.offset = request.offset; write.length = request.data.size();
            r::MetadataStore::PayloadIdentity identity;
            if (store.StageMutation(write, &identity) != r::MetadataStore::MutationStatus::Applied) {
                detail = "EncryptedRuntimePlainStageFailed:" + PlainRuntimeReason(store.LastMutationFailureReason()); return false;
            }
            r::TransactionManager::MutationIntent intent; IntentWipe wipe{intent};
            intent.path = write.path; intent.object_id = identity.object_id; intent.generation = identity.generation;
            intent.offset = request.offset; intent.length = intent.payload_length = request.data.size();
            intent.inline_payload.assign(request.data.begin(), request.data.end()); intent.payload_checksum = Digest(request.data);
            if (!transactions->ProtectedMutationCapacityAvailable(intent, detail)) return false;
            if (!transactions->Begin()) { detail = "EncryptedRuntimePlainBeginFailed"; return false; }
            if (!transactions->RecordMutation(intent) || !transactions->FlushPreparedRecords() || !transactions->Accept(preimage)) {
                if (transactions->CurrentState() == r::TransactionManager::State::Active) (void)transactions->Abort();
                if (detail.empty()) detail = "EncryptedRuntimePlainOriginalAcceptanceFailed";
                return false;
            }
            sequence = transactions->Watermarks().accepted_sequence; Observe();
            if (hook && !hook("after-software-plain-original-accept")) { detail = "EncryptedRuntimePlainInterruptedBeforeCommit"; return false; }
            store.SetFilePayloadRangeProvider([&](const auto& path, auto actual, auto at, std::span<std::byte> bytes) {
                if (path != write.path || actual.object_id != identity.object_id || actual.generation != identity.generation ||
                    at < request.offset || at - request.offset > request.data.size() ||
                    bytes.size() > request.data.size() - (at - request.offset)) return false;
                std::copy_n(request.data.begin() + static_cast<std::ptrdiff_t>(at - request.offset), bytes.size(), bytes.begin()); return true;
            });
            store.SetCommitStageHook(hook);
            if (store.CommitPendingMutations({preimage}) != r::MetadataStore::CommitStatus::Committed || store.CheckpointXid() != preimage + 1) {
                detail = "EncryptedRuntimePlainCommitFailed:" + PlainRuntimeReason(store.LastCommitFailureDetail()); return false;
            }
            if (hook && !hook("after-software-plain-publication")) { detail = "EncryptedRuntimePlainInterruptedAfterPublication"; return false; }
            if (!transactions->MarkApfsDurableThrough(sequence)) { detail = "EncryptedRuntimePlainDurableBoundaryFailed"; return false; }
            return true;
        }, error);
    if (!success && !sequence && image->CachedStatus().recovery_required) owner_failed = true;
    Observe();
    if (!success || !sequence || !Finish(sequence, error)) return false;
    result_inode = request.inode; return true;
}

bool EncryptedImageRuntime::Impl::RecoverPlainWrite(const r::TransactionManager::AcceptedTransaction& accepted_tx,
    std::string& error, const r::AppleCheckpointStageHook& hook)
{
    const auto& record = accepted_tx.mutations.front();
    const auto sequence = accepted_tx.accepted_sequence, preimage = accepted_tx.preimage_checkpoint_xid;
    if (!sequence || !preimage || preimage == UINT64_MAX || record.object_id < 16 || !record.parent_object_id ||
        record.payload_length == 0 || record.payload_length > 4096 || record.inline_payload.size() != record.payload_length ||
        record.payload_spool_id != record.sequence || record.logical_offset > UINT64_MAX - record.payload_length ||
        Digest(record.inline_payload) != record.payload_sha256) {
        error = "EncryptedRuntimePlainAcceptedInlineBoundaryRequired"; recovery.store(true); return false;
    }
    const auto success = image->WithTransitionPlainStore(*transactions, *witness,
        ApfsEncryptedImageWriteSession::PlainWriterPurpose::AcceptedRecovery, sequence,
        [&](r::MetadataStore& store, std::string& detail) {
            if (!store.PrepareNativeWritePath()) { detail = "EncryptedRuntimePlainReplayPrepareFailed"; return false; }
            if (store.CheckpointXid() == preimage + 1) {
                std::vector<std::uint64_t> applied;
                if (!store.ProveRetainedAcceptedPrefix(*transactions, *payload, options.recovery_directory / L"original.wal",
                        volume_utf8, applied, detail) || applied != std::vector<std::uint64_t>{sequence}) return false;
            } else {
                if (store.CheckpointXid() != preimage) { detail = "EncryptedRuntimePlainReplayPreimageRequired"; return false; }
                const auto inode = store.LookupCommittedInodeByObjectId(record.object_id);
                if (!inode || inode->full_path != Wide(record.path_utf8) || record.logical_offset > inode->logical_size ||
                    record.payload_length > inode->logical_size - record.logical_offset) {
                    detail = "EncryptedRuntimePlainReplayIncarnationMismatch"; return false;
                }
                r::MetadataStore::MutationRequest write;
                write.path = inode->full_path; write.offset = record.logical_offset; write.length = record.payload_length;
                write.object_id = record.object_id; write.generation = record.parent_object_id;
                r::MetadataStore::PayloadIdentity identity;
                if (store.StageMutation(write, &identity) != r::MetadataStore::MutationStatus::Applied ||
                    identity.object_id != record.object_id || identity.generation != record.parent_object_id) {
                    detail = "EncryptedRuntimePlainReplayStageMismatch"; return false;
                }
                store.SetFilePayloadRangeProvider([&](const auto& path, auto actual, auto at, std::span<std::byte> bytes) {
                    if (path != write.path || actual.object_id != identity.object_id || actual.generation != identity.generation ||
                        at < record.logical_offset || at - record.logical_offset > record.inline_payload.size() ||
                        bytes.size() > record.inline_payload.size() - (at - record.logical_offset)) return false;
                    std::copy_n(record.inline_payload.begin() + static_cast<std::ptrdiff_t>(at - record.logical_offset), bytes.size(), bytes.begin()); return true;
                });
                store.SetCommitStageHook(hook);
                if (store.CommitPendingMutations({preimage}) != r::MetadataStore::CommitStatus::Committed ||
                    store.CheckpointXid() != preimage + 1) {
                    detail = "EncryptedRuntimePlainReplayCommitFailed:" + PlainRuntimeReason(store.LastCommitFailureDetail()); return false;
                }
            }
            const auto marks = transactions->Watermarks();
            if (marks.apfs_durable_sequence < sequence && !transactions->MarkApfsDurableThrough(sequence)) {
                detail = "EncryptedRuntimePlainReplayDurableBoundaryFailed"; return false;
            }
            return true;
        }, error);
    Observe();
    if (!success) { recovery.store(true); return false; }
    return Finish(sequence, error);
}
