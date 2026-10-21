// Included after the typed transition decoder, inside apfsaccess::rw.
namespace
{
struct AuthorizationAbortIntent
{
    std::uint64_t version = 0, accepted = 0, transaction = 0, inode = 0;
    WriteAheadLog::ProtectedHistoryHead before;
    std::uint64_t next_transaction = 0, prefix = 0, terminal = 0;
    Digest body{}, original{}, scope{};
};
void AbortHead(Encoder& e, const WriteAheadLog::ProtectedHistoryHead& h)
{
    e.Number(h.bytes); e.Number(h.records); e.Number(h.last_sequence); e.Data(std::as_bytes(std::span(h.sha256)));
}
WriteAheadLog::ProtectedHistoryHead AbortHead(Decoder& d)
{
    WriteAheadLog::ProtectedHistoryHead h;
    h.bytes = d.Number(); h.records = d.Number(); h.last_sequence = d.Number();
    const auto hash = d.Data(32);
    if (hash.size() != 32) throw std::runtime_error("AuthorizationDispositionHead");
    std::memcpy(h.sha256.data(), hash.data(), 32); return h;
}
Digest AbortDigest(Decoder& d)
{
    Digest result{}; const auto bytes = d.Data(32);
    if (bytes.size() != 32) throw std::runtime_error("AuthorizationDispositionDigest");
    std::memcpy(result.data(), bytes.data(), 32); return result;
}
Digest AbortScope(const EncryptedPublicationJournal::Options& options)
{
    Encoder e; e.Text("apfs-unaccepted-authorization-disposition-v1");
    e.Data(options.witness.protected_persistence->source_binding);
    e.Data(options.maintenance_original_journal_identity);
    e.Data(options.witness.protected_persistence->journal_identity);
    e.Text(options.preimage_source_identity); e.Text(options.container_uuid); e.Text(options.volume_uuid);
    e.Number(options.container_bytes); e.Number(options.volume_object_id);
    Digest hash{}; if (!Hash(e.bytes, hash)) throw std::runtime_error("AuthorizationDispositionScope");
    return hash;
}
std::vector<std::byte> EncodeAbortIntent(const AuthorizationAbortIntent& a)
{
    Encoder e; e.Number(1); e.Number(a.version); e.Number(a.accepted); e.Number(a.transaction); e.Number(a.inode);
    AbortHead(e, a.before); e.Number(a.next_transaction); e.Number(a.prefix); e.Number(a.terminal);
    e.Data(std::as_bytes(std::span(a.body))); e.Data(std::as_bytes(std::span(a.original)));
    e.Data(std::as_bytes(std::span(a.scope))); return std::move(e.bytes);
}
AuthorizationAbortIntent DecodeAbortIntent(std::span<const std::byte> bytes)
{
    Decoder d{bytes}; AuthorizationAbortIntent a;
    if (d.Number() != 1) throw std::runtime_error("AuthorizationDispositionVersion");
    a.version = d.Number(); a.accepted = d.Number(); a.transaction = d.Number(); a.inode = d.Number();
    a.before = AbortHead(d); a.next_transaction = d.Number(); a.prefix = d.Number(); a.terminal = d.Number();
    a.body = AbortDigest(d); a.original = AbortDigest(d); a.scope = AbortDigest(d);
    if (!d.bytes.empty() || (a.version != 4 && a.version != 6 && a.version != 8) || !a.transaction || !a.next_transaction ||
        !a.accepted || a.accepted == UINT64_MAX || a.terminal > 1 || a.before.last_sequence > a.accepted ||
        a.accepted - a.before.last_sequence > max_bytes / chunk_bytes + 2)
        throw std::runtime_error("AuthorizationDispositionIntentInvalid");
    return a;
}
bool AbortTemplate(const WitnessGroup& group, const EncryptedPublicationJournal::Options& options,
    Witness& w, std::vector<std::byte>& original, std::string& error)
{
    w = Decode(group.bytes, options);
    if ((w.version != 4 && w.version != 6 && w.version != 8) || w.accepted != group.accepted ||
        w.transaction != group.transaction || w.inode != group.inode ||
        w.original_journal != options.maintenance_original_journal_identity ||
        w.source != options.preimage_source_identity || w.volume_object_id != options.volume_object_id ||
        w.volume_uuid != options.volume_uuid || w.inode != options.volume_object_id)
        return Fail(error, "AuthorizationDispositionTypedAuthorizationRequired");
    if ((w.version == 6 || w.version == 8) && !ValidateTransitionEnvelope(w, options, error)) return false;
    original = MaintenanceTemplate(w, options); Digest hash{};
    if (original.empty() || !Hash(original, hash) || w.length != original.size() || hash != w.replacement ||
        w.accepted <= (original.size() + chunk_bytes - 1) / chunk_bytes)
        return Fail(error, "AuthorizationDispositionTemplateMismatch");
    return true;
}
bool AbortPrefix(const std::vector<WriteAheadLog::Record>& records, std::size_t count,
    const Witness& w, std::span<const std::byte> bytes, std::uint64_t& prefix, bool& terminal, std::string& error)
{
    prefix = 0; terminal = false;
    const auto chunks = (bytes.size() + chunk_bytes - 1) / chunk_bytes;
    const auto first = w.accepted - chunks;
    if (count > records.size()) return Fail(error, "AuthorizationDispositionOriginalPrefixMissing");
    for (std::size_t n = 0; n < count; ++n) {
        const auto& r = records[n];
        if (r.transaction_id != w.transaction) {
            if (r.sequence >= first || (r.transaction_id && r.transaction_id > w.transaction))
                return Fail(error, "AuthorizationDispositionForeignOriginal");
            continue;
        }
        if (r.operation == WriteAheadLog::OperationKind::TransactionMarker) {
            if (terminal || r.state != WriteAheadLog::RecordState::Cleaned || r.flags != 2 ||
                r.sequence != first + prefix || r.logical_length != prefix || r.object_id || r.parent_object_id ||
                r.payload_length || r.payload_offset || r.payload_spool_id || r.logical_offset ||
                r.payload_sha256 != Digest{} || !r.inline_payload.empty() || !r.secondary_path_utf8.empty() || r.unlink_outcome)
                return Fail(error, "AuthorizationDispositionAcceptedOrContradictoryOriginal");
            terminal = true; continue;
        }
        const auto offset = static_cast<std::size_t>(prefix) * chunk_bytes;
        if (terminal || prefix >= chunks) return Fail(error, "AuthorizationDispositionOriginalPrefixMismatch");
        const auto part = bytes.subspan(offset, (std::min)(chunk_bytes, bytes.size() - offset)); Digest hash{};
        if (r.sequence != first + prefix || r.operation != WriteAheadLog::OperationKind::Write ||
            r.state != WriteAheadLog::RecordState::Prepared || r.object_id != w.inode ||
            r.parent_object_id != w.plan.expected_checkpoint_xid || r.flags || r.logical_offset != offset ||
            r.logical_length != part.size() || r.payload_length != part.size() || r.payload_offset ||
            r.payload_spool_id != r.sequence || r.unlink_outcome || !r.secondary_path_utf8.empty() ||
            r.path_utf8 != (w.version == 8 ? "\\$apfs-software-key-rotation-v1" :
                w.version == 6 ? "\\$apfs-software-transition-v1" : "\\$apfs-keybag-rewrap-v2") ||
            !Hash(part, hash) || r.payload_sha256 != hash || r.inline_payload.size() != part.size() ||
            !std::equal(part.begin(), part.end(), r.inline_payload.begin()))
            return Fail(error, "AuthorizationDispositionOriginalPrefixMismatch");
        ++prefix;
    }
    const auto last = count ? records[count - 1].sequence : first - 1;
    return last == first + prefix + (terminal ? 1 : 0) - 1 ||
        Fail(error, "AuthorizationDispositionOriginalPositionMismatch");
}
std::vector<WriteAheadLog::Record> AbortExtension(const AuthorizationAbortIntent& a, const std::string& identity)
{
    std::vector<WriteAheadLog::Record> rows;
    std::uint64_t transaction = a.next_transaction;
    for (auto sequence = a.before.last_sequence + 1; sequence <= a.accepted; ++sequence) {
        WriteAheadLog::Record r;
        r.volume_identity = identity; r.sequence = sequence;
        const bool close = rows.empty() && !a.terminal;
        r.transaction_id = close ? a.transaction : transaction++;
        if (r.transaction_id == UINT64_MAX || !r.transaction_id || transaction == UINT64_MAX)
            throw std::runtime_error("AuthorizationDispositionIdExhausted");
        r.operation = WriteAheadLog::OperationKind::TransactionMarker;
        r.state = WriteAheadLog::RecordState::Cleaned; r.flags = 2;
        r.logical_length = close ? a.prefix : 0;
        r.path_utf8 = "\\$apfs-unaccepted-authorization-spent-v1";
        rows.push_back(std::move(r));
    }
    return rows;
}
bool AbortExtensionDigest(const std::vector<WriteAheadLog::Record>& rows, Digest& digest)
{
    Encoder e; e.Text("apfs-authorization-abort-records-v1");
    for (const auto& row : rows) { const auto bytes = WriteAheadLog::EncodeForTest(row); e.Data(std::as_bytes(std::span(bytes))); }
    return Hash(e.bytes, digest);
}
std::vector<std::byte> AbortReceipt(std::span<const std::byte> intent, const WriteAheadLog::ProtectedHistoryHead& head,
    const std::vector<WriteAheadLog::Record>& extension)
{
    Digest intent_hash{}, extension_hash{};
    if (!Hash(intent, intent_hash) || !AbortExtensionDigest(extension, extension_hash))
        throw std::runtime_error("AuthorizationDispositionReceiptHash");
    Encoder e; e.Number(1); e.Data(std::as_bytes(std::span(intent_hash)));
    e.Data(std::as_bytes(std::span(extension_hash))); AbortHead(e, head); return std::move(e.bytes);
}
bool AbortIntentMatches(const AuthorizationAbortIntent& a, const WitnessGroup& group, const Witness& w,
    std::span<const std::byte> bytes, const EncryptedPublicationJournal::Options& options,
    const std::vector<WriteAheadLog::Record>& records, std::string& error)
{
    Digest body{}, original{}; std::uint64_t prefix = 0; bool terminal = false;
    if (!Hash(group.bytes, body) || !Hash(bytes, original) || a.body != body || a.original != original ||
        a.version != w.version || a.accepted != w.accepted || a.transaction != w.transaction || a.inode != w.inode ||
        a.next_transaction != w.transaction + 1 || a.scope != AbortScope(options) || !AbortPrefix(records, static_cast<std::size_t>(a.before.records),
            w, bytes, prefix, terminal, error) || prefix != a.prefix || terminal != (a.terminal != 0) ||
        a.before.last_sequence != w.accepted - (bytes.size() + chunk_bytes - 1) / chunk_bytes + prefix + (terminal ? 1 : 0) - 1)
        return Fail(error, "AuthorizationDispositionIntentMismatch");
    return true;
}
bool AbortRowsMatch(const AuthorizationAbortIntent& a, const std::vector<WriteAheadLog::Record>& records,
    const std::vector<WriteAheadLog::Record>& extension, bool complete, std::string& error)
{
    if (records.size() < a.before.records) return Fail(error, "AuthorizationDispositionOriginalRollback");
    const auto available = records.size() - static_cast<std::size_t>(a.before.records);
    if ((complete && available < extension.size()) || (!complete && available > extension.size()))
        return Fail(error, "AuthorizationDispositionOriginalExtentMismatch");
    for (std::size_t n = 0; n < (std::min)(available, extension.size()); ++n)
        if (WriteAheadLog::EncodeForTest(records[static_cast<std::size_t>(a.before.records) + n]) != WriteAheadLog::EncodeForTest(extension[n]))
            return Fail(error, "AuthorizationDispositionAbortRecordMismatch");
    return true;
}
}

bool EncryptedPublicationJournal::ValidateOriginalStreamConfiguration(const TransactionManager& tx, std::string& error) const
{
    const auto& original = tx.journal_protection_;
    const auto& witness = options_.witness.protected_persistence;
    const auto same = [](const auto& a, const auto& b) { return CompareStringOrdinal(a.c_str(), -1, b.c_str(), -1, TRUE) == CSTR_EQUAL; };
    if (!original || !witness || original->source_binding != witness->source_binding ||
        original->journal_identity != options_.maintenance_original_journal_identity ||
        original->journal_identity == witness->journal_identity || same(original->key_directory, witness->key_directory) ||
        same(std::filesystem::path(tx.journal_path_), options_.witness.path))
        return Fail(error, "AuthorizationDispositionStreamConfigurationInvalid");
    return true;
}

bool EncryptedPublicationJournal::ValidateUnacceptedDispositions(TransactionManager& tx,
    std::vector<std::uint64_t>& spent, std::string& error, bool allow_last_pending)
{
    spent.clear();
    try {
        if (!ValidateOriginalStreamConfiguration(tx, error)) return false;
        auto witness = witness_.ReadAllWithExclusiveWriterLease({64ull << 20, 4096}); Wipe wipe{witness.records};
        if (witness.status != WriteAheadLog::ReadStatus::Ok || witness.recovered_torn_tail)
            return Fail(error, "AuthorizationDispositionWitnessUnreadable");
        return ValidateUnacceptedDispositionRecords(tx, witness.records, spent, error, allow_last_pending, false);
    } catch (...) { return Fail(error, "AuthorizationDispositionInvalid"); }
}

bool EncryptedPublicationJournal::ValidateUnacceptedDispositionRecords(TransactionManager& tx,
    const std::vector<WriteAheadLog::Record>& authenticated_records, std::vector<std::uint64_t>& spent,
    std::string& error, bool allow_last_pending, bool allow_authenticated_incomplete_suffix)
{
    spent.clear();
    try {
        if (!ValidateOriginalStreamConfiguration(tx, error)) return false;
        std::vector<WitnessGroup> groups; WitnessGroup incomplete;
        if (!ReadGroups(authenticated_records, groups, error, allow_authenticated_incomplete_suffix ? &incomplete : nullptr))
            return Fail(error, "AuthorizationDispositionWitnessUnreadable");
        if (std::none_of(groups.begin(), groups.end(), [](const auto& g) { return !g.disposition_intent.empty(); })) return true;
        WriteAheadLog::ProtectedHistoryHead head; std::vector<WriteAheadLog::Record> records; Wipe clear{records};
        if (tx.ProtectedJournalIdentity() != std::optional{options_.maintenance_original_journal_identity} ||
            tx.ProtectedSourceBinding() != std::optional{options_.witness.protected_persistence->source_binding} ||
            !tx.ReadAuthorizationDispositionHistory(head, records, error)) return false;
        for (const auto& group : groups) {
            if (group.disposition_intent.empty()) continue;
            if (group.disposition_receipt.empty()) {
                if (allow_last_pending && &group == &groups.back()) continue;
                return Fail(error, "AuthorizationDispositionPending");
            }
            Witness w; std::vector<std::byte> original; TransitionBytesWipe original_wipe{original};
            if (!AbortTemplate(group, options_, w, original, error)) return false;
            Digest body_hash{};
            if (!Hash(group.bytes, body_hash)) return Fail(error, "AuthorizationDispositionHashFailed");
            std::optional<ProtectedJournalContinuation::Authority::RetainedAuthorization> retained;
            if (!ProtectedJournalContinuation::ReadRetainedAuthorization(tx, group.accepted, body_hash, retained, error)) return false;
            if (retained) {
                Digest intent_hash{}, receipt_hash{};
                if (!retained->spent || retained->version != w.version || retained->transaction != group.transaction ||
                    !Hash(group.disposition_intent, intent_hash) || !Hash(group.disposition_receipt, receipt_hash) ||
                    intent_hash != retained->intent_sha256 || receipt_hash != retained->receipt_sha256)
                    return Fail(error, "AuthorizationDispositionCertifiedReceiptMismatch");
                spent.push_back(group.accepted); continue;
            }
            const auto intent = DecodeAbortIntent(group.disposition_intent);
            if (!AbortIntentMatches(intent, group, w, original, options_, records, error) ||
                !tx.journal_.VerifyProtectedHistoryPrefix(intent.before)) return false;
            auto extension = AbortExtension(intent, TransactionManager::WideToUtf8(tx.volume_identity_)); Wipe extension_wipe{extension};
            if (!AbortRowsMatch(intent, records, extension, true, error)) return false;
            Decoder receipt{group.disposition_receipt};
            Digest intent_hash{}, extension_hash{};
            if (!Hash(group.disposition_intent, intent_hash) || !AbortExtensionDigest(extension, extension_hash) ||
                receipt.Number() != 1 || AbortDigest(receipt) != intent_hash || AbortDigest(receipt) != extension_hash)
                return Fail(error, "AuthorizationDispositionReceiptMismatch");
            const auto final_head = AbortHead(receipt);
            if (!receipt.bytes.empty() || final_head.records != intent.before.records + extension.size() ||
                final_head.last_sequence != intent.accepted || !tx.journal_.VerifyProtectedHistoryPrefix(final_head))
                return Fail(error, "AuthorizationDispositionOriginalReceiptMismatch");
            spent.push_back(group.accepted);
        }
        return true;
    } catch (...) { return Fail(error, "AuthorizationDispositionInvalid"); }
}

bool EncryptedPublicationJournal::ReconcileUnacceptedAuthorizations(TransactionManager& tx,
    ProtectedJournalContinuation::Endpoint& endpoint, std::string& error,
    const ProtectedJournalContinuation::StageHook& hook)
{
    error.clear();
    const auto cut = [&](std::string_view stage) { return !hook || hook(stage) || Fail(error, "AuthorizationDispositionInterrupted"); };
    try {
        const auto& source = endpoint.description_;
        if (!ValidateOriginalStreamConfiguration(tx, error)) return false;
        const bool prepared_recovery = !tx.RecoveryStateValid() && tx.CurrentState() == TransactionManager::State::Idle &&
            tx.journal_protection_ && tx.journal_.HasExclusiveWriterLease() && !tx.current_transaction_id_ &&
            !tx.journal_append_ambiguous_ && tx.pending_mutations_.empty() && tx.buffered_prepared_records_.empty();
        if (poisoned_) return Fail(error, "AuthorizationDispositionWitnessOwnerInvalid");
        if (!prepared_recovery && !tx.ProtectedSpoolOwnerValid()) {
            std::lock_guard lock(tx.deferred_wal_state_mutex_);
            error = "AuthorizationDispositionOriginalOwnerInvalid:valid=" + std::to_string(tx.RecoveryStateValid()) +
                ":state=" + std::to_string(static_cast<unsigned>(tx.CurrentState())) +
                ":current=" + std::to_string(tx.current_transaction_id_) + ":pending=" + std::to_string(tx.pending_mutations_.size()) +
                ":prepared=" + std::to_string(tx.buffered_prepared_records_.size()) +
                ":lease=" + std::to_string(tx.journal_.ExclusiveWriterLeaseGeneration()) +
                ":seedLease=" + std::to_string(tx.journal_state_writer_generation_) +
                ":ambiguous=" + std::to_string(tx.journal_append_ambiguous_) +
                ":flushFailed=" + std::to_string(tx.deferred_wal_flush_failed_) + ":flushing=" + std::to_string(tx.deferred_wal_flush_in_progress_);
            return false;
        }
        if (tx.ProtectedJournalIdentity() != std::optional{options_.maintenance_original_journal_identity} ||
            tx.ProtectedSourceBinding() != std::optional{options_.witness.protected_persistence->source_binding} ||
            source.source_binding != options_.witness.protected_persistence->source_binding ||
            source.source_identity != options_.preimage_source_identity || source.container_uuid != options_.container_uuid ||
            source.volume_uuid != options_.volume_uuid || source.volume_object_id != options_.volume_object_id ||
            source.container_bytes != options_.container_bytes || !endpoint.revalidate_ || !endpoint.read_guard_)
            return Fail(error, "AuthorizationDispositionOwnerMismatch");
        if (!endpoint.revalidate_(error)) return false;
        auto witness = witness_.ReadAllWithExclusiveWriterLease({64ull << 20, 4096}); Wipe wipe{witness.records};
        std::vector<WitnessGroup> groups;
        if (witness.status != WriteAheadLog::ReadStatus::Ok || witness.recovered_torn_tail ||
            !ReadGroups(witness.records, groups, error)) {
            // Repair only an accepted rotation whose private first certificate authenticates
            // the complete original template. This path never publishes APFS bytes.
            std::vector<TransactionManager::AcceptedTransaction> pending; AcceptedWipe pending_wipe{pending};
            if (!tx.LoadAcceptedTransactionsSinceCleanup(pending, &error) || pending.size() != 1 ||
                pending.front().mutations.empty() ||
                !std::all_of(pending.front().mutations.begin(), pending.front().mutations.end(), [](const auto& row) {
                    return row.operation == WriteAheadLog::OperationKind::Write &&
                        row.path_utf8 == TransactionManager::WideToUtf8(std::wstring(KeyRotationAcceptancePath));
                })) return Fail(error, "AuthorizationDispositionWitnessUnreadable");
            if (!RestageRetainedRewrite(tx, pending.front().accepted_sequence, 8, error) ||
                !endpoint.revalidate_(error)) return false;
            { Wipe clear{witness.records}; }
            witness = witness_.ReadAllWithExclusiveWriterLease({64ull << 20, 4096});
        }
        if (witness.status != WriteAheadLog::ReadStatus::Ok || witness.recovered_torn_tail || !ReadGroups(witness.records, groups, error))
            return Fail(error, "AuthorizationDispositionWitnessUnreadable");
        if (groups.empty()) return tx.RecoveryStateValid() || Fail(error, "AuthorizationDispositionPrivateAuthorizationRequired");
        auto& group = groups.back();
        if (std::any_of(groups.begin(), groups.end() - 1, [](const auto& prior) { return !prior.disposition_intent.empty(); })) {
            std::vector<std::uint64_t> prior_spent;
            if (!ValidateUnacceptedDispositions(tx, prior_spent, error, true)) return false;
        }
        const auto decoded = Decode(group.bytes, options_, false, OriginalJournalBinding::Historical);
        if (!group.disposition_receipt.empty()) {
            std::vector<std::uint64_t> spent; WriteAheadLog::ProtectedHistoryHead before, after, witness_before, witness_after;
            std::vector<WriteAheadLog::Record> rows; Wipe rows_wipe{rows};
            if (!ValidateUnacceptedDispositions(tx, spent, error) || !tx.ReadAuthorizationDispositionHistory(before, rows, error) ||
                !witness_.CaptureProtectedHistoryHead(witness_before) || !tx.journal_.FlushPendingAppends() || !witness_.FlushPendingAppends() ||
                !tx.journal_.CaptureProtectedHistoryHead(after) || after != before ||
                !witness_.CaptureProtectedHistoryHead(witness_after) || witness_after != witness_before || !endpoint.revalidate_(error))
                return Fail(error, "AuthorizationDispositionReceiptBarrierFailed");
            return true;
        }
        if (group.disposition_intent.empty() && group.accepted <= tx.Watermarks().accepted_sequence)
            return tx.RecoveryStateValid() || Fail(error, "AuthorizationDispositionPreparedPrefixInvalid");
        if (decoded.version != 4 && decoded.version != 6 && decoded.version != 8)
            return (!prepared_recovery && group.disposition_intent.empty()) || Fail(error, "AuthorizationDispositionTypedAuthorizationRequired");
        Witness w; std::vector<std::byte> original; TransitionBytesWipe original_wipe{original};
        if (!AbortTemplate(group, options_, w, original, error) || source.checkpoint_xid != w.plan.expected_checkpoint_xid)
            return Fail(error, "AuthorizationDispositionPreimageMismatch");
        auto block = crypto::SecureBytes::Allocate(4096);
        if (!block) return Fail(error, "AuthorizationDispositionGuardLockFailed");
        for (const auto& guard : w.plan.guard_blocks) {
            if (guard.bytes.size() != 4096 || guard.physical_block >= source.container_bytes / 4096 ||
                !endpoint.read_guard_(guard.physical_block * 4096, block.bytes.Bytes(), error) ||
                !std::equal(block.bytes.Bytes().begin(), block.bytes.Bytes().end(), guard.bytes.begin()))
                return Fail(error, "AuthorizationDispositionPreimageGuardMismatch");
        }
        WriteAheadLog::ProtectedHistoryHead head; std::vector<WriteAheadLog::Record> records; Wipe clear{records};
        if (!tx.ReadAuthorizationDispositionHistory(head, records, error)) return false;
        AuthorizationAbortIntent intent;
        if (group.disposition_intent.empty()) {
            const auto marks = tx.Watermarks();
            if (marks.accepted_sequence != marks.cleanup_sequence || marks.apfs_durable_sequence != marks.cleanup_sequence ||
                std::any_of(groups.begin(), groups.end() - 1, [&](const auto& g) {
                    return g.accepted > marks.cleanup_sequence && g.disposition_receipt.empty();
                })) return Fail(error, "AuthorizationDispositionPriorOriginalUnclean");
            bool terminal = false;
            intent.version = w.version; intent.accepted = w.accepted; intent.transaction = w.transaction; intent.inode = w.inode;
            intent.before = head; intent.next_transaction = (std::max)(tx.next_transaction_id_, w.transaction + 1);
            if (!AbortPrefix(records, records.size(), w, original, intent.prefix, terminal, error)) return false;
            const auto first = w.accepted - (original.size() + chunk_bytes - 1) / chunk_bytes;
            if (head.last_sequence != first + intent.prefix + (terminal ? 1 : 0) - 1 ||
                (!terminal && tx.next_transaction_id_ != w.transaction + (intent.prefix ? 1 : 0)) ||
                (terminal && tx.next_transaction_id_ != w.transaction + 1))
                return Fail(error, "AuthorizationDispositionOriginalIdMismatch");
            intent.terminal = terminal ? 1 : 0;
            if (!Hash(group.bytes, intent.body) || !Hash(original, intent.original)) return Fail(error, "AuthorizationDispositionHashFailed");
            intent.scope = AbortScope(options_); group.disposition_intent = EncodeAbortIntent(intent);
        } else intent = DecodeAbortIntent(group.disposition_intent);
        if (!AbortIntentMatches(intent, group, w, original, options_, records, error) ||
            !tx.journal_.VerifyProtectedHistoryPrefix(intent.before)) return false;
        auto extension = AbortExtension(intent, TransactionManager::WideToUtf8(tx.volume_identity_)); Wipe extension_wipe{extension};
        if (!AbortRowsMatch(intent, records, extension, false, error)) return false;
        const auto event = [&](std::string_view path, std::span<const std::byte> bytes, std::uint64_t sequence) {
            WriteAheadLog::Record r; r.sequence = sequence; r.transaction_id = w.transaction;
            r.volume_identity = options_.witness.volume_identity; r.operation = WriteAheadLog::OperationKind::Write;
            r.state = WriteAheadLog::RecordState::Prepared; r.object_id = w.inode; r.parent_object_id = w.accepted;
            r.path_utf8 = path; r.payload_length = r.logical_length = bytes.size(); r.inline_payload.assign(bytes.begin(), bytes.end());
            if (!Hash(bytes, r.payload_sha256)) throw std::runtime_error("AuthorizationDispositionEventHash");
            return r;
        };
        if (witness.records.empty() || witness.records.back().sequence > UINT64_MAX - 3)
            return Fail(error, "AuthorizationDispositionWitnessSequenceExhausted");
        const auto already_intent = witness.records.back().path_utf8 == disposition_intent_path;
        std::vector<WriteAheadLog::Record> capacity;
        Wipe capacity_wipe{capacity};
        auto sequence = witness.records.back().sequence + 1;
        if (!already_intent) capacity.push_back(event(disposition_intent_path, group.disposition_intent, sequence++));
        capacity.push_back(event(disposition_receipt_path, AbortReceipt(group.disposition_intent, head, extension), sequence));
        const auto completed = records.size() - static_cast<std::size_t>(intent.before.records);
        if (witness.records.size() > 4096 || capacity.size() > 4096 - witness.records.size() ||
            !witness_.ProtectedAppendCapacityAvailable(capacity) ||
            !tx.journal_.ProtectedAppendCapacityAvailable(std::span(extension).subspan(completed)))
            return Fail(error, "AuthorizationDispositionCapacityExceeded");
        const auto append_event = [&](std::string_view path, std::span<const std::byte> bytes) {
            auto current = witness_.ReadAllWithExclusiveWriterLease({64ull << 20, 4096}); Wipe current_wipe{current.records};
            if (current.status != WriteAheadLog::ReadStatus::Ok || current.recovered_torn_tail || current.records.empty() ||
                current.records.back().sequence == UINT64_MAX - 1) return Fail(error, "AuthorizationDispositionWitnessChanged");
            auto r = event(path, bytes, current.records.back().sequence + 1);
            if (witness_.AppendWithResult(r, true) != WriteAheadLog::AppendResult::Succeeded)
                return Fail(error, "AuthorizationDispositionWitnessAppendFailed");
            return true;
        };
        // The original barrier covers the exact retained head before intent publication.
        if ((head.bytes && !tx.journal_.FlushPendingAppends()) || !witness_.FlushPendingAppends() || !endpoint.revalidate_(error))
            return Fail(error, "AuthorizationDispositionOriginalBarrierFailed");
        {
            WriteAheadLog::ProtectedHistoryHead rechecked; std::vector<WriteAheadLog::Record> rows; Wipe rows_wipe{rows};
            if (!tx.ReadAuthorizationDispositionHistory(rechecked, rows, error) || rechecked != head)
                return Fail(error, "AuthorizationDispositionOriginalChanged");
        }
        if (!already_intent && !append_event(disposition_intent_path, group.disposition_intent)) return false;
        if (!cut("authorization-disposition-after-intent")) return false;
        for (std::size_t n = records.size() - static_cast<std::size_t>(intent.before.records); n < extension.size(); ++n) {
            if (!tx.AppendAuthorizationAbort(head, extension[n], error)) return false;
            { Wipe before_clear{records}; }
            records.clear();
            if (!tx.ReadAuthorizationDispositionHistory(head, records, error) || !endpoint.revalidate_(error)) return false;
            if (!cut("authorization-disposition-after-original-abort")) return false;
        }
        if (!cut("authorization-disposition-before-receipt")) return false;
        if (!append_event(disposition_receipt_path, AbortReceipt(group.disposition_intent, head, extension))) return false;
        if (!cut("authorization-disposition-after-receipt")) return false;
        std::vector<std::uint64_t> spent;
        return ValidateUnacceptedDispositions(tx, spent, error) && endpoint.revalidate_(error);
    } catch (...) { return Fail(error, "AuthorizationDispositionInvalid"); }
}
