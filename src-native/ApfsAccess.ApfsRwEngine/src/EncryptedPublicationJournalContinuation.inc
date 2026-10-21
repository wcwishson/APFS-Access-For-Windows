// Included inside apfsaccess::rw, after the ordinary Journal implementation.
bool EncryptedPublicationJournal::ReadCertifiedTransitionOriginal(TransactionManager& tx, std::uint64_t accepted,
    std::span<const std::byte> body, TransactionManager::AcceptedTransaction& output, bool& found, std::string& error)
{
    output = {}; found = false;
    Digest digest{};
    if (!Hash(body, digest)) return Fail(error, "ContinuationRetainedAuthorizationHashFailed");
    std::optional<ProtectedJournalContinuation::Authority::RetainedAuthorization> retained;
    if (!ProtectedJournalContinuation::ReadRetainedAuthorization(tx, accepted, digest, retained, error)) return false;
    if (!retained || retained->spent) return true;
    try {
        auto witness = Decode(body, options_);
        if (!IsRetainedRewrite(witness.version) || witness.accepted != accepted || witness.transaction != retained->transaction ||
            retained->version != witness.version || !ValidateTransitionEnvelope(witness, options_, error)) return false;
        TransactionManager::AcceptedTransaction original; Wipe clear_original{original.mutations};
        original.transaction_id = witness.transaction; original.accepted_sequence = accepted;
        original.preimage_checkpoint_xid = witness.plan.expected_checkpoint_xid;
        for (const auto& encoded : retained->original_records) {
            WriteAheadLog::Record record;
            if (!WriteAheadLog::DecodeCertifiedOriginalRecord(encoded, TransactionManager::WideToUtf8(tx.volume_identity_), record))
                return Fail(error, "ContinuationRetainedOriginalInvalid");
            if (record.operation == WriteAheadLog::OperationKind::TransactionMarker) {
                if (record.sequence != accepted || record.transaction_id != witness.transaction || record.flags != 8 ||
                    record.state != WriteAheadLog::RecordState::Accepted || record.logical_length != original.mutations.size() ||
                    record.object_id != witness.plan.expected_checkpoint_xid || &encoded != &retained->original_records.back())
                    return Fail(error, "ContinuationRetainedOriginalBoundaryMismatch");
            } else original.mutations.push_back(std::move(record));
        }
        if (retained->original_records.empty() || retained->original_records.size() != original.mutations.size() + 1 ||
            !MatchTransitionOriginal(original, witness, options_, error)) return false;
        output = std::move(original); found = true; return true;
    } catch (...) { return Fail(error, "ContinuationRetainedTransitionInvalid"); }
}

namespace
{
struct ContinuationAccepted
{
    const WriteAheadLog::Record* marker = nullptr;
    std::vector<const WriteAheadLog::Record*> mutations;
};
bool ContinuationMatchOriginal(const ContinuationAccepted& actual, const Witness& w,
    const EncryptedPublicationJournal::Options& options, const std::array<std::byte, 32>& original_jid,
    std::string& error)
{
    const auto fail = [&] { return Fail(error, "ContinuationAcceptedIntentMismatch"); };
    if (!actual.marker || actual.marker->sequence != w.accepted || actual.marker->transaction_id != w.transaction ||
        actual.marker->object_id != w.plan.expected_checkpoint_xid ||
        (w.version >= 4 && w.original_journal != original_jid)) return fail();
    if (IsRetainedRewrite(w.version)) {
        if (!ValidateTransitionEnvelope(w, options, error)) return false;
        TransactionManager::AcceptedTransaction tx;
        tx.transaction_id = w.transaction; tx.accepted_sequence = w.accepted;
        tx.preimage_checkpoint_xid = actual.marker->object_id;
        for (const auto* row : actual.mutations) tx.mutations.push_back(*row);
        Wipe clear{tx.mutations};
        return MatchTransitionOriginal(tx, w, options, error);
    }
    if (w.version == 4) {
        auto original = MaintenanceTemplate(w, options);
        struct Clear { std::vector<std::byte>& bytes; ~Clear() { SecureZeroMemory(bytes.data(), bytes.size()); } } clear{original};
        Digest digest{};
        if (w.inode != options.volume_object_id || w.offset || w.parent || w.destination_parent ||
            w.kind != catalog::EncryptedMutationKind::Overwrite || w.result_size || w.permissions || w.effective_mode ||
            w.name != Digest{} || w.destination_name != Digest{} || !Hash(original, digest) ||
            w.length != original.size() || w.replacement != digest ||
            actual.mutations.size() != (original.size() + chunk_bytes - 1) / chunk_bytes) return fail();
        std::size_t offset = 0;
        for (const auto* row : actual.mutations) {
            const auto& m = *row;
            const auto bytes = std::span(original).subspan(offset, (std::min)(chunk_bytes, original.size() - offset));
            if (m.operation != WriteAheadLog::OperationKind::Write || m.object_id != w.inode ||
                m.parent_object_id != w.plan.expected_checkpoint_xid || m.logical_offset != offset ||
                m.logical_length != bytes.size() || m.payload_length != bytes.size() || m.payload_offset || m.flags ||
                m.unlink_outcome || m.path_utf8 != "\\$apfs-keybag-rewrap-v2" || !m.secondary_path_utf8.empty() ||
                m.inline_payload.size() != bytes.size() || !std::equal(m.inline_payload.begin(), m.inline_payload.end(), bytes.begin()) ||
                !Hash(bytes, digest) || digest != m.payload_sha256) return fail();
            offset += bytes.size();
        }
        return true;
    }
    if ((w.version != 2 && w.version != 5 && w.version != 7) || actual.mutations.size() != 1) return fail();
    if ((w.version == 5 || w.version == 7) &&
        !std::binary_search(w.required_checkpoints.begin(), w.required_checkpoints.end(), w.plan.expected_checkpoint_xid)) return fail();
    const auto& m = *actual.mutations.front();
    if (!SupportedDataIntent(m, w.plan.expected_checkpoint_xid) || m.object_id != w.inode || m.unlink_outcome ||
        m.flags != (w.kind == catalog::EncryptedMutationKind::ReplaceRename ? 0x4u : 0u)) return fail();
    const auto name_matches = [&](const std::string& name, const Digest& expected) {
        Digest digest{}; return !name.empty() && name.size() <= 255 && name != "." && name != ".." &&
            name.find('\0') == name.npos && name.find('/') == name.npos && Hash(std::as_bytes(std::span(name)), digest) && digest == expected;
    };
    const auto payload = [&] { return m.payload_length == w.length && m.payload_sha256 == w.replacement; };
    const auto no_payload = [&] { return !m.payload_length && !m.payload_offset && !m.payload_spool_id &&
        m.inline_payload.empty() && m.payload_sha256 == Digest{}; };
    using Kind = catalog::EncryptedMutationKind; using Op = WriteAheadLog::OperationKind;
    switch (w.kind) {
    case Kind::Overwrite:
    case Kind::Write:
        return (m.operation == Op::Write && w.length &&
            (m.parent_object_id == w.plan.expected_checkpoint_xid || (!m.parent_object_id && !m.inline_payload.empty())) &&
            m.logical_offset == w.offset && m.logical_length == w.length && payload() && m.secondary_path_utf8.empty()) || fail();
    case Kind::Create:
        return (m.operation == Op::CreateFile && w.parent >= 2 && !w.destination_parent &&
            w.effective_mode == (0100000 | w.permissions) && m.parent_object_id == w.parent &&
            m.logical_offset == w.permissions && m.logical_length == w.length && w.result_size == w.length && payload() &&
            name_matches(m.path_utf8, w.name) && m.secondary_path_utf8.empty()) || fail();
    case Kind::MakeDirectory:
        return (m.operation == Op::CreateDirectory && w.parent >= 2 && !w.destination_parent && !w.offset &&
            !w.length && !w.result_size && w.effective_mode == (0040000 | w.permissions) && m.parent_object_id == w.parent &&
            m.logical_offset == w.permissions && !m.logical_length && no_payload() &&
            name_matches(m.path_utf8, w.name) && m.secondary_path_utf8.empty()) || fail();
    case Kind::SetInodeMetadata:
        return (m.operation == Op::SetInodeMetadata && !w.offset && !w.parent && !w.destination_parent &&
            m.parent_object_id == w.plan.expected_checkpoint_xid && !m.logical_offset && !m.logical_length && !m.payload_offset &&
            !m.payload_spool_id && m.secondary_path_utf8.empty() && payload() && WriteAheadLog::InlinePayloadIsConsistent(m) &&
            WriteAheadLog::InodeMetadataMutationIsConsistent(m)) || fail();
    case Kind::SetExtendedAttribute:
    case Kind::RemoveExtendedAttribute:
    {
        Digest name{}; const bool set = w.kind == Kind::SetExtendedAttribute;
        return (w.version == 7 && m.operation == (set ? Op::SetExtendedAttribute : Op::RemoveExtendedAttribute) &&
            !w.offset && !w.parent && !w.destination_parent && m.parent_object_id == w.plan.expected_checkpoint_xid &&
            m.path_utf8 == "encrypted-data" && WriteAheadLog::ExtendedAttributeMutationIsConsistent(m) &&
            Hash(std::as_bytes(std::span(m.secondary_path_utf8)), name) && name == w.name &&
            (set ? payload() : (!w.length && no_payload()))) || fail();
    }
    case Kind::Resize:
        return (m.operation == Op::SetFileSize && !m.parent_object_id && !m.logical_offset && m.logical_length == w.result_size &&
            no_payload() && m.secondary_path_utf8.empty()) || fail();
    case Kind::Rename:
    case Kind::ReplaceRename:
        return (m.operation == Op::Rename && w.parent >= 2 && w.destination_parent >= 2 &&
            (w.kind != Kind::ReplaceRename || ((w.version == 5 || w.version == 7) && (w.effective_mode & 0170000) == 0100000)) &&
            m.parent_object_id == w.parent && m.logical_offset == w.destination_parent && !m.logical_length && no_payload() &&
            name_matches(m.path_utf8, w.name) && name_matches(m.secondary_path_utf8, w.destination_name)) || fail();
    case Kind::Unlink:
        return (m.operation == Op::Delete && w.parent >= 2 && !w.destination_parent && m.parent_object_id == w.parent &&
            !m.logical_offset && !m.logical_length && no_payload() && name_matches(m.path_utf8, w.name) && m.secondary_path_utf8.empty()) || fail();
    }
    return fail();
}
}

bool EncryptedPublicationJournal::AuthorizeCleanContinuation(
    const ProtectedJournalContinuation::RecoveryEvidence& evidence, const WriteAheadLog::Options& original_options,
    ProtectedJournalContinuation::Endpoint& endpoint, ProtectedJournalContinuation::Authority& authority, std::string& error)
{
    using C = ProtectedJournalContinuation;
    authority = {}; error.clear();
    const auto fail = [&](const char* reason) { return Fail(error, reason); };
    try {
        const auto& d = endpoint.description_;
        const auto& original = original_options.protected_persistence;
        const auto& witness = options_.witness.protected_persistence;
        const auto same_path = [](const std::filesystem::path& a, const std::filesystem::path& b) {
            return CompareStringOrdinal(a.c_str(), -1, b.c_str(), -1, TRUE) == CSTR_EQUAL;
        };
        if (poisoned_ || !original || !witness || !endpoint.revalidate_ || !endpoint.read_guard_ ||
            !endpoint.revalidate_(error) || original->source_binding != d.source_binding || witness->source_binding != d.source_binding ||
            original->journal_identity != options_.maintenance_original_journal_identity ||
            same_path(original->key_directory, witness->key_directory) || same_path(original_options.path, options_.witness.path) ||
            d.source_identity != options_.preimage_source_identity || d.container_uuid != options_.container_uuid ||
            d.volume_uuid != options_.volume_uuid || d.volume_object_id != options_.volume_object_id ||
            d.container_bytes != options_.container_bytes || !d.checkpoint_xid || d.physical_nx_bytes.size() != 4096 ||
            d.physical_nx_offset % 4096 || d.physical_nx_offset > d.container_bytes ||
            d.physical_nx_bytes.size() > d.container_bytes - d.physical_nx_offset)
            return fail("ContinuationEndpointScopeMismatch");
        Digest nx{};
        if (!Hash(d.physical_nx_bytes, nx) || nx != d.physical_nx_sha256 ||
            evidence.witness.status != WriteAheadLog::ReadStatus::Ok || evidence.witness.recovered_torn_tail ||
            evidence.witness.records.size() != evidence.witness_head.records)
            return fail("ContinuationAuthenticatedEvidenceInvalid");
        C::Seed current;
        if (!C::ValidateOriginalEvidence(evidence, current, error)) return false;
        if (!current.accepted_sequence || (!evidence.admission_only &&
            (current.accepted_sequence != current.durable_sequence || current.accepted_sequence != current.cleanup_sequence)))
            return fail("ContinuationOriginalNotClean");
        std::map<std::uint64_t, std::vector<const WriteAheadLog::Record*>> pending;
        std::map<std::uint64_t, ContinuationAccepted> accepted;
        for (const auto& record : evidence.original.records) {
            if (record.operation == WriteAheadLog::OperationKind::DurabilityWatermark) continue;
            if (record.operation == WriteAheadLog::OperationKind::TransactionMarker) {
                const auto found = pending.find(record.transaction_id);
                if (record.state == WriteAheadLog::RecordState::Accepted && record.flags == 8) {
                    if (found == pending.end() || found->second.size() != record.logical_length ||
                        !accepted.emplace(record.sequence, ContinuationAccepted{&record, std::move(found->second)}).second)
                        return fail("ContinuationOriginalBoundaryInvalid");
                } else if (record.state != WriteAheadLog::RecordState::Cleaned || record.flags != 2) {
                    return fail("ContinuationOriginalTerminalUnsupported");
                }
                if (found != pending.end()) pending.erase(found);
            } else pending[record.transaction_id].push_back(&record);
        }
        std::vector<WitnessGroup> groups;
        if (!ReadGroups(evidence.witness.records, groups, error) || groups.empty()) return fail("ContinuationCompleteWitnessRequired");
        std::set<std::uint64_t> matched;
        std::optional<Witness> selected;
        std::uint64_t prior_xid = 0;
        for (std::size_t n = 0; n < groups.size(); ++n) {
            const auto& group = groups[n];
            auto body = Decode(group.bytes, options_, false, OriginalJournalBinding::Selected);
            Digest body_hash{};
            if (!Hash(group.bytes, body_hash)) return fail("ContinuationRetainedHashFailed");
            const auto certificate_row = std::find_if(evidence.certificate_authority.retained_authorizations.begin(),
                evidence.certificate_authority.retained_authorizations.end(), [&](const auto& row) {
                    return row.accepted == body.accepted && row.body_sha256 == body_hash;
                });
            const bool certified = certificate_row != evidence.certificate_authority.retained_authorizations.end();
            const bool certified_endpoint = evidence.active_original_seed.last_sequence &&
                body.accepted == evidence.active_original_seed.cleanup_sequence &&
                body_hash == evidence.certificate_authority.complete_publication_sha256;
            if (body.accepted != group.accepted || body.transaction != group.transaction || body.inode != group.inode ||
                body.source != d.source_identity || (body.version >= 4 && body.original_journal != original->journal_identity) ||
                (prior_xid && body.plan.expected_checkpoint_xid != prior_xid && !certified && !certified_endpoint))
                return fail("ContinuationWitnessChainMismatch");
            if (evidence.admission_only && &group == &groups.back() && body.accepted > current.accepted_sequence &&
                (body.version == 4 || IsRetainedRewrite(body.version)) && group.disposition_receipt.empty()) {
                Witness authorized; std::vector<std::byte> bytes; TransitionBytesWipe clear{bytes};
                if (!AbortTemplate(group, options_, authorized, bytes, error) || body.plan.expected_checkpoint_xid != d.checkpoint_xid)
                    return fail("ContinuationUnacceptedAuthorizationMismatch");
                if (group.disposition_intent.empty()) {
                    std::uint64_t prefix = 0; bool terminal = false;
                    if (!AbortPrefix(evidence.original.records, evidence.original.records.size(), body, bytes, prefix, terminal, error)) return false;
                } else {
                    const auto intent = DecodeAbortIntent(group.disposition_intent);
                    auto extension = AbortExtension(intent, original_options.volume_identity); Wipe rows_wipe{extension};
                    if (!AbortIntentMatches(intent, group, body, bytes, options_, evidence.original.records, error) ||
                        !AbortRowsMatch(intent, evidence.original.records, extension, false, error)) return false;
                }
                auto block = crypto::SecureBytes::Allocate(4096);
                if (!block) return fail("ContinuationUnacceptedGuardLockFailed");
                for (const auto& guard : body.plan.guard_blocks)
                    if (guard.bytes.size() != 4096 || guard.physical_block >= d.container_bytes / 4096 ||
                        !endpoint.read_guard_(guard.physical_block * 4096, block.bytes.Bytes(), error) ||
                        !std::equal(block.bytes.Bytes().begin(), block.bytes.Bytes().end(), guard.bytes.begin()))
                        return fail("ContinuationUnacceptedGuardMismatch");
                pending.erase(body.transaction);
                // Startup only: the TM is not returned to Runtime until the
                // disposition helper checks physical prefix hashes and closes
                // this exact typed absence under the same owner gate.
                continue;
            }
            C::Authority::RetainedAuthorization retention;
            if (certified) retention = *certificate_row;
            if (!group.disposition_intent.empty()) {
                Digest intent{}, receipt{};
                if (group.disposition_receipt.empty() || !Hash(group.disposition_intent, intent) || !Hash(group.disposition_receipt, receipt))
                    return fail("ContinuationAuthorizationDispositionPending");
                if (certified) {
                    if (!retention.spent || retention.transaction != body.transaction || retention.version != body.version ||
                        retention.intent_sha256 != intent || retention.receipt_sha256 != receipt)
                        return fail("ContinuationCertifiedDispositionMismatch");
                } else {
                    // The complete actual original is still present. Reuse the
                    // exact same intent/abort/receipt matcher as normal startup.
                    // It is validated by the TM-backed wrapper before capture.
                    // Spent positions burn sequence IDs without advancing the
                    // accepted cleanup watermark.
                    if (evidence.pending || body.accepted > current.last_sequence)
                        return fail("ContinuationUncertifiedDisposition");
                    retention.version = body.version; retention.accepted = body.accepted; retention.transaction = body.transaction;
                    retention.spent = true; retention.body_sha256 = body_hash; retention.intent_sha256 = intent; retention.receipt_sha256 = receipt;
                }
                authority.retained_authorizations.push_back(std::move(retention));
                continue;
            }
            prior_xid = body.plan.transaction_xid;
            const auto original_group = accepted.find(body.accepted);
            if (original_group == accepted.end()) {
                if (certified && IsRetainedRewrite(body.version) && !retention.spent &&
                    retention.version == body.version && retention.transaction == body.transaction) {
                    std::vector<WriteAheadLog::Record> rows; Wipe clear{rows};
                    for (const auto& encoded : retention.original_records) {
                        WriteAheadLog::Record record;
                        if (!WriteAheadLog::DecodeCertifiedOriginalRecord(encoded, original_options.volume_identity, record))
                            return fail("ContinuationRetainedOriginalInvalid");
                        rows.push_back(std::move(record));
                    }
                    ContinuationAccepted retained_original;
                    for (const auto& record : rows) {
                        if (record.operation == WriteAheadLog::OperationKind::TransactionMarker) {
                            if (retained_original.marker || record.state != WriteAheadLog::RecordState::Accepted || record.flags != 8)
                                return fail("ContinuationRetainedOriginalInvalid");
                            retained_original.marker = &record;
                        } else retained_original.mutations.push_back(&record);
                    }
                    if (!ContinuationMatchOriginal(retained_original, body, options_, original->journal_identity, error)) return false;
                } else if (!certified_endpoint) return fail("ContinuationRetiredBoundaryUnproved");
            } else {
                if (!ContinuationMatchOriginal(original_group->second, body, options_, original->journal_identity, error)) return false;
                matched.insert(body.accepted);
            }
            if (IsRetainedRewrite(body.version)) {
                if (!certified) {
                    if (original_group == accepted.end() || body.accepted > current.cleanup_sequence)
                        return fail("ContinuationTransitionNotDurablyClean");
                    retention.version = body.version; retention.accepted = body.accepted; retention.transaction = body.transaction; retention.body_sha256 = body_hash;
                    for (const auto* row : original_group->second.mutations) retention.original_records.push_back(WriteAheadLog::EncodeForTest(*row));
                    retention.original_records.push_back(WriteAheadLog::EncodeForTest(*original_group->second.marker));
                }
                authority.retained_authorizations.push_back(std::move(retention));
            }
            if (body.plan.transaction_xid == d.checkpoint_xid) selected = std::move(body);
        }
        if (!pending.empty()) return fail("ContinuationOriginalIncomplete");
        for (const auto& [sequence, actual] : accepted) {
            if (!matched.contains(sequence) && (!evidence.admission_only || sequence <= current.cleanup_sequence ||
                sequence != current.accepted_sequence)) return fail("ContinuationOriginalWitnessMissing");
            if (!matched.contains(sequence) && (actual.mutations.size() != 1 ||
                actual.marker->object_id != d.checkpoint_xid ||
                !SupportedDataIntent(*actual.mutations.front(), d.checkpoint_xid)))
                return fail("ContinuationPendingRecoveryUnsupported");
        }
        if (!selected || (!evidence.admission_only && selected->accepted != current.cleanup_sequence))
            return fail("ContinuationPublishedEndpointMissing");
        const auto& plan = selected->plan;
        if (plan.superblock_write.physical_block != d.physical_nx_offset / 4096 ||
            plan.superblock_write.bytes != d.physical_nx_bytes) return fail("ContinuationRawNxMismatch");
        std::map<std::uint64_t, const std::vector<std::byte>*> exact;
        const auto add = [&](std::uint64_t block, const std::vector<std::byte>& bytes) {
            if (block >= d.container_bytes / 4096 || bytes.size() != 4096) return false;
            const auto [it, inserted] = exact.emplace(block, &bytes);
            return inserted || *it->second == bytes;
        };
        for (const auto& row : plan.before_superblock_writes) if (!add(row.physical_block, row.bytes)) return fail("ContinuationPlannedAlias");
        if (!add(plan.superblock_write.physical_block, plan.superblock_write.bytes)) return fail("ContinuationPlannedAlias");
        for (const auto& row : plan.guard_blocks)
            if (!exact.contains(row.physical_block) && !add(row.physical_block, row.bytes)) return fail("ContinuationGuardAlias");
        Encoder commitment; commitment.Text("apfs-continuation-planned-guards-v6");
        auto bytes = crypto::SecureBytes::Allocate(4096);
        if (!bytes) return fail("ContinuationGuardLockFailed");
        for (const auto& [block, expected] : exact) {
            if (!endpoint.read_guard_(block * 4096, bytes.bytes.Bytes(), error) ||
                !std::equal(bytes.bytes.Bytes().begin(), bytes.bytes.Bytes().end(), expected->begin()))
                return fail("ContinuationPublishedGuardMismatch");
            commitment.Number(block); Digest digest{};
            if (!Hash(bytes.bytes.Bytes(), digest)) return fail("ContinuationGuardHashFailed");
            commitment.Data(std::as_bytes(std::span(digest)));
        }
        Encoder scope; scope.Text("apfs-clean-continuation-v6"); scope.Data(d.source_binding);
        scope.Text(d.source_identity); scope.Text(d.container_uuid); scope.Text(d.volume_uuid);
        scope.Number(d.container_bytes); scope.Number(d.volume_object_id);
        scope.Data(original->journal_identity); scope.Data(witness->journal_identity);
        const auto bind_path = [&](const std::filesystem::path& path) {
            const auto text = path.wstring(); Digest digest{};
            if (text.empty() || !path.is_absolute() || !Hash(std::as_bytes(std::span(text)), digest))
                throw std::runtime_error("ContinuationPathAuthorityInvalid");
            scope.Data(std::as_bytes(std::span(digest)));
        };
        bind_path(original_options.path); bind_path(original->key_directory);
        bind_path(options_.witness.path); bind_path(witness->key_directory);
        Digest scope_digest{};
        if (!Hash(scope.bytes, scope_digest) || !Hash(commitment.bytes, authority.planned_guard_sha256))
            return fail("ContinuationAuthorityHashFailed");
        const auto selected_group = std::find_if(groups.begin(), groups.end(), [&](const auto& group) { return group.accepted == selected->accepted; });
        if (selected_group == groups.end() || !Hash(selected_group->bytes, authority.complete_publication_sha256))
            return fail("ContinuationSelectedBodyHashFailed");
        std::memcpy(authority.scope_binding.data(), scope_digest.data(), scope_digest.size());
        authority.source_binding = d.source_binding; authority.original_journal_identity = original->journal_identity;
        authority.witness_journal_identity = witness->journal_identity;
        authority.original_head = evidence.original_head; authority.witness_head = evidence.witness_head;
        authority.original_seed = current; authority.witness_last_sequence = evidence.witness_head.last_sequence;
        const auto first = std::find_if(evidence.witness.records.begin(), evidence.witness.records.end(),
            [&](const auto& record) { return record.transaction_id == selected_group->transaction; });
        if (first == evidence.witness.records.end()) return fail("ContinuationRetainedGroupMissing");
        authority.witness_retained_first_sequence = first->sequence;
        if (authority.retained_authorizations.size() > 8) return fail("ContinuationRetainedAuthorizationCapacityExceeded");
        std::size_t retained_bytes = 0;
        for (auto& value : authority.retained_authorizations) {
            std::vector<std::uint64_t> sequences;
            for (const auto& row : evidence.witness.records)
                if (row.transaction_id == value.transaction && row.parent_object_id == value.accepted) sequences.push_back(row.sequence);
            if (sequences.empty() || sequences.size() > 512 ||
                (!value.witness_sequences.empty() && value.witness_sequences != sequences))
                return fail("ContinuationRetainedWitnessMismatch");
            value.witness_sequences = std::move(sequences);
            authority.witness_retained_first_sequence = (std::min)(authority.witness_retained_first_sequence, value.witness_sequences.front());
            for (const auto& encoded : value.original_records) {
                retained_bytes += encoded.size();
                if (encoded.size() > 16384 || retained_bytes > 2u * 1024u * 1024u)
                    return fail("ContinuationRetainedAuthorizationCapacityExceeded");
            }
        }
        std::set<std::uint64_t> retained_sequences;
        for (const auto& value : authority.retained_authorizations)
            retained_sequences.insert(value.witness_sequences.begin(), value.witness_sequences.end());
        std::uint64_t candidate_bytes = 16 + 192 + 80, candidate_records = 0;
        for (const auto& row : evidence.witness.records) {
            if (row.transaction_id != selected_group->transaction && !retained_sequences.contains(row.sequence)) continue;
            const auto encoded = WriteAheadLog::EncodeForTest(row);
            candidate_bytes += encoded.size() + journal::kJournalRecordHeaderBytes + crypto::kGcmTagBytes;
            if (encoded.empty() || ++candidate_records > 2048 || candidate_bytes > 2u * 1024u * 1024u)
                return fail("ContinuationRetainedAuthorizationCapacityExceeded");
        }
        // Includes the maximum receipt census and bounded control/path/row
        // framing. Refuse before reconciliation can create a cleanup receipt.
        if (candidate_bytes + retained_bytes + 256u * 1024u > 4u * 1024u * 1024u)
            return fail("ContinuationRetainedAuthorizationCapacityExceeded");
        authority.checkpoint_xid = d.checkpoint_xid;
        return endpoint.revalidate_(error);
    } catch (...) { authority = {}; return fail("ContinuationHistoryAuthorizationInvalid"); }
}

ProtectedJournalContinuation::Result EncryptedPublicationJournal::ContinueCleanGeneration(TransactionManager& original,
    PayloadSpool& spool, ProtectedJournalContinuation::Endpoint& endpoint, std::string& error,
    const ProtectedJournalContinuation::StageHook& hook)
{
    return ContinueCleanGeneration(original, spool, endpoint, error, hook, {});
}

ProtectedJournalContinuation::Result EncryptedPublicationJournal::ContinueCleanGeneration(TransactionManager& original,
    PayloadSpool& spool, ProtectedJournalContinuation::Endpoint& endpoint, std::string& error,
    const ProtectedJournalContinuation::StageHook& hook, const ProtectedJournalContinuation::ProgressHook& progress)
{
    using C = ProtectedJournalContinuation;
    std::vector<std::uint64_t> spent;
    if (!ValidateUnacceptedDispositions(original, spent, error)) return C::Result::RejectedBeforeWrite;
    C::RecoveryEvidence evidence; Wipe original_wipe{evidence.original.records}, witness_wipe{evidence.witness.records};
    const auto options = C::OriginalOptions(original); C::Authority authority;
    if (!C::CaptureEvidence(original, witness_, evidence, error) ||
        !AuthorizeCleanContinuation(evidence, options, endpoint, authority, error)) return C::Result::RejectedBeforeWrite;
    authority.flush_and_recheck = [&, expected = authority](std::string& reason) {
        if (!C::FlushCleanOriginalEvidence(original, expected.original_head, expected.original_seed.cleanup_sequence, reason) || !witness_.FlushPendingAppends())
            return Fail(reason, "ContinuationOriginalWitnessBarrierFailed");
        C::RecoveryEvidence checked; Wipe a{checked.original.records}, b{checked.witness.records}; C::Authority observed;
        std::vector<std::uint64_t> checked_spent;
        return ValidateUnacceptedDispositions(original, checked_spent, reason) && C::CaptureEvidence(original, witness_, checked, reason) &&
            AuthorizeCleanContinuation(checked, options, endpoint, observed, reason) &&
            (observed.original_head == expected.original_head && observed.witness_head == expected.witness_head &&
             observed.scope_binding == expected.scope_binding && observed.complete_publication_sha256 == expected.complete_publication_sha256 &&
             observed.planned_guard_sha256 == expected.planned_guard_sha256 || Fail(reason, "ContinuationEvidenceChanged"));
    };
    return C::Continue(original, spool, witness_, authority, endpoint, error, hook, progress);
}

bool EncryptedPublicationJournal::OpenOrRecoverCleanGeneration(TransactionManager& original,
    const WriteAheadLog::Options& original_options, PayloadSpool& spool, ProtectedJournalContinuation::Endpoint& endpoint,
    std::string& error, const ProtectedJournalContinuation::StageHook& hook)
{
    return OpenOrRecoverCleanGeneration(original, original_options, spool, endpoint, error, hook, {});
}

bool EncryptedPublicationJournal::OpenOrRecoverCleanGeneration(TransactionManager& original,
    const WriteAheadLog::Options& original_options, PayloadSpool& spool, ProtectedJournalContinuation::Endpoint& endpoint,
    std::string& error, const ProtectedJournalContinuation::StageHook& hook,
    const ProtectedJournalContinuation::ProgressHook& progress)
{
    using C = ProtectedJournalContinuation;
    const C::RecoveryAuthorizer authorize = [&](const C::RecoveryEvidence& evidence, C::Authority& authority, std::string& reason) {
        if (!AuthorizeCleanContinuation(evidence, original_options, endpoint, authority, reason)) return false;
        authority.flush_and_recheck = [&, expected = authority](std::string& why) {
            C::Authority current;
            return AuthorizeCleanContinuation(evidence, original_options, endpoint, current, why) &&
                (current.original_head == expected.original_head && current.witness_head == expected.witness_head &&
                 current.scope_binding == expected.scope_binding && current.planned_guard_sha256 == expected.planned_guard_sha256 ||
                 Fail(why, "ContinuationRecoveryEvidenceChanged"));
        };
        return true;
    };
    const auto opened = C::OpenOrRecover(original, original_options, spool, witness_, endpoint, authorize, error, hook, progress);
    if (opened != C::Result::Succeeded &&
        (opened != C::Result::RejectedBeforeWrite || original.RecoveryStateValid() || !original.journal_.HasExclusiveWriterLease() ||
         original.journal_path_ != original_options.path.wstring() || !original.journal_protection_ ||
         original.journal_protection_->journal_identity != original_options.protected_persistence->journal_identity)) return false;
    return ReconcileUnacceptedAuthorizations(original, endpoint, error, hook) && original.RecoveryStateValid();
}

ProtectedJournalContinuation::Result EncryptedPublicationJournal::RecoverCleanGeneration(TransactionManager& original,
    const WriteAheadLog::Options& options, PayloadSpool& spool, ProtectedJournalContinuation::Endpoint& endpoint, std::string& error,
    const ProtectedJournalContinuation::StageHook& hook)
{
    return RecoverCleanGeneration(original, options, spool, endpoint, error, hook, {});
}

ProtectedJournalContinuation::Result EncryptedPublicationJournal::RecoverCleanGeneration(TransactionManager& original,
    const WriteAheadLog::Options& options, PayloadSpool& spool, ProtectedJournalContinuation::Endpoint& endpoint, std::string& error,
    const ProtectedJournalContinuation::StageHook& hook, const ProtectedJournalContinuation::ProgressHook& progress)
{
    using C = ProtectedJournalContinuation;
    return OpenOrRecoverCleanGeneration(original, options, spool, endpoint, error, hook, progress) ?
        C::Result::Succeeded : C::Result::RecoveryRequired;
}
