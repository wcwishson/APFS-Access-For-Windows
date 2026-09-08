#pragma once

// Included immediately after NativeSparseMutationTests.h in the fixture namespace.
bool TestNativeSparseAllocationRenameWal357()
{
    using namespace apfsaccess::rw;
    using Store = MetadataStore;
    using Tx = TransactionManager;
    using Wal = WriteAheadLog;
    constexpr std::uint64_t tail = 64 * 1024 * 1024;
    constexpr std::uint64_t block = kNativeSparseBlock;
    constexpr std::uint64_t hole_block = tail / 2;
    constexpr std::uint64_t write_offset = hole_block + 17;

    const auto run = [&](bool replace) {
        const std::string label = replace ? "sparse WAL 357 replacement: " : "sparse WAL 357 rename-away: ";
        const auto check = [&](bool ok, const std::string& message) { return Require(ok, label + message); };
        const auto fixture = BuildNativeSparseMutationImage(tail);
        if (!check(!fixture.empty(), "fixture builds")) return false;
        NativeSparseImage image(fixture);
        // Own a newly created directory, including any WAL compaction siblings.
        // Never remove an existing evidence directory or the shared D: test root.
        struct Evidence
        {
            const std::filesystem::path root;
            bool owned = false;
            ~Evidence()
            {
                if (owned) { std::error_code error; std::filesystem::remove_all(root, error); }
            }
        } evidence{std::filesystem::absolute(image.path).lexically_normal().wstring() + L".replay357"};
        if (!check(evidence.root.is_absolute() && evidence.root.root_name() == std::filesystem::path(L"D:") &&
                evidence.root.parent_path() == std::filesystem::absolute(image.path).lexically_normal().parent_path(),
                "evidence is an isolated child of the D: fixture directory")) return false;
        std::error_code directory_error;
        evidence.owned = std::filesystem::create_directory(evidence.root, directory_error);
        if (!check(evidence.owned && !directory_error, "unique evidence directory created")) return false;
        const auto wal_path = evidence.root / L"accepted.wal";
        const auto volume_identity = L"native-sparse-replay357-" + image.path.stem().wstring();
        const auto volume_utf8 = Tx::WideToUtf8(volume_identity);
        Store::VolumeContext context;
        context.device_path = image.path.wstring(); context.volume_object_id = 101;
        context.allow_legacy_scaffold_for_fixtures = false;

        // Both owners must exist in the accepted transaction's committed preimage.
        {
            Store seed(context);
            Store::MutationRequest create;
            create.operation = Store::MutationOperation::CreateFile; create.path = L"\\temp";
            if (!check(seed.PrepareNativeWritePath() &&
                    seed.StageMutation(create) == Store::MutationStatus::Applied &&
                    seed.CommitPendingMutations() == Store::CommitStatus::Committed,
                    "ordinary empty temp commits alongside sparse original")) return false;
        }
        Store::InodeRecord ordinary, sparse;
        std::uint64_t source_xid = 0, accepted_sequence = 0, transaction_id = 0;
        std::vector<std::byte> preimage;
        {
            Store source(context);
            if (!check(source.PrepareNativeWritePath() && source.VerifyIntegrity(), "committed seed reopens")) return false;
            const auto temp = source.LookupCommittedInodeByPath(L"\\temp");
            const auto original = source.LookupCommittedInodeByPath(L"\\original");
            const auto checkpoint = source.CheckpointXid();
            if (!check(temp && original && checkpoint && *checkpoint != 0 && *checkpoint != UINT64_MAX &&
                    temp->object_id != original->object_id && temp->logical_size == 0 && temp->allocation_size == 0 &&
                    original->object_id == 17 && original->logical_size == tail + 3 * block &&
                    original->allocation_size == 6 * block, "distinct committed ordinary and sparse owners")) return false;
            ordinary = *temp; sparse = *original; source_xid = *checkpoint;
            if (!check(source.Device().Read(0, static_cast<std::size_t>(std::filesystem::file_size(image.path)), preimage),
                    "capture exact accepted preimage")) return false;
            Tx transactions(L"Strict");
            transactions.SetJournalPath(wal_path.wstring()); transactions.SetVolumeIdentity(volume_identity);
            if (!check(transactions.Begin(), "begin one real WAL transaction")) return false;
            transaction_id = transactions.CurrentTransactionId();

            const auto stage_and_record = [&](Store::MutationRequest request, Tx::MutationKind kind) {
                Store::PayloadIdentity identity;
                std::optional<UnlinkOutcome> unlink;
                if (!check(source.StageMutation(request, &identity, &unlink) == Store::MutationStatus::Applied,
                        "foreground mutation stages")) return false;
                const auto expected_owner = kind == Tx::MutationKind::SetAllocationSize ||
                    request.secondary_path == L"\\saved" ? ordinary.object_id : sparse.object_id;
                if (!check(identity.object_id == expected_owner && identity.generation == source_xid + 1 && !unlink,
                        "native staging supplies stable identity; rename has no Delete-only unlink proof")) return false;
                Tx::MutationIntent intent;
                intent.kind = kind; intent.path = request.path; intent.secondary_path = request.secondary_path;
                intent.offset = request.offset; intent.length = request.length;
                intent.object_id = identity.object_id; intent.generation = identity.generation;
                intent.replace_if_exists = request.replace_if_exists; intent.unlink_outcome = unlink;
                intent.wal_sequence = transactions.NextMutationSequence();
                if (kind == Tx::MutationKind::Write)
                {
                    intent.inline_payload = {std::byte{0x6b}}; intent.payload_length = intent.inline_payload.size();
                    std::string error, hex;
                    auto digest = apfsaccess::observer::Sha256Stream::Create(error);
                    if (!check(digest && digest->Update(intent.inline_payload.data(), intent.inline_payload.size()) &&
                            digest->FinalHex(hex) && hex.size() == 2 * intent.payload_checksum.size(),
                            "actual SHA-256 API hashes the accepted byte")) return false;
                    for (std::size_t i = 0; i < intent.payload_checksum.size(); ++i)
                        intent.payload_checksum[i] = static_cast<std::uint8_t>(std::stoul(hex.substr(i * 2, 2), nullptr, 16));
                }
                return check(transactions.RecordMutation(intent), "native request records through TransactionManager");
            };
            Store::MutationRequest request;
            request.operation = Store::MutationOperation::SetAllocationSize; request.path = L"\\temp"; request.length = block;
            if (!stage_and_record(request, Tx::MutationKind::SetAllocationSize)) return false;
            if (!replace)
            {
                request = {}; request.operation = Store::MutationOperation::Rename;
                request.path = L"\\temp"; request.secondary_path = L"\\saved";
                if (!stage_and_record(request, Tx::MutationKind::Rename)) return false;
            }
            // Match the real host WAL: replacement is a flagged Rename. The WAL
            // schema permits UnlinkOutcome only on Delete, not on this record.
            request = {}; request.operation = Store::MutationOperation::Rename;
            request.path = L"\\original"; request.secondary_path = L"\\temp"; request.replace_if_exists = replace;
            if (!stage_and_record(request, Tx::MutationKind::Rename)) return false;
            request = {}; request.path = L"\\temp"; request.offset = write_offset; request.length = 1;
            if (!stage_and_record(request, Tx::MutationKind::Write) ||
                !check(transactions.Accept(source_xid), "accept the complete ordered batch against its exact source XID")) return false;
            accepted_sequence = transactions.Watermarks().accepted_sequence;
            if (!check(accepted_sequence != 0 && transactions.Watermarks().apfs_durable_sequence == 0 &&
                    transactions.Watermarks().cleanup_sequence == 0 && source.CheckpointXid() == source_xid,
                    "acceptance precedes APFS publication and both finalization watermarks")) return false;
        } // Close foreground metadata, transaction state and writer lease without publishing.

        const std::vector<Wal::OperationKind> operations = replace
            ? std::vector<Wal::OperationKind>{Wal::OperationKind::SetAllocationSize, Wal::OperationKind::Rename, Wal::OperationKind::Write}
            : std::vector<Wal::OperationKind>{Wal::OperationKind::SetAllocationSize, Wal::OperationKind::Rename,
                Wal::OperationKind::Rename, Wal::OperationKind::Write};
        if (!check(std::filesystem::file_size(wal_path) <= 64 * 1024, "restart evidence stays bounded")) return false;
        {
            const auto persisted = Wal::ReadAll(wal_path, volume_utf8);
            if (!check(persisted.status == Wal::ReadStatus::Ok && !persisted.recovered_torn_tail &&
                    persisted.records.size() == operations.size() + 1, "actual WAL decoder reads prepared requests and acceptance")) return false;
            const auto& marker = persisted.records.back();
            if (!check(marker.operation == Wal::OperationKind::TransactionMarker && marker.state == Wal::RecordState::Accepted &&
                    marker.transaction_id == transaction_id && marker.sequence == accepted_sequence && marker.object_id == source_xid &&
                    marker.logical_length == operations.size(),
                    "persisted acceptance marker binds the original checkpoint")) return false;
        }
        {
            Tx replay(L"Strict");
            replay.SetJournalPath(wal_path.wstring()); replay.SetVolumeIdentity(volume_identity);
            std::vector<Tx::AcceptedTransaction> accepted;
            std::string error;
            if (!check(replay.LoadUnappliedAcceptedTransactions(accepted, &error) && accepted.size() == 1 &&
                    accepted.front().transaction_id == transaction_id && accepted.front().accepted_sequence == accepted_sequence &&
                    accepted.front().preimage_checkpoint_xid == source_xid && accepted.front().mutations.size() == operations.size(),
                    "fresh manager loads exactly the accepted batch: " + error)) return false;
            if (!check(replay.Watermarks().accepted_sequence == accepted_sequence &&
                    replay.Watermarks().apfs_durable_sequence == 0 && replay.Watermarks().cleanup_sequence == 0,
                    "restart preserves accepted-only watermarks")) return false;
            const auto& records = accepted.front().mutations;
            const auto& write = records.back();
            if (!check(write.inline_payload == std::vector<std::byte>{std::byte{0x6b}} && write.payload_length == 1 &&
                    write.logical_offset == write_offset && write.logical_length == 1 &&
                    write.payload_spool_id == write.sequence && write.payload_offset == 0 &&
                    Wal::InlinePayloadIsConsistent(write), "persisted inline payload has real sequence, length and SHA-256 proof")) return false;
            auto corrupt = write; corrupt.inline_payload.front() ^= std::byte{1};
            if (!check(!Wal::InlinePayloadIsConsistent(corrupt) && Wal::EncodeForTest(corrupt).empty(),
                    "changed payload fails the actual hash/encoder checks")) return false;
            {
                Store recovered(context);
                std::vector<std::byte> untouched;
                if (!check(recovered.PrepareNativeWritePath() && recovered.CheckpointXid() == source_xid &&
                        recovered.Device().Read(0, preimage.size(), untouched) && untouched == preimage,
                        "restart rebuilds from byte-identical original checkpoint")) return false;
                const auto old_temp = recovered.LookupCommittedInodeByPath(L"\\temp");
                const auto old_original = recovered.LookupCommittedInodeByPath(L"\\original");
                if (!check(old_temp && old_original && old_temp->object_id == ordinary.object_id &&
                        old_original->object_id == sparse.object_id && !recovered.LookupCommittedInodeByPath(L"\\saved"),
                        "restart retains the original namespace before replay")) return false;
                std::uint64_t previous_sequence = 0;
                for (std::size_t i = 0; i < records.size(); ++i)
                {
                    const auto& record = records[i];
                    const bool ordinary_request = i == 0 || (!replace && i == 1);
                    const bool rename = record.operation == Wal::OperationKind::Rename;
                    const std::string path = ordinary_request || !rename ? "\\temp" : "\\original";
                    const std::string secondary = rename ? (ordinary_request ? "\\saved" : "\\temp") : "";
                    const auto flags = replace && rename ? 0x4ULL : 0ULL; // Host's persisted replacement flag.
                    if (!check(record.operation == operations[i] && record.state == Wal::RecordState::Prepared &&
                            record.volume_identity == volume_utf8 && record.transaction_id == transaction_id &&
                            record.sequence > previous_sequence && record.sequence < accepted_sequence &&
                            record.object_id == (ordinary_request ? ordinary.object_id : sparse.object_id) &&
                            record.parent_object_id == source_xid + 1 && record.path_utf8 == path &&
                            record.secondary_path_utf8 == secondary && record.flags == flags && !record.unlink_outcome &&
                            Wal::UnlinkOutcomeIsConsistent(record) && Wal::AllocationSizeMutationIsConsistent(record) &&
                            !Wal::EncodeForTest(record).empty(), "persisted order, owner/generation and replacement semantics validate")) return false;
                    previous_sequence = record.sequence;
                    Store::MutationRequest request;
                    // These bounded fixture paths have just been checked as exact ASCII.
                    request.path.assign(record.path_utf8.begin(), record.path_utf8.end());
                    request.secondary_path.assign(record.secondary_path_utf8.begin(), record.secondary_path_utf8.end());
                    request.object_id = record.object_id; request.generation = record.parent_object_id;
                    request.offset = record.logical_offset; request.length = record.logical_length;
                    request.replace_if_exists = (record.flags & 0x4u) != 0;
                    request.expected_unlink_outcome = record.unlink_outcome;
                    switch (record.operation)
                    {
                    case Wal::OperationKind::SetAllocationSize: request.operation = Store::MutationOperation::SetAllocationSize; break;
                    case Wal::OperationKind::Rename: request.operation = Store::MutationOperation::Rename; break;
                    case Wal::OperationKind::Write: request.operation = Store::MutationOperation::Write; break;
                    default: return check(false, "unexpected accepted operation");
                    }
                    if (!check(record.logical_offset == (i + 1 == records.size() ? write_offset : 0) &&
                            record.logical_length == (i == 0 ? block : i + 1 == records.size() ? 1 : 0),
                            "allocation, rename and write lengths survive WAL encoding")) return false;
                    Store::PayloadIdentity identity;
                    std::optional<UnlinkOutcome> unlink;
                    if (!check(recovered.StageMutation(request, &identity, &unlink) == Store::MutationStatus::Applied &&
                            identity.object_id == record.object_id && identity.generation == record.parent_object_id &&
                            unlink == record.unlink_outcome, "ordered replay restages the recorded identity and outcome")) return false;
                }
                std::uint64_t supplied = 0;
                unsigned sparse_calls = 0;
                recovered.SetFilePayloadRangeProvider([&](const auto& path, auto identity, auto offset, std::span<std::byte> bytes) {
                    if (!replace && path == L"\\saved")
                        return check(identity.object_id == ordinary.object_id && identity.generation == source_xid + 1 &&
                            offset == 0 && bytes.empty(), "empty ordinary owner requires no payload");
                    // A dense fallback must fail even if it tries small chunks. Only
                    // the one written hole block may be acquired from accepted WAL.
                    if (!check(path == L"\\temp" && identity.object_id == write.object_id &&
                            identity.generation == write.parent_object_id && offset == hole_block && bytes.size() == block &&
                            ++sparse_calls == 1, "provider is bounded to the sparse owner's single changed block")) return false;
                    supplied += bytes.size();
                    std::fill(bytes.begin(), bytes.end(), std::byte{0});
                    std::copy(write.inline_payload.begin(), write.inline_payload.end(), bytes.begin() + (write.logical_offset - offset));
                    return true;
                });
                const auto committed = recovered.CommitCanonicalTransaction({accepted.front().preimage_checkpoint_xid});
                if (!check(committed == Store::CommitStatus::Committed,
                        "historical allocation path cannot disable sparse planning: " + recovered.LastCommitStage()) ||
                    !check(supplied == block && sparse_calls == 1 && recovered.CheckpointXid() == source_xid + 1,
                        "canonical publication uses exactly one sparse payload block")) return false;
            }
            {
                Store final(context);
                if (!check(final.PrepareNativeWritePath() && final.VerifyIntegrity() && final.CheckpointXid() == source_xid + 1,
                        "published canonical image reopens and verifies")) return false;
                const auto inode = final.LookupCommittedInodeByPath(L"\\temp");
                if (!check(inode && inode->object_id == sparse.object_id && inode->private_id == sparse.private_id &&
                        inode->xid == source_xid + 1 && inode->owner == sparse.owner && inode->group == sparse.group &&
                        inode->mode == sparse.mode && inode->link_count == 1 && inode->logical_size == sparse.logical_size &&
                        inode->allocation_size == 7 * block && !final.LookupCommittedInodeByPath(L"\\original"),
                        "sparse owner, generation, EOF and exact allocation survive rename/restart")) return false;
                const auto saved = final.LookupCommittedInodeByPath(L"\\saved");
                const auto surviving_owner = final.LookupCommittedInodeByObjectId(ordinary.object_id);
                if (replace)
                {
                    if (!check(!saved && !surviving_owner, "replacement removes the ordinary inode, not the sparse owner")) return false;
                }
                else if (!check(saved && surviving_owner && saved->object_id == ordinary.object_id &&
                        saved->private_id == ordinary.private_id && saved->xid == source_xid + 1 &&
                        saved->owner == ordinary.owner && saved->group == ordinary.group && saved->mode == ordinary.mode &&
                        saved->link_count == 1 && saved->logical_size == 0 && saved->allocation_size == block &&
                        surviving_owner->full_path == L"\\saved", "ordinary reservation and owner survive under saved")) return false;
                for (const auto offset : std::vector<std::uint64_t>{0, block, 2 * block, 3 * block,
                    hole_block - block, hole_block, hole_block + block, tail - block, tail, tail + block, tail + 2 * block})
                {
                    std::vector<std::byte> bytes;
                    if (!check(final.ReadCommittedFileRange(L"\\temp", offset, block, bytes) && bytes.size() == block,
                            "bounded committed range reads")) return false;
                    for (std::size_t i = 0; i < bytes.size(); ++i)
                    {
                        const auto at = offset + i;
                        const auto expected = at == write_offset ? std::byte{0x6b} : at < 3 * block ? std::byte{0x31} :
                            at >= tail ? std::byte{0xa7} : std::byte{0};
                        if (!check(bytes[i] == expected, "exact original bytes, accepted byte and hole zeros")) return false;
                    }
                }
                OrdinaryCowSnapshot raw;
                if (!ReadOrdinaryCowSnapshot(image.path, raw)) return false;
                std::uint64_t end = 0, physical = 0, holes = 0, referenced = 0;
                std::set<std::uint64_t> data_blocks, reference_blocks;
                for (const auto& [offset, record] : raw.extents)
                {
                    AppleFileExtentRecord extent;
                    if (!check(DecodeAppleFileExtentRecord(record, block, extent, error) && extent.object_id == sparse.object_id &&
                            offset == end && extent.length_bytes != 0 && extent.length_bytes % block == 0 &&
                            end <= sparse.logical_size && extent.length_bytes <= sparse.logical_size - end,
                            "raw sparse extents cover EOF exactly with explicit holes")) return false;
                    end += extent.length_bytes;
                    if (!extent.physical_block) { holes += extent.length_bytes; continue; }
                    physical += extent.length_bytes;
                    if (!check(physical <= 7 * block, "raw physical allocation stays sparse")) return false;
                    for (std::uint64_t n = 0; n < extent.length_bytes / block; ++n)
                    {
                        const auto logical = offset + n * block;
                        const auto physical_block = extent.physical_block + n;
                        if (!check(data_blocks.insert(physical_block).second &&
                                (logical < 3 * block ? physical_block == 100 + logical / block :
                                 logical >= tail ? physical_block == 110 + (logical - tail) / block : logical == hole_block),
                                "six original physical blocks are retained; only the written hole gains storage")) return false;
                    }
                }
                for (const auto& [physical_block, record] : raw.references)
                {
                    ApplePhysicalExtentRecord ref;
                    if (!check(DecodeApplePhysicalExtentRecord(record, ref, error) && physical_block != 0 &&
                            ref.physical_block == physical_block && ref.owning_object_id == sparse.object_id && ref.reference_count == 1 &&
                            ref.block_count > 0 && ref.block_count <= 7, "raw extent references retain exclusive sparse ownership")) return false;
                    referenced += ref.block_count * block;
                    for (std::uint64_t n = 0; n < ref.block_count; ++n)
                        if (!check(reference_blocks.insert(physical_block + n).second, "physical reference ranges do not overlap")) return false;
                }
                if (!check(raw.xid == source_xid + 1 && end == sparse.logical_size && physical == 7 * block &&
                        holes == sparse.logical_size - physical && referenced == physical && reference_blocks == data_blocks,
                        "raw extents, holes, inode allocation and owner references agree")) return false;
            }
            if (!check(replay.Watermarks().apfs_durable_sequence == 0 && replay.Watermarks().cleanup_sequence == 0 &&
                    replay.MarkApfsDurableThrough(accepted_sequence) &&
                    replay.Watermarks().apfs_durable_sequence == accepted_sequence && replay.Watermarks().cleanup_sequence == 0,
                    "durable watermark advances only after verified canonical commit")) return false;
            if (!check(replay.MarkCleanedThrough(accepted_sequence) && replay.Watermarks().cleanup_sequence == accepted_sequence,
                    "cleanup follows APFS durability")) return false;
        }
        Tx finished(L"Strict");
        finished.SetJournalPath(wal_path.wstring()); finished.SetVolumeIdentity(volume_identity);
        std::vector<Tx::AcceptedTransaction> remaining;
        return check(finished.RecoveryStateValid() && finished.LoadUnappliedAcceptedTransactions(remaining) && remaining.empty() &&
            finished.Watermarks().accepted_sequence == accepted_sequence && finished.Watermarks().apfs_durable_sequence == accepted_sequence &&
            finished.Watermarks().cleanup_sequence == accepted_sequence, "second WAL restart retains durable cleanup with nothing to replay");
    };
    bool ok = run(true);
    ok &= run(false);
    return ok;
}
