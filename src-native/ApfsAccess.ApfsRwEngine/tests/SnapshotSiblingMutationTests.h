#pragma once

namespace {
void SiblingSnapshotMutations()
{
    for (const bool allowed : {false, true})
    {
        const auto stem = std::string(allowed ? "sibling-enabled" : "sibling-disabled");
        Fresh(stem + ".apfs");
        Tx selected(L"Strict"), peer(L"Strict");
        Configure(selected, stem + ".wal");
        peer.SetJournalPath(std::filesystem::absolute(stem + ".peer.wal").wstring());
        peer.SetVolumeIdentity(L"apfs-vol:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:102");
        auto owner = Open(stem + ".apfs", selected, allowed);
        const auto original = LiveBytes(*owner, L"\\clone0");
        Create(*owner, selected, "selected-history");
        const auto history = List(*owner);
        Check(history.size() == 1, "one exact source snapshot before sibling mutations");
        std::map<std::uint64_t, std::vector<std::byte>> retained_blocks;
        {
            auto* selected_store = owner->FindSessionStore(101);
            const auto& checkpoint = *selected_store->AuthoritativeAppleCheckpointView();
            SnapshotRuntimeDeviceSource source(selected_store->Device(), checkpoint.container.superblock);
            ApfsSnapshotRecords records;
            std::string error;
            const auto& id = history.front().identity;
            Check(ApfsSnapshotStore::LoadExactRecords(source, id, records, error), "capture retained snapshot records: " + error);
            std::set<std::uint64_t> blocks(records.trees.filesystem_blocks.begin(), records.trees.filesystem_blocks.end());
            blocks.insert(records.trees.extentref_blocks.begin(), records.trees.extentref_blocks.end());
            for (auto block : {id.superblock_physical_block, id.omap_physical_block, id.omap_tree_physical_block,
                id.root_physical_block, id.extentref_physical_block}) blocks.insert(block);
            for (const auto& record : records.trees.filesystem) if (Type(record) == 8) {
                AppleFileExtentRecord extent;
                Check(DecodeAppleFileExtentRecord(record, kBlockSize, extent, error), "capture retained extent: " + error);
                if (extent.physical_block) for (std::uint64_t n = 0; n < extent.length_bytes / kBlockSize; ++n)
                    blocks.insert(extent.physical_block + n);
            }
            for (auto block : blocks)
                Check(source.Read(block * kBlockSize, kBlockSize, retained_blocks[block]), "capture exact retained source bytes");
        }
        const auto verify_history = [&] {
            std::string error;
            Check(owner->RefreshSessionForRecovery(101, error), "refresh selected history: " + error);
            const auto current = List(*owner);
            Check(current.size() == history.size(), "snapshot inventory count unchanged");
            auto identity = history.front().identity;
            identity.scope.checkpoint_xid = owner->CheckpointXid();
            Check(current.front().identity == identity, "snapshot identity exact at new enclosing checkpoint");
            const auto& expected = history.front().metadata;
            const auto& actual = current.front().metadata;
            Check(actual.xid == expected.xid && actual.name_utf8 == expected.name_utf8 &&
                actual.create_time_ns == expected.create_time_ns && actual.change_time_ns == expected.change_time_ns &&
                actual.inum == expected.inum && actual.flags == expected.flags, "snapshot record fields unchanged");
            auto* selected_store = owner->FindSessionStore(101);
            SnapshotRuntimeDeviceSource source(selected_store->Device(),
                selected_store->AuthoritativeAppleCheckpointView()->container.superblock);
            for (const auto& [block, bytes] : retained_blocks) {
                std::vector<std::byte> current_bytes;
                Check(source.Read(block * kBlockSize, kBlockSize, current_bytes) && current_bytes == bytes,
                    "retained metadata and payload source blocks byte-exact");
            }
            Check(LiveBytes(*owner, L"\\clone0") == original, "selected live source bytes unchanged by sibling");
            Observe(*owner, 0, original, {std::byte{1}, std::byte{2}, std::byte{3}});
        };
        auto* store = owner->FindSessionStore(102);
        Check(store->Context().shared_container_session && store->Context().allow_native_snapshot_runtime == allowed,
            "ordinary sibling retains its original explicit runtime setting");
        Check(store->AuthoritativeAppleCheckpointView()->volumes[1].object_map.snapshot_tree_oid == 0,
            "mutating peer has no local snapshots");
        const auto read_peer = [&] {
            const auto inode = store->LookupCommittedInodeByPath(L"\\clone0");
            std::vector<std::byte> bytes;
            Check(inode && store->ReadCommittedFileRange(L"\\clone0", 0, inode->logical_size, bytes), "read peer bytes");
            return bytes;
        };
        const auto before = read_peer();
        const auto publish = [&](Store::MutationRequest request, Tx::MutationKind kind,
            const std::vector<std::byte>& payload = {}) {
            const auto source_xid = owner->CheckpointXid();
            std::uint64_t sequence = 0;
            const auto result = owner->Commit(102, {request},
                [&](const auto& requests, const auto& identities, auto xid, auto& pins, std::string& error) {
                    Tx::MutationIntent intent;
                    intent.kind = kind;
                    intent.path = requests.front().path;
                    intent.object_id = identities.front().object_id;
                    intent.generation = identities.front().generation;
                    intent.offset = requests.front().offset;
                    intent.length = requests.front().length;
                    intent.inline_payload = payload;
                    if (!payload.empty()) { intent.payload_length = payload.size(); HashPayload(payload, intent.payload_checksum); }
                    if (!peer.Begin() || !peer.RecordMutation(intent) || !peer.Accept(xid)) return false;
                    sequence = peer.Watermarks().accepted_sequence;
                    return peer.LoadRequiredCheckpointXidsSinceCleanup(pins, &error);
                }, [&](std::size_t, const auto&, const auto&, std::string&) {
                    if (!payload.empty()) store->SetFilePayloadRangeProvider([payload](const auto&, auto, auto at, std::span<std::byte> out) {
                        if (at > payload.size() || out.size() > payload.size() - at) return false;
                        std::copy_n(payload.begin() + at, out.size(), out.begin()); return true;
                    });
                    return true;
                }, {}, false, {}, {}, [&](const Store& current, auto, std::string& error) {
                    return current.ValidateRequiredRecoveryCheckpoints({source_xid}, error);
                });
            if (result.committed && !result.commit_recovery_required) {
                std::string error; std::vector<std::uint64_t> pins;
                Check(sequence && peer.MarkApfsDurableThrough(sequence) && peer.MarkCleanedThrough(sequence) &&
                    peer.LoadRequiredCheckpointXidsSinceCleanup(pins, &error) && owner->UpdateRequiredCheckpointXids(102, pins, error),
                    "peer commit durable cleanup: " + error);
            }
            return result;
        };
        Store::MutationRequest directory;
        directory.operation = Store::MutationOperation::CreateDirectory;
        directory.path = L"\\peer-directory";
        const auto xid = owner->CheckpointXid();
        const auto directory_result = publish(directory, Tx::MutationKind::CreateDirectory);
        Success(directory_result);
        Check(owner->CheckpointXid() == xid + 1 && peer.Watermarks().accepted_sequence != 0 &&
            !!store->LookupCommittedInodeByPath(L"\\peer-directory"), "ordinary sibling mkdir publishes with either runtime setting");
        Check(read_peer() == before, "mkdir preserves sibling payload bytes");
        verify_history();
        std::vector<std::byte> changed(before.size(), std::byte{0x67});
        Store::MutationRequest write;
        write.operation = Store::MutationOperation::Write; write.path = L"\\clone0"; write.length = changed.size();
        Success(publish(write, Tx::MutationKind::Write, changed));
        Check(read_peer() == changed, "peer full overwrite persists exact bytes");
        verify_history();
        Store::MutationRequest shrink;
        shrink.operation = Store::MutationOperation::SetFileSize; shrink.path = L"\\clone0"; shrink.length = kBlockSize;
        Success(publish(shrink, Tx::MutationKind::SetFileSize));
        changed.resize(kBlockSize);
        Check(read_peer() == changed, "peer truncation persists exact bytes");
        verify_history();
        owner.reset();
        owner = Open(stem + ".apfs", selected, allowed);
        store = owner->FindSessionStore(102);
        Check(read_peer() == changed, "peer payload exact after a real owner reopen");
        Check(store->Context().allow_native_snapshot_runtime == allowed, "reopen does not promote sibling runtime authority");
        verify_history();
        if (!allowed) {
            SnapshotRuntimePlan create, remove;
            std::string error;
            const auto current_identity = List(*owner).front().identity;
            Check(PrepareSnapshotCreate(*owner, 101, "runtime-required", 1700000000000000001ull, 0, create, error) &&
                PrepareSnapshotDelete(*owner, current_identity, 1700000000000000001ull, remove, error),
                "valid current-source privileged Create/Delete intents: " + error);
            for (const auto& request : {create.request, remove.request})
                Check(ValidateSnapshotMutation(*owner->FindSessionStore(101), request, error), "positive typed authority control: " + error);
            const auto image = Bytes(stem + ".apfs"), journal = Bytes(stem + ".wal"), peer_journal = Bytes(stem + ".peer.wal");
            const auto selected_marks = selected.Watermarks(), peer_marks = peer.Watermarks();
            const auto current_xid = owner->CheckpointXid();
            Check(owner->UnmountVolume(101, error), "retire privileged fixture session: " + error);
            ContainerVolumeSession session;
            session.volume_object_id = 101; session.container_uuid_hex = owner->ContainerUuidHex();
            session.requested_write = true; session.use_canonical_transaction = true;
            session.metadata_context.allow_legacy_scaffold_for_fixtures = false;
            session.metadata_context.allow_native_snapshot_runtime = false;
            Check(owner->MountVolume(session, error), "ordinary source-history session: " + error);
            auto* ordinary = owner->FindSessionStore(101);
            Check(!ordinary->Context().allow_native_snapshot_runtime && ordinary->Context().shared_container_session,
                "preservation never grants privileged runtime authority");
            SnapshotRuntimePlan refused;
            Check(!PrepareSnapshotCreate(*owner, 101, "runtime-required", 1700000000000000001ull, 0, refused, error) &&
                error == "SnapshotRuntimeOwnerNotReady", "CreateSnapshot still requires explicit runtime authority");
            Check(!PrepareSnapshotDelete(*owner, current_identity, 1700000000000000001ull, refused, error) &&
                error == "SnapshotRuntimeOwnerNotReady", "DeleteSnapshot still requires explicit runtime authority");
            for (const auto& request : {create.request, remove.request}) {
                Check(!ValidateSnapshotMutation(*ordinary, request, error) && error == "SnapshotRuntimeMutationInvalid",
                    "valid typed snapshot mutation refuses after runtime authority removal");
                Check(ordinary->PreflightNativeCapacityMutation(request) != Store::MutationStatus::Applied &&
                    ordinary->StageMutation(request) != Store::MutationStatus::Applied && ordinary->PendingMutationCount() == 0,
                    "snapshot capacity and staging paths retain privileged authority gate");
            }
            const auto selected_after = selected.Watermarks(), peer_after = peer.Watermarks();
            Check(Bytes(stem + ".apfs") == image && Bytes(stem + ".wal") == journal &&
                Bytes(stem + ".peer.wal") == peer_journal && owner->CheckpointXid() == current_xid &&
                selected_after.accepted_sequence == selected_marks.accepted_sequence &&
                selected_after.apfs_durable_sequence == selected_marks.apfs_durable_sequence &&
                selected_after.cleanup_sequence == selected_marks.cleanup_sequence &&
                peer_after.accepted_sequence == peer_marks.accepted_sequence &&
                peer_after.apfs_durable_sequence == peer_marks.apfs_durable_sequence &&
                peer_after.cleanup_sequence == peer_marks.cleanup_sequence, "privileged refusals preserve all source/WAL bytes and markers");
            verify_history();
        }
        std::cout << "PASS sibling runtime=" << allowed << " preserves exact history through mkdir/write/truncate/reopen\n";
    }
}
}
