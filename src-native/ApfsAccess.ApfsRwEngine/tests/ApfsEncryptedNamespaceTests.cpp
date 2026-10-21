#include "ApfsEncryptedImageWriteSession.h"
#include "ApfsFormat.h"
#define wmain HistoricalOwnerRecoveryMain
#include "ApfsEncryptedImageRecoveryTests.cpp"
#undef wmain
#include "InodeMetadataPatch.h"
#undef CreateDirectory

bool SameSelection(const c::PasswordUnlockRequest& a, const c::PasswordUnlockRequest& b)
{
    return a.checkpoint_xid == b.checkpoint_xid && a.volume_oid == b.volume_oid &&
        a.container_uuid == b.container_uuid && a.volume_uuid == b.volume_uuid && a.user_uuid == b.user_uuid &&
        a.container_bag.oid == b.container_bag.oid && a.container_bag.xid == b.container_bag.xid &&
        a.volume_bag.oid == b.volume_bag.oid && a.volume_bag.xid == b.volume_bag.xid && a.length == b.length;
}
c::PasswordUnlockRequest ObservePublicSelection(const fs::path& image)
{
    c::FileRandomAccessSource file(r::TransactionManager::WideToUtf8(image.wstring()));
    c::OffsetRandomAccessSource window(&file, 20480, 4153344);
    c::BudgetedRandomAccessSource source(window,
        std::make_shared<c::ApfsReadBudget>(100000, 256ULL << 20, 1000000, 256ULL << 20));
    c::UnlockError error{};
    auto observed = c::InspectPasswordKeybagMetadata(source, 1026, c::KeybagLength::IncludesHeader, error);
    Check(observed && observed->users.size() == 1, "PreUnlockPublicSelection:" + std::to_string(static_cast<int>(error)));
    auto selection = observed->selection; selection.user_uuid = observed->users.front(); return selection;
}

void PreserveMetadata(const c::EncryptedNodeInfo& before, const c::EncryptedNodeInfo& after,
    const r::InodeMetadataPatch& patch)
{
    using M = r::InodeMetadataPatch;
    Check(before.inode_id == after.inode_id && before.parent_id == after.parent_id &&
        before.private_id == after.private_id && before.size == after.size &&
        before.allocated_size == after.allocated_size && before.default_crypto_id == after.default_crypto_id &&
        before.internal_flags == after.internal_flags && before.protection_class == after.protection_class &&
        before.write_generation == after.write_generation && before.children_or_links == after.children_or_links,
        "MetadataPreservesMacAndStreamFields");
    Check(after.mode == ((patch.mask & M::Mode) ? ((before.mode & 0170000) | patch.mode) : before.mode) &&
        after.uid == ((patch.mask & M::Owner) ? patch.owner : before.uid) &&
        after.gid == ((patch.mask & M::Group) ? patch.group : before.gid) &&
        after.bsd_flags == ((patch.mask & M::BsdFlags) ? patch.bsd_flags : before.bsd_flags), "ExactMetadataFields");
    const auto ns = [](std::uint64_t ticks) { return (ticks - M::UnixEpochTicks) * 100; };
    Check(after.create_time == ((patch.mask & M::CreateTime) ? ns(patch.create_time_utc) : before.create_time) &&
        after.modification_time == ((patch.mask & M::ModificationTime) ? ns(patch.modification_time_utc) : before.modification_time) &&
        after.change_time == ((patch.mask & M::ChangeTime) ? ns(patch.change_time_utc) : before.change_time) &&
        after.access_time == ((patch.mask & M::AccessTime) ? ns(patch.access_time_utc) : before.access_time),
        "ExactSelectedTimesPreservedUnselectedTimes");
}

int wmain(int argc, wchar_t** argv)
{
    try {
        Check(argc == 10, "Arguments:image,journal,phase,operation,inode,parent,destination,name,newname");
        const auto image = fs::absolute(argv[1]).lexically_normal(), directory = fs::absolute(argv[2]).lexically_normal();
        const std::wstring prefix = L"D:\\ApfsAccessScratch\\BN7\\";
        Check(image.wstring().starts_with(prefix) && directory.wstring().starts_with(prefix), "PrivateNamespaceDOnly");
        const std::wstring phase = argv[3], operation = argv[4];
        auto inode = std::stoull(argv[5]);
        const auto parent = std::stoull(argv[6]), destination = std::stoull(argv[7]);
        const auto name = r::TransactionManager::WideToUtf8(argv[8]), newname = r::TransactionManager::WideToUtf8(argv[9]);
        const auto expected_selection = ObservePublicSelection(image);
        auto owner = Open(image); const auto binding = owner->SourceBinding(); const auto identity = owner->SourceIdentity();
        Check(!owner->UnlockedSelection(), "LockedSelectionAbsent");
        const auto xid = owner->CachedStatus().checkpoint_xid;
        fs::create_directories(directory); std::string error;
        auto tx = std::make_unique<r::TransactionManager>(L"Conservative");
        Check(tx->OpenProtectedJournal((directory / "original.wal").wstring(), L"owner-reprepare-dfvfs",
            Protection(directory, binding, "original-v2"), error), "NamespaceOriginalOpen:" + error);
        Journal::Options options;
        options.container_bytes = owner->CachedStatus().container_bytes; options.container_uuid = owner->ContainerUuid();
        options.preimage_source_identity = identity; options.volume_object_id = owner->VolumeObjectId(); options.volume_uuid = owner->VolumeUuid();
        options.witness = {directory / "witness.wal", "namespace-witness-v2", 64ull << 20, Protection(directory, binding, "witness-v2")};
        auto journal = std::make_unique<Journal>(options);
        const auto initial = tx->Watermarks();
        unsigned writes = 0, status_calls = 0; bool drained = true, fault_hit = false;
        std::shared_ptr<c::ApfsEncryptedReadSession> view;
        c::EncryptedReadError re{};
        if (phase != L"keyless" && phase != L"refuse-witness") {
            Unlock(*owner); view = owner->OpenReadView(re); Check(static_cast<bool>(view), "NamespaceReadView");
            auto admitted = owner->UnlockedSelection();
            Check(admitted && SameSelection(*admitted, expected_selection) && admitted->checkpoint_xid == xid &&
                admitted->volume_oid == owner->VolumeObjectId() &&
                c::BytesToHexLower(admitted->container_uuid.data(), admitted->container_uuid.size()) == owner->ContainerUuid() &&
                c::BytesToHexLower(admitted->volume_uuid.data(), admitted->volume_uuid.size()) == owner->VolumeUuid(),
                "ExactAdmittedSelectionWithoutSecondUnlock");
            admitted->user_uuid[0] ^= std::byte{1}; admitted->volume_bag.xid ^= 1;
            Check(SameSelection(*owner->UnlockedSelection(), expected_selection), "SelectionCopyCannotChangeOwner");
        }
        c::EncryptedNodeInfo before{}; bool have_before = false;
        if (view && inode && (operation.starts_with(L"meta") || operation == L"compression")) {
            have_before = view->GetMetadata(inode, before) == c::EncryptedReadError::None;
            Check(have_before || phase == L"refuse", "OriginalMetadata");
        }
        c::EncryptedMutationRequest request;
        Bytes bytes;
        request.inode = inode;
        if (operation == L"mkdir" || operation == L"mkdir-data" || operation == L"mkdir-mode") {
            request.kind = c::EncryptedMutationKind::MakeDirectory; request.inode = 0;
            request.parent = parent; request.name = name; request.permissions = 0750;
            if (operation == L"mkdir-data") { bytes.data = {std::byte{1}}; request.data = bytes.data; }
            if (operation == L"mkdir-mode") request.permissions = 010000;
        } else if (operation == L"create") {
            request.kind = c::EncryptedMutationKind::Create; request.inode = 0;
            request.parent = parent; request.name = name; request.permissions = 0600;
        } else if (operation == L"rename") {
            request.kind = c::EncryptedMutationKind::Rename; request.parent = parent;
            request.destination_parent = destination; request.name = name; request.destination_name = newname;
        } else if (operation == L"unlink") {
            request.kind = c::EncryptedMutationKind::Unlink; request.parent = parent; request.name = name;
        } else if (operation == L"write") {
            request.kind = c::EncryptedMutationKind::Write;
            bytes.data.resize(65536);
            for (std::size_t i = 0; i < bytes.data.size(); ++i) bytes.data[i] = static_cast<std::byte>((i * 31 + 73) % 251);
            request.data = bytes.data;
        } else {
            request.kind = c::EncryptedMutationKind::SetInodeMetadata;
            using M = r::InodeMetadataPatch;
            M patch;
            if (operation == L"meta-v2") {
                patch.mask = M::BsdFlags | M::ModificationTime; patch.bsd_flags = 0x8000;
                patch.modification_time_utc = M::UnixEpochTicks + 17000000000000123ULL;
            } else if (operation == L"compression") {
                patch.mask = M::BsdFlags; patch.bsd_flags = before.bsd_flags ^ 0x20;
            } else if (operation == L"meta-mode") {
                patch.mask = M::Mode; patch.mode = 0640;
            } else {
                patch.mask = M::Owner | M::Group | M::Mode | M::CreateTime | M::ModificationTime | M::ChangeTime | M::AccessTime;
                patch.owner = 701; patch.group = 702; patch.mode = before.IsDirectory() ? 0750 : 0640;
                patch.create_time_utc = M::UnixEpochTicks + 17000000000000001ULL;
                patch.modification_time_utc = M::UnixEpochTicks + 17000000000000002ULL;
                patch.change_time_utc = M::UnixEpochTicks + 17000000000000003ULL;
                patch.access_time_utc = M::UnixEpochTicks + 17000000000000004ULL;
            }
            Check(r::EncodeInodeMetadataPatch(patch, bytes.data), "CanonicalPatchEncode");
            if (operation == L"badpatch") bytes.data[18] = std::byte{1};
            request.data = bytes.data;
        }
        std::uint64_t sequence = initial.accepted_sequence;
        std::unique_ptr<Owner::PreparedMutation> prepared;
        if (phase == L"cancel") {
            owner->Cancel(); owner->Cancel();
            c::EncryptedNamespaceInfo info;
            Check(owner->CachedStatus().key_present && !owner->UnlockedSelection() &&
                view->GetNamespaceInfo(info) == c::EncryptedReadError::Cancelled,
                "CancelSignalsViewsWithoutWipingOwnerKey");
            Check(!owner->PrepareMutation(xid, request, error) && error == "ImageWriterCancelled" &&
                !owner->OpenReadView(re) && re == c::EncryptedReadError::Cancelled && Same(initial, tx->Watermarks()) &&
                !tx->HasUnappliedAcceptedWork(), "CancelRefusesBeforeAcceptance");
            owner->Lock();
            Check(!owner->CachedStatus().key_present && !owner->UnlockedSelection(), "LockDrainsCancelledViews");
            auto dummy = apfsaccess::crypto::SecureBytes::Allocate(1); c::PasswordUnlockBudget attempts;
            Check(dummy && !owner->Unlock(dummy.bytes, attempts, error) && error == "ImageWriterCancelled",
                "CancelStickyAcrossLock");
            owner->Close(); Check(!owner->UnlockedSelection(), "ClosedSelectionAbsent");
            owner = Open(image); Check(!owner->UnlockedSelection(), "NewOwnerLockedSelectionAbsent"); owner->Close();
            std::cout << "{\"status\":\"PASS\",\"refused\":true,\"cancelled\":true,\"checks\":" << checks << "}\n"; return 0;
        }
        if (phase == L"refuse") {
            Check(!owner->PrepareMutation(xid, request, error) && Same(initial, tx->Watermarks()) &&
                !tx->HasUnappliedAcceptedWork() && owner->CachedStatus().phase == Phase::Ready,
                "NamespaceRefusesBeforeAccept:" + error);
            c::EncryptedNamespaceInfo info; Check(view->GetNamespaceInfo(info) == c::EncryptedReadError::None, "RefusalPreservesReadView");
            owner->Close();
            std::cout << "{\"status\":\"PASS\",\"refused\":true,\"reason\":\"" << error << "\",\"checks\":" << checks << "}\n"; return 0;
        }
        const bool recovering = phase == L"recover" || phase == L"keyless" || phase == L"refuse-witness";
        if (!recovering) {
            prepared = owner->PrepareMutation(xid, request, error);
            Check(prepared != nullptr, "NamespacePrepare:" + error);
            const auto& captured = prepared->Intent(); inode = captured.RequestedInode();
            Check(captured.IntentKind() == request.kind && captured.ReplacementLength() == bytes.data.size() &&
                captured.ReplacementSha256() == Hash(bytes.data) && captured.RequestedOffset() == request.offset,
                "ExactPrivateKindPayloadBinding");
            if (request.kind == c::EncryptedMutationKind::MakeDirectory)
                Check(captured.ResultSize() == 0 && captured.EffectiveMode() == (0040000 | request.permissions) &&
                    captured.RequestedPermissions() == request.permissions, "ExactDirectoryIntent");
            if (request.kind == c::EncryptedMutationKind::SetInodeMetadata)
                Check(captured.ResultSize() == before.size && (captured.ReplacementLength() == 52 || captured.ReplacementLength() == 56),
                    "ExactMetadataLengthAndPreservedEof");
            r::TransactionManager::MutationIntent intent;
            intent.object_id = inode; intent.path = L"encrypted-data";
            switch (request.kind) {
            case c::EncryptedMutationKind::MakeDirectory:
                intent.kind = r::TransactionManager::MutationKind::CreateDirectory;
                intent.generation = parent; intent.offset = request.permissions; intent.path = argv[8]; break;
            case c::EncryptedMutationKind::Create:
                intent.kind = r::TransactionManager::MutationKind::CreateFile;
                intent.generation = parent; intent.offset = request.permissions; intent.path = argv[8]; intent.payload_checksum = Hash({}); break;
            case c::EncryptedMutationKind::Rename:
                intent.kind = r::TransactionManager::MutationKind::Rename;
                intent.generation = parent; intent.offset = destination; intent.path = argv[8]; intent.secondary_path = argv[9]; break;
            case c::EncryptedMutationKind::Unlink:
                intent.kind = r::TransactionManager::MutationKind::Delete;
                intent.generation = parent; intent.path = argv[8]; break;
            case c::EncryptedMutationKind::SetInodeMetadata:
                intent.kind = r::TransactionManager::MutationKind::SetInodeMetadata;
                intent.generation = xid;
                intent.inline_payload = bytes.data; intent.length = intent.payload_length = bytes.data.size();
                if (phase == L"mismatch") intent.inline_payload[16] = std::byte{0xA4};
                intent.payload_checksum = Hash(intent.inline_payload); break;
            default:
                intent.kind = r::TransactionManager::MutationKind::Write;
                intent.generation = xid; intent.length = intent.payload_length = bytes.data.size(); break;
            }
            if (phase == L"mismatch" && request.kind == c::EncryptedMutationKind::MakeDirectory) intent.offset = 0700;
            std::unique_ptr<r::PayloadSpool> spool;
            if (request.kind == c::EncryptedMutationKind::Write) {
                spool = Spool(directory, binding);
                if (tx->NextMutationSequence() > 1) ReconcileOriginalSpool(*tx, *spool, error);
                intent.wal_sequence = tx->NextMutationSequence(); intent.payload_checksum = Hash(bytes.data);
            }
            const bool capacity = tx->ProtectedMutationCapacityAvailable(intent, error);
            Check(capacity, "CapacityBeforeAccept:" + error);
            Check(tx->Begin(), "NamespaceBegin");
            if (spool) {
                r::PayloadSpool::AppendResult ref;
                Check(spool->Append({"owner-reprepare-dfvfs", inode, xid, 0, tx->NextMutationSequence(), bytes.data}, &ref) && spool->FlushPayloadBytes(), "NamespaceProtectedPayload");
                intent.wal_sequence = ref.wal_sequence; intent.payload_spool_offset = ref.spool_offset; intent.payload_checksum = ref.payload_sha256;
            }
            Check(tx->RecordMutation(intent), "NamespaceRecord"); Check(tx->Accept(xid), "NamespaceAccept");
            sequence = tx->Watermarks().accepted_sequence;
            if (phase == L"accept") {
                owner->Close();
                std::cout << "{\"status\":\"PASS\",\"accepted\":true,\"inode\":" << inode << ",\"xid\":" << xid
                    << ",\"sequence\":" << sequence << ",\"checks\":" << checks << "}\n"; return 0;
            }
        }
        const auto pending = tx->Watermarks();
        bool status_ok = true;
        std::uint64_t cancel_microseconds = 0;
        auto hook = [&](std::string_view stage) {
            if (stage == "before-apple-device-write") {
                ++writes;
                if (view) { c::EncryptedNamespaceInfo info; drained = drained && view->GetNamespaceInfo(info) == c::EncryptedReadError::Closed; }
                if (phase == L"cut") { fault_hit = true; return false; }
                if (phase == L"cancel-staged") {
                    auto future = std::async(std::launch::async, [&] {
                        const auto start = std::chrono::steady_clock::now(); owner->Cancel();
                        return std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start).count();
                    });
                    Check(future.wait_for(std::chrono::seconds(2)) == std::future_status::ready, "CancelDoesNotAcquireHeldCommitGate");
                    cancel_microseconds = static_cast<std::uint64_t>(future.get()); fault_hit = true;
                }
            }
            if (stage == "before-apple-prepublication-flush" && !status_calls) {
                auto future = std::async(std::launch::async, [&] {
                    for (unsigned i = 0; i < 10000; ++i) if (owner->CachedStatus().phase != Phase::Publishing) return false;
                    return true;
                });
                status_ok = future.wait_for(std::chrono::seconds(2)) == std::future_status::ready && future.get();
                status_calls = 10000;
            }
            return status_ok;
        };
        unsigned witness_chunks = 0;
        if (phase == L"partial") journal->SetWitnessFaultInjectionHook([&](std::string_view stage) {
            if (stage == "protected-before-write" && ++witness_chunks == 2) { fault_hit = true; return true; } return false;
        });
        bool published = false;
        if (phase == L"cancel-accepted") { owner->Cancel(); fault_hit = true; }
        if (recovering) {
            if (have_before && operation.starts_with(L"meta")) {
                std::vector<r::TransactionManager::AcceptedTransaction> accepted;
                Check(tx->LoadAcceptedTransactionsSinceCleanup(accepted, &error) && accepted.size() == 1 &&
                    accepted.front().mutations.size() == 1, "ExpectedMetadataOriginal:" + error);
                bytes.data = accepted.front().mutations.front().inline_payload;
                for (auto& row : accepted) for (auto& record : row.mutations)
                    SecureZeroMemory(record.inline_payload.data(), record.inline_payload.size());
            }
            if (phase != L"refuse-witness") {
                Journal::AcceptedDataRecovery classification;
                Check(journal->InspectAcceptedDataRecovery(*tx, sequence, classification, error) && classification ==
                    (phase == L"keyless" ? Journal::AcceptedDataRecovery::CompleteWitness : Journal::AcceptedDataRecovery::TypedReprepareAllowed),
                    "NamespaceRecoveryClassification:" + error);
            }
            published = owner->RecoverAcceptedMutation(*tx, *journal, sequence, {}, error, {}, hook);
        } else published = owner->CommitAcceptedPrepared(*tx, *journal, sequence, xid, std::move(prepared), error, hook);
        const bool cancel_commit = phase == L"cancel-staged" || phase == L"cancel-accepted";
        if (phase == L"cut" || phase == L"partial" || phase == L"mismatch" || phase == L"refuse-witness" || cancel_commit) {
            Check(!published && Same(pending, tx->Watermarks()) && owner->CachedStatus().recovery_required &&
                writes == ((phase == L"cut" || phase == L"cancel-staged") ? 1u : 0u), "NamespaceDebtPreserved:" + error);
            if (phase == L"cut" || phase == L"partial") Check(fault_hit, "NamespaceExactFault");
            Check(!owner->UnlockedSelection(), "RecoverySelectionAbsent");
            if (cancel_commit) Check(error == "ImageWriterCancelled" && owner->CachedStatus().key_present && drained,
                "CancelledAcceptedDebtRequiresFreshOwnerRecovery");
            owner->Close();
            std::cout << "{\"status\":\"PASS\",\"refused\":true,\"fault\":" << (fault_hit ? "true" : "false")
                << ",\"cancelMicroseconds\":" << cancel_microseconds << ",\"inode\":" << inode << ",\"checks\":" << checks << "}\n"; return 0;
        }
        Check(published && writes && drained && status_ok && status_calls == 10000, "NamespacePublish:" + error);
        Check(tx->Watermarks().apfs_durable_sequence == sequence && owner->CachedStatus().checkpoint_xid == xid + 1 &&
            owner->SourceBinding() == binding && owner->SourceIdentity() == identity, "NamespaceExactDurability");
        if (have_before) {
            r::InodeMetadataPatch patch; Check(r::DecodeInodeMetadataPatch(bytes.data, patch), "ObservedCanonicalPatch");
            auto fresh = owner->OpenReadView(re); c::EncryptedNodeInfo after;
            Check(fresh && fresh->GetMetadata(inode, after) == c::EncryptedReadError::None, "PublishedMetadata");
            PreserveMetadata(before, after, patch);
        }
        Check(tx->MarkCleanedThrough(sequence), "NamespaceCallerCleanup");
        const auto final_xid = owner->CachedStatus().checkpoint_xid, free = owner->CachedStatus().free_bytes;
        owner->Lock(); Check(!owner->UnlockedSelection(), "LockedSelectionRevoked");
        owner->Close(); Check(!owner->UnlockedSelection(), "ClosedSelectionRevoked"); owner = Open(image);
        Check(owner->CachedStatus().checkpoint_xid == final_xid && owner->SourceBinding() == binding && !owner->CachedStatus().key_present,
            "NamespaceFreshLockedReopen"); owner->Close();
        std::cout << "{\"status\":\"PASS\",\"inode\":" << inode << ",\"xid\":" << final_xid << ",\"sequence\":" << sequence
            << ",\"freeBytes\":" << free << ",\"statusCalls\":" << status_calls << ",\"checks\":" << checks << "}\n"; return 0;
    } catch (const std::exception& ex) { std::cerr << "EncryptedNamespaceFailure:" << ex.what() << '\n'; return 1; }
}
