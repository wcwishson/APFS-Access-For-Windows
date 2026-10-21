#include "ApfsEncryptedImageWriteSession.h"
#define wmain HistoricalRecoveryMain
#include "ApfsEncryptedImageRecoveryTests.cpp"
#undef wmain
#undef CreateDirectory

int wmain(int argc, wchar_t** argv)
{
    try {
        Check(argc == 5, "Arguments:image,journal,phase,name");
        const auto image = fs::absolute(argv[1]).lexically_normal(), directory = fs::absolute(argv[2]).lexically_normal();
        Check(image.wstring().starts_with(L"D:\\ApfsAccessScratch\\BN7\\") &&
            directory.wstring().starts_with(L"D:\\ApfsAccessScratch\\BN7\\"), "PrivateStatusImageOnly");
        const std::wstring phase = argv[3];
        const auto name = r::TransactionManager::WideToUtf8(argv[4]);
        Check(phase == L"commit" || phase == L"cut" || phase == L"recover" || phase == L"recover-typed", "KnownStatusPhase");
        auto owner = Open(image); Unlock(*owner);
        const auto initial = owner->CachedStatus();
        Check(initial.phase == Phase::Ready && !initial.recovery_required && initial.free_space_valid, "ReadyImageCapability");
        fs::create_directories(directory); std::string error;
        auto tx = std::make_unique<r::TransactionManager>(L"Conservative");
        Check(tx->OpenProtectedJournal((directory / "original.wal").wstring(), L"owner-reprepare-dfvfs",
            Protection(directory, owner->SourceBinding(), "original-v2"), error), "StatusOriginal:" + error);
        Journal::Options options;
        options.container_bytes = initial.container_bytes; options.container_uuid = owner->ContainerUuid();
        options.preimage_source_identity = owner->SourceIdentity(); options.volume_object_id = owner->VolumeObjectId();
        options.volume_uuid = owner->VolumeUuid();
        options.witness = {directory / "witness.wal", "status-witness-v2", 64ull << 20,
            Protection(directory, owner->SourceBinding(), "witness-v2")};
        auto journal = std::make_unique<Journal>(options);
        const bool recovering = phase == L"recover" || phase == L"recover-typed";
        std::unique_ptr<Owner::PreparedMutation> prepared;
        std::uint64_t inode = 0, sequence = tx->Watermarks().accepted_sequence;
        if (!recovering) {
            c::EncryptedMutationRequest request;
            request.kind = c::EncryptedMutationKind::MakeDirectory; request.parent = 2; request.name = name; request.permissions = 0750;
            prepared = owner->PrepareMutation(initial.checkpoint_xid, request, error);
            Check(static_cast<bool>(prepared), "StatusPrepare:" + error); inode = prepared->Intent().RequestedInode();
            r::TransactionManager::MutationIntent intent;
            intent.kind = r::TransactionManager::MutationKind::CreateDirectory;
            intent.object_id = inode; intent.generation = 2; intent.offset = 0750; intent.path = argv[4];
            Check(tx->ProtectedMutationCapacityAvailable(intent, error) && tx->Begin() && tx->RecordMutation(intent) &&
                tx->Accept(initial.checkpoint_xid), "StatusAuthenticAcceptance:" + error);
            sequence = tx->Watermarks().accepted_sequence;
        } else {
            std::vector<r::TransactionManager::AcceptedTransaction> pending;
            Check(tx->LoadAcceptedTransactionsSinceCleanup(pending, &error) && pending.size() == 1 &&
                pending.front().mutations.size() == 1 && pending.front().accepted_sequence == sequence,
                "StatusSingleOriginal:" + error);
            inode = pending.front().mutations.front().object_id;
        }
        const auto pending = tx->Watermarks();
        Check(pending.accepted_sequence > pending.cleanup_sequence && pending.apfs_durable_sequence < sequence,
            "RuntimeCleanupDebtIndependentOfImageCapability");
        bool stage_ok = true, publish_ok = true, cut = false;
        unsigned stage_calls = 0, publish_calls = 0;
        journal->SetWitnessFaultInjectionHook([&](std::string_view boundary) {
            if (boundary == "protected-before-write") {
                const auto status = owner->CachedStatus(); ++stage_calls;
                stage_ok = stage_ok && status.phase == Phase::Preparing && !status.recovery_required &&
                    status.free_space_valid && status.key_present;
            }
            return false;
        });
        const auto hook = [&](std::string_view boundary) {
            const auto status = owner->CachedStatus(); ++publish_calls;
            publish_ok = publish_ok && status.phase == Phase::Publishing && status.recovery_required == recovering &&
                status.free_space_valid && status.key_present;
            if (boundary == "before-apple-device-write" && phase == L"cut") { cut = true; return false; }
            return true;
        };
        bool ok = false;
        if (phase == L"recover") ok = owner->RecoverAccepted(*tx, *journal, sequence, error, hook);
        else if (phase == L"recover-typed") ok = owner->RecoverAcceptedMutation(*tx, *journal, sequence, {}, error, {}, hook);
        else ok = owner->CommitAcceptedPrepared(*tx, *journal, sequence, initial.checkpoint_xid, std::move(prepared), error, hook);
        Check(publish_calls && publish_ok && (recovering || (stage_calls && stage_ok)), "ExactActiveAndRecoveryStatus:" + error);
        const auto final = owner->CachedStatus();
        if (phase == L"cut") {
            Check(!ok && cut && final.phase == Phase::RecoveryRequired && final.recovery_required && Same(pending, tx->Watermarks()),
                "FailedCommitRetainsImageRecoveryAndOriginalDebt");
        } else {
            Check(ok && final.phase == Phase::Ready && !final.recovery_required && final.free_space_valid &&
                final.checkpoint_xid == initial.checkpoint_xid + 1 && tx->Watermarks().accepted_sequence == sequence &&
                tx->Watermarks().apfs_durable_sequence == sequence && tx->Watermarks().cleanup_sequence < sequence,
                "SuccessfulImageReadyBeforeCallerCleanup:" + error);
            c::EncryptedReadError re{}; auto view = owner->OpenReadView(re); c::EncryptedNodeInfo node;
            Check(view && view->GetMetadata(inode, node) == c::EncryptedReadError::None && node.IsDirectory() && node.parent_id == 2,
                "StatusPublishedDirectoryReread");
            Check(tx->MarkCleanedThrough(sequence), "StatusCallerCleanup");
        }
        owner->Close();
        std::cout << "{\"status\":\"PASS\",\"inode\":" << inode << ",\"xid\":" << final.checkpoint_xid
            << ",\"sequence\":" << sequence << ",\"stageCalls\":" << stage_calls << ",\"publishCalls\":" << publish_calls
            << ",\"cut\":" << (cut ? "true" : "false") << ",\"checks\":" << checks << "}\n";
        return 0;
    } catch (const std::exception& ex) { std::cerr << "WriterStatusFailure:" << ex.what() << '\n'; return 1; }
}
