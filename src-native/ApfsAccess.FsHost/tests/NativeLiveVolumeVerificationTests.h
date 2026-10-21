#pragma once

namespace {
struct VerificationJournalUnchanged
{
    HostVerification& host;
    Unchanged bytes;
    std::vector<Tx::DurabilityWatermarks> watermarks;
    std::vector<std::uint64_t> opens, flushes, scans, sequences;
    explicit VerificationJournalUnchanged(HostVerification& value) : host(value), bytes(value)
    {
        for (const auto& c : host.contexts)
        {
            watermarks.push_back(c->tx_manager->Watermarks());
            opens.push_back(c->tx_manager->JournalAppendHandleOpenCount());
            flushes.push_back(c->tx_manager->JournalAppendHandleFlushCount());
            scans.push_back(c->tx_manager->FinalizationCoverageWalScanCount());
            sequences.push_back(c->tx_manager->NextMutationSequence());
        }
    }
    void Assert()
    {
        bytes.Assert();
        for (std::size_t i = 0; i < host.contexts.size(); ++i)
        {
            const auto& journal = *host.contexts[i]->tx_manager;
            const auto marks = journal.Watermarks();
            Check(marks.accepted_sequence == watermarks[i].accepted_sequence &&
                marks.apfs_durable_sequence == watermarks[i].apfs_durable_sequence &&
                marks.cleanup_sequence == watermarks[i].cleanup_sequence &&
                journal.NextMutationSequence() == sequences[i], "inspection does not reseed watermarks or sequence");
            Check(journal.JournalAppendHandleOpenCount() == opens[i] &&
                journal.JournalAppendHandleFlushCount() == flushes[i] &&
                journal.FinalizationCoverageWalScanCount() == scans[i], "inspection does not acquire, append, flush or scan WAL history");
        }
    }
};

void UncleanDirectCommitVerificationRefusal()
{
    for (const bool peer : {false, true})
        for (const bool mixed : {false, true})
            for (const bool empty : {false, true})
            {
                const auto name = std::string("direct-proof-") + (peer ? "peer-" : "target-") +
                    (mixed ? "mixed-" : "pure-") + (empty ? "empty" : "mutation");
                HostVerification host(name, 0, true, true);
                const auto request = host.Request();
                auto& journal = *host.contexts[peer ? 1 : 0]->tx_manager;
                Tx::MutationIntent mutation;
                mutation.kind = Tx::MutationKind::CreateFile;
                mutation.path = L"\\unclean-direct-proof";
                std::uint64_t earlier = 0;
                if (mixed)
                {
                    Check(journal.Begin() && journal.RecordMutation(mutation) && journal.Accept(20), "earlier true acceptance");
                    earlier = journal.Watermarks().accepted_sequence;
                }
                Check(journal.Begin() && (empty || journal.RecordMutation(mutation)) && journal.Commit(20), "persist later direct Commit");
                const auto direct = journal.LastCommittedSequence();
                if (mixed)
                    Check(journal.MarkApfsDurableThrough(earlier) && journal.MarkCleanedThrough(earlier), "clean only earlier acceptance");
                const auto marks = journal.Watermarks();
                Check(direct > marks.cleanup_sequence && marks.accepted_sequence == marks.apfs_durable_sequence &&
                    marks.apfs_durable_sequence == marks.cleanup_sequence, "equal accepted watermarks do not cover direct Commit");
                VerificationJournalUnchanged unchanged(host);
                Check(journal.ValidatedCleanJournalGeneration() == 0, "direct Commit has no validated clean generation");
                Check(!GetVolumeVerificationCapability(host.Context(), *host.owner), "unclean target or sibling direct Commit hides capability");
                Refused(host.Run(request), "unclean target or sibling direct Commit refuses actual verifier");
                unchanged.Assert();
                if (mixed)
                    Check(journal.LastCommittedSequence() <= marks.cleanup_sequence,
                        "regression needs separate monotone bound after earlier cleanup lowers last_committed");
            }
    Pass("target and sibling pure/mixed empty/nonempty direct Commit boundaries refuse without WAL mutation");
}

void CompletedReceiptVerificationRefusal()
{
    for (const bool peer : {false, true})
        for (const bool torn : {false, true})
        {
            HostVerification host(std::string("receipt-proof-") + (peer ? "peer-" : "target-") + (torn ? "torn" : "checksum"), 0, true, true);
            const auto request = host.Request();
            auto& context = *host.contexts[peer ? 1 : 0];
            auto& journal = *context.tx_manager;
            journal.SetJournalMaxBytesForTest(1400);
            journal.SetJournalPath(context.tx_journal_file.wstring());
            std::string error;
            Check(journal.AcquireJournalOwnership(error), "reconfigure bounded journal owner: " + error);
            auto receipt = context.tx_journal_file;
            receipt += L".compact.intent";
            for (unsigned i = 0; i < 20 && !std::filesystem::exists(receipt); ++i)
            {
                Tx::MutationIntent mutation;
                mutation.kind = Tx::MutationKind::CreateFile;
                mutation.path = L"\\cleaned-compaction-proof-" + std::to_wstring(i);
                Check(journal.Begin() && journal.RecordMutation(mutation) && journal.Accept(20), "force actual completed compaction");
                const auto accepted = journal.Watermarks().accepted_sequence;
                Check(journal.MarkApfsDurableThrough(accepted) && journal.MarkCleanedThrough(accepted), "complete known cleanup");
            }
            Check(std::filesystem::exists(receipt), "real completed compaction receipt exists");
            bool tombstone = false;
            const auto prefix = context.tx_journal_file.filename().wstring() + L".compact.predecessor.";
            for (const auto& entry : std::filesystem::directory_iterator(context.tx_journal_file.parent_path()))
                if (entry.path().filename().wstring().starts_with(prefix))
                {
                    Check(entry.is_regular_file() && entry.file_size() == 0, "real predecessor tombstone is an ordinary zero-byte file");
                    tombstone = true;
                }
            Check(tombstone, "completed compaction preserves its old-identity tombstone");
            const auto original_receipt = FileBytes(receipt);
            VerificationJournalUnchanged healthy(host);
            Check(journal.ValidatedCleanJournalGeneration() != 0, "completed receipt retains validated clean generation");
            Check(GetVolumeVerificationCapability(host.Context(), *host.owner).has_value(), "valid completed receipt and zero predecessor preserve capability");
            const auto healthy_result = host.Run(request);
            Check(healthy_result.success && healthy_result.volume_verification &&
                healthy_result.volume_verification->report.outcome == VerificationOutcome::Complete, "valid completed proof verifies without repair");
            healthy.Assert();
            Check(FileBytes(receipt) == original_receipt, "healthy receipt remains unchanged");
            auto broken = original_receipt;
            Check(broken.size() > 1, "completed proof bytes");
            if (torn) broken.pop_back(); else broken.front() ^= std::byte{1};
            SaveBytes(receipt, broken);
            VerificationJournalUnchanged unchanged(host);
            Check(journal.ValidatedCleanJournalGeneration() == 0, "malformed receipt has no clean generation");
            Check(!GetVolumeVerificationCapability(host.Context(), *host.owner), "malformed completed proof on any peer hides capability");
            Refused(host.Run(request), "malformed completed proof refuses without replay");
            unchanged.Assert();
            Check(FileBytes(receipt) == broken, "inspection does not repair or truncate owned receipt");
        }
    Pass("valid completed receipt/tombstone accepted; changed or torn target/sibling proof refused read-only");
}

void LostJournalProofVerificationRefusal()
{
    for (const bool peer : {false, true})
        for (const bool transfer : {false, true})
        {
            HostVerification host(std::string("lease-proof-") + (peer ? "peer-" : "target-") + (transfer ? "transfer" : "hardlink"), 0, true, true);
            const auto request = host.Request();
            auto& context = *host.contexts[peer ? 1 : 0];
            std::unique_ptr<Tx> replacement;
            std::filesystem::path alias;
            if (transfer)
            {
                const auto path = context.tx_journal_file.wstring();
                context.tx_manager->SetJournalPath(L"");
                replacement = std::make_unique<Tx>(L"Strict");
                replacement->SetJournalPath(path);
                replacement->SetVolumeIdentity(L"apfs-vol:" + context.args.container_id + L":" + std::to_wstring(context.container_volume_oid));
                std::string error;
                Check(replacement->AcquireJournalOwnership(error), "separate replacement owns released journal: " + error);
            }
            else
            {
                alias = context.tx_journal_file;
                alias += L".unexpected-link";
                Check(CreateHardLinkW(alias.c_str(), context.tx_journal_file.c_str(), nullptr), "add unexpected link to held WAL");
            }
            VerificationJournalUnchanged unchanged(host);
            Check(context.tx_manager->ValidatedCleanJournalGeneration() == 0, "lost owner/path proof has no clean generation");
            Check(!GetVolumeVerificationCapability(host.Context(), *host.owner), "lost target/sibling journal proof hides capability");
            Refused(host.Run(request), "lost journal proof refuses without ownership acquisition");
            unchanged.Assert();
            if (replacement)
                Check(replacement->OwnsJournalForMaintenance(context.tx_journal_file.wstring(),
                    L"apfs-vol:" + context.args.container_id + L":" + std::to_wstring(context.container_volume_oid)), "inspection leaves replacement owner held");
            if (!alias.empty()) Check(FileBytes(alias) == FileBytes(context.tx_journal_file), "unexpected hardlink remains untouched");
        }
    Pass("target/sibling hardlinks and ownership transfers refuse without acquiring or replaying journal");
}
}
