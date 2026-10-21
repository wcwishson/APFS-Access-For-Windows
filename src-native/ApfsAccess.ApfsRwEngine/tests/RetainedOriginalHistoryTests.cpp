#include "TransactionManager.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>

using Tx = apfsaccess::rw::TransactionManager;
using Wal = apfsaccess::rw::WriteAheadLog;
namespace {
unsigned checks = 0;
void Check(bool value, const std::string& reason) {
    if (!value) throw std::runtime_error(reason);
    ++checks; std::cout << "PASS " << reason << '\n';
}
std::vector<char> Bytes(const std::filesystem::path& path) {
    std::ifstream f(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}
std::uint64_t Accept(Tx& tx, std::uint64_t xid, bool clean) {
    Tx::MutationIntent m; m.kind = Tx::MutationKind::SetBasicInfo;
    m.path = L"/original"; m.object_id = 30; m.timestamp_utc = xid;
    Check(tx.Begin() && tx.RecordMutation(m) && tx.Accept(xid), "actual original acceptance");
    const auto sequence = tx.Watermarks().accepted_sequence;
    if (clean) Check(tx.MarkApfsDurableThrough(sequence) && tx.MarkCleanedThrough(sequence), "actual original cleanup");
    return sequence;
}
void Chain(const std::filesystem::path& root) {
    const auto path = root / L"chain.wal"; std::string error;
    std::uint64_t a = 0, b = 0, c = 0;
    {
        Tx tx(L"strict"); Check(tx.OpenStartupJournal(path.wstring(), L"history-chain", error), "absent startup lease");
        Tx::RetainedAcceptedHistory h;
        Check(tx.LoadRetainedAcceptedHistory(h, error) && h.coverage == Tx::RetainedHistoryCoverage::NoAcceptedHistory &&
            h.cleaned.empty() && h.pending.empty() && !std::filesystem::exists(path), "empty observation creates no original WAL");
        Check(tx.MaterializeAbsentStartupJournal(error), "materialize actual journal");
        a = Accept(tx, 20, true); b = Accept(tx, 21, true); c = Accept(tx, 22, false);
        const auto before = Bytes(path); const auto generation = tx.ObservedJournalWriterLeaseGeneration();
        Check(tx.LoadRetainedAcceptedHistory(h, error) && h.coverage == Tx::RetainedHistoryCoverage::RetainedComplete,
            "complete retained original chain with pending debt");
        Check(h.cleaned.size() == 2 && h.pending.size() == 1 && h.cleaned[0].accepted_sequence == a &&
            h.cleaned[1].accepted_sequence == b && h.pending[0].accepted_sequence == c &&
            h.cleaned[0].preimage_checkpoint_xid == 20 && h.cleaned[1].preimage_checkpoint_xid == 21 &&
            h.pending[0].preimage_checkpoint_xid == 22, "all original boundaries retain order and exact preimages");
        Check(h.pending[0].mutations.size() == 1 && h.pending[0].mutations[0].object_id == 30 &&
            h.pending[0].mutations[0].logical_offset == 22 && h.pending[0].mutations[0].path_utf8 == "/original",
            "original mutation fields survive observation");
        Check(h.watermarks.accepted_sequence == c && h.watermarks.apfs_durable_sequence == b &&
            h.watermarks.cleanup_sequence == b && h.writer_lease_generation == generation && before == Bytes(path),
            "reader preserves debt, bytes and held lease");
        Check(!tx.LoadRetainedAcceptedHistory(h, error, {32, 1}) && error == "RetainedHistoryResourceLimit" &&
            h.cleaned.empty() && h.pending.empty() && before == Bytes(path), "bounded read failure clears results without repair");
        Check(tx.LoadRetainedAcceptedHistory(h, error) && h.pending.size() == 1, "full bounded retry retains real debt");
        Tx contender(L"strict");
        Check(!contender.OpenStartupJournal(path.wstring(), L"history-chain", error), "competing owner cannot obtain original authority");
        Check(tx.Begin(), "enter active transaction");
        Check(!tx.LoadRetainedAcceptedHistory(h, error) && h.cleaned.empty() && h.pending.empty(), "active owner cannot return idle history proof");
        Check(tx.Abort(), "close unaccepted active transaction");
    }
    {
        Tx tx(L"strict"); Tx::RetainedAcceptedHistory h;
        Check(tx.OpenStartupJournal(path.wstring(), L"history-chain", error) && tx.LoadRetainedAcceptedHistory(h, error) &&
            h.cleaned.size() == 2 && h.pending.size() == 1, "fresh owner recovers full prefix and debt");
        Check(tx.MarkApfsDurableThrough(c) && tx.LoadRetainedAcceptedHistory(h, error) && h.pending.size() == 1 &&
            h.watermarks.apfs_durable_sequence == c && h.watermarks.cleanup_sequence == b,
            "durable but uncleaned accepted row remains pending");
        Check(tx.MarkCleanedThrough(c) && tx.LoadRetainedAcceptedHistory(h, error) && h.cleaned.size() == 3 &&
            h.pending.empty() && h.watermarks.cleanup_sequence == c, "fully cleaned chain remains retained original proof");
    }
}
void Compacted(const std::filesystem::path& root) {
    const auto path = root / L"compacted.wal"; std::string error; std::uint64_t first = 0, pending = 0;
    {
        Tx tx(L"strict"); tx.SetVolumeIdentity(L"history-compacted"); tx.SetJournalPath(path.wstring());
        first = Accept(tx, 30, true); pending = Accept(tx, 31, false);
    }
    {
        Wal wal({path, "history-compacted"});
        Check(wal.Compact(first), "actual WAL compaction prunes cleaned mutation body");
    }
    const auto before = Bytes(path);
    Tx tx(L"strict"); Tx::RetainedAcceptedHistory h;
    Check(tx.OpenStartupJournal(path.wstring(), L"history-compacted", error) && tx.LoadRetainedAcceptedHistory(h, error),
        "compacted original remains readable under startup owner");
    Check(h.coverage == Tx::RetainedHistoryCoverage::Unavailable && h.cleaned.empty() && h.pending.size() == 1 &&
        h.pending[0].accepted_sequence == pending && h.watermarks.cleanup_sequence == first && before == Bytes(path),
        "pruned prefix is unavailable and never hides retained pending debt");
}
void Invalid(const std::filesystem::path& root) {
    const auto path = root / L"incomplete.wal";
    {
        Wal wal({path, "history-invalid"}); Wal::Record marker;
        marker.volume_identity = "history-invalid"; marker.transaction_id = 1; marker.sequence = 2;
        marker.operation = Wal::OperationKind::TransactionMarker; marker.state = Wal::RecordState::Accepted;
        marker.flags = 8; marker.logical_length = 1; marker.object_id = 40;
        Check(wal.Append(marker), "checksum-valid marker without original preparation fixture");
    }
    const auto before = Bytes(path); Tx tx(L"strict"); std::string error; Tx::RetainedAcceptedHistory h;
    Check(!tx.OpenStartupJournal(path.wstring(), L"history-invalid", error) &&
        !tx.LoadRetainedAcceptedHistory(h, error) && h.pending.empty() && before == Bytes(path),
        "missing accepted body refuses and preserves evidence");
    const auto torn = root / L"torn.wal";
    {
        Tx writer(L"strict"); writer.SetVolumeIdentity(L"history-torn"); writer.SetJournalPath(torn.wstring()); Accept(writer, 50, true);
    }
    { std::ofstream f(torn, std::ios::binary | std::ios::app); f << "torn"; }
    const auto damaged = Bytes(torn); Tx observer(L"strict");
    Check(!observer.OpenStartupJournal(torn.wstring(), L"history-torn", error) &&
        !observer.LoadRetainedAcceptedHistory(h, error) && damaged == Bytes(torn), "torn original is never truncated or called clean");
}
}
int wmain(int argc, wchar_t** argv) try {
    if (argc != 2) return 2;
    const std::filesystem::path root(argv[1]);
    if (!root.is_absolute() || !root.wstring().starts_with(L"D:\\ApfsAccessScratch\\WindowsClosure\\fusion-service-20261017\\")) return 2;
    std::filesystem::create_directories(root); Chain(root); Compacted(root); Invalid(root);
    std::cout << "PASS " << checks << " retained original history checks\n"; return 0;
} catch (const std::exception& e) { std::cerr << "FAIL " << e.what() << '\n'; return 1; }
