#include "TransactionManager.h"
#include "PayloadSpool.h"
#include "NativeHardLink.h"
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#undef CreateFile
#undef CreateDirectory

namespace
{
namespace fs = std::filesystem;
using Tx = apfsaccess::rw::TransactionManager;
using Wal = apfsaccess::rw::WriteAheadLog;
using Spool = apfsaccess::rw::PayloadSpool;
constexpr auto volume = "protected-transaction-volume-canary-4f91";
constexpr auto payload = "PROTECTED_TRANSACTION_PAYLOAD_CANARY_8f539a27";
constexpr auto path = L"\\PRIVATE_TRANSACTION_PATH_CANARY_781592.txt";
std::size_t checks = 0, groups = 0;
fs::path root;

void Check(bool value, const char* message)
{
    ++checks;
    if (!value) throw std::runtime_error(message);
}
std::vector<std::byte> Bytes(std::string_view text)
{
    return {reinterpret_cast<const std::byte*>(text.data()),
        reinterpret_cast<const std::byte*>(text.data() + text.size())};
}
std::array<std::byte, 32> Digest(unsigned n)
{
    std::array<std::byte, 32> result{};
    for (std::size_t i = 0; i < result.size(); ++i)
        result[i] = static_cast<std::byte>((n + i) & 255);
    return result;
}
std::array<std::uint8_t, 32> Hash(std::span<const std::byte> bytes)
{
    std::array<std::uint8_t, 32> digest{};
    Check(BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0,
        reinterpret_cast<PUCHAR>(const_cast<std::byte*>(bytes.data())),
        static_cast<ULONG>(bytes.size()), digest.data(), static_cast<ULONG>(digest.size())) >= 0,
        "test SHA-256");
    return digest;
}
std::vector<std::byte> Read(const fs::path& file)
{
    const auto size = fs::file_size(file);
    Check(size < (128ull << 20), "bounded test read");
    std::vector<std::byte> bytes(static_cast<std::size_t>(size));
    std::ifstream in(file, std::ios::binary);
    Check(static_cast<bool>(in), "open test evidence");
    in.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    Check(static_cast<std::size_t>(in.gcount()) == bytes.size(), "complete test evidence");
    return bytes;
}
void Write(const fs::path& file, std::span<const std::byte> bytes)
{
    std::ofstream out(file, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    out.flush();
    Check(static_cast<bool>(out), "write private refusal fixture");
}
Wal::ProtectedPersistence Protection(const fs::path& directory)
{
    return {directory / "wal-keys", Digest(13), Digest(71), {64ull << 20, 65536}, 256ull << 20};
}
fs::path Case(const char* name)
{
    const auto directory = root / name;
    Check(fs::create_directories(directory / "wal-keys"), "new private case");
    return directory;
}
bool Open(Tx& tx, const fs::path& directory)
{
    std::string error;
    return tx.OpenProtectedJournal((directory / "accepted.wal").wstring(),
        std::wstring(volume, volume + std::char_traits<char>::length(volume)), Protection(directory), error);
}
Tx::MutationIntent InlineWrite()
{
    Tx::MutationIntent mutation;
    mutation.kind = Tx::MutationKind::Write;
    mutation.path = path;
    mutation.object_id = 42;
    mutation.generation = 7;
    mutation.inline_payload = Bytes(payload);
    mutation.length = mutation.payload_length = mutation.inline_payload.size();
    mutation.payload_checksum = Hash(mutation.inline_payload);
    return mutation;
}
template<class Action> void Group(const char* name, Action action)
{
    action();
    ++groups;
    std::cout << "PASS " << name << '\n';
}
std::uint64_t Accepted(const fs::path& directory)
{
    Tx tx(L"Conservative");
    Check(Open(tx, directory), "fresh protected transaction owner");
    Check(tx.Begin() && tx.RecordMutation(InlineWrite()) && tx.Accept(25), "protected acceptance");
    Check(tx.HasUnappliedAcceptedWork(), "accepted work remains pending");
    return tx.Watermarks().accepted_sequence;
}
void AcceptanceAndRecovery()
{
    const auto directory = Case("accept-reopen");
    const auto sequence = Accepted(directory);
    Check(sequence > 0, "nonzero accepted boundary");
    {
        Tx tx(L"Conservative");
        Check(Open(tx, directory), "reopen protected transaction");
        std::vector<Tx::AcceptedTransaction> accepted;
        Check(tx.LoadUnappliedAcceptedTransactions(accepted) && accepted.size() == 1,
            "recovery returns exact accepted transaction");
        Check(accepted[0].accepted_sequence == sequence && accepted[0].preimage_checkpoint_xid == 25 &&
            accepted[0].mutations.size() == 1, "recovery boundary and preimage");
        const auto& record = accepted[0].mutations[0];
        Check(record.inline_payload == Bytes(payload) && record.path_utf8 == Tx::WideToUtf8(path) &&
            record.object_id == 42 && record.parent_object_id == 7, "recovery payload and metadata");
        Check(tx.CanFinalizeWithoutPayloadSpoolFlush(), "inline recovery needs no external spool");
        // This tests persisted watermarks, not an actual APFS durable commit.
        Check(tx.MarkApfsDurableThrough(sequence) && tx.MarkCleanedThrough(sequence), "persist final watermarks");
    }
    {
        Tx tx(L"Conservative");
        Check(Open(tx, directory), "reopen after watermark persistence");
        const auto marks = tx.Watermarks();
        Check(marks.accepted_sequence == sequence && marks.apfs_durable_sequence == sequence &&
            marks.cleanup_sequence == sequence && !tx.HasUnappliedAcceptedWork(), "watermarks survive reopen");
        std::vector<Tx::AcceptedTransaction> accepted;
        Check(tx.LoadUnappliedAcceptedTransactions(accepted) && accepted.empty(), "no duplicate accepted work");
    }
    const auto file = directory / "accepted.wal";
    const auto before = Read(file);
    Check(Wal::ReadAll(file, volume).status != Wal::ReadStatus::Ok, "legacy reader refuses protected WAL");
    Check(Read(file) == before, "legacy inspection preserves protected evidence");
}
void FrozenAuthority()
{
    for (unsigned mode = 0; mode != 3; ++mode)
    {
        const auto directory = Case(("frozen-" + std::to_string(mode)).c_str());
        Accepted(directory);
        const auto before = Read(directory / "accepted.wal");
        Tx tx(L"Conservative");
        Check(Open(tx, directory), "open authority refusal case");
        if (mode == 0) tx.SetJournalPath((directory / "downgraded.wal").wstring());
        if (mode == 1) tx.SetVolumeIdentity(L"different-volume");
        if (mode == 2) tx.SetJournalMaxBytesForTest(1024);
        Check(!tx.RecoveryStateValid() && !tx.Begin() && !tx.RecordMutation(InlineWrite()) &&
            !tx.MarkApfsDurableThrough(tx.Watermarks().accepted_sequence), "retarget poisons owner");
        Check(tx.ConfiguredVolumeIdentity() == std::wstring(volume, volume + std::char_traits<char>::length(volume)),
            "volume authority remains frozen");
        Check(Read(directory / "accepted.wal") == before && !fs::exists(directory / "downgraded.wal"),
            "no downgrade or persistent mutation");
    }
    const auto directory = Case("same-routing");
    Tx tx(L"Conservative");
    Check(Open(tx, directory), "open same-routing case");
    tx.SetJournalPath((directory / "accepted.wal").wstring());
    tx.SetVolumeIdentity(std::wstring(volume, volume + std::char_traits<char>::length(volume)));
    Check(tx.RecoveryStateValid() && tx.Begin() && tx.RecordMutation(InlineWrite()) && tx.Accept(),
        "same routing does not rotate or downgrade protection");
}
void WrongAuthorityAndCorruption()
{
    const auto directory = Case("wrong-authority");
    Accepted(directory);
    const auto file = directory / "accepted.wal";
    const auto before = Read(file);
    for (unsigned mode = 0; mode != 3; ++mode)
    {
        auto protection = Protection(directory);
        if (mode == 0) protection.source_binding[0] ^= std::byte{1};
        if (mode == 1) protection.journal_identity[0] ^= std::byte{1};
        if (mode == 2) { protection.key_directory = directory / "missing-keys"; }
        Tx tx(L"Conservative");
        std::string error;
        Check(!tx.OpenProtectedJournal(file.wstring(), std::wstring(volume, volume + std::char_traits<char>::length(volume)),
            protection, error) && !tx.RecoveryStateValid() && !tx.Begin(), "wrong authority refused");
        Check(Read(file) == before, "wrong authority preserves bytes");
    }
    for (bool torn : {false, true})
    {
        auto corrupt = before;
        if (torn) corrupt.pop_back();
        else corrupt[corrupt.size() / 2] ^= std::byte{1};
        Write(file, corrupt);
        {
            Tx tx(L"Conservative");
            Check(!Open(tx, directory) && !tx.RecoveryStateValid() && !tx.Begin(), "corrupt protected replay refused");
        }
        Check(Read(file) == corrupt, "corrupt evidence never repaired or truncated");
    }
    Write(file, before);
    Tx restored(L"Conservative");
    Check(Open(restored, directory) && restored.HasUnappliedAcceptedWork(), "original retained bytes recover");
}
void PreparedOnlyAndExclusiveOwner()
{
    const auto directory = Case("prepared-only");
    {
        Tx tx(L"Conservative");
        Check(Open(tx, directory), "open prepared owner");
        Tx competitor(L"Conservative");
        Check(!Open(competitor, directory), "concurrent transaction owner refused");
        Check(tx.Begin() && tx.RecordMutation(InlineWrite()) && tx.FlushPreparedRecords(), "persist prepared without acceptance");
    }
    const auto before = Read(directory / "accepted.wal");
    {
        Tx recovery(L"Conservative");
        Check(!Open(recovery, directory) && !recovery.RecoveryStateValid() && !recovery.Begin(),
            "unterminated preparation preserves existing strict refusal");
        std::vector<Tx::AcceptedTransaction> accepted;
        Check(!recovery.LoadUnappliedAcceptedTransactions(accepted) && accepted.empty(),
            "unterminated preparation cannot become accepted work");
    }
    Check(Read(directory / "accepted.wal") == before, "unterminated evidence remains exact");
    const auto aborted = Case("aborted-preparation");
    {
        Tx tx(L"Conservative");
        Check(Open(tx, aborted) && tx.Begin() && tx.RecordMutation(InlineWrite()) &&
            tx.FlushPreparedRecords() && tx.Abort(), "persist explicit abort marker");
    }
    Tx recovery(L"Conservative");
    Check(Open(recovery, aborted), "reopen explicitly aborted history");
    std::vector<Tx::AcceptedTransaction> accepted;
    Check(recovery.LoadUnappliedAcceptedTransactions(accepted) && accepted.empty() &&
        recovery.Begin() && recovery.RecordMutation(InlineWrite()) && recovery.Accept(),
        "new transaction after authenticated explicit abort");
}
void AcceptedSpoolRecovery()
{
    const auto directory = Case("accepted-spool");
    Check(fs::create_directory(directory / "spool"), "create protected spool root");
    Check(fs::create_directory(directory / "spool-keys"), "separate spool epoch lease");
    Spool::Options options;
    options.root = directory / "spool";
    options.volume_identity = volume;
    options.durable_flush_bytes = options.durable_flush_appends = 0;
    options.protected_persistence = true;
    options.protected_binding = Protection(directory).source_binding;
    options.protected_key_directory = directory / "spool-keys";
    const auto bytes = Bytes(payload);
    {
        Spool spool(options);
        Tx tx(L"Conservative");
        Check(Open(tx, directory) && tx.Begin(), "open protected WAL/spool composition");
        Spool::AppendResult reference;
        Check(spool.Append({volume, 42, 7, 0, tx.NextMutationSequence(), bytes}, &reference),
            "append actual protected payload");
        Check(spool.FlushPayloadBytes(), "payload durable before WAL acceptance");
        auto mutation = InlineWrite();
        mutation.inline_payload.clear();
        mutation.wal_sequence = reference.wal_sequence;
        mutation.payload_spool_offset = reference.spool_offset;
        mutation.payload_length = reference.payload_length;
        mutation.payload_checksum = reference.payload_sha256;
        Check(tx.RecordMutation(mutation) && tx.Accept(57), "accept original protected spool reference");
        Check(!tx.CanFinalizeWithoutPayloadSpoolFlush(), "external payload proof remains necessary");
        // Deliberately omit index persistence, simulating exit after durable
        // acceptance while retaining the original journal and payload bytes.
    }
    {
        Tx tx(L"Conservative");
        Check(Open(tx, directory), "reopen original accepted spool journal");
        std::vector<Tx::AcceptedTransaction> accepted;
        Check(tx.LoadUnappliedAcceptedTransactions(accepted) && accepted.size() == 1 &&
            accepted[0].mutations.size() == 1 && accepted[0].preimage_checkpoint_xid == 57,
            "recover original accepted spool mutation");
        const auto& record = accepted[0].mutations[0];
        Spool::PersistedRangeReference reference{volume, record.object_id, record.parent_object_id,
            record.logical_offset, record.payload_length, record.payload_offset,
            record.payload_spool_id, record.payload_sha256};
        Spool spool(options);
        std::vector<std::byte> read;
        Check(spool.RecoveryRequired() && !spool.ReadPersistedRange(reference, read) && read.empty(),
            "unproved spool index is not recovery authority");
        const auto before = Read(options.root / "payload-spool.bin");
        auto wrong = reference;
        ++wrong.spool_offset;
        Check(!spool.RebuildIndexFromReferences(std::span(&wrong, 1), 0), "wrong physical reference refused");
        Check(Read(options.root / "payload-spool.bin") == before, "refusal preserves encrypted payload");
        Check(spool.RebuildIndexFromReferences(std::span(&reference, 1), 0), "rebuild from complete authenticated WAL reference");
        Check(spool.ReadPersistedRange(reference, read) && read == bytes, "recovered original payload exact");
        std::vector<std::byte> overlay(bytes.size(), std::byte{0});
        std::size_t covered = 0;
        Check(spool.ReadFullyCoveredRange({volume, 42, 7, 0, overlay}, covered) &&
            covered == bytes.size() && overlay == bytes, "protected recovered overlay exact");
        Check(!spool.CleanupThroughSequence(reference.wal_sequence), "unsupported cleanup preserves recoverable payload");
        Check(Read(options.root / "payload-spool.bin") == before, "cleanup refusal preserves payload bytes");
    }
}
void AmbiguousAcceptance()
{
    const auto directory = Case("ambiguous-acceptance");
    {
        Tx tx(L"Conservative");
        Check(Open(tx, directory) && tx.Begin() && tx.RecordMutation(InlineWrite()), "prepare ambiguous acceptance");
        Check(tx.FlushPreparedRecords(), "materialize original preparation before acceptance fault");
        const auto before = Read(directory / "accepted.wal");
        bool injected = false;
        tx.SetJournalFaultInjectionHook([&](std::string_view stage) {
            if (!injected && stage == "durable-flush") { injected = true; return true; }
            return false;
        });
        Check(!tx.Accept(81) && injected, "failed durable flush cannot acknowledge acceptance");
        Check(tx.Watermarks().accepted_sequence == 0 && tx.CurrentState() == Tx::State::Failed && !tx.Begin(),
            "ambiguous owner publishes no accepted watermark or retry");
        Check(Read(directory / "accepted.wal").size() > before.size(), "fault follows actual acceptance-marker write");
    }
    Tx recovery(L"Conservative");
    Check(Open(recovery, directory), "reopen complete retained ambiguity evidence");
    std::vector<Tx::AcceptedTransaction> accepted;
    Check(recovery.LoadUnappliedAcceptedTransactions(accepted) && accepted.size() == 1 &&
        accepted[0].preimage_checkpoint_xid == 81 && accepted[0].mutations.size() == 1 &&
        accepted[0].mutations[0].inline_payload == Bytes(payload), "recover original complete accepted record once");
}
void AttributeCapacityAndReplay()
{
    for (unsigned profile = 0; profile < 3; ++profile) {
        const auto directory = Case(("attribute-capacity-" + std::to_string(profile)).c_str());
        Tx::MutationIntent intent;
        intent.kind = profile == 2 ? Tx::MutationKind::RemoveExtendedAttribute : Tx::MutationKind::SetExtendedAttribute;
        intent.object_id = 42; intent.generation = 7; intent.path = L"encrypted-data";
        intent.secondary_path = L"user.raw/name:preserved";
        if (profile == 0) intent.inline_payload = Bytes(payload);
        intent.payload_length = intent.inline_payload.size();
        if (profile != 2) intent.payload_checksum = Hash(intent.inline_payload);
        std::string error;
        {
            Tx tx(L"Conservative");Check(Open(tx,directory),"attribute protected owner");
            Check(tx.ProtectedMutationCapacityAvailable(intent,error),"exact attribute preaccept capacity");
            const auto sequence=tx.NextMutationSequence();
            const bool existed=fs::exists(directory/"accepted.wal");
            const auto before=existed?Read(directory/"accepted.wal"):std::vector<std::byte>{};
            const auto refuse=[&](Tx::MutationIntent bad) {
                Check(!tx.ProtectedMutationCapacityAvailable(bad,error),"malformed attribute capacity refuses");
                Check(tx.NextMutationSequence()==sequence && tx.Watermarks().accepted_sequence==0 &&
                    tx.CurrentState()==Tx::State::Idle,"capacity refusal cannot accept or advance");
                Check(fs::exists(directory/"accepted.wal")==existed &&
                    (!existed || Read(directory/"accepted.wal")==before),"capacity refusal preserves original bytes");
            };
            auto bad=intent;bad.generation=0;refuse(bad);
            bad=intent;bad.offset=1;refuse(bad);
            bad=intent;bad.length=1;refuse(bad);
            bad=intent;bad.payload_spool_offset=1;refuse(bad);
            bad=intent;bad.wal_sequence=sequence;refuse(bad);
            bad=intent;bad.secondary_path.clear();refuse(bad);
            bad=intent;bad.secondary_path.push_back(L'\0');refuse(bad);
            bad=intent;bad.payload_checksum[0]^=1;refuse(bad);
            Check(tx.Begin()&&tx.RecordMutation(intent)&&tx.Accept(7),"attribute original acceptance");
        }
        Tx reopened(L"Conservative");Check(Open(reopened,directory),"fresh attribute original owner");
        std::vector<Tx::AcceptedTransaction> rows;
        Check(reopened.LoadAcceptedTransactionsSinceCleanup(rows,&error)&&rows.size()==1&&rows[0].mutations.size()==1,
            "attribute exact accepted recovery row");
        const auto& record=rows[0].mutations[0];
        Check(record.operation==(profile==2?Wal::OperationKind::RemoveExtendedAttribute:Wal::OperationKind::SetExtendedAttribute)&&
            record.object_id==42&&record.parent_object_id==7&&record.path_utf8=="encrypted-data"&&
            record.secondary_path_utf8=="user.raw/name:preserved"&&!record.logical_offset&&!record.logical_length&&
            !record.payload_offset&&!record.payload_spool_id&&record.inline_payload==intent.inline_payload&&
            record.payload_sha256==intent.payload_checksum&&Wal::ExtendedAttributeMutationIsConsistent(record),
            "attribute original shape and payload survive protected replay");
    }
}
void HardLinkCapacityAndReplay()
{
    using namespace apfsaccess::rw;
    const auto directory = Case("hard-link-capacity");
    NativeHardLinkProof proof;
    proof.container_uuid = std::string(32, '1'); proof.volume_uuid = std::string(32, '2');
    proof.volume_oid = 101; proof.checkpoint = proof.source_generation = 7; proof.source_inode = 17;
    proof.original_parent = proof.destination_parent = 2;
    proof.original_name = "source"; proof.destination_name = "alias";
    proof.first_sibling = 1000; proof.next_object_id = 1007; proof.timestamp_ns = 1234;
    proof.incompatible_features = apfsaccess::catalog::kIncompatCaseInsensitive;
    proof.block_size = 4096; proof.block_count = 512; proof.image_size = 4096 * 512;
    proof.image_creation_time = 7; proof.image_file_id.fill(std::byte{1});
    proof.before_sha.fill(1); proof.after_sha.fill(2); proof.references_sha.fill(3);
    proof.payload_sha.fill(4); proof.publication_sha.fill(5); proof.preimages.push_back({});
    Tx::MutationIntent intent;
    intent.kind = Tx::MutationKind::HardLink; intent.path = L"\\alias"; intent.secondary_path = L"\\source";
    intent.object_id = proof.source_inode; intent.generation = proof.checkpoint;
    intent.inline_payload = EncodeNativeHardLink(proof);
    Check(!intent.inline_payload.empty(), "bounded typed hard-link proof encoded");
    intent.length = intent.payload_length = intent.inline_payload.size();
    intent.payload_checksum = Hash(intent.inline_payload);
    std::string error;
    {
        Tx tx(L"Conservative"); Check(Open(tx, directory), "protected hard-link original owner");
        const auto sequence = tx.NextMutationSequence();
        const bool existed = fs::exists(directory / "accepted.wal");
        const auto before = existed ? Read(directory / "accepted.wal") : std::vector<std::byte>{};
        Check(tx.ProtectedMutationCapacityAvailable(intent, error), "hard-link original preaccept capacity");
        const auto preserve = [&] {
            Check(tx.NextMutationSequence() == sequence && tx.Watermarks().accepted_sequence == 0 &&
                tx.CurrentState() == Tx::State::Idle, "hard-link preflight leaves owner idle and unaccepted");
            Check(fs::exists(directory / "accepted.wal") == existed &&
                (!existed || Read(directory / "accepted.wal") == before), "hard-link preflight preserves original bytes");
        };
        preserve();
        const auto refuse = [&](Tx::MutationIntent bad) {
            Check(!tx.ProtectedMutationCapacityAvailable(bad, error) && !error.empty(), "invalid hard-link capacity refuses");
            preserve();
        };
        auto bad = intent; bad.generation++; refuse(bad);
        bad = intent; bad.object_id++; refuse(bad);
        bad = intent; bad.payload_checksum[0] ^= 1; refuse(bad);
        bad = intent; bad.payload_spool_offset = 1; refuse(bad);
        bad = intent; bad.wal_sequence = sequence; refuse(bad);
        bad = intent; bad.secondary_path = bad.path; refuse(bad);
        bad = intent; bad.offset = 1; refuse(bad);
        bad = intent; bad.replace_if_exists = true; refuse(bad);
        Check(tx.Begin() && tx.RecordMutation(intent) && tx.Accept(proof.checkpoint), "original hard-link acceptance");
    }
    Tx reopened(L"Conservative"); Check(Open(reopened, directory), "fresh protected hard-link owner");
    std::vector<Tx::AcceptedTransaction> rows;
    Check(reopened.LoadAcceptedTransactionsSinceCleanup(rows, &error) && rows.size() == 1 &&
        rows[0].preimage_checkpoint_xid == proof.checkpoint && rows[0].mutations.size() == 1,
        "exact original hard-link recovery boundary");
    const auto& record = rows[0].mutations[0];
    Check(record.operation == Wal::OperationKind::HardLink && record.payload_spool_id == 0 &&
        record.logical_length == intent.inline_payload.size() && record.inline_payload == intent.inline_payload &&
        Wal::NativeHardLinkIsConsistent(record), "typed proof survives without a fabricated spool reference");
}
void ProtectedStartupPreservesHistory()
{
    const auto directory = Case("protected-startup-history");
    std::uint64_t cleaned = 0, pending = 0;
    {
        Tx tx(L"Conservative"); Check(Open(tx, directory), "seed actual protected original");
        Check(tx.Begin() && tx.RecordMutation(InlineWrite()) && tx.Accept(25), "first actual acceptance");
        cleaned = tx.Watermarks().accepted_sequence;
        Check(tx.MarkApfsDurableThrough(cleaned) && tx.MarkCleanedThrough(cleaned), "persist first clean fence");
        auto next = InlineWrite(); next.offset = 128;
        Check(tx.Begin() && tx.RecordMutation(next) && tx.Accept(25), "second pending actual acceptance");
        pending = tx.Watermarks().accepted_sequence;
    }
    const auto original = Read(directory / "accepted.wal");
    const auto open = [&](Tx& tx, const Wal::ProtectedPersistence& protection, const fs::path& journal) {
        std::string error;
        return tx.OpenProtectedStartupJournal(journal.wstring(), std::wstring(volume, volume + std::char_traits<char>::length(volume)),
            protection, error);
    };
    {
        Tx tx(L"Conservative"); Check(open(tx, Protection(directory), directory / "accepted.wal"), "fresh protected startup owner");
        Check(Read(directory / "accepted.wal") == original, "startup leaves original bytes exact");
        const auto marks = tx.Watermarks();
        Check(marks.accepted_sequence == pending && marks.apfs_durable_sequence == cleaned && marks.cleanup_sequence == cleaned,
            "startup preserves all three original fences");
        Tx::RetainedAcceptedHistory history; std::string error;
        Check(tx.LoadRetainedAcceptedHistory(history, error) && history.coverage == Tx::RetainedHistoryCoverage::RetainedComplete &&
            history.cleaned.size() == 1 && history.pending.size() == 1 &&
            history.cleaned[0].accepted_sequence == cleaned && history.pending[0].accepted_sequence == pending &&
            history.pending[0].mutations.size() == 1 && history.pending[0].mutations[0].logical_offset == 128,
            "retained original separates exact cleaned and pending transactions");
        Check(Read(directory / "accepted.wal") == original && tx.Watermarks().accepted_sequence == pending,
            "retained observation never repairs or reseeds owner");
        Tx competitor(L"Conservative");
        Check(!open(competitor, Protection(directory), directory / "accepted.wal"), "live protected startup lease excludes competitor");
    }
    {
        auto wrong = Protection(directory); wrong.source_binding[0] ^= std::byte{1};
        Tx tx(L"Conservative"); Check(!open(tx, wrong, directory / "accepted.wal"), "wrong protected source refuses");
        Check(Read(directory / "accepted.wal") == original, "wrong source leaves exact original");
    }
    auto torn = original; torn.push_back(std::byte{0xa5}); Write(directory / "accepted.wal", torn);
    {
        Tx tx(L"Conservative"); Check(!open(tx, Protection(directory), directory / "accepted.wal"), "torn protected startup evidence refuses");
        Check(Read(directory / "accepted.wal") == torn && !tx.RecoveryStateValid(), "torn suffix preserved without repair");
    }
    const auto absent = Case("protected-startup-absent");
    {
        Tx tx(L"Conservative"); Check(open(tx, Protection(absent), absent / "accepted.wal"), "fresh absent startup observation");
        Check(!fs::exists(absent / "accepted.wal") && fs::is_empty(absent / "wal-keys"), "observation creates no absent original or keys");
    }
}
void ScanPersistence()
{
    const std::wstring wide_path(path);
    const auto utf8_path = Bytes(Tx::WideToUtf8(path));
    const auto raw_payload = Bytes(payload);
    const auto raw_volume = Bytes(volume);
    const auto utf16_path = std::span<const std::byte>(reinterpret_cast<const std::byte*>(wide_path.data()), wide_path.size() * 2);
    std::size_t count = 0;
    for (const auto& entry : fs::recursive_directory_iterator(root))
    {
        Check(!entry.is_symlink(), "no linked persistence fixture");
        if (!entry.is_regular_file()) continue;
        const auto bytes = Read(entry.path());
        for (const auto needle : {std::span<const std::byte>(utf8_path), std::span<const std::byte>(raw_payload),
                std::span<const std::byte>(raw_volume), utf16_path})
            Check(std::search(bytes.begin(), bytes.end(), needle.begin(), needle.end()) == bytes.end(), "no plaintext persistence canary");
        ++count;
    }
    Check(count > 5, "non-vacuous persistence scan");
    std::cout << "SCAN " << count << " persisted files\n";
}
}

int wmain(int argc, wchar_t** argv)
{
    try
    {
        Check(argc == 2, "one local evidence root required");
        root = fs::path(argv[1]).make_preferred();
        Check(root.is_absolute() && root.native().size() > 3 && root.native()[1] == L':' &&
            root.native()[2] == L'\\' && GetDriveTypeW(root.root_path().c_str()) == DRIVE_FIXED &&
            !fs::exists(root), "fresh fixed-local test root required");
        Check(fs::create_directories(root), "create evidence root");
        Group("protected acceptance, exact replay and persisted watermarks", AcceptanceAndRecovery);
        Group("frozen protected owner routing and downgrade refusal", FrozenAuthority);
        Group("wrong authority, tamper and torn history preservation", WrongAuthorityAndCorruption);
        Group("prepared-only recovery and exclusive owner", PreparedOnlyAndExclusiveOwner);
        Group("actual protected spool acceptance and original-reference recovery", AcceptedSpoolRecovery);
        Group("ambiguous durable acceptance retains original recovery evidence", AmbiguousAcceptance);
        Group("attribute preaccept capacity and exact protected replay", AttributeCapacityAndReplay);
        Group("hard-link preaccept capacity and exact protected original replay", HardLinkCapacityAndReplay);
        Group("protected startup preserves complete original history and refuses torn evidence", ProtectedStartupPreservesHistory);
        Group("ciphertext-only persisted transaction scan", ScanPersistence);
        std::cout << "PASS " << groups << " groups / " << checks << " assertions\n";
        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
