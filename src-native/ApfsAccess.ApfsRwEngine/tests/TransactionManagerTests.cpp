#include "TransactionManager.h"
#include "InodeMetadataPatch.h"
#include "WriteAheadLog.h"
#include "PayloadSpool.h"
#include "NativeSnapshotIntent.h"

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <string>
#include <string_view>
#include <vector>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <windows.h>
#include <bcrypt.h>

#undef CreateFile
#undef CreateDirectory

namespace
{
bool Require(bool condition, const std::string& message)
{
    if (!condition)
    {
        std::cerr << "[FAIL] " << message << std::endl;
        return false;
    }

    return true;
}

bool EnvironmentFlag(const char* name)
{
    char* value = nullptr;
    std::size_t value_size = 0;
    if (_dupenv_s(&value, &value_size, name) != 0 || !value)
    {
        if (value)
        {
            std::free(value);
        }
        return false;
    }

    const std::string text(value);
    std::free(value);
    return text == "1" || text == "true" || text == "on";
}

std::uint64_t EnvironmentUnsigned(const char* name, std::uint64_t fallback)
{
    char* value = nullptr;
    std::size_t value_size = 0;
    if (_dupenv_s(&value, &value_size, name) != 0 || !value)
    {
        if (value)
        {
            std::free(value);
        }
        return fallback;
    }

    const std::string text(value);
    std::free(value);
    try
    {
        return std::stoull(text);
    }
    catch (...)
    {
        return fallback;
    }
}

bool TestDirectoryRestoreAcceptance(const std::filesystem::path& run_root)
{
    using namespace apfsaccess::rw;
    using Tx = TransactionManager;
    static_assert(static_cast<int>(Tx::MutationKind::RestoreDirectoryFromSymbolicLink) == 14);
    Tx::MutationIntent restore{};
    restore.kind = Tx::MutationKind::RestoreDirectoryFromSymbolicLink;
    restore.path = L"\\directory";
    restore.object_id = 42;
    restore.generation = 7;
    for (bool journal : {false, true})
    {
        Tx tx(L"DeferredContent");
        if (journal) tx.SetJournalPath((run_root / "invalid-directory-restore.wal").wstring());
        if (!tx.Begin()) return false;
        const auto sequence = tx.NextMutationSequence();
        const auto reject = [&](auto change)
        {
            auto bad = restore;
            change(bad);
            return Require(!tx.RecordMutation(bad) && tx.NextMutationSequence() == sequence &&
                tx.PendingMutationCount() == 0, "invalid restore does not consume sequence or queue intent");
        };
        if (!reject([](auto& m) { m.object_id = 0; }) ||
            !reject([](auto& m) { m.generation = 0; }) ||
            !reject([](auto& m) { m.path.clear(); }) ||
            !reject([](auto& m) { m.path.push_back(L'\0'); }) ||
            !reject([](auto& m) { m.path = std::wstring(1, wchar_t{0xd800}); }) ||
            !reject([](auto& m) { m.secondary_path = L"other"; }) ||
            !reject([](auto& m) { m.secondary_path = std::wstring(1, wchar_t{0xd800}); }) ||
            !reject([](auto& m) { m.offset = 1; }) ||
            !reject([](auto& m) { m.length = 1; }) ||
            !reject([](auto& m) { m.timestamp_utc = 1; }) ||
            !reject([](auto& m) { m.replace_if_exists = true; }) ||
            !reject([](auto& m) { m.payload_spool_offset = 1; }) ||
            !reject([](auto& m) { m.payload_length = 1; }) ||
            !reject([](auto& m) { m.payload_checksum.back() = 1; }) ||
            !reject([](auto& m) { m.inline_payload = {std::byte{1}}; }) ||
            !reject([](auto& m) { m.unlink_outcome.emplace(); })) return false;
        if (!tx.Abort()) return false;
    }
    const auto path = run_root / "directory-restore-accept.wal";
    std::uint64_t transaction_id = 0;
    {
        Tx tx(L"DeferredContent");
        tx.SetVolumeIdentity(L"directory-restore-volume");
        tx.SetJournalPath(path.wstring());
        if (!tx.Begin()) return false;
        transaction_id = tx.CurrentTransactionId();
        auto old = restore;
        old.kind = Tx::MutationKind::RemoveSymbolicLinkTarget;
        if (!Require(tx.RecordMutation(restore) && tx.RecordMutation(old) &&
                tx.CanAcceptWithoutPayloadSpoolFlush() && tx.Accept(123),
                "restore and old removal accept without a payload spool")) return false;
    }
    Tx reopened(L"DeferredContent");
    reopened.SetVolumeIdentity(L"directory-restore-volume");
    reopened.SetJournalPath(path.wstring());
    std::vector<Tx::AcceptedTransaction> accepted;
    if (!Require(reopened.RecoveryStateValid() && reopened.LoadUnappliedAcceptedTransactions(accepted) &&
            accepted.size() == 1 && accepted[0].mutations.size() == 2 &&
            accepted[0].transaction_id == transaction_id && accepted[0].preimage_checkpoint_xid == 123 &&
            reopened.CanFinalizeWithoutPayloadSpoolFlush(false),
            "reload preserves accepted restore without recovery payload")) return false;
    const auto& record = accepted[0].mutations[0];
    return Require(record.operation == WriteAheadLog::OperationKind::RestoreDirectoryFromSymbolicLink &&
        record.object_id == 42 && record.parent_object_id == 7 && record.path_utf8 == "\\directory" &&
        record.sequence == 1 && record.transaction_id == transaction_id &&
        WriteAheadLog::DirectoryRestoreMutationIsConsistent(record) &&
        accepted[0].mutations[1].operation == WriteAheadLog::OperationKind::RemoveSymbolicLinkTarget &&
        accepted[0].mutations[1].sequence == 2,
        "reloaded op14 identity and old symlink removal remain distinct");
}

bool TestAllocationSizeAcceptanceOrder(const std::filesystem::path& run_root)
{
    using namespace apfsaccess::rw;
    using Tx = TransactionManager;
    static_assert(static_cast<int>(Tx::MutationKind::SetAllocationSize) == 13);
    Tx::MutationIntent allocation{};
    allocation.kind = Tx::MutationKind::SetAllocationSize;
    allocation.path = L"\\allocation.bin";
    allocation.object_id = 42;
    allocation.generation = 7;
    allocation.length = 4096;
    for (bool journal : {false, true})
    {
        Tx tx(L"DeferredContent");
        if (journal) tx.SetJournalPath((run_root / "invalid-allocation.wal").wstring());
        if (!tx.Begin()) return false;
        const auto sequence = tx.NextMutationSequence();
        const auto reject = [&](auto change)
        {
            auto bad = allocation;
            change(bad);
            return Require(!tx.RecordMutation(bad) && tx.NextMutationSequence() == sequence &&
                    tx.PendingMutationCount() == 0, "invalid allocation does not consume sequence or queue intent");
        };
        if (!reject([](auto& m) { m.object_id = 0; }) ||
            !reject([](auto& m) { m.generation = 0; }) ||
            !reject([](auto& m) { m.path.clear(); }) ||
            !reject([](auto& m) { m.offset = 1; }) ||
            !reject([](auto& m) { m.length = 0x8000000000000000ull; }) ||
            !reject([](auto& m) { m.timestamp_utc = 1; }) ||
            !reject([](auto& m) { m.secondary_path = L"other"; }) ||
            !reject([](auto& m) { m.replace_if_exists = true; }) ||
            !reject([](auto& m) { m.payload_length = 1; }) ||
            !reject([](auto& m) { m.payload_spool_offset = 1; }) ||
            !reject([](auto& m) { m.inline_payload = {std::byte{1}}; }) ||
            !reject([](auto& m) { m.payload_checksum[0] = 1; }) ||
            !reject([](auto& m) { m.unlink_outcome.emplace(); })) return false;
        if (!tx.Abort()) return false;
    }
    const auto path = run_root / "allocation-order.wal";
    const std::vector<Tx::MutationKind> kinds{
        Tx::MutationKind::Write, Tx::MutationKind::SetFileSize,
        Tx::MutationKind::SetAllocationSize, Tx::MutationKind::SetFileSize,
        Tx::MutationKind::Write, Tx::MutationKind::SetAllocationSize};
    const std::vector<std::uint64_t> lengths{8192, 2048, 0, 16384, 4, 0};
    {
        Tx tx(L"DeferredContent");
        tx.SetJournalPath(path.wstring());
        if (!tx.Begin()) return false;
        for (std::size_t i = 0; i < kinds.size(); ++i)
        {
            auto mutation = allocation;
            mutation.kind = kinds[i];
            mutation.length = lengths[i];
            if (!Require(tx.RecordMutation(mutation), "ordered mutation admitted")) return false;
        }
        if (!Require(tx.Accept(), "ordered transaction accepted")) return false;
    }
    {
        WriteAheadLog wal({path, "default"});
        if (!Require(wal.Compact(1), "WAL retains entire accepted ordering")) return false;
    }
    Tx reopened(L"DeferredContent");
    reopened.SetJournalPath(path.wstring());
    std::vector<Tx::AcceptedTransaction> accepted;
    if (!Require(reopened.RecoveryStateValid() && reopened.LoadUnappliedAcceptedTransactions(accepted) &&
            accepted.size() == 1 && accepted[0].mutations.size() == kinds.size(),
            "recovery retains writes, truncate, repeated allocation barriers and later growth")) return false;
    const std::vector<WriteAheadLog::OperationKind> operations{
        WriteAheadLog::OperationKind::Write, WriteAheadLog::OperationKind::SetFileSize,
        WriteAheadLog::OperationKind::SetAllocationSize, WriteAheadLog::OperationKind::SetFileSize,
        WriteAheadLog::OperationKind::Write, WriteAheadLog::OperationKind::SetAllocationSize};
    for (std::size_t i = 0; i < operations.size(); ++i)
    {
        const auto& record = accepted[0].mutations[i];
        if (!Require(record.operation == operations[i] && record.logical_length == lengths[i] &&
                record.sequence == i + 1 && record.object_id == 42 && record.parent_object_id == 7 &&
                record.path_utf8 == "\\allocation.bin",
                "replay preserves exact mutation order, lengths and identity")) return false;
    }
    return true;
}

bool TestInodeMetadataAcceptance(const std::filesystem::path& run_root)
{
    using namespace apfsaccess::rw;
    using Tx = TransactionManager;
    static_assert(static_cast<int>(Tx::MutationKind::SetInodeMetadata) == 12);
    Tx::MutationIntent mutation{};
    mutation.kind = Tx::MutationKind::SetInodeMetadata;
    mutation.path = L"\\metadata";
    mutation.object_id = 42;
    mutation.generation = 7;
    mutation.length = mutation.payload_length = 52;
    InodeMetadataPatch patch{};
    patch.mask = InodeMetadataPatch::Owner;
    patch.owner = 0x12345678;
    if (!EncodeInodeMetadataPatch(patch, mutation.inline_payload)) return false;
    mutation.payload_checksum = {
        0x03, 0x7b, 0x15, 0xb0, 0xff, 0xc8, 0x63, 0xec,
        0xc3, 0x21, 0x63, 0x7d, 0x91, 0x94, 0x61, 0x2d,
        0xa2, 0x5c, 0xc4, 0x76, 0x67, 0x96, 0x4e, 0x41,
        0x0f, 0x23, 0xf0, 0xdc, 0x68, 0x22, 0xfc, 0xe2,
    };
    const auto path = run_root / "inode-metadata.wal";
    {
        Tx tx(L"DeferredContent");
        tx.SetVolumeIdentity(L"inode-metadata-volume");
        tx.SetJournalPath(path.wstring());
        if (!Require(tx.Begin() && tx.RecordMutation(mutation) && tx.Accept(),
                "metadata is durably accepted through the existing inline envelope")) return false;
        std::vector<Tx::AcceptedTransaction> accepted;
        std::string error;
        if (!Require(tx.LoadAcceptedTransactionsSinceCleanup(accepted, &error) &&
                accepted.size() == 1 && accepted[0].mutations.size() == 1 &&
                accepted[0].mutations[0].operation == WriteAheadLog::OperationKind::SetInodeMetadata &&
                accepted[0].mutations[0].inline_payload == mutation.inline_payload &&
                accepted[0].mutations[0].logical_length == 0 &&
                accepted[0].mutations[0].payload_length == 52 &&
                accepted[0].mutations[0].payload_spool_id == 0 &&
                tx.CanFinalizeWithoutPayloadSpoolFlush(false),
                "accepted metadata has complete inline recovery coverage: " + error)) return false;
    }
    {
        WriteAheadLog wal({path, "inode-metadata-volume"});
        if (!Require(wal.Compact(1), "accepted metadata transaction compacts")) return false;
    }
    {
        Tx reopened(L"DeferredContent");
        reopened.SetVolumeIdentity(L"inode-metadata-volume");
        reopened.SetJournalPath(path.wstring());
        std::vector<Tx::AcceptedTransaction> accepted;
        std::string error;
        if (!Require(reopened.RecoveryStateValid() &&
                reopened.LoadUnappliedAcceptedTransactions(accepted, &error) &&
                accepted.size() == 1 && accepted[0].mutations.size() == 1 &&
                accepted[0].mutations[0].inline_payload == mutation.inline_payload &&
                reopened.CanFinalizeWithoutPayloadSpoolFlush(false),
                "reopen recovers accepted metadata without spool data: " + error)) return false;
    }
    for (bool journal : {false, true})
    {
        Tx invalid(L"DeferredContent");
        if (journal)
        {
            invalid.SetVolumeIdentity(L"invalid-metadata-volume");
            invalid.SetJournalPath((run_root / "invalid-inode-metadata.wal").wstring());
        }
        if (!invalid.Begin()) return false;
        const auto sequence = invalid.NextMutationSequence();
        const auto reject = [&](auto change)
        {
            auto bad = mutation;
            change(bad);
            return Require(!invalid.RecordMutation(bad) && invalid.NextMutationSequence() == sequence,
                "malformed metadata requests reject before consuming a WAL sequence");
        };
        if (!reject([](auto& m) { m.length = 0; }) ||
            !reject([](auto& m) { m.length = 51; }) ||
            !reject([](auto& m) { m.length = 53; }) ||
            !reject([](auto& m) { m.payload_length = 0; }) ||
            !reject([](auto& m) { m.object_id = 0; }) ||
            !reject([](auto& m) { m.generation = 0; }) ||
            !reject([](auto& m) { m.offset = 1; }) ||
            !reject([](auto& m) { m.timestamp_utc = 1; }) ||
            !reject([](auto& m) { m.payload_spool_offset = 1; }) ||
            !reject([](auto& m) { m.replace_if_exists = true; }) ||
            !reject([](auto& m) { m.secondary_path = L"other"; }) ||
            !reject([](auto& m) { m.secondary_path.assign(1, static_cast<wchar_t>(0xd800)); }) ||
            !reject([](auto& m) { m.path.clear(); }) ||
            !reject([](auto& m) { m.payload_checksum[0] ^= 1; }) ||
            !reject([](auto& m) { m.inline_payload[4] = std::byte{128}; }) ||
            !reject([](auto& m) { m.unlink_outcome = UnlinkOutcome{}; })) return false;
        if (!Require(invalid.RecordMutation(mutation) && invalid.Abort(),
                "rejections leave room for a subsequent valid metadata request")) return false;
    }
    return true;
}

bool TestUnlinkOutcomeAcceptance(const std::filesystem::path& run_root)
{
    using Tx = apfsaccess::rw::TransactionManager;
    Tx tx(L"Conservative");
    tx.SetVolumeIdentity(L"unlink-outcome-volume");
    tx.SetJournalPath((run_root / "unlink-outcome.wal").wstring());
    Tx::MutationIntent mutation;
    mutation.kind = Tx::MutationKind::Delete;
    mutation.path = L"\\alias";
    mutation.object_id = 17;
    mutation.generation = 9;
    mutation.unlink_outcome = apfsaccess::rw::UnlinkOutcome{17, 9, 12, 2, 2, 1, "\\alias"};
    if (!Require(tx.Begin() && tx.RecordMutation(mutation) && tx.Accept(),
            "versioned unlink outcome can be accepted durably")) return false;
    std::vector<Tx::AcceptedTransaction> accepted;
    std::string error;
    if (!Require(tx.LoadAcceptedTransactionsSinceCleanup(accepted, &error) &&
            accepted.size() == 1 && accepted[0].mutations.size() == 1 &&
            accepted[0].mutations[0].unlink_outcome == mutation.unlink_outcome,
            "accepted transaction preserves the native unlink outcome: " + error)) return false;
    if (!Require(tx.Begin(), "next unlink transaction begins")) return false;
    const auto sequence = tx.NextMutationSequence();
    ++mutation.object_id;
    if (!Require(!tx.RecordMutation(mutation) && tx.NextMutationSequence() == sequence,
            "mismatched outcome identity is rejected before buffering or advancing the sequence")) return false;
    return Require(tx.Abort(), "invalid unlink transaction aborts cleanly");
}

bool TestExtendedAttributeAcceptanceAndValidation(const std::filesystem::path& run_root)
{
    using Tx = apfsaccess::rw::TransactionManager;
    using Wal = apfsaccess::rw::WriteAheadLog;
    const std::array<std::uint8_t, Wal::PayloadHashSize> binary_hash{
        0xe8, 0x05, 0x90, 0x12, 0xc1, 0x4b, 0x6e, 0xda,
        0xac, 0xa0, 0x24, 0x0f, 0x60, 0xe1, 0xe7, 0x66,
        0xc6, 0x45, 0x20, 0xb0, 0x70, 0x49, 0x0f, 0xbd,
        0x35, 0x07, 0x61, 0xe6, 0x54, 0xd4, 0xae, 0xb9,
    };
    const std::array<std::uint8_t, Wal::PayloadHashSize> empty_hash{
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    };

    Tx::MutationIntent binary;
    binary.kind = Tx::MutationKind::SetExtendedAttribute;
    binary.path = L"\\docs\\file.bin";
    binary.secondary_path = L"user.binary";
    binary.object_id = 41;
    binary.generation = 7;
    binary.payload_length = 4;
    binary.payload_checksum = binary_hash;
    binary.inline_payload = {
        std::byte{0x00}, std::byte{0x11}, std::byte{0x80}, std::byte{0xff}};

    auto empty = binary;
    empty.secondary_path = L"user.empty";
    empty.payload_length = 0;
    empty.payload_checksum = empty_hash;
    empty.inline_payload.clear();

    Tx::MutationIntent remove;
    remove.kind = Tx::MutationKind::RemoveExtendedAttribute;
    remove.path = binary.path;
    remove.secondary_path = empty.secondary_path;
    remove.object_id = binary.object_id;
    remove.generation = binary.generation;

    const auto path = run_root / "transaction-xattrs.wal";
    Tx tx(L"DeferredContent");
    tx.SetVolumeIdentity(L"transaction-xattrs-volume");
    tx.SetJournalPath(path.wstring());
    if (!Require(tx.Begin(), "xattr transaction begins") ||
        !Require(
            tx.RecordMutation(binary) && tx.RecordMutation(empty) && tx.RecordMutation(remove),
            "set binary, set empty, and remove xattr mutations are recorded") ||
        !Require(
            tx.CanAcceptWithoutPayloadSpoolFlush(),
            "embedded xattrs are fully covered by WAL bytes without payload-spool durability") ||
        !Require(tx.Accept(), "xattr transaction reaches an accepted WAL boundary"))
    {
        return false;
    }

    const auto raw = Wal::ReadAll(path, "transaction-xattrs-volume");
    if (!Require(
            raw.status == Wal::ReadStatus::Ok && raw.records.size() == 4 &&
                raw.records[0].operation == Wal::OperationKind::SetExtendedAttribute &&
                raw.records[0].inline_payload == binary.inline_payload &&
                raw.records[0].payload_spool_id == 0 &&
                raw.records[0].payload_offset == 0 &&
                raw.records[0].logical_offset == 0 &&
                raw.records[0].logical_length == 0 &&
                raw.records[1].operation == Wal::OperationKind::SetExtendedAttribute &&
                raw.records[1].payload_sha256 == empty_hash &&
                raw.records[2].operation == Wal::OperationKind::RemoveExtendedAttribute &&
                raw.records[2].payload_length == 0 &&
                raw.records[2].inline_payload.empty(),
            "accepted WAL preserves xattrs without representing them as file ranges or spool references"))
    {
        return false;
    }

    std::vector<Tx::AcceptedTransaction> accepted;
    std::string failure_reason;
    if (!Require(
            tx.LoadAcceptedTransactionsSinceCleanup(accepted, &failure_reason) &&
                accepted.size() == 1 && accepted.front().mutations.size() == 3 &&
                accepted.front().mutations[0].secondary_path_utf8 == "user.binary" &&
                accepted.front().mutations[0].inline_payload == binary.inline_payload &&
                accepted.front().mutations[1].operation == Wal::OperationKind::SetExtendedAttribute &&
                accepted.front().mutations[1].inline_payload.empty() &&
                accepted.front().mutations[2].operation == Wal::OperationKind::RemoveExtendedAttribute,
            "accepted transaction reload retains exact xattr operations and bytes: " + failure_reason) ||
        !Require(
            tx.CanFinalizeWithoutPayloadSpoolFlush(false),
            "strict WAL-scanned finalization accepts complete embedded xattr coverage"))
    {
        return false;
    }

    Tx restarted(L"DeferredContent");
    restarted.SetVolumeIdentity(L"transaction-xattrs-volume");
    restarted.SetJournalPath(path.wstring());
    accepted.clear();
    if (!Require(
            restarted.RecoveryStateValid() &&
                restarted.LoadUnappliedAcceptedTransactions(accepted, &failure_reason) &&
                accepted.size() == 1 && accepted.front().mutations.size() == 3 &&
                accepted.front().mutations[0].inline_payload == binary.inline_payload &&
                accepted.front().mutations[1].payload_sha256 == empty_hash &&
                accepted.front().mutations[2].operation == Wal::OperationKind::RemoveExtendedAttribute,
            "restart reconstructs the accepted xattr transaction: " + failure_reason))
    {
        return false;
    }

    Tx invalid(L"DeferredContent");
    invalid.SetVolumeIdentity(L"transaction-xattrs-invalid-volume");
    invalid.SetJournalPath((run_root / "transaction-xattrs-invalid.wal").wstring());
    if (!Require(invalid.Begin(), "invalid xattr fixture begins"))
    {
        return false;
    }
    const auto require_rejected = [&](const Tx::MutationIntent& mutation, const std::string& message)
    {
        const auto sequence = invalid.NextMutationSequence();
        return Require(
            !invalid.RecordMutation(mutation) && invalid.NextMutationSequence() == sequence &&
                invalid.PendingMutationCount() == 0,
            message);
    };

    auto malformed = binary;
    malformed.payload_checksum[0] ^= 0xff;
    if (!require_rejected(malformed, "xattr set with an incorrect hash rejects before sequence advance"))
    {
        return false;
    }
    malformed = binary;
    ++malformed.payload_length;
    if (!require_rejected(malformed, "xattr set with an incorrect payload length rejects"))
    {
        return false;
    }
    malformed = binary;
    malformed.secondary_path.clear();
    if (!require_rejected(malformed, "xattr set with an empty exact attribute name rejects"))
    {
        return false;
    }
    malformed = binary;
    malformed.secondary_path.assign(1, static_cast<wchar_t>(0xd800));
    if (!require_rejected(malformed, "xattr set rejects an attribute name that cannot encode as strict UTF-8"))
    {
        return false;
    }
    malformed = binary;
    malformed.inline_payload.assign(Wal::MaxExtendedAttributePayloadBytes + 1, std::byte{0x8a});
    malformed.payload_length = malformed.inline_payload.size();
    if (!require_rejected(malformed, "xattr set above 3804 bytes rejects"))
    {
        return false;
    }
    malformed = binary;
    malformed.payload_spool_offset = 1;
    if (!require_rejected(malformed, "xattr set cannot carry a payload-spool offset"))
    {
        return false;
    }
    malformed = binary;
    malformed.offset = 1;
    if (!require_rejected(malformed, "xattr set cannot masquerade as a file range"))
    {
        return false;
    }
    malformed = binary;
    malformed.replace_if_exists = true;
    if (!require_rejected(malformed, "xattr set rejects foreign mutation flags"))
    {
        return false;
    }
    auto malformed_remove = remove;
    malformed_remove.inline_payload = binary.inline_payload;
    malformed_remove.payload_length = binary.payload_length;
    malformed_remove.payload_checksum = binary_hash;
    if (!require_rejected(malformed_remove, "xattr remove cannot carry payload bytes"))
    {
        return false;
    }
    return Require(invalid.Abort(), "invalid xattr fixture aborts without buffered mutations");
}

bool RunAcceptanceBenchmark(const std::filesystem::path& run_root)
{
    const auto file_count = (std::max)(
        std::uint64_t{1},
        EnvironmentUnsigned("APFSACCESS_ACCEPTANCE_BENCHMARK_FILES", 64));
    const auto group_size = (std::min)(
        (std::min)(file_count, std::uint64_t{16}),
        (std::max)(
            std::uint64_t{1},
            EnvironmentUnsigned("APFSACCESS_ACCEPTANCE_GROUP_SIZE", 1)));
    constexpr std::size_t payload_bytes = 16 * 1024;
    const auto benchmark_root = run_root / "acceptance-benchmark";
    const std::string volume_identity = "acceptance-benchmark-volume";
    apfsaccess::rw::PayloadSpool spool({
        benchmark_root / "spool",
        volume_identity,
        128ull * 1024ull * 1024ull,
        128ull * 1024ull * 1024ull,
        8192,
    });
    apfsaccess::rw::TransactionManager tx(L"DeferredContent");
    tx.SetVolumeIdentity(L"acceptance-benchmark-volume");
    tx.SetJournalPath((benchmark_root / "write-ahead.wal").wstring());
    std::vector<std::byte> payload(payload_bytes, std::byte{0x5a});
    const bool deferred_index_persistence =
        !EnvironmentFlag("APFSACCESS_DISABLE_DEFERRED_INDEX_PERSISTENCE");

    const auto started = std::chrono::steady_clock::now();
    std::uint64_t accepted_targets = 0;
    for (std::uint64_t batch_start = 0; batch_start < file_count; batch_start += group_size)
    {
        if (!tx.Begin())
        {
            return Require(false, "Acceptance benchmark transaction should begin");
        }
        const auto batch_end = (std::min)(file_count, batch_start + group_size);
        for (auto index = batch_start; index < batch_end; ++index)
        {
            const auto wal_sequence = tx.NextMutationSequence();
            apfsaccess::rw::PayloadSpool::AppendResult reference{};
            if (!spool.Append({
                    volume_identity,
                    1000 + index,
                    1,
                    0,
                    wal_sequence,
                    std::span<const std::byte>(payload.data(), payload.size()),
                }, &reference))
            {
                return Require(false, "Acceptance benchmark payload append should succeed");
            }

            apfsaccess::rw::TransactionManager::MutationIntent mutation{};
            mutation.kind = apfsaccess::rw::TransactionManager::MutationKind::Write;
            mutation.path = L"\\small-" + std::to_wstring(index) + L".bin";
            mutation.length = payload.size();
            mutation.wal_sequence = reference.wal_sequence;
            mutation.object_id = reference.object_id;
            mutation.generation = reference.generation;
            mutation.payload_spool_offset = reference.spool_offset;
            mutation.payload_length = reference.payload_length;
            mutation.payload_checksum = reference.payload_sha256;
            if (!tx.RecordMutation(mutation))
            {
                return Require(false, "Acceptance benchmark mutation should be recorded");
            }
        }

        const bool payload_boundary_flushed = deferred_index_persistence
            ? spool.FlushPayloadBytes()
            : spool.FlushDirtyState();
        if (!payload_boundary_flushed || !tx.Accept())
        {
            return Require(false, "Acceptance benchmark durable boundary should succeed");
        }
        ++accepted_targets;
    }

    const auto acceptance_finished = std::chrono::steady_clock::now();
    if (deferred_index_persistence && !spool.FlushDirtyState())
    {
        return Require(false, "Acceptance benchmark final index persistence should succeed");
    }
    const auto finished = std::chrono::steady_clock::now();

    const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
        finished - started).count();
    const auto acceptance_elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
        acceptance_finished - started).count();
    const auto final_drain_elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
        finished - acceptance_finished).count();
    const auto spool_counters = spool.SnapshotCounters();
    const auto watermarks = tx.Watermarks();
    std::cout << "[BENCH] mode=" << (deferred_index_persistence ? "payload-only" : "full-index")
              << " files=" << file_count
              << " groupSize=" << group_size
              << " payloadBytes=" << payload_bytes
              << " wallUs=" << elapsed
              << " acceptanceUs=" << acceptance_elapsed
              << " finalDrainUs=" << final_drain_elapsed
              << " acceptedTargets=" << accepted_targets
              << " acceptedSequence=" << watermarks.accepted_sequence
              << " payloadOnlyFlushUs=" << spool_counters.payload_only_flush_microseconds
              << " payloadOnlyFlushCount=" << spool_counters.payload_only_flush_count
              << " spoolFlushUs=" << spool_counters.durable_flush_microseconds
              << " spoolSyncCount=" << spool_counters.spool_sync_count
              << " spoolSyncUs=" << spool_counters.spool_sync_microseconds
              << " spoolSyncHandleFlushes=" << spool_counters.spool_sync_handle_flush_count
              << " spoolSyncReopens=" << spool_counters.spool_sync_reopen_count
              << " indexPersistUs=" << spool_counters.index_persist_microseconds
              << " indexPersistBytes=" << spool_counters.index_persist_bytes
              << " indexJournalFrames=" << spool_counters.index_journal_frame_count
              << " indexJournalSnapshots=" << spool_counters.index_journal_snapshot_count
              << " indexJournalAppendFrames=" << spool_counters.index_journal_append_count
              << " indexJournalHandleOpens=" << spool_counters.index_journal_handle_open_count
              << " indexJournalHandleFlushes=" << spool_counters.index_journal_handle_flush_count
              << " walAppendUs=" << tx.DurableJournalAppendMicroseconds()
              << " walAppendMaxUs=" << tx.DurableJournalAppendMaxMicroseconds()
              << " walAppendCount=" << tx.DurableJournalAppendCount()
              << " walHandleOpens=" << tx.JournalAppendHandleOpenCount()
              << " walHandleFlushes=" << tx.JournalAppendHandleFlushCount()
              << std::endl;
    return true;
}

bool RunFinalizationCoverageBenchmark(const std::filesystem::path& run_root)
{
    constexpr std::uint64_t wal_flag_committed = 0x1;
    const auto history_transactions = (std::max)(
        std::uint64_t{1},
        EnvironmentUnsigned("APFSACCESS_FINALIZATION_BENCHMARK_HISTORY", 2048));
    const auto iterations = (std::max)(
        std::uint64_t{1},
        EnvironmentUnsigned("APFSACCESS_FINALIZATION_BENCHMARK_ITERATIONS", 8));
    const auto path_bytes = static_cast<std::size_t>((std::max)(
        std::uint64_t{32},
        EnvironmentUnsigned("APFSACCESS_FINALIZATION_BENCHMARK_PATH_BYTES", 2048)));
    const bool use_cache = !EnvironmentFlag("APFSACCESS_DISABLE_FINALIZATION_COVERAGE_CACHE");
    const auto benchmark_root = run_root / "finalization-coverage-benchmark";
    const auto wal_path = benchmark_root / "write-ahead.wal";
    const std::string volume_identity = "finalization-coverage-benchmark-volume";
    std::filesystem::create_directories(benchmark_root);

    std::vector<apfsaccess::rw::WriteAheadLog::Record> history;
    history.reserve(static_cast<std::size_t>(history_transactions * 2 + 1));
    std::uint64_t sequence = 1;
    std::uint64_t latest_accepted_sequence = 0;
    for (std::uint64_t index = 0; index < history_transactions; ++index)
    {
        apfsaccess::rw::WriteAheadLog::Record prepared{};
        prepared.volume_identity = volume_identity;
        prepared.transaction_id = index + 1;
        prepared.sequence = sequence++;
        prepared.operation = apfsaccess::rw::WriteAheadLog::OperationKind::SetBasicInfo;
        prepared.state = apfsaccess::rw::WriteAheadLog::RecordState::Prepared;
        prepared.path_utf8.assign(path_bytes, static_cast<char>('a' + (index % 26)));
        history.push_back(std::move(prepared));

        apfsaccess::rw::WriteAheadLog::Record marker{};
        marker.volume_identity = volume_identity;
        marker.transaction_id = index + 1;
        marker.sequence = sequence++;
        marker.operation = apfsaccess::rw::WriteAheadLog::OperationKind::TransactionMarker;
        marker.state = apfsaccess::rw::WriteAheadLog::RecordState::Checkpointed;
        marker.flags = wal_flag_committed;
        marker.logical_length = 1;
        latest_accepted_sequence = marker.sequence;
        history.push_back(std::move(marker));
    }

    apfsaccess::rw::WriteAheadLog::Record cleanup{};
    cleanup.volume_identity = volume_identity;
    cleanup.sequence = sequence++;
    cleanup.operation = apfsaccess::rw::WriteAheadLog::OperationKind::DurabilityWatermark;
    cleanup.state = apfsaccess::rw::WriteAheadLog::RecordState::Cleaned;
    cleanup.logical_offset = latest_accepted_sequence;
    history.push_back(std::move(cleanup));
    {
        apfsaccess::rw::WriteAheadLog wal({
            wal_path,
            volume_identity,
            128ull * 1024ull * 1024ull,
        });
        if (!wal.AppendBatch(history))
        {
            return Require(false, "Finalization benchmark history should persist");
        }
    }

    apfsaccess::rw::TransactionManager tx(L"DeferredContent");
    tx.SetVolumeIdentity(L"finalization-coverage-benchmark-volume");
    tx.SetJournalPath(wal_path.wstring());
    const std::vector<std::byte> inline_payload{
        std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
    };
    const std::array<std::uint8_t, apfsaccess::rw::WriteAheadLog::PayloadHashSize> inline_payload_sha256{
        0x9f, 0x64, 0xa7, 0x47, 0xe1, 0xb9, 0x7f, 0x13,
        0x1f, 0xab, 0xb6, 0xb4, 0x47, 0x29, 0x6c, 0x9b,
        0x6f, 0x02, 0x01, 0xe7, 0x9f, 0xb3, 0xc5, 0x35,
        0x6e, 0x6c, 0x77, 0xe8, 0x9b, 0x6a, 0x80, 0x6a,
    };
    apfsaccess::rw::TransactionManager::MutationIntent mutation{};
    mutation.kind = apfsaccess::rw::TransactionManager::MutationKind::Write;
    mutation.path = L"\\current.bin";
    mutation.length = inline_payload.size();
    mutation.object_id = history_transactions + 100;
    mutation.generation = 1;
    mutation.payload_spool_offset = 4096;
    mutation.payload_length = inline_payload.size();
    mutation.payload_checksum = inline_payload_sha256;
    mutation.inline_payload = inline_payload;
    if (!tx.Begin() || !tx.RecordMutation(mutation) || !tx.Accept())
    {
        return Require(false, "Finalization benchmark inline transaction should become accepted");
    }

    bool eligible = true;
    const auto started = std::chrono::steady_clock::now();
    for (std::uint64_t iteration = 0; iteration < iterations; ++iteration)
    {
        eligible = tx.CanFinalizeWithoutPayloadSpoolFlush(use_cache) && eligible;
    }
    const auto finished = std::chrono::steady_clock::now();
    const auto elapsed_us = std::chrono::duration_cast<std::chrono::microseconds>(
        finished - started).count();
    std::error_code size_error;
    const auto wal_bytes = std::filesystem::file_size(wal_path, size_error);
    std::cout << "[BENCH] mode=" << (use_cache ? "coverage-cache" : "wal-scan")
              << " historyTransactions=" << history_transactions
              << " iterations=" << iterations
              << " walBytes=" << (size_error ? 0 : wal_bytes)
              << " wallUs=" << elapsed_us
              << " perCallUs=" << (elapsed_us / static_cast<long long>(iterations))
              << " cacheHits=" << tx.FinalizationCoverageCacheHitCount()
              << " walScans=" << tx.FinalizationCoverageWalScanCount()
              << " walScanUs=" << tx.FinalizationCoverageWalScanMicroseconds()
              << std::endl;
    return Require(eligible, "Finalization benchmark transaction should remain inline-recoverable");
}

apfsaccess::rw::TransactionManager::MutationIntent MakeMetadataMutation(std::wstring path)
{
    apfsaccess::rw::TransactionManager::MutationIntent mutation{};
    mutation.kind = apfsaccess::rw::TransactionManager::MutationKind::SetBasicInfo;
    mutation.path = std::move(path);
    mutation.timestamp_utc = 123456789;
    return mutation;
}

bool TestConfigurationOrderAndLeaseTransfer(const std::filesystem::path& run_root)
{
    const auto path = run_root / "configuration-order-and-lease-transfer.wal";
    constexpr auto identity = L"configuration-order-volume";
    auto first_mutation = MakeMetadataMutation(L"\\first.txt");

    apfsaccess::rw::TransactionManager path_first(L"DeferredContent");
    path_first.SetJournalPath(path.wstring());
    path_first.SetVolumeIdentity(identity);
    if (!Require(path_first.Begin(), "path-first manager should begin") ||
        !Require(path_first.RecordMutation(first_mutation), "path-first manager should record metadata") ||
        !Require(path_first.Accept(), "path-first manager should accept its first transaction"))
    {
        return false;
    }
    const auto first_accepted_sequence = path_first.Watermarks().accepted_sequence;

    apfsaccess::rw::TransactionManager identity_first(L"DeferredContent");
    identity_first.SetVolumeIdentity(identity);
    identity_first.SetJournalPath(path.wstring());
    if (!Require(identity_first.RecoveryStateValid(), "identity-first configuration should recover the same WAL") ||
        !Require(
            identity_first.Watermarks().accepted_sequence == first_accepted_sequence &&
                identity_first.NextMutationSequence() > first_accepted_sequence,
            "configuration order should reconstruct identical sequence and watermark state") ||
        !Require(
            identity_first.MarkApfsDurableThrough(first_accepted_sequence),
            "the successor manager should append the APFS durability watermark") ||
        !Require(
            path_first.MarkCleanedThrough(first_accepted_sequence),
            "an idle stale manager should reacquire, reseed, and append the cleanup watermark"))
    {
        return false;
    }

    auto second_mutation = MakeMetadataMutation(L"\\second.txt");
    if (!Require(path_first.Begin(), "reseeded stale manager should begin a later transaction") ||
        !Require(path_first.RecordMutation(second_mutation), "reseeded stale manager should record later metadata") ||
        !Require(path_first.Accept(), "reseeded stale manager should append a later acceptance"))
    {
        return false;
    }
    const auto second_accepted_sequence = path_first.Watermarks().accepted_sequence;
    const auto snapshot = apfsaccess::rw::WriteAheadLog::ReadAll(
        path,
        apfsaccess::rw::TransactionManager::WideToUtf8(identity));
    if (!Require(snapshot.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok, "lease-transfer WAL should remain readable"))
    {
        return false;
    }
    std::uint64_t previous_sequence = 0;
    for (const auto& record : snapshot.records)
    {
        if (!Require(
                record.sequence > previous_sequence,
                "stale-manager reacquisition must preserve unique increasing WAL sequences"))
        {
            return false;
        }
        previous_sequence = record.sequence;
    }

    apfsaccess::rw::TransactionManager recovered(L"DeferredContent");
    recovered.SetJournalPath(path.wstring());
    recovered.SetVolumeIdentity(identity);
    if (!Require(
            recovered.Watermarks().accepted_sequence == second_accepted_sequence &&
                recovered.Watermarks().apfs_durable_sequence == first_accepted_sequence &&
                recovered.Watermarks().cleanup_sequence == first_accepted_sequence,
            "restart should retain independent watermarks across stale-manager lease transfer") ||
        !Require(path_first.CanFinalizeWithoutPayloadSpoolFlush(), "previous manager should rescan after restart takes its lease") ||
        !Require(path_first.CanFinalizeWithoutPayloadSpoolFlush(), "previous manager should cache its newly leased snapshot") ||
        !Require(recovered.CanFinalizeWithoutPayloadSpoolFlush(), "restarted manager should rescan after the lease returns") ||
        !Require(recovered.CanFinalizeWithoutPayloadSpoolFlush(), "restarted manager should cache its reacquired snapshot"))
    {
        return false;
    }
    return Require(
               path_first.FinalizationCoverageWalScanCount() == 1 &&
                   path_first.FinalizationCoverageCacheHitCount() == 1,
               "previous manager should scan once and cache once after transfer") &&
           Require(
               recovered.FinalizationCoverageWalScanCount() == 1 &&
                   recovered.FinalizationCoverageCacheHitCount() == 1,
               "restarted manager should scan once and cache once after transfer");
}

bool TestCompactionRetryRetainsCoverageTrust(const std::filesystem::path& run_root)
{
    const auto path = run_root / "compaction-retry-coverage.wal";
    apfsaccess::rw::TransactionManager tx(L"DeferredContent");
    tx.SetJournalMaxBytesForTest(900);
    tx.SetVolumeIdentity(L"compaction-retry-volume");
    tx.SetJournalPath(path.wstring());

    auto first_mutation = MakeMetadataMutation(L"\\cleaned-before-compaction.txt");
    if (!Require(tx.Begin(), "compaction fixture should begin its cleaned transaction") ||
        !Require(tx.RecordMutation(first_mutation), "compaction fixture should record its cleaned mutation") ||
        !Require(tx.Accept(), "compaction fixture should accept its cleaned transaction"))
    {
        return false;
    }
    const auto cleaned_sequence = tx.Watermarks().accepted_sequence;
    if (!Require(tx.MarkApfsDurableThrough(cleaned_sequence), "compaction fixture should mark APFS durability") ||
        !Require(tx.MarkCleanedThrough(cleaned_sequence), "compaction fixture should mark cleanup"))
    {
        return false;
    }

    auto second_mutation = MakeMetadataMutation(L"\\accepted-after-compaction.txt");
    if (!Require(tx.Begin(), "compaction retry transaction should begin") ||
        !Require(tx.RecordMutation(second_mutation), "compaction retry transaction should record metadata") ||
        !Require(tx.Accept(), "size rejection should compact and retry the accepted batch") ||
        !Require(
            tx.CanFinalizeWithoutPayloadSpoolFlush(),
            "successful compaction retry should retain trusted finalization coverage") ||
        !Require(
            tx.FinalizationCoverageCacheHitCount() == 1 &&
                tx.FinalizationCoverageWalScanCount() == 0,
            "compaction retry should not force a redundant validation scan"))
    {
        return false;
    }

    const auto snapshot = apfsaccess::rw::WriteAheadLog::ReadAll(
        path,
        "compaction-retry-volume");
    const auto has_compaction_index = std::any_of(
        snapshot.records.begin(),
        snapshot.records.end(),
        [](const auto& record)
        {
            return record.operation == apfsaccess::rw::WriteAheadLog::OperationKind::CompactionIndex;
        });
    return Require(
               snapshot.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok && has_compaction_index,
               "compaction retry fixture should prove that compaction actually occurred") &&
           Require(
               tx.RecoveryStateValid() && tx.Watermarks().accepted_sequence > cleaned_sequence,
               "compaction retry should retain valid advancing transaction state");
}

bool TestObserverReadsAndActiveLeaseLoss(const std::filesystem::path& run_root)
{
    const auto observer_path = run_root / "active-observer-read.wal";
    apfsaccess::rw::TransactionManager observed_tx(L"DeferredContent");
    observed_tx.SetVolumeIdentity(L"active-observer-volume");
    observed_tx.SetJournalPath(observer_path.wstring());
    auto observed_mutation = MakeMetadataMutation(L"\\observed.txt");
    if (!Require(observed_tx.Begin(), "observed transaction should begin") ||
        !Require(observed_tx.RecordMutation(observed_mutation), "observed transaction should buffer metadata"))
    {
        return false;
    }
    apfsaccess::rw::WriteAheadLog observer({
        observer_path,
        "active-observer-volume",
        0,
    });
    const auto observed_snapshot = observer.ReadAll();
    if (!Require(
            observed_snapshot.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                observed_snapshot.records.empty(),
            "observer should see the complete persisted prefix without revoking active ownership") ||
        !Require(observed_tx.Accept(), "observer read must not prevent the active owner from accepting"))
    {
        return false;
    }

    const auto stolen_path = run_root / "active-lease-loss.wal";
    apfsaccess::rw::TransactionManager stale_tx(L"DeferredContent");
    stale_tx.SetVolumeIdentity(L"active-lease-loss-volume");
    stale_tx.SetJournalPath(stolen_path.wstring());
    auto first_mutation = MakeMetadataMutation(L"\\prepared-before-theft.txt");
    auto second_mutation = MakeMetadataMutation(L"\\rejected-after-theft.txt");
    if (!Require(stale_tx.Begin(), "lease-loss transaction should begin") ||
        !Require(stale_tx.RecordMutation(first_mutation), "lease-loss fixture should record its first mutation") ||
        !Require(stale_tx.FlushPreparedRecords(), "lease-loss fixture should persist prepared evidence"))
    {
        return false;
    }
    apfsaccess::rw::WriteAheadLog successor({
        stolen_path,
        "active-lease-loss-volume",
        0,
    });
    if (!Require(successor.AcquireExclusiveWriterLease(), "successor should explicitly take the active writer lease") ||
        !Require(
            !stale_tx.RecordMutation(second_mutation),
            "active manager should reject new staging immediately after lease loss") ||
        !Require(!stale_tx.Abort(), "abort must report failure when its terminal marker cannot be persisted") ||
        !Require(
            stale_tx.CurrentState() == apfsaccess::rw::TransactionManager::State::Failed &&
                !stale_tx.RecoveryStateValid(),
            "lease loss should leave the stale transaction failed and recovery-blocked"))
    {
        return false;
    }
    const auto stolen_snapshot = successor.ReadAll();
    if (!Require(
            stolen_snapshot.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                stolen_snapshot.records.size() == 1 &&
                stolen_snapshot.records.front().state == apfsaccess::rw::WriteAheadLog::RecordState::Prepared,
            "failed abort should retain prepared evidence without a false terminal marker"))
    {
        return false;
    }
    apfsaccess::rw::TransactionManager recovered(L"DeferredContent");
    recovered.SetVolumeIdentity(L"active-lease-loss-volume");
    recovered.SetJournalPath(stolen_path.wstring());
    return Require(
        !recovered.RecoveryStateValid(),
        "restart should fail closed on unterminated prepared evidence after lease loss");
}

bool TestPoisonedManagerRejectsFurtherMutationAndReuse(const std::filesystem::path& run_root)
{
    const auto path = run_root / "poisoned-manager-reuse.wal";
    apfsaccess::rw::TransactionManager tx(L"DeferredContent");
    tx.SetVolumeIdentity(L"poisoned-manager-reuse-volume");
    tx.SetJournalPath(path.wstring());

    auto first = MakeMetadataMutation(L"\\first.txt");
    auto second = MakeMetadataMutation(L"\\second.txt");
    if (!Require(tx.Begin(), "poisoned-manager fixture should begin") ||
        !Require(tx.RecordMutation(first), "poisoned-manager fixture should record metadata"))
    {
        return false;
    }
    tx.SetJournalFaultInjectionHook([](std::string_view stage)
    {
        return stage == "read-all-exclusive";
    });
    const auto finalization_eligible = tx.CanFinalizeWithoutPayloadSpoolFlush(false);
    tx.SetJournalFaultInjectionHook({});
    if (!Require(
            !finalization_eligible,
            "strict validation should reject an unreadable WAL snapshot") ||
        !Require(
            !tx.RecoveryStateValid(),
            "strict validation failure should poison recovery state"))
    {
        return false;
    }

    const auto journal_before_abort = apfsaccess::rw::WriteAheadLog::ReadAll(
        path,
        "poisoned-manager-reuse-volume");
    const bool mutation_rejected = !tx.RecordMutation(second);
    const bool aborted = tx.Abort();
    const auto journal_after_abort = apfsaccess::rw::WriteAheadLog::ReadAll(
        path,
        "poisoned-manager-reuse-volume");
    return Require(mutation_rejected, "a poisoned active manager must reject later mutations") &&
           Require(!aborted, "a poisoned manager must not publish an abort boundary") &&
           Require(
               tx.CurrentState() == apfsaccess::rw::TransactionManager::State::Failed,
               "a rejected poisoned abort should leave the manager failed") &&
           Require(
               journal_before_abort.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                   journal_after_abort.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                   journal_after_abort.records.size() == journal_before_abort.records.size(),
               "a poisoned abort must leave WAL evidence unchanged") &&
           Require(
               !tx.Begin(),
               "an idle manager with poisoned recovery state must not begin another transaction");
}

bool TestPoisonedManagerRejectsDurabilityWatermarks(const std::filesystem::path& run_root)
{
    const auto run_case = [&](std::string_view stem, bool cleanup_watermark, bool no_op)
    {
        const auto path = run_root / (std::string(stem) + ".wal");
        const auto volume = std::string(stem) + "-volume";
        apfsaccess::rw::TransactionManager tx(L"DeferredContent");
        tx.SetVolumeIdentity(std::wstring(volume.begin(), volume.end()));
        tx.SetJournalPath(path.wstring());
        auto mutation = MakeMetadataMutation(L"\\watermark.txt");
        if (!Require(tx.Begin(), "poisoned-watermark fixture should begin") ||
            !Require(tx.RecordMutation(mutation), "poisoned-watermark fixture should record metadata") ||
            !Require(tx.Accept(), "poisoned-watermark fixture should accept metadata"))
        {
            return false;
        }

        const auto accepted = tx.Watermarks().accepted_sequence;
        if (cleanup_watermark &&
            !Require(
                tx.MarkApfsDurableThrough(accepted),
                "cleanup-watermark fixture should establish APFS durability before poisoning"))
        {
            return false;
        }

        tx.SetJournalFaultInjectionHook([](std::string_view stage)
        {
            return stage == "read-all-exclusive";
        });
        const auto finalization_eligible = tx.CanFinalizeWithoutPayloadSpoolFlush(false);
        tx.SetJournalFaultInjectionHook({});
        if (!Require(!finalization_eligible, "strict WAL read failure should reject finalization") ||
            !Require(!tx.RecoveryStateValid(), "strict WAL read failure should poison the manager"))
        {
            return false;
        }

        const auto before_watermarks = tx.Watermarks();
        const auto before_journal = apfsaccess::rw::WriteAheadLog::ReadAll(path, volume);
        const auto target = cleanup_watermark
            ? (no_op ? before_watermarks.cleanup_sequence : before_watermarks.apfs_durable_sequence)
            : (no_op ? before_watermarks.apfs_durable_sequence : before_watermarks.accepted_sequence);
        const bool marked = cleanup_watermark
            ? tx.MarkCleanedThrough(target)
            : tx.MarkApfsDurableThrough(target);
        const auto after_watermarks = tx.Watermarks();
        const auto after_journal = apfsaccess::rw::WriteAheadLog::ReadAll(path, volume);
        return Require(!marked, "poisoned manager must reject durability watermark calls") &&
               Require(!tx.RecoveryStateValid(), "watermark rejection must not heal poisoned recovery state") &&
               Require(
                   after_watermarks.accepted_sequence == before_watermarks.accepted_sequence &&
                       after_watermarks.apfs_durable_sequence == before_watermarks.apfs_durable_sequence &&
                       after_watermarks.cleanup_sequence == before_watermarks.cleanup_sequence,
                   "poisoned watermark rejection must preserve in-memory watermarks") &&
               Require(
                   before_journal.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                       after_journal.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                       after_journal.records.size() == before_journal.records.size(),
                   "poisoned watermark rejection must not append WAL records");
    };

    return run_case("poisoned-apfs-noop", false, true) &&
           run_case("poisoned-apfs-advance", false, false) &&
           run_case("poisoned-cleanup-noop", true, true) &&
           run_case("poisoned-cleanup-advance", true, false);
}

bool TestRecoveryClearingRequiresCurrentWriterGeneration(const std::filesystem::path& run_root)
{
    const auto path = run_root / "recovery-clear-writer-generation.wal";
    apfsaccess::rw::TransactionManager stale(L"DeferredContent");
    stale.SetVolumeIdentity(L"recovery-clear-writer-generation-volume");
    stale.SetJournalPath(path.wstring());
    auto first = MakeMetadataMutation(L"\\first.txt");
    if (!Require(stale.Begin(), "recovery-clear fixture should begin its first transaction") ||
        !Require(stale.RecordMutation(first), "recovery-clear fixture should record its first mutation") ||
        !Require(stale.Accept(), "recovery-clear fixture should accept its first transaction"))
    {
        return false;
    }
    const auto first_boundary = stale.Watermarks().accepted_sequence;
    if (!Require(stale.MarkApfsDurableThrough(first_boundary), "first boundary should become APFS durable") ||
        !Require(stale.MarkCleanedThrough(first_boundary), "first boundary should become clean") ||
        !Require(stale.CanClearRecoveryState(), "the current clean writer should permit recovery clearing"))
    {
        return false;
    }

    apfsaccess::rw::TransactionManager successor(L"DeferredContent");
    successor.SetVolumeIdentity(L"recovery-clear-writer-generation-volume");
    successor.SetJournalPath(path.wstring());
    auto second = MakeMetadataMutation(L"\\second.txt");
    if (!Require(successor.Begin(), "successor should acquire the transferred writer lease") ||
        !Require(successor.RecordMutation(second), "successor should record new accepted work") ||
        !Require(successor.Accept(), "successor should publish new accepted work"))
    {
        return false;
    }

    const auto stale_watermarks = stale.Watermarks();
    return Require(
               stale_watermarks.accepted_sequence == stale_watermarks.apfs_durable_sequence &&
                   stale_watermarks.apfs_durable_sequence == stale_watermarks.cleanup_sequence,
               "stale cached watermarks should reproduce the misleading clean state") &&
           Require(
               !stale.CanClearRecoveryState(),
               "a manager that lost its writer generation must not clear recovery state");
}

bool TestCommittedPreimageCensusDirect(const std::filesystem::path& run_root)
{
    using Tx = apfsaccess::rw::TransactionManager;
    using Wal = apfsaccess::rw::WriteAheadLog;
    const auto path = run_root / "committed-preimage-direct.wal";
    Tx tx(L"Conservative");
    tx.SetVolumeIdentity(L"committed-preimage-direct-volume");
    tx.SetJournalPath(path.wstring());
    auto mutation = MakeMetadataMutation(L"\\committed.txt");
    mutation.object_id = 900001;
    if (!Require(tx.Begin() && tx.RecordMutation(mutation) && tx.Commit(7007),
            "direct Commit should persist its explicit preimage checkpoint"))
    {
        return false;
    }
    const auto committed_sequence = tx.LastCommittedSequence();
    std::vector<std::uint64_t> xids{123};
    std::string error;
    const bool loaded = tx.LoadRequiredCheckpointXidsSinceCleanup(xids, &error);
    bool ok = Require(loaded && error.empty() && xids == std::vector<std::uint64_t>{7007},
        "direct Commit census should retain exact XID 7007 until cleanup: " + error);
    const auto read = Wal::ReadAll(path, "committed-preimage-direct-volume");
    ok &= Require(read.status == Wal::ReadStatus::Ok && read.records.size() == 2 &&
            read.records[0].object_id == 900001 &&
            read.records[1].operation == Wal::OperationKind::TransactionMarker &&
            read.records[1].state == Wal::RecordState::Checkpointed &&
            read.records[1].object_id == 7007,
        "committed terminal marker should store the preimage XID independently of its mutation inode");
    const auto watermarks = tx.Watermarks();
    ok &= Require(watermarks.accepted_sequence == committed_sequence &&
            watermarks.apfs_durable_sequence == committed_sequence && watermarks.cleanup_sequence == 0,
        "census should recognize committed work as APFS-durable but uncleaned");
    if (!Require(tx.MarkCleanedThrough(committed_sequence),
            "direct committed boundary should be eligible for durable cleanup"))
    {
        return false;
    }
    ok &= Require(tx.LoadRequiredCheckpointXidsSinceCleanup(xids, &error) &&
            xids.empty() && error.empty(),
        "durable cleanup should release a committed preimage checkpoint");
    return ok;
}

bool TestCommittedPreimageCensusAfterRestart(
    const std::filesystem::path& run_root,
    bool compact_before_restart)
{
    using Tx = apfsaccess::rw::TransactionManager;
    using Wal = apfsaccess::rw::WriteAheadLog;
    const std::string scenario = compact_before_restart ? "compacted-restart" : "restart";
    const std::string identity = "committed-preimage-" + scenario + "-volume";
    const std::wstring wide_identity(identity.begin(), identity.end());
    const auto path = run_root / ("committed-preimage-" + scenario + ".wal");
    std::uint64_t cleanup_sequence = 0;
    std::uint64_t committed_sequence = 0;
    {
        Tx tx(L"Conservative");
        tx.SetVolumeIdentity(wide_identity);
        tx.SetJournalPath(path.wstring());
        auto prefix = MakeMetadataMutation(L"\\cleaned-prefix.txt");
        if (!Require(tx.Begin() && tx.RecordMutation(prefix) && tx.Accept(111),
                scenario + ": accepted prefix should persist"))
        {
            return false;
        }
        cleanup_sequence = tx.Watermarks().accepted_sequence;
        if (!Require(tx.MarkApfsDurableThrough(cleanup_sequence) && tx.MarkCleanedThrough(cleanup_sequence),
                scenario + ": prefix should be durably cleaned"))
        {
            return false;
        }
        auto mutation = MakeMetadataMutation(L"\\retained-committed.txt");
        mutation.object_id = 900001;
        if (!Require(tx.Begin() && tx.RecordMutation(mutation) && tx.Commit(7007),
                scenario + ": unresolved committed transaction should persist"))
        {
            return false;
        }
        committed_sequence = tx.LastCommittedSequence();
    }
    if (compact_before_restart)
    {
        Wal wal({path, identity, 1024 * 1024});
        if (!Require(wal.Compact(cleanup_sequence),
                "committed marker must already exist when WAL compaction runs"))
        {
            return false;
        }
        const auto read = wal.ReadAll();
        if (!Require(read.status == Wal::ReadStatus::Ok &&
                std::any_of(read.records.begin(), read.records.end(), [&](const auto& record)
                {
                    return record.operation == Wal::OperationKind::CompactionIndex &&
                        record.sequence == cleanup_sequence;
                }) &&
                std::none_of(read.records.begin(), read.records.end(), [&](const auto& record)
                {
                    return record.sequence < cleanup_sequence;
                }),
                "compaction should remove the cleaned prefix while preserving its cleanup boundary"))
        {
            return false;
        }
    }
    Tx recovered(L"Conservative");
    recovered.SetVolumeIdentity(wide_identity);
    recovered.SetJournalPath(path.wstring());
    std::vector<std::uint64_t> xids{123};
    std::string error;
    const bool loaded = recovered.LoadRequiredCheckpointXidsSinceCleanup(xids, &error);
    bool ok = Require(loaded && error.empty() && xids == std::vector<std::uint64_t>{7007},
        scenario + ": Commit census should recover exact XID 7007 and exclude the cleaned prefix: " + error);
    std::vector<Tx::AcceptedTransaction> transactions;
    const bool replay_loaded = recovered.LoadAcceptedTransactionsSinceCleanup(transactions, &error);
    ok &= Require(replay_loaded && transactions.size() == 1 &&
            transactions[0].accepted_sequence == committed_sequence &&
            transactions[0].preimage_checkpoint_xid == 7007 &&
            transactions[0].mutations.size() == 1 && transactions[0].mutations[0].object_id == 900001,
        scenario + ": recovered committed boundary must retain the marker XID and complete mutation group");
    return ok;
}

bool TestLegacyCommittedPreimageCensus(const std::filesystem::path& run_root)
{
    using Tx = apfsaccess::rw::TransactionManager;
    const auto path = run_root / "committed-preimage-legacy.wal";
    {
        Tx tx(L"Conservative");
        tx.SetVolumeIdentity(L"committed-preimage-legacy-volume");
        tx.SetJournalPath(path.wstring());
        auto mutation = MakeMetadataMutation(L"\\legacy-committed.txt");
        mutation.object_id = 900001;
        if (!Require(tx.Begin() && tx.RecordMutation(mutation) && tx.Commit(),
                "legacy default Commit should remain supported"))
        {
            return false;
        }
    }
    Tx recovered(L"Conservative");
    recovered.SetVolumeIdentity(L"committed-preimage-legacy-volume");
    recovered.SetJournalPath(path.wstring());
    std::vector<Tx::AcceptedTransaction> transactions;
    std::string error;
    if (!Require(recovered.LoadAcceptedTransactionsSinceCleanup(transactions, &error) &&
            transactions.size() == 1 && transactions[0].preimage_checkpoint_xid == 0,
            "legacy committed zero marker should remain replayable after restart"))
    {
        return false;
    }
    std::vector<std::uint64_t> xids{123};
    bool ok = Require(!recovered.LoadRequiredCheckpointXidsSinceCleanup(xids, &error) &&
            xids.empty() && !error.empty() && recovered.RecoveryStateValid(),
        "only pin census should reject an unresolved legacy committed zero marker");
    if (!Require(recovered.MarkCleanedThrough(transactions[0].accepted_sequence),
            "legacy committed zero marker should still support durable cleanup"))
    {
        return false;
    }
    ok &= Require(recovered.LoadRequiredCheckpointXidsSinceCleanup(xids, &error) &&
            xids.empty() && error.empty(),
        "a cleaned legacy committed zero marker must not block pin census");
    return ok;
}

bool TestCleanPreimageCensusRetainsValidatedOwnership(const std::filesystem::path& run_root)
{
    using Tx = apfsaccess::rw::TransactionManager;
    using Wal = apfsaccess::rw::WriteAheadLog;
    const auto path = run_root / "clean-preimage-owned.wal";
    Tx tx(L"DeferredContent");
    tx.SetVolumeIdentity(L"clean-preimage-owned");
    tx.SetJournalPath(path.wstring());
    if (!Require(tx.Begin() && tx.RecordMutation(MakeMetadataMutation(L"\\clean.txt")) &&
        tx.Accept(700), "clean census fixture accepts a bound transaction")) return false;
    const auto accepted = tx.Watermarks().accepted_sequence;
    if (!Require(tx.MarkApfsDurableThrough(accepted) && tx.MarkCleanedThrough(accepted),
        "clean census fixture proves durable cleanup")) return false;
    unsigned scans = 0;
    tx.SetJournalFaultInjectionHook([&](std::string_view stage) {
        if (stage == "read-all-exclusive-revalidate") { ++scans; return true; }
        return false;
    });
    std::vector<std::uint64_t> pins{999};
    std::string error = "stale error";
    if (!Require(tx.LoadRequiredCheckpointXidsSinceCleanup(pins, &error) && pins.empty() &&
        error.empty() && scans == 0, "validated clean census avoids full historical WAL reads")) return false;
    tx.SetJournalFaultInjectionHook({});
    if (!Require(tx.Begin() && tx.RecordMutation(MakeMetadataMutation(L"\\pending.txt")) &&
        tx.Accept(701), "next accepted transaction keeps its real preimage")) return false;
    if (!Require(tx.LoadRequiredCheckpointXidsSinceCleanup(pins, &error) &&
        pins == std::vector<std::uint64_t>{701}, "unresolved transaction takes full validated census")) return false;
    const auto next = tx.Watermarks().accepted_sequence;
    if (!Require(tx.MarkApfsDurableThrough(next) && tx.MarkCleanedThrough(next) && tx.Begin(),
        "clean state may have only unaccepted buffered work")) return false;
    Wal successor({path, "clean-preimage-owned", 1024 * 1024});
    if (!Require(successor.AcquireExclusiveWriterLease(), "successor takes exact WAL ownership")) return false;
    pins = {999};
    return Require(!tx.LoadRequiredCheckpointXidsSinceCleanup(pins, &error) && pins.empty() &&
        !error.empty() && !tx.RecoveryStateValid(), "lost ownership cannot reuse clean census proof");
}

bool TestMixedCheckpointedBoundaryRejectsCleanShortcut(const std::filesystem::path& run_root)
{
    using Tx = apfsaccess::rw::TransactionManager;
    for (const bool empty_commit : {false, true})
    {
        const auto identity = empty_commit ? L"mixed-empty-census" : L"mixed-content-census";
        const auto path = run_root / (empty_commit ? "mixed-empty.wal" : "mixed-content.wal");
        Tx tx(L"DeferredContent");
        tx.SetVolumeIdentity(identity);
        tx.SetJournalPath(path.wstring());
        if (!Require(tx.Begin() && tx.RecordMutation(MakeMetadataMutation(L"\\accepted.txt")) &&
            tx.Accept(700), "mixed census accepts its earlier boundary")) return false;
        const auto earlier = tx.Watermarks().accepted_sequence;
        if (!Require(tx.Begin() && (empty_commit || tx.RecordMutation(MakeMetadataMutation(L"\\committed.txt"))) &&
            tx.Commit(701) && tx.LastCommittedSequence() > earlier,
            "mixed census persists a later direct Commit")) return false;
        if (!Require(tx.MarkApfsDurableThrough(earlier) && tx.MarkCleanedThrough(earlier),
            "mixed census reproduces the earlier watermark update")) return false;
        unsigned scans = 0;
        tx.SetJournalFaultInjectionHook([&](std::string_view stage) {
            if (stage == "read-all-exclusive-revalidate") ++scans;
            return false;
        });
        std::vector<std::uint64_t> pins{999};
        std::string error;
        if (!Require(!tx.LoadRequiredCheckpointXidsSinceCleanup(pins, &error) && pins.empty() &&
            !error.empty() && scans != 0 && !tx.RecoveryStateValid(),
            "later persisted Commit cannot be hidden by earlier cleaned watermarks")) return false;
    }
    return true;
}

bool TestDirectCommitSurvivesBudgetCompaction(const std::filesystem::path& run_root)
{
    using Tx = apfsaccess::rw::TransactionManager;
    using Wal = apfsaccess::rw::WriteAheadLog;
    const auto path = run_root / "direct-compaction-floor.wal";
    const std::string identity = "review-late-commit-compaction";
    Tx tx(L"Conservative");
    tx.SetJournalMaxBytesForTest(700);
    tx.SetVolumeIdentity(L"review-late-commit-compaction");
    tx.SetJournalPath(path.wstring());
    if (!Require(tx.Begin() && tx.RecordMutation(MakeMetadataMutation(L"\\retention.txt")) && tx.Commit(710),
        "bounded WAL persists its direct Commit")) return false;
    const auto committed = tx.LastCommittedSequence();
    if (!Require(committed != 0 && tx.Watermarks().cleanup_sequence == 0 && tx.Begin() &&
        tx.RecordMutation(MakeMetadataMutation(L"\\retention.txt")), "later acceptance starts without a masking census")) return false;
    const bool accepted = tx.Accept(711);
    const auto physical = Wal::ReadAll(path, identity);
    if (!Require(physical.status == Wal::ReadStatus::Ok &&
        std::any_of(physical.records.begin(), physical.records.end(), [](const auto& r) {
            return r.operation == Wal::OperationKind::CompactionIndex;
        }), "budget actually exercised persisted compaction")) return false;
    if (!Require(std::any_of(physical.records.begin(), physical.records.end(), [&](const auto& r) {
        return r.sequence == committed && r.operation == Wal::OperationKind::TransactionMarker &&
            r.state == Wal::RecordState::Checkpointed;
    }) && std::any_of(physical.records.begin(), physical.records.end(), [&](const auto& r) {
        return r.sequence < committed && r.state == Wal::RecordState::Prepared;
    }), "unclean direct Commit and its mutation survive budget compaction")) return false;
    if (!accepted) return true;
    std::vector<std::uint64_t> pins;
    std::string error;
    return Require(tx.LoadRequiredCheckpointXidsSinceCleanup(pins, &error) &&
        pins == std::vector<std::uint64_t>{710, 711}, "successful later acceptance preserves both preimages: " + error);
}

bool TestAcceptedPinCensusAvoidsHistoryReads(const std::filesystem::path& run_root)
{
    using Tx = apfsaccess::rw::TransactionManager;
    for (const bool deferred : {false, true})
    {
        const auto path = run_root / (deferred ? "pin-deferred.wal" : "pin-ordinary.wal");
        const auto identity = deferred ? L"pin-deferred" : L"pin-ordinary";
        {
            Tx tx(L"DeferredContent");
            tx.SetVolumeIdentity(identity);
            tx.SetJournalPath(path.wstring());
            if (!Require(tx.Begin() && tx.RecordMutation(MakeMetadataMutation(L"\\first.txt")) &&
                tx.FlushPreparedRecords() && tx.RecordMutation(MakeMetadataMutation(L"\\second.txt")) &&
                (deferred ? tx.AcceptForDeferredCommit(nullptr, 901) : tx.Accept(901)),
                "pin census accepts a transaction with previously flushed preparation")) return false;
            unsigned scans = 0;
            tx.SetJournalFaultInjectionHook([&](std::string_view stage) {
                if (stage == "read-all-exclusive") { ++scans; return true; }
                return false;
            });
            std::vector<std::uint64_t> pins{999};
            std::string error;
            for (unsigned i = 0; i < 3; ++i)
                if (!Require(tx.LoadRequiredCheckpointXidsSinceCleanup(pins, &error) &&
                    pins == std::vector<std::uint64_t>{901} && error.empty() && scans == 0,
                    "true acceptance retains the exact unresolved pin without historical reads: " + error)) return false;
            if (!Require(tx.Begin() && tx.RecordMutation(MakeMetadataMutation(L"\\unaccepted.txt")) &&
                tx.FlushPreparedRecords() && tx.LoadRequiredCheckpointXidsSinceCleanup(pins, &error) &&
                pins == std::vector<std::uint64_t>{901} && scans == 0 && tx.Abort(),
                "active prepared work cannot change accepted pins")) return false;
            std::vector<Tx::AcceptedTransaction> replay;
            if (!Require(!tx.LoadAcceptedTransactionsSinceCleanup(replay, &error) && scans != 0,
                "pin cache never bypasses complete replay collection")) return false;
        }
        Tx cold(L"DeferredContent");
        cold.SetVolumeIdentity(identity);
        cold.SetJournalPath(path.wstring());
        std::vector<std::uint64_t> pins;
        std::string error;
        if (!Require(cold.LoadRequiredCheckpointXidsSinceCleanup(pins, &error) &&
            pins == std::vector<std::uint64_t>{901}, "complete cold reseed returns identical pins")) return false;
        unsigned scans = 0;
        cold.SetJournalFaultInjectionHook([&](std::string_view stage) {
            if (stage == "read-all-exclusive") { ++scans; return true; }
            return false;
        });
        if (!Require(cold.LoadRequiredCheckpointXidsSinceCleanup(pins, &error) && scans == 0 &&
            pins == std::vector<std::uint64_t>{901}, "cold validated seed supports subsequent bounded census")) return false;
        cold.SetJournalFaultInjectionHook({});
        std::vector<Tx::AcceptedTransaction> limited;
        if (!Require(!cold.LoadAcceptedTransactionsSinceCleanup(limited, &error, {1, 1}) &&
            limited.empty() && error == "WAL read resource budget exceeded",
            "replay caller budgets remain enforced after a cached pin census")) return false;
    }
    return true;
}

bool MakePinSnapshotMutation(bool create, std::uint64_t checkpoint,
    std::vector<std::uint64_t> pins, apfsaccess::rw::TransactionManager::MutationIntent& mutation)
{
    using namespace apfsaccess::rw;
    NativeSnapshotIntent intent;
    intent.create = create;
    intent.scope.store_size_bytes = 64ull * 1024 * 1024;
    intent.scope.container_uuid_hex = "0123456789abcdef0123456789abcdef";
    intent.scope.volume_uuid_hex = "fedcba9876543210fedcba9876543210";
    intent.scope.volume_oid = 42;
    intent.scope.checkpoint_xid = checkpoint;
    intent.snapshot_xid = create ? checkpoint + 1 : 30;
    intent.time_ns = 123456789;
    intent.name = "pin-snapshot";
    auto& target = intent.expected_identity;
    target.scope = intent.scope;
    if (create) ++target.scope.checkpoint_xid;
    target.snapshot_xid = intent.snapshot_xid;
    target.name_utf8 = intent.name;
    target.superblock_physical_block = 10;
    target.omap_physical_block = 11;
    target.omap_tree_physical_block = 12;
    target.root_oid = 13;
    target.root_physical_block = 14;
    target.extentref_physical_block = 15;
    if (!create) intent.inventory.push_back(target);
    intent.pins = std::move(pins);
    mutation = {};
    mutation.kind = create ? TransactionManager::MutationKind::CreateSnapshot : TransactionManager::MutationKind::DeleteSnapshot;
    mutation.path = L"\\";
    mutation.object_id = intent.scope.volume_oid;
    mutation.generation = checkpoint + 1;
    mutation.inline_payload = EncodeNativeSnapshotIntent(intent);
    mutation.payload_length = mutation.inline_payload.size();
    mutation.length = mutation.inline_payload.size();
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) return false;
    const auto status = BCryptHash(algorithm, nullptr, 0,
        reinterpret_cast<PUCHAR>(mutation.inline_payload.data()), static_cast<ULONG>(mutation.inline_payload.size()),
        mutation.payload_checksum.data(), static_cast<ULONG>(mutation.payload_checksum.size()));
    const auto closed = BCryptCloseAlgorithmProvider(algorithm, 0);
    NativeSnapshotIntent decoded;
    return status >= 0 && closed >= 0 && DecodeNativeSnapshotIntent(mutation.inline_payload, decoded);
}

bool TestAcceptedSnapshotPinsRetireAtExactCleanup(const std::filesystem::path& run_root)
{
    using Tx = apfsaccess::rw::TransactionManager;
    const auto path = run_root / "pin-snapshot-boundaries.wal";
    Tx::MutationIntent create, remove;
    if (!Require(MakePinSnapshotMutation(true, 1000, {20, 50, 1000}, create) &&
        MakePinSnapshotMutation(false, 1100, {30, 1100}, remove), "valid snapshot pin payloads")) return false;
    std::uint64_t first = 0, second = 0;
    {
        Tx tx(L"DeferredContent");
        tx.SetVolumeIdentity(L"pin-snapshot-boundaries");
        tx.SetJournalPath(path.wstring());
        if (!Require(tx.Begin() && tx.RecordMutation(MakeMetadataMutation(L"\\earlier.txt")) && tx.Accept(900),
            "earlier acceptance precedes snapshot pin boundaries")) return false;
        first = tx.Watermarks().accepted_sequence;
        if (!Require(tx.Begin() && tx.RecordMutation(create) && tx.Accept(1000), "create snapshot acceptance")) return false;
        second = tx.Watermarks().accepted_sequence;
        if (!Require(tx.Begin() && tx.RecordMutation(remove) && tx.AcceptForDeferredCommit(nullptr, 1100),
            "delete snapshot deferred acceptance")) return false;
        unsigned scans = 0;
        tx.SetJournalFaultInjectionHook([&](std::string_view stage) {
            if (stage == "read-all-exclusive") { ++scans; return true; }
            return false;
        });
        std::vector<std::uint64_t> actual;
        std::string error;
        const auto expect = [&](std::vector<std::uint64_t> wanted) {
            return Require(tx.LoadRequiredCheckpointXidsSinceCleanup(actual, &error) && actual == wanted && scans == 0,
                "snapshot pins match exact unresolved accepted boundaries: " + error);
        };
        if (!expect({20, 30, 50, 900, 1000, 1100}) || !tx.MarkApfsDurableThrough(first) ||
            !expect({20, 30, 50, 900, 1000, 1100}) || !tx.MarkCleanedThrough(first) ||
            !expect({20, 30, 50, 1000, 1100})) return false;
    }
    Tx cold(L"DeferredContent");
    cold.SetVolumeIdentity(L"pin-snapshot-boundaries");
    cold.SetJournalPath(path.wstring());
    std::vector<std::uint64_t> pins;
    std::string error;
    if (!Require(cold.LoadRequiredCheckpointXidsSinceCleanup(pins, &error) &&
        pins == std::vector<std::uint64_t>{20, 30, 50, 1000, 1100}, "cold snapshot census matches partial cleanup")) return false;
    cold.SetJournalFaultInjectionHook([](std::string_view stage) { return stage == "read-all-exclusive"; });
    if (!Require(cold.MarkApfsDurableThrough(second) && cold.MarkCleanedThrough(second) &&
        cold.LoadRequiredCheckpointXidsSinceCleanup(pins, &error) && pins == std::vector<std::uint64_t>{30, 1100},
        "earlier snapshot cleanup retains every later delete snapshot pin")) return false;
    const auto latest = cold.Watermarks().accepted_sequence;
    return Require(cold.MarkApfsDurableThrough(latest) && cold.MarkCleanedThrough(latest) &&
        cold.LoadRequiredCheckpointXidsSinceCleanup(pins, &error) && pins.empty(), "only durable cleanup retires final pins");
}

bool TestUntrustedAcceptedPinCensusFallsBack(const std::filesystem::path& run_root)
{
    using Tx = apfsaccess::rw::TransactionManager;
    using Wal = apfsaccess::rw::WriteAheadLog;
    const auto path = run_root / "pin-untrusted.wal";
    {
        Tx tx(L"DeferredContent");
        tx.SetVolumeIdentity(L"pin-untrusted");
        tx.SetJournalPath(path.wstring());
        if (!Require(tx.Begin() && tx.RecordMutation(MakeMetadataMutation(L"\\zero.txt")) && tx.Accept(),
            "legacy zero XID remains a successful acceptance")) return false;
        unsigned scans = 0;
        tx.SetJournalFaultInjectionHook([&](std::string_view stage) {
            if (stage == "read-all-exclusive") ++scans;
            return false;
        });
        std::vector<std::uint64_t> pins{999};
        std::string error;
        if (!Require(!tx.LoadRequiredCheckpointXidsSinceCleanup(pins, &error) && pins.empty() && scans != 0 &&
            tx.RecoveryStateValid(), "zero XID falls back and refuses an incomplete pin set")) return false;
        const auto accepted = tx.Watermarks().accepted_sequence;
        if (!Require(tx.MarkApfsDurableThrough(accepted) && tx.MarkCleanedThrough(accepted), "zero XID cleanup")) return false;
    }
    {
        Wal wal({path, "pin-untrusted", 1024 * 1024});
        if (!Require(wal.Compact(1), "completed receipt fixture")) return false;
    }
    Tx tx(L"DeferredContent");
    tx.SetVolumeIdentity(L"pin-untrusted");
    tx.SetJournalPath(path.wstring());
    if (!Require(tx.Begin() && tx.RecordMutation(MakeMetadataMutation(L"\\owned.txt")) && tx.Accept(910),
        "accepted cache over a completed compaction receipt")) return false;
    unsigned scans = 0;
    tx.SetJournalFaultInjectionHook([&](std::string_view stage) {
        if (stage == "read-all-exclusive") { ++scans; return true; }
        return false;
    });
    std::vector<std::uint64_t> pins;
    std::string error;
    if (!Require(tx.LoadRequiredCheckpointXidsSinceCleanup(pins, &error) && pins == std::vector<std::uint64_t>{910} &&
        scans == 0, "valid receipt permits unresolved accepted census")) return false;
    auto receipt = path;
    receipt += L".compact.intent";
    { std::ofstream torn(receipt, std::ios::binary | std::ios::app); torn.put('!'); }
    return Require(!tx.LoadRequiredCheckpointXidsSinceCleanup(pins, &error) && pins.empty() && scans != 0,
        "malformed owned receipt cannot reuse accepted pin cache");
}

bool TestAcceptedPinCensusOwnershipAndAmbiguousAppend(const std::filesystem::path& run_root)
{
    using Tx = apfsaccess::rw::TransactionManager;
    for (const bool active : {false, true})
    {
        const auto path = run_root / (active ? "pin-active-transfer.wal" : "pin-idle-transfer.wal");
        Tx owner(L"DeferredContent");
        owner.SetVolumeIdentity(L"pin-transfer");
        owner.SetJournalPath(path.wstring());
        if (!Require(owner.Begin() && owner.RecordMutation(MakeMetadataMutation(L"\\old.txt")) && owner.Accept(920),
            "old owner accepts its pin")) return false;
        if (active && !owner.Begin()) return false;
        Tx successor(L"DeferredContent");
        successor.SetVolumeIdentity(L"pin-transfer");
        successor.SetJournalPath(path.wstring());
        if (!Require(successor.Begin() && successor.RecordMutation(MakeMetadataMutation(L"\\new.txt")) && successor.Accept(921),
            "successor accepts after actual handle transfer")) return false;
        unsigned scans = 0;
        owner.SetJournalFaultInjectionHook([&](std::string_view stage) {
            if (stage == "read-all-exclusive") ++scans;
            return false;
        });
        std::vector<std::uint64_t> pins{999};
        std::string error;
        const auto loaded = owner.LoadRequiredCheckpointXidsSinceCleanup(pins, &error);
        if (!Require(active ? (!loaded && pins.empty() && !owner.RecoveryStateValid()) :
            (loaded && pins == std::vector<std::uint64_t>{920, 921} && scans != 0),
            "transferred ownership requires complete reseed or active refusal")) return false;
    }
    Tx tx(L"DeferredContent");
    tx.SetVolumeIdentity(L"pin-ambiguous");
    tx.SetJournalPath((run_root / "pin-ambiguous.wal").wstring());
    if (!Require(tx.Begin() && tx.RecordMutation(MakeMetadataMutation(L"\\known.txt")) && tx.Accept(930) &&
        tx.Begin() && tx.RecordMutation(MakeMetadataMutation(L"\\ambiguous.txt")), "ambiguous acceptance fixture")) return false;
    tx.SetJournalFaultInjectionHook([](std::string_view stage) { return stage == "durable-flush"; });
    if (!Require(!tx.Accept(931) && !tx.RecoveryStateValid(), "persisted bytes with failed flush poison acceptance")) return false;
    tx.SetJournalFaultInjectionHook({});
    std::vector<std::uint64_t> pins{999};
    std::string error;
    return Require(!tx.LoadRequiredCheckpointXidsSinceCleanup(pins, &error) && pins.empty() && !error.empty(),
        "ambiguous append cannot return its older cached pin set");
}

bool TestBoundedAcceptedPinCensus(const std::filesystem::path& run_root)
{
    using Tx = apfsaccess::rw::TransactionManager;
    using Wal = apfsaccess::rw::WriteAheadLog;
    for (const bool snapshot_limit : {false, true})
    {
        const auto path = run_root / (snapshot_limit ? "pin-entry-cap.wal" : "pin-boundary-cap.wal");
        const auto count = snapshot_limit ? Tx::MaxCachedCheckpointPinEntries() / 64 + 1 :
            Tx::MaxCachedCheckpointPinBoundaries() + 1;
        std::vector<Wal::Record> records;
        std::vector<std::uint64_t> expected;
        for (std::size_t i = 0; i < count; ++i)
        {
            const std::uint64_t xid = 10000 + i;
            Wal::Record prepared;
            prepared.volume_identity = "pin-cap";
            prepared.transaction_id = i + 1;
            prepared.sequence = 2 * i + 1;
            prepared.state = Wal::RecordState::Prepared;
            prepared.operation = Wal::OperationKind::SetBasicInfo;
            prepared.path_utf8 = "\\cap.txt";
            if (snapshot_limit)
            {
                std::vector<std::uint64_t> snapshot_pins;
                for (std::uint64_t pin = 1; pin <= 63; ++pin) snapshot_pins.push_back(pin);
                snapshot_pins.push_back(xid);
                Tx::MutationIntent mutation;
                if (!MakePinSnapshotMutation(true, xid, snapshot_pins, mutation)) return false;
                prepared.operation = Wal::OperationKind::CreateSnapshot;
                prepared.object_id = mutation.object_id;
                prepared.parent_object_id = mutation.generation;
                prepared.path_utf8 = "\\";
                prepared.payload_length = mutation.payload_length;
                prepared.payload_sha256 = mutation.payload_checksum;
                prepared.inline_payload = std::move(mutation.inline_payload);
            }
            records.push_back(std::move(prepared));
            Wal::Record marker;
            marker.volume_identity = "pin-cap";
            marker.transaction_id = i + 1;
            marker.sequence = 2 * i + 2;
            marker.operation = Wal::OperationKind::TransactionMarker;
            marker.state = Wal::RecordState::Accepted;
            marker.flags = 8;
            marker.object_id = xid;
            marker.logical_length = 1;
            records.push_back(std::move(marker));
            expected.push_back(xid);
        }
        if (snapshot_limit) for (std::uint64_t pin = 1; pin <= 63; ++pin) expected.push_back(pin);
        std::sort(expected.begin(), expected.end());
        { Wal wal({path, "pin-cap", 8 * 1024 * 1024}); if (!wal.AppendBatch(records)) return false; }
        Tx tx(L"DeferredContent");
        tx.SetVolumeIdentity(L"pin-cap");
        tx.SetJournalPath(path.wstring());
        std::vector<std::uint64_t> pins;
        std::string error;
        if (!Require(tx.LoadRequiredCheckpointXidsSinceCleanup(pins, &error) && pins == expected,
            "complete fallback preserves every pin beyond the cache cap")) return false;
        unsigned scans = 0;
        tx.SetJournalFaultInjectionHook([&](std::string_view stage) {
            if (stage == "read-all-exclusive") { ++scans; return true; }
            return false;
        });
        if (!Require(!tx.LoadRequiredCheckpointXidsSinceCleanup(pins, &error) && pins.empty() && scans != 0,
            "cache cap never permits a truncated pin result")) return false;
    }
    return true;
}

bool TestIncompleteCompactedPinHistoryFallsBack(const std::filesystem::path& run_root)
{
    using Tx = apfsaccess::rw::TransactionManager;
    using Wal = apfsaccess::rw::WriteAheadLog;
    const auto path = run_root / "pin-incomplete-compacted.wal";
    {
        Tx tx(L"DeferredContent");
        tx.SetVolumeIdentity(L"pin-incomplete");
        tx.SetJournalPath(path.wstring());
        Tx::MutationIntent snapshot;
        if (!MakePinSnapshotMutation(true, 1000, {20, 1000}, snapshot) || !tx.Begin()) return false;
        auto malformed = snapshot;
        malformed.inline_payload.front() = std::byte{0};
        if (!Require(!tx.RecordMutation(malformed) && tx.RecordMutation(snapshot) && tx.Accept(1000),
            "invalid snapshot payload refuses before a successful valid acceptance")) return false;
    }
    {
        Wal wal({path, "pin-incomplete", 1024 * 1024});
        if (!Require(wal.Compact(2), "fixture removes unresolved preparation at its marker floor")) return false;
    }
    Tx cold(L"DeferredContent");
    cold.SetVolumeIdentity(L"pin-incomplete");
    cold.SetJournalPath(path.wstring());
    std::vector<std::uint64_t> pins{999};
    std::string error;
    unsigned scans = 0;
    cold.SetJournalFaultInjectionHook([&](std::string_view stage) {
        if (stage == "read-all-exclusive") ++scans;
        return false;
    });
    return Require(!cold.LoadRequiredCheckpointXidsSinceCleanup(pins, &error) && pins.empty() && scans != 0,
        "a valid compacted envelope without unresolved snapshot preparation cannot seed pins");
}

bool TestAcceptedPinsSurvivePreparationCompaction(const std::filesystem::path& run_root)
{
    using Tx = apfsaccess::rw::TransactionManager;
    using Wal = apfsaccess::rw::WriteAheadLog;
    for (const bool deferred : {false, true})
    {
        const std::string identity = "review-accepted-partial-deferred";
        const auto path = run_root / (deferred ? "pin-prepared-deferred.wal" : "pin-prepared-ordinary.wal");
        Wal::Record prototype;
        prototype.volume_identity = identity;
        prototype.operation = Wal::OperationKind::SetBasicInfo;
        prototype.state = Wal::RecordState::Prepared;
        prototype.path_utf8 = "\\retention.txt";
        const auto prepared_size = Wal::EncodeForTest(prototype).size();
        prototype.operation = Wal::OperationKind::TransactionMarker;
        prototype.state = Wal::RecordState::Accepted;
        prototype.path_utf8 = "DeferredContent";
        const auto marker_size = Wal::EncodeForTest(prototype).size();
        prototype.operation = Wal::OperationKind::DurabilityWatermark;
        prototype.path_utf8.clear();
        const auto watermark_size = Wal::EncodeForTest(prototype).size();
        Tx tx(L"DeferredContent");
        tx.SetJournalMaxBytesForTest(7 * prepared_size + 2 * marker_size + 2 * watermark_size + prepared_size / 2);
        tx.SetVolumeIdentity(L"review-accepted-partial-deferred");
        tx.SetJournalPath(path.wstring());
        const auto mutation = MakeMetadataMutation(L"\\retention.txt");
        if (!Require(tx.Begin() && tx.RecordMutation(mutation) && tx.RecordMutation(mutation) &&
            tx.RecordMutation(mutation) && tx.RecordMutation(mutation) && tx.RecordMutation(mutation) &&
            tx.Accept(940), "cleaned prefix fills bounded preparation fixture")) return false;
        const auto cleaned = tx.Watermarks().accepted_sequence;
        if (!Require(tx.MarkApfsDurableThrough(cleaned) && tx.MarkCleanedThrough(cleaned) && tx.Begin() &&
            tx.RecordMutation(mutation) && (deferred ? tx.AcceptForDeferredCommit(nullptr, 941) : tx.Accept(941)),
            "bounded fixture retains later unresolved acceptance")) return false;
        const auto earlier = tx.Watermarks().accepted_sequence;
        if (!Require(tx.Begin() && tx.RecordMutation(mutation) && tx.FlushPreparedRecords() &&
            tx.RecordMutation(mutation) && tx.FlushPreparedRecords() && tx.Accept(942),
            "actual compaction permits a split prepared transaction to complete")) return false;
        const auto physical = Wal::ReadAll(path, identity);
        if (!Require(physical.status == Wal::ReadStatus::Ok &&
            std::any_of(physical.records.begin(), physical.records.end(), [](const auto& r) {
                return r.operation == Wal::OperationKind::CompactionIndex;
            }) && std::count_if(physical.records.begin(), physical.records.end(), [](const auto& r) {
                return r.state == Wal::RecordState::Prepared;
            }) == 3, "persisted compaction retains unresolved preparation and both split records")) return false;
        unsigned scans = 0;
        tx.SetJournalFaultInjectionHook([&](std::string_view stage) {
            if (stage == "read-all-exclusive") { ++scans; return true; }
            return false;
        });
        std::vector<std::uint64_t> pins;
        std::string error;
        if (!Require(tx.LoadRequiredCheckpointXidsSinceCleanup(pins, &error) &&
            pins == std::vector<std::uint64_t>{941, 942} && scans == 0,
            "known compaction transfers exact pin cache to its replacement generation")) return false;
        if (!Require(tx.MarkApfsDurableThrough(earlier) && tx.MarkCleanedThrough(earlier) &&
            tx.LoadRequiredCheckpointXidsSinceCleanup(pins, &error) &&
            pins == std::vector<std::uint64_t>{942} && scans == 0,
            "partial cleanup after compaction preserves the later accepted group")) return false;
    }
    return true;
}

bool TestIncrementalPinCensusCapAndReseed(const std::filesystem::path& run_root)
{
    using Tx = apfsaccess::rw::TransactionManager;
    const auto path = run_root / "pin-incremental-cap.wal";
    std::vector<std::uint64_t> expected;
    {
        Tx tx(L"DeferredContent");
        tx.SetVolumeIdentity(L"pin-incremental-cap");
        tx.SetJournalPath(path.wstring());
        for (std::size_t i = 0; i < Tx::MaxCachedCheckpointPinBoundaries(); ++i)
        {
            if (!tx.Begin() || !tx.RecordMutation(MakeMetadataMutation(L"\\cap.txt")) ||
                !tx.AcceptForDeferredCommit(nullptr, 10000 + i)) return false;
            expected.push_back(10000 + i);
        }
        unsigned scans = 0;
        tx.SetJournalFaultInjectionHook([&](std::string_view stage) {
            if (stage == "read-all-exclusive") { ++scans; return true; }
            return false;
        });
        std::vector<std::uint64_t> pins;
        std::string error;
        if (!Require(tx.LoadRequiredCheckpointXidsSinceCleanup(pins, &error) && pins == expected && scans == 0,
            "incremental census retains exactly the bounded maximum")) return false;
        const auto extra = 10000 + Tx::MaxCachedCheckpointPinBoundaries();
        if (!Require(tx.Begin() && tx.RecordMutation(MakeMetadataMutation(L"\\extra.txt")) &&
            tx.AcceptForDeferredCommit(nullptr, extra), "cache overflow cannot reject valid WAL acceptance")) return false;
        expected.push_back(extra);
        if (!Require(!tx.LoadRequiredCheckpointXidsSinceCleanup(pins, &error) && pins.empty() && scans != 0,
            "overflow invalidates the whole incremental cache and requires history")) return false;
    }
    Tx cold(L"DeferredContent");
    cold.SetVolumeIdentity(L"pin-incremental-cap");
    cold.SetJournalPath(path.wstring());
    std::vector<std::uint64_t> pins;
    std::string error;
    if (!Require(cold.LoadRequiredCheckpointXidsSinceCleanup(pins, &error) && pins == expected,
        "cold scan preserves the overflow boundary")) return false;
    const auto accepted = cold.Watermarks().accepted_sequence;
    if (!Require(cold.MarkApfsDurableThrough(accepted) && cold.MarkCleanedThrough(accepted) && cold.Begin() &&
        cold.RecordMutation(MakeMetadataMutation(L"\\after-cleanup.txt")) && cold.Accept(20000) &&
        cold.LoadRequiredCheckpointXidsSinceCleanup(pins, &error) && pins == std::vector<std::uint64_t>{20000},
        "full validated reseed after cleanup restores a small exact pin cache")) return false;
    cold.SetJournalFaultInjectionHook([](std::string_view stage) { return stage == "read-all-exclusive"; });
    return Require(cold.LoadRequiredCheckpointXidsSinceCleanup(pins, &error) &&
        pins == std::vector<std::uint64_t>{20000}, "reseeded cache resumes avoiding history reads");
}

bool TestCompletedCompactionRetainsCleanCensusProof(const std::filesystem::path& run_root)
{
    using Tx = apfsaccess::rw::TransactionManager;
    using Wal = apfsaccess::rw::WriteAheadLog;
    const auto path = run_root / "compacted-clean-census.wal";
    {
        Tx tx(L"DeferredContent");
        tx.SetVolumeIdentity(L"compacted-clean-census");
        tx.SetJournalPath(path.wstring());
        if (!Require(tx.Begin() && tx.RecordMutation(MakeMetadataMutation(L"\\clean.txt")) && tx.Accept(800),
            "compaction census accepts its checkpoint")) return false;
        const auto accepted = tx.Watermarks().accepted_sequence;
        if (!Require(tx.MarkApfsDurableThrough(accepted) && tx.MarkCleanedThrough(accepted),
            "compaction census cleans its checkpoint")) return false;
    }
    {
        Wal wal({path, "compacted-clean-census", 1024 * 1024});
        if (!Require(wal.Compact(1), "clean census compaction preserves validated history")) return false;
    }
    auto intent = path;
    intent += L".compact.intent";
    if (!Require(std::filesystem::exists(intent), "completed compaction retains its durable receipt")) return false;
    Tx recovered(L"DeferredContent");
    recovered.SetVolumeIdentity(L"compacted-clean-census");
    recovered.SetJournalPath(path.wstring());
    unsigned scans = 0;
    recovered.SetJournalFaultInjectionHook([&](std::string_view stage) {
        if (stage == "read-all-exclusive-revalidate") { ++scans; return true; }
        return false;
    });
    std::vector<std::uint64_t> pins{999};
    std::string error;
    for (unsigned i = 0; i < 3; ++i)
        if (!Require(recovered.LoadRequiredCheckpointXidsSinceCleanup(pins, &error) &&
            pins.empty() && error.empty() && scans == 0,
            "complete identity-bound receipt permits clean census reuse")) return false;
    {
        std::ofstream tamper(intent, std::ios::binary | std::ios::app);
        tamper.put('!');
        if (!Require(static_cast<bool>(tamper), "receipt tamper probe appended a torn byte")) return false;
    }
    return Require(!recovered.LoadRequiredCheckpointXidsSinceCleanup(pins, &error) && pins.empty() &&
        !error.empty() && scans != 0, "changed receipt refuses cached proof and requires complete validation");
}

bool TestEmptyCommittedPreimageCensus(const std::filesystem::path& run_root)
{
    using Tx = apfsaccess::rw::TransactionManager;
    using Wal = apfsaccess::rw::WriteAheadLog;
    bool ok = true;
    for (const bool compact : {false, true})
    for (const bool legacy : {false, true})
    {
        const std::string identity = std::string("empty-commit-") +
            (compact ? "compact-" : "plain-") + (legacy ? "legacy" : "identified");
        const std::wstring wide_identity(identity.begin(), identity.end());
        const auto path = run_root / (identity + ".wal");
        std::uint64_t cleanup_sequence = 0;
        std::uint64_t committed_sequence = 0;
        const auto check = [&](Tx& manager) {
            std::vector<Tx::AcceptedTransaction> transactions;
            std::string error;
            bool valid = Require(manager.LoadAcceptedTransactionsSinceCleanup(transactions, &error) &&
                    transactions.size() == 1 && transactions.front().mutations.empty() &&
                    transactions.front().preimage_checkpoint_xid == (legacy ? 0 : 7007),
                identity + ": empty committed boundary is complete: " + error);
            std::vector<std::uint64_t> xids{999};
            const bool loaded = manager.LoadRequiredCheckpointXidsSinceCleanup(xids, &error);
            valid &= Require(legacy ? (!loaded && xids.empty() &&
                    error == "Accepted WAL transaction has no preimage checkpoint XID") :
                (loaded && xids == std::vector<std::uint64_t>{7007}),
                identity + ": empty committed census preserves exact preimage semantics: " + error);
            return valid;
        };
        {
            Tx tx(L"Conservative");
            tx.SetVolumeIdentity(wide_identity);
            tx.SetJournalPath(path.wstring());
            if (!Require(tx.Begin() && tx.RecordMutation(MakeMetadataMutation(L"\\prefix.txt")) &&
                    tx.Accept(111), identity + ": cleanup prefix accepts")) return false;
            cleanup_sequence = tx.Watermarks().accepted_sequence;
            if (!Require(tx.MarkApfsDurableThrough(cleanup_sequence) &&
                    tx.MarkCleanedThrough(cleanup_sequence) && tx.Begin() &&
                    tx.Commit(legacy ? 0 : 7007), identity + ": empty Commit succeeds")) return false;
            committed_sequence = tx.LastCommittedSequence();
            ok &= check(tx);
        }
        if (compact)
        {
            Wal wal({path, identity, 1024 * 1024});
            if (!Require(wal.Compact(cleanup_sequence), identity + ": compaction succeeds")) return false;
        }
        Tx recovered(L"Conservative");
        recovered.SetVolumeIdentity(wide_identity);
        recovered.SetJournalPath(path.wstring());
        ok &= check(recovered);
        std::vector<std::uint64_t> xids{999};
        std::string error;
        ok &= Require(recovered.MarkCleanedThrough(committed_sequence) &&
                recovered.LoadRequiredCheckpointXidsSinceCleanup(xids, &error) && xids.empty(),
            identity + ": durable cleanup releases empty committed boundary");
    }
    return ok;
}

bool TestWalPreimageCheckpointContract(const std::filesystem::path& run_root)
{
    using Tx = apfsaccess::rw::TransactionManager;
    using Wal = apfsaccess::rw::WriteAheadLog;

    const auto lifecycle_path = run_root / "preimage-checkpoint-lifecycle.wal";
    Tx lifecycle(L"DeferredContent");
    lifecycle.SetVolumeIdentity(L"preimage-checkpoint-lifecycle-volume");
    lifecycle.SetJournalPath(lifecycle_path.wstring());

    auto first_mutation = MakeMetadataMutation(L"\\first-preimage.txt");
    first_mutation.object_id = 900001;
    auto first_extra_mutation = MakeMetadataMutation(L"\\first-preimage-extra.txt");
    first_extra_mutation.object_id = 900002;
    if (!Require(
            lifecycle.Begin() &&
                lifecycle.RecordMutation(first_mutation) &&
                lifecycle.RecordMutation(first_extra_mutation) &&
                lifecycle.Accept(900),
            "accepted transaction should persist its explicit preimage checkpoint XID"))
    {
        return false;
    }
    const auto first_accepted_sequence = lifecycle.Watermarks().accepted_sequence;

    auto second_mutation = MakeMetadataMutation(L"\\second-preimage.txt");
    second_mutation.object_id = 700001;
    std::uint64_t second_accepted_sequence = 0;
    if (!Require(
            lifecycle.Begin() &&
                lifecycle.RecordMutation(second_mutation) &&
                lifecycle.AcceptForDeferredCommit(&second_accepted_sequence, 700),
            "deferred acceptance should preserve the legacy sequence output and explicit preimage XID"))
    {
        return false;
    }
    auto duplicate_preimage_mutation = MakeMetadataMutation(L"\\duplicate-preimage.txt");
    if (!Require(
            lifecycle.Begin() &&
                lifecycle.RecordMutation(duplicate_preimage_mutation) &&
                lifecycle.Accept(700),
            "a later accepted transaction may require the same preimage checkpoint XID"))
    {
        return false;
    }
    const auto final_accepted_sequence = lifecycle.Watermarks().accepted_sequence;

    const auto lifecycle_read = Wal::ReadAll(
        lifecycle_path,
        "preimage-checkpoint-lifecycle-volume");
    std::vector<std::uint64_t> marker_preimage_xids;
    for (const auto& record : lifecycle_read.records)
    {
        if (record.operation == Wal::OperationKind::TransactionMarker &&
            record.state == Wal::RecordState::Accepted)
        {
            marker_preimage_xids.push_back(record.object_id);
        }
    }
    if (!Require(
            lifecycle_read.status == Wal::ReadStatus::Ok &&
                marker_preimage_xids == std::vector<std::uint64_t>({900, 700, 700}),
            "accepted terminal markers should own immutable preimage identities independent of mutation object IDs"))
    {
        return false;
    }

    std::vector<Tx::AcceptedTransaction> accepted;
    std::string failure_reason;
    if (!Require(
            lifecycle.LoadAcceptedTransactionsSinceCleanup(accepted, &failure_reason) &&
                accepted.size() == 3 &&
                accepted[0].preimage_checkpoint_xid == 900 &&
                accepted[1].preimage_checkpoint_xid == 700 &&
                accepted[2].preimage_checkpoint_xid == 700,
            "accepted transaction reconstruction should expose each terminal marker preimage XID: " +
                failure_reason))
    {
        return false;
    }

    std::vector<std::uint64_t> required_checkpoint_xids;
    if (!Require(
            lifecycle.LoadRequiredCheckpointXidsSinceCleanup(
                required_checkpoint_xids,
                &failure_reason) &&
                required_checkpoint_xids == std::vector<std::uint64_t>({700, 900}),
            "required preimage census should be sorted and unique across accepted-sequence gaps: " +
                failure_reason) ||
        !Require(
            !lifecycle.MarkCleanedThrough(first_accepted_sequence),
            "cleanup must fail before its accepted boundary is APFS-durable") ||
        !Require(
            lifecycle.LoadRequiredCheckpointXidsSinceCleanup(
                required_checkpoint_xids,
                &failure_reason) &&
                required_checkpoint_xids == std::vector<std::uint64_t>({700, 900}),
            "failed cleanup must retain all unresolved preimage checkpoint XIDs: " + failure_reason) ||
        !Require(
            lifecycle.MarkApfsDurableThrough(first_accepted_sequence) &&
                lifecycle.MarkCleanedThrough(first_accepted_sequence),
            "the first accepted boundary should become durably cleaned") ||
        !Require(
            lifecycle.LoadRequiredCheckpointXidsSinceCleanup(
                required_checkpoint_xids,
                &failure_reason) &&
                required_checkpoint_xids == std::vector<std::uint64_t>({700}),
            "durable cleanup should release only preimages at or below its exact accepted boundary: " +
                failure_reason) ||
        !Require(
            lifecycle.MarkApfsDurableThrough(second_accepted_sequence),
            "the second accepted boundary should become APFS-durable") ||
        !Require(
            lifecycle.LoadRequiredCheckpointXidsSinceCleanup(
                required_checkpoint_xids,
                &failure_reason) &&
                required_checkpoint_xids == std::vector<std::uint64_t>({700}),
            "APFS-durable and later accepted work must retain their shared preimage XID: " + failure_reason))
    {
        return false;
    }

    Tx restarted(L"DeferredContent");
    restarted.SetVolumeIdentity(L"preimage-checkpoint-lifecycle-volume");
    restarted.SetJournalPath(lifecycle_path.wstring());
    if (!Require(
            restarted.LoadRequiredCheckpointXidsSinceCleanup(
                required_checkpoint_xids,
                &failure_reason) &&
                required_checkpoint_xids == std::vector<std::uint64_t>({700}),
            "restart should reconstruct the unresolved preimage marker identity: " + failure_reason) ||
        !Require(
            restarted.MarkApfsDurableThrough(final_accepted_sequence) &&
                restarted.MarkCleanedThrough(final_accepted_sequence),
            "durable cleanup should advance through the remaining accepted boundary") ||
        !Require(
            restarted.LoadRequiredCheckpointXidsSinceCleanup(
                required_checkpoint_xids,
                &failure_reason) &&
                required_checkpoint_xids.empty(),
            "cleanup should release the final preimage XID: " + failure_reason))
    {
        return false;
    }

    const auto compaction_path = run_root / "preimage-checkpoint-compaction.wal";
    Tx compacting(L"DeferredContent");
    compacting.SetJournalMaxBytesForTest(900);
    compacting.SetVolumeIdentity(L"preimage-checkpoint-compaction-volume");
    compacting.SetJournalPath(compaction_path.wstring());
    auto cleaned_mutation = MakeMetadataMutation(L"\\cleaned-before-preimage-compaction.txt");
    if (!Require(
            compacting.Begin() && compacting.RecordMutation(cleaned_mutation) && compacting.Accept(111),
            "compaction fixture should accept its cleaned transaction"))
    {
        return false;
    }
    const auto cleaned_sequence = compacting.Watermarks().accepted_sequence;
    if (!Require(
            compacting.MarkApfsDurableThrough(cleaned_sequence) &&
                compacting.MarkCleanedThrough(cleaned_sequence),
            "compaction fixture should clean its first transaction"))
    {
        return false;
    }
    auto retained_mutation = MakeMetadataMutation(L"\\retained-after-preimage-compaction.txt");
    if (!Require(
            compacting.Begin() && compacting.RecordMutation(retained_mutation) && compacting.Accept(222),
            "size retry should compact and retain the new marker preimage identity"))
    {
        return false;
    }
    const auto compacted_read = Wal::ReadAll(
        compaction_path,
        "preimage-checkpoint-compaction-volume");
    const auto compacted_marker = std::find_if(
        compacted_read.records.begin(),
        compacted_read.records.end(),
        [](const auto& record)
        {
            return record.operation == Wal::OperationKind::TransactionMarker &&
                record.state == Wal::RecordState::Accepted;
        });
    if (!Require(
            compacted_read.status == Wal::ReadStatus::Ok &&
                std::any_of(
                    compacted_read.records.begin(),
                    compacted_read.records.end(),
                    [](const auto& record)
                    {
                        return record.operation == Wal::OperationKind::CompactionIndex;
                    }) &&
                compacted_marker != compacted_read.records.end() &&
                compacted_marker->object_id == 222,
            "compaction should preserve the accepted marker preimage XID"))
    {
        return false;
    }
    Tx compacted_restart(L"DeferredContent");
    compacted_restart.SetVolumeIdentity(L"preimage-checkpoint-compaction-volume");
    compacted_restart.SetJournalPath(compaction_path.wstring());
    if (!Require(
            compacted_restart.LoadRequiredCheckpointXidsSinceCleanup(
                required_checkpoint_xids,
                &failure_reason) &&
                required_checkpoint_xids == std::vector<std::uint64_t>({222}),
            "restart after compaction should preserve the unresolved preimage XID: " + failure_reason))
    {
        return false;
    }

    constexpr std::uint64_t wal_flag_accepted = 0x8;
    const auto make_prepared = [](const std::string& identity, std::uint64_t transaction_id)
    {
        Wal::Record record{};
        record.volume_identity = identity;
        record.transaction_id = transaction_id;
        record.sequence = 1;
        record.operation = Wal::OperationKind::SetBasicInfo;
        record.state = Wal::RecordState::Prepared;
        record.object_id = 123456;
        record.path_utf8 = "\\legacy.txt";
        return record;
    };
    const auto make_accepted_marker = [](
        const std::string& identity,
        std::uint64_t transaction_id,
        std::uint64_t sequence,
        std::uint64_t preimage_checkpoint_xid)
    {
        Wal::Record record{};
        record.volume_identity = identity;
        record.transaction_id = transaction_id;
        record.sequence = sequence;
        record.operation = Wal::OperationKind::TransactionMarker;
        record.state = Wal::RecordState::Accepted;
        record.flags = wal_flag_accepted;
        record.logical_length = 1;
        record.object_id = preimage_checkpoint_xid;
        return record;
    };

    const auto legacy_path = run_root / "preimage-checkpoint-legacy-zero.wal";
    const std::string legacy_identity = "preimage-checkpoint-legacy-zero-volume";
    Wal legacy_wal({legacy_path, legacy_identity, 1024 * 1024});
    if (!Require(
            legacy_wal.AppendBatch({
                make_prepared(legacy_identity, 1),
                make_accepted_marker(legacy_identity, 1, 2, 0),
            }),
            "legacy zero-preimage fixture should persist"))
    {
        return false;
    }
    Tx legacy(L"DeferredContent");
    legacy.SetVolumeIdentity(L"preimage-checkpoint-legacy-zero-volume");
    legacy.SetJournalPath(legacy_path.wstring());
    accepted.clear();
    if (!Require(
            legacy.LoadAcceptedTransactionsSinceCleanup(accepted, &failure_reason) &&
                accepted.size() == 1 && accepted.front().preimage_checkpoint_xid == 0,
            "legacy replay should continue exposing a zero preimage marker: " + failure_reason) ||
        !Require(
            !legacy.LoadRequiredCheckpointXidsSinceCleanup(
                required_checkpoint_xids,
                &failure_reason) &&
                required_checkpoint_xids.empty() &&
                !failure_reason.empty() &&
                legacy.RecoveryStateValid(),
            "only the new required-preimage census should reject a legacy zero marker"))
    {
        return false;
    }

    const auto conflicting_path = run_root / "preimage-checkpoint-conflicting-terminal.wal";
    const std::string conflicting_identity = "preimage-checkpoint-conflicting-terminal-volume";
    Wal conflicting_wal({conflicting_path, conflicting_identity, 1024 * 1024});
    if (!Require(
            conflicting_wal.AppendBatch({
                make_prepared(conflicting_identity, 1),
                make_accepted_marker(conflicting_identity, 1, 2, 333),
                make_accepted_marker(conflicting_identity, 1, 3, 444),
            }),
            "conflicting terminal identity fixture should persist checksum-valid evidence"))
    {
        return false;
    }
    Tx conflicting(L"DeferredContent");
    conflicting.SetVolumeIdentity(L"preimage-checkpoint-conflicting-terminal-volume");
    conflicting.SetJournalPath(conflicting_path.wstring());
    return Require(
               !conflicting.RecoveryStateValid(),
               "duplicate accepted terminals with conflicting preimage identities must be rejected") &&
        Require(
               !conflicting.LoadRequiredCheckpointXidsSinceCleanup(
                   required_checkpoint_xids,
                   &failure_reason),
               "the required-preimage census must not replace a conflicting terminal identity");
}

} // namespace

int main()
{
    std::error_code ec;
    const auto unique_id = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto run_root = std::filesystem::temp_directory_path(ec) / ("ApfsAccessTxTests_" + std::to_string(unique_id));
    if (ec)
    {
        std::cerr << "[FAIL] unable to access temporary directory" << std::endl;
        return 1;
    }

    std::filesystem::remove_all(run_root, ec);
    ec.clear();
    std::filesystem::create_directories(run_root, ec);
    if (ec)
    {
        std::cerr << "[FAIL] unable to create test directory" << std::endl;
        return 1;
    }

    char* benchmark_flag = nullptr;
    std::size_t benchmark_flag_size = 0;
    const bool benchmark_enabled =
        _dupenv_s(&benchmark_flag, &benchmark_flag_size, "APFSACCESS_ACCEPTANCE_BENCHMARK") == 0 &&
        benchmark_flag != nullptr;
    if (benchmark_flag)
    {
        std::free(benchmark_flag);
    }
    if (benchmark_enabled)
    {
        const auto benchmark_ok = RunAcceptanceBenchmark(run_root);
        std::filesystem::remove_all(run_root, ec);
        return benchmark_ok ? 0 : 1;
    }
    if (EnvironmentFlag("APFSACCESS_FINALIZATION_COVERAGE_BENCHMARK"))
    {
        const auto benchmark_ok = RunFinalizationCoverageBenchmark(run_root);
        std::filesystem::remove_all(run_root, ec);
        return benchmark_ok ? 0 : 1;
    }

    const auto journal_path = run_root / "rw-journal.wal";
    const std::string volume_identity = "tx-test-volume";
    apfsaccess::rw::TransactionManager tx(L"Conservative");
    tx.SetJournalPath(journal_path.wstring());
    tx.SetVolumeIdentity(L"tx-test-volume");

    std::vector<std::string> stages;
    tx.SetFaultInjectionHook([&stages](const std::string& stage)
    {
        stages.push_back(stage);
    });

    bool ok = true;
    ok &= TestUnlinkOutcomeAcceptance(run_root);
    ok &= TestExtendedAttributeAcceptanceAndValidation(run_root);
    ok &= TestInodeMetadataAcceptance(run_root);
    ok &= TestAllocationSizeAcceptanceOrder(run_root);
    ok &= TestDirectoryRestoreAcceptance(run_root);
    ok &= TestPoisonedManagerRejectsFurtherMutationAndReuse(run_root);
    ok &= TestPoisonedManagerRejectsDurabilityWatermarks(run_root);
    ok &= TestRecoveryClearingRequiresCurrentWriterGeneration(run_root);
    ok &= TestConfigurationOrderAndLeaseTransfer(run_root);
    ok &= TestCompactionRetryRetainsCoverageTrust(run_root);
    ok &= TestObserverReadsAndActiveLeaseLoss(run_root);
    ok &= TestWalPreimageCheckpointContract(run_root);
    ok &= TestCommittedPreimageCensusDirect(run_root);
    ok &= TestCommittedPreimageCensusAfterRestart(run_root, false);
    ok &= TestCommittedPreimageCensusAfterRestart(run_root, true);
    ok &= TestLegacyCommittedPreimageCensus(run_root);
    ok &= TestEmptyCommittedPreimageCensus(run_root);
    ok &= TestCleanPreimageCensusRetainsValidatedOwnership(run_root);
    ok &= TestMixedCheckpointedBoundaryRejectsCleanShortcut(run_root);
    ok &= TestDirectCommitSurvivesBudgetCompaction(run_root);
    ok &= TestAcceptedPinCensusAvoidsHistoryReads(run_root);
    ok &= TestAcceptedSnapshotPinsRetireAtExactCleanup(run_root);
    ok &= TestUntrustedAcceptedPinCensusFallsBack(run_root);
    ok &= TestAcceptedPinCensusOwnershipAndAmbiguousAppend(run_root);
    ok &= TestBoundedAcceptedPinCensus(run_root);
    ok &= TestIncompleteCompactedPinHistoryFallsBack(run_root);
    ok &= TestAcceptedPinsSurvivePreparationCompaction(run_root);
    ok &= TestIncrementalPinCensusCapAndReseed(run_root);
    ok &= TestCompletedCompactionRetainsCleanCensusProof(run_root);
    ok &= Require(tx.CurrentState() == apfsaccess::rw::TransactionManager::State::Idle, "Initial state should be idle");
    ok &= Require(tx.Begin(), "Begin should succeed from idle state");
    ok &= Require(tx.CurrentState() == apfsaccess::rw::TransactionManager::State::Active, "State should be active after begin");
    ok &= Require(tx.CurrentTransactionId() == 1, "First transaction id should be 1");

    apfsaccess::rw::TransactionManager::MutationIntent mutation{};
    mutation.kind = apfsaccess::rw::TransactionManager::MutationKind::CreateFile;
    mutation.path = L"\\docs\\tx.txt";
    ok &= Require(tx.RecordMutation(mutation), "RecordMutation should succeed in active state");
    apfsaccess::rw::TransactionManager::MutationIntent size_mutation{};
    size_mutation.kind = apfsaccess::rw::TransactionManager::MutationKind::SetFileSize;
    size_mutation.path = L"\\docs\\tx.txt";
    size_mutation.length = 4096;
    ok &= Require(tx.RecordMutation(size_mutation), "Second mutation in same transaction should succeed");
    ok &= Require(tx.PendingMutationCount() == 2, "Pending mutation count should be 2");
    auto pre_commit_journal = apfsaccess::rw::WriteAheadLog::ReadAll(journal_path, volume_identity);
    ok &= Require(
        pre_commit_journal.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
            pre_commit_journal.records.empty(),
        "Prepared transaction mutations should stay buffered until commit boundary");

    ok &= Require(tx.Commit(), "Commit should succeed");
    ok &= Require(tx.CurrentState() == apfsaccess::rw::TransactionManager::State::Idle, "State should return to idle after commit");
    ok &= Require(tx.PendingMutationCount() == 0, "Pending mutation count should be reset after commit");
    ok &= Require(
        tx.DurableJournalAppendCount() == 1,
        "Commit should persist prepared mutations and final marker with one durable WAL append");
    ok &= Require(
        tx.DurableJournalAppendMicroseconds() >= tx.DurableJournalAppendMaxMicroseconds(),
        "WAL timing telemetry should include the slowest durable append");
    ok &= Require(
        tx.JournalAppendHandleOpenCount() == 1 &&
            tx.JournalAppendHandleFlushCount() == 1,
        "Transaction manager should reuse one WAL append handle for the commit boundary");

    const std::vector<std::string> expected_stages =
    {
        "begin",
        "mutation-recorded",
        "mutation-recorded",
        "commit-start",
        "prepare",
        "write-data",
        "write-metadata",
        "flush-data",
        "switch-checkpoint",
        "finalize",
        "commit-finish",
    };
    ok &= Require(stages == expected_stages, "Stage callback sequence should match commit state machine");

    auto journal_read = apfsaccess::rw::WriteAheadLog::ReadAll(journal_path, volume_identity);
    ok &= Require(journal_read.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok, "WAL should read after commit");
    ok &= Require(journal_read.records.size() == 3, "WAL should capture prepared mutations plus a commit marker");
    ok &= Require(
        journal_read.records[0].state == apfsaccess::rw::WriteAheadLog::RecordState::Prepared &&
            journal_read.records[1].state == apfsaccess::rw::WriteAheadLog::RecordState::Prepared,
        "Committed transaction mutations should stay prepared until the final marker");
    ok &= Require(
        journal_read.records[2].operation == apfsaccess::rw::WriteAheadLog::OperationKind::TransactionMarker &&
            journal_read.records[2].state == apfsaccess::rw::WriteAheadLog::RecordState::Checkpointed &&
            journal_read.records[2].logical_length == 2,
        "Committed transaction should end with a durable marker and mutation count");
    ok &= Require(journal_read.records.front().path_utf8.find("\\docs\\tx.txt") != std::string::npos, "WAL should persist committed path");

    apfsaccess::rw::TransactionManager::MutationIntent delete_mutation{};
    delete_mutation.kind = apfsaccess::rw::TransactionManager::MutationKind::Delete;
    delete_mutation.path = L"\\docs\\tx.txt";
    ok &= Require(tx.Begin(), "Second Begin should succeed");
    ok &= Require(tx.RecordMutation(delete_mutation), "Second RecordMutation should succeed");
    auto pre_abort_journal = apfsaccess::rw::WriteAheadLog::ReadAll(journal_path, volume_identity);
    ok &= Require(pre_abort_journal.records.size() == 3, "Prepared abort mutation should stay buffered before abort marker");
    ok &= Require(tx.Abort(), "Abort should succeed");
    ok &= Require(tx.CurrentState() == apfsaccess::rw::TransactionManager::State::Idle, "State should return to idle after abort");
    ok &= Require(
        tx.DurableJournalAppendCount() == 2,
        "Abort marker should add one durable WAL append after the committed transaction");

    journal_read = apfsaccess::rw::WriteAheadLog::ReadAll(journal_path, volume_identity);
    ok &= Require(journal_read.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok, "WAL should read after abort");
    ok &= Require(journal_read.records.size() == 4, "WAL should capture committed transaction plus aborted marker");
    ok &= Require(
        journal_read.records.back().operation == apfsaccess::rw::WriteAheadLog::OperationKind::TransactionMarker &&
            journal_read.records.back().state == apfsaccess::rw::WriteAheadLog::RecordState::Cleaned,
        "Aborted transaction should end with a cleaned marker");

    apfsaccess::rw::TransactionManager unicode_tx(L"Conservative");
    unicode_tx.SetJournalPath(journal_path.wstring());
    unicode_tx.SetVolumeIdentity(L"tx-test-volume");
    apfsaccess::rw::TransactionManager::MutationIntent unicode_mutation{};
    unicode_mutation.kind = apfsaccess::rw::TransactionManager::MutationKind::CreateDirectory;
    unicode_mutation.path = L"\\unicode-\x6587\x4EF6-\xD83D\xDE80";
    ok &= Require(unicode_tx.Begin(), "Unicode Begin should succeed");
    ok &= Require(unicode_tx.RecordMutation(unicode_mutation), "Unicode RecordMutation should succeed");
    ok &= Require(unicode_tx.Commit(), "Unicode Commit should succeed");
    ok &= Require(
        unicode_tx.DurableJournalAppendCount() == 1,
        "New transaction manager should also batch prepared mutation and marker into one durable WAL append");

    journal_read = apfsaccess::rw::WriteAheadLog::ReadAll(journal_path, volume_identity);
    ok &= Require(journal_read.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok, "WAL should read after Unicode commit");
    ok &= Require(journal_read.records.size() == 6, "WAL should contain prepared mutations and final markers");
    const auto unicode_path_utf8 = apfsaccess::rw::TransactionManager::WideToUtf8(unicode_mutation.path);
    ok &= Require(
        !unicode_path_utf8.empty() &&
        journal_read.records[journal_read.records.size() - 2].path_utf8.find(unicode_path_utf8) != std::string::npos,
        "WAL should persist Unicode paths as UTF-8 without truncating the transaction record");
    ok &= Require(
        journal_read.records[journal_read.records.size() - 2].transaction_id == 3 &&
            journal_read.records.back().transaction_id == 3,
        "New manager should seed the next transaction id from the existing WAL");
    ok &= Require(
        journal_read.records[journal_read.records.size() - 2].sequence == 5 &&
            journal_read.records.back().sequence == 6,
        "New manager should seed the next sequence id from the existing WAL");

    apfsaccess::rw::TransactionManager checkpointed_recovery(L"Conservative");
    checkpointed_recovery.SetJournalPath(journal_path.wstring());
    checkpointed_recovery.SetVolumeIdentity(L"tx-test-volume");
    std::vector<apfsaccess::rw::TransactionManager::AcceptedTransaction> checkpointed_transactions;
    std::string checkpointed_failure;
    ok &= Require(
        checkpointed_recovery.LoadAcceptedTransactionsSinceCleanup(
            checkpointed_transactions,
            &checkpointed_failure),
        "Replay lookup should include checkpointed transactions after the cleanup watermark");
    ok &= Require(
        checkpointed_failure.empty() && checkpointed_transactions.size() == 2,
        "Replay lookup should reconstruct both committed transaction boundaries");
    if (checkpointed_transactions.size() == 2)
    {
        ok &= Require(
            checkpointed_transactions.front().accepted_sequence == journal_read.records[2].sequence &&
                checkpointed_transactions.front().mutations.size() == 2 &&
                checkpointed_transactions.back().accepted_sequence == journal_read.records.back().sequence &&
                checkpointed_transactions.back().mutations.size() == 1,
            "Replay lookup should preserve checkpointed transaction order and mutation counts");
    }

    apfsaccess::rw::TransactionManager proof_tx(L"DeferredContent");
    std::vector<std::uint64_t> retained_proof_ids;
    retained_proof_ids.reserve(
        apfsaccess::rw::TransactionManager::MaxRetainedAcceptedSequenceProofs());
    std::uint64_t oldest_proof_sequence = 0;
    for (std::size_t index = 0;
         index < apfsaccess::rw::TransactionManager::MaxRetainedAcceptedSequenceProofs();
         ++index)
    {
        apfsaccess::rw::TransactionManager::MutationIntent proof_mutation{};
        proof_mutation.kind = apfsaccess::rw::TransactionManager::MutationKind::CreateFile;
        proof_mutation.path = L"\\proof-" + std::to_wstring(index) + L".bin";
        ok &= Require(proof_tx.Begin(), "Pinned proof transaction should begin");
        const auto proof_id = proof_tx.CurrentTransactionId();
        ok &= Require(
            proof_tx.RetainAcceptedSequenceProof(proof_id),
            "Pinned proof registry should retain an active transaction");
        ok &= Require(
            proof_tx.RecordMutation(proof_mutation),
            "Pinned proof transaction should record a mutation");
        ok &= Require(
            proof_tx.Accept(),
            "Pinned proof transaction should reach an accepted boundary");
        const auto proof_sequence = proof_tx.AcceptedSequenceForTransaction(proof_id);
        ok &= Require(
            proof_sequence.has_value(),
            "Pinned proof should resolve the exact accepted transaction");
        if (index == 0 && proof_sequence.has_value())
        {
            oldest_proof_sequence = *proof_sequence;
        }
        retained_proof_ids.push_back(proof_id);
    }
    ok &= Require(
        proof_tx.RetainedAcceptedSequenceProofCount() ==
            apfsaccess::rw::TransactionManager::MaxRetainedAcceptedSequenceProofs(),
        "Pinned proof registry should stop at its fixed capacity");
    ok &= Require(proof_tx.Begin(), "Proof-cap fallback transaction should begin");
    apfsaccess::rw::TransactionManager::MutationIntent overflow_proof_mutation{};
    overflow_proof_mutation.kind = apfsaccess::rw::TransactionManager::MutationKind::CreateFile;
    overflow_proof_mutation.path = L"\\proof-overflow.bin";
    ok &= Require(
        proof_tx.RecordMutation(overflow_proof_mutation),
        "Proof-cap fallback transaction should record a mutation");
    ok &= Require(
        !proof_tx.RetainAcceptedSequenceProof(proof_tx.CurrentTransactionId()),
        "Pinned proof registry should apply backpressure instead of evicting a live proof");
    ok &= Require(proof_tx.Abort(), "Proof-cap fallback transaction should abort cleanly");
    ok &= Require(
        proof_tx.AcceptedSequenceForTransaction(retained_proof_ids.front()) == oldest_proof_sequence,
        "A full proof registry must preserve its oldest live transaction exactly");

    proof_tx.ReleaseAcceptedSequenceProof(retained_proof_ids.back());
    ok &= Require(proof_tx.Begin(), "Freed proof slot transaction should begin");
    const auto reused_proof_id = proof_tx.CurrentTransactionId();
    ok &= Require(
        proof_tx.RetainAcceptedSequenceProof(reused_proof_id) &&
            proof_tx.RetainAcceptedSequenceProof(reused_proof_id),
        "A freed proof slot should admit two callers for the same transaction");
    apfsaccess::rw::TransactionManager::MutationIntent reused_proof_mutation{};
    reused_proof_mutation.kind = apfsaccess::rw::TransactionManager::MutationKind::CreateFile;
    reused_proof_mutation.path = L"\\proof-reused-slot.bin";
    ok &= Require(
        proof_tx.RecordMutation(reused_proof_mutation),
        "Freed proof slot transaction should record a mutation");
    ok &= Require(
        proof_tx.Accept(),
        "Freed proof slot transaction should reach an accepted boundary");
    const auto reused_proof_sequence = proof_tx.AcceptedSequenceForTransaction(reused_proof_id);
    ok &= Require(
        reused_proof_sequence.has_value() &&
            proof_tx.RetainedAcceptedSequenceProofCount() ==
                apfsaccess::rw::TransactionManager::MaxRetainedAcceptedSequenceProofs(),
        "Reusing one slot should restore the registry to capacity without duplicating its entry");
    proof_tx.ReleaseAcceptedSequenceProof(reused_proof_id);
    ok &= Require(
        proof_tx.AcceptedSequenceForTransaction(reused_proof_id) == reused_proof_sequence,
        "The first grouped caller release must preserve a shared exact-transaction proof");
    proof_tx.ReleaseAcceptedSequenceProof(reused_proof_id);
    ok &= Require(
        !proof_tx.AcceptedSequenceForTransaction(reused_proof_id).has_value(),
        "The final grouped caller release should remove the shared exact-transaction proof");

    const auto latest_proof_sequence = proof_tx.Watermarks().accepted_sequence;
    ok &= Require(
        proof_tx.MarkApfsDurableThrough(latest_proof_sequence),
        "Pinned proof fixture should mark all accepted work APFS-durable");
    ok &= Require(
        proof_tx.MarkCleanedThrough(latest_proof_sequence),
        "Pinned proof fixture should advance cleanup through all accepted work");
    ok &= Require(
        proof_tx.TrackedAcceptedBoundaryCount() == 0,
        "Cleanup should prune accepted boundaries that can no longer be targeted");
    ok &= Require(
        proof_tx.AcceptedSequenceForTransaction(retained_proof_ids.front()) == oldest_proof_sequence,
        "Cleanup must not erase an explicitly pinned exact-transaction proof");
    for (const auto proof_id : retained_proof_ids)
    {
        proof_tx.ReleaseAcceptedSequenceProof(proof_id);
    }
    ok &= Require(
        proof_tx.RetainedAcceptedSequenceProofCount() == 0,
        "The final grouped caller should release every exact-transaction proof");

    const std::vector<std::byte> inline_payload{
        std::byte{0x01},
        std::byte{0x02},
        std::byte{0x03},
        std::byte{0x04},
    };
    const std::array<std::uint8_t, apfsaccess::rw::WriteAheadLog::PayloadHashSize> inline_payload_sha256{
        0x9f, 0x64, 0xa7, 0x47, 0xe1, 0xb9, 0x7f, 0x13,
        0x1f, 0xab, 0xb6, 0xb4, 0x47, 0x29, 0x6c, 0x9b,
        0x6f, 0x02, 0x01, 0xe7, 0x9f, 0xb3, 0xc5, 0x35,
        0x6e, 0x6c, 0x77, 0xe8, 0x9b, 0x6a, 0x80, 0x6a,
    };

    const auto inline_acceptance_path = run_root / "inline-accepted-write.wal";
    apfsaccess::rw::TransactionManager inline_acceptance_tx(L"DeferredContent");
    inline_acceptance_tx.SetVolumeIdentity(L"inline-accepted-volume");
    inline_acceptance_tx.SetJournalPath(inline_acceptance_path.wstring());
    apfsaccess::rw::TransactionManager::MutationIntent inline_mutation{};
    inline_mutation.kind = apfsaccess::rw::TransactionManager::MutationKind::Write;
    inline_mutation.path = L"\\inline.bin";
    inline_mutation.length = inline_payload.size();
    inline_mutation.object_id = 41;
    inline_mutation.generation = 7;
    inline_mutation.payload_spool_offset = 1024;
    inline_mutation.payload_length = inline_payload.size();
    inline_mutation.payload_checksum = inline_payload_sha256;
    inline_mutation.inline_payload = inline_payload;
    ok &= Require(inline_acceptance_tx.Begin(), "Inline acceptance transaction should begin");
    ok &= Require(
        inline_acceptance_tx.CanAddInlinePayload(apfsaccess::rw::WriteAheadLog::MaxInlinePayloadBytes),
        "An empty transaction should admit the complete inline payload budget");
    ok &= Require(
        !inline_acceptance_tx.CanAddInlinePayload(apfsaccess::rw::WriteAheadLog::MaxInlinePayloadBytes + 1),
        "A transaction should reject payload data beyond the inline budget");
    ok &= Require(
        inline_acceptance_tx.RecordMutation(inline_mutation),
        "Inline acceptance transaction should record its write");
    ok &= Require(
        inline_acceptance_tx.CanAddInlinePayload(
            apfsaccess::rw::WriteAheadLog::MaxInlinePayloadBytes - inline_payload.size()),
        "A transaction should admit payload data exactly through the inline budget") &&
        Require(
            !inline_acceptance_tx.CanAddInlinePayload(
                apfsaccess::rw::WriteAheadLog::MaxInlinePayloadBytes - inline_payload.size() + 1),
            "A transaction should reject aggregate inline payload data beyond its budget");
    ok &= Require(
        inline_acceptance_tx.CanAcceptWithoutPayloadSpoolFlush(),
        "A transaction with complete inline recovery bytes should not require a payload-spool flush");
    ok &= Require(
        inline_acceptance_tx.Accept(),
        "Inline acceptance transaction should persist its durable WAL boundary");
    ok &= Require(
        inline_acceptance_tx.CanFinalizeWithoutPayloadSpoolFlush(),
        "Accepted inline work should remain self-contained through finalization");
    ok &= Require(
        inline_acceptance_tx.FinalizationCoverageCacheHitCount() == 1 &&
            inline_acceptance_tx.FinalizationCoverageWalScanCount() == 0,
        "Same-process accepted work should use the bounded finalization coverage summary");
    ok &= Require(
        inline_acceptance_tx.CanFinalizeWithoutPayloadSpoolFlush(false),
        "The rollback path should preserve strict WAL-scanned finalization coverage");
    ok &= Require(
        inline_acceptance_tx.FinalizationCoverageWalScanCount() == 1,
        "Disabling the finalization coverage cache should force one complete WAL scan");
    const auto inline_acceptance_read = apfsaccess::rw::WriteAheadLog::ReadAll(
        inline_acceptance_path,
        "inline-accepted-volume");
    ok &= Require(
        inline_acceptance_read.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
            inline_acceptance_read.records.size() == 2 &&
            inline_acceptance_read.records.front().inline_payload == inline_payload,
        "Accepted WAL should retain byte-identical inline recovery payload data");
    apfsaccess::rw::TransactionManager restarted_inline_acceptance_tx(L"DeferredContent");
    restarted_inline_acceptance_tx.SetVolumeIdentity(L"inline-accepted-volume");
    restarted_inline_acceptance_tx.SetJournalPath(inline_acceptance_path.wstring());
    ok &= Require(
        restarted_inline_acceptance_tx.CanFinalizeWithoutPayloadSpoolFlush(),
        "Restarted inline accepted work should remain recoverable after strict WAL validation");
    ok &= Require(
        restarted_inline_acceptance_tx.FinalizationCoverageCacheHitCount() == 1 &&
            restarted_inline_acceptance_tx.FinalizationCoverageWalScanCount() == 0,
        "Restarted inline work should use coverage rebuilt from its exclusively leased WAL snapshot");
    ok &= Require(
        restarted_inline_acceptance_tx.MarkApfsDurableThrough(
            restarted_inline_acceptance_tx.Watermarks().accepted_sequence),
        "Restarted manager should be able to take over the writer lease and mark replay durable");
    ok &= Require(
        inline_acceptance_tx.CanFinalizeWithoutPayloadSpoolFlush(),
        "A manager that lost its writer lease should still validate inline recovery through the WAL") &&
        Require(
            inline_acceptance_tx.FinalizationCoverageCacheHitCount() == 1 &&
                inline_acceptance_tx.FinalizationCoverageWalScanCount() == 2,
            "Writer-lease transfer must force the previous manager back to strict WAL scanning");

    const auto mixed_acceptance_path = run_root / "mixed-accepted-write.wal";
    apfsaccess::rw::TransactionManager mixed_acceptance_tx(L"DeferredContent");
    mixed_acceptance_tx.SetVolumeIdentity(L"mixed-accepted-volume");
    mixed_acceptance_tx.SetJournalPath(mixed_acceptance_path.wstring());
    auto legacy_mutation = inline_mutation;
    legacy_mutation.path = L"\\legacy.bin";
    legacy_mutation.inline_payload.clear();
    ok &= Require(mixed_acceptance_tx.Begin(), "Mixed acceptance transaction should begin");
    ok &= Require(
        mixed_acceptance_tx.RecordMutation(inline_mutation) &&
            mixed_acceptance_tx.RecordMutation(legacy_mutation),
        "Mixed acceptance transaction should record both writes");
    ok &= Require(
        !mixed_acceptance_tx.CanAddInlinePayload(1),
        "A transaction with a non-inline write must reject further inline payload admission");
    ok &= Require(
        !mixed_acceptance_tx.CanAcceptWithoutPayloadSpoolFlush(),
        "One non-inline write should keep the complete transaction on the payload-spool flush path");
    ok &= Require(
        mixed_acceptance_tx.Accept(),
        "Mixed acceptance transaction should remain valid through the legacy acceptance path");
    ok &= Require(
        !mixed_acceptance_tx.CanFinalizeWithoutPayloadSpoolFlush(),
        "Accepted mixed work should retain payload-spool finalization durability");
    ok &= Require(
        mixed_acceptance_tx.FinalizationCoverageCacheHitCount() == 1 &&
            mixed_acceptance_tx.FinalizationCoverageWalScanCount() == 0,
        "Same-process mixed acceptance should be rejected by the bounded coverage summary");
    const auto mixed_accepted_sequence = mixed_acceptance_tx.Watermarks().accepted_sequence;
    ok &= Require(
        mixed_acceptance_tx.MarkApfsDurableThrough(mixed_accepted_sequence),
        "Mixed acceptance should advance only after its APFS checkpoint is proven durable");
    ok &= Require(
        mixed_acceptance_tx.CanFinalizeWithoutPayloadSpoolFlush(),
        "APFS-durable mixed work should no longer require a redundant pre-cleanup spool flush") &&
        Require(
            mixed_acceptance_tx.FinalizationCoverageCacheHitCount() == 2 &&
                mixed_acceptance_tx.FinalizationCoverageWalScanCount() == 0,
            "Durability advancement should prune the mixed acceptance coverage blocker");

    const auto flushed_legacy_path = run_root / "flushed-legacy-accepted-write.wal";
    apfsaccess::rw::TransactionManager flushed_legacy_tx(L"DeferredContent");
    flushed_legacy_tx.SetVolumeIdentity(L"flushed-legacy-accepted-volume");
    flushed_legacy_tx.SetJournalPath(flushed_legacy_path.wstring());
    ok &= Require(flushed_legacy_tx.Begin(), "Flushed legacy transaction should begin");
    ok &= Require(
        flushed_legacy_tx.RecordMutation(legacy_mutation),
        "Flushed legacy transaction should record its non-inline write");
    ok &= Require(
        flushed_legacy_tx.FlushPreparedRecords(),
        "Flushed legacy transaction should persist prepared records separately");
    ok &= Require(
        flushed_legacy_tx.Accept(),
        "Flushed legacy transaction should append its accepted marker");
    ok &= Require(
        !flushed_legacy_tx.CanFinalizeWithoutPayloadSpoolFlush(),
        "Separately flushed non-inline writes must retain their spool-flush requirement");
    ok &= Require(
        flushed_legacy_tx.FinalizationCoverageCacheHitCount() == 1 &&
            flushed_legacy_tx.FinalizationCoverageWalScanCount() == 0,
        "Flushed prepared records should retain bounded recovery classification");

    const auto poisoned_coverage_path = run_root / "poisoned-finalization-coverage.wal";
    apfsaccess::rw::TransactionManager poisoned_coverage_tx(L"DeferredContent");
    poisoned_coverage_tx.SetVolumeIdentity(L"poisoned-finalization-coverage-volume");
    poisoned_coverage_tx.SetJournalPath(poisoned_coverage_path.wstring());
    ok &= Require(poisoned_coverage_tx.Begin(), "Poisoned coverage transaction should begin");
    ok &= Require(
        poisoned_coverage_tx.RecordMutation(inline_mutation) && poisoned_coverage_tx.Accept(),
        "Poisoned coverage fixture should accept inline recovery data");
    const auto poisoned_accepted_sequence = poisoned_coverage_tx.Watermarks().accepted_sequence;
    ok &= Require(
        poisoned_coverage_tx.MarkApfsDurableThrough(poisoned_accepted_sequence),
        "Poisoned coverage fixture should first reach APFS durability");
    poisoned_coverage_tx.SetJournalFaultInjectionHook([](std::string_view stage)
    {
        return stage == "durable-flush";
    });
    ok &= Require(
        !poisoned_coverage_tx.MarkCleanedThrough(poisoned_accepted_sequence),
        "Ambiguous cleanup-watermark durability should poison finalization coverage");
    poisoned_coverage_tx.SetJournalFaultInjectionHook({});
    const auto poisoned_watermarks = poisoned_coverage_tx.Watermarks();
    ok &= Require(
        poisoned_watermarks.accepted_sequence == poisoned_watermarks.apfs_durable_sequence &&
            poisoned_watermarks.cleanup_sequence < poisoned_watermarks.apfs_durable_sequence,
        "Poisoned coverage fixture should retain equal accepted and APFS-durable watermarks");
    ok &= Require(
        !poisoned_coverage_tx.CanFinalizeWithoutPayloadSpoolFlush() &&
            !poisoned_coverage_tx.CanFinalizeWithoutPayloadSpoolFlush(),
        "Poisoned coverage must fail closed even when accepted and durable watermarks are equal");
    ok &= Require(
        poisoned_coverage_tx.FinalizationCoverageCacheHitCount() == 0 &&
            poisoned_coverage_tx.FinalizationCoverageWalScanCount() == 0,
        "Poisoned coverage should reject before cache use or redundant WAL scans");

    const auto acceptance_journal_path = run_root / "accepted-write.wal";
    apfsaccess::rw::TransactionManager accepted_tx(L"DeferredContent");
    accepted_tx.SetVolumeIdentity(L"accepted-test-volume");
    accepted_tx.SetJournalPath(acceptance_journal_path.wstring());

    apfsaccess::rw::TransactionManager::MutationIntent payload_mutation{};
    payload_mutation.kind = apfsaccess::rw::TransactionManager::MutationKind::Write;
    payload_mutation.path = L"\\accepted.bin";
    payload_mutation.offset = 4096;
    payload_mutation.length = 8192;
    payload_mutation.object_id = 77;
    payload_mutation.generation = 9;
    payload_mutation.payload_spool_offset = 12345;
    payload_mutation.payload_length = 8192;
    payload_mutation.payload_checksum[0] = 0x5a;

    ok &= Require(accepted_tx.Begin(), "Accepted transaction should begin");
    const auto first_accepted_transaction_id = accepted_tx.CurrentTransactionId();
    ok &= Require(
        accepted_tx.RetainAcceptedSequenceProof(first_accepted_transaction_id),
        "Accepted transaction fixture should pin its live exact-transaction proof");
    ok &= Require(accepted_tx.RecordMutation(payload_mutation), "Accepted transaction should record payload mutation");
    ok &= Require(accepted_tx.Accept(), "Accepted transaction should persist its durable acceptance boundary");
    const auto first_accepted_sequence = accepted_tx.Watermarks().accepted_sequence;
    ok &= Require(first_accepted_sequence == 2, "Accepted marker should become the accepted watermark");
    ok &= Require(
        accepted_tx.DurableJournalAppendCount() == 1 &&
            accepted_tx.DurableJournalAppendMicroseconds() >= accepted_tx.DurableJournalAppendMaxMicroseconds(),
        "Accepted transaction should expose one timed durable WAL append");
    ok &= Require(
        accepted_tx.Watermarks().apfs_durable_sequence == 0 &&
            accepted_tx.Watermarks().cleanup_sequence == 0,
        "Acceptance alone must not imply APFS durability or cleanup");
    ok &= Require(
        accepted_tx.CurrentState() == apfsaccess::rw::TransactionManager::State::Idle,
        "Accepted transaction should release the active slot for the next foreground batch");
    ok &= Require(
        accepted_tx.AcceptedSequenceForTransaction(first_accepted_transaction_id) == first_accepted_sequence,
        "Pinned acceptance proof should bind the original transaction to its accepted sequence");

    apfsaccess::rw::TransactionManager restarted_proof_tx(L"DeferredContent");
    restarted_proof_tx.SetVolumeIdentity(L"accepted-test-volume");
    restarted_proof_tx.SetJournalPath(acceptance_journal_path.wstring());
    ok &= Require(
        restarted_proof_tx.RetainedAcceptedSequenceProofCount() == 0 &&
            !restarted_proof_tx.AcceptedSequenceForTransaction(first_accepted_transaction_id).has_value(),
        "Restart should reconstruct WAL replay state without reviving process-local grouped proofs");
    accepted_tx.ReleaseAcceptedSequenceProof(first_accepted_transaction_id);

    const auto grouped_acceptance_path = run_root / "grouped-accepted-write.wal";
    apfsaccess::rw::TransactionManager grouped_acceptance_tx(L"DeferredContent");
    grouped_acceptance_tx.SetVolumeIdentity(L"grouped-accepted-volume");
    grouped_acceptance_tx.SetJournalPath(grouped_acceptance_path.wstring());
    auto grouped_mutation = payload_mutation;
    grouped_mutation.path = L"\\grouped.bin";
    std::mutex grouped_mutex;
    std::condition_variable grouped_cv;
    bool first_grouped_acceptance_ready = false;
    bool second_grouped_acceptance_ready = false;
    bool first_grouped_ok = false;
    std::uint64_t first_grouped_sequence = 0;
    std::thread first_grouped_thread([&]()
    {
        first_grouped_ok =
            grouped_acceptance_tx.Begin() &&
            grouped_acceptance_tx.RecordMutation(grouped_mutation) &&
            grouped_acceptance_tx.AcceptForDeferredCommit(&first_grouped_sequence);
        {
            std::lock_guard<std::mutex> lock(grouped_mutex);
            first_grouped_acceptance_ready = true;
        }
        grouped_cv.notify_all();
        {
            std::unique_lock<std::mutex> lock(grouped_mutex);
            grouped_cv.wait(lock, [&]() { return second_grouped_acceptance_ready; });
        }
        first_grouped_ok = first_grouped_ok &&
            grouped_acceptance_tx.WaitForDeferredAcceptanceDurability(first_grouped_sequence);
    });
    {
        std::unique_lock<std::mutex> lock(grouped_mutex);
        grouped_cv.wait(lock, [&]() { return first_grouped_acceptance_ready; });
    }
    std::uint64_t second_grouped_sequence = 0;
    const bool second_grouped_ok =
        grouped_acceptance_tx.Begin() &&
        grouped_acceptance_tx.RecordMutation(grouped_mutation) &&
        grouped_acceptance_tx.AcceptForDeferredCommit(&second_grouped_sequence) &&
        grouped_acceptance_tx.WaitForDeferredAcceptanceDurability(second_grouped_sequence);
    {
        std::lock_guard<std::mutex> lock(grouped_mutex);
        second_grouped_acceptance_ready = true;
    }
    grouped_cv.notify_all();
    first_grouped_thread.join();
    ok &= Require(
        first_grouped_ok && second_grouped_ok &&
            first_grouped_sequence != 0 &&
            second_grouped_sequence > first_grouped_sequence,
        "Deferred acceptance group should durably complete two sequential transactions");
    ok &= Require(
        grouped_acceptance_tx.DeferredWalGroupFlushCount() == 1,
        "Two deferred acceptance transactions should share one WAL flush barrier");
    ok &= Require(
        grouped_acceptance_tx.MarkApfsDurableThrough(second_grouped_sequence) &&
            grouped_acceptance_tx.MarkCleanedThrough(second_grouped_sequence),
        "Grouped deferred acceptance should remain valid through APFS durability and cleanup");

    auto accepted_read = apfsaccess::rw::WriteAheadLog::ReadAll(
        acceptance_journal_path,
        "accepted-test-volume");
    ok &= Require(
        accepted_read.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
            accepted_read.records.size() == 2,
        "Accepted WAL should contain one prepared payload record and one acceptance marker");
    if (accepted_read.records.size() == 2)
    {
        const auto& payload_record = accepted_read.records[0];
        const auto& accepted_marker = accepted_read.records[1];
        ok &= Require(
            payload_record.object_id == 77 &&
                payload_record.parent_object_id == 9 &&
                payload_record.payload_spool_id == payload_record.sequence &&
                payload_record.payload_offset == 12345 &&
                payload_record.payload_length == 8192 &&
                payload_record.logical_offset == 4096 &&
                payload_record.logical_length == 8192 &&
                payload_record.payload_sha256[0] == 0x5a,
            "Accepted payload record should bind object, generation, spool range, logical range, sequence, and checksum");
        ok &= Require(
            accepted_marker.operation == apfsaccess::rw::WriteAheadLog::OperationKind::TransactionMarker &&
                accepted_marker.state == apfsaccess::rw::WriteAheadLog::RecordState::Accepted &&
                accepted_marker.sequence == first_accepted_sequence,
            "Accepted transaction should end with a durable accepted marker");
    }

    ok &= Require(
        !accepted_tx.MarkCleanedThrough(first_accepted_sequence),
        "Cleanup watermark must not advance before APFS durability");
    ok &= Require(
        !accepted_tx.MarkApfsDurableThrough(first_accepted_sequence + 1),
        "APFS durability watermark must not advance beyond accepted work");
    ok &= Require(
        !accepted_tx.MarkApfsDurableThrough(first_accepted_sequence - 1),
        "APFS durability watermark must target an accepted transaction boundary");
    ok &= Require(
        accepted_tx.MarkApfsDurableThrough(first_accepted_sequence),
        "APFS durability watermark should advance through accepted work");
    ok &= Require(
        !accepted_tx.MarkCleanedThrough(first_accepted_sequence - 1),
        "Cleanup watermark must target an accepted transaction boundary");
    ok &= Require(
        accepted_tx.MarkCleanedThrough(first_accepted_sequence),
        "Cleanup watermark should advance through APFS-durable work");

    ok &= Require(accepted_tx.Begin(), "A second foreground transaction should begin after acceptance");
    payload_mutation.path = L"\\accepted-2.bin";
    payload_mutation.payload_spool_offset = 23456;
    ok &= Require(accepted_tx.RecordMutation(payload_mutation), "Second accepted transaction should record payload mutation");
    ok &= Require(accepted_tx.Accept(), "Second transaction should become durably accepted");
    const auto second_accepted_sequence = accepted_tx.Watermarks().accepted_sequence;
    ok &= Require(
        second_accepted_sequence > first_accepted_sequence &&
            accepted_tx.HasUnappliedAcceptedWork(),
        "A later accepted batch should remain distinguishable from the APFS-durable watermark");

    apfsaccess::rw::TransactionManager recovered_tx(L"DeferredContent");
    recovered_tx.SetVolumeIdentity(L"accepted-test-volume");
    recovered_tx.SetJournalPath(acceptance_journal_path.wstring());
    ok &= Require(recovered_tx.RecoveryStateValid(), "Restart should reconstruct a valid watermark state");
    ok &= Require(
        recovered_tx.Watermarks().accepted_sequence == second_accepted_sequence &&
            recovered_tx.Watermarks().apfs_durable_sequence == first_accepted_sequence &&
            recovered_tx.Watermarks().cleanup_sequence == first_accepted_sequence,
        "Restart should reconstruct accepted, APFS-durable, and cleanup watermarks independently");
    ok &= Require(
        recovered_tx.NextMutationSequence() > second_accepted_sequence,
        "Restart should seed later WAL writes after acceptance and watermark records");

    std::vector<apfsaccess::rw::TransactionManager::AcceptedTransaction> replay_transactions;
    std::string replay_failure;
    ok &= Require(
        recovered_tx.LoadUnappliedAcceptedTransactions(replay_transactions, &replay_failure),
        "Restart should reconstruct complete unapplied accepted transactions");
    ok &= Require(replay_failure.empty(), "Valid accepted transaction reconstruction should not report a failure");
    ok &= Require(replay_transactions.size() == 1, "Only the transaction beyond the APFS-durable watermark should require replay");
    if (replay_transactions.size() == 1)
    {
        ok &= Require(
            replay_transactions[0].accepted_sequence == second_accepted_sequence &&
                replay_transactions[0].mutations.size() == 1 &&
                replay_transactions[0].mutations[0].path_utf8.find("accepted-2.bin") != std::string::npos,
            "Replay reconstruction should bind the accepted marker to its complete prepared mutation set");
    }

    apfsaccess::rw::WriteAheadLog compacted_wal({
        acceptance_journal_path,
        "accepted-test-volume",
        1024 * 1024,
    });
    ok &= Require(
        compacted_wal.Compact(first_accepted_sequence),
        "Accepted WAL fixture should compact cleaned mutations while retaining their transaction boundary");
    apfsaccess::rw::TransactionManager compacted_tx(L"DeferredContent");
    compacted_tx.SetVolumeIdentity(L"accepted-test-volume");
    compacted_tx.SetJournalPath(acceptance_journal_path.wstring());
    ok &= Require(
        compacted_tx.RecoveryStateValid(),
        "Compaction metadata must preserve valid accepted-write watermark recovery");
    replay_transactions.clear();
    replay_failure.clear();
    ok &= Require(
        compacted_tx.LoadUnappliedAcceptedTransactions(replay_transactions, &replay_failure),
        "Compaction metadata must not be interpreted as an out-of-order mutation") &&
        Require(replay_transactions.size() == 1, "Compacted WAL should retain the unapplied accepted transaction") &&
        Require(
            replay_transactions.empty() || replay_transactions[0].accepted_sequence == second_accepted_sequence,
            "Compacted WAL replay should preserve the accepted transaction boundary");

    constexpr std::uint64_t wal_flag_committed = 0x1;
    constexpr std::uint64_t wal_flag_accepted = 0x8;
    const auto invalid_boundary_path = run_root / "invalid-boundary.wal";
    apfsaccess::rw::WriteAheadLog invalid_boundary_wal({
        invalid_boundary_path,
        "invalid-boundary-volume",
        1024 * 1024,
    });
    apfsaccess::rw::WriteAheadLog::Record invalid_mutation{};
    invalid_mutation.volume_identity = "invalid-boundary-volume";
    invalid_mutation.transaction_id = 1;
    invalid_mutation.sequence = 1;
    invalid_mutation.operation = apfsaccess::rw::WriteAheadLog::OperationKind::Write;
    invalid_mutation.state = apfsaccess::rw::WriteAheadLog::RecordState::Prepared;
    apfsaccess::rw::WriteAheadLog::Record invalid_marker{};
    invalid_marker.volume_identity = "invalid-boundary-volume";
    invalid_marker.transaction_id = 1;
    invalid_marker.sequence = 2;
    invalid_marker.operation = apfsaccess::rw::WriteAheadLog::OperationKind::TransactionMarker;
    invalid_marker.state = apfsaccess::rw::WriteAheadLog::RecordState::Accepted;
    invalid_marker.flags = wal_flag_accepted;
    invalid_marker.logical_length = 1;
    apfsaccess::rw::WriteAheadLog::Record invalid_watermark{};
    invalid_watermark.volume_identity = "invalid-boundary-volume";
    invalid_watermark.sequence = 3;
    invalid_watermark.operation = apfsaccess::rw::WriteAheadLog::OperationKind::DurabilityWatermark;
    invalid_watermark.state = apfsaccess::rw::WriteAheadLog::RecordState::Checkpointed;
    invalid_watermark.logical_offset = invalid_mutation.sequence;
    ok &= Require(
        invalid_boundary_wal.AppendBatch({invalid_mutation, invalid_marker, invalid_watermark}),
        "Invalid boundary fixture should persist a checksum-valid WAL");
    apfsaccess::rw::TransactionManager invalid_boundary_tx(L"DeferredContent");
    invalid_boundary_tx.SetVolumeIdentity(L"invalid-boundary-volume");
    invalid_boundary_tx.SetJournalPath(invalid_boundary_path.wstring());
    ok &= Require(
        !invalid_boundary_tx.RecoveryStateValid(),
        "Restart must reject a durability watermark inside an accepted transaction");

    const auto incomplete_path = run_root / "incomplete-accepted.wal";
    apfsaccess::rw::WriteAheadLog incomplete_wal({incomplete_path, "incomplete-volume", 1024 * 1024});
    apfsaccess::rw::WriteAheadLog::Record incomplete_mutation{};
    incomplete_mutation.volume_identity = "incomplete-volume";
    incomplete_mutation.transaction_id = 1;
    incomplete_mutation.sequence = 1;
    incomplete_mutation.operation = apfsaccess::rw::WriteAheadLog::OperationKind::Write;
    incomplete_mutation.state = apfsaccess::rw::WriteAheadLog::RecordState::Prepared;
    apfsaccess::rw::WriteAheadLog::Record incomplete_marker{};
    incomplete_marker.volume_identity = "incomplete-volume";
    incomplete_marker.transaction_id = 1;
    incomplete_marker.sequence = 2;
    incomplete_marker.operation = apfsaccess::rw::WriteAheadLog::OperationKind::TransactionMarker;
    incomplete_marker.state = apfsaccess::rw::WriteAheadLog::RecordState::Accepted;
    incomplete_marker.flags = wal_flag_accepted;
    incomplete_marker.logical_length = 2;
    ok &= Require(
        incomplete_wal.AppendBatch({incomplete_mutation, incomplete_marker}),
        "Incomplete accepted transaction fixture should persist a checksum-valid WAL");
    apfsaccess::rw::TransactionManager incomplete_tx(L"DeferredContent");
    incomplete_tx.SetVolumeIdentity(L"incomplete-volume");
    incomplete_tx.SetJournalPath(incomplete_path.wstring());
    replay_transactions.clear();
    replay_failure.clear();
    ok &= Require(
        !incomplete_tx.LoadUnappliedAcceptedTransactions(replay_transactions, &replay_failure),
        "Accepted marker with a missing mutation must fail closed") &&
        Require(!replay_failure.empty(), "Incomplete accepted transaction should report a replay validation reason");

    const auto make_prepared = [](
        const std::string& identity,
        std::uint64_t transaction_id,
        std::uint64_t sequence)
    {
        apfsaccess::rw::WriteAheadLog::Record record{};
        record.volume_identity = identity;
        record.transaction_id = transaction_id;
        record.sequence = sequence;
        record.operation = apfsaccess::rw::WriteAheadLog::OperationKind::Write;
        record.state = apfsaccess::rw::WriteAheadLog::RecordState::Prepared;
        return record;
    };
    const auto make_marker = [](
        const std::string& identity,
        std::uint64_t transaction_id,
        std::uint64_t sequence,
        apfsaccess::rw::WriteAheadLog::RecordState state,
        std::uint64_t flags,
        std::uint64_t mutation_count)
    {
        apfsaccess::rw::WriteAheadLog::Record record{};
        record.volume_identity = identity;
        record.transaction_id = transaction_id;
        record.sequence = sequence;
        record.operation = apfsaccess::rw::WriteAheadLog::OperationKind::TransactionMarker;
        record.state = state;
        record.flags = flags;
        record.logical_length = mutation_count;
        return record;
    };
    const auto make_watermark = [](
        const std::string& identity,
        std::uint64_t sequence,
        apfsaccess::rw::WriteAheadLog::RecordState state,
        std::uint64_t target_sequence)
    {
        apfsaccess::rw::WriteAheadLog::Record record{};
        record.volume_identity = identity;
        record.sequence = sequence;
        record.operation = apfsaccess::rw::WriteAheadLog::OperationKind::DurabilityWatermark;
        record.state = state;
        record.logical_offset = target_sequence;
        return record;
    };

    const auto require_rejected_wal = [&](
        const std::string& fixture_name,
        const std::string& identity,
        const std::vector<apfsaccess::rw::WriteAheadLog::Record>& records,
        const std::string& rejection_reason)
    {
        const auto path = run_root / (fixture_name + ".wal");
        apfsaccess::rw::WriteAheadLog wal({path, identity, 1024 * 1024});
        if (!Require(wal.AppendBatch(records), fixture_name + " should persist a checksum-valid WAL"))
        {
            return false;
        }

        apfsaccess::rw::TransactionManager recovered(L"DeferredContent");
        recovered.SetVolumeIdentity(std::wstring(identity.begin(), identity.end()));
        recovered.SetJournalPath(path.wstring());
        return Require(!recovered.RecoveryStateValid(), rejection_reason);
    };

    auto unknown_operation = make_prepared("unknown-operation-volume", 1, 1);
    unknown_operation.operation = static_cast<apfsaccess::rw::WriteAheadLog::OperationKind>(99);
    ok &= require_rejected_wal(
        "unknown-operation",
        "unknown-operation-volume",
        {
            unknown_operation,
            make_marker(
                "unknown-operation-volume",
                1,
                2,
                apfsaccess::rw::WriteAheadLog::RecordState::Accepted,
                wal_flag_accepted,
                1),
        },
        "Startup must reject an unsupported prepared WAL operation");

    auto overlapping_first = make_prepared("overlapping-transactions-volume", 1, 1);
    auto overlapping_second = make_prepared("overlapping-transactions-volume", 2, 2);
    overlapping_first.object_id = 77;
    overlapping_second.object_id = 77;
    ok &= require_rejected_wal(
        "overlapping-transactions",
        "overlapping-transactions-volume",
        {
            overlapping_first,
            overlapping_second,
            make_marker(
                "overlapping-transactions-volume",
                2,
                3,
                apfsaccess::rw::WriteAheadLog::RecordState::Accepted,
                wal_flag_accepted,
                1),
            make_marker(
                "overlapping-transactions-volume",
                1,
                4,
                apfsaccess::rw::WriteAheadLog::RecordState::Accepted,
                wal_flag_accepted,
                1),
        },
        "Startup must reject interleaved transactions that reverse same-object replay order");

    constexpr auto exhausted = (std::numeric_limits<std::uint64_t>::max)();
    ok &= require_rejected_wal(
        "exhausted-transaction-id",
        "exhausted-transaction-id-volume",
        {
            make_prepared("exhausted-transaction-id-volume", exhausted, 1),
            make_marker(
                "exhausted-transaction-id-volume",
                exhausted,
                2,
                apfsaccess::rw::WriteAheadLog::RecordState::Accepted,
                wal_flag_accepted,
                1),
        },
        "Startup must reject a WAL transaction id that would wrap recovery seeding");
    ok &= require_rejected_wal(
        "exhausted-sequence",
        "exhausted-sequence-volume",
        {
            make_prepared("exhausted-sequence-volume", 1, exhausted - 1),
            make_marker(
                "exhausted-sequence-volume",
                1,
                exhausted,
                apfsaccess::rw::WriteAheadLog::RecordState::Accepted,
                wal_flag_accepted,
                1),
        },
        "Startup must reject a WAL sequence that would wrap recovery seeding");

    apfsaccess::rw::WriteAheadLog::Record forged_compaction{};
    forged_compaction.volume_identity = "forged-compaction-volume";
    forged_compaction.sequence = 5;
    forged_compaction.operation = apfsaccess::rw::WriteAheadLog::OperationKind::CompactionIndex;
    forged_compaction.state = apfsaccess::rw::WriteAheadLog::RecordState::Cleaned;
    ok &= require_rejected_wal(
        "forged-compaction",
        "forged-compaction-volume",
        {
            make_prepared("forged-compaction-volume", 1, 1),
            make_marker(
                "forged-compaction-volume",
                1,
                5,
                apfsaccess::rw::WriteAheadLog::RecordState::Accepted,
                wal_flag_accepted,
                2),
            make_watermark(
                "forged-compaction-volume",
                6,
                apfsaccess::rw::WriteAheadLog::RecordState::Checkpointed,
                5),
            make_watermark(
                "forged-compaction-volume",
                7,
                apfsaccess::rw::WriteAheadLog::RecordState::Cleaned,
                5),
            forged_compaction,
        },
        "Startup must reject ordinary WAL records below the declared compaction floor");

    const auto duplicate_terminal_path = run_root / "all-clean-duplicate-terminal.wal";
    const std::string duplicate_terminal_identity = "all-clean-duplicate-terminal-volume";
    apfsaccess::rw::WriteAheadLog duplicate_terminal_wal({
        duplicate_terminal_path,
        duplicate_terminal_identity,
        1024 * 1024,
    });
    ok &= Require(
        duplicate_terminal_wal.AppendBatch({
            make_prepared(duplicate_terminal_identity, 1, 1),
            make_marker(
                duplicate_terminal_identity,
                1,
                2,
                apfsaccess::rw::WriteAheadLog::RecordState::Accepted,
                wal_flag_accepted,
                1),
            make_marker(
                duplicate_terminal_identity,
                1,
                3,
                apfsaccess::rw::WriteAheadLog::RecordState::Accepted,
                wal_flag_accepted,
                1),
            make_watermark(
                duplicate_terminal_identity,
                4,
                apfsaccess::rw::WriteAheadLog::RecordState::Checkpointed,
                3),
            make_watermark(
                duplicate_terminal_identity,
                5,
                apfsaccess::rw::WriteAheadLog::RecordState::Cleaned,
                3),
        }),
        "Duplicate-terminal fixture should persist a checksum-valid all-clean WAL");
    apfsaccess::rw::TransactionManager duplicate_terminal_tx(L"DeferredContent");
    duplicate_terminal_tx.SetVolumeIdentity(L"all-clean-duplicate-terminal-volume");
    duplicate_terminal_tx.SetJournalPath(duplicate_terminal_path.wstring());
    ok &= Require(
        !duplicate_terminal_tx.RecoveryStateValid(),
        "Startup must reject an all-clean WAL with duplicate terminal markers");

    const auto accepted_count_path = run_root / "all-clean-accepted-count.wal";
    const std::string accepted_count_identity = "all-clean-accepted-count-volume";
    apfsaccess::rw::WriteAheadLog accepted_count_wal({
        accepted_count_path,
        accepted_count_identity,
        1024 * 1024,
    });
    ok &= Require(
        accepted_count_wal.AppendBatch({
            make_prepared(accepted_count_identity, 1, 1),
            make_marker(
                accepted_count_identity,
                1,
                2,
                apfsaccess::rw::WriteAheadLog::RecordState::Accepted,
                wal_flag_accepted,
                2),
            make_watermark(
                accepted_count_identity,
                3,
                apfsaccess::rw::WriteAheadLog::RecordState::Checkpointed,
                2),
            make_watermark(
                accepted_count_identity,
                4,
                apfsaccess::rw::WriteAheadLog::RecordState::Cleaned,
                2),
        }),
        "Accepted-count fixture should persist a checksum-valid all-clean WAL");
    apfsaccess::rw::TransactionManager accepted_count_tx(L"DeferredContent");
    accepted_count_tx.SetVolumeIdentity(L"all-clean-accepted-count-volume");
    accepted_count_tx.SetJournalPath(accepted_count_path.wstring());
    ok &= Require(
        !accepted_count_tx.RecoveryStateValid(),
        "Startup must reject an all-clean accepted marker with a mismatched prepared count");

    const auto committed_count_path = run_root / "all-clean-committed-count.wal";
    const std::string committed_count_identity = "all-clean-committed-count-volume";
    apfsaccess::rw::WriteAheadLog committed_count_wal({
        committed_count_path,
        committed_count_identity,
        1024 * 1024,
    });
    ok &= Require(
        committed_count_wal.AppendBatch({
            make_prepared(committed_count_identity, 1, 1),
            make_marker(
                committed_count_identity,
                1,
                2,
                apfsaccess::rw::WriteAheadLog::RecordState::Checkpointed,
                wal_flag_committed,
                2),
            make_watermark(
                committed_count_identity,
                3,
                apfsaccess::rw::WriteAheadLog::RecordState::Cleaned,
                2),
        }),
        "Committed-count fixture should persist a checksum-valid all-clean WAL");
    apfsaccess::rw::TransactionManager committed_count_tx(L"Conservative");
    committed_count_tx.SetVolumeIdentity(L"all-clean-committed-count-volume");
    committed_count_tx.SetJournalPath(committed_count_path.wstring());
    ok &= Require(
        !committed_count_tx.RecoveryStateValid(),
        "Startup must reject an all-clean committed marker with a mismatched prepared count");

    const auto out_of_order_path = run_root / "all-clean-out-of-order.wal";
    const std::string out_of_order_identity = "all-clean-out-of-order-volume";
    apfsaccess::rw::WriteAheadLog out_of_order_wal({
        out_of_order_path,
        out_of_order_identity,
        1024 * 1024,
    });
    ok &= Require(
        out_of_order_wal.AppendBatch({
            make_prepared(out_of_order_identity, 1, 2),
            make_marker(
                out_of_order_identity,
                1,
                1,
                apfsaccess::rw::WriteAheadLog::RecordState::Accepted,
                wal_flag_accepted,
                1),
            make_watermark(
                out_of_order_identity,
                3,
                apfsaccess::rw::WriteAheadLog::RecordState::Checkpointed,
                1),
            make_watermark(
                out_of_order_identity,
                4,
                apfsaccess::rw::WriteAheadLog::RecordState::Cleaned,
                1),
        }),
        "Ordering fixture should persist a checksum-valid all-clean WAL");
    apfsaccess::rw::TransactionManager out_of_order_tx(L"DeferredContent");
    out_of_order_tx.SetVolumeIdentity(L"all-clean-out-of-order-volume");
    out_of_order_tx.SetJournalPath(out_of_order_path.wstring());
    ok &= Require(
        !out_of_order_tx.RecoveryStateValid(),
        "Startup must reject an all-clean WAL with out-of-order sequences");

    const auto invalid_flags_path = run_root / "all-clean-invalid-flags.wal";
    const std::string invalid_flags_identity = "all-clean-invalid-flags-volume";
    apfsaccess::rw::WriteAheadLog invalid_flags_wal({
        invalid_flags_path,
        invalid_flags_identity,
        1024 * 1024,
    });
    ok &= Require(
        invalid_flags_wal.AppendBatch({
            make_prepared(invalid_flags_identity, 1, 1),
            make_marker(
                invalid_flags_identity,
                1,
                2,
                apfsaccess::rw::WriteAheadLog::RecordState::Accepted,
                wal_flag_committed,
                1),
            make_watermark(
                invalid_flags_identity,
                3,
                apfsaccess::rw::WriteAheadLog::RecordState::Checkpointed,
                2),
            make_watermark(
                invalid_flags_identity,
                4,
                apfsaccess::rw::WriteAheadLog::RecordState::Cleaned,
                2),
        }),
        "Invalid-flags fixture should persist a checksum-valid all-clean WAL");
    apfsaccess::rw::TransactionManager invalid_flags_tx(L"DeferredContent");
    invalid_flags_tx.SetVolumeIdentity(L"all-clean-invalid-flags-volume");
    invalid_flags_tx.SetJournalPath(invalid_flags_path.wstring());
    ok &= Require(
        !invalid_flags_tx.RecoveryStateValid(),
        "Startup must reject an all-clean accepted marker with invalid flags");
    ok &= Require(
        invalid_flags_tx.JournalAppendHandleOpenCount() == 1,
        "A live degraded owner must retain its opened writer handle and quarantine semantic-invalid WAL evidence");

    const auto unterminated_path = run_root / "unterminated-transaction.wal";
    const std::string unterminated_identity = "unterminated-transaction-volume";
    apfsaccess::rw::WriteAheadLog unterminated_wal({
        unterminated_path,
        unterminated_identity,
        1024 * 1024,
    });
    ok &= Require(
        unterminated_wal.Append(make_prepared(unterminated_identity, 1, 1)),
        "Unterminated transaction fixture should persist a checksum-valid prepared record");
    apfsaccess::rw::TransactionManager unterminated_tx(L"DeferredContent");
    unterminated_tx.SetVolumeIdentity(L"unterminated-transaction-volume");
    unterminated_tx.SetJournalPath(unterminated_path.wstring());
    ok &= Require(
        !unterminated_tx.RecoveryStateValid(),
        "Startup must reject a WAL suffix with prepared records but no terminal marker");

    const auto ambiguous_path = run_root / "ambiguous-accept.wal";
    apfsaccess::rw::TransactionManager ambiguous_tx(L"DeferredContent");
    ambiguous_tx.SetVolumeIdentity(L"ambiguous-accept-volume");
    ambiguous_tx.SetJournalPath(ambiguous_path.wstring());
    ambiguous_tx.SetJournalFaultInjectionHook([](std::string_view stage)
    {
        return stage == "durable-flush";
    });
    apfsaccess::rw::TransactionManager::MutationIntent ambiguous_mutation{};
    ambiguous_mutation.kind = apfsaccess::rw::TransactionManager::MutationKind::Write;
    ambiguous_mutation.path = L"\\ambiguous.bin";
    ambiguous_mutation.length = 4;
    ok &= Require(ambiguous_tx.Begin(), "Ambiguous acceptance transaction should begin");
    ok &= Require(ambiguous_tx.RecordMutation(ambiguous_mutation), "Ambiguous acceptance transaction should buffer mutation");
    ok &= Require(!ambiguous_tx.Accept(), "Ambiguous acceptance must fail closed");
    ok &= Require(
        ambiguous_tx.CurrentState() == apfsaccess::rw::TransactionManager::State::Failed,
        "Ambiguous acceptance must leave the transaction manager failed");
    ok &= Require(
        ambiguous_tx.Watermarks().accepted_sequence == 0,
        "Ambiguous acceptance must not publish an accepted watermark");
    const auto ambiguous_read = apfsaccess::rw::WriteAheadLog::ReadAll(
        ambiguous_path,
        "ambiguous-accept-volume");
    ok &= Require(
        ambiguous_read.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
            ambiguous_read.records.size() == 2,
        "Ambiguous acceptance must retain the prepared record and terminal evidence");
    ok &= Require(
        std::none_of(
            ambiguous_read.records.begin(),
            ambiguous_read.records.end(),
            [](const auto& record)
            {
                return record.operation == apfsaccess::rw::WriteAheadLog::OperationKind::CompactionIndex;
            }),
        "Ambiguous acceptance must not compact before retrying the append");
    ok &= Require(
        ambiguous_tx.JournalAppendHandleOpenCount() == 1,
        "Ambiguous acceptance must not reopen the WAL for an unsafe retry");

    const auto empty_commit_path = run_root / "empty-committed.wal";
    apfsaccess::rw::TransactionManager empty_commit_tx(L"Conservative");
    empty_commit_tx.SetVolumeIdentity(L"empty-committed-volume");
    empty_commit_tx.SetJournalPath(empty_commit_path.wstring());
    ok &= Require(empty_commit_tx.Begin(), "Empty transaction should begin");
    ok &= Require(empty_commit_tx.Commit(), "Empty committed transaction should remain valid");
    apfsaccess::rw::TransactionManager empty_commit_recovery(L"Conservative");
    empty_commit_recovery.SetVolumeIdentity(L"empty-committed-volume");
    empty_commit_recovery.SetJournalPath(empty_commit_path.wstring());
    ok &= Require(
        empty_commit_recovery.RecoveryStateValid(),
        "Startup should preserve valid zero-mutation checkpointed transactions");

    std::filesystem::remove_all(run_root, ec);
    if (!ok)
    {
        return 1;
    }

    std::cout << "[PASS] TransactionManagerTests" << std::endl;
    return 0;
}
