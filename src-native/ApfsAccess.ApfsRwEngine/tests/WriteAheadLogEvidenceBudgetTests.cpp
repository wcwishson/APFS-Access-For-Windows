#include "TransactionManager.h"
#include "WriteAheadLog.h"
#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>
#include <windows.h>
#include <bcrypt.h>

using Wal = apfsaccess::rw::WriteAheadLog;
using Tx = apfsaccess::rw::TransactionManager;
namespace
{
unsigned checks = 0;
void Check(bool value, const char* name)
{
    ++checks;
    if (!value) throw std::runtime_error(name);
    std::cout << "[PASS] " << name << std::endl;
}
struct Handle
{
    HANDLE value;
    ~Handle() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};
std::array<std::uint8_t, 32> Hash(const std::vector<std::byte>& bytes)
{
    std::array<std::uint8_t, 32> digest{};
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
        throw std::runtime_error("hash provider");
    const auto status = BCryptHash(algorithm, nullptr, 0,
        reinterpret_cast<PUCHAR>(const_cast<std::byte*>(bytes.data())),
        static_cast<ULONG>(bytes.size()), digest.data(), static_cast<ULONG>(digest.size()));
    BCryptCloseAlgorithmProvider(algorithm, 0);
    if (status < 0) throw std::runtime_error("hash data");
    return digest;
}
std::vector<std::uint8_t> Bytes(const std::filesystem::path& path)
{
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("read fixture");
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}
void Write(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes)
{
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!output) throw std::runtime_error("write private fixture");
}
struct Snapshot
{
    BY_HANDLE_FILE_INFORMATION info{};
    std::vector<std::uint8_t> bytes;
};
Snapshot Capture(const std::filesystem::path& path)
{
    Handle handle{CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
    Snapshot result;
    if (handle.value == INVALID_HANDLE_VALUE || !GetFileInformationByHandle(handle.value, &result.info))
        throw std::runtime_error("capture fixture identity");
    result.bytes = Bytes(path);
    return result;
}
bool Same(const Snapshot& a, const Snapshot& b)
{
    return a.bytes == b.bytes && a.info.dwVolumeSerialNumber == b.info.dwVolumeSerialNumber &&
        a.info.nFileIndexHigh == b.info.nFileIndexHigh && a.info.nFileIndexLow == b.info.nFileIndexLow &&
        CompareFileTime(&a.info.ftCreationTime, &b.info.ftCreationTime) == 0 &&
        CompareFileTime(&a.info.ftLastWriteTime, &b.info.ftLastWriteTime) == 0;
}
Wal::ReadResult Read(const std::filesystem::path& path, const std::string& identity,
    apfsaccess::rw::WalReadLimits limits, std::uint64_t allocation)
{
    Handle handle{CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
    Check(handle.value != INVALID_HANDLE_VALUE, "read-only existing evidence handle");
    LARGE_INTEGER position{}; position.QuadPart = 7;
    Check(SetFilePointerEx(handle.value, position, nullptr, FILE_BEGIN) != FALSE, "set caller cursor");
    auto result = Wal::ReadAllEvidenceFromHeldHandle(handle.value, identity, limits, allocation);
    LARGE_INTEGER after{}, zero{};
    Check(SetFilePointerEx(handle.value, zero, &after, FILE_CURRENT) && after.QuadPart == 7,
        "all evidence outcomes preserve caller cursor");
    return result;
}
void Exercise(const std::filesystem::path& root)
{
    std::filesystem::create_directories(root);
    const auto path = root / "accepted.wal";
    const auto text = "bounded-evidence-" + std::to_string(GetCurrentProcessId());
    const std::wstring identity(text.begin(), text.end());
    std::uint64_t accepted = 0;
    {
        Tx producer(L"DeferredContent"); std::string error;
        Check(producer.OpenStartupJournal(path.wstring(), identity, error) &&
            producer.MaterializeAbsentStartupJournal(error), "real production original owner");
        Tx::MutationIntent mutation;
        mutation.kind = Tx::MutationKind::Write; mutation.path = L"\\bounded.bin";
        mutation.object_id = 42; mutation.generation = 17;
        mutation.inline_payload.assign(1u << 20, std::byte{0x5a});
        mutation.length = mutation.payload_length = mutation.inline_payload.size();
        mutation.payload_checksum = Hash(mutation.inline_payload);
        for (unsigned i = 0; i != 3; ++i)
        {
            Check(producer.Begin() && producer.RecordMutation(mutation) && producer.Accept(17),
                "genuine accepted inline original transaction");
            accepted = producer.Watermarks().accepted_sequence;
            if (i != 2) Check(producer.MarkApfsDurableThrough(accepted) && producer.MarkCleanedThrough(accepted),
                "genuine original completion markers");
        }
    }
    const auto original = Capture(path);
    const auto history = Wal::ReadAll(path, text);
    Check(history.status == Wal::ReadStatus::Ok && history.records.size() == 10,
        "actual producer emitted ten complete records");
    const auto size = std::filesystem::file_size(path);
    const auto count = history.records.size();
    const std::uint64_t exact = size * 4 + count * (sizeof(Wal::Record) + 4ull);
    const auto complete = Read(path, text, {size, count}, exact);
    Check(complete.status == Wal::ReadStatus::Ok && complete.records.size() == count && !complete.recovered_torn_tail,
        "payload-heavy original fits exact reserved record budget");
    for (const auto status : {
        Read(path, text, {size, count}, exact - 1).status,
        Read(path, text, {size - 1, count}, exact).status,
        Read(path, text, {size, count - 1}, exact).status,
        Read(path, text, {UINT64_MAX, count}, exact).status,
        Read(path, text, {size, SIZE_MAX}, exact).status,
        Read(path, text, {size, count}, UINT64_MAX).status})
        Check(status == Wal::ReadStatus::ResourceLimit, "finite allocation byte and real-record bounds remain strict");
    Check(Read(path, text + "-wrong", {size, count}, exact).status == Wal::ReadStatus::VolumeMismatch,
        "same bytes with substituted volume identity refuse");
    Check(Same(original, Capture(path)), "every bounded read preserves original bytes identity and timestamps");

    {
        auto frame = history.records.front();
        frame.inline_payload.assign(1, std::byte{0x35});
        frame.payload_length = frame.logical_length = frame.inline_payload.size();
        frame.payload_sha256 = Hash(frame.inline_payload);
        const auto overhead = Wal::EncodeForTest(frame).size() - frame.inline_payload.size();
        frame.inline_payload.assign(65530 - overhead, std::byte{0x35});
        frame.payload_length = frame.logical_length = frame.inline_payload.size();
        frame.payload_sha256 = Hash(frame.inline_payload);
        auto bytes = Wal::EncodeForTest(frame);
        Check(bytes.size() == 65530, "official codec places next header across the 64 KiB window");
        frame.sequence = 2;
        const auto tail = Wal::EncodeForTest(frame);
        bytes.insert(bytes.end(), tail.begin(), tail.end());
        const auto split = root / "split-window-header.wal"; Write(split, bytes);
        const auto before = Capture(split);
        const auto allocation = bytes.size() * 4ull + 2 * (sizeof(Wal::Record) + 4ull);
        const auto read = Read(split, text, {bytes.size(), 2}, allocation);
        Check(read.status == Wal::ReadStatus::Ok && read.records.size() == 2 && Same(before, Capture(split)),
            "split-window header reload retains framing cursor and original bytes");
    }

    {
        Wal owner({path, text, 64ull << 20});
        const auto read = owner.ReadStartupEvidence({size, count}, exact);
        const auto generation = owner.ValidatedAppendLeaseGeneration(true);
        Check(read.status == Wal::ReadStatus::Ok && generation && owner.HasExclusiveWriterLease(),
            "exact-budget startup retains real append lease");
        const auto counters = owner.SnapshotCounters();
        auto future = history.records.front(); future.sequence = accepted + 1; future.transaction_id = 4;
        const auto projected_size = size + Wal::EncodeForTest(future).size();
        const auto projected_count = count + 1;
        const std::uint64_t projected = projected_size * 4 + projected_count * (sizeof(Wal::Record) + 4ull);
        Check(owner.EvidenceAppendCapacityAvailable({future}, {projected_size, projected_count}, projected),
            "capacity uses actual retained plus projected records");
        Check(!owner.EvidenceAppendCapacityAvailable({future}, {projected_size, projected_count}, projected - 1) &&
            !owner.EvidenceAppendCapacityAvailable({future}, {projected_size - 1, projected_count}, projected) &&
            !owner.EvidenceAppendCapacityAvailable({future}, {projected_size, projected_count - 1}, projected),
            "projected allocation byte and record limits refuse");
        Check(!owner.EvidenceAppendCapacityAvailable(std::vector<Wal::Record>(9, future),
            {64ull << 20, 1000000}, 256ull << 20), "oversized projected batch still refuses");
        Wal contender({root / "contender.wal", text, 64ull << 20});
        const auto rejected = contender.ReadStartupEvidence({size, count}, exact);
        Check(rejected.status == Wal::ReadStatus::IoError && !contender.HasExclusiveWriterLease() &&
            !std::filesystem::exists(root / "contender.wal"), "same-identity contender cannot create or acquire ownership");
        const auto after = owner.SnapshotCounters();
        Check(owner.ValidatedAppendLeaseGeneration(true) == generation &&
            counters.append_handle_open_count == after.append_handle_open_count &&
            counters.append_handle_flush_count == after.append_handle_flush_count && Same(original, Capture(path)),
            "capacity and competing-owner checks preserve lease counters and complete original");
    }
    {
        Tx reopened(L"DeferredContent"); std::string error;
        std::vector<Tx::AcceptedTransaction> pending;
        Check(reopened.OpenStartupJournal(path.wstring(), identity, error) &&
            reopened.LoadAcceptedTransactionsSinceCleanup(pending, &error) && pending.size() == 1 &&
            pending.front().accepted_sequence == accepted && pending.front().preimage_checkpoint_xid == 17 &&
            pending.front().mutations.size() == 1 && pending.front().mutations.front().inline_payload.size() == (1u << 20),
            "fresh owner recovers exact pending accepted original and preimage");
        Check(Same(original, Capture(path)), "accepted-original recovery performs no append repair or compaction");
    }

    for (unsigned kind = 0; kind != 5; ++kind)
    {
        auto bytes = original.bytes;
        Wal::ReadStatus expected = Wal::ReadStatus::Corrupt;
        if (kind == 0) { bytes.back() ^= 0x40; expected = Wal::ReadStatus::ChecksumMismatch; }
        if (kind == 1) { bytes[4] = 0x7f; expected = Wal::ReadStatus::VersionMismatch; }
        if (kind == 2) { for (unsigned i = 8; i != 12; ++i) bytes[i] = 0xff; }
        if (kind == 3) bytes.pop_back();
        if (kind == 4) { bytes = {0xe4, 'A', 'P', 'F', 'S', 'W', 'A', 'L'}; expected = Wal::ReadStatus::VersionMismatch; }
        const auto wrong = root / ("negative-" + std::to_string(kind) + ".wal"); Write(wrong, bytes);
        const auto before = Capture(wrong);
        const auto refused = Read(wrong, text, {64ull << 20, 1000000}, 256ull << 20);
        Check(refused.status == expected && refused.records.empty() && Same(before, Capture(wrong)),
            "checksum version framing torn-tail and protected-domain controls refuse without repair");
        if (kind == 3)
        {
            const auto legacy = Wal::ReadAll(wrong, text);
            Check(legacy.status == Wal::ReadStatus::Ok && legacy.recovered_torn_tail && Same(before, Capture(wrong)),
                "legacy torn-prefix observation remains unchanged");
        }
    }
    const auto incomplete = root / "prepared-only.wal";
    Write(incomplete, Wal::EncodeForTest(history.records.front()));
    const auto before = Capture(incomplete);
    {
        Tx refused(L"DeferredContent"); std::string error;
        Check(!refused.OpenStartupJournal(incomplete.wstring(), identity, error) && error == "StartupJournalEvidenceInvalid",
            "framing-valid unaccepted transaction still fails semantic startup admission");
    }
    Check(Same(before, Capture(incomplete)), "semantic refusal preserves prepared-only original");
}
}
int wmain(int argc, wchar_t** argv)
{
    try
    {
        if (argc != 2 || !std::filesystem::path(argv[1]).is_absolute() ||
            std::filesystem::path(argv[1]).root_name() != L"D:") return 90;
        Exercise(std::filesystem::path(argv[1]));
        std::cout << "[PASS] Evidence budget checks=" << checks << std::endl;
        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << "[FAIL] " << error.what() << " checks=" << checks << std::endl;
        return 1;
    }
}
