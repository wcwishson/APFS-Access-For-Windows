#include "PayloadSpool.h"

#include <Windows.h>

#include <array>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <future>
#include <iostream>
#include <limits>
#include <span>
#include <string>
#include <shared_mutex>
#include <thread>
#include <vector>

namespace apfsaccess::rw
{
struct PayloadSpoolTestAccess
{
    static std::unique_lock<std::mutex> AcquireMutex(PayloadSpool& spool)
    {
        return spool.AcquireMutex();
    }

    static std::unique_lock<std::shared_mutex> AcquirePayloadIoExclusive(PayloadSpool& spool)
    {
        return std::unique_lock<std::shared_mutex>(spool.payload_io_mutex_);
    }

    static std::unique_lock<std::shared_mutex> TryAcquirePayloadIoExclusive(PayloadSpool& spool)
    {
        return std::unique_lock<std::shared_mutex>(spool.payload_io_mutex_, std::try_to_lock);
    }

    static bool ReplaceAppendHandleWithReadOnly(PayloadSpool& spool)
    {
        auto lock = spool.AcquireMutex();
        if (!spool.CloseAppendStreamLocked())
        {
            return false;
        }

        const auto path = spool.spool_file_.wstring();
        const auto handle = CreateFileW(
            path.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (handle == INVALID_HANDLE_VALUE)
        {
            return false;
        }
        spool.append_stream_handle_ = handle;
        return true;
    }

    static PayloadSpool::Counters SnapshotRaw(PayloadSpool& spool)
    {
        std::lock_guard<std::mutex> lock(spool.mutex_);
        return spool.SnapshotCountersLocked();
    }

    static PayloadSpool::Counters SetMutexWaitStateAndSnapshot(
        PayloadSpool& spool,
        std::uint64_t count,
        std::uint64_t total,
        std::uint64_t maximum,
        const std::array<std::uint64_t, 32>& buckets)
    {
        std::lock_guard<std::mutex> lock(spool.mutex_);
        spool.mutex_wait_count_ = count;
        spool.mutex_wait_microseconds_ = total;
        spool.mutex_wait_max_microseconds_ = maximum;
        spool.mutex_wait_buckets_ = buckets;
        return spool.SnapshotCountersLocked();
    }

    static std::pair<std::size_t, std::size_t> OverlayScratchCapacities(PayloadSpool& spool)
    {
        std::lock_guard<std::mutex> lock(spool.mutex_);
        return {
            spool.overlay_covered_ranges_scratch_.capacity(),
            spool.overlay_oversized_payload_scratch_.capacity(),
        };
    }

    static std::pair<std::size_t, std::size_t> AppendMergeScratchCapacities(PayloadSpool& spool)
    {
        std::lock_guard<std::mutex> lock(spool.mutex_);
        return {
            spool.append_merge_indices_scratch_.capacity(),
            spool.append_merge_payload_scratch_.capacity(),
        };
    }

};
} // namespace apfsaccess::rw

namespace
{
constexpr const char* kVolume = "volume-A";

struct ScopedPerfCounters
{
    explicit ScopedPerfCounters(const char* value)
    {
        (void)_putenv_s("APFSACCESS_PERF_COUNTERS", value);
    }

    ~ScopedPerfCounters()
    {
        (void)_putenv_s("APFSACCESS_PERF_COUNTERS", "");
    }
};

bool Require(bool condition, const char* message)
{
    if (!condition)
    {
        std::cerr << "[FAIL] " << message << std::endl;
        return false;
    }
    return true;
}

std::vector<std::byte> Bytes(std::string_view text)
{
    std::vector<std::byte> bytes;
    bytes.reserve(text.size());
    for (const auto ch : text)
    {
        bytes.push_back(static_cast<std::byte>(static_cast<unsigned char>(ch)));
    }
    return bytes;
}

std::string Text(std::span<const std::byte> bytes)
{
    std::string text;
    text.reserve(bytes.size());
    for (const auto byte : bytes)
    {
        text.push_back(static_cast<char>(byte));
    }
    return text;
}

std::filesystem::path MakeRunRoot()
{
    std::error_code ec;
    const auto unique_id = std::chrono::steady_clock::now().time_since_epoch().count();
    auto root = std::filesystem::temp_directory_path(ec) /
        ("ApfsAccessPayloadSpoolTests_" + std::to_string(unique_id));
    std::filesystem::remove_all(root, ec);
    std::filesystem::create_directories(root, ec);
    return root;
}

bool Append(
    apfsaccess::rw::PayloadSpool& spool,
    std::uint64_t object_id,
    std::uint64_t offset,
    std::string_view text,
    std::uint64_t sequence = 0,
    const char* volume = kVolume)
{
    const auto bytes = Bytes(text);
    return spool.Append({
        volume,
        object_id,
        1,
        offset,
        sequence,
        std::span<const std::byte>(bytes.data(), bytes.size()),
    });
}

bool Overlay(
    const apfsaccess::rw::PayloadSpool& spool,
    std::uint64_t object_id,
    std::uint64_t offset,
    std::string& buffer,
    const char* volume = kVolume)
{
    std::vector<std::byte> bytes = Bytes(buffer);
    std::size_t overlaid = 0;
    if (!spool.OverlayDirtyRanges({
            volume,
            object_id,
            1,
            offset,
            std::span<std::byte>(bytes.data(), bytes.size()),
        }, overlaid))
    {
        return false;
    }
    buffer = Text(bytes);
    return true;
}

bool OverlayWithCoverage(
    const apfsaccess::rw::PayloadSpool& spool,
    std::uint64_t object_id,
    std::uint64_t offset,
    std::string& buffer,
    std::size_t& overlaid,
    const char* volume = kVolume)
{
    std::vector<std::byte> bytes = Bytes(buffer);
    if (!spool.OverlayDirtyRanges({
            volume,
            object_id,
            1,
            offset,
            std::span<std::byte>(bytes.data(), bytes.size()),
        }, overlaid))
    {
        return false;
    }
    buffer = Text(bytes);
    return true;
}

bool TestAppendReturnsAcceptedPayloadReference(const std::filesystem::path& root)
{
    apfsaccess::rw::PayloadSpool spool({ root / "append-reference", kVolume, 1024 * 1024 });
    const auto payload = Bytes("accepted-payload");
    apfsaccess::rw::PayloadSpool::AppendResult result{};
    if (!Require(
            spool.Append({
                kVolume,
                901,
                17,
                4096,
                33,
                std::span<const std::byte>(payload.data(), payload.size()),
            }, &result),
            "append reference should stage payload"))
    {
        return false;
    }

    constexpr std::array<std::uint8_t, 32> expected_sha256{
        0x12, 0xfb, 0x4a, 0x61, 0x21, 0x1c, 0x55, 0xf6,
        0x6e, 0xe0, 0xa2, 0x26, 0xc9, 0x37, 0x69, 0x76,
        0x47, 0x5d, 0xc9, 0x78, 0xf8, 0xa7, 0x9f, 0x27,
        0x64, 0x31, 0x25, 0xee, 0x2d, 0x3b, 0xe0, 0xe4,
    };
    return Require(result.object_id == 901, "append reference should preserve object id") &&
           Require(result.generation == 17, "append reference should preserve generation") &&
           Require(result.logical_offset == 4096, "append reference should preserve logical offset") &&
           Require(result.payload_length == payload.size(), "append reference should preserve payload length") &&
           Require(result.spool_offset == 0, "first append reference should report the physical spool offset") &&
           Require(result.wal_sequence == 33, "append reference should preserve WAL sequence") &&
           Require(result.checksum != 0, "append reference should expose the persisted payload checksum") &&
           Require(result.payload_sha256 == expected_sha256, "append reference should expose the persisted payload SHA-256") &&
           Require(spool.FlushDirtyState(), "append reference should become durable before WAL acceptance");
}

bool TestPersistedRangeRequiresExactWalIdentityAndSha256(const std::filesystem::path& root)
{
    const auto spool_root = root / "persisted-range-reference";
    const auto bytes = Bytes("replay-payload");
    apfsaccess::rw::PayloadSpool::AppendResult appended{};
    {
        apfsaccess::rw::PayloadSpool spool({spool_root, kVolume, 1024 * 1024});
        if (!Require(
                spool.Append({
                    kVolume,
                    902,
                    18,
                    8192,
                    44,
                    std::span<const std::byte>(bytes.data(), bytes.size()),
                }, &appended),
                "Persisted range test should append payload") ||
            !Require(spool.FlushDirtyState(), "Persisted range test should flush payload and index"))
        {
            return false;
        }
    }

    apfsaccess::rw::PayloadSpool reloaded({spool_root, kVolume, 1024 * 1024});
    apfsaccess::rw::PayloadSpool::PersistedRangeReference reference{
        kVolume,
        appended.object_id,
        appended.generation,
        appended.logical_offset,
        appended.payload_length,
        appended.spool_offset,
        appended.wal_sequence,
        appended.payload_sha256,
    };
    std::vector<std::byte> replay_payload;
    if (!Require(reloaded.ReadPersistedRange(reference, replay_payload), "Exact WAL/spool reference should load payload") ||
        !Require(replay_payload == bytes, "Exact WAL/spool reference should preserve payload bytes"))
    {
        return false;
    }

    auto wrong_offset = reference;
    ++wrong_offset.spool_offset;
    auto wrong_hash = reference;
    wrong_hash.payload_sha256[0] ^= 0xff;
    auto missing_range = reference;
    ++missing_range.object_id;
    return Require(!reloaded.ReadPersistedRange(wrong_offset, replay_payload), "Mismatched physical spool offset should fail closed") &&
           Require(!reloaded.ReadPersistedRange(wrong_hash, replay_payload), "Mismatched payload SHA-256 should fail closed") &&
           Require(!reloaded.ReadPersistedRange(missing_range, replay_payload), "Missing WAL-referenced spool range should fail closed");
}

bool TestPayloadOnlyFlushRebuildsMissingIndex(const std::filesystem::path& root)
{
    const auto spool_root = root / "payload-only-index-rebuild";
    const auto payload = Bytes("payload-only-durability");
    apfsaccess::rw::PayloadSpool::AppendResult appended{};
    {
        apfsaccess::rw::PayloadSpool spool({ spool_root, kVolume, 1024 * 1024 });
        if (!Require(
                spool.Append({
                    kVolume,
                    903,
                    19,
                    123,
                    55,
                    std::span<const std::byte>(payload.data(), payload.size()),
                }, &appended),
                "Payload-only recovery fixture should append payload") ||
            !Require(spool.FlushPayloadBytes(), "Payload-only boundary should flush payload bytes") )
        {
            return false;
        }

        const auto counters = spool.SnapshotCounters();
        if (!Require(counters.index_dirty, "Payload-only boundary should leave the advisory index dirty") ||
            !Require(counters.bytes_since_sync == 0 && counters.appends_since_sync == 0,
                "Payload-only boundary should clear payload durability counters") ||
            !Require(!std::filesystem::exists(spool_root / "payload-spool.idx"),
                "Payload-only boundary should not persist the index"))
        {
            return false;
        }
    }

    std::ifstream payload_file(spool_root / "payload-spool.bin", std::ios::binary);
    std::vector<std::byte> durable_payload(payload.size());
    payload_file.read(
        reinterpret_cast<char*>(durable_payload.data()),
        static_cast<std::streamsize>(durable_payload.size()));
    if (!Require(
            payload_file.good() || payload_file.eof(),
            "Payload-only boundary should leave readable payload bytes") ||
        !Require(durable_payload == payload, "Payload-only boundary should preserve payload bytes"))
    {
        return false;
    }
    payload_file.close();

    apfsaccess::rw::PayloadSpool::PersistedRangeReference reference{
        kVolume,
        appended.object_id,
        appended.generation,
        appended.logical_offset,
        appended.payload_length,
        appended.spool_offset,
        appended.wal_sequence,
        appended.payload_sha256,
    };

    {
        apfsaccess::rw::PayloadSpool recovered({ spool_root, kVolume, 1024 * 1024 });
        const auto initial = recovered.SnapshotCounters();
        if (!Require(initial.recovery_required, "Missing index with a durable spool tail should require recovery") ||
            !Require(initial.dirty_range_count == 0, "Missing index should not invent unvalidated ranges"))
        {
            return false;
        }

        std::vector<std::byte> replayed;
        if (!Require(
                !recovered.ReadPersistedRange(reference, replayed),
                "Missing-index spool should remain unreadable until its identity index is rebuilt"))
        {
            return false;
        }
        if (!Require(
                recovered.RebuildIndexFromReferences(
                    std::span<const apfsaccess::rw::PayloadSpool::PersistedRangeReference>(&reference, 1),
                    0),
                "Validated WAL references should rebuild the missing index") ||
            !Require(
                recovered.ReadPersistedRange(reference, replayed),
                "Rebuilt identity index should make the WAL-bound range readable") ||
            !Require(replayed == payload, "Rebuilt identity index should preserve payload bytes"))
        {
            return false;
        }

        const auto rebuilt = recovered.SnapshotCounters();
        if (!Require(!rebuilt.recovery_required, "Rebuilt index should clear recovery state") ||
            !Require(rebuilt.index_dirty, "Rebuilt index should require one durable index persistence" ) ||
            !Require(recovered.FlushDirtyState(), "Rebuilt index should become durable") ||
            !Require(recovered.CleanupThroughSequence(appended.wal_sequence),
                "Rebuilt spool should clean through the WAL boundary"))
        {
            return false;
        }
    }

    apfsaccess::rw::PayloadSpool cleaned({ spool_root, kVolume, 1024 * 1024 });
    const auto counters = cleaned.SnapshotCounters();
    return Require(!counters.recovery_required, "Cleaned rebuilt spool should reload healthy") &&
           Require(counters.dirty_range_count == 0, "Cleaned rebuilt spool should have no ranges") &&
           Require(counters.spool_bytes == 0, "Cleaned rebuilt spool should reclaim payload bytes");
}

bool TestIndexRebuildDiscardsInlineWalRangesAndKeepsLegacyPayload(const std::filesystem::path& root)
{
    const auto spool_root = root / "mixed-inline-index-rebuild";
    apfsaccess::rw::PayloadSpool::AppendResult inline_range{};
    apfsaccess::rw::PayloadSpool::AppendResult legacy_range{};
    {
        apfsaccess::rw::PayloadSpool spool({spool_root, kVolume, 1024 * 1024});
        const auto inline_bytes = Bytes("inline");
        const auto legacy_bytes = Bytes("legacy");
        if (!Require(
                spool.Append({kVolume, 201, 1, 0, 10, inline_bytes}, &inline_range),
                "mixed rebuild should append its inline-backed range") ||
            !Require(
                spool.Append({kVolume, 202, 1, 0, 20, legacy_bytes}, &legacy_range),
                "mixed rebuild should append its legacy range") ||
            !Require(spool.FlushPayloadBytes(), "mixed rebuild payload bytes should become durable"))
        {
            return false;
        }
    }

    std::error_code ec;
    std::filesystem::remove(spool_root / "payload-spool.idx", ec);
    ec.clear();
    apfsaccess::rw::PayloadSpool recovered({spool_root, kVolume, 1024 * 1024});
    const apfsaccess::rw::PayloadSpool::PersistedRangeReference legacy_reference{
        kVolume,
        legacy_range.object_id,
        legacy_range.generation,
        legacy_range.logical_offset,
        legacy_range.payload_length,
        legacy_range.spool_offset,
        legacy_range.wal_sequence,
        legacy_range.payload_sha256,
    };
    const apfsaccess::rw::PayloadSpool::PersistedRangeReference inline_reference{
        kVolume,
        inline_range.object_id,
        inline_range.generation,
        inline_range.logical_offset,
        inline_range.payload_length,
        inline_range.spool_offset,
        inline_range.wal_sequence,
        inline_range.payload_sha256,
    };
    const std::array<apfsaccess::rw::PayloadSpool::PersistedRangeReference, 1> discardable_references{
        inline_reference,
    };
    if (!Require(recovered.RecoveryRequired(), "mixed rebuild should begin recovery-required") ||
        !Require(
            recovered.RebuildIndexFromReferences(
                std::span<const apfsaccess::rw::PayloadSpool::PersistedRangeReference>(&legacy_reference, 1),
                inline_range.wal_sequence,
                discardable_references),
            "mixed rebuild should discard a safe-prefix identity while retaining legacy payload"))
    {
        return false;
    }

    std::vector<std::byte> recovered_payload;
    const auto counters = recovered.SnapshotCounters();
    return Require(counters.dirty_range_count == 1, "mixed rebuild should retain only the legacy range") &&
           Require(
               recovered.ReadPersistedRange(legacy_reference, recovered_payload),
               "mixed rebuild should keep the legacy payload readable") &&
           Require(Text(recovered_payload) == "legacy", "mixed rebuild should preserve legacy payload bytes exactly");
}

bool TestIndexRebuildRejectsUnknownTailDespiteInlineWalRange(const std::filesystem::path& root)
{
    const auto spool_root = root / "inline-rebuild-unknown-tail";
    apfsaccess::rw::PayloadSpool::AppendResult inline_range{};
    apfsaccess::rw::PayloadSpool::AppendResult legacy_range{};
    {
        apfsaccess::rw::PayloadSpool spool({spool_root, kVolume, 1024 * 1024});
        if (!Require(spool.Append({kVolume, 301, 1, 0, 10, Bytes("inline")}, &inline_range),
                "unknown-tail rebuild should append its inline-backed range") ||
            !Require(spool.Append({kVolume, 302, 1, 0, 20, Bytes("legacy")}, &legacy_range),
                "unknown-tail rebuild should append its legacy range") ||
            !Require(Append(spool, 303, 0, "orphan", 30),
                "unknown-tail rebuild should append unreferenced trailing evidence") ||
            !Require(spool.FlushPayloadBytes(),
                "unknown-tail rebuild should make its fixture bytes durable"))
        {
            return false;
        }
    }

    std::error_code ec;
    std::filesystem::remove(spool_root / "payload-spool.idx", ec);
    ec.clear();
    apfsaccess::rw::PayloadSpool recovered({spool_root, kVolume, 1024 * 1024});
    const apfsaccess::rw::PayloadSpool::PersistedRangeReference legacy_reference{
        kVolume,
        legacy_range.object_id,
        legacy_range.generation,
        legacy_range.logical_offset,
        legacy_range.payload_length,
        legacy_range.spool_offset,
        legacy_range.wal_sequence,
        legacy_range.payload_sha256,
    };
    const apfsaccess::rw::PayloadSpool::PersistedRangeReference inline_reference{
        kVolume,
        inline_range.object_id,
        inline_range.generation,
        inline_range.logical_offset,
        inline_range.payload_length,
        inline_range.spool_offset,
        inline_range.wal_sequence,
        inline_range.payload_sha256,
    };
    return Require(recovered.RecoveryRequired(), "unknown-tail rebuild should begin recovery-required") &&
           Require(
               !recovered.RebuildIndexFromReferences(
                   std::span<const apfsaccess::rw::PayloadSpool::PersistedRangeReference>(&legacy_reference, 1),
                   0,
                   std::span<const apfsaccess::rw::PayloadSpool::PersistedRangeReference>(&inline_reference, 1)),
               "an inline WAL range must not excuse unrelated trailing spool evidence");
}

bool TestCoalescingAndPartialReads(const std::filesystem::path& root)
{
    apfsaccess::rw::PayloadSpool spool({ root / "coalesce", kVolume, 1024 * 1024 });
    if (!Require(Append(spool, 10, 0, "abcd", 1), "first append should succeed") ||
        !Require(Append(spool, 10, 4, "ef", 1), "adjacent append should succeed") ||
        !Require(Append(spool, 10, 2, "XYZ", 1), "overlapping append should succeed"))
    {
        return false;
    }

    auto counters = spool.SnapshotCounters();
    if (!Require(counters.dirty_range_count == 1, "adjacent and overlapping writes should coalesce"))
    {
        return false;
    }
    if (!Require(counters.append_merged_count == 2, "adjacent and overlapping small writes should use merge path"))
    {
        return false;
    }
    std::string full = "------";
    if (!Require(Overlay(spool, 10, 0, full), "full overlay should succeed") ||
        !Require(full == "abXYZf", "full overlay should reflect newest dirty bytes"))
    {
        return false;
    }

    std::string partial = "....";
    return Require(Overlay(spool, 10, 1, partial), "partial overlay should succeed") &&
           Require(partial == "bXYZ", "partial overlay should copy the requested slice");
}

bool TestOverlappingWritesReportUniqueCoverage(const std::filesystem::path& root)
{
    apfsaccess::rw::PayloadSpool spool({ root / "overlap-coverage", kVolume, 1024 * 1024 });
    if (!Require(Append(spool, 13, 0, "old!", 1), "overlap coverage first append should succeed") ||
        !Require(Append(spool, 13, 0, "new!", 2), "overlap coverage replacement append should succeed"))
    {
        return false;
    }

    std::size_t overlaid = 0;
    std::string read = "----";
    return Require(OverlayWithCoverage(spool, 13, 0, read, overlaid), "overlap coverage overlay should succeed") &&
           Require(read == "new!", "overlap coverage should return newest dirty bytes") &&
           Require(overlaid == read.size(), "overlap coverage should count unique requested bytes only");
}

bool TestOverlayUsesWalSequenceOrderNotAppendOrder(const std::filesystem::path& root)
{
    apfsaccess::rw::PayloadSpool spool({ root / "overlay-wal-order", kVolume, 1024 * 1024 });
    if (!Require(Append(spool, 14, 0, "new!", 2), "newer-sequence append should succeed") ||
        !Require(Append(spool, 14, 0, "old!", 1), "older-sequence append should succeed"))
    {
        return false;
    }

    std::string read = "----";
    return Require(Overlay(spool, 14, 0, read), "out-of-order WAL overlay should succeed") &&
           Require(read == "new!", "overlay should apply dirty ranges by WAL sequence, not append order");
}

bool TestOverlayUsesSpoolOrderAfterMergedAppend(const std::filesystem::path& root)
{
    apfsaccess::rw::PayloadSpool spool({ root / "overlay-merge-order", kVolume, 1024 * 1024 });
    if (!Require(Append(spool, 15, 0, "abcd", 1), "initial same-sequence append should succeed") ||
        !Require(Append(spool, 15, 8, "ijkl", 1), "later same-sequence append should succeed") ||
        !Require(Append(spool, 15, 2, "CDEF", 1), "merged same-sequence append should succeed"))
    {
        return false;
    }

    std::string read = "------------";
    return Require(Overlay(spool, 15, 0, read), "merged same-sequence overlay should succeed") &&
           Require(read == "abCDEF--ijkl", "overlay should preserve spool order after merge rebuilds lookup");
}

bool TestLargeSequentialWritesStayAppendFriendly(const std::filesystem::path& root)
{
    apfsaccess::rw::PayloadSpool spool({ root / "large-sequential", kVolume, 1024 * 1024 });
    const std::string first(64 * 1024, 'A');
    const std::string second(64 * 1024, 'B');
    if (!Require(Append(spool, 11, 0, first, 1), "first large append should succeed") ||
        !Require(Append(spool, 11, first.size(), second, 2), "second large append should succeed"))
    {
        return false;
    }

    const auto counters = spool.SnapshotCounters();
    if (!Require(counters.dirty_range_count == 2, "large adjacent writes should not be merged by rewriting prior payload"))
    {
        return false;
    }

    std::string boundary = "......";
    return Require(Overlay(spool, 11, first.size() - 3, boundary), "boundary overlay should succeed") &&
           Require(boundary == "AAABBB", "boundary overlay should combine adjacent dirty ranges");
}

bool TestDiscardSequenceKeepsEarlierWrites(const std::filesystem::path& root)
{
    apfsaccess::rw::PayloadSpool spool({ root / "discard-sequence", kVolume, 1024 * 1024 });
    if (!Require(Append(spool, 12, 0, "abcd", 1), "earlier append should succeed") ||
        !Require(Append(spool, 12, 2, "XY", 2), "later overlapping append should succeed"))
    {
        return false;
    }

    if (!Require(spool.DiscardSequence(2), "discarding failed sequence should succeed"))
    {
        return false;
    }

    const auto counters = spool.SnapshotCounters();
    if (!Require(counters.dirty_range_count == 1, "discard should only remove the failed sequence"))
    {
        return false;
    }

    std::string read = "----";
    return Require(Overlay(spool, 12, 0, read), "overlay after discard should succeed") &&
           Require(read == "abcd", "discard should preserve earlier dirty bytes");
}

bool TestChecksumMismatchAndWrongVolume(const std::filesystem::path& root)
{
    apfsaccess::rw::PayloadSpool spool({ root / "corrupt", kVolume, 1024 * 1024 });
    if (!Require(Append(spool, 20, 0, "abcd", 1), "append before corruption should succeed"))
    {
        return false;
    }

    {
        std::fstream file(spool.SpoolFilePath(), std::ios::binary | std::ios::in | std::ios::out);
        if (!Require(file.good(), "spool file should open for corruption"))
        {
            return false;
        }
        char corrupt = 'Z';
        file.seekp(0, std::ios::beg);
        file.write(&corrupt, 1);
    }

    std::string read = "----";
    if (!Require(!Overlay(spool, 20, 0, read), "checksum mismatch should reject overlay"))
    {
        return false;
    }

    return Require(!Append(spool, 20, 4, "ef", 2, "volume-B"), "wrong volume append should be rejected");
}

bool TestCleanupAndQuota(const std::filesystem::path& root)
{
    apfsaccess::rw::PayloadSpool spool({ root / "cleanup", kVolume, 1024 * 1024 });
    if (!Require(Append(spool, 30, 0, "aaaa", 1), "first cleanup append should succeed") ||
        !Require(Append(spool, 31, 0, "bbbb", 5), "second cleanup append should succeed") ||
        !Require(Append(spool, 32, 0, "cccc", 6), "third cleanup append should succeed") ||
        !Require(Append(spool, 33, 0, "dddd", 7), "fourth cleanup append should succeed"))
    {
        return false;
    }

    if (!Require(spool.CleanupThroughSequence(1), "cleanup through first sequence should succeed"))
    {
        return false;
    }
    auto counters = spool.SnapshotCounters();
    if (!Require(counters.dirty_range_count == 3, "cleanup should remove committed ranges") ||
        !Require(counters.spool_bytes == 16, "partial cleanup should retain physical bytes referenced by later WAL records") ||
        !Require(counters.range_payload_read_open_count == 0, "partial cleanup should avoid payload rewrite I/O"))
    {
        return false;
    }

    std::string removed = "----";
    if (!Require(Overlay(spool, 30, 0, removed), "overlay after cleanup should still succeed") ||
        !Require(removed == "----", "cleaned range should no longer overlay"))
    {
        return false;
    }

    std::string kept = "----";
    if (!Require(Overlay(spool, 31, 0, kept), "kept range overlay should succeed") ||
        !Require(kept == "bbbb", "cleanup should keep newer ranges"))
    {
        return false;
    }

    std::string kept_later = "----";
    if (!Require(Overlay(spool, 33, 0, kept_later), "later kept range overlay should succeed") ||
        !Require(kept_later == "dddd", "cleanup should keep all newer ranges"))
    {
        return false;
    }

    if (!Require(spool.CleanupThroughSequence(7), "final cleanup should remove every durable range"))
    {
        return false;
    }
    counters = spool.SnapshotCounters();
    if (!Require(counters.dirty_range_count == 0, "final cleanup should clear the range index") ||
        !Require(counters.spool_bytes == 0, "final cleanup should reclaim the spool after no WAL reference remains"))
    {
        return false;
    }

    apfsaccess::rw::PayloadSpool limited({ root / "quota", kVolume, 4 });
    const std::string oversized = "12345";
    apfsaccess::rw::PayloadSpool::AppendResult rejected{};
    const auto quota_status = limited.AppendWithStatus({
        kVolume,
        40,
        1,
        0,
        1,
        std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(oversized.data()),
            oversized.size()),
    }, &rejected);
    return Require(
        quota_status == apfsaccess::rw::PayloadSpool::AppendStatus::QuotaExceeded,
        "quota should be distinguishable from invalid input and storage failure");
}

bool TestFinalCleanupSkipsRedundantPayloadFlush(const std::filesystem::path& root)
{
    apfsaccess::rw::PayloadSpool spool({root / "cleanup-without-redundant-flush", kVolume, 1024 * 1024});
    if (!Require(Append(spool, 41, 0, "discard-me", 10), "cleanup-without-flush append should succeed"))
    {
        return false;
    }

    const auto before = spool.SnapshotCounters();
    if (!Require(before.bytes_since_sync == 10, "cleanup-without-flush fixture should begin unsynced") ||
        !Require(before.spool_sync_count == 0, "cleanup-without-flush fixture should begin without a device sync") ||
        !Require(spool.CleanupThroughSequence(10), "final cleanup should discard APFS-durable payload bytes"))
    {
        return false;
    }

    const auto after = spool.SnapshotCounters();
    return Require(after.dirty_range_count == 0, "final cleanup should remove the discarded range") &&
           Require(after.spool_bytes == 0, "final cleanup should remove the redundant spool file") &&
           Require(after.spool_sync_count == before.spool_sync_count, "final cleanup must not sync payload bytes immediately before deleting them");
}

bool TestMaxDirtyRangeEndTracksLatestLogicalTail(const std::filesystem::path& root)
{
    apfsaccess::rw::PayloadSpool spool({ root / "dirty-tail", kVolume, 1024 * 1024 });
    if (!Require(Append(spool, 45, 0, "abc", 1), "dirty tail first append should succeed") ||
        !Require(Append(spool, 45, 8, "xy", 2), "dirty tail sparse append should succeed") ||
        !Require(Append(spool, 46, 20, "other", 3), "dirty tail other object append should succeed"))
    {
        return false;
    }

    const auto first_queries = spool.SnapshotCounters().object_lookup_query_count;
    if (!Require(spool.MaxDirtyRangeEnd(kVolume, 45, 1) == 10, "dirty tail should report max end for matching object") ||
        !Require(spool.MaxDirtyRangeEnd(kVolume, 46, 1) == 25, "dirty tail should isolate objects") ||
        !Require(spool.MaxDirtyRangeEnd("volume-B", 45, 1) == 0, "dirty tail should reject wrong volume"))
    {
        return false;
    }

    const auto after_counters = spool.SnapshotCounters();
    return Require(after_counters.object_lookup_query_count == first_queries + 2, "dirty tail query counter should track matching lookups") &&
           Require(after_counters.object_lookup_candidate_count == 0, "dirty tail cache should avoid candidate scans");
}

bool TestOverlayReportsLogicalTailWithOneSpoolLookup(const std::filesystem::path& root)
{
    apfsaccess::rw::PayloadSpool spool({ root / "overlay-logical-tail", kVolume, 1024 * 1024 });
    if (!Require(Append(spool, 47, 12, "tail", 1),
            "combined overlay should stage its dirty tail") ||
        !Require(Append(spool, 47, 2, "head", 2),
            "combined overlay should stage an earlier range"))
    {
        return false;
    }

    std::vector<std::byte> destination = Bytes("----------------");
    std::size_t bytes_overlayed = 0;
    std::uint64_t logical_end = 0;
    const auto before = spool.SnapshotCounters();
    if (!Require(
            spool.OverlayDirtyRangesWithLogicalEnd(
                {
                    kVolume,
                    47,
                    1,
                    0,
                    std::span<std::byte>(destination.data(), destination.size()),
                },
                bytes_overlayed,
                logical_end),
            "combined overlay should succeed") ||
        !Require(Text(destination) == "--head------tail",
            "combined overlay should preserve both dirty ranges") ||
        !Require(bytes_overlayed == 8,
            "combined overlay should report the covered destination bytes") ||
        !Require(logical_end == 16,
            "combined overlay should report the object's logical dirty tail"))
    {
        return false;
    }

    const auto after = spool.SnapshotCounters();
    return Require(
               after.object_lookup_query_count == before.object_lookup_query_count + 1,
               "combined overlay should perform one indexed object lookup") &&
           Require(
               after.object_lookup_candidate_count == before.object_lookup_candidate_count + 2,
               "combined overlay should account for the object's two candidate ranges") &&
           Require(
               after.object_lookup_index_probe_count == before.object_lookup_index_probe_count + 1,
               "combined overlay should probe the object index only once");
}

bool TestIndexReloadAndCorruption(const std::filesystem::path& root)
{
    const auto spool_root = root / "reload";
    {
        apfsaccess::rw::PayloadSpool spool({ spool_root, kVolume, 1024 * 1024 });
        if (!Require(Append(spool, 50, 0, "persist", 7), "reload append should succeed"))
        {
            return false;
        }
        if (!Require(spool.FlushDirtyState(), "reload append should flush dirty spool index"))
        {
            return false;
        }
    }

    {
        apfsaccess::rw::PayloadSpool reloaded({ spool_root, kVolume, 1024 * 1024 });
        auto counters = reloaded.SnapshotCounters();
        if (!Require(counters.recovery_required, "reloaded dirty spool should require recovery before RW resumes") ||
            !Require(counters.dirty_range_count == 1, "reloaded clean spool should keep dirty range index"))
        {
            return false;
        }

        std::string read = "-------";
        if (!Require(!Overlay(reloaded, 50, 0, read), "reloaded dirty spool should not serve bytes while recovery is required") ||
            !Require(reloaded.CleanupThroughSequence(7), "reloaded cleanup should succeed"))
        {
            return false;
        }
    }

    {
        apfsaccess::rw::PayloadSpool cleaned({ spool_root, kVolume, 1024 * 1024 });
        const auto counters = cleaned.SnapshotCounters();
        if (!Require(!counters.recovery_required, "cleaned reload should not require recovery") ||
            !Require(counters.dirty_range_count == 0, "cleaned reload should have no dirty ranges"))
        {
            return false;
        }
    }

    const auto corrupt_root = root / "corrupt-index";
    {
        apfsaccess::rw::PayloadSpool spool({ corrupt_root, kVolume, 1024 * 1024 });
        if (!Require(Append(spool, 51, 0, "dirty", 8), "corrupt-index append should succeed"))
        {
            return false;
        }
        if (!Require(spool.FlushDirtyState(), "corrupt-index append should flush dirty spool index"))
        {
            return false;
        }
    }
    {
        std::fstream index(corrupt_root / "payload-spool.idx", std::ios::binary | std::ios::in | std::ios::out);
        if (!Require(index.good(), "spool index should open for corruption"))
        {
            return false;
        }
        char corrupt = 'X';
        index.seekp(0, std::ios::beg);
        index.write(&corrupt, 1);
    }
    apfsaccess::rw::PayloadSpool corrupted({ corrupt_root, kVolume, 1024 * 1024 });
    return Require(corrupted.SnapshotCounters().recovery_required, "corrupt index should require recovery");
}

bool TestAppendBatchesIndexPersistenceUntilFlush(const std::filesystem::path& root)
{
    const auto spool_root = root / "batched-index";
    apfsaccess::rw::PayloadSpool spool({
        spool_root,
        kVolume,
        1024 * 1024,
        1024 * 1024,
        1024,
    });
    if (!Require(Append(spool, 60, 0, "abcd", 1), "batched index first append should succeed") ||
        !Require(Append(spool, 60, 4, "efgh", 2), "batched index second append should succeed"))
    {
        return false;
    }

    auto counters = spool.SnapshotCounters();
    if (!Require(counters.dirty_range_count == 2, "batched index should track dirty ranges in memory") ||
        !Require(counters.index_dirty, "batched index should remain dirty before explicit flush") ||
        !Require(counters.appends_since_sync == 2, "batched index should count unflushed appends") ||
        !Require(!std::filesystem::exists(spool_root / "payload-spool.idx"), "batched index should not rewrite index per append"))
    {
        return false;
    }

    if (!Require(spool.FlushDirtyState(), "batched index explicit flush should succeed") ||
        !Require(std::filesystem::exists(spool_root / "payload-spool.idx"), "batched index flush should persist index"))
    {
        return false;
    }
    counters = spool.SnapshotCounters();
    if (!Require(!counters.index_dirty, "batched index flush should clear dirty flag") ||
        !Require(counters.appends_since_sync == 0, "batched index flush should reset append counter") ||
        !Require(counters.bytes_since_sync == 0, "batched index flush should reset byte counter") ||
        !Require(counters.durable_flush_count == 1, "batched index explicit flush should record one durable flush") ||
        !Require(counters.spool_sync_count == 1, "batched index explicit flush should sync the payload once") ||
        !Require(counters.spool_sync_handle_flush_count == 1, "batched index explicit flush should use the live append handle") ||
        !Require(counters.spool_sync_reopen_count == 0, "batched index explicit flush should not reopen the payload file") ||
        !Require(counters.index_persist_count == 1, "batched index explicit flush should persist the index once") ||
        !Require(counters.index_persist_bytes > 0, "batched index telemetry should report persisted index bytes") ||
        !Require(
            counters.index_persist_microseconds <= counters.durable_flush_microseconds,
            "index persistence time should be included in the total durable flush time"))
    {
        return false;
    }

    apfsaccess::rw::PayloadSpool reloaded({
        spool_root,
        kVolume,
        1024 * 1024,
        1024 * 1024,
        1024,
    });
    const auto reloaded_counters = reloaded.SnapshotCounters();
    return Require(reloaded_counters.recovery_required, "flushed dirty spool should require recovery on reload") &&
           Require(reloaded_counters.dirty_range_count == 2, "flushed dirty spool should reload both dirty ranges");
}

bool TestManySequentialAppendsAvoidPerAppendIndexRewrite(const std::filesystem::path& root)
{
    const auto spool_root = root / "many-sequential";
    apfsaccess::rw::PayloadSpool spool({
        spool_root,
        kVolume,
        16ull * 1024ull * 1024ull,
        16ull * 1024ull * 1024ull,
        8192,
    });

    const std::string chunk(4096, 'S');
    for (std::uint64_t index = 0; index < 2048; ++index)
    {
        if (!Require(
                Append(spool, 70, index * chunk.size(), chunk, index + 1),
                "many sequential append should succeed"))
        {
            return false;
        }
    }

    auto counters = spool.SnapshotCounters();
    if (!Require(counters.dirty_range_count == 2048, "many sequential appends should stay append-only ranges") ||
        !Require(counters.index_dirty, "many sequential appends should defer index persistence") ||
        !Require(counters.appends_since_sync == 2048, "many sequential appends should not flush before threshold") ||
        !Require(counters.append_direct_count == 2048, "many sequential appends should use direct append fast path") ||
        !Require(counters.append_merged_count == 0, "many sequential appends should not allocate merged payloads") ||
        !Require(counters.append_stream_open_count == 1, "many sequential appends should reuse one append stream") ||
        !Require(counters.append_stream_flush_count == 0, "many sequential appends should not flush the append stream per append") ||
        !Require(counters.append_rollback_snapshot_count == 0, "many sequential appends should not snapshot the whole spool index per append") ||
        !Require(!std::filesystem::exists(spool_root / "payload-spool.idx"), "many sequential appends should not write index per append"))
    {
        return false;
    }

    std::string boundary(8, '-');
    if (!Require(
            Overlay(spool, 70, (1024 * chunk.size()) - 4, boundary),
            "many sequential boundary overlay should succeed") ||
        !Require(boundary == std::string(8, 'S'), "many sequential boundary overlay should read adjacent ranges"))
    {
        return false;
    }
    counters = spool.SnapshotCounters();
    if (!Require(counters.append_stream_flush_count == 0, "many sequential overlay should not flush the append stream") ||
        !Require(counters.range_payload_read_open_count == 1, "many sequential overlay should reuse one payload read stream"))
    {
        return false;
    }

    return Require(spool.FlushDirtyState(), "many sequential explicit flush should succeed") &&
           Require(std::filesystem::exists(spool_root / "payload-spool.idx"), "many sequential flush should persist index");
}

bool TestNonOverlappingOverlayAvoidsPayloadOpen(const std::filesystem::path& root)
{
    apfsaccess::rw::PayloadSpool spool({ root / "non-overlap-overlay", kVolume, 1024 * 1024 });
    if (!Require(Append(spool, 73, 1024, "data", 1), "non-overlap append should succeed"))
    {
        return false;
    }

    std::string read = "----";
    if (!Require(Overlay(spool, 73, 0, read), "non-overlap overlay should succeed") ||
        !Require(read == "----", "non-overlap overlay should not alter the buffer"))
    {
        return false;
    }

    const auto counters = spool.SnapshotCounters();
    return Require(counters.range_payload_read_open_count == 0, "non-overlap overlay should not open the payload spool");
}

bool TestCoverageQueryUsesRangeIndexOnly(const std::filesystem::path& root)
{
    apfsaccess::rw::PayloadSpool spool({ root / "coverage-index-only", kVolume, 1024 * 1024 });
    if (!Require(Append(spool, 74, 8, "BBBB", 2), "coverage index later append should succeed") ||
        !Require(Append(spool, 74, 0, "AAAA", 1), "coverage index earlier append should succeed") ||
        !Require(Append(spool, 74, 4, "CCCC", 3), "coverage index middle append should succeed"))
    {
        return false;
    }

    auto counters = spool.SnapshotCounters();
    const auto before_payload_opens = counters.range_payload_read_open_count;
    if (!Require(
            spool.IsRangeFullyCovered(kVolume, 74, 1, 0, 12),
            "coverage index should merge out-of-order dirty ranges") ||
        !Require(
            !spool.IsRangeFullyCovered(kVolume, 74, 1, 0, 13),
            "coverage index should reject partial coverage") ||
        !Require(
            !spool.IsRangeFullyCovered("volume-B", 74, 1, 0, 12),
            "coverage index should reject wrong volume"))
    {
        return false;
    }

    counters = spool.SnapshotCounters();
    if (!Require(
            counters.range_payload_read_open_count == before_payload_opens,
            "coverage index query should not open or read the payload spool"))
    {
        return false;
    }

    std::string read = "------------";
    return Require(Overlay(spool, 74, 0, read), "coverage index actual overlay should still read payload bytes") &&
           Require(read == "AAAACCCCBBBB", "coverage index overlay should preserve WAL order semantics");
}

bool TestManyRangeCoverageUsesSortedUnion(const std::filesystem::path& root)
{
    apfsaccess::rw::PayloadSpool spool({ root / "many-range-coverage-sorted-union", kVolume, 1024 * 1024 });
    constexpr std::size_t kRangeCount = 128;
    for (std::size_t index = 0; index < kRangeCount; ++index)
    {
        const std::string payload(1, static_cast<char>('a' + (index % 26)));
        if (!Require(
                Append(spool, 76, static_cast<std::uint64_t>(index), payload, static_cast<std::uint64_t>(index + 1)),
                "many-range coverage append should succeed"))
        {
            return false;
        }
    }

    std::vector<std::byte> read(kRangeCount, std::byte{0});
    std::size_t overlaid = 0;
    if (!Require(
            spool.ReadFullyCoveredRange({ kVolume, 76, 1, 0, read }, overlaid),
            "many-range coverage should report complete coverage") ||
        !Require(overlaid == kRangeCount, "many-range coverage should count each byte once"))
    {
        return false;
    }

    for (std::size_t index = 0; index < kRangeCount; ++index)
    {
        if (!Require(
                read[index] == static_cast<std::byte>('a' + (index % 26)),
                "many-range coverage should preserve WAL-order payload bytes"))
        {
            return false;
        }
    }
    return true;
}

bool TestCoverageQueryDefersChecksumValidationToRead(const std::filesystem::path& root)
{
    apfsaccess::rw::PayloadSpool spool({ root / "coverage-corrupt", kVolume, 1024 * 1024 });
    if (!Require(Append(spool, 75, 0, "abcd", 1), "coverage corrupt append should succeed"))
    {
        return false;
    }

    {
        std::fstream file(spool.SpoolFilePath(), std::ios::binary | std::ios::in | std::ios::out);
        if (!Require(file.good(), "coverage corrupt spool file should open for corruption"))
        {
            return false;
        }
        char corrupt = 'Z';
        file.seekp(0, std::ios::beg);
        file.write(&corrupt, 1);
    }

    std::string read = "----";
    return Require(
               spool.IsRangeFullyCovered(kVolume, 75, 1, 0, 4),
               "coverage corrupt query should use index-only coverage") &&
           Require(
               !Overlay(spool, 75, 0, read),
               "coverage corrupt actual overlay should still reject checksum mismatch");
}

bool TestRepeatedDirtyReadsReusePayloadReadHandle(const std::filesystem::path& root)
{
    apfsaccess::rw::PayloadSpool spool({ root / "reused-payload-read-handle", kVolume, 1024 * 1024 });
    if (!Require(Append(spool, 751, 0, "payload", 1), "reused read handle append should succeed") ||
        !Require(spool.FlushPayloadBytes(), "reused read handle fixture should persist payload bytes"))
    {
        return false;
    }

    std::string first = "-------";
    std::string second = "-------";
    if (!Require(Overlay(spool, 751, 0, first), "reused read handle first overlay should succeed") ||
        !Require(Overlay(spool, 751, 0, second), "reused read handle second overlay should succeed") ||
        !Require(first == "payload" && second == "payload", "reused read handle overlays should preserve bytes"))
    {
        return false;
    }

    const auto counters = spool.SnapshotCounters();
    return Require(
               counters.range_payload_read_open_count == 1,
               "repeated dirty reads should reuse one payload read handle") &&
           Require(
               counters.range_payload_positional_read_count == 2,
               "repeated dirty reads should use positional payload reads");
}

bool TestPartialDirtyReadsReuseValidatedPayloadCache(const std::filesystem::path& root)
{
    apfsaccess::rw::PayloadSpool spool({ root / "validated-partial-read-cache", kVolume, 8 * 1024 * 1024 });
    std::vector<std::byte> expected(256 * 1024);
    for (std::size_t index = 0; index < expected.size(); ++index)
    {
        expected[index] = static_cast<std::byte>(index & 0xffu);
    }
    if (!Require(
            spool.Append({
                kVolume,
                758,
                1,
                0,
                1,
                std::span<const std::byte>(expected.data(), expected.size()),
            }),
            "validated partial-read cache fixture should append") ||
        !Require(spool.FlushPayloadBytes(),
            "validated partial-read cache fixture should persist payload bytes"))
    {
        return false;
    }

    const auto read_range = [&spool](
        std::uint64_t offset,
        std::size_t bytes,
        std::vector<std::byte>& output)
    {
        output.assign(bytes, std::byte{0});
        std::size_t overlaid = 0;
        return spool.OverlayDirtyRanges({
                   kVolume,
                   758,
                   1,
                   offset,
                   std::span<std::byte>(output.data(), output.size()),
               }, overlaid) &&
            overlaid == bytes;
    };

    std::vector<std::byte> first;
    std::vector<std::byte> second;
    if (!Require(read_range(64 * 1024, 4096, first), "first partial dirty read should succeed") ||
        !Require(read_range(64 * 1024, 4096, second), "cached partial dirty read should succeed") ||
        !Require(
            std::equal(
                expected.begin() + 64 * 1024,
                expected.begin() + 64 * 1024 + 4096,
                first.begin()) &&
                first == second,
            "cached partial dirty read should preserve exact bytes"))
    {
        return false;
    }

    const auto after_cache = spool.SnapshotCounters();
    if (!Require(
            after_cache.range_payload_positional_read_count == 1,
            "first partial dirty read should perform one positional read") ||
        !Require(
            after_cache.range_payload_cache_fill_count == 1,
            "first partial dirty read should fill one validated cache entry") ||
        !Require(
            after_cache.range_payload_cache_hit_count == 1,
            "second partial dirty read should hit the validated cache"))
    {
        return false;
    }

    std::vector<std::byte> replacement(4096, static_cast<std::byte>('N'));
    if (!Require(
            spool.Append({
                kVolume,
                758,
                1,
                128 * 1024,
                2,
                std::span<const std::byte>(replacement.data(), replacement.size()),
            }),
            "validated partial-read cache replacement should append"))
    {
        return false;
    }

    std::vector<std::byte> replacement_read;
    if (!Require(
            read_range(128 * 1024, 2048, replacement_read),
            "replacement partial dirty read should succeed") ||
        !Require(
            std::all_of(
                replacement_read.begin(),
                replacement_read.end(),
                [](std::byte value)
                {
                    return value == static_cast<std::byte>('N');
                }),
            "replacement partial dirty read should apply the newest WAL range"))
    {
        return false;
    }

    const auto before_cleanup = spool.SnapshotCounters();
    if (!Require(
            spool.CleanupThroughSequence(1),
            "validated partial-read cache cleanup should succeed"))
    {
        return false;
    }

    std::vector<std::byte> after_cleanup_read;
    if (!Require(
            read_range(128 * 1024, 2048, after_cleanup_read),
            "post-cleanup partial dirty read should succeed") ||
        !Require(
            after_cleanup_read == replacement_read,
            "post-cleanup partial dirty read should preserve exact bytes"))
    {
        return false;
    }

    const auto after_cleanup = spool.SnapshotCounters();
    return Require(
               after_cleanup.range_payload_positional_read_count ==
                   before_cleanup.range_payload_positional_read_count + 1,
               "cleanup should invalidate the partial-read cache") &&
           Require(
               after_cleanup.range_payload_cache_hit_count == before_cleanup.range_payload_cache_hit_count,
               "post-cleanup cache miss should not be reported as a cache hit");
}

bool TestConcurrentSingleRangeReadsPreserveBytes(const std::filesystem::path& root)
{
    apfsaccess::rw::PayloadSpool spool({ root / "concurrent-single-range-reads", kVolume, 8 * 1024 * 1024 });
    constexpr std::size_t range_count = 64;
    constexpr std::size_t range_bytes = 4096;
    constexpr std::size_t reader_count = 12;
    constexpr std::size_t reads_per_reader = 48;
    std::vector<std::string> expected_ranges;
    expected_ranges.reserve(range_count);
    for (std::size_t range_index = 0; range_index < range_count; ++range_index)
    {
        std::string expected(range_bytes, '\0');
        for (std::size_t byte_index = 0; byte_index < expected.size(); ++byte_index)
        {
            expected[byte_index] = static_cast<char>((range_index * 37 + byte_index * 13) & 0xffu);
        }
        if (!Require(
                Append(
                    spool,
                    7521,
                    static_cast<std::uint64_t>(range_index * range_bytes),
                    expected,
                    static_cast<std::uint64_t>(range_index + 1)),
                "concurrent single-range fixture append should succeed"))
        {
            return false;
        }
        expected_ranges.push_back(std::move(expected));
    }
    if (!Require(spool.FlushPayloadBytes(),
            "concurrent single-range fixture should persist payload bytes"))
    {
        return false;
    }

    std::promise<void> start_promise;
    const auto start = start_promise.get_future().share();
    std::vector<std::future<bool>> readers;
    readers.reserve(reader_count);
    for (std::size_t reader_index = 0; reader_index < reader_count; ++reader_index)
    {
        readers.push_back(std::async(std::launch::async, [&spool, &expected_ranges, start, reader_index]()
        {
            start.wait();
            for (std::size_t read_index = 0; read_index < reads_per_reader; ++read_index)
            {
                const auto range_index =
                    (reader_index * 17 + read_index * 29 + (read_index / 3)) % range_count;
                std::string actual(range_bytes, '\0');
                if (!Overlay(
                        spool,
                        7521,
                        static_cast<std::uint64_t>(range_index * range_bytes),
                        actual) ||
                    actual != expected_ranges[range_index])
                {
                    return false;
                }
                std::this_thread::yield();
            }
            return true;
        }));
    }

    start_promise.set_value();

    for (auto& reader : readers)
    {
        if (!Require(reader.get(), "concurrent single-range reads should preserve every byte"))
        {
            return false;
        }
    }

    const auto counters = spool.SnapshotCounters();
    return Require(
               counters.range_payload_read_open_count == 1,
               "concurrent single-range reads should share one reader handle") &&
           Require(
               counters.range_payload_positional_read_count == reader_count * reads_per_reader,
               "concurrent single-range reads should account for each positional read");
}

bool TestConcurrentMultiRangeReadsReleaseSpoolMutexDuringPayloadIo(const std::filesystem::path& root)
{
    apfsaccess::rw::PayloadSpool spool({ root / "concurrent-multi-range-reads", kVolume, 1024 * 1024 });
    const std::string left(64 * 1024, 'L');
    const std::string right(64 * 1024, 'R');
    if (!Require(
            Append(spool, 7522, 0, left, 1),
            "concurrent multi-range first append should succeed") ||
        !Require(
            Append(spool, 7522, left.size(), right, 2),
            "concurrent multi-range second append should succeed") ||
        !Require(spool.FlushPayloadBytes(),
            "concurrent multi-range fixture should persist payload bytes"))
    {
        return false;
    }

    auto payload_io_lock = apfsaccess::rw::PayloadSpoolTestAccess::AcquirePayloadIoExclusive(spool);
    auto worker = std::async(std::launch::async, [&spool, &left, &right]()
    {
        std::string actual(left.size() + right.size(), '.');
        std::size_t bytes_overlayed = 0;
        const auto ok = spool.OverlayDirtyRanges({
            kVolume,
            7522,
            1,
            0,
            std::span<std::byte>(
                reinterpret_cast<std::byte*>(actual.data()),
                actual.size()),
        }, bytes_overlayed);
        return ok && bytes_overlayed == actual.size() && actual == left + right;
    });

    bool reached_payload_io = false;
    for (std::size_t attempt = 0; attempt < 200; ++attempt)
    {
        if (apfsaccess::rw::PayloadSpoolTestAccess::SnapshotRaw(spool).range_payload_positional_read_count >= 2)
        {
            reached_payload_io = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    if (!Require(
            reached_payload_io,
            "concurrent multi-range read should snapshot before waiting for payload I/O"))
    {
        payload_io_lock.unlock();
        (void)worker.get();
        return false;
    }

    auto metadata_probe = std::async(std::launch::async, [&spool]()
    {
        return spool.SnapshotCounters();
    });
    const auto metadata_probe_completed =
        metadata_probe.wait_for(std::chrono::milliseconds(250)) == std::future_status::ready;
    payload_io_lock.unlock();
    const auto worker_completed = worker.get();
    const auto counters = metadata_probe.get();
    return Require(
               metadata_probe_completed,
               "multi-range payload I/O should not hold the spool metadata mutex") &&
           Require(
               worker_completed,
               "concurrent multi-range reads should preserve bytes after I/O resumes") &&
           Require(
               counters.range_payload_positional_read_count == 2,
               "concurrent multi-range read should account for both positional reads");
}

bool TestOverlayUsesDirectDestinationReads(const std::filesystem::path& root)
{
    apfsaccess::rw::PayloadSpool spool({ root / "direct-destination-overlay", kVolume, 1024 * 1024 });
    if (!Require(Append(spool, 752, 4, "direct", 1), "direct destination single range append should succeed") ||
        !Require(spool.FlushPayloadBytes(), "direct destination single range should persist payload bytes"))
    {
        return false;
    }

    std::string single = "----......----";
    if (!Require(Overlay(spool, 752, 0, single), "direct destination single range overlay should succeed") ||
        !Require(single == "----direct----", "direct destination single range overlay should preserve bytes"))
    {
        return false;
    }

    if (!Require(Append(spool, 753, 0, "left", 1), "direct destination first multi-range append should succeed") ||
        !Require(Append(spool, 753, 100, "right", 2), "direct destination second multi-range append should succeed") ||
        !Require(spool.FlushPayloadBytes(), "direct destination multi-range should persist payload bytes"))
    {
        return false;
    }

    std::string multiple(105, '.');
    if (!Require(Overlay(spool, 753, 0, multiple), "direct destination multi-range overlay should succeed") ||
        !Require(multiple.substr(0, 4) == "left", "direct destination first range should preserve bytes") ||
        !Require(multiple.substr(100, 5) == "right", "direct destination second range should preserve bytes"))
    {
        return false;
    }

    const auto counters = spool.SnapshotCounters();
    return Require(
               counters.overlay_direct_destination_read_count == 3,
               "fully contained dirty ranges should read directly into the destination") &&
           Require(
               counters.range_payload_positional_read_count == 3,
               "direct destination overlays should retain positional reads");
}

bool TestOverlayScratchStoragePersistsAcrossCalls(const std::filesystem::path& root)
{
    apfsaccess::rw::PayloadSpool spool({ root / "overlay-scratch-storage", kVolume, 2 * 1024 * 1024 });
    for (std::uint64_t index = 0; index < 32; ++index)
    {
        if (!Require(
                Append(spool, 755, index * 8, "data", index + 1),
                "overlay scratch coverage fixture append should succeed"))
        {
            return false;
        }
    }

    std::string covered(32 * 8, '.');
    if (!Require(
            Overlay(spool, 755, 0, covered),
            "overlay scratch coverage fixture should overlay successfully") ||
        !Require(
            covered.substr(0, 4) == "data" && covered.substr(8, 4) == "data" &&
                covered.substr(31 * 8, 4) == "data",
            "overlay scratch coverage fixture should preserve all dirty bytes"))
    {
        return false;
    }

    const auto coverage_capacity =
        apfsaccess::rw::PayloadSpoolTestAccess::OverlayScratchCapacities(spool).first;
    if (!Require(
            coverage_capacity >= 32,
            "overlay coverage storage should retain capacity for repeated range lookups"))
    {
        return false;
    }

    const std::string oversized_payload(300 * 1024, 'P');
    const auto oversized_capacity_before =
        apfsaccess::rw::PayloadSpoolTestAccess::OverlayScratchCapacities(spool).second;
    if (!Require(
            Append(spool, 756, 0, oversized_payload, 100),
            "overlay scratch oversized fixture append should succeed"))
    {
        return false;
    }

    std::string oversized_read(4096, '.');
    if (!Require(
            Overlay(spool, 756, 0, oversized_read),
            "overlay scratch oversized fixture should overlay successfully") ||
        !Require(
            oversized_read == std::string(4096, 'P'),
            "overlay scratch oversized fixture should preserve payload bytes"))
    {
        return false;
    }

    const auto capacities_after_oversized =
        apfsaccess::rw::PayloadSpoolTestAccess::OverlayScratchCapacities(spool);
    return Require(
               capacities_after_oversized.first >= coverage_capacity,
               "overlay coverage storage should remain reusable after oversized payload reads") &&
           Require(
               capacities_after_oversized.second == oversized_capacity_before,
               "unlocked single-range overlays should not mutate shared oversized scratch");
}

bool TestAppendMergeScratchStoragePersistsAcrossCalls(const std::filesystem::path& root)
{
    apfsaccess::rw::PayloadSpool spool({ root / "append-merge-scratch-storage", kVolume, 2 * 1024 * 1024 });
    if (!Require(
            Append(spool, 757, 0, "first", 1),
            "append merge scratch fixture first append should succeed") ||
        !Require(
            Append(spool, 757, 5, "second", 1),
            "append merge scratch fixture adjacent append should succeed") ||
        !Require(
            Append(spool, 757, 4, "merge", 1),
            "append merge scratch fixture overlapping append should succeed"))
    {
        return false;
    }

    const auto first_capacities =
        apfsaccess::rw::PayloadSpoolTestAccess::AppendMergeScratchCapacities(spool);
    if (!Require(first_capacities.first >= 1, "append merge index scratch should retain capacity") ||
        !Require(first_capacities.second >= 10, "append merge payload scratch should retain merged capacity"))
    {
        return false;
    }

    if (!Require(
            Append(spool, 757, 10, "tail", 1),
            "append merge scratch fixture repeated append should succeed"))
    {
        return false;
    }
    const auto second_capacities =
        apfsaccess::rw::PayloadSpoolTestAccess::AppendMergeScratchCapacities(spool);
    return Require(
        second_capacities.first >= first_capacities.first &&
            second_capacities.second >= first_capacities.second,
        "append merge scratch capacity should be reusable across calls");
}

bool TestReadFullyCoveredRangeCombinesCoverageAndRead(const std::filesystem::path& root)
{
    apfsaccess::rw::PayloadSpool spool({ root / "combined-covered-read", kVolume, 1024 * 1024 });
    if (!Require(Append(spool, 754, 8, "payload", 1), "combined covered read append should succeed"))
    {
        return false;
    }

    auto full_payload = Bytes("payload");
    std::size_t bytes_overlayed = 0;
    if (!Require(
            spool.ReadFullyCoveredRange({
                kVolume,
                754,
                1,
                8,
                std::span<std::byte>(full_payload.data(), full_payload.size()),
            }, bytes_overlayed),
            "combined covered read should succeed") ||
        !Require(Text(full_payload) == "payload", "combined covered read should preserve bytes") ||
        !Require(bytes_overlayed == full_payload.size(), "combined covered read should report all bytes"))
    {
        return false;
    }

    const auto before_partial = spool.SnapshotCounters();
    auto partial_payload = Bytes("----");
    bytes_overlayed = 0;
    if (!Require(
            !spool.ReadFullyCoveredRange({
                kVolume,
                754,
                1,
                0,
                std::span<std::byte>(partial_payload.data(), partial_payload.size()),
            }, bytes_overlayed),
            "combined covered read should reject partial coverage") ||
        !Require(Text(partial_payload) == "----", "partial covered read should not modify the destination"))
    {
        return false;
    }

    const auto after_partial = spool.SnapshotCounters();
    return Require(
               after_partial.range_payload_read_open_count == before_partial.range_payload_read_open_count,
               "partial covered read should not open the payload spool") &&
           Require(
               after_partial.range_payload_positional_read_count == before_partial.range_payload_positional_read_count,
               "partial covered read should not read payload bytes");
}

bool TestOverlayPastDirtyTailAvoidsPayloadOpen(const std::filesystem::path& root)
{
    apfsaccess::rw::PayloadSpool spool({ root / "overlay-past-tail", kVolume, 1024 * 1024 });
    if (!Require(Append(spool, 76, 0, "abcd", 1), "overlay past tail append should succeed"))
    {
        return false;
    }

    const auto before = spool.SnapshotCounters();
    std::string read = "----";
    if (!Require(Overlay(spool, 76, 4, read), "overlay past tail should succeed as a no-op"))
    {
        return false;
    }

    const auto after = spool.SnapshotCounters();
    return Require(read == "----", "overlay past tail should not change the buffer") &&
           Require(after.range_payload_read_open_count == before.range_payload_read_open_count, "overlay past tail should not open payload reads") &&
           Require(after.object_lookup_candidate_count == before.object_lookup_candidate_count, "overlay past tail should not scan range candidates");
}

bool TestThresholdFlushFailureRollsBackLastAppend(const std::filesystem::path& root)
{
    const auto spool_root = root / "flush-failure-rollback";
    apfsaccess::rw::PayloadSpool spool({
        spool_root,
        kVolume,
        1024 * 1024,
        8,
        2,
    });

    if (!Require(Append(spool, 71, 0, "aaaa", 1), "flush rollback first append should succeed"))
    {
        return false;
    }
    std::error_code ec;
    std::filesystem::create_directories(spool_root / "payload-spool.idx.tmp", ec);
    if (!Require(!ec, "flush rollback test should create blocking temp-index directory"))
    {
        return false;
    }
    if (!Require(!Append(spool, 72, 0, "bbbb", 2), "threshold flush failure should reject the triggering append"))
    {
        return false;
    }

    auto counters = spool.SnapshotCounters();
    if (!Require(counters.append_rollback_snapshot_count == 1, "flush failure should take one rollback snapshot") ||
        !Require(counters.dirty_range_count == 1, "flush failure rollback should restore prior dirty range set") ||
        !Require(counters.appends_since_sync == 1, "flush failure rollback should restore unflushed append count"))
    {
        return false;
    }

    std::string first = "----";
    std::string second = "----";
    if (!Require(Overlay(spool, 71, 0, first), "flush rollback first object should remain readable") ||
        !Require(first == "aaaa", "flush rollback should keep first object payload") ||
        !Require(Overlay(spool, 72, 0, second), "flush rollback removed object overlay should succeed") ||
        !Require(second == "----", "flush rollback should remove failed append from memory indexes"))
    {
        return false;
    }

    std::filesystem::remove_all(spool_root / "payload-spool.idx.tmp", ec);
    return Require(spool.FlushDirtyState(), "flush rollback should flush after removing the artificial failure");
}

bool TestThresholdFlushFailureRollsBackMergedRanges(const std::filesystem::path& root)
{
    const auto spool_root = root / "flush-failure-merged-rollback";
    apfsaccess::rw::PayloadSpool spool({
        spool_root,
        kVolume,
        1024 * 1024,
        8ull * 1024ull * 1024ull,
        3,
    });

    if (!Require(Append(spool, 73, 0, "aaaa", 9), "merged rollback first append should succeed") ||
        !Require(Append(spool, 73, 8, "bbbb", 9), "merged rollback second append should succeed"))
    {
        return false;
    }

    std::error_code ec;
    std::filesystem::create_directories(spool_root / "payload-spool.idx.tmp", ec);
    if (!Require(!ec, "merged rollback test should create blocking temp-index directory"))
    {
        return false;
    }
    if (!Require(!Append(spool, 73, 4, "cccc", 9), "merged threshold flush failure should reject the bridging append"))
    {
        return false;
    }

    const auto counters = spool.SnapshotCounters();
    if (!Require(counters.append_rollback_snapshot_count == 1, "merged flush failure should take one rollback guard") ||
        !Require(counters.dirty_range_count == 2, "merged flush failure should restore both original ranges") ||
        !Require(counters.appends_since_sync == 2, "merged flush failure should restore the unflushed append count"))
    {
        return false;
    }

    std::string first = "----";
    std::string second = "----";
    std::string bridge = "----";
    if (!Require(Overlay(spool, 73, 0, first), "merged rollback first range should remain readable") ||
        !Require(first == "aaaa", "merged rollback should preserve the first range payload") ||
        !Require(Overlay(spool, 73, 8, second), "merged rollback second range should remain readable") ||
        !Require(second == "bbbb", "merged rollback should preserve the second range payload") ||
        !Require(Overlay(spool, 73, 4, bridge), "merged rollback bridge read should succeed") ||
        !Require(bridge == "----", "merged rollback should remove the failed bridge payload"))
    {
        return false;
    }

    std::filesystem::remove_all(spool_root / "payload-spool.idx.tmp", ec);
    return Require(spool.FlushDirtyState(), "merged rollback should flush after removing the artificial failure");
}

bool TestManyObjectReadsUseObjectLookup(const std::filesystem::path& root)
{
    const auto spool_root = root / "many-objects";
    apfsaccess::rw::PayloadSpool spool({
        spool_root,
        kVolume,
        16ull * 1024ull * 1024ull,
        16ull * 1024ull * 1024ull,
        8192,
    });

    constexpr std::uint64_t object_count = 2048;
    for (std::uint64_t index = 0; index < object_count; ++index)
    {
        if (!Require(
                Append(spool, 1000 + index, 16, "data", index + 1),
                "many-object append should succeed"))
        {
            return false;
        }
    }

    auto counters = spool.SnapshotCounters();
    if (!Require(counters.dirty_range_count == object_count, "many-object test should keep every dirty range") ||
        !Require(counters.dirty_object_count == object_count, "many-object test should index every dirty object"))
    {
        return false;
    }

    const auto before_queries = counters.object_lookup_query_count;
    const auto before_candidates = counters.object_lookup_candidate_count;
    if (!Require(
            spool.MaxDirtyRangeEnd(kVolume, 1000 + (object_count / 2), 1) == 20,
            "many-object dirty tail should find only the matching object"))
    {
        return false;
    }

    std::string read = "----";
    if (!Require(
            Overlay(spool, 1000 + (object_count / 2), 16, read),
            "many-object overlay should succeed") ||
        !Require(read == "data", "many-object overlay should return matching object bytes"))
    {
        return false;
    }

    counters = spool.SnapshotCounters();
    return Require(
               counters.object_lookup_query_count == before_queries + 2,
               "many-object lookup query counter should track tail and overlay lookups") &&
           Require(
               counters.object_lookup_candidate_count == before_candidates + 1,
               "many-object lookup should examine one candidate on the overlay lookup");
}

bool TestOrphanedSpoolBytesRequireRecovery(const std::filesystem::path& root)
{
    const auto spool_root = root / "orphaned-spool";
    {
        apfsaccess::rw::PayloadSpool spool({
            spool_root,
            kVolume,
            1024 * 1024,
            1024 * 1024,
            1024,
        });
        if (!Require(Append(spool, 61, 0, "abcd", 1), "orphaned spool append should succeed"))
        {
            return false;
        }
    }

    apfsaccess::rw::PayloadSpool reloaded({
        spool_root,
        kVolume,
        1024 * 1024,
        1024 * 1024,
        1024,
    });
    const auto counters = reloaded.SnapshotCounters();
    return Require(counters.recovery_required, "orphaned spool bytes should require recovery") &&
           Require(counters.spool_bytes == 4, "orphaned spool bytes should be reported for diagnostics");
}

bool TestUnindexedPayloadRecoveryRequiresEmptyWalProof(const std::filesystem::path& root)
{
    const auto spool_root = root / "unindexed-payload-resolution";
    {
        apfsaccess::rw::PayloadSpool spool({spool_root, kVolume, 1024 * 1024});
        if (!Require(Append(spool, 62, 0, "orphan", 1), "unindexed recovery fixture should append payload"))
        {
            return false;
        }
    }

    apfsaccess::rw::PayloadSpool recovered({spool_root, kVolume, 1024 * 1024});
    const auto before = recovered.SnapshotCounters();
    if (!Require(
            before.recovery_required && before.dirty_range_count == 0 && before.spool_bytes == 6,
            "unindexed recovery fixture should expose only orphan payload bytes") ||
        !Require(
            !recovered.ResolveUnindexedPayloadRecovery(false),
            "unindexed payload must be retained without valid empty-WAL proof"))
    {
        return false;
    }

    const auto retained = recovered.SnapshotCounters();
    if (!Require(
            retained.recovery_required && retained.spool_bytes == before.spool_bytes,
            "failed empty-WAL proof should retain recovery evidence") ||
        !Require(
            recovered.ResolveUnindexedPayloadRecovery(true),
            "valid empty-WAL proof should resolve unindexed payload bytes"))
    {
        return false;
    }

    const auto after = recovered.SnapshotCounters();
    return Require(!after.recovery_required, "resolved unindexed payload should clear recovery state") &&
           Require(after.dirty_range_count == 0 && after.spool_bytes == 0, "resolved unindexed payload should remove orphan bytes");
}

bool TestCorruptIndexCannotUseUnindexedPayloadRecovery(const std::filesystem::path& root)
{
    const auto spool_root = root / "corrupt-index-unindexed-resolution";
    {
        apfsaccess::rw::PayloadSpool spool({spool_root, kVolume, 1024 * 1024});
        if (!Require(Append(spool, 63, 0, "indexed", 1), "corrupt-index fixture should append payload") ||
            !Require(spool.FlushDirtyState(), "corrupt-index fixture should persist its index"))
        {
            return false;
        }
    }

    const auto index_path = spool_root / "payload-spool.idx";
    std::error_code ec;
    const auto index_size = std::filesystem::file_size(index_path, ec);
    if (!Require(!ec && index_size > 1, "corrupt-index fixture should create a non-empty index"))
    {
        return false;
    }
    std::filesystem::resize_file(index_path, index_size - 1, ec);
    if (!Require(!ec, "corrupt-index fixture should truncate the persisted index"))
    {
        return false;
    }

    apfsaccess::rw::PayloadSpool corrupted({spool_root, kVolume, 1024 * 1024});
    const auto before = corrupted.SnapshotCounters();
    if (!Require(before.recovery_required && before.spool_bytes == 7, "corrupt index should require recovery") ||
        !Require(
            !corrupted.ResolveUnindexedPayloadRecovery(true),
            "empty-WAL proof must not discard payload behind a corrupt index"))
    {
        return false;
    }

    const auto after = corrupted.SnapshotCounters();
    return Require(after.recovery_required, "corrupt-index recovery should remain fail closed") &&
           Require(after.spool_bytes == before.spool_bytes, "corrupt-index recovery should preserve payload evidence");
}

bool TestOldestDirtyAgeTracksOldestRangeIncrementally(const std::filesystem::path& root)
{
    apfsaccess::rw::PayloadSpool spool({ root / "oldest-dirty-age", kVolume, 1024 * 1024 });
    if (!Require(Append(spool, 80, 0, "ab", 1), "oldest age first append should succeed"))
    {
        return false;
    }

    const auto first_counters = spool.SnapshotCounters();
    if (!Require(first_counters.oldest_dirty_age_ms <= 1000, "oldest age should start near zero"))
    {
        return false;
    }

    if (!Require(Append(spool, 80, 2, "cd", 2), "oldest age second append should succeed"))
    {
        return false;
    }

    const auto second_counters = spool.SnapshotCounters();
    if (!Require(second_counters.dirty_range_count == 2, "oldest age test should keep both dirty ranges") ||
        !Require(second_counters.oldest_dirty_age_ms >= first_counters.oldest_dirty_age_ms, "oldest age should not move backward with a newer append"))
    {
        return false;
    }

    if (!Require(spool.CleanupThroughSequence(2), "oldest age cleanup should succeed"))
    {
        return false;
    }

    const auto cleaned_counters = spool.SnapshotCounters();
    return Require(cleaned_counters.dirty_range_count == 0, "cleanup should clear all dirty ranges") &&
           Require(cleaned_counters.oldest_dirty_age_ms == 0, "cleanup should clear the oldest dirty age");
}

bool TestCleanupClearsDirtyTailCache(const std::filesystem::path& root)
{
    apfsaccess::rw::PayloadSpool spool({ root / "cleanup-dirty-tail-cache", kVolume, 1024 * 1024 });
    if (!Require(Append(spool, 81, 4, "abcd", 1), "cleanup cache append should succeed"))
    {
        return false;
    }

    if (!Require(spool.MaxDirtyRangeEnd(kVolume, 81, 1) == 8, "cleanup cache should report the dirty tail before cleanup"))
    {
        return false;
    }
    const auto before_candidates = spool.SnapshotCounters().object_lookup_candidate_count;

    if (!Require(spool.CleanupThroughSequence(1), "cleanup cache cleanup should succeed"))
    {
        return false;
    }

    std::string read = "----";
    return Require(spool.MaxDirtyRangeEnd(kVolume, 81, 1) == 0, "cleanup cache should clear the dirty tail index") &&
           Require(Overlay(spool, 81, 4, read), "cleanup cache overlay past tail should still succeed") &&
           Require(read == "----", "cleanup cache overlay past tail should remain a no-op") &&
           Require(spool.SnapshotCounters().object_lookup_candidate_count == before_candidates, "cleanup cache should not scan candidates after cleanup");
}

bool TestCleanupNoOpAvoidsSpoolRewrite(const std::filesystem::path& root)
{
    apfsaccess::rw::PayloadSpool spool({ root / "cleanup-no-op", kVolume, 1024 * 1024 });
    if (!Require(Append(spool, 83, 0, "abcd", 5), "cleanup no-op first append should succeed") ||
        !Require(Append(spool, 84, 0, "wxyz", 6), "cleanup no-op second append should succeed"))
    {
        return false;
    }

    const auto before_cleanup = spool.SnapshotCounters();
    if (!Require(spool.CleanupThroughSequence(1), "cleanup below oldest sequence should succeed as a no-op"))
    {
        return false;
    }
    const auto after_cleanup = spool.SnapshotCounters();
    if (!Require(after_cleanup.dirty_range_count == before_cleanup.dirty_range_count, "cleanup no-op should keep dirty ranges") ||
        !Require(after_cleanup.spool_bytes == before_cleanup.spool_bytes, "cleanup no-op should keep spool bytes") ||
        !Require(
            after_cleanup.range_payload_read_open_count == before_cleanup.range_payload_read_open_count,
            "cleanup no-op should avoid rewriting live ranges"))
    {
        return false;
    }

    if (!Require(spool.DiscardSequence(99), "discard of missing sequence should succeed as a no-op"))
    {
        return false;
    }
    const auto after_discard = spool.SnapshotCounters();
    return Require(after_discard.dirty_range_count == after_cleanup.dirty_range_count, "discard no-op should keep dirty ranges") &&
           Require(after_discard.spool_bytes == after_cleanup.spool_bytes, "discard no-op should keep spool bytes") &&
           Require(
               after_discard.range_payload_read_open_count == after_cleanup.range_payload_read_open_count,
               "discard no-op should avoid rewriting live ranges");
}

bool TestCleanupPersistsOnlySurvivingIndexState(const std::filesystem::path& root)
{
    const auto spool_root = root / "cleanup-surviving-index-only";
    apfsaccess::rw::PayloadSpool spool({spool_root, kVolume, 1024 * 1024});
    if (!Require(Append(spool, 86, 0, "old", 10), "Cleanup survivor old append should succeed") ||
        !Require(spool.FlushPayloadBytes(), "Cleanup survivor old payload should become durable") ||
        !Require(Append(spool, 87, 0, "live", 20), "Cleanup survivor live append should succeed") ||
        !Require(spool.FlushPayloadBytes(), "Cleanup survivor live payload should become durable"))
    {
        return false;
    }

    const auto before = spool.SnapshotCounters();
    if (!Require(before.index_dirty, "Cleanup survivor fixture should have a deferred dirty index") ||
        !Require(before.index_persist_count == 0, "Cleanup survivor fixture should not persist its pre-cleanup index"))
    {
        return false;
    }

    if (!Require(spool.CleanupThroughSequence(10), "Cleanup should remove only the durable old range"))
    {
        return false;
    }
    const auto after = spool.SnapshotCounters();
    if (!Require(after.dirty_range_count == 1, "Cleanup should retain the later range") ||
        !Require(after.index_persist_count == 1, "Cleanup should persist only the surviving index state") ||
        !Require(!after.index_dirty, "Cleanup should leave the surviving index durable"))
    {
        return false;
    }

    apfsaccess::rw::PayloadSpool reloaded({spool_root, kVolume, 1024 * 1024});
    const auto reloaded_counters = reloaded.SnapshotCounters();
    return Require(reloaded_counters.recovery_required, "Surviving accepted range should require replay after reload") &&
           Require(reloaded_counters.dirty_range_count == 1, "Reload should preserve only the surviving range") &&
           Require(reloaded.CleanupThroughSequence(20), "Reloaded surviving range should clean successfully");
}

bool TestCleanupReportsBlockedSpoolDeletion(const std::filesystem::path& root)
{
    const auto spool_root = root / "cleanup-blocked-delete";
    apfsaccess::rw::PayloadSpool spool({spool_root, kVolume, 1024 * 1024});
    if (!Require(Append(spool, 88, 0, "blocked", 30), "Blocked-delete append should succeed") ||
        !Require(spool.FlushPayloadBytes(), "Blocked-delete payload should become durable"))
    {
        return false;
    }

    std::ifstream blocker(spool.SpoolFilePath(), std::ios::binary);
    if (!Require(blocker.good(), "Blocked-delete fixture should hold the spool file open") ||
        !Require(!spool.CleanupThroughSequence(30), "Cleanup must report a blocked spool deletion") ||
        !Require(spool.SnapshotCounters().dirty_range_count == 1,
            "Failed cleanup must retain the dirty range for retry"))
    {
        return false;
    }

    blocker.close();
    if (!Require(spool.CleanupThroughSequence(30), "Cleanup should succeed after the blocking handle closes"))
    {
        return false;
    }

    apfsaccess::rw::PayloadSpool reloaded({spool_root, kVolume, 1024 * 1024});
    const auto counters = reloaded.SnapshotCounters();
    return Require(!counters.recovery_required, "Successful cleanup retry should reload healthy") &&
           Require(counters.dirty_range_count == 0, "Successful cleanup retry should leave no dirty ranges") &&
           Require(counters.spool_bytes == 0, "Successful cleanup retry should remove spool bytes");
}

bool TestCleanupBlocksPayloadRemovalWhenIndexRemovalFails(const std::filesystem::path& root)
{
    const auto spool_root = root / "cleanup-index-removal-order";
    apfsaccess::rw::PayloadSpool spool({spool_root, kVolume, 1024 * 1024});
    if (!Require(Append(spool, 89, 0, "retain", 31), "Index-order append should succeed") ||
        !Require(spool.FlushPayloadBytes(), "Index-order payload should become durable"))
    {
        return false;
    }

    std::error_code ec;
    std::filesystem::create_directories(spool_root / "payload-spool.idx", ec);
    if (!Require(!ec, "Index-order test should create an index blocker") )
    {
        return false;
    }
    std::ofstream blocker(spool_root / "payload-spool.idx" / "blocker", std::ios::binary);
    if (!Require(blocker.good(), "Index-order test should create a non-empty index blocker") ||
        !Require(!spool.CleanupThroughSequence(31), "Cleanup must fail when index removal is blocked") ||
        !Require(std::filesystem::exists(spool.SpoolFilePath()),
            "Cleanup must retain payload bytes when index removal fails") ||
        !Require(spool.SnapshotCounters().dirty_range_count == 1,
            "Failed index removal must retain the dirty range for retry"))
    {
        blocker.close();
        std::filesystem::remove_all(spool_root / "payload-spool.idx", ec);
        return false;
    }
    blocker.close();
    std::filesystem::remove_all(spool_root / "payload-spool.idx", ec);
    if (!Require(!ec, "Index-order test should remove the blocker before retry") ||
        !Require(spool.CleanupThroughSequence(31), "Cleanup should succeed after the index blocker is removed"))
    {
        return false;
    }

    return Require(!std::filesystem::exists(spool.SpoolFilePath()),
        "Successful index-order cleanup should finally remove payload bytes");
}

bool TestCleanupPreservesWalOffsetsForLaterRanges(const std::filesystem::path& root)
{
    apfsaccess::rw::PayloadSpool spool({root / "cleanup-preserves-wal-offsets", kVolume, 1024 * 1024});
    const auto first_payload = Bytes("first");
    const auto second_payload = Bytes("second");
    apfsaccess::rw::PayloadSpool::AppendResult first{};
    apfsaccess::rw::PayloadSpool::AppendResult second{};
    if (!Require(spool.Append({kVolume, 850, 1, 0, 10, first_payload}, &first), "Offset cleanup first append should succeed") ||
        !Require(spool.Append({kVolume, 851, 1, 0, 20, second_payload}, &second), "Offset cleanup second append should succeed") ||
        !Require(spool.FlushDirtyState(), "Offset cleanup fixture should become durable") ||
        !Require(spool.CleanupThroughSequence(10), "Offset cleanup should remove only the earlier sequence"))
    {
        return false;
    }

    apfsaccess::rw::PayloadSpool::PersistedRangeReference reference{
        kVolume,
        second.object_id,
        second.generation,
        second.logical_offset,
        second.payload_length,
        second.spool_offset,
        second.wal_sequence,
        second.payload_sha256,
    };
    std::vector<std::byte> replay_payload;
    return Require(
               spool.ReadPersistedRange(reference, replay_payload),
               "Cleaning an earlier sequence must preserve later WAL physical offsets") &&
           Require(replay_payload == second_payload, "Later accepted payload should remain byte-identical after earlier cleanup");
}

bool TestCleanupNoOpAvoidsSequenceScan(const std::filesystem::path& root)
{
    apfsaccess::rw::PayloadSpool spool({ root / "cleanup-no-op-sequence-scan", kVolume, 1024 * 1024 });
    for (std::uint64_t index = 0; index < 128; ++index)
    {
        if (!Require(
                Append(spool, 9000 + index, 0, "data", 1000 + index),
                "cleanup sequence-scan setup append should succeed"))
        {
            return false;
        }
    }

    const auto before_cleanup = spool.SnapshotCounters();
    if (!Require(spool.CleanupThroughSequence(1), "cleanup below minimum sequence should succeed as a no-op"))
    {
        return false;
    }

    const auto after_cleanup = spool.SnapshotCounters();
    return Require(
        after_cleanup.cleanup_sequence_probe_count == before_cleanup.cleanup_sequence_probe_count,
        "cleanup below minimum sequence should avoid scanning dirty WAL sequences");
}

bool TestDirtyTailCacheKeepsZeroOffsetRanges(const std::filesystem::path& root)
{
    apfsaccess::rw::PayloadSpool spool({ root / "zero-offset-dirty-tail-cache", kVolume, 1024 * 1024 });
    if (!Require(Append(spool, 82, 0, "abcd", 1), "zero-offset dirty tail append should succeed"))
    {
        return false;
    }

    const auto before = spool.SnapshotCounters();
    if (!Require(spool.MaxDirtyRangeEnd(kVolume, 82, 1) == 4, "zero-offset dirty tail should report the true end"))
    {
        return false;
    }

    const auto after = spool.SnapshotCounters();
    return Require(after.object_lookup_candidate_count == before.object_lookup_candidate_count, "zero-offset dirty tail cache should avoid scans");
}

struct ScopedIndexDeltaDisable
{
    std::string previous;
    bool had_previous = false;

    ScopedIndexDeltaDisable()
    {
        char* value = nullptr;
        std::size_t value_size = 0;
        if (_dupenv_s(&value, &value_size, "APFSACCESS_DISABLE_INDEX_DELTA") == 0 && value)
        {
            previous = value;
            had_previous = true;
        }
        if (value)
        {
            std::free(value);
        }
        _putenv_s("APFSACCESS_DISABLE_INDEX_DELTA", "1");
    }

    ~ScopedIndexDeltaDisable()
    {
        _putenv_s(
            "APFSACCESS_DISABLE_INDEX_DELTA",
            had_previous ? previous.c_str() : "");
    }
};

bool TestIndexJournalUsesAppendFramesAndReloads(const std::filesystem::path& root)
{
    const auto spool_root = root / "index-journal-frames";
    {
        apfsaccess::rw::PayloadSpool spool({
            spool_root,
            kVolume,
            1024 * 1024,
            1024 * 1024,
            1024,
        });
        if (!Require(Append(spool, 110, 0, "first", 1), "journal first append should succeed") ||
            !Require(spool.FlushDirtyState(), "journal first flush should succeed"))
        {
            return false;
        }

        auto counters = spool.SnapshotCounters();
        if (!Require(counters.index_journal_frame_count == 1, "journal first flush should write one frame") ||
            !Require(counters.index_journal_snapshot_count == 1, "journal first flush should write a snapshot") ||
            !Require(counters.index_journal_append_count == 0, "journal first flush should not write an append frame"))
        {
            return false;
        }

        if (!Require(Append(spool, 111, 0, "second", 2), "journal second append should succeed") ||
            !Require(spool.FlushDirtyState(), "journal second flush should succeed"))
        {
            return false;
        }
        counters = spool.SnapshotCounters();
        if (!Require(counters.index_journal_frame_count == 2, "journal second flush should add one frame") ||
            !Require(counters.index_journal_snapshot_count == 1, "direct append should keep the original snapshot") ||
            !Require(counters.index_journal_append_count == 1, "direct append should use one append frame") ||
            !Require(counters.index_journal_handle_open_count == 1, "append frame should reuse one journal handle") ||
            !Require(counters.index_journal_handle_flush_count >= 1, "append frame should flush the journal handle"))
        {
            return false;
        }
    }

    apfsaccess::rw::PayloadSpool reloaded({
        spool_root,
        kVolume,
        1024 * 1024,
        1024 * 1024,
        1024,
    });
    const auto counters = reloaded.SnapshotCounters();
    return Require(counters.recovery_required, "reloaded journal ranges should require replay") &&
           Require(counters.dirty_range_count == 2, "reloaded journal should preserve both ranges");
}

bool TestIndexJournalPreservesCleanupTailAcrossReload(const std::filesystem::path& root)
{
    const auto spool_root = root / "index-journal-cleanup-tail";
    {
        apfsaccess::rw::PayloadSpool spool({spool_root, kVolume, 1024 * 1024});
        if (!Require(Append(spool, 120, 0, "old", 10), "cleanup-tail old append should succeed") ||
            !Require(Append(spool, 121, 0, "live", 20), "cleanup-tail live append should succeed") ||
            !Require(spool.FlushDirtyState(), "cleanup-tail fixture should flush") ||
            !Require(spool.CleanupThroughSequence(10), "cleanup-tail should remove the old range"))
        {
            return false;
        }
    }

    {
        apfsaccess::rw::PayloadSpool reloaded({spool_root, kVolume, 1024 * 1024});
        const auto counters = reloaded.SnapshotCounters();
        if (!Require(counters.recovery_required, "remaining cleanup-tail range should require replay") ||
            !Require(counters.dirty_range_count == 1, "cleanup-tail reload should keep the live range") ||
            !Require(counters.spool_bytes == 7, "cleanup-tail reload should retain physical offsets") ||
            !Require(reloaded.CleanupThroughSequence(20), "cleanup-tail final cleanup should succeed"))
        {
            return false;
        }
    }

    apfsaccess::rw::PayloadSpool cleaned({spool_root, kVolume, 1024 * 1024});
    const auto counters = cleaned.SnapshotCounters();
    return Require(!counters.recovery_required, "fully cleaned journal should reload healthy") &&
           Require(counters.dirty_range_count == 0, "fully cleaned journal should have no ranges");
}

bool TestIndexJournalRejectsTornTail(const std::filesystem::path& root)
{
    const auto spool_root = root / "index-journal-torn-tail";
    {
        apfsaccess::rw::PayloadSpool spool({spool_root, kVolume, 1024 * 1024});
        if (!Require(Append(spool, 130, 0, "torn", 1), "torn-tail append should succeed") ||
            !Require(spool.FlushDirtyState(), "torn-tail fixture should flush"))
        {
            return false;
        }
    }

    const auto index_path = spool_root / "payload-spool.idx";
    std::error_code ec;
    const auto size = std::filesystem::file_size(index_path, ec);
    if (!Require(!ec && size > 1, "torn-tail index should have a non-empty file"))
    {
        return false;
    }
    std::filesystem::resize_file(index_path, size - 1, ec);
    if (!Require(!ec, "torn-tail fixture should truncate the index"))
    {
        return false;
    }

    apfsaccess::rw::PayloadSpool corrupted({spool_root, kVolume, 1024 * 1024});
    const auto counters = corrupted.SnapshotCounters();
    return Require(counters.recovery_required, "torn journal tail should require recovery") &&
           Require(counters.dirty_range_count == 0, "torn journal should not expose partial ranges");
}

bool TestLegacyIndexFallbackRemainsReadable(const std::filesystem::path& root)
{
    const auto spool_root = root / "legacy-index-fallback";
    {
        ScopedIndexDeltaDisable disable_delta;
        apfsaccess::rw::PayloadSpool spool({spool_root, kVolume, 1024 * 1024});
        if (!Require(Append(spool, 140, 0, "legacy", 1), "legacy append should succeed") ||
            !Require(spool.FlushDirtyState(), "legacy flush should succeed"))
        {
            return false;
        }
        const auto counters = spool.SnapshotCounters();
        if (!Require(counters.index_journal_frame_count == 0, "legacy fallback should not write journal frames"))
        {
            return false;
        }
    }

    apfsaccess::rw::PayloadSpool reloaded({spool_root, kVolume, 1024 * 1024});
    const auto counters = reloaded.SnapshotCounters();
    return Require(counters.recovery_required, "legacy index should remain recoverable") &&
           Require(counters.dirty_range_count == 1, "legacy index should reload its range");
}

bool TestFastCapacityProbeSkipsHealthySpoolLock(const std::filesystem::path& root)
{
    ScopedPerfCounters perf_counters("1");
    apfsaccess::rw::PayloadSpool spool({ root / "fast-capacity-headroom", kVolume, 1024 * 1024 });
    const auto before = apfsaccess::rw::PayloadSpoolTestAccess::SnapshotRaw(spool);
    const auto status = spool.CheckAppendCapacityFast(4096);
    const auto after = apfsaccess::rw::PayloadSpoolTestAccess::SnapshotRaw(spool);
    return Require(
               status == apfsaccess::rw::PayloadSpool::AppendStatus::Succeeded,
               "fast capacity probe should accept healthy headroom") &&
           Require(
               after.mutex_wait_count == before.mutex_wait_count,
               "fast capacity probe should avoid the spool mutex with healthy headroom");
}

bool TestFastCapacityProbeFallsBackForQuota(const std::filesystem::path& root)
{
    ScopedPerfCounters perf_counters("1");
    apfsaccess::rw::PayloadSpool spool({ root / "fast-capacity-quota", kVolume, 4 });
    if (!Require(Append(spool, 141, 0, "full", 1),
            "fast capacity quota fixture should consume its quota"))
    {
        return false;
    }

    const auto before = apfsaccess::rw::PayloadSpoolTestAccess::SnapshotRaw(spool);
    const auto status = spool.CheckAppendCapacityFast(1);
    const auto after = apfsaccess::rw::PayloadSpoolTestAccess::SnapshotRaw(spool);
    return Require(
               status == apfsaccess::rw::PayloadSpool::AppendStatus::QuotaExceeded,
               "fast capacity probe should use the exact locked quota result") &&
           Require(
               after.mutex_wait_count == before.mutex_wait_count + 1,
               "quota capacity probe should fall back to one locked check");
}

bool TestDirectReadReleasesPayloadIoBeforeMetadataReacquire(const std::filesystem::path& root)
{
    apfsaccess::rw::PayloadSpool spool({root / "direct-read-lock-order", kVolume, 2 * 1024 * 1024});
    const std::string payload(4096, 'L');
    if (!Require(Append(spool, 703, 0, payload, 702),
            "Direct-read lock-order fixture should append payload") ||
        !Require(spool.FlushPayloadBytes(),
            "Direct-read lock-order fixture should persist payload bytes"))
    {
        return false;
    }

    auto payload_io_lock = apfsaccess::rw::PayloadSpoolTestAccess::AcquirePayloadIoExclusive(spool);
    auto reader = std::async(std::launch::async, [&spool, &payload]()
    {
        std::string actual(payload.size(), '.');
        return Overlay(spool, 703, 0, actual) && actual == payload;
    });

    bool reader_waiting_for_payload_io = false;
    for (std::size_t attempt = 0; attempt < 200; ++attempt)
    {
        if (apfsaccess::rw::PayloadSpoolTestAccess::SnapshotRaw(spool)
                .range_payload_positional_read_count >= 1)
        {
            reader_waiting_for_payload_io = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    if (!Require(reader_waiting_for_payload_io,
            "Direct read should reach payload I/O after releasing spool metadata"))
    {
        payload_io_lock.unlock();
        (void)reader.get();
        return false;
    }

    auto metadata_lock = apfsaccess::rw::PayloadSpoolTestAccess::AcquireMutex(spool);
    payload_io_lock.unlock();
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    bool payload_io_reacquired = false;
    for (std::size_t attempt = 0; attempt < 200; ++attempt)
    {
        auto probe = apfsaccess::rw::PayloadSpoolTestAccess::TryAcquirePayloadIoExclusive(spool);
        if (probe.owns_lock())
        {
            payload_io_reacquired = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    metadata_lock.unlock();
    const auto reader_completed = reader.get();
    return Require(payload_io_reacquired,
               "Direct read must release payload I/O before waiting to reacquire spool metadata") &&
           Require(reader_completed,
               "Direct read should preserve bytes after the lock-order probe completes");
}

bool TestMultiRangeFailureReleasesPayloadIoBeforeMetadataReacquire(const std::filesystem::path& root)
{
    apfsaccess::rw::PayloadSpool spool({root / "multi-range-failure-lock-order", kVolume, 2 * 1024 * 1024});
    const std::string first(4096, 'A');
    const std::string second(4096, 'B');
    if (!Require(Append(spool, 706, 0, first, 705),
            "Multi-range failure fixture should append its first payload") ||
        !Require(Append(spool, 706, first.size(), second, 706),
            "Multi-range failure fixture should append its second payload") ||
        !Require(spool.FlushPayloadBytes(),
            "Multi-range failure fixture should persist payload bytes"))
    {
        return false;
    }

    {
        std::fstream file(spool.SpoolFilePath(), std::ios::binary | std::ios::in | std::ios::out);
        if (!Require(file.good(),
                "Multi-range failure fixture should open its persisted payload"))
        {
            return false;
        }
        const char corrupt = 'Z';
        file.seekp(static_cast<std::streamoff>(first.size()), std::ios::beg);
        file.write(&corrupt, 1);
        if (!Require(file.good(),
                "Multi-range failure fixture should corrupt its second range"))
        {
            return false;
        }
    }

    auto payload_io_lock = apfsaccess::rw::PayloadSpoolTestAccess::AcquirePayloadIoExclusive(spool);
    auto reader = std::async(std::launch::async, [&spool, &first, &second]()
    {
        std::vector<std::byte> actual(first.size() + second.size(), std::byte{0});
        std::size_t bytes_overlaid = 0;
        return spool.OverlayDirtyRanges({
            kVolume,
            706,
            1,
            0,
            std::span<std::byte>(actual.data(), actual.size()),
        }, bytes_overlaid);
    });

    bool reader_waiting_for_payload_io = false;
    for (std::size_t attempt = 0; attempt < 200; ++attempt)
    {
        if (apfsaccess::rw::PayloadSpoolTestAccess::SnapshotRaw(spool)
                .range_payload_positional_read_count >= 2)
        {
            reader_waiting_for_payload_io = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    if (!Require(reader_waiting_for_payload_io,
            "Multi-range failure should reach payload I/O after releasing spool metadata"))
    {
        payload_io_lock.unlock();
        (void)reader.get();
        return false;
    }

    auto metadata_lock = apfsaccess::rw::PayloadSpoolTestAccess::AcquireMutex(spool);
    payload_io_lock.unlock();
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    bool payload_io_reacquired = false;
    for (std::size_t attempt = 0; attempt < 200; ++attempt)
    {
        auto probe = apfsaccess::rw::PayloadSpoolTestAccess::TryAcquirePayloadIoExclusive(spool);
        if (probe.owns_lock())
        {
            payload_io_reacquired = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    metadata_lock.unlock();
    const auto reader_result = reader.get();
    return Require(payload_io_reacquired,
               "Multi-range failure must release payload I/O before updating metadata counters") &&
           Require(!reader_result,
               "Multi-range checksum corruption should still fail the overlay");
}

bool TestFailedLargeDirectAppendTruncatesUnindexedTail(const std::filesystem::path& root)
{
    const auto spool_root = root / "failed-large-direct-append";
    apfsaccess::rw::PayloadSpool spool({spool_root, kVolume, 4 * 1024 * 1024});
    constexpr std::string_view kPrefix = "prefix";
    constexpr std::string_view kInjectedTail = "partial";
    if (!Require(Append(spool, 704, 0, kPrefix, 703),
            "Failed direct-append fixture should stage its valid prefix") ||
        !Require(spool.FlushPayloadBytes(),
            "Failed direct-append fixture should persist its valid prefix"))
    {
        return false;
    }

    {
        std::ofstream output(spool.SpoolFilePath(), std::ios::binary | std::ios::app);
        if (!Require(output.good(),
                "Failed direct-append fixture should open its physical tail"))
        {
            return false;
        }
        output.write(kInjectedTail.data(), static_cast<std::streamsize>(kInjectedTail.size()));
        if (!Require(output.good(),
                "Failed direct-append fixture should inject a partial physical tail"))
        {
            return false;
        }
    }

    if (!Require(
            apfsaccess::rw::PayloadSpoolTestAccess::ReplaceAppendHandleWithReadOnly(spool),
            "Failed direct-append fixture should install a non-writable append handle"))
    {
        return false;
    }

    std::vector<std::byte> large_payload((1024 * 1024) + 1, std::byte{0x4f});
    const auto append_status = spool.AppendWithStatus({
        kVolume,
        705,
        1,
        0,
        704,
        std::span<const std::byte>(large_payload.data(), large_payload.size()),
    });
    std::error_code ec;
    const auto physical_bytes = std::filesystem::file_size(spool.SpoolFilePath(), ec);
    return Require(
               append_status == apfsaccess::rw::PayloadSpool::AppendStatus::StorageFailure,
               "Large direct append should surface its physical write failure") &&
           Require(!ec && physical_bytes == kPrefix.size(),
               "Failed large direct append should truncate every unindexed tail byte") &&
           Require(!spool.RecoveryRequired(),
               "Successful failed-append truncation should preserve the prior healthy state");
}

bool TestPayloadSpoolDisablesMutexWaitTelemetry(const std::filesystem::path& root)
{
    ScopedPerfCounters perf_counters("0");
    apfsaccess::rw::PayloadSpool spool({root / "mutex-wait-disabled", kVolume, 1024 * 1024});
    (void)spool.CheckAppendCapacity(1);
    (void)spool.SnapshotCounters();
    const auto counters = apfsaccess::rw::PayloadSpoolTestAccess::SnapshotRaw(spool);
    return Require(counters.mutex_wait_count == 0, "Disabled payload-spool telemetry should not count locks") &&
           Require(counters.mutex_wait_microseconds == 0, "Disabled payload-spool telemetry should not time locks") &&
           Require(counters.mutex_wait_max_microseconds == 0, "Disabled payload-spool telemetry should preserve zero maximum") &&
           Require(counters.mutex_wait_p50_microseconds == 0, "Disabled payload-spool telemetry should preserve zero p50") &&
           Require(counters.mutex_wait_p95_microseconds == 0, "Disabled payload-spool telemetry should preserve zero p95");
}

bool TestPayloadSpoolReportsContendedMutexWaitLatency(const std::filesystem::path& root)
{
    ScopedPerfCounters perf_counters("1");
    apfsaccess::rw::PayloadSpool spool({root / "mutex-wait-contended", kVolume, 1024 * 1024});
    const auto before = apfsaccess::rw::PayloadSpoolTestAccess::SnapshotRaw(spool);

    auto held = apfsaccess::rw::PayloadSpoolTestAccess::AcquireMutex(spool);
    std::promise<void> worker_started;
    auto started = worker_started.get_future();
    auto worker = std::async(std::launch::async, [&]()
    {
        worker_started.set_value();
        return spool.CheckAppendCapacity(1);
    });
    started.wait();
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    held.unlock();
    const auto completed = worker.get();

    const auto counters = apfsaccess::rw::PayloadSpoolTestAccess::SnapshotRaw(spool);
    return Require(completed == apfsaccess::rw::PayloadSpool::AppendStatus::Succeeded,
               "Contended payload-spool public lock path should complete") &&
           Require(counters.mutex_wait_count == before.mutex_wait_count + 2,
               "Enabled payload-spool telemetry should count both real acquisitions") &&
           Require(counters.mutex_wait_max_microseconds >= 10000,
               "Enabled payload-spool telemetry should record concurrent contention") &&
           Require(counters.mutex_wait_p50_microseconds <= counters.mutex_wait_max_microseconds,
               "Payload-spool p50 should not exceed exact maximum") &&
           Require(counters.mutex_wait_p95_microseconds <= counters.mutex_wait_max_microseconds,
               "Payload-spool p95 should not exceed exact maximum");
}

bool TestPayloadSpoolMutexWaitPercentileAndSaturationBoundaries(const std::filesystem::path& root)
{
    ScopedPerfCounters perf_counters("1");
    apfsaccess::rw::PayloadSpool spool({root / "mutex-wait-boundaries", kVolume, 1024 * 1024});
    std::array<std::uint64_t, 32> buckets{};

    buckets[0] = 1;
    auto counters = apfsaccess::rw::PayloadSpoolTestAccess::SetMutexWaitStateAndSnapshot(
        spool, 1, 0, 0, buckets);
    if (!Require(counters.mutex_wait_p50_microseconds == 0,
            "Payload-spool zero maximum should preserve zero p50") ||
        !Require(counters.mutex_wait_p95_microseconds == 0,
            "Payload-spool zero maximum should preserve zero p95"))
    {
        return false;
    }

    buckets = {};
    buckets[0] = 2;
    buckets[1] = 1;
    buckets[2] = 1;
    counters = apfsaccess::rw::PayloadSpoolTestAccess::SetMutexWaitStateAndSnapshot(
        spool, 4, 7, 4, buckets);
    if (!Require(counters.mutex_wait_p50_microseconds == 1,
            "Payload-spool p50 should use the exact nearest-rank bucket") ||
        !Require(counters.mutex_wait_p95_microseconds == 4,
            "Payload-spool p95 should use the exact nearest-rank bucket"))
    {
        return false;
    }

    buckets = {};
    buckets[0] = 19;
    buckets[1] = 1;
    counters = apfsaccess::rw::PayloadSpoolTestAccess::SetMutexWaitStateAndSnapshot(
        spool, 20, 20, 2, buckets);
    if (!Require(counters.mutex_wait_p95_microseconds == 1,
            "Payload-spool p95 rank should be ceil(19 * count / 20)"))
    {
        return false;
    }

    const auto max_u64 = (std::numeric_limits<std::uint64_t>::max)();
    buckets = {};
    buckets[0] = max_u64 / 2;
    buckets[1] = max_u64;
    counters = apfsaccess::rw::PayloadSpoolTestAccess::SetMutexWaitStateAndSnapshot(
        spool, max_u64, max_u64, 4, buckets);
    if (!Require(counters.mutex_wait_p50_microseconds == 2,
            "Payload-spool p50 rank and cumulative count should be overflow-safe"))
    {
        return false;
    }

    const auto p95_target = (max_u64 / 20) * 19 + (((max_u64 % 20) * 19 + 19) / 20);
    buckets = {};
    buckets[0] = p95_target - 1;
    buckets[1] = max_u64;
    counters = apfsaccess::rw::PayloadSpoolTestAccess::SetMutexWaitStateAndSnapshot(
        spool, max_u64, max_u64, 4, buckets);
    if (!Require(counters.mutex_wait_p95_microseconds == 2,
            "Payload-spool percentile rank and cumulative count should be overflow-safe"))
    {
        return false;
    }

    buckets = {};
    buckets[0] = max_u64;
    (void)apfsaccess::rw::PayloadSpoolTestAccess::SetMutexWaitStateAndSnapshot(
        spool, max_u64, max_u64, 1, buckets);
    (void)spool.CheckAppendCapacity(1);
    counters = apfsaccess::rw::PayloadSpoolTestAccess::SnapshotRaw(spool);
    return Require(counters.mutex_wait_count == max_u64,
               "Payload-spool lifetime count should saturate") &&
           Require(counters.mutex_wait_microseconds == max_u64,
               "Payload-spool lifetime total should saturate");
}
}

int main()
{
    const auto root = MakeRunRoot();
    bool ok = true;
    ok &= TestAppendReturnsAcceptedPayloadReference(root);
    ok &= TestPersistedRangeRequiresExactWalIdentityAndSha256(root);
    ok &= TestPayloadOnlyFlushRebuildsMissingIndex(root);
    ok &= TestIndexRebuildDiscardsInlineWalRangesAndKeepsLegacyPayload(root);
    ok &= TestIndexRebuildRejectsUnknownTailDespiteInlineWalRange(root);
    ok &= TestCoalescingAndPartialReads(root);
    ok &= TestOverlappingWritesReportUniqueCoverage(root);
    ok &= TestOverlayUsesWalSequenceOrderNotAppendOrder(root);
    ok &= TestOverlayUsesSpoolOrderAfterMergedAppend(root);
    ok &= TestLargeSequentialWritesStayAppendFriendly(root);
    ok &= TestDiscardSequenceKeepsEarlierWrites(root);
    ok &= TestChecksumMismatchAndWrongVolume(root);
    ok &= TestCleanupAndQuota(root);
    ok &= TestFinalCleanupSkipsRedundantPayloadFlush(root);
    ok &= TestMaxDirtyRangeEndTracksLatestLogicalTail(root);
    ok &= TestOverlayReportsLogicalTailWithOneSpoolLookup(root);
    ok &= TestIndexReloadAndCorruption(root);
    ok &= TestAppendBatchesIndexPersistenceUntilFlush(root);
    ok &= TestManySequentialAppendsAvoidPerAppendIndexRewrite(root);
    ok &= TestNonOverlappingOverlayAvoidsPayloadOpen(root);
    ok &= TestCoverageQueryUsesRangeIndexOnly(root);
    ok &= TestManyRangeCoverageUsesSortedUnion(root);
    ok &= TestCoverageQueryDefersChecksumValidationToRead(root);
    ok &= TestRepeatedDirtyReadsReusePayloadReadHandle(root);
    ok &= TestPartialDirtyReadsReuseValidatedPayloadCache(root);
    ok &= TestConcurrentSingleRangeReadsPreserveBytes(root);
    ok &= TestConcurrentMultiRangeReadsReleaseSpoolMutexDuringPayloadIo(root);
    ok &= TestOverlayUsesDirectDestinationReads(root);
    ok &= TestOverlayScratchStoragePersistsAcrossCalls(root);
    ok &= TestAppendMergeScratchStoragePersistsAcrossCalls(root);
    ok &= TestReadFullyCoveredRangeCombinesCoverageAndRead(root);
    ok &= TestOverlayPastDirtyTailAvoidsPayloadOpen(root);
    ok &= TestThresholdFlushFailureRollsBackLastAppend(root);
    ok &= TestThresholdFlushFailureRollsBackMergedRanges(root);
    ok &= TestManyObjectReadsUseObjectLookup(root);
    ok &= TestOrphanedSpoolBytesRequireRecovery(root);
    ok &= TestUnindexedPayloadRecoveryRequiresEmptyWalProof(root);
    ok &= TestCorruptIndexCannotUseUnindexedPayloadRecovery(root);
    ok &= TestOldestDirtyAgeTracksOldestRangeIncrementally(root);
    ok &= TestCleanupClearsDirtyTailCache(root);
    ok &= TestCleanupNoOpAvoidsSpoolRewrite(root);
    ok &= TestCleanupPersistsOnlySurvivingIndexState(root);
    ok &= TestCleanupReportsBlockedSpoolDeletion(root);
    ok &= TestCleanupBlocksPayloadRemovalWhenIndexRemovalFails(root);
    ok &= TestCleanupPreservesWalOffsetsForLaterRanges(root);
    ok &= TestCleanupNoOpAvoidsSequenceScan(root);
    ok &= TestDirtyTailCacheKeepsZeroOffsetRanges(root);
    ok &= TestIndexJournalUsesAppendFramesAndReloads(root);
    ok &= TestIndexJournalPreservesCleanupTailAcrossReload(root);
    ok &= TestIndexJournalRejectsTornTail(root);
    ok &= TestLegacyIndexFallbackRemainsReadable(root);
    ok &= TestFastCapacityProbeSkipsHealthySpoolLock(root);
    ok &= TestFastCapacityProbeFallsBackForQuota(root);
    ok &= TestDirectReadReleasesPayloadIoBeforeMetadataReacquire(root);
    ok &= TestMultiRangeFailureReleasesPayloadIoBeforeMetadataReacquire(root);
    ok &= TestFailedLargeDirectAppendTruncatesUnindexedTail(root);
    ok &= TestPayloadSpoolDisablesMutexWaitTelemetry(root);
    ok &= TestPayloadSpoolReportsContendedMutexWaitLatency(root);
    ok &= TestPayloadSpoolMutexWaitPercentileAndSaturationBoundaries(root);

    std::error_code ec;
    std::filesystem::remove_all(root, ec);
    if (!ok)
    {
        return 1;
    }

    std::cout << "[PASS] PayloadSpool tests passed." << std::endl;
    return 0;
}
