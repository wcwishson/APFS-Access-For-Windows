#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace apfsaccess::rw
{
class WriteAheadLog
{
public:
    static constexpr std::size_t PayloadHashSize = 32;
    static constexpr std::size_t MaxInlinePayloadBytes = 1024u * 1024u;

    enum class OperationKind : std::uint32_t
    {
        CreateFile = 1,
        CreateDirectory = 2,
        Write = 3,
        SetFileSize = 4,
        Rename = 5,
        Delete = 6,
        SetBasicInfo = 7,
        TransactionMarker = 100,
        CompactionIndex = 101,
        DurabilityWatermark = 102,
    };

    enum class RecordState : std::uint32_t
    {
        Prepared = 1,
        ApfsApplied = 2,
        Checkpointed = 3,
        Cleaned = 4,
        Accepted = 5,
        PublishArmed = 6,
        CleanupArmed = 7,
    };

    enum class ReadStatus
    {
        Ok,
        IoError,
        Corrupt,
        ChecksumMismatch,
        VersionMismatch,
        VolumeMismatch,
    };

    enum class AppendResult
    {
        Succeeded,
        RejectedBeforeWrite,
        BytesMayHavePersisted,
    };

    enum class CompactionResult
    {
        Succeeded,
        RejectedBeforeWrite,
        BytesMayHavePersisted,
    };

    using FaultInjectionHook = std::function<bool(std::string_view stage)>;

    struct Options
    {
        std::filesystem::path path;
        std::string volume_identity;
        std::uint64_t max_bytes = 64ull * 1024ull * 1024ull;
    };

    struct Record
    {
        std::string volume_identity;
        std::uint64_t transaction_id = 0;
        std::uint64_t sequence = 0;
        OperationKind operation = OperationKind::Write;
        RecordState state = RecordState::Prepared;
        std::uint64_t object_id = 0;
        std::uint64_t parent_object_id = 0;
        std::uint64_t payload_spool_id = 0;
        std::uint64_t payload_offset = 0;
        std::uint64_t payload_length = 0;
        std::uint64_t logical_offset = 0;
        std::uint64_t logical_length = 0;
        std::uint64_t flags = 0;
        std::array<std::uint8_t, PayloadHashSize> payload_sha256{};
        std::vector<std::byte> inline_payload;
        std::string path_utf8;
        std::string secondary_path_utf8;
    };

    struct ReadResult
    {
        ReadStatus status = ReadStatus::Ok;
        bool recovered_torn_tail = false;
        std::vector<Record> records;
    };

    struct Counters
    {
        std::uint64_t append_handle_open_count = 0;
        std::uint64_t append_handle_flush_count = 0;
    };

    explicit WriteAheadLog(Options options);
    ~WriteAheadLog();

    WriteAheadLog(const WriteAheadLog&) = delete;
    WriteAheadLog& operator=(const WriteAheadLog&) = delete;

    void Reconfigure(Options options);

    [[nodiscard]] bool AcquireExclusiveWriterLease() const;
    [[nodiscard]] bool Append(const Record& record, bool durable_flush = true) const;
    [[nodiscard]] bool AppendBatch(const std::vector<Record>& records, bool durable_flush = true) const;
    [[nodiscard]] AppendResult AppendWithResult(
        const Record& record,
        bool durable_flush = true,
        std::uint64_t expected_writer_generation = 0) const;
    [[nodiscard]] AppendResult AppendBatchWithResult(
        const std::vector<Record>& records,
        bool durable_flush = true,
        std::uint64_t expected_writer_generation = 0) const;
    [[nodiscard]] bool FlushPendingAppends() const;
    [[nodiscard]] bool Compact(std::uint64_t minimum_sequence_to_keep) const;
    [[nodiscard]] CompactionResult CompactWithResult(
        std::uint64_t minimum_sequence_to_keep,
        std::uint64_t expected_writer_generation = 0) const;
    [[nodiscard]] ReadResult ReadAll() const;
    [[nodiscard]] ReadResult ReadAllWithExclusiveWriterLease() const;

    [[nodiscard]] static ReadResult ReadAll(
        const std::filesystem::path& path,
        const std::string& expected_volume_identity);
    [[nodiscard]] static std::vector<std::uint8_t> EncodeForTest(
        const Record& record,
        std::uint16_t version_override = 0);
    [[nodiscard]] static bool InlinePayloadIsConsistent(const Record& record);
    [[nodiscard]] Counters SnapshotCounters() const;
    [[nodiscard]] bool HasExclusiveWriterLease() const;
    [[nodiscard]] std::uint64_t ExclusiveWriterLeaseGeneration() const;
    void SetFaultInjectionHook(FaultInjectionHook hook);

private:
    enum class EncodedAppendResult
    {
        Succeeded,
        RejectedBeforeWrite,
        BytesMayHavePersisted,
    };

    [[nodiscard]] bool EnsureAppendHandle(
        bool resolve_compaction_intent = true,
        bool allow_create = true) const;
    [[nodiscard]] bool EnsureWriterLease() const;
    [[nodiscard]] bool CloseAppendFileHandle() const noexcept;
    [[nodiscard]] bool CloseWriterLeaseHandle() const noexcept;
    [[nodiscard]] bool CloseAppendHandle() const noexcept;
    [[nodiscard]] bool PersistCompactionIntent(
        std::uint32_t volume_serial,
        std::uint64_t file_id,
        RecordState state = RecordState::Prepared,
        std::uint64_t replacement_file_id = 0,
        bool* bytes_may_have_persisted = nullptr,
        bool namespace_durable = false) const;
    [[nodiscard]] bool ReadLatestCompactionIntent(
        void* intent_handle,
        std::uint32_t intent_volume_serial,
        std::uint64_t intent_file_id,
        Record& latest_intent) const;
    [[nodiscard]] bool DeleteRetainedCompactionTemp(
        std::uint32_t volume_serial,
        std::uint64_t replacement_file_id) const;
    [[nodiscard]] bool CleanupPreIntentCompactionOrphans() const;
    [[nodiscard]] bool DeleteCompletedCompactionPredecessorTombstone(
        std::uint32_t volume_serial,
        std::uint64_t predecessor_file_id) const;
    [[nodiscard]] bool ClearCompletedCompactionIntentForNewCompaction() const;
    [[nodiscard]] bool RestoreMissingCanonicalForPublishArmedIntent() const;
    [[nodiscard]] bool ResolvePendingCompactionIntent() const;
    [[nodiscard]] bool ClearCompactionIntent(
        const Record& intent,
        std::uint32_t intent_volume_serial,
        std::uint64_t intent_file_id) const;
    [[nodiscard]] bool TruncateAppendHandle(std::uint64_t complete_prefix_bytes) const;
    [[nodiscard]] bool FlushAppendHandle() const;
    [[nodiscard]] EncodedAppendResult AppendEncoded(const std::vector<std::uint8_t>& encoded) const;
    void RegisterPath();
    void UnregisterPath() noexcept;
    [[nodiscard]] static bool TryTransferRegisteredHandlesForPath(
        const std::filesystem::path& path,
        const WriteAheadLog* successor);
    [[nodiscard]] static ReadResult ReadAllInternal(
        const std::filesystem::path& path,
        const std::string& expected_volume_identity,
        bool repair_torn_tail,
        std::uint64_t* complete_prefix_bytes);

    Options options_;
    mutable void* append_handle_ = nullptr;
    mutable void* writer_lease_handle_ = nullptr;
    mutable std::wstring writer_lease_name_;
    mutable std::uint64_t append_handle_size_ = 0;
    mutable bool append_handle_size_known_ = false;
    mutable std::uint64_t append_handle_open_count_ = 0;
    mutable std::uint64_t append_handle_flush_count_ = 0;
    mutable std::uint64_t writer_lease_generation_ = 0;
    FaultInjectionHook fault_injection_hook_;
    std::wstring registered_path_;
};
} // namespace apfsaccess::rw
