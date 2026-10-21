#pragma once

#include "NativeApfsReader.h"
#include <span>
#include <string_view>

namespace apfsaccess::catalog::payload
{
inline constexpr std::uint64_t MaxLogicalBytes = 268435456;
inline constexpr std::uint64_t MaxEntries = 1024;
inline constexpr std::size_t ChunkBytes = 65536;

enum class Kind { FileData, Xattr };
enum class ReadOutcome { Complete, NotRead, ReadFailure, BudgetExceeded, Unsupported };
enum class Outcome { ExactComplete, Incomplete, Unsupported, Error };
enum class Reason {
    None, InvalidProjection, InvalidBinding, LogicalLimit, EntryLimit, SharedBudget,
    Deadline, UnsupportedRepresentation, SourceReadFailure, HashProviderFailure,
    OutputLimit, AllocationFailure, CallbackFailure, HashProviderUnavailable,
    AdmissionNotComplete
};

struct Entry {
    Kind kind = Kind::FileData;
    std::uint64_t inodeOid = 0, streamOid = 0;
    std::optional<std::string> nameUtf8;
    std::uint64_t logicalSizeBytes = 0, logicalBytesRead = 0;
    ReadOutcome readOutcome = ReadOutcome::NotRead;
    std::optional<std::string> observedSha256;
    // There is intentionally no input or storage for expected hashes.
};

struct Result {
    Outcome outcome = Outcome::Error;
    Reason reason = Reason::InvalidBinding;
    bool enumerationComplete = false, readComplete = false, hashesObserved = false;
    static constexpr bool expectedComparisonNotSupplied = true;
    static constexpr bool wholeVolumeVerified = false;
    static constexpr bool payloadContentHashesVerified = false;
    std::uint64_t logicalBytesRead = 0;
    std::vector<Entry> entries;
    // Retain the exact allowance so serialization cannot replace an exhausted one.
    std::shared_ptr<catalog::ApfsReadBudget> sharedBudget;
    // failedSourceOffset is relative to Request::source (the ordinary store view).
    // An outer parent-source report adds the store base once, checking overflow.
    std::optional<std::uint64_t> failedSourceOffset, failedInodeOid, failedStreamOid;
    // Borrowed, unchanged aliases: projection must outlive the result.
    std::span<const rw::MetadataStore::DirectoryLink> aliases;
    [[nodiscard]] bool exactComplete() const noexcept { return outcome == Outcome::ExactComplete; }
};

struct SourceWindow {
    // Bounds are relative to Request::source. Never add this offset to extents.
    // Ordinary source-free projection: zero-based store view, {0, store.SizeBytes()}.
    std::uint64_t offsetBytes = 0, sizeBytes = 0;
};

struct Request {
    const rw::NativeApfsVolumeProjection& projection;
    // Ordinary source-free extents are store-relative: pass the existing
    // zero-based OffsetRandomAccessSource store, window {0, store.SizeBytes()},
    // and store.ReadBudget(), the exact nonnull inherited operation allowance.
    const catalog::RandomAccessSource& source;
    SourceWindow window;
    std::shared_ptr<catalog::ApfsReadBudget> budget;
    // Required cooperative predicate, true while observation may continue.
    // It must stay false once expired. Checked during enumeration and every chunk.
    std::function<bool()> withinDeadline;
};

// Caller has already admitted the exact ordinary current projection through
// namespace, ownership and allocator gates and holds projection/source immutable.
// No admission, source authentication, paths, APFS catalog loading or retry here.
[[nodiscard]] Result ObserveCurrentPayload(const Request& request);

// Emits the payloadInventory object, not a verifier report.
// Rejects contradictory results and output overflow; never truncates JSON.
// Serialization shares the same sticky materialization allowance and deadline.
[[nodiscard]] bool SerializeInventory(const Result& result,
    const std::shared_ptr<catalog::ApfsReadBudget>& budget,
    const std::function<bool()>& withinDeadline, std::size_t maxOutputBytes,
    std::string& output, Reason& failure);

[[nodiscard]] std::string_view Name(Kind value) noexcept;
[[nodiscard]] std::string_view Name(ReadOutcome value) noexcept;
[[nodiscard]] std::string_view Name(Outcome value) noexcept;
[[nodiscard]] std::string_view Name(Reason value) noexcept;
}
