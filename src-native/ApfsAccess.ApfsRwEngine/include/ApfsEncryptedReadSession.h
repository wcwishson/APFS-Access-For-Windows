#pragma once

#include "ApfsKeybagUnlock.h"
#include "ApfsNameCodec.h"
#include "ApfsEncryptedCowOverwrite.h"
#include <string_view>
#include <atomic>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace apfsaccess::catalog
{
class ApfsEncryptedReadSession;
class ApfsEncryptedImageWriteSession;
class AppleEncryptedMetadataReadContext;
class AppleEncryptedSnapshotReadContext;
class SoftwareVolumeRetainedOwners;

// Maximum allowance for one serialized runtime API call. A capable source may
// lower these limits; larger advertised values are clamped to these defaults.
// Initialization continues to use the original cumulative source budget.
struct EncryptedRuntimeReadLimits
{
    std::uint64_t reads = 100000, read_bytes = 256ULL * 1024 * 1024;
    std::uint64_t records = 1000000, materialized_bytes = 256ULL * 1024 * 1024;
};

// The host must hold an immutable, container-relative snapshot for this object's
// entire lifetime. Revision is an opaque host token, not an mtime or UUID guess.
// Initialization and legacy reads charge the same advertised cumulative budget.
// A held mutable file alone does not satisfy this contract. Session serializes
// all accesses, including opt-in runtime reads with a per-operation allowance.
class ImmutableEncryptedReadSource : public RandomAccessSource
{
public:
    [[nodiscard]] virtual std::string SourceIdentity() const = 0;
    [[nodiscard]] virtual std::uint64_t Revision() const = 0;

    // Opt in only when runtime reads can use the SAME held immutable lease
    // without charging ReadBudget(). Captured once after successful parsing.
    // nullopt preserves legacy cumulative read/materialization accounting.
    [[nodiscard]] virtual std::optional<EncryptedRuntimeReadLimits> RuntimeReadLimits() const { return {}; }

    // A borrowed, noncopyable reservation, created only by the session AFTER
    // charging one read and Size() bytes to its bounded operation budget.
    // It is valid only during ReadRuntime; never retain it or dispatch deferred
    // I/O. Check IsFor(*this), enforce the held lease/geometry, and read exactly
    // Offset()/Size(). No further budget charge and no call to legacy Read().
    class RuntimeRead final
    {
    public:
        RuntimeRead(const RuntimeRead&) = delete;
        RuntimeRead& operator=(const RuntimeRead&) = delete;
        [[nodiscard]] std::uint64_t Offset() const noexcept { return offset_; }
        [[nodiscard]] std::size_t Size() const noexcept { return size_; }
        [[nodiscard]] bool IsFor(const ImmutableEncryptedReadSource& source) const noexcept { return source_ == &source; }
    private:
        friend class ApfsEncryptedReadSession;
        RuntimeRead(const ImmutableEncryptedReadSource& source, std::uint64_t offset, std::size_t size)
            : source_(&source), offset_(offset), size_(size) {}
        const ImmutableEncryptedReadSource* const source_;
        const std::uint64_t offset_;
        const std::size_t size_;
    };
    [[nodiscard]] virtual bool ReadRuntime(const RuntimeRead&, std::vector<std::byte>& out) const
    { out.clear(); return false; }
};

enum class EncryptedReadError
{
    None, InvalidArgument, UnlockFailed, UnsupportedEncryptionLayout,
    SourceIdentityMismatch, ResourceLimit, ReadFailure, CryptoFailure,
    MetadataIntegrityFailure, Closed, Cancelled, FileNotFound,
    NotDirectory, XattrNotFound, NamespaceUnavailable
};

struct EncryptedFileInfo
{
    std::uint64_t inode_id = 0, size = 0, default_crypto_id = 0;
};

// Scalar inode facts preserve APFS ownership/mode and nanoseconds since Unix epoch.
// parent_id is the inode's primary parent (root reports itself); entry parent_id
// is authoritative for an individual hard link. No Windows ACL inference.
struct EncryptedNodeInfo
{
    std::uint64_t inode_id = 0, parent_id = 0, private_id = 0;
    std::uint64_t size = 0, allocated_size = 0, default_crypto_id = 0;
    std::uint64_t create_time = 0, modification_time = 0, change_time = 0, access_time = 0;
    std::uint64_t internal_flags = 0;
    std::uint32_t uid = 0, gid = 0, bsd_flags = 0, protection_class = 0, write_generation = 0;
    std::uint32_t children_or_links = 0;
    std::uint16_t mode = 0;
    [[nodiscard]] bool IsDirectory() const noexcept { return (mode & 0170000) == 0040000; }
};
struct EncryptedDirectoryEntry
{
    std::uint64_t parent_id = 0, inode_id = 0, sibling_id = 0, date_added = 0;
    std::uint16_t flags = 0;
    std::string name_utf8;
    std::wstring windows_name; // Exact reversible ApfsNameCodec projection.
};
struct EncryptedXattr
{
    std::string name_utf8;
    std::uint16_t flags = 0;
    std::vector<std::byte> data; // Embedded bytes, never an external-stream descriptor.
};
struct EncryptedNamespaceInfo
{
    std::uint64_t root_inode_id = 0, inode_count = 0, entry_count = 0;
    rw::ApfsNamePolicy name_policy;
};

// Software ONEKEY, generation zero, header-bearing virtual FS trees only.
// Encrypted nodes require OBJ_ENCRYPTED in their decrypted header. Plain nodes
// require a plain header. Default selection is fixed; explicit snapshot reads
// use a separate opaque capability. No trial decrypt, global cache, mount/write
// admission, compression, per-file key or hardware-key support.
class ApfsEncryptedReadSession final
{
public:
    ~ApfsEncryptedReadSession();
    ApfsEncryptedReadSession(const ApfsEncryptedReadSession&) = delete;
    ApfsEncryptedReadSession& operator=(const ApfsEncryptedReadSession&) = delete;

    // Unlock and bind within one owned source lifetime; credentials are borrowed
    // only during this call. Caller clears its locked credential buffer afterwards.
    [[nodiscard]] static std::unique_ptr<ApfsEncryptedReadSession> Unlock(
        std::shared_ptr<const ImmutableEncryptedReadSource> source,
        std::string expected_source_identity, std::uint64_t expected_revision,
        const PasswordUnlockRequest& request, std::span<const std::byte> password,
        PasswordUnlockBudget& attempts, EncryptedReadError& error, UnlockError& unlock_error,
        std::shared_ptr<const std::atomic<bool>> cancellation = {});

    // Exact-read: failure leaves output empty; no EOF clipping. Zero-byte reads
    // are accepted at/before EOF. Requests are capped at SecureBytes::kMaxBytes.
    // Successful outputs are ordinary caller-owned plaintext, not locked storage.
    // With RuntimeReadLimits opt-in, each public runtime call has its own bounded
    // allowance. Its exhaustion does not poison later calls. Source binding,
    // original-budget failure and observed cancellation remain sticky.
    EncryptedReadError ReadFile(std::uint64_t inode_id, std::uint64_t offset,
        std::size_t size, std::vector<std::byte>& output);
    EncryptedReadError ListFiles(std::vector<EncryptedFileInfo>& output);
    // Reuses this session's locked VEK, immutable source and exact selection.
    // No write capability; caller wipes canonical plaintext records after use.
    std::unique_ptr<AppleEncryptedMetadataReadContext> CreateMetadataReadContext(EncryptedReadError& error);
    // Exact earlier checkpoint on this same admitted source and protected VEK.
    // Reuses the private canonical keybag-era proof; no new key/source authority.
    std::unique_ptr<AppleEncryptedMetadataReadContext> CreateRetainedVerificationContext(
        std::uint64_t checkpoint_xid, std::string& error);
    // Canonical snapshot reads inherit this exact current or retained parent.
    // The separate type cannot enter checkpoint writer/context overloads.
    std::unique_ptr<AppleEncryptedSnapshotReadContext> CreateSnapshotVerificationContext(
        AppleEncryptedMetadataReadContext& parent, std::string& error);
    // Exact earlier snapshot parent, using a distinct verification-only era
    // proof. The wider parent never escapes as a metadata/writer context.
    std::unique_ptr<AppleEncryptedSnapshotReadContext> CreateRetainedSnapshotVerificationContext(
        std::uint64_t checkpoint_xid, std::string& error);
    EncryptedReadError ValidateSnapshotNamespace(AppleEncryptedSnapshotReadContext& context,
        std::uint64_t exact_snapshot_xid, EncryptedNamespaceInfo& output, std::string& error);
    EncryptedReadError ValidateSnapshotParentNamespace(AppleEncryptedSnapshotReadContext& context,
        EncryptedNamespaceInfo& output, std::string& error);
    // Validates the minted earlier selection with the existing namespace
    // projector. Uses this session's authority and budget; exports scalars only.
    EncryptedReadError ValidateRetainedNamespace(AppleEncryptedMetadataReadContext& context,
        EncryptedNamespaceInfo& output, std::string& error);
    // Private image preparation: one exclusively owned existing 4 KiB extent,
    // unchanged EOF and inode records. Exact source and current XID required.
    // Failure returns no executable candidate.
    std::unique_ptr<EncryptedCowOverwrite> PrepareCowOverwrite(
        const ImmutableEncryptedReadSource& expected_source, std::uint64_t expected_checkpoint_xid,
        std::uint64_t inode_id, std::uint64_t offset, std::span<const std::byte> replacement,
        std::string& error, std::span<const std::uint64_t> required_checkpoint_xids = {});
    // Private regular-file preparation, up to 64 KiB EOF/payload, 4 KiB blocks
    // and supported leaf trees. Write can extend through a zero-filled gap;
    // Resize zero-fills growth and discards the truncated tail. Create requires
    // an available canonical name; Rename/Unlink require the exact source name.
    // Source generations remain allocated. Unsupported ownership/history refuses.
    // Locked staging failure returns EncryptedCowLockedStagingCapacityLimit with
    // the OS status. No pageable fallback or process working-set adjustment.
    // No mounted-write or journal admission.
    std::unique_ptr<EncryptedCowOverwrite> PrepareMutation(
        const ImmutableEncryptedReadSource& expected_source, std::uint64_t expected_checkpoint_xid,
        const EncryptedMutationRequest& request, std::string& error,
        std::span<const std::uint64_t> required_checkpoint_xids = {});
    // Dense exclusive-file delta preparation: at most 64 changed 4 KiB blocks
    // and 256 nodes per tree, including partial EOF tails and zero-filled growth.
    // EOF is not a plaintext staging bound. Ownership sets charge the session
    // budget; unsupported layouts/history and resource exhaustion still refuse.
    std::unique_ptr<EncryptedCowOverwrite> PrepareDeltaMutation(
        const ImmutableEncryptedReadSource&, std::uint64_t expected_checkpoint_xid,
        const EncryptedMutationRequest&, std::string& error,
        std::span<const std::uint64_t> required_checkpoint_xids = {});
    // All metadata APIs are serialized, bounded and revalidate the held source
    // before publication. Non-success resets scalar outputs / empties vectors;
    // no partial namespace is ever advertised as complete. Inode-only legacy
    // inputs remain readable but these APIs return NamespaceUnavailable.
    // Successful outputs are ordinary caller-owned decrypted metadata: caller
    // must wipe/release them when done. Close cannot wipe previously returned
    // copies. Inputs must not alias output storage, which is reset on entry.
    // Session wipes retained names, lookup keys, xattrs and decoded xfield
    // bytes. Allocator/library/OS copies are outside that cleanup guarantee.
    EncryptedReadError GetNamespaceInfo(EncryptedNamespaceInfo& output);
    EncryptedReadError GetMetadata(std::uint64_t inode_id, EncryptedNodeInfo& output);
    EncryptedReadError ListDirectory(std::uint64_t parent_id, std::vector<EncryptedDirectoryEntry>& output);
    // APFS policy from the bound APSB is authoritative, including Unicode 9
    // normalization/case folding. No locale fold, wildcard, dot or dotdot lookup.
    EncryptedReadError Lookup(std::uint64_t parent_id, std::string_view name_utf8, EncryptedDirectoryEntry& output);
    EncryptedReadError LookupWindows(std::uint64_t parent_id, std::wstring_view name, EncryptedDirectoryEntry& output);
    // Absolute canonical Windows projection: \ root, \ separators, <=32768
    // UTF-16 units. Empty/dot components, trailing separators and slash refused.
    EncryptedReadError ResolvePath(std::wstring_view path, EncryptedNodeInfo& output);
    EncryptedReadError ListXattrs(std::uint64_t inode_id, std::vector<EncryptedXattr>& output);
    // Xattr names use exact UTF-8 byte comparison, independent of directory policy.
    EncryptedReadError ReadXattr(std::uint64_t inode_id, std::string_view name_utf8, std::vector<std::byte>& output);
    // Cancellation is sticky. Close first cancels, then waits for the serialized
    // reader to drain, wipes the VEK and clears session-local metadata.
    void Cancel() noexcept;
    void Close() noexcept;

#ifdef APFSACCESS_CRYPTO_TESTING
    // Deterministic vector injection only. Absent from production builds.
    static std::unique_ptr<ApfsEncryptedReadSession> OpenForTesting(
        std::shared_ptr<const ImmutableEncryptedReadSource> source,
        PasswordUnlockResult key, EncryptedReadError& error,
        std::shared_ptr<const std::atomic<bool>> cancellation = {});
#endif
private:
    friend class AppleEncryptedMetadataReadContext;
    friend class AppleEncryptedSnapshotReadContext;
    friend class ApfsEncryptedImageWriteSession;
    EncryptedReadError ValidateSnapshotNamespaceImpl(AppleEncryptedSnapshotReadContext&,
        std::optional<std::uint64_t> exact_snapshot_xid, EncryptedNamespaceInfo&, std::string& error);
    friend class SoftwareKeybagRewrap;
    std::unique_ptr<AppleEncryptedMetadataReadContext> CreateHistoricalKeybagEraContext(
        std::uint64_t checkpoint_xid, std::string& error);
    PasswordUnlockResult CopyKeyForImageWriter(EncryptedReadError& error);
    static std::unique_ptr<ApfsEncryptedReadSession> OpenImageWriterView(
        std::shared_ptr<const ImmutableEncryptedReadSource>, const PasswordUnlockResult&,
        const PasswordUnlockRequest&, EncryptedReadError&);
    static std::unique_ptr<ApfsEncryptedReadSession> OpenImageWriterView(
        std::shared_ptr<const ImmutableEncryptedReadSource>, const PasswordUnlockResult&,
        const PasswordUnlockRequest&, EncryptedReadError&, std::shared_ptr<const std::atomic<bool>>);
    static std::unique_ptr<ApfsEncryptedReadSession> OpenImageWriterView(
        std::shared_ptr<const ImmutableEncryptedReadSource>, const PasswordUnlockResult&,
        const PasswordUnlockRequest&, EncryptedReadError&, std::shared_ptr<const std::atomic<bool>>,
        std::uint64_t retained_checkpoint_xid);
    std::unique_ptr<EncryptedCowOverwrite> PrepareDeltaMutationWithReadPins(
        const ImmutableEncryptedReadSource&, std::uint64_t, const EncryptedMutationRequest&,
        std::string&, std::span<const std::uint64_t> recovery_pins, std::span<const std::uint64_t> read_pins);
    std::unique_ptr<EncryptedCowOverwrite> PrepareDeltaMutationWithTransitionRetention(
        const ImmutableEncryptedReadSource&, std::uint64_t, const EncryptedMutationRequest&,
        const SoftwareVolumeRetainedOwners&, const std::array<std::byte, 32>& actual_original_journal_identity,
        std::string&, std::span<const std::uint64_t> recovery_pins, std::span<const std::uint64_t> read_pins);
    struct Impl;
    explicit ApfsEncryptedReadSession(std::shared_ptr<Impl> impl);
    std::shared_ptr<Impl> impl_;
};
} // namespace apfsaccess::catalog
