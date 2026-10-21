#pragma once

#include "ApfsEncryptedImageWriteSession.h"
#include <filesystem>
#include <functional>

namespace apfsaccess::catalog
{
// One runtime owns the exclusive image, original WAL, protected payload spool
// and publication witness. Recovery and ordinary commits use the same gate.
class EncryptedImageRuntime final
{
public:
    static constexpr std::size_t MaxWriteBytes = 65536;
    static constexpr std::size_t MaxEmbeddedXattrBytes = 3804;
    struct Options
    {
        ApfsEncryptedImageWriteSession::Image image;
        std::filesystem::path recovery_directory;
        std::uint64_t journal_bytes = 64ull << 20;
        std::uint64_t payload_bytes = 64ull << 20;
    };
    struct Status
    {
        EncryptedImageWriteStatus image;
        std::uint64_t accepted = 0, durable = 0, cleaned = 0;
        bool recovery_required = false, closed = false;
    };
    enum class DurableBoundary : std::uint8_t
    {
        OriginalSpoolBarrier, IntentFlushed, RecoveryBarrier, ControlRenamed,
        CertificatePromoted, CandidateFlushed, OldRenamed, NewRenamed,
        CompletionReceipt, RetirementReceipt, ReadyReceipt, PublicationReconciled
    };
    // Borrowed only during one synchronous Apply. Diagnostic stage strings do
    // not construct these completed-barrier observations.
    class DurableProgress final
    {
    public:
        DurableProgress(const DurableProgress&) = delete;
        DurableProgress(DurableProgress&&) = delete;
        DurableProgress& operator=(const DurableProgress&) = delete;
        DurableProgress& operator=(DurableProgress&&) = delete;
        const EncryptedImageRuntime* Owner() const noexcept { return owner_; }
        std::uint64_t Invocation() const noexcept { return invocation_; }
        std::uint64_t Ordinal() const noexcept { return ordinal_; }
        std::uint8_t Slot() const noexcept { return slot_; }
        DurableBoundary Boundary() const noexcept { return boundary_; }
    private:
        friend class EncryptedImageRuntime;
        DurableProgress(const EncryptedImageRuntime* owner, std::uint64_t invocation,
            std::uint64_t ordinal, std::uint8_t slot, DurableBoundary boundary)
            : owner_(owner), invocation_(invocation), ordinal_(ordinal), slot_(slot), boundary_(boundary) {}
        const EncryptedImageRuntime* owner_;
        std::uint64_t invocation_, ordinal_;
        std::uint8_t slot_;
        DurableBoundary boundary_;
    };
    using ProgressHook = std::function<bool(const DurableProgress&)>;

    static std::unique_ptr<EncryptedImageRuntime> Open(const Options&, std::string& error);
    ~EncryptedImageRuntime();
    EncryptedImageRuntime(const EncryptedImageRuntime&) = delete;
    EncryptedImageRuntime& operator=(const EncryptedImageRuntime&) = delete;

    bool Unlock(const crypto::SecureBytes&, PasswordUnlockBudget&, std::string& error);
    // Complete private software-keybag maintenance under this runtime's image
    // and protected journal gate. Success leaves the owner locked; callers must
    // unlock again with the newly published canonical password before data I/O.
    bool ChangePassword(const crypto::SecureBytes& old_password,
        const crypto::SecureBytes& new_password, PasswordUnlockBudget&, std::string& error,
        const rw::AppleCheckpointStageHook& hook = {});
    bool Encrypt(const crypto::SecureBytes&, PasswordUnlockBudget&, std::string& error,
        const rw::AppleCheckpointStageHook& hook = {});
    bool Decrypt(const crypto::SecureBytes&, PasswordUnlockBudget&, std::string& error,
        const rw::AppleCheckpointStageHook& hook = {});
    bool RotateVolumeKey(const crypto::SecureBytes& old_password, const crypto::SecureBytes& new_password,
        PasswordUnlockBudget&, std::string& error, const rw::AppleCheckpointStageHook& hook = {});
    // One Write is bounded by MaxWriteBytes; callers split larger I/O and report
    // each completed prefix. Success includes APFS publication and cleanup.
    // Failed preparation leaves the original WAL unaccepted.
    bool Apply(const EncryptedMutationRequest&, std::uint64_t& result_inode,
        std::string& error, const rw::AppleCheckpointStageHook& hook = {});
    bool Apply(const EncryptedMutationRequest&, std::uint64_t& result_inode,
        std::string& error, const rw::AppleCheckpointStageHook&, const ProgressHook&);
    // Each completed prefix is durable. On failure, completed_bytes excludes
    // the failed transaction and lets a mounted caller report a short write.
    bool Write(std::uint64_t inode, std::uint64_t offset, std::span<const std::byte>,
        std::size_t& completed_bytes, std::string& error,
        const rw::AppleCheckpointStageHook& hook = {});
    bool Write(std::uint64_t inode, std::uint64_t offset, std::span<const std::byte>,
        std::size_t& completed_bytes, std::string& error,
        const rw::AppleCheckpointStageHook&, const ProgressHook&);
    bool Recover(std::string& error, const rw::AppleCheckpointStageHook& hook = {});
    std::shared_ptr<ApfsEncryptedReadSession> OpenReadView(EncryptedReadError& error);
    using ReadInode = ApfsEncryptedImageWriteSession::ReadInode;
    std::shared_ptr<ReadInode> RetainReadInode(std::uint64_t inode, std::string& error);
    std::shared_ptr<ApfsEncryptedReadSession> OpenReadView(const ReadInode&, EncryptedReadError& error);
    Status CachedStatus() const noexcept;
    bool CachedPersistenceStateValid() const noexcept;
    const std::string& SourceIdentity() const noexcept;
    const std::string& ContainerUuid() const noexcept;
    const std::string& VolumeUuid() const noexcept;
    std::uint64_t VolumeObjectId() const noexcept;
    std::optional<PasswordUnlockRequest> UnlockedSelection() const;
    // Public selectors only, observed on the held image at an authenticated clean boundary.
    bool ObserveKeyManagementEndpoint(ImageKeyManagementEndpoint&, std::string& error);
    // Sticky signal for the out-of-provider watchdog. Does not wait for the
    // serialized commit gate; Close subsequently drains and releases ownership.
    void Cancel() noexcept;
    void Lock() noexcept;
    void Close() noexcept;

private:
    struct Impl;
    explicit EncryptedImageRuntime(std::unique_ptr<Impl>);
    std::unique_ptr<Impl> impl_;
};
}
