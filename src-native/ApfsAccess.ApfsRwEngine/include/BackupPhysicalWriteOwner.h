#pragma once
#include "BackupRetainedSource.h"
#include "MetadataStore.h"
#include "PayloadSpool.h"
#include "TransactionManager.h"
#include <mutex>

namespace apfsaccess::rw
{
// The host retains its original startup census, G08 capability and journal/spool
// gates. This owner never opens a device, creates an original, or grants admission
// from serialized caller fields. Unsupported mutations have no fallback.
class BackupPhysicalWriteOwner final
{
public:
    struct Selection
    {
        std::string container_uuid, volume_uuid;
        std::uint64_t volume_oid = 0, checkpoint_xid = 0;
    };
    enum class WriteResult { Committed, Refused, RecoveryRequired };
    static std::unique_ptr<BackupPhysicalWriteOwner> Bind(
        const std::shared_ptr<VolumePhysicalSource>& held, const RawSnapshotBinding& trusted_binding,
        std::wstring_view trusted_instance, const Selection&, TransactionManager&, PayloadSpool&,
        const std::filesystem::path& original_path, std::string& error);
    bool Recover(std::string& error, const AppleCheckpointStageHook& hook = {});
    using PostpublicationVerifier = std::function<bool(const MetadataStore&, std::string&)>;
    bool RecoverWithVerification(std::string& error, const PostpublicationVerifier&,
        const AppleCheckpointStageHook& hook = {});
    // Single ownership handoff after proven cleanup; this retires the facade.
    std::unique_ptr<MetadataStore> TakeVerifiedStore(std::string& error);
    // Host retains its namespace/spool finalization boundary. The exact original
    // is APFS-durable here, but remains uncleaned until those checks finish.
    std::unique_ptr<MetadataStore> PublishAcceptedForHost(std::string& error,
        const PostpublicationVerifier& = {}, const AppleCheckpointStageHook& = {});
    WriteResult Write(const std::wstring& path, std::uint64_t offset, std::span<const std::byte> bytes,
        std::string& error, const AppleCheckpointStageHook& hook = {});
    WriteResult Apply(const MetadataStore::MutationRequest&, std::span<const std::byte> write_bytes,
        std::string& error, const AppleCheckpointStageHook& hook = {});
    bool Read(const std::wstring& path, std::uint64_t offset, std::size_t count,
        std::vector<std::byte>& bytes);
    std::optional<MetadataStore::InodeRecord> Metadata(const std::wstring& path);
    bool RecoveryRequired() const;
    std::uint64_t CheckpointXid() const;
private:
    BackupPhysicalWriteOwner(std::shared_ptr<VolumePhysicalSource>, TransactionManager&, PayloadSpool&,
        std::filesystem::path);
    bool Available(std::string&) const;
    bool Reload(std::string&);
    bool RecoverLocked(std::string&, const AppleCheckpointStageHook&, const PostpublicationVerifier& = {}, bool cleanup = true);
    bool RebuildSpool(const TransactionManager::RetainedAcceptedHistory&, std::string&);
    bool Fail(std::string&, const char*);
    mutable std::mutex gate_;
    std::shared_ptr<VolumePhysicalSource> held_;
    std::unique_ptr<BackupRetainedSource> source_;
    std::unique_ptr<MetadataStore> store_;
    MetadataStore::VolumeContext context_;
    TransactionManager& original_;
    PayloadSpool& spool_;
    std::filesystem::path original_path_;
    bool failed_ = false;
};
}
