#pragma once
#include "BackupImageWriterProfile.h"
#include "BlockDevice.h"
#include "VolumePhysicalMedia.h"

namespace apfsaccess::rw
{
// Retains an existing owner. Neither factory opens a path or admits a writer.
class BackupRetainedSource final : public catalog::RandomAccessSource
{
public:
    // Observation envelope only. Write authority still requires the live G08
    // source factory and the complete canonical backup profile below.
    static bool DecodePhysicalBinding(std::span<const std::byte>, RawSnapshotBinding&,
        std::wstring& instance, std::string& error);
    static std::unique_ptr<BackupRetainedSource> WholeImage(std::shared_ptr<BlockDevice> device,
        const catalog::AppleCheckpointView& selected, std::uint64_t oid, std::string& error)
    {
        error.clear();
        if (!device || !device->IsRegularFile() || device->BaseOffsetBytes())
        { error = "BackupRetainedImageOwnerRequired"; return {}; }
        auto owner = std::unique_ptr<BackupRetainedSource>(new BackupRetainedSource(std::move(device)));
        return owner->Admit(selected, oid, error) ? std::move(owner) : nullptr;
    }

    static std::unique_ptr<BackupRetainedSource> HeldPhysical(const std::shared_ptr<VolumePhysicalSource>& held,
        const RawSnapshotBinding& trusted_binding, std::wstring_view trusted_instance,
        const catalog::AppleCheckpointView& selected, std::uint64_t oid, std::string& error)
    {
        error.clear();
        auto device = VolumePhysicalSource::RetainMetadataDevice(held, trusted_binding, trusted_instance, error);
        if (!device) return {};
        auto owner = std::unique_ptr<BackupRetainedSource>(new BackupRetainedSource(std::move(device)));
        owner->physical_ = held;
        owner->binding_ = trusted_binding;
        owner->instance_ = trusted_instance;
        if (!owner->Admit(selected, oid, error)) return {};
        owner->recovery_identity_ = DeriveVolumePhysicalRecoveryIdentity(trusted_binding,
            selected.container.superblock.uuid_hex, oid);
        try { owner->journal_binding_ = PhysicalJournalBinding(trusted_binding, trusted_instance,
            selected.container.superblock.uuid_hex, selected.volumes.front().superblock.uuid_hex, oid); }
        catch (...) { error = "BackupPhysicalOriginalBindingFailed"; return {}; }
        return owner;
    }

    BackupRetainedSource(const BackupRetainedSource&) = delete;
    BackupRetainedSource& operator=(const BackupRetainedSource&) = delete;
    std::uint64_t SizeBytes() const override
    { return physical_ ? binding_.media.limit_bytes : device_->GetGeometry().total_bytes; }

    bool Read(std::uint64_t offset, std::size_t count, std::vector<std::byte>& bytes) const override
    {
        bytes.clear();
        if (!Current() || offset > SizeBytes() || count > SizeBytes() - offset || count > (4u << 20)) return false;
        if (!count) return Current();
        if (physical_) return physical_->Read(offset, count, bytes) && bytes.size() == count && Current();
        const auto begin = offset - offset % 4096;
        const auto prefix = static_cast<std::size_t>(offset - begin);
        const auto length = (prefix + count + 4095) / 4096 * 4096;
        if (length > SizeBytes() - begin || !device_->ReadForVerification(begin, length, bytes) ||
            bytes.size() != length || !Current()) { bytes.clear(); return false; }
        bytes.erase(bytes.begin(), bytes.begin() + prefix);
        bytes.resize(count);
        return true;
    }

    bool Current() const
    {
        if (!observation_) return false;
        if (!physical_) return device_->IsExclusiveWriteSourceObservationCurrent(*observation_) &&
            device_->IsRegularFile() && !device_->BaseOffsetBytes();
        // G08 retains the handle/window lease across this owner's own writes.
        // No-I/O planning and proof separately pin a fresh byte generation.
        std::string error;
        return physical_->Binding() == binding_ && physical_->InstanceId() == instance_ &&
            physical_->OwnsMetadataDevice(*device_, error) && physical_->Revalidate();
    }

    bool Matches(const BlockDevice& device, std::uint64_t context_offset,
        const catalog::AppleCheckpointView& checkpoint, std::uint64_t oid, std::string_view recovery_identity) const
    {
        return &device == device_.get() && context_offset == device_->BaseOffsetBytes() &&
            oid == oid_ && checkpoint.volumes.size() == 1 &&
            checkpoint.container.superblock.uuid_hex == container_uuid_ &&
            checkpoint.volumes.front().superblock.uuid_hex == volume_uuid_ &&
            checkpoint.volumes.front().superblock.object_id == oid_ &&
            (!physical_ || recovery_identity == recovery_identity_) && Current();
    }

    bool MatchesCheckpoint(const catalog::AppleCheckpointView& checkpoint) const
    {
        return checkpoint.volumes.size() == 1 && checkpoint.container.superblock.uuid_hex == container_uuid_ &&
            checkpoint.volumes.front().superblock.uuid_hex == volume_uuid_ &&
            checkpoint.volumes.front().superblock.object_id == oid_ && Current();
    }

    bool Flush() const
    { return Current() && (physical_ ? physical_->Flush() : device_->Flush()) && Current(); }

    const std::string& RecoveryIdentity() const { return recovery_identity_; }
    const std::optional<std::array<std::byte, 32>>& JournalSourceBinding() const { return journal_binding_; }
    bool IsPhysical() const { return physical_ != nullptr; }

private:
    static std::array<std::byte, 32> PhysicalJournalBinding(const RawSnapshotBinding&, std::wstring_view,
        std::string_view container_uuid, std::string_view volume_uuid, std::uint64_t oid);
    explicit BackupRetainedSource(std::shared_ptr<BlockDevice> device) : device_(std::move(device)) {}
    bool Admit(const catalog::AppleCheckpointView& selected, std::uint64_t oid, std::string& error)
    {
        observation_ = device_->CaptureExclusiveWriteSourceObservation();
        if (!Current() || SizeBytes() == 0 || SizeBytes() > (256ull << 20) || SizeBytes() % 4096 ||
            selected.volumes.size() != 1 || selected.volumes.front().superblock.object_id != oid)
        { error = "BackupRetainedSourceAuthorityUnproven"; return false; }
        const auto fresh = catalog::LoadAppleCheckpointView(*this, 0, SizeBytes(), error);
        if (!fresh || fresh->container.superblock_bytes != selected.container.superblock_bytes ||
            fresh->container.superblock_physical_block != selected.container.superblock_physical_block ||
            fresh->volumes.size() != 1 ||
            fresh->volumes.front().superblock_object.physical_block != selected.volumes.front().superblock_object.physical_block ||
            fresh->volumes.front().superblock.xid != selected.volumes.front().superblock.xid ||
            fresh->volumes.front().superblock.uuid_hex != selected.volumes.front().superblock.uuid_hex ||
            !ValidateBackupImageWriterProfile(*this, selected, oid, error) || !Current() ||
            !device_->IsExclusiveWriteSourceObservationCurrent(*observation_))
        { if (error.empty()) error = "BackupRetainedSourceCheckpointMismatch"; return false; }
        container_uuid_ = selected.container.superblock.uuid_hex;
        volume_uuid_ = selected.volumes.front().superblock.uuid_hex;
        oid_ = oid;
        return true;
    }

    std::shared_ptr<BlockDevice> device_;
    std::shared_ptr<VolumePhysicalSource> physical_;
    std::optional<BlockDevice::WriteSourceObservation> observation_;
    RawSnapshotBinding binding_;
    std::wstring instance_;
    std::string container_uuid_, volume_uuid_, recovery_identity_;
    std::optional<std::array<std::byte, 32>> journal_binding_;
    std::uint64_t oid_ = 0;
};
}
