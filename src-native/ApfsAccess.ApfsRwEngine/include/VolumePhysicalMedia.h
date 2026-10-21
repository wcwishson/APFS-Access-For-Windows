#pragma once
#include "ApfsFormat.h"
#include "AppleCheckpointPublisher.h"
#include "RawSnapshotBinding.h"
#include <filesystem>
#include <memory>

namespace apfsaccess::rw
{
class BlockDevice;
// Matches the managed production identity's native GUID byte ordering. Pure
// encoding only; the binding must come from held physical authority.
std::string DeriveVolumePhysicalRecoveryIdentity(const RawSnapshotBinding&, std::string_view container_uuid, std::uint64_t oid);
class VolumePhysicalSource final : public catalog::RandomAccessSource, public AppleCheckpointWriteTarget
{
public:
    ~VolumePhysicalSource();
    VolumePhysicalSource(const VolumePhysicalSource&) = delete;
    VolumePhysicalSource& operator=(const VolumePhysicalSource&) = delete;
    // The caller already owns the exclusive raw writer. This never opens one.
    static std::shared_ptr<VolumePhysicalSource> BindHeldRaw(std::shared_ptr<BlockDevice>,
        const RawSnapshotBinding& expected, std::wstring_view expected_instance, std::string& error);
    static std::shared_ptr<VolumePhysicalSource> OpenExclusiveRaw(const RawSnapshotBinding& expected,
        std::wstring_view expected_instance, std::string& error, std::wstring_view selected_device = {});
    static std::shared_ptr<VolumePhysicalSource> ObserveExclusiveRaw(std::wstring_view selected_physical_path,
        std::wstring_view expected_instance, std::uint64_t base_offset_bytes, std::uint64_t limit_bytes,
        const RawHardwareQualification& qualification, std::string& error);
    // Aliasing ownership keeps this complete source capability alive in the
    // existing MetadataStore device field. No device reopen or new admission.
    static std::shared_ptr<BlockDevice> RetainMetadataDevice(const std::shared_ptr<VolumePhysicalSource>&,
        const RawSnapshotBinding& trusted_binding, std::wstring_view trusted_instance, std::string& error);
    bool OwnsMetadataDevice(const BlockDevice&, std::string& error) const;
    std::uint64_t SizeBytes() const override;
    bool Read(std::uint64_t, std::size_t, std::vector<std::byte>&) const override;
    bool ReadBlock(std::uint64_t, std::uint32_t, std::vector<std::byte>&) override;
    bool ReadBlockRangeForVerification(std::uint64_t, std::uint32_t, std::size_t, std::vector<std::byte>&) override;
    bool WriteBlock(std::uint64_t, std::span<const std::byte>) override;
    bool Flush() override;
    bool ZeroRange(std::uint64_t, std::size_t);
    bool Revalidate() const;
    const RawSnapshotBinding& Binding() const;
    const std::wstring& InstanceId() const;
    const std::string& Identity() const;
    // Read-only verification of completed geometry evidence on this same lease.
    bool VerifyCompletedGeometry(std::span<const std::byte> encoded_plan, std::string& error) const;
private:
    friend struct VolumePhysicalKeeperTestPeer;
    struct Impl;
    explicit VolumePhysicalSource(std::unique_ptr<Impl>);
    std::unique_ptr<Impl> impl_;
};
}
