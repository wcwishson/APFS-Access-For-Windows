#pragma once
#include "VolumePhysicalMedia.h"

namespace apfsaccess::rw
{
struct VolumePhysicalGeometryAccess;
// Separate disk geometry lifetime. It cannot be used as a MetadataStore owner.
class VolumePhysicalGeometrySource final : public catalog::RandomAccessSource
{
public:
    ~VolumePhysicalGeometrySource();
    VolumePhysicalGeometrySource(const VolumePhysicalGeometrySource&) = delete;
    VolumePhysicalGeometrySource& operator=(const VolumePhysicalGeometrySource&) = delete;
    static std::shared_ptr<VolumePhysicalGeometrySource> OpenExclusiveRaw(const RawSnapshotBinding& original,
        std::wstring_view instance, std::string& error, std::wstring_view selected_device = {});
    std::uint64_t SizeBytes() const override;
    bool Read(std::uint64_t, std::size_t, std::vector<std::byte>&) const override;
    bool Revalidate() const;
    const RawSnapshotBinding& OriginalBinding() const;
    const std::wstring& InstanceId() const;
private:
    friend struct VolumePhysicalGeometryAccess;
    friend struct VolumePhysicalGeometryTestPeer;
    struct Impl;
    explicit VolumePhysicalGeometrySource(std::unique_ptr<Impl>);
    std::unique_ptr<Impl> impl_;
};
}
