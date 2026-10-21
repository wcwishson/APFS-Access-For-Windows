#pragma once
#include "AppleCheckpointPublisher.h"

namespace apfsaccess::catalog
{
class SoftwareKeybagRewrap;
// Privately minted, exact source-bound canonical ciphertext publication. No
// credentials or unwrapped keys. Protected journal staging is Root-owned and
// is required before this becomes a durable supported maintenance operation.
class SoftwareKeybagPublication final
{
public:
    SoftwareKeybagPublication(const SoftwareKeybagPublication&) = delete;
    const rw::AppleCheckpointPublicationPlan& Publication() const noexcept { return publication_; }
    const std::string& SourceIdentity() const noexcept { return identity_; }
    std::uint64_t VolumeObjectId() const noexcept { return volume_oid_; }
    const std::string& VolumeUuid() const noexcept { return volume_uuid_; }
    std::uint64_t OldContainerBagBlock() const noexcept { return old_container_; }
    std::uint64_t OldVolumeBagBlock() const noexcept { return old_volume_; }
    std::uint64_t NewContainerBagBlock() const noexcept { return new_container_; }
    std::uint64_t NewVolumeBagBlock() const noexcept { return new_volume_; }
    const std::vector<std::uint64_t>& RetainedCheckpoints() const noexcept { return retained_; }
    std::size_t RetiredCheckpoints() const noexcept { return retired_; }
private:
    friend class SoftwareKeybagRewrap;
    SoftwareKeybagPublication() = default;
    rw::AppleCheckpointPublicationPlan publication_;
    std::string identity_;
    std::uint64_t volume_oid_ = 0;
    std::string volume_uuid_;
    std::uint64_t old_container_=0,old_volume_=0,new_container_=0,new_volume_=0;
    std::vector<std::uint64_t> retained_;
    std::size_t retired_=0;
};
} // namespace apfsaccess::catalog
