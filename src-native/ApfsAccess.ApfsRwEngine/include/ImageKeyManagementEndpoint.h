#pragma once

#include "SoftwareVolumeTransition.h"
#include <optional>

namespace apfsaccess::catalog
{
// Public canonical observations under the actual owner gate. These selectors
// grant neither allocator authority nor an unlocked reader/key capability.
struct ImageKeyManagementEndpoint
{
    std::string source_identity, container_uuid, volume_uuid;
    std::uint64_t checkpoint_xid = 0, volume_object_id = 0;
    SoftwareVolumeMode mode = SoftwareVolumeMode::Plain;
    std::optional<PasswordUnlockRequest> encrypted_selection;
};
}
