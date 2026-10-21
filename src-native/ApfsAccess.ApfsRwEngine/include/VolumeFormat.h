#pragma once
#include "VolumeResize.h"
namespace apfsaccess::rw
{
// Explicit whole-container replacement of a verified ordinary APFS image.
// Format preserves unspecified free bytes; erase zeros all unowned blocks after
// publication. Neither is secure media erasure: the journal retains the original.
VolumeImageResult PrepareVolumeFormat(const VolumeImageRequest&);
VolumeImageResult ApplyVolumeFormat(const VolumeImageRequest&, std::string_view token,
    const AppleCheckpointStageHook& interrupt = {});
VolumeImageResult RecoverVolumeFormat(const VolumeImageRequest&, const AppleCheckpointStageHook& interrupt = {});
VolumeImageResult CancelVolumeFormat(const VolumeImageRequest&, std::string_view token);
}
