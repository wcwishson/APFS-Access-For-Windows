#pragma once
#include "VolumePhysicalMedia.h"
#include "VolumeResize.h"
#include "VolumePhysicalGeometry.h"

namespace apfsaccess::rw
{
// A trusted caller supplies an already-held source capability. Request.image
// must equal that capability's stable PNP instance, never a disk-number path.
// The initial physical profile is whole bound-window Format/Erase only.
VolumeImageResult PrepareVolumePhysicalFormat(const std::shared_ptr<VolumePhysicalSource>&,
    const VolumeImageRequest&);
VolumeImageResult ApplyVolumePhysicalFormat(const std::shared_ptr<VolumePhysicalSource>&,
    const VolumeImageRequest&, std::string_view confirmation, const AppleCheckpointStageHook& = {});
VolumeImageResult RecoverVolumePhysicalFormat(const std::shared_ptr<VolumePhysicalSource>&,
    const VolumeImageRequest&, const AppleCheckpointStageHook& = {});
VolumeImageResult CancelVolumePhysicalFormat(const std::shared_ptr<VolumePhysicalSource>&,
    const VolumeImageRequest&, std::string_view confirmation);
VolumeImageResult PrepareVolumePhysicalResize(const std::shared_ptr<VolumePhysicalGeometrySource>&,const VolumeImageRequest&);
VolumeImageResult ApplyVolumePhysicalResize(const std::shared_ptr<VolumePhysicalGeometrySource>&,const VolumeImageRequest&,
    std::string_view confirmation,const AppleCheckpointStageHook& = {},std::shared_ptr<VolumePhysicalSource>* rebound = nullptr);
VolumeImageResult RecoverVolumePhysicalResize(const std::shared_ptr<VolumePhysicalGeometrySource>&,const VolumeImageRequest&,
    const AppleCheckpointStageHook& = {},std::shared_ptr<VolumePhysicalSource>* rebound = nullptr);
VolumeImageResult CancelVolumePhysicalResize(const std::shared_ptr<VolumePhysicalGeometrySource>&,const VolumeImageRequest&,std::string_view);
}
