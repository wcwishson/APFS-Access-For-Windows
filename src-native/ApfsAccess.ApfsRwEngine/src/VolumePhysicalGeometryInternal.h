#pragma once
#include "VolumePhysicalGeometry.h"
#include "VolumeGptGeometry.h"
#include <mutex>

namespace apfsaccess::rw
{
struct VolumePhysicalGeometrySource::Impl
{
    RawSnapshotBinding original;
    std::wstring instance;
    mutable std::mutex gate;
    bool poisoned = false, authorized = false, completed = false;
    std::optional<volume_geometry::Plan> plan;
    std::function<bool()> current, flush, refresh, retire;
    std::function<bool(std::uint64_t,std::size_t,std::vector<std::byte>&)> read;
    std::function<bool(std::uint64_t,std::span<const std::byte>)> write;
    std::function<bool(std::uint64_t,std::size_t)> zero;
    std::function<std::shared_ptr<VolumePhysicalSource>(const RawSnapshotBinding&,std::string&)> rebind;
    bool Current() { if(poisoned)return false;if(current())return true;poisoned=true;return false; }
    bool Result(bool ok) { if(!ok)poisoned=true;return ok; }
};
struct VolumePhysicalGeometryAccess
{
    static void Authorize(const std::shared_ptr<VolumePhysicalGeometrySource>&,const volume_geometry::Plan&);
    static void BindPlan(const std::shared_ptr<VolumePhysicalGeometrySource>&,const volume_geometry::Plan&);
    static std::optional<volume_geometry::Plan> BoundPlan(const std::shared_ptr<VolumePhysicalGeometrySource>&);
    static bool ReadWindow(const VolumePhysicalGeometrySource&,std::uint64_t,std::size_t,std::vector<std::byte>&);
    static bool WriteWindow(VolumePhysicalGeometrySource&,std::uint64_t,std::span<const std::byte>);
    static bool Flush(VolumePhysicalGeometrySource&);
    static bool ZeroWindow(VolumePhysicalGeometrySource&,std::uint64_t,std::size_t);
    static void PublishGpt(const std::shared_ptr<VolumePhysicalGeometrySource>&,const AppleCheckpointStageHook&);
    static void MarkComplete(const std::shared_ptr<VolumePhysicalGeometrySource>&);
    static std::shared_ptr<VolumePhysicalSource> Rebind(const std::shared_ptr<VolumePhysicalGeometrySource>&,std::string&);
};
}
