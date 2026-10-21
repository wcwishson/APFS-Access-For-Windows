#include "VolumePhysicalGeometryInternal.h"

namespace apfsaccess::rw
{
using format_evidence::Need;
VolumePhysicalGeometrySource::VolumePhysicalGeometrySource(std::unique_ptr<Impl> impl):impl_(std::move(impl)){}
VolumePhysicalGeometrySource::~VolumePhysicalGeometrySource()=default;
std::uint64_t VolumePhysicalGeometrySource::SizeBytes() const{return impl_->original.media.disk_size_bytes;}
const RawSnapshotBinding& VolumePhysicalGeometrySource::OriginalBinding() const{return impl_->original;}
const std::wstring& VolumePhysicalGeometrySource::InstanceId() const{return impl_->instance;}
bool VolumePhysicalGeometrySource::Revalidate() const{std::lock_guard lock(impl_->gate);return impl_->Current();}
bool VolumePhysicalGeometrySource::Read(std::uint64_t offset,std::size_t size,std::vector<std::byte>& out) const
{
    out.clear();std::lock_guard lock(impl_->gate);
    const auto sector=impl_->original.media.logical_sector_bytes;
    if(!size || size>(4u<<20) || offset>SizeBytes() || size>SizeBytes()-offset || !impl_->Current())return false;
    const auto begin=offset-offset%sector,end=(offset+size+sector-1)/sector*sector;
    std::vector<std::byte> bytes;
    if(!impl_->Result(impl_->read(begin,static_cast<std::size_t>(end-begin),bytes) && bytes.size()==end-begin) || !impl_->Current())return false;
    out.assign(bytes.begin()+offset-begin,bytes.begin()+offset-begin+size);return true;
}
void VolumePhysicalGeometryAccess::BindPlan(const std::shared_ptr<VolumePhysicalGeometrySource>& source,const volume_geometry::Plan& plan)
{
    Need(source && source->Revalidate() && source->OriginalBinding()==plan.snapshot.original.binding &&
        source->InstanceId()==plan.snapshot.original.instance,"VolumeGeometryAuthorizationScopeMismatch");
    std::lock_guard lock(source->impl_->gate);
    Need(!source->impl_->plan || volume_geometry::Encode(*source->impl_->plan)==volume_geometry::Encode(plan),"VolumeGeometryAuthorizationChanged");
    source->impl_->plan=plan;
}
void VolumePhysicalGeometryAccess::Authorize(const std::shared_ptr<VolumePhysicalGeometrySource>& source,const volume_geometry::Plan& plan)
{BindPlan(source,plan);std::lock_guard lock(source->impl_->gate);source->impl_->authorized=true;}
std::optional<volume_geometry::Plan> VolumePhysicalGeometryAccess::BoundPlan(const std::shared_ptr<VolumePhysicalGeometrySource>& source)
{Need(!!source,"VolumeGeometryHeldSourceRequired");std::lock_guard lock(source->impl_->gate);return source->impl_->plan;}
bool VolumePhysicalGeometryAccess::ReadWindow(const VolumePhysicalGeometrySource& source,std::uint64_t offset,std::size_t size,std::vector<std::byte>& out)
{
    std::uint64_t base=0,limit=0;
    {std::lock_guard lock(source.impl_->gate);const auto& original=source.impl_->original;
        base=original.media.base_offset_bytes;
        limit=source.impl_->plan?(std::max)(original.media.limit_bytes,source.impl_->plan->snapshot.target_bytes):original.media.limit_bytes;}
    if(offset>limit || size>limit-offset)return false;
    return source.Read(base+offset,size,out);
}
bool VolumePhysicalGeometryAccess::WriteWindow(VolumePhysicalGeometrySource& source,std::uint64_t block,std::span<const std::byte> bytes)
{
    std::lock_guard lock(source.impl_->gate);auto& impl=*source.impl_;
    if(!impl.authorized || !impl.plan || block>=impl.plan->snapshot.target_bytes/4096 || bytes.size()!=4096 || !impl.Current())return false;
    return impl.Result(impl.write(impl.original.media.base_offset_bytes+block*4096,bytes)) && impl.Current();
}
bool VolumePhysicalGeometryAccess::Flush(VolumePhysicalGeometrySource& source)
{std::lock_guard lock(source.impl_->gate);return source.impl_->authorized && source.impl_->Current() && source.impl_->Result(source.impl_->flush()) && source.impl_->Current();}
bool VolumePhysicalGeometryAccess::ZeroWindow(VolumePhysicalGeometrySource& source,std::uint64_t offset,std::size_t size)
{
    std::lock_guard lock(source.impl_->gate);auto& impl=*source.impl_;
    return impl.authorized && impl.plan && size && size<=(4u<<20) && offset%4096==0 && size%4096==0 &&
        offset<=impl.plan->snapshot.target_bytes && size<=impl.plan->snapshot.target_bytes-offset && impl.Current() &&
        impl.Result(impl.zero(impl.original.media.base_offset_bytes+offset,size)) && impl.Current();
}
void VolumePhysicalGeometryAccess::PublishGpt(const std::shared_ptr<VolumePhysicalGeometrySource>& source,const AppleCheckpointStageHook& hook)
{
    const auto plan=BoundPlan(source);
    {std::lock_guard lock(source->impl_->gate);Need(source->impl_->authorized && plan && source->impl_->Current(),"VolumeGeometryAcceptedAuthorityRequired");}
    volume_geometry::Publish(*plan,[&](auto offset,auto bytes){
        std::lock_guard lock(source->impl_->gate);auto& impl=*source->impl_;
        const auto found=std::find_if(impl.plan->writes.begin(),impl.plan->writes.end(),[&](const auto& w){return w.offset==offset && std::equal(bytes.begin(),bytes.end(),w.after.begin(),w.after.end());});
        return found!=impl.plan->writes.end() && impl.Current() && impl.Result(impl.write(offset,bytes)) && impl.Current();
    },[&]{return Flush(*source);},*source,hook);
    if (plan->snapshot.profile == volume_geometry::Profile::ContainerWindow) return;
    std::lock_guard lock(source->impl_->gate);
    Need(source->impl_->Current() && source->impl_->Result(source->impl_->refresh()) && source->impl_->Current(),"VolumeGeometryPartitionRefreshFailed");
}
void VolumePhysicalGeometryAccess::MarkComplete(const std::shared_ptr<VolumePhysicalGeometrySource>& source)
{
    const auto plan=BoundPlan(source);Need(plan.has_value(),"VolumeGeometryAcceptedAuthorityRequired");volume_geometry::Verify(*source,*plan,3);
    std::lock_guard lock(source->impl_->gate);Need(source->impl_->authorized && source->impl_->Current(),"VolumeGeometryAcceptedAuthorityRequired");source->impl_->completed=true;
}
std::shared_ptr<VolumePhysicalSource> VolumePhysicalGeometryAccess::Rebind(const std::shared_ptr<VolumePhysicalGeometrySource>& source,std::string& error)
{
    error.clear();Need(!!source,"VolumeGeometryCompletionRequired");RawSnapshotBinding binding;
    std::function<std::shared_ptr<VolumePhysicalSource>(const RawSnapshotBinding&,std::string&)> rebind;
    {std::lock_guard lock(source->impl_->gate);Need(source->impl_->completed && source->impl_->plan && source->impl_->Current(),"VolumeGeometryCompletionRequired");
        binding=source->impl_->plan->after;rebind=source->impl_->rebind;
        Need(source->impl_->Result(source->impl_->retire()),"VolumeGeometryRetirementFailed");source->impl_->poisoned=true;}
    auto fixed=rebind(binding,error);
    Need(fixed && fixed->Binding()==binding && fixed->InstanceId()==source->InstanceId() && fixed->Revalidate(),"VolumeGeometryRebindFailed");return fixed;
}
}
