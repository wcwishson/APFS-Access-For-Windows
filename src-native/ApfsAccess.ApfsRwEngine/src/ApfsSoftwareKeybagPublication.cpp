#include "ApfsSoftwareKeybagMaintenance.h"
#include "ApfsSoftwareKeybagPublication.h"
#include "ApfsEncryptedReadSession.h"
#include "AppleSpacemanAllocator.h"
#include "ApfsTransactionWriter.h"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <algorithm>
#include <map>
#include <set>
#include <thread>

namespace apfsaccess::catalog
{
namespace
{
constexpr std::uint32_t bs=4096;
struct Records {
    std::vector<BtreeRecord> values;
    ~Records() { for(auto& r:values) { SecureZeroMemory(r.key.data(),r.key.size()); SecureZeroMemory(r.value.data(),r.value.size()); } }
};
bool SameRecords(const Records& a,const Records& b)
{
    return a.values.size()==b.values.size() && std::equal(a.values.begin(),a.values.end(),b.values.begin(),
        [](const auto& x,const auto& y){return x.key==y.key && x.value==y.value;});
}
void Put(std::vector<std::byte>& bytes,std::size_t offset,std::uint64_t n)
{ for(unsigned i=0;i<8;++i) bytes[offset+i]=static_cast<std::byte>(n>>(8*i)); }
class ObservedSource final : public ImmutableEncryptedReadSource
{
public:
    std::shared_ptr<const ImmutableEncryptedReadSource> inner;
    mutable std::map<std::uint64_t,std::vector<std::byte>> guards;
    explicit ObservedSource(std::shared_ptr<const ImmutableEncryptedReadSource> value):inner(std::move(value)){}
    std::uint64_t SizeBytes() const override {return inner->SizeBytes();}
    std::string SourceIdentity() const override {return inner->SourceIdentity();}
    std::uint64_t Revision() const override {return inner->Revision();}
    std::shared_ptr<ApfsReadBudget> ReadBudget() const override {return inner->ReadBudget();}
    bool Read(std::uint64_t at,std::size_t size,std::vector<std::byte>& out) const override
    {
        out.clear(); if(at>SizeBytes() || size>SizeBytes()-at) return false;
        std::vector<std::byte> result(size);
        for(std::size_t done=0;done<size;) {
            const auto block=(at+done)/bs;
            std::vector<std::byte> raw;
            if(!inner->Read(block*bs,bs,raw) || raw.size()!=bs) return false;
            auto found=guards.find(block);
            if(found!=guards.end() && found->second!=raw) return false;
            if(found==guards.end()) {
                if(guards.size()>=1024 || !ReadBudget()->Materialize(1,bs+96)) return false;
                guards.emplace(block,raw);
            }
            const auto within=static_cast<std::size_t>((at+done)%bs);
            const auto count=(std::min)(size-done,bs-within);
            std::copy_n(raw.begin()+within,count,result.begin()+done); done+=count;
        }
        out=std::move(result); return true;
    }
};
class Candidate final : public ImmutableEncryptedReadSource
{
public:
    const std::shared_ptr<const ImmutableEncryptedReadSource> base;
    const std::uint64_t xid;
    std::map<std::uint64_t,const std::vector<std::byte>*> blocks;
    Candidate(std::shared_ptr<const ImmutableEncryptedReadSource> input,const rw::AppleCheckpointPublicationPlan& plan)
        :base(std::move(input)),xid(plan.transaction_xid)
    {
        for(const auto& write:plan.before_superblock_writes)
            if(write.bytes.size()!=bs || !blocks.emplace(write.physical_block,&write.bytes).second)
                throw std::runtime_error("MaintenanceCandidateDuplicate");
        if(!blocks.emplace(plan.superblock_write.physical_block,&plan.superblock_write.bytes).second)
            throw std::runtime_error("MaintenanceCandidateDuplicateSwitch");
    }
    std::uint64_t SizeBytes() const override {return base->SizeBytes();}
    std::string SourceIdentity() const override {return base->SourceIdentity()+":maintenance-candidate:"+std::to_string(xid);}
    std::uint64_t Revision() const override {return base->Revision() ^ xid;}
    std::shared_ptr<ApfsReadBudget> ReadBudget() const override {return base->ReadBudget();}
    bool Read(std::uint64_t at,std::size_t size,std::vector<std::byte>& out) const override
    {
        out.clear(); if(at>SizeBytes() || size>SizeBytes()-at || !ReadBudget()->Read(size)) return false;
        std::vector<std::byte> result(size);
        for(std::size_t done=0;done<size;) {
            const auto block=(at+done)/bs; const auto found=blocks.find(block);
            std::vector<std::byte> raw;
            if(found==blocks.end() && !base->Read(block*bs,bs,raw)) return false;
            const auto& bytes=found==blocks.end()?raw:*found->second;
            const auto within=static_cast<std::size_t>((at+done)%bs),count=(std::min)(size-done,bs-within);
            std::copy_n(bytes.begin()+within,count,result.begin()+done); done+=count;
        }
        out=std::move(result); return true;
    }
};
bool Block(const RandomAccessSource& source,std::uint64_t block,std::vector<std::byte>& bytes)
{return block<source.SizeBytes()/bs && source.Read(block*bs,bs,bytes) && bytes.size()==bs;}
bool Allocated(const AppleSpacemanView& view,std::uint64_t block)
{
    for(const auto& chunk:view.chunks) if(block>=chunk.start_block && block-chunk.start_block<chunk.block_count) {
        const auto bit=block-chunk.start_block;
        return bit/8<chunk.allocation_bitmap.size() &&
            (std::to_integer<unsigned>(chunk.allocation_bitmap[bit/8])&(1u<<(bit%8)));
    }
    return false;
}
bool SameAllocator(const AppleSpacemanView& a,const AppleSpacemanView& b)
{
    if(a.bytes!=b.bytes || a.chunks.size()!=b.chunks.size() ||
        a.internal_pool.active_bitmaps.size()!=b.internal_pool.active_bitmaps.size()) return false;
    for(std::size_t d=0;d<a.devices.size();++d) {
        const auto& x=a.devices[d];const auto& y=b.devices[d];
        if(x.cibs.size()!=y.cibs.size() || x.cabs.size()!=y.cabs.size()) return false;
        for(std::size_t i=0;i<x.cibs.size();++i)
            if(x.cibs[i].object.physical_block!=y.cibs[i].object.physical_block || x.cibs[i].bytes!=y.cibs[i].bytes) return false;
        for(std::size_t i=0;i<x.cabs.size();++i)
            if(x.cabs[i].object.physical_block!=y.cabs[i].object.physical_block || x.cabs[i].bytes!=y.cabs[i].bytes) return false;
    }
    for(std::size_t i=0;i<a.chunks.size();++i)
        if(a.chunks[i].bitmap_block!=b.chunks[i].bitmap_block || a.chunks[i].allocation_bitmap!=b.chunks[i].allocation_bitmap) return false;
    for(std::size_t i=0;i<a.internal_pool.active_bitmaps.size();++i) {
        const auto& x=a.internal_pool.active_bitmaps[i];const auto& y=b.internal_pool.active_bitmaps[i];
        if(x.physical_block!=y.physical_block || x.rotation_index!=y.rotation_index || x.xid!=y.xid || x.bytes!=y.bytes) return false;
    }
    for(std::size_t i=0;i<a.free_queues.size();++i) {
        const auto& x=a.free_queues[i];const auto& y=b.free_queues[i];
        if(x.tree_blocks!=y.tree_blocks || x.entries.size()!=y.entries.size()) return false;
        for(std::size_t j=0;j<x.entries.size();++j)
            if(x.entries[j].xid!=y.entries[j].xid || x.entries[j].physical_block!=y.entries[j].physical_block || x.entries[j].block_count!=y.entries[j].block_count) return false;
    }
    return true;
}
bool ReadTree(const RandomAccessSource& source,const AppleObjectLocation& root,std::uint64_t xid,
    Records& rows,std::string& error,std::set<std::uint64_t>* owners=nullptr)
{
    std::vector<std::uint64_t> blocks;
    BtreeReadPolicy policy;policy.enforce_object_identity=true;policy.require_complete_traversal=true;
    policy.reject_unsupported_flags=true;policy.root_object_id=root.object_id;
    policy.storage_type=root.type;policy.subtype=root.subtype;
    policy.visited_physical_blocks=&blocks;
    if(!ReadBtreeLeafRecords(source,bs,root.physical_block,true,0,xid,policy,rows.values,error)) return false;
    if(owners) owners->insert(blocks.begin(),blocks.end());
    return true;
}
bool Compose(const RandomAccessSource& source,const ContainerCheckpointView& cp,
    const AppleSpacemanView* before,const rw::AppleSpacemanAllocationPlan* allocation,
    std::span<const rw::AppleCheckpointPhysicalWrite> bags,const std::vector<std::uint64_t>& required,
    std::uint64_t keylocker,rw::AppleCheckpointPublicationPlan& output,std::string& error)
{
    rw::AppleCheckpointPublicationRequest request;
    const auto& nx=cp.superblock;
    request.expected_checkpoint_xid=nx.xid;request.transaction_xid=nx.next_xid;request.next_object_id=nx.next_oid;
    request.required_checkpoint_xids=required;request.allocator_owned_writes.assign(bags.begin(),bags.end());
    std::map<std::uint64_t,rw::AppleCheckpointEphemeralObject> objects;
    if(allocation) {
        rw::AppleCheckpointEphemeralObject sm;sm.object=allocation->updated_spaceman.object;sm.object.physical_block=0;
        sm.object.size_bytes=static_cast<std::uint32_t>(allocation->updated_spaceman.bytes.size());sm.bytes=allocation->updated_spaceman.bytes;
        objects.emplace(sm.object.object_id,std::move(sm));
        for(const auto& write:allocation->writes) {
            if(write.kind==rw::AppleSpacemanWriteKind::FreeQueueTree) {
                if(!write.object_location || write.physical_block) {error="MaintenanceAllocatorObjectInvalid";return false;}
                rw::AppleCheckpointEphemeralObject object;object.object=*write.object_location;
                object.object.physical_block=0;object.bytes=write.bytes;
                if(!objects.emplace(object.object.object_id,std::move(object)).second) {error="MaintenanceAllocatorDuplicate";return false;}
                request.next_object_id=(std::max)(request.next_object_id,write.object_location->object_id+1);
            } else {
                if(!write.physical_block || write.object_location || write.bytes.size()!=bs) {error="MaintenanceAllocatorWriteInvalid";return false;}
                request.allocator_owned_writes.push_back({write.physical_block,write.bytes});
            }
        }
    }
    for(const auto& mapping:cp.mappings) {
        if(objects.contains(mapping.object_id)) continue;
        bool retired=false;
        if(before) for(const auto& queue:before->free_queues)
            if(objects.contains(queue.tree_oid) && std::find(queue.tree_blocks.begin(),queue.tree_blocks.end(),mapping.physical_block)!=queue.tree_blocks.end()) retired=true;
        if(retired) {request.retired_ephemeral_object_ids.push_back(mapping.object_id);continue;}
        if(mapping.size_bytes!=bs) {error="MaintenanceEphemeralSizeUnsupported";return false;}
        rw::AppleCheckpointEphemeralObject object;object.file_system_oid=mapping.file_system_oid;
        object.object={mapping.object_id,nx.next_xid,0,mapping.type,mapping.subtype,mapping.size_bytes};
        if(!Block(source,mapping.physical_block,object.bytes)) return false;
        Put(object.bytes,16,nx.next_xid);
        if(!rw::FinalizeAppleObjectChecksum(object.bytes,error)) return false;
        objects.emplace(mapping.object_id,std::move(object));
    }
    for(auto& [oid,object]:objects) {(void)oid;request.ephemeral_objects.push_back(std::move(object));}
    return rw::PlanAppleCheckpointPublication(source,cp,request,output,error,{keylocker,keylocker?1ULL:0ULL});
}
}

std::shared_ptr<const ImmutableEncryptedReadSource> SoftwareKeybagRewrap::ObserveSource(
    std::shared_ptr<const ImmutableEncryptedReadSource> source)
{return std::make_shared<ObservedSource>(std::move(source));}

std::unique_ptr<SoftwareKeybagPublication> SoftwareKeybagRewrap::PreparePublication(
    const crypto::SecureBytes& old_password,const crypto::SecureBytes& new_password,
    PasswordUnlockBudget& budget,std::string& error,std::span<const std::uint64_t> required)
{
    std::lock_guard lock(mutex_);error.clear();
    const auto fail=[&](const char* why)->std::unique_ptr<SoftwareKeybagPublication>{error=why;return {};};
    if(!session_ || !source_ || !old_password.IsLocked() || !new_password.IsLocked() ||
        source_->SourceIdentity()!=identity_ || source_->Revision()!=revision_) return fail("MaintenanceSourceRevoked");
    auto observed=std::dynamic_pointer_cast<const ObservedSource>(source_);
    if(!observed) return fail("MaintenanceObservedSourceRequired");
    try {
        EncryptedReadError read_error;
        auto context=session_->CreateMetadataReadContext(read_error);
        if(!context) return fail("MaintenanceSessionRevoked");
        auto current=LoadAppleCheckpointView(*source_,0,source_->SizeBytes(),error,*context,selection_.checkpoint_xid);
        if(!current) return {};
        const auto& nx=current->container.superblock;
        if(nx.block_size!=bs || nx.fs_oids.size()!=1 || nx.fs_oids.front()!=selection_.volume_oid ||
            nx.next_xid<=nx.xid || nx.xp_desc_noncontiguous || nx.xp_data_noncontiguous ||
            nx.xp_desc_block_count>256 || current->volumes.size()!=1) return fail("MaintenanceContainerProfileUnsupported");
        auto result=std::unique_ptr<SoftwareKeybagPublication>(new SoftwareKeybagPublication);
        rw::AppleCheckpointPublicationPlan preview;
        if(!Compose(*source_,current->container,nullptr,nullptr,{}, {},0,preview,error)) return {};
        auto preview_source=std::make_shared<Candidate>(source_,preview);
        std::set<std::uint64_t> all_xids{nx.xid},survivors{nx.xid},payload,metadata_owners,selected_fs,omap_fs;
        for(std::uint64_t i=0;i<nx.xp_desc_block_count;++i) {
            std::vector<std::byte> raw;if(!Block(*source_,nx.xp_desc_base_block+i,raw)) return {};
            auto cp=ParseNxSuperblock(raw);
            if(cp && cp->uuid_hex==nx.uuid_hex && cp->xid<=nx.xid) all_xids.insert(cp->xid);
        }
        if(all_xids.size()>6 || required.size()>6) return fail("MaintenanceRetentionLimit");
        for(auto xid:required) if(!xid || !all_xids.contains(xid)) return fail("MaintenanceRequiredCheckpointUnavailable");
        for(auto xid:all_xids) if(xid!=nx.xid) {
            std::string detail;auto cp=LoadContainerCheckpointView(*source_,0,source_->SizeBytes(),detail,xid);
            if(!cp) return fail("MaintenanceHistoricalCheckpointIncomplete");
            if(LoadContainerCheckpointView(*preview_source,0,source_->SizeBytes(),detail,xid)) survivors.insert(xid);
            else if(std::find(required.begin(),required.end(),xid)!=required.end()) return fail("MaintenanceRequiredCheckpointWouldRetire");
            else ++result->retired_;
        }
        Records current_fs,current_refs;
        std::vector<std::uint16_t> bitmap_indices;
        std::map<std::uint64_t,AppleSpacemanView> promised_allocators;
        std::map<std::uint64_t,std::pair<std::uint64_t,std::uint64_t>> bag_owners;
        std::map<std::uint64_t,std::vector<std::byte>> old_nx;
        for(auto xid:survivors) {
            auto cp=LoadContainerCheckpointView(*source_,0,source_->SizeBytes(),error,xid);
            if(!cp) return {};
            std::uint64_t container_bag=0,volume_bag=0;UnlockError unlock;
            auto metadata=InspectPasswordKeybagMetadataAtCheckpoint(*source_,selection_.volume_oid,selection_.length,xid,unlock,container_bag,volume_bag);
            if(!metadata || metadata->users.size()!=1 || metadata->users.front()!=selection_.user_uuid ||
                metadata->selection.volume_uuid!=selection_.volume_uuid || metadata->selection.container_uuid!=selection_.container_uuid)
                return fail("MaintenanceRetainedKeybagProfileUnsupported");
            bag_owners.emplace(xid,std::pair{container_bag,volume_bag});old_nx.emplace(xid,cp->superblock_bytes);
            metadata_owners.insert(container_bag);metadata_owners.insert(volume_bag);
            auto catalog=LoadAppleReadOnlyVolumeView(*source_,*cp,error);
            if(!catalog || catalog->volumes.size()!=1) return {};
            const auto& catalog_volume=catalog->volumes.front();
            std::vector<std::byte> apsb;
            if(!Block(*source_,catalog_volume.superblock_object.physical_block,apsb) ||
                ReadU64LE(apsb,0xD8)!=0 || ReadU64LE(apsb,0x3D0)!=0 || ReadU64LE(apsb,0xA0)!=0 || ReadU64LE(apsb,0xA8)!=0 ||
                catalog_volume.superblock.snap_meta_ext_oid || catalog_volume.superblock.fext_tree_oid)
                return fail("MaintenanceRetainedSnapshotOrRollingUnsupported");
            auto selected_context=xid==nx.xid ? session_->CreateMetadataReadContext(read_error) :
                session_->CreateHistoricalKeybagEraContext(xid,error);
            if(!selected_context) return error.empty() ? fail("MaintenanceRetainedContextUnavailable") : nullptr;
            auto view=LoadAppleCheckpointView(*source_,0,source_->SizeBytes(),error,*selected_context,xid,false);
            if(!view || view->volumes.size()!=1) return {};
            const auto& volume=view->volumes.front();
            if(volume.object_map.snapshot_tree_oid || view->container_object_map.snapshot_tree_oid || !volume.extentref_tree)
                return fail("MaintenanceRetainedTreeProfileUnsupported");
            Records fs,refs,comap,vomap;
            if(!ReadAppleVolumeFileSystemRecords(*source_,*cp,volume,fs.values,error,*selected_context) ||
                !ReadTree(*source_,*volume.extentref_tree,xid,refs,error,&metadata_owners) ||
                !ReadTree(*source_,view->container_object_map.tree,xid,comap,error,&metadata_owners) ||
                !ReadTree(*source_,volume.object_map.tree,xid,vomap,error,&metadata_owners)) return {};
            for(auto block:{volume.superblock_object.physical_block,volume.root_tree.physical_block,
                    volume.object_map.object.physical_block,view->container_object_map.object.physical_block}) metadata_owners.insert(block);
            if(comap.values.size()!=1 || ReadU64LE(comap.values.front().key,0)!=selection_.volume_oid ||
                ReadU64LE(comap.values.front().key,8)!=volume.superblock.xid) return fail("MaintenanceContainerOmapHistoryUnsupported");
            selected_fs.insert(volume.root_tree.physical_block);
            for(const auto& row:vomap.values) {
                const auto flags=ReadU32LE(row.value,0).value_or(~0u);
                if(flags==1) continue;
                if(flags!=4 || ReadU64LE(row.key,0)!=volume.root_tree.object_id || ReadU32LE(row.value,4)!=bs)
                    return fail("MaintenanceVolumeOmapHistoryUnsupported");
                omap_fs.insert(ReadU64LE(row.value,8).value_or(0));
            }
            if(volume.snapshot_metadata_tree) {
                Records snapshots;if(!ReadTree(*source_,*volume.snapshot_metadata_tree,xid,snapshots,error,&metadata_owners) || !snapshots.values.empty())
                    return fail("MaintenanceSnapshotInventoryUnsupported");
            }
            for(const auto& row:fs.values)
                if((ReadU64LE(row.key,0).value_or(0)>>60)==4 && (ReadU16LE(row.value,0).value_or(0)&rw::kAppleXattrDataStream))
                    return fail("MaintenanceExternalStreamUnsupported");
            std::vector<rw::ApplePhysicalExtentRecord> extents;
            if(!rw::ValidateAppleEncryptedPayloadExtentGraph(fs.values,refs.values,bs,nx.block_count,extents,error)) return {};
            for(const auto& extent:extents) {
                if(extent.reference_count!=1 || extent.block_count>65536) return fail("MaintenancePayloadProfileUnsupported");
                for(std::uint64_t i=0;i<extent.block_count;++i) {
                    const auto block=extent.physical_block+i;
                    const auto within=[&](std::uint64_t start,std::uint64_t count){return block>=start && block-start<count;};
                    const auto& pool=current->spaceman.internal_pool;
                    if(!block || within(nx.xp_desc_base_block,nx.xp_desc_block_count) || within(nx.xp_data_base_block,nx.xp_data_block_count) ||
                        within(pool.base_block,pool.block_count) || within(pool.bitmap_base_block,pool.bitmap_block_count))
                        return fail("MaintenancePayloadReservedOverlap");
                    if(!Allocated(current->spaceman,block)) return fail("MaintenanceHistoricalPayloadNotAllocated");
                    if(xid==nx.xid) for(const auto& queue:current->spaceman.free_queues) for(const auto& entry:queue.entries)
                        if(within(entry.physical_block,entry.block_count)) return fail("MaintenanceCurrentPayloadQueued");
                    if(!payload.contains(block)) {
                        if(payload.size()>=65536 || !source_->ReadBudget()->Materialize(1,64)) return fail("MaintenancePayloadOwnerLimit");
                        payload.insert(block);
                    }
                }
            }
            if(xid==nx.xid || std::find(required.begin(),required.end(),xid)!=required.end()) {
                AppleSpacemanView allocator;if(!LoadAppleSpacemanOwnershipView(*source_,*cp,allocator,error)) return {};
                const auto& pins=allocator.internal_pool;
                if(pins.base_block!=current->spaceman.internal_pool.base_block || pins.block_count!=current->spaceman.internal_pool.block_count ||
                    pins.bitmap_base_block!=current->spaceman.internal_pool.bitmap_base_block || pins.bitmap_block_count!=current->spaceman.internal_pool.bitmap_block_count)
                    return fail("MaintenanceRetainedBitmapGeometryUnsupported");
                for(const auto& bitmap:pins.active_bitmaps) bitmap_indices.push_back(bitmap.rotation_index);
                promised_allocators.emplace(xid,std::move(allocator));
            }
            if(xid==nx.xid) {current_fs.values=std::move(fs.values);current_refs.values=std::move(refs.values);}
        }
        if(!std::includes(selected_fs.begin(),selected_fs.end(),omap_fs.begin(),omap_fs.end()))
            return fail("MaintenanceUnselectedOmapOwnerUnsupported");
        for(auto block:metadata_owners) {
            const auto within=[&](std::uint64_t start,std::uint64_t count){return block>=start && block-start<count;};
            const auto& pool=current->spaceman.internal_pool;
            if(!block || within(nx.xp_desc_base_block,nx.xp_desc_block_count) || within(nx.xp_data_base_block,nx.xp_data_block_count) ||
                within(pool.base_block,pool.block_count) || within(pool.bitmap_base_block,pool.bitmap_block_count) ||
                !Allocated(current->spaceman,block) || payload.contains(block)) return fail("MaintenanceMetadataOwnershipUnproven");
        }
        rw::AppleSpacemanAllocationRequest allocate;
        allocate.expected_checkpoint_xid=nx.xid;allocate.transaction_xid=nx.next_xid;
        // Metadata/bag survivors are protected by complete owner exclusion and
        // candidate readback. Only promised full allocator generations restrict
        // queue age; a metadata-only view never supplies allocator authority.
        allocate.oldest_required_checkpoint_xid=nx.xid;
        for(auto xid:required) allocate.oldest_required_checkpoint_xid=(std::min)(allocate.oldest_required_checkpoint_xid,xid);
        allocate.first_ephemeral_object_id=nx.next_oid;
        allocate.main_block_count=2;allocate.reclaim_internal_pool_only=true;
        allocate.protected_internal_pool_bitmap_indices=bitmap_indices;
        rw::AppleSpacemanAllocationPlan allocation;
        if(!rw::PlanAppleSpacemanAllocation(current->spaceman,allocate,allocation,error)) return {};
        if(allocation.allocated_main_blocks.size()!=2 || std::any_of(allocation.deferred_frees.begin(),allocation.deferred_frees.end(),
                [](const auto& item){return item.queue_index!=0;}))
            return fail("MaintenanceAllocationOrReleaseUnexpected");
        if(current->spaceman.devices[0].free_count<2 || allocation.updated_spaceman.devices[0].free_count!=current->spaceman.devices[0].free_count-2)
            return fail("MaintenanceContainerChargeMismatch");
        for(std::size_t i=1;i<current->spaceman.free_queues.size();++i) {
            const auto& a=current->spaceman.free_queues[i].entries;const auto& b=allocation.updated_spaceman.free_queues[i].entries;
            if(a.size()!=b.size() || !std::equal(a.begin(),a.end(),b.begin(),[](const auto& x,const auto& y){return x.xid==y.xid && x.physical_block==y.physical_block && x.block_count==y.block_count;}))
                return fail("MaintenanceMainQueueChanged");
        }
        for(auto block:allocation.allocated_main_blocks)
            if(Allocated(current->spaceman,block) || payload.contains(block) || observed->guards.contains(block))
                return fail("MaintenanceAllocatedRetainedOwner");
        for(auto block:allocation.allocated_internal_pool_blocks)
            if(observed->guards.contains(block)) return fail("MaintenanceReclaimedRetainedOwner");
        const auto container_block=allocation.allocated_main_blocks[0],volume_block=allocation.allocated_main_blocks[1];
        std::vector<std::byte> container_bytes,volume_bytes;
        if(!RelocateBags(container_block,volume_block,nx.next_xid,container_bytes,volume_bytes,error)) return {};
        std::vector<rw::AppleCheckpointPhysicalWrite> writes{{container_block,std::move(container_bytes)},{volume_block,std::move(volume_bytes)}};
        std::vector<std::uint64_t> retained(survivors.begin(),survivors.end());
        if(!Compose(*source_,current->container,&current->spaceman,&allocation,writes,retained,container_block,result->publication_,error)) return {};
        auto candidate=std::make_shared<Candidate>(source_,result->publication_);
        std::uint64_t candidate_container=0,candidate_volume=0;UnlockError unlock;
        auto metadata=InspectPasswordKeybagMetadataAtCheckpoint(*candidate,selection_.volume_oid,selection_.length,nx.next_xid,unlock,candidate_container,candidate_volume);
        if(!metadata || candidate_container!=container_block || candidate_volume!=volume_block || metadata->users.size()!=1 ||
            metadata->users.front()!=selection_.user_uuid || metadata->selection.container_bag.xid!=nx.next_xid || metadata->selection.volume_bag.xid!=nx.next_xid)
            return fail("MaintenanceCandidateKeybagMismatch");
        auto selected=metadata->selection;selected.user_uuid=selection_.user_uuid;
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
        auto fresh=ApfsEncryptedReadSession::Unlock(candidate,candidate->SourceIdentity(),candidate->Revision(),selected,new_password.Bytes(),budget,read_error,unlock);
        if(!fresh) return fail("MaintenanceCandidateNewCredentialFailed");
        auto candidate_context=fresh->CreateMetadataReadContext(read_error);
        if(!candidate_context) return fail("MaintenanceCandidateContextUnavailable");
        auto after=LoadAppleCheckpointView(*candidate,0,candidate->SizeBytes(),error,*candidate_context,nx.next_xid);
        Records candidate_fs,candidate_refs;
        if(!after || after->volumes.size()!=1 || !after->volumes.front().extentref_tree ||
            !ReadAppleVolumeFileSystemRecords(*candidate,after->container,after->volumes.front(),candidate_fs.values,error,*candidate_context) ||
            !ReadTree(*candidate,*after->volumes.front().extentref_tree,nx.next_xid,candidate_refs,error) ||
            !SameRecords(current_fs,candidate_fs) || !SameRecords(current_refs,candidate_refs))
            return fail("MaintenanceCandidateFilesystemChanged");
        for(auto block:allocation.allocated_main_blocks) if(!Allocated(after->spaceman,block)) return fail("MaintenanceCandidateBagsUnallocated");
        if(after->spaceman.devices[0].free_count!=allocation.updated_spaceman.devices[0].free_count)
            return fail("MaintenanceCandidateChargeMismatch");
        for(auto block:payload) if(!Allocated(after->spaceman,block)) return fail("MaintenanceCandidatePayloadOwnershipLost");
        for(auto block:metadata_owners) if(!Allocated(after->spaceman,block)) return fail("MaintenanceCandidateMetadataOwnershipLost");
        for(const auto& [xid,owners]:bag_owners) {
            auto cp=LoadContainerCheckpointView(*candidate,0,candidate->SizeBytes(),error,xid);
            std::uint64_t a=0,b=0;
            auto old=InspectPasswordKeybagMetadataAtCheckpoint(*candidate,selection_.volume_oid,selection_.length,xid,unlock,a,b);
            if(!cp || cp->superblock_bytes!=old_nx.at(xid) || !old || std::pair{a,b}!=owners)
                return fail("MaintenanceRetainedKeybagsChanged");
            if(!Allocated(after->spaceman,a) || !Allocated(after->spaceman,b)) return fail("MaintenanceRetainedBagOwnershipLost");
            if(promised_allocators.contains(xid)) {
                AppleSpacemanView actual;
                if(!LoadAppleSpacemanOwnershipView(*candidate,*cp,actual,error) || !SameAllocator(promised_allocators.at(xid),actual))
                    return fail("MaintenanceRetainedAllocatorChanged");
            }
        }
        for(auto xid:all_xids) if(!survivors.contains(xid)) {
            std::string detail;if(LoadContainerCheckpointView(*candidate,0,candidate->SizeBytes(),detail,xid))
                return fail("MaintenanceUnexpectedRetainedGeneration");
        }
        std::set<std::uint64_t> staged;
        for(const auto& write:result->publication_.before_superblock_writes) staged.insert(write.physical_block);
        for(auto block:metadata_owners) if(staged.contains(block) || block==result->publication_.superblock_write.physical_block)
            return fail("MaintenanceStagedRetainedMetadata");
        for(const auto& [block,raw]:observed->guards) {
            if(staged.contains(block)) continue;
            if(block==result->publication_.superblock_write.physical_block) continue;
            std::vector<std::byte> actual;
            if(!candidate->Read(block*bs,bs,actual) || actual!=raw) return fail("MaintenanceRetainedRawOwnerChanged");
        }
        std::set<std::uint64_t> guard_index;
        for(const auto& guard:result->publication_.guard_blocks) guard_index.insert(guard.physical_block);
        for(const auto& [block,raw]:observed->guards)
            if(!staged.contains(block) && guard_index.insert(block).second) result->publication_.guard_blocks.push_back({block,raw});
        if(result->publication_.guard_blocks.size()>192 || source_->ReadBudget()->Failed() ||
            source_->SourceIdentity()!=identity_ || source_->Revision()!=revision_) return fail("MaintenanceFinalBindingOrBudgetFailed");
        result->identity_=identity_;result->volume_oid_=selection_.volume_oid;
        result->volume_uuid_=BytesToHexLower(selection_.volume_uuid.data(),selection_.volume_uuid.size());
        result->old_container_=container_block_;result->old_volume_=volume_block_;
        result->new_container_=container_block;result->new_volume_=volume_block;result->retained_=std::move(retained);
        return result;
    } catch(const std::bad_alloc&) {return fail("MaintenanceAllocationFailure");}
      catch(const std::exception&) {return fail("MaintenancePlanningException");}
}
} // namespace apfsaccess::catalog
