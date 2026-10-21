#include "NativeSparsePlan.h"
#include "ApfsExtendedRecordCodec.h"
#include <algorithm>
#include <map>

namespace apfsaccess::rw
{
namespace
{
constexpr std::uint64_t Mask = 0x0fffffffffffffffULL;
constexpr std::uint8_t DataStreamField = 8;
bool Fail(std::string& error,const char* text){error=text;return false;}
std::uint64_t Header(const catalog::BtreeRecord& record){return catalog::ReadU64LE(record.key,0).value_or(0);}
std::uint64_t Aligned(std::uint64_t n){return (n+4095)/4096*4096;}
void Put(std::vector<std::byte>& b,std::size_t at,std::uint64_t n){for(unsigned i=0;i<8;++i)b.at(at+i)=std::byte(n>>(8*i));}
AppleExtendedField* Field(AppleInodeRecord& inode,std::uint8_t type)
{
    AppleExtendedField* result=nullptr;
    for(auto& field:inode.extended_fields)if(field.type==type){if(result)return nullptr;result=&field;}
    return result;
}
void Range(std::vector<NativeSparseAllocatedRange>& ranges,std::uint64_t at,std::uint64_t bytes)
{
    if(!bytes)return;
    if(!ranges.empty() && ranges.back().offset+ranges.back().length==at)ranges.back().length+=bytes;
    else ranges.push_back({at,bytes});
}
}
bool NativeSparseRequestIsValid(const NativeSparseRequest& r)
{
    if(!r.timestamp_ns)return false;
    if(r.action==NativeSparseAction::SetSparse)return !r.offset && !r.length;
    return r.action==NativeSparseAction::ZeroRange && !r.sparse && r.offset<=INT64_MAX && r.length<=INT64_MAX-r.offset;
}
namespace {
bool ReadState(const catalog::RandomAccessSource& source,const catalog::AppleCheckpointView& cp,
    std::uint64_t volume_oid,std::uint64_t object,NativeSparseState& out,std::string& error,bool scaled)
{
    out={};error.clear();
    if(!object || object>Mask || cp.volumes.size()!=1 || cp.volumes.front().superblock.object_id!=volume_oid ||
        cp.container.superblock.block_size!=4096 || !cp.container.superblock.block_count ||
        cp.container.superblock.block_count>static_cast<std::uint64_t>(INT64_MAX)/4096 ||
        source.SizeBytes()!=cp.container.superblock.block_count*4096 ||
        (!scaled && source.SizeBytes()>NativeSparseMaxImageBytes))return Fail(error,"SparseSoleOrdinaryImageProfileRequired");
    const auto& v=cp.volumes.front();
    if(!v.extentref_tree || v.file_extent_tree || v.object_map.snapshot_tree_oid || v.superblock.snap_meta_ext_oid)
        return Fail(error,"SparseTreeProfileUnsupported");
    if(v.superblock.snap_meta_tree_oid){AppleSnapshotRetentionView retained;
        if(!LoadAppleSnapshotRetention(source,cp,retained,error))return false;
        if(!retained.identities.empty())return Fail(error,"SparseRetainedSnapshotUnsupported");}
    NativeSparseState state;
    if(!catalog::ReadAppleVolumeFileSystemRecords(source,cp.container,v,state.filesystem,error))return false;
    catalog::BtreeReadPolicy policy;policy.enforce_object_identity=true;
    policy.root_object_id=v.extentref_tree->object_id;policy.storage_type=v.extentref_tree->type;policy.subtype=v.extentref_tree->subtype;
    const bool physical=(policy.storage_type&catalog::kObjectStorageTypeMask)==catalog::kObjectPhysical;
    if(!catalog::ReadBtreeLeafRecords(source,4096,v.extentref_tree->physical_block,physical,physical?0:v.superblock.omap_oid,
        cp.container.superblock.xid,policy,state.references,error) || state.filesystem.size()>NativeSparseMaxRecords ||
        state.references.size()>NativeSparseMaxRecords ||
        !ValidateApplePayloadExtentGraph(state.filesystem,state.references,4096,cp.container.superblock.block_count,state.payload,error) ||
        !ValidateAppleCheckpointPayloadOwnership(source,cp,state.payload,error))return false;
    std::size_t metadata_bytes=0;
    for(const auto* records:{&state.filesystem,&state.references})for(const auto& record:*records){
        if(record.key.size()>(1u<<20)-metadata_bytes)return Fail(error,"SparseMetadataQuota");metadata_bytes+=record.key.size();
        if(record.value.size()>(1u<<20)-metadata_bytes)return Fail(error,"SparseMetadataQuota");metadata_bytes+=record.value.size();}
    unsigned found=0,streams=0,private_owners=0;
    for(const auto& record:state.filesystem){
        const auto header=Header(record),id=header&Mask,type=header>>60;
        if(type==3){AppleInodeRecord inode;
            if(!ApfsExtendedRecordCodec::DecodeInode(record,inode,error))return false;
            if(inode.private_id==object)++private_owners;
            if(id==object){state.inode=std::move(inode);++found;}}
        if(type==4 && id==object){AppleXattrRecord attr;
            if(!ApfsExtendedRecordCodec::DecodeXattr(record,attr,error))return false;
            if(attr.name_utf8=="com.apple.decmpfs")return Fail(error,"SparseCompressedContentUnsupported");}
        if(type==8 && id==object){AppleFileExtentRecord extent;
            if(!DecodeAppleFileExtentRecord(record,4096,extent,error) || extent.crypto_id || extent.logical_address%4096 ||
                extent.length_bytes%4096)return Fail(error,"SparseExtentInvalid");
            state.extents.push_back(extent);}
        if(type==6 && id==object){AppleDataStreamIdRecord stream;
            if(!DecodeAppleDataStreamIdRecord(record,stream,error) || stream.reference_count!=1 || ++streams!=1)
                return Fail(error,"SparseSharedPrivateStreamUnsupported");}
    }
    if(found!=1 || private_owners!=1 || state.inode.private_id!=object || (state.inode.mode&0170000)!=0100000 ||
        (state.inode.bsd_flags&kAppleBsdCompressedFlag))return Fail(error,"SparseOrdinaryInodeRequired");
    auto* stream=Field(state.inode,DataStreamField);auto* sparse=Field(state.inode,kAppleInodeSparseBytesField);
    if(stream){if(stream->data.size()!=40 || catalog::ReadU64LE(stream->data,16).value_or(1))return Fail(error,"SparseStreamInvalid");
        state.size=catalog::ReadU64LE(stream->data,0).value_or(UINT64_MAX);
        state.allocated=catalog::ReadU64LE(stream->data,8).value_or(UINT64_MAX);}
    else if(state.inode.uncompressed_size || !state.extents.empty() || streams)return Fail(error,"SparseStreamMissing");
    if(state.size>INT64_MAX-4095 || state.allocated>Aligned(state.size) || state.allocated%4096)
        return Fail(error,"SparseStreamSizeInvalid");
    state.sparse=(state.inode.internal_flags&kAppleInodeSparseFlag)!=0;
    if(state.sparse!=(sparse!=nullptr) || (sparse && (sparse->data.size()!=8 ||
        catalog::ReadU64LE(sparse->data,0)!=Aligned(state.size)-state.allocated)))return Fail(error,"SparseAccountingInvalid");
    std::sort(state.extents.begin(),state.extents.end(),[](const auto& a,const auto& b){return a.logical_address<b.logical_address;});
    std::uint64_t end=0,total=0;
    for(const auto& extent:state.extents){
        if(extent.logical_address<end || extent.logical_address>Aligned(state.size) ||
            extent.length_bytes>Aligned(state.size)-extent.logical_address)return Fail(error,"SparseExtentOutsideStream");
        end=extent.logical_address+extent.length_bytes;
        if(extent.physical_block){total+=extent.length_bytes;Range(state.ranges,extent.logical_address,extent.length_bytes);}
    }
    if(total!=state.allocated || (!state.sparse && total!=Aligned(state.size)) || (total && streams!=1))
        return Fail(error,"SparseAllocationGraphMismatch");
    out=std::move(state);return true;
}
}
bool ReadNativeSparseState(const catalog::RandomAccessSource& source,const catalog::AppleCheckpointView& cp,
    std::uint64_t volume,std::uint64_t object,NativeSparseState& out,std::string& error)
{return ReadState(source,cp,volume,object,out,error,false);}
bool ReadNativeSparseStateV2(const catalog::RandomAccessSource& source,const catalog::AppleCheckpointView& cp,
    std::uint64_t volume,std::uint64_t object,NativeSparseState& out,std::string& error)
{return ReadState(source,cp,volume,object,out,error,true);}
bool QueryNativeSparseRanges(const NativeSparseState& state,std::uint64_t offset,std::uint64_t length,
    std::size_t maximum,std::vector<NativeSparseAllocatedRange>& out,std::string& error)
{
    out.clear();error.clear();
    if(offset>INT64_MAX || length>INT64_MAX-offset || !maximum || maximum>NativeSparseMaxRecords)
        return Fail(error,"SparseQueryRangeInvalid");
    const auto end=(std::min)(state.size,offset+length);
    if(offset>=end)return true;
    if(!state.sparse){out.push_back({offset,end-offset});return true;}
    for(const auto& range:state.ranges){const auto first=(std::max)(offset,range.offset),last=(std::min)(end,range.offset+range.length);
        if(first<last)Range(out,first,last-first);
        if(out.size()>maximum){out.clear();return Fail(error,"SparseQueryBufferTooSmall");}}
    return true;
}
bool CompleteNativeSparseExtentCoverage(std::uint64_t object,std::uint64_t size,
    std::vector<catalog::BtreeRecord>& records,std::span<const NativeSparseAllocatedRange> pending,std::string& error)
{
    if(!object || object>Mask || size>INT64_MAX-4095 || records.size()>NativeSparseMaxRecords || pending.size()>NativeSparseMaxRecords)
        return Fail(error,"SparseLogicalCoverageInvalid");
    const auto end=Aligned(size);std::vector<NativeSparseAllocatedRange> ranges;ranges.reserve(records.size()+pending.size());
    for(const auto& record:records){AppleFileExtentRecord extent;
        if(!DecodeAppleFileExtentRecord(record,4096,extent,error) || extent.object_id!=object || extent.crypto_id ||
            extent.logical_address%4096 || extent.length_bytes%4096 || !extent.length_bytes ||
            extent.logical_address>end || extent.length_bytes>end-extent.logical_address)return Fail(error,"SparseLogicalCoverageInvalid");
        ranges.push_back({extent.logical_address,extent.length_bytes});}
    for(const auto& range:pending){
        if(!range.length || range.offset%4096 || range.length%4096 || range.offset>end || range.length>end-range.offset)
            return Fail(error,"SparseLogicalCoverageInvalid");ranges.push_back(range);}
    std::sort(ranges.begin(),ranges.end(),[](const auto& a,const auto& b){return a.offset<b.offset;});
    std::vector<catalog::BtreeRecord> holes;std::uint64_t cursor=0;
    const auto fill=[&](std::uint64_t finish){
        while(cursor<finish){if(records.size()+holes.size()>=NativeSparseMaxRecords)return Fail(error,"SparseMetadataQuota");
            const auto length=(std::min)(finish-cursor,0x00fffffffffff000ull);catalog::BtreeRecord record;
            if(!EncodeAppleFileExtentRecord({object,cursor,length,0,0,4096},record,error))return false;
            holes.push_back(std::move(record));cursor+=length;}
        return true;
    };
    for(const auto& range:ranges){if(range.offset<cursor)return Fail(error,"SparseLogicalCoverageOverlap");
        if(!fill(range.offset))return false;cursor=range.offset+range.length;}
    if(!fill(end))return false;
    records.insert(records.end(),std::make_move_iterator(holes.begin()),std::make_move_iterator(holes.end()));return true;
}
namespace {
bool Plan(const catalog::RandomAccessSource& source,const catalog::AppleCheckpointView& cp,
    std::uint64_t volume_oid,std::uint64_t object,const NativeSparseRequest& op,NativeSparseState& before,
    AppleVolumeTransactionPlan& out,std::vector<NativeSparseSourceBlock>* contributing,std::string& error,bool explicit_holes)
{
    out={};
    if(contributing)contributing->clear();
    if(!NativeSparseRequestIsValid(op))return Fail(error,"SparseRequestInvalid");
    if(!ReadState(source,cp,volume_oid,object,before,error,contributing!=nullptr))return false;
    AppleVolumeTransactionRequest request;request.volume_object_id=volume_oid;request.required_checkpoint_xids={cp.container.superblock.xid};
    request.filesystem_records=before.filesystem;request.last_modification_time=op.timestamp_ns;
    const auto finish=(std::min)(before.size,op.offset+op.length);
    const bool make_sparse=op.action==NativeSparseAction::SetSparse?op.sparse:before.sparse;
    std::vector<NativeSparseAllocatedRange> removed;
    std::map<std::uint64_t,std::vector<std::byte>> materialized;
    if(op.action==NativeSparseAction::ZeroRange && op.offset<finish){
        const auto low=op.offset/4096*4096,high=Aligned(finish);
        if(!before.sparse && high-low>NativeSparseMaxMaterializedBytes)return Fail(error,"SparseMaterializationQuota");
        for(const auto& extent:before.extents){
            if(!extent.physical_block)continue;
            const auto lo=(std::max)(low,extent.logical_address),hi=(std::min)(high,extent.logical_address+extent.length_bytes);
            if(lo>=hi)continue;
            Range(removed,lo,hi-lo);
            const auto block=[&](std::uint64_t at){
                const auto zlo=(std::max)(op.offset,at),zhi=(std::min)(finish,at+4096);
                if(before.sparse && zlo==at && zhi==at+4096)return true;
                if(materialized.size()>=NativeSparseMaxMaterializedBytes/4096)return Fail(error,"SparseMaterializationQuota");
                std::vector<std::byte> bytes;
                if(contributing && zlo==at && zhi==at+4096)bytes.resize(4096);
                else{
                    const auto physical=extent.physical_block+(at-extent.logical_address)/4096;
                    if(!source.Read(physical*4096,4096,bytes) || bytes.size()!=4096)return Fail(error,"SparseBoundaryUnreadable");
                    if(contributing){
                        auto found=std::find_if(contributing->begin(),contributing->end(),[&](const auto& b){return b.physical_block==physical;});
                        if(found==contributing->end()){
                            if(contributing->size()==2)return Fail(error,"SparseBoundaryCensusQuota");
                            NativeSparseSourceBlock saved;saved.physical_block=physical;
                            std::copy(bytes.begin(),bytes.end(),saved.bytes.begin());contributing->push_back(std::move(saved));
                        }else if(!std::equal(bytes.begin(),bytes.end(),found->bytes.begin()))return Fail(error,"SparseBoundaryChanged");
                    }
                }
                std::fill(bytes.begin()+(zlo-at),bytes.begin()+(zhi-at),std::byte{});materialized.emplace(at,std::move(bytes));
                if(contributing && before.size<at+4096)
                    std::fill(materialized.at(at).begin()+(before.size-at),materialized.at(at).end(),std::byte{});
                return true;
            };
            if(contributing && before.sparse){
                // Work follows extent records, not the number of removed blocks.
                if(!block(lo) || (hi-lo>4096 && !block(hi-4096)))return false;
            }else for(auto at=lo;at<hi;at+=4096){
                if(!block(at))return false;
            }
        }
    }
    if(op.action==NativeSparseAction::SetSparse && !op.sparse){
        std::uint64_t cursor=0;
        const auto add=[&](auto lo,auto hi){
            if(hi-lo>NativeSparseMaxMaterializedBytes-materialized.size()*4096)return false;
            for(auto at=lo;at<hi;at+=4096)materialized.emplace(at,std::vector<std::byte>(4096));return true;};
        for(const auto& range:before.ranges){if(!add(cursor,range.offset))return Fail(error,"SparseMaterializationQuota");cursor=range.offset+range.length;}
        if(!add(cursor,Aligned(before.size)))return Fail(error,"SparseMaterializationQuota");
    }
    std::uint64_t retained_bytes=0;
    std::vector<catalog::BtreeRecord> records;
    const auto retain=[&](const AppleFileExtentRecord& old,std::uint64_t lo,std::uint64_t hi){
        if(lo==hi)return true;auto next=old;next.logical_address=lo;next.length_bytes=hi-lo;
        next.physical_block+=(lo-old.logical_address)/4096;
        catalog::BtreeRecord record;if(!EncodeAppleFileExtentRecord(next,record,error))return false;
        records.push_back(std::move(record));retained_bytes+=hi-lo;return true;};
    for(const auto& extent:before.extents){
        if(!extent.physical_block)continue;
        auto cursor=extent.logical_address;const auto end=cursor+extent.length_bytes;
        for(const auto& range:removed){const auto lo=(std::max)(cursor,range.offset),hi=(std::min)(end,range.offset+range.length);
            if(lo>=hi)continue;if(!retain(extent,cursor,lo))return false;
            request.released_data_blocks.push_back({extent.physical_block+(lo-extent.logical_address)/4096,(hi-lo)/4096});cursor=hi;}
        if(!retain(extent,cursor,end))return false;
    }
    if(explicit_holes && make_sparse){std::vector<NativeSparseAllocatedRange> pending;pending.reserve(materialized.size());
        for(const auto& [at,_]:materialized)pending.push_back({at,4096});
        if(!CompleteNativeSparseExtentCoverage(object,before.size,records,pending,error))return false;}
    std::erase_if(request.filesystem_records,[&](const auto& record){return (Header(record)>>60)==8 && (Header(record)&Mask)==object;});
    request.filesystem_records.insert(request.filesystem_records.end(),records.begin(),records.end());
    for(auto& [at,bytes]:materialized)request.data_writes.push_back({object,at,0,std::move(bytes)});
    auto inode=before.inode;const auto allocated=retained_bytes+materialized.size()*4096;
    if(allocated>Aligned(before.size))return Fail(error,"SparseProjectedAllocationInvalid");
    auto* stream=Field(inode,DataStreamField);
    if(!stream){inode.extended_fields.push_back({DataStreamField,0,std::vector<std::byte>(40)});stream=&inode.extended_fields.back();}
    Put(stream->data,0,before.size);Put(stream->data,8,allocated);
    std::erase_if(inode.extended_fields,[](const auto& field){return field.type==kAppleInodeSparseBytesField;});
    if(make_sparse){inode.internal_flags|=kAppleInodeSparseFlag;
        AppleExtendedField sparse{kAppleInodeSparseBytesField,0,std::vector<std::byte>(8)};Put(sparse.data,0,Aligned(before.size)-allocated);inode.extended_fields.push_back(std::move(sparse));}
    else inode.internal_flags&=~kAppleInodeSparseFlag;
    inode.change_time=op.timestamp_ns;if(op.action==NativeSparseAction::ZeroRange)inode.modification_time=op.timestamp_ns;
    catalog::BtreeRecord encoded;if(!EncodeAppleInodeRecord(inode,encoded,error))return false;
    unsigned replaced=0;for(auto& record:request.filesystem_records)if(Header(record)==((3ull<<60)|object)){record=encoded;++replaced;}
    if(replaced!=1)return Fail(error,"SparseProjectedInodeMissing");
    if(contributing)std::sort(contributing->begin(),contributing->end(),[](const auto& a,const auto& b){return a.physical_block<b.physical_block;});
    return PlanAppleVolumeTransaction(source,cp,request,out,error);
}
}
bool PlanNativeSparseTransaction(const catalog::RandomAccessSource& source,const catalog::AppleCheckpointView& cp,
    std::uint64_t volume,std::uint64_t object,const NativeSparseRequest& request,NativeSparseState& before,
    AppleVolumeTransactionPlan& out,std::string& error)
{return Plan(source,cp,volume,object,request,before,out,nullptr,error,false);}
bool PlanNativeSparseTransactionV2(const catalog::RandomAccessSource& source,const catalog::AppleCheckpointView& cp,
    std::uint64_t volume,std::uint64_t object,const NativeSparseRequest& request,NativeSparseState& before,
    AppleVolumeTransactionPlan& out,std::vector<NativeSparseSourceBlock>& contributing,std::string& error)
{return Plan(source,cp,volume,object,request,before,out,&contributing,error,true);}
bool PlanNativeSparseTransactionV2Legacy(const catalog::RandomAccessSource& source,const catalog::AppleCheckpointView& cp,
    std::uint64_t volume,std::uint64_t object,const NativeSparseRequest& request,NativeSparseState& before,
    AppleVolumeTransactionPlan& out,std::vector<NativeSparseSourceBlock>& contributing,std::string& error)
{return Plan(source,cp,volume,object,request,before,out,&contributing,error,false);}
}
