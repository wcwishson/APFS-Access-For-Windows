#include "ApfsFirmlinkProducer.h"
#include "ApfsFirmlinkTable.h"
#include "ApfsExtendedRecordCodec.h"
#include <algorithm>
#include <bcrypt.h>

namespace apfsaccess::rw
{
namespace
{
bool Fail(std::string& error,const char* reason){error=reason;return false;}
bool IsUuid(const std::string& value)
{
    return value.size()==32&&value!=std::string(32,'0')&&std::all_of(value.begin(),value.end(),[](char c){
        return (c>='0'&&c<='9')||(c>='a'&&c<='f');});
}
class ImageSource final : public catalog::RandomAccessSource
{
public:
    ImageSource(const BlockDevice& device,std::shared_ptr<catalog::ApfsReadBudget> budget)
        : device_(device),budget_(std::move(budget)){}
    std::uint64_t SizeBytes() const override {return device_.GetGeometry().total_bytes;}
    std::shared_ptr<catalog::ApfsReadBudget> ReadBudget() const override{return budget_;}
    bool Read(std::uint64_t offset,std::size_t size,std::vector<std::byte>& out) const override
    {
        out.clear();return offset<=SizeBytes()&&size<=SizeBytes()-offset&&budget_->Read(size)&&
            (size==0||(device_.Read(offset,size,out)&&out.size()==size));
    }
private:
    const BlockDevice& device_;std::shared_ptr<catalog::ApfsReadBudget> budget_;
};
bool Components(std::string_view path,std::vector<std::string_view>& out,std::string& error)
{
    out.clear();
    if(path.empty()||path.front()!='/'||path.size()>4096||path.find('\0')!=std::string_view::npos||
        (path.size()>1&&path.back()=='/'))return Fail(error,"FirmlinkLookupPathInvalid");
    for(std::size_t at=1;at<path.size();){
        auto end=path.find('/',at);if(end==std::string_view::npos)end=path.size();
        if(end==at||end-at>255||out.size()==ApfsFirmlinkRouter::kMaxTraversalSteps)
            return Fail(error,"FirmlinkLookupPathInvalid");
        out.push_back(path.substr(at,end-at));at=end+1;
    }
    return true;
}
bool Hash(std::span<const std::byte> bytes,std::array<std::uint8_t,32>& out)
{
    out={};BCRYPT_ALG_HANDLE algorithm=nullptr;
    if(bytes.size()>65536||BCryptOpenAlgorithmProvider(&algorithm,BCRYPT_SHA256_ALGORITHM,nullptr,0)<0)return false;
    const auto status=BCryptHash(algorithm,nullptr,0,reinterpret_cast<PUCHAR>(const_cast<std::byte*>(bytes.data())),
        static_cast<ULONG>(bytes.size()),out.data(),static_cast<ULONG>(out.size()));
    BCryptCloseAlgorithmProvider(algorithm,0);if(status<0){out={};return false;}return true;
}
}
const NativeApfsVolumeProjection* ApfsFirmlinkProducer::Volume(std::uint64_t oid) const
{
    if(oid==system_.volume_object_id)return &system_;
    if(oid==data_.volume_object_id)return &data_;return nullptr;
}
const MetadataStore::InodeRecord* ApfsFirmlinkProducer::Inode(Key key) const
{
    const auto at=inodes_.find(key);const auto* volume=Volume(key.first);
    return at==inodes_.end()||!volume?nullptr:&volume->inodes[at->second];
}
FirmlinkObjectIdentity ApfsFirmlinkProducer::Identity(Key key) const
{
    const auto* inode=Inode(key);if(!inode)return {};
    const auto volume=std::find_if(container_.volumes.begin(),container_.volumes.end(),
        [&](const auto& v){return v.object_id==key.first;});
    if(volume==container_.volumes.end())return {};
    return {{container_.container_uuid_hex,volume->volume_uuid_hex,volume->name_utf8,volume->object_id,
        Volume(key.first)->incompatible_features},key.second,options_.checkpoint_xid,inode->xid};
}
bool ApfsFirmlinkProducer::Index(std::string& error)
{
    for(const auto* v:{&system_,&data_}){
        for(std::size_t i=0;i<v->inodes.size();++i)
            if(!inodes_.emplace(Key{v->volume_object_id,v->inodes[i].object_id},i).second)
                return Fail(error,"FirmlinkProducerDuplicateInode");
        for(const auto& link:v->directory_links){
            const auto name=ApfsNameCodec::Decode(std::as_bytes(std::span(link.entry_name_utf8)),v->name_policy);
            if(!name.ok()||!children_.emplace(NameKey{{v->volume_object_id,link.parent_object_id},name.value->lookup_key},link.child_object_id).second)
                return Fail(error,"FirmlinkProducerAmbiguousName");
        }
    }
    return true;
}
bool ApfsFirmlinkProducer::CheckAvailable(std::string& error) const
{
    BlockDevice::StableImageIdentity now;error.clear();
    if(!device_||!device_->RevalidateStableReadOnlyImage()||!device_->QueryStableReadOnlyImageIdentity(now)||now!=source_identity_)
        return Fail(error,"FirmlinkImageLeaseChanged");
    if(!budget_||budget_->Failed())return Fail(error,"FirmlinkReadBudgetExhausted");
    return true;
}
bool ApfsFirmlinkProducer::LookupBacking(std::uint64_t oid,std::string_view path,
    FirmlinkLookupResult& out,std::string& error) const
{
    out={};std::vector<std::string_view> components;
    const auto* volume=Volume(oid);if(!volume||!Components(path,components,error))return false;
    Key key{oid,volume->root_directory_inode};
    for(const auto component:components){
        const auto* parent=Inode(key);
        if(!parent||parent->node_type!=MetadataStore::NodeType::Directory||component=="."||component=="..")
            return Fail(error,"FirmlinkTableDirectoryPathInvalid");
        const auto name=ApfsNameCodec::Decode(std::as_bytes(std::span(component)),volume->name_policy);
        if(!name.ok())return Fail(error,"FirmlinkTableDirectoryNameInvalid");
        const auto child=children_.find({key,name.value->lookup_key});
        if(child==children_.end())return Fail(error,"FirmlinkTableDirectoryMissing");key.second=child->second;
    }
    const auto* inode=Inode(key);if(!inode)return Fail(error,"FirmlinkTableInodeMissing");
    out={Identity(key),inode->node_type,inode->logical_size};return true;
}
bool ApfsFirmlinkProducer::ReadBacking(const FirmlinkLookupResult& file,std::uint64_t offset,std::size_t bytes,
    std::vector<std::byte>& out,std::string& error) const
{
    out.clear();const Key key{file.identity.volume.object_id,file.identity.object_id};
    const auto* inode=Inode(key);const auto* volume=Volume(key.first);
    if(!inode||!volume||inode->node_type!=MetadataStore::NodeType::RegularFile||
        (inode->bsd_flags&kAppleBsdCompressedFlag)||bytes>(1u<<20)||offset>INT64_MAX||bytes>static_cast<std::uint64_t>(INT64_MAX)-offset)
        return Fail(error,"FirmlinkFileReadUnsupported");
    const auto attrs=volume->extended_attributes_by_inode.find(key.second);
    if(attrs!=volume->extended_attributes_by_inode.end()&&attrs->second.contains("com.apple.decmpfs"))
        return Fail(error,"FirmlinkFileReadUnsupported");
    const auto found=volume->read_extents_by_inode.find(key.second);
    const std::size_t count=offset<inode->logical_size?static_cast<std::size_t>((std::min)(static_cast<std::uint64_t>(bytes),inode->logical_size-offset)):0;
    if(!count)return true;
    if(found==volume->read_extents_by_inode.end()||found->second.size()>65536)return Fail(error,"FirmlinkFileExtentsMissing");
    std::vector<std::byte> result(count);std::uint64_t written=0,previous_end=0;
    for(const auto& extent:found->second){
        if(!extent.bytes||!extent.physical_address||extent.logical_offset!=previous_end||extent.bytes>UINT64_MAX-extent.logical_offset||
            extent.physical_address>device_->GetGeometry().total_bytes||extent.bytes>device_->GetGeometry().total_bytes-extent.physical_address)
            return Fail(error,"FirmlinkFileExtentsUnsupported");
        previous_end=extent.logical_offset+extent.bytes;
        if(previous_end<=offset||extent.logical_offset>=offset+count)continue;
        const auto start=(std::max)(extent.logical_offset,offset),finish=(std::min)(previous_end,offset+count);
        const auto size=static_cast<std::size_t>(finish-start);std::vector<std::byte> part;
        if(!budget_->Read(size)||!device_->Read(extent.physical_address+start-extent.logical_offset,size,part)||part.size()!=size)
            return Fail(error,"FirmlinkFileReadFailed");
        std::copy(part.begin(),part.end(),result.begin()+static_cast<std::ptrdiff_t>(start-offset));written+=size;
    }
    if(written!=count||previous_end<inode->logical_size)return Fail(error,"FirmlinkFileCoverageInvalid");
    out=std::move(result);return true;
}
bool ApfsFirmlinkProducer::TryOpenImage(const std::wstring& image,const FirmlinkImageOptions& expected,
    std::shared_ptr<const ApfsFirmlinkProducer>& out,std::string& error)
{
    out.reset();error.clear();
    if(!IsUuid(expected.container_uuid_hex)||!IsUuid(expected.group_uuid_hex)||!expected.system_volume_oid||!expected.data_volume_oid||
        expected.system_volume_oid==expected.data_volume_oid||!expected.checkpoint_xid)return Fail(error,"FirmlinkExpectedIdentityInvalid");
    if(image.empty()||image.size()>32767||image.find(L'\0')!=std::wstring::npos)return Fail(error,"FirmlinkImagePathInvalid");
    auto owner=std::shared_ptr<ApfsFirmlinkProducer>(new ApfsFirmlinkProducer);
    owner->options_=expected;owner->device_=BlockDevice::OpenStableReadOnlyImage(image,error);
    if(!owner->device_||!owner->device_->QueryStableReadOnlyImageIdentity(owner->source_identity_))return Fail(error,"FirmlinkStableImageRequired");
    owner->budget_=std::make_shared<catalog::ApfsReadBudget>(131072,512ULL<<20,2000000,512ULL<<20);
    ImageSource source(*owner->device_,owner->budget_);catalog::ApfsContainerCatalog catalog;
    if(!catalog::ApfsContainerCatalog::TryLoadImage(source,"firmlink-image", "held-ordinary-image",catalog,error,catalog::CatalogLoadPolicy::StrictApple))return false;
    if(catalog.Stores().size()!=1||catalog.Stores().front().offset_bytes!=0||catalog.Stores().front().size_bytes!=source.SizeBytes()||
        catalog.Containers().size()!=1||catalog.Containers().front().container_uuid_hex!=expected.container_uuid_hex||
        catalog.Containers().front().checkpoint_xid!=expected.checkpoint_xid)return Fail(error,"FirmlinkImageContainerMismatch");
    owner->container_=catalog.Containers().front();
    std::wstring why;
    if(!NativeApfsReader::TryLoadVolumeProjection(*owner->device_,expected.system_volume_oid,owner->system_,why,expected.checkpoint_xid,owner->budget_)||
        !NativeApfsReader::TryLoadVolumeProjection(*owner->device_,expected.data_volume_oid,owner->data_,why,expected.checkpoint_xid,owner->budget_))
        return Fail(error,"FirmlinkCanonicalProjectionFailed");
    // Catalog descriptors separate name-policy bits. The router consumes the
    // original APSB mask, so adapt a private copy only after exact agreement.
    auto routing_container=owner->container_;
    for(auto& volume:routing_container.volumes){
        const auto* projection=owner->Volume(volume.object_id);if(!projection)continue;
        const auto full=volume.incompatible_features|volume.name_policy_features;
        if((volume.incompatible_features&volume.name_policy_features)||full!=projection->incompatible_features)
            return Fail(error,"FirmlinkCanonicalNamePolicyMismatch");
        volume.incompatible_features=full;
    }
    std::shared_ptr<const ApfsFirmlinkRouter> topology;
    if(!ApfsFirmlinkRouter::TryBuild(routing_container,expected.group_uuid_hex,owner->system_,owner->data_,{},topology,error)||!owner->Index(error))return false;
    FirmlinkLookupResult table;
    if(!owner->LookupBacking(expected.system_volume_oid,"/usr/share/firmlinks",table,error)||
        table.node_type!=MetadataStore::NodeType::RegularFile||!table.logical_size||table.logical_size>65536)
        return Fail(error,"FirmlinkSystemTableInvalid");
    std::vector<std::byte> bytes;
    if(!owner->ReadBacking(table,0,static_cast<std::size_t>(table.logical_size),bytes,error)||bytes.size()!=table.logical_size)return false;
    std::vector<FirmlinkTablePathPair> pairs;if(!ParseAppleFirmlinkTable(bytes,pairs,error)||!Hash(bytes,owner->table_sha_))return false;
    owner->table_identity_=table.identity;owner->table_bytes_=bytes.size();
    for(const auto& pair:pairs){
        FirmlinkLookupResult system,data;
        if(!owner->LookupBacking(expected.system_volume_oid,pair.system_path,system,error)||
            !owner->LookupBacking(expected.data_volume_oid,"/"+pair.data_relative_path,data,error)||
            system.node_type!=MetadataStore::NodeType::Directory||data.node_type!=MetadataStore::NodeType::Directory)
            return Fail(error,"FirmlinkPairDirectoryInvalid");
        owner->records_.push_back({system.identity,data.identity});
        for(const auto* identity:{&system.identity,&data.identity}){
            const auto* volume=owner->Volume(identity->volume.object_id);
            const auto attrs=volume->extended_attributes_by_inode.find(identity->object_id);
            if(attrs!=volume->extended_attributes_by_inode.end()&&attrs->second.contains(std::string(kFirmlinkEaName)))++owner->opaque_marker_count_;
        }
    }
    if(!ApfsFirmlinkRouter::TryBuild(routing_container,expected.group_uuid_hex,owner->system_,owner->data_,owner->records_,owner->router_,error)||
        !owner->CheckAvailable(error))return false;
    out=std::move(owner);return true;
}
bool ApfsFirmlinkProducer::TryLookup(std::string_view path,FirmlinkAccess access,FirmlinkLookupResult& out,std::string& error) const
{
    out={};error.clear();if(!CheckAvailable(error))return false;
    if(access!=FirmlinkAccess::Read)return Fail(error,"FirmlinkUnifiedViewReadOnly");
    std::vector<std::string_view> components;if(!Components(path,components,error))return false;
    auto identity=Identity({system_.volume_object_id,system_.root_directory_inode});
    for(const auto component:components){
        const Key key{identity.volume.object_id,identity.object_id};const auto* parent=Inode(key);const auto* volume=Volume(key.first);
        if(!parent||!volume||parent->node_type!=MetadataStore::NodeType::Directory)return Fail(error,"FirmlinkLookupNotDirectory");
        if(component==".."){
            if(!router_->TryRoute(identity,FirmlinkViewPolicy::ReadOnlyUnifiedGroup,FirmlinkTraversal::Parent,access,identity,error))return false;
            continue;
        }
        if(component==".")continue;
        const auto name=ApfsNameCodec::Decode(std::as_bytes(std::span(component)),volume->name_policy);
        if(!name.ok())return Fail(error,"FirmlinkLookupNameInvalid");
        const auto child=children_.find({key,name.value->lookup_key});if(child==children_.end())return Fail(error,"FirmlinkLookupMissing");
        identity=Identity({key.first,child->second});const auto* inode=Inode({key.first,child->second});
        if(!inode)return Fail(error,"FirmlinkLookupInodeMissing");
        if(inode->node_type==MetadataStore::NodeType::Directory&&
            !router_->TryRoute(identity,FirmlinkViewPolicy::ReadOnlyUnifiedGroup,FirmlinkTraversal::Forward,access,identity,error))return false;
    }
    const auto* inode=Inode({identity.volume.object_id,identity.object_id});if(!inode||!CheckAvailable(error))return false;
    out={identity,inode->node_type,inode->logical_size};return true;
}
bool ApfsFirmlinkProducer::TryReadFile(std::string_view path,std::uint64_t offset,std::size_t count,
    std::vector<std::byte>& out,std::string& error) const
{
    out.clear();FirmlinkLookupResult file;std::vector<std::byte> bytes;
    if(!TryLookup(path,FirmlinkAccess::Read,file,error)||!ReadBacking(file,offset,count,bytes,error)||!CheckAvailable(error))return false;
    out=std::move(bytes);return true;
}
bool ApfsFirmlinkProducer::TryWindowsPath(std::wstring_view path,std::string& unix_path,std::string& error) const
{
    unix_path.clear();error.clear();
    if(!CheckAvailable(error))return false;
    if(path.empty()||path.size()>32768||path.front()!=L'\\'||path.find(L'/')!=path.npos||
        path.find(L'\0')!=path.npos||(path.size()>1&&path.back()==L'\\'))return Fail(error,"FirmlinkLookupPathInvalid");
    std::string result="/";
    for(std::size_t at=1;at<path.size();){
        auto end=path.find(L'\\',at);if(end==path.npos)end=path.size();
        const auto component=path.substr(at,end-at);
        if(component.empty())return Fail(error,"FirmlinkLookupPathInvalid");
        std::string native;
        if(component==L"."||component==L"..")native=component==L"."?".":"..";
        else {
            const auto encoded=ApfsNameCodec::EncodeWindowsName(component);
            if(!encoded.ok())return Fail(error,"FirmlinkLookupNameInvalid");
            native=*encoded.value;
        }
        if(result.size()>1)result+='/';result+=native;
        if(result.size()>4096)return Fail(error,"FirmlinkLookupPathInvalid");
        at=end+1;
    }
    FirmlinkLookupResult target;if(!TryLookup(result,FirmlinkAccess::Read,target,error))return false;
    unix_path=std::move(result);return true;
}
bool ApfsFirmlinkProducer::TryGetMetadata(std::string_view path,MetadataStore::InodeRecord& out,
    std::uint64_t& file_index,std::string& error) const
{
    out={};file_index=0;FirmlinkLookupResult target;
    if(!TryLookup(path,FirmlinkAccess::Read,target,error))return false;
    const Key key{target.identity.volume.object_id,target.identity.object_id};const auto* inode=Inode(key);
    if(!inode)return Fail(error,"FirmlinkLookupInodeMissing");
    // Stable, collision-free across the two volume OID namespaces. This is a
    // presentation ID for this immutable owner, not an APFS inode replacement.
    const auto at=inodes_.find(key);
    file_index=static_cast<std::uint64_t>(at->second)+1+(key.first==data_.volume_object_id?system_.inodes.size():0);
    auto metadata=*inode;
    if(!CheckAvailable(error)){file_index=0;return false;}
    out=std::move(metadata);return true;
}
bool ApfsFirmlinkProducer::TryEnumerate(std::string_view path,std::vector<FirmlinkDirectoryEntry>& out,std::string& error) const
{
    out.clear();FirmlinkLookupResult directory;
    if(!TryLookup(path,FirmlinkAccess::Read,directory,error))return false;
    if(directory.node_type!=MetadataStore::NodeType::Directory)return Fail(error,"FirmlinkLookupNotDirectory");
    const auto* volume=Volume(directory.identity.volume.object_id);std::vector<FirmlinkDirectoryEntry> result;
    for(const auto& link:volume->directory_links){
        if(link.parent_object_id!=directory.identity.object_id)continue;
        if(result.size()==65536)return Fail(error,"FirmlinkDirectoryLimit");
        const auto name=ApfsNameCodec::Decode(std::as_bytes(std::span(link.entry_name_utf8)),volume->name_policy);
        if(!name.ok())return Fail(error,"FirmlinkLookupNameInvalid");
        auto child=std::string(path);if(child!="/")child+='/';child+=link.entry_name_utf8;
        FirmlinkLookupResult target;if(!TryLookup(child,FirmlinkAccess::Read,target,error))return false;
        result.push_back({name.value->windows_display,std::move(child),std::move(target)});
    }
    std::sort(result.begin(),result.end(),[](const auto& a,const auto& b){return a.windows_name<b.windows_name;});
    if(!CheckAvailable(error))return false;out=std::move(result);return true;
}
}
