#include "VolumeResizeCli.h"
#include "VolumeManagement.h"
#include "../src/VolumeResizeInternal.h"
#include "BlockDevice.h"
#include "ObserverReadCache.h"
#include <ntddstor.h>
#include <sstream>

namespace {
using namespace apfsaccess;
using namespace apfsaccess::rw;
std::string Json(std::string_view value)
{
    std::string out="\"";constexpr char hex[]="0123456789abcdef";
    for(const unsigned char c:value){
        if(c=='"' || c=='\\'){out+='\\';out+=static_cast<char>(c);}
        else if(c<32){out+="\\u00";out+=hex[c>>4];out+=hex[c&15];}
        else out+=static_cast<char>(c);
    }
    return out+'"';
}
std::string Hex(std::span<const std::byte> bytes)
{
    constexpr char hex[]="0123456789abcdef";std::string out;out.reserve(bytes.size()*2);
    for(const auto value:bytes){const auto c=std::to_integer<unsigned>(value);out+=hex[c>>4];out+=hex[c&15];}
    return out;
}
bool Uuid(std::string_view value)
{
    return value.size()==32 && value!=std::string(32,'0') &&
        std::all_of(value.begin(),value.end(),[](char c){return (c>='0'&&c<='9') || (c>='a'&&c<='f');});
}
}
using PhysicalObservationSourceFactory = std::function<std::shared_ptr<apfsaccess::rw::VolumePhysicalSource>(
    std::wstring_view, std::wstring_view, std::uint64_t, std::uint64_t,
    const apfsaccess::rw::RawHardwareQualification&, std::string&)>;
int VolumePhysicalObserveMain(int argc,wchar_t** argv, const PhysicalObservationSourceFactory& source_factory =
    [](auto selected, auto instance, auto base, auto limit, const auto& qualification, auto& error) {
        return apfsaccess::rw::VolumePhysicalSource::ObserveExclusiveRaw(selected, instance, base, limit, qualification, error);
    })
{
    using namespace apfsaccess;using namespace apfsaccess::rw;using namespace apfsaccess::rw::volume_image_cli;
    VolumeManagementObservation observed;std::wstring device_path,instance;std::string binding,error;
    std::uint64_t base=0,limit=0;int code=2;
    try {
        const std::set<std::wstring> names={L"--device",L"--instance",L"--base",L"--limit",L"--vendor",L"--product",L"--serial",
            L"--container",L"--volume",L"--oid",L"--xid"};
        std::map<std::wstring,std::wstring> args;
        for(int i=1;i<argc;++i){const std::wstring key=argv[i];
            if(++i>=argc || !names.contains(key))throw std::runtime_error("unknown or incomplete physical observation option");
            (void)Utf8(key);(void)Utf8(argv[i]);
            if(!args.emplace(key,argv[i]).second)throw std::runtime_error("duplicate physical observation option");}
        for(const auto& name:names)if(name!=L"--instance" && !args.contains(name))throw std::runtime_error("complete physical observation scope and operator qualification required");
        device_path=args.at(L"--device");instance=args.contains(L"--instance")?args.at(L"--instance"):L"";base=Number(args.at(L"--base"));limit=Number(args.at(L"--limit"));
        const auto container=Utf8(args.at(L"--container")),volume=Utf8(args.at(L"--volume"));
        const auto oid=Number(args.at(L"--oid")),xid=Number(args.at(L"--xid"));
        if(!Uuid(container) || !Uuid(volume) || !oid || !xid)throw std::runtime_error("canonical complete physical source identity required");
        code=1;RawHardwareQualification qualification;qualification.kind=RawHardwareIdentityKind::QualifiedSerialTuple;
        qualification.bus_type=BusTypeUsb;qualification.vendor=Utf8(args.at(L"--vendor"));
        qualification.product=Utf8(args.at(L"--product"));qualification.qualified_serial=Utf8(args.at(L"--serial"));
        const auto held=source_factory(device_path,instance,base,limit,qualification,error);
        if(!held)throw std::runtime_error(error);
        const auto& scope=held->Binding();
        if(scope.media.base_offset_bytes!=base || scope.media.limit_bytes!=limit ||
            scope.hardware.kind!=qualification.kind || scope.hardware.bus_type!=qualification.bus_type ||
            scope.hardware.vendor!=qualification.vendor || scope.hardware.product!=qualification.product ||
            scope.hardware.serial!=qualification.qualified_serial || (!instance.empty() && held->InstanceId()!=instance) || !held->Revalidate())
            throw std::runtime_error("VolumePhysicalObservationFactoryAuthorityMismatch");
        instance=held->InstanceId();
        std::unique_ptr<physical_observer::ReadCache> cache;
        const catalog::RandomAccessSource* reader=held.get();
        // The factory contract also permits guarded sources without a metadata device.
        // Cache only an exact retained original lease; other sources keep normal reads.
        std::string metadata_error;
        if(const auto device=VolumePhysicalSource::RetainMetadataDevice(held,scope,instance,metadata_error)){
            const auto lease=device->CaptureHeldRawSnapshotLease();
            if(!lease)throw std::runtime_error("ObserverCacheOriginalLeaseUnavailable");
            cache=std::make_unique<physical_observer::ReadCache>(*held,
                [device,token=*lease]{return device->IsHeldRawSnapshotLeaseCurrent(token);},
                [held]{return held->Revalidate();});
            if(!cache->Begin())throw std::runtime_error(cache->Error());
            reader=cache.get();
        }
        auto budget=std::make_shared<catalog::ApfsReadBudget>(65536,256ull<<20,1000000,256ull<<20);
        catalog::BudgetedRandomAccessSource source(*reader,budget);
        const auto cp=catalog::LoadAppleCheckpointView(source,0,source.SizeBytes(),error);
        if(!cp || cp->container.superblock.uuid_hex!=container || cp->container.superblock.xid!=xid ||
            cp->container.superblock.block_size!=4096 || cp->container.superblock.block_count!=limit/4096 ||
            cp->volumes.empty() || cp->volumes.size()>100 ||
            std::count_if(cp->volumes.begin(),cp->volumes.end(),[&](const auto& v){
                return v.superblock.object_id==oid && v.superblock.uuid_hex==volume;})!=1)
            throw std::runtime_error("VolumePhysicalObservationCanonicalScopeMismatch:"+error);
        volume_image::VerifySource(source,*cp);
        std::set<std::string> uuids;std::set<std::uint64_t> oids;
        for(const auto& v:cp->volumes){
            if(!Uuid(v.superblock.uuid_hex) || !v.superblock.object_id || !uuids.insert(v.superblock.uuid_hex).second ||
                !oids.insert(v.superblock.object_id).second || !CheckAppleVolumeWriteFeatures(cp->container.superblock,v.superblock,error))
                throw std::runtime_error("VolumePhysicalObservationSiblingScopeInvalid:"+error);
            observed.volumes.push_back({v.superblock.uuid_hex,v.superblock.object_id});
        }
        if(budget->Failed())throw std::runtime_error(budget->Failure());
        if(cache){if(!cache->Finish())throw std::runtime_error(cache->Error());}
        else if(!held->Revalidate())throw std::runtime_error("VolumePhysicalObservationHeldSourceChanged");
        binding=Hex(volume_physical::Encode(held->Binding(),held->InstanceId()));observed.source_identity=held->Identity();
        observed.store_size_bytes=held->SizeBytes();observed.container_uuid=container;observed.checkpoint_xid=xid;
        observed.block_size=4096;observed.next_oid=cp->container.superblock.next_oid;
        if(!observed.next_oid)throw std::runtime_error("VolumePhysicalObservationNextOidInvalid");
        observed.complete=true;code=0;
    }catch(const std::exception& e){observed.error=e.what();observed.volumes.clear();binding.clear();}
    std::ostringstream out;
    out<<"{\"schemaVersion\":1,\"operation\":\"volume-physical-observe\",\"readOnly\":true,\"exclusiveLease\":"
        <<(observed.complete?"true":"false")<<",\"targetWrites\":\"0\""
        <<",\"outcome\":"<<Json(observed.complete?"complete":"refused")<<",\"error\":"<<Json(observed.error)
        <<",\"device\":"<<Json(Utf8(device_path))<<",\"image\":"<<Json(Utf8(instance))<<",\"bindingHex\":"<<Json(binding)
        <<",\"offsetBytes\":"<<Json(std::to_string(base))<<",\"storeSizeBytes\":"<<Json(std::to_string(observed.store_size_bytes))
        <<",\"sourceIdentity\":"<<Json(observed.source_identity)<<",\"containerUuid\":"<<Json(observed.container_uuid)
        <<",\"checkpointXid\":"<<Json(std::to_string(observed.checkpoint_xid))<<",\"blockBytes\":"<<Json(std::to_string(observed.block_size))
        <<",\"nextOid\":"<<Json(std::to_string(observed.next_oid))<<",\"volumes\":[";
    bool first=true;for(const auto& v:observed.volumes){if(!first)out<<',';first=false;
        out<<"{\"volumeUuid\":"<<Json(v.volume_uuid)<<",\"oid\":"<<Json(std::to_string(v.oid))<<'}';}
    out<<"]}";std::cout<<out.str()<<'\n';return code;
}
#ifndef APFS_VOLUME_PHYSICAL_OBSERVE_TESTING
int wmain(int argc,wchar_t** argv){return VolumePhysicalObserveMain(argc,argv);}
#endif
