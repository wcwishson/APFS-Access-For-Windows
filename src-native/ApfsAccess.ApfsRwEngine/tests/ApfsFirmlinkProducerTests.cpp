#include "ApfsFirmlinkProducer.h"
#include "ApfsFirmlinkTable.h"
#include "ApfsExtendedRecordCodec.h"
#include "TestFixtureBuilder.h"
#include <fstream>
#include <iostream>
#include <set>
#include <stdexcept>

using namespace apfsaccess;
using namespace apfsaccess::rw;
using namespace apfsaccess::testfixture;
namespace
{
unsigned checks=0;
void Check(bool value,const std::string& name){++checks;if(!value)throw std::runtime_error(name);}
std::vector<std::byte> Bytes(std::string_view text){const auto b=std::as_bytes(std::span(text));return {b.begin(),b.end()};}
std::vector<std::byte> Read(const std::filesystem::path& path)
{
    std::ifstream file(path,std::ios::binary);std::vector<char> chars((std::istreambuf_iterator<char>(file)),{});
    Check(file.eof()||static_cast<bool>(file),"fixture bytes read");
    std::vector<std::byte> out;for(auto c:chars)out.push_back(std::byte(static_cast<unsigned char>(c)));return out;
}
struct Tree
{
    std::map<std::string,std::uint64_t> dirs{{"/",2},{"/Users",3}};
    std::map<std::uint64_t,AppleInodeRecord> inodes;
    std::vector<AppleDirectoryRecord> entries;
    std::vector<catalog::BtreeRecord> extra;
    std::uint64_t next=100;
    Tree(){
        AppleInodeRecord root;root.object_id=root.private_id=root.parent_id=2;root.mode=0040755;inodes.emplace(2,root);
        AppleInodeRecord users;users.object_id=users.private_id=3;users.parent_id=2;users.mode=0040755;inodes.emplace(3,users);
        entries.push_back({2,3,0,4,"Users"});
    }
    std::uint64_t Directory(const std::string& path)
    {
        if(const auto found=dirs.find(path);found!=dirs.end())return found->second;
        const auto slash=path.find_last_of('/');const auto parent=Directory(slash?path.substr(0,slash):"/");
        const auto id=next++;AppleInodeRecord inode;inode.object_id=inode.private_id=id;inode.parent_id=parent;inode.mode=0040755;
        inodes.emplace(id,inode);dirs.emplace(path,id);entries.push_back({parent,id,0,4,path.substr(slash+1)});return id;
    }
    void File(const std::string& path,std::uint64_t id,std::span<const std::byte> bytes,std::uint64_t block,BuilderVolume& volume,std::uint32_t bs)
    {
        const auto slash=path.find_last_of('/');const auto parent=Directory(slash?path.substr(0,slash):"/");
        AppleInodeRecord inode;inode.object_id=inode.private_id=id;inode.parent_id=parent;inode.mode=0100644;inode.children_or_links=1;
        AppleExtendedField stream{8,0,std::vector<std::byte>(40)};PutU64LE(stream.data,0,bytes.size());PutU64LE(stream.data,8,bs);inode.extended_fields.push_back(stream);
        inodes.emplace(id,inode);entries.push_back({parent,id,0,8,path.substr(slash+1)});
        catalog::BtreeRecord record;std::string error;
        Check(EncodeAppleDataStreamIdRecord({id,1},record,error),"stream ID encodes");extra.push_back(record);
        Check(EncodeAppleFileExtentRecord({id,0,bs,block,0,bs},record,error),"file extent encodes");extra.push_back(record);
        Check(EncodeApplePhysicalExtentRecord({block,1,kApplePhysicalExtentKindNew,id,1},record,error),"reference encodes");volume.extentref_records.push_back(record);
        ++volume.additional_file_system_allocated_blocks;
    }
    void Finish(BuilderVolume& volume,bool marker)
    {
        catalog::BtreeRecord record;std::string error;
        for(auto& [id,inode]:inodes){
            if((inode.mode&0170000)==0040000)inode.children_or_links=static_cast<std::int32_t>(std::count_if(entries.begin(),entries.end(),[&](const auto& e){return e.parent_id==id;}));
            Check(EncodeAppleInodeRecord(inode,record,error),"inode encodes");volume.filesystem_records.push_back(record);
        }
        const auto policy=ApfsNamePolicy::FromIncompatibleFeatures(volume.incompat);
        for(const auto& entry:entries){Check(EncodeAppleDirectoryRecord(entry,policy,record,error),"directory encodes");volume.filesystem_records.push_back(record);}
        volume.filesystem_records.insert(volume.filesystem_records.end(),extra.begin(),extra.end());
        if(marker){
            Check(EncodeAppleXattrRecord({3,std::string(kFirmlinkEaName),kAppleXattrDataEmbedded,{std::byte{0xff},std::byte{0x7f}}},record,error),"opaque marker encodes");
            volume.filesystem_records.push_back(record);
        }
        Check(SortAppleBtreeRecords(volume.filesystem_records,policy.UsesHashedDirectoryKeys()?AppleBtreeKeyOrder::FileSystemHashedDirectory:AppleBtreeKeyOrder::FileSystemCaseSensitive,error),"filesystem records sort");
    }
};
FirmlinkImageOptions Options(){return {std::string(32,'a'),std::string(32,'d'),101,102,20};}
const auto payload=Bytes("independently expected data-volume bytes\n");
const auto peer=Bytes("independent peer remains unchanged\n");
const auto system_only=Bytes("hidden backing System child\n");
const auto kernel=Bytes("independent System-root file\n");
void Mint(const std::filesystem::path& path,const std::vector<std::byte>& table,bool marker,
    bool missing_target=false,bool wrong_role=false,bool table_on_data_only=false,std::uint64_t name_features=0)
{
    BuilderStore builder;builder.block_size=16384;builder.block_count=1024;builder.xid=20;
    builder.authoritative_checkpoint=true;builder.dual_checkpoint=false;builder.authoritative_internal_pool_blocks=16;
    builder.authoritative_checkpoint_ring_blocks=16;builder.volumes.resize(2);
    builder.volumes[0].oid=101;builder.volumes[1].oid=102;
    std::vector<FirmlinkTablePathPair> pairs;std::string error;
    const auto canonical=Read(path.parent_path()/"apple-firmlinks");
    Check(ParseAppleFirmlinkTable(canonical,pairs,error),"primary Apple table parses for fixture directories");
    Tree trees[2];
    for(unsigned index=0;index<2;++index){
        auto& volume=builder.volumes[index];volume.projectable=true;volume.incompat=name_features;volume.features=0x11;
        volume.group_hex=std::string(32,'d');volume.uuid_hex=std::string(32,index?'c':'b');
        volume.role=static_cast<std::uint16_t>(index?0x40:1);volume.name="Same label";
        if(wrong_role&&index)volume.role=0x4;
        for(const auto& pair:pairs){if(!(missing_target&&index&&pair.data_relative_path=="usr/local"))trees[index].Directory(pair.system_path);}
    }
    const auto seed=[&](std::uint64_t block,std::span<const std::byte> bytes){std::vector<std::byte> data(builder.block_size);std::copy(bytes.begin(),bytes.end(),data.begin());builder.authoritative_seeded_main_blocks.push_back({block,std::move(data)});};
    if(!table_on_data_only){trees[0].File("/usr/share/firmlinks",42,table,128,builder.volumes[0],builder.block_size);seed(128,table);}
    else {trees[1].File("/usr/share/firmlinks",42,table,128,builder.volumes[1],builder.block_size);seed(128,table);}
    trees[1].File("/Users/payload",43,payload,129,builder.volumes[1],builder.block_size);seed(129,payload);
    trees[1].File("/Library/peer",44,peer,130,builder.volumes[1],builder.block_size);seed(130,peer);
    trees[0].File("/Users/SystemOnly",44,system_only,131,builder.volumes[0],builder.block_size);seed(131,system_only);
    trees[0].File("/KernelReadme",45,kernel,132,builder.volumes[0],builder.block_size);seed(132,kernel);
    for(unsigned index=0;index<2;++index)trees[index].Finish(builder.volumes[index],marker&&index==0);
    auto image=BuildStoreImage(builder);
    // Fixture builder's informational counters are fixed examples. Give this
    // canonical fixture its actual independently counted file/directory totals.
    for(unsigned index=0;index<2;++index){
        const auto start=static_cast<std::size_t>((kFirstVolumeBlock+index)*builder.block_size);
        std::vector<std::byte> block(image.begin()+start,image.begin()+start+builder.block_size);
        PutU64LE(block,0xB8,static_cast<std::uint64_t>(std::count_if(trees[index].inodes.begin(),trees[index].inodes.end(),[](const auto& v){return (v.second.mode&0170000)==0100000;})));
        PutU64LE(block,0xC0,static_cast<std::uint64_t>(trees[index].dirs.size()));FletcherForBlock(block,block.size());
        std::copy(block.begin(),block.end(),image.begin()+start);
    }
    std::ofstream file(path,std::ios::binary);file.write(reinterpret_cast<const char*>(image.data()),static_cast<std::streamsize>(image.size()));Check(static_cast<bool>(file),"canonical image fixture materialized");
}
void ParserTests(const std::vector<std::byte>& primary)
{
    std::vector<FirmlinkTablePathPair> pairs;std::string error;
    Check(ParseAppleFirmlinkTable(primary,pairs,error)&&pairs.size()==19,"19 published Apple mappings");
    for(const auto& text:{"/Users Users\n","/Users\tUsers\r\n","/Users\tUsers","/Users\tElsewhere\n","/Users\tUsers\textra\n",
        "/Users\tUsers\n/Users\tUsers\n","/../Users\t../Users\n","/Users//child\tUsers//child\n","# comment\n","/\t\n"}){
        Check(!ParseAppleFirmlinkTable(Bytes(text),pairs,error)&&pairs.empty(),"unsupported/malformed table refuses complete output");
    }
    Check(!ParseAppleFirmlinkTable(std::vector<std::byte>(65537,std::byte{'x'}),pairs,error)&&pairs.empty(),"table byte bound");
}
void ActualTests(const std::filesystem::path& directory,const std::vector<std::byte>& primary)
{
    const auto positive=directory/"system-data.apfs";Mint(positive,primary,true);
    const auto before=Read(positive);std::shared_ptr<const ApfsFirmlinkProducer> owner;std::string error;
    const bool opened=ApfsFirmlinkProducer::TryOpenImage(positive.wstring(),Options(),owner,error);
    Check(opened,"actual source bytes -> verified pairs -> router: "+error);
    Check(owner->Records().size()==19&&owner->TableByteLength()==primary.size()&&owner->TableIdentity().object_id==42&&
        owner->TableIdentity().volume.object_id==101&&owner->OpaqueMarkerCount()==1,"System table identity and nonauthorizing opaque marker census");
    const std::array<std::uint8_t,32> expected_sha={0xbc,0x50,0xf9,0x53,0x0f,0x21,0x36,0x66,
        0x8b,0xc8,0xe8,0x32,0x7f,0xbe,0x68,0xd5,0x48,0x22,0x9f,0x10,0x45,0x4c,0xe6,0x6b,
        0x06,0xac,0x87,0xdb,0x97,0x26,0x97,0x8b};
    Check(owner->TableSha256()==expected_sha,"actual System bytes match immutable Apple source SHA256");
    const auto identity=owner->SourceIdentity();
    FirmlinkLookupResult result;
    Check(owner->TryLookup("/Users",FirmlinkAccess::Read,result,error)&&result.identity.object_id==3&&result.identity.volume.object_id==102&&
        result.identity.volume.volume_uuid_hex==std::string(32,'c')&&result.identity.checkpoint_xid==20&&result.identity.inode_xid==20,
        "same local inode OID across paired volumes routes by full identity");
    Check(owner->TryLookup("/Users/..",FirmlinkAccess::Read,result,error)&&result.identity.volume.object_id==101&&result.identity.object_id==2,"XNU parent reversal selects System parent");
    Check(owner->TryLookup("/Users/../usr/local",FirmlinkAccess::Read,result,error)&&result.identity.volume.object_id==102,"fresh multicomponent namespace lookup crosses again after parent reversal");
    Check(!owner->TryLookup("/Users/SystemOnly",FirmlinkAccess::Read,result,error)&&result.identity.object_id==0,"hidden System child is not used as fallback");
    Check(!owner->TryLookup("/Users/payload",FirmlinkAccess::Mutation,result,error)&&result.identity.object_id==0,"unified mutation refused including file leaf");
    Check(!owner->TryLookup("/users/payload",FirmlinkAccess::Read,result,error)&&result.identity.object_id==0,"case-sensitive policy never silently casefolds");
    for(const auto* path:{"Users","/Users/","/Users//payload","/Users/payload/child"})
        Check(!owner->TryLookup(path,FirmlinkAccess::Read,result,error)&&result.identity.object_id==0,"invalid or nondirectory lookup clears output");
    const std::string nul_path("/Users\0/payload",15);
    Check(!owner->TryLookup(nul_path,FirmlinkAccess::Read,result,error)&&result.identity.object_id==0,"embedded NUL lookup refuses");
    std::vector<std::byte> bytes;
    Check(owner->TryReadFile("/Users/payload",0,4096,bytes,error)&&bytes==payload,"actual routed Data bytes independently expected");
    Check(owner->TryReadFile("/Library/peer",0,4096,bytes,error)&&bytes==peer,"independent Data peer bytes unchanged");
    Check(owner->TryReadFile("/KernelReadme",0,4096,bytes,error)&&bytes==kernel,"noncrossing System bytes unchanged");
    Check(owner->TryReadFile("/usr/share/firmlinks",0,65536,bytes,error)&&bytes==primary,"exact primary table bytes read from System inode");
    Check(!owner->TryReadFile("/Users/payload",0,(1u<<20)+1,bytes,error)&&bytes.empty(),"read allocation bound clears previous payload");
    Check(!owner->TryReadFile("/Users/payload",INT64_MAX,1,bytes,error)&&bytes.empty(),"signed read arithmetic refuses overflow");
    Check(owner->TryReadFile("/Users/payload",payload.size(),1,bytes,error)&&bytes.empty(),"EOF read returns no invented bytes");
    HANDLE writer=CreateFileW(positive.c_str(),GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,0,nullptr);
    const auto last_error=GetLastError();if(writer!=INVALID_HANDLE_VALUE)CloseHandle(writer);
    Check(writer==INVALID_HANDLE_VALUE&&last_error==ERROR_SHARING_VIOLATION,"stable image lease excludes source writes");
    owner.reset();
    Check(ApfsFirmlinkProducer::TryOpenImage(positive.wstring(),Options(),owner,error),"fresh producer/catalog/projection/router owner");
    Check(owner->SourceIdentity()==identity&&owner->TryReadFile("/Users/payload",0,payload.size(),bytes,error)&&bytes==payload,"fresh source identity and routed bytes unchanged");
    owner.reset();Check(Read(positive)==before,"all RO queries leave actual image byte-exact");
    for(unsigned kind=0;kind!=5;++kind){
        auto options=Options();if(kind==0)options.container_uuid_hex=std::string(32,'e');
        if(kind==1)options.group_uuid_hex=std::string(32,'e');if(kind==2)std::swap(options.system_volume_oid,options.data_volume_oid);
        if(kind==3)options.checkpoint_xid=19;if(kind==4)options.data_volume_oid=999;
        Check(!ApfsFirmlinkProducer::TryOpenImage(positive.wstring(),options,owner,error)&&!owner,"wrong owner identity refuses no published producer");
    }
    for(const auto& uuid:{std::string(32,'0'),std::string(32,'g'),std::string(31,'a')}){
        auto options=Options();options.group_uuid_hex=uuid;
        Check(!ApfsFirmlinkProducer::TryOpenImage(positive.wstring(),options,owner,error)&&!owner&&error=="FirmlinkExpectedIdentityInvalid","invalid trusted UUID refuses before opening image");
    }
    auto nul_image=positive.wstring();nul_image.push_back(L'\0');nul_image+=L"ignored";
    Check(!ApfsFirmlinkProducer::TryOpenImage(nul_image,Options(),owner,error)&&!owner&&error=="FirmlinkImagePathInvalid","embedded NUL image spelling refuses before opening");
    const auto refused=[&](const char* name,const std::vector<std::byte>& table,bool missing,bool role,bool wrong_volume){
        const auto path=directory/name;Mint(path,table,true,missing,role,wrong_volume);const auto original=Read(path);
        Check(!ApfsFirmlinkProducer::TryOpenImage(path.wstring(),Options(),owner,error)&&!owner,"actual canonical refusal "+std::string(name));
        Check(Read(path)==original,"refused canonical image unchanged "+std::string(name));
    };
    refused("bad-table.apfs",Bytes("/Users\tElsewhere\n"),false,false,false);
    refused("missing-target.apfs",primary,true,false,false);
    refused("wrong-role.apfs",primary,false,true,false);
    refused("table-data-only.apfs",primary,false,false,true);
    const auto no_marker=directory/"no-marker.apfs";Mint(no_marker,primary,false);
    Check(ApfsFirmlinkProducer::TryOpenImage(no_marker.wstring(),Options(),owner,error)&&owner->Records().size()==19&&owner->OpaqueMarkerCount()==0,
        "canonical table authority needs no invented marker serialization");
    owner.reset();
}
void CasePolicyTest(const std::filesystem::path& directory,const std::vector<std::byte>& primary)
{
    const auto path=directory/"casefold.apfs";Mint(path,primary,false,false,false,false,9);
    std::shared_ptr<const ApfsFirmlinkProducer> owner;std::string error;
    const bool opened=ApfsFirmlinkProducer::TryOpenImage(path.wstring(),Options(),owner,error);
    Check(opened,"actual case/normalization policy preserved: "+error);
    FirmlinkLookupResult result;std::vector<std::byte> bytes;
    Check(owner->TryLookup("/uSeRs/PaYlOaD",FirmlinkAccess::Read,result,error)&&result.identity.volume.object_id==102&&
        result.identity.volume.incompatible_features==9,"casefold lookup retains exact source policy bits");
    Check(owner->TryReadFile("/uSeRs/PaYlOaD",0,4096,bytes,error)&&bytes==payload,"casefold actual Data read");
    const auto identity=owner->SourceIdentity();owner.reset();
    Check(ApfsFirmlinkProducer::TryOpenImage(path.wstring(),Options(),owner,error)&&owner->SourceIdentity()==identity&&
        owner->TryReadFile("/uSeRs/PaYlOaD",0,4096,bytes,error)&&bytes==payload,"fresh casefold owner preserves policy and backing bytes");
}
}
int main(int argc,char** argv)
{
    try{
        Check(argc==3||argc==4,"private evidence directory and pinned Apple table arguments");
        const auto directory=std::filesystem::path(argv[1]);std::filesystem::create_directories(directory);
        const auto primary=Read(argv[2]);Check(primary.size()==689,"published Apple primary fixture length");
        std::filesystem::copy_file(argv[2],directory/"apple-firmlinks",std::filesystem::copy_options::none);
        if(argc==4&&std::string_view(argv[3])=="all") {ParserTests(primary);ActualTests(directory,primary);CasePolicyTest(directory,primary);}
        else if(argc==4&&std::string_view(argv[3])=="casefold")CasePolicyTest(directory,primary);
        else if(argc==4)Check(false,"unknown private phase");
        else {ParserTests(primary);ActualTests(directory,primary);}
        std::cout<<"PASS "<<checks<<" checks: actual canonical System table bytes -> paired directory identities -> RO router -> fresh namespace/readback\n";
        return 0;
    }catch(const std::exception& e){std::cerr<<"FAIL "<<e.what()<<" after "<<checks<<" checks\n";return 1;}
}
