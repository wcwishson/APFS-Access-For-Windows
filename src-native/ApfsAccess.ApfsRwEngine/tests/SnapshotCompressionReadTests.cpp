#define main retained_snapshot_projection_main
#include "SnapshotProjectionTests.cpp"
#undef main
#include <filesystem>
#include <fstream>

namespace {
using Store=MetadataStore;
void SaveImage(const std::filesystem::path& path,const Bytes& bytes) {
    std::ofstream out(path,std::ios::binary|std::ios::trunc);
    out.write(reinterpret_cast<const char*>(bytes.data()),bytes.size());Check(bool(out),"save immutable image fixture");
}
Store::VolumeContext Context(const std::filesystem::path& path,const ApfsSnapshotIdentity& id) {
    Store::VolumeContext c;c.device_path=path.wstring();c.device_offset_bytes=id.scope.store_offset_bytes;
    c.volume_object_id=id.scope.volume_oid;c.allow_legacy_scaffold_for_fixtures=false;return c;
}
Bytes CompressedHex(std::string_view text) {
    Bytes out;
    const auto digit=[](char c)->unsigned { return c<='9'?c-'0':c-'a'+10; };
    for(std::size_t i=0;i<text.size();i+=2) out.push_back(std::byte((digit(text[i])<<4)|digit(text[i+1])));
    return out;
}
Bytes CompressionDescriptor(unsigned type,std::uint64_t size,const Bytes& payload={}) {
    auto out=CompressedHex("66706d63000000000000000000000000");
    PutU32LE(out,4,type);PutU64LE(out,8,size);out.insert(out.end(),payload.begin(),payload.end());return out;
}
// Independent .NET ZLibStream vectors retained in the canonical codec tests.
const auto compressed_hello=CompressedHex("78dacb48cdc9c90700062c0215");
const auto compressed_a64k=CompressedHex("78daedc181000000008020b6fda516a90a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006a1e8703d0");
Bytes CompressionResource(const std::vector<Bytes>& blocks) {
    Bytes out(0x108+blocks.size()*8);
    const auto be=[&](std::size_t at,std::uint32_t n){for(unsigned i=0;i<4;++i)out.at(at+i)=std::byte(n>>(24-8*i));};
    be(0,0x100);be(12,50);PutU32LE(out,0x104,static_cast<std::uint32_t>(blocks.size()));
    for(std::size_t i=0;i<blocks.size();++i){
        PutU32LE(out,0x108+i*8,static_cast<std::uint32_t>(out.size()-0x104));
        PutU32LE(out,0x10c+i*8,static_cast<std::uint32_t>(blocks[i].size()));
        out.insert(out.end(),blocks[i].begin(),blocks[i].end());
    }
    be(4,static_cast<std::uint32_t>(out.size()));be(8,static_cast<std::uint32_t>(out.size()-0x100));
    be(0x100,static_cast<std::uint32_t>(out.size()-0x104));
    const auto trailer=CompressedHex("000000000000000000000000000000000000000000000000001c003200000000636d70660000000a0001ffff000000000000");
    out.insert(out.end(),trailer.begin(),trailer.end());return out;
}
struct CompressedFixture:Fixture {
    Bytes descriptor,resource,expected;
    explicit CompressedFixture(unsigned mode=0,bool offset=false) {
        expected=CompressedHex("68656c6c6f");
        descriptor=CompressionDescriptor(3,5,compressed_hello);
        if(mode==1)descriptor=CompressionDescriptor(7,5,CompressedHex("e568656c6c6f0600000000000000"));
        if(mode==2||mode==5){
            resource=CompressionResource(mode==5?std::vector<Bytes>{compressed_a64k,compressed_hello}:std::vector<Bytes>{compressed_hello});
            if(mode==5){expected=Bytes(65536,std::byte{'A'});const auto tail=CompressedHex("68656c6c6f");expected.insert(expected.end(),tail.begin(),tail.end());}
            descriptor=CompressionDescriptor(4,expected.size());
        }
        if(mode==3){
            resource=CompressedHex("0800000016000000e568656c6c6f0600000000000000");
            descriptor=CompressionDescriptor(8,5);
        }
        AppleInodeRecord inode;std::string error;
        Check(ApfsExtendedRecordCodec::DecodeInode(fs[2],inode,error),"decode compressed historical inode");
        inode.bsd_flags|=kAppleBsdCompressedFlag;inode.internal_flags|=kAppleInodeHasUncompressedSize;
        inode.uncompressed_size=expected.size();
        for(auto& field:inode.extended_fields)if(field.type==8)field.data=Bytes(40);
        fs[2]=Encode(inode,EncodeAppleInodeRecord);fs.erase(fs.begin()+3);refs.clear();
        if(mode==4)ExternalAttribute("com.apple.decmpfs",40,222,descriptor);
        else fs.push_back(Encode(AppleXattrRecord{30,"com.apple.decmpfs",kAppleXattrDataEmbedded,descriptor},EncodeAppleXattrRecord));
        if(!resource.empty())ExternalAttribute("com.apple.ResourceFork",41,223,resource);
        Trees();for(const auto block:{4ull,180ull})Edit(block,[](auto& b){PutU16LE(b,0x3c4,0x180);});
        if(offset){image.insert(image.begin(),8192,std::byte{0xEE});scope.store_offset_bytes=8192;}
    }
    void ExternalAttribute(const std::string& name,std::uint64_t id,std::uint64_t block,const Bytes& bytes){
        Check(bytes.size()<=bs,"one allocated fixture xattr block");
        Bytes data(48);PutU64LE(data,0,id);PutU64LE(data,8,bytes.size());PutU64LE(data,16,bs);
        fs.push_back(Encode(AppleXattrRecord{30,name,kAppleXattrDataStream,data},EncodeAppleXattrRecord));
        fs.push_back(Encode(AppleDataStreamIdRecord{id,1},EncodeAppleDataStreamIdRecord));
        fs.push_back(Encode(AppleFileExtentRecord{id,0,bs,block,0,static_cast<std::uint32_t>(bs)},EncodeAppleFileExtentRecord));
        refs.push_back(Encode(ApplePhysicalExtentRecord{block,1,1,30,1},EncodeApplePhysicalExtentRecord));
        Bytes payload(bs);std::copy(bytes.begin(),bytes.end(),payload.begin());Put(block,payload,false);
    }
};
void CompressedPositive(unsigned mode,bool offset){
    CompressedFixture f(mode,offset);const auto id=f.Identity();const auto before=f.image;
    const auto path=std::filesystem::absolute("compressed-"+std::to_string(mode)+(offset?"-offset":"")+".apfs");SaveImage(path,f.image);
    for(unsigned reopen=0;reopen<2;++reopen){
        Store store(Context(path,id));std::string error;
        Check(store.PrepareNativeSnapshotReadPath(id,error),"admit compressed immutable backup: "+error);
        Check(store.LookupCommittedInodeByPath(L"\\report.txt")->logical_size==f.expected.size(),"decoded EOF from exact historical descriptor");
        Bytes bytes{std::byte{0xD1}};
        Check(store.ReadCommittedFileRange(L"\\report.txt",0,f.expected.size()+17,bytes)&&bytes==f.expected,"full historical decoded bytes");
        Check(store.ReadCommittedFileRange(L"\\report.txt",f.expected.size()-2,99,bytes)&&
            bytes==Bytes(f.expected.end()-2,f.expected.end()),"clipped decoded tail");
        Check(store.ReadCommittedFileRange(L"\\report.txt",UINT64_MAX,0,bytes)&&bytes.empty(),"decoded EOF validates then returns empty");
        if(mode==5){Check(store.ReadCommittedFileRange(L"\\report.txt",65534,5,bytes)&&bytes==CompressedHex("414168656c"),"codec block crossing");}
        const auto key=ApfsNameCodec::CanonicalWindowsPathKey(L"\\report.txt",ApfsNamePolicy::FromIncompatibleFeatures(store.Context().incompatible_features));
        Check(key.ok(),"compressed canonical name");auto plan=store.SnapshotCommittedFileReadPlan(*key.value);
        Check(plan&&plan->HasCompressionReadCandidate()&&plan->native_snapshot,"captured exact immutable compression roots");
        bytes=Bytes(f.expected.size());std::size_t count=99;
        Check(store.ReadCommittedFileRangeFromPlan(*plan,L"\\report.txt",0,bytes.size(),bytes.data(),bytes.size(),count)&&bytes==f.expected&&count==bytes.size(),"callback plan decoder path");
        Store foreign(Context(path,id));Check(foreign.PrepareNativeSnapshotReadPath(id,error),"fresh foreign owner");
        bytes=Bytes(8,std::byte{0xD2});count=99;
        Check(!foreign.ReadCommittedFileRangeFromPlan(*plan,L"\\report.txt",0,5,bytes.data(),bytes.size(),count)&&count==0&&bytes==Bytes(8,std::byte{0xD2}),"foreign plan refuses without output");
        Bytes descriptor(f.descriptor.size());
        Check(store.ReadCommittedExtendedAttributeRange(30,"com.apple.decmpfs",0,descriptor,count)&&descriptor==f.descriptor,"raw historical decmpfs preserved");
        if(!f.resource.empty()){Bytes fork(f.resource.size());Check(store.ReadCommittedExtendedAttributeRange(30,"com.apple.ResourceFork",0,fork,count)&&fork==f.resource,"raw historical compression fork preserved");}
        Store::MutationRequest write;write.operation=Store::MutationOperation::Write;write.path=L"\\report.txt";write.inline_payload=Bytes(1);write.length=1;
        Check(store.StageMutation(write)==Store::MutationStatus::UnsupportedOperation&&!store.PrepareNativeWritePath(),"compressed immutable view cannot acquire writer");
        Check(store.Device().RevalidateStableReadOnlyImage()&&!store.Device().HasWriteHandle(),"stable readonly image lease retained");
    }
    std::ifstream file(path,std::ios::binary);Bytes after(f.image.size());file.read(reinterpret_cast<char*>(after.data()),after.size());Check(after==before,"compressed source unchanged across fresh owners");
    Pass("compressed backup mode="+std::to_string(mode)+" offset="+std::to_string(offset));
}
void CompressedRefusals(){
    const auto reject=[](const char* name,const std::function<void(CompressedFixture&)>& change){
        CompressedFixture f;change(f);f.Trees();VectorRandomAccessSource source(f.image);Projection out;std::string error;
        Check(!Load(source,f.Identity(),out,error)&&!out&&!error.empty(),std::string("refuse ")+name);Pass(name);
    };
    reject("descriptor absent",[](auto& f){f.fs.pop_back();});
    reject("unknown compression type",[](auto& f){PutU32LE(f.fs.back().value,8,99);});
    reject("compressed default stream still allocated",[](auto& f){f.fs.push_back(Encode(AppleFileExtentRecord{30,0,4096,220,0,4096},EncodeAppleFileExtentRecord));f.refs.push_back(Encode(ApplePhysicalExtentRecord{220,1,1,30,1},EncodeApplePhysicalExtentRecord));});
    reject("wrong decoded EOF",[](auto& f){AppleInodeRecord inode;std::string e;Check(ApfsExtendedRecordCodec::DecodeInode(f.fs[2],inode,e),"decode EOF");inode.uncompressed_size++;f.fs[2]=Encode(inode,EncodeAppleInodeRecord);});
    reject("resource fork missing",[](auto& f){f.fs.back()=Encode(AppleXattrRecord{30,"com.apple.decmpfs",kAppleXattrDataEmbedded,CompressionDescriptor(4,5)},EncodeAppleXattrRecord);});
    for(unsigned mode:{0u,2u}){
        CompressedFixture f(mode);
        if(mode==0){f.descriptor.back()^=std::byte{1};f.fs.back()=Encode(AppleXattrRecord{30,"com.apple.decmpfs",kAppleXattrDataEmbedded,f.descriptor},EncodeAppleXattrRecord);f.Trees();}
        else f.Edit(223,[](auto& b){b[0]=std::byte{0x7F};},false);
        const auto id=f.Identity();const auto path=std::filesystem::absolute("bad-codec-"+std::to_string(mode)+".apfs");SaveImage(path,f.image);
        Store store(Context(path,id));std::string error;Check(store.PrepareNativeSnapshotReadPath(id,error),"header valid; codec bytes remain untrusted");
        Bytes out(9,std::byte{0xB1});const auto before=out;
        Check(!store.ReadCommittedFileRange(L"\\report.txt",0,5,out)&&out==before,"bad historical codec leaves vector untouched");
        std::size_t count=99;Check(!store.ReadCommittedFileRangeInto(L"\\report.txt",0,5,out.data(),out.size(),count)&&count==0&&out==before,"bad historical codec leaves callback output untouched");
        Pass("codec refusal mode="+std::to_string(mode));
    }
    CompressedFixture f;VectorRandomAccessSource source(f.image);std::string error;
    auto cp=LoadAppleCheckpointView(source,0,source.SizeBytes(),error);Check(bool(cp),"source-free control checkpoint");
    auto budget=std::make_shared<ApfsReadBudget>(65536,256ull*1024*1024,1000000,256ull*1024*1024);
    Check(!NativeApfsReader::ValidateOrdinaryFileSystemRecords(f.fs,cp->container.superblock,
        cp->volumes.front().superblock,budget,error)&&error.find("Compressed")!=std::string::npos,
        "source-free validation does not acquire compressed read authority");Pass("source-free validator unchanged");
}
}
int main(int argc,char** argv){try{
    if(argc==3&&std::string_view(argv[1])=="--make-fixture") {CompressedFixture f(5);SaveImage(std::filesystem::absolute(argv[2]),f.image);return 0;}
    for(unsigned mode=0;mode<6;++mode)for(bool offset:{false,true})CompressedPositive(mode,offset);
    CompressedRefusals();std::cout<<"RESULT PASS cases="<<cases<<" checks="<<checks<<"\n";return 0;
}catch(const std::exception& e){std::cerr<<"FAIL checks="<<checks<<": "<<e.what()<<"\n";return 1;}}
