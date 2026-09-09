// Fixture bytes adapted from ApfsFusionStoreTests and ApfsFusionCatalogTests. Export only.
#include "ApfsFusionStore.h"
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

using namespace apfsaccess::catalog;
namespace
{
using Bytes = std::vector<std::byte>;
unsigned checks = 0, cases = 0;
void Check(bool ok, const std::string& why) { ++checks; if (!ok) throw std::runtime_error(why); }
void Put(Bytes& b, std::size_t at, std::uint64_t value, std::size_t width = 8)
{ for (std::size_t n = 0; n < width; ++n) b.at(at + n) = std::byte((value >> (8 * n)) & 255); }
void Seal(Bytes& b) { Put(b, 0, Fletcher64(b.data() + 8, b.size() - 8).value()); }
Bytes Object(std::size_t bs, std::uint64_t oid, std::uint32_t type, std::uint64_t xid = 20)
{
    Bytes b(bs); Put(b, 8, oid); Put(b, 16, xid); Put(b, 24, type, 4); Seal(b); return b;
}
Bytes MiddleTree(std::size_t bs, std::uint64_t oid, bool nonempty = false)
{
    auto b = Object(bs, oid, kObjectPhysical | kObjectTypeBtree);
    Put(b, 28, 0x15, 4); Put(b, 0x20, 7, 2); // physical root, leaf, fixed KV
    Put(b, 0x24, nonempty ? 1 : 0, 4); Put(b, 0x2A, nonempty ? 4 : 0, 2);
    Put(b, 0x2C, nonempty ? 8 : 0, 2);
    Put(b, 0x2E, bs - 40 - 0x38 - (nonempty ? 28 : 0), 2);
    Put(b, 0x30, 0xFFFF, 2); Put(b, 0x34, 0xFFFF, 2);
    const auto info = bs - 40;
    Put(b, info, 0x11, 4); Put(b, info + 4, bs, 4); Put(b, info + 8, 8, 4);
    Put(b, info + 12, 16, 4); Put(b, info + 16, nonempty ? 8 : 0, 4);
    Put(b, info + 20, nonempty ? 16 : 0, 4); Put(b, info + 24, nonempty ? 1 : 0);
    Put(b, info + 32, 1);
    if (nonempty)
    {
        Put(b, 0x38, 0, 2); Put(b, 0x3A, 16, 2);
        Put(b, 0x3C, kFusionTier2ByteAddress / bs + 20);
        Put(b, info - 16, 20); Put(b, info - 8, 1, 4); Put(b, info - 4, 1, 4);
    }
    Seal(b); return b;
}
struct Source final : RandomAccessSource
{
    Bytes bytes;
    bool present = true, short_read = false, false_read = false;
    mutable std::uint64_t calls = 0, bytes_read = 0;
    mutable std::vector<std::pair<std::uint64_t, std::size_t>> reads;
    std::shared_ptr<ApfsReadBudget> budget;
    std::function<void()> after_read;
    explicit Source(std::size_t size) : bytes(size) {}
    std::uint64_t SizeBytes() const override { return bytes.size(); }
    std::shared_ptr<ApfsReadBudget> ReadBudget() const override { return budget; }
    bool Read(std::uint64_t offset, std::size_t size, Bytes& out) const override
    {
        ++calls; bytes_read += size; reads.emplace_back(offset, size); out.clear();
        if (budget && !budget->Read(size)) return false;
        if (!present || offset > bytes.size() || size > bytes.size() - offset) return false;
        out.assign(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
            bytes.begin() + static_cast<std::ptrdiff_t>(offset + size));
        if (short_read && !out.empty()) out.pop_back();
        if (after_read) after_read();
        return !false_read;
    }
};
struct Fixture
{
    std::uint32_t bs;
    std::uint64_t prefix;
    std::array<std::shared_ptr<Source>, 2> sources;
    FusionBindRequest request;
    explicit Fixture(std::uint32_t block_size = 4096, std::uint64_t prefix_blocks = 0)
        : bs(block_size), prefix(prefix_blocks * block_size)
    {
        sources[0] = std::make_shared<Source>(static_cast<std::size_t>(prefix + 64 * bs));
        sources[1] = std::make_shared<Source>(static_cast<std::size_t>(prefix + 32 * bs));
        request.container_uuid_hex = std::string(32, 'a');
        request.fusion_uuid_hex = std::string(32, 'b'); request.fusion_uuid_hex.back() = 'a';
        request.checkpoint_xid = 20;
        request.convention = FusionRoleConvention::LinuxApfsLastByteLowBit;
        Budget();
        for (std::size_t i = 0; i < 2; ++i)
        {
            FusionImageMember m;
            m.exact_identity = {1, {}, sources[i]->SizeBytes(), 1, 2};
            m.exact_identity.file_id[0] = std::byte(i + 1);
            m.stable_store_id = i ? "apfs-store:test-tier2" : "apfs-store:test-main";
            m.role = i ? FusionMemberRole::Tier2 : FusionMemberRole::Main;
            m.store_offset = prefix; m.store_size = (i ? 32ULL : 64ULL) * bs;
            request.members.push_back(m);
        }
        auto nx = Object(bs, 1, kObjectEphemeral | kNxSuperblockObjectType);
        Put(nx, 0x20, kNxsbMagic, 4); Put(nx, 0x24, bs, 4); Put(nx, 0x28, 96);
        Put(nx, 0x40, 0x102); std::fill_n(nx.begin() + 0x48, 16, std::byte{0xAA});
        Put(nx, 0x58, 100); Put(nx, 0x60, 21);
        Put(nx, 0x68, 4, 4); Put(nx, 0x6C, 4, 4); Put(nx, 0x70, 1); Put(nx, 0x78, 8);
        Put(nx, 0x80, 2, 4); Put(nx, 0x84, 2, 4); Put(nx, 0x88, 0, 4);
        Put(nx, 0x8C, 2, 4); Put(nx, 0x90, 0, 4); Put(nx, 0x94, 2, 4);
        Put(nx, 0x98, 10); Put(nx, 0xA0, 15); Put(nx, 0xB4, 100, 4);
        std::fill_n(nx.begin() + 0x500, 16, std::byte{0xBB}); nx[0x50F] = std::byte{0xBA};
        Put(nx, 0x548, 17); Put(nx, 0x550, 19); Put(nx, 0x558, 24); Put(nx, 0x560, 4);
        Seal(nx); Place(0, 0, nx); Place(0, 2, nx);
        nx[0x50F] |= std::byte{1}; Seal(nx); Place(1, 0, nx);
        auto map = Object(bs, 1, kObjectPhysical | kObjectTypeCheckpointMap);
        Put(map, 0x20, 1, 4); Put(map, 0x24, 2, 4);
        Put(map, 0x28, kObjectEphemeral | kObjectTypeSpaceman, 4);
        Put(map, 0x30, bs, 4); Put(map, 0x40, 10); Put(map, 0x48, 8);
        Put(map, 0x50, kObjectEphemeral | 0x16, 4); Put(map, 0x58, bs, 4);
        Put(map, 0x68, 19); Put(map, 0x70, 9); Seal(map); Place(0, 1, map);
        auto sm = Object(bs, 10, kObjectEphemeral | kObjectTypeSpaceman);
        Put(sm, 0x20, bs, 4); Put(sm, 0x24, 8ULL * bs, 4);
        Put(sm, 0x28, (bs - 0x28) / 0x20, 4); Put(sm, 0x2C, (bs - 0x28) / 8, 4);
        for (std::size_t i = 0; i < 2; ++i)
        { auto at = 0x30 + i * 0x30; Put(sm, at, i ? 32 : 64); Put(sm, at + 8, 1); Put(sm, at + 0x10, 1, 4); }
        Put(sm, 0x154, 0x158, 4); Seal(sm); Place(0, 8, sm);
        auto cache = Object(bs, 19, kObjectEphemeral | 0x16);
        Put(cache, 0x20, 0x70); Seal(cache); Place(0, 9, cache);
        Place(0, 17, MiddleTree(bs, 17));
        Place(0, 16, Object(bs, 16, kObjectPhysical | kObjectTypeFs));
        Place(1, 4, Object(bs, TierBlock() + 4, kObjectPhysical | kObjectTypeFs));
        for (std::size_t i = 0; i < 2; ++i)
        {
            Place(i, 20, Bytes(bs, std::byte(i ? 0xB1 : 0xA1)));
            Place(i, 21, Bytes(bs, std::byte(i ? 0xB2 : 0xA2)));
        }
    }
    std::uint64_t TierBlock() const { return kFusionTier2ByteAddress / bs; }
    void Budget(std::uint64_t reads = 10000, std::uint64_t bytes = 64 * 1024 * 1024,
        std::uint64_t records = 10000, std::uint64_t material = 64 * 1024 * 1024)
    { request.budget = std::make_shared<ApfsReadBudget>(reads, bytes, records, material); }
    void Place(std::size_t member, std::uint64_t block, const Bytes& bytes)
    { std::copy(bytes.begin(), bytes.end(), sources[member]->bytes.begin() + static_cast<std::ptrdiff_t>(prefix + block * bs)); }
    Bytes Block(std::size_t member, std::uint64_t block)
    {
        const auto at = static_cast<std::ptrdiff_t>(prefix + block * bs);
        return Bytes(sources[member]->bytes.begin() + at, sources[member]->bytes.begin() + at + bs);
    }
    void Edit(std::size_t member, std::uint64_t block, const std::function<void(Bytes&)>& change)
    { auto b = Block(member, block); change(b); Seal(b); Place(member, block, b); }
    void EditNx(const std::function<void(Bytes&)>& change)
    { Edit(0, 0, change); Edit(0, 2, change); Edit(1, 0, change); }
};
}
#include "ApfsFusionReadSession.h"
#include "ApfsExtendedRecordCodec.h"
#include "TestFixtureBuilder.h"
#include <type_traits>
namespace tf = apfsaccess::testfixture;
using namespace apfsaccess::rw;
using Record = apfsaccess::catalog::BtreeRecord;
static_assert(!std::is_convertible_v<AppleReadOnlyVolumeView, AppleCheckpointView>);
namespace {
std::string active_filter;
template<class T, class F> Record Enc(const T& value, F encode) {
    Record out; std::string error; if (!encode(value,out,error)) throw std::runtime_error(error); return out;
}
Record FileInode(std::uint64_t id, std::uint64_t size, unsigned links, bool dir=false, bool sparse=false) {
    AppleInodeRecord inode;inode.object_id=id;inode.parent_id=2;inode.private_id=id;
    inode.mode=dir?0040755:0100644;inode.children_or_links=links;
    if(!dir) { inode.uncompressed_size=size;AppleExtendedField stream{8,0,Bytes(40)};
        Put(stream.data,0,size);Put(stream.data,8,sparse?size-4096:size);inode.extended_fields.push_back(stream);
        if(sparse){inode.internal_flags=0x200;AppleExtendedField holes{13,0,Bytes(8)};Put(holes.data,0,4096);inode.extended_fields.push_back(holes);}}
    return Enc(inode,EncodeAppleInodeRecord);
}
struct CatalogFixture : Fixture {
    std::vector<Record> fs;
    bool insensitive=false, sparse=false, swapped=false;
    std::vector<tf::OmapRecordSpec> mappings;
    explicit CatalogFixture(bool multilevel=false,bool fold=false,bool hole=false,bool swap=false)
        : insensitive(fold),sparse(hole),swapped(swap) {
        EditNx([&](auto& b){Put(b,0xB8,101);Put(b,0xC0,102);});
        Place(0,15,tf::BuildOmap(18,20,bs,15,kObjectPhysical|kObjectTypeOmap,kObjectPhysical|kObjectTypeBtree));
        auto cm=tf::BuildBtreeNode({{101,swapped?16:TierBlock()+4,0,20},{102,swapped?TierBlock()+4:16,0,20}},20,bs,0,18,kObjectPhysical|kObjectTypeBtree,kObjectTypeOmap);Place(0,18,cm);
        tf::BuilderVolume v;v.oid=101;v.uuid_hex=std::string(32,'c');v.vol_omap_oid_override=TierBlock()+5;v.root_oid_override=1000;v.incompat=fold?1:0;v.name="Fusion Data";
        Place(swapped?0:1,swapped?16:4,tf::BuildApsb(v,20,bs));
        v.oid=102;v.uuid_hex=std::string(32,'d');v.vol_omap_oid_override=12;v.root_oid_override=2000;v.name="Second";v.incompat=0;
        Place(swapped?1:0,swapped?4:16,tf::BuildApsb(v,20,bs));
        Place(1,5,tf::BuildOmap(TierBlock()+6,20,bs,TierBlock()+5,kObjectPhysical|kObjectTypeOmap,kObjectPhysical|kObjectTypeBtree));
        Place(0,12,tf::BuildOmap(13,20,bs,12,kObjectPhysical|kObjectTypeOmap,kObjectPhysical|kObjectTypeBtree));
        Place(0,13,tf::BuildBtreeNode({{2000,TierBlock()+7,0,20}},20,bs,0,13,kObjectPhysical|kObjectTypeBtree,kObjectTypeOmap));
        auto root=FileInode(2,0,0,true);Place(1,7,tf::BuildRawLeafNode({root.key},{root.value},20,bs,0,2000,kObjectTypeBtree,kObjectTypeFsTree));
        AppleDirectoryRecord d;d.parent_id=2;d.file_id=30;d.name_utf8="Caf\xc3\xa9.txt";d.flags=8;
        const auto encodeDir = [&](const auto& v, auto& r, auto& error) { return EncodeAppleDirectoryRecord(v, ApfsNamePolicy::FromIncompatibleFeatures(fold?1:0), r, error); };
        fs={FileInode(2,0,multilevel?31:1,true),FileInode(30,(sparse?5:4)*4096,1,false,sparse),Enc(d,encodeDir)};
        for(unsigned n=0;n<4;++n) fs.push_back(Enc(AppleFileExtentRecord{30,n*4096ULL,4096,(n%2?TierBlock():0)+20+n/2,0,4096},EncodeAppleFileExtentRecord));
        if(sparse)fs.push_back(Enc(AppleFileExtentRecord{30,4*4096,4096,0,0,4096},EncodeAppleFileExtentRecord));
        fs.push_back(Enc(AppleXattrRecord{30,"com.apple.FinderInfo",kAppleXattrDataEmbedded,Bytes(32,std::byte{0x42})},EncodeAppleXattrRecord));
        Bytes desc(48);Put(desc,0,40);Put(desc,8,8192);Put(desc,16,8192);
        fs.push_back(Enc(AppleXattrRecord{30,"com.apple.ResourceFork",kAppleXattrDataStream,desc},EncodeAppleXattrRecord));
        fs.push_back(Enc(AppleDataStreamIdRecord{40,1},EncodeAppleDataStreamIdRecord));
        fs.push_back(Enc(AppleFileExtentRecord{40,0,4096,22,0,4096},EncodeAppleFileExtentRecord));
        fs.push_back(Enc(AppleFileExtentRecord{40,4096,4096,TierBlock()+22,0,4096},EncodeAppleFileExtentRecord));
        Place(0,22,Bytes(bs,std::byte{'X'}));Place(1,22,Bytes(bs,std::byte{'Y'}));
        if(multilevel)for(unsigned n=0;n<30;++n){fs.push_back(FileInode(100+n,0,1));d.file_id=100+n;d.name_utf8="child-"+std::to_string(n);fs.push_back(Enc(d,encodeDir));}
        Trees(multilevel);
    }
    void Trees(bool multi=false,bool sort=true) {
        std::string error;auto order=insensitive?AppleBtreeKeyOrder::FileSystemHashedDirectory:AppleBtreeKeyOrder::FileSystemCaseSensitive;
        if(sort && !SortAppleBtreeRecords(fs,order,error))throw std::runtime_error(error);
        mappings={{1000,30,0,20}};
        if(multi){AppleBtreeOptions options;options.block_size=bs;options.xid=20;options.root_object_id=1000;options.root_physical_block=30;
            options.first_child_object_id=3000;options.first_child_physical_block=31;options.subtype=14;options.key_order=order;
            AppleSerializedBtree tree;if(!SerializeAppleBtree(fs,options,tree,error)||!tree.height)throw std::runtime_error("multilevel fixture "+error);
            unsigned n=0;for(auto& object:tree.objects){if(object.location.object_id==1000){Place(0,30,object.bytes);continue;}
                const auto tier=n%2;const auto block=(tier?10:31)+n/2;Place(tier,block,object.bytes);
                mappings.push_back({object.location.object_id,(tier?TierBlock():0)+block,0,20});++n;}
        }else{std::vector<Bytes> keys,values;for(auto& r:fs){keys.push_back(r.key);values.push_back(r.value);}Place(0,30,tf::BuildRawLeafNode(keys,values,20,bs,0,1000,kObjectTypeBtree,14));}
        Maps();
    }
    void Maps(){std::sort(mappings.begin(),mappings.end(),[](auto a,auto b){return a.oid<b.oid;});Place(1,6,tf::BuildBtreeNode(mappings,20,bs,0,TierBlock()+6,kObjectPhysical|kObjectTypeBtree,kObjectTypeOmap));}
    FusionVolumeSelection Selection(){return {request.container_uuid_hex,std::string(32,'c'),{request.members[0].stable_store_id,request.members[1].stable_store_id},101,20};}
};
}

int wmain(int argc,wchar_t** argv) {try {
    if(argc!=3)return 2;std::filesystem::path root(argv[1]);std::filesystem::create_directories(root);
    const std::wstring kind(argv[2]);CatalogFixture f(kind==L"multilevel",false,true);
    if(kind==L"unknown-feature")f.EditNx([](auto& b){Put(b,0x40,0x80000102);});
    else if(kind==L"encrypted")f.Edit(1,4,[](auto& b){Put(b,0x108,0);});
    else if(kind==L"unknown-volume-feature")f.Edit(1,4,[](auto& b){Put(b,0x28,1ULL<<63);});
    else if(kind==L"dirty-cache")f.Edit(0,9,[](auto& b){Put(b,0x40,1);});
    else if(kind==L"nonempty-middle")f.Place(0,17,MiddleTree(f.bs,17,true));
    else if(kind==L"bad-range"){for(auto& r:f.fs)if(ReadU64LE(r.key,0).value()==((8ull<<60)|30)){Put(r.value,8,80);break;}f.Trees();}
    else if(kind==L"large-sparse"){
        for(auto& r:f.fs){auto key=ReadU64LE(r.key,0).value();if(key==((3ull<<60)|30)){
            AppleInodeRecord inode;std::string e;if(!ApfsExtendedRecordCodec::DecodeInode(r,inode,e))throw std::runtime_error(e);
            for(auto& field:inode.extended_fields){if(field.type==8){Put(field.data,0,16*1024*1024);Put(field.data,8,4*4096);}if(field.type==13)Put(field.data,0,16*1024*1024-4*4096);}
            r=Enc(inode,EncodeAppleInodeRecord);
        }if(key==((8ull<<60)|30)&&ReadU64LE(r.key,8).value()==4*4096)Put(r.value,0,16*1024*1024-4*4096);}f.Trees();
    } else if(kind!=L"good" && kind!=L"multilevel")return 2;
    for(unsigned n=0;n<2;++n){std::ofstream out(root/(n?"tier2.img":"main.img"),std::ios::binary|std::ios::trunc);
        out.write(reinterpret_cast<const char*>(f.sources[n]->bytes.data()),static_cast<std::streamsize>(f.sources[n]->bytes.size()));out.close();if(!out)return 3;}
    return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 3;}}
