#include "ApfsEncryptedSnapshotReadContext.h"
#include "ApfsReadOnlyMetadataAdmission.h"
#define APFS_RETAINED_NAMESPACE_FIXTURES_ONLY
#include "ApfsRetainedNamespaceTests.cpp"
#undef APFS_RETAINED_NAMESPACE_FIXTURES_ONLY

namespace
{
void Edit(Source& source, std::uint64_t block, const std::function<void(std::vector<std::byte>&)>& edit)
{
    std::vector<std::byte> bytes(source.image.begin()+block*4096,source.image.begin()+(block+1)*4096);
    edit(bytes);(void)FletcherForBlock(bytes,4096);
    std::copy(bytes.begin(),bytes.end(),source.image.begin()+block*4096);
}
void Put(Source& source, std::uint64_t block, std::vector<std::byte> bytes)
{
    (void)FletcherForBlock(bytes,4096);std::copy(bytes.begin(),bytes.end(),source.image.begin()+block*4096);
}
void AddSnapshot(Source& source, unsigned fault=0)
{
    const auto old_map=ReadU64LE(source.image,4*4096+0x80).value();
    const auto inventory_oid=ReadU64LE(source.image,4*4096+0x98).value();
    const auto extent=ReadU64LE(source.image,4*4096+0x90).value();
    // A COW'd descriptor/OMAP at XID8 still selects the immutable FS at XID7.
    std::vector<std::byte> apsb(source.image.begin()+4*4096,source.image.begin()+5*4096);
    PutU64LE(apsb,8,70);PutU64LE(apsb,16,fault==5?6:8);PutU32LE(apsb,24,kObjectPhysical|kObjectTypeFs);PutU64LE(apsb,0x80,92);
    if(fault==4)apsb[0xF0]^=std::byte{1};
    if(fault==7)PutU32LE(apsb,0x74,kObjectPhysical|kObjectTypeBtree);
    if(fault>=8&&fault<=13)apsb[std::array<std::size_t,6>{0x60,0x62,0x64,0x68,0x70,0x72}[fault-8]]^=std::byte{1};
    Put(source,70,std::move(apsb));
    Edit(source,90,[](auto& bytes){PutU64LE(bytes,0xD8,1);});
    Put(source,93,BuildBtreeNode({OmapRecordSpec{8293,80,fault==2?0u:4u,7},OmapRecordSpec{8293,81,4,8},
        OmapRecordSpec{inventory_oid,72,0,8}},8,4096,0,93,kObjectPhysical|kObjectTypeBtree,kObjectTypeOmap));
    std::vector<std::byte> key(8),value(16);PutU64LE(key,0,7);
    Put(source,71,BuildRawLeafNode({key},{value},8,4096,0,71,kObjectPhysical|kObjectTypeBtree,0x13));
    Edit(source,92,[&](auto& bytes){PutU32LE(bytes,0x24,fault==6?2:1);PutU32LE(bytes,0x2C,kObjectPhysical|kObjectTypeBtree);PutU64LE(bytes,0x38,71);PutU64LE(bytes,0x40,7);});
    const std::string name="retained-owner";
    std::vector<std::byte> metadata_key(8),metadata(51+name.size()),name_key(11+name.size()),name_value(8);
    PutU64LE(metadata_key,0,(1ULL<<60)|7);PutU64LE(metadata,0,extent);PutU64LE(metadata,8,70);
    PutU32LE(metadata,40,kObjectPhysical|kObjectTypeBtree);PutU16LE(metadata,48,static_cast<std::uint16_t>(name.size()+1));PutBytes(metadata,50,name.data(),name.size());
    PutU64LE(name_key,0,0xBFFFFFFFFFFFFFFFULL);PutU16LE(name_key,8,static_cast<std::uint16_t>(name.size()+1));PutBytes(name_key,10,name.data(),name.size());PutU64LE(name_value,0,fault==3?6:7);
    Put(source,72,BuildRawLeafNode({metadata_key,name_key},{metadata,name_value},8,4096,0,inventory_oid,kObjectTypeBtree,kObjectTypeSnapMetaTree));
    Edit(source,2,[](auto& bytes){PutU32LE(bytes,0x20,1);});
    if(fault==1)source.image[80*4096+100]^=std::byte{1};
    (void)old_map;
}
void Clear(AppleSnapshotCatalogRecords& catalog)
{
    const auto clear=[](auto& tree){for(auto* records:{&tree.filesystem,&tree.extentref})for(auto& record:*records)
        for(auto* bytes:{&record.key,&record.value})for(auto& byte:*bytes){volatile auto* p=&byte;*p=std::byte{0};}};
    clear(catalog.live);for(auto& tree:catalog.snapshots)clear(tree);catalog={};
}
void AddCheckpoint(Source& source)
{
    const auto block=[&](std::uint64_t b){return std::vector<std::byte>(source.image.begin()+b*4096,source.image.begin()+(b+1)*4096);};
    const auto descriptor=ReadU64LE(source.image,0x70).value();const auto data=ReadU64LE(source.image,0x78).value();
    auto apsb=block(90);PutU64LE(apsb,16,9);PutU64LE(apsb,0x80,111);Put(source,110,std::move(apsb));
    auto omap=block(92);PutU64LE(omap,8,111);PutU64LE(omap,16,9);PutU64LE(omap,48,112);Put(source,111,std::move(omap));
    auto tree=block(93);PutU64LE(tree,8,112);PutU64LE(tree,16,9);Put(source,112,std::move(tree));
    Put(source,113,BuildOmap(114,9,4096,113,kObjectPhysical|kObjectTypeOmap,kObjectPhysical|kObjectTypeBtree,1));
    Put(source,114,BuildBtreeNode({OmapRecordSpec{101,110,0,9}},9,4096,0,114,kObjectPhysical|kObjectTypeBtree,kObjectTypeOmap));
    auto map=block(descriptor+2);PutU64LE(map,8,descriptor+4);PutU64LE(map,16,9);
    for(unsigned i=0;i<3;++i){const auto destination=data+(6+i)%8;auto object=block(data+3+i);PutU64LE(object,16,9);Put(source,destination,std::move(object));PutU64LE(map,0x48+i*0x28,destination);}
    Put(source,descriptor+4,std::move(map));
    auto nx=block(descriptor+3);PutU64LE(nx,16,9);PutU64LE(nx,0x60,10);PutU64LE(nx,0xA0,113);
    PutU32LE(nx,0x80,6);PutU32LE(nx,0x88,4);PutU32LE(nx,0x84,1);PutU32LE(nx,0x90,6);
    Put(source,descriptor+5,nx);Put(source,0,std::move(nx));
    // The overwritten data-ring slot retires the old XID7 descriptor pair.
    Put(source,descriptor,std::vector<std::byte>(4096));Put(source,descriptor+1,std::vector<std::byte>(4096));
}
void RunRetainedSnapshot()
{
    {
        auto source=std::make_shared<Source>();AddSnapshot(*source);AddCheckpoint(*source);auto session=Open(source,9);std::string error;
        Check(!session->CreateRetainedVerificationContext(8,error),"strict historical context refuses snapshot-bearing parent cold");
        auto context=session->CreateRetainedSnapshotVerificationContext(8,error);Check(context!=nullptr,error.c_str());
        AppleCheckpointView parent;
        AppleSnapshotCatalogRecords catalog;std::vector<AppleSnapshotMetadataClaim> owners;
        Check(LoadAppleEncryptedSnapshotCatalog(*source,*context,parent,catalog,owners,error),error.c_str());
        Check(parent.container.superblock.xid==8&&parent.volumes.size()==1&&parent.volumes[0].superblock.xid==8&&
            parent.spaceman.object.object_id==0,"canonical historical parent XID8 with allocator deliberately unloaded");
        Check(catalog.inventory.size()==1&&catalog.inventory[0].xid==7&&catalog.inventory[0].volume.superblock.xid==8,"retained parent owns exact older snapshot");
        EncryptedNamespaceInfo info;Check(session->ValidateSnapshotParentNamespace(*context,info,error)==EncryptedReadError::None&&info.inode_count==2,"exact historical parent namespace");
        Check(session->ValidateSnapshotNamespace(*context,7,info,error)==EncryptedReadError::None&&info.inode_count==2,"retained-parent snapshot namespace");
        Check(!session->CreateRetainedVerificationContext(8,error),"strict historical context refuses snapshot-bearing parent warm");
        Clear(catalog);Check(LoadAppleEncryptedSnapshotCatalog(*source,*context,parent,catalog,owners,error)&&parent.container.superblock.xid==8,"strict/read cache separation preserves retained authority");
        info.inode_count=999;Check(session->ValidateSnapshotNamespace(*context,6,info,error)==EncryptedReadError::InvalidArgument&&
            info.inode_count==0,"absent snapshot cannot publish historical counts");
        Check(session->GetNamespaceInfo(info)==EncryptedReadError::None&&info.inode_count==2,"retained snapshot preserves latest namespace");
        Clear(catalog);++cases;
    }
    for(unsigned fault=0;fault<6;++fault)
    {
        auto source=std::make_shared<Source>();AddSnapshot(*source);AddCheckpoint(*source);auto session=Open(source,9);std::string error;
        auto context=session->CreateRetainedSnapshotVerificationContext(8,error);Check(context!=nullptr,error.c_str());
        auto foreign=std::make_shared<Source>();AddSnapshot(*foreign);AddCheckpoint(*foreign);
        if(fault==0){auto other=Open(source,9);EncryptedNamespaceInfo info;info.inode_count=999;
            Check(other->ValidateSnapshotParentNamespace(*context,info,error)==EncryptedReadError::SourceIdentityMismatch&&info.inode_count==0,"foreign session cannot use retained snapshot parent");++cases;continue;}
        if(fault==1)session->Close();if(fault==2)++source->revision;
        if(fault==3)source->on_read=[&](auto at){if(at==80*4096)session->Cancel();};
        if(fault==4)source->budget->LimitRemainingTo(1,4096,100,4096);
        AppleCheckpointView parent;parent.container.superblock.xid=999;
        AppleSnapshotCatalogRecords catalog;catalog.inventory.emplace_back();std::vector<AppleSnapshotMetadataClaim> owners(1);
        Check(!LoadAppleEncryptedSnapshotCatalog(fault==5?*foreign:*source,*context,parent,catalog,owners,error)&&
            parent.container.superblock.xid==0&&parent.volumes.empty()&&catalog.inventory.empty()&&catalog.snapshots.empty()&&
            catalog.live.filesystem.empty()&&owners.empty(),"retained parent/catalog/owners failure publishes no partial evidence");++cases;
    }
    for(unsigned fault=0;fault<6;++fault)
    {
        auto source=std::make_shared<Source>();AddSnapshot(*source);AddCheckpoint(*source);auto session=Open(source,9);std::string error;
        if(fault==0)session->Close();if(fault==1)++source->revision;
        if(fault==2)source->budget->LimitRemainingTo(1,4096,100,4096);
        if(fault==3)source->image[80*4096+100]^=std::byte{1};
        const auto xid=fault==4?9ULL:fault==5?6ULL:8ULL;
        Check(!session->CreateRetainedSnapshotVerificationContext(xid,error)&&!error.empty(),"retained mint rejects revoked/budget/corrupt/non-retained parent before publishing authority");++cases;
    }
}
void RunSnapshots()
{
    {
        struct Untrusted final:BtreeNodeReadContext{unsigned reads=0;bool ReadNode(std::uint64_t,std::uint64_t,bool,std::span<const std::byte>&,std::string&)override{++reads;return false;}void ReleaseNode()noexcept override{}} context;
        auto source=std::make_shared<Source>();BtreeReadPolicy policy;policy.enforce_object_identity=true;policy.require_complete_traversal=true;policy.reject_unsupported_flags=true;
        policy.root_object_id=8293;policy.subtype=kObjectTypeFsTree;policy.virtual_child_resolver=[](auto,std::string&)->std::optional<BtreeVirtualChildMapping>{return BtreeVirtualChildMapping{80,7,4,4096};};
        BtreeRoutingPolicy routing{[](const auto&,const auto&,std::string&)->std::optional<int>{return 0;}};
        std::vector<BtreeRecord> records;std::vector<BtreeNodeIdentity> identities;std::string error;
        Check(!ReadBtreeLeafRecords(*source,4096,80,false,5,7,policy,routing,records,error,&context,&identities,7)&&context.reads==0&&identities.empty()&&
            error=="CatalogBtreeIdentityCaptureRequiresStrictSelection","public caller provider cannot mint protected owner evidence");++cases;
    }
    for(unsigned fault=0;fault<8;++fault)
    {
        auto source=std::make_shared<Source>();AddSnapshot(*source,fault);auto session=Open(source);std::string error;EncryptedReadError code;
        auto parent=session->CreateMetadataReadContext(code);auto context=session->CreateSnapshotVerificationContext(*parent,error);Check(context!=nullptr,error.c_str());
        AppleSnapshotCatalogRecords catalog;std::vector<AppleSnapshotMetadataClaim> owners;
        const auto okay=LoadAppleEncryptedSnapshotCatalog(*source,*context,catalog,owners,error);
        Check(okay==(fault==0),("typed snapshot parser result "+std::to_string(fault)+":"+error).c_str());
        if(okay)
        {
            Check(catalog.inventory.size()==1&&catalog.snapshots.size()==1&&catalog.inventory[0].xid==7,"exact inventory selected");
            Check(catalog.inventory[0].volume.superblock.xid==8&&catalog.inventory[0].volume.object_map.object.xid==8,"separate COW descriptor/map generation");
            Check(catalog.inventory[0].volume.root_tree.xid==7&&catalog.inventory[0].volume.root_tree.physical_block==80,"snapshot selects older encrypted root");
            Check(std::any_of(owners.begin(),owners.end(),[](const auto& owner){return owner.view_xid==7&&owner.selection_xid==7&&owner.object_xid==7&&owner.physical_block==80&&owner.mapping_xid==7;}),"canonical snapshot node owner");
            Clear(catalog);Check(LoadAppleEncryptedSnapshotCatalog(*source,*context,catalog,owners,error),"warm canonical snapshot context");
            EncryptedNamespaceInfo info;Check(session->ValidateSnapshotNamespace(*context,7,info,error)==EncryptedReadError::None&&info.inode_count==2&&info.entry_count==2,"canonical snapshot namespace");
            auto cp=LoadAppleCheckpointView(*source,0,source->SizeBytes(),error,*parent,8,false);Check(cp.has_value(),"parent canonical metadata");
            for(unsigned repeat=0;repeat<2;++repeat){AppleSnapshotCatalogRecords refused;std::vector<AppleSnapshotMetadataClaim> ignored;
                Check(!LoadAppleSnapshotCatalog(*source,*cp,101,refused,ignored,error)&&refused.inventory.empty(),"strict mutation catalog remains refused");
                Check(!LoadAppleReadOnlySnapshotCatalog(*source,*cp,101,refused,ignored,error)&&refused.inventory.empty(),"ordinary read parser has no crypto authority");
                Clear(catalog);Check(LoadAppleEncryptedSnapshotCatalog(*source,*context,catalog,owners,error),"strict/read interleaving preserves cache separation");}
        }
        else Check(catalog.inventory.empty()&&catalog.live.filesystem.empty()&&catalog.snapshots.empty()&&owners.empty(),"failure has no partial plaintext or owners");
        Clear(catalog);++cases;
    }
    for(unsigned fault=1;fault<=6;++fault)
    {
        auto source=std::make_shared<Source>(fault);AddSnapshot(*source);auto session=Open(source);std::string error;EncryptedReadError code;
        auto parent=session->CreateMetadataReadContext(code);auto context=session->CreateSnapshotVerificationContext(*parent,error);
        EncryptedNamespaceInfo info;info.inode_count=999;const auto status=session->ValidateSnapshotNamespace(*context,7,info,error);
        Check(status!=EncryptedReadError::None&&info.inode_count==0&&info.entry_count==0,"bad snapshot namespace cannot publish current counts");
        Check(session->GetNamespaceInfo(info)==EncryptedReadError::None&&info.inode_count==2,"bad snapshot preserves current namespace");++cases;
    }
    for(unsigned fault=0;fault<5;++fault)
    {
        auto source=std::make_shared<Source>();AddSnapshot(*source);auto session=Open(source);std::string error;EncryptedReadError code;
        auto parent=session->CreateMetadataReadContext(code);auto context=session->CreateSnapshotVerificationContext(*parent,error);
        if(fault==0){auto other=Open(source);Check(!other->CreateSnapshotVerificationContext(*parent,error),"foreign parent cannot mint snapshot authority");++cases;continue;}
        if(fault==1)session->Close();if(fault==2)++source->revision;
        if(fault==3)source->on_read=[&](auto at){if(at==80*4096)session->Cancel();};
        if(fault==4)source->budget->LimitRemainingTo(1,4096,100,4096);
        AppleSnapshotCatalogRecords catalog;std::vector<AppleSnapshotMetadataClaim> owners;
        Check(!LoadAppleEncryptedSnapshotCatalog(*source,*context,catalog,owners,error)&&catalog.inventory.empty()&&catalog.snapshots.empty()&&owners.empty(),"revocation/cancellation/budget is atomic");++cases;
    }
}
void RunCryptoStates()
{
    for(unsigned fault=8;fault<=13;++fault)
    {
        auto source=std::make_shared<Source>();AddSnapshot(*source,fault);auto session=Open(source);
        std::string error;EncryptedReadError code;
        auto parent=session->CreateMetadataReadContext(code);
        auto context=session->CreateSnapshotVerificationContext(*parent,error);Check(context!=nullptr,error.c_str());
        AppleSnapshotCatalogRecords catalog;std::vector<AppleSnapshotMetadataClaim> owners;
        Check(!LoadAppleEncryptedSnapshotCatalog(*source,*context,catalog,owners,error)&&
            error=="SnapshotMetadataCryptoStateChanged"&&catalog.inventory.empty()&&catalog.live.filesystem.empty()&&owners.empty(),
            ("checksummed snapshot metadata crypto change must refuse: "+std::to_string(fault)+":"+error).c_str());
        EncryptedNamespaceInfo info;
        Check(session->GetNamespaceInfo(info)==EncryptedReadError::None&&info.inode_count==2,"changed snapshot crypto preserves parent namespace");
        Clear(catalog);++cases;
    }
}
}
#ifndef APFS_ENCRYPTED_SNAPSHOT_OWNERSHIP_FIXTURES_ONLY
int main(int argc,char** argv)try{
    const bool current_only=argc==2&&std::string(argv[1])=="--current-only";
    const bool crypto_only=argc==2&&std::string(argv[1])=="--crypto-only";
    Check(argc==1||current_only||crypto_only,"known focused test selector required");
    if(!crypto_only){RunSnapshots();std::cout<<"CURRENT PASS "<<cases<<" cases / "<<checks<<" checks\n";}
    if(!current_only)RunCryptoStates();
    if(argc==1)RunRetainedSnapshot();
    std::cout<<"PASS "<<cases<<" cases / "<<checks<<" checks; typed encrypted snapshot owner and namespace\n";return 0;}
catch(const std::exception& error){std::cerr<<"FAIL "<<error.what()<<" after "<<checks<<" checks\n";return 1;}
#endif
