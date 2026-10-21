#include "ApfsExtendedRecordCodec.h"
#include "AppleReadOnlyRecordGraph.h"
#define APFS_READONLY_RETENTION_FIXTURES_ONLY
#include "ApfsReadOnlyRetentionIntegrationTests.cpp"

namespace {
void NativeEnvelope(Record& record, bool native_flags)
{
    if((ReadU64LE(record.key,0).value_or(0)>>60)!=3 || record.value.size()<96) return;
    const auto count=ReadU16LE(record.value,92).value_or(0);
    const auto used=ReadU16LE(record.value,94).value_or(0);
    Check(used>=4*count,"fixture starts with canonical existing writer envelope");
    PutU16LE(record.value,94,static_cast<std::uint16_t>(used-4*count));
    if(native_flags) for(unsigned i=0;i<count;++i){
        const auto type=std::to_integer<unsigned>(record.value[96+4*i]);
        if(type==4) record.value[97+4*i]=std::byte{2};
        if(type==8) record.value[97+4*i]=std::byte{32};
    }
}

void ConvertFixture(Fixture& f)
{
    std::map<std::uint64_t,std::pair<AppleObjectLocation,std::vector<Record>>> trees;
    VectorRandomAccessSource source(f.image);std::string error;
    for(const auto& generation:f.generations){
        AppleSnapshotCatalogRecords catalog;
        Check(LoadAppleReadOnlySnapshotCatalog(source,generation,101,catalog,error),error);
        const auto save=[&](const auto& view,const auto& records){
            Check(records.filesystem_blocks.size()==1,"bounded synthetic single-leaf conversion");
            trees.emplace(view.root_tree.physical_block,std::pair{view.root_tree,records.filesystem});
        };
        save(generation.volumes[0],catalog.live);
        for(std::size_t i=0;i<catalog.inventory.size();++i)save(catalog.inventory[i].volume,catalog.snapshots[i]);
    }
    for(auto& [block,tree]:trees){
        std::vector<Bytes> keys,values;
        for(auto& record:tree.second){NativeEnvelope(record,true);keys.push_back(record.key);values.push_back(record.value);}
        const auto& object=tree.first;
        f.Put(block,BuildRawLeafNode(keys,values,object.xid,f.bs,0,object.object_id,object.type,object.subtype));
    }
    f.Reload();f.scope.account_retained_ownership=true;
}

void CodecCases()
{
    for(unsigned length=1;length<=25;++length){
        AppleInodeRecord inode;inode.object_id=inode.private_id=30;inode.parent_id=2;inode.children_or_links=1;inode.mode=0100644;
        AppleExtendedField name{4,2,Bytes(length+1,std::byte{'a'})};name.data.back()=std::byte{};
        inode.extended_fields={name,AppleExtendedField{8,32,Bytes(40)}};
        auto raw=Encode(inode,EncodeAppleInodeRecord);std::string error;AppleInodeRecord decoded;
        Check(ApfsExtendedRecordCodec::DecodeInode(raw,decoded,error),"strict existing writer round trip");
        NativeEnvelope(raw,false);
        Check(ApfsExtendedRecordCodec::DecodeInode(raw,decoded,error) && decoded.extended_fields.size()==2 &&
            decoded.extended_fields[0].data==name.data,"canonical native header form decodes without granting mutation admission");
        Check(ApfsExtendedRecordCodec::DecodeInodeReadOnly(raw,decoded,error) && decoded.extended_fields.size()==2 &&
            decoded.extended_fields[0].data==name.data && decoded.extended_fields[0].flags==2,"native values-only semantic decode");
        for(unsigned kind=0;kind<5;++kind){
            auto damaged=raw;
            if(kind==0)PutU16LE(damaged.value,94,ReadU16LE(damaged.value,94).value()+1);
            if(kind==1)PutU16LE(damaged.value,92,1025);
            if(kind==2)damaged.value.pop_back();
            if(kind==3)damaged.value[100]=damaged.value[96];
            if(kind==4){
                if((length+1)%8==0)continue;
                damaged.value[104+length+1]=std::byte{1};
            }
            Check(!ApfsExtendedRecordCodec::DecodeInodeReadOnly(damaged,decoded,error) && !decoded.object_id &&
                decoded.extended_fields.empty() && !error.empty(),"malformed native record has no partial decode");
        }
    }
    Pass("native xfield lengths, padding, count, truncation and duplicate descriptors");
}

void ImageCases()
{
    for(const auto bs:{4096u,8192u})for(unsigned profile=0;profile<3;++profile){
        Fixture f(bs);if(profile)f.Create("native",{20});if(profile==2)f.Cow(true,{20});ConvertFixture(f);
        const auto before=f.image;VectorRandomAccessSource source(f.image);std::string error;
        auto read_only=ApfsVerifier::VerifyReadOnly(source,f.scope);Accounted(read_only);
        auto strict=ApfsVerifier::Verify(source,f.scope);
        Check(strict.outcome!=VerificationOutcome::Complete && !strict.retained_ownership,"strict verifier does not accept observational xfields");
        std::optional<ApfsSnapshotSpaceAttribution> result;
        Check(TryAttributeAppleSnapshotSpaceReadOnly(source,f.scope,result,error)&&result&&result->complete,"actual native-envelope image attribution: "+error);
        Check(!TryAttributeAppleSnapshotSpace(source,f.scope,result,error)&&!result,"strict attribution refuses native-only envelope");
        auto budget=std::make_shared<ApfsReadBudget>(200000,512ull<<20,4000000,512ull<<20);
        BudgetedRandomAccessSource bounded(source,budget);SnapshotPlanningSource operation(bounded);
        std::vector<std::uint64_t> metadata;std::vector<ApplePhysicalExtentRecord> payload;
        for(unsigned order=0;order<3;++order){
            Check(!LoadAppleSnapshotCheckpointOwners(operation,f.checkpoint,metadata,payload,error)&&metadata.empty()&&payload.empty(),"strict cold/warm owner refusal");
            Check(LoadAppleReadOnlySnapshotCheckpointOwners(operation,f.checkpoint,metadata,payload,error),"read-only cache completeness: "+error);
            AppleSnapshotCreateRequest request;request.volume_object_id=101;request.name_utf8="refuse";request.creation_time_ns=f.checkpoint.container.superblock.next_xid;request.required_checkpoint_xids=Pins(f);
            AppleSnapshotCreatePlan plan;
            Check(!PlanAppleSnapshotCreate(operation,f.checkpoint,request,plan,error)&&plan.commit.publication.superblock_write.bytes.empty(),"actual mutation remains refused after observational warm cache");
        }
        Check(operation.VerifyUnchanged(error)&&f.image==before&&!budget->Failed(),"native-envelope image/cache controls preserve source");
        Pass("native-envelope image profile="+std::to_string(profile)+" block="+std::to_string(bs));
    }
}

Bytes NameBytes(const std::string& name)
{
    Bytes bytes;for(const auto ch:name)bytes.push_back(static_cast<std::byte>(ch));bytes.push_back(std::byte{});return bytes;
}

void NamespaceCases()
{
    Fixture f;VectorRandomAccessSource source(f.image);std::string error;std::vector<Record> records;
    Check(ReadAppleVolumeFileSystemRecords(source,f.checkpoint.container,f.checkpoint.volumes[0],records,error),error);
    for(auto& record:records)if(ReadU64LE(record.key,0).value_or(0)==((3ull<<60)|2)){
        AppleInodeRecord root;Check(ApfsExtendedRecordCodec::DecodeInode(record,root,error),error);
        root.parent_id=1;root.extended_fields.push_back({4,2,NameBytes("root")});record=Encode(root,EncodeAppleInodeRecord);
    }
    AppleInodeRecord reserved;reserved.object_id=reserved.private_id=3;reserved.parent_id=1;reserved.mode=0040755;
    reserved.extended_fields.push_back({4,2,NameBytes("private-dir")});records.push_back(Encode(reserved,EncodeAppleInodeRecord));
    for(const auto id:{2ull,3ull}){
        AppleDirectoryRecord entry;entry.parent_id=1;entry.file_id=id;entry.flags=4;entry.name_utf8=id==2?"root":"private-dir";
        entry.hashed_name=ApfsNamePolicy::FromIncompatibleFeatures(f.checkpoint.volumes[0].superblock.incompatible_features).UsesHashedDirectoryKeys();
        Record raw;Check(EncodeAppleDirectoryRecord(entry,raw,error),error);records.push_back(std::move(raw));
    }
    for(unsigned kind=0;kind<9;++kind){
        auto current=records;
        if(kind==1)for(auto& r:current)if(ReadU64LE(r.key,0).value_or(0)==((3ull<<60)|3)){
            AppleInodeRecord inode;Check(ApfsExtendedRecordCodec::DecodeInode(r,inode,error),error);inode.children_or_links=1;r=Encode(inode,EncodeAppleInodeRecord);
        }
        if(kind==2)current.push_back(current.back());
        if(kind==3)current.back().value[16]=std::byte{8};
        if(kind==4)for(auto& r:current)if(ReadU64LE(r.key,0).value_or(0)==((3ull<<60)|3)){
            AppleInodeRecord inode;Check(ApfsExtendedRecordCodec::DecodeInode(r,inode,error),error);inode.parent_id=2;r=Encode(inode,EncodeAppleInodeRecord);
        }
        if(kind==5)for(auto& r:current)if(ReadU64LE(r.key,0).value_or(0)==((3ull<<60)|2))r.value[97]=std::byte{0x22};
        if(kind==6)current.erase(current.end()-1);
        if(kind>=7)for(auto& r:current)if(ReadU64LE(r.key,0).value_or(0)==((3ull<<60)|3)){
            AppleInodeRecord inode;Check(ApfsExtendedRecordCodec::DecodeInode(r,inode,error),error);
            if(kind==7)inode.extended_fields.push_back({8,32,Bytes(40)});
            if(kind==8)inode.extended_fields[0].data=NameBytes("wrong-private-name");
            r=Encode(inode,EncodeAppleInodeRecord);
        }
        auto budget=std::make_shared<ApfsReadBudget>(65536,256ull<<20,1000000,256ull<<20);NativeApfsVolumeProjection projection;
        const bool observed=NativeApfsReader::TryProjectObservationalFileSystemRecords(current,f.checkpoint.container.superblock,
            f.checkpoint.volumes[0].superblock,budget,projection,error);
        if(kind==0){
            Check(observed&&projection.inodes.size()==2&&projection.directory_links.size()==1,"canonical sentinel anchors and empty private metadata: "+error);
            Check(!NativeApfsReader::ValidateOrdinaryFileSystemRecords(current,f.checkpoint.container.superblock,
                f.checkpoint.volumes[0].superblock,budget,error),"old namespace entry remains strict");
        }else Check(!observed&&projection.inodes.empty()&&!error.empty(),"malformed anchors/private state/flag combinations refuse complete projection");
        Pass("observational namespace anchors "+std::to_string(kind));
    }
}

void ChargeBoundaryCases()
{
    Fixture f;ConvertFixture(f);
    f.Edit(f.checkpoint.volumes[0].superblock_object.physical_block,[](auto& bytes){PutU64LE(bytes,0x58,0);});f.Reload();
    VectorRandomAccessSource source(f.image);auto report=ApfsVerifier::VerifyReadOnly(source,f.scope);Accounted(report);
    Check(Coverage(report,VerificationCheck::CurrentOwnershipCensus).scope_detail.find("not derived or compared")!=std::string::npos,
        "physical completeness expressly excludes logical volume charge comparison");
    AllocateOrphan(f,300);VectorRandomAccessSource orphan(f.image);report=ApfsVerifier::VerifyReadOnly(orphan,f.scope);
    Check(report.outcome!=VerificationOutcome::Complete&&!report.retained_ownership&&!report.allocation_census&&Has(report,VerificationCode::OrphanAllocation),
        "unknown charge semantics cannot hide an actual allocated orphan");
    Pass("logical charge unknown remains distinct from exact physical/orphan proof");
}
}
int main(){try{CodecCases();ImageCases();NamespaceCases();ChargeBoundaryCases();std::cout<<"PASS "<<cases<<" cases, "<<checks<<" checks\n";return 0;}catch(const std::exception& e){std::cerr<<"FAIL "<<e.what()<<'\n';return 1;}}
