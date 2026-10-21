#include "AppleVolumeTransaction.h"
#include "SnapshotTestFixture.h"
#include "NativeApfsReader.h"
#include "ApfsExtendedRecordCodec.h"
#include "../src/SnapshotPlanningSource.h"
#include <algorithm>
#include <iostream>
#include <fstream>
#include <functional>
#include <set>
#include <stdexcept>

using namespace apfsaccess::catalog;
using namespace apfsaccess::rw;
using namespace apfsaccess::testfixture;
namespace {
unsigned cases = 0, checks = 0;
void Check(bool value, const std::string& text) { ++checks; if (!value) throw std::runtime_error(text); }
void Pass(const std::string& text) { ++cases; std::cout << "PASS " << text << '\n'; }
template<class T, class F> apfsaccess::catalog::BtreeRecord Encode(const T& value, F encode) {
    apfsaccess::catalog::BtreeRecord record; std::string error;
    Check(encode(value, record, error), "encode: " + error); return record;
}
struct FixtureOwners { std::set<std::uint64_t> metadata, payload; };
// This fixture has one-node trees. Walk their serialized edges with the shared
// record codecs, independently of the production retirement graph.
FixtureOwners ReadFixtureOwners(const RandomAccessSource& source,const AppleCheckpointView& checkpoint) {
    FixtureOwners owners;std::string error;
    std::vector<std::uint64_t> pending;
    std::set<std::uint64_t> descriptors;
    for(const auto& volume:checkpoint.volumes)pending.push_back(volume.superblock_object.physical_block);
    const auto block=[&](std::uint64_t address){Bytes bytes;
        Check(address>0&&address<source.SizeBytes()/4096&&source.Read(address*4096,4096,bytes),"bounded fixture object read");
        return bytes;
    };
    const auto tree=[&](std::uint64_t address){
        const auto bytes=block(address);
        Check(ReadU16LE(bytes,0x22).value()==0,"fixture ownership oracle requires a single leaf node");
        owners.metadata.insert(address);std::vector<apfsaccess::catalog::BtreeRecord> records;
        const bool read=ReadBtreeLeafRecords(source,4096,address,true,0,checkpoint.container.superblock.xid,records,error);
        Check(read,"read serialized fixture ownership edges: "+error);return records;
    };
    const auto extent=[&](std::uint64_t first,std::uint64_t count){
        Check(first>0&&first<source.SizeBytes()/4096&&count>0&&count<=source.SizeBytes()/4096-first,"bounded fixture payload");
        for(std::uint64_t i=0;i<count;++i)owners.payload.insert(first+i);
    };
    while(!pending.empty()){
        const auto address=pending.back();pending.pop_back();
        if(!descriptors.insert(address).second)continue;
        Check(descriptors.size()<=source.SizeBytes()/4096,"bounded fixture descriptor closure");
        const auto apsb=ParseApsb(block(address));Check(apsb.has_value(),"parse fixture APSB");
        owners.metadata.insert(address);owners.metadata.insert(apsb->omap_oid);
        const auto omap=block(apsb->omap_oid);
        for(const auto& mapping:tree(ReadU64LE(omap,0x30).value())){
            Check(mapping.key.size()==16&&mapping.value.size()==16&&ReadU32LE(mapping.value,0).value()==0,
                "fixture contains complete live OMAP versions");
            const auto mapped=ReadU64LE(mapping.value,8).value();const auto node=block(mapped);
            const auto subtype=ReadU32LE(node,0x1C).value();
            for(const auto& record:tree(mapped)){
                const auto kind=ReadU64LE(record.key,0).value()>>60;
                if(subtype==kObjectTypeFsTree&&kind==8){AppleFileExtentRecord file;
                    Check(DecodeAppleFileExtentRecord(record,4096,file,error)&&file.length_bytes%4096==0,"decode raw fixture file extent");
                    if(file.physical_block)extent(file.physical_block,file.length_bytes/4096);
                }else if(subtype==kObjectTypeSnapMetaTree&&kind==1){
                    Check(record.value.size()>=50,"bounded fixture snapshot descriptor reference");
                    pending.push_back(ReadU64LE(record.value,8).value());
                }
            }
        }
        if(apsb->extentref_tree_oid)for(const auto& record:tree(apsb->extentref_tree_oid)){
            ApplePhysicalExtentRecord ref;Check(DecodeApplePhysicalExtentRecord(record,ref,error),"decode raw fixture physical reference");
            extent(ref.physical_block,ref.block_count);
        }
        const auto inventory=ReadU64LE(omap,0x38).value();if(inventory)tree(inventory);
    }
    return owners;
}
struct Fixture : SnapshotFixture {
    AppleCheckpointView checkpoint;
    explicit Fixture(std::uint64_t internal_pool_blocks = 4, std::uint32_t checkpoint_ring_blocks = 8)
        : SnapshotFixture(4096,internal_pool_blocks,checkpoint_ring_blocks) {
        SetPayload(220);
        // The live view has removed the file after snapshot 10. Its physical
        // reference layer must record that decrement, retaining the old bytes.
        auto removed = Encode(ApplePhysicalExtentRecord{220,1,kApplePhysicalExtentKindUpdate,30,-1}, EncodeApplePhysicalExtentRecord);
        Put(8,BuildRawLeafNode({removed.key},{removed.value},20,bs,0,8,kObjectPhysical|kObjectTypeBtree,kObjectTypeBlockRefTree));
        Bytes payload(bs, std::byte{0x53}); Put(220, payload, false);
        Reload();
        Allocate({180, 181, 183, 184, 185, 220});
    }
    void Reload() {
        VectorRandomAccessSource source(image); std::string error;
        auto loaded = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
        Check(loaded.has_value(), "reload: " + error); checkpoint = std::move(*loaded);
    }
    void PrepareLivePayloadForFirstCreate() {
        snapshots.clear();Inventory({});
        Edit(5,[](auto& b){PutU64LE(b,0x38,0);PutU32LE(b,0x2C,0);});
        Put(7,Block(183));Edit(7,[](auto& b){PutU64LE(b,0x10,20);});
        Put(8,Block(184));Edit(8,[](auto& b){PutU64LE(b,8,8);PutU64LE(b,0x10,20);});
        // Six live metadata blocks, one retained OMAP root version and payload.
        Edit(4,[](auto& b){PutU64LE(b,0xB8,1);PutU64LE(b,0xC0,1);PutU64LE(b,0x58,8);PutU64LE(b,0xE0,8);});
        Reload();
    }
    void SetPayload(std::uint64_t block, std::uint8_t kind = kApplePhysicalExtentKindNew) {
        auto file = Encode(AppleFileExtentRecord{30,0,bs,block,0,static_cast<std::uint32_t>(bs)}, EncodeAppleFileExtentRecord);
        auto ref = Encode(ApplePhysicalExtentRecord{block,1,kind,30,1}, EncodeApplePhysicalExtentRecord);
        AppleInodeRecord root;root.object_id=2;root.parent_id=2;root.private_id=9;root.mode=0040755;root.children_or_links=1;
        AppleInodeRecord inode;inode.object_id=30;inode.parent_id=2;inode.private_id=30;inode.mode=0100644;inode.children_or_links=1;
        inode.uncompressed_size=bs;AppleExtendedField stream{8,0,Bytes(40)};
        PutU64LE(stream.data,0,bs);PutU64LE(stream.data,8,bs);inode.extended_fields.push_back(stream);
        AppleDirectoryRecord directory;directory.parent_id=2;directory.file_id=30;directory.name_utf8="retained.bin";directory.flags=8;
        std::vector<apfsaccess::catalog::BtreeRecord> records={Encode(root,EncodeAppleInodeRecord),Encode(inode,EncodeAppleInodeRecord),
            Encode(directory,static_cast<bool(*)(const AppleDirectoryRecord&,apfsaccess::catalog::BtreeRecord&,std::string&)>(EncodeAppleDirectoryRecord)),
            Encode(AppleDataStreamIdRecord{30,1},EncodeAppleDataStreamIdRecord),file};
        std::string error;Check(SortAppleBtreeRecords(records,AppleBtreeKeyOrder::FileSystemCaseSensitive,error),"fixture sort");
        std::vector<Bytes> keys,values;for(const auto& record:records){keys.push_back(record.key);values.push_back(record.value);}
        Put(183,BuildRawLeafNode(keys,values,10,bs,0,root_oid,kObjectTypeBtree,kObjectTypeFsTree));
        Put(184,BuildRawLeafNode({ref.key},{ref.value},10,bs,0,184,kObjectPhysical|kObjectTypeBtree,kObjectTypeBlockRefTree));
        Edit(180,[](auto& bytes){PutU64LE(bytes,0xB8,1);PutU64LE(bytes,0xC0,1);});
    }
    void AddSiblingPayload() {
        BuilderVolume v;v.oid=102;v.uuid_hex=std::string(32,'c');v.vol_omap_oid_override=291;
        v.root_oid_override=root_oid;v.snap_meta_tree_oid=snap_oid;v.extentref_tree_oid=294;
        v.file_system_allocated_blocks=7;v.total_blocks_allocated=7;v.next_object_id=0x6000;
        Put(290,BuildApsb(v,20,bs));Put(291,BuildOmap(292,20,bs,291,kObjectPhysical|kObjectTypeOmap,kObjectPhysical|kObjectTypeBtree));
        Put(292,BuildBtreeNode({{root_oid,293,0,20},{snap_oid,295,0,20}},20,bs,0,292,kObjectPhysical|kObjectTypeBtree,kObjectTypeOmap));
        Put(293,Block(183));Edit(293,[](auto& b){PutU64LE(b,0x10,20);});
        Put(294,Block(184));Edit(294,[](auto& b){PutU64LE(b,8,294);PutU64LE(b,0x10,20);});
        Put(295,BuildRawLeafNode({}, {},20,bs,0,snap_oid,kObjectTypeBtree,kObjectTypeSnapMetaTree));
        Put(3,BuildBtreeNode({{101,4,0,20},{102,290,0,20}},20,bs,0,3,kObjectPhysical|kObjectTypeBtree,kObjectTypeOmap));
        Edit(0,[](auto& b){PutU32LE(b,0xB4,2);PutU64LE(b,0xC0,102);});
        Edit(checkpoint.container.superblock_physical_block,[](auto& b){PutU32LE(b,0xB4,2);PutU64LE(b,0xC0,102);});
        Allocate({290,291,292,293,294,295});
    }
    void AddEmptySibling() {
        AddSiblingPayload();
        Put(293,BuildRootFsLeaf(20,bs,root_oid,kObjectTypeBtree,kObjectTypeFsTree));
        Put(294,BuildRawLeafNode({}, {},20,bs,0,294,kObjectPhysical|kObjectTypeBtree,kObjectTypeBlockRefTree));
        Edit(290,[](auto& b){PutU64LE(b,0x58,6);PutU64LE(b,0xE0,6);});
        Reload();
    }
    void InstallLivePayload(std::uint64_t block) {
        VectorRandomAccessSource source(image);std::string error;std::vector<ApfsSnapshotInfo> items;
        Check(Enumerate(items,error),"live fixture inventory");ApfsSnapshotRecords raw;
        Check(ApfsSnapshotStore::LoadExactRecords(source,items[0].identity,raw,error),"live fixture exact records");
        std::vector<Bytes> keys,values;
        for(auto& r:raw.trees.filesystem){
            if(ReadU64LE(r.key,0).value_or(0)>>60==8){AppleFileExtentRecord f;
                Check(DecodeAppleFileExtentRecord(r,4096,f,error),"live fixture extent");f.physical_block=block;
                Check(EncodeAppleFileExtentRecord(f,r,error),"live fixture mapping");}
            keys.push_back(r.key);values.push_back(r.value);
        }
        Put(7,BuildRawLeafNode(keys,values,20,bs,0,root_oid,kObjectTypeBtree,kObjectTypeFsTree));
        auto live=Encode(ApplePhysicalExtentRecord{block,1,kApplePhysicalExtentKindNew,30,1},EncodeApplePhysicalExtentRecord);
        // Construct the signed decrement directly as fixture bytes so this
        // malformed ownership graph can also be exercised by the frozen codec.
        apfsaccess::catalog::BtreeRecord removed{Bytes(8),Bytes(20)};
        PutU64LE(removed.key,0,(2ull<<60)|220);PutU64LE(removed.value,0,(2ull<<60)|1);
        PutU64LE(removed.value,8,30);PutU32LE(removed.value,16,0xffffffffu);
        Put(8,BuildRawLeafNode({live.key,removed.key},{live.value,removed.value},20,bs,0,8,kObjectPhysical|kObjectTypeBtree,kObjectTypeBlockRefTree));Reload();
    }
    void Allocate(const std::vector<std::uint64_t>& blocks) {
        const auto& chunk=checkpoint.spaceman.chunks.at(0);
        auto bitmap=Block(chunk.bitmap_block); std::uint32_t added=0;
        for (const auto block:blocks) {
            auto& byte=bitmap.at(block/8); const auto mask=1u<<(block%8);
            if (!(std::to_integer<unsigned>(byte)&mask)) {byte|=static_cast<std::byte>(mask);++added;}
        }
        Put(chunk.bitmap_block,bitmap,false);
        const auto cib=checkpoint.spaceman.devices[0].cibs[chunk.cib_index].object.physical_block;
        Edit(cib,[&](auto& b){PutU32LE(b,0x3C,chunk.free_count-added);});
        Edit(checkpoint.spaceman.object.physical_block,[&](auto& b){
            PutU64LE(b,0x48,checkpoint.spaceman.devices[0].free_count-added);});
        Reload();
    }
    bool Census(AppleSnapshotRetentionView& result,std::string& error) const {
        VectorRandomAccessSource source(image);return LoadAppleSnapshotRetention(source,checkpoint,result,error);
    }
    AppleTransactionCommitRequest Request(std::vector<AppleSpacemanReleaseRequest> releases={}) const {
        AppleSpacemanAllocationRequest request;
        const auto& nx=checkpoint.container.superblock;
        request.expected_checkpoint_xid=nx.xid;request.transaction_xid=nx.next_xid;
        request.oldest_required_checkpoint_xid=nx.xid;request.first_ephemeral_object_id=nx.next_oid;
        request.main_block_count=1;request.released_blocks=std::move(releases);
        AppleTransactionCommitRequest commit;std::string error;
        Check(PlanAppleSpacemanAllocation(checkpoint.spaceman,request,commit.allocation_plan,error),"allocate: "+error);
        commit.next_object_id=nx.next_oid+32;
        commit.allocated_main_writes.push_back({commit.allocation_plan.allocated_main_blocks.at(0),Bytes(bs,std::byte{0x42})});
        return commit;
    }
    bool Plan(const AppleTransactionCommitRequest& request,AppleTransactionCommitPlan& plan,std::string& error) const {
        VectorRandomAccessSource source(image);return PlanAppleTransactionCommit(source,checkpoint,request,plan,error);
    }
};

class MutableFixtureSource final : public RandomAccessSource {
public:
    explicit MutableFixtureSource(const Bytes& bytes) : bytes_(bytes) {}
    mutable std::size_t read_count = 0;
    std::function<void(std::uint64_t,std::size_t)> after_read;
    std::uint64_t SizeBytes() const override { return bytes_.size(); }
    bool Read(std::uint64_t offset, std::size_t size, Bytes& out) const override {
        out.clear();
        if (offset > bytes_.size() || size > bytes_.size() - offset) return false;
        out.assign(bytes_.begin() + offset, bytes_.begin() + offset + size);
        ++read_count;
        if (after_read) after_read(offset,size);
        return true;
    }
private:
    const Bytes& bytes_;
};

class RetainedBufferBudgetSource final : public RandomAccessSource {
public:
    RetainedBufferBudgetSource(const Bytes& bytes, std::shared_ptr<ApfsReadBudget> budget)
        : source_(bytes), budget_(std::move(budget)) {}
    std::uint64_t SizeBytes() const override { return source_.SizeBytes(); }
    bool Read(std::uint64_t offset, std::size_t size, Bytes& out) const override {
        if (!source_.Read(offset,size,out)) return false;
        reads.push_back(budget_->Consumed());
        if (cut_after_read && reads.size()==*cut_after_read)
            budget_->LimitRemainingTo(65536,256ull<<20,1000000,0);
        return true;
    }
    mutable std::vector<ApfsReadBudget::Consumption> reads;
    std::optional<std::size_t> cut_after_read;
private:
    MutableFixtureSource source_;
    std::shared_ptr<ApfsReadBudget> budget_;
};

void ExtendedMetadataAdmissionTests() {
    for (const auto block : {4ull, 290ull}) {
        Fixture f(16,32);
        f.PrepareLivePayloadForFirstCreate();
        f.AddEmptySibling();
        MutableFixtureSource source(f.image);
        AppleSnapshotRetentionView retained;
        std::string error;
        Check(LoadAppleSnapshotRetention(source,f.checkpoint,retained,error) && retained.identities.empty(),
            "serialized zero OID and empty all-volume inventories retain ordinary admission: "+error);
        std::vector<AppleRecoveryCheckpointView> pins;
        Check(LoadAppleRecoveryCheckpoints(source,f.checkpoint,{20},pins,error) && pins.empty(),
            "zero OID current-only recovery positive control: "+error);
        auto budget=std::make_shared<ApfsReadBudget>(65536,256ull<<20,1000000,256ull<<20);
        BudgetedRandomAccessSource bounded(source,budget);
        SnapshotPlanningSource observation(bounded);
        Check(LoadAppleSnapshotRecoveryCheckpoints(observation,f.checkpoint,{20},pins,error),
            "warm zero-OID owner proof for an entirely snapshot-free cohort: "+error);
        // Deliberately keep the parsed checkpoint unchanged: source bytes govern admission.
        f.Edit(block,[](auto& b){PutU64LE(b,0x3E8,999);});
        const auto unchanged=f.image;
        retained.identities.resize(1);retained.metadata_blocks={999};
        Check(!LoadAppleSnapshotRetention(source,f.checkpoint,retained,error) &&
            error=="SnapshotExtendedMetadataUnsupported" && retained.identities.empty() &&
            retained.metadata_blocks.empty() && retained.payload_extents.empty(),
            "empty snapshot counts cannot hide a selected or sibling extended OID: "+error);
        pins.resize(1);
        Check(!LoadAppleRecoveryCheckpoints(source,f.checkpoint,{20},pins,error) && pins.empty() &&
            error=="SnapshotExtendedMetadataUnsupported",
            "current-XID recovery shortcut checks source-bound selected and sibling OIDs: "+error);
        std::shared_ptr<const std::vector<SnapshotRetentionCatalog>> catalogs;
        Check(!LoadSnapshotPlanningRetentionCatalogs(observation,f.checkpoint,retained,catalogs,error) &&
            budget->Failed() && !error.empty() && !catalogs && retained.identities.empty() &&
            retained.metadata_blocks.empty() && retained.payload_extents.empty(),
            "warm owner cache cannot admit changed selected or sibling APSB bytes");
        Check(f.image==unchanged,"empty-cohort refusals never rewrite opaque APSB bytes");
        Pass(block==4 ? "empty selected extended OID barrier" : "empty sibling extended OID barrier");
    }
    {
        Fixture f(16,32);
        f.Edit(180,[](auto& b){PutU64LE(b,0x3E8,999);});
        const auto unchanged=f.image;
        MutableFixtureSource source(f.image);
        AppleSnapshotRetentionView retained;
        std::string error;
        Check(!LoadAppleSnapshotRetention(source,f.checkpoint,retained,error) &&
            error=="SnapshotExtendedMetadataUnsupported" && retained.identities.empty() &&
            retained.metadata_blocks.empty() && retained.payload_extents.empty(),
            "historical snapshot APSB still refuses extended metadata: "+error);
        std::vector<std::uint64_t> metadata{999};
        std::vector<ApplePhysicalExtentRecord> payload(1);
        error.clear();
        Check(!LoadAppleSnapshotCheckpointOwners(source,f.checkpoint,metadata,payload,error) &&
            metadata.empty() && payload.empty() && error=="SnapshotExtendedMetadataUnsupported",
            "historical owner closure cannot turn an extended APSB into retention evidence: "+error);
        Check(f.image==unchanged,"historical refusal leaves the serialized source unchanged");
        Pass("historical snapshot extended OID barrier");
    }
    for (const auto oid : {101ull,102ull}) {
        Fixture f(16,32);
        f.PrepareLivePayloadForFirstCreate();
        f.AddEmptySibling();
        MutableFixtureSource source(f.image);
        AppleSnapshotCreateRequest request{101,"extended-cache",1};
        request.required_checkpoint_xids={20};
        AppleSnapshotCreatePlan plan;
        std::string error;
        Check(PlanAppleSnapshotCreate(source,f.checkpoint,request,plan,error),"extended cache fixture plan: "+error);
        auto budget=std::make_shared<ApfsReadBudget>(65536,256ull<<20,1000000,256ull<<20);
        BudgetedRandomAccessSource bounded(source,budget);
        SnapshotPlanningSource observation(bounded);
        AppleSnapshotRetirementProof proof;
        Check(ProveAppleSnapshotRetirement(observation,f.checkpoint,plan.commit.publication,101,{20},proof,error),
            "warm actual serialized staged retention proof: "+error);
        SnapshotPublicationSource staged(observation,plan.commit.publication);
        auto cp=LoadAppleCheckpointView(staged,0,staged.SizeBytes(),error);
        Check(cp.has_value(),"load staged zero extended OID checkpoint: "+error);
        AppleSnapshotRetentionView retained;
        std::shared_ptr<const std::vector<SnapshotRetentionCatalog>> catalogs;
        Check(LoadSnapshotPlanningRetentionCatalogs(staged,*cp,retained,catalogs,error) && catalogs,
            "borrow zero-OID completed staged proof: "+error);
        const auto found=std::find_if(cp->volumes.begin(),cp->volumes.end(),
            [&](const auto& v){return v.superblock.object_id==oid;});
        Check(found!=cp->volumes.end(),"staged extended OID target exists");
        auto write=std::find_if(plan.commit.publication.before_superblock_writes.begin(),
            plan.commit.publication.before_superblock_writes.end(),
            [&](const auto& w){return w.physical_block==found->superblock_object.physical_block;});
        if(write!=plan.commit.publication.before_superblock_writes.end()) {
            PutU64LE(write->bytes,0x3E8,999);FletcherForBlock(write->bytes,4096);
        } else {
            f.Edit(found->superblock_object.physical_block,[](auto& b){PutU64LE(b,0x3E8,999);});
        }
        const auto unchanged=f.image;
        Check(!LoadSnapshotPlanningRetentionCatalogs(staged,*cp,retained,catalogs,error) && !error.empty() &&
            retained.identities.empty() && retained.metadata_blocks.empty() && retained.payload_extents.empty() && !catalogs,
            "borrowed proof must reread selected or sibling extended OID before returning success");
        Check(f.image==unchanged,"borrowed-proof refusal never publishes or normalizes APSB bytes");
        Pass(oid==101 ? "borrowed selected extended OID barrier" : "borrowed sibling extended OID barrier");
    }
}

void PeerCatalogAdmissionTests() {
    for (const auto offset : {0x3E8u,0xA0u,0x418u}) {
        Fixture f(16,32);
        f.AddEmptySibling();
        MutableFixtureSource source(f.image);
        std::string error;
        AppleSnapshotCatalogRecords canonical;
        Check(LoadAppleSnapshotCatalog(source,f.checkpoint,102,canonical,error) && canonical.inventory.empty(),
            "canonical snapshot-free sibling positive control: "+error);
        auto budget=std::make_shared<ApfsReadBudget>(65536,256ull<<20,1000000,256ull<<20);
        BudgetedRandomAccessSource bounded(source,budget);
        SnapshotPlanningSource observation(bounded);
        std::vector<AppleRecoveryCheckpointView> pins;
        Check(LoadAppleSnapshotRecoveryCheckpoints(observation,f.checkpoint,{20},pins,error),
            "warm snapshot-bearing cohort with admitted empty sibling: "+error);
        Check(LoadAppleSnapshotRecoveryCheckpoints(observation,f.checkpoint,{20},pins,error),
            "reuse admitted complete peer graph: "+error);
        f.Edit(290,[&](auto& b){PutU64LE(b,offset,999);});
        f.Reload();
        const auto unchanged=f.image;
        Check(!LoadAppleSnapshotCatalog(source,f.checkpoint,102,canonical,error),
            "canonical loader refuses unsupported sibling layout");
        const auto expected=offset==0x3E8 ? "SnapshotExtendedMetadataUnsupported" :
            "SnapshotVolumeStateOrReservedFieldsUnsupported";
        Check(error==expected,"exact independent canonical admission refusal: "+error);
        AppleSnapshotRetentionView retained;
        std::shared_ptr<const std::vector<SnapshotRetentionCatalog>> catalogs;
        const bool admitted=LoadSnapshotPlanningRetentionCatalogs(source,f.checkpoint,retained,catalogs,error);
        Check(!admitted && error==expected,
            "cold whole-cohort catalog refuses the same unsupported peer: "+error);
        Check(retained.identities.empty() && retained.metadata_blocks.empty() && retained.payload_extents.empty() &&
            !catalogs,"cold refusal clears every reusable ownership output");
        pins.resize(1);
        Check(!LoadAppleSnapshotRecoveryCheckpoints(observation,f.checkpoint,{20},pins,error) && pins.empty(),
            "warm complete proof refuses changed sibling admission bytes: "+error);
        Check(!error.empty() && budget->Failed(),"changed cached peer has sticky explicit refusal");
        AppleSnapshotCreateRequest request{101,"peer-admission-negative",1};
        request.required_checkpoint_xids={20};
        AppleSnapshotCreatePlan plan;
        Check(!PlanAppleSnapshotCreate(source,f.checkpoint,request,plan,error),
            "actual second snapshot create refuses unsupported snapshot-free peer: "+error);
        Check(plan.commit.publication.before_superblock_writes.empty() && plan.allocation.allocated_main_blocks.empty() &&
            !plan.identity.snapshot_xid && f.image==unchanged,"refused peer creates no executable plan or source writes");
        Pass("strict cold and reused snapshot-free peer admission at "+std::to_string(offset));
    }
}

void GuardCopyBudgetTests(std::string_view selected="all") {
    Check(selected=="all" || selected=="records" || selected=="bytes","known guard-copy test mode");
    class Source final : public RandomAccessSource {
    public:
        Source(const Bytes& bytes, std::shared_ptr<ApfsReadBudget> budget,
            const AppleCheckpointView& checkpoint)
            : bytes_(bytes), budget_(std::move(budget)),
              object_blocks_{checkpoint.volumes[0].superblock_object.physical_block,
                  checkpoint.volumes[0].object_map.object.physical_block,
                  checkpoint.container_object_map.object.physical_block},
              map_tree_(checkpoint.volumes[0].object_map.tree.physical_block) {}
        std::uint64_t SizeBytes() const override { return bytes_.size(); }
        bool Read(std::uint64_t offset, std::size_t size, Bytes& out) const override {
            out.clear();
            if(offset>bytes_.size() || size>bytes_.size()-offset)return false;
            out.assign(bytes_.begin()+offset,bytes_.begin()+offset+size);
            ++reads;
            if(fired && size==4096 && offset==map_tree_*4096)++map_reads_after_limit;
            if(armed && !fired) {
                if(size==4096 && offset==object_blocks_[object_index_]*4096)++object_index_;
                else object_index_=size==4096 && offset==object_blocks_[0]*4096 ? 1 : 0;
                if(object_index_==3) {
                    // The first triple is the strict ownership recheck. The
                    // second is Create's late ReadObject prefix before guards.
                    object_index_=0;
                    if(++object_sequences_!=2)return true;
                    fired=true;reads_at_limit=reads;
                    if(deny_records || deny_bytes)
                        budget_->LimitRemainingTo(65536,256ull<<20,
                            deny_records ? metadata_ids-1 : 1000000,
                            deny_bytes ? metadata_ids*sizeof(std::uint64_t)-1 : 256ull<<20);
                }
            }
            return true;
        }
        bool armed=false,deny_records=false,deny_bytes=false;
        std::uint64_t metadata_ids=0;
        mutable bool fired=false;
        mutable std::uint64_t reads=0,reads_at_limit=0,map_reads_after_limit=0;
    private:
        const Bytes& bytes_;
        std::shared_ptr<ApfsReadBudget> budget_;
        std::uint64_t object_blocks_[3],map_tree_;
        mutable std::size_t object_index_=0,object_sequences_=0;
    };
    for(const auto* mode:{"positive","records","bytes"}) {
        if(std::string_view(mode)!="positive" && selected!="all" && selected!=mode)continue;
        Fixture f(16,32);
        f.PrepareLivePayloadForFirstCreate();
        MutableFixtureSource seed(f.image);std::string error;
        AppleSnapshotCreateRequest first_request{101,"guard-copy-existing",1};
        first_request.required_checkpoint_xids={f.checkpoint.container.superblock.xid};
        AppleSnapshotCreatePlan first;
        Check(PlanAppleSnapshotCreate(seed,f.checkpoint,first_request,first,error),
            "guard fixture first snapshot uses the production planner: "+error);
        SnapshotPublicationSource serialized(seed,first.commit.publication);Bytes current;
        Check(serialized.Read(0,static_cast<std::size_t>(serialized.SizeBytes()),current),
            "guard fixture uses the exact serialized first checkpoint");
        f.image=std::move(current);f.Reload();
        const auto original=f.image;
        auto budget=std::make_shared<ApfsReadBudget>(65536,256ull<<20,1000000,256ull<<20);
        Source source(f.image,budget,f.checkpoint);
        BudgetedRandomAccessSource bounded(source,budget);
        SnapshotPlanningSource observation(bounded);
        AppleSnapshotRetentionView retained;
        std::shared_ptr<const std::vector<SnapshotRetentionCatalog>> catalogs;
        std::vector<AppleRecoveryCheckpointView> pins;
        Check(LoadAppleSnapshotRecoveryCheckpoints(observation,f.checkpoint,
            {f.checkpoint.container.superblock.xid},pins,error),
            "warm the completed reusable owner graph before the guard boundary: "+error);
        Check(LoadSnapshotPlanningRetentionCatalogs(observation,f.checkpoint,retained,catalogs,error),
            "warm full current owner and canonical retention proof: "+error);
        const auto warmed_reads=source.reads;
        Check(LoadSnapshotPlanningRetentionCatalogs(observation,f.checkpoint,retained,catalogs,error) &&
            source.reads>warmed_reads,"warm proof still reads original dependencies: "+error);
        Check(catalogs && catalogs->size()==1 && !catalogs->front().metadata_preimages.empty(),
            "guard fixture owns complete canonical metadata evidence");
        source.metadata_ids=catalogs->front().records.metadata_blocks.size();
        Check(source.metadata_ids>0,"guard-copy reservation has actual metadata IDs");
        source.deny_records=std::string_view(mode)=="records";
        source.deny_bytes=std::string_view(mode)=="bytes";
        source.armed=true;
        AppleSnapshotCreateRequest request{101,"guard-copy-budget",1};
        request.required_checkpoint_xids={f.checkpoint.container.superblock.xid};
        AppleSnapshotCreatePlan plan;
        plan.commit.publication.before_superblock_writes.resize(1);
        plan.commit.publication.before_superblock_writes[0].physical_block=499;
        plan.commit.publication.before_superblock_writes[0].bytes.resize(4096);
        plan.allocation.allocated_main_blocks.push_back(499);plan.identity.snapshot_xid=99;
        const bool planned=PlanAppleSnapshotCreate(observation,f.checkpoint,request,plan,error);
        Check(source.fired,"limit applied after the exact three already-observed source object reads");
        if(std::string_view(mode)=="positive") {
            Check(planned && !budget->Failed() && !plan.commit.publication.before_superblock_writes.empty() &&
                plan.identity.snapshot_xid==f.checkpoint.container.superblock.next_xid,
                "unrestricted same warm proof creates a complete second snapshot plan: "+error);
            Check(source.map_reads_after_limit>0,"positive control reaches the following map-tree read");
        }else {
            const auto refused=budget->ReservationFailure();
            Check(!planned && budget->Failed() && error=="ApfsReadBudgetRecordLimit",
                "guard copy refuses the exact sticky allowance: "+error);
            std::cout<<"GUARD_COPY mode="<<mode<<" ids="<<source.metadata_ids
                <<" refused_count="<<refused.count<<" refused_bytes="<<refused.bytes
                <<" reads_after_limit="<<(source.reads-source.reads_at_limit)
                <<" next_map_reads="<<source.map_reads_after_limit<<'\n';
            Check(refused.count==source.metadata_ids && refused.bytes==source.metadata_ids*sizeof(std::uint64_t),
                "denied reservation is precisely the newly owned metadata-ID copy");
            Check(source.reads==source.reads_at_limit && source.map_reads_after_limit==0,
                "guard denial precedes allocation and the next map-tree backing read");
            Check(plan.commit.publication.before_superblock_writes.empty() &&
                plan.commit.publication.guard_blocks.empty() && plan.commit.publication.superblock_write.bytes.empty() &&
                plan.allocation.allocated_main_blocks.empty() && plan.allocation.writes.empty() &&
                !plan.identity.snapshot_xid,"guard denial clears every executable create output");
            const auto before=budget->Consumed();const auto backing_reads=source.reads;
            Check(!PlanAppleSnapshotCreate(observation,f.checkpoint,request,plan,error) &&
                error=="ApfsReadBudgetRecordLimit","guard-copy retry preserves the original sticky failure");
            const auto after=budget->Consumed();const auto retry_refused=budget->ReservationFailure();
            Check(source.reads==backing_reads && before.reads==after.reads && before.read_bytes==after.read_bytes &&
                before.records==after.records && before.record_bytes==after.record_bytes &&
                retry_refused.count==refused.count && retry_refused.bytes==refused.bytes,
                "guard-copy retry performs zero backing I/O or materialization");
            Check(plan.commit.publication.before_superblock_writes.empty() && plan.allocation.allocated_main_blocks.empty() &&
                !plan.identity.snapshot_xid,"sticky retry cannot return a cached executable plan");
        }
        Check(f.image==original,"guard-copy success or refusal preserves every original source byte");
        Pass(std::string("completed-catalog guard-copy budget: ")+mode);
    }
}

void PlanningObservationTests() {
    {
        Fixture f(16,32);
        f.PrepareLivePayloadForFirstCreate();
        MutableFixtureSource fixture(f.image);
        AppleSnapshotCreateRequest request{101,"retained-byte-budget",1};
        request.required_checkpoint_xids={20};
        AppleSnapshotCreatePlan plan;
        std::string error;
        Check(PlanAppleSnapshotCreate(fixture,f.checkpoint,request,plan,error),"retained-byte fixture publication");
        auto budget=std::make_shared<ApfsReadBudget>(65536,256ull<<20,1000000,256ull<<20);
        RetainedBufferBudgetSource source(f.image,budget);
        BudgetedRandomAccessSource bounded(source,budget);
        SnapshotPlanningSource observation(bounded);
        std::vector<AppleRecoveryCheckpointView> pins;
        Check(LoadAppleSnapshotRecoveryCheckpoints(observation,f.checkpoint,{20},pins,error),"warm original retained graph");
        source.reads.clear();
        AppleSnapshotRetirementProof proof;
        Check(ProveAppleSnapshotRetirement(observation,f.checkpoint,plan.commit.publication,101,{20},proof,error),
            "measure distinct staged retained graph");
        std::size_t buffer_read=0;
        for(std::size_t i=1;i<source.reads.size();++i) {
            const auto& before=source.reads[i-1]; const auto& after=source.reads[i];
            if(after.records==before.records && after.record_bytes-before.record_bytes==f.bs) {buffer_read=i;break;}
        }
        Check(buffer_read!=0,"distinct graph reserves an actual retained block buffer");
        auto limited=std::make_shared<ApfsReadBudget>(65536,256ull<<20,1000000,256ull<<20);
        RetainedBufferBudgetSource constrained(f.image,limited);
        BudgetedRandomAccessSource constrained_view(constrained,limited);
        SnapshotPlanningSource constrained_observation(constrained_view);
        Check(LoadAppleSnapshotRecoveryCheckpoints(constrained_observation,f.checkpoint,{20},pins,error),
            "warm original graph before byte restriction");
        constrained.reads.clear();
        constrained.cut_after_read=buffer_read;
        Check(!ProveAppleSnapshotRetirement(constrained_observation,f.checkpoint,plan.commit.publication,101,{20},proof,error),
            "retained staged buffer refuses insufficient bytes");
        const auto refused=limited->ReservationFailure();
        Check(limited->Failed() && error=="ApfsReadBudgetRecordLimit" && refused.count==0 && refused.bytes==f.bs,
            "retained bytes use the direct byte reservation rather than a zero-width product");
        Check(constrained.reads.size()==buffer_read,"refusal happens before allocating or dispatching the next block read");
        Check(proof.releases.empty() && proof.source_metadata_blocks.empty() && proof.source_owned_blocks.empty() &&
            !proof.allocated_volume_blocks && !proof.retired_volume_blocks && !proof.retired_volume_payload_blocks,
            "retained byte failure clears complete retirement proof");
        const auto before=limited->Consumed();
        Check(!ProveAppleSnapshotRetirement(constrained_observation,f.checkpoint,plan.commit.publication,101,{20},proof,error),
            "retained proof cannot escape failed shared budget");
        Check(limited->Consumed().reads==before.reads && limited->Consumed().record_bytes==before.record_bytes &&
            constrained.reads.size()==buffer_read,"sticky retained failure does no further reads or allocation");
        Pass("retained metadata byte reservation precedes allocation and remains sticky");
    }
    for (const auto* changed : {"omap", "allocator", "unknown-owner", "sticky-budget"}) {
        Fixture f(16,32);
        MutableFixtureSource source(f.image);
        auto budget = std::make_shared<ApfsReadBudget>(65536,256ull<<20,1000000,256ull<<20);
        BudgetedRandomAccessSource bounded(source,budget);
        SnapshotPlanningSource observation(bounded);
        std::vector<AppleRecoveryCheckpointView> pins;
        std::string error;
        Check(LoadAppleSnapshotRecoveryCheckpoints(observation,f.checkpoint,{20},pins,error),
            "warm actual current owner closure: " + error);
        const auto before = budget->Consumed();
        Check(LoadAppleSnapshotRecoveryCheckpoints(observation,f.checkpoint,{20},pins,error),
            "borrow unchanged completed closure: " + error);
        const auto after = budget->Consumed();
        Check(after.reads > before.reads && after.records - before.records < 1000,
            "reuse still reads original dependencies without rematerializing closure");
        if (std::string_view(changed) == "omap") f.Edit(6,[](auto& b){PutU64LE(b,0x10,21);});
        else if (std::string_view(changed) == "allocator") {
            const auto& chunk = f.checkpoint.spaceman.chunks[0];
            f.Edit(chunk.bitmap_block,[](auto& b){b[220/8] ^= static_cast<std::byte>(1u<<(220%8));},false);
        } else if (std::string_view(changed) == "unknown-owner")
            f.Put(3,BuildBtreeNode({{999,4,0,20}},20,f.bs,0,3,kObjectPhysical|kObjectTypeBtree,kObjectTypeOmap));
        else Check(!budget->Materialize(UINT64_MAX,0),"deliberately exhausted shared budget");
        pins.resize(1);
        Check(!LoadAppleSnapshotRecoveryCheckpoints(observation,f.checkpoint,{20},pins,error) && pins.empty(),
            "warm proof refuses changed dependency or exhausted budget: " + std::string(changed));
        Check(budget->Failed() && !error.empty(),"reuse failure is sticky and explicit");
        Pass(std::string("operation proof refusal: ") + changed);
    }
    for (bool byte_limit : {false, true}) {
        Fixture f(16,32);
        f.PrepareLivePayloadForFirstCreate();
        MutableFixtureSource source(f.image);
        auto budget = std::make_shared<ApfsReadBudget>(65536,256ull<<20,
            byte_limit ? 1000000 : 64, byte_limit ? 8192 : 256ull<<20);
        BudgetedRandomAccessSource bounded(source,budget);
        AppleSnapshotCreateRequest request{101,"tiny-budget",1};
        request.required_checkpoint_xids={20};
        AppleSnapshotCreatePlan plan;
        std::string error;
        Check(!PlanAppleSnapshotCreate(bounded,f.checkpoint,request,plan,error),"tiny materialization budget refuses create");
        Check(budget->Failed() && error=="ApfsReadBudgetRecordLimit" &&
            plan.commit.publication.before_superblock_writes.empty() && plan.allocation.allocated_main_blocks.empty() &&
            plan.identity.snapshot_xid==0,"budget failure clears the complete executable plan");
        const auto consumed=budget->Consumed();
        Check(!PlanAppleSnapshotCreate(bounded,f.checkpoint,request,plan,error),"failed budget cannot yield cached success");
        const auto retry=budget->Consumed();
        Check(consumed.reads==retry.reads && consumed.records==retry.records && consumed.record_bytes==retry.record_bytes,
            "failed budget does no further work or materialization");
        Pass(byte_limit ? "tiny byte budget remains sticky and clears create" : "tiny record budget remains sticky and clears create");
    }
    for (const auto* changed : {"staged-allocator","staged-omap"}) {
        Fixture f(16,32);
        f.PrepareLivePayloadForFirstCreate();
        MutableFixtureSource source(f.image);
        AppleSnapshotCreateRequest request{101,"staged-proof",1};
        request.required_checkpoint_xids={20};
        AppleSnapshotCreatePlan plan;
        std::string error;
        const bool planned=PlanAppleSnapshotCreate(source,f.checkpoint,request,plan,error);
        Check(planned,"actual staged proof fixture: "+error);
        auto budget=std::make_shared<ApfsReadBudget>(65536,256ull<<20,1000000,256ull<<20);
        BudgetedRandomAccessSource bounded(source,budget);
        SnapshotPlanningSource observation(bounded);
        AppleSnapshotRetirementProof proof;
        Check(ProveAppleSnapshotRetirement(observation,f.checkpoint,plan.commit.publication,101,{20},proof,error),
            "warm exact serialized original/staged owner graphs: "+error);
        SnapshotPublicationSource staged(observation,plan.commit.publication);
        auto cp=LoadAppleCheckpointView(staged,0,staged.SizeBytes(),error);
        Check(cp.has_value(),"fresh exact staged allocator: "+error);
        AppleSnapshotRetentionView retained;
        const auto before=budget->Consumed();
        Check(LoadAppleSnapshotRetention(staged,*cp,retained,error),"borrow completed staged catalog: "+error);
        Check(budget->Consumed().reads>before.reads,"staged reuse rechecks actual source and metadata bytes");
        const bool bitmap=std::string_view(changed)=="staged-allocator";
        const auto block=bitmap ? cp->spaceman.chunks[0].bitmap_block : cp->volumes[0].object_map.tree.physical_block;
        auto write=std::find_if(plan.commit.publication.before_superblock_writes.begin(),
            plan.commit.publication.before_superblock_writes.end(),[&](const auto& w){return w.physical_block==block;});
        Check(write!=plan.commit.publication.before_superblock_writes.end(),"mutate actual serialized staged evidence");
        if(bitmap) write->bytes[220/8]&=static_cast<std::byte>(~(1u<<(220%8)));
        else {PutU64LE(write->bytes,0x10,cp->container.superblock.xid+1);FletcherForBlock(write->bytes,4096);}
        retained.identities.resize(1);
        auto changed_cp=LoadAppleCheckpointView(staged,0,staged.SizeBytes(),error);
        const bool admitted=changed_cp && LoadAppleSnapshotRetention(staged,*changed_cp,retained,error);
        Check(!admitted && !error.empty(),"warm staged proof refuses changed actual allocator or OMAP: "+std::string(changed));
        if(changed_cp) Check(retained.identities.empty() && retained.metadata_blocks.empty() && retained.payload_extents.empty(),
            "changed staged census returns no retained proof");
        Check(f.checkpoint.container.superblock.xid==20,"negative never publishes staged checkpoint");
        Pass(std::string("completed staged proof refusal: ")+changed);
    }
    for(bool byte_limit:{false,true}) {
        Fixture f(16,32);
        f.PrepareLivePayloadForFirstCreate();
        MutableFixtureSource source(f.image);
        AppleSnapshotCreateRequest creation{101,"delete-budget",1};
        AppleSnapshotCreatePlan created;
        std::string error;
        Check(PlanAppleSnapshotCreate(source,f.checkpoint,creation,created,error),"delete budget preimage");
        SnapshotPublicationSource published(source,created.commit.publication);
        auto cp=LoadAppleCheckpointView(published,0,published.SizeBytes(),error);
        Check(cp.has_value(),"delete budget exact serialized checkpoint");
        AppleSnapshotDeleteRequest request;
        request.expected=created.identity;request.modification_time_ns=2;
        request.required_checkpoint_xids={cp->container.superblock.xid};
        auto budget=std::make_shared<ApfsReadBudget>(65536,256ull<<20,
            byte_limit ? 1000000 : 64,byte_limit ? 8192 : 256ull<<20);
        BudgetedRandomAccessSource limited(published,budget);
        AppleSnapshotDeletePlan plan;
        const bool planned=PlanAppleSnapshotDelete(limited,*cp,request,plan,error);
        Check(!planned && budget->Failed() && error=="ApfsReadBudgetRecordLimit",
            "tiny delete materialization allowance refuses: "+error+" sticky="+budget->Failure());
        Check(plan.allocation.allocated_main_blocks.empty() && plan.commit.publication.before_superblock_writes.empty() &&
            plan.surviving.empty() && !plan.removed.snapshot_xid && !plan.released_payload_blocks,
            "delete byte or record failure clears complete executable plan");
        const auto before=budget->Consumed();
        Check(!PlanAppleSnapshotDelete(limited,*cp,request,plan,error),"delete retry retains shared failure");
        const auto after=budget->Consumed();
        Check(after.reads==before.reads && after.record_bytes==before.record_bytes && after.records==before.records,
            "failed delete proof cannot create a new allowance or cached success");
        Pass(byte_limit ? "delete tiny byte budget stays sticky" : "delete tiny record budget stays sticky");
    }
}
void CanonicalRetentionReuseTests() {
    for (const auto* changed : {"current-tree-future", "snapshot-tree-future", "snapshot-multiplicity", "tree-checksum"}) {
        Fixture f(16,32);
        f.AddEmptySibling();
        MutableFixtureSource source(f.image);
        auto budget=std::make_shared<ApfsReadBudget>(65536,256ull<<20,1000000,256ull<<20);
        BudgetedRandomAccessSource bounded(source,budget);
        SnapshotPlanningSource observation(bounded);
        AppleSnapshotRetentionView retained;
        std::shared_ptr<const std::vector<SnapshotRetentionCatalog>> catalogs;
        std::string error;
        Check(LoadSnapshotPlanningRetentionCatalogs(observation,f.checkpoint,retained,catalogs,error),
            "warm full canonical record and geometry proof: "+error);
        const auto before=budget->Consumed();
        Check(LoadSnapshotPlanningRetentionCatalogs(observation,f.checkpoint,retained,catalogs,error),
            "reuse completed canonical proof with original source reads: "+error);
        Check(budget->Consumed().reads>before.reads,"canonical reuse rechecks actual metadata");
        const auto completed_catalogs=catalogs;
        const std::string_view kind(changed);
        if(kind=="current-tree-future")
            f.Edit(f.checkpoint.volumes[0].root_tree.physical_block,[](auto& bytes){PutU64LE(bytes,0x10,21);});
        else if(kind=="snapshot-tree-future") f.Edit(183,[](auto& bytes){PutU64LE(bytes,0x10,11);});
        else if(kind=="tree-checksum") f.Edit(183,[](auto& bytes){bytes[0]^=std::byte{1};},false);
        else {
            auto ref=Encode(ApplePhysicalExtentRecord{220,1,kApplePhysicalExtentKindNew,30,2},EncodeApplePhysicalExtentRecord);
            f.Put(184,BuildRawLeafNode({ref.key},{ref.value},10,f.bs,0,184,kObjectPhysical|kObjectTypeBtree,kObjectTypeBlockRefTree));
        }
        auto cold_budget=std::make_shared<ApfsReadBudget>(65536,256ull<<20,1000000,256ull<<20);
        BudgetedRandomAccessSource cold(source,cold_budget);
        Check(!LoadSnapshotPlanningRetentionCatalogs(cold,f.checkpoint,retained,catalogs,error) && !error.empty(),
            std::string("fresh canonical proof refuses invalid tree or exact reference count: ")+changed);
        Check(retained.identities.empty() && retained.metadata_blocks.empty() && retained.payload_extents.empty() && !catalogs,
            "cold canonical refusal clears every owned output");
        retained.identities.resize(1);catalogs=completed_catalogs;
        Check(!LoadSnapshotPlanningRetentionCatalogs(observation,f.checkpoint,retained,catalogs,error) && budget->Failed(),
            "completed proof refuses changed original canonical bytes");
        Check(retained.identities.empty() && retained.metadata_blocks.empty() && retained.payload_extents.empty() && !catalogs,
            "warm canonical refusal clears every owned output");
        const auto refused=budget->Consumed();
        Check(!LoadSnapshotPlanningRetentionCatalogs(observation,f.checkpoint,retained,catalogs,error),
            "changed canonical bytes cannot become cached success");
        Check(budget->Consumed().reads==refused.reads && budget->Consumed().record_bytes==refused.record_bytes,
            "canonical failure remains sticky without more reads or allocation");
        Pass(std::string("cold and warm canonical refusal: ")+changed);
    }
}
void DependencyBatchingTests() {
    class Source final : public RandomAccessSource {
    public:
        Bytes bytes=Bytes(64*4096,std::byte{0x42});
        mutable std::vector<std::pair<std::uint64_t,std::size_t>> calls;
        bool short_read=false;
        std::optional<std::uint64_t> short_at_offset;
        std::uint64_t SizeBytes()const override{return bytes.size();}
        bool Read(std::uint64_t offset,std::size_t size,Bytes&out)const override{
            calls.emplace_back(offset,size);out.clear();
            if(offset>bytes.size()||size>bytes.size()-offset)return false;
            out.assign(bytes.begin()+offset,bytes.begin()+offset+size);
            if((short_read||short_at_offset==offset)&&!out.empty())out.pop_back();return true;
        }
    } source;
    for(const auto* failure:{"unchanged","first","middle","last","short","budget"}) {
        source.bytes.assign(64*4096,std::byte{0x42});source.short_read=false;source.calls.clear();
        auto budget=std::make_shared<ApfsReadBudget>(65536,256ull<<20,1000000,256ull<<20);
        BudgetedRandomAccessSource bounded(source,budget);SnapshotPlanningSource observation(bounded);
        Bytes actual;std::string error;
        for(std::uint64_t block=0;block<34;++block)
            Check(observation.Read(block*4096,4096,actual),"record original dependency bytes");
        Check(observation.Read(50*4096,4096,actual),"record disjoint dependency");
        source.calls.clear();const auto before=budget->Consumed();
        Check(observation.VerifyUnchanged(error)&&source.calls.size()==4,"35 exact dependencies use four fresh reads");
        const auto after=budget->Consumed();
        Check(after.read_bytes-before.read_bytes==35*4096,"dependency batching reads every byte and no gaps");
        Check(after.record_bytes-before.record_bytes==65536,"scratch reservation precedes first verification allocation");
        source.calls.clear();
        if(std::string_view(failure)=="unchanged") {
            Check(observation.VerifyUnchanged(error)&&source.calls.size()==4,"warm proof still reaches actual transport");
            Check(budget->Consumed().record_bytes==after.record_bytes,"warm verification reuses reserved scratch");
        } else {
            if(std::string_view(failure)=="short")source.short_read=true;
            else if(std::string_view(failure)=="budget")budget->LimitRemainingTo(0,0,0,0);
            else source.bytes[(std::string_view(failure)=="first"?0:std::string_view(failure)=="middle"?17:50)*4096+7]^=std::byte{1};
            Check(!observation.VerifyUnchanged(error)&&budget->Failed(),"fresh dependency change/refusal remains sticky");
            const auto count=source.calls.size();
            Check(!observation.VerifyUnchanged(error)&&source.calls.size()==count,"failed proof does no further I/O");
        }
        for(const auto&[offset,size]:source.calls)Check(size<=65536,"bounded verification transport request");
        Pass(std::string("batched actual dependency proof: ")+failure);
    }
    for(const bool field_first:{false,true})
    for(const auto* failure:{"unchanged","field-change","block-change","short","read-change"}) {
        source.bytes.assign(64*4096,std::byte{0x42});source.short_read=false;source.short_at_offset.reset();source.calls.clear();
        auto budget=std::make_shared<ApfsReadBudget>(65536,256ull<<20,1000000,256ull<<20);
        BudgetedRandomAccessSource bounded(source,budget);SnapshotPlanningSource observation(bounded);
        Bytes actual;std::string error;
        for(std::uint64_t i=0;i<18;++i) {
            const auto block=i==17?50:i;
            if(field_first)Check(observation.Read(block*4096+0x3E8,8,actual),"capture narrow APSB admission field first");
            Check(observation.Read(block*4096,4096,actual),"capture overlapping full APSB block");
            if(!field_first)Check(observation.Read(block*4096+0x3E8,8,actual),"capture narrow APSB admission field last");
        }
        source.calls.clear();const auto before=budget->Consumed();
        Check(observation.VerifyUnchanged(error)&&source.calls.size()==3,
            "overlapping APSB observations do not fragment contiguous verification batches");
        Check(source.calls[0]==std::pair<std::uint64_t,std::size_t>{0,65536}&&
            source.calls[1]==std::pair<std::uint64_t,std::size_t>{65536,4096}&&
            source.calls[2]==std::pair<std::uint64_t,std::size_t>{50*4096,4096},
            "overlap verification reads the exact bounded union without crossing a gap");
        const auto after=budget->Consumed();
        Check(after.read_bytes-before.read_bytes==18*4096&&after.reads-before.reads==3&&
            after.record_bytes-before.record_bytes==65536,"overlap batching charges every transport read and fixed scratch");
        source.calls.clear();
        Check(observation.Read(0x3E8,8,actual)&&source.calls.size()==1&&actual.size()==8,
            "repeated narrow source Read still reaches current transport");
        source.calls.clear();
        if(std::string_view(failure)=="unchanged") {
            Check(observation.VerifyUnchanged(error)&&source.calls.size()==3,
                "warm overlapping proof rereads every union batch");
            Check(budget->Consumed().record_bytes==after.record_bytes,"warm overlap proof reuses fixed scratch");
        } else {
            if(std::string_view(failure)=="short")source.short_at_offset=65536;
            else source.bytes[std::string_view(failure)=="block-change"?16*4096+7:0x3E8+4]^=std::byte{1};
            if(std::string_view(failure)=="read-change")
                Check(!observation.Read(0x3E8,8,actual)&&actual.empty()&&source.calls.size()==1,
                    "changed narrow Read is checked against freshly read bytes");
            else Check(!observation.VerifyUnchanged(error),"overlap byte change or short union read refuses");
            Check(budget->Failed()&&std::string_view(budget->Failure())=="AppleSnapshotPlanningSourceChanged",
                "overlap verification preserves the sticky source-change failure");
            if(std::string_view(failure)=="short")Check(source.calls.size()==2,"short second union batch is actually reached");
            const auto calls=source.calls.size();const auto failed=budget->Consumed();
            Check(!observation.VerifyUnchanged(error)&&!observation.Read(0x3E8,8,actual)&&actual.empty()&&
                source.calls.size()==calls,"failed overlap proof performs no further transport reads");
            const auto retry=budget->Consumed();
            Check(retry.reads==failed.reads&&retry.read_bytes==failed.read_bytes&&
                retry.records==failed.records&&retry.record_bytes==failed.record_bytes,
                "overlap failure cannot acquire a new read or materialization allowance");
        }
        for(const auto&[offset,size]:source.calls)Check(size<=65536,"overlap verification keeps bounded requests");
        Pass(std::string("overlap dependency proof ")+(field_first?"field-first: ":"block-first: ")+failure);
    }
    for(const auto* failure:{"unchanged","tail-change","short"}) {
        source.bytes.assign(64*4096,std::byte{0x42});source.short_read=false;source.short_at_offset.reset();source.calls.clear();
        auto budget=std::make_shared<ApfsReadBudget>(65536,256ull<<20,1000000,256ull<<20);
        BudgetedRandomAccessSource bounded(source,budget);SnapshotPlanningSource observation(bounded);
        Bytes actual;std::string error;
        Check(observation.Read(0,4096,actual)&&observation.Read(4092,4096,actual),"capture partially overlapping spans");
        source.calls.clear();
        Check(observation.VerifyUnchanged(error)&&source.calls.size()==1&&
            source.calls[0]==std::pair<std::uint64_t,std::size_t>{0,8188},
            "partial overlap extends verification through the complete second observation");
        source.calls.clear();
        if(std::string_view(failure)=="unchanged")
            Check(observation.VerifyUnchanged(error)&&source.calls.size()==1,"partial overlap still rereads its entire union");
        else {
            if(std::string_view(failure)=="short")source.short_at_offset=0;
            else source.bytes[8187]^=std::byte{1};
            Check(!observation.VerifyUnchanged(error)&&budget->Failed()&&source.calls.size()==1,
                "partial overlap tail change or short union read refuses");
            Check(!observation.VerifyUnchanged(error)&&source.calls.size()==1,"partial overlap refusal remains sticky");
        }
        Pass(std::string("partial overlap dependency proof: ")+failure);
    }
    for(const bool field_first:{false,true}) {
        source.bytes.assign(64*4096,std::byte{0x42});source.short_read=false;source.short_at_offset.reset();source.calls.clear();
        auto budget=std::make_shared<ApfsReadBudget>(65536,256ull<<20,1000000,256ull<<20);
        BudgetedRandomAccessSource bounded(source,budget);SnapshotPlanningSource observation(bounded);
        Bytes actual;std::string error;
        Check(observation.Read(field_first?0x3E8:0,field_first?8:4096,actual),"capture first overlapping observation");
        source.bytes[0x3E8]^=std::byte{1};
        Check(observation.Read(field_first?0:0x3E8,field_first?4096:8,actual),"capture different-sized current observation");
        source.bytes[0x3E8]^=std::byte{1};source.calls.clear();
        Check(!observation.VerifyUnchanged(error)&&source.calls.size()==1&&budget->Failed()&&
            error=="AppleSnapshotPlanningSourceChanged","batched union compares both conflicting captured observations");
        Check(!observation.VerifyUnchanged(error)&&source.calls.size()==1,"conflicting overlap failure stays sticky");
        Pass(field_first?"conflicting field-first observations refuse":"conflicting block-first observations refuse");
    }
    for(const auto* failure:{"unchanged","tail-change","tail-short"}) {
        source.bytes.assign(64*4096,std::byte{0x42});source.short_read=false;source.short_at_offset.reset();source.calls.clear();
        auto budget=std::make_shared<ApfsReadBudget>(65536,256ull<<20,1000000,256ull<<20);
        BudgetedRandomAccessSource bounded(source,budget);SnapshotPlanningSource observation(bounded);
        Bytes actual;std::string error;
        Check(observation.Read(0,131072,actual),"capture admitted multi-block object dependency");
        Check(observation.Read(0x3E8,8,actual)&&observation.Read(131064,8,actual),
            "capture contained admission fields in both oversized-object chunks");
        source.calls.clear();const auto before=budget->Consumed();
        Check(observation.VerifyUnchanged(error)&&source.calls.size()==2,"oversized dependency uses two bounded actual reads");
        Check(budget->Consumed().record_bytes-before.record_bytes==65536,"oversized object retains fixed-size scratch");
        for(const auto&[offset,size]:source.calls)Check(size<=65536,"no oversized verification transport request");
        source.calls.clear();
        if(std::string_view(failure)=="unchanged") {
            Check(observation.VerifyUnchanged(error)&&source.calls.size()==2,"oversized dependency still rereads both chunks");
        } else {
            if(std::string_view(failure)=="tail-change")source.bytes[131071]^=std::byte{1};
            else source.short_at_offset=65536;
            Check(!observation.VerifyUnchanged(error)&&budget->Failed()&&source.calls.size()==2,
                "last chunk change or short read cannot escape verification");
            Check(!observation.VerifyUnchanged(error)&&source.calls.size()==2,"oversized tail refusal remains sticky");
        }
        Pass(std::string("oversized dependency actual proof: ")+failure);
    }
}
class MemoryTarget final : public AppleCheckpointWriteTarget {
public:
    Bytes image;std::size_t operations=0,writes=0;std::optional<std::size_t> fail_at;
    explicit MemoryTarget(const Bytes& original):image(original){}
    bool ReadBlock(std::uint64_t block,std::uint32_t bs,Bytes& out) override {
        MutableFixtureSource source(image);return source.Read(block*bs,bs,out);
    }
    bool WriteBlock(std::uint64_t block,std::span<const std::byte> bytes) override {
        if(fail_at==operations++)return false;
        if(bytes.size()!=4096||block>=image.size()/4096)return false;
        std::copy(bytes.begin(),bytes.end(),image.begin()+block*4096);++writes;return true;
    }
    bool Flush() override{return fail_at!=operations++;}
};
void Preserved(const Fixture& before,const Bytes& after,const AppleSnapshotRetentionView& retained) {
    for(const auto block:retained.metadata_blocks)
        Check(std::equal(before.image.begin()+block*before.bs,before.image.begin()+(block+1)*before.bs,
            after.begin()+block*before.bs),"retained metadata bytes changed: "+std::to_string(block));
    for(const auto& extent:retained.payload_extents)
        Check(std::equal(before.image.begin()+extent.physical_block*before.bs,
            before.image.begin()+(extent.physical_block+extent.block_count)*before.bs,
            after.begin()+extent.physical_block*before.bs),"retained payload bytes changed");
    VectorRandomAccessSource source(after);std::string error;
    auto current=LoadAppleCheckpointView(source,0,source.SizeBytes(),error);
    Check(current.has_value(),"post-fault checkpoint: "+error);
    AppleSnapshotRetentionView result;
    Check(LoadAppleSnapshotRetention(source,*current,result,error),"post-fault ownership: "+error);
    Check(result.identities.size()==retained.identities.size(),"snapshot inventory retained");
    Check(result.identities.at(0).snapshot_xid==10 && result.identities.at(0).name_utf8=="backup","historical identity retained");
    Check(result.payload_extents.size()==retained.payload_extents.size(),"historical payload retained");
    std::shared_ptr<const NativeApfsSnapshotProjection> projection;
    Check(NativeApfsReader::TryLoadSnapshotProjection(source,result.identities[0],projection,error),"historical reader projection: "+error);
    const auto& extents=projection->View().read_extents_by_inode.at(30);
    Check(extents.size()==1,"one retained file mapping");Bytes historical;
    Check(source.Read(extents[0].physical_address,4096,historical),"read historical file through projected mapping");
    Check(historical==Bytes(4096,std::byte{0x53}),"historical file bytes remain unchanged");
}
using SnapshotBytes = std::vector<std::pair<std::uint64_t,std::byte>>;
void LifecycleState(const Bytes& image,const SnapshotBytes& snapshots,std::byte live_byte) {
    VectorRandomAccessSource source(image);std::string error;
    auto cp=LoadAppleCheckpointView(source,0,source.SizeBytes(),error);
    Check(cp.has_value(),"lifecycle reopen: "+error);
    AppleSnapshotRetentionView proof;
    Check(LoadAppleSnapshotRetention(source,*cp,proof,error),"lifecycle ownership: "+error);
    Check(proof.identities.size()==snapshots.size(),"reopened snapshot count");
    const auto& volume=cp->volumes[0];Bytes apsb,omap;
    Check(source.Read(volume.superblock_object.physical_block*4096,4096,apsb)&&
        source.Read(volume.object_map.object.physical_block*4096,4096,omap),"reopen counters");
    Check(ReadU64LE(apsb,0xD8).value()==snapshots.size()&&ReadU32LE(omap,0x24).value()==snapshots.size(),"exact APSB and OMAP snapshot counters");
    Check(ReadU64LE(omap,0x40).value()==(snapshots.empty()?0:snapshots.back().first),"exact most recent snapshot XID");
    for(std::size_t i=0;i<snapshots.size();++i){
        Check(proof.identities[i].snapshot_xid==snapshots[i].first,"stable historical view XID");
        std::shared_ptr<const NativeApfsSnapshotProjection> projection;
        Check(NativeApfsReader::TryLoadSnapshotProjection(source,proof.identities[i],projection,error),"reopen historical projection: "+error);
        const auto& extents=projection->View().read_extents_by_inode.at(30);Bytes bytes;
        Check(extents.size()==1&&source.Read(extents[0].physical_address,4096,bytes)&&bytes==Bytes(4096,snapshots[i].second),"surviving snapshot bytes unchanged");
    }
    std::vector<apfsaccess::catalog::BtreeRecord> fs;
    Check(ReadAppleVolumeFileSystemRecords(source,cp->container,volume,fs,error),"reopen live namespace: "+error);
    auto found=std::find_if(fs.begin(),fs.end(),[](const auto& r){return ReadU64LE(r.key,0).value_or(0)>>60==8;});
    AppleFileExtentRecord extent;Bytes payload;
    Check(found!=fs.end()&&DecodeAppleFileExtentRecord(*found,4096,extent,error)&&
        source.Read(extent.physical_block*4096,4096,payload)&&payload==Bytes(4096,live_byte),"exact reopened live bytes");
    const auto& chunk=cp->spaceman.chunks[0];
    Check((std::to_integer<unsigned>(chunk.allocation_bitmap[extent.physical_block/8])&(1u<<(extent.physical_block%8)))!=0,"live payload is allocated");
    for(const auto& q:cp->spaceman.free_queues[1].entries)
        Check(!(q.physical_block<=extent.physical_block&&extent.physical_block-q.physical_block<q.block_count),"live payload never queued");
}
Bytes LifecyclePublish(const Bytes& before,const AppleCheckpointPublicationPlan& plan,
    const SnapshotBytes& old_snapshots,std::byte old_live,const SnapshotBytes& new_snapshots,std::byte new_live,const std::string& label) {
    std::string error;MemoryTarget success(before);
    Check(ExecuteAppleCheckpointPublication(success,plan,error),label+" publishes: "+error);
    LifecycleState(success.image,new_snapshots,new_live);
    const auto save=[&](const std::string& suffix,const Bytes& image){std::ofstream file(label+suffix+".img",std::ios::binary);
        file.write(reinterpret_cast<const char*>(image.data()),image.size());Check(file.good(),"preserve lifecycle image");};
    save("",success.image);
    VectorRandomAccessSource completed(success.image);auto cp=LoadAppleCheckpointView(completed,0,completed.SizeBytes(),error);
    const auto new_xid=cp->container.superblock.xid;
    const auto verify=[&](const Bytes& image){VectorRandomAccessSource src(image);auto selected=LoadAppleCheckpointView(src,0,src.SizeBytes(),error);
        Check(selected.has_value(),"fault selects a checkpoint");const bool newer=selected->container.superblock.xid==new_xid;
        Check(newer||selected->container.superblock.next_xid==new_xid,"fault selects exactly old or new checkpoint");
        LifecycleState(image,newer?new_snapshots:old_snapshots,newer?new_live:old_live);return selected->container.superblock.xid;};
    for(std::size_t n=0;n<success.operations;++n){MemoryTarget failed(before);failed.fail_at=n;
        Check(!ExecuteAppleCheckpointPublication(failed,plan,error),"failed publication never acknowledged");
        const auto failure=error;const auto selected=verify(failed.image);save("-fault-"+std::to_string(n),failed.image);
        std::cout<<label<<" WRITE/FLUSH "<<n<<" refusal="<<failure<<" reopened="<<selected<<" PASS\n";
    }
    for(const auto* stage:{"before-apple-device-write","before-apple-prepublication-flush","before-apple-checkpoint-switch","before-apple-final-flush"}){
        MemoryTarget failed(before);Check(!ExecuteAppleCheckpointPublication(failed,plan,error,[&](std::string_view at){return at!=stage;}),"lifecycle stage failure");
        const auto selected=verify(failed.image);save(std::string("-")+stage,failed.image);std::cout<<label<<" STAGE "<<stage<<" reopened="<<selected<<" PASS\n";
    }
    MemoryTarget stale(success.image);const auto stale_image=stale.image;
    Check(!ExecuteAppleCheckpointPublication(stale,plan,error)&&stale.writes==0&&stale.image==stale_image,"stale publication refuses before writes");
    std::cout<<label<<" FAILURE POSITIONS "<<success.operations<<" plus 4 stages PASS\n";
    return success.image;
}
void DeleteLifecycle(const Bytes& after_cow) {
    std::string error;VectorRandomAccessSource before(after_cow);auto cp=LoadAppleCheckpointView(before,0,before.SizeBytes(),error);
    AppleSnapshotCreateRequest create;create.volume_object_id=101;create.name_utf8="survivor";create.creation_time_ns=1700000000000000001ull;
    create.required_checkpoint_xids={21}; // an actual snapshot-bearing recovery pin
    AppleSnapshotCreatePlan second;
    const bool second_planned=PlanAppleSnapshotCreate(before,*cp,create,second,error);
    Check(second_planned,"second create plan: "+error);
    auto two=LifecyclePublish(after_cow,second.commit.publication,{{21,std::byte{0x53}}},std::byte{0x4D},
        {{21,std::byte{0x53}},{23,std::byte{0x4D}}},std::byte{0x4D},"lifecycle-second-create");
    VectorRandomAccessSource two_source(two);cp=LoadAppleCheckpointView(two_source,0,two_source.SizeBytes(),error);
    AppleVolumeTransactionRequest mutate;mutate.volume_object_id=101;
    Check(ReadAppleVolumeFileSystemRecords(two_source,cp->container,cp->volumes[0],mutate.filesystem_records,error),"second COW source");
    for(const auto& r:mutate.filesystem_records)if(ReadU64LE(r.key,0).value_or(0)>>60==8){AppleFileExtentRecord p;
        Check(DecodeAppleFileExtentRecord(r,4096,p,error),"decode second COW release");mutate.released_data_blocks.push_back({p.physical_block,1});}
    std::erase_if(mutate.filesystem_records,[](const auto& r){return ReadU64LE(r.key,0).value_or(0)>>60==8;});
    mutate.data_writes.push_back({30,0,0,Bytes(4096,std::byte{0x58})});AppleVolumeTransactionPlan live;
    Check(PlanAppleSnapshotLiveTransaction(two_source,*cp,mutate,live,error),"second live COW plan: "+error);
    auto changed=LifecyclePublish(two,live.commit.publication,{{21,std::byte{0x53}},{23,std::byte{0x4D}}},std::byte{0x4D},
        {{21,std::byte{0x53}},{23,std::byte{0x4D}}},std::byte{0x58},"lifecycle-second-cow");
    VectorRandomAccessSource current(changed);cp=LoadAppleCheckpointView(current,0,current.SizeBytes(),error);
    AppleSnapshotRetentionView retained;Check(LoadAppleSnapshotRetention(current,*cp,retained,error),"delete source census");
    std::vector<AppleRecoveryCheckpointView> snapshot_pins;
    const bool recovered=LoadAppleSnapshotRecoveryCheckpoints(current,*cp,{23},snapshot_pins,error);
    Check(recovered,"snapshot-aware recovery checkpoint 23 at 24: "+error);
    Check(snapshot_pins.size()==1,"recovery returns the requested checkpoint only");
    const auto exact_pin=LoadAppleCheckpointView(current,0,current.SizeBytes(),error,23);
    Check(exact_pin&&snapshot_pins[0].checkpoint.container.superblock.xid==23&&
        exact_pin->volumes.size()==1&&snapshot_pins[0].checkpoint.volumes[0].superblock.object_id==exact_pin->volumes[0].superblock.object_id,
        "recovery pin matches an independently loaded exact checkpoint");
    Check(retained.identities.size()==2&&retained.identities[0].snapshot_xid==21&&retained.identities[1].snapshot_xid==23,
        "exact two historical views for recovery coverage");
    std::vector<ApplePhysicalExtentRecord> expected_extents;
    for(const auto& id:retained.identities){
        std::shared_ptr<const NativeApfsSnapshotProjection> projection;
        const bool projected=NativeApfsReader::TryLoadSnapshotProjection(current,id,projection,error);
        Check(projected,"independent historical payload projection: "+error);
        Check(projection&&projection->View().read_extents_by_inode.at(30).size()==1,"one historical fixture extent");
        for(const auto& extent:projection->View().read_extents_by_inode.at(30)){
            Check(extent.physical_address>0&&extent.physical_address%4096==0&&extent.bytes==4096,"aligned positive historical payload");
            expected_extents.push_back({extent.physical_address/4096,extent.bytes/4096});
        }
    }
    std::vector<apfsaccess::catalog::BtreeRecord> pinned_fs;
    Check(ReadAppleVolumeFileSystemRecords(current,exact_pin->container,
        exact_pin->volumes[0],pinned_fs,error),"independent pinned live payload projection");
    for(const auto& record:pinned_fs)if(ReadU64LE(record.key,0).value_or(0)>>60==8){
        AppleFileExtentRecord extent;
        Check(DecodeAppleFileExtentRecord(record,4096,extent,error)&&extent.length_bytes==4096&&
            extent.physical_block==expected_extents[1].physical_block&&extent.physical_block!=220,"pinned live inherits the second historical payload");
        expected_extents.push_back({extent.physical_block,extent.length_bytes/4096});
    }
    Check(expected_extents.size()==3,"both historical extents and pinned live coverage are present");
    const auto payload_blocks=[&](const auto& extents){
        std::set<std::uint64_t> blocks;
        for(const auto& extent:extents){
            Check(extent.physical_block>0&&extent.physical_block<current.SizeBytes()/4096&&
                extent.block_count>0&&extent.block_count<=current.SizeBytes()/4096-extent.physical_block,"bounded physical ownership range");
            for(std::uint64_t offset=0;offset<extent.block_count;++offset){
                blocks.insert(extent.physical_block+offset);
            }
        }
        return blocks;
    };
    const auto expected_payload=payload_blocks(expected_extents);
    Check(expected_payload.size()==2&&payload_blocks(snapshot_pins[0].payload_extents)==expected_payload,
        "recovery covers both historical payloads without inflating the inherited live owner");
    for(const auto& id:retained.identities)Check(std::binary_search(snapshot_pins[0].metadata_blocks.begin(),snapshot_pins[0].metadata_blocks.end(),id.superblock_physical_block),
        "recovery pin includes snapshot APSB ownership");
    for(const auto invalid:{0ull,25ull})Check(!LoadAppleSnapshotRecoveryCheckpoints(current,*cp,{invalid},snapshot_pins,error)&&snapshot_pins.empty(),
        "invalid snapshot recovery XID clears output");
    auto recovery_budget=std::make_shared<ApfsReadBudget>(1,4096,1000000,256ull<<20);
    BudgetedRandomAccessSource recovery_limited(current,recovery_budget);
    Check(!LoadAppleSnapshotRecoveryCheckpoints(recovery_limited,*cp,{23},snapshot_pins,error)&&recovery_budget->Failed()&&snapshot_pins.empty(),
        "snapshot recovery shares a sticky bounded budget");
    AppleSnapshotDeleteRequest request;request.expected=retained.identities[0];request.modification_time_ns=create.creation_time_ns+1;
    AppleSnapshotDeletePlan deletion;
    Check(PlanAppleSnapshotDelete(current,*cp,request,deletion,error),"actual deletion plan: "+error);
    Check(deletion.released_payload_blocks==0&&deletion.surviving.size()==1,
        "oldest deletion retains payload owned by historical OMAP and survivor inventory");
    // Reconstruct the typed composer request from the planner's exact writes,
    // then corrupt its claimed operation. Neither path may leak a plan.
    AppleTransactionCommitRequest forged;forged.allocation_plan=deletion.allocation;
    forged.next_object_id=deletion.commit.publication.published_checkpoint.superblock.next_oid;
    forged.container_object_map_oid=deletion.commit.publication.published_checkpoint.superblock.omap_oid;
    for(const auto& w:deletion.commit.publication.before_superblock_writes)
        if(std::find(deletion.allocation.allocated_main_blocks.begin(),deletion.allocation.allocated_main_blocks.end(),w.physical_block)!=deletion.allocation.allocated_main_blocks.end())
            forged.allocated_main_writes.push_back({w.physical_block,w.bytes});
    AppleSnapshotInventoryChange invalid_change;AppleTransactionCommitPlan refused;
    Check(!PlanAppleSnapshotInventoryCommit(current,*cp,forged,invalid_change,refused,error)&&refused.publication.before_superblock_writes.empty(),
        "typed composer refuses missing inventory operation");
    invalid_change.removed=request.expected;invalid_change.created=request.expected;
    Check(!PlanAppleSnapshotInventoryCommit(current,*cp,forged,invalid_change,refused,error)&&refused.publication.before_superblock_writes.empty(),
        "typed composer refuses contradictory inventory operation");
    invalid_change.created.reset();invalid_change.removed->name_utf8="mismatch";
    Check(!PlanAppleSnapshotInventoryCommit(current,*cp,forged,invalid_change,refused,error)&&refused.publication.before_superblock_writes.empty(),
        "typed composer independently rechecks exact deletion identity");
    Check(deletion.surviving[0].snapshot_xid==23&&deletion.surviving[0].superblock_physical_block!=retained.identities[1].superblock_physical_block,
        "survivor metadata COW preserves view XID");
    AppleSnapshotRetirementProof retirement;
    Check(ProveAppleSnapshotRetirement(current,*cp,deletion.commit.publication,101,
        request.required_checkpoint_xids,retirement,error),"independent deletion retirement proof: "+error);
    Check(retirement.retired_volume_payload_blocks==0,"historical payload with a surviving owner is not retired");
    auto deleted=LifecyclePublish(changed,deletion.commit.publication,{{21,std::byte{0x53}},{23,std::byte{0x4D}}},std::byte{0x58},
        {{23,std::byte{0x4D}}},std::byte{0x58},"lifecycle-delete-oldest");
    for(const auto b:retained.metadata_blocks)Check(std::equal(changed.begin()+b*4096,changed.begin()+(b+1)*4096,deleted.begin()+b*4096),"old snapshot metadata byte exact after delete");
    VectorRandomAccessSource reopened(deleted);auto after=LoadAppleCheckpointView(reopened,0,reopened.SizeBytes(),error);
    const auto before_owners=ReadFixtureOwners(current,*cp),after_owners=ReadFixtureOwners(reopened,*after);
    std::vector<std::uint64_t> added_metadata,removed_metadata;
    std::set_difference(after_owners.metadata.begin(),after_owners.metadata.end(),before_owners.metadata.begin(),before_owners.metadata.end(),
        std::back_inserter(added_metadata));
    std::set_difference(before_owners.metadata.begin(),before_owners.metadata.end(),after_owners.metadata.begin(),after_owners.metadata.end(),
        std::back_inserter(removed_metadata));
    auto charged_added=added_metadata,charged_removed=removed_metadata;
    // A live APSB is referenced by the container OMAP. Physical snapshot
    // descriptors remain in the volume's ownership and in these charged sets.
    for(const auto& volume:after->volumes)std::erase(charged_added,volume.superblock_object.physical_block);
    for(const auto& volume:cp->volumes)std::erase(charged_removed,volume.superblock_object.physical_block);
    Check(!removed_metadata.empty()&&retirement.allocated_volume_blocks==charged_added.size()&&
        retirement.retired_volume_blocks==charged_removed.size(),"exact volume metadata charge excludes only container OMAP APSBs");
    const auto released=[&](std::uint64_t block){return std::any_of(retirement.releases.begin(),retirement.releases.end(),
        [&](const auto& range){return block>=range.physical_block&&block-range.physical_block<range.block_count;});};
    for(const auto block:removed_metadata)Check(released(block),"all retired metadata has an exact physical release, including live APSB");
    Check(before_owners.payload==after_owners.payload,"oldest deletion preserves every historical and live payload owner");
    for(const auto b:removed_metadata){
        Check(std::any_of(after->spaceman.free_queues[1].entries.begin(),after->spaceman.free_queues[1].entries.end(),
            [&](const auto& r){return r.physical_block<=b&&b-r.physical_block<r.block_count&&r.xid==25;}),"removed metadata queued at exact deletion XID");
        Check((std::to_integer<unsigned>(after->spaceman.chunks[0].allocation_bitmap[b/8])&(1u<<(b%8)))!=0&&
            std::equal(changed.begin()+b*4096,changed.begin()+(b+1)*4096,deleted.begin()+b*4096),
            "retired metadata remains allocated and byte exact before queue maturity");
    }
    for(const auto b:retained.metadata_blocks)
        Check((std::to_integer<unsigned>(after->spaceman.chunks[0].allocation_bitmap[b/8])&(1u<<(b%8)))!=0,
            "queued old metadata remains allocated until checkpoint retention permits reclamation");
    const bool recover_deleted=LoadAppleSnapshotRecoveryCheckpoints(reopened,*after,{24},snapshot_pins,error);
    Check(recover_deleted,"snapshot pin survives queued delete until actual reclamation: "+error);
    Check(snapshot_pins.size()==1,"previous checkpoint snapshot owners retained in recovery proof");
    Bytes old_apsb,new_apsb;
    Check(current.Read(cp->volumes[0].superblock_object.physical_block*4096,4096,old_apsb)&&
        reopened.Read(after->volumes[0].superblock_object.physical_block*4096,4096,new_apsb),"read deletion accounting");
    Check(ReadU64LE(new_apsb,0x58).value()==ReadU64LE(old_apsb,0x58).value()+
        retirement.allocated_volume_blocks-retirement.retired_volume_blocks,"precise charged blocks delta");
    Check(ReadU64LE(new_apsb,0xE0).value()==ReadU64LE(old_apsb,0xE0).value()+retirement.allocated_volume_blocks&&
        ReadU64LE(new_apsb,0xE8).value()==ReadU64LE(old_apsb,0xE8).value()+retirement.retired_volume_blocks,
        "precise lifetime allocation/free counters include proven metadata retirement");
    Check(std::none_of(after->spaceman.free_queues[1].entries.begin(),after->spaceman.free_queues[1].entries.end(),
        [](const auto& r){return r.physical_block<=220&&220-r.physical_block<r.block_count;}),
        "historically owned payload is never placed on a free queue");
    Check((std::to_integer<unsigned>(after->spaceman.chunks[0].allocation_bitmap[220/8])&(1u<<(220%8)))!=0,
        "historical OMAP payload stays allocated after public snapshot removal");
    ApfsSnapshotRecords records;
    auto stale_survivor=retained.identities[1];stale_survivor.scope.checkpoint_xid=25;
    Check(!ApfsSnapshotStore::LoadExactRecords(reopened,stale_survivor,records,error),"old physical identity cannot silently rebind to COW metadata");
    Check(ApfsSnapshotStore::LoadExactResolvedRecords(reopened,deletion.surviving[0],records,error),"returned survivor identity reopens exactly: "+error);
    AppleSnapshotDeletePlan rejected=deletion;
    Check(!PlanAppleSnapshotDelete(reopened,*after,request,rejected,error)&&rejected.commit.publication.before_superblock_writes.empty(),"stale delete request clears output");
    for(int field=0;field<6;++field){auto mismatch=request;
        if(field==0)mismatch.expected.name_utf8="wrong";if(field==1)++mismatch.expected.snapshot_xid;
        if(field==2)++mismatch.expected.root_physical_block;if(field==3)++mismatch.expected.superblock_physical_block;
        if(field==4)++mismatch.expected.scope.volume_oid;if(field==5)++mismatch.expected.extentref_physical_block;
        Check(!PlanAppleSnapshotDelete(current,*cp,mismatch,rejected,error)&&rejected.allocation.allocated_main_blocks.empty(),"mismatched delete has no allocation");}
    auto pinned=request;pinned.required_checkpoint_xids={23};
    const bool pin_delete=PlanAppleSnapshotDelete(current,*cp,pinned,rejected,error);
    Check(!pin_delete&&error=="AppleSnapshotDeleteRecoveryOwner",
        "snapshot-bearing pin vetoes queuing its payload: "+error);
    auto budget=std::make_shared<ApfsReadBudget>(1,4096,1000000,256ull<<20);BudgetedRandomAccessSource limited(current,budget);
    Check(!PlanAppleSnapshotDelete(limited,*cp,request,rejected,error)&&budget->Failed()&&rejected.surviving.empty(),"delete shared budget refuses atomically");
    // Deleting the newest snapshot must move most_recent_snap backwards while
    // retaining the oldest view and rebasing the live layer against it.
    auto newest=request;newest.expected=retained.identities[1];AppleSnapshotDeletePlan newest_plan;
    const bool newest_planned=PlanAppleSnapshotDelete(current,*cp,newest,newest_plan,error);
    Check(newest_planned,"newest snapshot deletion plan: "+error);
    Check(newest_plan.released_payload_blocks==1&&newest_plan.surviving.size()==1&&newest_plan.surviving[0].snapshot_xid==21,
        "newest deletion retires its last payload owner and identifies the older survivor");
    LifecyclePublish(changed,newest_plan.commit.publication,{{21,std::byte{0x53}},{23,std::byte{0x4D}}},std::byte{0x58},
        {{21,std::byte{0x53}}},std::byte{0x58},"lifecycle-delete-newest");
    // A second deletion consumes the COW-replaced survivor identity, removes
    // the final OMAP inventory root and restores an ordinary NEW live layer.
    AppleSnapshotDeleteRequest last;last.expected=deletion.surviving[0];last.modification_time_ns=request.modification_time_ns+1;
    AppleSnapshotDeletePlan final;
    Check(PlanAppleSnapshotDelete(reopened,*after,last,final,error),"final actual deletion plan: "+error);
    Check(final.surviving.empty(),"final deletion removes the last public snapshot");
    auto final_image=LifecyclePublish(deleted,final.commit.publication,{{23,std::byte{0x4D}}},std::byte{0x58},{},std::byte{0x58},"lifecycle-delete-final");
    VectorRandomAccessSource final_source(final_image);auto final_cp=LoadAppleCheckpointView(final_source,0,final_source.SizeBytes(),error);
    std::vector<std::uint64_t> prior_metadata,final_metadata;
    std::vector<ApplePhysicalExtentRecord> prior_payload,final_payload;
    Check(LoadAppleSnapshotCheckpointOwners(reopened,*after,prior_metadata,prior_payload,error)&&
        LoadAppleSnapshotCheckpointOwners(final_source,*final_cp,final_metadata,final_payload,error),
        "independent before/after serialized ownership census for final deletion");
    const auto raw_prior=ReadFixtureOwners(reopened,*after),raw_final=ReadFixtureOwners(final_source,*final_cp);
    const auto& prior_blocks=raw_prior.payload;const auto& final_blocks=raw_final.payload;
    Check(prior_blocks==payload_blocks(prior_payload)&&final_blocks==payload_blocks(final_payload),
        "production owner census agrees with independent serialized fixture traversal");
    std::vector<std::uint64_t> retired_payload;
    std::set_difference(prior_blocks.begin(),prior_blocks.end(),final_blocks.begin(),final_blocks.end(),
        std::back_inserter(retired_payload));
    Check(final.released_payload_blocks==retired_payload.size(),
        "final payload retirement equals physical owners absent from the serialized after graph");
    Check(prior_blocks.size()==3&&final_blocks.size()==1&&retired_payload.size()==2&&
        std::find(retired_payload.begin(),retired_payload.end(),220)!=retired_payload.end(),
        "final deletion retires both historical payloads and preserves the unique live payload");
    Check(final_cp->volumes[0].object_map.snapshot_tree_oid==0,"final delete removes OMAP snapshot root");
    Check(std::any_of(final_cp->spaceman.free_queues[1].entries.begin(),final_cp->spaceman.free_queues[1].entries.end(),
        [](const auto& r){return r.physical_block<=220&&220-r.physical_block<r.block_count&&r.xid==26;}),
        "last historical owner removal queues the payload at the final deletion XID");
    Check((std::to_integer<unsigned>(final_cp->spaceman.chunks[0].allocation_bitmap[220/8])&(1u<<(220%8)))!=0,
        "newly retired payload remains physically allocated through the retention floor");
    Check(!LoadAppleSnapshotRecoveryCheckpoints(final_source,*final_cp,{23},snapshot_pins,error)&&snapshot_pins.empty(),
        "reclaimed historical snapshot pin refuses with cleared result");
    std::cout<<"SNAPSHOT RECOVERY RECLAIM REFUSAL "<<error<<'\n';
    AppleSpacemanAllocationRequest reuse;reuse.expected_checkpoint_xid=final_cp->container.superblock.xid;
    reuse.transaction_xid=final_cp->container.superblock.next_xid;reuse.oldest_required_checkpoint_xid=reuse.expected_checkpoint_xid;
    reuse.first_ephemeral_object_id=final_cp->container.superblock.next_oid;reuse.main_block_count=final_cp->spaceman.devices[0].free_count;
    AppleSpacemanAllocationPlan reclaimed;
    Check(PlanAppleSpacemanAllocation(final_cp->spaceman,reuse,reclaimed,error),"canonical reuse plan after retirement: "+error);
    Check(std::find(reclaimed.allocated_main_blocks.begin(),reclaimed.allocated_main_blocks.end(),220)!=reclaimed.allocated_main_blocks.end(),
        "subsequent canonical allocator plan can reuse unowned payload at its proven queue floor");
    Pass("actual create live COW create live COW delete survivor delete final reopen lifecycle");
}

Bytes CatalogProofOnceImage() {
    Fixture fixture(16,32);
    fixture.PrepareLivePayloadForFirstCreate();
    fixture.AddEmptySibling();
    VectorRandomAccessSource source(fixture.image);
    AppleSnapshotCreateRequest request{101,"catalog-proof",1700000000000000000ull};
    AppleSnapshotCreatePlan plan;std::string error;
    Check(PlanAppleSnapshotCreate(source,fixture.checkpoint,request,plan,error),"catalog proof snapshot fixture: "+error);
    MemoryTarget target(fixture.image);
    Check(ExecuteAppleCheckpointPublication(target,plan.commit.publication,error),"catalog proof fixture publication: "+error);
    return target.image;
}
AppleVolumeTransactionRequest CatalogProofAtime(const RandomAccessSource& source,
    const AppleCheckpointView& checkpoint,std::uint64_t oid) {
    const auto volume=std::find_if(checkpoint.volumes.begin(),checkpoint.volumes.end(),
        [&](const auto& item){return item.superblock.object_id==oid;});
    Check(volume!=checkpoint.volumes.end(),"catalog proof selected volume exists");
    AppleVolumeTransactionRequest request;request.volume_object_id=oid;
    request.required_checkpoint_xids={checkpoint.container.superblock.xid};
    std::string error;
    Check(ReadAppleVolumeFileSystemRecords(source,checkpoint.container,*volume,request.filesystem_records,error),
        "catalog proof root records: "+error);
    bool changed=false;
    for(auto& record:request.filesystem_records) {
        if(ReadU64LE(record.key,0).value_or(0)!=((3ull<<60)|2))continue;
        AppleInodeRecord inode;
        Check(ApfsExtendedRecordCodec::DecodeInode(record,inode,error),"decode root atime");
        ++inode.access_time;
        Check(EncodeAppleInodeRecord(inode,record,error),"encode root atime");changed=true;
    }
    Check(changed,"ordinary selected root atime actually changes");return request;
}
void CatalogProofOnceBudgetTests(std::uint64_t selected=0) {
    for(const auto oid:{101ull,102ull}) {
        if(selected&&oid!=selected)continue;
        auto image=CatalogProofOnceImage();const auto original=image;
        VectorRandomAccessSource initial(image);std::string error;
        const auto checkpoint=LoadAppleCheckpointView(initial,0,initial.SizeBytes(),error);
        Check(checkpoint&&checkpoint->container.superblock.xid==21&&checkpoint->volumes.size()==2,
            "two-volume snapshot-bearing CP21 fixture: "+error);
        const auto owners=ReadFixtureOwners(initial,*checkpoint);
        auto request=CatalogProofAtime(initial,*checkpoint,oid);
        MutableFixtureSource source(image);
        auto budget=std::make_shared<ApfsReadBudget>(2420,256ull<<20,1000000,256ull<<20);
        BudgetedRandomAccessSource bounded(source,budget);AppleVolumeTransactionPlan plan;
        const bool planned=oid==101
            ? PlanAppleSnapshotLiveTransaction(bounded,*checkpoint,request,plan,error)
            : PlanAppleSnapshotSiblingTransaction(bounded,*checkpoint,request,plan,error);
        const auto used=budget->Consumed();
        std::cout<<"CATALOG_PROOF_ONCE oid="<<oid<<" planned="<<planned<<" reads="<<used.reads
            <<" bytes="<<used.read_bytes<<" records="<<used.records<<" materialized="<<used.record_bytes<<" error="<<error<<'\n';
        Check(image==original,"bounded planning preserves every source byte");
        Check(planned,"ordinary two-volume atime fits 2420 original transport reads: "+error);
        Check(!budget->Failed()&&used.reads>0&&used.reads<=2420&&source.read_count==used.reads,
            "one shared read cap accounts for every actual transport read");
        MemoryTarget target(image);
        Check(ExecuteAppleCheckpointPublication(target,plan.commit.publication,error)&&target.writes>0,
            "bounded plan actually publishes in memory: "+error);
        VectorRandomAccessSource published(target.image);
        const auto after=LoadAppleCheckpointView(published,0,published.SizeBytes(),error);
        Check(after&&after->container.superblock.xid==checkpoint->container.superblock.next_xid,
            "fresh checkpoint reopen selects exact P+1");
        const auto same_records=[](const auto& a,const auto& b){return a.size()==b.size()&&
            std::equal(a.begin(),a.end(),b.begin(),[](const auto& x,const auto& y){return x.key==y.key&&x.value==y.value;});};
        for(std::size_t i=0;i<checkpoint->volumes.size();++i) {
            std::vector<apfsaccess::catalog::BtreeRecord> before_records,after_records;
            Check(ReadAppleVolumeFileSystemRecords(initial,checkpoint->container,checkpoint->volumes[i],before_records,error)&&
                ReadAppleVolumeFileSystemRecords(published,after->container,after->volumes[i],after_records,error),
                "fresh selected and sibling filesystem records");
            Check(same_records(after_records,checkpoint->volumes[i].superblock.object_id==oid?request.filesystem_records:before_records),
                "only selected atime changes; peer records remain byte exact");
        }
        std::vector<AppleRecoveryCheckpointView> recovery;
        Check(LoadAppleSnapshotRecoveryCheckpoints(published,*after,request.required_checkpoint_xids,recovery,error)&&
            recovery.size()==1&&recovery[0].checkpoint.container.superblock.xid==21,
            "fresh accepted-preimage recovery includes the exact original owner checkpoint: "+error);
        for(const auto block:owners.metadata) {
            Check(std::binary_search(recovery[0].metadata_blocks.begin(),recovery[0].metadata_blocks.end(),block),
                "recovery proof retains each independently serialized metadata owner");
            Check(std::equal(original.begin()+block*4096,original.begin()+(block+1)*4096,target.image.begin()+block*4096),
                "accepted-preimage metadata bytes survive publication");
        }
        for(const auto block:owners.payload)Check(std::any_of(recovery[0].payload_extents.begin(),recovery[0].payload_extents.end(),
            [&](const auto& extent){return extent.physical_block<=block&&block-extent.physical_block<extent.block_count;}),
            "recovery proof retains each independently serialized payload owner");
        LifecycleState(target.image,{{21,std::byte{0x53}}},std::byte{0x53});
        Pass("catalog proof-once 2420-read publication and fresh recovery ownership: "+std::to_string(oid));
    }
}
void CatalogProofOncePreimageTests() {
    for(const std::string_view kind:{"source","overlay"}) {
        auto image=CatalogProofOnceImage();VectorRandomAccessSource initial(image);std::string error;
        const auto checkpoint=LoadAppleCheckpointView(initial,0,initial.SizeBytes(),error);
        Check(checkpoint.has_value(),"preimage checkpoint");
        const auto request=CatalogProofAtime(initial,*checkpoint,101);AppleVolumeTransactionPlan plan;
        Check(PlanAppleSnapshotLiveTransaction(initial,*checkpoint,request,plan,error),"preimage real staged publication: "+error);
        SnapshotPublicationSource staged(initial,plan.commit.publication);
        const auto next=LoadAppleCheckpointView(staged,0,staged.SizeBytes(),error);
        Check(next.has_value(),"preimage staged checkpoint");
        AppleSnapshotCatalogRecords catalog;
        Check(LoadAppleSnapshotCatalog(staged,*next,101,catalog,error)&&!catalog.metadata_blocks.empty(),
            "independent complete staged catalog footprint");
        const auto& volume=next->volumes[0];const auto root_block=volume.root_tree.physical_block;
        std::vector<Bytes> keys,values;
        for(auto record:catalog.live.filesystem) {
            if(ReadU64LE(record.key,0).value_or(0)==((3ull<<60)|2)) {
                AppleInodeRecord inode;Check(ApfsExtendedRecordCodec::DecodeInode(record,inode,error),"decode overlay root");
                inode.access_time+=17;Check(EncodeAppleInodeRecord(inode,record,error),"encode overlay root");
            }
            keys.push_back(record.key);values.push_back(record.value);
        }
        const auto replacement=BuildRawLeafNode(keys,values,next->container.superblock.xid,4096,0,
            volume.root_tree.object_id,kObjectTypeBtree,kObjectTypeFsTree);
        const auto original=image;MutableFixtureSource source(image);
        std::size_t position=0,completed=0;bool armed=false,mutated=false;
        // Wait for a complete catalog capture, then change admitted bytes while
        // its borrowed records are in flight, before graph authority returns.
        source.after_read=[&](std::uint64_t offset,std::size_t size) {
            if(mutated)return;
            if(armed&&offset==root_block*4096&&size==4096) {
                if(kind=="overlay") {
                    auto write=std::find_if(plan.commit.publication.before_superblock_writes.begin(),
                        plan.commit.publication.before_superblock_writes.end(),[&](const auto& item){return item.physical_block==root_block;});
                    Check(write!=plan.commit.publication.before_superblock_writes.end(),"actual staged root write exists");
                    write->bytes=replacement;
                } else image[checkpoint->volumes[0].root_tree.physical_block*4096+0x30]^=std::byte{1};
                mutated=true;return;
            }
            if(size==4096&&position<catalog.metadata_blocks.size()&&offset==catalog.metadata_blocks[position]*4096)++position;
            else position=size==4096&&offset==catalog.metadata_blocks.front()*4096?1:0;
            if(position==catalog.metadata_blocks.size()){++completed;armed=true;position=0;}
        };
        auto budget=std::make_shared<ApfsReadBudget>(65536,256ull<<20,1000000,256ull<<20);
        BudgetedRandomAccessSource bounded(source,budget);SnapshotPlanningSource observation(bounded);
        AppleSnapshotRetirementProof proof;
        proof.releases.push_back({499,1});proof.source_metadata_blocks.push_back(499);proof.source_owned_blocks.push_back({499,1});
        proof.allocated_volume_blocks=proof.retired_volume_blocks=proof.retired_volume_payload_blocks=1;
        const bool proved=ProveAppleSnapshotRetirement(observation,*checkpoint,plan.commit.publication,101,
            request.required_checkpoint_xids,proof,error);
        std::cout<<"CATALOG_PREIMAGE kind="<<kind<<" completed="<<completed<<" mutated="<<mutated<<" proved="<<proved<<" error="<<error<<'\n';
        Check(completed>0&&mutated,"injection follows full canonical capture and precedes graph completion");
        Check(!proved&&proof.releases.empty()&&proof.source_metadata_blocks.empty()&&proof.source_owned_blocks.empty()&&
            !proof.allocated_volume_blocks&&!proof.retired_volume_blocks&&!proof.retired_volume_payload_blocks,
            "changed admitted bytes clear every previously seeded retirement authority output");
        if(kind=="overlay")Check(image==original&&error=="AppleSnapshotRetirementCanonicalTreeChanged",
            "valid changed-atime overlay is refused independently of unchanged base transport");
        else {
            Check(error=="AppleSnapshotPlanningSourceChanged"&&budget->Failed(),"base dependency change poisons shared observation");
            const auto before=budget->Consumed();const auto reads=source.read_count;
            Check(!ProveAppleSnapshotRetirement(observation,*checkpoint,plan.commit.publication,101,
                request.required_checkpoint_xids,proof,error),"changed source cannot become a successful cached proof");
            const auto after=budget->Consumed();
            Check(source.read_count==reads&&before.reads==after.reads&&before.read_bytes==after.read_bytes&&
                before.records==after.records&&before.record_bytes==after.record_bytes,
                "sticky source refusal performs no further I/O or materialization");
        }
        Pass("catalog proof-once inflight preimage invalidation: "+std::string(kind));
    }
}
void CreateTests() {
    // Real pin retention needs additional canonical internal-pool COW space;
    // the ordinary four-block fixture correctly refuses under that pressure.
    Fixture f(16,32);
    f.PrepareLivePayloadForFirstCreate();
    VectorRandomAccessSource source(f.image);std::string error;
    const auto initial_owners=ReadFixtureOwners(source,f.checkpoint);
    Check(initial_owners.metadata.size()==7&&initial_owners.metadata.contains(183)&&
        initial_owners.payload==std::set<std::uint64_t>{220},"initial charge eight matches raw historical OMAP and payload edges");
    AppleSnapshotCreateRequest request;request.volume_object_id=101;request.name_utf8="created";request.creation_time_ns=1700000000000000000ull;
    AppleSnapshotCreatePlan plan;
    const bool planned=PlanAppleSnapshotCreate(source,f.checkpoint,request,plan,error);
    Check(planned,"first snapshot creation plans: "+error);
    Check(plan.identity.snapshot_xid==21&&plan.identity.extentref_physical_block==8,"real transferred extent-reference root");
    MemoryTarget target(f.image);const bool created=ExecuteAppleCheckpointPublication(target,plan.commit.publication,error);
    Check(created,"create publication: "+error);
    const auto verify=[&](const Bytes& bytes,bool must_exist){
        VectorRandomAccessSource current(bytes);auto cp=LoadAppleCheckpointView(current,0,current.SizeBytes(),error);
        Check(cp.has_value(),"select create checkpoint: "+error);
        AppleSnapshotRetentionView proof;Check(LoadAppleSnapshotRetention(current,*cp,proof,error),"create retained ownership: "+error);
        if(cp->container.superblock.xid==20){Check(!must_exist&&proof.identities.empty(),"old checkpoint has empty inventory");return;}
        Check(cp->container.superblock.xid==21&&proof.identities.size()==1,"new checkpoint has complete inventory");
        ApfsSnapshotRecords raw;Check(ApfsSnapshotStore::LoadExactRecords(current,proof.identities[0],raw,error),"created exact records: "+error);
        Check(raw.trees.extentref.size()==1,"snapshot owns transferred NEW record");
        const auto live_ref=cp->volumes[0].extentref_tree->physical_block;
        auto live_bytes=Bytes(bytes.begin()+live_ref*f.bs,bytes.begin()+(live_ref+1)*f.bs);
        Check(ReadU32LE(live_bytes,0x24).value()==0,"new live layer is genuinely empty");
        std::shared_ptr<const NativeApfsSnapshotProjection> projection;
        Check(NativeApfsReader::TryLoadSnapshotProjection(current,proof.identities[0],projection,error),"created snapshot projects: "+error);
        const auto extents=projection->View().read_extents_by_inode.at(30);Bytes payload;
        Check(extents.size()==1&&current.Read(extents[0].physical_address,4096,payload)&&payload==Bytes(4096,std::byte{0x53}),"created snapshot returns original bytes");
    };
    const auto save=[](const char* path,const Bytes& bytes){std::ofstream file(path,std::ios::binary);file.write(reinterpret_cast<const char*>(bytes.data()),bytes.size());Check(file.good(),"save canonical fixture artifact");};
    save("snapshot-precreate.img",f.image);save("snapshot-created.img",target.image);
    std::cout<<"CREATE FAILURE POSITIONS "<<target.operations<<" plus 4 stage hooks\n";
    verify(target.image,true);Pass("canonical first create transfers references and reads historical file bytes");
    for(const auto* stage:{"before-apple-device-write","before-apple-prepublication-flush","before-apple-checkpoint-switch","before-apple-final-flush"}){
        MemoryTarget failed(f.image);Check(!ExecuteAppleCheckpointPublication(failed,plan.commit.publication,error,[&](std::string_view at){return at!=stage;}),"create stage interruption");verify(failed.image,false);
    }

    {
        VectorRandomAccessSource before(target.image);
        auto cp=LoadAppleCheckpointView(before,0,before.SizeBytes(),error);
        AppleVolumeTransactionRequest mutate;mutate.volume_object_id=101;
        Check(ReadAppleVolumeFileSystemRecords(before,cp->container,cp->volumes[0],mutate.filesystem_records,error),"read current records for snapshot COW");
        std::erase_if(mutate.filesystem_records,[](const auto& r){return ReadU64LE(r.key,0).value_or(0)>>60==8;});
        mutate.released_data_blocks.push_back({220,1});
        mutate.data_writes.push_back({30,0,0,Bytes(4096,std::byte{0x4D})});
        AppleVolumeTransactionPlan live;
        const bool planned_live=PlanAppleSnapshotLiveTransaction(before,*cp,mutate,live,error);
        Check(planned_live,"snapshot live mutation plan: "+error);
        Check(std::none_of(live.allocation.deferred_frees.begin(),live.allocation.deferred_frees.end(),[](const auto& r){return r.physical_block<=220&&220-r.physical_block<r.block_count;}),"last live owner does not release retained payload");
        const auto verify_mutation=[&](const Bytes& image,bool durable){
            VectorRandomAccessSource src(image);auto selected=LoadAppleCheckpointView(src,0,src.SizeBytes(),error);
            Check(selected.has_value(),"mutation selected checkpoint");
            AppleSnapshotRetentionView proof;Check(LoadAppleSnapshotRetention(src,*selected,proof,error),"mutation ownership: "+error);
            Check(proof.identities.size()==1&&proof.identities[0].snapshot_xid==21,"mutation preserves exact snapshot");
            std::shared_ptr<const NativeApfsSnapshotProjection> projection;
            Check(NativeApfsReader::TryLoadSnapshotProjection(src,proof.identities[0],projection,error),"historical reader after mutation: "+error);
            Bytes bytes;const auto old=projection->View().read_extents_by_inode.at(30);
            Check(src.Read(old[0].physical_address,4096,bytes)&&bytes==Bytes(4096,std::byte{0x53}),"snapshot reads old bytes after live COW");
            std::vector<apfsaccess::catalog::BtreeRecord> current;
            Check(ReadAppleVolumeFileSystemRecords(src,selected->container,selected->volumes[0],current,error),"read live after mutation");
            AppleFileExtentRecord mapping;
            auto it=std::find_if(current.begin(),current.end(),[](const auto& r){return ReadU64LE(r.key,0).value_or(0)>>60==8;});
            Check(it!=current.end()&&DecodeAppleFileExtentRecord(*it,4096,mapping,error),"decode current exact extent");
            const bool changed=selected->container.superblock.xid==22;
            Check(changed||!durable,"successful publication chooses new live mapping");
            Check(src.Read(mapping.physical_block*4096,4096,bytes)&&bytes==Bytes(4096,changed?std::byte{0x4D}:std::byte{0x53}),"live bytes match selected checkpoint");
        };
        MemoryTarget mutated(target.image);Check(ExecuteAppleCheckpointPublication(mutated,live.commit.publication,error),"snapshot live COW publication: "+error);
        std::cout<<"LIVE COW FAILURE POSITIONS "<<mutated.operations<<" plus 4 stage hooks\n";
        verify_mutation(mutated.image,true);
        save("snapshot-live-mutated.img",mutated.image);
        DeleteLifecycle(mutated.image);
        for(const auto* stage:{"before-apple-device-write","before-apple-prepublication-flush","before-apple-checkpoint-switch","before-apple-final-flush"}){
            MemoryTarget failed(target.image);Check(!ExecuteAppleCheckpointPublication(failed,live.commit.publication,error,[&](std::string_view at){return at!=stage;}),"mutation stage interruption");verify_mutation(failed.image,false);
        }

        {
            VectorRandomAccessSource after(mutated.image);auto selected=LoadAppleCheckpointView(after,0,after.SizeBytes(),error);
            auto exact=plan.identity;exact.scope.checkpoint_xid=selected->container.superblock.xid;
            AppleSnapshotDeleteReferencePlan deletion;
            Check(PlanAppleSnapshotDeleteReferences(after,*selected,exact,deletion,error),"post-mutation final snapshot deletion preflight: "+error);
            Check(deletion.unreferenced_payload.size()==1&&deletion.unreferenced_payload[0].physical_block==220&&deletion.unreferenced_payload[0].block_count==1,"only historical payload becomes unreferenced");
            Check(deletion.replacements.size()==1&&deletion.replacements[0].snapshot_xid==0,"only live reference tree remains");
            ApplePhysicalExtentRecord live_ref;
            Check(deletion.replacements[0].extentref_records.size()==1&&DecodeApplePhysicalExtentRecord(deletion.replacements[0].extentref_records[0],live_ref,error)&&
                live_ref.kind==kApplePhysicalExtentKindNew&&live_ref.reference_count==1&&live_ref.physical_block!=220,"final deletion restores ordinary NEW live ownership");
            std::vector<AppleRecoveryCheckpointView> pins;
            Check(!LoadAppleRecoveryCheckpoints(after,*selected,{21},pins,error)&&pins.empty(),"snapshot-bearing WAL checkpoint pin still refuses incomplete recovery support");
            Check(error.find("SnapshotsUnsupported")!=std::string::npos,"exact recovery refusal: "+error);
            std::cout<<"RECOVERY BOUNDARY "<<error<<'\n';
            exact.name_utf8="wrong";
            Check(!PlanAppleSnapshotDeleteReferences(after,*selected,exact,deletion,error)&&deletion.replacements.empty()&&deletion.unreferenced_payload.empty(),"stale delete identity clears every proposed change");
            // Reference preflight has not removed records, published, or freed.
            Check(after.SizeBytes()==mutated.image.size(),"deletion preflight is read only");
        }

        for(std::size_t n=0;n<mutated.operations;++n){MemoryTarget failed(target.image);failed.fail_at=n;
            Check(!ExecuteAppleCheckpointPublication(failed,live.commit.publication,error),"failed live COW not acknowledged");verify_mutation(failed.image,false);}
        Pass("create then mutate live reads old snapshot bytes across every write and flush failure");
    }

    for(std::size_t n=0;n<target.operations;++n){
        MemoryTarget failed(f.image);failed.fail_at=n;
        Check(!ExecuteAppleCheckpointPublication(failed,plan.commit.publication,error),"interrupted create is never acknowledged");
        verify(failed.image,false);
    }
    Pass("every create write and flush failure selects complete old or new ownership");
    VectorRandomAccessSource published(target.image);auto cp=LoadAppleCheckpointView(published,0,published.SizeBytes(),error);
    AppleSnapshotCreatePlan rejected;
    Check(!PlanAppleSnapshotCreate(published,*cp,request,rejected,error)&&error=="AppleSnapshotCreateNameExists","duplicate create name refuses");
    request.name_utf8=std::string(1,static_cast<char>(0xff));
    Check(!PlanAppleSnapshotCreate(source,f.checkpoint,request,rejected,error)&&rejected.commit.publication.before_superblock_writes.empty(),"invalid name has no partial publication plan");
    Pass("first-create profile and all-or-nothing rejection");
}

void LayerTests() {
    std::string error;
    std::vector<apfsaccess::catalog::BtreeRecord> snapshots;
    for(const auto xid:{256ull,255ull,65536ull,65535ull}){apfsaccess::catalog::BtreeRecord r{Bytes(8),Bytes(16)};
        PutU64LE(r.key,0,xid);snapshots.push_back(std::move(r));}
    Check(SortAppleBtreeRecords(snapshots,AppleBtreeKeyOrder::SnapshotObjectMap,error),"numeric snapshot OMAP keys sort");
    Check(ReadU64LE(snapshots[0].key,0).value()==255&&ReadU64LE(snapshots[1].key,0).value()==256&&
        ReadU64LE(snapshots[2].key,0).value()==65535&&ReadU64LE(snapshots[3].key,0).value()==65536,"XID sort crosses byte boundaries");
    snapshots[0].value[0]=std::byte{1};
    Check(!SortAppleBtreeRecords(snapshots,AppleBtreeKeyOrder::SnapshotObjectMap,error),"snapshot OMAP deleted flag cannot enter supported serializer");
    Pass("snapshot OMAP numeric ordering and ordinary value profile");
    const ApplePhysicalExtentRecord original{220,4,kApplePhysicalExtentKindNew,30,1};
    const std::vector<ApplePhysicalExtentRecord> prior{original}, history{original,original};
    auto file=[](std::uint64_t owner,std::uint64_t block,std::uint64_t length){
        return Encode(AppleFileExtentRecord{owner,0,length*4096,block,0,4096},EncodeAppleFileExtentRecord);};
    auto ref=[](std::uint64_t block,std::uint64_t length,std::uint8_t kind,std::int32_t count,std::uint64_t owner=30){
        return Encode(ApplePhysicalExtentRecord{block,length,kind,owner,count},EncodeApplePhysicalExtentRecord);};
    std::vector<ApplePhysicalExtentRecord> resolved;
    Check(ResolveAppleSnapshotExtentLayer(prior,history,{file(30,220,4)},{},4096,512,resolved,error),"empty inherited layer: "+error);
    Check(resolved.size()==1&&resolved[0].reference_count==1,"two snapshots do not inflate clone count");
    Pass("empty transfer layer inherits one owner across overlapping snapshots");
    auto fs=std::vector<apfsaccess::catalog::BtreeRecord>{file(30,220,4),file(40,221,2)};
    auto delta=std::vector<apfsaccess::catalog::BtreeRecord>{ref(221,2,kApplePhysicalExtentKindUpdate,1)};
    Check(ResolveAppleSnapshotExtentLayer(prior,history,fs,delta,4096,512,resolved,error),"split clone addition: "+error);
    Check(resolved.size()==3&&resolved[0].reference_count==1&&resolved[1].reference_count==2&&resolved[2].reference_count==1,"exact clone counts at interval splits");
    std::vector<apfsaccess::catalog::BtreeRecord> full;for(const auto& r:resolved)full.push_back(Encode(r,EncodeApplePhysicalExtentRecord));
    std::vector<apfsaccess::catalog::BtreeRecord> planned;
    Check(PlanAppleSnapshotExtentLayer(prior,history,fs,full,4096,512,planned,error),"encode clone delta: "+error);
    Check(planned.size()==1&&planned[0].value==delta[0].value,"planner emits one signed UPDATE");
    Pass("partial overlap split and canonical UPDATE planning");
    Check(ResolveAppleSnapshotExtentLayer(prior,history,{}, {ref(220,4,kApplePhysicalExtentKindUpdate,-1)},4096,512,resolved,error),"final live owner removal: "+error);
    Check(resolved.empty()&&history.size()==2,"removed live owner leaves historical ownership intact");
    Check(PlanAppleSnapshotExtentLayer(prior,history,{}, {},4096,512,planned,error),"plan final live removal");
    ApplePhysicalExtentRecord decoded;Check(planned.size()==1&&DecodeApplePhysicalExtentRecord(planned[0],decoded,error)&&decoded.reference_count==-1,"negative UPDATE round trip");
    Pass("final current owner removal is a decrement and never a snapshot free");
    Check(ResolveAppleSnapshotExtentLayer({},history,{file(40,220,4)}, {ref(220,4,kApplePhysicalExtentKindUpdate,1,40)},4096,512,resolved,error),"historically held extent reused by reference");
    Check(resolved[0].reference_count==1&&resolved[0].owning_object_id==40,"resurrection does not add historical owners");
    Pass("positive UPDATE can reference retained data after an empty intermediate view");
    Check(ResolveAppleSnapshotExtentLayer(prior,history,{file(40,220,4)}, {ref(220,4,kApplePhysicalExtentKindUpdate,0,40)},4096,512,resolved,error),"zero delta owner transition");
    Pass("zero delta changes exact single mapping owner");
    for(const auto count:{-2,INT32_MAX}) {
        Check(!ResolveAppleSnapshotExtentLayer(prior,history,{}, {ref(220,4,kApplePhysicalExtentKindUpdate,count)},4096,512,resolved,error)&&resolved.empty(),"underflow or overflow refused");
    }
    Pass("signed count underflow and overflow refuse with empty output");
    Check(!ResolveAppleSnapshotExtentLayer(prior,history,{file(30,220,4)}, {ref(220,4,kApplePhysicalExtentKindNew,1)},4096,512,resolved,error)&&error=="AppleSnapshotNewOverlapsHistory","NEW cannot steal historical allocation");
    Check(!ResolveAppleSnapshotExtentLayer({}, {},{file(30,220,4)},delta,4096,512,resolved,error)&&error=="AppleSnapshotUpdateWithoutHistory","unanchored UPDATE refused");
    Check(!ResolveAppleSnapshotExtentLayer(prior,history,{file(30,220,4)},delta,4096,512,resolved,error),"wrong exact snapshot multiplicity refused");
    Check(!ResolveAppleSnapshotExtentLayer(prior,history,fs,{delta[0],delta[0]},4096,512,resolved,error)&&error=="AppleSnapshotLayerOverlap","overlapping layer records refused");
    Check(!ResolveAppleSnapshotExtentLayer(prior,history,{}, {},4096,512,resolved,error),"missing decrement cannot hide final owner removal");
    Pass("ownership mismatches and incomplete delta graph remain refused");
}

void CensusTests() {
    Fixture f;AppleSnapshotRetentionView retained;std::string error;
    const auto original=f.image;
    const bool censused = f.Census(retained,error);
    Check(censused,"census: "+error);
    Check(f.image==original,"census performs no writes");
    Check(retained.identities.size()==1 && retained.payload_extents.size()==1,"one snapshot and payload range");
    Check(retained.payload_extents[0].physical_block==220,"payload ownership at 220");
    for(auto block:{2ull,3ull,4ull,5ull,6ull,7ull,8ull,9ull,180ull,181ull,183ull,184ull,185ull})
        Check(std::binary_search(retained.metadata_blocks.begin(),retained.metadata_blocks.end(),block),"complete metadata: "+std::to_string(block));
    Pass("exact parser census and allocated retained ownership");
    {
        Fixture alias;alias.InstallLivePayload(180);
        Check(!alias.Census(retained,error)&&error=="AppleSnapshotRetentionPayloadMetadataOverlap", "live payload aliases historical APSB: "+error);
        Check(retained.identities.empty()&&retained.metadata_blocks.empty()&&retained.payload_extents.empty(),"alias failure clears census");
        Pass("allocated historical metadata cannot be owned as a live payload");
    }
    {
        Fixture alias;alias.AddSiblingPayload();
        Check(!alias.Census(retained,error)&&error=="AppleSnapshotRetentionCrossVolumePayloadOverlap","sibling cannot own snapshot payload: "+error);
        Check(retained.identities.empty(),"sibling alias clears ownership");
        Pass("snapshot sharing never authorizes another volume to own its payload");
    }
    Check(f.Census(retained,error),"restore census after alias test");

    {
        auto changed=retained.identities[0];changed.name_utf8="Backup";
        VectorRandomAccessSource source(f.image);ApfsSnapshotRecords records;
        Check(!ApfsSnapshotStore::LoadExactRecords(source,changed,records,error),"stale name refused");
        Check(records.trees.metadata_blocks.empty(),"stale identity clears footprint");
        Pass("stale exact identity clears ownership output");
    }
    {
        auto changed=f;changed.snapshots.push_back(SnapshotFixture::Metadata(11,"backup"));changed.Inventory({10,11});changed.Reload();
        Check(!changed.Census(retained,error),"duplicate name refused");
        Check(retained.identities.empty()&&retained.metadata_blocks.empty()&&retained.payload_extents.empty(),"failure clears all ownership");
        Pass("name collision cannot leak a partial census");
    }
    for(auto block:{180ull,183ull,184ull,185ull,220ull}) {
        Fixture bad;
        const auto& chunk=bad.checkpoint.spaceman.chunks[0];
        auto bitmap=bad.Block(chunk.bitmap_block);bitmap[block/8]&=static_cast<std::byte>(~(1u<<(block%8)));
        bad.Put(chunk.bitmap_block,bitmap,false);
        bad.Edit(bad.checkpoint.spaceman.devices[0].cibs[0].object.physical_block,[&](auto& b){PutU32LE(b,0x3C,chunk.free_count+1);});
        bad.Edit(bad.checkpoint.spaceman.object.physical_block,[&](auto& b){PutU64LE(b,0x48,bad.checkpoint.spaceman.devices[0].free_count+1);});
        bad.Reload();Check(!bad.Census(retained,error),"unallocated retained block refused: "+std::to_string(block));
        Check(error.find("NotOwned")!=std::string::npos,"ownership refusal: "+error);
        Check(retained.identities.empty(),"no partial ownership");Pass("unallocated retained block "+std::to_string(block));
    }
    {
        Fixture bad;bad.SetPayload(220,kApplePhysicalExtentKindUpdate);bad.Reload();
        Check(!bad.Census(retained,error)&&error=="AppleSnapshotUpdateWithoutHistory","UPDATE layer refused: "+error);
        Pass("unanchored snapshot delta remains fail closed");
    }
    {
        Fixture bad;bad.SetPayload(183);
        auto removed=Encode(ApplePhysicalExtentRecord{183,1,kApplePhysicalExtentKindUpdate,30,-1},EncodeApplePhysicalExtentRecord);
        bad.Put(8,BuildRawLeafNode({removed.key},{removed.value},20,bad.bs,0,8,kObjectPhysical|kObjectTypeBtree,kObjectTypeBlockRefTree));bad.Reload();
        Check(!bad.Census(retained,error)&&error=="AppleSnapshotRetentionPayloadMetadataOverlap","metadata alias refused: "+error);
        Pass("historical payload cannot alias historical metadata");
    }
    {
        Fixture bad;bad.SecondSnapshot();bad.Allocate({188,190,191});
        // Both snapshots can own the same payload without doubling a live refcount.
        bad.Put(188,bad.Block(183));bad.Edit(188,[](auto& b){PutU64LE(b,0x10,11);});
        // Creation transfers the preceding empty live layer; it does not copy
        // the first snapshot's NEW records or increase an ordinary refcount.
        bad.Reload();Check(bad.Census(retained,error),"shared historical payload: "+error);
        Check(retained.identities.size()==2&&retained.payload_extents.size()==2,"distinct snapshot owners remain distinct");
        Check(retained.payload_extents[0].physical_block==retained.payload_extents[1].physical_block,"shared physical range");
        Pass("multiple snapshot owners of the same payload");
        VectorRandomAccessSource shared(bad.image);AppleSnapshotDeleteReferencePlan deletion;
        Check(PlanAppleSnapshotDeleteReferences(shared,bad.checkpoint,retained.identities[0],deletion,error),"delete older overlapping snapshot preflight: "+error);
        Check(deletion.unreferenced_payload.empty()&&deletion.replacements.size()==2,"remaining snapshot prevents payload reclamation");
        ApplePhysicalExtentRecord rebased;
        Check(deletion.replacements[0].snapshot_xid==11&&deletion.replacements[0].extentref_records.size()==1&&
            DecodeApplePhysicalExtentRecord(deletion.replacements[0].extentref_records[0],rebased,error)&&
            rebased.kind==kApplePhysicalExtentKindNew&&rebased.reference_count==1,"oldest survivor receives NEW base without inflated clone count");
        Pass("deletion rebases overlapping survivor and preserves its sole mapping count");

    }
    {
        Fixture bad;VectorRandomAccessSource raw(bad.image);
        auto budget=std::make_shared<ApfsReadBudget>(1,4096,1000000,256ull<<20);
        BudgetedRandomAccessSource source(raw,budget);
        Check(!LoadAppleSnapshotRetention(source,bad.checkpoint,retained,error),"budget refusal");
        Check(budget->Failed()&&retained.identities.empty(),"sticky shared budget and no partial census");
        Pass("shared read budget bounds ownership walk");
    }
    {
        Fixture multi;
        VectorRandomAccessSource source(multi.image);ApfsSnapshotRecords bundle;
        std::vector<ApfsSnapshotInfo> items;
        Check(multi.Enumerate(items,error),"multilevel identity");
        Check(ApfsSnapshotStore::LoadExactRecords(source,items[0].identity,bundle,error),"multilevel records: "+error);
        auto records=std::move(bundle.trees.filesystem);
        // Embedded attributes require real child nodes while preserving the
        // complete historical file namespace and payload ownership graph.
        for(std::uint64_t id=100;id<260;++id)
            records.push_back(Encode(AppleXattrRecord{30,"user.retention."+std::to_string(id),kAppleXattrDataEmbedded,Bytes(32)},EncodeAppleXattrRecord));
        AppleBtreeOptions options;options.block_size=4096;options.xid=10;
        options.root_object_id=SnapshotFixture::root_oid;options.root_physical_block=183;
        options.first_child_object_id=0x7000;options.first_child_physical_block=230;
        options.subtype=kObjectTypeFsTree;options.key_order=AppleBtreeKeyOrder::FileSystemCaseSensitive;
        AppleSerializedBtree tree;
        Check(SerializeAppleBtree(records,options,tree,error),"multilevel fixture: "+error);
        Check(tree.height>0,"actual multilevel filesystem tree");
        std::vector<OmapRecordSpec> mappings;std::vector<std::uint64_t> blocks;
        for(const auto& object:tree.objects) {
            multi.Put(object.location.physical_block,object.bytes);blocks.push_back(object.location.physical_block);
            if(object.location.physical_block!=183)
                mappings.push_back({object.location.object_id,object.location.physical_block,0,10});
        }
        multi.SetMappings(mappings);multi.Allocate(blocks);
        Check(multi.Census(retained,error),"multilevel census: "+error);
        for(const auto block:blocks)
            Check(std::binary_search(retained.metadata_blocks.begin(),retained.metadata_blocks.end(),block),"historical child retained");
        const auto request=multi.Request({{blocks.back(),1}});AppleTransactionCommitPlan refused;
        const bool planned = multi.Plan(request,refused,error);
        Check(!planned&&error=="AppleTransactionSnapshotBlockReleased","historical child release refused: "+error);
        Pass("multilevel historical children participate in ownership and release guards");
    }
}
void CommitTests() {
    Fixture f;std::string error;AppleSnapshotRetentionView retained;
    Check(f.Census(retained,error),"fixture census: "+error);
    auto request=f.Request();AppleTransactionCommitPlan plan;
    Check(f.Plan(request,plan,error),"protected commit plan: "+error);
    for(auto block:retained.metadata_blocks)
        Check(std::any_of(plan.publication.guard_blocks.begin(),plan.publication.guard_blocks.end(),
            [block](const auto& guard){return guard.physical_block==block;}),"snapshot metadata preimage guard");
    MemoryTarget success(f.image);
    Check(ExecuteAppleCheckpointPublication(success,plan.publication,error),"protected publication: "+error);
    Check(success.image!=f.image&&success.writes!=0,"real checkpoint publication occurred");
    Preserved(f,success.image,retained);Pass("canonical checkpoint publication preserves snapshots and allocation");
    {
        VectorRandomAccessSource advanced(success.image);AppleSnapshotRetentionView stale=retained;
        Check(!LoadAppleSnapshotRetention(advanced,f.checkpoint,stale,error),"old checkpoint cannot authorize a new census");
        Check(stale.identities.empty()&&stale.metadata_blocks.empty()&&stale.payload_extents.empty(),"stale checkpoint clears all ownership");
        Pass("stale checkpoint census cannot silently advance to latest");
    }
    for(auto block:retained.metadata_blocks) {
        auto release=f.Request({{block,1}});AppleTransactionCommitPlan refused;
        Check(!f.Plan(release,refused,error)&&error=="AppleTransactionSnapshotBlockReleased","metadata release refused: "+error);
        Check(refused.publication.before_superblock_writes.empty(),"refusal leaks no plan");
    }
    {
        auto release=f.Request({{220,1}});AppleTransactionCommitPlan refused;
        Check(!f.Plan(release,refused,error)&&error=="AppleTransactionSnapshotBlockReleased","payload release refused: "+error);
        Pass("all retained metadata and payload releases refused before I/O");
    }
    {
        auto reuse=request;reuse.allocation_plan.allocated_main_blocks[0]=220;reuse.allocated_main_writes[0].physical_block=220;
        AppleTransactionCommitPlan refused;
        Check(!f.Plan(reuse,refused,error)&&error=="AppleTransactionSnapshotBlockReused","forged allocator reuse refused: "+error);
        Pass("retained payload reuse cannot bypass canonical commit");
    }
    {
        auto lost=request;lost.allocation_plan.updated_spaceman.chunks[0].allocation_bitmap[220/8]&=static_cast<std::byte>(~(1u<<(220%8)));
        AppleTransactionCommitPlan refused;
        Check(!f.Plan(lost,refused,error)&&error=="AppleTransactionSnapshotOwnershipLost","lost allocator ownership refused: "+error);
        Pass("updated bitmap must retain snapshot ownership");
    }
    {
        auto roots=request;roots.container_object_map_oid=roots.allocation_plan.allocated_main_blocks[0];
        AppleTransactionCommitPlan refused;
        Check(!f.Plan(roots,refused,error)&&error=="AppleTransactionSnapshotRootReplacementUnsupported","root replacement refused: "+error);
        Pass("original composer refuses implicit snapshot root replacement");
    }
    {
        auto corrupt=request;bool changed=false;
        for(auto& write:corrupt.allocation_plan.writes)
            if(write.kind==AppleSpacemanWriteKind::ChunkBitmap) {
                write.bytes[220/8]&=static_cast<std::byte>(~(1u<<(220%8)));changed=true;
            }
        Check(changed,"actual serialized chunk bitmap was corrupted");
        // The in-memory updated_spaceman still claims ownership. Only a
        // staged parse of publication bytes can reject this mismatch.
        const auto original=f.image;AppleTransactionCommitPlan refused;
        Check(!f.Plan(corrupt,refused,error)&&!error.empty(),"serialized allocation mismatch refused");
        Check(f.image==original&&refused.publication.before_superblock_writes.empty(),"serialized mismatch before I/O");
        Pass("serialized bitmap must prove ownership independently of allocator view");
    }
    {
        MemoryTarget stale(f.image);stale.image[183*4096+80]^=std::byte{1};const auto preimage=stale.image;
        Check(!ExecuteAppleCheckpointPublication(stale,plan.publication,error),"stale snapshot metadata refused");
        Check(stale.writes==0&&stale.image==preimage,"stale guard refusal before first write");
        Pass("stale snapshot preimage is checked before publication writes");
    }
    for(const auto* stage:{"before-apple-device-write","before-apple-prepublication-flush","before-apple-checkpoint-switch","before-apple-final-flush"}) {
        MemoryTarget failed(f.image);
        Check(!ExecuteAppleCheckpointPublication(failed,plan.publication,error,[&](std::string_view at){return at!=stage;}),"injected stage refusal");
        if(std::string_view(stage)=="before-apple-device-write")Check(failed.image==f.image,"pre-write exact preimage");
        Preserved(f,failed.image,retained);Pass(std::string("publication stage ownership: ")+stage);
    }
    for(std::size_t fault=0;fault<success.operations;++fault) {
        MemoryTarget failed(f.image);failed.fail_at=fault;
        Check(!ExecuteAppleCheckpointPublication(failed,plan.publication,error),"injected write/flush failure");
        Preserved(f,failed.image,retained);Pass("write/flush failure ownership "+std::to_string(fault));
    }
    {
        AppleVolumeTransactionRequest mutation;mutation.volume_object_id=101;
        // A valid ordinary root record reaches the existing snapshot refusal.
        mutation.filesystem_records.clear();AppleInodeRecord root;root.object_id=2;root.private_id=9;root.parent_id=2;root.mode=0040755;
        mutation.filesystem_records.push_back(Encode(root,EncodeAppleInodeRecord));
        VectorRandomAccessSource source(f.image);AppleVolumeTransactionPlan refused;
        Check(!PlanAppleVolumeTransaction(source,f.checkpoint,mutation,refused,error),"production snapshot write admission remains closed");
        Check(error=="AppleVolumeSnapshotsUnsupported","original admission boundary: "+error);
        Pass("production live mutation stays closed pending durable acceptance and recovery");
    }
}
}
int main(int argc, char** argv) {
    try {
        if ((argc == 2 || argc == 3) && std::string_view(argv[1]) == "--catalog-proof-once") {
            const std::string_view selected=argc==3?argv[2]:"all";
            Check(selected=="all"||selected=="budget"||selected=="preimages"||selected=="101"||selected=="102",
                "known catalog proof-once selection");
            if(selected!="preimages")CatalogProofOnceBudgetTests(selected=="101"?101:selected=="102"?102:0);
            if(selected=="all"||selected=="preimages")CatalogProofOncePreimageTests();
            std::cout<<"PASS "<<cases<<" cases, "<<checks<<" checks\n";return 0;
        }
        if ((argc == 2 || argc == 3) && std::string_view(argv[1]) == "--guard-copy-budget") {
            GuardCopyBudgetTests(argc==3 ? argv[2] : "all");
            std::cout<<"PASS "<<cases<<" cases, "<<checks<<" checks\n";return 0;
        }
        if (argc == 2 && std::string_view(argv[1]) == "--canonical-retention-reuse") {
            CanonicalRetentionReuseTests();PlanningObservationTests();PeerCatalogAdmissionTests();GuardCopyBudgetTests();
            std::cout<<"PASS "<<cases<<" cases, "<<checks<<" checks\n";return 0;
        }
        if (argc == 2 && std::string_view(argv[1]) == "--dependency-batching") {
            DependencyBatchingTests();
            std::cout<<"PASS "<<cases<<" cases, "<<checks<<" checks\n";return 0;
        }
        if (argc == 2 && std::string_view(argv[1]) == "--extended-metadata-admission") {
            ExtendedMetadataAdmissionTests();
            std::cout<<"PASS "<<cases<<" cases, "<<checks<<" checks\n";return 0;
        }
        if (argc == 2 && std::string_view(argv[1]) == "--peer-catalog-admission") {
            PeerCatalogAdmissionTests();
            std::cout<<"PASS "<<cases<<" cases, "<<checks<<" checks\n";return 0;
        }
        if (argc == 3 && std::string_view(argv[1]) == "--planner-budget-source") {
            const auto path = std::filesystem::absolute(argv[2]);
            Check(path.string().starts_with("D:\\ApfsAccessScratch\\"), "offline planner source must be an owned D: clone");
            FileRandomAccessSource source(path.string());
            Check(source.IsOpen(), "offline planner source opens");
            std::string error;
            auto checkpoint = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
            Check(checkpoint.has_value(), "offline exact source admission: " + error);
            for (const auto& volume : checkpoint->volumes) {
                std::vector<apfsaccess::catalog::BtreeRecord> mappings;
                Check(ReadBtreeLeafRecords(source, checkpoint->container.superblock.block_size,
                    volume.object_map.tree.physical_block, true, 0, checkpoint->container.superblock.xid,
                    mappings, error), "offline original volume OMAP: " + error);
                const auto root_versions = std::count_if(mappings.begin(), mappings.end(), [&](const auto& record) {
                    return ReadU64LE(record.key, 0) == volume.root_tree.object_id;
                });
                std::cout << "original volume=" << volume.superblock.object_id
                    << " apsbXid=" << volume.superblock.xid << " files=" << volume.superblock.file_count
                    << " omapRecords=" << mappings.size() << " filesystemRootVersions=" << root_versions << '\n';
            }
            auto budget = std::make_shared<ApfsReadBudget>(65536, 256ull << 20, 1000000, 256ull << 20);
            BudgetedRandomAccessSource bounded(source, budget);
            AppleSnapshotCreateRequest request;
            request.volume_object_id = 101;
            request.name_utf8 = "offline-budget-regression";
            request.creation_time_ns = 1;
            request.required_checkpoint_xids = {checkpoint->container.superblock.xid};
            AppleSnapshotCreatePlan plan;
            const bool planned = PlanAppleSnapshotCreate(bounded, *checkpoint, request, plan, error);
            const auto used = budget->Consumed();
            const auto failure = budget->ReservationFailure();
            std::cout << "planner planned=" << planned << " error=" << error
                << " xid=" << checkpoint->container.superblock.xid
                << " blocks=" << checkpoint->container.superblock.block_count
                << " descriptorBlocks=" << checkpoint->container.superblock.xp_desc_block_count
                << " reads=" << used.reads << " readBytes=" << used.read_bytes
                << " records=" << used.records << " materializedBytes=" << used.record_bytes
                << " refusedCount=" << failure.count << " refusedBytes=" << failure.bytes << '\n';
            Check(planned, "same-size/history snapshot create under unchanged production limits: " + error);
            Pass("offline actual-source snapshot planner budget");
            Bytes original;
            Check(source.Read(0,static_cast<std::size_t>(source.SizeBytes()),original),"sealed clone byte preimage");
            MemoryTarget target(original);
            Check(ExecuteAppleCheckpointPublication(target,plan.commit.publication,error),"actual offline publisher: "+error);
            Check(target.writes!=0,"actual serialized publication executes");
            MutableFixtureSource published(target.image);
            auto reopened=LoadAppleCheckpointView(published,0,published.SizeBytes(),error);
            Check(reopened && reopened->container.superblock.xid==checkpoint->container.superblock.next_xid,
                "fresh canonical reopen selects published P+1: "+error);
            std::shared_ptr<const NativeApfsSnapshotProjection> projection;
            auto projection_budget=std::make_shared<ApfsReadBudget>(65536,256ull<<20,1000000,256ull<<20);
            BudgetedRandomAccessSource projection_source(published,projection_budget);
            const bool projected=NativeApfsReader::TryLoadSnapshotProjection(projection_source,plan.identity,projection,error);
            const auto projection_used=projection_budget->Consumed();
            const auto projection_refused=projection_budget->ReservationFailure();
            std::cout<<"projection projected="<<projected<<" error="<<error<<" reads="<<projection_used.reads
                <<" readBytes="<<projection_used.read_bytes<<" records="<<projection_used.records
                <<" materializedBytes="<<projection_used.record_bytes<<" refusedCount="<<projection_refused.count
                <<" refusedBytes="<<projection_refused.bytes<<'\n';
            Check(projected,
                "fresh exact snapshot projection over copied-source publication: "+error);
            std::size_t payload_blocks=0;
            for(const auto& [inode,extents]:projection->View().read_extents_by_inode) for(const auto& extent:extents) {
                if(!extent.physical_address) continue;
                const auto bytes=extent.bytes;
                Check(extent.physical_address<=original.size() && bytes<=original.size()-extent.physical_address,
                    "snapshot payload stays inside original sealed window");
                Check(std::equal(original.begin()+extent.physical_address,original.begin()+extent.physical_address+bytes,
                    target.image.begin()+extent.physical_address),"copied-source snapshot payload remains byte exact");
                payload_blocks+=(bytes+projection->View().block_size-1)/projection->View().block_size;
            }
            Check(payload_blocks!=0,"ordinary original payload traversed through fresh snapshot reader");
            const auto sibling=std::find_if(checkpoint->volumes.begin(),checkpoint->volumes.end(),
                [](const auto& v){return v.superblock.object_id!=101;});
            Check(sibling!=checkpoint->volumes.end(),"copied original sibling exists");
            const auto sibling_block=sibling->superblock_object.physical_block;
            Check(std::equal(original.begin()+sibling_block*4096,original.begin()+(sibling_block+1)*4096,
                target.image.begin()+sibling_block*4096),"copied-source publication preserves original sibling APSB");
            Pass("offline actual publisher and fresh exact snapshot payload reopen");
            auto list_budget=std::make_shared<ApfsReadBudget>(65536,256ull<<20,1000000,256ull<<20);
            BudgetedRandomAccessSource list_source(published,list_budget);
            std::vector<ApfsSnapshotInfo> created_inventory;
            const bool listed=ApfsSnapshotStore::Enumerate(list_source,plan.identity.scope,created_inventory,error);
            const auto list_used=list_budget->Consumed();
            std::cout<<"list listed="<<listed<<" error="<<error<<" reads="<<list_used.reads
                <<" readBytes="<<list_used.read_bytes<<" records="<<list_used.records
                <<" materializedBytes="<<list_used.record_bytes<<'\n';
            Check(listed && created_inventory.size()==1 && created_inventory[0].identity==plan.identity,
                "fresh canonical inventory contains exact created identity: "+error);
            Pass("offline fresh exact created inventory");
            AppleSnapshotDeleteRequest deletion;
            deletion.expected=plan.identity;deletion.modification_time_ns=2;
            deletion.required_checkpoint_xids={reopened->container.superblock.xid};
            auto delete_budget=std::make_shared<ApfsReadBudget>(65536,256ull<<20,1000000,256ull<<20);
            BudgetedRandomAccessSource delete_source(published,delete_budget);
            AppleSnapshotDeletePlan deleted;
            const bool delete_planned=PlanAppleSnapshotDelete(delete_source,*reopened,deletion,deleted,error);
            const auto delete_used=delete_budget->Consumed();
            const auto delete_refused=delete_budget->ReservationFailure();
            std::cout<<"delete planned="<<delete_planned<<" error="<<error<<" reads="<<delete_used.reads
                <<" readBytes="<<delete_used.read_bytes<<" records="<<delete_used.records
                <<" materializedBytes="<<delete_used.record_bytes<<" refusedCount="<<delete_refused.count
                <<" refusedBytes="<<delete_refused.bytes<<" allocationBlocks="<<deleted.allocation.allocated_main_blocks.size()
                <<" publicationWrites="<<deleted.commit.publication.before_superblock_writes.size()<<'\n';
            Check(delete_planned,"copied-source actual deletion under unchanged limits: "+error);
            std::size_t physical_children=0;
            for(const auto& write:deleted.commit.publication.before_superblock_writes) {
                const auto type=ReadU32LE(write.bytes,0x18).value_or(0);
                const auto flags=ReadU16LE(write.bytes,0x20).value_or(0);
                if(type==(kObjectPhysical|kObjectTypeBtreeNode) && !(flags&1u))++physical_children;
            }
            Check(physical_children!=0,"actual copied-source deletion serializes physical child nodes");
            Check(ExecuteAppleCheckpointPublication(target,deleted.commit.publication,error),"offline actual deletion publication: "+error);
            auto final_cp=LoadAppleCheckpointView(published,0,published.SizeBytes(),error);
            Check(final_cp && final_cp->container.superblock.xid==reopened->container.superblock.next_xid,
                "fresh deletion P+1 canonical reopen: "+error);
            std::vector<ApfsSnapshotInfo> inventory;
            auto final_scope=plan.identity.scope;final_scope.checkpoint_xid=final_cp->container.superblock.xid;
            Check(ApfsSnapshotStore::Enumerate(published,final_scope,inventory,error) && inventory.empty(),
                "fresh deletion removes actual public inventory: "+error);
            Pass("offline copied-source delete publication and fresh inventory reopen");
        } else {LayerTests();CreateTests();CensusTests();CommitTests();ExtendedMetadataAdmissionTests();PeerCatalogAdmissionTests();PlanningObservationTests();CanonicalRetentionReuseTests();GuardCopyBudgetTests();DependencyBatchingTests();CatalogProofOnceBudgetTests();CatalogProofOncePreimageTests();}
        std::cout<<"PASS "<<cases<<" cases, "<<checks<<" checks\n";return 0;
    }
    catch(const std::exception& e){std::cerr<<"FAIL after "<<cases<<" cases, "<<checks<<" checks: "<<e.what()<<'\n';return 1;}
}
