#define main ExistingVerifierTestsMain
#include "ApfsVerifierTests.cpp"
#undef main

namespace
{
void AllocateSnapshotBlocks(SnapshotFixture& f, std::vector<std::uint64_t> blocks = {180,181,183,184,185,220})
{
    VectorRandomAccessSource source(f.image); std::string error;
    const auto cp=LoadAppleCheckpointView(source,0,source.SizeBytes(),error,20); Check(cp.has_value(),error);
    const auto& chunk=cp->spaceman.chunks[0]; unsigned added=0;
    f.Edit(chunk.bitmap_block,[&](auto& b){
        for(const auto block:blocks) {
            const auto bit=block-chunk.start_block;
            if((std::to_integer<unsigned>(b[bit/8])&(1u<<(bit%8)))==0){b[bit/8]|=std::byte(1u<<(bit%8));++added;}
        }
    },false);
    f.Edit(cp->spaceman.devices[0].cibs[0].object.physical_block,
        [&](auto& b){PutU32LE(b,0x3C,chunk.free_count-added);});
    f.Edit(cp->spaceman.object.physical_block,
        [&](auto& b){PutU64LE(b,0x48,cp->spaceman.devices[0].free_count-added);});
}
VerificationReport VerifySnapshot(SnapshotFixture& f)
{
    VerificationScope scope;scope.source_identity="private-snapshot-census";scope.exact=f.scope;
    scope.require_whole_volume=true;
    const auto before=f.image;TracedSource source(f.image);
    auto report=ApfsVerifier::Verify(source,scope);
    Check(before==f.image,"snapshot input unchanged");
    Check(!report.whole_volume_verified&&!report.allocation_census,"snapshot full accounting remains unavailable");
    Check(!source.Touched(220*f.bs,2*f.bs),"historical and live payload bytes never read");
    return report;
}
VerificationReport VerifyCurrentSnapshot(SnapshotFixture& f)
{
    VerificationScope scope;scope.source_identity="private-current-snapshot-metadata";scope.exact=f.scope;
    const auto before=f.image;TracedSource source(f.image);
    const auto report=ApfsVerifier::Verify(source,scope);
    Check(before==f.image&&!source.Touched(220*f.bs,2*f.bs),"current metadata scope preserves source and never reads payload");
    Check(!report.whole_volume_verified&&!report.payload_content_hashes_verified,"current scope cannot promote global integrity claims");
    Check(report.repair.refusal==(report.outcome==VerificationOutcome::Complete ?
        ApfsRepairRefusal::NoIndependentReconstructionEvidence:ApfsRepairRefusal::VerificationNotComplete),
        "current scope retains explicit repair refusal");
    return report;
}
void CurrentSnapshotAllocation(SnapshotFixture& f, std::uint64_t blocks=7)
{
    f.Edit(4,[&](auto& bytes){PutU64LE(bytes,0x58,blocks);});
}
class ChangedLiveReadSource final : public RandomAccessSource
{
public:
    ChangedLiveReadSource(const Bytes& image, std::uint64_t at, std::size_t ordinal, Bytes replacement)
        : original_(image), at_(at), ordinal_(ordinal), replacement_(std::move(replacement)) {}
    std::uint64_t SizeBytes() const override { return original_.SizeBytes(); }
    bool Read(std::uint64_t offset, std::size_t size, Bytes& out) const override
    {
        if (!original_.Read(offset,size,out)) return false;
        if (offset==at_&&size==replacement_.size()&&++seen_>=ordinal_) out=replacement_;
        return true;
    }
private:
    TracedSource original_;
    std::uint64_t at_;
    std::size_t ordinal_;
    Bytes replacement_;
    mutable std::size_t seen_=0;
};
void SnapshotPayload(SnapshotFixture& f, std::uint64_t physical=220)
{
    Fixture payload(static_cast<std::uint32_t>(f.bs));
    auto records=payload.spec.volumes[0].filesystem_records;
    for(auto& r:records) if(ReadU64LE(r.key,0).value()>>60==8)
        r=Encode(AppleFileExtentRecord{30,0,f.bs,physical,0,static_cast<std::uint32_t>(f.bs)},EncodeAppleFileExtentRecord);
    std::vector<Bytes> keys,values;for(const auto& r:records){keys.push_back(r.key);values.push_back(r.value);}
    f.Put(183,BuildRawLeafNode(keys,values,10,f.bs,0,SnapshotFixture::root_oid,kObjectTypeBtree,kObjectTypeFsTree));
    const auto ref=Encode(ApplePhysicalExtentRecord{physical,1,kApplePhysicalExtentKindNew,30,1},EncodeApplePhysicalExtentRecord);
    f.Put(184,BuildRawLeafNode({ref.key},{ref.value},10,f.bs,0,184,kObjectPhysical|kObjectTypeBtree,kObjectTypeBlockRefTree));
    const auto removed=Encode(ApplePhysicalExtentRecord{physical,1,kApplePhysicalExtentKindUpdate,30,-1},EncodeApplePhysicalExtentRecord);
    f.Put(8,BuildRawLeafNode({removed.key},{removed.value},20,f.bs,0,8,kObjectPhysical|kObjectTypeBtree,kObjectTypeBlockRefTree));
}
void SnapshotLayer(SnapshotFixture& f, std::uint64_t block, std::uint64_t xid,
    const std::vector<ApplePhysicalExtentRecord>& refs)
{
    std::vector<Bytes> keys,values;
    for(const auto& ref:refs){const auto record=Encode(ref,EncodeApplePhysicalExtentRecord);keys.push_back(record.key);values.push_back(record.value);}
    f.Put(block,BuildRawLeafNode(keys,values,xid,f.bs,0,block,kObjectPhysical|kObjectTypeBtree,kObjectTypeBlockRefTree));
}
std::vector<std::uint64_t> HistoricalOmap(SnapshotFixture& f, bool multilevel=false)
{
    f.Edit(180,[](auto& bytes){PutU64LE(bytes,0x80,192);});
    f.Put(192,BuildOmap(193,10,f.bs,192,kObjectPhysical|kObjectTypeOmap,kObjectPhysical|kObjectTypeBtree));
    std::vector<Record> mappings{Encode(AppleOmapRecord{SnapshotFixture::root_oid,10,0,
        static_cast<std::uint32_t>(f.bs),183},EncodeAppleOmapRecord)};
    if(multilevel) for(unsigned i=0;i<180;++i)
        mappings.push_back(Encode(AppleOmapRecord{0x9000+i,10,0,static_cast<std::uint32_t>(f.bs),250},EncodeAppleOmapRecord));
    AppleBtreeOptions options;options.block_size=static_cast<std::uint32_t>(f.bs);options.xid=10;
    options.root_object_id=options.root_physical_block=193;
    options.first_child_object_id=options.first_child_physical_block=194;
    options.storage_type=kObjectPhysical;options.subtype=kObjectTypeOmap;
    options.tree_flags=kAppleBtreePhysical;options.key_order=AppleBtreeKeyOrder::ObjectMap;
    options.fixed_key_size=options.fixed_value_size=16;
    AppleSerializedBtree tree;std::string error;
    Check(SerializeAppleBtree(mappings,options,tree,error),error);
    Check(!multilevel||tree.height>0,"historical OMAP must contain child nodes");
    std::vector<std::uint64_t> blocks{192};
    for(const auto& object:tree.objects){f.Put(object.location.physical_block,object.bytes);blocks.push_back(object.location.physical_block);}
    AllocateSnapshotBlocks(f,blocks);
    return blocks;
}
void SnapshotSibling(SnapshotFixture& f, std::uint64_t physical)
{
    Fixture payload(static_cast<std::uint32_t>(f.bs));
    auto records=payload.spec.volumes[0].filesystem_records;
    for(auto& record:records) if(ReadU64LE(record.key,0).value()>>60==8)
        record=Encode(AppleFileExtentRecord{30,0,f.bs,physical,0,static_cast<std::uint32_t>(f.bs)},EncodeAppleFileExtentRecord);
    BuilderVolume sibling;sibling.oid=102;sibling.uuid_hex=std::string(32,'c');
    sibling.vol_omap_oid_override=200;sibling.root_oid_override=0x2000+102;
    sibling.root_tree_type=kObjectTypeBtree;sibling.extentref_tree_oid=203;
    sibling.extentref_tree_type=kObjectPhysical|kObjectTypeBtree;
    sibling.snap_meta_tree_oid=0x3000+102;sibling.snap_meta_tree_type=kObjectTypeBtree;
    sibling.file_system_allocated_blocks=7;
    f.Put(199,BuildApsb(sibling,20,f.bs));
    f.Put(200,BuildOmap(201,20,f.bs,200,kObjectPhysical|kObjectTypeOmap,kObjectPhysical|kObjectTypeBtree));
    f.Put(201,BuildBtreeNode({OmapRecordSpec{0x2000+102,202,0,20},OmapRecordSpec{0x3000+102,204,0,20}},20,f.bs,0,
        201,kObjectPhysical|kObjectTypeBtree,kObjectTypeOmap));
    std::vector<Bytes> keys,values;for(const auto& record:records){keys.push_back(record.key);values.push_back(record.value);}
    f.Put(202,BuildRawLeafNode(keys,values,20,f.bs,0,0x2000+102,kObjectTypeBtree,kObjectTypeFsTree));
    const auto ref=Encode(ApplePhysicalExtentRecord{physical,1,kApplePhysicalExtentKindNew,30,1},EncodeApplePhysicalExtentRecord);
    f.Put(203,BuildRawLeafNode({ref.key},{ref.value},20,f.bs,0,203,kObjectPhysical|kObjectTypeBtree,kObjectTypeBlockRefTree));
    f.Put(204,BuildRawLeafNode({},{},20,f.bs,0,0x3000+102,kObjectTypeBtree,kObjectTypeSnapMetaTree));
    for(const auto block:{0ull,12ull}) f.Edit(block,[](auto& bytes){PutU32LE(bytes,0xB4,2);PutU64LE(bytes,0xC0,102);});
    f.Put(3,BuildBtreeNode({OmapRecordSpec{101,4,0,20},OmapRecordSpec{102,199,0,20}},20,f.bs,0,
        3,kObjectPhysical|kObjectTypeBtree,kObjectTypeOmap));
    AllocateSnapshotBlocks(f,{199,200,201,202,203,204,physical});
}
void SecondSnapshotPayload(SnapshotFixture& f, bool clone=false,
    std::uint64_t block=188, std::uint64_t xid=11, std::uint64_t physical=220)
{
    Fixture payload(static_cast<std::uint32_t>(f.bs));
    if(clone){
        payload.fs[0]=Inode(2,0,2,true,payload.bs);
        payload.fs.push_back(Drec(31,"clone.txt"));payload.fs.push_back(Inode(31,8,1,false,payload.bs));
        payload.fs.push_back(Encode(AppleFileExtentRecord{31,0,f.bs,220,0,static_cast<std::uint32_t>(f.bs)},EncodeAppleFileExtentRecord));
        payload.fs.push_back(Encode(AppleDataStreamIdRecord{31,1},EncodeAppleDataStreamIdRecord));
    }
    std::string error;
    for(auto& record:payload.fs) if(ReadU64LE(record.key,0).value()>>60==8){
        AppleFileExtentRecord extent;Check(DecodeAppleFileExtentRecord(record,payload.bs,extent,error),error);
        extent.physical_block=physical;record=Encode(extent,EncodeAppleFileExtentRecord);
    }
    Check(SortAppleBtreeRecords(payload.fs,AppleBtreeKeyOrder::FileSystemCaseSensitive,error),error);
    std::vector<Bytes> keys,values;for(const auto& record:payload.fs){keys.push_back(record.key);values.push_back(record.value);}
    f.Put(block,BuildRawLeafNode(keys,values,xid,f.bs,0,SnapshotFixture::root_oid,kObjectTypeBtree,kObjectTypeFsTree));
}
void SharePeerOmapNode(SnapshotFixture& f)
{
    SnapshotSibling(f,221);
    f.Edit(200,[](auto& bytes){PutU64LE(bytes,0x30,6);});
    f.Put(6,BuildBtreeNode({
        OmapRecordSpec{SnapshotFixture::root_oid,183,0,10},
        OmapRecordSpec{SnapshotFixture::root_oid,7,0,20},
        OmapRecordSpec{0x2000+102,202,0,20},
        OmapRecordSpec{SnapshotFixture::snap_oid,9,0,20},
        OmapRecordSpec{0x3000+102,204,0,20}},20,f.bs,0,
        6,kObjectPhysical|kObjectTypeBtree,kObjectTypeOmap));
}
void SnapshotIndexBranch(SnapshotFixture& f)
{
    SnapshotPayload(f);f.SecondSnapshot();
    std::string error;
    Check(SortAppleBtreeRecords(f.snapshots,AppleBtreeKeyOrder::FileSystemCaseSensitive,error),error);
    f.Inventory({10,11});
    f.Put(6,BuildBtreeNode({OmapRecordSpec{SnapshotFixture::root_oid,183,0,10},
        OmapRecordSpec{SnapshotFixture::root_oid,188,0,11},OmapRecordSpec{SnapshotFixture::root_oid,7,0,20},
        OmapRecordSpec{SnapshotFixture::snap_oid,9,0,20}},20,f.bs,0,6,kObjectPhysical|kObjectTypeBtree,kObjectTypeOmap));
    SnapshotLayer(f,191,11,{{220,1,kApplePhysicalExtentKindUpdate,30,-1}});
    SnapshotLayer(f,8,20,{});
    Bytes first(8),second(8),left(8),right(8),value(16);
    PutU64LE(first,0,10);PutU64LE(second,0,11);PutU64LE(left,0,186);PutU64LE(right,0,187);
    auto root=BuildRawLeafNode({first,second},{left,right},20,f.bs,0,185,kObjectPhysical|kObjectTypeBtree,0x13);
    PutU16LE(root,0x20,1);PutU16LE(root,0x22,1);
    PutU32LE(root,f.bs-40+20,16);PutU64LE(root,f.bs-40+32,3);f.Put(185,root);
    for(const auto block:{186ull,187ull}) {
        auto child=BuildRawLeafNode({block==186?first:second},{value},20,f.bs,0,block,
            kObjectPhysical|kObjectTypeBtreeNode,0x13);
        PutU16LE(child,0x20,2);
        // Nonroot nodes use block end, rather than the root footer boundary,
        // as the value offset origin. Keep the existing value bytes in place.
        PutU16LE(child,0x38+4,ReadU16LE(child,0x38+4).value()+40);
        std::fill(child.end()-40,child.end(),std::byte{0});f.Put(block,child);
    }
    AllocateSnapshotBlocks(f,{180,181,183,184,185,186,187,188,190,191,220});
    CurrentSnapshotAllocation(f,9);
}
std::vector<std::uint64_t> SnapshotMultilevel(SnapshotFixture& f)
{
    std::vector<Record> records{Inode(2,0,80,true,static_cast<std::uint32_t>(f.bs))};
    for(unsigned i=0;i<80;++i){records.push_back(Inode(100+i,0,1,false,static_cast<std::uint32_t>(f.bs)));records.push_back(Drec(100+i,"file-"+std::to_string(i)));}
    AppleBtreeOptions options;options.block_size=static_cast<std::uint32_t>(f.bs);options.xid=10;
    options.root_object_id=SnapshotFixture::root_oid;options.root_physical_block=183;
    options.first_child_object_id=0x7000;options.first_child_physical_block=230;
    options.subtype=kObjectTypeFsTree;options.key_order=AppleBtreeKeyOrder::FileSystemCaseSensitive;
    AppleSerializedBtree tree;std::string error;Check(SerializeAppleBtree(records,options,tree,error)&&tree.height>0,error);
    std::vector<OmapRecordSpec> mappings;std::vector<std::uint64_t> blocks{180,181,184,185};
    for(const auto& node:tree.objects){f.Put(node.location.physical_block,node.bytes);blocks.push_back(node.location.physical_block);
        if(node.location.physical_block!=183)mappings.push_back({node.location.object_id,node.location.physical_block,0,10});}
    f.SetMappings(mappings);AllocateSnapshotBlocks(f,blocks);
    blocks.erase(blocks.begin(),blocks.begin()+4);return blocks;
}
void ClearSnapshotAllocation(SnapshotFixture& f,std::uint64_t block)
{
    VectorRandomAccessSource source(f.image);std::string error;
    const auto cp=LoadAppleCheckpointView(source,0,source.SizeBytes(),error,20);Check(cp.has_value(),error);
    const auto& chunk=cp->spaceman.chunks[0];
    f.Edit(chunk.bitmap_block,[&](auto& b){b[block/8]&=~std::byte(1u<<(block%8));},false);
    f.Edit(cp->spaceman.devices[0].cibs[0].object.physical_block,[&](auto& b){PutU32LE(b,0x3C,chunk.free_count+1);});
    f.Edit(cp->spaceman.object.physical_block,[&](auto& b){PutU64LE(b,0x48,cp->spaceman.devices[0].free_count+1);});
}
bool Covered(const VerificationReport& report, VerificationCheck check)
{
    return std::any_of(report.coverage.begin(),report.coverage.end(),[&](const auto& c){
        return c.check==check&&c.state==VerificationCheckState::Verified;
    });
}
void ReferenceFailure(SnapshotFixture& f, std::uint64_t xid=10, std::uint64_t block=184)
{
    const auto report=VerifySnapshot(f);
    Check(report.outcome==VerificationOutcome::Incomplete&&Has(report,VerificationCode::ExtentReferenceInconsistent),Detail(report));
    Check(!Covered(report,VerificationCheck::SnapshotReachableAllocation),"failed historical graph cannot publish coverage");
    Check(report.covered_filesystem_records==0&&report.covered_physical_extents==0&&!report.payload_content_hashes_verified,
        "historical reference failure cannot publish partial proof or payload verification");
    const auto& finding=report.findings.front();
    Check(finding.check==VerificationCheck::SnapshotReachableAllocation&&finding.checkpoint_xid==xid&&
        finding.volume_oid==101&&finding.object_id==block&&finding.physical_block==block,"exact failing layer context");
    const auto again=VerifySnapshot(f);
    Check(again.findings==report.findings&&again.coverage==report.coverage&&again.repair==report.repair,
        "deterministic historical finding, coverage and repair refusal");
}
void SplitOffAllFreeChunk(Fixture& f)
{
    VectorRandomAccessSource source(f.image); std::string error;
    const auto cp = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error, 20);
    Check(cp.has_value(), error);
    const auto& chunk = cp->spaceman.chunks[0];
    Check(chunk.block_count == 512 && chunk.free_count >= 256, "split fixture geometry");
    f.Edit(cp->spaceman.object.physical_block, [](auto& b) {
        PutU32LE(b, 0x24, 256); PutU64LE(b, 0x38, 2);
    });
    f.Edit(cp->spaceman.devices[0].cibs[0].object.physical_block, [&](auto& b) {
        PutU32LE(b, 0x24, 2); PutU32LE(b, 0x38, 256);
        PutU32LE(b, 0x3C, chunk.free_count - 256);
        PutU64LE(b, 0x48, 20); PutU64LE(b, 0x50, 256);
        PutU32LE(b, 0x58, 256); PutU32LE(b, 0x5C, 256); PutU64LE(b, 0x60, 0);
    });
    VectorRandomAccessSource split(f.image);
    const auto control = LoadAppleCheckpointView(split, 0, split.SizeBytes(), error, 20);
    Check(control && control->spaceman.chunks.size() == 2 &&
        control->spaceman.chunks[1].allocation_bitmap.empty(), "canonical all-free chunk control: " + error);
}
void QueueSnapshotBlock(SnapshotFixture& f, std::uint64_t block)
{
    Fixture adapter(static_cast<std::uint32_t>(f.bs));
    adapter.image.swap(f.image);
    QueueMainBlock(adapter, block);
    adapter.image.swap(f.image);
}
}

int main(int argc, char** argv)
{
    unsigned failed = 0;
    unsigned seen = 0;
    const bool namespace_only = argc == 2 && std::string(argv[1]) == "--namespace-reuse-controls";
    const auto test = [&](const char* name, const auto& run) {
        ++seen;
        const auto label = std::string_view(name);
        // Current-metadata/r4 cases are the first group; retain the named
        // historical namespace, payload and cache-binding regressions as well.
        if (namespace_only && seen > 18 && label != "historical namespace mismatch" &&
            label != "snapshot payload reference multiplicity is exact" &&
            label != "snapshot payload reference owner is exact" &&
            label != "snapshot payload cannot be owned by a live sibling" &&
            label != "sibling live payload cannot alias another volume historical OMAP" &&
            label != "invalid live reference admission cannot publish requested payload observations" &&
            label != "closed live namespace reuse observes current payload only") return;
        try { run(); Pass(name); }
        catch (const std::exception& e) { ++failed; std::cout << "RED " << name << ": " << e.what() << '\n'; }
    };
    test("current metadata may not have two volume owners", [] {
        Fixture f; f.fs = {Inode(2,0,0,true,f.bs)}; f.refs.clear();
        f.spec.authoritative_seeded_main_blocks.clear();
        f.spec.volumes[0].additional_file_system_allocated_blocks=0;
        BuilderVolume sibling; sibling.oid=102; sibling.uuid_hex=std::string(32,'c');
        f.spec.volumes.push_back(sibling); f.Rebuild();
        VectorRandomAccessSource source(f.image); std::string error;
        const auto cp=LoadAppleCheckpointView(source,0,source.SizeBytes(),error,20); Check(cp.has_value(),error);
        f.Edit(5,[&](auto& b){PutU64LE(b,0x90,cp->volumes[0].extentref_tree->physical_block);});
        const auto report=Verify(f);
        Check(Has(report,VerificationCode::MetadataOwnerConflict),"metadata alias escaped: "+Detail(report));
    });
    test("snapshot-free peer retains typed owner refcount and coverage failures", [] {
        const auto probe = [](const std::vector<ApplePhysicalExtentRecord>& refs, const char* expected) {
            SnapshotFixture f; SnapshotPayload(f); AllocateSnapshotBlocks(f);
            SnapshotSibling(f,221); SnapshotLayer(f,203,20,refs);
            const auto report=VerifySnapshot(f);
            Check(report.outcome==VerificationOutcome::Incomplete&&
                Has(report,VerificationCode::ExtentReferenceInconsistent),Detail(report));
            const auto& finding=report.findings.front();
            Check(finding.check==VerificationCheck::SnapshotReachableAllocation&&finding.detail==expected,
                "canonical peer graph failure preserved");
            Check(!finding.volume_oid&&!finding.object_id&&!finding.physical_block,
                "all-peer census does not fabricate unavailable owner context");
            Check(!Covered(report,VerificationCheck::SnapshotReachableAllocation)&&
                report.covered_filesystem_records==0&&report.covered_physical_extents==0,
                "peer failure publishes no partial coverage or census");
            Check(report.findings==VerifySnapshot(f).findings,"deterministic typed peer failure");
        };
        probe({{221,1,kApplePhysicalExtentKindNew,31,1}},"AppleVolumePhysicalExtentOwnerMismatch");
        probe({{221,1,kApplePhysicalExtentKindNew,30,2}},"AppleVolumePhysicalExtentRefcountMismatch");
        probe({{221,1,kApplePhysicalExtentKindNew,30,1},{222,1,kApplePhysicalExtentKindNew,30,1}},
            "AppleVolumePhysicalExtentCoverageIncomplete");
    });
    test("explicit current metadata completes with retained payload and signed empty live graph", [] {
        SnapshotFixture f;SnapshotPayload(f);AllocateSnapshotBlocks(f);CurrentSnapshotAllocation(f);
        const auto report=VerifyCurrentSnapshot(f);
        Check(report.outcome==VerificationOutcome::Complete&&report.allocation_census.has_value(),Detail(report));
        Check(Covered(report,VerificationCheck::SnapshotReachableAllocation)&&
            Covered(report,VerificationCheck::PayloadReferences)&&Covered(report,VerificationCheck::PayloadAllocatorOwnership)&&
            Covered(report,VerificationCheck::CurrentOwnershipCensus),"all required current graph checks completed");
        Check(!Covered(report,VerificationCheck::HistoricalReachability)&&!Covered(report,VerificationCheck::CompleteAllocationAccounting),
            "current completion does not invent historical or full allocation proof");
        Check(report.allocation_census->current_metadata_blocks==18&&report.allocation_census->current_payload_blocks==0,
            "current OMAP snapshot-index is counted once, retained payload is not current");
        Check(report.allocation_census->unattributed_main_blocks==5 &&
            report.allocation_census->unattributed_main_ranges==std::vector<VerificationBlockRange>{{180,2},{183,2},{220,1}},
            "retained APSB OMAP FS refs and payload stay outside current graph census");
        Check(Has(VerifySnapshot(f),VerificationCode::SnapshotAccountingUnsupported),"same image still refuses broad verification");
        Check(report.allocation_census==VerifyCurrentSnapshot(f).allocation_census,"deterministic current census");
    });
    test("explicit current metadata resolves live signed references with two distinct peer payloads", [] {
        SnapshotFixture f;SnapshotPayload(f);AllocateSnapshotBlocks(f);SnapshotSibling(f,221);
        SecondSnapshotPayload(f,false,7,20,220);SnapshotLayer(f,8,20,{});CurrentSnapshotAllocation(f,8);
        const auto report=VerifyCurrentSnapshot(f);
        Check(report.outcome==VerificationOutcome::Complete&&report.allocation_census,Detail(report));
        Check(report.allocation_census->current_payload_blocks==2&&report.covered_physical_extents==1,
            "resolved current payloads count each peer once, not once per snapshot view");
        f.scope.volume_oid=102;f.scope.volume_uuid_hex=std::string(32,'c');
        const auto peer=VerifyCurrentSnapshot(f);
        Check(peer.outcome==VerificationOutcome::Complete&&peer.allocation_census==report.allocation_census,
            "either selected peer requires the same complete container current census");
    });
    test("current snapshot metadata refusal publishes no census after owner conflict", [] {
        SnapshotFixture f;SnapshotPayload(f);AllocateSnapshotBlocks(f);SharePeerOmapNode(f);CurrentSnapshotAllocation(f);
        const auto report=VerifyCurrentSnapshot(f);
        Check(Has(report,VerificationCode::MetadataOwnerConflict)&&report.outcome==VerificationOutcome::Incomplete,Detail(report));
        Check(!report.allocation_census&&!report.covered_filesystem_records&&!report.covered_physical_extents,
            "typed historical dependency conflict blocks current metadata completion");
    });
    test("current snapshot metadata preserves allocation minima and late quota refusal", [] {
        SnapshotFixture f;SnapshotPayload(f);AllocateSnapshotBlocks(f);CurrentSnapshotAllocation(f,6);
        auto report=VerifyCurrentSnapshot(f);
        Check(Has(report,VerificationCode::AllocatedCountUnderstated)&&!report.allocation_census,Detail(report));
        CurrentSnapshotAllocation(f,7);f.Edit(4,[](auto& bytes){PutU64LE(bytes,0x50,6);});
        report=VerifyCurrentSnapshot(f);
        Check(Has(report,VerificationCode::QuotaOrReserveInconsistent)&&!report.allocation_census&&
            !report.covered_filesystem_records&&!report.covered_physical_extents,Detail(report));
    });
    test("current metadata with snapshots does not satisfy required payload integrity", [] {
        SnapshotFixture f;SnapshotPayload(f);AllocateSnapshotBlocks(f);CurrentSnapshotAllocation(f);
        VerificationScope scope;scope.source_identity="current-snapshot-required-hashes";scope.exact=f.scope;
        scope.require_payload_content_hashes=true;TracedSource source(f.image);
        const auto report=ApfsVerifier::Verify(source,scope);
        Check(report.outcome==VerificationOutcome::Incomplete&&Has(report,VerificationCode::CoverageMissing)&&
            !report.allocation_census&&!report.payload_content_hashes_verified&&!report.whole_volume_verified&&
            !source.Touched(220*f.bs,2*f.bs),"independent expected payload integrity remains unavailable");
    });
    test("current snapshot graph is bound to reread raw FS and signed reference records", [] {
        for(const bool observe_payload:{false,true}) for(const auto block:{7ull,8ull}) {
            SnapshotFixture f;SnapshotPayload(f);AllocateSnapshotBlocks(f);CurrentSnapshotAllocation(f);
            VerificationScope scope;scope.source_identity="changed-current-snapshot-records";scope.exact=f.scope;
            scope.observe_payload_content=observe_payload;
            TracedSource control(f.image);const auto healthy=ApfsVerifier::Verify(control,scope);
            Check(healthy.outcome==VerificationOutcome::Complete,Detail(healthy));
            const auto ordinal=std::count(control.reads.begin(),control.reads.end(),std::pair<std::uint64_t,std::size_t>{block*f.bs,f.bs});
            Check(ordinal>1,"control observes canonical catalog before current reread");
            const auto original=f.Block(block);
            if(block==7) SecondSnapshotPayload(f,false,7,20,220);else SnapshotLayer(f,8,20,{});
            const auto changed=f.Block(block);f.Put(block,original);
            const auto before=f.image;
            ChangedLiveReadSource source(f.image,block*f.bs,static_cast<std::size_t>(ordinal),changed);
            const auto report=ApfsVerifier::Verify(source,scope);
            Check(Has(report,VerificationCode::IdentityMismatch)&&Detail(report)=="VerifierCurrentSnapshotLiveRecordsChanged"&&
                report.outcome==VerificationOutcome::Incomplete&&!report.allocation_census&&
                !report.covered_filesystem_records&&!report.covered_physical_extents&&!report.payload_projection,
                "later valid-but-different raw records cannot inherit an earlier signed graph: "+Detail(report));
            Check(f.image==before,"changing synthetic read source never mutates backing image");
        }
    });
    test("current snapshot completion requires the original sticky budgets and source reads", [] {
        SnapshotFixture f;SnapshotPayload(f);AllocateSnapshotBlocks(f);CurrentSnapshotAllocation(f);
        VerificationScope scope;scope.source_identity="bounded-current-snapshot";scope.exact=f.scope;
        TracedSource control(f.image);const auto healthy=ApfsVerifier::Verify(control,scope);
        Check(healthy.outcome==VerificationOutcome::Complete&&healthy.allocation_census,Detail(healthy));
        scope.max_record_bytes=healthy.read_budget->Consumed().record_bytes-1;
        TracedSource limited(f.image);const auto budget=ApfsVerifier::Verify(limited,scope);
        Check(Has(budget,VerificationCode::BudgetExceeded)&&!budget.allocation_census&&
            !budget.covered_filesystem_records&&!budget.covered_physical_extents,
            "late narrow-scope materialization failure cannot publish a computed census");
        scope.max_record_bytes=1ull<<28;
        TracedSource failed(f.image);failed.fail_at=control.reads.size();const auto io=ApfsVerifier::Verify(failed,scope);
        Check(Has(io,VerificationCode::ReadFailure)&&!io.allocation_census&&
            !io.covered_filesystem_records&&!io.covered_physical_extents,"late current read failure cannot publish proof");
    });
    test("current OMAP snapshot index has complete routing proof and unique census", [] {
        SnapshotFixture f;SnapshotIndexBranch(f);const auto report=VerifyCurrentSnapshot(f);
        Check(report.outcome==VerificationOutcome::Complete&&report.allocation_census,Detail(report));
        Check(report.allocation_census->current_metadata_blocks==20&&report.allocation_census->current_payload_blocks==0&&
            Covered(report,VerificationCheck::InternalSeparatorRouting),"all three live index nodes counted once with routing proof");
        f.Edit(185,[](auto& bytes){const auto [at,length]=KeyRegion(bytes,0);(void)length;PutU64LE(bytes,at,9);});
        const auto bad=VerifyCurrentSnapshot(f);
        Check(Has(bad,VerificationCode::TreeOrderInconsistent)&&!bad.allocation_census&&
            !bad.covered_filesystem_records&&!bad.covered_physical_extents,
            "checksum-valid index separator cannot hide valid children: "+Detail(bad));
    });
    test("canonical owner capture covers dependency footprint and selected versions only", [] {
        SnapshotFixture f; SnapshotPayload(f); AllocateSnapshotBlocks(f);
        const auto nodes=HistoricalOmap(f,true);
        const auto before=f.image; VectorRandomAccessSource source(f.image); std::string error;
        const auto cp=LoadAppleCheckpointView(source,0,source.SizeBytes(),error,20); Check(cp.has_value(),error);
        AppleSnapshotCatalogRecords catalog; std::vector<AppleSnapshotMetadataClaim> owners;
        Check(LoadAppleSnapshotCatalog(source,*cp,101,catalog,owners,error),error);
        std::vector<std::uint64_t> footprint;
        for(const auto& owner:owners) {
            footprint.push_back(owner.physical_block);
            Check(owner.block_count==1&&owner.object_id&&owner.object_xid&&owner.map_oid,
                "typed immutable object identity and bounded range");
            Check(owner.object_xid<=owner.selection_xid&&owner.selection_xid<=20&&owner.view_xid<=20,
                "header and selection bounds retained independently from logical view");
            Check(!owner.mapping_xid||(owner.object_xid<=*owner.mapping_xid&&*owner.mapping_xid<=owner.selection_xid),
                "selected virtual mapping bound retained");
            Check(owner.physical_block!=250,"unselected OMAP targets do not become reachable owners");
        }
        std::sort(footprint.begin(),footprint.end());footprint.erase(std::unique(footprint.begin(),footprint.end()),footprint.end());
        Check(footprint==catalog.metadata_blocks,"every canonical catalog dependency has a typed owner");
        for(const auto block:nodes) Check(std::any_of(owners.begin(),owners.end(),[&](const auto& owner){
            return owner.volume_oid==101&&owner.map_oid==192&&owner.view_xid==10&&
                owner.physical_block==block&&owner.object_id==block&&owner.object_xid==10&&
                owner.metadata_class==(block==192?AppleSnapshotMetadataClass::OmapObject:AppleSnapshotMetadataClass::OmapNode);
        }),"historical multi-level OMAP nodes retain their authenticated headers");
        Check(std::any_of(owners.begin(),owners.end(),[](const auto& owner){
            return owner.volume_oid==101&&owner.map_oid==192&&owner.view_xid==10&&owner.selection_xid==10&&
                owner.object_id==SnapshotFixture::root_oid&&owner.object_xid==10&&owner.physical_block==183&&
                owner.mapping_xid==10&&owner.metadata_class==AppleSnapshotMetadataClass::FileSystemNode;
        }),"selected historical virtual root retains exact OID XID and mapping provenance");
        Check(before==f.image,"owner capture is read-only");
    });
    test("authenticated immutable OMAP sharing within a volume stays admitted", [] {
        SnapshotFixture f; SnapshotPayload(f); AllocateSnapshotBlocks(f); HistoricalOmap(f);
        f.Edit(192,[](auto& bytes){PutU64LE(bytes,0x30,6);});
        const auto report=VerifySnapshot(f);
        Check(report.outcome==VerificationOutcome::Refused&&Has(report,VerificationCode::SnapshotAccountingUnsupported),Detail(report));
        Check(Covered(report,VerificationCheck::SnapshotReachableAllocation),"same owner may share a node through distinct maps and views");
        Check(!Has(report,VerificationCode::MetadataOwnerConflict),"authenticated same-volume sharing is not a conflicting owner");
    });
    test("canonical reachable OMAP node cannot have two volume owners", [] {
        SnapshotFixture f; SnapshotPayload(f); AllocateSnapshotBlocks(f); SharePeerOmapNode(f);
        const auto report=VerifySnapshot(f);
        Check(report.outcome==VerificationOutcome::Incomplete&&Has(report,VerificationCode::MetadataOwnerConflict),Detail(report));
        const auto& finding=report.findings.front();
        Check(finding.check==VerificationCheck::SnapshotReachableAllocation&&finding.volume_oid==102&&
            finding.object_id==6&&finding.physical_block==6&&finding.checkpoint_xid==20,
            "conflict identifies actual peer owner and node header");
        Check(!Covered(report,VerificationCheck::SnapshotReachableAllocation)&&report.covered_filesystem_records==0&&
            report.covered_physical_extents==0,"owner conflict cannot publish proof");
        Check(report.findings==VerifySnapshot(f).findings,"deterministic alias refusal");
    });
    test("late canonical owner failure clears catalog and claims", [] {
        SnapshotFixture f; SnapshotPayload(f); AllocateSnapshotBlocks(f); HistoricalOmap(f,true);
        VectorRandomAccessSource source(f.image); std::string error;
        const auto cp=LoadAppleCheckpointView(source,0,source.SizeBytes(),error,20); Check(cp.has_value(),error);
        f.Edit(183,[](auto& bytes){PutU64LE(bytes,0x08,SnapshotFixture::root_oid+1);});
        VectorRandomAccessSource damaged(f.image);
        AppleSnapshotCatalogRecords catalog; catalog.metadata_blocks.push_back(999);
        std::vector<AppleSnapshotMetadataClaim> owners(1);
        Check(!LoadAppleSnapshotCatalog(damaged,*cp,101,catalog,owners,error),"wrong selected root OID must fail");
        Check(catalog.metadata_blocks.empty()&&catalog.snapshots.empty()&&catalog.inventory.empty()&&
            catalog.live.filesystem.empty()&&owners.empty(),"no partial authenticated owners on late failure");
        Check(error.find("ObjectId")!=std::string::npos||error.find("Identity")!=std::string::npos,error);
    });
    test("canonical virtual child claims preserve each actual OMAP version", [] {
        SnapshotFixture f; const auto blocks=SnapshotMultilevel(f);
        VectorRandomAccessSource source(f.image); std::string error;
        const auto cp=LoadAppleCheckpointView(source,0,source.SizeBytes(),error,20); Check(cp.has_value(),error);
        AppleSnapshotCatalogRecords catalog; std::vector<AppleSnapshotMetadataClaim> owners;
        Check(LoadAppleSnapshotCatalog(source,*cp,101,catalog,owners,error),error);
        for(const auto block:blocks) {
            const auto raw=f.Block(block);const auto oid=ReadU64LE(raw,8).value();
            Check(std::any_of(owners.begin(),owners.end(),[&](const auto& owner){
                return owner.volume_oid==101&&owner.map_oid==181&&owner.view_xid==10&&owner.selection_xid==10&&
                    owner.object_id==oid&&owner.object_xid==10&&owner.physical_block==block&&owner.mapping_xid==10&&
                    owner.metadata_class==AppleSnapshotMetadataClass::FileSystemNode;
            }),"each child uses its decoded node OID and selected mapping XID, not its root identity");
        }
    });
    test("owner capture refuses a checksum-valid child newer than its selected mapping", [] {
        SnapshotFixture f;const auto blocks=SnapshotMultilevel(f);
        const auto child=*std::find_if(blocks.begin(),blocks.end(),[](auto block){return block!=183;});
        f.Edit(child,[](auto& bytes){PutU64LE(bytes,0x10,11);});
        VectorRandomAccessSource source(f.image);std::string error;
        const auto cp=LoadAppleCheckpointView(source,0,source.SizeBytes(),error,20);Check(cp.has_value(),error);
        AppleSnapshotCatalogRecords catalog;std::vector<AppleSnapshotMetadataClaim> owners(1);
        Check(!LoadAppleSnapshotCatalog(source,*cp,101,catalog,owners,error)&&error=="CatalogBtreeFutureXid",error);
        Check(owners.empty()&&catalog.metadata_blocks.empty()&&catalog.snapshots.empty(),
            "a valid checksum and current NX bound cannot replace selected child version authority");
    });
    test("canonical owner budget remains sticky and clears late outputs", [] {
        SnapshotFixture f; SnapshotPayload(f); AllocateSnapshotBlocks(f); HistoricalOmap(f,true);
        VectorRandomAccessSource source(f.image); std::string error;
        const auto cp=LoadAppleCheckpointView(source,0,source.SizeBytes(),error,20); Check(cp.has_value(),error);
        AppleSnapshotCatalogRecords catalog; std::vector<AppleSnapshotMetadataClaim> owners;
        auto control_budget=std::make_shared<ApfsReadBudget>(65536,1ull<<28,1000000,1ull<<28);
        BudgetedRandomAccessSource control(source,control_budget);
        Check(LoadAppleSnapshotCatalog(control,*cp,101,catalog,owners,error),error);
        Check(!owners.empty()&&control_budget->Consumed().record_bytes>1,"bounded owner control succeeds");
        auto budget=std::make_shared<ApfsReadBudget>(65536,1ull<<28,1000000,control_budget->Consumed().record_bytes-1);
        TracedSource traced(f.image);BudgetedRandomAccessSource limited(traced,budget);
        Check(!LoadAppleSnapshotCatalog(limited,*cp,101,catalog,owners,error)&&budget->Failed(),
            "last canonical owner walk materialization must obey inherited allowance");
        Check(owners.empty()&&catalog.metadata_blocks.empty()&&catalog.inventory.empty()&&catalog.snapshots.empty(),
            "late budget failure clears all proof outputs");
        const auto reads=traced.reads.size();
        Check(!LoadAppleSnapshotCatalog(limited,*cp,101,catalog,owners,error)&&traced.reads.size()==reads&&
            error==budget->Failure(),"retry cannot refresh the caller allowance or read source");
    });
    test("APSB cannot understate current unique ownership", [] {
        Fixture f; f.Edit(4,[](auto& b){PutU64LE(b,0x58,6);});
        const auto report=Verify(f);
        Check(Has(report,VerificationCode::AllocatedCountUnderstated),"allocated undercount escaped: "+Detail(report));
    });
    test("historical snapshot unallocated metadata precedes coverage refusal", [] {
        SnapshotFixture f;
        VerificationScope scope; scope.source_identity="snapshot-allocation-corruption";scope.exact=f.scope;
        const auto before=f.image; TracedSource source(f.image);
        const auto report=ApfsVerifier::Verify(source,scope);
        Check(before==f.image,"snapshot image unchanged");
        Check(Has(report,VerificationCode::MetadataAllocationInconsistent),"snapshot free metadata escaped: "+Detail(report));
        Check(!report.whole_volume_verified,"historical proof never claims full volume");
    });

    test("unattributed main allocation stays typed and unproven", [] {
        Fixture f;for(auto block:{221ull,222ull,223ull})f.spec.authoritative_seeded_main_blocks.emplace_back(block,Bytes(f.bs,std::byte{0x4a}));
        f.Rebuild();const auto report=Verify(f);
        Check(report.outcome==VerificationOutcome::Complete&&report.allocation_census.has_value(),Detail(report));
        Check(report.allocation_census->current_payload_blocks==1,"payload counted once");
        Check(std::any_of(report.allocation_census->unattributed_main_ranges.begin(),report.allocation_census->unattributed_main_ranges.end(),
            [](const auto& r){return r.physical_block==221&&r.block_count==3;}),"contiguous unattributed allocation is one interval");
        Check(!Covered(report,VerificationCheck::CompleteAllocationAccounting),"no orphan health claim");
        Check(report.allocation_census==Verify(f).allocation_census,"deterministic census");
    });
    test("internal pool reservation cannot conceal unattributed allocation", [] {
        Fixture f;VectorRandomAccessSource source(f.image);std::string error;
        const auto cp=LoadAppleCheckpointView(source,0,source.SizeBytes(),error,20);Check(cp.has_value(),error);
        const auto& pool=cp->spaceman.internal_pool;std::uint64_t index=0;
        while(index<pool.block_count&&(std::to_integer<unsigned>(pool.active_bitmaps[0].bytes[index/8])&(1u<<(index%8))))++index;
        Check(index<pool.block_count,"free internal bit exists");
        f.Edit(pool.active_bitmaps[0].physical_block,[&](auto& b){b[index/8]|=std::byte(1u<<(index%8));},false);
        const auto report=Verify(f);Check(report.outcome==VerificationOutcome::Complete&&report.allocation_census.has_value(),Detail(report));
        const auto block=pool.base_block+index;
        Check(std::any_of(report.allocation_census->unattributed_internal_ranges.begin(),report.allocation_census->unattributed_internal_ranges.end(),
            [&](const auto& r){return r.physical_block<=block&&block-r.physical_block<r.block_count;}),"internal allocation remains visible");
    });
    test("clone sharing consumes one physical block", [] {
        Fixture f;f.fs[0]=Inode(2,0,2,true,f.bs);f.fs.push_back(Drec(31,"clone.txt"));
        f.fs.push_back(Inode(31,8,1,false,f.bs));
        f.fs.push_back(Encode(AppleFileExtentRecord{31,0,f.bs,220,0,f.bs},EncodeAppleFileExtentRecord));
        f.fs.push_back(Encode(AppleDataStreamIdRecord{31,1},EncodeAppleDataStreamIdRecord));
        f.refs[0]=Encode(ApplePhysicalExtentRecord{220,1,1,30,2},EncodeApplePhysicalExtentRecord);f.Rebuild();
        const auto report=Verify(f);Check(report.outcome==VerificationOutcome::Complete,Detail(report));
        Check(report.allocation_census&&report.allocation_census->current_payload_blocks==1,"clone refcount is not allocation count");
    });
    test("allocated snapshot remains refused for complete historical ownership", [] {
        SnapshotFixture f;AllocateSnapshotBlocks(f);const auto report=VerifySnapshot(f);
        Check(report.outcome==VerificationOutcome::Refused&&Has(report,VerificationCode::SnapshotAccountingUnsupported),Detail(report));
        Check(Covered(report,VerificationCheck::SnapshotReachableAllocation),"snapshot reachability coverage established");
        Check(!Covered(report,VerificationCheck::HistoricalReachability),"historical census remains unproven");
    });
    test("historical OMAP header requires its own main allocation bit", [] {
        SnapshotFixture f; AllocateSnapshotBlocks(f);
        const auto valid=VerifySnapshot(f);
        Check(valid.outcome==VerificationOutcome::Refused &&
            Has(valid,VerificationCode::SnapshotAccountingUnsupported) &&
            Covered(valid,VerificationCheck::SnapshotReachableAllocation),Detail(valid));
        ClearSnapshotAllocation(f,181);
        const auto invalid=VerifySnapshot(f);
        Check(invalid.outcome==VerificationOutcome::Incomplete &&
            Has(invalid,VerificationCode::MetadataAllocationInconsistent) &&
            invalid.findings[0].physical_block==181 && invalid.findings[0].checkpoint_xid==10,
            "snapshot OMAP header cannot be unallocated: "+Detail(invalid));
        Check(!invalid.allocation_census && invalid.covered_filesystem_records==0 &&
            invalid.covered_physical_extents==0,"invalid snapshot supplies no partial census");
    });
    test("historical payload free bit is not hidden by inventory refusal", [] {
        SnapshotFixture f;SnapshotPayload(f);AllocateSnapshotBlocks(f,{180,181,183,184,185});
        const auto report=VerifySnapshot(f);
        Check(Has(report,VerificationCode::PayloadAllocationInconsistent),Detail(report));
        Check(report.findings[0].checkpoint_xid==10&&report.findings[0].physical_block==220,"exact snapshot and block context");
    });
    test("historical payload and metadata collision", [] {
        SnapshotFixture f;SnapshotPayload(f,183);AllocateSnapshotBlocks(f);
        const auto report=VerifySnapshot(f);Check(Has(report,VerificationCode::PayloadMetadataOverlap),Detail(report));
    });
    test("historical namespace mismatch", [] {
        SnapshotFixture f;SnapshotPayload(f);AllocateSnapshotBlocks(f);
        Fixture payload;payload.fs[2]=Inode(30,8,2,false,payload.bs);payload.Rebuild();
        std::vector<Bytes> keys,values;for(const auto& r:payload.spec.volumes[0].filesystem_records){keys.push_back(r.key);values.push_back(r.value);}
        f.Put(183,BuildRawLeafNode(keys,values,10,f.bs,0,SnapshotFixture::root_oid,kObjectTypeBtree,kObjectTypeFsTree));
        const auto report=VerifySnapshot(f);Check(Has(report,VerificationCode::NamespaceOrLinkInconsistent),Detail(report));
    });
    test("two exact snapshots may reach the same payload", [] {
        SnapshotFixture f;SnapshotPayload(f);f.SecondSnapshot();
        auto second=f.Block(183);PutU64LE(second,0x10,11);f.Put(188,second);
        AllocateSnapshotBlocks(f,{180,181,183,184,185,188,190,191,220});
        const auto report=VerifySnapshot(f);Check(report.outcome==VerificationOutcome::Refused&&Has(report,VerificationCode::SnapshotAccountingUnsupported),Detail(report));
        Check(Covered(report,VerificationCheck::SnapshotReachableAllocation),"payload reachability verified without historical refcount guess");
    });
    test("snapshot reference layer needs complete first NEW graph", [] {
        SnapshotFixture f;SnapshotPayload(f);AllocateSnapshotBlocks(f);SnapshotLayer(f,184,10,{});
        ReferenceFailure(f);
    });
    test("first snapshot UPDATE cannot invent historical authority", [] {
        SnapshotFixture f;SnapshotPayload(f);AllocateSnapshotBlocks(f);
        SnapshotLayer(f,184,10,{{220,1,kApplePhysicalExtentKindUpdate,30,1}});ReferenceFailure(f);
    });
    test("snapshot payload reference multiplicity is exact", [] {
        SnapshotFixture f;SnapshotPayload(f);AllocateSnapshotBlocks(f);
        SnapshotLayer(f,184,10,{{220,1,kApplePhysicalExtentKindNew,30,2}});ReferenceFailure(f);
    });
    test("snapshot payload reference owner is exact", [] {
        SnapshotFixture f;SnapshotPayload(f);AllocateSnapshotBlocks(f);
        SnapshotLayer(f,184,10,{{220,1,kApplePhysicalExtentKindNew,31,1}});ReferenceFailure(f);
    });
    test("snapshot reference-only interval cannot hide behind allocated payload", [] {
        SnapshotFixture f;SnapshotPayload(f);AllocateSnapshotBlocks(f,{180,181,183,184,185,220,221});
        SnapshotLayer(f,184,10,{{220,1,kApplePhysicalExtentKindNew,30,1},{221,1,kApplePhysicalExtentKindNew,30,1}});
        ReferenceFailure(f);
    });
    test("chronological UPDATE adds one per-view clone reference", [] {
        SnapshotFixture f;SnapshotPayload(f);f.SecondSnapshot();SecondSnapshotPayload(f,true);
        SnapshotLayer(f,191,11,{{220,1,kApplePhysicalExtentKindUpdate,30,1}});
        SnapshotLayer(f,8,20,{{220,1,kApplePhysicalExtentKindUpdate,30,-2}});
        AllocateSnapshotBlocks(f,{180,181,183,184,185,188,190,191,220});const auto report=VerifySnapshot(f);
        Check(Covered(report,VerificationCheck::SnapshotReachableAllocation)&&Has(report,VerificationCode::SnapshotAccountingUnsupported),Detail(report));
        Check(!Covered(report,VerificationCheck::HistoricalReachability)&&!report.whole_volume_verified,
            "per-view clone proof is not complete retained ownership");
    });
    test("second snapshot NEW cannot redefine retained payload", [] {
        SnapshotFixture f;SnapshotPayload(f);f.SecondSnapshot();SecondSnapshotPayload(f);
        SnapshotLayer(f,191,11,{{220,1,kApplePhysicalExtentKindNew,30,1}});
        AllocateSnapshotBlocks(f,{180,181,183,184,185,188,190,191,220});ReferenceFailure(f,11,191);
    });
    test("second snapshot signed decrement cannot underflow", [] {
        SnapshotFixture f;SnapshotPayload(f);f.SecondSnapshot();
        SnapshotLayer(f,191,11,{{220,1,kApplePhysicalExtentKindUpdate,30,-2}});
        AllocateSnapshotBlocks(f,{180,181,183,184,185,188,190,191,220});ReferenceFailure(f,11,191);
    });
    test("second snapshot clone increment must match exact mappings", [] {
        SnapshotFixture f;SnapshotPayload(f);f.SecondSnapshot();SecondSnapshotPayload(f,true);
        SnapshotLayer(f,191,11,{{220,1,kApplePhysicalExtentKindUpdate,30,2}});
        AllocateSnapshotBlocks(f,{180,181,183,184,185,188,190,191,220});ReferenceFailure(f,11,191);
    });
    test("empty later snapshot records exact decrement without reclaiming history", [] {
        SnapshotFixture f;SnapshotPayload(f);f.SecondSnapshot();
        SnapshotLayer(f,191,11,{{220,1,kApplePhysicalExtentKindUpdate,30,-1}});
        SnapshotLayer(f,8,20,{});
        AllocateSnapshotBlocks(f,{180,181,183,184,185,188,190,191,220});const auto report=VerifySnapshot(f);
        Check(Covered(report,VerificationCheck::SnapshotReachableAllocation)&&Has(report,VerificationCode::SnapshotAccountingUnsupported),Detail(report));
        Check(!report.allocation_census&&!report.whole_volume_verified,"no retained allocation reclaim proof");
    });
    test("empty later snapshot cannot omit its signed decrement", [] {
        SnapshotFixture f;SnapshotPayload(f);f.SecondSnapshot();
        AllocateSnapshotBlocks(f,{180,181,183,184,185,188,190,191,220});ReferenceFailure(f,11,191);
    });
    test("historical dependency OMAP free bit precedes broad coverage refusal", [] {
        SnapshotFixture f;SnapshotPayload(f);AllocateSnapshotBlocks(f);ClearSnapshotAllocation(f,6);
        const auto report=VerifySnapshot(f);
        Check(Has(report,VerificationCode::MetadataAllocationInconsistent)&&report.findings[0].physical_block==6&&
            !Covered(report,VerificationCheck::SnapshotReachableAllocation),Detail(report));
    });
    test("historical payload may not alias catalog dependency OMAP", [] {
        SnapshotFixture f;SnapshotPayload(f,6);AllocateSnapshotBlocks(f);
        const auto report=VerifySnapshot(f);
        Check(Has(report,VerificationCode::PayloadMetadataOverlap)&&report.findings[0].checkpoint_xid==10,Detail(report));
    });
    test("distinct historical OMAP ownership remains a bounded subset", [] {
        SnapshotFixture f;SnapshotPayload(f);AllocateSnapshotBlocks(f);HistoricalOmap(f,true);
        const auto report=VerifySnapshot(f);
        Check(Covered(report,VerificationCheck::SnapshotReachableAllocation)&&
            Has(report,VerificationCode::SnapshotAccountingUnsupported),Detail(report));
        Check(!Covered(report,VerificationCheck::HistoricalReachability)&&!report.payload_content_hashes_verified,
            "OMAP traversal is not ownership of every unused mapped version");
    });
    for(const auto block:{192ull,193ull}) test(block==192?"historical OMAP object must be allocated":"historical OMAP root must be allocated", [=] {
        SnapshotFixture f;SnapshotPayload(f);AllocateSnapshotBlocks(f);HistoricalOmap(f);ClearSnapshotAllocation(f,block);
        const auto report=VerifySnapshot(f);
        Check(Has(report,VerificationCode::MetadataAllocationInconsistent)&&report.findings[0].physical_block==block&&
            !Covered(report,VerificationCheck::SnapshotReachableAllocation),Detail(report));
    });
    test("historical OMAP child allocation is checked beyond the root", [] {
        SnapshotFixture f;SnapshotPayload(f);AllocateSnapshotBlocks(f);const auto blocks=HistoricalOmap(f,true);
        const auto child=*std::find_if(blocks.begin(),blocks.end(),[](auto block){return block>=194;});
        ClearSnapshotAllocation(f,child);const auto report=VerifySnapshot(f);
        Check(Has(report,VerificationCode::MetadataAllocationInconsistent)&&report.findings[0].physical_block==child&&
            !Covered(report,VerificationCheck::SnapshotReachableAllocation),Detail(report));
    });
    test("allocated historical OMAP object cannot be deferred free", [] {
        SnapshotFixture f;SnapshotPayload(f);AllocateSnapshotBlocks(f);HistoricalOmap(f);QueueSnapshotBlock(f,192);
        const auto report=VerifySnapshot(f);
        Check(Has(report,VerificationCode::MetadataAllocationInconsistent)&&report.findings[0].physical_block==192&&
            report.findings[0].detail=="VerifierCurrentMetadataQueuedForFree",Detail(report));
    });
    test("snapshot payload cannot masquerade as a distinct historical OMAP root", [] {
        SnapshotFixture f;SnapshotPayload(f,193);AllocateSnapshotBlocks(f);HistoricalOmap(f);
        const auto report=VerifySnapshot(f);
        Check(Has(report,VerificationCode::PayloadMetadataOverlap)&&report.findings[0].checkpoint_xid==10,Detail(report));
    });
    test("historical OMAP checksum failure is retained before ownership proof", [] {
        SnapshotFixture f;SnapshotPayload(f);AllocateSnapshotBlocks(f);HistoricalOmap(f);
        f.Edit(193,[](auto& bytes){bytes[0]^=std::byte{1};},false);
        const auto report=VerifySnapshot(f);
        Check(Has(report,VerificationCode::ChecksumMismatch)&&!Covered(report,VerificationCheck::SnapshotReachableAllocation),Detail(report));
    });
    test("historical OMAP cannot select a root with a different object identity", [] {
        SnapshotFixture f;SnapshotPayload(f);AllocateSnapshotBlocks(f);HistoricalOmap(f);
        f.Put(193,BuildBtreeNode({OmapRecordSpec{SnapshotFixture::root_oid,184,0,10}},10,f.bs,0,193,
            kObjectPhysical|kObjectTypeBtree,kObjectTypeOmap));
        const auto report=VerifySnapshot(f);
        Check(report.outcome!=VerificationOutcome::Complete&&!Covered(report,VerificationCheck::SnapshotReachableAllocation)&&
            !Has(report,VerificationCode::SnapshotAccountingUnsupported),Detail(report));
    });
    test("retained snapshot and disjoint sibling pass bounded owner census", [] {
        SnapshotFixture f;SnapshotPayload(f);AllocateSnapshotBlocks(f);HistoricalOmap(f);SnapshotSibling(f,221);
        const auto report=VerifySnapshot(f);
        Check(Covered(report,VerificationCheck::SnapshotReachableAllocation)&&
            Has(report,VerificationCode::SnapshotAccountingUnsupported),Detail(report));
    });
    test("snapshot payload cannot be owned by a live sibling", [] {
        SnapshotFixture f;SnapshotPayload(f);AllocateSnapshotBlocks(f);SnapshotSibling(f,220);
        const auto report=VerifySnapshot(f);
        Check(Has(report,VerificationCode::CrossVolumePayloadOverlap)&&
            report.findings[0].detail=="AppleSnapshotRetentionCrossVolumePayloadOverlap"&&
            !Covered(report,VerificationCheck::SnapshotReachableAllocation),Detail(report));
    });
    test("sibling live payload cannot alias another volume historical OMAP", [] {
        SnapshotFixture f;SnapshotPayload(f);AllocateSnapshotBlocks(f);HistoricalOmap(f);SnapshotSibling(f,193);
        const auto report=VerifySnapshot(f);
        Check(Has(report,VerificationCode::PayloadMetadataOverlap)&&
            report.findings[0].detail=="AppleSnapshotRetentionPayloadMetadataOverlap"&&
            !Covered(report,VerificationCheck::SnapshotReachableAllocation),Detail(report));
    });
    test("selecting sibling still validates retained owner in original volume", [] {
        SnapshotFixture f;SnapshotPayload(f);AllocateSnapshotBlocks(f);SnapshotSibling(f,220);
        f.scope.volume_oid=102;f.scope.volume_uuid_hex=std::string(32,'c');
        const auto report=VerifySnapshot(f);
        Check(report.selected&&report.selected->exact.volume_oid==102&&
            Has(report,VerificationCode::CrossVolumePayloadOverlap)&&!report.whole_volume_verified,
            "selected sibling cannot hide original historical ownership: "+Detail(report));
    });
    test("offset source preserves historical layer identity and read-only behavior", [] {
        SnapshotFixture f;SnapshotPayload(f);AllocateSnapshotBlocks(f);
        SnapshotLayer(f,184,10,{{220,1,kApplePhysicalExtentKindNew,30,2}});
        f.image.insert(f.image.begin(),8192,std::byte{0xee});f.scope.store_offset_bytes=8192;
        const auto before=f.image;TracedSource source(f.image);VerificationScope scope;scope.source_identity="offset-history";scope.exact=f.scope;
        const auto report=ApfsVerifier::Verify(source,scope);
        Check(Has(report,VerificationCode::ExtentReferenceInconsistent)&&report.findings[0].checkpoint_xid==10&&
            report.findings[0].physical_block==184,"offset historical reference identity: "+Detail(report));
        Check(before==f.image&&!source.Touched(8192+220*f.bs,f.bs)&&!source.Touched(220*f.bs,f.bs),
            "no write, payload read or offset double application");
    });
    test("historical reference materialization failure retains sticky allowance", [] {
        SnapshotFixture f;SnapshotPayload(f);AllocateSnapshotBlocks(f);
        VerificationScope scope;scope.source_identity="history-materialization";scope.exact=f.scope;
        scope.require_whole_volume=true;
        TracedSource control(f.image);const auto expected=ApfsVerifier::Verify(control,scope);
        Check(Covered(expected,VerificationCheck::SnapshotReachableAllocation)&&expected.read_budget,"reference budget control");
        scope.max_record_bytes=expected.read_budget->Consumed().record_bytes-1;
        TracedSource source(f.image);const auto report=ApfsVerifier::Verify(source,scope);
        Check(Has(report,VerificationCode::BudgetExceeded)&&report.read_budget->Failed()&&
            !Covered(report,VerificationCheck::SnapshotReachableAllocation)&&!report.allocation_census,Detail(report));
        const auto consumed=report.read_budget->Consumed();
        BudgetedRandomAccessSource shared(source,report.read_budget);const auto retry=ApfsVerifier::Verify(shared,scope);
        Check(Has(retry,VerificationCode::BudgetExceeded)&&report.read_budget->Consumed().reads==consumed.reads&&
            retry.read_budget==report.read_budget,"retry neither replaces nor replenishes exhausted allowance");
    });
    test("live view inherits retained payload with no multiplicity inflation", [] {
        SnapshotFixture f;SnapshotPayload(f);SecondSnapshotPayload(f,false,7,20);SnapshotLayer(f,8,20,{});
        AllocateSnapshotBlocks(f);const auto report=VerifySnapshot(f);
        Check(Covered(report,VerificationCheck::SnapshotReachableAllocation)&&Has(report,VerificationCode::SnapshotAccountingUnsupported),Detail(report));
        Check(!Covered(report,VerificationCheck::HistoricalReachability),"live closure is not full retained accounting");
    });
    test("live clone addition resolves against final snapshot only", [] {
        SnapshotFixture f;SnapshotPayload(f);SecondSnapshotPayload(f,true,7,20);
        SnapshotLayer(f,8,20,{{220,1,kApplePhysicalExtentKindUpdate,30,1}});
        AllocateSnapshotBlocks(f);const auto report=VerifySnapshot(f);
        Check(Covered(report,VerificationCheck::SnapshotReachableAllocation)&&Has(report,VerificationCode::SnapshotAccountingUnsupported),Detail(report));
    });
    test("live clone removal decrements the final snapshot multiplicity", [] {
        SnapshotFixture f;SnapshotPayload(f);f.SecondSnapshot();SecondSnapshotPayload(f,true);
        SnapshotLayer(f,191,11,{{220,1,kApplePhysicalExtentKindUpdate,30,1}});
        SecondSnapshotPayload(f,false,7,20);SnapshotLayer(f,8,20,{{220,1,kApplePhysicalExtentKindUpdate,30,-1}});
        AllocateSnapshotBlocks(f,{180,181,183,184,185,188,190,191,220});const auto report=VerifySnapshot(f);
        Check(Covered(report,VerificationCheck::SnapshotReachableAllocation)&&Has(report,VerificationCode::SnapshotAccountingUnsupported),Detail(report));
    });
    test("live COW releases its old reference while history retains the bytes", [] {
        SnapshotFixture f;SnapshotPayload(f);SecondSnapshotPayload(f,false,7,20,221);
        SnapshotLayer(f,8,20,{{220,1,kApplePhysicalExtentKindUpdate,30,-1},{221,1,kApplePhysicalExtentKindNew,30,1}});
        AllocateSnapshotBlocks(f,{180,181,183,184,185,220,221});const auto report=VerifySnapshot(f);
        Check(Covered(report,VerificationCheck::SnapshotReachableAllocation)&&Has(report,VerificationCode::SnapshotAccountingUnsupported),Detail(report));
        Check(!report.whole_volume_verified&&!report.payload_content_hashes_verified&&!report.allocation_census,
            "valid COW supplies no reclaim or full-volume authority");
    });
    test("live UPDATE can reuse older history after latest snapshot drops its reference", [] {
        SnapshotFixture f;SnapshotPayload(f);f.SecondSnapshot();
        SnapshotLayer(f,191,11,{{220,1,kApplePhysicalExtentKindUpdate,30,-1}});
        SecondSnapshotPayload(f,false,7,20);
        SnapshotLayer(f,8,20,{{220,1,kApplePhysicalExtentKindUpdate,30,1}});
        AllocateSnapshotBlocks(f,{180,181,183,184,185,188,190,191,220});
        const auto report=VerifySnapshot(f);
        Check(Covered(report,VerificationCheck::SnapshotReachableAllocation)&&
            Has(report,VerificationCode::SnapshotAccountingUnsupported),Detail(report));
        Check(!Covered(report,VerificationCheck::HistoricalReachability)&&!report.payload_content_hashes_verified,
            "older retained ownership is not a payload hash or full history proof");
    });
    test("live NEW cannot reuse older history when final snapshot reference is zero", [] {
        SnapshotFixture f;SnapshotPayload(f);f.SecondSnapshot();
        SnapshotLayer(f,191,11,{{220,1,kApplePhysicalExtentKindUpdate,30,-1}});
        SecondSnapshotPayload(f,false,7,20);
        SnapshotLayer(f,8,20,{{220,1,kApplePhysicalExtentKindNew,30,1}});
        AllocateSnapshotBlocks(f,{180,181,183,184,185,188,190,191,220});
        ReferenceFailure(f,20,8);
    });
    test("invalid live reference admission cannot publish requested payload observations", [] {
        SnapshotFixture f;SnapshotPayload(f);SnapshotLayer(f,8,20,{});AllocateSnapshotBlocks(f);
        VerificationScope scope;scope.source_identity="live-reference-before-observation";scope.exact=f.scope;
        scope.observe_payload_content=true;scope.require_payload_content_hashes=true;scope.require_whole_volume=true;
        const auto before=f.image;TracedSource source(f.image);
        const auto report=ApfsVerifier::Verify(source,scope);
        Check(Has(report,VerificationCode::ExtentReferenceInconsistent)&&
            report.findings[0].checkpoint_xid==20&&report.findings[0].physical_block==8,Detail(report));
        Check(report.payload_inventory&&report.payload_inventory->reason==payload::Reason::AdmissionNotComplete&&
            !report.payload_inventory->exactComplete()&&!report.payload_projection&&
            !report.payload_content_hashes_verified&&!report.whole_volume_verified&&!report.allocation_census,
            "failed graph supplies no admitted observation, hash authority or full-volume proof");
        Check(before==f.image&&!source.Touched(220*f.bs,2*f.bs)&&
            report.covered_filesystem_records==0&&report.covered_physical_extents==0,
            "requested payload mode cannot bypass failed live-reference admission");
    });
    test("empty live view cannot omit final retained decrement", [] {
        SnapshotFixture f;SnapshotPayload(f);SnapshotLayer(f,8,20,{});AllocateSnapshotBlocks(f);
        ReferenceFailure(f,20,8);
    });
    test("live NEW cannot redefine historical ownership", [] {
        SnapshotFixture f;SnapshotPayload(f);SecondSnapshotPayload(f,false,7,20);
        SnapshotLayer(f,8,20,{{220,1,kApplePhysicalExtentKindNew,30,1}});AllocateSnapshotBlocks(f);
        ReferenceFailure(f,20,8);
    });
    test("live multiplicity must match its own namespace mappings", [] {
        SnapshotFixture f;SnapshotPayload(f);SecondSnapshotPayload(f,false,7,20);
        SnapshotLayer(f,8,20,{{220,1,kApplePhysicalExtentKindUpdate,30,1}});AllocateSnapshotBlocks(f);
        ReferenceFailure(f,20,8);
    });
    test("live zero delta cannot change to a wrong owner", [] {
        SnapshotFixture f;SnapshotPayload(f);SecondSnapshotPayload(f,false,7,20);
        SnapshotLayer(f,8,20,{{220,1,kApplePhysicalExtentKindUpdate,31,0}});AllocateSnapshotBlocks(f);
        ReferenceFailure(f,20,8);
    });
    test("live signed decrement cannot underflow retained reference count", [] {
        SnapshotFixture f;SnapshotPayload(f);SnapshotLayer(f,8,20,{{220,1,kApplePhysicalExtentKindUpdate,30,-2}});
        AllocateSnapshotBlocks(f);ReferenceFailure(f,20,8);
    });
    test("new live payload must be allocated before broad historical refusal", [] {
        SnapshotFixture f;SnapshotPayload(f);SecondSnapshotPayload(f,false,7,20,221);
        SnapshotLayer(f,8,20,{{220,1,kApplePhysicalExtentKindUpdate,30,-1},{221,1,kApplePhysicalExtentKindNew,30,1}});
        AllocateSnapshotBlocks(f);const auto report=VerifySnapshot(f);
        Check(Has(report,VerificationCode::PayloadAllocationInconsistent)&&report.findings[0].checkpoint_xid==20&&
            report.findings[0].physical_block==221&&!Covered(report,VerificationCheck::SnapshotReachableAllocation),Detail(report));
    });
    test("new live payload cannot be queued for deferred free", [] {
        SnapshotFixture f;SnapshotPayload(f);SecondSnapshotPayload(f,false,7,20,221);
        SnapshotLayer(f,8,20,{{220,1,kApplePhysicalExtentKindUpdate,30,-1},{221,1,kApplePhysicalExtentKindNew,30,1}});
        AllocateSnapshotBlocks(f,{180,181,183,184,185,220,221});QueueSnapshotBlock(f,221);
        const auto report=VerifySnapshot(f);
        Check(Has(report,VerificationCode::PayloadAllocationInconsistent)&&report.findings[0].checkpoint_xid==20&&
            report.findings[0].detail=="VerifierSnapshotPayloadQueuedForFree",Detail(report));
    });
    test("live payload cannot alias a retained catalog dependency", [] {
        SnapshotFixture f;SnapshotPayload(f);SecondSnapshotPayload(f,false,7,20,6);
        SnapshotLayer(f,8,20,{{6,1,kApplePhysicalExtentKindNew,30,1},{220,1,kApplePhysicalExtentKindUpdate,30,-1}});
        AllocateSnapshotBlocks(f);const auto report=VerifySnapshot(f);
        Check(Has(report,VerificationCode::PayloadMetadataOverlap)&&report.findings[0].checkpoint_xid==20,Detail(report));
    });
    test("offset source reports exact live generation and reference root", [] {
        SnapshotFixture f;SnapshotPayload(f);SnapshotLayer(f,8,20,{});AllocateSnapshotBlocks(f);
        f.image.insert(f.image.begin(),8192,std::byte{0xee});f.scope.store_offset_bytes=8192;
        const auto before=f.image;TracedSource source(f.image);VerificationScope scope;scope.source_identity="offset-live-closure";scope.exact=f.scope;
        const auto report=ApfsVerifier::Verify(source,scope);
        Check(Has(report,VerificationCode::ExtentReferenceInconsistent)&&report.findings[0].checkpoint_xid==20&&
            report.findings[0].object_id==8&&report.findings[0].physical_block==8,Detail(report));
        Check(before==f.image&&!source.Touched(8192+220*f.bs,2*f.bs)&&!report.allocation_census&&
            report.covered_filesystem_records==0&&report.covered_physical_extents==0,"offset live failure has no payload I/O, writes or partial proof");
    });
    test("snapshot proof preserves caller read budget", [] {
        SnapshotFixture f;AllocateSnapshotBlocks(f);VerificationScope scope;scope.source_identity="snapshot-budget";scope.exact=f.scope;
        scope.require_whole_volume=true;
        TracedSource control(f.image);const auto expected=ApfsVerifier::Verify(control,scope);
        Check(expected.outcome==VerificationOutcome::Refused,"budget control");scope.max_reads=expected.source_reads-1;
        TracedSource source(f.image);const auto report=ApfsVerifier::Verify(source,scope);
        Check(Has(report,VerificationCode::BudgetExceeded)&&!Covered(report,VerificationCheck::SnapshotReachableAllocation),Detail(report));
    });

    test("exact snapshot parser exposes every multilevel metadata block", [] {
        SnapshotFixture f;const auto blocks=SnapshotMultilevel(f);
        VectorRandomAccessSource source(f.image);std::string error;
        const auto cp=LoadAppleCheckpointView(source,0,source.SizeBytes(),error,20);Check(cp.has_value(),error);
        AppleSnapshotTreeRecords trees;std::vector<AppleSnapshotRecord> snapshots;
        Check(LoadAppleSnapshotRecords(source,*cp,101,snapshots,error,10,trees),error);
        Check(trees.filesystem_blocks.size()==blocks.size()&&trees.extentref_blocks==std::vector<std::uint64_t>{184},"canonical complete visited block capture");
        const auto report=VerifySnapshot(f);Check(Covered(report,VerificationCheck::SnapshotReachableAllocation),Detail(report));
    });
    test("unallocated historical child beyond root is detected", [] {
        SnapshotFixture f;const auto blocks=SnapshotMultilevel(f);
        auto child=*std::find_if(blocks.begin(),blocks.end(),[](auto block){return block!=183;});
        ClearSnapshotAllocation(f,child);const auto report=VerifySnapshot(f);
        Check(Has(report,VerificationCode::MetadataAllocationInconsistent)&&report.findings[0].physical_block==child,Detail(report));
    });
    test("failed exact snapshot read clears all captured ownership blocks", [] {
        SnapshotFixture f;const auto blocks=SnapshotMultilevel(f);
        VectorRandomAccessSource before(f.image);std::string error;
        const auto cp=LoadAppleCheckpointView(before,0,before.SizeBytes(),error,20);Check(cp.has_value(),error);
        AppleSnapshotTreeRecords trees;std::vector<AppleSnapshotRecord> snapshots;
        Check(LoadAppleSnapshotRecords(before,*cp,101,snapshots,error,10,trees),error);
        auto child=*std::find_if(blocks.begin(),blocks.end(),[](auto block){return block!=183;});
        f.Edit(child,[](auto& b){b[0]^=std::byte{1};},false);VectorRandomAccessSource damaged(f.image);
        Check(!LoadAppleSnapshotRecords(damaged,*cp,101,snapshots,error,10,trees),"checksum must fail");
        Check(snapshots.empty()&&trees.filesystem.empty()&&trees.extentref.empty()&&trees.filesystem_blocks.empty()&&trees.extentref_blocks.empty(),"no stale exact ownership escapes");
    });
    test("early materialization refusal clears census observations", [] {
        Fixture f;f.scope.max_record_bytes=1;const auto report=Verify(f);
        Check(Has(report,VerificationCode::BudgetExceeded)&&!report.allocation_census,"no census on incomplete walk");
    });
    test("canonical all-free chunk without bitmap completes current census", [] {
        Fixture f; SplitOffAllFreeChunk(f); const auto report = Verify(f);
        Check(report.outcome == VerificationOutcome::Complete && report.allocation_census, Detail(report));
        Check(report.allocation_census->current_metadata_blocks == 17 &&
            report.allocation_census->current_payload_blocks == 1, "exact fixture ownership counts");
        Check(report.allocation_census->unattributed_main_blocks == 0 &&
            report.allocation_census->unattributed_internal_blocks == 0, "no invented allocations in bitmapless chunk");
    });
    test("bitmapless chunk with allocated count is corruption", [] {
        Fixture f; SplitOffAllFreeChunk(f);
        VectorRandomAccessSource source(f.image); std::string error;
        const auto cp = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error, 20);
        Check(cp.has_value(), error);
        f.Edit(cp->spaceman.devices[0].cibs[0].object.physical_block, [](auto& b) { PutU32LE(b, 0x5C, 255); });
        const auto report = Verify(f);
        Check(Has(report, VerificationCode::SpacemanInconsistent) && !report.allocation_census, Detail(report));
    });
    test("census keeps disjoint unknown runs and exact counts", [] {
        Fixture f;
        for (auto block : {221ull, 223ull, 224ull, 250ull})
            f.spec.authoritative_seeded_main_blocks.emplace_back(block, Bytes(f.bs, std::byte{0x4a}));
        f.Rebuild(); const auto report = Verify(f);
        Check(report.outcome == VerificationOutcome::Complete && report.allocation_census, Detail(report));
        const auto& census = *report.allocation_census;
        Check(census.current_metadata_blocks == 17 && census.current_payload_blocks == 1 &&
            census.unattributed_main_blocks == 4 && census.unattributed_internal_blocks == 0, "exact disjoint census counts");
        Check(census.unattributed_main_ranges == std::vector<VerificationBlockRange>{{221,1},{223,2},{250,1}},
            "free holes are never merged into unknown allocations");
    });
    test("deferred free allocation is explained without claiming an orphan", [] {
        Fixture f; f.spec.authoritative_seeded_main_blocks.emplace_back(221, Bytes(f.bs, std::byte{0x4a}));
        f.Rebuild(); QueueMainBlock(f, 221); const auto report = Verify(f);
        Check(report.outcome == VerificationOutcome::Complete && report.allocation_census, Detail(report));
        Check(report.allocation_census->unattributed_main_blocks == 0 &&
            report.allocation_census->current_metadata_blocks == 17 &&
            report.allocation_census->current_payload_blocks == 1, "queue excluded from current ownership and residual");
    });
    test("historical payload queued for free is detected", [] {
        SnapshotFixture f; SnapshotPayload(f); AllocateSnapshotBlocks(f); QueueSnapshotBlock(f, 220);
        const auto report = VerifySnapshot(f);
        Check(Has(report, VerificationCode::PayloadAllocationInconsistent) &&
            report.findings[0].detail == "VerifierSnapshotPayloadQueuedForFree" &&
            report.findings[0].checkpoint_xid == 10, Detail(report));
    });
    test("historical metadata queued for free is detected", [] {
        SnapshotFixture f; AllocateSnapshotBlocks(f); QueueSnapshotBlock(f, 183);
        const auto report = VerifySnapshot(f);
        Check(Has(report, VerificationCode::MetadataAllocationInconsistent) &&
            report.findings[0].detail == "VerifierCurrentMetadataQueuedForFree" &&
            report.findings[0].physical_block == 183, Detail(report));
    });
    test("late quota failure publishes no already computed census", [] {
        Fixture f; f.spec.volumes[0].quota_block_count = 1; f.Rebuild(); const auto report = Verify(f);
        Check(Has(report, VerificationCode::QuotaOrReserveInconsistent) &&
            Covered(report, VerificationCheck::CurrentOwnershipCensus) &&
            Covered(report, VerificationCheck::PayloadAllocatorOwnership), "late validation was reached: " + Detail(report));
        Check(!report.allocation_census && report.covered_filesystem_records == 0 &&
            report.covered_physical_extents == 0, "late failure cannot publish census");
    });
    test("zero residual cannot satisfy whole-volume request", [] {
        Fixture f; const auto control = Verify(f);
        Check(control.allocation_census && control.allocation_census->unattributed_main_blocks == 0 &&
            control.allocation_census->unattributed_internal_blocks == 0, "zero-residual control");
        f.scope.require_whole_volume = true; const auto report = Verify(f);
        Check(report.outcome == VerificationOutcome::Incomplete && Has(report, VerificationCode::CoverageMissing) &&
            !Covered(report, VerificationCheck::CompleteAllocationAccounting) && !report.allocation_census, Detail(report));
    });
    test("8192-byte exact snapshot reaches allocation proof", [] {
        SnapshotFixture f(8192); SnapshotPayload(f); AllocateSnapshotBlocks(f); const auto report = VerifySnapshot(f);
        Check(report.outcome == VerificationOutcome::Refused && Covered(report, VerificationCheck::SnapshotReachableAllocation) &&
            Has(report, VerificationCode::SnapshotAccountingUnsupported), Detail(report));
    });
    test("unattributed interval crosses two allocated chunk bitmaps", [] {
        Fixture f; SplitOffAllFreeChunk(f);
        VectorRandomAccessSource source(f.image); std::string error;
        const auto cp = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error, 20);
        Check(cp.has_value(), error);
        const auto& pool = cp->spaceman.internal_pool;
        const auto second_bitmap = pool.base_block + 2;
        Check(pool.block_count > 2 && (std::to_integer<unsigned>(pool.active_bitmaps[0].bytes[0]) & 4u) == 0,
            "free internal block for second bitmap");
        f.Edit(pool.active_bitmaps[0].physical_block, [](auto& b) { b[0] |= std::byte{4}; }, false);
        f.Edit(second_bitmap, [](auto& b) { b.assign(b.size(), std::byte{0}); b[0] = std::byte{1}; }, false);
        f.Edit(cp->spaceman.chunks[0].bitmap_block, [](auto& b) { b[31] |= std::byte{0x80}; }, false);
        f.Edit(cp->spaceman.devices[0].cibs[0].object.physical_block, [&](auto& b) {
            PutU32LE(b, 0x3C, cp->spaceman.chunks[0].free_count - 1);
            PutU32LE(b, 0x5C, 255); PutU64LE(b, 0x60, second_bitmap);
        });
        f.Edit(cp->spaceman.object.physical_block, [&](auto& b) {
            PutU64LE(b, 0x48, cp->spaceman.devices[0].free_count - 2);
        });
        const auto report = Verify(f);
        Check(report.outcome == VerificationOutcome::Complete && report.allocation_census, Detail(report));
        Check(report.allocation_census->unattributed_main_ranges == std::vector<VerificationBlockRange>{{255,2}} &&
            report.allocation_census->unattributed_main_blocks == 2 &&
            report.allocation_census->current_metadata_blocks == 18 &&
            report.allocation_census->unattributed_internal_blocks == 0, "exact cross-chunk ownership and residual");
    });
    test("materialization limit at final census allocation clears output", [] {
        Fixture f; std::uint64_t low = 1, high = f.scope.max_record_bytes;
        while (low < high)
        {
            f.scope.max_record_bytes = low + (high - low) / 2;
            const auto report = Verify(f);
            if (report.outcome == VerificationOutcome::Complete) high = f.scope.max_record_bytes;
            else { Check(Has(report, VerificationCode::BudgetExceeded), Detail(report)); low = f.scope.max_record_bytes + 1; }
        }
        f.scope.max_record_bytes = low; Check(Verify(f).outcome == VerificationOutcome::Complete, "exact sufficient budget");
        f.scope.max_record_bytes = low - 1; const auto report = Verify(f);
        Check(Has(report, VerificationCode::BudgetExceeded) && Covered(report, VerificationCheck::PayloadAllocatorOwnership) &&
            report.findings[0].check == VerificationCheck::CurrentOwnershipCensus, "budget fails in final census: " + Detail(report));
        Check(!report.allocation_census && report.covered_filesystem_records == 0 && report.covered_physical_extents == 0,
            "no partial census after late allocation failure");
    });
    test("closed live namespace reuse observes current payload only", [] {
        SnapshotFixture f;SnapshotPayload(f);AllocateSnapshotBlocks(f);CurrentSnapshotAllocation(f);
        VerificationScope scope;scope.source_identity="closed-live-namespace";scope.exact=f.scope;scope.observe_payload_content=true;
        TracedSource empty_source(f.image);auto report=ApfsVerifier::Verify(empty_source,scope);
        Check(report.outcome==VerificationOutcome::Complete&&report.payload_inventory->exactComplete()&&
            report.payload_inventory->entries.empty()&&report.payload_projection->inodes.size()==1,
            "retained file never enters the empty current namespace: "+Detail(report));
        SecondSnapshotPayload(f,false,7,20,220);SnapshotLayer(f,8,20,{});CurrentSnapshotAllocation(f,8);
        TracedSource live_source(f.image);report=ApfsVerifier::Verify(live_source,scope);
        Check(report.outcome==VerificationOutcome::Complete&&report.payload_inventory->exactComplete()&&
            !report.payload_inventory->entries.empty()&&report.payload_inventory->logicalBytesRead>0&&
            !report.whole_volume_verified&&!report.payload_content_hashes_verified,
            "new invocation observes admitted live bytes without expected-content authority: "+Detail(report));
    });
    std::cout << "CENSUS " << cases << " passed, " << failed << " failed, " << checks << " checks\n";
    return failed?1:0;
}

