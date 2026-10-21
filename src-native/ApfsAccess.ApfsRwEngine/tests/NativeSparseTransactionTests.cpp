#define APPLE_CLONE_TEST_HELPERS_ONLY
#include "AppleCloneCowTests.cpp"
#include "NativeSparse.h"
#include "MetadataStore.h"
#include "TransactionManager.h"
#include <filesystem>

namespace {
using Store=MetadataStore;
using Journal=TransactionManager;
NativeSparseRequest Set(bool value=true){return {NativeSparseAction::SetSparse,value,0,0,123456789};}
NativeSparseRequest Zero(std::uint64_t at,std::uint64_t bytes){return {NativeSparseAction::ZeroRange,false,at,bytes,123456790};}
BuilderStore SparseSpec(bool shared=false,bool sparse=false){
    auto spec=CloneSpec(shared?2:1);
    for(auto& r:spec.volumes[0].filesystem_records)if(Type(r)==3&&Id(r)==17){
        AppleInodeRecord inode;std::string error;Check(ApfsExtendedRecordCodec::DecodeInode(r,inode,error),error);
        if(sparse){inode.internal_flags|=kAppleInodeSparseFlag;inode.extended_fields.push_back({kAppleInodeSparseBytesField,0,std::vector<std::byte>(8)});}
        Check(EncodeAppleInodeRecord(inode,r,error),error);
    }
    return spec;
}
NativeSparseState State(const Fixture& f){NativeSparseState state;std::string error;VectorRandomAccessSource source(f.image);
    Check(ReadNativeSparseState(source,f.checkpoint,101,17,state,error),"canonical sparse state: "+error);return state;}
AppleVolumeTransactionPlan SparsePlan(Fixture& f,NativeSparseRequest request){VectorRandomAccessSource source(f.image);
    NativeSparseState before;AppleVolumeTransactionPlan plan;std::string error;
    Check(PlanNativeSparseTransaction(source,f.checkpoint,101,17,request,before,plan,error),"sparse planner: "+error);return plan;}
void PlannerCases(){
    for(bool shared:{false,true}){
        Fixture f(SparseSpec(shared));const auto original=Payload(f,17);
        auto p=SparsePlan(f,Set());Publish(f,p);Check(State(f).sparse&&State(f).allocated==16384,"SetSparse marks real dense extent graph");
        p=SparsePlan(f,Zero(101,12000));Check(p.payload_blocks.size()==2,"partial boundaries allocate exactly two COW payload blocks");
        Publish(f,p);auto state=State(f);Check(state.sparse&&state.allocated==12288,"full covered block becomes real hole");
        std::vector<NativeSparseAllocatedRange> ranges;std::string error;
        Check(QueryNativeSparseRanges(state,0,UINT16_MAX,10,ranges,error)&&ranges==std::vector<NativeSparseAllocatedRange>{{0,4096},{8192,8192}},"allocated query follows actual extent holes");
        auto expected=original;std::fill(expected.begin()+101,expected.begin()+12101,std::byte{});
        Check(Payload(f,17)==expected,"partial zero preserves every outside byte");
        if(shared)Check(Payload(f,18)==original,"shared physical clone peer retains every original byte");
        p=SparsePlan(f,Zero(0,16384));Check(p.payload_blocks.empty(),"whole sparse zero materializes no payload");Publish(f,p);
        state=State(f);Check(state.allocated==0&&state.ranges.empty(),"whole zero has no physical file mapping");
        p=SparsePlan(f,Set(false));Check(p.payload_blocks.size()==4,"clear sparse materializes all four zero holes");Publish(f,p);
        state=State(f);Check(!state.sparse&&state.allocated==16384,"clear sparse yields dense graph");
        Check(Payload(f,17)==std::vector<std::byte>(16384),"unsparse payload remains logically zero");CheckGraph(f);
    }
    Fixture dense(SparseSpec());auto old=Payload(dense,17);auto plan=SparsePlan(dense,Zero(4000,10000));
    Check(plan.payload_blocks.size()==4,"dense ZeroRange retains physical allocation");Publish(dense,plan);
    auto expected=old;std::fill(expected.begin()+4000,expected.begin()+14000,std::byte{});
    Check(!State(dense).sparse&&State(dense).allocated==16384&&Payload(dense,17)==expected,"dense partial zero has exact bounded COW");
    std::string error;NativeSparseState before;VectorRandomAccessSource source(dense.image);
    Check(!PlanNativeSparseTransaction(source,dense.checkpoint,101,17,Zero(INT64_MAX,1),before,plan,error)&&Empty(plan),"signed range overflow refuses with empty plan");
    const auto state=State(dense);std::vector<NativeSparseAllocatedRange> ranges;
    Check(QueryNativeSparseRanges(state,16000,10000,10,ranges,error)&&ranges==std::vector<NativeSparseAllocatedRange>{{16000,384}},"query clips actual EOF");
    for(unsigned fault=0;fault<4;++fault){auto spec=SparseSpec();for(auto& r:spec.volumes[0].filesystem_records){
        if(fault==0&&Type(r)==3&&Id(r)==17){AppleInodeRecord i;Check(ApfsExtendedRecordCodec::DecodeInode(r,i,error),error);i.bsd_flags|=kAppleBsdCompressedFlag;Check(EncodeAppleInodeRecord(i,r,error),error);}
        if(fault==1&&Type(r)==6&&Id(r)==17)PutU32LE(r.value,0,2);
        if(fault==2&&Type(r)==8&&Id(r)==17)PutU64LE(r.value,16,1);
        if(fault==3&&Type(r)==3&&Id(r)==17){AppleInodeRecord i;Check(ApfsExtendedRecordCodec::DecodeInode(r,i,error),error);i.internal_flags|=kAppleInodeSparseFlag;Check(EncodeAppleInodeRecord(i,r,error),error);}
    }Fixture bad(spec);VectorRandomAccessSource input(bad.image);
        Check(!PlanNativeSparseTransaction(input,bad.checkpoint,101,17,Set(),before,plan,error)&&Empty(plan),"malformed ownership/compression/sparse accounting refuses");}
}
void Save(const std::filesystem::path& path,std::span<const std::byte> bytes){std::ofstream out(path,std::ios::binary);out.write(reinterpret_cast<const char*>(bytes.data()),bytes.size());Check(out.good(),"save owned small image");}
std::vector<std::byte> Bytes(const std::filesystem::path& path){std::ifstream in(path,std::ios::binary|std::ios::ate);if(!in)return {};
    auto n=in.tellg();Check(n>=0&&n<8*1024*1024,"bounded persistence read");std::vector<std::byte> bytes(static_cast<std::size_t>(n));in.seekg(0);in.read(reinterpret_cast<char*>(bytes.data()),bytes.size());Check(in.good()||bytes.empty(),"read persistence bytes");return bytes;}
std::vector<std::byte> HeldBytes(const BlockDevice& device){std::vector<std::byte> bytes;
    Check(device.GetGeometry().total_bytes<8*1024*1024&&device.ReadForVerification(0,static_cast<std::size_t>(device.GetGeometry().total_bytes),bytes),"read exact held image bytes");return bytes;}
Store::VolumeContext Context(const std::filesystem::path& image){Store::VolumeContext context;context.device_path=std::filesystem::absolute(image).wstring();context.volume_object_id=101;context.allow_legacy_scaffold_for_fixtures=false;return context;}
void Open(Journal& journal,const std::filesystem::path& wal,const Fixture& f){std::string error;
    const auto hex=f.checkpoint.container.superblock.uuid_hex;const auto identity=L"apfs-vol:"+std::wstring(hex.begin(),hex.end())+L":101";
    Check(journal.OpenStartupJournal(std::filesystem::absolute(wal).wstring(),identity,error),"open actual original: "+error);
    if(!std::filesystem::exists(wal))Check(journal.MaterializeAbsentStartupJournal(error),"materialize actual original");
    Check(journal.EnrollCanonicalJournalIdentity(identity),"enroll canonical original");}
NativeSparseOpenEntry Entry(Store& store){const auto inode=store.LookupCommittedInodeByPath(L"\\clone0");Check(!!inode,"open committed inode");
    NativeSparseOpenEntry entry{17,inode->xid,2,0,"clone0"};
    // An ordinary singly linked directory record uses sibling ID zero.
    return entry;
}
Store::SparseAcceptance Accept(Store& store,Journal& journal,NativeSparseRequest request,Store::SparseReceipt& receipt,std::string& error){
    auto result=Store::SparseAcceptance::Refused;const auto entry=Entry(store);
    const bool borrowed=store.WithNativeSparseSession(entry,[&](const auto& session,std::string& detail){
        result=store.AcceptNativeSparse(journal,session,request,receipt,detail);return result==Store::SparseAcceptance::Accepted;
    },error);Check(borrowed==(result==Store::SparseAcceptance::Accepted),"borrowed acceptance outcome coherent: "+error);return result;
}
std::vector<NativeSparseAllocatedRange> Query(Store& store,std::uint64_t offset=0,std::uint64_t length=16384){
    std::vector<NativeSparseAllocatedRange> ranges;std::string error;
    const auto ok=store.WithNativeSparseSession(Entry(store),[&](const auto& session,std::string& detail){
        return store.QueryNativeAllocatedRanges(session,offset,length,16,ranges,detail);
    },error);Check(ok,"borrowed actual allocated ranges: "+error);return ranges;
}
void ProofControls(const WriteAheadLog::Record& original){
    NativeSparseProof proof,decoded;Check(DecodeNativeSparse(original.inline_payload,proof)&&EncodeNativeSparse(proof)==original.inline_payload,"exact real original body roundtrip");
    for(unsigned mode=0;mode<5;++mode){auto body=original.inline_payload;
        if(mode==0)body.resize(8);if(mode==1)body.pop_back();if(mode==2)body.push_back(std::byte{});if(mode==3)body[8]=std::byte{2};if(mode==4)body[0]^=std::byte{1};
        decoded=proof;Check(!DecodeNativeSparse(body,decoded)&&decoded==NativeSparseProof{},"bounded/trailing/version failure clears output");}
    auto invalid=proof;invalid.preimages.push_back(invalid.preimages.back());Check(EncodeNativeSparse(invalid).empty(),"duplicate original block refuses");
    invalid=proof;invalid.request=Zero(INT64_MAX,1);Check(EncodeNativeSparse(invalid).empty(),"invalid original range refuses");
    for(unsigned mode=0;mode<10;++mode){auto row=original;
        if(mode==0)row.flags=1;if(mode==1)++row.object_id;if(mode==2)++row.parent_object_id;if(mode==3)++row.logical_offset;
        if(mode==4)++row.payload_offset;if(mode==5)++row.payload_spool_id;if(mode==6)row.secondary_path_utf8="spoof";
        if(mode==7)row.payload_sha256[0]^=1;if(mode==8)++row.logical_length;if(mode==9)row.state=WriteAheadLog::RecordState::Accepted;
        Check(!WriteAheadLog::InlinePayloadIsConsistent(row),"outer scope/hash/operation cannot reinterpret typed original");}
    for(unsigned mode=0;mode<3;++mode){const auto path=std::filesystem::absolute("admission-"+std::to_string(mode)+".wal");
        const auto narrow=original.volume_identity+":sparse-admission-"+std::to_string(mode);const std::wstring identity(narrow.begin(),narrow.end());
        Journal journal(L"Strict");std::string error;Check(journal.OpenStartupJournal(path.wstring(),identity,error)&&journal.MaterializeAbsentStartupJournal(error),"fresh typed admission control");
        Journal::MutationIntent intent;intent.kind=Journal::MutationKind::NativeSparse;intent.path=L"\\clone0";intent.object_id=proof.inode;intent.generation=proof.checkpoint;
        intent.length=intent.payload_length=original.inline_payload.size();intent.inline_payload=original.inline_payload;intent.payload_checksum=original.payload_sha256;
        const auto before=Bytes(path);Check(journal.Begin()&&journal.RecordMutation(intent)&&!journal.FlushPreparedRecords()&&Bytes(path)==before,"typed original cannot flush a partial prepared group");
        if(mode==2){Journal::MutationIntent extra;extra.kind=Journal::MutationKind::CreateFile;extra.object_id=999;extra.path=L"\\extra";Check(journal.RecordMutation(extra),"mixed batch fixture");}
        Check(journal.Accept(proof.checkpoint+(mode==0?1:0))==(mode==1),"single typed original requires exact accepted preimage");
        if(mode!=1)Check(Bytes(path)==before&&!journal.Watermarks().accepted_sequence,"rejected typed boundary persists no bytes");
    }
}
void RefusalCases(){
    for(unsigned mode=0;mode<9;++mode){Fixture fixture(SparseSpec(false,true));const auto stem="refuse-"+std::to_string(mode);
        const auto image=std::filesystem::path(stem+".apfs"),wal=std::filesystem::path(stem+".wal");Save(image,fixture.image);const auto context=Context(image);
        std::string error;auto lease=BlockDevice::OpenExclusiveManagementImage(context.device_path,0,error);Check(!!lease,"refusal held image");
        Store store(context,lease);Check(store.PrepareNativeWritePath(),"refusal store source");Journal journal(L"Strict");Open(journal,wal,fixture);
        if(mode==0){const auto before=HeldBytes(*lease),original=Bytes(wal);const auto good=Entry(store);
            for(unsigned n=0;n<4;++n){auto bad=good;if(n==0)++bad.generation;if(n==1)++bad.parent_object_id;if(n==2)++bad.sibling_id;if(n==3)bad.name_utf8="other";
                Check(!store.WithNativeSparseSession(bad,[](const auto&,std::string&){return true;},error),"stale/foreign open binding refuses");}
            Check(store.WithNativeSparseSession(good,[&](const auto& session,std::string& detail){std::vector<NativeSparseAllocatedRange> out;
                return store.QueryNativeAllocatedRanges(session,0,16384,16,out,detail)&&!store.QueryNativeAllocatedRanges(session,0,16384,16,out,detail);
            },error),"borrowed capability is one-shot");
            Check(HeldBytes(*lease)==before&&Bytes(wal)==original,"query/open-binding controls preserve all original/target bytes");continue;
        }
        Store::SparseReceipt receipt;
        if(mode==1){const auto original=Bytes(wal);store.SetCommitStageHook([&](auto stage){
            if(stage=="before-native-sparse-accept"){std::vector<std::byte> bytes;Check(lease->ReadForVerification(kShared*4096,4096,bytes),"preaccept drift source read");bytes[71]^=std::byte{1};Check(lease->Write(kShared*4096,bytes)&&lease->Flush(),"preaccept actual payload drift");}return true;});
            Check(Accept(store,journal,Zero(101,12000),receipt,error)==Store::SparseAcceptance::Refused,"payload drift after plan refuses acceptance: "+error);
            Check(Bytes(wal)==original&&!journal.Watermarks().accepted_sequence,"preaccept payload drift earns no original debt");continue;
        }
        Check(Accept(store,journal,Zero(101,12000),receipt,error)==Store::SparseAcceptance::Accepted,"negative recovery exact acceptance");
        if(mode==6){const auto foreign=std::filesystem::path("foreign-image.apfs");Save(foreign,fixture.image);const auto foreign_context=Context(foreign);
            auto other=BlockDevice::OpenExclusiveManagementImage(foreign_context.device_path,0,error);Check(!!other,"distinct held image authority");
            Store wrong(foreign_context,other);Check(wrong.PrepareNativeWritePath(),"byte-identical foreign image canonical owner");const auto before=HeldBytes(*other),original=Bytes(wal);
            Check(wrong.PublishOrRecoverNativeSparse(journal,error)==Store::SparsePublication::Refused&&HeldBytes(*other)==before&&Bytes(wal)==original,"byte-identical different file ID cannot consume original authority");continue;
        }
        if(mode==7){store.SetCommitStageHook([](auto stage){return stage!="before-apple-final-flush";});
            Check(store.PublishOrRecoverNativeSparse(journal,error)==Store::SparsePublication::RecoveryRequired,"actual selected-new checkpoint cut");
            Store fresh(context,lease);Check(fresh.PrepareNativeWritePath(),"fresh selected-new owner before planned payload corruption");
            VectorRandomAccessSource source(fixture.image);NativeSparseState before;AppleVolumeTransactionPlan plan;
            Check(PlanNativeSparseTransaction(source,fixture.checkpoint,101,17,Zero(101,12000),before,plan,error)&&!plan.payload_blocks.empty(),"canonical COW payload destination");
            const auto block=plan.payload_blocks.front();std::vector<std::byte> bytes;Check(lease->ReadForVerification(block*4096,4096,bytes),"new planned payload read");
            bytes[77]^=std::byte{1};Check(lease->Write(block*4096,bytes)&&lease->Flush(),"genuine new payload corruption after switch");
            const auto damaged=HeldBytes(*lease),original=Bytes(wal);const auto outcome=fresh.PublishOrRecoverNativeSparse(journal,error);
            Check(outcome!=Store::SparsePublication::Published&&outcome!=Store::SparsePublication::AlreadyPublished&&journal.Watermarks().cleanup_sequence<receipt.sequence,"selected-new corruption cannot earn completion");
            Check(HeldBytes(*lease)==damaged&&Bytes(wal)==original,"new payload refusal preserves all target/original evidence");continue;
        }
        if(mode==8){const auto identity=journal.ConfiguredVolumeIdentity();const auto volume=TransactionManager::WideToUtf8(identity);
            auto read=WriteAheadLog::ReadAll(wal,volume);Check(read.status==WriteAheadLog::ReadStatus::Ok&&read.records.size()==2,"exact original for changed commitment control");
            NativeSparseProof changed;Check(DecodeNativeSparse(read.records.front().inline_payload,changed),"decode original publication commitment");changed.publication_sha[0]^=1;
            auto& row=read.records.front();row.inline_payload=EncodeNativeSparse(changed);Check(NativeHardLinkHash(row.inline_payload,row.payload_sha256),"self-consistent changed original body hash");
            const auto wrong=std::filesystem::path("changed-commitment.wal");std::ofstream output(wrong,std::ios::binary);
            for(const auto& record:read.records){const auto bytes=WriteAheadLog::EncodeForTest(record);Check(!bytes.empty(),"valid exact outer framing");output.write(reinterpret_cast<const char*>(bytes.data()),bytes.size());}output.close();
            journal.SetJournalPath(L"");Journal altered(L"Strict");Check(altered.OpenStartupJournal(std::filesystem::absolute(wrong).wstring(),identity,error)&&altered.EnrollCanonicalJournalIdentity(identity),"framing-valid changed original opens");
            const auto before=HeldBytes(*lease),original=Bytes(wrong);const auto outcome=store.PublishOrRecoverNativeSparse(altered,error);
            Check(outcome!=Store::SparsePublication::Published&&outcome!=Store::SparsePublication::AlreadyPublished&&!altered.Watermarks().cleanup_sequence,"canonical whole-body replan rejects self-consistent changed commitment");
            Check(HeldBytes(*lease)==before&&Bytes(wrong)==original,"changed commitment earns no target or original mutation");continue;
        }
        if(mode==2){const auto before=HeldBytes(*lease);journal.SetJournalFaultInjectionHook([](auto stage){return stage=="durable-flush";});
            Check(store.PublishOrRecoverNativeSparse(journal,error)==Store::SparsePublication::RecoveryRequired&&HeldBytes(*lease)==before,"original flush failure precedes every target write");continue;}
        Store recovered(context,lease);Check(recovered.PrepareNativeWritePath(),"fresh owner before independent source drift");
        const auto block=mode==3?fixture.checkpoint.volumes.front().root_tree.physical_block:kShared;
        std::vector<std::byte> bytes;Check(lease->ReadForVerification(block*4096,4096,bytes),"negative original guard read");bytes[73]^=std::byte{0x44};
        if(mode==5){store.SetCommitStageHook([&](auto stage){if(stage=="before-native-sparse-publication")Check(lease->Write(block*4096,bytes)&&lease->Flush(),"late actual source payload drift");return true;});
            const auto original=Bytes(wal);Check(store.PublishOrRecoverNativeSparse(journal,error)==Store::SparsePublication::RecoveryRequired,"late payload drift refuses publication");
            auto expected=fixture.image;std::copy(bytes.begin(),bytes.end(),expected.begin()+block*4096);Check(HeldBytes(*lease)==expected&&Bytes(wal)==original,"late source drift preserves every other target/original byte");continue;}
        Check(lease->Write(block*4096,bytes)&&lease->Flush(),"actual old guard/payload drift");const auto damaged=HeldBytes(*lease),original=Bytes(wal);
        Check(recovered.PublishOrRecoverNativeSparse(journal,error)!=Store::SparsePublication::Published&&journal.Watermarks().cleanup_sequence<receipt.sequence,"original guard/payload drift cannot complete");
        Check(HeldBytes(*lease)==damaged&&Bytes(wal)==original,"refused recovery changes no original/target byte");
    }
}
void EmptyAndEofCases(){
    for(bool empty:{true,false}){
        auto spec=SparseSpec();auto& volume=spec.volumes.front();std::string error;
        for(auto& r:volume.filesystem_records)if(Type(r)==3&&Id(r)==17){AppleInodeRecord inode;
            Check(ApfsExtendedRecordCodec::DecodeInode(r,inode,error),error);inode.uncompressed_size=empty?0:12345;
            if(empty)std::erase_if(inode.extended_fields,[](const auto& field){return field.type==8;});
            else for(auto& field:inode.extended_fields)if(field.type==8)PutU64LE(field.data,0,12345);
            Check(EncodeAppleInodeRecord(inode,r,error),error);
        }
        if(empty){std::erase_if(volume.filesystem_records,[](const auto& r){return Id(r)==17&&(Type(r)==6||Type(r)==8);});
            volume.extentref_records.clear();volume.additional_file_system_allocated_blocks=0;spec.authoritative_seeded_main_blocks.clear();}
        Fixture fixture(spec);const auto stem=empty?"empty":"partial-eof";const auto image=std::filesystem::path(std::string(stem)+".apfs"),wal=std::filesystem::path(std::string(stem)+".wal");
        Save(image,fixture.image);const auto context=Context(image);auto lease=BlockDevice::OpenExclusiveManagementImage(context.device_path,0,error);Check(!!lease,"empty/EOF actual source lease");
        Store store(context,lease);Check(store.PrepareNativeWritePath(),"empty/EOF canonical owner");Journal journal(L"Strict");Open(journal,wal,fixture);
        Store::SparseReceipt receipt;const auto accepted=Accept(store,journal,Set(),receipt,error);
        Check(accepted==Store::SparseAcceptance::Accepted,std::string(stem)+" SetSparse acceptance: "+error);
        auto published=store.PublishOrRecoverNativeSparse(journal,error);Check(published==Store::SparsePublication::Published,std::string(stem)+" SetSparse publication: "+error);
        const auto zeroed=Accept(store,journal,empty?Zero(0,0):Zero(12340,10000),receipt,error);
        Check(zeroed==Store::SparseAcceptance::Accepted,std::string(stem)+" ZeroRange acceptance: "+error);
        published=store.PublishOrRecoverNativeSparse(journal,error);Check(published==Store::SparsePublication::Published,std::string(stem)+" ZeroRange publication: "+error);
        std::vector<std::byte> bytes;
        if(empty){Check(Query(store).empty(),"empty sparse allocated query empty");
            Check(store.ReadCommittedFileRange(L"\\clone0",0,1,bytes)&&bytes.empty(),"empty ZeroRange never grows EOF");}
        else{auto expected=Payload(fixture,17);expected.resize(12345);std::fill(expected.begin()+12340,expected.end(),std::byte{});
            Check(store.ReadCommittedFileRange(L"\\clone0",0,16384,bytes)&&bytes==expected,"ZeroRange clips partial EOF and preserves every earlier byte");
            Check(Query(store,12000,10000)==std::vector<NativeSparseAllocatedRange>{{12000,345}},"allocated query clips partial EOF");
            Fixture final(SparseSpec());final.image=HeldBytes(*lease);final.Reload();auto state=State(final);const auto& last=state.extents.back();
            const auto padding=last.physical_block*4096+(12345-last.logical_address);
            Check(std::equal(final.image.begin()+padding,final.image.begin()+(last.physical_block+last.length_bytes/4096)*4096,
                fixture.image.begin()+kShared*4096+12345),"partial EOF preserves physical bytes beyond EOF");
        }
        const auto cleared=Accept(store,journal,Set(false),receipt,error);Check(cleared==Store::SparseAcceptance::Accepted,std::string(stem)+" clear sparse acceptance: "+error);
        published=store.PublishOrRecoverNativeSparse(journal,error);Check(published==Store::SparsePublication::Published,std::string(stem)+" clear sparse publication: "+error);
        std::cout<<"PASS actual sparse "<<stem<<'\n'<<std::flush;
    }
}
void FileCase(unsigned index,const std::string& cut,bool torn=false){
    Fixture fixture(SparseSpec(true));const auto image=std::filesystem::path("sparse-"+std::to_string(index)+".apfs");const auto wal=std::filesystem::path("sparse-"+std::to_string(index)+".wal");
    Save(image,fixture.image);const auto context=Context(image);const auto original=Payload(fixture,17);std::uint64_t sequence=0,xid=0;
    {
        std::string error;auto lease=BlockDevice::OpenExclusiveManagementImage(context.device_path,0,error);Check(!!lease,"actual image lease: "+error);
        Store store(context,lease);Check(store.PrepareNativeWritePath(),"actual store prepares");Journal journal(L"Strict");Open(journal,wal,fixture);
        Check(Query(store)==std::vector<NativeSparseAllocatedRange>{{0,16384}},"initial actual query dense-backed sparse file");
        Store::SparseReceipt receipt;
        Check(Accept(store,journal,Set(),receipt,error)==Store::SparseAcceptance::Accepted,"actual SetSparse true accepted: "+error);
        Check(store.PublishOrRecoverNativeSparse(journal,error)==Store::SparsePublication::Published,"actual SetSparse true publishes canonical sparse flag/accounting: "+error);
        fixture.image=HeldBytes(*lease);fixture.Reload();const auto unchanged=HeldBytes(*lease);
        Check(Accept(store,journal,Zero(101,12000),receipt,error)==Store::SparseAcceptance::Accepted,"original accepts exact sparse operation: "+error);
        sequence=receipt.sequence;xid=fixture.checkpoint.container.superblock.next_xid;
        Check(sequence&&HeldBytes(*lease)==unchanged&&journal.Watermarks().cleanup_sequence<sequence,"acceptance preserves target and retains debt");
        if(index==0){std::vector<Journal::AcceptedTransaction> debt;Check(journal.LoadAcceptedTransactionsSinceCleanup(debt,&error)&&debt.size()==1,"actual original proof for codec/admission controls");ProofControls(debt.front().mutations.front());}
        if(cut!="accepted-only"){
            if(!cut.empty())store.SetCommitStageHook([&](auto stage){return stage!=cut;});
            const auto result=store.PublishOrRecoverNativeSparse(journal,error);
            Check(result==(cut.empty()?Store::SparsePublication::Published:Store::SparsePublication::RecoveryRequired),"publication/cut outcome: "+error);
        }
        if(torn){
            std::vector<Journal::AcceptedTransaction> debt;Check(journal.LoadAcceptedTransactionsSinceCleanup(debt,&error)&&debt.size()==1,"retained typed original");
            NativeSparseProof proof;Check(DecodeNativeSparse(debt.front().mutations.front().inline_payload,proof),"exact typed body decodes");
            VectorRandomAccessSource source(fixture.image);NativeSparseState before;AppleVolumeTransactionPlan plan;
            Check(PlanNativeSparseTransaction(source,fixture.checkpoint,101,17,proof.request,before,plan,error),"torn destination canonical plan");
            const auto& write=plan.commit.publication.before_superblock_writes.front();auto bytes=write.bytes;bytes.resize(4096);bytes[123]^=std::byte{0x55};
            Check(lease->Write(write.physical_block*4096,bytes)&&lease->Flush(),"genuine torn COW destination bytes");
        }
    }
    {
        std::string error;auto lease=BlockDevice::OpenExclusiveManagementImage(context.device_path,0,error);Check(!!lease,"fresh held source");
        Store store(context,lease);Check(store.PrepareNativeWritePath(),"fresh store canonical recovery admission");Journal journal(L"Strict");Open(journal,wal,fixture);
        if(!cut.empty()){
            const auto result=store.PublishOrRecoverNativeSparse(journal,error);
            Check(result==Store::SparsePublication::Published||result==Store::SparsePublication::AlreadyPublished,"fresh owner exact original recovery: "+error);
        }
        auto expected=original;std::fill(expected.begin()+101,expected.begin()+12101,std::byte{});std::vector<std::byte> bytes;
        Check(store.ReadCommittedFileRange(L"\\clone0",0,expected.size(),bytes)&&bytes==expected,"actual reopened file exact outside/inside zero bytes");
        Check(store.ReadCommittedFileRange(L"\\clone1",0,original.size(),bytes)&&bytes==original,"actual reopened clone peer byte-exact");
        Check(Query(store)==std::vector<NativeSparseAllocatedRange>{{0,4096},{8192,8192}},"actual reopened canonical holes/ranges");
        const auto marks=journal.Watermarks();Check(marks.accepted_sequence==sequence&&marks.cleanup_sequence==sequence&&marks.apfs_durable_sequence==sequence&&store.CheckpointXid()==xid,"exact single publication and original fences");
        Store::SparseReceipt receipt;Check(Accept(store,journal,Set(false),receipt,error)==Store::SparseAcceptance::Accepted,"second typed original accepts hole materialization: "+error);
        Check(store.PublishOrRecoverNativeSparse(journal,error)==Store::SparsePublication::Published,"actual clear sparse publication: "+error);
        Check(Query(store)==std::vector<NativeSparseAllocatedRange>{{0,16384}},"actual unsparse dense ranges");
        Check(store.ReadCommittedFileRange(L"\\clone0",0,expected.size(),bytes)&&bytes==expected,"unsparse preserves logical bytes");
    }
    Fixture final(SparseSpec());final.image=Bytes(image);final.Reload();CheckGraph(final);
    std::cout<<"PASS actual sparse "<<index<<" cut="<<cut<<" torn="<<torn<<'\n'<<std::flush;
}
}
int main(int argc,char** argv){try{
    if(argc<2)throw std::runtime_error("Fresh explicit D: evidence root required");const auto root=std::filesystem::absolute(argv[1]);
    Check(root.wstring().substr(0,3)==L"D:\\"&&!std::filesystem::exists(root),"fresh private D: test root");
    Check(std::filesystem::create_directories(root),"create evidence root");std::filesystem::current_path(root);
    if(argc>2&&std::string(argv[2])=="--edges")EmptyAndEofCases();
    else{PlannerCases();unsigned n=0;
        for(const auto& cut:{std::string{},std::string("accepted-only"),std::string("before-apple-checkpoint-switch"),std::string("before-apple-final-flush"),std::string("before-native-sparse-durable"),std::string("before-native-sparse-cleaned")})FileCase(n++,cut);
        FileCase(n++,"accepted-only",true);RefusalCases();EmptyAndEofCases();}
    std::cout<<"PASS native sparse "<<checks<<" checks\n";return 0;
}catch(const std::exception& error){std::cerr<<"FAIL "<<error.what()<<'\n';return 1;}}
