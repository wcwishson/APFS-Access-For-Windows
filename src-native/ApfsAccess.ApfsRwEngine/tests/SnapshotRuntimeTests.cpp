#define APPLE_CLONE_TEST_HELPERS_ONLY
#include "AppleCloneCowTests.cpp"
#include "SnapshotRuntime.h"
#include "SnapshotRuntimeSource.h"
#include "../src/SnapshotPreimageHash.h"
#include "NativeApfsReader.h"
#include <fstream>
#include <filesystem>
#include <bcrypt.h>
namespace {
using Store=MetadataStore;using Owner=ContainerMountCoordinator;using Tx=TransactionManager;
void Save(const std::filesystem::path&p,const std::vector<std::byte>&b){std::ofstream f(p,std::ios::binary);f.write(reinterpret_cast<const char*>(b.data()),b.size());Check(!!f,"save image");}
std::vector<std::byte> Bytes(const std::filesystem::path&p){std::ifstream f(p,std::ios::binary);std::vector<char> b((std::istreambuf_iterator<char>(f)),{});std::vector<std::byte> r(b.size());memcpy(r.data(),b.data(),b.size());return r;}
BuilderStore RuntimeSpec(unsigned owners=1){auto spec=CloneSpec(owners);spec.block_count=2048;spec.authoritative_checkpoint_ring_blocks=64;spec.authoritative_internal_pool_blocks=64;
    for(auto&r:spec.volumes[0].filesystem_records)if(Type(r)==3){AppleInodeRecord i;std::string e;Check(ApfsExtendedRecordCodec::DecodeInode(r,i,e),e);for(auto&f:i.extended_fields)f.flags=0;Check(EncodeAppleInodeRecord(i,r,e),e);}
    for(auto& seed:spec.authoritative_seeded_main_blocks)seed.first+=384;
    for(auto&r:spec.volumes[0].filesystem_records)if(Type(r)==8)PutU64LE(r.value,8,512);
    PutU64LE(spec.volumes[0].extentref_records[0].key,0,(2ull<<60)|512);
    AppleXattrRecord fork;fork.object_id=17;fork.name_utf8="com.apple.ResourceFork";fork.flags=kAppleXattrDataEmbedded;fork.data={std::byte{1},std::byte{2},std::byte{3}};apfsaccess::catalog::BtreeRecord encoded;std::string error;Check(EncodeAppleXattrRecord(fork,encoded,error),error);spec.volumes[0].filesystem_records.push_back(encoded);
    auto sibling=spec.volumes[0];sibling.oid=102;sibling.uuid_hex=std::string(32,'c');
    for(auto&r:sibling.filesystem_records)if(Type(r)==8)PutU64LE(r.value,8,528);
    PutU64LE(sibling.extentref_records[0].key,0,(2ull<<60)|528);spec.volumes.push_back(sibling);
    for(unsigned i=0;i<4;++i)spec.authoritative_seeded_main_blocks.push_back({528+i,std::vector<std::byte>(kBlockSize,std::byte(90+i))});return spec;
}
void Configure(Tx&j,const std::filesystem::path&p){j.SetJournalPath(std::filesystem::absolute(p).wstring());j.SetVolumeIdentity(L"apfs-vol:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:101");}
std::unique_ptr<Owner> Open(const std::filesystem::path&p,Tx&j,bool sibling_snapshots=true,std::uint64_t base=0){std::string e;auto o=Owner::Open(std::filesystem::absolute(p).string(),base,e,CatalogLoadPolicy::StrictApple,true,true);Check(!!o,"owner: "+e);
    std::vector<VolumeCheckpointPins> census;
    for(auto oid:{101ull,102ull}){ContainerVolumeSession s;s.volume_object_id=oid;s.container_uuid_hex=o->ContainerUuidHex();s.requested_write=true;s.use_canonical_transaction=true;s.metadata_context.allow_legacy_scaffold_for_fixtures=false;s.metadata_context.allow_native_snapshot_runtime=true;
        if(oid==102)s.metadata_context.allow_native_snapshot_runtime=sibling_snapshots;
        Check(o->MountVolume(s,e),"session: "+e);VolumeCheckpointPins pins;pins.volume_object_id=oid;if(oid==101){const bool loaded=j.LoadRequiredCheckpointXidsSinceCleanup(pins.required_checkpoint_xids,&e);Check(loaded,"wal pins ("+p.string()+"): "+e);pins.unapplied_accepted_work=j.HasUnappliedAcceptedWork();}census.push_back(pins);}
    Check(o->InitializeRequiredCheckpointCensus(census,e),"census: "+e);return o;
}
void Success(const ContainerCommitResult&r){Check(r.committed&&!r.commit_recovery_required&&r.commit_status_code==static_cast<int>(Store::CommitStatus::Committed),"commit: "+r.error+" stage="+r.commit_stage);}
std::vector<ApfsSnapshotInfo> List(Owner&o){auto*store=o.FindSessionStore(101);const auto&cp=*store->AuthoritativeAppleCheckpointView();SnapshotRuntimeDeviceSource s(store->Device(),cp.container.superblock);
    ApfsSnapshotScope scope{0,s.SizeBytes(),o.ContainerUuidHex(),cp.volumes[0].superblock.uuid_hex,101,o.CheckpointXid()};std::vector<ApfsSnapshotInfo> out;std::string e;Check(s.IsValid()&&ApfsSnapshotStore::Enumerate(s,scope,out,e),"list: "+e);return out;}
void Create(Owner&o,Tx&j,const char*name){SnapshotRuntimePlan p;std::string e;bool ok=PrepareSnapshotCreate(o,101,name,1700000000000000000ull,0,p,e);Check(ok,"prepare create: "+e);Success(ApplySnapshot(o,j,p));Check(!ApplySnapshot(o,j,p).committed,"consumed plan");}
void Delete(Owner&o,Tx&j,const ApfsSnapshotIdentity&id){SnapshotRuntimePlan p;std::string e;bool ok=PrepareSnapshotDelete(o,id,1700000000000000001ull,p,e);Check(ok,"prepare delete: "+e);Success(ApplySnapshot(o,j,p));}

Fixture Fresh(const std::filesystem::path&path,BuilderStore spec=RuntimeSpec()){
    Fixture f(spec);PutU32LE(f.image,2*kBlockSize+0x20,1);std::vector<std::byte> omap(f.image.begin()+2*kBlockSize,f.image.begin()+3*kBlockSize);FletcherForBlock(omap,kBlockSize);std::copy(omap.begin(),omap.end(),f.image.begin()+2*kBlockSize);f.Reload();Save(path,f.image);return f;
}
void HashPayload(std::span<const std::byte>b,std::array<std::uint8_t,32>&h){BCRYPT_ALG_HANDLE a=nullptr;Check(BCryptOpenAlgorithmProvider(&a,BCRYPT_SHA256_ALGORITHM,nullptr,0)>=0,"hash provider");Check(BCryptHash(a,nullptr,0,reinterpret_cast<PUCHAR>(const_cast<std::byte*>(b.data())),static_cast<ULONG>(b.size()),h.data(),32)>=0,"hash");BCryptCloseAlgorithmProvider(a,0);}
void PreimageBatching(){
    class Source final : public RandomAccessSource {
    public:
        std::vector<std::byte> bytes=std::vector<std::byte>(64*kBlockSize);
        mutable std::vector<std::pair<std::uint64_t,std::size_t>> calls;
        bool short_read=false;
        std::uint64_t SizeBytes()const override{return bytes.size();}
        bool Read(std::uint64_t offset,std::size_t size,std::vector<std::byte>&out)const override{
            calls.emplace_back(offset,size);out.clear();
            if(offset>bytes.size()||size>bytes.size()-offset)return false;
            out.assign(bytes.begin()+offset,bytes.begin()+offset+size);
            if(short_read&&!out.empty())out.pop_back();return true;
        }
    } source;
    for(std::size_t i=0;i<source.bytes.size();++i)source.bytes[i]=std::byte((i/4096+i%251)%256);
    std::set<std::uint64_t> blocks{50,52};for(std::uint64_t i=1;i<=34;++i)blocks.insert(i);
    std::vector<std::byte> canonical;
    for(const auto block:blocks){
        std::array<std::uint8_t,32> digest{};
        HashPayload(std::span<const std::byte>(source.bytes).subspan(block*kBlockSize,kBlockSize),digest);
        for(unsigned i=0;i<8;++i)canonical.push_back(std::byte((block>>(8*i))&255));
        for(auto byte:digest)canonical.push_back(std::byte(byte));
    }
    std::array<std::uint8_t,32> expected{},actual{};HashPayload(canonical,expected);
    Check(snapshot_detail::HashPreimageBlocks(source,kBlockSize,64,blocks,actual)&&actual==expected,
        "batched preimage equals independent legacy sorted per-block wire digest");
    Check(source.calls.size()==5,"36 selected blocks use five actual bounded reads");
    std::size_t observed_bytes=0;
    for(const auto&[offset,size]:source.calls){Check(size<=65536&&offset%kBlockSize==0,"aligned bounded preimage batch");observed_bytes+=size;}
    Check(observed_bytes==blocks.size()*kBlockSize,"preimage never reads gaps or omits selected blocks");
    source.bytes[50*kBlockSize+27]^=std::byte{1};source.calls.clear();
    Check(snapshot_detail::HashPreimageBlocks(source,kBlockSize,64,blocks,actual)&&actual!=expected,
        "later sibling payload change is freshly hashed");
    source.short_read=true;actual=expected;
    Check(!snapshot_detail::HashPreimageBlocks(source,kBlockSize,64,blocks,actual)&&actual==std::array<std::uint8_t,32>{},
        "successful short-read transport still refuses without a digest");
    source.short_read=false;source.calls.clear();auto invalid=blocks;invalid.insert(64);
    Check(!snapshot_detail::HashPreimageBlocks(source,kBlockSize,64,invalid,actual)&&source.calls.empty(),
        "out-of-window block refuses before I/O");
    auto budget=std::make_shared<ApfsReadBudget>(4,256ull<<20,1000000,256ull<<20);
    BudgetedRandomAccessSource limited(source,budget);source.calls.clear();
    Check(!snapshot_detail::HashPreimageBlocks(limited,kBlockSize,64,blocks,actual)&&budget->Failed()&&
        source.calls.size()==4&&actual==std::array<std::uint8_t,32>{},"preimage preserves sticky read refusal");
    Check(!snapshot_detail::HashPreimageBlocks(limited,kBlockSize,64,blocks,actual)&&source.calls.size()==4,
        "failed budget cannot retry or return cached hash");
    std::cout<<"PreimageBatching: 36 blocks, 5 reads, canonical digest exact\n";
}
void Live(Owner&o,Tx&j,Store::MutationRequest request,const std::vector<std::byte>&payload={}){
    const auto operation=request.operation;const auto preimage=o.CheckpointXid();std::uint64_t seq=0;
    auto source_payload=payload;
    if(operation!=Store::MutationOperation::Write&&operation!=Store::MutationOperation::CloneFile){auto*store=o.FindSessionStore(101);const auto inode=store->LookupCommittedInodeByPath(request.path);if(inode)Check(store->ReadCommittedFileRange(request.path,0,inode->logical_size,source_payload),"read live mutation source");}
    if(operation==Store::MutationOperation::SetFileSize && request.length>source_payload.size())source_payload.resize(request.length,std::byte{0});

    auto result=o.Commit(101,{request},[&](const auto&requests,const auto&ids,std::uint64_t xid,auto&pins,std::string&e){
        Tx::MutationIntent intent;intent.path=requests[0].path;intent.secondary_path=requests[0].secondary_path;intent.object_id=ids[0].object_id;intent.generation=ids[0].generation;intent.offset=requests[0].offset;intent.length=requests[0].length;
        if(operation==Store::MutationOperation::Write){intent.kind=Tx::MutationKind::Write;intent.inline_payload=payload;}
        else if(operation==Store::MutationOperation::SetFileSize)intent.kind=Tx::MutationKind::SetFileSize;
        else if(operation==Store::MutationOperation::CloneFile){intent.kind=Tx::MutationKind::CloneFile;intent.inline_payload=requests[0].inline_payload;}
        else if(operation==Store::MutationOperation::SetExtendedAttribute){intent.kind=Tx::MutationKind::SetExtendedAttribute;intent.length=0;intent.inline_payload=requests[0].inline_payload;}
        else return false;
        if(!intent.inline_payload.empty()){intent.payload_length=intent.inline_payload.size();HashPayload(intent.inline_payload,intent.payload_checksum);}
        if(!j.Begin()||!j.RecordMutation(intent)||!j.Accept(xid)){e="live acceptance";return false;}seq=j.Watermarks().accepted_sequence;return j.LoadRequiredCheckpointXidsSinceCleanup(pins,&e);
    },[&](std::size_t,const auto&,const auto&,std::string&){if(operation!=Store::MutationOperation::CloneFile)o.FindSessionStore(101)->SetFilePayloadRangeProvider([&](const auto&,auto,auto at,std::span<std::byte>b){if(at>source_payload.size()||b.size()>source_payload.size()-at)return false;std::copy_n(source_payload.begin()+at,b.size(),b.begin());return true;});return true;},{},false,{}, {},
    [&](const Store&store,std::uint64_t,std::string&e){return store.ValidateRequiredRecoveryCheckpoints({preimage},e);});
    // Ordinary live verification is independent of WAL sequence numbers.
    Success(result);if(operation==Store::MutationOperation::CloneFile){std::vector<Tx::AcceptedTransaction>txs;Check(j.LoadAcceptedTransactionsSinceCleanup(txs)&&txs.size()==1,"clone accepted receipt");std::string e;Check(o.FindSessionStore(101)->ReplayNativeClone(txs[0].mutations[0],preimage)==Store::CloneReplay::AlreadyPublished,"snapshot clone published proof");}
    Check(j.MarkApfsDurableThrough(seq)&&j.MarkCleanedThrough(seq),"live cleanup");std::vector<std::uint64_t>pins;std::string e;Check(j.LoadRequiredCheckpointXidsSinceCleanup(pins,&e)&&o.UpdateRequiredCheckpointXids(101,pins,e),"live pin retirement");
}
std::vector<std::byte> LiveBytes(Owner&o,const std::wstring&path){auto*s=o.FindSessionStore(101);auto i=s->LookupCommittedInodeByPath(path);Check(!!i,"live inode");std::vector<std::byte>b;Check(s->ReadCommittedFileRange(path,0,i->logical_size,b),"live bytes");return b;}
void Observe(Owner&o,std::size_t index,const std::vector<std::byte>&expected,const std::vector<std::byte>&fork,std::optional<std::size_t>clone_size={}){
    auto id=List(o).at(index).identity;std::string e;auto reader=o.AcquireSnapshotReader(id,e);Check(!!reader,"reader lease: "+e);
    const auto&view=reader->Projection().View();std::vector<std::byte>b;Check(reader->Read(17,0,expected.size(),b)&&b==expected,"historical payload hash/bytes exact");
    std::array<std::uint8_t,32>a{},c{};HashPayload(expected,a);HashPayload(b,c);Check(a==c,"historical SHA256");
    Check(view.extended_attributes_by_inode.at(17).at("com.apple.ResourceFork").data==fork,"historical resource fork exact");
    auto inode=std::find_if(view.inodes.begin(),view.inodes.end(),[](const auto&i){return i.object_id==17;});Check(inode!=view.inodes.end()&&inode->mode==0100640&&inode->owner==501&&inode->group==20&&inode->logical_size==expected.size(),"historical metadata exact");
    Check(inode->xid==id.snapshot_xid,"historical file-view XID preserved");
    if(clone_size){auto clone=std::find_if(view.inodes.begin(),view.inodes.end(),[](const auto&i){return i.full_path==L"\\copy";});Check(clone!=view.inodes.end()&&clone->logical_size==*clone_size,"historical clone size");Check(reader->Read(clone->object_id,0,*clone_size,b)&&std::equal(b.begin(),b.end(),expected.begin()),"historical clone bytes");}
}
void Lifecycle(){
    auto f=Fresh("lifecycle.apfs");Tx j(L"Strict");Configure(j,"lifecycle.wal");auto o=Open("lifecycle.apfs",j);const auto original=LiveBytes(*o,L"\\clone0");Create(*o,j,"one");Observe(*o,0,original,{std::byte{1},std::byte{2},std::byte{3}});
    SnapshotRuntimePlan busy;std::string e;auto id=List(*o)[0].identity;auto reader=o->AcquireSnapshotReader(id,e);Check(!!reader,"pin snapshot");Check(PrepareSnapshotDelete(*o,id,1,busy,e),"busy deletion preflight");auto refused=ApplySnapshot(*o,j,busy);Check(!refused.committed&&refused.error=="SnapshotRuntimeReaderBusy","deletion refuses active reader");
    auto write=[&](const std::wstring&path,std::vector<std::byte>payload){Store::MutationRequest r;r.operation=Store::MutationOperation::Write;r.path=path;r.length=payload.size();Live(*o,j,r,payload);};
    std::vector<std::byte> second(original.size(),std::byte{0x42});write(L"\\clone0",second);std::vector<std::byte> pinned_bytes;Check(reader->Read(17,0,original.size(),pinned_bytes)&&pinned_bytes==original,"reader holds history through live COW and WAL cleanup");reader.reset();Observe(*o,0,original,{std::byte{1},std::byte{2},std::byte{3}});
    Store::MutationRequest clone;Check(o->FindSessionStore(101)->PrepareNativeClone(L"\\clone0",L"\\copy",clone),"snapshot-aware clone prepares");Live(*o,j,clone);
    Store::MutationRequest resize;resize.operation=Store::MutationOperation::SetFileSize;resize.path=L"\\copy";resize.length=4096;Live(*o,j,resize);
    Store::MutationRequest attr;attr.operation=Store::MutationOperation::SetExtendedAttribute;attr.path=L"\\clone0";attr.secondary_path=L"com.apple.ResourceFork";attr.inline_payload={std::byte{9},std::byte{8}};attr.length=attr.inline_payload.size();Live(*o,j,attr);
    Create(*o,j,"two");Observe(*o,1,second,{std::byte{9},std::byte{8}},4096);Observe(*o,0,original,{std::byte{1},std::byte{2},std::byte{3}});
    std::vector<std::byte> third(original.size(),std::byte{0x58});write(L"\\clone0",third);resize.path=L"\\clone0";resize.length=8192;Live(*o,j,resize);third.resize(8192);
    Observe(*o,0,original,{std::byte{1},std::byte{2},std::byte{3}});Observe(*o,1,second,{std::byte{9},std::byte{8}},4096);
    Save("two-history.apfs",Bytes("lifecycle.apfs"));Delete(*o,j,List(*o)[0].identity);Observe(*o,0,second,{std::byte{9},std::byte{8}},4096);Check(LiveBytes(*o,L"\\clone0")==third,"live preserved after oldest deletion");Delete(*o,j,List(*o)[0].identity);Check(List(*o).empty()&&LiveBytes(*o,L"\\clone0")==third,"last deletion preserves live");
    const auto sibling=f.checkpoint.volumes[1].superblock_object.physical_block;const auto now=Bytes("lifecycle.apfs");Check(std::equal(now.begin()+sibling*kBlockSize,now.begin()+(sibling+1)*kBlockSize,f.image.begin()+sibling*kBlockSize),"sibling APSB unchanged");

    std::cout<<"PASS actual snapshot/live/clone/truncate/fork/oldest/newest/last lifecycle\n";
}
void Newest(){Fixture f(RuntimeSpec());const std::vector<std::byte> original(f.image.begin()+512*kBlockSize,f.image.begin()+516*kBlockSize);
    {Tx branch(L"Strict");Configure(branch,"newest.wal");Save("newest.apfs",Bytes("two-history.apfs"));auto other=Open("newest.apfs",branch);Delete(*other,branch,List(*other)[1].identity);Observe(*other,0,original,{std::byte{1},std::byte{2},std::byte{3}});Delete(*other,branch,List(*other)[0].identity);}
}
void Faults(){
    for(bool deletion:{false,true})for(const std::string mode:{"before-acceptance","accept-flush","after-acceptance","pre-switch","post-switch","final-flush","cleanup"}){
        const auto stem=std::string(deletion?"delete-":"create-")+mode;const auto image=stem+".apfs",wal=stem+".wal";auto fixture=Fresh(image);std::uint64_t source=0;
        {Tx j(L"Strict");Configure(j,wal);auto o=Open(image,j);if(deletion){Create(*o,j,"target");Store::MutationRequest write;write.operation=Store::MutationOperation::Write;write.path=L"\\clone0";write.length=4*kBlockSize;Live(*o,j,write,std::vector<std::byte>(4*kBlockSize,std::byte{0x6b}));}source=o->CheckpointXid();SnapshotRuntimePlan p;std::string e;
            Check(deletion?PrepareSnapshotDelete(*o,List(*o)[0].identity,1,p,e):PrepareSnapshotCreate(*o,101,"target",1,0,p,e),"fault plans: "+e);
            if(mode=="before-acceptance")j.SetFaultInjectionHook([](const std::string&stage){if(stage=="begin")throw std::runtime_error("injected before durable acceptance");});
            if(mode=="accept-flush")j.SetJournalFaultInjectionHook([](std::string_view s){return s=="durable-flush";});
            if(mode=="cleanup"){unsigned flushes=0;j.SetJournalFaultInjectionHook([flushes](std::string_view s)mutable{return s=="durable-flush"&&++flushes==3;});}
            o->FindSessionStore(101)->SetCommitStageHook([&](std::string_view s){if(mode=="final-flush"&&s=="before-apple-final-flush")SetEnvironmentVariableW(L"APFSACCESS_RW_FAULT_FLUSH",L"1");
                
                if(mode=="after-acceptance"&&s=="before-apple-publish")return false;
                if(mode=="pre-switch"&&s=="before-apple-checkpoint-switch")return false;
                if(mode=="post-switch"&&s=="before-apple-final-flush")return false;return true;});
            const auto result=ApplySnapshot(*o,j,p);SetEnvironmentVariableW(L"APFSACCESS_RW_FAULT_FLUSH",nullptr);
            std::cout<<stem<<" xid="<<o->CheckpointXid()<<" status="<<result.commit_status_code<<" error="<<result.error<<"\n";
            Check(!result.committed||result.commit_recovery_required,"fault never acknowledged");
            if(mode!="before-acceptance")Check(result.commit_recovery_required,"accepted evidence retained");
        }
        for(unsigned restart=0;restart<2;++restart){Tx j(L"Strict");Configure(j,wal);auto o=Open(image,j);std::string e;const auto recovered=ReplaySnapshot(*o,j,101,e);
            if(mode=="before-acceptance")Check(!recovered.has_value(),"preacceptance no receipt");
            else Check(restart? !recovered.has_value():(mode=="cleanup"?!recovered.has_value()||*recovered:recovered.value_or(false)),"restart "+std::to_string(restart)+": "+e);
            const auto inventory=List(*o);Check(inventory.size()==((mode=="before-acceptance")?(deletion?1:0):(deletion?0:1)),"restart exact inventory");
            Check(!j.HasUnappliedAcceptedWork(),"restart cleaned canonical WAL");
            auto disk=Bytes(image);Check(std::equal(disk.begin()+512*kBlockSize,disk.begin()+516*kBlockSize,fixture.image.begin()+512*kBlockSize),"zero-reference/retained snapshot payload never prematurely reused");
            const auto sibling=fixture.checkpoint.volumes[1].superblock_object.physical_block;
            Check(std::equal(disk.begin()+sibling*kBlockSize,disk.begin()+(sibling+1)*kBlockSize,fixture.image.begin()+sibling*kBlockSize),"fault/restart sibling APSB exact");}
    }
    std::cout<<"PASS publication and WAL fault boundaries with two real reopens\n";
}

void Negatives(){
    std::string e;{
    Fresh("negative.apfs");Tx j(L"Strict");Configure(j,"negative.wal");auto o=Open("negative.apfs",j);
    SnapshotRuntimePlan stale,good;Check(PrepareSnapshotCreate(*o,101,"stale",1,0,stale,e),"stale plan prepares");Create(*o,j,"good");const auto before=Bytes("negative.apfs");const auto accepted=j.Watermarks().accepted_sequence;
    Check(!ApplySnapshot(*o,j,stale).committed&&Bytes("negative.apfs")==before&&j.Watermarks().accepted_sequence==accepted,"stale plan rejected without WAL/image writes");
    auto id=List(*o)[0].identity;++id.root_physical_block;Check(!PrepareSnapshotDelete(*o,id,1,good,e),"mismatched exact snapshot root refused");
    Check(!PrepareSnapshotCreate(*o,101,"good",1,0,good,e),"duplicate name refused");
    Check(PrepareSnapshotCreate(*o,101,"forged",1,0,good,e),"forged plan base");NativeSnapshotIntent intent;Check(DecodeNativeSnapshotIntent(good.request.inline_payload,intent),"decode intent");intent.publication_hash[0]^=1;good.request.inline_payload=EncodeNativeSnapshotIntent(intent);
    Check(!ApplySnapshot(*o,j,good).committed&&Bytes("negative.apfs")==before&&j.Watermarks().accepted_sequence==accepted,"mismatched deterministic publication rejected before acceptance");
    } {auto spec=RuntimeSpec();spec.authoritative_main_free_blocks=5;Fresh("capacity.apfs",spec);Tx cj(L"Strict");Configure(cj,"capacity.wal");auto co=Open("capacity.apfs",cj);const auto cb=Bytes("capacity.apfs");SnapshotRuntimePlan cp;
    Check(!PrepareSnapshotCreate(*co,101,"full",1,0,cp,e)&&cj.Watermarks().accepted_sequence==0&&Bytes("capacity.apfs")==cb,"insufficient capacity precedes acceptance");std::cout<<"capacity refusal: "<<e<<"\n";
    }
    // Preserve one real accepted, unapplied intent; mutate checksum-valid WAL
    // records to exercise canonical transaction and typed replay validation.
    Fresh("receipt.apfs");{
        Tx tx(L"Strict");Configure(tx,"receipt.wal");auto owner=Open("receipt.apfs",tx);SnapshotRuntimePlan p;Check(PrepareSnapshotCreate(*owner,101,"receipt",1,0,p,e),"receipt prepares");owner->FindSessionStore(101)->SetCommitStageHook([](std::string_view stage){return stage!="before-apple-publish";});Check(ApplySnapshot(*owner,tx,p).commit_recovery_required,"receipt accepted unapplied");}
    auto read=WriteAheadLog::ReadAll("receipt.wal","apfs-vol:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:101");Check(read.status==WriteAheadLog::ReadStatus::Ok&&read.records.size()==2,"actual accepted envelope read");
    for(const std::string mode:{"duplicate","mixed","wrong-source","forged-history","forged-publication"}){
        auto records=read.records;
        if(mode=="duplicate"||mode=="mixed"){auto extra=records[0];extra.sequence=2;if(mode=="mixed"){extra.operation=WriteAheadLog::OperationKind::SetFileSize;extra.inline_payload.clear();extra.payload_length=0;extra.payload_sha256={};extra.object_id=17;extra.parent_object_id=0;extra.path_utf8="\\clone0";extra.logical_length=1;}records.insert(records.begin()+1,extra);records.back().sequence=3;records.back().logical_length=2;}
        else if(mode=="wrong-source")++records.back().object_id;
        else {NativeSnapshotIntent p;Check(DecodeNativeSnapshotIntent(records[0].inline_payload,p),"forgery decode");if(mode=="forged-history")p.preimage_hash[0]^=1;else p.publication_hash[0]^=1;records[0].inline_payload=EncodeNativeSnapshotIntent(p);HashPayload(records[0].inline_payload,records[0].payload_sha256);}
        const auto wal="forged-"+mode+".wal",image="forged-"+mode+".apfs";Save(image,Bytes("receipt.apfs"));{std::ofstream f(wal,std::ios::binary);for(const auto&r:records){auto encoded=WriteAheadLog::EncodeForTest(r);Check(!encoded.empty(),"checksum-valid forged envelope");f.write(reinterpret_cast<const char*>(encoded.data()),encoded.size());}}
        const auto old=Bytes(image),evidence=Bytes(wal);Tx tx(L"Strict");Configure(tx,wal);std::vector<std::uint64_t>pins;
        if(mode=="duplicate"||mode=="mixed"||mode=="wrong-source")Check(!tx.LoadRequiredCheckpointXidsSinceCleanup(pins,&e),"canonical rejects "+mode);
        else{auto owner=Open(image,tx);Check(!ReplaySnapshot(*owner,tx,101,e).value_or(true),"typed replay rejects "+mode);}
        Check(Bytes(image)==old&&Bytes(wal)==evidence,"forged receipt preserves all evidence");std::cout<<"receipt refusal "<<mode<<": "<<e<<"\n";
    }
    std::cout<<"PASS stale identity capacity and forged canonical receipts\n";
}

void ReaderLifetime(){
    Fresh("reader-lifetime.apfs");std::shared_ptr<const SnapshotRuntimeReader> reader;std::vector<std::byte> expected;
    {Tx tx(L"Strict");Configure(tx,"reader-lifetime.wal");auto owner=Open("reader-lifetime.apfs",tx);expected=LiveBytes(*owner,L"\\clone0");Create(*owner,tx,"held");std::string e;reader=owner->AcquireSnapshotReader(List(*owner)[0].identity,e);Check(!!reader,"reader acquired");}
    std::vector<std::byte>bytes;Check(!reader->Read(17,0,expected.size(),bytes)&&bytes.empty(),"coordinator destruction closes reader before history can retire");reader.reset();
    Tx tx(L"Strict");Configure(tx,"reader-lifetime.wal");auto owner=Open("reader-lifetime.apfs",tx);Delete(*owner,tx,List(*owner)[0].identity);
    std::cout<<"PASS reader lifetime tied to serialized coordinator history\n";
}

constexpr std::size_t kSnapshotPhysicalBase = 5 * kBlockSize + 512;
constexpr std::size_t kSnapshotTailBytes = 2 * kBlockSize + 37;

Fixture FreshWindow(const std::filesystem::path& path){
    auto f=Fresh(path);
    std::vector<std::byte> disk(kSnapshotPhysicalBase,std::byte{0xa5});
    disk.insert(disk.end(),f.image.begin(),f.image.end());
    disk.insert(disk.end(),kSnapshotTailBytes,std::byte{0x5a});
    Save(path,disk);return f;
}
void OutsideWindow(const std::filesystem::path& path,const std::vector<std::byte>& before){
    const auto after=Bytes(path);
    Check(after.size()==before.size(),"bounded snapshot preserves physical image length");
    Check(std::equal(after.begin(),after.begin()+kSnapshotPhysicalBase,before.begin()),"bounded snapshot preserves unrelated prefix");
    Check(std::equal(after.end()-kSnapshotTailBytes,after.end(),before.end()-kSnapshotTailBytes),"bounded snapshot preserves unrelated tail");
}
NativeRawSnapshotReceipt RawImageDisguise(const NativeSnapshotIntent& intent,
    const apfsaccess::catalog::AppleCheckpointView& checkpoint){
    NativeRawSnapshotReceipt receipt;auto& binding=receipt.binding;
    binding.hardware.kind=RawHardwareIdentityKind::QualifiedSerialTuple;
    binding.hardware.bus_type=BusTypeUsb;binding.hardware.vendor="Samsung";
    binding.hardware.product="Flash Drive FIT";binding.hardware.revision="1100";
    binding.hardware.serial="AA00000000000489";
    binding.media.disk_guid.fill(std::byte{0x0a});binding.media.partition_guid.fill(std::byte{0x0b});
    binding.media.partition_offset_bytes=binding.media.base_offset_bytes=1048576;
    binding.media.partition_length_bytes=binding.media.limit_bytes=intent.scope.store_size_bytes;
    binding.media.disk_size_bytes=1048576+intent.scope.store_size_bytes+1048576;
    binding.media.logical_sector_bytes=512;binding.media.physical_sector_bytes=4096;
    receipt.selected_journal_identity="apfs-vol:"+intent.scope.container_uuid_hex+":101";
    receipt.peers={{101,intent.scope.volume_uuid_hex,receipt.selected_journal_identity},
        {102,checkpoint.volumes[1].superblock.uuid_hex,"apfs-vol:"+intent.scope.container_uuid_hex+":102"}};
    return receipt;
}
void SameWatermarks(const Tx::DurabilityWatermarks& before,const Tx& journal){
    const auto after=journal.Watermarks();
    Check(before.accepted_sequence==after.accepted_sequence&&
        before.apfs_durable_sequence==after.apfs_durable_sequence&&
        before.cleanup_sequence==after.cleanup_sequence,"raw image refusal preserves all WAL watermarks");
}
void RawImageDisguiseRefusals(){
    for(const bool deletion:{false,true})for(const bool published:{false,true}){
        const auto stem=std::string("raw-image-refusal-")+(deletion?"delete-":"create-")+
            (published?"published":"preimage");
        const auto image=stem+".apfs",wal=stem+".wal";FreshWindow(image);std::uint64_t target_xid=0;
        {
            Tx journal(L"Strict");Configure(journal,wal);auto owner=Open(image,journal,true,kSnapshotPhysicalBase);
            if(deletion)Create(*owner,journal,"target");
            SnapshotRuntimePlan plan;std::string error;
            Check(deletion?PrepareSnapshotDelete(*owner,List(*owner)[0].identity,1,plan,error):
                PrepareSnapshotCreate(*owner,101,"target",1,0,plan,error),"raw refusal base plan prepares");
            auto* store=owner->FindSessionStore(101);const auto& checkpoint=*store->AuthoritativeAppleCheckpointView();
            NativeSnapshotIntent intent;Check(DecodeNativeSnapshotIntent(plan.request.inline_payload,intent),"raw refusal decodes original SNP1");
            intent.raw_receipt=RawImageDisguise(intent,checkpoint);
            SnapshotRuntimePlan forged;forged.owner=plan.owner;forged.request=plan.request;
            forged.request.inline_payload=EncodeNativeSnapshotIntent(intent);
            forged.request.length=forged.request.inline_payload.size();
            Check(!forged.request.inline_payload.empty(),"raw refusal uses canonical SNP2 bytes");
            const auto before=Bytes(image),journal_bytes=Bytes(wal);const auto exists=std::filesystem::exists(wal);
            const auto marks=journal.Watermarks();const auto pending=store->PendingMutationCount();
            SnapshotRuntimeDeviceSource source(store->Device(),checkpoint.container.superblock);
            AppleVolumeTransactionPlan publication;
            Check(!PlanSnapshotRuntimeCheckpoint(source,checkpoint,intent,intent.pins,publication,error),"public planner rejects raw receipt on image source");
            Check(!VerifyPublishedSnapshot(*store,intent,error)&&error=="SnapshotRuntimeRawReceiptNotAdmitted","publication verifier rejects raw image disguise");
            Check(store->StageMutation(forged.request)!=Store::MutationStatus::Applied,"direct staging rejects raw image disguise");
            Check(!ApplySnapshot(*owner,journal,forged).committed,"apply rejects raw image disguise before acceptance");
            SameWatermarks(marks,journal);
            Check(store->PendingMutationCount()==pending&&journal.PendingMutationCount()==0&&
                Bytes(image)==before&&std::filesystem::exists(wal)==exists&&Bytes(wal)==journal_bytes,
                "raw apply/staging refusal preserves whole image and original WAL");
            const auto source_xid=owner->CheckpointXid();target_xid=source_xid;bool hook_reached=false;
            store->SetCommitStageHook([&](std::string_view stage){
                if(stage!=(published?"after-apple-publish":"before-apple-publish"))return true;
                hook_reached=true;return false;
            });
            Check(ApplySnapshot(*owner,journal,plan).commit_recovery_required&&hook_reached,"real SNP1 acceptance reaches requested recovery boundary");
            const auto on_disk=apfsaccess::catalog::LoadAppleCheckpointView(source,0,source.SizeBytes(),error);
            Check(on_disk&&on_disk->container.superblock.xid==source_xid+(published?1:0),"raw replay test proves actual preimage/published disk state");
        }
        auto read=WriteAheadLog::ReadAll(wal,"apfs-vol:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:101");
        Check(read.status==WriteAheadLog::ReadStatus::Ok,"raw replay reads real accepted WAL");
        unsigned mutations=0;
        for(auto& record:read.records){
            if(record.operation!=WriteAheadLog::OperationKind::CreateSnapshot&&record.operation!=WriteAheadLog::OperationKind::DeleteSnapshot)continue;
            NativeSnapshotIntent intent;Check(DecodeNativeSnapshotIntent(record.inline_payload,intent),"raw replay accepted intent decodes");
            if(intent.scope.checkpoint_xid!=target_xid)continue;
            // Populate the sibling identity from the original source profile, never from a raw handle.
            Fixture fixture(RuntimeSpec());intent.raw_receipt=RawImageDisguise(intent,fixture.checkpoint);
            record.inline_payload=EncodeNativeSnapshotIntent(intent);record.payload_length=record.inline_payload.size();
            HashPayload(record.inline_payload,record.payload_sha256);++mutations;
        }
        Check(mutations==1,"raw replay changes exactly one accepted snapshot mutation");
        {std::ofstream output(wal,std::ios::binary|std::ios::trunc);
            for(const auto& record:read.records){const auto bytes=WriteAheadLog::EncodeForTest(record);
                Check(!bytes.empty(),"raw replay receipt retains valid outer checksum and journal identity");
                output.write(reinterpret_cast<const char*>(bytes.data()),bytes.size());}
            Check(!!output,"raw replay rewritten WAL saved");}
        const auto before=Bytes(image),journal_bytes=Bytes(wal);
        Tx journal(L"Strict");Configure(journal,wal);auto owner=Open(image,journal,true,kSnapshotPhysicalBase);
        auto* store=owner->FindSessionStore(101);const auto pending=store->PendingMutationCount();
        const auto marks=journal.Watermarks();std::string error;
        const auto replay=ReplaySnapshot(*owner,journal,101,error);
        Check(replay.has_value()&&!*replay,"raw replay refuses canonical SNP2 at both image boundaries");
        SameWatermarks(marks,journal);
        Check(store->PendingMutationCount()==pending&&journal.PendingMutationCount()==0&&
            journal.HasUnappliedAcceptedWork()&&Bytes(image)==before&&std::filesystem::exists(wal)&&Bytes(wal)==journal_bytes,
            "raw replay refusal preserves image, accepted debt and original WAL bytes");
    }
    std::cout<<"PASS raw image disguise rejection for Create/Delete apply/staging/planner and both accepted replay boundaries\n";
}
void SnapshotSourceWindowBounds(){
    const auto f=FreshWindow("window-bounds.apfs");const auto disk=Bytes("window-bounds.apfs");
    Tx j(L"Strict");Configure(j,"window-bounds.wal");auto owner=Open("window-bounds.apfs",j,true,kSnapshotPhysicalBase);
    const auto wal_exists=std::filesystem::exists("window-bounds.wal");const auto wal=Bytes("window-bounds.wal");
    auto*store=owner->FindSessionStore(101);const auto&cp=*store->AuthoritativeAppleCheckpointView();const auto&device=store->Device();
    SnapshotRuntimeDeviceSource source(device,cp.container.superblock);
    Check(device.IsRegularFile()&&device.BaseOffsetBytes()==kSnapshotPhysicalBase&&source.IsValid(),"bounded source retains real image authority and physical base");
    Check(source.SizeBytes()==f.image.size()&&device.GetGeometry().total_bytes>source.SizeBytes(),"source size is NX window, not remaining image geometry");
    std::vector<std::byte> bytes;
    Check(source.Read(0,kBlockSize,bytes)&&std::equal(bytes.begin(),bytes.end(),f.image.begin()),"bounded source applies device base exactly once");
    Check(source.Read(source.SizeBytes()-1,1,bytes)&&bytes[0]==f.image.back(),"bounded source reads last container byte");
    for(const auto offset:{source.SizeBytes(),UINT64_MAX}){
        bytes={std::byte{1}};Check(!source.Read(offset,1,bytes)&&bytes.empty(),"out-of-window read refuses with empty output");
    }
    bytes={std::byte{1}};Check(!source.Read(source.SizeBytes()-1,2,bytes)&&bytes.empty(),"read crossing into unrelated tail refuses");
    Check(source.Read(source.SizeBytes(),0,bytes)&&bytes.empty()&&!source.Read(UINT64_MAX,0,bytes),"zero-length reads still enforce the window");
    auto nx=cp.container.superblock;nx.block_count=UINT64_MAX;
    SnapshotRuntimeDeviceSource overflow(device,nx);bytes={std::byte{1}};
    Check(!overflow.IsValid()&&overflow.SizeBytes()==0&&!overflow.Read(0,1,bytes)&&bytes.empty(),"overflowing NX span refuses");
    nx=cp.container.superblock;nx.block_count+=3;SnapshotRuntimeDeviceSource oversized(device,nx);
    Check(!oversized.IsValid(),"NX span beyond held image refuses");
    nx=cp.container.superblock;nx.block_size=0;SnapshotRuntimeDeviceSource zero_size(device,nx);
    nx=cp.container.superblock;nx.block_count=0;SnapshotRuntimeDeviceSource zero_count(device,nx);
    Check(!zero_size.IsValid()&&!zero_count.IsValid(),"empty NX geometry refuses");
    std::string e;Check(VerifySnapshotJournalCurrency(*owner,101,j,e),"journal currency uses bounded source: "+e);
    SnapshotRuntimePlan plan;Check(PrepareSnapshotCreate(*owner,101,"bounded",1,0,plan,e),"bounded create prepares: "+e);
    NativeSnapshotIntent intent;Check(DecodeNativeSnapshotIntent(plan.request.inline_payload,intent)&&
        intent.scope.store_offset_bytes==0&&intent.scope.store_size_bytes==source.SizeBytes(),"SNP1 scope stays zero-based and NX-sized");
    Check(ValidateSnapshotMutation(*store,plan.request,e),"bounded preimage validates: "+e);
    auto disguised=intent;NativeRawSnapshotReceipt raw_receipt;auto&binding=raw_receipt.binding;
    binding.hardware.kind=RawHardwareIdentityKind::QualifiedSerialTuple;binding.hardware.bus_type=BusTypeUsb;
    binding.hardware.vendor="Samsung";binding.hardware.product="Flash Drive FIT";binding.hardware.revision="1100";binding.hardware.serial="AA00000000000489";
    binding.media.disk_guid.fill(std::byte{0x0a});binding.media.partition_guid.fill(std::byte{0x0b});
    binding.media.partition_offset_bytes=binding.media.base_offset_bytes=1048576;
    binding.media.partition_length_bytes=binding.media.limit_bytes=intent.scope.store_size_bytes;
    binding.media.disk_size_bytes=1048576+intent.scope.store_size_bytes+1048576;
    binding.media.logical_sector_bytes=512;binding.media.physical_sector_bytes=4096;
    raw_receipt.selected_journal_identity="apfs-vol:"+intent.scope.container_uuid_hex+":101";
    raw_receipt.peers={{101,intent.scope.volume_uuid_hex,raw_receipt.selected_journal_identity},{102,cp.volumes[1].superblock.uuid_hex,"apfs-vol:"+intent.scope.container_uuid_hex+":102"}};
    disguised.raw_receipt=raw_receipt;const auto disguised_bytes=EncodeNativeSnapshotIntent(disguised);
    NativeSnapshotIntent raw_decoded;Check(!disguised_bytes.empty()&&DecodeNativeSnapshotIntent(disguised_bytes,raw_decoded),"canonical SNP2 shape carries no image authority");
    auto disguised_request=plan.request;disguised_request.inline_payload=disguised_bytes;disguised_request.length=disguised_bytes.size();
    Check(!ValidateSnapshotMutation(*store,disguised_request,e)&&e=="SnapshotRuntimeRawReceiptNotAdmitted","SNP2 cannot grant raw authority to an image session");
    auto wrong=intent;wrong.scope.store_size_bytes=device.GetGeometry().total_bytes;
    auto request=plan.request;request.inline_payload=EncodeNativeSnapshotIntent(wrong);request.length=request.inline_payload.size();
    Check(!ValidateSnapshotMutation(*store,request,e),"wrong intent span refuses before acceptance");
    VectorRandomAccessSource whole(disk);OffsetRandomAccessSource unbounded(&whole,kSnapshotPhysicalBase,whole.SizeBytes()-kSnapshotPhysicalBase);
    AppleVolumeTransactionPlan publication;
    Check(!PlanSnapshotRuntimeCheckpoint(unbounded,cp,intent,intent.pins,publication,e),"geometry-sized planner source refuses despite correct container bytes");
    std::vector<BtreeRecord> references;
    Check(!LoadSnapshotRuntimeLiveReferences(unbounded,cp,101,references,e)&&references.empty(),"live reference source requires the same NX span");
    wrong=intent;wrong.checkpoint_slot=UINT64_MAX;
    Check(!PlanSnapshotRuntimeCheckpoint(source,cp,wrong,wrong.pins,publication,e),"overflowing checkpoint address refuses");
    Check(j.Watermarks().accepted_sequence==0&&store->PendingMutationCount()==0&&Bytes("window-bounds.apfs")==disk,"window refusals preserve whole image and WAL");
    Check(std::filesystem::exists("window-bounds.wal")==wal_exists&&Bytes("window-bounds.wal")==wal,"window refusals preserve original WAL presence and bytes");
    std::cout<<"PASS NX source window bounds, same-base reads and wrong-span refusals\n";
}
void SnapshotSourceWindowLifecycle(){
    FreshWindow("window-lifecycle.apfs");const auto disk=Bytes("window-lifecycle.apfs");
    {
        Tx j(L"Strict");Configure(j,"window-lifecycle.wal");auto owner=Open("window-lifecycle.apfs",j,true,kSnapshotPhysicalBase);
        const auto payload=LiveBytes(*owner,L"\\clone0");Create(*owner,j,"bounded");OutsideWindow("window-lifecycle.apfs",disk);
        const auto inventory=List(*owner);Check(inventory.size()==1&&inventory[0].identity.scope.store_offset_bytes==0&&
            inventory[0].identity.scope.store_size_bytes==disk.size()-kSnapshotPhysicalBase-kSnapshotTailBytes,"created snapshot has exact relative window");
        auto wrong=inventory[0].identity;wrong.scope.store_size_bytes+=kBlockSize;SnapshotRuntimePlan rejected;std::string e;
        const auto before=Bytes("window-lifecycle.apfs"),wal=Bytes("window-lifecycle.wal");
        Check(!PrepareSnapshotDelete(*owner,wrong,1,rejected,e)&&Bytes("window-lifecycle.apfs")==before&&Bytes("window-lifecycle.wal")==wal,"wrong Delete window refuses without image/WAL changes");
        wrong=inventory[0].identity;wrong.scope.store_offset_bytes=kSnapshotPhysicalBase;
        Check(!PrepareSnapshotDelete(*owner,wrong,1,rejected,e),"physical Delete offset cannot enter container-relative SNP1");
        Delete(*owner,j,inventory[0].identity);Check(List(*owner).empty()&&LiveBytes(*owner,L"\\clone0")==payload,"bounded Create/Delete preserve live payload");
        const auto marks=j.Watermarks();Check(marks.accepted_sequence>0&&marks.accepted_sequence==marks.apfs_durable_sequence&&
            marks.accepted_sequence==marks.cleanup_sequence&&!j.HasUnappliedAcceptedWork(),"bounded lifecycle cleans original real WAL");
        OutsideWindow("window-lifecycle.apfs",disk);
    }
    Tx j(L"Strict");Configure(j,"window-lifecycle.wal");auto owner=Open("window-lifecycle.apfs",j,true,kSnapshotPhysicalBase);
    Check(List(*owner).empty(),"bounded lifecycle reopens canonical image");OutsideWindow("window-lifecycle.apfs",disk);
    std::cout<<"PASS padded nonzero-base canonical Create/Delete and reopen\n";
}
void SnapshotSourceWindowReplay(){
    for(const bool deletion:{false,true})for(const bool published:{false,true}){
        const auto stem=std::string("window-replay-")+(deletion?"delete-":"create-")+(published?"published":"preimage");
        const auto image=stem+".apfs",wal=stem+".wal";FreshWindow(image);const auto disk=Bytes(image);
        {
            Tx j(L"Strict");Configure(j,wal);auto owner=Open(image,j,true,kSnapshotPhysicalBase);if(deletion)Create(*owner,j,"target");
            const auto source=owner->CheckpointXid();SnapshotRuntimePlan plan;std::string e;
            Check(deletion?PrepareSnapshotDelete(*owner,List(*owner)[0].identity,1,plan,e):PrepareSnapshotCreate(*owner,101,"target",1,0,plan,e),"window replay prepares: "+e);
            auto*store=owner->FindSessionStore(101);const auto nx=store->AuthoritativeAppleCheckpointView()->container.superblock;
            bool hook_reached=false;
            store->SetCommitStageHook([&](std::string_view stage){
                if(stage!=(published?"after-apple-publish":"before-apple-publish"))return true;
                hook_reached=true;return false;
            });
            const auto result=ApplySnapshot(*owner,j,plan);Check(result.commit_recovery_required,"window fault retains recovery ownership");
            Check(hook_reached,"window fault reaches the selected publication boundary");
            SnapshotRuntimeDeviceSource held_source(store->Device(),nx);
            const auto disk_checkpoint=LoadAppleCheckpointView(held_source,0,held_source.SizeBytes(),e);
            Check(disk_checkpoint.has_value(),"read actual held-source checkpoint after injected boundary: "+e);
            Check(disk_checkpoint->container.superblock.xid==source+(published?1:0),"window fault proves preimage versus published checkpoint on disk");
            std::vector<Tx::AcceptedTransaction> debt;Check(j.LoadAcceptedTransactionsSinceCleanup(debt,&e)&&debt.size()==1&&
                debt[0].mutations.size()==1&&debt[0].preimage_checkpoint_xid==source&&j.HasUnappliedAcceptedWork(),"window fault retains isolated original accepted receipt");
            NativeSnapshotIntent accepted;Check(DecodeNativeSnapshotIntent(debt[0].mutations[0].inline_payload,accepted)&&
                accepted.scope.store_offset_bytes==0&&accepted.scope.store_size_bytes==disk.size()-kSnapshotPhysicalBase-kSnapshotTailBytes,"accepted receipt binds NX-relative window");
            OutsideWindow(image,disk);
        }
        for(unsigned restart=0;restart!=2;++restart){
            Tx j(L"Strict");Configure(j,wal);auto owner=Open(image,j,true,kSnapshotPhysicalBase);std::string e;
            const auto replay=ReplaySnapshot(*owner,j,101,e);Check(restart?!replay.has_value():replay.value_or(false),"bounded accepted replay/reopen: "+e);
            Check(List(*owner).size()==(deletion?0u:1u),"bounded replay verifies exact final inventory");
            const auto marks=j.Watermarks();Check(marks.accepted_sequence==marks.apfs_durable_sequence&&marks.accepted_sequence==marks.cleanup_sequence&&
                !j.HasUnappliedAcceptedWork(),"bounded replay discharges only original accepted debt");OutsideWindow(image,disk);
        }
    }
    std::cout<<"PASS padded nonzero-base accepted Create/Delete replay before and after publication\n";
}
void SnapshotSourceWindow(){SnapshotSourceWindowBounds();SnapshotSourceWindowLifecycle();SnapshotSourceWindowReplay();RawImageDisguiseRefusals();}

}
#ifndef SNAPSHOT_RUNTIME_TEST_HELPERS_ONLY
#include "SnapshotSiblingMutationTests.h"
#include "SnapshotAllocationManagementTests.h"
int main(int argc, char** argv){try{
    // Isolate fixed filenames from the shared CTest working directory and from
    // reruns: each invocation runs in a fresh private directory.
    const auto root=std::filesystem::current_path();std::filesystem::path run_dir;
    for(unsigned n=0;n<1024;++n){auto path=root/("snapshot-runtime-run-"+std::to_string(n));
        if(std::filesystem::create_directory(path)){run_dir=std::move(path);break;}}
    Check(!run_dir.empty(),"fresh private snapshot-runtime evidence directory");
    std::filesystem::current_path(run_dir);
    try{if(argc==2 && std::string_view(argv[1])=="--test-preimage-batching")PreimageBatching();
        else if(argc==2 && std::string_view(argv[1])=="--test-source-window")SnapshotSourceWindow();
        else if(argc==2 && std::string_view(argv[1])=="--test-sibling-mutations")SiblingSnapshotMutations();
        else if(argc==2 && (std::string_view(argv[1])=="--test-allocation-management" ||
            std::string_view(argv[1])=="--test-allocation-cycles"))SnapshotAllocationManagementCycles();
        else if(argc==2 && std::string_view(argv[1])=="--test-allocation-management-baseline")SnapshotAllocationManagementCycles(0);
        else if(argc==2 && std::string_view(argv[1])=="--test-allocation-sparse")SnapshotAllocationSparseCycle();
        else if(argc==2 && std::string_view(argv[1])=="--test-allocation-deficit")SnapshotAllocationSourceDeficit();
        else if(argc==2 && std::string_view(argv[1])=="--test-allocation-proof"){SnapshotAllocationReaderFloor();SnapshotAllocationComposerProof();SnapshotAllocationHiddenHistory();SnapshotAllocationSparseCycle();SnapshotAllocationSourceDeficit();SnapshotAllocationAdmissionNegatives();}
        else if(argc==2 && std::string_view(argv[1])=="--test-snapshot-recovery") {Lifecycle();Newest();Faults();Negatives();ReaderLifetime();}
        else if(argc==1){PreimageBatching();SnapshotSourceWindow();Lifecycle();Newest();Faults();Negatives();ReaderLifetime();SiblingSnapshotMutations();SnapshotAllocationManagementCycles();SnapshotAllocationReaderFloor();SnapshotAllocationComposerProof();SnapshotAllocationHiddenHistory();SnapshotAllocationSparseCycle();SnapshotAllocationSourceDeficit();SnapshotAllocationAdmissionNegatives();}
        else throw std::runtime_error("Unknown focused snapshot test option");}
    catch(...){std::filesystem::current_path(root);throw;}
    std::filesystem::current_path(root);
    std::cout<<"SnapshotRuntimeTests: "<<checks<<" checks, 0 failures\n";return 0;}catch(const std::exception&e){std::cerr<<"FAIL after "<<checks<<" checks: "<<e.what()<<"\n";return 1;}}

#endif
