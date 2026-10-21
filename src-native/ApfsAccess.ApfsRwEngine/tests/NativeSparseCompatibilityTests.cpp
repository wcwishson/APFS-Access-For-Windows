#include "MetadataStore.h"
#include "NativeSparseV2.h"
#include "TransactionManager.h"
#include "ApfsExtendedRecordCodec.h"
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>

using namespace apfsaccess::rw;
using namespace apfsaccess::catalog;
#ifndef SPARSE_COMPAT_BODY_VERSION
#define SPARSE_COMPAT_BODY_VERSION 3
#endif
#if SPARSE_COMPAT_BODY_VERSION == 3
#include "../src/AppleCloneRangeMapping.h"
#endif
namespace {
using Bytes=std::vector<std::byte>;
using Record=apfsaccess::catalog::BtreeRecord;
using Store=MetadataStore;
unsigned checks=0;
void Check(bool value,const std::string& text){++checks;if(!value)throw std::runtime_error(text);}
class Source final:public RandomAccessSource {
public:explicit Source(const BlockDevice& device):device_(device){}
    std::uint64_t SizeBytes()const override{return device_.GetGeometry().total_bytes;}
    bool Read(std::uint64_t at,std::size_t n,Bytes& bytes)const override{
        bytes.clear();if(at>SizeBytes()||n>SizeBytes()-at||n>(1u<<20))return false;if(!n)return true;
        const auto first=at/4096*4096,last=(at+n+4095)/4096*4096;Bytes whole;
        if(last>SizeBytes()||!device_.ReadForVerification(first,static_cast<std::size_t>(last-first),whole)||whole.size()!=last-first)return false;
        bytes.assign(whole.begin()+at-first,whole.begin()+at-first+n);return true;}
private:const BlockDevice& device_;
};
AppleCheckpointView Load(const Source& source){std::string error;auto cp=LoadAppleCheckpointView(source,0,source.SizeBytes(),error);Check(cp.has_value(),"canonical checkpoint: "+error);return std::move(*cp);}
std::uint64_t Header(const Record& record){return ReadU64LE(record.key,0).value_or(0);}
void Put(Bytes& bytes,std::size_t at,std::uint64_t n){for(unsigned i=0;i<8;++i)bytes.at(at+i)=std::byte(n>>(i*8));}
std::wstring Wide(const std::string& text){const auto n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,text.data(),static_cast<int>(text.size()),nullptr,0);Check(n>0,"strict fixture name");std::wstring out(n,0);
    Check(MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,text.data(),static_cast<int>(text.size()),out.data(),n)==n,"fixture name conversion");return out;}
Bytes Pattern(std::uint64_t id){Bytes bytes(32768);for(std::size_t i=0;i<bytes.size();++i)bytes[i]=std::byte((i*19+41+id)&255);return bytes;}
constexpr std::array<std::uint64_t,4> Files{17,18,19,25};
void PrepareFixture(const std::filesystem::path& image,bool root_view=false){std::string error;auto device=BlockDevice::OpenExclusiveManagementImage(image.wstring(),0,error);Check(!!device,error);Source source(*device);const auto cp=Load(source);
    const auto selected=[&](std::uint64_t id){return root_view?id==17:std::find(Files.begin(),Files.end(),id)!=Files.end();};
    AppleVolumeTransactionRequest request;request.volume_object_id=cp.volumes.front().superblock.object_id;request.required_checkpoint_xids={cp.container.superblock.xid};request.last_modification_time=123456789;
    Check(ReadAppleVolumeFileSystemRecords(source,cp.container,cp.volumes.front(),request.filesystem_records,error),error);
    unsigned inodes=0;for(auto& record:request.filesystem_records){const auto id=Header(record)&0x0fffffffffffffffULL;if(Header(record)>>60!=3||!selected(id))continue;
        AppleInodeRecord inode;Check(ApfsExtendedRecordCodec::DecodeInode(record,inode,error),error);inode.uncompressed_size=32768;bool found=false;
        for(auto& field:inode.extended_fields)if(field.type==8){Check(!found&&field.data.size()==40,"one genuine stream field");found=true;Put(field.data,0,32768);Put(field.data,8,32768);}
        Check(found,"genuine ordinary file stream");Check(EncodeAppleInodeRecord(inode,record,error),error);++inodes;}
    Check(inodes==(root_view?1:Files.size()),"selected existing ordinary inodes");
    std::erase_if(request.filesystem_records,[&](const auto& record){const auto id=Header(record)&0x0fffffffffffffffULL;
        if(Header(record)>>60!=8||!selected(id))return false;AppleFileExtentRecord extent;
        Check(DecodeAppleFileExtentRecord(record,4096,extent,error),error);if(extent.physical_block)request.released_data_blocks.push_back({extent.physical_block,extent.length_bytes/4096});return true;});
    for(const auto id:Files)if(selected(id))request.data_writes.push_back({id,0,0,Pattern(id)});
    AppleVolumeTransactionPlan plan;Check(PlanAppleVolumeTransaction(source,cp,request,plan,error),"genuine patterned fixture plan: "+error);
    Check(ExecuteAppleCheckpointPublication(*device,plan.commit.publication,error),"genuine patterned fixture publication: "+error);
}
struct Owner {
    Store::VolumeContext context;std::shared_ptr<BlockDevice> device;std::unique_ptr<Store> store;std::unique_ptr<TransactionManager> journal;
    explicit Owner(const std::filesystem::path& root){context.device_path=std::filesystem::absolute(root/"sparse.apfs").wstring();context.allow_legacy_scaffold_for_fixtures=false;std::string error;
        device=BlockDevice::OpenExclusiveManagementImage(context.device_path,0,error);Check(!!device,error);Source source(*device);const auto cp=Load(source);context.volume_object_id=cp.volumes.front().superblock.object_id;
        store=std::make_unique<Store>(context,device);const auto ready=store->PrepareNativeWritePath();const auto why=store->RecoveryReason();
        std::string reason;for(const auto c:why)reason.push_back(c<=127?static_cast<char>(c):'?');
        Check(ready,"canonical fresh sparse owner: "+reason);journal=std::make_unique<TransactionManager>(L"Strict");
        const auto hex=cp.container.superblock.uuid_hex;const auto identity=L"apfs-vol:"+std::wstring(hex.begin(),hex.end())+L":"+std::to_wstring(context.volume_object_id);
        const auto wal=std::filesystem::absolute(root/"original.wal");Check(journal->OpenStartupJournal(wal.wstring(),identity,error),error);
        if(!std::filesystem::exists(wal))Check(journal->MaterializeAbsentStartupJournal(error),error);Check(journal->EnrollCanonicalJournalIdentity(identity),"canonical original identity");}
    NativeSparseOpenEntry Entry(std::uint64_t id){Source source(*device);const auto cp=Load(source);std::vector<Record> records;std::string error;
        Check(ReadAppleVolumeFileSystemRecords(source,cp.container,cp.volumes.front(),records,error),error);NativeSparseOpenEntry out;unsigned found=0;
        for(const auto& record:records)if(Header(record)>>60==9){AppleDirectoryRecord entry;
            Check(ApfsExtendedRecordCodec::DecodeDirectory(record,ApfsNamePolicy::FromIncompatibleFeatures(cp.volumes.front().superblock.incompatible_features),entry,error),error);
            if(entry.file_id!=id||found)continue;const auto parent=store->LookupCommittedInodeByObjectId(entry.parent_id);Check(!!parent&&parent->is_directory,"genuine parent identity");
            const auto path=parent->full_path==L"\\"?L"\\"+Wide(entry.name_utf8):parent->full_path+L"\\"+Wide(entry.name_utf8);
            const auto inode=store->LookupCommittedInodeByPath(path);Check(!!inode&&inode->object_id==id,"genuine exact file open");
            std::uint64_t sibling=0;for(const auto& field:entry.extended_fields)if(field.type==1){Check(!sibling&&field.data.size()==8,"exact directory sibling field");sibling=ReadU64LE(field.data,0).value_or(0);Check(sibling!=0,"nonzero directory sibling");}
            out={id,inode->xid,entry.parent_id,sibling,entry.name_utf8};++found;}
        Check(found==1,"one exact genuine open entry");return out;}
};
NativeSparseRequest Set(){return {NativeSparseAction::SetSparse,true,0,0,123456790};}
NativeSparseRequest Zero(std::uint64_t at,std::uint64_t n){return {NativeSparseAction::ZeroRange,false,at,n,123456791};}
void Accept(Owner& owner,std::uint64_t id,const NativeSparseRequest& request){std::string error;Store::SparseReceipt receipt;
#if SPARSE_COMPAT_BODY_VERSION == 1
    Check(owner.store->WithNativeSparseSession(owner.Entry(id),[&](const auto& session,std::string& detail){return owner.store->AcceptNativeSparse(*owner.journal,session,request,receipt,detail)==Store::SparseAcceptance::Accepted;},error),"exact legacy sparse acceptance: "+error);
    std::vector<TransactionManager::AcceptedTransaction> debt;Check(owner.journal->LoadAcceptedTransactionsSinceCleanup(debt,&error)&&debt.size()==1,"one exact accepted original");NativeSparseProof proof;
    Check(DecodeNativeSparse(debt.front().mutations.front().inline_payload,proof)&&
#else
    Check(owner.store->WithNativeSparseSession(owner.Entry(id),[&](const auto& session,std::string& detail){return owner.store->AcceptNativeSparseV2(*owner.journal,session,request,receipt,detail)==Store::SparseAcceptance::Accepted;},error),"exact sparse body3 acceptance: "+error);
    std::vector<TransactionManager::AcceptedTransaction> debt;Check(owner.journal->LoadAcceptedTransactionsSinceCleanup(debt,&error)&&debt.size()==1,"one exact accepted original");NativeSparseV2Proof proof;
    Check(DecodeNativeSparseV2(debt.front().mutations.front().inline_payload,proof)&&
#endif
        ReadU64LE(debt.front().mutations.front().inline_payload,8)==SPARSE_COMPAT_BODY_VERSION,"sparse publication has exact versioned original");}
void Operation(Owner& owner,std::uint64_t id,const NativeSparseRequest& request){Accept(owner,id,request);std::string error;
    Check(owner.store->PublishOrRecoverNativeSparse(*owner.journal,error)==Store::SparsePublication::Published,"genuine sparse publication: "+error);}
void Coverage(Owner& owner,std::uint64_t id){Source source(*owner.device);const auto cp=Load(source);NativeSparseState state;std::string error;
    Check(ReadNativeSparseStateV2(source,cp,owner.context.volume_object_id,id,state,error)&&state.sparse&&state.size==32768,"final sparse canonical state: "+error);
    std::uint64_t end=0;unsigned holes=0;for(const auto& extent:state.extents){Check(extent.logical_address==end,"explicit contiguous sparse logical coverage");end+=extent.length_bytes;if(!extent.physical_block)++holes;}
    Check(end==32768&&holes==1,"one explicit hole covering complete logical EOF");std::cout<<"SPARSE_EXTENTS inode="<<id;
    for(const auto& extent:state.extents)std::cout<<" [logical="<<extent.logical_address<<" bytes="<<extent.length_bytes<<" physical="<<extent.physical_block<<']';std::cout<<'\n';}
void Inspect(const std::filesystem::path& path,std::uint64_t id){std::string error;auto device=BlockDevice::OpenStableReadOnlyImage(path.wstring(),error);Check(!!device,error);Source source(*device);const auto cp=Load(source);std::vector<Record> records;
    Check(ReadAppleVolumeFileSystemRecords(source,cp.container,cp.volumes.front(),records,error),error);std::cout<<"INSPECT xid="<<cp.container.superblock.xid<<" inode="<<id<<'\n';
    for(const auto& record:records)if(Header(record)==((8ull<<60)|id)){AppleFileExtentRecord extent;Check(DecodeAppleFileExtentRecord(record,4096,extent,error),error);
        std::cout<<"EXTENT logical="<<extent.logical_address<<" bytes="<<extent.length_bytes<<" physical="<<extent.physical_block<<'\n';}
    Check(!device->HasWriteHandle()&&device->RevalidateStableReadOnlyImage(),"inspection held read-only exact identity");}
void Init(const std::filesystem::path& root,const std::filesystem::path& original){Check(!std::filesystem::exists(root),"fresh private interop root");std::filesystem::create_directories(root);
    Check(std::filesystem::copy_file(original,root/"sparse.apfs"),"private genuine fixture copy");PrepareFixture(root/"sparse.apfs");Owner owner(root);
    for(const auto id:Files)Operation(owner,id,Set());Accept(owner,17,Zero(4096,8192));owner.store->SetCommitStageHook([](auto stage){return stage!="before-apple-checkpoint-switch";});std::string error;
    Check(owner.store->PublishOrRecoverNativeSparse(*owner.journal,error)==Store::SparsePublication::RecoveryRequired,"genuine sparse cut requires fresh owner: "+error);}
void Recover(const std::filesystem::path& root){Owner owner(root);std::string error;std::vector<TransactionManager::AcceptedTransaction> debt;
    Check(owner.journal->LoadAcceptedTransactionsSinceCleanup(debt,&error)&&debt.size()==1,"fresh exact compatibility original");
    const auto version=ReadU64LE(debt.front().mutations.front().inline_payload,8).value_or(0);
    Check(owner.store->PublishOrRecoverNativeSparse(*owner.journal,error)==Store::SparsePublication::Published,"fresh genuine sparse original recovery: "+error);
    if(version<3)Operation(owner,17,Set());
    Operation(owner,18,Zero(0,4096));Operation(owner,19,Zero(24576,8192));Operation(owner,25,Zero(0,32768));for(const auto id:Files)Coverage(owner,id);
    Check(owner.journal->Watermarks().accepted_sequence==owner.journal->Watermarks().cleanup_sequence,"clean only after exact sparse publication");}
#if SPARSE_COMPAT_BODY_VERSION == 3
AppleVolumeTransactionRequest HoleRequest(Owner& owner,std::uint64_t id,std::uint64_t at,std::uint64_t length){Source source(*owner.device);const auto cp=Load(source);NativeSparseState state;std::string error;
    Check(ReadNativeSparseStateV2(source,cp,owner.context.volume_object_id,id,state,error)&&state.sparse,"complete sparse control source");
    AppleVolumeTransactionRequest request;request.volume_object_id=owner.context.volume_object_id;request.required_checkpoint_xids={cp.container.superblock.xid};request.filesystem_records=state.filesystem;
    std::vector<Record> extents;std::uint64_t removed=0;const auto emit=[&](AppleFileExtentRecord extent,std::uint64_t lo,std::uint64_t hi){if(lo>=hi)return;
        if(extent.physical_block)extent.physical_block+=(lo-extent.logical_address)/4096;extent.logical_address=lo;extent.length_bytes=hi-lo;Record record;
        Check(EncodeAppleFileExtentRecord(extent,record,error),error);extents.push_back(std::move(record));};
    for(const auto& extent:state.extents){const auto end=extent.logical_address+extent.length_bytes,lo=(std::max)(at,extent.logical_address),hi=(std::min)(at+length,end);
        if(lo>=hi){emit(extent,extent.logical_address,end);continue;}emit(extent,extent.logical_address,lo);emit(extent,hi,end);
        if(extent.physical_block){request.released_data_blocks.push_back({extent.physical_block+(lo-extent.logical_address)/4096,(hi-lo)/4096});removed+=hi-lo;}}
    Record hole;Check(EncodeAppleFileExtentRecord({id,at,length,0,0,4096},hole,error),error);extents.push_back(std::move(hole));
    std::erase_if(request.filesystem_records,[&](const auto& record){return Header(record)==((8ull<<60)|id);});request.filesystem_records.insert(request.filesystem_records.end(),extents.begin(),extents.end());
    for(auto& record:request.filesystem_records)if(Header(record)==((3ull<<60)|id)){AppleInodeRecord inode;Check(ApfsExtendedRecordCodec::DecodeInode(record,inode,error),error);
        for(auto& field:inode.extended_fields){if(field.type==8)Put(field.data,8,state.allocated-removed);
            if(field.type==kAppleInodeSparseBytesField)Put(field.data,0,(state.size+4095)/4096*4096-(state.allocated-removed));}
        Check(EncodeAppleInodeRecord(inode,record,error),error);}
    return request;
}
void HoleScopeControls(Owner& owner){Source source(*owner.device);const auto cp=Load(source);auto request=HoleRequest(owner,17,4096,4096);AppleVolumeTransactionPlan plan;std::string error;
    Check(PlanAppleVolumeTransaction(source,cp,request,plan,error),"explicit sparse hole removes exact old owner: "+error);
    auto dense=request;for(auto& record:dense.filesystem_records)if(Header(record)==((3ull<<60)|17)){AppleInodeRecord inode;Check(ApfsExtendedRecordCodec::DecodeInode(record,inode,error),error);
        inode.internal_flags&=~kAppleInodeSparseFlag;std::erase_if(inode.extended_fields,[](const auto& field){return field.type==kAppleInodeSparseBytesField;});Check(EncodeAppleInodeRecord(inode,record,error),error);}
    error.clear();Check(!PlanAppleVolumeTransaction(source,cp,dense,plan,error)&&error=="AppleVolumeSparseHoleScopeInvalid","dense inode cannot acquire a hole by raw extent edit");
    auto outside=request;for(auto& record:outside.filesystem_records)if(Header(record)==((8ull<<60)|17)&&ReadU64LE(record.key,8)==4096){AppleFileExtentRecord extent;
        Check(DecodeAppleFileExtentRecord(record,4096,extent,error),error);extent.logical_address=32768;Check(EncodeAppleFileExtentRecord(extent,record,error),error);}
    error.clear();Check(!PlanAppleVolumeTransaction(source,cp,outside,plan,error)&&error=="AppleVolumeSparseHoleScopeInvalid","new hole cannot cross aligned logical EOF");
    auto release=request;release.released_data_blocks.clear();error.clear();Check(!PlanAppleVolumeTransaction(source,cp,release,plan,error)&&error=="AppleVolumeReleaseSetMismatch","hole emission cannot omit old physical release evidence");
    auto wrong_source=HoleRequest(owner,24685,0,4096);error.clear();
    Check(!PlanAppleCloneRangeTransaction(source,cp,wrong_source,{17,24685,16384,0,4096},plan,error)&&error=="AppleVolumeCloneRangeSourceMismatch","clone hole cannot replace allocated original source bytes");
    Check(Load(source).container.superblock_bytes==cp.container.superblock_bytes,"all hole control plans preserve canonical source");
}
#endif
Bytes AliasBytes(Owner& owner){const auto inode=owner.store->LookupCommittedInodeByObjectId(24685);Check(!!inode&&inode->logical_size==32768,"exact prior production alias inode");Bytes bytes;
    Check(owner.store->ReadCommittedFileRange(inode->full_path,0,32768,bytes)&&bytes.size()==32768,"actual prior production alias bytes");return bytes;}
void InitRoot(const std::filesystem::path& root,const std::filesystem::path& original){Check(!std::filesystem::exists(root),"fresh private conforming root");std::filesystem::create_directories(root);
    Check(std::filesystem::copy_file(original,root/"sparse.apfs"),"private conforming source copy");PrepareFixture(root/"sparse.apfs",true);Owner owner(root);
    const auto original_alias=AliasBytes(owner);Operation(owner,17,Set());Operation(owner,24685,Set());Check(AliasBytes(owner)==original_alias,"hole serialization preserves exact existing aliases");
#if SPARSE_COMPAT_BODY_VERSION == 3
    HoleScopeControls(owner);
#endif
    Accept(owner,17,Zero(4096,8192));owner.store->SetCommitStageHook([](auto stage){return stage!="before-apple-checkpoint-switch";});std::string error;
    Check(owner.store->PublishOrRecoverNativeSparse(*owner.journal,error)==Store::SparsePublication::RecoveryRequired,"conforming sparse cut requires fresh owner: "+error);}
void RecoverRoot(const std::filesystem::path& root){Owner owner(root);std::string error;std::vector<TransactionManager::AcceptedTransaction> debt;
    Check(owner.journal->LoadAcceptedTransactionsSinceCleanup(debt,&error)&&debt.size()==1,"exact prior-version or new explicit original");
    const auto version=ReadU64LE(debt.front().mutations.front().inline_payload,8).value_or(0);const auto original_alias=AliasBytes(owner);
    Check(owner.store->PublishOrRecoverNativeSparse(*owner.journal,error)==Store::SparsePublication::Published,"fresh exact versioned sparse recovery: "+error);
    if(version<3)Operation(owner,17,Set());Operation(owner,24685,Set());
    Coverage(owner,17);Coverage(owner,24685);Check(AliasBytes(owner)==original_alias,"fresh recovery and explicit holes preserve prior alias payload");
    Check(owner.journal->Watermarks().accepted_sequence==owner.journal->Watermarks().cleanup_sequence,"exact sparse original completed");}
}
int wmain(int argc,wchar_t** argv){try{Check(argc==3||argc==4,"interop mode and private image/root");const std::wstring_view mode=argv[1];const std::filesystem::path path=argv[2];Check(path.is_absolute()&&path.wstring().substr(0,3)==L"D:\\","D private artifact");
    if(mode==L"--inspect"){Check(argc==4,"inspect object id");Inspect(path,std::stoull(argv[3]));}
    else if(mode==L"--init"){Check(argc==4,"immutable genuine fixture required");Init(path,argv[3]);}
    else if(mode==L"--init-root"){Check(argc==4,"immutable conforming source required");InitRoot(path,argv[3]);}
    else if(mode==L"--recover-root"){Check(argc==3,"conforming recovery arguments");RecoverRoot(path);}
    else {Check(mode==L"--recover"&&argc==3,"known interop mode");Recover(path);}
    std::cout<<"PASS sparse compatibility checks="<<checks<<'\n';return 0;
}catch(const std::exception& error){std::cerr<<"FAIL checks="<<checks<<' '<<error.what()<<'\n';return 1;}}
