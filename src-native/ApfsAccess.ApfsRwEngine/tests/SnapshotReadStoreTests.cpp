// Reuse the existing synthetic snapshot fixtures and parser regression cases.
#define main snapshot_projection_tests_main
#include "SnapshotProjectionTests.cpp"
#undef main
#include "TransactionManager.h"
#include "AppleTransactionCommit.h"
#include <fstream>
#include <filesystem>

namespace {
using Store = MetadataStore;
void SaveImage(const std::filesystem::path& path, const Bytes& bytes) {
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    file.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    Check(bool(file), "save ordinary local fixture");
}
Store::VolumeContext Context(const std::filesystem::path& path, const ApfsSnapshotIdentity& id) {
    Store::VolumeContext c; c.device_path=std::filesystem::absolute(path).wstring();
    c.device_offset_bytes=id.scope.store_offset_bytes;c.volume_object_id=id.scope.volume_oid;
    c.allow_legacy_scaffold_for_fixtures=false;return c;
}
void Refusals(Store& s) {
    for(unsigned operation=0;operation<=16;++operation) {
        Store::MutationRequest r;r.operation=static_cast<Store::MutationOperation>(operation);
        r.path=L"\\report.txt";r.secondary_path=L"\\new";r.length=4096;
        Store::PayloadIdentity payload{999,999};std::optional<UnlinkOutcome> unlink;
        Check(s.StageMutation(r,&payload,&unlink)==Store::MutationStatus::UnsupportedOperation &&
            !payload.object_id&&!payload.generation&&!unlink,"stage immutable operation "+std::to_string(operation));
        Check(s.ApplyMutation(r)==Store::MutationStatus::UnsupportedOperation,"apply immutable");
        std::uint64_t allocation=99;
        Check(s.PreflightNativeSparseMutation(r,&allocation)==Store::MutationStatus::UnsupportedOperation&&allocation==0,"sparse preflight immutable");
        Check(s.PreflightNativeCapacityMutation(r)==Store::MutationStatus::UnsupportedOperation,"capacity immutable");
    }
    Check(s.PreflightNativeCapacityMutations({})==Store::MutationStatus::UnsupportedOperation,"empty preview refused");
    Check(s.CheckPendingAppleCapacity()==Store::CommitStatus::NotWritable,"capacity check refused");
    Check(s.CommitTransaction()==Store::CommitStatus::NotWritable,"commit refused");
    Check(s.CommitCanonicalTransaction()==Store::CommitStatus::NotWritable,"canonical commit refused");
    Check(s.CommitPendingMutations()==Store::CommitStatus::NotWritable,"empty commit refused");
    Check(!s.PrepareNativeWritePath()&&!s.LoadContainerState()&&!s.LoadVolumeState()&&!s.LoadCanonicalState()&&
        !s.LoadContainerSuperblocks()&&!s.LoadObjectMap()&&!s.LoadSpacemanState(),"all live initialization entries refused");
    Check(!s.ReplayOrRecover()&&!s.ReplayCanonicalCheckpoint(),"recovery entries refused");
    std::string recovery_error;AppleVolumeReplayBoundary boundary;
    Check(!s.ValidateRequiredRecoveryCheckpoints({},recovery_error)&&
        !s.FindAcceptedReplayBoundary(10,boundary,recovery_error),"recovery checkpoint queries have no writable view");
    Check(!s.AllocateExtent(4096)&&!s.FreeExtent(4096,4096)&&!s.FreeExtent(4096,4096,nullptr),"allocator refused");
    Check(!s.WritePreparedFileRange(L"\\report.txt",0,Bytes(8))&&
        !s.SetCommittedReadExtents(30,{{0,221*4096,4096}})&&
        !s.DebugMergeNativeProjectionReadExtents(30,{{0,221*4096,4096}}),"payload and extent mutation refused");
    Store::MutationRequest rewrite;rewrite.path=L"stale";
    Check(!s.PrepareCompressionRewrite(L"\\report.txt",rewrite)&&rewrite.path.empty(),"rewrite refused and output cleared");
    rewrite.path=L"stale";
    Check(!s.PrepareNativeClone(L"\\report.txt",L"\\new",rewrite)&&rewrite.path.empty(),"clone refused and output cleared");
    TransactionManager journal(L"Strict");Store::CloneReceipt receipt;
    Check(s.AcceptNativeClone(journal,L"\\report.txt",L"\\new",receipt)==Store::CloneAcceptance::Refused&&
        journal.CurrentState()==TransactionManager::State::Idle,"clone refuses before journal entry");
    Check(s.ReplayNativeClone({},10)==Store::CloneReplay::Refused,"clone replay refused");
    Check(!s.IsNativeWriteReady()&&!s.IsCommitPathReady()&&!s.IsCanonicalCommitReady()&&
        !s.IsProductionCanonicalPathActive()&&!s.SupportsFileAllocationSize(),"no writable capabilities");
    Check(!s.IsRecoveryRequired()&&s.RecoveryReason().empty()&&s.LastIntegrityFailureReason().empty(),"expected refusal is not corruption");
    Check(s.PendingMutationCount()==0&&s.PendingAllocationCount()==0&&s.PendingObjectMapUpdateCount()==0&&
        s.PendingBtreeRecordCount()==0&&s.DebugWorkingInodeCount()==0&&
        !s.LookupWorkingPayloadIdentityByPath(L"\\report.txt"),"no mutable working state or payload identity");
}
void ReadAdapter(bool offset, bool sparse) {
    Fixture f; f.External(); f.Hardlinks();
    if(sparse) {
        AppleInodeRecord inode;std::string error;
        Check(ApfsExtendedRecordCodec::DecodeInode(Inode(30,8192,2),inode,error),"sparse inode");
        inode.internal_flags|=0x200;AppleExtendedField hole{13,0,Bytes(8)};PutU64LE(hole.data,0,4096);
        inode.extended_fields.push_back(hole);f.fs[2]=Encode(inode,EncodeAppleInodeRecord);
        f.fs.push_back(Encode(AppleFileExtentRecord{30,4096,4096,0,0,4096},EncodeAppleFileExtentRecord));f.Trees();
    }
    if(offset){f.image.insert(f.image.begin(),8192,std::byte{0xEE});f.scope.store_offset_bytes=8192;
        f.image.insert(f.image.end(),4096,std::byte{0xDD});}
    const auto id=f.Identity();const auto path=std::filesystem::absolute("snapshot-"+std::to_string(offset)+std::to_string(sparse)+".apfs");
    SaveImage(path,f.image);Store s(Context(path,id));std::string error;
    { BlockDevice live(path.wstring());Bytes bytes;
      Check(live.Read(id.scope.store_offset_bytes+221*4096,8,bytes)&&
          std::string(reinterpret_cast<char*>(bytes.data()),bytes.size())=="LIVEVIEW","live historical control differs"); }
    const bool prepared = s.PrepareNativeSnapshotReadPath(id,error);
    Check(prepared,"prepare exact snapshot: "+error);
    Check(s.IsImmutableSnapshotView()&&s.NativeSnapshot()&&s.NativeSnapshot()->identity==id,"exact identity query");
    Check(s.CheckpointXid()==10&&s.LastCommittedXid()==10&&s.TotalSizeBytes()==id.scope.store_size_bytes&&
        s.TotalBlocks()==512&&s.BlockSizeBytes()==4096&&!s.FreeSizeBytes(),"historical generation and exact store geometry");
    Check(s.LookupCommittedInodeByPath(L"\\")&&s.CommittedInodeCount()==2&&s.CommittedBtreeRecordCount()==0&&
        s.CommittedObjectCount()==0&&!s.AuthoritativeAppleCheckpointView(),"read graph without writable object/checkpoint state");
    const auto inode=s.LookupCommittedInodeByObjectId(30);
    Check(inode&&inode->xid==10&&inode->link_count==2&&inode->owner==501&&
        s.LookupCommittedInodeByPath(L"\\alias.txt")->object_id==30,"historical inode hardlinks and metadata");
    const auto children=s.SnapshotCommittedDirectoryChildInodes(2);
    Check(children&&children->size()==2&&s.LookupCommittedDirectoryLinkByPath(L"\\alias.txt"),"root children and link query");
    Bytes payload;Check(s.ReadCommittedFileRange(L"\\report.txt",0,8,payload)&&
        std::string(reinterpret_cast<char*>(payload.data()),payload.size())=="snapshot","normal file callback reads historical content");
    Check(s.ReadCommittedFileRange(L"\\alias.txt",0,8,payload)&&payload[0]==std::byte{'s'},"hardlink data");
    Check(s.ReadCommittedFileRange(L"\\report.txt",inode->logical_size,10,payload)&&payload.empty(),"EOF");
    if(sparse) {Check(s.ReadCommittedFileRange(L"\\report.txt",4092,4100,payload)&&payload==Bytes(4100),"sparse data/hole crossing");}
    std::size_t n=99;Bytes attr(32);
    Check(s.ReadCommittedExtendedAttributeRange(30,"com.apple.FinderInfo",0,attr,n)&&n==32&&attr==Bytes(32,std::byte{0x42}),"embedded xattr bytes");
    attr.resize(9);Check(s.ReadCommittedExtendedAttributeRange(30,"com.apple.ResourceFork",0,attr,n)&&n==9&&
        std::string(reinterpret_cast<char*>(attr.data()),n)=="fork-past","external xattr bytes");
    Check(s.LookupWorkingExtendedAttribute(30,"com.apple.FinderInfo")&&s.SnapshotWorkingExtendedAttributes(30).size()==2&&
        s.LookupWorkingInodeByPath(L"\\report.txt"),"generic working queries route immutable data");
    Check(!s.Device().IsWritable()&&!s.Device().HasWriteHandle()&&s.Device().RevalidateStableReadOnlyImage(),"read-only stable handle");
    { auto lease=BlockDevice::OpenStableReadOnlyImage(path.wstring(),error);
      Check(lease&&!lease->Write(0,Bytes{})&&!lease->Write(0,Bytes(1))&&
          !lease->WriteBatch({})&&!lease->Flush()&&!lease->HasWriteHandle(),"explicit stable device refuses all writes including empty operations"); }
    const auto writer=CreateFileW(path.c_str(),GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,0,nullptr);
    Check(writer==INVALID_HANDLE_VALUE,"OS lease excludes writer");
    Check(!DeleteFileW(path.c_str())&&!MoveFileExW(path.c_str(),(path.wstring()+L".replaced").c_str(),0),"OS lease excludes delete and replacement");
    Refusals(s);Check(s.VerifyIntegrity()&&s.ReadCommittedFileRange(L"\\report.txt",0,8,payload)&&payload[0]==std::byte{'s'},"refusals preserve readable snapshot");
    const auto key=ApfsNameCodec::CanonicalWindowsPathKey(L"\\report.txt",
        ApfsNamePolicy::FromIncompatibleFeatures(s.Context().incompatible_features));
    Check(key.ok(),"snapshot canonical path key");
    const auto plan=s.SnapshotCommittedFileReadPlan(*key.value);Check(bool(plan),"capture exact read plan");
    Check(!s.PrepareNativeSnapshotReadPath(s.NativeSnapshot()->identity,error),"alias-safe reinitialization refused");
    Check(s.NativeSnapshot()&&s.NativeSnapshot()->identity==id&&s.IsContainerLoaded()&&s.CheckpointXid()==10&&
        s.LookupCommittedInodeByPath(L"\\")&&!s.SnapshotWorkingExtendedAttributes(30).empty(),"failed reinit preserves installed view");
    payload=Bytes(8);n=99;Check(s.ReadCommittedFileRangeFromPlan(*plan,L"\\report.txt",0,8,payload.data(),8,n)&&n==8&&
        std::string(reinterpret_cast<char*>(payload.data()),payload.size())=="snapshot","captured plan remains valid after refused reinit");
    Check(s.ReadCommittedFileRange(L"\\report.txt",0,8,payload)&&payload.size()==8,"installed read view stays usable");
    Refusals(s);Pass("read adapter offset="+std::to_string(offset)+" sparse="+std::to_string(sparse));
}
void IdentityAndLeaseFailures() {
    Fixture f;auto id=f.Identity();auto path=std::filesystem::absolute("identity.apfs");SaveImage(path,f.image);
    for(unsigned field=0;field<6;++field) {
        auto wrong=id;if(field==0)++wrong.snapshot_xid;if(field==1)wrong.name_utf8="wrong";
        if(field==2)++wrong.root_oid;if(field==3)++wrong.scope.volume_oid;
        if(field==4)--wrong.scope.store_size_bytes;if(field==5)++wrong.scope.checkpoint_xid;
        Store s(Context(path,id));std::string error;
        Check(!s.PrepareNativeSnapshotReadPath(wrong,error)&&!error.empty()&&!s.NativeSnapshot()&&
            s.SnapshotCommittedInodes().empty()&&!s.IsRecoveryRequired(),"wrong identity no fallback");Refusals(s);
    }
    {Store s(Context(path,id));const auto h=CreateFileW(path.c_str(),GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,0,nullptr);
     Check(h!=INVALID_HANDLE_VALUE,"existing writer control");std::string error;const auto opened=s.PrepareNativeSnapshotReadPath(id,error);CloseHandle(h);
     Check(!opened&&!s.NativeSnapshot(),"existing writer blocks lease");}
    {Store s(Context(path,id));std::string error;Check(s.LoadContainerState(),"prior live state control");
     const auto xid=s.CheckpointXid();
     Check(!s.PrepareNativeSnapshotReadPath(id,error)&&s.IsContainerLoaded()&&s.CheckpointXid()==xid&&
         !s.IsImmutableSnapshotView(),"prior live initialization refused without changing existing state");}
    {BuilderStore spec;auto live=BuildAuthoritativeStoreImage(spec);auto live_path=std::filesystem::absolute("live-transition.apfs");
     SaveImage(live_path,live);Store s(Context(live_path,id));std::string error;
     Check(s.PrepareNativeWritePath(),"live writer before rejected snapshot initialization");
     Store::MutationRequest create;create.operation=Store::MutationOperation::CreateFile;create.path=L"\\pending";
     Check(s.StageMutation(create)==Store::MutationStatus::Applied&&s.PendingMutationCount()==1,"stale working data control");
     Check(!s.PrepareNativeSnapshotReadPath(id,error)&&s.IsNativeWriteReady()&&s.LookupWorkingInodeByPath(L"\\pending")&&
         s.AuthoritativeAppleCheckpointView()&&s.PendingMutationCount()==1&&!s.IsImmutableSnapshotView(),
         "snapshot initialization cannot discard pending writer state");
     Check(s.CommitCanonicalTransaction()==Store::CommitStatus::Committed&&s.LookupCommittedInodeByPath(L"\\pending"),
         "pending writer can still publish after refused snapshot initialization");}
    std::string error;Check(!BlockDevice::OpenStableReadOnlyImage(L"\\\\.\\PhysicalDrive0",error),"raw spelling rejected before open");
    Check(!BlockDevice::OpenStableReadOnlyImage(L"relative.apfs",error),"relative spelling refused");
    Pass("wrong identity and lease admission");
}
}
int main(){try{ReadAdapter(false,false);ReadAdapter(true,false);ReadAdapter(true,true);IdentityAndLeaseFailures();
    std::cout<<"RESULT PASS cases="<<cases<<" checks="<<checks<<"\n";return 0;}
catch(const std::exception& e){std::cerr<<"FAIL checks="<<checks<<": "<<e.what()<<"\n";return 1;}}
