#define APPLE_CLONE_TEST_HELPERS_ONLY
#include "AppleCloneCowTests.cpp"
#include "MetadataStore.h"
#include <filesystem>
namespace {
void SaveImage(const std::filesystem::path& path,const std::vector<std::byte>& image){std::ofstream f(path,std::ios::binary);f.write(reinterpret_cast<const char*>(image.data()),image.size());Check(!!f,"save regular fixture image");}
std::vector<std::byte> DiskBytes(const std::filesystem::path& path){std::ifstream f(path,std::ios::binary);std::vector<char> c((std::istreambuf_iterator<char>(f)),{});std::vector<std::byte> b(c.size());std::transform(c.begin(),c.end(),b.begin(),[](char c){return std::byte(static_cast<unsigned char>(c));});return b;}
void StoreCase(bool faults){
    auto path=std::filesystem::current_path()/(faults?"store-clone-fault.apfs":"store-clone.apfs");Fixture fixture(CloneSpec(3));SaveImage(path,fixture.image);auto old=Payload(fixture,17);auto expected=old;
    MetadataStore::VolumeContext context;context.device_path=path.wstring();context.volume_object_id=101;context.allow_legacy_scaffold_for_fixtures=false;
    MetadataStore store(context);const bool ready=store.PrepareNativeWritePath();if(!ready)std::wcerr<<L"gate "<<store.LastCanonicalGateFailure()<<L" replay "<<store.RecoveryReason()<<L"\n";Check(ready,"clone store prepares");
    const auto initial_xid=store.CheckpointXid().value();
    auto check_read=[&](MetadataStore& reader,std::wstring name,const std::vector<std::byte>& bytes){std::vector<std::byte> actual;Check(reader.ReadCommittedFileRange(name,0,bytes.size(),actual)&&actual==bytes,"fresh store clone payload");};
    for(auto name:{L"\\clone0",L"\\clone1",L"\\clone2"})check_read(store,name,old);
    MetadataStore::MutationRequest write;write.path=L"\\clone1";write.offset=kBlockSize+71;write.length=29;
    MetadataStore::PayloadIdentity identity;Check(store.StageMutation(write,&identity)==MetadataStore::MutationStatus::Applied,"clone write accepted with identity");
    std::fill_n(expected.begin()+write.offset,write.length,std::byte{0x79});bool deny=faults;std::uint64_t acquired=0;unsigned legacy=0;
    store.SetFilePayloadProvider([&](const auto&,auto)->std::optional<std::vector<std::byte>>{++legacy;return expected;});
    store.SetFilePayloadRangeProvider([&](const auto& name,auto owner,auto offset,std::span<std::byte> bytes){
        Check(name==L"\\clone1"&&owner.object_id==identity.object_id&&owner.generation==identity.generation,"source byte provider binds clone inode and generation");
        Check(offset<=expected.size()&&bytes.size()<=expected.size()-offset,"bounded payload acquisition");acquired+=bytes.size();
        if(deny)return false;std::copy_n(expected.begin()+offset,bytes.size(),bytes.begin());return true;});
    if(faults){const auto before=DiskBytes(path);Check(store.CommitPendingMutations({initial_xid})!=MetadataStore::CommitStatus::Committed,"refused identity-bound provider fails");Check(legacy==0&&DiskBytes(path)==before,"provider refusal cannot fall back or publish");deny=false;
        store.SetCommitStageHook([](std::string_view stage){return stage!="before-apple-publish";});
        Check(store.CommitPendingMutations({initial_xid})==MetadataStore::CommitStatus::PersistFailed,"publication interruption fails");Check(DiskBytes(path)==before,"before-publication failure preserves image");store.SetCommitStageHook({});}
    acquired=0;const auto status=store.CommitPendingMutations({initial_xid});
    if(status!=MetadataStore::CommitStatus::Committed)std::wcerr<<L"store failure "<<store.LastCommitFailureReason()<<L" "<<store.LastCommitFailureDetail()<<L"\n";
    Check(status==MetadataStore::CommitStatus::Committed,"store clone COW commits");Check(acquired==kBlockSize&&legacy==0,"first write acquires only one shared physical block");
    {MetadataStore fresh(context);Check(fresh.PrepareNativeWritePath(),"fresh COW image opens");check_read(fresh,L"\\clone0",old);check_read(fresh,L"\\clone1",expected);check_read(fresh,L"\\clone2",old);
        auto inode=fresh.LookupCommittedInodeByPath(L"\\clone1");Check(inode&&inode->owner==501&&inode->group==20&&inode->mode==0100640,"Mac permissions preserved");
        auto attribute=fresh.LookupCommittedExtendedAttribute(18,"user.keep");Check(attribute&&attribute->data==HexToBytes("cafebabe012345"),"unrelated xattr bytes survive clone COW");}
    fixture.image=DiskBytes(path);fixture.Reload();CheckGraph(fixture);Check(Payload(fixture,18,initial_xid)==old,"store COW retains old checkpoint mapping");
    // Truncate uses the existing complete payload provider and private identity.
    expected.resize(511);MetadataStore::MutationRequest truncate;truncate.operation=MetadataStore::MutationOperation::SetFileSize;truncate.path=L"\\clone1";truncate.length=expected.size();
    Check(store.StageMutation(truncate,&identity)==MetadataStore::MutationStatus::Applied,"clone truncate stages");
    Check(store.CommitPendingMutations({initial_xid})==MetadataStore::CommitStatus::Committed,"clone truncate commits");
    {MetadataStore fresh(context);Check(fresh.PrepareNativeWritePath(),"fresh truncated image opens");check_read(fresh,L"\\clone1",expected);check_read(fresh,L"\\clone0",old);check_read(fresh,L"\\clone2",old);}
    for(auto name:{L"\\clone0",L"\\clone2"}){MetadataStore::MutationRequest remove;remove.operation=MetadataStore::MutationOperation::Delete;remove.path=name;Check(store.StageMutation(remove)==MetadataStore::MutationStatus::Applied,"overlapping clone unlink stages");}
    Check(store.CommitPendingMutations({initial_xid})==MetadataStore::CommitStatus::Committed,"multiple clone unlink commits");
    {MetadataStore fresh(context);Check(fresh.PrepareNativeWritePath(),"fresh multiple unlink opens");check_read(fresh,L"\\clone1",expected);Check(!fresh.LookupCommittedInodeByPath(L"\\clone0")&&!fresh.LookupCommittedInodeByPath(L"\\clone2"),"deleted clone names stay absent");}
    fixture.image=DiskBytes(path);fixture.Reload();CheckGraph(fixture);Check(Payload(fixture,17,initial_xid)==old,"store retained old clone payload after truncate/unlink");
}
}
int main(){try{StoreCase(false);StoreCase(true);std::cout<<"PASS MetadataStore clone COW "<<checks<<" checks\n";return 0;}catch(const std::exception& e){std::cerr<<"FAIL "<<e.what()<<"\n";return 1;}}
