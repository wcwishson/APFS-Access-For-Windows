#define wmain PrimitiveKeybagMain
#include "ApfsSoftwareKeybagMaintenanceTests.cpp"
#undef wmain
#include "ApfsSoftwareKeybagPublication.h"
#include <fstream>

namespace
{
constexpr wchar_t canonical_root[]=L"D:\\ApfsAccessScratch\\WindowsClosure\\software-keybag-canonical-20261016";
struct PublicationTarget final : apfsaccess::rw::AppleCheckpointWriteTarget
{
    Handle file;
    std::uint64_t base,size,switch_block;
    std::wstring mode;
    std::size_t writes=0,flushes=0,lease_retries=0;
    PublicationTarget(const std::filesystem::path& path,const Profile& p,const std::string& identity,
        std::uint64_t selected_switch,std::wstring selected_mode)
        :base(p.Base()),size(p.Size()),switch_block(selected_switch),mode(std::move(selected_mode))
    {
        Check(path.wstring().starts_with(std::wstring(canonical_root)+L"\\run-"),"CanonicalPrivatePath");
        DWORD failure=0;
        for(unsigned attempt=0;attempt<40;++attempt) {
            file.h=CreateFileW(path.c_str(),GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_RANDOM_ACCESS,nullptr);
            if(file.h!=INVALID_HANDLE_VALUE) break;
            failure=GetLastError();
            if(failure!=ERROR_SHARING_VIOLATION && failure!=ERROR_LOCK_VIOLATION) break;
            ++lease_retries;Sleep(50);
        }
        if(file.h==INVALID_HANDLE_VALUE) throw std::runtime_error("CanonicalExclusiveFile:"+std::to_string(failure));
        BY_HANDLE_FILE_INFORMATION id{};
        Check(GetFileType(file.h)==FILE_TYPE_DISK && GetFileInformationByHandle(file.h,&id) &&
            !(id.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT|FILE_ATTRIBUTE_DEVICE)),"CanonicalRegularFile");
        const auto actual="windows-file:"+std::to_string(id.dwVolumeSerialNumber)+":"+
            std::to_string((uint64_t(id.nFileIndexHigh)<<32)|id.nFileIndexLow)+":"+
            std::to_string((uint64_t(id.nFileSizeHigh)<<32)|id.nFileSizeLow)+":"+
            std::to_string((uint64_t(id.ftLastWriteTime.dwHighDateTime)<<32)|id.ftLastWriteTime.dwLowDateTime);
        Check(actual==identity,"CanonicalExclusiveIdentity");
    }
    bool ReadBlock(std::uint64_t block,std::uint32_t block_size,std::vector<std::byte>& bytes) override
    {
        bytes.clear();if(block_size!=4096 || block>=size/4096) return false;
        LARGE_INTEGER at{};at.QuadPart=static_cast<LONGLONG>(base+block*4096);DWORD got=0;bytes.resize(4096);
        const bool ok=SetFilePointerEx(file.h,at,nullptr,FILE_BEGIN) && ::ReadFile(file.h,bytes.data(),4096,&got,nullptr) && got==4096;
        if(ok && mode==L"guard-fault") bytes[0]^=std::byte{1};
        return ok;
    }
    bool WriteBlock(std::uint64_t block,Bytes bytes) override
    {
        if(bytes.size()!=4096 || block>=size/4096) return false;
        LARGE_INTEGER at{};at.QuadPart=static_cast<LONGLONG>(base+block*4096);DWORD put=0;
        const DWORD count=(mode==L"torn-switch" && block==switch_block)?32:4096;
        if(!SetFilePointerEx(file.h,at,nullptr,FILE_BEGIN) || !WriteFile(file.h,bytes.data(),count,&put,nullptr) || put!=count) return false;
        ++writes;return count==4096;
    }
    bool Flush() override {++flushes;return FlushFileBuffers(file.h)!=FALSE;}
};
int CanonicalCase(const std::filesystem::path& image,const Profile& profile,std::wstring mode)
{
    auto credentials=ReceivePair();auto& old_password=credentials.old_password;auto& new_password=credentials.new_password;
    const auto expected=NativeRead(image,profile,old_password.Bytes(),true);
    auto lease=std::make_shared<t::WindowsImageLease>(image.wstring());const auto identity=lease->Identity();
    auto source=std::make_shared<t::OwnedEncryptedImageSource>(lease,profile.Base(),profile.Size());
    c::UnlockError unlock;c::PasswordUnlockBudget budget;
    auto capability=c::SoftwareKeybagRewrap::Prepare(source,source->SourceIdentity(),source->Revision(),1026,
        c::KeybagLength::IncludesHeader,old_password,new_password,budget,unlock);
    Check(static_cast<bool>(capability),"CanonicalSourceRewrap");std::string error;
    const std::uint64_t pin=mode==L"pin4"?4:6;
    auto prepared=capability->PreparePublication(old_password,mode==L"wrong-new"?old_password:new_password,budget,error,
        (mode==L"pin6" || mode==L"pin4")?std::span(&pin,1):std::span<const std::uint64_t>{});
    if(!prepared) {
        std::cout<<"{\"prepared\":false,\"error\":\""<<error<<"\",\"writes\":0}\n";
        if(mode==L"wrong-new") return error=="MaintenanceCandidateNewCredentialFailed"?0:1;
        if(mode==L"pin4") return error=="MaintenanceRequiredCheckpointWouldRetire"?0:1;
        return profile.native?0:1;
    }
    const auto old_container=prepared->OldContainerBagBlock(),old_volume=prepared->OldVolumeBagBlock();
    std::vector<std::byte> old_container_bytes,old_volume_bytes;
    Check(source->Read(old_container*4096,4096,old_container_bytes) && source->Read(old_volume*4096,4096,old_volume_bytes),"OldBagRead");
    capability.reset();Check(source.use_count()==1,"CanonicalSourceRelease");source.reset();
    Check(lease.use_count()==1,"CanonicalLeaseRelease");lease.reset();
    const auto& publication=prepared->Publication();
    bool completed=false;std::size_t writes=0,flushes=0,lease_retries=0;
    {
        PublicationTarget target(image,profile,identity,publication.superblock_write.physical_block,mode);
        const auto hook=[&](std::string_view stage) {
            return !((mode==L"before-write" && stage=="before-apple-device-write") ||
                (mode==L"before-preflush" && stage=="before-apple-prepublication-flush") ||
                (mode==L"before-switch" && stage=="before-apple-checkpoint-switch") ||
                (mode==L"before-finalflush" && stage=="before-apple-final-flush"));
        };
        completed=apfsaccess::rw::ExecuteAppleCheckpointPublication(target,publication,error,hook);
        writes=target.writes;flushes=target.flushes;lease_retries=target.lease_retries;
        Check(completed==(mode==L"commit" || mode==L"pin6"),"CanonicalCutOutcome");
    }
    const bool switched=mode==L"commit" || mode==L"pin6" || mode==L"before-finalflush";
    const auto& active=switched?new_password:old_password;
    const auto& refused=switched?old_password:new_password;
    Check(NativeRead(image,profile,active.Bytes(),true)==expected,"CanonicalActiveCredentialPayload");
    NativeRead(image,profile,refused.Bytes(),false);
    auto fresh_lease=std::make_shared<t::WindowsImageLease>(image.wstring());
    auto fresh=std::make_shared<t::OwnedEncryptedImageSource>(fresh_lease,profile.Base(),profile.Size());
    auto cp=c::LoadContainerCheckpointView(*fresh,0,fresh->SizeBytes(),error);Check(static_cast<bool>(cp),"CanonicalFreshSelection");
    Check(cp->superblock.xid==(switched?publication.transaction_xid:publication.expected_checkpoint_xid),"CanonicalSelectedXid");
    std::vector<std::byte> a,b;
    Check(fresh->Read(old_container*4096,4096,a) && fresh->Read(old_volume*4096,4096,b) && a==old_container_bytes && b==old_volume_bytes,"CanonicalOldBagsPreserved");
    if(switched) for(auto xid:prepared->RetainedCheckpoints()) {
        std::uint64_t container=0,volume=0;
        auto selected=c::InspectPasswordKeybagMetadataAtCheckpoint(*fresh,1026,c::KeybagLength::IncludesHeader,xid,unlock,container,volume);
        Check(selected && container!=prepared->NewContainerBagBlock() && volume!=prepared->NewVolumeBagBlock(),"CanonicalOldRangesPreserved");
        auto request=selected->selection;request.user_uuid=selected->users.front();c::PasswordUnlockBudget old_attempts;
        auto old=c::UnlockPasswordKeybags(*fresh,request,old_password.Bytes(),old_attempts);
        Check(static_cast<bool>(old),"CanonicalHistoricalOldCredential");
    }
    std::cout<<"{\"prepared\":true,\"published\":"<<(completed?"true":"false")<<",\"switched\":"<<(switched?"true":"false")
        <<",\"writes\":"<<writes<<",\"flushes\":"<<flushes<<",\"exclusiveLeaseRetries\":"<<lease_retries<<",\"sourceXid\":"<<publication.expected_checkpoint_xid
        <<",\"selectedXid\":"<<cp->superblock.xid<<",\"oldContainer\":"<<old_container<<",\"oldVolume\":"<<old_volume
        <<",\"newContainer\":"<<prepared->NewContainerBagBlock()<<",\"newVolume\":"<<prepared->NewVolumeBagBlock()
        <<",\"retired\":"<<prepared->RetiredCheckpoints()<<",\"oldBagsPreserved\":true,\"protectedMaintenanceJournal\":false,\"payloadSha256\":\""<<expected<<"\",\"retained\":[";
    bool first=true;for(auto xid:prepared->RetainedCheckpoints()){if(!first)std::cout<<",";first=false;std::cout<<xid;}
    std::cout<<"],\"plannedBlocks\":[";first=true;
    for(const auto& write:publication.before_superblock_writes) {
        if(!first)std::cout<<",";first=false;
        std::cout<<"{\"block\":"<<write.physical_block<<",\"sha256\":\""<<Digest(write.bytes)<<"\"}";
    }
    std::cout<<",{\"block\":"<<publication.superblock_write.physical_block<<",\"sha256\":\""<<Digest(publication.superblock_write.bytes)<<"\"}]}\n";
    return 0;
}
int CanonicalDriver(const std::filesystem::path& executable,std::wstring mode,bool native)
{
    const Profile profile{native};
    const auto run=std::filesystem::path(canonical_root)/(L"run-"+std::to_wstring(GetCurrentProcessId())+L"-"+std::to_wstring(GetTickCount64())+L"-"+mode);
    std::filesystem::create_directory(run);
    const auto original=std::filesystem::path(fixtures)/profile.Name(),image=run/profile.Name();
    Check(DigestFile(original)==profile.Pin(),"CanonicalOriginalPin");Check(CopyFileW(original.c_str(),image.c_str(),TRUE),"CanonicalCopy");
    auto old_password=NoteCredential(profile),new_password=RandomCredential();auto pair=Pair(old_password.Bytes(),new_password.Bytes());
    const auto args=(native?L" native ":L" dfvfs ")+Quoted(image);
    const auto result=Child(executable,L"canonical"+args+L" "+mode,pair.Bytes(),run/L"case.log");pair.Clear();
    Check(result==0,"CanonicalCaseChild");
    std::ifstream log(run/L"case.log");std::string contents((std::istreambuf_iterator<char>(log)),{});
    const bool prepared=contents.find("\"prepared\":true")!=std::string::npos;
    if(prepared) {
        const bool switched=mode==L"commit" || mode==L"pin6" || mode==L"before-finalflush";
        const auto active_exit=Child(executable,L"oracle-pass"+args,switched?new_password.Bytes():old_password.Bytes(),run/L"oracle-active.log");
        if(mode==L"torn-switch") {
            std::ifstream active(run/L"oracle-active.log");std::string refusal((std::istreambuf_iterator<char>(active)),{});
            Check(active_exit==1 && refusal=="FAIL OracleOpen\n","TornIndependentStructuralRefusal");
            std::cout<<"TORN_OBSERVATION nativeOldFallback=true independentOpenRefusal=true protectedRepairPending=true\n";
        } else {
            Check(active_exit==0,"CanonicalIndependentActive");
            Check(Child(executable,L"oracle-refuse"+args,switched?old_password.Bytes():new_password.Bytes(),run/L"oracle-refused.log")==0,"CanonicalIndependentRefused");
        }
    } else Check(DigestFile(image)==profile.Pin(),"CanonicalRefusalUnchanged");
    Check(DigestFile(original)==profile.Pin(),"CanonicalOriginalPreserved");
    for(const auto& file:std::filesystem::directory_iterator(run)) if(file.is_regular_file()) Absent(file.path(),old_password.Bytes(),new_password.Bytes());
    std::cout<<contents;
    std::wcout<<L"EVIDENCE "<<run.wstring()<<L"\n";return 0;
}
}
int wmain(int argc,wchar_t** argv)
{
    try {
        if(argc==4 && std::wstring_view(argv[1])==L"drive-canonical") return CanonicalDriver(argv[0],argv[3],std::wstring_view(argv[2])==L"native");
        if(argc==5 && std::wstring_view(argv[1])==L"canonical") return CanonicalCase(argv[3],Profile{std::wstring_view(argv[2])==L"native"},argv[4]);
        return PrimitiveKeybagMain(argc,argv);
    }catch(const std::exception& error){std::cerr<<"FAIL "<<error.what()<<'\n';return 1;}
}
