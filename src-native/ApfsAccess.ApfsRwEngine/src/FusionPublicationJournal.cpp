#include "FusionPublicationJournal.h"
#include "FusionPublicationInternal.h"
#include "BlockDevice.h"
#include "FusionRetainedPrefixCache.h"
#include <bcrypt.h>
#include <algorithm>
#include <filesystem>
#include <set>

namespace apfsaccess::rw {
namespace {
constexpr std::size_t Limit = 8 * 1024 * 1024;
constexpr std::uint64_t Magic = 0x3257504E4F495346ULL;
bool Fail(std::string& e,const char* why) { e=why;return false; }
void U64(std::vector<std::byte>& b,std::uint64_t n) {
    for(unsigned i=0;i<8;++i)b.push_back(std::byte((n>>(i*8))&255));
}
void Blob(std::vector<std::byte>& b,std::span<const std::byte> v) {
    U64(b,v.size());b.insert(b.end(),v.begin(),v.end());
}
struct Cursor {
    std::span<const std::byte> b;std::size_t at=0;bool ok=true;
    std::uint64_t Number() {
        if(b.size()-at<8){ok=false;return 0;}std::uint64_t n=0;
        for(unsigned i=0;i<8;++i)n|=std::uint64_t(std::to_integer<unsigned>(b[at++]))<<(i*8);
        return n;
    }
    std::vector<std::byte> Bytes(std::size_t max=Limit) {
        auto n=Number();if(!ok||n>max||n>b.size()-at){ok=false;return {};}
        std::vector<std::byte> v(b.begin()+at,b.begin()+at+static_cast<std::size_t>(n));at+=static_cast<std::size_t>(n);return v;
    }
};
struct Handle { HANDLE h=INVALID_HANDLE_VALUE;~Handle(){if(h!=INVALID_HANDLE_VALUE)CloseHandle(h);} };
bool Ordinary(const std::wstring& p) {
    if(p.size()<4||!iswalpha(p[0])||p[1]!=L':'||p[2]!=L'\\'||p.find_first_of(L":/*?\"<>|",3)!=p.npos)return false;
    for(std::size_t at=3;at<p.size();) {
        auto end=p.find(L'\\',at);if(end==p.npos)end=p.size();auto part=p.substr(at,end-at);
        if(part.empty()||part==L"."||part==L".."||part.back()==L'.'||part.back()==L' ')return false;
        auto stem=part.substr(0,part.find(L'.'));for(auto& c:stem)c=static_cast<wchar_t>(towupper(c));
        if(stem==L"CON"||stem==L"PRN"||stem==L"AUX"||stem==L"NUL"||stem==L"CONIN$"||stem==L"CONOUT$"||
            (stem.size()==4&&(stem.starts_with(L"COM")||stem.starts_with(L"LPT"))))return false;
        for(auto c:part)if(c<32)return false;
        at=end+1;
    }
    return p.back()!=L'\\';
}
}
bool FusionPublicationHash(std::span<const std::byte> bytes,std::array<std::byte,32>& hash) {
    return bytes.size()<=Limit&&BCryptHash(BCRYPT_SHA256_ALG_HANDLE,nullptr,0,
        reinterpret_cast<PUCHAR>(const_cast<std::byte*>(bytes.data())),static_cast<ULONG>(bytes.size()),
        reinterpret_cast<PUCHAR>(hash.data()),static_cast<ULONG>(hash.size()))>=0;
}
bool FusionPreparedPublication::Encode(std::vector<std::byte>& b,std::string& e) const {
    b.clear();
    if(jid.size()>1024||name.size()>255||payload.size()>256*1024||plan.block_size!=4096)
        return Fail(e,"FusionWitnessBindingBounds");
    if(plan.before_superblock_writes.size()>WriteLimit)return Fail(e,"FusionWitnessWriteLimit");
    if(plan.guard_blocks.size()>GuardLimit)return Fail(e,"FusionWitnessGuardLimit");
    if(before.size()>PreimageLimit)return Fail(e,"FusionWitnessPreimageLimit");
    if(!plan.fusion_tier2_anchor_write)return Fail(e,"FusionWitnessMirrorRequired");
    const auto valid_write=[](const auto& w){return static_cast<unsigned>(w.kind)<=4&&w.bytes.size()==4096;};
    if(!valid_write(plan.superblock_write)||!valid_write(*plan.fusion_tier2_anchor_write)||
        !std::all_of(plan.before_superblock_writes.begin(),plan.before_superblock_writes.end(),valid_write)||
        std::any_of(plan.guard_blocks.begin(),plan.guard_blocks.end(),[](const auto& g){return g.bytes.size()!=4096;})||
        std::any_of(before.begin(),before.end(),[](const auto& p){return p.second.size()!=4096;}))
        return Fail(e,"FusionWitnessBlockBounds");
    // Every count and byte string must fit the replay grammar before the
    // original WAL accepts the digest. Reserve room for the witness envelope.
    const auto encoded_size=8+(8+source.size())+(8+payload_hash.size())+(8+jid.size())+(8+name.size())+
        5*8+(8+payload.size())+4*8+8+(plan.before_superblock_writes.size()+2)*(4*8+4096)+
        8+plan.guard_blocks.size()*(2*8+4096)+8+before.size()*(2*8+4096);
    if(encoded_size>Limit-128)return Fail(e,"FusionWitnessCapacity");
    b.reserve(encoded_size);U64(b,Magic);Blob(b,source);Blob(b,payload_hash);
    Blob(b,std::as_bytes(std::span(jid)));Blob(b,std::as_bytes(std::span(name)));U64(b,volume);U64(b,inode);U64(b,offset);U64(b,length);U64(b,operation);Blob(b,payload);
    U64(b,plan.block_size);U64(b,plan.expected_checkpoint_xid);U64(b,plan.transaction_xid);U64(b,plan.next_object_id);
    const auto write=[&](const auto& w){U64(b,static_cast<unsigned>(w.kind));U64(b,w.physical_block);U64(b,w.object_id);Blob(b,w.bytes);};
    U64(b,plan.before_superblock_writes.size());for(const auto& w:plan.before_superblock_writes)write(w);
    write(plan.superblock_write);
    write(*plan.fusion_tier2_anchor_write);
    U64(b,plan.guard_blocks.size());for(const auto& g:plan.guard_blocks){U64(b,g.physical_block);Blob(b,g.bytes);}
    U64(b,before.size());for(const auto& [at,bytes]:before){U64(b,at);Blob(b,bytes);}
    return b.size()<=Limit-128||Fail(e,"FusionWitnessCapacity");
}
bool FusionPreparedPublication::Decode(std::span<const std::byte> b,FusionPreparedPublication& p,std::string& e) {
    Cursor c{b};if(b.size()>Limit||c.Number()!=Magic)return Fail(e,"FusionWitnessHeader");
    auto source=c.Bytes(32),hash=c.Bytes(32),jid=c.Bytes(1024);
    if(source.size()!=32||hash.size()!=32)return Fail(e,"FusionWitnessBinding");
    std::copy(source.begin(),source.end(),p.source.begin());std::copy(hash.begin(),hash.end(),p.payload_hash.begin());
    p.jid.assign(reinterpret_cast<const char*>(jid.data()),jid.size());auto name=c.Bytes(255);p.name.assign(reinterpret_cast<const char*>(name.data()),name.size());
    p.volume=c.Number();p.inode=c.Number();p.offset=c.Number();p.length=c.Number();p.operation=c.Number();p.payload=c.Bytes(256*1024);
    if(c.Number()!=4096)return Fail(e,"FusionWitnessBlockSize");p.plan.block_size=4096;
    p.plan.expected_checkpoint_xid=c.Number();p.plan.transaction_xid=c.Number();p.plan.next_object_id=c.Number();
    auto write=[&]() { AppleCheckpointPlannedWrite w;auto kind=c.Number();if(kind>4)c.ok=false;
        w.kind=static_cast<AppleCheckpointWriteKind>(kind);w.physical_block=c.Number();w.object_id=c.Number();w.bytes=c.Bytes(4096);return w; };
    auto n=c.Number();if(n>WriteLimit)return Fail(e,"FusionWitnessWriteLimit");
    for(std::uint64_t i=0;i<n;++i)p.plan.before_superblock_writes.push_back(write());
    p.plan.superblock_write=write();p.plan.fusion_tier2_anchor_write=write();
    n=c.Number();if(n>GuardLimit)return Fail(e,"FusionWitnessGuardLimit");
    for(std::uint64_t i=0;i<n;++i){auto at=c.Number();p.plan.guard_blocks.push_back({at,c.Bytes(4096)});}
    n=c.Number();if(n>PreimageLimit)return Fail(e,"FusionWitnessPreimageLimit");
    for(std::uint64_t i=0;i<n;++i){auto at=c.Number();auto bytes=c.Bytes(4096);if(!p.before.emplace(at,std::move(bytes)).second)c.ok=false;}
    std::array<std::byte,32> computed{};
    if(!c.ok||c.at!=b.size()||!FusionPublicationHash(p.payload,computed)||computed!=p.payload_hash)return Fail(e,"FusionWitnessMalformed");
    return true;
}
bool FusionPreparedPublication::Digest(std::string& digest,std::string& e) const {
    std::vector<std::byte> bytes;std::array<std::byte,32> hash{};
    if(!Encode(bytes,e)||!FusionPublicationHash(bytes,hash))return Fail(e,"FusionWitnessHash");
    digest=catalog::BytesToHexLower(hash.data(),hash.size());return true;
}
struct FusionPublicationJournal::State {
    FusionRetainedPrefixCache<> prefix;
    std::wstring path;std::vector<HANDLE> directories;
    HANDLE witness=INVALID_HANDLE_VALUE;
    void Release(){if(witness!=INVALID_HANDLE_VALUE){CloseHandle(witness);witness=INVALID_HANDLE_VALUE;}}
    ~State(){Release();for(auto h:directories)CloseHandle(h);}
};
FusionPublicationJournal::FusionPublicationJournal(std::wstring path):state_(std::make_unique<State>()) { state_->path=std::move(path); }
FusionPublicationJournal::~FusionPublicationJournal()=default;
void FusionPublicationJournal::BindContinuationProof(const std::array<std::byte,32>& source,const std::string& jid,
    std::uint64_t volume,std::uint64_t generation,std::uint64_t serial,std::uint64_t file){
    state_->prefix.Bind({source,jid,volume,generation,serial,file});
}
bool FusionPublicationJournal::PinContinuationProof(const std::wstring& path,const std::array<std::byte,32>& hash,std::string& e){
    return state_->prefix.PinFile(path,hash,e);
}
bool FusionPublicationJournal::HasContinuationProof(std::uint64_t floor,const std::array<std::byte,32>& hash) const {
    return state_->prefix.Has(floor,hash);
}
void FusionPublicationJournal::RememberContinuationProof(std::uint64_t floor,const std::array<std::byte,32>& hash,
    const std::vector<std::pair<std::uint64_t,std::string>>& census){
    std::vector<std::wstring> dependencies;dependencies.reserve(census.size());
    for(const auto& row:census)dependencies.push_back(state_->path+L".fusion-"+std::to_wstring(row.first)+L".witness");
    state_->prefix.Remember(floor,hash,state_->path+L".fusion-continue-"+std::to_wstring(floor)+L".cert",dependencies);
}
void FusionPublicationJournal::AdvanceContinuationProof(const std::array<std::byte,32>& source,const std::string& jid,
    std::uint64_t volume,std::uint64_t generation,std::uint64_t serial,std::uint64_t before,std::uint64_t after){
    state_->prefix.Advance({source,jid,volume,generation,serial,before},{source,jid,volume,generation,serial,after});
}
bool FusionPublicationJournal::Pin(std::string& e) {
    const auto& path=state_->path;if(!Ordinary(path))return Fail(e,"FusionJournalOrdinaryPathRequired");
    auto type=GetDriveTypeW(path.substr(0,3).c_str());if(type!=DRIVE_FIXED&&type!=DRIVE_REMOVABLE&&type!=DRIVE_RAMDISK)return Fail(e,"FusionJournalLocalDriveRequired");
    for(std::size_t end=2;end!=path.npos;end=path.find(L'\\',end+1)) {
        auto prefix=path.substr(0,end==2?3:end);
        auto h=CreateFileW(prefix.c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ,nullptr,OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
        if(h==INVALID_HANDLE_VALUE)return Fail(e,"FusionJournalDirectoryLease");state_->directories.push_back(h);
        FILE_ATTRIBUTE_TAG_INFO info{};
        if(!GetFileInformationByHandleEx(h,FileAttributeTagInfo,&info,sizeof(info))||!(info.FileAttributes&FILE_ATTRIBUTE_DIRECTORY)||
            (info.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT))return Fail(e,"FusionJournalDirectoryReparse");
    }
    const auto attributes=GetFileAttributesW(path.c_str());
    if(attributes!=INVALID_FILE_ATTRIBUTES&&(attributes&(FILE_ATTRIBUTE_REPARSE_POINT|FILE_ATTRIBUTE_DIRECTORY)))return Fail(e,"FusionJournalFileReparse");
    return true;
}
bool FusionPublicationJournal::Preflight(std::uint64_t sequence,const FusionPreparedPublication& p,std::string& e) {
    std::vector<std::byte> bytes;if(!sequence||!p.Encode(bytes,e))return false;
    auto path=state_->path+L".fusion-"+std::to_wstring(sequence)+L".witness";
    const auto attributes=GetFileAttributesW(path.c_str());
    if(attributes!=INVALID_FILE_ATTRIBUTES)return Fail(e,"FusionWitnessExistingEvidence");
    return GetLastError()==ERROR_FILE_NOT_FOUND||Fail(e,"FusionWitnessDestinationUnavailable");
}
bool FusionPublicationJournal::Store(std::uint64_t sequence,const FusionPreparedPublication& p,std::string& e) {
    state_->Release();
    if(!sequence||p.accepted_sequence!=sequence||!p.transaction_id||!p.mutation_sequence||p.mutation_sequence>=sequence)return Fail(e,"FusionWitnessOriginalEnrollmentRequired");
    std::vector<std::byte> body,bytes;if(!p.Encode(body,e))return false;
    U64(bytes,Magic);U64(bytes,sequence);U64(bytes,p.transaction_id);U64(bytes,p.mutation_sequence);Blob(bytes,body);std::array<std::byte,32> hash{};
    if(!FusionPublicationHash(bytes,hash))return Fail(e,"FusionWitnessHash");bytes.insert(bytes.end(),hash.begin(),hash.end());
    auto path=state_->path+L".fusion-"+std::to_wstring(sequence)+L".witness";
    Handle h;h.h=CreateFileW(path.c_str(),GENERIC_READ|GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_FLAG_WRITE_THROUGH|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    if(h.h==INVALID_HANDLE_VALUE)return Fail(e,"FusionWitnessExistsOrCreateFailed");
    DWORD done=0;
    if(!WriteFile(h.h,bytes.data(),static_cast<DWORD>(bytes.size()),&done,nullptr)||done!=bytes.size()||!FlushFileBuffers(h.h))return Fail(e,"FusionWitnessDurableWriteFailed");
    LARGE_INTEGER zero{};if(!SetFilePointerEx(h.h,zero,nullptr,FILE_BEGIN))return Fail(e,"FusionWitnessSeek");
    std::vector<std::byte> read(bytes.size());done=0;
    if(!ReadFile(h.h,read.data(),static_cast<DWORD>(read.size()),&done,nullptr)||done!=read.size()||read!=bytes)return Fail(e,"FusionWitnessReadback");
    return true;
}
bool FusionPublicationJournal::Load(std::uint64_t sequence,std::unique_ptr<FusionPreparedPublication>& p,std::string& e) {
    return Read(sequence,p,e,ReadPurpose::PendingReplay);
}
bool FusionPublicationJournal::LoadRetained(std::uint64_t sequence,std::unique_ptr<FusionPreparedPublication>& p,std::string& e) {
    return Read(sequence,p,e,ReadPurpose::RetainedCensus);
}
bool FusionPublicationJournal::Read(std::uint64_t sequence,std::unique_ptr<FusionPreparedPublication>& p,std::string& e,ReadPurpose purpose) {
    p.reset();state_->Release();auto path=state_->path+L".fusion-"+std::to_wstring(sequence)+L".witness";
    const bool replay=purpose==ReadPurpose::PendingReplay;
    Handle h;h.h=CreateFileW(path.c_str(),replay?GENERIC_READ|GENERIC_WRITE:GENERIC_READ,
        replay?0:FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    if(h.h==INVALID_HANDLE_VALUE)return Fail(e,GetLastError()==ERROR_FILE_NOT_FOUND?"FusionWitnessMissing":"FusionWitnessOpenFailed");
    BY_HANDLE_FILE_INFORMATION info{};LARGE_INTEGER size{};
    if(!GetFileInformationByHandle(h.h,&info)||info.nNumberOfLinks!=1||(info.dwFileAttributes&(FILE_ATTRIBUTE_REPARSE_POINT|FILE_ATTRIBUTE_DIRECTORY))||
        !GetFileSizeEx(h.h,&size)||size.QuadPart<72||size.QuadPart>Limit)return Fail(e,"FusionWitnessFileInvalid");
    std::vector<std::byte> bytes(static_cast<std::size_t>(size.QuadPart));DWORD done=0;
    if(!ReadFile(h.h,bytes.data(),static_cast<DWORD>(bytes.size()),&done,nullptr)||done!=bytes.size())return Fail(e,"FusionWitnessRead");
    std::array<std::byte,32> hash{};auto content=std::span(bytes).first(bytes.size()-32);
    if(!FusionPublicationHash(content,hash)||!std::equal(hash.begin(),hash.end(),bytes.end()-32))return Fail(e,"FusionWitnessChecksum");
    Cursor c{content};if(c.Number()!=Magic||c.Number()!=sequence)return Fail(e,"FusionWitnessSequence");
    const auto transaction=c.Number(),mutation=c.Number();auto body=c.Bytes();
    if(!c.ok||c.at!=content.size())return Fail(e,"FusionWitnessPartial");
    auto decoded=std::unique_ptr<FusionPreparedPublication>(new FusionPreparedPublication);
    if(!FusionPreparedPublication::Decode(body,*decoded,e)||!transaction||!mutation||mutation>=sequence)return Fail(e,"FusionWitnessOriginalEnrollmentInvalid");
    if(replay&&!FlushFileBuffers(h.h))return Fail(e,"FusionWitnessReplayDurabilityFailed");
    decoded->accepted_sequence=sequence;decoded->transaction_id=transaction;decoded->mutation_sequence=mutation;
    if(!replay&&state_->prefix.Active()){
        std::array<std::byte,32> full_hash{};
        if(!FusionPublicationHash(bytes,full_hash)||!state_->prefix.PinFile(path,full_hash,e))return false;
    }
    state_->witness=h.h;h.h=INVALID_HANDLE_VALUE;p=std::move(decoded);return true;
}
}
