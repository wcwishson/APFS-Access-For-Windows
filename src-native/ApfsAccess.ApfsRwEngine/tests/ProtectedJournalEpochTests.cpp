#include "ProtectedJournalEpoch.h"
#include "ApfsCryptoTestHooks.h"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <dpapi.h>
#include <winioctl.h>
#include <algorithm>
#include <atomic>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace apfsaccess::journal;
namespace crypto = apfsaccess::crypto;
namespace jt = apfsaccess::journal::testing;
namespace fs = std::filesystem;
namespace
{
unsigned checks = 0, groups = 0, cases = 0;
std::wstring root;
constexpr char keyCanary[] = "APFS_KEY_CANARY_0123456789ABCDEF";
constexpr char plainCanary[] = "PRIVATE_PAYLOAD_CANARY_20261016_NO_PLAINTEXT";
constexpr char metadataCanary[] = "D:\\PRIVATE_SOURCE_CANARY\\volume-metadata-name.bin";
static_assert(sizeof(keyCanary) - 1 == 32);
#define CHECK(e) do { ++checks; if (!(e)) throw std::runtime_error("check failed at line " + std::to_string(__LINE__) + ": " #e); } while(false)
struct File
{
    HANDLE h = INVALID_HANDLE_VALUE;
    explicit File(HANDLE value) : h(value) {}
    ~File() { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); }
    File(const File&) = delete;
    File& operator=(const File&) = delete;
};
bool Exact(HANDLE h, const std::wstring& path, bool directory, bool singleLink=true)
{
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(h, &info) || (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
        ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) != directory || (!directory && singleLink && info.nNumberOfLinks != 1)) return false;
    wchar_t name[1024]{};
    const auto n=GetFinalPathNameByHandleW(h, name, 1024, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    return n && n < 1024 && CompareStringOrdinal(name, -1, (L"\\\\?\\" + path).c_str(), -1, TRUE) == CSTR_EQUAL;
}
struct Pins
{
    std::vector<std::unique_ptr<File>> handles;
    explicit Pins(const std::wstring& directory)
    {
        CHECK(directory.size() >= 3 && directory.substr(0,3) == L"D:\\");
        CHECK(directory.find(L"..") == directory.npos);
        for(std::size_t end=2;;) {
            auto prefix=directory.substr(0,end==2 ? 3:end);
            auto f=std::make_unique<File>(CreateFileW(prefix.c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ,nullptr,
                OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
            CHECK(f->h != INVALID_HANDLE_VALUE); CHECK(Exact(f->h,prefix,true));
            handles.push_back(std::move(f));
            if(end==directory.size()) break;
            end=directory.find(L'\\',end+1); if(end==directory.npos) end=directory.size();
        }
    }
};
void NewDirectory(const std::wstring& path)
{
    CHECK(path.starts_with(root + L"\\") || path == root);
    Pins parent(fs::path(path).parent_path().wstring());
    CHECK(CreateDirectoryW(path.c_str(), nullptr));
    File f(CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    CHECK(f.h != INVALID_HANDLE_VALUE); CHECK(Exact(f.h, path, true));
}
std::wstring Case(const wchar_t* label)
{
    auto path=root+L"\\"+std::to_wstring(++cases)+L"-"+label;
    NewDirectory(path); return path;
}
std::vector<std::byte> Bytes(std::string_view s)
{ return {reinterpret_cast<const std::byte*>(s.data()), reinterpret_cast<const std::byte*>(s.data()+s.size())}; }
std::vector<std::byte> Copy(std::span<const std::byte> s) { return {s.begin(),s.end()}; }
JournalDigest Digest(unsigned seed)
{
    JournalDigest d{};
    for(std::size_t i=0;i<d.size();++i) d[i]=static_cast<std::byte>((seed+17*i)&255);
    return d;
}
JournalRecordContext Context() { return {7,Digest(83),12345}; }
std::wstring Slot(const std::wstring& directory, const JournalEpochId& id)
{
    constexpr wchar_t hex[]=L"0123456789abcdef";
    auto name=directory+L"\\epoch-";
    for(auto b:id) { auto v=std::to_integer<unsigned>(b); name+=hex[v>>4]; name+=hex[v&15]; }
    return name+L".key";
}
void Write(const std::wstring& path, std::span<const std::byte> b, bool replace=false)
{
    CHECK(path.starts_with(root+L"\\"));
    Pins parent(fs::path(path).parent_path().wstring());
    // OPEN_ALWAYS never truncates an existing target until its resolved handle
    // and link count have been verified. All replacement targets are test copies.
    File f(CreateFileW(path.c_str(),GENERIC_READ|GENERIC_WRITE,0,nullptr,replace?OPEN_ALWAYS:CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_WRITE_THROUGH,nullptr));
    CHECK(f.h!=INVALID_HANDLE_VALUE); CHECK(Exact(f.h,path,false));
    LARGE_INTEGER zero{}; CHECK(SetFilePointerEx(f.h,zero,nullptr,FILE_BEGIN));
    CHECK(SetEndOfFile(f.h)); DWORD written=0;
    CHECK(WriteFile(f.h,b.data(),static_cast<DWORD>(b.size()),&written,nullptr)); CHECK(written==b.size());
    CHECK(FlushFileBuffers(f.h));
}
std::vector<std::byte> Read(const std::wstring& path)
{
    CHECK(path.starts_with(root+L"\\"));
    Pins parent(fs::path(path).parent_path().wstring());
    File f(CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
    CHECK(f.h!=INVALID_HANDLE_VALUE); CHECK(Exact(f.h,path,false));
    LARGE_INTEGER size{}; CHECK(GetFileSizeEx(f.h,&size)); CHECK(size.QuadPart>=0 && size.QuadPart<=2*1024*1024);
    std::vector<std::byte> b(static_cast<std::size_t>(size.QuadPart)); DWORD got=0;
    CHECK(ReadFile(f.h,b.data(),static_cast<DWORD>(b.size()),&got,nullptr)); CHECK(got==b.size()); return b;
}
using Snapshot=std::map<std::wstring,std::vector<std::byte>>;
Snapshot Files(const std::wstring& directory)
{
    Pins pin(directory); Snapshot result;
    for(const auto& f:fs::directory_iterator(directory)) {
        CHECK(!(GetFileAttributesW(f.path().c_str())&FILE_ATTRIBUTE_REPARSE_POINT));
        if(f.is_regular_file()) result.emplace(f.path().filename().wstring(),Read(f.path().wstring()));
    }
    return result;
}
void Rejected(const JournalRecordResult& r, JournalError expected)
{
    CHECK(!r); CHECK(r.status.error==expected); CHECK(r.bytes.Size()==0); CHECK(!r.bytes.IsLocked());
}
void RejectedAny(const JournalRecordResult& r)
{ CHECK(!r); CHECK(r.bytes.Size()==0); CHECK(!r.bytes.IsLocked()); }
void Put32(std::vector<std::byte>& b,std::size_t at,std::uint32_t n)
{ for(unsigned i=0;i<4;++i) b[at+i]=static_cast<std::byte>((n>>(8*i))&255); }
std::array<std::byte,12> Nonce(std::span<const std::byte> frame)
{ std::array<std::byte,12> n{}; std::memcpy(n.data(),frame.data()+40,12); return n; }
template<class F> void Group(const char* name,F operation)
{
    jt::hooks={}; crypto::testing::hooks={};
    operation();
    CHECK(jt::hooks.dpapi_released_zero); CHECK(jt::hooks.dpapi_wipes==jt::hooks.dpapi_releases);
    CHECK(crypto::testing::hooks.all_released_bytes_zero);
    CHECK(crypto::testing::hooks.wipes==crypto::testing::hooks.releases);
    ++groups; std::cout<<"PASS "<<name<<'\n';
}

void RoundTrips()
{
    const auto directory=Case(L"roundtrip"); const auto binding=Digest(11); const auto context=Context();
    const auto payload=Bytes(std::string(plainCanary)+"|"+metadataCanary+"|"+std::string(300,'P'));
    auto first=ProtectedJournalEpoch::AcquireWriter(directory,binding);
    CHECK(first); CHECK(first.epoch); const auto firstId=first.epoch->Id();
    auto busy=ProtectedJournalEpoch::AcquireWriter(directory,binding);
    CHECK(!busy); CHECK(busy.status.error==JournalError::Busy); CHECK(!busy.epoch);
    CHECK(!MoveFileExW(directory.c_str(),(directory+L"-moved").c_str(),0));
    auto frame=first.epoch->Seal(context,payload); CHECK(frame); CHECK(frame.bytes.IsLocked());
    auto empty=first.epoch->Seal(context,{}); CHECK(empty); CHECK(empty.bytes.Size()==80);
    Write(directory+L"\\record.bin",frame.bytes.Bytes()); Write(directory+L"\\empty.bin",empty.bytes.Bytes());
    auto concurrentRead=ProtectedJournalEpoch::Open(directory,binding,context,frame.bytes.Bytes());
    CHECK(concurrentRead); CHECK(Copy(concurrentRead.bytes.Bytes())==payload);
    first.epoch.reset();
    const auto old=Files(directory);
    auto second=ProtectedJournalEpoch::AcquireWriter(directory,binding); CHECK(second); CHECK(second.epoch->Id()!=firstId);
    auto other=second.epoch->Seal(context,payload); CHECK(other);
    CHECK(Nonce(frame.bytes.Bytes())==Nonce(other.bytes.Bytes())); // Reset is safe only with a fresh key/epoch.
    CHECK(Copy(frame.bytes.Bytes())!=Copy(other.bytes.Bytes()));
    auto oldRead=ProtectedJournalEpoch::Open(directory,binding,context,Read(directory+L"\\record.bin"));
    CHECK(oldRead); CHECK(Copy(oldRead.bytes.Bytes())==payload);
    auto emptyRead=ProtectedJournalEpoch::Open(directory,binding,context,Read(directory+L"\\empty.bin"));
    CHECK(emptyRead); CHECK(emptyRead.bytes.Size()==0); CHECK(!emptyRead.bytes.IsLocked());
    auto newRead=ProtectedJournalEpoch::Open(directory,binding,context,other.bytes.Bytes()); CHECK(newRead);
    for(const auto& [name,data]:old) CHECK(Read(directory+L"\\"+name)==data);
    CHECK(jt::hooks.dpapi_unlocks>=6);
}
void BindingAndContext()
{
    const auto directory=Case(L"binding"); const auto binding=Digest(11); const auto context=Context();
    auto w=ProtectedJournalEpoch::AcquireWriter(directory,binding); CHECK(w);
    auto frame=w.epoch->Seal(context,Bytes(plainCanary)); CHECK(frame); w.epoch.reset();
    const auto before=Files(directory);
    for(std::size_t i=0;i<binding.size();++i) {
        auto wrong=binding; wrong[i]^=std::byte{1};
        Rejected(ProtectedJournalEpoch::Open(directory,wrong,context,frame.bytes.Bytes()),JournalError::BindingMismatch);
    }
    auto wrong=context; ++wrong.purpose;
    Rejected(ProtectedJournalEpoch::Open(directory,binding,wrong,frame.bytes.Bytes()),JournalError::IntegrityFailure);
    wrong=context; ++wrong.chunk;
    Rejected(ProtectedJournalEpoch::Open(directory,binding,wrong,frame.bytes.Bytes()),JournalError::IntegrityFailure);
    for(auto& b:wrong.operation) {
        wrong=context; // Full digest substitution; individual-byte cases follow.
        b^=std::byte{1};
        Rejected(ProtectedJournalEpoch::Open(directory,binding,wrong,frame.bytes.Bytes()),JournalError::IntegrityFailure);
    }
    const auto other=Case(L"cross-source"); const auto otherBinding=Digest(12);
    auto second=ProtectedJournalEpoch::AcquireWriter(other,otherBinding); CHECK(second);
    auto otherFrame=second.epoch->Seal(context,Bytes(plainCanary)); CHECK(otherFrame); second.epoch.reset();
    const auto copied=Case(L"copied-key-slot");
    for(const auto& [name,data]:before) Write(copied+L"\\"+name,data);
    Rejected(ProtectedJournalEpoch::Open(copied,otherBinding,context,frame.bytes.Bytes()),JournalError::BindingMismatch);
    auto forged=Copy(frame.bytes.Bytes());
    std::memcpy(forged.data()+24,otherFrame.bytes.Bytes().data()+24,16);
    Rejected(ProtectedJournalEpoch::Open(other,otherBinding,context,forged),JournalError::IntegrityFailure);
    CHECK(Files(directory)==before);
}
void RecordFrames()
{
    const auto directory=Case(L"record-frames"); const auto binding=Digest(19); const auto context=Context();
    auto w=ProtectedJournalEpoch::AcquireWriter(directory,binding); CHECK(w);
    auto sealed=w.epoch->Seal(context,Bytes(plainCanary)); CHECK(sealed); const auto frame=Copy(sealed.bytes.Bytes());
    w.epoch.reset(); const auto before=Files(directory);
    for(std::size_t n=0;n<frame.size();++n)
        RejectedAny(ProtectedJournalEpoch::Open(directory,binding,context,std::span(frame).first(n)));
    for(std::size_t i=0;i<frame.size();++i) {
        auto bad=frame; bad[i]^=std::byte{1};
        RejectedAny(ProtectedJournalEpoch::Open(directory,binding,context,bad));
    }
    for(std::size_t n=1;n<=16;++n) {
        auto bad=frame; bad.resize(bad.size()+n); RejectedAny(ProtectedJournalEpoch::Open(directory,binding,context,bad));
    }
    for(auto at:{8U,12U,16U,20U}) for(auto value:{0U,1U,63U,64U,0xffffffffU}) {
        auto bad=frame; Put32(bad,at,value);
        if(bad!=frame) RejectedAny(ProtectedJournalEpoch::Open(directory,binding,context,bad));
    }
    auto bad=frame; bad.push_back(std::byte{}); Put32(bad,16,static_cast<std::uint32_t>(bad.size()));
    Put32(bad,20,static_cast<std::uint32_t>(bad.size()-64));
    Rejected(ProtectedJournalEpoch::Open(directory,binding,context,bad),JournalError::IntegrityFailure);
    auto max=std::vector<std::byte>(kMaxJournalRecordBytes+1);
    Rejected(ProtectedJournalEpoch::Open(directory,binding,context,max),JournalError::ResourceLimit);
    CHECK(Files(directory)==before);
}
void KeySlotFrames()
{
    const auto source=Case(L"key-slot-source"); const auto binding=Digest(22); const auto context=Context();
    auto w=ProtectedJournalEpoch::AcquireWriter(source,binding); CHECK(w); const auto id=w.epoch->Id();
    auto sealed=w.epoch->Seal(context,Bytes(plainCanary)); CHECK(sealed); const auto frame=Copy(sealed.bytes.Bytes()); w.epoch.reset();
    const auto slot=Read(Slot(source,id)); const auto sourceBefore=Files(source);
    const auto missing=Case(L"missing-slot"); const auto emptyBefore=Files(missing);
    Rejected(ProtectedJournalEpoch::Open(missing,binding,context,frame),JournalError::MissingKey); CHECK(Files(missing)==emptyBefore);
    const auto corrupt=Case(L"corrupt-key-slot"); const auto path=Slot(corrupt,id);
    Write(path,{});
    for(std::size_t n=0;n<slot.size();++n) {
        const auto cut=std::span(slot).first(n); Write(path,cut,true);
        RejectedAny(ProtectedJournalEpoch::Open(corrupt,binding,context,frame)); CHECK(Read(path)==Copy(cut));
    }
    for(std::size_t i=0;i<slot.size();++i) {
        auto bad=slot; bad[i]^=std::byte{1}; Write(path,bad,true);
        RejectedAny(ProtectedJournalEpoch::Open(corrupt,binding,context,frame)); CHECK(Read(path)==bad);
    }
    auto extra=slot; extra.push_back(std::byte{}); Write(path,extra,true);
    RejectedAny(ProtectedJournalEpoch::Open(corrupt,binding,context,frame)); CHECK(Read(path)==extra);
    Write(path,std::vector<std::byte>(kMaxJournalKeySlotBytes+1),true);
    Rejected(ProtectedJournalEpoch::Open(corrupt,binding,context,frame),JournalError::ResourceLimit);
    Write(path,slot,true);
    auto good=ProtectedJournalEpoch::Open(corrupt,binding,context,frame); CHECK(good);
    auto collision=ProtectedJournalEpoch::AcquireWriter(corrupt,binding); CHECK(collision); collision.epoch.reset();
    jt::hooks.id_override=id;
    auto denied=ProtectedJournalEpoch::AcquireWriter(corrupt,binding);
    CHECK(!denied); CHECK(!denied.epoch); CHECK(denied.status.error==JournalError::IoFailure); CHECK(Read(path)==slot);
    jt::hooks.id_override={};
    CHECK(Files(source)==sourceBefore);
}
void PublicationFailures()
{
    const auto directory=Case(L"publication-failures"); const auto binding=Digest(23); const auto context=Context();
    auto old=ProtectedJournalEpoch::AcquireWriter(directory,binding); CHECK(old); auto frame=old.epoch->Seal(context,Bytes(plainCanary)); CHECK(frame);
    old.epoch.reset(); const auto before=Files(directory);
    for(auto point:{jt::EpochFault::Random,jt::EpochFault::ProtectAfter,jt::EpochFault::SlotCreate,
        jt::EpochFault::SlotWrite,jt::EpochFault::SlotFlush,jt::EpochFault::SlotReadback,
        jt::EpochFault::UnprotectAfter,jt::EpochFault::AfterPublication}) {
        jt::hooks.fault=point; jt::hooks.triggered=false;
        auto failed=ProtectedJournalEpoch::AcquireWriter(directory,binding);
        CHECK(!failed); CHECK(!failed.epoch); CHECK(jt::hooks.triggered); CHECK(failed.status.os_status!=0);
        jt::hooks.fault=jt::EpochFault::None;
        for(const auto& [name,data]:before) CHECK(Read(directory+L"\\"+name)==data);
        auto recovered=ProtectedJournalEpoch::Open(directory,binding,context,frame.bytes.Bytes()); CHECK(recovered);
        auto fresh=ProtectedJournalEpoch::AcquireWriter(directory,binding); CHECK(fresh);
        auto record=fresh.epoch->Seal(context,{}); CHECK(record);
        auto decode=ProtectedJournalEpoch::Open(directory,binding,context,record.bytes.Bytes()); CHECK(decode);
    }
    CHECK(jt::hooks.dpapi_released_zero);
}
void NonceFailuresAndExhaustion()
{
    const auto directory=Case(L"nonces"); const auto binding=Digest(30); const auto context=Context();
    auto w=ProtectedJournalEpoch::AcquireWriter(directory,binding); CHECK(w);
    auto first=w.epoch->Seal(context,{}); CHECK(first); const auto n0=Nonce(first.bytes.Bytes());
    CHECK(std::all_of(n0.begin(),n0.end(),[](auto b){return b==std::byte{};}));
    crypto::testing::hooks.cng_failure_at=crypto::testing::hooks.cng_calls+4;
    crypto::testing::hooks.cng_fail_after_call=true;
    Rejected(w.epoch->Seal(context,Bytes(plainCanary)),JournalError::CryptoFailure);
    crypto::testing::hooks.cng_failure_at=-1;
    crypto::testing::hooks.allocation_failure_at=crypto::testing::hooks.allocations;
    Rejected(w.epoch->Seal(context,{}),JournalError::CryptoFailure);
    crypto::testing::hooks.allocation_failure_at=-1;
    crypto::testing::hooks.lock_failure_at=crypto::testing::hooks.locks;
    Rejected(w.epoch->Seal(context,{}),JournalError::CryptoFailure);
    crypto::testing::hooks.lock_failure_at=-1;
    auto after=w.epoch->Seal(context,{}); CHECK(after); auto n=Nonce(after.bytes.Bytes());
    CHECK(n.back()==std::byte{4}); CHECK(n!=n0);
    std::array<std::byte,12> end{}; end.fill(std::byte{255});
    w.epoch->TestSetNextNonce(end,0);
    auto final=w.epoch->Seal(context,{}); CHECK(final); CHECK(Nonce(final.bytes.Bytes())==end);
    Rejected(w.epoch->Seal(context,{}),JournalError::NonceExhausted);
    Rejected(w.epoch->Seal(context,{}),JournalError::NonceExhausted);
    end.fill(std::byte{}); end[0]=std::byte{1};
    w.epoch->TestSetNextNonce(end,kMaxJournalEpochRecords-1);
    CHECK(w.epoch->Seal(context,{})); Rejected(w.epoch->Seal(context,{}),JournalError::NonceExhausted);
}
void ConcurrentNonces()
{
    const auto directory=Case(L"concurrency"); const auto binding=Digest(34); const auto context=Context();
    auto w=ProtectedJournalEpoch::AcquireWriter(directory,binding); CHECK(w);
    constexpr std::size_t threads=8, each=32;
    std::vector<std::vector<std::vector<std::byte>>> frames(threads);
    std::atomic<bool> ok{true}; std::vector<std::thread> workers;
    for(std::size_t t=0;t<threads;++t) workers.emplace_back([&,t]{
        for(std::size_t i=0;i<each;++i) {
            auto r=w.epoch->Seal(context,{});
            if(!r) {ok=false; return;}
            frames[t].push_back(Copy(r.bytes.Bytes()));
        }
        if(!crypto::testing::hooks.all_released_bytes_zero) ok=false;
    });
    for(auto& t:workers) t.join(); CHECK(ok);
    std::set<std::array<std::byte,12>> seen;
    for(const auto& worker:frames) for(const auto& f:worker) {
        CHECK(seen.insert(Nonce(f)).second);
        auto plain=ProtectedJournalEpoch::Open(directory,binding,context,f); CHECK(plain);
    }
    CHECK(seen.size()==threads*each);
    std::uint64_t expected=0;
    for(const auto& n:seen) {
        CHECK(std::all_of(n.begin(),n.begin()+10,[](auto b){return b==std::byte{};}));
        CHECK(256*std::to_integer<unsigned>(n[10])+std::to_integer<unsigned>(n[11])==expected++);
    }
}
void WrongUser()
{
    const auto directory=Case(L"wrong-user"); const auto binding=Digest(38); const auto context=Context();
    auto w=ProtectedJournalEpoch::AcquireWriter(directory,binding); CHECK(w); const auto id=w.epoch->Id();
    auto sealed=w.epoch->Seal(context,Bytes(plainCanary)); CHECK(sealed); w.epoch.reset();
    const auto slot=Read(Slot(directory,id)); const auto before=Files(directory);
    std::array<std::byte,56> entropy{};
    std::memcpy(entropy.data(),"APFSKEY1",8); std::memcpy(entropy.data()+8,id.data(),16); std::memcpy(entropy.data()+24,binding.data(),32);
    DATA_BLOB input{static_cast<DWORD>(slot.size()-72-32),reinterpret_cast<BYTE*>(const_cast<std::byte*>(slot.data()+72))};
    DATA_BLOB extra{56,reinterpret_cast<BYTE*>(entropy.data())}, output{};
    CHECK(ImpersonateAnonymousToken(GetCurrentThread()));
    const auto ok=CryptUnprotectData(&input,nullptr,&extra,nullptr,nullptr,CRYPTPROTECT_UI_FORBIDDEN,&output);
    const auto error=GetLastError();
    auto denied=ProtectedJournalEpoch::Open(directory,binding,context,sealed.bytes.Bytes());
    const auto reverted=RevertToSelf();
    if(output.pbData) { SecureZeroMemory(output.pbData,LocalSize(output.pbData)); LocalFree(output.pbData); }
    CHECK(reverted); CHECK(!ok); CHECK(error!=0); RejectedAny(denied);
    auto good=ProtectedJournalEpoch::Open(directory,binding,context,sealed.bytes.Bytes()); CHECK(good); CHECK(Files(directory)==before);
}
void Junction(const std::wstring& path,const std::wstring& target)
{
    NewDirectory(path); Pins parent(fs::path(path).parent_path().wstring()); Pins destination(target);
    File f(CreateFileW(path.c_str(),GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
    CHECK(f.h!=INVALID_HANDLE_VALUE); CHECK(Exact(f.h,path,true));
    const auto substitute=L"\\??\\"+target;
    const auto chars=substitute.size()+1+target.size()+1;
    std::vector<std::byte> b(16+chars*sizeof(wchar_t));
    Put32(b,0,IO_REPARSE_TAG_MOUNT_POINT);
    auto put16=[&](std::size_t at,std::size_t n){ b[at]=static_cast<std::byte>(n&255); b[at+1]=static_cast<std::byte>((n>>8)&255); };
    put16(4,b.size()-8); put16(8,0); put16(10,substitute.size()*2);
    put16(12,(substitute.size()+1)*2); put16(14,target.size()*2);
    std::memcpy(b.data()+16,substitute.c_str(),(substitute.size()+1)*2);
    std::memcpy(b.data()+16+(substitute.size()+1)*2,target.c_str(),(target.size()+1)*2);
    DWORD returned=0;
    CHECK(DeviceIoControl(f.h,FSCTL_SET_REPARSE_POINT,b.data(),static_cast<DWORD>(b.size()),nullptr,0,&returned,nullptr));
}
void PathsAndLeases()
{
    const auto directory=Case(L"paths"); const auto binding=Digest(42); const auto context=Context();
    auto w=ProtectedJournalEpoch::AcquireWriter(directory,binding); CHECK(w); const auto id=w.epoch->Id();
    auto sealed=w.epoch->Seal(context,{}); CHECK(sealed); w.epoch.reset(); const auto before=Files(directory);
    for(const auto& bad:std::vector<std::wstring>{L"relative",L"\\\\.\\PhysicalDrive0",L"\\\\server\\share",directory+L"\\..",directory+L":stream",directory+L"\\NUL",directory+L"\\trailing.",directory+L"\\"}) {
        auto fail=ProtectedJournalEpoch::AcquireWriter(bad,binding); CHECK(!fail); CHECK(fail.status.error==JournalError::UnsafePath);
        Rejected(ProtectedJournalEpoch::Open(bad,binding,context,sealed.bytes.Bytes()),JournalError::UnsafePath);
    }
    const auto target=Case(L"junction-target"); Write(target+L"\\untouched.bin",Bytes("UNCHANGED_TARGET_CANARY")); const auto targetBefore=Files(target);
    const auto link=root+L"\\junction"; Junction(link,target);
    auto denied=ProtectedJournalEpoch::AcquireWriter(link,binding); CHECK(!denied); CHECK(denied.status.error==JournalError::UnsafePath);
    Rejected(ProtectedJournalEpoch::Open(link,binding,context,sealed.bytes.Bytes()),JournalError::UnsafePath);
    const auto ancestor=link+L"\\child";
    denied=ProtectedJournalEpoch::AcquireWriter(ancestor,binding); CHECK(!denied); CHECK(denied.status.error==JournalError::UnsafePath);
    CHECK(Files(target)==targetBefore);
    const auto hard=Case(L"hard-link"); const auto original=Slot(directory,id); const auto alias=Slot(hard,id);
    { Pins a(directory),b(hard); CHECK(CreateHardLinkW(alias.c_str(),original.c_str(),nullptr)); }
    Rejected(ProtectedJournalEpoch::Open(hard,binding,context,sealed.bytes.Bytes()),JournalError::UnsafePath);
    // Lease aliases are also refused before any writable key slot is created.
    const auto lease=Case(L"lease-alias");
    { Pins a(directory),b(lease); CHECK(CreateHardLinkW((lease+L"\\writer.lease").c_str(),(directory+L"\\writer.lease").c_str(),nullptr)); }
    denied=ProtectedJournalEpoch::AcquireWriter(lease,binding); CHECK(!denied); CHECK(denied.status.error==JournalError::UnsafePath);
    // Read original artifacts via their pinned handles without single-link helper.
    CHECK(GetFileAttributesW(original.c_str())!=INVALID_FILE_ATTRIBUTES);
    CHECK(before.size()==2);
}
void BoundsAndCleanup()
{
    const auto directory=Case(L"bounds"); const auto binding=Digest(49); const auto context=Context();
    for(std::size_t n:{0,1,31,33}) {
        auto fail=ProtectedJournalEpoch::AcquireWriter(directory,std::vector<std::byte>(n)); CHECK(!fail); CHECK(fail.status.error==JournalError::InvalidArgument);
    }
    CHECK(!ProtectedJournalEpoch::AcquireWriter(directory,JournalDigest{})); CHECK(Files(directory).empty());
    auto w=ProtectedJournalEpoch::AcquireWriter(directory,binding); CHECK(w);
    auto bad=context; bad.purpose=0; Rejected(w.epoch->Seal(bad,{}),JournalError::InvalidArgument);
    bad=context; bad.operation={}; Rejected(w.epoch->Seal(bad,{}),JournalError::InvalidArgument);
    const std::vector<std::byte> large(kMaxJournalPlaintextBytes+1);
    Rejected(w.epoch->Seal(context,large),JournalError::ResourceLimit);
    crypto::testing::hooks.allocation_failure_at=crypto::testing::hooks.allocations;
    Rejected(w.epoch->Seal(context,std::span(large).first(kMaxJournalPlaintextBytes)),JournalError::CryptoFailure);
    crypto::testing::hooks.allocation_failure_at=-1;
    auto record=w.epoch->Seal(context,Bytes(plainCanary)); CHECK(record); w.epoch.reset();
    for(auto kind:{0,1}) {
        const int allocations=crypto::testing::hooks.allocations;
        if(kind==0) crypto::testing::hooks.allocation_failure_at=allocations;
        else crypto::testing::hooks.lock_failure_at=crypto::testing::hooks.locks;
        Rejected(ProtectedJournalEpoch::Open(directory,binding,context,record.bytes.Bytes()),JournalError::CryptoFailure);
        crypto::testing::hooks.allocation_failure_at=crypto::testing::hooks.lock_failure_at=-1;
    }
    jt::hooks.fault=jt::EpochFault::UnprotectAfter;
    Rejected(ProtectedJournalEpoch::Open(directory,binding,context,record.bytes.Bytes()),JournalError::ProtectionFailure);
    jt::hooks.fault=jt::EpochFault::None;
    auto good=ProtectedJournalEpoch::Open(directory,binding,context,record.bytes.Bytes()); CHECK(good);
}
void CanaryScan()
{
    const auto directory=Case(L"canaries"); const auto binding=Digest(57); const auto context=Context();
    jt::hooks.key_override={reinterpret_cast<const std::byte*>(keyCanary),32};
    auto w=ProtectedJournalEpoch::AcquireWriter(directory,binding); CHECK(w); jt::hooks.key_override={};
    const auto payload=Bytes(std::string(plainCanary)+"|"+metadataCanary);
    auto record=w.epoch->Seal(context,payload); CHECK(record);
    Write(directory+L"\\record.bin",record.bytes.Bytes()); w.epoch.reset();
    auto plain=ProtectedJournalEpoch::Open(directory,binding,context,Read(directory+L"\\record.bin")); CHECK(plain); CHECK(Copy(plain.bytes.Bytes())==payload);
    unsigned scanned=0, junctions=0;
    // Do not follow the deliberate private junction fixture during enumeration.
    fs::recursive_directory_iterator it(root),end;
    for(;it!=end;++it) {
        const auto attrs=GetFileAttributesW(it->path().c_str()); CHECK(attrs!=INVALID_FILE_ATTRIBUTES);
        if(attrs&FILE_ATTRIBUTE_REPARSE_POINT) { it.disable_recursion_pending(); ++junctions; continue; }
        if(!it->is_regular_file()) continue;
        // Hard-link fixtures are intentionally unsafe inputs. Read bytes through
        // the Win32 handle, retaining resolved-path checks but allowing >1 links.
        Pins parent(it->path().parent_path().wstring());
        File f(CreateFileW(it->path().c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
        CHECK(f.h!=INVALID_HANDLE_VALUE); BY_HANDLE_FILE_INFORMATION info{}; CHECK(GetFileInformationByHandle(f.h,&info));
        CHECK(Exact(f.h,it->path().wstring(),false,false));
        CHECK(!(info.dwFileAttributes&(FILE_ATTRIBUTE_REPARSE_POINT|FILE_ATTRIBUTE_DIRECTORY)));
        LARGE_INTEGER size{}; CHECK(GetFileSizeEx(f.h,&size)); CHECK(size.QuadPart>=0 && size.QuadPart<=2*1024*1024);
        std::vector<std::byte> bytes(static_cast<std::size_t>(size.QuadPart)); DWORD got=0;
        CHECK(ReadFile(f.h,bytes.data(),static_cast<DWORD>(bytes.size()),&got,nullptr)); CHECK(got==bytes.size());
        for(auto canary:{std::string_view(keyCanary),std::string_view(plainCanary),std::string_view(metadataCanary)}) {
            auto needle=Bytes(canary); CHECK(std::search(bytes.begin(),bytes.end(),needle.begin(),needle.end())==bytes.end());
            std::vector<std::byte> wide; for(char c:canary) {wide.push_back(static_cast<std::byte>(c));wide.push_back(std::byte{});}
            CHECK(std::search(bytes.begin(),bytes.end(),wide.begin(),wide.end())==bytes.end());
        }
        ++scanned;
    }
    CHECK(scanned>=30); CHECK(junctions==1);
    std::cout<<"SCAN "<<scanned<<" persistence files; raw/UTF-16 key, payload and path canaries absent; "<<junctions<<" reparse fixture excluded\n";
}
} // namespace

int wmain(int argc,wchar_t** argv)
{
    try {
        CHECK(argc==2); root=fs::path(argv[1]).make_preferred().wstring();
        CHECK(fs::path(root).is_absolute() && root.size()>3 && root[1]==L':' &&
            root[2]==L'\\' && GetDriveTypeW(root.substr(0,3).c_str())==DRIVE_FIXED);
        CHECK(!fs::exists(root));
        CHECK(root.find(L"..") == root.npos); NewDirectory(root);
        Group("actual current-user DPAPI, two fresh epochs, old-epoch and empty reads, exclusive lease",RoundTrips);
        Group("source binding, reconstructed purpose/operation/chunk and cross-record substitution",BindingAndContext);
        Group("every record byte/truncation, tag/header/length/trailing-data and resource refusal",RecordFrames);
        Group("missing slot, every key-slot byte/truncation, unknown framing and immutable collision",KeySlotFrames);
        Group("key-publication failure injection, no writer before flush/readback and old-slot preservation",PublicationFailures);
        Group("nonce burns across provider/allocation/lock failures, full 96-bit and per-key exhaustion",NonceFailuresAndExhaustion);
        Group("eight concurrent seal callers: 256 unique monotonic nonces and authenticated opens",ConcurrentNonces);
        Group("actual anonymous-user DPAPI refusal and same-user recovery without mutation",WrongUser);
        Group("local path policy, real directory junction, hard-link/lease alias and rename denial",PathsAndLeases);
        Group("argument/resource caps and secure/DPAPI cleanup on handled failures",BoundsAndCleanup);
        Group("persisted key/payload/path canary scan and authenticated canary recovery",CanaryScan);
        std::cout<<"PASS "<<groups<<" groups / "<<checks<<" assertions; "<<cases<<" private file cases\n";
        return 0;
    } catch(const std::exception& e) { (void)RevertToSelf(); std::cerr<<"FAIL "<<e.what()<<'\n'; return 1; }
}
