#include "WriteAheadLog.h"
#ifndef APFSACCESS_WAL_BASELINE_ONLY
#include "ProtectedJournalEpoch.h"
#include "ApfsCryptoTestHooks.h"
#endif
#include <windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <map>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <tuple>
#include <vector>

using Wal = apfsaccess::rw::WriteAheadLog;
namespace fs = std::filesystem;
namespace
{
unsigned checks=0, groups=0, cases=0;
fs::path root;
#define CHECK(x) do { ++checks; if(!(x)) throw std::runtime_error("line " + std::to_string(__LINE__) + ": " #x); } while(false)
bool LocalAbsolute(const fs::path& path)
{
    const auto s=path.wstring();
    if(s.size()<4||s.size()>220||!((s[0]>=L'A'&&s[0]<=L'Z')||(s[0]>=L'a'&&s[0]<=L'z'))||
        s[1]!=L':'||s[2]!=L'\\'||s.back()==L'\\'||s.find_first_of(L"/<>\"|?*")!=s.npos||s.find(L':',2)!=s.npos)return false;
    for(std::size_t begin=3;begin<s.size();){
        auto end=s.find(L'\\',begin);if(end==s.npos)end=s.size();const auto part=s.substr(begin,end-begin);
        if(part.empty()||part==L"."||part==L".."||part.back()==L'.'||part.back()==L' '||
            std::any_of(part.begin(),part.end(),[](wchar_t c){return c<32;}))return false;
        auto base=part.substr(0,part.find(L'.'));for(auto& c:base)if(c>=L'a'&&c<=L'z')c-=L'a'-L'A';
        if(base==L"CON"||base==L"PRN"||base==L"AUX"||base==L"NUL"||
            (base.size()==4&&(base.starts_with(L"COM")||base.starts_with(L"LPT"))&&base[3]>=L'1'&&base[3]<=L'9'))return false;
        begin=end+1;
    }
    return GetDriveTypeW(s.substr(0,3).c_str())==DRIVE_FIXED;
}
struct Handle
{
    HANDLE h=INVALID_HANDLE_VALUE;
    explicit Handle(HANDLE value):h(value){}
    ~Handle(){if(h!=INVALID_HANDLE_VALUE)CloseHandle(h);}
    Handle(const Handle&)=delete;
};
bool Exact(HANDLE h,const fs::path& path,bool directory,bool single=true)
{
    BY_HANDLE_FILE_INFORMATION i{};
    if(!GetFileInformationByHandle(h,&i)||(i.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT)||
        ((i.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)!=0)!=directory||(!directory&&single&&i.nNumberOfLinks!=1))return false;
    wchar_t resolved[1024]{}; auto n=GetFinalPathNameByHandleW(h,resolved,1024,FILE_NAME_NORMALIZED|VOLUME_NAME_DOS);
    return n&&n<1024&&CompareStringOrdinal(resolved,-1,(L"\\\\?\\"+path.wstring()).c_str(),-1,TRUE)==CSTR_EQUAL;
}
struct Pins
{
    std::vector<std::unique_ptr<Handle>> handles;
    explicit Pins(const fs::path& path)
    {
        auto s=path.wstring();CHECK(s.size()==3?GetDriveTypeW(s.c_str())==DRIVE_FIXED:LocalAbsolute(path));
        for(std::size_t end=2;;){
            auto p=s.substr(0,end==2?3:end);
            auto h=std::make_unique<Handle>(CreateFileW(p.c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ,nullptr,OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
            CHECK(h->h!=INVALID_HANDLE_VALUE); CHECK(Exact(h->h,p,true)); handles.push_back(std::move(h));
            if(end==s.size())break; end=s.find(L'\\',end+1); if(end==s.npos)end=s.size();
        }
    }
};
void Directory(const fs::path& path)
{
    CHECK(path==root||path.wstring().starts_with(root.wstring()+L"\\")); Pins p(path.parent_path());
    CHECK(CreateDirectoryW(path.c_str(),nullptr)); Pins verify(path);
}
fs::path Case(const wchar_t* label){auto p=root/(std::to_wstring(++cases)+L"-"+label);Directory(p);return p;}
std::vector<std::uint8_t> Read(const fs::path& path,bool single=true)
{
    Pins p(path.parent_path()); Handle h(CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,
        OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr)); CHECK(h.h!=INVALID_HANDLE_VALUE); CHECK(Exact(h.h,path,false,single));
    LARGE_INTEGER size{}; CHECK(GetFileSizeEx(h.h,&size)); CHECK(size.QuadPart>=0&&size.QuadPart<=(65ll<<20));
    std::vector<std::uint8_t>b(static_cast<std::size_t>(size.QuadPart)); DWORD got=0;
    CHECK(ReadFile(h.h,b.data(),static_cast<DWORD>(b.size()),&got,nullptr)); CHECK(got==b.size());return b;
}
void Write(const fs::path& path,std::span<const std::uint8_t>b,bool replace=false)
{
    CHECK(path.wstring().starts_with(root.wstring()+L"\\")); Pins p(path.parent_path());
    Handle h(CreateFileW(path.c_str(),GENERIC_READ|GENERIC_WRITE,0,nullptr,replace?OPEN_ALWAYS:CREATE_NEW,
        FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_WRITE_THROUGH,nullptr));CHECK(h.h!=INVALID_HANDLE_VALUE);CHECK(Exact(h.h,path,false));
    LARGE_INTEGER zero{};CHECK(SetFilePointerEx(h.h,zero,nullptr,FILE_BEGIN));CHECK(SetEndOfFile(h.h));DWORD written=0;
    CHECK(WriteFile(h.h,b.data(),static_cast<DWORD>(b.size()),&written,nullptr));CHECK(written==b.size());CHECK(FlushFileBuffers(h.h));
}
using Snapshot=std::map<std::wstring,std::vector<std::uint8_t>>;
Snapshot Files(const fs::path& path)
{
    Pins p(path); Snapshot s;
    for(const auto& f:fs::directory_iterator(path)){
        auto attr=GetFileAttributesW(f.path().c_str());CHECK(attr!=INVALID_FILE_ATTRIBUTES);CHECK(!(attr&FILE_ATTRIBUTE_REPARSE_POINT));
        if(f.is_regular_file())s.emplace(f.path().filename().wstring(),Read(f.path()));
    }return s;
}
std::uint32_t U32(std::span<const std::uint8_t>b,std::size_t p)
{std::uint32_t n=0;for(unsigned i=0;i<4;++i)n|=std::uint32_t(b[p+i])<<(8*i);return n;}
std::string Hash(std::span<const std::uint8_t>b)
{
    std::array<std::uint8_t,32>d{};CHECK(BCryptHash(BCRYPT_SHA256_ALG_HANDLE,nullptr,0,const_cast<PUCHAR>(b.data()),static_cast<ULONG>(b.size()),d.data(),32)>=0);
    constexpr char h[]="0123456789abcdef";std::string out;for(auto v:d){out+=h[v>>4];out+=h[v&15];}return out;
}
Wal::Record Record(std::uint64_t sequence)
{
    Wal::Record r;r.volume_identity="ordinary-gate-volume";r.transaction_id=10;r.sequence=sequence;r.object_id=42;r.parent_object_id=7;
    r.payload_spool_id=3;r.payload_offset=100;r.payload_length=12;r.logical_offset=4096;r.logical_length=12;r.flags=5;
    r.payload_sha256[0]=0xaa;r.path_utf8="\\docs\\file.bin";r.secondary_path_utf8="\\docs\\other.bin";return r;
}
Wal::Record Marker(std::uint64_t n,Wal::RecordState state)
{
    Wal::Record r;r.volume_identity="ordinary-gate-volume";r.transaction_id=10;r.sequence=n;
    r.operation=Wal::OperationKind::TransactionMarker;r.state=state;r.object_id=71;return r;
}
Wal::Options Ordinary(const fs::path& directory){return {directory/L"journal.wal","ordinary-gate-volume",4ull<<20};}
template<class F>void Group(const char* label,F f){f();++groups;std::cout<<"PASS "<<label<<std::endl;}
void OrdinaryCodec()
{
    static_assert(std::is_aggregate_v<Wal::Options>);
    auto p=Case(L"ordinary-codec"); auto o=Ordinary(p);std::vector<std::uint8_t> corpus;
    auto r=Record(1);auto v1=Wal::EncodeForTest(r);CHECK(U32(v1,0)==0x574c4141&&v1[4]==1&&v1[6]==148);
    auto r2=r;r2.sequence=2;r2.inline_payload={std::byte{1},std::byte{0},std::byte{3}};r2.payload_length=r2.logical_length=3;
    CHECK(BCryptHash(BCRYPT_SHA256_ALG_HANDLE,nullptr,0,reinterpret_cast<PUCHAR>(r2.inline_payload.data()),3,r2.payload_sha256.data(),32)>=0);
    auto v2=Wal::EncodeForTest(r2);CHECK(v2[4]==2&&v2[6]==152);
    auto r3=r;r3.sequence=3;r3.operation=Wal::OperationKind::Delete;r3.payload_spool_id=0;r3.payload_offset=r3.payload_length=r3.logical_offset=r3.logical_length=r3.flags=0;
    r3.parent_object_id=3;r3.payload_sha256={};r3.secondary_path_utf8.clear();r3.unlink_outcome=apfsaccess::rw::UnlinkOutcome{42,3,4,7,2,1,r3.path_utf8};
    auto v3=Wal::EncodeForTest(r3);CHECK(!v3.empty()&&v3[4]==3&&v3[6]==192);
    for(const auto* b:{&v1,&v2,&v3})corpus.insert(corpus.end(),b->begin(),b->end());
    Write(p/L"wire.bin",corpus);auto decoded=Wal::ReadAll(p/L"wire.bin",o.volume_identity);CHECK(decoded.status==Wal::ReadStatus::Ok);CHECK(decoded.records.size()==3);
    CHECK(decoded.records[1].inline_payload==r2.inline_payload);CHECK(decoded.records[2].unlink_outcome==r3.unlink_outcome);
    std::cout<<"ORDINARY_WIRE_SHA256 "<<Hash(corpus)<<std::endl;
}
void OrdinaryPersistence()
{
    auto p=Case(L"ordinary-persistence");auto o=Ordinary(p);
    {Wal w(o);CHECK(w.Append(Record(1),false));CHECK(w.AppendBatch({Record(2),Marker(3,Wal::RecordState::Accepted)},false));
        CHECK(w.SnapshotCounters().append_handle_flush_count==0);CHECK(w.FlushPendingAppends());CHECK(w.SnapshotCounters().append_handle_flush_count==1);
        CHECK(w.ValidatedAppendLeaseGeneration()!=0);CHECK(w.ReadAll().records.size()==3);}
    {Wal w(o);auto read=w.ReadAllWithExclusiveWriterLease();CHECK(read.status==Wal::ReadStatus::Ok&&read.records.size()==3);CHECK(w.Append(Record(4)));}
    auto read=Wal::ReadAll(o.path,o.volume_identity);CHECK(read.status==Wal::ReadStatus::Ok&&read.records.size()==4);
    CHECK(Wal::ReadAll(o.path,"wrong").status==Wal::ReadStatus::VolumeMismatch);
}
void OrdinaryTailAndLimits()
{
    auto p=Case(L"ordinary-tail");auto o=Ordinary(p);auto bytes=Wal::EncodeForTest(Record(1));auto tail=Wal::EncodeForTest(Record(2));
    bytes.insert(bytes.end(),tail.begin(),tail.end()-7);Write(o.path,bytes);
    auto read=Wal::ReadAll(o.path,o.volume_identity);CHECK(read.status==Wal::ReadStatus::Ok&&read.recovered_torn_tail&&read.records.size()==1);
    {Wal w(o);read=w.ReadAllWithExclusiveWriterLease();CHECK(read.status==Wal::ReadStatus::Ok&&read.recovered_torn_tail);CHECK(w.Append(Record(2)));}
    CHECK(Wal::ReadAll(o.path,o.volume_identity).records.size()==2);
    auto before=Read(o.path);auto capped=o;capped.max_bytes=before.size();{Wal w(capped);CHECK(w.AppendWithResult(Record(3))==Wal::AppendResult::RejectedBeforeWrite);}CHECK(Read(o.path)==before);
    before[12]^=1;Write(o.path,before,true);CHECK(Wal::ReadAll(o.path,o.volume_identity).status==Wal::ReadStatus::ChecksumMismatch);
}
void OrdinaryCompactionAndAmbiguity()
{
    auto p=Case(L"ordinary-maintenance");auto o=Ordinary(p);
    {Wal w(o);CHECK(w.AppendBatch({Record(1),Record(2),Marker(3,Wal::RecordState::Accepted)}));CHECK(w.Compact(2));
        auto r=w.ReadAll();CHECK(r.status==Wal::ReadStatus::Ok);CHECK(std::none_of(r.records.begin(),r.records.end(),[](const auto& x){return x.sequence<2;}));
        CHECK(std::any_of(r.records.begin(),r.records.end(),[](const auto& x){return x.operation==Wal::OperationKind::CompactionIndex;}));}
    auto q=Case(L"ordinary-flush");o=Ordinary(q);{Wal w(o);w.SetFaultInjectionHook([](auto stage){return stage=="durable-flush";});CHECK(w.AppendWithResult(Record(1))==Wal::AppendResult::BytesMayHavePersisted);}
    CHECK(Wal::ReadAll(o.path,o.volume_identity).records.size()==1);
}

#ifndef APFSACCESS_WAL_BASELINE_ONLY
namespace jc=apfsaccess::journal;
namespace jt=apfsaccess::journal::testing;
namespace cc=apfsaccess::crypto;
constexpr char payloadCanary[]="PROTECTED_WAL_PAYLOAD_CANARY_20261016";
constexpr char pathCanary[]="\\PRIVATE_WAL_PATH_CANARY\\classified-name.bin";
constexpr char secondaryCanary[]="\\PRIVATE_SECONDARY_METADATA_CANARY";
constexpr char keyCanary[]="APFS_KEY_CANARY_0123456789ABCDEF";
std::array<std::byte,32> Digest(unsigned n){std::array<std::byte,32>d{};for(std::size_t i=0;i<32;++i)d[i]=std::byte((n+13*i)&255);return d;}
Wal::Options Protected(const fs::path& p)
{
    Directory(p/L"keys");auto o=Ordinary(p);Wal::ProtectedPersistence a;
    a.key_directory=p/L"keys";a.source_binding=Digest(31);a.journal_identity=Digest(71);o.protected_persistence=a;return o;
}
Wal::Record PrivateRecord(std::uint64_t n)
{
    auto r=Record(n);r.path_utf8=pathCanary;r.secondary_path_utf8=secondaryCanary;
    auto b=std::as_bytes(std::span(payloadCanary,sizeof(payloadCanary)-1));r.inline_payload.assign(b.begin(),b.end());
    r.payload_length=r.logical_length=b.size();r.payload_spool_id=0;r.payload_offset=0;
    CHECK(BCryptHash(BCRYPT_SHA256_ALG_HANDLE,nullptr,0,reinterpret_cast<PUCHAR>(r.inline_payload.data()),static_cast<ULONG>(b.size()),r.payload_sha256.data(),32)>=0);return r;
}
std::vector<std::size_t> Frames(const std::vector<std::uint8_t>& b)
{
    CHECK(b.size()>=104&&b[0]==0xe4);std::vector<std::size_t> at;
    for(std::size_t p=16;p<b.size();){CHECK(b.size()-p>=80);auto n=U32(b,p+16);CHECK(n>=80&&n<=b.size()-p);at.push_back(p);p+=n;}return at;
}
void BadRead(Wal& w){auto r=w.ReadAll();CHECK(r.status!=Wal::ReadStatus::Ok);CHECK(r.records.empty());CHECK(!r.recovered_torn_tail);}
void ProtectedLifecycle()
{
    auto p=Case(L"protected-lifecycle");auto o=Protected(p);Snapshot oldKeys;std::vector<std::uint8_t> first;
    {Wal w(o);auto r=w.ReadAllWithExclusiveWriterLease();CHECK(r.status==Wal::ReadStatus::Ok&&r.records.empty());CHECK(w.HasExclusiveWriterLease());
        CHECK(!fs::exists(o.path)&&Files(o.protected_persistence->key_directory).empty());CHECK(w.ExclusiveWriterLeaseGeneration()!=0);
        CHECK(w.ReadStartupEvidence({4ull<<20,100},16ull<<20).status==Wal::ReadStatus::Ok);CHECK(!w.MaterializeAbsentStartupJournal());
        CHECK(!fs::exists(o.path)&&Files(o.protected_persistence->key_directory).empty());
        auto g=w.ExclusiveWriterLeaseGeneration();CHECK(w.AppendBatchWithResult({PrivateRecord(1),Marker(2,Wal::RecordState::Accepted)},true,g)==Wal::AppendResult::Succeeded);
        CHECK(w.ValidatedAppendLeaseGeneration()==g);CHECK(w.ReadAll().records.size()==2);CHECK(w.ReadStartupEvidence({4ull<<20,100},16ull<<20).records.size()==2);
        auto r3=Marker(3,Wal::RecordState::Checkpointed);CHECK(w.EvidenceAppendCapacityAvailable({r3},{4ull<<20,100},16ull<<20));
        r3.volume_identity.clear();CHECK(w.EvidenceAppendCapacityAvailable({r3},{4ull<<20,100},16ull<<20));
        first=Read(o.path);oldKeys=Files(o.protected_persistence->key_directory);CHECK(Frames(first).size()==3);}
    {Wal w(o);auto r=w.ReadAllWithExclusiveWriterLease();CHECK(r.status==Wal::ReadStatus::Ok&&r.records.size()==2);CHECK(r.records[0].path_utf8==pathCanary);
        CHECK(r.records[1].state==Wal::RecordState::Accepted&&r.records[1].object_id==71);CHECK(w.Append(Marker(3,Wal::RecordState::Checkpointed)));}
    auto second=Read(o.path);CHECK(std::equal(first.begin(),first.end(),second.begin()));auto frames=Frames(second);
    CHECK(!std::equal(second.begin()+frames[1]+24,second.begin()+frames[1]+40,second.begin()+frames.back()+24));
    for(const auto& [name,b]:oldKeys)CHECK(Read(o.protected_persistence->key_directory/name)==b);
    Wal reader(o);CHECK(reader.ReadAll().records.size()==3);
}
void AuthorityAndMixing()
{
    auto p=Case(L"protected-authority");auto o=Protected(p);{Wal w(o);CHECK(w.Append(PrivateRecord(1)));}
    auto before=Read(o.path);auto keys=Files(o.protected_persistence->key_directory);
    for(unsigned kind=0;kind<4;++kind){auto bad=o;if(kind==0)bad.protected_persistence->source_binding[0]^=std::byte{1};
        if(kind==1)bad.protected_persistence->journal_identity[0]^=std::byte{1};if(kind==2)bad.volume_identity+="-wrong";
        if(kind==3){Directory(p/L"empty-keys");bad.protected_persistence->key_directory=p/L"empty-keys";}
        Wal w(bad);BadRead(w);CHECK(w.AppendWithResult(PrivateRecord(2))==Wal::AppendResult::RejectedBeforeWrite);CHECK(Read(o.path)==before);}
    CHECK(Files(o.protected_persistence->key_directory)==keys);
    CHECK(Wal::ReadAll(o.path,o.volume_identity).status==Wal::ReadStatus::VersionMismatch);
    {Wal ordinary(Ordinary(p));CHECK(!ordinary.AcquireExclusiveWriterLease());CHECK(!ordinary.Append(Record(2)));CHECK(!ordinary.Compact(1));}CHECK(Read(o.path)==before);
    {Handle h(CreateFileW(o.path.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr));CHECK(h.h!=INVALID_HANDLE_VALUE);
        auto r=Wal::ReadAllEvidenceFromHeldHandle(h.h,o.volume_identity,{4ull<<20,100},16ull<<20);CHECK(r.status!=Wal::ReadStatus::Ok&&r.records.empty());}
    auto q=Case(L"protected-reject-ordinary");auto legacy=Protected(q);{Wal w(Ordinary(q));CHECK(w.Append(Record(1)));}auto raw=Read(legacy.path);
    {Wal w(legacy);BadRead(w);CHECK(!w.Append(Record(2)));}CHECK(Read(legacy.path)==raw);CHECK(Files(legacy.protected_persistence->key_directory).empty());
    auto mixed=before;auto marker=Wal::EncodeForTest(Marker(2,Wal::RecordState::Accepted));mixed.insert(mixed.end(),marker.begin(),marker.end());Write(o.path,mixed,true);
    {Wal w(o);BadRead(w);CHECK(!w.Append(PrivateRecord(3)));}CHECK(Read(o.path)==mixed);
}
void ConfigurationAndMaintenance()
{
    auto p=Case(L"protected-config");auto o=Protected(p);
    for(unsigned k=0;k<10;++k){auto bad=o;auto& a=*bad.protected_persistence;
        if(k==0)a.source_binding={};if(k==1)a.journal_identity={};if(k==2)a.key_directory=L"relative";
        if(k==3)a.key_directory=p;if(k==4)a.key_directory=p/L"missing";if(k==5)bad.max_bytes=0;
        if(k==6)a.read_limits.bytes=UINT64_MAX;if(k==7)a.read_limits.records=SIZE_MAX;if(k==8)a.max_allocation_bytes=0;if(k==9)bad.path=p/L".."/L"escape.wal";
        Wal w(bad);CHECK(!w.AcquireWriterLeaseOnly());CHECK(!w.AcquireExclusiveWriterLease());CHECK(!w.Append(PrivateRecord(1)));BadRead(w);
        CHECK(w.CompactWithResult(0)==Wal::CompactionResult::RejectedBeforeWrite);CHECK(!fs::exists(o.path));CHECK(Files(o.protected_persistence->key_directory).empty());}
    {Wal w(o);CHECK(w.Append(PrivateRecord(1)));}auto canonical=Read(o.path);auto keys=Files(o.protected_persistence->key_directory);
    const std::vector<std::uint8_t> evidence{9,8,7};
    for(const auto* suffix:{L".compact.intent",L".compact.1.2",L".compact.predecessor.1",L".compact.intent.tmp.1.2",L".compact.unknown"}){
        auto q=Case(L"protected-maintenance");auto bad=o;bad.path=q/L"journal.wal";Write(bad.path,canonical);Write(fs::path(bad.path.wstring()+suffix),evidence);
        auto saved=Files(q);Wal w(bad);std::string error;CHECK(!w.AcquireExistingRepairLease(error));CHECK(!w.AcquireExclusiveWriterLease());
        CHECK(!w.Append(PrivateRecord(2)));CHECK(w.CompactWithResult(1)==Wal::CompactionResult::RejectedBeforeWrite);CHECK(!w.MaterializeAbsentStartupJournal());
        CHECK(w.ReadStartupEvidence({4ull<<20,100},16ull<<20).status!=Wal::ReadStatus::Ok);CHECK(Files(q)==saved);CHECK(Files(o.protected_persistence->key_directory)==keys);}
}
void CorruptionAndPosition()
{
    auto p=Case(L"protected-framing-source");auto o=Protected(p);{Wal w(o);CHECK(w.AppendBatch({PrivateRecord(1),PrivateRecord(2),Marker(3,Wal::RecordState::Accepted)}));}
    auto original=Read(o.path);auto positions=Frames(original);auto q=Case(L"protected-framing-mutant");auto bad=o;bad.path=q/L"journal.wal";
    const auto reject=[&](std::span<const std::uint8_t> b){Write(bad.path,b,fs::exists(bad.path));
        {Wal w(bad);BadRead(w);auto read=w.ReadAllWithExclusiveWriterLease();CHECK(read.status!=Wal::ReadStatus::Ok&&read.records.empty());
            CHECK(w.AppendWithResult(PrivateRecord(4))==Wal::AppendResult::RejectedBeforeWrite);CHECK(!w.Compact(1));}CHECK(Read(bad.path)==std::vector<std::uint8_t>(b.begin(),b.end()));};
    for(std::size_t n=1;n<=16;++n){
        const auto prefix=std::span(original).first(n);Write(bad.path,prefix,fs::exists(bad.path));
        CHECK(Wal::ReadAll(bad.path,o.volume_identity).status!=Wal::ReadStatus::Ok);
        {Wal legacy(Ordinary(q));CHECK(!legacy.AcquireExclusiveWriterLease());CHECK(!legacy.Append(Record(4)));}
        CHECK(Read(bad.path)==std::vector<std::uint8_t>(prefix.begin(),prefix.end()));
    }
    for(std::size_t n=0;n<original.size();++n){
        // Removing whole authenticated suffix records is prefix rollback, which
        // needs external head authority. Partial frames always fail closed.
        if(n==104||std::find(positions.begin()+1,positions.end(),n)!=positions.end())continue;
        reject(std::span(original).first(n));
    }
    for(std::size_t i=0;i<original.size();++i){auto b=original;b[i]^=1;reject(b);}
    auto swapped=original;auto a=positions[1],b=positions[2],c=positions[3];CHECK(b-a==c-b);
    std::swap_ranges(swapped.begin()+a,swapped.begin()+b,swapped.begin()+b);reject(swapped);
    auto duplicate=original;duplicate.insert(duplicate.end(),original.begin()+positions[1],original.begin()+positions[2]);reject(duplicate);
    auto prefix=std::vector<std::uint8_t>(original.begin(),original.begin()+positions.back());Write(bad.path,prefix,true);
    {Wal w(bad);auto r=w.ReadAll();CHECK(r.status==Wal::ReadStatus::Ok&&r.records.size()==2);
        CHECK(std::none_of(r.records.begin(),r.records.end(),[](const auto& r){return r.state==Wal::RecordState::Accepted;}));}
    CHECK(Read(o.path)==original);
}
void KeyAndPublicationFailures()
{
    auto p=Case(L"protected-key-source");auto o=Protected(p);{Wal w(o);CHECK(w.Append(PrivateRecord(1)));}auto canonical=Read(o.path);auto saved=Files(o.protected_persistence->key_directory);
    for(auto kind:{0,1}){auto q=Case(L"protected-bad-key");auto bad=o;Directory(q/L"keys");bad.protected_persistence->key_directory=q/L"keys";
        if(kind==1)for(const auto& [name,blob]:saved){auto b=blob;if(name.ends_with(L".key"))b.back()^=1;Write(q/L"keys"/name,b);}
        auto before=Files(q/L"keys");{Wal w(bad);BadRead(w);CHECK(!w.Append(PrivateRecord(2)));}CHECK(Files(q/L"keys")==before);CHECK(Read(o.path)==canonical);}
    for(auto fault:{jt::EpochFault::ProtectAfter,jt::EpochFault::SlotWrite,jt::EpochFault::SlotFlush,jt::EpochFault::SlotReadback,jt::EpochFault::AfterPublication}){
        auto q=Case(L"protected-key-publication");auto a=Protected(q);jt::hooks={};jt::hooks.fault=fault;
        {Wal w(a);CHECK(w.AppendWithResult(PrivateRecord(1))==Wal::AppendResult::RejectedBeforeWrite);CHECK(jt::hooks.triggered);CHECK(!fs::exists(a.path));}
        auto orphans=Files(a.protected_persistence->key_directory);jt::hooks.fault=jt::EpochFault::None;
        {Wal w(a);CHECK(w.Append(PrivateRecord(1)));CHECK(w.ReadAll().records.size()==1);}for(const auto& [name,b]:orphans)CHECK(Read(a.protected_persistence->key_directory/name)==b);
        CHECK(jt::hooks.dpapi_released_zero);}
}
void FailureResultsAndNonce()
{
    auto fresh=Case(L"protected-anchor-provider-retry");auto freshOptions=Protected(fresh);
    {Wal w(freshOptions);cc::testing::hooks.cng_failure_at=cc::testing::hooks.cng_calls+4;cc::testing::hooks.cng_fail_after_call=true;
        CHECK(w.AppendWithResult(PrivateRecord(1))==Wal::AppendResult::RejectedBeforeWrite);cc::testing::hooks.cng_failure_at=-1;
        CHECK(!fs::exists(freshOptions.path));auto keys=Files(freshOptions.protected_persistence->key_directory);CHECK(!keys.empty());
        CHECK(w.Append(PrivateRecord(1)));CHECK(Files(freshOptions.protected_persistence->key_directory)==keys);
        auto bytes=Read(freshOptions.path);auto at=Frames(bytes);CHECK(at.size()==2&&bytes[at[0]+51]==1&&bytes[at[1]+51]==2);}
    auto p=Case(L"protected-failure");auto o=Protected(p);
    {Wal w(o);CHECK(w.Append(PrivateRecord(1)));auto before=Read(o.path);
        w.SetFaultInjectionHook([](auto stage){return stage=="protected-before-write";});CHECK(w.AppendWithResult(PrivateRecord(2))==Wal::AppendResult::RejectedBeforeWrite);CHECK(Read(o.path)==before);
        w.SetFaultInjectionHook({});cc::testing::hooks.cng_failure_at=cc::testing::hooks.cng_calls+4;cc::testing::hooks.cng_fail_after_call=true;
        CHECK(w.AppendWithResult(PrivateRecord(2))==Wal::AppendResult::RejectedBeforeWrite);CHECK(Read(o.path)==before);cc::testing::hooks.cng_failure_at=-1;
        CHECK(w.Append(PrivateRecord(2)));auto after=Read(o.path);auto pos=Frames(after);CHECK(after[pos.back()+51]==4); // anchor0, record1, failures2/3, record4.
        w.SetFaultInjectionHook([](auto stage){return stage=="protected-partial-write";});CHECK(w.AppendWithResult(Marker(3,Wal::RecordState::Accepted))==Wal::AppendResult::BytesMayHavePersisted);
        auto torn=Read(o.path);CHECK(torn.size()==after.size()+13);CHECK(!w.Append(PrivateRecord(4)));CHECK(!w.FlushPendingAppends());BadRead(w);CHECK(Read(o.path)==torn);}
    {Wal w(o);BadRead(w);CHECK(!w.Append(PrivateRecord(4)));}
    auto q=Case(L"protected-flush-ambiguous");auto a=Protected(q);{Wal w(a);CHECK(w.Append(PrivateRecord(1)));
        w.SetFaultInjectionHook([](auto stage){return stage=="durable-flush";});CHECK(w.AppendWithResult(Marker(2,Wal::RecordState::Accepted))==Wal::AppendResult::BytesMayHavePersisted);
        CHECK(!w.Append(PrivateRecord(3)));}
    {Wal w(a);auto r=w.ReadAllWithExclusiveWriterLease();CHECK(r.status==Wal::ReadStatus::Ok&&r.records.size()==2);CHECK(w.Append(Marker(3,Wal::RecordState::Checkpointed)));}
}
void LeasesAndBudgets()
{
    auto p=Case(L"protected-leases");auto o=Protected(p);
    {Wal first(o);CHECK(first.ReadAllWithExclusiveWriterLease().status==Wal::ReadStatus::Ok);Wal second(o);CHECK(!second.AcquireExclusiveWriterLease());
        CHECK(!second.Append(PrivateRecord(1)));CHECK(!fs::exists(o.path));CHECK(first.Append(PrivateRecord(1)));CHECK(!second.Append(PrivateRecord(2)));
        CHECK(first.AppendWithResult(PrivateRecord(2),true,first.ExclusiveWriterLeaseGeneration()+1)==Wal::AppendResult::RejectedBeforeWrite);
        auto r=first.ReadStartupEvidence({1,1},1024);CHECK(r.status==Wal::ReadStatus::ResourceLimit&&r.records.empty());}
    auto before=Read(o.path);{auto a=o;a.max_bytes=before.size();Wal w(a);CHECK(!w.Append(PrivateRecord(2)));}CHECK(Read(o.path)==before);
    auto q=Case(L"protected-hard-link");{Pins a(p),b(q);CHECK(CreateHardLinkW((q/L"alias.wal").c_str(),o.path.c_str(),nullptr));}
    {Wal w(o);BadRead(w);CHECK(!w.Append(PrivateRecord(2)));}CHECK(Read(o.path,false)==before);
    auto resource=Case(L"protected-resource-admission");auto bounded=Protected(resource);Wal w(bounded);
    cc::testing::hooks.lock_failure_at=cc::testing::hooks.locks;
    CHECK(w.AppendWithResult(PrivateRecord(1))==Wal::AppendResult::RejectedBeforeWrite);cc::testing::hooks.lock_failure_at=-1;
    CHECK(!fs::exists(bounded.path)&&Files(bounded.protected_persistence->key_directory).empty());
    auto large=PrivateRecord(1);large.inline_payload.resize(jc::kMaxJournalPlaintextBytes,std::byte{0x37});large.payload_length=large.logical_length=large.inline_payload.size();
    CHECK(BCryptHash(BCRYPT_SHA256_ALG_HANDLE,nullptr,0,reinterpret_cast<PUCHAR>(large.inline_payload.data()),static_cast<ULONG>(large.inline_payload.size()),large.payload_sha256.data(),32)>=0);
    CHECK(w.AppendWithResult(large)==Wal::AppendResult::RejectedBeforeWrite);
    CHECK(!fs::exists(bounded.path)&&Files(bounded.protected_persistence->key_directory).empty());CHECK(w.Append(PrivateRecord(1)));
}
void CanaryScan()
{
    auto p=Case(L"protected-canary");auto o=Protected(p);jt::hooks={};jt::hooks.key_override=std::as_bytes(std::span(keyCanary,sizeof(keyCanary)-1));
    {Wal w(o);CHECK(w.AppendBatch({PrivateRecord(1),Marker(2,Wal::RecordState::Accepted)}));CHECK(w.Append(Marker(3,Wal::RecordState::Checkpointed)));}jt::hooks.key_override={};
    unsigned scanned=0;
    // Scan only component-generated protected files; ordinary controls intentionally
    // persist plaintext, and corruption tests deliberately supply untrusted input.
    for(const auto& file:std::vector<fs::path>{o.path}){
        auto bytes=Read(file);for(auto text:{std::string_view(pathCanary),std::string_view(secondaryCanary),std::string_view(payloadCanary),std::string_view(keyCanary),std::string_view(o.volume_identity)}){
            CHECK(std::search(bytes.begin(),bytes.end(),text.begin(),text.end())==bytes.end());
            std::vector<std::uint8_t> wide;for(unsigned char c:text){wide.push_back(c);wide.push_back(0);}CHECK(std::search(bytes.begin(),bytes.end(),wide.begin(),wide.end())==bytes.end());}++scanned;}
    for(const auto& [name,b]:Files(o.protected_persistence->key_directory)){
        (void)name;for(auto text:{std::string_view(pathCanary),std::string_view(secondaryCanary),std::string_view(payloadCanary),std::string_view(keyCanary),std::string_view(o.volume_identity)}){
            CHECK(std::search(b.begin(),b.end(),text.begin(),text.end())==b.end());
            std::vector<std::uint8_t> wide;for(unsigned char c:text){wide.push_back(c);wide.push_back(0);}CHECK(std::search(b.begin(),b.end(),wide.begin(),wide.end())==b.end());}++scanned;}
    Wal reader(o);auto r=reader.ReadAll();CHECK(r.status==Wal::ReadStatus::Ok&&r.records.size()==3);CHECK(r.records.front().path_utf8==pathCanary);
    CHECK(jt::hooks.dpapi_released_zero);CHECK(cc::testing::hooks.all_released_bytes_zero);
    std::cout<<"SCAN "<<scanned<<" protected persistence artifacts; key/path/payload/volume canaries absent"<<std::endl;
}
bool SameRecord(const Wal::Record& a,const Wal::Record& b)
{
    const auto fields=[](const auto& r){return std::tie(r.volume_identity,r.transaction_id,r.sequence,r.operation,r.state,r.object_id,r.parent_object_id,
        r.payload_spool_id,r.payload_offset,r.payload_length,r.logical_offset,r.logical_length,r.flags,r.payload_sha256,r.inline_payload,r.path_utf8,r.secondary_path_utf8,r.unlink_outcome);};
    return fields(a)==fields(b);
}
Wal::ProtectedHistoryHead Head(Wal& w){Wal::ProtectedHistoryHead h;CHECK(w.CaptureProtectedHistoryHead(h));return h;}
void ExactRecords(Wal& w,const std::vector<Wal::Record>& expected)
{
    auto r=w.ReadAll();CHECK(r.status==Wal::ReadStatus::Ok&&!r.recovered_torn_tail&&r.records.size()==expected.size());
    for(std::size_t i=0;i<expected.size();++i)CHECK(SameRecord(r.records[i],expected[i]));
}
std::vector<Wal::Record> MaintenanceRecords()
{
    std::vector<Wal::Record> records;
    for(std::uint64_t n=1;n<=12;++n){auto r=PrivateRecord(n);r.transaction_id=n;records.push_back(r);}
    records[0].transaction_id=1;
    records[1].transaction_id=records[2].transaction_id=2;records[1].inline_payload.clear();records[1].payload_spool_id=73;records[1].payload_offset=900;
    records[3]=Marker(4,Wal::RecordState::Accepted);records[3].transaction_id=2;
    auto& unlink=records[4];unlink.transaction_id=3;unlink.operation=Wal::OperationKind::Delete;unlink.object_id=42;unlink.parent_object_id=3;
    unlink.payload_spool_id=unlink.payload_offset=unlink.payload_length=unlink.logical_offset=unlink.logical_length=unlink.flags=0;
    unlink.inline_payload.clear();unlink.payload_sha256={};unlink.secondary_path_utf8.clear();unlink.unlink_outcome=apfsaccess::rw::UnlinkOutcome{42,3,4,7,2,1,unlink.path_utf8};
    records[5]=Marker(6,Wal::RecordState::PublishArmed);records[5].transaction_id=3;
    records[6]=Marker(7,Wal::RecordState::Cleaned);records[6].transaction_id=0;records[6].operation=Wal::OperationKind::DurabilityWatermark;
    records[6].object_id=123;records[6].parent_object_id=120;records[6].flags=17;
    records[7].transaction_id=4;records[8]=Marker(9,Wal::RecordState::Checkpointed);records[8].transaction_id=4;
    records[9].transaction_id=30;records[10].transaction_id=5;records[11].transaction_id=6;
    return records;
}
void AppendRecords(Wal& w,const std::vector<Wal::Record>& r)
{
    const auto middle=(std::min)(r.size(),std::size_t{7});CHECK(w.AppendBatch({r.begin(),r.begin()+middle}));
    if(middle<r.size())CHECK(w.AppendBatch({r.begin()+middle,r.end()}));
}
fs::path Side(const fs::path& path,const wchar_t* suffix){return fs::path(path.wstring()+suffix);}
fs::path Archive(const fs::path& path,const Wal::ProtectedHistoryHead& h)
{
    constexpr wchar_t hex[]=L"0123456789abcdef";auto s=path.wstring()+L".pcold.";
    for(auto b:h.sha256){s+=hex[b>>4];s+=hex[b&15];}return fs::path(s);
}
void MaintenanceLifecycle()
{
    auto p=Case(L"maintenance-life");auto o=Protected(p);auto all=MaintenanceRecords();auto retained=all;retained.erase(retained.begin());
    Wal::ProtectedHistoryHead first,second,third;Snapshot keys;std::vector<std::uint8_t> original;
    {Wal w(o);AppendRecords(w,all);first=Head(w);keys=Files(o.protected_persistence->key_directory);original=Read(o.path);
        auto before=Files(p);Wal::ProtectedHistoryHead output;auto wrong=first;wrong.sha256[0]^=1;
        CHECK(w.CompactProtectedWithResult(8,wrong,output)==Wal::CompactionResult::RejectedBeforeWrite);CHECK(Files(p)==before);
        CHECK(w.CompactProtectedWithResult(8,first,output,w.ExclusiveWriterLeaseGeneration()+1)==Wal::CompactionResult::RejectedBeforeWrite);CHECK(Files(p)==before);
        CHECK(w.CompactProtectedWithResult(8,first,second,w.ExclusiveWriterLeaseGeneration())==Wal::CompactionResult::Succeeded);
        CHECK(Head(w)==second&&second.records==11&&second.last_sequence==12&&second.bytes<first.bytes);ExactRecords(w,retained);
        CHECK(Read(Archive(o.path,first))==original);CHECK(w.ReadAllAtProtectedHead(first).status!=Wal::ReadStatus::Ok);
        CHECK(!w.Append(PrivateRecord(13)));
        CHECK(w.ReadAllAtProtectedHead(second).records.size()==11);CHECK(w.CompactWithResult(8)==Wal::CompactionResult::RejectedBeforeWrite);
        CHECK(w.CompactProtectedWithResult(13,second,third)==Wal::CompactionResult::Succeeded);retained.erase(retained.begin()+9);ExactRecords(w,retained);
        CHECK(third.records==10&&Head(w)==third);for(const auto& [name,b]:keys)CHECK(Read(o.protected_persistence->key_directory/name)==b);}
    {Wal w(o);ExactRecords(w,retained);CHECK(w.ReadAllAtProtectedHead(third).records.size()==10);
        Wal::ProtectedHistoryHead recovered;CHECK(w.RecoverProtectedCompaction(second,13,Wal::ProtectedRecoveryChoice::PromoteReplacement,recovered)==Wal::CompactionResult::Succeeded);CHECK(recovered==third);
        auto marker=Marker(13,Wal::RecordState::Accepted);marker.transaction_id=40;CHECK(w.Append(marker));retained.push_back(marker);ExactRecords(w,retained);}
    {Wal w(o);ExactRecords(w,retained);CHECK(Head(w).last_sequence==13);}
    auto empty=Case(L"maintenance-empty");auto e=Protected(empty);
    {Wal w(e);auto r=PrivateRecord(1);CHECK(w.Append(r));auto h=Head(w);Wal::ProtectedHistoryHead next;
        CHECK(w.CompactProtectedWithResult(2,h,next)==Wal::CompactionResult::Succeeded);ExactRecords(w,{r});}
}
void MaintenanceCuts()
{
    const std::vector<std::string> stages={"pcompact-before-create","pcompact-after-create","pcompact-partial-write","pcompact-after-write","pcompact-flush",
        "pcompact-after-flush","pcompact-after-readback","pcompact-before-old-rename","pcompact-after-old-rename","pcompact-old-flush",
        "pcompact-before-new-rename","pcompact-after-new-rename","pcompact-new-flush","pcompact-before-archive","pcompact-after-archive","pcompact-archive-flush","pcompact-before-reopen"};
    for(const auto& stage:stages){auto p=Case(L"maintenance-cut");auto o=Protected(p);auto all=MaintenanceRecords();auto kept=all;kept.erase(kept.begin());
        Wal::ProtectedHistoryHead h,out;bool triggered=false;auto before=std::vector<std::uint8_t>{};Snapshot keys;
        {Wal w(o);AppendRecords(w,all);h=Head(w);before=Read(o.path);keys=Files(o.protected_persistence->key_directory);
            w.SetFaultInjectionHook([&](auto s){if(s!=stage)return false;triggered=true;return true;});auto result=w.CompactProtectedWithResult(8,h,out);
            CHECK(triggered);CHECK(result==(stage=="pcompact-before-create"?Wal::CompactionResult::RejectedBeforeWrite:Wal::CompactionResult::BytesMayHavePersisted));}
        {Wal w(o);
            if(stage=="pcompact-before-create"){CHECK(Read(o.path)==before);CHECK(w.CompactProtectedWithResult(8,h,out)==Wal::CompactionResult::Succeeded);ExactRecords(w,kept);}
            else if(stage=="pcompact-after-create"||stage=="pcompact-partial-write"){
                auto snapshot=Files(p);CHECK(w.RecoverProtectedCompaction(h,8,Wal::ProtectedRecoveryChoice::PromoteReplacement,out)==Wal::CompactionResult::RejectedBeforeWrite);CHECK(Files(p)==snapshot);
                CHECK(w.RecoverProtectedCompaction(h,8,Wal::ProtectedRecoveryChoice::RetainOriginal,out)==Wal::CompactionResult::Succeeded);CHECK(out==h);ExactRecords(w,all);CHECK(Read(o.path)==before);
                CHECK(w.CompactProtectedWithResult(8,h,out)==Wal::CompactionResult::Succeeded);ExactRecords(w,kept);}
            else {CHECK(w.RecoverProtectedCompaction(h,8,Wal::ProtectedRecoveryChoice::PromoteReplacement,out)==Wal::CompactionResult::Succeeded);ExactRecords(w,kept);}
            for(const auto& [name,b]:keys)CHECK(Read(o.protected_persistence->key_directory/name)==b);
            CHECK(!fs::exists(Side(o.path,L".compact.pnext"))&&!fs::exists(Side(o.path,L".compact.pold")));
            auto marker=Marker(13,Wal::RecordState::Checkpointed);CHECK(w.Append(marker));}
        {Wal w(o);auto r=w.ReadAll();CHECK(r.status==Wal::ReadStatus::Ok&&r.records.back().sequence==13);}
    }
}
void MaintenanceRetainAndRefusals()
{
    for(auto stage:{"pcompact-after-readback","pcompact-after-old-rename","pcompact-before-new-rename","pcompact-after-new-rename"}){
        auto p=Case(L"maintenance-retain");auto o=Protected(p);auto all=MaintenanceRecords();Wal::ProtectedHistoryHead h,out;
        {Wal w(o);AppendRecords(w,all);h=Head(w);w.SetFaultInjectionHook([&](auto s){return s==stage;});CHECK(w.CompactProtectedWithResult(8,h,out)==Wal::CompactionResult::BytesMayHavePersisted);}
        {Wal w(o);auto saved=Files(p);auto result=w.RecoverProtectedCompaction(h,8,Wal::ProtectedRecoveryChoice::RetainOriginal,out);
            if(std::string_view(stage)=="pcompact-after-new-rename"){CHECK(result==Wal::CompactionResult::RejectedBeforeWrite);CHECK(Files(p)==saved);
                CHECK(w.RecoverProtectedCompaction(h,8,Wal::ProtectedRecoveryChoice::PromoteReplacement,out)==Wal::CompactionResult::Succeeded);}
            else{CHECK(result==Wal::CompactionResult::Succeeded&&out==h);ExactRecords(w,all);CHECK(w.CompactProtectedWithResult(8,h,out)==Wal::CompactionResult::Succeeded);}}
    }
    auto p=Case(L"maintenance-corrupt");auto o=Protected(p);auto all=MaintenanceRecords();Wal::ProtectedHistoryHead h,out;
    {Wal w(o);AppendRecords(w,all);h=Head(w);w.SetFaultInjectionHook([](auto s){return s=="pcompact-after-readback";});CHECK(w.CompactProtectedWithResult(8,h,out)==Wal::CompactionResult::BytesMayHavePersisted);}
    auto pending=Side(o.path,L".compact.pnext");auto b=Read(pending);b.back()^=1;Write(pending,b,true);auto saved=Files(p);auto keys=Files(o.protected_persistence->key_directory);
    {Wal w(o);CHECK(w.RecoverProtectedCompaction(h,8,Wal::ProtectedRecoveryChoice::PromoteReplacement,out)==Wal::CompactionResult::RejectedBeforeWrite);CHECK(Files(p)==saved);}
    for(unsigned k=0;k<3;++k){auto bad=o;auto head=h;if(k==0)bad.protected_persistence->source_binding[0]^=std::byte{1};if(k==1)bad.protected_persistence->journal_identity[0]^=std::byte{1};if(k==2)head.sha256[0]^=1;
        Wal w(bad);CHECK(w.RecoverProtectedCompaction(head,8,Wal::ProtectedRecoveryChoice::RetainOriginal,out)==Wal::CompactionResult::RejectedBeforeWrite);CHECK(Files(p)==saved);CHECK(Files(o.protected_persistence->key_directory)==keys);}
    {Wal w(o);CHECK(w.RecoverProtectedCompaction(h,8,Wal::ProtectedRecoveryChoice::RetainOriginal,out)==Wal::CompactionResult::Succeeded);ExactRecords(w,all);}
}
void MaintenanceNoReplaceAndRollback()
{
    auto all=MaintenanceRecords();
    for(unsigned conflict=0;conflict<3;++conflict){auto p=Case(L"maintenance-conflict");auto o=Protected(p);Wal w(o);AppendRecords(w,all);auto h=Head(w);auto original=Read(o.path);Wal::ProtectedHistoryHead out;
        const std::vector<std::uint8_t> occupied{0x65,0x11,0x37};
        if(conflict==0){Write(Archive(o.path,h),occupied);auto saved=Files(p);CHECK(w.CompactProtectedWithResult(8,h,out)==Wal::CompactionResult::RejectedBeforeWrite);CHECK(Files(p)==saved);}
        else{bool inserted=false;w.SetFaultInjectionHook([&](auto stage){if(!inserted&&stage==(conflict==1?"pcompact-before-old-rename":"pcompact-before-new-rename")){
                    Write(conflict==1?Side(o.path,L".compact.pold"):o.path,occupied);inserted=true;}return false;});
            CHECK(w.CompactProtectedWithResult(8,h,out)==Wal::CompactionResult::BytesMayHavePersisted);CHECK(inserted);
            CHECK(Read(conflict==1?Side(o.path,L".compact.pold"):o.path)==occupied);
            CHECK(Read(conflict==1?o.path:Side(o.path,L".compact.pold"))==original);
            auto saved=Files(p);w.SetFaultInjectionHook({});CHECK(w.RecoverProtectedCompaction(h,8,Wal::ProtectedRecoveryChoice::PromoteReplacement,out)==Wal::CompactionResult::RejectedBeforeWrite);CHECK(Files(p)==saved);}
    }
    auto p=Case(L"maintenance-rollback");auto o=Protected(p);Wal::ProtectedHistoryHead before,after;std::vector<std::uint8_t> old;
    {Wal w(o);AppendRecords(w,all);before=Head(w);old=Read(o.path);CHECK(w.CompactProtectedWithResult(8,before,after)==Wal::CompactionResult::Succeeded);}
    Write(o.path,old,true);auto saved=Files(p);
    {Wal w(o);CHECK(w.ReadAllAtProtectedHead(after).status!=Wal::ReadStatus::Ok);CHECK(w.ReadAllAtProtectedHead(before).records.size()==all.size());CHECK(Files(p)==saved);}
    auto q=Case(L"maintenance-missing");auto missing=o;missing.path=q/L"journal.wal";Write(Archive(missing.path,before),old);
    {Wal w(missing);BadRead(w);CHECK(!w.Append(PrivateRecord(20)));CHECK(!fs::exists(missing.path));}
}
void MaintenanceRecoveryCutsAndKeys()
{
    for(auto stage:{"pcompact-before-quarantine","pcompact-after-quarantine","pcompact-before-restore","pcompact-after-restore"}){
        auto p=Case(L"maintenance-recovery-cut");auto o=Protected(p);auto records=MaintenanceRecords();Wal::ProtectedHistoryHead h,out;
        {Wal w(o);AppendRecords(w,records);h=Head(w);w.SetFaultInjectionHook([](auto s){return s=="pcompact-after-old-rename";});
            CHECK(w.CompactProtectedWithResult(8,h,out)==Wal::CompactionResult::BytesMayHavePersisted);}
        {Wal w(o);bool hit=false;w.SetFaultInjectionHook([&](auto s){if(s!=stage)return false;hit=true;return true;});
            const auto result=w.RecoverProtectedCompaction(h,8,Wal::ProtectedRecoveryChoice::RetainOriginal,out);CHECK(hit);
            CHECK(result==(std::string_view(stage)=="pcompact-before-quarantine"?Wal::CompactionResult::RejectedBeforeWrite:Wal::CompactionResult::BytesMayHavePersisted));}
        {Wal w(o);CHECK(w.RecoverProtectedCompaction(h,8,Wal::ProtectedRecoveryChoice::RetainOriginal,out)==Wal::CompactionResult::Succeeded);CHECK(out==h);ExactRecords(w,records);CHECK(w.Append(Marker(13,Wal::RecordState::Accepted)));}
    }
    auto p=Case(L"maintenance-missing-key");auto o=Protected(p);auto records=MaintenanceRecords();Wal::ProtectedHistoryHead h,out;Snapshot oldkeys;
    {Wal w(o);AppendRecords(w,records);h=Head(w);oldkeys=Files(o.protected_persistence->key_directory);}
    {Wal w(o);w.SetFaultInjectionHook([](auto s){return s=="pcompact-after-readback";});CHECK(w.CompactProtectedWithResult(8,h,out)==Wal::CompactionResult::BytesMayHavePersisted);}
    Directory(p/L"oldkeys");for(const auto& [name,b]:oldkeys)Write(p/L"oldkeys"/name,b);
    auto missing=o;missing.protected_persistence->key_directory=p/L"oldkeys";auto saved=Files(p);
    {Wal w(missing);CHECK(w.RecoverProtectedCompaction(h,8,Wal::ProtectedRecoveryChoice::PromoteReplacement,out)==Wal::CompactionResult::RejectedBeforeWrite);CHECK(Files(p)==saved);
        CHECK(w.RecoverProtectedCompaction(h,8,Wal::ProtectedRecoveryChoice::RetainOriginal,out)==Wal::CompactionResult::Succeeded);CHECK(out==h);ExactRecords(w,records);}
    auto q=Case(L"maintenance-unsafe-candidate");auto a=Protected(q);
    {Wal w(a);AppendRecords(w,records);h=Head(w);w.SetFaultInjectionHook([](auto s){return s=="pcompact-after-readback";});CHECK(w.CompactProtectedWithResult(8,h,out)==Wal::CompactionResult::BytesMayHavePersisted);}
    auto next=Side(a.path,L".compact.pnext");const auto before=Read(next);{Pins pins(q);CHECK(CreateHardLinkW((q/L"alias").c_str(),next.c_str(),nullptr));}
    {Wal w(a);CHECK(w.RecoverProtectedCompaction(h,8,Wal::ProtectedRecoveryChoice::PromoteReplacement,out)==Wal::CompactionResult::RejectedBeforeWrite);
        CHECK(w.RecoverProtectedCompaction(h,8,Wal::ProtectedRecoveryChoice::RetainOriginal,out)==Wal::CompactionResult::RejectedBeforeWrite);}CHECK(Read(next,false)==before);
    auto u=Case(L"maintenance-unknown");auto unknown=Protected(u);
    {Wal w(unknown);AppendRecords(w,records);h=Head(w);}
    Write(Side(unknown.path,L".compact.pnext.extra"),std::vector<std::uint8_t>{5,6,7});saved=Files(u);
    {Wal w(unknown);CHECK(w.RecoverProtectedCompaction(h,8,Wal::ProtectedRecoveryChoice::RetainOriginal,out)==Wal::CompactionResult::RejectedBeforeWrite);CHECK(Files(u)==saved);}
    auto capped=Case(L"maintenance-budget");auto limited=Protected(capped);
    {Wal w(limited);AppendRecords(w,records);h=Head(w);}
    saved=Files(capped);limited.protected_persistence->max_allocation_bytes=40*1024;
    {Wal w(limited);CHECK(w.CompactProtectedWithResult(8,h,out)==Wal::CompactionResult::RejectedBeforeWrite);CHECK(Files(capped)==saved);}
}
void MaintenanceCanaries()
{
    auto p=Case(L"maintenance-canaries");auto o=Protected(p);jt::hooks={};jt::hooks.key_override=std::as_bytes(std::span(keyCanary,sizeof(keyCanary)-1));
    {Wal w(o);AppendRecords(w,MaintenanceRecords());auto h=Head(w);Wal::ProtectedHistoryHead out;CHECK(w.CompactProtectedWithResult(8,h,out)==Wal::CompactionResult::Succeeded);}jt::hooks.key_override={};
    unsigned scanned=0;
    for(const auto& directory:std::vector<fs::path>{p,o.protected_persistence->key_directory})for(const auto& [name,bytes]:Files(directory)){
        (void)name;for(std::string_view text:{pathCanary,secondaryCanary,payloadCanary,keyCanary,"ordinary-gate-volume"}){
            CHECK(std::search(bytes.begin(),bytes.end(),text.begin(),text.end())==bytes.end());std::vector<std::uint8_t> wide;for(auto c:text){wide.push_back(static_cast<std::uint8_t>(c));wide.push_back(0);}
            CHECK(std::search(bytes.begin(),bytes.end(),wide.begin(),wide.end())==bytes.end());}++scanned;}
    CHECK(jt::hooks.dpapi_released_zero&&cc::testing::hooks.all_released_bytes_zero);std::cout<<"MAINTENANCE_SCAN "<<scanned<<" files, key and plaintext canaries absent"<<std::endl;
}
void MaintenanceCheckpointBounds()
{
    auto p=Case(L"maintenance-prefix");auto o=Protected(p);auto records=MaintenanceRecords();Wal::ProtectedHistoryHead h,out;
    {Wal w(o);AppendRecords(w,records);h=Head(w);w.SetFaultInjectionHook([](auto s){return s=="pcompact-after-readback";});CHECK(w.CompactProtectedWithResult(8,h,out)==Wal::CompactionResult::BytesMayHavePersisted);}
    auto pending=Side(o.path,L".compact.pnext");auto full=Read(pending);auto at=Frames(full);CHECK(at[1]==208);
    for(auto n:std::vector<std::size_t>{0,16,103,104,207,208,at[2],full.size()-1}){
        auto prefix=std::span(full).first(n);Write(pending,prefix,true);auto saved=Files(p);
        Wal w(o);CHECK(w.RecoverProtectedCompaction(h,8,Wal::ProtectedRecoveryChoice::PromoteReplacement,out)==Wal::CompactionResult::RejectedBeforeWrite);CHECK(Files(p)==saved);
    }
    // Even an authentic original log is not a replacement checkpoint receipt.
    auto original=Read(o.path);Write(pending,original,true);auto saved=Files(p);
    {Wal w(o);CHECK(w.RecoverProtectedCompaction(h,8,Wal::ProtectedRecoveryChoice::PromoteReplacement,out)==Wal::CompactionResult::RejectedBeforeWrite);CHECK(Files(p)==saved);}
    Write(pending,full,true);
    {Wal w(o);saved=Files(p);CHECK(w.RecoverProtectedCompaction(h,9,Wal::ProtectedRecoveryChoice::PromoteReplacement,out)==Wal::CompactionResult::RejectedBeforeWrite);CHECK(Files(p)==saved);
        CHECK(w.RecoverProtectedCompaction(h,8,Wal::ProtectedRecoveryChoice::PromoteReplacement,out)==Wal::CompactionResult::Succeeded);}
    auto base=Read(o.path);Wal::ProtectedHistoryHead newer;
    {Wal w(o);CHECK(w.Append(Marker(13,Wal::RecordState::Accepted)));newer=Head(w);}
    Write(o.path,base,true);saved=Files(p);
    {Wal w(o);CHECK(w.ReadAllAtProtectedHead(newer).status!=Wal::ReadStatus::Ok);CHECK(!w.Append(PrivateRecord(14)));CHECK(Files(p)==saved);
        CHECK(w.RecoverProtectedCompaction(h,8,Wal::ProtectedRecoveryChoice::RetainOriginal,out)==Wal::CompactionResult::RejectedBeforeWrite);CHECK(Files(p)==saved);}
    auto q=Case(L"maintenance-committed-prefix");auto truncated=o;truncated.path=q/L"journal.wal";Write(truncated.path,std::span(base).first(at[2]));saved=Files(q);
    {Wal w(truncated);BadRead(w);CHECK(!w.Append(PrivateRecord(14)));}CHECK(Files(q)==saved);
    for(auto fault:{jt::EpochFault::SlotFlush,jt::EpochFault::AfterPublication}){
        auto dir=Case(L"maintenance-key-publish");auto a=Protected(dir);Wal::ProtectedHistoryHead old;
        {Wal w(a);AppendRecords(w,records);old=Head(w);}auto bytes=Read(a.path);
        jt::hooks={};jt::hooks.fault=fault;
        {Wal w(a);CHECK(w.CompactProtectedWithResult(8,old,out)==Wal::CompactionResult::RejectedBeforeWrite);CHECK(jt::hooks.triggered);CHECK(Read(a.path)==bytes);CHECK(!fs::exists(Side(a.path,L".compact.pnext")));}
        auto slots=Files(a.protected_persistence->key_directory);jt::hooks.fault=jt::EpochFault::None;
        {Wal w(a);CHECK(w.CompactProtectedWithResult(8,old,out)==Wal::CompactionResult::Succeeded);}
        for(const auto& [name,b]:slots)CHECK(Read(a.protected_persistence->key_directory/name)==b);
    }
}
void AppendUnflushedHistory(Wal& w,const std::vector<Wal::Record>& records,bool ambiguous)
{
    CHECK(records.size()==12);
    CHECK(w.AppendBatchWithResult({records.begin(),records.begin()+7},false)==Wal::AppendResult::Succeeded);
    // Only the new anchor has been flushed. The semantic records have not.
    CHECK(w.SnapshotCounters().append_handle_flush_count==1);
    if(ambiguous)w.SetFaultInjectionHook([](auto s){return s=="durable-flush";});
    CHECK(w.AppendBatchWithResult({records.begin()+7,records.end()},ambiguous)==
        (ambiguous?Wal::AppendResult::BytesMayHavePersisted:Wal::AppendResult::Succeeded));
    CHECK(w.SnapshotCounters().append_handle_flush_count==1);w.SetFaultInjectionHook({});
}
void MaintenanceOriginalBarrier()
{
    const std::vector<std::string> faults={"pcompact-original-flush","durable-flush","pcompact-after-original-flush","pcompact-before-reseal"};
    for(unsigned mode=0;mode<3;++mode)for(const auto& fault:faults){
        auto p=Case(L"maintenance-original-barrier");auto o=Protected(p);auto all=MaintenanceRecords();auto kept=all;kept.erase(kept.begin());
        auto w=std::make_unique<Wal>(o);AppendUnflushedHistory(*w,all,mode==2);
        if(mode!=0){w.reset();w=std::make_unique<Wal>(o);CHECK(w->SnapshotCounters().append_handle_flush_count==0);}
        const auto flushes=w->SnapshotCounters().append_handle_flush_count;auto h=Head(*w);ExactRecords(*w,all);
        CHECK(w->SnapshotCounters().append_handle_flush_count==flushes);
        auto before=Files(p),keys=Files(o.protected_persistence->key_directory);auto original=Read(o.path);
        Wal::ProtectedHistoryHead out=h;bool hit=false,flushed=false,reseal=false,created=false;
        w->SetFaultInjectionHook([&](auto s){
            if(s=="pcompact-after-original-flush"){flushed=true;CHECK(w->SnapshotCounters().append_handle_flush_count==flushes+1);}
            if(s=="pcompact-before-reseal"){CHECK(flushed);reseal=true;}
            if(s=="pcompact-before-create")created=true;
            if(s!=fault)return false;hit=true;return true;
        });
        CHECK(w->CompactProtectedWithResult(8,h,out)==Wal::CompactionResult::RejectedBeforeWrite);
        CHECK(hit&&out==Wal::ProtectedHistoryHead{}&&!created);
        CHECK(flushed==(fault=="pcompact-after-original-flush"||fault=="pcompact-before-reseal"));
        CHECK(reseal==(fault=="pcompact-before-reseal"));CHECK(Files(p)==before);CHECK(Files(o.protected_persistence->key_directory)==keys);
        w->SetFaultInjectionHook({});CHECK(Head(*w)==h);ExactRecords(*w,all);
        const auto retry_flushes=w->SnapshotCounters().append_handle_flush_count;
        bool compact_flush=false,recovery_flush=false,old_rename=false;std::vector<std::string> order;
        w->SetFaultInjectionHook([&](auto s){
            if(s=="pcompact-original-flush"||s=="durable-flush"||s=="pcompact-after-original-flush"||s=="pcompact-before-reseal"||
                s=="pcompact-before-create"||s=="precover-original-flush"||s=="precover-after-original-flush"||
                s=="pcompact-before-old-rename"||s=="pcompact-after-old-rename")order.emplace_back(s);
            if(s=="pcompact-after-original-flush"){compact_flush=true;CHECK(w->SnapshotCounters().append_handle_flush_count==retry_flushes+1);}
            if(s=="pcompact-before-reseal"||s=="pcompact-before-create")CHECK(compact_flush);
            if(s=="precover-after-original-flush"){CHECK(compact_flush);recovery_flush=true;}
            if(s=="pcompact-before-old-rename"){CHECK(compact_flush&&recovery_flush);old_rename=true;}
            return s=="pcompact-after-old-rename";
        });
        CHECK(w->CompactProtectedWithResult(8,h,out)==Wal::CompactionResult::BytesMayHavePersisted);
        CHECK(compact_flush&&recovery_flush&&old_rename&&out==Wal::ProtectedHistoryHead{});
        const std::vector<std::string> expected={"pcompact-original-flush","durable-flush","pcompact-after-original-flush","pcompact-before-reseal",
            "pcompact-before-create","precover-original-flush","precover-after-original-flush","pcompact-before-old-rename","pcompact-after-old-rename"};
        CHECK(order==expected);CHECK(!fs::exists(o.path));CHECK(Read(Side(o.path,L".compact.pold"))==original);
        w.reset();w=std::make_unique<Wal>(o);
        CHECK(w->RecoverProtectedCompaction(h,8,Wal::ProtectedRecoveryChoice::PromoteReplacement,out)==Wal::CompactionResult::Succeeded);
        ExactRecords(*w,kept);CHECK(Read(Archive(o.path,h))==original);
        for(const auto& [name,bytes]:keys)CHECK(Read(o.protected_persistence->key_directory/name)==bytes);
        auto marker=Marker(13,Wal::RecordState::Accepted);CHECK(w->Append(marker));kept.push_back(marker);w.reset();
        {Wal reopened(o);ExactRecords(reopened,kept);}
        std::cout<<"ORIGINAL_BARRIER mode="<<mode<<" fault="<<fault<<"; retry order:";
        for(const auto& stage:order)std::cout<<' '<<stage;std::cout<<std::endl;
    }
}
void MaintenanceRecoveryOriginalBarrier()
{
    for(bool ambiguous:{false,true})for(unsigned action=0;action<3;++action){
        auto p=Case(L"maintenance-recovery-original-barrier");auto o=Protected(p);auto all=MaintenanceRecords();auto kept=all;kept.erase(kept.begin());
        Wal::ProtectedHistoryHead h,out;{Wal w(o);AppendUnflushedHistory(w,all,ambiguous);}
        {Wal w(o);h=Head(w);CHECK(w.SnapshotCounters().append_handle_flush_count==0);}
        if(action!=2){Wal w(o);w.SetFaultInjectionHook([](auto s){return s=="pcompact-after-readback";});
            CHECK(w.CompactProtectedWithResult(8,h,out)==Wal::CompactionResult::BytesMayHavePersisted);}
        const auto choice=action==0?Wal::ProtectedRecoveryChoice::PromoteReplacement:Wal::ProtectedRecoveryChoice::RetainOriginal;
        const auto before=Files(p),keys=Files(o.protected_persistence->key_directory);
        for(auto fault:{"precover-original-flush","precover-after-original-flush"}){
            Wal w(o);CHECK(w.SnapshotCounters().append_handle_flush_count==0);bool hit=false,after=false,mutation=false;
            out=h;w.SetFaultInjectionHook([&](auto s){
                if(s=="precover-after-original-flush")after=true;
                if(s=="pcompact-before-old-rename"||s=="pcompact-before-quarantine"||s=="pcompact-before-restore"||s=="pcompact-before-reopen")mutation=true;
                if(s!=fault)return false;hit=true;return true;
            });
            CHECK(w.RecoverProtectedCompaction(h,8,choice,out)==Wal::CompactionResult::RejectedBeforeWrite);
            CHECK(hit&&!mutation&&out==Wal::ProtectedHistoryHead{});CHECK(after==(std::string_view(fault)=="precover-after-original-flush"));
            CHECK(Files(p)==before);CHECK(Files(o.protected_persistence->key_directory)==keys);
        }
        std::vector<std::string> order;
        {Wal w(o);bool flushed=false;w.SetFaultInjectionHook([&](auto s){
                if(s=="precover-original-flush"||s=="precover-after-original-flush"||s=="pcompact-before-old-rename"||
                    s=="pcompact-before-quarantine"||s=="pcompact-before-reopen")order.emplace_back(s);
                if(s=="precover-after-original-flush")flushed=true;
                if(s=="pcompact-before-old-rename"||s=="pcompact-before-quarantine"||s=="pcompact-before-reopen")CHECK(flushed);
                return false;
            });
            CHECK(w.RecoverProtectedCompaction(h,8,choice,out)==Wal::CompactionResult::Succeeded);CHECK(flushed);
            const std::vector<std::string> expected=action==2?
                std::vector<std::string>{"precover-original-flush","precover-after-original-flush","pcompact-before-reopen"}:
                std::vector<std::string>{"precover-original-flush","precover-after-original-flush",action==0?"pcompact-before-old-rename":"pcompact-before-quarantine","pcompact-before-reopen"};
            CHECK(order==expected);ExactRecords(w,action==0?kept:all);if(action!=0)CHECK(out==h);
            if(action==2){CHECK(Files(p)==before);CHECK(Files(o.protected_persistence->key_directory)==keys);}
            w.SetFaultInjectionHook({});auto marker=Marker(13,Wal::RecordState::Accepted);CHECK(w.Append(marker));
            if(action==0)kept.push_back(marker);else all.push_back(marker);
        }
        {Wal reopened(o);ExactRecords(reopened,action==0?kept:all);}
        std::cout<<"RECOVERY_ORIGINAL_BARRIER ambiguous="<<ambiguous<<" action="<<action<<"; success order:";
        for(const auto& stage:order)std::cout<<' '<<stage;std::cout<<std::endl;
    }
}
#endif
} // namespace
int wmain(int argc,wchar_t** argv)
{
    try{
        CHECK(argc==2||argc==3);const bool maintenance=argc==3;CHECK(!maintenance||std::wstring_view(argv[2])==L"--maintenance");
        root=fs::path(argv[1]).make_preferred();CHECK(LocalAbsolute(root));Directory(root);
        Group("ordinary v1/v2/v3 shared codec and exact wire corpus",OrdinaryCodec);
        Group("ordinary append/batch/flush/lease/read/reopen",OrdinaryPersistence);
        Group("ordinary torn-tail repair, byte cap and checksum refusal",OrdinaryTailAndLimits);
        Group("ordinary actual compaction and ambiguous durable flush",OrdinaryCompactionAndAmbiguity);
#ifndef APFSACCESS_WAL_BASELINE_ONLY
        Group("protected missing exclusive history, first append anchor, acceptance, reopen and fresh epoch",ProtectedLifecycle);
        Group("wrong authority and bidirectional ordinary/mixed history refusal",AuthorityAndMixing);
        Group("invalid configuration and every compaction sidecar refusal before writes",ConfigurationAndMaintenance);
        if(!maintenance)Group("every protected byte/partial tail, acceptance and physical-position substitution",CorruptionAndPosition);
        Group("missing/corrupt keys and injected key-publication failure preservation",KeyAndPublicationFailures);
        Group("provider failure nonce burns, partial writes and ambiguous acceptance flush",FailureResultsAndNonce);
        Group("exclusive leases, stale generations, replay/append budgets and hard links",LeasesAndBudgets);
        Group("protected persistence canaries and actual accepted-record recovery",CanaryScan);
        Group("protected checkpoint exact retention, ID bounds, repeated maintenance and append/reopen",MaintenanceLifecycle);
        Group("protected maintenance publication failure cuts and complete recovery",MaintenanceCuts);
        Group("protected original retention, corrupt candidates and authority refusals",MaintenanceRetainAndRefusals);
        Group("protected no-replace conflicts, missing canonical and external rollback head",MaintenanceNoReplaceAndRollback);
        Group("protected restore failure cuts, missing new key, unsafe aliases and bounded maintenance",MaintenanceRecoveryCutsAndKeys);
        Group("protected maintenance persistence key/plaintext canaries",MaintenanceCanaries);
        Group("protected checkpoint prefix commitment, wrong valid candidates and key-publication failures",MaintenanceCheckpointBounds);
        Group("original durability before resealing, deferred/reopened/ambiguous heads and old-rename cut recovery",MaintenanceOriginalBarrier);
        Group("explicit recovery original barriers before promotion/quarantine and no-op durable retention",MaintenanceRecoveryOriginalBarrier);
#endif
        std::cout<<"PASS "<<groups<<" groups / "<<checks<<" assertions / "<<cases<<" private cases"<<std::endl;return 0;
    }catch(const std::exception& e){std::cerr<<"FAIL "<<e.what()<<std::endl;return 1;}
}
