#include "ProtectedJournalEpoch.h"
#include "WriteAheadLog.h"
#include "ApfsCryptoTestHooks.h"
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <algorithm>
#include <atomic>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <thread>
#include <vector>

namespace {
namespace fs = std::filesystem;
namespace j = apfsaccess::journal;
namespace c = apfsaccess::crypto;
using Wal = apfsaccess::rw::WriteAheadLog;
unsigned checks = 0, groups = 0;
fs::path root;
void Check(bool value, const char* text, int line) {
    ++checks; if(!value) throw std::runtime_error(std::string(text)+":"+std::to_string(line));
}
#define CHECK(x) Check(static_cast<bool>(x), #x, __LINE__)
struct Handle { HANDLE h=INVALID_HANDLE_VALUE; ~Handle(){if(h!=INVALID_HANDLE_VALUE) CloseHandle(h);} };
j::JournalDigest Binding() { j::JournalDigest b{}; for(unsigned i=0;i<32;++i)b[i]=std::byte(i+1); return b; }
j::JournalRecordContext Context() { return {19,Binding(),7}; }
constexpr char canary[]="READ_PASS_PLAINTEXT_CANARY_a8f61d2e";
auto Plain() { return std::as_bytes(std::span(canary,sizeof(canary)-1)); }
std::vector<std::byte> Read(const fs::path& path) {
    std::ifstream f(path,std::ios::binary); CHECK(f.good());
    const std::vector<char> v((std::istreambuf_iterator<char>(f)),{});
    std::vector<std::byte> out(v.size());std::memcpy(out.data(),v.data(),v.size());return out;
}
void Write(const fs::path& p,std::span<const std::byte> b) {
    std::ofstream f(p,std::ios::binary|std::ios::trunc);CHECK(f.good());
    f.write(reinterpret_cast<const char*>(b.data()),static_cast<std::streamsize>(b.size()));CHECK(f.good());
}
fs::path Key(const fs::path& dir, const j::JournalEpochId& id) {
    std::string n="epoch-";constexpr char hex[]="0123456789abcdef";
    for(auto v:id) {auto b=std::to_integer<unsigned>(v);n+=hex[b>>4];n+=hex[b&15];}
    return dir/(n+".key");
}
struct Fixture {
    fs::path dir; j::JournalEpochId id{}; std::vector<std::byte> frame;
    explicit Fixture(const char* name) : dir(root/name) {
        fs::create_directory(dir);auto writer=j::ProtectedJournalEpoch::AcquireWriter(dir.wstring(),Binding());CHECK(writer);
        id=writer.epoch->Id();auto sealed=writer.epoch->Seal(Context(),Plain());CHECK(sealed);
        frame.assign(sealed.bytes.Bytes().begin(),sealed.bytes.Bytes().end());
    }
};
bool Exact(const j::JournalRecordResult& r) { return r && std::ranges::equal(r.bytes.Bytes(),Plain()) && r.bytes.IsLocked(); }
void ReuseAndScope() {
    Fixture f("reuse");auto pass=j::ProtectedJournalReadPass::Acquire(f.dir.wstring(),Binding());CHECK(pass);
    const auto before=j::testing::hooks.dpapi_releases;
    for(unsigned i=0;i<12;++i) CHECK(Exact(pass.reader->Open(Context(),f.frame)));
    CHECK(j::testing::hooks.dpapi_releases==before+1);
    pass.reader.reset();
    auto fresh=j::ProtectedJournalReadPass::Acquire(f.dir.wstring(),Binding());CHECK(fresh);
    CHECK(Exact(fresh.reader->Open(Context(),f.frame)));CHECK(j::testing::hooks.dpapi_releases==before+2);
    for(unsigned i=0;i<3;++i) CHECK(Exact(j::ProtectedJournalEpoch::Open(f.dir.wstring(),Binding(),Context(),f.frame)));
    CHECK(j::testing::hooks.dpapi_releases==before+5);
    auto context=Context();context.purpose++;
    auto bad=fresh.reader->Open(context,f.frame);CHECK(!bad && bad.bytes.Size()==0 && bad.status.error==j::JournalError::IntegrityFailure);
    CHECK(Exact(fresh.reader->Open(Context(),f.frame)));CHECK(j::testing::hooks.dpapi_releases==before+6);
    context=Context();context.operation[0]^=std::byte{1};CHECK(!fresh.reader->Open(context,f.frame));
    context=Context();context.chunk++;CHECK(!fresh.reader->Open(context,f.frame));
    auto wrong=Binding();wrong[0]^=std::byte{1};auto foreign=j::ProtectedJournalReadPass::Acquire(f.dir.wstring(),wrong);CHECK(foreign);
    bad=foreign.reader->Open(Context(),f.frame);CHECK(!bad && bad.status.error==j::JournalError::BindingMismatch && bad.bytes.Size()==0);
}
void KeyChanges() {
    Fixture f("keys");auto pass=j::ProtectedJournalReadPass::Acquire(f.dir.wstring(),Binding());CHECK(pass);
    CHECK(Exact(pass.reader->Open(Context(),f.frame)));
    const auto key=Key(f.dir,f.id),saved=root/"preserved-key";const auto original=Read(key);
    fs::rename(key,saved);auto bad=pass.reader->Open(Context(),f.frame);
    CHECK(!bad && bad.status.error==j::JournalError::MissingKey && bad.bytes.Size()==0);
    fs::rename(saved,key);CHECK(Exact(pass.reader->Open(Context(),f.frame)));
    auto altered=original;altered.back()^=std::byte{1};Write(key,altered);
    bad=pass.reader->Open(Context(),f.frame);CHECK(!bad && bad.status.error==j::JournalError::InvalidFrame && bad.bytes.Size()==0);
    CHECK(Read(key)==altered);Write(key,original);CHECK(Exact(pass.reader->Open(Context(),f.frame)));
    CHECK(CreateHardLinkW((root/"preserved-key-link").c_str(),key.c_str(),nullptr));
    bad=pass.reader->Open(Context(),f.frame);CHECK(!bad && bad.status.error==j::JournalError::UnsafePath && bad.bytes.Size()==0);
    CHECK(Read(key)==original);
}
void EpochRotationAndConcurrency() {
    Fixture f("rotation");auto writer=j::ProtectedJournalEpoch::AcquireWriter(f.dir.wstring(),Binding());CHECK(writer);
    CHECK(writer.epoch->Id()!=f.id);auto second=writer.epoch->Seal(Context(),Plain());CHECK(second);
    auto pass=j::ProtectedJournalReadPass::Acquire(f.dir.wstring(),Binding());CHECK(pass);
    const auto before=j::testing::hooks.dpapi_releases;
    CHECK(Exact(pass.reader->Open(Context(),f.frame)));CHECK(Exact(pass.reader->Open(Context(),second.bytes.Bytes())));
    CHECK(Exact(pass.reader->Open(Context(),f.frame)));CHECK(j::testing::hooks.dpapi_releases==before+3);
    std::atomic<bool> ok=true;std::vector<std::thread> threads;
    for(unsigned n=0;n<4;++n) threads.emplace_back([&] {
        for(unsigned i=0;i<32;++i) if(!Exact(pass.reader->Open(Context(),f.frame))) ok=false;
        if(!c::testing::hooks.all_released_bytes_zero || !j::testing::hooks.dpapi_released_zero) ok=false;
    });
    for(auto& t:threads)t.join();CHECK(ok.load());
}
void FramesAndFailures() {
    Fixture f("frames");auto pass=j::ProtectedJournalReadPass::Acquire(f.dir.wstring(),Binding());CHECK(pass);
    for(std::size_t n=0;n<f.frame.size();++n) {
        const auto truncated=std::span(f.frame).first(n);
        auto a=pass.reader->Open(Context(),truncated),b=j::ProtectedJournalEpoch::Open(f.dir.wstring(),Binding(),Context(),truncated);
        CHECK(!a && !b && a.bytes.Size()==0 && b.bytes.Size()==0 && a.status.error==b.status.error);
        auto changed=f.frame;changed[n]^=std::byte{1};a=pass.reader->Open(Context(),changed);
        b=j::ProtectedJournalEpoch::Open(f.dir.wstring(),Binding(),Context(),changed);
        CHECK(!a && !b && a.bytes.Size()==0 && b.bytes.Size()==0 && a.status.error==b.status.error);
    }
    auto extra=f.frame;extra.push_back(std::byte{});CHECK(!pass.reader->Open(Context(),extra));
    extra.resize(j::kMaxJournalRecordBytes+1);auto too_big=pass.reader->Open(Context(),extra);
    CHECK(!too_big && too_big.status.error==j::JournalError::ResourceLimit && too_big.bytes.Size()==0);
    for(int n=0;n<4;++n) {
        CHECK(Exact(pass.reader->Open(Context(),f.frame)));
        if(n==0)c::testing::hooks.allocation_failure_at=c::testing::hooks.allocations;
        if(n==1)c::testing::hooks.lock_failure_at=c::testing::hooks.locks;
        if(n==2)c::testing::hooks.cng_failure_at=c::testing::hooks.cng_calls;
        if(n==3) {c::testing::hooks.cng_failure_at=c::testing::hooks.cng_calls;c::testing::hooks.cng_fail_after_call=true;}
        const auto bad=pass.reader->Open(Context(),f.frame);CHECK(!bad && bad.bytes.Size()==0);
        c::testing::hooks.allocation_failure_at=c::testing::hooks.lock_failure_at=c::testing::hooks.cng_failure_at=-1;
        c::testing::hooks.cng_fail_after_call=false;
        const auto releases=j::testing::hooks.dpapi_releases;CHECK(Exact(pass.reader->Open(Context(),f.frame)));
        CHECK(j::testing::hooks.dpapi_releases==releases+1);
        CHECK(c::testing::hooks.all_released_bytes_zero && j::testing::hooks.dpapi_released_zero);
    }
}
void ActualWal() {
    const auto dir=root/"wal";fs::create_directory(dir);fs::create_directory(dir/"keys");
    Wal::ProtectedPersistence p;p.key_directory=dir/"keys";p.source_binding=p.journal_identity=Binding();
    Wal::Options options{dir/"original.wal","read-pass-volume",1u<<20,p};
    {
        Wal wal(options);std::vector<Wal::Record> rows;
        for(unsigned n=1;n<=8;++n) {Wal::Record row;row.sequence=n;row.transaction_id=n;row.object_id=19;
            row.path_utf8="\\read-pass-private-canary";rows.push_back(row);}
        CHECK(wal.AppendBatch(rows));Wal::ProtectedHistoryHead head;CHECK(wal.CaptureProtectedHistoryHead(head));
        auto read=wal.ReadAllAtProtectedHead(head);CHECK(read.status==Wal::ReadStatus::Ok && read.records.size()==8);
        for(unsigned n=0;n<8;++n) CHECK(read.records[n].sequence==n+1 && read.records[n].path_utf8==rows[n].path_utf8);
        auto foreign=options;foreign.protected_persistence->journal_identity[0]^=std::byte{1};Wal wrong(foreign);
        read=wrong.ReadAll();CHECK(read.status!=Wal::ReadStatus::Ok && read.records.empty());
    }
    {
        Wal wal(options);Wal::Record row;row.sequence=9;row.transaction_id=9;row.object_id=19;
        CHECK(wal.Append(row));auto read=wal.ReadAllWithExclusiveWriterLease();CHECK(read.status==Wal::ReadStatus::Ok && read.records.size()==9);
    }
    const auto original=Read(options.path);auto torn=original;torn.pop_back();Write(options.path,torn);
    {Wal wal(options);auto read=wal.ReadAllWithExclusiveWriterLease();CHECK(read.status!=Wal::ReadStatus::Ok && read.records.empty());}
    CHECK(Read(options.path)==torn);Write(options.path,original);
    for(const auto& e:fs::directory_iterator(dir/"keys")) if(e.path().extension()==".key") {
        const auto saved=dir/e.path().filename();fs::rename(e.path(),saved);
        {Wal wal(options);auto read=wal.ReadAll();CHECK(read.status!=Wal::ReadStatus::Ok && read.records.empty());}
        fs::rename(saved,e.path());break;
    }
    CHECK(Read(options.path)==original);
}
void PersistenceCanaries() {
    std::array<std::byte,32> key{};for(unsigned n=0;n<32;++n)key[n]=std::byte(0x91+n);
    j::testing::hooks.key_override=key;Fixture f("scan");j::testing::hooks.key_override={};
    Write(f.dir/"sealed-frame",f.frame);
    std::vector<std::byte> wide;for(auto ch:Plain()) {wide.push_back(ch);wide.push_back(std::byte{});}
    for(const auto& e:fs::recursive_directory_iterator(root)) if(e.is_regular_file()) {
        const auto b=Read(e.path());
        CHECK(std::search(b.begin(),b.end(),Plain().begin(),Plain().end())==b.end());
        CHECK(std::search(b.begin(),b.end(),wide.begin(),wide.end())==b.end());
        CHECK(std::search(b.begin(),b.end(),key.begin(),key.end())==b.end());
    }
}
}
int main(int argc,char** argv) {
    try {
        CHECK(argc==2);root=fs::path(argv[1]).make_preferred();const auto text=root.wstring();
        CHECK(text.size()>3 && text.size()<170 && (text[0]==L'D'||text[0]==L'd') && text[1]==L':' && text[2]==L'\\');
        CHECK(text.find_first_of(L":/*?\"<>|",3)==text.npos && text.back()!=L'\\' && GetDriveTypeW(L"D:\\")==DRIVE_FIXED);
        for(const auto& part:root.relative_path()) {const auto s=part.wstring();CHECK(!s.empty() && s!=L"." && s!=L".." && s.back()!=L'.' && s.back()!=L' ');}
        std::vector<std::unique_ptr<Handle>> pins;auto parent=root.parent_path();
        while(!parent.empty()) {
            auto h=std::make_unique<Handle>();h->h=CreateFileW(parent.c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE,
                nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
            BY_HANDLE_FILE_INFORMATION i{};CHECK(h->h!=INVALID_HANDLE_VALUE && GetFileInformationByHandle(h->h,&i));
            CHECK(GetFileType(h->h)==FILE_TYPE_DISK && (i.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY) && !(i.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT));
            std::wstring actual(512,L'\0');const auto size=GetFinalPathNameByHandleW(h->h,actual.data(),static_cast<DWORD>(actual.size()),FILE_NAME_NORMALIZED|VOLUME_NAME_DOS);
            CHECK(size && size<actual.size());actual.resize(size);
            CHECK(CompareStringOrdinal(actual.c_str(),-1,(L"\\\\?\\"+parent.wstring()).c_str(),-1,TRUE)==CSTR_EQUAL);
            pins.push_back(std::move(h));if(parent==parent.parent_path())break;parent=parent.parent_path();
        }
        CHECK(!fs::exists(root));fs::create_directory(root);
        const auto run=[](const char* name,auto fn){fn();++groups;std::cout<<"PASS "<<name<<std::endl;};
        run("bounded reuse, legacy static Open and exact context/source",ReuseAndScope);
        run("warm missing/corrupt/hardlinked actual key slots",KeyChanges);
        run("fresh epochs, old reads, one-key eviction and concurrent authentication",EpochRotationAndConcurrency);
        run("every frame byte/truncation and allocation/lock/provider failure cleanup",FramesAndFailures);
        run("actual protected WAL append/read/reopen, foreign JID, torn tail and missing key",ActualWal);
        run("actual wrapped slots and encrypted persistence raw/UTF16 plaintext and key canaries",PersistenceCanaries);
        CHECK(c::testing::hooks.all_released_bytes_zero && j::testing::hooks.dpapi_released_zero);
        std::cout<<"PASS "<<groups<<" groups / "<<checks<<" assertions\n";return 0;
    }catch(const std::exception& e){std::cerr<<"FAIL "<<e.what()<<'\n';return 1;}
}
