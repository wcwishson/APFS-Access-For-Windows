#include "FusionRetainedPrefixCache.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>

using Cache=apfsaccess::rw::FusionRetainedPrefixCache<>;
namespace {
unsigned checks=0;
void Check(bool condition,const char* label){if(!condition)throw std::runtime_error(label);++checks;}
Cache::Digest Hash(const std::string& bytes){Cache::Digest h{};
 Check(BCryptHash(BCRYPT_SHA256_ALG_HANDLE,nullptr,0,reinterpret_cast<PUCHAR>(const_cast<char*>(bytes.data())),
    static_cast<ULONG>(bytes.size()),reinterpret_cast<PUCHAR>(h.data()),32)>=0,"hash");return h;}
void Write(const std::filesystem::path& p,const std::string& bytes){std::ofstream f(p,std::ios::binary);f.write(bytes.data(),static_cast<std::streamsize>(bytes.size()));f.close();Check(bool(f),"fixture write");}
Cache::Domain Domain(){Cache::Domain d;d.source[0]=std::byte{7};d.journal="exact-jid";d.volume=101;d.generation=7;d.serial=9;d.file=11;return d;}
void Writable(const std::filesystem::path& p,bool expected){
 HANDLE h=CreateFileW(p.c_str(),GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,0,nullptr);
 const auto error=GetLastError();Check((h!=INVALID_HANDLE_VALUE)==expected,"actual writable lease state");
 if(h!=INVALID_HANDLE_VALUE)CloseHandle(h);else Check(error==ERROR_SHARING_VIOLATION,"actual sharing refusal");
}
}
int wmain(int argc,wchar_t** argv)try{
 Check(argc==2,"private output required");const std::filesystem::path root(argv[1]);
 Check(root.is_absolute()&&root.native().starts_with(L"D:\\ApfsAccessScratch\\"),"owned D output");
 Check(!std::filesystem::exists(root),"fresh output only");std::filesystem::create_directories(root);
 const auto head=root/L"head.cert",witness=root/L"1.witness";Write(head,"authenticated-head");Write(witness,"complete-witness");
 const auto hash=Hash("authenticated-head"),other=Hash("other");std::string error;
 {Cache cache;cache.Bind(Domain());Check(!cache.Has(13,hash),"new owner has no proof");
  cache.Remember(13,hash,head.native());Check(!cache.Has(13,hash),"unleased head cannot mint proof");
  Check(cache.PinFile(head.native(),hash,error),"exact head pinned");cache.Remember(13,hash,head.native());
  Check(cache.Has(13,hash)&&!cache.Has(13,other)&&!cache.Has(14,hash),"floor and digest exact");
  Writable(head,false);Check(!DeleteFileW(head.c_str()),"actual delete blocked");
  Check(!cache.PinFile(head.native(),other,error),"changed expected digest refuses");
  cache.Bind(Domain());Check(cache.Has(13,hash),"same held domain reuses proof");
  auto after=Domain();after.file=12;cache.Advance(Domain(),after);Check(cache.Has(13,hash),"certified same-generation physical transition keeps pins");
  Writable(head,false);cache.Bind(after);Check(cache.Has(13,hash),"new exact physical identity matches transition");
  auto wrong=after;wrong.generation++;cache.Bind(wrong);Check(!cache.Has(13,hash),"writer generation invalidates prefix");Writable(head,true);
 }
 const auto live_alias=root/L"live-alias.cert";
 {Cache cache;cache.Bind(Domain());Check(cache.PinFile(head.native(),hash,error)&&cache.PinFile(witness.native(),Hash("complete-witness"),error),"segment evidence pins");
  cache.Remember(13,hash,head.native(),{witness.native()});Check(cache.Has(13,hash),"exact segment metadata initially admitted");
  Check(CreateHardLinkW(live_alias.c_str(),witness.c_str(),nullptr)!=FALSE,"actual witness alias can be added despite read lease");
  Check(!cache.Has(13,hash),"changed witness link count invalidates cached segment census");Writable(witness,false);}
 Check(DeleteFileW(live_alias.c_str())!=FALSE,"owned alias retires after evidence lease");
 Writable(head,true);Write(head,"tampered-head");
 {Cache cache;cache.Bind(Domain());Check(!cache.PinFile(head.native(),hash,error),"fresh owner detects changed evidence bytes");Check(!cache.Has(13,hash),"tamper never gains cached proof");}
 Write(head,"authenticated-head");
 for(unsigned field=0;field<6;++field){Cache cache;auto d=Domain();cache.Bind(d);Check(cache.PinFile(head.native(),hash,error),"domain test pin");cache.Remember(13,hash,head.native());
  if(field==0)d.source[1]=std::byte{1};else if(field==1)d.journal+="-foreign";else if(field==2)++d.volume;else if(field==3)++d.serial;else if(field==4)++d.file;else ++d.generation;
  cache.Bind(d);Check(!cache.Has(13,hash),"every source domain component invalidates");Writable(head,true);
 }
 {Cache cache;auto d=Domain();cache.Bind(d);Check(cache.PinFile(head.native(),hash,error),"transition pin");cache.Remember(13,hash,head.native());
  auto after=d;++after.file;++after.generation;cache.Advance(d,after);Check(!cache.Has(13,hash),"unproved generation transition drops proof");Writable(head,true);}
 const auto alias=root/L"alias.cert";Check(CreateHardLinkW(alias.c_str(),head.c_str(),nullptr)!=FALSE,"hardlink fixture");
 {Cache cache;cache.Bind(Domain());Check(!cache.PinFile(head.native(),hash,error),"multiply linked evidence refuses");}
 const auto a=root/L"a.cert",b=root/L"b.cert",c=root/L"c.cert";Write(a,"a");Write(b,"b");Write(c,"c");
 const auto empty=root/L"empty.cert",large=root/L"large.cert";Write(empty,"");Write(large,"bounded");
 {HANDLE file=CreateFileW(large.c_str(),GENERIC_WRITE,0,nullptr,OPEN_EXISTING,0,nullptr);Check(file!=INVALID_HANDLE_VALUE,"oversized fixture handle");
  LARGE_INTEGER end{};end.QuadPart=(8ull<<20)+1;Check(SetFilePointerEx(file,end,nullptr,FILE_BEGIN)&&SetEndOfFile(file),"oversized fixture length");CloseHandle(file);}
 {Cache cache;cache.Bind(Domain());Check(!cache.PinFile(empty.native(),Hash(""),error),"empty evidence refuses");
  Check(!cache.PinFile(large.native(),hash,error),"oversized evidence refuses before materialization");Check(!cache.Has(13,hash),"malformed files grant no proof");}
 {using Small=apfsaccess::rw::FusionRetainedPrefixCache<2>;Small cache;Small::Domain d;d.journal="j";d.volume=d.generation=d.serial=d.file=1;cache.Bind(d);
  Check(cache.PinFile(a.native(),Hash("a"),error)&&cache.PinFile(b.native(),Hash("b"),error),"finite pin boundary fits");cache.Remember(1,Hash("a"),a.native());Check(cache.Has(1,Hash("a")),"complete bounded proof reusable");
  Check(cache.PinFile(c.native(),Hash("c"),error),"overflow retains full-walk fallback");Check(!cache.Active()&&!cache.Has(1,Hash("a")),"overflow releases all incomplete optimization state");
  cache.Bind(d);Check(!cache.Active(),"same owner cannot renew failed cache allowance");Writable(a,true);Writable(b,true);
 }
 {using Small=apfsaccess::rw::FusionRetainedPrefixCache<2>;Small cache;Small::Domain d;d.journal="j";d.volume=d.generation=d.serial=d.file=1;cache.Bind(d);
  Check(cache.PinFile(a.native(),Hash("a"),error)&&cache.PinFile(b.native(),Hash("b"),error),"reference limit fixture pins");
  cache.Remember(1,Hash("a"),a.native(),{b.native()});cache.Remember(2,Hash("b"),b.native(),{a.native()});
  Check(cache.Has(1,Hash("a"))&&cache.Has(2,Hash("b")),"exact finite reference boundary fits");
  cache.Remember(3,Hash("a"),a.native(),{b.native()});
  Check(!cache.Active()&&!cache.Has(1,Hash("a")),"reference envelope exhaustion selects full-walk fallback");Writable(a,true);Writable(b,true);
 }
 std::cout<<"PASS "<<checks<<" actual Windows retained-prefix checks\n";return 0;
}catch(const std::exception& e){std::cerr<<"FAIL "<<e.what()<<'\n';return 1;}
