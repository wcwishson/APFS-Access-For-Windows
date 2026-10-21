#include "FusionImageRuntime.h"
#include "ApfsFormat.h"
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>

using namespace apfsaccess;
namespace {
unsigned checks=0;std::string error;
void Check(bool ok,const char* label){if(!ok)throw std::runtime_error(std::string(label)+": "+error);++checks;}
std::vector<char> Read(const std::filesystem::path& p){std::ifstream f(p,std::ios::binary);Check(bool(f),"evidence read opens");return {(std::istreambuf_iterator<char>(f)),{}};}
void Write(const std::filesystem::path& p,const std::vector<char>& b){std::ofstream f(p,std::ios::binary|std::ios::trunc);f.write(b.data(),static_cast<std::streamsize>(b.size()));f.close();Check(bool(f),"private evidence write");}
std::unique_ptr<rw::FusionImageRuntime> Open(const std::filesystem::path& root,bool latest){
 catalog::FusionBindRequest r;r.checkpoint_xid=20;r.container_uuid_hex=std::string(32,'a');r.fusion_uuid_hex=std::string(31,'b')+"a";
 r.convention=catalog::FusionRoleConvention::LinuxApfsLastByteLowBit;r.budget=rw::FusionImageRuntime::CreateStartupReadBudget();r.cancellation=std::make_shared<std::atomic<bool>>(false);
 for(unsigned i=0;i<2;++i){catalog::FusionImageMember m;m.path=(root/(i?L"tier.apfs":L"main.apfs")).wstring();m.role=i?catalog::FusionMemberRole::Tier2:catalog::FusionMemberRole::Main;m.store_offset=8192;m.stable_store_id=i?"apfs-store:test-tier2":"apfs-store:test-main";
  if(!catalog::ApfsFusionStore::InspectImage(m.path,m.exact_identity,error))return {};m.store_size=m.exact_identity.size_bytes-8192;r.members.push_back(m);}
 if(latest){std::ifstream f(root/L"main.apfs",std::ios::binary);std::vector<std::byte> nx(4096);f.seekg(8192);f.read(reinterpret_cast<char*>(nx.data()),4096);auto parsed=catalog::ParseNxSuperblock(nx);Check(bool(f)&&bool(parsed),"latest source checkpoint");r.checkpoint_xid=parsed->xid;}
 rw::FusionVolumeSelection selected{r.container_uuid_hex,std::string(32,'c'),{"apfs-store:test-main","apfs-store:test-tier2"},101,r.checkpoint_xid};
 return rw::FusionImageRuntime::Open(r,selected,(root/L"private.wal").wstring(),error);
}
std::vector<std::filesystem::path> Certificates(const std::filesystem::path& root){
 const std::wstring prefix=L"private.wal.fusion-continue-";std::vector<std::filesystem::path> result;
 for(const auto& f:std::filesystem::directory_iterator(root))if(f.path().filename().wstring().starts_with(prefix)&&f.path().extension()==L".cert")result.push_back(f.path());
 std::sort(result.begin(),result.end(),[&](const auto& a,const auto& b){return std::stoull(a.filename().wstring().substr(prefix.size()))<std::stoull(b.filename().wstring().substr(prefix.size()));});return result;
}
std::filesystem::path Key(const std::filesystem::path& certificate){const auto bytes=Read(certificate);Check(bytes.size()>64,"protected certificate envelope");
 constexpr wchar_t hex[]=L"0123456789abcdef";std::wstring name=L"epoch-";
 for(std::size_t i=48;i<64;++i){const auto n=static_cast<unsigned char>(bytes[i]);name+=hex[n>>4];name+=hex[n&15];}
 return certificate.parent_path()/(name+L".key");
}
}
int wmain(int argc,wchar_t** argv)try{
 Check(argc==3,"root and focused mode required");const std::filesystem::path root(argv[1]);const std::wstring mode(argv[2]);
 Check(root.is_absolute()&&root.native().starts_with(L"D:\\ApfsAccessScratch\\WindowsClosure\\fusion-service-20261017\\"),"private regular image scope");
 auto runtime=Open(root,false);Check(bool(runtime)&&runtime->Recover(error),"fresh actual owner");
 const bool held=mode==L"private";if(held)Check(runtime->UnlinkRetainingFile(30,error),"actual retained unlink");
 for(unsigned i=0;i<12;++i)Check(runtime->Overwrite(30,held?i*262144ull:0,std::vector<std::byte>(262144,std::byte{0x66}),error),"actual accepted write through continuation");
 const auto certs=Certificates(root);Check(certs.size()>=3,"multiple authenticated predecessor epochs");
 if(held){
  Check(runtime->HasRetainedFile(30),"private ownership survives cached census leases");runtime.reset();runtime=Open(root,true);
  Check(bool(runtime)&&runtime->Recover(error)&&!runtime->HasRetainedFile(30),"fresh owner retires original retained lifetime");
 }else if(mode==L"key-tamper"||mode==L"key-missing"){
  const auto key=Key(certs.front());Check(key!=Key(certs.back()),"older key is distinct from authenticated head key");
  const auto original=Read(key);Check(!original.empty(),"bounded original encrypted key slot retained");
  const auto saved=key.wstring()+L".test-held";
  if(mode==L"key-tamper"){auto changed=original;changed.back()^=1;Write(key,changed);}else std::filesystem::rename(key,saved);
  bool refused=false;
  for(unsigned i=0;i<6&&!refused;++i){const auto before=runtime->Watermarks();const bool ok=runtime->Overwrite(30,0,std::vector<std::byte>(262144,std::byte{0x66}),error);
   if(!ok){refused=true;const auto after=runtime->Watermarks();Check(before.accepted_sequence==after.accepted_sequence&&before.apfs_durable_sequence==after.apfs_durable_sequence&&before.cleanup_sequence==after.cleanup_sequence,"ancestor-key refusal precedes new acceptance");
    Check(error.find("Authentication")!=std::string::npos||error.find("Key")!=std::string::npos||error=="FusionContinuationPredecessorChain","ancestor actual key authentication is retained");
    std::cout<<"Ancestor slot refusal: "<<error<<'\n';}}
  Check(refused,"cached witness census cannot bypass older ancestor key slot");
  if(mode==L"key-tamper")Write(key,original);else std::filesystem::rename(saved,key);
  Check(runtime->Overwrite(30,0,std::vector<std::byte>(262144,std::byte{0x66}),error),"exact key restoration permits validated continuation");
 }else if(mode==L"witness-lease"){
  const auto witness=root/L"private.wal.fusion-2.witness";
  HANDLE write=CreateFileW(witness.c_str(),GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,0,nullptr);
  const auto reason=GetLastError();Check(write==INVALID_HANDLE_VALUE&&reason==ERROR_SHARING_VIOLATION,"old witness actual write lease refused while census cached");
  runtime.reset();auto original=Read(witness);auto changed=original;changed.back()^=1;Write(witness,changed);
  const auto before=Read(root/L"private.wal");runtime=Open(root,true);Check(!runtime,"fresh owner does not inherit predecessor witness verdict");Check(Read(root/L"private.wal")==before,"fresh tamper refusal preserves original WAL");Write(witness,original);
  runtime=Open(root,true);Check(bool(runtime)&&runtime->Recover(error),"restored original witness fresh owner");
 }else if(mode==L"witness-alias"){
  const auto witness=root/L"private.wal.fusion-2.witness",alias=root/L"test-owned-witness-alias";
  Check(CreateHardLinkW(alias.c_str(),witness.c_str(),nullptr)!=FALSE,"actual alias added to old pinned witness");
  bool refused=false;
  for(unsigned i=0;i<6&&!refused;++i){const auto before=runtime->Watermarks();
   if(!runtime->Overwrite(30,0,std::vector<std::byte>(4096,std::byte{0x66}),error)){
    refused=true;const auto after=runtime->Watermarks();
    Check(before.accepted_sequence==after.accepted_sequence&&before.apfs_durable_sequence==after.apfs_durable_sequence&&before.cleanup_sequence==after.cleanup_sequence,
     "cached witness metadata refusal precedes new acceptance");}}
  Check(refused,"alias invalidates historical witness census");runtime.reset();
  const auto before=Read(root/L"private.wal");runtime=Open(root,true);
  Check(!runtime&&Read(root/L"private.wal")==before,"fresh alias refusal leaves original WAL unchanged");
  Check(DeleteFileW(alias.c_str())!=FALSE,"exact owned alias removal");runtime=Open(root,true);
  Check(bool(runtime)&&runtime->Recover(error)&&runtime->Overwrite(30,0,std::vector<std::byte>(4096,std::byte{0x66}),error),"restored single-link original resumes safely");
 }else if(mode==L"pending"||mode==L"pending-no-witness"){
  const auto before=runtime->Watermarks();bool cut=false;
  Check(!runtime->Overwrite(30,0,std::vector<std::byte>(4096,std::byte{0x44}),error,
   [&](std::string_view stage){if(stage==(mode==L"pending"?"after-fusion-witness":"after-fusion-accept")){cut=true;return false;}return true;})&&cut,
   "actual accepted cut after warmed predecessor census");
  const auto pending=runtime->Watermarks();
  Check(pending.accepted_sequence>before.accepted_sequence&&pending.apfs_durable_sequence==before.apfs_durable_sequence&&pending.cleanup_sequence==before.cleanup_sequence,
   "cut keeps real original accepted debt");
  runtime.reset();runtime=Open(root,true);
  Check(bool(runtime)&&runtime->Recover(error),"fresh pending owner authenticates and publishes original exact boundary");
  std::vector<std::byte> actual;
  Check(runtime->ReadFile(30,0,4096,actual,error)&&actual==std::vector<std::byte>(4096,std::byte{0x44}),"fresh pending owner reads exact accepted bytes");
 }else Check(false,"unknown focused mode");
 const auto water=runtime->Watermarks();Check(water.accepted_sequence==water.apfs_durable_sequence&&water.accepted_sequence==water.cleanup_sequence,"final original fences equal");
 std::cout<<"PASS "<<checks<<" actual continuation-prefix checks\n";return 0;
}catch(const std::exception& ex){std::cerr<<"FAIL "<<ex.what()<<'\n';return 1;}
