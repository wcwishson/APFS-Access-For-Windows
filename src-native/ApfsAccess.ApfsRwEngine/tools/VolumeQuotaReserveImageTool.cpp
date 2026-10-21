#include "VolumeMetadata.h"
#include "ApfsSharedSpace.h"
#include "VolumeKeeperWal.h"
#include "VolumeKeeperOriginalWal.h"
#include "WindowsImageLease.h"
#include <bcrypt.h>
#include <filesystem>
#include <iostream>
#include <map>
#include <set>
#include <charconv>
#include <cwctype>
#include <utility>

using namespace apfsaccess::rw;
using namespace apfsaccess::catalog;
namespace {
std::string Utf8(std::wstring_view text) {
    if(text.empty())return {};
    int n=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,text.data(),static_cast<int>(text.size()),nullptr,0,nullptr,nullptr);
    if(n<=0)throw std::runtime_error("invalid Unicode argument");std::string out(n,' ');
    WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,text.data(),static_cast<int>(text.size()),out.data(),n,nullptr,nullptr);return out;
}
std::uint64_t Number(const std::string& text) {
    std::uint64_t n=0;auto [end,ec]=std::from_chars(text.data(),text.data()+text.size(),n);
    if(text.empty()||ec!=std::errc{}||end!=text.data()+text.size())throw std::runtime_error("expected exact unsigned integer");return n;
}
std::filesystem::path LocalPath(const std::wstring& value) {
    if(value.size()<4||!((value[0]>=L'A'&&value[0]<=L'Z')||(value[0]>=L'a'&&value[0]<=L'z'))||value[1]!=L':'||
        (value[2]!=L'\\'&&value[2]!=L'/')||value.find(L':',2)!=std::wstring::npos)
        throw std::runtime_error("quota command requires an absolute local regular path");
    auto root=value.substr(0,3);root[2]=L'\\';
    if(GetDriveTypeW(root.c_str())!=DRIVE_FIXED)
        throw std::runtime_error("quota command requires a local fixed filesystem");
    auto path=std::filesystem::path(value).lexically_normal();
    for(auto parent=path;!parent.empty()&&parent!=parent.root_path();parent=parent.parent_path()) {
        const auto attrs=GetFileAttributesW(parent.c_str());
        if(attrs!=INVALID_FILE_ATTRIBUTES&&(attrs&FILE_ATTRIBUTE_REPARSE_POINT))throw std::runtime_error("reparse paths refused");
    }
    return path;
}
std::string Digest(std::span<const std::byte> bytes) {
    BCRYPT_ALG_HANDLE alg=nullptr;std::array<unsigned char,32> hash{};
    if(BCryptOpenAlgorithmProvider(&alg,BCRYPT_SHA256_ALGORITHM,nullptr,0)<0)throw std::runtime_error("SHA256 provider failed");
    auto status=BCryptHash(alg,nullptr,0,reinterpret_cast<PUCHAR>(const_cast<std::byte*>(bytes.data())),static_cast<ULONG>(bytes.size()),hash.data(),32);
    BCryptCloseAlgorithmProvider(alg,0);if(status<0)throw std::runtime_error("SHA256 failed");
    std::string out;const char hex[]="0123456789abcdef";for(auto b:hash){out+=hex[b>>4];out+=hex[b&15];}return out;
}
class DeviceSource final:public RandomAccessSource {
    const BlockDevice& d;
public:explicit DeviceSource(const BlockDevice& value):d(value){}
    std::uint64_t SizeBytes()const override{return d.GetGeometry().total_bytes;}
    bool Read(std::uint64_t offset,std::size_t size,std::vector<std::byte>& out)const override{return d.Read(offset,size,out)&&out.size()==size;}
};
void Require(bool ok,const std::string& error){if(!ok)throw std::runtime_error(error);}
using OriginalWal = volume_keeper::OriginalWal;
}
int wmain(int argc,wchar_t** argv) {
    try {
        if(argc==1){std::cout<<"Offline regular-image quota/reserve command. Required: --image ABSOLUTE_LOCAL_IMAGE --offset N --container UUID32 --volume UUID32 --oid N --xid N --quota-blocks N --reserve-blocks N --wal OID=ABSOLUTE_LOCAL_WAL (every volume). Choose --dry-run or --commit --confirm SHA256. Add --recover for an accepted operation20 WAL. Zero quota clears the maximum; zero reserve clears the reservation.\n";return 2;}
        std::map<std::wstring,std::wstring> args;std::map<std::uint64_t,std::filesystem::path> paths;
        bool dry=false,commit=false,recover=false;
        const std::set<std::wstring> names={L"--image",L"--offset",L"--container",L"--volume",L"--oid",L"--xid",L"--quota-blocks",L"--reserve-blocks",L"--confirm"};
        for(int i=1;i<argc;++i){std::wstring key=argv[i];
            if(key==L"--dry-run"){Require(!dry,"duplicate dry-run");dry=true;continue;}
            if(key==L"--commit"){Require(!commit,"duplicate commit");commit=true;continue;}
            if(key==L"--recover"){Require(!recover,"duplicate recover");recover=true;continue;}
            Require(i+1<argc,"missing argument value");std::wstring value=argv[++i];
            if(key==L"--wal"){auto split=value.find(L'=');Require(split!=std::wstring::npos,"WAL syntax OID=absolute-local-path");
                auto oid=Number(Utf8(value.substr(0,split)));Require(paths.emplace(oid,LocalPath(value.substr(split+1))).second,"duplicate WAL OID");continue;}
            Require(names.contains(key)&&args.emplace(key,value).second,"unknown or duplicate option");
        }
        Require(dry!=commit,"choose exactly one of dry-run and commit");
        for(auto key:{L"--image",L"--offset",L"--container",L"--volume",L"--oid",L"--xid",L"--quota-blocks",L"--reserve-blocks"})Require(args.contains(key),"missing exact target/limit field");
        Require(commit==args.contains(L"--confirm"),"commit requires confirmation; dry-run does not take one");
        auto image=LocalPath(args.at(L"--image"));auto offset=Number(Utf8(args.at(L"--offset")));
        auto uuid=Utf8(args.at(L"--container")),volume=Utf8(args.at(L"--volume"));
        auto oid=Number(Utf8(args.at(L"--oid"))),xid=Number(Utf8(args.at(L"--xid")));
        auto quota=Number(Utf8(args.at(L"--quota-blocks"))),reserve=Number(Utf8(args.at(L"--reserve-blocks")));
        Require(ValidRenameUuid(uuid)&&ValidRenameUuid(volume)&&oid&&xid,"invalid exact target");
        std::string error;
        auto owner=ContainerMountCoordinator::Open(Utf8(image.wstring()),offset,error,CatalogLoadPolicy::StrictApple,true,true,true);
        Require(!!owner,error);Require(owner->ContainerUuidHex()==uuid&&owner->CheckpointXid()==xid,"exact container/XID mismatch");
        DeviceSource source(owner->Device());auto cp=LoadAppleCheckpointView(source,0,source.SizeBytes(),error);Require(!!cp,error);
        Require(paths.size()==cp->volumes.size()&&paths.contains(oid),"complete explicit per-volume WAL census required");
        std::vector<VolumeCheckpointPins> census;std::map<std::uint64_t,std::unique_ptr<TransactionManager>> journals;
        std::map<std::uint64_t,std::vector<TransactionManager::AcceptedTransaction>> inspected;
        std::map<std::uint64_t,TransactionManager::DurabilityWatermarks> observed;
        std::map<std::uint64_t,std::unique_ptr<OriginalWal>> originals;
        std::set<std::wstring> unique_paths;
        for(const auto& v:cp->volumes){const auto id=v.superblock.object_id;Require(paths.contains(id),"sibling WAL missing");
            auto wal=paths.at(id);auto normalized=wal.wstring();for(auto& c:normalized)c=std::towlower(c);
            Require(unique_paths.insert(normalized).second,"WAL paths must be distinct");
            Require(!std::filesystem::exists(wal)||!std::filesystem::equivalent(image,wal),"WAL cannot alias image");
            Require(std::filesystem::is_directory(wal.parent_path()),"WAL parent must already exist");
            for(const auto& [peer,other]:journals)if(std::filesystem::exists(wal)&&std::filesystem::exists(paths.at(peer)))
                Require(!std::filesystem::equivalent(wal,paths.at(peer)),"WAL hardlink alias refused");
            auto original=std::make_unique<OriginalWal>(wal);
            const auto identities=AcquireVolumeKeeperWalLeases(wal,uuid,id,original->leases,"VolumeQuota");
            auto identity=identities.production;
            const auto records=WriteAheadLog::ReadAll(wal,"");
            Require(records.status==WriteAheadLog::ReadStatus::Ok&&!records.recovered_torn_tail,"original WAL strict inspection failed");
            bool first_record=true;
            for(const auto& record:records.records){
                Require(record.volume_identity==identities.canonical||record.volume_identity==identities.production,"original WAL identity unproven");
                if(first_record){identity=record.volume_identity;first_record=false;}
                else Require(record.volume_identity==identity,"original WAL mixed identities");
            }
            original->identity=identity;
            originals.emplace(id,std::move(original));
            bool loaded=TransactionManager::InspectAcceptedTransactionsReadOnly(wal,identity,inspected[id],observed[id],error);Require(loaded,error);
            Require((id==oid&&recover)||inspected[id].empty(),"conflicting accepted session or replay");
            VolumeCheckpointPins pins;pins.volume_object_id=id;
            pins.unapplied_accepted_work=observed[id].accepted_sequence>observed[id].apfs_durable_sequence;
            for(const auto& tx:inspected[id]){Require(tx.preimage_checkpoint_xid!=0,"WAL preimage missing");pins.required_checkpoint_xids.push_back(tx.preimage_checkpoint_xid);}
            census.push_back(pins);
            auto journal=std::make_unique<TransactionManager>(L"Strict");
            journals.emplace(id,std::move(journal));
        }
        ContainerVolumeSession session;session.volume_object_id=oid;session.container_uuid_hex=uuid;session.requested_write=true;session.use_canonical_transaction=true;
        session.metadata_context.allow_legacy_scaffold_for_fixtures=false;
        bool ok=owner->MountVolume(session,error);Require(ok,error);ok=owner->InitializeRequiredCheckpointCensus(census,error);Require(ok,error);
        auto* store=owner->FindSessionStore(oid);Require(store&&store->Context().volume_uuid_hex==volume,"exact volume UUID/OID mismatch");
        auto& journal=*journals.at(oid);VolumeQuotaReservePlan plan;std::vector<std::byte> binding;
        if(!recover){ok=PrepareVolumeQuotaReserve(*owner,oid,quota,reserve,plan,error);Require(ok,error);binding=plan.request.inline_payload;}
        else {
            const auto& debt=inspected.at(oid);
            Require(debt.size()==1&&debt[0].mutations.size()==1,"recovery requires one actual accepted intent");
            const auto& record=debt[0].mutations[0];NativeVolumeQuotaReserve intent;
            Require(record.operation==WriteAheadLog::OperationKind::SetVolumeQuotaReserve&&WriteAheadLog::VolumeQuotaReserveIsConsistent(record)&&DecodeNativeVolumeQuotaReserve(record.inline_payload,intent),"invalid operation20 WAL");
            std::string imageid;Require(owner->Device().QueryRegularImageIdentity(imageid),"image identity unavailable");
            Require(intent.volume==oid&&intent.volume_uuid==volume&&intent.container_uuid==uuid&&intent.image_identity==imageid&&intent.quota_blocks==quota&&intent.reserve_blocks==reserve,"WAL recovery target mismatch");
            Require(intent.checkpoint==debt[0].preimage_checkpoint_xid,"WAL preimage/intent mismatch");
            // Recovery preview must establish the same source/publication proof
            // as replay before issuing a token or acquiring writable journals.
            if (xid==intent.checkpoint) {
                MetadataStore::MutationRequest request;
                request.operation=MetadataStore::MutationOperation::SetVolumeQuotaReserve;request.path=L"\\";
                request.object_id=intent.volume;request.generation=record.parent_object_id;
                request.inline_payload=record.inline_payload;request.length=request.inline_payload.size();
                ok=ValidateVolumeMetadataMutation(*store,request,error);Require(ok,error);
                std::vector<std::uint64_t> required;
                for(const auto& pins:census)required.insert(required.end(),pins.required_checkpoint_xids.begin(),pins.required_checkpoint_xids.end());
                AppleVolumeTransactionPlan preview;
                ok=PlanVolumeMetadataCheckpoint(source,*cp,intent,required,preview,error);Require(ok,error);
            } else {
                ok=VerifyPublishedVolumeRename(*store,intent,error);Require(ok,error);
            }
            binding=record.inline_payload;
        }
        const auto bindText=std::string(recover?"recover:":"apply:")+std::to_string(xid)+":"+Utf8(image.wstring());
        const auto append=[&](std::string_view t){for(unsigned i=0;i<8;++i)binding.push_back(std::byte((std::uint64_t(t.size())>>(8*i))&255));for(unsigned char c:t)binding.push_back(std::byte(c));};
        append(bindText);for(const auto& [id,wal]:paths){append(std::to_string(id));append(Utf8(wal.wstring()));append(originals.at(id)->identity);append(originals.at(id)->FileBinding());}
        for(const auto& [id,w]:observed){append(std::to_string(id));append(std::to_string(w.accepted_sequence));append(std::to_string(w.apfs_durable_sequence));append(std::to_string(w.cleanup_sequence));}
        const auto token=Digest(binding);
        ApfsSharedSpaceProjection space;ok=TryProjectAppleSharedSpace(*cp,space,error);Require(ok,error);
        std::cout<<"{\"operation\":20,\"xid\":"<<xid<<",\"oid\":"<<oid<<",\"quotaBlocks\":"<<quota<<",\"reserveBlocks\":"<<reserve<<",\"blockBytes\":"<<space.allocation_unit_bytes<<",\"freeBlocks\":"<<space.free.blocks<<",\"confirm\":\""<<token<<"\",\"volumes\":[";
        bool first=true;for(const auto& v:space.volumes){if(!first)std::cout<<',';first=false;std::cout<<"{\"oid\":"<<v.object_id<<",\"charged\":"<<v.allocated.blocks<<",\"quota\":"<<(v.quota?v.quota->blocks:0)<<",\"reserve\":"<<(v.reserve?v.reserve->blocks:0)<<'}';}std::cout<<"]}\n";
        std::cout.flush();
        Require(std::cout.good(),"QuotaPlanOutputFailed");
        if(dry)return 0;
        Require(Utf8(args.at(L"--confirm"))==token,"confirmation does not bind this exact plan");
        // Keep the original files fenced until their selected identity has moved
        // to the transaction owner. The alternate legal identity remains leased.
        for(auto& [id,j]:journals) {
            auto& original=*originals.at(id);const auto& identity=original.identity;
            j->SetVolumeIdentity(std::wstring(identity.begin(),identity.end()));
            j->SetJournalPath(paths.at(id).wstring(),false);
            Require(j->RecoveryStateValid(),"original WAL read-only binding failed");
            const auto identities=VolumeKeeperWalIdentities{"apfs-vol:"+uuid+":"+std::to_string(id),DerivePartitionlessVolumeRecoveryIdentity(uuid,id)};
            original.leases[identity==identities.canonical?0:1].reset();
            ok=j->AcquireJournalOwnership(error);Require(ok,error);
            Require(j->EnrollCanonicalJournalIdentity(std::wstring(identities.canonical.begin(),identities.canonical.end())),"resolved canonical journal enrollment failed");
            original.read_fence.reset();
            original.Verify(paths.at(id));
            Require(j->RecoveryStateValid(),"WAL owner conflict");
            std::vector<TransactionManager::AcceptedTransaction> current;
            ok=j->LoadAcceptedTransactionsSinceCleanup(current,&error);Require(ok,error);
            original.Verify(paths.at(id));
            const auto& w=observed.at(id);const auto now=j->Watermarks();
            Require(w.accepted_sequence==now.accepted_sequence&&w.apfs_durable_sequence==now.apfs_durable_sequence&&w.cleanup_sequence==now.cleanup_sequence&&current.size()==inspected.at(id).size(),"WAL census changed after dry-run");
            for(std::size_t i=0;i<current.size();++i){const auto& old=inspected.at(id)[i];const auto& next=current[i];
                Require(old.accepted_sequence==next.accepted_sequence&&old.preimage_checkpoint_xid==next.preimage_checkpoint_xid&&old.mutations.size()==next.mutations.size(),"WAL transaction changed");
                for(std::size_t n=0;n<old.mutations.size();++n)Require(WriteAheadLog::EncodeForTest(old.mutations[n])==WriteAheadLog::EncodeForTest(next.mutations[n]),"WAL intent changed");
            }
        }
        if(recover){auto result=ReplayVolumeQuotaReserve(*owner,journal,oid,error);Require(result.value_or(false),error);}
        else {const auto result=ApplyVolumeQuotaReserve(*owner,journal,plan);Require(result.committed&&!result.commit_recovery_required&&result.commit_status_code==static_cast<int>(MetadataStore::CommitStatus::Committed),result.error);}
        std::cout<<"{\"durable\":true,\"checkpointXid\":"<<owner->CheckpointXid()<<",\"cleanupSequence\":"<<journal.Watermarks().cleanup_sequence<<"}\n";
        std::cout.flush();
        Require(std::cout.good(),"QuotaDurableResultOutputFailed");
        return 0;
    }catch(const std::exception& e){std::cerr<<"REFUSED "<<e.what()<<"\n";return 1;}
}
