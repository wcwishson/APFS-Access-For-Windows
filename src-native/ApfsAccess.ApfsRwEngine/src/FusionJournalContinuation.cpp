#include "FusionJournalContinuation.h"
#include "FusionPublicationInternal.h"
#include "ProtectedJournalEpoch.h"
#include "FusionContinuationCompression.h"
#include <algorithm>
#include <Windows.h>

namespace apfsaccess::rw {
namespace {
using Bytes=std::vector<std::byte>;
using Digest=std::array<std::byte,32>;
constexpr std::size_t Limit=8u<<20, Chunk=64u<<10;
constexpr std::uint64_t Magic=0x31434e4f495346ULL;
bool Fail(std::string& e,const char* why){e=why;return false;}
bool Cancelled(const std::atomic<bool>* token,std::string& e){
    if(token&&token->load()){e="FusionContinuationCancelled";return true;}return false;
}
void U64(Bytes& b,std::uint64_t n){for(unsigned i=0;i<8;++i)b.push_back(std::byte((n>>(8*i))&255));}
void Blob(Bytes& b,std::span<const std::byte> v){U64(b,v.size());b.insert(b.end(),v.begin(),v.end());}
struct Cursor {
    std::span<const std::byte> bytes;std::size_t at=0;bool ok=true;
    std::uint64_t Number(){if(bytes.size()-at<8){ok=false;return 0;}std::uint64_t n=0;
        for(unsigned i=0;i<8;++i)n|=std::uint64_t(std::to_integer<unsigned>(bytes[at++]))<<(8*i);return n;}
    Bytes Read(std::size_t max=Limit){const auto n=Number();if(!ok||n>max||n>bytes.size()-at){ok=false;return {};}
        Bytes result(bytes.begin()+at,bytes.begin()+at+static_cast<std::size_t>(n));at+=static_cast<std::size_t>(n);return result;}
};
struct File {HANDLE h=INVALID_HANDLE_VALUE;~File(){if(h!=INVALID_HANDLE_VALUE)CloseHandle(h);}};
std::wstring Path(const std::wstring& original,std::uint64_t floor){return original+L".fusion-continue-"+std::to_wstring(floor)+L".cert";}
bool Read(const std::wstring& path,Bytes& bytes,std::string& e){
    File f;f.h=CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    if(f.h==INVALID_HANDLE_VALUE)return Fail(e,GetLastError()==ERROR_FILE_NOT_FOUND?"FusionContinuationMissing":"FusionContinuationOpen");
    BY_HANDLE_FILE_INFORMATION info{};LARGE_INTEGER size{};DWORD done=0;
    if(!GetFileInformationByHandle(f.h,&info)||info.nNumberOfLinks!=1||
        (info.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT))||
        !GetFileSizeEx(f.h,&size)||size.QuadPart<=0||size.QuadPart>Limit)return Fail(e,"FusionContinuationFileBounds");
    bytes.resize(static_cast<std::size_t>(size.QuadPart));
    return (ReadFile(f.h,bytes.data(),static_cast<DWORD>(bytes.size()),&done,nullptr)&&done==bytes.size())||Fail(e,"FusionContinuationRead");
}
bool Context(const std::wstring& jid,std::uint64_t floor,journal::JournalRecordContext& context){
    const auto text=TransactionManager::WideToUtf8(jid);Bytes bytes;Blob(bytes,std::as_bytes(std::span(text)));U64(bytes,Magic);U64(bytes,floor);
    context.purpose=0x46554331;return FusionPublicationHash(bytes,context.operation);
}
bool Unseal(const std::wstring& original,const std::wstring& jid,std::uint64_t floor,const Digest& source,
    std::span<const std::byte> sealed,Bytes& plain,std::string& e,journal::ProtectedJournalReadPass* reader){
    Cursor c{sealed};if(c.Number()!=Magic)return Fail(e,"FusionContinuationEnvelope");
    const auto count=c.Number();if(!count||count>128)return Fail(e,"FusionContinuationFrameCount");
    journal::JournalReadPassAcquisition pass;
    if(!reader){pass=journal::ProtectedJournalReadPass::Acquire(std::filesystem::path(original).parent_path().wstring(),source);
        if(!pass)return Fail(e,"FusionContinuationKey");reader=pass.reader.get();}
    journal::JournalRecordContext context;if(!Context(jid,floor,context))return Fail(e,"FusionContinuationKey");
    Bytes stored;plain.clear();
    for(std::uint64_t i=0;i<count;++i){auto frame=c.Read(journal::kMaxJournalRecordBytes);context.chunk=i;
        if(!c.ok)return Fail(e,"FusionContinuationFrameBounds");auto result=reader->Open(context,frame);
        if(!result||result.bytes.Size()>Limit-stored.size())return Fail(e,"FusionContinuationAuthentication");
        const auto data=result.bytes.Bytes();stored.insert(stored.end(),data.begin(),data.end());}
    if(!c.ok||c.at!=sealed.size())return Fail(e,"FusionContinuationTrailingBytes");
    return fusion_continuation::Unpack(stored,plain)||Fail(e,"FusionContinuationCompressionBounds");
}
bool Protect(const std::wstring& original,const std::wstring& jid,std::uint64_t floor,const Digest& source,
    std::span<const std::byte> plain,Bytes& sealed,std::string& e){
    if(plain.empty()||plain.size()>Limit-4096)return Fail(e,"FusionContinuationArchiveBounds");
    Bytes stored;if(!fusion_continuation::Pack(plain,stored))return Fail(e,"FusionContinuationCompressionBounds");
    auto epoch=journal::ProtectedJournalEpoch::AcquireWriter(std::filesystem::path(original).parent_path().wstring(),source);
    journal::JournalRecordContext context;if(!epoch||!Context(jid,floor,context))return Fail(e,"FusionContinuationKeyCreate");
    sealed.clear();U64(sealed,Magic);U64(sealed,(stored.size()+Chunk-1)/Chunk);
    for(std::size_t at=0;at<stored.size();at+=Chunk,++context.chunk){
        auto frame=epoch.epoch->Seal(context,std::span<const std::byte>(stored).subspan(at,(std::min)(Chunk,stored.size()-at)));
        if(!frame){e="FusionContinuationSeal:"+std::to_string(static_cast<unsigned>(frame.status.error))+":"+
            std::to_string(frame.status.os_status);return false;}Blob(sealed,frame.bytes.Bytes());}
    File f;const auto path=Path(original,floor);
    f.h=CreateFileW(path.c_str(),GENERIC_READ|GENERIC_WRITE,0,nullptr,CREATE_NEW,
        FILE_FLAG_WRITE_THROUGH|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    DWORD done=0;if(f.h==INVALID_HANDLE_VALUE||!WriteFile(f.h,sealed.data(),static_cast<DWORD>(sealed.size()),&done,nullptr)||
        done!=sealed.size()||!FlushFileBuffers(f.h))return Fail(e,"FusionContinuationArchiveDurability");
    Bytes actual(sealed.size());LARGE_INTEGER zero{};
    if(!SetFilePointerEx(f.h,zero,nullptr,FILE_BEGIN)||!ReadFile(f.h,actual.data(),static_cast<DWORD>(actual.size()),&done,nullptr)||
        done!=actual.size()||actual!=sealed)return Fail(e,"FusionContinuationArchiveReadback");
    return true;
}
std::uint64_t Floor(const std::vector<WriteAheadLog::Record>& rows){
    std::uint64_t floor=0;for(const auto& r:rows)if(r.operation==WriteAheadLog::OperationKind::CompactionIndex){
        if(floor)return UINT64_MAX;floor=r.sequence;}return floor;
}
}

struct FusionJournalContinuation::Certificate {
    FusionOriginalCapture original;
    Digest source{},previous_hash{},sealed_hash{};
    std::uint64_t previous_floor=0,origin_xid=0,base_xid=0,end_xid=0,volume=0;
    std::map<std::uint64_t,std::uint64_t> private_files;
    std::vector<std::pair<std::uint64_t,std::string>> census;
};
bool FusionJournalContinuation::Replacement(const FusionOriginalCapture& c,std::vector<std::uint8_t>& bytes){
    bytes.clear();for(const auto& r:c.records)if(r.operation!=WriteAheadLog::OperationKind::CompactionIndex&&r.sequence>=c.floor){
        auto encoded=WriteAheadLog::EncodeForTest(r);if(encoded.empty())return false;bytes.insert(bytes.end(),encoded.begin(),encoded.end());}
    WriteAheadLog::Record index;index.volume_identity=c.identity;index.sequence=c.floor;
    index.operation=WriteAheadLog::OperationKind::CompactionIndex;index.state=WriteAheadLog::RecordState::Cleaned;
    auto encoded=WriteAheadLog::EncodeForTest(index);bytes.insert(bytes.end(),encoded.begin(),encoded.end());return !bytes.empty();
}
bool FusionJournalContinuation::Encode(const Certificate& c,Bytes& b,std::string& e){
    b.clear();U64(b,Magic);U64(b,c.original.floor);U64(b,c.previous_floor);Blob(b,c.previous_hash);Blob(b,c.source);
    for(auto n:{c.origin_xid,c.base_xid,c.end_xid,c.volume,c.original.volume_serial,c.original.file_id,
        c.original.next_transaction,c.original.next_sequence,c.original.accepted})U64(b,n);
    Blob(b,std::as_bytes(std::span(c.original.identity)));Blob(b,std::as_bytes(std::span(c.original.bytes)));
    U64(b,c.private_files.size());for(const auto& [id,xid]:c.private_files){U64(b,id);U64(b,xid);}
    U64(b,c.census.size());for(const auto& [seq,hash]:c.census){U64(b,seq);Blob(b,std::as_bytes(std::span(hash)));}
    return b.size()<=Limit-4096||Fail(e,"FusionContinuationCertificateBounds");
}
bool FusionJournalContinuation::Decode(std::span<const std::byte> bytes,Certificate& c,std::string& e){
    c=Certificate{};
    Cursor r{bytes};if(r.Number()!=Magic)return Fail(e,"FusionContinuationCertificateHeader");
    c.original.floor=r.Number();c.previous_floor=r.Number();const auto previous=r.Read(32),source=r.Read(32);
    if(previous.size()!=32||source.size()!=32)return Fail(e,"FusionContinuationCertificateBinding");
    std::copy(previous.begin(),previous.end(),c.previous_hash.begin());std::copy(source.begin(),source.end(),c.source.begin());
    c.origin_xid=r.Number();c.base_xid=r.Number();c.end_xid=r.Number();c.volume=r.Number();
    c.original.volume_serial=r.Number();c.original.file_id=r.Number();c.original.next_transaction=r.Number();
    c.original.next_sequence=r.Number();c.original.accepted=r.Number();
    const auto identity=r.Read(1024),original=r.Read(4u<<20);
    c.original.identity.assign(reinterpret_cast<const char*>(identity.data()),identity.size());
    c.original.bytes.resize(original.size());std::transform(original.begin(),original.end(),c.original.bytes.begin(),
        [](std::byte b){return std::to_integer<std::uint8_t>(b);});
    auto n=r.Number();if(n>4096)return Fail(e,"FusionContinuationPrivateBounds");
    for(std::uint64_t i=0;i<n;++i){const auto id=r.Number(),xid=r.Number();if(!c.private_files.emplace(id,xid).second)return Fail(e,"FusionContinuationPrivateCollision");}
    n=r.Number();if(!n||n>4096)return Fail(e,"FusionContinuationCensusBounds");
    for(std::uint64_t i=0;i<n;++i){const auto seq=r.Number();auto hash=r.Read(64);
        if(hash.size()!=64)return Fail(e,"FusionContinuationCensusHash");c.census.emplace_back(seq,std::string(reinterpret_cast<const char*>(hash.data()),hash.size()));}
    if(!r.ok||r.at!=bytes.size()||!c.original.floor||c.previous_floor>=c.original.floor||!c.origin_xid||
        c.origin_xid>c.base_xid||c.end_xid!=c.base_xid+1||c.end_xid==0)return Fail(e,"FusionContinuationCertificateMalformed");
    const auto decoded=WriteAheadLog::DecodeFusionOriginalForContinuation(c.original.bytes,c.original.identity);
    if(decoded.status!=WriteAheadLog::ReadStatus::Ok||decoded.recovered_torn_tail)return Fail(e,"FusionContinuationOriginalDecode");
    c.original.records=decoded.records;return true;
}
bool FusionJournalContinuation::Load(FusionImageRuntime& r,std::uint64_t floor,const Digest& source,Certificate& c,std::string& e,
    journal::ProtectedJournalReadPass* reader){
    Bytes sealed,plain;if(!Read(Path(r.journal_path_,floor),sealed,e)||
        !Unseal(r.journal_path_,r.transactions_.volume_identity_,floor,source,sealed,plain,e,reader)||!Decode(plain,c,e))return false;
    c.original.path=r.journal_path_;
    if(c.original.floor!=floor||c.source!=source||c.original.identity!=TransactionManager::WideToUtf8(r.transactions_.volume_identity_)||
        !FusionPublicationHash(sealed,c.sealed_hash))return Fail(e,"FusionContinuationSourceMismatch");
    return r.witness_->PinContinuationProof(Path(r.journal_path_,floor),c.sealed_hash,e);
}
bool FusionJournalContinuation::Census(FusionImageRuntime& r,const FusionOriginalCapture& original,Certificate& c,std::string& e,const std::atomic<bool>* cancellation){
    TransactionManager observer(L"strict");
    if(!observer.SeedIdsFromJournalRecords(original.records,0)||observer.next_sequence_!=original.next_sequence||
        observer.next_transaction_id_!=original.next_transaction||observer.watermarks_.accepted_sequence!=original.accepted||
        observer.watermarks_.apfs_durable_sequence!=original.accepted||observer.watermarks_.cleanup_sequence!=original.accepted)
        return Fail(e,"FusionContinuationArchivedFences");
    TransactionManager::RetainedAcceptedHistory history;
    if(!observer.CollectRetainedAcceptedTransactions(original.records,history,e)||!history.pending.empty()||history.cleaned.empty())return false;
    std::vector<std::pair<std::uint64_t,std::string>> census;std::uint64_t xid=history.cleaned.front().preimage_checkpoint_xid;
    for(const auto& row:history.cleaned){
        if(Cancelled(cancellation,e))return false;
        std::unique_ptr<FusionPreparedPublication> p;std::string digest;
        if(row.preimage_checkpoint_xid!=xid||!r.witness_->LoadRetained(row.accepted_sequence,p,e)||!r.Match(*p,row,e,&digest)||
            p->source!=c.source||p->jid!=original.identity||p->volume!=c.volume)return Fail(e,"FusionContinuationWitnessCensus");
        census.emplace_back(row.accepted_sequence,digest);xid=p->plan.transaction_xid;
    }
    if(history.cleaned.back().mutations.front().sequence!=original.floor||
        history.cleaned.back().preimage_checkpoint_xid!=c.base_xid||xid!=c.end_xid)return Fail(e,"FusionContinuationEndpointXid");
    if(c.census.empty())c.census=std::move(census);
    else if(c.census!=census)return Fail(e,"FusionContinuationWitnessCensusChanged");
    return true;
}
bool FusionJournalContinuation::Validate(FusionImageRuntime& r,const FusionOriginalCapture& current,
    const Digest& source,Certificate& head,std::string& e,const std::atomic<bool>* cancellation){
    if(Cancelled(cancellation,e))return false;
    const auto floor=Floor(current.records);
    if(!floor||floor==UINT64_MAX)return Fail(e,"FusionContinuationPredecessorRequired");
    if(!Load(r,floor,source,head,e))return false;
    r.witness_->BindContinuationProof(source,current.identity,head.volume,current.writer_generation,current.volume_serial,current.file_id);
    if(!r.witness_->PinContinuationProof(Path(r.journal_path_,floor),head.sealed_hash,e))return false;
    std::vector<std::uint8_t> replacement;
    if(!Replacement(head.original,replacement)||replacement.size()>current.bytes.size()||
        !std::equal(replacement.begin(),replacement.end(),current.bytes.begin()))return Fail(e,"FusionContinuationReplacementPrefix");
    if(!r.transactions_.journal_.ValidateFusionReplacementReceipt(head.original,current)){
        // A new certified attempt may have retired the prior native receipt
        // before publishing its own intent. Its flushed archive pins these
        // exact still-canonical bytes and physical identity, not a seed.
        std::uint64_t last=0;for(const auto& row:current.records)
            if(row.operation==WriteAheadLog::OperationKind::TransactionMarker&&row.state==WriteAheadLog::RecordState::Accepted)last=row.sequence;
        Certificate attempt;
        if(last<2||last-1<=floor||!Load(r,last-1,source,attempt,e)||attempt.previous_floor!=floor||
            attempt.previous_hash!=head.sealed_hash||attempt.original.bytes!=current.bytes||
            attempt.original.volume_serial!=current.volume_serial||attempt.original.file_id!=current.file_id||
            !ValidateArchiveChain(r,attempt,e,cancellation))return Fail(e,"FusionContinuationReplacementReceipt");
    }
    return ValidateArchiveChain(r,head,e,cancellation);
}
bool FusionJournalContinuation::ValidateArchiveChain(FusionImageRuntime& r,const Certificate& head,std::string& e,const std::atomic<bool>* cancellation){
    // Pin ancestors once for this synchronous walk. Every slot and frame is
    // still reopened and authenticated; the read pass caches at most one key.
    auto pass=journal::ProtectedJournalReadPass::Acquire(std::filesystem::path(r.journal_path_).parent_path().wstring(),head.source);
    if(!pass)return Fail(e,"FusionContinuationKey");
    Certificate segment=head;std::vector<std::uint8_t> replacement;
    for(;;){
        if(Cancelled(cancellation,e)||(r.owner_&&!r.owner_->Available(e)))return false;
        // Only the witness census is reusable. Every ancestor is still loaded,
        // its actual key slot reread, and every GCM frame authenticated below.
        if((!r.witness_->HasContinuationProof(segment.original.floor,segment.sealed_hash)&&
            !Census(r,segment.original,segment,e,cancellation))||Floor(segment.original.records)!=segment.previous_floor)return false;
        r.witness_->RememberContinuationProof(segment.original.floor,segment.sealed_hash,segment.census);
        if(!segment.previous_floor){
            if(segment.original.records.empty()||segment.original.records.front().sequence!=1||
                segment.origin_xid!=segment.original.records.front().parent_object_id||
                std::any_of(segment.previous_hash.begin(),segment.previous_hash.end(),[](auto b){return b!=std::byte{};}))
                return Fail(e,"FusionContinuationFirstOriginal");
            break;
        }
        Certificate previous;if(!Load(r,segment.previous_floor,head.source,previous,e,pass.reader.get())||previous.sealed_hash!=segment.previous_hash||
            previous.origin_xid!=head.origin_xid||previous.volume!=head.volume||
            previous.original.next_sequence>segment.original.next_sequence||
            !Replacement(previous.original,replacement)||replacement.size()>segment.original.bytes.size()||
            !std::equal(replacement.begin(),replacement.end(),segment.original.bytes.begin()))return Fail(e,"FusionContinuationPredecessorChain");
        segment=std::move(previous);
    }
    r.witness_->RememberContinuationProof(head.original.floor,head.sealed_hash,head.census);
    return true;
}
bool FusionJournalContinuation::OpenOriginal(FusionImageRuntime& r,const catalog::FusionBindRequest& request,
    const FusionVolumeSelection& selected,const Digest& source,const std::wstring& jid,std::string& e){
    if(Cancelled(request.cancellation.get(),e))return false;
    if(r.transactions_.OpenStartupJournal(r.journal_path_,jid,e))return true;
    FusionOriginalCapture observed;Certificate certificate;
    if(!r.transactions_.journal_.InspectFusionCompactionRecovery(observed)||
        !Load(r,observed.floor,source,certificate,e)||!ValidateArchiveChain(r,certificate,e,request.cancellation.get())||
        certificate.volume!=selected.volume_oid||certificate.original.volume_serial!=observed.volume_serial||
        certificate.original.file_id!=observed.file_id||(!observed.bytes.empty()&&observed.bytes!=certificate.original.bytes)||
        request.checkpoint_xid<certificate.origin_xid||request.checkpoint_xid>certificate.end_xid)
        return Fail(e,"FusionContinuationRecoveryAuthority");
    TransactionManager observer(L"strict");TransactionManager::RetainedAcceptedHistory history;
    if(!observer.SeedIdsFromJournalRecords(certificate.original.records,0)||
        !observer.CollectRetainedAcceptedTransactions(certificate.original.records,history,e)||history.cleaned.empty()||!history.pending.empty())return false;
    history.writer_lease_generation=observed.writer_generation;
    std::unique_ptr<FusionContinuationAdmission> admission;
    if(certificate.previous_floor){Certificate prior;if(!Load(r,certificate.previous_floor,source,prior,e))return false;
        admission=std::unique_ptr<FusionContinuationAdmission>(new FusionContinuationAdmission);
        admission->origin_xid=prior.origin_xid;admission->base_xid=prior.base_xid;admission->private_files=prior.private_files;}
    auto binding=request;auto selection=selected;
    binding.checkpoint_xid=selection.checkpoint_xid=history.cleaned.front().preimage_checkpoint_xid;
    if(!r.BindRetainedChain(binding,selection,source,jid,history,e,admission.get()))return false;
    File pinned;pinned.h=CreateFileW(Path(r.journal_path_,observed.floor).c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,
        OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    if(pinned.h==INVALID_HANDLE_VALUE)return Fail(e,"FusionContinuationRecoveryArchiveLease");
    const auto expected=certificate.sealed_hash;
    certificate.original.writer_generation=observed.writer_generation;
    FusionCertifiedPredecessor capability;capability.original=&certificate.original;
    capability.revalidate=[&]{Certificate check;return r.owner_->Available(e)&&Load(r,observed.floor,source,check,e)&&check.sealed_hash==expected;};
    if(!r.transactions_.journal_.RecoverFusionCompaction(capability)||!r.transactions_.SeedIdsFromExistingJournal(true))
        return Fail(e,"FusionContinuationRecoveryDebt");
    e.clear();return true;
}
bool FusionJournalContinuation::Admit(FusionImageRuntime& r,TransactionManager::RetainedAcceptedHistory& history,
    const Digest& source,const std::wstring&,std::unique_ptr<FusionContinuationAdmission>& admission,std::string& e,const std::atomic<bool>* cancellation){
    admission.reset();
    if(Cancelled(cancellation,e))return false;
    if(history.coverage!=TransactionManager::RetainedHistoryCoverage::Unavailable)return true;
    FusionOriginalCapture current;Certificate certificate;
    if(!r.transactions_.journal_.CaptureFusionOriginalForContinuation(current)||!Validate(r,current,source,certificate,e,cancellation)||
        history.cleaned.empty()||history.cleaned.front().preimage_checkpoint_xid!=certificate.base_xid)
        return Fail(e,e.empty()?"FusionContinuationAdmission":e.c_str());
    auto result=std::unique_ptr<FusionContinuationAdmission>(new FusionContinuationAdmission);
    result->origin_xid=certificate.origin_xid;result->base_xid=certificate.base_xid;result->private_files=certificate.private_files;
    admission=std::move(result);return true;
}
bool FusionJournalContinuation::Continue(FusionImageRuntime& r,std::string& e,const AppleCheckpointStageHook& hook){
    const auto* cancellation=r.owner_->request_.cancellation.get();
    if(Cancelled(cancellation,e)||!r.owner_->Available(e))return false;
    const auto water=r.transactions_.Watermarks();if(!water.accepted_sequence)return true;
    FusionOriginalCapture original;if(!r.transactions_.CaptureFusionOriginalForContinuation(original,e))return false;
    r.witness_->BindContinuationProof(r.owner_->source_binding_,original.identity,r.owner_->volume_oid_,
        original.writer_generation,original.volume_serial,original.file_id);
    TransactionManager::RetainedAcceptedHistory history;
    if(!r.transactions_.CollectRetainedAcceptedTransactions(original.records,history,e))return false;
    history.writer_lease_generation=original.writer_generation;
    const auto existing=GetFileAttributesW(Path(r.journal_path_,original.floor).c_str());
    // Small namespace operations need no immediate rollover. Eight witnesses
    // fit the 64 MiB retained-proof bound; the byte trigger leaves room under
    // the 2 MiB original preaccept limit for the next bounded inline request.
    if(original.bytes.size()<(1u<<20)&&history.cleaned.size()<8&&existing==INVALID_FILE_ATTRIBUTES){
        return GetLastError()==ERROR_FILE_NOT_FOUND||Fail(e,"FusionContinuationDestinationUnavailable");
    }
    std::unique_ptr<FusionContinuationAdmission> admission;
    if(!Admit(r,history,r.owner_->source_binding_,r.owner_->journal_identity_,admission,e,cancellation))return false;
    // A cut after native replacement leaves the retained last transaction at
    // this floor. Admit proved its exact certificate and replacement receipt;
    // no newer original boundary exists to certify or compact again.
    if(admission&&Floor(original.records)==original.floor)return r.owner_->Available(e);
    auto binding=r.owner_->request_;auto selection=r.owner_->selection_;
    // Fresh Open proves the whole active segment. Each subsequent publication
    // proves its complete old/new graphs before Cleaned. Recheck the endpoint
    // through that same held owner; the original/witness census below still
    // covers every archived acceptance. No external clean-state assertion exists.
    if(history.cleaned.empty()||r.owner_->status_.checkpoint_xid!=history.cleaned.back().preimage_checkpoint_xid+1)
        return Fail(e,"FusionContinuationHeldEndpointXid");
    binding.checkpoint_xid=selection.checkpoint_xid=history.cleaned.back().preimage_checkpoint_xid;
    const auto private_before=r.retained_files_;
    const auto startup_before=r.startup_recovery_;
    if(!r.BindRetainedChain(binding,selection,r.owner_->source_binding_,r.owner_->journal_identity_,history,e,admission.get())||
        r.retained_files_!=private_before)return Fail(e,e.empty()?"FusionContinuationEndpointPrivateCensus":e.c_str());
    r.startup_recovery_=startup_before;
    Certificate certificate;certificate.original=original;certificate.source=r.owner_->source_binding_;
    certificate.volume=r.owner_->volume_oid_;certificate.previous_floor=Floor(original.records);
    certificate.origin_xid=admission?admission->origin_xid:history.cleaned.front().preimage_checkpoint_xid;
    certificate.base_xid=history.cleaned.back().preimage_checkpoint_xid;certificate.end_xid=certificate.base_xid+1;
    certificate.private_files=admission?admission->private_files:std::map<std::uint64_t,std::uint64_t>{};
    const auto final_private=r.retained_files_;r.retained_files_=certificate.private_files;
    for(auto it=history.cleaned.begin();it!=std::prev(history.cleaned.end());++it)r.TrackPrivateBoundary(*it);
    certificate.private_files=r.retained_files_;r.retained_files_=final_private;
    if(certificate.previous_floor){Certificate prior;if(!Load(r,certificate.previous_floor,certificate.source,prior,e))return false;
        certificate.previous_hash=prior.sealed_hash;}
    if(!Census(r,original,certificate,e,cancellation))return false;
    Bytes plain,sealed;if(!Encode(certificate,plain,e))return false;
    if(existing==INVALID_FILE_ATTRIBUTES){
        if(!Protect(r.journal_path_,r.owner_->journal_identity_,original.floor,certificate.source,plain,sealed,e))return false;
    }else{Certificate previous;Bytes exact;
        if(!Load(r,original.floor,certificate.source,previous,e)||!Encode(previous,exact,e)||exact!=plain)
            return Fail(e,"FusionContinuationExistingCertificateMismatch");}
    Certificate verified;Bytes verified_plain;
    if(!Load(r,original.floor,certificate.source,verified,e)||!Encode(verified,verified_plain,e)||verified_plain!=plain)
        return Fail(e,"FusionContinuationArchiveIndependentReadback");
    File pinned;pinned.h=CreateFileW(Path(r.journal_path_,original.floor).c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,
        OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    if(pinned.h==INVALID_HANDLE_VALUE)return Fail(e,"FusionContinuationArchiveLease");
    if(hook&&!hook("fusion-continuation-certified"))return Fail(e,"FusionContinuationInterrupted");
    FusionCertifiedPredecessor capability;capability.original=&original;
    capability.revalidate=[&]{Certificate check;Bytes exact;
        return r.owner_->Available(e)&&Load(r,original.floor,certificate.source,check,e)&&Encode(check,exact,e)&&exact==plain;};
    r.transactions_.SetJournalFaultInjectionHook([&](std::string_view stage){return hook&&!hook(stage);});
    const auto compacted=r.transactions_.CompactFusionOriginalForContinuation(capability,e);
    r.transactions_.SetJournalFaultInjectionHook({});
    if(!compacted)return false;
    // Admit/Census already proved every predecessor before publishing the
    // pinned certificate. The same original gate held through replacement;
    // prove its exact output and receipt without walking the archive twice.
    FusionOriginalCapture current;Certificate retained;std::vector<std::uint8_t> replacement;
    if(Cancelled(cancellation,e)||!r.transactions_.journal_.CaptureFusionOriginalForContinuation(current)||
        Floor(current.records)!=original.floor||!Replacement(original,replacement)||current.bytes!=replacement||
        !r.transactions_.journal_.ValidateFusionReplacementReceipt(original,current)||
        !Load(r,original.floor,certificate.source,retained,e)||retained.sealed_hash!=verified.sealed_hash||
        !r.owner_->Available(e))return Fail(e,e.empty()?"FusionContinuationReplacementEvidence":e.c_str());
    r.witness_->AdvanceContinuationProof(certificate.source,original.identity,certificate.volume,
        current.writer_generation,current.volume_serial,original.file_id,current.file_id);
    r.witness_->RememberContinuationProof(original.floor,retained.sealed_hash,retained.census);
    return !hook||hook("fusion-continuation-complete")||Fail(e,"FusionContinuationInterrupted");
}
}
