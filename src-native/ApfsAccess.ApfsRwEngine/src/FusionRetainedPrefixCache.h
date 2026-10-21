#pragma once
#include <Windows.h>
#include <bcrypt.h>
#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace apfsaccess::rw {
// Process-local witness-census reuse under deny-write/delete evidence leases.
// Certificate traversal, key-slot reads and GCM authentication are not cached.
template<std::size_t PinLimit=8192> class FusionRetainedPrefixCache final {
    static_assert(PinLimit>0&&PinLimit<=8192);
public:
    using Digest=std::array<std::byte,32>;
    struct Domain {
        Digest source{};std::string journal;
        std::uint64_t volume=0,generation=0,serial=0,file=0;
        bool operator==(const Domain&) const = default;
    };
private:
    struct Pin {
        HANDLE handle=INVALID_HANDLE_VALUE;Digest hash{};std::uint64_t size=0;
        Pin()=default;Pin(const Pin&)=delete;Pin& operator=(const Pin&)=delete;
        Pin(Pin&& p) noexcept:handle(p.handle),hash(p.hash),size(p.size){p.handle=INVALID_HANDLE_VALUE;}
        ~Pin(){if(handle!=INVALID_HANDLE_VALUE)CloseHandle(handle);}
    };
    static constexpr std::size_t MaxFileBytes=8u<<20;
    Domain domain_{};bool bound_=false,disabled_=false;
    std::map<std::wstring,Pin> pins_;
    struct Prefix {Digest hash{};std::vector<const Pin*> evidence;};
    std::map<std::uint64_t,Prefix> prefixes_;
    std::size_t references_=0;
    void Clear(){prefixes_.clear();pins_.clear();references_=0;bound_=false;}
    static bool Current(const Pin& pin){
        BY_HANDLE_FILE_INFORMATION info{};
        return GetFileInformationByHandle(pin.handle,&info)&&info.nNumberOfLinks==1&&
            !(info.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT))&&
            ((std::uint64_t(info.nFileSizeHigh)<<32)|info.nFileSizeLow)==pin.size;
    }
public:
    bool Active() const {return bound_&&!disabled_;}
    void Bind(const Domain& domain){
        if(bound_&&domain_==domain)return;
        Clear();domain_=domain;disabled_=false;
        bound_=domain.generation&&domain.serial&&domain.file&&domain.volume&&!domain.journal.empty();
    }
    bool PinFile(const std::wstring& path,const Digest& expected,std::string& error){
        if(!Active())return true;
        const auto existing=pins_.find(path);
        if(existing!=pins_.end()){
            if(existing->second.hash==expected&&Current(existing->second))return true;
            error="FusionContinuationPinnedHashChanged";return false;
        }
        if(pins_.size()==PinLimit){
            // Capacity disables this optimization, never an existing admission
            // check. The caller falls back to complete authenticated walks.
            Clear();bound_=true;disabled_=true;return true;
        }
        Pin pin;pin.handle=CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
        if(pin.handle==INVALID_HANDLE_VALUE){error="FusionContinuationEvidenceLease";return false;}
        BY_HANDLE_FILE_INFORMATION info{};LARGE_INTEGER size{};
        if(!GetFileInformationByHandle(pin.handle,&info)||info.nNumberOfLinks!=1||
            (info.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT))||
            !GetFileSizeEx(pin.handle,&size)||size.QuadPart<=0||size.QuadPart>static_cast<LONGLONG>(MaxFileBytes)){
            error="FusionContinuationEvidenceFile";return false;
        }
        pin.size=static_cast<std::uint64_t>(size.QuadPart);
        std::vector<std::byte> bytes(static_cast<std::size_t>(size.QuadPart));DWORD done=0;
        if(!ReadFile(pin.handle,bytes.data(),static_cast<DWORD>(bytes.size()),&done,nullptr)||done!=bytes.size()||
            BCryptHash(BCRYPT_SHA256_ALG_HANDLE,nullptr,0,reinterpret_cast<PUCHAR>(bytes.data()),
                static_cast<ULONG>(bytes.size()),reinterpret_cast<PUCHAR>(pin.hash.data()),32)<0||pin.hash!=expected){
            error="FusionContinuationEvidenceHash";return false;
        }
        pins_.emplace(path,std::move(pin));return true;
    }
    bool Has(std::uint64_t floor,const Digest& hash) const {
        const auto p=prefixes_.find(floor);
        if(!Active()||p==prefixes_.end()||p->second.hash!=hash)return false;
        // Deny-write/delete sharing fixes bytes, but Windows still permits a
        // new hard link. Recheck the original admission metadata per segment.
        for(const auto* pin:p->second.evidence)if(!Current(*pin))return false;
        return true;
    }
    void Remember(std::uint64_t floor,const Digest& hash,const std::wstring& head,
        const std::vector<std::wstring>& dependencies={}){
        const auto p=pins_.find(head);
        if(!Active()||!floor||p==pins_.end()||p->second.hash!=hash)return;
        if(const auto old=prefixes_.find(floor);old!=prefixes_.end()&&old->second.hash==hash)return;
        if(dependencies.size()>=PinLimit||dependencies.size()+1>PinLimit*2-references_){
            Clear();bound_=true;disabled_=true;return;
        }
        Prefix proof;proof.hash=hash;proof.evidence.push_back(&p->second);
        for(const auto& path:dependencies){const auto pin=pins_.find(path);if(pin==pins_.end())return;proof.evidence.push_back(&pin->second);}
        if(const auto old=prefixes_.find(floor);old!=prefixes_.end())references_-=old->second.evidence.size();
        references_+=proof.evidence.size();prefixes_.insert_or_assign(floor,std::move(proof));
    }
    void Advance(const Domain& before,const Domain& after){
        if(!Active())return;
        auto expected=before;expected.file=after.file;
        if(domain_!=before||expected!=after||!after.file||after.file==before.file){Clear();return;}
        domain_=after;
    }
};
}
