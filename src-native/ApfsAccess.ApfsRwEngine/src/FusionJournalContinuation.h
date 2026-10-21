#pragma once
#include "FusionOriginalContinuation.h"
#include "FusionImageRuntime.h"

namespace apfsaccess::journal { class ProtectedJournalReadPass; }
namespace apfsaccess::rw {
class FusionContinuationAdmission final {
    friend class FusionJournalContinuation;
    friend class FusionImageRuntime;
    FusionContinuationAdmission()=default;
    std::uint64_t origin_xid=0, base_xid=0;
    std::map<std::uint64_t,std::uint64_t> private_files;
};

class FusionJournalContinuation final {
    friend class FusionImageRuntime;
    struct Certificate;
    static bool OpenOriginal(FusionImageRuntime&,const catalog::FusionBindRequest&,const FusionVolumeSelection&,
        const std::array<std::byte,32>&,const std::wstring&,std::string&);
    static bool Continue(FusionImageRuntime&,std::string&,const AppleCheckpointStageHook&);
    static bool Admit(FusionImageRuntime&,TransactionManager::RetainedAcceptedHistory&,
        const std::array<std::byte,32>&,const std::wstring&,std::unique_ptr<FusionContinuationAdmission>&,std::string&,const std::atomic<bool>*);
    static bool Census(FusionImageRuntime&,const FusionOriginalCapture&,Certificate&,std::string&,const std::atomic<bool>*);
    static bool Load(FusionImageRuntime&,std::uint64_t,const std::array<std::byte,32>&,Certificate&,std::string&,
        journal::ProtectedJournalReadPass* = nullptr);
    static bool Validate(FusionImageRuntime&,const FusionOriginalCapture&,const std::array<std::byte,32>&,
        Certificate&,std::string&,const std::atomic<bool>*);
    static bool ValidateArchiveChain(FusionImageRuntime&,const Certificate&,std::string&,const std::atomic<bool>*);
    static bool Encode(const Certificate&,std::vector<std::byte>&,std::string&);
    static bool Decode(std::span<const std::byte>,Certificate&,std::string&);
    static bool Replacement(const FusionOriginalCapture&,std::vector<std::uint8_t>&);
};
}
