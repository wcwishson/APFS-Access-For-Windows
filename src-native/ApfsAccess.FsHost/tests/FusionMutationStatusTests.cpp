#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <atomic>
#include <cstdint>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>

namespace fusion_mount {
struct Water {std::uint64_t accepted_sequence=18,apfs_durable_sequence=18,cleanup_sequence=18;};
struct Writer {Water water;Water Watermarks() const{return water;}};
struct State {
    Writer storage;Writer* writer=&storage;
    std::uint64_t accepted=0,durable=0,cleaned=0;
    std::atomic<bool> failed{false},deadline_expired{false};
    std::shared_ptr<std::atomic<bool>> cancelled=std::make_shared<std::atomic<bool>>(false);
    std::string error;unsigned cancels=0,publications=0,caches=0,availability=0;
    bool cache_ok=true,available=true;
    void Cancel(){++cancels;*cancelled=true;}
    void PublicationCompleted(){++publications;}
    bool Cache(std::string&){++caches;return cache_ok;}
    bool CheckAvailable(std::string&){++availability;return available;}
};
}
NTSTATUS FusionStatus(fusion_mount::State&,bool){return STATUS_DEVICE_NOT_READY;}
#include "../src/FusionMutationResult.h"

int main()try {
    unsigned checks=0;
    const auto check=[&](bool ok){if(!ok)throw std::runtime_error("status regression check "+std::to_string(checks+1));++checks;};
    const auto expect=[&](const char* error,NTSTATUS status){fusion_mount::State s;s.error=error;
        check(FusionMutationResult(s,false)==status);check(!s.failed&&!s.cancels&&!s.publications&&!s.caches);
        check(s.accepted==18&&s.durable==18&&s.cleaned==18);};
    expect("FusionRuntimeWriteBoundsOrCollision:FusionIoDeadlineExpired",STATUS_IO_TIMEOUT);
    expect("FusionRuntimeWriteBoundsOrCollision:FusionReadCancelled",STATUS_CANCELLED);
    expect("FusionRuntimeWriteBoundsOrCollision:ApfsReadBudgetRecordLimit",STATUS_INSUFFICIENT_RESOURCES);
    expect("FusionRuntimeWriteBoundsOrCollision:ApfsReadBudgetByteLimit",STATUS_INSUFFICIENT_RESOURCES);
    expect("FusionRuntimeWriteBoundsOrCollision:ApfsReadFailed",STATUS_IO_DEVICE_ERROR);
    expect("FusionRuntimeWriteBoundsOrCollision:FusionContinuationAdmission",STATUS_IO_DEVICE_ERROR);
    expect("FusionRuntimeNameCollision",STATUS_OBJECT_NAME_COLLISION);
    expect("FusionRuntimeNameCollision:ApfsReadFailed",STATUS_IO_DEVICE_ERROR);
    expect("FusionRuntimeDirectoryNotEmpty:ApfsReadFailed",STATUS_IO_DEVICE_ERROR);
    for(const auto* structural:{"FusionRuntimeCreateOidCollision","FusionRuntimeWriteCollision","FusionRuntimeAnchorCollision",
        "FusionRuntimeGuardCollision","FusionRuntimeRetainedWriteCollision","FusionRuntimeRetainedAnchorCollision",
        "FusionContinuationPrivateCollision","FusionVolumeOwnerReservedCollision","FusionVolumePayloadOwnerCollision",
        "FusionVolumeAllocationDuplicate","FusionVolumeEphemeralCollision"})expect(structural,STATUS_IO_DEVICE_ERROR);
    expect("FusionRuntimeDirectoryNotEmpty",STATUS_DIRECTORY_NOT_EMPTY);
    expect("FusionRuntimeDirectoryCycle",STATUS_INVALID_PARAMETER);
    expect("FusionRuntimeInvalidName",STATUS_INVALID_PARAMETER);
    expect("FusionRuntimeOriginalCapacity",STATUS_DISK_FULL);
    expect("FusionVolumeObjectIdExhausted",STATUS_DISK_FULL);
    expect("FusionWitnessCapacity",STATUS_DISK_FULL);
    for(const auto* error:{"FusionRuntimeNameCollision","FusionIoDeadlineExpired","FusionReadCancelled","FusionWitnessCapacity"}){
        fusion_mount::State s;s.error=error;s.storage.water.accepted_sequence=22;
        check(FusionMutationResult(s,false)==STATUS_IO_DEVICE_ERROR);check(s.failed&&s.cancels==1&&s.cancelled->load());
        check(s.accepted==22&&s.durable==18&&s.cleaned==18&&!s.availability);
    }
    {fusion_mount::State s;s.deadline_expired=true;*s.cancelled=true;s.error="FusionRuntimeNameCollision";check(FusionMutationResult(s,false)==STATUS_IO_TIMEOUT);}
    {fusion_mount::State s;*s.cancelled=true;s.error="FusionRuntimeNameCollision";check(FusionMutationResult(s,false)==STATUS_CANCELLED);}
    {fusion_mount::State s;check(FusionMutationResult(s,true)==STATUS_SUCCESS);check(s.publications==1&&s.caches==1&&!s.cancels);}
    {fusion_mount::State s;s.cache_ok=false;check(FusionMutationResult(s,true)==STATUS_IO_DEVICE_ERROR);check(s.publications==1&&s.caches==1);}
    {fusion_mount::State s;s.available=false;check(FusionMutationResult(s,false)==STATUS_DEVICE_NOT_READY);check(s.availability==1);}
    std::cout<<"PASS "<<checks<<" production Fusion mutation-result checks\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
