#include "BlockDevice.h"
#include "MetadataStore.h"
#include "VolumePhysicalMedia.h"
#include "VolumePhysicalMetadataOwner.h"
#include "../src/VolumePhysicalMediaInternal.h"
#include <Windows.h>
#include <winioctl.h>
#include <filesystem>
#include <fstream>
#include <iostream>

namespace apfsaccess::rw {
// Real private sparse-file handles only. This peer never opens a device or
// qualifies PNP hardware; it models the already-admitted original lease.
struct BlockDeviceRawSnapshotTestPeer {
    static void Seed(BlockDevice& device, const RawSnapshotBinding& binding) {
        std::lock_guard handle(device.handle_mutex_);
        std::lock_guard source(device.write_source_mutex_);
        if (!device.exclusive_write_image_ || device.read_handle_ == INVALID_HANDLE_VALUE ||
            device.write_handle_ == INVALID_HANDLE_VALUE) throw std::runtime_error("real exclusive file lease required");
        device.regular_file_ = false; device.raw_writer_accepted_ = true; device.writable_ = true;
        device.raw_write_limit_bytes_ = binding.media.limit_bytes;
        device.raw_write_source_size_bytes_ = binding.media.disk_size_bytes - binding.media.base_offset_bytes;
        device.raw_writer_identity_ = "physical-metadata-private-sparse-simulation";
        device.raw_presence_probe_result_ = true;
        device.raw_presence_probe_hook_for_tests_ = [](DWORD& error) { error = ERROR_SUCCESS;return true; };
        device.logical_block_size_cache_ = 4096;
        device.geometry_cached_ = true;
        device.geometry_cache_.logical_block_size = 4096;
        device.geometry_cache_.total_bytes = binding.media.limit_bytes;
        device.raw_snapshot_lease_retired_ = false; device.write_source_handles_retired_ = false;
    }
    static void Retire(BlockDevice& device) {
        std::lock_guard lock(device.handle_mutex_);device.InvalidateWriteSourceHandlesLocked();
    }
};
struct VolumePhysicalKeeperTestPeer {
    static std::shared_ptr<VolumePhysicalSource> Bind(const std::shared_ptr<BlockDevice>& device, const RawSnapshotBinding& binding) {
        std::string error;
        if (!ValidateVolumePhysicalPolicy(binding, L"USBSTOR\\DISK&VEN_TESTVENDOR&PROD_SURROGATE&REV_0001\\TESTINSTANCE42&0", error))
            throw std::runtime_error(error);
        const auto lease=device->CaptureHeldRawSnapshotLease();
        if (!lease) throw std::runtime_error("real retained raw-model token required");
        auto impl=std::make_unique<VolumePhysicalSource::Impl>();impl->metadata_device=device;
        impl->binding=binding;impl->instance=L"USBSTOR\\DISK&VEN_TESTVENDOR&PROD_SURROGATE&REV_0001\\TESTINSTANCE42&0";
        impl->identity=VolumePhysicalIdentity(binding,impl->instance);
        impl->current=[device,lease=*lease]{return device->IsHeldRawSnapshotLeaseCurrent(lease);};
        impl->read=[device](auto offset,auto size,auto& bytes,bool){return device->ReadForVerification(offset,size,bytes);};
        impl->write=[device](auto offset,auto bytes){return device->Write(offset,bytes);};
        impl->flush=[device]{return device->Flush();};
        return std::shared_ptr<VolumePhysicalSource>(new VolumePhysicalSource(std::move(impl)));
    }
};
}
namespace {
using namespace apfsaccess::rw;
using Bytes=std::vector<std::byte>;
unsigned checks=0;
void Check(bool ok,const std::string& why){++checks;if(!ok)throw std::runtime_error(why);}
constexpr auto base=1048576ull, disk_size=128ull<<30, window=4153344ull;
RawSnapshotBinding Binding(){
    RawSnapshotBinding b;b.hardware.kind=RawHardwareIdentityKind::QualifiedSerialTuple;b.hardware.bus_type=BusTypeUsb;
    b.hardware.vendor="TestVendor";b.hardware.product="Surrogate Storage";b.hardware.revision="0001";b.hardware.serial="TESTSERIAL42";
    b.media.disk_guid.fill(std::byte{0x31});b.media.partition_guid.fill(std::byte{0x52});
    b.media.base_offset_bytes=b.media.partition_offset_bytes=base;b.media.limit_bytes=b.media.partition_length_bytes=window;
    b.media.disk_size_bytes=disk_size;b.media.logical_sector_bytes=b.media.physical_sector_bytes=4096;return b;
}
Bytes Original(){
    std::ifstream f(L"D:\\ApfsAccessScratch\\WindowsClosure\\encrypted-fixtures-20261008-173132\\dfvfs-plain-apfs.raw",std::ios::binary);
    Bytes bytes(window);f.read(reinterpret_cast<char*>(bytes.data()),bytes.size());Check(f.good(),"genuine fixture read");return bytes;
}
void SaveAt(HANDLE h,std::uint64_t offset,std::span<const std::byte> bytes){
    LARGE_INTEGER at{};at.QuadPart=offset;DWORD wrote{};
    Check(SetFilePointerEx(h,at,nullptr,FILE_BEGIN) && WriteFile(h,bytes.data(),static_cast<DWORD>(bytes.size()),&wrote,nullptr) &&
        wrote==bytes.size(),"bounded private sparse seed");
}
void Run(const std::filesystem::path& root){
    Check(root.is_absolute() && root.root_name()==L"D:" && !std::filesystem::exists(root),"fresh absolute D private root");
    std::filesystem::create_directories(root);const auto path=root/L"metadata-window.img";const auto original=Original();
    const auto h=CreateFileW(path.c_str(),GENERIC_READ|GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
    Check(h!=INVALID_HANDLE_VALUE,"private regular file create");
    struct Close{HANDLE h;~Close(){if(h!=INVALID_HANDLE_VALUE)CloseHandle(h);}} close{h};DWORD got{};
    Check(DeviceIoControl(h,FSCTL_SET_SPARSE,nullptr,0,nullptr,0,&got,nullptr),"sparse carrier required");
    LARGE_INTEGER end{};end.QuadPart=disk_size;
    Check(SetFilePointerEx(h,end,nullptr,FILE_BEGIN) && SetEndOfFile(h),"sparse logical disk length");
    const Bytes sentinel(4096,std::byte{0x71});SaveAt(h,0,sentinel);SaveAt(h,base-4096,sentinel);
    SaveAt(h,base,original);SaveAt(h,base+window,sentinel);SaveAt(h,disk_size-4096,sentinel);
    Check(FlushFileBuffers(h),"seed flush");CloseHandle(h);close.h=INVALID_HANDLE_VALUE;
    std::string error;auto device=BlockDevice::OpenExclusiveManagementImage(path.wstring(),base,error);
    Check(!!device,"real exclusive regular file: "+error);const auto binding=Binding();
    BlockDeviceRawSnapshotTestPeer::Seed(*device,binding);
    auto source=VolumePhysicalKeeperTestPeer::Bind(device,binding);const auto instance=source->InstanceId();
    auto wrong=binding;++wrong.media.limit_bytes;
    Check(!VolumePhysicalSource::RetainMetadataDevice(source,wrong,instance,error),"changed trusted window refuses");
    Check(!VolumePhysicalSource::RetainMetadataDevice(source,binding,L"different-instance",error),"changed trusted PNP refuses");
    Check(!VolumePhysicalSource::RetainMetadataDevice({},binding,instance,error),"missing source refuses");
    BlockDevice unrelated(path.wstring(),base);
    Check(!source->OwnsMetadataDevice(unrelated,error),"same path with another device object refuses");
    auto alias=VolumePhysicalSource::RetainMetadataDevice(source,binding,instance,error);
    Check(alias && alias.get()==device.get() && !alias.owner_before(source) && !source.owner_before(alias),"alias retains exact source control block");
    MetadataStore::VolumeContext context;context.device_path=path.wstring();context.device_offset_bytes=base;
    context.volume_object_id=1026;context.allow_raw_device_canonical_commit=true;context.allow_legacy_scaffold_for_fixtures=false;
    context.container_uuid_hex="d08a9fa0d5a5458b813eebf9bf5d5338";
    auto wrong_context=context;wrong_context.device_offset_bytes=0;
    Check(!CreateVolumePhysicalMetadataStore(source,binding,instance,wrong_context,error),"wrong context offset refuses without fallback");
    wrong_context=context;wrong_context.device_path+=L".wrong";
    Check(!CreateVolumePhysicalMetadataStore(source,binding,instance,wrong_context,error),"wrong context path refuses without fallback");
    Check(!CreateVolumePhysicalMetadataStore({},binding,instance,context,error),"missing capability refuses without independent open");
    auto store=CreateVolumePhysicalMetadataStore(source,binding,instance,context,error);
    Check(!!store,"checked physical metadata owner construction: "+error);
    std::weak_ptr<VolumePhysicalSource> weak=source;
    alias.reset();device.reset();source.reset();Check(!weak.expired(),"MetadataStore alone retains physical capability");
    source=weak.lock();Check(source && source->OwnsMetadataDevice(store->Device(),error),"store uses same retained actual device");
    Check(store->LoadContainerState() && store->CheckpointXid()==4 && store->BlockSizeBytes()==4096,"canonical genuine metadata read through retained device");
    Bytes read;Check(source->Read(0,32,read) && std::equal(read.begin(),read.end(),original.begin()),"bounded uncached header slice");
    Check(store->Device().ReadForVerification(0,4096,read) && std::equal(read.begin(),read.end(),original.begin()),"same original uncached reader");
    const Bytes replacement(4096,std::byte{0x69});
    Check(source->WriteBlock(window/4096-1,replacement) && source->Flush(),"same held target and real file flush");
    Check(source->Read(window-4096,4096,read) && read==replacement,"uncached held target readback");
    Check(!source->WriteBlock(window/4096,replacement) && !source->Read(window,4096,read),"outside window refuses");
    Check(source->OwnsMetadataDevice(store->Device(),error),"normal bounded write preserves original lease");
    auto retained=VolumePhysicalSource::RetainMetadataDevice(source,binding,instance,error);
    BlockDeviceRawSnapshotTestPeer::Retire(*retained);
    Check(!source->Revalidate() && !source->OwnsMetadataDevice(store->Device(),error) &&
        !VolumePhysicalSource::RetainMetadataDevice(source,binding,instance,error),"retirement revokes original source and alias mint");
    Check(!source->WriteBlock(window/4096-1,replacement) && !source->Flush(),"revoked target and flush refuse");
    retained.reset();source.reset();Check(!weak.expired(),"failed retained store preserves owner for settlement");
    store.reset();Check(weak.expired(),"last metadata owner releases capability without a cycle");
    std::ifstream verify(path,std::ios::binary);Check(verify.good(),"closed original handles release file");
    for(const auto offset:{0ull,base-4096,base+window,disk_size-4096}){
        verify.seekg(offset);Bytes bytes(4096);verify.read(reinterpret_cast<char*>(bytes.data()),bytes.size());
        Check(verify.good() && bytes==sentinel,"every unrelated-range sentinel unchanged");
    }
}
}
int wmain(int argc,wchar_t** argv){try{Check(argc==2,"private artifact root required");Run(std::filesystem::path(argv[1]).make_preferred());
    std::cout<<"PASS physical metadata ownership "<<checks<<" checks; regular-file simulation; no device enumeration/open"<<std::endl;return 0;
}catch(const std::exception& e){std::cerr<<"FAIL after "<<checks<<" checks: "<<e.what()<<std::endl;return 1;}}
