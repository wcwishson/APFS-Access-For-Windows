#include "VolumePhysicalMediaInternal.h"
#include "VolumePhysicalGeometryInternal.h"
#include "BlockDevice.h"
#include "VolumeFormatEvidence.h"
#include "VolumePhysicalInstanceInternal.h"
#include <setupapi.h>
#include <ntddstor.h>
#include <wincrypt.h>
#include <charconv>
#include <iomanip>
#include <optional>
#include <sstream>

namespace apfsaccess::rw
{
namespace
{
bool CanonicalInstance(std::wstring_view value)
{
    if(value.empty() || value.size()>400 || value.front()==L'\\' || value.back()==L'\\' || value.find(L':')!=value.npos)return false;
    const auto first=value.find(L'\\');
    if(first==value.npos || value.find(L'\\',first+1)==value.npos || value.find(L"\\\\")!=value.npos)return false;
    return std::all_of(value.begin(),value.end(),[](auto c){return c>=33 && c<=126 && !(c>=L'a' && c<=L'z');});
}
bool Span(std::uint64_t limit, std::uint64_t offset, std::uint64_t size)
{ return size && offset <= limit && size <= limit - offset; }
std::optional<std::uint32_t> PhysicalDriveNumber(std::wstring_view path)
{
    constexpr std::wstring_view prefix = L"\\\\.\\PhysicalDrive";
    if (path.size() <= prefix.size() || path.size() > prefix.size() + 8 ||
        CompareStringOrdinal(path.data(), static_cast<int>(prefix.size()), prefix.data(),
            static_cast<int>(prefix.size()), TRUE) != CSTR_EQUAL) return {};
    std::uint64_t number = 0;
    for (const auto c : path.substr(prefix.size())) {
        if (c < L'0' || c > L'9') return {};number = number * 10 + c - L'0';
    }
    if (number > MAXDWORD || path.substr(prefix.size()) != std::to_wstring(number)) return {};
    return static_cast<std::uint32_t>(number);
}
bool DosTarget(std::wstring_view path,std::wstring& target)
{
    target.clear();
    if(path.size()<=4 || path.size()>4096 || (path.substr(0,4)!=L"\\\\.\\" && path.substr(0,4)!=L"\\\\?\\"))return false;
    const std::wstring name(path.substr(4));
    if(name.find_first_of(L"\\/")!=name.npos || name.find(L'\0')!=name.npos)return false;
    std::vector<wchar_t> text(32768);
    const auto count=QueryDosDeviceW(name.c_str(),text.data(),static_cast<DWORD>(text.size()));
    if(!count || count>text.size())return false;
    // QueryDosDevice lists the current mapping first, followed by any retired
    // mappings. Match only the current target; do not open enumerated disks.
    const auto size=wcsnlen(text.data(),count);
    if(!size || size==count || size>4096)return false;
    target.assign(text.data(),size);
    return target.starts_with(L"\\Device\\");
}
bool FindInterface(std::wstring_view expected,std::wstring_view selected,std::wstring& instance_out,std::wstring& out)
{
    out.clear();instance_out.clear();
    if(!expected.empty() && !CanonicalInstance(expected))return false;
    const auto selected_number=PhysicalDriveNumber(selected);
    if(selected.size()>4096)return false;
    std::wstring selected_target;
    if(selected_number && !DosTarget(selected,selected_target))return false;
    if(selected_number) {
        std::wstring instance, current;
        if(!physical_instance::Selected(selected,instance) || (!expected.empty() && instance!=expected) ||
            !FindInterface(instance,{},instance_out,out) || !physical_instance::Selected(selected,current) || current!=instance ||
            !DosTarget(selected,current) || current!=selected_target) { instance_out.clear();out.clear();return false; }
        return true;
    }
    const auto devices = SetupDiGetClassDevsW(&GUID_DEVINTERFACE_DISK, nullptr, nullptr, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (devices == INVALID_HANDLE_VALUE) return false;
    struct Close { HDEVINFO h; ~Close() { SetupDiDestroyDeviceInfoList(h); } } close{devices};
    unsigned matches = 0;
    for (DWORD index = 0; index < 1024; ++index) {
        SP_DEVICE_INTERFACE_DATA item{}; item.cbSize = sizeof(item);
        if (!SetupDiEnumDeviceInterfaces(devices, nullptr, &GUID_DEVINTERFACE_DISK, index, &item)) {
            return GetLastError()==ERROR_NO_MORE_ITEMS && matches==1;
        }
        DWORD size{}; SetupDiGetDeviceInterfaceDetailW(devices, &item, nullptr, 0, &size, nullptr);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || size < sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W) || size > 65536) return false;
        std::vector<std::byte> storage(size); auto* detail = reinterpret_cast<SP_DEVICE_INTERFACE_DETAIL_DATA_W*>(storage.data());
        detail->cbSize = sizeof(*detail); SP_DEVINFO_DATA device{}; device.cbSize = sizeof(device);
        if (!SetupDiGetDeviceInterfaceDetailW(devices, &item, detail, size, nullptr, &device)) return false;
        wchar_t text[4096]{}; DWORD chars{};
        if (!SetupDiGetDeviceInstanceIdW(devices, &device, text, 4096, &chars) || !chars || chars > 4096) return false;
        const auto instance_length = wcsnlen(text, 4096);
        if (!instance_length || instance_length == 4096) return false;
        std::wstring instance(text, instance_length);
        for (auto& c : instance) { if (c < 32 || c > 126) return false; if (c >= L'a' && c <= L'z') c -= L'a' - L'A'; }
        if (!CanonicalInstance(instance) || (!expected.empty() && instance != expected)) continue;
        const auto maximum = (size - offsetof(SP_DEVICE_INTERFACE_DETAIL_DATA_W, DevicePath)) / sizeof(wchar_t);
        const auto length = wcsnlen(detail->DevicePath, maximum);
        if (!length || length == maximum) return false;
        if(!selected.empty() && CompareStringOrdinal(selected.data(),static_cast<int>(selected.size()),detail->DevicePath,static_cast<int>(length),TRUE)!=CSTR_EQUAL)continue;
        if(++matches!=1)return false;
        instance_out=instance;
        out.assign(detail->DevicePath, length);
    }
    return false;
}
bool DeviceInterface(std::wstring_view expected,std::wstring& out)
{std::wstring instance;return !expected.empty() && FindInterface(expected,{},instance,out);}
bool Instance(const std::wstring& path, std::wstring& out,std::wstring_view expected={})
{
    out.clear();std::wstring interface_path;
    if (path.empty() || path.size() > 4096 || path.find(L'\0') != std::wstring::npos) return false;
    return FindInterface(expected,path,out,interface_path);
}
}
bool ValidateVolumePhysicalPolicy(const RawSnapshotBinding& binding, std::wstring_view instance, std::string& error)
{
    error.clear();
    if (binding.version != 1 || !CanonicalInstance(instance) || binding.hardware.kind != RawHardwareIdentityKind::QualifiedSerialTuple ||
        binding.hardware.bus_type != BusTypeUsb || !raw_snapshot_detail::CanonicalText(binding.hardware.serial) ||
        !raw_snapshot_detail::NonGenericText(binding.hardware.serial) ||
        binding.hardware.vpd_code_set || binding.hardware.vpd_type || !binding.hardware.vpd_identifier.empty() ||
        !raw_snapshot_detail::CanonicalText(binding.hardware.vendor) || !raw_snapshot_detail::CanonicalText(binding.hardware.product) ||
        !raw_snapshot_detail::CanonicalText(binding.hardware.revision) || !raw_snapshot_detail::NonGenericText(binding.hardware.vendor) ||
        !raw_snapshot_detail::NonGenericText(binding.hardware.product) ||
        !binding.media.disk_size_bytes || binding.media.disk_size_bytes>INT64_MAX || binding.media.base_offset_bytes != binding.media.partition_offset_bytes ||
        binding.media.logical_sector_bytes > 4096 || binding.media.base_offset_bytes % 4096 ||
        binding.media.limit_bytes < 1048576 || binding.media.limit_bytes > (1ull << 40)) {
        error = "VolumePhysicalOperatorProfileMismatch"; return false;
    }
    return ValidateRawSnapshotMediaBinding(binding.media, error);
}
std::string VolumePhysicalIdentity(const RawSnapshotBinding& binding, std::wstring_view instance)
{
    using format_evidence::Number; std::vector<std::byte> bytes;
    const auto text = [&](std::string_view value) { Number(bytes, value.size()); for (const auto c : value) bytes.push_back(std::byte(c)); };
    text("volume-physical-source-v1"); Number(bytes, instance.size()); for (const auto c : instance) Number(bytes, c);
    // Mutable media/descriptor fields belong to the full frame binding. They
    // must not move outstanding intent out of this device's journal namespace.
    text(binding.hardware.serial);
    const auto hash = format_evidence::Hash(bytes); std::ostringstream identity; identity << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < 24; ++i) identity << std::setw(2) << std::to_integer<unsigned>(hash[i]);
    identity << std::setw(16) << binding.media.base_offset_bytes << std::setw(16) << binding.media.base_offset_bytes + binding.media.limit_bytes;
    return identity.str();
}
std::string DeriveVolumePhysicalRecoveryIdentity(const RawSnapshotBinding& binding, std::string_view uuid, std::uint64_t oid)
{
    std::string error;
    format_evidence::Need(ValidateRawSnapshotMediaBinding(binding.media, error) && uuid.size() == 32 && oid &&
        uuid != std::string(32, '0') && uuid.find_first_not_of("0123456789abcdef") == std::string_view::npos,
        "VolumePhysicalRecoveryIdentityInvalid");
    std::array<std::byte, 42> material{}; material[0] = std::byte{1};
    constexpr std::array<unsigned, 16> native_order{3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15};
    for (std::size_t i = 0; i < native_order.size(); ++i) material[1 + i] = binding.media.partition_guid[native_order[i]];
    for (std::size_t i = 0; i < 16; ++i) {
        unsigned value = 0; const auto [end, ec] = std::from_chars(uuid.data() + 2 * i, uuid.data() + 2 * i + 2, value, 16);
        format_evidence::Need(ec == std::errc{} && end == uuid.data() + 2 * i + 2, "VolumePhysicalRecoveryIdentityInvalid");
        material[17 + i] = std::byte(value);
    }
    material[33] = std::byte{1}; for (unsigned i = 0; i < 8; ++i) material[34 + i] = std::byte((oid >> (i * 8)) & 255);
    const auto digest = format_evidence::Hash(material); DWORD length{};
    constexpr DWORD flags = CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF;
    format_evidence::Need(CryptBinaryToStringA(reinterpret_cast<const BYTE*>(digest.data()), static_cast<DWORD>(digest.size()), flags, nullptr, &length),
        "VolumePhysicalRecoveryIdentityEncodingFailed");
    std::string encoded(length, '\0');
    format_evidence::Need(CryptBinaryToStringA(reinterpret_cast<const BYTE*>(digest.data()), static_cast<DWORD>(digest.size()), flags, encoded.data(), &length),
        "VolumePhysicalRecoveryIdentityEncodingFailed"); encoded.resize(length);
    if (!encoded.empty() && encoded.back() == '\0') encoded.pop_back(); while (!encoded.empty() && encoded.back() == '=') encoded.pop_back();
    std::replace(encoded.begin(), encoded.end(), '+', '-'); std::replace(encoded.begin(), encoded.end(), '/', '_');
    format_evidence::Need(encoded.size() == 43, "VolumePhysicalRecoveryIdentityEncodingFailed"); return "apfs-recovery-v1-" + encoded;
}
VolumePhysicalSource::VolumePhysicalSource(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
VolumePhysicalSource::~VolumePhysicalSource() = default;
std::shared_ptr<VolumePhysicalSource> VolumePhysicalSource::OpenExclusiveRaw(const RawSnapshotBinding& expected,
    std::wstring_view expected_instance, std::string& error, std::wstring_view selected_device)
{
    error.clear();
    if (!ValidateVolumePhysicalPolicy(expected, expected_instance, error)) return {};
    if (!selected_device.empty()) {
        std::wstring instance;
        if (!PhysicalDriveNumber(selected_device) || !Instance(std::wstring(selected_device), instance,expected_instance) || instance != expected_instance) {
            error = "VolumePhysicalSelectedDeviceMismatch";return {};
        }
    }
    std::wstring path;
    if (!DeviceInterface(expected_instance,path)) { error = "VolumePhysicalInstanceUnavailable";return {}; }
    auto device = std::make_shared<BlockDevice>(std::move(path), expected.media.base_offset_bytes);
    if (!device->AdmitExclusiveRawWriterImpl(expected.media.limit_bytes, error, true) || !device->ProbeUnderlyingDevice(true)) {
        if (error.empty()) error = "VolumePhysicalHeldDeviceUnavailable";return {};
    }
    if(!selected_device.empty()) {
        STORAGE_DEVICE_NUMBER number{};DWORD bytes=0,io_error=0;std::lock_guard handle(device->handle_mutex_);
        if(!device->RawSnapshotIoctl(device->read_handle_.load(std::memory_order_acquire),IOCTL_STORAGE_GET_DEVICE_NUMBER,
            nullptr,0,&number,sizeof(number),bytes,io_error) || !physical_instance::WholeDisk(number,bytes,*PhysicalDriveNumber(selected_device))) {
            error="VolumePhysicalSelectedDiskNumberMismatch";return {};
        }
    }
    return BindHeldRaw(std::move(device), expected, expected_instance, error);
}
std::shared_ptr<VolumePhysicalSource> VolumePhysicalSource::ObserveExclusiveRaw(std::wstring_view selected_physical_path,
    std::wstring_view expected_instance, std::uint64_t base_offset_bytes, std::uint64_t limit_bytes,
    const RawHardwareQualification& qualification, std::string& error)
{
    error.clear();
    if (!PhysicalDriveNumber(selected_physical_path) || (!expected_instance.empty() && !CanonicalInstance(expected_instance)) ||
        qualification.kind != RawHardwareIdentityKind::QualifiedSerialTuple ||
        qualification.bus_type != BusTypeUsb || !raw_snapshot_detail::CanonicalText(qualification.qualified_serial) ||
        !raw_snapshot_detail::NonGenericText(qualification.qualified_serial) || qualification.qualified_vpd_type ||
        !raw_snapshot_detail::CanonicalText(qualification.vendor) || !raw_snapshot_detail::NonGenericText(qualification.vendor) ||
        !raw_snapshot_detail::CanonicalText(qualification.product) || !raw_snapshot_detail::NonGenericText(qualification.product) ||
        base_offset_bytes % 4096 || limit_bytes % 4096 || limit_bytes < 1048576 ||
        limit_bytes>(1ull<<40) || base_offset_bytes>INT64_MAX-limit_bytes) {
        error = "VolumePhysicalOperatorProfileMismatch";return {};
    }
    std::wstring instance, path;
    if (!Instance(std::wstring(selected_physical_path), instance,expected_instance) ||
        (!expected_instance.empty() && instance != expected_instance) || !DeviceInterface(instance,path)) {
        error = "VolumePhysicalInstanceUnavailable";return {};
    }
    auto device = std::make_shared<BlockDevice>(std::move(path), base_offset_bytes);
    if (!device->AdmitExclusiveRawWriterImpl(limit_bytes, error, true) || !device->ProbeUnderlyingDevice(true)) {
        if (error.empty()) error = "VolumePhysicalHeldDeviceUnavailable";return {};
    }
    {
        STORAGE_DEVICE_NUMBER number{};DWORD bytes=0,io_error=0;std::lock_guard handle(device->handle_mutex_);
        if(!device->RawSnapshotIoctl(device->read_handle_.load(std::memory_order_acquire),IOCTL_STORAGE_GET_DEVICE_NUMBER,
            nullptr,0,&number,sizeof(number),bytes,io_error) || !physical_instance::WholeDisk(number,bytes,*PhysicalDriveNumber(selected_physical_path))) {
            error="VolumePhysicalSelectedDiskNumberMismatch";return {};
        }
    }
    const auto lease = device->CaptureHeldRawSnapshotLease();RawSnapshotBinding binding;
    if (!lease || !device->QueryHeldRawSnapshotBinding(*lease, qualification, binding, error)) {
        if (error.empty()) error = "VolumePhysicalHeldAuthorityMismatch";return {};
    }
    return BindHeldRaw(std::move(device), binding, instance, error);
}
std::shared_ptr<VolumePhysicalSource> VolumePhysicalSource::BindHeldRaw(std::shared_ptr<BlockDevice> device,
    const RawSnapshotBinding& expected, std::wstring_view expected_instance, std::string& error)
{
    error.clear();
    if (!ValidateVolumePhysicalPolicy(expected, expected_instance, error)) return {};
    const auto fail = [&]() -> std::shared_ptr<VolumePhysicalSource> { if (error.empty()) error = "VolumePhysicalHeldAuthorityMismatch"; return {}; };
    if (!device || !device->IsRawWriterAccepted() || device->IsRegularFile() || device->BaseOffsetBytes() != expected.media.base_offset_bytes ||
        device->RawWriteLimitBytes() != expected.media.limit_bytes) return fail();
    const auto lease = device->CaptureHeldRawSnapshotLease(); if (!lease) return fail();
    const auto device_number = [device](STORAGE_DEVICE_NUMBER& number) {
        DWORD bytes=0,error=0;std::lock_guard handle(device->handle_mutex_);
        return device->RawSnapshotIoctl(device->read_handle_.load(std::memory_order_acquire),IOCTL_STORAGE_GET_DEVICE_NUMBER,
            nullptr,0,&number,sizeof(number),bytes,error) && physical_instance::WholeDisk(number,bytes,number.DeviceNumber);
    };
    STORAGE_DEVICE_NUMBER admitted_number{};
    if(!device_number(admitted_number))return fail();
    RawSnapshotDescriptors descriptors;
    if (!device->QueryHeldRawSnapshotDescriptors(*lease, descriptors, error)) return fail();
    RawHardwareQualification qualification; qualification.kind = RawHardwareIdentityKind::QualifiedSerialTuple;
    qualification.bus_type = BusTypeUsb; qualification.vendor = expected.hardware.vendor; qualification.product = expected.hardware.product;
    qualification.qualified_serial = expected.hardware.serial; RawSnapshotBinding actual;
    if (!device->QueryHeldRawSnapshotBinding(*lease, qualification, actual, error) || actual != expected) return fail();
    std::wstring instance, interface_path;
    if (!FindInterface(expected_instance,device->Path(),instance,interface_path) || instance != expected_instance) return fail();
    auto impl = std::make_unique<Impl>(); impl->metadata_device = device;
    impl->binding = expected; impl->instance = instance; impl->identity = VolumePhysicalIdentity(expected, instance);
    impl->current = [device, token = *lease, expected, qualification, instance, interface_path, device_number, admitted_number] {
        RawSnapshotBinding now; std::string detail; std::wstring current;
        STORAGE_DEVICE_NUMBER number{};
        return device->IsHeldRawSnapshotLeaseCurrent(token) && Instance(interface_path, current,instance) && current == instance &&
            device_number(number) && number.DeviceNumber==admitted_number.DeviceNumber && number.PartitionNumber==admitted_number.PartitionNumber &&
            device->ProbeUnderlyingDevice(true) &&
            device->QueryHeldRawSnapshotBinding(token, qualification, now, detail) && now == expected;
    };
    impl->read = [device](auto offset, auto size, auto& out, bool verify) {
        return verify ? device->ReadForVerification(offset, size, out) : device->Read(offset, size, out);
    };
    impl->read_metadata = [device, token = *lease, expected](auto offset, auto size, auto& out) {
        out.clear();const auto sector=expected.media.logical_sector_bytes;
        if(!size || size>(1u<<20) || offset%sector || size%sector || offset>expected.media.disk_size_bytes ||
            size>expected.media.disk_size_bytes-offset)return false;
        std::lock_guard writer(device->write_mutex_);std::lock_guard handle(device->handle_mutex_);
        std::lock_guard source(device->write_source_mutex_);
        if(!device->IsHeldRawSnapshotLeaseCurrentLocked(token))return false;
        out.resize(size);DWORD got{};
        if(!device->ReadAt(device->read_handle_.load(std::memory_order_acquire),offset,out.data(),static_cast<DWORD>(size),got) || got!=size){out.clear();return false;}
        return device->IsHeldRawSnapshotLeaseCurrentLocked(token);
    };
    impl->write = [device](auto offset, auto bytes) { return device->Write(offset, bytes); };
    impl->flush = [device] { return device->Flush(); };
    impl->zero = [device](auto offset, auto size) {
        std::vector<std::byte> zero((std::min<std::size_t>)(size, 65536));
        for (std::size_t at = 0; at < size; at += zero.size())
            if (!device->Write(offset + at, std::span(zero).first((std::min)(zero.size(), size - at)))) return false;
        return true;
    };
    auto result = std::shared_ptr<VolumePhysicalSource>(new VolumePhysicalSource(std::move(impl)));
    return result->Revalidate() ? result : fail();
}
std::uint64_t VolumePhysicalSource::SizeBytes() const { return impl_->binding.media.limit_bytes; }
std::shared_ptr<BlockDevice> VolumePhysicalSource::RetainMetadataDevice(const std::shared_ptr<VolumePhysicalSource>& held,
    const RawSnapshotBinding& trusted_binding, std::wstring_view trusted_instance, std::string& error)
{
    error.clear();auto owner = held;
    if (!owner || owner->Binding() != trusted_binding || owner->InstanceId() != trusted_instance) {
        error = "VolumePhysicalMetadataAuthorityMismatch";return {};
    }
    auto* device = owner->impl_->metadata_device.get();
    if (!device || !owner->OwnsMetadataDevice(*device, error)) {
        if (error.empty()) error = "VolumePhysicalMetadataDeviceUnavailable";return {};
    }
    return std::shared_ptr<BlockDevice>(std::move(owner), device);
}
bool VolumePhysicalSource::OwnsMetadataDevice(const BlockDevice& device, std::string& error) const
{
    error.clear();std::lock_guard lock(impl_->gate);
    if (!impl_->metadata_device || impl_->metadata_device.get() != &device || device.IsRegularFile() ||
        !device.IsRawWriterAccepted() || device.BaseOffsetBytes() != impl_->binding.media.base_offset_bytes ||
        device.RawWriteLimitBytes() != impl_->binding.media.limit_bytes || !impl_->Current()) {
        error = "VolumePhysicalMetadataDeviceMismatch";return false;
    }
    return true;
}
const RawSnapshotBinding& VolumePhysicalSource::Binding() const { return impl_->binding; }
const std::wstring& VolumePhysicalSource::InstanceId() const { return impl_->instance; }
const std::string& VolumePhysicalSource::Identity() const { return impl_->identity; }
bool VolumePhysicalSource::Revalidate() const { std::lock_guard lock(impl_->gate); return impl_->Current(); }
bool VolumePhysicalSource::VerifyCompletedGeometry(std::span<const std::byte> bytes, std::string& error) const
{
    error.clear();
    try {
        const auto plan=volume_geometry::Decode(bytes);
        std::lock_guard lock(impl_->gate);
        format_evidence::Need(plan.after==impl_->binding && plan.snapshot.original.instance==impl_->instance &&
            impl_->read_metadata && impl_->Current(),"VolumeGeometryCompletedBindingMismatch");
        class Metadata final:public catalog::RandomAccessSource {
        public:
            std::uint64_t size;std::function<bool(std::uint64_t,std::size_t,std::vector<std::byte>&)> read;
            std::uint64_t SizeBytes()const override{return size;}
            bool Read(std::uint64_t at,std::size_t n,std::vector<std::byte>& out)const override{return read(at,n,out);}
        } source;
        source.size=impl_->binding.media.disk_size_bytes;
        source.read=[&](auto at,auto n,auto& out){return impl_->Current() && impl_->Result(impl_->read_metadata(at,n,out)) && impl_->Current();};
        volume_geometry::Verify(source,plan,3);return impl_->Current();
    }catch(const std::exception& ex){error=ex.what();return false;}
}
bool VolumePhysicalSource::Read(std::uint64_t offset, std::size_t size, std::vector<std::byte>& out) const
{
    out.clear(); std::lock_guard lock(impl_->gate);
    if (!Span(SizeBytes(), offset, size) || size > (4u << 20) || !impl_->Current()) return false;
    // Canonical readers can request a 32-byte object header. Borrow complete
    // aligned blocks from the held uncached reader, then return only that slice.
    const auto begin = offset - offset % 4096, end = (offset + size + 4095) / 4096 * 4096;
    std::vector<std::byte> aligned;
    if (!impl_->Result(impl_->read(begin, static_cast<std::size_t>(end - begin), aligned, true) && aligned.size() == end - begin) ||
        !impl_->Current()) return false;
    out.assign(aligned.begin() + offset - begin, aligned.begin() + offset - begin + size); return true;
}
bool VolumePhysicalSource::ReadBlock(std::uint64_t block, std::uint32_t size, std::vector<std::byte>& out)
{ return size == 4096 && block < SizeBytes() / size && Read(block * size, size, out); }
bool VolumePhysicalSource::ReadBlockRangeForVerification(std::uint64_t block, std::uint32_t size, std::size_t maximum, std::vector<std::byte>& out)
{
    out.clear(); std::lock_guard lock(impl_->gate);
    const auto ok = size == 4096 && maximum && block < SizeBytes() / size && impl_->Current() &&
        impl_->Result(impl_->read(block * size, size, out, true) && out.size() == size) && impl_->Current();
    if (!ok) out.clear(); return ok;
}
bool VolumePhysicalSource::WriteBlock(std::uint64_t block, std::span<const std::byte> bytes)
{
    std::lock_guard lock(impl_->gate);
    return bytes.size() == 4096 && block < SizeBytes() / 4096 && impl_->Current() &&
        impl_->Result(impl_->write(block * 4096, bytes)) && impl_->Current();
}
bool VolumePhysicalSource::ZeroRange(std::uint64_t offset, std::size_t size)
{
    std::lock_guard lock(impl_->gate);
    return offset % 4096 == 0 && size % 4096 == 0 && Span(SizeBytes(), offset, size) && size <= (4u << 20) &&
        impl_->Current() && impl_->Result(impl_->zero(offset, size)) && impl_->Current();
}
bool VolumePhysicalSource::Flush()
{ std::lock_guard lock(impl_->gate); return impl_->Current() && impl_->Result(impl_->flush()) && impl_->Current(); }

std::shared_ptr<VolumePhysicalGeometrySource> VolumePhysicalGeometrySource::OpenExclusiveRaw(const RawSnapshotBinding& expected,
    std::wstring_view expected_instance, std::string& error, std::wstring_view selected_device)
{
    error.clear();
    if (!ValidateVolumePhysicalPolicy(expected,expected_instance,error)) return {};
    if (!selected_device.empty()) {
        std::wstring selected;
        if (!PhysicalDriveNumber(selected_device) || !Instance(std::wstring(selected_device),selected,expected_instance) || selected!=expected_instance) {
            error="VolumeGeometrySelectedDeviceMismatch";return {};
        }
    }
    std::wstring path;
    if (!DeviceInterface(expected_instance,path)) {error="VolumeGeometryInstanceUnavailable";return {};}
    struct Owner
    {
        HANDLE handle=INVALID_HANDLE_VALUE;
        STORAGE_DEVICE_NUMBER admitted_number{};
        ~Owner(){if(handle!=INVALID_HANDLE_VALUE)CloseHandle(handle);}
        bool Number(STORAGE_DEVICE_NUMBER& number) const
        {
            DWORD got{};
            return handle!=INVALID_HANDLE_VALUE && DeviceIoControl(handle,IOCTL_STORAGE_GET_DEVICE_NUMBER,nullptr,0,
                &number,sizeof(number),&got,nullptr) && physical_instance::WholeDisk(number,got,number.DeviceNumber);
        }
        bool Hardware(const RawSnapshotBinding& expected) const
        {
            STORAGE_DEVICE_NUMBER number{};
            if(!Number(number) || number.DeviceNumber!=admitted_number.DeviceNumber ||
                number.PartitionNumber!=admitted_number.PartitionNumber)return false;
            STORAGE_PROPERTY_QUERY query{};query.PropertyId=StorageDeviceProperty;query.QueryType=PropertyStandardQuery;
            STORAGE_DESCRIPTOR_HEADER header{};DWORD got{};
            if(!DeviceIoControl(handle,IOCTL_STORAGE_QUERY_PROPERTY,&query,sizeof(query),&header,sizeof(header),&got,nullptr) ||
                got!=sizeof(header) || header.Size<sizeof(STORAGE_DEVICE_DESCRIPTOR) || header.Size>65536 || header.Version>header.Size)return false;
            std::vector<std::byte> bytes(header.Size);
            if(!DeviceIoControl(handle,IOCTL_STORAGE_QUERY_PROPERTY,&query,sizeof(query),bytes.data(),static_cast<DWORD>(bytes.size()),&got,nullptr) ||
                got>bytes.size())return false;
            RawDeviceDescriptor descriptor;std::string error;
            if(!ParseRawDeviceDescriptor(std::span(bytes).first(got),descriptor,error))return false;
            const auto& h=expected.hardware;
            if(descriptor.bus_type!=h.bus_type || descriptor.vendor!=h.vendor || descriptor.product!=h.product ||
                descriptor.revision!=h.revision || descriptor.serial!=h.serial)return false;
            GET_LENGTH_INFORMATION length{};
            if(!DeviceIoControl(handle,IOCTL_DISK_GET_LENGTH_INFO,nullptr,0,&length,sizeof(length),&got,nullptr) ||
                got!=sizeof(length) || length.Length.QuadPart<=0 || static_cast<std::uint64_t>(length.Length.QuadPart)!=expected.media.disk_size_bytes)return false;
            query.PropertyId=StorageAccessAlignmentProperty;STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR alignment{};
            if(DeviceIoControl(handle,IOCTL_STORAGE_QUERY_PROPERTY,&query,sizeof(query),&alignment,sizeof(alignment),&got,nullptr))
                return got==sizeof(alignment) && alignment.Size==sizeof(alignment) && alignment.Version==sizeof(alignment) &&
                    alignment.BytesPerLogicalSector==expected.media.logical_sector_bytes && alignment.BytesPerPhysicalSector==expected.media.physical_sector_bytes;
            const auto failure=GetLastError();if(failure!=ERROR_NOT_SUPPORTED && failure!=ERROR_INVALID_FUNCTION && failure!=ERROR_INVALID_PARAMETER)return false;
            DISK_GEOMETRY geometry{};
            return expected.media.physical_sector_bytes==0 && DeviceIoControl(handle,IOCTL_DISK_GET_DRIVE_GEOMETRY,nullptr,0,&geometry,sizeof(geometry),&got,nullptr) &&
                got==sizeof(geometry) && geometry.BytesPerSector==expected.media.logical_sector_bytes;
        }
    };
    auto owner=std::make_shared<Owner>();
    owner->handle=CreateFileW(path.c_str(),GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_WRITE_THROUGH,nullptr);
    if(owner->handle==INVALID_HANDLE_VALUE || GetFileType(owner->handle)!=FILE_TYPE_DISK || !owner->Number(owner->admitted_number) ||
        (!selected_device.empty() && owner->admitted_number.DeviceNumber!=*PhysicalDriveNumber(selected_device)) || !owner->Hardware(expected)) {
        error="VolumeGeometryExclusiveHardwareMismatch";return {};
    }
    auto impl=std::make_unique<Impl>();impl->original=expected;impl->instance=expected_instance;
    impl->current=[owner,expected,path,instance=std::wstring(expected_instance)]{std::wstring current;return DeviceInterface(instance,current) && current==path && owner->Hardware(expected);};
    impl->read=[owner](std::uint64_t offset,std::size_t size,std::vector<std::byte>& out){
        LARGE_INTEGER at{};at.QuadPart=offset;DWORD got{};out.resize(size);
        const auto ok=size<=MAXDWORD && SetFilePointerEx(owner->handle,at,nullptr,FILE_BEGIN) &&
            ReadFile(owner->handle,out.data(),static_cast<DWORD>(size),&got,nullptr) && got==size;
        if(!ok)out.clear();return !!ok;
    };
    impl->write=[owner](std::uint64_t offset,std::span<const std::byte> bytes){
        LARGE_INTEGER at{};at.QuadPart=offset;DWORD got{};
        return bytes.size()<=MAXDWORD && SetFilePointerEx(owner->handle,at,nullptr,FILE_BEGIN) &&
            WriteFile(owner->handle,bytes.data(),static_cast<DWORD>(bytes.size()),&got,nullptr) && got==bytes.size();
    };
    impl->flush=[owner]{return FlushFileBuffers(owner->handle)!=FALSE;};
    impl->zero=[owner](std::uint64_t offset,std::size_t size){
        const std::vector<std::byte> zero(65536);LARGE_INTEGER at{};at.QuadPart=offset;DWORD got{};
        if(!SetFilePointerEx(owner->handle,at,nullptr,FILE_BEGIN))return false;
        for(std::size_t pos=0;pos<size;pos+=zero.size()) {
            const auto count=static_cast<DWORD>((std::min)(zero.size(),size-pos));
            if(!WriteFile(owner->handle,zero.data(),count,&got,nullptr) || got!=count)return false;
        }
        return true;
    };
    impl->refresh=[owner]{DWORD got{};return DeviceIoControl(owner->handle,IOCTL_DISK_UPDATE_PROPERTIES,nullptr,0,nullptr,0,&got,nullptr)!=FALSE;};
    impl->retire=[owner]{if(owner->handle==INVALID_HANDLE_VALUE)return false;const auto ok=CloseHandle(owner->handle);owner->handle=INVALID_HANDLE_VALUE;return !!ok;};
    impl->rebind=[instance=std::wstring(expected_instance)](const RawSnapshotBinding& binding,std::string& detail){
        return VolumePhysicalSource::OpenExclusiveRaw(binding,instance,detail);
    };
    auto source=std::shared_ptr<VolumePhysicalGeometrySource>(new VolumePhysicalGeometrySource(std::move(impl)));
    if(!source->Revalidate()){error="VolumeGeometryHeldHardwareChanged";return {};}
    return source;
}
}
