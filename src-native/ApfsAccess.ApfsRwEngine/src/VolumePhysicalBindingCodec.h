#pragma once
#include "VolumePhysicalMediaInternal.h"
#include "VolumeFormatEvidence.h"

namespace apfsaccess::rw::volume_physical
{
inline constexpr std::uint64_t Magic = 0x3646495653465041ull;
inline constexpr std::uint64_t ManagementMagic = 0x32544d5653465041ull;
inline constexpr std::uint64_t PhysicalSnapshotImageMagic = 0x33544d5653465041ull;
inline constexpr std::uint64_t PhysicalSnapshotManagementMagic = 0x34544d5653465041ull;
inline bool IsManagementMagic(std::uint64_t magic) { return magic == ManagementMagic || magic == PhysicalSnapshotManagementMagic; }
inline bool IsManagementImageMagic(std::uint64_t magic) { return magic == 0x31544d5653465041ull || magic == PhysicalSnapshotImageMagic; }
inline constexpr std::uint64_t FlaggedFormatMagic = 0x4346495653465041ull;
inline bool IsFormatMagic(std::uint64_t magic) { return magic == Magic || magic == FlaggedFormatMagic; }
struct Envelope
{
    RawSnapshotBinding binding;
    std::wstring instance;
};
inline std::vector<std::byte> Encode(const RawSnapshotBinding& binding, std::wstring_view instance)
{
    std::string error;
    format_evidence::Need(ValidateVolumePhysicalPolicy(binding, instance, error), "VolumePhysicalBindingInvalid");
    std::vector<std::byte> bytes; const auto number = [&](std::uint64_t value) { format_evidence::Number(bytes, value); };
    const auto text = [&](std::string_view value) { number(value.size()); for (const auto c : value) bytes.push_back(std::byte(c)); };
    number(Magic); number(binding.version); number(instance.size()); for (const auto c : instance) number(c);
    const auto& h = binding.hardware; number(static_cast<unsigned>(h.kind)); number(h.bus_type);
    text(h.vendor); text(h.product); text(h.revision); text(h.serial);
    const auto& m = binding.media; bytes.insert(bytes.end(), m.disk_guid.begin(), m.disk_guid.end());
    bytes.insert(bytes.end(), m.partition_guid.begin(), m.partition_guid.end());
    for (const auto value : {m.partition_offset_bytes, m.partition_length_bytes, m.base_offset_bytes, m.limit_bytes, m.disk_size_bytes}) number(value);
    number(m.logical_sector_bytes); number(m.physical_sector_bytes);
    format_evidence::Need(bytes.size() <= 4096, "VolumePhysicalBindingSize"); return bytes;
}
inline Envelope Decode(std::span<const std::byte> bytes)
{
    format_evidence::Need(bytes.size() <= 4096, "VolumePhysicalBindingSize"); std::size_t at = 0;
    const auto number = [&]() {
        format_evidence::Need(at <= bytes.size() && bytes.size() - at >= 8, "VolumePhysicalBindingTruncated");
        const auto value = catalog::ReadU64LE(bytes, at).value(); at += 8; return value;
    };
    const auto bounded_number = [&]() { const auto n = number(); format_evidence::Need(n <= UINT32_MAX, "VolumePhysicalBindingInteger"); return static_cast<std::uint32_t>(n); };
    const auto text = [&]() {
        const auto size = number(); format_evidence::Need(size <= 128 && size <= bytes.size() - at, "VolumePhysicalBindingText");
        std::string value(reinterpret_cast<const char*>(bytes.data() + at), static_cast<std::size_t>(size)); at += size;
        format_evidence::Need(raw_snapshot_detail::CanonicalText(value), "VolumePhysicalBindingText"); return value;
    };
    Envelope result; format_evidence::Need(number() == Magic, "VolumePhysicalBindingVersion"); result.binding.version = bounded_number();
    const auto size = number(); format_evidence::Need(size <= 4096 && size <= (bytes.size() - at) / 8, "VolumePhysicalBindingInstance");
    for (std::uint64_t i = 0; i < size; ++i) { const auto c = number(); format_evidence::Need(c >= 32 && c <= 126, "VolumePhysicalBindingInstance"); result.instance.push_back(static_cast<wchar_t>(c)); }
    const auto kind = bounded_number(); format_evidence::Need(kind == static_cast<unsigned>(RawHardwareIdentityKind::QualifiedSerialTuple), "VolumePhysicalBindingScheme");
    auto& h = result.binding.hardware; h.kind = RawHardwareIdentityKind::QualifiedSerialTuple; h.bus_type = bounded_number();
    h.vendor = text(); h.product = text(); h.revision = text(); h.serial = text();
    format_evidence::Need(bytes.size() - at >= 32, "VolumePhysicalBindingTruncated"); auto& m = result.binding.media;
    std::copy_n(bytes.begin() + at, 16, m.disk_guid.begin()); at += 16;
    std::copy_n(bytes.begin() + at, 16, m.partition_guid.begin()); at += 16;
    m.partition_offset_bytes = number(); m.partition_length_bytes = number(); m.base_offset_bytes = number();
    m.limit_bytes = number(); m.disk_size_bytes = number(); m.logical_sector_bytes = bounded_number(); m.physical_sector_bytes = bounded_number();
    std::string error; format_evidence::Need(at == bytes.size() && ValidateVolumePhysicalPolicy(result.binding, result.instance, error), "VolumePhysicalBindingInvalid");
    return result;
}
}
