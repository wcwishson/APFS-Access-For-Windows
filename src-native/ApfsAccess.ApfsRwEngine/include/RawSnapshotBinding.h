#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <winioctl.h>

namespace apfsaccess::rw
{
inline constexpr std::size_t kRawSnapshotDescriptorMaxBytes = 65536;
inline constexpr std::size_t kRawSnapshotIdentifierMaxCount = 128;
inline constexpr std::size_t kRawSnapshotIdentifierMaxBytes = 256;
inline constexpr std::size_t kRawSnapshotTextMaxBytes = 128;

enum class RawHardwareIdentityKind : std::uint8_t
{
    Unavailable = 0,
    QualifiedSerialTuple = 1,
    QualifiedDeviceVpd = 2,
};

struct RawHardwareIdentity
{
    RawHardwareIdentityKind kind = RawHardwareIdentityKind::Unavailable;
    std::uint32_t bus_type = 0;
    std::string vendor, product, revision, serial;
    std::uint32_t vpd_code_set = 0, vpd_type = 0;
    std::vector<std::byte> vpd_identifier;
    bool operator==(const RawHardwareIdentity&) const = default;
};

struct RawSnapshotMediaBinding
{
    // RFC-4122/network-order bytes, never the native GUID structure layout.
    std::array<std::byte, 16> disk_guid{}, partition_guid{};
    std::uint64_t partition_offset_bytes = 0, partition_length_bytes = 0;
    std::uint64_t base_offset_bytes = 0, limit_bytes = 0, disk_size_bytes = 0;
    // Physical zero means the driver did not report it; never infer it from logical size.
    std::uint32_t logical_sector_bytes = 0, physical_sector_bytes = 0;
    bool operator==(const RawSnapshotMediaBinding&) const = default;
};

struct RawSnapshotBinding
{
    std::uint32_t version = 1;
    RawHardwareIdentity hardware;
    RawSnapshotMediaBinding media;
    bool operator==(const RawSnapshotBinding&) const = default;
};

struct RawDeviceDescriptor
{
    std::uint32_t bus_type = 0;
    std::string vendor, product, revision, serial;
    bool operator==(const RawDeviceDescriptor&) const = default;
};

struct RawDeviceVpdIdentifier
{
    std::uint32_t code_set = 0, type = 0, association = 0;
    std::vector<std::byte> bytes;
    bool operator==(const RawDeviceVpdIdentifier&) const = default;
};

struct RawSnapshotDescriptors
{
    RawSnapshotMediaBinding media;
    RawDeviceDescriptor device;
    bool device_id_available = false;
    std::vector<RawDeviceVpdIdentifier> identifiers;
    bool operator==(const RawSnapshotDescriptors&) const = default;
};

// Qualification is operator/profile evidence, not a fact inferred by the parser.
// Default construction enables neither hardware scheme.
struct RawHardwareQualification
{
    RawHardwareIdentityKind kind = RawHardwareIdentityKind::Unavailable;
    std::uint32_t bus_type = 0;
    std::string vendor, product, qualified_serial;
    std::uint32_t qualified_vpd_type = 0;
};

namespace raw_snapshot_detail
{
inline bool Refuse(std::string& error, const char* reason)
{
    error = reason;
    return false;
}

template<class T>
inline bool Load(std::span<const std::byte> bytes, std::size_t offset, T& value)
{
    if (offset > bytes.size() || sizeof(T) > bytes.size() - offset) return false;
    std::memcpy(&value, bytes.data() + offset, sizeof(T));
    return true;
}

inline bool Envelope(std::span<const std::byte>& bytes, std::size_t header, std::string& error)
{
    STORAGE_DESCRIPTOR_HEADER value{};
    if (bytes.size() > kRawSnapshotDescriptorMaxBytes || !Load(bytes, 0, value) ||
        value.Version < header || value.Version > value.Size ||
        value.Size < header || value.Size > bytes.size())
        return Refuse(error, "RawHardwareDescriptorEnvelopeInvalid");
    bytes = bytes.first(value.Size);
    return true;
}

inline bool Text(std::span<const std::byte> bytes, std::uint32_t offset,
                 std::size_t header, std::string& out, std::string& error)
{
    out.clear();
    if (offset == 0) return true;
    if (offset < header || offset >= bytes.size())
        return Refuse(error, "RawHardwareDescriptorTextOffsetInvalid");
    const auto available = (std::min)(bytes.size() - offset, kRawSnapshotTextMaxBytes + 1);
    std::size_t length = 0;
    for (; length < available; ++length)
    {
        const auto ch = std::to_integer<unsigned char>(bytes[offset + length]);
        if (ch == 0) break;
        if (ch < 0x20 || ch > 0x7e)
            return Refuse(error, "RawHardwareDescriptorTextInvalid");
    }
    if (length == available || length > kRawSnapshotTextMaxBytes)
        return Refuse(error, "RawHardwareDescriptorTextUnterminated");
    out.assign(reinterpret_cast<const char*>(bytes.data() + offset), length);
    const auto first = out.find_first_not_of(' ');
    if (first == std::string::npos) out.clear();
    else out = out.substr(first, out.find_last_not_of(' ') - first + 1);
    return true;
}

inline bool NonGenericText(std::string_view value)
{
    if (value.empty() || value.size() > kRawSnapshotTextMaxBytes) return false;
    std::string folded;
    for (const unsigned char ch : value)
    {
        if (ch < 0x20 || ch > 0x7e) return false;
        if (ch != ' ' && ch != '-' && ch != '_' && ch != '.' && ch != '/' && ch != ':')
            folded.push_back(ch >= 'a' && ch <= 'z' ? static_cast<char>(ch - 'a' + 'A') : ch);
    }
    constexpr std::array<std::string_view, 15> generic = {
        "", "NA", "NONE", "NULL", "UNKNOWN", "DEFAULT", "GENERIC", "USB",
        "SERIAL", "SERIALNUMBER", "NOTSPECIFIED", "NOTAVAILABLE",
        "TOBEFILLEDBYOEM", "123456789", "0123456789"};
    if (std::find(generic.begin(), generic.end(), folded) != generic.end()) return false;
    return !std::all_of(folded.begin(), folded.end(), [&](char ch) { return ch == folded.front(); });
}

inline bool CanonicalText(std::string_view value)
{
    return value.size() <= kRawSnapshotTextMaxBytes &&
        (value.empty() || (value.front() != ' ' && value.back() != ' ')) &&
        std::all_of(value.begin(), value.end(), [](unsigned char ch) { return ch >= 0x20 && ch <= 0x7e; });
}

inline bool KnownBus(std::uint32_t bus)
{
    return bus > BusTypeUnknown && bus < BusTypeMax &&
        bus != BusTypeVirtual && bus != BusTypeFileBackedVirtual && bus != BusTypeSpaces;
}

inline bool QualifiedVpd(const RawDeviceVpdIdentifier& id)
{
    if (id.association != StorageIdAssocDevice || id.code_set != StorageIdCodeSetBinary ||
        (id.type == StorageIdTypeEUI64 ? id.bytes.size() != 8 :
            id.type != StorageIdTypeFCPHName || (id.bytes.size() != 8 && id.bytes.size() != 16)) ||
        std::all_of(id.bytes.begin(), id.bytes.end(), [&](std::byte b) { return b == id.bytes.front(); }))
        return false;
    if (id.type == StorageIdTypeEUI64) return id.bytes.size() == 8;
    if (id.type != StorageIdTypeFCPHName) return false;
    const auto naa = std::to_integer<unsigned char>(id.bytes.front()) >> 4;
    return (id.bytes.size() == 8 && (naa == 2 || naa == 3 || naa == 5)) ||
        (id.bytes.size() == 16 && naa == 6);
}
template<class Builder>
void AttemptDescriptorCacheOnce(bool& attempted,bool& complete,Builder&& build)
{
    if (attempted) return;
    attempted=true;complete=false;
    complete=std::forward<Builder>(build)();
}
} // namespace raw_snapshot_detail

inline bool ParseRawDeviceDescriptor(std::span<const std::byte> bytes,
                                     RawDeviceDescriptor& out, std::string& error)
{
    out = {};
    error.clear();
    constexpr auto header = offsetof(STORAGE_DEVICE_DESCRIPTOR, RawDeviceProperties);
    if (!raw_snapshot_detail::Envelope(bytes, header, error)) return false;
    STORAGE_DEVICE_DESCRIPTOR descriptor{};
    std::memcpy(&descriptor, bytes.data(), header);
    if (descriptor.DeviceType != 0 || descriptor.RawPropertiesLength > bytes.size() - header ||
        !raw_snapshot_detail::KnownBus(static_cast<std::uint32_t>(descriptor.BusType)))
        return raw_snapshot_detail::Refuse(error, "RawHardwareDescriptorUnsupported");
    RawDeviceDescriptor parsed;
    parsed.bus_type = static_cast<std::uint32_t>(descriptor.BusType);
    if (!raw_snapshot_detail::Text(bytes, descriptor.VendorIdOffset, header, parsed.vendor, error) ||
        !raw_snapshot_detail::Text(bytes, descriptor.ProductIdOffset, header, parsed.product, error) ||
        !raw_snapshot_detail::Text(bytes, descriptor.ProductRevisionOffset, header, parsed.revision, error) ||
        !raw_snapshot_detail::Text(bytes, descriptor.SerialNumberOffset, header, parsed.serial, error))
        return false;
    out = std::move(parsed);
    return true;
}

inline bool ParseRawDeviceIdDescriptor(std::span<const std::byte> bytes,
                                       std::vector<RawDeviceVpdIdentifier>& out, std::string& error)
{
    out.clear();
    error.clear();
    constexpr auto header = offsetof(STORAGE_DEVICE_ID_DESCRIPTOR, Identifiers);
    constexpr auto entry_header = offsetof(STORAGE_IDENTIFIER, Identifier);
    if (!raw_snapshot_detail::Envelope(bytes, header, error)) return false;
    DWORD count = 0;
    (void)raw_snapshot_detail::Load(bytes, offsetof(STORAGE_DEVICE_ID_DESCRIPTOR, NumberOfIdentifiers), count);
    if (count > kRawSnapshotIdentifierMaxCount || count > (bytes.size() - header) / entry_header)
        return raw_snapshot_detail::Refuse(error, "RawHardwareIdentifierCountInvalid");
    std::vector<RawDeviceVpdIdentifier> parsed;
    std::size_t offset = header;
    for (DWORD index = 0; index < count; ++index)
    {
        STORAGE_IDENTIFIER id{};
        if (offset > bytes.size() || entry_header > bytes.size() - offset)
            return raw_snapshot_detail::Refuse(error, "RawHardwareIdentifierTruncated");
        std::memcpy(&id, bytes.data() + offset, entry_header);
        if (id.IdentifierSize == 0 || id.IdentifierSize > kRawSnapshotIdentifierMaxBytes ||
            id.IdentifierSize > bytes.size() - offset - entry_header ||
            id.CodeSet < StorageIdCodeSetBinary || id.CodeSet > StorageIdCodeSetUtf8 ||
            static_cast<std::uint32_t>(id.Association) > StorageIdAssocTarget ||
            static_cast<std::uint32_t>(id.Type) > StorageIdTypeScsiNameString)
            return raw_snapshot_detail::Refuse(error, "RawHardwareIdentifierInvalid");
        const auto extent = entry_header + id.IdentifierSize;
        if ((index + 1 == count && id.NextOffset != 0) ||
            (index + 1 < count && (id.NextOffset < extent || id.NextOffset > bytes.size() - offset ||
                                  entry_header > bytes.size() - offset - id.NextOffset)))
            return raw_snapshot_detail::Refuse(error, "RawHardwareIdentifierNextOffsetInvalid");
        RawDeviceVpdIdentifier entry;
        entry.code_set = static_cast<std::uint32_t>(id.CodeSet);
        entry.type = static_cast<std::uint32_t>(id.Type);
        entry.association = static_cast<std::uint32_t>(id.Association);
        entry.bytes.assign(bytes.begin() + offset + entry_header, bytes.begin() + offset + extent);
        if (std::find(parsed.begin(), parsed.end(), entry) != parsed.end())
            return raw_snapshot_detail::Refuse(error, "RawHardwareIdentifierDuplicate");
        parsed.push_back(std::move(entry));
        offset += id.NextOffset;
    }
    out = std::move(parsed);
    return true;
}

inline std::array<std::byte, 16> RawSnapshotGuidBytes(const GUID& guid)
{
    std::array<std::byte, 16> out{};
    for (std::size_t i = 0; i < 4; ++i) out[i] = std::byte((guid.Data1 >> (24 - 8 * i)) & 0xff);
    for (std::size_t i = 0; i < 2; ++i)
    {
        out[4 + i] = std::byte((guid.Data2 >> (8 - 8 * i)) & 0xff);
        out[6 + i] = std::byte((guid.Data3 >> (8 - 8 * i)) & 0xff);
    }
    for (std::size_t i = 0; i < 8; ++i) out[8 + i] = std::byte(guid.Data4[i]);
    return out;
}

inline bool ValidateRawSnapshotMediaBinding(const RawSnapshotMediaBinding& media, std::string& error)
{
    error.clear();
    const auto nonzero = [](const auto& guid) {
        return std::any_of(guid.begin(), guid.end(), [](std::byte b) { return b != std::byte{0}; });
    };
    const auto sector = [](std::uint32_t value) {
        return value >= 512 && value <= 65536 && (value & (value - 1)) == 0;
    };
    if (!nonzero(media.disk_guid) || !nonzero(media.partition_guid) ||
        !sector(media.logical_sector_bytes) ||
        (media.physical_sector_bytes && (!sector(media.physical_sector_bytes) ||
            media.physical_sector_bytes < media.logical_sector_bytes)) || media.disk_size_bytes == 0 ||
        media.disk_size_bytes % media.logical_sector_bytes != 0 ||
        media.limit_bytes == 0 || media.limit_bytes % 4096 != 0 ||
        media.base_offset_bytes % media.logical_sector_bytes != 0 ||
        media.limit_bytes % media.logical_sector_bytes != 0 ||
        media.partition_offset_bytes % media.logical_sector_bytes != 0 ||
        media.partition_length_bytes % media.logical_sector_bytes != 0 ||
        media.partition_offset_bytes > media.disk_size_bytes ||
        media.partition_length_bytes > media.disk_size_bytes - media.partition_offset_bytes ||
        media.base_offset_bytes < media.partition_offset_bytes ||
        media.limit_bytes > media.partition_length_bytes ||
        media.base_offset_bytes - media.partition_offset_bytes > media.partition_length_bytes - media.limit_bytes)
        return raw_snapshot_detail::Refuse(error, "RawSnapshotMediaBindingInvalid");
    return true;
}

inline bool ParseRawSnapshotMediaBinding(std::span<const std::byte> layout_bytes,
                                        std::span<const std::byte> length_bytes,
                                        std::span<const std::byte> alignment_bytes,
                                        std::uint64_t base, std::uint64_t limit,
                                        RawSnapshotMediaBinding& out, std::string& error,
                                        std::span<const std::byte> geometry_bytes = {})
{
    out = {};
    error.clear();
    constexpr auto header = offsetof(DRIVE_LAYOUT_INFORMATION_EX, PartitionEntry);
    DRIVE_LAYOUT_INFORMATION_EX layout{};
    GET_LENGTH_INFORMATION length{};
    STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR alignment{};
    if (layout_bytes.size() < header || layout_bytes.size() > kRawSnapshotDescriptorMaxBytes ||
        !raw_snapshot_detail::Load(length_bytes, 0, length) || length.Length.QuadPart <= 0)
        return raw_snapshot_detail::Refuse(error, "RawSnapshotMediaDescriptorInvalid");
    std::uint32_t logical_sector=0,physical_sector=0;
    if (!alignment_bytes.empty())
    {
        if (!geometry_bytes.empty() || !raw_snapshot_detail::Envelope(alignment_bytes,sizeof(alignment),error) ||
            !raw_snapshot_detail::Load(alignment_bytes,0,alignment) || !alignment.BytesPerPhysicalSector)
            return raw_snapshot_detail::Refuse(error,"RawSnapshotAlignmentDescriptorInvalid");
        logical_sector=alignment.BytesPerLogicalSector;physical_sector=alignment.BytesPerPhysicalSector;
    }
    else
    {
        DISK_GEOMETRY geometry{};
        if (geometry_bytes.size()!=sizeof(geometry) || !raw_snapshot_detail::Load(geometry_bytes,0,geometry))
            return raw_snapshot_detail::Refuse(error,"RawSnapshotLogicalGeometryUnavailable");
        logical_sector=geometry.BytesPerSector;
    }
    std::memcpy(&layout, layout_bytes.data(), header);
    if (layout.PartitionStyle != PARTITION_STYLE_GPT ||
        layout.PartitionCount > 1024 ||
        layout.PartitionCount > (layout_bytes.size() - header) / sizeof(PARTITION_INFORMATION_EX))
        return raw_snapshot_detail::Refuse(error, "RawSnapshotLayoutInvalid");
    constexpr GUID apfs_type = {0x7c3457ef, 0x0000, 0x11aa, {0xaa, 0x11, 0x00, 0x30, 0x65, 0x43, 0xec, 0xac}};
    RawSnapshotMediaBinding media;
    media.disk_guid = RawSnapshotGuidBytes(layout.Gpt.DiskId);
    media.base_offset_bytes = base;
    media.limit_bytes = limit;
    media.disk_size_bytes = static_cast<std::uint64_t>(length.Length.QuadPart);
    media.logical_sector_bytes = logical_sector;
    media.physical_sector_bytes = physical_sector;
    std::size_t matches = 0;
    for (DWORD index = 0; index < layout.PartitionCount; ++index)
    {
        PARTITION_INFORMATION_EX entry{};
        (void)raw_snapshot_detail::Load(layout_bytes, header + index * sizeof(entry), entry);
        if (entry.PartitionStyle != PARTITION_STYLE_GPT || entry.StartingOffset.QuadPart < 0 ||
            entry.PartitionLength.QuadPart <= 0 || std::memcmp(&entry.Gpt.PartitionType, &apfs_type, sizeof(GUID)) != 0)
            continue;
        const auto start = static_cast<std::uint64_t>(entry.StartingOffset.QuadPart);
        const auto extent = static_cast<std::uint64_t>(entry.PartitionLength.QuadPart);
        if (base >= start && limit <= extent && base - start <= extent - limit)
        {
            ++matches;
            media.partition_guid = RawSnapshotGuidBytes(entry.Gpt.PartitionId);
            media.partition_offset_bytes = start;
            media.partition_length_bytes = extent;
        }
    }
    if (matches != 1) return raw_snapshot_detail::Refuse(error, "RawSnapshotPartitionNotUnique");
    if (!ValidateRawSnapshotMediaBinding(media, error)) return false;
    out = media;
    return true;
}

inline bool QualifyRawSnapshotBinding(const RawSnapshotDescriptors& descriptors,
                                      const RawHardwareQualification& qualification,
                                      RawSnapshotBinding& out, std::string& error)
{
    out = {};
    error.clear();
    if (!ValidateRawSnapshotMediaBinding(descriptors.media, error)) return false;
    const auto& device = descriptors.device;
    if (!raw_snapshot_detail::KnownBus(device.bus_type) || device.bus_type != qualification.bus_type ||
        !raw_snapshot_detail::CanonicalText(device.vendor) || !raw_snapshot_detail::CanonicalText(device.product) ||
        !raw_snapshot_detail::CanonicalText(device.revision) || !raw_snapshot_detail::CanonicalText(device.serial) ||
        !raw_snapshot_detail::NonGenericText(device.vendor) ||
        !raw_snapshot_detail::NonGenericText(device.product) ||
        device.vendor != qualification.vendor || device.product != qualification.product)
        return raw_snapshot_detail::Refuse(error, "RawHardwareProfileUnqualified");
    RawHardwareIdentity hardware;
    hardware.kind = qualification.kind;
    hardware.bus_type = device.bus_type;
    hardware.vendor = device.vendor;
    hardware.product = device.product;
    hardware.revision = device.revision;
    if (qualification.kind == RawHardwareIdentityKind::QualifiedSerialTuple)
    {
        if (device.serial.size() < 4 || !raw_snapshot_detail::NonGenericText(device.serial) ||
            device.serial != qualification.qualified_serial || qualification.qualified_vpd_type != 0)
            return raw_snapshot_detail::Refuse(error, "RawHardwareSerialUnavailableOrUnqualified");
        hardware.serial = device.serial;
    }
    else if (qualification.kind == RawHardwareIdentityKind::QualifiedDeviceVpd)
    {
        if (!qualification.qualified_serial.empty() || !descriptors.device_id_available ||
            descriptors.identifiers.size() > kRawSnapshotIdentifierMaxCount ||
            (qualification.qualified_vpd_type != StorageIdTypeEUI64 &&
             qualification.qualified_vpd_type != StorageIdTypeFCPHName))
            return raw_snapshot_detail::Refuse(error, "RawHardwareVpdUnavailableOrUnqualified");
        const RawDeviceVpdIdentifier* selected = nullptr;
        for (const auto& id : descriptors.identifiers)
        {
            if (id.type != qualification.qualified_vpd_type || !raw_snapshot_detail::QualifiedVpd(id)) continue;
            if (selected) return raw_snapshot_detail::Refuse(error, "RawHardwareVpdAmbiguous");
            selected = &id;
        }
        if (!selected) return raw_snapshot_detail::Refuse(error, "RawHardwareVpdUnavailableOrUnqualified");
        hardware.vpd_code_set = selected->code_set;
        hardware.vpd_type = selected->type;
        hardware.vpd_identifier = selected->bytes;
    }
    else return raw_snapshot_detail::Refuse(error, "RawHardwareIdentityUnavailable");
    out.hardware = std::move(hardware);
    out.media = descriptors.media;
    return true;
}
} // namespace apfsaccess::rw
