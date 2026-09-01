#include "CheckpointDelta.h"

#include <algorithm>
#include <limits>
#include <unordered_map>

namespace apfsaccess::rw
{
namespace
{
constexpr std::uint32_t kMagic = 0x44465041; // APFD
constexpr std::uint32_t kChainMagic = 0x43465041; // APFC
constexpr std::uint16_t kVersion = 1;
constexpr std::uint32_t kChecksumSeed = 2166136261u;
constexpr std::uint32_t kChecksumPrime = 16777619u;
constexpr std::size_t kHeaderBytes = 40;
constexpr std::size_t kChainHeaderBytes = 44;
constexpr std::size_t kSectionHeaderBytes = 1 + sizeof(std::uint32_t) + sizeof(std::uint32_t);

enum class SectionKind : std::uint8_t
{
    ObjectMap = 1,
    SpacemanAllocation = 2,
    SpacemanDeallocation = 3,
    Inode = 4,
    DirectoryLink = 5,
    Btree = 6,
};

std::uint32_t UpdateFnv1a(std::uint32_t hash, const std::byte* bytes, std::size_t length)
{
    for (std::size_t index = 0; index < length; ++index)
    {
        hash ^= static_cast<std::uint32_t>(std::to_integer<unsigned char>(bytes[index]));
        hash *= kChecksumPrime;
    }
    return hash;
}

std::uint32_t ComputeChecksum(std::span<const std::byte> bytes)
{
    auto hash = kChecksumSeed;
    if (bytes.empty())
    {
        return hash;
    }

    hash = UpdateFnv1a(hash, bytes.data(), 12);
    if (bytes.size() > 16)
    {
        hash = UpdateFnv1a(hash, bytes.data() + 16, bytes.size() - 16);
    }
    return hash;
}

bool CheckedAddSize(std::size_t& value, std::size_t addend)
{
    if (addend > (std::numeric_limits<std::size_t>::max() - value))
    {
        return false;
    }

    value += addend;
    return true;
}

bool CheckedMultiplySize(std::size_t lhs, std::size_t rhs, std::size_t& product)
{
    if (lhs != 0 && rhs > (std::numeric_limits<std::size_t>::max() / lhs))
    {
        return false;
    }

    product = lhs * rhs;
    return true;
}

std::optional<std::uint32_t> Utf16ByteCount(std::wstring_view value)
{
    if (value.size() > (std::numeric_limits<std::uint32_t>::max() / sizeof(std::uint16_t)))
    {
        return std::nullopt;
    }

    return static_cast<std::uint32_t>(value.size() * sizeof(std::uint16_t));
}

bool AddLengthPrefixedBytes(std::size_t& value, std::size_t payload_bytes)
{
    if (payload_bytes > std::numeric_limits<std::uint32_t>::max())
    {
        return false;
    }

    return CheckedAddSize(value, sizeof(std::uint32_t)) &&
        CheckedAddSize(value, payload_bytes);
}

bool AddLengthPrefixedStringBytes(std::size_t& value, std::wstring_view text)
{
    const auto payload_bytes = Utf16ByteCount(text);
    return payload_bytes.has_value() &&
        AddLengthPrefixedBytes(value, payload_bytes.value());
}

bool AddSectionBytes(std::size_t& value, std::size_t count, std::size_t fixed_record_bytes)
{
    if (count > std::numeric_limits<std::uint32_t>::max())
    {
        return false;
    }

    std::size_t payload_bytes = 0;
    return CheckedMultiplySize(count, fixed_record_bytes, payload_bytes) &&
        CheckedAddSize(value, kSectionHeaderBytes) &&
        CheckedAddSize(value, payload_bytes);
}

std::optional<std::size_t> EstimateEncodedDeltaBytes(const CheckpointDelta& delta)
{
    std::size_t bytes = kHeaderBytes;
    if (!AddSectionBytes(bytes, delta.object_map_updates.size(), (sizeof(std::uint64_t) * 4) + 1) ||
        !AddSectionBytes(bytes, delta.spaceman_allocations.size(), sizeof(std::uint64_t) * 2) ||
        !AddSectionBytes(bytes, delta.spaceman_deallocations.size(), sizeof(std::uint64_t) * 2))
    {
        return std::nullopt;
    }

    if (delta.inode_updates.size() > std::numeric_limits<std::uint32_t>::max() ||
        !CheckedAddSize(bytes, kSectionHeaderBytes))
    {
        return std::nullopt;
    }
    for (const auto& inode : delta.inode_updates)
    {
        if (!CheckedAddSize(bytes, sizeof(std::uint64_t) * 2) ||
            !AddLengthPrefixedStringBytes(bytes, inode.name) ||
            !AddLengthPrefixedStringBytes(bytes, inode.full_path) ||
            !CheckedAddSize(bytes, 1 + (sizeof(std::uint64_t) * 4) + 1))
        {
            return std::nullopt;
        }
    }

    if (delta.directory_link_updates.size() > std::numeric_limits<std::uint32_t>::max() ||
        !CheckedAddSize(bytes, kSectionHeaderBytes))
    {
        return std::nullopt;
    }
    for (const auto& link : delta.directory_link_updates)
    {
        if (!CheckedAddSize(bytes, sizeof(std::uint64_t)) ||
            !AddLengthPrefixedStringBytes(bytes, link.entry_name) ||
            !CheckedAddSize(bytes, (sizeof(std::uint64_t) * 2) + 1))
        {
            return std::nullopt;
        }
    }

    if (delta.btree_records.size() > std::numeric_limits<std::uint32_t>::max() ||
        !CheckedAddSize(bytes, kSectionHeaderBytes))
    {
        return std::nullopt;
    }
    for (const auto& record : delta.btree_records)
    {
        if (!CheckedAddSize(bytes, 2) ||
            !AddLengthPrefixedBytes(bytes, record.key.size()) ||
            !AddLengthPrefixedBytes(bytes, record.value.size()))
        {
            return std::nullopt;
        }
    }

    return bytes;
}

void AppendU8(std::vector<std::byte>& out, std::uint8_t value)
{
    out.push_back(static_cast<std::byte>(value));
}

void AppendU16(std::vector<std::byte>& out, std::uint16_t value)
{
    out.push_back(static_cast<std::byte>(value & 0xffu));
    out.push_back(static_cast<std::byte>((value >> 8) & 0xffu));
}

void AppendU32(std::vector<std::byte>& out, std::uint32_t value)
{
    for (int shift = 0; shift < 32; shift += 8)
    {
        out.push_back(static_cast<std::byte>((value >> shift) & 0xffu));
    }
}

void AppendU64(std::vector<std::byte>& out, std::uint64_t value)
{
    for (int shift = 0; shift < 64; shift += 8)
    {
        out.push_back(static_cast<std::byte>((value >> shift) & 0xffu));
    }
}

void PatchU32(std::vector<std::byte>& out, std::size_t offset, std::uint32_t value)
{
    if (offset + 4 > out.size())
    {
        return;
    }
    for (int shift = 0; shift < 32; shift += 8)
    {
        out[offset + static_cast<std::size_t>(shift / 8)] =
            static_cast<std::byte>((value >> shift) & 0xffu);
    }
}

std::uint64_t HashVolumeIdentity(std::string_view value)
{
    auto hash = static_cast<std::uint64_t>(1469598103934665603ull);
    for (const char ch : value)
    {
        hash ^= static_cast<unsigned char>(ch);
        hash *= 1099511628211ull;
    }
    return hash;
}

std::wstring DirectoryLinkKey(std::uint64_t parent_object_id, std::wstring_view entry_name)
{
    return std::to_wstring(parent_object_id) + L":" + std::wstring(entry_name);
}

std::string BtreeRecordKey(const BtreeRecord& record)
{
    std::string key;
    key.reserve(1 + record.key.size());
    key.push_back(static_cast<char>(record.kind));
    key.append(
        reinterpret_cast<const char*>(record.key.data()),
        record.key.size());
    return key;
}

std::wstring DecodeUtf16(std::span<const std::byte> bytes, bool& ok)
{
    if ((bytes.size() % 2) != 0)
    {
        ok = false;
        return {};
    }

    std::wstring out;
    out.reserve(bytes.size() / 2);
    for (std::size_t index = 0; index < bytes.size(); index += 2)
    {
        const auto code_unit =
            static_cast<std::uint16_t>(std::to_integer<unsigned char>(bytes[index])) |
            (static_cast<std::uint16_t>(std::to_integer<unsigned char>(bytes[index + 1])) << 8);
        out.push_back(static_cast<wchar_t>(code_unit));
    }
    return out;
}

void AppendBytes(std::vector<std::byte>& out, std::span<const std::byte> bytes)
{
    AppendU32(out, static_cast<std::uint32_t>(bytes.size()));
    out.insert(out.end(), bytes.begin(), bytes.end());
}

void AppendString(std::vector<std::byte>& out, std::wstring_view value)
{
    const auto byte_count = Utf16ByteCount(value).value_or(0);
    AppendU32(out, byte_count);
    for (const wchar_t ch : value)
    {
        const auto code_unit = static_cast<std::uint32_t>(ch);
        out.push_back(static_cast<std::byte>(code_unit & 0xffu));
        out.push_back(static_cast<std::byte>((code_unit >> 8) & 0xffu));
    }
}

void BeginSection(std::vector<std::byte>& out, SectionKind kind, std::size_t count, std::size_t& size_offset)
{
    AppendU8(out, static_cast<std::uint8_t>(kind));
    AppendU32(out, static_cast<std::uint32_t>(count));
    size_offset = out.size();
    AppendU32(out, 0);
}

void EndSection(std::vector<std::byte>& out, std::size_t size_offset)
{
    const auto payload_start = size_offset + sizeof(std::uint32_t);
    const auto payload_size = out.size() - payload_start;
    PatchU32(out, size_offset, static_cast<std::uint32_t>(payload_size));
}

class Reader
{
public:
    explicit Reader(std::span<const std::byte> bytes) : bytes_(bytes) {}

    [[nodiscard]] bool ReadU8(std::uint8_t& value)
    {
        if (remaining() < 1)
        {
            return false;
        }
        value = std::to_integer<std::uint8_t>(bytes_[offset_++]);
        return true;
    }

    [[nodiscard]] bool ReadU16(std::uint16_t& value)
    {
        if (remaining() < 2)
        {
            return false;
        }
        value = static_cast<std::uint16_t>(std::to_integer<unsigned char>(bytes_[offset_])) |
            (static_cast<std::uint16_t>(std::to_integer<unsigned char>(bytes_[offset_ + 1])) << 8);
        offset_ += 2;
        return true;
    }

    [[nodiscard]] bool ReadU32(std::uint32_t& value)
    {
        if (remaining() < 4)
        {
            return false;
        }
        value = 0;
        for (int shift = 0; shift < 32; shift += 8)
        {
            value |= static_cast<std::uint32_t>(std::to_integer<unsigned char>(bytes_[offset_++])) << shift;
        }
        return true;
    }

    [[nodiscard]] bool ReadU64(std::uint64_t& value)
    {
        if (remaining() < 8)
        {
            return false;
        }
        value = 0;
        for (int shift = 0; shift < 64; shift += 8)
        {
            value |= static_cast<std::uint64_t>(std::to_integer<unsigned char>(bytes_[offset_++])) << shift;
        }
        return true;
    }

    [[nodiscard]] bool ReadBytes(std::span<const std::byte>& bytes)
    {
        std::uint32_t size = 0;
        if (!ReadU32(size) || remaining() < size)
        {
            return false;
        }
        bytes = bytes_.subspan(offset_, size);
        offset_ += size;
        return true;
    }

    [[nodiscard]] bool ReadString(std::wstring& value)
    {
        std::span<const std::byte> bytes;
        if (!ReadBytes(bytes))
        {
            return false;
        }
        bool ok = true;
        value = DecodeUtf16(bytes, ok);
        return ok;
    }

    [[nodiscard]] bool Skip(std::size_t bytes)
    {
        if (remaining() < bytes)
        {
            return false;
        }
        offset_ += bytes;
        return true;
    }

    [[nodiscard]] std::size_t offset() const noexcept { return offset_; }
    [[nodiscard]] std::size_t remaining() const noexcept { return bytes_.size() - offset_; }

private:
    std::span<const std::byte> bytes_;
    std::size_t offset_ = 0;
};

bool IsValidXidRange(std::uint64_t base_xid, std::uint64_t target_xid)
{
    return base_xid != 0 &&
        target_xid != 0 &&
        target_xid > base_xid &&
        target_xid == base_xid + 1;
}

bool IsValidDeltaForApply(const CheckpointDelta& delta)
{
    if (!IsValidXidRange(delta.base_xid, delta.target_xid) ||
        delta.volume_identity.empty())
    {
        return false;
    }

    for (const auto& update : delta.object_map_updates)
    {
        if (update.object_id == 0 ||
            update.xid != delta.target_xid ||
            (!update.tombstone && (update.physical_address == 0 || update.logical_size == 0)))
        {
            return false;
        }
    }
    for (const auto& allocation : delta.spaceman_allocations)
    {
        if (allocation.physical_address == 0 || allocation.bytes == 0)
        {
            return false;
        }
    }
    for (const auto& deallocation : delta.spaceman_deallocations)
    {
        if (deallocation.physical_address == 0 || deallocation.bytes == 0)
        {
            return false;
        }
    }
    for (const auto& inode : delta.inode_updates)
    {
        if (inode.object_id == 0 ||
            inode.xid != delta.target_xid ||
            (!inode.tombstone && inode.full_path.empty()))
        {
            return false;
        }
    }
    for (const auto& link : delta.directory_link_updates)
    {
        if (link.parent_object_id == 0 ||
            link.child_object_id == 0 ||
            link.xid != delta.target_xid ||
            link.entry_name.empty())
        {
            return false;
        }
    }
    for (const auto& record : delta.btree_records)
    {
        if (record.key.empty() ||
            record.kind < BtreeRecordKind::Inode ||
            record.kind > BtreeRecordKind::FileExtent)
        {
            return false;
        }
    }

    return true;
}

bool RemoveExtent(std::vector<ExtentAllocator::Extent>& extents, const ExtentAllocator::Extent& target)
{
    const auto existing = std::find_if(
        extents.begin(),
        extents.end(),
        [&](const ExtentAllocator::Extent& extent)
        {
            return extent.physical_address == target.physical_address &&
                extent.bytes == target.bytes;
        });
    if (existing == extents.end())
    {
        return false;
    }

    extents.erase(existing);
    return true;
}

} // namespace

std::vector<std::byte> CheckpointDeltaCodec::Encode(const CheckpointDelta& delta)
{
    const auto estimated_bytes = EstimateEncodedDeltaBytes(delta);
    if (!estimated_bytes.has_value())
    {
        return {};
    }

    std::vector<std::byte> out;
    out.reserve(estimated_bytes.value());
    AppendU32(out, kMagic);
    AppendU16(out, kVersion);
    AppendU16(out, 0);
    AppendU32(out, kHeaderBytes);
    AppendU32(out, 0);
    AppendU64(out, HashVolumeIdentity(delta.volume_identity));
    AppendU64(out, delta.base_xid);
    AppendU64(out, delta.target_xid);

    const auto write_section = [&out](SectionKind kind, std::size_t count, auto writer) -> bool
    {
        if (count > static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max()))
        {
            return false;
        }
        std::size_t size_offset = 0;
        BeginSection(out, kind, count, size_offset);
        writer();
        EndSection(out, size_offset);
        return true;
    };

    if (!write_section(SectionKind::ObjectMap, delta.object_map_updates.size(), [&]()
    {
        for (const auto& update : delta.object_map_updates)
        {
            AppendU64(out, update.object_id);
            AppendU64(out, update.physical_address);
            AppendU64(out, update.logical_size);
            AppendU64(out, update.xid);
            AppendU8(out, update.tombstone ? 1 : 0);
        }
    }))
    {
        return {};
    }

    if (!write_section(SectionKind::SpacemanAllocation, delta.spaceman_allocations.size(), [&]()
    {
        for (const auto& allocation : delta.spaceman_allocations)
        {
            AppendU64(out, allocation.physical_address);
            AppendU64(out, allocation.bytes);
        }
    }))
    {
        return {};
    }

    if (!write_section(SectionKind::SpacemanDeallocation, delta.spaceman_deallocations.size(), [&]()
    {
        for (const auto& deallocation : delta.spaceman_deallocations)
        {
            AppendU64(out, deallocation.physical_address);
            AppendU64(out, deallocation.bytes);
        }
    }))
    {
        return {};
    }

    if (!write_section(SectionKind::Inode, delta.inode_updates.size(), [&]()
    {
        for (const auto& inode : delta.inode_updates)
        {
            AppendU64(out, inode.object_id);
            AppendU64(out, inode.parent_object_id);
            AppendString(out, inode.name);
            AppendString(out, inode.full_path);
            AppendU8(out, inode.is_directory ? 1 : 0);
            AppendU64(out, inode.logical_size);
            AppendU64(out, inode.data_physical_address);
            AppendU64(out, inode.xid);
            AppendU64(out, inode.timestamp_utc);
            AppendU8(out, inode.tombstone ? 1 : 0);
        }
    }))
    {
        return {};
    }

    if (!write_section(SectionKind::DirectoryLink, delta.directory_link_updates.size(), [&]()
    {
        for (const auto& link : delta.directory_link_updates)
        {
            AppendU64(out, link.parent_object_id);
            AppendString(out, link.entry_name);
            AppendU64(out, link.child_object_id);
            AppendU64(out, link.xid);
            AppendU8(out, link.tombstone ? 1 : 0);
        }
    }))
    {
        return {};
    }

    if (!write_section(SectionKind::Btree, delta.btree_records.size(), [&]()
    {
        for (const auto& record : delta.btree_records)
        {
            AppendU8(out, static_cast<std::uint8_t>(record.kind));
            AppendU8(out, record.tombstone ? 1 : 0);
            AppendBytes(out, record.key);
            AppendBytes(out, record.value);
        }
    }))
    {
        return {};
    }

    if (out.size() != estimated_bytes.value())
    {
        return {};
    }
    PatchU32(out, 12, ComputeChecksum(out));
    return out;
}

CheckpointDeltaParseResult CheckpointDeltaCodec::Decode(
    std::span<const std::byte> bytes,
    std::string_view expected_volume_identity)
{
    if (bytes.empty())
    {
        return { CheckpointDeltaParseStatus::Empty, std::nullopt };
    }
    if (bytes.size() < kHeaderBytes)
    {
        return { CheckpointDeltaParseStatus::Truncated, std::nullopt };
    }

    Reader reader(bytes);
    std::uint32_t magic = 0;
    std::uint16_t version = 0;
    std::uint16_t flags = 0;
    std::uint32_t header_bytes = 0;
    std::uint32_t expected_checksum = 0;
    std::uint64_t volume_hash = 0;
    CheckpointDelta delta;
    if (!reader.ReadU32(magic) ||
        !reader.ReadU16(version) ||
        !reader.ReadU16(flags) ||
        !reader.ReadU32(header_bytes) ||
        !reader.ReadU32(expected_checksum) ||
        !reader.ReadU64(volume_hash) ||
        !reader.ReadU64(delta.base_xid) ||
        !reader.ReadU64(delta.target_xid))
    {
        return { CheckpointDeltaParseStatus::Truncated, std::nullopt };
    }

    if (magic != kMagic || header_bytes != kHeaderBytes || flags != 0)
    {
        return { CheckpointDeltaParseStatus::InvalidHeader, std::nullopt };
    }
    if (version != kVersion)
    {
        return { CheckpointDeltaParseStatus::UnsupportedVersion, std::nullopt };
    }
    if (expected_checksum != ComputeChecksum(bytes))
    {
        return { CheckpointDeltaParseStatus::InvalidChecksum, std::nullopt };
    }
    if (volume_hash != HashVolumeIdentity(expected_volume_identity))
    {
        return { CheckpointDeltaParseStatus::WrongVolume, std::nullopt };
    }
    if (!IsValidXidRange(delta.base_xid, delta.target_xid))
    {
        return { CheckpointDeltaParseStatus::InvalidXid, std::nullopt };
    }

    delta.volume_identity = std::string(expected_volume_identity);
    while (reader.remaining() > 0)
    {
        std::uint8_t section_kind_value = 0;
        std::uint32_t count = 0;
        std::uint32_t payload_bytes = 0;
        if (!reader.ReadU8(section_kind_value) ||
            !reader.ReadU32(count) ||
            !reader.ReadU32(payload_bytes))
        {
            return { CheckpointDeltaParseStatus::Truncated, std::nullopt };
        }
        if (reader.remaining() < payload_bytes)
        {
            return { CheckpointDeltaParseStatus::Truncated, std::nullopt };
        }

        const auto section_end = reader.offset() + payload_bytes;
        const auto section_kind = static_cast<SectionKind>(section_kind_value);
        for (std::uint32_t index = 0; index < count; ++index)
        {
            switch (section_kind)
            {
            case SectionKind::ObjectMap:
            {
                CheckpointDeltaObjectMapUpdate update;
                std::uint8_t tombstone = 0;
                if (!reader.ReadU64(update.object_id) ||
                    !reader.ReadU64(update.physical_address) ||
                    !reader.ReadU64(update.logical_size) ||
                    !reader.ReadU64(update.xid) ||
                    !reader.ReadU8(tombstone) ||
                    update.object_id == 0 ||
                    update.xid != delta.target_xid ||
                    tombstone > 1)
                {
                    return { CheckpointDeltaParseStatus::InvalidRecord, std::nullopt };
                }
                update.tombstone = tombstone != 0;
                delta.object_map_updates.push_back(std::move(update));
                break;
            }
            case SectionKind::SpacemanAllocation:
            case SectionKind::SpacemanDeallocation:
            {
                ExtentAllocator::Extent extent;
                if (!reader.ReadU64(extent.physical_address) ||
                    !reader.ReadU64(extent.bytes) ||
                    extent.physical_address == 0 ||
                    extent.bytes == 0)
                {
                    return { CheckpointDeltaParseStatus::InvalidRecord, std::nullopt };
                }
                if (section_kind == SectionKind::SpacemanAllocation)
                {
                    delta.spaceman_allocations.push_back(extent);
                }
                else
                {
                    delta.spaceman_deallocations.push_back(extent);
                }
                break;
            }
            case SectionKind::Inode:
            {
                CheckpointDeltaInodeUpdate inode;
                std::uint8_t is_directory = 0;
                std::uint8_t tombstone = 0;
                if (!reader.ReadU64(inode.object_id) ||
                    !reader.ReadU64(inode.parent_object_id) ||
                    !reader.ReadString(inode.name) ||
                    !reader.ReadString(inode.full_path) ||
                    !reader.ReadU8(is_directory) ||
                    !reader.ReadU64(inode.logical_size) ||
                    !reader.ReadU64(inode.data_physical_address) ||
                    !reader.ReadU64(inode.xid) ||
                    !reader.ReadU64(inode.timestamp_utc) ||
                    !reader.ReadU8(tombstone) ||
                    inode.object_id == 0 ||
                    inode.xid != delta.target_xid ||
                    is_directory > 1 ||
                    tombstone > 1)
                {
                    return { CheckpointDeltaParseStatus::InvalidRecord, std::nullopt };
                }
                inode.is_directory = is_directory != 0;
                inode.tombstone = tombstone != 0;
                delta.inode_updates.push_back(std::move(inode));
                break;
            }
            case SectionKind::DirectoryLink:
            {
                CheckpointDeltaDirectoryLinkUpdate link;
                std::uint8_t tombstone = 0;
                if (!reader.ReadU64(link.parent_object_id) ||
                    !reader.ReadString(link.entry_name) ||
                    !reader.ReadU64(link.child_object_id) ||
                    !reader.ReadU64(link.xid) ||
                    !reader.ReadU8(tombstone) ||
                    link.parent_object_id == 0 ||
                    link.child_object_id == 0 ||
                    link.xid != delta.target_xid ||
                    tombstone > 1)
                {
                    return { CheckpointDeltaParseStatus::InvalidRecord, std::nullopt };
                }
                link.tombstone = tombstone != 0;
                delta.directory_link_updates.push_back(std::move(link));
                break;
            }
            case SectionKind::Btree:
            {
                BtreeRecord record;
                std::uint8_t kind = 0;
                std::uint8_t tombstone = 0;
                std::span<const std::byte> key;
                std::span<const std::byte> value;
                if (!reader.ReadU8(kind) ||
                    !reader.ReadU8(tombstone) ||
                    !reader.ReadBytes(key) ||
                    !reader.ReadBytes(value) ||
                    kind < static_cast<std::uint8_t>(BtreeRecordKind::Inode) ||
                    kind > static_cast<std::uint8_t>(BtreeRecordKind::FileExtent) ||
                    tombstone > 1)
                {
                    return { CheckpointDeltaParseStatus::InvalidRecord, std::nullopt };
                }
                record.kind = static_cast<BtreeRecordKind>(kind);
                record.tombstone = tombstone != 0;
                record.key.assign(key.begin(), key.end());
                record.value.assign(value.begin(), value.end());
                delta.btree_records.push_back(std::move(record));
                break;
            }
            default:
                return { CheckpointDeltaParseStatus::InvalidRecord, std::nullopt };
            }
        }

        if (reader.offset() != section_end)
        {
            return { CheckpointDeltaParseStatus::InvalidRecord, std::nullopt };
        }
    }

    return { CheckpointDeltaParseStatus::Ok, std::move(delta) };
}

CheckpointDeltaChainResult CheckpointDeltaCodec::CompactChain(
    std::span<const CheckpointDelta> deltas,
    std::string_view expected_volume_identity,
    std::uint64_t base_xid)
{
    CheckpointDeltaChainResult result;
    if (deltas.empty() || expected_volume_identity.empty() || base_xid == 0)
    {
        result.status = CheckpointDeltaParseStatus::InvalidXid;
        return result;
    }

    result.compacted.volume_identity = std::string(expected_volume_identity);
    result.compacted.base_xid = base_xid;
    auto expected_base = base_xid;

    std::unordered_map<std::uint64_t, CheckpointDeltaObjectMapUpdate> object_map_by_id;
    std::unordered_map<std::uint64_t, CheckpointDeltaInodeUpdate> inode_by_id;
    std::unordered_map<std::wstring, CheckpointDeltaDirectoryLinkUpdate> link_by_key;
    std::unordered_map<std::string, BtreeRecord> btree_by_key;

    for (const auto& delta : deltas)
    {
        if (delta.volume_identity != expected_volume_identity ||
            delta.base_xid != expected_base ||
            !IsValidXidRange(delta.base_xid, delta.target_xid))
        {
            result.status = delta.volume_identity != expected_volume_identity
                ? CheckpointDeltaParseStatus::WrongVolume
                : CheckpointDeltaParseStatus::InvalidXid;
            return result;
        }

        for (const auto& update : delta.object_map_updates)
        {
            object_map_by_id[update.object_id] = update;
        }
        result.compacted.spaceman_allocations.insert(
            result.compacted.spaceman_allocations.end(),
            delta.spaceman_allocations.begin(),
            delta.spaceman_allocations.end());
        result.compacted.spaceman_deallocations.insert(
            result.compacted.spaceman_deallocations.end(),
            delta.spaceman_deallocations.begin(),
            delta.spaceman_deallocations.end());
        for (const auto& inode : delta.inode_updates)
        {
            inode_by_id[inode.object_id] = inode;
        }
        for (const auto& link : delta.directory_link_updates)
        {
            link_by_key[DirectoryLinkKey(link.parent_object_id, link.entry_name)] = link;
        }
        for (const auto& record : delta.btree_records)
        {
            btree_by_key[BtreeRecordKey(record)] = record;
        }

        expected_base = delta.target_xid;
    }

    result.target_xid = expected_base;
    result.compacted.target_xid = expected_base;
    result.compacted.object_map_updates.reserve(object_map_by_id.size());
    for (auto& [_, update] : object_map_by_id)
    {
        update.xid = expected_base;
        result.compacted.object_map_updates.push_back(std::move(update));
    }
    result.compacted.inode_updates.reserve(inode_by_id.size());
    for (auto& [_, inode] : inode_by_id)
    {
        inode.xid = expected_base;
        result.compacted.inode_updates.push_back(std::move(inode));
    }
    result.compacted.directory_link_updates.reserve(link_by_key.size());
    for (auto& [_, link] : link_by_key)
    {
        link.xid = expected_base;
        result.compacted.directory_link_updates.push_back(std::move(link));
    }
    result.compacted.btree_records.reserve(btree_by_key.size());
    for (auto& [_, record] : btree_by_key)
    {
        result.compacted.btree_records.push_back(std::move(record));
    }
    result.status = CheckpointDeltaParseStatus::Ok;
    return result;
}

std::vector<std::byte> CheckpointDeltaCodec::EncodeChain(
    std::span<const CheckpointDelta> deltas,
    std::string_view volume_identity,
    std::uint64_t base_xid)
{
    auto target_xid = base_xid;
    for (const auto& delta : deltas)
    {
        if (delta.volume_identity != volume_identity ||
            delta.base_xid != target_xid ||
            !IsValidXidRange(delta.base_xid, delta.target_xid))
        {
            return {};
        }

        target_xid = delta.target_xid;
    }

    std::vector<std::byte> out;
    std::size_t reserve_bytes = kChainHeaderBytes;
    for (const auto& delta : deltas)
    {
        const auto delta_bytes = EstimateEncodedDeltaBytes(delta);
        if (!delta_bytes.has_value() ||
            !AddLengthPrefixedBytes(reserve_bytes, delta_bytes.value()))
        {
            return {};
        }
    }
    out.reserve(reserve_bytes);
    AppendU32(out, kChainMagic);
    AppendU16(out, kVersion);
    AppendU16(out, 0);
    AppendU32(out, kChainHeaderBytes);
    AppendU32(out, 0);
    AppendU64(out, HashVolumeIdentity(volume_identity));
    AppendU64(out, base_xid);
    AppendU64(out, target_xid);
    AppendU32(out, static_cast<std::uint32_t>(deltas.size()));

    for (const auto& delta : deltas)
    {
        auto encoded = Encode(delta);
        if (encoded.empty())
        {
            return {};
        }
        AppendU32(out, static_cast<std::uint32_t>(encoded.size()));
        out.insert(out.end(), encoded.begin(), encoded.end());
    }

    if (out.size() != reserve_bytes)
    {
        return {};
    }
    PatchU32(out, 12, ComputeChecksum(out));
    return out;
}

CheckpointDeltaChainParseResult CheckpointDeltaCodec::DecodeChain(
    std::span<const std::byte> bytes,
    std::string_view expected_volume_identity,
    std::uint64_t expected_base_xid)
{
    CheckpointDeltaChainParseResult result;
    if (bytes.empty())
    {
        result.status = CheckpointDeltaParseStatus::Empty;
        return result;
    }
    if (bytes.size() < kChainHeaderBytes)
    {
        result.status = CheckpointDeltaParseStatus::Truncated;
        return result;
    }

    Reader reader(bytes);
    std::uint32_t magic = 0;
    std::uint16_t version = 0;
    std::uint16_t flags = 0;
    std::uint32_t header_bytes = 0;
    std::uint32_t expected_checksum = 0;
    std::uint64_t volume_hash = 0;
    std::uint64_t base_xid = 0;
    std::uint64_t target_xid = 0;
    std::uint32_t record_count = 0;
    if (!reader.ReadU32(magic) ||
        !reader.ReadU16(version) ||
        !reader.ReadU16(flags) ||
        !reader.ReadU32(header_bytes) ||
        !reader.ReadU32(expected_checksum) ||
        !reader.ReadU64(volume_hash) ||
        !reader.ReadU64(base_xid) ||
        !reader.ReadU64(target_xid) ||
        !reader.ReadU32(record_count))
    {
        result.status = CheckpointDeltaParseStatus::Truncated;
        return result;
    }

    if (magic != kChainMagic || header_bytes != kChainHeaderBytes || flags != 0)
    {
        result.status = CheckpointDeltaParseStatus::InvalidHeader;
        return result;
    }
    if (version != kVersion)
    {
        result.status = CheckpointDeltaParseStatus::UnsupportedVersion;
        return result;
    }
    if (expected_checksum != ComputeChecksum(bytes))
    {
        result.status = CheckpointDeltaParseStatus::InvalidChecksum;
        return result;
    }
    if (base_xid == 0 || base_xid != expected_base_xid)
    {
        result.status = CheckpointDeltaParseStatus::InvalidXid;
        return result;
    }
    if (expected_volume_identity.empty() ||
        volume_hash != HashVolumeIdentity(expected_volume_identity))
    {
        result.status = CheckpointDeltaParseStatus::WrongVolume;
        return result;
    }

    result.base_xid = base_xid;
    result.target_xid = target_xid;
    result.deltas.reserve(record_count);

    auto expected_delta_base = base_xid;
    for (std::uint32_t index = 0; index < record_count; ++index)
    {
        std::span<const std::byte> encoded_delta;
        if (!reader.ReadBytes(encoded_delta))
        {
            result.status = CheckpointDeltaParseStatus::Truncated;
            result.deltas.clear();
            return result;
        }

        auto parsed = Decode(encoded_delta, expected_volume_identity);
        if (parsed.status != CheckpointDeltaParseStatus::Ok || !parsed.delta.has_value())
        {
            result.status = parsed.status;
            result.deltas.clear();
            return result;
        }
        if (parsed.delta->base_xid != expected_delta_base)
        {
            result.status = CheckpointDeltaParseStatus::InvalidXid;
            result.deltas.clear();
            return result;
        }

        expected_delta_base = parsed.delta->target_xid;
        result.deltas.push_back(std::move(parsed.delta.value()));
    }

    if (reader.remaining() != 0 ||
        expected_delta_base != target_xid ||
        (record_count == 0 && target_xid != base_xid))
    {
        result.status = CheckpointDeltaParseStatus::InvalidXid;
        result.deltas.clear();
        return result;
    }

    result.status = CheckpointDeltaParseStatus::Ok;
    return result;
}

CheckpointDeltaParseStatus CheckpointDeltaCodec::ApplyDelta(
    CheckpointDeltaState& state,
    const CheckpointDelta& delta)
{
    if (state.volume_identity != delta.volume_identity)
    {
        return CheckpointDeltaParseStatus::WrongVolume;
    }
    if (state.checkpoint_xid != delta.base_xid ||
        !IsValidDeltaForApply(delta))
    {
        return CheckpointDeltaParseStatus::InvalidXid;
    }

    auto next = state;
    for (const auto& update : delta.object_map_updates)
    {
        if (update.tombstone)
        {
            next.object_map.erase(update.object_id);
        }
        else
        {
            next.object_map[update.object_id] = update;
        }
    }
    for (const auto& allocation : delta.spaceman_allocations)
    {
        next.spaceman_allocations.push_back(allocation);
    }
    for (const auto& deallocation : delta.spaceman_deallocations)
    {
        if (!RemoveExtent(next.spaceman_allocations, deallocation))
        {
            return CheckpointDeltaParseStatus::InvalidRecord;
        }
    }
    for (const auto& inode : delta.inode_updates)
    {
        if (inode.tombstone)
        {
            next.inodes.erase(inode.object_id);
        }
        else
        {
            next.inodes[inode.object_id] = inode;
        }
    }
    for (const auto& link : delta.directory_link_updates)
    {
        const auto key = DirectoryLinkKey(link.parent_object_id, link.entry_name);
        if (link.tombstone)
        {
            next.directory_links.erase(key);
        }
        else
        {
            next.directory_links[key] = link;
        }
    }
    for (const auto& record : delta.btree_records)
    {
        const auto key = BtreeRecordKey(record);
        if (record.tombstone)
        {
            next.btree_records.erase(key);
        }
        else
        {
            next.btree_records[key] = record;
        }
    }

    next.checkpoint_xid = delta.target_xid;
    state = std::move(next);
    return CheckpointDeltaParseStatus::Ok;
}

CheckpointDeltaParseStatus CheckpointDeltaCodec::ApplyChain(
    CheckpointDeltaState& state,
    std::span<const CheckpointDelta> deltas)
{
    if (deltas.empty())
    {
        return CheckpointDeltaParseStatus::Empty;
    }

    auto next = state;
    for (const auto& delta : deltas)
    {
        const auto status = ApplyDelta(next, delta);
        if (status != CheckpointDeltaParseStatus::Ok)
        {
            return status;
        }
    }

    state = std::move(next);
    return CheckpointDeltaParseStatus::Ok;
}
} // namespace apfsaccess::rw
