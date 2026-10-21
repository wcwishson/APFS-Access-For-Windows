#include "NativeApfsReader.h"
#include "ApfsCompression.h"
#include "ApfsContainerCatalog.h"
#include "ApfsExtendedRecordCodec.h"
#include "ApfsFirmlinkRouter.h"
#include "AppleTransactionCommit.h"
#include "SnapshotRuntime.h"
#include "RandomAccessSource.h"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <cwchar>
#include <iostream>
#include <iterator>
#include <limits>
#include <queue>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>
#include <Windows.h>
#include "SnapshotCompressionRead.h"

namespace apfsaccess::rw
{
namespace
{
constexpr std::uint32_t kNxsbMagic = 0x4253584E; // 'NXSB'
constexpr std::uint32_t kApsbMagic = 0x42535041; // 'APSB'
constexpr std::uint32_t kObjectTypeMask = 0x0000FFFF;
constexpr std::uint32_t kObjectTypeOmap = 0x0000000B;
constexpr std::uint32_t kObjectTypeBtree = 0x00000002;
constexpr std::uint32_t kObjectTypeBtreeNode = 0x00000003;
constexpr std::uint32_t kObjectTypeFs = 0x0000000D;
constexpr std::uint32_t kObjectTypeCheckpointMap = 0x0000000C;
constexpr std::uint16_t kBtnodeRoot = 0x0001;
constexpr std::uint16_t kBtnodeLeaf = 0x0002;
constexpr std::uint16_t kBtnodeFixedKvSize = 0x0004;
constexpr std::uint64_t kApfsObjectIdMask = 0x0fffffffffffffffull;
constexpr std::uint64_t kApfsObjectTypeShift = 60;
constexpr std::uint64_t kApfsTypeInode = 3;
constexpr std::uint64_t kApfsTypeXattr = 4;
constexpr std::uint64_t kApfsTypeSiblingLink = 5;
constexpr std::uint64_t kApfsTypeFileExtent = 8;
constexpr std::uint64_t kApfsTypeDirectoryRecord = 9;
constexpr std::uint64_t kApfsTypeSiblingMap = 12;
constexpr std::uint64_t kRootDirectoryInode = 2;

bool MaterializeNamespaceRecord(
    const std::shared_ptr<catalog::ApfsReadBudget>& budget,
    const catalog::BtreeRecord& record, std::uint64_t type)
{
    if (!budget) return true;
    // Extents decode to scalars and bounded index/vector entries. Variable
    // metadata still reserves its larger codec and name-expansion envelope.
    const auto base = type == kApfsTypeFileExtent ? 1024ull : 4096ull;
    const auto factor = type == kApfsTypeFileExtent ? 4ull : 32ull;
    const auto key_bytes = static_cast<std::uint64_t>(record.key.size());
    const auto value_bytes = static_cast<std::uint64_t>(record.value.size());
    if (value_bytes > UINT64_MAX - key_bytes ||
        key_bytes + value_bytes > (UINT64_MAX - base) / factor)
        return budget->Refuse("ApfsReadBudgetRecordLimit");
    return budget->Materialize(1, base + factor * (key_bytes + value_bytes));
}

constexpr std::uint8_t kInodeExtendedFieldDataStream = 8;
constexpr std::uint8_t kInodeExtendedFieldSparseBytes = 13;
constexpr std::uint64_t kInodeHasSparseBytes = 0x200;
constexpr std::size_t kInodeUncompressedSizeOffset = 0x54;
constexpr std::size_t kInodeExtendedFieldsOffset = 0x5C;
constexpr std::uint64_t kWindowsFileTimeUnixEpochTicks = 116444736000000000ull;
constexpr std::uint16_t kModeTypeMask = 0170000;
constexpr std::uint16_t kModeDirectory = 0040000;
constexpr std::uint16_t kModeRegular = 0100000;
constexpr std::uint16_t kModeSymlink = 0120000;
constexpr std::uint16_t kModeFifo = 0010000;
constexpr std::uint16_t kModeSocket = 0140000;
constexpr std::uint16_t kModeCharacterDevice = 0020000;
constexpr std::uint16_t kModeBlockDevice = 0060000;
constexpr std::uint16_t kDrecTypeMask = 0x000f;
constexpr std::uint16_t kDrecTypeDirectory = 4;
constexpr std::size_t kObjectHeaderBytes = 0x20;
constexpr std::size_t kBtreeDataOffset = 0x38;
constexpr std::size_t kBtreeInfoBytes = 40;

// Read-only RandomAccessSource view over a BlockDevice (which already applies
// its base offset, so this is a store-relative view for offset devices).
class BlockDeviceSource final : public catalog::RandomAccessSource
{
public:
    explicit BlockDeviceSource(const BlockDevice& device,
        std::shared_ptr<catalog::ApfsReadBudget> budget = {})
        : device_(device), budget_(std::move(budget))
    {
    }

    std::shared_ptr<catalog::ApfsReadBudget> ReadBudget() const override { return budget_; }

    [[nodiscard]] std::uint64_t SizeBytes() const override
    {
        return device_.GetGeometry().total_bytes;
    }

    [[nodiscard]] bool Read(
        std::uint64_t offset,
        std::size_t size,
        std::vector<std::byte>& out_bytes) const override
    {
        out_bytes.clear();
        if (budget_ && !budget_->Read(size)) return false;
        if (size == 0)
        {
            return true;
        }
        if (!device_.Read(offset, size, out_bytes) || out_bytes.size() != size)
        {
            out_bytes.clear();
            return false;
        }
        return true;
    }

private:
    const BlockDevice& device_;
    std::shared_ptr<catalog::ApfsReadBudget> budget_;
};

std::uint16_t ReadLe16(const std::vector<std::byte>& buffer, std::size_t offset)
{
    if (offset + sizeof(std::uint16_t) > buffer.size())
    {
        return 0;
    }
    return static_cast<std::uint16_t>(std::to_integer<unsigned char>(buffer[offset + 0])) |
           (static_cast<std::uint16_t>(std::to_integer<unsigned char>(buffer[offset + 1])) << 8);
}

std::uint32_t ReadLe32(const std::vector<std::byte>& buffer, std::size_t offset)
{
    if (offset + sizeof(std::uint32_t) > buffer.size())
    {
        return 0;
    }
    return static_cast<std::uint32_t>(std::to_integer<unsigned char>(buffer[offset + 0])) |
           (static_cast<std::uint32_t>(std::to_integer<unsigned char>(buffer[offset + 1])) << 8) |
           (static_cast<std::uint32_t>(std::to_integer<unsigned char>(buffer[offset + 2])) << 16) |
           (static_cast<std::uint32_t>(std::to_integer<unsigned char>(buffer[offset + 3])) << 24);
}

std::uint64_t ReadLe64(const std::vector<std::byte>& buffer, std::size_t offset)
{
    if (offset + sizeof(std::uint64_t) > buffer.size())
    {
        return 0;
    }

    std::uint64_t value = 0;
    for (int index = 0; index < 8; ++index)
    {
        value |= static_cast<std::uint64_t>(std::to_integer<unsigned char>(buffer[offset + static_cast<std::size_t>(index)])) << (index * 8);
    }
    return value;
}

void AppendLe32(std::vector<std::byte>& buffer, std::uint32_t value)
{
    buffer.push_back(static_cast<std::byte>(value & 0xffu));
    buffer.push_back(static_cast<std::byte>((value >> 8) & 0xffu));
    buffer.push_back(static_cast<std::byte>((value >> 16) & 0xffu));
    buffer.push_back(static_cast<std::byte>((value >> 24) & 0xffu));
}

void AppendLe64(std::vector<std::byte>& buffer, std::uint64_t value)
{
    for (int index = 0; index < 8; ++index)
    {
        buffer.push_back(static_cast<std::byte>((value >> (index * 8)) & 0xffu));
    }
}

void AppendWideString(std::vector<std::byte>& buffer, const std::wstring& value)
{
    AppendLe32(buffer, static_cast<std::uint32_t>(value.size()));
    for (const auto ch : value)
    {
        const auto code_unit = static_cast<std::uint16_t>(ch);
        buffer.push_back(static_cast<std::byte>(code_unit & 0xffu));
        buffer.push_back(static_cast<std::byte>((code_unit >> 8) & 0xffu));
    }
}

std::wstring NormalizePath(const std::wstring& path)
{
    if (path.empty() || path == L"\\")
    {
        return L"\\";
    }

    std::wstring normalized = path;
    std::replace(normalized.begin(), normalized.end(), L'/', L'\\');
    if (normalized.front() != L'\\')
    {
        normalized.insert(normalized.begin(), L'\\');
    }
    while (normalized.size() > 1 && normalized.back() == L'\\')
    {
        normalized.pop_back();
    }
    return normalized;
}

std::wstring JoinPath(const std::wstring& parent, const std::wstring& name)
{
    const auto normalized_parent = NormalizePath(parent);
    if (normalized_parent == L"\\")
    {
        return L"\\" + name;
    }
    return normalized_parent + L"\\" + name;
}

bool IsSupportedFileTypeFromMode(std::uint16_t mode)
{
    const auto type = static_cast<std::uint16_t>(mode & kModeTypeMask);
    return type == kModeDirectory || type == kModeRegular || type == kModeSymlink ||
        type == kModeFifo || type == kModeSocket ||
        type == kModeCharacterDevice || type == kModeBlockDevice;
}

bool IsDirectoryMode(std::uint16_t mode)
{
    return static_cast<std::uint16_t>(mode & kModeTypeMask) == kModeDirectory;
}

bool IsDirectoryDrec(std::uint16_t flags)
{
    return static_cast<std::uint16_t>(flags & kDrecTypeMask) == kDrecTypeDirectory;
}

bool IsSupportedDrec(std::uint16_t flags)
{
    const auto type = static_cast<std::uint16_t>(flags & kDrecTypeMask);
    return IsSupportedFileTypeFromMode(static_cast<std::uint16_t>(type << 12));
}

std::uint64_t AlignUp(std::uint64_t value, std::uint64_t alignment)
{
    if (alignment == 0)
    {
        return value;
    }
    const auto remainder = value % alignment;
    if (remainder == 0)
    {
        return value;
    }
    if (value > (std::numeric_limits<std::uint64_t>::max() - (alignment - remainder)))
    {
        return 0;
    }
    return value + (alignment - remainder);
}

bool NormalizeFileExtents(
    std::vector<MetadataStore::FileExtent> extents,
    std::vector<MetadataStore::FileExtent>& normalized)
{
    normalized.clear();
    if (extents.empty())
    {
        return true;
    }

    std::sort(extents.begin(), extents.end(), [](const auto& lhs, const auto& rhs)
    {
        if (lhs.logical_offset != rhs.logical_offset)
        {
            return lhs.logical_offset < rhs.logical_offset;
        }
        if (lhs.physical_address != rhs.physical_address)
        {
            return lhs.physical_address < rhs.physical_address;
        }
        return lhs.bytes < rhs.bytes;
    });

    std::uint64_t previous_end = 0;
    bool has_previous = false;
    for (const auto& extent : extents)
    {
        if (extent.bytes == 0 ||
            extent.logical_offset > (std::numeric_limits<std::uint64_t>::max() - extent.bytes) ||
            extent.physical_address > (std::numeric_limits<std::uint64_t>::max() - extent.bytes))
        {
            return false;
        }
        if (!normalized.empty())
        {
            const auto& previous = normalized.back();
            if (extent.logical_offset == previous.logical_offset &&
                extent.physical_address == previous.physical_address &&
                extent.bytes == previous.bytes)
            {
                continue;
            }
        }
        if (has_previous && extent.logical_offset < previous_end)
        {
            return false;
        }

        previous_end = extent.logical_offset + extent.bytes;
        has_previous = true;
        normalized.push_back(extent);
    }

    return true;
}

std::optional<MetadataStore::FileExtent> TryResolveSingleExtentProjection(
    const std::vector<MetadataStore::FileExtent>& extents,
    std::uint64_t logical_size)
{
    if (logical_size == 0 || extents.size() != 1)
    {
        return std::nullopt;
    }

    const auto& extent = extents.front();
    if (extent.logical_offset != 0 ||
        extent.physical_address == 0 ||
        extent.bytes < logical_size)
    {
        return std::nullopt;
    }

    return MetadataStore::FileExtent
    {
        0,
        extent.physical_address,
        extent.bytes
    };
}

MetadataStore::NodeType NodeTypeFromMode(std::uint16_t mode)
{
    switch (static_cast<std::uint16_t>(mode & kModeTypeMask))
    {
    case kModeDirectory:
        return MetadataStore::NodeType::Directory;
    case kModeSymlink:
        return MetadataStore::NodeType::SymbolicLink;
    case kModeFifo:
        return MetadataStore::NodeType::Fifo;
    case kModeSocket:
        return MetadataStore::NodeType::Socket;
    case kModeCharacterDevice:
        return MetadataStore::NodeType::CharacterDevice;
    case kModeBlockDevice:
        return MetadataStore::NodeType::BlockDevice;
    default:
        return MetadataStore::NodeType::RegularFile;
    }
}

bool IsReadTraceEnabled()
{
    static const bool enabled = []()
    {
        wchar_t value[8]{};
        const auto chars = GetEnvironmentVariableW(L"APFSACCESS_TRACE_READS", value, static_cast<DWORD>(std::size(value)));
        return chars > 0 && value[0] != L'\0' && value[0] != L'0';
    }();
    return enabled;
}

struct InodeDataStreamInfo
{
    std::uint64_t logical_size = 0;
    std::uint64_t allocated_size = std::numeric_limits<std::uint64_t>::max();
};

std::optional<InodeDataStreamInfo> ReadInodeDataStreamInfo(const std::vector<std::byte>& inode_value)
{
    if (inode_value.size() < kInodeExtendedFieldsOffset + 4)
    {
        return std::nullopt;
    }

    const auto field_count = static_cast<std::size_t>(ReadLe16(inode_value, kInodeExtendedFieldsOffset));
    const auto used_data = static_cast<std::size_t>(ReadLe16(inode_value, kInodeExtendedFieldsOffset + 2));
    if (field_count == 0 || used_data == 0)
    {
        return std::nullopt;
    }

    const auto metadata_bytes = field_count * 4;
    if (field_count > 1024 ||
        metadata_bytes > inode_value.size() - (kInodeExtendedFieldsOffset + 4) ||
        used_data < metadata_bytes ||
        used_data > inode_value.size() - (kInodeExtendedFieldsOffset + 4))
    {
        return std::nullopt;
    }

    const auto field_table_start = kInodeExtendedFieldsOffset + 4;
    auto data_cursor = field_table_start + metadata_bytes;
    const auto data_end = field_table_start + used_data;
    if (data_cursor > data_end || data_end > inode_value.size())
    {
        return std::nullopt;
    }

    for (std::size_t index = 0; index < field_count; ++index)
    {
        const auto field_offset = field_table_start + (index * 4);
        if (field_offset + 4 > inode_value.size())
        {
            return std::nullopt;
        }

        const auto field_type = std::to_integer<unsigned char>(inode_value[field_offset]);
        const auto field_size = static_cast<std::size_t>(ReadLe16(inode_value, field_offset + 2));
        if (field_size > data_end - data_cursor)
        {
            return std::nullopt;
        }

        if (field_type == kInodeExtendedFieldDataStream && field_size >= sizeof(std::uint64_t))
        {
            InodeDataStreamInfo info{};
            info.logical_size = ReadLe64(inode_value, data_cursor);
            if (field_size >= sizeof(std::uint64_t) * 2)
            {
                info.allocated_size = ReadLe64(inode_value, data_cursor + sizeof(std::uint64_t));
            }
            else
            {
                info.allocated_size = AlignUp(info.logical_size, 8);
            }
            return info;
        }

        const auto padded_size = static_cast<std::size_t>(AlignUp(field_size, 8));
        if (padded_size < field_size || padded_size > data_end - data_cursor)
        {
            return std::nullopt;
        }
        data_cursor += padded_size;
    }

    return std::nullopt;
}

std::uint64_t ApfsNanosecondsToFileTime(std::uint64_t apfs_nanoseconds)
{
    const auto filetime_ticks = apfs_nanoseconds / 100;
    if (filetime_ticks > std::numeric_limits<std::uint64_t>::max() - kWindowsFileTimeUnixEpochTicks)
    {
        return 0;
    }
    return kWindowsFileTimeUnixEpochTicks + filetime_ticks;
}
bool ProjectValidatedAttributeStreams(
    const std::vector<catalog::BtreeRecord>& records,
    std::uint32_t block_size, std::uint64_t block_count,
    std::uint64_t store_offset, NativeApfsVolumeProjection& projection, bool strict,
    std::uint64_t routed_address_blocks = 0, bool observational = false)
{
    const auto address_blocks = routed_address_blocks ? routed_address_blocks : block_count;
    const auto container_bytes = block_count * block_size;
    std::string error;
    struct Stream
    {
        std::vector<std::byte> descriptor;
        std::uint64_t owners = 0;
        bool invalid = false;
        std::vector<MetadataStore::FileExtent> extents;
    };
    std::unordered_map<std::uint64_t, Stream> streams;
    std::unordered_map<std::uint64_t, std::uint32_t> references;
    std::unordered_set<std::uint64_t> inode_streams;
    for (const auto& record : records)
    {
        if (record.key.size() < 8) return false;
        const auto key = ReadLe64(record.key, 0);
        const auto type = key >> kApfsObjectTypeShift;
        if (type == kApfsTypeInode)
        {
            AppleInodeRecord inode;
            if (!(observational ? ApfsExtendedRecordCodec::DecodeInodeReadOnly(record, inode, error) :
                ApfsExtendedRecordCodec::DecodeInode(record, inode, error))) return false;
            inode_streams.insert(inode.object_id);
            inode_streams.insert(inode.private_id);
        }
        else if (type == 6)
        {
            AppleDataStreamIdRecord reference;
            if (!DecodeAppleDataStreamIdRecord(record, reference, error) ||
                !references.emplace(reference.object_id, reference.reference_count).second) return false;
        }
        else if (type == kApfsTypeXattr)
        {
            AppleXattrRecord attribute;
            if (!ApfsExtendedRecordCodec::DecodeXattr(record, attribute, error)) return false;
            if ((attribute.flags & kAppleXattrDataStream) == 0) continue;
            if (attribute.data.size() != kAppleXattrDataStreamBytes) return false;
            const auto id = ReadLe64(attribute.data, 0);
            auto& stream = streams[id];
            if (stream.owners++ == 0) stream.descriptor = attribute.data;
            else if (stream.descriptor != attribute.data) stream.invalid = true;
            if (id == 0 ||
                (attribute.flags & ~(kAppleXattrDataStream | kAppleXattrFileSystemOwned)) != 0 ||
                ReadLe64(attribute.data, 24) != 0) stream.invalid = true;
        }
    }
    for (const auto& record : records)
    {
        const auto key = ReadLe64(record.key, 0);
        if ((key >> kApfsObjectTypeShift) != kApfsTypeFileExtent) continue;
        const auto found = streams.find(key & kApfsObjectIdMask);
        if (found == streams.end()) continue;
        auto& stream = found->second;
        AppleFileExtentRecord extent;
        if (!DecodeAppleFileExtentRecord(record, block_size, extent, error) || extent.crypto_id != 0 ||
            extent.physical_block == 0 ||
            extent.physical_block >= address_blocks ||
            extent.length_bytes / block_size > address_blocks - extent.physical_block)
        {
            stream.invalid = true;
            continue;
        }
        stream.extents.push_back({extent.logical_address,
            store_offset + extent.physical_block * block_size, extent.length_bytes});
    }
    for (auto& [id, stream] : streams)
    {
        const auto reference = references.find(id);
        if (stream.invalid || inode_streams.contains(id) || reference == references.end() ||
            reference->second != stream.owners) { if (strict) return false; continue; }
        const auto logical_size = ReadLe64(stream.descriptor, 8);
        const auto allocated_size = ReadLe64(stream.descriptor, 16);
        if (logical_size > allocated_size || allocated_size > container_bytes ||
            allocated_size % block_size != 0) { if (strict) return false; continue; }
        std::sort(stream.extents.begin(), stream.extents.end(), [](const auto& left, const auto& right) {
            return left.logical_offset < right.logical_offset;
        });
        std::uint64_t covered = 0;
        for (const auto& extent : stream.extents)
        {
            if (extent.logical_offset != covered || extent.bytes > allocated_size - covered)
            {
                stream.invalid = true;
                break;
            }
            covered += extent.bytes;
        }
        if (stream.invalid || covered != allocated_size) { if (strict) return false; continue; }
        projection.attribute_stream_extents.emplace(id,
            std::make_shared<const std::vector<MetadataStore::FileExtent>>(std::move(stream.extents)));
    }
    return true;
}

void ProjectAttributeStreams(
    const std::vector<catalog::BtreeRecord>& records,
    const std::vector<catalog::BtreeRecord>& extentref_records,
    const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint,
    std::uint64_t store_offset, NativeApfsVolumeProjection& projection)
{
    const auto budget = source.ReadBudget();
    bool completed = false;
    struct ProjectionBudgetScope
    {
        const std::shared_ptr<catalog::ApfsReadBudget>& budget;
        bool& completed;
        ~ProjectionBudgetScope() { if (budget && !completed) (void)budget->Refuse("ApfsReadBudgetAttributeOwnershipUnproven"); }
    } projection_budget_scope{budget, completed};
    if (budget)
    {
        for (const auto* input : {&records, &extentref_records})
            for (const auto& record : *input)
            {
                const auto bytes = record.key.size() + record.value.size();
                if (bytes > (UINT64_MAX - 1024) / 4 || !budget->Materialize(1, 1024 + bytes * 4)) return;
            }
    }
    const auto block_size = checkpoint.container.superblock.block_size;
    const auto block_count = checkpoint.container.superblock.block_count;
    if (block_size == 0 || block_count > (std::numeric_limits<std::uint64_t>::max)() / block_size)
        return;
    const auto container_bytes = block_count * block_size;
    if (store_offset > (std::numeric_limits<std::uint64_t>::max)() - container_bytes) return;
    std::string error;
    std::vector<ApplePhysicalExtentRecord> physical;
    std::vector<catalog::BtreeRecord> live_references;
    const auto selected = std::find_if(checkpoint.volumes.begin(), checkpoint.volumes.end(),
        [&](const auto& volume) { return volume.superblock.object_id == projection.volume_object_id; });
    const auto* references = &extentref_records;
    if (selected != checkpoint.volumes.end() && selected->superblock.role_raw == 0x0180 &&
        selected->object_map.snapshot_tree_oid)
    {
        // Backup extent-reference trees include historical owners. Resolve the
        // canonical chronological layers before validating this live fork map.
        if (!LoadSnapshotRuntimeLiveReferences(source, checkpoint, projection.volume_object_id,
                live_references, error)) return;
        references = &live_references;
    }
    if (!ValidateApplePayloadExtentGraph(records, *references,
            block_size, block_count, physical, error)) return;
    // The snapshot resolver above first proves complete retained metadata and
    // payload ownership. The ordinary checker deliberately excludes snapshots.
    if (references == &extentref_records &&
        !ValidateAppleCheckpointPayloadOwnership(source, checkpoint, physical, error)) return;

    if (!ProjectValidatedAttributeStreams(records, block_size, block_count,
        store_offset, projection, false)) return;
    completed = true;
}

void ProjectExternalCompressionSizes(const catalog::RandomAccessSource& source,
    NativeApfsVolumeProjection& projection)
{
    const auto budget = source.ReadBudget();
    const ApfsCompressionLimits limits;
    std::unordered_map<std::uint64_t, BtreeRecord> refreshed;
    for (auto& inode : projection.inodes) {
        if (inode.node_type != MetadataStore::NodeType::RegularFile ||
            (inode.internal_flags & kAppleInodeHasUncompressedSize) != 0) continue;
        const auto owner = projection.extended_attributes_by_inode.find(inode.object_id);
        if (owner == projection.extended_attributes_by_inode.end()) continue;
        const auto attribute = owner->second.find("com.apple.decmpfs");
        if (attribute == owner->second.end()) continue;
        const auto& raw = attribute->second;
        if ((raw.flags & ~kAppleXattrFileSystemOwned) != kAppleXattrDataStream ||
            raw.data.size() != kAppleXattrDataStreamBytes) continue;
        const auto size = ReadLe64(raw.data, 8);
        if (size < 16 || size > limits.max_decmpfs_bytes) continue;
        const auto stream = projection.attribute_stream_extents.find(ReadLe64(raw.data, 0));
        if (stream == projection.attribute_stream_extents.end() || !stream->second ||
            stream->second->empty()) continue;
        const auto& first = stream->second->front();
        if (first.logical_offset != 0 || first.physical_address == 0 || first.bytes < size) continue;
        if (budget && !budget->Materialize(1, size)) return;
        std::vector<std::byte> descriptor;
        if (!source.Read(first.physical_address, static_cast<std::size_t>(size), descriptor) ||
            descriptor.size() != size) continue;
        ApfsCompressionHeader header;
        if (!ApfsCompression::Inspect(descriptor, limits, header) ||
            inode.logical_size == header.uncompressed_size) continue;
        if (budget && !budget->Materialize(1, 192 + inode.name.size() * sizeof(wchar_t))) return;
        inode.logical_size = header.uncompressed_size;
        refreshed.emplace(inode.object_id, BtreeMutationCodec::EncodeInodeRecord(
            inode.object_id, inode.parent_object_id, inode.name, inode.is_directory,
            inode.logical_size, inode.data_physical_address, inode.timestamp_utc,
            inode.xid, false));
    }
    // Keep the in-memory compatibility index consistent with the native view.
    for (auto& record : projection.btree_records) {
        if (record.kind != BtreeRecordKind::Inode || record.key.size() != 17) continue;
        const auto found = refreshed.find(ReadLe64(record.key, 9));
        if (found != refreshed.end() && record.key == found->second.key)
            record = std::move(found->second);
    }
}
} // namespace

namespace
{
// Record the metadata actually read by the authoritative resolver. This is
// operation-local read evidence, not a retained-block allocation oracle.
class SnapshotMetadataSource final : public catalog::RandomAccessSource
{
public:
    explicit SnapshotMetadataSource(const catalog::RandomAccessSource& source) : source_(source) {}
    std::uint64_t SizeBytes() const override { return source_.SizeBytes(); }
    std::shared_ptr<catalog::ApfsReadBudget> ReadBudget() const override { return source_.ReadBudget(); }
    bool Read(std::uint64_t offset, std::size_t size, std::vector<std::byte>& out) const override
    {
        out.clear();
        if (!ReadBudget()->Materialize(1, 2 * sizeof(Range))) return false;
        if (!source_.Read(offset, size, out)) return false;
        if (size) ranges.emplace_back(offset, offset + size);
        return true;
    }
    using Range = std::pair<std::uint64_t, std::uint64_t>;
    mutable std::vector<Range> ranges;
private:
    const catalog::RandomAccessSource& source_;
};

bool ValidateSnapshotStreams(const std::vector<catalog::BtreeRecord>& records,
    NativeApfsVolumeProjection& projection,
    const std::shared_ptr<catalog::ApfsReadBudget>& budget, std::string& error, bool observational = false,
    const std::unordered_set<std::uint64_t>* compressed = nullptr)
{
    const auto fail = [&](const char* reason) { error = reason; return false; };
    std::unordered_map<std::uint64_t, std::uint32_t> owners, references;
    std::unordered_set<std::uint64_t> file_streams;
    std::unordered_set<std::uint64_t> projected_file_streams;
    struct NativeSparseMetadata
    {
        std::uint64_t bytes = 0;
        std::optional<std::uint64_t> allocation_size;
    };
    std::unordered_map<std::uint64_t, NativeSparseMetadata> sparse_bytes;
    for (const auto& record : records)
    {
        if ((ReadLe64(record.key, 0) >> kApfsObjectTypeShift) != kApfsTypeInode) continue;
        AppleInodeRecord inode;
        if (!(observational ? ApfsExtendedRecordCodec::DecodeInodeReadOnly(record, inode, error) :
            ApfsExtendedRecordCodec::DecodeInode(record, inode, error))) return false;
        bool sparse = false;
        std::optional<std::uint64_t> native_allocation_size;
        for (const auto& field : inode.extended_fields)
        {
            if (field.type == kInodeExtendedFieldDataStream)
            {
                if (field.data.size() != 40 || ReadLe64(field.data, 16) != 0)
                    return fail("SnapshotEncryptedOrMalformedDataStreamUnsupported");
                native_allocation_size = ReadLe64(field.data, 8);
            }
            if (field.type != kInodeExtendedFieldSparseBytes) continue;
            if (field.data.size() != sizeof(std::uint64_t)) return fail("SnapshotSparseMetadataInvalid");
            if (!budget || !budget->Materialize(1, 64 + sizeof(std::pair<std::uint64_t, NativeSparseMetadata>)))
                return fail("SnapshotProjectionBudget");
            if (!sparse_bytes.emplace(inode.object_id, NativeSparseMetadata{ReadLe64(field.data, 0), {}}).second)
                return fail("SnapshotSparseMetadataInvalid");
            sparse = true;
        }
        if (sparse != ((inode.internal_flags & kAppleInodeSparseFlag) != 0))
            return fail("SnapshotSparseMetadataInvalid");
        if (sparse) sparse_bytes.at(inode.object_id).allocation_size = native_allocation_size;
    }
    for (const auto& inode : projection.inodes)
    {
        if (inode.node_type != MetadataStore::NodeType::RegularFile) continue;
        if (inode.private_id == 0 || inode.private_id >= kApfsObjectIdMask)
            return fail("SnapshotFileStreamIdentityInvalid");
        file_streams.insert(inode.private_id);
        ++owners[inode.private_id]; // hardlinks are one inode, not extra stream owners
        const auto attributes = projection.extended_attributes_by_inode.find(inode.object_id);
        // Compressed read plans require a separate immutable read adapter. Do
        // not publish apparently ordinary zero bytes for an unsupported codec.
        if ((inode.bsd_flags & kAppleBsdCompressedFlag) ||
            (attributes != projection.extended_attributes_by_inode.end() &&
                attributes->second.contains("com.apple.decmpfs")))
        {
            if (!compressed || !compressed->contains(inode.object_id))
                return fail("SnapshotCompressedDataProjectionUnsupported");
            // A compressed default fork has no payload mappings. Its historical
            // attribute forks still pass the complete ownership census below.
            continue;
        }
        const auto found = projection.read_extents_by_inode.find(inode.object_id);
        if (found != projection.read_extents_by_inode.end() && !found->second.empty())
            projected_file_streams.insert(inode.private_id);
        if (projection.block_size == 0 ||
            inode.logical_size > UINT64_MAX - (projection.block_size - 1))
            return fail("SnapshotFileExtentCoverageInvalid");
        const auto covered = AlignUp(inode.logical_size, projection.block_size);
        std::uint64_t end = 0, allocated = 0;
        bool implicit_holes = false;
        if (found != projection.read_extents_by_inode.end())
            for (const auto& extent : found->second)
            {
                if (!extent.bytes || extent.logical_offset < end || extent.logical_offset > covered ||
                    extent.bytes > covered - extent.logical_offset)
                    return fail("SnapshotFileExtentCoverageInvalid");
                implicit_holes |= extent.logical_offset != end;
                end = extent.logical_offset + extent.bytes;
                if (extent.physical_address) allocated += extent.bytes;
            }
        implicit_holes |= end != covered;
        const auto declared = sparse_bytes.find(inode.object_id);
        // Projected allocation can default to zero without a native dstream.
        // Implicit holes require its actual decoded allocation field.
        if ((inode.allocation_size && allocated != *inode.allocation_size) ||
            (implicit_holes && (!(inode.internal_flags & kAppleInodeSparseFlag) ||
                declared == sparse_bytes.end() || !declared->second.allocation_size ||
                allocated != *declared->second.allocation_size)))
            return fail("SnapshotFileExtentCoverageInvalid");
        if (declared != sparse_bytes.end() && declared->second.bytes != covered - allocated)
            return fail("SnapshotSparseByteCountMismatch");
        if (implicit_holes)
        {
            // Missing mappings are holes only when the native sparse declaration
            // and physical accounting agree for this exact validated stream.
            const auto count = found == projection.read_extents_by_inode.end() ? 0 : found->second.size();
            if (count > ((SIZE_MAX - 64) / sizeof(MetadataStore::FileExtent) - 1) / 2)
                return fail("SnapshotFileExtentCoverageInvalid");
            const auto capacity = 2 * count + 1;
            if (!budget || !budget->Materialize(1, 64 + capacity * sizeof(MetadataStore::FileExtent)))
                return fail("SnapshotProjectionBudget");
            std::vector<MetadataStore::FileExtent> complete;
            complete.reserve(capacity);
            end = 0;
            if (found != projection.read_extents_by_inode.end())
                for (const auto& extent : found->second)
                {
                    if (extent.logical_offset != end) complete.push_back({end, 0, extent.logical_offset - end});
                    complete.push_back(extent);
                    end = extent.logical_offset + extent.bytes;
                }
            if (end != covered) complete.push_back({end, 0, covered - end});
            projection.read_extents_by_inode[inode.object_id] = std::move(complete);
        }
    }
    for (const auto& [inode, attributes] : projection.extended_attributes_by_inode)
        for (const auto& [name, attribute] : attributes)
            if (attribute.flags & kAppleXattrDataStream) ++owners[ReadLe64(attribute.data, 0)];
    for (const auto& record : records)
    {
        const auto header = ReadLe64(record.key, 0);
        const auto id = header & kApfsObjectIdMask;
        switch (header >> kApfsObjectTypeShift)
        {
        case kApfsTypeInode: break;
        case 6:
        {
            AppleDataStreamIdRecord reference;
            if (!DecodeAppleDataStreamIdRecord(record, reference, error) ||
                !references.emplace(id, reference.reference_count).second ||
                !owners.contains(id) || owners.at(id) != reference.reference_count)
                return fail("SnapshotDataStreamOwnershipInvalid");
            break;
        }
        case kApfsTypeFileExtent:
        {
            AppleFileExtentRecord extent;
            if (!DecodeAppleFileExtentRecord(record, projection.block_size, extent, error)) return false;
            if (extent.crypto_id != 0) return fail("SnapshotEncryptedExtentUnsupported");
            if (file_streams.contains(id) && !projected_file_streams.contains(id))
                return fail("SnapshotHiddenFileExtent");
            if (!file_streams.contains(id) && !projection.attribute_stream_extents.contains(id))
                return fail("SnapshotExtentOwnerMissing");
            break;
        }
        case kApfsTypeXattr: case kApfsTypeSiblingLink:
        case kApfsTypeDirectoryRecord: case kApfsTypeSiblingMap: break;
        default: return fail("SnapshotFilesystemRecordUnsupported");
        }
    }
    for (const auto& [inode, declared] : sparse_bytes)
    {
        std::uint64_t holes = 0;
        const auto extents = projection.read_extents_by_inode.find(inode);
        if (extents != projection.read_extents_by_inode.end())
            for (const auto& extent : extents->second)
                if (!extent.physical_address)
                {
                    if (extent.bytes > UINT64_MAX - holes) return fail("SnapshotSparseByteCountMismatch");
                    holes += extent.bytes;
                }
        if (declared.bytes != holes) return fail("SnapshotSparseByteCountMismatch");
    }
    for (const auto& [id, count] : owners)
        if (count > 1 && (!references.contains(id) || references.at(id) != count))
            return fail("SnapshotSharedStreamOwnershipInvalid");
    return true;
}

bool ValidateSnapshotDirectorySiblings(
    const std::vector<catalog::BtreeRecord>& records,
    const NativeApfsVolumeProjection& projection,
    const std::shared_ptr<catalog::ApfsReadBudget>& budget,
    std::string& error)
{
    // The shared projector derives link IDs from sibling-link/map records.
    // Complete snapshot authority also requires the directory's own ID to agree.
    if (!budget->Materialize(1, 4096 + 2ull * sizeof(const MetadataStore::DirectoryLink*) *
            projection.directory_links.size())) return false;
    std::vector<const MetadataStore::DirectoryLink*> links;
    links.reserve(projection.directory_links.size());
    for (const auto& link : projection.directory_links) links.push_back(&link);
    std::sort(links.begin(), links.end(), [](const auto* left, const auto* right) {
        return left->parent_object_id < right->parent_object_id ||
            (left->parent_object_id == right->parent_object_id && left->entry_name_utf8 < right->entry_name_utf8);
    });
    for (const auto& record : records)
    {
        if ((ReadLe64(record.key, 0) >> kApfsObjectTypeShift) != kApfsTypeDirectoryRecord) continue;
        if (!MaterializeNamespaceRecord(budget, record, kApfsTypeDirectoryRecord)) return false;
        AppleDirectoryRecord directory;
        if (!ApfsExtendedRecordCodec::DecodeDirectory(record, projection.name_policy, directory, error)) return false;
        std::uint64_t sibling_id = 0;
        for (const auto& field : directory.extended_fields)
        {
            if (field.type != 1) continue;
            if (field.flags || field.data.size() != 8 ||
                !(sibling_id = catalog::ReadU64LE(field.data, 0).value_or(0)))
            {
                error = "SnapshotDirectorySiblingInvalid";
                return false;
            }
        }
        const auto link = std::lower_bound(links.begin(), links.end(), directory,
            [](const auto* entry, const auto& value) {
                return entry->parent_object_id < value.parent_id ||
                    (entry->parent_object_id == value.parent_id && entry->entry_name_utf8 < value.name_utf8);
            });
        if (link == links.end() || (*link)->parent_object_id != directory.parent_id ||
            (*link)->entry_name_utf8 != directory.name_utf8 || (*link)->child_object_id != directory.file_id ||
            (*link)->sibling_id != sibling_id)
        {
            error = "SnapshotDirectorySiblingMismatch";
            return false;
        }
    }
    return true;
}
} // namespace

bool NativeApfsReader::ValidateOrdinaryFileSystemRecords(
    const std::vector<catalog::BtreeRecord>& records,
    const catalog::NxSuperblock& container, const catalog::ApsbVolume& volume,
    const std::shared_ptr<catalog::ApfsReadBudget>& budget, std::string& out_error)
{
    NativeApfsVolumeProjection projection;
    return TryProjectOrdinaryFileSystemRecords(records, container, volume, budget, projection, out_error);
}

bool NativeApfsReader::TryProjectOrdinaryFileSystemRecords(
    const std::vector<catalog::BtreeRecord>& records,
    const catalog::NxSuperblock& container, const catalog::ApsbVolume& volume,
    const std::shared_ptr<catalog::ApfsReadBudget>& budget,
    NativeApfsVolumeProjection& out_projection, std::string& out_error)
{
    return ProjectReadOnlyRecords(records, container, volume, container.block_count,
        budget, out_projection, out_error);
}

bool NativeApfsReader::ValidateBackupWriterFileSystemRecords(
    const std::vector<catalog::BtreeRecord>& records,
    const catalog::NxSuperblock& container, const catalog::ApsbVolume& volume,
    const std::shared_ptr<catalog::ApfsReadBudget>& budget, std::string& out_error)
{
    if (volume.role_raw != 0x0180)
    {
        out_error = "BackupWriterVolumeProfileUnsupported";
        return false;
    }
    NativeApfsVolumeProjection projection;
    if (!ProjectReadOnlyRecordsWithAdmission(records, container, volume,
        container.block_count, budget, projection, out_error, false, true)) return false;
    for (const auto& inode : projection.inodes)
        if (inode.node_type == MetadataStore::NodeType::RegularFile && inode.logical_size > (8ull << 20))
        {
            out_error = "BackupWriterLiveFileLimit";
            return false;
        }
    return true;
}

bool NativeApfsReader::ProjectReadOnlyRecords(
    const std::vector<catalog::BtreeRecord>& records,
    const catalog::NxSuperblock& container, const catalog::ApsbVolume& volume,
    std::uint64_t routed_address_blocks,
    const std::shared_ptr<catalog::ApfsReadBudget>& budget,
    NativeApfsVolumeProjection& out_projection, std::string& out_error)
{
    return ProjectReadOnlyRecordsWithAdmission(records,container,volume,routed_address_blocks,budget,out_projection,out_error,false);
}

bool NativeApfsReader::ValidateBackupHistoricalFileSystemRecords(
    const catalog::RandomAccessSource& source, const std::vector<catalog::BtreeRecord>& records,
    const catalog::NxSuperblock& container, const catalog::ApsbVolume& volume, std::string& out_error)
{
    if (volume.role_raw != 0x0180 || !source.ReadBudget())
    {
        out_error = "BackupWriterHistoricalProfileUnsupported";
        return false;
    }
    NativeApfsVolumeProjection projection;
    return ProjectReadOnlyRecordsWithAdmission(records, container, volume, container.block_count,
        source.ReadBudget(), projection, out_error, false, true, &source);
}

bool NativeApfsReader::ProjectFusionReadOnlyRecords(
    const std::vector<catalog::BtreeRecord>& records,
    const catalog::NxSuperblock& container, const catalog::ApsbVolume& volume,
    std::uint64_t routed_address_blocks, const std::shared_ptr<catalog::ApfsReadBudget>& budget,
    NativeApfsVolumeProjection& projection, std::string& error)
{
    return ProjectReadOnlyRecordsWithProfile(records, container, volume, routed_address_blocks,
        budget, projection, error, false, false, nullptr, true);
}

bool NativeApfsReader::ValidateObservationalFileSystemRecords(
    const std::vector<catalog::BtreeRecord>& records, const catalog::NxSuperblock& container,
    const catalog::ApsbVolume& volume, const std::shared_ptr<catalog::ApfsReadBudget>& budget, std::string& error)
{
    NativeApfsVolumeProjection projection;
    return TryProjectObservationalFileSystemRecords(records,container,volume,budget,projection,error);
}

bool NativeApfsReader::TryProjectObservationalFileSystemRecords(
    const std::vector<catalog::BtreeRecord>& records, const catalog::NxSuperblock& container,
    const catalog::ApsbVolume& volume, const std::shared_ptr<catalog::ApfsReadBudget>& budget,
    NativeApfsVolumeProjection& projection, std::string& error)
{
    return ProjectReadOnlyRecordsWithAdmission(records,container,volume,container.block_count,budget,projection,error,true);
}

bool NativeApfsReader::ProjectReadOnlyRecordsWithAdmission(
    const std::vector<catalog::BtreeRecord>& records, const catalog::NxSuperblock& container,
    const catalog::ApsbVolume& volume, std::uint64_t routed_address_blocks,
    const std::shared_ptr<catalog::ApfsReadBudget>& budget,
    NativeApfsVolumeProjection& projection, std::string& error, bool observational,
    bool backup_clone_hint, const catalog::RandomAccessSource* historical_compression_source)
{
    return ProjectReadOnlyRecordsWithProfile(records, container, volume, routed_address_blocks,
        budget, projection, error, observational, backup_clone_hint, historical_compression_source, false);
}

bool NativeApfsReader::TryProjectMarkedReferenceFileSystemRecords(
    const std::vector<catalog::BtreeRecord>& records, const catalog::NxSuperblock& container,
    const catalog::ApsbVolume& volume, const std::shared_ptr<catalog::ApfsReadBudget>& budget,
    NativeApfsVolumeProjection& projection, std::string& error)
{
    return ProjectReadOnlyRecordsWithProfile(records, container, volume, container.block_count,
        budget, projection, error, true, false, nullptr, false, true);
}

bool NativeApfsReader::ProjectReadOnlyRecordsWithProfile(
    const std::vector<catalog::BtreeRecord>& records, const catalog::NxSuperblock& container,
    const catalog::ApsbVolume& volume, std::uint64_t routed_address_blocks,
    const std::shared_ptr<catalog::ApfsReadBudget>& budget,
    NativeApfsVolumeProjection& out_projection, std::string& out_error, bool observational,
    bool backup_clone_hint, const catalog::RandomAccessSource* historical_compression_source,
    bool fusion_private_namespace, bool marked_reference_namespace)
{
    out_projection = {};
    out_error.clear();
    const auto fail = [&](const char* reason) {
        out_error = budget && budget->Failed() ? budget->Failure() : reason;
        return false;
    };
    if (!budget) return fail("VerifierNamespaceBudgetRequired");
    if (marked_reference_namespace && (!observational || backup_clone_hint || fusion_private_namespace))
        return fail("VerifierMarkedReferenceProfileUnsupported");
    try
    {
        // Admit ordinary semantics on the same decoded records used below;
        // a separate preflight would duplicate codecs and temporary objects.
        NativeApfsVolumeProjection view;
        view.block_size = container.block_size;
        view.total_blocks = container.block_count;
        view.checkpoint_xid = container.xid;
        view.volume_object_id = volume.object_id;
        view.root_directory_inode = kRootDirectoryInode;
        view.name_policy = ApfsNamePolicy::FromIncompatibleFeatures(volume.incompatible_features);
        if (!ProjectFileSystemTreeWithProfile(records, container.block_size, container.block_count,
            container.xid, view.name_policy, view, true, budget, routed_address_blocks, &out_error, observational,
            backup_clone_hint, fusion_private_namespace, marked_reference_namespace))
            return fail(out_error.empty() ? "VerifierNamespaceOrLinkInconsistent" : out_error.c_str());
        if (!ProjectValidatedAttributeStreams(records, container.block_size,
            container.block_count, 0, view, true, routed_address_blocks, observational)) return fail("VerifierAttributeStreamInvalid");
        std::unordered_set<std::uint64_t> compressed;
        if (historical_compression_source &&
            !snapshot_compression::Admit(*historical_compression_source, view, budget, compressed, out_error))
            return fail(out_error.c_str());
        if (!ValidateSnapshotStreams(records, view, budget, out_error, observational,
                historical_compression_source ? &compressed : nullptr)) return fail(out_error.c_str());
        if (budget->Failed()) return fail("VerifierNamespaceBudget");
        view.btree_records.clear();
        out_projection = std::move(view);
        return true;
    }
    catch (const std::bad_alloc&)
    { (void)budget->Refuse("ApfsReadBudgetAllocationFailed"); return fail(budget->Failure()); }
    catch (const std::length_error&)
    { (void)budget->Refuse("ApfsReadBudgetAllocationFailed"); return fail(budget->Failure()); }
}

bool NativeApfsReader::TryLoadSnapshotProjection(
    const catalog::RandomAccessSource& source,
    const catalog::ApfsSnapshotIdentity& expected,
    std::shared_ptr<const NativeApfsSnapshotProjection>& out_projection,
    std::string& out_error)
{
    // Keep the old owner alive when expected aliases its immutable identity.
    const auto previous = std::move(out_projection);
    out_projection.reset();
    out_error.clear();
    auto budget = source.ReadBudget();
    try
    {
        if (!budget) budget = std::make_shared<catalog::ApfsReadBudget>(65536,
            256ull * 1024 * 1024, 1000000, 256ull * 1024 * 1024);
        const auto fail = [&](const char* reason) {
            out_error = budget->Failed() ? budget->Failure() : reason;
            return false;
        };
        if (!budget->Materialize(1, sizeof(NativeApfsSnapshotProjection) +
            sizeof(catalog::ApfsSnapshotRecords) + expected.name_utf8.size() + 256))
            return fail("SnapshotProjectionBudget");
        const auto identity = expected;
        catalog::BudgetedRandomAccessSource bounded(source, budget);
        SnapshotMetadataSource metadata(bounded);
        catalog::ApfsSnapshotRecords loaded;
        std::vector<ApplePhysicalExtentRecord> physical;
        if (!catalog::ApfsSnapshotStore::LoadExactProjectionRecords(metadata, identity, loaded, physical, out_error))
            return fail(out_error.c_str());
        const auto& checkpoint = loaded.checkpoint;
        const auto& nx = checkpoint.container.superblock;
        const auto& volume = loaded.snapshot.metadata.volume;
        const auto offset = identity.scope.store_offset_bytes;
        if (nx.block_size == 0 || nx.block_count == 0 ||
            nx.block_count > UINT64_MAX / nx.block_size ||
            identity.scope.store_size_bytes != nx.block_count * nx.block_size)
            return fail("SnapshotProjectionSourceWindowMismatch");
        if (offset % nx.block_size != 0) return fail("SnapshotProjectionStoreUnaligned");
        auto result = std::make_shared<NativeApfsSnapshotProjection>();
        auto& view = result->view_;
        view.checkpoint_xid = identity.scope.checkpoint_xid;
        // Historical APSB o_oid is physical; the selected volume OID is virtual.
        view.volume_object_id = identity.scope.volume_oid;
        view.volume_superblock_block = offset / nx.block_size + identity.superblock_physical_block;
        view.volume_object_map_oid = volume.superblock.omap_oid;
        view.root_tree_oid = identity.root_oid;
        view.root_tree_block = offset / nx.block_size + identity.root_physical_block;
        view.root_directory_inode = kRootDirectoryInode;
        view.block_size = nx.block_size;
        view.total_blocks = nx.block_count;
        view.incompatible_features = volume.superblock.incompatible_features;
        view.name_policy = ApfsNamePolicy::FromIncompatibleFeatures(view.incompatible_features);
        auto& records = loaded.trees.filesystem;
        // Sort compares scalar/byte keys and moves existing buffers in place.
        // Bound its stack/pivot workspace separately; namespace allocations
        // are reserved by ProjectFileSystemTree before each actual codec/index.
        if (!budget->Materialize(1, 65536 + 2 * sizeof(catalog::BtreeRecord)))
            return fail("SnapshotProjectionBudget");
        if (!SortAppleBtreeRecords(records, view.name_policy.UsesHashedDirectoryKeys()
            ? AppleBtreeKeyOrder::FileSystemHashedDirectory : AppleBtreeKeyOrder::FileSystemCaseSensitive,
            out_error)) return false;
        if (!ProjectFileSystemTree(records, nx.block_size, nx.block_count,
            identity.snapshot_xid, view.name_policy, view, true, budget))
            return fail("SnapshotNamespaceProjectionInvalid");
        if (!ValidateSnapshotDirectorySiblings(records, view, budget, out_error))
            return fail(out_error.empty() ? "SnapshotDirectorySiblingInvalid" : out_error.c_str());
        // The exact chronological resolver supplied the same complete graph
        // after its coverage/owner/refcount validation. Do not re-encode it.
        // Exclude all metadata read in this operation, plus complete reserved
        // checkpoint and spaceman pool ranges. Do not consult live free bits.
        const auto reserve = [&](std::uint64_t block, std::uint64_t count) {
            if (!count) return true;
            if (block >= nx.block_count || count > nx.block_count - block)
                return false;
            if (!budget->Materialize(1, 2 * sizeof(SnapshotMetadataSource::Range))) return false;
            metadata.ranges.emplace_back(offset + block * nx.block_size,
                offset + (block + count) * nx.block_size);
            return true;
        };
        const auto& pool = checkpoint.spaceman.internal_pool;
        if (!reserve(nx.xp_desc_base_block, nx.xp_desc_block_count) ||
            !reserve(nx.xp_data_base_block, nx.xp_data_block_count) ||
            !reserve(pool.base_block, pool.block_count) ||
            !reserve(pool.bitmap_base_block, pool.bitmap_block_count))
            return fail("SnapshotReservedGeometryInvalid");
        std::sort(metadata.ranges.begin(), metadata.ranges.end());
        std::uint64_t merged = 0;
        for (const auto& range : metadata.ranges)
        {
            if (merged && range.first <= metadata.ranges[merged - 1].second)
                metadata.ranges[merged - 1].second = (std::max)(metadata.ranges[merged - 1].second, range.second);
            else metadata.ranges[merged++] = range;
        }
        metadata.ranges.resize(static_cast<std::size_t>(merged));
        for (const auto& extent : physical)
        {
            const auto begin = offset + extent.physical_block * nx.block_size;
            const auto end = begin + extent.block_count * nx.block_size;
            const auto after = std::lower_bound(metadata.ranges.begin(), metadata.ranges.end(), end,
                [](const auto& range, std::uint64_t value) { return range.first < value; });
            if (after != metadata.ranges.begin() && std::prev(after)->second > begin)
                return fail("SnapshotPayloadMetadataOverlap");
        }
        if (!ProjectValidatedAttributeStreams(records, nx.block_size, nx.block_count,
            offset, view, true)) return fail("SnapshotAttributeStreamInvalid");
        std::unordered_set<std::uint64_t> compressed;
        if (!snapshot_compression::Admit(bounded, view, budget, compressed, out_error) ||
            !ValidateSnapshotStreams(records, view, budget, out_error, false, &compressed)) return false;
        // Core projection uses store-relative addresses; translate once, keeping
        // zero holes as zero. Attribute streams above already use source offsets.
        for (auto& [inode, extents] : view.read_extents_by_inode)
            for (auto& extent : extents)
                if (extent.physical_address) extent.physical_address += offset;
        for (auto& inode : view.inodes)
            if (inode.data_physical_address) inode.data_physical_address += offset;
        // These are legacy mutable catalog encodings, not snapshot read state.
        view.btree_records.clear();
        if (budget->Failed()) return fail("SnapshotProjectionBudget");
        result->snapshot_ = std::move(loaded.snapshot);
        out_projection = std::move(result);
        return true;
    }
    catch (const std::bad_alloc&)
    {
        if (budget) (void)budget->Refuse("ApfsReadBudgetAllocationFailed");
        out_error = "ApfsReadBudgetAllocationFailed";
        return false;
    }
    catch (const std::length_error&)
    {
        if (budget) (void)budget->Refuse("ApfsReadBudgetAllocationFailed");
        out_error = "ApfsReadBudgetAllocationFailed";
        return false;
    }
}

bool NativeApfsReader::TryLoadVolumeProjection(
    const BlockDevice& device,
    std::uint64_t volume_object_id,
    NativeApfsVolumeProjection& out_projection,
    std::wstring& out_error,
    std::optional<std::uint64_t> exact_checkpoint_xid,
    std::shared_ptr<catalog::ApfsReadBudget> budget)
{
    return TryLoadVolumeProjectionImpl(device, volume_object_id, out_projection,
        out_error, exact_checkpoint_xid, std::move(budget), nullptr);
}

bool NativeApfsReader::TryLoadVolumeProjectionFromValidatedCheckpoint(
    ValidatedCheckpointProjection& context,
    NativeApfsVolumeProjection& projection, std::wstring& error)
{
    projection = {};
    error.clear();
    const auto fail = [&](const wchar_t* reason) { projection = {}; error = reason; return false; };
    if (context.consumed) return fail(L"NativeApfsCheckpointHandoffConsumed");
    context.consumed = true;
    const auto budget = context.source.ReadBudget();
    if (budget && budget->Failed())
    {
        const std::string reason = budget->Failure();
        error.assign(reason.begin(), reason.end());
        return false;
    }
    const auto stable = [&] {
        if (context.image_identity)
        {
            BlockDevice::StableImageIdentity observed;
            return context.device.QueryStableReadOnlyImageIdentity(observed) &&
                observed == *context.image_identity && context.device.RevalidateStableReadOnlyImage();
        }
        return context.expected.shared_container_session && !context.raw_identity.empty() &&
            context.device.IsRawWriterAccepted() &&
            context.device.RawWriterIdentity() == context.raw_identity;
    };
    if (!stable()) return fail(L"NativeApfsCheckpointHandoffSourceUnstable");
    const auto& checkpoint = context.checkpoint;
    const auto& nx = checkpoint.container.superblock;
    const auto source_size = context.source.SizeBytes();
    if (context.device.BaseOffsetBytes() != context.expected.device_offset_bytes ||
        source_size != context.device.GetGeometry().total_bytes || nx.block_size == 0 ||
        nx.block_size > (1u << 20) || nx.block_count == 0 ||
        nx.block_count > source_size / nx.block_size ||
        checkpoint.container.superblock_physical_block >= nx.block_count ||
        (!context.image_identity && context.device.RawWriteLimitBytes() != nx.block_count * nx.block_size))
        return fail(L"NativeApfsCheckpointHandoffWindowMismatch");
    if (context.checkpoint_xid == 0 || nx.xid != context.checkpoint_xid ||
        checkpoint.container.checkpoint_map_blocks.empty() ||
        checkpoint.container.superblock_bytes.size() != nx.block_size ||
        !catalog::VerifyObjectChecksum(checkpoint.container.superblock_bytes, nx.block_size) ||
        catalog::ReadU64LE(checkpoint.container.superblock_bytes, 16) != nx.xid)
        return fail(L"NativeApfsCheckpointHandoffGenerationMismatch");
    if (!context.expected.container_uuid_hex.empty() &&
        context.expected.container_uuid_hex != nx.uuid_hex)
        return fail(L"NativeApfsCheckpointHandoffContainerMismatch");
    if (std::any_of(nx.fusion_uuid.begin(), nx.fusion_uuid.end(), [](auto byte) { return byte != std::byte{0}; }) ||
        nx.fusion_middle_tree_oid || nx.fusion_writeback_oid)
        return fail(L"NativeApfsFusionUnsupported");
    const catalog::AppleVolumeCheckpointView* selected = nullptr;
    for (const auto& volume : checkpoint.volumes)
        if (volume.superblock.object_id == context.expected.volume_object_id)
        {
            if (selected) return fail(L"NativeApfsVolumeAmbiguous");
            selected = &volume;
        }
    if (context.expected.volume_object_id == 0 || !selected ||
        (!context.expected.volume_uuid_hex.empty() &&
            context.expected.volume_uuid_hex != selected->superblock.uuid_hex))
        return fail(L"NativeApfsCheckpointHandoffVolumeMismatch");
    if (!TryLoadVolumeProjectionImpl(context.device, context.expected.volume_object_id,
            projection, error, std::nullopt, budget, &context)) return false;
    if (!stable()) return fail(L"NativeApfsCheckpointHandoffSourceChanged");
    return true;
}

bool NativeApfsReader::TryLoadVolumeProjectionImpl(const BlockDevice& device,
    std::uint64_t volume_object_id, NativeApfsVolumeProjection& out_projection,
    std::wstring& out_error, std::optional<std::uint64_t> exact_checkpoint_xid,
    std::shared_ptr<catalog::ApfsReadBudget> budget, const ValidatedCheckpointProjection* context)
{
    out_projection = {};
    out_error.clear();
    bool complete = false;
    struct ProjectionScope
    {
        NativeApfsVolumeProjection& projection;
        std::wstring& error;
        const std::shared_ptr<catalog::ApfsReadBudget>& budget;
        bool& complete;
        ~ProjectionScope()
        {
            if (!complete) projection = {};
            if (budget && budget->Failed())
            {
                const std::string reason = budget->Failure();
                error.assign(reason.begin(), reason.end());
            }
        }
    } projection_scope{out_projection, out_error, budget, complete};
    if (budget && budget->Failed()) return false;

    // Production volume selection is always explicit: callers resolve the
    // volume object ID through the container catalog (name or --volume-oid)
    // before projecting. Object ID 0 (first-volume fallback) is rejected.
    if (volume_object_id == 0)
    {
        out_error = L"NativeApfsVolumeOidZero";
        return false;
    }
    const auto selected_volume_oid = volume_object_id;

    // A1: the container catalog is the sole location authority for cataloged
    // media. There is no block-0 guess, no proximity scan, and every object
    // traversed here is checksum- and xid-verified by the catalog walk.
    BlockDeviceSource device_source(device, budget);
    const catalog::RandomAccessSource& projection_source = context ? context->source : device_source;
    catalog::ApfsContainerCatalog catalog;
    catalog::ApfsPhysicalStoreDescriptor handoff_store;
    const catalog::ApfsPhysicalStoreDescriptor* matched_store = nullptr;
    const catalog::ApfsVolumeDescriptor* matched_volume = nullptr;
    const catalog::AppleCheckpointView* checkpoint = nullptr;
    if (context)
    {
        handoff_store.offset_bytes = 0;
        handoff_store.size_bytes = projection_source.SizeBytes();
        matched_store = &handoff_store;
        checkpoint = &context->checkpoint;
    }
    else
    {
    std::wstring catalog_error;
    // TryLoadDevice owns an unbudgeted adapter. Use its existing portable
    // authority directly for opted-in callers, never a direct-device fallback.
    std::string bounded_catalog_error;
    std::string device_identifier, disk_slug;
    if (budget)
    {
        // Preserve TryLoadDevice's catalog labels as well as its source bytes.
        for (wchar_t ch : device.Path()) device_identifier.push_back(ch < 0x80 ? static_cast<char>(ch) : '?');
        for (char ch : device_identifier)
            disk_slug.push_back(((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                (ch >= '0' && ch <= '9')) ? ch : '-');
        const auto start = disk_slug.find_first_not_of('-');
        disk_slug = start == std::string::npos ? "device" : disk_slug.substr(start);
    }
    const bool catalog_loaded = budget
        ? catalog::ApfsContainerCatalog::TryLoadImage(device_source,
            disk_slug, device_identifier, catalog, bounded_catalog_error,
            catalog::CatalogLoadPolicy::StrictApple)
        : catalog::ApfsContainerCatalog::TryLoadDevice(device, catalog, catalog_error);
    if (!catalog_loaded || (budget && budget->Failed()))
    {
        out_error = L"NativeApfsCatalogLoadFailed";
        return false;
    }
    const catalog::ApfsContainerDescriptor* matched_container = nullptr;
    for (const auto& container : catalog.Containers())
    {
        for (const auto& volume : container.volumes)
        {
            if (volume.object_id != selected_volume_oid)
            {
                continue;
            }
            if (matched_volume != nullptr)
            {
                out_error = L"NativeApfsVolumeAmbiguous";
                return false;
            }
            matched_container = &container;
            matched_volume = &volume;
        }
    }
    if (matched_container == nullptr || matched_volume == nullptr)
    {
        out_error = L"NativeApfsVolumeNotCataloged";
        return false;
    }
    if (matched_container->member_store_ids.size() != 1)
    {
        // Multi-store (Fusion) block routing belongs to a later phase; the
        // legacy path could only mis-project it, so fail closed instead.
        out_error = L"NativeApfsFusionUnsupported";
        return false;
    }
    for (const auto& store : catalog.Stores())
    {
        if (store.stable_store_id == matched_container->member_store_ids.front())
        {
            matched_store = &store;
            break;
        }
    }
    if (matched_store == nullptr)
    {
        out_error = L"NativeApfsStoreMissing";
        return false;
    }
    checkpoint = catalog.TryGetAppleCheckpointView(matched_store->stable_store_id);
    if (checkpoint == nullptr)
    {
        out_error = L"NativeApfsAuthoritativeCheckpointMissing";
        return false;
    }
    }
    std::optional<catalog::AppleCheckpointView> historical_checkpoint;
    if (exact_checkpoint_xid)
    {
        std::string error;
        historical_checkpoint = catalog::LoadAppleCheckpointView(projection_source,
            matched_store->offset_bytes, matched_store->size_bytes, error, exact_checkpoint_xid);
        if (!historical_checkpoint || historical_checkpoint->container.superblock.uuid_hex !=
                checkpoint->container.superblock.uuid_hex)
        {
            out_error = L"NativeApfsHistoricalCheckpointUnavailable";
            return false;
        }
        checkpoint = &*historical_checkpoint;
    }
    const catalog::AppleVolumeCheckpointView* selected_volume = nullptr;
    for (const auto& volume : checkpoint->volumes)
    {
        if (volume.superblock.object_id == selected_volume_oid)
        {
            selected_volume = &volume;
            break;
        }
    }
    if (selected_volume == nullptr)
    {
        out_error = L"NativeApfsAuthoritativeVolumeMissing";
        return false;
    }
    if (exact_checkpoint_xid && selected_volume->superblock.uuid_hex != matched_volume->volume_uuid_hex)
    {
        out_error = L"NativeApfsHistoricalVolumeIdentityMismatch";
        return false;
    }
    const auto block_size = checkpoint->container.superblock.block_size;
    const auto checkpoint_xid = checkpoint->container.superblock.xid;
    const auto total_blocks = checkpoint->container.superblock.block_count;
    if (block_size == 0 || block_size > (1u << 20) || total_blocks == 0)
    {
        out_error = L"NativeApfsContainerGeometryInvalid";
        return false;
    }
    if (matched_store->offset_bytes % block_size != 0)
    {
        out_error = L"NativeApfsStoreUnaligned";
        return false;
    }
    const std::uint64_t store_block_base = matched_store->offset_bytes / block_size;
    catalog::OffsetRandomAccessSource store_view(
        &projection_source, matched_store->offset_bytes, matched_store->size_bytes);

    auto to_device_block = [&](std::uint64_t store_block, std::uint64_t& out_device_block)
    {
        if (store_block > (std::numeric_limits<std::uint64_t>::max() - store_block_base))
        {
            return false;
        }
        out_device_block = store_block_base + store_block;
        return true;
    };

    std::uint64_t aps_block = 0;
    if (!to_device_block(selected_volume->superblock_object.physical_block, aps_block))
    {
        out_error = L"NativeApfsVolumeBlockOverflow";
        return false;
    }
    VolumeSuperblock volume{};
    volume.object_id = selected_volume_oid;
    volume.xid = selected_volume->superblock.xid;
    volume.object_map_oid = selected_volume->superblock.omap_oid;
    volume.root_tree_oid = selected_volume->superblock.root_oid;
    volume.file_extent_tree_oid = selected_volume->superblock.fext_tree_oid;

    const auto selected_volume_superblock_block = aps_block;
    std::uint64_t root_device_block = 0;
    if (!to_device_block(selected_volume->root_tree.physical_block, root_device_block))
    {
        out_error = L"NativeApfsRootTreeBlockOverflow";
        return false;
    }

    out_projection.checkpoint_xid = checkpoint_xid;
    out_projection.volume_object_id = selected_volume_oid;
    out_projection.volume_superblock_block = selected_volume_superblock_block;
    out_projection.volume_object_map_oid = volume.object_map_oid;
    out_projection.root_tree_oid = volume.root_tree_oid;
    out_projection.root_tree_block = root_device_block;
    out_projection.file_extent_tree_oid = volume.file_extent_tree_oid;
    out_projection.root_directory_inode = kRootDirectoryInode;
    out_projection.total_blocks = total_blocks;
    out_projection.block_size = block_size;

    std::vector<RawBtreeRecord> fs_records;
    std::string resolve_error;
    {
        std::vector<catalog::BtreeRecord> catalog_records;
        catalog::BtreeReadPolicy tree_policy;
        tree_policy.enforce_object_identity = true;
        tree_policy.root_object_id = selected_volume->root_tree.object_id;
        tree_policy.storage_type = selected_volume->root_tree.type;
        tree_policy.subtype = catalog::kObjectTypeFsTree;
        tree_policy.require_complete_traversal = budget || exact_checkpoint_xid.has_value();
        if (!catalog::ReadBtreeLeafRecords(
                store_view, block_size, selected_volume->root_tree.physical_block,
                (selected_volume->root_tree.type & catalog::kObjectStorageTypeMask) ==
                    catalog::kObjectPhysical,
                volume.object_map_oid, checkpoint_xid, tree_policy,
                catalog_records, resolve_error))
        {
            out_error = L"NativeApfsRootTreeReadFailed";
            return false;
        }
        fs_records = std::move(catalog_records);
    }

    if (selected_volume->file_extent_tree.has_value())
    {
        const auto& file_extent_tree = selected_volume->file_extent_tree.value();
        std::vector<catalog::BtreeRecord> file_extent_records;
        std::uint64_t extent_device_block = 0;
        catalog::BtreeReadPolicy tree_policy;
        tree_policy.enforce_object_identity = true;
        tree_policy.root_object_id = file_extent_tree.object_id;
        tree_policy.storage_type = file_extent_tree.type;
        tree_policy.subtype = catalog::kObjectTypeFileExtentTree;
        tree_policy.require_complete_traversal = static_cast<bool>(budget);
        if (catalog::ReadBtreeLeafRecords(
                store_view, block_size, file_extent_tree.physical_block,
                (file_extent_tree.type & catalog::kObjectStorageTypeMask) ==
                    catalog::kObjectPhysical,
                volume.object_map_oid, checkpoint_xid, tree_policy,
                file_extent_records, resolve_error) &&
            to_device_block(file_extent_tree.physical_block, extent_device_block))
        {
            out_projection.file_extent_tree_block = extent_device_block;
            for (auto& record : file_extent_records)
            {
                fs_records.push_back(std::move(record));
            }
        }
        else if (budget)
        {
            out_error = L"NativeApfsFileExtentTreeReadFailed";
            return false;
        }
        else if (IsReadTraceEnabled())
        {
            std::wcerr << L"[NativeApfsReader] file extent tree read failed"
                       << L" oid=" << volume.file_extent_tree_oid << std::endl;
        }
    }

    out_projection.incompatible_features =
        selected_volume->superblock.incompatible_features;
    out_projection.name_policy = ApfsNamePolicy::FromIncompatibleFeatures(
        selected_volume->superblock.incompatible_features);
    // A sibling's publication advances NXSB without changing this volume.
    // Bind projected inode/link generations to the selected APSB, preserving
    // identities across sibling commits and fresh recovery owners.
    if (!ProjectFileSystemTree(
            fs_records, block_size, total_blocks, volume.xid,
            out_projection.name_policy, out_projection, budget || exact_checkpoint_xid.has_value(), budget))
    {
        out_projection = {};
        out_error = L"NativeApfsRootTreeProjectionFailed";
        return false;
    }

    const bool has_external_attributes = std::any_of(fs_records.begin(), fs_records.end(), [](const auto& record) {
        return record.key.size() >= 8 && (ReadLe64(record.key, 0) >> kApfsObjectTypeShift) == kApfsTypeXattr &&
            (ReadLe16(record.value, 0) & kAppleXattrDataStream) != 0;
    });
    if (has_external_attributes && selected_volume->extentref_tree)
    {
        // Payload authority requires a complete checksum-checked ownership graph,
        // even when the ordinary read-only namespace tolerated a partial tree.
        auto complete_checkpoint = catalog::LoadAppleCheckpointView(
            store_view, 0, store_view.SizeBytes(), resolve_error, checkpoint_xid);
        if (!complete_checkpoint || complete_checkpoint->container.superblock_bytes !=
                checkpoint->container.superblock_bytes)
        {
            if (budget) return budget->Refuse("ApfsReadBudgetAttributeCheckpointUnproven");
            complete = true; return true;
        }
        const auto complete_volume = std::find_if(complete_checkpoint->volumes.begin(),
            complete_checkpoint->volumes.end(), [selected_volume_oid](const auto& candidate) {
                return candidate.superblock.object_id == selected_volume_oid;
            });
        if (complete_volume == complete_checkpoint->volumes.end() ||
            complete_volume->superblock.uuid_hex != selected_volume->superblock.uuid_hex ||
            complete_volume->superblock.xid != selected_volume->superblock.xid ||
            complete_volume->root_tree.physical_block != selected_volume->root_tree.physical_block ||
            !complete_volume->extentref_tree)
        {
            if (budget) return budget->Refuse("ApfsReadBudgetAttributeVolumeUnproven");
            complete = true; return true;
        }
        const auto read_complete = [&](const catalog::AppleObjectLocation& tree, std::uint32_t subtype,
                                       std::uint64_t omap, std::vector<catalog::BtreeRecord>& records) {
            catalog::BtreeReadPolicy policy;
            policy.enforce_object_identity = true;
            policy.root_object_id = tree.object_id;
            policy.storage_type = tree.type;
            policy.subtype = subtype;
            policy.require_complete_traversal = true;
            policy.ephemeral_checkpoint = &complete_checkpoint->container;
            return catalog::ReadBtreeLeafRecords(store_view, block_size, tree.physical_block,
                (tree.type & catalog::kObjectStorageTypeMask) == catalog::kObjectPhysical,
                omap, checkpoint_xid, policy, records, resolve_error);
        };
        std::vector<catalog::BtreeRecord> complete_records, extentref_records, fext_records;
        if (read_complete(complete_volume->root_tree, catalog::kObjectTypeFsTree,
                complete_volume->superblock.omap_oid, complete_records) &&
            read_complete(*complete_volume->extentref_tree, catalog::kObjectTypeBlockRefTree, 0, extentref_records) &&
            (!complete_volume->file_extent_tree || read_complete(*complete_volume->file_extent_tree,
                catalog::kObjectTypeFileExtentTree, complete_volume->superblock.omap_oid, fext_records)))
        {
            complete_records.insert(complete_records.end(),
                std::make_move_iterator(fext_records.begin()), std::make_move_iterator(fext_records.end()));
            ProjectAttributeStreams(complete_records, extentref_records, store_view, *complete_checkpoint,
                matched_store->offset_bytes, out_projection);
        }
        else if (budget) return budget->Refuse("ApfsReadBudgetAttributeWalkIncomplete");
    }
    ProjectExternalCompressionSizes(projection_source, out_projection);
    if (budget && budget->Failed()) return false;
    complete = true;
    return true;
}

bool NativeApfsReader::ReadBlock(
    const BlockDevice& device,
    std::uint32_t block_size,
    std::uint64_t block_index,
    std::vector<std::byte>& out_block)
{
    out_block.clear();
    if (block_size == 0 || block_index == 0)
    {
        return false;
    }
    if (block_index > (std::numeric_limits<std::uint64_t>::max() / static_cast<std::uint64_t>(block_size)))
    {
        return false;
    }
    return device.Read(block_index * static_cast<std::uint64_t>(block_size), block_size, out_block) &&
           out_block.size() >= block_size;
}

std::optional<NativeApfsReader::ObjectMapValue> NativeApfsReader::ResolveObjectMapValue(
    const BlockDevice& device,
    std::uint32_t block_size,
    std::uint64_t map_oid,
    std::uint64_t object_id,
    std::uint64_t xid,
    ProjectionLookupCache* cache)
{
    const ObjectMapValueCacheKey value_cache_key
    {
        block_size,
        map_oid,
        object_id,
        xid,
    };
    if (cache)
    {
        if (auto cached = cache->object_map_values.find(value_cache_key);
            cached != cache->object_map_values.end())
        {
            return cached->second;
        }
    }

    std::vector<RawBtreeRecord> records_storage;
    const std::vector<RawBtreeRecord>* records = nullptr;
    if (cache)
    {
        const ObjectMapRecordsCacheKey records_cache_key{ block_size, map_oid };
        auto cached_records = cache->object_map_records.find(records_cache_key);
        if (cached_records == cache->object_map_records.end())
        {
            std::vector<RawBtreeRecord> loaded_records;
            if (!ReadObjectMapRecords(device, block_size, map_oid, loaded_records))
            {
                cache->object_map_values.emplace(value_cache_key, std::nullopt);
                return std::nullopt;
            }
            cached_records = cache->object_map_records.emplace(records_cache_key, std::move(loaded_records)).first;
        }
        records = &cached_records->second;
    }
    else
    {
        if (!ReadObjectMapRecords(device, block_size, map_oid, records_storage))
        {
            return std::nullopt;
        }
        records = &records_storage;
    }

    if (!records)
    {
        return std::nullopt;
    }

    std::optional<ObjectMapValue> selected;
    for (const auto& record : *records)
    {
        if (record.key.size() < 16 || record.value.size() < 16)
        {
            continue;
        }
        const auto candidate_oid = ReadLe64(record.key, 0);
        const auto candidate_xid = ReadLe64(record.key, 8);
        if (candidate_oid != object_id || candidate_xid > xid)
        {
            continue;
        }

        ObjectMapValue value{};
        value.flags = ReadLe32(record.value, 0);
        value.size = ReadLe32(record.value, 4);
        value.physical_block = ReadLe64(record.value, 8);
        value.xid = candidate_xid;
        if ((value.flags & 0x1u) != 0 || value.physical_block == 0)
        {
            continue;
        }
        if (!selected.has_value() || value.xid > selected->xid)
        {
            selected = value;
        }
    }

    if (cache)
    {
        cache->object_map_values.emplace(value_cache_key, selected);
    }
    return selected;
}

bool NativeApfsReader::ReadObjectMapRecords(
    const BlockDevice& device,
    std::uint32_t block_size,
    std::uint64_t map_oid,
    std::vector<RawBtreeRecord>& out_records)
{
    out_records.clear();
    std::vector<std::byte> omap;
    if (!ReadBlock(device, block_size, map_oid, omap))
    {
        return false;
    }
    if ((ReadLe32(omap, 0x18) & kObjectTypeMask) != kObjectTypeOmap)
    {
        return false;
    }

    const auto tree_oid = ReadLe64(omap, 0x30);
    if (tree_oid == 0)
    {
        return false;
    }
    return ReadBtreeRecords(
        device,
        block_size,
        tree_oid,
        /*child_addresses_are_physical=*/true,
        std::nullopt,
        ReadLe64(omap, 0x10),
        out_records);
}

bool NativeApfsReader::ReadBtreeRecords(
    const BlockDevice& device,
    std::uint32_t block_size,
    std::uint64_t root_block,
    bool child_addresses_are_physical,
    std::optional<std::uint64_t> child_object_map_oid,
    std::uint64_t xid,
    std::vector<RawBtreeRecord>& out_records,
    ProjectionLookupCache* cache)
{
    out_records.clear();
    if (root_block == 0)
    {
        return false;
    }

    std::queue<std::uint64_t> pending;
    pending.push(root_block);
    std::unordered_set<std::uint64_t> visited;
    visited.reserve(4096);
    std::vector<std::byte> block;

    while (!pending.empty())
    {
        const auto block_index = pending.front();
        pending.pop();
        if (!visited.insert(block_index).second)
        {
            continue;
        }
        if (visited.size() > 4096)
        {
            return false;
        }

        if (!ReadBlock(device, block_size, block_index, block))
        {
            return false;
        }
        const auto object_type = ReadLe32(block, 0x18) & kObjectTypeMask;
        if (object_type != kObjectTypeBtree && object_type != kObjectTypeBtreeNode)
        {
            return false;
        }

        const auto flags = ReadLe16(block, 0x20);
        const auto level = ReadLe16(block, 0x22);
        const auto key_count = ReadLe32(block, 0x24);
        const auto table_offset = ReadLe16(block, 0x28);
        const auto table_length = ReadLe16(block, 0x2A);
        const auto free_offset = ReadLe16(block, 0x2C);
        const auto free_length = ReadLe16(block, 0x2E);
        const auto fixed_kv = (flags & kBtnodeFixedKvSize) != 0;
        const auto is_root = (flags & kBtnodeRoot) != 0;
        const auto info_start = is_root ? (block.size() - kBtreeInfoBytes) : block.size();
        const auto key_size = is_root ? ReadLe32(block, info_start + 8) : 0;
        const auto value_size = is_root ? ReadLe32(block, info_start + 12) : 0;
        const auto entry_size = fixed_kv ? 4u : 8u;
        const auto table_start = kBtreeDataOffset + static_cast<std::size_t>(table_offset);
        const auto key_area_start = kBtreeDataOffset + static_cast<std::size_t>(table_offset) + static_cast<std::size_t>(table_length);
        const auto free_start = key_area_start + static_cast<std::size_t>(free_offset);
        const auto value_area_start = free_start + static_cast<std::size_t>(free_length);
        const auto value_area_end = info_start;

        if (key_count > 100000 ||
            table_start > block.size() ||
            key_area_start > block.size() ||
            value_area_start > block.size() ||
            value_area_end > block.size() ||
            value_area_start > value_area_end ||
            static_cast<std::uint64_t>(key_count) * entry_size > (block.size() - table_start))
        {
            return false;
        }

        for (std::uint32_t index = 0; index < key_count; ++index)
        {
            const auto entry_offset = table_start + static_cast<std::size_t>(index) * entry_size;
            std::uint16_t key_offset = 0;
            std::uint16_t key_length = 0;
            std::uint16_t value_offset = 0;
            std::uint16_t value_length = 0;
            if (fixed_kv)
            {
                key_offset = ReadLe16(block, entry_offset);
                value_offset = ReadLe16(block, entry_offset + 2);
                key_length = static_cast<std::uint16_t>(key_size);
                value_length = static_cast<std::uint16_t>(value_size != 0 ? value_size : sizeof(std::uint64_t));
            }
            else
            {
                key_offset = ReadLe16(block, entry_offset);
                key_length = ReadLe16(block, entry_offset + 2);
                value_offset = ReadLe16(block, entry_offset + 4);
                value_length = ReadLe16(block, entry_offset + 6);
            }

            if (key_offset == 0xffffu || value_offset == 0xffffu)
            {
                continue;
            }
            if (key_area_start + key_offset > block.size() ||
                key_length > block.size() - (key_area_start + key_offset) ||
                value_offset > value_area_end ||
                value_length > value_area_end ||
                value_area_end - value_offset > block.size() ||
                value_length > block.size() - (value_area_end - value_offset))
            {
                return false;
            }

            const auto key_start = key_area_start + key_offset;
            const auto value_start = value_area_end - value_offset;
            if (level == 0)
            {
                RawBtreeRecord record{};
                record.key.assign(
                    block.begin() + static_cast<std::vector<std::byte>::difference_type>(key_start),
                    block.begin() + static_cast<std::vector<std::byte>::difference_type>(key_start + key_length));
                record.value.assign(
                    block.begin() + static_cast<std::vector<std::byte>::difference_type>(value_start),
                    block.begin() + static_cast<std::vector<std::byte>::difference_type>(value_start + value_length));
                out_records.push_back(std::move(record));
                continue;
            }

            if (value_length < sizeof(std::uint64_t))
            {
                return false;
            }
            auto child_block = ReadLe64(block, value_start);
            if (!child_addresses_are_physical)
            {
                if (!child_object_map_oid.has_value())
                {
                    return false;
                }
                const auto child_mapping = ResolveObjectMapValue(device, block_size, child_object_map_oid.value(), child_block, xid, cache);
                if (!child_mapping.has_value())
                {
                    return false;
                }
                child_block = child_mapping->physical_block;
            }
            if (child_block != 0)
            {
                pending.push(child_block);
            }
        }
    }

    return true;
}

bool NativeApfsReader::ParseVolumeSuperblock(
    const std::vector<std::byte>& block,
    VolumeSuperblock& out_superblock)
{
    out_superblock = {};
    if (block.size() < 0xF8 ||
        (ReadLe32(block, 0x18) & kObjectTypeMask) != kObjectTypeFs ||
        ReadLe32(block, 0x20) != kApsbMagic)
    {
        return false;
    }

    out_superblock.object_id = ReadLe64(block, 0x08);
    out_superblock.xid = ReadLe64(block, 0x10);
    out_superblock.object_map_oid = ReadLe64(block, 0x80);
    out_superblock.root_tree_oid = ReadLe64(block, 0x88);
    out_superblock.file_count = ReadLe64(block, 0xB8);
    out_superblock.directory_count = ReadLe64(block, 0xC0);
    if (block.size() >= 0x410)
    {
        out_superblock.file_extent_tree_oid = ReadLe64(block, 0x408);
    }
    return out_superblock.object_id != 0 &&
           out_superblock.object_map_oid != 0 &&
           out_superblock.root_tree_oid != 0;
}

bool NativeApfsReader::ProjectFileSystemTree(
    const std::vector<RawBtreeRecord>& records,
    std::uint32_t block_size,
    std::uint64_t total_blocks,
    std::uint64_t xid,
    const ApfsNamePolicy& name_policy,
    NativeApfsVolumeProjection& projection,
    bool require_complete_namespace,
    const std::shared_ptr<catalog::ApfsReadBudget>& budget,
    std::uint64_t routed_address_blocks,
    std::string* ordinary_record_error)
{
    return ProjectFileSystemTreeWithAdmission(records,block_size,total_blocks,xid,name_policy,projection,
        require_complete_namespace,budget,routed_address_blocks,ordinary_record_error,false);
}

bool NativeApfsReader::ProjectFileSystemTreeWithAdmission(
    const std::vector<RawBtreeRecord>& records, std::uint32_t block_size, std::uint64_t total_blocks,
    std::uint64_t xid, const ApfsNamePolicy& name_policy, NativeApfsVolumeProjection& projection,
    bool require_complete_namespace, const std::shared_ptr<catalog::ApfsReadBudget>& budget,
    std::uint64_t routed_address_blocks, std::string* ordinary_record_error, bool observational,
    bool backup_clone_hint)
{
    return ProjectFileSystemTreeWithProfile(records, block_size, total_blocks, xid, name_policy,
        projection, require_complete_namespace, budget, routed_address_blocks, ordinary_record_error,
        observational, backup_clone_hint, false);
}

bool NativeApfsReader::ProjectFileSystemTreeWithProfile(
    const std::vector<RawBtreeRecord>& records, std::uint32_t block_size, std::uint64_t total_blocks,
    std::uint64_t xid, const ApfsNamePolicy& name_policy, NativeApfsVolumeProjection& projection,
    bool require_complete_namespace, const std::shared_ptr<catalog::ApfsReadBudget>& budget,
    std::uint64_t routed_address_blocks, std::string* ordinary_record_error, bool observational,
    bool backup_clone_hint, bool fusion_private_namespace, bool marked_reference_namespace)
{
    const auto ordinary_refusal = [&](const char* reason) {
        if (ordinary_record_error) *ordinary_record_error = reason;
        return false;
    };
    if (block_size == 0)
    {
        return false;
    }
    const auto volume_bytes = total_blocks > 0 && total_blocks <= (std::numeric_limits<std::uint64_t>::max() / block_size)
        ? total_blocks * static_cast<std::uint64_t>(block_size)
        : std::numeric_limits<std::uint64_t>::max();

    const auto address_blocks = routed_address_blocks ? routed_address_blocks : total_blocks;
    if (block_size == 0 || address_blocks > UINT64_MAX / block_size) return false;
    const auto address_bytes = address_blocks * block_size;

    struct RawInode
    {
        std::uint64_t object_id = 0;
        std::uint64_t parent_id = 0;
        std::uint64_t private_id = 0;
        std::uint64_t logical_size = 0;
        std::uint64_t uncompressed_size = 0;
        std::uint64_t allocated_size = std::numeric_limits<std::uint64_t>::max();
        std::uint64_t timestamp = 0;
        std::uint64_t create_time = 0;
        std::uint64_t modification_time = 0;
        std::uint64_t change_time = 0;
        std::uint64_t access_time = 0;
        std::uint64_t internal_flags = 0;
        std::uint32_t link_count = 1;
        std::uint32_t directory_entry_count = 0;
        std::uint32_t default_protection_class = 0;
        std::uint32_t write_generation = 0;
        std::uint32_t bsd_flags = 0;
        std::uint32_t owner = 0;
        std::uint32_t group = 0;
        std::uint16_t mode = 0;
        std::uint16_t reserved_pad = 0;
        bool is_directory = false;
        bool has_data_stream_info = false;
        bool directory_symlink_metadata_safe = false;
        std::string primary_name_utf8;
        MetadataStore::NodeType node_type = MetadataStore::NodeType::RegularFile;
        std::string symlink_target_utf8;
    };

    struct RawDirectoryEntry
    {
        std::uint64_t parent_id = 0;
        std::uint64_t child_id = 0;
        std::uint64_t timestamp = 0;
        std::uint16_t flags = 0;
        std::wstring name;
        std::string name_utf8;
        std::uint64_t sibling_id = 0;
    };

    std::unordered_map<std::uint64_t, RawInode> raw_inodes;
    std::vector<RawDirectoryEntry> directory_entries;
    std::vector<AppleSiblingLinkRecord> sibling_links;
    std::unordered_map<std::uint64_t, std::uint64_t> sibling_maps;
    std::unordered_map<std::uint64_t, AppleXattrRecord> symlink_targets;
    std::unordered_map<std::uint64_t, std::vector<MetadataStore::FileExtent>> read_extents_by_private_id;
    std::unordered_set<std::uint64_t> extent_record_ids;
    std::unordered_set<std::uint64_t> invalid_read_extent_ids;
    std::unordered_set<std::uint64_t> type_dependent_record_ids;

    for (const auto& record : records)
    {
        // Reserve a conservative envelope before codecs copy variable fields
        // and before the derived inode/xattr/name/extent indexes allocate.
        // Path-dependent and shared-extent copies are charged below separately.
        const auto type = record.key.size() >= sizeof(std::uint64_t)
            ? ReadLe64(record.key, 0) >> kApfsObjectTypeShift : 0;
        if (!MaterializeNamespaceRecord(budget, record, type)) return false;
        if (record.key.size() < sizeof(std::uint64_t))
        {
            if (ordinary_record_error) return ordinary_refusal("VerifierFilesystemRecordInvalid");
            if (require_complete_namespace) return false;
            continue;
        }

        const auto obj_id_and_type = ReadLe64(record.key, 0);
        const auto object_id = obj_id_and_type & kApfsObjectIdMask;
        const auto record_type = (obj_id_and_type >> kApfsObjectTypeShift) & 0x0f;
        if (ordinary_record_error)
        {
            switch (record_type)
            {
            case kApfsTypeInode: case kApfsTypeXattr: case kApfsTypeSiblingLink:
            case 6: case kApfsTypeFileExtent: case kApfsTypeSiblingMap: break;
            case kApfsTypeDirectoryRecord:
                if (catalog::ReadU16LE(record.value, 16).value_or(0) & ~0xfu)
                    return ordinary_refusal("VerifierDirectoryExtendedMetadataUnsupported");
                break;
            default: return ordinary_refusal("VerifierFilesystemRecordUnsupported");
            }
        }
        if (record_type != kApfsTypeInode && record_type != kApfsTypeXattr &&
            record_type != kApfsTypeDirectoryRecord)
            type_dependent_record_ids.insert(object_id);
        projection.highest_file_system_object_id = (std::max)(
            projection.highest_file_system_object_id, object_id);
        if (object_id == 0)
        {
            if (require_complete_namespace || record_type == kApfsTypeFileExtent) return false;
            continue;
        }

        if (record_type == kApfsTypeInode)
        {
            AppleInodeRecord apple_inode;
            std::string record_error;
            if (!(observational ? ApfsExtendedRecordCodec::DecodeInodeReadOnly(record,apple_inode,record_error) :
                ApfsExtendedRecordCodec::DecodeInode(record, apple_inode, record_error)))
            {
                if (ordinary_record_error) *ordinary_record_error = record_error;
                return false;
            }
            if (ordinary_record_error)
            {
                constexpr std::uint64_t neutral = 0x8 | 0x20 | 0x40 | 0x100 | 0x8000;
                // This historical regular-file hint is not extent ownership authority.
                const std::uint64_t clone_hint = (backup_clone_hint || observational) &&
                    (apple_inode.mode & 0170000) == 0100000 ? 0x400 : 0;
                const std::uint64_t marked_flags = marked_reference_namespace && observational &&
                    (apple_inode.mode & 0170000) == 0100000 ? 0x180000 : 0;
                if (apple_inode.reserved_pad || (apple_inode.internal_flags &
                    ~(neutral | clone_hint | marked_flags | kAppleInodeSparseFlag | kAppleInodeHasUncompressedSize |
                        (fusion_private_namespace ? 1ull : 0ull))))
                    return ordinary_refusal("VerifierInodeFlagsUnsupported");
                for (const auto& field : apple_inode.extended_fields)
                    if ((field.flags && !(observational &&
                            ((field.type == 4 && field.flags == 0x02) ||
                             (field.type == kInodeExtendedFieldDataStream && field.flags == 0x20)))) ||
                        (field.type != 4 && field.type != kInodeExtendedFieldDataStream &&
                        field.type != kInodeExtendedFieldSparseBytes))
                        return ordinary_refusal("VerifierInodeExtendedFieldUnsupported");
            }
            // DecodeInode already validates the xfield envelope and uniqueness.
            // INODE_IS_SPARSE means INO_EXT_TYPE_SPARSE_BYTES is present, even
            // when its uint64_t count is zero. Validate this on import so an
            // absent extent map cannot turn malformed metadata into zero reads.
            const auto sparse_field = std::find_if(apple_inode.extended_fields.begin(),
                apple_inode.extended_fields.end(), [](const auto& field) {
                    return field.type == kInodeExtendedFieldSparseBytes;
                });
            const bool has_sparse_field = sparse_field != apple_inode.extended_fields.end();
            if (has_sparse_field != ((apple_inode.internal_flags & kInodeHasSparseBytes) != 0) ||
                (has_sparse_field && sparse_field->data.size() != sizeof(std::uint64_t)))
            {
                return false;
            }
            RawInode inode{};
            inode.object_id = object_id;
            inode.parent_id = apple_inode.parent_id;
            inode.private_id = apple_inode.private_id;
            projection.highest_file_system_object_id = (std::max)(
                projection.highest_file_system_object_id, apple_inode.private_id);
            inode.create_time = ApfsNanosecondsToFileTime(apple_inode.create_time);
            inode.modification_time = ApfsNanosecondsToFileTime(apple_inode.modification_time);
            inode.change_time = ApfsNanosecondsToFileTime(apple_inode.change_time);
            inode.access_time = ApfsNanosecondsToFileTime(apple_inode.access_time);
            inode.timestamp = inode.modification_time;
            inode.uncompressed_size =
                (apple_inode.internal_flags & kAppleInodeHasUncompressedSize) != 0
                    ? apple_inode.uncompressed_size : 0;
            inode.logical_size = inode.uncompressed_size;
            inode.internal_flags = apple_inode.internal_flags;
            inode.default_protection_class = apple_inode.default_protection_class;
            inode.write_generation = apple_inode.write_generation;
            inode.bsd_flags = apple_inode.bsd_flags;
            inode.owner = apple_inode.owner;
            inode.group = apple_inode.group;
            inode.mode = apple_inode.mode;
            inode.reserved_pad = apple_inode.reserved_pad;
            if (!IsSupportedFileTypeFromMode(inode.mode))
            {
                if (require_complete_namespace) return false;
                continue;
            }
            inode.is_directory = IsDirectoryMode(inode.mode);
            inode.node_type = NodeTypeFromMode(inode.mode);
            // A type change may preserve neutral fields, but must not carry directory
            // statistics, mounted-filesystem state, storage or unknown fields into a link.
            // Strict imports require a valid size. Observational Apple links
            // may derive it from an exact filesystem-owned terminated target.
            constexpr std::uint64_t neutral_flags =
                0x8 | 0x20 | 0x40 | 0x100 | 0x8000 | kAppleInodeHasUncompressedSize;
            inode.directory_symlink_metadata_safe =
                (inode.is_directory || inode.node_type == MetadataStore::NodeType::SymbolicLink) &&
                (!inode.is_directory || apple_inode.uncompressed_size == 0) &&
                (apple_inode.internal_flags & ~neutral_flags) == 0 &&
                std::all_of(apple_inode.extended_fields.begin(), apple_inode.extended_fields.end(),
                    [](const auto& field) {
                        return (field.type == 3 && field.data.size() == 4) ||
                            field.type == 4 || (field.type == 7 && field.data.size() == 32);
                    });
            const bool is_special = !inode.is_directory &&
                inode.node_type != MetadataStore::NodeType::RegularFile &&
                inode.node_type != MetadataStore::NodeType::SymbolicLink;
            if (is_special && (inode.uncompressed_size != 0 ||
                std::any_of(apple_inode.extended_fields.begin(), apple_inode.extended_fields.end(),
                    [](const auto& field) { return field.type == kInodeExtendedFieldDataStream; })))
            {
                return false;
            }
            if (inode.is_directory)
            {
                inode.directory_entry_count = static_cast<std::uint32_t>(
                    apple_inode.children_or_links);
                inode.link_count = 1;
            }
            else
            {
                inode.link_count = static_cast<std::uint32_t>(
                    apple_inode.children_or_links);
                if (inode.link_count == 0)
                {
                    return false;
                }
            }
            for (const auto& field : apple_inode.extended_fields)
            {
                if (field.type != 4)
                {
                    continue;
                }
                if (field.data.size() <= 1 || field.data.back() != std::byte{0})
                {
                    return false;
                }
                inode.primary_name_utf8.assign(
                    reinterpret_cast<const char*>(field.data.data()),
                    field.data.size() - 1);
                const auto decoded_name = ApfsNameCodec::Decode(
                    std::span(field.data.data(), field.data.size() - 1),
                    name_policy);
                if (!decoded_name.ok())
                {
                    return false;
                }
            }
            if (!inode.is_directory)
            {
                if(observational){
                    for(const auto& field:apple_inode.extended_fields)if(field.type==kInodeExtendedFieldDataStream){
                        AppleDataStreamRecord stream;
                        if(!ApfsExtendedRecordCodec::DecodeDataStream(field,stream,record_error))
                            return ordinary_refusal("VerifierDataStreamInvalid");
                        inode.logical_size=stream.size;inode.allocated_size=stream.allocated_size;inode.has_data_stream_info=true;
                    }
                }
                else if (auto data_stream = ReadInodeDataStreamInfo(record.value); data_stream.has_value())
                {
                    inode.logical_size = data_stream->logical_size;
                    inode.allocated_size = data_stream->allocated_size;
                    inode.has_data_stream_info = true;
                }
            }
            if (require_complete_namespace && raw_inodes.contains(inode.object_id)) return false;
            raw_inodes[inode.object_id] = inode;
        }
        else if (record_type == kApfsTypeXattr)
        {
            AppleXattrRecord xattr;
            std::string record_error;
            if (!ApfsExtendedRecordCodec::DecodeXattr(
                    record, xattr, record_error))
            {
                if (ordinary_record_error) *ordinary_record_error = record_error;
                return false;
            }
            if (ordinary_record_error &&
                (xattr.flags & ~(kAppleXattrDataEmbedded | kAppleXattrDataStream | kAppleXattrFileSystemOwned)))
                return ordinary_refusal("VerifierXattrFlagsUnsupported");
            if ((xattr.flags & kAppleXattrDataStream) != 0)
                projection.highest_file_system_object_id = (std::max)(
                    projection.highest_file_system_object_id, ReadLe64(xattr.data, 0));
            if (xattr.name_utf8 == "com.apple.fs.symlink" &&
                !symlink_targets.emplace(xattr.object_id, xattr).second)
            {
                return false;
            }
            // Firmlink markers are opaque here: count them for evidence and
            // keep the original record untouched. No path is resolved, no
            // payload interpreted, no route built. A unified group view
            // stays unavailable until macOS fixtures prove a decoder.
            if (InspectFirmlinkAttribute(xattr) == FirmlinkDecodeStatus::UnsupportedSerialization)
            {
                // A census counter must never fail projection: saturate on
                // the unreachable overflow instead.
                if (projection.firmlink_markers_unsupported <
                    std::numeric_limits<std::uint64_t>::max())
                    ++projection.firmlink_markers_unsupported;
            }
            const auto name = xattr.name_utf8;
            if (!projection.extended_attributes_by_inode[xattr.object_id].emplace(
                    name, std::move(xattr)).second)
            {
                return false;
            }
        }
        else if (record_type == kApfsTypeSiblingLink)
        {
            catalog::BtreeRecord typed_record{record.key, record.value};
            AppleSiblingLinkRecord link;
            std::string record_error;
            if (!ApfsExtendedRecordCodec::DecodeSiblingLink(
                    typed_record, link, record_error))
            {
                return false;
            }
            sibling_links.push_back(std::move(link));
        }
        else if (record_type == kApfsTypeDirectoryRecord)
        {
            const bool directory_keys_are_hashed =
                name_policy.UsesHashedDirectoryKeys();
            const std::size_t name_offset = directory_keys_are_hashed ? 12u : 10u;
            if (record.key.size() < name_offset || record.value.size() < 18)
            {
                if (require_complete_namespace) return false;
                continue;
            }
            const auto name_length = directory_keys_are_hashed
                ? static_cast<std::size_t>(ReadLe32(record.key, 8) & 0x3ffu)
                : static_cast<std::size_t>(ReadLe16(record.key, 8));
            if (name_length <= 1 ||
                name_length != record.key.size() - name_offset ||
                record.key[name_offset + name_length - 1] != std::byte{0})
            {
                return false;
            }
            const auto name_bytes = std::span(
                record.key.data() + name_offset, name_length - 1);
            const auto decoded = ApfsNameCodec::Decode(name_bytes, name_policy);
            if (!decoded.ok() ||
                (directory_keys_are_hashed &&
                 !ApfsNameCodec::MatchesHashedDirectoryKey(
                     *decoded.value, ReadLe32(record.key, 8))))
            {
                return false;
            }
            RawDirectoryEntry entry{};
            entry.parent_id = object_id;
            entry.name = decoded.value->windows_display;
            entry.name_utf8 = decoded.value->original_utf8;
            entry.child_id = ReadLe64(record.value, 0x00);
            entry.timestamp = ReadLe64(record.value, 0x08);
            entry.flags = ReadLe16(record.value, 0x10);
            if (ordinary_record_error && record.value.size() > 18)
            {
                AppleDirectoryRecord typed;
                std::string record_error;
                if (!ApfsExtendedRecordCodec::DecodeDirectory(record, name_policy, typed, record_error) ||
                    typed.flags != 8 || typed.extended_fields.size() != 1 ||
                    typed.extended_fields.front().type != 1 || typed.extended_fields.front().flags ||
                    typed.extended_fields.front().data.size() != 8 ||
                    !(entry.sibling_id = catalog::ReadU64LE(typed.extended_fields.front().data, 0).value_or(0)))
                    return ordinary_refusal("VerifierDirectoryExtendedMetadataUnsupported");
            }
            if (entry.name.empty() ||
                entry.name == L"." ||
                entry.name == L".." ||
                entry.child_id == 0 ||
                !IsSupportedDrec(entry.flags))
            {
                if (require_complete_namespace) return false;
                continue;
            }
            directory_entries.push_back(std::move(entry));
        }
        else if (record_type == kApfsTypeSiblingMap)
        {
            catalog::BtreeRecord typed_record{record.key, record.value};
            AppleSiblingMapRecord map;
            std::string record_error;
            if (!ApfsExtendedRecordCodec::DecodeSiblingMap(
                    typed_record, map, record_error) ||
                !sibling_maps.emplace(map.sibling_id, map.file_id).second)
            {
                return false;
            }
        }
        else if (record_type == kApfsTypeFileExtent)
        {
            extent_record_ids.insert(object_id);
            AppleFileExtentRecord extent;
            std::string record_error;
            if (!DecodeAppleFileExtentRecord(record, block_size, extent, record_error))
            {
                invalid_read_extent_ids.insert(object_id);
                continue;
            }
            // A hole has no physical allocation. Its logical length may exceed
            // the entire device; only nonzero physical mappings consume media.
            std::uint64_t physical_address = 0;
            if (extent.physical_block != 0)
            {
                if (extent.physical_block > address_bytes / block_size)
                {
                    invalid_read_extent_ids.insert(object_id);
                    continue;
                }
                physical_address = extent.physical_block * block_size;
                if (extent.length_bytes > address_bytes - physical_address)
                {
                    invalid_read_extent_ids.insert(object_id);
                    continue;
                }
            }
            read_extents_by_private_id[object_id].push_back(
                MetadataStore::FileExtent
                {
                    extent.logical_address,
                    physical_address,
                    extent.length_bytes
                });
        }
    }

    // The scalar payload projection feeds legacy OMAP/allocator validators
    // that require exclusive addresses. Keep shared mappings in the existing
    // per-inode extent path; physical sharing never grants write authority.
    struct PhysicalReadRange { std::uint64_t begin, end, stream; };
    std::vector<PhysicalReadRange> physical_read_ranges;
    std::unordered_set<std::uint64_t> shared_read_streams;
    std::unordered_map<std::uint64_t, std::size_t> private_read_owners;
    for (const auto& [id, inode] : raw_inodes)
        if (++private_read_owners[inode.private_id] > 1) shared_read_streams.insert(inode.private_id);
    for (const auto& [stream, extents] : read_extents_by_private_id)
        for (const auto& extent : extents)
        {
            if (!extent.physical_address) continue;
            if (budget && !budget->Materialize(1, sizeof(PhysicalReadRange) + 64)) return false;
            physical_read_ranges.push_back({extent.physical_address, extent.physical_address + extent.bytes, stream});
        }
    std::sort(physical_read_ranges.begin(), physical_read_ranges.end(), [](const auto& a, const auto& b) {
        return a.begin < b.begin;
    });
    for (std::size_t begin = 0; begin < physical_read_ranges.size();)
    {
        auto end = begin + 1;
        auto physical_end = physical_read_ranges[begin].end;
        while (end < physical_read_ranges.size() && physical_read_ranges[end].begin < physical_end)
        {
            physical_end = (std::max)(physical_end, physical_read_ranges[end].end);
            ++end;
        }
        if (end - begin > 1)
            for (auto at = begin; at < end; ++at) shared_read_streams.insert(physical_read_ranges[at].stream);
        begin = end;
    }

    if (!raw_inodes.contains(kRootDirectoryInode))
    {
        return false;
    }
    for (const auto& [object_id, attributes] : projection.extended_attributes_by_inode)
    {
        if (!raw_inodes.contains(object_id))
        {
            return false;
        }
    }

    for (auto& [object_id, inode] : raw_inodes)
    {
        const auto owner_attributes = projection.extended_attributes_by_inode.find(object_id);
        const AppleXattrRecord* decmpfs = nullptr;
        if (owner_attributes != projection.extended_attributes_by_inode.end())
        {
            const auto found = owner_attributes->second.find("com.apple.decmpfs");
            if (found != owner_attributes->second.end()) decmpfs = &found->second;
        }
        const bool compressed = inode.node_type == MetadataStore::NodeType::RegularFile &&
            ((inode.bsd_flags & kAppleBsdCompressedFlag) != 0 || decmpfs != nullptr);
        // Without a default dstream, a compressed inode carries decoded EOF,
        // which can exceed container capacity. Classify after collecting xattrs,
        // but retain the capacity check for native streams and ordinary files.
        if (!inode.is_directory && (inode.has_data_stream_info || !compressed) &&
            (inode.has_data_stream_info ? inode.allocated_size : inode.logical_size) > volume_bytes)
        {
            if (require_complete_namespace) return false;
            inode.logical_size = 0;
            inode.allocated_size = 0;
        }
        if (compressed)
        {
            // Compressed files often have a zero-byte native data stream. Its
            // EOF must not erase the inode's uncompressed-size evidence. Where
            // both are absent, only a validated embedded descriptor can supply
            // size without reading the device. Other cases fail closed on read.
            if (inode.uncompressed_size != 0) inode.logical_size = inode.uncompressed_size;
            if (inode.logical_size == 0 && decmpfs != nullptr && decmpfs->object_id == object_id &&
                (decmpfs->flags & ~kAppleXattrFileSystemOwned) == kAppleXattrDataEmbedded)
            {
                ApfsCompressionHeader header;
                if (ApfsCompression::Inspect(decmpfs->data, {}, header))
                    inode.logical_size = header.uncompressed_size;
            }
        }
        if (inode.directory_symlink_metadata_safe)
        {
            inode.directory_symlink_metadata_safe =
                !type_dependent_record_ids.contains(object_id) &&
                !type_dependent_record_ids.contains(inode.private_id);
            const auto attributes = projection.extended_attributes_by_inode.find(object_id);
            if (attributes != projection.extended_attributes_by_inode.end())
                for (const auto& [name, attribute] : attributes->second)
                    if (attribute.flags != kAppleXattrDataEmbedded ||
                        name == "com.apple.decmpfs" || name == "com.apple.ResourceFork")
                        inode.directory_symlink_metadata_safe = false;
        }
        if (!inode.is_directory && inode.node_type != MetadataStore::NodeType::RegularFile &&
            inode.node_type != MetadataStore::NodeType::SymbolicLink &&
            (extent_record_ids.contains(inode.private_id) || extent_record_ids.contains(object_id)))
        {
            return false;
        }
        const auto target = symlink_targets.find(object_id);
        if (inode.node_type != MetadataStore::NodeType::SymbolicLink)
        {
            if (target != symlink_targets.end())
            {
                return false;
            }
            continue;
        }
        if (observational && target != symlink_targets.end() &&
            target->second.flags == (kAppleXattrDataEmbedded | kAppleXattrFileSystemOwned) &&
            !target->second.data.empty() && target->second.data.back() == std::byte{0})
        {
            const auto& data = target->second.data;
            if (inode.has_data_stream_info || data.size() < 2 || data.size() > 3804 ||
                std::find(data.begin(), data.end() - 1, std::byte{0}) != data.end() - 1 ||
                ((inode.internal_flags & kAppleInodeHasUncompressedSize) && inode.logical_size != data.size() - 1))
                return false;
            inode.symlink_target_utf8.assign(reinterpret_cast<const char*>(data.data()), data.size() - 1);
            inode.logical_size = data.size() - 1;
            continue;
        }
        if (target == symlink_targets.end() ||
            (target->second.flags & (kAppleXattrDataStream | kAppleXattrDataEmbedded)) !=
                kAppleXattrDataEmbedded ||
            target->second.data.empty() ||
            std::find(target->second.data.begin(), target->second.data.end(), std::byte{0}) !=
                target->second.data.end())
        {
            return false;
        }
        inode.symlink_target_utf8.assign(
            reinterpret_cast<const char*>(target->second.data.data()),
            target->second.data.size());
        if (inode.logical_size != inode.symlink_target_utf8.size())
        {
            return false;
        }
    }

    if (marked_reference_namespace)
    {
        // Apple reserves directory7 for purgeable references and gives it no
        // inode. Validate its typed target relation; do not interpret names as
        // policy or treat these references as user-visible hard links.
        if (raw_inodes.contains(7) || type_dependent_record_ids.contains(7) ||
            projection.extended_attributes_by_inode.contains(7))
            return ordinary_refusal("VerifierMarkedReferenceDirectoryUnsupported");
        std::unordered_set<std::uint64_t> targets;
        std::unordered_set<std::string> names;
        for (const auto& entry : directory_entries)
        {
            if (budget && !budget->Materialize(1, 1)) return false;
            if (entry.parent_id != 7) continue;
            const auto inode = raw_inodes.find(entry.child_id);
            if (inode == raw_inodes.end() || inode->second.node_type != MetadataStore::NodeType::RegularFile ||
                !(inode->second.internal_flags & 0x80000) || inode->second.link_count != 1 ||
                entry.flags != 8 || entry.sibling_id)
                return ordinary_refusal("VerifierMarkedReferenceMismatch");
            if (budget && !budget->Materialize(2, 128 + entry.name_utf8.size())) return false;
            if (!targets.insert(entry.child_id).second || !names.insert(entry.name_utf8).second)
                return ordinary_refusal("VerifierMarkedReferenceMismatch");
        }
        for (const auto& [id, inode] : raw_inodes)
        {
            if (budget && !budget->Materialize(1, 1)) return false;
            if ((inode.internal_flags & 0x80000) && !targets.contains(id))
                return ordinary_refusal("VerifierMarkedReferenceMissing");
        }
        std::erase_if(directory_entries, [](const auto& entry) { return entry.parent_id == 7; });
    }

    const auto sibling_link_key = [](
        std::uint64_t inode_id,
        std::uint64_t parent_id,
        const std::string& name_utf8)
    {
        return std::to_string(inode_id) + "\x1f" +
            std::to_string(parent_id) + "\x1f" + name_utf8;
    };
    std::unordered_map<std::string, std::uint64_t> sibling_by_link;
    std::unordered_map<std::uint64_t, std::size_t> sibling_count_by_inode;
    for (const auto& link : sibling_links)
    {
        const auto mapped = sibling_maps.find(link.sibling_id);
        if (mapped == sibling_maps.end() || mapped->second != link.inode_id ||
            !sibling_by_link.emplace(
                sibling_link_key(link.inode_id, link.parent_id, link.name_utf8),
                link.sibling_id).second)
        {
            return false;
        }
        ++sibling_count_by_inode[link.inode_id];
    }
    if (sibling_maps.size() != sibling_links.size())
    {
        return false;
    }

    std::unordered_set<std::uint64_t> matched_sibling_ids;
    for (auto& entry : directory_entries)
    {
        const auto inode = raw_inodes.find(entry.child_id);
        if (inode == raw_inodes.end() || inode->second.is_directory ||
            inode->second.link_count <= 1)
        {
            if (ordinary_record_error && entry.sibling_id)
                return ordinary_refusal("VerifierDirectorySiblingMismatch");
            continue;
        }
        const auto sibling = sibling_by_link.find(
            sibling_link_key(entry.child_id, entry.parent_id, entry.name_utf8));
        if (sibling == sibling_by_link.end() ||
            (ordinary_record_error && entry.sibling_id != sibling->second) ||
            !matched_sibling_ids.insert(sibling->second).second)
        {
            return false;
        }
        entry.sibling_id = sibling->second;
    }
    for (const auto& [object_id, inode] : raw_inodes)
    {
        if (inode.is_directory)
        {
            continue;
        }
        const auto sibling_count = sibling_count_by_inode.contains(object_id)
            ? sibling_count_by_inode.at(object_id)
            : 0;
        if ((inode.link_count > 1 && sibling_count != inode.link_count) ||
            (inode.link_count <= 1 && sibling_count != 0))
        {
            return false;
        }
    }
    if (matched_sibling_ids.size() != sibling_links.size())
    {
        return false;
    }

    std::unordered_map<std::uint64_t, std::vector<RawDirectoryEntry>> children_by_parent;
    std::unordered_map<std::uint64_t, std::unordered_set<std::wstring>> names_by_parent;
    std::unordered_map<std::uint64_t, std::size_t> incoming_links;
    bool fusion_private_root = false;
#include "FusionPrivateNamespace.inc"
    if(observational && std::any_of(directory_entries.begin(),directory_entries.end(),
        [](const auto& entry){return entry.parent_id==1;})){
        // ROOT_DIR_PARENT is an on-disk sentinel, not an inode. Admit only the
        // two canonical anchors and an empty private directory in this profile.
        const auto root=raw_inodes.find(2), reserved=raw_inodes.find(3);
        if(raw_inodes.contains(1)||root==raw_inodes.end()||reserved==raw_inodes.end()||
            !root->second.is_directory||root->second.parent_id!=1||root->second.private_id!=2||root->second.primary_name_utf8!="root"||
            !reserved->second.is_directory||reserved->second.parent_id!=1||reserved->second.private_id!=3||
            reserved->second.primary_name_utf8!="private-dir"||reserved->second.directory_entry_count||
            !reserved->second.directory_symlink_metadata_safe||
            reserved->second.has_data_stream_info||reserved->second.uncompressed_size||
            extent_record_ids.contains(3)||type_dependent_record_ids.contains(3)||
            projection.extended_attributes_by_inode.contains(3))return ordinary_refusal("VerifierReservedNamespaceUnsupported");
        unsigned roots=0,private_dirs=0;
        for(const auto& entry:directory_entries){
            if(entry.parent_id==3||(entry.child_id==3&&entry.parent_id!=1))
                return ordinary_refusal("VerifierPrivateDirectoryHistoryUnsupported");
            if(entry.parent_id!=1)continue;
            if(entry.flags!=4)return ordinary_refusal("VerifierRootAnchorInvalid");
            if(entry.child_id==2&&entry.name_utf8=="root")++roots;
            else if(entry.child_id==3&&entry.name_utf8=="private-dir")++private_dirs;
            else return ordinary_refusal("VerifierRootAnchorInvalid");
        }
        if(roots!=1||private_dirs!=1)return ordinary_refusal("VerifierRootAnchorInvalid");
        std::erase_if(directory_entries,[](const auto& entry){return entry.parent_id==1;});
        raw_inodes.erase(3);
    }
    for (const auto& entry : directory_entries)
    {
        if (!raw_inodes.contains(entry.child_id))
        {
            if (require_complete_namespace) return false;
            continue;
        }
        if (require_complete_namespace)
        {
            const auto parent = raw_inodes.find(entry.parent_id);
            const auto name = ApfsNameCodec::CanonicalWindowsComponentKey(entry.name, name_policy);
            const auto& child = raw_inodes.at(entry.child_id);
            if (parent == raw_inodes.end() || !parent->second.is_directory ||
                entry.parent_id == entry.child_id || !name.ok() ||
                !names_by_parent[entry.parent_id].insert(*name.value).second ||
                (entry.flags & 0xfu) != ((child.mode >> 12) & 0xfu)) return false;
            ++incoming_links[entry.child_id];
        }
        children_by_parent[entry.parent_id].push_back(entry);
    }
    if (require_complete_namespace)
    {
        if (!raw_inodes.at(kRootDirectoryInode).is_directory) return false;
        for (const auto& [id, inode] : raw_inodes)
        {
            const auto expected_links = id == kRootDirectoryInode || (fusion_private_root && id == 3)
                ? 0 : inode.is_directory ? 1 : inode.link_count;
            if (incoming_links[id] != expected_links || (inode.is_directory &&
                    children_by_parent[id].size() != inode.directory_entry_count)) return false;
            if (id != kRootDirectoryInode && !(fusion_private_root && id == 3))
            {
                const auto parent = raw_inodes.find(inode.parent_id);
                const auto entries = children_by_parent.find(inode.parent_id);
                if (parent == raw_inodes.end() || !parent->second.is_directory ||
                    entries == children_by_parent.end() ||
                    std::none_of(entries->second.begin(), entries->second.end(), [&](const auto& entry) {
                        return entry.child_id == id && (inode.primary_name_utf8.empty() ||
                            inode.primary_name_utf8 == entry.name_utf8);
                    })) return false;
            }
        }
    }

    projection.inodes.clear();
    projection.directory_links.clear();
    projection.btree_records.clear();
    if (!budget)
    {
        projection.inodes.reserve(raw_inodes.size());
        projection.btree_records.reserve(records.size());
    }
    struct PendingInode
    {
        std::uint64_t object_id = 0;
        std::wstring path;
        std::string name_utf8;
    };
    std::queue<PendingInode> pending;
    std::unordered_set<std::uint64_t> visited_inodes;
    pending.push({ kRootDirectoryInode, L"\\", {} });
    if (fusion_private_root) pending.push({3, L"\\private-dir", "private-dir"});

    while (!pending.empty())
    {
        auto [object_id, path, name_utf8] = std::move(pending.front());
        pending.pop();
        if (!visited_inodes.insert(object_id).second)
        {
            continue;
        }
        auto inode_it = raw_inodes.find(object_id);
        if (inode_it == raw_inodes.end())
        {
            continue;
        }
        const auto& raw_inode = inode_it->second;

        if (budget && !budget->Materialize(4, 4096 +
                16ULL * (path.size() * sizeof(wchar_t) + name_utf8.size() +
                    raw_inode.symlink_target_utf8.size()))) return false;

        MetadataStore::InodeRecord inode{};
        inode.object_id = raw_inode.object_id;
        inode.parent_object_id = object_id == kRootDirectoryInode ? kRootDirectoryInode : raw_inode.parent_id;
        inode.full_path = NormalizePath(path);
        inode.name = inode.full_path == L"\\" ? L"" : inode.full_path.substr(inode.full_path.find_last_of(L'\\') + 1);
        inode.is_directory = raw_inode.is_directory;
        inode.directory_symlink_metadata_safe = raw_inode.directory_symlink_metadata_safe;
        inode.logical_size = raw_inode.is_directory ? 0 : raw_inode.logical_size;
        inode.xid = xid;
        inode.timestamp_utc = raw_inode.timestamp;
        inode.name_utf8 = std::move(name_utf8);
        inode.private_id = raw_inode.private_id;
        inode.create_time_utc = raw_inode.create_time;
        inode.modification_time_utc = raw_inode.modification_time;
        inode.change_time_utc = raw_inode.change_time;
        inode.access_time_utc = raw_inode.access_time;
        inode.internal_flags = raw_inode.internal_flags;
        inode.link_count = raw_inode.link_count;
        inode.directory_entry_count = raw_inode.directory_entry_count;
        inode.default_protection_class = raw_inode.default_protection_class;
        inode.write_generation = raw_inode.write_generation;
        inode.bsd_flags = raw_inode.bsd_flags;
        inode.owner = raw_inode.owner;
        inode.group = raw_inode.group;
        inode.mode = raw_inode.mode;
        inode.reserved_pad = raw_inode.reserved_pad;
        inode.node_type = raw_inode.node_type;
        inode.symlink_target_utf8 = raw_inode.symlink_target_utf8;
        if (inode.node_type == MetadataStore::NodeType::RegularFile)
            inode.allocation_size = raw_inode.has_data_stream_info ? raw_inode.allocated_size : 0;

        // Preserve opaque external attributes for inspection, but never turn a
        // malformed data stream owned by a regular file into implicit zeroes.
        if (inode.node_type == MetadataStore::NodeType::RegularFile &&
            invalid_read_extent_ids.contains(raw_inode.private_id))
        {
            return false;
        }
        if (inode.node_type == MetadataStore::NodeType::RegularFile &&
            (inode.logical_size > 0 || inode.allocation_size.value_or(0) > 0))
        {
            if (auto read_extents_it = read_extents_by_private_id.find(raw_inode.private_id);
                read_extents_it != read_extents_by_private_id.end())
            {
                if (budget && !budget->Materialize(read_extents_it->second.size(),
                        4ULL * sizeof(MetadataStore::FileExtent) * read_extents_it->second.size())) return false;
                std::vector<MetadataStore::FileExtent> normalized_extents;
                if (NormalizeFileExtents(read_extents_it->second, normalized_extents))
                {
                    projection.read_extents_by_inode[inode.object_id] = normalized_extents;
                    if (auto single_extent = TryResolveSingleExtentProjection(normalized_extents,
                            (std::max)(inode.logical_size, inode.allocation_size.value_or(0)));
                        single_extent.has_value() && !shared_read_streams.contains(raw_inode.private_id))
                    {
                        inode.data_physical_address = single_extent->physical_address;
                        projection.btree_records.push_back(
                            BtreeMutationCodec::EncodeExtentRecord(
                                inode.object_id,
                                0,
                                single_extent->physical_address,
                                single_extent->bytes,
                                xid,
                                false));
                    }
                }
                else
                {
                    if (IsReadTraceEnabled())
                    {
                        std::wcerr << L"[NativeApfsReader] invalid data extent set"
                                   << L" object=" << inode.object_id
                                   << L" privateId=" << raw_inode.private_id
                                   << L" path=" << inode.full_path
                                   << std::endl;
                    }
                    return false;
                }
            }
            else if ((raw_inode.has_data_stream_info && raw_inode.allocated_size == 0) ||
                (raw_inode.bsd_flags & kAppleBsdCompressedFlag) != 0 ||
                (projection.extended_attributes_by_inode.contains(inode.object_id) &&
                    projection.extended_attributes_by_inode.at(inode.object_id).contains("com.apple.decmpfs")))
            {
                // Compressed content may live entirely in xattrs. Preserve its
                // namespace; the committed read plan validates and decodes it.
                projection.read_extents_by_inode[inode.object_id] = {};
                inode.data_physical_address = 0;
            }
            else if (IsReadTraceEnabled())
            {
                std::wcerr << L"[NativeApfsReader] no data extent"
                           << L" object=" << inode.object_id
                           << L" privateId=" << raw_inode.private_id
                           << L" path=" << inode.full_path
                           << L" logicalSize=" << raw_inode.logical_size
                           << L" allocatedSize=" << raw_inode.allocated_size
                           << L" hasDstream=" << (raw_inode.has_data_stream_info ? L"true" : L"false")
                           << std::endl;
            }
        }

        if (inode.object_id != kRootDirectoryInode)
        {
            projection.btree_records.push_back(
                BtreeMutationCodec::EncodeInodeRecord(
                    inode.object_id,
                    inode.parent_object_id,
                    inode.name,
                    inode.is_directory,
                    inode.logical_size,
                    inode.data_physical_address,
                    inode.timestamp_utc,
                    xid,
                    false));
        }
        projection.inodes.push_back(inode);

        if (!inode.is_directory)
        {
            continue;
        }

        if (auto child_it = children_by_parent.find(object_id); child_it != children_by_parent.end())
        {
            std::stable_sort(
                child_it->second.begin(), child_it->second.end(),
                [&raw_inodes](const auto& left, const auto& right)
                {
                    const auto left_inode = raw_inodes.find(left.child_id);
                    const auto right_inode = raw_inodes.find(right.child_id);
                    const bool left_primary = left_inode != raw_inodes.end() &&
                        left_inode->second.parent_id == left.parent_id &&
                        left_inode->second.primary_name_utf8 == left.name_utf8;
                    const bool right_primary = right_inode != raw_inodes.end() &&
                        right_inode->second.parent_id == right.parent_id &&
                        right_inode->second.primary_name_utf8 == right.name_utf8;
                    if (left_primary != right_primary)
                    {
                        return left_primary;
                    }
                    return left.name_utf8 < right.name_utf8;
                });
            for (const auto& child : child_it->second)
            {
                if (child.child_id == object_id || !raw_inodes.contains(child.child_id))
                {
                    continue;
                }
                if (budget && !budget->Materialize(3, 4096 +
                        16ULL * ((inode.full_path.size() + child.name.size() + 1) * sizeof(wchar_t) +
                            child.name_utf8.size()))) return false;
                const auto child_path = JoinPath(inode.full_path, child.name);
                projection.btree_records.push_back(
                    BtreeMutationCodec::EncodeDirectoryRecord(
                        object_id,
                        child.name,
                        child.child_id,
                        xid,
                        false));
                projection.directory_links.push_back(
                    MetadataStore::DirectoryLink{
                        object_id,
                        child.name,
                        child.child_id,
                        xid,
                        child.name_utf8,
                        child.sibling_id,
                        child.timestamp,
                        child.flags});
                pending.push({ child.child_id, child_path, child.name_utf8 });
            }
        }
    }

    return !projection.inodes.empty() && (!require_complete_namespace ||
        (projection.inodes.size() == raw_inodes.size() &&
            projection.directory_links.size() == directory_entries.size()));
}
} // namespace apfsaccess::rw
