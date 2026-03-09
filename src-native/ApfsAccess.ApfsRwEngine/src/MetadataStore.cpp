#include "MetadataStore.h"
#include "ApfsObjectMapStore.h"
#include "ApfsSpacemanStore.h"
#include "ApfsVolumeTreeStore.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <cwctype>
#include <fstream>
#include <set>
#include <limits>
#include <unordered_set>
#include <utility>

namespace apfsaccess::rw
{
namespace
{
constexpr std::size_t kCheckpointHeaderBytes = 32;
constexpr std::size_t kCheckpointChecksumOffset = 28;
constexpr std::uint32_t kCheckpointChecksumSeed = 2166136261u;
constexpr std::uint32_t kCheckpointChecksumPrime = 16777619u;

std::uint32_t UpdateFnv1a(std::uint32_t hash, const std::byte* bytes, std::size_t length)
{
    for (std::size_t index = 0; index < length; ++index)
    {
        hash ^= static_cast<std::uint32_t>(std::to_integer<unsigned char>(bytes[index]));
        hash *= kCheckpointChecksumPrime;
    }
    return hash;
}

std::uint32_t ComputeCheckpointChecksum(const std::vector<std::byte>& block, std::size_t payload_bytes)
{
    if (block.size() < kCheckpointHeaderBytes || payload_bytes > (block.size() - kCheckpointHeaderBytes))
    {
        return 0;
    }

    auto hash = UpdateFnv1a(kCheckpointChecksumSeed, block.data(), kCheckpointChecksumOffset);
    if (payload_bytes > 0)
    {
        hash = UpdateFnv1a(hash, block.data() + kCheckpointHeaderBytes, payload_bytes);
    }
    return hash;
}

std::string BuildBtreeKeyBlob(const std::vector<std::byte>& key)
{
    if (key.empty())
    {
        return {};
    }

    return std::string(
        reinterpret_cast<const char*>(key.data()),
        reinterpret_cast<const char*>(key.data()) + static_cast<std::ptrdiff_t>(key.size()));
}

bool BtreeRecordKeyLess(const apfsaccess::rw::BtreeRecord& lhs, const apfsaccess::rw::BtreeRecord& rhs)
{
    return std::lexicographical_compare(
        lhs.key.begin(),
        lhs.key.end(),
        rhs.key.begin(),
        rhs.key.end(),
        [](std::byte l, std::byte r)
        {
            return std::to_integer<unsigned char>(l) < std::to_integer<unsigned char>(r);
        });
}

std::vector<apfsaccess::rw::BtreeRecord> CanonicalizeBtreeRecords(
    const std::vector<apfsaccess::rw::BtreeRecord>& source)
{
    std::unordered_map<std::string, apfsaccess::rw::BtreeRecord> latest_by_key;
    latest_by_key.reserve(source.size());

    for (const auto& record : source)
    {
        if (record.key.empty())
        {
            continue;
        }

        auto key_blob = BuildBtreeKeyBlob(record.key);
        if (key_blob.empty())
        {
            continue;
        }

        if (record.tombstone)
        {
            latest_by_key.erase(key_blob);
            continue;
        }

        latest_by_key.insert_or_assign(std::move(key_blob), record);
    }

    std::vector<apfsaccess::rw::BtreeRecord> canonicalized;
    canonicalized.reserve(latest_by_key.size());
    for (auto& [_, record] : latest_by_key)
    {
        canonicalized.push_back(std::move(record));
    }

    std::sort(canonicalized.begin(), canonicalized.end(), BtreeRecordKeyLess);
    return canonicalized;
}

struct ScopeExit
{
    std::function<void()> callback;

    ~ScopeExit()
    {
        if (callback)
        {
            callback();
        }
    }
};

bool TryReadLe32(const std::vector<std::byte>& buffer, std::size_t offset, std::uint32_t& value)
{
    if (offset + sizeof(std::uint32_t) > buffer.size())
    {
        return false;
    }

    value = static_cast<std::uint32_t>(std::to_integer<unsigned char>(buffer[offset + 0])) |
            (static_cast<std::uint32_t>(std::to_integer<unsigned char>(buffer[offset + 1])) << 8) |
            (static_cast<std::uint32_t>(std::to_integer<unsigned char>(buffer[offset + 2])) << 16) |
            (static_cast<std::uint32_t>(std::to_integer<unsigned char>(buffer[offset + 3])) << 24);
    return true;
}

bool CanReportCanonicalCommitReady(
    bool canonical_state_loaded,
    bool commit_path_ready,
    bool recovery_required,
    bool legacy_fixture_fallback_used)
{
    return canonical_state_loaded &&
           commit_path_ready &&
           !recovery_required &&
           !legacy_fixture_fallback_used;
}

bool TryReadLe64(const std::vector<std::byte>& buffer, std::size_t offset, std::uint64_t& value)
{
    if (offset + sizeof(std::uint64_t) > buffer.size())
    {
        return false;
    }

    value = static_cast<std::uint64_t>(std::to_integer<unsigned char>(buffer[offset + 0])) |
            (static_cast<std::uint64_t>(std::to_integer<unsigned char>(buffer[offset + 1])) << 8) |
            (static_cast<std::uint64_t>(std::to_integer<unsigned char>(buffer[offset + 2])) << 16) |
            (static_cast<std::uint64_t>(std::to_integer<unsigned char>(buffer[offset + 3])) << 24) |
            (static_cast<std::uint64_t>(std::to_integer<unsigned char>(buffer[offset + 4])) << 32) |
            (static_cast<std::uint64_t>(std::to_integer<unsigned char>(buffer[offset + 5])) << 40) |
            (static_cast<std::uint64_t>(std::to_integer<unsigned char>(buffer[offset + 6])) << 48) |
            (static_cast<std::uint64_t>(std::to_integer<unsigned char>(buffer[offset + 7])) << 56);
    return true;
}

bool TryReadWideStringWithLength(
    const std::vector<std::byte>& buffer,
    std::size_t& cursor,
    std::wstring& value)
{
    value.clear();

    std::uint32_t length = 0;
    if (!TryReadLe32(buffer, cursor, length))
    {
        return false;
    }
    cursor += sizeof(std::uint32_t);

    const auto required_bytes = static_cast<std::uint64_t>(length) * 2ull;
    if (required_bytes > (std::numeric_limits<std::size_t>::max() - cursor))
    {
        return false;
    }
    if (static_cast<std::size_t>(required_bytes) > (buffer.size() - cursor))
    {
        return false;
    }

    value.reserve(length);
    for (std::uint32_t index = 0; index < length; ++index)
    {
        const auto lo = static_cast<std::uint16_t>(std::to_integer<unsigned char>(buffer[cursor + 0]));
        const auto hi = static_cast<std::uint16_t>(std::to_integer<unsigned char>(buffer[cursor + 1]));
        const auto code_unit = static_cast<std::uint16_t>(lo | (hi << 8));
        value.push_back(static_cast<wchar_t>(code_unit));
        cursor += 2;
    }
    return true;
}

struct DecodedBtreeInode
{
    std::uint64_t object_id = 0;
    std::uint64_t parent_object_id = 0;
    std::uint64_t xid = 0;
    bool is_directory = false;
    std::uint64_t logical_size = 0;
    std::uint64_t data_physical_address = 0;
    std::uint64_t timestamp_utc = 0;
    std::wstring name;
};

struct DecodedBtreeDirectoryEntry
{
    std::uint64_t parent_object_id = 0;
    std::wstring entry_name;
    std::uint64_t child_object_id = 0;
    std::uint64_t xid = 0;
};

struct DecodedBtreeExtent
{
    std::uint64_t object_id = 0;
    std::uint64_t logical_offset = 0;
    std::uint64_t physical_address = 0;
    std::uint64_t extent_bytes = 0;
    std::uint64_t xid = 0;
};

std::wstring BuildDirectoryEntryIndexKey(std::uint64_t parent_object_id, const std::wstring& entry_name)
{
    std::wstring key = std::to_wstring(parent_object_id);
    key.push_back(L'\x1f');
    key += entry_name;
    return key;
}

bool DecodeBtreeInodeRecord(const apfsaccess::rw::BtreeRecord& record, DecodedBtreeInode& decoded)
{
    constexpr std::size_t kExpectedKeyBytes = 1 + 8 + 8;
    constexpr std::uint32_t kDirectoryFlag = 0x1u;
    constexpr std::uint32_t kTombstoneFlag = 0x2u;
    constexpr std::uint32_t kTimestampPresentFlag = 0x4u;
    if (record.key.size() != kExpectedKeyBytes)
    {
        return false;
    }

    if (!TryReadLe64(record.key, 1, decoded.parent_object_id) ||
        !TryReadLe64(record.key, 9, decoded.object_id))
    {
        return false;
    }

    std::size_t cursor = 0;
    std::uint32_t flags = 0;
    if (!TryReadLe64(record.value, cursor, decoded.xid))
    {
        return false;
    }
    cursor += 8;
    if (!TryReadLe32(record.value, cursor, flags))
    {
        return false;
    }
    cursor += 4;
    if (!TryReadLe64(record.value, cursor, decoded.logical_size))
    {
        return false;
    }
    cursor += 8;
    if (!TryReadLe64(record.value, cursor, decoded.data_physical_address))
    {
        return false;
    }
    cursor += 8;
    if ((flags & kTimestampPresentFlag) != 0)
    {
        if (!TryReadLe64(record.value, cursor, decoded.timestamp_utc))
        {
            return false;
        }
        cursor += 8;
    }
    if (!TryReadWideStringWithLength(record.value, cursor, decoded.name))
    {
        return false;
    }
    if (cursor != record.value.size())
    {
        return false;
    }

    decoded.is_directory = (flags & kDirectoryFlag) != 0;
    if ((flags & kTombstoneFlag) != 0)
    {
        return false;
    }
    if ((flags & ~(kDirectoryFlag | kTimestampPresentFlag)) != 0)
    {
        return false;
    }
    if (decoded.object_id == 0 || decoded.name.empty())
    {
        return false;
    }
    if (decoded.is_directory)
    {
        if (decoded.logical_size != 0 || decoded.data_physical_address != 0)
        {
            return false;
        }
    }
    else if (decoded.logical_size > 0 && decoded.data_physical_address == 0)
    {
        return false;
    }

    return true;
}

bool DecodeBtreeDirectoryRecord(const apfsaccess::rw::BtreeRecord& record, DecodedBtreeDirectoryEntry& decoded)
{
    if (record.key.size() < 1 + 8 + 4)
    {
        return false;
    }

    if (!TryReadLe64(record.key, 1, decoded.parent_object_id))
    {
        return false;
    }
    std::size_t key_cursor = 1 + 8;
    if (!TryReadWideStringWithLength(record.key, key_cursor, decoded.entry_name))
    {
        return false;
    }
    if (key_cursor != record.key.size() || decoded.entry_name.empty())
    {
        return false;
    }

    if (record.value.size() != (8 + 8 + 1))
    {
        return false;
    }
    if (!TryReadLe64(record.value, 0, decoded.xid) ||
        !TryReadLe64(record.value, 8, decoded.child_object_id))
    {
        return false;
    }
    if (decoded.child_object_id == 0)
    {
        return false;
    }
    const auto tombstone_flag = std::to_integer<unsigned char>(record.value[16]);
    if (tombstone_flag != 0)
    {
        return false;
    }

    return true;
}

bool DecodeBtreeExtentRecord(const apfsaccess::rw::BtreeRecord& record, DecodedBtreeExtent& decoded)
{
    constexpr std::size_t kExpectedKeyBytes = 1 + 8 + 8;
    if (record.key.size() != kExpectedKeyBytes)
    {
        return false;
    }
    if (!TryReadLe64(record.key, 1, decoded.object_id) ||
        !TryReadLe64(record.key, 9, decoded.logical_offset))
    {
        return false;
    }
    if (decoded.object_id == 0)
    {
        return false;
    }

    if (record.value.size() != (8 + 8 + 8 + 1))
    {
        return false;
    }
    if (!TryReadLe64(record.value, 0, decoded.xid) ||
        !TryReadLe64(record.value, 8, decoded.physical_address) ||
        !TryReadLe64(record.value, 16, decoded.extent_bytes))
    {
        return false;
    }
    if (decoded.physical_address == 0 || decoded.extent_bytes == 0)
    {
        return false;
    }
    const auto tombstone_flag = std::to_integer<unsigned char>(record.value[24]);
    if (tombstone_flag != 0)
    {
        return false;
    }

    return true;
}
} // namespace

MetadataStore::MetadataStore(VolumeContext context)
    : context_(std::move(context))
    , device_(context_.device_path)
{
    SyncCommitBlobTelemetryWithMode();
}

const MetadataStore::VolumeContext& MetadataStore::Context() const noexcept
{
    return context_;
}

const BlockDevice& MetadataStore::Device() const noexcept
{
    return device_;
}

bool MetadataStore::LoadContainerState()
{
    return LoadContainerSuperblocks();
}

bool MetadataStore::LoadVolumeState()
{
    if (!LoadContainerState())
    {
        MarkRecoveryRequired(L"ContainerStateLoadFailed");
        return false;
    }

    if (!LoadObjectMap())
    {
        if (recovery_reason_.empty())
        {
            MarkRecoveryRequired(L"ObjectMapLoadFailed");
        }
        return false;
    }

    if (!LoadSpacemanState())
    {
        if (recovery_reason_.empty())
        {
            MarkRecoveryRequired(L"SpacemanStateLoadFailed");
        }
        return false;
    }

    if (!EnsureRootState())
    {
        MarkRecoveryRequired(L"RootStateInvalid");
        return false;
    }

    if (context_.integrity_check_on_mount && !VerifyIntegrity())
    {
        MarkRecoveryRequired(L"IntegrityCheckFailedOnMount");
        return false;
    }

    return true;
}

bool MetadataStore::LoadCanonicalState()
{
    canonical_state_loaded_ = false;
    canonical_commit_ready_ = false;

    if (!LoadVolumeState())
    {
        return false;
    }

    ApfsObjectMapStore object_map_store;
    std::vector<ApfsObjectMapEntry> object_map_entries;
    object_map_entries.reserve(committed_object_map_.size());
    for (const auto& [_, update] : committed_object_map_)
    {
        object_map_entries.push_back(
            {
                update.object_id,
                update.physical_address,
                update.logical_size,
                update.xid,
            });
    }
    if (!object_map_store.ValidateEntries(object_map_entries))
    {
        MarkRecoveryRequired(L"CanonicalObjectMapStateInvalid");
        return false;
    }

    ApfsSpacemanStore spaceman_store;
    std::vector<ApfsExtent> allocations;
    allocations.reserve(committed_spaceman_allocations_.size());
    for (const auto& allocation : committed_spaceman_allocations_)
    {
        allocations.push_back({ allocation.physical_address, allocation.bytes });
    }

    std::vector<ApfsExtent> free_extents;
    free_extents.reserve(committed_spaceman_free_extents_.size());
    for (const auto& extent : committed_spaceman_free_extents_)
    {
        free_extents.push_back({ extent.physical_address, extent.bytes });
    }
    if (!spaceman_store.ValidateState(allocations, free_extents))
    {
        MarkRecoveryRequired(L"CanonicalSpacemanStateInvalid");
        return false;
    }

    ApfsVolumeTreeStore volume_tree_store;
    ApfsVolumeTreeProjection volume_tree_projection{};
    std::wstring volume_tree_error;
    if (!volume_tree_store.TryProjectFromBtreeRecords(
            committed_btree_records_,
            volume_tree_projection,
            volume_tree_error))
    {
        MarkRecoveryRequired(
            volume_tree_error.empty()
                ? L"CanonicalVolumeTreeStateInvalid"
                : volume_tree_error);
        return false;
    }

    canonical_state_loaded_ = container_loaded_ &&
                              object_map_loaded_ &&
                              spaceman_loaded_ &&
                              !recovery_required_;
    canonical_commit_ready_ = CanReportCanonicalCommitReady(
        canonical_state_loaded_,
        commit_path_ready_,
        recovery_required_,
        legacy_fixture_fallback_used_);
    return canonical_state_loaded_;
}

bool MetadataStore::LoadContainerSuperblocks()
{
    // Offsets are based on apfs_sb layout from Paragon CE apfs_struct.h.
    constexpr std::size_t kSuperblockBytes = 0x570;
    constexpr std::size_t kMagicOffset = 0x20;
    constexpr std::size_t kBlockSizeOffset = 0x24;
    constexpr std::size_t kTotalBlocksOffset = 0x28;
    constexpr std::size_t kCheckpointXidOffset = 0x10;
    constexpr std::size_t kSpacemanObjectIdOffset = 0x98;
    constexpr std::size_t kVolumeRootBlockOffset = 0xA0;
    constexpr std::size_t kFirstSbBlockOffset = 0x70;
    constexpr std::size_t kFirstMetaBlockOffset = 0x78;
    constexpr std::size_t kCurrentSbMapIndexOffset = 0x88;
    constexpr std::size_t kNextMetaIndexOffset = 0x84;
    constexpr std::size_t kCurrentMetaIndexOffset = 0x90;
    constexpr std::uint32_t kNxsbMagic = 0x4253584E; // 'NXSB'

    struct ParsedSuperblock
    {
        std::uint32_t block_size = 0;
        std::uint64_t total_blocks = 0;
        std::uint64_t checkpoint_xid = 0;
        std::uint64_t spaceman_object_id = 0;
        std::uint64_t volume_root_block = 0;
        std::uint64_t first_sb_block = 0;
        std::uint64_t first_meta_block = 0;
        std::uint32_t current_sb_map_index = 0;
        std::uint32_t next_meta_index = 0;
        std::uint32_t current_meta_index = 0;
    };

    const auto parse_superblock = [&](const std::vector<std::byte>& raw, ParsedSuperblock& parsed) -> bool
    {
        if (raw.size() < kSuperblockBytes)
        {
            return false;
        }

        const auto magic = ReadLe32(raw, kMagicOffset);
        if (magic != kNxsbMagic)
        {
            return false;
        }

        const auto block_size = ReadLe32(raw, kBlockSizeOffset);
        if (block_size == 0 || block_size > (1u << 20))
        {
            return false;
        }

        parsed.block_size = block_size;
        parsed.total_blocks = ReadLe64(raw, kTotalBlocksOffset);
        parsed.checkpoint_xid = ReadLe64(raw, kCheckpointXidOffset);
        parsed.spaceman_object_id = ReadLe64(raw, kSpacemanObjectIdOffset);
        parsed.volume_root_block = ReadLe64(raw, kVolumeRootBlockOffset);
        parsed.first_sb_block = ReadLe64(raw, kFirstSbBlockOffset);
        parsed.first_meta_block = ReadLe64(raw, kFirstMetaBlockOffset);
        parsed.current_sb_map_index = ReadLe32(raw, kCurrentSbMapIndexOffset);
        parsed.next_meta_index = ReadLe32(raw, kNextMetaIndexOffset);
        parsed.current_meta_index = ReadLe32(raw, kCurrentMetaIndexOffset);
        return true;
    };

    std::vector<std::byte> primary_superblock;
    if (!device_.Read(0, kSuperblockBytes, primary_superblock) || primary_superblock.size() < kSuperblockBytes)
    {
        container_loaded_ = false;
        return false;
    }

    ParsedSuperblock primary{};
    if (!parse_superblock(primary_superblock, primary))
    {
        container_loaded_ = false;
        return false;
    }

    ParsedSuperblock selected = primary;
    std::uint64_t selected_offset = 0;
    std::uint64_t secondary_offset = static_cast<std::uint64_t>(primary.block_size);

    std::vector<std::byte> secondary_superblock;
    ParsedSuperblock secondary{};
    const auto has_secondary = device_.Read(secondary_offset, kSuperblockBytes, secondary_superblock) &&
                               parse_superblock(secondary_superblock, secondary) &&
                               secondary.block_size == primary.block_size &&
                               secondary.total_blocks == primary.total_blocks &&
                               secondary.spaceman_object_id == primary.spaceman_object_id &&
                               secondary.volume_root_block == primary.volume_root_block;
    if (has_secondary && secondary.checkpoint_xid > primary.checkpoint_xid)
    {
        selected = secondary;
        selected_offset = secondary_offset;
        secondary_offset = 0;
    }

    block_size_ = selected.block_size;
    total_blocks_ = selected.total_blocks;
    checkpoint_xid_ = selected.checkpoint_xid;
    loaded_superblock_checkpoint_xid_ = selected.checkpoint_xid;
    active_superblock_offset_ = selected_offset;
    alternate_superblock_offset_ = secondary_offset;
    first_superblock_block_ = selected.first_sb_block;
    first_meta_block_ = selected.first_meta_block;
    current_superblock_map_index_ = selected.current_sb_map_index;
    next_meta_index_ = selected.next_meta_index;
    current_meta_index_ = selected.current_meta_index;
    spaceman_object_id_ = selected.spaceman_object_id;
    volume_root_block_ = selected.volume_root_block;
    next_ephemeral_extent_ = static_cast<std::uint64_t>(block_size_) * 0x100ull;
    const auto metadata_cursor_index = static_cast<std::uint64_t>(std::max(current_meta_index_, next_meta_index_));
    if (first_meta_block_ != 0 && block_size_ != 0)
    {
        if (first_meta_block_ <= (std::numeric_limits<std::uint64_t>::max() - metadata_cursor_index))
        {
            const auto metadata_cursor_block = first_meta_block_ + metadata_cursor_index;
            if (metadata_cursor_block <= (std::numeric_limits<std::uint64_t>::max() / static_cast<std::uint64_t>(block_size_)))
            {
                const auto metadata_cursor_bytes = metadata_cursor_block * static_cast<std::uint64_t>(block_size_);
                if (metadata_cursor_bytes > next_ephemeral_extent_)
                {
                    next_ephemeral_extent_ = metadata_cursor_bytes;
                }
            }
        }
    }
    working_next_ephemeral_extent_ = next_ephemeral_extent_;
    object_map_loaded_ = false;
    spaceman_loaded_ = false;
    native_write_ready_ = false;
    commit_path_ready_ = false;
    canonical_state_loaded_ = false;
    canonical_commit_ready_ = false;
    legacy_fixture_fallback_used_ = false;
    SyncCommitBlobTelemetryWithMode();
    write_device_allowed_ = false;
    recovery_required_ = false;
    recovery_reason_.clear();
    persistent_state_loaded_ = false;
    last_committed_xid_.reset();
    last_commit_blob_address_.reset();
    last_commit_blob_bytes_.reset();
    superblock_object_block_map_.clear();
    pending_mutations_.clear();
    committed_object_map_.clear();
    committed_inodes_.clear();
    committed_path_index_.clear();
    committed_directory_links_.clear();
    committed_btree_records_.clear();
    working_inodes_.clear();
    working_path_index_.clear();
    working_directory_links_.clear();
    committed_spaceman_allocations_.clear();
    committed_spaceman_free_extents_.clear();
    working_spaceman_free_extents_.clear();
    pending_object_map_updates_.clear();
    pending_spaceman_allocations_.clear();
    pending_spaceman_deallocations_.clear();
    pending_btree_records_.clear();
    next_generated_object_id_ = 1;
    last_commit_stage_.clear();
    last_replay_stage_.clear();
    last_replay_checkpoint_candidate_present_ = false;
    last_replay_checkpoint_pending_window_ = false;
    persistent_state_path_.clear();
    container_loaded_ = true;
    return true;
}

bool MetadataStore::LoadObjectMap()
{
    if (!container_loaded_ && !LoadContainerSuperblocks())
    {
        return false;
    }

    superblock_object_block_map_.clear();
    object_map_loaded_ = false;

    const auto block_has_header = [&](const std::vector<std::byte>& block) -> bool
    {
        return block.size() >= 0x20 &&
               ReadLe64(block, 0x08) != 0 &&
               ReadLe64(block, 0x10) != 0;
    };

    // Preferred path: parse checkpoint SB-map entries and build object->block map.
    if (first_superblock_block_ != 0 && block_size_ != 0)
    {
        if (first_superblock_block_ <= (std::numeric_limits<std::uint64_t>::max() - static_cast<std::uint64_t>(current_superblock_map_index_)))
        {
            const auto sb_map_block_index = first_superblock_block_ + static_cast<std::uint64_t>(current_superblock_map_index_);
            std::vector<std::byte> sb_map_block;
            if (ReadMetadataBlock(sb_map_block_index, sb_map_block))
            {
                constexpr std::size_t kEntriesCountOffset = 0x24;
                constexpr std::size_t kEntriesBaseOffset = 0x28;
                constexpr std::size_t kEntrySize = 0x28;
                constexpr std::size_t kEntryObjectIdOffset = 0x18;
                constexpr std::size_t kEntryBlockOffset = 0x20;

                const auto entries_count = ReadLe32(sb_map_block, kEntriesCountOffset);
                for (std::uint32_t index = 0; index < entries_count; ++index)
                {
                    const auto entry_offset = kEntriesBaseOffset + static_cast<std::size_t>(index) * kEntrySize;
                    if (entry_offset > sb_map_block.size() ||
                        kEntrySize > (sb_map_block.size() - entry_offset))
                    {
                        break;
                    }

                    const auto object_id = ReadLe64(sb_map_block, entry_offset + kEntryObjectIdOffset);
                    const auto block_index = ReadLe64(sb_map_block, entry_offset + kEntryBlockOffset);
                    if (object_id == 0 || block_index == 0)
                    {
                        continue;
                    }
                    superblock_object_block_map_[object_id] = block_index;
                }
            }
        }
    }

    const auto baseline_object_map = committed_object_map_;
    const auto baseline_last_committed_xid = last_committed_xid_;
    std::unordered_map<std::uint64_t, ObjectMapUpdate> selected_object_map;
    std::optional<std::uint64_t> selected_last_committed_xid;
    std::uint64_t selected_checkpoint_xid = 0;
    bool selected_checkpoint_valid = false;

    for (const auto candidate_block : ResolveObjectMapCheckpointBlockIndices())
    {
        std::vector<std::byte> checkpoint_block;
        if (!ReadBlockByIndexDirect(candidate_block, checkpoint_block))
        {
            continue;
        }

        committed_object_map_ = baseline_object_map;
        last_committed_xid_ = baseline_last_committed_xid;
        if (!LoadObjectMapCheckpointBlock(candidate_block, checkpoint_block))
        {
            continue;
        }

        const auto candidate_xid = ReadLe64(checkpoint_block, 12);
        if (!selected_checkpoint_valid || candidate_xid > selected_checkpoint_xid)
        {
            selected_checkpoint_xid = candidate_xid;
            selected_object_map = committed_object_map_;
            selected_last_committed_xid = last_committed_xid_;
            selected_checkpoint_valid = true;
        }
    }

    if (selected_checkpoint_valid)
    {
        committed_object_map_ = std::move(selected_object_map);
        last_committed_xid_ = selected_last_committed_xid;
        object_map_loaded_ = true;
    }
    else
    {
        committed_object_map_ = baseline_object_map;
        last_committed_xid_ = baseline_last_committed_xid;
    }

    const auto allow_fixture_fallback = IsLegacyFixtureFallbackAllowedForCurrentContext();
    const auto volume_block_candidate = ResolveObjectBlockIndex(volume_root_block_).value_or(0);
    if (!object_map_loaded_ &&
        allow_fixture_fallback &&
        volume_block_candidate != 0)
    {
        std::vector<std::byte> volume_block;
        if (ReadMetadataBlock(volume_block_candidate, volume_block) && block_has_header(volume_block))
        {
            object_map_loaded_ = true;
            legacy_fixture_fallback_used_ = true;
        }
    }
    if (!object_map_loaded_ && allow_fixture_fallback)
    {
        // Test/image fixtures may not expose full checkpoint metadata yet.
        object_map_loaded_ = volume_root_block_ != 0;
        legacy_fixture_fallback_used_ = object_map_loaded_;
    }

    if (!object_map_loaded_)
    {
        MarkRecoveryRequired(L"CanonicalObjectMapCheckpointMissing");
        return false;
    }

    return object_map_loaded_;
}

bool MetadataStore::LoadSpacemanState()
{
    if (!container_loaded_ && !LoadContainerSuperblocks())
    {
        return false;
    }

    spaceman_loaded_ = false;
    const auto baseline_allocations = committed_spaceman_allocations_;
    const auto baseline_free_extents = committed_spaceman_free_extents_;
    const auto baseline_working_free_extents = working_spaceman_free_extents_;
    const auto baseline_next_ephemeral_extent = next_ephemeral_extent_;
    const auto baseline_working_next_ephemeral_extent = working_next_ephemeral_extent_;
    const auto baseline_last_committed_xid = last_committed_xid_;

    std::vector<SpacemanAllocation> selected_allocations;
    std::vector<SpacemanAllocation> selected_free_extents;
    std::vector<SpacemanAllocation> selected_working_free_extents;
    std::uint64_t selected_next_ephemeral_extent = baseline_next_ephemeral_extent;
    std::uint64_t selected_working_next_ephemeral_extent = baseline_working_next_ephemeral_extent;
    std::optional<std::uint64_t> selected_last_committed_xid;
    std::uint64_t selected_checkpoint_xid = 0;
    bool selected_checkpoint_valid = false;

    for (const auto candidate_block : ResolveSpacemanCheckpointBlockIndices())
    {
        std::vector<std::byte> checkpoint_block;
        if (!ReadBlockByIndexDirect(candidate_block, checkpoint_block))
        {
            continue;
        }

        committed_spaceman_allocations_ = baseline_allocations;
        committed_spaceman_free_extents_ = baseline_free_extents;
        working_spaceman_free_extents_ = baseline_working_free_extents;
        next_ephemeral_extent_ = baseline_next_ephemeral_extent;
        working_next_ephemeral_extent_ = baseline_working_next_ephemeral_extent;
        last_committed_xid_ = baseline_last_committed_xid;

        if (!LoadSpacemanCheckpointBlock(candidate_block, checkpoint_block))
        {
            continue;
        }

        const auto candidate_xid = ReadLe64(checkpoint_block, 12);
        if (!selected_checkpoint_valid || candidate_xid > selected_checkpoint_xid)
        {
            selected_checkpoint_xid = candidate_xid;
            selected_allocations = committed_spaceman_allocations_;
            selected_free_extents = committed_spaceman_free_extents_;
            selected_working_free_extents = working_spaceman_free_extents_;
            selected_next_ephemeral_extent = next_ephemeral_extent_;
            selected_working_next_ephemeral_extent = working_next_ephemeral_extent_;
            selected_last_committed_xid = last_committed_xid_;
            selected_checkpoint_valid = true;
        }
    }

    if (selected_checkpoint_valid)
    {
        committed_spaceman_allocations_ = std::move(selected_allocations);
        committed_spaceman_free_extents_ = std::move(selected_free_extents);
        working_spaceman_free_extents_ = std::move(selected_working_free_extents);
        next_ephemeral_extent_ = selected_next_ephemeral_extent;
        working_next_ephemeral_extent_ = selected_working_next_ephemeral_extent;
        last_committed_xid_ = selected_last_committed_xid;
        spaceman_loaded_ = true;
    }
    else
    {
        committed_spaceman_allocations_ = baseline_allocations;
        committed_spaceman_free_extents_ = baseline_free_extents;
        working_spaceman_free_extents_ = baseline_working_free_extents;
        next_ephemeral_extent_ = baseline_next_ephemeral_extent;
        working_next_ephemeral_extent_ = baseline_working_next_ephemeral_extent;
        last_committed_xid_ = baseline_last_committed_xid;
    }

    const auto spaceman_block = ResolveObjectBlockIndex(spaceman_object_id_).value_or(0);
    if (!spaceman_loaded_ && spaceman_block != 0)
    {
        std::vector<std::byte> spaceman;
        if (ReadMetadataBlock(spaceman_block, spaceman))
        {
            constexpr std::size_t kBmdBlockSizeOffset = 0x20;
            constexpr std::size_t kBmdTotalBlocksOffset = 0x30;
            constexpr std::size_t kBmdFreeBlocksOffset = 0x48;
            constexpr std::size_t kBmdBitmapBlockOffset = 0xB0;

            const auto bmd_block_size = ReadLe32(spaceman, kBmdBlockSizeOffset);
            const auto bmd_total_blocks = ReadLe64(spaceman, kBmdTotalBlocksOffset);
            const auto bmd_free_blocks = ReadLe64(spaceman, kBmdFreeBlocksOffset);
            const auto bmd_bitmap_block = ReadLe64(spaceman, kBmdBitmapBlockOffset);

            const auto block_size_matches = bmd_block_size == 0 || bmd_block_size == block_size_;
            const auto total_blocks_plausible = bmd_total_blocks == 0 || bmd_total_blocks == total_blocks_;
            const auto bitmap_block_plausible = bmd_bitmap_block == 0 || total_blocks_ == 0 || bmd_bitmap_block < total_blocks_;
            const auto free_blocks_plausible = total_blocks_ == 0 || bmd_free_blocks <= total_blocks_;

            if (block_size_matches && total_blocks_plausible && bitmap_block_plausible && free_blocks_plausible)
            {
                spaceman_loaded_ = true;
            }
        }
    }

    const auto allow_fixture_fallback = IsLegacyFixtureFallbackAllowedForCurrentContext();
    if (!spaceman_loaded_ && allow_fixture_fallback)
    {
        // Test/image fixtures may not expose full checkpoint metadata yet.
        spaceman_loaded_ = spaceman_object_id_ != 0;
        legacy_fixture_fallback_used_ = legacy_fixture_fallback_used_ || spaceman_loaded_;
    }

    if (!spaceman_loaded_)
    {
        MarkRecoveryRequired(L"CanonicalSpacemanCheckpointMissing");
        return false;
    }

    return spaceman_loaded_;
}

std::optional<std::uint64_t> MetadataStore::ResolveObjectBlockIndex(std::uint64_t object_or_block) const
{
    if (block_size_ == 0 || object_or_block == 0)
    {
        return std::nullopt;
    }

    auto block_index = object_or_block;
    if (auto mapped = superblock_object_block_map_.find(object_or_block); mapped != superblock_object_block_map_.end())
    {
        block_index = mapped->second;
    }

    if (block_index == 0)
    {
        return std::nullopt;
    }

    if (total_blocks_ != 0 && block_index >= total_blocks_)
    {
        return std::nullopt;
    }
    if (block_index > (std::numeric_limits<std::uint64_t>::max() / static_cast<std::uint64_t>(block_size_)))
    {
        return std::nullopt;
    }
    return block_index;
}

bool MetadataStore::ReadBlockByIndexDirect(std::uint64_t block_index, std::vector<std::byte>& out_block) const
{
    out_block.clear();
    if (block_size_ == 0 || block_index == 0)
    {
        return false;
    }
    if (total_blocks_ != 0 && block_index >= total_blocks_)
    {
        return false;
    }
    if (block_index > (std::numeric_limits<std::uint64_t>::max() / static_cast<std::uint64_t>(block_size_)))
    {
        return false;
    }

    const auto block_offset = block_index * static_cast<std::uint64_t>(block_size_);
    return device_.Read(block_offset, block_size_, out_block) &&
           out_block.size() >= static_cast<std::size_t>(block_size_);
}

bool MetadataStore::WriteBlockByIndexDirect(std::uint64_t block_index, const std::vector<std::byte>& block)
{
    if (block_size_ == 0 || block_index == 0)
    {
        return false;
    }
    if (total_blocks_ != 0 && block_index >= total_blocks_)
    {
        return false;
    }
    if (block_index > (std::numeric_limits<std::uint64_t>::max() / static_cast<std::uint64_t>(block_size_)))
    {
        return false;
    }
    if (block.size() > static_cast<std::size_t>(block_size_))
    {
        return false;
    }

    auto payload = block;
    if (payload.size() < static_cast<std::size_t>(block_size_))
    {
        payload.resize(static_cast<std::size_t>(block_size_), std::byte{0});
    }

    const auto block_offset = block_index * static_cast<std::uint64_t>(block_size_);
    return device_.Write(block_offset, payload);
}

bool MetadataStore::ReadMetadataBlock(std::uint64_t block_index, std::vector<std::byte>& out_block) const
{
    out_block.clear();
    auto resolved = ResolveObjectBlockIndex(block_index);
    if (!resolved.has_value())
    {
        return false;
    }

    return ReadBlockByIndexDirect(resolved.value(), out_block);
}

bool MetadataStore::WriteMetadataBlock(std::uint64_t block_index, const std::vector<std::byte>& block)
{
    auto resolved = ResolveObjectBlockIndex(block_index);
    if (!resolved.has_value())
    {
        return false;
    }

    return WriteBlockByIndexDirect(resolved.value(), block);
}

bool MetadataStore::IsReservedMetadataBlock(std::uint64_t block_index) const
{
    if (block_index == 0)
    {
        return true;
    }
    if (total_blocks_ != 0 && block_index >= total_blocks_)
    {
        return true;
    }

    if (block_size_ != 0)
    {
        const auto matches_offset_block = [&](std::uint64_t offset) -> bool
        {
            if (offset == 0 || (offset % static_cast<std::uint64_t>(block_size_)) != 0)
            {
                return false;
            }
            return (offset / static_cast<std::uint64_t>(block_size_)) == block_index;
        };

        if (matches_offset_block(active_superblock_offset_) ||
            matches_offset_block(alternate_superblock_offset_))
        {
            return true;
        }
    }

    if (first_superblock_block_ != 0)
    {
        if (first_superblock_block_ <= (std::numeric_limits<std::uint64_t>::max() - static_cast<std::uint64_t>(current_superblock_map_index_)) &&
            block_index == (first_superblock_block_ + static_cast<std::uint64_t>(current_superblock_map_index_)))
        {
            return true;
        }
    }
    if (first_meta_block_ != 0)
    {
        if (first_meta_block_ <= (std::numeric_limits<std::uint64_t>::max() - static_cast<std::uint64_t>(current_meta_index_)) &&
            block_index == (first_meta_block_ + static_cast<std::uint64_t>(current_meta_index_)))
        {
            return true;
        }
        if (first_meta_block_ <= (std::numeric_limits<std::uint64_t>::max() - static_cast<std::uint64_t>(next_meta_index_)) &&
            block_index == (first_meta_block_ + static_cast<std::uint64_t>(next_meta_index_)))
        {
            return true;
        }
    }

    for (const auto& entry : superblock_object_block_map_)
    {
        if (entry.second == block_index)
        {
            return true;
        }
    }

    if (auto volume_root_block = ResolveObjectBlockIndex(volume_root_block_);
        volume_root_block.has_value() && volume_root_block.value() == block_index)
    {
        return true;
    }
    if (auto spaceman_block = ResolveObjectBlockIndex(spaceman_object_id_);
        spaceman_block.has_value() && spaceman_block.value() == block_index)
    {
        return true;
    }

    return false;
}

std::optional<std::uint64_t> MetadataStore::FindCheckpointCompanionBlock(
    std::uint64_t primary_block,
    const std::vector<std::uint64_t>& disallowed_blocks) const
{
    if (primary_block == 0)
    {
        return std::nullopt;
    }

    const auto is_disallowed = [&](std::uint64_t candidate) -> bool
    {
        if (candidate == 0 || candidate == primary_block)
        {
            return true;
        }
        if (IsReservedMetadataBlock(candidate))
        {
            return true;
        }
        return std::find(disallowed_blocks.begin(), disallowed_blocks.end(), candidate) != disallowed_blocks.end();
    };

    for (std::uint64_t delta = 1; delta <= 64; ++delta)
    {
        if (primary_block > (std::numeric_limits<std::uint64_t>::max() - delta))
        {
            break;
        }

        const auto candidate = primary_block + delta;
        if (is_disallowed(candidate))
        {
            continue;
        }
        return candidate;
    }

    return std::nullopt;
}

std::vector<std::uint64_t> MetadataStore::ResolveObjectMapCheckpointBlockIndices() const
{
    std::vector<std::uint64_t> candidates;
    auto primary = ResolveObjectBlockIndex(volume_root_block_);
    if (!primary.has_value())
    {
        return candidates;
    }

    candidates.push_back(primary.value());
    std::vector<std::uint64_t> disallowed
    {
        primary.value(),
        ResolveObjectBlockIndex(spaceman_object_id_).value_or(0)
    };
    for (const auto inode_slot : ResolveInodeCheckpointBlockIndices())
    {
        disallowed.push_back(inode_slot);
    }

    if (auto companion = FindCheckpointCompanionBlock(primary.value(), disallowed); companion.has_value())
    {
        candidates.push_back(companion.value());
    }
    return candidates;
}

std::vector<std::uint64_t> MetadataStore::ResolveSpacemanCheckpointBlockIndices() const
{
    std::vector<std::uint64_t> candidates;
    auto primary = ResolveObjectBlockIndex(spaceman_object_id_);
    if (!primary.has_value())
    {
        return candidates;
    }

    candidates.push_back(primary.value());
    std::vector<std::uint64_t> disallowed
    {
        primary.value(),
        ResolveObjectBlockIndex(volume_root_block_).value_or(0)
    };
    for (const auto inode_slot : ResolveInodeCheckpointBlockIndices())
    {
        disallowed.push_back(inode_slot);
    }

    if (auto companion = FindCheckpointCompanionBlock(primary.value(), disallowed); companion.has_value())
    {
        candidates.push_back(companion.value());
    }
    return candidates;
}

std::vector<std::uint64_t> MetadataStore::ResolveInodeCheckpointBlockIndices() const
{
    std::vector<std::uint64_t> candidates;
    auto volume_block = ResolveObjectBlockIndex(volume_root_block_);
    if (!volume_block.has_value())
    {
        return candidates;
    }

    const auto spaceman_block = ResolveObjectBlockIndex(spaceman_object_id_).value_or(0);
    for (std::uint64_t delta = 1; delta <= 64 && candidates.size() < 2; ++delta)
    {
        if (volume_block.value() > (std::numeric_limits<std::uint64_t>::max() - delta))
        {
            break;
        }

        const auto candidate = volume_block.value() + delta;
        if (candidate == 0 ||
            candidate == volume_block.value() ||
            candidate == spaceman_block ||
            IsReservedMetadataBlock(candidate))
        {
            continue;
        }
        if (std::find(candidates.begin(), candidates.end(), candidate) != candidates.end())
        {
            continue;
        }

        candidates.push_back(candidate);
    }

    return candidates;
}

std::vector<std::uint64_t> MetadataStore::ResolveBtreeCheckpointBlockIndices() const
{
    std::vector<std::uint64_t> candidates;
    auto volume_block = ResolveObjectBlockIndex(volume_root_block_);
    if (!volume_block.has_value())
    {
        return candidates;
    }

    std::vector<std::uint64_t> disallowed
    {
        volume_block.value(),
        ResolveObjectBlockIndex(spaceman_object_id_).value_or(0)
    };

    const auto object_map_slots = ResolveObjectMapCheckpointBlockIndices();
    disallowed.insert(disallowed.end(), object_map_slots.begin(), object_map_slots.end());
    const auto spaceman_slots = ResolveSpacemanCheckpointBlockIndices();
    disallowed.insert(disallowed.end(), spaceman_slots.begin(), spaceman_slots.end());
    const auto inode_slots = ResolveInodeCheckpointBlockIndices();
    disallowed.insert(disallowed.end(), inode_slots.begin(), inode_slots.end());

    for (std::uint64_t delta = 1; delta <= 96 && candidates.size() < 2; ++delta)
    {
        if (volume_block.value() > (std::numeric_limits<std::uint64_t>::max() - delta))
        {
            break;
        }

        const auto candidate = volume_block.value() + delta;
        if (candidate == 0 ||
            IsReservedMetadataBlock(candidate) ||
            std::find(disallowed.begin(), disallowed.end(), candidate) != disallowed.end())
        {
            continue;
        }
        candidates.push_back(candidate);
        disallowed.push_back(candidate);
    }

    return candidates;
}

std::vector<std::uint64_t> MetadataStore::ResolveReplayCheckpointBlockIndices() const
{
    std::vector<std::uint64_t> candidates;
    auto volume_block = ResolveObjectBlockIndex(volume_root_block_);
    if (!volume_block.has_value())
    {
        return candidates;
    }

    std::vector<std::uint64_t> disallowed
    {
        volume_block.value(),
        ResolveObjectBlockIndex(spaceman_object_id_).value_or(0)
    };

    const auto object_map_slots = ResolveObjectMapCheckpointBlockIndices();
    disallowed.insert(disallowed.end(), object_map_slots.begin(), object_map_slots.end());
    const auto spaceman_slots = ResolveSpacemanCheckpointBlockIndices();
    disallowed.insert(disallowed.end(), spaceman_slots.begin(), spaceman_slots.end());
    const auto inode_slots = ResolveInodeCheckpointBlockIndices();
    disallowed.insert(disallowed.end(), inode_slots.begin(), inode_slots.end());
    const auto btree_slots = ResolveBtreeCheckpointBlockIndices();
    disallowed.insert(disallowed.end(), btree_slots.begin(), btree_slots.end());

    for (std::uint64_t delta = 1; delta <= 128 && candidates.size() < 2; ++delta)
    {
        if (volume_block.value() > (std::numeric_limits<std::uint64_t>::max() - delta))
        {
            break;
        }

        const auto candidate = volume_block.value() + delta;
        if (candidate == 0 ||
            IsReservedMetadataBlock(candidate) ||
            std::find(disallowed.begin(), disallowed.end(), candidate) != disallowed.end())
        {
            continue;
        }
        candidates.push_back(candidate);
        disallowed.push_back(candidate);
    }

    return candidates;
}

bool MetadataStore::LoadObjectMapCheckpointBlock(std::uint64_t block_index, const std::vector<std::byte>& block)
{
    (void)block_index;
    ApfsObjectMapStore object_map_store;
    std::vector<ApfsObjectMapEntry> parsed_entries;
    std::uint64_t persisted_xid = 0;
    if (!object_map_store.TryParseCheckpointV3(block, parsed_entries, persisted_xid))
    {
        return false;
    }

    committed_object_map_.clear();
    committed_object_map_.reserve(parsed_entries.size());
    for (const auto& entry : parsed_entries)
    {
        committed_object_map_.emplace(
            entry.object_id,
            ObjectMapUpdate
            {
                entry.object_id,
                entry.physical_address,
                entry.logical_size,
                entry.xid
            });
    }

    if (persisted_xid > 0)
    {
        last_committed_xid_ = std::max(last_committed_xid_.value_or(0), persisted_xid);
    }
    return true;
}

bool MetadataStore::LoadSpacemanCheckpointBlock(std::uint64_t block_index, const std::vector<std::byte>& block)
{
    (void)block_index;
    ApfsSpacemanStore spaceman_store;
    std::vector<ApfsExtent> parsed_allocations;
    std::vector<ApfsExtent> parsed_free_extents;
    std::uint64_t persisted_xid = 0;
    if (!spaceman_store.TryParseCheckpointV3(
            block,
            parsed_allocations,
            parsed_free_extents,
            persisted_xid))
    {
        return false;
    }

    committed_spaceman_allocations_.clear();
    committed_spaceman_allocations_.reserve(parsed_allocations.size());
    for (const auto& extent : parsed_allocations)
    {
        const auto aligned_bytes = AlignExtentBytes(extent.bytes);
        if (aligned_bytes == 0 || aligned_bytes != extent.bytes)
        {
            return false;
        }
        committed_spaceman_allocations_.push_back(
            SpacemanAllocation
            {
                extent.physical_address,
                aligned_bytes
            });
    }

    committed_spaceman_free_extents_.clear();
    committed_spaceman_free_extents_.reserve(parsed_free_extents.size());
    for (const auto& extent : parsed_free_extents)
    {
        const auto aligned_bytes = AlignExtentBytes(extent.bytes);
        if (aligned_bytes == 0 || aligned_bytes != extent.bytes)
        {
            return false;
        }
        committed_spaceman_free_extents_.push_back(
            SpacemanAllocation
            {
                extent.physical_address,
                aligned_bytes
            });
    }

    std::sort(
        committed_spaceman_free_extents_.begin(),
        committed_spaceman_free_extents_.end(),
        [](const SpacemanAllocation& lhs, const SpacemanAllocation& rhs)
        {
            return lhs.physical_address < rhs.physical_address;
        });

    std::vector<SpacemanAllocation> merged_free_extents;
    merged_free_extents.reserve(committed_spaceman_free_extents_.size());
    for (const auto& extent : committed_spaceman_free_extents_)
    {
        if (merged_free_extents.empty())
        {
            merged_free_extents.push_back(extent);
            continue;
        }

        auto& previous = merged_free_extents.back();
        const auto previous_end = previous.physical_address + previous.bytes;
        const auto current_end = extent.physical_address + extent.bytes;
        if (extent.physical_address <= previous_end)
        {
            if (current_end > previous_end)
            {
                previous.bytes = current_end - previous.physical_address;
            }
            continue;
        }
        merged_free_extents.push_back(extent);
    }
    committed_spaceman_free_extents_ = std::move(merged_free_extents);

    for (const auto& allocation : committed_spaceman_allocations_)
    {
        const auto allocation_end = allocation.physical_address + allocation.bytes;
        if (allocation_end > next_ephemeral_extent_)
        {
            next_ephemeral_extent_ = allocation_end;
        }
    }
    working_spaceman_free_extents_ = committed_spaceman_free_extents_;
    working_next_ephemeral_extent_ = next_ephemeral_extent_;

    if (persisted_xid > 0)
    {
        last_committed_xid_ = std::max(last_committed_xid_.value_or(0), persisted_xid);
    }

    return true;
}

std::optional<std::uint64_t> MetadataStore::ResolveInodeCheckpointBlockIndex() const
{
    auto candidates = ResolveInodeCheckpointBlockIndices();
    if (candidates.empty())
    {
        return std::nullopt;
    }

    return candidates.front();
}

bool MetadataStore::LoadInodeCheckpointBlock(std::uint64_t block_index, const std::vector<std::byte>& block)
{
    (void)block_index;
    constexpr std::array<char, 12> kMagicV4 =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'I', 'N', 'O', 'D', '4', '\0'
    };
    constexpr std::array<char, 12> kMagicV5 =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'I', 'N', 'O', 'D', '5', '\0'
    };
    constexpr std::size_t kHeaderBytes = kCheckpointHeaderBytes;
    constexpr std::size_t kRecordFixedBytesV4 = 52;
    constexpr std::size_t kRecordFixedBytesV5 = 60;
    if (block.size() < kHeaderBytes)
    {
        return false;
    }

    const auto matches_magic = [&](const std::array<char, 12>& magic)
    {
        for (std::size_t index = 0; index < magic.size(); ++index)
        {
            if (std::to_integer<unsigned char>(block[index]) != static_cast<unsigned char>(magic[index]))
            {
                return false;
            }
        }
        return true;
    };
    const auto has_persisted_timestamp = matches_magic(kMagicV5);
    if (!has_persisted_timestamp && !matches_magic(kMagicV4))
    {
        return false;
    }
    const auto kRecordFixedBytes = has_persisted_timestamp ? kRecordFixedBytesV5 : kRecordFixedBytesV4;

    const auto persisted_xid = ReadLe64(block, 12);
    const auto inode_count = ReadLe32(block, 20);
    const auto persisted_payload_bytes = ReadLe32(block, 24);
    const auto persisted_checksum = ReadLe32(block, kCheckpointChecksumOffset);

    std::unordered_map<std::uint64_t, InodeRecord> loaded_inodes;
    std::unordered_map<std::wstring, std::uint64_t> loaded_path_index;
    std::vector<DirectoryLink> loaded_directory_links;
    loaded_inodes.reserve(inode_count);
    loaded_path_index.reserve(inode_count);
    loaded_directory_links.reserve(inode_count > 0 ? static_cast<std::size_t>(inode_count - 1) : 0);

    std::size_t cursor = kHeaderBytes;
    for (std::uint32_t index = 0; index < inode_count; ++index)
    {
        if (cursor > block.size() ||
            kRecordFixedBytes > (block.size() - cursor))
        {
            return false;
        }

        InodeRecord inode{};
        inode.object_id = ReadLe64(block, cursor + 0);
        inode.parent_object_id = ReadLe64(block, cursor + 8);
        inode.logical_size = ReadLe64(block, cursor + 16);
        inode.data_physical_address = ReadLe64(block, cursor + 24);
        inode.xid = ReadLe64(block, cursor + 32);
        std::size_t flags_offset = cursor + 40;
        std::size_t name_length_offset = cursor + 44;
        std::size_t path_length_offset = cursor + 48;
        if (has_persisted_timestamp)
        {
            inode.timestamp_utc = ReadLe64(block, cursor + 40);
            flags_offset += 8;
            name_length_offset += 8;
            path_length_offset += 8;
        }
        const auto flags = ReadLe32(block, flags_offset);
        const auto name_length = ReadLe32(block, name_length_offset);
        const auto path_length = ReadLe32(block, path_length_offset);
        cursor += kRecordFixedBytes;

        const auto name_bytes = static_cast<std::uint64_t>(name_length) * static_cast<std::uint64_t>(sizeof(wchar_t));
        const auto path_bytes = static_cast<std::uint64_t>(path_length) * static_cast<std::uint64_t>(sizeof(wchar_t));
        if (name_bytes > (std::numeric_limits<std::size_t>::max() - cursor) ||
            path_bytes > (std::numeric_limits<std::size_t>::max() - cursor - static_cast<std::size_t>(name_bytes)))
        {
            return false;
        }
        const auto required_bytes = static_cast<std::size_t>(name_bytes + path_bytes);
        if (required_bytes > (block.size() - cursor))
        {
            return false;
        }

        inode.is_directory = (flags & 0x1u) != 0;
        inode.name.resize(name_length);
        if (name_bytes > 0)
        {
            std::memcpy(inode.name.data(), block.data() + cursor, static_cast<std::size_t>(name_bytes));
        }
        cursor += static_cast<std::size_t>(name_bytes);
        inode.full_path.resize(path_length);
        if (path_bytes > 0)
        {
            std::memcpy(inode.full_path.data(), block.data() + cursor, static_cast<std::size_t>(path_bytes));
        }
        cursor += static_cast<std::size_t>(path_bytes);

        if (inode.object_id == 0 || inode.full_path.empty())
        {
            return false;
        }
        if (NormalizePath(inode.full_path) != inode.full_path)
        {
            return false;
        }
        if (!inode.is_directory && inode.logical_size > 0 && inode.data_physical_address == 0)
        {
            return false;
        }
        if (inode.is_directory && (inode.logical_size != 0 || inode.data_physical_address != 0))
        {
            return false;
        }

        auto [inode_it, inserted] = loaded_inodes.emplace(inode.object_id, inode);
        if (!inserted)
        {
            return false;
        }

        const auto canonical_path = CanonicalPathKey(inode.full_path);
        auto [path_it, path_inserted] = loaded_path_index.emplace(canonical_path, inode.object_id);
        if (!path_inserted && path_it->second != inode.object_id)
        {
            return false;
        }

        if (!IsRootPath(inode.full_path))
        {
            loaded_directory_links.push_back(DirectoryLink
            {
                inode.parent_object_id,
                inode.name,
                inode.object_id,
                inode.xid
            });
        }
    }

    const auto payload_bytes = cursor - kHeaderBytes;
    if (persisted_payload_bytes != 0 &&
        persisted_payload_bytes != static_cast<std::uint32_t>(payload_bytes))
    {
        return false;
    }
    if (persisted_checksum != 0 &&
        ComputeCheckpointChecksum(block, payload_bytes) != persisted_checksum)
    {
        return false;
    }

    if (!ValidateInodeGraphState(
            loaded_inodes,
            loaded_path_index,
            loaded_directory_links,
            /*require_root_object=*/true))
    {
        return false;
    }

    committed_inodes_ = std::move(loaded_inodes);
    committed_path_index_ = std::move(loaded_path_index);
    committed_directory_links_ = std::move(loaded_directory_links);
    working_inodes_ = committed_inodes_;
    working_path_index_ = committed_path_index_;
    working_directory_links_ = committed_directory_links_;

    if (persisted_xid > 0)
    {
        last_committed_xid_ = std::max(last_committed_xid_.value_or(0), persisted_xid);
    }
    return true;
}

bool MetadataStore::LoadBtreeCheckpointBlock(std::uint64_t block_index, const std::vector<std::byte>& block)
{
    (void)block_index;
    constexpr std::array<char, 12> kMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'B', 'T', 'R', '5', '\0', '\0'
    };
    constexpr std::size_t kHeaderBytes = kCheckpointHeaderBytes;
    constexpr std::size_t kRecordHeaderBytes = 16;
    if (block.size() < kHeaderBytes)
    {
        return false;
    }

    for (std::size_t index = 0; index < kMagic.size(); ++index)
    {
        if (std::to_integer<unsigned char>(block[index]) != static_cast<unsigned char>(kMagic[index]))
        {
            return false;
        }
    }

    const auto persisted_xid = ReadLe64(block, 12);
    const auto record_count = ReadLe32(block, 20);
    const auto persisted_payload_bytes = ReadLe32(block, 24);
    const auto persisted_checksum = ReadLe32(block, kCheckpointChecksumOffset);

    std::vector<BtreeRecord> loaded_records;
    loaded_records.reserve(record_count);
    std::size_t cursor = kHeaderBytes;
    for (std::uint32_t index = 0; index < record_count; ++index)
    {
        if (cursor > block.size() ||
            kRecordHeaderBytes > (block.size() - cursor))
        {
            return false;
        }

        const auto kind_value = ReadLe32(block, cursor + 0);
        const auto tombstone_flag = ReadLe32(block, cursor + 4);
        const auto key_length = ReadLe32(block, cursor + 8);
        const auto value_length = ReadLe32(block, cursor + 12);
        cursor += kRecordHeaderBytes;

        if (kind_value < static_cast<std::uint32_t>(BtreeRecordKind::Inode) ||
            kind_value > static_cast<std::uint32_t>(BtreeRecordKind::FileExtent))
        {
            return false;
        }

        const auto required_payload =
            static_cast<std::uint64_t>(key_length) + static_cast<std::uint64_t>(value_length);
        if (required_payload > (std::numeric_limits<std::size_t>::max() - cursor))
        {
            return false;
        }
        if (static_cast<std::size_t>(required_payload) > (block.size() - cursor))
        {
            return false;
        }

        BtreeRecord record{};
        record.kind = static_cast<BtreeRecordKind>(kind_value);
        record.tombstone = tombstone_flag != 0;
        if (key_length > 0)
        {
            record.key.insert(
                record.key.end(),
                block.begin() + static_cast<std::vector<std::byte>::difference_type>(cursor),
                block.begin() + static_cast<std::vector<std::byte>::difference_type>(cursor + key_length));
            cursor += key_length;
        }
        if (value_length > 0)
        {
            record.value.insert(
                record.value.end(),
                block.begin() + static_cast<std::vector<std::byte>::difference_type>(cursor),
                block.begin() + static_cast<std::vector<std::byte>::difference_type>(cursor + value_length));
            cursor += value_length;
        }
        loaded_records.push_back(std::move(record));
    }

    const auto payload_bytes = cursor - kHeaderBytes;
    if (persisted_payload_bytes != 0 &&
        persisted_payload_bytes != static_cast<std::uint32_t>(payload_bytes))
    {
        return false;
    }
    if (persisted_checksum != 0 &&
        ComputeCheckpointChecksum(block, payload_bytes) != persisted_checksum)
    {
        return false;
    }

    committed_btree_records_ = CanonicalizeBtreeRecords(loaded_records);

    const auto allow_fixture_fallback = IsLegacyFixtureFallbackAllowedForCurrentContext();

    ApfsVolumeTreeStore volume_tree_store;
    ApfsVolumeTreeProjection volume_tree_projection{};
    std::wstring volume_tree_error;
    if (!volume_tree_store.TryProjectFromBtreeRecords(
            committed_btree_records_,
            volume_tree_projection,
            volume_tree_error))
    {
        if (!allow_fixture_fallback)
        {
            return false;
        }

        legacy_fixture_fallback_used_ = true;
    }
    if (persisted_xid > 0)
    {
        last_committed_xid_ = std::max(last_committed_xid_.value_or(0), persisted_xid);
    }
    return true;
}

bool MetadataStore::LoadReplayCheckpointBlock(
    std::uint64_t block_index,
    const std::vector<std::byte>& block,
    std::uint64_t& out_target_xid,
    std::uint64_t& out_source_xid,
    std::uint64_t& out_commit_blob_address,
    std::uint64_t& out_commit_blob_bytes) const
{
    (void)block_index;
    constexpr std::array<char, 12> kMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'R', 'P', 'L', '1', '\0', '\0'
    };
    constexpr std::size_t kHeaderBytes = kCheckpointHeaderBytes;
    constexpr std::size_t kReplayPayloadBytes = 24;

    if (block.size() < (kHeaderBytes + kReplayPayloadBytes))
    {
        return false;
    }

    for (std::size_t index = 0; index < kMagic.size(); ++index)
    {
        if (std::to_integer<unsigned char>(block[index]) != static_cast<unsigned char>(kMagic[index]))
        {
            return false;
        }
    }

    const auto persisted_xid = ReadLe64(block, 12);
    const auto persisted_version = ReadLe32(block, 20);
    const auto persisted_payload_bytes = ReadLe32(block, 24);
    const auto persisted_checksum = ReadLe32(block, kCheckpointChecksumOffset);
    if (persisted_xid == 0 || persisted_version != 1)
    {
        return false;
    }
    if (persisted_payload_bytes != kReplayPayloadBytes)
    {
        return false;
    }
    if (persisted_checksum == 0 ||
        ComputeCheckpointChecksum(block, persisted_payload_bytes) != persisted_checksum)
    {
        return false;
    }
    for (std::size_t index = (kHeaderBytes + kReplayPayloadBytes); index < block.size(); ++index)
    {
        if (block[index] != std::byte{0})
        {
            return false;
        }
    }

    const auto source_xid = ReadLe64(block, kHeaderBytes + 0);
    const auto commit_blob_address = ReadLe64(block, kHeaderBytes + 8);
    const auto commit_blob_bytes = ReadLe64(block, kHeaderBytes + 16);
    if (source_xid >= persisted_xid || (source_xid + 1) != persisted_xid)
    {
        return false;
    }
    if (!ValidateCommitBlobLocation(commit_blob_address, commit_blob_bytes))
    {
        return false;
    }

    out_target_xid = persisted_xid;
    out_source_xid = source_xid;
    out_commit_blob_address = commit_blob_address;
    out_commit_blob_bytes = commit_blob_bytes;
    return true;
}

bool MetadataStore::RebuildInodeStateFromBtreeRecords(
    const std::vector<BtreeRecord>& records,
    std::unordered_map<std::uint64_t, InodeRecord>& out_inodes,
    std::unordered_map<std::wstring, std::uint64_t>& out_path_index,
    std::vector<DirectoryLink>& out_directory_links) const
{
    out_inodes.clear();
    out_path_index.clear();
    out_directory_links.clear();

    std::unordered_map<std::uint64_t, DecodedBtreeInode> decoded_inodes;
    std::unordered_map<std::uint64_t, DecodedBtreeExtent> decoded_extents;
    std::unordered_map<std::uint64_t, std::vector<DecodedBtreeDirectoryEntry>> decoded_directory_entries_by_parent;
    std::unordered_set<std::wstring> seen_directory_entry_keys;

    const auto canonical_name_key = [](const std::wstring& name)
    {
        std::wstring key = name;
        std::transform(key.begin(), key.end(), key.begin(), [](wchar_t ch)
        {
            return static_cast<wchar_t>(std::towlower(ch));
        });
        return key;
    };
    const auto build_directory_entry_key = [&](std::uint64_t parent_object_id, const std::wstring& entry_name)
    {
        std::wstring key = std::to_wstring(parent_object_id);
        key.push_back(L'\x1f');
        key.append(canonical_name_key(entry_name));
        return key;
    };

    for (const auto& record : records)
    {
        if (record.tombstone)
        {
            return false;
        }

        switch (record.kind)
        {
        case BtreeRecordKind::Inode:
        {
            DecodedBtreeInode decoded{};
            if (!DecodeBtreeInodeRecord(record, decoded))
            {
                return false;
            }
            if (!decoded_inodes.emplace(decoded.object_id, std::move(decoded)).second)
            {
                return false;
            }
            break;
        }
        case BtreeRecordKind::DirectoryEntry:
        {
            DecodedBtreeDirectoryEntry decoded{};
            if (!DecodeBtreeDirectoryRecord(record, decoded))
            {
                return false;
            }
            auto entry_key = build_directory_entry_key(decoded.parent_object_id, decoded.entry_name);
            if (!seen_directory_entry_keys.emplace(std::move(entry_key)).second)
            {
                return false;
            }
            decoded_directory_entries_by_parent[decoded.parent_object_id].push_back(std::move(decoded));
            break;
        }
        case BtreeRecordKind::FileExtent:
        {
            DecodedBtreeExtent decoded{};
            if (!DecodeBtreeExtentRecord(record, decoded))
            {
                return false;
            }
            if (decoded.logical_offset != 0)
            {
                return false;
            }
            if (!decoded_extents.emplace(decoded.object_id, std::move(decoded)).second)
            {
                return false;
            }
            break;
        }
        default:
            return false;
        }
    }

    for (const auto& [object_id, inode] : decoded_inodes)
    {
        if (inode.is_directory)
        {
            if (decoded_extents.contains(object_id))
            {
                return false;
            }
            continue;
        }

        if (inode.logical_size == 0)
        {
            if (inode.data_physical_address != 0 || decoded_extents.contains(object_id))
            {
                return false;
            }
            continue;
        }

        auto extent_it = decoded_extents.find(object_id);
        if (extent_it == decoded_extents.end())
        {
            return false;
        }
        if (extent_it->second.physical_address != inode.data_physical_address ||
            extent_it->second.extent_bytes != inode.logical_size)
        {
            return false;
        }
    }

    const auto root_path = std::wstring(L"\\");
    const auto root_object_id = volume_root_block_ != 0 ? volume_root_block_ : StableObjectIdFromPath(root_path);
    InodeRecord root_inode{};
    root_inode.object_id = root_object_id;
    root_inode.parent_object_id = root_object_id;
    root_inode.name = L"";
    root_inode.full_path = root_path;
    root_inode.is_directory = true;
    root_inode.logical_size = 0;
    root_inode.data_physical_address = 0;
    root_inode.xid = checkpoint_xid_;
    out_inodes.emplace(root_inode.object_id, root_inode);
    out_path_index.emplace(CanonicalPathKey(root_inode.full_path), root_inode.object_id);

    std::vector<std::uint64_t> directory_queue;
    directory_queue.push_back(root_object_id);
    std::size_t queue_cursor = 0;
    std::unordered_set<std::uint64_t> visited_non_root_inodes;
    while (queue_cursor < directory_queue.size())
    {
        const auto parent_object_id = directory_queue[queue_cursor++];
        auto parent_inode_it = out_inodes.find(parent_object_id);
        if (parent_inode_it == out_inodes.end())
        {
            return false;
        }

        auto entries_it = decoded_directory_entries_by_parent.find(parent_object_id);
        if (entries_it == decoded_directory_entries_by_parent.end())
        {
            continue;
        }

        auto entries = entries_it->second;
        std::sort(entries.begin(), entries.end(), [&](const DecodedBtreeDirectoryEntry& lhs, const DecodedBtreeDirectoryEntry& rhs)
        {
            const auto lhs_key = canonical_name_key(lhs.entry_name);
            const auto rhs_key = canonical_name_key(rhs.entry_name);
            if (lhs_key == rhs_key)
            {
                return lhs.child_object_id < rhs.child_object_id;
            }
            return lhs_key < rhs_key;
        });

        for (const auto& entry : entries)
        {
            if (entry.child_object_id == 0 || entry.child_object_id == root_object_id)
            {
                return false;
            }

            auto decoded_inode_it = decoded_inodes.find(entry.child_object_id);
            if (decoded_inode_it == decoded_inodes.end())
            {
                return false;
            }
            const auto& decoded_inode = decoded_inode_it->second;
            if (decoded_inode.parent_object_id != parent_object_id ||
                canonical_name_key(decoded_inode.name) != canonical_name_key(entry.entry_name))
            {
                return false;
            }

            if (!visited_non_root_inodes.emplace(entry.child_object_id).second)
            {
                return false;
            }
            if (out_inodes.contains(entry.child_object_id))
            {
                return false;
            }

            std::wstring child_path = parent_inode_it->second.full_path;
            if (!IsRootPath(child_path))
            {
                child_path.push_back(L'\\');
            }
            child_path.append(decoded_inode.name);
            child_path = NormalizePath(child_path);
            if (child_path.empty() || IsRootPath(child_path))
            {
                return false;
            }

            const auto child_path_key = CanonicalPathKey(child_path);
            if (child_path_key.empty())
            {
                return false;
            }
            if (!out_path_index.emplace(child_path_key, entry.child_object_id).second)
            {
                return false;
            }

            InodeRecord rebuilt_inode{};
            rebuilt_inode.object_id = entry.child_object_id;
            rebuilt_inode.parent_object_id = parent_object_id;
            rebuilt_inode.name = decoded_inode.name;
            rebuilt_inode.full_path = std::move(child_path);
            rebuilt_inode.is_directory = decoded_inode.is_directory;
            rebuilt_inode.logical_size = decoded_inode.logical_size;
            rebuilt_inode.data_physical_address = decoded_inode.data_physical_address;
            rebuilt_inode.xid = decoded_inode.xid;
            rebuilt_inode.timestamp_utc = decoded_inode.timestamp_utc;
            out_inodes.emplace(rebuilt_inode.object_id, rebuilt_inode);
            out_directory_links.push_back(DirectoryLink
            {
                parent_object_id,
                rebuilt_inode.name,
                rebuilt_inode.object_id,
                entry.xid
            });

            if (rebuilt_inode.is_directory)
            {
                directory_queue.push_back(rebuilt_inode.object_id);
            }
        }
    }

    if (visited_non_root_inodes.size() != decoded_inodes.size())
    {
        return false;
    }

    return ValidateInodeGraphState(
        out_inodes,
        out_path_index,
        out_directory_links,
        /*require_root_object=*/true);
}

bool MetadataStore::IsContainerLoaded() const noexcept
{
    return container_loaded_;
}

std::optional<std::uint32_t> MetadataStore::BlockSizeBytes() const noexcept
{
    return container_loaded_ ? std::optional<std::uint32_t>(block_size_) : std::nullopt;
}

std::optional<std::uint64_t> MetadataStore::TotalBlocks() const noexcept
{
    return container_loaded_ ? std::optional<std::uint64_t>(total_blocks_) : std::nullopt;
}

std::optional<std::uint64_t> MetadataStore::CheckpointXid() const noexcept
{
    return container_loaded_ ? std::optional<std::uint64_t>(checkpoint_xid_) : std::nullopt;
}

bool MetadataStore::PrepareNativeWritePath()
{
    const auto fail_prepare = [this](std::wstring reason) -> bool
    {
        native_write_ready_ = false;
        commit_path_ready_ = false;
        canonical_state_loaded_ = false;
        canonical_commit_ready_ = false;
        write_device_allowed_ = false;
        SyncCommitBlobTelemetryWithMode();
        if (!reason.empty())
        {
            MarkRecoveryRequired(std::move(reason));
        }
        return false;
    };

    if (!container_loaded_ && !LoadContainerState())
    {
        return fail_prepare(L"ContainerStateLoadFailed");
    }
    if (!LoadCanonicalState())
    {
        if (!recovery_reason_.empty())
        {
            return fail_prepare(recovery_reason_);
        }
        return fail_prepare(L"VolumeStateLoadFailed");
    }
    if (!persistent_state_loaded_ && !LoadPersistentState())
    {
        return fail_prepare(L"PersistentStateLoadFailed");
    }

    native_write_ready_ = true;
    write_device_allowed_ = device_.IsWritable() &&
                            (context_.allow_raw_physical_write || !IsLikelyRawDevicePath(context_.device_path));
    commit_path_ready_ = native_write_ready_ && write_device_allowed_ && !recovery_required_;
    canonical_state_loaded_ = canonical_state_loaded_ && native_write_ready_;
    canonical_commit_ready_ = CanReportCanonicalCommitReady(
        canonical_state_loaded_,
        commit_path_ready_,
        recovery_required_,
        legacy_fixture_fallback_used_);
    if (!EnsureRootState())
    {
        return fail_prepare(L"RootStateInvalid");
    }
    if (context_.integrity_check_on_mount && !VerifyIntegrity())
    {
        return fail_prepare(L"IntegrityCheckFailedOnMount");
    }

    working_inodes_ = committed_inodes_;
    working_path_index_ = committed_path_index_;
    working_directory_links_ = committed_directory_links_;
    working_spaceman_free_extents_ = committed_spaceman_free_extents_;
    working_next_ephemeral_extent_ = next_ephemeral_extent_;
    pending_mutations_.clear();
    pending_object_map_updates_.clear();
    pending_spaceman_allocations_.clear();
    pending_spaceman_deallocations_.clear();
    pending_btree_records_.clear();
    canonical_commit_ready_ = CanReportCanonicalCommitReady(
        canonical_state_loaded_,
        commit_path_ready_,
        recovery_required_,
        legacy_fixture_fallback_used_);
    SyncCommitBlobTelemetryWithMode();
    return true;
}

bool MetadataStore::IsNativeWriteReady() const noexcept
{
    return native_write_ready_ && container_loaded_ && object_map_loaded_ && spaceman_loaded_;
}

bool MetadataStore::IsCommitPathReady() const noexcept
{
    return IsNativeWriteReady() && commit_path_ready_;
}

void MetadataStore::RefreshCanonicalGateState() const
{
    production_canonical_path_active_ = false;

    if (!canonical_state_loaded_)
    {
        last_canonical_gate_failure_ = L"CanonicalStateNotLoaded";
        return;
    }

    if (recovery_required_)
    {
        last_canonical_gate_failure_ = recovery_reason_.empty()
            ? std::wstring(L"RecoveryRequired")
            : recovery_reason_;
        return;
    }

    if (!native_write_ready_ || !IsNativeWriteReady())
    {
        last_canonical_gate_failure_ = L"NativeWriteNotReady";
        return;
    }

    if (!write_device_allowed_)
    {
        last_canonical_gate_failure_ = L"WriteDeviceNotAllowed";
        return;
    }

    if (!commit_path_ready_ || !IsCommitPathReady())
    {
        last_canonical_gate_failure_ = L"CommitPathNotReady";
        return;
    }

    if (legacy_fixture_fallback_used_)
    {
        last_canonical_gate_failure_ = L"FixtureLegacyFallbackActive";
        return;
    }

    if (uses_scaffold_commit_blob_)
    {
        last_canonical_gate_failure_ = L"ScaffoldCommitBlobActive";
        return;
    }

    if (!canonical_commit_ready_)
    {
        last_canonical_gate_failure_ = L"CanonicalCommitNotReady";
        return;
    }

    production_canonical_path_active_ = true;
    last_canonical_gate_failure_.clear();
}

bool MetadataStore::IsCanonicalCommitReady() const noexcept
{
    RefreshCanonicalGateState();
    return production_canonical_path_active_;
}

bool MetadataStore::IsProductionCanonicalPathActive() const noexcept
{
    RefreshCanonicalGateState();
    return production_canonical_path_active_;
}

std::wstring MetadataStore::LastCanonicalGateFailure() const
{
    RefreshCanonicalGateState();
    return last_canonical_gate_failure_;
}

std::string MetadataStore::LastCommitStage() const
{
    return last_commit_stage_;
}

std::string MetadataStore::LastReplayStage() const
{
    return last_replay_stage_;
}

std::string MetadataStore::LastCommitBlobMagic() const
{
    return last_commit_blob_magic_;
}

bool MetadataStore::LastReplayCheckpointCandidatePresent() const noexcept
{
    return last_replay_checkpoint_candidate_present_;
}

bool MetadataStore::LastReplayCheckpointPendingWindow() const noexcept
{
    return last_replay_checkpoint_pending_window_;
}

MetadataStore::NativeWriteCommitModel MetadataStore::ActiveCommitModel() const noexcept
{
    // Commit model reports the active commit-blob format, independent of
    // readiness. Readiness/canonical gate state is exposed separately.
    return uses_scaffold_commit_blob_
        ? NativeWriteCommitModel::ScaffoldCheckpoint
        : NativeWriteCommitModel::CanonicalApfsCheckpoint;
}

MetadataStore::NativeWriteValidationState MetadataStore::ValidationState() const noexcept
{
    if (!native_write_ready_ || recovery_required_)
    {
        return NativeWriteValidationState::Scaffold;
    }

    if (legacy_fixture_fallback_used_ || !canonical_state_loaded_)
    {
        return NativeWriteValidationState::Scaffold;
    }

    if (!IsLikelyRawDevicePath(context_.device_path))
    {
        return NativeWriteValidationState::CanonicalImageValidated;
    }

    if (context_.allow_raw_physical_write)
    {
        return NativeWriteValidationState::HardwarePilotValidated;
    }

    return NativeWriteValidationState::CanonicalImageValidated;
}

bool MetadataStore::IsFixtureLegacyFallbackActive() const noexcept
{
    return legacy_fixture_fallback_used_;
}

bool MetadataStore::IsFixtureCompatibilityPathActive() const noexcept
{
    // Fixture compatibility path activity is fixture-scoped. Non-fixture media can
    // still surface scaffold telemetry via UsesScaffoldCommitBlob(), but should not
    // be reported as "fixture compatibility path active".
    return legacy_fixture_fallback_used_ ||
           (uses_scaffold_commit_blob_ && IsLegacyFixtureFallbackAllowedForCurrentContext());
}

bool MetadataStore::UsesScaffoldCommitBlob() const noexcept
{
    return uses_scaffold_commit_blob_;
}

bool MetadataStore::IsRecoveryRequired() const noexcept
{
    return recovery_required_;
}

std::wstring MetadataStore::RecoveryReason() const
{
    return recovery_reason_;
}

MetadataStore::MutationStatus MetadataStore::StageMutation(const MutationRequest& request)
{
    return ApplyMutation(request);
}

void MetadataStore::MarkRecoveryRequired(std::wstring reason)
{
    recovery_required_ = true;
    recovery_reason_ = reason.empty() ? L"RecoveryRequired" : std::move(reason);
    commit_path_ready_ = false;
}

void MetadataStore::ClearRecoveryRequired()
{
    recovery_required_ = false;
    recovery_reason_.clear();
    commit_path_ready_ = native_write_ready_ && write_device_allowed_;
}

MetadataStore::MutationStatus MetadataStore::ApplyMutation(const MutationRequest& request)
{
    if (!IsNativeWriteReady())
    {
        return MutationStatus::NotReady;
    }
    const auto normalized_path = NormalizePath(request.path);
    if (normalized_path.empty())
    {
        return MutationStatus::InvalidRequest;
    }
    const auto normalized_secondary = NormalizePath(request.secondary_path);
    const auto target_xid = checkpoint_xid_ + 1;
    const auto working_inodes_snapshot = working_inodes_;
    const auto working_path_index_snapshot = working_path_index_;
    const auto working_directory_links_snapshot = working_directory_links_;
    const auto working_spaceman_free_extents_snapshot = working_spaceman_free_extents_;
    const auto pending_object_map_updates_snapshot = pending_object_map_updates_;
    const auto pending_spaceman_allocations_snapshot = pending_spaceman_allocations_;
    const auto pending_spaceman_deallocations_snapshot = pending_spaceman_deallocations_;
    const auto pending_btree_records_snapshot = pending_btree_records_;
    const auto working_next_ephemeral_extent_snapshot = working_next_ephemeral_extent_;
    bool mutation_applied = false;
    ScopeExit rollback_guard{
        [&]()
        {
            if (mutation_applied)
            {
                return;
            }

            working_inodes_ = working_inodes_snapshot;
            working_path_index_ = working_path_index_snapshot;
            working_directory_links_ = working_directory_links_snapshot;
            working_spaceman_free_extents_ = working_spaceman_free_extents_snapshot;
            pending_object_map_updates_ = pending_object_map_updates_snapshot;
            pending_spaceman_allocations_ = pending_spaceman_allocations_snapshot;
            pending_spaceman_deallocations_ = pending_spaceman_deallocations_snapshot;
            pending_btree_records_ = pending_btree_records_snapshot;
            working_next_ephemeral_extent_ = working_next_ephemeral_extent_snapshot;
        }};
    const auto stage_inode_record = [&](const InodeRecord& inode, bool tombstone)
    {
        pending_btree_records_.push_back(BtreeMutationCodec::EncodeInodeRecord(
            inode.object_id,
            inode.parent_object_id,
            inode.name,
            inode.is_directory,
            inode.logical_size,
            inode.data_physical_address,
            inode.timestamp_utc,
            inode.xid,
            tombstone));
    };
    const auto stage_directory_record = [&](std::uint64_t parent_object_id, const std::wstring& name, std::uint64_t child_object_id, bool tombstone)
    {
        pending_btree_records_.push_back(BtreeMutationCodec::EncodeDirectoryRecord(
            parent_object_id,
            name,
            child_object_id,
            target_xid,
            tombstone));
    };
    const auto stage_extent_record = [&](std::uint64_t object_id, std::uint64_t logical_offset, std::uint64_t physical_address, std::uint64_t extent_bytes, bool tombstone)
    {
        pending_btree_records_.push_back(BtreeMutationCodec::EncodeExtentRecord(
            object_id,
            logical_offset,
            physical_address,
            extent_bytes,
            target_xid,
            tombstone));
    };

    switch (request.operation)
    {
    case MutationOperation::CreateFile:
    case MutationOperation::CreateDirectory:
    {
        if (IsRootPath(normalized_path))
        {
            return MutationStatus::InvalidRequest;
        }

        const auto parent_path = ParentPath(normalized_path);
        const auto parent_inode = LookupWorkingInode(parent_path);
        if (!parent_inode.has_value() || !parent_inode->is_directory)
        {
            return MutationStatus::InvalidRequest;
        }

        const auto leaf_name = LeafName(normalized_path);
        if (leaf_name.empty())
        {
            return MutationStatus::InvalidRequest;
        }

        auto existing = LookupWorkingInode(normalized_path);
        std::optional<std::uint64_t> replacement_id;
        if (existing.has_value())
        {
            if (!request.replace_if_exists)
            {
                return MutationStatus::InvalidRequest;
            }
            if (existing->is_directory != (request.operation == MutationOperation::CreateDirectory))
            {
                return MutationStatus::InvalidRequest;
            }
            if (existing->is_directory && HasWorkingChildren(existing->object_id))
            {
                return MutationStatus::InvalidRequest;
            }

            replacement_id = existing->object_id;
            RemoveWorkingDirectoryLink(existing->parent_object_id, existing->name);
            working_path_index_.erase(CanonicalPathKey(normalized_path));
            working_inodes_.erase(existing->object_id);
            stage_directory_record(existing->parent_object_id, existing->name, existing->object_id, true);
            if (!existing->is_directory && existing->data_physical_address != 0 && existing->logical_size > 0)
            {
                if (!StageSpacemanDeallocation(existing->data_physical_address, existing->logical_size))
                {
                    return MutationStatus::AllocationFailed;
                }
                stage_extent_record(existing->object_id, 0, existing->data_physical_address, existing->logical_size, true);
            }
            stage_inode_record(*existing, true);
            if (!StageObjectMapUpdate(existing->object_id, 0, 0))
            {
                return MutationStatus::AllocationFailed;
            }
        }

        InodeRecord inode{};
        inode.object_id = replacement_id.value_or(ResolveUniqueObjectId(normalized_path));
        inode.parent_object_id = parent_inode->object_id;
        inode.name = leaf_name;
        inode.full_path = normalized_path;
        inode.is_directory = request.operation == MutationOperation::CreateDirectory;
        inode.logical_size = 0;
        inode.data_physical_address = 0;
        inode.xid = target_xid;

        working_inodes_[inode.object_id] = inode;
        working_path_index_[CanonicalPathKey(inode.full_path)] = inode.object_id;
        UpsertWorkingDirectoryLink(inode.parent_object_id, inode.name, inode.object_id, target_xid);

        if (!StageObjectMapUpdate(inode.object_id, inode.data_physical_address, inode.logical_size))
        {
            return MutationStatus::AllocationFailed;
        }
        stage_inode_record(inode, false);
        stage_directory_record(inode.parent_object_id, inode.name, inode.object_id, false);
        break;
    }
    case MutationOperation::Write:
    {
        if (request.length == 0)
        {
            break;
        }
        auto inode = LookupWorkingInode(normalized_path);
        if (!inode.has_value() || inode->is_directory)
        {
            return MutationStatus::InvalidRequest;
        }

        if (request.offset > (std::numeric_limits<std::uint64_t>::max() - request.length))
        {
            return MutationStatus::InvalidRequest;
        }

        const auto requested_end = request.offset + request.length;
        const auto target_logical_size = std::max<std::uint64_t>(inode->logical_size, requested_end);
        auto extent = AllocateExtent(target_logical_size);
        if (!extent.has_value())
        {
            return MutationStatus::AllocationFailed;
        }

        if (!StageSpacemanAllocation(*extent, target_logical_size))
        {
            return MutationStatus::AllocationFailed;
        }

        auto& inode_ref = working_inodes_[inode->object_id];
        const auto previous_physical = inode_ref.data_physical_address;
        const auto previous_size = inode_ref.logical_size;
        inode_ref.data_physical_address = *extent;
        inode_ref.logical_size = target_logical_size;
        inode_ref.xid = target_xid;
        if (!StageObjectMapUpdate(inode_ref.object_id, inode_ref.data_physical_address, inode_ref.logical_size))
        {
            return MutationStatus::AllocationFailed;
        }
        if (previous_physical != 0 && previous_physical != inode_ref.data_physical_address && previous_size > 0)
        {
            if (!StageSpacemanDeallocation(previous_physical, previous_size))
            {
                return MutationStatus::AllocationFailed;
            }
            stage_extent_record(inode_ref.object_id, 0, previous_physical, previous_size, true);
        }
        stage_extent_record(inode_ref.object_id, 0, inode_ref.data_physical_address, inode_ref.logical_size, false);
        stage_inode_record(inode_ref, false);
        break;
    }
    case MutationOperation::SetFileSize:
    {
        auto inode = LookupWorkingInode(normalized_path);
        if (!inode.has_value() || inode->is_directory)
        {
            return MutationStatus::InvalidRequest;
        }

        auto& inode_ref = working_inodes_[inode->object_id];
        const auto previous_physical = inode_ref.data_physical_address;
        const auto previous_size = inode_ref.logical_size;
        if (request.length == 0)
        {
            if (previous_physical != 0 && previous_size > 0)
            {
                if (!StageSpacemanDeallocation(previous_physical, previous_size))
                {
                    return MutationStatus::AllocationFailed;
                }
                stage_extent_record(inode_ref.object_id, 0, previous_physical, previous_size, true);
            }
            inode_ref.data_physical_address = 0;
        }
        else
        {
            auto extent = AllocateExtent(request.length);
            if (!extent.has_value())
            {
                return MutationStatus::AllocationFailed;
            }
            if (!StageSpacemanAllocation(*extent, request.length))
            {
                return MutationStatus::AllocationFailed;
            }

            if (previous_physical != 0 &&
                previous_size > 0 &&
                previous_physical != *extent)
            {
                if (!StageSpacemanDeallocation(previous_physical, previous_size))
                {
                    return MutationStatus::AllocationFailed;
                }
                stage_extent_record(inode_ref.object_id, 0, previous_physical, previous_size, true);
            }

            inode_ref.data_physical_address = *extent;
            stage_extent_record(inode_ref.object_id, 0, inode_ref.data_physical_address, request.length, false);
        }
        inode_ref.logical_size = request.length;
        inode_ref.xid = target_xid;
        if (!StageObjectMapUpdate(inode_ref.object_id, inode_ref.data_physical_address, inode_ref.logical_size))
        {
            return MutationStatus::AllocationFailed;
        }
        stage_inode_record(inode_ref, false);
        break;
    }
    case MutationOperation::Rename:
    {
        if (normalized_secondary.empty() || IsRootPath(normalized_path))
        {
            return MutationStatus::InvalidRequest;
        }

        auto inode = LookupWorkingInode(normalized_path);
        if (!inode.has_value())
        {
            return MutationStatus::InvalidRequest;
        }
        const auto source_path_key = CanonicalPathKey(normalized_path);
        const auto destination_path_key = CanonicalPathKey(normalized_secondary);

        const auto destination_parent_path = ParentPath(normalized_secondary);
        const auto destination_parent = LookupWorkingInode(destination_parent_path);
        if (!destination_parent.has_value() || !destination_parent->is_directory)
        {
            return MutationStatus::InvalidRequest;
        }
        if (LeafName(normalized_secondary).empty())
        {
            return MutationStatus::InvalidRequest;
        }
        if (inode->is_directory &&
            (IsDescendantPath(destination_parent_path, normalized_path) ||
             CanonicalPathKey(destination_parent_path) == CanonicalPathKey(normalized_path)))
        {
            return MutationStatus::InvalidRequest;
        }

        auto destination_inode = LookupWorkingInode(normalized_secondary);
        const auto destination_is_same_object = destination_inode.has_value() &&
                                                destination_inode->object_id == inode->object_id;
        if (destination_is_same_object &&
            source_path_key == destination_path_key &&
            normalized_secondary == normalized_path)
        {
            // No-op rename request.
            return MutationStatus::Applied;
        }
        if (destination_inode.has_value())
        {
            if (!destination_is_same_object && !request.replace_if_exists)
            {
                return MutationStatus::InvalidRequest;
            }
            if (!destination_is_same_object &&
                destination_inode->is_directory != inode->is_directory)
            {
                return MutationStatus::InvalidRequest;
            }
            if (!destination_is_same_object &&
                destination_inode->is_directory && HasWorkingChildren(destination_inode->object_id))
            {
                return MutationStatus::InvalidRequest;
            }
            if (!destination_is_same_object)
            {
                RemoveWorkingDirectoryLink(destination_inode->parent_object_id, destination_inode->name);
                working_path_index_.erase(CanonicalPathKey(normalized_secondary));
                working_inodes_.erase(destination_inode->object_id);
                stage_directory_record(destination_inode->parent_object_id, destination_inode->name, destination_inode->object_id, true);
                if (!destination_inode->is_directory &&
                    destination_inode->data_physical_address != 0 &&
                    destination_inode->logical_size > 0)
                {
                    if (!StageSpacemanDeallocation(destination_inode->data_physical_address, destination_inode->logical_size))
                    {
                        return MutationStatus::AllocationFailed;
                    }
                    stage_extent_record(
                        destination_inode->object_id,
                        0,
                        destination_inode->data_physical_address,
                        destination_inode->logical_size,
                        true);
                }
                stage_inode_record(*destination_inode, true);
                if (!StageObjectMapUpdate(destination_inode->object_id, 0, 0))
                {
                    return MutationStatus::AllocationFailed;
                }
            }
        }

        const auto source_prefix = IsRootPath(normalized_path) ? normalized_path : normalized_path + L"\\";
        const auto source_prefix_key = CanonicalPathKey(source_prefix);
        std::vector<std::pair<std::wstring, std::wstring>> descendant_renames;
        if (inode->is_directory)
        {
            descendant_renames.reserve(working_inodes_.size());
            for (const auto& [object_id, child_inode] : working_inodes_)
            {
                if (object_id == inode->object_id)
                {
                    continue;
                }

                const auto child_path = child_inode.full_path;
                const auto child_path_key = CanonicalPathKey(child_path);
                if (child_path_key.rfind(source_prefix_key, 0) == 0 &&
                    child_path.size() >= source_prefix.size())
                {
                    descendant_renames.emplace_back(
                        child_path,
                        normalized_secondary + L"\\" + child_path.substr(source_prefix.size()));
                }
            }
            std::sort(descendant_renames.begin(), descendant_renames.end(), [](const auto& lhs, const auto& rhs)
            {
                return lhs.first.size() < rhs.first.size();
            });
        }

        const auto old_path = inode->full_path;
        const auto old_parent_object_id = inode->parent_object_id;
        const auto old_name = inode->name;
        RemoveWorkingDirectoryLink(inode->parent_object_id, inode->name);
        working_path_index_.erase(CanonicalPathKey(old_path));
        stage_directory_record(old_parent_object_id, old_name, inode->object_id, true);

        auto& inode_ref = working_inodes_[inode->object_id];
        inode_ref.parent_object_id = destination_parent->object_id;
        inode_ref.name = LeafName(normalized_secondary);
        inode_ref.full_path = normalized_secondary;
        inode_ref.xid = target_xid;
        working_path_index_[CanonicalPathKey(inode_ref.full_path)] = inode_ref.object_id;
        UpsertWorkingDirectoryLink(inode_ref.parent_object_id, inode_ref.name, inode_ref.object_id, target_xid);
        stage_directory_record(inode_ref.parent_object_id, inode_ref.name, inode_ref.object_id, false);
        stage_inode_record(inode_ref, false);

        for (const auto& [old_descendant_path, new_descendant_path] : descendant_renames)
        {
            auto descendant_it = working_path_index_.find(CanonicalPathKey(old_descendant_path));
            if (descendant_it == working_path_index_.end())
            {
                continue;
            }
            const auto descendant_object_id = descendant_it->second;
            working_path_index_.erase(descendant_it);
            auto& descendant_inode = working_inodes_[descendant_object_id];
            const auto descendant_old_parent_object_id = descendant_inode.parent_object_id;
            const auto descendant_old_name = descendant_inode.name;
            const auto new_parent_path = ParentPath(new_descendant_path);
            descendant_inode.full_path = new_descendant_path;
            descendant_inode.name = LeafName(new_descendant_path);
            if (new_parent_path == inode_ref.full_path)
            {
                descendant_inode.parent_object_id = inode_ref.object_id;
            }
            else if (auto parent_it = working_path_index_.find(CanonicalPathKey(new_parent_path)); parent_it != working_path_index_.end())
            {
                descendant_inode.parent_object_id = parent_it->second;
            }
            descendant_inode.xid = target_xid;
            working_path_index_[CanonicalPathKey(new_descendant_path)] = descendant_object_id;
            RemoveWorkingDirectoryLink(descendant_old_parent_object_id, descendant_old_name);
            stage_directory_record(descendant_old_parent_object_id, descendant_old_name, descendant_object_id, true);
            UpsertWorkingDirectoryLink(descendant_inode.parent_object_id, descendant_inode.name, descendant_object_id, target_xid);
            stage_directory_record(descendant_inode.parent_object_id, descendant_inode.name, descendant_object_id, false);
            if (!StageObjectMapUpdate(
                    descendant_inode.object_id,
                    descendant_inode.data_physical_address,
                    descendant_inode.logical_size))
            {
                return MutationStatus::AllocationFailed;
            }
            stage_inode_record(descendant_inode, false);
        }

        if (!StageObjectMapUpdate(inode_ref.object_id, inode_ref.data_physical_address, inode_ref.logical_size))
        {
            return MutationStatus::AllocationFailed;
        }
        break;
    }
    case MutationOperation::Delete:
    {
        if (IsRootPath(normalized_path))
        {
            return MutationStatus::InvalidRequest;
        }

        auto inode = LookupWorkingInode(normalized_path);
        if (!inode.has_value())
        {
            return MutationStatus::InvalidRequest;
        }
        if (inode->is_directory && HasWorkingChildren(inode->object_id))
        {
            return MutationStatus::InvalidRequest;
        }

        RemoveWorkingDirectoryLink(inode->parent_object_id, inode->name);
        working_path_index_.erase(CanonicalPathKey(normalized_path));
        working_inodes_.erase(inode->object_id);
        stage_directory_record(inode->parent_object_id, inode->name, inode->object_id, true);
        if (!inode->is_directory && inode->data_physical_address != 0 && inode->logical_size > 0)
        {
            if (!StageSpacemanDeallocation(inode->data_physical_address, inode->logical_size))
            {
                return MutationStatus::AllocationFailed;
            }
            stage_extent_record(inode->object_id, 0, inode->data_physical_address, inode->logical_size, true);
        }
        stage_inode_record(*inode, true);

        if (!StageObjectMapUpdate(inode->object_id, 0, 0))
        {
            return MutationStatus::AllocationFailed;
        }
        break;
    }
    case MutationOperation::SetBasicInfo:
    {
        auto inode = LookupWorkingInode(normalized_path);
        if (!inode.has_value())
        {
            return MutationStatus::InvalidRequest;
        }

        auto& inode_ref = working_inodes_[inode->object_id];
        inode_ref.xid = target_xid;
        inode_ref.timestamp_utc = request.timestamp_utc;
        if (!StageObjectMapUpdate(inode_ref.object_id, inode_ref.data_physical_address, inode_ref.logical_size))
        {
            return MutationStatus::AllocationFailed;
        }
        stage_inode_record(inode_ref, false);
        break;
    }
    default:
        return MutationStatus::UnsupportedOperation;
    }

    pending_mutations_.push_back(request);
    mutation_applied = true;
    return MutationStatus::Applied;
}

MetadataStore::CommitStatus MetadataStore::CommitPendingMutations()
{
    last_commit_stage_ = "start";
    const auto fail_commit = [this](CommitStatus status, std::string_view stage) -> CommitStatus
    {
        if (!stage.empty())
        {
            last_commit_stage_ = std::string(stage);
        }
        return status;
    };

    if (!IsNativeWriteReady())
    {
        return fail_commit(CommitStatus::NotReady, "not-ready");
    }

    if (pending_mutations_.empty())
    {
        return fail_commit(CommitStatus::NothingToCommit, "nothing-to-commit");
    }

    if (!commit_path_ready_ || !write_device_allowed_)
    {
        return fail_commit(CommitStatus::NotWritable, "not-writable");
    }
    if (!AllowCommitStage("before-preflight"))
    {
        return fail_commit(CommitStatus::InvariantFailed, "preflight-stage-blocked");
    }
    if (!ValidatePendingCommitState())
    {
        return fail_commit(CommitStatus::InvariantFailed, "preflight-validation-failed");
    }

    const auto target_xid = checkpoint_xid_ + 1;
    auto commit_blob = BuildCommitBlob(target_xid);
    if (commit_blob.empty())
    {
        return fail_commit(CommitStatus::PersistFailed, "commit-blob-build-failed");
    }
    const auto commit_blob_persist_bytes = AlignExtentBytes(static_cast<std::uint64_t>(commit_blob.size()));
    if (commit_blob_persist_bytes == 0 ||
        commit_blob_persist_bytes < static_cast<std::uint64_t>(commit_blob.size()) ||
        commit_blob_persist_bytes > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
    {
        return fail_commit(CommitStatus::PersistFailed, "commit-blob-alignment-invalid");
    }
    if (static_cast<std::size_t>(commit_blob_persist_bytes) > commit_blob.size())
    {
        commit_blob.resize(static_cast<std::size_t>(commit_blob_persist_bytes), std::byte{0});
    }

    const auto working_free_extents_snapshot = working_spaceman_free_extents_;
    const auto working_next_extent_snapshot = working_next_ephemeral_extent_;
    auto commit_extent = AllocateExtent(commit_blob_persist_bytes);
    if (!commit_extent.has_value())
    {
        return fail_commit(CommitStatus::AllocationFailed, "commit-extent-allocate-failed");
    }
    if (!StageSpacemanAllocation(*commit_extent, commit_blob_persist_bytes))
    {
        working_spaceman_free_extents_ = working_free_extents_snapshot;
        working_next_ephemeral_extent_ = working_next_extent_snapshot;
        return fail_commit(CommitStatus::AllocationFailed, "commit-extent-stage-allocation-failed");
    }
    const auto rollback_commit_extent_stage = [&]()
    {
        if (!pending_spaceman_allocations_.empty() &&
            pending_spaceman_allocations_.back().physical_address == *commit_extent)
        {
            pending_spaceman_allocations_.pop_back();
        }
        working_spaceman_free_extents_ = working_free_extents_snapshot;
        working_next_ephemeral_extent_ = working_next_extent_snapshot;
    };
    if (!ValidatePendingCommitState())
    {
        rollback_commit_extent_stage();
        return fail_commit(CommitStatus::InvariantFailed, "post-allocation-preflight-failed");
    }

    struct PendingPayloadWrite
    {
        std::uint64_t physical_address = 0;
        std::vector<std::byte> bytes;
    };

    std::unordered_set<std::wstring> payload_paths;
    payload_paths.reserve(pending_mutations_.size());
    for (const auto& mutation : pending_mutations_)
    {
        const auto normalized_path = NormalizePath(mutation.path);
        const auto normalized_key = CanonicalPathKey(normalized_path);
        switch (mutation.operation)
        {
        case MutationOperation::Write:
            if (mutation.length > 0)
            {
                payload_paths.insert(normalized_key);
            }
            break;
        case MutationOperation::SetFileSize:
            if (mutation.length > 0)
            {
                payload_paths.insert(normalized_key);
            }
            else
            {
                payload_paths.erase(normalized_key);
            }
            break;
        case MutationOperation::Rename:
        {
            const auto normalized_secondary = NormalizePath(mutation.secondary_path);
            const auto normalized_secondary_key = CanonicalPathKey(normalized_secondary);
            if (auto pending = payload_paths.find(normalized_key); pending != payload_paths.end())
            {
                payload_paths.erase(pending);
                if (!normalized_secondary_key.empty())
                {
                    payload_paths.insert(normalized_secondary_key);
                }
            }
            break;
        }
        case MutationOperation::Delete:
            payload_paths.erase(normalized_key);
            break;
        default:
            break;
        }
    }

    std::vector<PendingPayloadWrite> pending_payload_writes;
    pending_payload_writes.reserve(payload_paths.size());
    for (const auto& payload_path : payload_paths)
    {
        auto inode = LookupWorkingInode(payload_path);
        if (!inode.has_value() ||
            inode->is_directory ||
            inode->data_physical_address == 0 ||
            inode->logical_size == 0)
        {
            continue;
        }

        if (inode->logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
        {
            rollback_commit_extent_stage();
            return fail_commit(CommitStatus::PersistFailed, "payload-size-overflow");
        }

        if (!file_payload_provider_)
        {
            rollback_commit_extent_stage();
            return fail_commit(CommitStatus::PersistFailed, "payload-provider-missing");
        }

        auto resolved = file_payload_provider_(inode->full_path, inode->logical_size);
        if (!resolved.has_value())
        {
            rollback_commit_extent_stage();
            return fail_commit(CommitStatus::PersistFailed, "payload-provider-unresolved");
        }
        auto payload_bytes = std::move(resolved.value());

        const auto logical_size = static_cast<std::size_t>(inode->logical_size);
        if (payload_bytes.size() < logical_size)
        {
            payload_bytes.resize(logical_size, std::byte{0});
        }
        else if (payload_bytes.size() > logical_size)
        {
            payload_bytes.resize(logical_size);
        }

        pending_payload_writes.push_back(PendingPayloadWrite
        {
            inode->data_physical_address,
            std::move(payload_bytes),
        });
    }

    if (!AllowCommitStage("before-device-write"))
    {
        rollback_commit_extent_stage();
        return CommitStatus::PersistFailed;
    }

    for (const auto& payload_write : pending_payload_writes)
    {
        if (!device_.Write(payload_write.physical_address, payload_write.bytes))
        {
            rollback_commit_extent_stage();
            return fail_commit(CommitStatus::PersistFailed, "payload-device-write-failed");
        }
    }

    if (!device_.Write(*commit_extent, commit_blob))
    {
        rollback_commit_extent_stage();
        return fail_commit(CommitStatus::PersistFailed, "commit-blob-device-write-failed");
    }
    if (!AllowCommitStage("before-device-flush"))
    {
        rollback_commit_extent_stage();
        return CommitStatus::FlushFailed;
    }
    if (!device_.Flush())
    {
        rollback_commit_extent_stage();
        return fail_commit(CommitStatus::FlushFailed, "device-flush-failed");
    }

    auto committed_object_map_snapshot = committed_object_map_;
    auto committed_allocations_snapshot = committed_spaceman_allocations_;
    auto committed_free_extents_snapshot = committed_spaceman_free_extents_;
    auto committed_inodes_snapshot = committed_inodes_;
    auto committed_path_index_snapshot = committed_path_index_;
    auto committed_directory_links_snapshot = committed_directory_links_;
    auto committed_btree_snapshot = committed_btree_records_;
    auto last_commit_blob_snapshot = last_commit_blob_address_;
    auto last_commit_blob_bytes_snapshot = last_commit_blob_bytes_;
    auto checkpoint_xid_snapshot = checkpoint_xid_;
    auto last_committed_xid_snapshot = last_committed_xid_;
    const auto rollback_committed_state = [&]()
    {
        committed_object_map_ = committed_object_map_snapshot;
        committed_spaceman_allocations_ = committed_allocations_snapshot;
        committed_spaceman_free_extents_ = committed_free_extents_snapshot;
        committed_inodes_ = committed_inodes_snapshot;
        committed_path_index_ = committed_path_index_snapshot;
        committed_directory_links_ = committed_directory_links_snapshot;
        committed_btree_records_ = committed_btree_snapshot;
        last_commit_blob_address_ = last_commit_blob_snapshot;
        last_commit_blob_bytes_ = last_commit_blob_bytes_snapshot;
        checkpoint_xid_ = checkpoint_xid_snapshot;
        last_committed_xid_ = last_committed_xid_snapshot;
        next_ephemeral_extent_ = working_next_extent_snapshot;
    };

    for (const auto& update : pending_object_map_updates_)
    {
        committed_object_map_[update.object_id] = update;
    }
    committed_spaceman_allocations_.insert(
        committed_spaceman_allocations_.end(),
        pending_spaceman_allocations_.begin(),
        pending_spaceman_allocations_.end()
    );
    for (const auto& deallocation : pending_spaceman_deallocations_)
    {
        committed_spaceman_allocations_.erase(
            std::remove_if(
                committed_spaceman_allocations_.begin(),
                committed_spaceman_allocations_.end(),
                [&](const SpacemanAllocation& allocation)
                {
                    return allocation.physical_address == deallocation.physical_address &&
                           allocation.bytes == deallocation.bytes;
                }),
            committed_spaceman_allocations_.end());
        if (!FreeExtent(deallocation.physical_address, deallocation.bytes))
        {
            rollback_commit_extent_stage();
            rollback_committed_state();
            return fail_commit(CommitStatus::AllocationFailed, "deallocation-free-extent-failed");
        }
    }
    committed_inodes_ = working_inodes_;
    committed_path_index_ = working_path_index_;
    committed_directory_links_ = working_directory_links_;
    auto merged_btree_records = committed_btree_records_;
    merged_btree_records.insert(
        merged_btree_records.end(),
        pending_btree_records_.begin(),
        pending_btree_records_.end());
    committed_btree_records_ = CanonicalizeBtreeRecords(merged_btree_records);
    committed_spaceman_free_extents_ = working_spaceman_free_extents_;
    next_ephemeral_extent_ = working_next_ephemeral_extent_;

    checkpoint_xid_ = target_xid;
    last_committed_xid_ = target_xid;
    last_commit_blob_address_ = *commit_extent;
    last_commit_blob_bytes_ = commit_blob_persist_bytes;
    const auto verify_object_map_checkpoint_roundtrip = [&]() -> bool
    {
        auto checkpoint_blocks = ResolveObjectMapCheckpointBlockIndices();
        if (checkpoint_blocks.empty())
        {
            return false;
        }
        const auto checkpoint_slot = checkpoint_blocks[
            static_cast<std::size_t>(target_xid % static_cast<std::uint64_t>(checkpoint_blocks.size()))];

        std::vector<std::byte> checkpoint_block;
        if (!ReadBlockByIndexDirect(checkpoint_slot, checkpoint_block))
        {
            return false;
        }

        ApfsObjectMapStore parser;
        std::vector<ApfsObjectMapEntry> parsed_entries;
        std::uint64_t parsed_xid = 0;
        if (!parser.TryParseCheckpointV3(checkpoint_block, parsed_entries, parsed_xid) ||
            parsed_xid != target_xid ||
            parsed_entries.size() != committed_object_map_.size())
        {
            return false;
        }

        for (const auto& entry : parsed_entries)
        {
            auto expected = committed_object_map_.find(entry.object_id);
            if (expected == committed_object_map_.end())
            {
                return false;
            }
            if (expected->second.physical_address != entry.physical_address ||
                expected->second.logical_size != entry.logical_size ||
                expected->second.xid != entry.xid)
            {
                return false;
            }
        }

        return true;
    };
    const auto verify_spaceman_checkpoint_roundtrip = [&]() -> bool
    {
        auto checkpoint_blocks = ResolveSpacemanCheckpointBlockIndices();
        if (checkpoint_blocks.empty())
        {
            return false;
        }
        const auto checkpoint_slot = checkpoint_blocks[
            static_cast<std::size_t>(target_xid % static_cast<std::uint64_t>(checkpoint_blocks.size()))];

        std::vector<std::byte> checkpoint_block;
        if (!ReadBlockByIndexDirect(checkpoint_slot, checkpoint_block))
        {
            return false;
        }

        ApfsSpacemanStore parser;
        std::vector<ApfsExtent> parsed_allocations;
        std::vector<ApfsExtent> parsed_free_extents;
        std::uint64_t parsed_xid = 0;
        if (!parser.TryParseCheckpointV3(
                checkpoint_block,
                parsed_allocations,
                parsed_free_extents,
                parsed_xid) ||
            parsed_xid != target_xid)
        {
            return false;
        }

        const auto normalize_spaceman = [](const std::vector<SpacemanAllocation>& extents)
        {
            std::vector<std::pair<std::uint64_t, std::uint64_t>> normalized;
            normalized.reserve(extents.size());
            for (const auto& extent : extents)
            {
                normalized.emplace_back(extent.physical_address, extent.bytes);
            }
            std::sort(normalized.begin(), normalized.end());
            return normalized;
        };
        const auto normalize_parsed = [](const std::vector<ApfsExtent>& extents)
        {
            std::vector<std::pair<std::uint64_t, std::uint64_t>> normalized;
            normalized.reserve(extents.size());
            for (const auto& extent : extents)
            {
                normalized.emplace_back(extent.physical_address, extent.bytes);
            }
            std::sort(normalized.begin(), normalized.end());
            return normalized;
        };

        return normalize_spaceman(committed_spaceman_allocations_) == normalize_parsed(parsed_allocations) &&
               normalize_spaceman(committed_spaceman_free_extents_) == normalize_parsed(parsed_free_extents);
    };
    const auto verify_inode_checkpoint_roundtrip = [&]() -> bool
    {
        auto checkpoint_blocks = ResolveInodeCheckpointBlockIndices();
        if (checkpoint_blocks.empty())
        {
            return false;
        }
        const auto checkpoint_slot = checkpoint_blocks[
            static_cast<std::size_t>(target_xid % static_cast<std::uint64_t>(checkpoint_blocks.size()))];

        std::vector<std::byte> checkpoint_block;
        if (!ReadBlockByIndexDirect(checkpoint_slot, checkpoint_block))
        {
            return false;
        }

        if (checkpoint_block.size() < kCheckpointHeaderBytes)
        {
            return false;
        }
        if (ReadLe64(checkpoint_block, 12) != target_xid)
        {
            return false;
        }

        const auto committed_inodes_snapshot = committed_inodes_;
        const auto committed_path_index_snapshot = committed_path_index_;
        const auto committed_directory_links_snapshot = committed_directory_links_;
        const auto working_inodes_snapshot = working_inodes_;
        const auto working_path_index_snapshot = working_path_index_;
        const auto working_directory_links_snapshot = working_directory_links_;
        const auto last_committed_xid_snapshot = last_committed_xid_;

        const auto restore_state = [&]()
        {
            committed_inodes_ = committed_inodes_snapshot;
            committed_path_index_ = committed_path_index_snapshot;
            committed_directory_links_ = committed_directory_links_snapshot;
            working_inodes_ = working_inodes_snapshot;
            working_path_index_ = working_path_index_snapshot;
            working_directory_links_ = working_directory_links_snapshot;
            last_committed_xid_ = last_committed_xid_snapshot;
        };

        if (!LoadInodeCheckpointBlock(checkpoint_slot, checkpoint_block))
        {
            restore_state();
            return false;
        }

        const auto normalize_directory_links = [](const std::vector<DirectoryLink>& links)
        {
            std::vector<std::wstring> normalized;
            normalized.reserve(links.size());
            for (const auto& link : links)
            {
                std::wstring entry = std::to_wstring(link.parent_object_id);
                entry.push_back(L'\x1f');
                entry.append(link.entry_name);
                entry.push_back(L'\x1f');
                entry.append(std::to_wstring(link.child_object_id));
                normalized.push_back(std::move(entry));
            }
            std::sort(normalized.begin(), normalized.end());
            return normalized;
        };

        const auto same_inodes = [](
            const std::unordered_map<std::uint64_t, InodeRecord>& lhs,
            const std::unordered_map<std::uint64_t, InodeRecord>& rhs) -> bool
        {
            if (lhs.size() != rhs.size())
            {
                return false;
            }
            for (const auto& [object_id, inode] : lhs)
            {
                auto other = rhs.find(object_id);
                if (other == rhs.end())
                {
                    return false;
                }
                const auto& rhs_inode = other->second;
                if (inode.object_id != rhs_inode.object_id ||
                    inode.parent_object_id != rhs_inode.parent_object_id ||
                    inode.name != rhs_inode.name ||
                    inode.full_path != rhs_inode.full_path ||
                    inode.is_directory != rhs_inode.is_directory ||
                    inode.logical_size != rhs_inode.logical_size ||
                    inode.data_physical_address != rhs_inode.data_physical_address ||
                    inode.xid != rhs_inode.xid)
                {
                    return false;
                }
            }
            return true;
        };

        const auto matches =
            same_inodes(committed_inodes_, committed_inodes_snapshot) &&
            committed_path_index_ == committed_path_index_snapshot &&
            normalize_directory_links(committed_directory_links_) == normalize_directory_links(committed_directory_links_snapshot) &&
            last_committed_xid_.value_or(0) == target_xid;

        restore_state();
        return matches;
    };
    const auto verify_btree_checkpoint_roundtrip = [&]() -> bool
    {
        auto checkpoint_blocks = ResolveBtreeCheckpointBlockIndices();
        if (checkpoint_blocks.empty())
        {
            return false;
        }
        const auto checkpoint_slot = checkpoint_blocks[
            static_cast<std::size_t>(target_xid % static_cast<std::uint64_t>(checkpoint_blocks.size()))];

        std::vector<std::byte> checkpoint_block;
        if (!ReadBlockByIndexDirect(checkpoint_slot, checkpoint_block))
        {
            return false;
        }

        if (checkpoint_block.size() < kCheckpointHeaderBytes)
        {
            return false;
        }
        if (ReadLe64(checkpoint_block, 12) != target_xid)
        {
            return false;
        }

        const auto committed_btree_snapshot = committed_btree_records_;
        const auto last_committed_xid_snapshot = last_committed_xid_;

        const auto restore_state = [&]()
        {
            committed_btree_records_ = committed_btree_snapshot;
            last_committed_xid_ = last_committed_xid_snapshot;
        };

        if (!LoadBtreeCheckpointBlock(checkpoint_slot, checkpoint_block))
        {
            restore_state();
            return false;
        }

        const auto same_btree_records = [](
            const std::vector<BtreeRecord>& lhs,
            const std::vector<BtreeRecord>& rhs) -> bool
        {
            if (lhs.size() != rhs.size())
            {
                return false;
            }

            for (std::size_t index = 0; index < lhs.size(); ++index)
            {
                const auto& left = lhs[index];
                const auto& right = rhs[index];
                if (left.kind != right.kind ||
                    left.tombstone != right.tombstone ||
                    left.key != right.key ||
                    left.value != right.value)
                {
                    return false;
                }
            }
            return true;
        };

        const auto matches =
            same_btree_records(committed_btree_records_, committed_btree_snapshot) &&
            last_committed_xid_.value_or(0) == target_xid;
        restore_state();
        return matches;
    };
    const auto verify_replay_checkpoint_roundtrip = [&]() -> bool
    {
        auto checkpoint_blocks = ResolveReplayCheckpointBlockIndices();
        if (checkpoint_blocks.empty() ||
            !last_commit_blob_address_.has_value() ||
            !last_commit_blob_bytes_.has_value())
        {
            return false;
        }

        const auto expected_source_xid = target_xid - 1;
        const auto expected_commit_blob_address = last_commit_blob_address_.value();
        const auto expected_commit_blob_bytes = last_commit_blob_bytes_.value();
        if (expected_commit_blob_address == 0 || expected_commit_blob_bytes == 0)
        {
            return false;
        }

        const auto checkpoint_slot = checkpoint_blocks[
            static_cast<std::size_t>(target_xid % static_cast<std::uint64_t>(checkpoint_blocks.size()))];

        std::vector<std::byte> checkpoint_block;
        if (!ReadBlockByIndexDirect(checkpoint_slot, checkpoint_block))
        {
            return false;
        }

        std::uint64_t parsed_target_xid = 0;
        std::uint64_t parsed_source_xid = 0;
        std::uint64_t parsed_commit_blob_address = 0;
        std::uint64_t parsed_commit_blob_bytes = 0;
        if (!LoadReplayCheckpointBlock(
                checkpoint_slot,
                checkpoint_block,
                parsed_target_xid,
                parsed_source_xid,
                parsed_commit_blob_address,
                parsed_commit_blob_bytes))
        {
            return false;
        }

        if (parsed_target_xid != target_xid ||
            parsed_source_xid != expected_source_xid ||
            parsed_commit_blob_address != expected_commit_blob_address ||
            parsed_commit_blob_bytes != expected_commit_blob_bytes)
        {
            return false;
        }

        return ValidateReplayCommitBlobCandidate(
            parsed_commit_blob_address,
            parsed_commit_blob_bytes,
            parsed_source_xid,
            parsed_target_xid);
    };
    const auto verify_superblock_checkpoint_roundtrip = [&]() -> bool
    {
        if (!container_loaded_ || block_size_ == 0)
        {
            return false;
        }

        constexpr std::size_t kSuperblockBytes = 0x570;
        constexpr std::size_t kMagicOffset = 0x20;
        constexpr std::size_t kBlockSizeOffset = 0x24;
        constexpr std::size_t kCheckpointXidOffset = 0x10;
        constexpr std::uint32_t kNxsbMagic = 0x4253584E; // 'NXSB'

        if (active_superblock_offset_ > (std::numeric_limits<std::uint64_t>::max() - kSuperblockBytes))
        {
            return false;
        }

        std::vector<std::byte> superblock;
        if (!device_.Read(active_superblock_offset_, kSuperblockBytes, superblock) ||
            superblock.size() < kSuperblockBytes)
        {
            return false;
        }

        return ReadLe32(superblock, kMagicOffset) == kNxsbMagic &&
               ReadLe32(superblock, kBlockSizeOffset) == block_size_ &&
               ReadLe64(superblock, kCheckpointXidOffset) == target_xid;
    };

    if (!AllowCommitStage("before-object-map-persist"))
    {
        MarkRecoveryRequired(L"CommitInterruptedBeforeObjectMapPersist");
        return CommitStatus::PersistFailed;
    }
    if (!PersistObjectMapCheckpoint(target_xid))
    {
        MarkRecoveryRequired(L"CommitObjectMapPersistFailed");
        return CommitStatus::PersistFailed;
    }
    if (!verify_object_map_checkpoint_roundtrip())
    {
        MarkRecoveryRequired(L"CommitObjectMapRoundTripFailed");
        return CommitStatus::PersistFailed;
    }

    if (!AllowCommitStage("before-spaceman-persist"))
    {
        MarkRecoveryRequired(L"CommitInterruptedBeforeSpacemanPersist");
        return CommitStatus::PersistFailed;
    }
    if (!PersistSpacemanCheckpoint(target_xid))
    {
        MarkRecoveryRequired(L"CommitSpacemanPersistFailed");
        return CommitStatus::PersistFailed;
    }
    if (!verify_spaceman_checkpoint_roundtrip())
    {
        MarkRecoveryRequired(L"CommitSpacemanRoundTripFailed");
        return CommitStatus::PersistFailed;
    }

    if (!AllowCommitStage("before-inode-persist"))
    {
        MarkRecoveryRequired(L"CommitInterruptedBeforeInodePersist");
        return CommitStatus::PersistFailed;
    }
    if (!PersistInodeCheckpoint(target_xid))
    {
        MarkRecoveryRequired(L"CommitInodePersistFailed");
        return CommitStatus::PersistFailed;
    }
    if (!verify_inode_checkpoint_roundtrip())
    {
        MarkRecoveryRequired(L"CommitInodeRoundTripFailed");
        return CommitStatus::PersistFailed;
    }

    if (!AllowCommitStage("before-btree-persist"))
    {
        MarkRecoveryRequired(L"CommitInterruptedBeforeBtreePersist");
        return CommitStatus::PersistFailed;
    }
    if (!PersistBtreeCheckpoint(target_xid))
    {
        MarkRecoveryRequired(L"CommitBtreePersistFailed");
        return CommitStatus::PersistFailed;
    }
    if (!verify_btree_checkpoint_roundtrip())
    {
        MarkRecoveryRequired(L"CommitBtreeRoundTripFailed");
        return CommitStatus::PersistFailed;
    }

    if (!AllowCommitStage("before-replay-persist"))
    {
        MarkRecoveryRequired(L"CommitInterruptedBeforeReplayPersist");
        return CommitStatus::PersistFailed;
    }
    if (!PersistReplayCheckpoint(target_xid))
    {
        MarkRecoveryRequired(L"CommitReplayPersistFailed");
        return CommitStatus::PersistFailed;
    }
    if (!AllowCommitStage("before-replay-roundtrip-verify"))
    {
        MarkRecoveryRequired(L"CommitInterruptedBeforeReplayRoundTripVerify");
        return CommitStatus::PersistFailed;
    }
    if (!verify_replay_checkpoint_roundtrip())
    {
        MarkRecoveryRequired(L"CommitReplayRoundTripFailed");
        return CommitStatus::PersistFailed;
    }

    const auto require_canonical_non_fixture_commit_path = RequiresCanonicalNonFixtureCommitPath();
    const auto allow_state_persist_stage = AllowCommitStage("before-state-persist");
    if (!allow_state_persist_stage)
    {
        if (!require_canonical_non_fixture_commit_path)
        {
            rollback_commit_extent_stage();
            rollback_committed_state();
            return CommitStatus::PersistFailed;
        }

        // Canonical non-fixture commit/replay paths are disk-authoritative.
        // Sidecar state persistence is best-effort telemetry and must not block
        // durable checkpoint switch on production media.
        last_commit_stage_ = "state-persist-skipped";
    }
    else if (!PersistPersistentState(*commit_extent, static_cast<std::uint64_t>(commit_blob.size())))
    {
        if (!require_canonical_non_fixture_commit_path)
        {
            rollback_commit_extent_stage();
            rollback_committed_state();
            return CommitStatus::PersistFailed;
        }

        last_commit_stage_ = "state-persist-best-effort-failed";
    }
    if (!AllowCommitStage("before-checkpoint-switch"))
    {
        MarkRecoveryRequired(L"CommitInterruptedBeforeCheckpointSwitch");
        return CommitStatus::PersistFailed;
    }
    if (!PersistCheckpointSuperblock(target_xid))
    {
        MarkRecoveryRequired(L"CommitCheckpointWriteFailed");
        return CommitStatus::PersistFailed;
    }
    if (!AllowCommitStage("before-checkpoint-roundtrip-verify"))
    {
        MarkRecoveryRequired(L"CommitInterruptedBeforeCheckpointRoundTripVerify");
        return CommitStatus::PersistFailed;
    }
    if (!verify_superblock_checkpoint_roundtrip())
    {
        MarkRecoveryRequired(L"CommitCheckpointRoundTripFailed");
        return CommitStatus::PersistFailed;
    }
    if (!AllowCommitStage("before-checkpoint-flush"))
    {
        MarkRecoveryRequired(L"CommitInterruptedBeforeCheckpointFlush");
        return CommitStatus::FlushFailed;
    }
    if (!device_.Flush())
    {
        MarkRecoveryRequired(L"CommitCheckpointFlushFailed");
        return CommitStatus::FlushFailed;
    }

    ClearRecoveryRequired();
    pending_mutations_.clear();
    pending_object_map_updates_.clear();
    pending_spaceman_allocations_.clear();
    pending_spaceman_deallocations_.clear();
    pending_btree_records_.clear();
    canonical_commit_ready_ = CanReportCanonicalCommitReady(
        canonical_state_loaded_,
        commit_path_ready_,
        recovery_required_,
        legacy_fixture_fallback_used_);
    last_commit_stage_ = "finalize";
    return CommitStatus::Committed;
}

MetadataStore::CommitStatus MetadataStore::CommitTransaction()
{
    return CommitPendingMutations();
}

MetadataStore::CommitStatus MetadataStore::CommitCanonicalTransaction()
{
    if (!canonical_state_loaded_)
    {
        return CommitStatus::NotReady;
    }

    if (!IsCanonicalCommitReady())
    {
        return CommitStatus::NotWritable;
    }

    auto status = CommitPendingMutations();
    if (status == CommitStatus::Committed || status == CommitStatus::NothingToCommit)
    {
        canonical_commit_ready_ = CanReportCanonicalCommitReady(
            canonical_state_loaded_,
            commit_path_ready_,
            recovery_required_,
            legacy_fixture_fallback_used_);
    }
    else
    {
        canonical_commit_ready_ = false;
    }

    return status;
}

bool MetadataStore::ReplayOrRecover()
{
    last_replay_stage_ = "start";
    const auto set_replay_stage = [this](std::string_view stage)
    {
        last_replay_stage_ = std::string(stage);
    };

    const auto fail_recovery = [this](std::wstring reason) -> bool
    {
        if (!reason.empty())
        {
            MarkRecoveryRequired(std::move(reason));
        }
        canonical_state_loaded_ = false;
        canonical_commit_ready_ = false;
        SyncCommitBlobTelemetryWithMode();
        return false;
    };

    set_replay_stage("load-volume-state");
    if (!LoadVolumeState())
    {
        if (recovery_reason_.empty())
        {
            return fail_recovery(L"RecoveryLoadVolumeStateFailed");
        }
        return false;
    }

    set_replay_stage("load-persistent-state");
    if (!persistent_state_loaded_ && !LoadPersistentState())
    {
        return fail_recovery(L"RecoveryPersistentStateLoadFailed");
    }

    set_replay_stage("evaluate-recovery");
    native_write_ready_ = container_loaded_ && object_map_loaded_ && spaceman_loaded_;
    write_device_allowed_ = device_.IsWritable() &&
                            (context_.allow_raw_physical_write || !IsLikelyRawDevicePath(context_.device_path));
    commit_path_ready_ = native_write_ready_ && write_device_allowed_ && !recovery_required_;
    canonical_state_loaded_ = native_write_ready_ && !recovery_required_;
    canonical_commit_ready_ = CanReportCanonicalCommitReady(
        canonical_state_loaded_,
        commit_path_ready_,
        recovery_required_,
        legacy_fixture_fallback_used_);
    SyncCommitBlobTelemetryWithMode();

    if (!recovery_required_)
    {
        set_replay_stage("complete-no-recovery");
        return true;
    }

    const auto replay_if_safe = !_wcsicmp(context_.crash_replay_mode.c_str(), L"ReplayIfSafe");
    if (!replay_if_safe)
    {
        canonical_commit_ready_ = false;
        return false;
    }

    const auto superblock_in_sync = loaded_superblock_checkpoint_xid_ == checkpoint_xid_;
    if (superblock_in_sync &&
        last_committed_xid_.has_value() &&
        last_committed_xid_.value() == checkpoint_xid_)
    {
        set_replay_stage("integrity-fastpath");
        if (VerifyIntegrity())
        {
            ClearRecoveryRequired();
            commit_path_ready_ = native_write_ready_ && write_device_allowed_ && !recovery_required_;
            canonical_state_loaded_ = native_write_ready_ && !recovery_required_;
            canonical_commit_ready_ = CanReportCanonicalCommitReady(
                canonical_state_loaded_,
                commit_path_ready_,
                recovery_required_,
                legacy_fixture_fallback_used_);
            SyncCommitBlobTelemetryWithMode();
            set_replay_stage("complete-fastpath");
            return true;
        }

        return fail_recovery(L"ReplayIntegrityCheckFailed");
    }

    if (!last_committed_xid_.has_value() ||
        !last_commit_blob_address_.has_value() ||
        !last_commit_blob_bytes_.has_value())
    {
        if (RequiresCanonicalNonFixtureCommitPath())
        {
            if (last_replay_checkpoint_candidate_present_ &&
                !last_replay_checkpoint_pending_window_)
            {
                return fail_recovery(L"ReplayCheckpointNotPendingWindow");
            }
            return fail_recovery(L"ReplayCanonicalCandidateMissing");
        }
        return fail_recovery(L"ReplayMetadataStateMissing");
    }

    const auto on_disk_checkpoint_xid = loaded_superblock_checkpoint_xid_;
    if (last_committed_xid_.value() <= on_disk_checkpoint_xid)
    {
        return fail_recovery(L"ReplayXidWindowInvalid");
    }

    if ((last_committed_xid_.value() - on_disk_checkpoint_xid) != 1)
    {
        return fail_recovery(L"ReplayXidWindowInvalid");
    }

    if (!ValidateCommitBlobLocation(
            last_commit_blob_address_.value(),
            last_commit_blob_bytes_.value()))
    {
        return fail_recovery(L"ReplayCommitBlobInvalid");
    }

    set_replay_stage("read-commit-blob");
    std::vector<std::byte> commit_blob;
    if (!device_.Read(last_commit_blob_address_.value(), static_cast<std::size_t>(last_commit_blob_bytes_.value()), commit_blob))
    {
        return fail_recovery(L"ReplayCommitBlobReadFailed");
    }

    if (commit_blob.size() < static_cast<std::size_t>(last_commit_blob_bytes_.value()))
    {
        return fail_recovery(L"ReplayCommitBlobReadFailed");
    }

    constexpr std::array<char, 13> kCommitBlobMagicCanonicalV3 =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'C', 'A', 'N', 'O', 'N', '3', '\0'
    };
    constexpr std::array<char, 13> kCommitBlobMagicScaffoldV2 =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'S', 'C', 'A', 'F', 'F', '2', '\0'
    };
    constexpr std::array<char, 13> kCommitBlobMagicScaffoldV3 =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'S', 'C', 'A', 'F', 'F', '3', '\0'
    };
    constexpr std::size_t kCommitBlobBaseHeaderBytes = 13 + 8 + 8 + 4 + 4 + 4 + 4 + 4;
    constexpr std::size_t kCommitBlobChecksumFieldOffset = kCommitBlobBaseHeaderBytes;
    constexpr std::size_t kCommitBlobHeaderBytesV3 = kCommitBlobBaseHeaderBytes + sizeof(std::uint32_t);
    if (commit_blob.size() < kCommitBlobBaseHeaderBytes)
    {
        return fail_recovery(L"ReplayCommitBlobInvalid");
    }

    const auto matches_magic = [&](const std::array<char, 13>& magic) -> bool
    {
        for (std::size_t index = 0; index < magic.size(); ++index)
        {
            if (std::to_integer<unsigned char>(commit_blob[index]) != static_cast<unsigned char>(magic[index]))
            {
                return false;
            }
        }
        return true;
    };

    enum class CommitBlobMagicKind
    {
        Unknown,
        CanonicalV3,
        ScaffoldV3,
        ScaffoldV2,
    };
    const auto detected_magic = [&]() -> CommitBlobMagicKind
    {
        if (matches_magic(kCommitBlobMagicCanonicalV3))
        {
            return CommitBlobMagicKind::CanonicalV3;
        }
        if (matches_magic(kCommitBlobMagicScaffoldV3))
        {
            return CommitBlobMagicKind::ScaffoldV3;
        }
        if (matches_magic(kCommitBlobMagicScaffoldV2))
        {
            return CommitBlobMagicKind::ScaffoldV2;
        }
        return CommitBlobMagicKind::Unknown;
    }();
    if (detected_magic == CommitBlobMagicKind::Unknown)
    {
        return fail_recovery(L"ReplayCommitBlobInvalid");
    }

    const auto observed_scaffold_commit_blob =
        detected_magic == CommitBlobMagicKind::ScaffoldV3 ||
        detected_magic == CommitBlobMagicKind::ScaffoldV2;
    last_commit_blob_magic_ = detected_magic == CommitBlobMagicKind::CanonicalV3
        ? "APFSRWCANON3"
        : detected_magic == CommitBlobMagicKind::ScaffoldV3
            ? "APFSRWSCAFF3"
            : "APFSRWSCAFF2";
    uses_scaffold_commit_blob_ = observed_scaffold_commit_blob;

    const auto require_canonical_replay_candidate = RequiresCanonicalNonFixtureCommitPath();
    if (require_canonical_replay_candidate &&
        detected_magic != CommitBlobMagicKind::CanonicalV3)
    {
        return fail_recovery(L"ScaffoldCommitBlobActive");
    }
    const auto allow_scaffold_commit_blob = ShouldAcceptScaffoldCommitBlobForCurrentContext();
    if ((detected_magic == CommitBlobMagicKind::ScaffoldV3 ||
         detected_magic == CommitBlobMagicKind::ScaffoldV2) &&
        !allow_scaffold_commit_blob)
    {
        return fail_recovery(L"ScaffoldCommitBlobActive");
    }
    const bool commit_blob_has_checksum =
        detected_magic == CommitBlobMagicKind::CanonicalV3 ||
        detected_magic == CommitBlobMagicKind::ScaffoldV3;

    const auto commit_blob_header_bytes =
        commit_blob_has_checksum ? kCommitBlobHeaderBytesV3 : kCommitBlobBaseHeaderBytes;
    if (commit_blob.size() < commit_blob_header_bytes)
    {
        return fail_recovery(L"ReplayCommitBlobInvalid");
    }

    set_replay_stage("parse-commit-blob");
    auto source_xid = ReadLe64(commit_blob, 13);
    auto target_xid = ReadLe64(commit_blob, 21);
    auto mutation_count = ReadLe32(commit_blob, 29);
    auto object_map_updates = ReadLe32(commit_blob, 33);
    auto spaceman_allocations = ReadLe32(commit_blob, 37);
    auto spaceman_deallocations = ReadLe32(commit_blob, 41);
    auto btree_records = ReadLe32(commit_blob, 45);

    const auto mutation_component_total =
        static_cast<std::uint64_t>(object_map_updates) +
        static_cast<std::uint64_t>(spaceman_allocations) +
        static_cast<std::uint64_t>(spaceman_deallocations) +
        static_cast<std::uint64_t>(btree_records);
    if (mutation_count == 0 || mutation_component_total == 0 ||
        mutation_count > mutation_component_total)
    {
        return fail_recovery(L"ReplayCommitBlobInvalid");
    }

    if (source_xid != on_disk_checkpoint_xid ||
        target_xid != last_committed_xid_.value())
    {
        return fail_recovery(L"ReplayCommitBlobInvalid");
    }

    const auto commit_blob_payload_checksum =
        commit_blob_has_checksum ? ReadLe32(commit_blob, kCommitBlobChecksumFieldOffset) : 0;
    const auto payload_capacity = static_cast<std::uint64_t>(commit_blob.size() - commit_blob_header_bytes);
    const auto checked_multiply = [](std::uint32_t value, std::uint64_t unit_bytes, std::uint64_t& out_bytes) -> bool
    {
        if (unit_bytes == 0)
        {
            out_bytes = 0;
            return true;
        }
        if (value > (std::numeric_limits<std::uint64_t>::max() / unit_bytes))
        {
            return false;
        }
        out_bytes = static_cast<std::uint64_t>(value) * unit_bytes;
        return true;
    };
    const auto checked_add = [](std::uint64_t lhs, std::uint64_t rhs, std::uint64_t& out_sum) -> bool
    {
        if (lhs > (std::numeric_limits<std::uint64_t>::max() - rhs))
        {
            return false;
        }
        out_sum = lhs + rhs;
        return true;
    };
    std::uint64_t object_map_min_bytes = 0;
    std::uint64_t spaceman_allocation_min_bytes = 0;
    std::uint64_t spaceman_deallocation_min_bytes = 0;
    std::uint64_t btree_min_bytes = 0;
    if (!checked_multiply(object_map_updates, 32ull, object_map_min_bytes) ||
        !checked_multiply(spaceman_allocations, 16ull, spaceman_allocation_min_bytes) ||
        !checked_multiply(spaceman_deallocations, 16ull, spaceman_deallocation_min_bytes) ||
        !checked_multiply(btree_records, 17ull, btree_min_bytes))
    {
        return fail_recovery(L"ReplayCommitBlobInvalid");
    }
    std::uint64_t minimum_payload_bytes = 0;
    if (!checked_add(object_map_min_bytes, spaceman_allocation_min_bytes, minimum_payload_bytes))
    {
        return fail_recovery(L"ReplayCommitBlobInvalid");
    }
    if (!checked_add(minimum_payload_bytes, spaceman_deallocation_min_bytes, minimum_payload_bytes))
    {
        return fail_recovery(L"ReplayCommitBlobInvalid");
    }
    if (!checked_add(minimum_payload_bytes, btree_min_bytes, minimum_payload_bytes))
    {
        return fail_recovery(L"ReplayCommitBlobInvalid");
    }
    if (minimum_payload_bytes > payload_capacity)
    {
        return fail_recovery(L"ReplayCommitBlobInvalid");
    }

    std::size_t cursor = commit_blob_header_bytes;
    std::vector<ObjectMapUpdate> parsed_object_map_updates;
    std::vector<SpacemanAllocation> parsed_spaceman_allocations;
    std::vector<SpacemanAllocation> parsed_spaceman_deallocations;
    std::vector<BtreeRecord> parsed_btree_records;
    std::unordered_set<std::uint64_t> parsed_object_map_object_ids;
    try
    {
        parsed_object_map_updates.reserve(object_map_updates);
        parsed_spaceman_allocations.reserve(spaceman_allocations);
        parsed_spaceman_deallocations.reserve(spaceman_deallocations);
        parsed_btree_records.reserve(btree_records);
        parsed_object_map_object_ids.reserve(object_map_updates);
    }
    catch (...)
    {
        return fail_recovery(L"ReplayCommitBlobInvalid");
    }
    const auto advance = [&](std::uint64_t bytes) -> bool
    {
        if (bytes > (std::numeric_limits<std::size_t>::max() - cursor))
        {
            return false;
        }
        const auto next = cursor + static_cast<std::size_t>(bytes);
        if (next > commit_blob.size())
        {
            return false;
        }
        cursor = next;
        return true;
    };

    for (std::uint32_t index = 0; index < object_map_updates; ++index)
    {
        if (cursor > commit_blob.size() || 32 > (commit_blob.size() - cursor))
        {
            return fail_recovery(L"ReplayCommitBlobInvalid");
        }

        ObjectMapUpdate update{};
        update.object_id = ReadLe64(commit_blob, cursor + 0);
        update.physical_address = ReadLe64(commit_blob, cursor + 8);
        update.logical_size = ReadLe64(commit_blob, cursor + 16);
        update.xid = ReadLe64(commit_blob, cursor + 24);
        cursor += 32;

        if (update.object_id == 0 ||
            update.xid != target_xid ||
            (update.physical_address == 0) != (update.logical_size == 0))
        {
            return fail_recovery(L"ReplayCommitBlobInvalid");
        }
        if (!parsed_object_map_object_ids.insert(update.object_id).second)
        {
            return fail_recovery(L"ReplayCommitBlobInvalid");
        }
        parsed_object_map_updates.push_back(update);
    }

    for (std::uint32_t index = 0; index < spaceman_allocations; ++index)
    {
        if (cursor > commit_blob.size() || 16 > (commit_blob.size() - cursor))
        {
            return fail_recovery(L"ReplayCommitBlobInvalid");
        }

        SpacemanAllocation allocation{};
        allocation.physical_address = ReadLe64(commit_blob, cursor + 0);
        allocation.bytes = ReadLe64(commit_blob, cursor + 8);
        cursor += 16;
        if (allocation.physical_address == 0 || allocation.bytes == 0)
        {
            return fail_recovery(L"ReplayCommitBlobInvalid");
        }

        const auto aligned_bytes = AlignExtentBytes(allocation.bytes);
        if (aligned_bytes == 0 ||
            aligned_bytes != allocation.bytes ||
            ExtentOverlapsReservedMetadata(allocation.physical_address, allocation.bytes))
        {
            return fail_recovery(L"ReplayCommitBlobInvalid");
        }

        parsed_spaceman_allocations.push_back(allocation);
    }

    for (std::uint32_t index = 0; index < spaceman_deallocations; ++index)
    {
        if (cursor > commit_blob.size() || 16 > (commit_blob.size() - cursor))
        {
            return fail_recovery(L"ReplayCommitBlobInvalid");
        }

        SpacemanAllocation deallocation{};
        deallocation.physical_address = ReadLe64(commit_blob, cursor + 0);
        deallocation.bytes = ReadLe64(commit_blob, cursor + 8);
        cursor += 16;
        if (deallocation.physical_address == 0 || deallocation.bytes == 0)
        {
            return fail_recovery(L"ReplayCommitBlobInvalid");
        }

        const auto aligned_bytes = AlignExtentBytes(deallocation.bytes);
        if (aligned_bytes == 0 || aligned_bytes != deallocation.bytes)
        {
            return fail_recovery(L"ReplayCommitBlobInvalid");
        }

        parsed_spaceman_deallocations.push_back(deallocation);
    }

    if (cursor > commit_blob.size())
    {
        return fail_recovery(L"ReplayCommitBlobInvalid");
    }

    for (std::uint32_t index = 0; index < btree_records; ++index)
    {
        if (cursor > commit_blob.size() || 16 > (commit_blob.size() - cursor))
        {
            return fail_recovery(L"ReplayCommitBlobInvalid");
        }

        const auto kind_value = ReadLe32(commit_blob, cursor + 0);
        const auto tombstone_flag = ReadLe32(commit_blob, cursor + 4);
        const auto key_size = ReadLe32(commit_blob, cursor + 8);
        const auto value_size = ReadLe32(commit_blob, cursor + 12);
        cursor += 16;

        if (kind_value < static_cast<std::uint32_t>(BtreeRecordKind::Inode) ||
            kind_value > static_cast<std::uint32_t>(BtreeRecordKind::FileExtent) ||
            tombstone_flag > 1)
        {
            return fail_recovery(L"ReplayCommitBlobInvalid");
        }

        const auto payload_size = static_cast<std::uint64_t>(key_size) + static_cast<std::uint64_t>(value_size);
        const auto payload_start = cursor;
        if (!advance(payload_size))
        {
            return fail_recovery(L"ReplayCommitBlobInvalid");
        }

        BtreeRecord record{};
        record.kind = static_cast<BtreeRecordKind>(kind_value);
        record.tombstone = tombstone_flag != 0;
        if (key_size > 0)
        {
            record.key.insert(
                record.key.end(),
                commit_blob.begin() + static_cast<std::vector<std::byte>::difference_type>(payload_start),
                commit_blob.begin() + static_cast<std::vector<std::byte>::difference_type>(payload_start + key_size));
        }
        if (value_size > 0)
        {
            const auto value_start = payload_start + key_size;
            record.value.insert(
                record.value.end(),
                commit_blob.begin() + static_cast<std::vector<std::byte>::difference_type>(value_start),
                commit_blob.begin() + static_cast<std::vector<std::byte>::difference_type>(value_start + value_size));
        }
        if (record.key.empty())
        {
            return fail_recovery(L"ReplayCommitBlobInvalid");
        }
        if (std::to_integer<unsigned char>(record.key.front()) !=
            static_cast<unsigned char>(record.kind))
        {
            return fail_recovery(L"ReplayCommitBlobInvalid");
        }
        parsed_btree_records.push_back(std::move(record));
    }

    if (commit_blob_has_checksum)
    {
        const auto payload_bytes = cursor - commit_blob_header_bytes;
        const auto computed_payload_checksum = UpdateFnv1a(
            kCheckpointChecksumSeed,
            commit_blob.data() + static_cast<std::vector<std::byte>::difference_type>(commit_blob_header_bytes),
            payload_bytes);
        if (commit_blob_payload_checksum != computed_payload_checksum)
        {
            return fail_recovery(L"ReplayCommitBlobInvalid");
        }
    }

    if (cursor > commit_blob.size())
    {
        return fail_recovery(L"ReplayCommitBlobInvalid");
    }
    for (std::size_t index = cursor; index < commit_blob.size(); ++index)
    {
        if (commit_blob[index] != std::byte{0})
        {
            return fail_recovery(L"ReplayCommitBlobInvalid");
        }
    }

    if (!VerifyIntegrity())
    {
        return fail_recovery(L"ReplayIntegrityCheckFailed");
    }

    set_replay_stage("apply-replay-mutations");
    {
        std::unordered_map<std::uint64_t, ObjectMapUpdate> final_object_map_updates;
        final_object_map_updates.reserve(parsed_object_map_updates.size());
        for (const auto& update : parsed_object_map_updates)
        {
            final_object_map_updates[update.object_id] = update;
        }

        struct RawInodeMutationState
        {
            bool tombstone = false;
            bool is_directory = false;
            std::uint64_t logical_size = 0;
            std::uint64_t data_physical_address = 0;
        };

        auto canonical_blob_btree_records = CanonicalizeBtreeRecords(parsed_btree_records);
        std::unordered_map<std::uint64_t, DecodedBtreeInode> parsed_inodes_by_object;
        std::unordered_map<std::uint64_t, DecodedBtreeExtent> parsed_extents_by_object;
        std::unordered_map<std::wstring, DecodedBtreeDirectoryEntry> canonical_directory_entries_by_key;
        std::unordered_map<std::uint64_t, RawInodeMutationState> raw_inode_mutations_by_object;
        parsed_inodes_by_object.reserve(canonical_blob_btree_records.size());
        parsed_extents_by_object.reserve(canonical_blob_btree_records.size());
        canonical_directory_entries_by_key.reserve(canonical_blob_btree_records.size());
        raw_inode_mutations_by_object.reserve(parsed_btree_records.size());

        const auto canonical_name_key = [](const std::wstring& name)
        {
            std::wstring key = name;
            std::transform(key.begin(), key.end(), key.begin(), [](wchar_t ch)
            {
                return static_cast<wchar_t>(std::towlower(ch));
            });
            return key;
        };
        const auto build_directory_entry_triplet_key = [&](std::uint64_t parent_object_id, const std::wstring& entry_name, std::uint64_t child_object_id)
        {
            auto key = std::to_wstring(parent_object_id);
            key.push_back(L'|');
            key.append(canonical_name_key(entry_name));
            key.push_back(L'|');
            key.append(std::to_wstring(child_object_id));
            return key;
        };
        const auto build_extent_key = [](std::uint64_t physical_address, std::uint64_t bytes)
        {
            return std::to_wstring(physical_address) + L":" + std::to_wstring(bytes);
        };

        std::unordered_set<std::wstring> raw_directory_tombstone_triplets;
        std::unordered_set<std::wstring> raw_inode_tombstone_triplets;
        std::unordered_map<std::wstring, std::size_t> raw_extent_tombstone_counts;
        raw_directory_tombstone_triplets.reserve(parsed_btree_records.size());
        raw_inode_tombstone_triplets.reserve(parsed_btree_records.size());
        raw_extent_tombstone_counts.reserve(parsed_btree_records.size());

        for (const auto& raw_record : parsed_btree_records)
        {
            switch (raw_record.kind)
            {
            case BtreeRecordKind::Inode:
            {
                if (raw_record.key.size() != (1 + 8 + 8))
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }

                std::uint64_t parent_object_id = 0;
                std::uint64_t object_id = 0;
                if (!TryReadLe64(raw_record.key, 1, parent_object_id) ||
                    !TryReadLe64(raw_record.key, 9, object_id) ||
                    parent_object_id == 0 ||
                    object_id == 0)
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }

                std::size_t cursor_in_value = 0;
                std::uint64_t xid = 0;
                std::uint32_t flags = 0;
                std::uint64_t logical_size = 0;
                std::uint64_t data_physical_address = 0;
                std::uint64_t timestamp_utc = 0;
                std::wstring inode_name;
                if (!TryReadLe64(raw_record.value, cursor_in_value, xid))
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }
                cursor_in_value += 8;
                if (!TryReadLe32(raw_record.value, cursor_in_value, flags))
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }
                cursor_in_value += 4;
                if (!TryReadLe64(raw_record.value, cursor_in_value, logical_size))
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }
                cursor_in_value += 8;
                if (!TryReadLe64(raw_record.value, cursor_in_value, data_physical_address))
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }
                cursor_in_value += 8;
                if ((flags & 0x4u) != 0)
                {
                    if (!TryReadLe64(raw_record.value, cursor_in_value, timestamp_utc))
                    {
                        return fail_recovery(L"ReplayCommitBlobInvalid");
                    }
                    cursor_in_value += 8;
                }
                if (!TryReadWideStringWithLength(raw_record.value, cursor_in_value, inode_name) ||
                    cursor_in_value != raw_record.value.size())
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }

                const auto value_tombstone = (flags & 0x2u) != 0;
                (void)timestamp_utc;
                if (xid != target_xid ||
                    (flags & ~0x7u) != 0 ||
                    value_tombstone != raw_record.tombstone ||
                    (raw_record.tombstone && inode_name.empty() && parent_object_id != object_id) ||
                    ((flags & 0x1u) != 0 && (logical_size != 0 || data_physical_address != 0)) ||
                    ((flags & 0x1u) == 0 && logical_size > 0 && data_physical_address == 0))
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }

                if (raw_record.tombstone &&
                    object_id != volume_root_block_)
                {
                    raw_inode_tombstone_triplets.insert(
                        build_directory_entry_triplet_key(parent_object_id, inode_name, object_id));
                }

                raw_inode_mutations_by_object.insert_or_assign(
                    object_id,
                    RawInodeMutationState
                    {
                        raw_record.tombstone,
                        (flags & 0x1u) != 0,
                        logical_size,
                        data_physical_address,
                    });
                break;
            }
            case BtreeRecordKind::DirectoryEntry:
            {
                if (raw_record.key.size() < (1 + 8 + 4) ||
                    raw_record.value.size() != (8 + 8 + 1))
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }

                std::uint64_t parent_object_id = 0;
                if (!TryReadLe64(raw_record.key, 1, parent_object_id) ||
                    parent_object_id == 0)
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }
                std::size_t key_cursor = 1 + 8;
                std::wstring entry_name;
                if (!TryReadWideStringWithLength(raw_record.key, key_cursor, entry_name) ||
                    key_cursor != raw_record.key.size() ||
                    entry_name.empty())
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }

                const auto xid = ReadLe64(raw_record.value, 0);
                const auto child_object_id = ReadLe64(raw_record.value, 8);
                const auto value_tombstone = std::to_integer<unsigned char>(raw_record.value[16]) != 0;
                if (xid != target_xid ||
                    child_object_id == 0 ||
                    value_tombstone != raw_record.tombstone)
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }

                if (raw_record.tombstone)
                {
                    raw_directory_tombstone_triplets.insert(
                        build_directory_entry_triplet_key(parent_object_id, entry_name, child_object_id));
                }
                break;
            }
            case BtreeRecordKind::FileExtent:
            {
                if (raw_record.key.size() != (1 + 8 + 8) ||
                    raw_record.value.size() != (8 + 8 + 8 + 1))
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }

                const auto xid = ReadLe64(raw_record.value, 0);
                const auto physical_address = ReadLe64(raw_record.value, 8);
                const auto extent_bytes = ReadLe64(raw_record.value, 16);
                const auto value_tombstone = std::to_integer<unsigned char>(raw_record.value[24]) != 0;
                if (xid != target_xid ||
                    value_tombstone != raw_record.tombstone ||
                    physical_address == 0 ||
                    extent_bytes == 0)
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }
                if (raw_record.tombstone)
                {
                    const auto aligned_extent_bytes = AlignExtentBytes(extent_bytes);
                    if (aligned_extent_bytes == 0)
                    {
                        return fail_recovery(L"ReplayCommitBlobInvalid");
                    }
                    ++raw_extent_tombstone_counts[build_extent_key(physical_address, aligned_extent_bytes)];
                }
                break;
            }
            default:
                return fail_recovery(L"ReplayCommitBlobInvalid");
            }
        }

        for (const auto& inode_tombstone_key : raw_inode_tombstone_triplets)
        {
            if (!raw_directory_tombstone_triplets.contains(inode_tombstone_key))
            {
                return fail_recovery(L"ReplayCommitBlobInvalid");
            }
        }

        for (const auto& [object_id, update] : final_object_map_updates)
        {
            auto raw_inode_it = raw_inode_mutations_by_object.find(object_id);
            if (raw_inode_it == raw_inode_mutations_by_object.end())
            {
                return fail_recovery(L"ReplayCommitBlobInvalid");
            }

            const auto& raw_inode = raw_inode_it->second;
            if (raw_inode.is_directory &&
                (raw_inode.logical_size != 0 || raw_inode.data_physical_address != 0))
            {
                return fail_recovery(L"ReplayCommitBlobInvalid");
            }

            if (raw_inode.tombstone)
            {
                if (update.logical_size != 0 || update.physical_address != 0)
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }
                continue;
            }

            if (raw_inode.logical_size != update.logical_size ||
                raw_inode.data_physical_address != update.physical_address)
            {
                return fail_recovery(L"ReplayCommitBlobInvalid");
            }
        }

        for (const auto& record : canonical_blob_btree_records)
        {
            switch (record.kind)
            {
            case BtreeRecordKind::Inode:
            {
                DecodedBtreeInode decoded{};
                if (!DecodeBtreeInodeRecord(record, decoded) ||
                    !parsed_inodes_by_object.emplace(decoded.object_id, std::move(decoded)).second)
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }
                break;
            }
            case BtreeRecordKind::FileExtent:
            {
                DecodedBtreeExtent decoded{};
                if (!DecodeBtreeExtentRecord(record, decoded) ||
                    decoded.logical_offset != 0 ||
                    !parsed_extents_by_object.emplace(decoded.object_id, std::move(decoded)).second)
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }
                break;
            }
            case BtreeRecordKind::DirectoryEntry:
            {
                DecodedBtreeDirectoryEntry decoded{};
                if (!DecodeBtreeDirectoryRecord(record, decoded))
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }

                auto key = build_directory_entry_triplet_key(
                    decoded.parent_object_id,
                    decoded.entry_name,
                    decoded.child_object_id);
                if (!canonical_directory_entries_by_key.emplace(std::move(key), std::move(decoded)).second)
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }
                break;
            }
            default:
                return fail_recovery(L"ReplayCommitBlobInvalid");
            }
        }

        std::unordered_set<std::wstring> committed_directory_triplets;
        committed_directory_triplets.reserve(committed_directory_links_.size());
        for (const auto& link : committed_directory_links_)
        {
            if (link.parent_object_id == 0 ||
                link.child_object_id == 0 ||
                link.entry_name.empty())
            {
                return fail_recovery(L"ReplayCommitBlobInvalid");
            }

            committed_directory_triplets.insert(
                build_directory_entry_triplet_key(
                    link.parent_object_id,
                    link.entry_name,
                    link.child_object_id));
        }

        for (const auto& [object_id, inode] : parsed_inodes_by_object)
        {
            if (object_id == 0 ||
                object_id == volume_root_block_)
            {
                continue;
            }

            auto entry_key = build_directory_entry_triplet_key(
                inode.parent_object_id,
                inode.name,
                object_id);
            if (!canonical_directory_entries_by_key.contains(entry_key) &&
                !committed_directory_triplets.contains(entry_key))
            {
                return fail_recovery(L"ReplayCommitBlobInvalid");
            }
        }

        for (const auto& [object_id, inode] : parsed_inodes_by_object)
        {
            if (inode.is_directory)
            {
                if (parsed_extents_by_object.contains(object_id))
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }
                continue;
            }

            if (inode.logical_size == 0)
            {
                if (inode.data_physical_address != 0 ||
                    parsed_extents_by_object.contains(object_id))
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }
                continue;
            }

            auto extent_it = parsed_extents_by_object.find(object_id);
            if (extent_it == parsed_extents_by_object.end() ||
                extent_it->second.physical_address != inode.data_physical_address ||
                extent_it->second.extent_bytes != inode.logical_size)
            {
                return fail_recovery(L"ReplayCommitBlobInvalid");
            }
        }

        for (const auto& [object_id, extent] : parsed_extents_by_object)
        {
            auto inode_it = parsed_inodes_by_object.find(object_id);
            if (inode_it == parsed_inodes_by_object.end() ||
                inode_it->second.is_directory ||
                inode_it->second.logical_size != extent.extent_bytes ||
                inode_it->second.data_physical_address != extent.physical_address)
            {
                return fail_recovery(L"ReplayCommitBlobInvalid");
            }
        }

        for (const auto& [_, directory_entry] : canonical_directory_entries_by_key)
        {
            auto parsed_inode_it = parsed_inodes_by_object.find(directory_entry.child_object_id);
            if (parsed_inode_it == parsed_inodes_by_object.end() ||
                parsed_inode_it->second.parent_object_id != directory_entry.parent_object_id ||
                canonical_name_key(parsed_inode_it->second.name) != canonical_name_key(directory_entry.entry_name))
            {
                return fail_recovery(L"ReplayCommitBlobInvalid");
            }
        }

        const auto has_committed_allocation = [this](std::uint64_t physical_address, std::uint64_t bytes_required) -> bool
        {
            if (physical_address == 0 || bytes_required == 0)
            {
                return false;
            }
            for (const auto& allocation : committed_spaceman_allocations_)
            {
                if (allocation.physical_address == physical_address &&
                    allocation.bytes >= bytes_required)
                {
                    return true;
                }
            }
            return false;
        };
        const auto is_covered_by_free_extent = [this](std::uint64_t physical_address, std::uint64_t bytes) -> bool
        {
            if (physical_address == 0 || bytes == 0 ||
                physical_address > (std::numeric_limits<std::uint64_t>::max() - bytes))
            {
                return false;
            }

            const auto end = physical_address + bytes;
            for (const auto& extent : committed_spaceman_free_extents_)
            {
                if (extent.physical_address == 0 || extent.bytes == 0 ||
                    extent.physical_address > (std::numeric_limits<std::uint64_t>::max() - extent.bytes))
                {
                    continue;
                }
                const auto extent_end = extent.physical_address + extent.bytes;
                if (physical_address >= extent.physical_address && end <= extent_end)
                {
                    return true;
                }
            }
            return false;
        };
        std::unordered_set<std::wstring> seen_allocation_extents;
        seen_allocation_extents.reserve(parsed_spaceman_allocations.size());
        for (const auto& allocation : parsed_spaceman_allocations)
        {
            auto key = build_extent_key(allocation.physical_address, allocation.bytes);
            if (!seen_allocation_extents.insert(std::move(key)).second)
            {
                return fail_recovery(L"ReplayCommitBlobInvalid");
            }
        }

        std::unordered_set<std::wstring> seen_deallocation_extents;
        seen_deallocation_extents.reserve(parsed_spaceman_deallocations.size());
        const auto has_overlapping_extents = [](const std::vector<SpacemanAllocation>& extents)
        {
            if (extents.size() < 2)
            {
                return false;
            }

            std::vector<SpacemanAllocation> sorted_extents = extents;
            std::sort(sorted_extents.begin(), sorted_extents.end(), [](const auto& lhs, const auto& rhs)
            {
                if (lhs.physical_address != rhs.physical_address)
                {
                    return lhs.physical_address < rhs.physical_address;
                }
                return lhs.bytes < rhs.bytes;
            });

            std::uint64_t previous_end = 0;
            bool has_previous = false;
            for (const auto& extent : sorted_extents)
            {
                if (extent.bytes == 0 ||
                    extent.physical_address > (std::numeric_limits<std::uint64_t>::max() - extent.bytes))
                {
                    return true;
                }

                const auto current_end = extent.physical_address + extent.bytes;
                if (has_previous && extent.physical_address < previous_end)
                {
                    return true;
                }

                previous_end = current_end;
                has_previous = true;
            }

            return false;
        };
        if (has_overlapping_extents(parsed_spaceman_allocations) ||
            has_overlapping_extents(parsed_spaceman_deallocations))
        {
            return fail_recovery(L"ReplayCommitBlobInvalid");
        }
        const auto extents_overlap = [](const SpacemanAllocation& lhs, const SpacemanAllocation& rhs)
        {
            if (lhs.bytes == 0 || rhs.bytes == 0 ||
                lhs.physical_address > (std::numeric_limits<std::uint64_t>::max() - lhs.bytes) ||
                rhs.physical_address > (std::numeric_limits<std::uint64_t>::max() - rhs.bytes))
            {
                return true;
            }

            const auto lhs_end = lhs.physical_address + lhs.bytes;
            const auto rhs_end = rhs.physical_address + rhs.bytes;
            return lhs.physical_address < rhs_end && rhs.physical_address < lhs_end;
        };
        std::unordered_set<std::wstring> exact_overlap_extents;
        exact_overlap_extents.reserve(
            std::min(parsed_spaceman_allocations.size(), parsed_spaceman_deallocations.size()));
        for (const auto& allocation : parsed_spaceman_allocations)
        {
            for (const auto& deallocation : parsed_spaceman_deallocations)
            {
                if (!extents_overlap(allocation, deallocation))
                {
                    continue;
                }

                if (allocation.physical_address == deallocation.physical_address &&
                    allocation.bytes == deallocation.bytes)
                {
                    exact_overlap_extents.insert(
                        build_extent_key(allocation.physical_address, allocation.bytes));
                    continue;
                }

                return fail_recovery(L"ReplayCommitBlobInvalid");
            }
        }
        for (const auto& [object_id, update] : final_object_map_updates)
        {
            auto parsed_inode_it = parsed_inodes_by_object.find(object_id);
            if (update.logical_size == 0)
            {
                if (update.physical_address != 0)
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }
                if (parsed_inode_it != parsed_inodes_by_object.end() &&
                    (!parsed_inode_it->second.is_directory ||
                     parsed_inode_it->second.logical_size != 0 ||
                     parsed_inode_it->second.data_physical_address != 0))
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }
            }
            else
            {
                if (parsed_inode_it == parsed_inodes_by_object.end() ||
                    parsed_inode_it->second.is_directory ||
                    parsed_inode_it->second.logical_size != update.logical_size ||
                    parsed_inode_it->second.data_physical_address != update.physical_address)
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }
            }

            auto committed_it = committed_object_map_.find(object_id);
            if (committed_it == committed_object_map_.end())
            {
                return fail_recovery(L"ReplayCommitBlobInvalid");
            }
            if (committed_it->second.physical_address != update.physical_address ||
                committed_it->second.logical_size != update.logical_size ||
                committed_it->second.xid != update.xid)
            {
                return fail_recovery(L"ReplayCommitBlobInvalid");
            }

            if (update.logical_size > 0)
            {
                const auto required_bytes = AlignExtentBytes(update.logical_size);
                if (required_bytes == 0 ||
                    !has_committed_allocation(update.physical_address, required_bytes))
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }
            }
        }

        for (const auto& deallocation : parsed_spaceman_deallocations)
        {
            auto key = build_extent_key(deallocation.physical_address, deallocation.bytes);
            const auto is_exact_overlap_extent = exact_overlap_extents.contains(key);
            if (!seen_deallocation_extents.insert(key).second)
            {
                return fail_recovery(L"ReplayCommitBlobInvalid");
            }
            if (!is_exact_overlap_extent &&
                !is_covered_by_free_extent(deallocation.physical_address, deallocation.bytes))
            {
                return fail_recovery(L"ReplayCommitBlobInvalid");
            }
        }
        for (const auto& [key, count] : raw_extent_tombstone_counts)
        {
            if (count != 1 || !seen_deallocation_extents.contains(key))
            {
                return fail_recovery(L"ReplayCommitBlobInvalid");
            }
        }
        for (const auto& overlap_key : exact_overlap_extents)
        {
            if (!seen_deallocation_extents.contains(overlap_key))
            {
                return fail_recovery(L"ReplayCommitBlobInvalid");
            }
            if (!raw_extent_tombstone_counts.contains(overlap_key))
            {
                return fail_recovery(L"ReplayCommitBlobInvalid");
            }
        }
        for (const auto& deallocation_key : seen_deallocation_extents)
        {
            if (!raw_extent_tombstone_counts.contains(deallocation_key))
            {
                return fail_recovery(L"ReplayCommitBlobInvalid");
            }
        }

        std::unordered_map<std::wstring, std::size_t> committed_allocation_counts;
        committed_allocation_counts.reserve(committed_spaceman_allocations_.size());
        for (const auto& allocation : committed_spaceman_allocations_)
        {
            ++committed_allocation_counts[build_extent_key(allocation.physical_address, allocation.bytes)];
        }

        std::unordered_map<std::wstring, int> net_allocation_delta;
        net_allocation_delta.reserve(parsed_spaceman_allocations.size() + parsed_spaceman_deallocations.size());
        for (const auto& allocation : parsed_spaceman_allocations)
        {
            ++net_allocation_delta[build_extent_key(allocation.physical_address, allocation.bytes)];
        }
        for (const auto& deallocation : parsed_spaceman_deallocations)
        {
            --net_allocation_delta[build_extent_key(deallocation.physical_address, deallocation.bytes)];
        }

        for (const auto& [key, delta] : net_allocation_delta)
        {
            if (delta <= 0)
            {
                continue;
            }
            auto committed_it = committed_allocation_counts.find(key);
            if (committed_it == committed_allocation_counts.end() ||
                committed_it->second < static_cast<std::size_t>(delta))
            {
                return fail_recovery(L"ReplayCommitBlobInvalid");
            }
        }

        std::unordered_map<std::string, BtreeRecord> committed_btree_by_key;
        committed_btree_by_key.reserve(committed_btree_records_.size());
        for (const auto& record : committed_btree_records_)
        {
            auto key_blob = BuildBtreeKeyBlob(record.key);
            if (!key_blob.empty())
            {
                committed_btree_by_key.insert_or_assign(std::move(key_blob), record);
            }
        }

        for (const auto& record : canonical_blob_btree_records)
        {
            auto key_blob = BuildBtreeKeyBlob(record.key);
            if (key_blob.empty())
            {
                return fail_recovery(L"ReplayCommitBlobInvalid");
            }

            auto committed_it = committed_btree_by_key.find(key_blob);
            if (committed_it == committed_btree_by_key.end() ||
                committed_it->second.kind != record.kind ||
                committed_it->second.tombstone != record.tombstone ||
                committed_it->second.value != record.value)
            {
                return fail_recovery(L"ReplayCommitBlobInvalid");
            }
        }
    }

    if (!AllowCommitStage("replay-before-checkpoint-switch"))
    {
        return fail_recovery(L"ReplayInterruptedBeforeCheckpointSwitch");
    }

    if (!PersistCheckpointSuperblock(target_xid))
    {
        return fail_recovery(L"ReplayCheckpointWriteFailed");
    }

    if (!AllowCommitStage("replay-before-checkpoint-flush"))
    {
        return fail_recovery(L"ReplayInterruptedBeforeCheckpointFlush");
    }

    if (!device_.Flush())
    {
        return fail_recovery(L"ReplayCheckpointFlushFailed");
    }

    checkpoint_xid_ = target_xid;
    loaded_superblock_checkpoint_xid_ = target_xid;
    ClearRecoveryRequired();
    commit_path_ready_ = native_write_ready_ && write_device_allowed_ && !recovery_required_;
    canonical_state_loaded_ = native_write_ready_ && !recovery_required_;
    canonical_commit_ready_ = CanReportCanonicalCommitReady(
        canonical_state_loaded_,
        commit_path_ready_,
        recovery_required_,
        legacy_fixture_fallback_used_);
    set_replay_stage("complete");
    return true;
}

bool MetadataStore::ReplayCanonicalCheckpoint()
{
    if (!canonical_state_loaded_ && !LoadCanonicalState())
    {
        return false;
    }

    const auto replay_result = ReplayOrRecover();
    canonical_state_loaded_ = replay_result &&
                              container_loaded_ &&
                              object_map_loaded_ &&
                              spaceman_loaded_ &&
                              !recovery_required_;
    canonical_commit_ready_ = CanReportCanonicalCommitReady(
        canonical_state_loaded_,
        commit_path_ready_,
        recovery_required_,
        legacy_fixture_fallback_used_);
    return replay_result;
}

bool MetadataStore::VerifyIntegrity() const
{
    if (!container_loaded_ || !object_map_loaded_ || !spaceman_loaded_)
    {
        return false;
    }

    if (!ValidateInodeGraphState(
            committed_inodes_,
            committed_path_index_,
            committed_directory_links_,
            true))
    {
        return false;
    }

    for (const auto& [path_key, object_id] : committed_path_index_)
    {
        if (path_key.empty())
        {
            return false;
        }

        if (committed_inodes_.find(object_id) == committed_inodes_.end())
        {
            return false;
        }
    }

    for (const auto& [object_id, inode] : committed_inodes_)
    {
        if (object_id == 0 || inode.object_id != object_id)
        {
            return false;
        }

        if (!inode.is_directory && inode.logical_size > 0 && inode.data_physical_address == 0)
        {
            return false;
        }
    }

    const auto xid_upper_bound = std::max<std::uint64_t>(
        1,
        std::max(checkpoint_xid_, last_committed_xid_.value_or(0)));

    const auto has_allocation_for_physical = [this](std::uint64_t physical_address, std::uint64_t logical_size) -> bool
    {
        if (physical_address == 0 || logical_size == 0)
        {
            return false;
        }

        const auto required_bytes = AlignExtentBytes(logical_size);
        if (required_bytes == 0)
        {
            return false;
        }

        for (const auto& allocation : committed_spaceman_allocations_)
        {
            if (allocation.physical_address == physical_address &&
                allocation.bytes >= required_bytes)
            {
                return true;
            }
        }
        return false;
    };

    std::unordered_set<std::string> projected_btree_keys;
    projected_btree_keys.reserve(committed_btree_records_.size());
    for (const auto& record : committed_btree_records_)
    {
        if (record.key.empty() ||
            record.kind < BtreeRecordKind::Inode ||
            record.kind > BtreeRecordKind::FileExtent)
        {
            return false;
        }
        if (record.tombstone)
        {
            return false;
        }
        if (std::to_integer<unsigned char>(record.key.front()) != static_cast<unsigned char>(record.kind))
        {
            return false;
        }

        auto key_blob = BuildBtreeKeyBlob(record.key);
        if (key_blob.empty() || !projected_btree_keys.insert(std::move(key_blob)).second)
        {
            return false;
        }
    }

    std::unordered_set<std::string> expected_btree_keys;
    expected_btree_keys.reserve(
        committed_inodes_.size() +
        committed_directory_links_.size() +
        committed_inodes_.size());

    for (const auto& [object_id, inode] : committed_inodes_)
    {
        if (IsRootPath(inode.full_path))
        {
            continue;
        }

        auto inode_key_record = BtreeMutationCodec::EncodeInodeRecord(
            object_id,
            inode.parent_object_id,
            inode.name,
            inode.is_directory,
            inode.logical_size,
            inode.data_physical_address,
            inode.timestamp_utc,
            xid_upper_bound,
            false);
        auto inode_key = BuildBtreeKeyBlob(inode_key_record.key);
        if (inode_key.empty() || !expected_btree_keys.insert(std::move(inode_key)).second)
        {
            return false;
        }

        if (!inode.is_directory &&
            inode.logical_size > 0 &&
            inode.data_physical_address != 0)
        {
            auto extent_key_record = BtreeMutationCodec::EncodeExtentRecord(
                object_id,
                0,
                inode.data_physical_address,
                inode.logical_size,
                xid_upper_bound,
                false);
            auto extent_key = BuildBtreeKeyBlob(extent_key_record.key);
            if (extent_key.empty() || !expected_btree_keys.insert(std::move(extent_key)).second)
            {
                return false;
            }
        }
    }

    for (const auto& link : committed_directory_links_)
    {
        auto directory_key_record = BtreeMutationCodec::EncodeDirectoryRecord(
            link.parent_object_id,
            link.entry_name,
            link.child_object_id,
            xid_upper_bound,
            false);
        auto directory_key = BuildBtreeKeyBlob(directory_key_record.key);
        if (directory_key.empty() || !expected_btree_keys.insert(std::move(directory_key)).second)
        {
            return false;
        }
    }

    if (projected_btree_keys.size() != expected_btree_keys.size())
    {
        return false;
    }
    for (const auto& expected_key : expected_btree_keys)
    {
        if (!projected_btree_keys.contains(expected_key))
        {
            return false;
        }
    }

    std::unordered_map<std::uint64_t, DecodedBtreeInode> decoded_inodes_by_object;
    std::unordered_map<std::wstring, DecodedBtreeDirectoryEntry> decoded_directory_entries;
    std::unordered_map<std::uint64_t, DecodedBtreeExtent> decoded_extents_by_object;
    decoded_inodes_by_object.reserve(committed_btree_records_.size());
    decoded_directory_entries.reserve(committed_btree_records_.size());
    decoded_extents_by_object.reserve(committed_btree_records_.size());

    for (const auto& record : committed_btree_records_)
    {
        switch (record.kind)
        {
        case BtreeRecordKind::Inode:
        {
            DecodedBtreeInode decoded{};
            if (!DecodeBtreeInodeRecord(record, decoded))
            {
                return false;
            }
            if (!decoded_inodes_by_object.emplace(decoded.object_id, std::move(decoded)).second)
            {
                return false;
            }
            break;
        }
        case BtreeRecordKind::DirectoryEntry:
        {
            DecodedBtreeDirectoryEntry decoded{};
            if (!DecodeBtreeDirectoryRecord(record, decoded))
            {
                return false;
            }
            auto key = BuildDirectoryEntryIndexKey(decoded.parent_object_id, decoded.entry_name);
            if (!decoded_directory_entries.emplace(std::move(key), std::move(decoded)).second)
            {
                return false;
            }
            break;
        }
        case BtreeRecordKind::FileExtent:
        {
            DecodedBtreeExtent decoded{};
            if (!DecodeBtreeExtentRecord(record, decoded))
            {
                return false;
            }
            if (decoded.logical_offset != 0)
            {
                return false;
            }
            if (!decoded_extents_by_object.emplace(decoded.object_id, std::move(decoded)).second)
            {
                return false;
            }
            break;
        }
        default:
            return false;
        }
    }

    std::size_t expected_non_root_inode_count = 0;
    for (const auto& [object_id, inode] : committed_inodes_)
    {
        (void)object_id;
        if (!IsRootPath(inode.full_path))
        {
            ++expected_non_root_inode_count;
        }
    }
    if (decoded_inodes_by_object.size() != expected_non_root_inode_count)
    {
        return false;
    }

    for (const auto& [object_id, inode] : committed_inodes_)
    {
        if (IsRootPath(inode.full_path))
        {
            continue;
        }

        auto decoded_it = decoded_inodes_by_object.find(object_id);
        if (decoded_it == decoded_inodes_by_object.end())
        {
            return false;
        }
        const auto& decoded = decoded_it->second;
        if (decoded.parent_object_id != inode.parent_object_id ||
            decoded.is_directory != inode.is_directory ||
            decoded.logical_size != inode.logical_size ||
            decoded.data_physical_address != inode.data_physical_address ||
            decoded.timestamp_utc != inode.timestamp_utc ||
            decoded.name != inode.name)
        {
            return false;
        }
        if (decoded.xid == 0 || decoded.xid > xid_upper_bound)
        {
            return false;
        }
        if (decoded.parent_object_id == 0 || !committed_inodes_.contains(decoded.parent_object_id))
        {
            return false;
        }
        if (auto parent_it = committed_inodes_.find(decoded.parent_object_id);
            parent_it == committed_inodes_.end() || !parent_it->second.is_directory)
        {
            return false;
        }

        if (inode.is_directory || inode.logical_size == 0 || inode.data_physical_address == 0)
        {
            if (decoded_extents_by_object.contains(object_id))
            {
                return false;
            }
        }
        else
        {
            auto extent_it = decoded_extents_by_object.find(object_id);
            if (extent_it == decoded_extents_by_object.end())
            {
                return false;
            }
            const auto& extent = extent_it->second;
            if (extent.physical_address != inode.data_physical_address ||
                extent.extent_bytes != inode.logical_size ||
                extent.xid == 0 ||
                extent.xid > xid_upper_bound)
            {
                return false;
            }

            auto mapped = committed_object_map_.find(object_id);
            if (mapped == committed_object_map_.end())
            {
                return false;
            }
            if (mapped->second.xid == 0 ||
                mapped->second.xid > xid_upper_bound ||
                mapped->second.physical_address != extent.physical_address ||
                mapped->second.logical_size != extent.extent_bytes)
            {
                return false;
            }
            if (!has_allocation_for_physical(mapped->second.physical_address, mapped->second.logical_size))
            {
                return false;
            }
        }
    }

    if (decoded_directory_entries.size() != committed_directory_links_.size())
    {
        return false;
    }
    for (const auto& link : committed_directory_links_)
    {
        auto entry_key = BuildDirectoryEntryIndexKey(link.parent_object_id, link.entry_name);
        auto decoded_it = decoded_directory_entries.find(entry_key);
        if (decoded_it == decoded_directory_entries.end())
        {
            return false;
        }
        const auto& decoded = decoded_it->second;
        if (decoded.child_object_id != link.child_object_id ||
            decoded.xid == 0 ||
            decoded.xid > xid_upper_bound)
        {
            return false;
        }

        auto parent_it = committed_inodes_.find(link.parent_object_id);
        auto child_it = committed_inodes_.find(link.child_object_id);
        if (parent_it == committed_inodes_.end() ||
            child_it == committed_inodes_.end() ||
            !parent_it->second.is_directory ||
            child_it->second.parent_object_id != link.parent_object_id ||
            child_it->second.name != link.entry_name)
        {
            return false;
        }
    }

    return true;
}

std::size_t MetadataStore::PendingMutationCount() const noexcept
{
    return pending_mutations_.size();
}

std::size_t MetadataStore::PendingObjectMapUpdateCount() const noexcept
{
    return pending_object_map_updates_.size();
}

std::size_t MetadataStore::PendingAllocationCount() const noexcept
{
    return pending_spaceman_allocations_.size();
}

std::size_t MetadataStore::PendingDeallocationCount() const noexcept
{
    return pending_spaceman_deallocations_.size();
}

std::size_t MetadataStore::PendingBtreeRecordCount() const noexcept
{
    return pending_btree_records_.size();
}

std::optional<std::uint64_t> MetadataStore::LastCommittedXid() const noexcept
{
    return last_committed_xid_;
}

std::size_t MetadataStore::CommittedObjectCount() const noexcept
{
    return committed_object_map_.size();
}

std::size_t MetadataStore::CommittedAllocationCount() const noexcept
{
    return committed_spaceman_allocations_.size();
}

std::size_t MetadataStore::CommittedFreeExtentCount() const noexcept
{
    return committed_spaceman_free_extents_.size();
}

std::size_t MetadataStore::CommittedBtreeRecordCount() const noexcept
{
    return committed_btree_records_.size();
}

std::optional<MetadataStore::ObjectMapUpdate> MetadataStore::LookupCommittedObject(std::uint64_t object_id) const
{
    if (auto it = committed_object_map_.find(object_id); it != committed_object_map_.end())
    {
        return it->second;
    }

    return std::nullopt;
}

std::size_t MetadataStore::CommittedInodeCount() const noexcept
{
    return committed_inodes_.size();
}

std::optional<MetadataStore::InodeRecord> MetadataStore::LookupCommittedInodeByPath(const std::wstring& path) const
{
    const auto normalized = NormalizePath(path);
    auto it = committed_path_index_.find(CanonicalPathKey(normalized));
    if (it == committed_path_index_.end())
    {
        return std::nullopt;
    }

    auto inode = committed_inodes_.find(it->second);
    if (inode == committed_inodes_.end())
    {
        return std::nullopt;
    }

    return inode->second;
}

std::vector<MetadataStore::InodeRecord> MetadataStore::SnapshotCommittedInodes() const
{
    std::vector<InodeRecord> snapshot;
    snapshot.reserve(committed_inodes_.size());
    for (const auto& [_, inode] : committed_inodes_)
    {
        snapshot.push_back(inode);
    }

    std::sort(snapshot.begin(), snapshot.end(), [](const InodeRecord& lhs, const InodeRecord& rhs)
    {
        const auto lhs_key = CanonicalPathKey(lhs.full_path);
        const auto rhs_key = CanonicalPathKey(rhs.full_path);
        if (lhs_key == rhs_key)
        {
            return lhs.object_id < rhs.object_id;
        }
        return lhs_key < rhs_key;
    });

    return snapshot;
}

bool MetadataStore::ReadCommittedFileRange(
    const std::wstring& path,
    std::uint64_t offset,
    std::size_t bytes_to_read,
    std::vector<std::byte>& out_payload) const
{
    out_payload.clear();

    auto inode = LookupCommittedInodeByPath(path);
    if (!inode.has_value() || inode->is_directory)
    {
        return false;
    }

    if (bytes_to_read == 0 || offset >= inode->logical_size)
    {
        return true;
    }

    if (inode->data_physical_address == 0 || inode->logical_size == 0)
    {
        return false;
    }

    const auto available_u64 = inode->logical_size - offset;
    const auto available_bytes = available_u64 > static_cast<std::uint64_t>(bytes_to_read)
        ? bytes_to_read
        : static_cast<std::size_t>(available_u64);

    if (inode->data_physical_address > (std::numeric_limits<std::uint64_t>::max() - offset))
    {
        return false;
    }
    const auto physical_offset = inode->data_physical_address + offset;

    std::vector<std::byte> read_buffer;
    if (!device_.Read(physical_offset, available_bytes, read_buffer))
    {
        return false;
    }

    if (read_buffer.size() < available_bytes)
    {
        read_buffer.resize(available_bytes, std::byte{0});
    }

    out_payload = std::move(read_buffer);
    return true;
}

void MetadataStore::SetCommitStageHook(std::function<bool(std::string_view stage)> hook)
{
    commit_stage_hook_ = std::move(hook);
}

void MetadataStore::SetFilePayloadProvider(
    std::function<std::optional<std::vector<std::byte>>(const std::wstring& path, std::uint64_t logical_size)> provider)
{
    file_payload_provider_ = std::move(provider);
}

std::optional<std::uint64_t> MetadataStore::AllocateExtent(std::uint64_t bytes)
{
    if (!container_loaded_ || !spaceman_loaded_)
    {
        return std::nullopt;
    }

    std::optional<std::uint64_t> container_bytes;
    if (total_blocks_ != 0)
    {
        if (block_size_ == 0 ||
            total_blocks_ > (std::numeric_limits<std::uint64_t>::max() / static_cast<std::uint64_t>(block_size_)))
        {
            return std::nullopt;
        }
        container_bytes = total_blocks_ * static_cast<std::uint64_t>(block_size_);
    }

    const auto aligned_bytes = AlignExtentBytes(bytes);
    if (aligned_bytes == 0)
    {
        return std::nullopt;
    }

    for (auto it = working_spaceman_free_extents_.begin(); it != working_spaceman_free_extents_.end(); ++it)
    {
        if (it->bytes < aligned_bytes)
        {
            continue;
        }

        const auto allocation_address = it->physical_address;
        if (allocation_address > (std::numeric_limits<std::uint64_t>::max() - aligned_bytes))
        {
            continue;
        }
        const auto allocation_end = allocation_address + aligned_bytes;
        if (container_bytes.has_value() && allocation_end > container_bytes.value())
        {
            continue;
        }
        if (ExtentOverlapsReservedMetadata(allocation_address, aligned_bytes))
        {
            continue;
        }
        it->physical_address += aligned_bytes;
        it->bytes -= aligned_bytes;
        if (it->bytes == 0)
        {
            working_spaceman_free_extents_.erase(it);
        }
        return allocation_address;
    }

    auto current = working_next_ephemeral_extent_;
    if (current > (std::numeric_limits<std::uint64_t>::max() - aligned_bytes))
    {
        return std::nullopt;
    }

    const auto allocation_end = current + aligned_bytes;
    if (container_bytes.has_value() && allocation_end > container_bytes.value())
    {
        return std::nullopt;
    }
    if (ExtentOverlapsReservedMetadata(current, aligned_bytes))
    {
        return std::nullopt;
    }

    working_next_ephemeral_extent_ = allocation_end;
    return current;
}

bool MetadataStore::FreeExtent(std::uint64_t physical_address, std::uint64_t bytes)
{
    if (!container_loaded_ || !spaceman_loaded_ || physical_address == 0 || bytes == 0)
    {
        return false;
    }

    const auto aligned_bytes = AlignExtentBytes(bytes);
    if (aligned_bytes == 0)
    {
        return false;
    }
    if (physical_address > (std::numeric_limits<std::uint64_t>::max() - aligned_bytes))
    {
        return false;
    }

    if (total_blocks_ != 0)
    {
        if (block_size_ == 0 ||
            total_blocks_ > (std::numeric_limits<std::uint64_t>::max() / static_cast<std::uint64_t>(block_size_)))
        {
            return false;
        }

        const auto container_bytes = total_blocks_ * static_cast<std::uint64_t>(block_size_);
        if ((physical_address + aligned_bytes) > container_bytes)
        {
            return false;
        }
    }
    if (ExtentOverlapsReservedMetadata(physical_address, aligned_bytes))
    {
        return false;
    }

    working_spaceman_free_extents_.push_back(SpacemanAllocation
    {
        physical_address,
        aligned_bytes
    });
    std::sort(
        working_spaceman_free_extents_.begin(),
        working_spaceman_free_extents_.end(),
        [](const SpacemanAllocation& lhs, const SpacemanAllocation& rhs)
        {
            return lhs.physical_address < rhs.physical_address;
        });

    std::vector<SpacemanAllocation> merged;
    merged.reserve(working_spaceman_free_extents_.size());
    for (const auto& extent : working_spaceman_free_extents_)
    {
        if (extent.bytes == 0)
        {
            continue;
        }

        if (merged.empty())
        {
            merged.push_back(extent);
            continue;
        }

        auto& last = merged.back();
        const auto last_end = last.physical_address + last.bytes;
        const auto extent_end = extent.physical_address + extent.bytes;
        if (extent.physical_address <= last_end)
        {
            if (extent_end > last_end)
            {
                last.bytes = extent_end - last.physical_address;
            }
            continue;
        }

        merged.push_back(extent);
    }

    working_spaceman_free_extents_ = std::move(merged);
    return true;
}

std::uint64_t MetadataStore::StableObjectIdFromPath(const std::wstring& path)
{
    constexpr std::uint64_t kFnvOffset = 1469598103934665603ull;
    constexpr std::uint64_t kFnvPrime = 1099511628211ull;

    std::uint64_t hash = kFnvOffset;
    for (const auto ch : path)
    {
        const auto lower = static_cast<std::uint16_t>(std::towlower(ch));
        const auto lo = static_cast<std::uint8_t>(lower & 0xffu);
        const auto hi = static_cast<std::uint8_t>((lower >> 8) & 0xffu);
        hash ^= lo;
        hash *= kFnvPrime;
        hash ^= hi;
        hash *= kFnvPrime;
    }

    return hash == 0 ? 1 : hash;
}

std::wstring MetadataStore::NormalizePath(const std::wstring& path)
{
    if (path.empty())
    {
        return {};
    }

    std::wstring normalized;
    normalized.reserve(path.size() + 1);

    if (path.front() != L'\\' && path.front() != L'/')
    {
        normalized.push_back(L'\\');
    }

    bool previous_separator = false;
    for (const auto ch : path)
    {
        const auto mapped = (ch == L'/') ? L'\\' : ch;
        if (mapped == L'\\')
        {
            if (previous_separator)
            {
                continue;
            }
            previous_separator = true;
            normalized.push_back(mapped);
            continue;
        }

        previous_separator = false;
        normalized.push_back(mapped);
    }

    while (normalized.size() > 1 && normalized.back() == L'\\')
    {
        normalized.pop_back();
    }

    if (normalized.empty())
    {
        return {};
    }

    if (normalized.front() != L'\\')
    {
        normalized.insert(normalized.begin(), L'\\');
    }

    return normalized;
}

std::wstring MetadataStore::CanonicalPathKey(const std::wstring& normalized_path)
{
    auto key = NormalizePath(normalized_path);
    std::transform(key.begin(), key.end(), key.begin(), [](wchar_t ch)
    {
        return static_cast<wchar_t>(std::towlower(ch));
    });
    return key;
}

bool MetadataStore::IsRootPath(const std::wstring& normalized_path)
{
    return normalized_path == L"\\";
}

bool MetadataStore::IsDescendantPath(const std::wstring& candidate_path, const std::wstring& parent_path)
{
    const auto candidate_key = CanonicalPathKey(candidate_path);
    const auto parent_key = CanonicalPathKey(parent_path);
    if (candidate_key.empty() || parent_key.empty())
    {
        return false;
    }
    if (candidate_key == parent_key)
    {
        return false;
    }

    auto parent_prefix = parent_key;
    if (!parent_prefix.empty() && parent_prefix.back() != L'\\')
    {
        parent_prefix.push_back(L'\\');
    }

    return candidate_key.rfind(parent_prefix, 0) == 0;
}

std::wstring MetadataStore::ParentPath(const std::wstring& normalized_path)
{
    if (normalized_path.empty() || IsRootPath(normalized_path))
    {
        return L"\\";
    }

    const auto last_separator = normalized_path.find_last_of(L'\\');
    if (last_separator == std::wstring::npos || last_separator == 0)
    {
        return L"\\";
    }

    return normalized_path.substr(0, last_separator);
}

std::wstring MetadataStore::LeafName(const std::wstring& normalized_path)
{
    if (normalized_path.empty() || IsRootPath(normalized_path))
    {
        return {};
    }

    const auto last_separator = normalized_path.find_last_of(L'\\');
    if (last_separator == std::wstring::npos)
    {
        return normalized_path;
    }

    return normalized_path.substr(last_separator + 1);
}

bool MetadataStore::EnsureRootState()
{
    const auto root_path = std::wstring(L"\\");
    const auto root_object_id = volume_root_block_ != 0 ? volume_root_block_ : StableObjectIdFromPath(root_path);

    if (committed_path_index_.empty() && !committed_inodes_.empty())
    {
        for (const auto& [object_id, inode] : committed_inodes_)
        {
            if (!inode.full_path.empty())
            {
                committed_path_index_[CanonicalPathKey(inode.full_path)] = object_id;
            }
        }
    }

    auto root_path_it = committed_path_index_.find(CanonicalPathKey(root_path));
    if (root_path_it == committed_path_index_.end())
    {
        InodeRecord root_inode{};
        root_inode.object_id = root_object_id;
        root_inode.parent_object_id = root_object_id;
        root_inode.name = L"";
        root_inode.full_path = root_path;
        root_inode.is_directory = true;
        root_inode.logical_size = 0;
        root_inode.data_physical_address = 0;
        root_inode.xid = checkpoint_xid_;
        committed_inodes_[root_inode.object_id] = root_inode;
        committed_path_index_[CanonicalPathKey(root_inode.full_path)] = root_inode.object_id;
    }
    else if (auto inode_it = committed_inodes_.find(root_path_it->second); inode_it == committed_inodes_.end())
    {
        InodeRecord root_inode{};
        root_inode.object_id = root_path_it->second;
        root_inode.parent_object_id = root_path_it->second;
        root_inode.name = L"";
        root_inode.full_path = root_path;
        root_inode.is_directory = true;
        root_inode.logical_size = 0;
        root_inode.data_physical_address = 0;
        root_inode.xid = checkpoint_xid_;
        committed_inodes_[root_inode.object_id] = root_inode;
    }

    committed_directory_links_.clear();
    committed_directory_links_.reserve(committed_inodes_.size());
    for (const auto& [object_id, inode] : committed_inodes_)
    {
        if (IsRootPath(inode.full_path))
        {
            continue;
        }

        committed_directory_links_.push_back(DirectoryLink
        {
            inode.parent_object_id,
            inode.name,
            object_id,
            inode.xid
        });
    }

    const auto graph_state_valid = ValidateInodeGraphState(
        committed_inodes_,
        committed_path_index_,
        committed_directory_links_,
        /*require_root_object=*/true);
    if (graph_state_valid)
    {
        RefreshObjectIdAllocator();
    }
    return graph_state_valid;
}

bool MetadataStore::ValidateInodeGraphState(
    const std::unordered_map<std::uint64_t, InodeRecord>& inode_table,
    const std::unordered_map<std::wstring, std::uint64_t>& path_index,
    const std::vector<DirectoryLink>& directory_links,
    bool require_root_object
) const
{
    if (inode_table.empty())
    {
        return !require_root_object;
    }

    const auto canonical_name_key = [](const std::wstring& name)
    {
        std::wstring key = name;
        std::transform(key.begin(), key.end(), key.begin(), [](wchar_t ch)
        {
            return static_cast<wchar_t>(std::towlower(ch));
        });
        return key;
    };
    const auto make_link_key = [&](std::uint64_t parent_object_id, const std::wstring& entry_name)
    {
        auto key = std::to_wstring(parent_object_id);
        key.push_back(L'|');
        key.append(canonical_name_key(entry_name));
        return key;
    };

    std::unordered_map<std::wstring, std::uint64_t> canonical_paths;
    canonical_paths.reserve(inode_table.size());
    std::size_t root_count = 0;
    for (const auto& [object_id, inode] : inode_table)
    {
        if (object_id == 0 || inode.full_path.empty())
        {
            return false;
        }

        const auto normalized_path = NormalizePath(inode.full_path);
        if (normalized_path != inode.full_path)
        {
            return false;
        }

        const auto path_key = CanonicalPathKey(inode.full_path);
        if (path_key.empty())
        {
            return false;
        }

        auto [path_it, inserted] = canonical_paths.emplace(path_key, object_id);
        if (!inserted && path_it->second != object_id)
        {
            return false;
        }

        auto indexed_it = path_index.find(path_key);
        if (indexed_it == path_index.end() || indexed_it->second != object_id)
        {
            return false;
        }

        const auto is_root = IsRootPath(inode.full_path);
        if (is_root)
        {
            ++root_count;
            if (!inode.is_directory ||
                inode.parent_object_id != object_id ||
                !inode.name.empty() ||
                inode.data_physical_address != 0 ||
                inode.logical_size != 0)
            {
                return false;
            }
        }
        else
        {
            if (inode.name.empty() ||
                LeafName(inode.full_path) != inode.name ||
                inode.parent_object_id == object_id)
            {
                return false;
            }

            auto parent_it = inode_table.find(inode.parent_object_id);
            if (parent_it == inode_table.end() || !parent_it->second.is_directory)
            {
                return false;
            }

            if (CanonicalPathKey(ParentPath(inode.full_path)) != CanonicalPathKey(parent_it->second.full_path))
            {
                return false;
            }
        }

        if (inode.is_directory)
        {
            if (inode.data_physical_address != 0 || inode.logical_size != 0)
            {
                return false;
            }
        }
        else
        {
            if ((inode.logical_size == 0 && inode.data_physical_address != 0) ||
                (inode.logical_size > 0 && inode.data_physical_address == 0))
            {
                return false;
            }
        }
    }

    if (require_root_object && root_count != 1)
    {
        return false;
    }

    if (path_index.size() != canonical_paths.size())
    {
        return false;
    }
    for (const auto& [path_key, object_id] : path_index)
    {
        auto inode_it = inode_table.find(object_id);
        if (inode_it == inode_table.end())
        {
            return false;
        }

        if (path_key != CanonicalPathKey(inode_it->second.full_path))
        {
            return false;
        }
    }

    std::unordered_map<std::wstring, std::uint64_t> expected_links;
    expected_links.reserve(inode_table.size());
    for (const auto& [object_id, inode] : inode_table)
    {
        if (IsRootPath(inode.full_path))
        {
            continue;
        }

        auto [it, inserted] = expected_links.emplace(
            make_link_key(inode.parent_object_id, inode.name),
            object_id);
        if (!inserted && it->second != object_id)
        {
            return false;
        }
    }

    if (directory_links.size() != expected_links.size())
    {
        return false;
    }
    std::unordered_set<std::wstring> seen_links;
    seen_links.reserve(directory_links.size());
    for (const auto& link : directory_links)
    {
        if (link.parent_object_id == 0 || link.child_object_id == 0 || link.entry_name.empty())
        {
            return false;
        }

        auto parent_it = inode_table.find(link.parent_object_id);
        auto child_it = inode_table.find(link.child_object_id);
        if (parent_it == inode_table.end() ||
            child_it == inode_table.end() ||
            !parent_it->second.is_directory)
        {
            return false;
        }

        if (child_it->second.parent_object_id != link.parent_object_id)
        {
            return false;
        }

        if (canonical_name_key(link.entry_name) != canonical_name_key(child_it->second.name))
        {
            return false;
        }

        const auto link_key = make_link_key(link.parent_object_id, link.entry_name);
        auto expected_it = expected_links.find(link_key);
        if (expected_it == expected_links.end() || expected_it->second != link.child_object_id)
        {
            return false;
        }

        if (!seen_links.emplace(link_key).second)
        {
            return false;
        }
    }

    for (const auto& [object_id, inode] : inode_table)
    {
        std::unordered_set<std::uint64_t> seen;
        seen.reserve(inode_table.size());

        auto cursor = object_id;
        bool reached_root = false;
        for (std::size_t steps = 0; steps <= inode_table.size(); ++steps)
        {
            if (!seen.emplace(cursor).second)
            {
                return false;
            }

            auto current_it = inode_table.find(cursor);
            if (current_it == inode_table.end())
            {
                return false;
            }

            if (IsRootPath(current_it->second.full_path))
            {
                reached_root = true;
                break;
            }

            cursor = current_it->second.parent_object_id;
        }

        if (!reached_root)
        {
            return false;
        }
    }

    return true;
}

void MetadataStore::RefreshObjectIdAllocator()
{
    std::uint64_t highest_object_id = 0;
    const auto consider_object_id = [&](std::uint64_t object_id)
    {
        if (object_id > highest_object_id)
        {
            highest_object_id = object_id;
        }
    };

    consider_object_id(volume_root_block_);
    for (const auto& [object_id, _] : committed_object_map_)
    {
        consider_object_id(object_id);
    }
    for (const auto& [object_id, _] : committed_inodes_)
    {
        consider_object_id(object_id);
    }
    for (const auto& [object_id, _] : working_inodes_)
    {
        consider_object_id(object_id);
    }
    for (const auto& update : pending_object_map_updates_)
    {
        consider_object_id(update.object_id);
    }

    if (highest_object_id == std::numeric_limits<std::uint64_t>::max())
    {
        next_generated_object_id_ = 1;
        return;
    }

    const auto candidate = highest_object_id + 1;
    if (candidate == 0)
    {
        next_generated_object_id_ = 1;
        return;
    }

    if (next_generated_object_id_ < candidate)
    {
        next_generated_object_id_ = candidate;
    }
}

std::uint64_t MetadataStore::ResolveUniqueObjectId(const std::wstring& normalized_path)
{
    const auto object_id_is_in_use = [&](std::uint64_t object_id)
    {
        if (object_id == 0 ||
            committed_object_map_.contains(object_id) ||
            committed_inodes_.contains(object_id) ||
            working_inodes_.contains(object_id))
        {
            return true;
        }

        for (const auto& update : pending_object_map_updates_)
        {
            if (update.object_id == object_id)
            {
                return true;
            }
        }
        return false;
    };

    auto candidate = next_generated_object_id_;
    if (candidate == 0)
    {
        candidate = 1;
    }
    if (candidate <= volume_root_block_)
    {
        candidate = volume_root_block_ + 1;
        if (candidate == 0)
        {
            candidate = 1;
        }
    }

    constexpr std::uint32_t kMonotonicProbeLimit = 65536;
    for (std::uint32_t probe = 0; probe < kMonotonicProbeLimit; ++probe)
    {
        if (!object_id_is_in_use(candidate))
        {
            next_generated_object_id_ = candidate + 1;
            if (next_generated_object_id_ == 0)
            {
                next_generated_object_id_ = 1;
            }
            return candidate;
        }

        ++candidate;
        if (candidate == 0)
        {
            candidate = 1;
        }
    }

    candidate = StableObjectIdFromPath(normalized_path);
    if (candidate == 0)
    {
        candidate = 1;
    }

    constexpr std::uint32_t kFallbackProbeLimit = 4096;
    const auto normalized_key = CanonicalPathKey(normalized_path);
    for (std::uint32_t probe = 0; probe < kFallbackProbeLimit; ++probe)
    {
        auto existing = working_inodes_.find(candidate);
        if ((existing == working_inodes_.end() ||
             CanonicalPathKey(existing->second.full_path) == normalized_key) &&
            !object_id_is_in_use(candidate))
        {
            next_generated_object_id_ = candidate + 1;
            if (next_generated_object_id_ == 0)
            {
                next_generated_object_id_ = 1;
            }
            return candidate;
        }

        ++candidate;
        if (candidate == 0)
        {
            candidate = 1;
        }
    }

    const auto stable_candidate = StableObjectIdFromPath(normalized_path);
    next_generated_object_id_ = stable_candidate + 1;
    if (next_generated_object_id_ == 0)
    {
        next_generated_object_id_ = 1;
    }
    return stable_candidate == 0 ? 1 : stable_candidate;
}

bool MetadataStore::IsDirectoryInWorkingState(const std::wstring& normalized_path) const
{
    auto inode = LookupWorkingInode(normalized_path);
    return inode.has_value() && inode->is_directory;
}

std::optional<MetadataStore::InodeRecord> MetadataStore::LookupWorkingInode(const std::wstring& normalized_path) const
{
    auto index = working_path_index_.find(CanonicalPathKey(normalized_path));
    if (index == working_path_index_.end())
    {
        return std::nullopt;
    }

    auto inode = working_inodes_.find(index->second);
    if (inode == working_inodes_.end())
    {
        return std::nullopt;
    }

    return inode->second;
}

bool MetadataStore::HasWorkingChildren(std::uint64_t parent_object_id) const
{
    for (const auto& [object_id, inode] : working_inodes_)
    {
        if (object_id != parent_object_id && inode.parent_object_id == parent_object_id)
        {
            return true;
        }
    }

    return false;
}

void MetadataStore::UpsertWorkingDirectoryLink(
    std::uint64_t parent_object_id,
    const std::wstring& entry_name,
    std::uint64_t child_object_id,
    std::uint64_t xid
)
{
    for (auto& link : working_directory_links_)
    {
        if (link.parent_object_id == parent_object_id &&
            link.entry_name == entry_name)
        {
            link.child_object_id = child_object_id;
            link.xid = xid;
            return;
        }
    }

    working_directory_links_.push_back(DirectoryLink
    {
        parent_object_id,
        entry_name,
        child_object_id,
        xid
    });
}

void MetadataStore::RemoveWorkingDirectoryLink(std::uint64_t parent_object_id, const std::wstring& entry_name)
{
    working_directory_links_.erase(
        std::remove_if(
            working_directory_links_.begin(),
            working_directory_links_.end(),
            [&](const DirectoryLink& link)
            {
                return link.parent_object_id == parent_object_id &&
                       link.entry_name == entry_name;
            }),
        working_directory_links_.end()
    );
}

bool MetadataStore::IsLikelyRawDevicePath(const std::wstring& path)
{
    if (path.empty())
    {
        return false;
    }

    std::wstring normalized = path;
    std::transform(normalized.begin(), normalized.end(), normalized.begin(), [](wchar_t c)
    {
        return static_cast<wchar_t>(std::towlower(c));
    });

    return normalized.rfind(LR"(\\.\physicaldrive)", 0) == 0 ||
           normalized.rfind(LR"(\\?\physicaldrive)", 0) == 0;
}

bool MetadataStore::IsFixtureImagePath(const std::wstring& path)
{
    if (path.empty() || IsLikelyRawDevicePath(path))
    {
        return false;
    }

    std::wstring normalized = path;
    std::transform(normalized.begin(), normalized.end(), normalized.begin(), [](wchar_t c)
    {
        return static_cast<wchar_t>(std::towlower(c));
    });

    const auto has_suffix = [&normalized](std::wstring_view suffix) -> bool
    {
        if (normalized.size() < suffix.size())
        {
            return false;
        }
        return normalized.compare(normalized.size() - suffix.size(), suffix.size(), suffix.data(), suffix.size()) == 0;
    };

    if (has_suffix(L".apfs.img") ||
        has_suffix(L".img") ||
        has_suffix(L".apfs.fixture"))
    {
        return true;
    }

    std::filesystem::path device_path(path);
    auto extension = device_path.extension().wstring();
    std::transform(extension.begin(), extension.end(), extension.begin(), [](wchar_t c)
    {
        return static_cast<wchar_t>(std::towlower(c));
    });
    if (extension == L".img" || extension == L".apfs" || extension == L".fixture")
    {
        return true;
    }

    // Do not infer fixture mode from parent-directory naming (for example,
    // "...\\fixtures\\volume.bin"). Production/non-fixture eligibility must be
    // determined by explicit image naming, not incidental folder segments.
    return false;
}

bool MetadataStore::StageObjectMapUpdate(
    std::uint64_t object_id,
    std::uint64_t physical_address,
    std::uint64_t logical_size
)
{
    if (!IsNativeWriteReady() || object_id == 0)
    {
        return false;
    }

    ObjectMapUpdate next_update
    {
        object_id,
        physical_address,
        logical_size,
        checkpoint_xid_ + 1
    };

    for (auto& pending : pending_object_map_updates_)
    {
        if (pending.object_id == object_id)
        {
            pending = next_update;
            return true;
        }
    }

    pending_object_map_updates_.push_back(next_update);
    return true;
}

bool MetadataStore::StageSpacemanAllocation(std::uint64_t physical_address, std::uint64_t bytes)
{
    if (!IsNativeWriteReady() || physical_address == 0 || bytes == 0)
    {
        return false;
    }

    const auto aligned_bytes = AlignExtentBytes(bytes);
    if (aligned_bytes == 0)
    {
        return false;
    }
    if (physical_address > (std::numeric_limits<std::uint64_t>::max() - aligned_bytes))
    {
        return false;
    }
    if (total_blocks_ != 0)
    {
        if (block_size_ == 0 ||
            total_blocks_ > (std::numeric_limits<std::uint64_t>::max() / static_cast<std::uint64_t>(block_size_)))
        {
            return false;
        }
        const auto container_bytes = total_blocks_ * static_cast<std::uint64_t>(block_size_);
        if ((physical_address + aligned_bytes) > container_bytes)
        {
            return false;
        }
    }
    if (ExtentOverlapsReservedMetadata(physical_address, aligned_bytes))
    {
        return false;
    }

    pending_spaceman_allocations_.push_back(SpacemanAllocation
    {
        physical_address,
        aligned_bytes
    });
    return true;
}

bool MetadataStore::StageSpacemanDeallocation(std::uint64_t physical_address, std::uint64_t bytes)
{
    if (!IsNativeWriteReady() || physical_address == 0 || bytes == 0)
    {
        return false;
    }

    const auto aligned_bytes = AlignExtentBytes(bytes);
    if (aligned_bytes == 0)
    {
        return false;
    }
    if (physical_address > (std::numeric_limits<std::uint64_t>::max() - aligned_bytes))
    {
        return false;
    }
    if (total_blocks_ != 0)
    {
        if (block_size_ == 0 ||
            total_blocks_ > (std::numeric_limits<std::uint64_t>::max() / static_cast<std::uint64_t>(block_size_)))
        {
            return false;
        }
        const auto container_bytes = total_blocks_ * static_cast<std::uint64_t>(block_size_);
        if ((physical_address + aligned_bytes) > container_bytes)
        {
            return false;
        }
    }
    if (ExtentOverlapsReservedMetadata(physical_address, aligned_bytes))
    {
        return false;
    }

    pending_spaceman_deallocations_.push_back(SpacemanAllocation
    {
        physical_address,
        aligned_bytes
    });
    return true;
}

std::uint64_t MetadataStore::AlignExtentBytes(std::uint64_t bytes) const noexcept
{
    if (bytes == 0)
    {
        return 0;
    }

    const auto block = static_cast<std::uint64_t>(std::max<std::uint32_t>(1u, block_size_));
    auto aligned_bytes = std::max<std::uint64_t>(bytes, block);
    const auto remainder = aligned_bytes % block;
    if (remainder != 0)
    {
        if (aligned_bytes > (std::numeric_limits<std::uint64_t>::max() - (block - remainder)))
        {
            return 0;
        }
        aligned_bytes += block - remainder;
    }
    return aligned_bytes;
}

bool MetadataStore::ExtentOverlapsReservedMetadata(
    std::uint64_t physical_address,
    std::uint64_t bytes) const
{
    if (physical_address == 0 || bytes == 0)
    {
        return true;
    }

    const auto block_bytes = static_cast<std::uint64_t>(std::max<std::uint32_t>(1u, block_size_));
    if ((physical_address % block_bytes) != 0 || (bytes % block_bytes) != 0)
    {
        return true;
    }
    if (physical_address > (std::numeric_limits<std::uint64_t>::max() - bytes))
    {
        return true;
    }

    const auto first_block = physical_address / block_bytes;
    const auto block_count = bytes / block_bytes;
    if (block_count == 0)
    {
        return true;
    }
    if (first_block > (std::numeric_limits<std::uint64_t>::max() - (block_count - 1)))
    {
        return true;
    }

    const auto replay_checkpoint_blocks = ResolveReplayCheckpointBlockIndices();
    for (std::uint64_t index = 0; index < block_count; ++index)
    {
        const auto block = first_block + index;
        if (IsReservedMetadataBlock(block) ||
            std::find(replay_checkpoint_blocks.begin(), replay_checkpoint_blocks.end(), block) != replay_checkpoint_blocks.end())
        {
            return true;
        }
    }
    return false;
}

bool MetadataStore::ValidateCommitBlobLocation(
    std::uint64_t physical_address,
    std::uint64_t bytes) const
{
    if (physical_address == 0 ||
        bytes < 64 ||
        bytes > (16ull * 1024ull * 1024ull))
    {
        return false;
    }

    const auto aligned_bytes = AlignExtentBytes(bytes);
    if (aligned_bytes == 0 ||
        aligned_bytes != bytes ||
        physical_address > (std::numeric_limits<std::uint64_t>::max() - aligned_bytes))
    {
        return false;
    }

    const auto block_bytes = static_cast<std::uint64_t>(std::max<std::uint32_t>(1u, block_size_));
    if ((physical_address % block_bytes) != 0 ||
        (aligned_bytes % block_bytes) != 0)
    {
        return false;
    }

    if (total_blocks_ != 0)
    {
        if (block_size_ == 0 ||
            total_blocks_ > (std::numeric_limits<std::uint64_t>::max() / static_cast<std::uint64_t>(block_size_)))
        {
            return false;
        }

        const auto container_bytes = total_blocks_ * static_cast<std::uint64_t>(block_size_);
        if ((physical_address + aligned_bytes) > container_bytes)
        {
            return false;
        }
    }

    return !ExtentOverlapsReservedMetadata(physical_address, aligned_bytes);
}

bool MetadataStore::IsLegacyFixtureFallbackAllowedForCurrentContext() const noexcept
{
    return context_.allow_legacy_scaffold_for_fixtures &&
           IsFixtureImagePath(context_.device_path);
}

bool MetadataStore::RequiresCanonicalNonFixtureCommitPath() const noexcept
{
    if (IsFixtureImagePath(context_.device_path))
    {
        return false;
    }

    // All non-fixture media uses canonical commit/replay semantics. Fixture-only
    // compatibility controls must never relax production non-fixture safety paths.
    return true;
}

bool MetadataStore::ShouldAcceptScaffoldCommitBlobForCurrentContext() const noexcept
{
    const auto is_fixture_image = IsFixtureImagePath(context_.device_path);
    if (!is_fixture_image)
    {
        // Legacy scaffold replay compatibility is fixture-only.
        return false;
    }

    if (!IsLegacyFixtureFallbackAllowedForCurrentContext())
    {
        return false;
    }

    // Fixture media keeps legacy scaffold replay compatibility to recover older
    // interrupted fixture commits during test/image migration workflows.
    return legacy_fixture_fallback_used_ || is_fixture_image;
}

bool MetadataStore::ShouldUseScaffoldCommitBlobForCurrentContext() const noexcept
{
    const auto is_fixture_image = IsFixtureImagePath(context_.device_path);
    if (!is_fixture_image)
    {
        // Non-fixture commits always emit canonical commit blobs. Relaxed
        // compatibility flags only affect replay acceptance for fixture/debug flows.
        return false;
    }

    return IsLegacyFixtureFallbackAllowedForCurrentContext() &&
           legacy_fixture_fallback_used_;
}

void MetadataStore::SyncCommitBlobTelemetryWithMode() noexcept
{
    uses_scaffold_commit_blob_ = ShouldUseScaffoldCommitBlobForCurrentContext();
    last_commit_blob_magic_ = uses_scaffold_commit_blob_
        ? "APFSRWSCAFF3"
        : "APFSRWCANON3";
}

bool MetadataStore::ValidateReplayCommitBlobCandidate(
    std::uint64_t physical_address,
    std::uint64_t bytes,
    std::uint64_t expected_source_xid,
    std::uint64_t expected_target_xid) const
{
    if (!ValidateCommitBlobLocation(physical_address, bytes))
    {
        return false;
    }

    std::vector<std::byte> commit_blob;
    if (!device_.Read(physical_address, static_cast<std::size_t>(bytes), commit_blob))
    {
        return false;
    }
    if (commit_blob.size() < static_cast<std::size_t>(bytes))
    {
        return false;
    }

    constexpr std::array<char, 13> kCommitBlobMagicCanonicalV3 =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'C', 'A', 'N', 'O', 'N', '3', '\0'
    };
    constexpr std::array<char, 13> kCommitBlobMagicScaffoldV2 =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'S', 'C', 'A', 'F', 'F', '2', '\0'
    };
    constexpr std::array<char, 13> kCommitBlobMagicScaffoldV3 =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'S', 'C', 'A', 'F', 'F', '3', '\0'
    };
    constexpr std::size_t kCommitBlobBaseHeaderBytes = 13 + 8 + 8 + 4 + 4 + 4 + 4 + 4;
    constexpr std::size_t kCommitBlobChecksumFieldOffset = kCommitBlobBaseHeaderBytes;
    constexpr std::size_t kCommitBlobHeaderBytesV3 = kCommitBlobBaseHeaderBytes + sizeof(std::uint32_t);

    if (commit_blob.size() < kCommitBlobBaseHeaderBytes)
    {
        return false;
    }

    const auto matches_magic = [&](const std::array<char, 13>& magic) -> bool
    {
        for (std::size_t index = 0; index < magic.size(); ++index)
        {
            if (std::to_integer<unsigned char>(commit_blob[index]) != static_cast<unsigned char>(magic[index]))
            {
                return false;
            }
        }
        return true;
    };

    enum class CommitBlobMagicKind
    {
        Unknown,
        CanonicalV3,
        ScaffoldV3,
        ScaffoldV2,
    };
    const auto detected_magic = [&]() -> CommitBlobMagicKind
    {
        if (matches_magic(kCommitBlobMagicCanonicalV3))
        {
            return CommitBlobMagicKind::CanonicalV3;
        }
        if (matches_magic(kCommitBlobMagicScaffoldV3))
        {
            return CommitBlobMagicKind::ScaffoldV3;
        }
        if (matches_magic(kCommitBlobMagicScaffoldV2))
        {
            return CommitBlobMagicKind::ScaffoldV2;
        }
        return CommitBlobMagicKind::Unknown;
    }();
    if (detected_magic == CommitBlobMagicKind::Unknown)
    {
        return false;
    }
    const auto require_canonical_replay_candidate = RequiresCanonicalNonFixtureCommitPath();
    if (require_canonical_replay_candidate &&
        detected_magic != CommitBlobMagicKind::CanonicalV3)
    {
        return false;
    }
    const auto allow_scaffold_commit_blob = ShouldAcceptScaffoldCommitBlobForCurrentContext();
    if ((detected_magic == CommitBlobMagicKind::ScaffoldV3 ||
         detected_magic == CommitBlobMagicKind::ScaffoldV2) &&
        !allow_scaffold_commit_blob)
    {
        return false;
    }
    const bool commit_blob_has_checksum =
        detected_magic == CommitBlobMagicKind::CanonicalV3 ||
        detected_magic == CommitBlobMagicKind::ScaffoldV3;

    const auto commit_blob_header_bytes =
        commit_blob_has_checksum ? kCommitBlobHeaderBytesV3 : kCommitBlobBaseHeaderBytes;
    if (commit_blob.size() < commit_blob_header_bytes)
    {
        return false;
    }

    const auto source_xid = ReadLe64(commit_blob, 13);
    const auto target_xid = ReadLe64(commit_blob, 21);
    if (source_xid != expected_source_xid ||
        target_xid != expected_target_xid)
    {
        return false;
    }

    const auto mutation_count = ReadLe32(commit_blob, 29);
    const auto object_map_updates = ReadLe32(commit_blob, 33);
    const auto spaceman_allocations = ReadLe32(commit_blob, 37);
    const auto spaceman_deallocations = ReadLe32(commit_blob, 41);
    const auto btree_records = ReadLe32(commit_blob, 45);

    const auto mutation_component_total =
        static_cast<std::uint64_t>(object_map_updates) +
        static_cast<std::uint64_t>(spaceman_allocations) +
        static_cast<std::uint64_t>(spaceman_deallocations) +
        static_cast<std::uint64_t>(btree_records);
    if (mutation_count == 0 || mutation_component_total == 0 ||
        mutation_count > mutation_component_total)
    {
        return false;
    }

    const auto commit_blob_payload_checksum =
        commit_blob_has_checksum ? ReadLe32(commit_blob, kCommitBlobChecksumFieldOffset) : 0;
    const auto payload_capacity = static_cast<std::uint64_t>(commit_blob.size() - commit_blob_header_bytes);
    const auto checked_multiply = [](std::uint32_t value, std::uint64_t unit_bytes, std::uint64_t& out_bytes) -> bool
    {
        if (unit_bytes == 0)
        {
            out_bytes = 0;
            return true;
        }
        if (value > (std::numeric_limits<std::uint64_t>::max() / unit_bytes))
        {
            return false;
        }
        out_bytes = static_cast<std::uint64_t>(value) * unit_bytes;
        return true;
    };
    const auto checked_add = [](std::uint64_t lhs, std::uint64_t rhs, std::uint64_t& out_sum) -> bool
    {
        if (lhs > (std::numeric_limits<std::uint64_t>::max() - rhs))
        {
            return false;
        }
        out_sum = lhs + rhs;
        return true;
    };

    std::uint64_t object_map_min_bytes = 0;
    std::uint64_t spaceman_allocation_min_bytes = 0;
    std::uint64_t spaceman_deallocation_min_bytes = 0;
    std::uint64_t btree_min_bytes = 0;
    if (!checked_multiply(object_map_updates, 32ull, object_map_min_bytes) ||
        !checked_multiply(spaceman_allocations, 16ull, spaceman_allocation_min_bytes) ||
        !checked_multiply(spaceman_deallocations, 16ull, spaceman_deallocation_min_bytes) ||
        !checked_multiply(btree_records, 17ull, btree_min_bytes))
    {
        return false;
    }
    std::uint64_t minimum_payload_bytes = 0;
    if (!checked_add(object_map_min_bytes, spaceman_allocation_min_bytes, minimum_payload_bytes) ||
        !checked_add(minimum_payload_bytes, spaceman_deallocation_min_bytes, minimum_payload_bytes) ||
        !checked_add(minimum_payload_bytes, btree_min_bytes, minimum_payload_bytes))
    {
        return false;
    }
    if (minimum_payload_bytes > payload_capacity)
    {
        return false;
    }

    std::unordered_set<std::uint64_t> parsed_object_map_object_ids;
    struct ReplayExtent
    {
        std::uint64_t physical_address = 0;
        std::uint64_t bytes = 0;
    };
    std::vector<ReplayExtent> parsed_spaceman_allocations;
    std::vector<ReplayExtent> parsed_spaceman_deallocations;
    try
    {
        parsed_object_map_object_ids.reserve(object_map_updates);
        parsed_spaceman_allocations.reserve(spaceman_allocations);
        parsed_spaceman_deallocations.reserve(spaceman_deallocations);
    }
    catch (...)
    {
        return false;
    }

    std::size_t cursor = commit_blob_header_bytes;
    const auto advance = [&](std::uint64_t delta_bytes) -> bool
    {
        if (delta_bytes > (std::numeric_limits<std::size_t>::max() - cursor))
        {
            return false;
        }
        const auto next = cursor + static_cast<std::size_t>(delta_bytes);
        if (next > commit_blob.size())
        {
            return false;
        }
        cursor = next;
        return true;
    };

    for (std::uint32_t index = 0; index < object_map_updates; ++index)
    {
        if (cursor > commit_blob.size() || 32 > (commit_blob.size() - cursor))
        {
            return false;
        }
        const auto object_id = ReadLe64(commit_blob, cursor + 0);
        const auto object_physical = ReadLe64(commit_blob, cursor + 8);
        const auto object_logical = ReadLe64(commit_blob, cursor + 16);
        const auto object_xid = ReadLe64(commit_blob, cursor + 24);
        cursor += 32;
        if (object_id == 0 ||
            object_xid != expected_target_xid ||
            ((object_physical == 0) != (object_logical == 0)))
        {
            return false;
        }
        if (!parsed_object_map_object_ids.insert(object_id).second)
        {
            return false;
        }
    }

    for (std::uint32_t index = 0; index < spaceman_allocations; ++index)
    {
        if (cursor > commit_blob.size() || 16 > (commit_blob.size() - cursor))
        {
            return false;
        }
        const auto allocation_address = ReadLe64(commit_blob, cursor + 0);
        const auto allocation_bytes = ReadLe64(commit_blob, cursor + 8);
        cursor += 16;
        if (allocation_address == 0 || allocation_bytes == 0)
        {
            return false;
        }
        const auto aligned_bytes = AlignExtentBytes(allocation_bytes);
        if (aligned_bytes == 0 ||
            aligned_bytes != allocation_bytes ||
            ExtentOverlapsReservedMetadata(allocation_address, allocation_bytes))
        {
            return false;
        }
        parsed_spaceman_allocations.push_back({allocation_address, allocation_bytes});
    }

    for (std::uint32_t index = 0; index < spaceman_deallocations; ++index)
    {
        if (cursor > commit_blob.size() || 16 > (commit_blob.size() - cursor))
        {
            return false;
        }
        const auto deallocation_address = ReadLe64(commit_blob, cursor + 0);
        const auto deallocation_bytes = ReadLe64(commit_blob, cursor + 8);
        cursor += 16;
        if (deallocation_address == 0 || deallocation_bytes == 0)
        {
            return false;
        }
        const auto aligned_bytes = AlignExtentBytes(deallocation_bytes);
        if (aligned_bytes == 0 || aligned_bytes != deallocation_bytes)
        {
            return false;
        }
        parsed_spaceman_deallocations.push_back({deallocation_address, deallocation_bytes});
    }

    for (std::uint32_t index = 0; index < btree_records; ++index)
    {
        if (cursor > commit_blob.size() || 16 > (commit_blob.size() - cursor))
        {
            return false;
        }

        const auto kind_value = ReadLe32(commit_blob, cursor + 0);
        const auto tombstone_flag = ReadLe32(commit_blob, cursor + 4);
        const auto key_size = ReadLe32(commit_blob, cursor + 8);
        const auto value_size = ReadLe32(commit_blob, cursor + 12);
        cursor += 16;

        if (kind_value < static_cast<std::uint32_t>(BtreeRecordKind::Inode) ||
            kind_value > static_cast<std::uint32_t>(BtreeRecordKind::FileExtent) ||
            tombstone_flag > 1)
        {
            return false;
        }

        const auto payload_size = static_cast<std::uint64_t>(key_size) + static_cast<std::uint64_t>(value_size);
        const auto key_offset = cursor;
        if (!advance(payload_size))
        {
            return false;
        }
        if (key_size == 0)
        {
            return false;
        }
        if (std::to_integer<unsigned char>(commit_blob[key_offset]) != static_cast<unsigned char>(kind_value))
        {
            return false;
        }
    }

    const auto validate_no_overlap = [](std::vector<ReplayExtent>& extents) -> bool
    {
        if (extents.empty())
        {
            return true;
        }

        std::sort(
            extents.begin(),
            extents.end(),
            [](const ReplayExtent& lhs, const ReplayExtent& rhs)
            {
                if (lhs.physical_address == rhs.physical_address)
                {
                    return lhs.bytes < rhs.bytes;
                }
                return lhs.physical_address < rhs.physical_address;
            });

        std::optional<std::uint64_t> previous_end;
        for (const auto& extent : extents)
        {
            if (extent.physical_address == 0 || extent.bytes == 0)
            {
                return false;
            }
            if (extent.physical_address > (std::numeric_limits<std::uint64_t>::max() - extent.bytes))
            {
                return false;
            }
            const auto extent_end = extent.physical_address + extent.bytes;
            if (previous_end.has_value() && extent.physical_address < previous_end.value())
            {
                return false;
            }
            previous_end = extent_end;
        }
        return true;
    };

    if (!validate_no_overlap(parsed_spaceman_allocations) ||
        !validate_no_overlap(parsed_spaceman_deallocations))
    {
        return false;
    }

    if (!parsed_spaceman_allocations.empty() && !parsed_spaceman_deallocations.empty())
    {
        std::size_t allocation_index = 0;
        std::size_t deallocation_index = 0;
        while (allocation_index < parsed_spaceman_allocations.size() &&
               deallocation_index < parsed_spaceman_deallocations.size())
        {
            const auto& allocation = parsed_spaceman_allocations[allocation_index];
            const auto& deallocation = parsed_spaceman_deallocations[deallocation_index];
            const auto allocation_end = allocation.physical_address + allocation.bytes;
            const auto deallocation_end = deallocation.physical_address + deallocation.bytes;

            if (allocation_end <= deallocation.physical_address)
            {
                ++allocation_index;
                continue;
            }
            if (deallocation_end <= allocation.physical_address)
            {
                ++deallocation_index;
                continue;
            }

            if (allocation.physical_address == deallocation.physical_address &&
                allocation.bytes == deallocation.bytes)
            {
                ++allocation_index;
                ++deallocation_index;
                continue;
            }

            if (allocation.physical_address < deallocation_end &&
                deallocation.physical_address < allocation_end)
            {
                return false;
            }
        }
    }

    if (commit_blob_has_checksum)
    {
        const auto payload_bytes = cursor - commit_blob_header_bytes;
        const auto computed_payload_checksum = UpdateFnv1a(
            kCheckpointChecksumSeed,
            commit_blob.data() + static_cast<std::vector<std::byte>::difference_type>(commit_blob_header_bytes),
            payload_bytes);
        if (commit_blob_payload_checksum != computed_payload_checksum)
        {
            return false;
        }
    }

    if (cursor > commit_blob.size())
    {
        return false;
    }
    for (std::size_t index = cursor; index < commit_blob.size(); ++index)
    {
        if (commit_blob[index] != std::byte{0})
        {
            return false;
        }
    }

    return true;
}

bool MetadataStore::ValidatePendingCommitState() const
{
    if (pending_mutations_.empty())
    {
        return false;
    }
    if (!ValidateInodeGraphState(
            committed_inodes_,
            committed_path_index_,
            committed_directory_links_,
            /*require_root_object=*/true))
    {
        return false;
    }
    if (!ValidateInodeGraphState(
            working_inodes_,
            working_path_index_,
            working_directory_links_,
            /*require_root_object=*/true))
    {
        return false;
    }

    std::optional<std::uint64_t> container_bytes;
    if (total_blocks_ != 0)
    {
        if (block_size_ == 0 ||
            total_blocks_ > (std::numeric_limits<std::uint64_t>::max() / static_cast<std::uint64_t>(block_size_)))
        {
            return false;
        }
        container_bytes = total_blocks_ * static_cast<std::uint64_t>(block_size_);
    }

    const auto is_valid_extent = [this, &container_bytes](const SpacemanAllocation& extent) -> bool
    {
        if (extent.physical_address == 0 || extent.bytes == 0)
        {
            return false;
        }
        if (ExtentOverlapsReservedMetadata(extent.physical_address, extent.bytes))
        {
            return false;
        }
        if (AlignExtentBytes(extent.bytes) != extent.bytes)
        {
            return false;
        }
        if (extent.physical_address > (std::numeric_limits<std::uint64_t>::max() - extent.bytes))
        {
            return false;
        }
        if (container_bytes.has_value() && (extent.physical_address + extent.bytes) > container_bytes.value())
        {
            return false;
        }
        return true;
    };

    const auto overlaps = [](const SpacemanAllocation& lhs, const SpacemanAllocation& rhs) -> bool
    {
        const auto lhs_begin = lhs.physical_address;
        const auto lhs_end = lhs.physical_address + lhs.bytes;
        const auto rhs_begin = rhs.physical_address;
        const auto rhs_end = rhs.physical_address + rhs.bytes;
        return lhs_begin < rhs_end && rhs_begin < lhs_end;
    };
    const auto has_allocation_for_physical = [&](std::uint64_t physical_address, std::uint64_t logical_size) -> bool
    {
        if (physical_address == 0 || logical_size == 0)
        {
            return false;
        }

        const auto required_bytes = AlignExtentBytes(logical_size);
        if (required_bytes == 0)
        {
            return false;
        }

        for (const auto& allocation : pending_spaceman_allocations_)
        {
            if (allocation.physical_address == physical_address &&
                allocation.bytes >= required_bytes)
            {
                return true;
            }
        }
        for (const auto& allocation : committed_spaceman_allocations_)
        {
            if (allocation.physical_address == physical_address &&
                allocation.bytes >= required_bytes)
            {
                return true;
            }
        }
        return false;
    };

    std::unordered_map<std::uint64_t, ObjectMapUpdate> effective_object_map = committed_object_map_;

    for (const auto& update : pending_object_map_updates_)
    {
        if (update.object_id == 0 ||
            update.xid != checkpoint_xid_ + 1)
        {
            return false;
        }
        effective_object_map[update.object_id] = update;
    }

    std::vector<ApfsObjectMapEntry> effective_object_entries;
    effective_object_entries.reserve(effective_object_map.size());
    for (const auto& [_, update] : effective_object_map)
    {
        effective_object_entries.push_back(
            {
                update.object_id,
                update.physical_address,
                update.logical_size,
                update.xid,
            });
    }
    ApfsObjectMapStore object_map_store;
    if (!object_map_store.ValidateEntries(effective_object_entries))
    {
        return false;
    }

    for (const auto& allocation : pending_spaceman_allocations_)
    {
        if (!is_valid_extent(allocation))
        {
            return false;
        }
        for (const auto& committed_allocation : committed_spaceman_allocations_)
        {
            if (overlaps(allocation, committed_allocation))
            {
                return false;
            }
        }
    }
    for (std::size_t i = 0; i < pending_spaceman_allocations_.size(); ++i)
    {
        for (std::size_t j = i + 1; j < pending_spaceman_allocations_.size(); ++j)
        {
            if (overlaps(pending_spaceman_allocations_[i], pending_spaceman_allocations_[j]))
            {
                return false;
            }
        }
    }
    for (const auto& allocation : pending_spaceman_allocations_)
    {
        for (const auto& deallocation : pending_spaceman_deallocations_)
        {
            if (!overlaps(allocation, deallocation))
            {
                continue;
            }

            if (allocation.physical_address == deallocation.physical_address &&
                allocation.bytes == deallocation.bytes)
            {
                continue;
            }

            return false;
        }
    }

    std::set<std::uint64_t> live_extent_addresses;
    for (const auto& [object_id, inode] : working_inodes_)
    {
        if (inode.is_directory ||
            inode.data_physical_address == 0 ||
            inode.logical_size == 0)
        {
            continue;
        }

        const auto mapped = effective_object_map.find(object_id);
        if (mapped == effective_object_map.end())
        {
            return false;
        }
        if (mapped->second.physical_address != inode.data_physical_address ||
            mapped->second.logical_size != inode.logical_size)
        {
            return false;
        }
        if (!has_allocation_for_physical(inode.data_physical_address, inode.logical_size))
        {
            return false;
        }

        live_extent_addresses.insert(inode.data_physical_address);
    }

    for (const auto& entry : effective_object_map)
    {
        const auto& update = entry.second;
        if (update.physical_address == 0 || update.logical_size == 0)
        {
            continue;
        }
        if (!has_allocation_for_physical(update.physical_address, update.logical_size))
        {
            return false;
        }
    }

    std::set<std::pair<std::uint64_t, std::uint64_t>> seen_deallocations;
    for (const auto& deallocation : pending_spaceman_deallocations_)
    {
        if (!is_valid_extent(deallocation))
        {
            return false;
        }
        if (!seen_deallocations.emplace(deallocation.physical_address, deallocation.bytes).second)
        {
            return false;
        }
        if (live_extent_addresses.contains(deallocation.physical_address))
        {
            return false;
        }

        bool matched = false;
        for (const auto& allocation : committed_spaceman_allocations_)
        {
            if (allocation.physical_address == deallocation.physical_address &&
                allocation.bytes == deallocation.bytes)
            {
                matched = true;
                break;
            }
        }
        if (!matched)
        {
            for (const auto& allocation : pending_spaceman_allocations_)
            {
                if (allocation.physical_address == deallocation.physical_address &&
                    allocation.bytes == deallocation.bytes)
                {
                    matched = true;
                    break;
                }
            }
        }
        if (!matched)
        {
            return false;
        }
    }

    std::vector<ApfsExtent> projected_allocations;
    projected_allocations.reserve(committed_spaceman_allocations_.size() + pending_spaceman_allocations_.size());
    for (const auto& allocation : committed_spaceman_allocations_)
    {
        bool removed_by_deallocation = false;
        for (const auto& deallocation : pending_spaceman_deallocations_)
        {
            if (allocation.physical_address == deallocation.physical_address &&
                allocation.bytes == deallocation.bytes)
            {
                removed_by_deallocation = true;
                break;
            }
        }
        if (!removed_by_deallocation)
        {
            projected_allocations.push_back(
                {
                    allocation.physical_address,
                    allocation.bytes,
                });
        }
    }
    for (const auto& allocation : pending_spaceman_allocations_)
    {
        projected_allocations.push_back(
            {
                allocation.physical_address,
                allocation.bytes,
            });
    }

    std::vector<ApfsExtent> projected_free_extents;
    projected_free_extents.reserve(working_spaceman_free_extents_.size());
    for (const auto& extent : working_spaceman_free_extents_)
    {
        projected_free_extents.push_back(
            {
                extent.physical_address,
                extent.bytes,
            });
    }

    ApfsSpacemanStore spaceman_store;
    if (!spaceman_store.ValidateState(projected_allocations, projected_free_extents))
    {
        return false;
    }

    for (const auto& record : pending_btree_records_)
    {
        if (record.key.empty() ||
            record.kind < BtreeRecordKind::Inode ||
            record.kind > BtreeRecordKind::FileExtent)
        {
            return false;
        }
        if (std::to_integer<unsigned char>(record.key.front()) != static_cast<unsigned char>(record.kind))
        {
            return false;
        }
    }

    auto projected_btree_records = committed_btree_records_;
    projected_btree_records.insert(
        projected_btree_records.end(),
        pending_btree_records_.begin(),
        pending_btree_records_.end());
    projected_btree_records = CanonicalizeBtreeRecords(projected_btree_records);

    std::size_t expected_non_root_inode_count = 0;
    std::size_t expected_extent_count = 0;
    for (const auto& [_, inode] : working_inodes_)
    {
        if (IsRootPath(inode.full_path))
        {
            continue;
        }

        ++expected_non_root_inode_count;
        if (!inode.is_directory &&
            inode.logical_size > 0 &&
            inode.data_physical_address != 0)
        {
            ++expected_extent_count;
        }
    }

    ApfsVolumeTreeStore volume_tree_store;
    ApfsVolumeTreeProjection volume_tree_projection{};
    std::wstring volume_tree_error;
    if (!volume_tree_store.TryProjectFromBtreeRecords(
            projected_btree_records,
            volume_tree_projection,
            volume_tree_error))
    {
        return false;
    }
    if (volume_tree_projection.inode_record_count != expected_non_root_inode_count ||
        volume_tree_projection.directory_entry_record_count != working_directory_links_.size() ||
        volume_tree_projection.extent_record_count != expected_extent_count)
    {
        return false;
    }

    std::unordered_set<std::string> projected_btree_keys;
    projected_btree_keys.reserve(projected_btree_records.size());
    for (const auto& record : projected_btree_records)
    {
        if (record.key.empty() ||
            record.kind < BtreeRecordKind::Inode ||
            record.kind > BtreeRecordKind::FileExtent)
        {
            return false;
        }
        if (std::to_integer<unsigned char>(record.key.front()) != static_cast<unsigned char>(record.kind))
        {
            return false;
        }

        auto key_blob = BuildBtreeKeyBlob(record.key);
        if (key_blob.empty() || !projected_btree_keys.insert(std::move(key_blob)).second)
        {
            return false;
        }
    }

    const auto target_xid = checkpoint_xid_ + 1;
    std::unordered_set<std::string> expected_btree_keys;
    expected_btree_keys.reserve(
        working_inodes_.size() +
        working_directory_links_.size() +
        working_inodes_.size());

    for (const auto& [object_id, inode] : working_inodes_)
    {
        if (IsRootPath(inode.full_path))
        {
            continue;
        }

        auto inode_key_record = BtreeMutationCodec::EncodeInodeRecord(
            object_id,
            inode.parent_object_id,
            inode.name,
            inode.is_directory,
            inode.logical_size,
            inode.data_physical_address,
            inode.timestamp_utc,
            target_xid,
            false);
        auto inode_key = BuildBtreeKeyBlob(inode_key_record.key);
        if (inode_key.empty() || !expected_btree_keys.insert(std::move(inode_key)).second)
        {
            return false;
        }

        if (!inode.is_directory &&
            inode.logical_size > 0 &&
            inode.data_physical_address != 0)
        {
            auto extent_key_record = BtreeMutationCodec::EncodeExtentRecord(
                object_id,
                0,
                inode.data_physical_address,
                inode.logical_size,
                target_xid,
                false);
            auto extent_key = BuildBtreeKeyBlob(extent_key_record.key);
            if (extent_key.empty() || !expected_btree_keys.insert(std::move(extent_key)).second)
            {
                return false;
            }
        }
    }

    for (const auto& link : working_directory_links_)
    {
        auto directory_key_record = BtreeMutationCodec::EncodeDirectoryRecord(
            link.parent_object_id,
            link.entry_name,
            link.child_object_id,
            target_xid,
            false);
        auto directory_key = BuildBtreeKeyBlob(directory_key_record.key);
        if (directory_key.empty() || !expected_btree_keys.insert(std::move(directory_key)).second)
        {
            return false;
        }
    }

    if (projected_btree_keys.size() != expected_btree_keys.size())
    {
        return false;
    }
    for (const auto& expected_key : expected_btree_keys)
    {
        if (!projected_btree_keys.contains(expected_key))
        {
            return false;
        }
    }

    std::unordered_map<std::uint64_t, DecodedBtreeInode> decoded_inodes_by_object;
    std::unordered_map<std::wstring, DecodedBtreeDirectoryEntry> decoded_directory_entries;
    std::unordered_map<std::uint64_t, DecodedBtreeExtent> decoded_extents_by_object;
    decoded_inodes_by_object.reserve(projected_btree_records.size());
    decoded_directory_entries.reserve(projected_btree_records.size());
    decoded_extents_by_object.reserve(projected_btree_records.size());

    for (const auto& record : projected_btree_records)
    {
        if (record.tombstone)
        {
            return false;
        }

        switch (record.kind)
        {
        case BtreeRecordKind::Inode:
        {
            DecodedBtreeInode decoded{};
            if (!DecodeBtreeInodeRecord(record, decoded))
            {
                return false;
            }
            if (!decoded_inodes_by_object.emplace(decoded.object_id, std::move(decoded)).second)
            {
                return false;
            }
            break;
        }
        case BtreeRecordKind::DirectoryEntry:
        {
            DecodedBtreeDirectoryEntry decoded{};
            if (!DecodeBtreeDirectoryRecord(record, decoded))
            {
                return false;
            }
            auto key = BuildDirectoryEntryIndexKey(decoded.parent_object_id, decoded.entry_name);
            if (!decoded_directory_entries.emplace(std::move(key), std::move(decoded)).second)
            {
                return false;
            }
            break;
        }
        case BtreeRecordKind::FileExtent:
        {
            DecodedBtreeExtent decoded{};
            if (!DecodeBtreeExtentRecord(record, decoded))
            {
                return false;
            }
            if (decoded.logical_offset != 0)
            {
                return false;
            }
            if (!decoded_extents_by_object.emplace(decoded.object_id, std::move(decoded)).second)
            {
                return false;
            }
            break;
        }
        default:
            return false;
        }
    }

    if (decoded_inodes_by_object.size() != expected_non_root_inode_count)
    {
        return false;
    }

    for (const auto& [object_id, inode] : working_inodes_)
    {
        if (IsRootPath(inode.full_path))
        {
            continue;
        }

        auto decoded_it = decoded_inodes_by_object.find(object_id);
        if (decoded_it == decoded_inodes_by_object.end())
        {
            return false;
        }
        const auto& decoded = decoded_it->second;
        if (decoded.parent_object_id != inode.parent_object_id ||
            decoded.is_directory != inode.is_directory ||
            decoded.logical_size != inode.logical_size ||
            decoded.data_physical_address != inode.data_physical_address ||
            decoded.name != inode.name)
        {
            return false;
        }
        if (decoded.xid == 0 || decoded.xid > target_xid)
        {
            return false;
        }
        if (decoded.parent_object_id == 0 || !working_inodes_.contains(decoded.parent_object_id))
        {
            return false;
        }
        if (auto parent_it = working_inodes_.find(decoded.parent_object_id);
            parent_it == working_inodes_.end() || !parent_it->second.is_directory)
        {
            return false;
        }

        if (inode.is_directory || inode.logical_size == 0 || inode.data_physical_address == 0)
        {
            if (decoded_extents_by_object.contains(object_id))
            {
                return false;
            }
        }
        else
        {
            auto extent_it = decoded_extents_by_object.find(object_id);
            if (extent_it == decoded_extents_by_object.end())
            {
                return false;
            }
            const auto& extent = extent_it->second;
            if (extent.physical_address != inode.data_physical_address ||
                extent.extent_bytes != inode.logical_size ||
                extent.xid == 0 ||
                extent.xid > target_xid)
            {
                return false;
            }

            auto mapped = effective_object_map.find(object_id);
            if (mapped == effective_object_map.end())
            {
                return false;
            }
            if (mapped->second.physical_address != extent.physical_address ||
                mapped->second.logical_size != extent.extent_bytes)
            {
                return false;
            }
        }
    }

    if (decoded_directory_entries.size() != working_directory_links_.size())
    {
        return false;
    }
    for (const auto& link : working_directory_links_)
    {
        auto entry_key = BuildDirectoryEntryIndexKey(link.parent_object_id, link.entry_name);
        auto decoded_it = decoded_directory_entries.find(entry_key);
        if (decoded_it == decoded_directory_entries.end())
        {
            return false;
        }
        const auto& decoded = decoded_it->second;
        if (decoded.child_object_id != link.child_object_id ||
            decoded.xid == 0 ||
            decoded.xid > target_xid)
        {
            return false;
        }

        auto parent_it = working_inodes_.find(link.parent_object_id);
        auto child_it = working_inodes_.find(link.child_object_id);
        if (parent_it == working_inodes_.end() ||
            child_it == working_inodes_.end() ||
            !parent_it->second.is_directory ||
            child_it->second.parent_object_id != link.parent_object_id ||
            child_it->second.name != link.entry_name)
        {
            return false;
        }
    }

    return true;
}

bool MetadataStore::AllowCommitStage(std::string_view stage)
{
    if (stage.rfind("before-recovery-", 0) == 0 || stage.rfind("replay-", 0) == 0)
    {
        last_replay_stage_ = std::string(stage);
    }
    else
    {
        last_commit_stage_ = std::string(stage);
    }

    if (!commit_stage_hook_)
    {
        return true;
    }

    return commit_stage_hook_(stage);
}

bool MetadataStore::PersistObjectMapCheckpoint(std::uint64_t target_xid)
{
    auto object_map_blocks = ResolveObjectMapCheckpointBlockIndices();
    if (object_map_blocks.empty())
    {
        return false;
    }
    const auto target_slot = object_map_blocks[
        static_cast<std::size_t>(target_xid % static_cast<std::uint64_t>(object_map_blocks.size()))];

    constexpr std::array<char, 12> kMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'O', 'M', 'A', 'P', '3', '\0'
    };
    constexpr std::size_t kHeaderBytes = kCheckpointHeaderBytes;
    constexpr std::size_t kEntryBytes = 32;

    const auto required_bytes = kHeaderBytes + (committed_object_map_.size() * kEntryBytes);
    if (required_bytes > static_cast<std::size_t>(block_size_))
    {
        return false;
    }

    std::vector<std::byte> block(static_cast<std::size_t>(block_size_), std::byte{0});
    for (std::size_t index = 0; index < kMagic.size(); ++index)
    {
        block[index] = static_cast<std::byte>(kMagic[index]);
    }
    WriteLe64(block, 12, target_xid);
    WriteLe32(block, 20, static_cast<std::uint32_t>(committed_object_map_.size()));

    std::vector<std::uint64_t> object_ids;
    object_ids.reserve(committed_object_map_.size());
    for (const auto& [object_id, _] : committed_object_map_)
    {
        object_ids.push_back(object_id);
    }
    std::sort(object_ids.begin(), object_ids.end());

    std::size_t cursor = kHeaderBytes;
    for (const auto object_id : object_ids)
    {
        auto it = committed_object_map_.find(object_id);
        if (it == committed_object_map_.end())
        {
            return false;
        }

        WriteLe64(block, cursor + 0, it->second.object_id);
        WriteLe64(block, cursor + 8, it->second.physical_address);
        WriteLe64(block, cursor + 16, it->second.logical_size);
        WriteLe64(block, cursor + 24, it->second.xid);
        cursor += kEntryBytes;
    }

    const auto payload_bytes = cursor - kHeaderBytes;
    WriteLe32(block, 24, static_cast<std::uint32_t>(payload_bytes));
    WriteLe32(block, kCheckpointChecksumOffset, ComputeCheckpointChecksum(block, payload_bytes));
    return WriteBlockByIndexDirect(target_slot, block);
}

bool MetadataStore::PersistSpacemanCheckpoint(std::uint64_t target_xid)
{
    auto spaceman_blocks = ResolveSpacemanCheckpointBlockIndices();
    if (spaceman_blocks.empty())
    {
        return false;
    }
    const auto target_slot = spaceman_blocks[
        static_cast<std::size_t>(target_xid % static_cast<std::uint64_t>(spaceman_blocks.size()))];

    constexpr std::array<char, 12> kMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'S', 'P', 'M', '3', '\0', '\0'
    };
    constexpr std::size_t kHeaderBytes = kCheckpointHeaderBytes;
    constexpr std::size_t kEntryBytes = 16;

    const auto required_entries = committed_spaceman_allocations_.size() + committed_spaceman_free_extents_.size();
    const auto required_bytes = kHeaderBytes + (required_entries * kEntryBytes);
    if (required_bytes > static_cast<std::size_t>(block_size_))
    {
        return false;
    }

    auto allocations = committed_spaceman_allocations_;
    auto free_extents = committed_spaceman_free_extents_;
    std::sort(allocations.begin(), allocations.end(), [](const SpacemanAllocation& lhs, const SpacemanAllocation& rhs)
    {
        return lhs.physical_address < rhs.physical_address;
    });
    std::sort(free_extents.begin(), free_extents.end(), [](const SpacemanAllocation& lhs, const SpacemanAllocation& rhs)
    {
        return lhs.physical_address < rhs.physical_address;
    });

    std::vector<std::byte> block(static_cast<std::size_t>(block_size_), std::byte{0});
    for (std::size_t index = 0; index < kMagic.size(); ++index)
    {
        block[index] = static_cast<std::byte>(kMagic[index]);
    }
    WriteLe64(block, 12, target_xid);
    WriteLe32(block, 20, static_cast<std::uint32_t>(allocations.size()));
    WriteLe32(block, 24, static_cast<std::uint32_t>(free_extents.size()));

    std::size_t cursor = kHeaderBytes;
    for (const auto& allocation : allocations)
    {
        WriteLe64(block, cursor + 0, allocation.physical_address);
        WriteLe64(block, cursor + 8, allocation.bytes);
        cursor += kEntryBytes;
    }
    for (const auto& extent : free_extents)
    {
        WriteLe64(block, cursor + 0, extent.physical_address);
        WriteLe64(block, cursor + 8, extent.bytes);
        cursor += kEntryBytes;
    }

    const auto payload_bytes = cursor - kHeaderBytes;
    WriteLe32(block, kCheckpointChecksumOffset, ComputeCheckpointChecksum(block, payload_bytes));
    return WriteBlockByIndexDirect(target_slot, block);
}

bool MetadataStore::PersistInodeCheckpoint(std::uint64_t target_xid)
{
    auto inode_blocks = ResolveInodeCheckpointBlockIndices();
    if (inode_blocks.empty())
    {
        return false;
    }
    const auto target_slot = inode_blocks[
        static_cast<std::size_t>(target_xid % static_cast<std::uint64_t>(inode_blocks.size()))];

    constexpr std::array<char, 12> kMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'I', 'N', 'O', 'D', '5', '\0'
    };
    constexpr std::size_t kHeaderBytes = kCheckpointHeaderBytes;
    constexpr std::size_t kRecordFixedBytes = 60;

    std::vector<std::uint64_t> object_ids;
    object_ids.reserve(committed_inodes_.size());
    for (const auto& [object_id, _] : committed_inodes_)
    {
        object_ids.push_back(object_id);
    }
    std::sort(object_ids.begin(), object_ids.end(), [&](std::uint64_t lhs, std::uint64_t rhs)
    {
        const auto lhs_it = committed_inodes_.find(lhs);
        const auto rhs_it = committed_inodes_.find(rhs);
        if (lhs_it == committed_inodes_.end() || rhs_it == committed_inodes_.end())
        {
            return lhs < rhs;
        }

        const auto lhs_key = CanonicalPathKey(lhs_it->second.full_path);
        const auto rhs_key = CanonicalPathKey(rhs_it->second.full_path);
        if (lhs_key == rhs_key)
        {
            return lhs < rhs;
        }
        return lhs_key < rhs_key;
    });

    std::size_t required_bytes = kHeaderBytes;
    for (const auto object_id : object_ids)
    {
        auto inode_it = committed_inodes_.find(object_id);
        if (inode_it == committed_inodes_.end())
        {
            return false;
        }

        const auto name_bytes = inode_it->second.name.size() * sizeof(wchar_t);
        const auto path_bytes = inode_it->second.full_path.size() * sizeof(wchar_t);
        if (required_bytes > (std::numeric_limits<std::size_t>::max() - kRecordFixedBytes - name_bytes - path_bytes))
        {
            return false;
        }
        required_bytes += kRecordFixedBytes + name_bytes + path_bytes;
    }
    if (required_bytes > static_cast<std::size_t>(block_size_))
    {
        return false;
    }

    std::vector<std::byte> block(static_cast<std::size_t>(block_size_), std::byte{0});
    for (std::size_t index = 0; index < kMagic.size(); ++index)
    {
        block[index] = static_cast<std::byte>(kMagic[index]);
    }
    WriteLe64(block, 12, target_xid);
    WriteLe32(block, 20, static_cast<std::uint32_t>(object_ids.size()));

    std::size_t cursor = kHeaderBytes;
    for (const auto object_id : object_ids)
    {
        auto inode_it = committed_inodes_.find(object_id);
        if (inode_it == committed_inodes_.end())
        {
            return false;
        }

        const auto& inode = inode_it->second;
        WriteLe64(block, cursor + 0, inode.object_id);
        WriteLe64(block, cursor + 8, inode.parent_object_id);
        WriteLe64(block, cursor + 16, inode.logical_size);
        WriteLe64(block, cursor + 24, inode.data_physical_address);
        WriteLe64(block, cursor + 32, inode.xid);
        WriteLe64(block, cursor + 40, inode.timestamp_utc);
        WriteLe32(block, cursor + 48, inode.is_directory ? 1u : 0u);
        WriteLe32(block, cursor + 52, static_cast<std::uint32_t>(inode.name.size()));
        WriteLe32(block, cursor + 56, static_cast<std::uint32_t>(inode.full_path.size()));
        cursor += kRecordFixedBytes;

        const auto name_bytes = inode.name.size() * sizeof(wchar_t);
        if (name_bytes > 0)
        {
            std::memcpy(block.data() + cursor, inode.name.data(), name_bytes);
            cursor += name_bytes;
        }

        const auto path_bytes = inode.full_path.size() * sizeof(wchar_t);
        if (path_bytes > 0)
        {
            std::memcpy(block.data() + cursor, inode.full_path.data(), path_bytes);
            cursor += path_bytes;
        }
    }

    const auto payload_bytes = cursor - kHeaderBytes;
    WriteLe32(block, 24, static_cast<std::uint32_t>(payload_bytes));
    WriteLe32(block, kCheckpointChecksumOffset, ComputeCheckpointChecksum(block, payload_bytes));
    return WriteBlockByIndexDirect(target_slot, block);
}

bool MetadataStore::PersistBtreeCheckpoint(std::uint64_t target_xid)
{
    auto btree_blocks = ResolveBtreeCheckpointBlockIndices();
    if (btree_blocks.empty())
    {
        return false;
    }
    const auto target_slot = btree_blocks[
        static_cast<std::size_t>(target_xid % static_cast<std::uint64_t>(btree_blocks.size()))];

    constexpr std::array<char, 12> kMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'B', 'T', 'R', '5', '\0', '\0'
    };
    constexpr std::size_t kHeaderBytes = kCheckpointHeaderBytes;
    constexpr std::size_t kRecordHeaderBytes = 16;

    std::size_t required_bytes = kHeaderBytes;
    for (const auto& record : committed_btree_records_)
    {
        if (required_bytes > (std::numeric_limits<std::size_t>::max() - kRecordHeaderBytes - record.key.size() - record.value.size()))
        {
            return false;
        }
        required_bytes += kRecordHeaderBytes + record.key.size() + record.value.size();
    }
    if (required_bytes > static_cast<std::size_t>(block_size_))
    {
        return false;
    }

    std::vector<std::byte> block(static_cast<std::size_t>(block_size_), std::byte{0});
    for (std::size_t index = 0; index < kMagic.size(); ++index)
    {
        block[index] = static_cast<std::byte>(kMagic[index]);
    }
    WriteLe64(block, 12, target_xid);
    WriteLe32(block, 20, static_cast<std::uint32_t>(committed_btree_records_.size()));

    std::size_t cursor = kHeaderBytes;
    for (const auto& record : committed_btree_records_)
    {
        WriteLe32(block, cursor + 0, static_cast<std::uint32_t>(record.kind));
        WriteLe32(block, cursor + 4, record.tombstone ? 1u : 0u);
        WriteLe32(block, cursor + 8, static_cast<std::uint32_t>(record.key.size()));
        WriteLe32(block, cursor + 12, static_cast<std::uint32_t>(record.value.size()));
        cursor += kRecordHeaderBytes;

        if (!record.key.empty())
        {
            std::memcpy(block.data() + cursor, record.key.data(), record.key.size());
            cursor += record.key.size();
        }
        if (!record.value.empty())
        {
            std::memcpy(block.data() + cursor, record.value.data(), record.value.size());
            cursor += record.value.size();
        }
    }

    const auto payload_bytes = cursor - kHeaderBytes;
    WriteLe32(block, 24, static_cast<std::uint32_t>(payload_bytes));
    WriteLe32(block, kCheckpointChecksumOffset, ComputeCheckpointChecksum(block, payload_bytes));
    return WriteBlockByIndexDirect(target_slot, block);
}

bool MetadataStore::PersistReplayCheckpoint(std::uint64_t target_xid)
{
    auto replay_blocks = ResolveReplayCheckpointBlockIndices();
    if (replay_blocks.empty() ||
        target_xid == 0 ||
        !last_commit_blob_address_.has_value() ||
        !last_commit_blob_bytes_.has_value() ||
        last_commit_blob_address_.value() == 0 ||
        last_commit_blob_bytes_.value() == 0 ||
        !ValidateCommitBlobLocation(
            last_commit_blob_address_.value(),
            last_commit_blob_bytes_.value()))
    {
        return false;
    }
    const auto source_xid = target_xid - 1;
    if (!ValidateReplayCommitBlobCandidate(
            last_commit_blob_address_.value(),
            last_commit_blob_bytes_.value(),
            source_xid,
            target_xid))
    {
        return false;
    }

    const auto target_slot = replay_blocks[
        static_cast<std::size_t>(target_xid % static_cast<std::uint64_t>(replay_blocks.size()))];

    constexpr std::array<char, 12> kMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'R', 'P', 'L', '1', '\0', '\0'
    };
    constexpr std::size_t kHeaderBytes = kCheckpointHeaderBytes;
    constexpr std::size_t kReplayPayloadBytes = 24;
    if ((kHeaderBytes + kReplayPayloadBytes) > static_cast<std::size_t>(block_size_))
    {
        return false;
    }

    std::vector<std::byte> block(static_cast<std::size_t>(block_size_), std::byte{0});
    for (std::size_t index = 0; index < kMagic.size(); ++index)
    {
        block[index] = static_cast<std::byte>(kMagic[index]);
    }

    WriteLe64(block, 12, target_xid);
    WriteLe32(block, 20, 1);
    WriteLe32(block, 24, static_cast<std::uint32_t>(kReplayPayloadBytes));
    WriteLe64(block, kHeaderBytes + 0, source_xid);
    WriteLe64(block, kHeaderBytes + 8, last_commit_blob_address_.value());
    WriteLe64(block, kHeaderBytes + 16, last_commit_blob_bytes_.value());
    WriteLe32(block, kCheckpointChecksumOffset, ComputeCheckpointChecksum(block, kReplayPayloadBytes));
    return WriteBlockByIndexDirect(target_slot, block);
}

bool MetadataStore::PersistCheckpointSuperblock(std::uint64_t target_xid)
{
    if (!container_loaded_)
    {
        return false;
    }

    // Offsets are based on apfs_sb layout from Paragon CE apfs_struct.h.
    constexpr std::size_t kSuperblockBytes = 0x570;
    constexpr std::size_t kMagicOffset = 0x20;
    constexpr std::size_t kBlockSizeOffset = 0x24;
    constexpr std::size_t kCheckpointXidOffset = 0x10;
    constexpr std::uint32_t kNxsbMagic = 0x4253584E; // 'NXSB'

    const auto resolve_target_offset = [&]() -> std::optional<std::uint64_t>
    {
        auto candidate = alternate_superblock_offset_;
        if (candidate == active_superblock_offset_)
        {
            candidate = active_superblock_offset_ == 0
                ? static_cast<std::uint64_t>(block_size_)
                : 0;
        }
        if (candidate > (std::numeric_limits<std::uint64_t>::max() - kSuperblockBytes))
        {
            return std::nullopt;
        }
        if (total_blocks_ != 0)
        {
            if (total_blocks_ > (std::numeric_limits<std::uint64_t>::max() / static_cast<std::uint64_t>(block_size_)))
            {
                return std::nullopt;
            }
            const auto total_bytes = total_blocks_ * static_cast<std::uint64_t>(block_size_);
            if (candidate + kSuperblockBytes > total_bytes)
            {
                return std::nullopt;
            }
        }
        return candidate;
    };

    auto target_offset = resolve_target_offset();
    if (!target_offset.has_value())
    {
        return false;
    }

    auto source_offset = active_superblock_offset_;
    std::vector<std::byte> superblock;
    if (!device_.Read(source_offset, kSuperblockBytes, superblock) || superblock.size() < kSuperblockBytes)
    {
        source_offset = 0;
        if (!device_.Read(source_offset, kSuperblockBytes, superblock) || superblock.size() < kSuperblockBytes)
        {
            return false;
        }
    }
    if (ReadLe32(superblock, kMagicOffset) != kNxsbMagic)
    {
        return false;
    }

    if (ReadLe32(superblock, kBlockSizeOffset) != block_size_)
    {
        return false;
    }

    if (!AllowCommitStage("before-checkpoint-write"))
    {
        return false;
    }

    WriteLe64(superblock, kCheckpointXidOffset, target_xid);
    if (!device_.Write(*target_offset, superblock))
    {
        return false;
    }

    active_superblock_offset_ = *target_offset;
    alternate_superblock_offset_ = source_offset;
    return true;
}

bool MetadataStore::LoadPersistentState()
{
    persistent_state_path_ = BuildPersistentStatePath(context_);
    persistent_state_loaded_ = true;
    recovery_required_ = false;
    recovery_reason_.clear();
    const auto disk_loaded_object_map = committed_object_map_;
    const auto disk_loaded_allocations = committed_spaceman_allocations_;
    const auto disk_loaded_free_extents = committed_spaceman_free_extents_;
    const auto disk_loaded_btree_records = committed_btree_records_;
    const auto disk_loaded_last_committed_xid = last_committed_xid_;
    const auto disk_loaded_next_extent = next_ephemeral_extent_;
    const auto disk_loaded_checkpoint_xid = checkpoint_xid_;
    committed_object_map_.clear();
    committed_spaceman_allocations_.clear();
    committed_spaceman_free_extents_.clear();
    committed_inodes_.clear();
    committed_path_index_.clear();
    committed_directory_links_.clear();
    committed_btree_records_.clear();
    working_inodes_.clear();
    working_path_index_.clear();
    working_directory_links_.clear();
    working_spaceman_free_extents_.clear();
    last_commit_blob_address_.reset();
    last_commit_blob_bytes_.reset();
    pending_mutations_.clear();
    pending_object_map_updates_.clear();
    pending_spaceman_allocations_.clear();
    pending_spaceman_deallocations_.clear();
    pending_btree_records_.clear();

    std::unordered_map<std::uint64_t, InodeRecord> disk_loaded_inodes;
    std::unordered_map<std::wstring, std::uint64_t> disk_loaded_path_index;
    std::vector<DirectoryLink> disk_loaded_directory_links;
    std::vector<BtreeRecord> disk_loaded_btree_checkpoint_records;
    std::optional<std::uint64_t> disk_loaded_btree_last_committed_xid;
    std::optional<std::uint64_t> disk_loaded_inode_last_committed_xid;
    std::optional<std::uint64_t> disk_loaded_replay_target_xid;
    std::optional<std::uint64_t> disk_loaded_replay_commit_blob_address;
    std::optional<std::uint64_t> disk_loaded_replay_commit_blob_bytes;
    std::optional<int> disk_loaded_replay_priority;
    last_replay_checkpoint_candidate_present_ = false;
    last_replay_checkpoint_pending_window_ = false;

    auto btree_checkpoint_blocks = ResolveBtreeCheckpointBlockIndices();
    if (!btree_checkpoint_blocks.empty())
    {
        std::uint64_t selected_checkpoint_xid = 0;
        bool selected_checkpoint_valid = false;
        std::vector<BtreeRecord> selected_btree_records;
        std::optional<std::uint64_t> selected_last_committed_xid;

        for (const auto btree_checkpoint_block : btree_checkpoint_blocks)
        {
            std::vector<std::byte> btree_checkpoint_bytes;
            if (!ReadBlockByIndexDirect(btree_checkpoint_block, btree_checkpoint_bytes))
            {
                continue;
            }

            committed_btree_records_.clear();
            last_committed_xid_ = disk_loaded_last_committed_xid;
            if (!LoadBtreeCheckpointBlock(btree_checkpoint_block, btree_checkpoint_bytes))
            {
                continue;
            }

            const auto candidate_xid = ReadLe64(btree_checkpoint_bytes, 12);
            if (!selected_checkpoint_valid || candidate_xid > selected_checkpoint_xid)
            {
                selected_checkpoint_xid = candidate_xid;
                selected_btree_records = committed_btree_records_;
                selected_last_committed_xid = last_committed_xid_;
                selected_checkpoint_valid = true;
            }
        }

        if (selected_checkpoint_valid)
        {
            disk_loaded_btree_checkpoint_records = std::move(selected_btree_records);
            disk_loaded_btree_last_committed_xid = selected_last_committed_xid;
        }
        committed_btree_records_.clear();
    }

    auto inode_checkpoint_blocks = ResolveInodeCheckpointBlockIndices();
    if (!inode_checkpoint_blocks.empty())
    {
        std::uint64_t selected_checkpoint_xid = 0;
        bool selected_checkpoint_valid = false;
        std::unordered_map<std::uint64_t, InodeRecord> selected_inodes;
        std::unordered_map<std::wstring, std::uint64_t> selected_path_index;
        std::vector<DirectoryLink> selected_directory_links;
        std::optional<std::uint64_t> selected_last_committed_xid;

        for (const auto inode_checkpoint_block : inode_checkpoint_blocks)
        {
            std::vector<std::byte> inode_checkpoint_bytes;
            if (!ReadBlockByIndexDirect(inode_checkpoint_block, inode_checkpoint_bytes))
            {
                continue;
            }

            committed_inodes_.clear();
            committed_path_index_.clear();
            committed_directory_links_.clear();
            working_inodes_.clear();
            working_path_index_.clear();
            working_directory_links_.clear();
            last_committed_xid_ = disk_loaded_last_committed_xid;

            if (!LoadInodeCheckpointBlock(inode_checkpoint_block, inode_checkpoint_bytes))
            {
                continue;
            }

            const auto candidate_xid = ReadLe64(inode_checkpoint_bytes, 12);
            if (!selected_checkpoint_valid || candidate_xid > selected_checkpoint_xid)
            {
                selected_checkpoint_xid = candidate_xid;
                selected_inodes = committed_inodes_;
                selected_path_index = committed_path_index_;
                selected_directory_links = committed_directory_links_;
                selected_last_committed_xid = last_committed_xid_;
                selected_checkpoint_valid = true;
            }
        }

        if (selected_checkpoint_valid)
        {
            disk_loaded_inodes = std::move(selected_inodes);
            disk_loaded_path_index = std::move(selected_path_index);
            disk_loaded_directory_links = std::move(selected_directory_links);
            disk_loaded_inode_last_committed_xid = selected_last_committed_xid;
        }
        committed_inodes_.clear();
        committed_path_index_.clear();
        committed_directory_links_.clear();
        working_inodes_.clear();
        working_path_index_.clear();
        working_directory_links_.clear();
    }

    if (disk_loaded_inodes.empty() &&
        !disk_loaded_btree_checkpoint_records.empty())
    {
        std::unordered_map<std::uint64_t, InodeRecord> rebuilt_inodes;
        std::unordered_map<std::wstring, std::uint64_t> rebuilt_path_index;
        std::vector<DirectoryLink> rebuilt_directory_links;
        if (RebuildInodeStateFromBtreeRecords(
                disk_loaded_btree_checkpoint_records,
                rebuilt_inodes,
                rebuilt_path_index,
                rebuilt_directory_links))
        {
            disk_loaded_inodes = std::move(rebuilt_inodes);
            disk_loaded_path_index = std::move(rebuilt_path_index);
            disk_loaded_directory_links = std::move(rebuilt_directory_links);
            if (disk_loaded_btree_last_committed_xid.has_value())
            {
                disk_loaded_inode_last_committed_xid = std::max(
                    disk_loaded_inode_last_committed_xid.value_or(0),
                    disk_loaded_btree_last_committed_xid.value());
            }
        }
    }

    auto replay_checkpoint_blocks = ResolveReplayCheckpointBlockIndices();
    if (!replay_checkpoint_blocks.empty())
    {
        std::uint64_t selected_replay_target_xid = 0;
        std::uint64_t selected_replay_commit_blob_address = 0;
        std::uint64_t selected_replay_commit_blob_bytes = 0;
        int selected_replay_priority = 0;
        bool selected_replay_valid = false;
        const auto can_advance_superblock_xid =
            loaded_superblock_checkpoint_xid_ < std::numeric_limits<std::uint64_t>::max();
        for (const auto replay_checkpoint_block : replay_checkpoint_blocks)
        {
            std::vector<std::byte> replay_checkpoint_bytes;
            if (!ReadBlockByIndexDirect(replay_checkpoint_block, replay_checkpoint_bytes))
            {
                continue;
            }

            std::uint64_t candidate_target_xid = 0;
            std::uint64_t candidate_source_xid = 0;
            std::uint64_t candidate_commit_blob_address = 0;
            std::uint64_t candidate_commit_blob_bytes = 0;
            if (!LoadReplayCheckpointBlock(
                    replay_checkpoint_block,
                    replay_checkpoint_bytes,
                    candidate_target_xid,
                    candidate_source_xid,
                    candidate_commit_blob_address,
                    candidate_commit_blob_bytes))
            {
                continue;
            }

            const auto matches_pending_window =
                can_advance_superblock_xid &&
                candidate_source_xid == loaded_superblock_checkpoint_xid_ &&
                candidate_target_xid == (loaded_superblock_checkpoint_xid_ + 1);
            const auto matches_applied_window =
                candidate_target_xid == loaded_superblock_checkpoint_xid_;
            if (!matches_pending_window && !matches_applied_window)
            {
                continue;
            }
            if (!ValidateReplayCommitBlobCandidate(
                    candidate_commit_blob_address,
                    candidate_commit_blob_bytes,
                    candidate_source_xid,
                    candidate_target_xid))
            {
                continue;
            }

            const int candidate_priority = matches_pending_window ? 2 : 1;
            if (!selected_replay_valid ||
                candidate_priority > selected_replay_priority ||
                (candidate_priority == selected_replay_priority &&
                 candidate_target_xid > selected_replay_target_xid))
            {
                selected_replay_target_xid = candidate_target_xid;
                selected_replay_commit_blob_address = candidate_commit_blob_address;
                selected_replay_commit_blob_bytes = candidate_commit_blob_bytes;
                selected_replay_priority = candidate_priority;
                selected_replay_valid = true;
            }
        }

        if (selected_replay_valid)
        {
            disk_loaded_replay_target_xid = selected_replay_target_xid;
            disk_loaded_replay_commit_blob_address = selected_replay_commit_blob_address;
            disk_loaded_replay_commit_blob_bytes = selected_replay_commit_blob_bytes;
            disk_loaded_replay_priority = selected_replay_priority;
        }
    }

    const auto apply_disk_fallback = [&](bool persistent_state_corrupt) -> bool
    {
        const auto require_canonical_non_fixture_commit_path = RequiresCanonicalNonFixtureCommitPath();
        const auto has_disk_replay_commit_blob_metadata =
            disk_loaded_replay_target_xid.has_value() &&
            disk_loaded_replay_commit_blob_address.has_value() &&
            disk_loaded_replay_commit_blob_bytes.has_value() &&
            disk_loaded_replay_commit_blob_address.value() > 0 &&
            disk_loaded_replay_commit_blob_bytes.value() > 0;
        const auto can_advance_superblock_xid =
            loaded_superblock_checkpoint_xid_ < std::numeric_limits<std::uint64_t>::max();
        const auto disk_replay_pending_window =
            has_disk_replay_commit_blob_metadata &&
            can_advance_superblock_xid &&
            disk_loaded_replay_priority.value_or(0) >= 2 &&
            disk_loaded_replay_target_xid.value() == (loaded_superblock_checkpoint_xid_ + 1);
        last_replay_checkpoint_candidate_present_ = has_disk_replay_commit_blob_metadata;
        last_replay_checkpoint_pending_window_ = disk_replay_pending_window;

        if (persistent_state_corrupt && !persistent_state_path_.empty())
        {
            std::error_code fs_ec;
            auto corrupt_path = persistent_state_path_;
            corrupt_path += L".corrupt";
            std::filesystem::remove(corrupt_path, fs_ec);
            fs_ec.clear();
            std::filesystem::rename(persistent_state_path_, corrupt_path, fs_ec);
            if (fs_ec)
            {
                fs_ec.clear();
                std::filesystem::remove(persistent_state_path_, fs_ec);
            }
        }

        checkpoint_xid_ = disk_loaded_checkpoint_xid;
        recovery_required_ = false;
        recovery_reason_.clear();
        committed_object_map_ = disk_loaded_object_map;
        committed_spaceman_allocations_ = disk_loaded_allocations;
        committed_spaceman_free_extents_ = disk_loaded_free_extents;
        committed_btree_records_ = disk_loaded_btree_checkpoint_records.empty()
            ? disk_loaded_btree_records
            : disk_loaded_btree_checkpoint_records;
        last_committed_xid_ = disk_loaded_last_committed_xid;
        if (disk_loaded_btree_last_committed_xid.has_value())
        {
            last_committed_xid_ = std::max(last_committed_xid_.value_or(0), disk_loaded_btree_last_committed_xid.value());
        }
        if (disk_loaded_inode_last_committed_xid.has_value())
        {
            last_committed_xid_ = std::max(last_committed_xid_.value_or(0), disk_loaded_inode_last_committed_xid.value());
        }
        if (disk_loaded_replay_target_xid.has_value() &&
            (!require_canonical_non_fixture_commit_path || disk_replay_pending_window))
        {
            last_committed_xid_ = std::max(last_committed_xid_.value_or(0), disk_loaded_replay_target_xid.value());
        }
        committed_inodes_ = disk_loaded_inodes;
        committed_path_index_ = disk_loaded_path_index;
        committed_directory_links_ = disk_loaded_directory_links;
        next_ephemeral_extent_ = std::max(next_ephemeral_extent_, disk_loaded_next_extent);
        last_commit_blob_address_.reset();
        last_commit_blob_bytes_.reset();
        if (disk_loaded_replay_commit_blob_address.has_value() &&
            disk_loaded_replay_commit_blob_bytes.has_value() &&
            disk_loaded_replay_commit_blob_address.value() > 0 &&
            disk_loaded_replay_commit_blob_bytes.value() > 0 &&
            (!require_canonical_non_fixture_commit_path || disk_replay_pending_window))
        {
            last_commit_blob_address_ = disk_loaded_replay_commit_blob_address.value();
            last_commit_blob_bytes_ = disk_loaded_replay_commit_blob_bytes.value();
            if (disk_loaded_replay_commit_blob_address.value() <=
                (std::numeric_limits<std::uint64_t>::max() - disk_loaded_replay_commit_blob_bytes.value()))
            {
                const auto commit_end = disk_loaded_replay_commit_blob_address.value() +
                                        disk_loaded_replay_commit_blob_bytes.value();
                if (commit_end > next_ephemeral_extent_)
                {
                    next_ephemeral_extent_ = commit_end;
                }
            }
        }
        working_inodes_ = committed_inodes_;
        working_path_index_ = committed_path_index_;
        working_directory_links_ = committed_directory_links_;
        working_spaceman_free_extents_ = committed_spaceman_free_extents_;
        working_next_ephemeral_extent_ = next_ephemeral_extent_;
        bool persistent_state_file_present = false;
        if (!persistent_state_path_.empty())
        {
            std::error_code exists_ec;
            persistent_state_file_present = std::filesystem::exists(persistent_state_path_, exists_ec) && !exists_ec;
        }
        if (!require_canonical_non_fixture_commit_path)
        {
            if (last_committed_xid_.has_value() && last_committed_xid_.value() > loaded_superblock_checkpoint_xid_)
            {
                recovery_required_ = true;
                recovery_reason_ = L"PersistentStateAheadOfSuperblock";
            }
            else if (last_committed_xid_.has_value() &&
                     last_committed_xid_.value() > 0 &&
                     last_committed_xid_.value() < loaded_superblock_checkpoint_xid_)
            {
                recovery_required_ = true;
                recovery_reason_ = L"PersistentStateBehindSuperblock";
            }
        }
        if (require_canonical_non_fixture_commit_path &&
            disk_replay_pending_window)
        {
            recovery_required_ = true;
            recovery_reason_ = L"ReplayCheckpointPendingWindow";
        }
        else if (require_canonical_non_fixture_commit_path &&
                 !persistent_state_file_present &&
                 last_committed_xid_.has_value() &&
                 last_committed_xid_.value() > loaded_superblock_checkpoint_xid_)
        {
            recovery_required_ = true;
            recovery_reason_ = L"PersistentStateAheadOfSuperblock";
        }
        return EnsureRootState();
    };

    if (RequiresCanonicalNonFixtureCommitPath())
    {
        // Production non-fixture mounts are disk/replay-checkpoint authoritative.
        // Sidecar payload parsing is fixture/test-only and bypassed.
        return apply_disk_fallback(false);
    }

    if (persistent_state_path_.empty() || !std::filesystem::exists(persistent_state_path_))
    {
        return apply_disk_fallback(false);
    }

    const auto load_persistent_state_file = [&]() -> bool
    {
        constexpr std::uint32_t kMaxPersistentRecordCount = 1u << 20; // 1,048,576
        constexpr std::uint32_t kMaxPersistentNameChars = 1024;
        constexpr std::uint32_t kMaxPersistentPathChars = 32u * 1024u;
        constexpr std::uint32_t kMaxPersistentBlobBytes = 4u * 1024u * 1024u;
        std::ifstream input(persistent_state_path_, std::ios::binary);
        if (!input.good())
        {
            return false;
        }

        std::uint32_t persistent_state_checksum = 0;
        std::uint32_t computed_state_checksum = kCheckpointChecksumSeed;
        const auto update_state_checksum_raw = [&computed_state_checksum](const unsigned char* bytes, std::size_t length)
        {
            if (bytes == nullptr || length == 0)
            {
                return;
            }
            computed_state_checksum = UpdateFnv1a(
                computed_state_checksum,
                reinterpret_cast<const std::byte*>(bytes),
                length);
        };
        const auto update_state_checksum_bytes = [&computed_state_checksum](const std::byte* bytes, std::size_t length)
        {
            if (bytes == nullptr || length == 0)
            {
                return;
            }
            computed_state_checksum = UpdateFnv1a(computed_state_checksum, bytes, length);
        };

        auto read_u32 = [&](std::uint32_t& value, bool include_checksum = true) -> bool
        {
            std::array<unsigned char, 4> bytes{};
            input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
            if (!input.good())
            {
                return false;
            }
            if (include_checksum)
            {
                update_state_checksum_raw(bytes.data(), bytes.size());
            }

            value = static_cast<std::uint32_t>(bytes[0]) |
                    (static_cast<std::uint32_t>(bytes[1]) << 8) |
                    (static_cast<std::uint32_t>(bytes[2]) << 16) |
                    (static_cast<std::uint32_t>(bytes[3]) << 24);
            return true;
        };

        auto read_u64 = [&](std::uint64_t& value, bool include_checksum = true) -> bool
        {
            std::array<unsigned char, 8> bytes{};
            input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
            if (!input.good())
            {
                return false;
            }
            if (include_checksum)
            {
                update_state_checksum_raw(bytes.data(), bytes.size());
            }

            value = static_cast<std::uint64_t>(bytes[0]) |
                    (static_cast<std::uint64_t>(bytes[1]) << 8) |
                    (static_cast<std::uint64_t>(bytes[2]) << 16) |
                    (static_cast<std::uint64_t>(bytes[3]) << 24) |
                    (static_cast<std::uint64_t>(bytes[4]) << 32) |
                    (static_cast<std::uint64_t>(bytes[5]) << 40) |
                    (static_cast<std::uint64_t>(bytes[6]) << 48) |
                    (static_cast<std::uint64_t>(bytes[7]) << 56);
            return true;
        };

        auto read_wstring = [&](std::uint32_t length, std::wstring& value, bool include_checksum = true) -> bool
        {
            value.clear();
            if (length == 0)
            {
                return true;
            }
            if (length > kMaxPersistentPathChars)
            {
                return false;
            }

            std::vector<wchar_t> buffer(length);
            input.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(sizeof(wchar_t) * length));
            if (!input.good())
            {
                return false;
            }
            if (include_checksum)
            {
                update_state_checksum_raw(
                    reinterpret_cast<const unsigned char*>(buffer.data()),
                    static_cast<std::size_t>(sizeof(wchar_t) * length));
            }

            value.assign(buffer.begin(), buffer.end());
            return true;
        };
        auto read_bytes = [&](std::uint32_t length, std::vector<std::byte>& value, bool include_checksum = true) -> bool
        {
            value.clear();
            if (length == 0)
            {
                return true;
            }
            if (length > kMaxPersistentBlobBytes)
            {
                return false;
            }

            value.resize(length);
            input.read(reinterpret_cast<char*>(value.data()), static_cast<std::streamsize>(length));
            if (!input.good())
            {
                return false;
            }
            if (include_checksum)
            {
                update_state_checksum_bytes(value.data(), value.size());
            }
            return true;
        };
        auto is_block_aligned_extent = [this](std::uint64_t physical_address, std::uint64_t bytes) -> bool
        {
            const auto block_bytes = static_cast<std::uint64_t>(std::max<std::uint32_t>(1u, block_size_));
            return (physical_address % block_bytes) == 0 &&
                   (bytes % block_bytes) == 0;
        };

        std::array<char, 16> magic{};
        input.read(magic.data(), static_cast<std::streamsize>(magic.size()));
        if (!input.good())
        {
            return false;
        }

        constexpr std::array<char, 16> kExpectedMagic =
        {
            'A', 'P', 'F', 'S', 'R', 'W', 'S', 'T', 'A', 'T', 'E', '2', '\0', '\0', '\0', '\0'
        };
        if (magic != kExpectedMagic)
        {
            return false;
        }
        update_state_checksum_raw(
            reinterpret_cast<const unsigned char*>(magic.data()),
            magic.size());

        std::uint32_t version = 0;
        std::uint32_t object_count = 0;
        std::uint32_t allocation_count = 0;
        std::uint32_t inode_count = 0;
        std::uint32_t btree_record_count = 0;
        std::uint32_t free_extent_count = 0;
        std::uint64_t persisted_checkpoint_xid = 0;
        std::uint64_t persisted_last_commit_xid = 0;
        std::uint64_t persisted_next_extent = 0;
        std::uint64_t persisted_next_object_id = 0;
        std::uint64_t persisted_last_commit_blob_address = 0;
        std::uint64_t persisted_last_commit_blob_bytes = 0;

        if (!read_u32(version))
        {
            return false;
        }
        if (version >= 6 && !read_u32(persistent_state_checksum, false))
        {
            return false;
        }
        if (!read_u64(persisted_checkpoint_xid) ||
            !read_u64(persisted_last_commit_xid) ||
            !read_u64(persisted_next_extent) ||
            !read_u64(persisted_last_commit_blob_address) ||
            !read_u64(persisted_last_commit_blob_bytes) ||
            !read_u32(object_count) ||
            !read_u32(allocation_count))
        {
            return false;
        }
        if (version != 1 &&
            version != 2 &&
            version != 3 &&
            version != 4 &&
            version != 5 &&
            version != 6 &&
            version != 7)
        {
            return false;
        }
        if (version >= 2 && !read_u32(inode_count))
        {
            return false;
        }
        if (version >= 3 && !read_u32(btree_record_count))
        {
            return false;
        }
        if (version >= 4 && !read_u32(free_extent_count))
        {
            return false;
        }
        if (version >= 5 && !read_u64(persisted_next_object_id))
        {
            return false;
        }
    if (object_count > kMaxPersistentRecordCount ||
        allocation_count > kMaxPersistentRecordCount ||
        inode_count > kMaxPersistentRecordCount ||
        btree_record_count > kMaxPersistentRecordCount ||
        free_extent_count > kMaxPersistentRecordCount)
    {
        return false;
    }
    if (total_blocks_ != 0)
    {
        const auto bounded_block_records = std::min<std::uint64_t>(
            total_blocks_,
            static_cast<std::uint64_t>(kMaxPersistentRecordCount));
        if (static_cast<std::uint64_t>(object_count) > bounded_block_records ||
            static_cast<std::uint64_t>(allocation_count) > bounded_block_records ||
            static_cast<std::uint64_t>(free_extent_count) > bounded_block_records)
        {
            return false;
        }
    }

    for (std::uint32_t index = 0; index < object_count; ++index)
    {
        ObjectMapUpdate entry{};
        if (!read_u64(entry.object_id) ||
            !read_u64(entry.physical_address) ||
            !read_u64(entry.logical_size) ||
            !read_u64(entry.xid))
        {
            return false;
        }
        if (entry.object_id == 0)
        {
            return false;
        }
        auto [_, inserted] = committed_object_map_.emplace(entry.object_id, entry);
        if (!inserted)
        {
            return false;
        }
    }

    committed_spaceman_allocations_.reserve(allocation_count);
    for (std::uint32_t index = 0; index < allocation_count; ++index)
    {
        SpacemanAllocation allocation{};
        if (!read_u64(allocation.physical_address) ||
            !read_u64(allocation.bytes))
        {
            return false;
        }
        if (allocation.physical_address == 0 || allocation.bytes == 0)
        {
            return false;
        }
        const auto aligned_bytes = AlignExtentBytes(allocation.bytes);
        if (aligned_bytes == 0 || aligned_bytes != allocation.bytes)
        {
            return false;
        }
        allocation.bytes = aligned_bytes;
        if (!is_block_aligned_extent(allocation.physical_address, allocation.bytes))
        {
            return false;
        }
        if (total_blocks_ != 0)
        {
            if (block_size_ == 0 ||
                total_blocks_ > (std::numeric_limits<std::uint64_t>::max() / static_cast<std::uint64_t>(block_size_)))
            {
                return false;
            }

            const auto container_bytes = total_blocks_ * static_cast<std::uint64_t>(block_size_);
            if (allocation.physical_address > (std::numeric_limits<std::uint64_t>::max() - allocation.bytes) ||
                (allocation.physical_address + allocation.bytes) > container_bytes)
            {
                return false;
            }
        }
        if (allocation.physical_address > (std::numeric_limits<std::uint64_t>::max() - allocation.bytes))
        {
            return false;
        }
        committed_spaceman_allocations_.push_back(allocation);
    }
    for (std::size_t i = 0; i < committed_spaceman_allocations_.size(); ++i)
    {
        const auto& lhs = committed_spaceman_allocations_[i];
        if (lhs.physical_address > (std::numeric_limits<std::uint64_t>::max() - lhs.bytes))
        {
            return false;
        }
        const auto lhs_end = lhs.physical_address + lhs.bytes;
        for (std::size_t j = i + 1; j < committed_spaceman_allocations_.size(); ++j)
        {
            const auto& rhs = committed_spaceman_allocations_[j];
            if (rhs.physical_address > (std::numeric_limits<std::uint64_t>::max() - rhs.bytes))
            {
                return false;
            }
            const auto rhs_end = rhs.physical_address + rhs.bytes;
            if (lhs.physical_address < rhs_end && rhs.physical_address < lhs_end)
            {
                return false;
            }
        }
    }

    if (version >= 2)
    {
        for (std::uint32_t index = 0; index < inode_count; ++index)
        {
            InodeRecord inode{};
            std::uint32_t flags = 0;
            std::uint32_t name_length = 0;
            std::uint32_t path_length = 0;
            if (!read_u64(inode.object_id) ||
                !read_u64(inode.parent_object_id) ||
                !read_u64(inode.logical_size) ||
                !read_u64(inode.data_physical_address) ||
                !read_u64(inode.xid) ||
                (version >= 7 && !read_u64(inode.timestamp_utc)) ||
                !read_u32(flags) ||
                !read_u32(name_length) ||
                !read_u32(path_length) ||
                !read_wstring(name_length, inode.name) ||
                !read_wstring(path_length, inode.full_path))
            {
                return false;
            }
            if (name_length > kMaxPersistentNameChars ||
                path_length == 0 ||
                path_length > kMaxPersistentPathChars)
            {
                return false;
            }

            if (inode.object_id == 0 || inode.full_path.empty())
            {
                return false;
            }
            const auto normalized_path = NormalizePath(inode.full_path);
            if (normalized_path != inode.full_path)
            {
                return false;
            }
            if (committed_inodes_.contains(inode.object_id))
            {
                return false;
            }

            inode.is_directory = (flags & 0x1u) != 0;
            committed_inodes_.emplace(inode.object_id, inode);
            const auto path_key = CanonicalPathKey(inode.full_path);
            if (!path_key.empty())
            {
                auto [path_it, inserted] = committed_path_index_.emplace(path_key, inode.object_id);
                if (!inserted && path_it->second != inode.object_id)
                {
                    return false;
                }
            }
        }
    }
    if (version >= 3)
    {
        committed_btree_records_.reserve(btree_record_count);
        for (std::uint32_t index = 0; index < btree_record_count; ++index)
        {
            std::uint32_t kind_value = 0;
            std::uint32_t tombstone_flag = 0;
            std::uint32_t key_length = 0;
            std::uint32_t value_length = 0;
            BtreeRecord record{};
            if (!read_u32(kind_value) ||
                !read_u32(tombstone_flag) ||
                !read_u32(key_length) ||
                !read_u32(value_length) ||
                !read_bytes(key_length, record.key) ||
                !read_bytes(value_length, record.value))
            {
                return false;
            }
            if (key_length == 0 ||
                key_length > kMaxPersistentBlobBytes ||
                value_length > kMaxPersistentBlobBytes)
            {
                return false;
            }

            if (kind_value < static_cast<std::uint32_t>(BtreeRecordKind::Inode) ||
                kind_value > static_cast<std::uint32_t>(BtreeRecordKind::FileExtent))
            {
                return false;
            }

            record.kind = static_cast<BtreeRecordKind>(kind_value);
            record.tombstone = tombstone_flag != 0;
            committed_btree_records_.push_back(std::move(record));
        }
        committed_btree_records_ = CanonicalizeBtreeRecords(committed_btree_records_);
    }
        if (version >= 4)
        {
            committed_spaceman_free_extents_.reserve(free_extent_count);
            working_spaceman_free_extents_.clear();
            for (std::uint32_t index = 0; index < free_extent_count; ++index)
            {
                SpacemanAllocation free_extent{};
                if (!read_u64(free_extent.physical_address) ||
                    !read_u64(free_extent.bytes) ||
                    free_extent.physical_address == 0 ||
                    free_extent.bytes == 0)
                {
                    return false;
                }
                const auto aligned_bytes = AlignExtentBytes(free_extent.bytes);
                if (aligned_bytes == 0 ||
                    aligned_bytes != free_extent.bytes ||
                    !is_block_aligned_extent(free_extent.physical_address, free_extent.bytes))
                {
                    return false;
                }
                if (!FreeExtent(free_extent.physical_address, free_extent.bytes))
                {
                    return false;
                }
            }
            committed_spaceman_free_extents_ = working_spaceman_free_extents_;
        }

        if (version >= 6 && persistent_state_checksum != computed_state_checksum)
        {
            return false;
        }
        if (input.peek() != std::char_traits<char>::eof())
        {
            return false;
        }

    const auto require_canonical_non_fixture_commit_path = RequiresCanonicalNonFixtureCommitPath();

    checkpoint_xid_ = std::max(checkpoint_xid_, persisted_checkpoint_xid);
    if (!require_canonical_non_fixture_commit_path &&
        persisted_checkpoint_xid > 0)
    {
        if (persisted_checkpoint_xid > loaded_superblock_checkpoint_xid_)
        {
            recovery_required_ = true;
            recovery_reason_ = L"PersistentStateAheadOfSuperblock";
        }
        else if (persisted_checkpoint_xid < loaded_superblock_checkpoint_xid_)
        {
            recovery_required_ = true;
            recovery_reason_ = L"PersistentStateBehindSuperblock";
        }
    }
    if (!require_canonical_non_fixture_commit_path &&
        persisted_next_extent > next_ephemeral_extent_)
    {
        next_ephemeral_extent_ = persisted_next_extent;
    }
    RefreshObjectIdAllocator();
    if (!require_canonical_non_fixture_commit_path &&
        version >= 5 &&
        persisted_next_object_id > next_generated_object_id_)
    {
        next_generated_object_id_ = persisted_next_object_id;
        if (next_generated_object_id_ == 0)
        {
            next_generated_object_id_ = 1;
        }
    }
    const auto persisted_commit_blob_valid =
        !require_canonical_non_fixture_commit_path &&
        persisted_last_commit_blob_address > 0 &&
        persisted_last_commit_blob_bytes > 0 &&
        persisted_last_commit_xid > 0 &&
        ValidateReplayCommitBlobCandidate(
            persisted_last_commit_blob_address,
            persisted_last_commit_blob_bytes,
            loaded_superblock_checkpoint_xid_,
            persisted_last_commit_xid);
    const auto has_disk_replay_commit_blob_metadata =
        disk_loaded_replay_target_xid.has_value() &&
        disk_loaded_replay_commit_blob_address.has_value() &&
        disk_loaded_replay_commit_blob_bytes.has_value() &&
        disk_loaded_replay_commit_blob_address.value() > 0 &&
        disk_loaded_replay_commit_blob_bytes.value() > 0;
    const auto can_advance_superblock_xid =
        loaded_superblock_checkpoint_xid_ < std::numeric_limits<std::uint64_t>::max();
    const auto disk_replay_pending_window =
        has_disk_replay_commit_blob_metadata &&
        can_advance_superblock_xid &&
        disk_loaded_replay_priority.value_or(0) >= 2 &&
        disk_loaded_replay_target_xid.value() == (loaded_superblock_checkpoint_xid_ + 1);
    last_replay_checkpoint_candidate_present_ = has_disk_replay_commit_blob_metadata;
    last_replay_checkpoint_pending_window_ = disk_replay_pending_window;
    if (require_canonical_non_fixture_commit_path &&
        disk_replay_pending_window)
    {
        // Canonical non-fixture recovery reason should prioritize pending
        // replay-checkpoint metadata over sidecar checkpoint drift markers.
        recovery_required_ = true;
        recovery_reason_ = L"ReplayCheckpointPendingWindow";
    }

    const auto apply_commit_blob_metadata = [this](std::uint64_t address, std::uint64_t bytes)
    {
        last_commit_blob_address_ = address;
        last_commit_blob_bytes_ = bytes;
        if (address <= (std::numeric_limits<std::uint64_t>::max() - bytes))
        {
            const auto commit_end = address + bytes;
            if (commit_end > next_ephemeral_extent_)
            {
                next_ephemeral_extent_ = commit_end;
            }
        }
    };

    last_committed_xid_.reset();
    last_commit_blob_address_.reset();
    last_commit_blob_bytes_.reset();

    if (require_canonical_non_fixture_commit_path)
    {
        // Canonical non-fixture replay prefers on-disk replay-checkpoint metadata.
        if (disk_replay_pending_window)
        {
            last_committed_xid_ = disk_loaded_replay_target_xid.value();
            apply_commit_blob_metadata(
                disk_loaded_replay_commit_blob_address.value(),
                disk_loaded_replay_commit_blob_bytes.value());
        }
    }
    else
    {
        if (persisted_commit_blob_valid)
        {
            apply_commit_blob_metadata(
                persisted_last_commit_blob_address,
                persisted_last_commit_blob_bytes);
        }

        if (persisted_last_commit_xid > 0 &&
            (persisted_commit_blob_valid || !disk_loaded_replay_target_xid.has_value()))
        {
            last_committed_xid_ = persisted_last_commit_xid;
        }
        if (disk_loaded_replay_target_xid.has_value())
        {
            last_committed_xid_ = std::max(last_committed_xid_.value_or(0), disk_loaded_replay_target_xid.value());
        }

        const auto prefer_replay_commit_blob =
            !persisted_commit_blob_valid ||
            (disk_loaded_replay_target_xid.has_value() &&
             disk_loaded_replay_target_xid.value() >= persisted_last_commit_xid);
        if ((prefer_replay_commit_blob ||
             !last_commit_blob_address_.has_value() ||
             !last_commit_blob_bytes_.has_value()) &&
            has_disk_replay_commit_blob_metadata)
        {
            apply_commit_blob_metadata(
                disk_loaded_replay_commit_blob_address.value(),
                disk_loaded_replay_commit_blob_bytes.value());
        }
    }

    if (require_canonical_non_fixture_commit_path)
    {
        // Canonical non-fixture mounts keep committed metadata state sourced from
        // on-disk checkpoints/superblock state, not sidecar payload fields.
        committed_object_map_ = disk_loaded_object_map;
        committed_spaceman_allocations_ = disk_loaded_allocations;
        committed_spaceman_free_extents_ = disk_loaded_free_extents;
        committed_btree_records_ = disk_loaded_btree_checkpoint_records.empty()
            ? disk_loaded_btree_records
            : disk_loaded_btree_checkpoint_records;
        committed_inodes_ = disk_loaded_inodes;
        committed_path_index_ = disk_loaded_path_index;
        committed_directory_links_ = disk_loaded_directory_links;
        checkpoint_xid_ = disk_loaded_checkpoint_xid;
        next_ephemeral_extent_ = std::max(next_ephemeral_extent_, disk_loaded_next_extent);
        RefreshObjectIdAllocator();
        // Canonical non-fixture mounts derive runtime xid progression strictly from
        // on-disk canonical sources (container/btree/inode/replay checkpoints).
        if (disk_loaded_last_committed_xid.has_value())
        {
            last_committed_xid_ = std::max(last_committed_xid_.value_or(0), disk_loaded_last_committed_xid.value());
        }
        if (disk_loaded_btree_last_committed_xid.has_value())
        {
            last_committed_xid_ = std::max(last_committed_xid_.value_or(0), disk_loaded_btree_last_committed_xid.value());
        }
        if (disk_loaded_inode_last_committed_xid.has_value())
        {
            last_committed_xid_ = std::max(last_committed_xid_.value_or(0), disk_loaded_inode_last_committed_xid.value());
        }
        if (disk_replay_pending_window && disk_loaded_replay_target_xid.has_value())
        {
            last_committed_xid_ = std::max(last_committed_xid_.value_or(0), disk_loaded_replay_target_xid.value());
        }
        if (checkpoint_xid_ > 0)
        {
            last_committed_xid_ = std::max(last_committed_xid_.value_or(0), checkpoint_xid_);
        }
    }

    working_spaceman_free_extents_ = committed_spaceman_free_extents_;
    working_next_ephemeral_extent_ = next_ephemeral_extent_;

    if (!EnsureRootState())
    {
        return false;
    }

        return ValidateInodeGraphState(
            committed_inodes_,
            committed_path_index_,
            committed_directory_links_,
            /*require_root_object=*/true);
    };

    if (!load_persistent_state_file())
    {
        // Non-fixture canonical mounts keep sidecar payload parse failures
        // non-fatal and avoid sidecar corruption marker churn. Disk/replay
        // checkpoint reconciliation remains authoritative.
        const auto parse_failure_corrupts_sidecar = !RequiresCanonicalNonFixtureCommitPath();
        return apply_disk_fallback(parse_failure_corrupts_sidecar);
    }

    return true;
}

bool MetadataStore::PersistPersistentState(std::uint64_t commit_blob_address, std::uint64_t commit_blob_bytes)
{
    if (!ValidateCommitBlobLocation(commit_blob_address, commit_blob_bytes))
    {
        return false;
    }

    if (RequiresCanonicalNonFixtureCommitPath())
    {
        // Production non-fixture commit/replay state is disk-authoritative.
        // Sidecar persistence is fixture/test-only and intentionally skipped.
        return true;
    }

    if (persistent_state_path_.empty())
    {
        persistent_state_path_ = BuildPersistentStatePath(context_);
    }
    if (persistent_state_path_.empty())
    {
        return false;
    }

    std::error_code ec;
    std::filesystem::create_directories(persistent_state_path_.parent_path(), ec);
    if (ec)
    {
        return false;
    }

    auto tmp_path = persistent_state_path_;
    tmp_path += L".tmp";
    std::ofstream output(tmp_path, std::ios::binary | std::ios::trunc);
    if (!output.good())
    {
        return false;
    }

    constexpr std::array<char, 16> kMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'S', 'T', 'A', 'T', 'E', '2', '\0', '\0', '\0', '\0'
    };
    constexpr std::streamoff kPersistentStateChecksumOffset =
        static_cast<std::streamoff>(kMagic.size() + sizeof(std::uint32_t));

    std::uint32_t persistent_state_checksum = kCheckpointChecksumSeed;
    const auto update_state_checksum = [&persistent_state_checksum](const void* data, std::size_t bytes)
    {
        if (data == nullptr || bytes == 0)
        {
            return;
        }
        persistent_state_checksum = UpdateFnv1a(
            persistent_state_checksum,
            reinterpret_cast<const std::byte*>(data),
            bytes);
    };
    const auto write_raw = [&](const void* data, std::size_t bytes, bool include_checksum = true) -> bool
    {
        if (bytes == 0)
        {
            return true;
        }

        output.write(
            reinterpret_cast<const char*>(data),
            static_cast<std::streamsize>(bytes));
        if (!output.good())
        {
            return false;
        }
        if (include_checksum)
        {
            update_state_checksum(data, bytes);
        }
        return true;
    };

    const auto write_u32 = [&](std::uint32_t value, bool include_checksum = true) -> bool
    {
        std::array<unsigned char, 4> bytes
        {
            static_cast<unsigned char>(value & 0xffu),
            static_cast<unsigned char>((value >> 8) & 0xffu),
            static_cast<unsigned char>((value >> 16) & 0xffu),
            static_cast<unsigned char>((value >> 24) & 0xffu),
        };
        return write_raw(bytes.data(), bytes.size(), include_checksum);
    };

    const auto write_u64 = [&](std::uint64_t value, bool include_checksum = true) -> bool
    {
        std::array<unsigned char, 8> bytes
        {
            static_cast<unsigned char>(value & 0xffu),
            static_cast<unsigned char>((value >> 8) & 0xffu),
            static_cast<unsigned char>((value >> 16) & 0xffu),
            static_cast<unsigned char>((value >> 24) & 0xffu),
            static_cast<unsigned char>((value >> 32) & 0xffu),
            static_cast<unsigned char>((value >> 40) & 0xffu),
            static_cast<unsigned char>((value >> 48) & 0xffu),
            static_cast<unsigned char>((value >> 56) & 0xffu),
        };
        return write_raw(bytes.data(), bytes.size(), include_checksum);
    };

    const auto write_wstring = [&](const std::wstring& value, bool include_checksum = true) -> bool
    {
        if (value.empty())
        {
            return true;
        }

        return write_raw(
            value.data(),
            value.size() * sizeof(wchar_t),
            include_checksum);
    };

    if (!write_raw(kMagic.data(), kMagic.size()) ||
        !write_u32(7) ||
        !write_u32(0, false) ||
        !write_u64(checkpoint_xid_) ||
        !write_u64(last_committed_xid_.value_or(0)) ||
        !write_u64(next_ephemeral_extent_) ||
        !write_u64(commit_blob_address) ||
        !write_u64(commit_blob_bytes) ||
        !write_u32(static_cast<std::uint32_t>(committed_object_map_.size())) ||
        !write_u32(static_cast<std::uint32_t>(committed_spaceman_allocations_.size())) ||
        !write_u32(static_cast<std::uint32_t>(committed_inodes_.size())) ||
        !write_u32(static_cast<std::uint32_t>(committed_btree_records_.size())) ||
        !write_u32(static_cast<std::uint32_t>(committed_spaceman_free_extents_.size())) ||
        !write_u64(next_generated_object_id_))
    {
        output.close();
        std::filesystem::remove(tmp_path, ec);
        return false;
    }

    for (const auto& [object_id, entry] : committed_object_map_)
    {
        if (!write_u64(object_id) ||
            !write_u64(entry.physical_address) ||
            !write_u64(entry.logical_size) ||
            !write_u64(entry.xid))
        {
            output.close();
            std::filesystem::remove(tmp_path, ec);
            return false;
        }
    }

    for (const auto& allocation : committed_spaceman_allocations_)
    {
        if (!write_u64(allocation.physical_address) ||
            !write_u64(allocation.bytes))
        {
            output.close();
            std::filesystem::remove(tmp_path, ec);
            return false;
        }
    }

    for (const auto& [object_id, inode] : committed_inodes_)
    {
        const std::uint32_t flags = inode.is_directory ? 0x1u : 0u;
        if (!write_u64(object_id) ||
            !write_u64(inode.parent_object_id) ||
            !write_u64(inode.logical_size) ||
            !write_u64(inode.data_physical_address) ||
            !write_u64(inode.xid) ||
            !write_u64(inode.timestamp_utc) ||
            !write_u32(flags) ||
            !write_u32(static_cast<std::uint32_t>(inode.name.size())) ||
            !write_u32(static_cast<std::uint32_t>(inode.full_path.size())) ||
            !write_wstring(inode.name) ||
            !write_wstring(inode.full_path))
        {
            output.close();
            std::filesystem::remove(tmp_path, ec);
            return false;
        }
    }
    for (const auto& record : committed_btree_records_)
    {
        if (!write_u32(static_cast<std::uint32_t>(record.kind)) ||
            !write_u32(record.tombstone ? 1u : 0u) ||
            !write_u32(static_cast<std::uint32_t>(record.key.size())) ||
            !write_u32(static_cast<std::uint32_t>(record.value.size())))
        {
            output.close();
            std::filesystem::remove(tmp_path, ec);
            return false;
        }

        if (!record.key.empty())
        {
            if (!write_raw(record.key.data(), record.key.size()))
            {
                output.close();
                std::filesystem::remove(tmp_path, ec);
                return false;
            }
        }
        if (!record.value.empty())
        {
            if (!write_raw(record.value.data(), record.value.size()))
            {
                output.close();
                std::filesystem::remove(tmp_path, ec);
                return false;
            }
        }
    }
    for (const auto& free_extent : committed_spaceman_free_extents_)
    {
        if (!write_u64(free_extent.physical_address) ||
            !write_u64(free_extent.bytes))
        {
            output.close();
            std::filesystem::remove(tmp_path, ec);
            return false;
        }
    }

    if (!output.seekp(kPersistentStateChecksumOffset, std::ios::beg) ||
        !write_u32(persistent_state_checksum, false) ||
        !output.seekp(0, std::ios::end))
    {
        output.close();
        std::filesystem::remove(tmp_path, ec);
        return false;
    }

    output.flush();
    if (!output.good())
    {
        output.close();
        std::filesystem::remove(tmp_path, ec);
        return false;
    }
    output.close();

    std::filesystem::rename(tmp_path, persistent_state_path_, ec);
    if (ec)
    {
        std::filesystem::remove(persistent_state_path_, ec);
        ec.clear();
        std::filesystem::rename(tmp_path, persistent_state_path_, ec);
    }
    if (ec)
    {
        std::filesystem::remove(tmp_path, ec);
        return false;
    }

    return true;
}

std::filesystem::path MetadataStore::BuildPersistentStatePath(const VolumeContext& context)
{
    std::error_code ec;
    auto root = std::filesystem::temp_directory_path(ec);
    if (ec)
    {
        return {};
    }

    root /= "ApfsAccess";
    root /= "rw-state";

    const auto key = context.device_path + L"|" + context.volume_name;
    const auto stable_id = StableObjectIdFromPath(key);
    return root / (std::to_wstring(stable_id) + L".bin");
}

std::vector<std::byte> MetadataStore::BuildCommitBlob(std::uint64_t target_xid)
{
    if (!IsNativeWriteReady())
    {
        return {};
    }

    constexpr std::array<char, 13> kScaffoldMagicV3 =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'S', 'C', 'A', 'F', 'F', '3', '\0'
    };
    constexpr std::array<char, 13> kCanonicalMagicV3 =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'C', 'A', 'N', 'O', 'N', '3', '\0'
    };
    constexpr std::size_t kCommitBlobChecksumOffset = 13 + 8 + 8 + 4 + 4 + 4 + 4 + 4;
    constexpr std::size_t kCommitBlobPayloadOffset = kCommitBlobChecksumOffset + sizeof(std::uint32_t);

    std::vector<std::byte> blob;
    blob.reserve(static_cast<std::size_t>(block_size_));

    const auto use_scaffold_blob = ShouldUseScaffoldCommitBlobForCurrentContext();
    uses_scaffold_commit_blob_ = use_scaffold_blob;
    const auto& selected_magic = use_scaffold_blob ? kScaffoldMagicV3 : kCanonicalMagicV3;
    last_commit_blob_magic_ = use_scaffold_blob ? "APFSRWSCAFF3" : "APFSRWCANON3";
    for (const auto c : selected_magic)
    {
        blob.push_back(static_cast<std::byte>(c));
    }

    AppendLe64(blob, checkpoint_xid_);
    AppendLe64(blob, target_xid);
    AppendLe32(blob, static_cast<std::uint32_t>(pending_mutations_.size()));
    AppendLe32(blob, static_cast<std::uint32_t>(pending_object_map_updates_.size()));
    AppendLe32(blob, static_cast<std::uint32_t>(pending_spaceman_allocations_.size()));
    AppendLe32(blob, static_cast<std::uint32_t>(pending_spaceman_deallocations_.size()));
    AppendLe32(blob, static_cast<std::uint32_t>(pending_btree_records_.size()));
    AppendLe32(blob, 0); // placeholder for payload checksum (v3 format)

    for (const auto& update : pending_object_map_updates_)
    {
        AppendLe64(blob, update.object_id);
        AppendLe64(blob, update.physical_address);
        AppendLe64(blob, update.logical_size);
        AppendLe64(blob, update.xid);
    }

    for (const auto& allocation : pending_spaceman_allocations_)
    {
        AppendLe64(blob, allocation.physical_address);
        AppendLe64(blob, allocation.bytes);
    }
    for (const auto& deallocation : pending_spaceman_deallocations_)
    {
        AppendLe64(blob, deallocation.physical_address);
        AppendLe64(blob, deallocation.bytes);
    }
    for (const auto& record : pending_btree_records_)
    {
        AppendLe32(blob, static_cast<std::uint32_t>(record.kind));
        AppendLe32(blob, record.tombstone ? 1u : 0u);
        AppendLe32(blob, static_cast<std::uint32_t>(record.key.size()));
        AppendLe32(blob, static_cast<std::uint32_t>(record.value.size()));
        blob.insert(blob.end(), record.key.begin(), record.key.end());
        blob.insert(blob.end(), record.value.begin(), record.value.end());
    }

    if (blob.size() < kCommitBlobPayloadOffset)
    {
        return {};
    }
    const auto payload_bytes = blob.size() - kCommitBlobPayloadOffset;
    const auto payload_checksum = UpdateFnv1a(
        kCheckpointChecksumSeed,
        blob.data() + static_cast<std::vector<std::byte>::difference_type>(kCommitBlobPayloadOffset),
        payload_bytes);
    WriteLe32(blob, kCommitBlobChecksumOffset, payload_checksum);

    auto remainder = blob.size() % block_size_;
    if (remainder != 0)
    {
        blob.resize(blob.size() + (block_size_ - remainder), std::byte{});
    }

    return blob;
}

void MetadataStore::AppendLe32(std::vector<std::byte>& blob, std::uint32_t value)
{
    blob.push_back(static_cast<std::byte>(value & 0xffu));
    blob.push_back(static_cast<std::byte>((value >> 8) & 0xffu));
    blob.push_back(static_cast<std::byte>((value >> 16) & 0xffu));
    blob.push_back(static_cast<std::byte>((value >> 24) & 0xffu));
}

void MetadataStore::AppendLe64(std::vector<std::byte>& blob, std::uint64_t value)
{
    for (int i = 0; i < 8; ++i)
    {
        blob.push_back(static_cast<std::byte>((value >> (8 * i)) & 0xffu));
    }
}

void MetadataStore::WriteLe32(std::vector<std::byte>& buffer, std::size_t offset, std::uint32_t value)
{
    if (offset + sizeof(std::uint32_t) > buffer.size())
    {
        return;
    }

    buffer[offset + 0] = static_cast<std::byte>(value & 0xffu);
    buffer[offset + 1] = static_cast<std::byte>((value >> 8) & 0xffu);
    buffer[offset + 2] = static_cast<std::byte>((value >> 16) & 0xffu);
    buffer[offset + 3] = static_cast<std::byte>((value >> 24) & 0xffu);
}

void MetadataStore::WriteLe64(std::vector<std::byte>& buffer, std::size_t offset, std::uint64_t value)
{
    if (offset + sizeof(std::uint64_t) > buffer.size())
    {
        return;
    }

    for (int i = 0; i < 8; ++i)
    {
        buffer[offset + static_cast<std::size_t>(i)] = static_cast<std::byte>((value >> (8 * i)) & 0xffu);
    }
}

std::uint32_t MetadataStore::ReadLe32(const std::vector<std::byte>& buffer, std::size_t offset)
{
    if (offset + sizeof(std::uint32_t) > buffer.size())
    {
        return 0;
    }

    const auto* p = reinterpret_cast<const unsigned char*>(buffer.data() + offset);
    return static_cast<std::uint32_t>(p[0]) |
           (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) |
           (static_cast<std::uint32_t>(p[3]) << 24);
}

std::uint64_t MetadataStore::ReadLe64(const std::vector<std::byte>& buffer, std::size_t offset)
{
    if (offset + sizeof(std::uint64_t) > buffer.size())
    {
        return 0;
    }

    const auto* p = reinterpret_cast<const unsigned char*>(buffer.data() + offset);
    return static_cast<std::uint64_t>(p[0]) |
           (static_cast<std::uint64_t>(p[1]) << 8) |
           (static_cast<std::uint64_t>(p[2]) << 16) |
           (static_cast<std::uint64_t>(p[3]) << 24) |
           (static_cast<std::uint64_t>(p[4]) << 32) |
           (static_cast<std::uint64_t>(p[5]) << 40) |
           (static_cast<std::uint64_t>(p[6]) << 48) |
           (static_cast<std::uint64_t>(p[7]) << 56);
}
} // namespace apfsaccess::rw
