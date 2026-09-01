#pragma once

#include "BtreeMutationCodec.h"
#include "ExtentAllocator.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

namespace apfsaccess::rw
{
struct CheckpointDeltaObjectMapUpdate
{
    std::uint64_t object_id = 0;
    std::uint64_t physical_address = 0;
    std::uint64_t logical_size = 0;
    std::uint64_t xid = 0;
    bool tombstone = false;
};

struct CheckpointDeltaInodeUpdate
{
    std::uint64_t object_id = 0;
    std::uint64_t parent_object_id = 0;
    std::wstring name;
    std::wstring full_path;
    bool is_directory = false;
    std::uint64_t logical_size = 0;
    std::uint64_t data_physical_address = 0;
    std::uint64_t xid = 0;
    std::uint64_t timestamp_utc = 0;
    bool tombstone = false;
};

struct CheckpointDeltaDirectoryLinkUpdate
{
    std::uint64_t parent_object_id = 0;
    std::wstring entry_name;
    std::uint64_t child_object_id = 0;
    std::uint64_t xid = 0;
    bool tombstone = false;
};

struct CheckpointDelta
{
    std::string volume_identity;
    std::uint64_t base_xid = 0;
    std::uint64_t target_xid = 0;
    std::vector<CheckpointDeltaObjectMapUpdate> object_map_updates;
    std::vector<ExtentAllocator::Extent> spaceman_allocations;
    std::vector<ExtentAllocator::Extent> spaceman_deallocations;
    std::vector<CheckpointDeltaInodeUpdate> inode_updates;
    std::vector<CheckpointDeltaDirectoryLinkUpdate> directory_link_updates;
    std::vector<BtreeRecord> btree_records;
};

enum class CheckpointDeltaParseStatus
{
    Ok,
    Empty,
    UnsupportedVersion,
    InvalidHeader,
    InvalidChecksum,
    WrongVolume,
    InvalidXid,
    Truncated,
    InvalidRecord,
};

struct CheckpointDeltaParseResult
{
    CheckpointDeltaParseStatus status = CheckpointDeltaParseStatus::InvalidHeader;
    std::optional<CheckpointDelta> delta;
};

struct CheckpointDeltaChainResult
{
    CheckpointDeltaParseStatus status = CheckpointDeltaParseStatus::InvalidHeader;
    std::uint64_t target_xid = 0;
    CheckpointDelta compacted;
};

struct CheckpointDeltaChainParseResult
{
    CheckpointDeltaParseStatus status = CheckpointDeltaParseStatus::InvalidHeader;
    std::uint64_t base_xid = 0;
    std::uint64_t target_xid = 0;
    std::vector<CheckpointDelta> deltas;
};

struct CheckpointDeltaState
{
    std::string volume_identity;
    std::uint64_t checkpoint_xid = 0;
    std::unordered_map<std::uint64_t, CheckpointDeltaObjectMapUpdate> object_map;
    std::vector<ExtentAllocator::Extent> spaceman_allocations;
    std::unordered_map<std::uint64_t, CheckpointDeltaInodeUpdate> inodes;
    std::unordered_map<std::wstring, CheckpointDeltaDirectoryLinkUpdate> directory_links;
    std::unordered_map<std::string, BtreeRecord> btree_records;
};

class CheckpointDeltaCodec
{
public:
    [[nodiscard]] static std::vector<std::byte> Encode(const CheckpointDelta& delta);

    [[nodiscard]] static CheckpointDeltaParseResult Decode(
        std::span<const std::byte> bytes,
        std::string_view expected_volume_identity);

    [[nodiscard]] static CheckpointDeltaChainResult CompactChain(
        std::span<const CheckpointDelta> deltas,
        std::string_view expected_volume_identity,
        std::uint64_t base_xid);

    [[nodiscard]] static std::vector<std::byte> EncodeChain(
        std::span<const CheckpointDelta> deltas,
        std::string_view volume_identity,
        std::uint64_t base_xid);

    [[nodiscard]] static CheckpointDeltaChainParseResult DecodeChain(
        std::span<const std::byte> bytes,
        std::string_view expected_volume_identity,
        std::uint64_t expected_base_xid);

    [[nodiscard]] static CheckpointDeltaParseStatus ApplyDelta(
        CheckpointDeltaState& state,
        const CheckpointDelta& delta);

    [[nodiscard]] static CheckpointDeltaParseStatus ApplyChain(
        CheckpointDeltaState& state,
        std::span<const CheckpointDelta> deltas);
};
} // namespace apfsaccess::rw
