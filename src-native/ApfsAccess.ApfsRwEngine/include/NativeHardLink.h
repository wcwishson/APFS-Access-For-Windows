#pragma once
#include "NativeHardLinkPlan.h"
#include "AppleCheckpointPublisher.h"
#include "BlockDevice.h"
#include "WriteAheadLog.h"
#include <array>

namespace apfsaccess::rw
{
class MetadataStore;
struct NativeHardLinkOpenEntry
{
    std::uint64_t object_id = 0, generation = 0, parent_object_id = 0, sibling_id = 0;
    std::string name_utf8;
};
// Owner-minted for one synchronous callback while the caller retains its real
// open contexts and owner gates. This is never a serialized client authority.
class NativeHardLinkSession
{
    friend class MetadataStore;
public:
    NativeHardLinkSession(const NativeHardLinkSession&) = delete;
    NativeHardLinkSession& operator=(const NativeHardLinkSession&) = delete;
    NativeHardLinkSession(NativeHardLinkSession&&) = delete;
    NativeHardLinkSession& operator=(NativeHardLinkSession&&) = delete;
private:
    NativeHardLinkSession(const MetadataStore* owner, std::uint64_t epoch,
        BlockDevice::WriteSourceObservation observation, std::wstring source, std::wstring target)
        : owner_(owner), epoch_(epoch), observation_(std::move(observation)),
          source_(std::move(source)), target_(std::move(target)) {}
    const MetadataStore* owner_;
    std::uint64_t epoch_;
    BlockDevice::WriteSourceObservation observation_;
    std::wstring source_, target_;
    std::uint64_t timestamp_ns_ = 0;
    bool active_ = true;
    mutable bool consumed_ = false;
    mutable bool accepted_ = false, ambiguous_ = false;
};
// Proposed typed original-WAL kind. The TM/WAL owner registers and validates it;
// this constant alone does not make a record accepted or replayable.
inline constexpr std::uint32_t NativeHardLinkOperationKind = 21;
using NativeHardLinkDigest = std::array<std::uint8_t, 32>;
inline constexpr std::size_t MaxNativeHardLinkProofBytes = 1024u * 1024u;
inline constexpr std::size_t MaxNativeHardLinkPreimageBlocks = 240;
struct NativeHardLinkPreimage
{
    std::uint64_t physical_block = 0;
    std::array<std::byte, 4096> bytes{};
    bool operator==(const NativeHardLinkPreimage&) const = default;
};
struct NativeHardLinkProof
{
    std::uint64_t version = 3;
    std::string container_uuid, volume_uuid, original_name, destination_name;
    std::uint64_t volume_oid = 0, checkpoint = 0, source_inode = 0, source_generation = 0;
    std::uint64_t original_parent = 0, destination_parent = 0;
    std::uint64_t first_sibling = 0, next_object_id = 0, timestamp_ns = 0;
    std::uint64_t incompatible_features = 0, block_size = 0, block_count = 0, store_offset = 0;
    std::uint64_t image_volume_serial = 0, image_size = 0, image_creation_time = 0;
    std::array<std::byte, 16> image_file_id{};
    NativeHardLinkDigest before_sha{}, after_sha{}, references_sha{}, payload_sha{}, publication_sha{};
    // Exact guards and destination preimages for read-only canonical replanning.
    // These never authorize arbitrary image writes or a hash-only completion.
    std::vector<NativeHardLinkPreimage> preimages;
    bool operator==(const NativeHardLinkProof&) const = default;
};
bool NativeHardLinkHash(std::span<const std::byte> bytes, NativeHardLinkDigest& out);
bool NativeHardLinkRecordsHash(const std::vector<catalog::BtreeRecord>& records,
    NativeHardLinkDigest& out);
bool NativeHardLinkPublicationHash(const AppleCheckpointPublicationPlan& plan,
    NativeHardLinkDigest& out);
bool NativeHardLinkExtentHash(std::span<const ApplePhysicalExtentRecord>, NativeHardLinkDigest& out);
bool NativeHardLinkLegacyPayloadHash(const BlockDevice&, std::span<const ApplePhysicalExtentRecord>, NativeHardLinkDigest& out);
bool NativeHardLinkWritesExcludePayload(const AppleCheckpointPublicationPlan&,
    std::span<const ApplePhysicalExtentRecord>, std::uint64_t block_count);
std::vector<std::byte> EncodeNativeHardLink(const NativeHardLinkProof& proof);
bool DecodeNativeHardLink(std::span<const std::byte> bytes, NativeHardLinkProof& out);
// Framing/typed-field check only. Recovery still needs the original accepted
// transaction, exact held-image identity and canonical before/after proof.
bool NativeHardLinkWalIsConsistent(const WriteAheadLog::Record& record);
}
