#pragma once
#include "NativeCloneRangePlan.h"
#include "NativeHardLink.h"

namespace apfsaccess::rw
{
inline constexpr std::uint32_t NativeCloneRangeOperationKind = 23;
inline constexpr std::size_t NativeCloneRangeMaxProofBytes = 1024u * 1024u;
inline constexpr std::size_t NativeCloneRangeMaxPreimages = 240;
using NativeCloneRangeOpenEntry = NativeHardLinkOpenEntry;
class NativeCloneRangeSession
{
    friend class MetadataStore;
public:
    NativeCloneRangeSession(const NativeCloneRangeSession&) = delete;
    NativeCloneRangeSession& operator=(const NativeCloneRangeSession&) = delete;
    NativeCloneRangeSession(NativeCloneRangeSession&&) = delete;
    NativeCloneRangeSession& operator=(NativeCloneRangeSession&&) = delete;
private:
    NativeCloneRangeSession(const MetadataStore* owner, std::uint64_t epoch,
        BlockDevice::WriteSourceObservation observation, NativeCloneRangeOpenEntry source,
        NativeCloneRangeOpenEntry target, std::wstring source_path, std::wstring target_path)
        : owner_(owner), epoch_(epoch), observation_(std::move(observation)), source_(std::move(source)),
          target_(std::move(target)), source_path_(std::move(source_path)), target_path_(std::move(target_path)) {}
    const MetadataStore* owner_;
    std::uint64_t epoch_;
    BlockDevice::WriteSourceObservation observation_;
    NativeCloneRangeOpenEntry source_, target_;
    std::wstring source_path_, target_path_;
    bool active_ = true;
    mutable bool consumed_ = false, accepted_ = false, ambiguous_ = false;
};
struct NativeCloneRangeProof
{
    std::uint64_t version = 2;
    std::uint64_t volume_oid = 0, checkpoint = 0, source_inode = 0, target_inode = 0;
    std::uint64_t source_generation = 0, target_generation = 0, block_count = 0;
    std::uint64_t image_volume_serial = 0, image_size = 0, image_creation_time = 0;
    std::array<std::byte, 16> image_file_id{};
    std::string container_uuid, volume_uuid, source_path_utf8, target_path_utf8;
    NativeCloneRangeRequest request;
    NativeHardLinkDigest before_sha{}, after_sha{}, before_refs_sha{}, after_refs_sha{}, payload_sha{}, publication_sha{};
    std::vector<NativeHardLinkPreimage> preimages;
    bool operator==(const NativeCloneRangeProof&) const = default;
};
std::vector<std::byte> EncodeNativeCloneRange(const NativeCloneRangeProof&);
bool DecodeNativeCloneRange(std::span<const std::byte>, NativeCloneRangeProof&);
bool NativeCloneRangeWalIsConsistent(const WriteAheadLog::Record&);
}
