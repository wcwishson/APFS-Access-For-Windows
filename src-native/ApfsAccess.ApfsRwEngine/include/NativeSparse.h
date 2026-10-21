#pragma once
#include "NativeSparsePlan.h"
#include "NativeHardLink.h"

namespace apfsaccess::rw
{
// Reservation proposed to the TM/WAL owner. Acceptance also requires its
// matching registered enum; this number grants no publication authority.
inline constexpr std::uint32_t NativeSparseOperationKind = 22;
using NativeSparseDigest = NativeHardLinkDigest;
inline constexpr std::size_t NativeSparseMaxPreimages = 240;
inline constexpr std::size_t NativeSparseMaxProofBytes = 1024u * 1024u;
struct NativeSparseOpenEntry
{
    std::uint64_t object_id = 0, generation = 0, parent_object_id = 0, sibling_id = 0;
    std::string name_utf8;
};
// Valid only inside the synchronous owner callback while the actual open
// context and the caller's store/journal gates remain held.
class NativeSparseSession
{
    friend class MetadataStore;
public:
    NativeSparseSession(const NativeSparseSession&) = delete;
    NativeSparseSession& operator=(const NativeSparseSession&) = delete;
    NativeSparseSession(NativeSparseSession&&) = delete;
    NativeSparseSession& operator=(NativeSparseSession&&) = delete;
private:
    NativeSparseSession(const MetadataStore* owner,std::uint64_t epoch,
        BlockDevice::WriteSourceObservation observation,std::uint64_t inode,std::uint64_t generation,std::wstring path)
        : owner_(owner),epoch_(epoch),observation_(std::move(observation)),inode_(inode),generation_(generation),path_(std::move(path)){}
    const MetadataStore* owner_;
    std::uint64_t epoch_;
    BlockDevice::WriteSourceObservation observation_;
    std::uint64_t inode_, generation_;
    std::wstring path_;
    bool active_ = true;
    mutable bool consumed_ = false, succeeded_ = false, accepted_ = false, ambiguous_ = false;
};
struct NativeSparsePreimage
{
    std::uint64_t physical_block = 0;
    std::array<std::byte,4096> bytes{};
    bool operator==(const NativeSparsePreimage&) const = default;
};
struct NativeSparseProof
{
    std::uint64_t volume_oid = 0, checkpoint = 0, inode = 0, generation = 0;
    std::uint64_t store_offset = 0, block_count = 0, image_volume_serial = 0, image_size = 0, image_creation_time = 0;
    std::array<std::byte,16> image_file_id{};
    std::string container_uuid, volume_uuid, path_utf8;
    NativeSparseRequest request;
    NativeSparseDigest before_sha{}, after_sha{}, before_refs_sha{}, after_refs_sha{}, payload_sha{}, publication_sha{};
    std::vector<NativeSparsePreimage> preimages;
    bool operator==(const NativeSparseProof&) const = default;
};
std::vector<std::byte> EncodeNativeSparse(const NativeSparseProof&);
bool DecodeNativeSparse(std::span<const std::byte>, NativeSparseProof&);
bool NativeSparseWalIsConsistent(const WriteAheadLog::Record&);
}
