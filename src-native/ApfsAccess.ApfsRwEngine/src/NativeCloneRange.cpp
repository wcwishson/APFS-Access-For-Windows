#include "NativeCloneRange.h"
#include <algorithm>

namespace apfsaccess::rw
{
namespace
{
constexpr std::uint64_t Magic1 = 0x3152434e; // NCR1
constexpr std::uint64_t Magic2 = 0x3252434e; // NCR2
void Number(std::vector<std::byte>& bytes, std::uint64_t n)
{ for (unsigned i = 0; i < 8; ++i) bytes.push_back(std::byte(n >> (8 * i))); }
void Data(std::vector<std::byte>& bytes, std::span<const std::byte> value)
{ Number(bytes, value.size()); bytes.insert(bytes.end(), value.begin(), value.end()); }
bool Uuid(std::string_view text)
{ return text.size() == 32 && text != std::string(32, '0') && text.find_first_not_of("0123456789abcdef") == text.npos; }
template<class T> bool Nonzero(const T& bytes)
{ return std::any_of(bytes.begin(), bytes.end(), [](auto b) { return b != decltype(b){}; }); }
bool Path(std::string_view text)
{ return !text.empty() && text.front() == '\\' && text.size() <= 4096 && text.find('\0') == text.npos; }
bool Valid(const NativeCloneRangeProof& proof)
{
    constexpr auto mask = 0x0fffffffffffffffULL;
    if ((proof.version != 1 && proof.version != 2) || !proof.volume_oid || !proof.checkpoint || proof.checkpoint == UINT64_MAX ||
        !proof.source_inode || !proof.target_inode || proof.source_inode == proof.target_inode ||
        proof.source_inode > mask || proof.target_inode > mask || !proof.source_generation || !proof.target_generation ||
        proof.source_generation > proof.checkpoint || proof.target_generation > proof.checkpoint ||
        !proof.block_count || proof.block_count > static_cast<std::uint64_t>(INT64_MAX) / 4096 ||
        proof.image_size != proof.block_count * 4096 || !Nonzero(proof.image_file_id) ||
        !Uuid(proof.container_uuid) || !Uuid(proof.volume_uuid) || !Path(proof.source_path_utf8) || !Path(proof.target_path_utf8) ||
        !NativeCloneRangeRequestIsValid(proof.request) || proof.preimages.empty() || proof.preimages.size() > NativeCloneRangeMaxPreimages) return false;
    for (const auto* hash : {&proof.before_sha, &proof.after_sha, &proof.before_refs_sha, &proof.after_refs_sha, &proof.payload_sha, &proof.publication_sha})
        if (!Nonzero(*hash)) return false;
    bool first = true; std::uint64_t prior = 0;
    for (const auto& pre : proof.preimages) {
        if (pre.physical_block >= proof.block_count || (first ? pre.physical_block != 0 : pre.physical_block <= prior)) return false;
        prior = pre.physical_block; first = false;
    }
    return true;
}
}
bool NativeCloneRangeRequestIsValid(const NativeCloneRangeRequest& request)
{
    return request.timestamp_ns && request.length && request.length < (1ull << 32) &&
        !(request.source_offset % 4096) && !(request.target_offset % 4096) && !(request.length % 4096) &&
        request.source_offset <= INT64_MAX && request.length <= INT64_MAX - request.source_offset &&
        request.target_offset <= INT64_MAX && request.length <= INT64_MAX - request.target_offset;
}
std::vector<std::byte> EncodeNativeCloneRange(const NativeCloneRangeProof& proof)
{
    if (!Valid(proof)) return {};
    std::vector<std::byte> bytes; Number(bytes, proof.version == 1 ? Magic1 : Magic2); Number(bytes, proof.version);
    for (const auto n : {proof.volume_oid, proof.checkpoint, proof.source_inode, proof.target_inode,
        proof.source_generation, proof.target_generation, proof.block_count, proof.image_volume_serial, proof.image_size, proof.image_creation_time,
        proof.request.source_offset, proof.request.target_offset, proof.request.length, proof.request.timestamp_ns}) Number(bytes, n);
    Data(bytes, proof.image_file_id);
    for (const auto* text : {&proof.container_uuid, &proof.volume_uuid, &proof.source_path_utf8, &proof.target_path_utf8})
        Data(bytes, std::as_bytes(std::span(*text)));
    for (const auto* hash : {&proof.before_sha, &proof.after_sha, &proof.before_refs_sha, &proof.after_refs_sha, &proof.payload_sha, &proof.publication_sha})
        Data(bytes, std::as_bytes(std::span(*hash)));
    Number(bytes, proof.preimages.size());
    for (const auto& pre : proof.preimages) { Number(bytes, pre.physical_block); Data(bytes, pre.bytes); }
    if (bytes.size() > NativeCloneRangeMaxProofBytes) return {};
    return bytes;
}
bool DecodeNativeCloneRange(std::span<const std::byte> bytes, NativeCloneRangeProof& out)
{
    out = {}; if (bytes.size() < 16 || bytes.size() > NativeCloneRangeMaxProofBytes) return false;
    std::size_t at = 0;
    const auto number = [&](std::uint64_t& n) {
        if (bytes.size() - at < 8) return false;
        n = 0; for (unsigned i = 0; i != 8; ++i) n |= std::uint64_t(std::to_integer<unsigned>(bytes[at++])) << (8 * i);
        return true;
    };
    const auto data = [&](std::size_t maximum, std::span<const std::byte>& value) {
        std::uint64_t count = 0;
        if (!number(count) || count > maximum || count > bytes.size() - at) return false;
        value = bytes.subspan(at, static_cast<std::size_t>(count)); at += static_cast<std::size_t>(count); return true;
    };
    std::uint64_t magic = 0, version = 0;
    if (!number(magic) || !number(version) || !((magic == Magic1 && version == 1) || (magic == Magic2 && version == 2))) return false;
    NativeCloneRangeProof proof;
    proof.version = version;
    for (auto* n : {&proof.volume_oid, &proof.checkpoint, &proof.source_inode, &proof.target_inode,
        &proof.source_generation, &proof.target_generation, &proof.block_count, &proof.image_volume_serial, &proof.image_size, &proof.image_creation_time,
        &proof.request.source_offset, &proof.request.target_offset, &proof.request.length, &proof.request.timestamp_ns}) if (!number(*n)) return false;
    std::span<const std::byte> value;
    if (!data(16, value) || value.size() != 16) return false;
    std::copy(value.begin(), value.end(), proof.image_file_id.begin());
    for (auto* text : {&proof.container_uuid, &proof.volume_uuid, &proof.source_path_utf8, &proof.target_path_utf8}) {
        if (!data(4096, value)) return false;
        text->assign(reinterpret_cast<const char*>(value.data()), value.size());
    }
    for (auto* hash : {&proof.before_sha, &proof.after_sha, &proof.before_refs_sha, &proof.after_refs_sha, &proof.payload_sha, &proof.publication_sha}) {
        if (!data(32, value) || value.size() != 32) return false;
        for (std::size_t i = 0; i != 32; ++i) (*hash)[i] = std::to_integer<std::uint8_t>(value[i]);
    }
    std::uint64_t count = 0;
    if (!number(count) || !count || count > NativeCloneRangeMaxPreimages) return false;
    for (std::uint64_t i = 0; i < count; ++i) {
        NativeHardLinkPreimage pre;
        if (!number(pre.physical_block) || !data(4096, value) || value.size() != 4096) return false;
        std::copy(value.begin(), value.end(), pre.bytes.begin()); proof.preimages.push_back(std::move(pre));
    }
    if (at != bytes.size() || !Valid(proof)) return false;
    out = std::move(proof); return true;
}
bool NativeCloneRangeWalIsConsistent(const WriteAheadLog::Record& record)
{
    NativeCloneRangeProof proof; NativeHardLinkDigest hash;
    return static_cast<std::uint32_t>(record.operation) == NativeCloneRangeOperationKind &&
        record.state == WriteAheadLog::RecordState::Prepared && !record.flags && !record.unlink_outcome &&
        !record.logical_offset && !record.payload_offset && !record.payload_spool_id &&
        record.logical_length == record.inline_payload.size() && record.payload_length == record.inline_payload.size() &&
        DecodeNativeCloneRange(record.inline_payload, proof) && record.object_id == proof.target_inode &&
        record.parent_object_id == proof.checkpoint && record.path_utf8 == proof.target_path_utf8 &&
        record.secondary_path_utf8 == proof.source_path_utf8 &&
        NativeHardLinkHash(record.inline_payload, hash) && hash == record.payload_sha256;
}
}
