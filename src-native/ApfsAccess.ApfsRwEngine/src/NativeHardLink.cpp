#include "NativeHardLink.h"
#include <algorithm>
#include <bcrypt.h>
#include <limits>

namespace apfsaccess::rw
{
namespace
{
constexpr std::uint64_t Mask = 0x0fffffffffffffffULL;
constexpr std::size_t Limit = MaxNativeHardLinkProofBytes;
bool Nonzero(const auto& bytes)
{
    return std::any_of(bytes.begin(), bytes.end(), [](auto value) { return value != decltype(value){}; });
}
bool Uuid(std::string_view text)
{
    return text.size() == 32 && std::all_of(text.begin(), text.end(), [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); }) &&
        text != std::string(32, '0');
}
bool Valid(const NativeHardLinkProof& p)
{
    if ((p.version != 2 && p.version != 3) || p.preimages.empty() || p.preimages.size() > MaxNativeHardLinkPreimageBlocks ||
        p.preimages.front().physical_block != 0) return false;
    for (std::size_t i = 0; i < p.preimages.size(); ++i)
        if (p.preimages[i].physical_block >= p.block_count ||
            (i && p.preimages[i - 1].physical_block >= p.preimages[i].physical_block)) return false;
    const auto policy = ApfsNamePolicy::FromIncompatibleFeatures(p.incompatible_features);
    const auto name = [&](const std::string& text) {
        return ApfsNameCodec::Decode(std::as_bytes(std::span(text)), policy).ok();
    };
    return Uuid(p.container_uuid) && Uuid(p.volume_uuid) && p.volume_oid && p.volume_oid < Mask &&
        p.checkpoint && p.checkpoint != UINT64_MAX && p.source_inode > 2 && p.source_inode < Mask &&
        p.source_generation && p.source_generation <= p.checkpoint && p.original_parent && p.original_parent < Mask &&
        p.destination_parent && p.destination_parent < Mask && p.source_inode != p.destination_parent &&
        p.first_sibling > (std::max)({p.source_inode,p.original_parent,p.destination_parent}) &&
        p.first_sibling < Mask - 1 && p.next_object_id >= p.first_sibling + (p.version == 2 ? 2 : 1) &&
        p.next_object_id < Mask && p.timestamp_ns &&
        p.block_size == 4096 && p.block_count && p.block_count <= UINT64_MAX / p.block_size &&
        p.store_offset <= p.image_size && p.block_count * p.block_size <= p.image_size - p.store_offset &&
        p.image_creation_time && Nonzero(p.image_file_id) && Nonzero(p.before_sha) && Nonzero(p.after_sha) &&
        Nonzero(p.references_sha) && Nonzero(p.payload_sha) && Nonzero(p.publication_sha) && name(p.original_name) && name(p.destination_name);
}
void U64(std::vector<std::byte>& bytes, std::uint64_t value)
{
    for (unsigned i = 0; i != 8; ++i) bytes.push_back(std::byte((value >> (i * 8)) & 255));
}
void Data(std::vector<std::byte>& bytes, std::span<const std::byte> value)
{
    U64(bytes,value.size()); bytes.insert(bytes.end(),value.begin(),value.end());
}
class Hash
{
public:
    Hash()
    {
        if (BCryptOpenAlgorithmProvider(&algorithm_,BCRYPT_SHA256_ALGORITHM,nullptr,0) >= 0)
            valid_ = BCryptCreateHash(algorithm_,&hash_,nullptr,0,nullptr,0,0) >= 0;
    }
    ~Hash()
    {
        if (hash_) BCryptDestroyHash(hash_);
        if (algorithm_) BCryptCloseAlgorithmProvider(algorithm_,0);
    }
    bool Bytes(std::span<const std::byte> bytes)
    {
        if (!valid_ || bytes.size() > ULONG_MAX) return valid_ = false;
        if (!bytes.empty()) valid_ = BCryptHashData(hash_,reinterpret_cast<PUCHAR>(const_cast<std::byte*>(bytes.data())),
            static_cast<ULONG>(bytes.size()),0) >= 0;
        return valid_;
    }
    bool Number(std::uint64_t value)
    {
        std::array<std::byte,8> bytes{};
        for (unsigned i=0;i!=8;++i) bytes[i]=std::byte((value>>(i*8))&255);
        return Bytes(bytes);
    }
    bool Field(std::span<const std::byte> bytes) { return Number(bytes.size()) && Bytes(bytes); }
    bool Finish(NativeHardLinkDigest& out)
    {
        out={};
        if (!valid_ || BCryptFinishHash(hash_,out.data(),static_cast<ULONG>(out.size()),0)<0) {out={};return false;}
        return true;
    }
private:
    BCRYPT_ALG_HANDLE algorithm_ = nullptr;
    BCRYPT_HASH_HANDLE hash_ = nullptr;
    bool valid_ = false;
};
}
bool NativeHardLinkHash(std::span<const std::byte> bytes, NativeHardLinkDigest& out)
{
    out={}; Hash hash; return hash.Bytes(bytes) && hash.Finish(out);
}
bool NativeHardLinkExtentHash(std::span<const ApplePhysicalExtentRecord> extents, NativeHardLinkDigest& out)
{
    out={};if(extents.size()>16384)return false;
    Hash hash;constexpr std::string_view domain="apfs-native-hardlink-no-payload-writes-v1";
    if(!hash.Field(std::as_bytes(std::span(domain)))||!hash.Number(extents.size()))return false;
    std::uint64_t end=0;
    for(const auto& extent:extents){
        catalog::BtreeRecord encoded;std::string error;
        if(!extent.block_count||extent.physical_block<end||extent.block_count>UINT64_MAX-extent.physical_block||
            !EncodeApplePhysicalExtentRecord(extent,encoded,error)||!hash.Field(encoded.key)||!hash.Field(encoded.value))return false;
        end=extent.physical_block+extent.block_count;
    }
    return hash.Finish(out);
}
bool NativeHardLinkLegacyPayloadHash(const BlockDevice& device,std::span<const ApplePhysicalExtentRecord> extents,
    NativeHardLinkDigest& out)
{
    out={};Hash hash;std::uint64_t total=0;
    constexpr std::uint64_t limit=32ULL<<20;
    for(const auto& extent:extents){
        if(total>limit-16||!extent.block_count||extent.block_count>(limit-total-16)/4096||
            extent.physical_block>UINT64_MAX/4096)return false;
        const auto size=extent.block_count*4096,start=extent.physical_block*4096;
        if(start>device.GetGeometry().total_bytes||size>device.GetGeometry().total_bytes-start||
            !hash.Number(extent.physical_block)||!hash.Number(extent.block_count))return false;
        for(std::uint64_t at=0;at<size;){
            const auto count=static_cast<std::size_t>((std::min)(size-at,64ULL*1024));
            std::vector<std::byte> bytes;
            if(!device.ReadForVerification(start+at,count,bytes)||bytes.size()!=count||!hash.Bytes(bytes))return false;
            at+=count;
        }
        total+=16+size;
    }
    return hash.Finish(out);
}
bool NativeHardLinkWritesExcludePayload(const AppleCheckpointPublicationPlan& plan,
    std::span<const ApplePhysicalExtentRecord> extents,std::uint64_t block_count)
{
    if(plan.block_size!=4096||plan.fusion_tier2_anchor_write||extents.size()>16384||
        plan.before_superblock_writes.size()>MaxNativeHardLinkPreimageBlocks)return false;
    for(const auto& extent:extents)
        if(!extent.block_count||extent.physical_block>=block_count||extent.block_count>block_count-extent.physical_block)return false;
    const auto excluded=[&](const auto& write){
        if(write.bytes.empty()||write.bytes.size()%4096||write.physical_block>=block_count||
            write.bytes.size()/4096>block_count-write.physical_block)return false;
        const auto end=write.physical_block+write.bytes.size()/4096;
        for(const auto& extent:extents)
            if(write.physical_block<extent.physical_block+extent.block_count&&extent.physical_block<end)return false;
        return true;
    };
    return excluded(plan.superblock_write)&&std::all_of(plan.before_superblock_writes.begin(),plan.before_superblock_writes.end(),excluded);
}
bool NativeHardLinkRecordsHash(const std::vector<catalog::BtreeRecord>& records, NativeHardLinkDigest& out)
{
    out={}; if(records.size()>16384)return false;
    Hash hash; if(!hash.Number(1)||!hash.Number(records.size()))return false;
    std::size_t total=0;
    for(const auto& record:records)
    {
        if(record.key.size()>1048576-total)return false;total+=record.key.size();
        if(record.value.size()>1048576-total)return false;total+=record.value.size();
        if(!hash.Field(record.key)||!hash.Field(record.value))return false;
    }
    return hash.Finish(out);
}
bool NativeHardLinkPublicationHash(const AppleCheckpointPublicationPlan& p, NativeHardLinkDigest& out)
{
    out={};
    if(p.fusion_tier2_anchor_write || p.guard_blocks.size()>16384 || p.before_superblock_writes.size()>16384)return false;
    Hash hash;
    if(!hash.Number(1)||!hash.Number(p.block_size)||!hash.Number(p.expected_checkpoint_xid)||
        !hash.Number(p.transaction_xid)||!hash.Number(p.next_object_id)||!hash.Number(p.guard_blocks.size()))return false;
    std::size_t total=0;
    const auto bytes=[&](const auto& block){
        if(block.bytes.size()> (64ULL<<20)-total)return false;total+=block.bytes.size();
        return hash.Number(block.physical_block)&&hash.Field(block.bytes);
    };
    for(const auto& guard:p.guard_blocks)if(!bytes(guard))return false;
    if(!hash.Number(p.before_superblock_writes.size()))return false;
    const auto write=[&](const auto& w){return hash.Number(static_cast<std::uint64_t>(w.kind))&&hash.Number(w.object_id)&&bytes(w);};
    for(const auto& w:p.before_superblock_writes)if(!write(w))return false;
    return write(p.superblock_write)&&hash.Finish(out);
}
std::vector<std::byte> EncodeNativeHardLink(const NativeHardLinkProof& p)
{
    if(!Valid(p))return {};
    std::vector<std::byte> bytes{std::byte{'N'},std::byte{'H'},std::byte{'L'},std::byte(p.version==2?'2':'3')};
    U64(bytes,p.version);
    for(const auto value:{p.volume_oid,p.checkpoint,p.source_inode,p.source_generation,p.original_parent,p.destination_parent,
        p.first_sibling,p.next_object_id,p.timestamp_ns,p.incompatible_features,p.block_size,p.block_count,p.store_offset,
        p.image_volume_serial,p.image_size,p.image_creation_time})U64(bytes,value);
    Data(bytes,p.image_file_id);
    for(const auto* text:{&p.container_uuid,&p.volume_uuid,&p.original_name,&p.destination_name})Data(bytes,std::as_bytes(std::span(*text)));
    for(const auto* digest:{&p.before_sha,&p.after_sha,&p.references_sha,&p.payload_sha,&p.publication_sha})Data(bytes,std::as_bytes(std::span(*digest)));
    U64(bytes,p.preimages.size());
    for (const auto& preimage : p.preimages) { U64(bytes,preimage.physical_block); Data(bytes,preimage.bytes); }
    if(bytes.size()>Limit)return {};
    return bytes;
}
bool DecodeNativeHardLink(std::span<const std::byte> bytes, NativeHardLinkProof& out)
{
    out={};
    if(bytes.size()<12 || bytes.size()>Limit || bytes[0]!=std::byte{'N'} || bytes[1]!=std::byte{'H'} ||
        bytes[2]!=std::byte{'L'} || (bytes[3]!=std::byte{'2'}&&bytes[3]!=std::byte{'3'}))return false;
    std::size_t at=4;
    const auto number=[&](std::uint64_t& value){
        value=0;if(bytes.size()-at<8)return false;
        for(unsigned i=0;i!=8;++i)value|=static_cast<std::uint64_t>(std::to_integer<unsigned char>(bytes[at++]))<<(i*8);
        return true;
    };
    std::uint64_t version=0;if(!number(version)||(version!=2&&version!=3)||
        bytes[3]!=std::byte(version==2?'2':'3'))return false;
    NativeHardLinkProof p;
    p.version=version;
    for(auto* value:{&p.volume_oid,&p.checkpoint,&p.source_inode,&p.source_generation,&p.original_parent,&p.destination_parent,
        &p.first_sibling,&p.next_object_id,&p.timestamp_ns,&p.incompatible_features,&p.block_size,&p.block_count,&p.store_offset,
        &p.image_volume_serial,&p.image_size,&p.image_creation_time})if(!number(*value))return false;
    const auto data=[&](std::size_t limit,std::span<const std::byte>& value){
        std::uint64_t size=0;if(!number(size)||size>limit||size>bytes.size()-at)return false;
        value=bytes.subspan(at,static_cast<std::size_t>(size));at+=static_cast<std::size_t>(size);return true;
    };
    std::span<const std::byte> value;
    if(!data(16,value)||value.size()!=16)return false;
    std::copy(value.begin(),value.end(),p.image_file_id.begin());
    for(auto* text:{&p.container_uuid,&p.volume_uuid,&p.original_name,&p.destination_name}){
        if(!data(255,value))return false;text->assign(reinterpret_cast<const char*>(value.data()),value.size());
    }
    for(auto* digest:{&p.before_sha,&p.after_sha,&p.references_sha,&p.payload_sha,&p.publication_sha}){
        if(!data(32,value)||value.size()!=32)return false;
        for(std::size_t i=0;i!=32;++i)(*digest)[i]=std::to_integer<std::uint8_t>(value[i]);
    }
    std::uint64_t count=0;
    if(!number(count)||!count||count>MaxNativeHardLinkPreimageBlocks)return false;
    p.preimages.reserve(static_cast<std::size_t>(count));
    for(std::uint64_t i=0;i<count;++i){
        NativeHardLinkPreimage preimage;
        if(!number(preimage.physical_block)||!data(preimage.bytes.size(),value)||value.size()!=preimage.bytes.size())return false;
        std::copy(value.begin(),value.end(),preimage.bytes.begin());p.preimages.push_back(std::move(preimage));
    }
    if(at!=bytes.size()||!Valid(p))return false;
    out=std::move(p);return true;
}
bool NativeHardLinkWalIsConsistent(const WriteAheadLog::Record& record)
{
    NativeHardLinkProof p; NativeHardLinkDigest hash{};
    return static_cast<std::uint32_t>(record.operation)==NativeHardLinkOperationKind &&
        record.state==WriteAheadLog::RecordState::Prepared && record.flags==0 && !record.unlink_outcome && record.logical_offset==0 &&
        record.logical_length==record.inline_payload.size() && record.payload_length==record.inline_payload.size() &&
        record.payload_offset==0 && record.payload_spool_id==0 &&
        !record.inline_payload.empty() && DecodeNativeHardLink(record.inline_payload,p) &&
        record.object_id==p.source_inode && record.parent_object_id==p.checkpoint &&
        !record.path_utf8.empty() && record.path_utf8.size()<=4096 && record.path_utf8.find('\0')==std::string::npos &&
        !record.secondary_path_utf8.empty() && record.secondary_path_utf8.size()<=4096 &&
        record.secondary_path_utf8.find('\0')==std::string::npos && record.path_utf8!=record.secondary_path_utf8 &&
        NativeHardLinkHash(record.inline_payload,hash) && hash==record.payload_sha256;
}
}
