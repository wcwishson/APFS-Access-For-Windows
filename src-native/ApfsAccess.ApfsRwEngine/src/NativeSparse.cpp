#include "NativeSparse.h"
#include <algorithm>

namespace apfsaccess::rw
{
namespace
{
constexpr std::uint64_t Magic=0x3150534e; // NSP1
void Number(std::vector<std::byte>& bytes,std::uint64_t n){for(unsigned i=0;i<8;++i)bytes.push_back(std::byte(n>>(8*i)));}
void Data(std::vector<std::byte>& bytes,std::span<const std::byte> value){Number(bytes,value.size());bytes.insert(bytes.end(),value.begin(),value.end());}
bool Uuid(std::string_view text){return text.size()==32 && text!=std::string(32,'0') && text.find_first_not_of("0123456789abcdef")==text.npos;}
template<class T> bool Nonzero(const T& bytes){return std::any_of(bytes.begin(),bytes.end(),[](auto b){return b!=decltype(b){};});}
bool Valid(const NativeSparseProof& p)
{
    if(!p.volume_oid || !p.checkpoint || p.checkpoint==UINT64_MAX || !p.inode || !p.generation || p.store_offset ||
        !p.block_count || p.block_count>NativeSparseMaxImageBytes/4096 || p.image_size!=p.block_count*4096 ||
        !Nonzero(p.image_file_id) || !Uuid(p.container_uuid) || !Uuid(p.volume_uuid) || p.path_utf8.empty() ||
        p.path_utf8.size()>4096 || p.path_utf8.find('\0')!=p.path_utf8.npos || !NativeSparseRequestIsValid(p.request) ||
        p.preimages.empty() || p.preimages.size()>NativeSparseMaxPreimages)return false;
    for(const auto* digest:{&p.before_sha,&p.after_sha,&p.before_refs_sha,&p.after_refs_sha,&p.payload_sha,&p.publication_sha})if(!Nonzero(*digest))return false;
    bool first=true;std::uint64_t prior=0;
    for(const auto& pre:p.preimages){if(pre.physical_block>=p.block_count || (first?pre.physical_block!=0:pre.physical_block<=prior))return false;
        prior=pre.physical_block;first=false;}
    return true;
}
}
std::vector<std::byte> EncodeNativeSparse(const NativeSparseProof& p)
{
    if(!Valid(p))return {};
    std::vector<std::byte> b;Number(b,Magic);Number(b,1);
    for(const auto n:{p.volume_oid,p.checkpoint,p.inode,p.generation,p.store_offset,p.block_count,p.image_volume_serial,p.image_size,p.image_creation_time,
        static_cast<std::uint64_t>(p.request.action),static_cast<std::uint64_t>(p.request.sparse),p.request.offset,p.request.length,p.request.timestamp_ns})Number(b,n);
    Data(b,p.image_file_id);
    for(const auto* text:{&p.container_uuid,&p.volume_uuid,&p.path_utf8})Data(b,std::as_bytes(std::span(*text)));
    for(const auto* digest:{&p.before_sha,&p.after_sha,&p.before_refs_sha,&p.after_refs_sha,&p.payload_sha,&p.publication_sha})Data(b,std::as_bytes(std::span(*digest)));
    Number(b,p.preimages.size());for(const auto& pre:p.preimages){Number(b,pre.physical_block);Data(b,pre.bytes);}
    if(b.size()>NativeSparseMaxProofBytes)return {};return b;
}
bool DecodeNativeSparse(std::span<const std::byte> b,NativeSparseProof& out)
{
    out={};if(b.size()<16 || b.size()>NativeSparseMaxProofBytes)return false;
    std::size_t at=0;
    const auto number=[&](std::uint64_t& n){if(b.size()-at<8)return false;n=0;for(unsigned i=0;i<8;++i)n|=std::uint64_t(std::to_integer<unsigned>(b[at++]))<<(8*i);return true;};
    const auto data=[&](std::size_t max,std::span<const std::byte>& bytes){std::uint64_t n=0;if(!number(n)||n>max||n>b.size()-at)return false;
        bytes=b.subspan(at,static_cast<std::size_t>(n));at+=static_cast<std::size_t>(n);return true;};
    std::uint64_t magic=0,version=0,action=0,sparse=0;
    if(!number(magic)||magic!=Magic||!number(version)||version!=1)return false;
    NativeSparseProof p;
    for(auto* n:{&p.volume_oid,&p.checkpoint,&p.inode,&p.generation,&p.store_offset,&p.block_count,&p.image_volume_serial,&p.image_size,&p.image_creation_time,
        &action,&sparse,&p.request.offset,&p.request.length,&p.request.timestamp_ns})if(!number(*n))return false;
    if(sparse>1)return false;p.request.action=static_cast<NativeSparseAction>(action);p.request.sparse=sparse!=0;
    std::span<const std::byte> bytes;
    if(!data(16,bytes)||bytes.size()!=16)return false;std::copy(bytes.begin(),bytes.end(),p.image_file_id.begin());
    for(auto* text:{&p.container_uuid,&p.volume_uuid,&p.path_utf8}){if(!data(4096,bytes))return false;text->assign(reinterpret_cast<const char*>(bytes.data()),bytes.size());}
    for(auto* digest:{&p.before_sha,&p.after_sha,&p.before_refs_sha,&p.after_refs_sha,&p.payload_sha,&p.publication_sha}){
        if(!data(32,bytes)||bytes.size()!=32)return false;for(std::size_t i=0;i<32;++i)(*digest)[i]=std::to_integer<std::uint8_t>(bytes[i]);}
    std::uint64_t count=0;if(!number(count)||!count||count>NativeSparseMaxPreimages)return false;
    p.preimages.reserve(static_cast<std::size_t>(count));
    for(std::uint64_t i=0;i<count;++i){NativeSparsePreimage pre;if(!number(pre.physical_block)||!data(4096,bytes)||bytes.size()!=4096)return false;
        std::copy(bytes.begin(),bytes.end(),pre.bytes.begin());p.preimages.push_back(std::move(pre));}
    if(at!=b.size()||!Valid(p))return false;out=std::move(p);return true;
}
bool NativeSparseWalIsConsistent(const WriteAheadLog::Record& record)
{
    NativeSparseProof p;NativeSparseDigest hash;
    return static_cast<std::uint32_t>(record.operation)==NativeSparseOperationKind && record.state==WriteAheadLog::RecordState::Prepared &&
        !record.flags && !record.unlink_outcome && !record.logical_offset && !record.payload_offset && !record.payload_spool_id &&
        record.secondary_path_utf8.empty() && record.logical_length==record.inline_payload.size() && record.payload_length==record.inline_payload.size() &&
        DecodeNativeSparse(record.inline_payload,p) && record.object_id==p.inode && record.parent_object_id==p.checkpoint && record.path_utf8==p.path_utf8 &&
        NativeHardLinkHash(record.inline_payload,hash) && hash==record.payload_sha256;
}
}
