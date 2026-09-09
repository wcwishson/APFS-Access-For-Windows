#pragma once
#include "ApfsTransactionWriter.h"
#include <span>
namespace apfsaccess::rw {
// NCL1: exact native source record bytes, never file payload bytes.
struct NativeCloneProof {
    std::uint64_t checkpoint=0, volume=0, source=0, generation=0, target=0;
    std::string container_uuid, volume_uuid;
    std::vector<catalog::BtreeRecord> records;
};
inline std::vector<std::byte> EncodeNativeClone(const NativeCloneProof& p) {
    std::vector<std::byte> b;
    auto put=[&](std::uint64_t n){for(unsigned i=0;i<8;++i)b.push_back(std::byte((n>>(8*i))&255));};
    put(0x314c434e);put(p.checkpoint);put(p.volume);put(p.source);put(p.generation);put(p.target);
    for(const auto* uuid:{&p.container_uuid,&p.volume_uuid}){put(uuid->size());for(auto c:*uuid)b.push_back(std::byte(static_cast<unsigned char>(c)));}
    put(p.records.size());
    for(const auto& r:p.records)for(const auto* v:{&r.key,&r.value}){put(v->size());b.insert(b.end(),v->begin(),v->end());}
    return b;
}
inline bool DecodeNativeClone(std::span<const std::byte> b, NativeCloneProof& out) {
    if(b.size()<72 || b.size()>(1u<<20))return false;
    std::size_t at=0;bool ok=true;
    auto get=[&](){std::uint64_t n=0;if(b.size()-at<8){ok=false;return n;}for(unsigned i=0;i<8;++i)n|=std::uint64_t(std::to_integer<unsigned char>(b[at++]))<<(8*i);return n;};
    if(get()!=0x314c434e)return false;
    NativeCloneProof p;p.checkpoint=get();p.volume=get();p.source=get();p.generation=get();p.target=get();
    for(auto* uuid:{&p.container_uuid,&p.volume_uuid}){auto n=get();if(!ok||(n!=0&&n!=32)||n>b.size()-at)return false;
        for(std::uint64_t i=0;i<n;++i){auto c=std::to_integer<unsigned char>(b[at++]);if(!((c>='0'&&c<='9')||(c>='a'&&c<='f')))return false;uuid->push_back(static_cast<char>(c));}}
    auto count=get();
    if(!p.checkpoint||p.checkpoint==UINT64_MAX||!p.volume||!p.source||!p.generation||p.target<=p.source||p.target>=0x0fffffffffffffffULL||!count||count>4096)return false;
    for(std::uint64_t i=0;i<count;++i){catalog::BtreeRecord r;for(auto* v:{&r.key,&r.value}){auto n=get();if(!ok||n>b.size()-at)return false;v->assign(b.begin()+at,b.begin()+at+n);at+=static_cast<std::size_t>(n);}if(r.key.size()<8)return false;p.records.push_back(std::move(r));}
    if(!ok||at!=b.size())return false;out=std::move(p);return true;
}
}
