#pragma once
#include "NativeVolumeRename.h"
#include "ApfsSnapshotStore.h"
#include "NativeRawSnapshotReceipt.h"
#include <array>
#include <optional>

namespace apfsaccess::rw {
// SNP1 images and source-bound SNP2 raw receipts share the versioned WAL envelope. Bounded
// deterministic arguments, exact inventory, preimage and publication digests.
struct NativeSnapshotIntent {
    bool create = true;
    catalog::ApfsSnapshotScope scope;
    std::uint64_t snapshot_xid = 0, time_ns = 0, inum = 0;
    std::string name;
    catalog::ApfsSnapshotIdentity expected_identity;
    std::vector<catalog::ApfsSnapshotIdentity> inventory;
    std::vector<std::uint64_t> pins;
    std::array<std::uint8_t,32> preimage_hash{}, publication_hash{};
    std::uint64_t checkpoint_slot=0;
    std::vector<std::byte> checkpoint_slot_preimage;
    std::optional<NativeRawSnapshotReceipt> raw_receipt;
};
namespace snapshot_wire {
inline void Put(std::vector<std::byte>& b, std::uint64_t n) { for(unsigned i=0;i<8;++i)b.push_back(std::byte((n>>(8*i))&255)); }
inline void Text(std::vector<std::byte>& b,const std::string& s){Put(b,s.size());for(unsigned char c:s)b.push_back(std::byte(c));}
inline void Identity(std::vector<std::byte>& b,const catalog::ApfsSnapshotIdentity& id) {
    Put(b,id.snapshot_xid);Text(b,id.name_utf8);
    for(auto n:{id.superblock_physical_block,id.omap_physical_block,id.omap_tree_physical_block,id.root_oid,id.root_physical_block,id.extentref_physical_block})Put(b,n);
}
}
inline std::vector<std::byte> EncodeNativeSnapshotIntent(const NativeSnapshotIntent& p) {
    using namespace snapshot_wire;std::vector<std::byte>b;
    if(p.raw_receipt&&!ValidateNativeRawSnapshotReceiptShape(*p.raw_receipt,p.scope.volume_oid,p.scope.volume_uuid_hex,p.scope.store_size_bytes))return b;
    Put(b,p.raw_receipt?0x32504e53:0x31504e53);Put(b,p.create?18:19);Put(b,p.scope.store_offset_bytes);Put(b,p.scope.store_size_bytes);
    Text(b,p.scope.container_uuid_hex);Text(b,p.scope.volume_uuid_hex);Put(b,p.scope.volume_oid);Put(b,p.scope.checkpoint_xid);
    Put(b,p.snapshot_xid);Text(b,p.name);Put(b,p.time_ns);Put(b,p.inum);
    Identity(b,p.expected_identity);
    Put(b,p.inventory.size());for(const auto& id:p.inventory)Identity(b,id);
    Put(b,p.pins.size());for(auto xid:p.pins)Put(b,xid);
    Put(b,p.checkpoint_slot);Put(b,p.checkpoint_slot_preimage.size());b.insert(b.end(),p.checkpoint_slot_preimage.begin(),p.checkpoint_slot_preimage.end());
    if(p.raw_receipt){
        const auto&r=*p.raw_receipt;const auto&h=r.binding.hardware;const auto&m=r.binding.media;
        Put(b,r.binding.version);Put(b,static_cast<std::uint64_t>(h.kind));Put(b,h.bus_type);
        Text(b,h.vendor);Text(b,h.product);Text(b,h.revision);Text(b,h.serial);
        Put(b,h.vpd_code_set);Put(b,h.vpd_type);Put(b,h.vpd_identifier.size());
        b.insert(b.end(),h.vpd_identifier.begin(),h.vpd_identifier.end());
        b.insert(b.end(),m.disk_guid.begin(),m.disk_guid.end());b.insert(b.end(),m.partition_guid.begin(),m.partition_guid.end());
        for(auto n:{m.partition_offset_bytes,m.partition_length_bytes,m.base_offset_bytes,m.limit_bytes,m.disk_size_bytes})Put(b,n);
        Put(b,m.logical_sector_bytes);Put(b,m.physical_sector_bytes);Text(b,r.selected_journal_identity);
        Put(b,r.peers.size());for(const auto&peer:r.peers){Put(b,peer.volume_oid);Text(b,peer.volume_uuid_hex);Text(b,peer.journal_identity);}
    }
    for(const auto& hash:{p.preimage_hash,p.publication_hash})for(auto c:hash)b.push_back(std::byte(c));
    return b;
}
inline bool DecodeNativeSnapshotIntent(std::span<const std::byte>b,NativeSnapshotIntent& out) {
    out={};if(b.size()<200 || b.size()>131072)return false;
    std::size_t at=0;bool ok=true;
    auto get=[&](){std::uint64_t n=0;if(b.size()-at<8){ok=false;return n;}for(unsigned i=0;i<8;++i)n|=std::uint64_t(std::to_integer<unsigned char>(b[at++]))<<(8*i);return n;};
    auto text=[&](std::string& s){auto n=get();if(!ok||n>255||n>b.size()-at){ok=false;return;}s.assign(reinterpret_cast<const char*>(b.data()+at),n);at+=n;};
    const auto magic=get();if(magic!=0x31504e53&&magic!=0x32504e53)return false;const auto op=get();if(op!=18&&op!=19)return false;
    NativeSnapshotIntent p;p.create=op==18;p.scope.store_offset_bytes=get();p.scope.store_size_bytes=get();
    text(p.scope.container_uuid_hex);text(p.scope.volume_uuid_hex);p.scope.volume_oid=get();p.scope.checkpoint_xid=get();
    p.snapshot_xid=get();text(p.name);p.time_ns=get();p.inum=get();
    const auto identity=[&](const catalog::ApfsSnapshotScope&scope){catalog::ApfsSnapshotIdentity id;id.scope=scope;id.snapshot_xid=get();text(id.name_utf8);
        id.superblock_physical_block=get();id.omap_physical_block=get();id.omap_tree_physical_block=get();id.root_oid=get();id.root_physical_block=get();id.extentref_physical_block=get();return id;};
    auto expected_scope=p.scope;if(p.create)++expected_scope.checkpoint_xid;p.expected_identity=identity(expected_scope);
    auto count=get();if(!ok||count>64)return false;
    std::uint64_t last=0;
    for(std::uint64_t i=0;i<count;++i){catalog::ApfsSnapshotIdentity id;id.scope=p.scope;id.snapshot_xid=get();text(id.name_utf8);
        id.superblock_physical_block=get();id.omap_physical_block=get();id.omap_tree_physical_block=get();id.root_oid=get();id.root_physical_block=get();id.extentref_physical_block=get();
        if(!ok||id.snapshot_xid<=last||id.snapshot_xid>p.scope.checkpoint_xid||!ValidNativeVolumeLabel(id.name_utf8)||!id.superblock_physical_block||!id.omap_physical_block||!id.omap_tree_physical_block||!id.root_oid||!id.root_physical_block||!id.extentref_physical_block)return false;
        if(std::any_of(p.inventory.begin(),p.inventory.end(),[&](const auto&prior){return prior.name_utf8==id.name_utf8;}))return false;
        last=id.snapshot_xid;p.inventory.push_back(std::move(id));}
    count=get();if(!ok||count>64)return false;last=0;
    for(std::uint64_t i=0;i<count;++i){auto xid=get();if(!ok||!xid||xid<=last||xid>p.scope.checkpoint_xid)return false;last=xid;p.pins.push_back(xid);}
    p.checkpoint_slot=get();count=get();if(!ok||count>65536||count>b.size()-at)return false;
    p.checkpoint_slot_preimage.assign(b.begin()+at,b.begin()+at+count);at+=count;
    if(magic==0x32504e53){
        NativeRawSnapshotReceipt r;auto&h=r.binding.hardware;auto&m=r.binding.media;
        const auto read_u32=[&](std::uint32_t&v){const auto n=get();if(!ok||n>UINT32_MAX){ok=false;return;}v=static_cast<std::uint32_t>(n);};
        read_u32(r.binding.version);const auto kind=get();if(!ok||kind<1||kind>2)return false;h.kind=static_cast<RawHardwareIdentityKind>(kind);read_u32(h.bus_type);
        text(h.vendor);text(h.product);text(h.revision);text(h.serial);read_u32(h.vpd_code_set);read_u32(h.vpd_type);
        count=get();if(!ok||count>kRawSnapshotIdentifierMaxBytes||count>b.size()-at)return false;
        h.vpd_identifier.assign(b.begin()+at,b.begin()+at+count);at+=count;
        if(b.size()-at<32)return false;
        for(auto*guid:{&m.disk_guid,&m.partition_guid}){std::copy_n(b.begin()+at,16,guid->begin());at+=16;}
        m.partition_offset_bytes=get();m.partition_length_bytes=get();m.base_offset_bytes=get();m.limit_bytes=get();m.disk_size_bytes=get();
        read_u32(m.logical_sector_bytes);read_u32(m.physical_sector_bytes);text(r.selected_journal_identity);
        count=get();if(!ok||!count||count>100)return false;
        for(std::uint64_t i=0;i<count;++i){NativeRawSnapshotPeer peer;peer.volume_oid=get();text(peer.volume_uuid_hex);text(peer.journal_identity);if(!ok)return false;r.peers.push_back(std::move(peer));}
        if(!ValidateNativeRawSnapshotReceiptShape(r,p.scope.volume_oid,p.scope.volume_uuid_hex,p.scope.store_size_bytes))return false;
        p.raw_receipt=std::move(r);
    }
    if(!ok||b.size()-at!=64)return false;
    for(auto* hash:{&p.preimage_hash,&p.publication_hash})for(auto& c:*hash)c=std::to_integer<std::uint8_t>(b[at++]);
    if(p.scope.store_offset_bytes||!p.scope.store_size_bytes||!p.scope.volume_oid||!p.scope.checkpoint_xid||p.scope.checkpoint_xid==UINT64_MAX||
        !ValidRenameUuid(p.scope.container_uuid_hex)||!ValidRenameUuid(p.scope.volume_uuid_hex)||!ValidNativeVolumeLabel(p.name)||!p.time_ns||
        p.pins.empty()||p.pins.back()!=p.scope.checkpoint_xid)return false;
    const auto found=std::find_if(p.inventory.begin(),p.inventory.end(),[&](const auto& id){return id.snapshot_xid==p.snapshot_xid&&id.name_utf8==p.name;});
    const auto& target=p.expected_identity;
    if(target.snapshot_xid!=p.snapshot_xid||target.name_utf8!=p.name||!target.superblock_physical_block||!target.omap_physical_block||!target.omap_tree_physical_block||!target.root_oid||!target.root_physical_block||!target.extentref_physical_block)return false;
    if(p.create){if(p.snapshot_xid!=p.scope.checkpoint_xid+1||std::any_of(p.inventory.begin(),p.inventory.end(),[&](const auto& id){return id.name_utf8==p.name;}))return false;}
    else if(found==p.inventory.end()||p.inum||*found!=target)return false;
    out=std::move(p);return true;
}
}
