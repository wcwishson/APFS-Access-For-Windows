#pragma once
#include "ApfsSnapshotStore.h"
#include "TestFixtureBuilder.h"
#include <functional>

namespace apfsaccess::testfixture {
using namespace apfsaccess::catalog;
using Bytes = std::vector<std::byte>;
struct SnapshotFixture {
    std::size_t bs;
    Bytes image;
    ApfsSnapshotScope scope;
    std::vector<BtreeRecord> snapshots;
    static constexpr std::uint64_t root_oid = 0x2000 + 101, snap_oid = 0x3000 + 101;
    explicit SnapshotFixture(std::size_t block_size = 4096, std::uint64_t internal_pool_blocks = 4,
        std::uint32_t checkpoint_ring_blocks = 8) : bs(block_size) {
        BuilderStore spec; spec.block_size = static_cast<std::uint32_t>(bs);
        spec.block_count = 512; spec.xid = 20; spec.volumes[0].uuid_hex = std::string(32, 'b');
        spec.authoritative_internal_pool_blocks = internal_pool_blocks;
        spec.authoritative_checkpoint_ring_blocks = checkpoint_ring_blocks;
        image = BuildAuthoritativeStoreImage(spec);
        // Apple requires OMAP_MANUALLY_MANAGED on the container OMAP.
        // Keep the shared legacy fixture helper untouched; specialize here.
        Edit(2,[](auto& b){PutU32LE(b,0x20,1);});
        scope = {0, image.size(), std::string(32, 'a'), std::string(32, 'b'), 101, 20};
        BuilderVolume snap; snap.oid = 180; snap.uuid_hex = scope.volume_uuid_hex;
        snap.vol_omap_oid_override = 181; snap.root_oid_override = root_oid;
        snap.extentref_tree_oid = 184;
        auto apsb = BuildApsb(snap, 10, bs);
        PutU32LE(apsb, 0x18, kObjectPhysical | kObjectTypeFs); Put(180, apsb);
        // The descriptor has no inventory. Its OMAP must not borrow the live
        // header's nonempty snapshot index; versioned filesystem mappings remain shared.
        Put(181, BuildOmap(6, 20, bs, 181, kObjectPhysical | kObjectTypeOmap, kObjectPhysical | kObjectTypeBtree));
        Put(183, BuildRootFsLeaf(10, bs, root_oid, kObjectTypeBtree, kObjectTypeFsTree));
        Put(184, BuildRawLeafNode({}, {}, 10, bs, 0, 184,
            kObjectPhysical | kObjectTypeBtree, kObjectTypeBlockRefTree));
        SetMappings();
        snapshots = {Metadata(10, "backup"), Name(10, "backup")};
        Inventory();
    }
    Bytes Block(std::uint64_t block) const {
        return Bytes(image.begin() + block * bs, image.begin() + (block + 1) * bs);
    }
    void Put(std::uint64_t block, Bytes bytes, bool checksum = true) {
        if (checksum) FletcherForBlock(bytes, bs);
        std::copy(bytes.begin(), bytes.end(), image.begin() + block * bs);
    }
    void Edit(std::uint64_t block, const std::function<void(Bytes&)>& edit, bool checksum = true) {
        auto bytes = Block(block); edit(bytes); Put(block, bytes, checksum);
    }
    void SetMappings(std::vector<OmapRecordSpec> extra = {}) {
        std::vector<OmapRecordSpec> mappings = {{root_oid,183,0,10}, {root_oid,7,0,20}, {snap_oid,9,0,20}};
        mappings.insert(mappings.end(), extra.begin(), extra.end());
        Put(6, BuildBtreeNode(mappings,20,bs,0,6,kObjectPhysical|kObjectTypeBtree,kObjectTypeOmap));
    }
    static BtreeRecord Metadata(std::uint64_t xid, const std::string& name) {
        BtreeRecord out{Bytes(8), Bytes(50 + name.size() + 1)};
        PutU64LE(out.key,0,(1ull<<60)|xid); PutU64LE(out.value,0,184); PutU64LE(out.value,8,180);
        PutU64LE(out.value,16,1234567890123456); PutU64LE(out.value,24,1234567890123499);
        PutU64LE(out.value,32,987); PutU32LE(out.value,40,kObjectPhysical|kObjectTypeBtree);
        PutU16LE(out.value,48,static_cast<std::uint16_t>(name.size()+1)); PutBytes(out.value,50,name.data(),name.size());
        return out;
    }
    static BtreeRecord Name(std::uint64_t xid,const std::string& name) {
        BtreeRecord out{Bytes(10 + name.size() + 1), Bytes(8)};
        PutU64LE(out.key,0,0xBFFFFFFFFFFFFFFFull);
        PutU16LE(out.key,8,static_cast<std::uint16_t>(name.size()+1)); PutBytes(out.key,10,name.data(),name.size());
        PutU64LE(out.value,0,xid); return out;
    }
    void Inventory(std::vector<std::uint64_t> xids = {10}) {
        std::vector<Bytes> keys,values;
        for (const auto& record:snapshots) { keys.push_back(record.key); values.push_back(record.value); }
        Put(9,BuildRawLeafNode(keys,values,20,bs,0,snap_oid,kObjectTypeBtree,kObjectTypeSnapMetaTree));
        Edit(4,[&](auto& b){PutU64LE(b,0xD8,xids.size());});
        keys.clear();values.clear();
        for(auto xid:xids) {Bytes key(8),value(16);PutU64LE(key,0,xid);keys.push_back(key);values.push_back(value);}
        Put(185,BuildRawLeafNode(keys,values,20,bs,0,185,kObjectPhysical|kObjectTypeBtree,0x13));
        Edit(5,[&](auto& b){PutU32LE(b,0x24,static_cast<std::uint32_t>(xids.size()));
            PutU32LE(b,0x2C,kObjectPhysical|kObjectTypeBtree);PutU64LE(b,0x38,185);
            PutU64LE(b,0x40,xids.empty()?0:xids.back());});
    }
    void SecondSnapshot() {
        auto second=Metadata(11,"Backup");PutU64LE(second.value,0,191);PutU64LE(second.value,8,190);
        snapshots.insert(snapshots.begin()+1,second);snapshots.push_back(Name(11,"Backup"));Inventory({10,11});
        auto apsb=Block(180);PutU64LE(apsb,8,190);PutU64LE(apsb,0x10,11);PutU64LE(apsb,0x90,191);Put(190,apsb);
        Put(188,BuildRootFsLeaf(11,bs,root_oid,2,14));
        Put(191,BuildRawLeafNode({}, {},11,bs,0,191,kObjectPhysical|2,15));
        SetMappings({{root_oid,188,0,11}});
    }
    bool Enumerate(std::vector<ApfsSnapshotInfo>& output,std::string& error) const {
        VectorRandomAccessSource source(image);return ApfsSnapshotStore::Enumerate(source,scope,output,error);
    }
};
}
