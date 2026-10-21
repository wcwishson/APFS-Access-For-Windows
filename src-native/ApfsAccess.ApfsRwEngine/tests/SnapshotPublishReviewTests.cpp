#include "AppleVolumeTransaction.h"
#include "SnapshotTestFixture.h"
#include <algorithm>
#include <iostream>
using namespace apfsaccess::catalog;
using namespace apfsaccess::rw;
using namespace apfsaccess::testfixture;
class ReviewTarget final : public AppleCheckpointWriteTarget {
public:
    Bytes bytes;unsigned writes=0;
    explicit ReviewTarget(const Bytes& image):bytes(image){}
    bool ReadBlock(std::uint64_t block,std::uint32_t bs,Bytes& out) override {
        VectorRandomAccessSource source(bytes);return source.Read(block*bs,bs,out);
    }
    bool WriteBlock(std::uint64_t block,std::span<const std::byte> data) override {
        if(data.size()!=4096||block>=bytes.size()/4096)return false;
        std::copy(data.begin(),data.end(),bytes.begin()+block*4096);++writes;return true;
    }
    bool Flush() override{return true;}
};
int main(){
    unsigned failures=0,checks=0;
    const auto check=[&](bool value,const char* message){++checks;std::cout<<(value?"PASS ":"FAIL ")<<message<<'\n';if(!value)++failures;};
    std::string error;std::vector<ApfsSnapshotInfo> snapshots;
    SnapshotFixture cow;
    cow.Edit(180,[](auto& b){PutU64LE(b,0x10,11);});
    cow.Edit(184,[](auto& b){PutU64LE(b,0x10,11);});
    check(cow.Enumerate(snapshots,error),"snapshot 10 reopens metadata COW at XID 11");
    if(!snapshots.empty())check(snapshots[0].identity.snapshot_xid==10&&snapshots[0].metadata.volume.root_tree.xid==10,
        "metadata XID never changes filesystem view XID");
    for(const auto xid:{9ull,21ull}){auto bad=cow;bad.Edit(180,[&](auto& b){PutU64LE(b,0x10,xid);});
        check(!bad.Enumerate(snapshots,error)&&snapshots.empty(),"APSB older than view or newer than checkpoint refuses");}
    {auto bad=cow;bad.Edit(183,[](auto& b){PutU64LE(b,0x10,11);});
        check(!bad.Enumerate(snapshots,error),"newer filesystem bytes cannot enter historical view");}
    {auto bad=cow;bad.Edit(184,[](auto& b){PutU64LE(b,0x10,12);});
        check(!bad.Enumerate(snapshots,error),"extent metadata newer than its APSB refuses");}
    AppleSnapshotCreateRequest request;request.volume_object_id=101;request.name_utf8="guard";request.creation_time_ns=1;
    {
        SnapshotFixture unowned;unowned.snapshots.clear();unowned.Inventory({});
        unowned.Edit(5,[](auto& b){PutU64LE(b,0x38,0);PutU32LE(b,0x2C,0);});
        const auto before=unowned.image;VectorRandomAccessSource source(unowned.image);
        const auto cp=LoadAppleCheckpointView(source,0,source.SizeBytes(),error);
        check(cp.has_value(),"unallocated historical mapping retains a parseable checkpoint");
        if(cp){
            const auto chunk=std::find_if(cp->spaceman.chunks.begin(),cp->spaceman.chunks.end(),
                [](const auto& c){return c.start_block<=183&&183-c.start_block<c.block_count;});
            check(chunk!=cp->spaceman.chunks.end()&&183-chunk->start_block<chunk->allocation_bitmap.size()*8&&
                !(std::to_integer<unsigned>(chunk->allocation_bitmap[(183-chunk->start_block)/8])&
                    (1u<<((183-chunk->start_block)%8))),"historical mapped root 183 is canonically unallocated");
            AppleSnapshotCreatePlan rejected;
            const bool planned=PlanAppleSnapshotCreate(source,*cp,request,rejected,error);
            check(!planned&&error=="AppleSnapshotRetirementOwnershipUnproven"&&
                rejected.commit.publication.before_superblock_writes.empty()&&unowned.image==before,
                "unallocated historical root refuses before a publication plan");
            if(planned||error!="AppleSnapshotRetirementOwnershipUnproven")std::cerr<<"ownership refusal: "<<error<<'\n';
        }
    }
    // Build allocation truth together with the empty graph. SnapshotFixture
    // adds its historical root after the builder has already sealed the bitmap.
    BuilderStore spec;spec.block_count=512;spec.xid=20;spec.volumes[0].uuid_hex=std::string(32,'b');
    const auto empty=BuildAuthoritativeStoreImage(spec);
    VectorRandomAccessSource source(empty);auto cp=LoadAppleCheckpointView(source,0,source.SizeBytes(),error);
    AppleSnapshotCreatePlan plan;
    const bool planned=cp&&PlanAppleSnapshotCreate(source,*cp,request,plan,error);check(planned,"first create review fixture plans");
    if(!planned)std::cerr<<"first create planner: "<<error<<'\n';
    if(planned){ReviewTarget target(empty);const bool published=ExecuteAppleCheckpointPublication(target,plan.commit.publication,error);
        check(published,"first create review fixture publishes");const auto writes=target.writes;const auto before=target.bytes;
        const bool replay=ExecuteAppleCheckpointPublication(target,plan.commit.publication,error);
        check(!replay&&target.writes==writes&&target.bytes==before,"stale snapshot plan refuses before any write");}
    std::cout<<checks<<" checks, "<<failures<<" failures\n";return failures?1:0;
}
