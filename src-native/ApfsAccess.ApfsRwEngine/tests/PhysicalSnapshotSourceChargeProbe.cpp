#define PHYSICAL_SNAPSHOT_NO_MAIN
#include "PhysicalSnapshotMetadataTests.cpp"
#include "../src/AppleTransactionCommit.cpp"

int wmain() {
    try {
        const auto image=GenuineSource();VectorRandomAccessSource source(image);const auto cp=Load(image);
        apfsaccess::rw::RetirementGraph graph;std::string error;
        Call(apfsaccess::rw::BuildRetirementGraph(source,cp,graph,error,apfsaccess::rw::RetentionAdmission::Strict),"genuine graph diagnostic",error);
        for(const auto& [owner,ranges]:graph.owners) {
            std::cout<<"OWNER "<<owner<<" blocks="<<apfsaccess::rw::RetirementCount(ranges)<<" ranges=";
            for(const auto& r:ranges)std::cout<<r.physical_block<<"+"<<r.block_count<<",";
            std::cout<<std::endl;
        }
        const auto& v=cp.volumes[0];
        std::cout<<"ALLOCATED "<<v.superblock.space.allocated_block_count<<" APSB="<<v.superblock_object.physical_block
            <<" OMAP="<<v.object_map.object.physical_block<<" MAPTREE="<<v.object_map.tree.physical_block
            <<" FS="<<v.root_tree.physical_block<<" REFS="<<v.extentref_tree->physical_block
            <<" META="<<v.snapshot_metadata_tree->physical_block<<std::endl;
        return 0;
    }catch(const std::exception& e){std::cerr<<e.what()<<std::endl;return 1;}
}
