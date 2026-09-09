#include "ApfsFormat.h"
#include "TestFixtureBuilder.h"
#include <iostream>
using namespace apfsaccess::catalog;
using namespace apfsaccess::testfixture;
int main() {
    unsigned passed=0, failed=0;
    for(unsigned mutation=0;mutation<6;++mutation) {
        auto node=BuildRawLeafNode({}, {},10,4096,0,1,kObjectPhysical|kObjectTypeBtree,kObjectTypeSnapMetaTree);
        if(mutation==0) PutU16LE(node,0x20,0x43);
        if(mutation==1) PutU32LE(node,4096-40,0x80000050);
        if(mutation==2) PutU32LE(node,0x18,0x41000002);
        if(mutation==3) PutU16LE(node,0x20,0xB);
        if(mutation==4) PutU64LE(node,4096-16,1);
        if(mutation==5) PutU64LE(node,4096-8,2);
        FletcherForBlock(node,4096);
        std::vector<std::byte> bytes(8192);std::copy(node.begin(),node.end(),bytes.begin()+4096);
        VectorRandomAccessSource source(bytes);BtreeReadPolicy policy;
        policy.enforce_object_identity=true;policy.require_complete_traversal=true;
        policy.root_object_id=1;policy.storage_type=kObjectPhysical;policy.subtype=kObjectTypeSnapMetaTree;
#ifdef SNAPSHOT_STRICT_POLICY
        policy.reject_unsupported_flags=true;
#endif
        std::vector<BtreeRecord> out;std::string error;
        const bool accepted=ReadBtreeLeafRecords(source,4096,1,true,0,10,policy,out,error);
        if(!accepted&&!error.empty()) {++passed;std::cout<<"PASS malformed flags case "<<mutation<<": "<<error<<"\n";}
        else {++failed;std::cout<<"FAIL malformed flags case "<<mutation<<": baseline accepted unsupported layout\n";}
        // Strict snapshot validation must remain opt-in. These legacy layouts
        // retain the same acceptance with a completely default policy.
        const bool default_accepted=ReadBtreeLeafRecords(source,4096,1,true,0,10,
            BtreeReadPolicy{},out,error);
        if(default_accepted && error.empty()) {
            ++passed;std::cout<<"PASS default policy case "<<mutation<<"\n";
        } else {
            ++failed;std::cout<<"FAIL default policy case "<<mutation<<": "<<error<<"\n";
        }
    }
    std::cout<<"RESULT passed="<<passed<<" failed="<<failed<<"\n";
    return failed?1:0;
}
