#include "AppleReadOnlyRetention.h"
#include "ApfsReadOnlyMetadataAdmission.h"
#include "ApfsVerificationJson.h"
#include "../src/SnapshotPlanningSource.h"
#define APFS_SNAPSHOT_ATTRIBUTION_FIXTURES_ONLY
#include "ApfsSnapshotAttributionTests.cpp"
#undef APFS_SNAPSHOT_ATTRIBUTION_FIXTURES_ONLY

namespace
{
void InactiveDefaults(Fixture& f)
{
    VectorRandomAccessSource source(f.image); AppleSnapshotCatalogRecords catalog; std::string error;
    Check(LoadAppleSnapshotCatalog(source, f.checkpoint, 101, catalog, error), error);
    std::set<std::uint64_t> blocks;
    for (const auto& generation : f.generations)
        for (const auto& volume : generation.volumes) blocks.insert(volume.superblock_object.physical_block);
    for (const auto& snapshot : catalog.inventory) blocks.insert(snapshot.volume.superblock_object.physical_block);
    for (const auto block : blocks) f.Edit(block, [](auto& bytes) {
        PutU32LE(bytes, 0x410, kObjectPhysical | kObjectTypeBtree);
        PutU32LE(bytes, 0x414, kObjectPhysical | kObjectTypeBtree);
    });
    f.Reload(); f.scope.account_retained_ownership = true;
}

void CompleteReadOnly(Fixture& f)
{
    const auto original = f.image; VectorRandomAccessSource source(f.image);
    const auto report = ApfsVerifier::VerifyReadOnly(source, f.scope);
    Accounted(report);
    Check(report.repair.refusal == ApfsRepairRefusal::NoIndependentReconstructionEvidence, "read-only completeness grants no repair authority");
    const auto strict = ApfsVerifier::Verify(source, f.scope);
    Check(strict.outcome == VerificationOutcome::Refused && !strict.retained_ownership && !strict.allocation_census,
        "old verifier stays strict after observational success");
    std::optional<ApfsSnapshotSpaceAttribution> result; std::string error;
    Check(!TryAttributeAppleSnapshotSpace(source, f.scope, result, error) && !result, "old attribution stays strict");
    const auto attributed = TryAttributeAppleSnapshotSpaceReadOnly(source, f.scope, result, error);
    Check(attributed && result && result->complete && result->read_budget, "explicit read-only attribution: " + error);
    Check(result->retained_checkpoint_xids == report.retained_ownership->checkpoint_xids &&
        result->allocation_unit_bytes == f.bs, "attribution shares exact retained closure and geometry");
    for (const auto& row : result->snapshots)
        Check(!row.apple_purgeable && !row.reclaimable && !row.purgeable_marked_payload.blocks &&
            row.payload.referenced.blocks == row.payload.shared_with_live.blocks + row.payload.absent_from_live.blocks,
            "bounded physical amounts retain policy unknowns");
    std::string json; payload::Reason reason;
    Check(SerializeSnapshotSpaceAttribution(result, f.scope, "D:\\readonly-fixture.apfs", [] { return true; },
        MaxSnapshotSpaceAttributionJsonBytes, json, reason) && json.find("\"complete\":true") != std::string::npos,
        "complete observational attribution uses unchanged serializer");
    Check(f.image == original, "all observational and refusal operations preserve source bytes");
}

void PhysicalEmptyInventory(Fixture& f)
{
    const auto& volume = f.checkpoint.volumes.at(0);
    const auto root = volume.root_tree;
    const auto inventory = *volume.snapshot_metadata_tree;
    f.Put(volume.object_map.tree.physical_block, BuildBtreeNode(
        {OmapRecordSpec{root.object_id, root.physical_block, 0, root.xid}},
        volume.object_map.tree.xid, f.bs, 0, volume.object_map.tree.object_id,
        kObjectPhysical | kObjectTypeBtree, kObjectTypeOmap));
    f.Put(inventory.physical_block, BuildRawLeafNode({}, {}, inventory.xid, f.bs, 0,
        inventory.physical_block, kObjectPhysical | kObjectTypeBtree, kObjectTypeSnapMetaTree));
    f.Edit(volume.superblock_object.physical_block, [&](auto& bytes) {
        PutU32LE(bytes, 0x7c, kObjectPhysical | kObjectTypeBtree);
        PutU64LE(bytes, 0x98, inventory.physical_block);
    });
    f.Reload(); f.generations = {f.checkpoint};
}

void PositiveCases()
{
    for (const auto bs : {4096u,8192u})
    {
        { Fixture f(bs); InactiveDefaults(f); CompleteReadOnly(f); Pass("empty read-only attribution " + std::to_string(bs)); }
        { Fixture f(bs); f.Create("first", {20}); InactiveDefaults(f); CompleteReadOnly(f); Pass("shared read-only snapshot " + std::to_string(bs)); }
        { Fixture f(bs); f.Create("first", {20}); f.Create("second", Pins(f)); f.Cow(true, Pins(f));
          InactiveDefaults(f); CompleteReadOnly(f); Pass("read-only multiple signed layers " + std::to_string(bs)); }
        { Fixture f(bs); Seed(f, true, true); f.Create("attribute", {20});
          InactiveDefaults(f); CompleteReadOnly(f); Pass("read-only shared clones and external xattr " + std::to_string(bs)); }
        { auto f=Ordinary(bs); f.scope.retained_from_xid.reset(); InactiveDefaults(f); CompleteReadOnly(f);
          Pass("read-only exact nonconsecutive retained chain " + std::to_string(bs)); }
        { Fixture f(bs); PhysicalEmptyInventory(f); InactiveDefaults(f); CompleteReadOnly(f);
          Pass("read-only physical empty snapshot root " + std::to_string(bs)); }
    }
    {
        Fixture f; f.Create("ordinary", {20}); f.scope.account_retained_ownership = true; VectorRandomAccessSource source(f.image);
        const auto strict=ApfsVerifier::Verify(source,f.scope), read_only=ApfsVerifier::VerifyReadOnly(source,f.scope);
        Accounted(strict); Accounted(read_only);
        Check(strict.retained_ownership == read_only.retained_ownership && strict.allocation_census == read_only.allocation_census,
            "ordinary old/new APIs prove identical physical partitions");
        Pass("ordinary profile strict/read-only compatibility");
    }
}

void CacheCases()
{
    for (unsigned profile=0;profile<3;++profile)
        for (const bool cold_strict : {false,true})
        {
            Fixture f; if(profile==1) f.Create("cache",{20});
            if(profile==2) PhysicalEmptyInventory(f); InactiveDefaults(f);
            const auto original=f.image; VectorRandomAccessSource raw(f.image);
            auto budget=std::make_shared<ApfsReadBudget>(200000,512ull<<20,4000000,512ull<<20);
            BudgetedRandomAccessSource source(raw,budget); SnapshotPlanningSource observation(source);
            std::vector<std::uint64_t> metadata; std::vector<ApplePhysicalExtentRecord> payload; std::string error;
            const auto strict_refused = [&](const RandomAccessSource& view) {
                metadata={999}; payload.resize(1); error.clear();
                Check(!LoadAppleSnapshotCheckpointOwners(view,f.checkpoint,metadata,payload,error) && metadata.empty() && payload.empty() &&
                    !error.empty(), "strict current-owner cache cannot borrow observational proof");
            };
            if(cold_strict) strict_refused(observation);
            Check(LoadAppleReadOnlySnapshotCheckpointOwners(observation,f.checkpoint,metadata,payload,error) && !metadata.empty(),
                "warm observational graph: " + error);
            std::vector<AppleRecoveryCheckpointView> history;
            Check(LoadAppleReadOnlySnapshotRecoveryCheckpoints(observation,f.checkpoint,Pins(f),history,error),
                "warm observational current-owner and retained caches: " + error);
            strict_refused(observation);
            // An empty staged overlay shares source/endpoint bytes and exercises
            // the staged graph cache, rather than the direct-current cache slot.
            AppleCheckpointPublicationPlan empty; empty.block_size=f.bs; SnapshotPublicationSource overlay(observation,empty);
            strict_refused(overlay);
            Check(LoadAppleReadOnlySnapshotCheckpointOwners(overlay,f.checkpoint,metadata,payload,error),
                "observational staged key remains reusable: " + error);
            AppleSnapshotCreateRequest request; request.volume_object_id=101;request.name_utf8="must-refuse";
            request.creation_time_ns=f.checkpoint.container.superblock.next_xid;request.required_checkpoint_xids=Pins(f);
            AppleSnapshotCreatePlan plan;
            Check(!PlanAppleSnapshotCreate(observation,f.checkpoint,request,plan,error) &&
                plan.commit.publication.before_superblock_writes.empty() && plan.commit.publication.superblock_write.bytes.empty(),
                "actual cold/warm/interleaved mutation remains refused with no executable plan");
            Check(LoadAppleReadOnlySnapshotRecoveryCheckpoints(observation,f.checkpoint,Pins(f),history,error) &&
                observation.VerifyUnchanged(error) && !budget->Failed() && f.image==original,
                "strict refusal cannot poison or upgrade independent observational cache");
            Pass("cache separation profile="+std::to_string(profile)+" coldStrict="+std::to_string(cold_strict));
        }
}

void NegativeCases()
{
    for(unsigned kind=0;kind<4;++kind)
    {
        Fixture f; PhysicalEmptyInventory(f); InactiveDefaults(f);
        const auto block=f.checkpoint.volumes[0].snapshot_metadata_tree->physical_block;
        f.Edit(block,[&](auto& bytes){
            if(kind==0) bytes[0]^=std::byte{1};
            if(kind==1) PutU64LE(bytes,8,block+1);
            if(kind==2) PutU64LE(bytes,0x10,f.checkpoint.container.superblock.xid+1);
            if(kind==3) PutU32LE(bytes,0x18,0x50000002u);
        },kind!=0);
        VectorRandomAccessSource source(f.image); std::string error;
        std::vector<std::uint64_t> metadata{999}; std::vector<ApplePhysicalExtentRecord> payload(1);
        Check(!LoadAppleReadOnlySnapshotCheckpointOwners(source,f.checkpoint,metadata,payload,error) &&
            metadata.empty() && payload.empty() && !error.empty(),"physical snapshot root identity/checksum/generation/flags cannot escape as ownership");
        const auto report=ApfsVerifier::VerifyReadOnly(source,f.scope);
        Check(report.outcome!=VerificationOutcome::Complete && !report.retained_ownership && !report.allocation_census,
            "physical snapshot root failure has no complete partition");
        Pass("read-only malformed physical inventory "+std::to_string(kind));
    }
    for (unsigned kind=0;kind<5;++kind)
    {
        Fixture f; InactiveDefaults(f);
        if(kind==0) AllocateOrphan(f,300);
        if(kind==1) f.Edit(f.checkpoint.volumes[0].superblock_object.physical_block,[](auto& b){PutU32LE(b,0x414,0x50000002);});
        if(kind==2) f.Edit(f.checkpoint.volumes[0].superblock_object.physical_block,[](auto& b){PutU64LE(b,0x418,220);});
        if(kind==3) f.scope.exact.volume_uuid_hex=std::string(32,'c');
        if(kind==4) f.scope.max_reads=1;
        VectorRandomAccessSource source(f.image); const auto report=ApfsVerifier::VerifyReadOnly(source,f.scope);
        Check(report.outcome != VerificationOutcome::Complete && !report.retained_ownership && !report.allocation_census,
            "read-only orphan/admission/identity/budget failure publishes no complete accounting");
        std::optional<ApfsSnapshotSpaceAttribution> result{ApfsSnapshotSpaceAttribution{}};std::string error;
        Check(!TryAttributeAppleSnapshotSpaceReadOnly(source,f.scope,result,error) && !result && !error.empty(), "actual incomplete read-only attribution clears output");
        Pass("read-only terminal refusal "+std::to_string(kind));
    }
    {
        Fixture f; InactiveDefaults(f); VectorRandomAccessSource source(f.image);
        const auto report=ApfsVerifier::VerifyReadOnly(source,f.scope,[]{return false;});
        Check(report.outcome!=VerificationOutcome::Complete && !report.retained_ownership && report.read_budget->Failed(),"read-only expired deadline is sticky");
        std::optional<ApfsSnapshotSpaceAttribution> result;std::string error;
        Check(!TryAttributeAppleSnapshotSpaceReadOnly(source,f.scope,result,error,[]{return false;}) && !result,"read-only attribution deadline cannot publish partial result");
        Pass("read-only deadline boundaries");
    }
}
}

#ifndef APFS_READONLY_RETENTION_FIXTURES_ONLY
int main()
{
    try{PositiveCases();CacheCases();NegativeCases();std::cout<<"PASS "<<cases<<" cases, "<<checks<<" checks\n";return 0;}
    catch(const std::exception& e){std::cerr<<"FAIL "<<e.what()<<'\n';return 1;}
}
#endif
