#include "ApfsVerificationJson.h"
#include "ApfsReadOnlyMetadataAdmission.h"
#define APFS_SNAPSHOT_ATTRIBUTION_FIXTURES_ONLY
#include "ApfsSnapshotAttributionTests.cpp"
#undef APFS_SNAPSHOT_ATTRIBUTION_FIXTURES_ONLY

namespace
{
ApfsSnapshotAllocationCounters Counters(Fixture& fixture)
{
    VectorRandomAccessSource source(fixture.image);
    std::optional<ApfsSnapshotAllocationCounters> result; std::string error;
    Check(TryObserveAppleSnapshotAllocationCountersReadOnly(source, fixture.scope, result, error), error);
    Check(result && result->complete && result->scope == fixture.scope.exact &&
        !result->snapshot_allocation_charge && !result->apple_purgeable && !result->reclaimable,
        "canonical observed counters have no independent snapshot charge or policy amount");
    return std::move(*result);
}

void CounterCases()
{
    for (const auto declared : {0ull, 17ull})
    {
        Fixture fixture; Seed(fixture, true, true); fixture.Create("counter-clone-xattr", Pins(fixture));
        VectorRandomAccessSource before(fixture.image); AppleSnapshotCatalogRecords catalog; std::string error;
        Check(LoadAppleReadOnlySnapshotCatalog(before, fixture.checkpoint, 101, catalog, error), error);
        Check(catalog.inventory.size() == 1, "one canonical snapshot descriptor");
        const auto descriptor = catalog.inventory.front().volume.superblock_object;
        fixture.Edit(descriptor.physical_block, [&](auto& bytes) { PutU64LE(bytes, 0x58, declared); });
        const auto image = fixture.image;
        auto result = Counters(fixture);
        Check(fixture.image == image && result.snapshots.size() == 1, "counter observation does not change the image");
        const auto& row = result.snapshots.front();
        Check(row.snapshot_xid == catalog.inventory.front().xid && row.descriptor.xid == descriptor.xid &&
            row.descriptor.physical_block == descriptor.physical_block && row.declared_filesystem_allocation.blocks == declared &&
            row.declared_filesystem_allocation.bytes == declared * fixture.bs, "parsed exact descriptor amount is preserved");
        std::string output; payload::Reason reason;
        const bool encoded = SerializeSnapshotAllocationCounters(result, fixture.scope, "private-image.apfs", [] { return true; },
            MaxImageVerificationJsonBytes, output, reason);
        Check(encoded, "counter serializer: " + std::to_string(static_cast<unsigned>(reason)));
        Check(output.find("\"format\":\"apfs-access-snapshot-allocation-counters\",\"version\":1") != std::string::npos &&
            output.find("\"counterMeaning\":\"parsed-apfs-fs-alloc-count-at-descriptor-xid\"") != std::string::npos &&
            output.find("\"independentSnapshotChargeVerified\":false") != std::string::npos &&
            output.find("\"snapshotAllocationCharge\":null,\"applePurgeable\":null,\"reclaimable\":null") != std::string::npos,
            "counter wire exposes exact observed meaning and unknown policy");
        Check(output.find("\"declaredFilesystemAllocation\":{\"blocks\":\"" + std::to_string(declared) +
            "\",\"bytes\":\"" + std::to_string(declared * fixture.bs) + "\"}") != std::string::npos,
            "encoded counter is not substituted with payload, metadata, unique or exclusive footprint");
        Pass("parsed snapshot allocation counter with shared clone and external xattr");
    }
    for (unsigned fault = 0; fault < 9; ++fault)
    {
        Fixture fixture; fixture.Create("counter-serializer-negative", Pins(fixture));
        auto result = Counters(fixture); auto expected = fixture.scope;
        if (fault == 0) result.complete = false;
        if (fault == 1) expected.source_identity += "-wrong";
        if (fault == 2) result.snapshots[0].descriptor.xid = fixture.scope.exact.checkpoint_xid + 1;
        if (fault == 3) ++result.snapshots[0].descriptor.object_id;
        if (fault == 4) result.snapshots[0].declared_filesystem_allocation = {513, 513ull * fixture.bs};
        if (fault == 5) result.snapshot_allocation_charge = ApfsSpaceAmount{};
        if (fault == 6) result.apple_purgeable = ApfsSpaceAmount{};
        if (fault == 7) result.reclaimable = ApfsSpaceAmount{};
        if (fault == 8) result.read_budget.reset();
        std::string output = "stale complete report"; payload::Reason reason;
        Check(!SerializeSnapshotAllocationCounters(result, expected, "private.apfs", [] { return true; },
            MaxImageVerificationJsonBytes, output, reason) && output.empty() && reason != payload::Reason::None,
            "contradictory/refused counter result cannot encode a complete report");
        Pass("counter serializer contradiction " + std::to_string(fault));
    }
    for (unsigned fault = 0; fault < 4; ++fault)
    {
        Fixture fixture; fixture.Create("counter-resource-negative", Pins(fixture));
        auto result = Counters(fixture);
        if (fault == 0) (void)result.read_budget->Refuse("CounterTestSpentBudget");
        unsigned calls = 0, control_calls = 0;
        if (fault == 2) {
            std::string control; payload::Reason reason;
            Check(SerializeSnapshotAllocationCounters(result, fixture.scope, "private.apfs", [&] { ++control_calls; return true; },
                MaxImageVerificationJsonBytes, control, reason) && control_calls > 1, "late deadline control completes");
        }
        const auto deadline = [&] { return fault != 1 && (fault != 2 || ++calls < control_calls); };
        std::string output = "stale"; payload::Reason reason;
        Check(!SerializeSnapshotAllocationCounters(result, fixture.scope, "private.apfs", deadline,
            fault == 3 ? 32 : MaxImageVerificationJsonBytes, output, reason) && output.empty(),
            "sticky budget, early/late deadline and output overflow clear encoded counters");
        Pass("counter serializer bounded failure " + std::to_string(fault));
    }
    for (unsigned fault = 0; fault < 4; ++fault)
    {
        Fixture fixture; fixture.Create("counter-producer-negative", Pins(fixture));
        if (fault == 0) fixture.scope.exact.volume_uuid_hex = std::string(32, 'f');
        if (fault == 1) fixture.scope.account_retained_ownership = true;
        if (fault == 2) AllocateOrphan(fixture, 300);
        if (fault == 3) fixture.scope.max_reads = 1;
        VectorRandomAccessSource source(fixture.image);
        std::optional<ApfsSnapshotAllocationCounters> result{ApfsSnapshotAllocationCounters{}};
        std::string error;
        Check(!TryObserveAppleSnapshotAllocationCountersReadOnly(source, fixture.scope, result, error) && !result && !error.empty(),
            "wrong binding, broader scope, orphan or budget cannot produce complete descriptor counters");
        Pass("counter producer refusal " + std::to_string(fault));
    }
}
}

int main()
{
    try { CounterCases(); std::cout << "PASS " << cases << " cases, " << checks << " checks\n"; return 0; }
    catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
