// Reuse the existing canonical image producers and corruption helpers.
#define main ExistingHistoryTestsMain
#include "ApfsVerifierHistoryTests.cpp"
#undef main

namespace
{
VerificationReport Account(Fixture& fixture)
{
    fixture.scope.account_retained_ownership = true;
    const auto before = fixture.image;
    TracedSource source(fixture.image);
    auto report = ApfsVerifier::Verify(source, fixture.scope);
    Check(before == fixture.image, "accounting never writes source bytes");
    Check(report.source_reads == source.reads.size(), "exact source read count");
    Check(!report.whole_volume_verified && !report.payload_content_hashes_verified, "no content or whole-volume promotion");
    for (const auto block : fixture.payload_blocks)
        Check(std::none_of(source.reads.begin(), source.reads.end(), [&](const auto& read) {
            return read.first < (block + 1) * fixture.bs && block * fixture.bs < read.first + read.second;
        }), "payload accounting requires no payload byte reads");
    if (report.outcome != VerificationOutcome::Complete)
        Check(!report.retained_ownership && !report.allocation_census && !report.requested_history &&
            !report.covered_filesystem_records && !report.covered_physical_extents, "no failed accounting proof escapes");
    return report;
}

void Accounted(const VerificationReport& report)
{
    Check(report.outcome == VerificationOutcome::Complete && report.retained_ownership && report.allocation_census,
        "complete retained ownership: " + Detail(report));
    for (const auto check : {VerificationCheck::HistoricalReachability, VerificationCheck::CompleteAllocationAccounting})
        Check(Coverage(report, check).implemented && Coverage(report, check).required &&
            Coverage(report, check).state == VerificationCheckState::Verified, "exhaustive requested graph verified");
    const auto& accounting = *report.retained_ownership;
    Check(accounting.allocated_main_blocks == accounting.owned_main_blocks + accounting.reserved_main_blocks +
        accounting.deferred_main_blocks, "disjoint complete main allocator partition");
    Check(accounting.allocated_internal_blocks == accounting.owned_internal_blocks + accounting.deferred_internal_blocks,
        "disjoint complete internal allocator partition");
    Check(!report.allocation_census->unattributed_main_blocks && !report.allocation_census->unattributed_internal_blocks,
        "no unattributed allocated bits");
    Check(!accounting.purgeable_bytes && !accounting.snapshot_total_bytes, "unknown Apple charges and purgeability stay unknown");
}

void AllocateOrphan(Fixture& fixture, std::uint64_t block)
{
    const auto& cp = fixture.checkpoint;
    const auto& chunk = cp.spaceman.chunks.front();
    const auto bit = block - chunk.start_block;
    Check(bit < chunk.block_count && !(std::to_integer<unsigned>(chunk.allocation_bitmap[bit / 8]) &
        (1u << (bit % 8))), "new orphan was free");
    fixture.Edit(chunk.bitmap_block, [&](auto& bytes) { bytes[bit / 8] |= std::byte(1u << (bit % 8)); }, false);
    fixture.Edit(cp.spaceman.devices[0].cibs[0].object.physical_block,
        [&](auto& bytes) { PutU32LE(bytes, 0x3C, chunk.free_count - 1); });
    fixture.Edit(cp.spaceman.object.physical_block,
        [&](auto& bytes) { PutU64LE(bytes, 0x48, cp.spaceman.devices[0].free_count - 1); });
}

void AddPeer(Fixture& fixture, std::uint64_t physical)
{
    BuilderStore spec; spec.block_size = fixture.bs; spec.block_count = 512; spec.xid = 20;
    spec.authoritative_internal_pool_blocks = 32; spec.authoritative_checkpoint_ring_blocks = 32;
    auto& first = spec.volumes[0]; first.uuid_hex = std::string(32, 'b');
    VectorRandomAccessSource source(fixture.image); std::string error;
    Check(ReadAppleVolumeFileSystemRecords(source, fixture.checkpoint.container, fixture.checkpoint.volumes[0],
        first.filesystem_records, error), error);
    first.additional_file_system_allocated_blocks = 1;
    first.extentref_records = {Encode(ApplePhysicalExtentRecord{220, 1, kApplePhysicalExtentKindNew, 30, 1}, EncodeApplePhysicalExtentRecord)};
    auto second = first; second.oid = 102; second.uuid_hex = std::string(32, 'c');
    for (auto& record : second.filesystem_records)
        if (ReadU64LE(record.key, 0).value_or(0) >> 60 == 8)
            record = Encode(AppleFileExtentRecord{30, 0, fixture.bs, physical, 0, fixture.bs}, EncodeAppleFileExtentRecord);
    second.extentref_records = {Encode(ApplePhysicalExtentRecord{physical, 1, kApplePhysicalExtentKindNew, 30, 1}, EncodeApplePhysicalExtentRecord)};
    spec.volumes.push_back(std::move(second));
    for (const auto block : std::set<std::uint64_t>{220, physical})
        spec.authoritative_seeded_main_blocks.emplace_back(block, Bytes(fixture.bs, std::byte{0x42}));
    fixture.image = BuildAuthoritativeStoreImage(spec);
    for (const auto block : {4ull, 5ull}) fixture.Edit(block, [](auto& bytes) {
        PutU64LE(bytes, 0xB8, 1); PutU64LE(bytes, 0xC0, 1);
    });
    fixture.Reload(); fixture.generations = {fixture.checkpoint}; fixture.payload_blocks = {220, physical};
}

void QueueOrphan(Fixture& fixture, std::uint64_t block)
{
    AllocateOrphan(fixture, block);
    const auto& cp = fixture.checkpoint;
    const auto& queue = cp.spaceman.free_queues[1];
    Record record{Bytes(16), {}}; PutU64LE(record.key, 0, 20); PutU64LE(record.key, 8, block);
    AppleBtreeOptions options; options.block_size = fixture.bs; options.xid = 20;
    options.root_object_id = queue.tree_oid; options.root_physical_block = queue.root.physical_block;
    options.storage_type = kObjectEphemeral; options.subtype = kObjectTypeSpacemanFreeQueue;
    options.key_order = AppleBtreeKeyOrder::SpacemanFreeQueue;
    options.fixed_key_size = 16; options.fixed_value_size = 8;
    options.tree_flags = kAppleBtreeEphemeral | kAppleBtreeSequentialInsert | kAppleBtreeAllowGhosts;
    options.minimum_longest_key = 16; options.minimum_longest_value = 8;
    AppleSerializedBtree tree; std::string error;
    Check(SerializeAppleBtree({record}, options, tree, error), error);
    for (const auto& object : tree.objects) fixture.Put(object.location.physical_block, object.bytes);
    fixture.Edit(cp.spaceman.object.physical_block, [](auto& bytes) {
        PutU64LE(bytes, 0xF0, 1); PutU64LE(bytes, 0x100, 20);
    });
}

void RetainedOwnershipCases()
{
    for (const auto bs : {4096u, 8192u})
    {
        Fixture initial(bs);
        const auto first = Account(initial); Accounted(first);
        Check(first.retained_ownership->checkpoint_xids == std::vector<std::uint64_t>{20}, "single descriptor generation exact");
        Check(first.retained_ownership->snapshot_payload_usage.size() == 1 &&
            !first.retained_ownership->snapshot_payload_usage[0].referenced_bytes, "snapshot-free inventory has known zero payload");
        Pass("single-generation physical accounting " + std::to_string(bs));

        auto fixture = Ordinary(bs);
        // Exhaustive enumeration must work independently of an explicit pin.
        fixture.scope.retained_from_xid.reset();
        const auto report = Account(fixture); Accounted(report);
        Check(report.retained_ownership->checkpoint_xids == std::vector<std::uint64_t>({20, 30, 31}),
            "all retained nonconsecutive descriptor generations");
        const auto payload = Blocks(report.retained_ownership->payload_ranges, 512);
        Check(payload == std::set<std::uint64_t>(fixture.payload_blocks.begin(), fixture.payload_blocks.end()),
            "historical-only payload attributed exactly once");
        const auto repeat = Account(fixture);
        Check(repeat.retained_ownership == report.retained_ownership && repeat.repair == report.repair,
            "deterministic accounting and bound plan");
        Pass("complete retained allocator graph " + std::to_string(bs));
    }

    {
        Fixture fixture;
        fixture.Create("retained", {20});
        fixture.Cow(true, {20});
        const auto report = Account(fixture); Accounted(report);
        const auto& usage = report.retained_ownership->snapshot_payload_usage.at(0);
        Check(usage.volume_oid == 101 && usage.referenced_blocks == 1 && usage.exclusive_blocks == 1 &&
            usage.referenced_bytes == fixture.bs && usage.exclusive_bytes == fixture.bs,
            "actual snapshot payload and live-exclusive usage");
        Pass("snapshot UPDATE layer retained payload usage");
    }
    {
        Fixture fixture;
        fixture.Create("shared", {20});
        const auto report = Account(fixture); Accounted(report);
        const auto& usage = report.retained_ownership->snapshot_payload_usage.at(0);
        Check(usage.referenced_blocks == 1 && usage.exclusive_blocks == 0, "live/snapshot sharing not charged twice");
        Pass("shared snapshot payload unique accounting");
    }
    {
        Fixture fixture; AddPeer(fixture, 221);
        const auto report = Account(fixture); Accounted(report);
        Check(report.retained_ownership->snapshot_payload_usage.size() == 2 &&
            Blocks(report.retained_ownership->payload_ranges, 512) == std::set<std::uint64_t>{220, 221},
            "complete peer ownership without first-volume bias");
        Pass("two volumes share one complete allocator partition");
    }
    {
        Fixture fixture; AddPeer(fixture, 220);
        const auto report = Account(fixture);
        Check(Has(report, VerificationCode::CrossVolumePayloadOverlap), "peer alias is corruption: " + Detail(report));
        Pass("cross-volume payload alias rejected");
    }
    {
        Fixture fixture; QueueOrphan(fixture, 300);
        const auto report = Account(fixture); Accounted(report);
        Check(report.retained_ownership->deferred_main_blocks == 1, "queue allocation counted exactly once");
        Pass("deferred free has distinct physical accounting");
    }
    {
        Fixture fixture; AllocateOrphan(fixture, 300);
        const auto report = Account(fixture);
        Check(Has(report, VerificationCode::OrphanAllocation) && report.findings.front().physical_block == 300 &&
            report.findings.front().detail == "VerifierOrphanAllocation:main=1:internal=0", Detail(report));
        Pass("allocated main orphan with truthful free counters rejected");
    }
    {
        Fixture fixture;
        const auto& pool = fixture.checkpoint.spaceman.internal_pool;
        std::uint64_t bit = 0;
        while (bit < pool.block_count && (std::to_integer<unsigned>(pool.active_bitmaps[0].bytes[bit / 8]) & (1u << (bit % 8)))) ++bit;
        Check(bit < pool.block_count, "fixture internal free bit");
        fixture.Edit(pool.active_bitmaps[0].physical_block, [&](auto& bytes) { bytes[bit / 8] |= std::byte(1u << (bit % 8)); }, false);
        const auto report = Account(fixture);
        Check(Has(report, VerificationCode::OrphanAllocation) && report.findings.front().physical_block == pool.base_block + bit,
            "internal reservation cannot conceal orphan: " + Detail(report));
        Pass("internal pool orphan rejected independently of main reservation");
    }
    {
        auto fixture = Ordinary(); fixture.scope.retained_from_xid.reset(); BreakNextLink(fixture);
        const auto report = Account(fixture);
        Check(Has(report, VerificationCode::CheckpointUnavailable), "missing successor cannot certify history: " + Detail(report));
        Pass("retained continuity gap rejected without caller pin");
    }
    {
        auto fixture = Ordinary(); fixture.scope.retained_from_xid.reset();
        fixture.Edit(fixture.generations.front().container.superblock_physical_block,
            [](auto& bytes) { bytes[0] ^= std::byte{1}; }, false);
        const auto report = Account(fixture);
        Check(Has(report, VerificationCode::ChecksumMismatch), "damaged older NXSB cannot vanish from census: " + Detail(report));
        Pass("damaged older descriptor cannot be skipped");
    }
    {
        auto fixture = Ordinary(); fixture.scope.retained_from_xid.reset();
        fixture.Edit(fixture.generations.front().container.superblock_physical_block,
            [](auto& bytes) { PutU32LE(bytes, 0x18, kObjectTypeFs); });
        const auto report = Account(fixture);
        Check(Has(report, VerificationCode::StructuralInconsistency) && !Has(report, VerificationCode::ChecksumMismatch),
            "checksum-valid malformed descriptor is structural: " + Detail(report));
        Pass("malformed retained descriptor has precise structural classification");
    }
    {
        auto fixture = Ordinary(); fixture.scope.retained_from_xid.reset();
        fixture.scope.exact.checkpoint_xid = 20;
        const auto report = Account(fixture);
        Check(report.outcome != VerificationOutcome::Complete, "stale endpoint rejected");
        Pass("exhaustive accounting requires latest endpoint");
    }
    {
        Fixture fixture;
        const auto complete = Account(fixture); Accounted(complete);
        fixture.scope.max_reads = complete.source_reads - 1;
        const auto short_report = Account(fixture);
        Check(Has(short_report, VerificationCode::BudgetExceeded), "late shared read budget: " + Detail(short_report));
        Pass("late budget failure publishes no accounting proof");
    }
    {
        auto fixture = Ordinary(); fixture.scope.account_retained_ownership = true;
        Bytes parent(2 * fixture.bs, std::byte{0xA5});
        parent.insert(parent.end(), fixture.image.begin(), fixture.image.end());
        parent.resize(parent.size() + fixture.bs, std::byte{0xA5});
        fixture.scope.exact.store_offset_bytes = 2 * fixture.bs;
        TracedSource source(parent); const auto report = ApfsVerifier::Verify(source, fixture.scope); Accounted(report);
        Check(report.requested_history && report.retained_ownership->checkpoint_xids == report.requested_history->chain_xids,
            "requested pin and exhaustive descriptor chain agree");
        for (const auto& [at, count] : source.reads)
            Check(at >= 2 * fixture.bs && at + count <= 2 * fixture.bs + fixture.image.size(), "bounded parent window");
        Pass("exhaustive and requested history in exact offset window");
    }
    {
        Fixture fixture; fixture.scope.account_retained_ownership = true;
        const auto control = Account(fixture); Accounted(control);
        TracedSource source(fixture.image); source.fail_at = control.source_reads;
        const auto report = ApfsVerifier::Verify(source, fixture.scope);
        Check(Has(report, VerificationCode::ReadFailure) && !report.retained_ownership && !report.allocation_census,
            "late backing I/O failure cannot escape as complete accounting");
        Pass("late source failure clears proof");
    }
    {
        Fixture fixture; fixture.scope.account_retained_ownership = true;
        TracedSource source(fixture.image); unsigned callbacks = 0;
        const auto report = ApfsVerifier::Verify(source, fixture.scope, [&] { return ++callbacks < 50; });
        Check(Has(report, VerificationCode::BudgetExceeded) && !report.retained_ownership, "cooperative deadline clears proof");
        Pass("deadline remains enforced in exhaustive scope");
    }
    {
        Fixture fixture;
        const auto advanced = Account(fixture); Accounted(advanced);
        fixture.scope.account_retained_ownership = false;
        const auto current = Verify(fixture, fixture.scope);
        Check(current.outcome == VerificationOutcome::Complete && !current.retained_ownership &&
            current.repair.plan_id != advanced.repair.plan_id, "default cost/coverage and plan identity preserved");
        Pass("default scope retains its original contract");
    }
}

void EmitOwnershipFixtures(const std::filesystem::path& directory)
{
    Check(directory.is_absolute() && directory.root_name() == "D:", "evidence must be on D:");
    std::filesystem::create_directories(directory);
    auto ordinary = Ordinary(); ordinary.scope.retained_from_xid.reset();
    const auto good = Account(ordinary); Accounted(good);
    auto orphan = ordinary; AllocateOrphan(orphan, 300);
    const auto bad = Account(orphan); Check(Has(bad, VerificationCode::OrphanAllocation), Detail(bad));
    Fixture snapshot; snapshot.Create("retained", {20}); snapshot.Cow(true, {20});
    const auto snap = Account(snapshot); Accounted(snap);
    for (const auto& pair : {std::pair{"retained-positive.apfs", &ordinary.image},
        {"retained-orphan.apfs", &orphan.image}, {"snapshot-positive.apfs", &snapshot.image}})
    {
        std::ofstream file(directory / pair.first, std::ios::binary);
        file.write(reinterpret_cast<const char*>(pair.second->data()), pair.second->size());
        file.close(); Check(static_cast<bool>(file), "evidence image written");
    }
    const auto& a = *good.retained_ownership;
    const auto& usage = snap.retained_ownership->snapshot_payload_usage.at(0);
    std::ofstream receipt(directory / "native-receipt.json");
    receipt << "{\n  \"profile\": \"single-store-unencrypted-complete-retained-physical-ownership\",\n"
        << "  \"checkpointXids\": [20,30,31],\n"
        << "  \"allocatedMainBlocks\": " << a.allocated_main_blocks << ",\n"
        << "  \"ownedMainBlocks\": " << a.owned_main_blocks << ",\n"
        << "  \"reservedMainBlocks\": " << a.reserved_main_blocks << ",\n"
        << "  \"deferredMainBlocks\": " << a.deferred_main_blocks << ",\n"
        << "  \"allocatedInternalBlocks\": " << a.allocated_internal_blocks << ",\n"
        << "  \"ownedInternalBlocks\": " << a.owned_internal_blocks << ",\n"
        << "  \"deferredInternalBlocks\": " << a.deferred_internal_blocks << ",\n"
        << "  \"snapshotReferencedPayloadBytes\": " << usage.referenced_bytes << ",\n"
        << "  \"snapshotExclusivePayloadBytes\": " << usage.exclusive_bytes << ",\n"
        << "  \"snapshotTotalBytes\": null,\n  \"purgeableBytes\": null,\n"
        << "  \"orphanCode\": " << static_cast<unsigned>(bad.findings.front().code) << ",\n"
        << "  \"orphanBlock\": " << bad.findings.front().physical_block.value() << ",\n"
        << "  \"wholeVolumeVerified\": false,\n  \"writeAuthority\": false\n}\n";
    receipt.close(); Check(static_cast<bool>(receipt), "evidence receipt written");
    Pass("frozen positive and negative native image evidence");
}
}

#ifndef APFS_RETAINED_OWNERSHIP_FIXTURES_ONLY
int main(int argc, char** argv)
{
    try
    {
        RetainedOwnershipCases();
        if (argc == 3 && std::string(argv[1]) == "--emit-fixtures") EmitOwnershipFixtures(argv[2]);
        else Check(argc == 1, "usage: ApfsVerifierRetainedOwnershipTests [--emit-fixtures ABSOLUTE_D_DIR]");
        std::cout << "PASS " << cases << " cases, " << checks << " checks\n";
        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
#endif
