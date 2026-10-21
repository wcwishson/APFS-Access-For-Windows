#include "ApfsReadOnlyMetadataAdmission.h"
#include "SnapshotPlanningSource.h"
#include "NativeApfsReader.h"
#define APFS_SNAPSHOT_ATTRIBUTION_FIXTURES_ONLY
#include "ApfsSnapshotAttributionTests.cpp"
#undef APFS_SNAPSHOT_ATTRIBUTION_FIXTURES_ONLY

namespace
{
void SetMarks(Fixture& f, const std::map<std::uint64_t, std::uint64_t>& flags, bool live_only = false)
{
    VectorRandomAccessSource source(f.image); AppleSnapshotCatalogRecords catalog; std::string error;
    Check(LoadAppleReadOnlySnapshotCatalog(source, f.checkpoint, 101, catalog, error), error);
    std::set<std::uint64_t> blocks; std::vector<Record> inodes;
    const auto collect = [&](const AppleSnapshotTreeRecords& trees) {
        blocks.insert(trees.filesystem_blocks.begin(), trees.filesystem_blocks.end());
        for (const auto& record : trees.filesystem)
            if ((ReadU64LE(record.key, 0).value_or(0) >> 60) == 3 &&
                flags.contains(ReadU64LE(record.key, 0).value() & 0x0fffffffffffffffull) &&
                std::none_of(inodes.begin(), inodes.end(), [&](const auto& old) { return old.key == record.key && old.value == record.value; }))
                inodes.push_back(record);
    };
    collect(catalog.live);
    if (!live_only) for (const auto& trees : catalog.snapshots) collect(trees);
    for (const auto& record : inodes)
    {
        AppleInodeRecord inode; Check(ApfsExtendedRecordCodec::DecodeInode(record, inode, error), error);
        inode.internal_flags |= flags.at(inode.object_id);
        const auto changed = Encode(inode, EncodeAppleInodeRecord);
        Check(changed.key == record.key && changed.value.size() == record.value.size(), "flag-only canonical fixture encoding");
        std::size_t hits = 0;
        for (const auto block : blocks)
            f.Edit(block, [&](auto& bytes) {
                auto found = std::search(bytes.begin(), bytes.end(), record.value.begin(), record.value.end());
                if (found == bytes.end()) return;
                Check(found - bytes.begin() >= 0x38 && std::search(found + record.value.size(), bytes.end(),
                    record.value.begin(), record.value.end()) == bytes.end(), "canonical inode value uniquely located in FS node");
                std::copy(changed.value.begin(), changed.value.end(), found); ++hits;
            });
        Check(hits != 0, "actual image inode mark edited without a second APFS parser");
    }
    f.Reload();
}

ApfsMarkedFileExtentRecordsObservation ObserveMarks(Fixture& f)
{
    const auto before = f.image; TracedSource source(f.image); std::string error;
    std::optional<ApfsMarkedFileExtentRecordsObservation> out;
    Check(TryObserveAppleMarkedFileExtentRecords(source, f.scope, out, error), "marked record observation: " + error);
    Check(out && out->complete && out->read_budget && error.empty() && out->scope == f.scope.exact &&
        out->source_identity == f.scope.source_identity && out->allocation_unit_bytes == f.bs, "exact source-bound complete record subset");
    Check(!out->apple_purgeable && !out->reclaimable && !out->snapshot_allocation_charge, "no policy/charge promotion");
    Check(f.image == before && out->views.size() >= 1 && out->views.back().current &&
        out->views.back().view_xid == f.scope.exact.checkpoint_xid && out->views.back().snapshot_name_utf8.empty(), "stable source and exact current row");
    Check(out->referenced_physical_union.bytes == out->referenced_physical_union.blocks * f.bs, "exact physical units");
    for (const auto block : f.payload_blocks)
        for (const auto& read : source.reads)
            Check(read.first + read.second <= block * f.bs || read.first >= (block + 1) * f.bs, "record observation never reads file/xattr payload");
    return std::move(*out);
}

void MarkRefused(Fixture& f, const std::string& expected)
{
    VectorRandomAccessSource source(f.image); std::string error;
    std::optional<ApfsMarkedFileExtentRecordsObservation> out{ApfsMarkedFileExtentRecordsObservation{}};
    const auto observed = TryObserveAppleMarkedFileExtentRecords(source, f.scope, out, error);
    Check(!observed && !out &&
        error.find(expected) != std::string::npos, "refusal has no partial record result: " + error);
}

void CurrentRecordCases()
{
    for (const auto bs : {4096u, 8192u})
        for (unsigned profile = 0; profile != 5; ++profile)
        {
            Fixture f(bs); Seed(f, true, true, 3);
            if (profile == 1) SetMarks(f, {{30, 0x100000}});
            if (profile == 2) SetMarks(f, {{30, 0x80000}, {31, 0x100000}});
            if (profile == 3) SetMarks(f, {{30, 0x80000}, {31, 0x80000}});
            if (profile == 4) SetMarks(f, {{30, 0x180000}});
            const auto out = ObserveMarks(f); const auto& row = out.views.back();
            Check(out.views.size() == 1 && row.referenced_physical.blocks == (profile >= 2 ? 3 : 0) &&
                out.referenced_physical_union.blocks == row.referenced_physical.blocks,
                "clones form a union and attribute-only stream is excluded");
            Check(row.marked_regular_inode_count == (profile == 3 ? 2 : profile >= 2 ? 1 : 0) &&
                row.want_only_regular_inode_count == (profile == 1 || profile == 2 ? 1 : 0), "IS and WANT-only meanings are distinct");
            if (profile)
            {
                std::optional<ApfsSnapshotSpaceAttribution> complete; std::string error; VectorRandomAccessSource source(f.image);
                Check(!TryAttributeAppleSnapshotSpaceReadOnly(source, f.scope, complete, error) && !complete,
                    "record subset cannot promote the unchanged complete-attribution profile");
                auto scope = f.scope; scope.account_retained_ownership = true;
                const auto report = ApfsVerifier::VerifyReadOnly(source, scope);
                Check(report.outcome != VerificationOutcome::Complete && !report.retained_ownership && !report.allocation_census,
                    "record marks do not grant full verifier/allocation certification");
            }
            Pass("marked current clones/xattr profile=" + std::to_string(profile) + " block=" + std::to_string(bs));
        }
}

void HistoricalRecordCases()
{
    {
        Fixture f; f.Create("first", Pins(f)); f.Cow(true, Pins(f)); f.Create("second", Pins(f)); f.Cow(true, Pins(f));
        SetMarks(f, {{30, 0x80000}}); const auto out = ObserveMarks(f);
        Check(out.views.size() == 3 && out.views[0].snapshot_name_utf8 == "first" &&
            out.views[1].snapshot_name_utf8 == "second" && out.views[0].view_xid < out.views[1].view_xid,
            "exact chronological snapshot rows");
        for (const auto& row : out.views) Check(row.marked_regular_inode_count == 1 && row.referenced_physical.blocks == 1,
            "each actual signed-history layer has exact marked records");
        Check(out.referenced_physical_union.blocks == 3, "three distinct COW generations union once");
        Pass("multiple snapshots and complete signed COW record history");
    }
    {
        Fixture f; f.Create("unmarked-history", Pins(f)); f.Cow(true, Pins(f)); SetMarks(f, {{30, 0x80000}}, true);
        const auto out = ObserveMarks(f);
        Check(out.views.size() == 2 && !out.views[0].marked_regular_inode_count &&
            !out.views[0].referenced_physical.blocks && out.views[1].referenced_physical.blocks == 1 &&
            out.referenced_physical_union.blocks == 1, "current mark does not backdate into snapshot metadata");
        Pass("current versus snapshot marks remain generation-bound");
    }
    {
        Fixture f; GrowMetadata(f); SetMarks(f, {{30, 0x80000}}); const auto out = ObserveMarks(f);
        Check(out.views.size() == 1 && out.referenced_physical_union.blocks == 1, "multi-node canonical FS census");
        Pass("marked file in multi-node filesystem tree");
    }
    {
        Fixture f; SetMarks(f, {{30, 0x80000}}); Bytes wrapped(1024, std::byte{0x11});
        wrapped.insert(wrapped.end(), f.image.begin(), f.image.end()); wrapped.resize(wrapped.size() + 1024);
        f.scope.exact.store_offset_bytes = 1024; VectorRandomAccessSource source(wrapped); std::string error;
        std::optional<ApfsMarkedFileExtentRecordsObservation> out;
        Check(TryObserveAppleMarkedFileExtentRecords(source, f.scope, out, error) && out &&
            out->scope.store_offset_bytes == 1024 && out->referenced_physical_union.blocks == 1, "exact offset source binding: " + error);
        Pass("marked records in exact offset window");
    }
}

void FailureRecordCases()
{
    {
        Fixture f; VectorRandomAccessSource source(f.image); std::vector<Record> records; std::string error;
        Check(ReadAppleVolumeFileSystemRecords(source, f.checkpoint.container, f.checkpoint.volumes[0], records, error), error);
        for (auto& record : records)
            if (ReadU64LE(record.key, 0).value_or(0) == (3ull << 60 | 30))
            {
                AppleInodeRecord inode; Check(ApfsExtendedRecordCodec::DecodeInode(record, inode, error), error);
                inode.internal_flags |= 0x80000; inode.extended_fields.push_back({15, 0, Bytes(8)});
                record = Encode(inode, EncodeAppleInodeRecord);
            }
        std::vector<Bytes> keys, values; for (const auto& record : records) { keys.push_back(record.key); values.push_back(record.value); }
        const auto& tree = f.checkpoint.volumes[0].root_tree;
        f.Put(tree.physical_block, BuildRawLeafNode(keys, values, tree.xid, f.bs, 0, tree.object_id, tree.type, tree.subtype));
        MarkRefused(f, "InodeFieldUnsupported"); Pass("reserved purgeability xfield remains unknown");
    }
    {
        Fixture f; SetMarks(f, {{30, 0x80000}}); VectorRandomAccessSource source(f.image);
        AppleSnapshotCatalogRecords catalog; std::string error;
        Check(LoadAppleReadOnlySnapshotCatalog(source, f.checkpoint, 101, catalog, error), error);
        auto refs = catalog.live.extentref; PutU64LE(refs[0].value, 0, 3ull << 60 | 1);
        std::vector<Bytes> keys, values; for (const auto& record : refs) { keys.push_back(record.key); values.push_back(record.value); }
        const auto& tree = *f.checkpoint.volumes[0].extentref_tree;
        f.Put(tree.physical_block, BuildRawLeafNode(keys, values, tree.xid, f.bs, 0, tree.object_id, tree.type, tree.subtype));
        MarkRefused(f, "AppleSnapshotLayerRecordInvalid"); Pass("unknown physical owner kind refuses");
    }
    for (const auto flags : {0x200000ull, 0x80000ull})
    {
        Fixture f; SetMarks(f, {{flags == 0x80000 ? 2 : 30, flags}});
        MarkRefused(f, flags == 0x80000 ? "NonRegular" : "InodeProfile");
        Pass("unknown inode state or marked directory refuses");
    }
    {
        Fixture f; f.Create("bad", Pins(f)); f.Cow(true, Pins(f)); SetMarks(f, {{30, 0x80000}});
        VectorRandomAccessSource source(f.image); AppleSnapshotCatalogRecords catalog; std::string error;
        Check(LoadAppleReadOnlySnapshotCatalog(source, f.checkpoint, 101, catalog, error), error);
        auto refs = catalog.live.extentref; bool changed = false;
        for (auto& record : refs)
        {
            ApplePhysicalExtentRecord extent; Check(DecodeApplePhysicalExtentRecord(record, extent, error), error);
            if (extent.kind == kApplePhysicalExtentKindUpdate) { PutU32LE(record.value, 16, 1); changed = true; }
        }
        Check(changed, "real signed layer selected"); std::vector<Bytes> keys, values;
        for (const auto& record : refs) { keys.push_back(record.key); values.push_back(record.value); }
        const auto& tree = *f.checkpoint.volumes[0].extentref_tree;
        f.Put(tree.physical_block, BuildRawLeafNode(keys, values, tree.xid, f.bs, 0, tree.object_id, tree.type, tree.subtype));
        MarkRefused(f, "AppleVolume"); Pass("incorrect signed owner history refuses marked records");
    }
    {
        Fixture f; SetMarks(f, {{30, 0x80000}}); TracedSource traced(f.image); std::string error;
        std::optional<ApfsMarkedFileExtentRecordsObservation> out;
        Check(TryObserveAppleMarkedFileExtentRecords(traced, f.scope, out, error), error);
        TracedSource changed(f.image); changed.change_at = traced.reads.size();
        Check(!TryObserveAppleMarkedFileExtentRecords(changed, f.scope, out, error) && !out && !error.empty(), "final dependency revalidation clears result");
        TracedSource failed(f.image); failed.fail_at = traced.reads.size(); failed.short_read = true;
        Check(!TryObserveAppleMarkedFileExtentRecords(failed, f.scope, out, error) && !out, "late short read clears result");
        unsigned ticks = 0; VectorRandomAccessSource source(f.image);
        Check(TryObserveAppleMarkedFileExtentRecords(source, f.scope, out, error, [&] { ++ticks; return true; }), error);
        unsigned now = 0;
        Check(!TryObserveAppleMarkedFileExtentRecords(source, f.scope, out, error, [&] { return ++now < ticks; }) && !out &&
            error.find("Deadline") != std::string::npos, "late deadline clears result");
        auto budget = std::make_shared<ApfsReadBudget>(1, 1, 1, 1); BudgetedRandomAccessSource spent(source, budget);
        for (unsigned i = 0; i < 2; ++i) Check(!TryObserveAppleMarkedFileExtentRecords(spent, f.scope, out, error) && !out && budget->Failed(),
            "shared budget stays exhausted on retry");
        Pass("final source, I/O, deadline and sticky-budget boundaries");
    }
    for (unsigned kind = 0; kind != 4; ++kind)
    {
        Fixture f;
        if (kind == 0) f.scope.exact.volume_uuid_hex = std::string(32, 'c');
        if (kind == 1) f.scope.require_whole_volume = true;
        if (kind == 2) f.scope.account_retained_ownership = true;
        if (kind == 3) f.scope.observe_payload_content = true;
        MarkRefused(f, kind ? "ScopeUnsupported" : "IdentityMismatch");
        Pass("wrong exact identity or unsupported stronger scope");
    }
}

void SparseRecordCase()
{
    Fixture f; VectorRandomAccessSource source(f.image); std::vector<Record> records; std::string error;
    Check(ReadAppleVolumeFileSystemRecords(source, f.checkpoint.container, f.checkpoint.volumes[0], records, error), error);
    for (auto& record : records)
    {
        const auto key = ReadU64LE(record.key, 0).value_or(0);
        if (key == (3ull << 60 | 30))
        {
            AppleInodeRecord inode; Check(ApfsExtendedRecordCodec::DecodeInode(record, inode, error), error);
            inode.internal_flags |= kAppleInodeSparseFlag; PutU64LE(inode.extended_fields[0].data, 8, 0);
            AppleExtendedField sparse{13, 0, Bytes(8)}; PutU64LE(sparse.data, 0, f.bs); inode.extended_fields.push_back(sparse);
            record = Encode(inode, EncodeAppleInodeRecord);
        }
        if ((key >> 60) == 8) record = Encode(AppleFileExtentRecord{30, 0, f.bs, 0, 0, f.bs}, EncodeAppleFileExtentRecord);
    }
    BuilderStore spec; spec.block_size = f.bs; spec.block_count = 512; spec.xid = 20;
    spec.authoritative_internal_pool_blocks = 32; spec.authoritative_checkpoint_ring_blocks = 32;
    spec.volumes[0].uuid_hex = std::string(32, 'b'); spec.volumes[0].filesystem_records = records;
    f.image = BuildAuthoritativeStoreImage(spec);
    f.Edit(4, [](auto& bytes) { PutU64LE(bytes, 0xB8, 1); PutU64LE(bytes, 0xC0, 1); }); f.Reload(); f.payload_blocks.clear();
    VectorRandomAccessSource valid(f.image); auto scope = f.scope; scope.account_retained_ownership = true;
    const auto control = ApfsVerifier::VerifyReadOnly(valid, scope);
    Check(control.outcome == VerificationOutcome::Complete && control.retained_ownership, "sparse control has complete canonical physical proof: " + Detail(control));
    SetMarks(f, {{30, 0x80000}}); const auto out = ObserveMarks(f);
    Check(out.views.back().marked_regular_inode_count == 1 && !out.referenced_physical_union.blocks, "holes are never charged as physical records");
    Pass("verified sparse image has zero physical marked extent records");
}

void StrictWarmRecordCase()
{
    Fixture f; SetMarks(f, {{30, 0x80000}}); VectorRandomAccessSource original(f.image);
    std::vector<Record> records; std::string error;
    Check(ReadAppleVolumeFileSystemRecords(original, f.checkpoint.container, f.checkpoint.volumes[0], records, error), error);
    for (auto& record : records)
        if (ReadU64LE(record.key, 0).value_or(0) == (3ull << 60 | 30))
        {
            const auto count = ReadU16LE(record.value, 92).value();
            const auto used = ReadU16LE(record.value, 94).value();
            Check(count && used >= count * 4, "native envelope fixture bound");
            PutU16LE(record.value, 94, static_cast<std::uint16_t>(used - count * 4));
        }
    std::vector<Bytes> keys, values; for (const auto& record : records) { keys.push_back(record.key); values.push_back(record.value); }
    const auto& tree = f.checkpoint.volumes[0].root_tree;
    f.Put(tree.physical_block, BuildRawLeafNode(keys, values, tree.xid, f.bs, 0, tree.object_id, tree.type, tree.subtype));
    // The native inode header is now canonical on both paths. Use the actual
    // observational-only inactive-tree seam for a mutation refusal control.
    f.Edit(4, [](auto& bytes) { PutU32LE(bytes, 0x414, kObjectPhysical | kObjectTypeBtree); }); f.Reload();
    const auto before = f.image; VectorRandomAccessSource source(f.image);
    auto budget = std::make_shared<ApfsReadBudget>(200000, 512ull << 20, 4000000, 512ull << 20);
    BudgetedRandomAccessSource bounded(source, budget); SnapshotPlanningSource operation(bounded);
    std::vector<std::uint64_t> metadata; std::vector<ApplePhysicalExtentRecord> payload;
    for (unsigned round = 0; round != 3; ++round)
    {
        Check(!LoadAppleSnapshotCheckpointOwners(operation, f.checkpoint, metadata, payload, error) && metadata.empty() && payload.empty(),
            "strict cold/warm owner refuses observational inactive-tree defaults: " + error);
        std::vector<Record> current;
        Check(ReadAppleVolumeFileSystemRecords(operation, f.checkpoint.container, f.checkpoint.volumes[0], current, error), error);
        NativeApfsVolumeProjection projection;
        Check(!NativeApfsReader::TryProjectOrdinaryFileSystemRecords(current, f.checkpoint.container.superblock,
            f.checkpoint.volumes[0].superblock, budget, projection, error) && projection.inodes.empty(),
            "strict cold/warm namespace still refuses marked files after canonical header decoding");
        std::optional<ApfsMarkedFileExtentRecordsObservation> out;
        Check(TryObserveAppleMarkedFileExtentRecords(operation, f.scope, out, error) && out &&
            out->referenced_physical_union.blocks == 1, "same-operation observational marked records succeed");
        AppleSnapshotCreateRequest request; request.volume_object_id = 101; request.name_utf8 = "must-refuse";
        request.creation_time_ns = f.checkpoint.container.superblock.next_xid; request.required_checkpoint_xids = Pins(f);
        AppleSnapshotCreatePlan plan;
        Check(!PlanAppleSnapshotCreate(operation, f.checkpoint, request, plan, error) &&
            plan.commit.publication.superblock_write.bytes.empty(), "actual mutation remains refused after marked-record observation");
    }
    Check(f.image == before && operation.VerifyUnchanged(error) && !budget->Failed(), "interleaved admission preserves source and allowance");
    Pass("marked native-envelope cold/warm interleaved mutation refusal");
}
}

#ifndef APFS_MARKED_RECORD_FIXTURES_ONLY
int main()
{
    try { CurrentRecordCases(); HistoricalRecordCases(); SparseRecordCase(); FailureRecordCases(); StrictWarmRecordCase(); std::cout << "PASS " << cases << " cases, " << checks << " checks\n"; return 0; }
    catch (const std::exception& e) { std::cerr << "FAIL " << e.what() << '\n'; return 1; }
}
#endif
