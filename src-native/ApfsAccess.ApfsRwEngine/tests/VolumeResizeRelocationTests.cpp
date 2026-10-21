#define wmain FormatStreamedFixtureMain
#include "VolumeFormatStreamedTests.cpp"
#undef wmain
#include "../src/VolumeResizeRelocation.h"
#include "ApfsExtendedRecordCodec.h"

VolumeImageRequest RelocationRequest(const mc::SparseStore& source)
{
    const auto cp = mc::Load(source); VolumeImageRequest r;
    r.operation = VolumeImageOperation::Shrink; r.container_uuid = cp.container.superblock.uuid_hex;
    r.volume_uuid = cp.volumes.front().superblock.uuid_hex; r.volume_oid = cp.volumes.front().superblock.object_id;
    r.checkpoint_xid = cp.container.superblock.xid; r.expected_bytes = source.SizeBytes();
    r.target_bytes = (3 * mc::ChunkBlocks - 25) * 4096; return r;
}
void MarkOrphanedTail(mc::SparseStore& source, std::uint32_t count)
{
    const auto cp = mc::Load(source); const auto& chunk = cp.spaceman.chunks.back();
    Check(chunk.bitmap_block && count < chunk.free_count, "real free tail bitmap exists");
    auto bitmap = chunk.allocation_bitmap;
    for (std::uint64_t i = 1000; i < 1000 + count; ++i) {
        Check(!vi::Bit(bitmap, i), "negative-control allocation starts free"); vi::SetBit(bitmap, i, true);
    }
    source.blocks[chunk.bitmap_block] = bitmap;
    const auto& original = cp.spaceman.devices[0].cibs.at(chunk.cib_index);
    auto cib = original.bytes; vi::Put(cib, 0x28 + chunk.index_in_cib * 0x20 + 0x14, chunk.free_count - count, 4);
    vi::Checksum(cib); source.blocks[original.object.physical_block] = cib;
    auto sm = cp.spaceman.bytes; vi::Put(sm, 0x48, cp.spaceman.devices[0].free_count - count);
    vi::Checksum(sm); source.blocks[cp.spaceman.object.physical_block] = sm;
    mc::Verify(source, mc::Load(source));
}
mc::SparseStore RelocationPolicySource(std::uint64_t features, bool malformed_hash = false)
{
    auto source = Source();
    auto format = Request(root, VolumeImageOperation::Format, Fixture());
    format.expected_bytes = format.target_bytes = source.SizeBytes(); format.case_sensitive = true;
    auto formatted = vi::BuildFormatPublication(source, format, mc::Load(source));
    vi::FinishFormatSource(source, format, formatted); source = mc::Publish(std::move(source), formatted);
    const auto cp = mc::Load(source); const auto& volume = cp.volumes.front(); std::string error;
    const auto before_policy = ApfsNamePolicy::FromIncompatibleFeatures(volume.superblock.incompatible_features);
    const auto policy = ApfsNamePolicy::FromIncompatibleFeatures(features);
    std::vector<apfsaccess::catalog::BtreeRecord> records;
    Check(ReadAppleVolumeFileSystemRecords(source, cp.container, volume, records, error), error);
    unsigned directories = 0;
    // Author the fixture before resize admission using the existing name codec.
    for (auto& record : records) if ((ReadU64LE(record.key, 0).value_or(0) >> 60) == 9) {
        AppleDirectoryRecord directory;
        Check(ApfsExtendedRecordCodec::DecodeDirectory(record, before_policy, directory, error), error);
        directory.name_utf8 = "caf\xc3\xa9";
        Check(EncodeAppleDirectoryRecord(directory, policy, record, error), error); ++directories;
        if (malformed_hash) {
            Check(features == 8 && record.key.size() > 12, "malformed control starts from a hashed key");
            record.key[11] ^= std::byte{1}; AppleDirectoryRecord rejected;
            Check(!ApfsExtendedRecordCodec::DecodeDirectory(record, policy, rejected, error),
                "wrong stored hash is refused by the existing typed decoder");
        }
    }
    Check(directories == 1, "formatted fixture has one canonical private directory");
    AppleBtreeOptions options; options.block_size = 4096; options.root_object_id = volume.root_tree.object_id;
    options.root_physical_block = volume.root_tree.physical_block; options.xid = volume.root_tree.xid;
    options.storage_type = volume.root_tree.type & kObjectStorageTypeMask; options.subtype = volume.root_tree.subtype;
    options.tree_flags = options.storage_type == kObjectPhysical ? kAppleBtreePhysical : 0;
    options.key_order = policy.UsesHashedDirectoryKeys() ? AppleBtreeKeyOrder::FileSystemHashedDirectory : AppleBtreeKeyOrder::FileSystemCaseSensitive;
    options.max_nodes = 1; AppleSerializedBtree tree;
    Check(SerializeAppleBtree(records, options, tree, error) && tree.objects.size() == 1, error);
    source.blocks[volume.root_tree.physical_block] = tree.objects.front().bytes;
    auto apsb = source.blocks.at(volume.superblock_object.physical_block);
    vi::Put(apsb, 0x38, features); vi::Checksum(apsb); source.blocks[volume.superblock_object.physical_block] = std::move(apsb);
    if (!malformed_hash) mc::Verify(source, mc::Load(source));
    return source;
}
void RelocationNamePolicies()
{
    VolumeImageRequest malformed_request;
    for (const auto features : {0ull, 1ull, 8ull, 9ull}) {
        std::cout << "POLICY " << features << " relocation begin" << std::endl;
        auto source = RelocationPolicySource(features); const auto request = RelocationRequest(source);
        if (features == 8) malformed_request = request;
        const auto before = mc::Load(source); const auto& volume = before.volumes.front(); std::string error;
        Check(volume.superblock.incompatible_features == features, "exact policy in the source APSB");
        std::vector<apfsaccess::catalog::BtreeRecord> expected;
        Check(ReadAppleVolumeFileSystemRecords(source, before.container, volume, expected, error), error);
        const auto inventory = vi::InspectResizeRelocationSource(source, request);
        Check(!inventory.blocks.empty() && !inventory.unknown_blocks && volume.root_tree.physical_block >= request.target_bytes / 4096,
            "canonical filesystem root is an owned actual relocation target");
        const auto originals = source.blocks; const auto writes = source.writes, flushes = source.flushes;
        const auto plan = inventory.physical_snapshot_root_in_tail ? vi::BuildResizeRelocationPublicationV2(source, request) :
            vi::BuildResizeRelocationPublication(source, request);
        Check(source.blocks == originals && source.writes == writes && source.flushes == flushes,
            "relocation planning preserves every represented source block");
        auto after = mc::Publish(source, plan); after.block_count = request.target_bytes / 4096;
        std::erase_if(after.blocks, [&](const auto& block) { return block.first >= after.block_count; });
        const auto path = root / ("unicode-relocation-" + std::to_string(features) + ".apfs");
        Check(!std::filesystem::exists(path), "fresh exact private sparse image"); mc::SparseFile(path, after);
        Check(std::filesystem::file_size(path) == request.target_bytes, "actual sparse image EOF is the reduced capacity");
        Target reopened(path); const auto cp = mc::Load(reopened); mc::Verify(reopened, cp); const auto& result = cp.volumes.front();
        Check(cp.container.superblock.uuid_hex == before.container.superblock.uuid_hex &&
            result.superblock.uuid_hex == volume.superblock.uuid_hex && result.superblock.incompatible_features == features &&
            result.root_tree.object_id == volume.root_tree.object_id && result.root_tree.physical_block < after.block_count,
            "fresh file reopen preserves exact volume policy and root identity below the tail");
        std::vector<apfsaccess::catalog::BtreeRecord> actual;
        Check(ReadAppleVolumeFileSystemRecords(reopened, cp.container, result, actual, error) && actual.size() == expected.size(), error);
        for (std::size_t i = 0; i < actual.size(); ++i)
            Check(actual[i].key == expected[i].key && actual[i].value == expected[i].value,
                "every Unicode directory and inode record survives relocation byte-for-byte");
        std::cout << "POLICY " << features << " relocation and persisted reopen passed" << std::endl;
    }
    auto malformed = RelocationPolicySource(8, true);
    const auto matching_request = RelocationRequest(malformed);
    Check(matching_request.operation == malformed_request.operation &&
        matching_request.container_uuid == malformed_request.container_uuid &&
        matching_request.volume_uuid == malformed_request.volume_uuid && matching_request.volume_oid == malformed_request.volume_oid &&
        matching_request.checkpoint_xid == malformed_request.checkpoint_xid &&
        matching_request.expected_bytes == malformed_request.expected_bytes && matching_request.target_bytes == malformed_request.target_bytes,
        "malformed hash control uses the exact matching source identity and geometry");
    const auto originals = malformed.blocks; const auto writes = malformed.writes, flushes = malformed.flushes;
    bool refused = false;
    try { (void)vi::BuildResizeRelocationPublication(malformed, malformed_request); }
    catch (const std::exception&) { refused = true; }
    Check(refused && malformed.blocks == originals && malformed.writes == writes && malformed.flushes == flushes,
        "features8 malformed hashed directory refuses relocation without source writes");
    Pass("all four name policies relocate and reopen exact Unicode records; malformed hash refuses unchanged");
}
void Inventory()
{
    auto source = Source(); auto r = RelocationRequest(source); const auto original = source.blocks;
    Check(vi::InspectResizeRelocationSource(source, r).blocks.empty() && source.blocks == original,
        "tail-free inventory is read-only");
    auto format = Request(root, VolumeImageOperation::Format, Fixture()); format.expected_bytes = format.target_bytes = source.SizeBytes();
    auto plan = vi::BuildFormatPublication(source, format, mc::Load(source)); vi::FinishFormatSource(source, format, plan);
    source = mc::Publish(std::move(source), plan); const auto formatted = mc::Load(source);
    {
        const auto request = RelocationRequest(source); const auto original_blocks = source.blocks;
        const auto relocated = vi::BuildResizeRelocationPublication(source, request);
        Check(relocated.postimage.empty() && source.blocks == original_blocks, "bootstrap relocation plans without source mutation or postimage");
        auto after = mc::Publish(source, relocated); after.block_count = request.target_bytes / 4096;
        const auto cp = mc::Load(after); mc::Verify(after, cp);
        Check(cp.container.superblock.uuid_hex == formatted.container.superblock.uuid_hex &&
            cp.volumes.front().superblock.uuid_hex == formatted.volumes.front().superblock.uuid_hex &&
            cp.spaceman.internal_pool.base_block + cp.spaceman.internal_pool.block_count <= after.block_count,
            "relocated canonical bootstrap preserves identities inside target");
        mc::NativeWrite(after); mc::Verify(after, mc::Load(after));
    }
    const auto historical = formatted.volumes.front().root_tree;
    {
        AppleVolumeTransactionRequest mutation; mutation.volume_object_id = formatted.volumes.front().superblock.object_id;
        mutation.preserve_source_metadata = true; mutation.last_modification_time = 1700000000000000000ull;
        std::string error;
        Check(ReadAppleVolumeFileSystemRecords(source, formatted.container, formatted.volumes.front(), mutation.filesystem_records, error), error);
        AppleVolumeTransactionPlan replacement;
        Check(PlanAppleVolumeTransaction(source, formatted, mutation, replacement, error), error);
        Check(ExecuteAppleCheckpointPublication(source, replacement.commit.publication, error), error);
    }
    {
        const auto cp = mc::Load(source); const auto& map = cp.volumes.front().object_map;
        std::vector<apfsaccess::catalog::BtreeRecord> records; std::string error;
        Check(ReadBtreeLeafRecords(source, 4096, map.tree.physical_block, true, 0, cp.container.superblock.xid, records, error), error);
        apfsaccess::catalog::BtreeRecord old; Check(EncodeAppleOmapRecord({historical.object_id, historical.xid, 0, 4096, historical.physical_block}, old, error), error);
        Check(std::none_of(records.begin(), records.end(), [&](const auto& item) { return item.key == old.key; }), "real old root is not current mapping");
        records.push_back(old); Check(SortAppleBtreeRecords(records, AppleBtreeKeyOrder::ObjectMap, error), error);
        AppleBtreeOptions o; o.block_size = 4096; o.xid = map.tree.xid; o.root_object_id = map.tree.object_id;
        o.root_physical_block = map.tree.physical_block; o.storage_type = kObjectPhysical; o.subtype = kObjectTypeOmap;
        o.tree_flags = kAppleBtreePhysical; o.key_order = AppleBtreeKeyOrder::ObjectMap;
        o.fixed_key_size = o.fixed_value_size = 16; o.max_nodes = 1;
        AppleSerializedBtree tree; Check(SerializeAppleBtree(records, o, tree, error) && tree.objects.size() == 1, error);
        source.blocks[map.tree.physical_block] = tree.objects.front().bytes;
    }
    r = RelocationRequest(source); const auto before = source.blocks; const auto writes = source.writes;
    const auto inventory = vi::InspectResizeRelocationSource(source, r);
    Check(inventory.reserved_region_crosses_target && !inventory.blocks.empty(), "actual formatted bootstrap lies in removed tail");
    const auto retained = std::find_if(inventory.blocks.begin(), inventory.blocks.end(), [&](const auto& b) { return b.physical_block == historical.physical_block; });
    Check(retained != inventory.blocks.end() && retained->Has(vi::ResizeTailRole::Metadata), "hidden historical root is retained in tail inventory");
    Check(source.blocks == before && source.writes == writes, "inventory cannot publish or alter source");
    for (const auto& block : inventory.blocks) { Bytes bytes; Check(source.Read(block.physical_block * 4096, 4096, bytes) &&
        fe::Hash(bytes) == block.original_sha256, "tail digest is exact original bytes"); }
    auto bad = r; ++bad.checkpoint_xid; bool refused = false;
    try { (void)vi::InspectResizeRelocationSource(source, bad); } catch (const std::exception& ex) {
        refused = std::string_view(ex.what()) == "VolumeImageIdentityOrGeometryMismatch"; }
    Check(refused && source.blocks == before, "stale checkpoint cannot create inventory");
    auto orphan = source; MarkOrphanedTail(orphan, 1);
    const auto unknown = vi::InspectResizeRelocationSource(orphan, RelocationRequest(orphan));
    const auto orphaned_block = mc::Load(orphan).spaceman.chunks.back().start_block + 1000;
    Check(unknown.unknown_blocks == inventory.unknown_blocks + 1 && std::count_if(unknown.blocks.begin(), unknown.blocks.end(),
        [&](const auto& block) { return block.physical_block == orphaned_block && block.Has(vi::ResizeTailRole::Unknown); }) == 1,
        "orphaned allocation adds exactly one unknown owner at its actual address");
    auto quota = source; MarkOrphanedTail(quota, 4097); refused = false;
    try { (void)vi::InspectResizeRelocationSource(quota, RelocationRequest(quota)); } catch (const std::exception& ex) {
        refused = std::string_view(ex.what()) == "VolumeResizeRelocationBlockQuotaExceeded"; }
    Check(refused, "relocation memory quota refuses before producing partial inventory");
    Check(source.largest_read <= fe::Chunk, "no image-sized read");
    Pass("canonical tail inventory preserves hidden owners and refuses stale or oversized scope");
}
int wmain(int argc, wchar_t** argv)
{
    try { Check(argc == 2 || (argc == 3 && std::wstring_view(argv[2]) == L"--unicode-relocation-only"), "private artifact root"); root = argv[1];
        if (argc == 3)
            Check(root.is_absolute() && root.wstring().starts_with(L"D:\\ApfsAccessScratch\\"), "owned ordinary D artifact root");
        if (argc == 2) Inventory();
        std::filesystem::create_directories(root); RelocationNamePolicies();
        std::cout << "PASS groups=" << groups << " checks=" << checks << '\n'; return 0;
    } catch (const std::exception& ex) { std::cerr << "FAIL checks=" << checks << " " << ex.what() << '\n'; return 1; }
}
