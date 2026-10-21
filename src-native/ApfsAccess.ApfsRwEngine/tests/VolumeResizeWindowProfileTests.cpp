#define APFS_PHYSICAL_RESIZE_FIXTURE_ONLY
#include "VolumePhysicalResizeTests.cpp"
#undef APFS_PHYSICAL_RESIZE_FIXTURE_ONLY
#include "../src/VolumeResizeRelocation.h"
#include <iomanip>

namespace
{
namespace catalog = apfsaccess::catalog;
constexpr std::uint64_t PartitionBytes = 6 * mc::ChunkBlocks * 4096;
template<class S> void MoveSnapshotRoot(S& source, std::uint64_t target)
{
    const auto cp = mc::Load(source); const auto& volume = cp.volumes.front();
    Check(volume.snapshot_metadata_tree && volume.snapshot_metadata_tree->type == (kObjectPhysical | kObjectTypeBtree),
        "genuine-shape physical snapshot metadata root");
    const auto old = volume.snapshot_metadata_tree->physical_block, destination = cp.container.superblock.block_count - 256;
    Check(old < target / 4096 && destination >= target / 4096, "physical root crosses exact shrink boundary");
    auto ip = cp.spaceman.internal_pool.active_bitmaps.front().bytes;
    std::map<std::size_t, Bytes> bitmaps, cibs; std::map<std::size_t, std::uint64_t> addresses;
    for (const auto [block, allocated] : {std::pair{old, false}, std::pair{destination, true}}) {
        const auto index = static_cast<std::size_t>(block / cp.spaceman.blocks_per_chunk); const auto& chunk = cp.spaceman.chunks.at(index);
        auto bitmap = chunk.allocation_bitmap; auto address = chunk.bitmap_block;
        if (!address) {
            Check(allocated && chunk.free_count == chunk.block_count, "new bitmap only describes a genuinely free canonical chunk");
            bitmap.assign(4096, std::byte{});
            for (auto bit = chunk.block_count; bit < cp.spaceman.blocks_per_chunk; ++bit) vi::SetBit(bitmap, bit, true);
            std::uint64_t slot = 0; while (slot < cp.spaceman.internal_pool.block_count && vi::Bit(ip, slot)) ++slot;
            Check(slot < cp.spaceman.internal_pool.block_count, "unused real internal-pool slot for authored bitmap");
            vi::SetBit(ip, slot, true); address = cp.spaceman.internal_pool.base_block + slot;
        }
        Check(vi::Bit(bitmap, block - chunk.start_block) != allocated, "move changes exact original allocated/free bits");
        vi::SetBit(bitmap, block - chunk.start_block, allocated); addresses[index] = address; bitmaps[index] = std::move(bitmap);
    }
    std::string error; AppleBtreeOptions options; options.block_size = 4096;
    options.root_object_id = options.root_physical_block = destination; options.xid = volume.snapshot_metadata_tree->xid;
    options.storage_type = kObjectPhysical; options.subtype = kObjectTypeSnapMetaTree; options.tree_flags = kAppleBtreePhysical;
    AppleSerializedBtree tree; Check(SerializeAppleBtree({}, options, tree, error) && tree.objects.size() == 1, error);
    Check(source.WriteBlock(destination, tree.objects.front().bytes), "canonical authored physical root in allocated tail");
    for (const auto& [index, bitmap] : bitmaps) {
        const auto& chunk = cp.spaceman.chunks.at(index); std::uint64_t free = 0;
        for (std::uint64_t bit = 0; bit < chunk.block_count; ++bit) if (!vi::Bit(bitmap, bit)) ++free;
        auto [cib, _] = cibs.try_emplace(chunk.cib_index, cp.spaceman.devices[0].cibs.at(chunk.cib_index).bytes);
        vi::Put(cib->second, 0x28 + chunk.index_in_cib * 32 + 20, free, 4);
        vi::Put(cib->second, 0x28 + chunk.index_in_cib * 32 + 24, addresses.at(index));
        Check(source.WriteBlock(addresses.at(index), bitmap), "exact authored main allocation bitmap");
    }
    for (auto& [index, cib] : cibs) { vi::Checksum(cib); Check(source.WriteBlock(cp.spaceman.devices[0].cibs.at(index).object.physical_block, cib), "authored CIB counters"); }
    Check(source.WriteBlock(cp.spaceman.internal_pool.active_bitmaps.front().physical_block, ip), "authored pool bitmap accounting");
    Bytes apsb; Check(source.Read(volume.superblock_object.physical_block * 4096, 4096, apsb), "APSB before physical root move");
    vi::Put(apsb, 0x98, destination); vi::Checksum(apsb);
    Check(source.WriteBlock(volume.superblock_object.physical_block, apsb) && source.Flush(), "durable authored APSB physical pointer");
    mc::Verify(source, mc::Load(source));
}
template<class S> void PayloadExact(S& source, bool overwritten = false)
{
    const auto cp = mc::Load(source); mc::Verify(source, cp); std::vector<catalog::BtreeRecord> records; std::string error;
    Check(ReadAppleVolumeFileSystemRecords(source, cp.container, cp.volumes.front(), records, error), error);
    std::uint64_t end = 0;
    for (const auto& record : records) if ((ReadU64LE(record.key, 0).value_or(0) >> 60) == 8 &&
        (ReadU64LE(record.key, 0).value() & 0x0fffffffffffffffULL) == 1030) {
        AppleFileExtentRecord extent; Check(DecodeAppleFileExtentRecord(record, 4096, extent, error), error);
        Check(extent.logical_address == end && extent.physical_block, "complete nonzero payload graph after geometry");
        Bytes bytes; Check(source.Read(extent.physical_block * 4096, static_cast<std::size_t>(extent.length_bytes), bytes), "payload readback");
        for (std::size_t i = 0; i < bytes.size(); ++i) Check(bytes[i] == (overwritten && end + i < 4096 ? std::byte{0x35} : std::byte{0x59}), "exact retained payload byte");
        end += extent.length_bytes;
    }
    Check(end == 8192, "complete 8192-byte ordinary payload remains");
}
template<class S> void RewritePayload(S& source)
{
    const auto cp = mc::Load(source); AppleVolumeTransactionRequest request; request.volume_object_id = cp.volumes.front().superblock.object_id;
    request.required_checkpoint_xids = {cp.container.superblock.xid}; std::string error;
    Check(ReadAppleVolumeFileSystemRecords(source, cp.container, cp.volumes.front(), request.filesystem_records, error), error);
    unsigned found = 0; auto original = std::move(request.filesystem_records);
    for (auto record : original) {
        if ((ReadU64LE(record.key, 0).value_or(0) >> 60) == 8 &&
            (ReadU64LE(record.key, 0).value() & 0x0fffffffffffffffULL) == 1030 && ReadU64LE(record.key, 8) == 0) {
            AppleFileExtentRecord extent; Check(DecodeAppleFileExtentRecord(record, 4096, extent, error) && extent.length_bytes >= 4096, "retained first payload block");
            request.released_data_blocks.push_back({extent.physical_block, 1}); ++found;
            if (extent.length_bytes == 4096) continue;
            extent.logical_address = 4096; ++extent.physical_block; extent.length_bytes -= 4096;
            Check(EncodeAppleFileExtentRecord(extent, record, error), error);
        }
        request.filesystem_records.push_back(std::move(record));
    }
    Check(found == 1, "one exact ordinary COW boundary"); request.data_writes.push_back({1030, 0, 0, Bytes(4096, std::byte{0x35})});
    AppleVolumeTransactionPlan plan; Check(PlanAppleVolumeTransaction(source, cp, request, plan, error), "ordinary COW after window rebind: " + error);
    Check(ExecuteAppleCheckpointPublication(source, plan.commit.publication, error), error); PayloadExact(source, true);
}
void SaveCase(const GeometryFixture& f, const std::filesystem::path& journal)
{
    std::ofstream state(root / "case.txt"); const auto& r = f.request;
    state << std::quoted(journal.string()) << '\n' << std::quoted((root / "case" / "simulated-physical-window.img").string()) << '\n'
        << std::quoted(r.journal_directory.string()) << '\n' << r.container_uuid << ' ' << r.volume_uuid << ' ' << r.volume_oid << ' '
        << r.checkpoint_xid << ' ' << r.expected_bytes << ' ' << r.target_bytes << ' ' << static_cast<unsigned>(r.operation) << '\n' << r.sibling_wals.size() << '\n';
    for (const auto& [oid, wal] : r.sibling_wals) state << oid << ' ' << std::quoted(wal.string()) << '\n';
    state << f.fixture.file->sentinels.size() << '\n';
    for (const auto& [offset, bytes] : f.fixture.file->sentinels) { Check(bytes == Bytes(bytes.size(), std::byte{0x6d}), "fixed private outside-range sentinel"); state << offset << ' ' << bytes.size() << '\n'; }
    Check(state.good(), "persist private recovery harness parameters");
}
void PrepareCut(bool window, bool physical_tail, std::string_view cut)
{
    GeometryFixture f("case", !physical_tail, 4096, true, window ? PartitionBytes : 0);
    mc::NativeWrite(*f.fixture.source); f.request.checkpoint_xid = mc::Load(*f.fixture.source).container.superblock.xid;
    if (physical_tail) MoveSnapshotRoot(*f.fixture.source, f.request.target_bytes);
    const auto before = f.fixture.Digests(); const auto writes_before = f.fixture.file->writes;
    if (physical_tail) {
        bool refused = false; try { (void)vi::BuildResizeRelocationPublication(*f.fixture.source, f.request); } catch (...) { refused = true; }
        Check(refused, "legacy VIF5 planner continues to refuse unsupported physical-root tail");
        const auto plan = vi::BuildResizeRelocationPublicationV2(*f.fixture.source, f.request);
        const auto& v = plan.after.volumes.front(); Check(v.snapshot_metadata_tree && v.snapshot_metadata_tree->object_id == v.snapshot_metadata_tree->physical_block &&
            v.snapshot_metadata_tree->physical_block < f.request.target_bytes / 4096, "physical COW identity and APSB pointer land inside target");
    }
    const auto p = PrepareVolumePhysicalResize(f.source, f.request); Check(p.outcome == VolumeImageOutcome::Prepared, "new geometry preparation: " + p.error);
    Check(f.fixture.Digests() == before && f.fixture.file->writes == writes_before, "new profile prepare preserves all original bytes");
    const auto plan = DecodeVolumeKeeperGeometryPlan(Read(p.journal));
    Check(ReadU64LE(Read(p.journal), 0) == (window || physical_tail ? vg::Version2Magic : vg::Magic), "explicit original geometry version");
    Check(window ? plan.writes.empty() && plan.after.media.partition_length_bytes == f.original.media.partition_length_bytes : plan.writes.size() == 4,
        "window profile has no GPT write; partition profile keeps exact four writes");
    bool hit = false; const auto result = ApplyVolumePhysicalResize(f.source, f.request, p.token, [&](auto stage) {
        if (stage != cut) return true; hit = true; return false;
    });
    Check(hit && result.outcome == VolumeImageOutcome::RecoveryRequired, "genuine accepted geometry cut: " + result.error);
    SaveCase(f, p.journal); Check(f.fixture.file->Current() && !f.fixture.file->escaped, "exact carrier identity and neighbors preserved at cut");
}
void RecoverCase()
{
    std::ifstream state(root / "case.txt"); std::string journal, carrier, directory; VolumeImageRequest r; unsigned operation = 0; std::size_t count = 0;
    state >> std::quoted(journal) >> std::quoted(carrier) >> std::quoted(directory) >> r.container_uuid >> r.volume_uuid >> r.volume_oid >>
        r.checkpoint_xid >> r.expected_bytes >> r.target_bytes >> operation >> count;
    Check(state.good() && count <= 100 && operation >= 1 && operation <= 2, "bounded private recovery parameters");
    r.operation = static_cast<VolumeImageOperation>(operation); r.journal_directory = directory; r.image = SimulatedInstance;
    for (std::size_t i = 0; i < count; ++i) { std::uint64_t oid; std::string wal; state >> oid >> std::quoted(wal); r.sibling_wals.emplace(oid, wal); }
    const auto plan = DecodeVolumeKeeperGeometryPlan(Read(journal)); auto file = std::make_shared<PhysicalFile>(); file->binding = plan.snapshot.original.binding;
    state >> count; Check(count <= 16, "bounded sentinel census");
    for (std::size_t i = 0; i < count; ++i) { std::uint64_t offset; std::size_t size; state >> offset >> size; Check(size <= 4096, "bounded sentinel bytes"); file->sentinels.emplace(offset, Bytes(size, std::byte{0x6d})); }
    Check(state.good(), "complete recovery parameters");
    file->handle = CreateFileW(FixtureIoPath(carrier).c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_FLAG_WRITE_THROUGH, nullptr);
    Check(file->handle != INVALID_HANDLE_VALUE && GetFileInformationByHandleEx(file->handle, FileIdInfo, &file->id, sizeof(file->id)) && file->Current(), "fresh process holds same private surrogate");
    auto source = VolumePhysicalGeometryTestPeer::Bind(file, plan.snapshot.original.binding); std::shared_ptr<VolumePhysicalSource> fixed;
    const auto done = RecoverVolumePhysicalResize(source, r, {}, &fixed);
    Check(done.outcome == VolumeImageOutcome::Committed && fixed && !source->Revalidate(), "fresh process forward recovery/revocation/rebind: " + done.error);
    std::string error; Check(fixed->VerifyCompletedGeometry(vg::Encode(plan), error), "complete GPT copies/census after recovery: " + error);
    PayloadExact(*fixed);
    { auto history = AcquireVolumeKeeperPhysicalHistory(fixed, *fixed, r.journal_directory, {}); RewritePayload(*fixed); }
    source = VolumePhysicalGeometryTestPeer::Bind(file, plan.snapshot.original.binding);
    Check(RecoverVolumePhysicalResize(source, r).outcome == VolumeImageOutcome::Committed, "completed original permits later ordinary generation/reopen");
    Check(file->Current() && !file->escaped, "all unrelated sentinels and carrier EOF preserved after ordinary COW");
    std::ofstream oracle(root / "payload-ranges.txt"); const auto cp = mc::Load(*fixed); std::vector<catalog::BtreeRecord> records;
    Check(ReadAppleVolumeFileSystemRecords(*fixed, cp.container, cp.volumes.front(), records, error), error);
    for (const auto& record : records) if ((ReadU64LE(record.key, 0).value_or(0) >> 60) == 8 && (ReadU64LE(record.key, 0).value() & 0x0fffffffffffffffULL) == 1030) {
        AppleFileExtentRecord extent; Check(DecodeAppleFileExtentRecord(record, 4096, extent, error), error);
        oracle << extent.logical_address << ' ' << SimulatedBase + extent.physical_block * 4096 << ' ' << extent.length_bytes << '\n';
    }
    Check(oracle.good(), "independent carrier payload offsets");
}
void CodecControls()
{
    GeometryFixture f("controls", true, 4096, true, PartitionBytes); const auto plan = vg::Capture(*f.source, {f.original, std::wstring(SimulatedInstance)}, f.request.target_bytes);
    const auto bytes = vg::Encode(plan); Check(vg::Encode(vg::Decode(bytes)) == bytes && plan.writes.empty(), "exact new window codec roundtrip");
    for (unsigned fault = 0; fault < 4; ++fault) { auto bad = bytes;
        if (fault == 0) vi::Put(bad, 0, vg::Magic);
        if (fault == 1) vi::Put(bad, 8, 0);
        if (fault == 2) vi::Put(bad, 8, 3);
        if (fault == 3) bad.push_back(std::byte{});
        bool refused = false; try { (void)vg::Decode(bad); } catch (...) { refused = true; } Check(refused, "mode/version/profile/trailing spoof refuses");
    }
    auto bad = plan.snapshot; bad.target_bytes = PartitionBytes + 4096; bool refused = false;
    try { (void)vg::Build(bad); } catch (...) { refused = true; } Check(refused, "window cannot grow beyond selected partition");
    const auto before = f.fixture.Digests(); const auto prepared = PrepareVolumePhysicalResize(f.source, f.request);
    Check(prepared.outcome == VolumeImageOutcome::Prepared, prepared.error);
    Check(CancelVolumePhysicalResize(f.source, f.request, prepared.token).outcome == VolumeImageOutcome::Cancelled &&
        f.fixture.Digests() == before && !f.fixture.file->writes && !f.fixture.file->zeros, "new window cancel preserves APFS and GPT");
}
void ImageTail()
{
    GeometryFixture f("image-source", false, 4096, true); mc::NativeWrite(*f.fixture.source);
    f.request.checkpoint_xid = mc::Load(*f.fixture.source).container.superblock.xid;
    MoveSnapshotRoot(*f.fixture.source, f.request.target_bytes);
    mc::SparseStore original; original.block_count = f.request.expected_bytes / 4096;
    for (std::uint64_t at = 0; at < f.request.expected_bytes; at += fe::Chunk) {
        Bytes chunk; const auto n = static_cast<std::size_t>((std::min)(fe::Chunk, f.request.expected_bytes - at));
        Check(f.fixture.source->Read(at, n, chunk) && chunk.size() == n, "bounded original image source");
        for (std::size_t i = 0; i < n; i += 4096) if (std::any_of(chunk.begin() + i, chunk.begin() + i + 4096, [](auto b) { return b != std::byte{}; }))
            original.blocks[(at + i) / 4096] = Bytes(chunk.begin() + i, chunk.begin() + i + 4096);
    }
    auto r = f.request; r.image = root / "image.apfs"; r.journal_directory = root / "image-keeper";
    std::filesystem::create_directories(r.journal_directory);
    for (auto& [oid, wal] : r.sibling_wals) wal = r.journal_directory / (std::to_string(oid) + ".wal");
    mc::SparseFile(r.image, original); const auto before = Digests(r.image);
    const auto p = PrepareVolumeResize(r); Check(p.outcome == VolumeImageOutcome::Prepared, "VIF9 image prepare: " + p.error);
    Check(ReadU64LE(Read(p.journal), 0) == vg::PhysicalSnapshotRelocationMagic && Digests(r.image) == before, "distinct VIF9 and exact immutable preimage");
    const auto accepted = ApplyVolumeResize(r, p.token, [](auto stage) { return stage != "after-image-accept"; });
    Check(accepted.outcome == VolumeImageOutcome::RecoveryRequired, accepted.error);
    auto frame = Read(p.journal); auto wrong = frame; vi::Put(wrong, 0, fe::RelocationMagic); Save(p.journal, wrong);
    Check(RecoverVolumeResize(r).outcome == VolumeImageOutcome::RecoveryRequired && Digests(r.image) == before,
        "VIF9 original cannot be relabeled as historical VIF5"); Save(p.journal, frame);
    const auto plan = vi::BuildResizeRelocationPublicationV2(original, r);
    { Target target(r.image); const auto& write = plan.publication.before_superblock_writes.front(); auto torn = write.bytes;
      std::fill_n(torn.begin(), 71, std::byte{0x86}); Check(target.WriteBlock(write.physical_block, torn) && target.Flush(), "actual torn planned private destination"); }
    const auto recovered = RecoverVolumeResize(r); Check(recovered.outcome == VolumeImageOutcome::Committed, "VIF9 forward recovery: " + recovered.error);
    { Target target(r.image); PayloadExact(target); const auto cp = mc::Load(target); const auto& v = cp.volumes.front();
      Check(v.snapshot_metadata_tree && v.snapshot_metadata_tree->physical_block == v.superblock.snap_meta_tree_oid &&
          v.snapshot_metadata_tree->physical_block < r.target_bytes / 4096, "VIF9 APSB physical root pointer remains in bounds");
      auto history = AcquireVolumeKeeperHistory(p.source_identity, target, r.journal_directory, {}); RewritePayload(target); }
    Check(RecoverVolumeResize(r).outcome == VolumeImageOutcome::Committed && InspectVolumeKeeperImage(r.image, 0, r.journal_directory).admitted,
        "VIF9 completed history permits ordinary COW and reopen");
    Pass("VIF9 image physical root COW, mode refusal, torn destination and ordinary write");
}
}
int wmain(int argc, wchar_t** argv)
{
    try { Check(argc >= 3 && argc <= 5, "mode, fresh D root and optional cut"); root = argv[2];
        Check(root.is_absolute() && root.wstring().starts_with(L"D:\\ApfsAccessScratch\\"), "private D artifacts only");
        const std::wstring_view mode(argv[1]);
        if (mode == L"--recover") RecoverCase();
        else { Check(!std::filesystem::exists(root) && std::filesystem::create_directories(root), "fresh private output root");
            if (mode == L"--controls") CodecControls();
            else if (mode == L"--boundaries") GeometryBoundaryControls(true);
            else if (mode == L"--sequence") GeometrySequential(true);
            else if (mode == L"--image-tail") ImageTail();
            else if (mode == L"--dispatch") GeometryDispatch(true);
            else { Check(argc == 5, "window/tail switches and cut name");
                const bool window = mode == L"--window"; Check(window || mode == L"--partition", "known geometry profile");
                const bool tail = std::wstring_view(argv[3]) == L"tail"; Check(tail || std::wstring_view(argv[3]) == L"grow", "known source owner profile");
                const std::wstring cut(argv[4]); PrepareCut(window, tail, std::string(cut.begin(), cut.end())); }
        }
        std::cout << "PASS geometry windows groups=" << groups << " checks=" << checks << " hardware=0\n"; return 0;
    } catch (const std::exception& error) { std::cerr << "FAIL geometry windows checks=" << checks << ' ' << error.what() << '\n'; return 1; }
}
