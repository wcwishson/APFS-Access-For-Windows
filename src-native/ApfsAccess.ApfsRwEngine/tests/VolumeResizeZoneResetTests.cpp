#define APFS_ZONE_POLICY_FIXTURE_ONLY
#include "VolumeResizeZonePolicyTests.cpp"

namespace {
constexpr std::uint64_t OldBlocks = (1ull << 21) + mc::ChunkBlocks / 2;
constexpr std::uint64_t NewBlocks = (1ull << 21) + mc::ChunkBlocks / 4;
constexpr std::uint64_t FixtureBudget = 512ull << 20;
std::uint64_t physical_peak = 0;

std::uint64_t PhysicalBytes(const std::filesystem::path& path)
{
    DWORD high = 0; SetLastError(ERROR_SUCCESS);
    const auto low = GetCompressedFileSizeW(FixtureIoPath(path).c_str(), &high);
    Check(low != INVALID_FILE_SIZE || GetLastError() == ERROR_SUCCESS, "measure regular-file allocation");
    return (static_cast<std::uint64_t>(high) << 32) | low;
}
void Storage(const char* stage)
{
    std::uint64_t allocated = 0, logical = 0;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(root)) {
        Check(!entry.is_symlink(), "fixture contains no linked paths");
        if (!entry.is_regular_file()) continue;
        allocated += PhysicalBytes(entry.path()); logical += entry.file_size();
        if (entry.path().extension() == L".apfs")
            Check(PhysicalBytes(entry.path()) <= (8ull << 20), "sparse image allocation stays below eight MiB");
    }
    physical_peak = (std::max)(physical_peak, allocated);
    Check(allocated <= FixtureBudget, "complete fixture/keeper/WAL physical budget");
    std::cout << "STORAGE " << stage << " logical=" << logical << " allocated=" << allocated
        << " peak=" << physical_peak << std::endl;
}
void SparseProof(const std::filesystem::path& path)
{
    const auto attributes = GetFileAttributesW(FixtureIoPath(path).c_str());
    Check(attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_SPARSE_FILE), "NTFS sparse flag is set before keeper admission");
    const auto handle = CreateFileW(FixtureIoPath(path).c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, 0, nullptr);
    Check(handle != INVALID_HANDLE_VALUE, "open only the private sparse regular file");
    wchar_t filesystem[32]{};
    const bool ntfs = GetVolumeInformationByHandleW(handle, nullptr, 0, nullptr, nullptr, nullptr, filesystem, 32) &&
        std::wstring_view(filesystem) == L"NTFS";
    FILE_ALLOCATED_RANGE_BUFFER query{}; query.Length.QuadPart = static_cast<LONGLONG>(std::filesystem::file_size(path));
    std::array<FILE_ALLOCATED_RANGE_BUFFER, 128> ranges{}; DWORD bytes = 0;
    const bool queried = DeviceIoControl(handle, FSCTL_QUERY_ALLOCATED_RANGES, &query, sizeof(query),
        ranges.data(), static_cast<DWORD>(sizeof(ranges)), &bytes, nullptr) != 0;
    CloseHandle(handle);
    Check(ntfs && queried && bytes % sizeof(ranges[0]) == 0, "bounded NTFS allocated-range query succeeds");
    std::uint64_t covered = 0;
    for (std::size_t i = 0; i < bytes / sizeof(ranges[0]); ++i) covered += ranges[i].Length.QuadPart;
    Check(covered <= (8ull << 20) && std::filesystem::file_size(path) == OldBlocks * 4096,
        "eight-GiB logical source has a measured small allocation");
    std::cout << "SPARSE logical=" << OldBlocks * 4096 << " ranges=" << bytes / sizeof(ranges[0])
        << " rangeBytes=" << covered << " allocation=" << PhysicalBytes(path) << std::endl;
}
Bytes CanonicalPolicy(unsigned index = 2)
{
    Bytes policy(0x880);
    for (unsigned slot = 0; slot < 4; ++slot) {
        const auto at = slot * 0x88;
        for (unsigned pair = 0; pair < 8; ++pair) {
            const auto chunk = 4 + slot * 8 + pair;
            vi::Put(policy, at + pair * 16, chunk * mc::ChunkBlocks);
            vi::Put(policy, at + pair * 16 + 8, (chunk + 1) * mc::ChunkBlocks);
        }
        vi::Put(policy, at + 0x80, slot + 1, 2); vi::Put(policy, at + 0x82, index, 2);
    }
    return policy;
}
mc::SparseStore ResetSource(const Bytes& policy = CanonicalPolicy())
{
    auto source = Source(); const auto cp = mc::Load(source);
    const auto used = cp.spaceman.devices[0].block_count - cp.spaceman.devices[0].free_count;
    source.block_count = OldBlocks;
    for (auto& [block, bytes] : source.blocks) {
        (void)block; if (ParseNxSuperblock(bytes)) { vi::Put(bytes, 0x28, OldBlocks); vi::Checksum(bytes); }
    }
    auto sm = cp.spaceman.bytes;
    vi::Put(sm, 0x30, OldBlocks); vi::Put(sm, 0x38, 65); vi::Put(sm, 0x48, OldBlocks - used);
    vi::Put(sm, 0x154, 0x9d8, 4);
    std::copy(policy.begin(), policy.end(), sm.begin() + 0x158); vi::Checksum(sm);
    source.blocks[cp.spaceman.object.physical_block] = std::move(sm);
    auto cib = cp.spaceman.devices[0].cibs.front().bytes;
    vi::Put(cib, 0x24, 65, 4); std::fill(cib.begin() + 0x28, cib.end(), std::byte{});
    for (std::uint64_t i = 0; i < 65; ++i) {
        const auto at = 0x28 + i * 0x20, length = (std::min)(mc::ChunkBlocks, OldBlocks - i * mc::ChunkBlocks);
        vi::Put(cib, at, cp.container.superblock.xid); vi::Put(cib, at + 8, i * mc::ChunkBlocks);
        vi::Put(cib, at + 16, length, 4); vi::Put(cib, at + 20, length - (i == 0 ? used : 0), 4);
        vi::Put(cib, at + 24, i == 0 ? cp.spaceman.chunks.front().bitmap_block : 0);
    }
    vi::Checksum(cib); source.blocks[cp.spaceman.devices[0].cibs.front().object.physical_block] = std::move(cib);
    mc::Verify(source, mc::Load(source)); return source;
}
void SourceWal(const std::filesystem::path& path, const std::string& identity, std::uint64_t xid, bool accepted)
{
    {
    TransactionManager tx(L"Strict"); tx.SetJournalPath(path.wstring());
    tx.SetVolumeIdentity(std::wstring(identity.begin(), identity.end()));
    TransactionManager::MutationIntent mutation; mutation.kind = TransactionManager::MutationKind::CreateFile;
    mutation.path = L"\\retained-wal-intent"; mutation.object_id = 900; mutation.generation = xid + 1;
    Check(tx.Begin() && tx.RecordMutation(mutation), "real source WAL mutation recorded");
    Check(accepted ? tx.Accept(xid) : (tx.FlushPreparedRecords() && tx.Abort()), "real source WAL acceptance or abort is durable");
    }
    std::vector<TransactionManager::AcceptedTransaction> pending; TransactionManager::DurabilityWatermarks marks{};
    std::string error;
    Check(TransactionManager::InspectAcceptedTransactionsReadOnly(path,
        identity, pending, marks, error) && pending.size() == (accepted ? 1u : 0u),
        "source WAL has its actual expected accepted-debt state: " + error);
}
VolumeImageRequest ResetImage(const std::string& name, bool accepted = false)
{
    const auto directory = root / name; Check(!std::filesystem::exists(directory), "fresh private case directory");
    std::filesystem::create_directories(directory);
    const auto source = ResetSource(); auto request = Request(directory, VolumeImageOperation::Shrink, Fixture());
    request.expected_bytes = source.SizeBytes(); request.target_bytes = NewBlocks * 4096;
    mc::SparseFile(request.image, source); SparseProof(request.image); Storage("source-before-admission");
    { Target target(request.image); NativeMetadataWrite(target); const auto cp = mc::Load(target);
      request.checkpoint_xid = cp.container.superblock.xid; mc::Verify(target, cp); }
    for (const auto& [oid, path] : request.sibling_wals)
        SourceWal(path, "apfs-vol:" + request.container_uuid + ":" + std::to_string(oid), request.checkpoint_xid,
            accepted && oid == request.volume_oid);
    return request;
}
using Digest = std::array<std::byte, 32>;
struct Integrity {
    std::map<std::uint64_t, std::vector<std::pair<Bytes, Bytes>>> filesystem;
    std::map<std::uint64_t, Bytes> apsbs;
    std::map<std::pair<std::uint64_t, std::uint64_t>, Digest> payload;
};
Integrity CaptureIntegrity(Target& source)
{
    const auto cp = mc::Load(source); mc::Verify(source, cp); Integrity result; std::string error;
    for (const auto& volume : cp.volumes) {
        std::vector<apfsaccess::catalog::BtreeRecord> records;
        Check(ReadAppleVolumeFileSystemRecords(source, cp.container, volume, records, error), error);
        for (const auto& record : records)
            result.filesystem[volume.superblock.object_id].emplace_back(record.key, record.value);
        Bytes bytes; Check(source.Read(volume.superblock_object.physical_block * 4096, 4096, bytes), "read independently retained APSB");
        result.apsbs[volume.superblock.object_id] = std::move(bytes);
    }
    std::vector<std::uint64_t> metadata; std::vector<ApplePhysicalExtentRecord> payload;
    Check(LoadAppleSnapshotCheckpointOwners(source, cp, metadata, payload, error) && !metadata.empty(), error);
    for (const auto& extent : payload) {
        Bytes bytes; Check(source.Read(extent.physical_block * 4096, static_cast<std::size_t>(extent.block_count * 4096), bytes), "read every owned payload extent");
        result.payload[{extent.physical_block, extent.block_count}] = fe::Hash(bytes);
    }
    Check(result.filesystem.size() == 2 && result.payload.size() >= 2, "two populated independent sibling payload graphs");
    return result;
}
void CheckIntegrity(const VolumeImageRequest& request, const Integrity& expected, bool apsbs = true)
{
    Target source(request.image); const auto actual = CaptureIntegrity(source);
    Check(actual.filesystem == expected.filesystem && actual.payload == expected.payload &&
        (!apsbs || actual.apsbs == expected.apsbs), "all sibling metadata records and SHA256 payload preimages preserved");
    const auto cp = mc::Load(source);
    Check(cp.container.superblock.block_count == NewBlocks && cp.spaceman.devices[0].chunk_count == 65 &&
        cp.spaceman.chunks.back().block_count == NewBlocks % mc::ChunkBlocks,
        "fresh canonical geometry and partial-tail CIB length");
    Check(std::all_of(cp.spaceman.bytes.begin() + 0x158, cp.spaceman.bytes.begin() + 0x9d8,
        [](auto b) { return b == std::byte{}; }), "exact physical zero publication including IDs histories indices and reserved bytes");
}
void FreeNativeFile(Target& target, const apfsaccess::catalog::BtreeRecord& original_root)
{
    const auto cp = mc::Load(target); AppleVolumeTransactionRequest request;
    request.volume_object_id = cp.volumes.front().superblock.object_id; request.file_count_delta = -1;
    std::vector<apfsaccess::catalog::BtreeRecord> records; std::string error;
    Check(ReadAppleVolumeFileSystemRecords(target, cp.container, cp.volumes.front(), records, error), error);
    for (auto record : records) {
        const auto key = ReadU64LE(record.key, 0).value(), type = key >> 60, oid = key & ((1ull << 60) - 1);
        if (type == 8 && oid == 1030) {
            AppleFileExtentRecord extent; Check(DecodeAppleFileExtentRecord(record, 4096, extent, error), error);
            request.released_data_blocks.push_back({extent.physical_block, extent.length_bytes / 4096});
        }
        if (oid == 1030 || (type == 9 && ReadU64LE(record.value, 0) == 1030)) continue;
        if (type == 3 && oid == 2) {
            Check(record.key == original_root.key, "restore the exact original root inode key");
            record = original_root;
        }
        request.filesystem_records.push_back(std::move(record));
    }
    Check(!request.released_data_blocks.empty(), "native free uses the exact relinquished stream mappings");
    AppleVolumeTransactionPlan plan;
    Check(PlanAppleVolumeTransaction(target, cp, request, plan, error), "real native release plan: " + error);
    Check(!plan.allocation.deferred_frees.empty(), "native release preserves deferred retirement rather than clearing retained owners");
    Check(ExecuteAppleCheckpointPublication(target, plan.commit.publication, error), "real native release publication: " + error);
    mc::Verify(target, mc::Load(target));
}
void PositiveReset()
{
    auto request = ResetImage("positive"); Integrity expected; apfsaccess::catalog::BtreeRecord original_root;
    { Target target(request.image); expected = CaptureIntegrity(target);
      for (const auto& [key, value] : expected.filesystem.at(request.volume_oid))
          if (ReadU64LE(key, 0) == ((3ull << 60) | 2)) { original_root.key = key; original_root.value = value; }
      Check(!original_root.key.empty(), "complete original root inode captured before allocation"); }
    std::map<std::uint64_t, Bytes> wals;
    for (const auto& [oid, path] : request.sibling_wals) wals[oid] = Read(path);
    const auto prepared = PrepareVolumeResize(request);
    Check(prepared.outcome == VolumeImageOutcome::Prepared, "populated finite shrink must prepare: " + prepared.error);
    Storage("prepared"); Check(std::filesystem::file_size(prepared.journal) < (16ull << 20), "actual bounded serialized keeper evidence");
    const auto applied = ApplyVolumeResize(request, prepared.token, [](auto) { Storage("publication"); return true; });
    Check(applied.outcome == VolumeImageOutcome::Committed, "actual populated finite shrink commits: " + applied.error);
    Check(std::filesystem::file_size(request.image) == request.target_bytes && request.target_bytes < request.expected_bytes,
        "actual strict EOF reduction");
    Check(RecoverVolumeResize(request).outcome == VolumeImageOutcome::Committed, "fresh keeper recovery after reset");
    CheckIntegrity(request, expected);
    { Target target(request.image); auto history = AcquireVolumeKeeperHistory(prepared.source_identity, target, request.journal_directory, {});
      mc::NativeWrite(target); }
    { Target target(request.image); auto history = AcquireVolumeKeeperHistory(prepared.source_identity, target, request.journal_directory, {});
      FreeNativeFile(target, original_root); }
    Check(RecoverVolumeResize(request).outcome == VolumeImageOutcome::Committed, "fresh reopen after real native allocation and free");
    CheckIntegrity(request, expected, false);
    for (const auto& [oid, path] : request.sibling_wals) Check(Read(path) == wals.at(oid), "nonempty prior aborted WAL bytes remain unchanged");
    Storage("positive-complete"); Pass("populated reset strict shrink sibling integrity native allocation free and fresh reopen");
}
void ResetCuts()
{
    const std::vector<std::string> stages{"after-image-accept", "before-apple-checkpoint-switch", "before-image-anchor",
        "after-image-anchor", "after-image-truncate"};
    for (std::size_t i = 0; i < stages.size(); ++i) {
        auto request = ResetImage("cut-" + std::to_string(i)); Integrity expected;
        { Target target(request.image); expected = CaptureIntegrity(target); }
        const auto prepared = PrepareVolumeResize(request); Check(prepared.outcome == VolumeImageOutcome::Prepared, prepared.error);
        bool hit = false;
        const auto cut = ApplyVolumeResize(request, prepared.token, [&](auto stage) {
            Storage("cut-publication"); if (stage == stages[i]) { hit = true; return false; } return true; });
        Check(hit && cut.outcome == VolumeImageOutcome::RecoveryRequired, "actual populated reset interruption: " + cut.error);
        Check(RecoverVolumeResize(request).outcome == VolumeImageOutcome::Committed, "forward reset publication/truncation recovery");
        CheckIntegrity(request, expected); Storage("cut-recovered");
    }
    Pass("accepted publication anchor and truncation interruptions preserve owners and recover forward");
}
void ResetControls()
{
    auto source = ResetSource(); const auto original = mc::Load(source).spaceman;
    for (unsigned variant = 0; variant < 11; ++variant) {
        auto sm = original; auto target = NewBlocks;
        if (variant == 0) vi::Put(sm.bytes, 0x158 + 0x82, 7, 2);
        if (variant == 1) vi::Put(sm.bytes, 0x158 + 0x80, 5, 2);
        if (variant == 2) vi::Put(sm.bytes, 0x158 + 0x84, 1, 4);
        if (variant == 3) sm.bytes[0x158 + 4 * 0x88] = std::byte{1};
        if (variant == 4) sm.bytes[0x158 + 8 * 0x88] = std::byte{1};
        if (variant == 5) { vi::Put(sm.bytes, 0x158 + 16, 4 * mc::ChunkBlocks);
            vi::Put(sm.bytes, 0x158 + 24, 5 * mc::ChunkBlocks); }
        if (variant == 6) vi::Put(sm.bytes, 0x158, 4 * mc::ChunkBlocks + 1);
        if (variant == 7) sm.structure_size = 4096;
        if (variant == 8) sm.version = 2;
        if (variant == 9) target = 63 * mc::ChunkBlocks + 12;
        if (variant == 10) target = 64 * mc::ChunkBlocks;
        const auto before = sm.bytes; std::string denied;
        try { vi::ValidateResizeAllocationZones(sm, target); } catch (const std::exception& e) { denied = e.what(); }
        Check(!denied.empty() && sm.bytes == before, "opaque/index7/ID/reserved/alias/geometry controls refuse without rewriting input");
        if (variant == 5) {
            for (unsigned slot = 0; slot < 4; ++slot) for (unsigned pair = 0; pair < 8; ++pair) {
                const auto at = 0x158 + slot * 0x88 + pair * 16;
                const auto begin = ReadU64LE(sm.bytes, at).value(), end = ReadU64LE(sm.bytes, at + 8).value();
                Check(begin % mc::ChunkBlocks == 0 && begin >= 4 * mc::ChunkBlocks &&
                    end == begin + mc::ChunkBlocks && end < NewBlocks, "duplicate control retains every canonical full-pair boundary");
            }
            Check(denied == "VolumeResizeZoneResetBoundaryUnsupported", "valid full duplicate pair isolates reset distinctness guard");
        }
    }
    for (unsigned index = 0; index < 7; ++index) {
        auto sm = original;
        for (unsigned slot = 0; slot < 4; ++slot) vi::Put(sm.bytes, 0x158 + slot * 0x88 + 0x82, index, 2);
        const auto before = sm.bytes; vi::ValidateResizeAllocationZones(sm, NewBlocks);
        Check(sm.bytes == before, "each legitimate zero-based history ring position is admitted read-only");
    }
    ZoneBoundaries(); Pass("finite reset predicate refuses all unadmitted profiles and retains legacy grow controls");
}
void LegacyGrowReplay(bool produce)
{
    const auto policy = ZonePolicy();
    auto request = Request(root / "legacy-grow", VolumeImageOperation::Grow, Fixture());
    request.expected_bytes = Source().SizeBytes(); request.target_bytes = (5 * mc::ChunkBlocks - 13) * 4096;
    if (produce) {
        request = ZonedImage("legacy-grow", VolumeImageOperation::Grow, policy);
        const auto prepared = PrepareVolumeResize(request); Check(prepared.outcome == VolumeImageOutcome::Prepared, prepared.error);
        bool accepted = false;
        const auto cut = ApplyVolumeResize(request, prepared.token, [&](auto stage) {
            if (stage == "after-image-accept") { accepted = true; return false; } return true;
        });
        Check(accepted && cut.outcome == VolumeImageOutcome::RecoveryRequired, "original engine persisted an actually accepted grow journal");
        Check(ReadU16LE(policy, 130) == 2, "unchanged baseline fixture uses next-write slot two");
        Pass("original-100-object engine accepted grow journal for cross-build recovery"); return;
    }
    Integrity expected; { Target target(request.image); expected = CaptureIntegrity(target); ExactPolicy(target, policy); }
    const auto result = RecoverVolumeResize(request);
    Check(result.outcome == VolumeImageOutcome::Committed, "accepted pre-change grow journal replay: " + result.error);
    { Target target(request.image); const auto actual = CaptureIntegrity(target);
      Check(actual.filesystem == expected.filesystem && actual.payload == expected.payload && actual.apsbs == expected.apsbs,
          "cross-build grow replay retains all exact filesystem records and sibling payload hashes");
      ExactPolicy(target, policy); }
    Check(std::filesystem::file_size(request.image) == request.target_bytes, "legacy grow recovered the actual target EOF");
    Pass("accepted pre-change grow journal reconstructs and recovers under candidate validator");
}
std::uint64_t NativeTailAllocation(Target& target, std::uint64_t release = 0)
{
    const auto cp = mc::Load(target); AppleSpacemanAllocationRequest request;
    request.expected_checkpoint_xid = cp.container.superblock.xid; request.transaction_xid = cp.container.superblock.next_xid;
    request.oldest_required_checkpoint_xid = 1; request.first_ephemeral_object_id = cp.container.superblock.next_oid;
    request.main_block_count = release ? 0 : 1; request.search_from_end = true;
    if (release) request.released_blocks.push_back({release, 1});
    for (const auto& bitmap : cp.spaceman.internal_pool.active_bitmaps)
        request.protected_internal_pool_bitmap_indices.push_back(bitmap.rotation_index);
    AppleTransactionCommitRequest commit; std::string error;
    Check(PlanAppleSpacemanAllocation(cp.spaceman, request, commit.allocation_plan, error), "native tail allocation/release plan: " + error);
    const auto block = release ? release : commit.allocation_plan.allocated_main_blocks.at(0);
    Check(block >= NewBlocks && block < OldBlocks, "native allocator selected a block in the actual truncated tail");
    if (!release) commit.allocated_main_writes.push_back({block, Bytes(4096, std::byte{0x71})});
    else Check(std::any_of(commit.allocation_plan.deferred_frees.begin(), commit.allocation_plan.deferred_frees.end(),
        [&](const auto& free) { return free.physical_block <= block && block - free.physical_block < free.block_count; }),
        "native release records an actual deferred tail retirement");
    commit.next_object_id = cp.container.superblock.next_oid;
    AppleTransactionCommitPlan plan;
    Check(PlanAppleTransactionCommit(target, cp, commit, plan, error), "native tail publication plan: " + error);
    Check(ExecuteAppleCheckpointPublication(target, plan.publication, error), "native tail publication: " + error);
    mc::Verify(target, mc::Load(target)); return block;
}
void OwnTailPayload(Target& target, std::uint64_t tail)
{
    const auto cp = mc::Load(target); const auto& volume = cp.volumes.front(); std::string error;
    std::vector<apfsaccess::catalog::BtreeRecord> records; std::uint64_t original = 0; unsigned changed = 0;
    Check(ReadAppleVolumeFileSystemRecords(target, cp.container, volume, records, error), error);
    for (auto& record : records) {
        AppleFileExtentRecord extent;
        if (!DecodeAppleFileExtentRecord(record, 4096, extent, error)) continue;
        Check(extent.object_id == 30 && extent.length_bytes == 4096, "one known complete retained payload mapping");
        original = extent.physical_block; extent.physical_block = tail;
        Check(EncodeAppleFileExtentRecord(extent, record, error), error); ++changed;
    }
    Check(changed == 1 && volume.extentref_tree.has_value(), "exactly one selected-volume file extent moves to the allocated tail");
    const auto serialize = [&](std::vector<apfsaccess::catalog::BtreeRecord> input, const AppleObjectLocation& location,
        AppleBtreeKeyOrder order) {
        Check(SortAppleBtreeRecords(input, order, error), error); AppleBtreeOptions options;
        options.block_size = 4096; options.root_object_id = location.object_id; options.root_physical_block = location.physical_block;
        options.xid = location.xid; options.subtype = location.subtype; options.storage_type = location.type & kObjectStorageTypeMask;
        options.key_order = order; options.max_nodes = 1;
        options.tree_flags = options.storage_type == kObjectPhysical ? kAppleBtreePhysical : 0;
        AppleSerializedBtree tree; Check(SerializeAppleBtree(input, options, tree, error) && tree.objects.size() == 1, error);
        Check(target.WriteBlock(location.physical_block, tree.objects.front().bytes), "canonical owned-tail fixture leaf");
    };
    serialize(records, volume.root_tree, volume.superblock.incompatible_features & kIncompatCaseInsensitive ?
        AppleBtreeKeyOrder::FileSystemHashedDirectory : AppleBtreeKeyOrder::FileSystemCaseSensitive);
    records.clear(); Check(ReadBtreeLeafRecords(target, 4096, volume.extentref_tree->physical_block, true, 0,
        volume.superblock.xid, records, error), error); changed = 0;
    for (auto& record : records) {
        ApplePhysicalExtentRecord extent; Check(DecodeApplePhysicalExtentRecord(record, extent, error), error);
        if (extent.physical_block != original) continue;
        Check(extent.block_count == 1, "exact one-block extent-reference preimage"); extent.physical_block = tail;
        Check(EncodeApplePhysicalExtentRecord(extent, record, error), error); ++changed;
    }
    Check(changed == 1, "exact corresponding extent-reference owner moves with the file mapping");
    serialize(records, *volume.extentref_tree, AppleBtreeKeyOrder::PhysicalExtent);
    Bytes payload; Check(target.Read(original * 4096, 4096, payload) && target.WriteBlock(tail, payload) && target.Flush(),
        "actual original payload copied into its allocated owned tail block");
    mc::Verify(target, mc::Load(target));
    const auto actual = CaptureIntegrity(target);
    Check(actual.payload.contains({tail, 1}), "independent typed owner census reaches the actual tail payload");
}
void TailRefusals()
{
    for (unsigned variant = 0; variant < 3; ++variant) {
        auto request = ResetImage("tail-" + std::to_string(variant));
        { Target target(request.image); const auto tail = NativeTailAllocation(target);
          if (variant == 1) OwnTailPayload(target, tail);
          if (variant == 2) NativeTailAllocation(target, tail);
          const auto cp = mc::Load(target); request.checkpoint_xid = cp.container.superblock.xid;
          vi::ValidateResizeAllocationZones(cp.spaceman, NewBlocks);
          Check(vi::Bit(cp.spaceman.chunks.back().allocation_bitmap, tail - cp.spaceman.chunks.back().start_block),
              "tail control has an actual persisted allocated bit");
          if (variant == 2) Check(std::any_of(cp.spaceman.free_queues.begin(), cp.spaceman.free_queues.end(), [&](const auto& queue) {
              return std::any_of(queue.entries.begin(), queue.entries.end(), [&](const auto& entry) {
                  return entry.physical_block <= tail && tail - entry.physical_block < entry.block_count;
              }); }), "fresh parsed spaceman contains the actual retired-tail queue entry");
          const auto inventory = vi::InspectResizeRelocationSource(target, request);
          const auto found = std::find_if(inventory.blocks.begin(), inventory.blocks.end(),
              [&](const auto& entry) { return entry.physical_block == tail; });
          const auto role = variant == 0 ? vi::ResizeTailRole::Unknown :
              variant == 1 ? vi::ResizeTailRole::Payload : vi::ResizeTailRole::Queued;
          Check(found != inventory.blocks.end() && found->roles == static_cast<std::uint32_t>(role),
              "independent inventory isolates allocated-unattributed, owned-payload or retired-queued tail");
          std::string direct_error;
          try { (void)vi::BuildResizePublication(target, request, cp); }
          catch (const std::exception& error) { direct_error = error.what(); }
          Check(direct_error == "VolumeResizeAllocatedTailRequiresRelocation", "ordinary publication cannot truncate any actually allocated tail"); }
        const auto before = Digests(request.image); std::map<std::uint64_t, Bytes> wals;
        for (const auto& [oid, path] : request.sibling_wals) wals[oid] = Read(path);
        const auto denied = PrepareVolumeResize(request);
        std::cout << "TAIL variant=" << variant << " error=" << denied.error << std::endl;
        const auto expected_error = variant == 0 ? "VolumeResizeRelocationUnknownTailOwner" : "VolumeResizeAllocationZoneResetMissing";
        Check(denied.outcome == VolumeImageOutcome::Refused && denied.token.empty() && denied.error == expected_error && Digests(request.image) == before,
            "actual allocated/owned/retired populated-tail shrink refuses with the original image intact: " + denied.error);
        for (const auto& [oid, path] : request.sibling_wals) Check(Read(path) == wals.at(oid), "tail refusal retains every original WAL byte");
        Storage("tail-refused");
    }
    Pass("persisted populated-profile allocated owned and retired tails refuse before acceptance");
}
void AcceptedWalControl()
{
    auto request = ResetImage("accepted-wal", true);
    const auto path = request.sibling_wals.at(request.volume_oid);
    const auto identity = "apfs-vol:" + request.container_uuid + ":" + std::to_string(request.volume_oid);
    std::vector<TransactionManager::AcceptedTransaction> pending;
    TransactionManager::DurabilityWatermarks marks{}; std::string error;
    Check(TransactionManager::InspectAcceptedTransactionsReadOnly(path, identity, pending, marks, error) &&
        pending.size() == 1 && marks.accepted_sequence > marks.cleanup_sequence, "actual accepted preimage debt exists: " + error);
    const auto wal = Read(path);
    const auto image = Digests(request.image);
    const auto prepared = PrepareVolumeResize(request);
    Check(prepared.outcome == VolumeImageOutcome::Refused && prepared.token.empty() &&
        Read(path) == wal && Digests(request.image) == image, "pending accepted WAL vetoes reset without acknowledgment or image mutation");
    std::vector<TransactionManager::AcceptedTransaction> after; TransactionManager::DurabilityWatermarks final_marks{};
    Check(TransactionManager::InspectAcceptedTransactionsReadOnly(path, identity, after, final_marks, error) &&
        after.size() == pending.size() && final_marks.accepted_sequence == marks.accepted_sequence &&
        final_marks.cleanup_sequence == marks.cleanup_sequence, "accepted work remains pending at the original watermark");
    Storage("accepted-wal-refused"); Pass("real accepted WAL debt remains intact and cannot be acknowledged to enable reset");
}
class ReadOnlySavedSource final : public RandomAccessSource
{
public:
    explicit ReadOnlySavedSource(const std::filesystem::path& path) : size_(std::filesystem::file_size(path)),
        file_(FixtureIoPath(path), std::ios::binary) { Check(file_.good(), "open saved failed evidence read-only"); }
    std::uint64_t SizeBytes() const override { return size_; }
    bool Read(std::uint64_t offset, std::size_t count, Bytes& bytes) const override {
        bytes.clear(); if (offset > size_ || count > size_ - offset) return false;
        file_.clear(); file_.seekg(static_cast<std::streamoff>(offset)); bytes.resize(count);
        file_.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(count));
        if (file_.good()) return true; bytes.clear(); return false;
    }
private:
    std::uint64_t size_; mutable std::ifstream file_;
};
void RecordLoadedGeometry(const RandomAccessSource& source, const std::string& name)
{
    const auto cp = mc::Load(source); const auto& sm = cp.spaceman;
    std::ofstream output(FixtureIoPath(root / (name + ".json")));
    output << "{\"flags\":" << sm.flags << ",\"version\":" << sm.version << ",\"structureSize\":" << sm.structure_size
        << ",\"objectSize\":" << sm.object.size_bytes << ",\"objectBlock\":" << sm.object.physical_block
        << ",\"objectXid\":" << sm.object.xid << ",\"blockSize\":" << cp.container.superblock.block_size
        << ",\"blocksPerChunk\":" << sm.blocks_per_chunk << ",\"chunksPerCib\":" << sm.chunks_per_cib
        << ",\"cibsPerCab\":" << sm.cibs_per_cab << ",\"loadedChunkCount\":" << sm.chunks.size() << ",\"devices\":[";
    for (std::size_t i = 0; i < sm.devices.size(); ++i) {
        const auto& d = sm.devices[i]; if (i) output << ',';
        output << "{\"blockCount\":" << d.block_count << ",\"chunkCount\":" << d.chunk_count
            << ",\"cibCount\":" << d.cib_count << ",\"cabCount\":" << d.cab_count << ",\"freeCount\":" << d.free_count
            << ",\"loadedCibs\":" << d.cibs.size() << ",\"loadedCabs\":" << d.cabs.size() << '}';
    }
    output << "]}\n"; Check(output.good(), "persist every actual loaded finite geometry predicate field");
}
void StorageProof()
{
    const auto saved = root.parent_path().parent_path() / "fixtures/r04-storage/storage-proof/image.apfs";
    if (std::filesystem::exists(saved)) { ReadOnlySavedSource original(saved); RecordLoadedGeometry(original, "loaded-geometry-original-r04"); }
    auto request = ResetImage("storage-proof");
    std::size_t captured = 0, destinations = 0;
    {
        Target target(request.image); RecordLoadedGeometry(target, "loaded-geometry-current");
        auto evidence = fe::Scan(target); fe::Capture capture(target, evidence);
        const auto inventory = vi::InspectResizeRelocationSource(capture, request);
        Check(!inventory.reserved_region_crosses_target && inventory.blocks.empty() &&
            !inventory.physical_snapshot_root_in_tail, "ordinary same-K route has no relocation copy");
        const auto plan = vi::BuildResizePublication(capture, request, mc::Load(capture));
        Bytes boundary; Check(capture.Read(request.target_bytes - 4096, 4096, boundary), "capture the actual keeper target-boundary preimage");
        const auto last = (request.target_bytes - 1) / fe::Chunk;
        for (const auto& [index, bytes] : evidence.chunks) {
            Check((index == 0 || index == last) && bytes.size() == fe::Chunk,
                "every actual captured chunk is first metadata or target boundary");
            captured += bytes.size();
        }
        Check(evidence.chunks.size() <= 2 && captured <= (8ull << 20) && fe::Encode(evidence).size() < (9ull << 20),
            "actual ordinary planner original evidence stays below nine MiB");
        for (const auto destination : plan.destinations)
            Check(destination < fe::Chunk / 4096, "every publication write stays in the first four MiB");
        destinations = plan.destinations.size();
    }
    Storage("storage-proof-terminal");
    std::ofstream output(FixtureIoPath(root / "storage-proof.json"));
    output << "{\"logicalSourceBytes\":" << OldBlocks * 4096 << ",\"targetBytes\":" << NewBlocks * 4096
        << ",\"allocatedImageBytes\":" << PhysicalBytes(request.image) << ",\"capturedBytes\":" << captured
        << ",\"publicationDestinations\":" << destinations << ",\"fixturePeakPhysical\":" << physical_peak << "}\n";
    Check(output.good(), "persist measured pre-keeper allocation and evidence proof");
    Pass("measured NTFS sparse ordinary-plan capture and bounded physical publication proof");
}
}
int wmain(int argc, wchar_t** argv)
{
    try {
        const auto mode = argc == 3 ? std::wstring_view(argv[2]) : L"";
        Check(argc == 2 || (argc == 3 && (mode == L"--red" || mode == L"--storage-proof" ||
            mode == L"--legacy-grow-accept" || mode == L"--legacy-grow-recover")),
            "private D fixture root and known proof/baseline selector");
        root = argv[1]; std::filesystem::create_directories(root);
        if (mode == L"--storage-proof") StorageProof();
        else if (mode == L"--legacy-grow-accept" || mode == L"--legacy-grow-recover") LegacyGrowReplay(mode == L"--legacy-grow-accept");
        else { PositiveReset(); if (argc == 2) { ResetCuts(); ResetControls(); TailRefusals(); AcceptedWalControl(); } }
        Storage("terminal"); std::cout << "PASS groups=" << groups << " checks=" << checks << " peakPhysical=" << physical_peak << std::endl;
        return 0;
    } catch (const std::exception& error) { std::cerr << "FAIL checks=" << checks << " " << error.what() << std::endl; return 1; }
}
