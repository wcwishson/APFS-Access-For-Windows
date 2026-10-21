#define wmain SparseCompatibilityHelpersMain
#include "NativeSparseCompatibilityTests.cpp"
#undef wmain

namespace
{
constexpr auto SourcePath = L"\\combined-source.bin";
constexpr auto TargetPath = L"\\combined-target.bin";
constexpr auto AliasPath = L"\\combined-linked.bin";
Bytes CombinedBytes(bool target, bool changed)
{
    Bytes bytes(32768);
    for (std::size_t i = 0; i < bytes.size(); ++i) bytes[i] = std::byte((i * 29 + 53) & 255);
    if (target) std::fill_n(bytes.begin() + 16384, 4096, std::byte{});
    if (target && changed) bytes[9] = std::byte{172};
    return bytes;
}
void CombinedExact(Owner& owner, bool changed)
{
    const auto target = owner.store->LookupCommittedInodeByPath(TargetPath);
    const auto alias = owner.store->LookupCommittedInodeByPath(AliasPath);
    Check(target && alias && target->object_id == alias->object_id && target->link_count == 2 &&
        target->logical_size == 32768 && target->allocation_size == 28672, "exact shared sparse hard-link inode/accounting");
    for (const auto path : {SourcePath, TargetPath, AliasPath}) {
        Bytes bytes;
        Check(owner.store->ReadCommittedFileRange(path, 0, 32768, bytes) &&
            bytes == CombinedBytes(path != SourcePath, changed), "complete source/alias bytes after shared sparse COW");
        Check(owner.store->ReadCommittedFileRange(path, 32768, 1, bytes) && bytes.empty(), "exact EOF after shared COW");
    }
    Source source(*owner.device); const auto cp = Load(source); NativeSparseState state; std::string error;
    Check(ReadNativeSparseStateV2(source, cp, owner.context.volume_object_id, target->object_id, state, error),
        "complete post-COW reference/allocator census: " + error);
    unsigned shared = 0, private_blocks = 0;
    for (const auto& extent : state.extents) if (extent.physical_block)
        for (std::uint64_t b = extent.physical_block; b < extent.physical_block + extent.length_bytes / 4096; ++b) {
            const auto ref = std::find_if(state.payload.begin(), state.payload.end(), [&](const auto& r) {
                return b >= r.physical_block && b - r.physical_block < r.block_count;
            });
            Check(ref != state.payload.end(), "every target block has exact physical reference coverage");
            if (ref->reference_count == 2) ++shared;
            else { Check(ref->reference_count == 1 && ref->owning_object_id == target->object_id,
                "private replacement retains exact owner"); ++private_blocks; }
        }
    Check(shared == (changed ? 6u : 7u) && private_blocks == (changed ? 1u : 0u),
        "hard-link aliases do not add stream references; only written shared block becomes private");
}
void FreshCopy(const std::filesystem::path& root, const std::filesystem::path& original)
{
    Check(!std::filesystem::exists(root) && std::filesystem::create_directories(root), "fresh private evidence directory");
    Check(std::filesystem::copy_file(original, root / "sparse.apfs"), "one bounded private copy of closed failed source");
}
Store::MutationRequest WriteRequest(Owner& owner)
{
    const auto inode = owner.store->LookupCommittedInodeByPath(AliasPath);
    Check(inode.has_value(), "exact linked write target");
    Store::MutationRequest write; write.path = AliasPath; write.object_id = inode->object_id;
    write.generation = owner.store->CheckpointXid().value() + 1; write.offset = 9; write.length = 1;
    return write;
}
void RestageWrite(Owner& owner, const WriteAheadLog::Record& record, bool interrupt)
{
    const auto before = CombinedBytes(true, false);
    auto request = WriteRequest(owner);
    Check(record.operation == WriteAheadLog::OperationKind::Write && record.path_utf8 == "\\combined-linked.bin" &&
        record.object_id == request.object_id && record.logical_offset == 9 && record.logical_length == 1 &&
        record.inline_payload == Bytes{std::byte{172}}, "exact original accepted inline write authority");
    request.generation = record.parent_object_id;
    std::uint64_t allocation = 0;
    Check(owner.store->PreflightNativeSparseMutation(request, &allocation) == Store::MutationStatus::Applied && allocation == 28672,
        "legitimate shared sparse target preflights with unchanged allocation");
    Store::PayloadIdentity identity;
    Check(owner.store->StageMutation(request, &identity) == Store::MutationStatus::Applied, "shared sparse partial write stages");
    std::uint64_t supplied = 0;
    owner.store->SetFilePayloadRangeProvider([&](const auto& path, auto current, auto offset, std::span<std::byte> bytes) {
        if ((path != AliasPath && path != TargetPath) || current.object_id != identity.object_id || current.generation != identity.generation ||
            offset != 0 || bytes.size() != 4096) return false;
        supplied += bytes.size(); std::copy_n(before.begin(), bytes.size(), bytes.begin()); bytes[9] = record.inline_payload.front(); return true;
    });
    bool cut_hit = false;
    if (interrupt) owner.store->SetCommitStageHook([&](auto stage) {
        if (stage != "before-apple-checkpoint-switch") return true;
        cut_hit = true; return false;
    });
    const auto committed = owner.store->CommitCanonicalTransaction({owner.store->CheckpointXid().value()});
    Check(committed == (interrupt ? Store::CommitStatus::PersistFailed : Store::CommitStatus::Committed),
        "bounded shared COW publication/cut: " + owner.store->LastCommitStage());
    Check((!interrupt || cut_hit) && supplied == 4096, "one-byte write borrows exactly one boundary block and reaches requested cut: " +
        std::to_string(supplied) + ":" + owner.store->LastCommitStage());
    owner.store->SetCommitStageHook({});
    owner.store->SetFilePayloadRangeProvider({});
}
void Cut(const std::filesystem::path& root, const std::filesystem::path& original, bool red)
{
    FreshCopy(root, original); Owner owner(root); CombinedExact(owner, false); auto write = WriteRequest(owner);
    if (red) {
        Check(owner.store->PreflightNativeSparseMutation(write) == Store::MutationStatus::UnsupportedOperation &&
            owner.store->PendingMutationCount() == 0, "prior source reproduces exact shared sparse preflight refusal");
        CombinedExact(owner, false); return;
    }
    TransactionManager::MutationIntent intent; intent.kind = TransactionManager::MutationKind::Write;
    intent.path = write.path; intent.object_id = write.object_id; intent.generation = write.generation;
    intent.offset = write.offset; intent.length = intent.payload_length = 1; intent.inline_payload = {std::byte{172}};
    Check(NativeHardLinkHash(intent.inline_payload, intent.payload_checksum), "exact original payload digest");
    const auto xid = owner.store->CheckpointXid().value();
    Check(owner.journal->Begin() && owner.journal->RecordMutation(intent) && owner.journal->Accept(xid), "durable original one-byte acceptance");
    std::vector<TransactionManager::AcceptedTransaction> debt; std::string error;
    Check(owner.journal->LoadAcceptedTransactionsSinceCleanup(debt, &error) && debt.size() == 1 && debt.front().mutations.size() == 1,
        "exact one accepted original transaction");
    RestageWrite(owner, debt.front().mutations.front(), true);
    Check(owner.journal->Watermarks().apfs_durable_sequence == 0 && owner.journal->Watermarks().cleanup_sequence == 0,
        "interrupted COW retains original debt");
}
void RecoverWrite(const std::filesystem::path& root)
{
    Owner owner(root); CombinedExact(owner, false); std::string error; std::vector<TransactionManager::AcceptedTransaction> debt;
    Check(owner.journal->LoadAcceptedTransactionsSinceCleanup(debt, &error) && debt.size() == 1 && debt.front().mutations.size() == 1 &&
        debt.front().preimage_checkpoint_xid == owner.store->CheckpointXid(), "fresh owner selects exact original checkpoint");
    const auto sequence = debt.front().accepted_sequence; RestageWrite(owner, debt.front().mutations.front(), false);
    Check(owner.journal->MarkApfsDurableThrough(sequence) && owner.journal->MarkCleanedThrough(sequence), "settle only verified shared COW publication");
    CombinedExact(owner, true);
}
void CorruptReferences(const std::filesystem::path& image, unsigned fault)
{
    std::string error; auto device = BlockDevice::OpenExclusiveManagementImage(image.wstring(), 0, error); Check(!!device, error);
    Source source(*device); const auto cp = Load(source); const auto& v = cp.volumes.front();
    const auto target = [&] { std::uint64_t id = 0; std::vector<Record> fs;
        Check(ReadAppleVolumeFileSystemRecords(source, cp.container, v, fs, error), error);
        for (const auto& record : fs) if (Header(record) >> 60 == 9) { AppleDirectoryRecord d;
            Check(ApfsExtendedRecordCodec::DecodeDirectory(record, ApfsNamePolicy::FromIncompatibleFeatures(v.superblock.incompatible_features), d, error), error);
            if (d.name_utf8 == "combined-target.bin") id = d.file_id; }
        Check(id != 0, "negative target identity"); return id; }();
    std::vector<Record> records; const auto& root = *v.extentref_tree;
    Check(ReadBtreeLeafRecords(source, 4096, root.physical_block, true, 0, cp.container.superblock.xid, records, error), error);
    bool changed = false; Bytes missing;
    for (auto& record : records) { ApplePhysicalExtentRecord ref; Check(DecodeApplePhysicalExtentRecord(record, ref, error), error);
        if (changed || ref.reference_count != 2) continue;
        if (fault == 0) ref.reference_count = 3;
        if (fault == 1) { ref.reference_count = 1; ref.owning_object_id = target; }
        if (fault == 2) { missing = record.key; changed = true; break; }
        if (fault == 3) { record.value.pop_back(); changed = true; break; }
        Check(EncodeApplePhysicalExtentRecord(ref, record, error), error); changed = true;
    }
    Check(changed, "real shared extent negative control changed");
    if (fault == 2) std::erase_if(records, [&](const auto& record) { return record.key == missing; });
    if (fault == 4) { Record spare; Check(EncodeApplePhysicalExtentRecord({cp.container.superblock.block_count - 1, 1,
            kApplePhysicalExtentKindNew, 999, 1}, spare, error), error); records.push_back(spare); }
    const auto order = fault == 3 ? AppleBtreeKeyOrder::Lexicographic : AppleBtreeKeyOrder::PhysicalExtent;
    Check(SortAppleBtreeRecords(records, order, error), error);
    AppleBtreeOptions options; options.block_size = 4096; options.root_object_id = root.object_id;
    options.root_physical_block = root.physical_block; options.xid = root.xid; options.storage_type = kObjectPhysical;
    options.subtype = root.subtype; options.tree_flags = kAppleBtreePhysical; options.key_order = order; options.max_nodes = 1;
    AppleSerializedBtree tree; Check(SerializeAppleBtree(records, options, tree, error) && tree.objects.size() == 1, error);
    Check(device->Write(root.physical_block * 4096, tree.objects.front().bytes) && device->Flush(), "persist only private negative-control metadata");
}
void Controls(const std::filesystem::path& root, const std::filesystem::path& original)
{
    Check(!std::filesystem::exists(root) && std::filesystem::create_directories(root), "fresh private control root");
    for (unsigned fault = 0; fault < 5; ++fault) {
        const auto dir = root / std::to_string(fault); FreshCopy(dir, original); const auto image = dir / "sparse.apfs";
        CorruptReferences(image, fault); std::string error; auto device = BlockDevice::OpenExclusiveManagementImage(image.wstring(), 0, error);
        Check(!!device, error); Bytes before; Check(device->ReadForVerification(0, static_cast<std::size_t>(device->GetGeometry().total_bytes), before), "negative exact original bytes");
        Source source(*device); const auto cp = Load(source); Store::VolumeContext context;
        context.device_path = image.wstring(); context.volume_object_id = cp.volumes.front().superblock.object_id; context.allow_legacy_scaffold_for_fixtures = false;
        Store store(context, device); const auto ready = store.PrepareNativeWritePath(); unsigned acquired = 0;
        store.SetFilePayloadRangeProvider([&](const auto&, auto, auto, auto) { ++acquired; return false; });
        if (ready) { Store::MutationRequest write; write.path = AliasPath; write.offset = 9; write.length = 1;
            Check(store.PreflightNativeSparseMutation(write) != Store::MutationStatus::Applied &&
                store.StageMutation(write) != Store::MutationStatus::Applied && store.PendingMutationCount() == 0,
                "over/under/missing/malformed/spare reference refuses before staging"); }
        Bytes after; Check(!acquired && device->ReadForVerification(0, before.size(), after) && before == after,
            "negative ownership refusal preserves every image byte and acquires no payload");
    }
}
}
int wmain(int argc, wchar_t** argv)
{
    try { Check(argc == 3 || argc == 4, "mode and D evidence root"); const std::filesystem::path root(argv[2]);
        Check(root.is_absolute() && root.wstring().starts_with(L"D:\\ApfsAccessScratch\\"), "private D evidence only");
        const std::wstring_view mode(argv[1]);
        if (mode == L"--cut" || mode == L"--red") { Check(argc == 4, "pinned closed fixture argument"); Cut(root, argv[3], mode == L"--red"); }
        else if (mode == L"--controls") { Check(argc == 4, "pinned closed fixture controls"); Controls(root, argv[3]); }
        else if (mode == L"--recover") RecoverWrite(root);
        else { Check(mode == L"--check", "known mode"); Owner owner(root); CombinedExact(owner, true); }
        std::cout << "PASS shared sparse COW checks=" << checks << '\n'; return 0;
    } catch (const std::exception& error) { std::cerr << "FAIL shared sparse COW " << checks << ' ' << error.what() << '\n'; return 1; }
}
