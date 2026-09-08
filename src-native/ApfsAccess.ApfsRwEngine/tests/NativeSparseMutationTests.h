#pragma once

// Included after the canonical fixture/snapshot helpers in ApfsCompatibilityTests.cpp.
// Test images stay on D: even if the combined test runner uses a C: TEMP directory.
struct NativeSparseImage
{
    std::filesystem::path path;
    explicit NativeSparseImage(const std::vector<std::byte>& bytes)
    {
        const auto directory = std::filesystem::path(L"D:/Temp/ApfsAccess-native-sparse");
        std::filesystem::create_directories(directory);
        path = directory / ("sparse-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) +
            "-" + std::to_string(g_temp_image_counter.fetch_add(1)) + ".img");
        std::ofstream out(path, std::ios::binary);
        out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    }
    ~NativeSparseImage() { std::error_code error; std::filesystem::remove(path, error); }
};

constexpr std::uint64_t kNativeSparseBlock = 4096;

std::vector<std::byte> BuildNativeSparseMutationImage(std::uint64_t tail, unsigned invalid = 0)
{
    using namespace apfsaccess::rw;
    BuilderStore fixture;
    fixture.authoritative_checkpoint = true;
    fixture.block_count = 1024;
    auto& volume = fixture.volumes.front();
    volume.incompat = 0;
    volume.additional_file_system_allocated_blocks = 6;
    auto& records = volume.filesystem_records;
    std::string error;
    apfsaccess::catalog::BtreeRecord encoded;
    AppleInodeRecord root;
    root.object_id = root.private_id = root.parent_id = 2;
    root.mode = 0040755; root.children_or_links = invalid == 4 ? 2 : 1;
    if (!Require(EncodeAppleInodeRecord(root, encoded, error), "sparse root encodes")) return {};
    records.push_back(encoded);
    AppleInodeRecord file;
    file.object_id = file.private_id = 17; file.parent_id = 2;
    file.mode = 0100640; file.owner = 501; file.group = 20; file.children_or_links = 1;
    AppleExtendedField stream;
    stream.type = 8; stream.data.resize(40);
    PutU64LE(stream.data, 0, tail + 3 * kNativeSparseBlock);
    PutU64LE(stream.data, 8, 6 * kNativeSparseBlock);
    file.extended_fields.push_back(stream);
    if (!Require(EncodeAppleInodeRecord(file, encoded, error), "sparse inode encodes")) return {};
    records.push_back(encoded);
    AppleDirectoryRecord link;
    link.parent_id = 2; link.file_id = 17; link.flags = 8; link.name_utf8 = "original";
    if (!Require(EncodeAppleDirectoryRecord(link, encoded, error), "sparse link encodes")) return {};
    records.push_back(encoded);
    if (!Require(EncodeAppleDataStreamIdRecord({17, 1}, encoded, error), "sparse stream encodes")) return {};
    records.push_back(encoded);
    for (const auto& attribute : {AppleXattrRecord{17, "user.preserved", kAppleXattrDataEmbedded,
        {std::byte{0}, std::byte{0xff}, std::byte{0x43}}},
        AppleXattrRecord{17, "com.apple.FinderInfo", kAppleXattrDataEmbedded, std::vector<std::byte>(32)}})
    {
        if (!Require(EncodeAppleXattrRecord(attribute, encoded, error), "sparse xattr encodes")) return {};
        records.push_back(encoded);
    }
    AppleSecurityRecord security;
    AppleSecurityAce ace;
    ace.flags = 1; ace.rights = 2;
    if (!Require(ApfsExtendedRecordCodec::EncodeSecurityPrincipal({ApplePrincipalKind::Uid, 501}, ace.applicable, error),
            "sparse ACL principal encodes")) return {};
    security.entries.push_back(ace);
    AppleXattrRecord acl{17, "com.apple.system.Security", kAppleXattrDataEmbedded, {}};
    if (!Require(ApfsExtendedRecordCodec::EncodeSecurity(security, acl.data, error) &&
            EncodeAppleXattrRecord(acl, encoded, error), "sparse native ACL encodes")) return {};
    records.push_back(encoded);
    for (const auto& extent : {AppleFileExtentRecord{17, 0, 3 * kNativeSparseBlock, 100, 0, 4096},
        AppleFileExtentRecord{17, 3 * kNativeSparseBlock, tail - 3 * kNativeSparseBlock, 0, 0, 4096},
        AppleFileExtentRecord{17, tail, 3 * kNativeSparseBlock, 110, 0, 4096}})
    {
        if (!Require(EncodeAppleFileExtentRecord(extent, encoded, error), "sparse extent encodes")) return {};
        if (invalid == 1 && extent.physical_block == 110) PutU64LE(encoded.key, 8, 2 * kNativeSparseBlock);
        if (invalid == 2 && extent.physical_block == 110) PutU64LE(encoded.key, 8, UINT64_MAX - 4095);
        records.push_back(encoded);
    }
    for (const auto block : {100ULL, 110ULL})
    {
        ApplePhysicalExtentRecord reference;
        reference.physical_block = block; reference.block_count = 3;
        reference.kind = kApplePhysicalExtentKindNew;
        reference.owning_object_id = invalid == 3 ? 18 : 17; reference.reference_count = 1;
        if (!Require(EncodeApplePhysicalExtentRecord(reference, encoded, error), "sparse reference encodes")) return {};
        volume.extentref_records.push_back(encoded);
        for (std::uint64_t i = 0; i < 3; ++i)
            fixture.authoritative_seeded_main_blocks.push_back({block + i,
                std::vector<std::byte>(4096, block == 100 ? std::byte{0x31} : std::byte{0xa7})});
    }
    if (invalid == 4)
    {
        file.object_id = file.private_id = 18;
        if (!Require(EncodeAppleInodeRecord(file, encoded, error), "shared sparse inode encodes")) return {};
        records.push_back(encoded);
        link.file_id = 18; link.name_utf8 = "shared";
        if (!Require(EncodeAppleDirectoryRecord(link, encoded, error), "shared sparse link encodes")) return {};
        records.push_back(encoded);
        if (!Require(EncodeAppleDataStreamIdRecord({18, 1}, encoded, error), "shared stream encodes")) return {};
        records.push_back(encoded);
        const auto copy = records;
        for (const auto& record : copy)
        {
            AppleFileExtentRecord extent;
            if (!DecodeAppleFileExtentRecord(record, 4096, extent, error)) continue;
            extent.object_id = 18;
            if (!Require(EncodeAppleFileExtentRecord(extent, encoded, error), "shared extent encodes")) return {};
            records.push_back(encoded);
        }
        for (auto& record : volume.extentref_records)
        {
            ApplePhysicalExtentRecord ref;
            if (!DecodeApplePhysicalExtentRecord(record, ref, error)) return {};
            ref.reference_count = 2;
            if (!EncodeApplePhysicalExtentRecord(ref, record, error)) return {};
        }
    }
    return BuildStoreImage(fixture);
}

bool TestNativeSparseMutation(bool huge = false, const std::string& stop = {})
{
    using namespace apfsaccess::rw;
    const std::uint64_t tail = huge ? 1ULL << 40 : 64ULL * 1024 * 1024;
    const auto fixture = BuildNativeSparseMutationImage(tail);
    if (!Require(!fixture.empty(), "sparse fixture built")) return false;
    NativeSparseImage image(fixture);
    MetadataStore::VolumeContext context;
    context.device_path = image.path.wstring(); context.volume_object_id = 101;
    context.allow_legacy_scaffold_for_fixtures = false;
    MetadataStore metadata(context);
    if (!Require(metadata.PrepareNativeWritePath() && metadata.VerifyIntegrity(), "sparse fixture prepares and verifies")) return false;
    const auto original = metadata.LookupCommittedInodeByPath(L"\\original");
    if (!Require(original && original->logical_size == tail + 12288 && original->allocation_size == 24576,
            "sparse fixture EOF and allocation verified")) return false;
    const auto original_acl = metadata.LookupCommittedExtendedAttribute(17, "com.apple.system.Security");
    if (!Require(original_acl.has_value(), "sparse fixture ACL present")) return false;
    OrdinaryCowSnapshot before;
    if (!ReadOrdinaryCowSnapshot(image.path, before) || !Require(before.extents.size() == 3 && before.references.size() == 2,
            "sparse fixture has two physical runs around one hole")) return false;
    struct Edit { std::uint64_t offset, length; std::byte value; };
    std::vector<Edit> edits;
    const auto expected = [&](std::uint64_t at, bool changed) {
        auto value = at < 12288 ? std::byte{0x31} : at >= tail ? std::byte{0xa7} : std::byte{0};
        if (changed) for (const auto& edit : edits)
            if (at >= edit.offset && at - edit.offset < edit.length) value = edit.value;
        return value;
    };
    std::uint64_t supplied = 0;
    MetadataStore::PayloadIdentity identity;
    metadata.SetFilePayloadRangeProvider([&](const auto& path, auto owner, auto offset, std::span<std::byte> bytes) {
        if (!Require(path == L"\\original" && owner.object_id == identity.object_id && owner.generation == identity.generation &&
                bytes.size() <= 1024 * 1024 && offset % 4096 == 0, "sparse bounded provider identity")) return false;
        supplied += bytes.size();
        for (std::size_t i = 0; i < bytes.size(); ++i) bytes[i] = expected(offset + i, true);
        return true;
    });
    const auto write = [&](Edit edit) {
        MetadataStore::MutationRequest request;
        request.path = L"\\original"; request.offset = edit.offset; request.length = edit.length;
        if (!Require(metadata.StageMutation(request, &identity) == MetadataStore::MutationStatus::Applied,
                "sparse write stages")) return false;
        edits.push_back(edit);
        return Require(metadata.PendingAllocationCount() == 0, "sparse staging reserves no EOF scratch buffer");
    };
    for (const auto& edit : {Edit{17, 9, std::byte{0x51}}, Edit{12281, 29, std::byte{0x52}},
        Edit{tail / 2 + 4093, 9, std::byte{0x53}}, Edit{19, 3, std::byte{0x54}}, Edit{tail - 5, 12, std::byte{0x55}}})
        if (!write(edit)) return false;
    const auto working = metadata.LookupWorkingInodeByPath(L"\\original");
    if (!Require(working && working->allocation_size == 10 * 4096 && working->owner == 501 && working->group == 20 &&
            working->mode == 0100640, "sparse pending allocation is union of physical blocks")) return false;
    if (!stop.empty()) metadata.SetCommitStageHook([&](auto stage) { return stage != stop; });
    const auto committed = metadata.CommitCanonicalTransaction({before.xid});
    if (!Require(committed == (stop.empty() ? MetadataStore::CommitStatus::Committed : MetadataStore::CommitStatus::PersistFailed),
            "sparse commit/publication status: " + metadata.LastCommitStage())) return false;
    if (!Require(supplied == 7 * 4096, "sparse provider acquires exactly seven affected blocks")) return false;
    const bool published = stop.empty() || stop == "after-apple-publish";
    MetadataStore fresh(context);
    if (!Require(fresh.PrepareNativeWritePath() && fresh.VerifyIntegrity(), "sparse canonical reopen verifies")) return false;
    const auto inode = fresh.LookupCommittedInodeByPath(L"\\original");
    if (!Require(inode && inode->owner == original->owner && inode->group == original->group && inode->mode == original->mode &&
            inode->logical_size == original->logical_size && inode->allocation_size == (published ? 40960 : 24576),
            "sparse Mac identity, EOF and actual allocation survive reopen")) return false;
    const auto retained_acl = fresh.LookupCommittedExtendedAttribute(17, "com.apple.system.Security");
    if (!Require(retained_acl && retained_acl->flags == original_acl->flags && retained_acl->data == original_acl->data,
            "sparse native ACL remains byte-identical")) return false;
    const auto attribute = fresh.LookupCommittedExtendedAttribute(17, "user.preserved");
    if (!Require(attribute && attribute->data == std::vector<std::byte>{std::byte{0}, std::byte{0xff}, std::byte{0x43}},
            "sparse binary xattr survives")) return false;
    for (const auto offset : {0ULL, 8192ULL, 12288ULL, tail / 2, tail / 2 + 4096, tail - 4096, tail, tail + 4096})
    {
        std::vector<std::byte> bytes;
        if (!Require(fresh.ReadCommittedFileRange(L"\\original", offset, 4096, bytes) && bytes.size() == 4096,
                "sparse bounded read succeeds")) return false;
        for (std::size_t i = 0; i < bytes.size(); ++i)
            if (!Require(bytes[i] == expected(offset + i, published), "sparse exact bytes/zeros after reopen")) return false;
    }
    OrdinaryCowSnapshot after;
    if (!ReadOrdinaryCowSnapshot(image.path, after)) return false;
    std::uint64_t physical = 0, hole = 0, end = 0;
    for (const auto& [offset, record] : after.extents)
    {
        AppleFileExtentRecord extent; std::string error;
        if (!Require(DecodeAppleFileExtentRecord(record, 4096, extent, error) && offset == end,
                "sparse raw extents ordered and contiguous including holes")) return false;
        end += extent.length_bytes;
        if (extent.physical_block) physical += extent.length_bytes; else hole += extent.length_bytes;
        if (offset <= 4096 && offset + extent.length_bytes > 4096)
            if (!Require(extent.physical_block + (4096 - offset) / 4096 == 101, "untouched left block retained")) return false;
        if (offset <= tail + 4096 && offset + extent.length_bytes > tail + 4096)
            if (!Require(extent.physical_block + (tail + 4096 - offset) / 4096 == 111, "untouched right block retained")) return false;
    }
    std::uint64_t references = 0;
    for (const auto& [block, record] : after.references)
    {
        ApplePhysicalExtentRecord reference; std::string error;
        if (!Require(block != 0 && DecodeApplePhysicalExtentRecord(record, reference, error) && reference.reference_count == 1 &&
                reference.owning_object_id == 17, "sparse physical references have exclusive owner")) return false;
        references += reference.block_count * 4096;
    }
    if (!Require(physical == *inode->allocation_size && references == physical && physical + hole == inode->logical_size,
            "sparse raw allocation and extentref accounting agree")) return false;
    if (!stop.empty())
        return Require(after.xid == before.xid + (published ? 1 : 0) && metadata.IsRecoveryRequired(),
            "sparse interruption exposes old or new canonical checkpoint and retains recovery ownership");
    // A second transaction rewriting an already allocated former hole must not increase allocation.
    MetadataStore::MutationRequest repeat;
    repeat.path = L"\\original"; repeat.offset = tail / 2 + 4095; repeat.length = 2;
    MetadataStore::PayloadIdentity next_identity;
    fresh.SetFilePayloadRangeProvider([&](const auto&, auto owner, auto offset, std::span<std::byte> bytes) {
        if (owner.object_id != next_identity.object_id || owner.generation != next_identity.generation) return false;
        for (std::size_t i = 0; i < bytes.size(); ++i)
            bytes[i] = offset + i >= repeat.offset && offset + i < repeat.offset + repeat.length ? std::byte{0x66} : expected(offset + i, true);
        return true;
    });
    if (!Require(fresh.StageMutation(repeat, &next_identity) == MetadataStore::MutationStatus::Applied &&
            fresh.CommitPendingMutations() == MetadataStore::CommitStatus::Committed, "sparse second transaction commits")) return false;
    MetadataStore final(context);
    if (!Require(final.PrepareNativeWritePath(), "sparse second transaction reopens")) return false;
    const auto final_inode = final.LookupCommittedInodeByPath(L"\\original");
    std::vector<std::byte> repeated;
    const auto repeated_read = final.ReadCommittedFileRange(repeat.path, repeat.offset, 2, repeated);
    if (!Require(final_inode && final_inode->allocation_size == 40960 &&
            repeated_read && repeated == std::vector<std::byte>(2, std::byte{0x66}),
            "sparse repeated write preserves allocation and exact bytes")) return false;
    repeat.operation = MetadataStore::MutationOperation::SetFileSize; repeat.offset = 0; repeat.length = tail;
    if (!Require(final.PreflightNativeSparseMutation(repeat) == MetadataStore::MutationStatus::Applied &&
            final.StageMutation(repeat) == MetadataStore::MutationStatus::Applied &&
            final.CommitPendingMutations() == MetadataStore::CommitStatus::Committed,
            "sparse shrink commits without payload materialization")) return false;
    MetadataStore shrunk(context);
    if (!Require(shrunk.PrepareNativeWritePath(), "sparse shrink reopens")) return false;
    const auto smaller = shrunk.LookupCommittedInodeByPath(repeat.path);
    return Require(smaller && smaller->logical_size == tail && smaller->allocation_size == 7 * 4096,
        "sparse shrink releases only removed tail blocks");
}

bool TestNativeSparseInvalidRecords()
{
    using namespace apfsaccess::rw;
    for (unsigned invalid = 1; invalid <= 4; ++invalid)
    {
        const auto fixture = BuildNativeSparseMutationImage(64 * 1024 * 1024, invalid);
        if (!Require(!fixture.empty(), "invalid sparse fixture built")) return false;
        NativeSparseImage image(fixture);
        MetadataStore::VolumeContext context;
        context.device_path = image.path.wstring(); context.volume_object_id = 101;
        context.allow_legacy_scaffold_for_fixtures = false;
        MetadataStore metadata(context);
        if (!metadata.PrepareNativeWritePath())
        {
            if (!Require(invalid != 4, "valid shared sparse fixture imports")) return false;
            continue;
        }
        if (invalid == 4)
        {
            if (!Require(metadata.VerifyIntegrity(), "valid shared sparse fixture verifies")) return false;
            MetadataStore::MutationRequest create;
            create.operation = MetadataStore::MutationOperation::CreateFile; create.path = L"\\unrelated";
            if (!Require(metadata.StageMutation(create) == MetadataStore::MutationStatus::Applied,
                    "unrelated pending create precedes shared sparse refusal")) return false;
        }
        const auto pending_before = metadata.PendingMutationCount();
        unsigned acquired = 0;
        metadata.SetFilePayloadRangeProvider([&](const auto&, auto, auto, auto) { ++acquired; return false; });
        MetadataStore::MutationRequest write; write.path = L"\\original"; write.offset = 12289; write.length = 1;
        const auto before = OrdinaryCowWriteCounterBytes(metadata.Device());
        if (!Require(metadata.PreflightNativeSparseMutation(write) != MetadataStore::MutationStatus::Applied,
                "invalid or shared sparse hole write preflights refusal")) return false;
        write.offset = 17;
        if (!Require(metadata.PreflightNativeSparseMutation(write) != MetadataStore::MutationStatus::Applied,
                "invalid or shared sparse allocated write preflights refusal")) return false;
        const auto staged = metadata.StageMutation(write);
        if (!Require(staged != MetadataStore::MutationStatus::Applied && metadata.PendingMutationCount() == pending_before,
                "malformed sparse admission refuses before staging")) return false;
        if (!Require(acquired == 0 && before == OrdinaryCowWriteCounterBytes(metadata.Device()),
                "malformed sparse records refuse before payload/device writes")) return false;
        if (invalid == 4 && !Require(metadata.CommitPendingMutations() == MetadataStore::CommitStatus::Committed,
                "shared sparse refusal does not poison unrelated pending create")) return false;
    }
    // The actual raw planner must refuse invented retained mappings and overlapping fragments.
    NativeSparseImage image(BuildNativeSparseMutationImage(64 * 1024 * 1024));
    apfsaccess::catalog::HeldFileSource source(image.path.string());
    std::string error;
    const auto checkpoint = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
    if (!Require(checkpoint && checkpoint->volumes.size() == 1, "sparse planner fixture checkpoint")) return false;
    const auto& volume = checkpoint->volumes.front();
    std::vector<apfsaccess::catalog::BtreeRecord> records;
    if (!Require(apfsaccess::catalog::ReadBtreeLeafRecords(source, 4096, volume.root_tree.physical_block, false,
            volume.superblock.omap_oid, checkpoint->container.superblock.xid, records, error), "sparse planner fixture tree")) return false;
    for (unsigned invalid = 0; invalid < 2; ++invalid)
    {
        AppleVolumeTransactionRequest request;
        request.volume_object_id = 101; request.filesystem_records = records;
        bool found = false;
        for (auto& record : request.filesystem_records)
        {
            AppleFileExtentRecord extent;
            if (!DecodeAppleFileExtentRecord(record, 4096, extent, error) || extent.physical_block != 100) continue;
            extent.length_bytes = 4096;
            if (invalid == 0) ++extent.physical_block;
            if (!Require(EncodeAppleFileExtentRecord(extent, record, error), "sparse forged fragment encodes")) return false;
            if (invalid == 1) request.filesystem_records.push_back(record);
            found = true; break;
        }
        if (!Require(found, "sparse planner physical fixture extent found")) return false;
        AppleVolumeTransactionPlan plan;
        if (!Require(!PlanAppleVolumeTransaction(source, *checkpoint, request, plan, error),
                "sparse planner rejects forged/overlapping retention")) return false;
    }
    return true;
}


bool TestNativeSparseMixed340()
{
    using Store = apfsaccess::rw::MetadataStore;
    constexpr std::uint64_t tail = 64 * 1024 * 1024;
    for (unsigned order = 0; order < 2; ++order)
    {
        NativeSparseImage image(BuildNativeSparseMutationImage(tail));
        Store::VolumeContext context;
        context.device_path = image.path.wstring(); context.volume_object_id = 101;
        context.allow_legacy_scaffold_for_fixtures = false;
        Store store(context);
        if (!Require(store.PrepareNativeWritePath(), "mixed sparse fixture prepares")) return false;
        Store::MutationRequest write;
        write.path = L"\\original"; write.offset = tail + 12293; write.length = 2;
        const auto sparse = [&] {
            Store::MutationRequest attribute;
            attribute.operation = Store::MutationOperation::SetExtendedAttribute;
            attribute.path = write.path; attribute.secondary_path = L"user.archive-companion";
            attribute.inline_payload = {std::byte{0x20}}; attribute.length = 1;
            return Require(store.PreflightNativeSparseMutation(write) == Store::MutationStatus::Applied &&
                store.StageMutation(attribute) == Store::MutationStatus::Applied &&
                store.StageMutation(write) == Store::MutationStatus::Applied, "sparse append plus companion xattr stages");
        };
        const auto ordinary = [&] {
            Store::MutationRequest create;
            create.operation = Store::MutationOperation::CreateFile; create.path = L"\\other";
            Store::MutationRequest append; append.path = create.path; append.length = 3;
            return Require(store.StageMutation(create) == Store::MutationStatus::Applied &&
                store.StageMutation(append) == Store::MutationStatus::Applied, "unrelated create and append stage");
        };
        if (!(order ? sparse() && ordinary() : ordinary() && sparse())) return false;
        std::uint64_t acquired = 0;
        store.SetFilePayloadRangeProvider([&](const auto& path, auto, auto offset, std::span<std::byte> bytes) {
            acquired += bytes.size();
            for (std::size_t i = 0; i < bytes.size(); ++i)
            {
                const auto at = offset + i;
                bytes[i] = path == L"\\other" ? std::byte{0x78} :
                    at >= write.offset && at < write.offset + 2 ? std::byte{0x59} :
                    at < 12288 ? std::byte{0x31} : at >= tail && at < tail + 12288 ? std::byte{0xa7} : std::byte{0};
            }
            return true;
        });
        if (!Require(store.CommitPendingMutations() == Store::CommitStatus::Committed,
                "mixed sparse append commits in either order: " + store.LastCommitStage())) return false;
        Store fresh(context);
        if (!Require(fresh.PrepareNativeWritePath() && fresh.VerifyIntegrity(), "mixed sparse reopen verifies")) return false;
        const auto inode = fresh.LookupCommittedInodeByPath(write.path);
        std::vector<std::byte> bytes, other;
        if (!Require(inode && inode->logical_size == write.offset + 2 && inode->allocation_size == 7 * 4096 &&
                fresh.LookupCommittedExtendedAttribute(17, "user.archive-companion") && acquired < 16384 &&
                fresh.ReadCommittedFileRange(write.path, tail + 12288, 7, bytes) &&
                bytes == std::vector<std::byte>{std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0x59}, std::byte{0x59}} &&
                fresh.ReadCommittedFileRange(L"\\other", 0, 3, other) && other == std::vector<std::byte>(3, std::byte{0x78}),
                "mixed append preserves holes, exact data, companion metadata and ordinary bytes")) return false;
        Store::MutationRequest resize;
        resize.operation = Store::MutationOperation::SetFileSize; resize.path = write.path; resize.length = 8193;
        if (!Require(fresh.StageMutation(resize) == Store::MutationStatus::Applied, "sparse partial block shrink stages")) return false;
        resize.length = tail + 32768;
        if (!Require(fresh.StageMutation(resize) == Store::MutationStatus::Applied, "sparse regrow stages")) return false;
        fresh.SetFilePayloadRangeProvider([](const auto&, auto, auto, std::span<std::byte> bytes) {
            std::fill(bytes.begin(), bytes.end(), std::byte{0x31}); return true;
        });
        if (!Require(fresh.CommitPendingMutations() == Store::CommitStatus::Committed,
                "sparse shrink-regrow commits: " + fresh.LastCommitStage())) return false;
        Store final(context);
        if (!Require(final.PrepareNativeWritePath() && final.VerifyIntegrity(), "sparse shrink-regrow reopens")) return false;
        const auto final_inode = final.LookupCommittedInodeByPath(write.path);
        if (!Require(final_inode && final_inode->logical_size == resize.length && final_inode->allocation_size == 12288 &&
                final.ReadCommittedFileRange(write.path, 8192, 4096, bytes) && bytes.size() == 4096 && bytes[0] == std::byte{0x31} &&
                std::all_of(bytes.begin() + 1, bytes.end(), [](auto value) { return value == std::byte{0}; }) &&
                final.ReadCommittedFileRange(write.path, tail, 4096, bytes) &&
                std::all_of(bytes.begin(), bytes.end(), [](auto value) { return value == std::byte{0}; }),
                "regrowth preserves partial prefix and cannot resurrect truncated physical data")) return false;
        resize.length = 0;
        if (!Require(final.StageMutation(resize) == Store::MutationStatus::Applied, "sparse truncate to zero stages")) return false;
        resize.length = tail;
        if (!Require(final.StageMutation(resize) == Store::MutationStatus::Applied, "zero-allocation sparse regrowth stages")) return false;
        resize.length = 8193;
        if (!Require(final.StageMutation(resize) == Store::MutationStatus::Applied, "second partial truncate cannot restore discarded blocks")) return false;
        resize.length = tail;
        if (!Require(final.StageMutation(resize) == Store::MutationStatus::Applied &&
                final.CommitPendingMutations() == Store::CommitStatus::Committed, "zero-allocation sparse regrowth commits")) return false;
        Store empty(context);
        if (!Require(empty.PrepareNativeWritePath(), "zero-allocation sparse file reopens")) return false;
        const auto hole = empty.LookupCommittedInodeByPath(write.path);
        write.offset = 17; write.length = 1;
        empty.SetFilePayloadRangeProvider([](const auto&, auto, auto offset, std::span<std::byte> bytes) {
            std::fill(bytes.begin(), bytes.end(), std::byte{0});
            if (offset <= 17 && 17 - offset < bytes.size()) bytes[17 - offset] = std::byte{0x67};
            return true;
        });
        if (!Require(hole && hole->allocation_size == 0 && hole->logical_size == tail &&
                empty.PreflightNativeSparseMutation(write) == Store::MutationStatus::Applied &&
                empty.StageMutation(write) == Store::MutationStatus::Applied &&
                empty.CommitPendingMutations() == Store::CommitStatus::Committed,
                "hole-only sparse file remains writable after zero truncate and regrowth")) return false;
    }
    return true;
}

bool TestNativeSparseCommittedRegrowth353()
{
    using Store = apfsaccess::rw::MetadataStore;
    constexpr std::uint64_t tail = 64 * 1024 * 1024;
    for (const auto shrink : {8193ULL, 0ULL})
    {
        NativeSparseImage image(BuildNativeSparseMutationImage(tail));
        Store::VolumeContext context;
        context.device_path = image.path.wstring(); context.volume_object_id = 101;
        context.allow_legacy_scaffold_for_fixtures = false;
        Store::MutationRequest size;
        size.operation = Store::MutationOperation::SetFileSize; size.path = L"\\original"; size.length = shrink;
        {
            Store first(context);
            first.SetFilePayloadRangeProvider([](const auto&, auto, auto, std::span<std::byte> bytes) {
                std::fill(bytes.begin(), bytes.end(), std::byte{0x31}); return true;
            });
            if (!Require(first.PrepareNativeWritePath() && first.StageMutation(size) == Store::MutationStatus::Applied &&
                    first.CommitPendingMutations() == Store::CommitStatus::Committed,
                    "sparse partial/zero shrink publishes before closing")) return false;
        }
        {
            Store second(context);
            if (!Require(second.PrepareNativeWritePath(), "truncated sparse image reopens")) return false;
            const auto shrunk = second.LookupCommittedInodeByPath(size.path);
            if (!Require(shrunk && (shrunk->internal_flags & apfsaccess::rw::kAppleInodeSparseFlag) &&
                    shrunk->logical_size == shrink && shrunk->allocation_size == (shrink ? 12288 : 0),
                    "native sparse identity survives hole-free committed shrink")) return false;
            size.length = tail + 32768;
            second.SetFilePayloadRangeProvider([&](const auto&, auto, auto offset, std::span<std::byte> bytes) {
                for (std::size_t i = 0; i < bytes.size(); ++i) bytes[i] = offset + i < shrink ? std::byte{0x31} : std::byte{0};
                return true;
            });
            const auto staged = second.StageMutation(size);
            if (!Require(staged == Store::MutationStatus::Applied,
                    "reopened sparse regrowth stages after " + std::to_string(shrink) + ": " + std::to_string(static_cast<int>(staged)))) return false;
            const auto published = second.CommitPendingMutations();
            if (!Require(published == Store::CommitStatus::Committed,
                    "reopened sparse file regrows without dense reservation: " + second.LastCommitStage())) return false;
        }
        Store final(context);
        if (!Require(final.PrepareNativeWritePath() && final.VerifyIntegrity(), "regrown sparse file reopens and verifies")) return false;
        const auto inode = final.LookupCommittedInodeByPath(size.path);
        std::vector<std::byte> bytes;
        if (!Require(inode && inode->allocation_size == (shrink ? 12288 : 0) && inode->logical_size == size.length &&
                final.ReadCommittedFileRange(size.path, shrink, 4096, bytes) && bytes == std::vector<std::byte>(4096) &&
                final.ReadCommittedFileRange(size.path, tail, 4096, bytes) && bytes == std::vector<std::byte>(4096),
                "committed regrowth retains exact allocation and cannot resurrect data")) return false;
        Store::MutationRequest write; write.path = size.path; write.offset = tail + 7; write.length = 1;
        final.SetFilePayloadRangeProvider([&](const auto&, auto, auto offset, std::span<std::byte> output) {
            std::fill(output.begin(), output.end(), std::byte{0});
            if (write.offset >= offset && write.offset - offset < output.size()) output[write.offset - offset] = std::byte{0x57};
            return true;
        });
        if (!Require(final.StageMutation(write) == Store::MutationStatus::Applied &&
                final.CommitPendingMutations() == Store::CommitStatus::Committed,
                "regrown sparse file supports later writes")) return false;
    }
    return true;
}

bool TestNativeSparseAllocationPathReuse353()
{
    using Store = apfsaccess::rw::MetadataStore;
    constexpr std::uint64_t tail = 64 * 1024 * 1024;
    for (bool replace : {false, true})
    {
        NativeSparseImage image(BuildNativeSparseMutationImage(tail));
        Store::VolumeContext context;
        context.device_path = image.path.wstring(); context.volume_object_id = 101;
        context.allow_legacy_scaffold_for_fixtures = false;
        Store store(context);
        if (!Require(store.PrepareNativeWritePath(), "allocation path-reuse fixture prepares")) return false;
        Store::MutationRequest request;
        request.operation = Store::MutationOperation::CreateFile; request.path = L"\\temp";
        if (!Require(store.StageMutation(request) == Store::MutationStatus::Applied, "ordinary temporary file stages")) return false;
        const auto ordinary = store.LookupWorkingInodeByPath(request.path)->object_id;
        request.operation = Store::MutationOperation::SetAllocationSize; request.length = 4096;
        if (!Require(store.StageMutation(request) == Store::MutationStatus::Applied, "ordinary allocation stages")) return false;
        if (!replace)
        {
            request.operation = Store::MutationOperation::Rename; request.length = 0; request.secondary_path = L"\\saved";
            if (!Require(store.StageMutation(request) == Store::MutationStatus::Applied, "ordinary allocation owner renames away")) return false;
        }
        request = {};
        request.operation = Store::MutationOperation::Rename;
        request.path = L"\\original"; request.secondary_path = L"\\temp"; request.replace_if_exists = replace;
        if (!Require(store.StageMutation(request) == Store::MutationStatus::Applied, "sparse inode takes old allocation path")) return false;
        request = {}; request.path = L"\\temp"; request.offset = tail / 2; request.length = 1;
        if (!Require(store.StageMutation(request) == Store::MutationStatus::Applied, "sparse path-reuse write stages")) return false;
        store.SetFilePayloadRangeProvider([&](const auto& path, auto owner, auto offset, std::span<std::byte> bytes) {
            if (path == L"\\saved") return owner.object_id == ordinary && bytes.empty();
            if (path != L"\\temp" || owner.object_id != 17) return false;
            for (std::size_t i = 0; i < bytes.size(); ++i)
            {
                const auto at = offset + i;
                bytes[i] = at == request.offset ? std::byte{0x6b} :
                    at < 12288 ? std::byte{0x31} : at >= tail ? std::byte{0xa7} : std::byte{0};
            }
            return true;
        });
        if (!Require(store.CommitPendingMutations() == Store::CommitStatus::Committed,
                "historical allocation cannot disable sparse planning for another inode: " + store.LastCommitStage())) return false;
        Store fresh(context);
        if (!Require(fresh.PrepareNativeWritePath() && fresh.VerifyIntegrity(), "path-reuse sparse result reopens")) return false;
        const auto inode = fresh.LookupCommittedInodeByPath(L"\\temp");
        std::vector<std::byte> bytes;
        if (!Require(inode && inode->object_id == 17 && inode->allocation_size == 7 * 4096 &&
                fresh.ReadCommittedFileRange(L"\\temp", request.offset, 1, bytes) && bytes == std::vector<std::byte>{std::byte{0x6b}},
                "path-reuse sparse owner and payload preserved")) return false;
    }
    return true;
}

bool TestNativeSparsePreflightAllocationFailure353()
{
    using Store = apfsaccess::rw::MetadataStore;
    NativeSparseImage image(BuildNativeSparseMutationImage(64 * 1024 * 1024));
    Store::VolumeContext context;
    context.device_path = image.path.wstring(); context.volume_object_id = 101;
    context.allow_legacy_scaffold_for_fixtures = false;
    Store store(context);
    if (!Require(store.PrepareNativeWritePath(), "sparse allocation failure fixture prepares")) return false;
    Store::MutationRequest write; write.path = L"\\original"; write.offset = 16384; write.length = 1;
    unsigned calls = 0;
    store.SetSparsePreflightHookForTests([&] { if (++calls == 2) throw std::bad_alloc{}; });
    if (!Require(store.PreflightNativeSparseMutation(write) == Store::MutationStatus::Applied, "first sparse ownership scan succeeds")) return false;
    Store::MutationRequest companion;
    companion.operation = Store::MutationOperation::CreateFile; companion.path = L"\\prior";
    if (!Require(store.StageMutation(companion) == Store::MutationStatus::Applied, "prior accepted-state model stages before failure")) return false;
    const auto pending = store.PendingMutationCount();
    if (!Require(store.StageMutation(write) == Store::MutationStatus::AllocationFailed && calls == 2 &&
            store.PendingMutationCount() == pending && store.LookupWorkingAllocationByObjectId(17) == 24576,
            "second ownership scan reports allocation failure without losing prior work")) return false;
    store.SetSparsePreflightHookForTests({});
    return Require(store.CommitPendingMutations() == Store::CommitStatus::Committed &&
        store.LookupCommittedInodeByPath(L"\\prior"), "prior work remains committable after sparse allocation failure");
}

bool TestNativeSparseResizeRollback368()
{
    using Store = apfsaccess::rw::MetadataStore;
    constexpr std::uint64_t tail = 64 * 1024 * 1024;
    for (const bool length_failure : {false, true})
    {
        NativeSparseImage image(BuildNativeSparseMutationImage(tail));
        Store::VolumeContext context;
        context.device_path = image.path.wstring(); context.volume_object_id = 101;
        context.allow_legacy_scaffold_for_fixtures = false;
        Store store(context);
        if (!Require(store.PrepareNativeWritePath(), "sparse resize rollback fixture prepares")) return false;
        Store::MutationRequest write;
        write.path = L"\\original"; write.offset = 16384; write.length = 3;
        if (!Require(store.StageMutation(write) == Store::MutationStatus::Applied,
                "earlier sparse payload stages before failing shrink")) return false;
        const auto pending = store.PendingMutationCount();
        const auto dirty = store.PendingPayloadDirtyByteEstimate();
        const auto prior = store.LookupWorkingInodeByPath(write.path);
        bool fired = false;
        store.SetSparseResizePublicationHookForTests([&] {
            if (fired) return;
            fired = true;
            if (length_failure) throw std::length_error("sparse resize publication");
            throw std::bad_alloc{};
        });
        Store::MutationRequest size;
        size.operation = Store::MutationOperation::SetFileSize;
        size.path = write.path; size.length = length_failure ? 16385 : 8193;
        Store::MutationStatus status;
        try { status = store.StageMutation(size); }
        catch (...) { return Require(false, "sparse resize allocation error escaped mutation boundary"); }
        const auto restored = store.LookupWorkingInodeByPath(write.path);
        if (!Require(fired && status == Store::MutationStatus::AllocationFailed && prior && restored &&
                restored->logical_size == prior->logical_size && restored->allocation_size == prior->allocation_size &&
                restored->xid == prior->xid && restored->internal_flags == prior->internal_flags &&
                store.PendingMutationCount() == pending && store.PendingPayloadDirtyByteEstimate() == dirty && dirty == 3,
                "failed shrink restores prior inode, mutation count and exact dirty range accounting")) return false;
        store.SetSparseResizePublicationHookForTests({});
        store.SetFilePayloadRangeProvider([&](const auto&, auto, auto offset, std::span<std::byte> bytes) {
            for (std::size_t i = 0; i < bytes.size(); ++i)
            {
                const auto at = offset + i;
                bytes[i] = at >= write.offset && at - write.offset < write.length ? std::byte{0x6e} :
                    at < 12288 ? std::byte{0x31} : at >= tail ? std::byte{0xa7} : std::byte{0};
            }
            return true;
        });
        if (!Require(store.CommitPendingMutations() == Store::CommitStatus::Committed,
                "earlier sparse payload remains committable after resize allocation failure: " + store.LastCommitStage())) return false;
        Store fresh(context);
        std::vector<std::byte> bytes;
        if (!Require(fresh.PrepareNativeWritePath() && fresh.VerifyIntegrity() &&
                fresh.LookupCommittedInodeByPath(write.path)->logical_size == prior->logical_size &&
                fresh.ReadCommittedFileRange(write.path, write.offset, write.length, bytes) &&
                bytes == std::vector<std::byte>(3, std::byte{0x6e}),
                "fresh sparse reader sees all earlier bytes after failed shrink")) return false;
    }
    NativeSparseImage image(BuildNativeSparseMutationImage(tail));
    Store::VolumeContext context;
    context.device_path = image.path.wstring(); context.volume_object_id = 101;
    context.allow_legacy_scaffold_for_fixtures = false;
    Store store(context);
    if (!Require(store.PrepareNativeWritePath(), "successful sparse shrink accounting fixture prepares")) return false;
    Store::MutationRequest write;
    write.path = L"\\original"; write.offset = 16384; write.length = 3;
    if (!Require(store.StageMutation(write) == Store::MutationStatus::Applied, "pending hole payload stages")) return false;
    Store::MutationRequest size;
    size.operation = Store::MutationOperation::SetFileSize;
    size.path = write.path; size.length = 16385;
    if (!Require(store.StageMutation(size) == Store::MutationStatus::Applied &&
            store.PendingPayloadDirtyByteEstimate() == 1, "successful shrink clips dirty-byte accounting")) return false;
    size.length = 0;
    return Require(store.StageMutation(size) == Store::MutationStatus::Applied &&
        store.PendingPayloadDirtyByteEstimate() == 0 && store.CommitPendingMutations() == Store::CommitStatus::Committed,
        "zero shrink discards only truncated bytes and commits without phantom dirty payload");
}

bool TestNativeSparseWalReplay()
{
    using namespace apfsaccess::rw;
    constexpr std::uint64_t tail = 64 * 1024 * 1024;
    const auto fixture = BuildNativeSparseMutationImage(tail);
    if (!Require(!fixture.empty(), "sparse WAL fixture builds")) return false;
    NativeSparseImage image(fixture);
    MetadataStore::VolumeContext context;
    context.device_path = image.path.wstring(); context.volume_object_id = 101;
    context.allow_legacy_scaffold_for_fixtures = false;
    auto wal = image.path; wal += L".wal";
    struct RemoveWal { std::filesystem::path path; ~RemoveWal() { std::error_code error; std::filesystem::remove(path, error); } } cleanup{wal};
    std::uint64_t xid = 0, accepted_sequence = 0;
    {
        MetadataStore original(context);
        if (!Require(original.PrepareNativeWritePath(), "sparse WAL fixture prepares")) return false;
        xid = *original.CheckpointXid();
        TransactionManager transactions(L"Strict");
        transactions.SetJournalPath(wal.wstring()); transactions.SetVolumeIdentity(L"native-sparse-fixture");
        TransactionManager::MutationIntent intent;
        intent.kind = TransactionManager::MutationKind::Write; intent.path = L"\\original";
        intent.object_id = 17; intent.generation = xid + 1;
        intent.offset = tail / 2 - 1; intent.length = intent.payload_length = 3;
        intent.inline_payload = {std::byte{0x91}, std::byte{0}, std::byte{0xff}};
        std::string error, hex;
        auto digest = apfsaccess::observer::Sha256Stream::Create(error);
        if (!Require(digest && digest->Update(intent.inline_payload.data(), intent.inline_payload.size()) && digest->FinalHex(hex),
                "sparse WAL payload hashes")) return false;
        for (std::size_t i = 0; i < intent.payload_checksum.size(); ++i)
            intent.payload_checksum[i] = static_cast<std::uint8_t>(std::stoul(hex.substr(i * 2, 2), nullptr, 16));
        if (!Require(transactions.Begin() && transactions.RecordMutation(intent) && transactions.Accept(xid),
                "sparse WAL accepts durable identity-bound bytes")) return false;
        accepted_sequence = transactions.Watermarks().accepted_sequence;
        if (!Require(accepted_sequence != 0 && transactions.Watermarks().apfs_durable_sequence == 0,
                "sparse WAL acceptance precedes APFS durability")) return false;
    }
    TransactionManager replay(L"Strict");
    replay.SetJournalPath(wal.wstring()); replay.SetVolumeIdentity(L"native-sparse-fixture");
    std::vector<TransactionManager::AcceptedTransaction> accepted;
    if (!Require(replay.LoadUnappliedAcceptedTransactions(accepted) && accepted.size() == 1 && accepted[0].mutations.size() == 1 &&
            accepted[0].preimage_checkpoint_xid == xid, "sparse WAL accepted bytes reload after restart")) return false;
    const auto& record = accepted[0].mutations.front();
    MetadataStore recovered(context);
    if (!Require(recovered.PrepareNativeWritePath() && recovered.CheckpointXid() == xid, "sparse replay finds original checkpoint")) return false;
    MetadataStore::MutationRequest request;
    request.path = L"\\original"; request.object_id = record.object_id; request.generation = record.parent_object_id;
    request.offset = record.logical_offset; request.length = record.logical_length;
    MetadataStore::PayloadIdentity identity;
    if (!Require(recovered.StageMutation(request, &identity) == MetadataStore::MutationStatus::Applied,
            "sparse accepted mutation restages with original identity")) return false;
    recovered.SetFilePayloadRangeProvider([&](const auto&, auto owner, auto offset, std::span<std::byte> bytes) {
        if (owner.object_id != identity.object_id || owner.generation != identity.generation) return false;
        std::fill(bytes.begin(), bytes.end(), std::byte{0});
        for (std::size_t i = 0; i < bytes.size(); ++i)
            if (offset + i >= record.logical_offset && offset + i - record.logical_offset < record.inline_payload.size())
                bytes[i] = record.inline_payload[static_cast<std::size_t>(offset + i - record.logical_offset)];
        return true;
    });
    if (!Require(recovered.CommitCanonicalTransaction({xid}) == MetadataStore::CommitStatus::Committed &&
            replay.MarkApfsDurableThrough(accepted_sequence) && replay.MarkCleanedThrough(accepted_sequence),
            "sparse replay publishes before advancing WAL watermarks")) return false;
    MetadataStore final(context);
    if (!Require(final.PrepareNativeWritePath(), "sparse WAL result reopens")) return false;
    const auto inode = final.LookupCommittedInodeByPath(request.path);
    std::vector<std::byte> bytes;
    return TestNativeSparseMixed340() && Require(inode && inode->allocation_size == 8 * 4096 && inode->logical_size == tail + 12288 &&
        final.ReadCommittedFileRange(request.path, request.offset, 3, bytes) && bytes == record.inline_payload &&
        replay.Watermarks().cleanup_sequence == accepted_sequence, "sparse WAL replay preserves holes and exact accepted payload");
}
