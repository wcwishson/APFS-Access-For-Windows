#pragma once

// Include after NativeSparseMutationTests.h and the compatibility fixture helpers.
// These are read-only imports: no PrepareNativeWritePath or mutation preflight.
enum class NativeSparseReadFixture
{
    MissingField, ShortField, LongField, DuplicateField, FieldWithoutFlag,
    PhysicalPastDevice, PartialInvalid, ShortExtent, ZeroExtent, LogicalOverflow,
    OverlappingExtents, AllHole, ExplicitHole, HugeHole, Ordinary, AllocatedSparse
};

std::vector<std::byte> BuildNativeSparseReadValidationImage(NativeSparseReadFixture kind)
{
    using namespace apfsaccess::rw;
    using apfsaccess::catalog::ReadU64LE;
    const auto bytes = BuildNativeSparseMutationImage(64ULL * 1024 * 1024);
    if (bytes.empty()) return {};
    apfsaccess::catalog::VectorRandomAccessSource source(bytes);
    std::string error;
    const auto checkpoint = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
    if (!Require(checkpoint && checkpoint->volumes.size() == 1,
            "sparse read seed checkpoint loads")) return {};
    const auto& volume = checkpoint->volumes.front();
    std::vector<apfsaccess::catalog::BtreeRecord> records;
    if (!Require(apfsaccess::catalog::ReadBtreeLeafRecords(source, 4096,
            volume.root_tree.physical_block, false, volume.superblock.omap_oid,
            checkpoint->container.superblock.xid, records, error),
            "sparse read seed filesystem tree loads")) return {};

    // Independently lay out j_inode_val_t and x_field_t bytes, rather than use
    // the inode/extent encoder under test. APFS Reference: internal_flags at
    // 0x30; xfields at 0x5c; INODE_IS_SPARSE = 0x200; field 13 is uint64_t.
    const bool pair = kind == NativeSparseReadFixture::PartialInvalid ||
        kind == NativeSparseReadFixture::OverlappingExtents;
    const bool ordinary = kind == NativeSparseReadFixture::Ordinary;
    const bool physical_only = ordinary || kind == NativeSparseReadFixture::AllocatedSparse;
    const std::uint64_t eof = kind == NativeSparseReadFixture::HugeHole ?
        1ULL << 40 : pair ? 8192 : 4096;
    const std::uint64_t allocated = physical_only || pair ? 4096 : 0;
    const unsigned sparse_fields = kind == NativeSparseReadFixture::MissingField || ordinary ? 0 :
        kind == NativeSparseReadFixture::DuplicateField ? 2 : 1;
    const std::size_t sparse_size = kind == NativeSparseReadFixture::ShortField ? 4 :
        kind == NativeSparseReadFixture::LongField ? 16 : 8;
    const std::size_t sparse_padded = (sparse_size + 7) & ~std::size_t{7};
    bool found_inode = false;
    for (auto& record : records)
    {
        if (ReadU64LE(record.key, 0) != ((3ULL << 60) | 17)) continue;
        found_inode = true;
        record.value.resize(0x5c);
        PutU64LE(record.value, 0x30,
            ordinary || kind == NativeSparseReadFixture::FieldWithoutFlag ? 0 : 0x200);
        PutU64LE(record.value, 0x54, 0);
        const auto field_count = 1 + sparse_fields;
        const auto used = field_count * 4 + 40 + sparse_fields * sparse_padded;
        record.value.resize(0x60 + used, std::byte{0});
        PutU16LE(record.value, 0x5c, static_cast<std::uint16_t>(field_count));
        PutU16LE(record.value, 0x5e, static_cast<std::uint16_t>(used));
        record.value[0x60] = std::byte{8}; // INO_EXT_TYPE_DSTREAM
        PutU16LE(record.value, 0x62, 40);
        const auto stream_offset = 0x60 + field_count * 4;
        PutU64LE(record.value, stream_offset, eof);
        PutU64LE(record.value, stream_offset + 8, allocated);
        for (unsigned i = 0; i < sparse_fields; ++i)
        {
            const auto descriptor = 0x64 + i * 4;
            record.value[descriptor] = std::byte{13};
            PutU16LE(record.value, descriptor + 2, static_cast<std::uint16_t>(sparse_size));
            // Even the short-field fixture has a valid padded xfield envelope.
            PutU64LE(record.value, stream_offset + 40 + i * sparse_padded, eof - allocated);
        }
    }
    if (!Require(found_inode, "sparse read seed inode found")) return {};
    std::erase_if(records, [](const auto& record) {
        return apfsaccess::catalog::ReadU64LE(record.key, 0) == ((8ULL << 60) | 17);
    });
    const auto extent = [&](std::uint64_t logical, std::uint64_t length, std::uint64_t physical) {
        apfsaccess::catalog::BtreeRecord record;
        record.key.resize(16); record.value.resize(24);
        PutU64LE(record.key, 0, (8ULL << 60) | 17);
        PutU64LE(record.key, 8, logical);
        PutU64LE(record.value, 0, length); // len_and_flags, with no reserved flags
        PutU64LE(record.value, 8, physical);
        PutU64LE(record.value, 16, 0); // crypto_id
        records.push_back(std::move(record));
    };
    const auto past_device = bytes.size() / 4096;
    switch (kind)
    {
    case NativeSparseReadFixture::PhysicalPastDevice: extent(0, 4096, past_device); break;
    case NativeSparseReadFixture::PartialInvalid:
        extent(0, 4096, 100); extent(4096, 4096, past_device); break;
    case NativeSparseReadFixture::ShortExtent:
        extent(0, 4096, 100); records.back().value.resize(16); break;
    case NativeSparseReadFixture::ZeroExtent: extent(0, 0, 100); break;
    case NativeSparseReadFixture::LogicalOverflow: extent(UINT64_MAX - 4095, 4096, 0); break;
    case NativeSparseReadFixture::OverlappingExtents:
        extent(0, 8192, 0); extent(4096, 4096, 100); break;
    case NativeSparseReadFixture::ExplicitHole:
    case NativeSparseReadFixture::HugeHole: extent(0, eof, 0); break;
    case NativeSparseReadFixture::Ordinary:
    case NativeSparseReadFixture::AllocatedSparse: extent(0, 4096, 100); break;
    default: break;
    }
    if (!Require(SortAppleBtreeRecords(records, AppleBtreeKeyOrder::FileSystemCaseSensitive, error),
            "sparse read raw records sort")) return {};
    // Rebuild the container envelope so positive all-hole fixtures have no
    // leftover physical references or allocations from the seed image.
    BuilderStore fixture;
    fixture.authoritative_checkpoint = true;
    fixture.block_count = bytes.size() / 4096;
    auto& target = fixture.volumes.front();
    target.incompat = 0;
    target.filesystem_records = std::move(records);
    if (physical_only || pair)
    {
        apfsaccess::catalog::BtreeRecord reference;
        reference.key.resize(8); reference.value.resize(20);
        PutU64LE(reference.key, 0, (2ULL << 60) | 100); // j_phys_ext_key_t
        PutU64LE(reference.value, 0, (1ULL << 60) | 1); // one block, APFS_KIND_NEW
        PutU64LE(reference.value, 8, 17);
        PutU32LE(reference.value, 16, 1);
        target.extentref_records.push_back(std::move(reference));
        target.additional_file_system_allocated_blocks = 1;
        fixture.authoritative_seeded_main_blocks.push_back({100, std::vector<std::byte>(4096, std::byte{0x31})});
    }
    return BuildStoreImage(fixture);
}

bool RequireNativeSparseReadRejected(NativeSparseReadFixture kind, const std::string& label)
{
    using namespace apfsaccess::rw;
    const auto fixture = BuildNativeSparseReadValidationImage(kind);
    if (!Require(!fixture.empty(), label + ": raw fixture built")) return false;
    NativeSparseImage image(fixture);
    BlockDevice device(image.path.wstring());
    NativeApfsVolumeProjection projection;
    std::wstring error;
    const bool projected = NativeApfsReader::TryLoadVolumeProjection(device, 101, projection, error);
    bool ok = Require(!projected && error == L"NativeApfsRootTreeProjectionFailed" &&
        projection.inodes.empty() && projection.read_extents_by_inode.empty(),
        label + ": malformed content fails and clears the read projection");
    MetadataStore::VolumeContext context;
    context.device_path = image.path.wstring(); context.volume_object_id = 101;
    context.allow_legacy_scaffold_for_fixtures = false;
    MetadataStore metadata(context);
    if (!Require(metadata.LoadContainerSuperblocks(), label + ": container remains readable")) return false;
    const bool imported = metadata.LoadObjectMap();
    std::vector<std::byte> payload{std::byte{0xa5}};
    // Do not short-circuit on failed import: exercise the public read itself.
    const bool read = metadata.ReadCommittedFileRange(L"\\original", 0, 64, payload);
    ok &= Require(!imported && !read && payload.empty(),
        label + ": committed read refuses instead of returning manufactured zeros or partial data");
    return ok;
}

bool TestNativeSparseReadInvalidFields()
{
    bool ok = true;
    ok &= RequireNativeSparseReadRejected(NativeSparseReadFixture::MissingField, "missing field 13");
    ok &= RequireNativeSparseReadRejected(NativeSparseReadFixture::ShortField, "4-byte field 13");
    ok &= RequireNativeSparseReadRejected(NativeSparseReadFixture::LongField, "16-byte field 13");
    ok &= RequireNativeSparseReadRejected(NativeSparseReadFixture::DuplicateField, "duplicate field 13");
    ok &= RequireNativeSparseReadRejected(NativeSparseReadFixture::FieldWithoutFlag, "field 13 without sparse flag");
    return ok;
}

bool TestNativeSparseReadInvalidExtents()
{
    bool ok = true;
    ok &= RequireNativeSparseReadRejected(NativeSparseReadFixture::PhysicalPastDevice, "physical extent past device");
    ok &= RequireNativeSparseReadRejected(NativeSparseReadFixture::PartialInvalid, "valid plus invalid extent");
    ok &= RequireNativeSparseReadRejected(NativeSparseReadFixture::ShortExtent, "truncated extent value");
    ok &= RequireNativeSparseReadRejected(NativeSparseReadFixture::ZeroExtent, "zero-length extent");
    ok &= RequireNativeSparseReadRejected(NativeSparseReadFixture::LogicalOverflow, "overflowing logical extent");
    ok &= RequireNativeSparseReadRejected(NativeSparseReadFixture::OverlappingExtents, "overlapping extent set");
    return ok;
}

bool RequireNativeSparseReadAccepted(NativeSparseReadFixture kind, std::uint64_t eof, bool explicit_extent)
{
    using namespace apfsaccess::rw;
    const auto fixture = BuildNativeSparseReadValidationImage(kind);
    if (!Require(!fixture.empty(), "valid sparse read raw fixture built")) return false;
    NativeSparseImage image(fixture);
    BlockDevice device(image.path.wstring());
    NativeApfsVolumeProjection projection;
    std::wstring error;
    if (!Require(NativeApfsReader::TryLoadVolumeProjection(device, 101, projection, error),
            "valid metadata projects through native reader")) return false;
    const auto extents = projection.read_extents_by_inode.find(17);
    const bool ordinary = kind == NativeSparseReadFixture::Ordinary ||
        kind == NativeSparseReadFixture::AllocatedSparse;
    if (!Require(extents != projection.read_extents_by_inode.end() &&
            extents->second.size() == (explicit_extent ? 1u : 0u),
            "read projection retains exactly the supplied extent evidence")) return false;
    if (explicit_extent && !Require(extents->second[0].logical_offset == 0 &&
            extents->second[0].bytes == eof &&
            extents->second[0].physical_address == (ordinary ? 100ULL * 4096 : 0),
            "explicit physical/hole extent survives with its full logical length")) return false;
    if (kind == NativeSparseReadFixture::HugeHole &&
        !Require(eof > fixture.size(), "huge logical hole exceeds actual image capacity")) return false;
    MetadataStore::VolumeContext context;
    context.device_path = image.path.wstring(); context.volume_object_id = 101;
    context.allow_legacy_scaffold_for_fixtures = false;
    MetadataStore metadata(context);
    if (!Require(metadata.LoadContainerSuperblocks() && metadata.LoadObjectMap(),
            "valid sparse/ordinary metadata imports without writer preflight")) return false;
    const auto inode = metadata.LookupCommittedInodeByPath(L"\\original");
    if (!Require(inode && inode->logical_size == eof && inode->allocation_size == (ordinary ? 4096 : 0),
            "valid read inode retains logical and allocated sizes")) return false;
    for (const auto offset : {std::uint64_t{0}, eof / 2, eof - 64})
    {
        std::vector<std::byte> payload{std::byte{0xa5}};
        if (!Require(metadata.ReadCommittedFileRange(L"\\original", offset, 64, payload) &&
                payload == std::vector<std::byte>(64, ordinary ? std::byte{0x31} : std::byte{0}),
                "bounded native reads return exact data at start, middle and end")) return false;
    }
    return true;
}

bool TestNativeSparseReadAllHole()
{
    const bool implicit = RequireNativeSparseReadAccepted(NativeSparseReadFixture::AllHole, 4096, false);
    const bool explicit_hole = RequireNativeSparseReadAccepted(NativeSparseReadFixture::ExplicitHole, 4096, true);
    return implicit && explicit_hole;
}

bool TestNativeSparseReadHugeHole()
{
    return RequireNativeSparseReadAccepted(NativeSparseReadFixture::HugeHole, 1ULL << 40, true);
}

bool TestNativeSparseReadCompatibleMetadata()
{
    using namespace apfsaccess::rw;
    if (!RequireNativeSparseReadAccepted(NativeSparseReadFixture::Ordinary, 4096, true)) return false;
    if (!RequireNativeSparseReadAccepted(NativeSparseReadFixture::AllocatedSparse, 4096, true)) return false;
    // Valid compressed content has a zero native dstream and no field 13.
    // Keep this control on D: using the same lifetime helper as sparse images.
    NativeCompressionFixture spec;
    const auto plain = NativeCompressionHex("68656c6c6f");
    spec.decmpfs = NativeCompressionAttribute(1, plain.size(), plain);
    const auto fixture = BuildNativeCompressionImage(spec);
    if (!Require(!fixture.empty(), "compressed read control built")) return false;
    NativeSparseImage image(fixture);
    MetadataStore::VolumeContext context;
    context.device_path = image.path.wstring(); context.volume_object_id = 101;
    context.allow_legacy_scaffold_for_fixtures = false;
    MetadataStore metadata(context);
    if (!Require(metadata.LoadContainerSuperblocks() && metadata.LoadObjectMap(),
            "compressed zero-dstream metadata still imports")) return false;
    std::vector<std::byte> payload;
    return Require(metadata.ReadCommittedFileRange(L"\\original", 0, plain.size(), payload) && payload == plain,
        "compressed metadata still reads its inline content without sparse field 13");
}
