#pragma once
// Include inside FsHostSemanticsTests.cpp's test namespace after
// DirectorySymlinkFixture and HostCompression* helpers. Include the production
// header at main.cpp's GLOBAL native-engine include block (see the handoff).

// Independently expected bytes and frozen vectors shared with
// ApfsCompressionTests.cpp:TestLzvnLargeLogicalRange and LzfseDecoderBridgeTests.h.
std::vector<std::byte> HostCompressionModernPattern()
{
    constexpr std::string_view pattern = "Task5 LZFSE bounded decoder: abcdefghijklmnopqrstuvwxyz 0123456789\n";
    std::vector<std::byte> bytes(8192);
    for (std::size_t i = 0; i < bytes.size(); ++i) bytes[i] = static_cast<std::byte>(pattern[i % pattern.size()]);
    return bytes;
}

const auto kHostCompressionLzfseV2 = HostCompressionHex(
    "62767832002000004400e0020005000051b955f7ac110060b00000003cbc400fefc01500000000575700000000f01bbc20bf01000000fc060000000000000000000000000000dc0100000000f0370000000077777777776fc0dddddddd1d0000dcdd01700700777700dc01c01bf006bc013fc3cf7077777777f706dcddbd015fc1dddd1bf006dcbd017777777777000000000000000000000000000000000000000000000000000000000000000000000000c008aa0922b277000e233a59356a0c62b1de7d7f280564d93d6ffaff56dd4e742a2fc2762a345762e42ba5010000000000000000c06ffd7fff7ffcff6062767824");

struct HostCompressionRewrite211Fixture
{
    DirectorySymlinkFixture fixture{false};
    std::uint64_t eof = 5;
    std::vector<std::byte> expected_source;
    std::uint64_t resource_bytes = 0, resource_blocks = 0, resource_first_block = 100;

    static bool UsesResourceFork(unsigned type) { return type == 4 || type == 8 || type == 10 || type == 12 || type == 14; }

    bool Initialize(unsigned type, bool corrupt = false, bool omit_name = false, bool external_finder = false,
        bool archive_clear = false, std::uint64_t quota_blocks = 0)
    {
        using namespace apfsaccess::rw;
        auto builder = TwoProjectableVolumeStore();
        builder.volumes.resize(1);
        builder.authoritative_checkpoint = true; builder.dual_checkpoint = false; builder.xid = 20;
        // These callbacks publish several generations while retaining source proof.
        builder.authoritative_internal_pool_blocks = 16;
        builder.authoritative_checkpoint_ring_blocks = 16;
        auto& volume = builder.volumes.front();
        volume.quota_block_count = quota_blocks;
        auto& records = volume.filesystem_records;
        apfsaccess::catalog::BtreeRecord encoded;
        std::string error;
        const auto add = [&](bool ok) { if (ok) records.push_back(encoded); return ok; };
        AppleInodeRecord root;
        root.object_id = root.private_id = root.parent_id = 2; root.mode = 0040755; root.children_or_links = 2;
        if (!add(EncodeAppleInodeRecord(root, encoded, error))) return false;
        auto content = HostCompressionHex("68656c6c6f");
        auto resource = type == 4 ? HostCompressionResource({kHostCompressionA64k, kHostCompressionHello}) :
            std::vector<std::byte>{std::byte{0x46}, std::byte{0x00}, std::byte{0x80}};
        if (type == 4) content.insert(content.begin(), 65536, std::byte{'A'});
        eof = content.size();
        auto marker = HostCompressionAttribute(type, eof,
            type == 4 ? std::vector<std::byte>{} : type == 1 ? content : kHostCompressionHello);
        if (type == 7 || type == 11 || type == 8 || type == 12)
        {
            auto payload = HostCompressionHex("e568656c6c6f0600000000000000");
            if (type == 11) { content = HostCompressionModernPattern(); payload = kHostCompressionLzfseV2; }
            if (type == 8 || type == 12)
            {
                // Both forks span multiple physical blocks and decode across
                // 64 KiB. At least one block uses actual compression.
                auto first = HostCompressionHex("400141");
                for (unsigned i = 0; i < 241; ++i)
                { first.push_back(std::byte{0xf0}); first.push_back(std::byte{0xff}); }
                const auto ending = HostCompressionHex("f0cd0600000000000000");
                first.insert(first.end(), ending.begin(), ending.end());
                auto tail = HostCompressionModernPattern();
                if (type == 8) tail.insert(tail.begin(), std::byte{0x06}); // LZVN raw block.
                else
                {
                    // LZFSE raw bvx- block plus EOS, as in the bridge fixture.
                    first = HostCompressionHex("6276782d00000100");
                    first.insert(first.end(), 65536, std::byte{'A'});
                    const auto eos_bytes = HostCompressionHex("62767824");
                    first.insert(first.end(), eos_bytes.begin(), eos_bytes.end());
                    tail = kHostCompressionLzfseV2;
                }
                resource.assign(12, std::byte{});
                apfsaccess::testfixture::PutU32LE(resource, 0, 12);
                apfsaccess::testfixture::PutU32LE(resource, 4, static_cast<std::uint32_t>(12 + first.size()));
                apfsaccess::testfixture::PutU32LE(resource, 8, static_cast<std::uint32_t>(12 + first.size() + tail.size()));
                resource.insert(resource.end(), first.begin(), first.end());
                resource.insert(resource.end(), tail.begin(), tail.end());
                content.assign(65536, std::byte{'A'});
                const auto plain_tail = HostCompressionModernPattern();
                content.insert(content.end(), plain_tail.begin(), plain_tail.end());
                payload.clear();
            }
            eof = content.size();
            marker = HostCompressionAttribute(type, eof, payload);
        }
        if (type == 9 || type == 10 || type == 13 || type == 14)
        {
            // One literal bitmap seeds ABCDEFGH; three back-references repeat
            // it to 32 bytes. Frozen independently from the range codec tests.
            const auto bitmap = HostCompressionHex(
                "5a424d092a000020000017000017000017000041424344454647484344ff00000000000000000000000000000000060000000000");
            std::vector<std::byte> bitmap_plain(32);
            for (std::size_t i = 0; i < bitmap_plain.size(); ++i) bitmap_plain[i] = std::byte('A' + i % 8);
            const auto encode = [type](const std::vector<std::byte>& plain) {
                if (type == 9 || type == 10)
                {
                    std::vector<std::byte> bytes{std::byte{0xcc}};
                    bytes.insert(bytes.end(), plain.begin(), plain.end());
                    return bytes;
                }
                // ZBM's internal chunks are at most 32 KiB, independently of
                // the enclosing APFS resource codec's 64 KiB block size.
                auto bytes = HostCompressionHex("5a424d09");
                for (std::size_t offset = 0; offset < plain.size();)
                {
                    const auto chunk = (std::min)(std::size_t{32768}, plain.size() - offset);
                    for (const auto count : {chunk + 6, chunk})
                        for (unsigned i = 0; i < 3; ++i) bytes.push_back(std::byte((count >> (8*i)) & 255));
                    bytes.insert(bytes.end(), plain.begin() + offset, plain.begin() + offset + chunk);
                    offset += chunk;
                }
                const auto end = HostCompressionHex("060000000000");
                bytes.insert(bytes.end(), end.begin(), end.end());
                return bytes;
            };
            if (type == 13) content = bitmap_plain;
            auto payload = type == 13 ? bitmap : encode(content);
            if (UsesResourceFork(type))
            {
                const auto first = encode(std::vector<std::byte>(65536, std::byte{'A'}));
                const auto tail = type == 14 ? bitmap_plain : HostCompressionModernPattern();
                const auto second = type == 14 ? bitmap : encode(tail);
                resource.assign(12, std::byte{});
                apfsaccess::testfixture::PutU32LE(resource, 0, 12);
                apfsaccess::testfixture::PutU32LE(resource, 4, static_cast<std::uint32_t>(12 + first.size()));
                apfsaccess::testfixture::PutU32LE(resource, 8, static_cast<std::uint32_t>(12 + first.size() + second.size()));
                resource.insert(resource.end(), first.begin(), first.end());
                resource.insert(resource.end(), second.begin(), second.end());
                content.assign(65536, std::byte{'A'});
                content.insert(content.end(), tail.begin(), tail.end());
                payload.clear();
            }
            eof = content.size();
            marker = HostCompressionAttribute(type, eof, payload);
        }
        expected_source = content;
        if (corrupt)
        {
            if (UsesResourceFork(type))
            {
                if (type == 10)
                {
                    // A wrong raw marker leaves the whole offset table valid:
                    // the first block reads, but preparing the full tail fails.
                    const auto tail_offset = 12 + 65537;
                    resource.at(tail_offset) = std::byte{0xcd};
                }
                else resource.pop_back();
                // Keep modern tables valid so the first block remains readable;
                // full-source preparation must discover the truncated final block.
                if (type == 8 || type == 10 || type == 12 || type == 14)
                    apfsaccess::testfixture::PutU32LE(resource, 8, static_cast<std::uint32_t>(resource.size()));
            }
            else if (type == 7 || type == 9 || type == 11 || type == 13) marker.pop_back();
            else marker.back() ^= std::byte{1};
        }
        AppleInodeRecord inode;
        inode.object_id = inode.private_id = 17; inode.parent_id = 2; inode.children_or_links = 2;
        inode.mode = 0100640; inode.owner = 501; inode.group = 20;
        inode.bsd_flags = kAppleBsdCompressedFlag; inode.uncompressed_size = eof;
        inode.create_time = inode.modification_time = inode.change_time = inode.access_time = 1700000000000000000ULL;
        AppleExtendedField stream; stream.type = 8; stream.data.resize(40); inode.extended_fields.push_back(stream);
        AppleExtendedField name; name.type = 4;
        const std::string primary("compressed\0", 11);
        name.data.assign(reinterpret_cast<const std::byte*>(primary.data()),
            reinterpret_cast<const std::byte*>(primary.data() + primary.size()));
        if (!omit_name) inode.extended_fields.push_back(name);
        if (!add(EncodeAppleInodeRecord(inode, encoded, error))) return false;
        if (archive_clear)
        {
            const auto value = EncodeWindowsAttributes(0);
            if (!add(EncodeAppleXattrRecord({17, kWindowsAttributesName, kAppleXattrDataEmbedded,
                    {value.begin(), value.end()}}, encoded, error))) return false;
        }
        for (const auto sibling : {700ULL, 701ULL})
        {
            const auto leaf = sibling == 700 ? "compressed" : "alias";
            AppleDirectoryRecord link;
            link.parent_id = 2; link.file_id = 17; link.flags = 8; link.name_utf8 = leaf; link.date_added = sibling;
            if (!add(EncodeAppleDirectoryRecord(link, encoded, error)) ||
                !add(EncodeAppleSiblingLinkRecord({17, sibling, 2, leaf}, encoded, error)) ||
                !add(EncodeAppleSiblingMapRecord({sibling, 17}, encoded, error))) return false;
        }
        if (!add(EncodeAppleXattrRecord({17, "com.apple.decmpfs", kAppleXattrDataEmbedded, marker}, encoded, error)) ||
            (!external_finder && !add(EncodeAppleXattrRecord({17, "com.apple.FinderInfo", kAppleXattrDataEmbedded,
                std::vector<std::byte>(32, std::byte{0x46})}, encoded, error)))) return false;
        std::vector<std::byte> descriptor(kAppleXattrDataStreamBytes);
        resource_bytes = resource.size();
        resource_blocks = (resource_bytes + 4095) / 4096;
        // Block 103 belongs exclusively to the external FinderInfo fixture.
        resource_first_block = resource_blocks > 1 ? 104 : 100;
        const auto resource_allocation = resource_blocks * 4096;
        apfsaccess::testfixture::PutU64LE(descriptor, 0, 777);
        apfsaccess::testfixture::PutU64LE(descriptor, 8, resource.size());
        apfsaccess::testfixture::PutU64LE(descriptor, 16, resource_allocation);
        if (!add(EncodeAppleXattrRecord({17, "com.apple.ResourceFork", kAppleXattrDataStream, descriptor}, encoded, error)) ||
            !add(EncodeAppleDataStreamIdRecord({777, 1}, encoded, error)) ||
            !add(EncodeAppleFileExtentRecord({777, 0, resource_allocation, resource_first_block, 0, 4096}, encoded, error)) ||
            !EncodeApplePhysicalExtentRecord({resource_first_block, resource_blocks, kApplePhysicalExtentKindNew, 777, 1}, encoded, error)) return false;
        volume.extentref_records.push_back(encoded);
        volume.additional_file_system_allocated_blocks += resource_blocks;
        resource.resize(static_cast<std::size_t>(resource_allocation));
        for (std::uint64_t i = 0; i < resource_blocks; ++i)
        {
            const auto begin = resource.begin() + static_cast<std::size_t>(i * 4096);
            // Seed each nonzero block so BuildStoreImage's spaceman bitmap
            // reserves the complete fork as well as its extent/refcount graph.
            builder.authoritative_seeded_main_blocks.push_back({resource_first_block + i, {begin, begin + 4096}});
        }
        if (external_finder)
        {
            apfsaccess::testfixture::PutU64LE(descriptor, 0, 778);
            apfsaccess::testfixture::PutU64LE(descriptor, 8, 32);
            apfsaccess::testfixture::PutU64LE(descriptor, 16, 4096);
            if (!add(EncodeAppleXattrRecord({17, "com.apple.FinderInfo", kAppleXattrDataStream, descriptor}, encoded, error)) ||
                !add(EncodeAppleDataStreamIdRecord({778, 1}, encoded, error)) ||
                !add(EncodeAppleFileExtentRecord({778, 0, 4096, 103, 0, 4096}, encoded, error)) ||
                !EncodeApplePhysicalExtentRecord({103, 1, kApplePhysicalExtentKindNew, 778, 1}, encoded, error)) return false;
            volume.extentref_records.push_back(encoded); ++volume.additional_file_system_allocated_blocks;
            builder.authoritative_seeded_main_blocks.push_back({103, std::vector<std::byte>(4096, std::byte{0x46})});
        }
        return SortAppleBtreeRecords(records, AppleBtreeKeyOrder::FileSystemCaseSensitive, error) &&
            SortAppleBtreeRecords(volume.extentref_records, AppleBtreeKeyOrder::PhysicalExtent, error) &&
            WriteFileBytes(fixture.image.path, apfsaccess::testfixture::BuildStoreImage(builder)) && fixture.Initialize(false);
    }
};

apfsaccess::fshost::NativeCompressionRewrite::Admission HostCompressionRewrite211Admission()
{
    apfsaccess::fshost::NativeCompressionRewrite::Admission admission;
    admission.native_writes_admitted = true; admission.visibility_unresolved = false;
    admission.manifest_session = false; admission.windows_attributes_pending = false;
    admission.publication_budget_bytes = apfsaccess::rw::CompressionRewrite::MaxLogicalBytes;
    return admission;
}

bool TestNativeCompressionRewritePreparation211(unsigned only_type = 0)
{
    using Helper = apfsaccess::fshost::NativeCompressionRewrite;
    using Failure = Helper::Failure;
    using Store = apfsaccess::rw::MetadataStore;
    if (!Require(ToLowerInvariant(std::filesystem::temp_directory_path().root_name().wstring()) == L"d:",
            "compression preparation requires runner TEMP/TMP on D: before fixture construction")) return false;
    std::uint64_t bytes = 99;
    if (!Require(Helper::PublicationBytes(1, 4096, bytes) && bytes == 4096 &&
            Helper::PublicationBytes(65541, 4096, bytes) && bytes == 69632 &&
            Helper::PublicationBytes(apfsaccess::rw::CompressionRewrite::MaxLogicalBytes, 4096, bytes) &&
            bytes == apfsaccess::rw::CompressionRewrite::MaxLogicalBytes &&
            !Helper::PublicationBytes(UINT64_MAX, 4096, bytes) && bytes == 0 &&
            !Helper::PublicationBytes(5, 0, bytes) && !Helper::PublicationBytes(5, 4095, bytes),
            "full EOF including padding is bounded independently of dirty bytes")) return false;
    for (const auto type : only_type ? std::vector<unsigned>{only_type} : std::vector<unsigned>{1u, 3u, 4u})
    {
        HostCompressionRewrite211Fixture owned;
        if (!Require(owned.Initialize(type), "host preparation canonical compressed fixture initializes")) return false;
        auto& c = *owned.fixture.context; auto& store = *c.metadata_store; auto& tx = *c.tx_manager;
        const auto before_image = ReadFileBytes(owned.fixture.image.path);
        const auto inode = store.LookupCommittedInodeByPath(L"\\alias");
        if (!Require(inode.has_value() && tx.Begin(), "empty caller-owned transaction starts")) return false;
        const auto before_wal = ReadFileBytes(c.session_root / "accepted.wal");
        const Store::PayloadIdentity identity{inode->object_id, inode->xid};
        auto admission = HostCompressionRewrite211Admission();
        Failure reason;
        auto prepared = Helper::Prepare(store, tx, admission, L"\\alias", identity, 1, 1, reason);
        if (!Require(prepared.has_value() && reason == Failure::None && prepared->LogicalEof() == owned.eof &&
                prepared->JournalIntent().generation == inode->xid &&
                prepared->JournalIntent().length == prepared->Request().inline_payload.size() &&
                prepared->JournalIntent().payload_length == prepared->JournalIntent().length &&
                prepared->Revalidate(store, tx, admission) == Failure::None,
                "native evidence becomes immutable source request and source-identity WAL intent")) return false;
        apfsaccess::rw::CompressionRewrite proof;
        std::vector<std::byte> source;
        if (!Require(apfsaccess::rw::DecodeCompressionRewrite(prepared->Request().inline_payload, proof) &&
                proof.type == type && proof.size == owned.expected_source.size() &&
                proof.resource.size() == owned.resource_bytes &&
                store.ReadCommittedFileRange(L"\\alias", 0, owned.eof, source) && source == owned.expected_source,
                "prepared proof retains the entire allocated source fork and independently expected logical bytes")) return false;
        const auto denied = [&](Helper::Admission options, Store::PayloadIdentity id,
                                std::uint64_t offset, std::uint64_t length, Failure expected) {
            return !Helper::Prepare(store, tx, options, L"\\alias", id, offset, length, reason) && reason == expected;
        };
        auto options = admission; options.native_writes_admitted = false;
        if (!Require(denied(options, identity, 1, 1, Failure::AdmissionClosed), "closed host admission refuses")) return false;
        options = admission; options.visibility_unresolved = true;
        if (!Require(denied(options, identity, 1, 1, Failure::AdmissionClosed), "unresolved durability refuses")) return false;
        options = admission; options.manifest_session = true;
        if (!Require(denied(options, identity, 1, 1, Failure::AdmissionClosed), "unwired manifest identity binder refuses")) return false;
        options = admission; options.windows_attributes_pending = true;
        if (!Require(denied(options, identity, 1, 1, Failure::ArchiveUpdateRequired), "archive xattr cannot join conversion")) return false;
        options = admission; options.queued_requests = 1;
        if (!Require(denied(options, identity, 1, 1, Failure::TransactionNotEmpty), "older queued work refuses")) return false;
        options = admission; options.publication_budget_bytes = prepared->PublicationByteReservation() - 1;
        if (!Require(denied(options, identity, 1, 1, Failure::BudgetExceeded), "one-byte edit requires full EOF budget")) return false;
        options.publication_budget_bytes = prepared->PublicationByteReservation() + 7;
        options.reserved_publication_bytes = 7;
        if (!Require(Helper::Prepare(store, tx, options, L"\\alias", identity, 1, 1, reason).has_value(),
                "exact remaining full-EOF budget is admitted")) return false;
        options = admission; options.reserved_publication_bytes = UINT64_MAX;
        if (!Require(denied(options, identity, 1, 1, Failure::BudgetExceeded) &&
                denied(admission, {identity.object_id + 1, identity.generation}, 1, 1, Failure::IdentityMismatch) &&
                denied(admission, {identity.object_id, identity.generation + 1}, 1, 1, Failure::IdentityMismatch) &&
                denied(admission, identity, owned.eof, 1, Failure::RangeUnsupported) &&
                denied(admission, identity, 1, UINT64_MAX, Failure::RangeUnsupported) &&
                denied(admission, identity, 0, 0, Failure::RangeUnsupported),
                "budget overflow, replaced identity, EOF growth, overflow and no-op refuse")) return false;
        Store::MutationRequest write;
        if (!Require(!prepared->PrepareWrite(store, identity, L"\\compressed", 1, 1, write) &&
                store.PendingMutationCount() == 0 && store.PendingAllocationCount() == 0 &&
                tx.PendingMutationCount() == 0 && ReadFileBytes(owned.fixture.image.path) == before_image &&
                ReadFileBytes(c.session_root / "accepted.wal") == before_wal,
                "preparation and all refusals preserve image, working state, allocator and WAL")) return false;
        if (!Require(tx.Abort() && tx.Begin() && prepared->Revalidate(store, tx, admission) == Failure::SourceChanged,
                "an aborted transaction cannot reuse prepared evidence even at the same checkpoint")) return false;
        (void)tx.Abort();
    }
    for (const auto type : only_type ? std::vector<unsigned>{only_type} : std::vector<unsigned>{3u, 4u, 2u})
    {
        HostCompressionRewrite211Fixture owned;
        if (!Require(owned.Initialize(type, type != 2), "corrupt or unsupported compressed source imports for refusal")) return false;
        auto& store = *owned.fixture.context->metadata_store; auto& tx = *owned.fixture.context->tx_manager;
        const auto inode = store.LookupCommittedInodeByPath(L"\\alias");
        if (!inode || !tx.Begin()) return false;
        const auto before = ReadFileBytes(owned.fixture.image.path);
        const auto before_wal = ReadFileBytes(owned.fixture.context->session_root / "accepted.wal");
        if (type == 8 || type == 10 || type == 12 || type == 14)
        {
            std::vector<std::byte> first;
            if (!Require(store.ReadCommittedFileRange(L"\\alias", 0, 1, first) &&
                    first == std::vector<std::byte>{std::byte{'A'}},
                    "corrupt modern resource fixture has a readable first block before its malformed tail")) return false;
            auto fs = BuildFileSystem(owned.fixture.context.get());
            OpenContext reader{};
            reader.node = FindNode(owned.fixture.context.get(), L"\\alias");
            reader.metadata_read_fallback = true;
            InitializeOpenAccess(&reader, FILE_READ_DATA);
            std::vector<std::byte> guarded(static_cast<std::size_t>(owned.eof) + 17, std::byte{0xa6});
            const auto sentinel = guarded;
            ULONG done = 999;
            if (!Require(CB_Read(&fs, &reader, guarded.data(), 0, static_cast<ULONG>(owned.eof), &done) ==
                    STATUS_NOT_SUPPORTED && done == 0 && guarded == sentinel,
                    "late malformed block cannot publish a decoded prefix or touch caller buffer guards")) return false;
        }
        Failure reason;
        const auto prepared = Helper::Prepare(store, tx, HostCompressionRewrite211Admission(), L"\\alias",
            {inode->object_id, inode->xid}, 0, 1, reason);
        if (!Require(!prepared && reason == Failure::SourceUnsupported && !store.PendingMutationCount() &&
                !store.PendingAllocationCount() && !store.PendingDeallocationCount() && !tx.PendingMutationCount() &&
                ReadFileBytes(owned.fixture.image.path) == before &&
                ReadFileBytes(owned.fixture.context->session_root / "accepted.wal") == before_wal,
                "complete-source validation rejects corruption beyond the edit or unsupported type before mutation")) return false;
        (void)tx.Abort();
    }
    return true;
}

bool TestNativeCompressionRewriteWal211(unsigned only_type = 0)
{
    using namespace apfsaccess::rw;
    using Helper = apfsaccess::fshost::NativeCompressionRewrite;
    if (!Require(ToLowerInvariant(std::filesystem::temp_directory_path().root_name().wstring()) == L"d:",
            "compression WAL requires runner TEMP/TMP on D: before fixture construction")) return false;
    for (const auto type : only_type ? std::vector<unsigned>{only_type} : std::vector<unsigned>{1u, 3u, 4u})
    {
        HostCompressionRewrite211Fixture owned;
        if (!owned.Initialize(type)) return false;
        auto& c = *owned.fixture.context; auto& store = *c.metadata_store; auto& tx = *c.tx_manager;
        const auto before_image = ReadFileBytes(owned.fixture.image.path);
        const auto inode = store.LookupCommittedInodeByPath(L"\\alias");
        if (!inode || !tx.Begin()) return false;
        auto admission = HostCompressionRewrite211Admission();
        Helper::Failure failure;
        const auto prepared = Helper::Prepare(store, tx, admission, L"\\alias",
            {inode->object_id, inode->xid}, 1, 1, failure);
        if (!prepared || prepared->Revalidate(store, tx, admission) != Helper::Failure::None) return false;
        // Actual existing WAL and native staging APIs. No canonical publication
        // is attempted by this focused preparation/acceptance fixture.
        MetadataStore::PayloadIdentity target;
        const MetadataStore::PayloadIdentity source_identity{inode->object_id, inode->xid};
        const MetadataStore::PayloadIdentity wrong_source{inode->object_id, prepared->PreimageCheckpoint() + 1};
        const auto& conversion = prepared->Request();
        if (!Require(!RecordMutationBestEffort(&c, TransactionManager::MutationKind::RewriteCompressedContent,
                conversion.path, L"", 0, conversion.inline_payload.size(), false, 0, 0,
                &wrong_source, nullptr, conversion.inline_payload) && !tx.PendingMutationCount(),
                "host journal rejects target incarnation as immutable conversion source before recording")) return false;
        bool staged = false;
        if (!Require(RecordNativeMutationBestEffort(&c, MetadataStore::MutationOperation::RewriteCompressedContent,
                conversion.path, L"", 0, conversion.inline_payload.size(), false, 0, &target, &staged,
                nullptr, 3, conversion.inline_payload) && staged &&
                RecordMutationBestEffort(&c, TransactionManager::MutationKind::RewriteCompressedContent,
                    conversion.path, L"", 0, conversion.inline_payload.size(), false, 0, 0,
                    &source_identity, nullptr, conversion.inline_payload) &&
                target.object_id == inode->object_id && target.generation == prepared->PreimageCheckpoint() + 1,
                "conversion is journaled first with source identity and stages a distinct target identity")) return false;
        if (!Require(prepared->Revalidate(store, tx, admission) == Helper::Failure::TransactionNotEmpty,
                "prepared conversion cannot be admitted a second time into its staged transaction")) return false;
        MetadataStore::MutationRequest write;
        if (!Require(!prepared->PrepareWrite(store, {target.object_id, inode->xid}, L"\\alias", 1, 1, write) &&
                !prepared->PrepareWrite(store, target, L"\\missing", 1, 1, write) &&
                !prepared->PrepareWrite(store, target, L"\\alias", owned.eof, 1, write) &&
                prepared->PrepareWrite(store, target, L"\\compressed", 1, 1, write),
                "follow-up writes require conversion target incarnation and same-owner alias within source EOF")) return false;
        const auto timestamp = UtcNow();
        MetadataStore::MutationRequest times;
        times.operation = MetadataStore::MutationOperation::SetInodeMetadata; times.path = L"\\alias";
        times.object_id = target.object_id; times.generation = target.generation;
        times.inline_payload = EncodeContentTimes(timestamp); times.length = times.inline_payload.size();
        if (!Require(store.StageMutation(times) == MetadataStore::MutationStatus::Applied &&
                JournalContentTimes(&c, times.path, timestamp, target) &&
                store.StageMutation(write) == MetadataStore::MutationStatus::Applied,
                "existing host canonical content-time journal follows conversion and precedes alias edit")) return false;
        const std::byte edited{0x5a};
        std::uint64_t accepted_sequence = 0;
        if (!Require(RecordPayloadWriteMutationBestEffort(&c, write.path, 1, &edited, 1, &target) &&
                AcceptMutationJournalForDeferredCommitBestEffort(&c, L"CompressionRewrite211", &accepted_sequence,
                    nullptr, nullptr, true, prepared->PreimageCheckpoint()) && accepted_sequence != 0,
                "existing host acceptance flushes required payload/WAL and accepts conversion, times and edit together")) return false;
        std::vector<TransactionManager::AcceptedTransaction> accepted;
        std::string error;
        if (!Require(tx.LoadUnappliedAcceptedTransactions(accepted, &error) && accepted.size() == 1 &&
                Helper::AcceptedBatchIsConsistent(accepted.front(), store.Context().volume_object_id),
                "actual accepted WAL retains exact preimage and bounded conversion-first shape")) return false;
        const auto& batch = accepted.front();
        MetadataStore::MutationRequest replay;
        if (!Require(batch.mutations.size() == 3 && Helper::ReplayRequest(batch.mutations.front(), replay) &&
                replay.object_id == prepared->Request().object_id && replay.generation == prepared->Request().generation &&
                replay.inline_payload == prepared->Request().inline_payload &&
                replay.length == replay.inline_payload.size(), "native operation-15 reconstruction preserves immutable CRW1 bytes")) return false;
        const auto invalid = [&](auto change) {
            auto candidate = batch; change(candidate);
            return !Helper::AcceptedBatchIsConsistent(candidate, store.Context().volume_object_id);
        };
        if (!Require(invalid([](auto& b) { ++b.preimage_checkpoint_xid; }) &&
                invalid([](auto& b) { ++b.mutations[0].parent_object_id; }) &&
                invalid([](auto& b) { b.mutations[0].inline_payload.back() ^= std::byte{1}; }) &&
                invalid([](auto& b) { b.mutations[0].payload_sha256[0] ^= 1; }) &&
                invalid([](auto& b) { b.mutations[0].payload_spool_id = 1; }) &&
                invalid([](auto& b) { std::swap(b.mutations[0], b.mutations[1]); }) &&
                invalid([](auto& b) { b.mutations[1] = b.mutations[0]; }) &&
                invalid([](auto& b) { ++b.mutations[2].object_id; }) &&
                invalid([&](auto& b) { b.mutations[2].parent_object_id = inode->xid; }) &&
                invalid([&](auto& b) { b.mutations[2].logical_offset = owned.eof; }) &&
                invalid([](auto& b) { b.mutations[2].logical_length = UINT64_MAX; }) &&
                invalid([](auto& b) { b.mutations[2].operation = WriteAheadLog::OperationKind::SetFileSize; }) &&
                invalid([](auto& b) { b.mutations[1].operation = WriteAheadLog::OperationKind::SetExtendedAttribute; }) &&
                invalid([](auto& b) { b.mutations[2].transaction_id++; }) &&
                invalid([](auto& b) { b.mutations[2].sequence = b.mutations[1].sequence; }) &&
                invalid([](auto& b) { b.mutations[2].path_utf8 = std::string("\\bad") + char(0xff); }) &&
                invalid([](auto& b) { b.mutations.pop_back(); }) &&
                !Helper::AcceptedBatchIsConsistent(batch, store.Context().volume_object_id + 1),
                "replay rejects rebasing, source tampering, reordered/foreign/oversized writes, xattrs and conversion-only batches")) return false;
        MetadataStore::MutationRequest original;
        const auto working = store.LookupWorkingInodeByPath(L"\\compressed");
        if (!Require(store.PrepareCompressionRewrite(L"\\alias", original) && original.inline_payload == replay.inline_payload &&
                working && working->owner == inode->owner && working->group == inode->group && working->mode == inode->mode &&
                working->create_time_utc == inode->create_time_utc && working->access_time_utc == inode->access_time_utc &&
                store.LookupWorkingExtendedAttribute(17, "com.apple.FinderInfo").has_value() &&
                !store.LookupWorkingExtendedAttribute(17, "com.apple.decmpfs") &&
                store.LookupWorkingExtendedAttribute(17, "com.apple.ResourceFork").has_value() == !owned.UsesResourceFork(type) &&
                tx.HasUnappliedAcceptedWork() && ReadFileBytes(owned.fixture.image.path) == before_image,
                "acceptance alone preserves on-disk Mac metadata and source proof; pending removal is compression-owned only")) return false;
    }
    return true;
}
