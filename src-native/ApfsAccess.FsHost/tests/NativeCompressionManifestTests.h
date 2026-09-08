#pragma once
// Include after the compression fixtures. These selectors require D: TEMP/TMP
// before constructing any regular image; they do not mount WinFsp.

struct NativeCompressionManifest266Fixture
{
    using Store = apfsaccess::rw::MetadataStore;
    DirectorySymlinkFixture fixture{true};
    MountContext sibling;
    std::vector<std::byte> original;

    bool Initialize(unsigned type, bool archive_clear = false, bool corrupt = false)
    {
        using namespace apfsaccess::rw;
        auto builder = TwoProjectableVolumeStore();
        builder.authoritative_checkpoint = true; builder.dual_checkpoint = false; builder.xid = 20;
        builder.authoritative_internal_pool_blocks = 32;
        builder.authoritative_checkpoint_ring_blocks = 32;
        builder.block_count = 1024;
        auto& volume = builder.volumes.front();
        auto& records = volume.filesystem_records;
        apfsaccess::catalog::BtreeRecord encoded;
        std::string error;
        const auto add = [&](bool ok) { if (ok) records.push_back(encoded); return ok; };
        AppleInodeRecord root;
        root.object_id = root.private_id = root.parent_id = 2; root.mode = 0040755; root.children_or_links = 2;
        if (!add(EncodeAppleInodeRecord(root, encoded, error))) return false;
        original = HostCompressionHex("68656c6c6f");
        auto resource = type == 4 ? HostCompressionResource({kHostCompressionA64k, kHostCompressionHello}) :
            std::vector<std::byte>{std::byte{0x46}, std::byte{0}, std::byte{0x80}};
        if (type == 4) original.insert(original.begin(), 65536, std::byte{'A'});
        auto marker = HostCompressionAttribute(type, original.size(),
            type == 4 ? std::vector<std::byte>{} : type == 1 ? original : kHostCompressionHello);
        if (corrupt)
        {
            // Preserve the fork envelope and first block. Only decoding the
            // second block discovers its invalid zlib checksum.
            auto bad_second = kHostCompressionHello;
            bad_second.back() ^= std::byte{1};
            resource = HostCompressionResource({kHostCompressionA64k, bad_second});
        }
        AppleInodeRecord inode;
        inode.object_id = inode.private_id = 17; inode.parent_id = 2; inode.children_or_links = 2;
        inode.mode = 0100640; inode.owner = 501; inode.group = 20;
        inode.bsd_flags = kAppleBsdCompressedFlag; inode.uncompressed_size = original.size();
        inode.create_time = inode.modification_time = inode.change_time = inode.access_time = 1700000000000000000ULL;
        AppleExtendedField stream; stream.type = 8; stream.data.resize(40); inode.extended_fields.push_back(stream);
        AppleExtendedField name; name.type = 4;
        const std::string primary("compressed\0", 11);
        name.data.assign(reinterpret_cast<const std::byte*>(primary.data()),
            reinterpret_cast<const std::byte*>(primary.data() + primary.size()));
        inode.extended_fields.push_back(name);
        if (!add(EncodeAppleInodeRecord(inode, encoded, error))) return false;
        for (const auto id : {700ULL, 701ULL})
        {
            const auto leaf = id == 700 ? "compressed" : "alias";
            AppleDirectoryRecord link;
            link.parent_id = 2; link.file_id = 17; link.flags = 8; link.name_utf8 = leaf; link.date_added = id;
            if (!add(EncodeAppleDirectoryRecord(link, encoded, error)) ||
                !add(EncodeAppleSiblingLinkRecord({17, id, 2, leaf}, encoded, error)) ||
                !add(EncodeAppleSiblingMapRecord({id, 17}, encoded, error))) return false;
        }
        const auto attributes = EncodeWindowsAttributes(archive_clear ? 0 : FILE_ATTRIBUTE_ARCHIVE);
        if (!add(EncodeAppleXattrRecord({17, kWindowsAttributesName, kAppleXattrDataEmbedded,
                {attributes.begin(), attributes.end()}}, encoded, error)) ||
            !add(EncodeAppleXattrRecord({17, "com.apple.decmpfs", kAppleXattrDataEmbedded, marker}, encoded, error)) ||
            !add(EncodeAppleXattrRecord({17, "com.apple.FinderInfo", kAppleXattrDataEmbedded,
                std::vector<std::byte>(32, std::byte{0x46})}, encoded, error))) return false;
        std::vector<std::byte> descriptor(kAppleXattrDataStreamBytes);
        apfsaccess::testfixture::PutU64LE(descriptor, 0, 777);
        apfsaccess::testfixture::PutU64LE(descriptor, 8, resource.size());
        apfsaccess::testfixture::PutU64LE(descriptor, 16, 4096);
        if (!add(EncodeAppleXattrRecord({17, "com.apple.ResourceFork", kAppleXattrDataStream, descriptor}, encoded, error)) ||
            !add(EncodeAppleDataStreamIdRecord({777, 1}, encoded, error)) ||
            !add(EncodeAppleFileExtentRecord({777, 0, 4096, 200, 0, 4096}, encoded, error)) ||
            !EncodeApplePhysicalExtentRecord({200, 1, kApplePhysicalExtentKindNew, 777, 1}, encoded, error)) return false;
        volume.extentref_records.push_back(encoded); ++volume.additional_file_system_allocated_blocks;
        resource.resize(4096); builder.authoritative_seeded_main_blocks.push_back({200, resource});
        if (!SortAppleBtreeRecords(records, AppleBtreeKeyOrder::FileSystemCaseSensitive, error) ||
            !SortAppleBtreeRecords(volume.extentref_records, AppleBtreeKeyOrder::PhysicalExtent, error) ||
            !WriteFileBytes(fixture.image.path, apfsaccess::testfixture::BuildStoreImage(builder)) ||
            !fixture.Initialize(true)) return false;
        auto& c = *fixture.context;
        c.args.write_require_canonical_commit = true;
        sibling.args = ManifestSessionArgs(fixture.image.path, 102,
            Utf8ToWide(fixture.coordinator->ContainerUuidHex()), L"private-beta-266", true);
        sibling.args.write_require_canonical_commit = true;
        sibling.args.allow_legacy_scaffold_for_fixtures = false;
        std::wstring mount_error;
        return Require(MountManifestSession(*fixture.coordinator, sibling.args, sibling, mount_error),
            "manifest compression: prepare real second-volume session");
    }

    bool PublishSibling(const std::wstring& path)
    {
        Store::MutationRequest create;
        create.operation = Store::MutationOperation::CreateFile; create.path = path;
        return Require(CommitManifestMutations(&sibling, {create}).status == Store::CommitStatus::Committed,
            "manifest compression: sibling publishes through real container commit");
    }
};

bool TestNativeCompressionManifest266(bool tamper)
{
    using Store = apfsaccess::rw::MetadataStore;
    using Tx = apfsaccess::rw::TransactionManager;
    using Wal = apfsaccess::rw::WriteAheadLog;
    using Replay = apfsaccess::fshost::NativeCompressionReplay;
    if (!CompressionReplay222ScratchReady()) return false;
    bool passed = true;
    for (const auto type : {1u, 3u, 4u})
    for (const auto policy : {L"FailClosed", L"BestEffort"})
    {
        NativeCompressionManifest266Fixture f;
        if (!Require(f.Initialize(type), "manifest compression: native two-volume source initializes")) return false;
        auto& c = *f.fixture.context;
        c.args.write_recovery_policy = policy;
        auto fs = BuildFileSystem(&c);
        const auto initial = c.metadata_store->LookupCommittedInodeByPath(L"\\compressed");
        const auto finder = c.metadata_store->LookupCommittedExtendedAttribute(17, "com.apple.FinderInfo");
        const auto fork = c.metadata_store->LookupCommittedExtendedAttribute(17, "com.apple.ResourceFork");
        Store::MutationRequest stale;
        if (!Require(initial && c.metadata_store->PrepareCompressionRewrite(L"\\alias", stale),
                "manifest compression: capture source before actual sibling checkpoint")) return false;
        FSP_FSCTL_FILE_INFO info{};
        PVOID writer = nullptr, alias = nullptr;
        ScopeExit close{[&] {
            g_compressed_manifest_before_verification_hook = {};
            g_compressed_after_publication_hook = {};
            if (writer) CB_Close(&fs, writer);
            if (alias) CB_Close(&fs, alias);
        }};
        if (!Require(CB_Open(&fs, const_cast<PWSTR>(L"\\alias"), FILE_OPEN << 24,
                    GENERIC_READ | GENERIC_WRITE, &writer, &info) == STATUS_SUCCESS &&
                CB_Open(&fs, const_cast<PWSTR>(L"\\compressed"), FILE_OPEN << 24,
                    GENERIC_READ | GENERIC_WRITE, &alias, &info) == STATUS_SUCCESS,
                "manifest compression: Mac 0640 owner opens through easy Windows access with both aliases")) return false;
        if (!f.PublishSibling(L"\\before-compression")) return false;
        Store::MutationRequest older;
        older.operation = Store::MutationOperation::CreateFile; older.path = L"\\older-selected-work";
        EnqueueManifestRequest(&c, older);
        // The callback must first flush the older metadata batch. Its resulting
        // container checkpoint, following the sibling, is the conversion source.
        const auto source_xid = f.fixture.coordinator->CheckpointXid() + 1;
        bool evidence_checked = false, materialization_checked = false;
        unsigned verifier_calls = 0;
        Replay::Result actual_proof = Replay::Result::Unavailable;
        g_compressed_manifest_before_verification_hook = [&](const Store& live) {
            ++verifier_calls;
            std::vector<Tx::AcceptedTransaction> batches;
            std::vector<std::uint64_t> pins;
            if (!Require(c.tx_manager->LoadAcceptedTransactionsSinceCleanup(batches) && batches.size() == 1 &&
                    batches.front().mutations.size() == 3 &&
                    c.tx_manager->LoadRequiredCheckpointXidsSinceCleanup(pins) &&
                    pins == std::vector<std::uint64_t>{source_xid},
                    "manifest compression: verifier receives actual accepted batch and fresh source pin")) return;
            const auto& b = batches.front();
            const auto& conversion = b.mutations[0];
            apfsaccess::rw::CompressionRewrite proof;
            apfsaccess::rw::NativeApfsVolumeProjection source_projection;
            std::wstring source_error;
            if (!Require(apfsaccess::rw::NativeApfsReader::TryLoadVolumeProjection(
                    live.Device(), 101, source_projection, source_error, source_xid),
                    "manifest compression: independently read exact retained source checkpoint")) return;
            const auto source_inode = std::find_if(source_projection.inodes.begin(), source_projection.inodes.end(),
                [&](const auto& inode) { return inode.object_id == initial->object_id; });
            if (!Require(source_inode != source_projection.inodes.end(),
                    "manifest compression: retained source contains the original inode")) return;
            evidence_checked = Require(apfsaccess::rw::DecodeCompressionRewrite(conversion.inline_payload, proof) &&
                proof.preserved_attributes_sha256 && proof.type == type && proof.checkpoint == source_xid &&
                proof.volume == 101 && proof.object == initial->object_id && proof.generation == source_inode->xid &&
                conversion.operation == Wal::OperationKind::RewriteCompressedContent &&
                conversion.object_id == initial->object_id && conversion.parent_object_id == source_inode->xid &&
                conversion.inline_payload != stale.inline_payload && b.preimage_checkpoint_xid == source_xid &&
                b.mutations[1].operation == Wal::OperationKind::SetInodeMetadata &&
                b.mutations[2].operation == Wal::OperationKind::Write &&
                b.mutations[1].object_id == proof.object && b.mutations[2].object_id == proof.object &&
                b.mutations[1].parent_object_id == source_xid + 1 && b.mutations[2].parent_object_id == source_xid + 1 &&
                conversion.parent_object_id != b.mutations[2].parent_object_id && live.CheckpointXid() == source_xid + 1 &&
                c.compression_verification_pending.load() == proof.object &&
                c.tx_manager->Watermarks().apfs_durable_sequence < b.accepted_sequence &&
                !ReadFileBytes(c.payload_spool->SpoolFilePath()).empty(),
                "manifest compression: CRW2 preserves source incarnation; times/write bind actual staged successor");
            if (!evidence_checked)
                std::cerr << "manifest evidence: type=" << type << " source=" << source_xid
                    << " proof=" << proof.checkpoint << "/" << proof.generation
                    << " initial=" << initial->xid << " conversion=" << conversion.parent_object_id
                    << " times=" << b.mutations[1].parent_object_id << " write=" << b.mutations[2].parent_object_id
                    << " live=" << live.CheckpointXid().value_or(0) << " pin=" << b.preimage_checkpoint_xid
                    << " guard=" << c.compression_verification_pending.load()
                    << " durable=" << c.tx_manager->Watermarks().apfs_durable_sequence
                    << " accepted=" << b.accepted_sequence << " spool=" << ReadFileBytes(c.payload_spool->SpoolFilePath()).size()
                    << " stale-equal=" << (conversion.inline_payload == stale.inline_payload) << '\n';
            if (tamper)
            {
                apfsaccess::rw::NativeApfsVolumeProjection projection;
                std::wstring error;
                if (!Require(apfsaccess::rw::NativeApfsReader::TryLoadVolumeProjection(live.Device(), 101, projection, error),
                        "manifest compression: locate published data using native projection")) return;
                const auto found = projection.read_extents_by_inode.find(proof.object);
                if (!Require(found != projection.read_extents_by_inode.end() && !found->second.empty() &&
                        found->second.front().logical_offset == 0 && found->second.front().physical_address,
                        "manifest compression: published first extent is addressable")) return;
                std::fstream image(f.fixture.image.path, std::ios::binary | std::ios::in | std::ios::out);
                image.seekp(static_cast<std::streamoff>(found->second.front().physical_address));
                const auto value = static_cast<char>(std::to_integer<unsigned char>(f.original[0]) ^ 1);
                image.write(&value, 1); image.flush();
                if (!Require(image.good(), "manifest compression: corrupt exactly one untouched published byte")) return;
            }
            actual_proof = Replay::Verify(live, *c.tx_manager, b.accepted_sequence,
                c.payload_spool.get(), c.payload_spool_volume_identity);
        };
        g_compressed_after_publication_hook = [&](MountContext*) {
            const auto marks = c.tx_manager->Watermarks();
            PVOID observed = nullptr;
            const auto status = CB_Open(&fs, const_cast<PWSTR>(L"\\compressed"), FILE_OPEN << 24,
                GENERIC_READ, &observed, &info);
            if (observed) CB_Close(&fs, observed);
            materialization_checked = Require(status == STATUS_DEVICE_BUSY && !observed &&
                    c.compression_verification_pending.load() == 17 && marks.accepted_sequence > marks.cleanup_sequence &&
                    !FinalizeMutationJournalBestEffort(&c, L"ManifestCompressionPrematureCleanup"),
                    "manifest compression: alias admission and cleanup stay fenced before cache materialization");
            // Verification is already complete. A later sibling is now legal;
            // cleanup must rely on that completed immediate proof, not rebase it.
            materialization_checked = f.PublishSibling(L"\\after-verification") && materialization_checked;
        };
        auto expected = f.original;
        std::byte value{'Z'};
        ULONG done = 999;
        const auto status = CB_Write(&fs, writer, &value, 1, 1, FALSE, FALSE, &done, &info);
        expected[1] = value;
        g_compressed_manifest_before_verification_hook = {};
        g_compressed_after_publication_hook = {};
        if (!Require(evidence_checked && verifier_calls == 1 && actual_proof ==
                (tamper ? Replay::Result::ContentMismatch : Replay::Result::Verified),
                "manifest compression: actual native verifier reaches expected result once")) return false;
        if (!Require(c.metadata_store->LookupCommittedInodeByPath(older.path).has_value(),
                "manifest compression: older unrelated metadata publishes before fresh preparation")) return false;
        if (tamper)
        {
            const auto marks = c.tx_manager->Watermarks();
            const auto wal = ReadFileBytes(c.session_root / "accepted.wal");
            const auto spool = ReadFileBytes(c.payload_spool->SpoolFilePath());
            const auto index = ReadFileBytes(c.payload_spool->SpoolFilePath().parent_path() / "payload-spool.idx");
            const auto image = ReadFileBytes(f.fixture.image.path);
            if (!Require(!NT_SUCCESS(status) && done == 0 && marks.accepted_sequence > marks.apfs_durable_sequence &&
                    marks.accepted_sequence > marks.cleanup_sequence && c.compression_verification_pending.load() == 17 &&
                    c.write_degraded && !c.native_write_enabled && !c.overlay_write_enabled && !wal.empty() && !spool.empty(),
                    "manifest compression: both policies block actual verifier refusal and retain accepted evidence")) return false;
            const auto retained = [&] {
                const auto after = c.tx_manager->Watermarks();
                std::vector<std::uint64_t> pins;
                std::vector<Tx::AcceptedTransaction> batches;
                return Require(after.accepted_sequence == marks.accepted_sequence &&
                    after.apfs_durable_sequence == marks.apfs_durable_sequence && after.cleanup_sequence == marks.cleanup_sequence &&
                    c.tx_manager->LoadRequiredCheckpointXidsSinceCleanup(pins) && pins == std::vector<std::uint64_t>{source_xid} &&
                    c.tx_manager->LoadAcceptedTransactionsSinceCleanup(batches) && batches.size() == 1 &&
                    wal == ReadFileBytes(c.session_root / "accepted.wal") && spool == ReadFileBytes(c.payload_spool->SpoolFilePath()) &&
                    index == ReadFileBytes(c.payload_spool->SpoolFilePath().parent_path() / "payload-spool.idx") &&
                    image == ReadFileBytes(f.fixture.image.path) && !ReadFileBytes(c.recovery_marker_file).empty(),
                    "manifest compression: every failed boundary preserves WAL/spool/index/image/pins and dirty marker");
            };
            (void)CB_Flush(&fs, writer, &info); passed &= retained();
            passed &= Require(!NT_SUCCESS(CommitNativeMutationsOnFlushBestEffort(&c)) &&
                !FinalizeMutationJournalBestEffort(&c, L"ManifestCompressionRefused"),
                "manifest compression: unresolved evidence refuses drains and finalization");
            passed &= retained();
            Store::MutationRequest blocked;
            blocked.operation = Store::MutationOperation::CreateFile; blocked.path = L"\\must-not-publish";
            const auto sibling_result = CommitManifestMutations(&f.sibling, {blocked});
            passed &= Require(sibling_result.status != Store::CommitStatus::Committed &&
                    f.fixture.coordinator->CheckpointXid() == source_xid + 1,
                    "manifest compression: failed immediate verifier fences sibling publication");
            passed &= retained();
            CB_Close(&fs, writer); writer = nullptr; CB_Close(&fs, alias); alias = nullptr;
            passed &= retained();
        }
        else
        {
            if (!Require(status == STATUS_SUCCESS && done == 1 && materialization_checked &&
                    !c.compression_verification_pending.load() && !c.write_degraded,
                    "manifest compression: verified conversion materializes and completes")) return false;
            const auto first = c.tx_manager->Watermarks();
            std::vector<std::uint64_t> pins;
            if (!Require(first.accepted_sequence && first.accepted_sequence == first.apfs_durable_sequence &&
                    first.accepted_sequence == first.cleanup_sequence &&
                    c.tx_manager->LoadRequiredCheckpointXidsSinceCleanup(pins) && pins.empty() &&
                    c.payload_spool->SnapshotCounters().dirty_range_count == 0,
                    "manifest compression: accepted cleanup releases only verified evidence")) return false;
            for (const auto handle : {writer, alias})
            {
                value = handle == writer ? std::byte{'Y'} : std::byte{'X'};
                const auto offset = handle == writer ? expected.size() - 1 : 2;
                if (!Require(CB_Write(&fs, handle, &value, offset, 1, FALSE, FALSE, &done, &info) == STATUS_SUCCESS && done == 1,
                        "manifest compression: same handle and already-open alias support repeated writes")) return false;
                expected[offset] = value;
                for (const auto reader : {writer, alias})
                {
                    std::vector<std::byte> actual(expected.size());
                    if (!Require(CB_Read(&fs, reader, actual.data(), 0, static_cast<ULONG>(actual.size()), &done) == STATUS_SUCCESS &&
                            done == actual.size() && actual == expected,
                            "manifest compression: both aliases read all edits and untouched bytes")) return false;
                }
            }
            if (!Require(CB_Flush(&fs, writer, &info) == STATUS_SUCCESS,
                    "manifest compression: repeated ordinary writes flush")) return false;
            const auto final_marks = c.tx_manager->Watermarks();
            if (!Require(final_marks.accepted_sequence > first.accepted_sequence &&
                    final_marks.accepted_sequence == final_marks.apfs_durable_sequence &&
                    final_marks.accepted_sequence == final_marks.cleanup_sequence,
                    "manifest compression: repeated accepted writes finish cleanup")) return false;
            Store fresh(f.fixture.volume);
            std::vector<std::byte> actual;
            if (!Require(fresh.PrepareNativeWritePath() && fresh.ReadCommittedFileRange(L"\\compressed", 0, expected.size(), actual) &&
                    actual == expected, "manifest compression: independently reopened volume contains all edits")) return false;
            const auto after = fresh.LookupCommittedInodeByPath(L"\\compressed");
            const auto finder_after = fresh.LookupCommittedExtendedAttribute(17, "com.apple.FinderInfo");
            const auto fork_after = fresh.LookupCommittedExtendedAttribute(17, "com.apple.ResourceFork");
            if (!Require(after && after->mode == initial->mode && after->owner == initial->owner && after->group == initial->group &&
                    after->create_time_utc == initial->create_time_utc && after->access_time_utc == initial->access_time_utc &&
                    after->modification_time_utc != initial->modification_time_utc && after->change_time_utc != initial->change_time_utc &&
                    finder && finder_after && finder->flags == finder_after->flags && finder->data == finder_after->data &&
                    fork_after.has_value() == (type != 4) &&
                    (type == 4 || (fork && fork_after && fork->flags == fork_after->flags && fork->data == fork_after->data)) &&
                    !fresh.LookupCommittedExtendedAttribute(17, "com.apple.decmpfs"),
                    "manifest compression: permissions, Finder data and independent resource fork survive")) return false;
        }
        auto beta_volume = f.fixture.volume; beta_volume.volume_object_id = 102;
        Store beta(beta_volume);
        if (!Require(beta.PrepareNativeWritePath() && beta.LookupCommittedInodeByPath(L"\\before-compression") &&
                (tamper || beta.LookupCommittedInodeByPath(L"\\after-verification")),
                "manifest compression: independently reopened sibling namespace survives")) return false;
    }
    return passed;
}

bool TestNativeCompressionManifestRefusals266()
{
    using Store = apfsaccess::rw::MetadataStore;
    using Tx = apfsaccess::rw::TransactionManager;
    if (!CompressionReplay222ScratchReady()) return false;
    for (unsigned mode = 0; mode != 4; ++mode)
    {
        // Archive and range refusal precede a real queued unrelated request.
        // Corruption is discovered by the live builder after clean admission.
        NativeCompressionManifest266Fixture f;
        if (!Require(f.Initialize(4, mode == 0, mode == 2), "manifest refusal: canonical fixture initializes")) return false;
        auto& c = *f.fixture.context;
        auto fs = BuildFileSystem(&c);
        FSP_FSCTL_FILE_INFO info{}; PVOID writer = nullptr;
        ScopeExit close{[&] { if (writer) CB_Close(&fs, writer); }};
        const auto open_status = CB_Open(&fs, const_cast<PWSTR>(L"\\compressed"), FILE_OPEN << 24,
                GENERIC_READ | GENERIC_WRITE, &writer, &info);
        if (open_status != STATUS_SUCCESS)
            std::cerr << "manifest refusal open: mode=" << mode << " status=" << std::hex << open_status << std::dec << '\n';
        if (!Require(open_status == STATUS_SUCCESS,
                "manifest refusal: first compressed block permits candidate open")) return false;
        Store::MutationRequest unrelated;
        unrelated.operation = Store::MutationOperation::CreateFile; unrelated.path = L"\\unrelated-queued";
        if (mode != 2) EnqueueManifestRequest(&c, unrelated);
        if (mode == 3)
        {
            unrelated.operation = Store::MutationOperation::Write; unrelated.length = 1;
            EnqueueManifestRequest(&c, unrelated);
        }
        const auto image = ReadFileBytes(f.fixture.image.path);
        const auto wal = ReadFileBytes(c.session_root / "accepted.wal");
        const auto marks = c.tx_manager->Watermarks();
        const auto next_sequence = c.tx_manager->NextMutationSequence();
        const auto marker = ReadFileBytes(c.recovery_marker_file);
        std::byte value{'Z'}; ULONG done = 999;
        const auto status = CB_Write(&fs, writer, &value, mode == 1 ? f.original.size() : 1,
            1, FALSE, FALSE, &done, &info);
        const auto after = c.tx_manager->Watermarks();
        if (!Require(status == (mode == 3 ? STATUS_DEVICE_BUSY : STATUS_NOT_SUPPORTED) &&
                done == 0 && image == ReadFileBytes(f.fixture.image.path) &&
                wal == ReadFileBytes(c.session_root / "accepted.wal") && marker == ReadFileBytes(c.recovery_marker_file) &&
                marks.accepted_sequence == after.accepted_sequence && marks.apfs_durable_sequence == after.apfs_durable_sequence &&
                marks.cleanup_sequence == after.cleanup_sequence && c.tx_manager->CurrentState() == Tx::State::Idle &&
                next_sequence == c.tx_manager->NextMutationSequence() &&
                !c.tx_manager->PendingMutationCount() && !c.metadata_store->PendingMutationCount() &&
                ManifestQueuedRequestCount(&c) == (mode == 2 ? 0u : mode == 3 ? 2u : 1u) &&
                !c.compression_verification_pending.load() && !c.recovery_active && !c.write_degraded &&
                c.payload_spool->SnapshotCounters().dirty_range_count == 0,
                "manifest refusal: no false success, discarded queue, accepted evidence, native I/O or recovery downgrade")) return false;
        if (mode != 2)
        {
            ManifestJournalExpectation expectation;
            expectation.kind = mode == 3 ? Tx::MutationKind::Write : Tx::MutationKind::CreateFile;
            expectation.path = unrelated.path;
            if (mode == 3)
            {
                expectation.length = expectation.payload_bytes = 1;
                expectation.has_payload = true; expectation.payload = &value;
                // This synthetic queue has no foreground hydration node. Its
                // original writer supplies data through the actual bound spool.
                c.metadata_store->SetFilePayloadRangeProvider([&, spool_path = unrelated.path](const std::wstring& path,
                    Store::PayloadIdentity identity, std::uint64_t at, std::span<std::byte> destination) {
                    if (path != spool_path)
                        return ReadHydratedPayloadRangeForPath(&c, path, identity, at, destination);
                    std::size_t read = 0;
                    return c.payload_spool->ReadFullyCoveredRange({c.payload_spool_volume_identity,
                        identity.object_id, identity.generation, at, destination}, read) && read == destination.size();
                });
            }
            if (!Require(CommitQueuedManifestMutationWithWalBestEffort(&c, expectation, L"ManifestRefusalUnrelated") &&
                    c.metadata_store->LookupCommittedInodeByPath(unrelated.path),
                    "manifest refusal: preserved unrelated queue remains commit-capable through ordinary WAL binder")) return false;
            if (mode == 3)
            {
                std::vector<std::byte> actual;
                if (!Require(c.metadata_store->ReadCommittedFileRange(unrelated.path, 0, 1, actual) &&
                        actual == std::vector<std::byte>{value},
                        "manifest refusal: retried unrelated write persists the original writer's exact byte")) return false;
            }
        }
        if (!f.PublishSibling(L"\\after-refusal")) return false;
    }
    {
        NativeCompressionManifest266Fixture f;
        if (!f.Initialize(1)) return false;
        auto& c = *f.fixture.context;
        Store::MutationRequest stale;
        if (!Require(c.metadata_store->PrepareCompressionRewrite(L"\\compressed", stale) &&
                f.PublishSibling(L"\\stale-plan-sibling"),
                "manifest stale plan: capture source then publish actual sibling")) return false;
        const auto image = ReadFileBytes(f.fixture.image.path);
        const auto wal = ReadFileBytes(c.session_root / "accepted.wal");
        const auto xid = f.fixture.coordinator->CheckpointXid();
        const auto refused = CommitManifestMutations(&c, {stale});
        if (!Require(refused.status != Store::CommitStatus::Committed && !refused.recovery_required &&
                image == ReadFileBytes(f.fixture.image.path) && wal == ReadFileBytes(c.session_root / "accepted.wal") &&
                f.fixture.coordinator->CheckpointXid() == xid && !c.metadata_store->PendingMutationCount() &&
                c.metadata_store->LookupCommittedExtendedAttribute(17, "com.apple.decmpfs").has_value() &&
                f.PublishSibling(L"\\after-stale-refusal"),
                "manifest stale plan: native guard rejects old source, rolls back scratch and preserves sibling admission")) return false;
    }
    return true;
}
