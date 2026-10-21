#pragma once
// Include inside the existing test namespace AFTER NativeCompressionRewriteTests.h.
// NativeCompressionReplay.h belongs in main.cpp's GLOBAL native-engine block.
// These tests use regular image files only, and refuse before fixture creation
// unless the existing runner's TEMP/TMP location is on D:.

bool CompressionReplay222ScratchReady()
{
    return Require(ToLowerInvariant(std::filesystem::temp_directory_path().root_name().wstring()) == L"d:",
        "compression replay 222 requires the runner's TEMP/TMP on D:");
}

bool CompressionReplay222Hash(apfsaccess::rw::TransactionManager::MutationIntent& intent)
{
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) return false;
    const auto status = BCryptHash(algorithm, nullptr, 0,
        reinterpret_cast<PUCHAR>(intent.inline_payload.data()), static_cast<ULONG>(intent.inline_payload.size()),
        intent.payload_checksum.data(), static_cast<ULONG>(intent.payload_checksum.size()));
    BCryptCloseAlgorithmProvider(algorithm, 0);
    intent.length = intent.payload_length = intent.inline_payload.size();
    return status >= 0;
}

struct HostCompressionReplay222Fixture
{
    using Store = apfsaccess::rw::MetadataStore;
    using Tx = apfsaccess::rw::TransactionManager;
    using Replay = apfsaccess::fshost::NativeCompressionReplay;
    HostCompressionRewrite211Fixture owned;
    std::uint64_t sequence = 0, preimage = 0;
    std::vector<std::byte> expected;
    std::vector<Tx::MutationIntent> intents;

    bool Initialize(unsigned type, bool external = false, bool omit_name = false, bool external_finder = false,
        std::uint64_t private_id = 17)
    {
        using namespace apfsaccess::rw;
        using Preparation = apfsaccess::fshost::NativeCompressionRewrite;
        if (!owned.Initialize(type, false, omit_name, external_finder, false, 0, private_id))
        { std::cerr << "[compression fixture] source initialization type=" << type << " private=" << private_id << '\n'; return false; }
        auto& c = *owned.fixture.context;
        auto& store = *c.metadata_store;
        auto& tx = *c.tx_manager;
        const auto inode = store.LookupCommittedInodeByPath(L"\\alias");
        const auto preserve_failure = [&] {
            const auto saved = std::filesystem::temp_directory_path() /
                (owned.fixture.image.path.filename().wstring() + L".c1-source-failure");
            (void)WriteFileBytes(saved, ReadFileBytes(owned.fixture.image.path));
            std::wcerr << L"[compression fixture] retained source " << saved.wstring() << L'\n';
        };
        if (!inode) {preserve_failure();std::cerr << "[compression fixture] alias absent\n";return false;}
        if (!store.ReadCommittedFileRange(L"\\alias", 0, static_cast<std::size_t>(owned.eof), expected) || expected.size() != owned.eof)
        { preserve_failure();std::cerr << "[compression fixture] source read type=" << type << " private=" << private_id << " bytes=" << expected.size() << " eof=" << owned.eof << '\n';return false; }
        if (!tx.Begin()) {preserve_failure();std::cerr << "[compression fixture] Begin refused\n";return false;}
        Preparation::Failure reason;
        auto plan = Preparation::Prepare(store, tx, HostCompressionRewrite211Admission(), L"\\alias",
            {inode->object_id, inode->xid}, 1, 1, reason);
        if (!plan)
        { std::cerr << "[compression fixture] prepare failure=" << static_cast<int>(reason) << " type=" << type << " private=" << private_id << '\n'; return false; }
        preimage = plan->PreimageCheckpoint();
        intents.push_back(plan->JournalIntent());
        Store::PayloadIdentity target;
        if (!tx.RecordMutation(intents.back()) ||
            store.StageMutation(plan->Request(), &target) != Store::MutationStatus::Applied)
        { std::cerr << "[compression fixture] record or stage rewrite type=" << type << " private=" << private_id << '\n'; return false; }
        const auto times = [&](std::uint64_t ticks) {
            Tx::MutationIntent intent;
            intent.kind = Tx::MutationKind::SetInodeMetadata;
            intent.path = L"\\alias"; intent.object_id = target.object_id; intent.generation = target.generation;
            intent.inline_payload = EncodeContentTimes(ToFileTime(ticks));
            if (!CompressionReplay222Hash(intent)) return false;
            Store::MutationRequest request;
            request.operation = Store::MutationOperation::SetInodeMetadata; request.path = intent.path;
            request.object_id = target.object_id; request.generation = target.generation;
            request.inline_payload = intent.inline_payload; request.length = intent.length;
            intents.push_back(intent);
            return tx.RecordMutation(intent) && store.StageMutation(request) == Store::MutationStatus::Applied;
        };
        if (!times(InodeMetadataPatch::UnixEpochTicks + 123456789))
        { std::cerr << "[compression fixture] initial times\n"; return false; }
        for (const auto [offset, byte] : std::vector<std::pair<std::uint64_t, std::byte>>{
                {1, std::byte{'X'}}, {1, std::byte{'Z'}}, {owned.eof - 1, std::byte{'Y'}}})
        {
            Store::MutationRequest request;
            if (!plan->PrepareWrite(store, target, L"\\compressed", offset, 1, request))
            { std::cerr << "[compression fixture] prepare write\n"; return false; }
            Tx::MutationIntent intent;
            intent.kind = Tx::MutationKind::Write; intent.path = request.path;
            intent.object_id = target.object_id; intent.generation = target.generation; intent.offset = offset;
            intent.inline_payload = {byte};
            if (!CompressionReplay222Hash(intent)) return false;
            if (external)
            {
                PayloadSpool::AppendResult appended;
                intent.wal_sequence = tx.NextMutationSequence();
                if (!c.payload_spool->Append({c.payload_spool_volume_identity, target.object_id, target.generation,
                        offset, intent.wal_sequence, intent.inline_payload}, &appended)) return false;
                intent.payload_spool_offset = appended.spool_offset;
                intent.payload_checksum = appended.payload_sha256;
                intent.inline_payload.clear();
            }
            intents.push_back(intent);
            if (!tx.RecordMutation(intent) || store.StageMutation(request) != Store::MutationStatus::Applied)
            { std::cerr << "[compression fixture] record or stage write\n"; return false; }
            expected[static_cast<std::size_t>(offset)] = byte;
        }
        if (!times(InodeMetadataPatch::UnixEpochTicks + 987654321))
        { std::cerr << "[compression fixture] final times\n"; return false; }
        // The test provider supplies ordinary write ranges; the native engine
        // remains responsible for decompression and untouched original bytes.
        store.SetFilePayloadRangeProvider([this, target](const auto&, auto identity, auto offset, auto bytes) {
            if (identity.object_id != target.object_id || identity.generation != target.generation ||
                offset > expected.size() || bytes.size() > expected.size() - offset) return false;
            std::copy_n(expected.begin() + static_cast<std::size_t>(offset), bytes.size(), bytes.begin());
            return true;
        });
        if (external && !c.payload_spool->FlushDirtyState()) return false;
        if (!tx.Accept(preimage))
        { std::cerr << "[compression fixture] accept\n"; return false; }
        sequence = tx.Watermarks().accepted_sequence;
        return sequence != 0;
    }
    bool Publish()
    {
        auto& c = *owned.fixture.context;
        std::vector<std::uint64_t> pins;
        return c.tx_manager->LoadRequiredCheckpointXidsSinceCleanup(pins) &&
            std::find(pins.begin(), pins.end(), preimage) != pins.end() &&
            c.metadata_store->CommitPendingMutations(pins) == Store::CommitStatus::Committed;
    }
    Replay::Result Verify(Store& store)
    {
        auto& c = *owned.fixture.context;
        return Replay::Verify(store, *c.tx_manager, sequence, c.payload_spool.get(), c.payload_spool_volume_identity);
    }
};

bool TestNativeCompressionReplayPublished222()
{
    using F = HostCompressionReplay222Fixture;
    using Result = F::Replay::Result;
    if (!CompressionReplay222ScratchReady()) return false;
    for (const auto type : {1u, 3u, 4u}) for (const bool external : {false, true}) for (const bool omit_name : {false, true})
    {
        F fixture;
        if (!Require(fixture.Initialize(type, external, omit_name), "222 accepts actual compression proof, overlapping writes and same-owner times")) return false;
        auto& c = *fixture.owned.fixture.context;
        if (!Require(fixture.Verify(*c.metadata_store) != Result::Verified,
                "acceptance and staged decmpfs removal alone are not publication proof") ||
            !Require(fixture.Publish(), "222 publishes once through the existing native commit with original pin")) return false;
        F::Store reopened(fixture.owned.fixture.volume);
        if (!Require(reopened.PrepareNativeWritePath(), "222 reopens published image independently")) return false;
        const auto before = ReadFileBytes(fixture.owned.fixture.image.path);
        const auto watermarks = c.tx_manager->Watermarks();
        std::vector<std::uint64_t> pins_before, pins_after;
        if (!c.tx_manager->LoadRequiredCheckpointXidsSinceCleanup(pins_before)) return false;
        const auto result = fixture.Verify(reopened);
        if (result != Result::Verified) std::cerr << "222 verifier result=" << static_cast<int>(result) << '\n';
        if (!Require(result == Result::Verified, "222 proves complete published types 1/3/4 from original WAL and checkpoint") ||
            !Require(c.tx_manager->LoadRequiredCheckpointXidsSinceCleanup(pins_after) && pins_before == pins_after &&
                c.tx_manager->Watermarks().accepted_sequence == watermarks.accepted_sequence &&
                c.tx_manager->Watermarks().apfs_durable_sequence == watermarks.apfs_durable_sequence &&
                c.tx_manager->Watermarks().cleanup_sequence == watermarks.cleanup_sequence &&
                !reopened.PendingMutationCount() && before == ReadFileBytes(fixture.owned.fixture.image.path),
                "222 verification changes no image, pending state, checkpoint pins or watermarks")) return false;
        if (external && !Require(F::Replay::Verify(reopened, *c.tx_manager, fixture.sequence, nullptr,
                c.payload_spool_volume_identity) == Result::PayloadMismatch,
                "correct APFS bytes cannot substitute for missing accepted external spool evidence")) return false;
        if (!Require(F::Replay::Verify(reopened, *c.tx_manager, fixture.sequence, c.payload_spool.get(),
                "another-volume") == Result::AcceptedEvidenceInvalid,
                "matching payload bytes do not authorize a foreign WAL/spool volume identity")) return false;
        if (!Require(c.tx_manager->MarkApfsDurableThrough(fixture.sequence) && fixture.Verify(reopened) == Result::Verified,
                "durable but uncleaned accepted WAL remains independently verifiable")) return false;
        if (!Require(c.tx_manager->MarkCleanedThrough(fixture.sequence) &&
                fixture.Verify(reopened) == Result::AcceptedEvidenceInvalid,
                "already-cleaned evidence cannot be replaced by a self-attesting image")) return false;
    }
    return true;
}

// Rebuild only this tiny fixture's CURRENT filesystem leaf with existing native
// record encoders and the existing checksummed leaf builder. Historical trees,
// payload blocks and checkpoint identity stay intact. This constructs plausible
// independently loadable forged post-publication states, not fake proof objects.
bool CompressionReplay222ReplaceCurrentLeaf(std::vector<std::byte>& image,
    const std::function<bool(std::vector<apfsaccess::catalog::BtreeRecord>&)>& change)
{
    using namespace apfsaccess;
    catalog::VectorRandomAccessSource source(image);
    std::string error;
    const auto checkpoint = catalog::LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
    if (!checkpoint || checkpoint->volumes.size() != 1) return false;
    const auto& volume = checkpoint->volumes.front();
    const auto& root = volume.root_tree;
    const auto size = checkpoint->container.superblock.block_size;
    std::vector<catalog::BtreeRecord> records;
    const bool physical = (root.type & catalog::kObjectStorageTypeMask) == catalog::kObjectPhysical;
    if (!catalog::ReadBtreeLeafRecords(source, size, root.physical_block, physical,
            physical ? 0 : volume.superblock.omap_oid, checkpoint->container.superblock.xid, records, error) ||
        !change(records) || !rw::SortAppleBtreeRecords(records, rw::AppleBtreeKeyOrder::FileSystemCaseSensitive, error)) return false;
    std::vector<std::vector<std::byte>> keys, values;
    std::size_t bytes = 128;
    for (const auto& record : records)
    {
        bytes += record.key.size() + record.value.size() + 8;
        keys.push_back(record.key); values.push_back(record.value);
    }
    if (bytes > size) return false;
    auto leaf = testfixture::BuildRawLeafNode(keys, values, checkpoint->container.superblock.xid,
        size, 0, root.object_id, root.type, root.subtype);
    const auto offset = root.physical_block * size;
    if (offset > image.size() || leaf.size() > image.size() - offset) return false;
    std::copy(leaf.begin(), leaf.end(), image.begin() + static_cast<std::size_t>(offset));
    return true;
}

bool TestNativeCompressionReplayForged222()
{
    using namespace apfsaccess;
    using F = HostCompressionReplay222Fixture;
    using Result = F::Replay::Result;
    if (!CompressionReplay222ScratchReady()) return false;
    F fixture;
    std::string phase = "initialization";
    bool completed = false;
    ScopeExit diagnosis{[&] { if (!completed) std::cerr << "[FAIL] forged publication phase: " << phase << '\n'; }};
    if (!Require(fixture.Initialize(4) && fixture.Publish(), "222 forged-state baseline really publishes type 4")) return false;
    auto& c = *fixture.owned.fixture.context;
    const auto original_image = ReadFileBytes(fixture.owned.fixture.image.path);
    rw::NativeApfsVolumeProjection projection;
    std::wstring read_error;
    if (!rw::NativeApfsReader::TryLoadVolumeProjection(c.metadata_store->Device(), 101, projection, read_error))
    {
        std::wcerr << L"[FAIL] forged source projection: " << read_error << L'\n';
        return false;
    }
    const auto check = [&](const std::vector<std::byte>& bytes, bool same_content, Result wanted) {
        ContainerFixtureFile copy("compression-replay-222-forged", true, true);
        if (!WriteFileBytes(copy.path, bytes)) return false;
        auto context = fixture.owned.fixture.volume;
        context.device_path = copy.path.wstring();
        F::Store store(context);
        if (!Require(store.PrepareNativeWritePath(), "forged 222 image has a loadable canonical checkpoint")) return false;
        std::vector<std::byte> content;
        if (!Require(store.ReadCommittedFileRange(L"\\compressed", 0, fixture.expected.size(), content), "read forged publication bytes")) return false;
        if (!Require((content == fixture.expected) == same_content && content[1] == std::byte{'Z'},
                "forged 222 image still matches accepted modified byte")) return false;
        return Require(fixture.Verify(store) == wanted, "222 independently rejects the plausible forged publication");
    };
    // Corrupt an UNTOUCHED byte in the first block while the tail write and both
    // overlapping writes still match. No metadata/checksum changes are needed.
    auto image = original_image;
    const auto& extents = projection.read_extents_by_inode.at(17);
    if (!Require(!extents.empty() && extents.front().logical_offset == 0 && extents.front().physical_address &&
        extents.front().physical_address < image.size(), "forged image has first payload extent")) return false;
    image[static_cast<std::size_t>(extents.front().physical_address)] ^= std::byte{1};
    phase = "untouched payload";
    if (!check(image, false, Result::ContentMismatch)) return false;
    // Fields unavailable through projected host properties (nanosecond tail,
    // reserved bits) are compared through the native raw inode codec as well.
    for (const auto choice : {0, 1, 2, 3})
    {
        phase = "inode metadata " + std::to_string(choice);
        image = original_image;
        if (!CompressionReplay222ReplaceCurrentLeaf(image, [&](auto& records) {
            std::string error;
            for (auto& record : records)
            {
                rw::AppleInodeRecord inode;
                if (!rw::ApfsExtendedRecordCodec::DecodeInode(record, inode, error) || inode.object_id != 17) continue;
                if (choice == 0) ++inode.owner;
                if (choice == 1) ++inode.create_time; // Same Windows tick, different original nanoseconds.
                if (choice == 2) ++inode.modification_time;
                if (choice == 3) ++inode.reserved_pad;
                return rw::EncodeAppleInodeRecord(inode, record, error);
            }
            return false;
        }) || !check(image, true, Result::MetadataMismatch)) return false;
    }
    phase = "FinderInfo";
    image = original_image;
    if (!CompressionReplay222ReplaceCurrentLeaf(image, [](auto& records) {
        std::string error;
        for (auto& record : records)
        {
            rw::AppleXattrRecord attribute;
            if (!rw::ApfsExtendedRecordCodec::DecodeXattr(record, attribute, error) ||
                attribute.name_utf8 != "com.apple.FinderInfo") continue;
            attribute.data.front() ^= std::byte{1};
            return rw::EncodeAppleXattrRecord(attribute, record, error);
        }
        return false;
    }) || !check(image, true, Result::MetadataMismatch)) return false;
    phase = "resurrected compression fork";
    image = original_image;
    if (!CompressionReplay222ReplaceCurrentLeaf(image, [](auto& records) {
        catalog::BtreeRecord record;
        std::string error;
        if (!rw::EncodeAppleXattrRecord({17, "com.apple.ResourceFork", rw::kAppleXattrDataEmbedded,
                {std::byte{'F'}}}, record, error)) return false;
        records.push_back(std::move(record));
        return true;
    }) || !check(image, true, Result::MetadataMismatch)) return false;
    phase = "directory alias metadata";
    image = original_image;
    if (!CompressionReplay222ReplaceCurrentLeaf(image, [](auto& records) {
        std::string error;
        for (auto& record : records)
        {
            rw::AppleSiblingLinkRecord link;
            if (!rw::ApfsExtendedRecordCodec::DecodeSiblingLink(record, link, error) || link.inode_id != 17) continue;
            // Keep alias identity and spelling; alter the separate directory
            // date metadata below so the namespace remains fully coherent.
            for (auto& directory : records)
            {
                const auto key = catalog::ReadU64LE(directory.key, 0).value_or(0);
                if ((key >> 60) != 9) continue;
                // Existing fixture directory codec provides the actual record.
                rw::AppleDirectoryRecord replacement;
                replacement.parent_id = 2; replacement.file_id = 17; replacement.flags = 8;
                replacement.name_utf8 = "alias"; replacement.date_added = 999;
                catalog::BtreeRecord encoded;
                if (!rw::EncodeAppleDirectoryRecord(replacement, encoded, error)) return false;
                if (encoded.key == directory.key) { directory = std::move(encoded); return true; }
            }
        }
        return false;
    }) || !check(image, true, Result::MetadataMismatch)) return false;
    // Destroy the retained original descriptor. Current owner/content is still
    // independently readable, but source existence is no longer provable.
    phase = "original checkpoint descriptor";
    image = original_image;
    catalog::VectorRandomAccessSource source(image);
    std::string error;
    const auto old = catalog::LoadAppleCheckpointView(source, 0, source.SizeBytes(), error, fixture.preimage);
    if (!old) return false;
    const auto old_offset = old->container.superblock_physical_block * old->container.superblock.block_size;
    if (old_offset >= image.size()) return false;
    image[static_cast<std::size_t>(old_offset)] ^= std::byte{1};
    if (!check(image, true, Result::OriginalEvidenceUnavailable)) return false;
    // Independent fixtures deliberately reuse this test volume identity. End
    // the original journal lease before opening their separate accepted WALs.
    fixture.owned.fixture.context->tx_manager->SetJournalPath(L"");
    for (const auto type : {1u, 3u})
    {
        phase = "independent resource fork " + std::to_string(type);
        F independent;
        if (!Require(independent.Initialize(type) && independent.Publish(),
            "independent fork fixture acquires its own journal lease and publishes")) return false;
        auto& owner = *independent.owned.fixture.context;
        rw::NativeApfsVolumeProjection state;
        if (!rw::NativeApfsReader::TryLoadVolumeProjection(owner.metadata_store->Device(), 101, state,
                read_error, owner.metadata_store->CheckpointXid())) return false;
        const auto fork = state.attribute_stream_extents.find(777);
        if (fork == state.attribute_stream_extents.end() || !fork->second || fork->second->empty()) return false;
        auto corrupt = ReadFileBytes(independent.owned.fixture.image.path);
        const auto address = fork->second->front().physical_address;
        if (!address || address >= corrupt.size()) return false;
        corrupt[static_cast<std::size_t>(address)] ^= std::byte{1};
        ContainerFixtureFile copy("compression-replay-222-independent-fork", true, true);
        if (!WriteFileBytes(copy.path, corrupt)) return false;
        auto context = independent.owned.fixture.volume; context.device_path = copy.path.wstring();
        F::Store store(context);
        std::vector<std::byte> content;
        if (!Require(store.PrepareNativeWritePath() &&
                store.ReadCommittedFileRange(L"\\compressed", 0, independent.expected.size(), content) &&
                content == independent.expected && independent.Verify(store) == Result::SourceMismatch,
                "types 1/3 cannot attest preservation of an independently altered fork from data bytes alone")) return false;
    }
    completed = true;
    return true;
}

bool TestNativeCompressionPreservedStreamAuthentication(std::uint64_t private_id = 17)
{
    using F = HostCompressionReplay222Fixture;
    using Result = F::Replay::Result;
    if (!CompressionReplay222ScratchReady()) return false;
    F fixture;
    const bool initialized = fixture.Initialize(3, false, false, true, private_id);
    const bool published = initialized && fixture.Publish();
    if (!published)
    {
        const auto& failed = *fixture.owned.fixture.context;
        std::wcerr << L"[compression attribute] private=" << private_id << L" initialized=" << initialized
            << L" stage=" << Utf8ToWide(failed.metadata_store->LastCommitStage())
            << L" reason=" << failed.metadata_store->LastCommitFailureReason()
            << L" detail=" << failed.metadata_store->LastCommitFailureDetail() << L'\n';
    }
    if (!Require(published,
        "publish compressed owner with a separately stored ordinary FinderInfo")) return false;
    auto& c = *fixture.owned.fixture.context;
    F::Store fresh(fixture.owned.fixture.volume);
    if (!Require(fresh.PrepareNativeWritePath() && fixture.Verify(fresh) == Result::Verified,
        "unchanged external FinderInfo is authenticated against accepted preimage")) return false;
    apfsaccess::rw::NativeApfsVolumeProjection projection;
    std::wstring error;
    if (!Require(apfsaccess::rw::NativeApfsReader::TryLoadVolumeProjection(fresh.Device(), 101, projection,
        error, fresh.CheckpointXid()), "load independent current FinderInfo extents")) return false;
    const auto stream = projection.attribute_stream_extents.find(778);
    if (!Require(stream != projection.attribute_stream_extents.end() && stream->second && !stream->second->empty(),
        "FinderInfo has a real external payload")) return false;
    auto bytes = ReadFileBytes(fixture.owned.fixture.image.path);
    const auto at = stream->second->front().physical_address;
    if (!Require(at < bytes.size(), "FinderInfo corruption target lies within the image")) return false;
    bytes[static_cast<std::size_t>(at)] ^= std::byte{1};
    ContainerFixtureFile changed("compression-preserved-stream", true, true);
    if (!WriteFileBytes(changed.path, bytes)) return false;
    auto context = fixture.owned.fixture.volume;
    context.device_path = changed.path.wstring();
    F::Store corrupted(context);
    if (!Require(corrupted.PrepareNativeWritePath(), "shared-block tamper leaves both metadata trees loadable")) return false;
    std::vector<std::byte> content;
    if (!Require(corrupted.ReadCommittedFileRange(L"\\compressed", 0, fixture.expected.size(), content) && content == fixture.expected,
        "file content still exactly matches accepted writes after unrelated stream tamper")) return false;
    return Require(fixture.Verify(corrupted) == Result::MetadataMismatch,
        "accepted fingerprint detects external metadata tamper despite shared old and new extents");
}

bool TestNativeCompressionDistinctStreamOwner()
{
    using namespace apfsaccess;
    using F = HostCompressionReplay222Fixture;
    if (!CompressionReplay222ScratchReady()) return false;
    {
    F fixture;
    if (!Require(fixture.Initialize(4, true, false, true, 29) && fixture.Publish(),
        "distinct stream owner publishes accepted conversion with independent FinderInfo")) return false;
    auto& c = *fixture.owned.fixture.context;
    F::Store fresh(fixture.owned.fixture.volume);
    if (!Require(fresh.PrepareNativeWritePath() && fixture.Verify(fresh) == F::Replay::Result::Verified,
        "distinct stream owner verifies from actual accepted original and retained preimage")) return false;
    const auto inode = fresh.LookupCommittedInodeByPath(L"\\compressed");
    std::vector<std::byte> content;
    if (!Require(inode && inode->object_id == 17 && inode->private_id == 29 &&
        fresh.ReadCommittedFileRange(L"\\alias", 0, fixture.expected.size(), content) && content == fixture.expected,
        "distinct stream identity and every published byte survive fresh native read")) return false;
    auto image = ReadFileBytes(fixture.owned.fixture.image.path);
    catalog::VectorRandomAccessSource source(image);std::string error;
    const auto checkpoint = catalog::LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
    if (!Require(checkpoint && checkpoint->volumes.size() == 1 && checkpoint->volumes[0].extentref_tree,
        "wrong-owner control finds actual current reference tree")) return false;
    const auto& root = *checkpoint->volumes[0].extentref_tree;
    const auto bs = checkpoint->container.superblock.block_size;
    std::vector<catalog::BtreeRecord> records;
    if (!catalog::ReadBtreeLeafRecords(source, bs, root.physical_block, true, 0,
        checkpoint->container.superblock.xid, records, error)) return false;
    bool changed = false, finder = false;
    for (auto& record : records)
    {
        rw::ApplePhysicalExtentRecord extent;
        if (!rw::DecodeApplePhysicalExtentRecord(record, extent, error)) return false;
        if (extent.owning_object_id == 29)
        {
            extent.owning_object_id = 17;
            if (!rw::EncodeApplePhysicalExtentRecord(extent, record, error)) return false;
            changed = true;
        }
        if (extent.physical_block <= 103 && 103 - extent.physical_block < extent.block_count)
            finder = extent.owning_object_id == 17 && extent.reference_count == 1;
    }
    if (!Require(changed && finder, "new file owner is 29 while independent attribute remains header-owned 17")) return false;
    std::vector<std::vector<std::byte>> keys, values;
    for (const auto& record : records){keys.push_back(record.key);values.push_back(record.value);}
    const auto leaf = testfixture::BuildRawLeafNode(keys, values, checkpoint->container.superblock.xid,
        bs, 0, root.object_id, root.type, root.subtype);
    const auto offset = root.physical_block * bs;
    if (offset > image.size() || leaf.size() > image.size() - offset) return false;
    std::copy(leaf.begin(), leaf.end(), image.begin() + static_cast<std::size_t>(offset));
    ContainerFixtureFile forged("compression-distinct-wrong-owner", true, true);
    auto context = fixture.owned.fixture.volume;context.device_path = forged.path.wstring();
    if (!WriteFileBytes(forged.path, ReadFileBytes(fixture.owned.fixture.image.path))) return false;
    {
        F::Store valid(context);
        if (!Require(valid.PrepareNativeWritePath() && fixture.Verify(valid) == F::Replay::Result::Verified,
            "identical private copy verifies before only the physical owner is changed")) return false;
    }
    if (!WriteFileBytes(forged.path, image)) return false;
    const auto marks = c.tx_manager->Watermarks();
    const auto wal = ReadFileBytes(c.session_root / "accepted.wal");
    F::Store wrong(context);
    const bool loaded = wrong.PrepareNativeWritePath();
    if (!Require((!loaded || fixture.Verify(wrong) != F::Replay::Result::Verified) &&
        image == ReadFileBytes(forged.path) && wal == ReadFileBytes(c.session_root / "accepted.wal") &&
        c.tx_manager->Watermarks().accepted_sequence == marks.accepted_sequence &&
        c.tx_manager->Watermarks().apfs_durable_sequence == marks.apfs_durable_sequence &&
        c.tx_manager->Watermarks().cleanup_sequence == marks.cleanup_sequence,
        "checksummed wrong ordinary owner refuses without changing image or accepted authority")) return false;
    }
    return TestNativeCompressionPreservedStreamAuthentication(29);
}

bool TestCompressionReplayWalBudget()
{
    using F = HostCompressionReplay222Fixture;
    if (!CompressionReplay222ScratchReady()) return false;
    F fixture;
    if (!Require(fixture.Initialize(1) && fixture.Publish(), "WAL budget baseline really publishes")) return false;
    auto& c = *fixture.owned.fixture.context;
    const auto before = ReadFileBytes(c.session_root / "accepted.wal");
    const auto watermarks = c.tx_manager->Watermarks();
    for (const auto limits : {apfsaccess::rw::WalReadLimits{1, 4096}, apfsaccess::rw::WalReadLimits{64ULL << 20, 1}})
    {
        std::vector<F::Tx::AcceptedTransaction> batches;
        std::string error;
        if (!Require(!c.tx_manager->LoadAcceptedTransactionsSinceCleanup(batches, &error, limits) &&
            batches.empty() && error == "WAL read resource budget exceeded" && c.tx_manager->RecoveryStateValid() &&
            before == ReadFileBytes(c.session_root / "accepted.wal") &&
            c.tx_manager->Watermarks().accepted_sequence == watermarks.accepted_sequence &&
            c.tx_manager->Watermarks().cleanup_sequence == watermarks.cleanup_sequence,
            "WAL budget refusal preserves evidence and healthy ownership")) return false;
    }
    F::Store fresh(fixture.owned.fixture.volume);
    return Require(fresh.PrepareNativeWritePath() && fixture.Verify(fresh) == F::Replay::Result::Verified,
        "valid bounded proof still succeeds after insufficient WAL budget refusals");
}

bool TestNativeCompressionReplayAuthority222()
{
    using namespace apfsaccess::rw;
    using F = HostCompressionReplay222Fixture;
    using Store = F::Store;
    using Result = F::Replay::Result;
    if (!CompressionReplay222ScratchReady()) return false;
    F fixture;
    if (!Require(fixture.Initialize(1) && fixture.Publish(), "authority baseline publishes")) return false;
    auto& c = *fixture.owned.fixture.context;
    F::Store reopened(fixture.owned.fixture.volume);
    if (!Require(reopened.PrepareNativeWritePath(), "authority baseline reopens")) return false;
    const auto baseline_result = fixture.Verify(reopened);
    if (baseline_result != Result::Verified) std::cerr << "[INFO] authority baseline result=" << static_cast<int>(baseline_result) << '\n';
    if (!Require(baseline_result == Result::Verified, "authority baseline verifies")) return false;
    // The alternate journal must obtain the same volume lease in sequence,
    // rather than asking the production lease guard to admit a second writer.
    c.tx_manager->SetJournalPath(L"");
    // A fully valid, rehashed accepted WAL lies about a source byte subsequently
    // overwritten by an accepted write. Even an identical final result cannot
    // authenticate this fabricated original-checkpoint proof.
    for (const bool forge_source : {true, false})
    {
        auto intents = fixture.intents;
        if (forge_source)
        {
            CompressionRewrite proof;
            if (!DecodeCompressionRewrite(intents[0].inline_payload, proof)) return false;
            proof.decmpfs.back() ^= std::byte{1}; proof.decmpfs_descriptor = proof.decmpfs;
            intents[0].inline_payload = EncodeCompressionRewrite(proof);
            if (!CompressionReplay222Hash(intents[0])) return false;
        }
        else
        {
            intents[3].inline_payload = {std::byte{'Q'}};
            if (!CompressionReplay222Hash(intents[3])) return false;
        }
        TransactionManager forged(L"Conservative");
        forged.SetVolumeIdentity(L"directory-symlink-volume");
        const auto journal_directory = c.session_root / (forge_source ? "forged-source-222" : "forged-write-222");
        std::filesystem::create_directories(journal_directory);
        forged.SetJournalPath((journal_directory / "accepted.wal").wstring());
        if (!Require(forged.Begin(), "forged WAL begins")) return false;
        for (const auto& intent : intents) if (!Require(forged.RecordMutation(intent), "forged WAL records intent")) return false;
        if (!Require(forged.Accept(fixture.preimage), "forged WAL accepts")) return false;
        if (!Require(F::Replay::Verify(reopened, forged, forged.Watermarks().accepted_sequence, nullptr,
                c.payload_spool_volume_identity) == (forge_source ? Result::SourceMismatch : Result::ContentMismatch),
                "222 refuses internally valid accepted WAL when original source or applied payload authority disagrees")) return false;
    }
    // A later accepted batch is not a supersession receipt, even if not yet
    // published and the first conversion's complete bytes still match.
    c.tx_manager->SetJournalPath((c.session_root / "accepted.wal").wstring());
    if (!c.tx_manager->Begin() || !c.tx_manager->RecordMutation(fixture.intents[2]) ||
        !c.tx_manager->Accept(fixture.preimage + 1)) return false;
    if (!Require(fixture.Verify(reopened) == Result::HistoryUnsupported,
            "222 refuses later accepted history without claiming byte matches prove supersession")) return false;
    // A later, real checkpoint must refuse even when it changes only a time.
    c.tx_manager->SetJournalPath(L"");
    F later;
    if (!later.Initialize(3) || !later.Publish()) return false;
    auto& live = *later.owned.fixture.context->metadata_store;
    const auto unchanged_plan = live.SnapshotCommittedFileReadPlan(
        LowerPathKey(later.owned.fixture.context.get(), L"\\compressed"));
    if (!Require(unchanged_plan.has_value(), "later checkpoint captures actual committed payload")) return false;
    Store::MutationRequest times;
    times.operation = Store::MutationOperation::SetInodeMetadata; times.path = L"\\compressed";
    times.object_id = 17; times.generation = live.CheckpointXid().value_or(0) + 1;
    times.inline_payload = EncodeContentTimes(ToFileTime(InodeMetadataPatch::UnixEpochTicks + 999999999));
    times.length = times.inline_payload.size();
    Store::PayloadIdentity later_target;
    if (!Require(live.StageMutation(times, &later_target) == Store::MutationStatus::Applied &&
            later_target.object_id == unchanged_plan->object_id && later_target.generation == times.generation,
            "later content-time mutation stages")) return false;
    // Bind the next transaction's identity to a snapshot of actual APFS bytes;
    // the conversion provider only authorized the previous generation.
    live.SetFilePayloadRangeProvider([&live, unchanged_plan, later_target](const auto& path,
        auto identity, auto offset, auto destination) {
        if (identity.object_id != later_target.object_id || identity.generation != later_target.generation) return false;
        std::size_t read = 0;
        if (!live.ReadCommittedFileRangeFromPlan(*unchanged_plan, path, offset, destination.size(),
                destination.data(), destination.size(), read) || read != destination.size()) return false;
        return true;
    });
    const auto later_commit = live.CommitPendingMutations({later.preimage});
    if (later_commit != Store::CommitStatus::Committed)
        std::wcerr << L"[INFO] later checkpoint stage=" << Utf8ToWide(live.LastCommitStage())
            << L" detail=" << live.LastCommitFailureDetail() << L'\n';
    // A metadata-only publication can preserve all existing payload extents.
    // Prove the new checkpoint through a fresh reader, not a provider call count.
    Store published(later.owned.fixture.volume);
    if (!Require(later_commit == Store::CommitStatus::Committed &&
            live.CheckpointXid() == times.generation && published.PrepareNativeWritePath() &&
            published.CheckpointXid() == times.generation && times.generation == later.preimage + 2,
            "later content-time checkpoint really publishes")) return false;
    std::vector<std::byte> unchanged;
    if (!Require(published.ReadCommittedFileRange(L"\\compressed", 0, later.expected.size(), unchanged) &&
            unchanged == later.expected, "later checkpoint preserves the actual committed content")) return false;
    const auto later_result = later.Verify(published);
    if (later_result != Result::HistoryUnsupported)
        std::cerr << "[INFO] later publication verifier result=" << static_cast<int>(later_result) << '\n';
    if (!Require(later_result == Result::HistoryUnsupported,
            "222 refuses an actual later publication with identical data bytes")) return false;
    return true;
}
