#pragma once
// Include inside FsHostSemanticsTests.cpp's test namespace after
// DirectorySymlinkFixture and HostCompression* helpers. Include the production
// header at main.cpp's GLOBAL native-engine include block (see the handoff).

struct HostCompressionRewrite211Fixture
{
    DirectorySymlinkFixture fixture{false};
    std::uint64_t eof = 5;

    bool Initialize(unsigned type, bool corrupt = false, bool omit_name = false, bool external_finder = false,
        bool archive_clear = false)
    {
        using namespace apfsaccess::rw;
        auto builder = TwoProjectableVolumeStore();
        builder.volumes.resize(1);
        builder.authoritative_checkpoint = true; builder.dual_checkpoint = false; builder.xid = 20;
        // These callbacks publish several generations while retaining source proof.
        builder.authoritative_internal_pool_blocks = 16;
        builder.authoritative_checkpoint_ring_blocks = 16;
        auto& volume = builder.volumes.front();
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
        if (corrupt)
        {
            if (type == 4) resource.pop_back(); // First block remains readable; complete EOF validation must refuse.
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
        apfsaccess::testfixture::PutU64LE(descriptor, 0, 777);
        apfsaccess::testfixture::PutU64LE(descriptor, 8, resource.size());
        apfsaccess::testfixture::PutU64LE(descriptor, 16, 4096);
        if (!add(EncodeAppleXattrRecord({17, "com.apple.ResourceFork", kAppleXattrDataStream, descriptor}, encoded, error)) ||
            !add(EncodeAppleDataStreamIdRecord({777, 1}, encoded, error)) ||
            !add(EncodeAppleFileExtentRecord({777, 0, 4096, 100, 0, 4096}, encoded, error)) ||
            !EncodeApplePhysicalExtentRecord({100, 1, kApplePhysicalExtentKindNew, 777, 1}, encoded, error)) return false;
        volume.extentref_records.push_back(encoded); ++volume.additional_file_system_allocated_blocks;
        resource.resize(4096); builder.authoritative_seeded_main_blocks.push_back({100, resource});
        if (external_finder)
        {
            apfsaccess::testfixture::PutU64LE(descriptor, 0, 778);
            apfsaccess::testfixture::PutU64LE(descriptor, 8, 32);
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

bool TestNativeCompressionRewritePreparation211()
{
    using Helper = apfsaccess::fshost::NativeCompressionRewrite;
    using Failure = Helper::Failure;
    using Store = apfsaccess::rw::MetadataStore;
    std::uint64_t bytes = 99;
    if (!Require(Helper::PublicationBytes(1, 4096, bytes) && bytes == 4096 &&
            Helper::PublicationBytes(65541, 4096, bytes) && bytes == 69632 &&
            Helper::PublicationBytes(apfsaccess::rw::CompressionRewrite::MaxLogicalBytes, 4096, bytes) &&
            bytes == apfsaccess::rw::CompressionRewrite::MaxLogicalBytes &&
            !Helper::PublicationBytes(UINT64_MAX, 4096, bytes) && bytes == 0 &&
            !Helper::PublicationBytes(5, 0, bytes) && !Helper::PublicationBytes(5, 4095, bytes),
            "full EOF including padding is bounded independently of dirty bytes")) return false;
    for (const auto type : {1u, 3u, 4u})
    {
        HostCompressionRewrite211Fixture owned;
        if (!Require(owned.Initialize(type), "host preparation canonical compressed fixture initializes")) return false;
        auto& c = *owned.fixture.context; auto& store = *c.metadata_store; auto& tx = *c.tx_manager;
        const auto before_image = ReadFileBytes(owned.fixture.image.path);
        const auto inode = store.LookupCommittedInodeByPath(L"\\alias");
        if (!Require(inode.has_value() && tx.Begin(), "empty caller-owned transaction starts")) return false;
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
                tx.PendingMutationCount() == 0 && ReadFileBytes(owned.fixture.image.path) == before_image,
                "preparation and all refusals preserve image, working state, allocator and WAL")) return false;
        if (!Require(tx.Abort() && tx.Begin() && prepared->Revalidate(store, tx, admission) == Failure::SourceChanged,
                "an aborted transaction cannot reuse prepared evidence even at the same checkpoint")) return false;
        (void)tx.Abort();
    }
    for (const auto type : {3u, 4u, 7u})
    {
        HostCompressionRewrite211Fixture owned;
        if (!Require(owned.Initialize(type, type != 7), "corrupt or unsupported compressed source imports for refusal")) return false;
        auto& store = *owned.fixture.context->metadata_store; auto& tx = *owned.fixture.context->tx_manager;
        const auto inode = store.LookupCommittedInodeByPath(L"\\alias");
        if (!inode || !tx.Begin()) return false;
        const auto before = ReadFileBytes(owned.fixture.image.path);
        Failure reason;
        const auto prepared = Helper::Prepare(store, tx, HostCompressionRewrite211Admission(), L"\\alias",
            {inode->object_id, inode->xid}, 0, 1, reason);
        if (!Require(!prepared && reason == Failure::SourceUnsupported && !store.PendingMutationCount() &&
                !store.PendingAllocationCount() && !tx.PendingMutationCount() && ReadFileBytes(owned.fixture.image.path) == before,
                "complete-source validation rejects corruption beyond the edit or unsupported type before mutation")) return false;
        (void)tx.Abort();
    }
    return true;
}

bool TestNativeCompressionRewriteWal211()
{
    using namespace apfsaccess::rw;
    using Helper = apfsaccess::fshost::NativeCompressionRewrite;
    for (const auto type : {1u, 3u, 4u})
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
                store.LookupWorkingExtendedAttribute(17, "com.apple.ResourceFork").has_value() == (type != 4) &&
                tx.HasUnappliedAcceptedWork() && ReadFileBytes(owned.fixture.image.path) == before_image,
                "acceptance alone preserves on-disk Mac metadata and source proof; pending removal is compression-owned only")) return false;
    }
    return true;
}
