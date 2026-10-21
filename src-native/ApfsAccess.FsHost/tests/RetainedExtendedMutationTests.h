#pragma once

#include "RetainedGenerationPressureTests.h"

// Include after DirectorySymlinkFixture in FsHostSemanticsTests.cpp.
namespace RetainedExtendedMutationTests
{
using namespace RetainedGenerationPressureTests;
using Operation = Store::MutationOperation;

bool CheckAttribute(Store& store, std::uint64_t object, const std::string& name,
    const std::vector<std::byte>& expected, bool external)
{
    const auto attribute = store.LookupCommittedExtendedAttribute(object, name);
    std::vector<std::byte> bytes(expected.size() + 1);
    std::size_t read = 0;
    if (!Require(attribute && attribute->flags == (external ? apfsaccess::rw::kAppleXattrDataStream :
            apfsaccess::rw::kAppleXattrDataEmbedded) &&
            store.ReadCommittedExtendedAttributeRange(object, name, 0, bytes, read) && read == expected.size(),
            "W09 extended canonical attribute storage kind and exact EOF")) return false;
    bytes.resize(read);
    return Require(bytes == expected && (external || attribute->data == expected),
        "W09 extended canonical attribute bytes equal the original logical input");
}

bool CheckLink(Store& store, const std::wstring& path, std::uint64_t object, const std::wstring& target)
{
    const auto inode = store.LookupCommittedInodeByPath(path);
    const auto utf8 = WideToUtf8(target);
    const std::vector<std::byte> bytes(reinterpret_cast<const std::byte*>(utf8.data()),
        reinterpret_cast<const std::byte*>(utf8.data() + utf8.size()));
    return Require(inode && inode->object_id == object && inode->node_type == Store::NodeType::SymbolicLink &&
        !inode->is_directory && inode->symlink_target_utf8 == utf8 && inode->logical_size == bytes.size(),
        "W09 extended symlink preserves exact UTF-8 target and byte length") &&
        CheckAttribute(store, object, "com.apple.fs.symlink", bytes, false);
}

bool RunReplayIdReservations()
{
    constexpr auto maximum = 0x0fffffffffffffffull;
    for (unsigned scenario = 0; scenario != 5; ++scenario)
    {
        DirectorySymlinkFixture fixture(false);
        auto spec = TwoProjectableVolumeStore();
        spec.volumes.resize(1); spec.authoritative_checkpoint = true; spec.dual_checkpoint = false; spec.xid = 20;
        spec.block_count = 512; spec.authoritative_checkpoint_ring_blocks = 32;
        spec.authoritative_internal_pool_blocks = 64; spec.authoritative_main_free_blocks = 180;
        if (!WriteFileBytes(fixture.image.path, apfsaccess::testfixture::BuildStoreImage(spec)) || !fixture.Initialize(false)) return false;
        auto& store = *fixture.context->metadata_store;
        const auto original = ReadFileBytes(fixture.image.path);
        const auto floor = store.AuthoritativeAppleCheckpointView()->volumes.front().superblock.next_object_id;
        const auto create = [&](const std::wstring& path, std::uint64_t id = 0) {
            Store::MutationRequest request;
            request.operation = Operation::CreateFile; request.path = path; request.object_id = id;
            request.generation = id ? store.CheckpointXid().value_or(0) + 1 : 0;
            return request;
        };
        const auto generated = [&](const std::wstring& path, std::uint64_t expected) {
            Store::PayloadIdentity identity;
            return Require(store.StageMutation(create(path), &identity) == Store::MutationStatus::Applied && identity.object_id == expected,
                "W09 generated ID follows the exact successful replay reservation cursor");
        };
        if (scenario == 0)
        {
            for (const auto id : {maximum + 1, UINT64_MAX})
                if (!Require(store.StageMutation(create(L"\\invalid", id)) != Store::MutationStatus::Applied &&
                        !store.PendingMutationCount() && !store.LookupWorkingInodeByPath(L"\\invalid"),
                        "W09 replay ID outside the 60-bit namespace leaves no staged mutation")) return false;
            if (!generated(L"\\after-invalid", floor)) return false;
        }
        if (scenario == 1)
        {
            if (!Require(store.StageMutation(create(L"\\gap", floor + 100)) == Store::MutationStatus::Applied,
                    "W09 replay ID gap stages") ||
                !Require(store.StageMutation(create(L"\\below-cursor", floor + 50)) == Store::MutationStatus::Applied,
                    "W09 lower replay ID does not lower the cursor")) return false;
            Store::MutationRequest remove;
            remove.operation = Operation::Delete; remove.path = L"\\gap";
            if (!Require(store.StageMutation(remove) == Store::MutationStatus::Applied,
                    "W09 newly created replay inode is deleted in the same batch") ||
                !generated(L"\\after-delete", floor + 101)) return false;
        }
        if (scenario == 2)
        {
            if (!Require(store.StageMutation(create(L"\\near-limit", maximum - 1)) == Store::MutationStatus::Applied,
                    "W09 highest replay reservation advances without integer wrap") ||
                !generated(L"\\last-id", maximum) ||
                !Require(store.StageMutation(create(L"\\exhausted")) != Store::MutationStatus::Applied &&
                        !store.LookupWorkingInodeByPath(L"\\exhausted"),
                        "W09 exhausting the 60-bit namespace refuses another generated ID") ||
                !Require(store.StageMutation(create(L"\\lower-after-exhaustion", floor + 10)) == Store::MutationStatus::Applied &&
                        store.StageMutation(create(L"\\still-exhausted")) != Store::MutationStatus::Applied &&
                        !store.LookupWorkingInodeByPath(L"\\still-exhausted"),
                        "W09 a lower bound ID never revives an exhausted allocator")) return false;
        }
        if (scenario == 3)
        {
            const std::array requests{create(L"\\preview-first", floor + 100), create(L"\\missing-parent\\preview-second", floor + 101)};
            if (!Require(store.PreflightNativeCapacityMutations(requests) != Store::MutationStatus::Applied &&
                    !store.PendingMutationCount() && !store.LookupWorkingInodeByPath(L"\\preview-first") &&
                    !store.LookupWorkingInodeByPath(L"\\missing-parent\\preview-second"),
                    "W09 failed multi-create preview rolls back the earlier ID reservation and namespace") ||
                !generated(L"\\after-failed-preview", floor)) return false;
        }
        if (scenario == 4)
        {
            if (!Require(store.StageMutation(create(L"\\bound-last-id", maximum)) == Store::MutationStatus::Applied &&
                    store.StageMutation(create(L"\\exhausted-after-bound")) != Store::MutationStatus::Applied &&
                    !store.LookupWorkingInodeByPath(L"\\exhausted-after-bound"),
                    "W09 direct maximum bound ID consumes the last allocator identity") ||
                !Require(store.StageMutation(create(L"\\lower-after-bound-maximum", floor + 10)) == Store::MutationStatus::Applied &&
                    store.StageMutation(create(L"\\still-exhausted-after-bound")) != Store::MutationStatus::Applied &&
                    !store.LookupWorkingInodeByPath(L"\\still-exhausted-after-bound"),
                    "W09 direct maximum bound reservation cannot be revived by a lower bound ID")) return false;
        }
        if (!Require(ReadFileBytes(fixture.image.path) == original,
                "W09 ID reservation and exhaustion tests perform no image publication")) return false;
    }
    return true;
}

bool RunPendingCreateAttribute()
{
    DirectorySymlinkFixture fixture(false);
    auto spec = TwoProjectableVolumeStore();
    spec.volumes.resize(1); spec.authoritative_checkpoint = true; spec.dual_checkpoint = false; spec.xid = 20;
    spec.block_count = 512; spec.authoritative_checkpoint_ring_blocks = 32;
    spec.authoritative_internal_pool_blocks = 64; spec.authoritative_main_free_blocks = 180;
    if (!Require(WriteFileBytes(fixture.image.path, apfsaccess::testfixture::BuildStoreImage(spec)) &&
            fixture.Initialize(false), "W09 pending create attribute canonical image initializes")) return false;
    auto& c = *fixture.context;
    const auto xid = c.metadata_store->CheckpointXid().value_or(0);
    const auto floor = c.metadata_store->AuthoritativeAppleCheckpointView()->volumes.front().superblock.next_object_id;
    Store::MutationRequest preview;
    preview.operation = Operation::CreateFile; preview.path = L"\\preview-reservation";
    preview.object_id = floor + 100; preview.generation = xid + 1;
    if (!Require(c.metadata_store->PreflightNativeCapacityMutation(preview) == Store::MutationStatus::Applied &&
            !c.metadata_store->PendingMutationCount() && !c.metadata_store->LookupWorkingInodeByPath(preview.path),
            "W09 explicit create capacity preview restores namespace and pending state")) return false;
    auto invalid = preview;
    invalid.object_id = 0x1000000000000000ull;
    if (!Require(c.metadata_store->StageMutation(invalid) != Store::MutationStatus::Applied &&
            !c.metadata_store->PendingMutationCount() && !c.metadata_store->LookupWorkingInodeByPath(invalid.path),
            "W09 out-of-range replay create refuses without staging or reserving an ID")) return false;
    const auto stage = [&](Store::MutationRequest request, Store::PayloadIdentity& identity) {
        if (!Require(c.metadata_store->StageMutation(request, &identity) == Store::MutationStatus::Applied,
                "W09 pending create attribute original mutation stages")) return false;
        const auto kind = ManifestJournalKindForOperation(request.operation);
        c.pending_native_writes = true;
        return kind && RecordMutationBestEffort(&c, *kind, request.path, request.secondary_path, request.offset,
            request.length, request.replace_if_exists, 0, request.timestamp_utc, &identity, nullptr, request.inline_payload);
    };
    if (!c.tx_manager->Begin()) return false;
    Store::MutationRequest directory;
    directory.operation = Operation::CreateDirectory; directory.path = L"\\pending-dir";
    Store::PayloadIdentity directory_id, file_id, attribute_id;
    if (!stage(directory, directory_id) || !Require(directory_id.object_id == floor,
            "W09 create preview and refused replay identity do not advance the real allocator")) return false;
    Store::MutationRequest file;
    file.operation = Operation::CreateFile; file.path = L"\\pending-dir\\payload";
    if (!stage(file, file_id)) return false;
    const auto external = BuildPatternPayloadForTest(2 * Block + 83, 0x68);
    Store::MutationRequest attribute;
    attribute.operation = Operation::SetExtendedAttribute; attribute.path = file.path;
    attribute.secondary_path = L"com.apple.ResourceFork";
    attribute.inline_payload = external; attribute.length = external.size();
    if (!stage(attribute, attribute_id)) return false;
    std::uint64_t accepted = 0;
    if (!c.payload_spool->FlushDirtyState() ||
        !AcceptMutationJournalForDeferredCommitBestEffort(&c, L"W09PendingCreateAttribute", &accepted)) return false;
    const auto original = ReadFileBytes(fixture.image.path);
    const auto wal = ReadFileBytes(c.session_root / "accepted.wal");
    HANDLE borrowed = INVALID_HANDLE_VALUE;
    if (!Reopen(fixture, true, borrowed)) return false;
    auto& r = *fixture.context;
    unsigned publications = 0;
    r.metadata_store->SetCommitStageHook([&](std::string_view point) {
        if (point == "before-apple-publish") ++publications;
        return true;
    });
    const auto valid = [&](Store& store) {
        const auto parent = store.LookupCommittedInodeByPath(directory.path);
        const auto child = store.LookupCommittedInodeByPath(file.path);
        const auto fork = store.LookupCommittedExtendedAttribute(file_id.object_id, "com.apple.ResourceFork");
        const auto stream = fork ? apfsaccess::catalog::ReadU64LE(fork->data, 0).value_or(0) : 0;
        return Require(parent && parent->is_directory && parent->object_id == directory_id.object_id &&
            child && child->object_id == file_id.object_id && file_id.object_id == floor + 1 && child->logical_size == 0 &&
            stream == floor + 2 && stream != directory_id.object_id,
            "W09 pending create replay reserves exact inode IDs before external stream allocation") &&
            CheckAttribute(store, file_id.object_id, "com.apple.ResourceFork", external, true);
    };
    if (!Require(ReplayAcceptedWriteAheadLogAfterMetadataBootstrap(r) && publications == 1 &&
            r.tx_manager->Watermarks().accepted_sequence == accepted &&
            r.tx_manager->Watermarks().apfs_durable_sequence == accepted &&
            r.tx_manager->Watermarks().cleanup_sequence == accepted,
            "W09 original pending create plus external xattr publishes exactly once after restart") ||
        !valid(*r.metadata_store)) return false;
    std::vector<std::byte> stable;
    if (!r.metadata_store->Device().ReadForVerification(0, original.size(), stable)) return false;
    const auto completed = ReadFileBytes(r.tx_journal_file);
    if (!Require(stable != original && completed.size() > wal.size() &&
            std::equal(wal.begin(), wal.end(), completed.begin()) &&
            ReplayAcceptedWriteAheadLogAfterMetadataBootstrap(r) && publications == 1 &&
            completed == ReadFileBytes(r.tx_journal_file),
            "W09 pending create replay appends receipts and repeated recovery preserves original WAL")) return false;
    std::vector<std::byte> repeated;
    if (!Require(r.metadata_store->Device().ReadForVerification(0, stable.size(), repeated) && stable == repeated,
            "W09 repeated pending create recovery preserves all committed image bytes")) return false;
    r.owned_metadata_store.reset(); r.metadata_store = nullptr;
    Store fresh(fixture.volume);
    return Require(fresh.PrepareNativeWritePath(), "W09 pending create independent canonical reopen") && valid(fresh);
}

// Root registers Run() and the explicit fault strings listed in the handoff.
bool Run(const std::string& fault = {})
{
    const std::vector<std::string> faults{"corrupt-attribute", "misbound-attribute",
        "misbound-symlink", "misbound-remove", "misbound-restore", "misbound-tail",
        "logged-link-bytes", "unlogged-attribute", "unlogged-symlink", "unlogged-xattr-time"};
    if (!Require(fault.empty() || std::find(faults.begin(), faults.end(), fault) != faults.end(),
            "W09 extended fault selector is known")) return false;
    DirectorySymlinkFixture fixture(false);
    auto spec = TwoProjectableVolumeStore();
    spec.volumes.resize(1); spec.authoritative_checkpoint = true; spec.dual_checkpoint = false; spec.xid = 20;
    spec.block_count = 512; spec.authoritative_checkpoint_ring_blocks = 32;
    spec.authoritative_internal_pool_blocks = 64; spec.authoritative_main_free_blocks = 180;
    if (!Require(WriteFileBytes(fixture.image.path, apfsaccess::testfixture::BuildStoreImage(spec)) &&
            fixture.Initialize(false), "W09 extended ordinary canonical image initializes")) return false;
    auto& c = *fixture.context;
    c.args.write_require_canonical_commit = true; c.args.write_max_dirty_transactions = 64;
    Batch bystander{L"\\bystander", BuildPatternPayloadForTest(Block + 17, 0x35)};
    Batch target{L"\\target", BuildPatternPayloadForTest(Block + 29, 0x57)};
    std::map<std::uint64_t, std::vector<std::byte>> contents;
    c.metadata_store->SetFilePayloadRangeProvider([&](const auto& path, auto identity, auto offset, auto destination) {
        const auto inode = c.metadata_store->LookupWorkingInodeByPath(path);
        const auto found = contents.find(identity.object_id);
        if (!inode || inode->object_id != identity.object_id || inode->xid != identity.generation ||
            found == contents.end() || offset > found->second.size() || destination.size() > found->second.size() - offset)
            return false;
        std::copy_n(found->second.begin() + offset, destination.size(), destination.begin());
        return true;
    });
    for (auto* seed : {&bystander, &target})
    {
        if (!Accept(c, *seed, true)) return false;
        contents[seed->identity.object_id] = seed->payload;
        if (!Require(NT_SUCCESS(CommitNativeMutationsBestEffort(&c, L"W09ExtendedSeed")) &&
                FinalizeMutationJournalBestEffort(&c, L"W09ExtendedSeed"), "W09 extended seed publishes and cleans")) return false;
    }
    const auto original = ReadFileBytes(fixture.image.path);
    const auto source_xid = c.metadata_store->CheckpointXid().value_or(0);
    auto retained = std::make_unique<Store>(fixture.volume);
    std::unique_ptr<Store> extended_retained;
    if (!Require(retained->PrepareNativeWritePath(), "W09 extended retained reader captures original checkpoint")) return false;
    std::vector<std::uint64_t> protected_blocks, accepted;
    std::vector<std::vector<std::byte>> wal_prefixes;
    std::uint64_t link_id = 0, directory_id = 0, external_at = UINT64_MAX;
    unsigned batch = 0;
    const auto make = [](Operation operation, const std::wstring& path, const std::wstring& secondary = L"") {
        Store::MutationRequest request;
        request.operation = operation; request.path = path; request.secondary_path = secondary;
        return request;
    };
    const auto stage = [&](Store::MutationRequest request) {
        Store::PayloadIdentity identity;
        if (!Require(c.metadata_store->StageMutation(request, &identity) == Store::MutationStatus::Applied,
                "W09 extended original mutation stages")) return false;
        if (request.path == L"\\link") link_id = identity.object_id;
        if (request.path == L"\\directory") directory_id = identity.object_id;
        const auto kind = ManifestJournalKindForOperation(request.operation);
        if (!kind) return false;
        if ((fault == "misbound-attribute" && batch == 0 && request.secondary_path == L"com.apple.FinderInfo") ||
            (fault == "misbound-symlink" && batch == 0 && request.operation == Operation::SetSymbolicLinkTarget))
            identity.object_id = bystander.identity.object_id;
        if ((fault == "misbound-remove" && batch == 2 && request.operation == Operation::RemoveExtendedAttribute) ||
            (fault == "misbound-restore" && batch == 1 && request.operation == Operation::RestoreDirectoryFromSymbolicLink) ||
            (fault == "misbound-tail" && batch == 4 && request.operation == Operation::RemoveExtendedAttribute))
            --identity.generation;
        if (fault == "logged-link-bytes" && batch == 0 && request.operation == Operation::SetSymbolicLinkTarget)
            request.secondary_path += L"/other";
        c.pending_native_writes = true;
        return Require(RecordMutationBestEffort(&c, *kind, request.path, request.secondary_path, request.offset,
            request.length, request.replace_if_exists, 0, request.timestamp_utc, &identity, nullptr, request.inline_payload),
            "W09 extended original WAL uses production recording, canonical codec and checksum");
    };
    const auto attribute = [&](Operation operation, const std::wstring& path, const std::wstring& name,
            const std::vector<std::byte>& bytes = {}) {
        auto request = make(operation, path, name);
        request.inline_payload = bytes; request.length = bytes.size();
        if (fault == "unlogged-xattr-time" && batch == 0 && name == L"com.apple.FinderInfo")
            request.timestamp_utc = 133700000000009999ULL;
        return stage(request);
    };
    const auto finder_a = BuildPatternPayloadForTest(32, 0x81);
    const auto finder_b = BuildPatternPayloadForTest(32, 0x92);
    auto embedded_value = BuildPatternPayloadForTest(19, 0xa3);
    embedded_value.front() = std::byte{0}; embedded_value.back() = std::byte{0xff};
    const auto external_a = BuildPatternPayloadForTest(2 * Block + 47, 0xb4);
    const auto external_b = BuildPatternPayloadForTest(3 * Block + 13, 0xc5);
    const auto fork = BuildPatternPayloadForTest(2 * Block + 31, 0xd6);
    const std::vector<std::byte> hint(kWindowsDirectorySymlinkHint.begin(), kWindowsDirectorySymlinkHint.end());
    const std::wstring first_target = L"../Mixed\\Case/./\u503c/../target";
    const std::wstring final_target = L"../../Exact\\Bytes/\u00e9/./target";
    const auto accept = [&]() {
        std::uint64_t sequence = 0;
        if (!c.payload_spool->FlushDirtyState() ||
            !AcceptMutationJournalForDeferredCommitBestEffort(&c, L"W09ExtendedAccept", &sequence)) return false;
        accepted.push_back(sequence);
        wal_prefixes.push_back(ReadFileBytes(c.session_root / "accepted.wal"));
        return true;
    };
    const auto publish = [&]() {
        const auto status = CommitNativeMutationsBestEffort(&c, L"W09ExtendedPublish");
        std::fwprintf(stderr, L"[W09-extended] batch=%u status=%lx xid=%llu detail=%ls\n", batch,
            static_cast<unsigned long>(status), c.metadata_store->CheckpointXid().value_or(0),
            c.metadata_store->LastCommitFailureDetail().c_str());
        return Require(NT_SUCCESS(status), "W09 extended accepted publication omits durability receipt") &&
            CheckHistory(fixture.image.path, original, source_xid, protected_blocks.empty(), protected_blocks) &&
            CheckFile(*retained, target) && CheckFile(*retained, bystander) && CheckFile(*c.metadata_store, bystander) &&
            (!extended_retained ||
                (CheckAttribute(*extended_retained, target.identity.object_id, "com.apple.FinderInfo", finder_a, false) &&
                 CheckAttribute(*extended_retained, target.identity.object_id, "com.apple.ResourceFork", fork, true) &&
                 CheckAttribute(*extended_retained, target.identity.object_id, "user.external", external_a, true) &&
                 CheckLink(*extended_retained, L"\\directory", directory_id, first_target)));
    };
    if (!c.tx_manager->Begin() || !stage(make(Operation::CreateFile, L"\\link")) ||
        !stage(make(Operation::CreateDirectory, L"\\directory")) ||
        !attribute(Operation::SetExtendedAttribute, target.path, L"com.apple.FinderInfo", finder_a) ||
        !attribute(Operation::SetExtendedAttribute, target.path, L"com.apple.ResourceFork", fork) ||
        !attribute(Operation::SetExtendedAttribute, target.path, L"user.binary", embedded_value) ||
        !attribute(Operation::SetExtendedAttribute, target.path, L"user.external", external_a) ||
        !attribute(Operation::SetExtendedAttribute, target.path, L"user.empty") ||
        !stage(make(Operation::SetSymbolicLinkTarget, L"\\link", first_target)) ||
        !stage(make(Operation::SetSymbolicLinkTarget, L"\\directory", first_target)) ||
        !attribute(Operation::SetExtendedAttribute, L"\\directory", kWindowsSymlinkKindNameWide, hint) || !accept()) return false;
    if (fault == "unlogged-attribute")
    {
        auto extra = make(Operation::SetExtendedAttribute, target.path, L"user.binary");
        extra.inline_payload = finder_b; extra.length = finder_b.size();
        if (c.metadata_store->StageMutation(extra) != Store::MutationStatus::Applied) return false;
    }
    if (fault == "unlogged-symlink" &&
        c.metadata_store->StageMutation(make(Operation::SetSymbolicLinkTarget, L"\\link", L"unlogged/target")) !=
            Store::MutationStatus::Applied) return false;
    if (!publish() || !CheckAttribute(*c.metadata_store, target.identity.object_id, "com.apple.FinderInfo", finder_a, false) ||
        !CheckAttribute(*c.metadata_store, target.identity.object_id, "com.apple.ResourceFork", fork, true) ||
        !CheckAttribute(*c.metadata_store, target.identity.object_id, "user.external", external_a, true) ||
        !CheckAttribute(*c.metadata_store, target.identity.object_id, "user.binary",
            fault == "unlogged-attribute" ? finder_b : embedded_value, false) ||
        !CheckAttribute(*c.metadata_store, target.identity.object_id, "user.empty", {}, false) ||
        !CheckAttribute(*c.metadata_store, directory_id, kWindowsSymlinkKindName, hint, false) ||
        (fault != "unlogged-symlink" && !CheckLink(*c.metadata_store, L"\\link", link_id, first_target)) ||
        !CheckLink(*c.metadata_store, L"\\directory", directory_id, first_target)) return false;
    const auto first_publication = ReadFileBytes(fixture.image.path);
    const auto location = std::search(first_publication.begin(), first_publication.end(), external_a.begin(), external_a.end());
    if (!Require(location != first_publication.end() &&
            std::search(location + 1, first_publication.end(), external_a.begin(), external_a.end()) == first_publication.end(),
            "W09 extended corruption target is one exact external payload in the private fixture")) return false;
    external_at = static_cast<std::uint64_t>(location - first_publication.begin());
    extended_retained = std::make_unique<Store>(fixture.volume);
    if (!Require(extended_retained->PrepareNativeWritePath(),
            "W09 extended retained reader captures original embedded, external, fork and symlink publication")) return false;
    ++batch;
    // The host journals directory restoration as a dedicated two-record batch.
    if (!c.tx_manager->Begin() ||
        !stage(make(Operation::RestoreDirectoryFromSymbolicLink, L"\\directory")) ||
        !attribute(Operation::RemoveExtendedAttribute, L"\\directory", kWindowsSymlinkKindNameWide) ||
        !accept() || !publish()) return false;
    ++batch;
    if (!c.tx_manager->Begin() ||
        !attribute(Operation::SetExtendedAttribute, target.path, L"com.apple.FinderInfo", finder_b) ||
        !attribute(Operation::SetExtendedAttribute, target.path, L"com.apple.ResourceFork", embedded_value) ||
        !attribute(Operation::SetExtendedAttribute, target.path, L"user.binary", external_b) ||
        !attribute(Operation::SetExtendedAttribute, target.path, L"user.external", embedded_value) ||
        !attribute(Operation::RemoveExtendedAttribute, target.path, L"user.empty") ||
        !stage(make(Operation::RemoveSymbolicLinkTarget, L"\\link")) ||
        !accept() || !publish() ||
        !CheckAttribute(*c.metadata_store, target.identity.object_id, "com.apple.FinderInfo", finder_b, false) ||
        !CheckAttribute(*c.metadata_store, target.identity.object_id, "com.apple.ResourceFork", embedded_value, false) ||
        !CheckAttribute(*c.metadata_store, target.identity.object_id, "user.binary", external_b, true) ||
        !CheckAttribute(*c.metadata_store, target.identity.object_id, "user.external", embedded_value, false)) return false;
    const auto restored = c.metadata_store->LookupCommittedInodeByPath(L"\\directory");
    const auto removed = c.metadata_store->LookupCommittedInodeByPath(L"\\link");
    if (!Require(restored && restored->object_id == directory_id && restored->is_directory &&
            removed && removed->object_id == link_id && removed->node_type == Store::NodeType::RegularFile &&
            removed->logical_size == 0 && !c.metadata_store->LookupCommittedExtendedAttribute(link_id, "com.apple.fs.symlink") &&
            !c.metadata_store->LookupCommittedExtendedAttribute(directory_id, "com.apple.fs.symlink") &&
            !c.metadata_store->LookupCommittedExtendedAttribute(directory_id, kWindowsSymlinkKindName) &&
            !c.metadata_store->LookupCommittedExtendedAttribute(target.identity.object_id, "user.empty"),
            "W09 extended removal and directory restore retain identity and remove exact attributes")) return false;
    ++batch;
    apfsaccess::rw::InodeMetadataPatch patch;
    patch.mask = apfsaccess::rw::InodeMetadataPatch::ChangeTime;
    patch.change_time_utc = 133700000000000777ULL;
    auto time = make(Operation::SetInodeMetadata, target.path);
    if (!apfsaccess::rw::EncodeInodeMetadataPatch(patch, time.inline_payload)) return false;
    time.length = time.inline_payload.size();
    if (!c.tx_manager->Begin() ||
        !attribute(Operation::RemoveExtendedAttribute, target.path, L"com.apple.FinderInfo") ||
        !attribute(Operation::RemoveExtendedAttribute, target.path, L"com.apple.ResourceFork") ||
        !attribute(Operation::RemoveExtendedAttribute, target.path, L"user.binary") ||
        !attribute(Operation::SetExtendedAttribute, target.path, L"user.external", external_b) ||
        !stage(make(Operation::SetSymbolicLinkTarget, L"\\link", final_target)) ||
        !stage(make(Operation::SetSymbolicLinkTarget, L"\\directory", final_target)) ||
        !attribute(Operation::SetExtendedAttribute, L"\\directory", kWindowsSymlinkKindNameWide, hint) ||
        !stage(time) || !accept() || !publish() ||
        !CheckLink(*c.metadata_store, L"\\link", link_id, final_target) ||
        !CheckLink(*c.metadata_store, L"\\directory", directory_id, final_target)) return false;
    ++batch;
    if (!c.tx_manager->Begin() ||
        !stage(make(Operation::RestoreDirectoryFromSymbolicLink, L"\\directory")) ||
        !attribute(Operation::RemoveExtendedAttribute, L"\\directory", kWindowsSymlinkKindNameWide) || !accept()) return false;
    const auto wal = ReadFileBytes(c.session_root / "accepted.wal");
    const auto spool = ReadFileBytes(c.payload_spool->SpoolFilePath());
    for (const auto& prefix : wal_prefixes)
        if (!Require(prefix.size() <= wal.size() && std::equal(prefix.begin(), prefix.end(), wal.begin()),
                "W09 extended every original accepted WAL prefix is retained exactly")) return false;
    std::filesystem::path evidence;
    if (const auto* destination = std::getenv("APFSACCESS_W09_EVIDENCE"))
    {
        evidence = std::filesystem::path(destination) / (fault.empty() ? "extended-positive" : "extended-" + fault);
        if (!WriteFileBytes(evidence / "original.img", original) ||
            !WriteFileBytes(evidence / "first-publication.img", first_publication) ||
            !WriteFileBytes(evidence / "published.img", ReadFileBytes(fixture.image.path)) ||
            !WriteFileBytes(evidence / "accepted.wal", wal) || !WriteFileBytes(evidence / "payload-spool.bin", spool) ||
            !WriteFileBytes(evidence / "target-expected.bin", target.payload) ||
            !WriteFileBytes(evidence / "external-original.bin", external_a)) return false;
    }
    retained.reset();
    extended_retained.reset();
    HANDLE borrowed = INVALID_HANDLE_VALUE;
    if (!Reopen(fixture, true, borrowed)) return false;
    auto& r = *fixture.context;
    const auto image_bytes = [&]() {
        std::vector<std::byte> bytes;
        if (!r.metadata_store->Device().ReadForVerification(0, static_cast<std::size_t>(spec.block_count * Block), bytes))
            bytes.clear();
        return bytes;
    };
    if (!Require(wal == ReadFileBytes(r.tx_journal_file) && spool == ReadFileBytes(r.payload_spool->SpoolFilePath()),
            "W09 extended startup owner preserves original accepted evidence")) return false;
    if (fault == "corrupt-attribute")
    {
        const auto before = image_bytes();
        if (!Require(external_at < before.size() && external_a.size() <= before.size() - external_at &&
                std::equal(external_a.begin(), external_a.end(), before.begin() + external_at),
                "W09 extended retained external value remains original before corruption")) return false;
        const auto fault_at = external_at + 19;
        const auto at = fault_at - fault_at % Block;
        std::vector<std::byte> cached;
        if (!r.metadata_store->Device().Read(at, Block, cached) || cached.size() != Block) return false;
        auto changed = cached; changed.at(static_cast<std::size_t>(fault_at - at)) ^= std::byte{1};
        OVERLAPPED write_at{};
        write_at.Offset = static_cast<DWORD>(at); write_at.OffsetHigh = static_cast<DWORD>(at >> 32);
        DWORD written = 0;
        const auto started = WriteFile(borrowed, changed.data(), static_cast<DWORD>(Block), &written, &write_at);
        const auto completed = started || (GetLastError() == ERROR_IO_PENDING &&
            GetOverlappedResult(borrowed, &write_at, &written, TRUE));
        if (!Require(completed && written == Block && FlushFileBuffers(borrowed),
                "W09 extended injects one real retained external payload corruption through the fixture owner")) return false;
        auto expected = before; expected.at(static_cast<std::size_t>(external_at + 19)) ^= std::byte{1};
        std::vector<std::byte> general;
        const auto cache_enabled = std::getenv("APFSACCESS_EXPERIMENTAL_BLOCK_READ_CACHE");
        if (!Require(image_bytes() == expected && r.metadata_store->Device().Read(at, Block, general) &&
                (!cache_enabled || std::string(cache_enabled) != "1" || general == cached),
                "W09 extended uncached source sees actual fault while enabled general cache retains old bytes")) return false;
    }
    const auto before = image_bytes();
    const auto spool_before = ReadFileBytes(r.payload_spool->SpoolFilePath());
    const auto index = ReadFileBytes(r.session_root / "payload-spool" / "payload-spool.idx");
    const auto marks = r.tx_manager->Watermarks();
    const auto unchanged = [&]() {
        const auto now = r.tx_manager->Watermarks();
        return !before.empty() && before == image_bytes() && wal == ReadFileBytes(r.tx_journal_file) &&
            spool_before == ReadFileBytes(r.payload_spool->SpoolFilePath()) &&
            index == ReadFileBytes(r.session_root / "payload-spool" / "payload-spool.idx") &&
            marks.accepted_sequence == now.accepted_sequence && marks.apfs_durable_sequence == now.apfs_durable_sequence &&
            marks.cleanup_sequence == now.cleanup_sequence;
    };
    std::vector<std::uint64_t> sequences{UINT64_MAX};
    std::string error;
    const bool proven = r.metadata_store->ProveRetainedAcceptedPrefix(*r.tx_manager, *r.payload_spool,
        r.tx_journal_file, r.payload_spool_volume_identity, sequences, error);
    std::fprintf(stderr, "[W09-extended] fault=%s proof=%d sequences=%zu error=%s\n",
        fault.c_str(), proven, sequences.size(), error.c_str());
    if (!Require(unchanged() && CheckFile(*r.metadata_store, bystander),
            "W09 extended proof preserves complete image, WAL, spool, index and all watermarks")) return false;
    if (!evidence.empty() && (!WriteFileBytes(evidence / "before-proof.img", before) ||
            !WriteFileBytes(evidence / "after-proof.img", image_bytes()) ||
            !WriteFileBytes(evidence / "after-proof.wal", ReadFileBytes(r.tx_journal_file)) ||
            !WriteFileBytes(evidence / "before-proof-spool.bin", spool_before) ||
            !WriteFileBytes(evidence / "after-proof-spool.bin", ReadFileBytes(r.payload_spool->SpoolFilePath())) ||
            !WriteFileBytes(evidence / "before-proof-spool.idx", index) ||
            !WriteFileBytes(evidence / "after-proof-spool.idx", ReadFileBytes(r.session_root / "payload-spool" / "payload-spool.idx"))))
        return false;
    unsigned publications = 0;
    r.metadata_store->SetCommitStageHook([&](std::string_view point) {
        if (point == "before-apple-publish") ++publications;
        return true;
    });
    if (!fault.empty())
    {
        const auto expected = fault.starts_with("misbound-") ? "RetainedAcceptedOriginalStageMismatch" :
            "RetainedAcceptedPublicationReadbackMismatch";
        return Require(!proven && sequences.empty() && error == expected,
                "W09 extended corrupt, misbound or unlogged operation refuses the entire prefix") &&
            Require(!ReplayAcceptedWriteAheadLogAfterMetadataBootstrap(r) && publications == 0 && unchanged(),
                "W09 extended startup refusal publishes nothing and preserves original evidence and all watermarks");
    }
    const std::vector<std::uint64_t> published(accepted.begin(), accepted.end() - 1);
    if (!Require(proven && sequences == published && published.size() == 4 &&
            marks.apfs_durable_sequence < published.front() && marks.cleanup_sequence < published.front(),
            "W09 extended complete publication-byte proof certifies four missing-receipt batches and validates pending restore pair")) return false;
    const auto check_final = [&](Store& store) {
        const auto inode = store.LookupCommittedInodeByPath(target.path);
        const auto link = store.LookupCommittedInodeByPath(L"\\link");
        const auto directory = store.LookupCommittedInodeByPath(L"\\directory");
        return Require(inode && inode->change_time_utc == patch.change_time_utc &&
            link && link->object_id == link_id && link->node_type == Store::NodeType::SymbolicLink &&
            directory && directory->object_id == directory_id && directory->is_directory &&
            !store.LookupCommittedExtendedAttribute(directory_id, "com.apple.fs.symlink") &&
            !store.LookupCommittedExtendedAttribute(directory_id, kWindowsSymlinkKindName) &&
            !store.LookupCommittedExtendedAttribute(target.identity.object_id, "com.apple.ResourceFork") &&
            !store.LookupCommittedExtendedAttribute(target.identity.object_id, "user.binary") &&
            !store.LookupCommittedExtendedAttribute(target.identity.object_id, "com.apple.FinderInfo") &&
            !store.LookupCommittedExtendedAttribute(target.identity.object_id, "user.empty"),
            "W09 extended final inode metadata, directory restore and attribute removals") &&
            CheckLink(store, L"\\link", link_id, final_target) &&
            CheckAttribute(store, target.identity.object_id, "user.external", external_b, true) &&
            CheckFile(store, target) && CheckFile(store, bystander);
    };
    if (!Require(ReplayAcceptedWriteAheadLogAfterMetadataBootstrap(r) && publications == 1 &&
            r.tx_manager->Watermarks().accepted_sequence == accepted.back() &&
            r.tx_manager->Watermarks().apfs_durable_sequence == accepted.back() &&
            r.tx_manager->Watermarks().cleanup_sequence == accepted.back(),
            "W09 extended startup marks proven original prefix then publishes original pending tail once") ||
        !check_final(*r.metadata_store)) return false;
    const auto stable = image_bytes();
    if (!Require(ReplayAcceptedWriteAheadLogAfterMetadataBootstrap(r) && publications == 1 && stable == image_bytes(),
            "W09 extended repeated startup changes no image byte")) return false;
    if (!evidence.empty() && (!WriteFileBytes(evidence / "recovered.img", stable) ||
            !WriteFileBytes(evidence / "recovered.wal", ReadFileBytes(r.tx_journal_file)))) return false;
    r.owned_metadata_store.reset(); r.metadata_store = nullptr;
    Store fresh(fixture.volume);
    return Require(fresh.PrepareNativeWritePath(), "W09 extended independent canonical reopen") && check_final(fresh);
}
}
