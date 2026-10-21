#define APFSACCESS_BACKUP_FIXTURES_ONLY
#include "BackupImageWriterTests.cpp"
#undef APFSACCESS_BACKUP_FIXTURES_ONLY
#include "BackupRetainedSource.h"
#include "BackupPhysicalWriteOwner.h"
#include "BackupMutationContract.h"
#include "BackupHeldOriginalCensus.h"
#include "VolumePhysicalMetadataOwner.h"
#include "../src/VolumePhysicalMediaInternal.h"

namespace apfsaccess::rw
{
// The only physical authority in this executable is a sparse regular-file model.
struct BlockDeviceRawSnapshotTestPeer
{
    static void Seed(BlockDevice& device, const RawSnapshotBinding& binding)
    {
        std::lock_guard handle(device.handle_mutex_);
        std::lock_guard source(device.write_source_mutex_);
        if (!device.exclusive_write_image_ || device.read_handle_ == INVALID_HANDLE_VALUE ||
            device.write_handle_ == INVALID_HANDLE_VALUE) throw std::runtime_error("exclusive model file required");
        device.regular_file_ = false; device.raw_writer_accepted_ = true; device.writable_ = true;
        device.raw_write_limit_bytes_ = binding.media.limit_bytes;
        device.raw_write_source_size_bytes_ = binding.media.disk_size_bytes - binding.media.base_offset_bytes;
        device.raw_writer_identity_ = "backup-retained-source-private-model";
        device.raw_presence_probe_result_ = true;
        device.raw_presence_probe_hook_for_tests_ = [](DWORD& error) { error = ERROR_SUCCESS; return true; };
        device.logical_block_size_cache_ = 4096;
        device.geometry_cached_ = true;
        device.geometry_cache_.logical_block_size = 4096;
        device.geometry_cache_.total_bytes = binding.media.limit_bytes;
        device.raw_snapshot_lease_retired_ = false; device.write_source_handles_retired_ = false;
    }
    static void Retire(BlockDevice& device)
    { std::lock_guard lock(device.handle_mutex_); device.InvalidateWriteSourceHandlesLocked(); }
};
struct VolumePhysicalKeeperTestPeer
{
    static std::shared_ptr<VolumePhysicalSource> Bind(const std::shared_ptr<BlockDevice>& device,
        const RawSnapshotBinding& binding, std::shared_ptr<std::atomic<std::uint64_t>> writes = {})
    {
        std::string error;
#ifdef APFSACCESS_BACKUP_LEGACY_G08_MODEL
        constexpr auto instance = L"USBSTOR\\DISK&VEN_SAMSUNG&PROD_FLASH_DRIVE_FIT&REV_1100\\0375421050005833&0";
#else
        constexpr auto instance = L"USBSTOR\\DISK&VEN_TESTVENDOR&PROD_SURROGATE&REV_0001\\TESTINSTANCE42&0";
#endif
        if (!ValidateVolumePhysicalPolicy(binding, instance, error)) throw std::runtime_error(error);
        const auto lease = device->CaptureHeldRawSnapshotLease();
        if (!lease) throw std::runtime_error("retained model lease required");
        auto impl = std::make_unique<VolumePhysicalSource::Impl>();
        impl->metadata_device = device; impl->binding = binding; impl->instance = instance;
        impl->identity = VolumePhysicalIdentity(binding, instance);
        impl->current = [device, lease = *lease] { return device->IsHeldRawSnapshotLeaseCurrent(lease); };
        impl->read = [device](auto offset, auto size, auto& bytes, bool) { return device->ReadForVerification(offset, size, bytes); };
        impl->write = [device, writes](auto offset, auto bytes) {
            if (writes) ++*writes;
            return device->Write(offset, bytes);
        };
        impl->flush = [device] { return device->Flush(); };
        return std::shared_ptr<VolumePhysicalSource>(new VolumePhysicalSource(std::move(impl)));
    }
};
}

namespace
{
constexpr std::uint64_t kModelBase = 1048576;
#ifdef APFSACCESS_BACKUP_LEGACY_G08_MODEL
constexpr std::uint64_t kModelDiskBytes = 128314368000ull;
#else
constexpr std::uint64_t kModelDiskBytes = 128ull << 30;
#endif
void SeedBackupCarrier(const std::filesystem::path& path, const std::vector<std::byte>& image)
{
    const auto file = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    Check(file != INVALID_HANDLE_VALUE, "fresh private backup recovery carrier");
    struct Close { HANDLE h; ~Close() { CloseHandle(h); } } close{file};
    DWORD got{}; LARGE_INTEGER at{}; at.QuadPart = kModelDiskBytes;
    Check(DeviceIoControl(file, FSCTL_SET_SPARSE, nullptr, 0, nullptr, 0, &got, nullptr) &&
        SetFilePointerEx(file, at, nullptr, FILE_BEGIN) && SetEndOfFile(file), "sparse model disk geometry");
    const auto write = [&](std::uint64_t offset, std::span<const std::byte> bytes) {
        LARGE_INTEGER start{}; start.QuadPart = offset; DWORD wrote{};
        Check(SetFilePointerEx(file, start, nullptr, FILE_BEGIN) &&
            WriteFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &wrote, nullptr) && wrote == bytes.size(), "bounded carrier seed");
    };
    const std::vector<std::byte> sentinel(4096, std::byte{0x71});
    for (const auto offset : {0ull, kModelBase - 4096, kModelBase + image.size(), kModelDiskBytes - 4096}) write(offset, sentinel);
    Check(image.size() % 4096 == 0, "block-aligned canonical carrier seed");
    for (std::size_t at = 0; at < image.size(); at += 4096)
    {
        const auto block = std::span(image).subspan(at, 4096);
        if (std::any_of(block.begin(), block.end(), [](std::byte byte) { return byte != std::byte{}; }))
            write(kModelBase + at, block);
    }
    Check(FlushFileBuffers(file), "carrier seed durable");
}
struct BackupPhysicalCaseOwner
{
    std::shared_ptr<apfsaccess::rw::BlockDevice> device;
    std::shared_ptr<apfsaccess::rw::VolumePhysicalSource> held;
    std::unique_ptr<apfsaccess::rw::BackupRetainedSource> source;
    std::unique_ptr<MetadataStore> store;
    std::shared_ptr<std::atomic<std::uint64_t>> writes = std::make_shared<std::atomic<std::uint64_t>>(0);
};
BackupPhysicalCaseOwner OpenBackupPhysicalCase(const std::filesystem::path& path, const apfsaccess::rw::RawSnapshotBinding& binding)
{
    using namespace apfsaccess::rw;
    std::string error; BackupPhysicalCaseOwner owner;
    owner.device = BlockDevice::OpenExclusiveManagementImage(path.wstring(), kModelBase, error);
    Check(bool(owner.device), "fresh exclusive model owner: " + error);
    BlockDeviceRawSnapshotTestPeer::Seed(*owner.device, binding);
    owner.held = VolumePhysicalKeeperTestPeer::Bind(owner.device, binding, owner.writes);
    const auto checkpoint = LoadAppleCheckpointView(*owner.held, 0, owner.held->SizeBytes(), error);
    Check(bool(checkpoint), "fresh canonical held checkpoint: " + error);
    owner.source = BackupRetainedSource::HeldPhysical(owner.held, binding, owner.held->InstanceId(), *checkpoint, 101, error);
    Check(bool(owner.source), "fresh complete backup capability: " + error);
    auto context = BackupContext(path); context.device_offset_bytes = kModelBase;
    context.allow_raw_device_canonical_commit = true;
    owner.store = CreateVolumePhysicalMetadataStore(owner.held, binding, owner.held->InstanceId(), context, error);
    Check(bool(owner.store), "reviewed checked physical metadata constructor: " + error);
    Check(owner.store->PrepareBackupRetainedWritePath(*owner.source, error), "complete retained backup canonical preparation: " + error);
    return owner;
}
void BackupPhysicalOriginalRecovery(const RawSnapshotBinding& binding, const Fixture& fixture, unsigned scenario)
{
    using namespace apfsaccess::rw;
    const auto root = std::filesystem::absolute("original-recovery-" + std::to_string(scenario));
    Check(std::filesystem::create_directory(root), "fresh original recovery evidence root");
    const auto image = root / "window.sparse", wal = root / "original.wal", spool_root = root / "spool", keys = root / "keys";
    std::filesystem::create_directories(keys); SeedBackupCarrier(image, fixture.image);
    const auto original = Payload(fixture, 17); auto expected = original;
    const bool spooled = scenario == 1 || scenario == 3;
    const std::uint64_t offset = spooled ? 0 : 4101;
    const std::vector<std::byte> replacement(spooled ? original.size() : 1, std::byte{0x6d});
    std::copy(replacement.begin(), replacement.end(), expected.begin() + offset);
    std::string identity, error; std::uint64_t accepted = 0, preimage = 0;
    std::uint64_t original_writes = 0, recovery_writes = 0;
    WriteAheadLog::ProtectedPersistence protection; protection.key_directory = keys; protection.journal_identity.fill(std::byte{0x62});
    std::map<std::uint64_t, std::vector<std::byte>> retained_history;
    {
        auto owner = OpenBackupPhysicalCase(image, binding);
        identity = owner.source->RecoveryIdentity(); protection.source_binding = *owner.source->JournalSourceBinding();
        preimage = *owner.store->CheckpointXid();
        AppleSnapshotRetentionView retention;
        Check(LoadAppleSnapshotRetention(*owner.source, *owner.store->AuthoritativeAppleCheckpointView(), retention, error), "original historical retention census: " + error);
        AppleSnapshotCatalogRecords snapshots; std::vector<AppleSnapshotMetadataClaim> claims;
        Check(LoadAppleSnapshotCatalog(*owner.source, *owner.store->AuthoritativeAppleCheckpointView(), 101, snapshots, claims, error), "exact selected historical metadata owners: " + error);
        const auto retain = [&](std::uint64_t block)
        {
            std::vector<std::byte> bytes; Check(owner.source->Read(block * 4096, 4096, bytes), "original retained block");
            retained_history.emplace(block, std::move(bytes));
        };
        for (const auto& claim : claims) if (std::any_of(snapshots.inventory.begin(), snapshots.inventory.end(), [&](const auto& snapshot) { return claim.view_xid == snapshot.xid; }))
            for (std::uint64_t i = 0; i < claim.block_count; ++i) retain(claim.physical_block + i);
        for (const auto& extent : retention.payload_extents)
            for (std::uint64_t i = 0; i < extent.block_count; ++i) retain(extent.physical_block + i);
        BackupTx tx(L"Strict");
        Check(tx.OpenProtectedJournal(wal.wstring(), std::wstring(identity.begin(), identity.end()), protection, error), "actual protected original opens: " + error);
        PayloadSpool spool(PayloadSpool::Options{spool_root, identity});
        BackupStore::MutationRequest request; request.path = L"\\clone0"; request.offset = offset; request.length = replacement.size();
        BackupStore::PayloadIdentity payload_identity;
        Check(owner.store->StageBackupRetainedMutation(*owner.source, request, &payload_identity) == BackupStore::MutationStatus::Applied, "actual held-source Write stages");
        owner.store->SetFilePayloadRangeProvider([&](const auto& name, auto id, auto at, std::span<std::byte> out) {
            Check(name == request.path && id.object_id == payload_identity.object_id && id.generation == payload_identity.generation &&
                at <= expected.size() && out.size() <= expected.size() - at, "exact accepted payload provider");
            std::copy_n(expected.begin() + at, out.size(), out.begin()); return true;
        });
        Check(tx.Begin(), "original protected transaction begins");
        BackupTx::MutationIntent intent; intent.path = request.path; intent.offset = request.offset; intent.object_id = payload_identity.object_id;
        intent.generation = payload_identity.generation; intent.wal_sequence = tx.NextMutationSequence();
        PayloadSpool::AppendResult reference;
        Check(spool.Append({identity, intent.object_id, intent.generation, intent.offset, intent.wal_sequence, replacement}, &reference), "actual original immutable spool append");
        intent.length = intent.payload_length = reference.payload_length; intent.payload_spool_offset = reference.spool_offset;
        intent.payload_checksum = reference.payload_sha256; if (!spooled) intent.inline_payload = replacement;
        Check(tx.RecordMutation(intent) && spool.FlushDirtyState() && tx.Accept(preimage), "actual original protected Write acceptance");
        accepted = tx.Watermarks().accepted_sequence;
        Check(tx.FlushAcceptedEvidenceDurability(accepted), "original durability barrier before window writes");
        std::vector<std::byte> before_plan, after_plan;
        Check(owner.source->Read(0, fixture.image.size(), before_plan), "window before no-I/O plan");
        AppleCheckpointPublicationPlan plan;
        Check(owner.store->PlanBackupRetainedPendingMutations(*owner.source, {preimage}, plan, error), "exact native held-source plan: " + error);
        Check(owner.source->Read(0, fixture.image.size(), after_plan) && before_plan == after_plan, "staging/planning perform no device writes");
        if (scenario == 1) Check(SetEnvironmentVariableW(L"APFSACCESS_RW_FAULT_WRITE", L"first-half"), "arm actual mid-data failure");
        struct Reset { ~Reset() { SetEnvironmentVariableW(L"APFSACCESS_RW_FAULT_WRITE", nullptr); } } reset;
        const auto cut = scenario == 0 ? "before-apple-device-write" : scenario == 2 ? "before-apple-final-flush" : "";
        const bool published = ExecuteAppleCheckpointPublication(*owner.held, plan, error,
            [&](std::string_view stage) { return owner.source->Current() && stage != cut; });
        if (scenario == 1) SetEnvironmentVariableW(L"APFSACCESS_RW_FAULT_WRITE", nullptr);
        Check(published == (scenario == 3), "real window publication reaches selected cut");
        original_writes = owner.writes->load();
        Check(scenario == 0 ? original_writes == 0 : original_writes != 0, "selected cut has actual expected device-write boundary");
        if (scenario == 3)
        {
            Check(owner.source->Flush(), "actual held flush before ambiguous original marker");
            tx.SetJournalFaultInjectionHook([](std::string_view stage) { return stage == "durable-flush"; });
            Check(!tx.MarkApfsDurableThrough(accepted), "complete authenticated Checkpointed marker then actual original flush failure");
        }
    }
    {
        auto owner = OpenBackupPhysicalCase(image, binding);
        BackupTx tx(L"Strict");
        const bool opened = tx.OpenProtectedStartupJournal(wal.wstring(), std::wstring(identity.begin(), identity.end()), protection, error);
        Check(opened, "fresh nonrepairing protected original owner: " + error);
        if (scenario == 3) Check(tx.Watermarks().apfs_durable_sequence == accepted,
            "fresh original observes complete authenticated Checkpointed marker despite prior flush failure");
        unsigned barriers = 0; tx.SetJournalFaultInjectionHook([&](std::string_view stage) { if (stage == "durable-flush") ++barriers; return false; });
        Check(tx.FlushRetainedOriginalEvidenceDurability() && barriers == 1, "fresh original always flushes even readable marker");
        PayloadSpool spool(PayloadSpool::Options{spool_root, identity});
        if (*owner.store->CheckpointXid() == preimage)
        {
            std::vector<BackupTx::AcceptedTransaction> batches;
            Check(tx.LoadAcceptedTransactionsSinceCleanup(batches) && batches.size() == 1, "fresh original accepted Write retained");
            const auto& record = batches.front().mutations.front(); std::vector<std::byte> payload;
            Check(spool.ReadPersistedRange({identity, record.object_id, record.parent_object_id, record.logical_offset,
                record.payload_length, record.payload_offset, record.payload_spool_id, record.payload_sha256}, payload) && payload == replacement,
                "fresh original spool exact payload before replay");
            BackupStore::MutationRequest replay; replay.path = L"\\clone0"; replay.object_id = record.object_id; replay.generation = record.parent_object_id;
            replay.offset = record.logical_offset; replay.length = record.logical_length;
            Check(owner.store->StageBackupRetainedMutation(*owner.source, replay) == BackupStore::MutationStatus::Applied, "original accepted replay stages on fresh held owner");
            owner.store->SetFilePayloadRangeProvider([&](const auto& name, auto id, auto at, std::span<std::byte> out) {
                Check(name == replay.path && id.object_id == record.object_id && id.generation == record.parent_object_id &&
                    at <= expected.size() && out.size() <= expected.size() - at, "original authenticated replay provider identity and bounds");
                std::copy_n(expected.begin() + at, out.size(), out.begin()); return true;
            });
            AppleCheckpointPublicationPlan replay_plan;
            const bool replayed = owner.store->PlanBackupRetainedPendingMutations(*owner.source, {preimage}, replay_plan, error) &&
                ExecuteAppleCheckpointPublication(*owner.held, replay_plan, error, [&](auto) { return owner.source->Current(); });
            Check(replayed, "actual accepted replay through original held window: " + error);
            owner.store.reset(); auto context = BackupContext(image); context.device_offset_bytes = kModelBase; context.allow_raw_device_canonical_commit = true;
            owner.store = CreateVolumePhysicalMetadataStore(owner.held, binding, owner.held->InstanceId(), context, error);
            Check(owner.store && owner.store->PrepareBackupRetainedWritePath(*owner.source, error), "fresh post-publication canonical owner: " + error);
        }
        Check(*owner.store->CheckpointXid() == preimage + 1, "actual accepted successor selected");
        std::vector<std::byte> before, after; Check(owner.source->Read(0, fixture.image.size(), before), "source before original proof");
        std::vector<std::uint64_t> proven;
        Check(!owner.store->ProveBackupRetainedAcceptedPrefix(tx, spool, wal, "foreign-original", *owner.source, proven, error) && proven.empty(), "wrong original identity refuses without receipt");
        const bool proof = owner.store->ProveBackupRetainedAcceptedPrefix(tx, spool, wal, identity, *owner.source, proven, error);
        Check(proof && proven == std::vector<std::uint64_t>{accepted}, "physical original protected reconstruction and complete postimage proof: " + error);
        Check(owner.source->Read(0, fixture.image.size(), after) && before == after, "proof attempts no APFS writes");
        Check(owner.store->FlushBackupRetainedRecoveryEvidence(*owner.source) && tx.MarkApfsDurableThrough(accepted) && tx.MarkCleanedThrough(accepted),
            "same held target flush precedes original durable and cleaned markers");
        recovery_writes = owner.writes->load();
        Check(scenario < 2 ? recovery_writes != 0 : recovery_writes == 0,
            "fresh old-checkpoint recovery writes; selected postimage settlement never replays writes");
        std::vector<std::byte> bytes;
        Check(owner.store->ReadCommittedFileRange(L"\\clone0", 0, expected.size(), bytes) && bytes == expected, "accepted current bytes exact");
        Check(owner.store->ReadCommittedFileRange(L"\\clone1", 0, original.size(), bytes) && bytes == original, "independent peer bytes unchanged");
        for (const auto& [block, original_block] : retained_history)
            Check(owner.source->Read(block * 4096, 4096, bytes) && bytes == original_block, "selected historical metadata and payload raw bytes unchanged");
        const auto* selected = owner.store->AuthoritativeAppleCheckpointView();
        ApfsSnapshotScope scope{0, owner.source->SizeBytes(), selected->container.superblock.uuid_hex,
            selected->volumes.front().superblock.uuid_hex, 101, selected->container.superblock.xid};
        std::vector<ApfsSnapshotInfo> snapshots;
        Check(ApfsSnapshotStore::Enumerate(*owner.source, scope, snapshots, error) && snapshots.size() == 1, "retained snapshot catalog exact: " + error);
        std::shared_ptr<const NativeApfsSnapshotProjection> projection;
        Check(NativeApfsReader::TryLoadSnapshotProjection(*owner.source, snapshots.front().identity, projection, error), "fresh immutable historical projection: " + error);
        const auto& decmpfs = projection->View().extended_attributes_by_inode.at(19).at("com.apple.decmpfs").data;
        Check(static_cast<bool>(ApfsCompression::DecodeRange(decmpfs, {}, 0, 16384, {}, bytes)) && bytes == std::vector<std::byte>(16384, std::byte{0x7a}),
            "compressed historical stream independently expected decoded bytes");
        Check(owner.source->Current(), "retained authority current after settlement");
    }
    {
        BackupTx final(L"Strict"); std::vector<BackupTx::AcceptedTransaction> pending;
        Check(final.OpenProtectedStartupJournal(wal.wstring(), std::wstring(identity.begin(), identity.end()), protection, error) &&
            final.LoadUnappliedAcceptedTransactions(pending) && pending.empty(), "fresh original confirms durable cleaned boundary");
        std::ifstream file(image, std::ios::binary); std::vector<std::byte> bytes(4096);
        for (const auto offset : {0ull, kModelBase - 4096, kModelBase + fixture.image.size(), kModelDiskBytes - 4096})
        { file.seekg(offset); file.read(reinterpret_cast<char*>(bytes.data()), bytes.size()); Check(file.good() && bytes == std::vector<std::byte>(4096, std::byte{0x71}), "all unrelated physical-model ranges unchanged"); }
    }
    std::cout << "PASS original protected physical-model recovery cut=" << scenario << " spooled=" << spooled <<
        " original_writes=" << original_writes << " recovery_writes=" << recovery_writes << '\n';
}
void BackupPhysicalProductOwner(const RawSnapshotBinding& binding, const Fixture& fixture,
    unsigned scenario = 0, bool cut_gate = false)
{
    using namespace apfsaccess::rw;
    using Product = BackupPhysicalWriteOwner;
    const auto root = std::filesystem::absolute(cut_gate ? "product-cut-" + std::to_string(scenario) : "product-owner");
    Check(std::filesystem::create_directory(root), "fresh product-owner root");
    const auto image = root / "window.sparse", wal = root / "original.wal", spool_root = root / "spool";
    SeedBackupCarrier(image, fixture.image); std::filesystem::create_directory(root / "keys");
    const auto original = Payload(fixture, 17); auto expected = original;
    WriteAheadLog::ProtectedPersistence protection; protection.key_directory = root / "keys";
    protection.journal_identity.fill(std::byte{0x43});
    std::string identity, error; std::uint64_t pending = 0, before_cut = 0;
    std::uint64_t cut_writes = 0, replay_writes = 0;
    std::map<std::uint64_t, std::vector<std::byte>> history_bytes;
    const auto bind = [&](auto& raw, auto& tx, auto& spool) {
        const auto cp = LoadAppleCheckpointView(*raw.held, 0, raw.held->SizeBytes(), error);
        Check(bool(cp), "product current catalog");
        const auto& container = cp->container.superblock;
        Product::Selection selected{container.uuid_hex, cp->volumes.front().superblock.uuid_hex, 101, container.xid};
        const auto canonical = L"apfs-vol:" + std::wstring(container.uuid_hex.begin(), container.uuid_hex.end()) + L":101";
        Check(tx.EnrollCanonicalJournalIdentity(canonical), "catalog-enrolled canonical original owner");
        auto wrong = selected; ++wrong.volume_oid;
        const auto writes = raw.writes->load();
        Check(!Product::Bind(raw.held, binding, raw.held->InstanceId(), wrong, tx, spool, wal, error) && raw.writes->load() == writes,
            "foreign selected volume refused before writes");
        auto owner = Product::Bind(raw.held, binding, raw.held->InstanceId(), selected, tx, spool, wal, error);
        Check(bool(owner), "product binds held capability and exact original: " + error);
        return owner;
    };
    {
        auto raw = OpenBackupPhysicalCase(image, binding);
        if (cut_gate)
        {
            const auto* cp = raw.store->AuthoritativeAppleCheckpointView();
            AppleSnapshotCatalogRecords snapshots; std::vector<AppleSnapshotMetadataClaim> claims;
            AppleSnapshotRetentionView retention;
            Check(LoadAppleSnapshotCatalog(*raw.source, *cp, 101, snapshots, claims, error) &&
                LoadAppleSnapshotRetention(*raw.source, *cp, retention, error), "product original canonical historical census: " + error);
            const auto retain = [&](std::uint64_t block) {
                std::vector<std::byte> bytes;
                Check(raw.source->Read(block * 4096, 4096, bytes), "product historical pin capture");
                history_bytes.emplace(block, std::move(bytes));
            };
            for (const auto& claim : claims)
                if (std::any_of(snapshots.inventory.begin(), snapshots.inventory.end(), [&](const auto& snapshot) { return snapshot.xid == claim.view_xid; }))
                    for (std::uint64_t i = 0; i < claim.block_count; ++i) retain(claim.physical_block + i);
            for (const auto& extent : retention.payload_extents)
                for (std::uint64_t i = 0; i < extent.block_count; ++i) retain(extent.physical_block + i);
            Check(!history_bytes.empty(), "nonempty exact historical metadata/payload pin set");
        }
        identity = raw.source->RecoveryIdentity(); protection.source_binding = *raw.source->JournalSourceBinding();
        {
            BackupTx birth(L"Strict");
            Check(birth.OpenProtectedJournal(wal.wstring(), std::wstring(identity.begin(), identity.end()), protection, error), "new protected original birth owner");
            Check(birth.Begin() && birth.Abort(), "ordinary protected birth/abort establishes original after canonical startup census");
        }
        BackupTx tx(L"Strict");
        Check(tx.OpenProtectedStartupJournal(wal.wstring(), std::wstring(identity.begin(), identity.end()), protection, error), "fresh nonrepairing owner after original birth");
        PayloadSpool spool(PayloadSpool::Options{spool_root, identity});
        auto owner = bind(raw, tx, spool);
        const bool clean_recovery = owner->Recover(error);
        Check(clean_recovery && !owner->RecoveryRequired(), "clean product startup recovery: " + error);
        const std::vector<std::byte> first(1, std::byte{0x4c}); expected[4101] = first.front();
        auto result = owner->Write(L"\\clone0", 4101, first, error);
        Check(result == Product::WriteResult::Committed, "product inline accepted Write settles: " + error);
        std::vector<std::byte> bytes;
        Check(owner->Read(L"\\clone0", 0, expected.size(), bytes) && bytes == expected, "product inline readback exact");
        Check(owner->Read(L"\\clone1", 0, original.size(), bytes) && bytes == original, "product peer remains exact");
        const std::vector<std::byte> second(65536, std::byte{0x5d});
        expected = second;
        result = owner->Write(L"\\clone0", 0, second, error);
        Check(result == Product::WriteResult::Committed, "product 64KiB original spool Write settles: " + error);
        Check(owner->Read(L"\\clone0", 0, expected.size(), bytes) && bytes == expected, "product complete spooled readback exact");
        Check(tx.Watermarks().accepted_sequence == tx.Watermarks().cleanup_sequence && tx.CanClearRecoveryState(), "two sequential original boundaries durable/cleaned");
        before_cut = raw.writes->load();
        const bool spooled_cut = cut_gate && (scenario == 1 || scenario == 3);
        const std::vector<std::byte> third(spooled_cut ? 65536 : 1, std::byte{0x6e});
        const std::uint64_t cut_offset = spooled_cut ? 0 : 17;
        std::copy(third.begin(), third.end(), expected.begin() + cut_offset);
        bool image_ready = false, marker_flush_failed = false;
        unsigned after_image_flushes = 0;
        if (cut_gate && scenario == 3)
            tx.SetJournalFaultInjectionHook([&](std::string_view stage) {
                if (image_ready && stage == "durable-flush" && ++after_image_flushes == 2)
                { marker_flush_failed = true; return true; }
                return false;
            });
        if (cut_gate && scenario == 1)
            Check(SetEnvironmentVariableW(L"APFSACCESS_RW_FAULT_WRITE", L"first-half"), "arm product actual half-write failure");
        struct ResetFault { ~ResetFault() { SetEnvironmentVariableW(L"APFSACCESS_RW_FAULT_WRITE", nullptr); } } reset_fault;
        result = owner->Write(L"\\clone0", cut_offset, third, error, [&](std::string_view stage) {
            if (stage == "before-apple-final-flush") image_ready = true;
            return scenario == 0 ? stage != "before-apple-device-write" :
                scenario == 2 ? stage != "before-apple-final-flush" : true;
        });
        SetEnvironmentVariableW(L"APFSACCESS_RW_FAULT_WRITE", nullptr);
        pending = tx.Watermarks().accepted_sequence;
        cut_writes = raw.writes->load() - before_cut;
        Check(result == Product::WriteResult::RecoveryRequired && owner->RecoveryRequired() &&
            (scenario == 0 ? cut_writes == 0 : scenario == 1 ? cut_writes == 1 : cut_writes > 1) &&
            pending > tx.Watermarks().cleanup_sequence, "accepted product cut retains exact original debt and selected real write boundary: " + error);
        if (cut_gate && scenario == 3)
            Check(marker_flush_failed && after_image_flushes == 2, "actual WAL flush fault occurs after original barrier and authenticated marker append");
        Check(!owner->Read(L"\\clone0", 0, 1, bytes) && !owner->Metadata(L"\\clone0"), "failed owner gates data/metadata visibility");
    }
    {
        auto raw = OpenBackupPhysicalCase(image, binding);
        BackupTx tx(L"Strict");
        Check(tx.OpenProtectedStartupJournal(wal.wstring(), std::wstring(identity.begin(), identity.end()), protection, error), "fresh protected product recovery owner");
        if (cut_gate && scenario == 3)
            Check(tx.Watermarks().apfs_durable_sequence == pending && tx.Watermarks().cleanup_sequence < pending,
                "fresh product sees complete Checkpointed marker despite failed durable flush");
        PayloadSpool spool(PayloadSpool::Options{spool_root, identity});
        auto owner = bind(raw, tx, spool);
        const bool recovered = owner->Recover(error);
        Check(recovered && !owner->RecoveryRequired(), "product accepted original recovery: " + error);
        replay_writes = raw.writes->load();
        Check((scenario < 2 ? replay_writes > 0 : replay_writes == 0) && tx.Watermarks().cleanup_sequence == pending,
            "fresh product settles exact accepted boundary with stage-correct replay/no-replay");
        std::vector<std::byte> bytes;
        Check(owner->Read(L"\\clone0", 0, expected.size(), bytes) && bytes == expected, "fresh product complete current bytes exact");
        Check(owner->Read(L"\\clone1", 0, original.size(), bytes) && bytes == original, "fresh product peer unchanged");
        for (const auto& [block, old] : history_bytes)
            Check(raw.source->Read(block * 4096, 4096, bytes) && bytes == old, "product complete historical raw metadata/payload unchanged");
        const auto current = owner->CheckpointXid();
        const auto writes = raw.writes->load();
        Check(owner->Recover(error) && owner->CheckpointXid() == current && raw.writes->load() == writes, "second product recovery idempotent without APFS replay");
        BlockDeviceRawSnapshotTestPeer::Retire(*raw.device);
        Check(owner->RecoveryRequired() && !owner->Read(L"\\clone0", 0, 1, bytes), "retired G08 capability revokes product owner");
    }
    if (cut_gate)
    {
        BackupTx final(L"Strict"); std::vector<BackupTx::AcceptedTransaction> unapplied;
        Check(final.OpenProtectedStartupJournal(wal.wstring(), std::wstring(identity.begin(), identity.end()), protection, error) &&
            final.LoadUnappliedAcceptedTransactions(unapplied) && unapplied.empty() && final.Watermarks().cleanup_sequence == pending,
            "final independent original owner confirms durable clean boundary");
    }
    std::ifstream file(image, std::ios::binary); std::vector<std::byte> sentinel(4096);
    for (const auto offset : {0ull, kModelBase - 4096, kModelBase + fixture.image.size(), kModelDiskBytes - 4096})
    { file.seekg(offset); file.read(reinterpret_cast<char*>(sentinel.data()), sentinel.size()); Check(file.good() && sentinel == std::vector<std::byte>(4096, std::byte{0x71}), "product unrelated source ranges exact"); }
    std::cout << "PASS product held-owner sequential inline/spool and accepted recovery checks=" << checks << '\n';
    if (cut_gate) std::cout << "PASS product cut=" << scenario << " original_writes=" << cut_writes << " recovery_writes=" << replay_writes << '\n';
}

void BackupPhysicalTypedOwner(const RawSnapshotBinding& binding, const Fixture& fixture, unsigned scenario, bool core_only = false)
{
    using namespace apfsaccess::rw;
    using Product = BackupPhysicalWriteOwner;
    using Op = MetadataStore::MutationOperation;
    const auto root = std::filesystem::absolute(std::string(core_only ? "typed-core-" : "typed-owner-") + std::to_string(scenario));
    Check(std::filesystem::create_directory(root), "fresh typed held-owner root");
    const auto image = root / "window.sparse", spool_root = root / "spool", wal = spool_root / "write-ahead.wal";
    SeedBackupCarrier(image, fixture.image); std::filesystem::create_directory(root / "keys");
    std::filesystem::create_directory(spool_root);
    WriteAheadLog::ProtectedPersistence protection; protection.key_directory = root / "keys";
    protection.journal_identity.fill(std::byte{0x53});
    std::string identity, error; std::uint64_t pending = 0;
    const auto marker = root / "recovery.state";
    const apfsaccess::fshost::RawSnapshotStartupEvidencePaths paths{marker.wstring(),
        (spool_root / "payload-spool.idx").wstring(), (spool_root / "payload-spool.bin").wstring()};
    using Census = apfsaccess::fshost::BackupHeldOriginalCensus;
    std::map<std::uint64_t, std::vector<std::byte>> retained;
    const std::vector<std::byte> content(65536, std::byte{0x69});
    const auto bind = [&](auto& raw, auto& tx, auto& spool) {
        const auto cp = LoadAppleCheckpointView(*raw.held, 0, raw.held->SizeBytes(), error);
        Check(bool(cp), "typed selected canonical checkpoint");
        const auto& nx = cp->container.superblock;
        Check(tx.EnrollCanonicalJournalIdentity(L"apfs-vol:" + std::wstring(nx.uuid_hex.begin(), nx.uuid_hex.end()) + L":101"),
            "typed selected original enrolled");
        auto owner = Product::Bind(raw.held, binding, raw.held->InstanceId(),
            {nx.uuid_hex, cp->volumes.front().superblock.uuid_hex, 101, nx.xid}, tx, spool, wal, error);
        Check(bool(owner), "typed exact held source/original owner: " + error); return owner;
    };
    const auto request = [](Op op, std::wstring path, std::wstring second = L"") {
        MetadataStore::MutationRequest r; r.operation = op; r.path = std::move(path); r.secondary_path = std::move(second); return r;
    };
    {
        auto raw = OpenBackupPhysicalCase(image, binding);
        identity = raw.source->RecoveryIdentity(); protection.source_binding = *raw.source->JournalSourceBinding();
        AppleSnapshotCatalogRecords snapshots; std::vector<AppleSnapshotMetadataClaim> claims;
        AppleSnapshotRetentionView retention;
        const auto* cp = raw.store->AuthoritativeAppleCheckpointView();
        Check(LoadAppleSnapshotCatalog(*raw.source, *cp, 101, snapshots, claims, error) &&
            LoadAppleSnapshotRetention(*raw.source, *cp, retention, error), "typed original canonical historical owners");
        const auto retain = [&](std::uint64_t block) {
            std::vector<std::byte> bytes; Check(raw.source->Read(block * 4096, 4096, bytes), "typed historical block capture");
            retained.emplace(block, std::move(bytes));
        };
        for (const auto& claim : claims)
            if (std::any_of(snapshots.inventory.begin(), snapshots.inventory.end(), [&](const auto& snap) { return snap.xid == claim.view_xid; }))
                for (std::uint64_t i = 0; i < claim.block_count; ++i) retain(claim.physical_block + i);
        for (const auto& extent : retention.payload_extents)
            for (std::uint64_t i = 0; i < extent.block_count; ++i) retain(extent.physical_block + i);
        Check(!retained.empty(), "typed complete historical pin set is nonempty");
        BackupTx tx(L"Strict");
        Check(tx.OpenProtectedStartupJournal(wal.wstring(), std::wstring(identity.begin(), identity.end()), protection, error),
            "typed nonrepairing original owner");
        Check(!std::filesystem::exists(wal) && !std::filesystem::exists(marker) && std::filesystem::is_empty(root / "keys"),
            "protected startup observes absent original/marker/keys without creating evidence");
        auto census = Census::Inspect(*raw.source, tx, wal, paths, 512ull << 20, *raw.store->CheckpointXid(), error);
        Check(census && census->PromoteForRecovery(error), "host original census and retained marker/spool handoff: " + error);
        Check(std::filesystem::exists(wal) && !std::filesystem::is_empty(root / "keys") && !tx.Watermarks().accepted_sequence,
            "real protected original anchor materializes only after full held-source census, without synthetic transaction");
        PayloadSpool spool(PayloadSpool::Options{spool_root, identity}); auto owner = bind(raw, tx, spool);
        Check(owner->Recover(error) && census->CompleteRecovery(owner->CheckpointXid(), error) && census->Ready(), "typed initial recovery: " + error);
        const auto apply = [&](const auto& r) {
            Check(census->BeforeMutation(owner->CheckpointXid(), error), "host dirty marker precedes typed mutation");
            const auto status = owner->Apply(r, {}, error);
            Check(status == Product::WriteResult::Committed, "typed canonical operation " + std::to_string(static_cast<int>(r.operation)) + ": " + error);
            Check(census->CompleteRecovery(owner->CheckpointXid(), error) && census->Ready(), "host clean marker follows exact original settlement");
        };
        auto forged = request(Op::CreateFile, L"\\forged"); forged.object_id = 777;
        const auto writes = raw.writes->load(), accepted = tx.Watermarks().accepted_sequence;
        Check(owner->Apply(forged, {}, error) == Product::WriteResult::Refused &&
            raw.writes->load() == writes && tx.Watermarks().accepted_sequence == accepted, "foreground cannot supply replay object authority");
        auto unsupported = request(Op::CreateSnapshot, L"\\not-admitted");
        Check(owner->Apply(unsupported, {}, error) == Product::WriteResult::Refused && raw.writes->load() == writes,
            "snapshot operations outside typed contract refuse before writes");
        apply(request(Op::CreateDirectory, L"\\backup"));
        apply(request(Op::CreateFile, L"\\backup\\current"));
        Check(census->BeforeMutation(owner->CheckpointXid(), error), "host dirty marker before spooled Write");
        const auto write_status = owner->Write(L"\\backup\\current", 0, content, error);
        const auto write_error = GetLastError();
        Check(write_status == Product::WriteResult::Committed,
            "typed created file actual original 64KiB spool: " + error + " Win32=" + std::to_string(write_error));
        Check(census->CompleteRecovery(owner->CheckpointXid(), error), "host spooled Write marker settled");
        auto mode = request(Op::SetInodeMetadata, L"\\backup\\current");
        InodeMetadataPatch patch; patch.mask = InodeMetadataPatch::Mode; patch.mode = 0600;
        Check(EncodeInodeMetadataPatch(patch, mode.inline_payload), "typed bounded mode patch"); mode.length = mode.inline_payload.size(); apply(mode);
        auto attr = request(Op::SetExtendedAttribute, L"\\backup\\current", L"com.apple.FinderInfo");
        attr.inline_payload.assign(32, std::byte{0x27}); attr.length = attr.inline_payload.size(); apply(attr);
        if (scenario && !core_only) apply(request(Op::CloneFile, L"\\backup\\copy", L"\\backup\\current"));
        auto interrupted = scenario ? request(Op::Rename, L"\\backup\\current", L"\\backup\\renamed") :
            request(Op::CloneFile, L"\\backup\\copy", L"\\backup\\current");
        if (core_only) {
            interrupted = scenario ? mode : attr;
            if (scenario) { patch.mode = 0640; Check(EncodeInodeMetadataPatch(patch, interrupted.inline_payload), "interrupted mode payload"); }
            else interrupted.inline_payload.assign(32, std::byte{0x28});
        }
        bool cut = false;
        Check(census->BeforeMutation(owner->CheckpointXid(), error), "host marker armed before accepted cut");
        const auto status = owner->Apply(interrupted, {}, error, [&](auto stage) {
            if (stage == (scenario ? "before-apple-final-flush" : "before-apple-device-write"))
            { cut = true; return false; } return true;
        });
        pending = tx.Watermarks().accepted_sequence;
        Check(status == Product::WriteResult::RecoveryRequired && cut && pending > tx.Watermarks().cleanup_sequence,
            "typed actual original accepted before publication interruption: " + error);
        Check(!census->Ready(), "host capability does not advertise an owner with accepted debt");
        TransactionManager::RetainedAcceptedHistory history;
        Check(tx.LoadRetainedAcceptedHistory(history, error) && history.pending.size() == 1, "typed actual pending original census");
        MetadataStore::MutationRequest decoded;
        auto malformed = history.pending.front().mutations.front(); malformed.flags |= 0x80;
        Check(!DecodeBackupAcceptedMutation(malformed, decoded, error) && decoded.path.empty(), "authenticated typed shape rejects unsupported flags");
    }
    {
        auto raw = OpenBackupPhysicalCase(image, binding); BackupTx tx(L"Strict");
        Check(tx.OpenProtectedStartupJournal(wal.wstring(), std::wstring(identity.begin(), identity.end()), protection, error),
            "fresh typed original restart");
        const auto before = raw.writes->load();
        Check(!Census::Inspect(*raw.source, tx, wal, paths, 512ull << 20, *raw.store->CheckpointXid() + 5, error) &&
            raw.writes->load() == before, "host pending original rejects foreign selected boundary before writes");
        auto census = Census::Inspect(*raw.source, tx, wal, paths, 512ull << 20, *raw.store->CheckpointXid(), error);
        Check(census && census->PromoteForRecovery(error), "fresh host census preserves dirty original handoff: " + error);
        PayloadSpool spool(PayloadSpool::Options{spool_root, identity}); auto owner = bind(raw, tx, spool);
        if (scenario) {
            Check(!owner->PublishAcceptedForHost(error, [](const auto&, auto& failure) {
                failure = "ExpectedHostNamespaceProofRefusal"; return false;
            }) && tx.Watermarks().cleanup_sequence < pending && raw.writes->load() == 0,
                "host postpublication verifier refusal retains original debt without replay writes");
            owner = bind(raw, tx, spool);
        }
        bool verified = false;
        auto transferred = owner->PublishAcceptedForHost(error, [&](const auto& store, auto&) {
            verified = store.CheckpointXid().value_or(0) > 0; return verified;
        });
        Check(transferred && verified && tx.Watermarks().apfs_durable_sequence == pending &&
            tx.Watermarks().cleanup_sequence < pending && !census->Ready(),
            "host receives exact published store with original durable but uncleaned: " + error);
        Check(!owner->TakeVerifiedStore(error), "retired publication facade cannot transfer another store");
        Check(transferred->FlushBackupRetainedRecoveryEvidence(*raw.source) && tx.MarkCleanedThrough(pending) &&
            spool.CleanupThroughSequence(pending), "host cleanup follows verified namespace and held source flush");
        transferred.reset(); owner = bind(raw, tx, spool);
        Check(owner->Recover(error) && !owner->RecoveryRequired() && tx.Watermarks().cleanup_sequence == pending,
            "fresh typed original confirms host publication settlement: " + error);
        Check(census->CompleteRecovery(owner->CheckpointXid(), error) && census->Ready(), "fresh host ready capability only after original and marker settle");
        Check(scenario ? raw.writes->load() == 0 : raw.writes->load() > 0, "typed cut replay/no-replay boundary");
        const auto current = scenario && !core_only ? L"\\backup\\renamed" : L"\\backup\\current";
        std::vector<std::byte> bytes;
        Check(owner->Read(current, 0, content.size(), bytes) && bytes == content, "typed current file bytes exact");
        const auto inode = owner->Metadata(current), clone = owner->Metadata(L"\\backup\\copy");
        Check(inode && (inode->mode & 07777) == (core_only && scenario ? 0640 : 0600), "typed exact accepted mode preserved");
        if (!core_only) {
            Check(owner->Read(L"\\backup\\copy", 0, content.size(), bytes) && bytes == content &&
                clone && inode->object_id != clone->object_id && (clone->mode & 07777) == 0600,
                "typed clone independent inode identity/mode and bytes preserved");
        const std::vector<std::byte> replacement(1, std::byte{0x5a});
        Check(owner->Write(current, 17, replacement, error) == Product::WriteResult::Committed &&
            owner->Read(L"\\backup\\copy", 0, content.size(), bytes) && bytes == content, "typed shared extent write preserves clone peer: " + error);
        const auto delete_request = request(Op::Delete, L"\\backup\\copy");
        Check(owner->Apply(delete_request, {}, error) == Product::WriteResult::Committed && !owner->Metadata(L"\\backup\\copy"),
            "typed original unlink outcome settles without removing source: " + error);
        }
        Check(owner->Read(L"\\clone1", 0, Payload(fixture, 17).size(), bytes) && bytes == Payload(fixture, 17), "unrelated original clone peer exact");
        for (const auto& [block, old] : retained)
            Check(raw.source->Read(block * 4096, 4096, bytes) && bytes == old, "typed historical raw metadata/payload unchanged");
        Check(owner->Recover(error) && tx.Watermarks().cleanup_sequence == tx.Watermarks().accepted_sequence, "typed repeated cleanup idempotent");
    }
    {
        auto raw = OpenBackupPhysicalCase(image, binding);
        const auto path = scenario && !core_only ? L"\\backup\\renamed" : L"\\backup\\current";
        const auto inode = raw.store->LookupCommittedInodeByPath(path);
        Check(bool(inode), "final independent canonical namespace lookup");
        const auto attr = raw.store->LookupCommittedExtendedAttribute(inode->object_id, "com.apple.FinderInfo");
        Check(attr && attr->data == std::vector<std::byte>(32, core_only && !scenario ? std::byte{0x28} : std::byte{0x27}),
            "final native xattr retained exact");
    }
    std::cout << (core_only ? "PASS typed held metadata and host census scenario=" : "PASS typed held namespace/metadata/clone scenario=")
        << scenario << " checks=" << checks << '\n';
}
}

void BackupHeldCapacityBoundary(const RawSnapshotBinding& binding, const Fixture& fixture)
{
    using namespace apfsaccess::rw;
    const auto root = std::filesystem::absolute("typed-capacity-boundary");
    Check(std::filesystem::create_directory(root), "fresh capacity boundary root");
    const auto image = root / "window.sparse";
    SeedBackupCarrier(image, fixture.image);
    auto raw = OpenBackupPhysicalCase(image, binding);
    const auto identity = raw.source->RecoveryIdentity();
    WriteAheadLog::ProtectedPersistence protection;
    protection.source_binding = *raw.source->JournalSourceBinding(); protection.journal_identity.fill(std::byte{0x71});
    std::string error;
    {
        protection.key_directory = root / "refused-keys"; std::filesystem::create_directory(protection.key_directory);
        BackupTx original(L"Strict"); const auto wal = root / "refused.wal";
        Check(original.OpenProtectedStartupJournal(wal.wstring(), std::wstring(identity.begin(), identity.end()), protection, error), "absent original opens without materialization");
        Check(!original.MaterializeAbsentProtectedStartupJournal([] { return false; }, error) &&
            !std::filesystem::exists(wal) && std::filesystem::is_empty(protection.key_directory),
            "changed held census refuses before original/key writes");
    }
    for (const auto records : {1ull, 8ull, 9ull}) {
        const auto part = root / std::to_string(records); std::filesystem::create_directory(part);
        protection.key_directory = part / "keys"; std::filesystem::create_directory(protection.key_directory);
        protection.read_limits.records = records;
        BackupTx original(L"Strict"); const auto wal = part / "original.wal";
        Check(original.OpenProtectedStartupJournal(wal.wstring(), std::wstring(identity.begin(), identity.end()), protection, error) &&
            original.MaterializeAbsentProtectedStartupJournal([&] { return raw.source->Current(); }, error), "capacity original anchor materialized");
        BackupTx::MutationIntent intent; intent.kind = BackupTx::MutationKind::CreateFile;
        intent.path = L"\\created"; intent.object_id = 900; intent.generation = *raw.store->CheckpointXid();
        const auto bytes = BackupDisk(wal); const auto writes = raw.writes->load();
        Check(original.ProtectedBackupMutationCapacityAvailable(intent, error) == (records >= 8),
            "one exact typed record plus seven terminal reserve boundary");
        Check(BackupDisk(wal) == bytes && raw.writes->load() == writes && !original.Watermarks().accepted_sequence,
            "capacity admission/refusal changes neither original nor image");
        if (records >= 8) {
            Check(original.Begin() && original.RecordMutation(intent), "actual first typed record buffered");
            intent.kind = BackupTx::MutationKind::SetBasicInfo; intent.timestamp_utc = 123;
            Check(original.ProtectedBackupMutationCapacityAvailable(intent, error) == (records == 9) &&
                original.CurrentState() == BackupTx::State::Active && original.PendingMutationCount() == 1 && BackupDisk(wal) == bytes,
                "second typed record has exact active-buffer capacity boundary without acceptance or poisoning");
            if (records == 9) Check(original.RecordMutation(intent) && original.PendingMutationCount() == 2 && BackupDisk(wal) == bytes,
                "sufficient active-buffer capacity accepts the real second metadata record without premature original writes");
            Check(original.Abort(), "bounded declined batch retires normally");
        }
    }
}

#ifndef APFSACCESS_BACKUP_NO_MAIN
int main(int argc, char** argv)
try
{
    using namespace apfsaccess::rw;
    Check(std::filesystem::current_path().root_name() == L"D:", "private D test root");
    auto fixture = BackupFixture(BackupCompressedSpec(), true);
    constexpr std::uint64_t base = kModelBase, disk_size = kModelDiskBytes;
    RawSnapshotBinding binding;
    binding.hardware.kind = RawHardwareIdentityKind::QualifiedSerialTuple;
#ifdef APFSACCESS_BACKUP_LEGACY_G08_MODEL
    binding.hardware.bus_type = BusTypeUsb; binding.hardware.vendor = "Samsung";
    binding.hardware.product = "Flash Drive FIT"; binding.hardware.revision = "1100";
    binding.hardware.serial = "AA00000000000489";
#else
    binding.hardware.bus_type = BusTypeUsb; binding.hardware.vendor = "TestVendor";
    binding.hardware.product = "Surrogate Storage"; binding.hardware.revision = "0001";
    binding.hardware.serial = "TESTSERIAL42";
#endif
    binding.media.disk_guid.fill(std::byte{0x31}); binding.media.partition_guid.fill(std::byte{0x52});
    binding.media.base_offset_bytes = binding.media.partition_offset_bytes = base;
    binding.media.limit_bytes = binding.media.partition_length_bytes = fixture.image.size();
    binding.media.disk_size_bytes = disk_size;
    binding.media.logical_sector_bytes = binding.media.physical_sector_bytes = 4096;
    if (argc > 1 && std::string_view(argv[1]) == "typed-boundaries")
    { BackupHeldCapacityBoundary(binding, fixture); std::cout << "PASS typed capacity boundaries checks=" << checks << '\n'; return 0; }
    if (argc > 1 && std::string_view(argv[1]) == "typed-core")
    {
        for (unsigned scenario = 0; scenario < 2; ++scenario) BackupPhysicalTypedOwner(binding, fixture, scenario, true);
        std::cout << "PASS typed retained metadata focused gate checks=" << checks << '\n'; return 0;
    }
    if (argc > 1 && std::string_view(argv[1]) == "typed-owner")
    {
        for (unsigned scenario = 0; scenario < 2; ++scenario) BackupPhysicalTypedOwner(binding, fixture, scenario);
        std::cout << "PASS typed retained owner focused gate checks=" << checks << '\n'; return 0;
    }
    if (argc > 1 && std::string_view(argv[1]) == "product-cuts")
    {
        for (unsigned scenario = 0; scenario < 4; ++scenario) BackupPhysicalProductOwner(binding, fixture, scenario, true);
        std::cout << "PASS product four cuts checks=" << checks << '\n'; return 0;
    }
    if (argc > 1 && std::string_view(argv[1]) == "product-owner")
    { BackupPhysicalProductOwner(binding, fixture); return 0; }
    if (argc > 1 && std::string_view(argv[1]) == "original-recovery")
    {
        for (unsigned scenario = 0; scenario != 4; ++scenario) BackupPhysicalOriginalRecovery(binding, fixture, scenario);
        std::cout << "PASS original consumer recovery checks=" << checks << '\n'; return 0;
    }
    const auto path = std::filesystem::absolute("backup-window.sparse");
    auto handle = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    Check(handle != INVALID_HANDLE_VALUE, "new private carrier");
    struct Close { HANDLE& h; ~Close() { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); } } close{handle};
    DWORD count{}; LARGE_INTEGER at{};
    Check(DeviceIoControl(handle, FSCTL_SET_SPARSE, nullptr, 0, nullptr, 0, &count, nullptr), "sparse carrier required");
    at.QuadPart = disk_size;
    Check(SetFilePointerEx(handle, at, nullptr, FILE_BEGIN) && SetEndOfFile(handle), "model disk length");
    const std::vector<std::byte> sentinel(4096, std::byte{0x71});
    const auto write = [&](std::uint64_t offset, std::span<const std::byte> bytes) {
        LARGE_INTEGER start{}; start.QuadPart = offset; DWORD wrote{};
        return SetFilePointerEx(handle, start, nullptr, FILE_BEGIN) &&
            WriteFile(handle, bytes.data(), static_cast<DWORD>(bytes.size()), &wrote, nullptr) && wrote == bytes.size();
    };
    for (const auto offset : {0ull, base - 4096, base + fixture.image.size(), disk_size - 4096})
        Check(write(offset, sentinel), "outside sentinel");
    Check(write(base, fixture.image) && FlushFileBuffers(handle), "canonical backup window seed");
    CloseHandle(handle); handle = INVALID_HANDLE_VALUE;
    std::string error;
    auto device = BlockDevice::OpenExclusiveManagementImage(path.wstring(), base, error);
    Check(bool(device), "exclusive model file: " + error);
    BlockDeviceRawSnapshotTestPeer::Seed(*device, binding);
    auto held = VolumePhysicalKeeperTestPeer::Bind(device, binding);
    const auto instance = held->InstanceId();
    auto source = BackupRetainedSource::HeldPhysical(held, binding, instance, fixture.checkpoint, 101, error);
    Check(bool(source), "real canonical backup graph through G08 retained model: " + error);
    const auto identity = DeriveVolumePhysicalRecoveryIdentity(binding, fixture.checkpoint.container.superblock.uuid_hex, 101);
    Check(source->RecoveryIdentity() == identity && source->IsPhysical(), "partitioned original identity");
    Check(source->JournalSourceBinding().has_value() && std::any_of(source->JournalSourceBinding()->begin(),
        source->JournalSourceBinding()->end(), [](std::byte b) { return b != std::byte{0}; }), "nonzero full original protected-source binding");
    auto next_epoch = binding; next_epoch.media.disk_guid.front() ^= std::byte{1};
    auto next_held = VolumePhysicalKeeperTestPeer::Bind(device, next_epoch);
    auto next_source = BackupRetainedSource::HeldPhysical(next_held, next_epoch, instance, fixture.checkpoint, 101, error);
    Check(bool(next_source), "separately trusted G08 model epoch admits same canonical bytes: " + error);
    Check(next_source->RecoveryIdentity() == source->RecoveryIdentity(), "GPT epoch drift retains stable partition debt locator");
    Check(next_source->JournalSourceBinding() != source->JournalSourceBinding(), "same locator and APFS bytes cannot authorize foreign original GPT epoch");
    next_source.reset(); next_held.reset();
    Check(source->Matches(*device, base, fixture.checkpoint, 101, identity), "exact owner selection");
    Check(!source->Matches(*device, 0, fixture.checkpoint, 101, identity) &&
        !source->Matches(*device, base, fixture.checkpoint, 101, "foreign-original"), "offset and original identity substitution refuse");
    BlockDevice unrelated(path.wstring(), base);
    Check(!source->Matches(unrelated, base, fixture.checkpoint, 101, identity), "same-path foreign owner refuses");
    auto wrong = binding; wrong.media.partition_guid.front() ^= std::byte{1};
    Check(!BackupRetainedSource::HeldPhysical(held, wrong, instance, fixture.checkpoint, 101, error), "wrong trusted GPT refuses");
    Check(!BackupRetainedSource::HeldPhysical(held, binding, L"other-instance", fixture.checkpoint, 101, error), "wrong trusted PNP refuses");
    Check(!BackupRetainedSource::WholeImage(device, fixture.checkpoint, 101, error), "raw model cannot enter image factory");
    std::vector<std::byte> bytes;
    Check(source->Read(0, 32, bytes) && std::equal(bytes.begin(), bytes.end(), fixture.image.begin()), "uncached object-header slice");
    Check(!source->Read(source->SizeBytes(), 1, bytes) && source->Flush(), "bounded held read and actual file flush");
    BlockDeviceRawSnapshotTestPeer::Retire(*device);
    Check(!source->Current() && !source->Flush() && !source->Read(0, 32, bytes), "retirement revokes read and durability authority");
    source.reset(); held.reset(); device.reset();
    std::ifstream verify(path, std::ios::binary);
    for (const auto offset : {0ull, base - 4096, base + fixture.image.size(), disk_size - 4096})
    {
        verify.seekg(offset); bytes.resize(4096); verify.read(reinterpret_cast<char*>(bytes.data()), bytes.size());
        Check(verify.good() && bytes == sentinel, "all outside sentinels unchanged");
    }
    std::cout << "PASS regular-file G08 model only; no device factory/open; checks=" << checks << '\n';
    return 0;
}
catch (const std::exception& e) { std::cerr << "FAIL " << e.what() << '\n'; return 1; }
#endif
