#pragma once

// Include after SnapshotMountTests.cpp's Check, Pass, Save and
// DispatchStorageEnvironment definitions. No WinFsp mount is made here.
#include "../../ApfsAccess.ApfsRwEngine/tests/TestFixtureBuilder.h"
#include <future>

namespace apfsaccess::rw {
struct NativeCheckpointHandoffTestAccess {
    static void RequireRecovery(MetadataStore& store) { store.MarkRecoveryRequired(L"IndependentRawHostTestRecovery"); }
    static void DisableNativeReady(MetadataStore& store) { store.native_write_ready_ = false; }
};

// These descriptors describe only an ordinary loopback file. Never open a
// PhysicalDrive path or treat this fixture as hardware qualification evidence.
struct BlockDeviceRawSnapshotTestPeer {
    static bool IsFixturePath(const std::wstring& path) {
        const std::wstring prefix = L"D:\\ApfsAccessScratch\\raw-host-";
        return path.compare(0, prefix.size(), prefix) == 0 &&
            std::filesystem::path(path).filename() == L"loopback-test-never-physical.apfs.img";
    }
    static void Seed(BlockDevice& device, const RawSnapshotDescriptors& descriptors) {
        std::lock_guard<std::mutex> presence(device.raw_presence_probe_mutex_);
        std::lock_guard<std::mutex> handles(device.handle_mutex_);
        std::lock_guard<std::mutex> source(device.write_source_mutex_);
        DWORD flags = 0;
        if (!device.regular_file_.load() || !IsFixturePath(device.path_) ||
            descriptors.media.base_offset_bytes != 4096 || device.BaseOffsetBytes() != 4096 ||
            descriptors.media.limit_bytes != 2048ull * 4096 ||
            descriptors.media.disk_size_bytes != 4096 + 2048ull * 4096 + 8192 ||
            !GetHandleInformation(device.read_handle_.load(), &flags) ||
            !GetHandleInformation(device.write_handle_.load(), &flags))
            throw std::runtime_error("Raw host fixture requires its complete ordinary D: loopback and real held file handles");
        device.regular_file_.store(false);
        device.raw_writer_accepted_.store(true);
        device.writable_.store(true);
        device.raw_write_limit_bytes_.store(descriptors.media.limit_bytes);
        device.raw_write_source_size_bytes_ = descriptors.media.disk_size_bytes - device.BaseOffsetBytes();
        device.raw_writer_identity_ = "gpt:loopback-test-never-physical|base:" +
            std::to_string(device.BaseOffsetBytes()) + "|limit:" + std::to_string(descriptors.media.limit_bytes);
        device.raw_snapshot_lease_retired_ = false;
        device.write_source_handles_retired_ = false;
        device.raw_snapshot_descriptors_attempted_ = true;
        device.raw_snapshot_descriptors_complete_ = true;
        device.raw_snapshot_descriptors_ = descriptors;
        device.raw_snapshot_descriptors_error_.clear();
    }

    // Simulate transport verification only for this exact ordinary test file.
    // Actual forced probes, retirement, binding checks and FlushFileBuffers run.
    class HeldFilePresenceProbe {
        struct FileHandle {
            HANDLE value = INVALID_HANDLE_VALUE;
            ~FileHandle() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
        } validation_;
        BlockDevice& device_;
        HANDLE reader_ = INVALID_HANDLE_VALUE, writer_ = INVALID_HANDLE_VALUE;
        std::wstring path_;
        FILE_ID_INFO identity_{};
        std::uint64_t length_ = 0;
        std::atomic<bool> healthy_{false};
        std::atomic<std::uint64_t> probes_{0};

        bool OriginalFile(HANDLE handle) const {
            FILE_ID_INFO identity{};
            FILE_STANDARD_INFO size{};
            FILE_ATTRIBUTE_TAG_INFO attributes{};
            return handle != INVALID_HANDLE_VALUE && GetFileType(handle) == FILE_TYPE_DISK &&
                GetFileInformationByHandleEx(handle, FileIdInfo, &identity, sizeof(identity)) &&
                GetFileInformationByHandleEx(handle, FileStandardInfo, &size, sizeof(size)) &&
                GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &attributes, sizeof(attributes)) &&
                !size.Directory && !size.DeletePending && size.NumberOfLinks && size.EndOfFile.QuadPart >= 0 &&
                static_cast<std::uint64_t>(size.EndOfFile.QuadPart) == length_ &&
                !(attributes.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_DEVICE | FILE_ATTRIBUTE_REPARSE_POINT)) &&
                identity.VolumeSerialNumber == identity_.VolumeSerialNumber &&
                std::memcmp(identity.FileId.Identifier, identity_.FileId.Identifier, sizeof(identity.FileId.Identifier)) == 0;
        }
        bool EnvelopeRange(std::uint64_t offset, DWORD count, std::byte expected) const {
            LARGE_INTEGER position{};
            position.QuadPart = static_cast<LONGLONG>(offset);
            std::vector<std::byte> bytes(count);
            DWORD done = 0;
            return SetFilePointerEx(validation_.value, position, nullptr, FILE_BEGIN) &&
                ReadFile(validation_.value, bytes.data(), count, &done, nullptr) && done == count &&
                std::all_of(bytes.begin(), bytes.end(), [expected](std::byte byte) { return byte == expected; });
        }
        bool Probe(DWORD& error) noexcept {
            // ProbeUnderlyingDevice owns the presence mutex, including during Flush.
            probes_.fetch_add(1, std::memory_order_relaxed);
            try {
                std::lock_guard<std::mutex> handles(device_.handle_mutex_);
                std::lock_guard<std::mutex> source(device_.write_source_mutex_);
                FileHandle current_path;
                current_path.value = CreateFileW(path_.c_str(), GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
                const bool present = IsFixturePath(path_) && device_.path_ == path_ &&
                    device_.raw_writer_accepted_.load() && !device_.regular_file_.load() &&
                    device_.BaseOffsetBytes() == 4096 && device_.raw_write_limit_bytes_.load() == 2048ull * 4096 &&
                    device_.raw_write_source_size_bytes_ == length_ - 4096 &&
                    device_.read_handle_.load() == reader_ && device_.write_handle_.load() == writer_ &&
                    !device_.write_source_handles_retired_ && !device_.raw_snapshot_lease_retired_ &&
                    OriginalFile(reader_) && OriginalFile(writer_) && OriginalFile(validation_.value) &&
                    OriginalFile(current_path.value) && EnvelopeRange(0, 4096, std::byte{0x5a}) &&
                    EnvelopeRange(length_ - 8192, 8192, std::byte{0x6b});
                healthy_.store(present, std::memory_order_release);
                error = present ? ERROR_SUCCESS : ERROR_INVALID_DATA;
                return present;
            } catch (...) {
                healthy_.store(false, std::memory_order_release);
                error = ERROR_GEN_FAILURE;
                return false;
            }
        }
    public:
        explicit HeldFilePresenceProbe(BlockDevice& device) : device_(device) {
            std::lock_guard<std::mutex> presence(device_.raw_presence_probe_mutex_);
            if (device_.raw_presence_probe_hook_for_tests_)
                throw std::runtime_error("Synthetic loopback transport requires an unowned test-only presence hook");
            {
                std::lock_guard<std::mutex> handles(device_.handle_mutex_);
                std::lock_guard<std::mutex> source(device_.write_source_mutex_);
                path_ = device_.path_;
                reader_ = device_.read_handle_.load();
                writer_ = device_.write_handle_.load();
                length_ = 4096 + 2048ull * 4096 + 8192;
                validation_.value = CreateFileW(path_.c_str(), GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
                if (!IsFixturePath(path_) || validation_.value == INVALID_HANDLE_VALUE ||
                    !GetFileInformationByHandleEx(reader_, FileIdInfo, &identity_, sizeof(identity_)) ||
                    !OriginalFile(reader_) || !OriginalFile(writer_) || !OriginalFile(validation_.value) ||
                    !EnvelopeRange(0, 4096, std::byte{0x5a}) || !EnvelopeRange(length_ - 8192, 8192, std::byte{0x6b}))
                    throw std::runtime_error("Synthetic raw presence requires the exact original held D: loopback handles, size and complete envelope");
            }
            device_.raw_presence_probe_hook_for_tests_ = [this](DWORD& error) { return Probe(error); };
            device_.raw_presence_probe_tick_ms_.store(0, std::memory_order_release);
        }
        ~HeldFilePresenceProbe() {
            std::lock_guard<std::mutex> presence(device_.raw_presence_probe_mutex_);
            device_.raw_presence_probe_hook_for_tests_ = {};
            device_.raw_presence_probe_tick_ms_.store(0, std::memory_order_release);
        }
        HeldFilePresenceProbe(const HeldFilePresenceProbe&) = delete;
        HeldFilePresenceProbe& operator=(const HeldFilePresenceProbe&) = delete;
        bool Healthy() const { return healthy_.load(std::memory_order_acquire); }
        std::uint64_t Probes() const { return probes_.load(std::memory_order_acquire); }
    };
    static void ChangeSerial(BlockDevice& device, const std::string& serial = "DIFFERENT00000490") {
        std::lock_guard<std::mutex> source(device.write_source_mutex_);
        device.raw_snapshot_descriptors_.device.serial = serial;
    }
};
}

namespace {
namespace raw_snapshot_host_tests {
using Buffer = std::vector<std::byte>;
using Owner = apfsaccess::catalog::ContainerMountCoordinator;
using Tx = apfsaccess::rw::TransactionManager;
using DevicePeer = apfsaccess::rw::BlockDeviceRawSnapshotTestPeer;
constexpr std::uint64_t BlockSize = 4096;
constexpr std::uint64_t PrefixSize = 4096;
constexpr std::uint64_t TailSize = 8192;
constexpr std::uint64_t StoreSize = 2048 * BlockSize;

Buffer TextBytes(const std::string& text) {
    Buffer bytes(text.size());
    if (!bytes.empty()) std::memcpy(bytes.data(), text.data(), text.size());
    return bytes;
}

struct FileEvidence {
    bool present = false;
    std::uint64_t volume_serial = 0;
    std::array<unsigned char, 16> file_id{};
    Buffer bytes;
};

FileEvidence ObserveFile(const std::filesystem::path& path) {
    FileEvidence out;
    UniqueWinHandle handle(CreateFileW(path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    if (handle.get() == INVALID_HANDLE_VALUE) {
        const auto error = GetLastError();
        Check(error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND,
            "raw host evidence absence must be an actual missing path");
        return out;
    }
    FILE_ID_INFO identity{};
    FILE_STANDARD_INFO size{};
    Check(GetFileInformationByHandleEx(handle.get(), FileIdInfo, &identity, sizeof(identity)) &&
        GetFileInformationByHandleEx(handle.get(), FileStandardInfo, &size, sizeof(size)) &&
        !size.Directory && size.EndOfFile.QuadPart >= 0 && size.EndOfFile.QuadPart <= 64ll * 1024 * 1024,
        "bounded original raw host file identity");
    out.present = true;
    out.volume_serial = identity.VolumeSerialNumber;
    std::copy_n(identity.FileId.Identifier, out.file_id.size(), out.file_id.begin());
    out.bytes.resize(static_cast<std::size_t>(size.EndOfFile.QuadPart));
    std::size_t cursor = 0;
    while (cursor < out.bytes.size()) {
        const auto count = static_cast<DWORD>((std::min)(out.bytes.size() - cursor, std::size_t{128 * 1024}));
        DWORD done = 0;
        Check(ReadFile(handle.get(), out.bytes.data() + cursor, count, &done, nullptr) && done == count,
            "read complete original raw host evidence bytes");
        cursor += done;
    }
    return out;
}

void SameFile(const FileEvidence& expected, const std::filesystem::path& path) {
    const auto actual = ObserveFile(path);
    Check(actual.present == expected.present && actual.volume_serial == expected.volume_serial &&
        actual.file_id == expected.file_id && actual.bytes == expected.bytes,
        "raw host refusal or pure inspection preserves file identity, absence and exact bytes: " + path.string());
}

void SameMarks(const Tx::DurabilityWatermarks& expected, const Tx& journal) {
    const auto actual = journal.Watermarks();
    Check(actual.accepted_sequence == expected.accepted_sequence &&
        actual.apfs_durable_sequence == expected.apfs_durable_sequence &&
        actual.cleanup_sequence == expected.cleanup_sequence, "raw host original journal watermarks unchanged");
}

void Envelope(const Buffer& before, const Buffer& after) {
    Check(before.size() == PrefixSize + StoreSize + TailSize && after.size() == before.size() &&
        std::equal(before.begin(), before.begin() + PrefixSize, after.begin()) &&
        std::equal(before.end() - TailSize, before.end(), after.end() - TailSize),
        "raw host publication preserves entire 4096-byte prefix and 8192-byte tail");
}

apfsaccess::rw::RawSnapshotDescriptors LoopbackDescriptors() {
    apfsaccess::rw::RawSnapshotDescriptors out;
    out.device = {BusTypeUsb, "Samsung", "Flash Drive FIT", "1100", "AA00000000000489"};
    auto& media = out.media;
    media.disk_guid.fill(std::byte{0x0a});
    media.partition_guid.fill(std::byte{0x0b});
    media.base_offset_bytes = media.partition_offset_bytes = PrefixSize;
    media.partition_length_bytes = media.limit_bytes = StoreSize;
    media.disk_size_bytes = PrefixSize + StoreSize + TailSize;
    media.logical_sector_bytes = 512;
    media.physical_sector_bytes = 4096;
    return out;
}

Buffer BuildLoopbackImage() {
    using namespace apfsaccess::testfixture;
    BuilderStore spec;
    spec.authoritative_checkpoint = true;
    spec.block_count = 2048;
    spec.authoritative_checkpoint_ring_blocks = 64;
    spec.authoritative_internal_pool_blocks = 64;
    spec.volumes.front().uuid_hex = std::string(32, 'b');
    auto sibling = spec.volumes.front();
    sibling.oid = 102;
    sibling.name = "Sibling";
    sibling.uuid_hex = std::string(32, 'c');
    spec.volumes.push_back(std::move(sibling));
    auto store = BuildAuthoritativeStoreImage(spec);
    Check(store.size() == StoreSize, "ordinary authoritative BuilderStore geometry");
    apfsaccess::testfixture::PutU32LE(store, 2 * BlockSize + 0x20, 1);
    Buffer omap(store.begin() + 2 * BlockSize, store.begin() + 3 * BlockSize);
    apfsaccess::testfixture::FletcherForBlock(omap, BlockSize);
    std::copy(omap.begin(), omap.end(), store.begin() + 2 * BlockSize);
    Buffer image(PrefixSize, std::byte{0x5a});
    image.insert(image.end(), store.begin(), store.end());
    image.resize(image.size() + TailSize, std::byte{0x6b});
    return image;
}

struct Harness {
    std::filesystem::path root, image;
    std::unique_ptr<DispatchStorageEnvironment> recovery_environment, spool_environment;
    std::unique_ptr<Owner> owner;
    std::unique_ptr<DevicePeer::HeldFilePresenceProbe> presence_probe;
    std::vector<std::unique_ptr<MountContext>> sessions;
    std::array<Arguments, 2> arguments;
    bool admitted = false;

    explicit Harness(const std::string& tag) {
        static unsigned sequence = 0;
        const std::filesystem::path scratch(L"D:\\ApfsAccessScratch");
        Check(std::filesystem::is_directory(scratch), "D:\\ApfsAccessScratch must exist for raw host artifacts");
        const auto scratch_attributes = GetFileAttributesW(scratch.c_str());
        Check(scratch_attributes != INVALID_FILE_ATTRIBUTES && !(scratch_attributes & FILE_ATTRIBUTE_REPARSE_POINT),
            "fixed raw fixture parent has no reparse redirection");
        root = scratch / ("raw-host-" + tag + "-" + std::to_string(GetCurrentProcessId()) + "-" +
            std::to_string(GetTickCount64()) + "-" + std::to_string(++sequence));
        Check(std::filesystem::create_directory(root), "exclusive owned D: raw host fixture directory");
        {
            const auto directory = CreateFileW(root.c_str(), GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
            Check(directory != INVALID_HANDLE_VALUE, "open only the new raw fixture evidence directory");
            ScopeExit close{[&] { CloseHandle(directory); }};
            const auto attributes = GetFileAttributesW(root.c_str());
            Check(attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_REPARSE_POINT),
                "new raw fixture evidence directory has no reparse redirection");
            USHORT compression = COMPRESSION_FORMAT_DEFAULT;
            DWORD returned = 0;
            const bool compressed = DeviceIoControl(directory, FSCTL_SET_COMPRESSION, &compression, sizeof(compression),
                nullptr, 0, &returned, nullptr) != FALSE;
            const auto compressed_attributes = GetFileAttributesW(root.c_str());
            Check(compressed && compressed_attributes != INVALID_FILE_ATTRIBUTES &&
                    (compressed_attributes & FILE_ATTRIBUTE_COMPRESSED),
                "raw fixture children inherit compression before any image or recovery evidence is created");
        }
        recovery_environment = std::make_unique<DispatchStorageEnvironment>(L"APFSACCESS_RECOVERY_ROOT", root / "recovery");
        spool_environment = std::make_unique<DispatchStorageEnvironment>(L"APFSACCESS_SPOOL_ROOT", root / "spool");
        image = root / "loopback-test-never-physical.apfs.img";
        Save(image, BuildLoopbackImage());
        for (std::size_t index = 0; index < arguments.size(); ++index) {
            auto& args = arguments[index];
            args.device = image.wstring();
            args.device_offset_bytes = PrefixSize;
            args.container_id = std::wstring(32, L'a');
            args.volume_object_id = 101 + index;
            args.volume = index ? L"Sibling" : L"Data";
            args.container_manifest = (root / "never-mounted.manifest").wstring();
            args.recovery_identity = L"apfs-recovery-v1-" + std::wstring(43, index ? L'E' : L'A');
            args.readwrite = true;
            args.write_backend = L"Native";
            args.write_safety_level = L"Strict";
            args.write_recovery_policy = L"FailClosed";
            args.write_crash_replay_mode = L"FailClosed";
            args.write_require_canonical_commit = true;
            args.allow_legacy_scaffold_for_fixtures = false;
            args.allow_raw_physical_write = true;
            args.enable_raw_snapshots = true;
            args.raw_snapshot_hardware.bus_type = BusTypeUsb;
            args.raw_snapshot_hardware.vendor = L"Samsung";
            args.raw_snapshot_hardware.product = L"Flash Drive FIT";
            args.raw_snapshot_hardware.serial = L"AA00000000000489";
            Check(IsValidRecoveryIdentity(args.recovery_identity), "original canonical 43-character recovery identity");
        }
    }
    ~Harness() { Close(); }
    void Close() {
        // Release only the in-process fixture owners, without draining accepted
        // debt or replacing any files. Artifacts stay on D: for parent review.
        presence_probe.reset();
        sessions.clear();
        owner.reset();
        admitted = false;
    }
    std::filesystem::path Storage(std::size_t index) const {
        return BuildPayloadSpoolSessionRoot(arguments[index], apfsaccess::rw::PayloadSpool::ResolveDefaultRoot());
    }
    std::filesystem::path Marker(std::size_t index) const { return BuildRecoveryMarkerPath(arguments[index]); }
    std::filesystem::path Wal(std::size_t index) const { return Storage(index) / "write-ahead.wal"; }
    std::vector<std::filesystem::path> Files() const {
        std::vector<std::filesystem::path> paths{image};
        for (std::size_t index = 0; index < arguments.size(); ++index) {
            paths.push_back(Marker(index));
            paths.push_back(Storage(index) / "payload-spool.idx");
            paths.push_back(Storage(index) / "payload-spool.bin");
            paths.push_back(Wal(index));
        }
        return paths;
    }
    void Put(const std::filesystem::path& path, const Buffer& bytes) {
        std::filesystem::create_directories(path.parent_path());
        Save(path, bytes);
    }
    MountContext& Selected() { return *sessions.at(0); }
    MountContext& Sibling() { return *sessions.at(1); }

    bool OpenPeers(std::string& error) {
        Check(!owner && sessions.empty(), "fresh original host and journal owners on every restart");
        owner = Owner::Open(image.string(), PrefixSize, error,
            apfsaccess::catalog::CatalogLoadPolicy::StrictApple, true, true);
        if (!owner) return false;
        DevicePeer::Seed(const_cast<apfsaccess::rw::BlockDevice&>(owner->Device()), LoopbackDescriptors());
        presence_probe = std::make_unique<DevicePeer::HeldFilePresenceProbe>(
            const_cast<apfsaccess::rw::BlockDevice&>(owner->Device()));
        Check(owner->Device().ProbeUnderlyingDevice(true) && presence_probe->Healthy() && presence_probe->Probes() == 1,
            "real forced probe validates the complete original loopback through the private test-only transport hook");
        for (std::size_t index = 0; index < arguments.size(); ++index) {
            auto session = std::make_unique<MountContext>();
            session->args = arguments[index];
            session->native_write_enabled = true;
            auto& ctx = *session;
            sessions.push_back(std::move(session));
            const auto storage = Storage(index);
            ctx.recovery_marker_file = Marker(index);
            ctx.tx_journal_file = Wal(index);
            ctx.raw_snapshot_startup_evidence =
                std::make_unique<apfsaccess::fshost::NativeRawSnapshotStartupEvidence>(
                    apfsaccess::fshost::RawSnapshotStartupEvidencePaths{ctx.recovery_marker_file.wstring(),
                        (storage / "payload-spool.idx").wstring(), (storage / "payload-spool.bin").wstring()},
                    kPayloadSpoolMaxBytes);
            if (!ctx.raw_snapshot_startup_evidence->Ready()) {
                error = ctx.raw_snapshot_startup_evidence->Failure();
                return false;
            }
            // Observe real marker/index/payload before either production loader.
            apfsaccess::fshost::RawSnapshotStartupEvidence observed;
            Check(ctx.raw_snapshot_startup_evidence->Verify(observed), "original startup evidence before loaders");
            const auto marker = LoadRecoveryMarkerAtStartup(ctx);
            if (marker.load_status == RecoveryMarkerLoadStatus::Invalid) {
                error = "RecoveryMarkerInvalid";
                return false;
            }
            ctx.tx_manager = std::make_unique<Tx>(ctx.args.write_safety_level);
            const auto canonical = Utf8ToWide("apfs-vol:" + owner->ContainerUuidHex() + ":" +
                std::to_string(ctx.args.volume_object_id));
            if (!ctx.tx_manager->EnrollCanonicalJournalIdentity(canonical) ||
                !ctx.tx_manager->OpenStartupJournal(ctx.tx_journal_file.wstring(), BuildWalVolumeIdentity(ctx.args), error))
                return false;
            Check(ctx.tx_manager->ConfiguredVolumeIdentity() == ctx.args.recovery_identity &&
                ctx.tx_manager->EnrolledCanonicalJournalIdentity() == canonical,
                "canonical enrollment retains the original recovery-form WAL identity");
            if (!ObserveFile(ctx.tx_journal_file).present)
                Check(!ctx.tx_manager->ObservedJournalAppendLeaseGeneration(), "absent startup WAL remains absent before admission");
            ctx.payload_spool_volume_identity = WideToUtf8(BuildWalVolumeIdentity(ctx.args));
            ctx.payload_spool = std::make_unique<apfsaccess::rw::PayloadSpool>(
                apfsaccess::rw::PayloadSpool::Options{storage, ctx.payload_spool_volume_identity,
                    kPayloadSpoolMaxBytes, kPayloadSpoolForegroundFlushBytes, kPayloadSpoolForegroundFlushAppends,
                    8ull * 1024 * 1024, 32ull * 1024 * 1024});
            std::wstring mount_error;
            if (!MountManifestSession(*owner, ctx.args, ctx, mount_error)) {
                error = WideToUtf8(mount_error);
                return false;
            }
        }
        return InitializeManifestCheckpointCensus(*owner, sessions, error);
    }
    bool Admit(std::string& error) {
        admitted = PrepareRawSnapshotHostStartup(*owner, sessions, error);
        return admitted;
    }
    void Start() {
        std::string error;
        const bool opened = OpenPeers(error);
        Check(opened, "actual original raw host bootstrap: " + error);
        const bool ready = Admit(error);
        Check(ready, "actual raw host startup admission: " + error);
    }
    ContainerControlRequest Request() const {
        ContainerControlRequest request;
        request.volume_object_id = 101;
        return request;
    }
    ContainerControlActionResult Create(const std::string& name) {
        auto request = Request();
        request.snapshot_name = name;
        return SnapshotCreateForControl(Selected(), *owner, request);
    }
    ContainerControlActionResult Delete(const apfsaccess::catalog::ApfsSnapshotIdentity& identity) {
        auto request = Request();
        request.has_snapshot_identity = true;
        request.snapshot_identity = identity;
        return SnapshotDeleteForControl(Selected(), *owner, request);
    }
    ContainerControlActionResult Recover() { return SnapshotRecoverForControl(Selected(), *owner, Request()); }
    LiveVolumeVerificationScope Scope() {
        LiveVolumeVerificationScope scope;
        std::string error;
        SnapshotControlLocks gates(Selected(), true);
        Check(gates.acquired, "full original host locks for scope observation");
        auto& ctx = Selected();
        const bool described = owner->InspectPublishedCheckpointForVerification(ctx.container_volume_oid,
            [&](const auto& store, const auto& checkpoint, auto& detail) {
                return DescribeVolumeVerificationSource(ctx, store, checkpoint, scope, detail);
            }, error);
        Check(described, "actual physical-window verification scope: " + error);
        return scope;
    }
    ContainerControlActionResult List() {
        auto request = Request();
        request.verification_scope = Scope();
        return SnapshotListForControl(Selected(), *owner, request);
    }
    std::vector<apfsaccess::catalog::ApfsSnapshotInfo> Inventory() {
        const auto result = List();
        Check(result.success && result.code == "SnapshotInventory" && result.snapshot_inventory.has_value(),
            "actual raw host list control: " + result.code);
        const auto& inventory = *result.snapshot_inventory;
        Check(inventory.scope.store_offset_bytes == PrefixSize && inventory.scope.store_size_bytes == StoreSize &&
            inventory.scope.container_uuid_hex == owner->ContainerUuidHex() && inventory.scope.volume_oid == 101 &&
            inventory.scope.volume_uuid_hex == std::string(32, 'b') && inventory.scope.checkpoint_xid == owner->CheckpointXid(),
            "public list retains exact physical scope instead of relative engine receipt scope");
        for (const auto& snapshot : inventory.snapshots)
            Check(snapshot.identity.scope == inventory.scope, "each public snapshot identity has exact physical scope");
        return inventory.snapshots;
    }
};

struct Evidence {
    std::vector<std::filesystem::path> paths;
    std::vector<FileEvidence> files;
    explicit Evidence(const Harness& harness) : paths(harness.Files()) {
        for (const auto& path : paths) files.push_back(ObserveFile(path));
    }
    void Unchanged() const {
        for (std::size_t index = 0; index < paths.size(); ++index) SameFile(files[index], paths[index]);
    }
};

void SameCensus(const std::vector<apfsaccess::catalog::VolumeCheckpointPins>& expected, const Owner& owner) {
    const auto actual = owner.CheckpointCensusSnapshot();
    Check(actual.size() == expected.size(), "pure host inspection preserves complete census size");
    for (std::size_t index = 0; index < expected.size(); ++index)
        Check(actual[index].volume_object_id == expected[index].volume_object_id &&
            actual[index].required_checkpoint_xids == expected[index].required_checkpoint_xids &&
            actual[index].unapplied_accepted_work == expected[index].unapplied_accepted_work,
            "pure host inspection preserves original census pins and debt");
}

void PureCapabilities(Harness& harness, bool writable, bool recoverable) {
    const Evidence before(harness);
    const auto census = harness.owner->CheckpointCensusSnapshot();
    std::vector<Tx::DurabilityWatermarks> marks;
    std::vector<std::uint64_t> epochs;
    for (const auto& session : harness.sessions) {
        marks.push_back(session->tx_manager->Watermarks());
        epochs.push_back(session->metadata_store->StateEpoch());
    }
    for (unsigned repeat = 0; repeat < 2; ++repeat) {
        const auto capabilities = GetSnapshotControlCapabilities(harness.Selected(), *harness.owner);
        Check(capabilities.inventory == writable && capabilities.mutation == writable &&
            GetSnapshotRecoveryCapability(harness.Selected(), *harness.owner) == recoverable,
            "actual host capabilities reflect clean writes or paused recovery without file mutation");
        before.Unchanged();
        SameCensus(census, *harness.owner);
        for (std::size_t index = 0; index < harness.sessions.size(); ++index) {
            SameMarks(marks[index], *harness.sessions[index]->tx_manager);
            Check(epochs[index] == harness.sessions[index]->metadata_store->StateEpoch(),
                "pure capability inspection preserves every original store epoch");
        }
    }
}

void AdmittedMarkerPins(Harness& harness) {
    const Evidence before(harness);
    for (std::size_t index = 0; index < harness.arguments.size(); ++index) {
        const auto marker = harness.Marker(index);
        Check(ObserveFile(marker).present && harness.sessions[index]->raw_snapshot_startup_evidence &&
            harness.sessions[index]->raw_snapshot_startup_evidence->OwnsMarkerPath(marker.wstring()) &&
            harness.sessions[index]->raw_snapshot_startup_evidence->VerifyMarkerOwner(),
            "admitted startup retains actual marker ownership from the original evidence fence");
        UniqueWinHandle writer(CreateFileW(marker.c_str(), GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr));
        const auto writer_error = GetLastError();
        Check(writer.get() == INVALID_HANDLE_VALUE && writer_error == ERROR_SHARING_VIOLATION,
            "retained admitted marker excludes every external writer");
        auto renamed = marker;
        renamed += L".unowned-replacement";
        Check(!std::filesystem::exists(renamed), "fresh marker rename destination");
        Check(!MoveFileExW(marker.c_str(), renamed.c_str(), 0) && !DeleteFileW(marker.c_str()),
            "retained admitted marker excludes external rename and deletion");
        const auto parent = marker.parent_path();
        auto parent_renamed = parent;
        parent_renamed += L".unowned-replacement";
        Check(!std::filesystem::exists(parent_renamed) && !MoveFileExW(parent.c_str(), parent_renamed.c_str(), 0),
            "admitted original recovery parent cannot be renamed or replaced");
    }
    before.Unchanged();
}

void Writable(Harness& harness) {
    Check(!harness.owner->IsRecoveryRequired(), "engine completion latch released");
    for (const auto& session : harness.sessions) {
        const auto& ctx = *session;
        const auto marks = ctx.tx_manager->Watermarks();
        Check(ctx.raw_snapshot_startup_admitted && ctx.raw_snapshot_authority && ctx.native_write_enabled &&
            !ctx.raw_snapshot_host_write_paused && !ctx.recovery_active && !ctx.write_degraded && !ctx.pending_native_writes &&
            !ctx.raw_snapshot_restart_sequence && !ctx.raw_snapshot_completion_xid &&
            SnapshotRecoveryStoreClean(*ctx.metadata_store) && SnapshotRecoverySpoolClean(ctx) &&
            marks.accepted_sequence == marks.apfs_durable_sequence && marks.accepted_sequence == marks.cleanup_sequence,
            "all original host peers restored only with clean engine, journals and spools");
    }
    for (const auto& entry : harness.owner->CheckpointCensusSnapshot())
        Check(!entry.unapplied_accepted_work && entry.required_checkpoint_xids.empty(), "all census pins retired after completion");
}

void CleanMarker(Harness& harness, std::uint64_t xid) {
    RecoveryMarkerState marker;
    Check(LoadRecoveryMarkerState(harness.Marker(0), marker) == RecoveryMarkerLoadStatus::Loaded &&
        !marker.dirty && marker.last_commit_xid == xid, "actual original clean marker readback has the exact completed XID");
}

apfsaccess::rw::NativeSnapshotIntent Debt(Harness& harness) {
    std::vector<Tx::AcceptedTransaction> accepted;
    std::string error;
    Check(harness.Selected().tx_manager->LoadAcceptedTransactionsSinceCleanup(accepted, &error) &&
        accepted.size() == 1 && accepted.front().mutations.size() == 1,
        "one actual original WAL snapshot receipt remains accepted: " + error);
    apfsaccess::rw::NativeSnapshotIntent intent;
    Check(apfsaccess::rw::WriteAheadLog::SnapshotIntentIsConsistent(accepted.front().mutations.front()) &&
        apfsaccess::rw::DecodeNativeSnapshotIntent(accepted.front().mutations.front().inline_payload, intent) && intent.raw_receipt &&
        accepted.front().preimage_checkpoint_xid == intent.scope.checkpoint_xid &&
        accepted.front().mutations.front().volume_identity == WideToUtf8(harness.arguments[0].recovery_identity),
        "debt comes from a consistent original raw receipt and recovery identity");
    return intent;
}

void PausedDebt(Harness& harness, const apfsaccess::rw::NativeSnapshotIntent& intent) {
    const auto marks = harness.Selected().tx_manager->Watermarks();
    Check(marks.accepted_sequence && marks.cleanup_sequence < marks.accepted_sequence &&
        harness.Selected().recovery_active && harness.Selected().write_degraded && harness.Selected().pending_native_writes,
        "selected host stays blocked while accepted receipt is uncleaned");
    for (const auto& session : harness.sessions)
        Check(!session->native_write_enabled, "every original host peer remains paused while selected debt is retained");
    const auto census = harness.owner->CheckpointCensusSnapshot();
    const auto selected = std::find_if(census.begin(), census.end(), [](const auto& entry) { return entry.volume_object_id == 101; });
    Check(selected != census.end() && selected->unapplied_accepted_work && selected->required_checkpoint_xids == intent.pins,
        "selected census retains exact receipt pins until actual host completion");
    std::string error;
    apfsaccess::catalog::ApfsSnapshotScope scope;
    const Evidence before(harness);
    {
        SnapshotControlLocks gates(harness.Selected(), true);
        Check(gates.acquired && !InspectRawSnapshotHostResume(harness.Selected(), *harness.owner, scope, error),
            "strict clean-resume inspection cannot bypass retained accepted debt");
    }
    before.Unchanged();
    PureCapabilities(harness, false, true);
}

void CleanAbsentStartup() {
    Harness harness("absent-startup");
    const Evidence before(harness);
    std::string error;
    const bool opened = harness.OpenPeers(error);
    Check(opened, "clean raw host peer bootstrap: " + error);
    before.Unchanged();
    for (const auto& session : harness.sessions) {
        apfsaccess::fshost::RawSnapshotStartupEvidence observed;
        Check(session->raw_snapshot_startup_evidence->Verify(observed) && !observed.marker.present &&
            !observed.spool_index.present && !observed.payload.present &&
            session->raw_snapshot_startup_evidence->Reads().bytes_read == 0,
            "real fence retains all three absent observations without file creation");
        Check(!session->tx_manager->ObservedJournalAppendLeaseGeneration() &&
            session->tx_manager->ObservedJournalWriterLeaseGeneration() &&
            !ObserveFile(session->tx_journal_file).present && !session->raw_snapshot_authority,
            "original absent WAL is enrolled and leased without materialization or self-attested authority");
    }
    const bool ready = harness.Admit(error);
    Check(ready, "clean absent raw host admission: " + error);
    SameFile(before.files.front(), harness.image);
    Check(harness.Selected().raw_snapshot_authority == harness.Sibling().raw_snapshot_authority,
        "actual startup installs one shared authority for the complete cohort");
    for (std::size_t index = 0; index < harness.arguments.size(); ++index) {
        Check(ObserveFile(harness.Wal(index)).present &&
            ObserveFile(harness.Marker(index)).present &&
            !ObserveFile(harness.Storage(index) / "payload-spool.idx").present &&
            !ObserveFile(harness.Storage(index) / "payload-spool.bin").present,
            "admitted startup owns original WAL and marker while empty spool files remain absent");
    }
    Writable(harness);
    AdmittedMarkerPins(harness);
    const Evidence transport(harness);
    const auto probes = harness.presence_probe->Probes();
    Check(harness.owner->Device().ProbeUnderlyingDevice(true) && harness.presence_probe->Healthy() &&
        harness.presence_probe->Probes() == probes + 1,
        "forced host presence probe synchronously revalidates original held file IDs, path and complete envelope");
    Check(const_cast<apfsaccess::rw::BlockDevice&>(harness.owner->Device()).Flush() &&
        harness.presence_probe->Healthy() && harness.presence_probe->Probes() == probes + 2,
        "actual BlockDevice flush forces transport validation and still calls real FlushFileBuffers");
    transport.Unchanged();
    PureCapabilities(harness, true, true);
    Check(harness.Inventory().empty(), "ordinary authoritative fixture starts without snapshots");
    Pass("raw host clean absent startup uses real fences and original WAL enrollment");
}

std::unique_ptr<MountContext> RecoveryPolicyContext(const Harness& harness, std::size_t index) {
    auto ctx = std::make_unique<MountContext>();
    ctx->args = harness.arguments.at(index);
    // This context is used only by the file-evidence policy, never by a device
    // opener or MountManifestSession. The real harness keeps its loopback path.
    ctx->args.device = L"\\\\.\\PhysicalDrive2";
    ctx->native_write_enabled = true;
    Check(IsRawPhysicalDevicePath(ctx->args.device) &&
        !IsRawPhysicalDevicePath(harness.arguments.at(index).device) &&
        BuildPayloadSpoolSessionRoot(ctx->args, apfsaccess::rw::PayloadSpool::ResolveDefaultRoot()) == harness.Storage(index) &&
        BuildRecoveryMarkerPath(ctx->args) == harness.Marker(index),
        "actual raw-path policy uses the original immutable-identity evidence paths without device access");
    return ctx;
}

void RecoveryIdentityStartupOrdering() {
    Harness harness("identity-policy-ordering");
    harness.Start();
    harness.Close();
    const Evidence original(harness);
    for (std::size_t index = 0; index < harness.arguments.size(); ++index)
        Check(ObserveFile(harness.Wal(index)).present, "restart starts with both real modern WALs already persisted");
    const auto open_journal = [&](MountContext& ctx, std::size_t index) {
        ctx.tx_journal_file = harness.Wal(index);
        ctx.tx_manager = std::make_unique<Tx>(ctx.args.write_safety_level);
        const auto canonical = L"apfs-vol:" + ctx.args.container_id + L":" + std::to_wstring(ctx.args.volume_object_id);
        std::string error;
        Check(ctx.tx_manager->EnrollCanonicalJournalIdentity(canonical) &&
            ctx.tx_manager->OpenStartupJournal(ctx.tx_journal_file.wstring(), BuildWalVolumeIdentity(ctx.args), error),
            "actual existing-WAL startup owner: " + error);
        Check(ctx.tx_manager->ObservedJournalWriterLeaseGeneration() &&
            ctx.tx_manager->ConfiguredVolumeIdentity() == harness.arguments[index].recovery_identity,
            "restart holds the real WAL writer with the original modern identity");
    };
    for (std::size_t first : {0u, 1u}) {
        auto alpha = RecoveryPolicyContext(harness, first);
        auto beta = RecoveryPolicyContext(harness, 1 - first);
        PreflightRecoveryIdentityStartup(*alpha);
        Check(!alpha->recovery_identity_blocked && alpha->native_write_enabled && !alpha->tx_manager,
            "old interleaving admits the first policy while both WALs are closed");
        open_journal(*alpha, first);
        {
            UniqueWinHandle probe(CreateFileW(harness.Wal(first).c_str(), GENERIC_READ,
                FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
            const auto error = GetLastError();
            Check(probe.get() == INVALID_HANDLE_VALUE && error == ERROR_SHARING_VIOLATION,
                "natural production reader sharing conflicts with the already-open sibling WAL writer");
        }
        PreflightRecoveryIdentityStartup(*beta);
        Check(beta->recovery_identity_blocked && !beta->native_write_enabled && beta->write_degraded &&
            beta->runtime_recovery_reason == L"LegacyRecoveryEvidenceAmbiguous" && !beta->tx_manager,
            "old interleaving blocks the second modern sibling with the exact legacy-evidence reason");
        original.Unchanged();
    }
    std::array<std::unique_ptr<MountContext>, 2> cohort{
        RecoveryPolicyContext(harness, 0), RecoveryPolicyContext(harness, 1)};
    for (auto& ctx : cohort) {
        Check(!cohort[0]->tx_manager && !cohort[1]->tx_manager, "all policies precede every journal open");
        PreflightRecoveryIdentityStartup(*ctx);
        Check(!ctx->recovery_identity_blocked && ctx->native_write_enabled && !ctx->write_degraded,
            "whole-cohort preflight admits both persisted modern sibling WALs");
        original.Unchanged();
    }
    for (std::size_t index = 0; index < cohort.size(); ++index) open_journal(*cohort[index], index);
    original.Unchanged();
    for (auto& ctx : cohort) ctx.reset();
    std::string error;
    Check(harness.OpenPeers(error), "original per-volume mount/marker/WAL path after cohort preflight: " + error);
    original.Unchanged();
    Check(harness.Admit(error), "actual checkpoint census and clean restart authority after preflight: " + error);
    Writable(harness);
    original.Unchanged();
    Pass("raw identity startup: natural held-writer interleaving blocks either second peer; all-first preflight restarts both existing WALs");
}

void RecoveryIdentityPreflightRefusals() {
    using Wal = apfsaccess::rw::WriteAheadLog;
    for (const std::string mode : {"missing-identity", "malformed-identity", "malformed-wal", "torn-wal",
            "mixed-wal-identities", "legacy-clean-wal", "legacy-spool", "scan-exception"}) {
        Harness harness("identity-preflight-" + mode);
        harness.Start();
        harness.Close();
        auto ctx = RecoveryPolicyContext(harness, 0);
        std::vector<std::filesystem::path> extra;
        if (mode == "missing-identity") ctx->args.recovery_identity.clear();
        else if (mode == "malformed-identity") ctx->args.recovery_identity = L"apfs-recovery-v1-malformed";
        else if (mode == "malformed-wal") harness.Put(harness.Wal(1), TextBytes("malformed sibling WAL"));
        else if (mode == "torn-wal") {
            auto bytes = ObserveFile(harness.Wal(1)).bytes;
            const auto tail = TextBytes("torn");
            bytes.insert(bytes.end(), tail.begin(), tail.end());
            harness.Put(harness.Wal(1), bytes);
        } else if (mode == "mixed-wal-identities" || mode == "legacy-clean-wal") {
            Arguments legacy = ctx->args;
            legacy.recovery_identity.clear();
            Wal::Record record;
            record.transaction_id = record.sequence = 1;
            record.operation = Wal::OperationKind::CreateFile;
            record.state = Wal::RecordState::Cleaned;
            record.object_id = 43;
            record.path_utf8 = "\\legacy-evidence.bin";
            Buffer bytes;
            if (mode == "mixed-wal-identities") {
                record.volume_identity = WideToUtf8(BuildWalVolumeIdentity(harness.arguments[1]));
                for (const auto byte : Wal::EncodeForTest(record)) bytes.push_back(static_cast<std::byte>(byte));
                record.transaction_id = record.sequence = 2;
            }
            record.volume_identity = WideToUtf8(BuildLegacyWalVolumeIdentity(legacy));
            const auto encoded = Wal::EncodeForTest(record);
            for (const auto byte : encoded) bytes.push_back(static_cast<std::byte>(byte));
            const auto path = mode == "mixed-wal-identities" ? harness.Wal(1) :
                BuildLegacyPayloadSpoolSessionRoot(legacy, apfsaccess::rw::PayloadSpool::ResolveDefaultRoot()) / "write-ahead.wal";
            harness.Put(path, bytes);
            extra.push_back(path);
        } else if (mode == "legacy-spool") {
            Arguments legacy = ctx->args;
            legacy.recovery_identity.clear();
            const auto path = BuildLegacyPayloadSpoolSessionRoot(legacy,
                apfsaccess::rw::PayloadSpool::ResolveDefaultRoot()) / "payload-spool.bin";
            harness.Put(path, TextBytes("retained legacy payload"));
            extra.push_back(path);
        } else ctx->test_force_recovery_identity_scan_exception = true;
        const Evidence before(harness);
        std::vector<FileEvidence> extra_before;
        for (const auto& path : extra) extra_before.push_back(ObserveFile(path));
        const auto reason = mode == "missing-identity" ? L"ImmutableRecoveryIdentityMissing" :
            mode == "malformed-identity" ? L"ImmutableRecoveryIdentityInvalid" : L"LegacyRecoveryEvidenceAmbiguous";
        for (unsigned attempt = 0; attempt != 2; ++attempt) {
            PreflightRecoveryIdentityStartup(*ctx);
            Check(ctx->recovery_identity_blocked && !ctx->native_write_enabled && ctx->write_degraded &&
                ctx->recovery_active && ctx->runtime_recovery_reason == reason && !ctx->tx_manager &&
                !ctx->raw_snapshot_startup_admitted && !ctx->raw_snapshot_authority,
                "unchanged production policy refuses before journal ownership: " + mode);
            before.Unchanged();
            for (std::size_t index = 0; index < extra.size(); ++index) SameFile(extra_before[index], extra[index]);
        }
        Pass("raw cohort preflight preserves every original evidence byte and file ID: " + mode);
    }
}

void MixedPreflightContextSettlement() {
    Harness harness("mixed-preflight-settlement");
    harness.Start();
    harness.Close();
    const Evidence original(harness);
    std::string error;
    auto owner = Owner::Open(harness.image.string(), PrefixSize, error,
        apfsaccess::catalog::CatalogLoadPolicy::StrictApple, true, true);
    Check(owner && owner->RawLeaseHeld(), "mixed initialization owns the original loopback coordinator: " + error);
    auto& device = const_cast<apfsaccess::rw::BlockDevice&>(owner->Device());
    DevicePeer::Seed(device, LoopbackDescriptors());
    auto presence = std::make_unique<DevicePeer::HeldFilePresenceProbe>(device);
    Check(device.ProbeUnderlyingDevice(true), "mixed initialization probes only the original held loopback");
    Arguments process_args;
    process_args.status_file = (harness.root / "mixed-initialization.status.json").wstring();
    std::vector<std::unique_ptr<MountContext>> contexts;
    ScopeExit settle{[&] {
        presence.reset();
        (void)SettleFailedManifestInitialization(process_args, *owner, contexts);
    }};
    for (std::size_t index = 0; index < 3; ++index) {
        auto ctx = std::make_unique<MountContext>();
        ctx->args = harness.arguments[index == 0 ? 0 : 1];
        ctx->native_write_enabled = true;
        contexts.push_back(std::move(ctx));
    }
    auto& initialized = *contexts[0];
    auto& failing = *contexts[1];
    auto& never_mounted = *contexts[2];
    std::wstring mount_error;
    Check(MountManifestSession(*owner, initialized.args, initialized, mount_error),
        "first preallocated context initializes its actual metadata store: " + WideToUtf8(mount_error));
    initialized.tx_journal_file = harness.Wal(0);
    initialized.tx_manager = std::make_unique<Tx>(initialized.args.write_safety_level);
    const auto canonical = L"apfs-vol:" + initialized.args.container_id + L":101";
    Check(initialized.tx_manager->EnrollCanonicalJournalIdentity(canonical) &&
        initialized.tx_manager->OpenStartupJournal(initialized.tx_journal_file.wstring(),
            BuildWalVolumeIdentity(initialized.args), error), "first initialized context retains its original WAL: " + error);
    const auto marks = initialized.tx_manager->Watermarks();
    for (auto* ctx : {&initialized, &failing}) {
        ctx->sd = BuildWritableVolumeSecurityDescriptor(&ctx->sd_size);
        Check(ctx->sd != nullptr, "mixed initialization owns real security resources");
        ctx->session_root = harness.root / (ctx == &initialized ? "initialized-session" : "failing-session");
        ctx->cache_root = ctx->session_root / "hydrate";
        Check(std::filesystem::create_directories(ctx->cache_root), "mixed initialization owns actual hydration resources");
    }
    failing.args.container_id = std::wstring(32, L'f');
    Check(!MountManifestSession(*owner, failing.args, failing, mount_error) && !mount_error.empty() &&
        !failing.metadata_store && !failing.container_coordinator,
        "second preallocated context fails the actual container-identity mount check");
    Check(owner->MountedVolumeCount() == 1 && initialized.metadata_store &&
        !never_mounted.metadata_store && !never_mounted.tx_manager && never_mounted.session_root.empty(),
        "cohort contains initialized, failing and never-mounted contexts at settlement");
    for (const auto& ctx : contexts)
        Check(!ctx->fs && ctx->winfsp_lifecycle_phase.load() == WinFspLifecyclePhase::Empty,
            "mixed context settlement remains before any WinFsp filesystem exists");
    original.Unchanged();
    // Settlement releases the borrowed device; detach its test hook first.
    presence.reset();
    Check(SettleFailedManifestInitialization(process_args, *owner, contexts),
        "production failed-initialization settlement accepts the original mixed preallocated cohort");
    Check(!owner->RawLeaseHeld() && owner->MountedVolumeCount() == 0,
        "successful mixed settlement releases original stores and the held source lease");
    for (const auto& ctx : contexts)
        Check(!ctx->native_write_enabled && !ctx->mount_ready.load() && !ctx->manifest_mount_attached.load() &&
            !ctx->metadata_store && !ctx->container_coordinator && !ctx->container_volume_oid &&
            !ctx->sd && !ctx->sd_size && (ctx->session_root.empty() || !std::filesystem::exists(ctx->session_root)),
            "mixed settlement clears borrowed stores and only owned initialization resources for every context");
    const auto status_bytes = ObserveFile(process_args.status_file).bytes;
    const std::string status(reinterpret_cast<const char*>(status_bytes.data()), status_bytes.size());
    Check(status.find("\"leaseHeld\":false") != std::string::npos && status.find("\"volumes\":[]") != std::string::npos,
        "mixed settlement publishes an empty terminal cohort only after the actual drain");
    original.Unchanged();
    SameMarks(marks, *initialized.tx_manager);
    Pass("raw preallocated initialized/failing/never-mounted cohort settles without changing original source or recovery artifacts");
}

void RawWireDelete() {
    Harness harness("wire-delete");
    harness.Start();
    Check(harness.Create("wire-survivor").success && harness.Create("wire-victim").success,
        "actual raw host publishes both snapshots before wire deletion");
    const auto inventory = harness.Inventory();
    const auto victim = std::find_if(inventory.begin(), inventory.end(),
        [](const auto& value) { return value.identity.name_utf8 == "wire-victim"; });
    const auto survivor = std::find_if(inventory.begin(), inventory.end(),
        [](const auto& value) { return value.identity.name_utf8 == "wire-survivor"; });
    Check(inventory.size() == 2 && victim != inventory.end() && survivor != inventory.end(),
        "wire delete selects the exact owned snapshot from actual held raw inventory");
    const auto exact = victim->identity;
    const auto checkpoint = harness.owner->CheckpointXid();
    // The real control endpoint is outside the held recovery-evidence trees.
    const auto control_root = harness.root.parent_path() / ("raw-wire-control-" + harness.root.filename().string());
    Check(std::filesystem::create_directory(control_root), "exclusive ordinary D: raw control endpoint directory");
    Arguments process_args;
    process_args.container_control_file = (control_root / "wire-delete.control").wstring();
    process_args.container_control_token = Utf8ToWide(kControlToken);
    process_args.status_file = (control_root / "wire-delete.status.json").wstring();
    const auto dispatch = [&](const std::string& body) {
        std::error_code response_error;
        std::filesystem::remove(process_args.container_control_file + L".response", response_error);
        Check(!response_error, "retire only this test's previous control response");
        harness.Put(process_args.container_control_file, TextBytes(body));
        const auto written = ObserveFile(process_args.container_control_file);
        Check(written.present && written.bytes == TextBytes(body), "real control file contains exact request bytes");
        ContainerControlRequest wire_request;
        std::string parse_error;
        Check(ParseContainerControlRequestContents(body, WideToUtf8(process_args.container_control_token), wire_request, parse_error),
            "actual process token authenticates this wire body: " + parse_error);
        const bool processed = ProcessContainerControlRequest(process_args, *harness.owner, harness.sessions);
        const auto dispatch_error = GetLastError();
        if (!processed) std::cerr << "raw wire dispatch failed at " << WideToUtf8(process_args.container_control_file)
            << " win32=" << dispatch_error << '\n';
        Check(processed, "actual file-backed ProcessContainerControlRequest consumes raw delete request; win32=" +
            std::to_string(dispatch_error) + " request=" + std::to_string(std::filesystem::exists(process_args.container_control_file)) +
            " response=" + std::to_string(std::filesystem::exists(process_args.container_control_file + L".response")) +
            " status=" + std::to_string(std::filesystem::exists(process_args.status_file)));
        Check(!std::filesystem::exists(process_args.container_control_file), "raw wire request is consumed");
        const auto bytes = ObserveFile(process_args.container_control_file + L".response").bytes;
        std::istringstream input(std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size()));
        std::vector<std::string> fields;
        std::string line;
        while (std::getline(input, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            fields.push_back(line);
        }
        while (!fields.empty() && fields.back().empty()) fields.pop_back();
        Check(fields.size() == 4 && fields[0] == "APFS-CONTROL/1" && fields[1] == kControlRequestId &&
            (fields[2] == "ok" || fields[2] == "error"), "actual raw delete response envelope and request ID");
        return fields[2] + ":" + fields[3];
    };
    const auto body = ControlContents("snapshot-delete", 101, DispatchDeleteArgs(exact));
    ContainerControlRequest parsed;
    std::string error;
    Check(ParseControl(body, parsed, error) && parsed.snapshot_identity_needs_owner_scope &&
        parsed.has_snapshot_identity && parsed.snapshot_identity.scope.checkpoint_xid == checkpoint &&
        !parsed.snapshot_identity.scope.store_offset_bytes && !parsed.snapshot_identity.scope.store_size_bytes &&
        !parsed.snapshot_identity.scope.volume_oid && parsed.snapshot_identity.scope.container_uuid_hex.empty(),
        "real nine-field wire parser marks its checkpoint-only scope for held-owner binding");
    const Evidence original(harness);
    const auto alpha_marks = harness.Selected().tx_manager->Watermarks();
    const auto beta_marks = harness.Sibling().tx_manager->Watermarks();
    const auto unchanged = [&] {
        original.Unchanged();
        SameMarks(alpha_marks, *harness.Selected().tx_manager);
        SameMarks(beta_marks, *harness.Sibling().tx_manager);
        Check(harness.owner->CheckpointXid() == checkpoint && harness.Inventory().size() == 2,
            "raw wire refusal preserves checkpoint and both actual snapshots");
        Writable(harness);
    };
    for (const auto stale_checkpoint : {checkpoint - 1, checkpoint + 1}) {
        auto fields = DispatchDeleteArgs(exact);
        fields[8] = std::to_string(stale_checkpoint);
        Check(dispatch(ControlContents("snapshot-delete", 101, fields)) == "error:SnapshotRuntimeDeleteStaleIdentity",
            "wire owner binding cannot replace an old or future requested checkpoint");
        unchanged();
    }
    const auto exact_fields = DispatchDeleteArgs(exact);
    for (std::size_t field : {2u, 3u, 4u, 5u, 6u, 7u}) {
        auto tampered = exact_fields;
        tampered[field] = std::to_string(std::stoull(tampered[field]) + 1);
        Check(dispatch(ControlContents("snapshot-delete", 101, tampered)) == "error:SnapshotRuntimeDeleteStaleIdentity",
            "wire owner binding retains every supplied physical/OID identity field");
        unchanged();
    }
    Check(dispatch(ControlContents("snapshot-delete", 102, exact_fields)) == "error:SnapshotRuntimeDeleteStaleIdentity",
        "wire identity from Alpha cannot delete through declared Beta");
    unchanged();
    Check(dispatch(ControlContents("snapshot-delete", 999, exact_fields)) == "error:VolumeNotPredeclared",
        "wire delete cannot bind an undeclared volume");
    unchanged();
    auto direct = harness.Request();
    direct.action = ContainerControlAction::SnapshotDelete;
    direct.has_snapshot_identity = true;
    direct.snapshot_identity = exact;
    direct.snapshot_identity.scope.store_offset_bytes = 0;
    Check(!direct.snapshot_identity_needs_owner_scope, "direct identity never opts into wire scope completion");
    const auto refused = SnapshotDeleteForControl(harness.Selected(), *harness.owner, direct);
    Check(!refused.success && refused.code == "SnapshotRuntimeDeleteStaleIdentity",
        "direct relative scope remains refused by the full physical-scope check");
    unchanged();
    Check(dispatch(body) == "ok:SnapshotDeleted", "exact nine-field raw wire delete publishes successfully");
    const auto remaining = harness.Inventory();
    Check(harness.owner->CheckpointXid() == checkpoint + 1 && remaining.size() == 1 &&
        remaining.front().identity.snapshot_xid == survivor->identity.snapshot_xid &&
        remaining.front().identity.name_utf8 == survivor->identity.name_utf8,
        "wire success advances exactly once and retains the original sibling snapshot");
    SameFile(original.files[8], harness.Wal(1));
    SameMarks(beta_marks, *harness.Sibling().tx_manager);
    Envelope(original.files.front().bytes, ObserveFile(harness.image).bytes);
    CleanMarker(harness, checkpoint + 1);
    Writable(harness);
    const Evidence deleted(harness);
    const auto deleted_marks = harness.Selected().tx_manager->Watermarks();
    Check(deleted_marks.accepted_sequence > alpha_marks.accepted_sequence &&
        deleted_marks.accepted_sequence == deleted_marks.apfs_durable_sequence &&
        deleted_marks.apfs_durable_sequence == deleted_marks.cleanup_sequence,
        "actual wire deletion completes its selected WAL publication and cleanup");
    Check(dispatch(body) == "error:SnapshotRuntimeDeleteStaleIdentity", "replayed raw wire delete remains stale after publication");
    deleted.Unchanged();
    SameMarks(deleted_marks, *harness.Selected().tx_manager);
    SameMarks(beta_marks, *harness.Sibling().tx_manager);
    Pass("raw actual wire delete: stale checkpoint, tampered fields, wrong volume and direct relative scope preserve evidence; exact delete publishes once");
}

Buffer MarkerRestartPayload() {
    Buffer bytes(4096);
    for (std::size_t i = 0; i < bytes.size(); ++i) bytes[i] = std::byte((i * 29 + 53) & 255);
    return bytes;
}

void MarkerRestartWrite(Harness& harness, std::size_t index, std::wstring path) {
    auto& ctx = *harness.sessions.at(index);
    ctx.session_root = harness.root / ("restart-callback-" + std::to_string(index));
    ctx.cache_root = ctx.session_root / "hydrate";
    std::filesystem::create_directories(ctx.cache_root);
    Check(InitializeMountNamespace(ctx), "marker restart imports the actual peer namespace");
    ctx.metadata_store->SetFilePayloadRangeProvider([&ctx](const std::wstring& name,
        apfsaccess::rw::MetadataStore::PayloadIdentity identity, std::uint64_t offset,
        std::span<std::byte> destination) {
        return ReadHydratedPayloadRangeForPath(&ctx, name, identity, offset, destination);
    });
    FSP_FILE_SYSTEM fs{};
    fs.UserContext = &ctx;
    PVOID handle = nullptr;
    FSP_FSCTL_FILE_INFO info{};
    ScopeExit close{[&] { if (handle) CB_Close(&fs, handle); }};
    Check(CB_Create(&fs, path.data(), FILE_NON_DIRECTORY_FILE,
        FILE_READ_DATA | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES, 0, nullptr, 0, &handle, &info) == STATUS_SUCCESS && handle,
        "marker restart admits actual peer Create callback");
    auto expected = MarkerRestartPayload();
    ULONG done = 0;
    Check(CB_Write(&fs, handle, expected.data(), 0, static_cast<ULONG>(expected.size()), FALSE, FALSE, &done, &info) ==
        STATUS_SUCCESS && done == expected.size(), "marker restart admits actual peer Write callback");
    Check(CB_Flush(&fs, handle, &info) == STATUS_SUCCESS, "marker restart peer payload actually flushes");
    Buffer actual(expected.size());
    Check(CB_Read(&fs, handle, actual.data(), 0, static_cast<ULONG>(actual.size()), &done) == STATUS_SUCCESS &&
        done == actual.size() && actual == expected, "marker restart actual peer Read callback returns exact payload");
    Check(CB_Flush(&fs, handle, &info) == STATUS_SUCCESS, "marker restart drains readback access-time work");
    CB_Close(&fs, handle);
    handle = nullptr;
    Buffer committed;
    Check(ctx.metadata_store->ReadCommittedFileRange(path, 0, expected.size(), committed) && committed == expected,
        "marker restart peer readback independently matches actual committed APFS extents");
    Writable(harness);
}

std::uint64_t SeedOldDirtyMarker(Harness& harness, LiveVolumeVerificationScope* before_snapshots = nullptr) {
    for (auto& args : harness.arguments) args.write_crash_replay_mode = L"ReplayIfSafe";
    harness.Start();
    MarkerRestartWrite(harness, 1, L"\\before-marker.bin");
    const auto old_checkpoint = harness.owner->CheckpointXid();
    if (before_snapshots) *before_snapshots = harness.Scope();
    const auto marks = harness.Sibling().tx_manager->Watermarks();
    Check(marks.accepted_sequence && marks.accepted_sequence == marks.apfs_durable_sequence &&
        marks.accepted_sequence == marks.cleanup_sequence && ObserveFile(harness.Wal(1)).present,
        "dirty-marker fixture retains a nonempty actual original clean Beta WAL");
    Check(harness.Create("marker-survivor-a").success && harness.Create("marker-survivor-b").success,
        "Alpha publishes actual snapshots after Beta's last clean transaction");
    Check(harness.owner->CheckpointXid() > old_checkpoint && harness.Inventory().size() == 2,
        "sibling publication advances the real container beyond the retained Beta marker XID");
    SameMarks(marks, *harness.Sibling().tx_manager);
    const auto checkpoint = harness.owner->CheckpointXid();
    harness.Close();
    // Model the interrupted marker arm on disk; only the real startup loader
    // sets recovery flags in the subsequent new owner.
    harness.Put(harness.Marker(1), TextBytes("dirty=1\nlastCommitXid=" + std::to_string(old_checkpoint) + "\n"));
    return checkpoint;
}

void MarkerRestartOriginals(const Evidence& before) {
    for (std::size_t i = 0; i < before.paths.size(); ++i)
        if (i != 5) SameFile(before.files[i], before.paths[i]);
    const auto marker = ObserveFile(before.paths[5]);
    Check(marker.present && marker.file_id == before.files[5].file_id &&
        marker.volume_serial == before.files[5].volume_serial,
        "startup reconciliation retains the same original Beta marker file identity");
}

void CheckMarkerStartupLoaded(Harness& harness, std::uint64_t checkpoint) {
    auto& beta = harness.Sibling();
    Check(beta.pending_native_writes && beta.recovery_active && !beta.write_degraded && beta.native_write_enabled &&
        beta.runtime_recovery_reason == L"RecoveryMarkerDirty" &&
        beta.runtime_last_recovery_action == L"RecoveryMarkerDetected" && beta.runtime_last_commit_xid &&
        *beta.runtime_last_commit_xid < checkpoint && beta.last_recovery_marker_dirty == true &&
        beta.last_recovery_marker_commit_xid == beta.runtime_last_commit_xid,
        "actual LoadRecoveryMarkerAtStartup applies old dirty Beta marker without any flag shortcut");
    for (const auto& peer : harness.sessions) {
        std::vector<Tx::AcceptedTransaction> debt;
        std::string error;
        Check(peer->tx_manager->LoadAcceptedTransactionsSinceCleanup(debt, &error) && debt.empty() &&
            peer->tx_manager->ValidatedCleanJournalGeneration() && peer->tx_manager->CanClearRecoveryState(),
            "actual original WAL validates clean with no accepted debt: " + error);
    }
}

std::string MarkerRestartWire(Harness& harness, std::uint64_t volume) {
    const auto root = harness.root.parent_path() / ("marker-wire-" + harness.root.filename().string() + "-" + std::to_string(volume));
    Check(std::filesystem::create_directory(root), "exclusive ordinary marker restart control directory");
    Arguments args;
    args.container_control_file = (root / "request.control").wstring();
    args.container_control_token = Utf8ToWide(kControlToken);
    args.status_file = (root / "status.json").wstring();
    harness.Put(args.container_control_file, TextBytes(ControlContents("snapshot-create", volume,
        {"marker-wire-" + std::to_string(volume)})));
    Check(ProcessContainerControlRequest(args, *harness.owner, harness.sessions) &&
        !std::filesystem::exists(args.container_control_file), "actual restarted peer consumes its wire snapshot request");
    const auto bytes = ObserveFile(args.container_control_file + L".response").bytes;
    std::istringstream input(std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size()));
    std::array<std::string, 4> fields;
    for (auto& field : fields) {
        Check(static_cast<bool>(std::getline(input, field)), "restarted peer returns four actual response fields");
        if (!field.empty() && field.back() == '\r') field.pop_back();
    }
    Check(fields[0] == "APFS-CONTROL/1" && fields[1] == kControlRequestId,
        "restarted raw wire response retains exact protocol and request ID");
    return fields[2] + ":" + fields[3];
}

void CleanWalDirtyMarkerRestart() {
    Harness harness("clean-wal-dirty-marker");
    LiveVolumeVerificationScope stale_scope;
    const auto checkpoint = SeedOldDirtyMarker(harness, &stale_scope);
    const Evidence original(harness);
    std::string error;
    Check(harness.OpenPeers(error) && harness.owner->CheckpointXid() == checkpoint,
        "fresh actual raw owners reopen the original snapshot-bearing checkpoint: " + error);
    CheckMarkerStartupLoaded(harness, checkpoint);
    original.Unchanged();
    const auto alpha_marks = harness.Selected().tx_manager->Watermarks();
    const auto beta_marks = harness.Sibling().tx_manager->Watermarks();
    const auto attempts = harness.Sibling().raw_snapshot_startup_evidence->MarkerFlushAttemptsForTest();
    const bool admitted = harness.Admit(error);
    if (!admitted) original.Unchanged();
    Check(admitted, "clean original WAL reconciles actual old dirty Beta marker at startup: " + error);
    Check(harness.owner->CheckpointXid() == checkpoint &&
        harness.Sibling().raw_snapshot_startup_evidence->MarkerFlushAttemptsForTest() == attempts + 1,
        "marker-only reconciliation flushes once without republishing the APFS checkpoint");
    MarkerRestartOriginals(original);
    SameMarks(alpha_marks, *harness.Selected().tx_manager);
    SameMarks(beta_marks, *harness.Sibling().tx_manager);
    RecoveryMarkerState marker;
    auto& beta = harness.Sibling();
    Check(LoadRecoveryMarkerState(harness.Marker(1), marker) == RecoveryMarkerLoadStatus::Loaded && !marker.dirty &&
        marker.last_commit_xid == checkpoint && beta.last_recovery_marker_dirty == false &&
        beta.last_recovery_marker_commit_xid == checkpoint && beta.runtime_last_commit_xid == checkpoint &&
        beta.runtime_recovery_reason.empty() && beta.runtime_last_recovery_action == L"RawSnapshotStartupMarkerReconciled",
        "durable original marker and actual runtime marker cache agree at current checkpoint");
    Writable(harness);
    Check(stale_scope.exact.checkpoint_xid < harness.owner->CheckpointXid(),
        "scope captured from the actual earlier checkpoint predates the fixture's snapshot publications");
    const Evidence inventory_inputs(harness);
    const auto survivors = harness.Inventory();
    Check(survivors.size() == 2 && survivors[0].identity.name_utf8 != survivors[1].identity.name_utf8,
        "fresh reconciled owner preserves both original snapshots");
    auto stale_request = harness.Request();
    stale_request.verification_scope = stale_scope;
    const auto stale_result = SnapshotListForControl(harness.Selected(), *harness.owner, stale_request);
    Check(!stale_result.success && stale_result.code == "SnapshotInventoryScopeChanged",
        "captured older checkpoint remains refused after correct published-scope inventory");
    inventory_inputs.Unchanged();
    Buffer committed;
    Check(beta.metadata_store->ReadCommittedFileRange(L"\\before-marker.bin", 0, 4096, committed) &&
        committed == MarkerRestartPayload(), "fresh reopened Beta preserves its original committed payload");
    MarkerRestartWrite(harness, 0, L"\\after-marker-alpha.bin");
    MarkerRestartWrite(harness, 1, L"\\after-marker-beta.bin");
    Check(MarkerRestartWire(harness, 101) == "ok:SnapshotCreated" &&
        MarkerRestartWire(harness, 102) == "ok:SnapshotCreated", "both actual restarted peers admit wire snapshot controls");
    const auto inventory = harness.Inventory();
    for (const auto& survivor : survivors)
        Check(std::any_of(inventory.begin(), inventory.end(), [&](const auto& value) {
            return value.identity.snapshot_xid == survivor.identity.snapshot_xid &&
                value.identity.name_utf8 == survivor.identity.name_utf8 &&
                value.identity.root_physical_block == survivor.identity.root_physical_block;
        }), "post-reconciliation peer writes and wire controls preserve exact original snapshot identities");
    Writable(harness);
    Pass("raw fresh startup reconciles an older dirty marker only from actual clean original WALs; both peers write/read and wire controls survive");
}

void DirtyMarkerRestartRefusals() {
    for (const std::string mode : {"missing-wal", "corrupt-wal", "torn-wal", "pending-wal", "future-marker", "policy-disabled", "other-degradation"}) {
        Harness harness("dirty-marker-refusal-" + mode);
        const auto checkpoint = SeedOldDirtyMarker(harness);
        if (mode == "missing-wal") Check(std::filesystem::remove(harness.Wal(1)), "remove only owned fixture original Beta WAL");
        if (mode == "corrupt-wal") harness.Put(harness.Wal(1), TextBytes("corrupt original Beta WAL"));
        if (mode == "torn-wal") {
            auto bytes = ObserveFile(harness.Wal(1)).bytes;
            const auto tail = TextBytes("torn"); bytes.insert(bytes.end(), tail.begin(), tail.end());
            harness.Put(harness.Wal(1), bytes);
        }
        if (mode == "pending-wal") {
            Tx pending(L"Strict");
            std::string error;
            Check(pending.EnrollCanonicalJournalIdentity(L"apfs-vol:" + harness.arguments[1].container_id + L":102") &&
                pending.OpenStartupJournal(harness.Wal(1).wstring(), BuildWalVolumeIdentity(harness.arguments[1]), error) &&
                pending.Begin(), "original Beta transaction owner begins real retained WAL work: " + error);
            Tx::MutationIntent mutation;
            mutation.kind = Tx::MutationKind::SetFileSize;
            mutation.path = L"\\before-marker.bin"; mutation.length = 4096;
            Check(pending.RecordMutation(mutation) && pending.Accept(checkpoint), "actual original WAL retains accepted unfinished work");
        }
        if (mode == "future-marker") harness.Put(harness.Marker(1),
            TextBytes("dirty=1\nlastCommitXid=" + std::to_string(checkpoint + 1) + "\n"));
        if (mode == "policy-disabled") harness.arguments[1].write_crash_replay_mode = L"FailClosed";
        const Evidence original(harness);
        std::string error;
        const bool opened = harness.OpenPeers(error);
        if (opened && mode == "other-degradation")
            LatchRecoveryIdentityStartupBlock(harness.Sibling(), L"IndependentStartupDegradation", L"IndependentStartupRefusal", true);
        Check(!opened || !harness.Admit(error), "dirty marker cannot erase negative original evidence: " + mode + ": " + error);
        original.Unchanged();
        for (const auto& peer : harness.sessions)
            Check(!peer->raw_snapshot_startup_admitted && !peer->raw_snapshot_authority,
                "dirty-marker refusal grants no peer raw mutation authority");
        harness.Close();
        original.Unchanged();
    }
    Pass("raw dirty-marker restart refuses lost/corrupt/torn/pending original WAL, future marker, disabled replay and other degradation without changing evidence");
}

void DirtyMarkerRestartFlushFailure() {
    Harness harness("dirty-marker-flush-failure");
    const auto checkpoint = SeedOldDirtyMarker(harness);
    const Evidence original(harness);
    std::string error;
    Check(harness.OpenPeers(error), "fresh dirty-marker flush-failure peers reopen actual original evidence: " + error);
    CheckMarkerStartupLoaded(harness, checkpoint);
    auto& beta = harness.Sibling();
    auto& fence = *beta.raw_snapshot_startup_evidence;
    const auto attempts = fence.MarkerFlushAttemptsForTest();
    fence.ForceMarkerFlushFailureForTest(true);
    Check(!harness.Admit(error) && error == "RawSnapshotStartupMarkerRecoveryPersistFailed" &&
        fence.MarkerFlushAttemptsForTest() == attempts + 1, "failed real owned-marker flush never acknowledges startup reconciliation: " + error);
    MarkerRestartOriginals(original);
    Check(beta.recovery_active && beta.pending_native_writes && beta.runtime_recovery_reason == L"RecoveryMarkerDirty",
        "flush failure preserves actual loaded dirty-marker recovery flags");
    for (const auto& peer : harness.sessions)
        Check(!peer->raw_snapshot_startup_admitted && !peer->raw_snapshot_authority,
            "failed marker durability grants no cohort raw mutation authority");
    Check(harness.owner->CheckpointXid() == checkpoint, "failed marker flush cannot republish source checkpoint");
    Pass("raw dirty-marker startup retains recovery flags and never grants authority after actual marker flush failure");
}

void IdleRetryStatus(Harness& harness, const std::filesystem::path& root, bool queued) {
    auto& peer = harness.Selected();
    const auto dirty = SnapshotNativeDirtyStatus(peer);
    Check(dirty.deferred_access_time_requested == queued,
        "actual deferred access request is reflected in NativeDirtyStatus");
    peer.args.status_file = (root / "host.status.json").wstring();
    Arguments process;
    process.status_file = (root / "container.status.json").wstring();
    Check(WriteHostStatusFile(peer) && WriteContainerStatusFile(process, *harness.owner, harness.sessions),
        "real host and container status writers publish deferred access observations");
    for (const auto& path : {peer.args.status_file, process.status_file}) {
        const auto bytes = ObserveFile(path).bytes;
        const std::string text(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        Check(text.find(std::string("\"deferredAccessTimeRequested\":") + (queued ? "true" : "false")) != std::string::npos,
            "published JSON carries the actual deferred access request flag");
    }
}

std::uint64_t QueueIdleRead(Harness& harness, std::wstring path) {
    auto& peer = harness.Selected();
    FSP_FILE_SYSTEM fs{};
    fs.UserContext = &peer;
    PVOID handle = nullptr;
    FSP_FSCTL_FILE_INFO info{};
    ScopeExit close{[&] { if (handle) CB_Close(&fs, handle); }};
    Check(CB_Open(&fs, path.data(), FILE_NON_DIRECTORY_FILE | (FILE_OPEN << 24),
        FILE_READ_DATA | FILE_READ_ATTRIBUTES, &handle, &info) == STATUS_SUCCESS && handle,
        "actual raw peer opens an ordinary read-only callback handle");
    Buffer bytes(4096);
    ULONG done = 0;
    Check(CB_Read(&fs, handle, bytes.data(), 0, static_cast<ULONG>(bytes.size()), &done) == STATUS_SUCCESS &&
        done == bytes.size() && bytes == MarkerRestartPayload(), "actual read returns original committed payload");
    CB_Cleanup(&fs, handle, nullptr, FspCleanupSetLastAccessTime);
    CB_Close(&fs, handle); handle = nullptr;
    MutationCallbackScope mutation(&peer);
    Check(peer.deferred_access_times.size() == 1 && !peer.open_write_handle_count,
        "production read cleanup enqueues real access work without an open writer");
    return peer.deferred_access_times.begin()->second.time;
}

void TransientHostIdleRetry() {
    DispatchStorageEnvironment deferred(L"APFSACCESS_DEFER_CLOSE_COMMITS", L"1");
    DispatchStorageEnvironment writeback(L"APFSACCESS_DISABLE_CONTENT_WRITEBACK", L"0");
    Harness harness("transient-idle-retry");
    harness.Start();
    MarkerRestartWrite(harness, 0, L"\\idle-peer.bin");
    const auto initial = GetSnapshotControlCapabilities(harness.Selected(), *harness.owner);
    Check(initial.inventory && initial.mutation, "actual original cohort is ready before deferred read cleanup");
    auto request = harness.Request();
    request.action = ContainerControlAction::SnapshotList;
    request.verification_scope = harness.Scope();
    auto& peer = harness.Selected();
    FSP_FILE_SYSTEM fs{};
    fs.UserContext = &peer;
    const Evidence original(harness);
    const auto checkpoint = harness.owner->CheckpointXid();
    const auto alpha_marks = harness.Selected().tx_manager->Watermarks();
    const auto beta_marks = harness.Sibling().tx_manager->Watermarks();
    const auto access_time = QueueIdleRead(harness, L"\\idle-peer.bin");
    Check(SnapshotNativeDirtyStatus(peer).deferred_access_time_requested && !SnapshotRecoveryHostIdle(peer),
        "actual original peer scheduler reports deferred read cleanup");
    original.Unchanged();
    const auto census = harness.owner->CheckpointCensusSnapshot();
    const auto root = harness.root.parent_path() / ("idle-status-" + harness.root.filename().string());
    Check(std::filesystem::create_directory(root), "exclusive ordinary D: idle status directory");
    IdleRetryStatus(harness, root, true);
    for (unsigned retry = 0; retry != 2; ++retry) {
        const auto caps = GetSnapshotControlCapabilities(harness.Selected(), *harness.owner);
        Check(!caps.inventory && !caps.mutation && caps.refusal == "SnapshotControlBusy",
            "actual deferred peer work is transient busy capability refusal: " + caps.refusal);
        const auto result = SnapshotListForControl(harness.Selected(), *harness.owner, request);
        Check(!result.success && result.code == "SnapshotControlBusy",
            "actual control inventory preserves transient busy classification: " + result.code);
        original.Unchanged();
        SameCensus(census, *harness.owner);
        SameMarks(alpha_marks, *harness.Selected().tx_manager);
        SameMarks(beta_marks, *harness.Sibling().tx_manager);
        Check(harness.owner->CheckpointXid() == checkpoint && SnapshotNativeDirtyStatus(peer).deferred_access_time_requested &&
            peer.native_write_enabled && !peer.recovery_active && !peer.write_degraded,
            "busy observations neither drain queued access work nor degrade the original cohort");
    }
    Check(CB_Flush(&fs, nullptr, nullptr) == STATUS_SUCCESS &&
        !SnapshotNativeDirtyStatus(peer).deferred_access_time_requested && SnapshotRecoveryHostIdle(peer),
        "actual volume Flush drains the original deferred access batch");
    {
        MutationCallbackScope mutation(&peer);
        Check(peer.deferred_access_times.empty(), "actual deferred access queue is empty under its mutation owner");
    }
    const auto inode = peer.metadata_store->LookupCommittedInodeByPath(L"\\idle-peer.bin");
    Buffer payload;
    Check(inode && inode->access_time_utc == access_time && harness.owner->CheckpointXid() > checkpoint &&
        peer.metadata_store->ReadCommittedFileRange(L"\\idle-peer.bin", 0, 4096, payload) && payload == MarkerRestartPayload(),
        "drain commits actual access time while preserving original data bytes");
    SameFile(original.files[8], harness.Wal(1));
    SameMarks(beta_marks, *harness.Sibling().tx_manager);
    Envelope(original.files[0].bytes, ObserveFile(harness.image).bytes);
    IdleRetryStatus(harness, root, false);
    const auto ready = GetSnapshotControlCapabilities(harness.Selected(), *harness.owner);
    Check(ready.inventory && ready.mutation, "same original capability succeeds after actual queue drain");
    const auto stale = SnapshotListForControl(harness.Selected(), *harness.owner, request);
    Check(!stale.success && stale.code == "SnapshotInventoryScopeChanged", "busy retry does not bypass checkpoint scope binding");
    request.verification_scope = harness.Scope();
    const Evidence drained(harness);
    const auto result = SnapshotListForControl(harness.Selected(), *harness.owner, request);
    Check(result.success && result.code == "SnapshotInventory" && result.snapshot_inventory &&
        result.snapshot_inventory->scope.checkpoint_xid == harness.owner->CheckpointXid(),
        "same inventory control succeeds with its required current checkpoint scope after drain: " + result.code);
    drained.Unchanged();
    Writable(harness);
    Pass("raw actual deferred read cleanup reports transient busy without evidence changes; real Flush clears status and restores exact inventory control");
}

void HostIdleRetryHardRefusals() {
    DispatchStorageEnvironment deferred(L"APFSACCESS_DEFER_CLOSE_COMMITS", L"1");
    DispatchStorageEnvironment writeback(L"APFSACCESS_DISABLE_CONTENT_WRITEBACK", L"0");
    for (const std::string mode : {"journal", "identity", "degraded", "spool"}) {
        Harness harness("idle-hard-" + mode);
        harness.Start();
        MarkerRestartWrite(harness, 0, L"\\hard-idle-peer.bin");
        auto request = harness.Request();
        request.action = ContainerControlAction::SnapshotList;
        request.verification_scope = harness.Scope();
        (void)QueueIdleRead(harness, L"\\hard-idle-peer.bin");
        Check(UpdateRecoveryMarkerBestEffort(&harness.Selected(), true),
            "production dirty marker adds independent pending work before the hard peer check");
        Check(!SnapshotRecoveryHostIdle(harness.Selected()), "earlier original peer has actual queued access work");
        auto& beta = harness.Sibling();
        if (mode == "journal") beta.tx_manager->SetJournalPath((harness.root / "substituted.wal").wstring());
        if (mode == "identity") beta.args.recovery_identity = L"apfs-recovery-v1-" + std::wstring(43, L'Z');
        if (mode == "degraded") LatchRecoveryIdentityStartupBlock(beta, L"IndependentIdleDegradation", L"IndependentIdleRefusal", true);
        if (mode == "spool") {
            const auto bytes = MarkerRestartPayload();
            apfsaccess::rw::PayloadSpool::WriteRequest write;
            write.volume_identity = beta.payload_spool_volume_identity;
            write.object_id = 43; write.generation = 1; write.wal_sequence = 1; write.payload = bytes;
            Check(beta.payload_spool->Append(write) && !SnapshotRecoverySpoolClean(beta),
                "actual original payload spool retains real unclean bytes");
        }
        const Evidence original(harness);
        const auto census = harness.owner->CheckpointCensusSnapshot();
        const auto substitute = ObserveFile(harness.root / "substituted.wal");
        for (unsigned retry = 0; retry != 2; ++retry) {
            const auto caps = GetSnapshotControlCapabilities(harness.Selected(), *harness.owner);
            const auto result = SnapshotListForControl(harness.Selected(), *harness.owner, request);
            Check(!caps.inventory && !caps.mutation && caps.refusal == "RawSnapshotHostOriginalPeerRequired" &&
                !result.success && result.code == "RawSnapshotHostOriginalPeerRequired",
                "original journal, identity, degradation or spool refusal cannot become retryable busy: " + mode);
            original.Unchanged();
            SameFile(substitute, harness.root / "substituted.wal");
            SameCensus(census, *harness.owner);
            for (auto& session : harness.sessions)
                std::reverse(session->container_session_contexts.begin(), session->container_session_contexts.end());
        }
    }
    Pass("raw transient-idle classification retains hard original journal, identity, degradation and spool refusals without evidence mutation");
}

void PublishedHostIdleRefusal() {
    Harness harness("published-idle-refusal");
    harness.Start();
    const auto checkpoint = harness.owner->CheckpointXid();
    harness.Selected().test_force_snapshot_marker_readback_failure = true;
    const auto failed = harness.Create("published-idle-survivor");
    Check(!failed.success && harness.owner->IsRecoveryRequired() && harness.owner->CheckpointXid() == checkpoint + 1,
        "actual published snapshot retains original accepted completion debt");
    const auto intent = Debt(harness);
    PausedDebt(harness, intent);
    harness.Selected().test_force_snapshot_marker_readback_failure = false;
    const Evidence published(harness);
    const auto census = harness.owner->CheckpointCensusSnapshot();
    const auto marks = harness.Selected().tx_manager->Watermarks();
    std::atomic<bool> locked{false}, release{false};
    std::thread worker([&] {
        std::unique_lock schedule(harness.Sibling().deferred_commit_mutex);
        locked.store(true, std::memory_order_release); locked.notify_one();
        release.wait(false, std::memory_order_acquire);
    });
    ScopeExit join{[&] {
        release.store(true, std::memory_order_release); release.notify_one();
        if (worker.joinable()) worker.join();
    }};
    locked.wait(false, std::memory_order_acquire);
    const auto refused = harness.Recover();
    Check(!refused.success && refused.code == "RawSnapshotHostCompletionPeersRequired",
        "postpublication recovery idle refusal is never retryable preaccept busy: " + refused.code);
    {
        SnapshotControlLocks gates(harness.Selected(), true);
        std::string error;
        Check(gates.acquired && !RestoreRawSnapshotHostWrites(harness.Selected(), *harness.owner, error) &&
            error == "RawSnapshotHostCompletionPeersRequired", "actual postpublication restore refuses completion without Busy: " + error);
    }
    published.Unchanged();
    SameCensus(census, *harness.owner);
    SameMarks(marks, *harness.Selected().tx_manager);
    Check(harness.owner->IsRecoveryRequired() &&
        apfsaccess::rw::EncodeNativeSnapshotIntent(Debt(harness)) == apfsaccess::rw::EncodeNativeSnapshotIntent(intent),
        "postpublication refusal retains the same actual owned receipt and engine completion latch");
    for (const auto& peer : harness.sessions)
        Check(!peer->native_write_enabled && peer->raw_snapshot_host_write_paused,
            "postpublication idle refusal preserves every owned peer pause");
    release.store(true, std::memory_order_release); release.notify_one(); worker.join();
    const auto recovered = harness.Recover();
    Check(recovered.success && recovered.code == "SnapshotRecovered", "actual recovery completes after scheduler ownership releases");
    Writable(harness);
    SameFile(published.files.front(), harness.image);
    const auto inventory = harness.Inventory();
    Check(harness.owner->CheckpointXid() == checkpoint + 1 && inventory.size() == 1 &&
        inventory.front().identity.name_utf8 == "published-idle-survivor",
        "postpublication idle recovery preserves the once-published original snapshot without republication");
    Pass("raw published receipt recovery/restore never reports Busy; real scheduler ownership contention retains owned pause and debt until completion");
}

struct StagedAtimeWorker {
    MountContext& peer;
    std::promise<void> staged, release;
    std::future<void> ready = staged.get_future();
    std::shared_future<void> resume = release.get_future().share();
    std::atomic<bool> hook_timed_out{false};
    bool released = false;
    explicit StagedAtimeWorker(MountContext& context) : peer(context) {
        peer.test_before_deferred_atime_publish = [&] {
            staged.set_value();
            if (resume.wait_for(std::chrono::seconds(20)) != std::future_status::ready)
                hook_timed_out.store(true, std::memory_order_release);
        };
    }
    void Release() { if (!released) { released = true; release.set_value(); } }
    ~StagedAtimeWorker() {
        Release();
        if (peer.deferred_commit_thread.joinable() && !StopDeferredCommitWorker(&peer)) std::terminate();
        peer.test_before_deferred_atime_publish = {};
    }
};

void StagedAccessTimeRetry() {
    DispatchStorageEnvironment deferred(L"APFSACCESS_DEFER_CLOSE_COMMITS", L"1");
    DispatchStorageEnvironment writeback(L"APFSACCESS_DISABLE_CONTENT_WRITEBACK", L"0");
    Harness harness("staged-atime-retry");
    harness.Start();
    MarkerRestartWrite(harness, 0, L"\\staged-atime.bin");
    Check(harness.Create("staged-atime-survivor").success, "actual snapshot exists before staged atime");
    const auto survivor = harness.Inventory();
    const auto checkpoint = harness.owner->CheckpointXid();
    auto& peer = harness.Selected();
    StagedAtimeWorker worker(peer);
    const auto atime = QueueIdleRead(harness, L"\\staged-atime.bin");
    StartDeferredCommitWorker(&peer);
    Check(worker.ready.wait_for(std::chrono::seconds(5)) == std::future_status::ready,
        "real deferred worker reaches its bounded production prepublication hook");
    Check(peer.pending_native_writes && ManifestQueuedRequestCount(&peer) == 1 &&
        SnapshotRecoveryStoreClean(*peer.metadata_store) && SnapshotNativeDirtyStatus(peer).deferred_access_time_requested &&
        !peer.active_foreground_mutation_callbacks && !peer.open_write_handle_count &&
        !peer.recovery_active && !peer.write_degraded,
        "real manifest atime staging arms pending marker with clean store and no active foreground mutation");
    RecoveryMarkerState marker;
    Check(LoadRecoveryMarkerState(harness.Marker(0), marker) == RecoveryMarkerLoadStatus::Loaded && marker.dirty,
        "actual staged atime marker is durably dirty");
    const Evidence staged(harness);
    const auto census = harness.owner->CheckpointCensusSnapshot();
    const auto marks = peer.tx_manager->Watermarks();
    auto request = harness.Request();
    request.action = ContainerControlAction::SnapshotList;
    request.verification_scope = harness.Scope();
    for (unsigned retry = 0; retry != 2; ++retry) {
        const auto caps = GetSnapshotControlCapabilities(peer, *harness.owner);
        const auto control = SnapshotListForControl(peer, *harness.owner, request);
        Check(!caps.inventory && !caps.mutation && caps.refusal == "SnapshotControlBusy" &&
            !control.success && control.code == "SnapshotControlBusy",
            "actual staged atime is preaccept Busy: " + caps.refusal + "/" + control.code);
        SnapshotControlLocks gates(peer, true);
        Check(gates.acquired, "all original control gates acquire while real atime worker is staged");
        std::string error;
        Check(!RawSnapshotHostPeers(peer, *harness.owner, true, error) && error == "RawSnapshotHostCompletionPeersRequired",
            "selected staged-atime recovery never becomes retryable Busy: " + error);
        Check(!RawSnapshotHostPeers(harness.Sibling(), *harness.owner, true, error) && error == "RawSnapshotHostCleanPeerRequired",
            "nonselected staged-atime recovery retains its hard clean-peer requirement: " + error);
    }
    staged.Unchanged(); SameCensus(census, *harness.owner); SameMarks(marks, *peer.tx_manager);
    Check(harness.owner->CheckpointXid() == checkpoint && !harness.owner->IsRecoveryRequired(),
        "staged-atime inspection neither publishes nor accepts a snapshot");
    worker.Release();
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (SnapshotNativeDirtyStatus(peer).deferred_access_time_requested && std::chrono::steady_clock::now() < deadline) Sleep(5);
    Check(!worker.hook_timed_out && !SnapshotNativeDirtyStatus(peer).deferred_access_time_requested &&
        !peer.pending_native_writes && SnapshotRecoveryStoreClean(*peer.metadata_store),
        "actual worker completes its once-staged atime and clears durable pending state");
    const auto inode = peer.metadata_store->LookupCommittedInodeByPath(L"\\staged-atime.bin");
    Buffer payload;
    Check(inode && inode->access_time_utc == atime &&
        peer.metadata_store->ReadCommittedFileRange(L"\\staged-atime.bin", 0, 4096, payload) && payload == MarkerRestartPayload(),
        "worker publishes the exact queued time and preserves actual payload");
    const auto ready = GetSnapshotControlCapabilities(peer, *harness.owner);
    request.verification_scope = harness.Scope();
    const auto control = SnapshotListForControl(peer, *harness.owner, request);
    Check(ready.inventory && ready.mutation && control.success && harness.Inventory().size() == survivor.size(),
        "same current-scoped inventory succeeds after actual staged drain with snapshot survivor intact");
    const auto after = harness.Inventory();
    Check(after.size() == 1 && after.front().identity.snapshot_xid == survivor.front().identity.snapshot_xid &&
        after.front().identity.name_utf8 == survivor.front().identity.name_utf8,
        "ordinary atime publication preserves the original snapshot identity");
    Envelope(staged.files.front().bytes, ObserveFile(harness.image).bytes);
    Writable(harness);
    Pass("raw real worker staged-atime preaccept Busy drains to success while selected/nonselected recovery remains nonretryable");
}

void PendingMarkerRetry() {
    Harness harness("pending-marker-only");
    harness.Start();
    auto& peer = harness.Selected();
    Check(UpdateRecoveryMarkerBestEffort(&peer, true), "production marker helper arms an independent actual pending marker");
    Check(peer.pending_native_writes && SnapshotRecoveryStoreClean(*peer.metadata_store) && SnapshotRecoveryHostIdle(peer) &&
        !SnapshotNativeDirtyStatus(peer).deferred_access_time_requested && !ManifestQueuedRequestCount(&peer),
        "independent pending marker has no queued atime, worker or staged store work");
    const Evidence pending(harness);
    const auto census = harness.owner->CheckpointCensusSnapshot();
    auto request = harness.Request(); request.action = ContainerControlAction::SnapshotList;
    request.verification_scope = harness.Scope();
    const auto caps = GetSnapshotControlCapabilities(peer, *harness.owner);
    const auto control = SnapshotListForControl(peer, *harness.owner, request);
    Check(caps.refusal == "SnapshotControlBusy" && !caps.inventory && !caps.mutation &&
        !control.success && control.code == "SnapshotControlBusy", "independent production pending marker remains preaccept Busy");
    {
        SnapshotControlLocks gates(peer, true); std::string error;
        Check(gates.acquired && RawSnapshotHostPeers(peer, *harness.owner, true, error),
            "recovery retains original selected-peer pending-marker exemption");
        Check(!RawSnapshotHostPeers(harness.Sibling(), *harness.owner, true, error) && error == "RawSnapshotHostCleanPeerRequired",
            "recovery retains original nonselected pending-marker hard refusal");
    }
    pending.Unchanged(); SameCensus(census, *harness.owner);
    FSP_FILE_SYSTEM fs{}; fs.UserContext = &peer;
    Check(CB_Flush(&fs, nullptr, nullptr) == STATUS_SUCCESS && !peer.pending_native_writes,
        "real Flush reconciles the independent clean-store pending marker");
    Check(GetSnapshotControlCapabilities(peer, *harness.owner).mutation &&
        SnapshotListForControl(peer, *harness.owner, request).success,
        "same independent-marker control succeeds after ordinary Flush");
    Pass("raw independent durably armed pending marker is Busy only before acceptance and ordinary Flush restores control");
}

void StagedHardFailureOrders() {
    for (const std::string mode : {"store-recovery", "store-unready", "native-disabled", "runtime-recovery", "degraded"}) {
        Harness harness("staged-hard-" + mode); harness.Start();
        auto& alpha = harness.Selected(); auto& beta = harness.Sibling();
        auto request = harness.Request(); request.action = ContainerControlAction::SnapshotList;
        request.verification_scope = harness.Scope();
        Check(UpdateRecoveryMarkerBestEffort(&alpha, true), "production marker provides independent earlier-peer Busy state");
        if (mode == "store-recovery") apfsaccess::rw::NativeCheckpointHandoffTestAccess::RequireRecovery(*beta.metadata_store);
        if (mode == "store-unready") apfsaccess::rw::NativeCheckpointHandoffTestAccess::DisableNativeReady(*beta.metadata_store);
        if (mode == "native-disabled") beta.native_write_enabled = false;
        if (mode == "runtime-recovery") beta.recovery_active = true;
        if (mode == "degraded") beta.write_degraded = true;
        const Evidence original(harness); const auto census = harness.owner->CheckpointCensusSnapshot();
        for (unsigned order = 0; order != 2; ++order) {
            const auto caps = GetSnapshotControlCapabilities(alpha, *harness.owner);
            const auto control = SnapshotListForControl(alpha, *harness.owner, request);
            Check(!caps.inventory && !caps.mutation && caps.refusal == "RawSnapshotHostCleanPeerRequired" &&
                !control.success && control.code == "RawSnapshotHostCleanPeerRequired",
                "independent hard store/runtime state dominates earlier or later pending peer: " + mode);
            {
                SnapshotControlLocks gates(alpha, true); std::string error;
                Check(gates.acquired && !RawSnapshotHostPeers(alpha, *harness.owner, true, error) &&
                    error == "RawSnapshotHostCleanPeerRequired", "nonselected hard failure remains refused during recovery: " + mode);
            }
            original.Unchanged(); SameCensus(census, *harness.owner);
            for (auto& session : harness.sessions) std::reverse(session->container_session_contexts.begin(), session->container_session_contexts.end());
        }
    }
    Pass("raw native-unready, store recovery, disabled writes, runtime recovery and degradation dominate pending markers in both peer orders");
}

void OrdinarySiblingPublication() {
    Harness harness("ordinary-sibling-publication");
    harness.Start();
    auto& alpha = harness.Selected();
    auto& beta = harness.Sibling();
    alpha.session_root = harness.root / "callback-session";
    alpha.cache_root = alpha.session_root / "hydrate";
    std::filesystem::create_directories(alpha.cache_root);
    Check(InitializeMountNamespace(alpha), "ordinary callback namespace imports the actual original store");
    alpha.metadata_store->SetFilePayloadRangeProvider([&alpha](const std::wstring& path,
        apfsaccess::rw::MetadataStore::PayloadIdentity identity, std::uint64_t offset,
        std::span<std::byte> destination) {
        return ReadHydratedPayloadRangeForPath(&alpha, path, identity, offset, destination);
    });
    FSP_FILE_SYSTEM fs{};
    fs.UserContext = &alpha;
    PVOID handle = nullptr;
    FSP_FSCTL_FILE_INFO info{};
    ScopeExit close{[&]() { if (handle) CB_Close(&fs, handle); }};
    const auto original_xid = harness.owner->CheckpointXid();
    const auto beta_epoch = beta.metadata_store->StateEpoch();
    const auto beta_marks = beta.tx_manager->Watermarks();
    const auto beta_wal = ObserveFile(harness.Wal(1));
    std::wstring path = L"\\ordinary-publication.bin";
    const auto created = CB_Create(&fs, path.data(), FILE_NON_DIRECTORY_FILE,
        FILE_READ_DATA | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES, 0, nullptr, 0, &handle, &info);
    Check(created == STATUS_SUCCESS && handle, "actual ordinary Create callback: " + std::to_string(created));
    Buffer payload(4096);
    for (std::size_t index = 0; index < payload.size(); ++index) payload[index] = std::byte((index * 37 + 19) & 255);
    ULONG written = 0;
    const auto write = CB_Write(&fs, handle, payload.data(), 0, static_cast<ULONG>(payload.size()),
        FALSE, FALSE, &written, &info);
    Check(write == STATUS_SUCCESS && written == payload.size(), "actual ordinary 4096-byte Write callback");
    const auto flushed = CB_Flush(&fs, handle, &info);
    Check(flushed == STATUS_SUCCESS, "actual ordinary Flush callback: " + std::to_string(flushed));
    CB_Close(&fs, handle);
    handle = nullptr;
    Buffer readback;
    Check(alpha.metadata_store->ReadCommittedFileRange(path, 0, payload.size(), readback) && readback == payload,
        "ordinary write reads back through the actual committed APFS extents");
    const auto published_xid = harness.owner->CheckpointXid();
    Check(published_xid > original_xid && alpha.metadata_store->CheckpointXid() == published_xid &&
        beta.metadata_store->CheckpointXid() == original_xid && beta.metadata_store->StateEpoch() == beta_epoch,
        "actual ordinary publication advances Alpha and coordinator while leaving the clean sibling view behind");
    Writable(harness);
    SameMarks(beta_marks, *beta.tx_manager);
    SameFile(beta_wal, harness.Wal(1));
    const Evidence published(harness);
    const auto census = harness.owner->CheckpointCensusSnapshot();
    const auto alpha_epoch = alpha.metadata_store->StateEpoch();
    const auto alpha_marks = alpha.tx_manager->Watermarks();
    std::string error;
    apfsaccess::catalog::ApfsSnapshotScope stale_scope;
    {
        SnapshotControlLocks locks(beta, true);
        Check(locks.acquired && !apfsaccess::rw::InspectRawSnapshotRuntimeAuthority(beta.raw_snapshot_authority,
            *harness.owner, 102, stale_scope, nullptr, error) &&
            error == "SnapshotRuntimeRawInspectionMountedCheckpointStale" && stale_scope == apfsaccess::catalog::ApfsSnapshotScope{},
            "pure engine inspection retains the exact mounted checkpoint stale guard: " + error);
    }
    published.Unchanged();
    Check(harness.owner->UpdateRequiredCheckpointXids(101, {original_xid}, error, true),
        "actual coordinator retains an unresolved original census pin");
    const auto pinned_census = harness.owner->CheckpointCensusSnapshot();
    const auto pinned_caps = GetSnapshotControlCapabilities(beta, *harness.owner);
    Check(!pinned_caps.inventory && !pinned_caps.mutation &&
        beta.metadata_store->StateEpoch() == beta_epoch && alpha.metadata_store->StateEpoch() == alpha_epoch,
        "accepted census debt refuses sibling refresh before any mounted store change: " + pinned_caps.refusal);
    published.Unchanged();
    SameCensus(pinned_census, *harness.owner);
    Check(harness.owner->UpdateRequiredCheckpointXids(101, {}, error), "restore the original proven clean census");
    SameCensus(census, *harness.owner);
    DevicePeer::ChangeSerial(const_cast<apfsaccess::rw::BlockDevice&>(harness.owner->Device()));
    const auto changed_source_caps = GetSnapshotControlCapabilities(beta, *harness.owner);
    Check(!changed_source_caps.inventory && !changed_source_caps.mutation &&
        changed_source_caps.refusal == "SnapshotRuntimeRawSourceChanged" &&
        beta.metadata_store->StateEpoch() == beta_epoch && alpha.metadata_store->StateEpoch() == alpha_epoch,
        "changed actual held transport qualification cannot authorize a sibling refresh");
    published.Unchanged();
    DevicePeer::ChangeSerial(const_cast<apfsaccess::rw::BlockDevice&>(harness.owner->Device()), "AA00000000000489");
    const auto capabilities = GetSnapshotControlCapabilities(beta, *harness.owner);
    Check(capabilities.inventory && capabilities.mutation,
        "clean sibling host capabilities refresh the actual published checkpoint: " + capabilities.refusal);
    Check(beta.metadata_store->CheckpointXid() == published_xid && beta.metadata_store->StateEpoch() != beta_epoch &&
        alpha.metadata_store->StateEpoch() == alpha_epoch,
        "only the actual stale sibling store reloads at the already published checkpoint");
    LiveVolumeVerificationScope scope;
    {
        SnapshotControlLocks locks(beta, true);
        const auto* checkpoint = beta.metadata_store->AuthoritativeAppleCheckpointView();
        Check(locks.acquired && checkpoint && DescribeVolumeVerificationSource(beta, *beta.metadata_store, *checkpoint, scope, error),
            "refreshed sibling describes the exact original source: " + error);
    }
    Check(scope.exact.store_offset_bytes == PrefixSize && scope.exact.store_size_bytes == StoreSize &&
        scope.exact.volume_oid == 102 && scope.exact.volume_uuid_hex == std::string(32, 'c') &&
        scope.exact.checkpoint_xid == published_xid, "sibling public scope preserves the exact physical NX window and UUID");
    ContainerControlRequest request;
    request.volume_object_id = 102;
    request.verification_scope = scope;
    const auto listed = SnapshotListForControl(beta, *harness.owner, request);
    Check(listed.success && listed.snapshot_inventory && listed.snapshot_inventory->scope == scope.exact &&
        listed.snapshot_inventory->snapshots.empty(), "actual sibling list restores exact current inventory: " + listed.code);
    const auto refreshed_epoch = beta.metadata_store->StateEpoch();
    for (unsigned repeat = 0; repeat < 2; ++repeat) {
        const auto caps = GetSnapshotControlCapabilities(beta, *harness.owner);
        Check(caps.inventory && caps.mutation && beta.metadata_store->StateEpoch() == refreshed_epoch,
            "already current sibling capabilities remain pure without repeated reload");
        published.Unchanged();
        SameCensus(census, *harness.owner);
        SameMarks(alpha_marks, *alpha.tx_manager);
        SameMarks(beta_marks, *beta.tx_manager);
    }
    request.snapshot_name = "sibling-after-ordinary";
    const auto snapshot = SnapshotCreateForControl(beta, *harness.owner, request);
    Check(snapshot.success && snapshot.code == "SnapshotCreated" && harness.owner->CheckpointXid() == published_xid + 1,
        "sibling snapshot prepares actual P and publishes only P+1 after the ordinary commit: " + snapshot.code);
    Writable(harness);
    Check(alpha.metadata_store->ReadCommittedFileRange(path, 0, payload.size(), readback) && readback == payload,
        "sibling snapshot preserves Alpha's actual ordinary payload");
    const auto alpha_stale_epoch = alpha.metadata_store->StateEpoch();
    const auto beta_current_epoch = beta.metadata_store->StateEpoch();
    const auto terminal_census = harness.owner->CheckpointCensusSnapshot();
    auto& device = const_cast<apfsaccess::rw::BlockDevice&>(harness.owner->Device());
    const auto slot = beta.metadata_store->AuthoritativeAppleCheckpointView()->container.superblock_physical_block * BlockSize;
    Buffer checkpoint_bytes;
    Check(device.Read(slot, BlockSize, checkpoint_bytes), "read the actual published descriptor through the original held source");
    auto corrupt_checkpoint = checkpoint_bytes;
    corrupt_checkpoint.front() ^= std::byte{1};
    Check(device.Write(slot, corrupt_checkpoint) && device.Flush(), "corrupt only the actual loopback's published descriptor checksum");
    const Evidence corrupted_source(harness);
    const auto corrupted_caps = GetSnapshotControlCapabilities(alpha, *harness.owner);
    Check(!corrupted_caps.inventory && !corrupted_caps.mutation &&
        alpha.metadata_store->StateEpoch() == alpha_stale_epoch && beta.metadata_store->StateEpoch() == beta_current_epoch &&
        harness.owner->CheckpointXid() == published_xid + 1,
        "changed actual checkpoint or fallback cannot authorize a reload or move the coordinator: " + corrupted_caps.refusal);
    corrupted_source.Unchanged();
    SameCensus(terminal_census, *harness.owner);
    Check(device.Write(slot, checkpoint_bytes) && device.Flush(), "restore only the exact original loopback descriptor preimage");
    const auto before_changed_owner = Evidence(harness);
    beta.tx_manager->SetJournalPath((harness.root / "substituted-original-owner.wal").wstring());
    {
        SnapshotControlLocks locks(alpha, true);
        apfsaccess::catalog::ApfsSnapshotScope refused_scope;
        Check(locks.acquired && !apfsaccess::rw::RefreshAndInspectRawSnapshotRuntimeAuthority(alpha.raw_snapshot_authority,
            *harness.owner, 101, refused_scope, nullptr, error) && refused_scope == apfsaccess::catalog::ApfsSnapshotScope{} &&
            error == "SnapshotRuntimeRawCensusChanged" && alpha.metadata_store->StateEpoch() == alpha_stale_epoch &&
            beta.metadata_store->StateEpoch() == beta_current_epoch,
            "changed original sibling WAL ownership refuses refresh of stale Alpha before reload: " + error);
    }
    before_changed_owner.Unchanged();
    SameCensus(terminal_census, *harness.owner);
    Pass("raw host ordinary publication refreshes a clean sibling while pure inspection retains the stale guard");
}

void Lifecycle() {
    Harness harness("lifecycle");
    harness.Start();
    AdmittedMarkerPins(harness);
    const auto original = ObserveFile(harness.image).bytes;
    const auto original_marker = ObserveFile(harness.Marker(0));
    const auto sibling_wal = ObserveFile(harness.Wal(1));
    const auto sibling_marks = harness.Sibling().tx_manager->Watermarks();
    auto created = harness.Create("host-original");
    Check(created.success && created.code == "SnapshotCreated", "actual raw host create: " + created.code);
    Writable(harness);
    CleanMarker(harness, harness.owner->CheckpointXid());
    const auto created_marker = ObserveFile(harness.Marker(0));
    Check(created_marker.file_id == original_marker.file_id && created_marker.volume_serial == original_marker.volume_serial,
        "create updates the startup-owned marker in place without leaf replacement");
    PureCapabilities(harness, true, true);
    const auto inventory = harness.Inventory();
    Check(inventory.size() == 1 && inventory.front().identity.name_utf8 == "host-original", "actual host-created snapshot listed");
    const auto listed = Evidence(harness);
    for (unsigned mode = 0; mode < 4; ++mode) {
        auto request = harness.Request();
        auto scope = harness.Scope();
        if (mode == 1) scope.exact.store_offset_bytes = 0;
        if (mode == 2) ++scope.exact.store_size_bytes;
        if (mode == 3) scope.source_identity += "-substituted";
        if (mode) request.verification_scope = scope;
        const auto refused = SnapshotListForControl(harness.Selected(), *harness.owner, request);
        Check(!refused.success && refused.code == (mode ? "SnapshotInventoryScopeChanged" : "SnapshotInventoryScopeRequired"),
            "list refuses absent, relative, resized or substituted physical scope");
        listed.Unchanged();
    }
    auto relative = inventory.front().identity;
    relative.scope.store_offset_bytes = 0;
    const auto refused = harness.Delete(relative);
    Check(!refused.success && refused.code == "SnapshotRuntimeDeleteStaleIdentity", "raw delete refuses relative engine identity at host boundary");
    listed.Unchanged();
    const auto deleted = harness.Delete(inventory.front().identity);
    Check(deleted.success && deleted.code == "SnapshotDeleted", "actual exact-scope raw host delete: " + deleted.code);
    Writable(harness);
    Check(harness.Inventory().empty(), "deleted snapshot is absent from actual host list");
    CleanMarker(harness, harness.owner->CheckpointXid());
    const auto deleted_marker = ObserveFile(harness.Marker(0));
    Check(deleted_marker.file_id == original_marker.file_id && deleted_marker.volume_serial == original_marker.volume_serial,
        "delete retains the same admitted marker file identity");
    SameFile(sibling_wal, harness.Wal(1));
    SameMarks(sibling_marks, *harness.Sibling().tx_manager);
    Envelope(original, ObserveFile(harness.image).bytes);
    Pass("raw host create list delete enforce exact physical scope and preserve sibling WAL");
}

void MarkerReadbackRecovery() {
    for (const bool deletion : {false, true}) {
        Harness harness(deletion ? "retained-delete" : "retained-create");
        harness.Start();
        if (deletion) Check(harness.Create("retained").success, "host seed for retained deletion");
        const auto identity = deletion ? harness.Inventory().front().identity : apfsaccess::catalog::ApfsSnapshotIdentity{};
        const auto original = ObserveFile(harness.image).bytes;
        const auto sibling_wal = ObserveFile(harness.Wal(1));
        const auto sibling_marks = harness.Sibling().tx_manager->Watermarks();
        const auto p = harness.owner->CheckpointXid();
        harness.Selected().test_force_snapshot_marker_readback_failure = true;
        const auto failed = deletion ? harness.Delete(identity) : harness.Create("retained");
        Check(!failed.success && harness.owner->IsRecoveryRequired() && harness.owner->CheckpointXid() == p + 1,
            "host marker readback failure retains engine completion latch after one publication");
        const auto intent = Debt(harness);
        PausedDebt(harness, intent);
        CleanMarker(harness, p + 1);
        Check(harness.Selected().tx_manager->Watermarks().apfs_durable_sequence ==
            harness.Selected().tx_manager->Watermarks().accepted_sequence,
            "actual engine durability precedes failed marker readback and retained cleanup");
        const auto publication = ObserveFile(harness.image);
        const Evidence retry(harness);
        const auto still_failed = harness.Recover();
        Check(!still_failed.success, "actual recovery cannot release latch while marker readback still fails");
        retry.Unchanged();
        PausedDebt(harness, intent);
        harness.Selected().test_force_snapshot_marker_readback_failure = false;
        const auto recovered = harness.Recover();
        Check(recovered.success && recovered.code == "SnapshotRecovered", "real retained raw host recovery: " + recovered.code);
        Writable(harness);
        SameFile(publication, harness.image);
        CleanMarker(harness, p + 1);
        Check(harness.Inventory().size() == (deletion ? 0u : 1u), "retained recovery preserves exact once create/delete result");
        SameFile(sibling_wal, harness.Wal(1));
        SameMarks(sibling_marks, *harness.Sibling().tx_manager);
        Envelope(original, publication.bytes);
    }
    Pass("raw host marker readback failure retains every peer and real recovery discharges selected debt");
}

void WalCompletionStages(Harness& harness, std::uint64_t accepted_sequence, bool cleaned) {
    using Wal = apfsaccess::rw::WriteAheadLog;
    const Evidence before(harness);
    {
        SnapshotControlLocks gates(harness.Selected(), true);
        Check(gates.acquired, "full original host gates for independent WAL stage observation");
        UniqueWinHandle handle(CreateFileW(harness.Wal(0).c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        Check(handle.get() != INVALID_HANDLE_VALUE, "open actual original selected WAL read-only");
        const auto read = Wal::ReadAllEvidenceFromHeldHandle(handle.get(), WideToUtf8(harness.arguments[0].recovery_identity),
            {64ull * 1024 * 1024, 1000000}, 256ull * 1024 * 1024);
        Check(read.status == Wal::ReadStatus::Ok && !read.recovered_torn_tail, "original WAL stages decode without repair or reseeding");
        const auto missing = read.records.size();
        auto acceptance = missing, durability = missing, cleanup = missing;
        unsigned accepted_count = 0, durable_count = 0, cleanup_count = 0;
        for (std::size_t index = 0; index < read.records.size(); ++index) {
            const auto& record = read.records[index];
            if (record.operation == Wal::OperationKind::TransactionMarker && record.sequence == accepted_sequence &&
                record.state == Wal::RecordState::Accepted && record.logical_length == 1) {
                acceptance = index;
                ++accepted_count;
            }
            if (record.operation == Wal::OperationKind::DurabilityWatermark && record.logical_offset == accepted_sequence) {
                if (record.state == Wal::RecordState::Checkpointed) { durability = index; ++durable_count; }
                if (record.state == Wal::RecordState::Cleaned) { cleanup = index; ++cleanup_count; }
            }
        }
        Check(accepted_count == 1 && durable_count == 1 && acceptance < durability &&
            (cleaned ? cleanup_count == 1 && durability < cleanup : cleanup_count == 0),
            "actual WAL preserves acceptance then APFS durability, with cleanup only after successful host completion");
    }
    before.Unchanged();
}

void FreshCompletionRestart() {
    for (const bool deletion : {false, true}) for (const bool resume_failure : {false, true}) {
        Harness harness(std::string("fresh-completion-") + (deletion ? "delete-" : "create-") +
            (resume_failure ? "resume-failure" : "complete"));
        harness.Start();
        if (deletion) Check(harness.Create("fresh-completion").success, "host seed for fresh completion deletion");
        const auto identity = deletion ? harness.Inventory().front().identity : apfsaccess::catalog::ApfsSnapshotIdentity{};
        const auto p = harness.owner->CheckpointXid();
        const auto sibling_wal = ObserveFile(harness.Wal(1));
        const auto sibling_marks = harness.Sibling().tx_manager->Watermarks();
        const auto sibling_marker = ObserveFile(harness.Marker(1));
        harness.Selected().test_force_snapshot_marker_readback_failure = true;
        const auto failed = deletion ? harness.Delete(identity) : harness.Create("fresh-completion");
        Check(!failed.success && harness.owner->IsRecoveryRequired() && harness.owner->CheckpointXid() == p + 1,
            "actual normal create/delete retains debt after clean P+1 marker readback failure");
        const auto intent = Debt(harness);
        Check(intent.scope.checkpoint_xid == p, "fresh completion restart uses the original accepted P receipt");
        const auto marks = harness.Selected().tx_manager->Watermarks();
        Check(marks.accepted_sequence && marks.apfs_durable_sequence == marks.accepted_sequence &&
            marks.cleanup_sequence < marks.accepted_sequence, "published completion debt is durable but not cleaned");
        CleanMarker(harness, p + 1);
        WalCompletionStages(harness, marks.accepted_sequence, false);
        const auto publication = ObserveFile(harness.image);
        harness.Close();
        const Evidence interrupted(harness);
        std::string error;
        const bool opened = harness.OpenPeers(error);
        Check(opened && harness.owner->CheckpointXid() == p + 1 &&
            !harness.Selected().test_force_snapshot_marker_readback_failure &&
            !harness.Selected().test_force_snapshot_resume_failure,
            "fresh host owners load the actual clean-marker P+1 source with injection hooks unset: " + error);
        SameMarks(marks, *harness.Selected().tx_manager);
        interrupted.Unchanged();
        auto& fence = *harness.Selected().raw_snapshot_startup_evidence;
        const auto initial_flushes = fence.MarkerFlushAttemptsForTest();
        Check(initial_flushes == 0, "fresh selected fence has not flushed observed startup marker bytes");
        fence.ForceMarkerFlushFailureForTest(true);
        const bool ready = harness.Admit(error);
        Check(ready && harness.Selected().raw_snapshot_restart_sequence == marks.accepted_sequence &&
            harness.Selected().raw_snapshot_completion_xid == p + 1,
            "strict fresh startup admits original durable debt with the actual clean P+1 marker: " + error);
        interrupted.Unchanged();
        PureCapabilities(harness, false, true);
        Check(fence.MarkerFlushAttemptsForTest() == initial_flushes,
            "strict restart admission and pure capabilities do not flush or certify observed startup bytes");
        const auto flush_failed = harness.Recover();
        Check(!flush_failed.success && flush_failed.code == "RawSnapshotHostMarkerCompletionFailed" &&
            fence.MarkerFlushAttemptsForTest() == initial_flushes + 1 && harness.owner->IsRecoveryRequired() &&
            harness.owner->CheckpointXid() == p + 1,
            "first identical clean marker persist must flush, and failed flush retains the actual engine completion latch");
        SameMarks(marks, *harness.Selected().tx_manager);
        Check(harness.Selected().raw_snapshot_restart_sequence == marks.accepted_sequence &&
            harness.Selected().raw_snapshot_completion_xid == p + 1 &&
            apfsaccess::rw::EncodeNativeSnapshotIntent(Debt(harness)) == apfsaccess::rw::EncodeNativeSnapshotIntent(intent),
            "fresh marker flush refusal retains the original accepted restart receipt and completion target");
        for (const auto& session : harness.sessions)
            Check(!session->native_write_enabled && session->raw_snapshot_host_write_paused,
                "fresh failed marker flush keeps every original peer write-disabled and paused");
        PausedDebt(harness, intent);
        CleanMarker(harness, p + 1);
        WalCompletionStages(harness, marks.accepted_sequence, false);
        interrupted.Unchanged();
        fence.ForceMarkerFlushFailureForTest(false);
        harness.Selected().test_force_snapshot_resume_failure = resume_failure;
        auto recovered = harness.Recover();
        Check(fence.MarkerFlushAttemptsForTest() == initial_flushes + 2,
            "retry must flush the identical marker after the failed attempt before authorizing cleanup");
        if (resume_failure) {
            Check(!recovered.success && recovered.code == "RawSnapshotHostResumeInjectedFailure" &&
                !harness.owner->IsRecoveryRequired(), "fresh engine completion can precede failed host write restoration");
            const auto terminal = harness.Selected().tx_manager->Watermarks();
            Check(terminal.accepted_sequence == marks.accepted_sequence &&
                terminal.apfs_durable_sequence == marks.accepted_sequence && terminal.cleanup_sequence == marks.accepted_sequence,
                "fresh restart token completes only the original accepted sequence before host resume failure");
            for (const auto& session : harness.sessions)
                Check(!session->native_write_enabled && session->raw_snapshot_host_write_paused,
                    "fresh completed restart keeps all original peers paused until host restoration");
            const Evidence completed(harness);
            const auto epoch = harness.Selected().metadata_store->StateEpoch();
            WalCompletionStages(harness, marks.accepted_sequence, true);
            PureCapabilities(harness, false, true);
            harness.Selected().test_force_snapshot_resume_failure = false;
            recovered = harness.Recover();
            Check(recovered.success && harness.Selected().metadata_store->StateEpoch() == epoch,
                "second real recovery resumes the clean completed restart without store reload");
            completed.Unchanged();
        }
        Check(recovered.success && recovered.code == "SnapshotRecovered", "actual fresh completion restart recovery: " + recovered.code);
        Writable(harness);
        CleanMarker(harness, p + 1);
        WalCompletionStages(harness, marks.accepted_sequence, true);
        SameFile(publication, harness.image);
        SameFile(sibling_wal, harness.Wal(1));
        SameMarks(sibling_marks, *harness.Sibling().tx_manager);
        SameFile(sibling_marker, harness.Marker(1));
        Check(harness.owner->CheckpointXid() == p + 1 && harness.Inventory().size() == (deletion ? 0u : 1u),
            "fresh clean-marker restart preserves the exact once published create/delete result");
    }
    Pass("raw host fresh clean P+1 restart retains debt on marker flush failure and completes without republication");
}

void CleanResume() {
    Harness harness("clean-host-resume");
    for (std::size_t index = 0; index < harness.arguments.size(); ++index)
        harness.Put(harness.Storage(index) / "payload-spool.bin", Buffer{});
    harness.Start();
    harness.Selected().test_force_snapshot_resume_failure = true;
    const auto failed = harness.Create("resume-clean");
    Check(!failed.success && failed.code == "RawSnapshotHostResumeInjectedFailure" &&
        !harness.owner->IsRecoveryRequired(), "engine cleanup can complete before injected host restoration failure");
    for (const auto& session : harness.sessions)
        Check(!session->native_write_enabled && session->raw_snapshot_host_write_paused, "all peers remain paused after engine cleanup");
    Check(harness.Selected().recovery_active && harness.Selected().write_degraded && harness.Selected().pending_native_writes,
        "selected host is still blocked despite clean actual engine");
    const auto marks = harness.Selected().tx_manager->Watermarks();
    Check(marks.accepted_sequence && marks.accepted_sequence == marks.apfs_durable_sequence &&
        marks.accepted_sequence == marks.cleanup_sequence, "terminal host-resume gap has equal actual watermarks");
    CleanMarker(harness, harness.owner->CheckpointXid());
    const Evidence clean(harness);
    const auto epoch = harness.Selected().metadata_store->StateEpoch();
    {
        SnapshotControlLocks gates(harness.Selected(), true);
        apfsaccess::catalog::ApfsSnapshotScope scope;
        std::string error;
        const bool inspected = gates.acquired && InspectRawSnapshotHostResume(harness.Selected(), *harness.owner, scope, error);
        Check(inspected && scope.checkpoint_xid == harness.owner->CheckpointXid(), "strict pure clean-resume authority: " + error);
    }
    clean.Unchanged();
    SameMarks(marks, *harness.Selected().tx_manager);
    Check(harness.Selected().metadata_store->StateEpoch() == epoch, "pure clean-resume inspection cannot reload or republish");
    PureCapabilities(harness, false, true);
    harness.Selected().test_force_snapshot_resume_failure = false;
    const auto recovered = harness.Recover();
    Check(recovered.success && recovered.code == "SnapshotRecovered", "actual terminal host clean resume: " + recovered.code);
    Writable(harness);
    clean.Unchanged();
    SameMarks(marks, *harness.Selected().tx_manager);
    Check(harness.Selected().metadata_store->StateEpoch() == epoch && harness.Inventory().size() == 1,
        "terminal resume does not append, clean or publish a second snapshot");
    Pass("raw host terminal clean authority restores paused peers without source or WAL writes");
}

void PreacceptMarkerRollbackRecovery() {
    Harness harness("preaccept-marker-rollback");
    harness.Start();
    const auto p = harness.owner->CheckpointXid();
    const Evidence clean(harness);
    harness.Selected().test_force_recovery_marker_finalize_failure = true;
    harness.Selected().test_force_snapshot_resume_failure = true;
    const auto failed = harness.Create("never-accepted");
    Check(!failed.success && failed.code == "RawSnapshotHostMarkerArmFailed" &&
        !harness.owner->IsRecoveryRequired() && harness.owner->CheckpointXid() == p,
        "failed actual marker arm and host rollback stop before engine acceptance");
    for (const auto& session : harness.sessions) {
        const auto marks = session->tx_manager->Watermarks();
        Check(!session->native_write_enabled && session->raw_snapshot_host_write_paused &&
            !marks.accepted_sequence && !marks.apfs_durable_sequence && !marks.cleanup_sequence,
            "preaccept marker rollback failure pauses the cohort without accepted debt");
    }
    clean.Unchanged();
    PureCapabilities(harness, false, true);
    harness.Selected().test_force_recovery_marker_finalize_failure = false;
    harness.Selected().test_force_snapshot_resume_failure = false;
    const auto recovered = harness.Recover();
    Check(recovered.success && recovered.code == "SnapshotRecovered", "strict original clean authority recovers failed preaccept rollback: " + recovered.code);
    Writable(harness);
    SameFile(clean.files.front(), harness.image);
    for (std::size_t index = 0; index < harness.arguments.size(); ++index)
        SameFile(clean.files[4 + index * 4], harness.Wal(index));
    CleanMarker(harness, p);
    Check(harness.Inventory().empty(), "preaccept recovery cannot publish the refused snapshot");
    Pass("raw host failed preaccept marker arm and rollback resumes only with clean original engine evidence");
}

void Restart() {
    for (const bool deletion : {false, true}) for (const bool published : {false, true}) {
        Harness harness(std::string("restart-") + (deletion ? "delete-" : "create-") + (published ? "p1" : "p"));
        harness.Start();
        if (deletion) Check(harness.Create("restart").success, "host seed for restart deletion");
        const auto identity = deletion ? harness.Inventory().front().identity : apfsaccess::catalog::ApfsSnapshotIdentity{};
        const auto p = harness.owner->CheckpointXid();
        const auto original = ObserveFile(harness.image).bytes;
        const auto sibling_wal = ObserveFile(harness.Wal(1));
        const auto sibling_marks = harness.Sibling().tx_manager->Watermarks();
        harness.Selected().metadata_store->SetCommitStageHook([published](std::string_view stage) {
            return stage != (published ? "after-apple-publish" : "before-apple-publish");
        });
        const auto failed = deletion ? harness.Delete(identity) : harness.Create("restart");
        Check(!failed.success, "actual host create/delete interrupted at selected publication boundary");
        const auto intent = Debt(harness);
        Check(intent.scope.checkpoint_xid == p && intent.scope.store_offset_bytes == 0 &&
            intent.scope.store_size_bytes == StoreSize, "original raw receipt uses relative NX window at P");
        RecoveryMarkerState dirty;
        Check(LoadRecoveryMarkerState(harness.Marker(0), dirty) == RecoveryMarkerLoadStatus::Loaded &&
            dirty.dirty && dirty.last_commit_xid == p, "actual interrupted host marker stays dirty at P");
        harness.Close();
        const Evidence interrupted(harness);
        std::string error;
        const bool opened = harness.OpenPeers(error);
        Check(opened && harness.owner->CheckpointXid() == p + (published ? 1 : 0),
            "fresh original host bootstraps actual P/P+1 checkpoint: " + error);
        interrupted.Unchanged();
        const bool ready = harness.Admit(error);
        Check(ready && harness.Selected().raw_snapshot_restart_sequence &&
            harness.Selected().raw_snapshot_completion_xid == p + 1, "real startup admits exact isolated original restart debt: " + error);
        interrupted.Unchanged();
        for (const auto& session : harness.sessions) Check(!session->native_write_enabled, "fresh restart pauses every original host peer");
        PureCapabilities(harness, false, true);
        const auto recovered = harness.Recover();
        Check(recovered.success && recovered.code == "SnapshotRecovered", "actual fresh P/P+1 raw host recovery: " + recovered.code);
        Writable(harness);
        Check(harness.owner->CheckpointXid() == p + 1 && harness.Inventory().size() == (deletion ? 0u : 1u),
            "fresh restart publishes only missing P+1 and completes exact create/delete outcome");
        CleanMarker(harness, p + 1);
        SameFile(sibling_wal, harness.Wal(1));
        SameMarks(sibling_marks, *harness.Sibling().tx_manager);
        const auto recovered_image = ObserveFile(harness.image);
        Envelope(original, recovered_image.bytes);
        if (published) SameFile(interrupted.files.front(), harness.image);
        const Evidence finished(harness);
        const auto no_op = harness.Recover();
        Check(no_op.success && no_op.code == "SnapshotRecoverNoOp", "repeated completed host recovery is a pure no-op");
        finished.Unchanged();
    }
    Pass("raw host fresh original P/P+1 startup and controls recover create/delete exactly once");
}

void StartupRefusals() {
    for (unsigned mode = 0; mode < 4; ++mode) {
        Harness harness("corrupt-evidence-" + std::to_string(mode));
        if (mode == 0) harness.Put(harness.Marker(0), TextBytes("dirty=unknown\nlastCommitXid=7\n"));
        if (mode == 1) harness.Put(harness.Storage(0) / "payload-spool.idx", TextBytes("corrupt original index"));
        if (mode == 2) harness.Put(harness.Wal(0), TextBytes("corrupt original WAL"));
        if (mode == 3) harness.Put(harness.Storage(0) / "payload-spool.bin", TextBytes("original unindexed payload bytes"));
        const Evidence corrupt(harness);
        std::string error;
        const bool opened = harness.OpenPeers(error);
        const bool accepted = opened && harness.Admit(error);
        Check(!accepted && !error.empty(), "actual corrupted marker/index/WAL or unindexed payload startup refuses");
        corrupt.Unchanged();
        for (const auto& session : harness.sessions)
            Check(!session->raw_snapshot_startup_admitted && !session->raw_snapshot_authority,
                "corrupt original evidence never grants host authority");
    }
    for (unsigned mode = 0; mode < 3; ++mode) {
        Harness harness("appeared-evidence-" + std::to_string(mode));
        std::string error;
        const bool opened = harness.OpenPeers(error);
        Check(opened, "observe absent original evidence before appearance: " + error);
        const auto path = mode == 0 ? harness.Marker(0) : harness.Storage(0) /
            (mode == 1 ? "payload-spool.idx" : "payload-spool.bin");
        harness.Put(path, mode == 0 ? TextBytes("dirty=0\nlastCommitXid=7\n") : Buffer{});
        const Evidence appeared(harness);
        Check(!harness.Admit(error) && !error.empty(), "actual appeared marker/index/payload refuses original absent observation");
        appeared.Unchanged();
        for (const auto& session : harness.sessions)
            Check(!session->raw_snapshot_startup_admitted && !session->raw_snapshot_authority &&
                !ObserveFile(session->tx_journal_file).present, "appeared evidence refusal precedes original WAL materialization");
    }
    Harness changed("changed-source-binding");
    std::string error;
    const bool opened = changed.OpenPeers(error);
    Check(opened, "open original raw host before binding change: " + error);
    const Evidence before(changed);
    DevicePeer::ChangeSerial(const_cast<apfsaccess::rw::BlockDevice&>(changed.owner->Device()));
    Check(!changed.Admit(error), "host startup refuses changed actual held descriptor qualification");
    before.Unchanged();
    Pass("raw host corrupt or appeared original evidence refuses without replacing source or recovery files");
}

void CorruptRestartSource() {
    for (const bool published : {false, true}) {
        Harness harness(published ? "corrupt-restart-p1" : "corrupt-restart-p");
        harness.Start();
        harness.Selected().metadata_store->SetCommitStageHook([published](std::string_view stage) {
            return stage != (published ? "after-apple-publish" : "before-apple-publish");
        });
        Check(!harness.Create("corrupt-restart").success, "create real raw restart debt before source corruption");
        const auto intent = Debt(harness);
        harness.Close();
        auto source = ObserveFile(harness.image).bytes;
        const auto offset = PrefixSize + intent.checkpoint_slot * BlockSize;
        Check(offset < PrefixSize + StoreSize, "receipt destination belongs to admitted original NX window");
        source.at(static_cast<std::size_t>(offset)) ^= std::byte{1};
        Save(harness.image, source);
        const Evidence corrupt(harness);
        std::string error;
        const bool opened = harness.OpenPeers(error);
        Check(!(opened && harness.Admit(error)) && !error.empty(), "fresh actual host refuses corrupted original receipt destination");
        corrupt.Unchanged();
        for (const auto& session : harness.sessions)
            Check(!session->raw_snapshot_startup_admitted && !session->raw_snapshot_authority,
                "corrupted restart source never mints fresh host authority");
    }
    Pass("raw host corrupted P/P+1 restart sources preserve original source and every recovery artifact");
}
}

void RunRawHostIdleRetryTests() {
    raw_snapshot_host_tests::StagedAccessTimeRetry();
    raw_snapshot_host_tests::PendingMarkerRetry();
    raw_snapshot_host_tests::StagedHardFailureOrders();
    raw_snapshot_host_tests::TransientHostIdleRetry();
    raw_snapshot_host_tests::HostIdleRetryHardRefusals();
    raw_snapshot_host_tests::PublishedHostIdleRefusal();
}

void RunRawSnapshotHostTests() {
    RunRawHostIdleRetryTests();
    raw_snapshot_host_tests::CleanWalDirtyMarkerRestart();
    raw_snapshot_host_tests::DirtyMarkerRestartRefusals();
    raw_snapshot_host_tests::DirtyMarkerRestartFlushFailure();
    raw_snapshot_host_tests::RawWireDelete();
    raw_snapshot_host_tests::RecoveryIdentityStartupOrdering();
    raw_snapshot_host_tests::RecoveryIdentityPreflightRefusals();
    raw_snapshot_host_tests::MixedPreflightContextSettlement();
    raw_snapshot_host_tests::CleanAbsentStartup();
    raw_snapshot_host_tests::OrdinarySiblingPublication();
    raw_snapshot_host_tests::Lifecycle();
    raw_snapshot_host_tests::MarkerReadbackRecovery();
    raw_snapshot_host_tests::FreshCompletionRestart();
    raw_snapshot_host_tests::CleanResume();
    raw_snapshot_host_tests::PreacceptMarkerRollbackRecovery();
    raw_snapshot_host_tests::Restart();
    raw_snapshot_host_tests::StartupRefusals();
    raw_snapshot_host_tests::CorruptRestartSource();
}
}
