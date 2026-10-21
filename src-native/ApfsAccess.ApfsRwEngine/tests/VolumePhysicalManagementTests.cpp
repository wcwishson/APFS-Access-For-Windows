#include "VolumeManagementTestFixture.h"
#include "../src/VolumePhysicalMediaInternal.h"
#include "../src/VolumePhysicalBindingCodec.h"
#include "../src/VolumePhysicalGeometryInternal.h"
#include "../src/VolumeGptGeometry.h"
#include "../src/VolumeManagementInternal.h"
#include "../src/VolumeResizeInternal.h"
#include "VolumePhysicalKeeper.h"
#include "PayloadSpool.h"
#include <winioctl.h>
#include <wincrypt.h>
#include <iostream>
#include <sstream>

#define APFS_VOLUME_MANAGEMENT_TOOL_TESTING
#define APFS_VOLUME_MANAGEMENT_FAULT_INJECTION
#include "../tools/VolumeManagementImage.cpp"

using PhysicalObservationSourceFactory = std::function<std::shared_ptr<apfsaccess::rw::VolumePhysicalSource>(
    std::wstring_view, std::wstring_view, std::uint64_t, std::uint64_t,
    const apfsaccess::rw::RawHardwareQualification&, std::string&)>;
int VolumePhysicalObserveMain(int, wchar_t**, const PhysicalObservationSourceFactory&);

namespace {
namespace vm = apfsaccess::volume_management_test;
using namespace apfsaccess::rw;
using namespace apfsaccess::catalog;
using Bytes = std::vector<std::byte>;
constexpr std::uint64_t Base = 1048576, Disk = 16u << 20, Window = 2u << 20;
constexpr std::wstring_view Instance = L"USBSTOR\\DISK&VEN_FICTIONAL&PROD_TOPOLOGY&REV_0001\\TOPOLOGYTEST42&0";
unsigned checks = 0, groups = 0;
void Check(bool value, const std::string& message) { ++checks; if (!value) throw std::runtime_error(message); }
struct Carrier {
    HANDLE h = INVALID_HANDLE_VALUE;
    FILE_ID_INFO expected{};
    bool available = true;
    std::uint64_t writes = 0, escaped = 0;
    std::uint64_t zero_calls = 0, zero_bytes = 0;
    std::uint64_t disk = Disk, window = Window;
    std::uint64_t epoch = 0;
    std::map<std::uint64_t, Bytes> sentinels;
    RawSnapshotBinding binding;
    ~Carrier() { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); }
    bool Read(std::uint64_t at, std::size_t size, Bytes& bytes) const {
        bytes.clear(); if (at > disk || size > disk - at || size > MAXDWORD) return false;
        LARGE_INTEGER pos{}; pos.QuadPart = at; DWORD got{}; bytes.resize(size);
        if (SetFilePointerEx(h, pos, nullptr, FILE_BEGIN) && ReadFile(h, bytes.data(), static_cast<DWORD>(size), &got, nullptr) && got == size) return true;
        bytes.clear(); return false;
    }
    bool WriteAt(std::uint64_t at, std::span<const std::byte> bytes) {
        if (at > disk || bytes.size() > disk - at || bytes.size() > MAXDWORD) return false;
        LARGE_INTEGER pos{}; pos.QuadPart = at; DWORD count{};
        return SetFilePointerEx(h, pos, nullptr, FILE_BEGIN) && WriteFile(h, bytes.data(), static_cast<DWORD>(bytes.size()), &count, nullptr) && count == bytes.size();
    }
    bool Current() const {
        FILE_ID_INFO now{}; LARGE_INTEGER length{};
        if (!available || !GetFileInformationByHandleEx(h, FileIdInfo, &now, sizeof(now)) ||
            std::memcmp(&now, &expected, sizeof(now)) || !GetFileSizeEx(h, &length) || static_cast<std::uint64_t>(length.QuadPart) != disk) return false;
        for (const auto& [at, expected_bytes] : sentinels) {
            Bytes bytes; if (!Read(at, expected_bytes.size(), bytes) || bytes != expected_bytes) return false;
        }
        return true;
    }
};
}

namespace apfsaccess::rw {
struct VolumePhysicalKeeperTestPeer {
    static std::shared_ptr<VolumePhysicalSource> Bind(const std::shared_ptr<Carrier>& file,
        std::function<bool()> current_control = {}, std::function<bool()> read_control = {}) {
        std::string error; Check(ValidateVolumePhysicalPolicy(file->binding, Instance, error), error);
        auto state = std::make_unique<VolumePhysicalSource::Impl>();
        state->binding = file->binding; state->instance = Instance;
        state->identity = VolumePhysicalIdentity(file->binding, Instance);
        state->current = [file, epoch = file->epoch, current_control] {
            return file->epoch == epoch && file->Current() && (!current_control || current_control());
        };
        state->read = [file, read_control](auto at, auto count, auto& bytes, bool) {
            if (read_control && !read_control()) return false;
            return at <= file->window && count <= file->window - at && file->Read(Base + at, count, bytes);
        };
        state->read_metadata = [file](auto at, auto count, auto& bytes) { return file->Read(at, count, bytes); };
        state->write = [file](auto at, auto bytes) {
            if (at > file->window || bytes.size() > file->window - at) { ++file->escaped; return false; }
            ++file->writes; return file->WriteAt(Base + at, bytes);
        };
        state->flush = [file] { return FlushFileBuffers(file->h) != FALSE; };
        state->zero = [file](auto at, auto count) {
            if (at % 4096 || count % 4096 || at > file->window || count > file->window - at) { ++file->escaped; return false; }
            FILE_ZERO_DATA_INFORMATION range{}; range.FileOffset.QuadPart = Base + at;
            range.BeyondFinalZero.QuadPart = Base + at + count; DWORD got{};
            ++file->writes; ++file->zero_calls; file->zero_bytes += count;
            return DeviceIoControl(file->h, FSCTL_SET_ZERO_DATA, &range, sizeof(range), nullptr, 0, &got, nullptr) != FALSE;
        };
        return std::shared_ptr<VolumePhysicalSource>(new VolumePhysicalSource(std::move(state)));
    }
};
struct VolumePhysicalGeometryTestPeer {
    static std::shared_ptr<VolumePhysicalGeometrySource> Bind(const std::shared_ptr<Carrier>& file, const RawSnapshotBinding& original) {
        auto impl = std::make_unique<VolumePhysicalGeometrySource::Impl>(); auto* state = impl.get();
        impl->original = original; impl->instance = Instance; impl->current = [file] { return file->Current(); };
        impl->read = [file](auto at, auto count, auto& out) { return file->Read(at, count, out); };
        impl->write = [file, state](auto at, auto bytes) {
            const bool window = state->plan && at >= Base && at - Base <= state->plan->snapshot.target_bytes &&
                bytes.size() <= state->plan->snapshot.target_bytes - (at - Base);
            const bool gpt = state->plan && std::any_of(state->plan->writes.begin(), state->plan->writes.end(), [&](const auto& w) {
                return w.offset == at && bytes.size() == w.after.size() && std::equal(bytes.begin(), bytes.end(), w.after.begin()); });
            if (!window && !gpt) { ++file->escaped; return false; } ++file->writes; return file->WriteAt(at, bytes);
        };
        impl->zero = [file, state](auto at, auto count) {
            if (!state->plan || at < Base || at - Base > state->plan->snapshot.target_bytes || count > state->plan->snapshot.target_bytes - (at - Base)) return false;
            FILE_ZERO_DATA_INFORMATION range{}; range.FileOffset.QuadPart = at; range.BeyondFinalZero.QuadPart = at + count; DWORD got{};
            return DeviceIoControl(file->h, FSCTL_SET_ZERO_DATA, &range, sizeof(range), nullptr, 0, &got, nullptr) != FALSE;
        };
        impl->flush = [file] { return FlushFileBuffers(file->h) != FALSE; };
        impl->refresh = [file] { return file->Current(); };
        impl->retire = [file] { if (!file->Current()) return false; ++file->epoch; return true; };
        impl->rebind = [file](const RawSnapshotBinding& binding, std::string&) {
            file->binding = binding; file->window = binding.media.limit_bytes; return VolumePhysicalKeeperTestPeer::Bind(file);
        };
        return std::shared_ptr<VolumePhysicalGeometrySource>(new VolumePhysicalGeometrySource(std::move(impl)));
    }
};
}

namespace {
struct Fixture {
    std::filesystem::path root;
    std::shared_ptr<Carrier> file;
    std::shared_ptr<VolumePhysicalSource> source;
    VolumeManagementRequest request;
    Fixture(const std::filesystem::path& directory, bool create = true, bool scale = false, bool compact = false) : root(directory), file(std::make_shared<Carrier>()) {
        std::filesystem::create_directories(root);
        if (scale) { file->window = 128u << 20; file->disk = 4ull << 30; }
        if (compact) { Check(scale, "compact carrier retains scaled APFS window"); file->disk = 192u << 20; }
        const auto original = vm::Fixture(true, 0, file->window / 4096);
        Check(original.size() == file->window, "bounded canonical source fixture");
        const auto path = root / "carrier.sparse";
        file->h = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, create ? CREATE_NEW : OPEN_EXISTING,
            FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        Check(file->h != INVALID_HANDLE_VALUE, "exclusive private sparse carrier");
        auto& b = file->binding;
        b.hardware.kind = RawHardwareIdentityKind::QualifiedSerialTuple; b.hardware.bus_type = 7;
        b.hardware.vendor = "Fictional"; b.hardware.product = "Topology Surrogate"; b.hardware.revision = "0001"; b.hardware.serial = "TOPOLOGYTEST42";
        b.media.disk_guid.fill(std::byte{0x31}); b.media.partition_guid.fill(std::byte{0x52});
        b.media.partition_offset_bytes = b.media.base_offset_bytes = Base; b.media.partition_length_bytes = scale ? 2ull << 30 : 8u << 20;
        if (compact) b.media.partition_length_bytes = 144u << 20;
        b.media.limit_bytes = file->window; b.media.disk_size_bytes = file->disk; b.media.logical_sector_bytes = b.media.physical_sector_bytes = 4096;
        for (const auto at : {std::uint64_t(0), Base - 4096, Base + (scale ? b.media.partition_length_bytes : file->window), file->disk - 4096})
            file->sentinels.emplace(at, Bytes(4096, std::byte{0x69}));
        if (create) {
            DWORD got{}; Check(DeviceIoControl(file->h, FSCTL_SET_SPARSE, nullptr, 0, nullptr, 0, &got, nullptr) != FALSE, "sparse storage");
            LARGE_INTEGER end{}; end.QuadPart = file->disk;
            Check(SetFilePointerEx(file->h, end, nullptr, FILE_BEGIN) && SetEndOfFile(file->h), "fixed carrier EOF");
            for (std::size_t at = 0; at < original.size(); at += 4096) {
                const std::span block(original.data() + at, 4096);
                if (std::any_of(block.begin(), block.end(), [](auto value) { return value != std::byte{}; }))
                    Check(file->WriteAt(Base + at, block), "populated canonical source block");
            }
            for (const auto& [at, bytes] : file->sentinels)
                Check(file->WriteAt(at, bytes), "independent outside-window sentinel");
            Check(FlushFileBuffers(file->h) && GetFileInformationByHandleEx(file->h, FileIdInfo, &file->expected, sizeof(file->expected)), "source durability and ID");
            const auto* begin = reinterpret_cast<const std::byte*>(&file->expected);
            vm::Save(root / "original-file-id.bin", Bytes(begin, begin + sizeof(file->expected)));
        } else {
            const auto id = vm::Read(root / "original-file-id.bin");
            Check(id.size() == sizeof(file->expected), "original retained file ID"); std::memcpy(&file->expected, id.data(), id.size());
        }
        Check(file->Current(), "held original file/EOF/sentinels");
        source = VolumePhysicalKeeperTestPeer::Bind(file);
        request = vm::Request(root, true, original); request.image = Instance; request.offset_bytes = Base;
        request.history_context = {root / "spool", root / "recovery"};
        if (create) {
            std::filesystem::create_directories(request.history_context.spool_root);
            std::filesystem::create_directories(request.history_context.recovery_root);
        }
        const auto cp = vm::Checkpoint(original); request.sibling_wals.clear();
        for (const auto& v : cp.volumes) {
            const auto wal = Wal(v.superblock.object_id);
            if (create) { std::filesystem::create_directories(wal.parent_path()); vm::Save(wal, {}); }
            request.sibling_wals.emplace(v.superblock.object_id, wal);
        }
    }
    std::filesystem::path Wal(std::uint64_t oid) const {
        const auto identity = DeriveVolumePhysicalRecoveryIdentity(file->binding, request.container_uuid, oid);
        return request.history_context.spool_root / ("apfs_recovery_v1_" + identity.substr(17)) / "write-ahead.wal";
    }
    Bytes Image() const {
        Bytes bytes; bytes.reserve(static_cast<std::size_t>(file->window));
        for (std::uint64_t at = 0; at < file->window;) {
            const auto count = static_cast<std::size_t>((std::min<std::uint64_t>)(4u << 20, file->window - at)); Bytes part;
            Check(source->Read(at, count, part) && part.size() == count, "actual held source read");
            bytes.insert(bytes.end(), part.begin(), part.end()); at += count;
        }
        return bytes;
    }
    AppleCheckpointView Checkpoint() const { return vm::Checkpoint(Image()); }
    void Payloads() const { for (unsigned i = 0; i < 2; ++i) { Bytes b; Check(source->Read((200 + i * 8) * 4096, 4096, b) && b == Bytes(4096, std::byte(0x41 + i)), "unchanged complete sibling payload"); } }
};
void Positive(const std::filesystem::path& root) {
    Fixture f(root); const auto before = f.Image();
    const auto p = PrepareVolumePhysicalCreate(f.source, f.request);
    Check(p.outcome == VolumeManagementOutcome::Prepared, "physical create prepare: " + p.error);
    Check(f.Image() == before && !f.file->writes, "prepare never changes source");
    Check(ReadU64LE(vm::Read(p.journal_path), 0) == volume_physical::PhysicalSnapshotManagementMagic,
        "typed VMT4 original with physical snapshot-tree authority");
    const auto done = ApplyVolumePhysicalManagement(f.source, f.request, p.confirmation_token);
    Check(done.outcome == VolumeManagementOutcome::Committed, "physical create: " + done.error);
    Check(f.Checkpoint().volumes.size() == 3 && f.file->Current() && !f.file->escaped, "new peer and unchanged external ranges");
    f.Payloads();
    Check(RecoverVolumePhysicalManagement(f.source, f.request).outcome == VolumeManagementOutcome::Committed, "idempotent create recovery");
    auto cp = f.Checkpoint(); auto remove = f.request;
    remove.operation = VolumeManagementOperation::Delete; remove.checkpoint_xid = cp.container.superblock.xid;
    remove.name_utf8.clear(); remove.quota_blocks = remove.reserve_blocks = 0; remove.case_sensitive = false;
    remove.sibling_wals.emplace(remove.volume_oid, f.Wal(remove.volume_oid));
    const auto deletion = PrepareVolumePhysicalDelete(f.source, remove);
    Check(deletion.outcome == VolumeManagementOutcome::Prepared, "physical delete prepare: " + deletion.error);
    const auto deleted = ApplyVolumePhysicalManagement(f.source, remove, deletion.confirmation_token);
    Check(deleted.outcome == VolumeManagementOutcome::Committed, "physical delete: " + deleted.error);
    Check(f.Checkpoint().volumes.size() == 2, "delete restores exact sibling count"); f.Payloads();
    Check(RecoverVolumePhysicalManagement(f.source, remove).outcome == VolumeManagementOutcome::Committed, "fresh history/idempotent delete");
    auto history = AcquireVolumeKeeperPhysicalHistory(f.source, *f.source, f.request.journal_directory, {}, {}, {}, {}, f.request.history_context, true);
    Check(history && f.file->Current(), "completed topology admits exact physical continuation history");
    ++groups;
}
void Controls(const std::filesystem::path& root) {
    Fixture f(root); const auto before = f.Image(); const auto p = PrepareVolumePhysicalCreate(f.source, f.request);
    Check(p.outcome == VolumeManagementOutcome::Prepared, p.error);
    auto request = f.request; request.image = L"\\\\.\\PhysicalDrive2";
    Check(ApplyVolumePhysicalManagement(f.source, request, p.confirmation_token).outcome == VolumeManagementOutcome::Refused, "disk number cannot replace instance");
    const auto original = f.file->binding; f.file->binding.media.partition_guid[0] ^= std::byte{1};
    auto changed = VolumePhysicalKeeperTestPeer::Bind(f.file);
    Check(ApplyVolumePhysicalManagement(changed, f.request, p.confirmation_token).outcome == VolumeManagementOutcome::Refused && !f.file->writes,
        "same debt namespace but different GPT binding refuses"); f.file->binding = original;
    const auto frame = vm::Read(p.journal_path); auto spoof = frame;
    apfsaccess::testfixture::PutU64LE(spoof, 0, 0x31544d5653465041ull); vm::Save(p.journal_path, spoof);
    Check(RecoverVolumePhysicalManagement(f.source, f.request).outcome == VolumeManagementOutcome::Refused && !f.file->writes, "physical original cannot become VMT1");
    vm::Save(p.journal_path, frame);
    Check(CancelVolumePhysicalManagement(f.source, f.request, p.confirmation_token).outcome == VolumeManagementOutcome::Cancelled && f.Image() == before,
        "exact cancel preserves all source bytes");
    ++groups;
}
void Cut(const std::filesystem::path& root) {
    Fixture f(root); const auto p = PrepareVolumePhysicalCreate(f.source, f.request); Check(p.outcome == VolumeManagementOutcome::Prepared, p.error);
    bool hit = false;
    const auto r = ApplyVolumePhysicalManagement(f.source, f.request, p.confirmation_token, [&](auto stage) {
        if (stage == "before-apple-checkpoint-switch") { hit = true; return false; } return true;
    });
    Check(hit && r.outcome == VolumeManagementOutcome::RecoveryRequired, "accepted partial publication cut: " + r.error);
    Check(f.file->writes && f.Checkpoint().volumes.size() == 2 && f.file->Current(), "cut holds old canonical generation");
    f.Payloads(); ++groups;
}
void Recover(const std::filesystem::path& root) {
    Fixture f(root, false); const auto r = RecoverVolumePhysicalManagement(f.source, f.request);
    Check(r.outcome == VolumeManagementOutcome::Committed, "fresh-process forward replay: " + r.error);
    Check(f.Checkpoint().volumes.size() == 3 && f.file->Current() && !f.file->escaped, "fresh generation and neighbor preservation");
    f.Payloads();
    Check(RecoverVolumePhysicalManagement(f.source, f.request).outcome == VolumeManagementOutcome::Committed, "fresh replay is idempotent"); ++groups;
}
void AuthorityControls(const std::filesystem::path& root) {
    {
        Fixture f(root / "stale"); const auto p = PrepareVolumePhysicalCreate(f.source, f.request);
        Check(p.outcome == VolumeManagementOutcome::Prepared, p.error);
        Bytes changed; Check(f.source->Read(Window - 4096, 4096, changed), "stale block read"); changed.back() ^= std::byte{1};
        Check(f.file->WriteAt(Base + Window - 4096, changed), "actual stale byte"); const auto stale = f.Image();
        const auto r = ApplyVolumePhysicalManagement(f.source, f.request, p.confirmation_token);
        Check(r.outcome == VolumeManagementOutcome::Refused && r.error == "VolumeManagementStalePreimage" &&
            f.Image() == stale && !f.file->writes, "stale source consumes plan without publication: " + r.error);
    }
    {
        Fixture f(root / "wal"); const auto p = PrepareVolumePhysicalCreate(f.source, f.request);
        Check(p.outcome == VolumeManagementOutcome::Prepared, p.error); const auto before = f.Image();
        vm::Save(f.request.sibling_wals.at(101), Bytes(1, std::byte{0x31}));
        Check(ApplyVolumePhysicalManagement(f.source, f.request, p.confirmation_token).outcome == VolumeManagementOutcome::Refused &&
            f.Image() == before && !f.file->writes, "changed original WAL refuses before target writes");
    }
    {
        Fixture f(root / "original-debt"); const auto before = f.Image();
        {
            TransactionManager tx(L"Strict"); tx.SetJournalPath(f.Wal(101).wstring());
            const auto identity = DeriveVolumePhysicalRecoveryIdentity(f.file->binding, f.request.container_uuid, 101);
            tx.SetVolumeIdentity(std::wstring(identity.begin(), identity.end()));
            TransactionManager::MutationIntent intent; intent.kind = TransactionManager::MutationKind::CreateFile;
            intent.path = L"\\pending"; intent.object_id = 400; intent.generation = f.request.checkpoint_xid + 1;
            Check(tx.Begin() && tx.RecordMutation(intent) && tx.Accept(f.request.checkpoint_xid), "actual original physical WAL acceptance");
        }
        const auto r = PrepareVolumePhysicalCreate(f.source, f.request);
        Check(r.outcome == VolumeManagementOutcome::Refused && r.error == "VolumeManagementWalDebtOrRecoveryPins" &&
            f.Image() == before && !f.file->writes, "original accepted debt veto after owner release: " + r.error);
    }
    {
        Fixture f(root / "snapshot"); const auto cp = f.Checkpoint(); const auto bytes = f.Image();
        VectorRandomAccessSource original(bytes); AppleSnapshotCreateRequest request;
        request.volume_object_id = 101; request.name_utf8 = "retained"; request.snapshot_inum = 600;
        request.creation_time_ns = 1700000000000000000ull; AppleSnapshotCreatePlan plan; std::string error;
        Check(PlanAppleSnapshotCreate(original, cp, request, plan, error), "canonical snapshot producer: " + error);
        for (const auto& w : plan.commit.publication.before_superblock_writes)
            Check(f.file->WriteAt(Base + w.physical_block * 4096, w.bytes), "snapshot COW destination");
        const auto& nx = plan.commit.publication.superblock_write;
        Check(f.file->WriteAt(Base + nx.physical_block * 4096, nx.bytes) && FlushFileBuffers(f.file->h), "snapshot canonical switch");
        const auto changed = f.Image(); const auto next = vm::Checkpoint(changed);
        f.request.checkpoint_xid = next.container.superblock.xid; f.request.volume_oid = next.container.superblock.next_oid;
        Check(PrepareVolumePhysicalCreate(f.source, f.request).outcome == VolumeManagementOutcome::Refused &&
            f.Image() == changed && !f.file->writes, "snapshot ownership cannot be bypassed by physical create");
    }
    {
        Fixture f(root / "foreign"); const auto before = f.Image(); VectorRandomAccessSource source(before);
        volume_management::TopologyPlan plan; std::string error;
        Check(volume_management::PlanTopology(source, f.request, plan, error), error);
        const auto p = PrepareVolumePhysicalCreate(f.source, f.request); Check(p.outcome == VolumeManagementOutcome::Prepared, p.error);
        Check(ApplyVolumePhysicalManagement(f.source, f.request, p.confirmation_token,
            [](auto stage) { return stage != "after-volume-management-accept"; }).outcome == VolumeManagementOutcome::RecoveryRequired,
            "original accepted before foreign NX test");
        const auto at = plan.publication.before_superblock_writes.front().physical_block * 4096;
        Bytes nx(before.begin(), before.begin() + 4096);
        apfsaccess::testfixture::PutU64LE(nx, 0x10, p.post_xid + 100); apfsaccess::testfixture::FletcherForBlock(nx, 4096);
        Check(ParseNxSuperblock(nx).has_value() && f.file->WriteAt(Base + at, nx), "valid foreign NX at planned data destination");
        const auto changed = f.Image();
        const auto r = RecoverVolumePhysicalManagement(f.source, f.request);
        Check(r.outcome == VolumeManagementOutcome::RecoveryRequired && !f.file->writes && f.Image() == changed,
            "accepted recovery refuses foreign valid NX without writes: " + r.error);
    }
    ++groups;
}
std::pair<int, std::string> InvokeTool(std::vector<std::wstring> args, const PhysicalManagementSourceFactory& factory) {
    std::vector<wchar_t*> argv; for (auto& arg : args) argv.push_back(arg.data());
    std::ostringstream output; const auto old = std::cout.rdbuf(output.rdbuf()); int code;
    try { code = VolumeManagementImageMain(static_cast<int>(argv.size()), argv.data(), factory); }
    catch (...) { std::cout.rdbuf(old); throw; }
    std::cout.rdbuf(old); return {code, output.str()};
}
std::pair<int, std::string> InvokeObserver(std::vector<std::wstring> args, const PhysicalObservationSourceFactory& factory) {
    std::vector<wchar_t*> argv; for (auto& arg : args) argv.push_back(arg.data());
    std::ostringstream output; const auto old = std::cout.rdbuf(output.rdbuf()); int code;
    try { code = VolumePhysicalObserveMain(static_cast<int>(argv.size()), argv.data(), factory); }
    catch (...) { std::cout.rdbuf(old); throw; }
    std::cout.rdbuf(old); return {code, output.str()};
}
void ObservationControls(const std::filesystem::path& root) {
    Fixture f(root); const auto before = f.Image(); const auto cp = f.Checkpoint();
    const auto& volume = cp.volumes.front().superblock;
    const auto Wide = [](const std::string& value) { return std::wstring(value.begin(), value.end()); };
    const std::vector<std::wstring> args = {L"observer", L"--device", L"\\\\.\\PhysicalDrive42", L"--instance", std::wstring(Instance),
        L"--base", std::to_wstring(Base), L"--limit", std::to_wstring(Window),
        L"--vendor", L"Fictional", L"--product", L"Topology Surrogate", L"--serial", L"TOPOLOGYTEST42",
        L"--container", Wide(cp.container.superblock.uuid_hex), L"--volume", Wide(volume.uuid_hex),
        L"--oid", std::to_wstring(volume.object_id), L"--xid", std::to_wstring(cp.container.superblock.xid)};
    std::shared_ptr<VolumePhysicalSource> source;
    unsigned calls = 0, currents = 0, reads = 0;
    const auto factory = [&](auto selected, auto instance, auto base, auto limit, const auto& q, auto&) {
        ++calls;
        Check(selected == L"\\\\.\\PhysicalDrive42" && instance == Instance && base == Base && limit == Window &&
            q.kind == f.file->binding.hardware.kind && q.bus_type == 7 && q.vendor == "Fictional" &&
            q.product == "Topology Surrogate" && q.qualified_serial == "TOPOLOGYTEST42", "observer exact factory envelope");
        return source;
    };
    const auto Bind = [&](std::function<bool()> current = {}, std::function<bool()> read = {}) {
        currents = reads = 0;
        source = VolumePhysicalKeeperTestPeer::Bind(f.file,
            [&, current] { ++currents; return !current || current(); },
            [&, read] { ++reads; return !read || read(); });
    };
    const auto Refused = [&](const auto& frame, const char* error) {
        Check(frame.first == 1 && frame.second.find("\"outcome\":\"refused\"") != std::string::npos &&
            frame.second.find("\"bindingHex\":\"\"") != std::string::npos &&
            frame.second.find("\"volumes\":[]") != std::string::npos &&
            frame.second.find(error) != std::string::npos, std::string("observer refusal clears authority: ") + frame.second);
    };
    Bind(); std::string metadata_error;
    Check(!VolumePhysicalSource::RetainMetadataDevice(source, source->Binding(), Instance, metadata_error) &&
        metadata_error == "VolumePhysicalMetadataDeviceUnavailable", "legitimate virtual factory has no metadata device");
    const auto complete = InvokeObserver(args, factory);
    Check(complete.first == 0 && complete.second.find("\"outcome\":\"complete\",\"error\":\"\"") != std::string::npos &&
        complete.second.find(cp.volumes[0].superblock.uuid_hex) != std::string::npos &&
        complete.second.find(cp.volumes[1].superblock.uuid_hex) != std::string::npos, "uncached factory retains complete two-peer observation: " + complete.second);
    Check(reads > 0 && currents == 2 * reads + 2, "fallback checks every original read before/after and full start/end");
    const auto complete_currents = currents;
    Bind(); Check(InvokeObserver(args, factory) == complete, "fresh virtual owner produces exact same complete frame");
    Bind([&] { return currents < complete_currents; });
    Refused(InvokeObserver(args, factory), "VolumePhysicalObservationHeldSourceChanged");
    Check(currents == complete_currents && reads > 0, "final full validation still refuses after successful parse/verify");
    Bind({}, [] { return false; });
    Refused(InvokeObserver(args, factory), "VolumePhysicalObservationCanonicalScopeMismatch:");
    Check(reads == 1, "failed original read stops uncached parser without retry or cache");
    Bind({}, [&] { f.file->available = false; return true; });
    Refused(InvokeObserver(args, factory), "VolumePhysicalObservationCanonicalScopeMismatch:");
    f.file->available = true;
    Check(!source->Revalidate(), "original source retirement remains sticky after external availability returns");
    Bind(); auto wrong_args = args;
    *std::next(std::find(wrong_args.begin(), wrong_args.end(), L"--base")) = std::to_wstring(Base + 4096);
    const auto unchecked_factory = [&](auto, auto, auto, auto, const auto&, auto&) { return source; };
    Refused(InvokeObserver(wrong_args, unchecked_factory), "VolumePhysicalObservationFactoryAuthorityMismatch");
    Check(!currents && !reads, "wrong binding refuses before reading factory source");
    Bind(); auto wrong_xid = args;
    *std::next(std::find(wrong_xid.begin(), wrong_xid.end(), L"--xid")) = std::to_wstring(cp.container.superblock.xid + 1);
    Refused(InvokeObserver(wrong_xid, factory), "VolumePhysicalObservationCanonicalScopeMismatch:");
    Check(InvokeObserver(wrong_xid, factory).second.find(metadata_error) == std::string::npos,
        "optional metadata lookup error never replaces canonical parser error");
    Check(calls >= 7 && f.Image() == before && !f.file->writes && !f.file->escaped && f.file->Current(),
        "observer success/refusals preserve complete original image and unrelated-range sentinels");
    ++groups;
}
void ToolRoute(const std::filesystem::path& root) {
    Fixture f(root); unsigned calls = 0;
    const auto factory = [&](const auto& binding, auto instance, auto selected, auto&) {
        ++calls; Check(binding == f.source->Binding() && instance == Instance, "tool exact typed factory envelope");
        Check(selected.empty() || selected == L"\\\\.\\PhysicalDrive42", "explicit selection only before accept"); return f.source;
    };
    const auto encoded = volume_physical::Encode(f.file->binding, Instance); const wchar_t* digits = L"0123456789abcdef";
    std::wstring hex; for (const auto b : encoded) { const auto n = std::to_integer<unsigned>(b); hex += digits[n >> 4]; hex += digits[n & 15]; }
    const auto& r = f.request;
    std::vector<std::wstring> common = {L"tool", L"--operation", L"create", L"--image", r.image.wstring(), L"--offset", std::to_wstring(Base),
        L"--journal-directory", r.journal_directory.wstring(), L"--container", std::wstring(r.container_uuid.begin(), r.container_uuid.end()),
        L"--volume", std::wstring(r.volume_uuid.begin(), r.volume_uuid.end()), L"--oid", std::to_wstring(r.volume_oid), L"--xid", std::to_wstring(r.checkpoint_xid),
        L"--name", L"Created Data", L"--quota-blocks", L"64", L"--reserve-blocks", L"16", L"--case-sensitive", L"false",
        L"--history-spool-root", r.history_context.spool_root.wstring(), L"--history-recovery-root", r.history_context.recovery_root.wstring(),
        L"--source-kind", L"physical", L"--physical-binding-hex", hex};
    for (const auto& [oid, wal] : r.sibling_wals) { common.push_back(L"--wal"); common.push_back(std::to_wstring(oid) + L"=" + wal.wstring()); }
    auto args = common; args.insert(args.end(), {L"--mode", L"dry-run", L"--physical-device", L"\\\\.\\PhysicalDrive42"});
    const auto prepared = InvokeTool(args, factory);
    Check(prepared.first == 0 && !f.file->writes && calls == 1, "public native dry-run dispatch: " + prepared.second);
    constexpr std::string_view key = "\"confirmationToken\":\"";
    const auto start = prepared.second.find(key); Check(start != std::string::npos, "native confirmation output");
    const auto token = prepared.second.substr(start + key.size(), 64);
    Check(token.size() == 64 && token.find_first_not_of("0123456789abcdef") == std::string::npos, "exact confirmation token");
    args = common; args.insert(args.end(), {L"--mode", L"apply", L"--physical-device", L"\\\\.\\PhysicalDrive42", L"--confirm", std::wstring(token.begin(), token.end())});
    const auto done = InvokeTool(args, factory); Check(done.first == 0 && calls == 2 && f.Checkpoint().volumes.size() == 3, "public native apply: " + done.second);
    args = common; args.insert(args.end(), {L"--mode", L"recover"});
    Check(InvokeTool(args, factory).first == 0 && calls == 3, "public recovery rebinds original typed instance without disk-number authority");
    args.insert(args.end(), {L"--physical-device", L"\\\\.\\PhysicalDrive42"});
    Check(InvokeTool(args, factory).first == 2 && calls == 3, "recovery rejects selected-device argument before factory");
    f.Payloads(); Check(f.file->Current() && !f.file->escaped, "tool whole held authority and neighbor preservation"); ++groups;
}
std::vector<AppleCheckpointPhysicalWrite> AddPayload(const std::shared_ptr<VolumePhysicalSource>& source,
    std::uint64_t oid, std::byte pattern) {
    std::string error; auto cp = LoadAppleCheckpointView(*source, 0, source->SizeBytes(), error); Check(cp.has_value(), error);
    const auto volume = std::find_if(cp->volumes.begin(), cp->volumes.end(), [&](const auto& v) { return v.superblock.object_id == oid; });
    Check(volume != cp->volumes.end(), "ordinary payload exact current peer");
    AppleVolumeTransactionRequest request; request.volume_object_id = oid;
    Check(ReadAppleVolumeFileSystemRecords(*source, cp->container, *volume, request.filesystem_records, error), error);
    const auto id = (std::max<std::uint64_t>)(volume->superblock.next_object_id, 1030);
    AppleInodeRecord inode; inode.object_id = inode.private_id = id; inode.parent_id = 2; inode.mode = 0100644;
    inode.children_or_links = 1; inode.uncompressed_size = 8192;
    AppleExtendedField stream{8, 0, Bytes(40)}; apfsaccess::testfixture::PutU64LE(stream.data, 0, 8192); apfsaccess::testfixture::PutU64LE(stream.data, 8, 8192);
    inode.extended_fields.push_back(stream); BtreeRecord record;
    Check(EncodeAppleInodeRecord(inode, record, error), error); request.filesystem_records.push_back(record);
    AppleDirectoryRecord name{2, id, 0, 8, "peer-payload.bin"};
    Check(EncodeAppleDirectoryRecord(name, ApfsNamePolicy::FromIncompatibleFeatures(volume->superblock.incompatible_features), record, error), error);
    request.filesystem_records.push_back(record); unsigned roots = 0;
    for (auto& item : request.filesystem_records) {
        AppleInodeRecord root_inode;
        if (!ApfsExtendedRecordCodec::DecodeInode(item, root_inode, error) || root_inode.object_id != 2) continue;
        ++root_inode.children_or_links; Check(EncodeAppleInodeRecord(root_inode, item, error), error); ++roots;
    }
    Check(roots == 1, "one canonical peer root");
    Check(EncodeAppleDataStreamIdRecord({id, 1}, record, error), error); request.filesystem_records.push_back(record);
    request.file_count_delta = 1; request.data_writes.push_back({id, 0, 0, Bytes(8192, pattern)});
    AppleVolumeTransactionPlan plan;
    Check(PlanAppleVolumeTransaction(*source, *cp, request, plan, error), "ordinary peer payload plan: " + error);
    Check(ExecuteAppleCheckpointPublication(*source, plan.commit.publication, error), error);
    std::vector<AppleCheckpointPhysicalWrite> payload;
    for (const auto block : plan.payload_blocks) payload.push_back({block, Bytes(4096, pattern)});
    Check(payload.size() == 2, "two complete peer payload blocks"); return payload;
}
Bytes InstallGpt(const std::shared_ptr<Carrier>& file) {
    namespace vg = volume_geometry; using apfsaccess::testfixture::PutU64LE; using apfsaccess::testfixture::PutU32LE;
    const auto guid = [](Bytes& bytes, std::size_t at, const std::array<std::byte, 16>& id) {
        constexpr unsigned order[] = {3,2,1,0,5,4,7,6,8,9,10,11,12,13,14,15};
        for (unsigned i = 0; i < 16; ++i) bytes[at + order[i]] = id[i];
    };
    const auto& media = file->binding.media; const auto last = file->disk / 4096 - 1;
    Bytes array(16384); std::array<std::byte, 16> type{};
    constexpr unsigned apfs[] = {0x7c,0x34,0x57,0xef,0,0,0x11,0xaa,0xaa,0x11,0,0x30,0x65,0x43,0xec,0xac};
    for (unsigned i = 0; i < 16; ++i) type[i] = std::byte(apfs[i]); guid(array, 0, type); guid(array, 16, media.partition_guid);
    PutU64LE(array, 32, Base / 4096); PutU64LE(array, 40, (Base + media.partition_length_bytes) / 4096 - 1);
    type.fill(std::byte{0x63}); guid(array, 128, type); type.fill(std::byte{0x64}); guid(array, 144, type);
    const auto neighbor = Base + media.partition_length_bytes + (16u << 20);
    PutU64LE(array, 160, neighbor / 4096); PutU64LE(array, 168, neighbor / 4096 + 7);
    Bytes mbr(4096); mbr[450] = std::byte{0xee}; PutU32LE(mbr, 454, 1); PutU32LE(mbr, 458, static_cast<std::uint32_t>(last));
    mbr[510] = std::byte{0x55}; mbr[511] = std::byte{0xaa};
    const auto header = [&](bool backup) {
        Bytes bytes(4096); PutU64LE(bytes, 0, 0x5452415020494645ull); PutU32LE(bytes, 8, 0x10000); PutU32LE(bytes, 12, 92);
        PutU64LE(bytes, 24, backup ? last : 1); PutU64LE(bytes, 32, backup ? 1 : last); PutU64LE(bytes, 40, 34); PutU64LE(bytes, 48, last - 33);
        guid(bytes, 56, media.disk_guid); PutU64LE(bytes, 72, backup ? last - 4 : 2); PutU32LE(bytes, 80, 128); PutU32LE(bytes, 84, 128);
        PutU32LE(bytes, 88, vg::Crc32(array)); PutU32LE(bytes, 16, vg::Crc32(std::span(bytes).first(92))); return bytes;
    };
    const auto primary = header(false), backup = header(true);
    for (const auto& [at, bytes] : std::vector<std::pair<std::uint64_t, Bytes>>{{0,mbr},{4096,primary},{8192,array},{(last-4)*4096,array},{last*4096,backup}})
        Check(file->WriteAt(at, bytes), "exact primary/backup GPT fixture");
    file->sentinels[0] = mbr; file->sentinels[last * 4096] = backup;
    for (const auto at : {neighbor, neighbor + 7 * 4096}) {
        file->sentinels[at] = Bytes(4096, std::byte{0x73}); Check(file->WriteAt(at, file->sentinels.at(at)), "unaffected partition fixture data");
    }
    Check(FlushFileBuffers(file->h) && file->Current(), "GPT and unrelated partition fixture durable");
    Bytes encoded; for (const auto& bytes : {mbr, primary, array, array, backup}) encoded.insert(encoded.end(), bytes.begin(), bytes.end()); return encoded;
}
void FormatThenCreate(const std::filesystem::path& root) {
    Fixture f(root, true, true); const auto gpt = InstallGpt(f.file); const auto before = f.Checkpoint(); VolumeImageRequest format;
    format.operation = VolumeImageOperation::Format; format.image = Instance; format.journal_directory = f.request.journal_directory;
    format.container_uuid = f.request.container_uuid; format.volume_uuid = before.volumes.front().superblock.uuid_hex;
    format.volume_oid = 101; format.checkpoint_xid = before.container.superblock.xid;
    format.expected_bytes = format.target_bytes = f.file->window; format.sibling_wals = f.request.sibling_wals;
    format.new_container_uuid = "bbbbbbbbbbbb4bbb8bbbbbbbbbbbbbbb"; format.new_volume_uuid = "cccccccccccc4ccc8ccccccccccccccc";
    format.name_utf8 = "Formatted Peer"; format.history_context = f.request.history_context;
    const auto identity = DeriveVolumePhysicalRecoveryIdentity(f.file->binding, format.new_container_uuid, 1024);
    format.new_volume_wal = f.request.history_context.spool_root / ("apfs_recovery_v1_" + identity.substr(17)) / "write-ahead.wal";
    std::filesystem::create_directories(format.new_volume_wal.parent_path());
    const auto p = PrepareVolumePhysicalFormat(f.source, format);
    Check(p.outcome == VolumeImageOutcome::Prepared, "physical Format before peer create: " + p.error);
    const auto formatted = ApplyVolumePhysicalFormat(f.source, format, p.token);
    Check(formatted.outcome == VolumeImageOutcome::Committed, "physical Format commit: " + formatted.error);
    auto cp = f.Checkpoint(); Check(cp.volumes.size() == 1 && cp.container.superblock.uuid_hex == format.new_container_uuid, "one formatted peer");
    auto create = f.request; create.container_uuid = cp.container.superblock.uuid_hex; create.checkpoint_xid = cp.container.superblock.xid;
    create.volume_oid = cp.container.superblock.next_oid; create.sibling_wals = {{1024, format.new_volume_wal}};
    const auto c = PrepareVolumePhysicalCreate(f.source, create);
    Check(c.outcome == VolumeManagementOutcome::Prepared, "create after complete physical Format history: " + c.error);
    const auto done = ApplyVolumePhysicalManagement(f.source, create, c.confirmation_token);
    Check(done.outcome == VolumeManagementOutcome::Committed, "second peer after Format: " + done.error);
    cp = f.Checkpoint(); Check(cp.volumes.size() == 2, "Format plus typed create exposes both peers");
    std::vector<AppleCheckpointPhysicalWrite> payloads;
    for (const auto& v : cp.volumes) {
        auto history = AcquireVolumeKeeperPhysicalHistory(f.source, *f.source, create.journal_directory, {}, {}, {}, {}, create.history_context);
        auto blocks = AddPayload(f.source, v.superblock.object_id, std::byte(v.superblock.object_id & 0xff));
        payloads.insert(payloads.end(), blocks.begin(), blocks.end());
    }
    for (const auto& w : payloads) { Bytes bytes; Check(f.source->Read(w.physical_block * 4096, 4096, bytes) && bytes == w.bytes, "complete sibling payload after independent canonical writes"); }
    Check(RecoverVolumePhysicalManagement(f.source, create).outcome == VolumeManagementOutcome::Committed, "completed topology history survives later ordinary peer writes");
    const auto reopen = RecoverVolumePhysicalFormat(f.source, format);
    Check(reopen.outcome == VolumeImageOutcome::Committed, "completed Format history recognizes typed physical topology and later canonical writes: " + reopen.error);
    {
        auto history = AcquireVolumeKeeperPhysicalHistory(f.source, *f.source, create.journal_directory, {}, {}, {}, {}, create.history_context, true);
        Check(history && f.Checkpoint().volumes.size() == 2 && f.file->Current() && !f.file->escaped, "full mixed family continuation proof");
    }
    const auto original_binding = f.source->Binding(); auto geometry = VolumePhysicalGeometryTestPeer::Bind(f.file, original_binding);
    std::string error; const auto current = LoadAppleCheckpointView(*f.source, 0, f.source->SizeBytes(), error); Check(current.has_value(), error);
    VolumeImageRequest grow; grow.operation = VolumeImageOperation::Grow; grow.image = Instance; grow.journal_directory = create.journal_directory;
    grow.container_uuid = current->container.superblock.uuid_hex; grow.volume_uuid = current->volumes.front().superblock.uuid_hex;
    grow.volume_oid = current->volumes.front().superblock.object_id; grow.checkpoint_xid = current->container.superblock.xid;
    grow.expected_bytes = f.source->SizeBytes(); grow.target_bytes = 1ull << 30; grow.history_context = create.history_context;
    for (const auto& v : current->volumes) {
        const auto id = DeriveVolumePhysicalRecoveryIdentity(original_binding, grow.container_uuid, v.superblock.object_id);
        grow.sibling_wals.emplace(v.superblock.object_id, create.history_context.spool_root / ("apfs_recovery_v1_" + id.substr(17)) / "write-ahead.wal");
    }
    const auto prepared = PrepareVolumePhysicalResize(geometry, grow); Check(prepared.outcome == VolumeImageOutcome::Prepared, "two-peer 1 GiB window grow: " + prepared.error);
    const auto cut = ApplyVolumePhysicalResize(geometry, grow, prepared.token, [](auto stage) { return stage != "after-image-anchor"; });
    Check(cut.outcome == VolumeImageOutcome::RecoveryRequired, "accepted two-peer window cut: " + cut.error);
    geometry = VolumePhysicalGeometryTestPeer::Bind(f.file, original_binding); std::shared_ptr<VolumePhysicalSource> rebound;
    const auto recovered = RecoverVolumePhysicalResize(geometry, grow, {}, &rebound);
    Check(recovered.outcome == VolumeImageOutcome::Committed && rebound && !geometry->Revalidate(), "fresh geometry authority forward recovery: " + recovered.error);
    Check(!f.source->Revalidate() && rebound->SizeBytes() == (1ull << 30) && rebound->Binding().media.partition_length_bytes == (2ull << 30), "old window revoked and prefix grows within unchanged partition");
    const auto after = LoadAppleCheckpointView(*rebound, 0, rebound->SizeBytes(), error);
    Check(after && after->volumes.size() == 2 && after->container.superblock.block_count == (1u << 18), "canonical 1 GiB two-peer checkpoint");
    for (const auto& w : payloads) { Bytes bytes; Check(rebound->Read(w.physical_block * 4096, 4096, bytes) && bytes == w.bytes, "both complete payloads after 1 GiB recovery"); }
    auto history = AcquireVolumeKeeperPhysicalHistory(rebound, *rebound, create.journal_directory, {}, {}, {}, {}, create.history_context, true);
    Check(history && f.file->Current() && !f.file->escaped, "VIF8 plus VMT2 plus Format complete continuation");
    Bytes observed; const auto last = f.file->disk / 4096 - 1;
    for (const auto [at, count] : {std::pair<std::uint64_t, std::size_t>{0,4096},{4096,4096},{8192,16384},{(last-4)*4096,16384},{last*4096,4096}}) {
        Bytes bytes; Check(f.file->Read(at, count, bytes), "GPT readback"); observed.insert(observed.end(), bytes.begin(), bytes.end());
    }
    Check(observed == gpt, "entire primary/backup GPT and both arrays unchanged by prefix window growth"); ++groups;
}
std::array<std::byte, 42> NamespaceMaterial(std::string_view container, std::uint64_t oid,
    const RawSnapshotBinding* binding) {
    std::array<std::byte, 42> bytes{};
    Check(container.size() == 32 && oid, "independent namespace tuple");
    if (binding) {
        bytes[0] = std::byte{1};
        constexpr unsigned order[] = {3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15};
        for (unsigned i = 0; i < 16; ++i) bytes[i + 1] = binding->media.partition_guid[order[i]];
    }
    for (unsigned i = 0; i < 16; ++i) {
        const auto n = std::stoul(std::string(container.substr(i * 2, 2)), nullptr, 16);
        bytes[i + 17] = std::byte(n);
    }
    bytes[33] = std::byte{1};
    for (unsigned i = 0; i < 8; ++i) bytes[i + 34] = std::byte((oid >> (i * 8)) & 255);
    return bytes;
}
std::string NamespaceSuffix(std::span<const std::byte> material) {
    BCRYPT_ALG_HANDLE algorithm{}; std::array<unsigned char, 32> digest{};
    Check(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0, "namespace oracle SHA256");
    const auto status = BCryptHash(algorithm, nullptr, 0,
        reinterpret_cast<PUCHAR>(const_cast<std::byte*>(material.data())), static_cast<ULONG>(material.size()), digest.data(), 32);
    BCryptCloseAlgorithmProvider(algorithm, 0); Check(status >= 0, "namespace oracle hash");
    DWORD size{}; constexpr DWORD flags = CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF;
    Check(CryptBinaryToStringA(digest.data(), 32, flags, nullptr, &size), "namespace oracle encoded size");
    std::string suffix(size, '\0');
    Check(CryptBinaryToStringA(digest.data(), 32, flags, suffix.data(), &size), "namespace oracle encoding");
    while (!suffix.empty() && (suffix.back() == '\0' || suffix.back() == '=')) suffix.pop_back();
    std::replace(suffix.begin(), suffix.end(), '+', '-'); std::replace(suffix.begin(), suffix.end(), '/', '_');
    Check(suffix.size() == 43, "canonical namespace oracle suffix"); return suffix;
}
std::filesystem::path NamespaceWitness(const Fixture& f, std::string_view suffix) {
    return f.request.journal_directory / ("spool-namespace-" + std::string(suffix) + ".vks1");
}
std::string OrdinaryFileId(const std::filesystem::path& path) {
    const auto h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
        OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    Check(h != INVALID_HANDLE_VALUE, "retained namespace file ID");
    try { const auto id = VolumeKeeperWalFileIdentity({path, h}); CloseHandle(h); return id; }
    catch (...) { CloseHandle(h); throw; }
}
struct NamespaceStore {
    std::array<std::byte, 42> material;
    std::string suffix, identity;
    std::filesystem::path directory, wal, marker, witness;
    std::unique_ptr<PayloadSpool> spool;
    std::unique_ptr<TransactionManager> writer;
    std::map<std::filesystem::path, std::pair<Bytes, std::string>> evidence;
    NamespaceStore(Fixture& f, std::string_view container, std::uint64_t oid, const RawSnapshotBinding* binding,
        bool active = false) : material(NamespaceMaterial(container, oid, binding)), suffix(NamespaceSuffix(material)),
        identity("apfs-recovery-v1-" + suffix), directory(f.request.history_context.spool_root / ("apfs_recovery_v1_" + suffix)),
        wal(directory / "write-ahead.wal"), marker(f.request.history_context.recovery_root / ("apfs_recovery_v1_" + suffix + "_Native.state")),
        witness(NamespaceWitness(f, suffix)) {
        const auto derived = binding ? DeriveVolumePhysicalRecoveryIdentity(*binding, container, oid) :
            DerivePartitionlessVolumeRecoveryIdentity(container, oid);
        Check(derived == identity, "independent 42-byte oracle agrees with existing recovery namespace");
        std::filesystem::create_directories(directory);
        if (active) {
            PayloadSpool::Options options; options.root = directory; options.volume_identity = identity;
            spool = std::make_unique<PayloadSpool>(options); const Bytes payload(8193, std::byte{0x7b});
            PayloadSpool::AppendResult appended;
            Check(spool->Append({identity, 400, 7, 0, 1, payload}, &appended) && spool->FlushDirtyState(), "actual foreign persisted payload and index");
            writer = std::make_unique<TransactionManager>(L"Strict"); writer->SetJournalPath(wal.wstring());
            writer->SetVolumeIdentity(std::wstring(identity.begin(), identity.end()));
            TransactionManager::MutationIntent intent; intent.kind = TransactionManager::MutationKind::Write;
            intent.path = L"\\foreign-payload.bin"; intent.object_id = 400; intent.generation = 7;
            intent.length = intent.payload_length = payload.size(); intent.wal_sequence = appended.wal_sequence;
            intent.payload_spool_offset = appended.spool_offset; intent.payload_checksum = appended.payload_sha256;
            Check(writer->Begin() && writer->RecordMutation(intent) && writer->Accept(6), "actual unresolved foreign accepted original");
            Check(writer->Watermarks().accepted_sequence > writer->Watermarks().cleanup_sequence, "foreign original remains pending");
        } else vm::Save(wal, {});
        const std::string text = active ? "dirty=1\nlastCommitXid=6\n" : "dirty=0\nlastCommitXid=6\n";
        vm::Save(marker, Bytes(reinterpret_cast<const std::byte*>(text.data()), reinterpret_cast<const std::byte*>(text.data() + text.size())));
        for (const auto& entry : std::filesystem::directory_iterator(directory)) Capture(entry.path());
        Capture(marker);
    }
    void Capture(const std::filesystem::path& path) {
        auto bytes = vm::Read(path); Check(bytes.size() == std::filesystem::file_size(path), "complete foreign evidence read");
        evidence.emplace(path, std::make_pair(std::move(bytes), OrdinaryFileId(path)));
    }
    void Install() const { vm::Save(witness, Bytes(material.begin(), material.end())); }
    void Unchanged() const {
        for (const auto& [path, original] : evidence)
            Check(vm::Read(path) == original.first && OrdinaryFileId(path) == original.second, "foreign original bytes and file ID unchanged");
    }
};
std::string HistoryError(Fixture& f) {
    try {
        auto history = AcquireVolumeKeeperPhysicalHistory(f.source, *f.source, f.request.journal_directory,
            {}, {}, {}, {}, f.request.history_context);
        return history ? std::string{} : "MissingHistoryLease";
    } catch (const std::exception& ex) { return ex.what(); }
}
void NamespaceForeign(const std::filesystem::path& root) {
    Fixture f(root); const auto before = f.Image();
    NamespaceStore foreign(f, "bb00112233445566778899aabbccddee", 777, &f.file->binding, true);
    Check(HistoryError(f) == "KeeperHistoryUnknownSpoolEvidence", "preimage absence reproduces shared-root refusal");
    foreign.Install(); const auto error = HistoryError(f);
    Check(error.empty(), "foreign spool plus dirty marker excluded only by exact witness: " + error);
    foreign.Unchanged();
    Check(f.Image() == before && !f.file->writes, "foreign classification performs no target writes");
    const auto p = PrepareVolumePhysicalCreate(f.source, f.request);
    Check(p.outcome == VolumeManagementOutcome::Prepared, "public physical prepare with active foreign namespace: " + p.error);
    Check(CancelVolumePhysicalManagement(f.source, f.request, p.confirmation_token).outcome == VolumeManagementOutcome::Cancelled,
        "foreign marker does not block real cancellation");
    foreign.Unchanged(); Check(f.Image() == before && !f.file->writes, "prepare and cancellation preserve exact source"); ++groups;
}
void NamespaceControls(const std::filesystem::path& root) {
    constexpr std::string_view other = "bb00112233445566778899aabbccddee";
    const std::vector<std::string> cases = {"same-container", "partitionless-same-container", "missing", "mode", "version",
        "zero-container", "zero-oid", "partitionless-guid", "physical-zero-guid", "hash", "guid-order", "short", "long", "hardlink"};
    for (const auto& name : cases) {
        Fixture f(root / name); const auto before = f.Image(); auto binding = f.file->binding;
        for (unsigned i = 0; i < 16; ++i) binding.media.partition_guid[i] = std::byte(i + 1);
        const auto container = name == "same-container" || name == "partitionless-same-container" ? f.request.container_uuid : std::string(other);
        const auto* physical = name == "partitionless-same-container" ? nullptr : &binding;
        if (name == "same-container") binding = f.file->binding;
        NamespaceStore unknown(f, container, 777, physical);
        Bytes material(unknown.material.begin(), unknown.material.end());
        if (name == "mode") material[0] = std::byte{2};
        if (name == "version") material[33] = std::byte{2};
        if (name == "zero-container") std::fill(material.begin() + 17, material.begin() + 33, std::byte{});
        if (name == "zero-oid") std::fill(material.begin() + 34, material.end(), std::byte{});
        if (name == "partitionless-guid") material[0] = std::byte{};
        if (name == "physical-zero-guid") std::fill(material.begin() + 1, material.begin() + 17, std::byte{});
        if (name == "hash") material[17] ^= std::byte{1};
        if (name == "guid-order") {
            std::reverse(material.begin() + 1, material.begin() + 5);
            std::reverse(material.begin() + 5, material.begin() + 7); std::reverse(material.begin() + 7, material.begin() + 9);
        }
        if (name == "short") material.pop_back();
        if (name == "long") material.push_back(std::byte{});
        if (name != "missing") vm::Save(unknown.witness, material);
        if (name == "hardlink")
            Check(CreateHardLinkW((f.root / "witness-alias.private").c_str(), unknown.witness.c_str(), nullptr), "private witness hardlink control");
        const auto error = HistoryError(f);
        Check(!error.empty(), "invalid or unproved namespace refuses: " + name);
        unknown.Unchanged(); Check(f.Image() == before && !f.file->writes, "namespace refusal leaves target unchanged: " + name);
        if (name != "missing") Check(vm::Read(unknown.witness) == material, "refusal never rewrites malformed witness: " + name);
    }
    {
        Fixture f(root / "other-partition"); auto binding = f.file->binding; binding.media.partition_guid[0] ^= std::byte{1};
        NamespaceStore foreign(f, f.request.container_uuid, 777, &binding, true); foreign.Install();
        const auto error = HistoryError(f); Check(error.empty(), "genuinely distinct partition is scoped separately: " + error); foreign.Unchanged();
    }
    for (const auto& name : {"foreign", "unknown", "same-container", "malformed"}) {
        Fixture f(root / (std::string("marker-") + name)); const auto before = f.Image();
        const auto container = std::string(name) == "same-container" ? f.request.container_uuid : std::string(other);
        auto material = NamespaceMaterial(container, 777, &f.file->binding); const auto suffix = NamespaceSuffix(material);
        const auto path = f.request.history_context.recovery_root / ("apfs_recovery_v1_" + suffix + "_Native.state");
        const std::string dirty = "dirty=1\nlastCommitXid=6\n";
        const Bytes bytes(reinterpret_cast<const std::byte*>(dirty.data()), reinterpret_cast<const std::byte*>(dirty.data() + dirty.size()));
        vm::Save(path, bytes); const auto id = OrdinaryFileId(path);
        if (std::string(name) == "malformed") material[33] = std::byte{2};
        if (std::string(name) != "unknown") vm::Save(NamespaceWitness(f, suffix), Bytes(material.begin(), material.end()));
        const auto error = HistoryError(f);
        Check(std::string(name) == "foreign" ? error.empty() : !error.empty(), "independent marker-only classification: " + std::string(name) + ": " + error);
        Check(vm::Read(path) == bytes && OrdinaryFileId(path) == id && f.Image() == before && !f.file->writes,
            "marker-only admission or refusal preserves source and exact marker");
    }
    for (const auto& name : {"empty", "nonempty-bin", "nonempty-index", "unindexed", "unexpected", "hardlink"}) {
        Fixture f(root / (std::string("selected-") + name)); const auto before = f.Image(); const auto directory = f.Wal(101).parent_path();
        auto path = directory / (std::string(name) == "unexpected" ? "payload-spool.bin.tmp" : "payload-spool.bin");
        vm::Save(path, std::string(name) == "nonempty-bin" || std::string(name) == "unindexed" ? Bytes(8193, std::byte{0x61}) : Bytes{});
        if (std::string(name) != "unindexed") vm::Save(directory / "payload-spool.idx", std::string(name) == "nonempty-index" ? Bytes(1, std::byte{1}) : Bytes{});
        if (std::string(name) == "hardlink")
            Check(CreateHardLinkW((f.root / "payload-alias.private").c_str(), path.c_str(), nullptr), "private payload hardlink control");
        const auto original = vm::Read(path); const auto error = HistoryError(f);
        Check(std::string(name) == "empty" ? error.empty() : !error.empty(), "selected payload exact zero-only policy: " + std::string(name) + ": " + error);
        Check(vm::Read(path) == original && f.Image() == before && !f.file->writes, "selected payload classification never repairs evidence");
    }
    {
        Fixture f(root / "witness-publication"); const auto before = f.Image();
        const auto material = NamespaceMaterial(f.request.container_uuid, 101, &f.file->binding);
        const auto witness = NamespaceWitness(f, NamespaceSuffix(material));
        auto p = PrepareVolumePhysicalCreate(f.source, f.request); Check(p.outcome == VolumeManagementOutcome::Prepared, p.error);
        Check(vm::Read(witness) == Bytes(material.begin(), material.end()), "native admission publishes exact independently encoded witness");
        const auto id = OrdinaryFileId(witness);
        Check(CancelVolumePhysicalManagement(f.source, f.request, p.confirmation_token).outcome == VolumeManagementOutcome::Cancelled, "witness setup cancellation");
        p = PrepareVolumePhysicalCreate(f.source, f.request); Check(p.outcome == VolumeManagementOutcome::Prepared, "idempotent witness publication: " + p.error);
        Check(OrdinaryFileId(witness) == id && vm::Read(witness) == Bytes(material.begin(), material.end()), "idempotent witness publication preserves immutable file ID and bytes");
        Check(CancelVolumePhysicalManagement(f.source, f.request, p.confirmation_token).outcome == VolumeManagementOutcome::Cancelled, "second witness setup cancellation");
        Bytes changed(material.begin(), material.end()); changed[17] ^= std::byte{1}; vm::Save(witness, changed);
        const auto refused = PrepareVolumePhysicalCreate(f.source, f.request);
        Check(refused.outcome == VolumeManagementOutcome::Refused && vm::Read(witness) == changed && OrdinaryFileId(witness) == id,
            "native admission refuses conflicting witness without replacement: " + refused.error);
        Check(f.Image() == before && !f.file->writes, "witness publication and conflict never change target");
    }
    ++groups;
}
void MarkerText(const std::filesystem::path& path, const std::string& text) {
    vm::Save(path, Bytes(reinterpret_cast<const std::byte*>(text.data()), reinterpret_cast<const std::byte*>(text.data() + text.size())));
}
std::filesystem::path PhysicalMarker(const Fixture& f, std::string_view container, std::uint64_t oid) {
    const auto suffix = DeriveVolumePhysicalRecoveryIdentity(f.file->binding, container, oid).substr(17);
    return f.request.history_context.recovery_root / ("apfs_recovery_v1_" + suffix + "_Native.state");
}
void CanonicalMarkers(Fixture& f) {
    const auto cp = f.Checkpoint();
    for (const auto& volume : cp.volumes)
        MarkerText(PhysicalMarker(f, cp.container.superblock.uuid_hex, volume.superblock.object_id),
            "dirty=0\nlastCommitXid=" + std::to_string(cp.container.superblock.xid) + "\n");
}
std::filesystem::path LegacyMarker(Fixture& f) {
    const auto path = f.request.history_context.recovery_root / "__._PhysicalDrive42_Previous Data_Native.state";
    MarkerText(path, "dirty=0\nlastCommitXid=48810\n"); return path;
}
void LegacyMarkerControls(const std::filesystem::path& root) {
    {
        Fixture f(root / "positive"); CanonicalMarkers(f); const auto legacy = LegacyMarker(f);
        const auto bytes = vm::Read(legacy); const auto id = OrdinaryFileId(legacy); const auto before = f.Image();
        const auto cp = f.Checkpoint(); Check(cp.container.superblock.xid < 48810, "legacy XID is genuinely ahead of selected checkpoint");
        {
            auto history = AcquireVolumeKeeperPhysicalHistory(f.source, *f.source, f.request.journal_directory, {}, {}, {}, {}, f.request.history_context);
            Check(history && history->CheckpointXid() == cp.container.superblock.xid && history->Members().size() == 2,
                "clean legacy terminal adds no member and cannot advance selected XID");
            const auto write = CreateFileW(legacy.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
            const auto error = GetLastError(); if (write != INVALID_HANDLE_VALUE) CloseHandle(write);
            Check(write == INVALID_HANDLE_VALUE && error == ERROR_SHARING_VIOLATION, "legacy terminal is retained under an actual read fence");
        }
        Check(vm::Read(legacy) == bytes && OrdinaryFileId(legacy) == id && f.Image() == before && !f.file->writes,
            "legacy XID is ignored without changing marker or selected source");
    }
    const std::vector<std::pair<std::string, std::string>> bodies = {
        {"dirty", "dirty=1\nlastCommitXid=48810\n"}, {"zero", "dirty=0\nlastCommitXid=0\n"},
        {"leading-zero", "dirty=0\nlastCommitXid=048810\n"}, {"signed", "dirty=0\nlastCommitXid=+48810\n"},
        {"crlf", "dirty=0\r\nlastCommitXid=48810\r\n"}, {"missing-lf", "dirty=0\nlastCommitXid=48810"},
        {"overflow", "dirty=0\nlastCommitXid=18446744073709551616\n"}, {"trailing", "dirty=0\nlastCommitXid=48810\nextra\n"}
    };
    for (const auto& [name, text] : bodies) {
        Fixture f(root / name); CanonicalMarkers(f); const auto legacy = LegacyMarker(f); MarkerText(legacy, text);
        const auto before = f.Image(); const auto bytes = vm::Read(legacy);
        Check(!HistoryError(f).empty(), "malformed legacy terminal refuses: " + name);
        Check(vm::Read(legacy) == bytes && f.Image() == before && !f.file->writes, "legacy refusal does not sanitize marker: " + name);
    }
    for (const auto& name : {"unknown_Native.state", "__._PhysicalDrive_Previous_Native.state", "__._PhysicalDrive042_Previous_Native.state",
        "__._PhysicalDrive123456789_Previous_Native.state", "__._PhysicalDrive42__Native.state", "__._PhysicalDrive42_Previous.state"}) {
        Fixture f(root / name); CanonicalMarkers(f); const auto path = f.request.history_context.recovery_root / name;
        MarkerText(path, "dirty=0\nlastCommitXid=48810\n"); const auto before = f.Image(); const auto bytes = vm::Read(path);
        Check(!HistoryError(f).empty(), "unknown or nonsanitizer legacy name refuses: " + std::string(name));
        Check(vm::Read(path) == bytes && f.Image() == before && !f.file->writes, "unknown marker name remains untouched");
    }
    {
        Fixture f(root / "missing-required"); CanonicalMarkers(f); const auto legacy = LegacyMarker(f);
        const auto path = PhysicalMarker(f, f.request.container_uuid, 101);
        std::filesystem::rename(path, f.root / "retained-canonical-101.private"); const auto before = f.Image();
        Check(HistoryError(f) == "KeeperHistoryCurrentMarkerMissingWithLegacyTerminal", "legacy cannot replace an ordinary missing canonical marker");
        Check(!std::filesystem::exists(path) && vm::Read(legacy).size() == 28 && f.Image() == before && !f.file->writes,
            "missing original marker is not synthesized from legacy XID");
    }
    for (const bool dirty_canonical : {false, true}) {
        Fixture f(root / (dirty_canonical ? "cancel-dirty" : "cancel-debt")); CanonicalMarkers(f);
        const auto prepared = PrepareVolumePhysicalCreate(f.source, f.request); Check(prepared.outcome == VolumeManagementOutcome::Prepared, prepared.error);
        const auto legacy = LegacyMarker(f); const auto wal = f.Wal(101);
        {
            TransactionManager tx(L"Strict"); tx.SetJournalPath(wal.wstring());
            const auto identity = DeriveVolumePhysicalRecoveryIdentity(f.file->binding, f.request.container_uuid, 101);
            tx.SetVolumeIdentity(std::wstring(identity.begin(), identity.end()));
            TransactionManager::MutationIntent intent; intent.kind = TransactionManager::MutationKind::CreateFile;
            intent.path = L"\\still-pending"; intent.object_id = 400; intent.generation = f.request.checkpoint_xid + 1;
            Check(tx.Begin() && tx.RecordMutation(intent) && tx.Accept(f.request.checkpoint_xid), "genuine pending original retained across cancellation");
        }
        if (dirty_canonical) MarkerText(PhysicalMarker(f, f.request.container_uuid, 101),
            "dirty=1\nlastCommitXid=" + std::to_string(f.request.checkpoint_xid) + "\n");
        const auto before = f.Image(); const auto original = vm::Read(wal); const auto frame = vm::Read(prepared.journal_path);
        std::map<std::filesystem::path, Bytes> markers;
        for (const auto& entry : std::filesystem::directory_iterator(f.request.history_context.recovery_root)) markers.emplace(entry.path(), vm::Read(entry.path()));
        const auto result = CancelVolumePhysicalManagement(f.source, f.request, prepared.confirmation_token);
        Check(result.outcome == (dirty_canonical ? VolumeManagementOutcome::Refused : VolumeManagementOutcome::Cancelled),
            "cancellation fence retains original debt and still checks canonical marker: " + result.error);
        Check(vm::Read(wal) == original && f.Image() == before && !f.file->writes, "cancellation cannot publish, clean or rewrite original debt");
        for (const auto& [path, bytes] : markers) Check(vm::Read(path) == bytes, "cancellation preserves every canonical and legacy marker byte");
        const auto after = vm::Read(prepared.journal_path);
        Check(dirty_canonical ? after == frame : after.size() == frame.size() + 40 && std::equal(frame.begin(), frame.end(), after.begin()),
            "cancellation either retains prepared original or appends only its true terminal receipt");
        const auto identity = DeriveVolumePhysicalRecoveryIdentity(f.file->binding, f.request.container_uuid, 101);
        std::vector<TransactionManager::AcceptedTransaction> debt; TransactionManager::DurabilityWatermarks marks; std::string error;
        Check(TransactionManager::InspectAcceptedTransactionsReadOnly(wal, identity, debt, marks, error) && debt.size() == 1 &&
            marks.accepted_sequence > marks.apfs_durable_sequence && marks.cleanup_sequence == 0, "cancelled management intent does not settle pending ordinary original");
        Check(!HistoryError(f).empty() && vm::Read(legacy) == markers.at(legacy), "legacy exception never turns pending WAL into publication authority");
    }
    ++groups;
}
VolumeManagementRequest NextPhysicalCreate(Fixture& f, std::string uuid) {
    const auto cp = f.Checkpoint(); auto request = f.request; request.container_uuid = cp.container.superblock.uuid_hex;
    request.checkpoint_xid = cp.container.superblock.xid; request.volume_oid = cp.container.superblock.next_oid;
    request.volume_uuid = std::move(uuid); request.sibling_wals.clear();
    for (const auto& volume : cp.volumes) request.sibling_wals.emplace(volume.superblock.object_id, f.Wal(volume.superblock.object_id));
    return request;
}
std::filesystem::path OriginalProof(const std::filesystem::path& journal, std::string_view identity) {
    const auto binding = DecodeVolumeKeeperHistoryBinding(vm::Read(journal), journal, journal.parent_path(), identity);
    return journal.parent_path() / ("wal-history-" + binding.frame_digest + ".vkh1");
}
Bytes ArchiveBytes(const std::filesystem::path& path) {
    auto native = std::filesystem::absolute(path); native.make_preferred();
    auto text = native.wstring();
    if (text.rfind(L"\\\\?\\", 0) != 0) text = L"\\\\?\\" + text;
    std::ifstream input(std::filesystem::path(text), std::ios::binary | std::ios::ate);
    Check(input.is_open(), "archived frame opens through normalized extended path");
    const auto size = input.tellg(); Check(size >= 0, "archived frame length available");
    Bytes bytes(static_cast<std::size_t>(size)); input.seekg(0);
    if (!bytes.empty()) input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    Check(input.good(), "complete archived frame read"); return bytes;
}
void AdvanceQueueObjectId(Fixture& f) {
    const auto cp = f.Checkpoint(); constexpr std::size_t queue = 1;
    const auto old_oid = cp.spaceman.free_queues[queue].tree_oid;
    const auto new_oid = cp.container.superblock.next_oid;
    Check(old_oid && new_oid && old_oid != new_oid, "existing canonical queue root and fresh container OID");
    AppleCheckpointPublicationRequest request; request.expected_checkpoint_xid = cp.container.superblock.xid;
    request.transaction_xid = cp.container.superblock.next_xid; request.next_object_id = new_oid + 1;
    request.retired_ephemeral_object_ids.push_back(old_oid);
    for (const auto& mapping : cp.container.mappings) {
        AppleCheckpointEphemeralObject object; object.file_system_oid = mapping.file_system_oid;
        object.object = {mapping.object_id, request.transaction_xid, 0, mapping.type, mapping.subtype, mapping.size_bytes};
        Check(f.source->Read(mapping.physical_block * 4096, mapping.size_bytes, object.bytes), "complete canonical queue COW object");
        if (mapping.object_id == old_oid) { object.object.object_id = new_oid; apfsaccess::testfixture::PutU64LE(object.bytes, 8, new_oid); }
        if (mapping.object_id == cp.container.superblock.spaceman_oid)
            apfsaccess::testfixture::PutU64LE(object.bytes, 0xc8 + queue * 0x28 + 8, new_oid);
        apfsaccess::testfixture::PutU64LE(object.bytes, 0x10, request.transaction_xid);
        apfsaccess::testfixture::FletcherForBlock(object.bytes, 4096); request.ephemeral_objects.push_back(std::move(object));
    }
    AppleCheckpointPublicationPlan plan; std::string error;
    Check(PlanAppleCheckpointPublication(*f.source, cp.container, request, plan, error), "canonical queue-root OID allocation: " + error);
    Check(ExecuteAppleCheckpointPublication(*f.source, plan, error), "canonical queue-root COW publication: " + error);
    const auto after = f.Checkpoint(); Check(volume_management::VerifyTopology(*f.source, after, error), "complete topology after queue-root COW: " + error);
    Check(after.spaceman.free_queues[queue].tree_oid == new_oid && after.container.superblock.next_oid == new_oid + 1,
        "fresh container OID consumed by a real queue object with updated spaceman pointer");
}
void ReservationControls(const std::filesystem::path& root) {
    for (const auto& name : {"positive", "nonempty", "replaced", "missing-proof", "changed-proof", "busy"}) {
        Fixture f(root / name); const auto p = PrepareVolumePhysicalCreate(f.source, f.request);
        Check(p.outcome == VolumeManagementOutcome::Prepared, "reservation prepare: " + p.error);
        const auto proof = OriginalProof(p.journal_path, p.source_identity); Check(std::filesystem::exists(proof), "successful prepare retains original certificate");
        const auto reserved = f.Wal(f.request.volume_oid); const auto file_id = OrdinaryFileId(reserved);
        Check(CancelVolumePhysicalManagement(f.source, f.request, p.confirmation_token).outcome == VolumeManagementOutcome::Cancelled,
            "genuine cancelled original reservation");
        const auto cancelled = vm::Read(p.journal_path); const auto certificate = vm::Read(proof);
        const auto payloads = AddPayload(f.source, 101, std::byte{0x79});
        AdvanceQueueObjectId(f);
        auto next = NextPhysicalCreate(f, "223456781234423482341234567890ab");
        Check(next.volume_oid > f.request.volume_oid && next.checkpoint_xid > f.request.checkpoint_xid,
            "ordinary create/write and genuine queue-root COW advance checkpoint and next OID past reserved destination");
        const auto before = f.Image(); const auto writes = f.file->writes;
        std::unique_ptr<WriteAheadLog> busy;
        if (std::string(name) == "nonempty") vm::Save(reserved, Bytes(1, std::byte{0x42}));
        if (std::string(name) == "replaced") { std::filesystem::rename(reserved, f.root / "reserved-original.wal"); vm::Save(reserved, {});
            Check(OrdinaryFileId(reserved) != file_id, "zero-byte replacement has a distinct actual file ID"); }
        if (std::string(name) == "missing-proof") std::filesystem::rename(proof, f.root / "withheld-original-proof.private");
        if (std::string(name) == "changed-proof") { auto bytes = certificate; bytes.back() ^= std::byte{1}; vm::Save(proof, bytes); }
        if (std::string(name) == "busy") {
            const auto id = DeriveVolumePhysicalRecoveryIdentity(f.file->binding, f.request.container_uuid, f.request.volume_oid);
            busy = std::make_unique<WriteAheadLog>(WriteAheadLog::Options{reserved, id}); Check(busy->AcquireWriterLeaseOnly(), "reserved original writer exclusion control");
        }
        const auto result = PrepareVolumePhysicalCreate(f.source, next);
        Check(std::string(name) == "positive" ? result.outcome == VolumeManagementOutcome::Prepared : result.outcome == VolumeManagementOutcome::Refused,
            "cancelled reservation disposition: " + std::string(name) + ": " + result.error);
        if (std::string(name) == "positive") {
            Check(CancelVolumePhysicalManagement(f.source, next, result.confirmation_token).outcome == VolumeManagementOutcome::Cancelled,
                "later prepare cancellation retains prior unused reservation");
            Check(OrdinaryFileId(reserved) == file_id && std::filesystem::file_size(reserved) == 0 && vm::Read(proof) == certificate,
                "unused original reservation identity and certificate unchanged");
        }
        bool retained = false;
        for (const auto& entry : std::filesystem::directory_iterator(f.root))
            if (entry.path().filename().wstring().starts_with(p.journal_path.filename().wstring())) retained |= ArchiveBytes(entry.path()) == cancelled;
        Check(retained, "exact cancelled original frame is retained through native archival");
        Check(f.Image() == before && f.file->writes == writes, "later prepare/refusal writes no target");
        for (const auto& block : payloads) { Bytes bytes; Check(f.source->Read(block.physical_block * 4096, 4096, bytes) && bytes == block.bytes,
            "intervening complete ordinary payload preserved"); }
    }
    ++groups;
}
VolumeImageRequest PhysicalFormatRequest(Fixture& f);
void RefusedPrepareLifecycle(const std::filesystem::path& root) {
    for (const bool format : {false, true}) {
        Fixture f(root / (format ? "format" : "create"), true, format); const auto before = f.Image();
        NamespaceStore foreign(f, "bb00112233445566778899aabbccddee", 777, &f.file->binding, true);
        if (format) {
            auto request = PhysicalFormatRequest(f); const auto refused = PrepareVolumePhysicalFormat(f.source, request);
            Check(refused.outcome == VolumeImageOutcome::Refused && refused.error == "KeeperHistoryUnknownSpoolEvidence", "actual Format post-frame history refusal");
            const auto frame = vm::Read(refused.journal); const auto binding = DecodeVolumeKeeperHistoryBinding(frame, refused.journal, request.journal_directory, refused.source_identity);
            Check(binding.state == VolumeKeeperJournalState::Cancelled, "refused Format has a genuine native cancellation receipt");
            Check(std::filesystem::exists(OriginalProof(refused.journal, refused.source_identity)), "refused Format retains exact original reservation certificate");
            const auto destination_id = OrdinaryFileId(request.new_volume_wal); foreign.Install();
            const auto prepared = PrepareVolumePhysicalFormat(f.source, request);
            Check(prepared.outcome == VolumeImageOutcome::Prepared, "witnessed Format prepare after actual refusal: " + prepared.error);
            Check(CancelVolumePhysicalFormat(f.source, request, prepared.token).outcome == VolumeImageOutcome::Cancelled, "later Format true cancellation");
            Check(OrdinaryFileId(request.new_volume_wal) == destination_id && std::filesystem::file_size(request.new_volume_wal) == 0,
                "refused Format destination is retained without reset");
            bool retained = false;
            for (const auto& entry : std::filesystem::directory_iterator(f.root))
                if (entry.path().filename().wstring().starts_with(refused.journal.filename().wstring())) retained |= ArchiveBytes(entry.path()) == frame;
            Check(retained, "refused Format original and genuine cancellation retained");
        } else {
            const auto refused = PrepareVolumePhysicalCreate(f.source, f.request);
            Check(refused.outcome == VolumeManagementOutcome::Refused && refused.error == "KeeperHistoryUnknownSpoolEvidence", "actual Create post-frame history refusal");
            const auto frame = vm::Read(refused.journal_path); const auto binding = DecodeVolumeKeeperHistoryBinding(frame, refused.journal_path, f.request.journal_directory, refused.source_identity);
            Check(binding.state == VolumeKeeperJournalState::Cancelled, "refused Create has a genuine native cancellation receipt");
            Check(std::filesystem::exists(OriginalProof(refused.journal_path, refused.source_identity)), "refused Create retains exact original reservation certificate");
            const auto destination = f.Wal(f.request.volume_oid); const auto destination_id = OrdinaryFileId(destination); foreign.Install();
            const auto prepared = PrepareVolumePhysicalCreate(f.source, f.request);
            Check(prepared.outcome == VolumeManagementOutcome::Prepared, "witnessed Create prepare after actual refusal: " + prepared.error);
            Check(CancelVolumePhysicalManagement(f.source, f.request, prepared.confirmation_token).outcome == VolumeManagementOutcome::Cancelled, "later Create true cancellation");
            Check(OrdinaryFileId(destination) == destination_id && std::filesystem::file_size(destination) == 0, "refused Create destination retained without reset");
            bool retained = false;
            for (const auto& entry : std::filesystem::directory_iterator(f.root))
                if (entry.path().filename().wstring().starts_with(refused.journal_path.filename().wstring())) retained |= ArchiveBytes(entry.path()) == frame;
            Check(retained, "refused Create original and genuine cancellation retained");
        }
        foreign.Unchanged(); Check(f.Image() == before && !f.file->writes && f.file->Current(), "refusal lifecycle and later prepare write no target");
    }
    ++groups;
}
VolumeImageRequest PhysicalFormatRequest(Fixture& f) {
    const auto cp = f.Checkpoint(); VolumeImageRequest request; request.operation = VolumeImageOperation::Format;
    request.image = Instance; request.journal_directory = f.request.journal_directory; request.container_uuid = cp.container.superblock.uuid_hex;
    request.volume_uuid = cp.volumes.front().superblock.uuid_hex; request.volume_oid = cp.volumes.front().superblock.object_id;
    request.checkpoint_xid = cp.container.superblock.xid; request.expected_bytes = request.target_bytes = f.file->window;
    request.sibling_wals = f.request.sibling_wals; request.history_context = f.request.history_context;
    request.new_container_uuid = "bbbbbbbbbbbb4bbb8bbbbbbbbbbbbbbb"; request.new_volume_uuid = "cccccccccccc4ccc8ccccccccccccccc";
    request.name_utf8 = "Namespace Format"; const auto id = DeriveVolumePhysicalRecoveryIdentity(f.file->binding, request.new_container_uuid, 1024);
    request.new_volume_wal = request.history_context.spool_root / ("apfs_recovery_v1_" + id.substr(17)) / "write-ahead.wal";
    std::filesystem::create_directories(request.new_volume_wal.parent_path()); return request;
}
template<class Target>
std::uint64_t PublishTimestampOriginal(const RandomAccessSource& source, Target& target,
    const AppleCheckpointView& cp, std::uint64_t oid, const std::filesystem::path& wal, const std::string& identity) {
    const auto volume = std::find_if(cp.volumes.begin(), cp.volumes.end(),
        [&](const auto& v) { return v.superblock.object_id == oid; });
    Check(volume != cp.volumes.end(), "exact live timestamp volume");
    AppleVolumeTransactionRequest request; request.volume_object_id = oid; std::string error;
    Check(ReadAppleVolumeFileSystemRecords(source, cp.container, *volume, request.filesystem_records, error), error);
    const auto stamp = 1700000000000000000ull + cp.container.superblock.xid * 100;
    unsigned roots = 0;
    for (auto& record : request.filesystem_records) {
        AppleInodeRecord inode;
        if (!ApfsExtendedRecordCodec::DecodeInode(record, inode, error) || inode.object_id != 2) continue;
        inode.modification_time = stamp; Check(EncodeAppleInodeRecord(inode, record, error), error); ++roots;
    }
    Check(roots == 1, "one exact existing root timestamp mutation"); AppleVolumeTransactionPlan plan;
    Check(PlanAppleVolumeTransaction(source, cp, request, plan, error), error);
    TransactionManager writer(L"Strict"); writer.SetJournalPath(wal.wstring());
    writer.SetVolumeIdentity(std::wstring(identity.begin(), identity.end()));
    TransactionManager::MutationIntent intent; intent.kind = TransactionManager::MutationKind::SetInodeMetadata;
    intent.path = L"\\"; intent.object_id = 2; intent.generation = plan.commit.publication.transaction_xid;
    InodeMetadataPatch patch; patch.mask = InodeMetadataPatch::ModificationTime;
    patch.modification_time_utc = InodeMetadataPatch::UnixEpochTicks + stamp / 100;
    Check(EncodeInodeMetadataPatch(patch, intent.inline_payload), "typed physical timestamp original");
    intent.length = intent.payload_length = intent.inline_payload.size(); BCRYPT_ALG_HANDLE algorithm{};
    Check(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0, "timestamp original SHA256");
    const auto status = BCryptHash(algorithm, nullptr, 0, reinterpret_cast<PUCHAR>(intent.inline_payload.data()),
        static_cast<ULONG>(intent.inline_payload.size()), intent.payload_checksum.data(), static_cast<ULONG>(intent.payload_checksum.size()));
    BCryptCloseAlgorithmProvider(algorithm, 0); Check(status >= 0, "timestamp original checksum");
    Check(writer.Begin() && writer.RecordMutation(intent) && writer.Accept(cp.container.superblock.xid), "durable actual physical original acceptance");
    const auto accepted = writer.Watermarks().accepted_sequence;
    Check(accepted && ExecuteAppleCheckpointPublication(target, plan.commit.publication, error), "actual timestamp publication: " + error);
    Check(writer.MarkApfsDurableThrough(accepted) && writer.MarkCleanedThrough(accepted), "actual physical original durable and CLEAN");
    return plan.commit.publication.transaction_xid;
}
std::uint64_t PublishPhysicalTimestamp(Fixture& f, std::uint64_t oid, const std::filesystem::path& wal) {
    const auto cp = f.Checkpoint();
    const auto identity = DeriveVolumePhysicalRecoveryIdentity(f.file->binding, cp.container.superblock.uuid_hex, oid);
    const auto xid = PublishTimestampOriginal(*f.source, *f.source, cp, oid, wal, identity);
    const auto after = f.Checkpoint(); Check(after.container.superblock.xid == xid && xid > cp.container.superblock.xid,
        "ordinary original advances canonical generation");
    MarkerText(PhysicalMarker(f, after.container.superblock.uuid_hex, oid), "dirty=0\nlastCommitXid=" + std::to_string(after.container.superblock.xid) + "\n");
    return after.container.superblock.xid;
}
void AppendPendingOriginal(const std::filesystem::path& wal, const std::string& identity, std::uint64_t xid) {
    TransactionManager writer(L"Strict"); writer.SetJournalPath(wal.wstring());
    writer.SetVolumeIdentity(std::wstring(identity.begin(), identity.end()));
    TransactionManager::MutationIntent intent; intent.kind = TransactionManager::MutationKind::CreateFile;
    intent.path = L"\\pending-unpublished"; intent.object_id = 9001; intent.generation = xid + 1;
    Check(writer.Begin() && writer.RecordMutation(intent) && writer.Accept(xid), "genuine pending original acceptance");
    const auto marks = writer.Watermarks();
    Check(marks.accepted_sequence > marks.apfs_durable_sequence && marks.accepted_sequence > marks.cleanup_sequence,
        "pending original is neither APFS durable nor CLEAN");
}
void WalBootstrapControls(const std::filesystem::path& root) {
    for (const auto& name : {"missing-current", "nonempty-destination", "prospective-destination"}) {
        Fixture f(root / name, true, true); auto request = PhysicalFormatRequest(f); const auto before = f.Image();
        const auto current = request.sibling_wals.at(101); const auto current_id = OrdinaryFileId(current);
        if (std::string(name) == "missing-current") std::filesystem::rename(current, f.root / "preserved-missing-original.wal");
        if (std::string(name) == "nonempty-destination") {
            TransactionManager tx(L"Strict"); tx.SetJournalPath(request.new_volume_wal.wstring());
            const auto identity = DeriveVolumePhysicalRecoveryIdentity(f.file->binding, request.new_container_uuid, 1024);
            tx.SetVolumeIdentity(std::wstring(identity.begin(), identity.end()));
            TransactionManager::MutationIntent intent; intent.kind = TransactionManager::MutationKind::CreateFile;
            intent.path = L"\\unused-aborted"; intent.object_id = 400; intent.generation = request.checkpoint_xid + 1;
            Check(tx.Begin() && tx.RecordMutation(intent) && tx.Abort(), "valid nonempty destination with no accepted debt");
        }
        const auto original = std::filesystem::exists(request.new_volume_wal) ? vm::Read(request.new_volume_wal) : Bytes{};
        const auto prepared = PrepareVolumePhysicalFormat(f.source, request);
        if (std::string(name) == "prospective-destination") {
            Check(prepared.outcome == VolumeImageOutcome::Prepared, "only prospective destination may bootstrap: " + prepared.error);
            Check(std::filesystem::exists(request.new_volume_wal) && std::filesystem::file_size(request.new_volume_wal) == 0,
                "prospective destination bootstraps to an actual empty file");
            Check(CancelVolumePhysicalFormat(f.source, request, prepared.token).outcome == VolumeImageOutcome::Cancelled, "bootstrap plan true cancellation");
        } else {
            Check(prepared.outcome == VolumeImageOutcome::Refused, "missing current or nonempty prospective WAL refuses: " + std::string(name));
            if (std::string(name) == "missing-current") Check(!std::filesystem::exists(current) &&
                OrdinaryFileId(f.root / "preserved-missing-original.wal") == current_id, "missing production original is never silently recreated");
            else Check(vm::Read(request.new_volume_wal) == original && !original.empty(), "nonempty destination original is preserved without reset");
        }
        Check(f.Image() == before && !f.file->writes && f.file->Current(), "bootstrap decisions write no target or external range");
    }
    ++groups;
}
void CompletedFormatOriginal(const std::filesystem::path& root) {
    Fixture f(root, true, true); CanonicalMarkers(f); const auto legacy = LegacyMarker(f); const auto request = PhysicalFormatRequest(f);
    const auto prepared = PrepareVolumePhysicalFormat(f.source, request); Check(prepared.outcome == VolumeImageOutcome::Prepared, prepared.error);
    Check(ApplyVolumePhysicalFormat(f.source, request, prepared.token).outcome == VolumeImageOutcome::Committed, "complete Format before first ordinary owner");
    const auto proof = OriginalProof(prepared.journal, prepared.source_identity); const auto certificate = vm::Read(proof);
    const auto wal_id = OrdinaryFileId(request.new_volume_wal);
    const auto marker = PhysicalMarker(f, request.new_container_uuid, 1024);
    Check(!std::filesystem::exists(marker) && HistoryError(f).empty(), "certified freshly formatted empty original needs no fabricated canonical marker");
    const auto payload = AddPayload(f.source, 1024, std::byte{0x5a});
    const auto xid = PublishPhysicalTimestamp(f, 1024, request.new_volume_wal);
    Check(xid > prepared.post_xid && !vm::Read(request.new_volume_wal).empty() && OrdinaryFileId(request.new_volume_wal) == wal_id,
        "same originally empty destination now contains a genuine all-clean ordinary original");
    Check(HistoryError(f).empty(), "existing history already proves later clean original in its published live member");
    const auto before = f.Image(); const auto original = vm::Read(request.new_volume_wal); const auto marker_bytes = vm::Read(marker); const auto legacy_bytes = vm::Read(legacy);
    const auto writes = f.file->writes; const auto recovered = RecoverVolumePhysicalFormat(f.source, request);
    Check(f.Image() == before && f.file->writes == writes && vm::Read(request.new_volume_wal) == original && OrdinaryFileId(request.new_volume_wal) == wal_id &&
        vm::Read(marker) == marker_bytes && vm::Read(legacy) == legacy_bytes && vm::Read(proof) == certificate,
        "completed recovery preserves later data, original, both markers and original certificate");
    Check(recovered.outcome == VolumeImageOutcome::Committed, "completed Format recognizes later clean ordinary original: " + recovered.error);
    for (const auto& block : payload) { Bytes bytes; Check(f.source->Read(block.physical_block * 4096, 4096, bytes) && bytes == block.bytes, "complete later ordinary payload remains unchanged"); }
    const auto retained = f.root / "retained-original.wal"; std::filesystem::rename(request.new_volume_wal, retained);
    vm::Save(request.new_volume_wal, original); const auto replacement_id = OrdinaryFileId(request.new_volume_wal);
    Check(replacement_id != wal_id, "byte-identical replacement genuinely changes original file ID");
    const auto replaced = RecoverVolumePhysicalFormat(f.source, request);
    Check(f.Image() == before && f.file->writes == writes && vm::Read(request.new_volume_wal) == original &&
        OrdinaryFileId(request.new_volume_wal) == replacement_id && vm::Read(retained) == original && OrdinaryFileId(retained) == wal_id &&
        vm::Read(marker) == marker_bytes && vm::Read(legacy) == legacy_bytes && vm::Read(proof) == certificate,
        "replaced-original refusal preserves both files and all target/history bytes");
    Check(replaced.outcome != VolumeImageOutcome::Committed && !replaced.error.empty(), "completed recovery refuses replaced live original: " + replaced.error);
    std::filesystem::rename(request.new_volume_wal, f.root / "retained-replacement.wal"); std::filesystem::rename(retained, request.new_volume_wal);
    std::filesystem::rename(marker, f.root / "retained-new-canonical-marker.private");
    Check(HistoryError(f) == "KeeperHistoryCurrentMarkerMissingWithLegacyTerminal", "nonempty formerly fresh original now requires its own canonical marker");
    const auto missing_marker = RecoverVolumePhysicalFormat(f.source, request);
    Check(missing_marker.outcome != VolumeImageOutcome::Committed && f.Image() == before && vm::Read(request.new_volume_wal) == original &&
        f.file->writes == writes && vm::Read(proof) == certificate, "legacy cannot settle newly missing current marker");
    std::filesystem::rename(f.root / "retained-new-canonical-marker.private", marker);
    const auto identity = DeriveVolumePhysicalRecoveryIdentity(f.file->binding, request.new_container_uuid, 1024);
    AppendPendingOriginal(request.new_volume_wal, identity, xid); const auto dirty_original = vm::Read(request.new_volume_wal);
    const auto dirty = RecoverVolumePhysicalFormat(f.source, request);
    Check(f.Image() == before && f.file->writes == writes && vm::Read(request.new_volume_wal) == dirty_original &&
        OrdinaryFileId(request.new_volume_wal) == wal_id && vm::Read(marker) == marker_bytes && vm::Read(proof) == certificate,
        "pending-original refusal preserves accepted debt and later data");
    Check(dirty.outcome != VolumeImageOutcome::Committed && !dirty.error.empty(), "completed recovery refuses pending original: " + dirty.error);
    ++groups;
}
void BoundedCompletedOriginal(const std::filesystem::path& root) {
    std::filesystem::create_directories(root); const auto seed = vm::Fixture(true, 0, 1024);
    auto originals = vm::Request(root, true, seed); vm::Save(originals.image, seed);
    originals.history_context = {root / "spool", root / "recovery"};
    std::filesystem::create_directories(originals.history_context.spool_root);
    std::filesystem::create_directories(originals.history_context.recovery_root);
    const auto wal = [&](const std::string& container, std::uint64_t oid) {
        return originals.history_context.spool_root / ("apfs_recovery_v1_" + DerivePartitionlessVolumeRecoveryIdentity(container, oid).substr(17)) / "write-ahead.wal";
    };
    const auto marker = [&](const std::string& container, std::uint64_t oid) {
        return originals.history_context.recovery_root / ("apfs_recovery_v1_" + DerivePartitionlessVolumeRecoveryIdentity(container, oid).substr(17) + "_Native.state");
    };
    for (auto& [oid, path] : originals.sibling_wals) { path = wal(originals.container_uuid, oid); std::filesystem::create_directories(path.parent_path()); }
    vm::ProvisionOriginalWals(originals, true); const auto cp = vm::Checkpoint(vm::Read(originals.image));
    for (const auto& [oid, path] : originals.sibling_wals)
        MarkerText(marker(originals.container_uuid, oid), "dirty=0\nlastCommitXid=" + std::to_string(cp.container.superblock.xid) + "\n");
    VolumeImageRequest request; request.operation = VolumeImageOperation::Format; request.image = originals.image;
    request.journal_directory = root; request.container_uuid = originals.container_uuid;
    request.volume_uuid = cp.volumes.front().superblock.uuid_hex; request.volume_oid = cp.volumes.front().superblock.object_id;
    request.checkpoint_xid = cp.container.superblock.xid; request.expected_bytes = request.target_bytes = seed.size();
    request.sibling_wals = originals.sibling_wals; request.history_context = originals.history_context;
    request.new_container_uuid = "dddddddddddd4ddd8ddddddddddddddd"; request.new_volume_uuid = "eeeeeeeeeeee4eee8eeeeeeeeeeeeeee";
    request.name_utf8 = "Bounded Completed"; request.new_volume_wal = wal(request.new_container_uuid, 1024);
    std::filesystem::create_directories(request.new_volume_wal.parent_path());
    const auto prepared = PrepareVolumeFormat(request); Check(prepared.outcome == VolumeImageOutcome::Prepared, "bounded prepare: " + prepared.error);
    Check(ReadU64LE(vm::Read(prepared.journal), 0) == 0x4146495653465041ull, "actual bounded flagged-format original");
    Check(ApplyVolumeFormat(request, prepared.token).outcome == VolumeImageOutcome::Committed, "bounded Format publication");
    const auto wal_id = OrdinaryFileId(request.new_volume_wal); std::uint64_t xid{};
    {
        std::string error; auto device = BlockDevice::OpenExclusiveManagementImage(request.image.wstring(), 0, error);
        Check(device != nullptr, error); Bytes bytes;
        Check(device->Read(0, seed.size(), bytes), "held bounded postimage read"); const auto current = vm::Checkpoint(bytes);
        VectorRandomAccessSource source(bytes);
        xid = PublishTimestampOriginal(source, *device, current, 1024, request.new_volume_wal,
            DerivePartitionlessVolumeRecoveryIdentity(request.new_container_uuid, 1024));
        Check(device->Read(0, seed.size(), bytes) && vm::Checkpoint(bytes).container.superblock.xid == xid, "bounded ordinary canonical publication readback");
    }
    MarkerText(marker(request.new_container_uuid, 1024), "dirty=0\nlastCommitXid=" + std::to_string(xid) + "\n");
    const auto image = vm::Read(request.image), frame = vm::Read(prepared.journal), original = vm::Read(request.new_volume_wal);
    const auto proof = OriginalProof(prepared.journal, prepared.source_identity); const auto certificate = vm::Read(proof);
    const auto recovered = RecoverVolumeFormat(request);
    Check(vm::Read(request.image) == image && vm::Read(prepared.journal) == frame && vm::Read(request.new_volume_wal) == original &&
        OrdinaryFileId(request.new_volume_wal) == wal_id && vm::Read(proof) == certificate, "bounded completed replay preserves later image and exact originals");
    Check(recovered.outcome == VolumeImageOutcome::Committed && xid > prepared.post_xid, "bounded completed recovery admits later all-clean original: " + recovered.error);
    AppendPendingOriginal(request.new_volume_wal, DerivePartitionlessVolumeRecoveryIdentity(request.new_container_uuid, 1024), xid);
    const auto pending = vm::Read(request.new_volume_wal); const auto dirty = RecoverVolumeFormat(request);
    Check(vm::Read(request.image) == image && vm::Read(request.new_volume_wal) == pending && vm::Read(prepared.journal) == frame &&
        OrdinaryFileId(request.new_volume_wal) == wal_id && vm::Read(proof) == certificate, "bounded pending refusal retains original debt and source");
    Check(dirty.outcome != VolumeImageOutcome::Committed && !dirty.error.empty(), "bounded completed recovery refuses pending original: " + dirty.error); ++groups;
}
std::array<unsigned char, 32> OutsideWindowDigest(const Carrier& file) {
    BCRYPT_ALG_HANDLE algorithm{}; BCRYPT_HASH_HANDLE hash{}; DWORD size{}, got{};
    Check(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0, "outside-window SHA256 provider");
    Check(BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&size), sizeof(size), &got, 0) >= 0, "outside-window hash size");
    Bytes object(size); Check(BCryptCreateHash(algorithm, &hash, reinterpret_cast<PUCHAR>(object.data()), size, nullptr, 0, 0) >= 0, "outside-window hash");
    for (const auto [begin, length] : {std::pair<std::uint64_t, std::uint64_t>{0, Base},
        {Base + file.window, file.disk - Base - file.window}}) {
        for (std::uint64_t at = 0; at < length;) {
            const auto count = static_cast<std::size_t>((std::min<std::uint64_t>)(4u << 20, length - at)); Bytes bytes;
            Check(file.Read(begin + at, count, bytes), "whole outside-window range read");
            Check(BCryptHashData(hash, reinterpret_cast<PUCHAR>(bytes.data()), static_cast<ULONG>(bytes.size()), 0) >= 0, "outside-window hash update"); at += count;
        }
    }
    std::array<unsigned char, 32> digest{};
    const auto status = BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0);
    BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(algorithm, 0); Check(status >= 0, "outside-window final digest"); return digest;
}
void VerifyErasedSource(const RandomAccessSource& source, const volume_image::Plan& plan) {
    std::map<std::uint64_t, Bytes> writes;
    for (const auto& write : plan.publication.before_superblock_writes) writes.emplace(write.physical_block, write.bytes);
    writes[plan.publication.superblock_write.physical_block] = plan.publication.superblock_write.bytes; writes[0] = plan.anchor;
    std::uint64_t zero_blocks = 0;
    for (std::uint64_t offset = 0; offset < source.SizeBytes();) {
        const auto count = static_cast<std::size_t>((std::min<std::uint64_t>)(4u << 20, source.SizeBytes() - offset)); Bytes bytes;
        Check(source.Read(offset, count, bytes) && bytes.size() == count, "full erase range readback");
        for (std::size_t at = 0; at < bytes.size(); at += 4096) {
            const auto expected = writes.find((offset + at) / 4096); const auto block = std::span<const std::byte>(bytes).subspan(at, 4096);
            if (expected == writes.end()) {
                Check(std::all_of(block.begin(), block.end(), [](auto b) { return b == std::byte{}; }), "every non-publication block is zero"); ++zero_blocks;
            } else Check(std::equal(block.begin(), block.end(), expected->second.begin()), "erase preserves every exact new publication block");
        }
        offset += count;
    }
    Check(zero_blocks > 0, "full zero oracle exercised actual cleanup blocks");
    std::string error; const auto cp = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
    Check(cp && cp->container.superblock.xid == plan.after.container.superblock.xid && cp->volumes.size() == 1, "canonical erased checkpoint readback: " + error);
    if (cp) volume_image::VerifySource(source, *cp);
}
void PhysicalFormatErase(const std::filesystem::path& root, bool interrupted) {
    Fixture f(root, true, true, true); const auto gpt = InstallGpt(f.file); const auto outside = OutsideWindowDigest(*f.file);
    const auto target_bytes = f.source->SizeBytes(); Check(target_bytes == (128u << 20), "actual 128 MiB physical API source");
    const auto format = PhysicalFormatRequest(f); const auto formatted = PrepareVolumePhysicalFormat(f.source, format);
    Check(formatted.outcome == VolumeImageOutcome::Prepared, "Format before Erase prepare: " + formatted.error);
    Check(ApplyVolumePhysicalFormat(f.source, format, formatted.token).outcome == VolumeImageOutcome::Committed, "actual Format before Erase");
    f.Payloads();
    const std::vector<AppleCheckpointPhysicalWrite> payload{{200, Bytes(4096, std::byte{0x41})}, {208, Bytes(4096, std::byte{0x42})}};
    const auto cp = f.Checkpoint(); auto erase = format; erase.operation = VolumeImageOperation::Erase;
    erase.container_uuid = cp.container.superblock.uuid_hex; erase.volume_uuid = cp.volumes.front().superblock.uuid_hex;
    erase.volume_oid = cp.volumes.front().superblock.object_id; erase.checkpoint_xid = cp.container.superblock.xid;
    erase.sibling_wals = {{1024, format.new_volume_wal}}; erase.new_container_uuid = "dddddddddddd4ddd8ddddddddddddddd";
    erase.new_volume_uuid = "eeeeeeeeeeee4eee8eeeeeeeeeeeeeee"; erase.name_utf8 = "Erased Physical";
    const auto identity = DeriveVolumePhysicalRecoveryIdentity(f.file->binding, erase.new_container_uuid, 1024);
    erase.new_volume_wal = erase.history_context.spool_root / ("apfs_recovery_v1_" + identity.substr(17)) / "write-ahead.wal";
    std::filesystem::create_directories(erase.new_volume_wal.parent_path());
    const auto before = f.Image(); const auto writes = f.file->writes; const auto original_wal = vm::Read(format.new_volume_wal);
    const auto prepared = PrepareVolumePhysicalFormat(f.source, erase);
    Check(f.Image() == before && f.file->writes == writes && OutsideWindowDigest(*f.file) == outside &&
        vm::Read(format.new_volume_wal) == original_wal, "Erase prepare/refusal preserves target, outside ranges and original WAL");
    std::cout << "ERASE_PREPARE bytes=" << target_bytes << " error=" << prepared.error << '\n';
    Check(prepared.outcome == VolumeImageOutcome::Prepared, "physical 128 MiB Format -> Erase prepare: " + prepared.error);
    VectorRandomAccessSource original(before); auto plan = volume_image::BuildFormatPublicationV2(original, erase, cp);
    Check(plan.cleanup.empty() && plan.postimage.empty(), "stream construction has no bounded cleanup vector or postimage");
    volume_image::FinishFormatSource(original, erase, plan);
    for (const auto& block : payload) Check(!plan.destinations.contains(block.physical_block), "old payload must be erased after replacement");
    unsigned chunks = 0; const auto applied = ApplyVolumePhysicalFormat(f.source, erase, prepared.token, [&](auto stage) {
        if (stage == "after-image-erase-chunk") ++chunks;
        return !interrupted || stage != "after-image-erase-chunk" || chunks != 1;
    });
    if (interrupted) {
        Check(chunks == 1 && applied.outcome == VolumeImageOutcome::RecoveryRequired && f.file->zero_calls > 0 && f.file->zero_bytes <= (4u << 20),
            "actual first flushed erase chunk cursor interruption: " + applied.error);
        Check(OutsideWindowDigest(*f.file) == outside && f.file->Current() && !f.file->escaped, "cursor cut preserves all outside-window bytes");
        f.source.reset(); f.source = VolumePhysicalKeeperTestPeer::Bind(f.file);
        const auto recovered = RecoverVolumePhysicalFormat(f.source, erase);
        Check(recovered.outcome == VolumeImageOutcome::Committed, "fresh held-source capability erase recovery: " + recovered.error);
    } else Check(applied.outcome == VolumeImageOutcome::Committed, "physical Erase apply: " + applied.error);
    VerifyErasedSource(*f.source, plan);
    Check(f.source->SizeBytes() == target_bytes && f.source->Binding().media.limit_bytes == target_bytes && f.file->zero_calls > 0 &&
        OutsideWindowDigest(*f.file) == outside && f.file->Current() && !f.file->escaped && vm::Read(format.new_volume_wal) == original_wal,
        "erase keeps exact target length, original history, GPT, neighbor and every unrelated byte");
    const auto after = f.Image(); const auto zero_calls = f.file->zero_calls;
    Check(RecoverVolumePhysicalFormat(f.source, erase).outcome == VolumeImageOutcome::Committed && f.Image() == after &&
        f.file->zero_calls == zero_calls, "completed Erase recovery is read-only and idempotent");
    Check(!gpt.empty(), "real primary/backup GPT fixture retained");
    std::cout << "ERASE_COMPLETE bytes=" << f.source->SizeBytes() << " zeroCalls=" << zero_calls << " cutChunks=" << chunks << '\n'; ++groups;
}
void BoundedEraseControl(const std::filesystem::path& root) {
    std::filesystem::create_directories(root); const auto seed = vm::Fixture(true, 0, 1024);
    auto originals = vm::Request(root, true, seed); vm::Save(originals.image, seed);
    originals.history_context = {root / "spool", root / "recovery"};
    std::filesystem::create_directories(originals.history_context.spool_root); std::filesystem::create_directories(originals.history_context.recovery_root);
    const auto wal = [&](const std::string& container, std::uint64_t oid) {
        return originals.history_context.spool_root / ("apfs_recovery_v1_" + DerivePartitionlessVolumeRecoveryIdentity(container, oid).substr(17)) / "write-ahead.wal";
    };
    for (auto& [oid, path] : originals.sibling_wals) { path = wal(originals.container_uuid, oid); std::filesystem::create_directories(path.parent_path()); }
    vm::ProvisionOriginalWals(originals, true); const auto before = vm::Read(originals.image); const auto cp = vm::Checkpoint(before);
    for (const auto& [oid, path] : originals.sibling_wals)
        MarkerText(originals.history_context.recovery_root / (path.parent_path().filename().string() + "_Native.state"),
            "dirty=0\nlastCommitXid=" + std::to_string(cp.container.superblock.xid) + "\n");
    VolumeImageRequest request; request.operation = VolumeImageOperation::Erase; request.image = originals.image; request.journal_directory = root;
    request.container_uuid = originals.container_uuid; request.volume_uuid = cp.volumes.front().superblock.uuid_hex;
    request.volume_oid = cp.volumes.front().superblock.object_id; request.checkpoint_xid = cp.container.superblock.xid;
    request.expected_bytes = request.target_bytes = seed.size(); request.sibling_wals = originals.sibling_wals; request.history_context = originals.history_context;
    request.new_container_uuid = "abababababab4bab8bababababababab"; request.new_volume_uuid = "cdcdcdcdcdcd4dcd8dcdcdcdcdcdcdcd";
    request.name_utf8 = "Bounded Erase"; request.new_volume_wal = wal(request.new_container_uuid, 1024);
    std::filesystem::create_directories(request.new_volume_wal.parent_path()); const auto id = OrdinaryFileId(request.image);
    const auto prepared = PrepareVolumeFormat(request);
    Check(prepared.outcome == VolumeImageOutcome::Prepared && vm::Read(request.image) == before, "bounded Erase prepare: " + prepared.error);
    VectorRandomAccessSource original(before); auto plan = volume_image::BuildFormatPublicationV2(original, request, cp);
    volume_image::FinishFormatSource(original, request, plan);
    Check(ApplyVolumeFormat(request, prepared.token).outcome == VolumeImageOutcome::Committed, "bounded Erase apply");
    const auto after = vm::Read(request.image); VectorRandomAccessSource source(after); VerifyErasedSource(source, plan);
    Check(after.size() == seed.size() && OrdinaryFileId(request.image) == id, "bounded Erase preserves exact file size and identity");
    Check(RecoverVolumeFormat(request).outcome == VolumeImageOutcome::Committed && vm::Read(request.image) == after, "bounded Erase original recovery control"); ++groups;
}
void LegacyFormatControls(const std::filesystem::path& root) {
    for (const auto& name : {"prepared", "stale-source", "replaced-wal", "accepted"}) {
        Fixture f(root / name, true, true); auto request = PhysicalFormatRequest(f);
        const auto p = PrepareVolumePhysicalFormat(f.source, request); Check(p.outcome == VolumeImageOutcome::Prepared, "legacy-format setup: " + p.error);
        const auto proof = OriginalProof(p.journal, p.source_identity); const auto certificate = vm::Read(proof);
        Check(!certificate.empty(), "successful Format prepare certifies its original destination before acceptance");
        if (std::string(name) == "accepted") {
            const auto cut = ApplyVolumePhysicalFormat(f.source, request, p.token, [](auto stage) { return stage != "after-image-accept"; });
            Check(cut.outcome == VolumeImageOutcome::RecoveryRequired && !f.file->writes, "accepted original cut before target writes");
        }
        std::filesystem::rename(proof, f.root / "retained-pre-upgrade-certificate.private");
        const auto frame = vm::Read(p.journal);
        if (std::string(name) == "stale-source") { Bytes bytes(4096, std::byte{0x62}); Check(f.file->WriteAt(Base + f.file->window - 4096, bytes), "actual stale source control"); }
        if (std::string(name) == "replaced-wal") {
            const auto path = request.sibling_wals.at(101); std::filesystem::rename(path, f.root / "retained-original-101.wal"); vm::Save(path, {});
        }
        const auto before = f.Image(); const auto result = RecoverVolumePhysicalFormat(f.source, request);
        if (std::string(name) == "prepared") {
            Check(result.outcome == VolumeImageOutcome::Cancelled, "legacy state-zero recovery performs true cancellation: " + result.error);
            Check(vm::Read(proof) == certificate, "legacy state-zero certificate equals exact privately retained original");
            const auto after = vm::Read(p.journal); Check(after.size() == frame.size() + 40 && std::equal(frame.begin(), frame.end(), after.begin()),
                "legacy prepared bytes retained with one real cancellation receipt");
            Check(DecodeVolumeKeeperHistoryBinding(after, p.journal, request.journal_directory, p.source_identity).state == VolumeKeeperJournalState::Cancelled,
                "native decoder confirms terminal cancellation");
        } else {
            Check(result.outcome == (std::string(name) == "accepted" ? VolumeImageOutcome::RecoveryRequired : VolumeImageOutcome::Refused),
                "missing certificate cannot mint accepted or stale authority: " + std::string(name) + ": " + result.error);
            Check(!std::filesystem::exists(proof) && vm::Read(p.journal) == frame, "refused recovery creates no replacement certificate or receipt");
        }
        Check(f.Image() == before && !f.file->writes && f.file->Current(), "legacy recovery leaves exact target and external ranges unchanged");
    }
    {
        Fixture f(root / "retired-cross-container", true, true); const auto request = PhysicalFormatRequest(f);
        const auto p = PrepareVolumePhysicalFormat(f.source, request); Check(p.outcome == VolumeImageOutcome::Prepared, p.error);
        Check(ApplyVolumePhysicalFormat(f.source, request, p.token).outcome == VolumeImageOutcome::Committed, "cross-container retired history setup");
        Check(HistoryError(f).empty(), "completed Format retains known old-container history");
        const auto before = f.Image(); const auto writes = f.file->writes; const auto old_wal = f.Wal(101); const auto original = vm::Read(old_wal);
        const auto suffix = DeriveVolumePhysicalRecoveryIdentity(f.file->binding, request.container_uuid, 101).substr(17);
        const auto material = NamespaceMaterial(request.container_uuid, 101, &f.file->binding);
        Check(vm::Read(NamespaceWitness(f, suffix)) == Bytes(material.begin(), material.end()), "retired namespace has a real preimage witness");
        {
            const auto identity = DeriveVolumePhysicalRecoveryIdentity(f.file->binding, request.container_uuid, 101);
            TransactionManager tx(L"Strict"); tx.SetJournalPath(old_wal.wstring()); tx.SetVolumeIdentity(std::wstring(identity.begin(), identity.end()));
            TransactionManager::MutationIntent intent; intent.kind = TransactionManager::MutationKind::CreateFile;
            intent.path = L"\\retired-aborted"; intent.object_id = 700; intent.generation = request.checkpoint_xid + 1;
            Check(tx.Begin() && tx.RecordMutation(intent) && tx.Abort(), "real aborted suffix changes retired original while leaving no accepted debt");
        }
        std::vector<TransactionManager::AcceptedTransaction> debt; TransactionManager::DurabilityWatermarks marks; std::string error;
        const auto identity = DeriveVolumePhysicalRecoveryIdentity(f.file->binding, request.container_uuid, 101);
        Check(TransactionManager::InspectAcceptedTransactionsReadOnly(old_wal, identity, debt, marks, error) && debt.empty() &&
            marks.accepted_sequence == marks.apfs_durable_sequence && marks.apfs_durable_sequence == marks.cleanup_sequence,
            "changed retired original remains syntactically valid and semantically all-clean: " + error);
        Check(HistoryError(f) == "KeeperHistoryRetiredWalChanged", "known retired digest remains enforced despite valid foreign-container witness"); vm::Save(old_wal, original);
        const auto marker = request.history_context.recovery_root / ("apfs_recovery_v1_" + suffix + "_Native.state");
        const std::string dirty = "dirty=1\nlastCommitXid=6\n";
        vm::Save(marker, Bytes(reinterpret_cast<const std::byte*>(dirty.data()), reinterpret_cast<const std::byte*>(dirty.data() + dirty.size())));
        Check(!HistoryError(f).empty(), "known retired dirty marker is never excluded as foreign");
        Check(f.Image() == before && f.file->writes == writes && f.file->Current(), "retired original refusals do not publish");
    }
    ++groups;
}
std::string PrivateJson(std::string_view value) {
    std::string out = "\"";
    for (const auto c : value) { if (c == '\\' || c == '"') out += '\\'; out += c; }
    return out + '"';
}
int ProcessBridge(int argc, wchar_t** argv) {
    Check(argc >= 3, "private process bridge scope"); const std::wstring_view mode(argv[1]);
    const std::filesystem::path root(argv[2]); Check(root.wstring().starts_with(L"D:\\"), "D-only private process bridge");
    Fixture f(root, mode == L"bridge-setup");
    if (mode == L"bridge-setup" || mode == L"bridge-probe") {
        const auto cp = f.Checkpoint(); f.Payloads(); Check(f.file->Current() && !f.file->escaped, "private oracle neighbors and payloads");
        std::string binding_hex; constexpr char hex[] = "0123456789abcdef";
        for (const auto b : volume_physical::Encode(f.file->binding, Instance)) {
            const auto n = std::to_integer<unsigned>(b); binding_hex += hex[n >> 4]; binding_hex += hex[n & 15];
        }
        std::cout << "{\"containerUuid\":" << PrivateJson(cp.container.superblock.uuid_hex)
            << ",\"xid\":\"" << cp.container.superblock.xid << "\",\"nextOid\":\"" << cp.container.superblock.next_oid
            << "\",\"sourceIdentity\":" << PrivateJson(f.source->Identity()) << ",\"bindingHex\":" << PrivateJson(binding_hex) << ",\"volumes\":[";
        bool first = true;
        for (const auto& v : cp.volumes) {
            if (!first) std::cout << ','; first = false;
            std::cout << "{\"uuid\":" << PrivateJson(v.superblock.uuid_hex) << ",\"oid\":\"" << v.superblock.object_id << "\"}";
        }
        std::cout << "]}" << '\n'; return 0;
    }
    if (mode == L"bridge-observe") return VolumePhysicalObserveMain(argc - 2, argv + 2,
        [&](auto selected, auto instance, auto base, auto limit, const auto& q, auto& error) {
            if (selected != L"\\\\.\\PhysicalDrive42" || (!instance.empty() && instance != Instance) || base != Base || limit != Window ||
                q.kind != f.file->binding.hardware.kind || q.bus_type != 7 || q.vendor != "Fictional" ||
                q.product != "Topology Surrogate" || q.qualified_serial != "TOPOLOGYTEST42") {
                error = "PrivatePhysicalObservationAuthorityMismatch"; return std::shared_ptr<VolumePhysicalSource>{};
            }
            return f.source;
        });
    Check(mode == L"bridge-tool", "known private process bridge mode");
    return VolumeManagementImageMain(argc - 2, argv + 2,
        [&](const auto& binding, auto instance, auto selected, auto& error) {
            if (instance != Instance || (!selected.empty() && selected != L"\\\\.\\PhysicalDrive42") ||
                volume_physical::Encode(binding, instance) != volume_physical::Encode(f.file->binding, Instance)) {
                error = "PrivatePhysicalManagementAuthorityMismatch"; return std::shared_ptr<VolumePhysicalSource>{};
            }
            return f.source;
        });
}
}
int wmain(int argc, wchar_t** argv) {
    try {
        if (argc >= 2 && std::wstring_view(argv[1]).starts_with(L"bridge-")) return ProcessBridge(argc, argv);
        Check(argc == 2 || argc == 3, "mode and private D root required"); const std::filesystem::path root(argv[argc - 1]);
        Check(root.wstring().starts_with(L"D:\\"), "D-only private fixture root");
        const std::wstring_view mode = argc == 2 ? L"all" : std::wstring_view(argv[1]);
        if (mode == L"all") { Positive(root / "positive"); Controls(root / "controls"); Cut(root / "cut"); Recover(root / "cut"); AuthorityControls(root / "authority"); ToolRoute(root / "tool"); FormatThenCreate(root / "format"); ObservationControls(root / "observation"); NamespaceForeign(root / "namespace-foreign"); NamespaceControls(root / "namespace-controls"); ReservationControls(root / "reservations"); LegacyFormatControls(root / "legacy-format"); RefusedPrepareLifecycle(root / "prepare-lifecycle"); LegacyMarkerControls(root / "legacy-markers"); WalBootstrapControls(root / "wal-bootstrap"); CompletedFormatOriginal(root / "completed-original"); }
        else if (mode == L"positive") Positive(root);
        else if (mode == L"controls") Controls(root);
        else if (mode == L"cut") Cut(root);
        else if (mode == L"recover") Recover(root);
        else if (mode == L"authority") AuthorityControls(root);
        else if (mode == L"tool") ToolRoute(root);
        else if (mode == L"format") FormatThenCreate(root);
        else if (mode == L"observation") ObservationControls(root);
        else if (mode == L"namespace-foreign") NamespaceForeign(root);
        else if (mode == L"namespace-controls") NamespaceControls(root);
        else if (mode == L"reservations") ReservationControls(root);
        else if (mode == L"legacy-format") LegacyFormatControls(root);
        else if (mode == L"prepare-lifecycle") RefusedPrepareLifecycle(root);
        else if (mode == L"legacy-markers") LegacyMarkerControls(root);
        else if (mode == L"wal-bootstrap") WalBootstrapControls(root);
        else if (mode == L"completed-original") CompletedFormatOriginal(root);
        else if (mode == L"bounded-completed-original") BoundedCompletedOriginal(root);
        else if (mode == L"erase-sequence") PhysicalFormatErase(root, false);
        else if (mode == L"erase-cursor") PhysicalFormatErase(root, true);
        else if (mode == L"bounded-erase") BoundedEraseControl(root);
        else throw std::runtime_error("unknown mode");
        std::cout << "PASS groups=" << groups << " checks=" << checks << '\n'; return 0;
    } catch (const std::exception& error) { std::cerr << "FAIL checks=" << checks << " " << error.what() << '\n'; return 1; }
}
