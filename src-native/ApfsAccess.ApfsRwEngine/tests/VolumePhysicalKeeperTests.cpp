#define wmain StreamedPhysicalFixtureMain
#include "VolumeFormatStreamedTests.cpp"
#undef wmain
#include "VolumePhysicalKeeper.h"
#include "../src/VolumePhysicalMediaInternal.h"
#include "../src/VolumePhysicalBindingCodec.h"

namespace
{
constexpr std::uint64_t SimulatedDiskBytes = 128ull<<30, SimulatedBase = 1048576;
constexpr std::wstring_view SimulatedInstance = L"USBSTOR\\DISK&VEN_TESTVENDOR&PROD_SURROGATE&REV_0001\\TESTINSTANCE42&0";
struct PhysicalFile
{
    HANDLE handle = INVALID_HANDLE_VALUE;
    FILE_ID_INFO id{};
    bool available = true;
    std::uint64_t writes = 0, zeros = 0, escaped = 0;
    RawSnapshotBinding binding;
    std::map<std::uint64_t, Bytes> sentinels;
    ~PhysicalFile() { if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle); }
    bool Read(std::uint64_t offset, std::size_t size, Bytes& out) const
    {
        out.clear(); if (offset > SimulatedDiskBytes || size > SimulatedDiskBytes - offset || size > MAXDWORD) return false;
        LARGE_INTEGER at{}; at.QuadPart = offset; DWORD got{}; out.resize(size);
        if (SetFilePointerEx(handle, at, nullptr, FILE_BEGIN) && ReadFile(handle, out.data(), static_cast<DWORD>(size), &got, nullptr) && got == size) return true;
        out.clear(); return false;
    }
    bool Current() const
    {
        FILE_ID_INFO now{}; LARGE_INTEGER size{};
        if (!available || !GetFileInformationByHandleEx(handle, FileIdInfo, &now, sizeof(now)) ||
            std::memcmp(&now, &id, sizeof(id)) || !GetFileSizeEx(handle, &size) || size.QuadPart != SimulatedDiskBytes) return false;
        for (const auto& [offset, expected] : sentinels) { Bytes bytes; if (!Read(offset, expected.size(), bytes) || bytes != expected) return false; }
        return true;
    }
    bool Range(std::uint64_t offset, std::size_t size)
    {
        const auto& media = binding.media;
        if (offset > media.limit_bytes || size > media.limit_bytes - offset) { ++escaped; return false; } return true;
    }
    bool Write(std::uint64_t offset, std::span<const std::byte> bytes)
    {
        if (!Range(offset, bytes.size())) return false;
        LARGE_INTEGER at{}; at.QuadPart = SimulatedBase + offset; DWORD wrote{}; ++writes;
        return SetFilePointerEx(handle, at, nullptr, FILE_BEGIN) &&
            WriteFile(handle, bytes.data(), static_cast<DWORD>(bytes.size()), &wrote, nullptr) && wrote == bytes.size();
    }
    bool Zero(std::uint64_t offset, std::size_t size)
    {
        if (!Range(offset, size)) return false;
        FILE_ZERO_DATA_INFORMATION range{}; range.FileOffset.QuadPart = SimulatedBase + offset;
        range.BeyondFinalZero.QuadPart = SimulatedBase + offset + size; DWORD got{}; ++zeros;
        return DeviceIoControl(handle, FSCTL_SET_ZERO_DATA, &range, sizeof(range), nullptr, 0, &got, nullptr) != FALSE;
    }
};
}

namespace apfsaccess::rw
{
// This peer simulates held hardware authority using one exclusive ordinary
// sparse file. It exercises keeper I/O, not PNP/GPT transport qualification.
struct VolumePhysicalKeeperTestPeer
{
    static std::shared_ptr<VolumePhysicalSource> Bind(const std::shared_ptr<PhysicalFile>& file)
    {
        std::string error; Check(ValidateVolumePhysicalPolicy(file->binding, SimulatedInstance, error), error);
        auto impl = std::make_unique<VolumePhysicalSource::Impl>(); impl->binding = file->binding;
        impl->instance = SimulatedInstance; impl->identity = VolumePhysicalIdentity(file->binding, SimulatedInstance);
        impl->current = [file] { return file->Current(); };
        impl->read = [file](auto offset, auto size, auto& out, bool) { return file->Range(offset, size) && file->Read(SimulatedBase + offset, size, out); };
        impl->read_metadata = [file](auto offset,auto size,auto& out){return file->Read(offset,size,out);};
        impl->write = [file](auto offset, auto bytes) { return file->Write(offset, bytes); };
        impl->zero = [file](auto offset, auto size) { return file->Zero(offset, size); };
        impl->flush = [file] { return FlushFileBuffers(file->handle) != FALSE; };
        return std::shared_ptr<VolumePhysicalSource>(new VolumePhysicalSource(std::move(impl)));
    }
};
}

namespace
{
struct PhysicalFixture
{
    VolumeImageRequest request;
    std::shared_ptr<PhysicalFile> file;
    std::shared_ptr<VolumePhysicalSource> source;
    PhysicalFixture(const std::string& name, VolumeImageOperation operation)
    {
        const auto directory = root / name; std::filesystem::create_directories(directory);
        const auto original = Source(); request = Request(directory, operation, Fixture());
        request.expected_bytes = request.target_bytes = original.SizeBytes(); request.image = SimulatedInstance;
        const auto path = directory / "simulated-physical-window.img";
        mc::SparseStore carrier; carrier.block_count = SimulatedDiskBytes / 4096;
        for (const auto& [block, bytes] : original.blocks) carrier.blocks[SimulatedBase / 4096 + block] = bytes;
        file = std::make_shared<PhysicalFile>(); auto& binding = file->binding;
        binding.hardware.kind = RawHardwareIdentityKind::QualifiedSerialTuple; binding.hardware.bus_type = BusTypeUsb;
        binding.hardware.vendor = "TestVendor"; binding.hardware.product = "Surrogate Storage"; binding.hardware.revision = "0001";
        binding.hardware.serial = "TESTSERIAL42";
        auto& media = binding.media; media.disk_guid.fill(std::byte{0x31}); media.partition_guid.fill(std::byte{0x52});
        media.disk_size_bytes = SimulatedDiskBytes; media.partition_offset_bytes = media.base_offset_bytes = SimulatedBase;
        media.partition_length_bytes = media.limit_bytes = original.SizeBytes(); media.logical_sector_bytes = media.physical_sector_bytes = 4096;
        const std::array<std::uint64_t, 4> offsets{0, SimulatedBase - 4096, SimulatedBase + original.SizeBytes(), SimulatedDiskBytes - 4096};
        for (std::size_t i = 0; i < offsets.size(); ++i) {
            auto bytes = Bytes(4096, std::byte(0x71 + i)); carrier.blocks[offsets[i] / 4096] = bytes; file->sentinels.emplace(offsets[i], std::move(bytes));
        }
        mc::SparseFile(path, carrier);
        file->handle = CreateFileW(FixtureIoPath(path).c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_FLAG_WRITE_THROUGH, nullptr);
        Check(file->handle != INVALID_HANDLE_VALUE && GetFileInformationByHandleEx(file->handle, FileIdInfo, &file->id, sizeof(file->id)), "exclusive simulated source identity");
        source = VolumePhysicalKeeperTestPeer::Bind(file); Check(source->Revalidate(), "initial held simulation");
    }
    std::vector<fe::Digest> Digests() const { return fe::Scan(*source).digests; }
};
void PhysicalPositive()
{
    for (const auto operation : {VolumeImageOperation::Format, VolumeImageOperation::Erase}) {
        PhysicalFixture fixture(operation == VolumeImageOperation::Format ? "physical-format" : "physical-erase", operation);
        const auto before = fixture.Digests(); const auto prepared = PrepareVolumePhysicalFormat(fixture.source, fixture.request);
        Check(prepared.outcome == VolumeImageOutcome::Prepared, "physical simulation preparation: " + prepared.error);
        Check(before == fixture.Digests() && !fixture.file->writes && !fixture.file->zeros, "prepare has no source write");
        const auto frame = Read(prepared.journal);
        Check(ReadU64LE(frame, 0) == volume_physical::FlaggedFormatMagic &&
            ReadU64LE(frame, 48) == static_cast<std::uint64_t>(operation), "distinct flagged physical frame and exact operation");
        ValidateVolumeKeeperPhysicalFrame(Read(prepared.journal), *fixture.source);
        const auto done = ApplyVolumePhysicalFormat(fixture.source, fixture.request, prepared.token);
        Check(done.outcome == VolumeImageOutcome::Committed, "physical simulation apply: " + done.error);
        Check(RecoverVolumePhysicalFormat(fixture.source, fixture.request).outcome == VolumeImageOutcome::Committed, "physical simulation idempotent recovery");
        const auto cp = mc::Load(*fixture.source); mc::Verify(*fixture.source, cp);
        Check(cp.container.superblock.uuid_hex == fixture.request.new_container_uuid && fixture.file->Current() && !fixture.file->escaped,
            "exact new container and unchanged outside sentinels and source length");
        auto history = AcquireVolumeKeeperPhysicalHistory(fixture.source, *fixture.source, fixture.request.journal_directory, {});
        mc::NativeWrite(*fixture.source); history.reset();
        Check(RecoverVolumePhysicalFormat(fixture.source, fixture.request).outcome == VolumeImageOutcome::Committed,
            "completed physical history permits ordinary write and reopen");
        Check(operation == VolumeImageOperation::Format ? fixture.file->zeros == 0 : fixture.file->zeros > 0, "only erase issues bounded zero operations");
    }
    Pass("simulated physical held window actual sparse I/O and ordinary write");
}
void PhysicalControls()
{
    PhysicalFixture fixture("physical-controls", VolumeImageOperation::Format);
    {
        auto binding = fixture.file->binding;
        constexpr std::array<unsigned, 16> network_guid{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
        for (std::size_t i = 0; i < network_guid.size(); ++i) binding.media.partition_guid[i] = std::byte(network_guid[i]);
        Check(DeriveVolumePhysicalRecoveryIdentity(binding, "112233445566778899aabbccddeeff00", 1024) ==
            "apfs-recovery-v1-jEGxJS6lT7NVreofB5UhKU6RKslP_CMKSGRPUxrzQVY", "independent managed Guid.ToByteArray recovery vector");
        std::string error;
        Check(!ValidateVolumePhysicalPolicy(binding, L"USBSTOR\\DISK&VEN_TOSHIBA", error), "other instance is never authorized");
        binding.hardware.serial = "unknown";
        Check(!ValidateVolumePhysicalPolicy(binding, SimulatedInstance, error), "generic serial never qualifies");
        binding.hardware.serial = "SECOND-FICTIONAL-SERIAL";
        Check(ValidateVolumePhysicalPolicy(binding, SimulatedInstance, error), "policy does not embed an operator device allowlist");
        binding = fixture.file->binding; ++binding.media.disk_size_bytes;
        Check(!ValidateVolumePhysicalPolicy(binding, SimulatedInstance, error), "other capacity is never authorized");
    }
    const auto before = fixture.Digests(); const auto prepared = PrepareVolumePhysicalFormat(fixture.source, fixture.request);
    Check(prepared.outcome == VolumeImageOutcome::Prepared, prepared.error);
    auto request = fixture.request; request.image = L"\\\\.\\PhysicalDrive2";
    Check(ApplyVolumePhysicalFormat(fixture.source, request, prepared.token).outcome == VolumeImageOutcome::Refused, "disk number cannot substitute stable PNP identity");
    request = fixture.request; request.operation = VolumeImageOperation::Shrink;
    Check(PrepareVolumePhysicalFormat(fixture.source, request).error == "VolumePhysicalOperationUnproved", "unproved physical resize is explicit");
    const auto frame = Read(prepared.journal);
    for (unsigned variant = 0; variant < 5; ++variant) {
        const auto original = fixture.file->binding;
        if (variant == 0) fixture.file->binding.media.partition_guid[0] ^= std::byte{1};
        if (variant == 1) fixture.file->binding.media.disk_guid[0] ^= std::byte{1};
        if (variant == 2) fixture.file->binding.media.partition_length_bytes += 4096;
        if (variant == 3) fixture.file->binding.hardware.revision += "X";
        if (variant == 4) fixture.file->binding.media.physical_sector_bytes = 8192;
        auto changed = VolumePhysicalKeeperTestPeer::Bind(fixture.file); bool refused = false;
        Check(changed->Identity() == fixture.source->Identity(), "media or descriptor changes retain the same device debt namespace");
        try { ValidateVolumeKeeperPhysicalFrame(frame, *changed); } catch (...) { refused = true; }
        Check(refused, "complete physical binding mismatch refuses");
        const auto mismatched = ApplyVolumePhysicalFormat(changed, fixture.request, prepared.token);
        Check(mismatched.outcome == VolumeImageOutcome::Refused && mismatched.journal == prepared.journal && !fixture.file->writes,
            "fresh changed binding cannot bypass the existing original intent"); fixture.file->binding = original;
    }
    auto bad = frame; vi::Put(bad, 0, fe::Magic); Save(prepared.journal, bad);
    const auto spoof = RecoverVolumePhysicalFormat(fixture.source, fixture.request);
    Check(spoof.outcome == VolumeImageOutcome::RecoveryRequired && before == fixture.Digests() && !fixture.file->writes,
        "physical frame cannot replay as ordinary VIF2"); Save(prepared.journal, frame);
    fixture.file->available = false;
    Check(ApplyVolumePhysicalFormat(fixture.source, fixture.request, prepared.token).outcome == VolumeImageOutcome::Refused && !fixture.file->writes,
        "stale capability refuses before target writes"); fixture.file->available = true;
    Check(!fixture.source->Revalidate(), "failed held authority remains poisoned");
    fixture.source = VolumePhysicalKeeperTestPeer::Bind(fixture.file);
    Check(before == fixture.Digests() && CancelVolumePhysicalFormat(fixture.source, fixture.request, prepared.token).outcome == VolumeImageOutcome::Cancelled,
        "fresh exact authority can cancel unchanged prepared intent");
    Pass("simulated physical mode identity GPT extent and stale lease controls");
}
void PhysicalCuts()
{
    const std::vector<std::string> stages{"after-image-accept", "before-apple-checkpoint-switch", "before-image-anchor",
        "after-image-anchor", "after-image-erase-authorize", "after-image-erase-write"};
    for (std::size_t i = 0; i < stages.size(); ++i) {
        PhysicalFixture fixture("physical-cut-" + std::to_string(i), VolumeImageOperation::Erase);
        const auto prepared = PrepareVolumePhysicalFormat(fixture.source, fixture.request);
        Check(prepared.outcome == VolumeImageOutcome::Prepared, prepared.error); bool hit = false;
        const auto cut = ApplyVolumePhysicalFormat(fixture.source, fixture.request, prepared.token,
            [&](auto stage) { if (stage == stages[i]) { hit = true; return false; } return true; });
        Check(hit && cut.outcome == VolumeImageOutcome::RecoveryRequired, "physical simulation accepted cut: " + cut.error);
        fixture.source = VolumePhysicalKeeperTestPeer::Bind(fixture.file);
        const auto recovered = RecoverVolumePhysicalFormat(fixture.source, fixture.request);
        Check(recovered.outcome == VolumeImageOutcome::Committed, "physical simulation forward recovery: " + recovered.error);
        Check(fixture.file->Current() && !fixture.file->escaped, "recovery preserves all outside guards");
        mc::Verify(*fixture.source, mc::Load(*fixture.source));
    }
    Pass("simulated physical bounded erase publication and zero-range cuts");
}
}
#ifndef APFS_PHYSICAL_KEEPER_FIXTURE_ONLY
int wmain(int argc, wchar_t** argv)
{
    try {
        const auto mode = argc == 3 ? std::wstring_view(argv[2]) : L"--all";
        Check((argc == 2 || argc == 3) && (mode == L"--all" || mode == L"--positive-only" || mode == L"--controls-cuts"), "private simulation root required");
        root = argv[1]; std::filesystem::create_directories(root);
        if (mode != L"--controls-cuts") PhysicalPositive();
        if (mode != L"--positive-only") { PhysicalControls(); PhysicalCuts(); }
        std::cout << "PASS groups=" << groups << " checks=" << checks << " simulatedAuthority=1 hardware=0\n"; return 0;
    } catch (const std::exception& ex) { std::cerr << "FAIL checks=" << checks << " " << ex.what() << '\n'; return 1; }
}
#endif
