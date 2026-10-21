#define APFS_PHYSICAL_KEEPER_FIXTURE_ONLY
#include "VolumePhysicalKeeperTests.cpp"
#include "BlockDevice.h"
#include "VolumeKeeperAdmission.h"

namespace apfsaccess::rw
{
struct BlockDeviceRawSnapshotTestPeer
{
    static void Seed(BlockDevice& d, HANDLE held, const RawSnapshotBinding& binding)
    {
        HANDLE reader = INVALID_HANDLE_VALUE, writer = INVALID_HANDLE_VALUE;
        if (!DuplicateHandle(GetCurrentProcess(), held, GetCurrentProcess(), &reader, 0, FALSE, DUPLICATE_SAME_ACCESS) ||
            !DuplicateHandle(GetCurrentProcess(), held, GetCurrentProcess(), &writer, 0, FALSE, DUPLICATE_SAME_ACCESS))
            throw std::runtime_error("Held synthetic file handles required");
        d.read_handle_.store(reader); d.write_handle_.store(writer);
        d.regular_file_.store(false); d.raw_writer_accepted_.store(true); d.writable_.store(true);
        d.raw_write_limit_bytes_.store(binding.media.limit_bytes);
        d.raw_write_source_size_bytes_ = binding.media.disk_size_bytes - d.BaseOffsetBytes();
        d.raw_writer_identity_ = "gpt:synthetic-held-source";
        d.raw_presence_probe_result_.store(true);
        d.raw_snapshot_lease_retired_ = false;
        d.write_source_handles_retired_ = false;
        d.raw_snapshot_descriptors_attempted_ = d.raw_snapshot_descriptors_complete_ = true;
        auto& descriptors = d.raw_snapshot_descriptors_;
        descriptors.media = binding.media;
        const auto& hardware = binding.hardware;
        descriptors.device = {hardware.bus_type, hardware.vendor, hardware.product, hardware.revision, hardware.serial};
    }
    static void Change(BlockDevice& d, const std::string& fault)
    {
        std::lock_guard<std::mutex> lock(d.write_source_mutex_);
        if (fault == "hardware") d.raw_snapshot_descriptors_.device.serial += "X";
        if (fault == "gpt") d.raw_snapshot_descriptors_.media.partition_guid[0] ^= std::byte{1};
        if (fault == "window") d.raw_snapshot_descriptors_.media.limit_bytes -= 4096;
        if (fault == "retired") d.raw_snapshot_lease_retired_ = true;
        if (fault == "unaccepted") d.raw_writer_accepted_.store(false);
        if (fault == "generic") d.raw_snapshot_descriptors_.device.serial = "UNKNOWN";
    }
};
}

namespace
{
std::function<bool(std::wstring_view, std::wstring&)> instance_observation;
}
namespace apfsaccess::rw::physical_instance
{
bool KeeperRawInstanceForTests(std::wstring_view selected, std::wstring& instance)
{
    return instance_observation && instance_observation(selected, instance);
}
}

namespace
{
void RawAdmission(const std::string& state)
{
    PhysicalFixture fixture("raw-admission-" + state, VolumeImageOperation::Format);
    const auto prepared = PrepareVolumePhysicalFormat(fixture.source, fixture.request);
    Check(prepared.outcome == VolumeImageOutcome::Prepared, prepared.error);
    if (state == "completed")
        Check(ApplyVolumePhysicalFormat(fixture.source, fixture.request, prepared.token).outcome == VolumeImageOutcome::Committed,
            "actual synthetic completed frame");
    if (state == "cancelled")
        Check(CancelVolumePhysicalFormat(fixture.source, fixture.request, prepared.token).outcome == VolumeImageOutcome::Cancelled,
            "actual synthetic cancelled frame");
    if (state == "accepted" || state == "anchor-durable")
    {
        const auto cut = state == "accepted" ? "after-image-accept" : "after-image-anchor";
        const auto result = ApplyVolumePhysicalFormat(fixture.source, fixture.request, prepared.token,
            [&](auto stage) { return std::string_view(stage) != cut; });
        Check(result.outcome == VolumeImageOutcome::RecoveryRequired, "actual synthetic nonterminal receipt: " + result.error);
    }
    auto frame = Read(prepared.journal);
    if (state == "malformed") { frame[16] ^= std::byte{1}; Save(prepared.journal, frame); }
    if (state == "torn") { frame.push_back(std::byte{1}); Save(prepared.journal, frame); }
    const auto writes = fixture.file->writes, zeros = fixture.file->zeros;
    BlockDevice device((fixture.request.journal_directory / "simulated-physical-window.img").wstring(), SimulatedBase);
    BlockDeviceRawSnapshotTestPeer::Seed(device, fixture.file->handle, fixture.file->binding);
    unsigned observations = 0;
    instance_observation = [&](std::wstring_view, std::wstring& instance)
    {
        ++observations; instance = SimulatedInstance;
        if (observations == 2 && (state == "hardware" || state == "gpt" || state == "window" || state == "retired"))
            BlockDeviceRawSnapshotTestPeer::Change(device, state);
        if (observations == 2 && state == "instance") instance += L"OTHER";
        return state != "missing-instance";
    };
    if (state == "unaccepted" || state == "generic") BlockDeviceRawSnapshotTestPeer::Change(device, state);
    // Identity controls use terminal evidence, so refusal cannot be attributed to pending debt.
    if (state == "hardware" || state == "gpt" || state == "window" || state == "retired" || state == "instance" ||
        state == "missing-instance" || state == "unaccepted" || state == "generic" || state == "missing-root" || state == "foreign-malformed")
    {
        Check(CancelVolumePhysicalFormat(fixture.source, fixture.request, prepared.token).outcome == VolumeImageOutcome::Cancelled,
            "terminal evidence for identity control");
        frame = Read(prepared.journal);
    }
    if (state == "empty") std::filesystem::remove(prepared.journal);
    const auto foreign = fixture.request.journal_directory / "unproved.vmt1";
    if (state == "foreign-malformed") Save(foreign, Bytes(8, std::byte{0x31}));
    const auto admission = InspectHeldVolumeKeeperRaw(device,
        state == "missing-root" ? std::filesystem::path{} : fixture.request.journal_directory);
    const bool expected = state == "completed" || state == "cancelled" || state == "empty";
    Check(admission.admitted == expected, state + ": " + admission.error);
    if (expected) Check(admission.source_identity == fixture.source->Identity() && observations == 2,
        "held source identity matches actual physical keeper namespace");
    if (state == "prepared" || state == "accepted" || state == "anchor-durable" || state == "malformed" || state == "torn")
        Check(admission.error.starts_with("VolumeKeeperAdmissionBlocked:vif1:" +
            (state == "malformed" || state == "torn" ? std::string("invalid") : state)), "exact authoritative debt refusal");
    if (state == "foreign-malformed")
        Check(admission.error.starts_with("VolumeKeeperAdmissionBlocked:vmt1:invalid") && Read(foreign) == Bytes(8, std::byte{0x31}),
            "unbound foreign evidence is not skipped");
    Check((state == "empty" ? !std::filesystem::exists(prepared.journal) : Read(prepared.journal) == frame) &&
        fixture.file->writes == writes && fixture.file->zeros == zeros && !fixture.file->escaped,
        "admission preserves evidence and never writes the synthetic source");
    instance_observation = {};
    Pass(state.c_str());
}
}

int wmain(int argc, wchar_t** argv)
{
    try
    {
        Check(argc == 2, "fresh private D test root required");
        root = argv[1]; Check(root.root_name() == L"D:", "D-rooted fixtures required");
        std::filesystem::create_directories(root);
        {
            BlockDevice unopened((root / "must-not-open.img").wstring());
            Check(InspectHeldVolumeKeeperRaw(unopened, {}).error == "VolumeKeeperJournalRootRequired" &&
                !std::filesystem::exists(root / "must-not-open.img"), "missing root refuses before touching an unopened source");
            Pass("missing root before source observation");
        }
        for (const auto state : {"empty", "completed", "cancelled", "prepared", "accepted", "anchor-durable", "malformed", "torn",
            "foreign-malformed", "missing-root", "unaccepted", "generic", "missing-instance", "hardware", "gpt", "window", "retired", "instance"})
            RawAdmission(state);
        std::cout << "PASS groups=" << groups << " checks=" << checks << " simulatedAuthority=1 hardware=0\n";
        return 0;
    }
    catch (const std::exception& ex) { std::cerr << "FAIL checks=" << checks << " " << ex.what() << '\n'; return 1; }
}
