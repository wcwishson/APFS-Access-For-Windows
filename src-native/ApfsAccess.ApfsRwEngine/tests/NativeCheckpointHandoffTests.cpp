#include "NativeApfsReader.h"
#include "TestFixtureBuilder.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>

namespace apfsaccess::rw
{
struct NativeCheckpointHandoffTestAccess
{
    using Context = NativeApfsReader::ValidatedCheckpointProjection;
    static bool Project(Context& context, NativeApfsVolumeProjection& projection, std::wstring& error)
    { return NativeApfsReader::TryLoadVolumeProjectionFromValidatedCheckpoint(context, projection, error); }
    static bool Load(MetadataStore& store, const catalog::RandomAccessSource& source)
    { return store.LoadVolumeState(source); }
    static bool PublicObjectMapIgnoresUnfreshView(MetadataStore& store, std::uint64_t xid)
    {
        store.authoritative_apple_checkpoint_view_->container.superblock.xid += 100;
        return store.LoadObjectMap() && store.last_committed_xid_ == xid;
    }
};
}

namespace
{
using namespace apfsaccess::catalog;
using namespace apfsaccess::rw;
namespace fixture = apfsaccess::testfixture;
using Access = NativeCheckpointHandoffTestAccess;
constexpr auto Unlimited = (std::numeric_limits<std::uint64_t>::max)();

bool Check(bool condition, const char* message)
{
    if (!condition) std::cerr << "[FAIL] " << message << '\n';
    return condition;
}

struct Image
{
    std::filesystem::path path;
    std::shared_ptr<BlockDevice> device;
    BlockDevice::StableImageIdentity identity;
    explicit Image(const std::vector<std::byte>& bytes)
    {
        const auto directory = std::filesystem::temp_directory_path() / "apfs-checkpoint-handoff";
        std::filesystem::create_directories(directory);
        static unsigned serial = 0;
        path = directory / ("handoff-" + std::to_string(GetCurrentProcessId()) + "-" + std::to_string(++serial) + ".img");
        {
            std::ofstream stream(path, std::ios::binary);
            stream.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
            if (!stream.good()) throw std::runtime_error("fixture write failed");
        }
        std::string error;
        device = BlockDevice::OpenStableReadOnlyImage(path.wstring(), error);
        if (!device || !device->QueryStableReadOnlyImageIdentity(identity))
            throw std::runtime_error("fixture lease failed: " + error);
    }
    ~Image()
    {
        device.reset();
        std::error_code error;
        std::filesystem::remove(path, error);
    }
};

class CountingSource final : public RandomAccessSource
{
public:
    explicit CountingSource(const BlockDevice& device) : device(device) {}
    std::uint64_t SizeBytes() const override { return device.GetGeometry().total_bytes + size_adjustment; }
    bool Read(std::uint64_t offset, std::size_t size, std::vector<std::byte>& out) const override
    { ++reads; return device.Read(offset, size, out) && out.size() == size; }
    const BlockDevice& device;
    mutable std::uint64_t reads = 0;
    std::uint64_t size_adjustment = 0;
};

fixture::BuilderStore Spec(bool sibling = false)
{
    fixture::BuilderStore spec;
    spec.authoritative_checkpoint = true;
    if (sibling) spec.volumes[0].xid_offset = -1;
    return spec;
}

MetadataStore::VolumeContext Expected(const Image& image, const AppleCheckpointView& checkpoint)
{
    MetadataStore::VolumeContext expected;
    expected.device_path = image.path.wstring();
    expected.volume_object_id = checkpoint.volumes.front().superblock.object_id;
    expected.container_uuid_hex = checkpoint.container.superblock.uuid_hex;
    expected.volume_uuid_hex = checkpoint.volumes.front().superblock.uuid_hex;
    expected.allow_legacy_scaffold_for_fixtures = false;
    expected.integrity_check_on_mount = false;
    return expected;
}

bool Empty(const NativeApfsVolumeProjection& projection)
{
    return projection.checkpoint_xid == 0 && projection.volume_object_id == 0 &&
        projection.inodes.empty() && projection.btree_records.empty() &&
        projection.attribute_stream_extents.empty();
}

void ObserveDevice(const char* label, const BlockDevice& device)
{
    // The runner parses this existing structured counter, covering every adapter
    // and cache hit rather than only reads through CountingSource.
    std::cout << label << '=' << device.PerformanceJson() << '\n';
}

bool TestReadsAndInvocation()
{
    Image image(fixture::BuildStoreImage(Spec()));
    CountingSource raw(*image.device);
    std::string error;
    auto checkpoint = LoadAppleCheckpointView(raw, 0, raw.SizeBytes(), error);
    if (!Check(checkpoint.has_value(), "complete checkpoint control")) return false;
    const auto validation_reads = raw.reads;
    auto expected = Expected(image, *checkpoint);
    NativeApfsVolumeProjection projection, ordinary;
    std::wstring native_error;
    Access::Context context{*image.device, raw, *checkpoint, expected,
        checkpoint->container.superblock.xid, image.identity, {}};
    ObserveDevice("handoffDeviceBefore", *image.device);
    bool ok = Check(Access::Project(context, projection, native_error) && raw.reads == validation_reads + 1,
        "handoff performs one FS read with no initial recatalog");
    ObserveDevice("handoffDeviceAfter", *image.device);
    const auto reads = raw.reads;
    ok &= Check(!Access::Project(context, ordinary, native_error) && Empty(ordinary) && raw.reads == reads &&
        native_error == L"NativeApfsCheckpointHandoffConsumed", "context is single use");
    ok &= Check(NativeApfsReader::TryLoadVolumeProjection(*image.device, expected.volume_object_id,
        ordinary, native_error, checkpoint->container.superblock.xid) &&
        ordinary.checkpoint_xid == projection.checkpoint_xid && ordinary.root_tree_block == projection.root_tree_block &&
        ordinary.inodes.size() == projection.inodes.size() && ordinary.btree_records.size() == projection.btree_records.size(),
        "public exact-XID projection remains identical");
    CountingSource metadata_source(*image.device);
    MetadataStore metadata(expected, image.device);
    ObserveDevice("metadataDeviceBefore", *image.device);
    ok &= Check(Access::Load(metadata, metadata_source) && metadata_source.reads == validation_reads + 1,
        "MetadataStore wires handoff only after its same-invocation full load");
    ObserveDevice("metadataDeviceAfter", *image.device);
    ok &= Check(Access::PublicObjectMapIgnoresUnfreshView(metadata, checkpoint->container.superblock.xid),
        "persistent view presence cannot authorize public LoadObjectMap reuse");
    MetadataStore auxiliary(expected, image.device);
    ok &= Check(auxiliary.LoadContainerSuperblocks() && auxiliary.LoadObjectMap(), "allocator-read control prepares");
    ObserveDevice("allocatorDeviceBefore", *image.device);
    ok &= Check(auxiliary.LoadSpacemanState(), "unchanged allocator stage control");
    ObserveDevice("allocatorDeviceAfter", *image.device);
    std::cout << "validationReads=" << validation_reads << " handoffAdditionalReads=1 metadataReads="
        << metadata_source.reads << '\n';
    return ok;
}

bool TestBindingsAndSibling()
{
    Image image(fixture::BuildStoreImage(Spec(true)));
    CountingSource raw(*image.device);
    std::string error;
    const auto checkpoint = LoadAppleCheckpointView(raw, 0, raw.SizeBytes(), error);
    if (!Check(checkpoint.has_value(), "sibling checkpoint control")) return false;
    const auto expected = Expected(image, *checkpoint);
    bool ok = true;
    for (unsigned failure = 0; failure < 8; ++failure)
    {
        auto view = *checkpoint;
        auto binding = expected;
        auto identity = std::optional(image.identity);
        auto xid = view.container.superblock.xid;
        raw.size_adjustment = 0;
        if (failure == 0) binding.container_uuid_hex = "wrong-container";
        if (failure == 1) binding.volume_uuid_hex = "wrong-volume";
        if (failure == 2) binding.device_offset_bytes = 4096;
        if (failure == 3) ++xid;
        if (failure == 4) raw.size_adjustment = 4096;
        if (failure == 5) identity.reset();
        if (failure == 6) view.container.superblock_bytes[64] ^= std::byte{1};
        if (failure == 7) view.volumes.push_back(view.volumes.front());
        NativeApfsVolumeProjection projection;
        projection.checkpoint_xid = 123;
        projection.inodes.resize(1);
        std::wstring native_error;
        const auto reads = raw.reads;
        Access::Context context{*image.device, raw, view, binding, xid, identity, {}};
        ok &= Check(!Access::Project(context, projection, native_error) && Empty(projection) && raw.reads == reads,
            "invalid identity/window/generation/lease/duplicate binding refuses before reads");
    }
    raw.size_adjustment = 0;
    NativeApfsVolumeProjection projection;
    std::wstring native_error;
    Access::Context context{*image.device, raw, *checkpoint, expected,
        checkpoint->container.superblock.xid, image.identity, {}};
    ok &= Check(Access::Project(context, projection, native_error) &&
        projection.checkpoint_xid == checkpoint->container.superblock.xid && !projection.inodes.empty() &&
        projection.inodes.front().xid == checkpoint->volumes.front().superblock.xid &&
        projection.inodes.front().xid < projection.checkpoint_xid, "sibling NXSB advance preserves APSB inode generation");
    return ok;
}

bool TestCumulativeBudget()
{
    Image image(fixture::BuildStoreImage(Spec()));
    CountingSource control(*image.device);
    std::string error;
    const auto view = LoadAppleCheckpointView(control, 0, control.SizeBytes(), error);
    if (!Check(view.has_value(), "budget checkpoint control")) return false;
    const auto expected = Expected(image, *view);
    bool ok = true;
    for (unsigned failure = 0; failure < 3; ++failure)
    {
        CountingSource raw(*image.device);
        auto budget = std::make_shared<ApfsReadBudget>(control.reads + (failure == 0 ? 1 : 0),
            Unlimited, Unlimited, Unlimited);
        BudgetedRandomAccessSource source(raw, budget);
        auto checkpoint = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
        if (!Check(checkpoint.has_value(), "validation spends the projection's shared budget")) return false;
        if (failure == 2) budget->LimitRemainingTo(Unlimited, Unlimited, 0, 0);
        NativeApfsVolumeProjection projection;
        std::wstring native_error;
        Access::Context context{*image.device, source, *checkpoint, expected,
            checkpoint->container.superblock.xid, image.identity, {}};
        if (failure == 0)
            ok &= Check(Access::Project(context, projection, native_error) && !budget->Failed() &&
                raw.reads == control.reads + 1, "one extra read allowance succeeds without a recatalog");
        else
        {
            const auto reads = raw.reads;
            ok &= Check(!Access::Project(context, projection, native_error) && Empty(projection) &&
                raw.reads == reads && native_error == (failure == 1 ? L"ApfsReadBudgetSourceLimit" : L"ApfsReadBudgetRecordLimit"),
                "spent read/materialization allowance refuses and clears outputs");
            Access::Context retry{*image.device, source, *checkpoint, expected,
                checkpoint->container.superblock.xid, image.identity, {}};
            ok &= Check(!Access::Project(retry, projection, native_error) && raw.reads == reads && Empty(projection),
                "fresh context cannot replenish a sticky budget");
        }
    }
    return ok;
}
}

int main()
{
    try
    {
        const bool reads = TestReadsAndInvocation();
        const bool bindings = TestBindingsAndSibling();
        const bool budget = TestCumulativeBudget();
        std::cout << "reads=" << reads << " bindings=" << bindings << " budget=" << budget << '\n';
        return reads && bindings && budget ? 0 : 1;
    }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
