#include "ApfsContainerCatalog.h"
#include "TestFixtureBuilder.h"
#include <iostream>
#include <functional>
#include <limits>
#include <map>
#include <stdexcept>

using namespace apfsaccess::catalog;
using namespace apfsaccess::testfixture;

namespace {
std::size_t assertions = 0;
using MemorySource = VectorRandomAccessSource;
void Check(bool condition, const char* message) {
    ++assertions;
    if (!condition) throw std::runtime_error(message);
}
BuilderStore StrictSpec(std::size_t count = 1) {
    BuilderStore spec;
    spec.authoritative_checkpoint = true;
    spec.block_count = 256;
    spec.volumes.resize(count);
    for (std::size_t i = 0; i < count; ++i) spec.volumes[i].oid = 101 + i;
    return spec;
}
ApfsContainerCatalog Load(const BuilderStore& spec, CatalogLoadPolicy policy = CatalogLoadPolicy::StrictApple) {
    MemorySource source(BuildStoreImage(spec));
    ApfsContainerCatalog catalog;
    std::string error;
    if (!ApfsContainerCatalog::TryLoadImage(source, "fixture", "memory", catalog, error, policy))
        throw std::runtime_error(error);
    return catalog;
}
AppleCheckpointView View(const BuilderStore& spec) {
    auto catalog = Load(spec);
    const auto* view = catalog.TryGetAppleCheckpointView("apfs-store:raw");
    Check(view != nullptr, "strict view missing");
    return *view;
}
ApfsSharedSpaceProjection Space(const BuilderStore& spec) {
    auto catalog = Load(spec);
    ApfsSharedSpaceProjection out;
    std::string error;
    if (!catalog.TryProjectSharedSpace(spec.uuid_hex, out, error)) throw std::runtime_error(error);
    return out;
}
void Empty(const ApfsContainerCatalog& catalog) {
    Check(catalog.DiskId().empty() && catalog.DeviceIdentifier().empty() &&
        catalog.DiskGuid().empty() && catalog.DiskSizeBytes() == 0 &&
        catalog.Partitions().empty() && catalog.Stores().empty() &&
        catalog.Containers().empty() && !catalog.TryGetAppleCheckpointView("apfs-store:raw"),
        "rejected catalog published partial output");
}
void RejectedCatalogIsEmpty() {
    BuilderStore spec;
    spec.volumes[0].bad_checksum = true;
    MemorySource source(BuildStoreImage(spec));
    ApfsContainerCatalog catalog;
    std::string error;
    Check(!ApfsContainerCatalog::TryLoadImage(source, "fixture", "memory", catalog, error), "corruption must fail");
    Empty(catalog);
    catalog = Load(StrictSpec());
    BuilderImage image;
    image.stores = {StrictSpec(), StrictSpec()};
    image.stores[1].uuid_hex = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    image.stores[1].volumes[0].bad_checksum = true;
    MemorySource later_failure(BuildTestImage(image));
    Check(!ApfsContainerCatalog::TryLoadImage(later_failure, "fixture", "memory", catalog, error,
        CatalogLoadPolicy::StrictApple), "second store corruption must fail");
    Empty(catalog);
}
void FieldsAndBounds() {
    for (const std::size_t bs : {4096, 16384, 65536}) {
        BuilderVolume v;
        v.reserve_block_count = 0x1122334455667788ULL;
        v.quota_block_count = 0x8877665544332211ULL;
        v.file_system_allocated_blocks = 0x0123456789ABCDEFULL;
        v.total_blocks_allocated = 999;
        v.total_blocks_freed = 888;
        auto bytes = BuildApsb(v, 7, bs);
        const auto parsed = ParseApsb(bytes);
        Check(parsed.has_value(), "APSB fields parse");
        Check(parsed->space.reserve_block_count == v.reserve_block_count &&
            parsed->space.quota_block_count == v.quota_block_count &&
            parsed->space.allocated_block_count == v.file_system_allocated_blocks,
            "original APSB counters and endian layout");
        Check(parsed->xid == 7 && parsed->object_id == v.oid, "field extension preserves identity");
        bytes[0x48] ^= std::byte{1};
        Check(!ParseApsb(bytes), "changed reserve checksum rejected");
        bytes = BuildApsb(v, 7, bs);
        bytes.resize(0x410);
        FletcherForBlock(bytes, bytes.size());
        Check(!ParseApsb(bytes), "truncated APSB rejected");
        bytes = BuildApsb(v, 7, bs);
        PutU64LE(bytes, 8, 0);
        FletcherForBlock(bytes, bytes.size());
        Check(!ParseApsb(bytes), "zero APSB oid rejected");
        bytes = BuildApsb(v, 7, bs);
        PutU32LE(bytes, 0x18, kObjectTypeOmap);
        FletcherForBlock(bytes, bytes.size());
        Check(!ParseApsb(bytes), "wrong APSB type rejected");
    }
    const auto zero = ParseApsb(BuildApsb(BuilderVolume{}, 7, 4096));
    Check(zero && zero->space.reserve_block_count == 0 && zero->space.quota_block_count == 0 &&
        zero->space.allocated_block_count == 0, "zero fields are known zeros");
}
void ExactRoles() {
    const std::map<std::uint32_t, std::string> known = {
        {0,"none"},{1,"system"},{2,"user"},{4,"recovery"},{8,"vm"},{16,"preboot"},
        {32,"installer"},{0x40,"data"},{0x80,"baseband"},{0xC0,"update"},
        {0x100,"xart"},{0x140,"hardware"},{0x180,"backup"},{0x240,"enterprise"},{0x2C0,"prelogin"}};
    for (std::uint32_t raw = 0; raw <= 65535; ++raw) {
        const auto role = static_cast<std::uint16_t>(raw);
        const auto found = known.find(role);
        const auto expected = found == known.end() ? "unknown" : found->second;
        Check(RoleNameFor(role) == expected, "role enum must match exactly");
        Check(RolesFor(role) == std::vector<std::string>{role == 0 ? "data" : expected},
            "legacy role policy categories preserved");
    }
    auto spec = StrictSpec();
    for (auto raw : {0, 3, 0xC0, 0x180, 0x8000}) {
        spec.volumes[0].role = static_cast<std::uint16_t>(raw);
        auto catalog = Load(spec);
        const auto& volume = catalog.Containers()[0].volumes[0];
        Check(volume.role_raw == raw && volume.role_name == RoleNameFor(static_cast<std::uint16_t>(raw)),
            "catalog retains raw and truthful role name");
    }
}
BuilderStore Pair() {
    auto spec = StrictSpec(2);
    spec.volumes[0].role = 1;
    for (auto& v : spec.volumes) {
        v.group_hex = "11111111111111111111111111111111";
        v.features |= 0x10;
    }
    return spec;
}
void GroupStatus(const BuilderStore& spec, const char* expected) {
    const auto catalog = Load(spec);
    const auto& container = catalog.Containers()[0];
    Check(container.volumes[0].group_association_status == expected, "association status stays on volume");
    if (spec.volumes.size() == 1) {
        Check(container.groups.empty(), "singleton preserves existing catalog shape");
        return;
    }
    Check(container.groups.size() == 1, "group represented");
    const auto& group = container.groups[0];
    Check(group.container_uuid_hex == spec.uuid_hex && group.association_status == expected,
        "group status and container scope");
    if (group.association_status == "valid-system-data") {
        Check(group.system_volume_id == "apfs-vol:" + spec.uuid_hex + ":101" &&
            group.data_volume_id == "apfs-vol:" + spec.uuid_hex + ":102", "canonical backing identities");
    } else {
        Check(group.system_volume_id.empty() && group.data_volume_id.empty(), "invalid groups have no routing targets");
    }
}
void Groups() {
    GroupStatus(Pair(), "valid-system-data");
    auto spec = Pair(); spec.volumes.resize(1); GroupStatus(spec, "incomplete");
    spec = Pair(); spec.volumes[0].role = 0x40; GroupStatus(spec, "ambiguous");
    spec = Pair(); spec.volumes.push_back(spec.volumes[1]); spec.volumes.back().oid = 103;
    GroupStatus(spec, "ambiguous");
    spec = Pair(); spec.volumes[0].features &= ~0x10ULL; GroupStatus(spec, "malformed");
    for (auto role : {0, 3, 0x180, 0x8000}) {
        spec = Pair(); spec.volumes[1].role = static_cast<std::uint16_t>(role); GroupStatus(spec, "malformed");
    }
    spec = Pair(); spec.volumes[1].uuid_hex = std::string(32, '0'); GroupStatus(spec, "malformed");
    spec = StrictSpec(); spec.volumes[0].features |= 0x10;
    const auto catalog = Load(spec);
    Check(catalog.Containers()[0].groups.empty() && !catalog.Containers()[0].volumes[0].group_metadata_valid,
        "group flag with zero UUID explicitly malformed");
}
void GroupContainerScope() {
    BuilderImage spec;
    spec.stores = {Pair(), Pair()};
    spec.stores[1].uuid_hex = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    MemorySource source(BuildTestImage(spec));
    ApfsContainerCatalog catalog;
    std::string error;
    Check(ApfsContainerCatalog::TryLoadImage(source, "fixture", "memory", catalog, error,
        CatalogLoadPolicy::StrictApple), "two-container catalog");
    Check(catalog.Containers().size() == 2, "two separate containers");
    const auto& a = catalog.Containers()[0].groups[0];
    const auto& b = catalog.Containers()[1].groups[0];
    Check(a.group_uuid_hex == b.group_uuid_hex && a.container_uuid_hex != b.container_uuid_hex &&
        a.system_volume_id != b.system_volume_id, "same group UUID cannot bridge containers");
    ResolvedMountVolume resolved;
    Check(catalog.TryResolveVolume(spec.stores[1].uuid_hex, 102, resolved, error) &&
        resolved.container_uuid_hex == spec.stores[1].uuid_hex, "qualified identity grammar preserved");
}
void SpaceArithmetic() {
    auto spec = StrictSpec(3);
    spec.volumes[0].reserve_block_count = 16;
    spec.volumes[0].quota_block_count = 20;
    spec.volumes[1].reserve_block_count = 26;
    const auto out = Space(spec);
    const auto free = out.free.blocks;
    Check(out.container_uuid_hex == spec.uuid_hex && out.checkpoint_xid == spec.xid &&
        out.allocation_unit_bytes == 4096 && out.total.blocks == 256, "space checkpoint geometry");
    Check(out.total.bytes == 256 * 4096 && out.used.blocks + free == 256 &&
        out.free.bytes == free * 4096, "container accounting units");
    Check(out.volumes.size() == 3 && out.volumes[0].allocated.blocks == 6, "volume APSB allocated count");
    Check(out.volumes[0].available.blocks == 14 && out.volumes[0].sibling_reserve_remaining.blocks == 20,
        "quota and sibling reserve cap");
    Check(out.volumes[1].available.blocks == free - 10 &&
        out.volumes[2].available.blocks == free - 30, "unmet own reserves not double charged");
    Check(out.volumes[0].reserve->blocks == 16 && out.volumes[0].quota->blocks == 20,
        "configured reserve and quota retained");
    Check(!out.volumes[2].reserve && !out.volumes[2].quota, "zero reserve quota are unset");
    for (const auto& volume : out.volumes)
        Check(!volume.snapshot && !volume.purgeable, "unknown snapshot/purgeable not zero or free");
    const auto catalog = Load(spec);
    Check(catalog.Containers()[0].volumes[0].space->reserve_block_count == 16, "strict catalog known counters");
}
void ZeroAndQuotaCases() {
    auto spec = StrictSpec();
    auto out = Space(spec);
    Check(out.volumes[0].available.blocks == out.free.blocks, "unset quota does not mean zero available");
    spec.volumes[0].quota_block_count = 6;
    Check(Space(spec).volumes[0].available.blocks == 0, "quota exhausted");
    spec.volumes[0].quota_block_count = 1;
    Check(Space(spec).volumes[0].available.blocks == 0, "over-quota state saturates safely");
    spec.volumes[0].quota_block_count = 300;
    out = Space(spec);
    Check(out.volumes[0].available.blocks == out.free.blocks, "quota may exceed container capacity");
    spec = StrictSpec(); spec.volumes[0].reserve_block_count = 6;
    out = Space(spec);
    Check(out.volumes[0].available.blocks == out.free.blocks, "fulfilled reserve not charged twice");
    // Arithmetic-only boundary: the unchanged strict loader view contract is
    // covered separately with source fixtures; no synthetic view is media proof.
    auto view = View(StrictSpec());
    view.spaceman.devices[0].free_count = 0;
    std::string error;
    Check(TryProjectAppleSharedSpace(view, out, error) && out.free.blocks == 0 &&
        out.volumes[0].available.bytes == 0, "known full container has zero free");
    view.volumes[0].superblock.space.allocated_block_count = 0;
    Check(TryProjectAppleSharedSpace(view, out, error) && out.volumes[0].allocated.bytes == 0,
        "known zero allocation distinct from unknown");
}
void ProjectionRefusals() {
    const auto original = View(StrictSpec(2));
    using Edit = std::function<void(AppleCheckpointView&)>;
    const std::vector<std::pair<const char*, Edit>> cases = {
        {"SharedSpaceCheckpointInvalid", [](auto& v){ v.spaceman.devices[0].free_count = 257; }},
        {"SharedSpaceCheckpointInvalid", [](auto& v){ ++v.spaceman.object.xid; }},
        {"SharedSpaceCheckpointInvalid", [](auto& v){ v.container.superblock.block_size = 0; }},
        {"SharedSpaceCheckpointInvalid", [](auto& v){ v.container.superblock.block_count = 0; }},
        {"SharedSpaceMultiStoreUnsupported", [](auto& v){ v.spaceman.devices[1].block_count = 1; }},
        {"SharedSpaceVolumeSetInvalid", [](auto& v){ v.volumes.clear(); }},
        {"SharedSpaceVolumeSetInvalid", [](auto& v){ v.volumes.pop_back(); }},
        {"SharedSpaceVolumeIdentityInvalid", [](auto& v){ ++v.volumes[1].superblock.xid; }},
        {"SharedSpaceVolumeIdentityInvalid", [](auto& v){ v.container.superblock.fs_oids[1] = 101; v.volumes[1] = v.volumes[0]; }},
        {"SharedSpaceVolumeCountersInvalid", [](auto& v){ v.volumes[1].superblock.space.allocated_block_count = 257; }},
        {"SharedSpaceVolumeCountersInvalid", [](auto& v){ v.volumes[1].superblock.space.reserve_block_count = 257; }},
        {"SharedSpaceVolumeCountersInvalid", [](auto& v){ auto& s=v.volumes[1].superblock.space; s.reserve_block_count=9; s.quota_block_count=8; }},
        {"SharedSpaceReservesExceedFree", [](auto& v){ v.volumes[0].superblock.space.reserve_block_count = 256; }},
        {"SharedSpaceByteOverflow", [](auto& v){ v.volumes[1].superblock.space.quota_block_count = (std::numeric_limits<std::uint64_t>::max)(); }},
        {"SharedSpaceByteOverflow", [](auto& v){ v.container.superblock.block_count = v.spaceman.devices[0].block_count = (std::numeric_limits<std::uint64_t>::max)(); }}
    };
    for (const auto& [expected, edit] : cases) {
        auto view = original;
        edit(view);
        ApfsSharedSpaceProjection out;
        out.container_uuid_hex = "stale";
        out.volumes.resize(3);
        std::string error;
        Check(!TryProjectAppleSharedSpace(view, out, error) && error == expected, "malformed/overflow projection refused");
        Check(out.container_uuid_hex.empty() && out.volumes.empty() && out.total.bytes == 0 &&
            out.checkpoint_xid == 0, "projection failure cannot publish earlier volume output");
    }
}
void VerifiedFullContainer() {
    const auto spec = StrictSpec();
    auto bytes = BuildStoreImage(spec);
    auto view = View(spec);
    auto put_block = [&](std::uint64_t block, const std::vector<std::byte>& data) {
        std::copy(data.begin(), data.end(), bytes.begin() + block * spec.block_size);
    };
    for (const auto& chunk : view.spaceman.chunks) {
        auto bitmap = chunk.allocation_bitmap;
        for (std::uint32_t bit = 0; bit < chunk.block_count; ++bit)
            bitmap[bit / 8] |= static_cast<std::byte>(1u << (bit % 8));
        put_block(chunk.bitmap_block, bitmap);
        auto& cib = view.spaceman.devices[chunk.device_index].cibs[chunk.cib_index];
        PutU32LE(cib.bytes, 0x28 + chunk.index_in_cib * 0x20 + 0x14, 0);
    }
    for (auto& cib : view.spaceman.devices[0].cibs) {
        FletcherForBlock(cib.bytes, cib.bytes.size());
        put_block(cib.object.physical_block, cib.bytes);
    }
    auto sm = view.spaceman.bytes;
    PutU64LE(sm, 0x48, 0);
    FletcherForBlock(sm, sm.size());
    put_block(view.spaceman.object.physical_block, sm);
    MemorySource source(std::move(bytes));
    ApfsContainerCatalog catalog;
    ApfsSharedSpaceProjection out;
    std::string error;
    Check(ApfsContainerCatalog::TryLoadImage(source, "fixture", "memory", catalog, error,
        CatalogLoadPolicy::StrictApple), "strict full-container fixture loads");
    Check(catalog.TryProjectSharedSpace(spec.uuid_hex, out, error) &&
        out.free.bytes == 0 && out.used.blocks == out.total.blocks &&
        out.volumes[0].available.bytes == 0, "verified zero free is known and unavailable");
}
void StrictVersusLegacy() {
    BuilderStore spec;
    auto catalog = Load(spec, CatalogLoadPolicy::AllowLegacySynthetic);
    Check(!catalog.Containers()[0].volumes[0].space, "legacy counters not verified space");
    ApfsSharedSpaceProjection out;
    out.volumes.resize(1);
    std::string error;
    Check(!catalog.TryProjectSharedSpace(spec.uuid_hex, out, error) &&
        error == "SharedSpaceUnverifiedCheckpoint" && out.volumes.empty(), "legacy never invents free space");
    MemorySource source(BuildStoreImage(spec));
    Check(!ApfsContainerCatalog::TryLoadImage(source, "fixture", "memory", catalog, error,
        CatalogLoadPolicy::StrictApple), "strict refuses legacy fixture");
    Empty(catalog);
    spec = StrictSpec();
    catalog = Load(spec, CatalogLoadPolicy::AllowLegacySynthetic);
    Check(!catalog.TryProjectSharedSpace(spec.uuid_hex, out, error), "compatibility load cannot assert strict spaceman proof");
    catalog = Load(spec);
    Check(!catalog.TryProjectSharedSpace("missing", out, error) && error == "SharedSpaceContainerMissing",
        "space lookup exact container identity");
}
void ParserRegressions() {
    auto spec = StrictSpec(2);
    spec.volumes[1].xid_offset = 1;
    MemorySource future(BuildStoreImage(spec));
    ApfsContainerCatalog catalog;
    std::string error;
    Check(!ApfsContainerCatalog::TryLoadImage(future, "fixture", "memory", catalog, error,
        CatalogLoadPolicy::StrictApple), "future XID refused"); Empty(catalog);
    spec = StrictSpec(2); spec.volumes[1].uuid_hex = spec.volumes[0].uuid_hex = std::string(32, '5');
    MemorySource duplicate(BuildStoreImage(spec));
    Check(!ApfsContainerCatalog::TryLoadImage(duplicate, "fixture", "memory", catalog, error,
        CatalogLoadPolicy::StrictApple) && error.find("CatalogDuplicateVolumeUuid") == 0, "duplicate UUID refused"); Empty(catalog);
    spec = StrictSpec(0);
    MemorySource empty(BuildStoreImage(spec));
    Check(!ApfsContainerCatalog::TryLoadImage(empty, "fixture", "memory", catalog, error,
        CatalogLoadPolicy::StrictApple), "no-volume catalog refused"); Empty(catalog);
    spec = StrictSpec();
    MemorySource source(BuildStoreImage(spec));
    const auto view = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error, spec.xid);
    Check(view && view->container.superblock.xid == spec.xid, "exact XID reader preserved");
    Check(!LoadAppleCheckpointView(source, 0, source.SizeBytes(), error, spec.xid + 1), "missing exact XID refused");
    Check(!LoadAppleCheckpointView(source, 1, source.SizeBytes(), error), "store bounds preserved");
    // Tamper the free counter and recompute checksum: the ownership reader
    // must still reject the counter/bitmap disagreement before projection.
    const auto sm_block = view->spaceman.object.physical_block;
    auto sm_bytes = view->spaceman.bytes;
    PutU64LE(sm_bytes, 0x48, view->spaceman.devices[0].free_count - 1);
    FletcherForBlock(sm_bytes, sm_bytes.size());
    auto tampered = BuildStoreImage(spec);
    std::copy(sm_bytes.begin(), sm_bytes.end(), tampered.begin() + sm_block * spec.block_size);
    MemorySource corrupt(std::move(tampered));
    Check(!ApfsContainerCatalog::TryLoadImage(corrupt, "fixture", "memory", catalog, error,
        CatalogLoadPolicy::StrictApple), "verified checksum is insufficient for incorrect free counters"); Empty(catalog);
}
}
int main() {
    const std::vector<std::pair<const char*, void(*)()>> tests = {
        {"RejectedCatalogIsEmpty", RejectedCatalogIsEmpty}, {"FieldsAndBounds", FieldsAndBounds},
        {"ExactRoles", ExactRoles}, {"Groups", Groups}, {"GroupContainerScope", GroupContainerScope},
        {"SpaceArithmetic", SpaceArithmetic}, {"ZeroAndQuotaCases", ZeroAndQuotaCases},
        {"ProjectionRefusals", ProjectionRefusals}, {"StrictVersusLegacy", StrictVersusLegacy},
        {"VerifiedFullContainer", VerifiedFullContainer},
        {"ParserRegressions", ParserRegressions}};
    std::size_t failed = 0;
    for (const auto& [name, test] : tests) {
        try { test(); std::cout << "PASS " << name << '\n'; }
        catch (const std::exception& e) { ++failed; std::cerr << "FAIL " << name << ": " << e.what() << '\n'; }
    }
    std::cout << tests.size() - failed << '/' << tests.size() << " cases passed; " << assertions << " assertions\n";
    return failed ? 1 : 0;
}
