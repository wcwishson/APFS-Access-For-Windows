// Bind-validated two-tier spaceman ownership contract over the shared
// synthetic Fusion image family. Proves member binding (64 main + 32 tier2),
// generation binding, live-byte reading (patched free counts surface without
// rebind), and fail-closed torn/advanced members. Bitmap-level allocation
// truth is explicitly out of scope (needs macOS-created images); this gate
// owns geometry, accounting, area confinement, and generation only.
// Mount-free; in-memory sources only.
#include "ApfsFusionSpaceman.h"
#include "FusionTestFixture.h"
#include "TestFixtureBuilder.h"
#include <iostream>
#include <stdexcept>

using namespace apfsaccess::catalog;
using namespace apfsaccess::fusiontest;
using namespace apfsaccess::testfixture;
namespace
{
unsigned checks = 0, cases = 0;
void Check(bool ok, const std::string& why) { ++checks; if (!ok) throw std::runtime_error(why); }
void Pass(const std::string& name) { ++cases; std::cout << "PASS " << name << '\n'; }
bool SameView(const FusionSpacemanOwnership& left, const FusionSpacemanOwnership& right)
{
    return left.block_size == right.block_size && left.checkpoint_xid == right.checkpoint_xid &&
        left.main_.block_count == right.main_.block_count && left.main_.free_count == right.main_.free_count &&
        left.tier2_.block_count == right.tier2_.block_count && left.tier2_.free_count == right.tier2_.free_count &&
        left.combined_block_count == right.combined_block_count &&
        left.desc_base_block == right.desc_base_block && left.desc_block_count == right.desc_block_count &&
        left.data_base_block == right.data_base_block && left.data_block_count == right.data_block_count;
}
void CompleteGeometry()
{
    Fixture fixture;
    std::string error;
    auto store = fixture.Bind(error);
    Check(bool(store), "bind complete set: " + error);
    FusionSpacemanOwnership first, second;
    Check(LoadFusionSpacemanOwnership(*store, first, error), "load ownership: " + error);
    Check(first.block_size == fixture.bs, "block size bound");
    Check(first.checkpoint_xid == 20, "generation bound");
    Check(first.main_.block_count == 64 && first.tier2_.block_count == 32, "member binding");
    Check(first.combined_block_count == 96, "combined blocks");
    Check(first.main_.free_count <= 64 && first.tier2_.free_count <= 32, "free accounting bounded");
    Check(first.desc_base_block == 1 && first.desc_block_count == 4, "descriptor area main-local");
    Check(first.data_base_block == 8 && first.data_block_count == 4, "data area main-local");
    Check(LoadFusionSpacemanOwnership(*store, second, error) && SameView(first, second),
        "deterministic reload: " + error);
    Pass("complete geometry binds members, generation, and areas");
}
void LiveBytes()
{
    Fixture fixture;
    // Free counts patched in the live member bytes (resealed): the loader
    // must report them without a rebind, proving it reads bytes, not the
    // fixture template. Same API shape a macOS image will flow through.
    fixture.Edit(0, 8, [](Bytes& b) { Put(b, 0x48, std::uint64_t{50}); Put(b, 0x78, std::uint64_t{20}); });
    std::string error;
    auto store = fixture.Bind(error);
    Check(bool(store), "bind patched set: " + error);
    FusionSpacemanOwnership view;
    Check(LoadFusionSpacemanOwnership(*store, view, error), "load patched ownership: " + error);
    Check(view.main_.free_count == 50 && view.tier2_.free_count == 20, "live free accounting surfaces");
    Pass("loader reads live member bytes");
}
void TornMemberRefuses()
{
    Fixture fixture;
    std::string error;
    auto store = fixture.Bind(error);
    Check(bool(store), "bind before tear: " + error);
    // Tier-2 free count driven past its member size after bind (the single
    // shared spaceman copy lives at main member block 8).
    fixture.Edit(0, 8, [](Bytes& b) { Put(b, 0x78, std::uint64_t{33}); });
    FusionSpacemanOwnership view;
    Check(!LoadFusionSpacemanOwnership(*store, view, error) &&
        error == "FusionOwnershipMemberGeometryMismatch", "torn member admitted: " + error);
    Pass("torn member fails closed");
}
void AdvancedGenerationRefuses()
{
    Fixture fixture;
    std::string error;
    auto store = fixture.Bind(error);
    Check(bool(store), "bind before advance: " + error);
    // The mapped spaceman object moves to a newer generation out from under
    // the pinned checkpoint: exact-XID read must refuse, never select it.
    fixture.Edit(0, 8, [](Bytes& b) { Put(b, 0x10, std::uint64_t{21}); });
    FusionSpacemanOwnership view;
    Check(!LoadFusionSpacemanOwnership(*store, view, error), "advanced generation admitted");
    Check(error.rfind("FusionOwnershipSpacemanUnreadable:", 0) == 0, "exact refusal: " + error);
    Pass("advanced generation fails closed");
}
void ZeroMutation()
{
    Fixture fixture;
    const auto before_main = fixture.sources[0]->bytes;
    const auto before_tier = fixture.sources[1]->bytes;
    std::string error;
    auto store = fixture.Bind(error);
    Check(bool(store), "bind for purity probe: " + error);
    FusionSpacemanOwnership view;
    Check(LoadFusionSpacemanOwnership(*store, view, error), "load for purity probe: " + error);
    Check(fixture.sources[0]->bytes == before_main && fixture.sources[1]->bytes == before_tier,
        "loader mutated member bytes");
    Pass("ownership load is side-effect free");
}
} // namespace
int main()
{
    try
    {
        CompleteGeometry(); LiveBytes(); TornMemberRefuses(); AdvancedGenerationRefuses(); ZeroMutation();
        std::cout << "PASS " << cases << " cases, " << checks << " checks\n";
        return 0;
    }
    catch (const std::exception& e) { std::cerr << "FAIL after " << cases << " cases, " << checks << " checks: " << e.what() << '\n'; return 1; }
}
