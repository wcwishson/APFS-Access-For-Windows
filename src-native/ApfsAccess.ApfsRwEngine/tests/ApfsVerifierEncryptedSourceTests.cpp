#include "ApfsVerifierEncryptedSource.h"
#include "ApfsReadOnlyMetadataAdmission.h"
#include "AppleVolumeTransaction.h"
#include "TestFixtureBuilder.h"
#include <iostream>

using namespace apfsaccess::catalog;
namespace tf = apfsaccess::testfixture;
namespace rw = apfsaccess::rw;
namespace
{
unsigned checks = 0;
void Check(bool value, const char* message) { ++checks; if (!value) throw std::runtime_error(message); }
struct Held final : ImmutableEncryptedReadSource
{
    std::shared_ptr<ApfsReadBudget> budget = std::make_shared<ApfsReadBudget>(20, 81920, 100, 81920);
    std::uint64_t revision = 1;
    std::uint64_t SizeBytes() const override { return 4096; }
    std::string SourceIdentity() const override { return "bounded-held-source"; }
    std::uint64_t Revision() const override { return revision; }
    std::shared_ptr<ApfsReadBudget> ReadBudget() const override { return budget; }
    std::optional<EncryptedRuntimeReadLimits> RuntimeReadLimits() const override { return EncryptedRuntimeReadLimits{}; }
    bool Read(std::uint64_t at, std::size_t size, std::vector<std::byte>& out) const override
    {
        out.clear(); if (!budget->Read(size) || at > SizeBytes() || size > SizeBytes()-at) return false;
        out.assign(size, std::byte{0x5A}); return true;
    }
};
}
int main() try
{
    {
        auto held = std::make_shared<Held>(); VerificationScope scope; scope.max_reads = 2;
        ApfsVerifierEncryptedSource source(held, scope, [] { return true; }); std::vector<std::byte> bytes;
        Check(!source.RuntimeReadLimits() && source.ReadBudget() == held->budget, "host runtime allowance leaked into verification");
        Check(source.SourceIdentity() == held->SourceIdentity() && source.Revision() == 1, "held identity changed");
        Check(source.Read(0, 4096, bytes) && source.Read(0, 4096, bytes), "shared cumulative allowance");
        Check(!source.Read(0, 1, bytes) && bytes.empty() && held->budget->Failed(), "read budget failure not sticky");
        VerificationScope larger;
        ApfsVerifierEncryptedSource retry(held, larger, [] { return true; });
        Check(!retry.Read(0, 1, bytes) && bytes.empty(), "new wrapper reset poisoned source allowance");
    }
    for (unsigned n = 0; n < 2; ++n)
    {
        auto held = std::make_shared<Held>(); VerificationScope scope;
        ApfsVerifierEncryptedSource source(held, scope, [n]() -> bool { if (n) throw std::runtime_error("deadline"); return false; });
        std::vector<std::byte> bytes(4);
        Check(!source.Read(0, 4, bytes) && bytes.empty() && held->budget->Failed(), "deadline/callback did not close read");
        Check(held->budget->Consumed().reads == 0, "expired deadline dispatched backing read");
    }
    tf::BuilderVolume spec; spec.fs_flags = kFsFlagOneKey;
    auto original = tf::BuildApsb(spec, 7, 4096);
    for (unsigned n = 0; n < 6; ++n)
    {
        auto bytes = original;
        if (n == 0) { tf::PutU32LE(bytes, 0x414, kObjectPhysical | kObjectTypeBtree); tf::PutU32LE(bytes, 0x410, kObjectPhysical | kObjectTypeBtree); }
        if (n == 1) tf::PutU64LE(bytes, 0x418, 55);
        if (n == 2) tf::PutU64LE(bytes, 0x400, 55);
        if (n == 3) tf::PutU32LE(bytes, 0x414, 0x40000003);
        if (n == 4) tf::PutU64LE(bytes, 0x108, kFsFlagUnencrypted);
        Check(tf::FletcherForBlock(bytes, 4096), "checksum fixture");
        if (n == 5) bytes[8] ^= std::byte{1};
        const auto volume = ParseApsb(n == 5 ? original : bytes); Check(volume.has_value(), "canonical volume fixture");
        std::string error;
        const bool result = CheckAppleReadOnlyOneKeyInactiveTreeDefaults(bytes, *volume, error);
        Check(result == (n == 0), "explicit ONEKEY inactive facts admitted malformed/other flags");
        Check(CheckAppleReadOnlyInactiveTreeDefaults(bytes, *volume, error) == (n == 4), "ordinary inactive admission changed");
        NxSuperblock nx;
        if (volume->fs_flags == kFsFlagOneKey)
            Check(!rw::CheckAppleVolumeWriteFeatures(nx, *volume, error), "ONEKEY observational helper promoted mutation admission");
    }
    std::cout << "PASS 9 cases, " << checks << " checks; bounded source and strict inactive-tree profiles\n"; return 0;
}
catch (const std::exception& e) { std::cout << "FAIL " << e.what() << '\n'; return 1; }
