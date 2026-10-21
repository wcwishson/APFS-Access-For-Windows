#pragma once

#include "ApfsContainerCatalog.h"
#include "BlockDevice.h"
#include <array>
#include <atomic>
#include <functional>
#include <memory>
#include <map>

namespace apfsaccess::rw { class ApfsFusionReadSession; class ApfsFusionImageWriteSession; }

namespace apfsaccess::catalog
{
inline constexpr std::uint64_t kFusionTier2ByteAddress = 0x4000000000000000ULL;
inline constexpr std::uint64_t kNxIncompatFusion = 0x100;

// The Apple 2020 reference's role prose conflicts with original implementations.
// No autodetection or default interpretation: the caller must select this profile.
enum class FusionRoleConvention { Unspecified, LinuxApfsLastByteLowBit };
enum class FusionMemberRole { Main, Tier2 };
// Coverage, not a complete filesystem/allocator validation or mount capability.
enum class FusionReadLayout { CleanAnchorsEmptyCachesMainCheckpoint };

using FusionImageIdentity = rw::BlockDevice::StableImageIdentity;

struct FusionImageMember
{
    std::wstring path;
    FusionImageIdentity exact_identity;
    std::string stable_store_id;
    FusionMemberRole role = FusionMemberRole::Main;
    std::uint64_t store_offset = 0;
    std::uint64_t store_size = 0;
};

struct FusionBindRequest
{
    // Exactly two distinct references; input order never determines device role.
    std::vector<FusionImageMember> members;
    std::string container_uuid_hex;
    std::string fusion_uuid_hex; // canonical main UUID, role bit clear
    std::uint64_t checkpoint_xid = 0; // exact complete generation; no fallback
    FusionRoleConvention convention = FusionRoleConvention::Unspecified;
    std::shared_ptr<ApfsReadBudget> budget;
    std::shared_ptr<const std::atomic<bool>> cancellation;
};

struct FusionRoute
{
    FusionMemberRole role = FusionMemberRole::Main;
    std::string stable_store_id;
    std::uint64_t member_offset = 0; // relative to partition/store start
    std::uint64_t image_offset = 0;
    std::uint64_t length = 0;
};
struct FusionExtent
{
    std::uint64_t physical_block = 0;
    std::uint64_t offset_in_block = 0;
    std::size_t length = 0;
};

// Single-threaded immutable read session. Only held regular local image leases
// can enter the production factory, using BlockDevice's stable read-only API.
// Both leases and identities are checked for every read, including unused tier.
// Requires a natively validated empty middle tree and version-0x70 empty WBC.
// Nonempty caches, lagging anchors, and non-main checkpoint areas refuse binding.
class ApfsFusionStore final : public RandomAccessSource
{
public:
    static bool InspectImage(const std::wstring& path, FusionImageIdentity& out,
        std::string& error);
    static std::unique_ptr<ApfsFusionStore> BindImages(const FusionBindRequest& request,
        std::string& error, unsigned* unavailable_members = nullptr);
    ~ApfsFusionStore() override;
    ApfsFusionStore(const ApfsFusionStore&) = delete;
    ApfsFusionStore& operator=(const ApfsFusionStore&) = delete;

    // Encoded address-space span, NOT capacity. The gap always rejects reads.
    std::uint64_t SizeBytes() const override;
    std::uint64_t CapacityBytes() const noexcept;
    static constexpr FusionReadLayout SupportedLayout() noexcept
    { return FusionReadLayout::CleanAnchorsEmptyCachesMainCheckpoint; }
    std::shared_ptr<ApfsReadBudget> ReadBudget() const override;
    bool Read(std::uint64_t encoded_byte_address, std::size_t size,
        std::vector<std::byte>& out) const override;
    bool MapPhysical(std::uint64_t physical_block, std::uint64_t offset_in_block,
        std::uint64_t length, FusionRoute& out, std::string& error) const;
    bool ReadExtents(const std::vector<FusionExtent>& extents,
        std::vector<std::byte>& out, std::string& error) const;
    // Header-bearing, single-block native metadata; checks checksum, type, OID,
    // and caller-specified version against the pinned container checkpoint.
    bool ReadMetadata(std::uint64_t physical_block, std::uint32_t exact_type,
        std::uint32_t exact_subtype, std::uint64_t exact_oid, std::uint64_t exact_xid,
        std::vector<std::byte>& out, std::string& error) const;
    // Routing identity only: volumes/groups are not enumerated by this layer,
    // and this descriptor is not a complete catalog or a health/RW assertion.
    const ApfsContainerDescriptor& Container() const noexcept;
    const std::array<ApfsPhysicalStoreDescriptor, 2>& Members() const noexcept;
    const FusionImageMember& Binding(FusionMemberRole role) const;
    const ContainerCheckpointView& Checkpoint() const noexcept;
    const std::string& LastError() const noexcept;

    bool CheckAvailable(std::string& error) const;
    // True when bind tolerated an exact tier-ahead-by-one crash skew (the
    // main anchor stays authoritative). Lets status surfaces report the
    // pending mirror heal truthfully instead of showing a fully synced set.
    [[nodiscard]] bool TierAheadSkewTolerated() const noexcept;    unsigned UnavailableMembers() const noexcept;
    // Retains both held leases. Every cached catalog access must invoke it.
    std::function<bool(std::string&)> RetainAvailabilityLease() const;
    void Cancel() const;

    // No defensible durable multi-device publication protocol is established by
    // this candidate. This explicit transaction entry point always refuses,
    // before any write handle, payload dispatch, flush, or checkpoint publish.
    bool BeginOrderedWriteTransaction(std::uint64_t next_xid, std::string& error) const;

#ifdef APFS_FUSION_STORE_TESTING
    // Pure syntax probe: never queries or opens any path.
    static bool TestOrdinaryLocalImagePathSyntax(const std::wstring& path);
    struct TestMember
    {
        std::shared_ptr<RandomAccessSource> source;
        std::function<bool()> verify_unchanged;
    };
    // Test-only injection; excluded from the production object/API build.
    static std::unique_ptr<ApfsFusionStore> BindTestSources(const FusionBindRequest& request,
        const std::vector<TestMember>& sources, std::string& error, unsigned* unavailable_members = nullptr);
#endif
private:
    friend class rw::ApfsFusionReadSession;
    friend class rw::ApfsFusionImageWriteSession;
    // Only the image owner can bind its existing exclusive leases. No path
    // reopen or injected source can replace a member between read and write.
    static std::unique_ptr<ApfsFusionStore> BindHeldImages(const FusionBindRequest& request,
        const std::array<std::shared_ptr<rw::BlockDevice>, 2>& devices,
        std::shared_ptr<const std::atomic<bool>> owner_cancellation,
        std::string& error, unsigned* unavailable_members = nullptr,
        const std::map<std::uint64_t, std::vector<std::byte>>* recovery_preimage = nullptr);
    // Borrowed, uncopyable reservation; only the admitted session can create it
    // after charging an operation allowance. Never changes ReadBudget().
    class RuntimeRead final {
        friend class rw::ApfsFusionReadSession;
        friend class ApfsFusionStore;
        RuntimeRead(const ApfsFusionStore& source, std::uint64_t offset, std::size_t size)
            : source_(source), offset_(offset), size_(size) {}
        RuntimeRead(const RuntimeRead&) = delete;
        const ApfsFusionStore& source_;
        std::uint64_t offset_; std::size_t size_;
    };
    bool RuntimeCapable() const noexcept;
    bool ReadRuntime(const RuntimeRead& request, std::vector<std::byte>& out) const;
    struct Impl;
    explicit ApfsFusionStore(std::unique_ptr<Impl> impl);
    static std::unique_ptr<ApfsFusionStore> FinishBind(std::unique_ptr<Impl> impl,
        const FusionBindRequest& request, std::string& error, unsigned* unavailable_members = nullptr);
    std::shared_ptr<Impl> impl_;
};
} // namespace apfsaccess::catalog
