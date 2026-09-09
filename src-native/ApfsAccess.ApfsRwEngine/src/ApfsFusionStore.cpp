#include "ApfsFusionStore.h"
// Format facts (independent implementation, no external driver code linked):
// Apple File System Reference (2020-06-22), nx_superblock_t and Fusion, pp. 34,
// 172-173: https://developer.apple.com/support/downloads/Apple-File-System-Reference.pdf
// Original behavior cross-checks: linux-apfs/apfsprogs at
// 3721463ba7f539e532907bc1d10ed5b9a97d0449, apfsck/{super,btree,spaceman}.c;
// linux-apfs/linux-apfs-rw at 8264a1a35b52c2b2238ebc5c1b853c2c90b412b2,
// super.c; sgan81/apfs-fuse at 66b86bd525e8cb90f9012543be89b1f092b75cf3,
// ApfsLib/ApfsContainer.cpp. Role prose disagreement is an explicit API policy.
#include <algorithm>
#include <limits>
#include <stdexcept>
#include <utility>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace apfsaccess::catalog
{
namespace
{
constexpr std::size_t kMaxRead = 16 * 1024 * 1024;
bool Fail(std::string& error, const char* reason) { error = reason; return false; }
bool HexUuid(const std::string& value)
{
    return value.size() == 32 && value != std::string(32, '0') &&
        std::all_of(value.begin(), value.end(), [](char c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); });
}
bool RequestValid(const FusionBindRequest& r, std::string& error)
{
    if (r.members.size() != 2) return Fail(error, "FusionCompleteTwoMemberSetRequired");
    if (!r.budget || r.budget->Failed()) return Fail(error, "FusionLiveReadBudgetRequired");
    if (r.convention != FusionRoleConvention::LinuxApfsLastByteLowBit)
        return Fail(error, "FusionRoleConventionUnestablished");
    if (!HexUuid(r.container_uuid_hex) || !HexUuid(r.fusion_uuid_hex) || !r.checkpoint_xid)
        return Fail(error, "FusionExactContainerAndGenerationRequired");
    if (r.members[0].role == r.members[1].role)
        return Fail(error, "FusionDuplicateOrMissingRole");
    for (const auto& m : r.members)
    {
        if (m.role != FusionMemberRole::Main && m.role != FusionMemberRole::Tier2)
            return Fail(error, "FusionUnknownMemberRole");
        if (m.stable_store_id.empty() || m.stable_store_id.size() > 256 ||
            m.exact_identity.file_id == std::array<std::byte, 16>{} ||
            m.store_size < 4096 || m.store_size >= kFusionTier2ByteAddress ||
            m.store_offset > m.exact_identity.size_bytes ||
            m.store_size > m.exact_identity.size_bytes - m.store_offset)
            return Fail(error, "FusionMemberIdentityOrRangeInvalid");
    }
    if (r.members[0].stable_store_id == r.members[1].stable_store_id ||
        (r.members[0].exact_identity.volume_serial == r.members[1].exact_identity.volume_serial &&
         r.members[0].exact_identity.file_id == r.members[1].exact_identity.file_id))
        return Fail(error, "FusionDuplicateMemberIdentity");
    return true;
}

#ifdef _WIN32
// Syntax only: artifact placement is independent of runtime drive selection.
// No filesystem call here, including for rejected device/UNC/ADS spellings.
bool OrdinaryLocalImagePathSyntax(const std::wstring& path)
{
    if (path.size() < 4 || !((path[0] >= L'A' && path[0] <= L'Z') ||
        (path[0] >= L'a' && path[0] <= L'z')) ||
        path[1] != L':' || path[2] != L'\\' ||
        path.find_first_of(L":/*?\"<>|", 3) != std::wstring::npos ||
        std::any_of(path.begin(), path.end(), [](wchar_t c) { return c < 32; })) return false;
    std::size_t begin = 3;
    while (begin < path.size())
    {
        auto end = path.find(L'\\', begin);
        if (end == std::wstring::npos) end = path.size();
        const auto part = path.substr(begin, end - begin);
        if (part.empty() || part == L"." || part == L".." || part.back() == L'.' || part.back() == L' ')
            return false;
        auto stem = part.substr(0, part.find(L'.'));
        std::transform(stem.begin(), stem.end(), stem.begin(), [](wchar_t c) -> wchar_t {
            return c >= L'a' && c <= L'z' ? static_cast<wchar_t>(c - (L'a' - L'A')) : c; });
        if (stem == L"CON" || stem == L"PRN" || stem == L"AUX" || stem == L"NUL" ||
            stem == L"CONIN$" || stem == L"CONOUT$" ||
            (stem.size() == 4 && (stem.rfind(L"COM", 0) == 0 || stem.rfind(L"LPT", 0) == 0))) return false;
        begin = end + 1;
    }
    return path.back() != L'\\';
}
class LockedImage final : public RandomAccessSource
{
public:
    explicit LockedImage(const std::wstring& path)
    {
        if (!OrdinaryLocalImagePathSyntax(path)) return;
        const auto drive_type = GetDriveTypeW(path.substr(0, 3).c_str());
        if (drive_type != DRIVE_FIXED && drive_type != DRIVE_REMOVABLE &&
            drive_type != DRIVE_CDROM && drive_type != DRIVE_RAMDISK) return;
        // Lock each directory from the drive root down before opening its child.
        // OPEN_REPARSE_POINT refuses junctions themselves; held sharing denial
        // prevents a checked ancestor being renamed/replaced or made a reparse
        // point between validation and the final image open.
        for (std::size_t end = 2; end != std::wstring::npos; end = path.find(L'\\', end + 1))
        {
            const auto prefix = path.substr(0, end == 2 ? 3 : end);
            const auto handle = CreateFileW(prefix.c_str(), FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
            if (handle == INVALID_HANDLE_VALUE) return;
            directories_.push_back(handle);
            FILE_ATTRIBUTE_TAG_INFO info{};
            if (!GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &info, sizeof(info)) ||
                !(info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
                (info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) return;
        }
        std::string error;
        device_ = rw::BlockDevice::OpenStableReadOnlyImage(path, error);
        if (!Identity(identity_)) device_.reset();
    }
    ~LockedImage() override
    {
        device_.reset();
        for (auto handle : directories_) CloseHandle(handle);
    }
    bool Identity(FusionImageIdentity& out) const
    {
        out = {};
        return device_ && device_->QueryStableReadOnlyImageIdentity(out) &&
            out.file_id != std::array<std::byte, 16>{};
    }
    bool Verify() const { FusionImageIdentity now; return Identity(now) && now == identity_; }
    std::uint64_t SizeBytes() const override { return identity_.size_bytes; }
    bool Read(std::uint64_t offset, std::size_t size, std::vector<std::byte>& out) const override
    {
        out.clear();
        if (!Verify() || offset > identity_.size_bytes || size > identity_.size_bytes - offset ||
            offset > std::uint64_t(INT64_MAX) || size > kMaxRead) return false;
        if (!device_->Read(offset, size, out) || out.size() != size || !Verify())
        { out.clear(); return false; }
        return true;
    }
private:
    std::vector<HANDLE> directories_;
    std::shared_ptr<rw::BlockDevice> device_;
    FusionImageIdentity identity_;
};
#endif
} // namespace

struct ApfsFusionStore::Impl
{
    struct Member
    {
        FusionImageMember binding;
        std::shared_ptr<RandomAccessSource> source;
        std::function<bool()> verify;
        std::vector<std::byte> anchor;
    };
    std::array<Member, 2> members;
    std::shared_ptr<ApfsReadBudget> budget;
    std::array<ApfsPhysicalStoreDescriptor, 2> descriptors;
    ApfsContainerDescriptor container;
    ContainerCheckpointView checkpoint;
    std::uint32_t block_size = 0;
    mutable std::string error;
    mutable bool poisoned = false;

    bool Refuse(const char* reason, bool poison = false) const
    {
        if (!poisoned) error = reason;
        poisoned = poisoned || poison;
        return false;
    }
    bool Verify() const
    {
        if (poisoned) return false;
        if (budget->Failed()) return Refuse(budget->Failure(), true);
        for (const auto& m : members)
        {
            if (!m.source || !m.verify || !m.verify() ||
                m.source->SizeBytes() != m.binding.exact_identity.size_bytes)
                return Refuse("FusionMemberDisappearedOrChanged", true);
            const auto inherited = m.source->ReadBudget();
            if (inherited && inherited != budget)
                return Refuse("FusionReadBudgetIdentityMismatch", true);
        }
        // Verification callbacks/held-handle queries can fail the allowance.
        // Publication must also see changes made during the last member check.
        if (budget->Failed()) return Refuse(budget->Failure(), true);
        for (const auto& m : members)
        {
            const auto inherited = m.source->ReadBudget();
            if (inherited && inherited != budget)
                return Refuse("FusionReadBudgetIdentityMismatch", true);
        }
        return true;
    }
    bool Map(std::uint64_t address, std::uint64_t length, FusionRoute& out) const
    {
        out = {};
        if (!Verify()) return false;
        if (address >= 2 * kFusionTier2ByteAddress)
            return Refuse("FusionAddressHighBitsUnsupported");
        const std::size_t member = address >= kFusionTier2ByteAddress ? 1 : 0;
        const auto relative = address - (member ? kFusionTier2ByteAddress : 0);
        const auto& b = members[member].binding;
        if (!length) return Refuse("FusionZeroLengthRange");
        if (length > kFusionTier2ByteAddress - relative)
            return Refuse("FusionAddressSpaceCrossing");
        if (relative >= b.store_size || length > b.store_size - relative)
            return Refuse("FusionMemberRangeOutsideGeometry");
        out = {b.role, b.stable_store_id, relative, b.store_offset + relative, length};
        error.clear();
        return true;
    }
    bool ReadMember(std::size_t index, std::uint64_t offset, std::size_t size,
        std::vector<std::byte>& out) const
    {
        out.clear();
        if (!Verify()) return false;
        const auto& m = members[index];
        if (size > kMaxRead || offset > m.binding.store_size || size > m.binding.store_size - offset)
            return Refuse("FusionMemberReadRangeInvalid");
        const auto inherited = m.source->ReadBudget();
        if (inherited && inherited != budget) return Refuse("FusionReadBudgetIdentityMismatch", true);
        if (!inherited && !budget->Read(size)) return Refuse(budget->Failure(), true);
        if (!m.source->Read(m.binding.store_offset + offset, size, out) || out.size() != size)
        { out.clear(); return Refuse("FusionMemberShortReadOrIoFailure", true); }
        if (!Verify()) { out.clear(); return false; }
        return true;
    }
    bool ReadEncoded(std::uint64_t address, std::size_t size, std::vector<std::byte>& out) const
    {
        out.clear();
        FusionRoute route;
        if (size > kMaxRead) return Refuse("FusionPerReadLimit");
        if (!Map(address, size, route)) return false;
        const auto i = route.role == FusionMemberRole::Main ? 0 : 1;
        return ReadMember(i, route.member_offset, size, out);
    }
    class BootstrapSource final : public RandomAccessSource
    {
    public:
        explicit BootstrapSource(const Impl& impl) : impl_(impl) {}
        std::uint64_t SizeBytes() const override { return kFusionTier2ByteAddress + impl_.members[1].binding.store_size; }
        std::shared_ptr<ApfsReadBudget> ReadBudget() const override { return impl_.budget; }
        bool Read(std::uint64_t address, std::size_t size, std::vector<std::byte>& out) const override
        { return impl_.ReadEncoded(address, size, out); }
    private: const Impl& impl_;
    };
};

ApfsFusionStore::ApfsFusionStore(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
ApfsFusionStore::~ApfsFusionStore() = default;
bool ApfsFusionStore::CheckAvailable(std::string& error) const
{
    error.clear();
    if (impl_->Verify()) return true;
    error = impl_->error; return false;
}
std::function<bool(std::string&)> ApfsFusionStore::RetainAvailabilityLease() const
{
    return [state = impl_](std::string& error) {
        error.clear();
        if (state->Verify()) return true;
        error = state->error; return false;
    };
}
void ApfsFusionStore::Cancel() const { (void)impl_->Refuse("FusionReadCancelled", true); }
bool ApfsFusionStore::InspectImage(const std::wstring& path, FusionImageIdentity& out, std::string& error)
{
    out = {}; error.clear();
#ifdef _WIN32
    LockedImage image(path);
    if (image.Identity(out)) return true;
#endif
    return Fail(error, "FusionOrdinaryLocalImageReadLeaseRequired");
}
std::unique_ptr<ApfsFusionStore> ApfsFusionStore::BindImages(const FusionBindRequest& r, std::string& error)
{
    error.clear();
    if (!RequestValid(r, error)) return {};
    auto impl = std::make_unique<Impl>(); impl->budget = r.budget;
    for (const auto& m : r.members)
    {
#ifdef _WIN32
        auto image = std::make_shared<LockedImage>(m.path);
        FusionImageIdentity identity;
        if (!image->Identity(identity) || identity != m.exact_identity)
        { error = "FusionExactImageIdentityMismatchOrUnavailable"; return {}; }
        auto& target = impl->members[m.role == FusionMemberRole::Main ? 0 : 1];
        target.binding = m; target.source = image;
        target.verify = [image] { return image->Verify(); };
#else
        error = "FusionRegularImagePlatformUnsupported"; return {};
#endif
    }
    return FinishBind(std::move(impl), r, error);
}
#ifdef APFS_FUSION_STORE_TESTING
bool ApfsFusionStore::TestOrdinaryLocalImagePathSyntax(const std::wstring& path)
{ return OrdinaryLocalImagePathSyntax(path); }
std::unique_ptr<ApfsFusionStore> ApfsFusionStore::BindTestSources(const FusionBindRequest& r,
    const std::vector<TestMember>& sources, std::string& error)
{
    error.clear();
    if (!RequestValid(r, error)) return {};
    if (sources.size() != 2) { error = "FusionCompleteTwoMemberSetRequired"; return {}; }
    if (sources[0].source == sources[1].source) { error = "FusionDuplicateSource"; return {}; }
    auto impl = std::make_unique<Impl>(); impl->budget = r.budget;
    for (std::size_t i = 0; i < 2; ++i)
    {
        auto& target = impl->members[r.members[i].role == FusionMemberRole::Main ? 0 : 1];
        target.binding = r.members[i]; target.source = sources[i].source;
        target.verify = sources[i].verify_unchanged;
    }
    return FinishBind(std::move(impl), r, error);
}
#endif

std::unique_ptr<ApfsFusionStore> ApfsFusionStore::FinishBind(std::unique_ptr<Impl> p,
    const FusionBindRequest& r, std::string& error)
{
    const auto refuse = [&](const char* reason) -> std::unique_ptr<ApfsFusionStore> {
        error = p->poisoned ? p->error : reason; return {}; };
    if (!p->Verify()) return refuse("FusionMemberUnavailable");
    if (!p->budget->Materialize(2, 2 * (sizeof(NxSuperblock) + 1024)))
        return refuse(p->budget->Failure());
    std::array<NxSuperblock, 2> nx;
    for (std::size_t i = 0; i < 2; ++i)
    {
        auto& member = p->members[i];
        std::vector<std::byte> probe;
        if (!p->ReadMember(i, 0, 4096, probe)) return refuse("FusionAnchorUnreadable");
        const auto bs = ReadU32LE(probe, 0x24).value_or(0);
        if (bs < 4096 || bs > 65536 || (bs & (bs - 1)) ||
            member.binding.store_offset % bs || member.binding.store_size % bs)
            return refuse("FusionMemberBlockGeometryInvalid");
        if (bs == 4096) member.anchor = std::move(probe);
        else if (!p->ReadMember(i, 0, bs, member.anchor)) return refuse("FusionAnchorUnreadable");
        auto parsed = ParseNxSuperblock(member.anchor);
        if (!parsed) return refuse("FusionAnchorChecksumOrFormatInvalid");
        if (ReadU32LE(member.anchor, 0x18) != (kObjectEphemeral | kNxSuperblockObjectType) ||
            ReadU32LE(member.anchor, 0x1C) != 0u)
            return refuse("FusionAnchorObjectStorageOrSubtypeUnsupported");
        nx[i] = std::move(*parsed);
        if (nx[i].incompatible_features != (kNxIncompatFusion | 2) || nx[i].readonly_features ||
            (nx[i].features & ~kNxKnownOptionalFeaturesMask))
            return refuse("FusionContainerFeatureProfileUnsupported");
        if (nx[i].uuid_hex != r.container_uuid_hex) return refuse("FusionContainerUuidMismatch");
        auto uuid = nx[i].fusion_uuid;
        const auto role_bit = std::to_integer<unsigned>(uuid[15]) & 1;
        if (role_bit != i) return refuse("FusionRoleBitMismatch");
        uuid[15] &= std::byte{0xFE};
        if (BytesToHexLower(uuid.data(), uuid.size()) != r.fusion_uuid_hex)
            return refuse("FusionSetUuidMismatch");
    }
    if (nx[0].block_size != nx[1].block_size) return refuse("FusionMemberBlockSizeMismatch");
    if (nx[0].xid != nx[1].xid) return refuse("FusionMemberAnchorGenerationMismatch");
    // apfsck fusion_super_compare: every byte except checksum and UUID role bit.
    for (std::size_t n = 8; n < p->members[0].anchor.size(); ++n)
    {
        auto a = p->members[0].anchor[n], b = p->members[1].anchor[n];
        if (n == 0x50F) b &= std::byte{0xFE};
        if (a != b) return refuse("FusionMemberAnchorContentMismatch");
    }
    p->block_size = nx[0].block_size;
    const auto main_blocks = p->members[0].binding.store_size / p->block_size;
    const auto tier_blocks = p->members[1].binding.store_size / p->block_size;
    if (nx[0].block_count != main_blocks + tier_blocks)
        return refuse("FusionCombinedBlockCountMismatch");
    if (nx[0].xp_desc_noncontiguous) return refuse("FusionCheckpointDescriptorTreeUnsupported");
    if (nx[0].xp_data_noncontiguous) return refuse("FusionCheckpointDataTreeUnsupported");
    if (nx[0].xp_desc_block_count > 65536 || nx[0].xp_data_block_count > 65536)
        return refuse("FusionCheckpointAreaLimit");
    const auto in_main = [&](std::uint64_t b, std::uint64_t count) {
        return count && b && b < main_blocks && count <= main_blocks - b; };
    if (!in_main(nx[0].xp_desc_base_block, nx[0].xp_desc_block_count) ||
        !in_main(nx[0].xp_data_base_block, nx[0].xp_data_block_count))
        return refuse("FusionCheckpointAreasMustBeMainLocal");
    const auto overlaps = [](std::uint64_t a, std::uint64_t ac, std::uint64_t b, std::uint64_t bc) {
        return a <= b ? b - a < ac : a - b < bc; };
    if (overlaps(nx[0].xp_desc_base_block, nx[0].xp_desc_block_count,
            nx[0].xp_data_base_block, nx[0].xp_data_block_count))
        return refuse("FusionCheckpointAreasOverlap");
    Impl::BootstrapSource source(*p);
    // A newer generation can have overwritten blocks used by the older anchor.
    // Without a recovery/retention proof, even a partially complete newer NXSB
    // invalidates this deliberately clean-checkpoint read profile.
    for (std::uint64_t n = 0; n < nx[0].xp_desc_block_count; ++n)
    {
        std::vector<std::byte> descriptor;
        if (!source.Read((nx[0].xp_desc_base_block + n) * p->block_size, p->block_size, descriptor))
            return refuse("FusionCheckpointDescriptorReadFailed");
        if (!p->budget->Materialize(0, sizeof(NxSuperblock) + 1024))
            return refuse(p->budget->Failure());
        auto candidate = ParseNxSuperblock(descriptor);
        if (candidate && candidate->xid > r.checkpoint_xid)
            return refuse("FusionNewerCheckpointRequiresRecovery");
    }
    // The loader's store-size argument checks capacity/contiguous checkpoint
    // geometry. It must never receive the enormous encoded virtual span.
    const auto capacity = p->members[0].binding.store_size + p->members[1].binding.store_size;
    auto cp = LoadContainerCheckpointView(source, 0, capacity, error, r.checkpoint_xid);
    if (!cp) { if (p->poisoned) error = p->error; return {}; }
    // Deliberately strict: lagging block-zero anchors need a separately validated
    // recovery policy. Never infer coherence from matching UUIDs at different XIDs.
    if (nx[0].xid != r.checkpoint_xid) return refuse("FusionAnchorCheckpointGenerationUnestablished");
    if (cp->superblock_bytes != p->members[0].anchor)
        return refuse("FusionAnchorCheckpointContentMismatch");
    if (cp->superblock.next_xid <= cp->superblock.xid)
        return refuse("FusionNextGenerationInvalid");
    if (cp->mappings.size() > 4096) return refuse("FusionCheckpointMappingLimit");
    using MappedRange = std::pair<std::uint64_t, std::uint64_t>;
    if (!p->budget->Materialize(cp->mappings.size(), cp->mappings.size() * sizeof(MappedRange)))
        return refuse(p->budget->Failure());
    std::vector<MappedRange> mapped_ranges;
    mapped_ranges.reserve(cp->mappings.size());
    for (const auto& mapping : cp->mappings)
    {
        if ((mapping.type & ~(kObjectStorageTypeMask | kObjectTypeMask)) != 0)
            return refuse("FusionCheckpointObjectFlagsUnsupported");
        const auto count = mapping.size_bytes / p->block_size;
        if (!in_main(mapping.physical_block, count) ||
            mapping.physical_block < nx[0].xp_data_base_block ||
            mapping.physical_block - nx[0].xp_data_base_block > nx[0].xp_data_block_count ||
            count > nx[0].xp_data_block_count - (mapping.physical_block - nx[0].xp_data_base_block))
            return refuse("FusionWrappedCheckpointObjectUnsupported");
        mapped_ranges.emplace_back(mapping.physical_block, count);
    }
    std::sort(mapped_ranges.begin(), mapped_ranges.end());
    for (std::size_t i = 1; i < mapped_ranges.size(); ++i)
        if (mapped_ranges[i].first - mapped_ranges[i-1].first < mapped_ranges[i-1].second)
            return refuse("FusionCheckpointMappingsOverlap");
    const auto sm = std::find_if(cp->mappings.begin(), cp->mappings.end(), [&](const auto& m) {
        return m.object_id == cp->superblock.spaceman_oid; });
    if (sm == cp->mappings.end() || sm->type != (kObjectEphemeral | kObjectTypeSpaceman) ||
        sm->subtype || sm->file_system_oid || sm->size_bytes < 0x158)
        return refuse("FusionSpacemanMappingInvalid");
    if (sm->size_bytes != p->block_size)
        return refuse("FusionSpacemanMultiBlockUnsupported");
    std::vector<std::byte> space;
    if (sm->physical_block >= main_blocks || sm->size_bytes > kMaxRead ||
        !source.Read(sm->physical_block * p->block_size, sm->size_bytes, space))
        return refuse("FusionSpacemanReadFailed");
    // Checkpoint loader already validated native object header/checksum/XID.
    if (ReadU32LE(space, 0x20) != p->block_size)
        return refuse("FusionSpacemanBlockSizeMismatch");
    const auto chunk_blocks = ReadU32LE(space, 0x24).value_or(0);
    const auto chunks_per_cib = ReadU32LE(space, 0x28).value_or(0);
    if (chunk_blocks != std::uint64_t(p->block_size) * 8 ||
        chunks_per_cib != (p->block_size - 0x28) / 0x20 ||
        ReadU32LE(space, 0x2C) != (p->block_size - 0x28) / 8)
        return refuse("FusionSpacemanChunkGeometryInvalid");
    const auto sm_flags = ReadU32LE(space, 0x90).value_or(~0u);
    if ((sm_flags & ~1u) != 0 || ((sm_flags & 1u) &&
        (ReadU32LE(space, 0x154).value_or(0) < 0x158 ||
         ReadU32LE(space, 0x154).value_or(0) > space.size())))
        return refuse("FusionSpacemanStructureUnsupported");
    for (std::size_t i = 0; i < 2; ++i)
    {
        const auto base = 0x30 + i * 0x30;
        const auto count = ReadU64LE(space, base).value_or(0);
        const auto expected = p->members[i].binding.store_size / p->block_size;
        const auto chunks = expected / chunk_blocks + (expected % chunk_blocks != 0);
        const auto cibs = chunks / chunks_per_cib + (chunks % chunks_per_cib != 0);
        const auto cibs_per_cab = (p->block_size - 0x28) / 8;
        const auto cab_groups = cibs / cibs_per_cab + (cibs % cibs_per_cab != 0);
        const auto cabs = cab_groups == 1 ? 0 : cab_groups;
        if (count != expected || ReadU64LE(space, base + 8) != chunks ||
            ReadU32LE(space, base + 0x10) != cibs || ReadU32LE(space, base + 0x14) != cabs ||
            ReadU64LE(space, base + 0x18).value_or(UINT64_MAX) > count)
            return refuse("FusionSpacemanMemberGeometryMismatch");
        if (ReadU32LE(space, base + 0x24) != 0u || ReadU64LE(space, base + 0x28) != 0)
            return refuse("FusionSpacemanMemberReservedFieldsUnsupported");
    }
    // Original apfsck requires both cache objects and a main-device WBC range.
    // Only its established empty-cache state is accepted. The public structs
    // alone do not establish precedence/recovery for dirty or tenant entries.
    if (!nx[0].fusion_middle_tree_oid || !nx[0].fusion_writeback_oid)
        return refuse("FusionRequiredCacheMetadataMissing");
    if (!in_main(nx[0].fusion_writeback_start, nx[0].fusion_writeback_blocks))
        return refuse("FusionWritebackRangeInvalid");
    if (overlaps(nx[0].fusion_writeback_start, nx[0].fusion_writeback_blocks,
            nx[0].xp_desc_base_block, nx[0].xp_desc_block_count) ||
        overlaps(nx[0].fusion_writeback_start, nx[0].fusion_writeback_blocks,
            nx[0].xp_data_base_block, nx[0].xp_data_block_count))
        return refuse("FusionWritebackOverlapsCheckpoint");
    const auto wbc = std::find_if(cp->mappings.begin(), cp->mappings.end(), [&](const auto& m) {
        return m.object_id == nx[0].fusion_writeback_oid; });
    if (wbc == cp->mappings.end() || wbc->type != (kObjectEphemeral | 0x16u) ||
        wbc->subtype || wbc->file_system_oid)
        return refuse("FusionWritebackMappingInvalid");
    if (wbc->size_bytes != p->block_size)
        return refuse("FusionWritebackMultiBlockUnsupported");
    std::vector<std::byte> cache;
    if (wbc->physical_block >= main_blocks ||
        !source.Read(wbc->physical_block * p->block_size, wbc->size_bytes, cache))
        return refuse("FusionWritebackReadFailed");
    if (ReadU64LE(cache, 0x20) != 0x70) return refuse("FusionWritebackVersionUnsupported");
    if (ReadU32LE(cache, 0x4C) != 0u) return refuse("FusionWritebackReservedFieldUnsupported");
    if (ReadU64LE(cache, 0x28) != 0 || ReadU64LE(cache, 0x30) != 0 ||
        ReadU64LE(cache, 0x38) != 0 || ReadU64LE(cache, 0x40) != 0 ||
        ReadU32LE(cache, 0x48) != 0u || ReadU64LE(cache, 0x50) != 0 ||
        ReadU64LE(cache, 0x58) != 0 || ReadU64LE(cache, 0x60) != 0)
        return refuse("FusionNonemptyWritebackRoutingUnestablished");
    const auto mt_oid = nx[0].fusion_middle_tree_oid;
    if (mt_oid > (2 * kFusionTier2ByteAddress - 1) / p->block_size)
        return refuse("FusionMiddleTreeAddressInvalid");
    if (mt_oid < kFusionTier2ByteAddress / p->block_size &&
        (overlaps(mt_oid, 1, nx[0].xp_desc_base_block, nx[0].xp_desc_block_count) ||
         overlaps(mt_oid, 1, nx[0].xp_data_base_block, nx[0].xp_data_block_count) ||
         overlaps(mt_oid, 1, nx[0].fusion_writeback_start, nx[0].fusion_writeback_blocks)))
        return refuse("FusionMiddleTreeOverlapsReservedArea");
    std::vector<std::byte> root;
    if (!source.Read(mt_oid * p->block_size, p->block_size, root))
        return refuse("FusionMiddleTreeReadFailed");
    const auto info = root.size() - 40;
    if (ReadU64LE(root, 16) == 0 || ReadU32LE(root, info + 8) != 8u ||
        ReadU32LE(root, info + 12) != 16u || (ReadU16LE(root, 0x20).value_or(0) & 4) == 0)
        return refuse("FusionMiddleTreeLayoutUnsupported");
    BtreeReadPolicy policy;
    policy.enforce_object_identity = true;
    policy.root_object_id = mt_oid;
    policy.storage_type = kObjectPhysical;
    policy.subtype = 0x15;
    policy.require_complete_traversal = true;
    policy.reject_unsupported_flags = true;
    std::vector<BtreeRecord> records;
    if (!ReadBtreeLeafRecords(source, p->block_size, mt_oid, true, 0,
            r.checkpoint_xid, policy, records, error))
    { if (p->poisoned) error = p->error; else error = "FusionMiddleTreeInvalid:" + error; return {}; }
    if (!records.empty()) return refuse("FusionNonemptyMiddleTreeRoutingUnestablished");
    p->checkpoint = std::move(*cp);
    p->container.container_uuid_hex = r.container_uuid_hex;
    p->container.block_size = p->block_size;
    p->container.checkpoint_xid = r.checkpoint_xid;
    p->container.total_blocks = nx[0].block_count;
    p->container.compatible_features = nx[0].features;
    p->container.incompatible_features = nx[0].incompatible_features;
    p->container.fusion = true;
    for (std::size_t i = 0; i < 2; ++i)
    {
        const auto& b = p->members[i].binding;
        p->descriptors[i].stable_store_id = b.stable_store_id;
        p->descriptors[i].container_uuid_hex = r.container_uuid_hex;
        p->descriptors[i].offset_bytes = b.store_offset;
        p->descriptors[i].size_bytes = b.store_size;
        p->descriptors[i].block_size_bytes = p->block_size;
        p->descriptors[i].total_blocks = b.store_size / p->block_size;
        p->container.member_store_ids.push_back(b.stable_store_id);
    }
    if (!p->Verify()) return refuse("FusionMemberUnavailable");
    p->error.clear(); error.clear();
    return std::unique_ptr<ApfsFusionStore>(new ApfsFusionStore(std::move(p)));
}

std::uint64_t ApfsFusionStore::SizeBytes() const { return kFusionTier2ByteAddress + impl_->members[1].binding.store_size; }
std::uint64_t ApfsFusionStore::CapacityBytes() const noexcept
{ return impl_->members[0].binding.store_size + impl_->members[1].binding.store_size; }
std::shared_ptr<ApfsReadBudget> ApfsFusionStore::ReadBudget() const { return impl_->budget; }
bool ApfsFusionStore::Read(std::uint64_t address, std::size_t size, std::vector<std::byte>& out) const
{ return impl_->ReadEncoded(address, size, out); }
bool ApfsFusionStore::MapPhysical(std::uint64_t block, std::uint64_t offset, std::uint64_t length,
    FusionRoute& out, std::string& error) const
{
    out = {}; error.clear();
    const auto bs = impl_->block_size;
    if (offset >= bs || block > (2 * kFusionTier2ByteAddress - 1 - offset) / bs)
        return Fail(error, "FusionPhysicalAddressOverflowOrOffsetInvalid");
    if (!impl_->Map(block * bs + offset, length, out)) { error = impl_->error; return false; }
    return true;
}
bool ApfsFusionStore::ReadExtents(const std::vector<FusionExtent>& extents,
    std::vector<std::byte>& out, std::string& error) const
{
    out.clear(); error.clear();
    if (extents.empty() || extents.size() > 4096) return Fail(error, "FusionExtentCountInvalid");
    if (!impl_->Verify()) { error = impl_->error; return false; }
    std::size_t total = 0;
    for (const auto& e : extents)
    {
        FusionRoute route;
        if (e.physical_block == 0) return Fail(error, "FusionSparseExtentRequiresHigherLayer");
        if (!MapPhysical(e.physical_block, e.offset_in_block, e.length, route, error)) return false;
        if (e.length > kMaxRead - total) return Fail(error, "FusionExtentMaterializationLimit");
        total += e.length;
    }
    if (!impl_->budget->Materialize(extents.size(), total)) return Fail(error, impl_->budget->Failure());
    std::vector<std::byte> staging; staging.reserve(total);
    for (const auto& e : extents)
    {
        std::vector<std::byte> piece;
        if (!Read(e.physical_block * impl_->block_size + e.offset_in_block, e.length, piece))
        { error = impl_->error; return false; }
        staging.insert(staging.end(), piece.begin(), piece.end());
    }
    if (!impl_->Verify()) { error = impl_->error; return false; }
    out = std::move(staging); return true;
}
bool ApfsFusionStore::ReadMetadata(std::uint64_t block, std::uint32_t type,
    std::uint32_t subtype, std::uint64_t oid, std::uint64_t xid, std::vector<std::byte>& out, std::string& error) const
{
    out.clear(); error.clear();
    if (!oid || !xid || xid > impl_->checkpoint.superblock.xid || (type & kObjectNoHeader))
        return Fail(error, "FusionMetadataIdentityInvalid");
    FusionRoute route;
    if (!MapPhysical(block, 0, impl_->block_size, route, error)) return false;
    std::vector<std::byte> bytes;
    if (!Read(block * impl_->block_size, impl_->block_size, bytes)) { error = impl_->error; return false; }
    if (!VerifyObjectChecksum(bytes, impl_->block_size) || ReadU64LE(bytes, 8) != oid ||
        ReadU64LE(bytes, 16) != xid || ReadU32LE(bytes, 24) != type || ReadU32LE(bytes, 28) != subtype)
        return Fail(error, "FusionMetadataChecksumOrIdentityMismatch");
    out = std::move(bytes); return true;
}
const ApfsContainerDescriptor& ApfsFusionStore::Container() const noexcept { return impl_->container; }
const std::array<ApfsPhysicalStoreDescriptor, 2>& ApfsFusionStore::Members() const noexcept { return impl_->descriptors; }
const FusionImageMember& ApfsFusionStore::Binding(FusionMemberRole role) const
{
    if (role != FusionMemberRole::Main && role != FusionMemberRole::Tier2)
        throw std::invalid_argument("FusionUnknownMemberRole");
    return impl_->members[role == FusionMemberRole::Main ? 0 : 1].binding;
}
const ContainerCheckpointView& ApfsFusionStore::Checkpoint() const noexcept { return impl_->checkpoint; }
const std::string& ApfsFusionStore::LastError() const noexcept { return impl_->error; }
bool ApfsFusionStore::BeginOrderedWriteTransaction(std::uint64_t next_xid, std::string& error) const
{
    error.clear();
    if (!impl_->Verify()) { error = impl_->error; return false; }
    if (next_xid <= impl_->checkpoint.superblock.xid || next_xid == UINT64_MAX)
        return Fail(error, "FusionWriteGenerationInvalid");
    return Fail(error, "FusionDurableMultiStoreWriteOrderingUnestablished");
}
} // namespace apfsaccess::catalog
