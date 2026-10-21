#include "ApfsFusionWriteSession.h"
#include <utility>

namespace apfsaccess::catalog
{
namespace
{
bool Fail(std::string& error, const char* reason) { error = reason; return false; }
// Stable file identity for replacement detection. Last-write time is
// deliberately excluded: legitimate writes advance it. Volume serial, file
// ID, size, and creation time are stable across ordinary writes; any file
// replacement, resize, or move changes at least one of them. (A same-size
// same-file rewrite keeps all four, but that actor already holds write
// access to the member and owns its bytes.)
bool SameMemberFile(const rw::BlockDevice::StableImageIdentity& a,
    const rw::BlockDevice::StableImageIdentity& b) noexcept
{
    return a.volume_serial == b.volume_serial && a.file_id == b.file_id &&
        a.size_bytes == b.size_bytes && a.creation_time == b.creation_time;
}
} // namespace

struct ApfsFusionWriteSession::Impl
{
    const ApfsFusionStore* store = nullptr;
    std::uint32_t block_size = 0;
    std::uint64_t main_blocks = 0;
    std::uint64_t tier2_blocks = 0;
    std::string container_uuid;
    std::uint64_t checkpoint_xid = 0;
    struct Member
    {
        std::shared_ptr<rw::BlockDevice> device;
        rw::BlockDevice::StableImageIdentity identity{};
        FusionMemberRole role = FusionMemberRole::Main;
    };
    // Index 0 serves Main, index 1 serves Tier2, regardless of bind order.
    std::array<Member, 2> members;
    bool bound = false;
    mutable bool poisoned = false;
    mutable std::string error;
    mutable Counters counters{};

    bool Refuse(std::string& out_error, std::string reason, bool poison = false)
    {
        if (!poisoned) error = std::move(reason);
        poisoned = poisoned || poison;
        out_error = error;
        return false;
    }

    bool CheckMemberFresh(std::size_t index, std::string& out_error)
    {
        const auto& member = members[index];
        rw::BlockDevice::StableImageIdentity now{};
        if (!member.device || !member.device->QueryHeldImageIdentity(now) || !SameMemberFile(now, member.identity))
        {
            return Refuse(out_error, "FusionWriteMemberReplaced", true);
        }
        return true;
    }
};

ApfsFusionWriteSession::ApfsFusionWriteSession(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
ApfsFusionWriteSession::~ApfsFusionWriteSession() = default;

std::unique_ptr<ApfsFusionWriteSession> ApfsFusionWriteSession::Bind(
    const ApfsFusionStore& store,
    std::shared_ptr<rw::BlockDevice> first_device,
    std::shared_ptr<rw::BlockDevice> second_device,
    std::string& error, unsigned* unavailable_members)
{
    if (unavailable_members) *unavailable_members = 0;
    error.clear();
    if (!first_device || !second_device || first_device == second_device)
        return (Fail(error, "FusionWriteDeviceMissing"), nullptr);
    std::string store_error;
    if (!store.CheckAvailable(store_error))
    {
        error = "FusionWriteStoreUnavailable:" + store_error;
        return nullptr;
    }
    auto impl = std::make_unique<Impl>();
    impl->store = &store;
    impl->block_size = store.Checkpoint().superblock.block_size;
    impl->checkpoint_xid = store.Checkpoint().superblock.xid;
    impl->container_uuid = store.Container().container_uuid_hex;
    if (!impl->block_size || (impl->block_size & (impl->block_size - 1)) ||
        impl->block_size < 4096 || impl->block_size > 65536)
        return (Fail(error, "FusionWriteBlockGeometryInvalid"), nullptr);
    const auto& members = store.Members();
    impl->main_blocks = members[0].size_bytes / impl->block_size;
    impl->tier2_blocks = members[1].size_bytes / impl->block_size;
    if (!impl->main_blocks || !impl->tier2_blocks)
        return (Fail(error, "FusionWriteMemberGeometryInvalid"), nullptr);
    std::shared_ptr<rw::BlockDevice> devices[2] = {std::move(first_device), std::move(second_device)};
    for (auto& device : devices)
    {
        if (!device->IsRegularFile())
            return (Fail(error, "FusionWriteMemberNotRegularFile"), nullptr);
        if (!device->HasWriteHandle())
            return (Fail(error, "FusionWriteHeldWriterRequired"), nullptr);
        // Routes already include the image's store offset. A device base would
        // be applied a second time by BlockDevice::Write.
        if (device->BaseOffsetBytes() != 0)
            return (Fail(error, "FusionWriteDeviceBaseOffsetUnsupported"), nullptr);
    }
    // Role assignment follows held file identity, never argument order: each
    // store binding must match exactly one distinct device.
    const FusionMemberRole roles[2] = {FusionMemberRole::Main, FusionMemberRole::Tier2};
    bool claimed[2] = {false, false};
    for (std::size_t slot = 0; slot < 2; ++slot)
    {
        rw::BlockDevice::StableImageIdentity identity{};
        if (!devices[slot]->QueryHeldImageIdentity(identity))
            return (Fail(error, "FusionWriteDeviceIdentityUnreadable"), nullptr);
        bool matched = false;
        for (std::size_t role = 0; role < 2; ++role)
        {
            if (claimed[role]) continue;
            const auto& binding = store.Binding(roles[role]);
            if (identity == binding.exact_identity &&
                identity.size_bytes >= binding.store_offset + binding.store_size)
            {
                auto& member = impl->members[role];
                member.device = devices[slot];
                member.identity = identity;
                member.role = roles[role];
                claimed[role] = true;
                matched = true;
                break;
            }
        }
        if (!matched)
        {
            if (unavailable_members)
                *unavailable_members = (claimed[0] ? 0u : 1u) | (claimed[1] ? 0u : 2u);
            return (Fail(error, "FusionWriteDeviceIdentityMismatch"), nullptr);
        }
    }
    impl->bound = true;
    return std::unique_ptr<ApfsFusionWriteSession>(new ApfsFusionWriteSession(std::move(impl)));
}

bool ApfsFusionWriteSession::WriteBlock(std::uint64_t physical_block,
    std::span<const std::byte> bytes, std::string& error)
{
    error.clear();
    if (!CheckAvailable(error)) return false;
    if (bytes.size() != impl_->block_size)
        return impl_->Refuse(error, "FusionWriteBlockUnaligned");
    return WriteBlocks(physical_block, bytes, error);
}

bool ApfsFusionWriteSession::CheckAvailable(std::string& error)
{
    error.clear();
    if (!impl_ || !impl_->bound) return Fail(error, "FusionWriteSessionUnavailable");
    if (impl_->poisoned) { error = impl_->error; return false; }
    std::string store_error;
    if (!impl_->store->CheckAvailable(store_error))
        return impl_->Refuse(error, "FusionWriteStoreUnavailable:" + store_error, true);
    if (!impl_->CheckMemberFresh(0, error) || !impl_->CheckMemberFresh(1, error))
        return false;
    impl_->error.clear();
    return true;
}

bool ApfsFusionWriteSession::IsBoundTo(const ApfsFusionStore& store) const noexcept
{
    return impl_ && impl_->bound && impl_->store == &store;
}

bool ApfsFusionWriteSession::WriteBlocks(std::uint64_t physical_block,
    std::span<const std::byte> bytes, std::string& error)
{
    if (!CheckAvailable(error)) return false;
    if (bytes.empty() || bytes.size() % impl_->block_size != 0)
        return impl_->Refuse(error, "FusionWriteBlockUnaligned");
    FusionRoute route;
    if (!impl_->store->MapPhysical(physical_block, 0, bytes.size(), route, error))
        return impl_->Refuse(error, "FusionWriteUnroutable:" + error);
    const std::size_t index = route.role == FusionMemberRole::Main ? 0 : 1;
    const auto blocks = bytes.size() / impl_->block_size;
    const auto budget = impl_->store->ReadBudget();
    if (budget && !budget->Materialize(blocks, bytes.size()))
        return impl_->Refuse(error, budget->Failure(), true);
    for (std::size_t i = 0; i < blocks; ++i)
    {
        if (!CheckAvailable(error)) return false;
        if (!impl_->members[index].device->Write(route.image_offset + i * impl_->block_size,
                bytes.subspan(i * impl_->block_size, impl_->block_size)))
            return impl_->Refuse(error,
                index == 0 ? "FusionWriteIoFailure:main" : "FusionWriteIoFailure:tier2", true);
        if (index == 0) ++impl_->counters.main_blocks_written;
        else ++impl_->counters.tier2_blocks_written;
    }
    return CheckAvailable(error);
}

bool ApfsFusionWriteSession::FlushOrdered(std::string& error)
{
    if (!CheckAvailable(error)) return false;
    // Crash-safe order: tier-2 payload first, main (which carries the
    // checkpoint) last. A tier-2 failure returns before main is flushed, so
    // main is not flushed after a tier-2 failure; staged bytes are not undone.
    if (!impl_->members[1].device->Flush())
        return impl_->Refuse(error, "FusionTier2FlushFailed", true);
    ++impl_->counters.tier2_flushes;
    if (!CheckAvailable(error)) return false;
    if (!impl_->members[0].device->Flush())
        return impl_->Refuse(error, "FusionMainFlushFailed", true);
    ++impl_->counters.main_flushes;
    return CheckAvailable(error);
}

std::uint32_t ApfsFusionWriteSession::BlockSize() const noexcept { return impl_ ? impl_->block_size : 0; }
std::uint64_t ApfsFusionWriteSession::MainBlocks() const noexcept { return impl_ ? impl_->main_blocks : 0; }
std::uint64_t ApfsFusionWriteSession::Tier2Blocks() const noexcept { return impl_ ? impl_->tier2_blocks : 0; }
const std::string& ApfsFusionWriteSession::ContainerUuid() const noexcept
{
    static const std::string empty;
    return impl_ ? impl_->container_uuid : empty;
}
std::uint64_t ApfsFusionWriteSession::CheckpointXid() const noexcept { return impl_ ? impl_->checkpoint_xid : 0; }
ApfsFusionWriteSession::Counters ApfsFusionWriteSession::counters() const noexcept
{
    return impl_ ? impl_->counters : Counters{};
}
const std::string& ApfsFusionWriteSession::LastError() const noexcept
{
    static const std::string empty;
    return impl_ ? impl_->error : empty;
}
} // namespace apfsaccess::catalog
