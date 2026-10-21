#include "ApfsFirmlinkRouter.h"

#include <algorithm>
#include <set>

namespace apfsaccess::rw
{
namespace
{
bool Fail(std::string& error, const char* code)
{
    error = code;
    return false;
}

bool IsUuid(const std::string& value)
{
    return value.size() == 32 && value != std::string(32, '0') &&
        std::all_of(value.begin(), value.end(), [](char c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        });
}

std::string VolumeId(const catalog::ApfsContainerDescriptor& c,
    const catalog::ApfsVolumeDescriptor& v)
{
    // Existing ApfsContainerCatalog::VolumeIdFor canonical spelling, no parsing.
    return "apfs-vol:" + c.container_uuid_hex + ":" + std::to_string(v.object_id);
}

bool SameIdentity(const FirmlinkObjectIdentity& a, const FirmlinkObjectIdentity& b)
{
    return a.volume.container_uuid_hex == b.volume.container_uuid_hex &&
        a.volume.volume_uuid_hex == b.volume.volume_uuid_hex &&
        a.volume.object_id == b.volume.object_id && a.object_id == b.object_id &&
        a.checkpoint_xid == b.checkpoint_xid && a.inode_xid == b.inode_xid;
}
} // namespace

FirmlinkDecodeStatus InspectFirmlinkAttribute(const AppleXattrRecord& attribute) noexcept
{
    return attribute.name_utf8 == kFirmlinkEaName
        ? FirmlinkDecodeStatus::UnsupportedSerialization : FirmlinkDecodeStatus::NotFirmlink;
}

bool ApfsFirmlinkRouter::TryBuild(const catalog::ApfsContainerDescriptor& container,
    const std::string& group_uuid_hex, const NativeApfsVolumeProjection& system,
    const NativeApfsVolumeProjection& data, std::span<const VerifiedFirmlinkRecord> records,
    std::shared_ptr<const ApfsFirmlinkRouter>& out, std::string& error)
{
    out.reset();
    error.clear();
    if (!IsUuid(container.container_uuid_hex) || !IsUuid(group_uuid_hex) ||
        container.checkpoint_xid == 0 || container.fusion || container.member_store_ids.size() != 1)
        return Fail(error, "FirmlinkContainerUnsupported");
    if (records.size() > kMaxRecords || system.inodes.size() > kMaxProjectionInodes ||
        data.inodes.size() > kMaxProjectionInodes - system.inodes.size() ||
        system.directory_links.size() > kMaxDirectoryLinks ||
        data.directory_links.size() > kMaxDirectoryLinks - system.directory_links.size())
        return Fail(error, "FirmlinkTableLimit");

    // Consume existing catalog group validation, then check exact membership
    // against its volume descriptors to reject incomplete or stale projections.
    const catalog::ApfsVolumeGroupDescriptor* group = nullptr;
    for (const auto& g : container.groups)
        if (g.group_uuid_hex == group_uuid_hex)
        {
            if (group) return Fail(error, "FirmlinkGroupAmbiguous");
            group = &g;
        }
    if (!group || group->association_status != "valid-system-data" ||
        group->container_uuid_hex != container.container_uuid_hex)
        return Fail(error, "FirmlinkGroupInvalid");
    const catalog::ApfsVolumeDescriptor* system_volume = nullptr;
    const catalog::ApfsVolumeDescriptor* data_volume = nullptr;
    std::set<std::string> member_ids, volume_uuids;
    std::set<std::uint64_t> volume_oids;
    for (const auto& v : container.volumes)
    {
        if (v.object_id == 0 || !volume_oids.insert(v.object_id).second ||
            (!v.volume_uuid_hex.empty() && !volume_uuids.insert(v.volume_uuid_hex).second))
            return Fail(error, "FirmlinkVolumeIdentityInvalid");
        if (v.group_uuid_hex != group_uuid_hex) continue;
        if (!v.group_metadata_valid || !IsUuid(v.volume_uuid_hex) ||
            v.group_association_status != "valid-system-data")
            return Fail(error, "FirmlinkGroupInvalid");
        const auto id = VolumeId(container, v);
        member_ids.insert(id);
        if (v.role_raw == 0x1)
        {
            if (system_volume) return Fail(error, "FirmlinkGroupAmbiguous");
            system_volume = &v;
        }
        if (v.role_raw == 0x40)
        {
            if (data_volume) return Fail(error, "FirmlinkGroupAmbiguous");
            data_volume = &v;
        }
    }
    if (!system_volume || !data_volume ||
        member_ids != std::set<std::string>(group->member_volume_ids.begin(), group->member_volume_ids.end()) ||
        member_ids.size() != group->member_volume_ids.size() ||
        group->system_volume_id != VolumeId(container, *system_volume) ||
        group->data_volume_id != VolumeId(container, *data_volume))
        return Fail(error, "FirmlinkGroupMembershipMismatch");

    auto table = std::shared_ptr<ApfsFirmlinkRouter>(new ApfsFirmlinkRouter);
    const auto add_volume = [&](const catalog::ApfsVolumeDescriptor& volume,
        const NativeApfsVolumeProjection& projection) -> bool {
        const auto policy = ApfsNamePolicy::FromIncompatibleFeatures(volume.incompatible_features);
        if (volume.locked || projection.volume_object_id != volume.object_id ||
            projection.checkpoint_xid != container.checkpoint_xid ||
            volume.superblock_xid == 0 || volume.superblock_xid > container.checkpoint_xid ||
            volume.superblock_block == 0 || projection.volume_superblock_block != volume.superblock_block ||
            projection.incompatible_features != volume.incompatible_features ||
            projection.name_policy.case_mode != policy.case_mode ||
            projection.name_policy.normalization_mode != policy.normalization_mode ||
            projection.root_directory_inode == 0)
            return Fail(error, "FirmlinkProjectionMismatch");
        std::map<std::uint64_t, const MetadataStore::InodeRecord*> inodes;
        std::set<std::uint64_t> linked_directories;
        std::set<std::pair<std::uint64_t, std::vector<std::byte>>> names;
        for (const auto& inode : projection.inodes)
        {
            if (inode.object_id == 0 || !inodes.emplace(inode.object_id, &inode).second)
                return Fail(error, "FirmlinkDuplicateInode");
            if (inode.is_directory != (inode.node_type == MetadataStore::NodeType::Directory))
                return Fail(error, "FirmlinkDirectoryKindMismatch");
            if (!inode.is_directory) continue;
            if (inode.object_id != projection.root_directory_inode && inode.parent_object_id == inode.object_id)
                return Fail(error, "FirmlinkParentCycle");
            if (inode.xid == 0 || inode.xid > projection.checkpoint_xid ||
                !inode.symlink_target_utf8.empty() || (inode.mode & 0170000) != 0040000)
                return Fail(error, "FirmlinkDirectoryMetadataInvalid");
            const Key key{volume.object_id, inode.object_id};
            catalog::ResolvedMountVolume resolved{container.container_uuid_hex, volume.volume_uuid_hex,
                volume.name_utf8, volume.object_id, volume.incompatible_features};
            table->directories_.emplace(key, Directory{
                {std::move(resolved), inode.object_id, projection.checkpoint_xid, inode.xid},
                {volume.object_id, inode.parent_object_id}});
        }
        const Key root{volume.object_id, projection.root_directory_inode};
        if (!table->directories_.contains(root) || table->directories_.at(root).parent != root)
            return Fail(error, "FirmlinkRootInvalid");
        for (const auto& link : projection.directory_links)
        {
            const auto child = inodes.find(link.child_object_id);
            if (child == inodes.end() || !table->directories_.contains({volume.object_id, link.parent_object_id}))
                return Fail(error, "FirmlinkDirectoryLinkDangling");
            if (link.xid == 0 || link.xid > projection.checkpoint_xid)
                return Fail(error, "FirmlinkDirectoryLinkXidInvalid");
            const auto name = ApfsNameCodec::Decode(std::as_bytes(std::span(link.entry_name_utf8)), policy);
            if (!name.ok() || name.value->windows_display != link.entry_name ||
                !names.emplace(link.parent_object_id, name.value->lookup_key).second)
                return Fail(error, "FirmlinkDirectoryNameInvalid");
            if (!child->second->is_directory) continue;
            if (link.child_object_id == projection.root_directory_inode ||
                !linked_directories.insert(link.child_object_id).second ||
                link.parent_object_id != child->second->parent_object_id ||
                link.entry_name_utf8 != child->second->name_utf8)
                return Fail(error, "FirmlinkDirectoryParentAmbiguous");
        }
        for (const auto& [key, directory] : table->directories_)
        {
            if (key.first != volume.object_id) continue;
            if (!table->directories_.contains(directory.parent) ||
                (key != root && !linked_directories.contains(key.second)))
                return Fail(error, "FirmlinkDirectoryParentMissing");
        }
        return true;
    };
    if (!add_volume(*system_volume, system) || !add_volume(*data_volume, data)) return false;
    for (const auto& record : records)
    {
        if (!table->Matches(record.source) || !table->Matches(record.target) ||
            record.source.volume.object_id != system_volume->object_id ||
            record.target.volume.object_id != data_volume->object_id)
            return Fail(error, "FirmlinkRecordIdentityInvalid");
        const Key source{record.source.volume.object_id, record.source.object_id};
        const Key target{record.target.volume.object_id, record.target.object_id};
        // Root replacement has no demonstrated semantics in this foundation.
        if (source.second == system.root_directory_inode || target.second == data.root_directory_inode)
            return Fail(error, "FirmlinkRootCrossingUnsupported");
        if (!table->forward_.emplace(source, target).second || !table->reverse_.emplace(target, source).second)
            return Fail(error, "FirmlinkMappingNotOneToOne");
    }
    if (!table->ValidateChains(error) || !table->ValidateUnnestedCrossings(error)) return false;
    out = std::move(table);
    return true;
}

bool ApfsFirmlinkRouter::Matches(const FirmlinkObjectIdentity& value) const
{
    const auto it = directories_.find({value.volume.object_id, value.object_id});
    return it != directories_.end() && SameIdentity(value, it->second.identity);
}

bool ApfsFirmlinkRouter::Forward(Key input, Key& out, std::string& error) const
{
    std::set<Key> seen;
    for (std::size_t step = 0; step < kMaxTraversalSteps; ++step)
    {
        if (!seen.insert(input).second) return Fail(error, "FirmlinkForwardCycle");
        const auto it = forward_.find(input);
        if (it == forward_.end()) { out = input; return true; }
        input = it->second;
    }
    return Fail(error, "FirmlinkForwardLimit");
}

bool ApfsFirmlinkRouter::Parent(Key input, Key& out, std::string& error) const
{
    // XNU vfs_cache.c: dotdot at target selects the SOURCE's parent.
    const auto reverse = reverse_.find(input);
    if (reverse != reverse_.end()) input = reverse->second;
    return Forward(directories_.at(input).parent, out, error);
}

bool ApfsFirmlinkRouter::ValidateChains(std::string& error) const
{
    for (const auto& [start, directory] : directories_)
    {
        (void)directory;
        Key ignored;
        if (!Forward(start, ignored, error)) return false;
        // Check both backing and unified parent graphs; never recurse on disk.
        for (const bool unified : {false, true})
        {
            Key current = start;
            std::set<Key> seen;
            bool rooted = false;
            for (std::size_t step = 0; step < kMaxTraversalSteps; ++step)
            {
                if (!seen.insert(current).second) return Fail(error, "FirmlinkParentCycle");
                Key parent;
                if (unified)
                {
                    if (!Parent(current, parent, error)) return false;
                }
                else parent = directories_.at(current).parent;
                if (parent == current && directories_.at(current).parent == current && !reverse_.contains(current))
                { rooted = true; break; }
                current = parent;
            }
            if (!rooted) return Fail(error, "FirmlinkParentLimit");
        }
    }
    return true;
}

bool ApfsFirmlinkRouter::ValidateUnnestedCrossings(std::string& error) const
{
    // A nested source is hidden by its ancestor's crossing. Nested targets
    // likewise introduce additional downward aliases. This bounded foundation
    // refuses both until a complete namespace projection proves round trips.
    for (const auto* edges : {&forward_, &reverse_})
        for (const auto& [start, target] : *edges)
        {
            (void)target;
            auto current = directories_.at(start).parent;
            bool rooted = false;
            for (std::size_t step = 0; step < kMaxTraversalSteps; ++step)
            {
                if (edges->contains(current)) return Fail(error, "FirmlinkNestedCrossingUnsupported");
                const auto parent = directories_.at(current).parent;
                if (parent == current) { rooted = true; break; }
                current = parent;
            }
            if (!rooted) return Fail(error, "FirmlinkParentLimit");
        }
    return true;
}

bool ApfsFirmlinkRouter::TryRoute(const FirmlinkObjectIdentity& input,
    FirmlinkViewPolicy view, FirmlinkTraversal traversal, FirmlinkAccess access,
    FirmlinkObjectIdentity& out, std::string& error) const
{
    // Permit input/output aliasing while still clearing outputs on failure.
    const auto original = input;
    out = {};
    error.clear();
    if ((traversal != FirmlinkTraversal::Forward && traversal != FirmlinkTraversal::Parent) ||
        (access != FirmlinkAccess::Read && access != FirmlinkAccess::Mutation))
        return Fail(error, "FirmlinkPolicyInvalid");
    if (view == FirmlinkViewPolicy::IndependentVolume) { out = original; return true; }
    if (view != FirmlinkViewPolicy::ReadOnlyUnifiedGroup) return Fail(error, "FirmlinkPolicyInvalid");
    if (access != FirmlinkAccess::Read) return Fail(error, "FirmlinkUnifiedViewReadOnly");
    if (!Matches(original)) return Fail(error, "FirmlinkIdentityNotInPinnedView");
    const Key key{original.volume.object_id, original.object_id};
    Key result;
    if (!(traversal == FirmlinkTraversal::Forward ? Forward(key, result, error) : Parent(key, result, error)))
        return false;
    out = directories_.at(result).identity;
    return true;
}
} // namespace apfsaccess::rw
