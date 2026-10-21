#pragma once

#ifdef APFSACCESS_FSHOST_UNIT_TEST
std::function<void(bool)> g_hardlink_namespace_allocation_scope;
#endif

bool PublishNativeHardLinkNamespace(MountContext& c, const std::wstring& target,
    std::uint64_t source_id, const std::shared_ptr<Node>& retained_source)
{
#ifdef APFSACCESS_FSHOST_UNIT_TEST
    if (g_hardlink_namespace_allocation_scope) g_hardlink_namespace_allocation_scope(true);
    ScopeExit allocation_scope{[] {
        if (g_hardlink_namespace_allocation_scope) g_hardlink_namespace_allocation_scope(false);
    }};
#endif
    using Store = apfsaccess::rw::MetadataStore;
    std::vector<Store::InodeRecord> entries;
    std::optional<Store::InodeRecord> added, parent_inode;
    std::unordered_map<std::uint64_t, std::optional<UINT32>> attributes;
    std::unordered_map<std::uint64_t, std::shared_ptr<const NativeInodeSecurity>> security;
    {
        std::lock_guard metadata(c.metadata_mutex);
        added = c.metadata_store->LookupCommittedInodeByPath(target);
        if (!added || added->object_id != source_id || added->node_type != Store::NodeType::RegularFile ||
            added->link_count < 2 || added->link_count > 16384) return false;
        parent_inode = c.metadata_store->LookupCommittedInodeByPath(ParentOfNormalizedPath(target));
        if (!parent_inode || !parent_inode->is_directory) return false;
        const auto inodes = c.metadata_store->SnapshotCommittedInodes();
        if (inodes.size() > 16384) return false;
        std::size_t seen = 0;
        for (const auto& inode : inodes)
        {
            if (!inode.is_directory) continue;
            const auto children = c.metadata_store->SnapshotCommittedDirectoryChildInodes(inode.object_id);
            if (!children || children->size() > 16384 - seen) return false;
            seen += children->size();
            for (const auto& child : *children) if (child.object_id == source_id) entries.push_back(child);
        }
        if (entries.size() != added->link_count) return false;
        for (const auto* inode : {&*added, &*parent_inode})
        {
            if (!CaptureCommittedWindowsAttributes(*c.metadata_store, inode->object_id, attributes)) return false;
            CaptureCommittedNativeSecurity(*c.metadata_store, *inode, security);
        }
    }
    const auto reported = CaptureReportedVolumeInfo(c);
    std::lock_guard names(c.mutex);
    const auto parent = TryGetNodeLockedNormalized(&c, parent_inode->full_path);
    if (!parent || !parent->is_directory || parent->object_id != parent_inode->object_id ||
        added->xid < c.namespace_checkpoint_xid) return false;
    const auto key = L"$inode:" + std::to_wstring(source_id);
    auto live_owner = c.shared_payload_owners.contains(key) ? c.shared_payload_owners.at(key) : nullptr;
    if (live_owner && live_owner->object_id != source_id) return false;
    for (const auto& item : c.nodes) if (item.second && item.second->object_id == source_id)
    {
        if (item.second->namespace_detached || IsDeleteBlockedStateLocked(item.second) ||
            item.second->shared_payload != live_owner) return false;
        if (!live_owner && (item.second->live_context_count || item.second->closing_context_count)) return false;
        const auto matches = std::count_if(entries.begin(), entries.end(), [&](const auto& entry) {
            return LowerPathKey(&c, entry.full_path) == item.first;
        });
        if (matches != 1) return false;
    }
    if (retained_source && (retained_source->object_id != source_id ||
        TryGetNodeLockedNormalized(&c, retained_source->path) != retained_source)) return false;

    // Existing projection runs only on detached nodes and a detached owner.
    // Every allocating step finishes before the visible namespace changes.
    MountContext staging;
    staging.reported_allocation_unit_bytes = reported.allocation_unit_bytes;
    auto staged_owner = std::make_shared<SharedInodePayload>();
    staged_owner->key = key; staged_owner->object_id = source_id;
    if (live_owner)
    {
        staged_owner->deferred_access_time.store(live_owner->deferred_access_time.load(std::memory_order_relaxed));
        staged_owner->materialized_generation = live_owner->materialized_generation;
        staged_owner->hardlink_cold_promotion = live_owner->hardlink_cold_promotion;
        staged_owner->visible_generation = live_owner->visible_generation;
        staged_owner->file_size = live_owner->file_size; staged_owner->allocation_size = live_owner->allocation_size;
        staged_owner->timestamp = live_owner->timestamp; staged_owner->inode_times = live_owner->inode_times;
        staged_owner->windows_attributes = live_owner->windows_attributes;
        staged_owner->attributes_generation = live_owner->attributes_generation;
        staged_owner->native_security = live_owner->native_security; staged_owner->security_generation = live_owner->security_generation;
    }
    else
    {
        live_owner = std::make_shared<SharedInodePayload>(); live_owner->key = key; live_owner->object_id = source_id;
        staged_owner->hardlink_cold_promotion = true;
    }
    staging.shared_payload_owners.emplace(key, staged_owner);
    std::vector<std::pair<std::shared_ptr<Node>, std::shared_ptr<Node>>> updates;
    std::vector<std::weak_ptr<Node>> aliases;
    auto staged_index = c.nodes;
    const auto now = UtcNow();
    for (const auto& entry : entries)
    {
        auto live = TryGetNodeLockedNormalized(&c, entry.full_path);
        if (live && (live->object_id != source_id || live->node_kind != NodeKind::RegularFile)) return false;
        auto staged = live ? std::make_shared<Node>(*live) : std::make_shared<Node>();
        SetNodePathNormalized(&c, *staged, entry.full_path);
        const auto directory = TryGetNodeLockedNormalized(&c, ParentOfNormalizedPath(entry.full_path));
        if (!directory || !directory->is_directory) return false;
        staged->apfs_path = ApfsChild(directory->apfs_path, LeafNameOfNormalizedPath(entry.full_path));
        staged->hydration_key = key; staged->shared_payload = staged_owner;
        staged_owner->aliases.push_back(staged);
        if (!ApplyCommittedInodeMetadataToNode(&staging, entry, now, staged,
                attributes.at(source_id), security.at(source_id))) return false;
        if (!live)
        {
            live = std::make_shared<Node>();
            if (!staged_index.emplace(staged->path_key, live).second) return false;
        }
        aliases.push_back(live); updates.emplace_back(std::move(live), std::move(staged));
    }
    auto staged_parent = std::make_shared<Node>(*parent);
    if (!ApplyCommittedInodeMetadataToNode(&staging, *parent_inode, now, staged_parent,
            attributes.at(parent_inode->object_id), security.at(parent_inode->object_id))) return false;
    AddChildName(*staged_parent, LeafNameOfNormalizedPath(target));
    auto staged_owners = c.shared_payload_owners;
    if (const auto owner = staged_owners.find(key); owner == staged_owners.end()) staged_owners.emplace(key, live_owner);
    else if (owner->second != live_owner) return false;

    static_assert(std::is_nothrow_move_assignable_v<Node>);
    static_assert(noexcept(c.nodes.swap(staged_index)) && noexcept(c.shared_payload_owners.swap(staged_owners)));
    live_owner->deferred_access_time.store(staged_owner->deferred_access_time.load(std::memory_order_relaxed));
    live_owner->materialized_generation = staged_owner->materialized_generation;
    live_owner->hardlink_cold_promotion = staged_owner->hardlink_cold_promotion;
    live_owner->visible_generation = staged_owner->visible_generation;
    live_owner->file_size = staged_owner->file_size; live_owner->allocation_size = staged_owner->allocation_size;
    live_owner->timestamp = staged_owner->timestamp; live_owner->inode_times = staged_owner->inode_times;
    live_owner->windows_attributes = staged_owner->windows_attributes;
    live_owner->attributes_generation = staged_owner->attributes_generation;
    live_owner->native_security.swap(staged_owner->native_security); live_owner->security_generation = staged_owner->security_generation;
    live_owner->aliases.swap(aliases);
    for (auto& update : updates) { update.second->shared_payload = live_owner; *update.first = std::move(*update.second); }
    *parent = std::move(*staged_parent);
    c.shared_payload_owners.swap(staged_owners); c.nodes.swap(staged_index);
    c.namespace_checkpoint_xid = (std::max)(c.namespace_checkpoint_xid, added->xid);
    return true;
}
