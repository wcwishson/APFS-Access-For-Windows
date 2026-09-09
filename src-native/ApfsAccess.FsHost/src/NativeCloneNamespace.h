#pragma once

#ifdef APFSACCESS_FSHOST_UNIT_TEST
// Brackets actual allocation sites, including STL allocations inside the
// existing metadata, child-name and index infrastructure. No alternate body.
std::function<void(bool)> g_clone_namespace_allocation_scope;
#endif

bool PublishNativeCloneNamespace(MountContext& c, const std::wstring& target,
    std::uint64_t target_id)
{
#ifdef APFSACCESS_FSHOST_UNIT_TEST
    if (g_clone_namespace_allocation_scope) g_clone_namespace_allocation_scope(true);
    ScopeExit allocation_scope{[] {
        if (g_clone_namespace_allocation_scope) g_clone_namespace_allocation_scope(false);
    }};
#endif
    using Store = apfsaccess::rw::MetadataStore;
    std::optional<Store::InodeRecord> inode, parent_inode;
    std::unordered_map<std::uint64_t, std::optional<UINT32>> attributes;
    std::unordered_map<std::uint64_t, std::shared_ptr<const NativeInodeSecurity>> security;
    {
        std::lock_guard metadata(c.metadata_mutex);
        inode = c.metadata_store->LookupCommittedInodeByPath(target);
        if (!inode || inode->object_id != target_id || inode->node_type != Store::NodeType::RegularFile ||
            inode->link_count != 1) return false;
        parent_inode = c.metadata_store->LookupCommittedInodeByPath(ParentOfNormalizedPath(inode->full_path));
        if (!parent_inode || !parent_inode->is_directory) return false;
        for (const auto* item : {&*inode, &*parent_inode})
        {
            if (!CaptureCommittedWindowsAttributes(*c.metadata_store, item->object_id, attributes)) return false;
            CaptureCommittedNativeSecurity(*c.metadata_store, *item, security);
        }
    }
    std::lock_guard names(c.mutex);
    const auto parent = TryGetNodeLockedNormalized(&c, parent_inode->full_path);
    if (!parent || parent->object_id != parent_inode->object_id || !parent->is_directory ||
        TryGetNodeLockedNormalized(&c, inode->full_path)) return false;
    // Clone gets a new inode/cache identity. Existing aliases, open contexts,
    // payload owners and directory pointer identity are preserved verbatim.
    if (c.shared_payload_owners.contains(L"$inode:" + std::to_wstring(target_id))) return false;
    auto node = std::make_shared<Node>();
    SetNodePathNormalized(&c, *node, inode->full_path);
    node->hydration_key = node->path_key;
    node->apfs_path = ApfsChild(parent->apfs_path, LeafNameOfNormalizedPath(inode->full_path));
    const auto now = UtcNow();
    if (!ApplyCommittedInodeMetadataToNode(&c, *inode, now, node,
            attributes.at(target_id), security.at(target_id))) return false;
    auto staged_parent = std::make_shared<Node>(*parent);
    if (!ApplyCommittedInodeMetadataToNode(&c, *parent_inode, now, staged_parent,
            attributes.at(parent_inode->object_id), security.at(parent_inode->object_id))) return false;
    AddChildName(*staged_parent, LeafNameOfNormalizedPath(inode->full_path));
    // Copy the existing index rather than rebuilding nodes or cache owners.
    // Any failure (even child emplace followed by vector growth) affects only
    // detached state. The visible tree stays coherent and WAL stays retained.
    auto staged_index = c.nodes;
    if (!staged_index.emplace(node->path_key, node).second) return false;
    static_assert(noexcept(c.nodes.swap(staged_index)));
    parent->children.swap(staged_parent->children);
    parent->sorted_children.swap(staged_parent->sorted_children);
    parent->child_index_by_name_key.swap(staged_parent->child_index_by_name_key);
    parent->sorted_children_valid = staged_parent->sorted_children_valid;
    parent->timestamp = staged_parent->timestamp;
    parent->inode_times = staged_parent->inode_times;
    parent->times_generation = staged_parent->times_generation;
    parent->file_size = staged_parent->file_size;
    parent->allocation_size = staged_parent->allocation_size;
    parent->allocation_unit_bytes = staged_parent->allocation_unit_bytes;
    parent->windows_attributes = staged_parent->windows_attributes;
    parent->attributes_generation = staged_parent->attributes_generation;
    parent->native_security.swap(staged_parent->native_security);
    parent->security_generation = staged_parent->security_generation;
    c.nodes.swap(staged_index);
    c.namespace_checkpoint_xid = (std::max)(c.namespace_checkpoint_xid, inode->xid);
    return true;
}
