#pragma once

// Included after hydration helpers. The mount's namespace mutex protects the
// bounded open-context census; closing contexts conservatively pin promotion.
bool NativeHardLinkHasMaterializedHandlesLocked(const MountContext& c, const Node& node)
{
    if (!c.hardlink_open_census_complete || node.closing_context_count) return true;
    if (node.shared_payload)
        for (const auto& weak : node.shared_payload->aliases)
            if (const auto alias = weak.lock(); alias && alias->closing_context_count) return true;
    std::size_t observed = 0;
    for (const auto* open : c.hardlink_live_opens)
        if (open && open->node && open->node->object_id == node.object_id)
        {
            ++observed;
            if (open->node->closing_context_count || open->file.load(std::memory_order_acquire) != INVALID_HANDLE_VALUE)
                return true;
        }
    return !node.shared_payload && observed != node.live_context_count;
}

bool PrepareNativeHardLinkCache(MountContext& c, const std::shared_ptr<Node>& node, std::uint64_t generation)
{
    const auto refuse = [&](const char* reason) { c.hardlink_last_error = reason; return false; };
    if (!node || !generation) return refuse("HardLinkCacheIdentityMissing");
    std::lock_guard names(c.mutex);
    if (c.hardlink_payload_opens_inflight.load(std::memory_order_acquire)) return refuse("HardLinkCacheOpenInFlight");
    if (!c.hardlink_open_census_complete || node->closing_context_count ||
        TryGetNodeLockedNormalized(&c, node->path) != node || node->namespace_detached ||
        IsDeleteBlockedStateLocked(node) || HasUnrestoredHydrationLocked(&c, node) ||
        !c.named_stream_sizes.empty()) return refuse("HardLinkCacheStateUnsupported");
    const bool stale = IsHydrationStaleLocked(&c, node);
    const auto key = L"$inode:" + std::to_wstring(node->object_id);
    if (node->shared_payload)
    {
        if (stale) return refuse("HardLinkCacheStateUnsupported");
        const auto owner = c.shared_payload_owners.find(key);
        for (const auto& weak : node->shared_payload->aliases)
            if (const auto alias = weak.lock(); alias && (alias->namespace_detached || alias->closing_context_count ||
                IsDeleteBlockedStateLocked(alias))) return refuse("HardLinkCacheAliasUnavailable");
        const auto matches = owner != c.shared_payload_owners.end() && owner->second == node->shared_payload &&
            owner->second->object_id == node->object_id;
        return matches || refuse("HardLinkCacheOwnerMismatch");
    }
    std::size_t observed = 0;
    bool materialized = false;
    for (const auto* open : c.hardlink_live_opens)
        if (open && open->node && open->node->object_id == node->object_id)
        {
            if (open->node != node || open->named_stream || open->native_xattr || open->node->closing_context_count)
                return refuse("HardLinkCacheOpenUnsupported");
            ++observed;
            materialized |= open->file.load(std::memory_order_acquire) != INVALID_HANDLE_VALUE;
        }
    if (observed != node->live_context_count || c.shared_payload_owners.contains(key)) return refuse("HardLinkCacheOpenCensusMismatch");
    if (stale && materialized) return refuse("HardLinkStaleCacheHasOpenHandles");
    auto owner = std::make_shared<SharedInodePayload>();
    owner->key = key; owner->object_id = node->object_id;
    owner->file_size = node->file_size; owner->allocation_size = node->allocation_size;
    owner->timestamp = node->timestamp; owner->inode_times = node->inode_times;
    owner->visible_generation = node->times_generation;
    owner->windows_attributes = node->windows_attributes; owner->attributes_generation = node->attributes_generation;
    owner->native_security = node->native_security; owner->security_generation = node->security_generation;
    owner->deferred_access_time.store(node->deferred_access_time, std::memory_order_relaxed);
    owner->aliases.push_back(node);
    auto staged_owners = c.shared_payload_owners;
    if (!staged_owners.emplace(key, owner).second) return refuse("HardLinkCacheOwnerExists");
    auto staged_key = key;
    const auto stale_entry = stale ? c.stale_hydration_keys.find(HydrationStateKey(&c, *node)) : c.stale_hydration_keys.end();
    const auto old_path = HydrationPath(&c, *node);
    Node retained; retained.shared_payload = owner;
    const auto next_path = HydrationPath(&c, retained);
    if (old_path != next_path)
    {
        if (GetFileAttributesW(next_path.c_str()) != INVALID_FILE_ATTRIBUTES) return refuse("HardLinkCacheDestinationExists");
        const auto error = GetLastError();
        if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) return refuse("HardLinkCacheDestinationUnreadable");
    }
    WIN32_FILE_ATTRIBUTE_DATA attributes{};
    const auto exists = GetFileAttributesExW(old_path.c_str(), GetFileExInfoStandard, &attributes);
    if (!exists)
    {
        const auto error = GetLastError();
        if (materialized || (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND)) return refuse("HardLinkCachePreimageMissing");
        owner->hardlink_cold_promotion = true;
    }
    else
    {
        if ((attributes.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) ||
            (!stale && ((static_cast<std::uint64_t>(attributes.nFileSizeHigh) << 32) | attributes.nFileSizeLow) != node->file_size))
            return refuse("HardLinkCachePreimageInvalid");
        InvalidateHydrationReadHandle(&c);
        if (stale)
        {
            // No materialized handle exists. Retain the stale bytes but never
            // promote them as the canonical inode cache or read them as data.
            const auto retained = std::filesystem::path(old_path.wstring() + L".hardlink-stale." +
                std::to_wstring(node->object_id) + L"." + std::to_wstring(generation));
            if (!MoveFileExW(old_path.c_str(), retained.c_str(), 0)) return refuse("HardLinkStaleCacheRetentionFailed");
            owner->hardlink_cold_promotion = true;
        }
        else
        {
            // Moving a valid cache preserves every already-open handle.
            if (old_path != next_path && !MoveFileExW(old_path.c_str(), next_path.c_str(), 0)) return refuse("HardLinkCacheMoveFailed");
            owner->materialized_generation = generation;
        }
    }
    node->hydration_key.swap(staged_key);
    node->shared_payload = std::move(owner);
    c.shared_payload_owners.swap(staged_owners);
    if (stale_entry != c.stale_hydration_keys.end()) c.stale_hydration_keys.erase(stale_entry);
    return true;
}
