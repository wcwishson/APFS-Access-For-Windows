#pragma once

// Value evidence captured under the full-peer gates and coordinator publication
// guard. The control request never supplies this descriptor or its factory.
struct HeldPhysicalSnapshotInventoryPeer
{
    const MountContext* const member;
    const apfsaccess::rw::MetadataStore* const store;
    const apfsaccess::rw::TransactionManager* const journal;
    const std::uint64_t volume_oid;
    const std::uint64_t clean_journal_generation;
    const bool canonical_raw_commit;
};

struct HeldPhysicalSnapshotInventoryAuthority
{
    const apfsaccess::catalog::ContainerMountCoordinator* const owner;
    const apfsaccess::rw::BlockDevice* const device;
    const apfsaccess::rw::MetadataStore* const store;
    const MountContext* const member;
    // The published checkpoint XID is the externally visible owner generation.
    const std::uint64_t owner_generation;
    const apfsaccess::catalog::ApfsSnapshotScope scope;
    const std::uint64_t raw_limit;
    const std::string source_identity;
    const std::vector<HeldPhysicalSnapshotInventoryPeer> peers;
};

bool DescribePhysicalSnapshotInventoryWindow(const MountContext& ctx,
    const apfsaccess::rw::MetadataStore& store,
    const apfsaccess::catalog::AppleCheckpointView& published,
    apfsaccess::catalog::ApfsSnapshotScope& scope, std::string& error)
{
    error = "SnapshotPhysicalInventoryWindowRequired";
    const auto& nx = published.container.superblock;
    const auto& device = store.Device();
    if (&store != ctx.metadata_store || store.IsImmutableSnapshotView() ||
        device.Path() != ctx.args.device || device.BaseOffsetBytes() != ctx.args.device_offset_bytes ||
        nx.uuid_hex != WideToUtf8(ctx.args.container_id) || !nx.block_size || !nx.block_count ||
        nx.block_count > UINT64_MAX / nx.block_size) return false;
    const auto size = nx.block_count * nx.block_size;
    const auto base = device.BaseOffsetBytes();
    if (base > UINT64_MAX - size || device.GetGeometry().total_bytes < size) return false;
    const auto volume = std::find_if(published.volumes.begin(), published.volumes.end(),
        [&](const auto& v) { return v.superblock.object_id == ctx.container_volume_oid; });
    if (volume == published.volumes.end() || !apfsaccess::rw::CheckAppleVolumeWriteFeatures(
        nx, volume->superblock, error)) return false;
    scope = {base, size, nx.uuid_hex, volume->superblock.uuid_hex, ctx.container_volume_oid, nx.xid};
    error.clear();
    return true;
}

std::optional<HeldPhysicalSnapshotInventoryAuthority> CaptureHeldPhysicalSnapshotInventoryAuthority(
    const MountContext& ctx, apfsaccess::catalog::ContainerMountCoordinator& coordinator,
    const apfsaccess::rw::MetadataStore& store,
    const apfsaccess::catalog::AppleCheckpointView& published)
{
    const auto& device = store.Device();
    // A held file, pathname or option alone cannot produce production evidence.
    if (&store != ctx.metadata_store || ctx.container_coordinator != &coordinator ||
        &device != &coordinator.Device() || !device.IsRawWriterAccepted() || !device.HasWriteHandle() ||
        !store.Context().allow_raw_device_canonical_commit || device.RawWriterIdentity().empty()) return std::nullopt;
    apfsaccess::catalog::ApfsSnapshotScope scope;
    std::string error;
    if (!DescribePhysicalSnapshotInventoryWindow(ctx, store, published, scope, error)) return std::nullopt;
    std::vector<HeldPhysicalSnapshotInventoryPeer> peers;
    for (const auto* peer : ctx.container_session_contexts)
    {
        if (!peer || !peer->metadata_store || !peer->tx_manager) return std::nullopt;
        peers.push_back({peer, peer->metadata_store, peer->tx_manager.get(), peer->container_volume_oid,
            peer->tx_manager->ValidatedCleanJournalGeneration(),
            peer->metadata_store->Context().allow_raw_device_canonical_commit});
    }
    return HeldPhysicalSnapshotInventoryAuthority{&coordinator, &device, &store, &ctx,
        published.container.superblock.xid, scope, device.RawWriteLimitBytes(), device.RawWriterIdentity(), std::move(peers)};
}

bool ValidateHeldPhysicalSnapshotInventoryAuthority(const HeldPhysicalSnapshotInventoryAuthority& authority,
    const MountContext& ctx, apfsaccess::catalog::ContainerMountCoordinator& coordinator,
    const apfsaccess::rw::MetadataStore& store, const apfsaccess::catalog::AppleCheckpointView& published,
    LiveVolumeVerificationScope& out, std::string& error)
{
    out = {};
    error = "SnapshotPhysicalInventoryOwnerRequired";
    const auto& device = store.Device();
    if (authority.owner != &coordinator || ctx.container_coordinator != &coordinator ||
        authority.device != &device || &device != &coordinator.Device() || authority.store != &store ||
        !device.HasWriteHandle() || authority.source_identity.empty() || authority.source_identity.size() > 192) return false;
    if (authority.member != &ctx || authority.scope.volume_oid != ctx.container_volume_oid)
    { error = "SnapshotPhysicalInventoryMemberRequired"; return false; }
    if (!authority.owner_generation || authority.owner_generation != coordinator.CheckpointXid() ||
        authority.owner_generation != published.container.superblock.xid)
    { error = "SnapshotPhysicalInventoryOwnerGenerationChanged"; return false; }
    apfsaccess::catalog::ApfsSnapshotScope scope;
    if (!DescribePhysicalSnapshotInventoryWindow(ctx, store, published, scope, error)) return false;
    if (!(authority.scope == scope) || authority.raw_limit != scope.store_size_bytes)
    { error = "SnapshotPhysicalInventoryWindowRequired"; return false; }
    if (authority.peers.size() != ctx.container_session_contexts.size())
    { error = "SnapshotPhysicalInventoryMemberRequired"; return false; }
    for (const auto* peer : ctx.container_session_contexts)
    {
        // Shared admission checks these first; also keep this validator total
        // for a missing member/store/journal descriptor.
        if (!peer || !peer->metadata_store || !peer->tx_manager)
        { error = "SnapshotPhysicalInventoryMemberRequired"; return false; }
        const auto found = std::find_if(authority.peers.begin(), authority.peers.end(),
            [&](const auto& fact) { return fact.member == peer; });
        if (found == authority.peers.end() || std::count_if(authority.peers.begin(), authority.peers.end(),
            [&](const auto& fact) { return fact.member == peer; }) != 1 ||
            found->volume_oid != peer->container_volume_oid || found->store != peer->metadata_store ||
            found->journal != peer->tx_manager.get() || &peer->metadata_store->Device() != &device)
        { error = "SnapshotPhysicalInventoryMemberRequired"; return false; }
        if (!found->canonical_raw_commit || peer->metadata_store->Context().allow_native_snapshot_runtime)
        { error = "SnapshotPhysicalInventoryCleanPeerRequired"; return false; }
        if (!found->clean_journal_generation ||
            found->clean_journal_generation != peer->tx_manager->ValidatedCleanJournalGeneration())
        { error = "SnapshotPhysicalInventoryJournalGenerationChanged"; return false; }
        const auto member = std::find_if(published.volumes.begin(), published.volumes.end(),
            [&](const auto& v) { return v.superblock.object_id == found->volume_oid; });
        if (member == published.volumes.end() || !apfsaccess::rw::CheckAppleVolumeWriteFeatures(
            published.container.superblock, member->superblock, error)) return false;
    }
    out.exact = scope;
    out.source_identity = authority.source_identity;
    out.source_kind = "retained-admitted-raw";
    error.clear();
    return true;
}

bool SameHeldPhysicalSnapshotInventoryAuthority(const HeldPhysicalSnapshotInventoryAuthority& a,
    const HeldPhysicalSnapshotInventoryAuthority& b)
{
    if (a.owner != b.owner || a.device != b.device || a.store != b.store || a.member != b.member ||
        a.owner_generation != b.owner_generation || !(a.scope == b.scope) || a.raw_limit != b.raw_limit ||
        a.source_identity != b.source_identity || a.peers.size() != b.peers.size()) return false;
    for (std::size_t i = 0; i < a.peers.size(); ++i)
    {
        const auto& x = a.peers[i]; const auto& y = b.peers[i];
        if (x.member != y.member || x.store != y.store || x.journal != y.journal ||
            x.volume_oid != y.volume_oid || x.clean_journal_generation != y.clean_journal_generation ||
            x.canonical_raw_commit != y.canonical_raw_commit) return false;
    }
    return true;
}
