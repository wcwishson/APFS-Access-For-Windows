namespace
{
void ClearEncryptedSnapshotTree(AppleSnapshotTreeRecords& tree) noexcept
{
    for (auto* records : {&tree.filesystem, &tree.extentref})
        for (auto& record : *records) { Wipe(record.key); Wipe(record.value); }
    tree = {};
}

void ClearEncryptedSnapshotCatalog(AppleSnapshotCatalogRecords& catalog) noexcept
{
    ClearEncryptedSnapshotTree(catalog.live);
    for (auto& tree : catalog.snapshots) ClearEncryptedSnapshotTree(tree);
    for (auto& record : catalog.inventory)
    {
        WipeText(record.name_utf8);
        WipeText(record.volume.superblock.name_utf8);
        WipeText(record.volume.superblock.uuid_hex);
        WipeText(record.volume.superblock.group_hex);
    }
    catalog = {};
}

void ClearEncryptedSnapshotParent(AppleCheckpointView& parent) noexcept
{
    for (auto& volume : parent.volumes)
    {
        WipeText(volume.superblock.name_utf8);
        WipeText(volume.superblock.uuid_hex);
        WipeText(volume.superblock.group_hex);
    }
    parent = {};
}

struct EncryptedSnapshotParentScope
{
    AppleCheckpointView& parent;
    ~EncryptedSnapshotParentScope() { ClearEncryptedSnapshotParent(parent); }
};
}

struct AppleEncryptedSnapshotReadContext::State
{
    std::shared_ptr<AppleEncryptedMetadataReadContext::State> parent;
    bool active = false;
    explicit State(std::shared_ptr<AppleEncryptedMetadataReadContext::State> value) : parent(std::move(value)) {}

    bool Bound(const RandomAccessSource& wrapped, const ContainerCheckpointView& checkpoint,
        std::string& error) const
    {
        const auto& owner = *parent->session;
        if (!active || &wrapped != static_cast<const RandomAccessSource*>(&owner) ||
            !parent->Bound(*owner.source, error))
        { if (error.empty()) error = "EncryptedSnapshotSourceAuthorityMismatch"; return false; }
        const auto& expected = parent->Checkpoint();
        const auto& nx = expected.superblock;
        if (checkpoint.superblock_bytes != expected.superblock_bytes ||
            checkpoint.superblock.xid != nx.xid || checkpoint.superblock.uuid_hex != nx.uuid_hex ||
            checkpoint.superblock.block_size != nx.block_size || checkpoint.superblock.block_count != nx.block_count ||
            checkpoint.superblock.omap_oid != nx.omap_oid || checkpoint.superblock.fs_oids != nx.fs_oids ||
            nx.block_size != 4096 || nx.block_count != owner.source_size / 4096)
        { error = "EncryptedSnapshotParentCheckpointMismatch"; return false; }
        return true;
    }

    struct NodeReader final : BtreeNodeReadContext
    {
        std::shared_ptr<State> state;
        AppleVolumeCheckpointView volume;
        std::uint64_t selection;
        std::vector<std::byte> cipher;
        crypto::SecureBytes plain;

        NodeReader(std::shared_ptr<State> authority, AppleVolumeCheckpointView selected_volume,
            std::uint64_t fs_selection)
            : state(std::move(authority)), volume(std::move(selected_volume)), selection(fs_selection) {}
        ~NodeReader() override { ReleaseNode(); }
        void ReleaseNode() noexcept override { plain.Clear(); Wipe(cipher); }

        bool ReadNode(std::uint64_t oid, std::uint64_t physical, bool root,
            std::span<const std::byte>& bytes, std::string& error) override
        {
            bytes = {}; ReleaseNode();
            auto& owner = *state->parent->session;
            const auto& checkpoint = state->parent->Checkpoint();
            if (!state->Bound(owner, checkpoint, error)) return false;
            const auto map = ResolveCanonicalMapping(owner, checkpoint, volume, selection, oid, error);
            return map && ReadMappedNode(oid, {physical, map->xid, map->flags, map->size}, root, bytes, error);
        }

        bool ReadMappedNode(std::uint64_t oid, const BtreeVirtualChildMapping& selected, bool root,
            std::span<const std::byte>& bytes, std::string& error) override
        {
            bytes = {}; ReleaseNode();
            auto& owner = *state->parent->session;
            const auto& checkpoint = state->parent->Checkpoint();
            if (!state->Bound(owner, checkpoint, error)) return false;
            const auto map = ResolveCanonicalMapping(owner, checkpoint, volume, selection, oid, error);
            if (!map || map->physical_block != selected.physical_block || map->xid != selected.xid ||
                map->flags != selected.flags || map->size != selected.size ||
                map->flags != 4 || map->size != 4096 || !map->xid || map->xid > selection ||
                map->physical_block >= checkpoint.superblock.block_count ||
                (root && oid != volume.superblock.root_oid))
            { if (error.empty()) error = "EncryptedSnapshotMappingMismatch"; return false; }
            if (!owner.Read(map->physical_block * 4096, 4096, cipher))
            { error = "EncryptedSnapshotNodeReadFailure"; return false; }
            if (!owner.Charge(0, 4096)) { error = "EncryptedSnapshotNodeBudgetExceeded"; return false; }
            auto allocation = crypto::SecureBytes::Allocate(4096);
            if (!allocation) { error = "EncryptedSnapshotSecureAllocationFailed"; return owner.Fail(CryptoErrorFor(allocation.error)); }
            plain = std::move(allocation.bytes);
            if (!owner.Transform(cipher, map->physical_block * 8, plain.Bytes()))
            { error = "EncryptedSnapshotNodeTransformFailure"; return false; }
            const auto view = std::span<const std::byte>(plain.Bytes());
            const auto type = 0x10000000u | (root ? kObjectTypeBtree : kObjectTypeBtreeNode);
            if (!VerifyObjectChecksum(view, 4096) || ReadU64LE(view, 8) != oid ||
                ReadU64LE(view, 16) != map->xid || ReadU32LE(view, 24) != type ||
                ReadU32LE(view, 28) != kObjectTypeFsTree ||
                (ReadU16LE(view, 32).value_or(0xFFFFu) & ~7u) != 0)
            { error = "EncryptedSnapshotNodeIntegrityFailure"; ReleaseNode(); return false; }
            if (!state->Bound(owner, checkpoint, error)) { ReleaseNode(); return false; }
            bytes = view; return true;
        }
    };
};

AppleEncryptedSnapshotReadContext::AppleEncryptedSnapshotReadContext(std::shared_ptr<State> state)
    : state_(std::move(state)) {}
AppleEncryptedSnapshotReadContext::~AppleEncryptedSnapshotReadContext() = default;

std::unique_ptr<AppleEncryptedSnapshotReadContext> ApfsEncryptedReadSession::CreateSnapshotVerificationContext(
    AppleEncryptedMetadataReadContext& parent, std::string& error)
{
    error.clear();
    std::lock_guard lock(impl_->mutex);
    impl_->failure = Error::None;
    if (!parent.state_ || parent.state_->session != impl_)
    { error = "EncryptedSnapshotParentOwnerMismatch"; return {}; }
    if (!impl_->Check() || !parent.state_->Bound(*impl_->source, error))
    { if (error.empty()) error = "EncryptedSnapshotSessionRevoked"; return {}; }
    try
    {
        Impl::RuntimeScope scope(*impl_);
        if (!impl_->Charge(1, sizeof(AppleEncryptedSnapshotReadContext::State)))
        { error = "EncryptedSnapshotContextBudgetExceeded"; return {}; }
        return std::unique_ptr<AppleEncryptedSnapshotReadContext>(new AppleEncryptedSnapshotReadContext(
            std::make_shared<AppleEncryptedSnapshotReadContext::State>(parent.state_)));
    }
    catch (const std::bad_alloc&) { error = "EncryptedSnapshotContextAllocationFailed"; return {}; }
}

std::unique_ptr<AppleEncryptedSnapshotReadContext> ApfsEncryptedReadSession::CreateRetainedSnapshotVerificationContext(
    std::uint64_t xid, std::string& error)
{
    error.clear();
    std::lock_guard lock(impl_->mutex);
    impl_->failure = Error::None;
    if (!impl_->Check()) { error = "EncryptedSnapshotSessionRevoked"; return {}; }
    try
    {
        Impl::RuntimeScope budget(*impl_);
        auto proof = SoftwareKeybagEraAuthority::ProveReadOnlySnapshotParent(*impl_->source, *impl_,
            impl_->identity, impl_->revision, impl_->key, impl_->checkpoint, impl_->volume, xid, error);
        if (!proof || !impl_->Check())
        { if (error.empty()) error = "EncryptedSnapshotSessionRevoked"; return {}; }
        if (!impl_->Charge(2, sizeof(AppleEncryptedMetadataReadContext::State) + sizeof(AppleEncryptedSnapshotReadContext::State)))
        { error = "EncryptedSnapshotContextBudgetExceeded"; return {}; }
        auto parent = std::make_shared<AppleEncryptedMetadataReadContext::State>(impl_,
            std::move(proof->checkpoint_), std::move(proof->volume_));
        auto context = std::unique_ptr<AppleEncryptedSnapshotReadContext>(new AppleEncryptedSnapshotReadContext(
            std::make_shared<AppleEncryptedSnapshotReadContext::State>(std::move(parent))));
        AppleCheckpointView canonical;
        EncryptedSnapshotParentScope clear_parent{canonical};
        AppleSnapshotCatalogRecords catalog;
        struct CatalogScope
        {
            AppleSnapshotCatalogRecords& value;
            ~CatalogScope() { ClearEncryptedSnapshotCatalog(value); }
        } clear_catalog{catalog};
        std::vector<AppleSnapshotMetadataClaim> owners;
        if (!context->LoadCatalogLocked(*impl_->source, canonical, catalog, owners, error) ||
            !impl_->Check() || !context->state_->parent->Bound(*impl_->source, error))
        { if (error.empty()) error = "EncryptedSnapshotRetainedParentCanonicalWalkFailed"; return {}; }
        return context;
    }
    catch (const std::bad_alloc&) { error = "EncryptedSnapshotContextAllocationFailed"; return {}; }
    catch (...) { error = "EncryptedSnapshotRetainedParentReadFailure"; return {}; }
}

std::unique_ptr<BtreeNodeReadContext> AppleEncryptedSnapshotReadContext::CreateCanonicalNodeReader(
    const RandomAccessSource& wrapped_owner, const ContainerCheckpointView& checkpoint,
    const AppleVolumeCheckpointView& volume, std::uint64_t fs_selection_xid, std::string& error)
{
    if (!state_->Bound(wrapped_owner, checkpoint, error)) return {};
    auto& owner = *state_->parent->session;
    const auto& selected = volume.superblock;
    const auto& parent = state_->parent->Volume();
    const bool parent_volume = state_->parent->Selection(checkpoint, volume);
    constexpr std::uint64_t encryption_rolled = 0x4;
    if (!fs_selection_xid || selected.xid > checkpoint.superblock.xid ||
        fs_selection_xid > selected.xid || (parent_volume && fs_selection_xid != selected.xid) ||
        selected.uuid_hex != parent.uuid_hex || selected.fs_flags != kFsFlagOneKey ||
        selected.root_tree_type != kObjectTypeBtree || !selected.root_oid || !selected.omap_oid ||
        selected.readonly_features || (selected.features & ~kVolumeKnownOptionalFeaturesMask) ||
        (selected.incompatible_features & ~(kVolumeSupportedIncompatibleFeaturesMask | encryption_rolled)) ||
        selected.fext_tree_oid || selected.snap_meta_ext_oid || !selected.name_valid ||
        selected.object_id != volume.superblock_object.object_id ||
        volume.superblock_object.xid != selected.xid || volume.superblock_object.size_bytes != 4096 ||
        volume.superblock_object.physical_block >= checkpoint.superblock.block_count ||
        volume.superblock_object.type != (parent_volume ? kObjectTypeFs : kObjectPhysical | kObjectTypeFs) ||
        (!parent_volume && selected.object_id != volume.superblock_object.physical_block) ||
        volume.superblock_object.subtype != 0 ||
        volume.object_map.object.object_id != selected.omap_oid ||
        volume.object_map.object.physical_block != selected.omap_oid ||
        volume.object_map.object.type != (kObjectPhysical | kObjectTypeOmap) ||
        volume.object_map.object.subtype != 0 || volume.object_map.object.size_bytes != 4096 ||
        !volume.object_map.object.xid || volume.object_map.object.xid > checkpoint.superblock.xid)
    { error = "EncryptedSnapshotVolumeProfileUnsupported"; owner.Fail(Error::UnsupportedEncryptionLayout); return {}; }
    const auto charge = sizeof(State::NodeReader) + selected.name_utf8.size() +
        selected.uuid_hex.size() + selected.group_hex.size();
    if (!owner.Charge(1, charge)) { error = "EncryptedSnapshotReaderBudgetExceeded"; return {}; }
    return std::make_unique<State::NodeReader>(state_, volume, fs_selection_xid);
}

bool AppleEncryptedSnapshotReadContext::LoadCatalogBound(const RandomAccessSource& original,
    AppleSnapshotCatalogRecords& output,
    std::vector<AppleSnapshotMetadataClaim>& owners, std::string& error)
{
    AppleCheckpointView parent;
    EncryptedSnapshotParentScope clear_parent{parent};
    return LoadCatalogBound(original, parent, output, owners, error);
}

bool AppleEncryptedSnapshotReadContext::LoadCatalogBound(const RandomAccessSource& original,
    AppleCheckpointView& canonical_parent, AppleSnapshotCatalogRecords& output,
    std::vector<AppleSnapshotMetadataClaim>& owners, std::string& error)
{
    auto& owner = *state_->parent->session;
    ClearEncryptedSnapshotParent(canonical_parent); ClearEncryptedSnapshotCatalog(output); owners.clear(); error.clear();
    std::lock_guard lock(owner.mutex);
    owner.failure = Error::None;
    try
    {
        ApfsEncryptedReadSession::Impl::RuntimeScope budget(owner);
        return LoadCatalogLocked(original, canonical_parent, output, owners, error);
    }
    catch (const std::bad_alloc&) { error = "EncryptedSnapshotCatalogAllocationFailed"; return owner.Fail(Error::ResourceLimit); }
    catch (...) { error = "EncryptedSnapshotCatalogReadFailure"; return false; }
}

bool AppleEncryptedSnapshotReadContext::LoadCatalogLocked(const RandomAccessSource& original,
    AppleSnapshotCatalogRecords& output, std::vector<AppleSnapshotMetadataClaim>& owners, std::string& error)
{
    AppleCheckpointView parent;
    EncryptedSnapshotParentScope clear_parent{parent};
    return LoadCatalogLocked(original, parent, output, owners, error);
}

bool AppleEncryptedSnapshotReadContext::LoadCatalogLocked(const RandomAccessSource& original,
    AppleCheckpointView& canonical_parent, AppleSnapshotCatalogRecords& output,
    std::vector<AppleSnapshotMetadataClaim>& owners, std::string& error)
{
    ClearEncryptedSnapshotParent(canonical_parent); ClearEncryptedSnapshotCatalog(output); owners.clear(); error.clear();
    struct OutputScope
    {
        AppleCheckpointView& parent;
        AppleSnapshotCatalogRecords& catalog;
        std::vector<AppleSnapshotMetadataClaim>& owners;
        bool committed = false;
        ~OutputScope()
        {
            if (!committed) { ClearEncryptedSnapshotParent(parent); ClearEncryptedSnapshotCatalog(catalog); owners.clear(); }
        }
    } publish{canonical_parent, output, owners};
    auto& state = *state_;
    auto& owner = *state.parent->session;
    struct ActiveScope
    {
        AppleEncryptedSnapshotReadContext::State& state;
        ~ActiveScope() { state.active = false; }
    } active{state};
    struct ResultScope
    {
        AppleSnapshotCatalogRecords& value;
        ~ResultScope() { ClearEncryptedSnapshotCatalog(value); }
    };
    try
    {
        if (!owner.Check() || !state.parent->Bound(original, error))
        { if (error.empty()) error = "EncryptedSnapshotSessionRevoked"; return false; }
        state.active = true;
        auto& nodes = state.parent->historical_checkpoint
            ? static_cast<BtreeNodeReadContext&>(*state.parent) : static_cast<BtreeNodeReadContext&>(owner);
        AppleEncryptedMetadataReadContext::State::NodeScope clear_parent_node{*state.parent};
        auto checkpoint = AppleEncryptedMetadataReadContext::LoadCanonical(owner, state.parent->Checkpoint(),
            state.parent->Volume(), nodes, error, false);
        if (!checkpoint) return false;
        const auto selected = std::find_if(checkpoint->volumes.begin(), checkpoint->volumes.end(),
            [&](const auto& volume) { return volume.superblock.object_id == state.parent->Volume().object_id; });
        if (selected == checkpoint->volumes.end() || !state.parent->Selection(checkpoint->container, *selected) ||
            !state.Bound(owner, checkpoint->container, error))
        { if (error.empty()) error = "EncryptedSnapshotCanonicalParentMismatch"; return false; }
        AppleSnapshotCatalogRecords result;
        ResultScope clear_result{result};
        std::vector<AppleSnapshotMetadataClaim> claims;
        if (!AppleEncryptedSnapshotReadContext::LoadCatalogCanonical(owner, *checkpoint,
                selected->superblock.object_id, *this, result, claims, error) ||
            !state.parent->Bound(original, error) || !state.Bound(owner, checkpoint->container, error)) return false;
        canonical_parent = std::move(*checkpoint);
        output = std::move(result); owners = std::move(claims); publish.committed = true; return true;
    }
    catch (const std::bad_alloc&) { error = "EncryptedSnapshotCatalogAllocationFailed"; return owner.Fail(Error::ResourceLimit); }
    catch (...) { error = "EncryptedSnapshotCatalogReadFailure"; return false; }
}

Error ApfsEncryptedReadSession::ValidateSnapshotNamespace(AppleEncryptedSnapshotReadContext& context,
    std::uint64_t exact_snapshot_xid, EncryptedNamespaceInfo& output, std::string& error)
{
    return ValidateSnapshotNamespaceImpl(context, exact_snapshot_xid, output, error);
}

Error ApfsEncryptedReadSession::ValidateSnapshotParentNamespace(AppleEncryptedSnapshotReadContext& context,
    EncryptedNamespaceInfo& output, std::string& error)
{
    return ValidateSnapshotNamespaceImpl(context, std::nullopt, output, error);
}

Error ApfsEncryptedReadSession::ValidateSnapshotNamespaceImpl(AppleEncryptedSnapshotReadContext& context,
    std::optional<std::uint64_t> exact_snapshot_xid, EncryptedNamespaceInfo& output, std::string& error)
{
    output = {}; error.clear();
    std::lock_guard lock(impl_->mutex);
    impl_->failure = Error::None;
    const auto fail = [&](Error code, const char* detail) {
        if (error.empty()) error = detail;
        return code;
    };
    auto& parent = *context.state_->parent;
    if (parent.session != impl_)
        return fail(Error::SourceIdentityMismatch, "EncryptedSnapshotNamespaceOwnerMismatch");
    if (!impl_->Check()) return fail(impl_->failure, "EncryptedSnapshotNamespaceSessionRevoked");
    if (exact_snapshot_xid && (!*exact_snapshot_xid || *exact_snapshot_xid > parent.Checkpoint().superblock.xid))
        return fail(Error::InvalidArgument, "EncryptedSnapshotNamespaceExactSelectionRequired");
    AppleCheckpointView canonical_parent;
    EncryptedSnapshotParentScope clear_parent{canonical_parent};
    AppleSnapshotCatalogRecords catalog;
    struct CatalogScope
    {
        AppleSnapshotCatalogRecords& catalog;
        ~CatalogScope() { ClearEncryptedSnapshotCatalog(catalog); }
    } clear{catalog};
    try
    {
        Impl::RuntimeScope budget(*impl_);
        std::vector<AppleSnapshotMetadataClaim> owners;
        if (!context.LoadCatalogLocked(*impl_->source, canonical_parent, catalog, owners, error))
        {
            if (!impl_->Check()) return fail(impl_->failure, "EncryptedSnapshotNamespaceCanonicalWalkFailed");
            return fail(impl_->failure == Error::None ? Error::MetadataIntegrityFailure : impl_->failure,
                "EncryptedSnapshotNamespaceCanonicalWalkFailed");
        }
        if (catalog.inventory.size() != catalog.snapshots.size())
            return fail(Error::MetadataIntegrityFailure, "EncryptedSnapshotNamespaceCatalogMismatch");
        const AppleSnapshotTreeRecords* tree = &catalog.live;
        auto features = parent.Volume().incompatible_features;
        if (exact_snapshot_xid)
        {
            const auto snapshot = std::find_if(catalog.inventory.begin(), catalog.inventory.end(),
                [&](const auto& value) { return value.xid == *exact_snapshot_xid; });
            if (snapshot == catalog.inventory.end())
                return fail(Error::InvalidArgument, "EncryptedSnapshotNamespaceExactXidMissing");
            tree = &catalog.snapshots[static_cast<std::size_t>(snapshot - catalog.inventory.begin())];
            features = snapshot->volume.superblock.incompatible_features;
        }
        if (!parent.Bound(*impl_->source, error))
            return fail(impl_->failure, "EncryptedSnapshotNamespaceSourceChanged");
        if (!impl_->Charge(1, sizeof(Impl)))
            return fail(impl_->failure, "EncryptedSnapshotNamespaceBudgetExceeded");
        Impl projection;
        projection.projection_authority = impl_.get();
        projection.source = impl_->source; projection.identity = impl_->identity;
        projection.revision = impl_->revision; projection.source_size = impl_->source_size;
        projection.budget = impl_->budget; projection.operation_budget = impl_->operation_budget;
        projection.checkpoint.superblock.block_size = parent.Checkpoint().superblock.block_size;
        projection.checkpoint.superblock.block_count = parent.Checkpoint().superblock.block_count;
        projection.name_policy = rw::ApfsNamePolicy::FromIncompatibleFeatures(features);
        if (!projection.Project(tree->filesystem))
            return fail(projection.failure, projection.failure == Error::UnsupportedEncryptionLayout
                ? "EncryptedSnapshotNamespaceProfileUnsupported" : "EncryptedSnapshotNamespaceIntegrityFailure");
        if (!projection.namespace_ready)
            return fail(Error::NamespaceUnavailable, "EncryptedSnapshotNamespaceUnavailable");
        if (!parent.Bound(*impl_->source, error))
            return fail(impl_->failure == Error::None ? Error::SourceIdentityMismatch : impl_->failure,
                "EncryptedSnapshotNamespaceFinalBindingMismatch");
        output = {2, projection.nodes.size(), projection.entries.size(), projection.name_policy};
        return Error::None;
    }
    catch (const std::bad_alloc&) { return fail(Error::ResourceLimit, "EncryptedSnapshotNamespaceAllocationFailed"); }
    catch (...) { return fail(Error::ReadFailure, "EncryptedSnapshotNamespaceReadFailure"); }
}

bool LoadAppleEncryptedSnapshotCatalog(const RandomAccessSource& original,
    AppleEncryptedSnapshotReadContext& context, AppleSnapshotCatalogRecords& output,
    std::vector<AppleSnapshotMetadataClaim>& owners, std::string& error)
{
    return context.LoadCatalogBound(original, output, owners, error);
}

bool LoadAppleEncryptedSnapshotCatalog(const RandomAccessSource& original,
    AppleEncryptedSnapshotReadContext& context, AppleCheckpointView& canonical_parent,
    AppleSnapshotCatalogRecords& output, std::vector<AppleSnapshotMetadataClaim>& owners, std::string& error)
{
    return context.LoadCatalogBound(original, canonical_parent, output, owners, error);
}
