namespace
{
struct BackupImageWriterAdmission
{
    catalog::AppleCheckpointView checkpoint;
    catalog::AppleSnapshotCatalogRecords catalog;
    AppleSnapshotRetentionView retention;
    std::vector<std::byte> superblock;
};

bool AdmitBackupImageWriter(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& expected, std::uint64_t oid,
    BackupImageWriterAdmission& out, std::string& error)
{
    out = {};
    if (!source.ReadBudget()) return Fail(error, "BackupWriterBudgetRequired");
    auto loaded = catalog::LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
    if (!loaded) return false;
    const auto& nx = loaded->container.superblock;
    if (oid == 0 || loaded->volumes.size() != 1 ||
        nx.xid != expected.container.superblock.xid || nx.uuid_hex != expected.container.superblock.uuid_hex ||
        nx.block_size != 4096 || nx.block_count > 65536 || nx.block_count != source.SizeBytes() / nx.block_size ||
        source.SizeBytes() % nx.block_size != 0 ||
        (nx.features & ~catalog::kNxKnownOptionalFeaturesMask) != 0)
        return Fail(error, "BackupWriterSourceScopeUnsupported");
    const auto& volume = loaded->volumes.front();
    const auto wanted = std::find_if(expected.volumes.begin(), expected.volumes.end(),
        [&](const auto& candidate) { return candidate.superblock.object_id == oid; });
    if (wanted == expected.volumes.end() || volume.superblock.object_id != oid ||
        volume.superblock.uuid_hex != wanted->superblock.uuid_hex ||
        volume.superblock.role_raw != 0x0180 || volume.superblock.fs_flags != catalog::kFsFlagUnencrypted ||
        (volume.superblock.features & ~catalog::kVolumeKnownOptionalFeaturesMask) != 0 ||
        volume.file_extent_tree || !volume.snapshot_metadata_tree || !volume.object_map.snapshot_tree_oid)
        return Fail(error, "BackupWriterVolumeProfileUnsupported");
    // Reuse only the common feature predicate on a parsed temporary. The actual
    // APSB and serialized plans never change their canonical backup role.
    auto features = volume.superblock;
    features.role_raw = 0x0040;
    if (!CheckAppleVolumeWriteFeatures(nx, features, error)) return false;
    if (!catalog::LoadAppleSnapshotCatalog(source, *loaded, oid, out.catalog, error)) return false;
    if (out.catalog.inventory.empty() || out.catalog.inventory.size() > 64 ||
        out.catalog.inventory.size() != out.catalog.snapshots.size())
        return Fail(error, "BackupWriterSnapshotProfileUnsupported");
    if (!LoadAppleSnapshotRetention(source, *loaded, out.retention, error) ||
        !ReadObject(source, volume.superblock_object, nx.block_size, out.superblock)) return false;
    if (!NativeApfsReader::ValidateBackupWriterFileSystemRecords(out.catalog.live.filesystem,
            nx, volume.superblock, source.ReadBudget(), error)) return false;
    for (std::size_t i = 0; i < out.catalog.inventory.size(); ++i)
    {
        const auto& historical = out.catalog.inventory[i].volume.superblock;
        if (historical.role_raw != 0x0180 || historical.fs_flags != catalog::kFsFlagUnencrypted ||
            historical.uuid_hex != volume.superblock.uuid_hex ||
            !NativeApfsReader::ValidateBackupHistoricalFileSystemRecords(source, out.catalog.snapshots[i].filesystem,
                nx, historical, error))
            return error.empty() ? Fail(error, "BackupWriterHistoricalProfileUnsupported") : false;
    }
    out.checkpoint = std::move(*loaded);
    return !source.ReadBudget()->Failed();
}

bool VerifyBackupImagePublication(const catalog::RandomAccessSource& source,
    const BackupImageWriterAdmission& admitted, AppleVolumeTransactionPlan& plan, std::string& error)
{
    const auto& nx = admitted.checkpoint.container.superblock;
    const auto overlaps = [](std::uint64_t first, std::uint64_t count, std::uint64_t other, std::uint64_t size) {
        return first < other + size && other < first + count;
    };
    const auto allowed_write = [&](const AppleCheckpointPlannedWrite& write) {
        if (write.bytes.empty() || write.bytes.size() % nx.block_size != 0 ||
            write.physical_block >= nx.block_count || write.bytes.size() / nx.block_size > nx.block_count - write.physical_block)
            return false;
        const auto count = write.bytes.size() / nx.block_size;
        for (const auto block : admitted.retention.metadata_blocks)
            if (overlaps(write.physical_block, count, block, 1)) return false;
        for (const auto& payload : admitted.retention.payload_extents)
            if (overlaps(write.physical_block, count, payload.physical_block, payload.block_count)) return false;
        return true;
    };
    for (const auto& write : plan.commit.publication.before_superblock_writes)
        if (!allowed_write(write)) return Fail(error, "BackupWriterRetainedSourceOverwrite");
    if (!allowed_write(plan.commit.publication.superblock_write))
        return Fail(error, "BackupWriterRetainedSourceOverwrite");
    SnapshotPublicationSource staged(source, plan.commit.publication);
    auto after = catalog::LoadAppleCheckpointView(staged, 0, staged.SizeBytes(), error);
    if (!after || after->volumes.size() != 1 || after->container.superblock.xid != nx.next_xid)
        return Fail(error, "BackupWriterStagedScopeMismatch");
    const auto& volume = after->volumes.front();
    std::vector<std::byte> bytes;
    if (!ReadObject(staged, volume.superblock_object, nx.block_size, bytes) || bytes.size() != admitted.superblock.size())
        return Fail(error, "BackupWriterStagedApsbUnreadable");
    const auto mutable_byte = [](std::size_t at) {
        return at < 8 || (at >= 0x10 && at < 0x18) || (at >= 0x58 && at < 0x60) ||
            (at >= 0x80 && at < 0xA0) || (at >= 0xB0 && at < 0xD8) ||
            (at >= 0xE0 && at < 0xF0) || (at >= 0x100 && at < 0x108);
    };
    for (std::size_t at = 0; at < bytes.size(); ++at)
        if (!mutable_byte(at) && bytes[at] != admitted.superblock[at])
            return Fail(error, "BackupWriterOpaqueApsbChanged");
    if (volume.superblock.role_raw != 0x0180 ||
        volume.superblock.snap_meta_tree_oid != admitted.checkpoint.volumes.front().superblock.snap_meta_tree_oid)
        return Fail(error, "BackupWriterIdentityOrInventoryChanged");
    catalog::AppleSnapshotCatalogRecords catalog;
    if (!catalog::LoadAppleSnapshotCatalog(staged, *after, volume.superblock.object_id, catalog, error) ||
        catalog.inventory.size() != admitted.catalog.inventory.size() || catalog.snapshots.size() != admitted.catalog.snapshots.size())
        return Fail(error, "BackupWriterHistoricalInventoryChanged");
    for (std::size_t i = 0; i < catalog.inventory.size(); ++i)
    {
        const auto& a = admitted.catalog.inventory[i];
        const auto& b = catalog.inventory[i];
        if (a.xid != b.xid || a.name_utf8 != b.name_utf8 || a.create_time_ns != b.create_time_ns ||
            a.change_time_ns != b.change_time_ns || a.inum != b.inum || a.flags != b.flags ||
            a.volume.superblock_object.physical_block != b.volume.superblock_object.physical_block ||
            !SameRecords(admitted.catalog.snapshots[i].filesystem, catalog.snapshots[i].filesystem) ||
            !SameRecords(admitted.catalog.snapshots[i].extentref, catalog.snapshots[i].extentref))
            return Fail(error, "BackupWriterHistoricalRecordsChanged");
    }
    if (!NativeApfsReader::ValidateBackupWriterFileSystemRecords(catalog.live.filesystem,
            after->container.superblock, volume.superblock, source.ReadBudget(), error)) return false;
    for (const auto block : admitted.retention.metadata_blocks)
        if (!AddGuard(source, block, nx.block_size, plan.commit.publication.guard_blocks))
            return Fail(error, "BackupWriterHistoricalGuardUnreadable");
    return !source.ReadBudget()->Failed();
}
}

bool ValidateBackupImageWriterProfile(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& expected, std::uint64_t oid, std::string& error) try
{
    if (!source.ReadBudget()) {
        auto budget = std::make_shared<catalog::ApfsReadBudget>(65536, 256ull << 20, 1000000, 256ull << 20);
        catalog::BudgetedRandomAccessSource bounded(source, budget);
        return ValidateBackupImageWriterProfile(bounded, expected, oid, error);
    }
    SnapshotPlanningSource observed(source);
    BackupImageWriterAdmission admitted;
    return AdmitBackupImageWriter(observed, expected, oid, admitted, error) && observed.VerifyUnchanged(error);
}
catch (const std::bad_alloc&) { return Fail(error, "ApfsReadBudgetAllocationFailed"); }
catch (const std::length_error&) { return Fail(error, "ApfsReadBudgetAllocationFailed"); }
