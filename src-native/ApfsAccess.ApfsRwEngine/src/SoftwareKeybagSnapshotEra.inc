// Separate from strict writer-era admission. Only the opaque snapshot mint
// consumes this proof and it must finish the canonical snapshot catalog walk.
std::unique_ptr<SoftwareKeybagEraAuthority> SoftwareKeybagEraAuthority::ProveReadOnlySnapshotParent(
    const ImmutableEncryptedReadSource& identity_source, const RandomAccessSource& source,
    const std::string& identity, std::uint64_t revision, const PasswordUnlockResult& admitted,
    const ContainerCheckpointView& admitted_checkpoint, const ApsbVolume& admitted_volume,
    std::uint64_t historical_xid, std::string& error)
{
    error.clear();
    const auto fail = [&](const char* why) -> std::unique_ptr<SoftwareKeybagEraAuthority> { error = why; return {}; };
    const auto bound = [&] { return identity_source.SourceIdentity() == identity &&
        identity_source.Revision() == revision && identity_source.SizeBytes() == source.SizeBytes(); };
    const auto budget = source.ReadBudget();
    if (identity.empty() || !bound() || !admitted || !admitted.xts_key.IsLocked() ||
        !historical_xid || historical_xid >= admitted.checkpoint_xid)
        return fail("SoftwareKeybagEraSourceOrAdmissionMismatch");
    if (!budget || budget->Failed()) return fail("SoftwareKeybagEraResourceLimit");
    try {
        std::string detail;
        auto latest = LoadContainerCheckpointView(source, 0, source.SizeBytes(), detail);
        if (!latest || latest->superblock.xid != admitted.checkpoint_xid ||
            latest->superblock_bytes != admitted_checkpoint.superblock_bytes ||
            admitted.volume_oid != admitted_volume.object_id || admitted.volume_xid != admitted_volume.xid)
            return fail("SoftwareKeybagEraCurrentCanonicalAdmissionRequired");
        struct Era {
            PasswordUnlockRequest selection;
            ContainerCheckpointView checkpoint;
            ApsbVolume volume;
            std::vector<std::byte> apsb;
            crypto::SecureBytes container, users;
            Bytes vek_der;
            Record vek, kek;
            std::uint64_t container_block = 0, volume_block = 0;
        };
        const auto load = [&](std::uint64_t xid, Era& era) {
            auto cp = LoadContainerCheckpointView(source, 0, source.SizeBytes(), detail, xid);
            if (!cp || cp->superblock.block_size != 4096 || cp->superblock.fs_oids != std::vector<std::uint64_t>{admitted.volume_oid} ||
                cp->superblock.readonly_features || cp->superblock.xp_desc_noncontiguous || cp->superblock.xp_data_noncontiguous ||
                ReadU32LE(cp->superblock_bytes, 24) != (kObjectEphemeral | kNxSuperblockObjectType) ||
                ReadU32LE(cp->superblock_bytes, 28) != 0u)
                return false;
            std::uint64_t container_block = 0, volume_block = 0; UnlockError status{};
            auto metadata = InspectMetadata(source, admitted.volume_oid, KeybagLength::IncludesHeader, status,
                xid, &container_block, &volume_block);
            if (!metadata || metadata->users != std::vector<KeybagUuid>{admitted.user_uuid} ||
                metadata->selection.container_uuid != admitted.container_uuid || metadata->selection.volume_uuid != admitted.volume_uuid)
                return false;
            auto view = LoadAppleReadOnlyVolumeView(source, *cp, detail);
            if (!view || view->volumes.size() != 1) return false;
            const auto& selected = view->volumes.front(); const auto& volume = selected.superblock;
            if (volume.object_id != admitted.volume_oid || volume.fs_flags != kFsFlagOneKey || volume.readonly_features ||
                volume.features != admitted_volume.features || volume.incompatible_features != admitted_volume.incompatible_features ||
                volume.role_raw != admitted_volume.role_raw || volume.fext_tree_oid || volume.snap_meta_ext_oid ||
                !ReadBlock(source, selected.superblock_object.physical_block, 4096, cp->superblock.block_count, era.apsb) ||
                !ObjectMatches(era.apsb, {volume.object_id, volume.xid}, kObjectTypeFs, xid) ||
                ReadU64LE(era.apsb, 0xA0).value_or(~0ULL) || ReadU64LE(era.apsb, 0xA8).value_or(~0ULL) ||
                ReadU64LE(era.apsb, 0x3D0).value_or(~0ULL))
                return false;
            WipedVector raw;
            if (!ReadBlock(source, container_block, 4096, cp->superblock.block_count, raw.bytes)) return false;
            auto container = DecryptApfsUuidKeybagBlock(admitted.container_uuid, container_block, raw.bytes);
            if (!container || !ObjectMatches(container.bytes.Bytes(), metadata->selection.container_bag, 0x6B657973, xid, true))
                return false;
            Locker containers;
            if (ParseLocker(container.bytes.Bytes(), KeybagKind::Container, KeybagLength::IncludesHeader, containers, *budget) != UnlockError::None ||
                containers.count != 2) return false;
            const auto* vek = Find(containers, admitted.volume_uuid, 2);
            const auto* reference = Find(containers, admitted.volume_uuid, 3);
            if (!vek || !reference || Le(reference->payload.first(8)) != volume_block || Le(reference->payload.last(8)) != 1 ||
                ParseRecord(vek->payload, false, era.vek) != UnlockError::None) return false;
            if (!ReadBlock(source, volume_block, 4096, cp->superblock.block_count, raw.bytes)) return false;
            auto users = DecryptApfsUuidKeybagBlock(admitted.volume_uuid, volume_block, raw.bytes);
            if (!users || !ObjectMatches(users.bytes.Bytes(), metadata->selection.volume_bag, 0x72656373, xid, true)) return false;
            Locker locker;
            if (ParseLocker(users.bytes.Bytes(), KeybagKind::Volume, KeybagLength::IncludesHeader, locker, *budget) != UnlockError::None)
                return false;
            const auto* kek = Find(locker, admitted.user_uuid, 3);
            if (!kek || ParseRecord(kek->payload, true, era.kek) != UnlockError::None) return false;
            era.vek_der = vek->payload; era.selection = metadata->selection; era.selection.user_uuid = admitted.user_uuid;
            era.checkpoint = std::move(*cp); era.volume = volume;
            era.container_block = container_block; era.volume_block = volume_block;
            era.container = std::move(container.bytes); era.users = std::move(users.bytes);
            return true;
        };
        Era current, historical;
        if (!load(admitted.checkpoint_xid, current) || !load(historical_xid, historical))
            return fail(budget->Failed() ? "SoftwareKeybagEraResourceLimit" : "SoftwareKeybagEraCanonicalProfileMismatch");
        if (current.volume.xid != admitted.volume_xid || current.checkpoint.superblock_bytes != admitted_checkpoint.superblock_bytes ||
            !Equal(current.vek_der, historical.vek_der) || current.vek.key_bytes != historical.vek.key_bytes ||
            !Equal(current.vek.key_uuid, historical.vek.key_uuid) ||
            !Equal(current.kek.info, historical.kek.info) || !Equal(current.kek.key_uuid, historical.kek.key_uuid) ||
            current.kek.iterations != historical.kek.iterations ||
            !Equal(Bytes(current.apsb).subspan(0x60, 0x18), Bytes(historical.apsb).subspan(0x60, 0x18)))
            return fail("SoftwareKeybagEraWrappedKeyOrCryptoStateChanged");
        if (!bound() || budget->Failed()) return fail("SoftwareKeybagEraSourceOrBudgetChanged");
        if (!budget->Materialize(1, sizeof(SoftwareKeybagEraAuthority))) return fail("SoftwareKeybagEraResourceLimit");
        auto proof = std::unique_ptr<SoftwareKeybagEraAuthority>(new SoftwareKeybagEraAuthority);
        proof->selection_ = historical.selection; proof->checkpoint_ = std::move(historical.checkpoint);
        proof->volume_ = historical.volume;
        proof->container_block_ = historical.container_block; proof->volume_block_ = historical.volume_block;
        proof->current_container_block_ = current.container_block; proof->current_volume_block_ = current.volume_block;
        return proof;
    } catch (const std::bad_alloc&) { return fail("SoftwareKeybagEraResourceLimit"); }
      catch (...) { return fail("SoftwareKeybagEraReadFailure"); }
}
