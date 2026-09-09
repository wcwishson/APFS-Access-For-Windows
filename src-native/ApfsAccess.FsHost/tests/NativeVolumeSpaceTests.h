#pragma once

bool TestManifestVolumeInfoUsesNonblockingSharedCapacity()
{
    ContainerFixtureFile fixture("shared-capacity", true, false, true);
    std::string error;
    auto coordinator = OpenContainerFixtureCoordinator(fixture, error);
    if (!Require(coordinator != nullptr, "shared capacity opens a strict two-volume image")) return false;
    auto alpha = std::make_unique<MountContext>();
    auto beta = std::make_unique<MountContext>();
    std::wstring mount_error;
    for (auto* context : {alpha.get(), beta.get()})
    {
        const auto oid = context == alpha.get() ? 101 : 102;
        context->args = ManifestSessionArgs(fixture.path, oid, Utf8ToWide(coordinator->ContainerUuidHex()),
            oid == 101 ? L"A:\\Alpha" : L"A:\\Beta", true);
        context->args.write_require_canonical_commit = true;
        context->args.allow_legacy_scaffold_for_fixtures = false;
        if (!Require(MountManifestSession(*coordinator, context->args, *context, mount_error),
                "shared capacity binds a manifest volume")) return false;
        // Deliberately stale values must never override the shared observation.
        context->reported_total_size_bytes = 999999999;
        context->reported_free_size_bytes = 888888888;
    }
    FSP_FILE_SYSTEM fs{};
    fs.UserContext = alpha.get();
    FSP_FSCTL_VOLUME_INFO before{};
    const auto first = coordinator->LookupSharedSpace(coordinator->ContainerUuidHex(), 101);
    if (!Require(first && CB_GetVolumeInfo(&fs, &before) == STATUS_SUCCESS &&
            before.TotalSize == first->total_bytes && before.FreeSize == first->available_bytes,
            "host reports the selected volume's shared capacity")) return false;
    std::promise<void> entered, release;
    auto entered_signal = entered.get_future();
    auto release_signal = release.get_future().share();
    apfsaccess::rw::MetadataStore::MutationRequest create;
    create.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create.path = L"\\sibling-space.bin";
    beta->metadata_store->SetCommitStageHook([&](std::string_view stage) {
        if (stage == "before-apple-publish")
        {
            entered.set_value();
            release_signal.wait();
        }
        return true;
    });
    auto writer = std::async(std::launch::async, [&] {
        return coordinator->Commit(102, {create});
    });
    const auto hook_reached = entered_signal.wait_for(std::chrono::seconds(5)) == std::future_status::ready;
    bool responsive = false;
    if (hook_reached)
    {
        std::unique_lock<std::mutex> metadata_lock(alpha->metadata_mutex);
        auto reader = std::async(std::launch::async, [&] {
            FSP_FSCTL_VOLUME_INFO during{};
            return CB_GetVolumeInfo(&fs, &during) == STATUS_SUCCESS && during.FreeSize != 888888888;
        });
        responsive = reader.wait_for(std::chrono::milliseconds(250)) == std::future_status::ready;
        metadata_lock.unlock();
        release.set_value();
        responsive = reader.get() && responsive;
    }
    else release.set_value();
    const auto committed = writer.get();
    beta->metadata_store->SetCommitStageHook({});
    if (!committed.committed) std::cerr << "[DETAIL] " << committed.error << std::endl;
    bool ok = Require(hook_reached && responsive,
        "volume-info callback completes while sibling commit and local metadata locks are held");
    ok &= Require(committed.committed && !committed.commit_recovery_required,
        "sibling capacity transaction commits");
    FSP_FSCTL_VOLUME_INFO after{};
    const auto current = coordinator->LookupSharedSpace(coordinator->ContainerUuidHex(), 101);
    ok &= Require(current && current->checkpoint_xid > first->checkpoint_xid &&
        CB_GetVolumeInfo(&fs, &after) == STATUS_SUCCESS && after.TotalSize == before.TotalSize &&
        after.FreeSize == current->available_bytes && after.FreeSize < before.FreeSize,
        "quiet sibling reports new shared capacity without reloading its metadata store");
    ok &= Require(coordinator->DrainAndStop(std::chrono::seconds(5)).clean, "shared capacity coordinator drains");
    FSP_FSCTL_VOLUME_INFO stopped{};
    ok &= Require(CB_GetVolumeInfo(&fs, &stopped) == STATUS_SUCCESS &&
        stopped.FreeSize == 0 && stopped.TotalSize == 0,
        "invalidated shared capacity cannot reuse stale per-volume values");
    return ok;
}
