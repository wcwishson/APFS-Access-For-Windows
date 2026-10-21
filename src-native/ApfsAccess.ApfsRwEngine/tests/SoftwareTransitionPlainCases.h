#include "SoftwareTransitionVolumeTransaction.h"
#include "NativeApfsReader.h"

namespace
{
int TransitionProtectedPlainPlan(const std::filesystem::path& run)
{
    const auto image = run / Profile{false}.Name(); const auto before = DigestFile(image);
    const auto scope = TransitionScope(run); auto tx = TransitionTx(run, scope); Journal journal(scope.journal); std::string error;
    auto source = std::make_shared<TransitionSource>(image);
    auto restored = journal.RestoreTransitionRetainedOwners(*tx, *source, error);
    Check(static_cast<bool>(restored), ("TransitionPlainPlanProtectedOwners:" + error).c_str());
    std::shared_ptr<const c::SoftwareVolumeRetainedOwners> owners(std::move(restored));
    std::vector<c::SoftwareVolumeOwnedRange> exclusions;
    Check(owners->RevalidateProtectedHistory(*source, *tx->ProtectedJournalIdentity(), exclusions, error),
        ("TransitionPlainPlanCurrentRawAndAllocator:" + error).c_str());
    auto current = c::LoadAppleCheckpointView(*source, 0, source->SizeBytes(), error);
    std::vector<c::BtreeRecord> records;
    Check(current && current->volumes.size() == 1 && c::ReadAppleVolumeFileSystemRecords(*source, current->container,
        current->volumes.front(), records, error), "TransitionPlainPlanCanonicalRecords");
    {
        auto diagnostic = std::make_shared<TransitionSource>(image);
        std::string detail;
        const auto valid = r::NativeApfsReader::ValidateOrdinaryFileSystemRecords(records, current->container.superblock,
            current->volumes.front().superblock, diagnostic->ReadBudget(), detail);
        std::cout << "PLAIN_NAMESPACE valid=" << (valid ? "true" : "false") << " reason=" << detail << '\n';
        r::NativeApfsVolumeProjection projected;
        auto observational = std::make_shared<TransitionSource>(image);
        const auto readable = r::NativeApfsReader::TryProjectObservationalFileSystemRecords(records, current->container.superblock,
            current->volumes.front().superblock, observational->ReadBudget(), projected, detail);
        std::cout << "PLAIN_OBSERVATIONAL_NAMESPACE valid=" << (readable ? "true" : "false") << " reason=" << detail << '\n';
        for (const auto& row : records) if ((c::ReadU64LE(row.key, 0).value_or(0) >> 60) == 3) {
            r::AppleInodeRecord inode;
            const auto decoded = r::ApfsExtendedRecordCodec::DecodeInode(row, inode, detail);
            std::cout << "PLAIN_INODE_CODEC id=" << (c::ReadU64LE(row.key, 0).value_or(0) & ((std::uint64_t{1} << 60) - 1))
                << " valid=" << (decoded ? "true" : "false") << " parent=" << inode.parent_id << " private=" << inode.private_id
                << " mode=" << inode.mode << " linksOrChildren=" << inode.children_or_links
                << " internal=" << inode.internal_flags << " uncompressed=" << inode.uncompressed_size << " reason=" << detail << '\n';
            if (decoded) for (const auto& field : inode.extended_fields) if (field.flags)
                std::cout << "PLAIN_INODE_FIELD id=" << inode.object_id << " type=" << unsigned(field.type)
                    << " flags=" << unsigned(field.flags) << " bytes=" << field.data.size() << '\n';
        }
        for (const auto& row : records) if ((c::ReadU64LE(row.key, 0).value_or(0) >> 60) == 4) {
            r::AppleXattrRecord attribute;
            const auto decoded = r::ApfsExtendedRecordCodec::DecodeXattr(row, attribute, detail);
            std::cout << "PLAIN_XATTR valid=" << (decoded ? "true" : "false") << " owner=" << attribute.object_id
                << " flags=" << attribute.flags << " bytes=" << attribute.data.size()
                << " symlink=" << (attribute.name_utf8 == "com.apple.fs.symlink" ? "true" : "false")
                << " zeroes=" << std::count(attribute.data.begin(), attribute.data.end(), std::byte{0}) << " reason=" << detail << '\n';
        }
        const auto policy = r::ApfsNamePolicy::FromIncompatibleFeatures(current->volumes.front().superblock.incompatible_features);
        for (const auto& row : records) if ((c::ReadU64LE(row.key, 0).value_or(0) >> 60) == 9) {
            r::AppleDirectoryRecord entry;
            const auto decoded = r::ApfsExtendedRecordCodec::DecodeDirectory(row, policy, entry, detail);
            std::cout << "PLAIN_DREC valid=" << (decoded ? "true" : "false") << " parent=" << entry.parent_id
                << " child=" << entry.file_id << " flags=" << entry.flags << " reason=" << detail << '\n';
        }
    }
    for (const auto& generation : owners->Generations()) {
        auto diagnostic = std::make_shared<TransitionSource>(image); c::AppleSpacemanInternalPoolView pool; std::string detail;
        auto actual_checkpoint = c::LoadContainerCheckpointView(*diagnostic, 0, diagnostic->SizeBytes(), detail,
            generation.checkpoint.superblock.xid);
        const auto loaded = actual_checkpoint && c::LoadAppleSpacemanRetentionBitmaps(*diagnostic, *actual_checkpoint, pool, detail);
        const auto& actual = current->spaceman.internal_pool;
        std::cout << "PLAIN_RETAINED_BITMAP xid=" << generation.checkpoint.superblock.xid << " loaded=" << (loaded ? "true" : "false")
            << " old=" << pool.base_block << ':' << pool.block_count << ':' << pool.bitmap_base_block << ':' << pool.bitmap_block_count
            << " current=" << actual.base_block << ':' << actual.block_count << ':' << actual.bitmap_base_block << ':' << actual.bitmap_block_count
            << " reason=" << detail << '\n';
    }
    r::AppleVolumeTransactionRequest request; request.volume_object_id = 1026;
    request.required_checkpoint_xids = {current->container.superblock.xid}; std::uint64_t stream = 0;
    for (const auto& row : records) if (c::ReadU64LE(row.key, 0) == ((std::uint64_t{3} << 60) | 21)) {
        r::AppleInodeRecord inode;
        Check(r::ApfsExtendedRecordCodec::DecodeInodeReadOnly(row, inode, error), "TransitionPlainPlanActualStream"); stream = inode.private_id;
    }
    Check(stream != 0, "TransitionPlainPlanStreamPresent");
    for (const auto& row : records) {
        if ((c::ReadU64LE(row.key, 0).value_or(0) >> 60) == 8) {
            r::AppleFileExtentRecord extent;
            Check(r::DecodeAppleFileExtentRecord(row, 4096, extent, error), "TransitionPlainPlanActualExtent");
            if (extent.object_id == stream) {
                request.released_data_blocks.push_back({extent.physical_block, extent.length_bytes / 4096}); continue;
            }
        }
        request.filesystem_records.push_back(row);
    }
    r::AppleVolumeDataWrite write; write.file_private_id = stream; write.bytes.assign(22, std::byte{0x5A});
    request.data_writes.push_back(std::move(write));
    r::AppleVolumeTransactionPlan plan; auto wrong = *tx->ProtectedJournalIdentity(); wrong.front() ^= std::byte{1};
    Check(!r::PlanSoftwareTransitionPlainTransaction(*source, *current, request, owners, wrong, plan, error) &&
        plan.commit.publication.before_superblock_writes.empty(), "TransitionPlainPlanWrongJournalNoPlan");
    request.required_checkpoint_xids.push_back(owners->MintedCheckpointXid());
    Check(!r::PlanSoftwareTransitionPlainTransaction(*source, *current, request, owners, *tx->ProtectedJournalIdentity(), plan, error) &&
        error == "AppleSoftwareTransitionOpaqueReadPinUnsupported" && plan.commit.publication.before_superblock_writes.empty(),
        "TransitionPlainPlanOpaqueHistoryCannotBecomeReadContext");
    request.required_checkpoint_xids.pop_back();
    const bool planned = r::PlanSoftwareTransitionPlainTransaction(*source, *current, request, owners, *tx->ProtectedJournalIdentity(), plan, error);
    Check(planned,
        ("TransitionProtectedPlainCanonicalPlanner:" + error).c_str());
    std::size_t unstable_guards = 0;
    for (const auto& guard : plan.commit.publication.guard_blocks)
        for (const auto& staged : plan.commit.publication.before_superblock_writes)
            if (guard.physical_block == staged.physical_block && guard.bytes != staged.bytes) {
                ++unstable_guards;
                std::cout << "PLAIN_GUARD_DESTINATION block=" << guard.physical_block << '\n';
            }
    Check(unstable_guards == 0, "TransitionPlainPlanStableGuardsCannotBePreSwitchDestinations");
    const auto intersects = [&](std::uint64_t block, std::uint64_t count) {
        return std::any_of(exclusions.begin(), exclusions.end(), [&](const auto& owner) {
            return block < owner.start_block + owner.block_count && owner.start_block < block + count;
        });
    };
    Check(!plan.commit.publication.before_superblock_writes.empty() &&
        std::none_of(plan.commit.publication.before_superblock_writes.begin(), plan.commit.publication.before_superblock_writes.end(),
            [&](const auto& item) { return intersects(item.physical_block, 1); }) &&
        !intersects(plan.commit.publication.superblock_write.physical_block, 1) &&
        std::none_of(plan.allocation.deferred_frees.begin(), plan.allocation.deferred_frees.end(),
            [&](const auto& item) { return intersects(item.physical_block, item.block_count); }), "TransitionPlainPlanAllOpaqueOwnersExcluded");
    Check(DigestFile(image) == before, "TransitionPlainPlannerNoImageWrites");
    std::cout << "{\"protectedPlainPlanner\":true,\"oldOwnerDestinationsAndFreesExcluded\":true,\"opaqueReadPinRefused\":true,\"targetWrites\":0}\n";
    return 0;
}
}
