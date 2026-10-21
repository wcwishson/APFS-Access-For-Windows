#pragma once
#include "InodeMetadataPatch.h"

c::EncryptedNodeInfo RuntimeMetadata(Runtime& runtime, std::uint64_t inode)
{
    c::EncryptedReadError error{}; auto view = runtime.OpenReadView(error);
    Check(static_cast<bool>(view), "NamespaceReadView");
    c::EncryptedNodeInfo metadata;
    Check(view->GetMetadata(inode, metadata) == c::EncryptedReadError::None, "NamespaceMetadata");
    view->Close(); return metadata;
}

void RuntimeName(Runtime& runtime, std::uint64_t parent, std::string_view name, std::uint64_t inode)
{
    c::EncryptedReadError error{}; auto view = runtime.OpenReadView(error);
    Check(static_cast<bool>(view), "NamespaceLookupView");
    c::EncryptedDirectoryEntry entry;
    Check(view->Lookup(parent, name, entry) == c::EncryptedReadError::None && entry.inode_id == inode,
        "NamespaceExactParentAndName");
    view->Close();
}

void NamespaceWorkflow(Runtime& runtime, std::string& error)
{
    const auto original = Inventory(runtime);
    const auto xid = runtime.CachedStatus().image.checkpoint_xid;
    std::uint64_t publications = 0;
    const auto apply = [&](const c::EncryptedMutationRequest& request) {
        std::uint64_t inode = 0;
        const auto applied = runtime.Apply(request, inode, error);
        Check(applied, "NamespaceApply:" + error);
        const auto status = runtime.CachedStatus();
        Check(status.accepted && status.accepted == status.cleaned && status.durable == status.cleaned &&
            !status.recovery_required && status.image.phase == c::EncryptedImageWritePhase::Ready,
            "NamespaceCleanBoundary");
        ++publications; return inode;
    };
    const auto mkdir = [&](std::uint64_t parent, const char* name) {
        c::EncryptedMutationRequest request;
        request.kind = c::EncryptedMutationKind::MakeDirectory;
        request.parent = parent; request.name = name; request.permissions = 0700;
        const auto inode = apply(request);
        RuntimeName(runtime, parent, name, inode);
        const auto metadata = RuntimeMetadata(runtime, inode);
        Check(metadata.mode == 0040700 && metadata.parent_id == parent && metadata.IsDirectory(), "CanonicalDirectory");
        return inode;
    };
    const auto first = mkdir(2, "runtime-private-a"), second = mkdir(2, "runtime-private-b");
    const auto child = mkdir(first, "nested");
    Bytes payload; payload.resize(4097);
    for (std::size_t i = 0; i < payload.size(); ++i) payload[i] = std::byte((i * 31 + 43) % 251);
    c::EncryptedMutationRequest request;
    request.kind = c::EncryptedMutationKind::Create; request.parent = child;
    request.name = "payload.bin"; request.permissions = 0600; request.data = std::span<const std::byte>(payload).first(4096);
    const auto file = apply(request);
    RuntimeName(runtime, child, "payload.bin", file);
    request = {}; request.kind = c::EncryptedMutationKind::Write; request.inode = file;
    request.offset = 4096; request.data = std::span<const std::byte>(payload).subspan(4096);
    Check(apply(request) == file, "NestedFileAppend");
    r::InodeMetadataPatch patch;
    patch.mask = r::InodeMetadataPatch::Owner | r::InodeMetadataPatch::Group | r::InodeMetadataPatch::Mode |
        r::InodeMetadataPatch::CreateTime | r::InodeMetadataPatch::ModificationTime |
        r::InodeMetadataPatch::ChangeTime | r::InodeMetadataPatch::AccessTime | r::InodeMetadataPatch::BsdFlags;
    patch.owner = 501; patch.group = 20; patch.mode = 0640;
    patch.create_time_utc = patch.modification_time_utc = patch.change_time_utc = patch.access_time_utc =
        r::InodeMetadataPatch::UnixEpochTicks + 123456789;
    Bytes encoded;
    Check(r::EncodeInodeMetadataPatch(patch, encoded), "EncodeCanonicalMacMetadata");
    request = {}; request.kind = c::EncryptedMutationKind::SetInodeMetadata; request.inode = file; request.data = encoded;
    Check(apply(request) == file, "MetadataResultInode");
    const auto metadata = RuntimeMetadata(runtime, file);
    Check(metadata.uid == 501 && metadata.gid == 20 && metadata.mode == 0100640 && !metadata.bsd_flags &&
        metadata.create_time == 12345678900ull && metadata.modification_time == 12345678900ull &&
        metadata.change_time == 12345678900ull && metadata.access_time == 12345678900ull,
        "PreservedMacOwnershipModeAndNanoseconds");
    const auto rename = [&](std::uint64_t inode, std::uint64_t parent, const char* name,
        std::uint64_t destination, const char* new_name) {
        c::EncryptedMutationRequest move;
        move.kind = c::EncryptedMutationKind::Rename; move.inode = inode;
        move.parent = parent; move.name = name; move.destination_parent = destination; move.destination_name = new_name;
        Check(apply(move) == inode, "RenameKeepsIdentity");
        RuntimeName(runtime, destination, new_name, inode);
        Check(RuntimeMetadata(runtime, inode).parent_id == destination, "MoveUpdatesPrimaryParent");
    };
    rename(file, child, "payload.bin", second, "moved.bin");
    rename(child, first, "nested", second, "moved-dir");
    const auto refuse = [&](const c::EncryptedMutationRequest& invalid) {
        const auto before = runtime.CachedStatus(); std::uint64_t result = 999;
        Check(!runtime.Apply(invalid, result, error) && !result, "InvalidNamespaceRefused");
        const auto after = runtime.CachedStatus();
        Check(after.accepted == before.accepted && after.cleaned == before.cleaned &&
            after.image.checkpoint_xid == before.image.checkpoint_xid && !after.recovery_required,
            "NamespaceRefusalBeforeOriginalAcceptance");
    };
    request = {}; request.kind = c::EncryptedMutationKind::Rename;
    request.inode = second; request.parent = 2; request.name = "runtime-private-b";
    request.destination_parent = child; request.destination_name = "cycle";
    refuse(request);
    request = {}; request.kind = c::EncryptedMutationKind::Unlink; request.inode = second;
    request.parent = 2; request.name = "runtime-private-b";
    refuse(request);
    const auto changed = Inventory(runtime);
    Check(changed.size() == original.size() + 1 && changed.at(file).hash == Digest(payload) &&
        changed.at(file).mode == 0100640, "MovedPayloadIntegrity");
    for (const auto& [inode, fact] : original)
        Check(changed.contains(inode) && changed.at(inode).hash == fact.hash && changed.at(inode).size == fact.size &&
            changed.at(inode).mode == fact.mode, "NamespaceOriginalFilePreservation");
    const auto unlink = [&](std::uint64_t inode, std::uint64_t parent, const char* name) {
        c::EncryptedMutationRequest remove;
        remove.kind = c::EncryptedMutationKind::Unlink; remove.inode = inode; remove.parent = parent; remove.name = name;
        Check(apply(remove) == inode, "UnlinkResultIdentity");
    };
    unlink(file, second, "moved.bin"); unlink(child, second, "moved-dir");
    unlink(first, 2, "runtime-private-a"); unlink(second, 2, "runtime-private-b");
    const auto final = Inventory(runtime);
    Check(final.size() == original.size(), "NamespaceReturnsToOriginalFileCount");
    for (const auto& [inode, fact] : original)
        Check(final.contains(inode) && final.at(inode).hash == fact.hash && final.at(inode).mode == fact.mode &&
            final.at(inode).size == fact.size, "FinalNamespaceOriginalIntegrity");
    Check(runtime.CachedStatus().image.checkpoint_xid == xid + publications, "EveryNamespaceCommitPublished");
}
