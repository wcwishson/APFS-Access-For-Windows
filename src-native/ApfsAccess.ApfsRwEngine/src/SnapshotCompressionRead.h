#pragma once
#include "ApfsCompression.h"

namespace apfsaccess::rw::snapshot_compression
{
// Called only after canonical historical attribute/extent ownership and payload
// exclusion have been proved. Addresses in attribute_stream_extents are already
// relative to the retained whole-image source, including a nonzero store window.
inline bool Admit(const catalog::RandomAccessSource& source,
    NativeApfsVolumeProjection& view, const std::shared_ptr<catalog::ApfsReadBudget>& budget,
    std::unordered_set<std::uint64_t>& admitted, std::string& error)
{
    admitted.clear();
    const auto fail = [&](const char* reason) { error = reason; return false; };
    const ApfsCompressionLimits limits;
    for (auto& inode : view.inodes)
    {
        const auto owner = view.extended_attributes_by_inode.find(inode.object_id);
        const AppleXattrRecord* descriptor = nullptr;
        if (owner != view.extended_attributes_by_inode.end())
        {
            const auto found = owner->second.find("com.apple.decmpfs");
            if (found != owner->second.end()) descriptor = &found->second;
        }
        const bool flagged = (inode.bsd_flags & kAppleBsdCompressedFlag) != 0;
        if (!flagged && !descriptor) continue;
        if (inode.node_type != MetadataStore::NodeType::RegularFile || !flagged || !descriptor)
            return fail("SnapshotCompressedMetadataInconsistent");
        const auto raw = view.read_extents_by_inode.find(inode.object_id);
        if (inode.allocation_size.value_or(0) != 0 || inode.data_physical_address != 0 ||
            (raw != view.read_extents_by_inode.end() && !raw->second.empty()) ||
            (inode.internal_flags & kAppleInodeSparseFlag) != 0)
            return fail("SnapshotCompressedDefaultStreamUnsupported");
        std::vector<std::byte> external;
        std::span<const std::byte> bytes = descriptor->data;
        const auto storage = descriptor->flags & ~kAppleXattrFileSystemOwned;
        if (storage == kAppleXattrDataStream)
        {
            if (bytes.size() != kAppleXattrDataStreamBytes)
                return fail("SnapshotCompressedDescriptorInvalid");
            const auto id = catalog::ReadU64LE(bytes, 0).value_or(0);
            const auto size = catalog::ReadU64LE(bytes, 8).value_or(0);
            const auto found = view.attribute_stream_extents.find(id);
            if (size < 16 || size > limits.max_decmpfs_bytes ||
                found == view.attribute_stream_extents.end() || !found->second ||
                !budget || !budget->Materialize(1, size))
                return fail("SnapshotCompressedDescriptorInvalid");
            external.reserve(static_cast<std::size_t>(size));
            for (const auto& extent : *found->second)
            {
                if (external.size() == size) break;
                if (extent.logical_offset != external.size() || !extent.physical_address)
                    return fail("SnapshotCompressedDescriptorInvalid");
                const auto count = static_cast<std::size_t>((std::min)(extent.bytes, size - external.size()));
                std::vector<std::byte> part;
                if (!budget->Materialize(1, count) ||
                    !source.Read(extent.physical_address, count, part) || part.size() != count)
                    return fail("SnapshotCompressedDescriptorReadFailed");
                external.insert(external.end(), part.begin(), part.end());
            }
            if (external.size() != size) return fail("SnapshotCompressedDescriptorInvalid");
            bytes = external;
        }
        else if (storage != kAppleXattrDataEmbedded)
            return fail("SnapshotCompressedDescriptorInvalid");
        ApfsCompressionHeader header;
        if (!ApfsCompression::Inspect(bytes, limits, header))
            return fail("SnapshotCompressedDescriptorInvalid");
        if (inode.logical_size != header.uncompressed_size &&
            (inode.logical_size != 0 || (inode.internal_flags & kAppleInodeHasUncompressedSize) != 0))
            return fail("SnapshotCompressedLogicalSizeMismatch");
        if (header.type == 4 || header.type == 8 || header.type == 10 || header.type == 12 || header.type == 14)
        {
            const auto resource = owner->second.find("com.apple.ResourceFork");
            if (resource == owner->second.end()) return fail("SnapshotCompressedResourceMissing");
            const auto& fork = resource->second;
            const auto size = (fork.flags & kAppleXattrDataStream) != 0
                ? catalog::ReadU64LE(fork.data, 8).value_or(UINT64_MAX) : fork.data.size();
            if (size == 0 || size > limits.max_resource_bytes)
                return fail("SnapshotCompressedResourceInvalid");
        }
        if (!budget || !budget->Materialize(1, 64 + sizeof(std::uint64_t)))
            return fail("SnapshotCompressedProjectionBudget");
        inode.logical_size = header.uncompressed_size;
        admitted.insert(inode.object_id);
    }
    return true;
}
}
