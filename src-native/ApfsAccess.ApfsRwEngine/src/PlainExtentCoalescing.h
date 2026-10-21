#pragma once

#include "AppleVolumeTransaction.h"
#include "ApfsExtendedRecordCodec.h"
#include "FusionExtentCoalescing.h"
#include <map>
#include <set>

namespace apfsaccess::rw::plain_compact {
using Records = std::vector<catalog::BtreeRecord>;
using Owners = std::set<std::uint64_t>;
inline std::uint64_t Header(const catalog::BtreeRecord& record) {
    return catalog::ReadU64LE(record.key, 0).value_or(0);
}

// Eligibility only. The caller must first validate the complete old/new graph,
// releases and stream accounting. A veto leaves the original record path intact.
inline Owners Eligible(const Records& before, const Records& after, const Records& references,
    const std::vector<AppleVolumeDataWrite>& writes, std::uint32_t block_size) {
    Owners owners;
    for (const auto& write : writes) owners.insert(write.file_private_id);
    for (const auto& write : writes) if (write.crypto_id) owners.erase(write.file_private_id);
    const auto inspect = [&](const Records& records, bool required) {
        std::map<std::uint64_t, unsigned> inodes, streams;
        Owners mapped, empty;
        for (const auto& record : records)
            if ((Header(record) >> 60) == 8) mapped.insert(Header(record) & fusion_compact::detail::Mask);
        for (const auto& record : records) {
            const auto header = Header(record), id = header & fusion_compact::detail::Mask;
            std::string error;
            if ((header >> 60) == 3) {
                AppleInodeRecord inode;
                if (!ApfsExtendedRecordCodec::DecodeInode(record, inode, error)) { owners.clear(); return; }
                if (!owners.contains(inode.private_id)) continue;
                ++inodes[inode.private_id];
                const auto stream = std::find_if(inode.extended_fields.begin(), inode.extended_fields.end(),
                    [](const auto& field) { return field.type == 8; });
                // A separately published empty file need not have a dstream yet.
                // Only its proven empty preimage gets this exception; the new
                // mapping still requires a complete private stream and refcount.
                const bool empty_before = !required && inode.uncompressed_size == 0 && !mapped.contains(inode.private_id) &&
                    (stream == inode.extended_fields.end() || (stream->data.size() == 40 &&
                        catalog::ReadU64LE(stream->data, 0).value_or(1) == 0 &&
                        catalog::ReadU64LE(stream->data, 8).value_or(1) == 0 &&
                        catalog::ReadU64LE(stream->data, 16).value_or(1) == 0));
                if (empty_before) empty.insert(inode.private_id);
                if (inode.object_id != inode.private_id || (inode.mode & 0170000) != 0100000 ||
                    (inode.bsd_flags & kAppleBsdCompressedFlag) ||
                    (inode.internal_flags & (0x3081 | kAppleInodeSparseFlag)) ||
                    (!empty_before && (stream == inode.extended_fields.end() || stream->data.size() != 40 ||
                        catalog::ReadU64LE(stream->data, 16).value_or(1) != 0)))
                    owners.erase(inode.private_id);
            } else if ((header >> 60) == 6 && owners.contains(id)) {
                AppleDataStreamIdRecord stream;
                if (!DecodeAppleDataStreamIdRecord(record, stream, error) || stream.reference_count != 1)
                    owners.erase(id);
                else ++streams[id];
            } else if ((header >> 60) == 4) {
                AppleXattrRecord attribute;
                if (!ApfsExtendedRecordCodec::DecodeXattr(record, attribute, error)) { owners.clear(); return; }
                if (attribute.name_utf8 == "com.apple.decmpfs" || (attribute.flags & kAppleXattrDataStream))
                    owners.erase(attribute.object_id);
                if (attribute.flags & kAppleXattrDataStream)
                    owners.erase(catalog::ReadU64LE(attribute.data, 0).value_or(0));
            } else if ((header >> 60) == 8 && owners.contains(id)) {
                AppleFileExtentRecord extent;
                if (!DecodeAppleFileExtentRecord(record, block_size, extent, error) || !extent.physical_block || extent.crypto_id)
                    owners.erase(id);
            }
        }
        std::erase_if(owners, [&](auto id) {
            return ((required || inodes[id] != 0) && (inodes[id] != 1 || (streams[id] != 1 && !empty.contains(id)))) || streams[id] > 1;
        });
    };
    inspect(before, false);
    inspect(after, true);
    std::map<std::uint64_t, ApplePhysicalExtentRecord> physical;
    for (const auto& record : references) {
        ApplePhysicalExtentRecord extent; std::string error;
        if (!DecodeApplePhysicalExtentRecord(record, extent, error) ||
            !physical.emplace(extent.physical_block, extent).second) return {};
    }
    for (const auto& record : before) {
        const auto header = Header(record), id = header & fusion_compact::detail::Mask;
        if ((header >> 60) != 8 || !owners.contains(id)) continue;
        AppleFileExtentRecord extent; std::string error;
        if (!DecodeAppleFileExtentRecord(record, block_size, extent, error)) { owners.erase(id); continue; }
        auto at = extent.physical_block;
        const auto end = at + extent.length_bytes / block_size;
        auto ref = physical.upper_bound(at);
        if (ref != physical.begin()) --ref;
        while (at < end) {
            if (ref == physical.end() || ref->first > at || ref->second.block_count <= at - ref->first ||
                ref->second.kind != kApplePhysicalExtentKindNew || ref->second.reference_count != 1 ||
                ref->second.owning_object_id != id) { owners.erase(id); break; }
            at = (std::min)(end, ref->first + ref->second.block_count);
            ++ref;
        }
    }
    return owners;
}

inline bool Coalesce(Records& files, Records& references, const Owners& owners,
    std::uint32_t block_size, std::string& error, const std::shared_ptr<catalog::ApfsReadBudget>& budget = {}) {
    if (owners.empty()) return true;
    const auto file_selected = [&](const auto& r) {
        return (Header(r) >> 60) == 8 && owners.contains(Header(r) & fusion_compact::detail::Mask);
    };
    const auto ref_selected = [&](const auto& r) {
        ApplePhysicalExtentRecord e; std::string detail;
        return DecodeApplePhysicalExtentRecord(r, e, detail) && owners.contains(e.owning_object_id) &&
            e.kind == kApplePhysicalExtentKindNew && e.reference_count == 1;
    };
    Records selected_files, selected_refs;
    for (const auto& r : files) if (file_selected(r)) selected_files.push_back(r);
    for (const auto& r : references) if (ref_selected(r)) selected_refs.push_back(r);
    if (!fusion_compact::FileRecords(selected_files, block_size, error, budget) ||
        !fusion_compact::PhysicalRecords(selected_refs, error, budget)) return false;
    std::erase_if(files, file_selected);
    std::erase_if(references, ref_selected);
    files.insert(files.end(), std::make_move_iterator(selected_files.begin()), std::make_move_iterator(selected_files.end()));
    references.insert(references.end(), std::make_move_iterator(selected_refs.begin()), std::make_move_iterator(selected_refs.end()));
    return true;
}

inline bool AppendPayloadRecords(const std::vector<AppleVolumeDataWrite>& writes,
    std::span<const std::uint64_t> blocks, const Owners& owners, std::uint32_t block_size,
    Records& files, Records& references, std::string& error,
    const std::span<const std::uint64_t>* capacity_bytes = nullptr) {
    std::size_t cursor = 0;
    for (const auto& write : writes) {
        const auto size = capacity_bytes ? (*capacity_bytes)[&write - writes.data()] : write.bytes.size();
        const auto count = (size + block_size - 1) / block_size;
        if (cursor > blocks.size() || count > blocks.size() - cursor)
            return fusion_compact::detail::Fail(error, "ApplePlainPayloadAllocationInvalid");
        for (std::size_t ordinal = 0; ordinal < count;) {
            std::size_t run = 1;
            const auto physical = blocks[cursor + ordinal];
            if (owners.contains(write.file_private_id) && !write.crypto_id) {
                while (run < count - ordinal && run < fusion_compact::detail::LengthMask / block_size &&
                    blocks[cursor + ordinal + run] == physical + run &&
                    fusion_compact::detail::SameMember(physical, physical + run + 1, catalog::kFusionTier2ByteAddress / block_size)) ++run;
            }
            catalog::BtreeRecord record;
            if (!EncodeAppleFileExtentRecord({write.file_private_id, write.logical_address + ordinal * block_size,
                    run * block_size, physical, write.crypto_id, block_size}, record, error)) return false;
            files.push_back(std::move(record));
            if (!EncodeApplePhysicalExtentRecord({physical, run, kApplePhysicalExtentKindNew, write.file_private_id, 1}, record, error)) return false;
            references.push_back(std::move(record));
            ordinal += run;
        }
        cursor += count;
    }
    return cursor == blocks.size() || fusion_compact::detail::Fail(error, "ApplePlainPayloadAllocationInvalid");
}
}
