bool MaterializeSmallPlainAttributes(const RandomAccessSource& source, Rows& filesystem,
    std::vector<rw::AppleXattrRecord>& converted, std::string& error)
{
    const auto fail = [&](const char* reason) { error = reason; return false; };
    std::set<std::uint64_t> retired_streams;
    for (auto& row : filesystem.values) {
        if ((ReadU64LE(row.key, 0).value_or(0) >> 60) != 4) continue;
        rw::AppleXattrRecord attribute;
        if (!rw::ApfsExtendedRecordCodec::DecodeXattr(row, attribute, error)) return false;
        if (!(attribute.flags & rw::kAppleXattrDataStream)) continue;
        const auto stream = ReadU64LE(attribute.data, 0).value_or(0);
        const auto size = ReadU64LE(attribute.data, 8).value_or(0);
        if ((attribute.flags & ~rw::kAppleXattrFileSystemOwned) != rw::kAppleXattrDataStream ||
            attribute.data.size() != rw::kAppleXattrDataStreamBytes || !stream || !size || size > 1024 ||
            ReadU64LE(attribute.data, 16) != block_size || ReadU64LE(attribute.data, 24) != 0 ||
            !retired_streams.insert(stream).second || converted.size() >= 8 ||
            (!rw::IsOrdinaryAppleXattrName(attribute.name_utf8) && attribute.name_utf8 != "com.apple.ResourceFork"))
            return fail("SoftwareTransitionSmallPlainAttributeProfileUnsupported");
        unsigned owners = 0, references = 0, extents = 0; std::uint64_t physical = 0; bool decmpfs = false;
        rw::AppleInodeRecord owner;
        for (const auto& sibling : filesystem.values) {
            const auto type = ReadU64LE(sibling.key, 0).value_or(0) >> 60;
            if (type == 3) {
                rw::AppleInodeRecord inode;
                if (!rw::ApfsExtendedRecordCodec::DecodeInodeReadOnly(sibling, inode, error)) return false;
                if (inode.private_id == stream) return fail("SoftwareTransitionSmallAttributeSharedWithFile");
                if (inode.object_id == attribute.object_id) { owner = std::move(inode); ++owners; }
            } else if (type == 4) {
                rw::AppleXattrRecord other;
                if (!rw::ApfsExtendedRecordCodec::DecodeXattr(sibling, other, error)) return false;
                decmpfs |= other.object_id == attribute.object_id && other.name_utf8 == "com.apple.decmpfs";
                if (&sibling != &row && (other.flags & rw::kAppleXattrDataStream) &&
                    ReadU64LE(other.data, 0) == stream) return fail("SoftwareTransitionSmallAttributeSharedStream");
            } else if (type == 6 && (ReadU64LE(sibling.key, 0).value_or(0) & 0x0FFFFFFFFFFFFFFFULL) == stream) {
                rw::AppleDataStreamIdRecord reference;
                if (!rw::DecodeAppleDataStreamIdRecord(sibling, reference, error) || reference.reference_count != 1)
                    return fail("SoftwareTransitionSmallAttributeReferenceUnproved");
                ++references;
            } else if (type == 8 && (ReadU64LE(sibling.key, 0).value_or(0) & 0x0FFFFFFFFFFFFFFFULL) == stream) {
                rw::AppleFileExtentRecord extent;
                if (!rw::DecodeAppleFileExtentRecord(sibling, block_size, extent, error) ||
                    extent.logical_address || extent.length_bytes != block_size || extent.crypto_id || !extent.physical_block)
                    return fail("SoftwareTransitionSmallAttributeExtentUnproved");
                physical = extent.physical_block; ++extents;
            }
        }
        // Genuine exclusive streams may omit a dstream-id record. The complete
        // payload graph still proves one physical owner; any present record
        // must independently say one reference.
        if (owners != 1 || references > 1 || extents != 1 ||
            !rw::IsUncompressedAppleResourceForkOwner(owner.object_id, owner.private_id, owner.mode, owner.bsd_flags, decmpfs)) {
            error = "SoftwareTransitionSmallAttributeOwnerUnproved:owners=" + std::to_string(owners) +
                ":references=" + std::to_string(references) + ":extents=" + std::to_string(extents) +
                ":regular=" + std::to_string((owner.mode & 0170000) == 0100000) + ":compressed=" + std::to_string(decmpfs);
            return false;
        }
        BytesOwner raw;
        if (!Block(source, physical, raw.bytes)) return fail("SoftwareTransitionSmallAttributePayloadUnreadable");
        attribute.flags = static_cast<std::uint16_t>((attribute.flags & rw::kAppleXattrFileSystemOwned) | rw::kAppleXattrDataEmbedded);
        attribute.data.assign(raw.bytes.begin(), raw.bytes.begin() + static_cast<std::ptrdiff_t>(size));
        BtreeRecord embedded;
        if (!rw::EncodeAppleXattrRecord(attribute, embedded, error)) return false;
        row = std::move(embedded); converted.push_back(std::move(attribute));
    }
    std::erase_if(filesystem.values, [&](const auto& row) {
        const auto key = ReadU64LE(row.key, 0).value_or(0), type = key >> 60;
        return (type == 6 || type == 8) && retired_streams.contains(key & 0x0FFFFFFFFFFFFFFFULL);
    });
    return true;
}
