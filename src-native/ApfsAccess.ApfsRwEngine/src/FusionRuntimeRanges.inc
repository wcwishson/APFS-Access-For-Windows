// Retain the exact v1 derivation for already accepted journals across upgrade.
// Only the held original record's commitment version selects this branch.
bool PlanFusionLegacyFile(ApfsFusionReadSession& reader, const FusionNodeInfo& node,
    AppleInodeRecord& native, bool create, bool resize, std::uint64_t offset,
    std::uint64_t length, std::span<const std::byte> payload,
    const std::vector<catalog::BtreeRecord>& records, AppleVolumeTransactionRequest& request,
    std::string& error)
{
    if ((!create && (node.size > MaxPayload || offset > node.size || (!resize && length > node.size - offset))) || length > MaxPayload)
        return Fail(error, "FusionRuntimeLegacyRange");
    std::vector<std::byte> content;
    if (!create && (!reader.ReadFile(native.object_id, 0, static_cast<std::size_t>(node.size), content, error) || content.size() != node.size)) return false;
    if (resize) content.resize(static_cast<std::size_t>(length));
    else if (!create) std::copy(payload.begin(), payload.end(), content.begin() + static_cast<std::size_t>(offset));
    native.uncompressed_size = content.size(); bool stream = false;
    for (auto& field : native.extended_fields) if (field.type == 8) {
        if (stream || field.data.size() != 40) return Fail(error, "FusionRuntimeStreamShape");
        stream = true; const auto allocated = ((content.size() + 4095) / 4096) * 4096;
        for (unsigned i = 0; i < 8; ++i) { field.data[i] = std::byte((content.size() >> (i * 8)) & 255); field.data[8+i] = std::byte((allocated >> (i * 8)) & 255); }
    }
    if (!stream) return Fail(error, "FusionRuntimeExplicitStreamRequired");
    for (const auto& record : records) {
        const auto key = catalog::ReadU64LE(record.key, 0).value_or(0);
        if ((key >> 60) != 8 || (key & ((1ull << 60) - 1)) != native.private_id) continue;
        AppleFileExtentRecord extent;
        if (!DecodeAppleFileExtentRecord(record, 4096, extent, error) || extent.crypto_id || extent.length_bytes % 4096)
            return Fail(error, "FusionRuntimeExtentUnsupported");
        if (extent.physical_block) request.released_data_blocks.push_back({extent.physical_block, extent.length_bytes / 4096});
    }
    if (!content.empty()) request.data_writes.push_back({native.private_id, 0, 0, std::move(content)});
    return true;
}

// The existing canonical projector admits implicit holes only with a matching
// sparse declaration, allocation count and complete ordinary stream ownership.
bool PlanFusionFileRanges(ApfsFusionReadSession& reader, const FusionNodeInfo& node,
    AppleInodeRecord& native, bool create, bool resize, std::uint64_t offset,
    std::uint64_t length, std::span<const std::byte> payload,
    const std::vector<catalog::BtreeRecord>& records, AppleVolumeTransactionRequest& request,
    std::string& error)
{
    const auto old_size = create ? 0 : node.size;
    const auto size = create ? 0 : resize ? length : (std::max)(old_size, offset + length);
    const auto rounded = (size + 4095) & ~std::uint64_t{4095};
    std::uint64_t begin = 0, end = 0, keep = 0;
    if (!create && !resize) {
        begin = offset & ~std::uint64_t{4095}; end = (offset + length + 4095) & ~std::uint64_t{4095};
        keep = begin < old_size ? (std::min)(end - begin, old_size - begin) : 0;
    } else if (!create && size != old_size && (std::min)(size, old_size) % 4096) {
        const auto boundary = (std::min)(size, old_size);
        begin = boundary & ~std::uint64_t{4095}; end = begin + 4096; keep = boundary - begin;
    }
    // Growing across an old partial EOF must not expose its on-disk padding.
    // Shrinking rewrites the retained prefix and clears the same tail.
    std::vector<std::byte> content;
    if (end > begin) {
        content.resize(static_cast<std::size_t>(end - begin));
        if (keep) {
            std::vector<std::byte> old;
            if (!reader.ReadFile(native.object_id, begin, static_cast<std::size_t>(keep), old, error) || old.size() != keep) return false;
            std::copy(old.begin(), old.end(), content.begin());
        }
        if (!resize) std::copy(payload.begin(), payload.end(), content.begin() + static_cast<std::size_t>(offset - begin));
    }
    std::vector<std::pair<std::uint64_t, std::uint64_t>> replaced;
    if (end > begin) {
        replaced.emplace_back(begin, end);
        request.data_writes.push_back({native.private_id, begin, 0, std::move(content)});
    }
    if (!create && !resize && offset > old_size && old_size % 4096 && begin > (old_size & ~std::uint64_t{4095})) {
        const auto tail = old_size & ~std::uint64_t{4095};
        std::vector<std::byte> prefix;
        if (!reader.ReadFile(native.object_id, tail, static_cast<std::size_t>(old_size - tail), prefix, error) || prefix.size() != old_size - tail) return false;
        prefix.resize(4096);
        replaced.emplace_back(tail, tail + 4096);
        request.data_writes.push_back({native.private_id, tail, 0, std::move(prefix)});
    }
    std::sort(replaced.begin(), replaced.end());
    std::uint64_t allocated = 0;
    for (const auto& [from, to] : replaced) allocated += to - from;
    for (const auto& record : records) {
        const auto key = catalog::ReadU64LE(record.key, 0).value_or(0);
        if ((key >> 60) != 8 || (key & ((1ull << 60) - 1)) != native.private_id) continue;
        AppleFileExtentRecord extent;
        if (!DecodeAppleFileExtentRecord(record, 4096, extent, error) || extent.crypto_id ||
            extent.logical_address % 4096 || extent.length_bytes % 4096 ||
            extent.logical_address > UINT64_MAX - extent.length_bytes)
            return Fail(error, "FusionRuntimeExtentUnsupported");
        if (!extent.physical_block) continue;
        const auto first = extent.logical_address, last = first + extent.length_bytes;
        std::vector<std::pair<std::uint64_t, std::uint64_t>> retained;
        const auto clipped = (std::min)(last, rounded);
        if (first < clipped) {
            auto cursor = first;
            for (const auto& [from, to] : replaced) {
                if (to <= cursor || from >= clipped) continue;
                if (cursor < from) retained.emplace_back(cursor, from);
                cursor = (std::max)(cursor, (std::min)(to, clipped));
            }
            if (cursor < clipped) retained.emplace_back(cursor, clipped);
        }
        auto cursor = first;
        const auto release = [&](std::uint64_t from, std::uint64_t to) {
            if (from < to) request.released_data_blocks.push_back({extent.physical_block + (from - first) / 4096, (to - from) / 4096});
        };
        for (const auto& [from, to] : retained) {
            release(cursor, from); cursor = to;
            auto part = extent; part.logical_address = from; part.length_bytes = to - from;
            part.physical_block += (from - first) / 4096;
            catalog::BtreeRecord encoded;
            if (!EncodeAppleFileExtentRecord(part, encoded, error)) return false;
            request.filesystem_records.push_back(std::move(encoded)); allocated += to - from;
        }
        release(cursor, last);
    }
    if (allocated > rounded) return Fail(error, "FusionRuntimeAllocationCoverage");
    native.uncompressed_size = size;
    bool stream = false;
    const auto put = [](auto& bytes, std::size_t at, std::uint64_t value) {
        for (unsigned i = 0; i < 8; ++i) bytes[at + i] = std::byte((value >> (8 * i)) & 255);
    };
    for (auto& field : native.extended_fields) if (field.type == 8) {
        if (stream || field.data.size() != 40 || catalog::ReadU64LE(field.data, 16).value_or(1))
            return Fail(error, "FusionRuntimeStreamShape");
        stream = true; put(field.data, 0, size); put(field.data, 8, allocated);
    }
    if (!stream) return Fail(error, "FusionRuntimeExplicitStreamRequired");
    std::erase_if(native.extended_fields, [](const auto& field) { return field.type == kAppleInodeSparseBytesField; });
    native.internal_flags &= ~kAppleInodeSparseFlag;
    if (rounded != allocated) {
        native.internal_flags |= kAppleInodeSparseFlag;
        native.extended_fields.push_back({kAppleInodeSparseBytesField, 0, std::vector<std::byte>(8)});
        put(native.extended_fields.back().data, 0, rounded - allocated);
    }
    return true;
}
