// Private members of CowPlanner. Inputs and decoded records never leave the session.
    static constexpr std::uint64_t max_file_bytes = 16 * bs;
    struct MutationState
    {
        std::uint64_t inode = 0, stream = 0, size = 0, blocks = 0;
        std::uint64_t old_block = 0, old_crypto = 0;
        std::uint64_t next_oid = 0, file_count = 0, directory_count = 0;
        std::uint16_t effective_mode = 0;
        std::uint8_t extent_flags = 1;
        bool rewrite_data = false, directory = false;
        std::uint64_t replaced_inode = 0, replaced_stream = 0, replaced_size = 0;
        std::uint16_t replaced_mode = 0;
        std::string_view replaced_name;
        crypto::SecureBytes plain;
        encrypted_delta::DataPlan delta;
    };
    bool Digest(std::span<const std::byte> input, std::array<std::uint8_t, 32>& out)
    {
        BCRYPT_ALG_HANDLE algorithm = nullptr;
        if (input.size() > ULONG_MAX || BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
            return Fail("EncryptedCowIntentHashFailed");
        const auto status = BCryptHash(algorithm, nullptr, 0,
            reinterpret_cast<PUCHAR>(const_cast<std::byte*>(input.data())), static_cast<ULONG>(input.size()),
            out.data(), static_cast<ULONG>(out.size()));
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return status >= 0 || Fail("EncryptedCowIntentHashFailed");
    }
    static std::uint64_t RowId(const BtreeRecord& row)
    { return ReadU64LE(row.key, 0).value_or(0) & 0x0fffffffffffffffULL; }
    static unsigned RowType(const BtreeRecord& row)
    { return static_cast<unsigned>(ReadU64LE(row.key, 0).value_or(0) >> 60); }
    bool Inode(const BtreeRecord& row, rw::AppleInodeRecord& inode)
    { return DecodeImageRecord(row, 0x5c, inode, error, rw::ApfsExtendedRecordCodec::DecodeInode); }
    bool Directory(const BtreeRecord& row, rw::AppleDirectoryRecord& directory)
    {
        return DecodeImageRecord(row, 18, directory, error, [&](const auto& value, auto& out, auto& detail) {
            return rw::ApfsExtendedRecordCodec::DecodeDirectory(value, owner.name_policy, out, detail);
        });
    }
    bool ChangeParent(Tree& fs, std::uint64_t parent, int delta)
    {
        for (auto& row : fs.records.bytes) if (RowType(row) == 3 && RowId(row) == parent) {
            rw::AppleInodeRecord inode; Cleanup clear{inode};
            if (!Inode(row, inode) || (inode.mode & 0170000) != 0040000 ||
                inode.children_or_links < 0 || (delta < 0 && inode.children_or_links == 0) ||
                (delta > 0 && inode.children_or_links == INT32_MAX)) return Fail("EncryptedCowParentInvalid");
            inode.children_or_links += delta;
            return rw::EncodeAppleInodeRecord(inode, row, error);
        }
        return Fail("EncryptedCowParentMissing");
    }
    bool NameAvailable(std::uint64_t parent, std::string_view name, std::uint64_t except = 0,
        std::uint64_t replaced = 0)
    {
        if (!owner.nodes.contains(parent) || !owner.nodes.at(parent).IsDirectory())
            return Fail("EncryptedCowParentMissing");
        auto decoded = rw::ApfsNameCodec::Decode(std::as_bytes(std::span(name)), owner.name_policy);
        if (!decoded.value) return Fail("EncryptedCowInvalidName");
        Cleanup clear{*decoded.value};
        for (const auto& entry : owner.entries)
            if (entry.info.parent_id == parent && entry.info.inode_id != except &&
                entry.info.inode_id != replaced && entry.lookup_key == decoded.value->lookup_key)
                return Fail("EncryptedCowNameExists");
        return true;
    }
    bool DirectoryDestination(std::uint64_t inode, std::uint64_t destination)
    {
        auto cursor = destination;
        for (std::size_t hops = 0; hops <= owner.nodes.size(); ++hops) {
            if (cursor == inode) return Fail("EncryptedCowDirectoryCycle");
            const auto parent = owner.nodes.find(cursor);
            if (parent == owner.nodes.end() || !parent->second.IsDirectory())
                return Fail("EncryptedCowDirectoryAncestorMissing");
            if (cursor == 2) return true;
            if (parent->second.parent_id < 2 || parent->second.parent_id == cursor)
                return Fail("EncryptedCowDirectoryAncestorInvalid");
            cursor = parent->second.parent_id;
        }
        return Fail("EncryptedCowDirectoryCycle");
    }
    bool PrepareAttribute(const EncryptedMutationRequest& request, Tree& fs, const MutationState& state)
    {
        const bool remove = request.kind == EncryptedMutationKind::RemoveExtendedAttribute;
        const bool fork = request.name == "com.apple.ResourceFork";
        if (request.name.size() > 821 ||
            request.name.find('\0') != request.name.npos ||
            MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, request.name.data(), static_cast<int>(request.name.size()), nullptr, 0) <= 0)
            return Fail("EncryptedCowAttributeNameInvalid");
        if (!rw::IsOrdinaryAppleXattrName(request.name) && !fork)
            return Fail("EncryptedCowSystemAttributeUnsupported");
        const auto& inode_metadata = owner.nodes.at(state.inode);
        if (fork && !rw::IsUncompressedAppleResourceForkOwner(state.inode, state.stream,
                inode_metadata.mode, inode_metadata.bsd_flags, false))
            return Fail("EncryptedCowResourceForkOwnerUnsupported");
        if (!remove && request.name == "com.apple.FinderInfo" && request.data.size() != 32)
            return Fail("EncryptedCowFinderInfoSizeInvalid");
        if (!remove && request.name == "com.apple.system.Security") {
            rw::AppleSecurityRecord security;
            if (!rw::ApfsExtendedRecordCodec::DecodeSecurity(request.data, security, error)) return false;
        }
        rw::AppleXattrRecord next; Cleanup clear{next};
        next.object_id = state.inode; next.name_utf8 = request.name; next.flags = rw::kAppleXattrDataEmbedded;
        next.data.assign(request.data.begin(), request.data.end());
        Records encoded; encoded.bytes.emplace_back();
        if (!rw::EncodeAppleXattrRecord(next, encoded.bytes.back(), error)) return false;
        auto selected = fs.records.bytes.end();
        for (auto it = fs.records.bytes.begin(); it != fs.records.bytes.end(); ++it) {
            if (RowType(*it) != 4 || RowId(*it) != state.inode) continue;
            rw::AppleXattrRecord old; Cleanup clear_old{old};
            if (!rw::ApfsExtendedRecordCodec::DecodeXattr(*it, old, error)) return false;
            if (old.name_utf8 != request.name) continue;
            if (selected != fs.records.bytes.end()) return Fail("EncryptedCowAttributeAmbiguous");
            if ((old.flags & ~rw::kAppleXattrFileSystemOwned) != rw::kAppleXattrDataEmbedded ||
                (fork && old.flags != rw::kAppleXattrDataEmbedded))
                return Fail("EncryptedCowAttributeStorageUnsupported");
            next.flags = old.flags; selected = it;
        }
        if (remove) {
            if (selected == fs.records.bytes.end()) return Fail("EncryptedCowAttributeMissing");
            Wipe(selected->key); Wipe(selected->value); fs.records.bytes.erase(selected);
        } else {
            if (!rw::EncodeAppleXattrRecord(next, encoded.bytes.back(), error)) return false;
            if (selected == fs.records.bytes.end()) fs.records.bytes.push_back(std::move(encoded.bytes.back()));
            else { Wipe(selected->key); Wipe(selected->value); *selected = std::move(encoded.bytes.back()); }
        }
        if (fork) for (auto& row : fs.records.bytes) if (RowType(row) == 3 && RowId(row) == state.inode) {
            rw::AppleInodeRecord inode; Cleanup clear_inode{inode};
            if (!Inode(row, inode)) return false;
            if (remove) inode.internal_flags |= kInodeNoResourceFork;
            else inode.internal_flags &= ~kInodeNoResourceFork;
            return rw::EncodeAppleInodeRecord(inode, row, error);
        }
        return !fork || Fail("EncryptedCowInodeMissing");
    }
    bool PrepareRecords(const EncryptedMutationRequest& request, const AppleCheckpointView& current,
        Tree& fs, MutationState& state)
    {
        const auto kind = request.kind;
        const bool make_directory = kind == EncryptedMutationKind::MakeDirectory;
        const bool set_metadata = kind == EncryptedMutationKind::SetInodeMetadata;
        const bool set_attribute = kind == EncryptedMutationKind::SetExtendedAttribute;
        const bool remove_attribute = kind == EncryptedMutationKind::RemoveExtendedAttribute;
        const bool mutate_attribute = set_attribute || remove_attribute;
        const bool create = kind == EncryptedMutationKind::Create || make_directory;
        const bool replace = kind == EncryptedMutationKind::ReplaceRename;
        const bool rename = kind == EncryptedMutationKind::Rename || replace;
        const bool unlink = kind == EncryptedMutationKind::Unlink;
        const bool resize = kind == EncryptedMutationKind::Resize;
        const bool overwrite = kind == EncryptedMutationKind::Overwrite;
        const bool write = kind == EncryptedMutationKind::Write || overwrite;
        if ((!create && !rename && !unlink && !resize && !write && !set_metadata && !mutate_attribute) || request.data.size() > (scalable ? 64 * bs : max_file_bytes) ||
            (!scalable && (request.offset > max_file_bytes || request.size > max_file_bytes)) ||
            ((rename || unlink || resize) && (!request.data.empty() || request.offset)) ||
            ((write || create || rename || unlink || set_metadata) && request.size) ||
            (!create && (request.permissions != 0644)) ||
            ((write || resize || set_metadata) && (request.parent || request.destination_parent || !request.name.empty() || !request.destination_name.empty())) ||
            ((create || unlink) && (request.destination_parent || !request.destination_name.empty())) ||
            (create && (request.inode || request.offset || (request.permissions & ~0777))) ||
            (make_directory && !request.data.empty()) || (set_metadata && request.offset) ||
            (mutate_attribute && (request.offset || request.size || request.parent || request.destination_parent ||
                !request.destination_name.empty() || request.name.empty() || request.data.size() > 3804)) ||
            (remove_attribute && !request.data.empty()))
            return Fail("EncryptedCowMutationArgumentsInvalid");
        rw::InodeMetadataPatch patch;
        if (set_metadata && !rw::DecodeInodeMetadataPatch(request.data, patch))
            return Fail("EncryptedCowMetadataPatchInvalid");
        const auto& selected_superblock = current.volumes.front().superblock;
        state.next_oid = selected_superblock.next_object_id; state.file_count = selected_superblock.file_count;
        state.directory_count = selected_superblock.directory_count;
        state.inode = request.inode;
        const Impl::File* file = nullptr;
        const EncryptedNodeInfo* target_metadata = nullptr;
        if (!create) {
            if (request.inode < 16 && !((set_metadata || mutate_attribute) && request.inode == 2)) return Fail("EncryptedCowReservedInodeUnsupported");
            const auto target_node = owner.nodes.find(request.inode);
            if (target_node == owner.nodes.end()) return Fail("EncryptedCowFileMissing");
            target_metadata = &target_node->second;
            if (replace && (target_metadata->mode & 0170000) != 0100000)
                return Fail("EncryptedCowReplacementDirectoryUnsupported");
            state.directory = target_metadata->IsDirectory();
            state.effective_mode = target_metadata->mode;
            if (state.directory) {
                if (replace) return Fail("EncryptedCowReplacementDirectoryUnsupported");
                if ((!rename && !unlink && !set_metadata && !mutate_attribute) || target_metadata->private_id != request.inode ||
                    target_metadata->size || target_metadata->allocated_size)
                    return Fail("EncryptedCowDirectoryLayoutUnsupported");
                for (const auto& [id, other] : owner.nodes)
                    if (id != request.inode && other.private_id == request.inode)
                        return Fail("EncryptedCowSharedStreamUnsupported");
                for (const auto& row : fs.records.bytes)
                    if (RowId(row) == request.inode && (RowType(row) == 6 || RowType(row) == 8))
                        return Fail("EncryptedCowDirectoryStreamUnsupported");
                if (unlink && (target_metadata->children_or_links ||
                    std::any_of(owner.entries.begin(), owner.entries.end(), [&](const auto& entry) {
                        return entry.info.parent_id == request.inode; })))
                    return Fail("EncryptedCowDirectoryNotEmpty");
                if (rename && !DirectoryDestination(request.inode, request.destination_parent)) return false;
                state.stream = request.inode;
            } else {
                const auto found = owner.files.find(request.inode);
                if (found == owner.files.end()) return Fail("EncryptedCowFileMissing");
                file = &found->second;
                if (file->sparse || target_metadata->children_or_links != 1 || target_metadata->private_id != file->private_id ||
                    (!scalable && target_metadata->size > max_file_bytes) || target_metadata->size > UINT64_MAX - (bs - 1) ||
                    target_metadata->allocated_size != ((target_metadata->size + bs - 1) / bs) * bs ||
                    (target_metadata->bsd_flags & rw::kAppleBsdCompressedFlag)) return Fail("EncryptedCowExistingExclusiveExtentRequired");
                for (const auto& [id, other] : owner.nodes)
                    if (id != request.inode && other.private_id == target_metadata->private_id) return Fail("EncryptedCowSharedStreamUnsupported");
                state.stream = file->private_id; state.size = file->info.size;
                if (!overwrite && state.stream != state.inode) return Fail("EncryptedCowPrivateIdentityUnsupported");
                if (!file->extents.empty()) { state.old_block = file->extents.front().physical_block; state.old_crypto = file->extents.front().crypto_id; }
            }
            for (const auto& entry : owner.entries)
                if (entry.info.inode_id == request.inode && entry.info.sibling_id) return Fail("EncryptedCowSiblingMutationUnsupported");
            for (const auto& attribute : owner.attributes) if (attribute.inode_id == request.inode &&
                ((attribute.info.flags & rw::kAppleXattrDataStream) || attribute.info.name_utf8 == "com.apple.decmpfs"))
                return Fail("EncryptedCowExternalAttributeUnsupported");
            if (set_metadata && (patch.mask & rw::InodeMetadataPatch::BsdFlags) &&
                ((patch.bsd_flags ^ target_metadata->bsd_flags) & rw::kAppleBsdCompressedFlag))
                return Fail("EncryptedCowCompressionFlagRequiresContentRewrite");
            if (set_metadata && (patch.mask & rw::InodeMetadataPatch::Mode))
                state.effective_mode = static_cast<std::uint16_t>((target_metadata->mode & 0170000) | patch.mode);
        }
        if (overwrite && (request.data.empty() || (!scalable && (file->extents.size() != 1 || target_metadata->allocated_size != bs)) ||
            request.offset > state.size || request.data.size() > state.size - request.offset))
            return Fail("EncryptedCowExistingExclusiveExtentRequired");
        if (write) {
            if (request.data.empty() || request.offset > UINT64_MAX - request.data.size() ||
                (!scalable && request.data.size() > max_file_bytes - request.offset)) return Fail("EncryptedCowWriteRangeInvalid");
            state.size = (std::max)(state.size, request.offset + request.data.size());
        } else if (resize) state.size = request.size;
        else if (create) state.size = request.data.size();
        state.rewrite_data = write || resize || (create && !make_directory);
        if (state.size > UINT64_MAX - (bs - 1)) return Fail("EncryptedDeltaRangeOverflow");
        state.blocks = state.rewrite_data ? (state.size + bs - 1) / bs : 0;
        if (scalable && state.rewrite_data) {
            std::vector<rw::AppleEncryptedFileExtentRecord> old;
            for (const auto& row : fs.records.bytes) if (RowType(row) == 8 && RowId(row) == state.stream) {
                rw::AppleEncryptedFileExtentRecord extent;
                if (!rw::DecodeAppleEncryptedFileExtentRecord(row, bs, profile, extent, error)) return false;
                if (!old.empty() && old.front().flags != extent.flags) return Fail("EncryptedCowMixedExtentFlagsUnsupported");
                state.extent_flags = extent.flags; old.push_back(extent);
            }
            std::sort(old.begin(), old.end(), [](const auto& a, const auto& b) { return a.extent.logical_address < b.extent.logical_address; });
            if (!encrypted_delta::PlanData(old, create ? state.next_oid : state.stream, file ? file->info.size : 0,
                request, 64, state.delta, error)) return false;
            state.blocks = state.delta.changed.size();
        }
        if (!scalable && state.blocks) {
            auto plain = crypto::SecureBytes::Allocate(static_cast<std::size_t>(state.blocks * bs));
            if (!plain) {
                error = "EncryptedCowLockedStagingCapacityLimit:" + std::to_string(plain.os_status);
                return false;
            }
            state.plain = std::move(plain.bytes);
            std::fill(state.plain.Bytes().begin(), state.plain.Bytes().end(), std::byte{});
        }
        if (!scalable && file && state.rewrite_data) {
            std::uint64_t logical = 0;
            for (const auto& extent : file->extents) {
                if (extent.logical_address != logical || !extent.physical_block || extent.length_bytes / bs > 16)
                    return Fail("EncryptedCowHoleOrExtentLimitUnsupported");
                for (std::uint64_t i = 0; i < extent.length_bytes / bs; ++i) {
                    const auto at = extent.logical_address + i * bs;
                    if (at < state.blocks * bs) {
                        std::vector<std::byte> cipher;
                        auto block = crypto::SecureBytes::Allocate(bs);
                        if (!block) {
                            error = "EncryptedCowLockedStagingCapacityLimit:" + std::to_string(block.os_status);
                            return false;
                        }
                        if (!Block(source, extent.physical_block + i, cipher) ||
                            !owner.Transform(cipher, (extent.crypto_id + i) * (bs / 512), block.bytes.Bytes())) return false;
                        const auto keep = overwrite ? bs : at >= file->info.size ? 0 : (std::min)(std::uint64_t(bs), file->info.size - at);
                        std::copy_n(block.bytes.Bytes().begin(), static_cast<std::size_t>(keep), state.plain.Bytes().begin() + at);
                    }
                }
                logical += extent.length_bytes;
            }
            if (logical != target_metadata->allocated_size) return Fail("EncryptedCowExactExtentMissing");
        }
        if (!scalable && (write || create)) std::copy(request.data.begin(), request.data.end(), state.plain.Bytes().begin() + request.offset);
        if (!scalable && state.rewrite_data && !overwrite && state.blocks)
            std::fill(state.plain.Bytes().begin() + state.size, state.plain.Bytes().end(), std::byte{});
        if (create || rename) {
            const auto parent = create ? request.parent : request.destination_parent;
            const auto name = create ? request.name : request.destination_name;
            if (replace) {
                auto decoded = rw::ApfsNameCodec::Decode(std::as_bytes(std::span(name)), owner.name_policy);
                if (!decoded.value) return Fail("EncryptedCowInvalidName");
                Cleanup clear{*decoded.value};
                for (const auto& entry : owner.entries) {
                    if (entry.info.parent_id != parent || entry.lookup_key != decoded.value->lookup_key) continue;
                    if (entry.info.inode_id == state.inode) return Fail("EncryptedCowReplacementSameInodeUnsupported");
                    if (state.replaced_inode) return Fail("EncryptedCowReplacementAmbiguous");
                    const auto found = owner.nodes.find(entry.info.inode_id);
                    if (found == owner.nodes.end() || (found->second.mode & 0170000) != 0100000)
                        return Fail("EncryptedCowReplacementDirectoryUnsupported");
                    state.replaced_inode = entry.info.inode_id; state.replaced_stream = found->second.private_id;
                    state.replaced_size = found->second.size; state.replaced_mode = found->second.mode;
                    state.replaced_name = entry.info.name_utf8;
                }
            }
            if (!NameAvailable(parent, name, rename ? state.inode : 0, state.replaced_inode)) return false;
            if (state.replaced_inode) {
                EncryptedMutationRequest remove;
                remove.kind = EncryptedMutationKind::Unlink; remove.inode = state.replaced_inode;
                remove.parent = parent; remove.name = state.replaced_name;
                MutationState removed;
                if (!PrepareRecords(remove, current, fs, removed)) return false;
                if (removed.directory || removed.stream != state.replaced_stream)
                    return Fail("EncryptedCowReplacementTargetChanged");
                state.file_count = removed.file_count;
            }
        }
        if (create) {
            for (const auto& attribute : owner.attributes)
                if (attribute.inode_id == request.parent && attribute.info.name_utf8 == "com.apple.system.Security")
                    return Fail("EncryptedCowInheritedSecurityUnsupported");
            if (!state.next_oid || state.next_oid >= 0x0fffffffffffffffULL ||
                (make_directory ? state.directory_count : state.file_count) == UINT64_MAX)
                return Fail("EncryptedCowObjectIdExhausted");
            for (const auto& row : fs.records.bytes)
                if (RowId(row) >= state.next_oid) return Fail("EncryptedCowNextObjectIdUnproven");
            for (const auto& [id, old] : owner.nodes) {
                (void)id;
                if (old.private_id >= state.next_oid) return Fail("EncryptedCowNextObjectIdUnproven");
            }
            state.inode = state.stream = state.next_oid++;
            state.directory = make_directory;
            if (make_directory) ++state.directory_count; else ++state.file_count;
            const auto& parent = owner.nodes.at(request.parent);
            rw::AppleInodeRecord inode; Cleanup clear_inode{inode};
            inode.object_id = inode.private_id = state.inode; inode.parent_id = request.parent;
            inode.mode = static_cast<std::uint16_t>((make_directory ? 0040000 : 0100000) | request.permissions);
            state.effective_mode = inode.mode;
            inode.owner = parent.uid; inode.group = parent.gid; inode.children_or_links = make_directory ? 0 : 1;
            inode.internal_flags = kInodeNoResourceFork; inode.default_protection_class = parent.protection_class;
            rw::AppleExtendedField name; name.type = 4; name.flags = 2;
            name.data.assign(reinterpret_cast<const std::byte*>(request.name.data()), reinterpret_cast<const std::byte*>(request.name.data() + request.name.size()));
            name.data.push_back(std::byte{}); inode.extended_fields.push_back(std::move(name));
            if (!make_directory) {
                rw::AppleExtendedField stream; stream.type = 8; stream.flags = 1; stream.data.resize(40);
                Put(stream.data, 0, state.size); Put(stream.data, 8, encrypted_delta::Blocks(state.size) * bs);
                inode.extended_fields.push_back(std::move(stream));
            }
            fs.records.bytes.emplace_back();
            if (!rw::EncodeAppleInodeRecord(inode, fs.records.bytes.back(), error)) return false;
            rw::AppleDirectoryRecord directory; Cleanup clear_directory{directory};
            directory.parent_id = request.parent; directory.file_id = state.inode; directory.flags = make_directory ? 4 : 8;
            directory.name_utf8 = request.name;
            fs.records.bytes.emplace_back();
            if (!rw::EncodeAppleDirectoryRecord(directory, owner.name_policy, fs.records.bytes.back(), error) ||
                !ChangeParent(fs, request.parent, 1)) return false;
        } else if (rename || unlink) {
            std::size_t matches = 0;
            for (auto& row : fs.records.bytes) if (RowType(row) == 9) {
                rw::AppleDirectoryRecord directory; Cleanup clear{directory};
                if (!Directory(row, directory)) return false;
                if (directory.file_id != state.inode) continue;
                if (directory.parent_id != request.parent || directory.name_utf8 != request.name || !directory.extended_fields.empty())
                    return Fail("EncryptedCowSourceNameMismatch");
                if (rename) {
                    directory.parent_id = request.destination_parent; directory.name_utf8 = request.destination_name;
                    if (!rw::EncodeAppleDirectoryRecord(directory, owner.name_policy, row, error)) return false;
                } else { Wipe(row.key); Wipe(row.value); }
                ++matches;
            }
            if (matches != 1) return Fail("EncryptedCowSourceNameMismatch");
            if (unlink || request.parent != request.destination_parent)
                if (!ChangeParent(fs, request.parent, -1)) return false;
            if (rename && request.parent != request.destination_parent)
                if (!ChangeParent(fs, request.destination_parent, 1)) return false;
            if (unlink) {
                auto& count = state.directory ? state.directory_count : state.file_count;
                if (!count) return Fail("EncryptedCowFileCountInvalid");
                --count; state.size = 0;
                for (auto& row : fs.records.bytes) if (RowId(row) == state.inode || RowId(row) == state.stream) {
                    if (RowType(row) != 3 && RowType(row) != 4 &&
                        (state.directory || (RowType(row) != 6 && RowType(row) != 8)))
                        return Fail("EncryptedCowUnlinkRecordUnsupported");
                    Wipe(row.key); Wipe(row.value);
                }
            }
            std::erase_if(fs.records.bytes, [](const auto& row) { return row.key.empty(); });
        }
        if (mutate_attribute && !PrepareAttribute(request, fs, state)) return false;
        if (!create && !unlink && !overwrite && (state.rewrite_data || rename || set_metadata)) {
            bool found = false;
            for (auto& row : fs.records.bytes) if (RowType(row) == 3 && RowId(row) == state.inode) {
                rw::AppleInodeRecord inode; Cleanup clear{inode};
                if (!Inode(row, inode)) return false;
                for (auto& field : inode.extended_fields) {
                    if (field.type == 8 && state.rewrite_data) {
                        if (field.data.size() != 40) return Fail("EncryptedCowStreamInvalid");
                        Put(field.data, 0, state.size); Put(field.data, 8, encrypted_delta::Blocks(state.size) * bs);
                    }
                    if (field.type == 4 && rename) {
                        Wipe(field.data);
                        const auto name = request.destination_name;
                        field.data.assign(reinterpret_cast<const std::byte*>(name.data()), reinterpret_cast<const std::byte*>(name.data() + name.size()));
                        field.data.push_back(std::byte{});
                    }
                }
                if (rename) inode.parent_id = request.destination_parent;
                if (set_metadata) {
                    inode.mode = state.effective_mode;
                    if (patch.mask & rw::InodeMetadataPatch::Owner) inode.owner = patch.owner;
                    if (patch.mask & rw::InodeMetadataPatch::Group) inode.group = patch.group;
                    if (patch.mask & rw::InodeMetadataPatch::BsdFlags) inode.bsd_flags = patch.bsd_flags;
                    const auto nanos = [](std::uint64_t ticks) { return (ticks - rw::InodeMetadataPatch::UnixEpochTicks) * 100; };
                    if (patch.mask & rw::InodeMetadataPatch::CreateTime) inode.create_time = nanos(patch.create_time_utc);
                    if (patch.mask & rw::InodeMetadataPatch::ModificationTime) inode.modification_time = nanos(patch.modification_time_utc);
                    if (patch.mask & rw::InodeMetadataPatch::ChangeTime) inode.change_time = nanos(patch.change_time_utc);
                    if (patch.mask & rw::InodeMetadataPatch::AccessTime) inode.access_time = nanos(patch.access_time_utc);
                }
                if (!rw::EncodeAppleInodeRecord(inode, row, error)) return false;
                found = true;
            }
            if (!found) return Fail("EncryptedCowInodeMissing");
        }
        return true;
    }
