// Read projection only. Runtime ownership still requires original accepted WAL
// evidence; these records and names alone never authorize orphan retirement.
if (fusion_private_namespace)
{
    const bool anchors = std::any_of(directory_entries.begin(), directory_entries.end(),
        [](const auto& entry) { return entry.parent_id == 1; });
    const bool private_records = raw_inodes.contains(3) || std::any_of(raw_inodes.begin(), raw_inodes.end(),
        [](const auto& pair) { return (pair.second.internal_flags & 1) != 0 || pair.second.parent_id == 3; });
    if (anchors || private_records)
    {
        const auto root = raw_inodes.find(2), reserved = raw_inodes.find(3);
        if (raw_inodes.contains(1) || root == raw_inodes.end() || reserved == raw_inodes.end() ||
            !root->second.is_directory || root->second.parent_id != 1 || root->second.private_id != 2 ||
            root->second.primary_name_utf8 != "root" || (root->second.internal_flags & 1) ||
            !reserved->second.is_directory || reserved->second.parent_id != 1 || reserved->second.private_id != 3 ||
            reserved->second.primary_name_utf8 != "private-dir" || !reserved->second.directory_symlink_metadata_safe ||
            reserved->second.has_data_stream_info || reserved->second.uncompressed_size ||
            extent_record_ids.contains(3) || type_dependent_record_ids.contains(3) ||
            projection.extended_attributes_by_inode.contains(3))
            return ordinary_refusal("FusionPrivateDirectoryInvalid");
        unsigned roots = 0, private_dirs = 0;
        for (const auto& entry : directory_entries)
        {
            if (entry.parent_id == 1)
            {
                if (entry.flags != 4) return ordinary_refusal("FusionPrivateAnchorInvalid");
                if (entry.child_id == 2 && entry.name_utf8 == "root") ++roots;
                else if (entry.child_id == 3 && entry.name_utf8 == "private-dir") ++private_dirs;
                else return ordinary_refusal("FusionPrivateAnchorInvalid");
            }
            else if (entry.child_id == 3) return ordinary_refusal("FusionPrivateAnchorInvalid");
            if (entry.parent_id == 3)
            {
                const auto child = raw_inodes.find(entry.child_id);
                if (child == raw_inodes.end() || child->first < 16 || child->second.parent_id != 3 ||
                    child->second.private_id != child->first || (child->second.mode & 0170000) != 0100000 ||
                    !(child->second.internal_flags & 1) || child->second.link_count != 1 || entry.flags != 8 ||
                    !entry.name_utf8.starts_with("apfsaccess-fusion-orphan-") ||
                    child->second.primary_name_utf8 != entry.name_utf8)
                    return ordinary_refusal("FusionPrivateFileProfileInvalid");
            }
        }
        for (const auto& [id, inode] : raw_inodes)
            if (((inode.internal_flags & 1) != 0) != (inode.parent_id == 3))
                return ordinary_refusal("FusionPrivateFilePlacementInvalid");
        if (roots != 1 || private_dirs != 1) return ordinary_refusal("FusionPrivateAnchorInvalid");
        std::erase_if(directory_entries, [](const auto& entry) { return entry.parent_id == 1; });
        fusion_private_root = true;
    }
}
