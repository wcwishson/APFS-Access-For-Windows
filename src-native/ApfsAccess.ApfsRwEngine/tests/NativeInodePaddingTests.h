void NativeInodePaddingCases()
{
    constexpr std::uint64_t padding = 0xfedcba9876543210ULL;
    for (const bool flagged : {false, true}) {
        auto spec = CloneSpec(1);
        std::string error;
        for (auto& record : spec.volumes[0].filesystem_records) {
            if (Type(record) != 3 || (Id(record) != 17 && Id(record) != 2)) continue;
            AppleInodeRecord inode;
            Check(ApfsExtendedRecordCodec::DecodeInode(record, inode, error), error);
            inode.uncompressed_size = padding;
            if (flagged && Id(record) == 17) {
                inode.internal_flags |= kAppleInodeHasUncompressedSize;
                inode.uncompressed_size = 4 * kBlockSize;
            }
            Check(EncodeAppleInodeRecord(inode, record, error), error);
        }
        Fixture fixture(spec);
        const auto path = std::filesystem::absolute(flagged ? "flagged-size.apfs" : "inode-padding.apfs");
        Save(path, fixture.image);
        Store store(Context(path));
        Check(store.PrepareNativeWritePath(), "native padding source opens");
        Store::MutationRequest create;
        create.operation = Store::MutationOperation::CreateFile;
        create.path = L"\\new-padding-check";
        Check(store.StageMutation(create) == Store::MutationStatus::Applied, "new inode stages");
        Store::MutationRequest truncate;
        truncate.operation = Store::MutationOperation::SetFileSize;
        truncate.path = L"\\clone0";
        truncate.length = 0;
        Check(store.StageMutation(truncate) == Store::MutationStatus::Applied, "padding owner truncates");
        Check(store.CommitCanonicalTransaction() == Store::CommitStatus::Committed,
            "padding-preserving mutation publishes");
        Store fresh(Context(path));
        Check(fresh.PrepareNativeWritePath(), "padding-preserving result reopens");
        Check(fresh.LookupCommittedInodeByPath(L"\\clone0")->logical_size == 0,
            "padding never becomes file EOF after truncate");
        const auto target = fresh.LookupCommittedInodeByPath(create.path);
        Check(target.has_value(), "new padding-test inode exists");
        fixture.image = Disk(path);
        fixture.Reload();
        unsigned inspected = 0;
        for (const auto& record : ReadTree(fixture)) {
            if (Type(record) != 3) continue;
            const auto id = Id(record);
            if (id != 2 && id != 17 && id != target->object_id) continue;
            AppleInodeRecord inode;
            Check(ApfsExtendedRecordCodec::DecodeInode(record, inode, error), error);
            const auto expected = id == target->object_id || (id == 17 && flagged) ? 0 : padding;
            Check(inode.uncompressed_size == expected,
                "new padding is zero, existing padding preserved, flagged size updated");
            ++inspected;
        }
        Check(inspected == 3, "parent, existing file and new file padding inspected");
    }

    auto spec = CloneSpec(1);
    auto& volume = spec.volumes[0];
    std::erase_if(volume.filesystem_records, [](const auto& record) {
        return Id(record) == 17 && (Type(record) == 6 || Type(record) == 8);
    });
    volume.extentref_records.clear();
    volume.additional_file_system_allocated_blocks = 0;
    spec.authoritative_seeded_main_blocks.clear();
    std::string error;
    for (auto& record : volume.filesystem_records) {
        if (Type(record) != 3 || Id(record) != 17) continue;
        AppleInodeRecord inode;
        Check(ApfsExtendedRecordCodec::DecodeInode(record, inode, error), error);
        inode.uncompressed_size = padding;
        std::erase_if(inode.extended_fields, [](const auto& field) { return field.type == 8; });
        Check(EncodeAppleInodeRecord(inode, record, error), error);
    }
    Fixture fixture(spec);
    const auto path = std::filesystem::absolute("empty-padding.apfs");
    Save(path, fixture.image);
    Store empty(Context(path));
    Check(empty.PrepareNativeWritePath(), "empty file accepts opaque native padding");
    const auto inode = empty.LookupCommittedInodeByPath(L"\\clone0");
    Check(inode && inode->logical_size == 0, "padding without dstream is not content size");
    std::vector<std::byte> bytes;
    Check(empty.ReadCommittedFileRange(L"\\clone0", 0, 4096, bytes) && bytes.empty(),
        "empty padded file reads EOF");
}
