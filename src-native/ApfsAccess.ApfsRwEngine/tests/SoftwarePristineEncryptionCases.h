namespace
{
constexpr const wchar_t* pristine_name = L"dfvfs-plain-apfs.raw";
constexpr const char* pristine_pin = "e3e3adcbbf189403d892b013d6cba155f2e58e42ff5eb541ec681c37a91a3f29";

class PristineObjectOverlay final : public c::RandomAccessSource
{
public:
    PristineObjectOverlay(const c::RandomAccessSource& source, std::uint64_t block, std::vector<std::byte> bytes)
        : source_(source), offset_(block * 4096), bytes_(std::move(bytes)) {}
    std::uint64_t SizeBytes() const override { return source_.SizeBytes(); }
    bool Read(std::uint64_t offset, std::size_t size, std::vector<std::byte>& out) const override
    {
        if (!source_.Read(offset, size, out)) return false;
        for (std::size_t i = 0; i < out.size(); ++i)
            if (offset + i >= offset_ && offset + i - offset_ < bytes_.size()) out[i] = bytes_[offset + i - offset_];
        return true;
    }
private:
    const c::RandomAccessSource& source_;
    std::uint64_t offset_;
    std::vector<std::byte> bytes_;
};

void PristineEmptyContainerControls(const c::RandomAccessSource& source, const c::ContainerCheckpointView& old)
{
    std::string error;
    Check(old.superblock.fs_oids.empty() && !c::LoadAppleReadOnlyVolumeView(source, old, error) &&
        error == "AppleCheckpointNoVolumes", "EmptyContainerDoesNotBecomeVolumeAdmission");
    const auto map = c::LoadAppleContainerObjectMapView(source, old, error);
    Check(map && map->object.xid <= old.superblock.xid && map->tree.xid <= old.superblock.xid,
        "GenuinePreVolumeContainerObjectMapAdmitted");
    std::vector<std::byte> raw;
    Check(source.Read(map->object.physical_block * 4096, 4096, raw), "GenuineContainerOmapControlBytes");
    const auto set = [](std::vector<std::byte>& bytes, std::size_t offset, std::uint64_t value, std::size_t width) {
        for (std::size_t i = 0; i < width; ++i) bytes[offset + i] = static_cast<std::byte>(value >> (i * 8));
    };
    for (int control = 0; control < 6; ++control) {
        auto altered = raw;
        if (control == 0) altered[0] ^= std::byte{1};
        if (control == 1) set(altered, 8, map->object.object_id + 1, 8);
        if (control == 2) set(altered, 16, old.superblock.xid + 1, 8);
        if (control == 3) set(altered, 24, 0x4000000Cu, 4);
        if (control == 4) set(altered, 0x30, source.SizeBytes() / 4096, 8);
        if (control == 5) set(altered, 0x20, 2, 4);
        if (control) set(altered, 0, *c::Fletcher64(altered.data() + 8, altered.size() - 8), 8);
        PristineObjectOverlay candidate(source, map->object.physical_block, std::move(altered));
        Check(!c::LoadAppleContainerObjectMapView(candidate, old, error), "ContainerOmapAuthenticMalformedObjectRefused");
    }
    Check(source.Read(map->tree.physical_block * 4096, 4096, raw), "GenuineContainerOmapTreeControlBytes");
    raw[100] ^= std::byte{1};
    PristineObjectOverlay bad_tree(source, map->tree.physical_block, std::move(raw));
    Check(!c::LoadAppleContainerObjectMapView(bad_tree, old, error), "ContainerOmapTreeChecksumRefused");
    auto exhausted = std::make_shared<c::ApfsReadBudget>(0, 0, 0, 0);
    c::BudgetedRandomAccessSource bounded(source, exhausted);
    Check(!c::LoadAppleContainerObjectMapView(bounded, old, error) && exhausted->Failed(), "ContainerOmapReadBudgetEnforced");
}

void PristineInventory(const std::filesystem::path& run)
{
    auto lease = std::make_shared<t::WindowsImageLease>((run / pristine_name).wstring());
    auto source = std::make_shared<t::OwnedEncryptedImageSource>(lease, 0, 4153344);
    std::string error; auto cp = c::LoadAppleCheckpointView(*source, 0, source->SizeBytes(), error);
    Check(cp && cp->container.superblock.xid == 4 && cp->volumes.size() == 1 &&
        cp->volumes.front().superblock.fs_flags == 1 &&
        c::ReadU64LE(cp->container.superblock_bytes, 0x510) == 0 &&
        c::ReadU64LE(cp->container.superblock_bytes, 0x518) == 0, "PristineRealPlainFullAllocatorAndBagAbsence");
    for (std::uint64_t xid = 1; xid <= 4; ++xid) {
        auto old = c::LoadContainerCheckpointView(*source, 0, source->SizeBytes(), error, xid);
        if (old && old->superblock.fs_oids.empty()) PristineEmptyContainerControls(*source, *old);
        auto view = old ? c::LoadAppleReadOnlyVolumeView(*source, *old, error) : std::nullopt;
        if (old && !old->superblock.fs_oids.empty()) {
            const auto plain = c::LoadApplePlainTransitionVolumeView(*source, *old, error);
            Check(view && !view->volumes.front().root_tree.object_id && plain && plain->volumes.size() == 1 &&
                plain->volumes.front().root_tree.object_id && plain->volumes.front().extentref_tree,
                "InactivePlainFileExtentTupleUsesSeparateStrictReadPath");
            const auto block = plain->volumes.front().superblock_object.physical_block;
            std::vector<std::byte> raw; Check(source->Read(block * 4096, 4096, raw), "InactiveFileExtentTupleRealApsb");
            for (int control = 0; control < 4; ++control) {
                auto altered = raw;
                const auto set = [&](std::size_t offset, std::uint64_t value, std::size_t width) {
                    for (std::size_t i = 0; i < width; ++i) altered[offset + i] = static_cast<std::byte>(value >> (i * 8));
                };
                if (control == 0) altered[0] ^= std::byte{1};
                if (control == 1) set(0x408, 1, 8);
                if (control == 2) set(0x410, 0x40000003, 4);
                if (control == 3) set(0x108, 8, 8);
                if (control) set(0, *c::Fletcher64(altered.data() + 8, altered.size() - 8), 8);
                PristineObjectOverlay candidate(*source, block, std::move(altered));
                Check(!c::LoadApplePlainTransitionVolumeView(candidate, *old, error),
                    "PlainTransitionReadRefusesActiveUnknownEncryptedOrCorruptTuple");
            }
        }
        std::cout << "{\"plainHistoricalXid\":" << xid << ",\"checkpointPresent\":" << (old ? "true" : "false")
            << ",\"fsOids\":" << (old ? old->superblock.fs_oids.size() : 0) << ",\"volumes\":" << (view ? view->volumes.size() : 0)
            << ",\"fsFlags\":" << (view && !view->volumes.empty() ? view->volumes.front().superblock.fs_flags : ~0ull) << "}\n";
    }
    std::vector<c::BtreeRecord> records;
    Check(c::ReadAppleVolumeFileSystemRecords(*source, cp->container, cp->volumes.front(), records, error),
        "PristineCanonicalWholeFileSystem");
    std::map<std::uint64_t, std::size_t> record_types;
    for (const auto& row : records) ++record_types[c::ReadU64LE(row.key, 0).value_or(0) >> 60];
    for (const auto& [type, count] : record_types)
        std::cout << "{\"pristineRecordType\":" << type << ",\"count\":" << count << "}\n";
    for (const auto& row : records) if (c::ReadU64LE(row.key, 0).value_or(0) >> 60 == 3) {
        r::AppleInodeRecord inode;
        Check(r::ApfsExtendedRecordCodec::DecodeInodeReadOnly(row, inode, error), "PristineReadProfileObservation");
        std::cout << "{\"pristineInode\":" << inode.object_id << ",\"mode\":" << inode.mode << ",\"internalFlags\":" << inode.internal_flags
            << ",\"bsdFlags\":" << inode.bsd_flags << ",\"extendedTypes\":[";
        bool first = true;
        for (const auto& field : inode.extended_fields) { if (!first) std::cout << ','; std::cout << unsigned(field.type); first = false; }
        std::cout << "]}\n";
    }
    for (const auto& row : records) {
        const auto key = c::ReadU64LE(row.key, 0).value_or(0);
        if (key >> 60 == 6) std::cout << "{\"plainStreamId\":" << (key & 0x0FFFFFFFFFFFFFFFULL)
            << ",\"references\":" << c::ReadU32LE(row.value, 0).value_or(~0u) << "}\n";
        if (key >> 60 == 3 && (key & 0x0FFFFFFFFFFFFFFFULL) == 23) {
            r::AppleInodeRecord inode;
            Check(r::ApfsExtendedRecordCodec::DecodeInodeReadOnly(row, inode, error), "PristineAttributeOwnerObservation");
            std::cout << "{\"attributeOwner\":23,\"privateId\":" << inode.private_id << ",\"mode\":" << inode.mode
                << ",\"bsdFlags\":" << inode.bsd_flags << "}\n";
        }
    }
    for (const auto& row : records) if (c::ReadU64LE(row.key, 0).value_or(0) >> 60 == 4) {
        r::AppleXattrRecord attribute;
        Check(r::ApfsExtendedRecordCodec::DecodeXattr(row, attribute, error), "PristineCanonicalXattrObservation");
        if ((attribute.flags & r::kAppleXattrDataStream) != 0)
            std::cout << "{\"externalAttributeOwner\":" << attribute.object_id << ",\"name\":\"" << attribute.name_utf8
                << "\",\"stream\":" << c::ReadU64LE(attribute.data, 0).value_or(0)
                << ",\"size\":" << c::ReadU64LE(attribute.data, 8).value_or(0)
                << ",\"allocated\":" << c::ReadU64LE(attribute.data, 16).value_or(0)
                << ",\"crypto\":" << c::ReadU64LE(attribute.data, 24).value_or(0) << "}\n";
    }
    for (const auto& row : records) if (c::ReadU64LE(row.key, 0).value_or(0) >> 60 == 7) {
        std::cout << "{\"plainCryptoObject\":" << (c::ReadU64LE(row.key, 0).value_or(0) & ((1ull << 60) - 1))
            << ",\"valueBytes\":" << row.value.size() << ",\"referenceCount\":" << c::ReadU32LE(row.value, 0).value_or(~0u)
            << ",\"statePrefix\":\"";
        constexpr char hex[] = "0123456789abcdef";
        for (const auto byte : std::span<const std::byte>(row.value).first((std::min)(row.value.size(), std::size_t{24}))) {
            const auto value = std::to_integer<unsigned>(byte); std::cout << hex[value >> 4] << hex[value & 15];
        }
        std::cout << "\",\"valueSha256\":\"" << Digest(row.value) << "\"}\n";
    }
    struct File { std::uint64_t id, stream, size; }; std::vector<File> files;
    for (const auto& row : records) if (c::ReadU64LE(row.key, 0).value_or(0) >> 60 == 3) {
        r::AppleInodeRecord inode;
        Check(r::ApfsExtendedRecordCodec::DecodeInodeReadOnly(row, inode, error), "PristineCanonicalInode");
        bool stream_seen = false;
        for (const auto& field : inode.extended_fields) if (field.type == 8) {
            r::AppleDataStreamRecord stream;
            Check(r::ApfsExtendedRecordCodec::DecodeDataStream(field, stream, error) && stream.default_crypto_id == 0 &&
                stream.size <= 64 * 4096, "PristinePlainCompleteDataStream");
            files.push_back({inode.object_id, inode.private_id, stream.size});
            stream_seen = true;
        }
        if (!stream_seen && (inode.mode & 0170000) == 0100000) files.push_back({inode.object_id, inode.private_id, 0});
    }
    Check(files.size() == 7, "PristineGenuineCompleteSevenFileInventory");
    std::ofstream out(run / L"expected-files.txt"); out << "E06FILES1\n" << files.size() << '\n';
    for (const auto& file : files) {
        auto plain = Locked(static_cast<std::size_t>((std::max)(file.size, 1ull))); std::uint64_t covered = 0;
        for (const auto& row : records) if (c::ReadU64LE(row.key, 0).value_or(0) >> 60 == 8) {
            r::AppleFileExtentRecord extent;
            Check(r::DecodeAppleFileExtentRecord(row, 4096, extent, error), "PristineCanonicalPlainExtent");
            if (extent.object_id != file.stream) continue;
            Check(extent.logical_address == covered && !extent.crypto_id && covered < file.size,
                "PristineDensePlainPayloadInventory");
            const auto count = static_cast<std::size_t>((std::min)(extent.length_bytes, file.size - covered));
            std::vector<std::byte> bytes;
            Check(source->Read(extent.physical_block * 4096, count, bytes) && bytes.size() == count,
                "PristineOriginalCompletePlainPayload");
            std::copy(bytes.begin(), bytes.end(), plain.Bytes().begin() + static_cast<std::ptrdiff_t>(covered));
            SecureZeroMemory(bytes.data(), bytes.size()); covered += count;
        }
        Check(covered == file.size, "PristineCompleteOriginalPayloadCoverage");
        out << file.id << ' ' << file.size << ' ' << Digest(plain.Bytes().first(static_cast<std::size_t>(file.size))) << '\n';
    }
    Check(static_cast<bool>(out), "PristineNonsecretOriginalHashManifest");
    std::vector<r::AppleXattrRecord> attributes;
    for (const auto& row : records) if (c::ReadU64LE(row.key, 0).value_or(0) >> 60 == 4) {
        r::AppleXattrRecord attribute;
        Check(r::ApfsExtendedRecordCodec::DecodeXattr(row, attribute, error) &&
            attribute.name_utf8.find_first_of(" \t\r\n") == std::string::npos, "PristineWholeAttributeInventory");
        if (attribute.flags & r::kAppleXattrDataStream) {
            const auto stream = c::ReadU64LE(attribute.data, 0).value_or(0), size = c::ReadU64LE(attribute.data, 8).value_or(0);
            unsigned extents = 0; std::vector<std::byte> bytes;
            for (const auto& extent_row : records) if (c::ReadU64LE(extent_row.key, 0).value_or(0) >> 60 == 8 &&
                (c::ReadU64LE(extent_row.key, 0).value_or(0) & 0x0FFFFFFFFFFFFFFFULL) == stream) {
                r::AppleFileExtentRecord extent;
                Check(r::DecodeAppleFileExtentRecord(extent_row, 4096, extent, error) && !extent.logical_address &&
                    !extent.crypto_id && size <= extent.length_bytes && size <= 1024 &&
                    source->Read(extent.physical_block * 4096, static_cast<std::size_t>(size), bytes) && bytes.size() == size,
                    "PristineActualExternalAttributeBytes"); ++extents;
            }
            Check(extents == 1, "PristineWholeAttributeCoverage"); attribute.data = std::move(bytes);
        }
        attributes.push_back(std::move(attribute));
    }
    std::ofstream attrs(run / L"expected-attributes.txt"); attrs << "E06ATTR1\n" << attributes.size() << '\n';
    for (const auto& attribute : attributes)
        attrs << attribute.object_id << ' ' << attribute.name_utf8 << ' ' << attribute.data.size() << ' ' << Digest(attribute.data) << '\n';
    Check(static_cast<bool>(attrs), "PristineWholeAttributeHashManifest");
}

int PristineRuntimeStep(const std::filesystem::path& run, unsigned step)
{
    auto password = Receive(); std::string error; c::EncryptedImageRuntime::Options options;
    options.image = {(run / pristine_name).wstring(), 0, 4153344, 1026};
    options.recovery_directory = run / L"runtime"; options.payload_bytes = 1ull << 20;
    auto runtime = c::EncryptedImageRuntime::Open(options, error);
    Check(static_cast<bool>(runtime), ("PristinePublicRuntimeOpen:" + error).c_str());
    c::PasswordUnlockBudget budget;
    if (!step) {
        const auto encrypted = runtime->Encrypt(password, budget, error);
        Check(encrypted, ("PristinePublicFirstEncryption:" + error).c_str());
    } else if (step == 1) {
        const auto unlocked = runtime->Unlock(password, budget, error);
        Check(unlocked, ("PristineFreshNewPasswordUnlock:" + error).c_str());
        std::vector<std::byte> payload(22, std::byte{0x6B}); std::size_t completed = 0;
        const auto written = runtime->Write(19, 0, payload, completed, error);
        Check(written && completed == payload.size(),
            ("PristineFreshFollowingDataWrite:" + error).c_str());
    } else {
        const auto decrypted = runtime->Decrypt(password, budget, error);
        Check(decrypted, ("PristinePublicFinalDecryption:" + error).c_str());
    }
    password.Clear(); const auto status = runtime->CachedStatus();
    Check(status.image.checkpoint_xid == 5 + step && !status.recovery_required && !status.image.recovery_required &&
        status.accepted && status.accepted == status.durable && status.durable == status.cleaned &&
        runtime->CachedPersistenceStateValid(), "PristinePublicOperationExactCleanEndpoint");
    if (step != 1) Check(!status.image.key_present && status.image.phase == c::EncryptedImageWritePhase::Locked,
        "PristineTransitionRevokesReaderAndKey");
    runtime->Close();
    std::cout << "{\"pristinePublicStep\":" << step << ",\"checkpoint\":" << 5 + step << ",\"accepted\":"
        << status.accepted << ",\"allClean\":true}\n"; return 0;
}

int PristineEncryptionDriver(const std::filesystem::path& executable, const std::filesystem::path& run)
{
    Check(run.wstring().starts_with(std::wstring(transition_root) + L"\\run-") && std::filesystem::create_directory(run),
        "PristinePrivateRun");
    const auto original = std::filesystem::path(fixtures) / pristine_name;
    Check(DigestFile(original) == pristine_pin && CopyFileW(original.c_str(), (run / pristine_name).c_str(), TRUE),
        "PristinePreserveAuthenticPlainOriginal");
    PristineInventory(run); auto password = RandomCredential(), wrong = RandomCredential();
    Check(Child(executable, L"pristine-plain-oracle " + Quoted(run), {}, run / L"before-plain-oracle.log") == 0,
        "PristineIndependentOriginalWholeFiles");
    Check(Child(executable, L"pristine-runtime-encrypt " + Quoted(run), password.Bytes(), run / L"first-encrypt.log") == 0,
        "PristineActualPublicFirstEncryption");
    Check(Child(executable, L"pristine-new-oracle " + Quoted(run), password.Bytes(), run / L"first-new-oracle.log") == 0 &&
        Child(executable, L"pristine-wrong-oracle " + Quoted(run), wrong.Bytes(), run / L"first-wrong-oracle.log") == 0,
        "PristineIndependentFirstNewPasswordAndWrongRefusal");
    {
        std::ifstream before(run / L"expected-files.txt"); std::ofstream after(run / L"expected-after-write.txt");
        std::string magic; std::size_t count = 0; before >> magic >> count; after << magic << '\n' << count << '\n';
        const std::vector<std::byte> payload(22, std::byte{0x6B}); bool selected = false;
        for (std::size_t i = 0; i < count; ++i) {
            ExpectedFile file; before >> file.inode >> file.bytes >> file.sha256;
            if (file.inode == 19) { Check(file.bytes == payload.size(), "PristineActualSelectedFileSize"); selected = true; }
            after << file.inode << ' ' << file.bytes << ' ' << (file.inode == 19 ? Digest(payload) : file.sha256) << '\n';
        }
        Check(before && after && selected, "PristineExactChangedAndUnchangedManifest");
    }
    Check(Child(executable, L"pristine-runtime-data " + Quoted(run), password.Bytes(), run / L"following-data.log") == 0,
        "PristineActualFreshNewPasswordData");
    Check(Child(executable, L"pristine-data-oracle " + Quoted(run), password.Bytes(), run / L"following-data-oracle.log") == 0,
        "PristineIndependentChangedAndUnchangedEncryptedFiles");
    Check(Child(executable, L"pristine-runtime-decrypt " + Quoted(run), password.Bytes(), run / L"final-decrypt.log") == 0 &&
        Child(executable, L"pristine-final-oracle " + Quoted(run), {}, run / L"final-plain-oracle.log") == 0,
        "PristineActualDecryptAndIndependentFinalFiles");
    for (const auto& file : std::filesystem::recursive_directory_iterator(run)) if (file.is_regular_file())
        Absent(file.path(), password.Bytes(), wrong.Bytes());
    Check(DigestFile(original) == pristine_pin, "PristineOriginalPinAfterCompleteSequence");
    std::cout << "PRISTINE_PUBLIC_ENCRYPT_DATA_DECRYPT_PASS\n"; return 0;
}
}
