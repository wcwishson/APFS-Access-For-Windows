#define APFS_KEYBAG_ERA_MAIN TransitionInheritedMain
#include "EncryptedKeybagEraTests.cpp"
#include "ApfsExtendedRecordCodec.h"
#include <map>

namespace
{
struct TransitionRows
{
    std::vector<c::BtreeRecord> rows;
    ~TransitionRows() { for (auto& row : rows) { SecureZeroMemory(row.key.data(), row.key.size()); SecureZeroMemory(row.value.data(), row.value.size()); } }
};
int TransitionProfile(const std::filesystem::path& image, bool encrypted)
{
    Check(image.wstring().starts_with(L"D:\\ApfsAccessScratch\\WindowsClosure\\software-volume-transition-20261017\\run-"),
        "TransitionPrivateImageRequired");
    const auto pin = encrypted ? Profile{false}.Pin() : "e3e3adcbbf189403d892b013d6cba155f2e58e42ff5eb541ec681c37a91a3f29";
    Check(DigestFile(image) == pin, "TransitionAuthenticFixturePin");
    auto lease = std::make_shared<t::WindowsImageLease>(image.wstring());
    auto source = std::make_shared<t::OwnedEncryptedImageSource>(lease, encrypted ? 20480 : 0, 4153344);
    std::string error;
    std::unique_ptr<c::ApfsEncryptedReadSession> session;
    std::unique_ptr<c::AppleEncryptedMetadataReadContext> context;
    if (encrypted) {
        auto password = Receive(); session = UnlockEra(source, password.Bytes()); password.Clear();
        c::EncryptedReadError status{}; context = session->CreateMetadataReadContext(status);
        Check(static_cast<bool>(context), "TransitionPrivateReadContext");
    }
    auto view = encrypted ? c::LoadAppleCheckpointView(*source, 0, 4153344, error, *context) :
        c::LoadAppleCheckpointView(*source, 0, 4153344, error);
    Check(view && view->volumes.size() == 1, ("TransitionCurrentFullAllocator:" + error).c_str());
    const auto& cp = view->container; const auto& volume = view->volumes.front();
    Check(volume.superblock.object_id == 1026 && volume.superblock.fs_flags == (encrypted ? 8 : 1) &&
        volume.extentref_tree && !volume.file_extent_tree && !volume.object_map.snapshot_tree_oid,
        "TransitionObservedProfile");
    TransitionRows fs, refs, omap;
    const bool read = encrypted ? c::ReadAppleVolumeFileSystemRecords(*source, cp, volume, fs.rows, error, *context) :
        c::ReadAppleVolumeFileSystemRecords(*source, cp, volume, fs.rows, error);
    Check(read, ("TransitionWholeFilesystem:" + error).c_str());
    const auto tree = [&](const c::AppleObjectLocation& location, TransitionRows& output) {
        c::BtreeReadPolicy policy; policy.enforce_object_identity = true; policy.require_complete_traversal = true;
        policy.reject_unsupported_flags = true; policy.root_object_id = location.object_id;
        policy.storage_type = location.type; policy.subtype = location.subtype;
        return c::ReadBtreeLeafRecords(*source, 4096, location.physical_block, true, 0, cp.superblock.xid,
            policy, output.rows, error);
    };
    Check(tree(*volume.extentref_tree, refs) && tree(volume.object_map.tree, omap), "TransitionCompleteOwnershipTrees");
    std::vector<r::ApplePhysicalExtentRecord> extents;
    bool graph = encrypted ? r::ValidateAppleEncryptedPayloadExtentGraph(fs.rows, refs.rows, 4096,
        cp.superblock.block_count, extents, error) : r::ValidateApplePayloadExtentGraph(fs.rows, refs.rows, 4096,
        cp.superblock.block_count, extents, error);
    std::size_t observational_envelopes = 0;
    if (!graph && !encrypted && error == "AppleExtendedFieldSizeInvalid") {
        TransitionRows semantic; semantic.rows = fs.rows;
        for (auto& row : semantic.rows) if (c::ReadU64LE(row.key, 0).value_or(0) >> 60 == 3) {
            r::AppleInodeRecord inode, roundtrip;
            Check(r::ApfsExtendedRecordCodec::DecodeInodeReadOnly(row, inode, error), "TransitionObservationalInode");
            c::BtreeRecord canonical;
            Check(r::EncodeAppleInodeRecord(inode, canonical, error) &&
                r::ApfsExtendedRecordCodec::DecodeInode(canonical, roundtrip, error) && canonical.key == row.key &&
                canonical.value.size() >= 0x5c && std::equal(row.value.begin(), row.value.begin() + 0x5c, canonical.value.begin()) &&
                inode.extended_fields.size() == roundtrip.extended_fields.size() &&
                std::equal(inode.extended_fields.begin(), inode.extended_fields.end(), roundtrip.extended_fields.begin(),
                    [](const auto& a, const auto& b) { return a.type == b.type && a.flags == b.flags && a.data == b.data; }),
                "TransitionLosslessInodeSemanticProjection");
            if (canonical.value != row.value) ++observational_envelopes;
            row = std::move(canonical);
            for (auto* decoded : {&inode, &roundtrip}) for (auto& field : decoded->extended_fields)
                SecureZeroMemory(field.data.data(), field.data.size());
        }
        graph = r::ValidateApplePayloadExtentGraph(semantic.rows, refs.rows, 4096, cp.superblock.block_count, extents, error);
    }
    const std::string graph_error = graph ? std::string{} : error;
    std::map<unsigned, std::size_t> types;
    std::set<std::uint64_t> crypto, streams;
    std::vector<r::AppleFileExtentRecord> observed_extents;
    std::uint64_t payload_blocks = 0;
    if (graph) for (const auto& extent : extents) {
        Check(extent.reference_count == 1 && extent.block_count <= 64, "TransitionExclusiveBoundedPayload");
        payload_blocks += extent.block_count;
    }
    for (const auto& row : fs.rows) {
        const auto type = static_cast<unsigned>(c::ReadU64LE(row.key, 0).value_or(0) >> 60); ++types[type];
        if (type == 8) {
            r::AppleFileExtentRecord extent;
            if (encrypted) {
                r::AppleEncryptedFileExtentRecord encoded;
                Check(r::DecodeAppleEncryptedFileExtentRecord(row, 4096, r::AppleEncryptedExtentProfile::OneKeyGenerationZero,
                    encoded, error), "TransitionEncryptedExtentCodec"); extent = encoded.extent;
            } else Check(r::DecodeAppleFileExtentRecord(row, 4096, extent, error), "TransitionPlainExtentCodec");
            crypto.insert(extent.crypto_id);
            observed_extents.push_back(extent);
        }
        if (type == 3) {
            r::AppleInodeRecord inode;
            Check(r::ApfsExtendedRecordCodec::DecodeInodeReadOnly(row, inode, error), "TransitionCanonicalInodeCodec");
            for (auto& field : inode.extended_fields) {
                if (field.type == 8) {
                    r::AppleDataStreamRecord stream;
                    Check(r::ApfsExtendedRecordCodec::DecodeDataStream(field, stream, error), "TransitionCanonicalStreamCodec");
                    streams.insert(stream.default_crypto_id);
                }
                SecureZeroMemory(field.data.data(), field.data.size());
            }
        }
    }
    std::set<std::uint32_t> mapping_flags;
    for (const auto& row : omap.rows) mapping_flags.insert(c::ReadU32LE(row.value, 0).value_or(~0u));
    std::vector<std::byte> apsb;
    Check(source->Read(volume.superblock_object.physical_block * 4096, 4096, apsb), "TransitionApsbObservation");
    std::cout << "{\"encrypted\":" << (encrypted ? "true" : "false") << ",\"xid\":" << cp.superblock.xid
        << ",\"fsFlags\":" << volume.superblock.fs_flags << ",\"nxFlags\":" << c::ReadU64LE(cp.superblock_bytes, 0x4F0).value_or(~0ull)
        << ",\"metaMajor\":" << c::ReadU16LE(apsb, 0x60).value_or(0) << ",\"metaMinor\":" << c::ReadU16LE(apsb, 0x62).value_or(0)
        << ",\"metaFlags\":" << c::ReadU32LE(apsb, 0x64).value_or(0) << ",\"metaClass\":" << c::ReadU32LE(apsb, 0x68).value_or(0)
        << ",\"metaOsVersion\":" << c::ReadU32LE(apsb, 0x6C).value_or(0) << ",\"metaRevision\":" << c::ReadU16LE(apsb, 0x70).value_or(0)
        << ",\"erStateOid\":" << c::ReadU64LE(apsb, 0x3D0).value_or(0) << ",\"payloadBlocks\":" << payload_blocks
        << ",\"filesystemRecords\":" << fs.rows.size() << ",\"cryptoStateRecords\":" << types[7]
        << ",\"losslessObservedInodeEnvelopes\":" << observational_envelopes << ",\"extentCryptoIds\":[";
    bool separator = false; for (auto id : crypto) { if (separator) std::cout << ','; separator = true; std::cout << id; }
    std::cout << "],\"streamCryptoIds\":["; separator = false;
    for (auto id : streams) { if (separator) std::cout << ','; separator = true; std::cout << id; }
    std::cout << "],\"omapFlags\":["; separator = false;
    for (auto flags : mapping_flags) { if (separator) std::cout << ','; separator = true; std::cout << flags; }
    std::cout << "],\"ownerMismatches\":["; separator = false;
    for (const auto& row : refs.rows) {
        r::ApplePhysicalExtentRecord extent;
        Check(r::DecodeApplePhysicalExtentRecord(row, extent, error), "TransitionObservedPhysicalExtentCodec");
        if (extent.reference_count != 1) continue;
        for (const auto& use : observed_extents) {
            if (!use.physical_block || use.physical_block < extent.physical_block ||
                use.physical_block - extent.physical_block >= extent.block_count || use.object_id == extent.owning_object_id) continue;
            if (separator) std::cout << ','; separator = true;
            std::cout << "{\"streamOwner\":" << use.object_id << ",\"physicalBlock\":" << use.physical_block
                << ",\"referenceOwner\":" << extent.owning_object_id << ",\"referenceCount\":1}";
        }
    }
    std::cout << "],\"payloadGraphAdmitted\":" << (graph ? "true" : "false") << ",\"payloadGraphError\":" << std::quoted(graph_error)
        << ",\"fullCurrentAllocatorValidated\":true,\"publicationAuthority\":false}\n";
    if (session) session->Close();
    Check(DigestFile(image) == pin, "TransitionReadOnlyOriginalBytes"); return 0;
}
int TransitionDriver(const std::filesystem::path& executable, const std::filesystem::path& run)
{
    Check(std::filesystem::create_directory(run), "TransitionFreshPrivateRun");
    for (bool encrypted : {false, true}) {
        const auto name = encrypted ? Profile{false}.Name() : L"dfvfs-plain-apfs.raw";
        const auto image = run / name, original = std::filesystem::path(fixtures) / name;
        Check(CopyFileW(original.c_str(), image.c_str(), TRUE), "TransitionPrivateFixtureCopy");
        auto password = encrypted ? NoteCredential(Profile{false}) : k::SecureBytes{};
        const auto code = Child(executable, L"transition-profile " + Quoted(image) + (encrypted ? L" encrypted" : L" plain"),
            password.Bytes(), run / (encrypted ? L"encrypted-profile.log" : L"plain-profile.log"));
        password.Clear(); Check(code == 0, "TransitionActualProfileChild");
    }
    std::cout << "TRANSITION_PROFILE_PASS\n"; return 0;
}
}
int wmain(int argc, wchar_t** argv)
{
    try {
        if (argc == 4 && std::wstring_view(argv[1]) == L"transition-profile") return TransitionProfile(argv[2], std::wstring_view(argv[3]) == L"encrypted");
        if (argc == 3 && std::wstring_view(argv[1]) == L"drive-transition-profile") return TransitionDriver(argv[0], argv[2]);
        return TransitionInheritedMain(argc, argv);
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
