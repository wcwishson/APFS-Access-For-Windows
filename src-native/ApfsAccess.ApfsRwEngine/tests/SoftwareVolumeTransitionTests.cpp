#define APFS_KEYBAG_ERA_MAIN TransitionInheritedMain
#include "EncryptedKeybagEraTests.cpp"
#include "SoftwareVolumeTransition.h"
#include "AppleVolumeTransaction.h"
#include "ApfsExtendedRecordCodec.h"

namespace
{
constexpr wchar_t transition_root[] = L"D:\\ApfsAccessScratch\\WindowsClosure\\software-volume-transition-20261017";
std::string OwnerIdentity(const BY_HANDLE_FILE_INFORMATION& id)
{
    return "image-writer-v1:" + std::to_string(id.dwVolumeSerialNumber) + ":" +
        std::to_string((std::uint64_t(id.nFileIndexHigh) << 32) | id.nFileIndexLow) + ":" +
        std::to_string((std::uint64_t(id.nFileSizeHigh) << 32) | id.nFileSizeLow) + ":20480:4153344";
}
class TransitionSource final : public c::ImmutableEncryptedReadSource
{
public:
    std::shared_ptr<t::WindowsImageLease> lease;
    std::string identity;
    std::shared_ptr<c::ApfsReadBudget> budget = std::make_shared<c::ApfsReadBudget>(100000, 256ull << 20, 1000000, 256ull << 20);
    explicit TransitionSource(const std::filesystem::path& path) : lease(std::make_shared<t::WindowsImageLease>(path.wstring()))
    {
        Handle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        BY_HANDLE_FILE_INFORMATION id{};
        Check(file.h != INVALID_HANDLE_VALUE && GetFileInformationByHandle(file.h, &id) && FileIdentity(id) == lease->Identity(),
            "TransitionSameHeldFileIdentity"); identity = OwnerIdentity(id);
    }
    std::string SourceIdentity() const override { return identity; }
    std::uint64_t Revision() const override { return 1; }
    std::uint64_t SizeBytes() const override { return 4153344; }
    std::shared_ptr<c::ApfsReadBudget> ReadBudget() const override { return budget; }
    bool Read(std::uint64_t offset, std::size_t size, std::vector<std::byte>& out) const override
    {
        out.clear();
        return offset <= 4153344 && size <= 4153344 - offset && lease->VerifyUnchanged() && budget->Read(size) &&
            lease->Read(20480 + offset, size, out) && lease->VerifyUnchanged();
    }
};
class TransitionTarget final : public r::AppleCheckpointWriteTarget
{
    Handle file_;
public:
    std::size_t writes = 0, flushes = 0;
    TransitionTarget(const std::filesystem::path& path, std::string_view expected) : file_(INVALID_HANDLE_VALUE)
    {
        Check(path.wstring().starts_with(std::wstring(transition_root) + L"\\run-"), "TransitionPrivateTarget");
        for (unsigned attempt = 0; attempt < 20; ++attempt) {
            file_.h = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_RANDOM_ACCESS, nullptr);
            if (file_.h != INVALID_HANDLE_VALUE || GetLastError() != ERROR_SHARING_VIOLATION) break;
            Sleep(50);
        }
        BY_HANDLE_FILE_INFORMATION id{};
        Check(file_.h != INVALID_HANDLE_VALUE && GetFileType(file_.h) == FILE_TYPE_DISK && GetFileInformationByHandle(file_.h, &id) &&
            !(id.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DEVICE)) &&
            OwnerIdentity(id) == expected, "TransitionExactExclusiveTarget");
    }
    bool ReadBlock(std::uint64_t block, std::uint32_t size, std::vector<std::byte>& out) override
    {
        out.clear(); if (size != 4096 || block >= 4153344 / 4096) return false;
        LARGE_INTEGER at{}; at.QuadPart = static_cast<LONGLONG>(20480 + block * 4096); DWORD read = 0; out.resize(4096);
        return SetFilePointerEx(file_.h, at, nullptr, FILE_BEGIN) && ::ReadFile(file_.h, out.data(), 4096, &read, nullptr) && read == 4096;
    }
    bool WriteBlock(std::uint64_t block, Bytes bytes) override
    {
        if (bytes.size() != 4096 || block >= 4153344 / 4096) return false;
        LARGE_INTEGER at{}; at.QuadPart = static_cast<LONGLONG>(20480 + block * 4096); DWORD written = 0;
        const bool ok = SetFilePointerEx(file_.h, at, nullptr, FILE_BEGIN) && WriteFile(file_.h, bytes.data(), 4096, &written, nullptr) && written == 4096;
        if (ok) ++writes; return ok;
    }
    bool Flush() override { ++flushes; return FlushFileBuffers(file_.h) != FALSE; }
};
struct ExpectedFile { std::uint64_t inode = 0, bytes = 0; std::string sha256; };
void RetentionControls(const std::filesystem::path& image, const std::filesystem::path& copied,
    const c::SoftwareVolumeTransitionPublication& prepared, const std::array<std::byte, 32>& jid)
{
    std::string error; std::vector<c::SoftwareVolumeOwnedRange> exclusions;
    {
        auto other = std::make_shared<TransitionSource>(copied);
        Check(!prepared.RetainedOwners().Revalidate(*other, jid, exclusions, error) && exclusions.empty(), "TransitionCopiedFileCertificateRefused");
    }
    const auto& generation = prepared.RetainedOwners().Generations().front();
    const auto payload = std::find_if(generation.ranges.begin(), generation.ranges.end(), [](const auto& range) {
        return range.kind == c::SoftwareVolumeOwnerKind::Payload;
    });
    Check(payload != generation.ranges.end() && payload->block_count == 1, "TransitionNegativeHistoricalPayloadAvailable");
    const auto guard = std::find_if(generation.graph_guards.begin(), generation.graph_guards.end(), [&](const auto& item) {
        return item.physical_block == payload->start_block;
    });
    Check(guard != generation.graph_guards.end(), "TransitionNegativeHistoricalRawFrameAvailable");
    const auto initial = DigestFile(image);
    auto changed = guard->bytes; changed.back() ^= std::byte{1};
    {
        TransitionTarget target(image, prepared.SourceIdentity());
        Check(target.WriteBlock(guard->physical_block, changed) && target.Flush(), "TransitionSetRetainedRawFault");
    }
    const auto fault = DigestFile(image);
    {
        auto source = std::make_shared<TransitionSource>(image);
        Check(!prepared.RetainedOwners().Revalidate(*source, jid, exclusions, error) && exclusions.empty() &&
            error == "SoftwareTransitionRetentionRawGuardChanged", "TransitionChangedRetainedRawRefused");
    }
    Check(DigestFile(image) == fault, "TransitionRawRefusalMakesNoWrites");
    {
        TransitionTarget target(image, prepared.SourceIdentity());
        Check(target.WriteBlock(guard->physical_block, guard->bytes) && target.Flush(), "TransitionRestoreRetainedRawFault");
    }
    std::uint64_t bitmap_block = 0, bitmap_bit = 0; std::vector<std::byte> bitmap;
    {
        auto source = std::make_shared<TransitionSource>(image);
        auto cp = c::LoadAppleCheckpointView(*source, 0, source->SizeBytes(), error);
        Check(static_cast<bool>(cp), "TransitionNegativeFullCurrentAllocatorAvailable");
        for (const auto& chunk : cp->spaceman.chunks) if (payload->start_block >= chunk.start_block && payload->start_block - chunk.start_block < chunk.block_count) {
            bitmap_block = chunk.bitmap_block; bitmap_bit = payload->start_block - chunk.start_block; bitmap = chunk.allocation_bitmap;
        }
        Check(bitmap_block && bitmap.size() == 4096 && bitmap_bit / 8 < bitmap.size(), "TransitionNegativeBitmapFrameAvailable");
    }
    changed = bitmap; changed[static_cast<std::size_t>(bitmap_bit / 8)] &= ~static_cast<std::byte>(1u << (bitmap_bit % 8));
    {
        TransitionTarget target(image, prepared.SourceIdentity());
        Check(target.WriteBlock(bitmap_block, changed) && target.Flush(), "TransitionSetCurrentAllocatorFault");
    }
    const auto allocation_fault = DigestFile(image);
    {
        auto source = std::make_shared<TransitionSource>(image);
        Check(!prepared.RetainedOwners().Revalidate(*source, jid, exclusions, error) && exclusions.empty(), "TransitionCurrentAllocatorFaultRefused");
    }
    Check(DigestFile(image) == allocation_fault, "TransitionAllocatorRefusalMakesNoWrites");
    {
        TransitionTarget target(image, prepared.SourceIdentity());
        Check(target.WriteBlock(bitmap_block, bitmap) && target.Flush(), "TransitionRestoreCurrentAllocatorFault");
    }
    Check(DigestFile(image) == initial, "TransitionExactImageRestoredAfterNegativeControls");
    std::cout << "{\"retainedRawTamperRefused\":true,\"currentAllocatorTamperRefused\":true,\"copiedFileRefused\":true,\"refusalWrites\":0,\"faultSetupFullyRestored\":true}\n";
}
void PlainPlannerProbe(const std::filesystem::path& image, const c::SoftwareVolumeTransitionPublication& prepared,
    const std::array<std::byte, 32>& jid)
{
    const auto before = DigestFile(image); std::string error;
    std::vector<c::SoftwareVolumeOwnedRange> exclusions;
    r::AppleVolumeTransactionPlan planned;
    bool admitted = false, disjoint = false;
    {
        auto source = std::make_shared<TransitionSource>(image);
        Check(prepared.RetainedOwners().Revalidate(*source, jid, exclusions, error) && !exclusions.empty(), "TransitionOrdinaryPreAllocatorCertificateValidated");
        auto current = c::LoadAppleCheckpointView(*source, 0, source->SizeBytes(), error);
        std::vector<c::BtreeRecord> records;
        Check(current && current->volumes.size() == 1 && c::ReadAppleVolumeFileSystemRecords(*source, current->container,
            current->volumes.front(), records, error), "TransitionOrdinaryCurrentPlainRecords");
        r::AppleVolumeTransactionRequest request; request.volume_object_id = 1026; request.required_checkpoint_xids = {current->container.superblock.xid};
        std::uint64_t stream = 0;
        for (const auto& row : records) if (c::ReadU64LE(row.key, 0) == ((std::uint64_t{3} << 60) | 21)) {
            r::AppleInodeRecord inode;
            Check(r::ApfsExtendedRecordCodec::DecodeInodeReadOnly(row, inode, error), "TransitionOrdinarySourceInode"); stream = inode.private_id;
        }
        Check(stream != 0, "TransitionOrdinarySourcePrivateStream");
        for (const auto& row : records) {
            if ((c::ReadU64LE(row.key, 0).value_or(0) >> 60) == 8) {
                r::AppleFileExtentRecord extent;
                Check(r::DecodeAppleFileExtentRecord(row, 4096, extent, error), "TransitionOrdinarySourceExtent");
                if (extent.object_id == stream) {
                    request.released_data_blocks.push_back({extent.physical_block, extent.length_bytes / 4096}); continue;
                }
            }
            request.filesystem_records.push_back(row);
        }
        r::AppleVolumeDataWrite write; write.file_private_id = stream; write.bytes.assign(22, std::byte{0x5A});
        request.data_writes.push_back(std::move(write));
        admitted = r::PlanAppleVolumeTransaction(*source, *current, request, planned, error);
        if (admitted) {
            const auto intersects = [&](std::uint64_t first, std::uint64_t count) {
                return std::any_of(exclusions.begin(), exclusions.end(), [&](const auto& owner) {
                    return first < owner.start_block + owner.block_count && owner.start_block < first + count;
                });
            };
            disjoint = std::none_of(planned.commit.publication.before_superblock_writes.begin(), planned.commit.publication.before_superblock_writes.end(),
                [&](const auto& item) { return intersects(item.physical_block, 1); }) &&
                !intersects(planned.commit.publication.superblock_write.physical_block, 1) &&
                std::none_of(planned.allocation.deferred_frees.begin(), planned.allocation.deferred_frees.end(),
                    [&](const auto& item) { return intersects(item.physical_block, item.block_count); });
        }
    }
    Check(DigestFile(image) == before, "TransitionOrdinaryProbeNoTargetWrites");
    std::cout << "{\"ordinaryPlainPlannerProbe\":true,\"certificateValidatedBeforeAllocator\":true,\"plannerAdmitted\":" << (admitted ? "true" : "false")
        << ",\"ownerDestinationsAndRetirementsDisjoint\":" << (disjoint ? "true" : "false") << ",\"error\":\"" << error
        << "\",\"targetWrites\":0,\"ordinaryWritePublished\":false}\n";
}
int DecryptPrimitive(const std::filesystem::path& run, const std::filesystem::path& executable, bool roundtrip = false)
{
    const auto image = run / Profile{false}.Name();
    Check(DigestFile(image) == Profile{false}.Pin(), "TransitionAuthenticEncryptedInput");
    Credentials credentials;
    auto password = roundtrip ? k::SecureBytes{} : Receive(); std::string error;
    if (roundtrip) { credentials = ReceivePair(); password = std::move(credentials.old_password); }
    const auto jid = Binding("e06-private-transition-original-v6");
    std::vector<ExpectedFile> expected;
    std::unique_ptr<c::SoftwareVolumeTransitionPublication> prepared;
    {
        auto source = std::make_shared<TransitionSource>(image);
        c::UnlockError unlock{}; c::EncryptedReadError read{}; c::PasswordUnlockBudget baseline_budget;
        auto metadata = c::InspectPasswordKeybagMetadata(*source, 1026, c::KeybagLength::IncludesHeader, unlock);
        Check(metadata && metadata->users.size() == 1, "TransitionAuthenticCurrentSelection");
        auto selection = metadata->selection; selection.user_uuid = metadata->users.front();
        auto baseline = c::ApfsEncryptedReadSession::Unlock(source, source->SourceIdentity(), source->Revision(), selection,
            password.Bytes(), baseline_budget, read, unlock);
        Check(static_cast<bool>(baseline), "TransitionBaselineUnlockedReader");
        std::vector<c::EncryptedFileInfo> files;
        Check(baseline->ListFiles(files) == c::EncryptedReadError::None && !files.empty(), "TransitionBaselineWholeFileInventory");
        for (const auto& file : files) {
            std::vector<std::byte> plain;
            Check(file.size <= 64 * 4096 && baseline->ReadFile(file.inode_id, 0, static_cast<std::size_t>(file.size), plain) == c::EncryptedReadError::None,
                "TransitionBaselineWholePayload");
            expected.push_back({file.inode_id, file.size, Digest(plain)}); SecureZeroMemory(plain.data(), plain.size());
        }
        baseline->Close(); baseline.reset();
        c::PasswordUnlockBudget budget;
        prepared = c::SoftwareVolumeTransition::PrepareDecryption(source, source->SourceIdentity(), source->Revision(),
            1026, c::KeybagLength::IncludesHeader, password, budget, jid, error);
        Check(static_cast<bool>(prepared), ("TransitionDecryptionPreparation:" + error).c_str());
        Check(prepared->BeforeMode() == c::SoftwareVolumeMode::OneKeyGenerationZero && prepared->AfterMode() == c::SoftwareVolumeMode::Plain &&
            prepared->Publication().expected_checkpoint_xid == 7 && prepared->Publication().transaction_xid == 8 &&
            prepared->RetainedOwners().Generations().size() > 0, "TransitionSourceRootedPrivateCapability");
    }
    if (!roundtrip) password.Clear();
    {
        std::ofstream output(run / L"expected-files.txt"); output << "E06FILES1\n" << expected.size() << '\n';
        for (const auto& file : expected) output << file.inode << ' ' << file.bytes << ' ' << file.sha256 << '\n';
        Check(static_cast<bool>(output), "TransitionBaselineDigestManifest");
    }
    {
        TransitionTarget target(image, prepared->SourceIdentity());
        Check(r::ExecuteAppleCheckpointPublication(target, prepared->Publication(), error), ("TransitionCanonicalDecryption:" + error).c_str());
        Check(target.writes == prepared->Publication().before_superblock_writes.size() + 1 && target.flushes >= 2,
            "TransitionActualCanonicalWritesAndBarriers");
    }
    {
        auto source = std::make_shared<TransitionSource>(image);
        auto current = c::LoadAppleCheckpointView(*source, 0, source->SizeBytes(), error);
        Check(current && current->container.superblock.xid == 8 && current->volumes.size() == 1 &&
            current->volumes.front().superblock.fs_flags == 1 && c::ReadU64LE(current->container.superblock_bytes, 0x4F0) == 0,
            "TransitionFreshCanonicalPlainReopen");
        std::vector<c::SoftwareVolumeOwnedRange> exclusions;
        Check(prepared->RetainedOwners().Revalidate(*source, jid, exclusions, error) && !exclusions.empty(),
            ("TransitionActualOpaqueEncryptedRetention:" + error).c_str());
        Check(!prepared->RetainedOwners().RevalidateProtectedHistory(*source, jid, exclusions, error) && exclusions.empty() &&
            error == "SoftwareTransitionProtectedOwnerHistoryRequired", "TransitionStagedCertificateCannotAuthorizePlainAllocation");
        auto wrong = jid; wrong.front() ^= std::byte{1};
        Check(!prepared->RetainedOwners().Revalidate(*source, wrong, exclusions, error) && exclusions.empty(),
            "TransitionWrongOriginalJournalRefuses");
    }
    Check(CopyFileW(image.c_str(), (run / L"decrypted-postimage.dmg").c_str(), TRUE), "TransitionPreserveActualPlainImage");
    if (roundtrip) {
        RetentionControls(image, run / L"decrypted-postimage.dmg", *prepared, jid);
        PlainPlannerProbe(image, *prepared, jid);
        Check(Child(executable, L"transition-plain-oracle " + Quoted(run), {}, run / L"first-plain-oracle.log") == 0,
            "TransitionFirstIndependentPlainPayload");
        std::unique_ptr<c::SoftwareVolumeTransitionPublication> encrypted;
        {
            auto source = std::make_shared<TransitionSource>(image); c::PasswordUnlockBudget budget;
            encrypted = c::SoftwareVolumeTransition::PrepareEncryption(source, source->SourceIdentity(), source->Revision(),
                1026, credentials.new_password, budget, jid, &prepared->RetainedOwners(), error);
            Check(static_cast<bool>(encrypted), ("TransitionEncryptionPreparation:" + error).c_str());
            Check(encrypted->BeforeMode() == c::SoftwareVolumeMode::Plain && encrypted->AfterMode() == c::SoftwareVolumeMode::OneKeyGenerationZero &&
                encrypted->Publication().expected_checkpoint_xid == 8 && encrypted->Publication().transaction_xid == 9,
                "TransitionFreshLockedKeyPrivateCapability");
        }
        {
            TransitionTarget target(image, encrypted->SourceIdentity());
            Check(r::ExecuteAppleCheckpointPublication(target, encrypted->Publication(), error), ("TransitionCanonicalEncryption:" + error).c_str());
        }
        Check(CopyFileW(image.c_str(), (run / L"reencrypted-postimage.dmg").c_str(), TRUE), "TransitionPreserveActualEncryptedImage");
        Check(Child(executable, L"transition-encrypted-oracle " + Quoted(run), credentials.new_password.Bytes(), run / L"encrypted-new-oracle.log") == 0,
            "TransitionIndependentFreshPasswordAllPayloads");
        Check(Child(executable, L"transition-old-oracle " + Quoted(run), password.Bytes(), run / L"encrypted-old-oracle.log") == 0,
            "TransitionIndependentOriginalPasswordRefused");
        {
            auto source = std::make_shared<TransitionSource>(image); c::UnlockError unlock{}; c::EncryptedReadError read{};
            auto bags = c::InspectPasswordKeybagMetadata(*source, 1026, c::KeybagLength::IncludesHeader, unlock);
            Check(bags && bags->users.size() == 1, "TransitionFreshCanonicalBagInspection");
            auto selected = bags->selection; selected.user_uuid = bags->users.front();
            c::PasswordUnlockBudget old_budget;
            auto refused = c::ApfsEncryptedReadSession::Unlock(source, source->SourceIdentity(), source->Revision(), selected,
                password.Bytes(), old_budget, read, unlock);
            Check(!refused && unlock == c::UnlockError::CredentialOrKeyMismatch, "TransitionNativeOriginalPasswordRefused");
        }
        password.Clear();
        std::unique_ptr<c::SoftwareVolumeTransitionPublication> again;
        {
            auto source = std::make_shared<TransitionSource>(image); c::PasswordUnlockBudget budget;
            again = c::SoftwareVolumeTransition::PrepareDecryption(source, source->SourceIdentity(), source->Revision(), 1026,
                c::KeybagLength::IncludesHeader, credentials.new_password, budget, jid, error, {}, {}, &encrypted->RetainedOwners());
            Check(static_cast<bool>(again), ("TransitionSecondDecryptionPreparation:" + error).c_str());
        }
        credentials.new_password.Clear();
        {
            TransitionTarget target(image, again->SourceIdentity());
            Check(r::ExecuteAppleCheckpointPublication(target, again->Publication(), error), ("TransitionSecondCanonicalDecryption:" + error).c_str());
        }
        {
            auto source = std::make_shared<TransitionSource>(image);
            auto current = c::LoadAppleCheckpointView(*source, 0, source->SizeBytes(), error);
            std::vector<c::SoftwareVolumeOwnedRange> exclusions;
            Check(current && current->container.superblock.xid == 10 && current->volumes.front().superblock.fs_flags == 1 &&
                again->RetainedOwners().Revalidate(*source, jid, exclusions, error), "TransitionSecondPlainAndOpaqueEraProof");
        }
        Check(CopyFileW(image.c_str(), (run / L"second-decrypted-postimage.dmg").c_str(), TRUE), "TransitionPreserveSecondPlainImage");
        std::cout << "{\"canonicalTransitionPublications\":3,\"xid\":10,\"freshLockedKeys\":true,\"independentPayloadFiles\":" << expected.size()
            << ",\"oldPasswordRefused\":true,\"protectedJournalIntegrated\":false,\"plainWriteProved\":false,\"e06Complete\":false}\n";
        return 0;
    }
    std::cout << "{\"canonicalDecryptionPublications\":1,\"xid\":8,\"payloadFiles\":" << expected.size()
        << ",\"retainedEncryptedGenerations\":" << prepared->RetainedOwners().Generations().size()
        << ",\"opaqueOwnersRevalidated\":true,\"protectedJournalIntegrated\":false,\"e06Complete\":false}\n";
    return 0;
}
int PlainOracle(const std::filesystem::path& run, unsigned credential_mode = 0, bool after_plain_write = false,
    const wchar_t* inventory_name = nullptr, bool pristine_raw = false)
{
    auto password = credential_mode ? Receive() : k::SecureBytes{};
    Check(DigestFile(oracle) == "3d0d4b68e651506ec7fc0c06944f488a0e465bf35a067a9d91ebf3611fdbf83b", "TransitionOraclePin");
    HMODULE module = LoadLibraryExW(oracle, nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    Check(module != nullptr, "TransitionOracleLoad"); using P = void*;
    P error{}, handle{}, container{}, volume{};
    const auto image = run / (pristine_raw ? L"dfvfs-plain-apfs.raw" : Profile{false}.Name());
    Check(Export<int (*)(P*, P*)>(module, "libbfio_file_range_initialize")(&handle, &error) == 1 &&
        Export<int (*)(P, const wchar_t*, size_t, P*)>(module, "libbfio_file_range_set_name_wide")(handle, image.c_str(), image.wstring().size(), &error) == 1 &&
        Export<int (*)(P, int64_t, uint64_t, P*)>(module, "libbfio_file_range_set")(handle, pristine_raw ? 0 : 20480, 4153344, &error) == 1 &&
        Export<int (*)(P*, P*)>(module, "libfsapfs_container_initialize")(&container, &error) == 1 &&
        Export<int (*)(P, P, int, P*)>(module, "libfsapfs_container_open_file_io_handle")(container, handle, 1, &error) == 1 &&
        Export<int (*)(P, int, P*, P*)>(module, "libfsapfs_container_get_volume_by_index")(container, 0, &volume, &error) == 1 &&
        Export<int (*)(P, P*)>(module, "libfsapfs_volume_is_locked")(volume, &error) == (credential_mode ? 1 : 0), "TransitionIndependentCanonicalMode");
    if (credential_mode) {
        Check(Export<int (*)(P, const uint8_t*, size_t, P*)>(module, "libfsapfs_volume_set_utf8_password")(
            volume, reinterpret_cast<const uint8_t*>(password.Bytes().data()), password.Size(), &error) == 1, "TransitionOracleLockedCredentialInput");
        const auto unlocked = Export<int (*)(P, P*)>(module, "libfsapfs_volume_unlock")(volume, &error); password.Clear();
        Check(unlocked == (credential_mode == 2 ? 0 : 1), "TransitionOracleCredentialResult");
        if (credential_mode == 2) {
            Export<int (*)(P*, P*)>(module, "libfsapfs_volume_free")(&volume, nullptr);
            Export<int (*)(P*, P*)>(module, "libfsapfs_container_free")(&container, nullptr);
            Export<int (*)(P*, P*)>(module, "libbfio_handle_free")(&handle, nullptr); FreeLibrary(module);
            std::cout << "{\"independentOldPasswordRefused\":true,\"unlockReturn\":0}\n"; return 0;
        }
    }
    std::ifstream expected(run / (inventory_name ? inventory_name : after_plain_write ? L"expected-plain-write-files.txt" : L"expected-files.txt")); std::string magic; std::size_t count = 0; expected >> magic >> count;
    Check(expected && magic == "E06FILES1" && count > 0 && count <= 64, "TransitionOracleWholeInventory");
    for (std::size_t i = 0; i < count; ++i) {
        ExpectedFile wanted; expected >> wanted.inode >> wanted.bytes >> wanted.sha256;
        Check(expected && wanted.bytes <= 64 * 4096 && wanted.sha256.size() == 64, "TransitionOracleExpectedFile");
        P file{}; std::uint64_t size = 0;
        Check(Export<int (*)(P, uint64_t, P*, P*)>(module, "libfsapfs_volume_get_file_entry_by_identifier")(volume, wanted.inode, &file, &error) == 1 &&
            Export<int (*)(P, uint64_t*, P*)>(module, "libfsapfs_file_entry_get_size")(file, &size, &error) == 1 && size == wanted.bytes,
            "TransitionOracleExactPlainFileSize");
        auto bytes = Locked(static_cast<std::size_t>((std::max)(wanted.bytes, 1ull)));
        Check(Export<intptr_t (*)(P, void*, size_t, int64_t, P*)>(module, "libfsapfs_file_entry_read_buffer_at_offset")(
            file, bytes.Bytes().data(), static_cast<std::size_t>(wanted.bytes), 0, &error) == static_cast<intptr_t>(wanted.bytes) &&
            Digest(bytes.Bytes().first(static_cast<std::size_t>(wanted.bytes))) == wanted.sha256, "TransitionOracleExactPlainPayload");
        Export<int (*)(P*, P*)>(module, "libfsapfs_file_entry_free")(&file, nullptr);
    }
    std::size_t attribute_count = 0;
    if (pristine_raw) {
        std::ifstream attributes(run / L"expected-attributes.txt"); std::string attribute_magic;
        attributes >> attribute_magic >> attribute_count;
        Check(attributes && attribute_magic == "E06ATTR1" && attribute_count > 0 && attribute_count <= 64,
            "PristineIndependentWholeAttributeInventory");
        for (std::size_t i = 0; i < attribute_count; ++i) {
            std::uint64_t inode = 0, size = 0, actual_size = 0; std::string name, hash;
            attributes >> inode >> name >> size >> hash;
            Check(attributes && size <= 4096 && name.size() <= 255, "PristineIndependentExpectedAttribute");
            P file{}, attribute{};
            Check(Export<int (*)(P, uint64_t, P*, P*)>(module, "libfsapfs_volume_get_file_entry_by_identifier")(volume, inode, &file, &error) == 1 &&
                Export<int (*)(P, const uint8_t*, size_t, P*, P*)>(module, "libfsapfs_file_entry_get_extended_attribute_by_utf8_name")(
                    file, reinterpret_cast<const uint8_t*>(name.data()), name.size(), &attribute, &error) == 1 &&
                Export<int (*)(P, uint64_t*, P*)>(module, "libfsapfs_extended_attribute_get_size")(attribute, &actual_size, &error) == 1 &&
                actual_size == size, "PristineIndependentExactAttributeIdentityAndSize");
            auto bytes = Locked(static_cast<std::size_t>((std::max)(size, 1ull)));
            Check(Export<intptr_t (*)(P, void*, size_t, int64_t, P*)>(module, "libfsapfs_extended_attribute_read_buffer_at_offset")(
                attribute, bytes.Bytes().data(), static_cast<std::size_t>(size), 0, &error) == static_cast<intptr_t>(size) &&
                Digest(bytes.Bytes().first(static_cast<std::size_t>(size))) == hash, "PristineIndependentExactWholeAttributeBytes");
            Export<int (*)(P*, P*)>(module, "libfsapfs_extended_attribute_free")(&attribute, nullptr);
            Export<int (*)(P*, P*)>(module, "libfsapfs_file_entry_free")(&file, nullptr);
        }
    }
    Export<int (*)(P*, P*)>(module, "libfsapfs_volume_free")(&volume, nullptr);
    Export<int (*)(P*, P*)>(module, "libfsapfs_container_free")(&container, nullptr);
    Export<int (*)(P*, P*)>(module, "libbfio_handle_free")(&handle, nullptr); FreeLibrary(module);
    std::cout << "{\"independentPlainMode\":" << (credential_mode ? "false" : "true") << ",\"exactPayloadFiles\":" << count
        << ",\"exactAttributes\":" << attribute_count << ",\"passwordSupplied\":" << (credential_mode ? "true" : "false") << "}\n"; return 0;
}
int DecryptDriver(const std::filesystem::path& executable, const std::filesystem::path& run, bool roundtrip = false)
{
    Check(run.wstring().starts_with(std::wstring(transition_root) + L"\\run-") && std::filesystem::create_directory(run), "TransitionFreshPrivateRun");
    const auto original = std::filesystem::path(fixtures) / Profile{false}.Name(), image = run / Profile{false}.Name();
    Check(DigestFile(original) == Profile{false}.Pin() && CopyFileW(original.c_str(), image.c_str(), TRUE) &&
        CopyFileW(image.c_str(), (run / L"encrypted-preimage.dmg").c_str(), TRUE), "TransitionPreserveAuthenticInput");
    auto password = NoteCredential(Profile{false}), fresh = RandomCredential(); auto pair = Pair(password.Bytes(), fresh.Bytes());
    Check(Child(executable, (roundtrip ? L"transition-roundtrip " : L"transition-decrypt ") + Quoted(run), roundtrip ? pair.Bytes() : password.Bytes(),
        run / L"decrypt.log") == 0, "TransitionActualDecryptionChild");
    Check(Child(executable, L"transition-plain-oracle " + Quoted(run), {}, run / L"plain-oracle.log") == 0, "TransitionIndependentPlainChild");
    for (const auto& item : std::filesystem::recursive_directory_iterator(run)) if (item.is_regular_file()) Absent(item.path(), password.Bytes(), fresh.Bytes());
    Check(DigestFile(original) == Profile{false}.Pin(), "TransitionOriginalUntouched");
    std::cout << (roundtrip ? "TRANSITION_ROUNDTRIP_PRIMITIVE_PASS\n" : "TRANSITION_DECRYPT_PRIMITIVE_PASS\n"); return 0;
}
}
#ifndef APFS_VOLUME_TRANSITION_MAIN
#define APFS_VOLUME_TRANSITION_MAIN wmain
#endif
int APFS_VOLUME_TRANSITION_MAIN(int argc, wchar_t** argv)
{
    try {
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-decrypt") return DecryptPrimitive(argv[2], argv[0]);
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-roundtrip") return DecryptPrimitive(argv[2], argv[0], true);
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-plain-oracle") return PlainOracle(argv[2]);
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-encrypted-oracle") return PlainOracle(argv[2], 1);
        if (argc == 3 && std::wstring_view(argv[1]) == L"transition-old-oracle") return PlainOracle(argv[2], 2);
        if (argc == 3 && std::wstring_view(argv[1]) == L"drive-transition-decrypt") return DecryptDriver(argv[0], argv[2]);
        if (argc == 3 && std::wstring_view(argv[1]) == L"drive-transition-roundtrip") return DecryptDriver(argv[0], argv[2], true);
        return TransitionInheritedMain(argc, argv);
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
