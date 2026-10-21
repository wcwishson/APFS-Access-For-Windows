#define APFS_KEYBAG_JOURNAL_MAIN KeybagJournalMain
#include "EncryptedKeybagJournalTests.cpp"
#include "ApfsSoftwareKeybagEra.h"

namespace
{
std::wstring PhaseName(unsigned phase) { return L"phase-" + std::to_wstring(phase); }
JournalState LoadEraState(const std::filesystem::path& run)
{
    Check(run.wstring().starts_with(std::wstring(journal_root) + L"\\run-") &&
        std::filesystem::file_size(run / L"fixture-state.txt") < 65536, "EraStatePrivatePath");
    JournalState s; std::ifstream in(run / L"fixture-state.txt"); std::string magic;
    in >> magic >> std::quoted(s.identity) >> std::quoted(s.container_uuid) >> std::quoted(s.volume_uuid)
        >> s.volume_oid >> s.before_xid >> s.after_xid >> s.accepted >> s.switch_block;
    Check(magic == "E05FIXTURE1" && s.volume_oid == 1026 && s.before_xid >= 7 && s.before_xid < 16 &&
        s.after_xid == s.before_xid + 1 && s.accepted, "EraStateBoundaries");
    for (auto* list : {&s.writes, &s.guards}) {
        std::size_t count = 0; in >> count; Check(count > 0 && count <= 192, "EraBlockCountBound");
        for (std::size_t i = 0; i < count; ++i) {
            ExpectedBlock block; in >> block.block >> block.sha;
            Check(block.block < 4153344 / 4096 && block.sha.size() == 64, "EraBlockBounds"); list->push_back(std::move(block));
        }
    }
    Check(static_cast<bool>(in), "EraReadState"); return s;
}
void SaveEraExpected(const std::filesystem::path& run, unsigned phase, std::string_view digest)
{
    Check(digest.size() == 64, "EraExpectedDigestBound");
    std::ofstream out(run / (PhaseName(phase) + L"-expected.sha256")); out << digest << '\n';
    Check(static_cast<bool>(out), "EraExpectedDigestWrite");
}
std::string EraExpected(const std::filesystem::path& run, unsigned phase)
{
    std::ifstream in(run / (PhaseName(phase) + L"-expected.sha256")); std::string digest; in >> digest;
    Check(in && digest.size() == 64, "EraExpectedDigestRead"); return digest;
}
std::unique_ptr<c::ApfsEncryptedReadSession> UnlockEra(
    const std::shared_ptr<t::OwnedEncryptedImageSource>& source, Bytes password)
{
    c::UnlockError unlock{}; c::EncryptedReadError read{}; c::PasswordUnlockBudget budget;
    auto metadata = c::InspectPasswordKeybagMetadata(*source, 1026, c::KeybagLength::IncludesHeader, unlock);
    Check(metadata && metadata->users.size() == 1, "EraCanonicalCurrentUser");
    auto selected = metadata->selection; selected.user_uuid = metadata->users.front();
    auto session = c::ApfsEncryptedReadSession::Unlock(source, source->SourceIdentity(), source->Revision(),
        selected, password, budget, read, unlock);
    Check(static_cast<bool>(session), "EraFreshCurrentCredentialUnlock"); return session;
}
std::pair<std::size_t, std::size_t> ExistingBagRecord(Bytes bytes, const c::KeybagUuid& uuid, std::uint16_t tag)
{
    const auto count = c::ReadU16LE(bytes, 34).value_or(0);
    const auto end = 32 + c::ReadU32LE(bytes, 36).value_or(0); std::size_t at = 48;
    Check(count && count <= 1024 && end <= bytes.size(), "EraObservationBoundedExistingLocker");
    for (unsigned i = 0; i < count; ++i) {
        Check(at <= end && end - at >= 24, "EraObservationExistingEntryFrame");
        const auto length = c::ReadU16LE(bytes, at + 18).value_or(65535);
        const auto stride = (24 + static_cast<std::size_t>(length) + 15) & ~std::size_t{15};
        Check(length < 512 && stride <= end - at, "EraObservationExistingStride");
        if (c::ReadU16LE(bytes, at + 16) == tag && std::equal(uuid.begin(), uuid.end(), bytes.begin() + at))
            return {at + 24, length};
        at += stride;
    }
    Check(false, "EraObservationSelectedRecordPresent"); return {};
}
std::vector<std::byte> ObservedVek(const t::OwnedEncryptedImageSource& source, std::uint64_t xid,
    c::PasswordUnlockRequest& selected)
{
    c::UnlockError error{}; std::uint64_t container = 0, volume = 0;
    auto metadata = c::InspectPasswordKeybagMetadataAtCheckpoint(source, 1026, c::KeybagLength::IncludesHeader, xid, error, container, volume);
    Check(metadata && metadata->users.size() == 1, "EraObservationCanonicalBagValidation"); selected = metadata->selection;
    std::vector<std::byte> raw;
    Check(source.Read(container * 4096, 4096, raw), "EraObservationContainerRead");
    auto plain = c::DecryptApfsUuidKeybagBlock(selected.container_uuid, container, raw);
    Check(plain && c::VerifyObjectChecksum(plain.bytes.Bytes(), 4096) &&
        c::ReadU64LE(plain.bytes.Bytes(), 16) == selected.container_bag.xid, "EraObservationExactValidatedHeader");
    const auto [at, length] = ExistingBagRecord(plain.bytes.Bytes(), selected.volume_uuid, 2);
    return {plain.bytes.Bytes().begin() + at, plain.bytes.Bytes().begin() + at + length};
}
void ObserveEraEquivalence(const t::OwnedEncryptedImageSource& source, const c::ContainerCheckpointView& current)
{
    c::PasswordUnlockRequest latest; const auto canonical = ObservedVek(source, current.superblock.xid, latest);
    std::set<std::uint64_t> xids;
    Check(current.superblock.xp_desc_block_count <= 256, "EraObservationRingBound");
    for (std::uint64_t i = 0; i < current.superblock.xp_desc_block_count; ++i) {
        std::vector<std::byte> raw;
        Check(source.Read((current.superblock.xp_desc_base_block + i) * 4096, 4096, raw), "EraObservationRingRead");
        auto nx = c::ParseNxSuperblock(raw);
        if (nx && nx->uuid_hex == current.superblock.uuid_hex && nx->xid < current.superblock.xid) xids.insert(nx->xid);
    }
    Check(!xids.empty() && xids.size() <= 6, "EraObservationActualRetainedCheckpoints");
    for (auto xid : xids) {
        std::string error;
        if (!c::LoadContainerCheckpointView(source, 0, source.SizeBytes(), error, xid)) continue;
        c::PasswordUnlockRequest historical; const auto before = ObservedVek(source, xid, historical);
        Check(before == canonical && historical.container_uuid == latest.container_uuid && historical.volume_uuid == latest.volume_uuid,
            "EraAuthenticWrappedVekDerUnchanged");
        std::cout << "ERA_EQ current=" << current.superblock.xid << " historical=" << xid
            << " currentBagHeaderXid=" << latest.container_bag.xid << " oldBagHeaderXid=" << historical.container_bag.xid
            << " wrappedVekDerBytes=" << canonical.size() << " exact=true\n";
    }
}
int PrepareEra(const std::filesystem::path& run, unsigned phase)
{
    Check(phase >= 1 && phase <= 4, "EraDeclaredPhase");
    const auto image = run / Profile{false}.Name(); JournalState s; std::string error;
    if (phase & 1) {
        auto credentials = ReceivePair();
        const auto expected = NativeRead(image, Profile{false}, credentials.old_password.Bytes(), true);
        auto fixture = PrepareKeybagFixture(image, credentials); const auto& proof = *fixture.publication;
        s = PlanState(proof.SourceIdentity(), proof.VolumeObjectId(), proof.VolumeUuid(), proof.Publication());
        {
            std::ofstream bags(run / (PhaseName(phase) + L"-bags.txt"));
            bags << "E05ERABAGS1\n" << proof.OldContainerBagBlock() << ' ' << proof.OldVolumeBagBlock() << ' '
                << proof.NewContainerBagBlock() << ' ' << proof.NewVolumeBagBlock() << '\n';
            bags << proof.RetainedCheckpoints().size(); for (auto xid : proof.RetainedCheckpoints()) bags << ' ' << xid;
            bags << '\n'; Check(static_cast<bool>(bags), "EraCapturedPrivateBagOwners");
        }
        auto tx = OpenTx(run, s); Journal journal(Options(run, s));
        const bool accepted = journal.AcceptMaintenance(*tx, proof, s.accepted, error);
        Check(accepted, ("EraPrivateMaintenanceAcceptance:" + error).c_str());
        const bool staged = journal.StageMaintenance(*tx, s.accepted, proof, error);
        Check(staged, ("EraPrivateMaintenanceStage:" + error).c_str());
        SaveEraExpected(run, phase, expected);
    } else {
        auto password = Receive();
        auto lease = std::make_shared<t::WindowsImageLease>(image.wstring());
        auto source = std::make_shared<t::OwnedEncryptedImageSource>(lease, 20480, 4153344);
        auto session = UnlockEra(source, password.Bytes()); password.Clear();
        c::EncryptedReadError read{}; auto context = session->CreateMetadataReadContext(read);
        Check(static_cast<bool>(context), "EraFreshDataContext");
        auto current = c::LoadAppleCheckpointView(*source, 0, 4153344, error, *context);
        Check(static_cast<bool>(current), "EraCurrentDataAllocator");
        ObserveEraEquivalence(*source, current->container);
        std::vector<std::byte> payload;
        Check(session->ReadFile(21, 0, 22, payload) == c::EncryptedReadError::None && payload.size() == 22, "EraReadPriorPayload");
        const std::string_view patch = phase == 2 ? "E05ERA1" : "E05ERA2";
        const auto bytes = std::as_bytes(std::span(patch));
        Check(!std::equal(bytes.begin(), bytes.end(), payload.begin() + 3), "EraDataActuallyChanges");
        auto proof = session->PrepareCowOverwrite(*source, current->container.superblock.xid, 21, 3, bytes, error);
        Check(static_cast<bool>(proof), ("EraFreshCurrentDataPlan:" + error).c_str());
        Check(proof->SourceIdentity() == source->SourceIdentity() && proof->SourceCheckpointXid() == current->container.superblock.xid &&
            proof->IntentInode() == 21 && proof->IntentOffset() == 3 && proof->IntentLength() == bytes.size() &&
            proof->IntentSha256() == Sha(bytes), "EraActualDataIntentFromPrivateCapability");
        s = PlanState(proof->SourceIdentity(), proof->VolumeObjectId(), proof->VolumeUuid(), proof->Publication());
        auto tx = OpenTx(run, s); Tx::MutationIntent intent;
        intent.kind = Tx::MutationKind::Write; intent.path = L"\\era-data"; intent.object_id = proof->IntentInode();
        intent.offset = proof->IntentOffset(); intent.length = intent.payload_length = proof->IntentLength();
        intent.inline_payload.assign(bytes.begin(), bytes.end()); intent.payload_checksum = proof->IntentSha256();
        Check(tx->Begin() && tx->RecordMutation(intent) && tx->FlushPreparedRecords() && tx->Accept(s.before_xid), "EraActualOriginalDataAcceptance");
        s.accepted = tx->Watermarks().accepted_sequence;
        auto options = Options(run, s); options.maintenance_original_journal_identity = {};
        Journal journal(options); const bool staged = journal.Stage(*tx, s.accepted, *proof, error);
        Check(staged, ("EraActualCurrentDataStage:" + error).c_str());
        std::copy(bytes.begin(), bytes.end(), payload.begin() + 3); SaveEraExpected(run, phase, Digest(payload));
        SecureZeroMemory(payload.data(), payload.size());
        session->Close(); context.reset(); session.reset(); source.reset(); lease.reset();
    }
    Check(s.before_xid == 6 + phase && s.after_xid == 7 + phase, "EraExactFourStepCheckpointSequence");
    SaveState(run, s);
    Check(CopyFileW((run / L"fixture-state.txt").c_str(), (run / (PhaseName(phase) + L"-state.txt")).c_str(), TRUE), "EraPreservePhasePlan");
    std::cout << "{\"prepared\":true,\"phase\":" << phase << ",\"beforeXid\":" << s.before_xid
        << ",\"afterXid\":" << s.after_xid << ",\"accepted\":" << s.accepted
        << ",\"actualFreshCapability\":true,\"plaintextCredentialsRetained\":false}\n";
    return 0;
}
int PublishEra(const std::filesystem::path& run, unsigned phase, bool cut)
{
    const auto s = LoadEraState(run); auto options = Options(run, s);
    if (!(phase & 1)) options.maintenance_original_journal_identity = {};
    const auto original_hash = DigestFile(run / L"original.wal");
    std::string error;
    if (phase & 1) {
        {
            auto tx = OpenTx(run, s); Journal journal(options);
            const bool staged = journal.RestageMaintenance(*tx, s.accepted, error);
            Check(staged, ("EraFreshNoSecretRestage:" + error).c_str());
        }
        Check(DigestFile(run / L"original.wal") == original_hash, "EraRestagePreservesOriginal");
    }
    auto tx = OpenTx(run, s); Journal journal(options);
    JournalTarget target(run / Profile{false}.Name(), s, false); target.tear = cut;
    const bool published = journal.PublishOrRecover(*tx, s.accepted, target, error);
    if (cut) {
        Check(!published && target.torn_bytes == 32 && tx->Watermarks().apfs_durable_sequence < s.accepted,
            "EraRealTornSwitchBeforeDurable");
        std::cout << "{\"tornSwitch\":true,\"phase\":" << phase << ",\"bytes\":32,\"durableNotAdvanced\":true}\n";
        return 0;
    }
    Check(published, ("EraFreshPublicationOrRecovery:" + error).c_str());
    for (const auto& block : s.writes) {
        std::vector<std::byte> actual;
        Check(target.ReadBlock(block.block, 4096, actual) && Digest(actual) == block.sha, "EraExactPublishedCiphertext");
    }
    for (const auto& block : s.guards) {
        if (std::any_of(s.writes.begin(), s.writes.end(), [&](const auto& row) { return row.block == block.block; })) continue;
        std::vector<std::byte> actual;
        Check(target.ReadBlock(block.block, 4096, actual) && Digest(actual) == block.sha, "EraRetainedBagAndMetadataGuard");
    }
    Check(tx->Watermarks().apfs_durable_sequence == s.accepted && tx->MarkCleanedThrough(s.accepted), "EraDurableThenCleanedBoundary");
    std::cout << "{\"published\":true,\"phase\":" << phase << ",\"selectedXid\":" << s.after_xid
        << ",\"accepted\":" << s.accepted << ",\"writes\":" << target.writes << ",\"flushes\":" << target.flushes
        << ",\"freshNoCredentialProcess\":true}\n"; return 0;
}
int EraOracle(const std::filesystem::path& image, std::string_view expected, std::size_t expected_length = 22)
{
    auto password = Receive(); const bool success = expected != "refuse";
    Check(expected_length > 0 && expected_length <= 65536, "EraOracleExpectedLengthBound");
    Check(DigestFile(oracle) == "3d0d4b68e651506ec7fc0c06944f488a0e465bf35a067a9d91ebf3611fdbf83b", "EraOraclePin");
    HMODULE module = LoadLibraryExW(oracle, nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    Check(module != nullptr, "EraOracleLoad"); using P = void*;
    Check(std::string_view(Export<const char* (*)()>(module, "libfsapfs_get_version")()) == "20260923", "EraOracleVersion");
    P error{}, handle{}, container{}, volume{}, file{};
    Check(Export<int (*)(P*, P*)>(module, "libbfio_file_range_initialize")(&handle, &error) == 1 &&
        Export<int (*)(P, const wchar_t*, size_t, P*)>(module, "libbfio_file_range_set_name_wide")(handle, image.c_str(), image.wstring().size(), &error) == 1 &&
        Export<int (*)(P, int64_t, uint64_t, P*)>(module, "libbfio_file_range_set")(handle, 20480, 4153344, &error) == 1, "EraOracleRange");
    Check(Export<int (*)(P*, P*)>(module, "libfsapfs_container_initialize")(&container, &error) == 1 &&
        Export<int (*)(P, P, int, P*)>(module, "libfsapfs_container_open_file_io_handle")(container, handle, 1, &error) == 1 &&
        Export<int (*)(P, int, P*, P*)>(module, "libfsapfs_container_get_volume_by_index")(container, 0, &volume, &error) == 1, "EraOracleOpen");
    Check(Export<int (*)(P, P*)>(module, "libfsapfs_volume_is_locked")(volume, &error) == 1 &&
        Export<int (*)(P, const uint8_t*, size_t, P*)>(module, "libfsapfs_volume_set_utf8_password")(
            volume, reinterpret_cast<const uint8_t*>(password.Bytes().data()), password.Size(), &error) == 1, "EraOracleCredentialInput");
    const auto unlocked = Export<int (*)(P, P*)>(module, "libfsapfs_volume_unlock")(volume, &error); password.Clear();
    Check(unlocked == (success ? 1 : 0), "EraOracleCredentialOutcome");
    if (success) {
        Check(Export<int (*)(P, uint64_t, P*, P*)>(module, "libfsapfs_volume_get_file_entry_by_identifier")(volume, 21, &file, &error) == 1, "EraOracleFile");
        auto bytes = Locked(expected_length); uint64_t size = 0;
        Check(Export<int (*)(P, uint64_t*, P*)>(module, "libfsapfs_file_entry_get_size")(file, &size, &error) == 1 && size == bytes.Size() &&
            Export<intptr_t (*)(P, void*, size_t, int64_t, P*)>(module, "libfsapfs_file_entry_read_buffer_at_offset")(
                file, bytes.Bytes().data(), bytes.Size(), 0, &error) == static_cast<intptr_t>(bytes.Size()) && Digest(bytes.Bytes()) == expected,
            "EraOracleExactChangedPayload");
        std::cout << "{\"unlocked\":true,\"sha256\":\"" << expected << "\"}\n";
    } else std::cout << "{\"refused\":true,\"unlockReturn\":0}\n";
    if (file) Export<int (*)(P*, P*)>(module, "libfsapfs_file_entry_free")(&file, nullptr);
    Export<int (*)(P*, P*)>(module, "libfsapfs_volume_free")(&volume, nullptr);
    Export<int (*)(P*, P*)>(module, "libfsapfs_container_free")(&container, nullptr);
    Export<int (*)(P*, P*)>(module, "libbfio_handle_free")(&handle, nullptr);
    FreeLibrary(module); return 0;
}
struct ExistingDerAtom { std::size_t tag, value, size, end; };
ExistingDerAtom ExistingDerField(Bytes bytes, std::size_t& at, unsigned tag)
{
    const auto begin = at;
    Check(at < bytes.size() && std::to_integer<unsigned>(bytes[at++]) == tag && at < bytes.size(), "EraNegativeExistingDerTag");
    std::size_t size = std::to_integer<unsigned>(bytes[at++]);
    if (size & 128) {
        const auto count = size & 127; Check(count > 0 && count <= 2 && count <= bytes.size() - at, "EraNegativeExistingDerLength");
        size = 0; for (std::size_t i = 0; i < count; ++i) size = size * 256 + std::to_integer<unsigned>(bytes[at++]);
    }
    Check(size <= bytes.size() - at, "EraNegativeExistingDerBound");
    const auto value = at; at += size; return {begin, value, size, at};
}
void MutateExistingDer(std::span<std::byte> record, bool key_class)
{
    std::size_t at = 0; const auto sequence = ExistingDerField(record, at, 0x30);
    Check(sequence.end == record.size(), "EraNegativeExactDerSequence"); at = sequence.value;
    (void)ExistingDerField(record, at, 0x80); const auto checksum = ExistingDerField(record, at, 0x81);
    const auto salt = ExistingDerField(record, at, 0x82); const auto body = ExistingDerField(record, at, 0xA3);
    Check(checksum.size == 32 && salt.size == 8 && body.end == record.size(), "EraNegativeExistingEnvelope");
    at = body.value; (void)ExistingDerField(record, at, 0x80); (void)ExistingDerField(record, at, 0x81);
    const auto info = ExistingDerField(record, at, 0x82); const auto wrapped = ExistingDerField(record, at, 0x83);
    if (key_class) {
        const auto flags = c::ReadU32LE(record, info.value).value_or(~0u);
        Check((flags == 0 || flags == 16) && wrapped.size == 40, "EraNegativeSupportedDistinctKekClasses");
        record[info.value] ^= std::byte{16};
    } else { Check(wrapped.size == 40, "EraNegativeExistingWrappedVekLength"); record[wrapped.value] ^= std::byte{1}; }
    std::array<std::byte, 14> cookie{std::byte{1}, std::byte{0x16}, std::byte{0x20}, std::byte{0x17}, std::byte{0x15}, std::byte{5}};
    std::copy_n(record.begin() + salt.value, 8, cookie.begin() + 6); auto key = Sha(cookie); Digest32 digest{};
    BCRYPT_ALG_HANDLE algorithm{};
    Check(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG) >= 0, "EraNegativePublicChecksumProvider");
    const auto status = BCryptHash(algorithm, key.data(), static_cast<ULONG>(key.size()),
        reinterpret_cast<PUCHAR>(record.data() + body.tag), static_cast<ULONG>(record.size() - body.tag), digest.data(), static_cast<ULONG>(digest.size()));
    BCryptCloseAlgorithmProvider(algorithm, 0); Check(status >= 0, "EraNegativeRepairPublicDerChecksum");
    std::transform(digest.begin(), digest.end(), record.begin() + checksum.value, [](auto byte) { return static_cast<std::byte>(byte); });
}
void FixEraObject(std::span<std::byte> bytes)
{
    const auto checksum = c::Fletcher64(bytes.data() + 8, bytes.size() - 8); Check(checksum.has_value(), "EraNegativeExistingObjectChecksum");
    for (unsigned i = 0; i < 8; ++i) bytes[i] = static_cast<std::byte>(*checksum >> (8 * i));
}
int NegativeEra(const std::filesystem::path& run, std::wstring_view mode)
{
    const auto image = run / L"era-negative.dmg"; auto password = Receive();
    constexpr std::uint64_t historical_xid = 7;
    std::uint64_t block = 0; std::vector<std::byte> replacement;
    {
        auto lease = std::make_shared<t::WindowsImageLease>(image.wstring());
        auto source = std::make_shared<t::OwnedEncryptedImageSource>(lease, 20480, 4153344);
        c::UnlockError error{}; std::uint64_t container = 0, volume = 0; std::string detail;
        auto metadata = c::InspectPasswordKeybagMetadataAtCheckpoint(*source, 1026, c::KeybagLength::IncludesHeader, historical_xid, error, container, volume);
        Check(metadata && metadata->users.size() == 1, "EraNegativeAuthenticHistoricalSelection");
        if (mode == L"bad-crypto") {
            auto cp = c::LoadContainerCheckpointView(*source, 0, 4153344, detail, historical_xid);
            auto view = cp ? c::LoadAppleReadOnlyVolumeView(*source, *cp, detail) : std::nullopt;
            Check(view && view->volumes.size() == 1, "EraNegativeHistoricalApsb"); block = view->volumes.front().superblock_object.physical_block;
            Check(source->Read(block * 4096, 4096, replacement), "EraNegativeHistoricalApsbRead"); replacement[0x70] ^= std::byte{1}; FixEraObject(replacement);
        } else {
            block = mode == L"bad-vek" ? container : volume;
            const auto& uuid = mode == L"bad-vek" ? metadata->selection.container_uuid : metadata->selection.volume_uuid;
            std::vector<std::byte> raw; Check(source->Read(block * 4096, 4096, raw), "EraNegativeHistoricalBagRead");
            auto plain = c::DecryptApfsUuidKeybagBlock(uuid, block, raw); Check(static_cast<bool>(plain), "EraNegativeExistingUuidXts");
            if (mode == L"bad-header") {
                for (unsigned i = 0; i < 8; ++i) plain.bytes.Bytes()[16 + i] = static_cast<std::byte>(10ULL >> (8 * i));
            } else {
                const auto [offset, length] = ExistingBagRecord(plain.bytes.Bytes(), mode == L"bad-vek" ? metadata->selection.volume_uuid : metadata->users.front(), mode == L"bad-vek" ? 2 : 3);
                MutateExistingDer(plain.bytes.Bytes().subspan(offset, length), mode == L"bad-class");
            }
            FixEraObject(plain.bytes.Bytes()); auto encoded = c::EncryptApfsUuidKeybagBlock(uuid, block, plain.bytes.Bytes());
            Check(static_cast<bool>(encoded), "EraNegativePreserveExistingOuterFormat"); replacement.assign(encoded.bytes.Bytes().begin(), encoded.bytes.Bytes().end());
        }
    }
    {
        Handle file(CreateFileW(image.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        Check(file.h != INVALID_HANDLE_VALUE && replacement.size() == 4096, "EraNegativeExclusivePrivateCopy");
        LARGE_INTEGER at{}; at.QuadPart = static_cast<LONGLONG>(20480 + block * 4096); DWORD written = 0;
        Check(SetFilePointerEx(file.h, at, nullptr, FILE_BEGIN) && WriteFile(file.h, replacement.data(), 4096, &written, nullptr) &&
            written == 4096 && FlushFileBuffers(file.h), "EraNegativePersistDeliberateHistoricalChange");
    }
    const auto before = DigestFile(image); std::string error;
    {
        auto lease = std::make_shared<t::WindowsImageLease>(image.wstring());
        auto source = std::make_shared<t::OwnedEncryptedImageSource>(lease, 20480, 4153344); auto session = UnlockEra(source, password.Bytes()); password.Clear();
        c::UnlockError inspect{}; std::uint64_t a = 0, b = 0;
        const auto historical = c::InspectPasswordKeybagMetadataAtCheckpoint(*source, 1026, c::KeybagLength::IncludesHeader, historical_xid, inspect, a, b);
        Check(static_cast<bool>(historical) == (mode != L"bad-header"), "EraNegativeCanonicalRecordControl");
        c::EncryptedReadError read{}; auto context = session->CreateMetadataReadContext(read);
        auto cp = context ? c::LoadAppleCheckpointView(*source, 0, 4153344, error, *context) : std::nullopt;
        Check(cp && cp->container.superblock.xid == 9, "EraNegativeFreshCanonicalLatestAdmission");
        const std::string_view patch = "REFUSE";
        const std::array<std::uint64_t, 1> required{historical_xid};
        auto proof = session->PrepareCowOverwrite(*source, 9, 21, 3, std::as_bytes(std::span(patch)), error, required);
        std::cout << "ERA_NEG observedCandidate=" << (proof ? "true" : "false") << " error=" << error << '\n';
        const std::string_view expected = mode == L"bad-header" ? "SoftwareKeybagEraCanonicalProfileMismatch" : "SoftwareKeybagEraWrappedKeyOrCryptoStateChanged";
        Check(!proof && error.find(expected) != std::string::npos, "EraNegativePrivateProofMustRefuse");
        session->Close();
    }
    Check(DigestFile(image) == before, "EraNegativeNoPlanningWrites");
    std::cout << "{\"eraProofRefused\":true,\"error\":\"" << error << "\",\"targetCalls\":0,\"imageUnchangedAfterFaultSetup\":true}\n"; return 0;
}
int EraDriver(const std::filesystem::path& executable, std::wstring_view mode)
{
    const bool negative = mode == L"bad-vek" || mode == L"bad-class" || mode == L"bad-crypto" || mode == L"bad-header";
    Check(negative || mode == L"normal" || mode == L"maintenance-torn" || mode == L"data-torn" || mode == L"maintenance-eof", "EraDeclaredFailureProfile");
    const Profile profile{false}; const auto original = std::filesystem::path(fixtures) / profile.Name();
    const auto run = std::filesystem::path(journal_root) / (L"run-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64()) + L"-eras-" + std::wstring(mode));
    Check(std::filesystem::create_directory(run), "EraPrivateDirectory");
    for (const auto* name : {L"original-keys", L"witness-keys"}) Check(std::filesystem::create_directory(run / name), "EraProtectedRoots");
    const auto image = run / profile.Name();
    Check(DigestFile(original) == profile.Pin() && CopyFileW(original.c_str(), image.c_str(), TRUE), "EraAuthenticPrivateCopy");
    auto initial = NoteCredential(profile), first = RandomCredential(), latest = RandomCredential();
    for (unsigned phase = 1; phase <= (negative ? 2u : 4u); ++phase) {
        const auto tag = PhaseName(phase); const auto args = Quoted(run) + L" " + std::to_wstring(phase);
        Check(CopyFileW(image.c_str(), (run / (tag + L"-preimage.dmg")).c_str(), TRUE), "EraPreservePreimage");
        if (phase & 1) {
            auto pair = Pair(phase == 1 ? initial.Bytes() : first.Bytes(), phase == 1 ? first.Bytes() : latest.Bytes());
            Check(Child(executable, L"era-prepare " + args, pair.Bytes(), run / (tag + L"-prepare.log")) == 0, "EraPrepareMaintenanceProcess"); pair.Clear();
        } else Check(Child(executable, L"era-prepare " + args, phase == 2 ? first.Bytes() : latest.Bytes(), run / (tag + L"-prepare.log")) == 0, "EraPrepareFreshDataProcess");
        if (phase == 3 && mode == L"maintenance-eof")
            Check(Child(executable, L"era-witness-tear " + Quoted(run), {}, run / (tag + L"-witness-tear.log")) == 0, "EraActualWitnessEofProcess");
        if ((phase == 3 && mode == L"maintenance-torn") || (phase == 4 && mode == L"data-torn"))
            Check(Child(executable, L"era-cut " + args, {}, run / (tag + L"-cut.log")) == 0, "EraActualSwitchTearProcess");
        Check(Child(executable, L"era-publish " + args, {}, run / (tag + L"-publish.log")) == 0, "EraFreshNoCredentialPublicationProcess");
        Check(CopyFileW(image.c_str(), (run / (tag + L"-postimage.dmg")).c_str(), TRUE), "EraPreservePostimage");
        const auto expected = EraExpected(run, phase); const auto expected_arg = std::wstring(expected.begin(), expected.end());
        const auto& active = phase <= 2 ? first : latest;
        Check(Child(executable, L"era-oracle " + Quoted(image) + L" " + expected_arg, active.Bytes(), run / (tag + L"-oracle-active.log")) == 0, "EraIndependentActivePasswordAndData");
        Check(Child(executable, L"era-oracle " + Quoted(image) + L" refuse", initial.Bytes(), run / (tag + L"-oracle-initial-refused.log")) == 0, "EraIndependentInitialPasswordRefused");
        if (phase >= 3) Check(Child(executable, L"era-oracle " + Quoted(image) + L" refuse", first.Bytes(), run / (tag + L"-oracle-intermediate-refused.log")) == 0,
            "EraIndependentIntermediatePasswordRefused");
        Check(NativeRead(image, profile, active.Bytes(), true) == expected, "EraFreshNativeExactData");
        NativeRead(image, profile, initial.Bytes(), false); if (phase >= 3) NativeRead(image, profile, first.Bytes(), false);
        for (const auto& entry : std::filesystem::recursive_directory_iterator(run)) if (entry.is_regular_file()) {
            Absent(entry.path(), initial.Bytes(), first.Bytes()); Absent(entry.path(), initial.Bytes(), latest.Bytes());
        }
    }
    if (negative) {
        const auto copy = run / L"era-negative.dmg";
        Check(CopyFileW(image.c_str(), copy.c_str(), TRUE), "EraNegativePrivateFaultCopy"); const auto main_hash = DigestFile(image);
        Check(Child(executable, L"era-negative " + Quoted(run) + L" " + std::wstring(mode), first.Bytes(), run / L"negative-proof.log") == 0, "EraNegativeProofProcess");
        const auto expected = EraExpected(run, 2);
        Check(Child(executable, L"era-oracle " + Quoted(copy) + L" " + std::wstring(expected.begin(), expected.end()), first.Bytes(), run / L"negative-current-active.log") == 0,
            "EraNegativeCurrentCredentialAndPayloadUnaffected");
        Check(Child(executable, L"era-oracle " + Quoted(copy) + L" refuse", initial.Bytes(), run / L"negative-initial-refused.log") == 0, "EraNegativeOldCanonicalCredentialRefused");
        Check(DigestFile(image) == main_hash, "EraNegativeSourceImagePreserved");
        for (const auto& entry : std::filesystem::recursive_directory_iterator(run)) if (entry.is_regular_file()) {
            Absent(entry.path(), initial.Bytes(), first.Bytes()); Absent(entry.path(), initial.Bytes(), latest.Bytes());
        }
    }
    Check(DigestFile(original) == profile.Pin(), "EraAuthenticOriginalPreserved");
    std::cout << "{\"negative\":" << (negative ? "true" : "false") << ",\"actualPublications\":" << (negative ? 2 : 4)
        << ",\"allCredentialOracles\":true,\"e05Complete\":false}\n";
    std::wcout << L"EVIDENCE " << run.wstring() << '\n'; return 0;
}
}
#ifndef APFS_KEYBAG_ERA_MAIN
#define APFS_KEYBAG_ERA_MAIN wmain
#endif
int APFS_KEYBAG_ERA_MAIN(int argc, wchar_t** argv)
{
    try {
        if (argc == 3 && std::wstring_view(argv[1]) == L"drive-keybag-eras") return EraDriver(argv[0], argv[2]);
        if (argc == 4 && std::wstring_view(argv[1]) == L"era-prepare") return PrepareEra(argv[2], static_cast<unsigned>(std::stoul(argv[3])));
        if (argc == 4 && (std::wstring_view(argv[1]) == L"era-publish" || std::wstring_view(argv[1]) == L"era-cut"))
            return PublishEra(argv[2], static_cast<unsigned>(std::stoul(argv[3])), std::wstring_view(argv[1]) == L"era-cut");
        if (argc == 3 && std::wstring_view(argv[1]) == L"era-witness-tear") { const auto s = LoadEraState(argv[2]); PrepareWitnessTear(argv[2], s, L"tear-first-prefix"); return 0; }
        if (argc == 4 && std::wstring_view(argv[1]) == L"era-oracle") return EraOracle(argv[2], Tx::WideToUtf8(std::wstring(argv[3])));
        if (argc == 4 && std::wstring_view(argv[1]) == L"era-negative") return NegativeEra(argv[2], argv[3]);
        return KeybagJournalMain(argc, argv);
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
