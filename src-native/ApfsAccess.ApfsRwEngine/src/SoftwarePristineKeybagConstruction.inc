namespace
{
std::vector<std::byte> PristineDerField(unsigned tag, Bytes payload)
{
    if (tag > 255 || payload.size() > 255) throw std::runtime_error("SoftwarePristineDerBound");
    std::vector<std::byte> bytes{static_cast<std::byte>(tag)};
    if (payload.size() >= 128) bytes.push_back(std::byte{0x81});
    bytes.push_back(static_cast<std::byte>(payload.size())); bytes.insert(bytes.end(), payload.begin(), payload.end()); return bytes;
}
void PristineAppend(std::vector<std::byte>& out, const std::vector<std::byte>& field)
{ out.insert(out.end(), field.begin(), field.end()); }
std::vector<std::byte> PristineKeyRecord(Bytes wrapped, Bytes kdf_salt = {})
{
    // Exact opaque eight-byte encoding observed in the authenticated dfvfs
    // capture. No revision/counter/UUID meaning is assigned to its unknown tail.
    const std::array<std::byte, 8> info{std::byte{}, std::byte{}, std::byte{}, std::byte{},
        kdf_salt.empty() ? std::byte{1} : std::byte{2}, std::byte{}, std::byte{0xA9}, std::byte{0xAB}};
    const auto random = [](auto& value) {
        return Cng([&] { return BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(value.data()),
            static_cast<ULONG>(value.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG); }) >= 0;
    };
    std::array<std::byte, 16> uuid{}; std::array<std::byte, 8> checksum_salt{};
    if (!random(uuid) || !random(checksum_salt)) throw std::runtime_error("SoftwarePristineRecordRandomFailed");
    const std::array<std::byte, 1> zero{};
    std::vector<std::byte> fields = PristineDerField(0x80, zero);
    PristineAppend(fields, PristineDerField(0x81, uuid)); PristineAppend(fields, PristineDerField(0x82, info));
    PristineAppend(fields, PristineDerField(0x83, wrapped));
    if (!kdf_salt.empty()) {
        if (kdf_salt.size() != 16) throw std::runtime_error("SoftwarePristineKdfSaltBound");
        const std::array<std::byte, 3> work{std::byte{0x02}, std::byte{0xC2}, std::byte{0xB8}};
        PristineAppend(fields, PristineDerField(0x84, work));
        PristineAppend(fields, PristineDerField(0x85, kdf_salt));
    }
    const auto authenticated = PristineDerField(0xA3, fields);
    std::array<std::byte, 14> cookie{std::byte{1}, std::byte{0x16}, std::byte{0x20}, std::byte{0x17}, std::byte{0x15}, std::byte{5}};
    std::copy(checksum_salt.begin(), checksum_salt.end(), cookie.begin() + 6); auto key = Digest(cookie);
    if (!key) throw std::runtime_error("SoftwarePristineChecksumKeyFailed");
    auto checksum = Digest(authenticated, key.bytes.Bytes());
    if (!checksum) throw std::runtime_error("SoftwarePristineChecksumFailed");
    auto envelope = PristineDerField(0x80, zero); PristineAppend(envelope, PristineDerField(0x81, checksum.bytes.Bytes()));
    PristineAppend(envelope, PristineDerField(0x82, checksum_salt)); PristineAppend(envelope, authenticated);
    return PristineDerField(0x30, envelope);
}
}

bool SoftwareVolumeTransition::InitializePristineKeybags(const RandomAccessSource& source, std::uint64_t volume_oid,
    std::uint64_t container_block, std::uint64_t volume_block, std::uint64_t xid, const crypto::SecureBytes& password,
    PasswordUnlockBudget& budget, crypto::SecureBytes& volume_key, std::vector<std::byte>& container_out,
    std::vector<std::byte>& volume_out, std::string& error)
{
    volume_key.Clear(); container_out.clear(); volume_out.clear();
    const auto fail = [&](const char* reason) { error = reason; return false; };
    if (!password.IsLocked() || !password.Size() || !PasswordValid(password.Bytes()) || !source.ReadBudget() ||
        !container_block || !volume_block || container_block == volume_block ||
        container_block >= source.SizeBytes() / 4096 || volume_block >= source.SizeBytes() / 4096 || !budget.Begin())
        return fail("SoftwarePristineConstructionScopeInvalid");
    try {
        auto cp = LoadContainerCheckpointView(source, 0, source.SizeBytes(), error);
        auto volumes = cp ? LoadAppleReadOnlyVolumeView(source, *cp, error) : std::nullopt;
        if (!volumes || volumes->volumes.size() != 1 || volumes->volumes.front().superblock.object_id != volume_oid ||
            volumes->volumes.front().superblock.fs_flags != kFsFlagUnencrypted ||
            ReadU64LE(cp->superblock_bytes, 0x510) != 0 || ReadU64LE(cp->superblock_bytes, 0x518) != 0 ||
            ReadU64LE(cp->superblock_bytes, 0x4F0) != 0 || xid != cp->superblock.next_xid)
            return fail("SoftwarePristineCanonicalAbsenceRequired");
        KeybagUuid container_uuid{}, volume_uuid{}, user_uuid{};
        std::copy_n(cp->superblock_bytes.begin() + 0x48, 16, container_uuid.begin());
        WipedVector apsb;
        if (!source.Read(volumes->volumes.front().superblock_object.physical_block * 4096, 4096, apsb.bytes) || apsb.bytes.size() != 4096)
            return fail("SoftwarePristineVolumeIdentityUnreadable");
        std::copy_n(apsb.bytes.begin() + 0xF0, 16, volume_uuid.begin());
        auto vek = SecureBytes::Allocate(32), kek = SecureBytes::Allocate(32);
        const auto random = [](std::span<std::byte> bytes) {
            return Cng([&] { return BCryptGenRandom(nullptr, Out(bytes), static_cast<ULONG>(bytes.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG); }) >= 0;
        };
        if (!vek || !kek || !random(vek.bytes.Bytes()) || !random(kek.bytes.Bytes()) || !random(user_uuid) ||
            Equal(vek.bytes.Bytes().first(16), vek.bytes.Bytes().last(16))) return fail("SoftwarePristineLockedKeyGenerationFailed");
        // KDF count is the genuine supported AES-256 capture's work factor.
        constexpr std::uint64_t iterations = 180920;
        std::array<std::byte, 16> salt{}; if (!random(salt) || !budget.Charge(iterations)) return fail("SoftwarePristineKdfBudgetOrRandomFailed");
        auto derived = crypto::Pbkdf2HmacSha256(password.Bytes(), salt, iterations, 32);
        if (!derived) return fail("SoftwarePristinePasswordDerivationFailed");
        auto wrapped_kek = WrapKek(derived.bytes.Bytes(), kek.bytes.Bytes()); auto wrapped_vek = WrapKek(kek.bytes.Bytes(), vek.bytes.Bytes());
        derived.bytes.Clear(); kek.bytes.Clear();
        if (!wrapped_kek || !wrapped_vek) return fail("SoftwarePristineWrapFailed");
        auto vek_der = PristineKeyRecord(wrapped_vek.bytes.Bytes());
        auto kek_der = PristineKeyRecord(wrapped_kek.bytes.Bytes(), salt);
        auto verified = DecodeRecords(vek_der, kek_der, password.Bytes(), budget);
        if (!verified || !Equal(verified.xts_key.Bytes(), vek.bytes.Bytes())) return fail("SoftwarePristineOwnedUnwrapRoundtripFailed");
        const auto bag = [&](bool container) {
            std::vector<std::byte> bytes(4096); const auto put = [&](std::size_t at, std::uint64_t value, unsigned count) {
                for (unsigned i = 0; i < count; ++i) bytes[at + i] = static_cast<std::byte>(value >> (8 * i));
            };
            put(16, xid, 8); put(24, container ? 0x6B657973 : 0x72656373, 4); put(32, 2, 2); put(34, container ? 2 : 1, 2);
            std::size_t at = 48;
            const auto entry = [&](const KeybagUuid& uuid_value, unsigned tag, Bytes payload) {
                std::copy(uuid_value.begin(), uuid_value.end(), bytes.begin() + at); put(at + 16, tag, 2); put(at + 18, payload.size(), 2);
                std::copy(payload.begin(), payload.end(), bytes.begin() + at + 24); at += (24 + payload.size() + 15) & ~std::size_t{15};
            };
            if (container) {
                entry(volume_uuid, 2, vek_der); std::array<std::byte, 16> range{};
                for (unsigned i = 0; i < 8; ++i) range[i] = static_cast<std::byte>(volume_block >> (8 * i));
                range[8] = std::byte{1};
                entry(volume_uuid, 3, range);
            } else entry(user_uuid, 3, kek_der);
            put(36, at - 32, 4); const auto sum = Fletcher64(bytes.data() + 8, bytes.size() - 8);
            if (!sum) throw std::runtime_error("SoftwarePristineObjectChecksumFailed"); put(0, *sum, 8); return bytes;
        };
        auto container_plain = bag(true), volume_plain = bag(false); Locker container_locker, volume_locker;
        if (ParseLocker(container_plain, KeybagKind::Container, KeybagLength::IncludesHeader, container_locker, *source.ReadBudget()) != UnlockError::None ||
            ParseLocker(volume_plain, KeybagKind::Volume, KeybagLength::IncludesHeader, volume_locker, *source.ReadBudget()) != UnlockError::None)
            return fail("SoftwarePristineCompleteBagRoundtripFailed");
        auto container_cipher = EncryptApfsUuidKeybagBlock(container_uuid, container_block, container_plain);
        auto volume_cipher = EncryptApfsUuidKeybagBlock(volume_uuid, volume_block, volume_plain);
        if (!container_cipher || !volume_cipher) return fail("SoftwarePristineUuidXtsFailed");
        container_out.assign(container_cipher.bytes.Bytes().begin(), container_cipher.bytes.Bytes().end());
        volume_out.assign(volume_cipher.bytes.Bytes().begin(), volume_cipher.bytes.Bytes().end()); volume_key = std::move(vek.bytes); return true;
    } catch (...) { return fail("SoftwarePristineConstructionFailed"); }
}
