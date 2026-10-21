// Included inside the private Journal test friend.
struct CarrySource final : c::ImmutableEncryptedReadSource
{
    std::shared_ptr<t::WindowsImageLease> lease;
    std::string identity;
    std::shared_ptr<c::ApfsReadBudget> budget = std::make_shared<c::ApfsReadBudget>(100000, 256ull << 20, 1000000, 256ull << 20);
    static std::string Identity(const BY_HANDLE_FILE_INFORMATION& info)
    {
        return "image-writer-v1:" + std::to_string(info.dwVolumeSerialNumber) + ":" +
            std::to_string((std::uint64_t(info.nFileIndexHigh) << 32) | info.nFileIndexLow) + ":" +
            std::to_string((std::uint64_t(info.nFileSizeHigh) << 32) | info.nFileSizeLow) + ":20480:4153344";
    }
    explicit CarrySource(const std::filesystem::path& image) : lease(std::make_shared<t::WindowsImageLease>(image.wstring()))
    {
        Handle file(CreateFileW(image.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        BY_HANDLE_FILE_INFORMATION info{};
        Require(file.h != INVALID_HANDLE_VALUE && GetFileInformationByHandle(file.h, &info), "carry held image identity");
        identity = Identity(info);
    }
    std::uint64_t SizeBytes() const override { return 4153344; }
    std::string SourceIdentity() const override { return identity; }
    std::uint64_t Revision() const override { return 1; }
    std::shared_ptr<c::ApfsReadBudget> ReadBudget() const override { return budget; }
    bool Read(std::uint64_t at, std::size_t count, std::vector<std::byte>& out) const override
    {
        return at <= SizeBytes() && count <= SizeBytes() - at && budget->Read(count) && lease->VerifyUnchanged() &&
            lease->Read(20480 + at, count, out) && lease->VerifyUnchanged();
    }
};
struct CarryTarget final : EncryptedPublicationTarget
{
    Handle file;
    std::array<std::byte, 32> binding;
    CarryTarget(const std::filesystem::path& image, const J::Options& options)
        : file(CreateFileW(image.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_RANDOM_ACCESS, nullptr)), binding(options.witness.protected_persistence->source_binding)
    {
        BY_HANDLE_FILE_INFORMATION info{}; wchar_t resolved[512]{};
        const auto expected = L"\\\\?\\" + image.wstring();
        const auto length = file.h == INVALID_HANDLE_VALUE ? 0 : GetFinalPathNameByHandleW(file.h, resolved, 512, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        Require(file.h != INVALID_HANDLE_VALUE && GetFileType(file.h) == FILE_TYPE_DISK && GetFileInformationByHandle(file.h, &info) &&
            info.nNumberOfLinks == 1 && !(info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_DEVICE)) &&
            length && length < 512 && CompareStringOrdinal(resolved, -1, expected.c_str(), -1, TRUE) == CSTR_EQUAL &&
            CarrySource::Identity(info) == options.preimage_source_identity, "same exclusive regular private target");
    }
    std::array<std::byte, 32> SourceBinding() const noexcept override { return binding; }
    bool ReadBlock(std::uint64_t block, std::uint32_t size, std::vector<std::byte>& out) override
    {
        if (size != 4096 || block >= 4153344 / 4096) return false;
        LARGE_INTEGER at{}; at.QuadPart = static_cast<LONGLONG>(20480 + block * 4096); DWORD count = 0; out.resize(4096);
        return SetFilePointerEx(file.h, at, nullptr, FILE_BEGIN) && ReadFile(file.h, out.data(), size, &count, nullptr) && count == size;
    }
    bool WriteBlock(std::uint64_t block, std::span<const std::byte> bytes) override
    {
        if (bytes.size() != 4096 || block >= 4153344 / 4096) return false;
        LARGE_INTEGER at{}; at.QuadPart = static_cast<LONGLONG>(20480 + block * 4096); DWORD count = 0;
        return SetFilePointerEx(file.h, at, nullptr, FILE_BEGIN) && WriteFile(file.h, bytes.data(), 4096, &count, nullptr) && count == 4096;
    }
    bool Flush() override { return FlushFileBuffers(file.h) != FALSE; }
};
static C::Endpoint CarryEndpoint(const std::shared_ptr<CarrySource>& source, const J::Options& options)
{
    std::string error; auto cp = c::LoadContainerCheckpointView(*source, 0, source->SizeBytes(), error);
    Require(static_cast<bool>(cp), "actual carry endpoint checkpoint:" + error);
    C::Endpoint::Description d;
    d.source_binding = options.witness.protected_persistence->source_binding; d.source_identity = source->SourceIdentity();
    d.container_uuid = options.container_uuid; d.volume_uuid = options.volume_uuid; d.volume_object_id = options.volume_object_id;
    d.container_bytes = source->SizeBytes(); d.checkpoint_xid = cp->superblock.xid;
    d.physical_nx_offset = cp->superblock_physical_block * 4096; d.physical_nx_bytes = cp->superblock_bytes;
    const auto digest = Binding(std::string_view(reinterpret_cast<const char*>(d.physical_nx_bytes.data()), d.physical_nx_bytes.size()));
    std::memcpy(d.physical_nx_sha256.data(), digest.data(), 32);
    return C::Endpoint(std::move(d), [source, expected = *cp](std::string& why) {
        auto current = c::LoadContainerCheckpointView(*source, 0, source->SizeBytes(), why);
        return current && current->superblock_physical_block == expected.superblock_physical_block && current->superblock_bytes == expected.superblock_bytes;
    }, [source](std::uint64_t at, std::span<std::byte> out, std::string&) {
        std::vector<std::byte> bytes;
        if (!source->Read(at, out.size(), bytes) || bytes.size() != out.size()) return false;
        std::copy(bytes.begin(), bytes.end(), out.begin()); SecureZeroMemory(bytes.data(), bytes.size()); return true;
    });
}
static int RunCarry(const std::filesystem::path& root, const std::filesystem::path& image,
    bool require_data = true, bool prepared_startup = false)
{
    Require(root.is_absolute() && image.is_absolute() && root.root_name() == L"D:" && image.root_name() == L"D:" &&
        root.wstring().size() < 120 && !std::filesystem::exists(root), "fresh bounded carry root");
    for (auto p = root.parent_path(); !p.empty(); p = p.parent_path()) {
        const auto attributes = GetFileAttributesW(p.c_str());
        Require(attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_REPARSE_POINT), "carry nonreparse ancestors");
        if (p == p.root_path()) break;
    }
    Require(CreateDirectoryW(root.c_str(), nullptr), "fresh carry directory");
    for (const auto* name : {L"o", L"w", L"pk", L"p"}) Require(CreateDirectoryW((root / name).c_str(), nullptr), "carry authority directory");
    auto credentials = ReceivePair(); auto& error = last_error; error.clear();
    const auto jid = Binding("accepted-v6-continuation-original-v1");
    auto source = std::make_shared<CarrySource>(image); c::PasswordUnlockBudget budget;
    auto transition = c::SoftwareVolumeTransition::PrepareDecryption(source, source->SourceIdentity(), source->Revision(), 1026,
        c::KeybagLength::IncludesHeader, credentials.old_password, budget, jid, error);
    Require(static_cast<bool>(transition), "carry actual decryption capability:" + error);
    J::Options options;
    WriteAheadLog::ProtectedPersistence original{root / L"o", transition->SourceBinding(), jid};
    auto witness = original; witness.key_directory = root / L"w"; witness.journal_identity = Binding("accepted-v6-continuation-witness-v1");
    const auto volume = "carry:" + source->SourceIdentity();
    WriteAheadLog::Options original_options{root / L"o.wal", volume, 4u << 20, original};
    options.witness = {root / L"w.wal", volume + ":witness", 4u << 20, witness};
    options.container_bytes = 4153344; options.container_uuid = transition->RetainedOwners().ContainerUuid();
    options.preimage_source_identity = source->SourceIdentity(); options.volume_object_id = 1026; options.volume_uuid = transition->VolumeUuid();
    options.maintenance_original_journal_identity = jid;
    PayloadSpool::Options spool_options{root / L"p", volume}; spool_options.protected_persistence = true;
    spool_options.protected_binding = original.source_binding; spool_options.protected_key_directory = root / L"pk";
    auto tx = std::make_unique<TransactionManager>(L"conservative"); tx->SetJournalMaxBytesForTest(4u << 20);
    Require(tx->OpenProtectedJournal(original_options.path.wstring(), std::wstring(volume.begin(), volume.end()), original, error), "carry original admission:" + error);
    auto journal = std::make_unique<J>(options); auto spool = std::make_unique<PayloadSpool>(spool_options);
    std::uint64_t accepted = 0;
    Require(journal->AcceptTransition(*tx, *transition, accepted, error), "carry actual accepted v6:" + error);
    std::vector<TransactionManager::AcceptedTransaction> first_original;
    Require(tx->LoadAcceptedTransactionsSinceCleanup(first_original, &error) && first_original.size() == 1,
        "carry actual first original records");
    auto first_witness = journal->witness_.ReadAllWithExclusiveWriterLease();
    Require(first_witness.status == WriteAheadLog::ReadStatus::Ok && !first_witness.recovered_torn_tail && !first_witness.records.empty(),
        "carry first authenticated witness records");
    std::vector<std::byte> first_body;
    for (const auto& row : first_witness.records)
        if (row.path_utf8 == first_witness.records.front().path_utf8)
            first_body.insert(first_body.end(), row.inline_payload.begin(), row.inline_payload.end());
    struct ClearFirst {
        std::vector<std::byte>& body;
        std::vector<TransactionManager::AcceptedTransaction>& original;
        std::vector<WriteAheadLog::Record>& witness;
        ~ClearFirst() {
            SecureZeroMemory(body.data(), body.size());
            for (auto& tx_row : original) for (auto& row : tx_row.mutations) SecureZeroMemory(row.inline_payload.data(), row.inline_payload.size());
            for (auto& row : witness) SecureZeroMemory(row.inline_payload.data(), row.inline_payload.size());
        }
    } clear_first{first_body, first_original, first_witness.records};
    transition.reset(); source.reset();
    const auto publish = [&] {
        Require(journal->RestageTransition(*tx, accepted, error), "carry keyless restage:" + error);
        { CarryTarget target(image, options); Require(journal->PublishOrRecover(*tx, accepted, target, error), "carry actual publication:" + error); }
        Require(tx->MarkCleanedThrough(accepted), "carry actual durable cleanup");
    };
    publish();
    const auto first_accepted = accepted;
    const auto reopen = [&] {
        journal.reset(); tx.reset(); spool.reset();
        tx = std::make_unique<TransactionManager>(L"conservative"); journal = std::make_unique<J>(options);
        spool = std::make_unique<PayloadSpool>(spool_options);
        auto held = std::make_shared<CarrySource>(image); auto endpoint = CarryEndpoint(held, options);
        const bool opened = journal->OpenOrRecoverCleanGeneration(*tx, original_options, *spool, endpoint, error);
        Require(opened, "carry fresh certified reopen:" + error);
        auto owners = journal->RestoreTransitionRetainedOwners(*tx, *held, error);
        Require(owners && owners->OriginalJournalIdentity() == jid && !owners->Generations().empty(), "carry real owner certificate restore:" + error);
        return owners;
    };
    {
        source = std::make_shared<CarrySource>(image); auto endpoint = CarryEndpoint(source, options);
        bool cut = false;
        const auto result = journal->ContinueCleanGeneration(*tx, *spool, endpoint, error, [&](std::string_view stage) {
            if (stage == "continuation-after-old-rename-1") { cut = true; return false; } return true;
        });
        Require(cut && result == C::Result::RecoveryRequired, "carry real v6 promotion cut:" + error); source.reset();
    }
    auto owners = reopen();
    Require(tx->Watermarks().cleanup_sequence == first_accepted, "carry original acceptance identity retained");
    source = std::make_shared<CarrySource>(image); c::PasswordUnlockBudget encrypt_budget;
    transition = c::SoftwareVolumeTransition::PrepareEncryption(source, source->SourceIdentity(), source->Revision(), 1026,
        credentials.new_password, encrypt_budget, jid, owners.get(), error);
    Require(static_cast<bool>(transition), "carry actual encryption after certified restart:" + error);
    if (prepared_startup) {
        const auto before_image = DigestFile(image);
        const auto before_marks = tx->Watermarks();
        std::vector<std::byte> prepared_cipher;
        bool cut = false;
        tx->SetFaultInjectionHook([&](const std::string& stage) {
            if (stage != "transition-after-original-prepared-chunk") return;
            Handle file(CreateFileW(original_options.path.c_str(), GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
            LARGE_INTEGER size{}; DWORD got = 0;
            Require(file.h != INVALID_HANDLE_VALUE && GetFileSizeEx(file.h, &size) &&
                size.QuadPart > 288 && size.QuadPart <= (128u << 10), "capture real bounded prepared ciphertext");
            prepared_cipher.resize(static_cast<std::size_t>(size.QuadPart));
            Require(ReadFile(file.h, prepared_cipher.data(), static_cast<DWORD>(prepared_cipher.size()), &got, nullptr) &&
                got == prepared_cipher.size(), "capture exact post-flush prepared cut");
            cut = true;
            throw std::runtime_error("test prepared original cut");
        });
        std::uint64_t unaccepted = 0;
        Require(!journal->AcceptTransition(*tx, *transition, unaccepted, error) && cut && !unaccepted,
            "real v6 authorization before acceptance");
        tx->SetFaultInjectionHook({});
        source.reset(); transition.reset(); owners.reset(); journal.reset(); tx.reset(); spool.reset();
        const auto retained_abort = root / L"original-with-ordinary-abort.wal";
        const auto abort_hash = DigestFile(original_options.path);
        Require(MoveFileW(original_options.path.c_str(), retained_abort.c_str()), "retain complete ordinary abort evidence");
        {
            Handle file(CreateFileW(original_options.path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
            DWORD written = 0;
            Require(file.h != INVALID_HANDLE_VALUE &&
                WriteFile(file.h, prepared_cipher.data(), static_cast<DWORD>(prepared_cipher.size()), &written, nullptr) &&
                written == prepared_cipher.size() && FlushFileBuffers(file.h), "restore exact captured crash boundary without truncation");
        }
        Require(DigestFile(retained_abort) == abort_hash, "retained abort bytes preserved");
        owners = reopen();
        std::vector<std::uint64_t> spent;
        Require(tx->RecoveryStateValid() && journal->ValidateUnacceptedDispositions(*tx, spent, error) && spent.size() == 1 &&
            tx->NextMutationSequence() == spent.front() + 1 &&
            tx->Watermarks().accepted_sequence == before_marks.accepted_sequence &&
            tx->Watermarks().apfs_durable_sequence == before_marks.apfs_durable_sequence &&
            tx->Watermarks().cleanup_sequence == before_marks.cleanup_sequence &&
            !tx->HasUnappliedAcceptedWork() && DigestFile(image) == before_image,
            "certified startup closes genuine unaccepted v6 suffix without APFS progress");
        const auto next_sequence = tx->NextMutationSequence();
        source = std::make_shared<CarrySource>(image); auto endpoint = CarryEndpoint(source, options);
        Require(journal->ContinueCleanGeneration(*tx, *spool, endpoint, error) == C::Result::Succeeded,
            "all-clean continuation after spent range without later Accepted");
        source.reset(); owners = reopen(); spent.clear();
        Require(journal->ValidateUnacceptedDispositions(*tx, spent, error) && spent.size() == 1 &&
            tx->NextMutationSequence() == next_sequence && tx->Watermarks().cleanup_sequence == before_marks.cleanup_sequence &&
            DigestFile(image) == before_image && DigestFile(retained_abort) == abort_hash,
            "spent certificate and exact earlier accepted owners survive continuation/reopen");
        NoIoTarget no_io; no_io.binding = original.source_binding;
        Require(!journal->PublishOrRecover(*tx, spent.front(), no_io, error) && !no_io.calls,
            "certified spent authorization has zero target access");
        credentials.old_password.Clear(); credentials.new_password.Clear();
        std::cout << "PASS certified real-v6 prepared suffix startup, spent-only continuation/reopen checks=" << checks
            << " imageUnchangedDuringDisposition=true\n";
        return 0;
    }
    Require(journal->AcceptTransition(*tx, *transition, accepted, error) && accepted > first_accepted, "carry second real v6 acceptance:" + error);
    transition.reset(); source.reset(); owners.reset(); publish();
    source = std::make_shared<CarrySource>(image); c::UnlockError unlock{}; c::EncryptedReadError read{};
    auto bags = c::InspectPasswordKeybagMetadata(*source, 1026, c::KeybagLength::IncludesHeader, unlock);
    Require(bags && bags->users.size() == 1, "carry new encrypted selection");
    auto selection = bags->selection; selection.user_uuid = bags->users.front(); c::PasswordUnlockBudget read_budget;
    auto reader = c::ApfsEncryptedReadSession::Unlock(source, source->SourceIdentity(), source->Revision(), selection,
        credentials.new_password.Bytes(), read_budget, read, unlock);
    Require(static_cast<bool>(reader), "carry new encrypted reader");
    const std::array payload{std::byte{0x5B}};
    c::EncryptedMutationRequest request; request.kind = c::EncryptedMutationKind::Create; request.parent = 2;
    request.name = "after-continuation-v6"; request.data = payload;
    const auto data_xid = bags->selection.checkpoint_xid;
    std::unique_ptr<c::EncryptedCowOverwrite> data;
    std::unique_ptr<c::ApfsEncryptedImageWriteSession> data_owner;
    std::unique_ptr<c::ApfsEncryptedImageWriteSession::PreparedMutation> owned_data;
    if (require_data) {
        reader->Close(); reader.reset(); source.reset();
        data_owner = c::ApfsEncryptedImageWriteSession::Open(
            {image.wstring(), 20480, 4153344, 1026, c::KeybagLength::IncludesHeader}, error);
        Require(static_cast<bool>(data_owner), "carry exact exclusive data owner:" + error);
        c::PasswordUnlockBudget owner_budget;
        Require(data_owner->Unlock(credentials.new_password, owner_budget, error), "carry data owner unlock:" + error);
        owned_data = data_owner->PrepareMutationWithTransitionRetention(*tx, *journal, data_xid, request, error);
        Require(static_cast<bool>(owned_data), "carry source-bound accepted-v6 owner preparation:" + error);
    } else data = reader->PrepareMutation(*source, data_xid, request, error);
    if (!data && !require_data) {
        Require(error.starts_with("SoftwareKeybagEraWrappedKeyOrCryptoStateChanged:retained-xid-"),
            "carry explicit existing post-transition data refusal");
        reader->Close(); reader.reset(); source.reset();
        const auto before = DigestFile(image); const auto boundary = tx->Watermarks().cleanup_sequence;
        source = std::make_shared<CarrySource>(image); auto endpoint = CarryEndpoint(source, options);
        Require(journal->ContinueCleanGeneration(*tx, *spool, endpoint, error) == C::Result::Succeeded,
            "carry two genuine accepted v6 authorizations");
        source.reset(); owners = reopen();
        TransactionManager::AcceptedTransaction certified; bool found = false;
        Require(journal->ReadCertifiedTransitionOriginal(*tx, first_accepted, first_body, certified, found, error) && found &&
            certified.transaction_id == first_original.front().transaction_id &&
            certified.accepted_sequence == first_accepted && certified.mutations.size() == first_original.front().mutations.size(),
            "carry earlier v6 exact certified original survives later v6");
        for (std::size_t n = 0; n < certified.mutations.size(); ++n) {
            Require(WriteAheadLog::EncodeForTest(certified.mutations[n]) == WriteAheadLog::EncodeForTest(first_original.front().mutations[n]),
                "carry exact original semantic record identity");
            SecureZeroMemory(certified.mutations[n].inline_payload.data(), certified.mutations[n].inline_payload.size());
        }
        auto retained = journal->witness_.ReadAllWithExclusiveWriterLease();
        Require(retained.status == WriteAheadLog::ReadStatus::Ok && !retained.recovered_torn_tail, "carry re-sealed witness readable");
        for (const auto& expected : first_witness.records) {
            const auto actual = std::find_if(retained.records.begin(), retained.records.end(), [&](const auto& row) { return row.sequence == expected.sequence; });
            Require(actual != retained.records.end() && WriteAheadLog::EncodeForTest(*actual) == WriteAheadLog::EncodeForTest(expected),
                "carry earlier v6 exact witness identity and sequence");
        }
        for (auto& row : retained.records) SecureZeroMemory(row.inline_payload.data(), row.inline_payload.size());
        Require(tx->Watermarks().cleanup_sequence == boundary && DigestFile(image) == before,
            "carry exact acceptance and image preserved by second continuation");
        credentials.old_password.Clear(); credentials.new_password.Clear();
        std::cout << "PASS accepted-v6 certificate carry, cut/reopen, later-v6 exact original/witness identity checks=" << checks
            << " postTransitionDataUnsupported=true laterDataCredit=false\n";
        return 0;
    }
    Require(data || owned_data, "carry genuine following data capability:" + error);
    const auto& capability = owned_data ? owned_data->Intent() : *data;
    const auto data_inode = capability.IntentInode();
    TransactionManager::MutationIntent intent; intent.kind = TransactionManager::MutationKind::CreateFile;
    intent.path.assign(request.name.begin(), request.name.end()); intent.object_id = capability.IntentInode(); intent.generation = 2;
    intent.offset = capability.RequestedPermissions(); intent.length = intent.payload_length = payload.size();
    intent.inline_payload.assign(payload.begin(), payload.end()); intent.payload_checksum = capability.IntentSha256();
    Require(tx->ProtectedMutationCapacityAvailable(intent, error) && tx->Begin() && tx->RecordMutation(intent) && tx->Accept(data_xid),
        "carry genuine data original acceptance");
    accepted = tx->Watermarks().accepted_sequence;
    if (owned_data) {
        Require(data_owner->CommitAcceptedPrepared(*tx, *journal, accepted, data_xid, std::move(owned_data), error),
            "carry actual retained-owner following data publication:" + error);
        data_owner->Close(); data_owner.reset();
    } else {
        Require(journal->Stage(*tx, accepted, *data, error), "carry genuine data witness:" + error);
        data.reset(); reader->Close(); reader.reset(); source.reset();
        CarryTarget target(image, options);
        Require(journal->PublishOrRecover(*tx, accepted, target, error), "carry actual following data publication:" + error);
    }
    Require(tx->MarkCleanedThrough(accepted), "carry following data cleanup");
    const auto image_before = DigestFile(image);
    {
        source = std::make_shared<CarrySource>(image); auto endpoint = CarryEndpoint(source, options);
        Require(journal->ContinueCleanGeneration(*tx, *spool, endpoint, error) == C::Result::Succeeded, "carry earlier v6 through later data:" + error);
        source.reset();
    }
    owners = reopen();
    Require(owners && tx->Watermarks().cleanup_sequence == accepted && DigestFile(image) == image_before,
        "carry earlier v6 after later data keeps exact image and acceptance");
    source = std::make_shared<CarrySource>(image);
    bags = c::InspectPasswordKeybagMetadata(*source, 1026, c::KeybagLength::IncludesHeader, unlock);
    Require(bags && bags->users.size() == 1, "carry final canonical encrypted selection");
    selection = bags->selection; selection.user_uuid = bags->users.front(); c::PasswordUnlockBudget final_budget;
    reader = c::ApfsEncryptedReadSession::Unlock(source, source->SourceIdentity(), source->Revision(), selection,
        credentials.new_password.Bytes(), final_budget, read, unlock);
    c::EncryptedDirectoryEntry entry; std::vector<std::byte> actual;
    Require(reader && reader->Lookup(2, request.name, entry) == c::EncryptedReadError::None && entry.inode_id == data_inode &&
        reader->ReadFile(data_inode, 0, payload.size(), actual) == c::EncryptedReadError::None &&
        std::equal(actual.begin(), actual.end(), payload.begin(), payload.end()), "carry final exact canonical name, inode and payload");
    SecureZeroMemory(actual.data(), actual.size()); reader->Close(); reader.reset(); source.reset();
    journal.reset(); tx.reset(); spool.reset(); owners.reset(); credentials.old_password.Clear(); credentials.new_password.Clear();
    std::cout << "PASS actual v6->continuation cut/reopen->v6->data->continuation/reopen checks=" << checks << '\n';
    return 0;
}
