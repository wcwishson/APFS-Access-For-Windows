#define wmain PrimitiveKeybagMain
#include "ApfsSoftwareKeybagMaintenanceTests.cpp"
#undef wmain
#include "ApfsSoftwareKeybagPublication.h"
#undef CreateFile
#undef CreateDirectory
#include "EncryptedPublicationJournal.h"
#include "ProtectedJournalEpoch.h"
#include <fstream>
#include <iomanip>
#include <limits>
#include <set>

namespace
{
constexpr wchar_t journal_root[] = L"D:\\ApfsAccessScratch\\WindowsClosure\\software-keybag-journal-20261016";

struct PreparedKeybagFixture
{
    std::unique_ptr<c::SoftwareKeybagPublication> publication;
    std::uint64_t volume_oid = 0;
    std::string volume_uuid;
};

PreparedKeybagFixture PrepareKeybagFixture(const std::filesystem::path& image,
    Credentials& credentials)
{
    const Profile profile{false};
    Check(image.wstring().starts_with(std::wstring(journal_root) + L"\\run-"), "JournalPrivateImage");
    auto lease = std::make_shared<t::WindowsImageLease>(image.wstring());
    auto source = std::make_shared<t::OwnedEncryptedImageSource>(lease, profile.Base(), profile.Size());
    c::UnlockError unlock{};
    const auto metadata = c::InspectPasswordKeybagMetadata(*source, 1026,
        c::KeybagLength::IncludesHeader, unlock);
    Check(metadata && metadata->users.size() == 1, "JournalAuthenticSelection");
    PreparedKeybagFixture fixture;
    fixture.volume_oid = metadata->selection.volume_oid;
    fixture.volume_uuid = c::BytesToHexLower(metadata->selection.volume_uuid.data(), metadata->selection.volume_uuid.size());
    const auto identity = source->SourceIdentity();
    c::PasswordUnlockBudget budget;
    auto owner = c::SoftwareKeybagRewrap::Prepare(source, identity, source->Revision(),
        fixture.volume_oid, c::KeybagLength::IncludesHeader, credentials.old_password,
        credentials.new_password, budget, unlock);
    Check(static_cast<bool>(owner), "JournalBoundRewrap");
    std::string error;
    fixture.publication = owner->PreparePublication(credentials.old_password,
        credentials.new_password, budget, error);
    Check(static_cast<bool>(fixture.publication), "JournalPrivatePublication");
    Check(fixture.publication->SourceIdentity() == identity &&
        fixture.publication->VolumeObjectId() == fixture.volume_oid &&
        fixture.publication->VolumeUuid() == fixture.volume_uuid, "JournalCapturedVolumeSelection");
    owner.reset();
    Check(source.use_count() == 1, "JournalSourceReleased");
    source.reset();
    Check(lease.use_count() == 1, "JournalLeaseReleased");
    lease.reset();
    credentials.new_password.Clear();
    credentials.old_password.Clear();
    return fixture;
}

int CapturedVolumeCase(const std::filesystem::path& image)
{
    auto credentials = ReceivePair();
    auto fixture = PrepareKeybagFixture(image, credentials);
    Check(fixture.publication->VolumeObjectId() == fixture.volume_oid &&
        fixture.publication->VolumeUuid() == fixture.volume_uuid, "JournalSelectionSurvivesOwnerRelease");
    std::cout << "{\"capturedVolumeObjectId\":" << fixture.publication->VolumeObjectId()
        << ",\"capturedVolumeUuid\":\"" << fixture.publication->VolumeUuid()
        << "\",\"ownerReleased\":true,\"protectedJournalExercised\":false}\n";
    return 0;
}

int CapturedVolumeDriver(const std::filesystem::path& executable)
{
    const Profile profile{false};
    const auto run = std::filesystem::path(journal_root) /
        (L"run-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64()) + L"-getters");
    std::filesystem::create_directory(run);
    const auto original = std::filesystem::path(fixtures) / profile.Name();
    const auto image = run / profile.Name();
    Check(DigestFile(original) == profile.Pin(), "JournalOriginalPin");
    Check(CopyFileW(original.c_str(), image.c_str(), TRUE), "JournalPrivateCopy");
    auto old_password = NoteCredential(profile), new_password = RandomCredential();
    auto pair = Pair(old_password.Bytes(), new_password.Bytes());
    const auto result = Child(executable, L"keybag-getters dfvfs " + Quoted(image),
        pair.Bytes(), run / L"binding.log");
    pair.Clear();
    Check(result == 0, "JournalCapturedVolumeChild");
    Check(DigestFile(image) == profile.Pin() && DigestFile(original) == profile.Pin(), "JournalNoPhysicalWrites");
    for (const auto& entry : std::filesystem::directory_iterator(run))
        if (entry.is_regular_file()) Absent(entry.path(), old_password.Bytes(), new_password.Bytes());
    std::wcout << L"EVIDENCE " << run.wstring() << L"\n";
    return 0;
}
}

namespace
{
namespace r = apfsaccess::rw;
using Tx = r::TransactionManager;
using Wal = r::WriteAheadLog;
using Journal = r::EncryptedPublicationJournal;
using Digest32 = std::array<std::uint8_t, 32>;
Digest32 Sha(Bytes bytes)
{
    Digest32 out{};
    Check(bytes.size() <= ULONG_MAX && BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0,
        reinterpret_cast<PUCHAR>(const_cast<std::byte*>(bytes.data())), static_cast<ULONG>(bytes.size()),
        out.data(), static_cast<ULONG>(out.size())) >= 0, "JournalSha256");
    return out;
}
std::array<std::byte, 32> Binding(std::string_view text)
{
    const auto hash = Sha(std::as_bytes(std::span(text)));
    std::array<std::byte, 32> out{};
    std::transform(hash.begin(), hash.end(), out.begin(), [](auto b) { return static_cast<std::byte>(b); });
    return out;
}
std::string FileIdentity(const BY_HANDLE_FILE_INFORMATION& id)
{
    return "windows-file:" + std::to_string(id.dwVolumeSerialNumber) + ":" +
        std::to_string((std::uint64_t(id.nFileIndexHigh) << 32) | id.nFileIndexLow) + ":" +
        std::to_string((std::uint64_t(id.nFileSizeHigh) << 32) | id.nFileSizeLow) + ":" +
        std::to_string((std::uint64_t(id.ftLastWriteTime.dwHighDateTime) << 32) | id.ftLastWriteTime.dwLowDateTime);
}
std::string FileOwnerIdentity(std::string id)
{
    constexpr std::string_view scope = ":scope:20480:4153344";
    if (id.ends_with(scope)) id.resize(id.size() - scope.size());
    return id;
}
std::string StableIdentity(std::string id) { id = FileOwnerIdentity(std::move(id)); id.resize(id.rfind(':')); return id; }
struct ExpectedBlock { std::uint64_t block = 0; std::string sha; };
struct JournalState
{
    std::string identity, container_uuid, volume_uuid;
    std::uint64_t volume_oid = 0, before_xid = 0, after_xid = 0, accepted = 0, switch_block = 0;
    std::vector<ExpectedBlock> writes, guards;
    std::string Volume() const { return "apfs-vol:" + container_uuid + ":" + std::to_string(volume_oid); }
    std::array<std::byte, 32> SourceBinding(std::string identity_value = {}) const
    {
        return Binding(StableIdentity(identity_value.empty() ? identity : identity_value) + ":20480:4153344:" +
            container_uuid + ":" + std::to_string(volume_oid) + ":" + volume_uuid);
    }
};
void SaveState(const std::filesystem::path& run, const JournalState& s)
{
    std::ofstream out(run / L"fixture-state.txt");
    out << "E05FIXTURE1\n" << std::quoted(s.identity) << '\n' << std::quoted(s.container_uuid) << '\n'
        << std::quoted(s.volume_uuid) << '\n' << s.volume_oid << ' ' << s.before_xid << ' ' << s.after_xid << ' '
        << s.accepted << ' ' << s.switch_block << '\n';
    for (const auto* list : {&s.writes, &s.guards}) {
        out << list->size() << '\n';
        for (const auto& block : *list) out << block.block << ' ' << block.sha << '\n';
    }
    Check(static_cast<bool>(out), "JournalTrustedFixtureStateWrite");
}
JournalState LoadState(const std::filesystem::path& run)
{
    Check(run.wstring().starts_with(std::wstring(journal_root) + L"\\run-") &&
        std::filesystem::file_size(run / L"fixture-state.txt") < 65536, "JournalTrustedFixtureStatePath");
    JournalState s; std::ifstream in(run / L"fixture-state.txt"); std::string magic;
    in >> magic >> std::quoted(s.identity) >> std::quoted(s.container_uuid) >> std::quoted(s.volume_uuid)
        >> s.volume_oid >> s.before_xid >> s.after_xid >> s.accepted >> s.switch_block;
    Check(magic == "E05FIXTURE1" && s.volume_oid == 1026 && s.before_xid >= 7 && s.before_xid <= 8 &&
        s.after_xid == s.before_xid + 1 && s.accepted, "JournalFixtureStateBounds");
    for (auto* list : {&s.writes, &s.guards}) {
        std::size_t count = 0; in >> count; Check(count <= 192, "JournalFixtureBlockCount");
        for (std::size_t i = 0; i < count; ++i) {
            ExpectedBlock block; in >> block.block >> block.sha;
            Check(block.block < 4153344 / 4096 && block.sha.size() == 64, "JournalFixtureBlockBounds"); list->push_back(std::move(block));
        }
    }
    Check(static_cast<bool>(in), "JournalTrustedFixtureStateRead"); return s;
}
Wal::ProtectedPersistence Protection(const std::filesystem::path& run, const JournalState& s, std::string_view stream)
{
    return {run / (std::string(stream) + "-keys"), s.SourceBinding(), Binding(stream), {64ULL << 20, 65536}, 256ULL << 20};
}
Journal::Options Options(const std::filesystem::path& run, const JournalState& s, std::string_view stream = "witness")
{
    Journal::Options o;
    o.witness = {run / (std::string(stream) + ".wal"), s.Volume() + ":maintenance-witness", 64ULL << 20, Protection(run, s, stream)};
    o.container_bytes = 4153344; o.container_uuid = s.container_uuid; o.preimage_source_identity = s.identity;
    o.volume_object_id = s.volume_oid; o.volume_uuid = s.volume_uuid;
    o.maintenance_original_journal_identity = Protection(run, s, "original").journal_identity; return o;
}
std::unique_ptr<Tx> OpenTx(const std::filesystem::path& run, const JournalState& s, bool wrong_binding = false, bool change_source = true,
    std::uint64_t max_bytes = 0)
{
    auto tx = std::make_unique<Tx>(L"Conservative"); auto p = Protection(run, s, wrong_binding ? "other-original" : "original");
    if (max_bytes) tx->SetJournalMaxBytesForTest(max_bytes);
    if (wrong_binding && change_source) p.source_binding.front() ^= std::byte{1};
    std::string error; const auto volume = s.Volume();
    const bool opened = tx->OpenProtectedJournal((run / (wrong_binding ? L"other-original.wal" : L"original.wal")).wstring(),
        std::wstring(volume.begin(), volume.end()), p, error);
    if (!opened) throw std::runtime_error("JournalOriginalOpen:" + error);
    Check(tx->RecoveryStateValid(), "JournalOriginalRecoveryValid"); return tx;
}
std::unique_ptr<Tx> OpenSameJidAlternateTx(const std::filesystem::path& run, const JournalState& s)
{
    auto tx = std::make_unique<Tx>(L"Conservative"); auto p = Protection(run, s, "other-original");
    p.journal_identity = Protection(run, s, "original").journal_identity;
    const auto volume = s.Volume(); std::string error;
    Check(tx->OpenProtectedJournal((run / L"other-original.wal").wstring(), std::wstring(volume.begin(), volume.end()), p, error),
        "JournalSameJidAlternateOriginalControl"); return tx;
}
std::vector<std::byte> OriginalInlineBlob(Tx& tx, const JournalState& s)
{
    std::vector<Tx::AcceptedTransaction> accepted; std::string error;
    Check(tx.LoadAcceptedTransactionsSinceCleanup(accepted, &error) && accepted.size() == 1 &&
        accepted.front().accepted_sequence == s.accepted && accepted.front().preimage_checkpoint_xid == s.before_xid &&
        !accepted.front().mutations.empty(), "JournalAuthenticatedOriginalBoundary");
    std::vector<std::byte> blob;
    for (const auto& m : accepted.front().mutations) {
        Check(m.operation == Wal::OperationKind::Write && m.path_utf8 == Tx::WideToUtf8(std::wstring(Journal::MaintenanceAcceptancePath)) &&
            !m.inline_payload.empty() && m.inline_payload.size() <= 4096 && m.object_id == s.volume_oid &&
            m.parent_object_id == s.before_xid && m.logical_offset == blob.size() && !m.payload_offset &&
            m.payload_length == m.logical_length && m.payload_length == m.inline_payload.size() && Sha(m.inline_payload) == m.payload_sha256,
            "JournalAuthenticatedOriginalInlineChunk");
        blob.insert(blob.end(), m.inline_payload.begin(), m.inline_payload.end());
    }
    return blob;
}
class JournalTarget final : public r::EncryptedPublicationTarget
{
    Handle file_; const JournalState& state_; std::array<std::byte, 32> binding_{};
public:
    std::size_t writes = 0, flushes = 0, attempts = 0, fail_after = SIZE_MAX, torn_bytes = 0;
    bool tear = false; std::function<void()> before_write;
    JournalTarget(const std::filesystem::path& image, const JournalState& s, bool first, bool wrong = false) : state_(s)
    {
        Check(image.wstring().starts_with(std::wstring(journal_root) + L"\\run-"), "JournalExclusivePrivatePath");
        for (unsigned retry = 0; retry < 40; ++retry) {
            file_.h = CreateFileW(image.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_RANDOM_ACCESS, nullptr);
            if (file_.h != INVALID_HANDLE_VALUE) break;
            const auto os = GetLastError();
            if (os != ERROR_SHARING_VIOLATION && os != ERROR_LOCK_VIOLATION) break; Sleep(50);
        }
        Check(file_.h != INVALID_HANDLE_VALUE, "JournalExclusivePrivateHandle"); BY_HANDLE_FILE_INFORMATION id{};
        Check(GetFileType(file_.h) == FILE_TYPE_DISK && GetFileInformationByHandle(file_.h, &id) &&
            !(id.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DEVICE)) &&
            StableIdentity(FileIdentity(id)) == StableIdentity(s.identity) && (!first || FileIdentity(id) == FileOwnerIdentity(s.identity)), "JournalHeldFileIdentity");
        binding_ = s.SourceBinding(FileIdentity(id)); if (wrong) binding_.front() ^= std::byte{1};
    }
    std::array<std::byte, 32> SourceBinding() const noexcept override { return binding_; }
    bool ReadBlock(std::uint64_t block, std::uint32_t size, std::vector<std::byte>& out) override
    {
        out.clear(); if (size != 4096 || block >= 4153344 / 4096) return false;
        LARGE_INTEGER at{}; at.QuadPart = static_cast<LONGLONG>(20480 + block * 4096); DWORD got = 0; out.resize(4096);
        return SetFilePointerEx(file_.h, at, nullptr, FILE_BEGIN) && ReadFile(file_.h, out.data(), 4096, &got, nullptr) && got == 4096;
    }
    bool WriteBlock(std::uint64_t block, Bytes bytes) override
    {
        ++attempts; if (before_write) before_write(); if (writes == fail_after) return false;
        if (bytes.size() != 4096 || block >= 4153344 / 4096) return false;
        LARGE_INTEGER at{}; at.QuadPart = static_cast<LONGLONG>(20480 + block * 4096); DWORD put = 0;
        const DWORD count = tear && block == state_.switch_block ? 32 : 4096;
        if (!SetFilePointerEx(file_.h, at, nullptr, FILE_BEGIN) || !WriteFile(file_.h, bytes.data(), count, &put, nullptr) || put != count) return false;
        if (count != 4096) { torn_bytes = count; return false; } ++writes; return true;
    }
    bool Flush() override { ++flushes; return FlushFileBuffers(file_.h) != FALSE; }
};
bool Negative(std::wstring_view mode) { return mode.starts_with(L"wrong-") || mode.starts_with(L"m1-") || mode == L"later-prefix" || mode == L"differing-prefix" || mode == L"torn-frame"; }
bool FirstNew(std::wstring_view mode) { return mode == L"commit" || mode == L"durable-restage" || mode == L"after-switch" || mode == L"lost-watermark" || mode == L"history-v4-v2-stage"; }
std::uint64_t AcceptInlineChunks(Tx& tx, const std::vector<Tx::MutationIntent>& chunks, std::uint64_t preimage)
{
    Check(tx.Begin(), "JournalOriginalBegin"); std::size_t flushed = 0;
    for (const auto& chunk : chunks) {
        SetLastError(ERROR_SUCCESS); const bool recorded = tx.RecordMutation(chunk); const auto record_os = GetLastError();
        const bool flush = recorded && tx.FlushPreparedRecords(); const auto flush_os = GetLastError();
        if (!recorded || !flush) std::cout << "ORIGINAL_CHUNK_FAILURE index=" << flushed << " recordWin32=" << record_os << " flushWin32=" << flush_os << std::endl;
        Check(recorded && flush, "JournalEachOriginalInlineChunkPreparedAndFlushed"); ++flushed;
    }
    SetLastError(ERROR_SUCCESS); const bool accepted = tx.Accept(preimage); const auto os = GetLastError();
    std::cout << "ORIGINAL_TM chunks=" << chunks.size() << " preparedFlushes=" << flushed << " accepted=" << accepted << " win32=" << os << std::endl;
    Check(accepted && tx.Watermarks().accepted_sequence && !tx.Watermarks().apfs_durable_sequence, "JournalOriginalAcceptedInlineCiphertextChunks");
    return tx.Watermarks().accepted_sequence;
}
void AddLaterPrefix(const std::filesystem::path& run, const JournalState& s, bool differing)
{
    const auto options = Options(run, s); std::vector<Wal::Record> records;
    { Wal wal(options.witness); auto read = wal.ReadAll(); Check(read.status == Wal::ReadStatus::Ok && !read.records.empty(), "JournalReadableWitnessForControl"); records = std::move(read.records); }
    auto record = records.front();
    auto destination = options.witness;
    if (differing) {
        destination = Options(run, s, "mismatched").witness; record.inline_payload.back() ^= std::byte{1}; record.payload_sha256 = Sha(record.inline_payload);
    } else { record.sequence = records.back().sequence + 1; ++record.transaction_id; record.parent_object_id = s.accepted + 1; }
    Wal wal(destination); Check(wal.Append(record, true), "JournalAuthenticatedNegativePrefixPersisted");
}
void AddM1CompleteGroup(const std::filesystem::path& run, const JournalState& s, bool wrong_transaction)
{
    std::vector<Wal::Record> records;
    { Wal original(Options(run, s).witness); auto read = original.ReadAll();
      Check(read.status == Wal::ReadStatus::Ok && read.records.size() > 2, "M1AuthenticCompleteGroupSource"); records = std::move(read.records); }
    Check(records.back().path_utf8 == "\\encrypted-publication-end-v2" && records.back().inline_payload.size() >= 64,
        "M1ExistingCompleteFooter");
    for (auto& row : records) {
        if (wrong_transaction) ++row.transaction_id; else ++row.object_id;
    }
    auto& end = records.back(); const auto at = wrong_transaction ? 16u : 24u;
    const auto value = wrong_transaction ? end.transaction_id : end.object_id;
    for (unsigned i = 0; i < 8; ++i) end.inline_payload[at + i] = static_cast<std::byte>(value >> (8 * i));
    end.payload_sha256 = Sha(end.inline_payload);
    Wal mismatched(Options(run, s, "m1").witness);
    for (const auto& row : records) Check(mismatched.Append(row, false), "M1RealAuthenticatedCompleteRecord");
    Check(mismatched.FlushPendingAppends(), "M1CompleteAuthenticatedGroupDurable");
}
bool TearControl(std::wstring_view mode) { return mode.starts_with(L"tear-") || mode.starts_with(L"wrong-tear-") || mode == L"history-v2-v4-tear"; }
void PrepareWitnessTear(const std::filesystem::path& run, const JournalState& s, std::wstring_view mode)
{
    if (mode == L"wrong-tear-later-group") AddLaterPrefix(run, s, false);
    const auto path = Options(run, s).witness.path;
    std::size_t records = 0, first_selected = 0;
    { Wal wal(Options(run, s).witness); auto read = wal.ReadAll();
      Check(read.status == Wal::ReadStatus::Ok && read.records.size() >= 60, "JournalAuthenticFullWitnessBeforeTear"); records = read.records.size();
      const auto selected = std::find_if(read.records.begin(), read.records.end(), [&](const auto& row) { return row.parent_object_id == s.accepted; });
      Check(selected != read.records.end(), "JournalActualSelectedCertificateBeforeTear");
      first_selected = static_cast<std::size_t>(selected - read.records.begin()); }
    const auto size = std::filesystem::file_size(path);
    Check(size > 4096 && size < (1ULL << 20), "JournalBoundedProtectedWitnessFixture");
    std::vector<std::byte> bytes(static_cast<std::size_t>(size));
    { std::ifstream in(path, std::ios::binary); in.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
      Check(static_cast<bool>(in), "JournalWitnessFrameObservationRead"); }
    struct Frame { std::size_t offset, bytes; }; std::vector<Frame> frames;
    // Observe the already authenticated writer output; these offsets confer no authority.
    for (std::size_t at = 16; at < bytes.size();) {
        Check(bytes.size() - at >= 64 && std::memcmp(bytes.data() + at, "APFSREC1", 8) == 0 &&
            c::ReadU32LE(bytes, at + 8) == 1 && c::ReadU32LE(bytes, at + 12) == 64, "JournalExistingProtectedFrameHeader");
        const auto length = c::ReadU32LE(bytes, at + 16).value_or(0);
        Check(length >= 80 && length <= bytes.size() - at, "JournalExistingProtectedFrameLength");
        frames.push_back({at, length}); at += length;
    }
    Check(frames.size() == records + 1, "JournalFrameCountIncludesExistingAnchor");
    Check(CopyFileW(path.c_str(), (run / L"witness-before-damage.wal").c_str(), TRUE), "JournalPreserveFullWitnessBeforeDamage");
    if (mode == L"wrong-tear-bad-tag") {
        bytes.back() ^= std::byte{1}; std::fstream out(path, std::ios::in | std::ios::out | std::ios::binary);
        out.seekp(-1, std::ios::end); out.write(reinterpret_cast<const char*>(&bytes.back()), 1);
        Check(static_cast<bool>(out), "JournalFullFrameTagDamage"); out.close();
    } else {
        std::size_t index = first_selected + 2, prefix = 1;
        if (mode == L"tear-middle-prefix") { index = frames.size() / 2; prefix = frames[index].bytes / 2; }
        if (mode == L"tear-final-prefix") { index = frames.size() - 1; prefix = frames[index].bytes - 1; }
        if (mode == L"wrong-tear-no-cert") { index = 1; prefix = frames[index].bytes / 2; }
        if (mode == L"wrong-tear-later-group") { index = frames.size() - 1; prefix = 16; }
        Check(prefix && prefix < frames[index].bytes, "JournalProperExistingFrameEofPrefix");
        std::filesystem::resize_file(path, frames[index].offset + prefix);
        std::cout << "WITNESS_TEAR frame=" << index << " prefix=" << prefix << " completeFrameBytes=" << frames[index].bytes << '\n';
    }
    Check(CopyFileW(path.c_str(), (run / L"witness-damaged.wal").c_str(), TRUE), "JournalRetainExactDamagedWitness");
}
void CheckTornWitnessArchive(const std::filesystem::path& run)
{
    const auto damaged = DigestFile(run / L"witness-damaged.wal"); std::size_t archives = 0;
    for (const auto& item : std::filesystem::directory_iterator(run))
        if (item.is_regular_file() && item.path().filename().wstring().starts_with(L"witness.wal.wrsaved.")) {
            Check(DigestFile(item.path()) == damaged, "JournalRawTornWitnessArchiveExact"); ++archives;
        }
    Check(archives == 1, "JournalOneRetainedTornWitnessArchive");
    std::cout << "WITNESS_REPAIR archiveVerified=true originalUnchanged=true\n";
}
class NoIoTarget final : public r::EncryptedPublicationTarget
{
    std::array<std::byte, 32> binding_;
public:
    unsigned reads = 0, writes = 0, flushes = 0;
    explicit NoIoTarget(const JournalState& s) : binding_(s.SourceBinding()) {}
    std::array<std::byte, 32> SourceBinding() const noexcept override { return binding_; }
    bool ReadBlock(std::uint64_t, std::uint32_t, std::vector<std::byte>&) override { ++reads; return false; }
    bool WriteBlock(std::uint64_t, Bytes) override { ++writes; return false; }
    bool Flush() override { ++flushes; return false; }
};
std::uint64_t AcceptPrivateMaintenance(Journal& journal, Tx& tx,
    const c::SoftwareKeybagPublication& proof, std::size_t chunks)
{
    std::size_t witness_flushes = 0, original_flushes = 0, recorded = 0, accept_starts = 0;
    std::size_t witness_appends = 0, complete_authorization_flushes = 0, prepared_flushes = 0, acceptance_flushes = 0;
    std::set<std::size_t> prepared_flush_phases;
    const auto expected = tx.NextMutationSequence() + chunks;
    journal.SetWitnessFaultInjectionHook([&](std::string_view stage) {
        if (stage == "protected-before-write") ++witness_appends;
        if (stage == "durable-flush") {
            Check(!recorded && !accept_starts && !tx.Watermarks().accepted_sequence && !tx.PendingMutationCount(),
                "JournalPrivateWitnessFlushBeforeAnyOriginalMutation");
            ++witness_flushes;
            if (witness_appends == chunks + 1) ++complete_authorization_flushes;
        }
        return false;
    });
    tx.SetJournalFaultInjectionHook([&](std::string_view stage) {
        if (stage == "protected-before-write") Check(complete_authorization_flushes == 1, "JournalPrivateWitnessBeforeOriginalAppend");
        if (stage == "durable-flush") {
            ++original_flushes;
            if (accept_starts) ++acceptance_flushes;
            else if (recorded) { prepared_flush_phases.insert(recorded); prepared_flushes = prepared_flush_phases.size(); }
        }
        return false;
    });
    tx.SetFaultInjectionHook([&](const std::string& stage) {
        if (stage == "mutation-recorded") ++recorded;
        if (stage == "accept-start") {
            Check(complete_authorization_flushes == 1 && prepared_flushes == chunks && recorded == chunks,
                "JournalPrivateWitnessBeforeOriginalAccept"); ++accept_starts;
        }
    });
    std::uint64_t accepted = 0; std::string error;
    const bool result = journal.AcceptMaintenance(tx, proof, accepted, error);
    journal.SetWitnessFaultInjectionHook({}); tx.SetJournalFaultInjectionHook({}); tx.SetFaultInjectionHook({});
    std::cout << "PRIVATE_AUTH_OBSERVED expected=" << expected << " accepted=" << accepted << " watermark=" << tx.Watermarks().accepted_sequence
        << " durable=" << tx.Watermarks().apfs_durable_sequence << " witnessFlushes=" << witness_flushes << " recorded=" << recorded
        << " originalFlushes=" << original_flushes << " acceptStarts=" << accept_starts << std::endl;
    Check(result, ("JournalPrivateAcceptMaintenance:" + error).c_str());
    Check(accepted == expected && accepted == tx.Watermarks().accepted_sequence && !tx.Watermarks().apfs_durable_sequence &&
        complete_authorization_flushes == 1 && witness_flushes == 2 && recorded == chunks && prepared_flushes == chunks &&
        original_flushes == chunks + 2 && acceptance_flushes == 1 && accept_starts == 1,
        "JournalExactPrivateAcceptanceBoundaryAndIncrementalFlushes");
    std::cout << "ORIGINAL_TM chunks=" << chunks << " preparedFlushes=" << prepared_flushes << " accepted=1 win32=0\n";
    std::cout << "PRIVATE_AUTH witnessFlushes=" << witness_flushes << " beforeOriginalMutations=true beforeOriginalAccept=true expectedBoundary="
        << expected << " actualBoundary=" << accepted << '\n';
    return accepted;
}

JournalState PlanState(const std::string& identity, std::uint64_t oid, const std::string& uuid,
    const r::AppleCheckpointPublicationPlan& plan)
{
    JournalState s; s.identity = identity; s.volume_oid = oid; s.volume_uuid = uuid;
    s.container_uuid = plan.published_checkpoint.superblock.uuid_hex;
    s.before_xid = plan.expected_checkpoint_xid; s.after_xid = plan.transaction_xid;
    s.switch_block = plan.superblock_write.physical_block;
    for (const auto& write : plan.before_superblock_writes) s.writes.push_back({write.physical_block, Digest(write.bytes)});
    s.writes.push_back({plan.superblock_write.physical_block, Digest(plan.superblock_write.bytes)});
    for (const auto& guard : plan.guard_blocks) s.guards.push_back({guard.physical_block, Digest(guard.bytes)});
    return s;
}
struct HistoryData
{
    std::unique_ptr<c::EncryptedCowOverwrite> proof;
    JournalState state;
    Tx::MutationIntent intent;
};
HistoryData PrepareHistoryData(const std::filesystem::path& image, Bytes password)
{
    const Profile profile{false};
    auto lease = std::make_shared<t::WindowsImageLease>(image.wstring());
    auto source = std::make_shared<t::OwnedEncryptedImageSource>(lease, profile.Base(), profile.Size());
    c::UnlockError unlock{}; c::EncryptedReadError read_error{}; c::PasswordUnlockBudget budget; std::string error;
    auto metadata = c::InspectPasswordKeybagMetadata(*source, 1026, c::KeybagLength::IncludesHeader, unlock);
    Check(metadata && metadata->users.size() == 1, "HistoryAuthenticDataSelector");
    auto selection = metadata->selection; selection.user_uuid = metadata->users.front();
    auto session = c::ApfsEncryptedReadSession::Unlock(source, source->SourceIdentity(), source->Revision(),
        selection, password, budget, read_error, unlock);
    Check(static_cast<bool>(session), "HistoryRealUnlockedDataSession");
    auto context = session->CreateMetadataReadContext(read_error);
    Check(static_cast<bool>(context), "HistoryDataReadContext");
    auto current = c::LoadAppleCheckpointView(*source, 0, profile.Size(), error, *context);
    Check(static_cast<bool>(current), "HistoryCurrentAllocatorAndCheckpoint");
    std::vector<std::byte> original;
    Check(session->ReadFile(21, 0, 1, original) == c::EncryptedReadError::None && original.size() == 1, "HistoryReadExactUnchangedByte");
    HistoryData data;
    data.proof = session->PrepareCowOverwrite(*source, current->container.superblock.xid, 21, 0, original, error);
    Check(static_cast<bool>(data.proof), ("HistoryRealDataCapability:" + error).c_str());
    data.state = PlanState(data.proof->SourceIdentity(), data.proof->VolumeObjectId(), data.proof->VolumeUuid(), data.proof->Publication());
    data.intent.kind = Tx::MutationKind::Write; data.intent.path = L"\\history-data";
    data.intent.object_id = 21; data.intent.offset = 0; data.intent.length = data.intent.payload_length = original.size();
    data.intent.inline_payload = original; data.intent.payload_checksum = Sha(original);
    SecureZeroMemory(original.data(), original.size());
    session->Close(); context.reset(); session.reset(); source.reset(); lease.reset();
    return data;
}
void StageHistoryData(const std::filesystem::path& run, HistoryData& data, Tx& tx)
{
    Check(tx.Begin() && tx.RecordMutation(data.intent) && tx.FlushPreparedRecords() && tx.Accept(data.state.before_xid),
        "HistoryActualOriginalDataAcceptance");
    data.state.accepted = tx.Watermarks().accepted_sequence;
    auto options = Options(run, data.state); options.maintenance_original_journal_identity = {};
    Check(options.maintenance_original_journal_identity == std::array<std::byte, 32>{}, "HistoryDataOptionsDefaultZeroMaintenanceJid");
    Journal journal(options); std::string error;
    const bool staged = journal.Stage(tx, data.state.accepted, *data.proof, error);
    Check(staged, ("HistoryActualDataStage:" + error).c_str());
    std::cout << "HISTORY_DATA staged=true defaultZeroMaintenanceJid=true accepted=" << data.state.accepted << '\n';
}
void PublishHistory(const std::filesystem::path& run, const JournalState& s, Tx& tx, bool data)
{
    auto options = Options(run, s); if (data) options.maintenance_original_journal_identity = {};
    Journal journal(options); std::string error;
    {
        JournalTarget target(run / Profile{false}.Name(), s, true);
        Check(journal.PublishOrRecover(tx, s.accepted, target, error), ("HistoryActualPublication:" + error).c_str());
        Check(target.writes == s.writes.size() && target.flushes == 3, "HistoryAllCanonicalWritesAndBarriers");
        for (const auto& block : s.writes) {
            std::vector<std::byte> bytes;
            Check(target.ReadBlock(block.block, 4096, bytes) && Digest(bytes) == block.sha, "HistoryExactPublishedPlan");
        }
    }
    Check(tx.MarkCleanedThrough(s.accepted) && tx.Watermarks().cleanup_sequence == s.accepted, "HistoryPriorActuallyDurableAndCleaned");
}
int JournalHistoryPrepare(const std::filesystem::path& run, std::wstring_view mode)
{
    const auto image = run / Profile{false}.Name(); auto credentials = ReceivePair();
    auto data = PrepareHistoryData(image, credentials.old_password.Bytes());
    auto tx = OpenTx(run, data.state);
    if (mode == L"history-v2-v4-tear") {
        StageHistoryData(run, data, *tx); PublishHistory(run, data.state, *tx, true);
        SaveState(run, data.state);
        Check(CopyFileW((run / L"fixture-state.txt").c_str(), (run / L"history-prior-state.txt").c_str(), TRUE) &&
            CopyFileW(image.c_str(), (run / L"history-maintenance-preimage.dmg").c_str(), TRUE), "HistoryPreserveActualCleanedDataPreimage");
        data.proof.reset();
    }
    auto fixture = PrepareKeybagFixture(image, credentials); const auto& proof = *fixture.publication;
    auto s = PlanState(proof.SourceIdentity(), proof.VolumeObjectId(), proof.VolumeUuid(), proof.Publication());
    Check(s.SourceBinding() == data.state.SourceBinding(), "HistorySameTrustedProtectedScope");
    if (mode == L"history-v2-v4-tear") Check(s.identity != data.state.identity && s.before_xid == data.state.after_xid,
        "HistoryActualSourceAChangesToB");
    auto options = Options(run, s); auto journal = std::make_unique<Journal>(options); std::string error;
    const auto predicted = tx->NextMutationSequence();
    Check(journal->AcceptMaintenance(*tx, proof, s.accepted, error) && s.accepted > predicted,
        ("HistoryPrivateMaintenanceAcceptance:" + error).c_str());
    Check(journal->StageMaintenance(*tx, s.accepted, proof, error), ("HistoryPrivateMaintenanceStage:" + error).c_str());
    SaveState(run, s); journal.reset(); fixture.publication.reset();
    if (mode == L"history-v2-v4-tear") {
        Check(tx->Watermarks().cleanup_sequence == data.state.accepted && tx->HasUnappliedAcceptedWork(), "HistoryOnlySelectedMaintenancePending");
        tx.reset(); PrepareWitnessTear(run, s, mode);
        std::cout << "MIXED_HISTORY prior=v2 cleaned=true sourceAtoB=true selected=v4 properEof=true\n";
    } else {
        Check(mode == L"history-v4-v2-stage", "HistoryDeclaredStageCase");
        PublishHistory(run, s, *tx, false);
        Check(CopyFileW((run / L"witness.wal").c_str(), (run / L"history-v4-complete.wal").c_str(), TRUE), "HistoryPreserveActualV4Predecessor");
        StageHistoryData(run, data, *tx);
        Check(tx->Watermarks().cleanup_sequence == s.accepted && tx->HasUnappliedAcceptedWork(), "HistoryOnlyDataStagePending");
        std::cout << "MIXED_HISTORY prior=v4 cleaned=true selected=v2 defaultZeroMaintenanceJid=true stageOnly=true capabilityCapturedBeforeMaintenance=true\n";
    }
    return 0;
}
int JournalHistoryStageCheck(const std::filesystem::path& run)
{
    const auto s = LoadState(run); const auto original = DigestFile(run / L"original.wal"), witness = DigestFile(run / L"witness.wal");
    const auto image = DigestFile(run / Profile{false}.Name());
    {
        auto tx = OpenTx(run, s); std::string error; std::vector<Tx::AcceptedTransaction> accepted;
        Check(tx->LoadAcceptedTransactionsSinceCleanup(accepted, &error) && accepted.size() == 1 &&
            accepted.front().mutations.size() == 1 && accepted.front().mutations.front().object_id == 21 &&
            tx->Watermarks().cleanup_sequence == s.accepted, "HistoryFreshRealDataAcceptanceAfterCleanedV4");
        Wal wal(Options(run, s).witness); const auto records = wal.ReadAll();
        Check(records.status == Wal::ReadStatus::Ok, "HistoryFreshAuthenticatedMixedStream");
        std::vector<std::uint64_t> versions, boundaries;
        for (const auto& row : records.records) if (row.logical_offset == 0 && row.path_utf8 == "\\encrypted-publication-chunk-v2") {
            versions.push_back(c::ReadU64LE(row.inline_payload, 0).value_or(0)); boundaries.push_back(row.parent_object_id);
        }
        Check(versions == std::vector<std::uint64_t>{4, 2} && boundaries.size() == 2 &&
            boundaries[0] == s.accepted && boundaries[1] == accepted.front().accepted_sequence, "HistoryActualV4ThenV2CompleteGroups");
    }
    Check(DigestFile(run / L"original.wal") == original && DigestFile(run / L"witness.wal") == witness &&
        DigestFile(run / Profile{false}.Name()) == image, "HistoryFreshStageCheckNoWrites");
    std::cout << "{\"mixedHistory\":true,\"versions\":[4,2],\"stageOnly\":true,\"freshNoSecretCheck\":true,\"allBytesUnchanged\":true}\n";
    return 0;
}
int JournalPrepare(const std::filesystem::path& run, std::wstring_view mode)
{
    if (mode.starts_with(L"history-")) return JournalHistoryPrepare(run, mode);
    Check(mode != L"partial-prefix" && mode != L"differing-prefix", "JournalPrefixRecoveryAwaitingCoordinatedHelper");
    const Profile profile{false}; const auto image = run / profile.Name(); auto credentials = ReceivePair();
    auto fixture = PrepareKeybagFixture(image, credentials); const auto& proof = *fixture.publication; const auto& plan = proof.Publication();
    JournalState s; s.identity = proof.SourceIdentity(); s.container_uuid = plan.published_checkpoint.superblock.uuid_hex;
    s.volume_oid = proof.VolumeObjectId(); s.volume_uuid = proof.VolumeUuid(); s.before_xid = plan.expected_checkpoint_xid;
    s.after_xid = plan.transaction_xid; s.switch_block = plan.superblock_write.physical_block;
    for (const auto& write : plan.before_superblock_writes) s.writes.push_back({write.physical_block, Digest(write.bytes)});
    s.writes.push_back({plan.superblock_write.physical_block, Digest(plan.superblock_write.bytes)});
    for (const auto& guard : plan.guard_blocks) s.guards.push_back({guard.physical_block, Digest(guard.bytes)});
    auto options = Options(run, s); auto journal = std::make_unique<Journal>(options); std::string error; std::vector<std::byte> blob;
    Check(journal->BuildMaintenanceAcceptance(proof, blob, error), ("JournalBuildBeforeOriginalAcceptance:" + error).c_str());
    Check(c::ReadU64LE(blob, 0) == 4 && Journal::MaintenanceAcceptancePath == L"\\$apfs-keybag-rewrap-v2", "JournalV4OriginContractRequired");
    std::cout << "MAINTENANCE_BLOB bytes=" << blob.size() << std::endl;
    Check(!credentials.old_password.Size() && !credentials.new_password.Size(), "JournalNoCredentialsAtOriginalAcceptance");
    std::vector<Tx::MutationIntent> chunks;
    Check(journal->BuildMaintenanceAcceptanceRecords(proof, chunks, error) && !chunks.empty(), "JournalBuildPrivateInlineChunks");
    std::size_t offset = 0;
    for (const auto& chunk : chunks) {
        Check(chunk.path == Journal::MaintenanceAcceptancePath && chunk.object_id == s.volume_oid && chunk.generation == s.before_xid &&
            chunk.offset == offset && chunk.length == chunk.inline_payload.size() && chunk.payload_length == chunk.length &&
            !chunk.payload_spool_offset && chunk.length > 0 && chunk.length <= 4096 && Sha(chunk.inline_payload) == chunk.payload_checksum &&
            std::equal(chunk.inline_payload.begin(), chunk.inline_payload.end(), blob.begin() + offset), "JournalPrivateChunkExactContract");
        offset += chunk.inline_payload.size();
    }
    Check(offset == blob.size(), "JournalPrivateChunksCoverFullBlob");
    if (mode == L"wrong-original-object") ++chunks.front().object_id;
    if (mode == L"wrong-original-generation") ++chunks.front().generation;
    if (mode == L"wrong-original-offset") ++chunks.back().offset;
    if (mode == L"wrong-original-order") std::swap(chunks[0], chunks[1]);
    if (mode == L"wrong-original-data") { chunks.back().inline_payload.back() ^= std::byte{1}; chunks.back().payload_checksum = Sha(chunks.back().inline_payload); }
    if (mode == L"wrong-original-truncated") {
        chunks.back().inline_payload.pop_back(); --chunks.back().length; --chunks.back().payload_length; chunks.back().payload_checksum = Sha(chunks.back().inline_payload);
    }
    auto tx = OpenTx(run, s, false, true, mode == L"wrong-quota" ? 8192 : 0);
    if (mode == L"wrong-quota") {
        std::size_t begins = 0, original_appends = 0, witness_appends = 0;
        const auto sequence = tx->NextMutationSequence();
        tx->SetFaultInjectionHook([&](const std::string& stage) { if (stage == "begin") ++begins; });
        tx->SetJournalFaultInjectionHook([&](std::string_view stage) { if (stage == "protected-before-write") ++original_appends; return false; });
        journal->SetWitnessFaultInjectionHook([&](std::string_view stage) { if (stage == "protected-before-write") ++witness_appends; return false; });
        std::uint64_t accepted = 123;
        const bool result = journal->AcceptMaintenance(*tx, proof, accepted, error);
        tx->SetFaultInjectionHook({}); tx->SetJournalFaultInjectionHook({}); journal->SetWitnessFaultInjectionHook({});
        Check(!result && !accepted && error == "ProtectedAcceptanceCapacityExceeded" && !begins && !original_appends && !witness_appends &&
            tx->CurrentState() == Tx::State::Idle && tx->NextMutationSequence() == sequence && !tx->Watermarks().accepted_sequence &&
            !std::filesystem::exists(run / L"original.wal") && !std::filesystem::exists(options.witness.path),
            "JournalOriginalCapacityPreflightBeforePrivateAuthorizationOrBegin");
        s.accepted = sequence + chunks.size(); SaveState(run, s);
        std::cout << "AUTH_QUOTA maxBytes=8192 begins=0 originalAppends=0 witnessAppends=0 originalAccepted=0 requestedBoundary=" << s.accepted << '\n';
        return 0;
    }
    if (mode.starts_with(L"wrong-auth-")) {
        const auto predicted = tx->NextMutationSequence() + chunks.size();
        std::size_t witness_appends = 0, witness_flushes = 0, recorded = 0, accept_starts = 0, original_appends = 0, complete_flushes = 0;
        journal->SetWitnessFaultInjectionHook([&](std::string_view stage) {
            if (stage == "protected-before-write") return ++witness_appends == 3 && mode == L"wrong-auth-write-cut";
            if (stage == "durable-flush") {
                ++witness_flushes; if (witness_appends == chunks.size() + 1) ++complete_flushes;
#ifdef APFSACCESS_PROTECTED_JOURNAL_TESTING
                if (mode == L"wrong-auth-readback" && complete_flushes == 1) {
                    apfsaccess::journal::testing::hooks.fault = apfsaccess::journal::testing::EpochFault::UnprotectAfter;
                    apfsaccess::journal::testing::hooks.triggered = false;
                }
#endif
                return mode == L"wrong-auth-flush-cut";
            }
            return false;
        });
        tx->SetFaultInjectionHook([&](const std::string& stage) {
            if (stage == "mutation-recorded") ++recorded;
            if (stage == "accept-start") ++accept_starts;
        });
        tx->SetJournalFaultInjectionHook([&](std::string_view stage) {
            return stage == "protected-before-write" && ++original_appends == 1 && mode == L"wrong-auth-original-cut";
        });
        std::uint64_t accepted = 0;
        const bool result = journal->AcceptMaintenance(*tx, proof, accepted, error);
        journal->SetWitnessFaultInjectionHook({}); tx->SetJournalFaultInjectionHook({}); tx->SetFaultInjectionHook({});
#ifdef APFSACCESS_PROTECTED_JOURNAL_TESTING
        if (mode == L"wrong-auth-readback") {
            const auto& hooks = apfsaccess::journal::testing::hooks;
            Check(hooks.triggered && hooks.dpapi_released_zero && error == "EncryptedPublicationWitnessUnreadable" &&
                complete_flushes == 1 && !recorded, "JournalAuthenticatedAuthorizationReadbackFailureBeforeOriginalData");
            apfsaccess::journal::testing::hooks.fault = apfsaccess::journal::testing::EpochFault::None;
            std::cout << "AUTH_READBACK injectedAfterUnprotect=true authorizationCompleteFlushes=1 originalMutations=0\n";
        }
#else
        Check(mode != L"wrong-auth-readback", "JournalReadbackFaultProfileRequired");
#endif
        Check(!result && !accepted && !tx->Watermarks().accepted_sequence && !tx->Watermarks().apfs_durable_sequence && !accept_starts,
            "JournalAuthorizationFaultBeforeOriginalAcceptance");
        if (mode == L"wrong-auth-write-cut") Check(witness_appends == 3 && !complete_flushes && !recorded, "JournalPartialAuthorizationBeforeOriginalData");
        if (mode == L"wrong-auth-flush-cut") Check(witness_flushes == 1 && !recorded, "JournalFailedAuthorizationFlushBeforeOriginalData");
        if (mode == L"wrong-auth-original-cut") Check(complete_flushes == 1 && recorded == 1 && original_appends == 1,
            "JournalOriginalAppendCutAfterPrivateAuthorization");
        s.accepted = predicted; SaveState(run, s);
        std::cout << "AUTH_CUT recorded=" << recorded << " acceptStarts=" << accept_starts << " witnessFlushes=" << witness_flushes
            << " originalAccepted=0 requestedBoundary=" << predicted << " error=" << error << '\n';
        journal.reset(); tx.reset();
        Check(DigestFile(image) == profile.Pin(), "JournalAuthorizationFaultImageUnchanged"); return 0;
    }
    s.accepted = mode.starts_with(L"wrong-original-") ?
        AcceptInlineChunks(*tx, chunks, mode == L"wrong-original-preimage" ? s.before_xid + 1 : s.before_xid) :
        AcceptPrivateMaintenance(*journal, *tx, proof, chunks.size());
    SaveState(run, s);
    if (mode == L"wrong-tx" || mode == L"wrong-tx-jid") {
        tx.reset();
        {
            auto other = OpenTx(run, s, true, mode != L"wrong-tx-jid");
            Check(AcceptInlineChunks(*other, chunks, s.before_xid) == s.accepted, "JournalOtherBindingSameAcceptedBoundary");
        }
        tx = OpenTx(run, s);
    }
    Check(s.accepted && tx->Watermarks().apfs_durable_sequence == 0, "JournalOriginalAcceptedOnly");
    if (mode == L"before-stage") { fixture.publication.reset(); blob.clear(); return 0; }
    std::size_t appends = 0;
    if (mode == L"partial-prefix" || mode == L"differing-prefix") journal->SetWitnessFaultInjectionHook([&](std::string_view stage) {
        return stage == "protected-before-write" && ++appends == 3;
    });
    const bool staged = journal->StageMaintenance(*tx, s.accepted, proof, error);
    if (mode.starts_with(L"wrong-original-")) {
        Check(!staged && !std::filesystem::exists(options.witness.path) && DigestFile(image) == profile.Pin(), "JournalWrongOriginalPrivateStageRefused");
        std::cout << "STAGE_REFUSAL " << error << std::endl; return 0;
    }
    if (mode == L"partial-prefix" || mode == L"differing-prefix") {
        Check(!staged && appends == 3 && error == "EncryptedPublicationWitnessAppendFailed", "JournalActualCompleteRecordPrefixFault");
        journal.reset(); Wal wal(options.witness); auto partial = wal.ReadAll();
        Check(partial.status == Wal::ReadStatus::Ok && partial.records.size() == 2 && !partial.recovered_torn_tail, "JournalTwoAuthenticatedCompletePrefixRecords");
    } else Check(staged, ("JournalStageMaintenance:" + error).c_str());
    journal.reset(); fixture.publication.reset(); blob.clear();
    Check(DigestFile(image) == profile.Pin(), "JournalStageHasNoImageWrites");
    if (TearControl(mode)) {
        tx.reset();
        if (mode == L"wrong-tear-m2-with-cert") {
            std::vector<std::byte> changed;
            for (const auto& row : chunks) changed.insert(changed.end(), row.inline_payload.begin(), row.inline_payload.end());
            Check(changed.size() >= 4096, "JournalM2ActualFinalNxsbPresent");
            std::vector<std::byte> nx(changed.end() - 4096, changed.end()); nx.back() ^= std::byte{1};
            const auto checksum = c::Fletcher64(nx.data() + 8, nx.size() - 8);
            Check(checksum.has_value(), "JournalM2RecomputeExistingNxsbChecksum");
            for (unsigned i = 0; i < 8; ++i) nx[i] = static_cast<std::byte>(*checksum >> (8 * i));
            const auto parsed = c::ParseNxSuperblock(nx);
            Check(parsed && parsed->xid == s.after_xid && parsed->uuid_hex == s.container_uuid && c::VerifyObjectChecksum(nx, 4096),
                "JournalM2ChangedNxsbStillParsesAndChecksums");
            std::copy(nx.begin(), nx.end(), changed.end() - 4096);
            auto altered = chunks; std::size_t changed_offset = 0;
            for (auto& row : altered) {
                std::copy_n(changed.begin() + changed_offset, row.inline_payload.size(), row.inline_payload.begin());
                row.payload_checksum = Sha(row.inline_payload); changed_offset += row.inline_payload.size();
            }
            auto other = OpenSameJidAlternateTx(run, s);
            Check(other->ProtectedJournalIdentity() == std::optional{options.maintenance_original_journal_identity} &&
                other->ProtectedSourceBinding() == std::optional{options.witness.protected_persistence->source_binding},
                "JournalM2SubstitutionUsesExactTrustedSourceAndOriginalJid");
            Check(AcceptInlineChunks(*other, altered, s.before_xid) == s.accepted, "JournalM2SameJidSameBoundaryChangedBody");
            std::cout << "M2_CERT validNxsbChecksum=true nxsbParsed=true sameSourceAndOriginalJid=true changedWholePlan=true\n";
        }
        PrepareWitnessTear(run, s, mode); return 0;
    }
    if (mode.starts_with(L"m1-")) { tx.reset(); AddM1CompleteGroup(run, s, mode == L"m1-wrong-transaction"); return 0; }
    if (mode == L"differing-prefix" || mode == L"later-prefix") { tx.reset(); AddLaterPrefix(run, s, mode == L"differing-prefix"); return 0; }
    if (mode == L"torn-frame") {
        const auto file = options.witness.path; Check(std::filesystem::file_size(file) > 4096, "JournalTornFrameBound");
        Check(CopyFileW(file.c_str(), (run / L"witness-before-torn.wal").c_str(), TRUE), "JournalPreserveUntornWitness");
        std::filesystem::resize_file(file, std::filesystem::file_size(file) - 1); return 0;
    }
    if (Negative(mode) || mode == L"partial-prefix" || mode == L"complete-restage") return 0;
    journal = std::make_unique<Journal>(options); std::size_t original_flushes = 0, witness_flushes = 0; bool watermark_cut = false;
    tx->SetJournalFaultInjectionHook([&](std::string_view stage) {
        if (stage == "durable-flush") ++original_flushes;
        if (mode == L"lost-watermark" && stage == "protected-before-write") { watermark_cut = true; return true; } return false;
    });
    journal->SetWitnessFaultInjectionHook([&](std::string_view stage) { if (stage == "durable-flush") ++witness_flushes; return false; });
    JournalTarget target(image, s, true); target.before_write = [&] { Check(original_flushes && witness_flushes, "JournalBothProtectedWalBarriersBeforeWrite"); };
    if (mode == L"mid-data") target.fail_after = 1;
    target.tear = mode == L"torn-switch"; bool cut = false;
    const bool result = journal->PublishOrRecover(*tx, s.accepted, target, error, [&](std::string_view stage) {
        if ((mode == L"before-write" && stage == "before-apple-device-write") ||
            (mode == L"before-switch" && stage == "before-apple-checkpoint-switch") ||
            (mode == L"after-switch" && stage == "before-apple-final-flush")) { cut = true; return false; } return true;
    });
    Check(result == (mode == L"commit" || mode == L"durable-restage"), ("JournalFirstPublicationOutcome:" + error).c_str());
    if (mode == L"before-write") Check(cut && !target.writes && !target.flushes, "JournalBeforeWriteReached");
    if (mode == L"mid-data") Check(target.writes == 1 && target.attempts == 2, "JournalMidBagDataReached");
    if (mode == L"before-switch") Check(cut && target.writes + 1 == s.writes.size() && target.flushes == 1, "JournalBeforeSwitchReached");
    if (mode == L"after-switch") Check(cut && target.writes == s.writes.size() && target.flushes == 1, "JournalAfterSwitchReached");
    if (mode == L"torn-switch") Check(target.torn_bytes == 32 && target.writes + 1 == s.writes.size(), "JournalTornSwitchReached");
    if (mode == L"lost-watermark") Check(watermark_cut && error == "EncryptedPublicationWatermarkFailed" && !tx->Watermarks().apfs_durable_sequence, "JournalLostOriginalWatermarkReached");
    std::cout << "{\"firstWrites\":" << target.writes << ",\"firstFlushes\":" << target.flushes << ",\"tornBytes\":" << target.torn_bytes
        << ",\"durable\":" << tx->Watermarks().apfs_durable_sequence << "}\n"; return 0;
}
int JournalRecover(const std::filesystem::path& run, std::wstring_view mode)
{
    const auto original_path = run / (mode == L"wrong-tear-m2-with-cert" ? L"other-original.wal" : L"original.wal");
    const bool had_original = std::filesystem::exists(original_path);
    const auto original_before = had_original ? DigestFile(original_path) : std::string{};
    const auto canonical_original_before = std::filesystem::exists(run / L"original.wal") ? DigestFile(run / L"original.wal") : std::string{};
    const bool had_witness = std::filesystem::exists(run / L"witness.wal");
    const auto witness_before = had_witness ? DigestFile(run / L"witness.wal") : std::string{};
    const auto s = LoadState(run); std::string error;
    if (mode.starts_with(L"wrong-auth-") || mode == L"wrong-quota") {
        auto tx = std::make_unique<Tx>(L"Conservative"); const auto volume = s.Volume();
        const bool opened = tx->OpenProtectedJournal((run / L"original.wal").wstring(),
            std::wstring(volume.begin(), volume.end()), Protection(run, s, "original"), error);
        if (opened) {
            std::vector<Tx::AcceptedTransaction> accepted;
            Check(tx->LoadAcceptedTransactionsSinceCleanup(accepted, &error) && accepted.empty() &&
                !tx->Watermarks().accepted_sequence && !tx->HasUnappliedAcceptedWork(), "JournalAuthorizationCutHasNoOriginalAcceptance");
        }
        auto journal = std::make_unique<Journal>(Options(run, s)); NoIoTarget target(s);
        Check(!journal->RestageMaintenance(*tx, s.accepted, error) && !journal->PublishOrRecover(*tx, s.accepted, target, error) &&
            !target.reads && !target.writes && !target.flushes, "JournalUnacceptedPrivateWitnessGrantsNoPublication");
        journal.reset(); tx.reset();
        Check(std::filesystem::exists(run / L"original.wal") == had_original && (!had_original || DigestFile(run / L"original.wal") == original_before) &&
            std::filesystem::exists(run / L"witness.wal") == had_witness && (!had_witness || DigestFile(run / L"witness.wal") == witness_before),
            "JournalAuthorizationCutEvidencePreserved");
        std::cout << "{\"refused\":true,\"originalAccepted\":false,\"targetCalls\":0,\"evidenceUnchanged\":true}\n"; return 0;
    }
    auto tx = mode == L"wrong-tear-m2-with-cert" ? OpenSameJidAlternateTx(run, s) : OpenTx(run, s);
    if (mode.starts_with(L"m1-")) {
        const auto options = Options(run, s, "m1"); const auto image = run / Profile{false}.Name();
        tx.reset();
        const auto original_hash = DigestFile(run / L"original.wal"), witness_hash = DigestFile(options.witness.path), image_hash = DigestFile(image);
        tx = OpenTx(run, s);
        auto journal = std::make_unique<Journal>(options); unsigned original_flushes = 0, witness_flushes = 0;
        tx->SetJournalFaultInjectionHook([&](std::string_view stage) { if (stage == "durable-flush") ++original_flushes; return false; });
        journal->SetWitnessFaultInjectionHook([&](std::string_view stage) { if (stage == "durable-flush") ++witness_flushes; return false; });
        const bool staged = journal->RestageMaintenance(*tx, s.accepted, error); const auto stage_error = error;
        NoIoTarget target(s);
        Check(!journal->PublishOrRecover(*tx, s.accepted, target, error) && error == "EncryptedPublicationWitnessBoundaryMismatch",
            "M1PublicationRefusesEnvelopeBodyMismatch");
        Check(!target.reads && !target.writes && !target.flushes && !original_flushes && !tx->Watermarks().apfs_durable_sequence,
            "M1NoTargetCallsOrOriginalProgress");
        journal.reset(); tx.reset();
        Check(DigestFile(run / L"original.wal") == original_hash && DigestFile(options.witness.path) == witness_hash && DigestFile(image) == image_hash,
            "M1OriginalWitnessAndImageBytesUnchanged");
        if (!staged) Check(stage_error == "EncryptedPublicationWitnessBoundaryMismatch" && !witness_flushes, "M1RejectBeforeWitnessSuccessFlush");
        std::cout << "{\"m1RestageAccepted\":" << (staged ? "true" : "false") << ",\"targetReads\":0,\"targetWrites\":0,\"targetFlushes\":0,"
            << "\"originalUnchanged\":true,\"witnessUnchanged\":true,\"imageUnchanged\":true,\"witnessFlushes\":" << witness_flushes << "}\n";
        return staged ? 2 : 0;
    }
    auto options = Options(run, s, mode == L"differing-prefix" ? "mismatched" : "witness");
    if (mode == L"wrong-source") options.preimage_source_identity += ":wrong";
    if (mode == L"wrong-volume") ++options.volume_object_id;
    if (mode == L"wrong-volume-uuid") options.volume_uuid.front() = options.volume_uuid.front() == '0' ? '1' : '0';
    if (mode == L"wrong-jid") options.maintenance_original_journal_identity.front() ^= std::byte{1};
    std::vector<std::byte> wrong_blob;
    if (mode == L"wrong-blob") { wrong_blob = OriginalInlineBlob(*tx, s); wrong_blob.back() ^= std::byte{1}; }
    if (mode == L"wrong-tx" || mode == L"wrong-tx-jid") { tx.reset(); tx = OpenTx(run, s, true, mode != L"wrong-tx-jid"); }
    auto journal = std::make_unique<Journal>(options);
    const auto initial_image_hash = DigestFile(run / Profile{false}.Name());
    if (tx->HasUnappliedAcceptedWork() || mode == L"wrong-tx" || mode == L"wrong-tx-jid" || mode == L"durable-restage") {
        const bool staged = mode == L"wrong-blob" ? journal->RestageMaintenance(*tx, s.accepted, wrong_blob, error) :
            journal->RestageMaintenance(*tx, mode == L"wrong-sequence" ? s.accepted + 1 : s.accepted, error);
        if (Negative(mode) && mode != L"wrong-target") {
            Check(!staged, "JournalNegativeRestageRefused");
            if (mode == L"wrong-original-data" || mode == L"wrong-original-no-authorization") {
#ifdef APFSACCESS_DERIVED_WITNESS_TESTING
                Check(error == "EncryptedPublicationMaintenanceWitnessRebuildRefused", "JournalRawOriginalCannotMintAuthority");
#else
                Check(error == "EncryptedPublicationMaintenanceAuthorizationMissing", "JournalRawOriginalCannotMintAuthority");
#endif
            }
            const auto refusal = error;
            if (mode == L"wrong-original-data" || mode == L"wrong-original-no-authorization") {
                NoIoTarget target(s);
                Check(!journal->PublishOrRecover(*tx, s.accepted, target, error) && error == "EncryptedPublicationWitnessMissing" &&
                    !target.reads && !target.writes && !target.flushes && !tx->Watermarks().apfs_durable_sequence,
                    "JournalUnauthorizedOriginalCannotReachTarget");
                journal.reset(); tx.reset();
                Check(DigestFile(run / L"original.wal") == original_before &&
                    std::filesystem::exists(run / L"witness.wal") == had_witness &&
                    (!had_witness || DigestFile(run / L"witness.wal") == witness_before), "JournalUnauthorizedOriginalAndWitnessPreserved");
            }
            if (mode.starts_with(L"wrong-tear-")) {
                NoIoTarget target(s);
                Check(!journal->PublishOrRecover(*tx, s.accepted, target, error) && !target.reads && !target.writes && !target.flushes &&
                    !tx->Watermarks().apfs_durable_sequence, "JournalRejectedTearMakesNoTargetCalls");
                journal.reset(); tx.reset();
                Check(DigestFile(original_path) == original_before && DigestFile(run / L"original.wal") == canonical_original_before &&
                    DigestFile(run / L"witness.wal") == witness_before,
                    "JournalRejectedTearPreservesRawOriginalAndWitness");
                for (const auto& item : std::filesystem::directory_iterator(run))
                    Check(!item.path().filename().wstring().starts_with(L"witness.wal.wr"), "JournalRejectedTearCreatesNoResetArtifacts");
            }
            if (mode == L"torn-frame") Check(error == "EncryptedPublicationWitnessUnreadable", "JournalTornAeadStrictUnreadable");
            if (mode == L"later-prefix") Check(error == "EncryptedPublicationWitnessIncomplete", "JournalLaterAuthenticatedPrefixNotIgnored");
            if (mode == L"differing-prefix") Check(error == "EncryptedPublicationWitnessPrefixMismatch", "JournalDifferingAuthenticatedPrefixNotAdopted");
            Check(DigestFile(run / Profile{false}.Name()) == initial_image_hash, "JournalRefusalNoImageWrites");
            std::cout << "{\"refused\":true,\"error\":\"" << refusal << "\",\"writes\":0}\n"; return 0;
        }
        Check(staged, ("JournalFreshPasswordFreeRestage:" + error).c_str());
        if (TearControl(mode)) {
            journal.reset(); tx.reset();
            Check(DigestFile(run / L"original.wal") == original_before, "JournalWitnessRepairPreservesOriginalBytes");
            CheckTornWitnessArchive(run);
            if (mode == L"history-v2-v4-tear") {
                auto saved_options = options.witness; saved_options.path = run / L"witness-before-damage.wal";
                const auto prior = [&] { Wal saved(saved_options); return saved.ReadAll(); }();
                const auto after = [&] { Wal repaired(options.witness); return repaired.ReadAll(); }();
                Check(prior.status == Wal::ReadStatus::Ok && after.status == Wal::ReadStatus::Ok &&
                    prior.records.size() > after.records.size(), "HistoryAuthenticatedPriorAndSelectedStreams");
                std::size_t retained = 0, selected = 0;
                for (const auto& row : prior.records) {
                    if (row.parent_object_id != s.accepted) { ++retained; continue; }
                    Check(selected < after.records.size() && after.records[selected].parent_object_id == s.accepted,
                        "HistoryRebuiltSelectedGroupOnly");
                    auto expected = row; expected.sequence = after.records[selected].sequence;
                    Check(Wal::EncodeForTest(expected) == Wal::EncodeForTest(after.records[selected++]),
                        "HistoryExactSelectedRecordAfterSequenceReset");
                }
                Check(retained > 2 && selected == after.records.size(), "HistoryRealCleanedPriorAndCompleteSelectedGroup");
                const auto damaged_size = static_cast<std::size_t>(std::filesystem::file_size(run / L"witness-damaged.wal"));
                Check(damaged_size < (1ULL << 20), "HistoryRawPrefixBound");
                std::vector<std::byte> full_prefix(damaged_size), damaged(damaged_size);
                std::ifstream full(run / L"witness-before-damage.wal", std::ios::binary), raw(run / L"witness-damaged.wal", std::ios::binary);
                full.read(reinterpret_cast<char*>(full_prefix.data()), static_cast<std::streamsize>(damaged_size));
                raw.read(reinterpret_cast<char*>(damaged.data()), static_cast<std::streamsize>(damaged_size));
                Check(full && raw && full_prefix == damaged, "HistoryArchivedRawPrefixPreservesAuthenticatedPriorRecords");
                std::cout << "HISTORY_RETAINED priorAuthenticatedRecords=" << retained << " rawArchiveExact=true selectedRecords=" << selected << '\n';
            }
            tx = OpenTx(run, s); journal = std::make_unique<Journal>(options);
            Check(journal->RestageMaintenance(*tx, s.accepted, error), "JournalReopenedRepairedWitnessIdempotent");
        }
        journal.reset();
        const auto witness_hash = DigestFile(options.witness.path);
        journal = std::make_unique<Journal>(options);
        Check(journal->RestageMaintenance(*tx, s.accepted, error), "JournalExactFinalCompleteWitnessIdempotentFlush");
        journal.reset();
        Check(DigestFile(options.witness.path) == witness_hash, "JournalExactFinalCompleteWitnessIdempotentBytes");
        journal = std::make_unique<Journal>(options);
    }
    wrong_blob.clear(); std::size_t original_flushes = 0, witness_flushes = 0;
    tx->SetJournalFaultInjectionHook([&](std::string_view stage) { if (stage == "durable-flush") ++original_flushes; return false; });
    journal->SetWitnessFaultInjectionHook([&](std::string_view stage) { if (stage == "durable-flush") ++witness_flushes; return false; });
    JournalTarget target(run / Profile{false}.Name(), s, false, mode == L"wrong-target");
    target.before_write = [&] { Check(original_flushes && witness_flushes, "JournalFreshBothWalBarriersBeforeWrite"); };
    const bool recovered = journal->PublishOrRecover(*tx, s.accepted, target, error);
    if (mode == L"wrong-target") {
        Check(!recovered && !target.attempts && !target.flushes && error == "EncryptedPublicationSourceBindingMismatch", "JournalWrongTargetRefusedBeforeWrites"); return 0;
    }
    Check(recovered, ("JournalFreshProtectedRecovery:" + error).c_str());
    Check(tx->Watermarks().apfs_durable_sequence == s.accepted && !tx->HasUnappliedAcceptedWork(), "JournalOriginalDurableBoundaryAdvanced");
    for (const auto& block : s.writes) { std::vector<std::byte> actual; Check(target.ReadBlock(block.block, 4096, actual) && Digest(actual) == block.sha, "JournalRecoveredExactCiphertextPlan"); }
    for (const auto& block : s.guards) {
        if (std::any_of(s.writes.begin(), s.writes.end(), [&](const auto& w) { return w.block == block.block; })) continue;
        std::vector<std::byte> actual; Check(target.ReadBlock(block.block, 4096, actual) && Digest(actual) == block.sha, "JournalRetainedGuardUnchanged");
    }
    if (FirstNew(mode)) Check(!target.writes && target.flushes, "JournalPostSwitchRecoveryNoReplayWrites");
    std::cout << "{\"recovered\":true,\"writes\":" << target.writes << ",\"flushes\":" << target.flushes
        << ",\"durable\":" << tx->Watermarks().apfs_durable_sequence << ",\"selectedXid\":" << s.after_xid << "}\n"; return 0;
}
int LegacyMaintenanceV3Refusal(const std::filesystem::path& run)
{
    Check(run.wstring().starts_with(std::wstring(journal_root) + L"\\run-") &&
        run.wstring().ends_with(L"-wrong-original-data"), "JournalPreservedV3ControlRequired");
    const auto s = LoadState(run); const auto image = run / Profile{false}.Name();
    const auto original = DigestFile(run / L"original.wal"), witness = DigestFile(run / L"witness.wal"), image_hash = DigestFile(image);
    {
        auto tx = OpenTx(run, s); Journal journal(Options(run, s)); NoIoTarget target(s); std::string error;
        Check(!journal.RestageMaintenance(*tx, s.accepted, error), "JournalLegacyV3CannotRestageAsPrivateAuthorization");
        Check(!journal.PublishOrRecover(*tx, s.accepted, target, error) && error == "EncryptedPublicationLegacyWitnessNeedsOriginalOwner" &&
            !target.reads && !target.writes && !target.flushes && !tx->Watermarks().apfs_durable_sequence,
            "JournalSelectedV3ExplicitRefusalBeforeTarget");
    }
    Check(DigestFile(run / L"original.wal") == original && DigestFile(run / L"witness.wal") == witness && DigestFile(image) == image_hash,
        "JournalLegacyV3PacketPreserved");
    std::cout << "{\"legacyV3Refused\":true,\"targetCalls\":0,\"allBytesUnchanged\":true}\n"; return 0;
}
int WitnessRepairCut(const std::filesystem::path& run, std::wstring_view mode)
{
    Check(mode == L"tear-cut-save" || mode == L"tear-cut-promote", "JournalDeclaredWitnessRepairCut");
    const auto s = LoadState(run); const auto image = run / Profile{false}.Name();
    const auto image_before = DigestFile(image), original_before = DigestFile(run / L"original.wal");
    bool reached = false; std::string error;
    {
        auto tx = OpenTx(run, s); Journal journal(Options(run, s));
        const auto wanted = mode == L"tear-cut-save" ? "wreset-after-save" : "wreset-after-promote";
        journal.SetWitnessFaultInjectionHook([&](std::string_view stage) {
            if (stage == wanted) { reached = true; return true; } return false;
        });
        Check(!journal.RestageMaintenance(*tx, s.accepted, error) && reached && !tx->Watermarks().apfs_durable_sequence,
            "JournalWitnessRepairNamespaceCutReached");
        NoIoTarget target(s);
        Check(!journal.PublishOrRecover(*tx, s.accepted, target, error) && !target.reads && !target.writes && !target.flushes,
            "JournalInterruptedWitnessRepairMakesNoTargetCalls");
    }
    Check(DigestFile(image) == image_before && DigestFile(run / L"original.wal") == original_before,
        "JournalWitnessRepairCutPreservesOriginalAndImage");
    std::cout << "{\"repairCutReached\":true,\"targetCalls\":0,\"originalAndImageUnchanged\":true}\n"; return 0;
}
int AlteredOriginalWriteBoundary(const std::filesystem::path& run)
{
    Check(run.wstring().starts_with(std::wstring(journal_root) + L"\\run-") &&
        run.wstring().ends_with(L"-wrong-original-data"), "JournalPreservedAlteredOriginalRunRequired");
    const auto s = LoadState(run); const auto image = run / Profile{false}.Name();
    const auto image_hash = DigestFile(image), original_hash = DigestFile(run / L"original.wal"),
        witness_hash = DigestFile(run / L"witness.wal");
    std::size_t attempts = 0, writes = 0, flushes = 0; std::uint64_t durable = 0;
    std::string error; bool published = false;
    {
        auto tx = OpenTx(run, s); Journal journal(Options(run, s));
        JournalTarget target(image, s, false); target.fail_after = 0;
        published = journal.PublishOrRecover(*tx, s.accepted, target, error);
        attempts = target.attempts; writes = target.writes; flushes = target.flushes;
        durable = tx->Watermarks().apfs_durable_sequence;
    }
    Check(!published && !writes && !flushes && !durable && DigestFile(image) == image_hash &&
        DigestFile(run / L"original.wal") == original_hash && DigestFile(run / L"witness.wal") == witness_hash,
        "JournalAlteredOriginalProbePreservesAllBytes");
    std::cout << "{\"published\":false,\"writeAttempts\":" << attempts << ",\"actualWrites\":" << writes
        << ",\"targetFlushes\":" << flushes << ",\"durable\":" << durable << ",\"allBytesUnchanged\":true,\"error\":\"" << error << "\"}\n";
    return attempts ? 2 : 0;
}
int JournalDriver(const std::filesystem::path& executable, std::wstring mode)
{
    const Profile profile{false}; const auto run = std::filesystem::path(journal_root) /
        (L"run-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64()) + L"-" + mode);
    std::filesystem::create_directory(run);
    for (const auto* name : {L"original-keys", L"witness-keys", L"other-original-keys", L"mismatched-keys", L"m1-keys"})
        Check(std::filesystem::create_directory(run / name), "JournalApprovedPrivateRecoveryRoots");
    const auto original = std::filesystem::path(fixtures) / profile.Name(), image = run / profile.Name();
    Check(DigestFile(original) == profile.Pin() && CopyFileW(original.c_str(), image.c_str(), TRUE), "JournalOriginalPrivateCopy");
    auto old_password = NoteCredential(profile), new_password = RandomCredential(); auto pair = Pair(old_password.Bytes(), new_password.Bytes());
    const auto prepared = Child(executable, L"keybag-prepare " + Quoted(run) + L" " + mode, pair.Bytes(), run / L"prepare.log"); pair.Clear();
    for (const auto& entry : std::filesystem::recursive_directory_iterator(run)) if (entry.is_regular_file()) Absent(entry.path(), old_password.Bytes(), new_password.Bytes());
    Check(prepared == 0, "JournalPrepareProcess");
    const auto args = L" dfvfs " + Quoted(image);
    if (mode == L"torn-switch") {
        Check(Child(executable, L"oracle-pass" + args, old_password.Bytes(), run / L"before-open.log") == 1, "JournalUnrepairedTornOracleOpenRefusal");
        std::ifstream in(run / L"before-open.log"); std::string text((std::istreambuf_iterator<char>(in)), {});
        Check(text == "FAIL OracleOpen\n", "JournalUnrepairedTornIsStructuralRefusal");
    } else {
        Check(Child(executable, L"oracle-pass" + args, FirstNew(mode) ? new_password.Bytes() : old_password.Bytes(), run / L"before-active.log") == 0,
            "JournalBeforeRecoveryIndependentActive");
        Check(Child(executable, L"oracle-refuse" + args, FirstNew(mode) ? old_password.Bytes() : new_password.Bytes(), run / L"before-refused.log") == 0,
            "JournalBeforeRecoveryIndependentRefused");
    }
    if (mode == L"tear-cut-save" || mode == L"tear-cut-promote")
        Check(Child(executable, L"keybag-repair-cut " + Quoted(run) + L" " + mode, {}, run / L"repair-cut.log") == 0,
            "JournalFirstFreshWitnessRepairCutProcess");
    const auto command = mode == L"history-v4-v2-stage" ? L"keybag-history-check " + Quoted(run) : L"keybag-recover " + Quoted(run) + L" " + mode;
    const auto recovered = Child(executable, command, {}, run / L"recover.log");
    if (!mode.starts_with(L"m1-")) Check(recovered == 0, "JournalFreshNoPasswordRecoveryProcess");
    const auto& active = Negative(mode) ? old_password : new_password;
    const auto& refused = Negative(mode) ? new_password : old_password;
    Check(Child(executable, L"oracle-pass" + args, active.Bytes(), run / L"after-active.log") == 0, "JournalFinalIndependentActive");
    Check(Child(executable, L"oracle-refuse" + args, refused.Bytes(), run / L"after-refused.log") == 0, "JournalFinalIndependentRefused");
    Check(NativeRead(image, profile, active.Bytes(), true) == "c7fbc0e821c0871805a99584c6a384533909f68a6bbe9a2a687d28d9f3b10c16", "JournalFinalNativePayload");
    NativeRead(image, profile, refused.Bytes(), false);
    if (Negative(mode)) Check(DigestFile(image) == profile.Pin(), "JournalNegativeWholeImageUnchanged");
    Check(DigestFile(original) == profile.Pin(), "JournalAuthenticOriginalUnchanged");
    for (const auto& entry : std::filesystem::recursive_directory_iterator(run)) if (entry.is_regular_file()) Absent(entry.path(), old_password.Bytes(), new_password.Bytes());
    if (mode.starts_with(L"m1-")) {
        std::cout << "M1_EXPECTED_REFUSAL actualRecoveryExit=" << recovered << '\n';
        std::wcout << L"EVIDENCE " << run.wstring() << L"\n";
        Check(recovered == 0, "M1RestageMustRefuse");
    }
    std::cout << "{\"caseSucceeded\":true,\"negative\":" << (Negative(mode) ? "true" : "false") << ",\"passwordFreeRecoveryProcess\":true}\n";
    std::wcout << L"EVIDENCE " << run.wstring() << L"\n"; return 0;
}
}

#ifndef APFS_KEYBAG_JOURNAL_MAIN
#define APFS_KEYBAG_JOURNAL_MAIN wmain
#endif
int APFS_KEYBAG_JOURNAL_MAIN(int argc, wchar_t** argv)
{
    try
    {
        if (argc == 3 && std::wstring_view(argv[1]) == L"drive-keybag-journal") return JournalDriver(argv[0], argv[2]);
        if (argc == 4 && std::wstring_view(argv[1]) == L"keybag-prepare") return JournalPrepare(argv[2], argv[3]);
        if (argc == 4 && std::wstring_view(argv[1]) == L"keybag-recover") return JournalRecover(argv[2], argv[3]);
        if (argc == 3 && std::wstring_view(argv[1]) == L"keybag-altered-original-probe") return AlteredOriginalWriteBoundary(argv[2]);
        if (argc == 3 && std::wstring_view(argv[1]) == L"keybag-legacy-v3-control") return LegacyMaintenanceV3Refusal(argv[2]);
        if (argc == 3 && std::wstring_view(argv[1]) == L"keybag-history-check") return JournalHistoryStageCheck(argv[2]);
        if (argc == 4 && std::wstring_view(argv[1]) == L"keybag-repair-cut") return WitnessRepairCut(argv[2], argv[3]);
        if (argc == 2 && std::wstring_view(argv[1]) == L"drive-keybag-getters")
            return CapturedVolumeDriver(argv[0]);
        if (argc == 4 && std::wstring_view(argv[1]) == L"keybag-getters" &&
            std::wstring_view(argv[2]) == L"dfvfs") return CapturedVolumeCase(argv[3]);
        return PrimitiveKeybagMain(argc, argv);
    }
    catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
