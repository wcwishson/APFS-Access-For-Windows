#include "ProtectedJournalContinuation.h"
#include "ProtectedJournalEpoch.h"
#include "TransactionManager.h"

#include <cstring>
#include <iostream>
#include <stdexcept>
#include <windows.h>

#undef CreateFile
#undef CreateDirectory

namespace apfsaccess::rw
{
// Internal admission/seed contract gate. It does not mint a production Journal
// capability or stand in for the separate two-stream continuation protocol gate.
struct ProtectedContinuationTestAccess
{
    static inline unsigned checks = 0;
    static void Require(bool condition, const char* message)
    { ++checks; if (!condition) throw std::runtime_error(message); }
    struct Handle
    {
        HANDLE h = INVALID_HANDLE_VALUE;
        explicit Handle(HANDLE value = INVALID_HANDLE_VALUE) : h(value) {}
        ~Handle() { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); }
    };
    static void WriteNew(const std::filesystem::path& path, std::span<const std::uint8_t> bytes)
    {
        Handle h(CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, nullptr,
            CREATE_NEW, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH, nullptr));
        Require(h.h != INVALID_HANDLE_VALUE, "fresh regular file");
        BY_HANDLE_FILE_INFORMATION info{}; DWORD written = 0;
        Require(GetFileInformationByHandle(h.h, &info) && info.nNumberOfLinks == 1 &&
            !(info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)), "regular single-link output");
        Require(WriteFile(h.h, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr) &&
            written == bytes.size() && FlushFileBuffers(h.h), "durable private bytes");
    }
    static void Put(std::span<std::byte> bytes, std::size_t at, std::uint64_t n)
    { for (unsigned i = 0; i < 8; ++i) bytes[at + i] = std::byte((n >> (i * 8)) & 255); }
    static TransactionManager::MutationIntent Intent()
    {
        TransactionManager::MutationIntent intent;
        intent.kind = TransactionManager::MutationKind::CreateFile;
        intent.path = L"\\continuation-private-canary";
        intent.object_id = 42; intent.generation = 2; intent.offset = 0644;
        return intent;
    }
    static void Commit(TransactionManager& tm, std::uint64_t xid)
    {
        const auto before = tm.NextMutationSequence();
        Require(tm.Begin() && tm.RecordMutation(Intent()) && tm.Accept(xid), "actual original acceptance");
        Require(tm.Watermarks().accepted_sequence == before + 1 &&
            tm.MarkApfsDurableThrough(before + 1) && tm.MarkCleanedThrough(before + 1), "actual original watermarks");
    }
    static void Run(const std::filesystem::path& root)
    {
        for (const auto* name : {L"original-keys", L"spool", L"spool-keys"})
            Require(CreateDirectoryW((root / name).c_str(), nullptr) != FALSE, "new private directory");
        WriteAheadLog::ProtectedPersistence protection;
        protection.key_directory = root / L"original-keys";
        protection.source_binding[0] = std::byte{1}; protection.journal_identity[0] = std::byte{2};
        const auto canonical = root / L"original.wal";
        const auto retained = std::filesystem::path(canonical.wstring() + L".jcont.old");
        const std::wstring identity = L"continuation-admission-" + root.filename().wstring();
        const auto utf8_identity = TransactionManager::WideToUtf8(identity);
        PayloadSpool::Options options{root / L"spool", utf8_identity};
        options.protected_persistence = true; options.protected_binding = protection.source_binding;
        options.protected_key_directory = root / L"spool-keys";
        PayloadSpool spool(options);
        auto tm = std::make_unique<TransactionManager>(L"conservative"); std::string error;
        Require(tm->OpenProtectedJournal(canonical.wstring(), identity, protection, error), "fresh protected owner");
        Commit(*tm, 7);
        WriteAheadLog::ProtectedHistoryHead old;
        Require(tm->CaptureProtectedOriginalHistoryHead(old, error), "complete actual original head");
        Require(tm->ReconcileProtectedPayloadSpool(spool, old, error) == PayloadSpool::ProtectedMaintenanceResult::Succeeded,
            "genuine all-clean spool reset");
        const auto next_id = tm->next_transaction_id_, next_sequence = tm->next_sequence_;
        const auto watermarks = tm->Watermarks();
        Require(tm->journal_.FlushPendingAppends() && tm->journal_.CloseAppendFileHandle(), "unconditional original barrier");
        auto epoch = journal::ProtectedJournalEpoch::AcquireWriter(protection.key_directory.wstring(), protection.source_binding);
        Require(static_cast<bool>(epoch), "fresh successor encryption key");
        WriteAheadLog::ContinuationAdmission admission;
        std::memcpy(admission.anchor.data(), "WALCONT1", 8);
        Put(admission.anchor, 8, 1); admission.anchor[16] = std::byte{3};
        Put(admission.anchor, 48, next_sequence - 1); Put(admission.anchor, 56, next_id);
        Put(admission.anchor, 64, watermarks.accepted_sequence); Put(admission.anchor, 72, watermarks.apfs_durable_sequence);
        Put(admission.anchor, 80, watermarks.cleanup_sequence); Put(admission.anchor, 128, 1);
        admission.last_sequence = next_sequence - 1;
        admission.immutable_siblings.push_back(retained.filename().wstring());
        std::vector<std::uint8_t> encrypted;
        Require(tm->journal_.SealContinuationAnchor(admission, *epoch.epoch, encrypted), "genuine successor AEAD anchor");
        epoch.epoch.reset();
        WriteAheadLog::ProtectedHistoryHead decoded_head;
        auto wrong = tm->journal_.DecodeContinuationEvidence(encrypted, std::nullopt, decoded_head);
        Require(wrong.status != WriteAheadLog::ReadStatus::Ok && wrong.records.empty(), "no anchor fallback without private admission");
        auto exact = tm->journal_.DecodeContinuationEvidence(encrypted, admission, decoded_head);
        Require(exact.status == WriteAheadLog::ReadStatus::Ok && exact.records.empty() && decoded_head.records == 0 &&
            decoded_head.last_sequence == old.last_sequence, "empty active head preserves global position");
        const auto next = std::filesystem::path(canonical.wstring() + L".jcont.next");
        WriteNew(next, encrypted);
        Require(MoveFileExW(canonical.c_str(), retained.c_str(), MOVEFILE_WRITE_THROUGH) != FALSE &&
            MoveFileExW(next.c_str(), canonical.c_str(), MOVEFILE_WRITE_THROUGH) != FALSE, "no-replace private staging");
        auto retained_handle = std::make_shared<Handle>(CreateFileW(retained.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
            OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        Require(retained_handle->h != INVALID_HANDLE_VALUE, "retained original evidence handle");
        WriteAheadLog unaware({canonical, utf8_identity, 64ull << 20, protection});
        Require(unaware.ReadAll().status != WriteAheadLog::ReadStatus::Ok &&
            WriteAheadLog::ReadAll(canonical, utf8_identity).status != WriteAheadLog::ReadStatus::Ok,
            "public protected and static readers refuse private generation");
        Require(tm->journal_.InstallContinuationAdmission(admission, retained_handle), "internal admitted AEAD decode");
        tm->continuation_seed_ = TransactionManager::ContinuationSeed{admission.last_sequence, next_id, watermarks};
        Require(tm->SeedIdsFromJournalRecords({}, tm->journal_.ExclusiveWriterLeaseGeneration()), "certified seed contract");
        Require(tm->NextMutationSequence() == next_sequence && tm->next_transaction_id_ == next_id &&
            tm->Watermarks().cleanup_sequence == watermarks.cleanup_sequence, "monotonic counters and watermark identity");
        WriteAheadLog::ProtectedHistoryHead successor;
        Require(tm->CaptureProtectedOriginalHistoryHead(successor, error) && successor.records == 0 &&
            successor.last_sequence == old.last_sequence, "bridge recognizes certified retired prefix");
        Require(tm->ReconcileProtectedPayloadSpool(spool, successor, error) == PayloadSpool::ProtectedMaintenanceResult::Succeeded,
            "actual spool reconcile with certified empty successor");
        Commit(*tm, 8);
        const auto after = tm->Watermarks();
        Require(after.accepted_sequence > watermarks.accepted_sequence && tm->next_transaction_id_ > next_id,
            "actual next accepted transaction does not reset IDs");
        Require(tm->CaptureProtectedOriginalHistoryHead(successor, error) && successor.records == 4 &&
            successor.last_sequence == old.last_sequence + 4, "active history remains exactly contiguous after retired prefix");
        Require(tm->ReconcileProtectedPayloadSpool(spool, successor, error) == PayloadSpool::ProtectedMaintenanceResult::Succeeded,
            "cleanup and reuse after certified prefix");
        tm.reset();
        tm = std::make_unique<TransactionManager>(L"conservative");
        Require(!tm->OpenProtectedJournal(canonical.wstring(), identity, protection, error), "ordinary fresh owner cannot self-admit continuation");
        tm->continuation_seed_ = TransactionManager::ContinuationSeed{admission.last_sequence, next_id, watermarks};
        Require(tm->journal_.InstallContinuationAdmission(admission, retained_handle), "internal fresh-owner admission contract");
        auto records = tm->journal_.ReadAllWithExclusiveWriterLease();
        Require(records.status == WriteAheadLog::ReadStatus::Ok && records.records.size() == 4 &&
            tm->SeedIdsFromJournalRecords(records.records, tm->journal_.ExclusiveWriterLeaseGeneration()), "fresh decode and seed actual active records");
        Require(tm->Watermarks().accepted_sequence == after.accepted_sequence &&
            tm->Watermarks().cleanup_sequence == after.cleanup_sequence && tm->NextMutationSequence() == successor.last_sequence + 1,
            "reopened exact accepted/watermark identity");
        Require(tm->CaptureProtectedOriginalHistoryHead(successor, error), "reopened complete certified original head");
        // Preserve the foreign evidence; do not remove it to make the test pass.
        WriteNew(std::filesystem::path(canonical.wstring() + L".jcont.foreign"), {encrypted.data(), 1});
        Require(tm->journal_.ReadAll().status != WriteAheadLog::ReadStatus::Ok &&
            !tm->CaptureProtectedOriginalHistoryHead(successor, error), "warm owner blocks unknown continuation evidence");
        std::cout << "PASS private admission/seed contract, actual original acceptance and spool cleanup/reuse, public refusal\n";
    }
};
}

int wmain(int argc, wchar_t** argv)
{
    try
    {
        if (argc != 2) throw std::runtime_error("one fresh absolute D root required");
        const std::filesystem::path root(argv[1]); const auto text = root.wstring();
        if (text.size() < 4 || text.size() > 120 || text[0] != L'D' || text[1] != L':' || text[2] != L'\\' ||
            text.find_first_of(L":/*?\"<>|", 3) != text.npos || text.back() == L'\\' || GetDriveTypeW(L"D:\\") != DRIVE_FIXED)
            throw std::runtime_error("fixed absolute D root required");
        for (const auto& part : root.relative_path())
            if (part == L"." || part == L".." || part.wstring().empty() || part.wstring().back() == L'.' || part.wstring().back() == L' ')
                throw std::runtime_error("path component refused");
        std::vector<std::shared_ptr<apfsaccess::rw::ProtectedContinuationTestAccess::Handle>> pins;
        for (auto at = root.parent_path();; at = at.parent_path())
        {
            auto h = std::make_shared<apfsaccess::rw::ProtectedContinuationTestAccess::Handle>(CreateFileW(at.c_str(),
                FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
            BY_HANDLE_FILE_INFORMATION info{}; wchar_t final[512]{};
            if (h->h == INVALID_HANDLE_VALUE || GetFileType(h->h) != FILE_TYPE_DISK ||
                !GetFileInformationByHandle(h->h, &info) || !(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
                (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
                !GetFinalPathNameByHandleW(h->h, final, 512, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS) ||
                CompareStringOrdinal(final, -1, (L"\\\\?\\" + at.wstring()).c_str(), -1, TRUE) != CSTR_EQUAL)
                throw std::runtime_error("resolved parent refused");
            pins.push_back(std::move(h)); if (at == at.parent_path()) break;
        }
        if (!CreateDirectoryW(root.c_str(), nullptr)) throw std::runtime_error("fresh root required");
        apfsaccess::rw::ProtectedContinuationTestAccess::Run(root);
        std::cout << "PASS " << apfsaccess::rw::ProtectedContinuationTestAccess::checks << " checks; internal contract only\n";
        return 0;
    }
    catch (const std::exception& ex) { std::cerr << "FAIL " << ex.what() << '\n'; return 1; }
}
