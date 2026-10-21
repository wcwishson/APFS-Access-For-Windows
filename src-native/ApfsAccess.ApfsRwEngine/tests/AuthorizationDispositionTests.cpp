#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#undef CreateFile
#undef CreateDirectory
#include "ApfsSoftwareKeybagMaintenance.h"
#include "ApfsEncryptedImageWriteSession.h"
#include "EncryptedPublicationJournal.h"
#include "EncryptedReadTransport.h"
#include "PayloadSpool.h"
#include <iostream>
#include <map>
#include <stdexcept>

namespace c = apfsaccess::catalog;
namespace t = apfsaccess::transport;
namespace
{
struct Handle
{
    HANDLE h;
    explicit Handle(HANDLE value) : h(value) {}
    ~Handle() { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); }
};
struct Hash
{
    BCRYPT_HASH_HANDLE h{};
    Hash() { if (BCryptCreateHash(BCRYPT_SHA256_ALG_HANDLE, &h, nullptr, 0, nullptr, 0, 0) < 0) throw std::runtime_error("hash create"); }
    ~Hash() { if (h) BCryptDestroyHash(h); }
    void Add(std::span<const std::byte> bytes)
    {
        if (BCryptHashData(h, reinterpret_cast<PUCHAR>(const_cast<std::byte*>(bytes.data())), static_cast<ULONG>(bytes.size()), 0) < 0)
            throw std::runtime_error("hash data");
    }
    std::string Finish()
    {
        std::array<std::uint8_t, 32> bytes{};
        if (BCryptFinishHash(h, bytes.data(), 32, 0) < 0) throw std::runtime_error("hash finish");
        std::string text; constexpr char hex[] = "0123456789abcdef";
        for (const auto byte : bytes) { text += hex[byte >> 4]; text += hex[byte & 15]; }
        return text;
    }
};
std::string DigestFile(const std::filesystem::path& path)
{
    Handle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    if (file.h == INVALID_HANDLE_VALUE) throw std::runtime_error("hash file");
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file.h, &size) || size.QuadPart < 0) throw std::runtime_error("hash size");
    Hash hash; std::array<std::byte, 4096> bytes{}; auto remaining = static_cast<std::uint64_t>(size.QuadPart);
    while (remaining) {
        const auto wanted = static_cast<DWORD>((std::min)(remaining, std::uint64_t{4096})); DWORD got = 0;
        if (!ReadFile(file.h, bytes.data(), wanted, &got, nullptr) || got != wanted) throw std::runtime_error("hash read");
        hash.Add(std::span(bytes).first(got)); remaining -= got;
    }
    return hash.Finish();
}
struct Credentials { apfsaccess::crypto::SecureBytes old_password, new_password; };
Credentials ReceivePair()
{
    std::atomic<bool> cancelled{false};
    auto pair = t::ReceiveCredential(GetStdHandle(STD_INPUT_HANDLE), std::chrono::seconds(10), cancelled);
    SetStdHandle(STD_INPUT_HANDLE, nullptr);
    if (!pair || pair.bytes.Size() <= 36) throw std::runtime_error("credential transport");
    std::size_t length = 0;
    for (const auto value : pair.bytes.Bytes().first(4)) {
        const auto digit = std::to_integer<unsigned>(value);
        if (digit < '0' || digit > '9') throw std::runtime_error("credential length");
        length = length * 10 + digit - '0';
    }
    if (!length || length + 36 != pair.bytes.Size()) throw std::runtime_error("credential frame");
    auto old_password = apfsaccess::crypto::SecureBytes::Allocate(length), new_password = apfsaccess::crypto::SecureBytes::Allocate(32);
    if (!old_password || !new_password) throw std::runtime_error("credential lock");
    std::copy_n(pair.bytes.Bytes().begin() + 4, length, old_password.bytes.Bytes().begin());
    std::copy_n(pair.bytes.Bytes().begin() + 4 + length, 32, new_password.bytes.Bytes().begin());
    return {std::move(old_password.bytes), std::move(new_password.bytes)};
}
}

namespace apfsaccess::rw
{
struct AuthorizationDispositionTestAccess
{
    using J = EncryptedPublicationJournal;
    using C = ProtectedJournalContinuation;
    struct NoIoTarget final : EncryptedPublicationTarget
    {
        std::array<std::byte, 32> binding{};
        unsigned calls = 0;
        std::array<std::byte, 32> SourceBinding() const noexcept override { return binding; }
        bool ReadBlock(std::uint64_t, std::uint32_t, std::vector<std::byte>&) override { ++calls; return false; }
        bool WriteBlock(std::uint64_t, std::span<const std::byte>) override { ++calls; return false; }
        bool Flush() override { ++calls; return false; }
    };
    static inline unsigned checks = 0;
    static inline std::string last_error;
    static void Require(bool ok, const std::string& why)
    { ++checks; if (!ok) throw std::runtime_error(why + (last_error.empty() ? "" : ":actual=" + last_error)); }
    static std::array<std::byte, 32> Binding(std::string_view text)
    {
        std::array<std::byte, 32> out{};
        Require(BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0,
            reinterpret_cast<PUCHAR>(const_cast<char*>(text.data())), static_cast<ULONG>(text.size()),
            reinterpret_cast<PUCHAR>(out.data()), 32) >= 0, "binding SHA256"); return out;
    }
    static auto Snapshot(const std::filesystem::path& directory_root)
    {
        std::map<std::wstring, std::string> result;
        for (const auto& file : std::filesystem::recursive_directory_iterator(directory_root))
            if (file.is_regular_file()) {
                Handle handle(CreateFileW(file.path().c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
                Require(handle.h != INVALID_HANDLE_VALUE, "shared evidence hash:" + file.path().string());
                LARGE_INTEGER size{}; Require(GetFileSizeEx(handle.h, &size) && size.QuadPart >= 0, "shared evidence size");
                ::Hash hash; std::array<std::byte, 4096> bytes{}; auto remaining = static_cast<std::uint64_t>(size.QuadPart);
                // Lease files are empty and may hold an exclusive byte-range
                // lock. Hash their actual zero bytes without reading past EOF.
                while (remaining) {
                    const auto wanted = static_cast<DWORD>((std::min)(remaining, std::uint64_t{4096})); DWORD got = 0;
                    const auto read = ReadFile(handle.h, bytes.data(), wanted, &got, nullptr); const auto code = GetLastError();
                    Require(read && got == wanted, "shared evidence read:" + file.path().string() + ":" + std::to_string(code));
                    hash.Add(std::span(bytes).first(got)); remaining -= got;
                }
                result.emplace(file.path().wstring(), hash.Finish());
            }
        return result;
    }
#include "AuthorizationContinuationCases.h"
    static int Run(const std::filesystem::path& test_root, const std::filesystem::path& image)
    {
        Require(test_root.is_absolute() && image.is_absolute() && test_root.wstring().size() < 120 &&
            test_root.root_name() == L"D:" && image.root_name() == L"D:" && !std::filesystem::exists(test_root), "fresh absolute local root");
        for (auto p = test_root.parent_path(); !p.empty(); p = p.parent_path()) {
            const auto attributes = GetFileAttributesW(p.c_str());
            Require(attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_REPARSE_POINT), "nonreparse ancestors");
            if (p == p.root_path()) break;
        }
        Require(CreateDirectoryW(test_root.c_str(), nullptr) != FALSE, "fresh test root");
        const auto initial_image = DigestFile(image);
        auto credentials = ReceivePair();
        auto lease = std::make_shared<t::WindowsImageLease>(image.wstring());
        auto source = std::make_shared<t::OwnedEncryptedImageSource>(lease, 20480, 4153344);
        c::UnlockError unlock{}; c::PasswordUnlockBudget budget;
        auto rewrap = c::SoftwareKeybagRewrap::Prepare(source, source->SourceIdentity(), source->Revision(),
            1026, c::KeybagLength::IncludesHeader, credentials.old_password, credentials.new_password, budget, unlock);
        Require(static_cast<bool>(rewrap), "actual private keybag preparation");
        auto& error = last_error; error.clear();
        auto prepared = rewrap->PreparePublication(credentials.old_password, credentials.new_password, budget, error);
        Require(static_cast<bool>(prepared), "actual v4 publication:" + error);
        rewrap.reset();
        const auto jid = Binding("authorization-disposition-original-v1");
        c::PasswordUnlockBudget transition_budget;
        auto transition = c::SoftwareVolumeTransition::PrepareDecryption(source, source->SourceIdentity(), source->Revision(),
            1026, c::KeybagLength::IncludesHeader, credentials.old_password, transition_budget, jid, error);
        Require(static_cast<bool>(transition), "actual private v6 decryption preparation:" + error);
        const auto binding = transition->SourceBinding();
        credentials.old_password.Clear(); credentials.new_password.Clear();
        const auto endpoint = [&](std::uint64_t xid) {
            C::Endpoint::Description d; d.source_binding = binding; d.source_identity = source->SourceIdentity();
            d.container_uuid = prepared->Publication().published_checkpoint.superblock.uuid_hex;
            d.volume_uuid = prepared->VolumeUuid(); d.volume_object_id = 1026; d.container_bytes = 4153344;
            d.checkpoint_xid = xid;
            return C::Endpoint(std::move(d), [source, identity = source->SourceIdentity(), revision = source->Revision()](std::string&) {
                return source->SourceIdentity() == identity && source->Revision() == revision;
            }, [source](std::uint64_t offset, std::span<std::byte> out, std::string&) {
                std::vector<std::byte> bytes;
                if (!source->Read(offset, out.size(), bytes) || bytes.size() != out.size()) return false;
                std::copy(bytes.begin(), bytes.end(), out.begin()); SecureZeroMemory(bytes.data(), bytes.size()); return true;
            });
        };
        unsigned scenario = 0;
        const std::vector<std::string> cuts{"", "authorization-disposition-after-intent",
            "authorization-disposition-after-original-abort", "authorization-disposition-before-receipt",
            "authorization-disposition-after-receipt", "abort-flush", "receipt-flush"};
        for (const bool v6 : {false, true}) for (const auto& cut : cuts) for (const int prefix : {0, 1, 2, 3, 4}) {
            if (prefix >= 3 && !cut.empty()) continue;
            if ((cut == "abort-flush" && (v6 || prefix != 0)) ||
                (cut == "receipt-flush" && (!v6 || prefix != 0))) continue;
            const auto directory = test_root / (L"c" + std::to_wstring(++scenario));
            Require(CreateDirectoryW(directory.c_str(), nullptr), "fresh case");
            for (const auto* name : {L"o", L"w"}) Require(CreateDirectoryW((directory / name).c_str(), nullptr), "fresh key root");
            const auto volume = "authorization-test:" + TransactionManager::WideToUtf8(directory.wstring());
            WriteAheadLog::ProtectedPersistence original; original.key_directory = directory / L"o";
            original.source_binding = binding; original.journal_identity = jid;
            auto witness = original; witness.key_directory = directory / L"w"; witness.journal_identity = Binding("disposition-witness");
            J::Options options; options.witness = {directory / L"w.wal", volume + ":witness", 4u << 20, witness};
            options.container_bytes = 4153344; options.container_uuid = prepared->Publication().published_checkpoint.superblock.uuid_hex;
            options.preimage_source_identity = source->SourceIdentity(); options.volume_object_id = 1026; options.volume_uuid = prepared->VolumeUuid();
            options.maintenance_original_journal_identity = jid;
            const auto open = [&](bool prepared_prefix = false) {
                auto tx = std::make_unique<TransactionManager>(L"conservative"); tx->SetJournalMaxBytesForTest(4u << 20);
                const auto opened = tx->OpenProtectedJournal((directory / L"o.wal").wstring(), std::wstring(volume.begin(), volume.end()), original, error);
                Require(opened || (prepared_prefix && !tx->RecoveryStateValid() && error == "ProtectedJournalEvidenceInvalid"), "original open:" + error);
                return tx;
            };
            auto tx = open(); auto journal = std::make_unique<J>(options); std::uint64_t accepted = 0;
            bool injected = false;
            tx->SetFaultInjectionHook([&](const std::string& stage) {
                const auto stop = v6 && prefix == 2 ? "transition-after-original-prepared-chunk" :
                    v6 ? "transition-after-private-authorization" : "maintenance-after-private-authorization";
                if (prefix != 4 && stage == stop) {
                    injected = true; throw std::runtime_error("test authorization cut");
                }
            });
            const auto accepted_result = v6 ? journal->AcceptTransition(*tx, *transition, accepted, error) :
                journal->AcceptMaintenance(*tx, *prepared, accepted, error);
            Require(prefix == 4 ? (accepted_result && accepted && !injected) : (!accepted_result && injected && !accepted),
                "real authorization and original acceptance control:" + error);
            tx->SetFaultInjectionHook({});
            // prefix 0 retains the real ordinary abort. Other profiles use a
            // separate original stream, retaining the first evidence unchanged.
            journal.reset(); tx.reset();
            if (prefix && prefix != 4 && !(v6 && prefix == 2)) {
                const auto retained = directory / L"original-before-control.wal";
                Require(MoveFileW((directory / L"o.wal").c_str(), retained.c_str()), "retain original abort control");
                tx = open();
                if (prefix >= 2) {
                    std::vector<TransactionManager::MutationIntent> rows;
                    Require(J(options).BuildMaintenanceAcceptanceRecords(*prepared, rows, error), "actual original template records");
                    if (prefix == 3) {
                        rows.front().object_id += 1;
                        if (v6) rows.front().path = J::TransitionAcceptancePath;
                    }
                    if (!v6 || prefix == 3) {
                        Require(tx->Begin() && tx->RecordMutation(rows.front()) && tx->FlushPreparedRecords(), "real exact prepared prefix");
                        tx.reset(); tx = open(true);
                    }
                }
            } else tx = open();
            journal = std::make_unique<J>(options);
            auto held = endpoint(prepared->Publication().expected_checkpoint_xid);
            const auto before = Snapshot(directory);
            if (prefix == 4) {
                std::vector<std::uint64_t> spent;
                Require(journal->ReconcileUnacceptedAuthorizations(*tx, held, error) &&
                    journal->ValidateUnacceptedDispositions(*tx, spent, error) && spent.empty() &&
                    tx->Watermarks().accepted_sequence == accepted && tx->HasUnappliedAcceptedWork() && Snapshot(directory) == before,
                    "real Accepted row cannot become spent or be changed");
                Require(DigestFile(image) == initial_image, "accepted negative has zero APFS writes");
                std::cout << "PASS v" << (v6 ? 6 : 4) << " Accepted negative\n";
                continue;
            }
            if (prefix == 3) {
                Require(!journal->ReconcileUnacceptedAuthorizations(*tx, held, error) && Snapshot(directory) == before &&
                    DigestFile(image) == initial_image, "authenticated but wrong original prefix refuses without mutation");
                std::cout << "PASS v" << (v6 ? 6 : 4) << " wrong-prefix negative\n";
                continue;
            }
            auto wrong = endpoint(prepared->Publication().expected_checkpoint_xid + 1);
            Require(!journal->ReconcileUnacceptedAuthorizations(*tx, wrong, error) && Snapshot(directory) == before,
                "wrong current checkpoint refuses before persistent mutation");
            if (cut.empty() && prefix == 0) {
                tx->SetJournalFaultInjectionHook([](auto stage) { return stage == "durable-flush"; });
                Require(!journal->ReconcileUnacceptedAuthorizations(*tx, held, error) && Snapshot(directory) == before,
                    "original durability failure precedes intent and preserves all bytes");
                journal.reset(); tx.reset(); tx = open(); journal = std::make_unique<J>(options);
            }
            bool reached = false;
            unsigned injected_flushes = 0;
            const auto hook = [&](std::string_view stage) {
                if (cut == "abort-flush" && stage == "authorization-disposition-after-intent") {
                    reached = true;
                    tx->SetJournalFaultInjectionHook([&](auto point) {
                        return point == "durable-flush" && ++injected_flushes == 2;
                    });
                } else if (cut == "receipt-flush" && stage == "authorization-disposition-before-receipt") {
                    reached = true;
                    journal->SetWitnessFaultInjectionHook([&](auto point) {
                        return point == "durable-flush" && ++injected_flushes == 1;
                    });
                } else if (!cut.empty() && stage == cut && !reached) { reached = true; return false; }
                return true;
            };
            const auto result = journal->ReconcileUnacceptedAuthorizations(*tx, held, error, hook);
            Require(cut.empty() ? result : (!result && reached), "typed disposition/cut:" + cut + ":" + error);
            journal.reset(); tx.reset(); tx = open(prefix == 2 || prefix == 3); journal = std::make_unique<J>(options);
            auto fresh = endpoint(prepared->Publication().expected_checkpoint_xid);
            Require(journal->ReconcileUnacceptedAuthorizations(*tx, fresh, error), "fresh owner disposition resume:" + error);
            std::vector<std::uint64_t> spent;
            Require(journal->ValidateUnacceptedDispositions(*tx, spent, error) && spent.size() == 1 &&
                tx->NextMutationSequence() == spent.front() + 1 && !tx->Watermarks().accepted_sequence &&
                !tx->Watermarks().apfs_durable_sequence && !tx->Watermarks().cleanup_sequence && !tx->HasUnappliedAcceptedWork(),
                "exact spent boundary without Accepted or APFS progress");
            NoIoTarget no_io; no_io.binding = binding;
            Require(!journal->PublishOrRecover(*tx, spent.front(), no_io, error) && !no_io.calls,
                "spent authorization cannot reach any APFS target method");
            const auto completed = Snapshot(directory);
            Require(journal->ReconcileUnacceptedAuthorizations(*tx, fresh, error) && Snapshot(directory) == completed, "idempotent receipt preserves bytes");
            std::unique_ptr<const c::SoftwareVolumeRetainedOwners> restored;
            Require(journal->TryRestoreTransitionRetainedOwners(*tx, *source, restored, error) && !restored,
                "spent transition cannot become an accepted owner certificate:" + error);
            std::uint64_t next_accepted = 0;
            Require((v6 ? journal->AcceptTransition(*tx, *transition, next_accepted, error) :
                journal->AcceptMaintenance(*tx, *prepared, next_accepted, error)) && next_accepted > spent.front(),
                "genuine typed acceptance remains available after spent range:" + error);
            Require(journal->ValidateUnacceptedDispositions(*tx, spent, error), "receipt remains valid after append:" + error);
            Require(DigestFile(image) == initial_image, "whole image unchanged; disposition has no APFS writer");
            std::cout << "PASS v" << (v6 ? 6 : 4) << " prefix=" << prefix << " cut=" << cut << '\n' << std::flush;
        }
        std::cout << "PASS typed unaccepted authorization checks=" << checks << " imageUnchanged=true\n";
        return 0;
    }
};
}

int wmain(int argc, wchar_t** argv)
{
    try {
        if (argc == 4 && std::wstring_view(argv[3]) == L"--carry")
            return apfsaccess::rw::AuthorizationDispositionTestAccess::RunCarry(argv[1], argv[2]);
        if (argc == 4 && std::wstring_view(argv[3]) == L"--carry-retention-only")
            return apfsaccess::rw::AuthorizationDispositionTestAccess::RunCarry(argv[1], argv[2], false);
        if (argc == 4 && std::wstring_view(argv[3]) == L"--carry-prepared-startup")
            return apfsaccess::rw::AuthorizationDispositionTestAccess::RunCarry(argv[1], argv[2], false, true);
        if (argc != 3) throw std::runtime_error("fresh absolute test root and private image required");
        return apfsaccess::rw::AuthorizationDispositionTestAccess::Run(argv[1], argv[2]);
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
