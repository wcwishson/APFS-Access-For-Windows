#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#undef CreateFile
#undef CreateDirectory
#include "ProtectedJournalContinuation.h"
#include "TransactionManager.h"
#include <cstring>
#include <iostream>
#include <map>
#include <stdexcept>
#include <type_traits>
#ifdef APFSACCESS_CONTINUATION_PROFILE
#include "Profile.h"
#include "ContinuationIoProbe.h"
#endif

#undef CreateFile
#undef CreateDirectory
namespace apfsaccess::rw
{
// This tests the file protocol with a private trusted test authorizer. Actual
// production Journal/held-APFS authority is tested by the separate runtime gate.
struct ProtectedContinuationTestAccess
{
    using C = ProtectedJournalContinuation;
    static inline unsigned checks = 0;
    static void Check(bool ok, const std::string& text)
    { ++checks; if (!ok) throw std::runtime_error(text); }
    static C::Digest Hash(std::span<const std::byte> bytes)
    {
        C::Digest digest{};
        Check(BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0, reinterpret_cast<PUCHAR>(const_cast<std::byte*>(bytes.data())),
            static_cast<ULONG>(bytes.size()), digest.data(), static_cast<ULONG>(digest.size())) >= 0, "SHA256"); return digest;
    }
    static std::vector<std::byte> Read(const std::filesystem::path& path)
    {
        const auto h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        Check(h != INVALID_HANDLE_VALUE, "read evidence"); LARGE_INTEGER size{};
        Check(GetFileSizeEx(h, &size) && size.QuadPart >= 0 && size.QuadPart <= (4 << 20), "bounded evidence");
        std::vector<std::byte> bytes(static_cast<std::size_t>(size.QuadPart)); DWORD count = 0;
        const bool ok = ReadFile(h, bytes.data(), static_cast<DWORD>(bytes.size()), &count, nullptr) && count == bytes.size();
        CloseHandle(h); Check(ok, "complete evidence read"); return bytes;
    }
    static auto Snapshot(const std::filesystem::path& root)
    {
        std::map<std::wstring, C::Digest> result;
        for (const auto& entry : std::filesystem::recursive_directory_iterator(root))
            if (entry.is_regular_file()) result.emplace(entry.path().wstring(), Hash(Read(entry.path())));
        return result;
    }
    struct World
    {
        std::filesystem::path root;
        WriteAheadLog::Options original, witness_options;
        PayloadSpool::Options spool_options;
        std::unique_ptr<TransactionManager> tm;
        std::unique_ptr<WriteAheadLog> witness;
        std::unique_ptr<PayloadSpool> spool;
        std::array<std::byte, 4096> raw{};
        std::vector<PayloadSpool::PersistedRangeReference> known_references;
        std::uint64_t next_witness = 0;
        std::string error;
        explicit World(const std::filesystem::path& path) : root(path)
        {
            Check(CreateDirectoryW(root.c_str(), nullptr) != FALSE, "fresh scenario");
            for (const auto* name : {L"o", L"w", L"p", L"pk"}) Check(CreateDirectoryW((root / name).c_str(), nullptr) != FALSE, "fresh authority directory");
            WriteAheadLog::ProtectedPersistence op, wp;
            op.source_binding[0] = std::byte{0x21}; op.journal_identity[0] = std::byte{0x31}; op.key_directory = root / L"o";
            wp = op; wp.journal_identity[0] = std::byte{0x32}; wp.key_directory = root / L"w";
            const auto volume = "continuation-native:" + TransactionManager::WideToUtf8(root.wstring());
            original = {root / L"original.wal", volume, 4u << 20, op};
            witness_options = {root / L"witness.wal", volume + ":witness", 4u << 20, wp};
            spool_options = {root / L"p", volume}; spool_options.protected_persistence = true;
            spool_options.protected_binding = op.source_binding; spool_options.protected_key_directory = root / L"pk";
            raw.fill(std::byte{0x71}); New();
            tm->SetJournalMaxBytesForTest(original.max_bytes);
            Check(tm->OpenProtectedJournal(original.path.wstring(), std::wstring(volume.begin(), volume.end()), op, error), "fresh original:" + error);
        }
        void Close() { witness.reset(); tm.reset(); spool.reset(); }
        void New()
        {
            next_witness = 0;
            tm = std::make_unique<TransactionManager>(L"conservative");
            witness = std::make_unique<WriteAheadLog>(witness_options);
            spool = std::make_unique<PayloadSpool>(spool_options);
        }
        auto Endpoint()
        {
            C::Endpoint::Description d; d.source_binding = original.protected_persistence->source_binding;
            d.source_identity = "native-test-held-source"; d.container_uuid = std::string(32, 'a'); d.volume_uuid = std::string(32, 'b');
            d.container_bytes = 4096; d.volume_object_id = 1026; d.checkpoint_xid = 7;
            d.physical_nx_bytes.assign(raw.begin(), raw.end()); d.physical_nx_sha256 = Hash(raw);
            const auto expected = d.physical_nx_sha256;
            return C::Endpoint(std::move(d), [this, expected](std::string&) { return Hash(raw) == expected; },
                [this](std::uint64_t at, std::span<std::byte> bytes, std::string&) {
                    if (at || bytes.size() != raw.size()) return false; std::copy(raw.begin(), raw.end(), bytes.begin()); return true;
                });
        }
        C::Authority Authority(const C::RecoveryEvidence& e)
        {
            C::Seed seed; Check(C::ValidateOriginalEvidence(e, seed, error), "actual original semantics:" + error);
            Check(seed.accepted_sequence && seed.accepted_sequence == seed.durable_sequence && seed.accepted_sequence == seed.cleanup_sequence,
                "actual clean original boundaries");
            Check(e.witness.status == WriteAheadLog::ReadStatus::Ok && !e.witness.records.empty(), "actual authenticated witness");
            C::Authority a; a.source_binding = original.protected_persistence->source_binding;
            a.original_journal_identity = original.protected_persistence->journal_identity; a.witness_journal_identity = witness_options.protected_persistence->journal_identity;
            const auto scope = Hash(std::as_bytes(std::span(original.volume_identity)));
            std::memcpy(a.scope_binding.data(), scope.data(), scope.size()); a.original_head = e.original_head; a.witness_head = e.witness_head;
            a.original_seed = seed; a.witness_last_sequence = e.witness_head.last_sequence;
            a.witness_retained_first_sequence = e.witness.records.back().sequence;
            a.checkpoint_xid = 7; a.complete_publication_sha256 = Hash(e.witness.records.back().inline_payload); a.planned_guard_sha256 = Hash(raw);
            return a;
        }
        void Commit(bool physical = false, bool through_bridge = true)
        {
            const auto sequence = tm->NextMutationSequence(); Check(tm->Begin(), "Begin");
            const auto transaction = tm->current_transaction_id_;
            TransactionManager::MutationIntent m; m.path = L"native-continuation-canary"; m.object_id = 42; m.generation = 7;
            if (physical) {
                const std::array data{std::byte{0x59}}; PayloadSpool::AppendResult appended;
                Check(spool->Append({original.volume_identity, m.object_id, m.generation, 0, sequence, data}, &appended) && spool->FlushPayloadBytes(), "real physical spool before acceptance");
                Check(appended.spool_offset == 0, "bounded all-clean physical reuse");
                m.kind = TransactionManager::MutationKind::Write; m.length = m.payload_length = 1;
                m.payload_spool_offset = appended.spool_offset; m.payload_checksum = appended.payload_sha256;
                known_references.push_back({original.volume_identity, m.object_id, m.generation, 0, 1,
                    appended.spool_offset, sequence, appended.payload_sha256});
            } else m.kind = TransactionManager::MutationKind::CreateFile;
            Check(tm->RecordMutation(m) && tm->Accept(7), "real TM accepted original");
            const auto accepted = tm->Watermarks().accepted_sequence;
            Check(tm->MarkApfsDurableThrough(accepted) && tm->MarkCleanedThrough(accepted), "caller-proved test endpoint watermarks");
            if (!next_witness) {
                const auto existing = witness->ReadAllWithExclusiveWriterLease(); Check(existing.status == WriteAheadLog::ReadStatus::Ok, "witness prior read");
                next_witness = existing.records.empty() ? 1 : existing.records.back().sequence + 1;
            }
            WriteAheadLog::Record row; row.volume_identity = witness_options.volume_identity; row.sequence = next_witness;
            row.transaction_id = transaction; row.object_id = 42; row.parent_object_id = accepted;
            row.path_utf8 = "native-trusted-witness"; row.inline_payload.assign(32, std::byte{0x41});
            row.inline_payload[0] = std::byte(transaction & 255); row.inline_payload[1] = std::byte((transaction >> 8) & 255);
            row.payload_length = row.logical_length = row.inline_payload.size(); row.payload_sha256 = Hash(row.inline_payload);
            Check(witness->Append(row), "real protected witness frame");
            ++next_witness;
            if (!through_bridge) {
                // This single exclusive writer produced every actual accepted
                // row and every reference above. Track that complete history
                // during setup; final continuation independently re-decodes it
                // through the production TM bridge before any retirement.
                const auto bytes = Read(original.path); const auto marks = tm->Watermarks();
                PayloadSpool::ProtectedCleanupProof proof;
                proof.source_binding = original.protected_persistence->source_binding;
                proof.wal_sha256 = Hash(bytes); proof.wal_bytes = bytes.size(); proof.wal_records = tm->next_sequence_ - 1;
                proof.wal_last_sequence = tm->next_sequence_ - 1; proof.durable_sequence = marks.apfs_durable_sequence;
                proof.cleanup_sequence = marks.cleanup_sequence;
                Check(spool->ReconcileProtectedHistory(proof, known_references) == PayloadSpool::ProtectedMaintenanceResult::Succeeded,
                    "actual accepted writer history setup census");
                return;
            }
            WriteAheadLog::ProtectedHistoryHead head;
            Check(tm->CaptureProtectedOriginalHistoryHead(head, error) &&
                tm->ReconcileProtectedPayloadSpool(*spool, head, error) == PayloadSpool::ProtectedMaintenanceResult::Succeeded,
                "complete actual original-derived census:" + error);
        }
        C::Result Continue(std::string_view cut = {}, const C::StageHook& observed = {}, const C::ProgressHook& progress = {})
        {
            C::RecoveryEvidence e; Check(C::CaptureEvidence(*tm, *witness, e, error), "capture actual streams:" + error);
            auto a = Authority(e); const auto expected = a;
            a.flush_and_recheck = [this, expected](std::string& reason) {
                return C::FlushCleanOriginalEvidence(*tm, expected.original_head, expected.original_seed.cleanup_sequence, reason) && witness->FlushPendingAppends();
            };
            auto endpoint = Endpoint();
            return C::Continue(*tm, *spool, *witness, a, endpoint, error, [&](std::string_view stage) {
                return (!observed || observed(stage)) && stage != cut;
            }, progress);
        }
        C::Result Reopen(const C::ProgressHook& progress = {})
        {
            Close(); New(); auto endpoint = Endpoint();
            return C::OpenOrRecover(*tm, original, *spool, *witness, endpoint,
                [this](const auto& e, C::Authority& a, std::string&) {
                    a = Authority(e); a.flush_and_recheck = [](std::string&) { return true; }; return true;
                }, error, {}, progress);
        }
    };
    static void TypedProgress(const std::filesystem::path& root)
    {
        static_assert(!std::is_copy_constructible_v<C::DurableProgress>);
        static_assert(!std::is_move_constructible_v<C::DurableProgress>);
        static_assert(!std::is_default_constructible_v<C::DurableProgress>);
        static_assert(!std::is_constructible_v<C::DurableProgress, C::DurableBoundary,
            std::uint8_t, std::uint8_t, std::uint8_t>);
        std::vector<unsigned> slots;
        const auto observe = [&](const C::DurableProgress& event) {
            Check(event.Slot() < 20 && event.Ordinal() == slots.size() + 1 &&
                std::find(slots.begin(), slots.end(), event.Slot()) == slots.end(), "distinct bounded ordered typed event");
            using B = C::DurableBoundary;
            if (event.Boundary() == B::ControlRenamed)
                Check(event.Index() >= 5 && event.Index() <= 8 && event.Slot() == event.Index() - 2, "control proof identity");
            else if (event.Boundary() == B::CandidateFlushed || event.Boundary() == B::OldRenamed || event.Boundary() == B::NewRenamed)
                Check(event.Index() < 3 && event.Slot() == event.Index() + (event.Boundary() == B::CandidateFlushed ? 8u :
                    event.Boundary() == B::OldRenamed ? 11u : 14u), "stream proof identity");
            else Check(event.Index() == 0, "nonindexed proof identity");
            slots.push_back(event.Slot()); return true;
        };
        World normal(root / L"typed"); normal.Commit(true);
        Check(normal.Continue({}, {}, observe) == C::Result::Succeeded, "typed first continuation:" + normal.error);
        Check(slots == std::vector<unsigned>({0,1,2,7,8,11,14,9,12,15,10,13,16,17,18,19}), "first generation actual completed barriers only");
        slots.clear(); normal.Commit(true);
        Check(normal.Continue({}, {}, observe) == C::Result::Succeeded, "typed second continuation:" + normal.error);
        Check(slots == std::vector<unsigned>({0,1,2,3,4,5,6,7,8,11,14,9,12,15,10,13,16,17,18,19}), "twenty distinct second-generation barriers");
        slots.clear(); Check(normal.Reopen(observe) == C::Result::Succeeded, "typed complete fresh admission:" + normal.error);
        Check(slots == std::vector<unsigned>({2}), "read-only admission emits only its unconditional exact-evidence barrier");
        normal.Commit(true);

        World cut(root / L"typed-cut"); cut.Commit(true); slots.clear();
        const auto original = Read(cut.original.path);
        Check(cut.Continue("continuation-before-candidate-flush-0", {}, observe) == C::Result::RecoveryRequired,
            "before candidate barrier cut requires recovery");
        Check(slots == std::vector<unsigned>({0,1,2,7}) && Read(cut.original.path) == original,
            "before-stage string never mints a candidate token or renames original");
        slots.clear(); Check(cut.Reopen(observe) == C::Result::Succeeded, "typed interrupted fresh recovery:" + cut.error);
        Check(slots == std::vector<unsigned>({2,7,8,11,14,9,12,15,10,13,16,17,18,19}), "fresh recovery proof namespace and ordinal");
        cut.Commit(true);

        World refusal(root / L"typed-refusal"); refusal.Commit(true); slots.clear();
        const auto retained = Read(refusal.original.path);
        Check(refusal.Continue({}, {}, [&](const auto& event) { observe(event); return event.Slot() != 8; }) == C::Result::RecoveryRequired,
            "typed observer refusal is explicit recovery debt");
        Check(slots == std::vector<unsigned>({0,1,2,7,8}) && Read(refusal.original.path) == retained &&
            GetFileAttributesW((refusal.original.path.wstring() + L".jcont.old").c_str()) == INVALID_FILE_ATTRIBUTES,
            "observer refusal stops before next old-name mutation");
        Check(refusal.Reopen() == C::Result::Succeeded, "observer refusal retains recoverable intent:" + refusal.error);
        refusal.Commit(true);

        World barrier(root / L"typed-barrier"); barrier.Commit(true); slots.clear();
        const auto before = Snapshot(barrier.root);
        barrier.tm->SetJournalFaultInjectionHook([](auto stage) { return stage == "durable-flush"; });
        Check(barrier.Continue({}, {}, observe) == C::Result::RejectedBeforeWrite && slots.empty() && Snapshot(barrier.root) == before,
            "failed original barrier mints nothing and preserves bytes");
#ifdef APFSACCESS_CONTINUATION_PROFILE
        World fault(root / L"typed-flush"); fault.Commit(true); slots.clear();
        const auto original_fault = Read(fault.original.path);
        continuation_io::Begin(fault.root.wstring());
        continuation_io::FailNextFlush(fault.original.path.wstring() + L".jcont.next");
        const auto result = fault.Continue({}, {}, observe); continuation_io::Stop();
        Check(result == C::Result::RecoveryRequired && !continuation_io::state.armed &&
            slots == std::vector<unsigned>({0,1,2,7}) && Read(fault.original.path) == original_fault,
            "actual failed candidate flush cannot mint completed proof");
        Check(fault.Reopen() == C::Result::Succeeded, "typed failed-flush recovery:" + fault.error);
        fault.Commit(true);
#endif
        std::cout << "PASS typed completed barriers, refusal, failure and fresh recovery\n" << std::flush;
    }
    static void WarmKeys(const std::filesystem::path& root)
    {
        World keys(root / L"warm-keys"); keys.Commit(true);
        Check(keys.Continue() == C::Result::Succeeded, "warm receipt-key setup:" + keys.error);
        std::vector<std::filesystem::path> slots;
        for (const auto& file : std::filesystem::directory_iterator(keys.original.protected_persistence->key_directory))
            if (file.path().extension() == L".key") slots.push_back(file.path());
        Check(slots.size() >= 5, "original, certificate and three distinct receipt epochs exist");
        const auto key_snapshot = Snapshot(keys.root); unsigned refused = 0;
        for (const auto& slot : slots) {
            const auto saved = std::filesystem::path(slot.wstring() + L".probe-saved");
            Check(MoveFileW(slot.c_str(), saved.c_str()) != FALSE, "retain exact slot during warm missing-key probe");
            const auto read = keys.tm->journal_.ReadAllWithExclusiveWriterLease();
            if (read.status != WriteAheadLog::ReadStatus::Ok) ++refused;
            std::cout << "KEY PROBE " << slot.filename().string() << " status=" << static_cast<unsigned>(read.status) << '\n' << std::flush;
            Check(MoveFileW(saved.c_str(), slot.c_str()) != FALSE, "restore exact slot without replacement/deletion");
            Check(keys.Reopen() == C::Result::Succeeded, "fresh owner after restored exact key:" + keys.error);
        }
        const auto after = Snapshot(keys.root);
        bool preserved = true;
        for (const auto& [path, digest] : key_snapshot) {
            const auto it = after.find(path);
            if (it == after.end() || it->second != digest) preserved = false;
        }
        for (const auto& [path, digest] : after) {
            const auto it = key_snapshot.find(path);
            if (it == key_snapshot.end()) {
                const auto file = std::filesystem::path(path);
                if (file.extension() != L".key" || !file.filename().wstring().starts_with(L"epoch-")) preserved = false;
            } else if (it->second != digest) preserved = false;
        }
        std::cout << "KEY PROBES refused=" << refused << " slots=" << slots.size() << " preserved=" << preserved << '\n' << std::flush;
        Check(refused >= 4 && preserved,
            "warm reader checks certificate and receipt keys; prior evidence preserved and only fresh epoch slots added");
    }
    static void GeneratedPaths(const std::filesystem::path& root)
    {
        const std::wstring longest = L".jcont.certificate.previous";
        for (const bool oversized : {true, false}) {
            World world(root / (oversized ? L"path-refuse" : L"path-boundary")); world.Close();
            const auto length = 210 - longest.size() + (oversized ? 1 : 0);
            const auto prefix = world.root.wstring().size() + 1;
            Check(prefix < length, "bounded generated-path fixture");
            world.original.path = world.root / std::wstring(length - prefix, L'x');
            world.New(); const auto before = Snapshot(world.root); auto endpoint = world.Endpoint(); unsigned called = 0;
            const auto result = C::OpenOrRecover(*world.tm, world.original, *world.spool, *world.witness, endpoint,
                [&](const auto&, C::Authority&, std::string&) { ++called; return false; }, world.error);
            Check(called == 0, "virgin path check never invokes recovery authorizer");
            if (oversized) {
                Check(result == C::Result::RejectedBeforeWrite && world.error == "ContinuationGeneratedPathUnsafe",
                    "generated continuation path refused before original open");
                Check(Snapshot(world.root) == before, "invalid generated path preserves all evidence");
            } else Check(result == C::Result::Succeeded, "exact generated-path boundary admits virgin original:" + world.error);
        }
    }
    static void CandidatePrefixes(const std::filesystem::path& root)
    {
        for (unsigned profile = 0; profile < 3; ++profile) {
            World world(root / (L"prefix" + std::to_wstring(profile))); world.Commit(true);
            const auto original = Read(world.original.path);
            Check(world.Continue("continuation-before-candidate-flush-0") == C::Result::RecoveryRequired,
                "complete buffered candidate leaves explicit debt before its flush");
            Check(Read(world.original.path) == original, "unflushed candidate cannot change original canonical bytes");
            world.Close(); const auto next = std::filesystem::path(world.original.path.wstring() + L".jcont.next");
            auto bytes = Read(next); Check(bytes.size() > 17, "real complete encrypted candidate");
            const auto saved = world.root / L"candidate-evidence";
            Check(MoveFileW(next.c_str(), saved.c_str()) != FALSE, "retain exact interrupted candidate");
            if (profile < 2) bytes.resize(17); else bytes.push_back(std::byte{0x37});
            if (profile == 1) bytes[0] ^= std::byte{1};
            const auto handle = CreateFileW(next.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_NEW,
                FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
            Check(handle != INVALID_HANDLE_VALUE, "fresh candidate failure fixture"); DWORD written = 0;
            const bool wrote = WriteFile(handle, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr) &&
                written == bytes.size() && FlushFileBuffers(handle); CloseHandle(handle);
            Check(wrote, "actual partial, foreign-prefix or oversized candidate bytes");
            const auto before = Snapshot(world.root); const auto result = world.Reopen();
            if (profile == 0) {
                Check(result == C::Result::Succeeded, "exact ciphertext prefix rebuilds from authenticated intent:" + world.error);
                world.Commit(true);
            } else Check(result == C::Result::RecoveryRequired && Snapshot(world.root) == before,
                "foreign prefix/unknown candidate tail refuses without evidence mutation");
        }
    }
#ifdef APFSACCESS_CONTINUATION_PROFILE
    static void CandidateIo(const std::filesystem::path& root)
    {
        using continuation_io::Kind;
        const auto assert_flags = [] {
            bool candidate = false;
            for (const auto& event : continuation_io::state.events) if (event.kind == Kind::Open && event.success) {
                if (event.path.ends_with(L".jcont.next")) {
                    candidate = true; Check(!(event.flags & FILE_FLAG_WRITE_THROUGH), "only private candidate is buffered");
                } else if (event.path.find(L".jcont.") != event.path.npos)
                    Check((event.flags & FILE_FLAG_WRITE_THROUGH) != 0, "control and receipt opens retain write-through");
            }
            Check(candidate && !continuation_io::state.overflow, "bounded actual candidate I/O observations");
        };
        {
            World world(root / L"buffered-success"); world.Commit(true);
            const std::array bases{world.original.path, world.witness_options.path, world.spool_options.root / L"payload-spool.idx"};
            continuation_io::Begin(world.root.wstring());
            const auto result = world.Continue(); continuation_io::Stop();
            Check(result == C::Result::Succeeded, "buffered candidates complete real continuation:" + world.error);
            assert_flags();
            for (const auto& base : bases) {
                const auto next = base.wstring() + L".jcont.next"; unsigned writes = 0;
                bool durable = false, old_renamed = false, new_renamed = false, canonical_durable = false;
                for (const auto& event : continuation_io::state.events) {
                    if (!event.success) continue;
                    if (event.kind == Kind::Write && continuation_io::Same(event.path, next)) ++writes;
                    if (event.kind == Kind::Flush && continuation_io::Same(event.path, next)) durable = true;
                    if (event.kind == Kind::Rename && continuation_io::Same(event.path, base.wstring())) {
                        Check(durable && !old_renamed, "old name changes only after candidate durability"); old_renamed = true;
                    }
                    if (event.kind == Kind::Rename && continuation_io::Same(event.path, next)) {
                        Check(old_renamed, "candidate promotion follows original archive"); new_renamed = true;
                    }
                    if (event.kind == Kind::Flush && continuation_io::Same(event.path, base.wstring()) && new_renamed)
                        canonical_durable = true;
                }
                Check(writes == 1 && durable && old_renamed && new_renamed && canonical_durable,
                    "one candidate content write with both required publication barriers");
            }
            Check(world.Reopen() == C::Result::Succeeded, "buffered positive fresh reopen:" + world.error); world.Commit(true);
        }
        for (unsigned n = 0; n < 3; ++n) {
            World world(root / (L"flush" + std::to_wstring(n))); world.Commit(true);
            const std::array bases{world.original.path, world.witness_options.path, world.spool_options.root / L"payload-spool.idx"};
            const auto old = Read(bases[n]);
            continuation_io::Begin(world.root.wstring());
            continuation_io::FailNextFlush(bases[n].wstring() + L".jcont.next");
            const auto result = world.Continue(); continuation_io::Stop();
            Check(result == C::Result::RecoveryRequired && !continuation_io::state.armed,
                "actual required candidate flush failure refuses promotion");
            assert_flags();
            Check(Read(bases[n]) == old && GetFileAttributesW((bases[n].wstring() + L".jcont.old").c_str()) == INVALID_FILE_ATTRIBUTES,
                "failed candidate barrier preserves its canonical bytes and name");
            Check(world.Reopen() == C::Result::Succeeded, "fresh owner flushes complete candidate and finishes:" + world.error);
            world.Commit(true);
        }
        for (unsigned n = 0; n < 3; ++n) {
            World world(root / (L"rename" + std::to_wstring(n))); world.Commit(true);
            const std::array bases{world.original.path, world.witness_options.path, world.spool_options.root / L"payload-spool.idx"};
            const auto old = Read(bases[n]); bool armed = false;
            continuation_io::Begin(world.root.wstring());
            const auto result = world.Continue({}, [&](std::string_view stage) {
                if (stage == "continuation-after-old-rename-" + std::to_string(n)) {
                    armed = true; continuation_io::FailNextFlush(bases[n].wstring());
                }
                return true;
            });
            continuation_io::Stop();
            Check(armed && !continuation_io::state.armed && result == C::Result::RecoveryRequired,
                "actual new rename succeeds then its flush fails");
            Check(Read(std::filesystem::path(bases[n].wstring() + L".jcont.old")) == old,
                "original archived bytes survive new-rename flush failure");
            continuation_io::Begin(world.root.wstring()); continuation_io::FailNextFlush(bases[n].wstring());
            const auto retry = world.Reopen(); continuation_io::Stop();
            Check(retry == C::Result::RecoveryRequired && !continuation_io::state.armed &&
                GetFileAttributesW((world.original.path.wstring() + L".jcont.done").c_str()) == INVALID_FILE_ATTRIBUTES,
                "fresh recovery must flush already-renamed canonical before completion receipt");
            Check(world.Reopen() == C::Result::Succeeded, "exact retained candidate recovers after barrier restored:" + world.error);
            world.Commit(true);
        }
        World certificate(root / L"certificate-flush"); certificate.Commit(true);
        const auto canonical = certificate.original.path.wstring() + L".jcont.certificate";
        continuation_io::Begin(certificate.root.wstring());
        const auto result = certificate.Continue({}, [&](std::string_view stage) {
            if (stage == "continuation-after-recovery-barrier") continuation_io::FailNextFlush(canonical);
            return true;
        });
        continuation_io::Stop();
        Check(result == C::Result::RecoveryRequired && !continuation_io::state.armed,
            "certificate rename succeeds then its flush fails");
        continuation_io::Begin(certificate.root.wstring()); continuation_io::FailNextFlush(canonical);
        const auto retry = certificate.Reopen(); continuation_io::Stop();
        Check(retry == C::Result::RecoveryRequired && !continuation_io::state.armed &&
            GetFileAttributesW((certificate.original.path.wstring() + L".jcont.old").c_str()) == INVALID_FILE_ATTRIBUTES,
            "fresh recovery must flush canonical certificate before stream promotion");
        Check(certificate.Reopen() == C::Result::Succeeded, "certificate recovery barrier restored:" + certificate.error);
        certificate.Commit(true);
        CandidatePrefixes(root); GeneratedPaths(root);
    }
#endif
    static void Run(const std::filesystem::path& root, bool receipt_limit, bool warm_only,
        bool profile_eight = false, bool candidate_io = false, bool typed_progress = false)
    {
        if (typed_progress) { TypedProgress(root); return; }
#ifdef APFSACCESS_CONTINUATION_PROFILE
        if (candidate_io) { CandidateIo(root); return; }
        if (profile_eight) {
            World world(root / L"eight");
            for (unsigned n = 0; n < 8; ++n) world.Commit(n == 0);
            profile::values = {};
            auto start = std::chrono::steady_clock::now();
            auto previous = start;
            auto counters = profile::values;
            const auto emit = [&](std::string_view stage) {
                const auto now = std::chrono::steady_clock::now();
                auto delta = profile::values;
                for (std::size_t n = 0; n < delta.size(); ++n) {
                    delta[n].calls -= counters[n].calls; delta[n].ns -= counters[n].ns;
                }
                std::cout << "PROFILE " << stage << " us=" <<
                    std::chrono::duration_cast<std::chrono::microseconds>(now - previous).count() << ' ';
                profile::Emit(std::cout, delta); std::cout << '\n' << std::flush;
                previous = now; counters = profile::values; return true;
            };
            Check(world.Continue({}, emit) == C::Result::Succeeded, "profile actual continuation:" + world.error);
            emit("return");
            std::cout << "PROFILE TOTAL us=" << std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - start).count() << ' ';
            profile::Emit(std::cout, profile::values); std::cout << '\n' << std::flush;
            Check(world.Reopen() == C::Result::Succeeded, "profile fresh reopen:" + world.error);
            world.Commit(true);
            return;
        }
#else
        Check(!profile_eight && !candidate_io, "profiling requires the private instrumentation build");
#endif
        if (warm_only) { WarmKeys(root); return; }
        if (receipt_limit) {
            World world(root / L"limit");
            for (unsigned n = 0; n < 1024; ++n) {
                world.Commit(n == 0, false);
                if ((n + 1) % 128 == 0) std::cout << "RECEIPTS " << n + 1 << '\n' << std::flush;
            }
            unsigned receipts = 0; for (const auto& f : std::filesystem::directory_iterator(world.spool_options.root))
                if (f.path().filename().wstring().starts_with(L"payload-spool.cleanup.")) ++receipts;
            Check(receipts == 2048, "actual full bounded receipt chain");
            Check(world.Continue() == C::Result::Succeeded, "1024-pair complete continuation:" + world.error);
            Check(world.Reopen() == C::Result::Succeeded, "1024-pair fresh reopen:" + world.error);
            world.Commit(true);
            receipts = 0; for (const auto& f : std::filesystem::directory_iterator(world.spool_options.root))
                if (f.path().filename().wstring().starts_with(L"payload-spool.cleanup.")) ++receipts;
            Check(receipts == 2, "bounded receipt namespace and exact physical reuse after full chain");
            std::cout << "PASS actual 1024 receipt pairs, original-derived retirement, reopen and physical reuse\n"; return;
        }
        unsigned n = 0;
        for (const auto* cut : {"continuation-after-intent-flush", "continuation-after-certificate-promotion",
            "continuation-before-candidate-flush-0", "continuation-after-candidate-0", "continuation-after-old-rename-0", "continuation-after-new-rename-0",
            "continuation-before-candidate-flush-1", "continuation-after-candidate-1",
            "continuation-after-old-rename-1", "continuation-after-new-rename-1", "continuation-after-old-rename-2",
            "continuation-before-candidate-flush-2", "continuation-after-candidate-2", "continuation-after-new-rename-2", "continuation-after-completion-receipt", "continuation-after-retirement-receipt",
            "continuation-after-retirement-1-0", "continuation-after-retirement-4-1", "continuation-after-ready-receipt", "continuation-after-admission"}) {
            World w(root / (L"c" + std::to_wstring(++n))); w.Commit(true); w.Commit();
            const auto before = w.tm->Watermarks(); const auto next = w.tm->NextMutationSequence();
            Check(w.Continue(cut) == C::Result::RecoveryRequired, "cut must leave explicit recovery debt:" + std::string(cut) + ":" + w.error);
            Check(w.Reopen() == C::Result::Succeeded, "reopen cut:" + std::string(cut) + ":" + w.error);
            Check(w.tm->NextMutationSequence() == next && w.tm->Watermarks().cleanup_sequence == before.cleanup_sequence, "exact global seed after cut");
            w.Commit(true); Check(w.tm->NextMutationSequence() > next, "real new acceptance/reclaim after cut");
            std::cout << "PASS " << cut << '\n' << std::flush;
        }
        World failed(root / L"barrier"); failed.Commit(true);
        const auto snapshot = Snapshot(failed.root);
        failed.tm->SetJournalFaultInjectionHook([](auto stage) { return stage == "durable-flush"; });
        Check(failed.Continue() == C::Result::RejectedBeforeWrite, "failed original barrier refuses");
        Check(Snapshot(failed.root) == snapshot, "failed original barrier preserves all bytes and paths");
        World corrupt(root / L"corrupt"); corrupt.Commit(true); Check(corrupt.Continue() == C::Result::Succeeded, "tamper setup"); corrupt.Close();
        const auto path = std::filesystem::path(corrupt.original.path.wstring() + L".jcont.certificate"); auto bytes = Read(path); bytes.back() ^= std::byte{1};
        const auto h = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        Check(h != INVALID_HANDLE_VALUE, "closed certificate mutation"); DWORD count = 0;
        Check(WriteFile(h, bytes.data(), static_cast<DWORD>(bytes.size()), &count, nullptr) && count == bytes.size() && FlushFileBuffers(h), "actual tag tamper"); CloseHandle(h);
        const auto damaged = Snapshot(corrupt.root);
        Check(corrupt.Reopen() == C::Result::RecoveryRequired && Snapshot(corrupt.root) == damaged, "corrupt certificate refuses and preserves all evidence");
        WarmKeys(root); CandidatePrefixes(root); GeneratedPaths(root);
    }
};
}

int wmain(int argc, wchar_t** argv)
{
    using Test = apfsaccess::rw::ProtectedContinuationTestAccess;
    try {
        Test::Check(argc == 2 || (argc == 3 && (std::wstring_view(argv[2]) == L"--receipt-limit" ||
            std::wstring_view(argv[2]) == L"--warm-keys-only" || std::wstring_view(argv[2]) == L"--profile-eight" ||
            std::wstring_view(argv[2]) == L"--candidate-io" || std::wstring_view(argv[2]) == L"--typed-progress")),
            "fresh absolute root and optional focused mode");
        const auto root = std::filesystem::path(argv[1]).make_preferred(); const auto p = root.wstring();
        Test::Check(p.size() > 3 && p.size() <= 120 && p[1] == L':' && p[2] == L'\\' && GetDriveTypeW(p.substr(0, 3).c_str()) == DRIVE_FIXED, "fixed-local absolute root");
        Test::Check(p.find_first_of(L":/*?\"<>|", 3) == p.npos && p.back() != L'\\', "root syntax");
        for (const auto& component : root.relative_path()) {
            const auto s = component.wstring(); Test::Check(!s.empty() && s != L"." && s != L".." && s.back() != L'.' && s.back() != L' ', "canonical root component");
        }
        std::vector<HANDLE> pins;
        for (auto parent = root.parent_path(); !parent.empty(); parent = parent.parent_path()) {
            const auto h = CreateFileW(parent.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
            BY_HANDLE_FILE_INFORMATION info{}; Test::Check(h != INVALID_HANDLE_VALUE && GetFileInformationByHandle(h, &info) &&
                (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && !(info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT), "resolved regular ancestor"); pins.push_back(h);
            if (parent == parent.root_path()) break;
        }
        Test::Check(CreateDirectoryW(root.c_str(), nullptr) != FALSE, "fresh root only");
        Test::Run(root, argc == 3 && std::wstring_view(argv[2]) == L"--receipt-limit",
            argc == 3 && std::wstring_view(argv[2]) == L"--warm-keys-only",
            argc == 3 && std::wstring_view(argv[2]) == L"--profile-eight",
            argc == 3 && std::wstring_view(argv[2]) == L"--candidate-io",
            argc == 3 && std::wstring_view(argv[2]) == L"--typed-progress");
        for (const auto h : pins) CloseHandle(h);
        std::cout << "PASS protected continuation file protocol checks=" << Test::checks << '\n'; return 0;
    } catch (const std::exception& e) { std::cerr << "FAIL " << e.what() << '\n'; return 1; }
}
