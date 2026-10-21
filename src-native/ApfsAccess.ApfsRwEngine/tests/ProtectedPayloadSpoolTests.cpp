#include "PayloadSpool.h"
#include "ApfsCryptoTestHooks.h"
#include "WriteAheadLog.h"
#include <windows.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace
{
namespace fs = std::filesystem;
using Spool = apfsaccess::rw::PayloadSpool;
namespace crypto = apfsaccess::crypto;
namespace journal = apfsaccess::journal;
fs::path root;
unsigned assertions = 0, groups = 0;
constexpr char volume[] = "PROTECTED_SPOOL_VOLUME_METADATA_CANARY_20261016";
constexpr char canary[] = "PROTECTED_SPOOL_PAYLOAD_CANARY_57b3f0626bc94e73";
constexpr char keyCanary[] = "SPOOL_KEY_CANARY_20261016_12345678";

struct DirectoryPin
{
    HANDLE handle = INVALID_HANDLE_VALUE;
    ~DirectoryPin() { if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle); }
};

void Check(bool ok, const char* what, int line)
{
    ++assertions;
    if (!ok) throw std::runtime_error(std::string(what) + " at line " + std::to_string(line));
}
#define CHECK(x) Check(static_cast<bool>(x), #x, __LINE__)
std::vector<std::byte> Bytes(std::string_view text)
{
    const auto b = std::as_bytes(std::span(text.data(), text.size()));
    return {b.begin(), b.end()};
}
std::vector<std::byte> Read(const fs::path& path)
{
    // Evidence reads must coexist with receipt handles holding DELETE access;
    // FILE_SHARE_DELETE grants no delete access to this read-only observer.
    DirectoryPin file; file.handle = CreateFileW(path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    CHECK(file.handle != INVALID_HANDLE_VALUE);
    LARGE_INTEGER size{}; CHECK(GetFileSizeEx(file.handle, &size) && size.QuadPart >= 0 && size.QuadPart <= 512ll * 1024 * 1024);
    std::vector<std::byte> result(static_cast<std::size_t>(size.QuadPart)); DWORD got = 0;
    CHECK(ReadFile(file.handle, result.data(), static_cast<DWORD>(result.size()), &got, nullptr) && got == result.size());
    return result;
}
void Write(const fs::path& path, std::span<const std::byte> bytes)
{
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    CHECK(out.good());
    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    CHECK(out.good());
}
Spool::Options Options(std::string_view name)
{
    const auto base = root / std::string(name);
    fs::create_directories(base / "spool"); fs::create_directories(base / "keys");
    Spool::Options o;
    o.root = base / "spool"; o.volume_identity = volume;
    o.max_bytes = 16 * 1024 * 1024;
    o.durable_flush_bytes = 0; o.durable_flush_appends = 0;
    o.protected_persistence = true; o.protected_key_directory = base / "keys";
    for (std::size_t i = 0; i < o.protected_binding.size(); ++i) o.protected_binding[i] = static_cast<std::byte>(i + 11);
    return o;
}
Spool::PersistedRangeReference Ref(const Spool::AppendResult& r)
{
    return {volume, r.object_id, r.generation, r.logical_offset, r.payload_length,
        r.spool_offset, r.wal_sequence, r.payload_sha256};
}
Spool::PersistedRangeReference Seed(const Spool::Options& o, bool index = true)
{
    Spool spool(o); CHECK(!spool.RecoveryRequired());
    Spool::AppendResult result;
    const auto payload = Bytes(canary);
    CHECK(spool.Append({volume, 17, 21, 5, 1, payload}, &result));
    CHECK(index ? spool.FlushDirtyState() : spool.FlushPayloadBytes());
    return Ref(result);
}
auto SpoolBytes(const Spool::Options& o)
{
    return std::pair{Read(o.root / "payload-spool.bin"), Read(o.root / "payload-spool.idx")};
}
void MustRefuse(const Spool::Options& o, const Spool::PersistedRangeReference& ref)
{
    const auto before = SpoolBytes(o);
    {
        Spool spool(o); CHECK(spool.RecoveryRequired());
        const std::array refs{ref};
        CHECK(!spool.RebuildIndexFromReferences(refs, 0));
        Spool::AppendResult result;
        CHECK(!spool.Append({volume, 17, 21, 0, 2, Bytes(canary)}, &result));
        CHECK(result.payload_length == 0);
        CHECK(!spool.FlushPayloadBytes()); CHECK(!spool.FlushDirtyState());
        CHECK(!spool.CleanupThroughSequence(UINT64_MAX)); CHECK(!spool.DiscardSequence(1));
        CHECK(!spool.ResolveUnindexedPayloadRecovery(true));
    }
    CHECK(SpoolBytes(o) == before);
}

void Persistence()
{
    auto o = Options("persistence");
    Spool::PersistedRangeReference a, b, c, d;
    const auto first = Bytes(canary), last = Bytes("xy");
    {
        Spool spool(o); CHECK(!spool.RecoveryRequired());
        Spool second(o); CHECK(second.RecoveryRequired()); // Exclusive file writer pins.
        Spool::AppendResult r;
        CHECK(spool.Append({volume, 17, 21, 5, 5, first}, &r)); a = Ref(r);
        CHECK(r.payload_length == first.size()); CHECK(r.spool_offset == 0);
        CHECK(spool.CheckAppendCapacityFast(1) == Spool::AppendStatus::Succeeded);
        CHECK(spool.FlushPayloadBytes()); CHECK(fs::file_size(o.root / "payload-spool.idx") == 0);
        CHECK(fs::file_size(spool.SpoolFilePath()) == first.size() + 80);
        CHECK(spool.Append({volume, 17, 21, 6, 5, last}, &r)); b = Ref(r);
        CHECK(r.spool_offset == first.size() + 80);
        CHECK(spool.Append({volume, 17, 21, 5, 3, Bytes("OLD")}, &r)); c = Ref(r);
        CHECK(spool.Append({volume, 99, 21, 0, 6, last}, &r)); d = Ref(r);
        CHECK(spool.FlushDirtyState());
        std::vector<std::byte> payload;
        CHECK(spool.ReadPersistedRange(a, payload) && payload == first);
        CHECK(spool.ReadPersistedRange(b, payload) && payload == last);
        auto expected = first; expected[1] = last[0]; expected[2] = last[1];
        std::vector<std::byte> dest(first.size(), std::byte{0}); std::size_t n = 0; std::uint64_t end = 0;
        CHECK(spool.OverlayDirtyRangesWithLogicalEnd({volume, 17, 21, 5, dest}, n, end));
        CHECK(n == first.size() && dest == expected && end == 5 + first.size());
        CHECK(spool.ReadFullyCoveredRange({volume, 17, 21, 5, dest}, n));
        CHECK(spool.IsRangeFullyCovered(volume, 17, 21, 5, first.size()));
        CHECK(spool.MaxDirtyRangeEnd(volume, 17, 21) == end);
        auto gap = Bytes("........"); const auto gapBefore = gap;
        CHECK(!spool.ReadFullyCoveredRange({volume, 17, 21, 0, gap}, n)); CHECK(gap == gapBefore && n == 0);
        CHECK(spool.RestoreInlineRange(a, first));
        const auto before = SpoolBytes(o);
        CHECK(!spool.CleanupThroughSequence(5)); CHECK(!spool.DiscardSequence(5));
        CHECK(spool.CleanupThroughSequence(0)); CHECK(spool.DiscardSequence(999));
        auto missing = a; missing.spool_offset = fs::file_size(spool.SpoolFilePath());
        CHECK(!spool.RestoreInlineRange(missing, first)); CHECK(SpoolBytes(o) == before);
        CHECK(!MoveFileExW(spool.SpoolFilePath().c_str(), (o.root / "renamed").c_str(), 0));
        CHECK(!MoveFileExW(o.root.c_str(), (o.root.parent_path() / "moved").c_str(), 0));
        const auto counters = spool.SnapshotCounters();
        CHECK(counters.append_direct_count == 4 && counters.append_merged_count == 0);
        CHECK(counters.index_persist_count == 1 && counters.spool_sync_handle_flush_count >= 2);
    }
    const std::array refs{d, c, b, a}; // Rebuild accepts unordered complete trusted references.
    const auto slotsBefore = std::distance(fs::directory_iterator(o.protected_key_directory), fs::directory_iterator{});
    {
        Spool spool(o); CHECK(spool.RecoveryRequired());
        std::vector<std::byte> dest(first.size()); std::size_t n = 0;
        CHECK(!spool.OverlayDirtyRanges({volume, 17, 21, 5, dest}, n));
        CHECK(spool.RebuildIndexFromReferences(refs, 0)); CHECK(!spool.RecoveryRequired());
        CHECK(spool.FlushDirtyState());
        std::vector<std::byte> payload; CHECK(spool.ReadPersistedRange(a, payload) && payload == first);
    }
    CHECK(std::distance(fs::directory_iterator(o.protected_key_directory), fs::directory_iterator{}) == slotsBefore + 1);
    Spool again(o); CHECK(again.RebuildIndexFromReferences(refs, 0)); CHECK(again.FlushDirtyState());
}

void References()
{
    auto o = Options("references"); const auto ref = Seed(o);
    Spool spool(o);
    const auto before = SpoolBytes(o);
    const std::array good{ref}; CHECK(spool.RebuildIndexFromReferences(good, 0));
    for (unsigned field = 0; field < 9; ++field)
    {
        auto bad = ref;
        switch (field)
        {
        case 0: bad.volume_identity += "X"; break;
        case 1: ++bad.object_id; break;
        case 2: ++bad.generation; break;
        case 3: ++bad.logical_offset; break;
        case 4: --bad.payload_length; break;
        case 5: ++bad.spool_offset; break;
        case 6: ++bad.wal_sequence; break;
        case 7: bad.payload_sha256[0] ^= 1; break;
        default: bad.spool_offset = UINT64_MAX; break;
        }
        std::vector<std::byte> output = Bytes("prior result");
        CHECK(!spool.ReadPersistedRange(bad, output)); CHECK(output.empty());
        const std::array refs{bad}; CHECK(!spool.RebuildIndexFromReferences(refs, 0));
        CHECK(!spool.RestoreInlineRange(bad, Bytes(canary)));
    }
    const std::array duplicate{ref, ref}; CHECK(!spool.RebuildIndexFromReferences(duplicate, 0));
    CHECK(!spool.RebuildIndexFromReferences({}, 0)); CHECK(!spool.RebuildIndexFromReferences(good, 1));
    CHECK(!spool.RebuildIndexFromReferences(good, 0, good));
    CHECK(SpoolBytes(o) == before);
}

void MissingAndStaleIndex()
{
    for (int mode = 0; mode < 3; ++mode)
    {
        auto o = Options("rebuild-" + std::to_string(mode)); const auto first = Seed(o, mode != 0);
        Spool::PersistedRangeReference second;
        if (mode == 1)
        {
            Spool spool(o); const std::array refs{first}; CHECK(spool.RebuildIndexFromReferences(refs, 0));
            Spool::AppendResult r;
            CHECK(spool.Append({volume, 23, 21, 0, 2, Bytes("tail")}, &r)); second = Ref(r);
            CHECK(spool.FlushPayloadBytes());
        }
        if (mode == 2) CHECK(fs::remove(o.root / "payload-spool.idx"));
        Spool spool(o); CHECK(spool.RecoveryRequired());
        CHECK(!spool.ResolveUnindexedPayloadRecovery(true));
        std::vector refs{first};
        if (mode == 1) { CHECK(!spool.RebuildIndexFromReferences(refs, 0)); refs.push_back(second); }
        CHECK(spool.RebuildIndexFromReferences(refs, 0)); CHECK(spool.FlushDirtyState());
        std::vector<std::byte> actual; CHECK(spool.ReadPersistedRange(first, actual) && actual == Bytes(canary));
    }
}

void Tampering()
{
    for (unsigned mode = 0; mode < 12; ++mode)
    {
        auto o = Options("tamper-" + std::to_string(mode)); const auto ref = Seed(o);
        const auto file = o.root / (mode < 6 ? "payload-spool.bin" : "payload-spool.idx");
        auto bytes = Read(file);
        switch (mode % 6)
        {
        case 0: bytes[0] ^= std::byte{1}; break;
        case 1: bytes[40] ^= std::byte{1}; break;
        case 2: bytes[64] ^= std::byte{1}; break;
        case 3: bytes.back() ^= std::byte{1}; break;
        case 4: bytes.pop_back(); break;
        default: bytes.push_back(std::byte{0}); break;
        }
        Write(file, bytes); MustRefuse(o, ref);
    }
    auto donor = Options("donor"); (void)Seed(donor);
    for (unsigned mode = 0; mode < 4; ++mode)
    {
        auto o = Options("substitution-" + std::to_string(mode)); const auto ref = Seed(o);
        if (mode == 0) o.protected_binding[0] ^= std::byte{1};
        if (mode == 1) o.volume_identity += "foreign";
        if (mode >= 2)
        {
            const auto name = mode == 2 ? "payload-spool.bin" : "payload-spool.idx";
            fs::copy_file(donor.root / name, o.root / name, fs::copy_options::overwrite_existing);
        }
        // Same binding/context and same purpose/offset legitimately accepts a
        // prior independently generated epoch. Source-specific binding is the
        // caller's anti-substitution authority; use a different trusted binding.
        if (mode >= 2) o.protected_binding[1] ^= std::byte{2};
        MustRefuse(o, ref);
    }
    auto o = Options("offset-swap"); Spool::PersistedRangeReference a, b;
    {
        Spool spool(o); Spool::AppendResult r;
        CHECK(spool.Append({volume, 1, 1, 0, 1, Bytes(canary)}, &r)); a = Ref(r);
        CHECK(spool.Append({volume, 1, 1, 0, 2, Bytes(canary)}, &r)); b = Ref(r);
        CHECK(spool.FlushDirtyState());
    }
    auto bytes = Read(o.root / "payload-spool.bin"); const auto half = bytes.size() / 2;
    std::rotate(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(half), bytes.end());
    Write(o.root / "payload-spool.bin", bytes); MustRefuse(o, a);
    (void)b;
}

void MixedAndPlainFallback()
{
    auto o = Options("plaintext-mixed");
    { auto plain = o; plain.protected_persistence = false; (void)Seed(plain); }
    const auto before = SpoolBytes(o);
    { Spool spool(o); CHECK(spool.RecoveryRequired()); CHECK(!spool.Append({volume, 1, 1, 0, 2, Bytes(canary)})); }
    CHECK(SpoolBytes(o) == before);
    auto protectedOptions = Options("ordinary-fallback"); const auto ref = Seed(protectedOptions);
    const auto protectedBefore = SpoolBytes(protectedOptions);
    {
        auto plain = protectedOptions; plain.protected_persistence = false;
        Spool spool(plain); CHECK(spool.RecoveryRequired());
        CHECK(!spool.Append({volume, 1, 1, 0, 2, Bytes(canary)}));
        CHECK(!spool.FlushDirtyState()); CHECK(!spool.CleanupThroughSequence(UINT64_MAX));
        CHECK(!spool.RestoreInlineRange(ref, Bytes(canary)));
        const std::array refs{ref}; CHECK(!spool.RebuildIndexFromReferences(refs, 0));
    }
    CHECK(SpoolBytes(protectedOptions) == protectedBefore);
    for (unsigned mode = 0; mode < 2; ++mode)
    {
        auto p = Options("ordinary-missing-index-" + std::to_string(mode));
        (void)Seed(p, false);
        if (mode == 1) CHECK(fs::remove(p.root / "payload-spool.idx"));
        const auto dataBefore = Read(p.root / "payload-spool.bin");
        {
            auto plain = p; plain.protected_persistence = false;
            Spool spool(plain); CHECK(spool.RecoveryRequired());
            CHECK(spool.CheckAppendCapacity(1) == Spool::AppendStatus::StorageFailure);
            CHECK(spool.CheckAppendCapacityFast(1) == Spool::AppendStatus::StorageFailure);
            CHECK(!spool.Append({volume, 1, 1, 0, 2, Bytes(canary)}));
            CHECK(!spool.FlushDirtyState()); CHECK(!spool.ResolveUnindexedPayloadRecovery(true));
            CHECK(!spool.DiscardSequence(1));
        }
        CHECK(Read(p.root / "payload-spool.bin") == dataBefore);
        CHECK(mode == 0 ? fs::file_size(p.root / "payload-spool.idx") == 0 : !fs::exists(p.root / "payload-spool.idx"));
    }
    auto plainMissing = Options("plain-missing-index");
    { auto plain = plainMissing; plain.protected_persistence = false; (void)Seed(plain, false); }
    const auto dataBefore = Read(plainMissing.root / "payload-spool.bin");
    {
        Spool spool(plainMissing); CHECK(spool.RecoveryRequired());
        CHECK(!spool.Append({volume, 1, 1, 0, 2, Bytes(canary)}));
        CHECK(!spool.FlushDirtyState());
    }
    CHECK(Read(plainMissing.root / "payload-spool.bin") == dataBefore);
    CHECK(!fs::exists(plainMissing.root / "payload-spool.idx"));
    CHECK(fs::is_empty(plainMissing.protected_key_directory));
    auto validEmpty = Options("ordinary-valid-empty-index"); (void)Seed(validEmpty);
    // A valid ordinary empty advisory index must not conceal protected data.
    std::vector<std::byte> body;
    const auto put = [](std::vector<std::byte>& b, std::uint64_t v, unsigned count) {
        for (unsigned i = 0; i < count; ++i) b.push_back(static_cast<std::byte>((v >> (8 * i)) & 255));
    };
    put(body, 0x5844494c4f4f5350ull, 8); put(body, 1, 4); put(body, sizeof(volume) - 1, 4); put(body, 0, 8);
    const auto id = Bytes(volume); body.insert(body.end(), id.begin(), id.end());
    std::uint64_t hash = 14695981039346656037ull;
    for (const auto b : body) { hash ^= std::to_integer<std::uint8_t>(b); hash *= 1099511628211ull; }
    std::vector<std::byte> index; put(index, hash, 8); index.insert(index.end(), body.begin(), body.end());
    Write(validEmpty.root / "payload-spool.idx", index);
    const auto mixedBefore = SpoolBytes(validEmpty);
    {
        auto plain = validEmpty; plain.protected_persistence = false; Spool spool(plain);
        CHECK(spool.RecoveryRequired()); CHECK(!spool.Append({volume, 1, 1, 0, 2, Bytes(canary)}));
        CHECK(!spool.FlushPayloadBytes()); CHECK(!spool.CleanupThroughSequence(UINT64_MAX));
    }
    CHECK(SpoolBytes(validEmpty) == mixedBefore);
}

void Limits()
{
    const auto payload = Bytes(canary);
    auto o = Options("exact-quota"); o.max_bytes = payload.size() + 80;
    {
        Spool spool(o); Spool::AppendResult r;
        CHECK(spool.CheckAppendCapacity(payload.size()) == Spool::AppendStatus::Succeeded);
        CHECK(spool.Append({volume, 1, 1, 0, 1, payload}, &r)); CHECK(spool.FlushDirtyState());
        const auto before = SpoolBytes(o);
        CHECK(spool.CheckAppendCapacityFast(1) == Spool::AppendStatus::QuotaExceeded);
        CHECK(spool.AppendWithStatus({volume, 1, 1, 0, 2, payload}, &r) == Spool::AppendStatus::QuotaExceeded);
        CHECK(r.payload_length == 0); CHECK(SpoolBytes(o) == before);
        CHECK(spool.CheckAppendCapacity(journal::kMaxJournalPlaintextBytes + 1) == Spool::AppendStatus::InvalidRequest);
        CHECK(spool.CheckAppendCapacity(UINT64_MAX) == Spool::AppendStatus::InvalidRequest);
        CHECK(spool.CheckAppendCapacity(0) == Spool::AppendStatus::InvalidRequest);
    }
    auto index = Options("index-quota"); index.startup_index_max_bytes = 159; // First snapshot needs 160.
    {
        Spool spool(index); CHECK(!spool.RecoveryRequired());
        CHECK(spool.AppendWithStatus({volume, 1, 1, 0, 1, payload}) == Spool::AppendStatus::QuotaExceeded);
        CHECK(fs::file_size(spool.SpoolFilePath()) == 0);
    }
    auto budgets = Options("startup-budgets"); const auto ref = Seed(budgets);
    const auto before = SpoolBytes(budgets);
    for (unsigned i = 0; i < 2; ++i)
    {
        auto b = budgets;
        if (i == 0) b.startup_index_max_bytes = 159;
        else b.startup_payload_read_max_bytes = payload.size() + 79;
        MustRefuse(b, ref);
    }
    CHECK(SpoolBytes(budgets) == before);
    for (unsigned i = 0; i < 5; ++i)
    {
        auto invalid = Options("invalid-options-" + std::to_string(i));
        if (i == 0) invalid.protected_binding.fill(std::byte{});
        if (i == 1) invalid.protected_key_directory.clear();
        if (i == 2) invalid.max_bytes = 0;
        if (i == 3) invalid.max_bytes = 512ull * 1024 * 1024 + 1;
        if (i == 4) invalid.root = L"relative";
        Spool spool(invalid); CHECK(spool.RecoveryRequired());
        CHECK(!spool.Append({volume, 1, 1, 0, 1, payload}));
    }
}

void KeyAndCryptoFailures()
{
    for (unsigned mode = 0; mode < 3; ++mode)
    {
        auto o = Options("key-failure-" + std::to_string(mode)); const auto ref = Seed(o);
        fs::path key;
        for (const auto& entry : fs::directory_iterator(o.protected_key_directory))
            if (entry.path().extension() == ".key") key = entry.path();
        CHECK(!key.empty());
        if (mode == 0) CHECK(fs::remove(key));
        else if (mode == 1) { auto bytes = Read(key); bytes.back() ^= std::byte{1}; Write(key, bytes); }
        else
        {
            // File corruption/refusal is already covered above. Inject a real
            // current-user DPAPI unprotect failure without changing identity.
            journal::testing::hooks.fault = journal::testing::EpochFault::UnprotectAfter;
        }
        MustRefuse(o, ref); journal::testing::hooks = {};
    }
    auto acquire = Options("epoch-publication-failure");
    journal::testing::hooks.fault = journal::testing::EpochFault::SlotFlush;
    { Spool spool(acquire); CHECK(spool.RecoveryRequired()); CHECK(!spool.FlushDirtyState()); }
    CHECK(journal::testing::hooks.triggered); journal::testing::hooks = {};
    auto o = Options("crypto-failure"); Spool spool(o); CHECK(!spool.RecoveryRequired());
    for (unsigned mode = 0; mode < 3; ++mode)
    {
        const auto before = SpoolBytes(o); crypto::testing::hooks = {};
        if (mode == 0) crypto::testing::hooks.allocation_failure_at = 0;
        if (mode == 1) crypto::testing::hooks.lock_failure_at = 0;
        if (mode == 2) crypto::testing::hooks.cng_failure_at = 0;
        Spool::AppendResult r;
        CHECK(!spool.Append({volume, 1, 1, 0, mode + 1, Bytes(canary)}, &r)); CHECK(r.payload_length == 0);
        CHECK(SpoolBytes(o) == before); CHECK(crypto::testing::hooks.all_released_bytes_zero);
    }
    crypto::testing::hooks = {};
    Spool::AppendResult r; CHECK(spool.Append({volume, 1, 1, 0, 1, Bytes(canary)}, &r)); CHECK(spool.FlushDirtyState());
    std::vector<std::byte> destination(8, std::byte{0x55}); const auto before = destination; std::size_t n = 99;
    crypto::testing::hooks = {}; crypto::testing::hooks.cng_failure_at = 0;
    CHECK(!spool.OverlayDirtyRanges({volume, 1, 1, 0, destination}, n)); CHECK(destination == before && n == 0);
    CHECK(crypto::testing::hooks.all_released_bytes_zero); crypto::testing::hooks = {};
}

void Paths()
{
    auto o = Options("paths"); const auto ref = Seed(o);
    auto alias = root / "data-hardlink";
    CHECK(CreateHardLinkW(alias.c_str(), (o.root / "payload-spool.bin").c_str(), nullptr));
    MustRefuse(o, ref);
    auto idx = Options("index-hardlink"); const auto idxRef = Seed(idx);
    CHECK(CreateHardLinkW((root / "index-hardlink-alias").c_str(), (idx.root / "payload-spool.idx").c_str(), nullptr));
    MustRefuse(idx, idxRef);
    auto active = Options("active-hardlink");
    {
        Spool spool(active); CHECK(!spool.RecoveryRequired());
        // Windows can permit adding a hard link to a pinned handle. Every
        // protected operation rechecks link count and must then fail closed.
        if (CreateHardLinkW((root / "active-alias").c_str(), spool.SpoolFilePath().c_str(), nullptr))
            CHECK(!spool.Append({volume, 1, 1, 0, 1, Bytes(canary)}));
    }
    auto symlink = Options("reparse"); const auto link = root / "directory-link";
    const auto made = CreateSymbolicLinkW(link.c_str(), symlink.root.c_str(), SYMBOLIC_LINK_FLAG_DIRECTORY | 2);
    if (made)
    {
        auto bad = symlink; bad.root = link;
        Spool spool(bad); CHECK(spool.RecoveryRequired());
        CHECK(!spool.Append({volume, 1, 1, 0, 1, Bytes(canary)}));
        auto badKey = symlink; badKey.protected_key_directory = link;
        Spool keySpool(badKey); CHECK(keySpool.RecoveryRequired()); CHECK(!keySpool.FlushDirtyState());
    }
    else throw std::runtime_error("Private directory symlink fixture unavailable: " + std::to_string(GetLastError()));
    for (const auto& path : std::vector<fs::path>{L"D:\\relative\\..", L"1:\\nonapproved", symlink.root.wstring() + L":stream", symlink.root.wstring() + L"\\"})
    {
        auto bad = symlink; bad.root = path;
        Spool spool(bad); CHECK(spool.RecoveryRequired()); CHECK(!spool.FlushDirtyState());
    }
}

void Thresholds()
{
    auto o = Options("threshold"); o.durable_flush_appends = 1;
    const auto ref = Seed(o); CHECK(fs::file_size(o.root / "payload-spool.idx") == 160);
    Spool spool(o); const std::array refs{ref}; CHECK(spool.RebuildIndexFromReferences(refs, 0));
    const auto before = fs::file_size(o.root / "payload-spool.idx");
    Spool::AppendResult r; CHECK(spool.Append({volume, 1, 1, 0, 2, Bytes("second")}, &r));
    CHECK(fs::file_size(o.root / "payload-spool.idx") > before);
    CHECK(!spool.SnapshotCounters().index_dirty);
}

void IoFailureAndOrdering()
{
    namespace testing = apfsaccess::rw::protected_spool_testing;
    const auto payload = Bytes(canary);
    auto ordering = Options("flush-order");
    {
        Spool spool(ordering); testing::hooks = {};
        CHECK(spool.Append({volume, 1, 1, 0, 1, payload}));
        CHECK(spool.FlushPayloadBytes()); CHECK(fs::file_size(ordering.root / "payload-spool.idx") == 0);
        CHECK(spool.FlushDirtyState());
        CHECK((testing::hooks.events == std::vector<unsigned>{1, 2, 2, 3, 4}));
    }
    for (const auto fault : {testing::Fault::DataWrite, testing::Fault::DataFlush, testing::Fault::IndexWrite, testing::Fault::IndexFlush})
    {
        auto o = Options("io-failure-" + std::to_string(static_cast<unsigned>(fault)));
        o.durable_flush_appends = 1;
        Spool spool(o); CHECK(!spool.RecoveryRequired());
        testing::hooks = {}; testing::hooks.fault = fault;
        Spool::AppendResult r;
        CHECK(!spool.Append({volume, 1, 1, 0, 1, payload}, &r));
        CHECK(testing::hooks.triggered); CHECK(r.payload_length == 0); CHECK(spool.RecoveryRequired());
        const auto before = SpoolBytes(o); CHECK(!before.first.empty());
        if (fault == testing::Fault::DataWrite) CHECK(before.first.size() == 13 && before.second.empty());
        if (fault == testing::Fault::IndexWrite) CHECK(before.second.size() == 13);
        if (fault == testing::Fault::IndexFlush) CHECK(before.second.size() == 160);
        CHECK(!spool.Append({volume, 1, 1, 0, 2, payload}));
        CHECK(!spool.FlushDirtyState()); CHECK(!spool.CleanupThroughSequence(UINT64_MAX));
        CHECK(!spool.ResolveUnindexedPayloadRecovery(true)); CHECK(SpoolBytes(o) == before);
        testing::hooks = {};
    }
}

void RangeAndHistoryBounds()
{
    auto o = Options("range-bound");
    Spool spool(o);
    const auto payload = Bytes("x");
    for (unsigned i = 0; i < 4096; ++i)
        CHECK(spool.Append({volume, 1, 1, i, i + 1, payload}));
    CHECK(spool.FlushPayloadBytes());
    const auto before = SpoolBytes(o);
    CHECK(spool.AppendWithStatus({volume, 1, 1, 4096, 4097, payload}) == Spool::AppendStatus::QuotaExceeded);
    CHECK(SpoolBytes(o) == before);
    auto history = Options("history-bound"); history.startup_index_max_bytes = 160;
    const auto ref = Seed(history);
    const auto historyBefore = SpoolBytes(history);
    Spool reopened(history); const std::array refs{ref}; CHECK(reopened.RebuildIndexFromReferences(refs, 0));
    CHECK(!reopened.FlushDirtyState()); // Keep intact old snapshot, no replacement/compaction.
    CHECK(reopened.AppendWithStatus({volume, 1, 1, 0, 2, payload}) == Spool::AppendStatus::QuotaExceeded);
    CHECK(SpoolBytes(history) == historyBefore);
    auto missing = Options("rebuild-budget"); const auto missingRef = Seed(missing, false);
    missing.startup_payload_read_max_bytes = 1;
    Spool underBudget(missing); const std::array missingRefs{missingRef};
    CHECK(!underBudget.RebuildIndexFromReferences(missingRefs, 0)); CHECK(underBudget.RecoveryRequired());
    auto entries = Options("key-directory-bound");
    for (unsigned i = 0; i < 4096; ++i)
    {
        std::ofstream fixture(entries.protected_key_directory / ("retained-" + std::to_string(i)), std::ios::binary);
        CHECK(fixture.good());
    }
    {
        Spool exhausted(entries); CHECK(exhausted.RecoveryRequired());
        CHECK(!exhausted.Append({volume, 1, 1, 0, 1, payload}));
    }
    CHECK(std::distance(fs::directory_iterator(entries.protected_key_directory), fs::directory_iterator{}) == 4096);
    CHECK(!fs::exists(entries.root / "payload-spool.bin")); CHECK(!fs::exists(entries.root / "payload-spool.idx"));
}

void OrdinaryArbitraryPrefixes()
{
    auto source = Options("ordinary-frame-source"); (void)Seed(source);
    for (unsigned mode = 0; mode < 3; ++mode)
    {
        auto o = Options("ordinary-prefix-" + std::to_string(mode)); o.protected_persistence = false;
        auto payload = mode == 2 ? Read(source.root / "payload-spool.bin") : std::vector<std::byte>(mode ? 96 : 12);
        if (mode != 2) std::memcpy(payload.data(), "APFSREC1", 8);
        if (mode == 1)
        {
            const auto put = [&](std::size_t at, std::uint32_t v) {
                for (unsigned i = 0; i < 4; ++i) payload[at + i] = static_cast<std::byte>((v >> (8 * i)) & 255);
            };
            put(8, 1); put(12, 64); put(16, 96); put(20, 32);
        }
        Spool::PersistedRangeReference first, second;
        {
            Spool s(o); Spool::AppendResult r;
            CHECK(s.Append({volume, 17, 21, 0, 1, payload}, &r)); first = Ref(r); CHECK(s.FlushDirtyState());
        }
        {
            Spool s(o); std::vector<std::byte> actual;
            CHECK(s.ReadPersistedRange(first, actual) && actual == payload);
            Spool::AppendResult r; CHECK(s.Append({volume, 18, 21, 0, 2, payload}, &r)); second = Ref(r);
            const std::array refs{first, second}; CHECK(s.RebuildIndexFromReferences(refs, 0));
            CHECK(s.FlushDirtyState());
        }
        {
            Spool s(o); const std::array refs{first, second}; CHECK(s.RebuildIndexFromReferences(refs, 0));
            std::vector<std::byte> actual; CHECK(s.ReadPersistedRange(first, actual) && actual == payload);
            CHECK(s.ReadPersistedRange(second, actual) && actual == payload);
            CHECK(!fs::exists(o.root / "payload-spool.protected"));
        }
        auto missing = Options("ordinary-proof-" + std::to_string(mode)); missing.protected_persistence = false;
        Spool::PersistedRangeReference ref;
        {
            Spool s(missing); Spool::AppendResult r;
            CHECK(s.Append({volume, 17, 21, 0, 1, payload}, &r)); ref = Ref(r); CHECK(s.FlushPayloadBytes());
        }
        {
            Spool s(missing); CHECK(s.RecoveryRequired());
            CHECK(s.CheckAppendCapacityFast(1) == Spool::AppendStatus::StorageFailure);
            CHECK(!s.Append({volume, 18, 21, 0, 2, payload})); CHECK(!s.FlushDirtyState());
            auto wrong = ref; wrong.payload_sha256[0] ^= 1;
            const std::array bad{wrong}; CHECK(!s.RebuildIndexFromReferences(bad, 0));
            const std::array good{ref}; CHECK(s.RebuildIndexFromReferences(good, 0));
            CHECK(s.Append({volume, 18, 21, 0, 2, payload})); CHECK(s.FlushDirtyState());
        }
    }
}

void StoreMarkers()
{
    namespace testing = apfsaccess::rw::protected_spool_testing;
    const auto marker = [](const Spool::Options& o) { return o.root / "payload-spool.protected"; };
    auto ordering = Options("anchor-order");
    testing::hooks = {};
    {
        Spool s(ordering); CHECK(!s.RecoveryRequired());
        CHECK((testing::hooks.events == std::vector<unsigned>{5, 6, 7, 8}));
        CHECK(fs::file_size(marker(ordering)) == 96); CHECK(fs::file_size(s.SpoolFilePath()) == 0);
        CHECK(s.Append({volume, 17, 21, 0, 1, Bytes(canary)})); CHECK(s.FlushDirtyState());
        CHECK((testing::hooks.events == std::vector<unsigned>{5, 6, 7, 8, 1, 2, 3, 4}));
        CHECK(!MoveFileExW(marker(ordering).c_str(), (ordering.root / "marker-renamed").c_str(), 0));
        HANDLE write = CreateFileW(marker(ordering).c_str(), GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
        CHECK(write == INVALID_HANDLE_VALUE);
    }
    testing::hooks = {};
    for (const auto fault : {testing::Fault::AnchorWrite, testing::Fault::AnchorFlush,
            testing::Fault::AnchorReadback, testing::Fault::AfterAnchorPublication})
    {
        auto o = Options("anchor-fault-" + std::to_string(static_cast<unsigned>(fault)));
        testing::hooks = {}; testing::hooks.fault = fault;
        { Spool failed(o); CHECK(failed.RecoveryRequired()); CHECK(testing::hooks.triggered); CHECK(!failed.FlushDirtyState()); }
        const auto bytes = Read(marker(o)); CHECK(bytes.size() == (fault == testing::Fault::AnchorWrite ? 13u : 96u));
        CHECK(fs::file_size(o.root / "payload-spool.bin") == 0 && fs::file_size(o.root / "payload-spool.idx") == 0);
        auto ordinary = o; ordinary.protected_persistence = false;
        { Spool s(ordinary); CHECK(s.RecoveryRequired()); CHECK(!s.Append({volume, 17, 21, 0, 1, Bytes(canary)})); }
        CHECK(Read(marker(o)) == bytes);
        testing::hooks = {};
        {
            Spool retry(o);
            if (fault == testing::Fault::AnchorWrite) CHECK(retry.RecoveryRequired());
            else { CHECK(!retry.RecoveryRequired()); CHECK(retry.Append({volume, 17, 21, 0, 1, Bytes(canary)})); CHECK(retry.FlushDirtyState()); }
        }
        CHECK(Read(marker(o)) == bytes); // Never replaces even an interrupted publication.
    }
    for (unsigned mode = 0; mode < 5; ++mode)
    {
        auto o = Options("anchor-tamper-" + std::to_string(mode)); const auto ref = Seed(o);
        auto bytes = Read(marker(o));
        if (mode == 0) bytes.back() ^= std::byte{1};
        if (mode == 1) bytes.pop_back();
        if (mode == 2) bytes.clear();
        if (mode < 3) Write(marker(o), bytes);
        if (mode == 3) CHECK(CreateHardLinkW((o.root / "marker-link").c_str(), marker(o).c_str(), nullptr));
        if (mode == 4) CHECK(fs::remove(marker(o)));
        MustRefuse(o, ref);
        if (mode != 4) CHECK(Read(marker(o)) == bytes);
        else CHECK(!fs::exists(marker(o)));
    }
    auto donor = Options("anchor-donor"); (void)Seed(donor);
    for (unsigned missing = 0; missing < 2; ++missing)
    {
        auto o = Options("anchor-substitute-" + std::to_string(missing)); const auto ref = Seed(o);
        fs::copy_file(marker(donor), marker(o), fs::copy_options::overwrite_existing);
        for (const auto& key : fs::directory_iterator(donor.protected_key_directory))
            if (key.path().extension() == ".key") fs::copy_file(key.path(), o.protected_key_directory / key.path().filename());
        if (missing) Write(o.root / "payload-spool.idx", {});
        MustRefuse(o, ref); // Valid donor binding/key is insufficient: records bind the exact anchor.
    }
    auto preexisting = Options("anchor-no-replace"); Write(marker(preexisting), Bytes("preexisting evidence"));
    const auto evidence = Read(marker(preexisting));
    { Spool s(preexisting); CHECK(s.RecoveryRequired()); CHECK(!s.Append({volume, 17, 21, 0, 1, Bytes(canary)})); }
    CHECK(Read(marker(preexisting)) == evidence); CHECK(fs::is_empty(preexisting.protected_key_directory));
    auto noIndex = Options("anchor-wrong-binding-no-index"); (void)Seed(noIndex, false);
    CHECK(fs::remove(noIndex.root / "payload-spool.idx"));
    const auto beforeData = Read(noIndex.root / "payload-spool.bin"), beforeMarker = Read(marker(noIndex));
    const auto beforeKeys = std::distance(fs::directory_iterator(noIndex.protected_key_directory), fs::directory_iterator{});
    auto foreign = noIndex; foreign.protected_binding[0] ^= std::byte{1};
    { Spool s(foreign); CHECK(s.RecoveryRequired()); CHECK(!s.FlushDirtyState()); }
    CHECK(!fs::exists(noIndex.root / "payload-spool.idx"));
    CHECK(Read(noIndex.root / "payload-spool.bin") == beforeData && Read(marker(noIndex)) == beforeMarker);
    CHECK(std::distance(fs::directory_iterator(noIndex.protected_key_directory), fs::directory_iterator{}) == beforeKeys);
    auto late = Options("anchor-late"); auto plain = late; plain.protected_persistence = false;
    Spool ordinary(plain);
    { Spool protectedSpool(late); CHECK(!protectedSpool.RecoveryRequired()); CHECK(!ordinary.Append({volume, 17, 21, 0, 1, Bytes(canary)})); }
    CHECK(!ordinary.Append({volume, 17, 21, 0, 1, Bytes(canary)}));
    testing::hooks = {};
}

void Scan()
{
    const auto rawPayload = Bytes(canary), rawVolume = Bytes(volume), rawKey = Bytes(std::string_view(keyCanary, 32));
    const auto wide = [](std::string_view text) {
        std::vector<std::byte> bytes;
        for (auto ch : text) { bytes.push_back(static_cast<std::byte>(ch)); bytes.push_back(std::byte{}); }
        return bytes;
    };
    const auto widePayload = wide(canary), wideVolume = wide(volume), wideKey = wide(std::string_view(keyCanary, 32));
    unsigned scanned = 0, reparse = 0;
    for (fs::recursive_directory_iterator it(root), end; it != end; ++it)
    {
        if (GetFileAttributesW(it->path().c_str()) & FILE_ATTRIBUTE_REPARSE_POINT)
        { it.disable_recursion_pending(); ++reparse; continue; }
        if (!it->is_regular_file()) continue;
        // Deliberate ordinary/mixed and byte-tamper fixtures are inspected by
        // their own assertions. Scan actual successful protected persistence.
        const auto relative = fs::relative(it->path(), root).generic_string();
        if (!relative.starts_with("persistence/") && !relative.starts_with("rebuild-") &&
            !relative.starts_with("exact-quota/") && !relative.starts_with("threshold/") &&
            !relative.starts_with("references/")) continue;
        const auto bytes = Read(it->path()); ++scanned;
        for (const auto* needle : {&rawPayload, &rawVolume, &rawKey, &widePayload, &wideVolume, &wideKey})
            CHECK(std::search(bytes.begin(), bytes.end(), needle->begin(), needle->end()) == bytes.end());
        CHECK(it->path().extension() != ".tmp");
    }
    CHECK(scanned >= 25); CHECK(reparse == 1);
    std::cout << "SCAN " << scanned << " protected persistence files; raw/UTF16 payload, volume, key canaries absent; "
        << reparse << " private reparse fixture excluded\n";
}
using Maintenance = Spool::ProtectedMaintenanceResult;
namespace st = apfsaccess::rw::protected_spool_testing;
using Wal = apfsaccess::rw::WriteAheadLog;
struct OriginalAuthority
{
    Spool::ProtectedCleanupProof proof;
    std::vector<Spool::PersistedRangeReference> refs;
};
OriginalAuthority Authority(const Spool::Options& o, const std::vector<Spool::PersistedRangeReference>& refs, std::uint64_t floor, bool durable = true)
{
    // Use the frozen real protected WAL, then reconstruct refs from its exact
    // authenticated head. This fixture does not manufacture a head from an index.
    auto base = o.root.parent_path() / "original-WAL"; fs::create_directories(base / "keys");
    Wal::ProtectedPersistence protection; protection.key_directory = base / "keys"; protection.source_binding = o.protected_binding;
    protection.journal_identity = o.protected_binding;
    Wal wal({base / "original.wal", volume, 4 * 1024 * 1024, protection});
    auto sorted = refs; std::sort(sorted.begin(), sorted.end(), [](const auto& a, const auto& b) { return a.wal_sequence < b.wal_sequence; });
    const auto previous = wal.ReadAllWithExclusiveWriterLease(); CHECK(previous.status == Wal::ReadStatus::Ok);
    std::size_t original_writes = 0;
    for (const auto& old : previous.records) if (old.operation == Wal::OperationKind::Write)
    {
        CHECK(original_writes < sorted.size()); const auto& r = sorted[original_writes++];
        CHECK(old.sequence == r.wal_sequence && old.object_id == r.object_id && old.payload_spool_id == r.generation &&
            old.logical_offset == r.logical_offset && old.payload_length == r.payload_length && old.payload_offset == r.spool_offset && old.payload_sha256 == r.payload_sha256);
    }
    for (std::size_t n = original_writes; n < sorted.size(); ++n)
    {
        const auto& r = sorted[n];
        Wal::Record record; record.volume_identity = volume; record.sequence = r.wal_sequence; record.transaction_id = r.wal_sequence;
        record.object_id = r.object_id; record.payload_spool_id = r.generation; record.payload_offset = r.spool_offset;
        record.payload_length = r.payload_length; record.logical_length = r.payload_length; record.logical_offset = r.logical_offset;
        record.payload_sha256 = r.payload_sha256; record.path_utf8 = "\\private-spool-canary";
        CHECK(wal.Append(record));
    }
    Wal::ProtectedHistoryHead head; CHECK(wal.CaptureProtectedHistoryHead(head));
    const auto decoded = wal.ReadAllAtProtectedHead(head); CHECK(decoded.status == Wal::ReadStatus::Ok);
    OriginalAuthority result;
    for (const auto& r : decoded.records) if (r.operation == Wal::OperationKind::Write && r.state == Wal::RecordState::Prepared)
        result.refs.push_back({r.volume_identity, r.object_id, r.payload_spool_id, r.logical_offset, r.payload_length, r.payload_offset, r.sequence, r.payload_sha256});
    CHECK(result.refs.size() == refs.size());
    auto durable_sequence = head.last_sequence;
    for (const auto& r : decoded.records) if (r.operation == Wal::OperationKind::DurabilityWatermark) durable_sequence = r.object_id;
    result.proof = {o.protected_binding, head.sha256, head.bytes, head.records, head.last_sequence, durable ? durable_sequence : 0, floor};
    return result;
}
using FileSnapshot = std::map<std::string, std::vector<std::byte>>;
FileSnapshot MaintenanceFiles(const fs::path& base)
{
    FileSnapshot result;
    for (const auto& entry : fs::directory_iterator(base))
    {
        const auto attr = GetFileAttributesW(entry.path().c_str()); CHECK(attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_REPARSE_POINT));
        if (entry.is_regular_file()) result.emplace(entry.path().filename().string(), Read(entry.path()));
    }
    return result;
}
std::vector<Spool::PersistedRangeReference> MaintenanceSeed(Spool& spool, unsigned count = 2, std::uint64_t first = 1)
{
    std::vector<Spool::PersistedRangeReference> refs;
    for (unsigned n = 0; n < count; ++n)
    {
        Spool::AppendResult r; CHECK(spool.Append({volume, 17 + n, 21, 5 + n, first + n, Bytes(canary)}, &r)); refs.push_back(Ref(r));
    }
    CHECK(spool.FlushPayloadBytes()); return refs;
}
void CheckLive(Spool& spool, const std::vector<Spool::PersistedRangeReference>& refs, std::uint64_t floor)
{
    for (const auto& r : refs)
    {
        std::vector<std::byte> payload = Bytes("must-clear-on-refusal"); const auto ok = spool.ReadPersistedRange(r, payload);
        CHECK(ok == (r.wal_sequence > floor)); CHECK(ok ? payload == Bytes(canary) : payload.empty());
    }
}
void MaintenanceWorkflow()
{
    auto o = Options("maintenance-life"); OriginalAuthority first, second, third, fourth;
    std::vector<Spool::PersistedRangeReference> refs; FileSnapshot old_keys; std::vector<std::byte> original, marker;
    {
        Spool spool(o); refs = MaintenanceSeed(spool, 3); first = Authority(o, refs, 1);
        original = Read(spool.SpoolFilePath()); marker = Read(o.root / "payload-spool.protected"); old_keys = MaintenanceFiles(o.protected_key_directory);
        CHECK(spool.ReconcileProtectedHistory(first.proof, first.refs) == Maintenance::Succeeded);
        CHECK(Read(spool.SpoolFilePath()) == original && fs::file_size(o.root / "payload-spool.idx") == 104);
        CHECK(spool.SnapshotCounters().dirty_range_count == 2); CheckLive(spool, refs, 1);
        CHECK(!spool.CleanupThroughSequence(2)); CHECK(!spool.DiscardSequence(2)); CHECK(!spool.RebuildIndexFromReferences(refs, 0));
        CHECK(!spool.Append({volume, 42, 21, 0, 1, Bytes(canary)}));
        Spool::AppendResult r; CHECK(spool.Append({volume, 42, 21, 0, 4, Bytes(canary)}, &r)); CHECK(r.spool_offset == original.size()); refs.push_back(Ref(r));
        CHECK(spool.FlushDirtyState());
    }
    // A corrupt advisory index cannot grant authority. Complete original WAL refs
    // authenticate the physical store and authorize its bounded replacement.
    Write(o.root / "payload-spool.idx", Bytes("untrusted-index")); second = Authority(o, refs, 2);
    {
        Spool spool(o); CHECK(spool.RecoveryRequired()); CHECK(!spool.RebuildIndexFromReferences(refs, 2));
        auto omitted = second.refs; omitted.erase(omitted.begin()); auto before = MaintenanceFiles(o.root);
        CHECK(spool.ReconcileProtectedHistory(second.proof, omitted) == Maintenance::RejectedBeforeWrite); CHECK(MaintenanceFiles(o.root) == before);
        CHECK(spool.ReconcileProtectedHistory(second.proof, second.refs) == Maintenance::Succeeded); CheckLive(spool, refs, 2);
        CHECK(spool.SnapshotCounters().spool_bytes == original.size() + refs.back().payload_length + 80);
        std::vector<std::byte> dest(refs[2].payload_length); std::size_t overlaid = 0;
        CHECK(spool.OverlayDirtyRanges({volume, refs[2].object_id, refs[2].generation, refs[2].logical_offset, dest}, overlaid));
        CHECK(dest == Bytes(canary) && overlaid == dest.size()); CHECK(spool.FlushDirtyState());
    }
    third = Authority(o, refs, 4);
    {
        Spool spool(o); CHECK(spool.RecoveryRequired()); CHECK(spool.ReconcileProtectedHistory(third.proof, third.refs) == Maintenance::Succeeded);
        CHECK(fs::file_size(spool.SpoolFilePath()) == 0 && fs::file_size(o.root / "payload-spool.idx") == 104);
        CHECK(Read(o.root / "payload-spool.protected") == marker); CheckLive(spool, refs, 4);
        CHECK(spool.SnapshotCounters().dirty_range_count == 0); CHECK(spool.CheckAppendCapacity(1) == Spool::AppendStatus::Succeeded);
    }
    {
        Spool spool(o); CHECK(spool.RecoveryRequired()); CHECK(spool.ReconcileProtectedHistory(third.proof, third.refs) == Maintenance::Succeeded);
        Spool::AppendResult r; CHECK(spool.Append({volume, 55, 21, 0, 5, Bytes(canary)}, &r)); CHECK(r.spool_offset == 0); refs.push_back(Ref(r)); CHECK(spool.FlushDirtyState());
    }
    fourth = Authority(o, refs, 4);
    { Spool spool(o); CHECK(spool.ReconcileProtectedHistory(fourth.proof, fourth.refs) == Maintenance::Succeeded); CheckLive(spool, refs, 4); }
    for (const auto& [name, bytes] : old_keys) CHECK(Read(o.protected_key_directory / name) == bytes);
}
void MissingIndexPublication()
{
    for (unsigned mode=0; mode<6; ++mode)
    {
        auto o=Options("lost-index-negative-"+std::to_string(mode)); const auto ref=Seed(o);
        CHECK(fs::remove(o.root/"payload-spool.idx"));
        if(mode==1){auto b=Read(o.root/"payload-spool.bin");b.back()^=std::byte{1};Write(o.root/"payload-spool.bin",b);}
        if(mode==2){auto b=Read(o.root/"payload-spool.bin");b.push_back(std::byte{1});Write(o.root/"payload-spool.bin",b);}
        if(mode==3)Write(o.root/"payload-spool.cleanup.0000000000000001.intent",Bytes("unknown-receipt"));
        if(mode==4)CHECK(fs::remove(o.root/"payload-spool.bin"));
        auto input=o;if(mode==5)input.protected_binding[0]^=std::byte{1};
        const auto before=MaintenanceFiles(o.root),keys=MaintenanceFiles(o.protected_key_directory);
        {
            Spool s(input); CHECK(s.RecoveryRequired()); CHECK(!fs::exists(o.root/"payload-spool.idx"));
            auto bad=ref;if(mode==0)bad.payload_sha256[0]^=1;
            CHECK(!s.RebuildIndexFromReferences(std::array{bad},0));
            CHECK(!s.Append({volume,99,21,0,2,Bytes(canary)}));
        }
        CHECK(MaintenanceFiles(o.root)==before && MaintenanceFiles(o.protected_key_directory)==keys);
    }
    for(const auto* cut:{"rebuild-missing-index-data-flush","rebuild-missing-index-after-create","rebuild-missing-index-flush"})
    {
        auto o=Options(std::string("lost-index-cut-")+cut);const auto ref=Seed(o);
        CHECK(fs::remove(o.root/"payload-spool.idx"));const auto data=Read(o.root/"payload-spool.bin");
        st::hooks={};st::hooks.maintenance_fault=cut;
        {Spool s(o);CHECK(s.RecoveryRequired());CHECK(!s.RebuildIndexFromReferences(std::array{ref},0));
            CHECK(st::hooks.triggered);CHECK(!s.Append({volume,99,21,0,2,Bytes(canary)}));}
        st::hooks={};CHECK(Read(o.root/"payload-spool.bin")==data);
        {Spool s(o);CHECK(s.RebuildIndexFromReferences(std::array{ref},0));CHECK(s.FlushDirtyState());}
        {Spool s(o);std::vector<std::byte> actual;CHECK(s.ReadPersistedRange(ref,actual)&&actual==Bytes(canary));}
    }
    for(unsigned fault=0;fault<2;++fault)
    {
        auto o=Options("lost-index-provider-"+std::to_string(fault));const auto ref=Seed(o);CHECK(fs::remove(o.root/"payload-spool.idx"));
        const auto before=MaintenanceFiles(o.root),keys=MaintenanceFiles(o.protected_key_directory);
        {Spool s(o);auto& hooks=crypto::testing::hooks;
            if(fault)hooks.cng_failure_at=hooks.cng_calls;else hooks.lock_failure_at=hooks.locks;
            CHECK(!s.RebuildIndexFromReferences(std::array{ref},0));hooks.cng_failure_at=hooks.lock_failure_at=-1;
            CHECK(MaintenanceFiles(o.root)==before && MaintenanceFiles(o.protected_key_directory)==keys);}
        {Spool s(o);CHECK(s.RebuildIndexFromReferences(std::array{ref},0));CHECK(s.FlushDirtyState());}
    }
    {
        auto o=Options("lost-index-key-publication");const auto ref=Seed(o);CHECK(fs::remove(o.root/"payload-spool.idx"));
        const auto data=Read(o.root/"payload-spool.bin"),marker=Read(o.root/"payload-spool.protected");
        const auto keys=MaintenanceFiles(o.protected_key_directory);
        {Spool s(o);journal::testing::hooks.fault=journal::testing::EpochFault::SlotFlush;journal::testing::hooks.triggered=false;
            CHECK(!s.RebuildIndexFromReferences(std::array{ref},0));CHECK(journal::testing::hooks.triggered);
            CHECK(!s.Append({volume,99,21,0,2,Bytes(canary)}));journal::testing::hooks.fault=journal::testing::EpochFault::None;}
        CHECK(Read(o.root/"payload-spool.bin")==data && Read(o.root/"payload-spool.protected")==marker);
        for(const auto& [name,bytes]:keys)CHECK(Read(o.protected_key_directory/name)==bytes);
        {Spool s(o);CHECK(s.RebuildIndexFromReferences(std::array{ref},0));CHECK(s.FlushDirtyState());}
    }
    {
        auto race=Options("lost-index-no-replace");const auto ref=Seed(race);CHECK(fs::remove(race.root/"payload-spool.idx"));
        const auto keys=MaintenanceFiles(race.protected_key_directory);const auto foreign=Bytes("foreign-index-evidence");
        {Spool s(race);bool inserted=false;st::hooks={};st::hooks.maintenance_observer=[&](std::string_view stage){
            if(stage=="rebuild-missing-index-before-create"){Write(race.root/"payload-spool.idx",foreign);inserted=true;}};
            CHECK(!s.RebuildIndexFromReferences(std::array{ref},0));CHECK(inserted);st::hooks={};}
        CHECK(Read(race.root/"payload-spool.idx")==foreign && MaintenanceFiles(race.protected_key_directory)==keys);
    }
    auto o=Options("lost-index-original");std::vector<Spool::PersistedRangeReference> refs;
    {Spool s(o);refs=MaintenanceSeed(s);CHECK(s.FlushDirtyState());}
    auto authority=Authority(o,refs,1);CHECK(fs::remove(o.root/"payload-spool.idx"));
    {
        Spool s(o);CHECK(s.RecoveryRequired());const auto before=MaintenanceFiles(o.root);
        auto wrong=authority.proof;wrong.source_binding[0]^=std::byte{1};
        CHECK(s.ReconcileProtectedHistory(wrong,refs)==Maintenance::RejectedBeforeWrite);CHECK(MaintenanceFiles(o.root)==before);
        CHECK(s.ReconcileProtectedHistory(authority.proof,refs)==Maintenance::Succeeded);CheckLive(s,refs,1);
        CHECK(s.FlushDirtyState());
    }
    authority=Authority(o,refs,2);
    {Spool s(o);CHECK(s.ReconcileProtectedHistory(authority.proof,refs)==Maintenance::Succeeded);CHECK(fs::file_size(s.SpoolFilePath())==0);}
    {Spool s(o);CHECK(s.ReconcileProtectedHistory(authority.proof,refs)==Maintenance::Succeeded);
        Spool::AppendResult r;CHECK(s.Append({volume,99,21,0,3,Bytes(canary)},&r));CHECK(r.spool_offset==0);CHECK(s.FlushDirtyState());}
    CHECK(fs::remove(o.root/"payload-spool.idx"));const auto unknown=MaintenanceFiles(o.root);
    {Spool s(o);CHECK(!s.RebuildIndexFromReferences({},0));CHECK(s.ReconcileProtectedHistory(authority.proof,refs)==Maintenance::RejectedBeforeWrite);}
    CHECK(MaintenanceFiles(o.root)==unknown);
}
void MaintenanceScaling()
{
    auto o = Options("maintenance-scale"); const auto frame = Bytes(canary).size() + 80; o.max_bytes = 2 * frame;
    std::vector<Spool::PersistedRangeReference> all; std::uint64_t floor = 0; OriginalAuthority previous; std::vector<std::byte> marker;
    for (unsigned cycle = 0; cycle < 5; ++cycle)
    {
        OriginalAuthority authority;
        {
            Spool spool(o); if (cycle) CHECK(spool.ReconcileProtectedHistory(previous.proof, previous.refs) == Maintenance::Succeeded);
            auto refs = MaintenanceSeed(spool, 2, floor + 1); CHECK(refs[0].spool_offset == 0 && refs[1].spool_offset == frame);
            all.insert(all.end(), refs.begin(), refs.end()); floor += 2;
            CHECK(fs::file_size(spool.SpoolFilePath()) == o.max_bytes); const auto full = SpoolBytes(o);
            CHECK(spool.AppendWithStatus({volume, 77, 21, 0, floor + 1, Bytes(canary)}) == Spool::AppendStatus::QuotaExceeded); CHECK(SpoolBytes(o) == full);
            authority = Authority(o, all, floor); auto keys = MaintenanceFiles(o.protected_key_directory);
            CHECK(spool.ReconcileProtectedHistory(authority.proof, authority.refs) == Maintenance::Succeeded);
            CHECK(fs::file_size(spool.SpoolFilePath()) == 0 && fs::file_size(o.root / "payload-spool.idx") == 104);
            CHECK(spool.SnapshotCounters().spool_bytes == 0 && spool.CheckAppendCapacity(Bytes(canary).size()) == Spool::AppendStatus::Succeeded);
            for (const auto& [name, bytes] : keys) CHECK(Read(o.protected_key_directory / name) == bytes);
            if (cycle == 0) marker = Read(o.root / "payload-spool.protected"); else CHECK(Read(o.root / "payload-spool.protected") == marker);
        }
        previous = std::move(authority);
    }
    Spool reopened(o); CHECK(reopened.RecoveryRequired());
    CHECK(reopened.ReconcileProtectedHistory(previous.proof, previous.refs) == Maintenance::Succeeded); CHECK(reopened.SnapshotCounters().spool_bytes == 0);
    { auto untouched = Options("maintenance-old"); Spool legacy(untouched); (void)MaintenanceSeed(legacy); CHECK(legacy.FlushDirtyState()); }
    std::cout << "SCALING 5 full-cap cycles reset real canonical data to zero and index to 104-byte guard; offsets reused only above cleanup floor\n";
}
void MaintenanceReferenceLimit()
{
    constexpr unsigned count = 4096;
    auto o = Options("maintenance-ref-limit"); o.max_bytes = 512ull * 1024 * 1024;
    SIZE_T minimum = 0, maximum = 0;
    CHECK(GetProcessWorkingSetSize(GetCurrentProcess(), &minimum, &maximum));
    const auto base = o.root.parent_path() / "original-WAL"; fs::create_directories(base / "keys");
    Wal::ProtectedPersistence protection; protection.key_directory = base / "keys";
    protection.source_binding = protection.journal_identity = o.protected_binding;
    const Wal::Options wal_options{base / "original.wal", volume, 16 * 1024 * 1024, protection};
    std::vector<Spool::PersistedRangeReference> refs; OriginalAuthority authority;
    const auto payload = Bytes(canary);
    {
        Spool spool(o); CHECK(!spool.RecoveryRequired());
        Wal wal(wal_options); std::vector<Wal::Record> batch;
        for (unsigned n = 0; n < count; ++n)
        {
            Spool::AppendResult r; CHECK(spool.Append({volume, 17 + n, 21, n, 2ull * n + 1, payload}, &r));
            refs.push_back(Ref(r)); CHECK(r.spool_offset == n * (payload.size() + 80));
            Wal::Record write; write.volume_identity = volume; write.sequence = write.transaction_id = r.wal_sequence;
            write.object_id = r.object_id; write.payload_spool_id = r.generation; write.logical_offset = r.logical_offset;
            write.payload_offset = r.spool_offset; write.payload_length = write.logical_length = r.payload_length;
            write.payload_sha256 = r.payload_sha256; write.path_utf8 = "\\private-spool-canary"; batch.push_back(write);
            Wal::Record accepted; accepted.volume_identity = volume; accepted.sequence = r.wal_sequence + 1;
            accepted.transaction_id = r.wal_sequence; accepted.operation = Wal::OperationKind::TransactionMarker;
            accepted.state = Wal::RecordState::Accepted; accepted.object_id = 73; batch.push_back(accepted);
            if (batch.size() == 8) { CHECK(wal.AppendBatch(batch, false)); batch.clear(); }
        }
        CHECK(batch.empty()); CHECK(spool.FlushPayloadBytes());
        CHECK(spool.AppendWithStatus({volume, 99, 21, 0, 8194, payload}) == Spool::AppendStatus::QuotaExceeded);
        Wal::Record watermark; watermark.volume_identity = volume; watermark.sequence = 8193;
        watermark.operation = Wal::OperationKind::DurabilityWatermark; watermark.state = Wal::RecordState::Cleaned;
        watermark.object_id = watermark.parent_object_id = 8193; CHECK(wal.Append(watermark));
        Wal::ProtectedHistoryHead head; CHECK(wal.CaptureProtectedHistoryHead(head));
        const auto decoded = wal.ReadAllAtProtectedHead(head); CHECK(decoded.status == Wal::ReadStatus::Ok);
        CHECK(decoded.records.size() == 8193 && head.records == 8193 && head.last_sequence == 8193);
        for (unsigned n = 0; n < count; ++n)
        {
            const auto& w = decoded.records[n * 2]; const auto& a = decoded.records[n * 2 + 1]; const auto& r = refs[n];
            CHECK(w.operation == Wal::OperationKind::Write && w.state == Wal::RecordState::Prepared);
            CHECK(w.sequence == r.wal_sequence && w.object_id == r.object_id && w.payload_offset == r.spool_offset &&
                w.payload_spool_id == r.generation && w.logical_offset == r.logical_offset && w.payload_length == r.payload_length && w.payload_sha256 == r.payload_sha256);
            CHECK(a.operation == Wal::OperationKind::TransactionMarker && a.state == Wal::RecordState::Accepted && a.transaction_id == w.transaction_id);
            authority.refs.push_back({w.volume_identity, w.object_id, w.payload_spool_id, w.logical_offset,
                w.payload_length, w.payload_offset, w.sequence, w.payload_sha256});
        }
        CHECK(decoded.records.back().object_id == 8193 && decoded.records.back().parent_object_id == 8193);
        authority.proof = {o.protected_binding, head.sha256, head.bytes, head.records, head.last_sequence, 8193, 8193};
    }
    const auto original = MaintenanceFiles(o.root), old_keys = MaintenanceFiles(o.protected_key_directory);
    const auto wal_bytes = Read(wal_options.path);
    {
        Spool spool(o); // No advisory snapshot: authority comes from the exact WAL.
        const auto acquired_keys = MaintenanceFiles(o.protected_key_directory);
        {
            auto probe = crypto::SecureBytes::Allocate(count * 80);
            std::cout << "REFERENCE_LIMIT locked allocation probe bytes=" << count * 80 << " error=" << static_cast<int>(probe.error)
                << " os_status=" << probe.os_status << " working_set_min=" << minimum << " max=" << maximum << std::endl;
        }
        // Caller order cannot change the canonical receipt digest.
        std::reverse(authority.refs.begin(), authority.refs.end());
        const auto result = spool.ReconcileProtectedHistory(authority.proof, authority.refs);
        SIZE_T after_minimum = 0, after_maximum = 0;
        CHECK(GetProcessWorkingSetSize(GetCurrentProcess(), &after_minimum, &after_maximum));
        CHECK(after_minimum == minimum && after_maximum == maximum);
        std::cout << "REFERENCE_LIMIT all_clean_result=" << static_cast<int>(result) << " actual_authenticated_refs=" << authority.refs.size() << std::endl;
        if (result != Maintenance::Succeeded)
        {
            CHECK(MaintenanceFiles(o.root) == original && MaintenanceFiles(o.protected_key_directory) == acquired_keys);
            CHECK(Read(wal_options.path) == wal_bytes);
        }
        CHECK(result == Maintenance::Succeeded);
        CHECK(fs::file_size(spool.SpoolFilePath()) == 0 && fs::file_size(o.root / "payload-spool.idx") == 104);
        CHECK(spool.SnapshotCounters().dirty_range_count == 0);
    }
    Spool::PersistedRangeReference reused;
    {
        Spool spool(o); CHECK(spool.RecoveryRequired());
        CHECK(spool.ReconcileProtectedHistory(authority.proof, authority.refs) == Maintenance::Succeeded);
        CHECK(!spool.Append({volume, 99, 21, 0, 8193, payload}));
        Spool::AppendResult r; CHECK(spool.Append({volume, 99, 21, 0, 8194, payload}, &r));
        CHECK(r.spool_offset == 0); reused = Ref(r); CHECK(spool.FlushPayloadBytes());
    }
    {
        Wal wal(wal_options); const auto previous = wal.ReadAllAtProtectedHead(
            {authority.proof.wal_sha256, authority.proof.wal_bytes, authority.proof.wal_records, authority.proof.wal_last_sequence});
        CHECK(previous.status == Wal::ReadStatus::Ok && previous.records.size() == 8193);
        Wal::Record write; write.volume_identity = volume; write.sequence = write.transaction_id = reused.wal_sequence;
        write.object_id = reused.object_id; write.payload_spool_id = reused.generation; write.payload_offset = reused.spool_offset;
        write.logical_offset = reused.logical_offset; write.payload_length = write.logical_length = reused.payload_length;
        write.payload_sha256 = reused.payload_sha256; write.path_utf8 = "\\private-spool-canary";
        Wal::Record accepted; accepted.volume_identity = volume; accepted.sequence = 8195; accepted.transaction_id = write.sequence;
        accepted.operation = Wal::OperationKind::TransactionMarker; accepted.state = Wal::RecordState::Accepted; accepted.object_id = 73;
        Wal::Record watermark; watermark.volume_identity = volume; watermark.sequence = 8196;
        watermark.operation = Wal::OperationKind::DurabilityWatermark; watermark.state = Wal::RecordState::Cleaned;
        watermark.object_id = 8196; watermark.parent_object_id = 8193;
        CHECK(wal.AppendBatch({write, accepted, watermark}));
        Wal::ProtectedHistoryHead head; CHECK(wal.CaptureProtectedHistoryHead(head));
        const auto decoded = wal.ReadAllAtProtectedHead(head); CHECK(decoded.status == Wal::ReadStatus::Ok && decoded.records.size() == 8196);
        const auto& r = decoded.records[8193]; CHECK(r.payload_offset == 0 && r.payload_sha256 == reused.payload_sha256);
        // References retired by the committed reset are no longer physical frames.
        authority.refs = {{r.volume_identity, r.object_id, r.payload_spool_id, r.logical_offset,
            r.payload_length, r.payload_offset, r.sequence, r.payload_sha256}};
        authority.proof = {o.protected_binding, head.sha256, head.bytes, head.records, head.last_sequence, 8196, 8193};
    }
    {
        Spool spool(o); CHECK(spool.RecoveryRequired());
        CHECK(spool.ReconcileProtectedHistory(authority.proof, authority.refs) == Maintenance::Succeeded);
        std::vector<std::byte> restored; CHECK(spool.ReadPersistedRange(reused, restored)); CHECK(restored == payload);
        CHECK(spool.SnapshotCounters().dirty_range_count == 1 && fs::file_size(spool.SpoolFilePath()) == payload.size() + 80);
    }
    const auto continued_wal = Read(wal_options.path); CHECK(std::equal(wal_bytes.begin(), wal_bytes.end(), continued_wal.begin()));
    for (const auto& [name, bytes] : old_keys) CHECK(Read(o.protected_key_directory / name) == bytes);
    CHECK(crypto::testing::hooks.all_released_bytes_zero && journal::testing::hooks.dpapi_released_zero);
    std::cout << "REFERENCE_LIMIT 4096 real accepted refs: all-clean reset, fresh-owner reopen, offset-zero reuse and exact new WAL replay PASS\n";
}
void MaintenanceReferenceHashFailures()
{
    auto o = Options("maintenance-ref-fail"); Spool spool(o);
    const auto refs = MaintenanceSeed(spool, 7); const auto authority = Authority(o, refs, 7);
    const auto before = MaintenanceFiles(o.root), keys = MaintenanceFiles(o.protected_key_directory);
    for (unsigned fault = 0; fault < 7; ++fault)
    {
        st::hooks = {}; auto& hooks = crypto::testing::hooks;
        if (fault < 2) hooks.allocation_failure_at = hooks.allocations + fault;
        else if (fault < 4) hooks.lock_failure_at = hooks.locks + fault - 2;
        else if (fault == 4) st::hooks.maintenance_fault = "cleanup-reference-hash-create";
        else if (fault == 5)
        {
            st::hooks.maintenance_observer = [seen = 0u](std::string_view stage) mutable {
                if (stage == "cleanup-reference-hash-data" && ++seen == 3) st::hooks.maintenance_fault = std::string(stage);
            };
        }
        else st::hooks.maintenance_fault = "cleanup-reference-hash-finish";
        const auto releases = hooks.releases;
        CHECK(spool.ReconcileProtectedHistory(authority.proof, authority.refs) == Maintenance::RejectedBeforeWrite);
        CHECK(fault < 4 || st::hooks.triggered);
        CHECK(MaintenanceFiles(o.root) == before && MaintenanceFiles(o.protected_key_directory) == keys);
        CHECK(hooks.all_released_bytes_zero && (fault == 0 || hooks.releases > releases));
        hooks.allocation_failure_at = hooks.lock_failure_at = -1; st::hooks = {};
    }
    CHECK(spool.ReconcileProtectedHistory(authority.proof, authority.refs) == Maintenance::Succeeded);
    CHECK(fs::file_size(spool.SpoolFilePath()) == 0 && crypto::testing::hooks.all_released_bytes_zero);
}
void MaintenanceCuts()
{
    const std::vector<std::string> stages = {"cleanup-original-data-flush", "cleanup-original-index-flush", "cleanup-after-original-barrier",
        "cleanup-after-chain-barrier", "cleanup-before-intent-create", "cleanup-after-intent-create", "cleanup-partial-intent-write", "cleanup-after-intent-write",
        "cleanup-intent-flush", "cleanup-after-intent-flush", "cleanup-after-intent-readback", "cleanup-before-guard-write", "cleanup-partial-guard-write",
        "cleanup-after-guard-write", "cleanup-guard-flush", "cleanup-after-guard-flush", "cleanup-after-guard-readback", "cleanup-before-data-reset", "cleanup-after-data-reset",
        "cleanup-data-reset-flush", "cleanup-after-data-reset-flush", "cleanup-before-index-reset", "cleanup-after-index-reset", "cleanup-index-reset-flush",
        "cleanup-after-index-reset-flush", "cleanup-before-commit-create", "cleanup-after-commit-create", "cleanup-partial-commit-write", "cleanup-after-commit-write",
        "cleanup-commit-flush", "cleanup-after-commit-flush", "cleanup-after-commit-readback"};
    for (unsigned mode = 0; mode < 2; ++mode) for (const auto& stage : stages)
    {
        if (mode && stage.find("data-reset") != stage.npos) continue;
        auto o = Options("maintenance-c" + std::to_string(mode) + "-" + std::to_string(&stage - stages.data()));
        OriginalAuthority authority; std::vector<std::byte> original; FileSnapshot keys;
        {
            Spool spool(o); auto refs = MaintenanceSeed(spool); authority = Authority(o, refs, mode ? 1 : 2);
            original = Read(spool.SpoolFilePath()); keys = MaintenanceFiles(o.protected_key_directory); const auto before = MaintenanceFiles(o.root);
            st::hooks = {}; st::hooks.maintenance_fault = stage;
            const auto result = spool.ReconcileProtectedHistory(authority.proof, authority.refs); CHECK(st::hooks.triggered);
            const bool prewrite = stage == "cleanup-original-data-flush" || stage == "cleanup-original-index-flush" || stage == "cleanup-after-original-barrier" ||
                stage == "cleanup-after-chain-barrier" || stage == "cleanup-before-intent-create";
            CHECK(result == (prewrite ? Maintenance::RejectedBeforeWrite : Maintenance::RecoveryRequired));
            if (prewrite) CHECK(MaintenanceFiles(o.root) == before);
            else { CHECK(!spool.Append({volume, 99, 21, 0, 3, Bytes(canary)})); CHECK(!spool.FlushDirtyState()); }
            if (mode) CHECK(Read(spool.SpoolFilePath()) == original);
            st::hooks = {};
        }
        {
            Spool reopened(o); auto wrong = authority.proof; wrong.wal_sha256[0] ^= 1;
            const auto pending = MaintenanceFiles(o.root);
            if (fs::exists(o.root / "payload-spool.cleanup.0000000000000001.intent") &&
                (!fs::exists(o.root / "payload-spool.cleanup.0000000000000001.commit") || fs::file_size(o.root / "payload-spool.cleanup.0000000000000001.commit") < 144) &&
                fs::file_size(o.root / "payload-spool.cleanup.0000000000000001.intent") == 352)
            { CHECK(reopened.ReconcileProtectedHistory(wrong, authority.refs) == Maintenance::RejectedBeforeWrite); CHECK(MaintenanceFiles(o.root) == pending); }
            CHECK(reopened.ReconcileProtectedHistory(authority.proof, authority.refs) == Maintenance::Succeeded);
            CheckLive(reopened, authority.refs, mode ? 1 : 2); CHECK(fs::file_size(reopened.SpoolFilePath()) == (mode ? original.size() : 0));
            for (const auto& [name, bytes] : keys) CHECK(Read(o.protected_key_directory / name) == bytes);
            Spool::AppendResult r; CHECK(reopened.Append({volume, 89, 21, 0, 3, Bytes(canary)}, &r));
            CHECK(r.spool_offset == (mode ? original.size() : 0)); CHECK(reopened.FlushDirtyState());
            auto refs = authority.refs; refs.push_back(Ref(r)); authority = Authority(o, refs, mode ? 1 : 2);
        }
        { Spool reopened(o); CHECK(reopened.ReconcileProtectedHistory(authority.proof, authority.refs) == Maintenance::Succeeded); CheckLive(reopened, authority.refs, mode ? 1 : 2); }
        std::cout << "CLEANUP_CUT mode=" << mode << ' ' << stage << " -> authorized recovery, exact live refs, append/reopen PASS\n";
    }
}
void MaintenanceAuthorityAndBarriers()
{
    auto o = Options("maintenance-auth"); Spool spool(o); auto refs = MaintenanceSeed(spool); auto authority = Authority(o, refs, 1);
    auto original = MaintenanceFiles(o.root), keys = MaintenanceFiles(o.protected_key_directory);
    for (unsigned n = 0; n < 8; ++n)
    {
        auto proof = authority.proof; auto supplied = authority.refs;
        if (n == 0) proof.source_binding[0] ^= std::byte{1}; if (n == 1) proof.wal_bytes = 0;
        if (n == 2) proof.cleanup_sequence = proof.durable_sequence + 1; if (n == 3) proof.durable_sequence = proof.wal_last_sequence + 1;
        if (n == 4) supplied.pop_back(); if (n == 5) supplied.push_back(supplied.front());
        if (n == 6) supplied.front().payload_sha256[0] ^= 1; if (n == 7) supplied.front().object_id ^= 1;
        CHECK(spool.ReconcileProtectedHistory(proof, supplied) == Maintenance::RejectedBeforeWrite);
        CHECK(MaintenanceFiles(o.root) == original && MaintenanceFiles(o.protected_key_directory) == keys);
    }
    st::hooks = {}; CHECK(spool.ReconcileProtectedHistory(authority.proof, authority.refs) == Maintenance::Succeeded);
    const auto& order = st::hooks.maintenance_events;
    const auto at = [&](std::string_view s) { const auto p = std::find(order.begin(), order.end(), s); CHECK(p != order.end()); return p - order.begin(); };
    CHECK(at("cleanup-after-original-barrier") < at("cleanup-before-intent-create"));
    CHECK(at("cleanup-after-intent-readback") < at("cleanup-before-guard-write"));
    CHECK(at("cleanup-after-guard-readback") < at("cleanup-before-index-reset"));
    CHECK(at("cleanup-after-intent-readback") < at("cleanup-before-index-reset"));
    CHECK(at("cleanup-after-index-reset-flush") < at("cleanup-before-commit-create")); st::hooks = {};
    std::cout << "CLEANUP_ORDER original barrier -> durable authenticated intent -> index reset/flush -> encrypted commit/flush/readback\n";
}
void MaintenanceTamperAndKeys()
{
    for (unsigned n = 0; n < 9; ++n)
    {
        auto o = Options("maintenance-t" + std::to_string(n)); OriginalAuthority authority;
        { Spool spool(o); auto refs = MaintenanceSeed(spool); authority = Authority(o, refs, 1); CHECK(spool.ReconcileProtectedHistory(authority.proof, authority.refs) == Maintenance::Succeeded); }
        auto target = o.root / (n == 1 ? "payload-spool.cleanup.0000000000000001.commit" : "payload-spool.cleanup.0000000000000001.intent");
        if (n < 2) { auto b = Read(target); b.back() ^= std::byte{1}; Write(target, b); }
        if (n == 2) { auto b = Read(o.root / "payload-spool.bin"); b.back() ^= std::byte{1}; Write(o.root / "payload-spool.bin", b); }
        if (n == 3) authority.proof.source_binding[0] ^= std::byte{1};
        if (n == 4) authority.proof.cleanup_sequence = 0; // Authenticated committed floor cannot regress.
        if (n == 5) { for (const auto& slot : fs::directory_iterator(o.protected_key_directory)) if (slot.path().extension() == ".key")
            { auto b = Read(slot.path()); CHECK(!b.empty()); b.back() ^= std::byte{1}; Write(slot.path(), b); break; } }
        if (n == 6) { fs::create_directory(o.root.parent_path() / "emptykeys"); o.protected_key_directory = o.root.parent_path() / "emptykeys"; }
        if (n == 7) { fs::rename(o.root / "payload-spool.protected", o.root / "preserved-marker");
            auto ordinary = o; ordinary.protected_persistence = false; Spool rejected(ordinary); CHECK(rejected.RecoveryRequired());
            CHECK(!rejected.Append({volume, 1, 21, 0, 4, Bytes(canary)})); CHECK(!rejected.ResolveUnindexedPayloadRecovery(true)); }
        if (n == 8) { fs::rename(target, o.root / "preserved-intent"); fs::rename(o.root / "preserved-intent", o.root / "PAYLOAD-SPOOL.CLEANUP.0000000000000001.intent"); }
        const auto before = MaintenanceFiles(o.root), keys = MaintenanceFiles(o.protected_key_directory);
        { Spool spool(o); CHECK(spool.RecoveryRequired()); CHECK(spool.ReconcileProtectedHistory(authority.proof, authority.refs) == Maintenance::RejectedBeforeWrite);
            CHECK(!spool.Append({volume, 88, 21, 0, 4, Bytes(canary)})); }
        CHECK(MaintenanceFiles(o.root) == before && MaintenanceFiles(o.protected_key_directory) == keys);
    }
    auto o = Options("maintenance-chain"); OriginalAuthority authority;
    { Spool spool(o); auto refs = MaintenanceSeed(spool); authority = Authority(o, refs, 2);
        st::hooks = {}; st::hooks.maintenance_fault = "cleanup-after-commit-write";
        CHECK(spool.ReconcileProtectedHistory(authority.proof, authority.refs) == Maintenance::RecoveryRequired); CHECK(st::hooks.triggered); st::hooks = {}; }
    { Spool spool(o); const auto before = MaintenanceFiles(o.root); st::hooks.maintenance_fault = "cleanup-chain-flush";
        CHECK(spool.ReconcileProtectedHistory(authority.proof, authority.refs) == Maintenance::RejectedBeforeWrite); CHECK(st::hooks.triggered); CHECK(MaintenanceFiles(o.root) == before);
        st::hooks = {}; CHECK(spool.ReconcileProtectedHistory(authority.proof, authority.refs) == Maintenance::Succeeded); }
    st::hooks = {};
}
void MaintenanceScan()
{
    const auto wide = [](std::string_view s) { std::vector<std::byte> b; for (auto c : s) { b.push_back(static_cast<std::byte>(c)); b.push_back(std::byte{}); } return b; };
    std::vector<std::vector<std::byte>> needles;
    for (auto text : {std::string_view(canary), std::string_view(volume), std::string_view(keyCanary, 32)}) { needles.push_back(Bytes(text)); needles.push_back(wide(text)); }
    unsigned scanned = 0;
    for (fs::recursive_directory_iterator it(root), end; it != end; ++it)
    {
        const auto& entry = *it;
        const auto attr = GetFileAttributesW(entry.path().c_str()); CHECK(attr != INVALID_FILE_ATTRIBUTES);
        if (attr & FILE_ATTRIBUTE_REPARSE_POINT) { it.disable_recursion_pending(); continue; }
        const auto name = entry.path().lexically_relative(root).generic_string(); if (!name.starts_with("maintenance-")) continue;
        if (!entry.is_regular_file() || name.starts_with("maintenance-t")) continue;
        const auto b = Read(entry.path()); for (const auto& needle : needles) CHECK(std::search(b.begin(), b.end(), needle.begin(), needle.end()) == b.end()); ++scanned;
    }
    CHECK(scanned > 100); CHECK(journal::testing::hooks.dpapi_released_zero && crypto::testing::hooks.all_released_bytes_zero);
    std::cout << "MAINTENANCE_SCAN " << scanned << " encrypted data/index/marker/receipt/quarantine/key/WAL files; raw and UTF16 canaries absent\n";
}
void MaintenanceRecoveryEdges()
{
    for (bool reopened : {false, true})
    {
        auto o = Options(reopened ? "maintenance-dr" : "maintenance-da"); auto spool = std::make_unique<Spool>(o); Spool::AppendResult result;
        CHECK(spool->Append({volume, 17, 21, 0, 1, Bytes(canary)}, &result)); CHECK(spool->SnapshotCounters().bytes_since_sync > 0);
        auto authority = Authority(o, {Ref(result)}, 0, false); // Durable Prepared WAL only; payload deliberately deferred.
        if (reopened) { spool.reset(); spool = std::make_unique<Spool>(o); CHECK(spool->SnapshotCounters().bytes_since_sync == 0); }
        const auto before = MaintenanceFiles(o.root), keys = MaintenanceFiles(o.protected_key_directory);
        for (auto fault : {"cleanup-original-data-flush", "cleanup-original-index-flush", "cleanup-after-original-barrier"})
        {
            st::hooks = {}; st::hooks.maintenance_fault = fault;
            CHECK(spool->ReconcileProtectedHistory(authority.proof, authority.refs) == Maintenance::RejectedBeforeWrite); CHECK(st::hooks.triggered);
            CHECK(MaintenanceFiles(o.root) == before && MaintenanceFiles(o.protected_key_directory) == keys);
        }
        st::hooks = {}; CHECK(spool->ReconcileProtectedHistory(authority.proof, authority.refs) == Maintenance::Succeeded); CheckLive(*spool, authority.refs, 0);
        CHECK(spool->FlushDirtyState()); st::hooks = {};
    }
    for (unsigned race = 0; race < 2; ++race)
    {
        auto o = Options("maintenance-r" + std::to_string(race)); Spool spool(o); auto refs = MaintenanceSeed(spool); auto authority = Authority(o, refs, 2);
        const auto occupied = o.root / (race ? "payload-spool.cleanup.0000000000000001.commit" : "payload-spool.cleanup.0000000000000001.intent");
        const auto foreign = std::vector<std::byte>(352, std::byte{0x37}); bool inserted = false;
        st::hooks = {}; st::hooks.maintenance_observer = [&](auto stage) {
            if (!inserted && stage == (race ? "cleanup-before-commit-create" : "cleanup-before-intent-create")) { Write(occupied, foreign); inserted = true; }
        };
        CHECK(spool.ReconcileProtectedHistory(authority.proof, authority.refs) == (race ? Maintenance::RecoveryRequired : Maintenance::RejectedBeforeWrite));
        CHECK(inserted && Read(occupied) == foreign); CHECK(!spool.Append({volume, 99, 21, 0, 3, Bytes(canary)})); st::hooks = {};
    }
    for (unsigned fault = 0; fault < 3; ++fault)
    {
        auto o = Options("maintenance-p" + std::to_string(fault)); Spool spool(o); auto refs = MaintenanceSeed(spool); auto authority = Authority(o, refs, 1);
        const auto before = MaintenanceFiles(o.root), keys = MaintenanceFiles(o.protected_key_directory);
        auto& hooks = crypto::testing::hooks;
        if (fault == 0) hooks.lock_failure_at = hooks.locks;
        if (fault == 1) hooks.allocation_failure_at = hooks.allocations;
        if (fault == 2) hooks.cng_failure_at = hooks.cng_calls;
        CHECK(spool.ReconcileProtectedHistory(authority.proof, authority.refs) == Maintenance::RejectedBeforeWrite);
        hooks.lock_failure_at = hooks.allocation_failure_at = hooks.cng_failure_at = -1;
        CHECK(MaintenanceFiles(o.root) == before && MaintenanceFiles(o.protected_key_directory) == keys);
        CHECK(spool.ReconcileProtectedHistory(authority.proof, authority.refs) == Maintenance::Succeeded);
    }
    auto o = Options("maintenance-key"); OriginalAuthority authority;
    { Spool spool(o); auto refs = MaintenanceSeed(spool); authority = Authority(o, refs, 1); CHECK(spool.ReconcileProtectedHistory(authority.proof, authority.refs) == Maintenance::Succeeded); }
    auto all_clean = Authority(o, authority.refs, 2); const auto before = MaintenanceFiles(o.root), keys = MaintenanceFiles(o.protected_key_directory);
    { Spool spool(o); journal::testing::hooks.fault = journal::testing::EpochFault::SlotFlush; journal::testing::hooks.triggered = false;
        CHECK(spool.ReconcileProtectedHistory(all_clean.proof, all_clean.refs) == Maintenance::RecoveryRequired); CHECK(journal::testing::hooks.triggered);
        journal::testing::hooks.fault = journal::testing::EpochFault::None; CHECK(MaintenanceFiles(o.root) == before); }
    for (const auto& [name, bytes] : keys) CHECK(Read(o.protected_key_directory / name) == bytes);
    { Spool spool(o); CHECK(spool.ReconcileProtectedHistory(all_clean.proof, all_clean.refs) == Maintenance::Succeeded); }
    // Restoring valid pre-reset bytes cannot satisfy the new trusted cleanup state.
    auto stale_data = before.at("payload-spool.bin"); Write(o.root / "payload-spool.bin", stale_data);
    const auto saved = MaintenanceFiles(o.root);
    { Spool spool(o); CHECK(spool.ReconcileProtectedHistory(all_clean.proof, all_clean.refs) == Maintenance::RejectedBeforeWrite); CHECK(MaintenanceFiles(o.root) == saved); }
    auto guard_options = Options("maintenance-guard"); OriginalAuthority guard_proof;
    { Spool spool(guard_options); auto refs = MaintenanceSeed(spool); guard_proof = Authority(guard_options, refs, 2);
        st::hooks = {}; st::hooks.maintenance_fault = "cleanup-after-data-reset-flush";
        CHECK(spool.ReconcileProtectedHistory(guard_proof.proof, guard_proof.refs) == Maintenance::RecoveryRequired); CHECK(st::hooks.triggered); st::hooks = {}; }
    auto guard_path = guard_options.root / "payload-spool.idx"; auto guard_bytes = Read(guard_path); guard_bytes.back() ^= std::byte{1}; Write(guard_path, guard_bytes);
    const auto damaged = MaintenanceFiles(guard_options.root);
    { Spool spool(guard_options); CHECK(spool.ReconcileProtectedHistory(guard_proof.proof, guard_proof.refs) == Maintenance::RejectedBeforeWrite); CHECK(MaintenanceFiles(guard_options.root) == damaged); }
    st::hooks = {};
}
void MaintenancePathBounds()
{
    const auto generated_name = L"payload-spool.cleanup.failed." + std::wstring(64, L'0') + L".15";
    for (const std::size_t length : {210u, 211u})
    {
        std::string name = "maintenance-path-" + std::to_string(length);
        const auto initial = (root / name / "spool" / generated_name).wstring().size();
        CHECK(initial <= length);
        name.append(length - initial, 'x');
        auto o = Options(name);
        CHECK((o.root / generated_name).wstring().size() == length);
        Spool spool(o); auto refs = MaintenanceSeed(spool); auto authority = Authority(o, refs, 2);
        const auto before = MaintenanceFiles(o.root), keys = MaintenanceFiles(o.protected_key_directory);
        CHECK(spool.MatchesProtectedMaintenanceAuthority(o.protected_binding, volume,
            o.root.parent_path() / "original-WAL" / "keys") == (length == 210));
        const auto result = spool.ReconcileProtectedHistory(authority.proof, authority.refs);
        if (length == 211)
        {
            CHECK(result == Maintenance::RejectedBeforeWrite);
            CHECK(MaintenanceFiles(o.root) == before && MaintenanceFiles(o.protected_key_directory) == keys);
        }
        else
        {
            CHECK(result == Maintenance::Succeeded && fs::file_size(spool.SpoolFilePath()) == 0);
            for (const auto& [file, bytes] : keys) CHECK(Read(o.protected_key_directory / file) == bytes);
        }
    }
    st::hooks = {};
}
void MaintenanceQuarantineCuts()
{
    unsigned n = 0;
    for (bool commit : {false, true}) for (auto cut : {"cleanup-before-quarantine", "cleanup-after-quarantine", "cleanup-quarantine-flush"})
    {
        auto o = Options("maintenance-q" + std::to_string(++n)); OriginalAuthority authority; std::vector<std::byte> torn;
        {
            Spool spool(o); auto refs = MaintenanceSeed(spool); authority = Authority(o, refs, 2);
            st::hooks = {}; st::hooks.maintenance_fault = commit ? "cleanup-partial-commit-write" : "cleanup-partial-intent-write";
            CHECK(spool.ReconcileProtectedHistory(authority.proof, authority.refs) == Maintenance::RecoveryRequired); CHECK(st::hooks.triggered); st::hooks = {};
        }
        const auto target = o.root / (commit ? "payload-spool.cleanup.0000000000000001.commit" : "payload-spool.cleanup.0000000000000001.intent");
        torn = Read(target); CHECK(torn.size() == 13);
        {
            Spool spool(o); st::hooks = {}; st::hooks.maintenance_fault = cut;
            CHECK(spool.ReconcileProtectedHistory(authority.proof, authority.refs) == Maintenance::RecoveryRequired); CHECK(st::hooks.triggered); st::hooks = {};
        }
        {
            Spool spool(o); CHECK(spool.ReconcileProtectedHistory(authority.proof, authority.refs) == Maintenance::Succeeded);
            CHECK(fs::file_size(spool.SpoolFilePath()) == 0); bool preserved = false;
            for (const auto& [name, b] : MaintenanceFiles(o.root)) if (name.starts_with("payload-spool.cleanup.failed.")) { CHECK(b == torn); preserved = true; }
            CHECK(preserved); st::hooks = {};
        }
        { Spool spool(o); CHECK(spool.ReconcileProtectedHistory(authority.proof, authority.refs) == Maintenance::Succeeded); CHECK(spool.Append({volume, 99, 21, 0, 3, Bytes(canary)})); }
        std::cout << "QUARANTINE_CUT commit=" << commit << ' ' << cut << " -> preserved exact torn bytes, durable retry/reopen PASS\n";
    }
    // An accepted append-only root can be too long for maintenance artifacts.
    // Admission must refuse before creating any receipt or changing canonical data.
    MaintenancePathBounds();
}
void MaintenanceAcceptedHistory()
{
    auto o = Options("maintenance-wal"); std::vector<Spool::PersistedRangeReference> refs; OriginalAuthority first, all_clean;
    const auto journal_path = o.root.parent_path() / "original-WAL" / "original.wal";
    const auto publish_floor = [&](std::uint64_t floor) {
        Wal::ProtectedPersistence protection; protection.key_directory = o.root.parent_path() / "original-WAL" / "keys";
        protection.source_binding = protection.journal_identity = o.protected_binding;
        Wal wal({journal_path, volume, 4 * 1024 * 1024, protection}); auto records = wal.ReadAllWithExclusiveWriterLease(); CHECK(records.status == Wal::ReadStatus::Ok);
        auto sequence = records.records.back().sequence;
        if (records.records.size() == refs.size()) for (const auto& r : refs) {
            Wal::Record marker; marker.sequence = ++sequence; marker.transaction_id = r.wal_sequence; marker.volume_identity = volume;
            marker.operation = Wal::OperationKind::TransactionMarker; marker.state = Wal::RecordState::Accepted; marker.object_id = 73; CHECK(wal.Append(marker));
        }
        Wal::Record watermark; watermark.volume_identity = volume; watermark.sequence = ++sequence;
        watermark.operation = Wal::OperationKind::DurabilityWatermark; watermark.state = Wal::RecordState::Cleaned;
        watermark.object_id = sequence; watermark.parent_object_id = floor; CHECK(wal.Append(watermark));
    };
    {
        Spool spool(o); refs = MaintenanceSeed(spool); (void)Authority(o, refs, 0); publish_floor(1); first = Authority(o, refs, 1);
        CHECK(first.proof.wal_records == 5 && first.proof.durable_sequence == 5); const auto original = Read(journal_path);
        CHECK(spool.ReconcileProtectedHistory(first.proof, first.refs) == Maintenance::Succeeded); CheckLive(spool, refs, 1); CHECK(Read(journal_path) == original);
        publish_floor(2); all_clean = Authority(o, refs, 2); const auto extended = Read(journal_path);
        CHECK(all_clean.proof.wal_records == 6 && std::equal(original.begin(), original.end(), extended.begin()));
        CHECK(spool.ReconcileProtectedHistory(all_clean.proof, all_clean.refs) == Maintenance::Succeeded); CHECK(Read(journal_path) == extended);
    }
    {
        Spool spool(o); CHECK(spool.ReconcileProtectedHistory(all_clean.proof, all_clean.refs) == Maintenance::Succeeded);
        Spool::AppendResult r; CHECK(spool.Append({volume, 99, 21, 0, 7, Bytes(canary)}, &r)); CHECK(r.spool_offset == 0); refs.push_back(Ref(r)); CHECK(spool.FlushPayloadBytes());
        const auto continued = Authority(o, refs, 2); CHECK(continued.proof.wal_last_sequence == 7 && continued.proof.durable_sequence == 6);
        CHECK(spool.ReconcileProtectedHistory(continued.proof, continued.refs) == Maintenance::Succeeded); CheckLive(spool, refs, 2);
    }
    std::cout << "ACCEPTED_WAL original accepted markers and durable/cleanup watermarks remain byte-exact across maintenance and append\n";
}
void MaintenanceReceiptPins()
{
    auto o = Options("receipt-pins");
    std::vector<Spool::PersistedRangeReference> refs;
    OriginalAuthority authority;
    {
        Spool spool(o);
        for (unsigned n = 1; n <= 6; ++n)
        {
            auto added = MaintenanceSeed(spool, 1, n); CHECK(added.front().spool_offset == 0);
            refs.push_back(added.front()); authority = Authority(o, refs, n);
            unsigned chain_flushes = 0;
            st::hooks = {}; st::hooks.maintenance_observer = [&](std::string_view stage) {
                if (stage == "cleanup-chain-flush") ++chain_flushes;
            };
            CHECK(spool.ReconcileProtectedHistory(authority.proof, authority.refs) == Maintenance::Succeeded);
            CHECK(chain_flushes == 0); // Already durable receipts stay immutable under held handles.
            st::hooks = {};
            CHECK(fs::file_size(spool.SpoolFilePath()) == 0);
            const auto receipts = MaintenanceFiles(o.root);
            for (const auto& [name, bytes] : receipts) if (name.starts_with("payload-spool.cleanup."))
            {
                const auto path = o.root / name;
                for (auto access : {DWORD(GENERIC_WRITE), DWORD(DELETE)})
                {
                    const auto h = CreateFileW(path.c_str(), access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
                    CHECK(h == INVALID_HANDLE_VALUE); CHECK(GetLastError() == ERROR_SHARING_VIOLATION);
                }
                CHECK(Read(path) == bytes);
            }
        }
    }
    const auto original = MaintenanceFiles(o.root), keys = MaintenanceFiles(o.protected_key_directory);
    FileSnapshot warmed_keys;
    {
        Spool spool(o); st::hooks = {}; st::hooks.maintenance_fault = "cleanup-chain-flush";
        CHECK(spool.ReconcileProtectedHistory(authority.proof, authority.refs) == Maintenance::RejectedBeforeWrite);
        CHECK(st::hooks.triggered); CHECK(MaintenanceFiles(o.root) == original);
        unsigned flushes = 0; st::hooks = {}; st::hooks.maintenance_observer = [&](std::string_view stage) {
            if (stage == "cleanup-chain-flush") ++flushes;
        };
        CHECK(spool.ReconcileProtectedHistory(authority.proof, authority.refs) == Maintenance::Succeeded);
        CHECK(flushes == 12); flushes = 0;
        warmed_keys = MaintenanceFiles(o.protected_key_directory);
        CHECK(spool.ReconcileProtectedHistory(authority.proof, authority.refs) == Maintenance::Succeeded);
        CHECK(flushes == 0); CHECK(MaintenanceFiles(o.root) == original);
        st::hooks = {}; st::hooks.maintenance_fault = "cleanup-original-data-flush";
        CHECK(spool.ReconcileProtectedHistory(authority.proof, authority.refs) == Maintenance::RejectedBeforeWrite);
        CHECK(st::hooks.triggered); CHECK(MaintenanceFiles(o.root) == original); st::hooks = {};
        const auto slot = fs::path(keys.begin()->first), saved = o.root.parent_path() / "saved-key";
        fs::rename(o.protected_key_directory / slot, saved);
        CHECK(spool.ReconcileProtectedHistory(authority.proof, authority.refs) == Maintenance::RejectedBeforeWrite);
        CHECK(MaintenanceFiles(o.root) == original);
        fs::rename(saved, o.protected_key_directory / slot);
        CHECK(spool.ReconcileProtectedHistory(authority.proof, authority.refs) == Maintenance::Succeeded);
        auto wrong = authority.proof; wrong.source_binding[0] ^= std::byte{1};
        CHECK(spool.ReconcileProtectedHistory(wrong, authority.refs) == Maintenance::RejectedBeforeWrite);
        CHECK(MaintenanceFiles(o.root) == original && MaintenanceFiles(o.protected_key_directory) == warmed_keys);
    }
    const auto target = o.root / "payload-spool.cleanup.0000000000000001.intent";
    auto damaged = Read(target); damaged.back() ^= std::byte{1}; Write(target, damaged);
    const auto corrupted = MaintenanceFiles(o.root);
    {
        Spool spool(o);
        CHECK(spool.ReconcileProtectedHistory(authority.proof, authority.refs) == Maintenance::RejectedBeforeWrite);
        CHECK(MaintenanceFiles(o.root) == corrupted && MaintenanceFiles(o.protected_key_directory) == warmed_keys);
    }
    st::hooks = {};
    std::cout << "RECEIPT_PINS six clean/reuse commits: warm chain flushes zero, reopen twelve, failed barrier retries, immutable files and missing-key/corrupt receipt refusals PASS\n";
}
}

int main(int argc, char** argv)
{
    try
    {
        CHECK(argc == 2 || argc == 3); const bool maintenance_only = argc == 3;
        const bool reference_only = argc == 3 && std::string_view(argv[2]) == "--reference-limit-only";
        const bool receipt_only = argc == 3 && std::string_view(argv[2]) == "--receipt-cache-only";
        const bool missing_only = argc == 3 && std::string_view(argv[2]) == "--missing-index-only";
        const bool tail_only = argc == 3 && std::string_view(argv[2]) == "--maintenance-tail-only";
        CHECK(!maintenance_only || reference_only || receipt_only || missing_only || tail_only || std::string_view(argv[2]) == "--maintenance-only"); root = fs::path(argv[1]).make_preferred();
        const auto path = root.wstring();
        CHECK(path.size() > 3 && path.size() <= 180 &&
            ((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')) &&
            path[1] == L':' && path[2] == L'\\' && path.back() != L'\\' && path.find_first_of(L":/*?\"<>|", 3) == path.npos);
        CHECK(GetDriveTypeW(path.substr(0, 3).c_str()) == DRIVE_FIXED);
        for (const auto& component : root.relative_path())
        {
            const auto part = component.wstring();
            CHECK(!part.empty() && part != L"." && part != L".." && part.back() != L'.' && part.back() != L' ');
        }
        const auto parent = root.parent_path().wstring();
        std::vector<std::unique_ptr<DirectoryPin>> pins;
        for (std::size_t end = 2;;)
        {
            const auto prefix = parent.substr(0, end == 2 ? 3 : end);
            auto pin = std::make_unique<DirectoryPin>();
            pin->handle = CreateFileW(prefix.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
            CHECK(pin->handle != INVALID_HANDLE_VALUE);
            BY_HANDLE_FILE_INFORMATION info{}; CHECK(GetFileInformationByHandle(pin->handle, &info));
            CHECK(GetFileType(pin->handle) == FILE_TYPE_DISK && (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                !(info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT));
            std::wstring actual(512, L'\0');
            const auto length = GetFinalPathNameByHandleW(pin->handle, actual.data(), static_cast<DWORD>(actual.size()),
                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
            CHECK(length && length < actual.size()); actual.resize(length);
            CHECK(CompareStringOrdinal(actual.c_str(), -1, (L"\\\\?\\" + prefix).c_str(), -1, TRUE) == CSTR_EQUAL);
            pins.push_back(std::move(pin));
            if (end >= parent.size()) break;
            end = parent.find(L'\\', end + 1); if (end == parent.npos) end = parent.size();
        }
        CHECK(!fs::exists(root)); fs::create_directories(root);
        const auto key = Bytes(std::string_view(keyCanary, 32)); journal::testing::hooks.key_override = key;
        const auto run = [](const char* name, auto test) { test(); ++groups; std::cout << "PASS " << name << '\n'; };
        if (tail_only)
        {
            run("existing original-derived partial live cleanup and reopen", MaintenanceWorkflow);
            run("existing all-clean reset/reuse across five owners", MaintenanceScaling);
            run("torn quarantine cuts and exact210/211 generated-path boundary", MaintenanceQuarantineCuts);
            run("same original accepted WAL, exact markers/watermarks and reopen", MaintenanceAcceptedHistory);
            run("all generated maintenance persistence canary scan and buffer cleanup", MaintenanceScan);
            std::cout << "PASS " << groups << " groups / " << assertions << " assertions\n"; return 0;
        }
        if(missing_only){
            run("existing missing/stale index complete reference census",MissingAndStaleIndex);
            run("missing index no-write refusals, publication cuts and original-derived cleanup/reopen/reuse",MissingIndexPublication);
            run("existing wrong refs and physical framing controls",References);
            run("existing marker binding and publication controls",StoreMarkers);
            CHECK(crypto::testing::hooks.all_released_bytes_zero && journal::testing::hooks.dpapi_released_zero);
            std::cout<<"PASS "<<groups<<" groups / "<<assertions<<" assertions\n";return 0;
        }
        if (receipt_only)
        {
            run("durable receipt pins, warm reuse, full reopen barrier, key loss and corrupt chain", MaintenanceReceiptPins);
            run("existing partial live refs and all-clean reopen/reuse", MaintenanceWorkflow);
            run("existing receipt/key/head/floor and ambiguous complete commit barriers", MaintenanceTamperAndKeys);
            run("existing original barriers, no-replace races, provider/lock failures and rollback", MaintenanceRecoveryEdges);
            run("existing original accepted WAL and exact watermark identity", MaintenanceAcceptedHistory);
            CHECK(crypto::testing::hooks.all_released_bytes_zero && journal::testing::hooks.dpapi_released_zero);
            std::cout << "PASS " << groups << " groups / " << assertions << " assertions\n"; return 0;
        }
        if (reference_only)
        {
            run("4096 actual accepted references, full-range cleanup/reopen/reuse without quota changes", MaintenanceReferenceLimit);
            run("streamed reference hashing allocation/lock/partial-hash failures preserve bytes and wipe buffers", MaintenanceReferenceHashFailures);
            run("existing partial cleanup/reopen workflow", MaintenanceWorkflow);
            run("existing five-cycle all-clean reuse", MaintenanceScaling);
            run("existing authority/refusal and durable barrier controls", MaintenanceAuthorityAndBarriers);
            run("existing accepted WAL/watermark identity", MaintenanceAcceptedHistory);
            CHECK(crypto::testing::hooks.all_released_bytes_zero);
            std::cout << "PASS " << groups << " groups / " << assertions << " assertions\n"; return 0;
        }
        if (!maintenance_only) {
        run("actual append/flush/read/reopen, exact physical references and immutable ordered overlay", Persistence);
        run("WAL identity, length, digest and offset controls", References);
        run("missing/stale index complete authenticated reference rebuild", MissingAndStaleIndex);
        run("missing index publication, exact original authority, cuts and guard-loss refusals", MissingIndexPublication);
        run("ciphertext/header/nonce/tag/torn/tail/offset tamper and binding controls", Tampering);
        run("ordinary/protected mixed formats and plaintext fallback refusal", MixedAndPlainFallback);
        run("physical quota, index reservation, startup budgets, invalid options", Limits);
        run("key loss/corruption/DPAPI/provider/lock/allocation failure and wiping", KeyAndCryptoFailures);
        run("fixed-local authority exercised only on D, single-link files, pins, real reparse refusal", Paths);
        run("threshold data-before-index flushing", Thresholds);
        run("actual partial writes and flush faults, evidence preservation, flush order", IoFailureAndOrdering);
        run("actual 4096-range cap, index-history refusal, missing-index replay budget", RangeAndHistoryBounds);
        run("ordinary arbitrary prefix, complete fake/real frame copies and trusted missing-index proof", OrdinaryArbitraryPrefixes);
        run("durable immutable authenticated store marker, publication faults, pins and substitution", StoreMarkers);
        run("actual persistence binary canary scan", Scan);
        }
        run("original authenticated WAL reference cleanup, live offsets, corrupt advisory index and reset/reopen", MaintenanceWorkflow);
        run("actual full-cap all-clean reset/reuse across five fresh-owner cycles", MaintenanceScaling);
        run("bounded durable receipt pins and fresh-owner barriers", MaintenanceReceiptPins);
        run("4096 actual accepted references, full-range cleanup/reopen/reuse without quota changes", MaintenanceReferenceLimit);
        run("streamed reference hashing allocation/lock/partial-hash failures preserve bytes and wipe buffers", MaintenanceReferenceHashFailures);
        run("all-clean and live-range maintenance cuts, preserved torn evidence and complete retry/reopen", MaintenanceCuts);
        run("complete reference and trusted proof refusals, real original/intent/commit barrier order", MaintenanceAuthorityAndBarriers);
        run("receipt/data/key/head/floor tamper and ambiguously flushed complete commit barrier", MaintenanceTamperAndKeys);
        run("deferred/reopened original barriers, no-replace races, provider/lock/key failure and rollback", MaintenanceRecoveryEdges);
        run("torn intent/commit quarantine cuts, durable evidence retention and path admission", MaintenanceQuarantineCuts);
        run("same original accepted WAL, exact markers/watermarks/head, durable-floor cleanup and append", MaintenanceAcceptedHistory);
        run("protected cleanup persistence raw/UTF16 canaries and secure buffer release", MaintenanceScan);
        CHECK(crypto::testing::hooks.all_released_bytes_zero);
        std::cout << "PASS " << groups << " groups / " << assertions << " assertions\n";
        return 0;
    }
    catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
