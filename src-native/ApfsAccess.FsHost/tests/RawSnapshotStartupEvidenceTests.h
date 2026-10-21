#pragma once

#include "../src/NativeRawSnapshotStartupEvidence.h"
#include <winioctl.h>

#include <atomic>
#include <iostream>
#include <stdexcept>

// Include after SnapshotProjectionTests.cpp, which supplies Check(bool, string).
namespace apfsaccess::fshost::tests {
namespace raw_startup_evidence_detail {

using CheckFunction = void (*)(bool, const std::string&);
constexpr std::uint64_t HostPayloadLimit = 4ull * 1024 * 1024 * 1024;

inline void Expect(CheckFunction check, bool condition, const std::string& message)
{
    check(condition, message);
    if (!condition) throw std::runtime_error(message);
}

class TestHandle
{
public:
    explicit TestHandle(HANDLE value) noexcept : value_(value) {}
    ~TestHandle() { if (value_ != INVALID_HANDLE_VALUE) CloseHandle(value_); }
    TestHandle(const TestHandle&) = delete;
    TestHandle& operator=(const TestHandle&) = delete;
    HANDLE Get() const noexcept { return value_; }
    bool Valid() const noexcept { return value_ != INVALID_HANDLE_VALUE; }
private:
    HANDLE value_;
};

struct Fingerprint
{
    DWORD volume = 0;
    DWORD id_high = 0, id_low = 0;
    std::array<unsigned char, 16> id{};
    std::uint64_t length = 0;
    std::uint64_t creation = 0, last_write = 0;
    DWORD attributes = 0, links = 0;
    std::vector<std::byte> bytes;
    bool operator==(const Fingerprint&) const = default;
};

inline Fingerprint Original(CheckFunction check, const std::wstring& path, bool content = true)
{
    TestHandle handle(CreateFileW(path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    Expect(check, handle.Valid(), "raw evidence independent original open");
    BY_HANDLE_FILE_INFORMATION info{};
    FILE_ID_INFO id{};
    Expect(check, GetFileInformationByHandle(handle.Get(), &info) &&
        GetFileInformationByHandleEx(handle.Get(), FileIdInfo, &id, sizeof(id)),
        "raw evidence independent original identity");
    Fingerprint result;
    result.volume = info.dwVolumeSerialNumber;
    result.id_high = info.nFileIndexHigh; result.id_low = info.nFileIndexLow;
    std::memcpy(result.id.data(), id.FileId.Identifier, result.id.size());
    result.length = (std::uint64_t(info.nFileSizeHigh) << 32) | info.nFileSizeLow;
    result.creation = (std::uint64_t(info.ftCreationTime.dwHighDateTime) << 32) | info.ftCreationTime.dwLowDateTime;
    result.last_write = (std::uint64_t(info.ftLastWriteTime.dwHighDateTime) << 32) | info.ftLastWriteTime.dwLowDateTime;
    result.attributes = info.dwFileAttributes; result.links = info.nNumberOfLinks;
    if (content)
    {
        Expect(check, result.length <= NativeRawSnapshotStartupEvidence::SpoolIndexLimitBytes,
            "raw evidence independent byte capture bounded to small files");
        result.bytes.resize(static_cast<std::size_t>(result.length));
        DWORD done = 0;
        Expect(check, ReadFile(handle.Get(), result.bytes.data(), static_cast<DWORD>(result.bytes.size()), &done, nullptr) &&
            done == result.bytes.size(), "raw evidence independent complete bytes");
    }
    return result;
}

inline bool Empty(const RawSnapshotStartupEvidence& evidence)
{
    return !evidence.marker.present && !evidence.spool_index.present && !evidence.payload.present &&
        !evidence.marker.bytes_captured && !evidence.spool_index.bytes_captured && !evidence.payload.bytes_captured &&
        evidence.marker.bytes.empty() && evidence.spool_index.bytes.empty() && evidence.payload.bytes.empty() &&
        evidence.marker.identity.volume_serial == 0 && evidence.spool_index.identity.volume_serial == 0 &&
        evidence.payload.identity.volume_serial == 0;
}

inline bool ZeroReadWork(const NativeRawSnapshotStartupEvidence& fence)
{
    const auto work = fence.Reads();
    return work.buffer_bytes_requested == 0 && work.bytes_read == 0 && work.read_calls == 0;
}

inline void SharingRefused(CheckFunction check, const std::wstring& path, DWORD access, bool directory = false)
{
    TestHandle handle(CreateFileW(path.c_str(), access,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | (directory ? FILE_FLAG_BACKUP_SEMANTICS : 0), nullptr));
    const auto error = GetLastError();
    Expect(check, !handle.Valid() && error == ERROR_SHARING_VIOLATION,
        "original raw evidence lease denies competing write/delete access");
}

class Fixture
{
public:
    explicit Fixture(CheckFunction check) : check_(check)
    {
        static std::atomic<unsigned> sequence{0};
        for (unsigned attempt = 0; attempt < 16; ++attempt)
        {
            root = L"D:\\ApfsAccessScratch\\RawStartupFenceTests-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
                std::to_wstring(GetTickCount64()) + L"-" + std::to_wstring(++sequence);
            if (CreateDirectoryW(root.c_str(), nullptr)) { owned_ = true; return; }
            if (GetLastError() != ERROR_ALREADY_EXISTS) break;
        }
        Expect(check_, false, "create new private D: raw evidence fixture (D:\\ApfsAccessScratch must exist)");
    }
    ~Fixture()
    {
        // Only explicitly owned names are removed, including reparse links themselves.
        for (auto it = files.rbegin(); it != files.rend(); ++it) DeleteFileW(it->c_str());
        for (auto it = directories.rbegin(); it != directories.rend(); ++it) RemoveDirectoryW(it->c_str());
        if (owned_) RemoveDirectoryW(root.c_str());
    }
    Fixture(const Fixture&) = delete;
    Fixture& operator=(const Fixture&) = delete;

    std::wstring Directory(const std::wstring& name)
    {
        const auto path = root + L"\\" + name;
        Expect(check_, CreateDirectoryW(path.c_str(), nullptr) != FALSE, "create owned D: fixture directory");
        directories.push_back(path);
        return path;
    }
    RawSnapshotStartupEvidencePaths Paths(const std::wstring& name)
    {
        const auto parent = Directory(name);
        const auto spool = Directory(name + L"\\payload-spool");
        return {parent + L"\\recovery.marker", spool + L"\\payload-spool.idx", spool + L"\\payload-spool.bin"};
    }
    void Save(const std::wstring& path, const std::string& bytes)
    {
        TestHandle file(CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
        Expect(check_, file.Valid(), "create new owned D: evidence file");
        files.push_back(path);
        DWORD done = 0;
        Expect(check_, WriteFile(file.Get(), bytes.data(), static_cast<DWORD>(bytes.size()), &done, nullptr) &&
            done == bytes.size(), "write complete D: fixture bytes");
    }
    void Resize(const std::wstring& path, std::uint64_t length)
    {
        TestHandle file(CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr));
        Expect(check_, file.Valid(), "open owned D: size fixture");
        LARGE_INTEGER size{}; size.QuadPart = static_cast<LONGLONG>(length);
        Expect(check_, SetFilePointerEx(file.Get(), size, nullptr, FILE_BEGIN) && SetEndOfFile(file.Get()),
            "set owned D: fixture logical size");
    }
    bool Sparse(const std::wstring& path, std::uint64_t length)
    {
        Save(path, "");
        TestHandle file(CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr));
        Expect(check_, file.Valid(), "open owned D: sparse payload fixture");
        DWORD done = 0;
        if (!DeviceIoControl(file.Get(), FSCTL_SET_SPARSE, nullptr, 0, nullptr, 0, &done, nullptr))
        {
            const auto error = GetLastError();
            Expect(check_, error == ERROR_NOT_SUPPORTED || error == ERROR_INVALID_FUNCTION,
                "sparse payload support failure must be explicit");
            std::cout << "SKIP raw startup sparse 4 GiB boundary: Win32 " << error << "\n";
            return false;
        }
        LARGE_INTEGER size{}; size.QuadPart = static_cast<LONGLONG>(length);
        Expect(check_, SetFilePointerEx(file.Get(), size, nullptr, FILE_BEGIN) && SetEndOfFile(file.Get()),
            "set sparse payload logical size without filling it");
        return true;
    }
    void Seed(const RawSnapshotStartupEvidencePaths& paths)
    {
        Save(paths.marker, "dirty=0\nlastCommitXid=73\n");
        Save(paths.spool_index, std::string("opaque\0index\xff", 13));
        Save(paths.payload, "original payload bytes");
    }

    std::wstring root;
    std::vector<std::wstring> files, directories;
private:
    CheckFunction check_;
    bool owned_ = false;
};

inline void PresentEvidence(CheckFunction check, Fixture& fixture)
{
    const auto paths = fixture.Paths(L"present"); fixture.Seed(paths);
    const auto marker = Original(check, paths.marker), index = Original(check, paths.spool_index);
    const auto payload = Original(check, paths.payload);
    {
        NativeRawSnapshotStartupEvidence fence(paths, HostPayloadLimit);
        RawSnapshotStartupEvidence observed;
        Expect(check, fence.Ready() && fence.Verify(observed), std::string("hold original evidence: ") + fence.Failure());
        Expect(check, observed.marker.bytes_captured && observed.spool_index.bytes_captured &&
            observed.marker.bytes == marker.bytes && observed.spool_index.bytes == index.bytes &&
            observed.marker.identity.file_id == marker.id && observed.spool_index.identity.file_id == index.id &&
            observed.payload.identity.file_id == payload.id && observed.payload.identity.length == payload.length &&
            !observed.payload.bytes_captured && observed.payload.bytes.empty(),
            "original marker/index bytes and all file IDs with unread payload");
        const auto work = fence.Reads();
        Expect(check, work.bytes_read == marker.length + index.length &&
            work.buffer_bytes_requested == work.bytes_read && work.read_calls == 2,
            "only exact bounded marker/index bytes are read");
        for (const auto* path : {&paths.marker, &paths.spool_index, &paths.payload})
        {
            SharingRefused(check, *path, GENERIC_WRITE);
            SharingRefused(check, *path, DELETE);
            Expect(check, !DeleteFileW(path->c_str()), "held evidence file cannot be deleted");
        }
        const auto parent = fixture.root + L"\\present";
        SharingRefused(check, parent, DELETE, true);
        Expect(check, !MoveFileExW(parent.c_str(), (parent + L"-moved").c_str(), 0),
            "held original ancestor cannot be substituted by rename");
        fixture.Save(parent + L"\\unrelated", "neighbor");
        Expect(check, fence.Verify(observed) && fence.Verify() && fence.Reads().read_calls == work.read_calls,
            "bounded namespace rechecks tolerate ordinary siblings and do no content reads");
        Expect(check, Original(check, paths.marker) == marker && Original(check, paths.spool_index) == index &&
            Original(check, paths.payload) == payload, "all original bytes and identities unchanged while held");
        fence.Release(); fence.Release();
        Expect(check, !fence.Verify(observed) && Empty(observed), "released observation cannot publish cached output");
    }
    for (const auto* path : {&paths.marker, &paths.spool_index, &paths.payload})
    {
        TestHandle writer(CreateFileW(path->c_str(), GENERIC_WRITE | DELETE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr));
        Expect(check, writer.Valid(), "explicit release permits later admitted write/delete handle opens");
    }
    Expect(check, Original(check, paths.marker) == marker && Original(check, paths.spool_index) == index &&
        Original(check, paths.payload) == payload, "release preserves original bytes and file IDs");
    NativeRawSnapshotStartupEvidence attributes_only(paths, HostPayloadLimit, {false, false});
    RawSnapshotStartupEvidence observed;
    Expect(check, attributes_only.Ready() && attributes_only.Verify(observed) && ZeroReadWork(attributes_only) &&
        !observed.marker.bytes_captured && !observed.spool_index.bytes_captured &&
        observed.marker.present && observed.spool_index.present, "optional byte capture makes zero byte-buffer requests/reads");
    SharingRefused(check, paths.payload, GENERIC_WRITE);
}

inline void ExistingContention(CheckFunction check, Fixture& fixture)
{
    const auto paths = fixture.Paths(L"contention"); fixture.Seed(paths);
    const auto before = Original(check, paths.marker);
    for (const DWORD access : {DWORD(GENERIC_WRITE), DWORD(DELETE)})
    {
        TestHandle prior(CreateFileW(paths.marker.c_str(), access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr));
        Expect(check, prior.Valid(), "real preexisting evidence writer/delete handle");
        NativeRawSnapshotStartupEvidence refused(paths, HostPayloadLimit);
        RawSnapshotStartupEvidence output; output.marker.present = true; output.marker.bytes.push_back(std::byte{0x7f});
        Expect(check, !refused.Ready() && refused.Win32Error() == ERROR_SHARING_VIOLATION &&
            !refused.Verify(output) && Empty(output) && ZeroReadWork(refused),
            "constructor refuses preexisting writer/delete access with no bytes or partial output");
    }
    Expect(check, Original(check, paths.marker) == before, "contention refusal preserves original file and bytes");
}

inline void HeldMetadataChange(CheckFunction check, Fixture& fixture)
{
    const auto paths = fixture.Paths(L"metadata-change"); fixture.Seed(paths);
    const auto marker = Original(check, paths.marker), index = Original(check, paths.spool_index);
    const auto payload = Original(check, paths.payload);
    NativeRawSnapshotStartupEvidence fence(paths, HostPayloadLimit);
    RawSnapshotStartupEvidence output;
    Expect(check, fence.Ready() && fence.Verify(output), "original held metadata before external attribute update");
    {
        // Win32 attribute-only access is unaffected by data sharing flags.
        TestHandle metadata(CreateFileW(paths.marker.c_str(), FILE_WRITE_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr));
        Expect(check, metadata.Valid(), "real metadata-only handle while evidence is held");
        const auto changed = marker.last_write + 10000000;
        const FILETIME time{static_cast<DWORD>(changed), static_cast<DWORD>(changed >> 32)};
        Expect(check, SetFileTime(metadata.Get(), nullptr, nullptr, &time) != FALSE,
            "real timestamp update to held original evidence");
    }
    Expect(check, !fence.Verify(output) && Empty(output) && !fence.Ready() &&
        std::string_view(fence.Failure()) == "EndpointIdentityChanged",
        "held original metadata change refuses and discards previously populated output");
    SharingRefused(check, paths.marker, GENERIC_WRITE); SharingRefused(check, paths.marker, DELETE);
    const auto after = Original(check, paths.marker);
    Expect(check, after.bytes == marker.bytes && after.id == marker.id && after.length == marker.length &&
        after.last_write != marker.last_write && Original(check, paths.spool_index) == index &&
        Original(check, paths.payload) == payload, "metadata change test preserves all original bytes and file IDs");
}

inline void AbsenceAndNamespace(CheckFunction check, Fixture& fixture)
{
    const auto empty_parent = fixture.Directory(L"missing");
    const RawSnapshotStartupEvidencePaths missing{empty_parent + L"\\uncreated\\deep\\recovery.marker",
        empty_parent + L"\\uncreated\\payload-spool.idx", empty_parent + L"\\uncreated\\payload-spool.bin"};
    {
        NativeRawSnapshotStartupEvidence fence(missing, HostPayloadLimit);
        RawSnapshotStartupEvidence output;
        Expect(check, fence.Ready() && fence.Verify(output) && Empty(output) && ZeroReadWork(fence),
            "missing nested endpoints observed through their original existing ancestor");
        Expect(check, GetFileAttributesW((empty_parent + L"\\uncreated").c_str()) == INVALID_FILE_ATTRIBUTES,
            "observation and verification never create missing parents");
        SharingRefused(check, empty_parent, DELETE, true);
        fixture.Directory(L"missing\\uncreated");
        output.marker.present = true;
        Expect(check, !fence.Verify(output) && Empty(output) && !fence.Ready() &&
            std::string_view(fence.Failure()) == "MissingNamespaceChanged", "creation of an originally absent parent is detected");
        Expect(check, GetFileAttributesW(missing.marker.c_str()) == INVALID_FILE_ATTRIBUTES,
            "parent creation is refused even with endpoint still absent");
    }
    const auto paths = fixture.Paths(L"missing-file"); fixture.Save(paths.marker, "original marker");
    const auto marker = Original(check, paths.marker);
    {
        NativeRawSnapshotStartupEvidence fence(paths, HostPayloadLimit);
        RawSnapshotStartupEvidence output;
        Expect(check, fence.Ready() && fence.Verify(output) && output.marker.present &&
            !output.spool_index.present && !output.payload.present, "mixed present/absent original endpoints");
        fixture.Save(paths.payload, "newly appeared");
        Expect(check, !fence.Verify(output) && Empty(output) && !fence.Verify(),
            "new endpoint invalidates all output and subsequent verification");
        SharingRefused(check, paths.marker, GENERIC_WRITE);
        Expect(check, Original(check, paths.marker) == marker, "failed recheck retains original file pins and bytes");
    }
    const auto type_parent = fixture.Directory(L"missing-type");
    const RawSnapshotStartupEvidencePaths type_paths{type_parent + L"\\recovery.marker",
        type_parent + L"\\payload-spool.idx", type_parent + L"\\payload-spool.bin"};
    NativeRawSnapshotStartupEvidence type_fence(type_paths, HostPayloadLimit);
    Expect(check, type_fence.Ready(), "absent endpoint type fixture observed");
    fixture.Directory(L"missing-type\\recovery.marker");
    RawSnapshotStartupEvidence output;
    Expect(check, !type_fence.Verify(output) && Empty(output), "directory substituted for absent file is detected");
}

inline void MissingParentMaterialization(CheckFunction check, Fixture& fixture)
{
    const auto base = fixture.Directory(L"materialization");
    const auto common = base + L"\\new";
    const RawSnapshotStartupEvidencePaths first{common + L"\\markers\\first.marker",
        common + L"\\first\\payload-spool.idx", common + L"\\first\\payload-spool.bin"};
    const RawSnapshotStartupEvidencePaths second{common + L"\\markers\\second.marker",
        common + L"\\second\\payload-spool.idx", common + L"\\second\\payload-spool.bin"};
    {
        NativeRawSnapshotStartupEvidence a(first, HostPayloadLimit), b(second, HostPayloadLimit);
        Expect(check, a.Ready() && b.Ready() && ZeroReadWork(a) && ZeroReadWork(b),
            "two original missing evidence sets share a missing ancestor");
        std::array<NativeRawSnapshotStartupEvidence*, 2> guards{&a, &b};
        Expect(check, NativeRawSnapshotStartupEvidence::PrepareMissingParents(guards),
            "cohort creates only its missing directories relative to retained handles");
        fixture.directories.insert(fixture.directories.end(),
            {common, common + L"\\markers", common + L"\\first", common + L"\\second"});
        RawSnapshotStartupEvidence ea, eb;
        Expect(check, a.Verify(ea) && b.Verify(eb) && Empty(ea) && Empty(eb) && ZeroReadWork(a) && ZeroReadWork(b),
            "new pinned parents retain every original endpoint's absence and zero byte work");
        for (const auto& path : {common, common + L"\\markers", common + L"\\first", common + L"\\second"})
            SharingRefused(check, path, DELETE, true);
        const auto moved = base + L"\\moved";
        Expect(check, !MoveFileExW(common.c_str(), moved.c_str(), 0),
            "strict authority capture interval cannot replace a newly created ancestor");
        fixture.Save(first.payload, "new recovery evidence");
        Expect(check, !a.Verify(ea) && Empty(ea) && b.Verify(eb) && Empty(eb),
            "evidence appearing during later strict capture refuses that original session");
    }
    const auto prior = fixture.Directory(L"materialization-refusal");
    const auto appeared = prior + L"\\appeared";
    const RawSnapshotStartupEvidencePaths paths{appeared + L"\\deep\\recovery.marker",
        appeared + L"\\payload-spool.idx", appeared + L"\\payload-spool.bin"};
    NativeRawSnapshotStartupEvidence fence(paths, HostPayloadLimit);
    Expect(check, fence.Ready(), "original ancestor absence recorded before external creation");
    fixture.Directory(L"materialization-refusal\\appeared");
    const auto unrelated = appeared + L"\\unrelated";
    fixture.Save(unrelated, "preserve external evidence");
    const auto original = Original(check, unrelated);
    Expect(check, !fence.PrepareMissingParents() && !fence.Ready() &&
        GetFileAttributesW((appeared + L"\\deep").c_str()) == INVALID_FILE_ATTRIBUTES &&
        Original(check, unrelated) == original,
        "appeared ancestor never becomes trusted, receives no descendants, and preserves external bytes and identity");
}

inline void SizeRefusals(CheckFunction check, Fixture& fixture)
{
    for (const auto kind : {0, 1, 2})
    {
        const auto paths = fixture.Paths(L"size-" + std::to_wstring(kind)); fixture.Seed(paths);
        const auto& oversized = kind == 0 ? paths.marker : kind == 1 ? paths.spool_index : paths.payload;
        const auto length = kind == 0 ? NativeRawSnapshotStartupEvidence::MarkerLimitBytes + 1 :
            kind == 1 ? NativeRawSnapshotStartupEvidence::SpoolIndexLimitBytes + 1 : 65;
        fixture.Resize(oversized, length);
        const auto before = Original(check, oversized, false);
        NativeRawSnapshotStartupEvidence fence(paths, kind == 2 ? 64 : HostPayloadLimit);
        RawSnapshotStartupEvidence output; output.payload.present = true;
        Expect(check, !fence.Ready() && !fence.Verify(output) && Empty(output) && ZeroReadWork(fence) &&
            std::string_view(fence.Failure()) == "FileSizeLimitExceeded",
            "oversized marker/index/caller-bounded payload refused before any byte-buffer request or read");
        SharingRefused(check, oversized, GENERIC_WRITE);
        Expect(check, Original(check, oversized, false) == before, "size refusal preserves original oversized identity/length");
    }
    const auto exact = fixture.Paths(L"exact-limits"); fixture.Seed(exact);
    fixture.Resize(exact.marker, NativeRawSnapshotStartupEvidence::MarkerLimitBytes);
    fixture.Resize(exact.spool_index, NativeRawSnapshotStartupEvidence::SpoolIndexLimitBytes);
    {
        NativeRawSnapshotStartupEvidence fence(exact, HostPayloadLimit, {false, false});
        RawSnapshotStartupEvidence output;
        Expect(check, fence.Ready() && fence.Verify(output) && ZeroReadWork(fence), "marker/index exact size limits are inclusive");
    }
    {
        const auto marker = Original(check, exact.marker), index = Original(check, exact.spool_index);
        NativeRawSnapshotStartupEvidence fence(exact, HostPayloadLimit);
        RawSnapshotStartupEvidence output;
        Expect(check, fence.Ready() && fence.Verify(output) && output.marker.bytes == marker.bytes &&
            output.spool_index.bytes == index.bytes && fence.Reads().read_calls == 129 &&
            fence.Reads().bytes_read == marker.length + index.length,
            "maximum permitted byte reads finish within 129 fixed-size Win32 reads");
        Expect(check, Original(check, exact.marker) == marker && Original(check, exact.spool_index) == index,
            "maximum bounded reads preserve original complete bytes and file IDs");
    }
    const auto large = fixture.Paths(L"four-gib");
    fixture.Save(large.marker, "marker"); fixture.Save(large.spool_index, "index");
    if (fixture.Sparse(large.payload, HostPayloadLimit))
    {
        const auto before = Original(check, large.payload, false);
        {
            NativeRawSnapshotStartupEvidence fence(large, HostPayloadLimit);
            RawSnapshotStartupEvidence output;
            Expect(check, fence.Ready() && fence.Verify(output) && output.payload.identity.length == HostPayloadLimit &&
                output.payload.bytes.empty() && !output.payload.bytes_captured && fence.Reads().bytes_read == 11,
                "explicit 4 GiB payload cap accepts sparse payload with no payload allocation/read");
            Expect(check, Original(check, large.payload, false) == before, "large payload original identity and length retained");
        }
        fixture.Resize(large.payload, HostPayloadLimit + 1);
        NativeRawSnapshotStartupEvidence refused(large, HostPayloadLimit);
        Expect(check, !refused.Ready() && ZeroReadWork(refused), "4 GiB plus one payload refuses before all content work");
    }
}

inline void RuntimeMarkerOwnership(CheckFunction check, Fixture& fixture)
{
    const std::string clean = "dirty=0\nlastCommitXid=20\n";
    const std::string dirty = "dirty=1\nlastCommitXid=20\n";
    const auto clean_bytes = std::as_bytes(std::span(clean));
    const auto dirty_bytes = std::as_bytes(std::span(dirty));
    for (const bool present : {false, true})
    {
        const auto paths = fixture.Paths(present ? L"runtime-present" : L"runtime-absent");
        if (present) fixture.Save(paths.marker, clean);
        NativeRawSnapshotStartupEvidence fence(paths, HostPayloadLimit);
        Expect(check, fence.Ready() && fence.PrepareMissingParents(), "original runtime marker evidence and parents admitted");
        const auto prior = present ? Original(check, paths.marker) : Fingerprint{};
        Expect(check, fence.PromoteMarkerOwner(clean_bytes) && !fence.Ready() &&
            fence.OwnsMarkerPath(paths.marker) && fence.VerifyMarkerOwner(),
            "strict evidence hands off to its original persistent marker and parent owner");
        if (!present) fixture.files.push_back(paths.marker);
        const auto original = Original(check, paths.marker);
        Expect(check, original.bytes == std::vector<std::byte>(clean_bytes.begin(), clean_bytes.end()) &&
            (!present || original == prior), "new clean marker is flushed; existing original marker is untouched during handoff");
#ifdef APFSACCESS_FSHOST_UNIT_TEST
        if (present)
        {
            const auto attempts = fence.MarkerFlushAttemptsForTest();
            fence.ForceMarkerFlushFailureForTest(true);
            Expect(check, !fence.PersistOwnedMarker(clean_bytes) &&
                fence.MarkerFlushAttemptsForTest() == attempts + 1 && fence.VerifyMarkerOwner(),
                "first identical existing-marker persist must attempt flush and refuse its failure");
            fence.ForceMarkerFlushFailureForTest(false);
            Expect(check, fence.PersistOwnedMarker(clean_bytes) &&
                fence.MarkerFlushAttemptsForTest() == attempts + 2,
                "failed persistence never seeds cache and retry must flush successfully");
            Expect(check, fence.PersistOwnedMarker(clean_bytes) &&
                fence.MarkerFlushAttemptsForTest() == attempts + 2,
                "only this owner's flushed readback permits identical-write coalescing");
        }
#endif
        SharingRefused(check, paths.marker, GENERIC_WRITE);
        SharingRefused(check, paths.marker, DELETE);
        SharingRefused(check, paths.marker.substr(0, paths.marker.find_last_of(L'\\')), GENERIC_WRITE, true);
        SharingRefused(check, paths.marker.substr(0, paths.marker.find_last_of(L'\\')), DELETE, true);
        const auto replacement = paths.marker + L".replacement";
        fixture.Save(replacement, "unrelated destination must survive");
        const auto unrelated = Original(check, replacement);
        const auto before_substitution = Original(check, paths.marker);
        Expect(check, !MoveFileExW(replacement.c_str(), paths.marker.c_str(), MOVEFILE_REPLACE_EXISTING) &&
            Original(check, replacement) == unrelated && Original(check, paths.marker) == before_substitution,
            "competing leaf substitution cannot replace the owned marker or consume unrelated bytes");
        Expect(check, fence.PersistOwnedMarker(dirty_bytes) && fence.PersistOwnedMarker(clean_bytes) &&
            fence.VerifyMarkerOwner(), "dirty arming and clean completion flush/read back the same held file");
        const auto completed = Original(check, paths.marker);
        Expect(check, completed.id == original.id && completed.creation == original.creation &&
            completed.bytes == original.bytes, "completion preserves original marker file identity and exact clean bytes");
        Expect(check, !fence.PersistOwnedMarker({}) &&
            !fence.PersistOwnedMarker(std::vector<std::byte>(NativeRawSnapshotStartupEvidence::MarkerLimitBytes + 1)) &&
            Original(check, paths.marker) == completed, "empty or oversized marker writes refuse without changing original bytes");
        fence.Release();
        TestHandle writer(CreateFileW(paths.marker.c_str(), GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr));
        Expect(check, writer.Valid(), "normal teardown releases persistent marker ownership");
    }
    const auto paths = fixture.Paths(L"runtime-appeared");
    NativeRawSnapshotStartupEvidence fence(paths, HostPayloadLimit);
    Expect(check, fence.Ready() && fence.PrepareMissingParents(), "original absent runtime leaf recorded");
    fixture.Save(paths.marker, "external appeared marker");
    const auto appeared = Original(check, paths.marker);
    Expect(check, !fence.PromoteMarkerOwner(clean_bytes) && !fence.OwnsMarkerPath(paths.marker) &&
        Original(check, paths.marker) == appeared, "appeared marker cannot be adopted, overwritten or promoted");
}

inline bool UnsupportedLink(DWORD error)
{
    return error == ERROR_PRIVILEGE_NOT_HELD || error == ERROR_ACCESS_DENIED ||
        error == ERROR_NOT_SUPPORTED || error == ERROR_INVALID_FUNCTION;
}

inline bool Symlink(CheckFunction check, const std::wstring& link, const std::wstring& target, bool directory)
{
    const DWORD flags = directory ? SYMBOLIC_LINK_FLAG_DIRECTORY : 0;
    if (CreateSymbolicLinkW(link.c_str(), target.c_str(), flags | 0x2)) return true;
    auto error = GetLastError();
    if (error == ERROR_INVALID_PARAMETER)
    {
        if (CreateSymbolicLinkW(link.c_str(), target.c_str(), flags)) return true;
        error = GetLastError();
    }
    Expect(check, UnsupportedLink(error), "symbolic link setup failure must be a supported skip reason");
    std::cout << "SKIP raw startup symbolic link fixture: Win32 " << error << "\n";
    return false;
}

inline bool Junction(CheckFunction check, const std::wstring& link, const std::wstring& target)
{
    struct MountPointBuffer
    {
        DWORD tag;
        WORD data_length, reserved;
        WORD substitute_offset, substitute_length, print_offset, print_length;
        wchar_t path[1024];
    } data{};
    const auto substitute = L"\\??\\" + target;
    const auto total = substitute.size() + 1 + target.size() + 1;
    Expect(check, total <= 1024, "bounded D: junction fixture buffer");
    data.tag = IO_REPARSE_TAG_MOUNT_POINT;
    data.substitute_length = static_cast<WORD>(substitute.size() * sizeof(wchar_t));
    data.print_offset = static_cast<WORD>((substitute.size() + 1) * sizeof(wchar_t));
    data.print_length = static_cast<WORD>(target.size() * sizeof(wchar_t));
    data.data_length = static_cast<WORD>(8 + total * sizeof(wchar_t));
    std::memcpy(data.path, substitute.data(), data.substitute_length);
    std::memcpy(data.path + substitute.size() + 1, target.data(), data.print_length);
    TestHandle handle(CreateFileW(link.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr));
    Expect(check, handle.Valid(), "open owned D: junction directory");
    DWORD done = 0;
    if (DeviceIoControl(handle.Get(), FSCTL_SET_REPARSE_POINT, &data, 8 + data.data_length, nullptr, 0, &done, nullptr))
        return true;
    const auto error = GetLastError();
    Expect(check, UnsupportedLink(error), "junction setup failure must be a supported skip reason");
    std::cout << "SKIP raw startup junction fixture: Win32 " << error << "\n";
    return false;
}

inline void LinkRefusals(CheckFunction check, Fixture& fixture)
{
    const auto paths = fixture.Paths(L"link-target"); fixture.Seed(paths);
    const auto original = Original(check, paths.marker);
    const auto file_link = fixture.root + L"\\symbolic.marker";
    if (Symlink(check, file_link, paths.marker, false))
    {
        fixture.files.push_back(file_link);
        auto linked = paths; linked.marker = file_link;
        NativeRawSnapshotStartupEvidence fence(linked, HostPayloadLimit);
        RawSnapshotStartupEvidence output;
        Expect(check, !fence.Ready() && !fence.Verify(output) && Empty(output) && ZeroReadWork(fence),
            "file symbolic link refused without target byte reads");
        linked = paths; linked.payload = file_link;
        NativeRawSnapshotStartupEvidence payload_link(linked, HostPayloadLimit);
        Expect(check, !payload_link.Ready() && ZeroReadWork(payload_link), "payload symbolic link refused too");
    }
    const auto target_parent = fixture.root + L"\\link-target";
    const auto parent_link = fixture.root + L"\\symbolic-parent";
    if (Symlink(check, parent_link, target_parent, true))
    {
        fixture.directories.push_back(parent_link);
        auto linked = paths; linked.marker = parent_link + L"\\recovery.marker";
        NativeRawSnapshotStartupEvidence fence(linked, HostPayloadLimit);
        Expect(check, !fence.Ready() && ZeroReadWork(fence), "symbolic ancestor refused before following it");
    }
    const auto junction = fixture.Directory(L"junction-parent");
    if (Junction(check, junction, target_parent))
    {
        auto linked = paths; linked.marker = junction + L"\\recovery.marker";
        NativeRawSnapshotStartupEvidence fence(linked, HostPayloadLimit);
        Expect(check, !fence.Ready() && ZeroReadWork(fence), "junction ancestor refused before following it");
    }
    Expect(check, Original(check, paths.marker) == original, "all reparse refusals preserve target bytes and file ID");
    const auto alias = fixture.root + L"\\hard.marker";
    if (CreateHardLinkW(alias.c_str(), paths.marker.c_str(), nullptr))
    {
        fixture.files.push_back(alias);
        const auto linked_original = Original(check, paths.marker);
        NativeRawSnapshotStartupEvidence fence(paths, HostPayloadLimit);
        RawSnapshotStartupEvidence output;
        Expect(check, linked_original.links == 2 && !fence.Ready() && !fence.Verify(output) && Empty(output) &&
            ZeroReadWork(fence), "original endpoint with another hard link refused");
        Expect(check, Original(check, paths.marker) == linked_original, "hardlink refusal preserves existing names/bytes/IDs");
    }
    else
    {
        const auto error = GetLastError();
        Expect(check, error == ERROR_NOT_SUPPORTED || error == ERROR_INVALID_FUNCTION, "hardlink setup failure is filesystem support only");
        std::cout << "SKIP raw startup hardlink fixture: Win32 " << error << "\n";
    }
}

inline void PathRefusals(CheckFunction check, Fixture& fixture)
{
    const auto paths = fixture.Paths(L"path-refusals"); fixture.Seed(paths);
    const auto before = Original(check, paths.marker);
    std::wstring embedded_null = paths.marker; embedded_null.push_back(L'\0'); embedded_null += L"suffix";
    auto deep = fixture.root;
    for (unsigned i = 0; i < 65; ++i) deep += L"\\absent";
    deep += L"\\recovery.marker";
    for (const auto& invalid : std::vector<std::wstring>{L"relative", L"D:relative", L"\\\\server\\share\\marker",
        L"\\\\.\\PhysicalDrive0", L"\\\\?\\D:\\marker", L"D:\\NUL", L"D:\\COM1.txt", L"D:\\file:stream",
        paths.marker + L".", paths.marker + L" ", paths.marker + L"\\", L"D:/marker", embedded_null,
        fixture.root + L"\\..\\marker", deep, L"D:\\" + std::wstring(4096, L'a')})
    {
        auto bad = paths; bad.marker = invalid;
        NativeRawSnapshotStartupEvidence fence(bad, HostPayloadLimit);
        RawSnapshotStartupEvidence output; output.marker.present = true;
        Expect(check, !fence.Ready() && !fence.Verify(output) && Empty(output) && ZeroReadWork(fence),
            "noncanonical/device/network/over-depth paths fail without content work");
    }
    auto duplicate = paths; duplicate.spool_index = duplicate.marker;
    NativeRawSnapshotStartupEvidence fence(duplicate, HostPayloadLimit);
    Expect(check, !fence.Ready() && ZeroReadWork(fence), "duplicate endpoint role is refused");
    Expect(check, Original(check, paths.marker) == before, "path refusals preserve original evidence");
}

} // namespace raw_startup_evidence_detail

inline bool RunRawSnapshotStartupEvidenceTests(
    raw_startup_evidence_detail::CheckFunction check = ::Check)
{
    using namespace raw_startup_evidence_detail;
    Fixture fixture(check);
    PresentEvidence(check, fixture);
    ExistingContention(check, fixture);
    HeldMetadataChange(check, fixture);
    AbsenceAndNamespace(check, fixture);
    MissingParentMaterialization(check, fixture);
    RuntimeMarkerOwnership(check, fixture);
    SizeRefusals(check, fixture);
    LinkRefusals(check, fixture);
    PathRefusals(check, fixture);
    return true;
}

} // namespace apfsaccess::fshost::tests
