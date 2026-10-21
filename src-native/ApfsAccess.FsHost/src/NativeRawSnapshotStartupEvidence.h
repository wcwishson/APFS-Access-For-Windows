#pragma once

#include <windows.h>
#include <winternl.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <span>
#include <utility>
#include <vector>

namespace apfsaccess::fshost {

struct RawSnapshotStartupEvidencePaths
{
    std::wstring marker;
    std::wstring spool_index;
    std::wstring payload;
};

struct RawSnapshotStartupEvidenceByteReads
{
    bool marker = true;
    bool spool_index = true;
};

struct RawSnapshotStartupFileIdentity
{
    std::uint64_t volume_serial = 0;
    std::array<unsigned char, 16> file_id{};
    std::uint64_t length = 0;
    std::int64_t creation_time = 0;
    std::int64_t last_write_time = 0;
    std::int64_t change_time = 0;
    DWORD attributes = 0;
    DWORD links = 0;
};

struct RawSnapshotStartupFileEvidence
{
    bool present = false;
    bool bytes_captured = false;
    RawSnapshotStartupFileIdentity identity;
    std::vector<std::byte> bytes;
};

struct RawSnapshotStartupEvidence
{
    RawSnapshotStartupFileEvidence marker;
    RawSnapshotStartupFileEvidence spool_index;
    RawSnapshotStartupFileEvidence payload;
};

// This is a retained filesystem observation. The host owns cohort admission,
// receipt validation and the decision to release these handles before writes.
class NativeRawSnapshotStartupEvidence final
{
public:
    static constexpr std::uint64_t MarkerLimitBytes = 4096;
    static constexpr std::uint64_t SpoolIndexLimitBytes = 8ull * 1024 * 1024;
    static constexpr std::size_t MaxPathCharacters = 4096;
    static constexpr std::size_t MaxPathComponents = 64;

    struct ReadWork
    {
        std::uint64_t buffer_bytes_requested = 0;
        std::uint64_t bytes_read = 0;
        std::uint32_t read_calls = 0;
    };

    // The payload cap is mandatory and comes from the caller's spool policy.
    explicit NativeRawSnapshotStartupEvidence(
        const RawSnapshotStartupEvidencePaths& paths,
        std::uint64_t max_payload_bytes,
        RawSnapshotStartupEvidenceByteReads reads = {}) noexcept
    {
        try
        {
            for (const auto* path : {&paths.marker, &paths.spool_index, &paths.payload})
                if (path->size() < 4 || path->size() > MaxPathCharacters)
                { Fail("NonCanonicalLocalPath"); return; }
            endpoints_[0].path = paths.marker;
            endpoints_[1].path = paths.spool_index;
            endpoints_[2].path = paths.payload;
            for (auto& endpoint : endpoints_)
                if (!BuildPrefixes(endpoint)) return;
            for (std::size_t i = 0; i < endpoints_.size(); ++i)
                for (std::size_t j = 0; j < i; ++j)
                    if (SamePath(endpoints_[i].path, endpoints_[j].path))
                    { Fail("DuplicateEndpoints"); return; }
            for (std::size_t i = 0; i < endpoints_.size(); ++i)
                if (!Observe(endpoints_[i], File(evidence_, i))) return;

            const std::array<std::uint64_t, 3> limits{
                MarkerLimitBytes, SpoolIndexLimitBytes, max_payload_bytes};
            // Check the entire set before requesting any evidence byte buffer.
            for (std::size_t i = 0; i < limits.size(); ++i)
                if (File(evidence_, i).present && File(evidence_, i).identity.length > limits[i])
                { Fail("FileSizeLimitExceeded"); return; }
            if (reads.marker && !ReadBytes(endpoints_[0], evidence_.marker)) return;
            if (reads.spool_index && !ReadBytes(endpoints_[1], evidence_.spool_index)) return;
            if (!Recheck()) return;
            ready_ = true;
            failure_ = nullptr;
        }
        catch (...) { Fail("EvidenceException"); }
    }

    ~NativeRawSnapshotStartupEvidence() noexcept { Release(); }
    NativeRawSnapshotStartupEvidence(const NativeRawSnapshotStartupEvidence&) = delete;
    NativeRawSnapshotStartupEvidence& operator=(const NativeRawSnapshotStartupEvidence&) = delete;
    NativeRawSnapshotStartupEvidence(NativeRawSnapshotStartupEvidence&&) = delete;
    NativeRawSnapshotStartupEvidence& operator=(NativeRawSnapshotStartupEvidence&&) = delete;

    bool Ready() const noexcept { return ready_; }
    const char* Failure() const noexcept { return failure_ ? failure_ : ""; }
    DWORD Win32Error() const noexcept { return win32_error_; }
    ReadWork Reads() const noexcept { return reads_; }

    // A refusal is sticky and retains the original pins until Release/destruction.
    bool Verify() noexcept
    {
        if (!ready_) return false;
        try { return Recheck(); }
        catch (...) { return Fail("EvidenceException"); }
    }

    // The output is always empty on refusal, including copy/allocation failure.
    bool Verify(RawSnapshotStartupEvidence& output) noexcept
    {
        output = {};
        if (!Verify()) return false;
        try
        {
            auto candidate = evidence_;
            if (!Recheck()) return false;
            output = std::move(candidate);
            return true;
        }
        catch (...) { return Fail("EvidenceException"); }
    }

    // Only the host's admitted cohort may request this transition. Create each
    // missing directory relative to its held parent and retain the new handle.
    // A preexisting component never substitutes for a directory we created.
    bool PrepareMissingParents() noexcept
    {
        NativeRawSnapshotStartupEvidence* guard = this;
        return PrepareMissingParents(std::span{&guard, std::size_t{1}});
    }

    static bool PrepareMissingParents(std::span<NativeRawSnapshotStartupEvidence*> guards) noexcept
    {
        if (guards.empty() || guards.size() > 100) return false;
        for (auto* guard : guards) if (!guard || !guard->Verify()) return false;
        try
        {
            struct CreatedParent { std::wstring path; RawSnapshotStartupFileIdentity identity; };
            std::vector<CreatedParent> created;
            for (auto* guard : guards)
            for (auto& endpoint : guard->endpoints_)
            {
                while (endpoint.parents.size() + 1 < endpoint.prefixes.size())
                {
                    const auto index = endpoint.parents.size();
                    const auto& path = endpoint.prefixes[index];
                    const auto known = std::find_if(created.begin(), created.end(),
                        [&](const auto& parent) { return SamePath(parent.path, path); });
                    auto handle = known == created.end()
                        ? CreateDirectoryRelative(endpoint.parents.back().handle.Get(),
                            path.substr(path.find_last_of(L'\\') + 1))
                        : Open(path);
                    RawSnapshotStartupFileIdentity identity;
                    if (!handle || !guard->Identity(handle.Get(), true, identity) || !guard->AtExpectedPath(endpoint, index, handle.Get()))
                        return guard->Fail("MissingParentCreationRefused", GetLastError());
                    if (known != created.end() && !SameIdentity(known->identity, identity, true))
                        return guard->Fail("CreatedParentChanged");
                    if (known == created.end()) created.push_back({path, identity});
                    endpoint.parents.push_back({std::move(handle), identity});
                    endpoint.first_missing = endpoint.parents.size();
                }
            }
            for (auto* guard : guards) if (!guard->Recheck()) return false;
            return true;
        }
        catch (...)
        {
            for (auto* guard : guards) guard->Fail("ParentCreationException");
            return false;
        }
    }

    // Handoff after strict cohort admission. Keep every original parent pinned
    // and exclude other writers/deleters from the marker for this owner's life.
    bool PromoteMarkerOwner(std::span<const std::byte> initial_missing_marker) noexcept
    {
        if (!Verify() || initial_missing_marker.empty() || initial_missing_marker.size() > MarkerLimitBytes)
            return false;
        try
        {
            auto& marker = endpoints_[0];
            const auto original = evidence_.marker;
            if (marker.parents.size() + 1 != marker.prefixes.size() ||
                (original.present && !original.bytes_captured)) return Fail("MarkerHandoffEvidenceRequired");
            marker.file.Reset();
            marker.file = OpenMarkerRelative(marker.parents.back().handle.Get(),
                marker.path.substr(marker.prefixes[marker.parents.size() - 1].size()), original.present);
            if (!marker.file) return Fail("MarkerHandoffOpenFailed", GetLastError());
            RawSnapshotStartupFileIdentity identity;
            if (!Identity(marker.file.Get(), false, identity) ||
                !AtExpectedPath(marker, marker.prefixes.size() - 1, marker.file.Get()) ||
                (original.present && !SameIdentity(identity, original.identity, false)) ||
                (!original.present && identity.length)) return Fail("MarkerHandoffIdentityChanged");
            std::vector<std::byte> actual;
            if (!ReadMarker(marker.file.Get(), identity.length, actual) ||
                (original.present && actual != original.bytes)) return Fail("MarkerHandoffBytesChanged");
            marker_identity_ = identity;
            // Observed startup bytes do not prove this owner has flushed them.
            marker_bytes_.clear();
            marker_owned_ = true;
            ready_ = false;
            for (std::size_t i = 1; i < endpoints_.size(); ++i) endpoints_[i].file.Reset();
            evidence_ = {};
            if (!VerifyMarkerOwner()) return false;
            if (!original.present && !PersistOwnedMarker(initial_missing_marker)) return false;
            failure_ = nullptr;
            return true;
        }
        catch (...) { return Fail("MarkerHandoffException"); }
    }

    bool OwnsMarkerPath(std::wstring_view path) const noexcept
    {
        return marker_owned_ && SamePath(path, endpoints_[0].path);
    }

    // Only after admitted marker handoff: allow spool leaf replacement while
    // retaining data-read handles that still exclude ancestor rename/deletion.
    bool PromoteMutableSpoolParents() noexcept
    {
        if (ready_ || !marker_owned_ || !VerifyMarkerOwner()) return false;
        try
        {
            std::array<std::vector<Parent>, 3> replacements;
            for (std::size_t e = 0; e < endpoints_.size(); ++e)
            {
                const auto& endpoint = endpoints_[e];
                replacements[e].reserve(endpoint.parents.size());
                for (std::size_t i = 0; i < endpoint.parents.size(); ++i)
                {
                    const auto path = L"\\\\?\\" + endpoint.prefixes[i];
                    Handle handle(CreateFileW(path.c_str(), GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
                    RawSnapshotStartupFileIdentity identity;
                    if (!handle || !Identity(handle.Get(), true, identity) ||
                        !SameIdentity(endpoint.parents[i].identity, identity, true) ||
                        !AtExpectedPath(endpoint, i, handle.Get()))
                        return Fail("MutableSpoolParentHandoffRefused", GetLastError());
                    replacements[e].push_back({std::move(handle), identity});
                }
            }
            if (!VerifyMarkerOwner()) return false;
            // Old pins remain in replacements until every new pin and the
            // unchanged exclusive marker have passed the final recheck.
            for (std::size_t e = 0; e < endpoints_.size(); ++e)
                endpoints_[e].parents.swap(replacements[e]);
            return VerifyMarkerOwner();
        }
        catch (...) { return Fail("MutableSpoolParentHandoffException"); }
    }

    bool VerifyMarkerOwner() noexcept
    {
        if (!marker_owned_) return false;
        try
        {
            for (const auto& endpoint : endpoints_)
            {
                std::wstring target;
                if (!CheckLocalDrive(endpoint, target) || target != endpoint.drive_target)
                    return Fail("MarkerOwnerDriveChanged");
                if (endpoint.parents.size() + 1 != endpoint.prefixes.size())
                    return Fail("MarkerOwnerParentsMissing");
                for (std::size_t i = 0; i < endpoint.parents.size(); ++i)
                    if (!RecheckOne(endpoint, i, endpoint.parents[i].handle.Get(), endpoint.parents[i].identity, true))
                        return false;
            }
            const auto& marker = endpoints_[0];
            RawSnapshotStartupFileIdentity current;
            if (!Identity(marker.file.Get(), false, current) || current.length > MarkerLimitBytes ||
                !AtExpectedPath(marker, marker.prefixes.size() - 1, marker.file.Get()) ||
                !SameIdentity(current, marker_identity_, true)) return Fail("MarkerOwnerIdentityChanged");
            return true;
        }
        catch (...) { return Fail("MarkerOwnerException"); }
    }

    bool PersistOwnedMarker(std::span<const std::byte> bytes) noexcept
    {
        if (bytes.empty() || bytes.size() > MarkerLimitBytes || !VerifyMarkerOwner()) return false;
        if (std::equal(bytes.begin(), bytes.end(), marker_bytes_.begin(), marker_bytes_.end())) return true;
        const auto handle = endpoints_[0].file.Get();
        LARGE_INTEGER zero{};
        DWORD written = 0;
        // Startup also authenticates the WAL/source if interrupted bytes parse.
        // Accepted WAL debt is retained until this write, flush and readback pass.
        if (!SetFilePointerEx(handle, zero, nullptr, FILE_BEGIN) ||
            !WriteFile(handle, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr) ||
            written != bytes.size() || !SetEndOfFile(handle) || !FlushMarker(handle))
        { marker_bytes_.clear(); failure_ = "MarkerOwnerWriteFailed"; win32_error_ = GetLastError(); return false; }
        try
        {
            std::vector<std::byte> actual;
            if (!ReadMarker(handle, bytes.size(), actual) ||
                !std::equal(bytes.begin(), bytes.end(), actual.begin(), actual.end()) || !VerifyMarkerOwner())
                return Fail("MarkerOwnerReadbackFailed");
            marker_bytes_ = std::move(actual);
            failure_ = nullptr;
            win32_error_ = ERROR_SUCCESS;
            return true;
        }
        catch (...) { return Fail("MarkerOwnerReadbackException"); }
    }

#ifdef APFSACCESS_FSHOST_UNIT_TEST
    void ForceMarkerFlushFailureForTest(bool fail) noexcept { test_marker_flush_failure_ = fail; }
    std::uint64_t MarkerFlushAttemptsForTest() const noexcept { return test_marker_flush_attempts_; }
#endif

    void Release() noexcept
    {
        ready_ = false;
        marker_owned_ = false;
        marker_bytes_.clear();
        evidence_ = {};
        for (auto& endpoint : endpoints_)
        {
            endpoint.file.Reset();
            for (auto it = endpoint.parents.rbegin(); it != endpoint.parents.rend(); ++it)
                it->handle.Reset();
            endpoint.parents.clear();
        }
        failure_ = "EvidenceReleased";
        win32_error_ = ERROR_SUCCESS;
    }

private:
    bool FlushMarker(HANDLE handle) noexcept
    {
#ifdef APFSACCESS_FSHOST_UNIT_TEST
        ++test_marker_flush_attempts_;
        if (test_marker_flush_failure_) { SetLastError(ERROR_WRITE_FAULT); return false; }
#endif
        return FlushFileBuffers(handle) != FALSE;
    }
#ifdef APFSACCESS_FSHOST_UNIT_TEST
    bool test_marker_flush_failure_ = false;
    std::uint64_t test_marker_flush_attempts_ = 0;
#endif
    class Handle
    {
    public:
        Handle() noexcept = default;
        explicit Handle(HANDLE value) noexcept : value_(value) {}
        ~Handle() noexcept { Reset(); }
        Handle(const Handle&) = delete;
        Handle& operator=(const Handle&) = delete;
        Handle(Handle&& other) noexcept : value_(other.value_) { other.value_ = INVALID_HANDLE_VALUE; }
        Handle& operator=(Handle&& other) noexcept
        {
            if (this != &other) { Reset(); value_ = other.value_; other.value_ = INVALID_HANDLE_VALUE; }
            return *this;
        }
        explicit operator bool() const noexcept { return value_ != INVALID_HANDLE_VALUE; }
        HANDLE Get() const noexcept { return value_; }
        void Reset() noexcept
        {
            if (value_ != INVALID_HANDLE_VALUE) CloseHandle(value_);
            value_ = INVALID_HANDLE_VALUE;
        }
    private:
        HANDLE value_ = INVALID_HANDLE_VALUE;
    };

    struct Parent
    {
        Handle handle;
        RawSnapshotStartupFileIdentity identity;
    };

    struct Endpoint
    {
        std::wstring path;
        std::vector<std::wstring> prefixes;
        std::wstring volume_root;
        std::wstring drive_target;
        std::vector<Parent> parents;
        Handle file;
        std::size_t first_missing = 0;
    };

    static RawSnapshotStartupFileEvidence& File(RawSnapshotStartupEvidence& evidence, std::size_t i) noexcept
    {
        return i == 0 ? evidence.marker : i == 1 ? evidence.spool_index : evidence.payload;
    }

    bool Fail(const char* reason, DWORD error = ERROR_SUCCESS) noexcept
    {
        ready_ = false;
        marker_owned_ = false;
        evidence_ = {};
        failure_ = reason;
        win32_error_ = error;
        return false;
    }

    static bool SamePath(std::wstring_view left, std::wstring_view right) noexcept
    {
        return left.size() == right.size() &&
            CompareStringOrdinal(left.data(), static_cast<int>(left.size()),
                right.data(), static_cast<int>(right.size()), TRUE) == CSTR_EQUAL;
    }

    static bool ReservedComponent(std::wstring_view component) noexcept
    {
        auto stem = component.substr(0, component.find(L'.'));
        while (!stem.empty() && stem.back() == L' ') stem.remove_suffix(1);
        for (const auto name : {L"CON", L"PRN", L"AUX", L"NUL", L"CONIN$", L"CONOUT$"})
            if (SamePath(stem, name)) return true;
        if (stem.size() == 4 && (SamePath(stem.substr(0, 3), L"COM") || SamePath(stem.substr(0, 3), L"LPT")))
        {
            const auto n = stem[3];
            return (n >= L'1' && n <= L'9') || n == 0x00b9 || n == 0x00b2 || n == 0x00b3;
        }
        return false;
    }

    bool BuildPrefixes(Endpoint& endpoint)
    {
        const auto& path = endpoint.path;
        if (path.size() < 4 || path.size() > MaxPathCharacters || path[1] != L':' || path[2] != L'\\' ||
            !((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')))
            return Fail("NonCanonicalLocalPath");
        endpoint.prefixes.push_back(path.substr(0, 3));
        std::size_t begin = 3;
        while (begin < path.size())
        {
            const auto separator = path.find(L'\\', begin);
            const auto end = separator == std::wstring::npos ? path.size() : separator;
            const auto component = std::wstring_view(path).substr(begin, end - begin);
            if (component.empty() || component.size() > 255 || component == L"." || component == L".." ||
                component.back() == L'.' || component.back() == L' ' || ReservedComponent(component))
                return Fail("NonCanonicalLocalPath");
            for (const auto ch : component)
                if (ch < 32 || ch == L'/' || ch == L':' || ch == L'"' || ch == L'<' || ch == L'>' ||
                    ch == L'|' || ch == L'*' || ch == L'?') return Fail("NonCanonicalLocalPath");
            if (endpoint.prefixes.size() > MaxPathComponents) return Fail("PathDepthLimitExceeded");
            endpoint.prefixes.push_back(path.substr(0, end));
            if (separator == std::wstring::npos) break;
            begin = end + 1;
            if (begin == path.size()) return Fail("NonCanonicalLocalPath");
        }
        return true;
    }

    bool CheckLocalDrive(const Endpoint& endpoint, std::wstring& target)
    {
        const auto root = endpoint.path.substr(0, 3);
        const auto type = GetDriveTypeW(root.c_str());
        if (type != DRIVE_FIXED && type != DRIVE_REMOVABLE) return Fail("NonLocalDrive");
        std::array<wchar_t, MaxPathCharacters + 1> buffer{};
        const auto drive = endpoint.path.substr(0, 2);
        const DWORD count = QueryDosDeviceW(drive.c_str(), buffer.data(), static_cast<DWORD>(buffer.size()));
        if (!count || count >= buffer.size()) return Fail("DriveMappingUnavailable", GetLastError());
        std::size_t length = 0;
        while (length < count && buffer[length]) ++length;
        const std::wstring_view name(buffer.data(), length);
        constexpr std::wstring_view prefix = L"\\Device\\HarddiskVolume";
        if (length == count || name.size() <= prefix.size() || name.substr(0, prefix.size()) != prefix)
            return Fail("NonLocalDriveMapping");
        for (const auto ch : name.substr(prefix.size()))
            if (ch < L'0' || ch > L'9') return Fail("NonLocalDriveMapping");
        // QueryDosDevice may include historical mappings. Only its first entry is current.
        target.assign(name);
        return true;
    }

    static Handle Open(const std::wstring& path)
    {
        const auto extended = L"\\\\?\\" + path;
        // Data-read access participates in Win32 sharing, including for directories
        // and the unread payload. Attributes-only handles would not enforce the fence.
        return Handle(CreateFileW(extended.c_str(), GENERIC_READ,
            FILE_SHARE_READ, nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    }

    static Handle CreateDirectoryRelative(HANDLE parent, std::wstring name)
    {
        using Create = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
            PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
        const auto create = reinterpret_cast<Create>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateFile"));
        if (!create || name.empty() || name.size() > 255) return {};
        UNICODE_STRING relative{};
        relative.Buffer = name.data();
        relative.Length = static_cast<USHORT>(name.size() * sizeof(wchar_t));
        relative.MaximumLength = relative.Length;
        OBJECT_ATTRIBUTES attributes{};
        attributes.Length = sizeof(attributes);
        attributes.RootDirectory = parent;
        attributes.ObjectName = &relative;
        attributes.Attributes = 0x40; // OBJ_CASE_INSENSITIVE
        IO_STATUS_BLOCK status{};
        HANDLE handle = INVALID_HANDLE_VALUE;
        constexpr ULONG create_new = 2; // FILE_CREATE
        constexpr ULONG directory_options = 0x1 | 0x20 | 0x200000;
        const auto result = create(&handle, GENERIC_READ | SYNCHRONIZE, &attributes, &status,
            nullptr, FILE_ATTRIBUTE_DIRECTORY, FILE_SHARE_READ, create_new, directory_options, nullptr, 0);
        if (result < 0)
        {
            if (handle != INVALID_HANDLE_VALUE && handle) CloseHandle(handle);
            SetLastError(ERROR_CANNOT_MAKE);
            return {};
        }
        return Handle(handle);
    }

    static Handle OpenMarkerRelative(HANDLE parent, std::wstring name, bool present)
    {
        using Create = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
            PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
        const auto create = reinterpret_cast<Create>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateFile"));
        if (!create) return {};
        if (!name.empty() && name.front() == L'\\') name.erase(0, 1);
        if (name.empty() || name.size() > 255 || name.find(L'\\') != std::wstring::npos) return {};
        UNICODE_STRING relative{};
        relative.Buffer = name.data();
        relative.Length = static_cast<USHORT>(name.size() * sizeof(wchar_t));
        relative.MaximumLength = relative.Length;
        OBJECT_ATTRIBUTES attributes{};
        attributes.Length = sizeof(attributes);
        attributes.RootDirectory = parent;
        attributes.ObjectName = &relative;
        attributes.Attributes = 0x40;
        IO_STATUS_BLOCK status{};
        HANDLE handle = INVALID_HANDLE_VALUE;
        const auto result = create(&handle, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &attributes, &status,
            nullptr, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, present ? 1 : 2,
            0x40 | 0x20 | 0x200000 | 0x2, nullptr, 0);
        if (result < 0)
        {
            if (handle != INVALID_HANDLE_VALUE && handle) CloseHandle(handle);
            SetLastError(ERROR_CANNOT_MAKE);
            return {};
        }
        return Handle(handle);
    }

    static bool ReadMarker(HANDLE handle, std::uint64_t length, std::vector<std::byte>& bytes)
    {
        if (length > MarkerLimitBytes) return false;
        LARGE_INTEGER zero{};
        if (!SetFilePointerEx(handle, zero, nullptr, FILE_BEGIN)) return false;
        bytes.resize(static_cast<std::size_t>(length));
        DWORD read = 0;
        return bytes.empty() || (ReadFile(handle, bytes.data(), static_cast<DWORD>(bytes.size()), &read, nullptr) && read == bytes.size());
    }

    bool Identity(HANDLE handle, bool directory, RawSnapshotStartupFileIdentity& output)
    {
        FILE_ID_INFO id{};
        FILE_BASIC_INFO basic{};
        FILE_STANDARD_INFO standard{};
        FILE_ATTRIBUTE_TAG_INFO tag{};
        if (GetFileType(handle) != FILE_TYPE_DISK) return Fail("NonDiskEndpoint");
        if (!GetFileInformationByHandleEx(handle, FileIdInfo, &id, sizeof(id)) ||
            !GetFileInformationByHandleEx(handle, FileBasicInfo, &basic, sizeof(basic)) ||
            !GetFileInformationByHandleEx(handle, FileStandardInfo, &standard, sizeof(standard)) ||
            !GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &tag, sizeof(tag)))
            return Fail("FileIdentityUnavailable", GetLastError());
        if (standard.DeletePending || standard.EndOfFile.QuadPart < 0 ||
            bool(standard.Directory) != directory || bool(basic.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != directory ||
            (basic.FileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DEVICE)) ||
            (tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) || tag.ReparseTag ||
            (!directory && standard.NumberOfLinks != 1)) return Fail("UnsafeEndpoint");
        output.volume_serial = id.VolumeSerialNumber;
        std::memcpy(output.file_id.data(), id.FileId.Identifier, output.file_id.size());
        output.length = static_cast<std::uint64_t>(standard.EndOfFile.QuadPart);
        output.creation_time = basic.CreationTime.QuadPart;
        output.last_write_time = basic.LastWriteTime.QuadPart;
        output.change_time = basic.ChangeTime.QuadPart;
        output.attributes = basic.FileAttributes;
        output.links = standard.NumberOfLinks;
        return true;
    }

    bool FinalPath(HANDLE handle, std::wstring& output)
    {
        std::array<wchar_t, MaxPathCharacters + 64> buffer{};
        const DWORD count = GetFinalPathNameByHandleW(handle, buffer.data(),
            static_cast<DWORD>(buffer.size()), FILE_NAME_NORMALIZED | VOLUME_NAME_GUID);
        if (!count || count >= buffer.size()) return Fail("CanonicalPathUnavailable", GetLastError());
        output.assign(buffer.data(), count);
        return true;
    }

    bool AtExpectedPath(const Endpoint& endpoint, std::size_t index, HANDLE handle)
    {
        std::wstring final_path;
        if (!FinalPath(handle, final_path)) return false;
        const auto expected = endpoint.volume_root + endpoint.prefixes[index].substr(3);
        return SamePath(final_path, expected) || Fail("EndpointPathChanged");
    }

    bool Observe(Endpoint& endpoint, RawSnapshotStartupFileEvidence& evidence)
    {
        if (!CheckLocalDrive(endpoint, endpoint.drive_target)) return false;
        for (std::size_t i = 0; i < endpoint.prefixes.size(); ++i)
        {
            const bool directory = i + 1 < endpoint.prefixes.size();
            auto handle = Open(endpoint.prefixes[i]);
            if (!handle)
            {
                const auto error = GetLastError();
                if (i && (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND))
                { endpoint.first_missing = i; return true; }
                return Fail("EndpointOpenFailed", error);
            }
            RawSnapshotStartupFileIdentity identity;
            if (!Identity(handle.Get(), directory, identity)) return false;
            if (i == 0)
            {
                if (!FinalPath(handle.Get(), endpoint.volume_root)) return false;
                const auto& root = endpoint.volume_root;
                if (root.size() != 49 || root.compare(0, 11, L"\\\\?\\Volume{") != 0 ||
                    root[47] != L'}' || root[48] != L'\\') return Fail("NonLocalVolumeRoot");
            }
            else if (!AtExpectedPath(endpoint, i, handle.Get())) return false;
            if (directory) endpoint.parents.push_back(Parent{std::move(handle), identity});
            else
            {
                endpoint.file = std::move(handle);
                evidence.present = true;
                evidence.identity = identity;
            }
        }
        return true;
    }

    bool ReadBytes(Endpoint& endpoint, RawSnapshotStartupFileEvidence& evidence)
    {
        if (!evidence.present) return true;
        reads_.buffer_bytes_requested += evidence.identity.length;
        evidence.bytes.resize(static_cast<std::size_t>(evidence.identity.length));
        constexpr std::size_t chunk_size = 64 * 1024;
        for (std::size_t offset = 0; offset < evidence.bytes.size();)
        {
            const auto remaining = evidence.bytes.size() - offset;
            const auto wanted = static_cast<DWORD>(remaining < chunk_size ? remaining : chunk_size);
            DWORD done = 0;
            ++reads_.read_calls;
            if (!ReadFile(endpoint.file.Get(), evidence.bytes.data() + offset, wanted, &done, nullptr))
                return Fail("EvidenceReadFailed", GetLastError());
            reads_.bytes_read += done;
            if (done != wanted) return Fail("EvidenceShortRead");
            offset += done;
        }
        evidence.bytes_captured = true;
        return true;
    }

    static bool SameIdentity(const RawSnapshotStartupFileIdentity& a,
        const RawSnapshotStartupFileIdentity& b, bool directory) noexcept
    {
        if (a.volume_serial != b.volume_serial || a.file_id != b.file_id || a.creation_time != b.creation_time)
            return false;
        // Sibling creation can change directory times while the pinned directory is identical.
        return directory || (a.length == b.length && a.last_write_time == b.last_write_time &&
            a.change_time == b.change_time && a.attributes == b.attributes && a.links == b.links);
    }

    bool RecheckOne(const Endpoint& endpoint, std::size_t i, HANDLE held,
        const RawSnapshotStartupFileIdentity& original, bool directory)
    {
        RawSnapshotStartupFileIdentity retained, current;
        if (!Identity(held, directory, retained) || !AtExpectedPath(endpoint, i, held)) return false;
        auto handle = Open(endpoint.prefixes[i]);
        if (!handle) return Fail("EndpointReopenFailed", GetLastError());
        if (!Identity(handle.Get(), directory, current) || !AtExpectedPath(endpoint, i, handle.Get())) return false;
        return (SameIdentity(original, retained, directory) && SameIdentity(original, current, directory)) ||
            Fail("EndpointIdentityChanged");
    }

    bool Recheck()
    {
        for (std::size_t n = 0; n < endpoints_.size(); ++n)
        {
            const auto& endpoint = endpoints_[n];
            std::wstring target;
            if (!CheckLocalDrive(endpoint, target)) return false;
            if (target != endpoint.drive_target) return Fail("DriveMappingChanged");
            for (std::size_t i = 0; i < endpoint.parents.size(); ++i)
                if (!RecheckOne(endpoint, i, endpoint.parents[i].handle.Get(), endpoint.parents[i].identity, true))
                    return false;
            if (endpoint.file)
            {
                if (!RecheckOne(endpoint, endpoint.prefixes.size() - 1, endpoint.file.Get(),
                    File(evidence_, n).identity, false)) return false;
            }
            else
            {
                // Probe only the first absent child of the held safe ancestor.
                auto appeared = Open(endpoint.prefixes[endpoint.first_missing]);
                if (appeared) return Fail("MissingNamespaceChanged");
                const auto error = GetLastError();
                if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND)
                    return Fail("MissingNamespaceRecheckFailed", error);
            }
        }
        return true;
    }

    std::array<Endpoint, 3> endpoints_;
    RawSnapshotStartupEvidence evidence_;
    ReadWork reads_;
    bool ready_ = false;
    bool marker_owned_ = false;
    RawSnapshotStartupFileIdentity marker_identity_;
    std::vector<std::byte> marker_bytes_;
    const char* failure_ = "EvidenceUnavailable";
    DWORD win32_error_ = ERROR_SUCCESS;
};

} // namespace apfsaccess::fshost
