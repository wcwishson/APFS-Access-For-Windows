#include "WriteAheadLog.h"

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>
#include <windows.h>

namespace
{
constexpr const char* kVolume = "volume-A";
constexpr const wchar_t* kCompactionChildPathEnv = L"APFSACCESS_WAL_COMPACTION_CHILD_PATH";
constexpr const wchar_t* kCompactionCrashStageEnv = L"APFSACCESS_WAL_COMPACTION_CRASH_STAGE";
constexpr const wchar_t* kCompactionReadyEventEnv = L"APFSACCESS_WAL_COMPACTION_READY_EVENT";
constexpr const wchar_t* kCompactionAttemptEventEnv = L"APFSACCESS_WAL_COMPACTION_ATTEMPT_EVENT";
constexpr std::string_view kCompactionIntentTag = "apfsaccess-wal-compaction-intent-v1";
constexpr std::uint64_t kCompactionIntentNamespaceDurableFlag = 0x1;
constexpr DWORD kCompactionCrashExitCode = 77;

bool Require(bool condition, const char* message)
{
    if (!condition)
    {
        std::cerr << "[FAIL] " << message << std::endl;
        return false;
    }
    return true;
}

std::filesystem::path MakeRunRoot()
{
    std::error_code ec;
    const auto unique_id = std::chrono::steady_clock::now().time_since_epoch().count();
    auto root = std::filesystem::temp_directory_path(ec) /
        ("ApfsAccessWalTests_" + std::to_string(unique_id));
    std::filesystem::remove_all(root, ec);
    std::filesystem::create_directories(root, ec);
    return root;
}

apfsaccess::rw::WriteAheadLog::Record MakeRecord(std::uint64_t sequence)
{
    apfsaccess::rw::WriteAheadLog::Record record{};
    record.volume_identity = kVolume;
    record.transaction_id = 10;
    record.sequence = sequence;
    record.operation = apfsaccess::rw::WriteAheadLog::OperationKind::Write;
    record.state = apfsaccess::rw::WriteAheadLog::RecordState::Prepared;
    record.object_id = 42;
    record.parent_object_id = 7;
    record.payload_spool_id = 3;
    record.payload_offset = 100;
    record.payload_length = 12;
    record.logical_offset = 4096;
    record.logical_length = 12;
    record.flags = 5;
    record.payload_sha256[0] = 0xaa;
    record.path_utf8 = "\\docs\\file.bin";
    record.secondary_path_utf8 = "\\docs\\other.bin";
    return record;
}

bool WriteBytes(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes, std::ios::openmode mode)
{
    std::ofstream output(path, std::ios::binary | mode);
    if (!output.good())
    {
        return false;
    }
    output.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    return output.good();
}

std::filesystem::path CompactionIntentPath(const std::filesystem::path& wal_path)
{
    auto path = wal_path;
    path += L".compact.intent";
    return path;
}

std::filesystem::path CompactionPredecessorGuardPath(
    const std::filesystem::path& wal_path,
    std::uint64_t predecessor_file_id)
{
    auto path = wal_path;
    path += L".compact.predecessor.";
    path += std::to_wstring(predecessor_file_id);
    return path;
}

std::vector<std::filesystem::path> FindNumericSiblingTemps(
    const std::filesystem::path& wal_path,
    std::wstring_view sibling_prefix)
{
    std::vector<std::filesystem::path> matches;
    const auto prefix = wal_path.filename().wstring() + std::wstring(sibling_prefix);
    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator(wal_path.parent_path(), ec))
    {
        const auto filename = entry.path().filename().wstring();
        if (!filename.starts_with(prefix))
        {
            continue;
        }
        const auto suffix = filename.substr(prefix.size());
        const auto separator = suffix.find(L'.');
        const bool numeric_name =
            separator != std::wstring::npos &&
            separator != 0 &&
            separator + 1 < suffix.size() &&
            std::all_of(
                suffix.begin(),
                suffix.begin() + static_cast<std::ptrdiff_t>(separator),
                [](wchar_t value) { return value >= L'0' && value <= L'9'; }) &&
            std::all_of(
                suffix.begin() + static_cast<std::ptrdiff_t>(separator + 1),
                suffix.end(),
                [](wchar_t value) { return value >= L'0' && value <= L'9'; });
        if (numeric_name)
        {
            matches.push_back(entry.path());
        }
    }
    if (ec)
    {
        matches.clear();
    }
    return matches;
}

std::vector<std::filesystem::path> FindCompactionTemps(
    const std::filesystem::path& wal_path)
{
    return FindNumericSiblingTemps(wal_path, L".compact.");
}

std::vector<std::filesystem::path> FindIntentStagingTemps(
    const std::filesystem::path& wal_path)
{
    return FindNumericSiblingTemps(wal_path, L".compact.intent.tmp.");
}

bool IsZeroByteRegularFile(const std::filesystem::path& path)
{
    std::error_code ec;
    return std::filesystem::is_regular_file(path, ec) &&
           !ec &&
           std::filesystem::file_size(path, ec) == 0 &&
           !ec;
}

bool HasCompletedCompactionProof(const std::filesystem::path& wal_path)
{
    const auto intent = apfsaccess::rw::WriteAheadLog::ReadAll(
        CompactionIntentPath(wal_path),
        kVolume);
    return intent.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
           !intent.recovered_torn_tail &&
           !intent.records.empty() &&
           intent.records.back().operation ==
               apfsaccess::rw::WriteAheadLog::OperationKind::CompactionIndex &&
           intent.records.back().state ==
               apfsaccess::rw::WriteAheadLog::RecordState::Cleaned &&
           intent.records.back().flags == kCompactionIntentNamespaceDurableFlag &&
           intent.records.back().object_id != 0 &&
           intent.records.back().logical_offset != 0;
}

std::vector<std::uint8_t> MakeCurrentWalCompactionIntent(
    const std::filesystem::path& wal_path)
{
    const auto wide_path = wal_path.wstring();
    auto* handle = CreateFileW(
        wide_path.c_str(),
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (handle == INVALID_HANDLE_VALUE)
    {
        return {};
    }

    BY_HANDLE_FILE_INFORMATION info{};
    const bool inspected = GetFileInformationByHandle(handle, &info) != FALSE;
    CloseHandle(handle);
    if (!inspected)
    {
        return {};
    }

    apfsaccess::rw::WriteAheadLog::Record intent{};
    intent.volume_identity = kVolume;
    intent.operation = apfsaccess::rw::WriteAheadLog::OperationKind::CompactionIndex;
    intent.state = apfsaccess::rw::WriteAheadLog::RecordState::Prepared;
    intent.object_id =
        (static_cast<std::uint64_t>(info.nFileIndexHigh) << 32u) |
        static_cast<std::uint64_t>(info.nFileIndexLow);
    intent.parent_object_id = info.dwVolumeSerialNumber;
    intent.path_utf8 = kCompactionIntentTag;
    return apfsaccess::rw::WriteAheadLog::EncodeForTest(intent);
}

bool ReadRequiredEnvironment(const wchar_t* name, std::wstring& value)
{
    const auto required = GetEnvironmentVariableW(name, nullptr, 0);
    if (required == 0)
    {
        return false;
    }
    value.resize(required);
    const auto copied = GetEnvironmentVariableW(name, value.data(), required);
    if (copied == 0 || copied >= required)
    {
        value.clear();
        return false;
    }
    value.resize(copied);
    return true;
}

int RunCompactionContenderChild()
{
    std::wstring path;
    std::wstring ready_event_name;
    std::wstring attempt_event_name;
    if (!ReadRequiredEnvironment(kCompactionChildPathEnv, path) ||
        !ReadRequiredEnvironment(kCompactionReadyEventEnv, ready_event_name) ||
        !ReadRequiredEnvironment(kCompactionAttemptEventEnv, attempt_event_name))
    {
        return 10;
    }

    const auto ready_event = OpenEventW(SYNCHRONIZE, FALSE, ready_event_name.c_str());
    const auto attempt_event = OpenEventW(EVENT_MODIFY_STATE, FALSE, attempt_event_name.c_str());
    if (ready_event == nullptr || attempt_event == nullptr)
    {
        if (ready_event != nullptr)
        {
            CloseHandle(ready_event);
        }
        if (attempt_event != nullptr)
        {
            CloseHandle(attempt_event);
        }
        return 11;
    }

    if (WaitForSingleObject(ready_event, 10000) != WAIT_OBJECT_0)
    {
        SetEvent(attempt_event);
        CloseHandle(attempt_event);
        CloseHandle(ready_event);
        return 12;
    }

    bool acquired = false;
    bool appended = false;
    {
        apfsaccess::rw::WriteAheadLog contender({ path, kVolume, 0 });
        acquired = contender.AcquireExclusiveWriterLease();
        if (acquired)
        {
            appended = contender.Append(MakeRecord(99));
        }
    }

    SetEvent(attempt_event);
    CloseHandle(attempt_event);
    CloseHandle(ready_event);
    if (!acquired)
    {
        return 0;
    }
    return appended ? 2 : 13;
}

int RunImmediateWalContenderChild()
{
    std::wstring path;
    if (!ReadRequiredEnvironment(kCompactionChildPathEnv, path))
    {
        return 10;
    }

    apfsaccess::rw::WriteAheadLog contender({ path, kVolume, 0 });
    if (!contender.AcquireExclusiveWriterLease())
    {
        return 0;
    }
    return contender.Append(MakeRecord(99)) ? 2 : 13;
}

bool RunImmediateWalContender(
    const std::filesystem::path& path,
    DWORD& child_exit)
{
    std::wstring executable(32768, L'\0');
    const auto executable_chars = GetModuleFileNameW(
        nullptr,
        executable.data(),
        static_cast<DWORD>(executable.size()));
    if (executable_chars == 0 || executable_chars >= executable.size())
    {
        return false;
    }
    executable.resize(executable_chars);

    SetEnvironmentVariableW(kCompactionChildPathEnv, path.wstring().c_str());
    std::wstring command_line = L"\"" + executable + L"\" cross-process-wal-contender";
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    const bool created = CreateProcessW(
        nullptr,
        command_line.data(),
        nullptr,
        nullptr,
        FALSE,
        CREATE_NO_WINDOW,
        nullptr,
        nullptr,
        &startup,
        &process) != FALSE;
    SetEnvironmentVariableW(kCompactionChildPathEnv, nullptr);
    if (!created)
    {
        return false;
    }
    CloseHandle(process.hThread);

    const auto child_wait = WaitForSingleObject(process.hProcess, 10000);
    if (child_wait != WAIT_OBJECT_0)
    {
        TerminateProcess(process.hProcess, 14);
        WaitForSingleObject(process.hProcess, 10000);
    }
    child_exit = 15;
    GetExitCodeProcess(process.hProcess, &child_exit);
    CloseHandle(process.hProcess);
    return child_wait == WAIT_OBJECT_0;
}

int RunCompactionCrashChild()
{
    std::wstring path;
    std::wstring crash_stage_wide;
    if (!ReadRequiredEnvironment(kCompactionChildPathEnv, path) ||
        !ReadRequiredEnvironment(kCompactionCrashStageEnv, crash_stage_wide))
    {
        return 20;
    }
    std::string crash_stage;
    crash_stage.reserve(crash_stage_wide.size());
    for (const auto character : crash_stage_wide)
    {
        if (character > 0x7f)
        {
            return 22;
        }
        crash_stage.push_back(static_cast<char>(character));
    }

    apfsaccess::rw::WriteAheadLog wal({ path, kVolume, 0 });
    if (!wal.Append(MakeRecord(1), false) || !wal.Append(MakeRecord(2)))
    {
        return 21;
    }
    wal.SetFaultInjectionHook([&](std::string_view stage)
    {
        if (stage == crash_stage)
        {
            (void)TerminateProcess(GetCurrentProcess(), kCompactionCrashExitCode);
            ExitProcess(kCompactionCrashExitCode);
        }
        return false;
    });
    (void)wal.CompactWithResult(2, wal.ExclusiveWriterLeaseGeneration());
    return 23;
}

bool TestAppendReadbackAndVolumeBinding(const std::filesystem::path& root)
{
    const auto path = root / "append.wal";
    apfsaccess::rw::WriteAheadLog wal({ path, kVolume, 0 });
    if (!Require(wal.Append(MakeRecord(1)), "append should succeed"))
    {
        return false;
    }

    const auto read = wal.ReadAll();
    if (!Require(read.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok, "readback status should be ok") ||
        !Require(read.records.size() == 1, "readback should return one record"))
    {
        return false;
    }

    const auto& record = read.records.front();
    if (!Require(record.volume_identity == kVolume, "record should keep volume identity") ||
        !Require(record.sequence == 1, "record should keep sequence") ||
        !Require(record.object_id == 42, "record should keep object id") ||
        !Require(record.path_utf8 == "\\docs\\file.bin", "record should keep path") ||
        !Require(record.secondary_path_utf8 == "\\docs\\other.bin", "record should keep secondary path"))
    {
        return false;
    }

    const auto wrong_volume = apfsaccess::rw::WriteAheadLog::ReadAll(path, "volume-B");
    return Require(
        wrong_volume.status == apfsaccess::rw::WriteAheadLog::ReadStatus::VolumeMismatch,
        "readback should reject wrong volume identity");
}

bool TestAppendHandleOwnsExclusiveWriterLease(const std::filesystem::path& root)
{
    const auto path = root / "exclusive-writer.wal";
    apfsaccess::rw::WriteAheadLog contender({ path, kVolume, 0 });
    {
        apfsaccess::rw::WriteAheadLog owner({ path, kVolume, 0 });
        if (!Require(owner.Append(MakeRecord(1)), "owner should establish the WAL writer lease"))
        {
            return false;
        }
        const auto owner_generation = owner.ExclusiveWriterLeaseGeneration();
        const auto path_wide = path.wstring();
        auto* external_writer = CreateFileW(
            path_wide.c_str(),
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (!Require(
                external_writer == INVALID_HANDLE_VALUE && GetLastError() == ERROR_SHARING_VIOLATION,
                "an external writer must be rejected while process-local WAL state is trusted") ||
            !Require(
                owner.Append(MakeRecord(2)),
                "the current owner should remain writable before explicit transfer") ||
            !Require(
                contender.AcquireExclusiveWriterLease(),
                "the registered in-process successor should explicitly take over the WAL writer lease") ||
            !Require(
                contender.Append(MakeRecord(3)),
                "the registered in-process successor should append after explicit transfer") ||
            !Require(
                !owner.HasExclusiveWriterLease() && contender.HasExclusiveWriterLease(),
                "in-process writer transfer must invalidate the previous owner's lease") ||
            !Require(
                owner_generation != 0 &&
                    contender.ExclusiveWriterLeaseGeneration() != 0 &&
                    contender.ExclusiveWriterLeaseGeneration() != owner_generation,
                "writer transfer must issue a distinct lease generation"))
        {
            if (external_writer != INVALID_HANDLE_VALUE)
            {
                CloseHandle(external_writer);
            }
            return false;
        }
        if (external_writer != INVALID_HANDLE_VALUE)
        {
            CloseHandle(external_writer);
        }
    }
    const auto read = contender.ReadAll();
    return Require(read.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok, "exclusive-writer WAL should remain readable") &&
           Require(read.records.size() == 3, "exclusive-writer WAL should retain every serialized append");
}

bool TestTornTailRecovery(const std::filesystem::path& root)
{
    const auto path = root / "torn-tail.wal";
    const auto first = apfsaccess::rw::WriteAheadLog::EncodeForTest(MakeRecord(1));
    auto second = apfsaccess::rw::WriteAheadLog::EncodeForTest(MakeRecord(2));
    second.resize(second.size() / 2);

    if (!WriteBytes(path, first, std::ios::trunc) ||
        !WriteBytes(path, second, std::ios::app))
    {
        return false;
    }

    const auto original_size = std::filesystem::file_size(path);
    const auto observed = apfsaccess::rw::WriteAheadLog::ReadAll(path, kVolume);
    if (!Require(observed.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok, "torn-tail observer read should stay ok") ||
        !Require(observed.recovered_torn_tail, "torn-tail observer read should report the incomplete suffix") ||
        !Require(observed.records.size() == 1, "torn-tail observer read should keep the complete prefix") ||
        !Require(std::filesystem::file_size(path) == original_size, "observer reads must not mutate a WAL without a writer lease"))
    {
        return false;
    }

    apfsaccess::rw::WriteAheadLog wal({ path, kVolume, 0 });
    const auto repaired = wal.ReadAllWithExclusiveWriterLease();
    if (!Require(repaired.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok, "leased torn-tail recovery should stay ok") ||
        !Require(repaired.recovered_torn_tail, "leased torn-tail recovery should report repair") ||
        !Require(std::filesystem::file_size(path) == first.size(), "leased recovery should truncate the bad suffix"))
    {
        return false;
    }
    if (!Require(wal.Append(MakeRecord(3)), "append after torn-tail recovery should succeed"))
    {
        return false;
    }
    const auto reread = wal.ReadAll();
    return Require(reread.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok, "recovered WAL should reread cleanly") &&
           Require(reread.records.size() == 2, "recovered WAL should accept later appends");
}

bool TestExclusiveLeaseReadRepairsTornTail(const std::filesystem::path& root)
{
    const auto path = root / "exclusive-lease-torn-tail.wal";
    const auto first = apfsaccess::rw::WriteAheadLog::EncodeForTest(MakeRecord(1));
    auto second = apfsaccess::rw::WriteAheadLog::EncodeForTest(MakeRecord(2));
    second.resize(second.size() / 2);
    if (!WriteBytes(path, first, std::ios::trunc) ||
        !WriteBytes(path, second, std::ios::app))
    {
        return false;
    }

    apfsaccess::rw::WriteAheadLog wal({ path, kVolume, 0 });
    if (!Require(wal.AcquireExclusiveWriterLease(), "fixture should acquire its initial writer lease"))
    {
        return false;
    }
    const auto initial_generation = wal.ExclusiveWriterLeaseGeneration();
    const auto read = wal.ReadAllWithExclusiveWriterLease();
    return Require(read.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok, "leased torn-tail read should recover") &&
           Require(read.recovered_torn_tail, "leased torn-tail read should report repair") &&
           Require(read.records.size() == 1, "leased torn-tail repair should retain the complete prefix") &&
           Require(std::filesystem::file_size(path) == first.size(), "leased torn-tail repair should truncate the suffix") &&
           Require(wal.HasExclusiveWriterLease(), "strict read should reacquire the writer lease after repair") &&
           Require(
               wal.ExclusiveWriterLeaseGeneration() != 0 &&
                   wal.ExclusiveWriterLeaseGeneration() == initial_generation,
               "strict repair should retain one uninterrupted writer generation");
}

bool TestStrictReadFailureRetainsCrossProcessWriterLease(const std::filesystem::path& root)
{
    const auto path = root / "strict-read-quarantine.wal";
    const auto valid = apfsaccess::rw::WriteAheadLog::EncodeForTest(MakeRecord(1));
    {
        apfsaccess::rw::WriteAheadLog seed({ path, kVolume, 0 });
        if (!Require(seed.Append(MakeRecord(1)), "strict-read quarantine fixture should seed a valid WAL"))
        {
            return false;
        }
    }

    auto corrupt = valid;
    corrupt.back() ^= 0xffu;
    if (!Require(
            WriteBytes(path, corrupt, std::ios::trunc),
            "strict-read quarantine fixture should corrupt the WAL checksum"))
    {
        return false;
    }

    {
        apfsaccess::rw::WriteAheadLog quarantined({ path, kVolume, 0 });
        const auto read = quarantined.ReadAllWithExclusiveWriterLease();
        if (!Require(
                read.status != apfsaccess::rw::WriteAheadLog::ReadStatus::Ok,
                "strict read must reject checksum-corrupt evidence") ||
            !Require(
                quarantined.HasExclusiveWriterLease(),
                "strict read failure must retain the volume writer lease") ||
            !Require(
                quarantined.ExclusiveWriterLeaseGeneration() != 0,
                "quarantined evidence must retain a valid writer generation"))
        {
            return false;
        }

        DWORD child_exit = 15;
        if (!Require(
                RunImmediateWalContender(path, child_exit),
                "cross-process quarantine contender should complete") ||
            !Require(
                child_exit == 0,
                "cross-process contender must not acquire or append while corrupt evidence is quarantined"))
        {
            return false;
        }

        const auto unchanged = apfsaccess::rw::WriteAheadLog::ReadAll(path, kVolume);
        if (!Require(
                unchanged.status == apfsaccess::rw::WriteAheadLog::ReadStatus::ChecksumMismatch,
                "blocked contender must leave the corrupt evidence unchanged"))
        {
            return false;
        }
    }

    if (!Require(
            WriteBytes(path, valid, std::ios::trunc),
            "released quarantine fixture should repair the WAL evidence"))
    {
        return false;
    }
    apfsaccess::rw::WriteAheadLog recovered({ path, kVolume, 0 });
    if (!Require(
            recovered.AcquireExclusiveWriterLease(),
            "a repaired WAL should become ownable after the quarantine owner is destroyed") ||
        !Require(recovered.Append(MakeRecord(2)), "repaired WAL should accept a new record"))
    {
        return false;
    }
    const auto snapshot = recovered.ReadAll();
    return Require(
               snapshot.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                   snapshot.records.size() == 2 &&
                   snapshot.records.back().sequence == 2,
               "repaired WAL should retain one coherent history");
}

bool TestStrictRepairFailuresRetainWriterLease(const std::filesystem::path& root)
{
    const auto torn_path = root / "strict-truncate-quarantine.wal";
    const auto first = apfsaccess::rw::WriteAheadLog::EncodeForTest(MakeRecord(1));
    auto torn = apfsaccess::rw::WriteAheadLog::EncodeForTest(MakeRecord(2));
    torn.resize(torn.size() / 2);
    if (!WriteBytes(torn_path, first, std::ios::trunc) ||
        !WriteBytes(torn_path, torn, std::ios::app))
    {
        return false;
    }
    {
        apfsaccess::rw::WriteAheadLog quarantined({ torn_path, kVolume, 0 });
        quarantined.SetFaultInjectionHook([](std::string_view stage)
        {
            return stage == "read-all-exclusive-truncate";
        });
        const auto read = quarantined.ReadAllWithExclusiveWriterLease();
        quarantined.SetFaultInjectionHook({});
        apfsaccess::rw::WriteAheadLog contender({ torn_path, kVolume, 0 });
        if (!Require(
                read.status == apfsaccess::rw::WriteAheadLog::ReadStatus::IoError,
                "failed torn-tail truncation should fail strict recovery") ||
            !Require(
                quarantined.HasExclusiveWriterLease(),
                "failed torn-tail truncation must retain quarantine ownership") ||
            !Require(
                !contender.AcquireExclusiveWriterLease(),
                "failed torn-tail truncation must block another writer"))
        {
            return false;
        }
    }

    const auto revalidate_path = root / "strict-revalidate-quarantine.wal";
    if (!WriteBytes(revalidate_path, first, std::ios::trunc))
    {
        return false;
    }
    apfsaccess::rw::WriteAheadLog quarantined({ revalidate_path, kVolume, 0 });
    quarantined.SetFaultInjectionHook([](std::string_view stage)
    {
        return stage == "read-all-exclusive-revalidate";
    });
    const auto read = quarantined.ReadAllWithExclusiveWriterLease();
    quarantined.SetFaultInjectionHook({});
    apfsaccess::rw::WriteAheadLog contender({ revalidate_path, kVolume, 0 });
    return Require(
               read.status == apfsaccess::rw::WriteAheadLog::ReadStatus::IoError,
               "failed strict revalidation should reject the WAL") &&
           Require(
               quarantined.HasExclusiveWriterLease(),
               "failed strict revalidation must retain quarantine ownership") &&
           Require(
               !contender.AcquireExclusiveWriterLease(),
               "failed strict revalidation must block another writer");
}

bool TestChecksumAndVersionRejection(const std::filesystem::path& root)
{
    auto corrupt = apfsaccess::rw::WriteAheadLog::EncodeForTest(MakeRecord(1));
    corrupt.back() ^= 0xffu;
    const auto corrupt_path = root / "checksum.wal";
    if (!WriteBytes(corrupt_path, corrupt, std::ios::trunc))
    {
        return false;
    }
    const auto corrupt_read = apfsaccess::rw::WriteAheadLog::ReadAll(corrupt_path, kVolume);
    if (!Require(
            corrupt_read.status == apfsaccess::rw::WriteAheadLog::ReadStatus::ChecksumMismatch,
            "corrupt record should fail checksum"))
    {
        return false;
    }

    const auto versioned = apfsaccess::rw::WriteAheadLog::EncodeForTest(MakeRecord(1), 999);
    const auto version_path = root / "version.wal";
    if (!WriteBytes(version_path, versioned, std::ios::trunc))
    {
        return false;
    }
    const auto version_read = apfsaccess::rw::WriteAheadLog::ReadAll(version_path, kVolume);
    return Require(
        version_read.status == apfsaccess::rw::WriteAheadLog::ReadStatus::VersionMismatch,
        "future version should be rejected");
}

bool TestAppendResultDistinguishesPrewriteAndAmbiguousFlush(const std::filesystem::path& root)
{
    const auto ambiguous_path = root / "ambiguous-flush.wal";
    apfsaccess::rw::WriteAheadLog ambiguous({ ambiguous_path, kVolume, 0 });
    ambiguous.SetFaultInjectionHook([](std::string_view stage)
    {
        return stage == "durable-flush";
    });

    const auto ambiguous_result = ambiguous.AppendWithResult(MakeRecord(1));
    if (!Require(
            ambiguous_result == apfsaccess::rw::WriteAheadLog::AppendResult::BytesMayHavePersisted,
            "flush failure after a WAL write should report bytes may have persisted") ||
        !Require(std::filesystem::file_size(ambiguous_path) > 0, "ambiguous WAL append should retain written bytes"))
    {
        return false;
    }

    const auto ambiguous_read = ambiguous.ReadAll();
    if (!Require(
            ambiguous_read.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                ambiguous_read.records.size() == 1,
            "ambiguous WAL append should retain a complete record for recovery"))
    {
        return false;
    }

    const auto rejected_path = root / "prewrite-rejection.wal";
    apfsaccess::rw::WriteAheadLog rejected({ rejected_path, kVolume, 32 });
    return Require(
               rejected.AppendWithResult(MakeRecord(1)) ==
                   apfsaccess::rw::WriteAheadLog::AppendResult::RejectedBeforeWrite,
               "size-limit rejection should report that no WAL bytes were written") &&
           Require(!std::filesystem::exists(rejected_path), "pre-write rejection should not create a WAL file");
}

bool TestCompactionAndSizeLimit(const std::filesystem::path& root)
{
    apfsaccess::rw::WriteAheadLog::Options default_options{};
    if (!Require(default_options.max_bytes > 0, "default WAL options should enforce a size limit"))
    {
        return false;
    }

    const auto path = root / "compact.wal";
    apfsaccess::rw::WriteAheadLog wal({ path, kVolume, 0 });
    if (!Require(wal.Append(MakeRecord(1), false), "first append should succeed") ||
        !Require(wal.Append(MakeRecord(2), false), "second append should succeed") ||
        !Require(wal.Append(MakeRecord(3)), "third append should succeed"))
    {
        return false;
    }
    const auto size_before = std::filesystem::file_size(path);

    if (!Require(wal.Compact(3), "compaction should succeed"))
    {
        return false;
    }
    const auto compacted = wal.ReadAll();
    const auto size_after = std::filesystem::file_size(path);
    const auto first_completion = apfsaccess::rw::WriteAheadLog::ReadAll(
        CompactionIntentPath(path),
        kVolume);
    const auto first_tombstone =
        first_completion.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
            !first_completion.records.empty()
        ? CompactionPredecessorGuardPath(path, first_completion.records.back().object_id)
        : std::filesystem::path{};
    if (!Require(compacted.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok, "compacted read should be ok") ||
        !Require(compacted.records.size() == 2, "compaction should keep one live record plus index") ||
        !Require(compacted.records.front().sequence == 3, "compaction should drop older records") ||
        !Require(size_after < size_before, "compaction should reduce file size") ||
        !Require(
            HasCompletedCompactionProof(path),
            "successful compaction should retain its durable completion proof") ||
         !Require(
             wal.SnapshotCounters().append_handle_open_count == 2,
             "compaction should reopen an exclusively owned handle before returning") ||
        !Require(
            IsZeroByteRegularFile(first_tombstone),
            "successful compaction should retain a zero-byte predecessor tombstone"))
    {
        return false;
    }

    if (!Require(wal.Append(MakeRecord(4)), "append after compaction should succeed") ||
        !Require(
            wal.SnapshotCounters().append_handle_open_count == 2,
            "compaction should close the old handle and reopen on the next append"))
    {
        return false;
    }
    if (!Require(wal.Compact(4), "a later compaction should retire the previous completion proof") ||
        !Require(
            !std::filesystem::exists(first_tombstone),
            "a later compaction should remove the previous predecessor tombstone") ||
        !Require(
            HasCompletedCompactionProof(path),
            "a later compaction should publish its own completion proof"))
    {
        return false;
    }

    const auto limited_path = root / "limited.wal";
    apfsaccess::rw::WriteAheadLog limited({ limited_path, kVolume, 32 });
    return Require(!limited.Append(MakeRecord(1)), "size limit should reject oversized append");
}

bool TestCompactionPostReplaceFailureIsAmbiguous(const std::filesystem::path& root)
{
    const auto path = root / "compact-post-replace-failure.wal";
    apfsaccess::rw::WriteAheadLog wal({ path, kVolume, 0 });
    if (!Require(wal.Append(MakeRecord(1), false), "ambiguous compaction fixture should append first record") ||
        !Require(wal.Append(MakeRecord(2)), "ambiguous compaction fixture should append second record"))
    {
        return false;
    }
    const auto expected_generation = wal.ExclusiveWriterLeaseGeneration();
    wal.SetFaultInjectionHook([](std::string_view stage)
    {
        return stage == "compact-target-flush";
    });
    const auto result = wal.CompactWithResult(2, expected_generation);
    wal.SetFaultInjectionHook({});
    const auto snapshot = apfsaccess::rw::WriteAheadLog::ReadAll(path, kVolume);
    const bool intent_retained = std::filesystem::exists(CompactionIntentPath(path));
    apfsaccess::rw::WriteAheadLog recovered({ path, kVolume, 0 });
    const bool recovered_lease = recovered.AcquireExclusiveWriterLease();
    return Require(
               result == apfsaccess::rw::WriteAheadLog::CompactionResult::BytesMayHavePersisted,
               "post-replacement compaction flush failure must be classified as ambiguous") &&
           Require(!wal.HasExclusiveWriterLease(), "ambiguous compaction should drop process-local writer trust") &&
           Require(intent_retained, "post-replacement failure should retain durable compaction intent") &&
           Require(recovered_lease, "restart should resolve a compaction whose predecessor has no surviving links") &&
           Require(
               HasCompletedCompactionProof(path),
               "resolved post-replacement compaction should retain a completion proof") &&
           Require(
               snapshot.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                   snapshot.records.size() == 2,
               "post-replacement failure should leave a coherent recoverable compacted WAL");
}

bool TestAmbiguousRenameResultPreservesPublishedReplacement(
    const std::filesystem::path& root)
{
    const auto path = root / "compact-ambiguous-rename-result.wal";
    apfsaccess::rw::WriteAheadLog wal({ path, kVolume, 0 });
    if (!Require(wal.Append(MakeRecord(1), false), "ambiguous-rename fixture should append first record") ||
        !Require(wal.Append(MakeRecord(2)), "ambiguous-rename fixture should append second record"))
    {
        return false;
    }

    bool result_ambiguity_injected = false;
    wal.SetFaultInjectionHook([&](std::string_view stage)
    {
        if (stage == "compact-replace-result-ambiguous")
        {
            result_ambiguity_injected = true;
            return true;
        }
        return false;
    });
    const auto result = wal.CompactWithResult(2, wal.ExclusiveWriterLeaseGeneration());
    wal.SetFaultInjectionHook({});
    const auto published = apfsaccess::rw::WriteAheadLog::ReadAll(path, kVolume);
    const bool intent_retained = std::filesystem::exists(CompactionIntentPath(path));

    apfsaccess::rw::WriteAheadLog recovered({ path, kVolume, 0 });
    const bool recovered_lease = recovered.AcquireExclusiveWriterLease();
    return Require(result_ambiguity_injected, "ambiguous-rename fixture should publish before reporting failure") &&
           Require(
               result == apfsaccess::rw::WriteAheadLog::CompactionResult::BytesMayHavePersisted,
               "ambiguous rename result must report possible persistence") &&
           Require(intent_retained, "ambiguous rename result must retain compaction intent") &&
           Require(
               published.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                   published.records.size() == 2 &&
                   published.records.front().sequence == 2,
               "ambiguous rename handling must not delete the published replacement") &&
           Require(recovered_lease, "restart should resolve an ambiguously reported published replacement") &&
           Require(
               HasCompletedCompactionProof(path),
               "resolved ambiguous rename should retain a namespace-durable completion proof");
}

bool TestResolvedCompactionIntentRecoversBeforeGuardDelete(const std::filesystem::path& root)
{
    const auto path = root / "compact-resolved-before-guard-delete.wal";
    apfsaccess::rw::WriteAheadLog wal({ path, kVolume, 0 });
    if (!Require(wal.Append(MakeRecord(1), false), "resolved-intent fixture should append first record") ||
        !Require(wal.Append(MakeRecord(2)), "resolved-intent fixture should append second record"))
    {
        return false;
    }
    bool reached_resolution_proof = false;
    wal.SetFaultInjectionHook([&](std::string_view stage)
    {
        if (stage == "compact-after-resolution-proof")
        {
            reached_resolution_proof = true;
            return true;
        }
        return false;
    });
    const auto result = wal.CompactWithResult(2, wal.ExclusiveWriterLeaseGeneration());
    wal.SetFaultInjectionHook({});
    const auto intent_path = CompactionIntentPath(path);
    const auto intent = apfsaccess::rw::WriteAheadLog::ReadAll(intent_path, kVolume);
    apfsaccess::rw::WriteAheadLog recovered({ path, kVolume, 0 });
    const bool recovered_lease = recovered.AcquireExclusiveWriterLease();
    const auto recovered_history = recovered.ReadAll();
    return Require(reached_resolution_proof, "resolved-intent fixture should reach the durable proof boundary") &&
           Require(
               result == apfsaccess::rw::WriteAheadLog::CompactionResult::BytesMayHavePersisted,
               "failure after durable resolution proof should remain ambiguous to the caller") &&
           Require(
               intent.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                   !intent.records.empty() &&
                   intent.records.back().state ==
                       apfsaccess::rw::WriteAheadLog::RecordState::Checkpointed &&
                   intent.records.back().logical_offset != 0,
               "the retained intent should bind a verified replacement identity") &&
           Require(recovered_lease, "restart should finish cleanup from a verified compaction intent") &&
           Require(HasCompletedCompactionProof(path), "verified intent recovery should retain a completion proof") &&
           Require(
               recovered_history.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                   recovered_history.records.size() == 2 &&
                   recovered_history.records.front().sequence == 2,
               "verified intent recovery should preserve compacted history");
}

bool TestCleanedIntentRecoversAfterPredecessorUnlink(const std::filesystem::path& root)
{
    const auto path = root / "compact-checkpointed-after-predecessor-unlink.wal";
    apfsaccess::rw::WriteAheadLog wal({ path, kVolume, 0 });
    if (!Require(wal.Append(MakeRecord(1), false), "post-unlink fixture should append first record") ||
        !Require(wal.Append(MakeRecord(2)), "post-unlink fixture should append second record"))
    {
        return false;
    }

    bool reached_post_unlink_boundary = false;
    wal.SetFaultInjectionHook([&](std::string_view stage)
    {
        if (stage == "compact-after-predecessor-unlink")
        {
            reached_post_unlink_boundary = true;
            return true;
        }
        return false;
    });
    const auto result = wal.CompactWithResult(2, wal.ExclusiveWriterLeaseGeneration());
    wal.SetFaultInjectionHook({});

    const auto retained = apfsaccess::rw::WriteAheadLog::ReadAll(
        CompactionIntentPath(path),
        kVolume);
    const bool retained_completion =
        retained.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
        !retained.records.empty() &&
        retained.records.back().state ==
            apfsaccess::rw::WriteAheadLog::RecordState::Cleaned &&
        retained.records.back().flags == 0;
    const auto guard_path = retained_completion
        ? CompactionPredecessorGuardPath(path, retained.records.back().object_id)
        : std::filesystem::path{};
    const bool guard_is_tombstone = retained_completion && IsZeroByteRegularFile(guard_path);

    apfsaccess::rw::WriteAheadLog recovered({ path, kVolume, 0 });
    const bool recovered_lease = recovered.AcquireExclusiveWriterLease();
    const auto recovered_history = recovered.ReadAll();
    return Require(reached_post_unlink_boundary, "post-unlink fixture should reach its crash boundary") &&
           Require(
               result == apfsaccess::rw::WriteAheadLog::CompactionResult::BytesMayHavePersisted,
               "failure after predecessor unlink must remain ambiguous to the caller") &&
           Require(retained_completion, "post-unlink failure should retain a cleaned intent") &&
           Require(
               guard_is_tombstone,
               "cleaned recovery evidence should retain a zero-byte predecessor tombstone") &&
           Require(recovered_lease, "restart should idempotently complete an authorized predecessor unlink") &&
           Require(HasCompletedCompactionProof(path), "post-unlink restart should publish a completion proof") &&
           Require(
               IsZeroByteRegularFile(guard_path),
               "completed recovery should retain its rollback tombstone until a later compaction") &&
           Require(
               recovered_history.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                   recovered_history.records.size() == 2 &&
                   recovered_history.records.front().sequence == 2,
               "post-unlink restart should preserve the compacted history");
}

bool TestCleanupArmedTombstoneRecoversAfterCrash(
    const std::filesystem::path& root)
{
    const auto path = root / "compact-checkpointed-missing-predecessor.wal";
    apfsaccess::rw::WriteAheadLog wal({ path, kVolume, 0 });
    if (!Require(wal.Append(MakeRecord(1), false), "missing-guard fixture should append first record") ||
        !Require(wal.Append(MakeRecord(2)), "missing-guard fixture should append second record"))
    {
        return false;
    }

    bool reached_zero_link_proof = false;
    wal.SetFaultInjectionHook([&](std::string_view stage)
    {
        if (stage == "compact-after-predecessor-zero-link-proof")
        {
            reached_zero_link_proof = true;
            return true;
        }
        return false;
    });
    const auto result = wal.CompactWithResult(2, wal.ExclusiveWriterLeaseGeneration());
    wal.SetFaultInjectionHook({});

    const auto intent = apfsaccess::rw::WriteAheadLog::ReadAll(
        CompactionIntentPath(path),
        kVolume);
    const bool cleanup_armed =
        intent.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
        !intent.records.empty() &&
        intent.records.back().state ==
            apfsaccess::rw::WriteAheadLog::RecordState::CleanupArmed;
    const auto guard_path = cleanup_armed
        ? CompactionPredecessorGuardPath(path, intent.records.back().object_id)
        : std::filesystem::path{};
    const bool tombstone_retained = cleanup_armed && IsZeroByteRegularFile(guard_path);
    apfsaccess::rw::WriteAheadLog recovered({ path, kVolume, 0 });
    const bool restarted = recovered.AcquireExclusiveWriterLease();
    const auto recovered_history = recovered.ReadAll();
    return Require(reached_zero_link_proof, "tombstone fixture should reach the durable truncation proof") &&
           Require(
               result == apfsaccess::rw::WriteAheadLog::CompactionResult::BytesMayHavePersisted,
               "failure before the cleaned proof must remain ambiguous") &&
           Require(cleanup_armed, "failure before the cleaned proof must retain cleanup-armed evidence") &&
           Require(tombstone_retained, "cleanup-armed recovery must retain its zero-byte tombstone") &&
           Require(restarted, "restart should promote a validated cleanup-armed tombstone") &&
           Require(HasCompletedCompactionProof(path), "tombstone recovery should publish a completion proof") &&
           Require(
               IsZeroByteRegularFile(guard_path),
               "completed tombstone recovery should retain its predecessor pathname") &&
           Require(
               recovered_history.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                   recovered_history.records.size() == 2 &&
                   recovered_history.records.front().sequence == 2,
               "tombstone recovery should preserve the compacted WAL history");
}

bool TestPredecessorAliasBeforeTombstoneTruncationFailsClosed(
    const std::filesystem::path& root)
{
    const auto path = root / "compact-posix-unlink-alias-race.wal";
    const auto alias = root / "compact-posix-unlink-unknown-alias.wal";
    apfsaccess::rw::WriteAheadLog wal({ path, kVolume, 0 });
    if (!Require(wal.Append(MakeRecord(1), false), "unlink-race fixture should append first record") ||
        !Require(wal.Append(MakeRecord(2)), "unlink-race fixture should append second record"))
    {
        return false;
    }

    bool alias_created = false;
    wal.SetFaultInjectionHook([&](std::string_view stage)
    {
        if (stage != "compact-after-cleanup-armed" || alias_created)
        {
            return false;
        }
        const auto guard_prefix = path.filename().wstring() + L".compact.predecessor.";
        std::error_code enumerate_ec;
        for (const auto& entry : std::filesystem::directory_iterator(root, enumerate_ec))
        {
            if (entry.path().filename().wstring().starts_with(guard_prefix))
            {
                alias_created = CreateHardLinkW(
                    alias.wstring().c_str(),
                    entry.path().wstring().c_str(),
                    nullptr) != FALSE;
                break;
            }
        }
        return false;
    });
    const auto result = wal.CompactWithResult(2, wal.ExclusiveWriterLeaseGeneration());
    wal.SetFaultInjectionHook({});

    const auto intent = apfsaccess::rw::WriteAheadLog::ReadAll(
        CompactionIntentPath(path),
        kVolume);
    const bool cleanup_armed =
        intent.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
        !intent.records.empty() &&
        intent.records.back().state ==
            apfsaccess::rw::WriteAheadLog::RecordState::CleanupArmed;
    const auto guard_path = cleanup_armed
        ? CompactionPredecessorGuardPath(path, intent.records.back().object_id)
        : std::filesystem::path{};
    const auto predecessor_before_recovery = apfsaccess::rw::WriteAheadLog::ReadAll(
        guard_path,
        kVolume);
    apfsaccess::rw::WriteAheadLog blocked_with_alias({ path, kVolume, 0 });
    const bool acquired_with_alias = blocked_with_alias.AcquireExclusiveWriterLease();
    std::error_code remove_ec;
    const bool alias_removed = std::filesystem::remove(alias, remove_ec) && !remove_ec;
    apfsaccess::rw::WriteAheadLog blocked_without_alias({ path, kVolume, 0 });
    const bool acquired_without_alias = blocked_without_alias.AcquireExclusiveWriterLease();
    return Require(alias_created, "unlink race should create an unknown predecessor alias") &&
           Require(
               result == apfsaccess::rw::WriteAheadLog::CompactionResult::BytesMayHavePersisted,
               "unknown alias at unlink must keep compaction ambiguous") &&
           Require(cleanup_armed, "unknown alias at unlink must retain cleanup-armed evidence") &&
           Require(
               predecessor_before_recovery.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                   predecessor_before_recovery.records.size() == 2 &&
                   predecessor_before_recovery.records.front().sequence == 1,
               "an aliased predecessor must not be truncated before ownership is exclusive") &&
           Require(!acquired_with_alias, "restart must reject a surviving unknown predecessor alias") &&
           Require(alias_removed, "unlink-race fixture should remove its unknown alias") &&
           Require(acquired_without_alias, "restart should recover after the predecessor alias is removed") &&
           Require(HasCompletedCompactionProof(path), "exclusive predecessor recovery should complete compaction") &&
           Require(IsZeroByteRegularFile(guard_path), "completed recovery should retain a zero-byte tombstone");
}

bool TestHardLinkCreationAfterTombstoneTruncationFailsClosed(
    const std::filesystem::path& root)
{
    const auto path = root / "compact-posix-disposition-source.wal";
    const auto alias = root / "compact-posix-disposition-late-alias.wal";
    apfsaccess::rw::WriteAheadLog wal({ path, kVolume, 0 });
    if (!Require(wal.Append(MakeRecord(1), false), "post-disposition fixture should append first record") ||
        !Require(wal.Append(MakeRecord(2)), "post-disposition fixture should append second record"))
    {
        return false;
    }

    bool link_attempted = false;
    bool link_created = false;
    std::filesystem::path predecessor_guard;
    wal.SetFaultInjectionHook([&](std::string_view stage)
    {
        if (stage == "compact-before-predecessor-unlink")
        {
            const auto guard_prefix = path.filename().wstring() + L".compact.predecessor.";
            std::error_code enumerate_ec;
            for (const auto& entry : std::filesystem::directory_iterator(root, enumerate_ec))
            {
                if (entry.path().filename().wstring().starts_with(guard_prefix))
                {
                    predecessor_guard = entry.path();
                    break;
                }
            }
            return false;
        }
        if (stage == "compact-after-predecessor-disposition" &&
            !link_attempted &&
            !predecessor_guard.empty())
        {
            link_attempted = true;
            link_created = CreateHardLinkW(
                alias.wstring().c_str(),
                predecessor_guard.wstring().c_str(),
                nullptr) != FALSE;
        }
        return false;
    });
    const auto result = wal.CompactWithResult(2, wal.ExclusiveWriterLeaseGeneration());
    wal.SetFaultInjectionHook({});
    const auto intent = apfsaccess::rw::WriteAheadLog::ReadAll(
        CompactionIntentPath(path),
        kVolume);
    const bool cleanup_armed =
        intent.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
        !intent.records.empty() &&
        intent.records.back().state ==
            apfsaccess::rw::WriteAheadLog::RecordState::CleanupArmed;
    apfsaccess::rw::WriteAheadLog blocked({ path, kVolume, 0 });
    const bool blocked_acquired = blocked.AcquireExclusiveWriterLease();
    const bool alias_is_tombstone = IsZeroByteRegularFile(alias);
    std::error_code remove_ec;
    const bool alias_removed = std::filesystem::remove(alias, remove_ec) && !remove_ec;
    apfsaccess::rw::WriteAheadLog recovered({ path, kVolume, 0 });
    const bool recovered_acquired = alias_removed && recovered.AcquireExclusiveWriterLease();
    return Require(link_attempted, "post-disposition fixture should attempt a late hard link") &&
           Require(link_created, "the retained tombstone pathname should allow the race fixture to create an alias") &&
           Require(
               result == apfsaccess::rw::WriteAheadLog::CompactionResult::BytesMayHavePersisted,
               "a late tombstone alias must keep compaction ambiguous") &&
           Require(cleanup_armed, "a late tombstone alias must retain cleanup-armed evidence") &&
           Require(IsZeroByteRegularFile(predecessor_guard), "the guarded predecessor should remain a tombstone") &&
           Require(alias_is_tombstone, "the late alias should reference only the zero-byte tombstone") &&
           Require(!blocked_acquired, "restart must fail closed while the tombstone alias survives") &&
           Require(alias_removed, "tombstone-alias fixture should remove its late alias") &&
           Require(recovered_acquired, "restart should complete after the tombstone alias is removed") &&
           Require(HasCompletedCompactionProof(path), "resolved tombstone recovery should retain completion proof") &&
           Require(IsZeroByteRegularFile(predecessor_guard), "completed recovery should retain its tombstone");
}

bool TestCompactionNamespaceFlushFailuresRetainEvidence(
    const std::filesystem::path& root)
{
    struct FlushCase
    {
        const wchar_t* suffix;
        std::string_view stage;
        std::uint64_t expected_first_sequence;
        bool expect_completion_proof;
    };
    const std::array cases{
        FlushCase{ L"intent", "compact-intent-directory-flush", 1, false },
        FlushCase{ L"predecessor", "compact-predecessor-directory-flush", 1, false },
        FlushCase{ L"replacement", "compact-replacement-directory-flush", 2, true },
        FlushCase{ L"unlink", "compact-predecessor-unlink-directory-flush", 2, true },
    };

    bool ok = true;
    for (const auto& flush_case : cases)
    {
        const auto path = root /
            (std::wstring(L"compact-namespace-flush-") + flush_case.suffix + L".wal");
        apfsaccess::rw::WriteAheadLog wal({ path, kVolume, 0 });
        if (!Require(wal.Append(MakeRecord(1), false), "namespace-flush fixture should append first record") ||
            !Require(wal.Append(MakeRecord(2)), "namespace-flush fixture should append second record"))
        {
            return false;
        }
        bool injected = false;
        wal.SetFaultInjectionHook([&](std::string_view stage)
        {
            if (!injected && stage == flush_case.stage)
            {
                injected = true;
                return true;
            }
            return false;
        });
        const auto result = wal.CompactWithResult(2, wal.ExclusiveWriterLeaseGeneration());
        wal.SetFaultInjectionHook({});
        const bool intent_retained = std::filesystem::exists(CompactionIntentPath(path));

        apfsaccess::rw::WriteAheadLog recovered({ path, kVolume, 0 });
        const bool recovered_lease = recovered.AcquireExclusiveWriterLease();
        const auto history = recovered.ReadAll();
        ok &= Require(injected, "namespace-flush fixture should inject its requested boundary");
        ok &= Require(
            result == apfsaccess::rw::WriteAheadLog::CompactionResult::BytesMayHavePersisted,
            "failed namespace flush must report ambiguous persistence");
        ok &= Require(intent_retained, "failed namespace flush must retain recovery evidence");
        ok &= Require(recovered_lease, "a later successful namespace flush should resolve retained evidence");
        ok &= Require(
            history.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                !history.records.empty() &&
                history.records.front().sequence == flush_case.expected_first_sequence,
            "namespace-flush recovery should preserve one coherent WAL history");
        ok &= Require(
            flush_case.expect_completion_proof
                ? HasCompletedCompactionProof(path)
                : !std::filesystem::exists(CompactionIntentPath(path)),
            "namespace-flush recovery should retain only the proof appropriate to its boundary");
    }

    const auto clear_path = root / "compact-namespace-flush-intent-clear.wal";
    apfsaccess::rw::WriteAheadLog clear_wal({ clear_path, kVolume, 0 });
    if (!Require(clear_wal.Append(MakeRecord(1), false), "intent-clear fixture should append first record") ||
        !Require(clear_wal.Append(MakeRecord(2)), "intent-clear fixture should append second record"))
    {
        return false;
    }
    bool replace_failed = false;
    bool clear_flush_failed = false;
    clear_wal.SetFaultInjectionHook([&](std::string_view stage)
    {
        if (stage == "compact-replace-call" && !replace_failed)
        {
            replace_failed = true;
            return true;
        }
        if (stage == "compact-intent-clear-directory-flush" && !clear_flush_failed)
        {
            clear_flush_failed = true;
            return true;
        }
        return false;
    });
    const auto clear_result = clear_wal.CompactWithResult(
        2,
        clear_wal.ExclusiveWriterLeaseGeneration());
    clear_wal.SetFaultInjectionHook({});
    const bool clear_intent_retained = std::filesystem::exists(CompactionIntentPath(clear_path));
    apfsaccess::rw::WriteAheadLog clear_recovery({ clear_path, kVolume, 0 });
    const bool clear_recovered = clear_recovery.AcquireExclusiveWriterLease();
    const auto clear_history = clear_recovery.ReadAll();
    return ok &&
           Require(replace_failed, "intent-clear fixture should reject canonical replacement") &&
           Require(clear_flush_failed, "intent-clear fixture should fail the deletion namespace flush") &&
           Require(
               clear_result == apfsaccess::rw::WriteAheadLog::CompactionResult::BytesMayHavePersisted,
               "failed intent deletion flush must remain ambiguous") &&
           Require(clear_intent_retained, "failed intent deletion flush must republish recovery evidence") &&
           Require(clear_recovered, "republished rollback evidence should resolve on retry") &&
           Require(
               !std::filesystem::exists(CompactionIntentPath(clear_path)),
               "successful rollback retry should remove the non-final intent") &&
           Require(
               clear_history.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                   clear_history.records.size() == 2 &&
                   clear_history.records.front().sequence == 1,
               "intent-clear retry should preserve the predecessor WAL");
}

bool TestPreReplacementCompactionIntentResolvesOnRestart(const std::filesystem::path& root)
{
    const auto path = root / "compact-intent-before-replace.wal";
    {
        apfsaccess::rw::WriteAheadLog wal({ path, kVolume, 0 });
        if (!Require(wal.Append(MakeRecord(1)), "pre-replacement intent fixture should append"))
        {
            return false;
        }
    }

    const auto intent = MakeCurrentWalCompactionIntent(path);
    if (!Require(!intent.empty(), "pre-replacement intent fixture should capture the WAL identity") ||
        !Require(
            WriteBytes(CompactionIntentPath(path), intent, std::ios::trunc),
            "pre-replacement intent fixture should persist an intent record"))
    {
        return false;
    }

    apfsaccess::rw::WriteAheadLog recovered({ path, kVolume, 0 });
    const bool acquired = recovered.AcquireExclusiveWriterLease();
    const auto snapshot = recovered.ReadAll();
    return Require(acquired, "restart should resolve intent when pathname replacement never happened") &&
           Require(
               !std::filesystem::exists(CompactionIntentPath(path)),
               "unchanged-WAL compaction intent should be cleared") &&
           Require(
               snapshot.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                   snapshot.records.size() == 1 &&
                   snapshot.records.front().sequence == 1,
               "pre-replacement intent recovery should preserve the original WAL");
}

bool TestCompactionReplaceFailureProvesPredecessorBeforeClearingIntent(
    const std::filesystem::path& root)
{
    const auto preserved_path = root / "compact-replace-failure-preserved.wal";
    {
        apfsaccess::rw::WriteAheadLog preserved({ preserved_path, kVolume, 0 });
        if (!Require(
                preserved.Append(MakeRecord(1), false) && preserved.Append(MakeRecord(2)),
                "replace-failure fixture should append its original WAL history"))
        {
            return false;
        }
        preserved.SetFaultInjectionHook([](std::string_view stage)
        {
            return stage == "compact-replace-call";
        });
        const auto preserved_result = preserved.CompactWithResult(
            2,
            preserved.ExclusiveWriterLeaseGeneration());
        preserved.SetFaultInjectionHook({});
        const auto preserved_history = preserved.ReadAll();
        if (!Require(
                preserved_result == apfsaccess::rw::WriteAheadLog::CompactionResult::RejectedBeforeWrite,
                "a failed replace with the exact predecessor intact should be a pre-write rejection") ||
            !Require(
                !std::filesystem::exists(CompactionIntentPath(preserved_path)),
                "a proven intact predecessor should allow compaction intent cleanup") ||
            !Require(
                preserved_history.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                    preserved_history.records.size() == 2 &&
                    preserved_history.records.front().sequence == 1,
                "failed replacement should preserve the predecessor history"))
        {
            return false;
        }
    }

    const auto missing_path = root / "compact-replace-failure-missing.wal";
    apfsaccess::rw::WriteAheadLog missing({ missing_path, kVolume, 0 });
    if (!Require(
            missing.Append(MakeRecord(1), false) && missing.Append(MakeRecord(2)),
            "missing-predecessor fixture should append its original WAL history"))
    {
        return false;
    }
    bool predecessor_removed = false;
    missing.SetFaultInjectionHook([&](std::string_view stage)
    {
        if (stage == "compact-replace-call")
        {
            predecessor_removed = DeleteFileW(missing_path.wstring().c_str()) != FALSE;
            return true;
        }
        return false;
    });
    const auto missing_result = missing.CompactWithResult(
        2,
        missing.ExclusiveWriterLeaseGeneration());
    missing.SetFaultInjectionHook({});
    const bool intent_retained = std::filesystem::exists(CompactionIntentPath(missing_path));
    apfsaccess::rw::WriteAheadLog recovered_restart({ missing_path, kVolume, 0 });
    const bool restarted = recovered_restart.AcquireExclusiveWriterLease();
    const auto recovered_history = recovered_restart.ReadAll();
    return Require(predecessor_removed, "replace-failure fixture should remove the predecessor") &&
           Require(
               missing_result == apfsaccess::rw::WriteAheadLog::CompactionResult::BytesMayHavePersisted,
               "a failed replace without the predecessor must remain ambiguous") &&
           Require(intent_retained, "missing predecessor must retain compaction intent") &&
            Require(restarted, "restart should restore the retained predecessor after an armed publication gap") &&
            Require(
                recovered_history.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                    recovered_history.records.size() == 2 &&
                    recovered_history.records.front().sequence == 1,
                "armed-gap recovery must restore the complete predecessor history") &&
            Require(
                !std::filesystem::exists(CompactionIntentPath(missing_path)),
                "restored predecessor recovery should clear its resolved intent");
}

bool TestAmbiguousIntentPublicationRetainsRecoveryEvidence(const std::filesystem::path& root)
{
    const auto path = root / "ambiguous-intent-publication.wal";
    apfsaccess::rw::WriteAheadLog wal({ path, kVolume, 0 });
    if (!Require(wal.Append(MakeRecord(1), false), "ambiguous-intent fixture should append its first record") ||
        !Require(wal.Append(MakeRecord(2)), "ambiguous-intent fixture should append its second record"))
    {
        return false;
    }

    bool publication_fault_invoked = false;
    wal.SetFaultInjectionHook([&](std::string_view stage)
    {
        if (stage == "compact-intent-publish-ambiguous" && !publication_fault_invoked)
        {
            publication_fault_invoked = true;
            return true;
        }
        return false;
    });
    const auto result = wal.CompactWithResult(2, wal.ExclusiveWriterLeaseGeneration());
    wal.SetFaultInjectionHook({});

    const auto intent_path = CompactionIntentPath(path);
    const bool intent_retained = std::filesystem::exists(intent_path);
    const auto intent = apfsaccess::rw::WriteAheadLog::ReadAll(intent_path, kVolume);
    const auto canonical_before_recovery = apfsaccess::rw::WriteAheadLog::ReadAll(path, kVolume);
    apfsaccess::rw::WriteAheadLog recovered({ path, kVolume, 0 });
    const bool recovered_acquired = recovered.AcquireExclusiveWriterLease();
    const auto canonical_after_recovery = apfsaccess::rw::WriteAheadLog::ReadAll(path, kVolume);

    return Require(publication_fault_invoked, "ambiguous-intent test should stop after publishing the intent") &&
           Require(
               result == apfsaccess::rw::WriteAheadLog::CompactionResult::BytesMayHavePersisted,
               "ambiguous intent publication must report that bytes may have persisted") &&
           Require(intent_retained, "ambiguous intent publication must retain the published marker") &&
           Require(
               intent.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                   intent.records.size() == 1 &&
                   intent.records.front().state ==
                       apfsaccess::rw::WriteAheadLog::RecordState::Prepared,
               "retained ambiguous intent should remain checksum-valid and prepared") &&
           Require(
               canonical_before_recovery.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                   canonical_before_recovery.records.size() == 2 &&
                   canonical_before_recovery.records.front().sequence == 1,
               "ambiguous intent publication before replacement must preserve the predecessor history") &&
           Require(recovered_acquired, "restart should resolve the retained pre-replacement intent") &&
           Require(!std::filesystem::exists(intent_path), "resolved pre-replacement intent should be removed") &&
           Require(
               canonical_after_recovery.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                   canonical_after_recovery.records.size() == 2 &&
                   canonical_after_recovery.records.front().sequence == 1,
                 "intent recovery must not alter the predecessor WAL history");
}

bool TestAliasedRetainedCompactionTempFailsClosed(
    const std::filesystem::path& root)
{
    const auto path = root / "aliased-retained-compaction-temp.wal";
    const auto alias = root / "aliased-retained-compaction-temp-alias.wal";
    apfsaccess::rw::WriteAheadLog wal({ path, kVolume, 0 });
    if (!Require(wal.Append(MakeRecord(1), false), "retained-temp fixture should append first record") ||
        !Require(wal.Append(MakeRecord(2)), "retained-temp fixture should append second record"))
    {
        return false;
    }

    bool publication_stopped = false;
    wal.SetFaultInjectionHook([&](std::string_view stage)
    {
        if (stage == "compact-after-publish-armed")
        {
            publication_stopped = true;
            return true;
        }
        return false;
    });
    const auto result = wal.CompactWithResult(2, wal.ExclusiveWriterLeaseGeneration());
    wal.SetFaultInjectionHook({});

    const auto temps = FindCompactionTemps(path);
    const bool alias_created = temps.size() == 1 &&
        CreateHardLinkW(alias.wstring().c_str(), temps.front().wstring().c_str(), nullptr) != FALSE;
    apfsaccess::rw::WriteAheadLog blocked({ path, kVolume, 0 });
    const bool blocked_acquired = alias_created && blocked.AcquireExclusiveWriterLease();
    const bool intent_retained = std::filesystem::exists(CompactionIntentPath(path));
    const bool temp_retained = temps.size() == 1 && std::filesystem::exists(temps.front());

    std::error_code remove_ec;
    const bool alias_removed = std::filesystem::remove(alias, remove_ec) && !remove_ec;
    apfsaccess::rw::WriteAheadLog recovered({ path, kVolume, 0 });
    const bool recovered_acquired = alias_removed && recovered.AcquireExclusiveWriterLease();
    const auto history = recovered.ReadAll();
    return Require(publication_stopped, "retained-temp fixture should stop after arming publication") &&
           Require(
               result == apfsaccess::rw::WriteAheadLog::CompactionResult::BytesMayHavePersisted,
               "armed publication failure must retain its compacted temp") &&
           Require(alias_created, "retained-temp fixture should create a hard-link alias") &&
           Require(!blocked_acquired, "recovery must reject an aliased retained compacted temp") &&
           Require(intent_retained, "blocked retained-temp cleanup must retain compaction intent") &&
           Require(temp_retained, "blocked retained-temp cleanup must preserve the identified temp") &&
           Require(alias_removed, "retained-temp fixture should remove its alias") &&
           Require(recovered_acquired, "recovery should resume after the retained-temp alias is removed") &&
           Require(FindCompactionTemps(path).empty(), "successful rollback should delete the retained temp") &&
           Require(
               !std::filesystem::exists(CompactionIntentPath(path)),
               "successful retained-temp rollback should clear compaction intent") &&
           Require(
               history.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                   history.records.size() == 2 &&
                   history.records.front().sequence == 1,
               "retained-temp rollback should preserve the predecessor history");
}

bool TestRetainedCompactionTempRejectsLateHardLinkRace(
    const std::filesystem::path& root)
{
    const auto path = root / "retained-compaction-temp-late-link.wal";
    const auto alias = root / "retained-compaction-temp-late-link-alias.wal";
    apfsaccess::rw::WriteAheadLog wal({ path, kVolume, 0 });
    if (!Require(wal.Append(MakeRecord(1), false), "late-link fixture should append first record") ||
        !Require(wal.Append(MakeRecord(2)), "late-link fixture should append second record"))
    {
        return false;
    }

    wal.SetFaultInjectionHook([](std::string_view stage)
    {
        return stage == "compact-after-publish-armed";
    });
    const auto result = wal.CompactWithResult(2, wal.ExclusiveWriterLeaseGeneration());
    wal.SetFaultInjectionHook({});
    const auto temps = FindCompactionTemps(path);

    bool handoff_reached = false;
    bool alias_created = false;
    DWORD alias_error = ERROR_SUCCESS;
    apfsaccess::rw::WriteAheadLog recovered({ path, kVolume, 0 });
    recovered.SetFaultInjectionHook([&](std::string_view stage)
    {
        if (stage == "compact-retained-temp-delete-handoff")
        {
            handoff_reached = true;
            alias_created = CreateHardLinkW(
                                alias.wstring().c_str(),
                                temps.front().wstring().c_str(),
                                nullptr) != FALSE;
            alias_error = alias_created ? ERROR_SUCCESS : GetLastError();
        }
        return false;
    });
    const bool recovered_acquired = temps.size() == 1 && recovered.AcquireExclusiveWriterLease();
    recovered.SetFaultInjectionHook({});
    const auto history = recovered.ReadAll();

    return Require(
               result == apfsaccess::rw::WriteAheadLog::CompactionResult::BytesMayHavePersisted,
               "late-link fixture should retain its armed compacted temp") &&
           Require(temps.size() == 1, "late-link fixture should leave one compacted temp") &&
           Require(handoff_reached, "recovery should reach the retained-temp delete handoff") &&
           Require(!alias_created, "retained-temp cleanup must deny a late hard-link race") &&
           Require(
               alias_error == ERROR_SHARING_VIOLATION || alias_error == ERROR_ACCESS_DENIED,
               "late hard-link denial should be an access or sharing refusal") &&
           Require(recovered_acquired, "denying the late hard link should let recovery finish") &&
           Require(!std::filesystem::exists(alias), "the denied late hard link must not leave an alias") &&
           Require(FindCompactionTemps(path).empty(), "recovery should delete the retained compacted temp") &&
           Require(
               !std::filesystem::exists(CompactionIntentPath(path)),
               "successful retained-temp rollback should clear compaction intent") &&
           Require(
               history.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                   history.records.size() == 2 &&
                   history.records.front().sequence == 1,
               "late-link recovery should preserve predecessor history");
}

bool TestUnsafePreIntentCompactionOrphansFailClosed(
    const std::filesystem::path& root)
{
    struct OrphanCase
    {
        const char* stem;
        const wchar_t* suffix;
    };
    const std::array cases{
        OrphanCase{ "aliased-pre-intent-compact", L".compact.123.456" },
        OrphanCase{ "aliased-pre-intent-intent", L".compact.intent.tmp.123.456" },
    };

    bool ok = true;
    for (const auto& orphan_case : cases)
    {
        const auto path = root / (std::string(orphan_case.stem) + ".wal");
        auto orphan = path;
        orphan += orphan_case.suffix;
        const auto alias = root / (std::string(orphan_case.stem) + "-alias.bin");
        {
            apfsaccess::rw::WriteAheadLog seed({ path, kVolume, 0 });
            ok &= Require(seed.Append(MakeRecord(1)), "orphan-alias fixture should seed its WAL");
        }
        {
            std::ofstream output(orphan, std::ios::binary | std::ios::trunc);
            output << "pre-intent-orphan";
            ok &= Require(output.good(), "orphan-alias fixture should create its exact internal name");
        }
        const bool alias_created =
            CreateHardLinkW(alias.wstring().c_str(), orphan.wstring().c_str(), nullptr) != FALSE;
        apfsaccess::rw::WriteAheadLog blocked({ path, kVolume, 0 });
        const bool blocked_acquired = alias_created && blocked.AcquireExclusiveWriterLease();
        const bool orphan_retained = std::filesystem::exists(orphan);

        std::error_code remove_ec;
        const bool alias_removed = std::filesystem::remove(alias, remove_ec) && !remove_ec;
        apfsaccess::rw::WriteAheadLog recovered({ path, kVolume, 0 });
        const bool recovered_acquired = alias_removed && recovered.AcquireExclusiveWriterLease();
        const auto history = recovered.ReadAll();

        ok &= Require(alias_created, "orphan-alias fixture should create a hard-link alias");
        ok &= Require(!blocked_acquired, "writer startup must refuse an aliased exact orphan");
        ok &= Require(orphan_retained, "refused orphan cleanup must retain its known path");
        ok &= Require(alias_removed, "orphan-alias fixture should remove its external alias");
        ok &= Require(recovered_acquired, "startup cleanup should resume after the alias is removed");
        ok &= Require(!std::filesystem::exists(orphan), "safe restart should reclaim the exact orphan");
        ok &= Require(
            history.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                history.records.size() == 1 &&
                history.records.front().sequence == 1,
            "orphan cleanup must preserve canonical WAL history");
    }
    return ok;
}

bool TestPreIntentOrphanCleanupIgnoresLookalikes(
    const std::filesystem::path& root)
{
    const auto path = root / "pre-intent-orphan-lookalikes.wal";
    {
        apfsaccess::rw::WriteAheadLog seed({ path, kVolume, 0 });
        if (!Require(seed.Append(MakeRecord(1)), "orphan-lookalike fixture should seed its WAL"))
        {
            return false;
        }
    }

    std::array<std::filesystem::path, 11> lookalikes;
    const std::array suffixes{
        L".compact.x.1",
        L".compact.1.x",
        L".compact.1.2.extra",
        L".compact.01.2",
        L".compact.1.02",
        L".compact.4294967296.1",
        L".compact.intent.tmp.x.1",
        L".compact.intent.tmp.1.x",
        L".compact.intent.tmp.1.2.extra",
        L".compact.intent.tmp.1.18446744073709551616",
        L".compact.predecessor.123",
    };
    bool fixtures_created = true;
    for (std::size_t index = 0; index < lookalikes.size(); ++index)
    {
        lookalikes[index] = path;
        lookalikes[index] += suffixes[index];
        std::ofstream output(lookalikes[index], std::ios::binary | std::ios::trunc);
        output << "unrelated-lookalike";
        fixtures_created &= output.good();
    }

    apfsaccess::rw::WriteAheadLog wal({ path, kVolume, 0 });
    const bool acquired = fixtures_created && wal.AcquireExclusiveWriterLease();
    const bool all_retained = std::all_of(
        lookalikes.begin(),
        lookalikes.end(),
        [](const auto& lookalike) { return std::filesystem::exists(lookalike); });
    return Require(fixtures_created, "orphan-lookalike fixture should create every unrelated name") &&
           Require(acquired, "unrelated orphan lookalikes must not block writer startup") &&
           Require(all_retained, "startup cleanup must not remove unrelated lookalike names");
}

bool TestPreIntentOrphanSharingConflictFailsClosed(
    const std::filesystem::path& root)
{
    const auto path = root / "pre-intent-orphan-sharing.wal";
    auto orphan = path;
    orphan += L".compact.123.456";
    {
        apfsaccess::rw::WriteAheadLog seed({ path, kVolume, 0 });
        if (!Require(seed.Append(MakeRecord(1)), "orphan-sharing fixture should seed its WAL"))
        {
            return false;
        }
    }
    {
        std::ofstream output(orphan, std::ios::binary | std::ios::trunc);
        output << "held-pre-intent-orphan";
        if (!Require(output.good(), "orphan-sharing fixture should create its exact orphan"))
        {
            return false;
        }
    }

    auto* held = CreateFileW(
        orphan.wstring().c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    apfsaccess::rw::WriteAheadLog blocked({ path, kVolume, 0 });
    const bool blocked_acquired =
        held != INVALID_HANDLE_VALUE && blocked.AcquireExclusiveWriterLease();
    const bool orphan_retained = std::filesystem::exists(orphan);
    const bool held_closed = held != INVALID_HANDLE_VALUE && CloseHandle(held) != FALSE;

    apfsaccess::rw::WriteAheadLog recovered({ path, kVolume, 0 });
    const bool recovered_acquired = held_closed && recovered.AcquireExclusiveWriterLease();
    return Require(held != INVALID_HANDLE_VALUE, "orphan-sharing fixture should hold its orphan open") &&
           Require(!blocked_acquired, "sharing-conflicted orphan cleanup must fail closed") &&
           Require(orphan_retained, "sharing-conflicted cleanup must retain the orphan") &&
           Require(held_closed, "orphan-sharing fixture should release its handle") &&
           Require(recovered_acquired, "cleanup should resume after the sharing conflict clears") &&
           Require(!std::filesystem::exists(orphan), "safe retry should reclaim the released orphan");
}

bool TestPreIntentReparseOrphanFailsClosed(
    const std::filesystem::path& root)
{
    const auto path = root / "pre-intent-reparse-orphan.wal";
    const auto target = root / "pre-intent-reparse-target.bin";
    auto orphan = path;
    orphan += L".compact.intent.tmp.123.456";
    {
        apfsaccess::rw::WriteAheadLog seed({ path, kVolume, 0 });
        if (!Require(seed.Append(MakeRecord(1)), "reparse-orphan fixture should seed its WAL"))
        {
            return false;
        }
    }
    {
        std::ofstream output(target, std::ios::binary | std::ios::trunc);
        output << "unrelated-reparse-target";
        if (!Require(output.good(), "reparse-orphan fixture should create its target"))
        {
            return false;
        }
    }

    constexpr DWORD allow_unprivileged_create = 0x2;
    bool created = CreateSymbolicLinkW(
        orphan.wstring().c_str(),
        target.wstring().c_str(),
        allow_unprivileged_create) != FALSE;
    auto create_error = created ? ERROR_SUCCESS : GetLastError();
    if (!created && create_error == ERROR_INVALID_PARAMETER)
    {
        created = CreateSymbolicLinkW(orphan.wstring().c_str(), target.wstring().c_str(), 0) != FALSE;
        create_error = created ? ERROR_SUCCESS : GetLastError();
    }
    if (!created &&
        (create_error == ERROR_PRIVILEGE_NOT_HELD || create_error == ERROR_NOT_SUPPORTED))
    {
        std::cout << "[SKIP] pre-intent reparse orphan test requires symbolic-link support." << std::endl;
        return true;
    }
    if (!Require(created, "reparse-orphan fixture should create its exact-name symlink"))
    {
        return false;
    }

    apfsaccess::rw::WriteAheadLog blocked({ path, kVolume, 0 });
    const bool blocked_acquired = blocked.AcquireExclusiveWriterLease();
    const auto orphan_attributes = GetFileAttributesW(orphan.wstring().c_str());
    const bool orphan_retained =
        orphan_attributes != INVALID_FILE_ATTRIBUTES &&
        (orphan_attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
    const bool target_retained = std::filesystem::exists(target);
    return Require(!blocked_acquired, "exact-name reparse orphan cleanup must fail closed") &&
           Require(orphan_retained, "refused reparse cleanup must retain the symlink") &&
           Require(target_retained, "refused reparse cleanup must preserve the unrelated target");
}

bool TestIntentPublicationNeverOverwritesUnrelatedDestination(
    const std::filesystem::path& root)
{
    const auto path = root / "intent-publication-collision.wal";
    const auto intent_path = CompactionIntentPath(path);
    constexpr std::string_view sentinel = "unrelated-intent-destination";
    apfsaccess::rw::WriteAheadLog wal({ path, kVolume, 0 });
    if (!Require(wal.Append(MakeRecord(1), false), "intent-collision fixture should append first record") ||
        !Require(wal.Append(MakeRecord(2)), "intent-collision fixture should append second record"))
    {
        return false;
    }

    bool destination_installed = false;
    wal.SetFaultInjectionHook([&](std::string_view stage)
    {
        if (stage == "compact-intent-publication-handoff")
        {
            std::ofstream unrelated(intent_path, std::ios::binary | std::ios::trunc);
            unrelated.write(sentinel.data(), static_cast<std::streamsize>(sentinel.size()));
            destination_installed = unrelated.good();
        }
        return false;
    });
    const auto result = wal.CompactWithResult(2, wal.ExclusiveWriterLeaseGeneration());
    wal.SetFaultInjectionHook({});

    std::ifstream unrelated(intent_path, std::ios::binary);
    const std::string unrelated_bytes{
        std::istreambuf_iterator<char>(unrelated),
        std::istreambuf_iterator<char>()};
    unrelated.close();
    const auto temps_after_failure = FindCompactionTemps(path);
    std::error_code remove_ec;
    const bool unrelated_removed =
        std::filesystem::remove(intent_path, remove_ec) && !remove_ec;
    apfsaccess::rw::WriteAheadLog recovered({ path, kVolume, 0 });
    const bool recovered_lease = unrelated_removed && recovered.AcquireExclusiveWriterLease();
    const auto history = recovered.ReadAll();
    return Require(destination_installed, "intent-collision fixture should install its destination") &&
           Require(
               result == apfsaccess::rw::WriteAheadLog::CompactionResult::RejectedBeforeWrite,
               "an initial intent collision should reject before publishing compaction state") &&
           Require(unrelated_bytes == sentinel, "intent publication must preserve an unrelated destination") &&
           Require(temps_after_failure.empty(), "rejected intent publication must remove its compacted temp") &&
           Require(unrelated_removed, "intent-collision fixture should remove its destination") &&
           Require(recovered_lease, "removing the unrelated intent destination should restore WAL access") &&
           Require(
               history.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                   history.records.size() == 2 &&
                   history.records.front().sequence == 1,
               "intent publication collision must preserve predecessor history");
}

bool TestIntentStateAppendNeverOverwritesSwappedDestination(
    const std::filesystem::path& root)
{
    const auto path = root / "intent-state-swap.wal";
    const auto intent_path = CompactionIntentPath(path);
    const auto displaced_intent = root / "intent-state-swap.displaced";
    constexpr std::string_view sentinel = "unrelated-swapped-intent";
    apfsaccess::rw::WriteAheadLog wal({ path, kVolume, 0 });
    if (!Require(wal.Append(MakeRecord(1), false), "intent-swap fixture should append first record") ||
        !Require(wal.Append(MakeRecord(2)), "intent-swap fixture should append second record"))
    {
        return false;
    }

    bool intent_displaced = false;
    bool destination_installed = false;
    wal.SetFaultInjectionHook([&](std::string_view stage)
    {
        if (stage == "compact-intent-state-append-ambiguous" && !intent_displaced)
        {
            intent_displaced = MoveFileExW(
                                   intent_path.wstring().c_str(),
                                   displaced_intent.wstring().c_str(),
                                   MOVEFILE_WRITE_THROUGH) != FALSE;
            if (intent_displaced)
            {
                std::ofstream unrelated(intent_path, std::ios::binary | std::ios::trunc);
                unrelated.write(sentinel.data(), static_cast<std::streamsize>(sentinel.size()));
                destination_installed = unrelated.good();
            }
        }
        return false;
    });
    const auto result = wal.CompactWithResult(2, wal.ExclusiveWriterLeaseGeneration());
    wal.SetFaultInjectionHook({});

    std::ifstream unrelated(intent_path, std::ios::binary);
    const std::string unrelated_bytes{
        std::istreambuf_iterator<char>(unrelated),
        std::istreambuf_iterator<char>()};
    unrelated.close();
    const bool temp_retained = FindCompactionTemps(path).size() == 1;
    apfsaccess::rw::WriteAheadLog blocked({ path, kVolume, 0 });
    const bool blocked_lease = blocked.AcquireExclusiveWriterLease();
    std::error_code remove_ec;
    const bool unrelated_removed =
        std::filesystem::remove(intent_path, remove_ec) && !remove_ec;
    const bool intent_restored =
        unrelated_removed &&
        MoveFileExW(
            displaced_intent.wstring().c_str(),
            intent_path.wstring().c_str(),
            MOVEFILE_WRITE_THROUGH) != FALSE;
    apfsaccess::rw::WriteAheadLog recovered({ path, kVolume, 0 });
    const bool recovered_lease = intent_restored && recovered.AcquireExclusiveWriterLease();
    const auto history = recovered.ReadAll();
    return Require(intent_displaced, "intent-swap fixture should displace the pinned intent") &&
           Require(destination_installed, "intent-swap fixture should install an unrelated destination") &&
           Require(
               result == apfsaccess::rw::WriteAheadLog::CompactionResult::BytesMayHavePersisted,
               "an intent state-path swap must retain recovery evidence") &&
           Require(unrelated_bytes == sentinel, "intent state append must not overwrite a swapped destination") &&
           Require(temp_retained, "blocked intent state append should retain the identified compacted temp") &&
           Require(!blocked_lease, "restart must fail closed while the unrelated intent destination remains") &&
           Require(intent_restored, "intent-swap fixture should restore the displaced recovery evidence") &&
           Require(recovered_lease, "restored intent evidence should roll back the interrupted compaction") &&
           Require(FindCompactionTemps(path).empty(), "intent rollback must remove the retained compacted temp") &&
           Require(
               history.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                   history.records.size() == 2 &&
                   history.records.front().sequence == 1,
               "intent state-path swap recovery must preserve predecessor history");
}

bool TestCompactionUsesUnredirectableUniqueTemp(const std::filesystem::path& root)
{
    const auto path = root / "compact-unique-temp-source.wal";
    const auto trap = root / "compact-unique-temp-trap.wal";
    auto fixed_temp = path;
    fixed_temp += L".compact";
    {
        apfsaccess::rw::WriteAheadLog trap_wal({ trap, kVolume, 0 });
        if (!Require(trap_wal.Append(MakeRecord(99)), "temp trap should contain a valid WAL record"))
        {
            return false;
        }
    }
    if (!Require(
            CreateHardLinkW(fixed_temp.wstring().c_str(), trap.wstring().c_str(), nullptr) != FALSE,
            "temp trap should occupy the former fixed compaction path"))
    {
        return false;
    }

    apfsaccess::rw::WriteAheadLog wal({ path, kVolume, 0 });
    if (!Require(
            wal.Append(MakeRecord(1), false) && wal.Append(MakeRecord(2)),
            "unique-temp fixture should append source history"))
    {
        return false;
    }
    const auto result = wal.CompactWithResult(2, wal.ExclusiveWriterLeaseGeneration());
    const auto compacted = wal.ReadAll();
    const auto trap_history = apfsaccess::rw::WriteAheadLog::ReadAll(trap, kVolume);
    return Require(
               result == apfsaccess::rw::WriteAheadLog::CompactionResult::Succeeded,
               "a preexisting fixed temp alias must not block unique-temp compaction") &&
           Require(
               compacted.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                   compacted.records.size() == 2 &&
                   compacted.records.front().sequence == 2,
               "unique-temp compaction should publish the compacted source history") &&
           Require(
               trap_history.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                   trap_history.records.size() == 1 &&
                   trap_history.records.front().sequence == 99,
               "compaction must not truncate or rewrite a fixed-path trap file") &&
           Require(std::filesystem::exists(fixed_temp), "compaction must leave the unrelated trap alias intact");
}

bool TestMalformedCompactionIntentFailsClosed(const std::filesystem::path& root)
{
    const auto invalid_path = root / "compact-intent-invalid.wal";
    {
        apfsaccess::rw::WriteAheadLog wal({ invalid_path, kVolume, 0 });
        if (!Require(wal.Append(MakeRecord(1)), "invalid intent fixture should append"))
        {
            return false;
        }
    }
    const std::vector<std::uint8_t> invalid_bytes{0x41, 0x42, 0x43, 0x44};
    if (!Require(
            WriteBytes(CompactionIntentPath(invalid_path), invalid_bytes, std::ios::trunc),
            "invalid intent fixture should write malformed bytes"))
    {
        return false;
    }

    apfsaccess::rw::WriteAheadLog invalid({ invalid_path, kVolume, 0 });
    const bool invalid_acquired = invalid.AcquireExclusiveWriterLease();
    const auto observed = apfsaccess::rw::WriteAheadLog::ReadAll(invalid_path, kVolume);
    if (!Require(!invalid_acquired, "malformed compaction intent must block writer acquisition") ||
        !Require(
            std::filesystem::exists(CompactionIntentPath(invalid_path)),
            "malformed compaction intent must be retained for diagnosis") ||
        !Require(
            observed.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                observed.records.size() == 1,
            "observer WAL reads must remain non-mutating while intent blocks writers"))
    {
        return false;
    }

    const auto torn_path = root / "compact-intent-torn.wal";
    {
        apfsaccess::rw::WriteAheadLog wal({ torn_path, kVolume, 0 });
        if (!Require(wal.Append(MakeRecord(1)), "torn intent fixture should append"))
        {
            return false;
        }
    }
    auto torn_bytes = MakeCurrentWalCompactionIntent(torn_path);
    if (!Require(torn_bytes.size() > 1, "torn intent fixture should encode a complete record"))
    {
        return false;
    }
    torn_bytes.pop_back();
    if (!Require(
            WriteBytes(CompactionIntentPath(torn_path), torn_bytes, std::ios::trunc),
            "torn intent fixture should persist a truncated record"))
    {
        return false;
    }

    apfsaccess::rw::WriteAheadLog torn({ torn_path, kVolume, 0 });
    return Require(!torn.AcquireExclusiveWriterLease(), "torn compaction intent must block writer acquisition") &&
           Require(
               std::filesystem::exists(CompactionIntentPath(torn_path)),
               "torn compaction intent must remain available for recovery diagnosis");
}

bool TestMissingWalWithCompactionIntentFailsClosed(const std::filesystem::path& root)
{
    const auto path = root / "compact-intent-missing-wal.wal";
    {
        apfsaccess::rw::WriteAheadLog wal({ path, kVolume, 0 });
        if (!Require(wal.Append(MakeRecord(1)), "missing-WAL intent fixture should append"))
        {
            return false;
        }
    }
    const auto intent = MakeCurrentWalCompactionIntent(path);
    if (!Require(!intent.empty(), "missing-WAL intent fixture should capture the WAL identity") ||
        !Require(
            WriteBytes(CompactionIntentPath(path), intent, std::ios::trunc),
            "missing-WAL intent fixture should persist an intent") ||
        !Require(std::filesystem::remove(path), "missing-WAL intent fixture should remove the canonical WAL"))
    {
        return false;
    }

    apfsaccess::rw::WriteAheadLog recovered({ path, kVolume, 0 });
    return Require(!recovered.AcquireExclusiveWriterLease(), "missing canonical WAL with intent must fail closed") &&
           Require(!std::filesystem::exists(path), "failed recovery must not create an empty replacement WAL") &&
           Require(
               std::filesystem::exists(CompactionIntentPath(path)),
               "missing-WAL recovery must retain its compaction evidence");
}

bool TestCompactionRetainsCrossProcessWriterLease(const std::filesystem::path& root)
{
    const auto path = root / "compact-cross-process-lease.wal";
    apfsaccess::rw::WriteAheadLog wal({ path, kVolume, 0 });
    if (!Require(wal.Append(MakeRecord(1), false), "cross-process compaction fixture should append first record") ||
        !Require(wal.Append(MakeRecord(2)), "cross-process compaction fixture should append second record"))
    {
        return false;
    }
    const auto expected_generation = wal.ExclusiveWriterLeaseGeneration();

    const auto unique_suffix = std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64());
    const auto ready_event_name = L"Local\\ApfsAccessWalCompactReady-" + unique_suffix;
    const auto attempt_event_name = L"Local\\ApfsAccessWalCompactAttempt-" + unique_suffix;
    const auto ready_event = CreateEventW(nullptr, TRUE, FALSE, ready_event_name.c_str());
    const auto attempt_event = CreateEventW(nullptr, TRUE, FALSE, attempt_event_name.c_str());
    if (!Require(ready_event != nullptr && attempt_event != nullptr, "cross-process compaction events should be created"))
    {
        if (ready_event != nullptr)
        {
            CloseHandle(ready_event);
        }
        if (attempt_event != nullptr)
        {
            CloseHandle(attempt_event);
        }
        return false;
    }

    std::wstring executable(32768, L'\0');
    const auto executable_chars = GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
    if (!Require(executable_chars > 0 && executable_chars < executable.size(), "cross-process test should resolve its executable"))
    {
        CloseHandle(attempt_event);
        CloseHandle(ready_event);
        return false;
    }
    executable.resize(executable_chars);

    SetEnvironmentVariableW(kCompactionChildPathEnv, path.wstring().c_str());
    SetEnvironmentVariableW(kCompactionReadyEventEnv, ready_event_name.c_str());
    SetEnvironmentVariableW(kCompactionAttemptEventEnv, attempt_event_name.c_str());
    std::wstring command_line = L"\"" + executable + L"\" cross-process-compaction-contender";
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    const bool created = CreateProcessW(
        nullptr,
        command_line.data(),
        nullptr,
        nullptr,
        FALSE,
        CREATE_NO_WINDOW,
        nullptr,
        nullptr,
        &startup,
        &process) != FALSE;
    SetEnvironmentVariableW(kCompactionAttemptEventEnv, nullptr);
    SetEnvironmentVariableW(kCompactionReadyEventEnv, nullptr);
    SetEnvironmentVariableW(kCompactionChildPathEnv, nullptr);
    if (!Require(created, "cross-process compaction contender should launch"))
    {
        CloseHandle(attempt_event);
        CloseHandle(ready_event);
        return false;
    }
    CloseHandle(process.hThread);

    bool reached_handoff = false;
    bool contender_attempted = false;
    wal.SetFaultInjectionHook([&](std::string_view stage)
    {
        if (stage == "compact-before-replace")
        {
            reached_handoff = SetEvent(ready_event) != FALSE;
            contender_attempted = WaitForSingleObject(attempt_event, 10000) == WAIT_OBJECT_0;
        }
        return false;
    });
    const auto result = wal.CompactWithResult(2, expected_generation);
    wal.SetFaultInjectionHook({});

    const auto child_wait = WaitForSingleObject(process.hProcess, 10000);
    if (child_wait != WAIT_OBJECT_0)
    {
        TerminateProcess(process.hProcess, 14);
        WaitForSingleObject(process.hProcess, 10000);
    }
    DWORD child_exit = 15;
    GetExitCodeProcess(process.hProcess, &child_exit);
    CloseHandle(process.hProcess);
    CloseHandle(attempt_event);
    CloseHandle(ready_event);

    const auto snapshot = wal.ReadAll();
    return Require(reached_handoff && contender_attempted, "cross-process contender should run in the close-before-replace window") &&
           Require(child_wait == WAIT_OBJECT_0 && child_exit == 0, "cross-process contender must not acquire the persistent writer lease") &&
           Require(result == apfsaccess::rw::WriteAheadLog::CompactionResult::Succeeded, "leased compaction should complete") &&
           Require(
               wal.ExclusiveWriterLeaseGeneration() == expected_generation,
               "compaction should retain the same writer generation across target replacement") &&
           Require(
               snapshot.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                   snapshot.records.size() == 2 &&
                   snapshot.records.front().sequence == 2,
               "cross-process compaction should retain the intended durable record set");
}

bool TestHardLinkedWalFailsWriterLeaseClosed(const std::filesystem::path& root)
{
    const auto path = root / "hard-link-source.wal";
    const auto alias = root / "hard-link-alias.wal";
    {
        apfsaccess::rw::WriteAheadLog seed({ path, kVolume, 0 });
        if (!Require(seed.Append(MakeRecord(1)), "hard-link fixture should persist its initial WAL record"))
        {
            return false;
        }
    }
    if (!Require(
            CreateHardLinkW(alias.wstring().c_str(), path.wstring().c_str(), nullptr) != FALSE,
            "hard-link fixture should create a physical alias"))
    {
        return false;
    }

    apfsaccess::rw::WriteAheadLog original({ path, kVolume, 0 });
    apfsaccess::rw::WriteAheadLog linked_alias({ alias, kVolume, 0 });
    const auto original_acquired = original.AcquireExclusiveWriterLease();
    const auto alias_acquired = linked_alias.AcquireExclusiveWriterLease();
    const auto snapshot = apfsaccess::rw::WriteAheadLog::ReadAll(path, kVolume);
    return Require(!original_acquired && !alias_acquired, "multi-link WAL paths must reject writer ownership before compaction") &&
           Require(
               snapshot.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                   snapshot.records.size() == 1 &&
                   snapshot.records.front().sequence == 1,
               "hard-link rejection must preserve the existing durable WAL");
}

bool TestWriterLeaseIsIndependentOfWalPath(const std::filesystem::path& root)
{
    const auto first_path = root / "volume-lease-first.wal";
    const auto second_path = root / "volume-lease-second.wal";
    apfsaccess::rw::WriteAheadLog owner({ first_path, kVolume, 0 });
    apfsaccess::rw::WriteAheadLog contender({ second_path, kVolume, 0 });
    if (!Require(owner.Append(MakeRecord(1)), "volume lease owner should append") ||
        !Require(!contender.AcquireExclusiveWriterLease(), "same-volume lease must not depend on the WAL pathname") ||
        !Require(owner.HasExclusiveWriterLease(), "failed alternate-path acquisition must not revoke the owner"))
    {
        return false;
    }

    return Require(owner.Append(MakeRecord(2)), "volume lease owner should remain writable") &&
           Require(!std::filesystem::exists(second_path), "blocked alternate path must not create another WAL");
}

bool TestMismatchedVolumeCannotTakeOverWalPath(const std::filesystem::path& root)
{
    const auto path = root / "mismatched-volume-takeover.wal";
    apfsaccess::rw::WriteAheadLog owner({ path, kVolume, 0 });
    if (!Require(owner.Append(MakeRecord(1)), "mismatched-volume fixture should append its first record"))
    {
        return false;
    }

    apfsaccess::rw::WriteAheadLog contender({ path, "volume-B", 0 });
    const bool contender_acquired = contender.AcquireExclusiveWriterLease();
    const bool owner_retained = owner.HasExclusiveWriterLease();
    const bool owner_appended = owner.Append(MakeRecord(2));
    const auto snapshot = apfsaccess::rw::WriteAheadLog::ReadAll(path, kVolume);
    return Require(!contender_acquired, "a different volume identity must not take over an existing WAL path") &&
           Require(owner_retained, "failed mismatched takeover must preserve the healthy writer lease") &&
           Require(owner_appended, "the preserved writer should remain appendable after a failed takeover") &&
           Require(
               snapshot.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                   snapshot.records.size() == 2 &&
                   snapshot.records.back().sequence == 2,
               "failed mismatched takeover must preserve one coherent WAL history");
}

bool TestOwnerlessWalAndExplicitRecordsRemainVolumeBound(const std::filesystem::path& root)
{
    const auto path = root / "ownerless-volume-binding.wal";
    {
        apfsaccess::rw::WriteAheadLog owner({ path, kVolume, 0 });
        if (!Require(owner.Append(MakeRecord(1)), "ownerless volume fixture should append its first record"))
        {
            return false;
        }
    }

    bool mismatched_owner_rejected = false;
    {
        apfsaccess::rw::WriteAheadLog mismatched_owner({ path, "volume-B", 0 });
        mismatched_owner_rejected = !mismatched_owner.AcquireExclusiveWriterLease();
    }

    apfsaccess::rw::WriteAheadLog owner({ path, kVolume, 0 });
    auto mismatched_record = MakeRecord(2);
    mismatched_record.volume_identity = "volume-B";
    const auto single_result = owner.AppendWithResult(mismatched_record);

    auto valid_batch_record = MakeRecord(2);
    auto mismatched_batch_record = MakeRecord(3);
    mismatched_batch_record.volume_identity = "volume-B";
    const auto batch_result = owner.AppendBatchWithResult(
        { valid_batch_record, mismatched_batch_record });
    const auto snapshot = apfsaccess::rw::WriteAheadLog::ReadAll(path, kVolume);

    return Require(
               mismatched_owner_rejected,
               "an ownerless WAL must still reject a different configured volume identity") &&
           Require(
               single_result == apfsaccess::rw::WriteAheadLog::AppendResult::RejectedBeforeWrite,
               "single append must reject an explicit mismatched record identity") &&
           Require(
               batch_result == apfsaccess::rw::WriteAheadLog::AppendResult::RejectedBeforeWrite,
               "batch append must reject every explicit mismatched record identity atomically") &&
           Require(
               snapshot.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                   snapshot.records.size() == 1 &&
                   snapshot.records.front().sequence == 1,
               "identity rejection must preserve the original WAL without a partial batch");
}

bool TestCompactionHandoffBlocksRawWalAppend(const std::filesystem::path& root)
{
    const auto path = root / "raw-writer-handoff.wal";
    apfsaccess::rw::WriteAheadLog wal({ path, kVolume, 0 });
    if (!Require(wal.Append(MakeRecord(1), false), "raw-writer fixture should append its first record") ||
        !Require(wal.Append(MakeRecord(2)), "raw-writer fixture should append its second record"))
    {
        return false;
    }

    bool append_attempted = false;
    bool append_blocked = false;
    wal.SetFaultInjectionHook([&](std::string_view stage)
    {
        if (stage != "compact-replace-handoff")
        {
            return false;
        }

        append_attempted = true;
        const auto encoded = apfsaccess::rw::WriteAheadLog::EncodeForTest(MakeRecord(99));
        auto* raw_writer = CreateFileW(
            path.wstring().c_str(),
            FILE_APPEND_DATA,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (raw_writer == INVALID_HANDLE_VALUE)
        {
            append_blocked = GetLastError() == ERROR_SHARING_VIOLATION;
            return false;
        }

        DWORD written = 0;
        const bool appended = WriteFile(
                                  raw_writer,
                                  encoded.data(),
                                  static_cast<DWORD>(encoded.size()),
                                  &written,
                                  nullptr) != FALSE &&
                              written == encoded.size() &&
                              FlushFileBuffers(raw_writer) != FALSE;
        append_blocked = !appended && GetLastError() == ERROR_LOCK_VIOLATION;
        CloseHandle(raw_writer);
        return false;
    });
    const auto result = wal.CompactWithResult(2, wal.ExclusiveWriterLeaseGeneration());
    wal.SetFaultInjectionHook({});

    const auto snapshot = apfsaccess::rw::WriteAheadLog::ReadAll(path, kVolume);
    return Require(append_attempted, "compaction should expose the raw-writer handoff boundary") &&
           Require(append_blocked, "the handoff must deny or lock out a raw concurrent append") &&
           Require(
               result == apfsaccess::rw::WriteAheadLog::CompactionResult::Succeeded,
               "a blocked raw append should not prevent compaction") &&
           Require(
               snapshot.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                   snapshot.records.size() == 2 &&
                   snapshot.records.front().sequence == 2 &&
                   snapshot.records.back().operation ==
                       apfsaccess::rw::WriteAheadLog::OperationKind::CompactionIndex,
               "compaction should retain only the intended coherent history");
}

bool TestHardLinkRaceDuringCompactionFailsBeforeReplace(const std::filesystem::path& root)
{
    const auto path = root / "hard-link-race-source.wal";
    const auto alias = root / "hard-link-race-alias.wal";
    apfsaccess::rw::WriteAheadLog wal({ path, kVolume, 0 });
    if (!Require(wal.Append(MakeRecord(1), false), "hard-link race fixture should append first record") ||
        !Require(wal.Append(MakeRecord(2)), "hard-link race fixture should append second record"))
    {
        return false;
    }

    bool link_created = false;
    wal.SetFaultInjectionHook([&](std::string_view stage)
    {
        if (stage == "compact-before-replace")
        {
            link_created = CreateHardLinkW(alias.wstring().c_str(), path.wstring().c_str(), nullptr) != FALSE;
        }
        return false;
    });
    const auto result = wal.CompactWithResult(2, wal.ExclusiveWriterLeaseGeneration());
    wal.SetFaultInjectionHook({});
    const auto canonical = apfsaccess::rw::WriteAheadLog::ReadAll(path, kVolume);
    return Require(link_created, "hard-link race should create an alias after the pre-compaction link check") &&
           Require(
               result == apfsaccess::rw::WriteAheadLog::CompactionResult::BytesMayHavePersisted,
               "a compaction link race must retain intent and fail closed before replacement") &&
           Require(!wal.HasExclusiveWriterLease(), "rejected multi-link WAL must drop writer trust") &&
           Require(
               canonical.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                   canonical.records.size() == 2 &&
                   canonical.records.front().sequence == 1,
               "rejected link-raced compaction must preserve the original WAL");
}

bool TestHardLinkRaceAtReplacementHandoffFailsClosed(const std::filesystem::path& root)
{
    const auto path = root / "hard-link-handoff-source.wal";
    const auto alias = root / "hard-link-handoff-alias.wal";
    apfsaccess::rw::WriteAheadLog wal({ path, kVolume, 0 });
    if (!Require(wal.Append(MakeRecord(1), false), "hard-link handoff fixture should append first record") ||
        !Require(wal.Append(MakeRecord(2)), "hard-link handoff fixture should append second record"))
    {
        return false;
    }

    bool link_created = false;
    wal.SetFaultInjectionHook([&](std::string_view stage)
    {
        if (stage == "compact-replace-handoff")
        {
            link_created = CreateHardLinkW(alias.wstring().c_str(), path.wstring().c_str(), nullptr) != FALSE;
        }
        return false;
    });
    const auto result = wal.CompactWithResult(2, wal.ExclusiveWriterLeaseGeneration());
    wal.SetFaultInjectionHook({});

    const auto canonical = apfsaccess::rw::WriteAheadLog::ReadAll(path, kVolume);
    const auto linked_history = apfsaccess::rw::WriteAheadLog::ReadAll(alias, kVolume);
    const bool intent_retained = std::filesystem::exists(CompactionIntentPath(path));
    apfsaccess::rw::WriteAheadLog blocked_restart({ path, kVolume, 0 });
    const bool blocked_acquired = blocked_restart.AcquireExclusiveWriterLease();
    const bool intent_retained_after_restart = std::filesystem::exists(CompactionIntentPath(path));
    std::error_code remove_ec;
    const bool alias_removed = std::filesystem::remove(alias, remove_ec) && !remove_ec;
    apfsaccess::rw::WriteAheadLog recovered_restart({ path, kVolume, 0 });
    const bool recovered_acquired = recovered_restart.AcquireExclusiveWriterLease();
    return Require(link_created, "hard-link handoff should create an alias in the final replacement window") &&
           Require(
               result == apfsaccess::rw::WriteAheadLog::CompactionResult::BytesMayHavePersisted,
               "a post-check hard-link race must fail closed as an ambiguous replacement") &&
           Require(!wal.HasExclusiveWriterLease(), "ambiguous hard-link replacement must drop writer trust") &&
           Require(intent_retained, "ambiguous hard-link replacement must retain durable intent") &&
           Require(!blocked_acquired, "restart must fail closed while the stale predecessor alias survives") &&
           Require(intent_retained_after_restart, "blocked restart must not discard compaction evidence") &&
           Require(
               canonical.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                   canonical.records.size() == 2 &&
                   canonical.records.front().sequence == 1,
               "the final identity recheck should preserve the predecessor history") &&
           Require(
               linked_history.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                   linked_history.records.size() == 2 &&
                   linked_history.records.front().sequence == 1,
               "the surviving alias should prove why the replacement is ambiguous") &&
           Require(alias_removed, "hard-link recovery fixture should remove the stale alias") &&
           Require(recovered_acquired, "restart should recover after the stale predecessor alias is removed") &&
           Require(
               !std::filesystem::exists(CompactionIntentPath(path)),
               "resolved pre-replacement handoff should clear the rolled-back intent");
}

bool TestCanonicalPathSwapAtReplacementHandoffFailsClosed(
    const std::filesystem::path& root)
{
    const auto path = root / "canonical-swap-handoff-source.wal";
    const auto displaced = root / "canonical-swap-displaced.wal";
    constexpr std::string_view sentinel = "unrelated-canonical-file";
    apfsaccess::rw::WriteAheadLog wal({ path, kVolume, 0 });
    if (!Require(wal.Append(MakeRecord(1), false), "canonical-swap fixture should append first record") ||
        !Require(wal.Append(MakeRecord(2)), "canonical-swap fixture should append second record"))
    {
        return false;
    }

    bool predecessor_moved = false;
    bool unrelated_created = false;
    wal.SetFaultInjectionHook([&](std::string_view stage)
    {
        if (stage == "compact-replace-handoff")
        {
            predecessor_moved = MoveFileExW(
                path.wstring().c_str(),
                displaced.wstring().c_str(),
                MOVEFILE_WRITE_THROUGH) != FALSE;
            if (predecessor_moved)
            {
                std::ofstream unrelated(path, std::ios::binary | std::ios::trunc);
                unrelated.write(sentinel.data(), static_cast<std::streamsize>(sentinel.size()));
                unrelated_created = unrelated.good();
            }
        }
        return false;
    });
    const auto result = wal.CompactWithResult(2, wal.ExclusiveWriterLeaseGeneration());
    wal.SetFaultInjectionHook({});

    std::ifstream unrelated(path, std::ios::binary);
    const std::string unrelated_bytes{
        std::istreambuf_iterator<char>(unrelated),
        std::istreambuf_iterator<char>()};
    unrelated.close();
    const bool intent_retained = std::filesystem::exists(CompactionIntentPath(path));
    std::error_code remove_ec;
    const bool unrelated_removed = std::filesystem::remove(path, remove_ec) && !remove_ec;
    const bool predecessor_restored = unrelated_removed &&
        MoveFileExW(
            displaced.wstring().c_str(),
            path.wstring().c_str(),
            MOVEFILE_WRITE_THROUGH) != FALSE;
    apfsaccess::rw::WriteAheadLog recovered({ path, kVolume, 0 });
    const bool recovered_lease = predecessor_restored && recovered.AcquireExclusiveWriterLease();
    const auto history = apfsaccess::rw::WriteAheadLog::ReadAll(path, kVolume);
    return Require(predecessor_moved, "canonical-swap fixture should move the checked predecessor") &&
           Require(unrelated_created, "canonical-swap fixture should install an unrelated destination") &&
           Require(
               result == apfsaccess::rw::WriteAheadLog::CompactionResult::BytesMayHavePersisted,
               "canonical pathname swap must stop replacement and retain evidence") &&
           Require(
               unrelated_bytes == sentinel,
               "replacement handoff must not overwrite an unrelated canonical destination") &&
           Require(intent_retained, "canonical pathname swap must retain compaction intent") &&
           Require(predecessor_restored, "canonical-swap fixture should restore the predecessor pathname") &&
           Require(recovered_lease, "restored predecessor should allow deterministic rollback") &&
           Require(
               history.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                   history.records.size() == 2 &&
                   history.records.front().sequence == 1,
               "canonical-swap rollback should preserve the predecessor WAL") &&
           Require(
               !std::filesystem::exists(CompactionIntentPath(path)),
                "canonical-swap rollback should clear the prepared intent");
}

bool TestCanonicalCollisionAfterUnlinkNeverOverwritesDestination(
    const std::filesystem::path& root)
{
    const auto path = root / "canonical-collision-after-unlink.wal";
    constexpr std::string_view sentinel = "unrelated-file-installed-after-unlink";
    apfsaccess::rw::WriteAheadLog wal({ path, kVolume, 0 });
    if (!Require(wal.Append(MakeRecord(1), false), "publication-collision fixture should append first record") ||
        !Require(wal.Append(MakeRecord(2)), "publication-collision fixture should append second record"))
    {
        return false;
    }

    bool unrelated_created = false;
    wal.SetFaultInjectionHook([&](std::string_view stage)
    {
        if (stage == "compact-publication-handoff")
        {
            std::ofstream unrelated(path, std::ios::binary | std::ios::trunc);
            unrelated.write(sentinel.data(), static_cast<std::streamsize>(sentinel.size()));
            unrelated_created = unrelated.good();
        }
        return false;
    });
    const auto result = wal.CompactWithResult(2, wal.ExclusiveWriterLeaseGeneration());
    wal.SetFaultInjectionHook({});

    std::ifstream unrelated(path, std::ios::binary);
    const std::string unrelated_bytes{
        std::istreambuf_iterator<char>(unrelated),
        std::istreambuf_iterator<char>()};
    unrelated.close();
    const bool intent_retained = std::filesystem::exists(CompactionIntentPath(path));
    const bool temp_retained = FindCompactionTemps(path).size() == 1;
    apfsaccess::rw::WriteAheadLog blocked({ path, kVolume, 0 });
    const bool blocked_lease = blocked.AcquireExclusiveWriterLease();
    const bool intent_retained_after_restart = std::filesystem::exists(CompactionIntentPath(path));

    std::error_code remove_ec;
    const bool unrelated_removed = std::filesystem::remove(path, remove_ec) && !remove_ec;
    apfsaccess::rw::WriteAheadLog recovered({ path, kVolume, 0 });
    const bool recovered_lease = unrelated_removed && recovered.AcquireExclusiveWriterLease();
    const auto history = recovered.ReadAll();
    const bool temp_removed_after_recovery = FindCompactionTemps(path).empty();
    return Require(unrelated_created, "publication-collision fixture should install an unrelated destination") &&
           Require(
               result == apfsaccess::rw::WriteAheadLog::CompactionResult::BytesMayHavePersisted,
               "a destination collision after unlink must retain recovery evidence") &&
           Require(unrelated_bytes == sentinel, "non-replacing publication must preserve the unrelated destination") &&
           Require(intent_retained, "destination collision must retain the armed compaction intent") &&
           Require(temp_retained, "destination collision must retain the identified compacted temp") &&
           Require(!blocked_lease, "restart must fail closed while the unrelated canonical destination remains") &&
           Require(intent_retained_after_restart, "blocked restart must retain collision evidence") &&
           Require(unrelated_removed, "publication-collision fixture should remove its unrelated destination") &&
           Require(recovered_lease, "restart should restore the predecessor after the collision is removed") &&
           Require(temp_removed_after_recovery, "collision rollback must remove the retained compacted temp") &&
           Require(
               history.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                   history.records.size() == 2 &&
                   history.records.front().sequence == 1,
               "collision recovery must preserve the complete predecessor history") &&
           Require(
               !std::filesystem::exists(CompactionIntentPath(path)),
               "collision rollback should clear its resolved intent");
}

bool TestPredecessorHardLinkDuringPublicationFailsClosed(
    const std::filesystem::path& root)
{
    const auto path = root / "predecessor-link-during-publication.wal";
    const auto alias = root / "predecessor-link-during-publication-alias.wal";
    apfsaccess::rw::WriteAheadLog wal({ path, kVolume, 0 });
    if (!Require(wal.Append(MakeRecord(1), false), "publication-link fixture should append first record") ||
        !Require(wal.Append(MakeRecord(2)), "publication-link fixture should append second record"))
    {
        return false;
    }

    bool alias_created = false;
    wal.SetFaultInjectionHook([&](std::string_view stage)
    {
        if (stage == "compact-publication-handoff")
        {
            const auto intent = apfsaccess::rw::WriteAheadLog::ReadAll(
                CompactionIntentPath(path),
                kVolume);
            if (intent.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                !intent.records.empty())
            {
                const auto guard = CompactionPredecessorGuardPath(
                    path,
                    intent.records.back().object_id);
                alias_created = CreateHardLinkW(
                    alias.wstring().c_str(),
                    guard.wstring().c_str(),
                    nullptr) != FALSE;
            }
        }
        return false;
    });
    const auto result = wal.CompactWithResult(2, wal.ExclusiveWriterLeaseGeneration());
    wal.SetFaultInjectionHook({});

    const auto compacted = apfsaccess::rw::WriteAheadLog::ReadAll(path, kVolume);
    const bool intent_retained = std::filesystem::exists(CompactionIntentPath(path));
    apfsaccess::rw::WriteAheadLog blocked({ path, kVolume, 0 });
    const bool blocked_lease = blocked.AcquireExclusiveWriterLease();
    const bool intent_retained_after_restart = std::filesystem::exists(CompactionIntentPath(path));
    std::error_code remove_ec;
    const bool alias_removed = std::filesystem::remove(alias, remove_ec) && !remove_ec;
    apfsaccess::rw::WriteAheadLog recovered({ path, kVolume, 0 });
    const bool recovered_lease = alias_removed && recovered.AcquireExclusiveWriterLease();
    return Require(alias_created, "publication-link fixture should create a predecessor alias after unlink") &&
           Require(
               result == apfsaccess::rw::WriteAheadLog::CompactionResult::BytesMayHavePersisted,
               "a late predecessor alias must make publication ambiguous") &&
           Require(intent_retained, "late predecessor alias must retain compaction evidence") &&
           Require(
               compacted.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                   compacted.records.size() == 2 &&
                   compacted.records.front().sequence == 2,
               "late predecessor alias must not corrupt the published replacement") &&
           Require(!blocked_lease, "restart must fail closed while the predecessor alias survives") &&
           Require(intent_retained_after_restart, "blocked restart must retain predecessor-alias evidence") &&
           Require(alias_removed, "publication-link fixture should remove the predecessor alias") &&
           Require(recovered_lease, "restart should complete publication after the alias is removed") &&
           Require(HasCompletedCompactionProof(path), "resolved late alias should retain a completion proof");
}

bool TestHardLinkRaceBeforeIntentClearFailsClosed(const std::filesystem::path& root)
{
    const auto path = root / "hard-link-before-clear-source.wal";
    const auto alias = root / "hard-link-before-clear-alias.wal";
    apfsaccess::rw::WriteAheadLog wal({ path, kVolume, 0 });
    if (!Require(wal.Append(MakeRecord(1), false), "before-clear fixture should append first record") ||
        !Require(wal.Append(MakeRecord(2)), "before-clear fixture should append second record"))
    {
        return false;
    }

    bool link_created = false;
    wal.SetFaultInjectionHook([&](std::string_view stage)
    {
        if (stage == "compact-before-intent-clear")
        {
            link_created = CreateHardLinkW(alias.wstring().c_str(), path.wstring().c_str(), nullptr) != FALSE;
        }
        return false;
    });
    const auto result = wal.CompactWithResult(2, wal.ExclusiveWriterLeaseGeneration());
    wal.SetFaultInjectionHook({});
    const bool intent_retained = std::filesystem::exists(CompactionIntentPath(path));
    apfsaccess::rw::WriteAheadLog blocked_restart({ path, kVolume, 0 });
    const bool blocked_acquired = blocked_restart.AcquireExclusiveWriterLease();
    const bool intent_retained_after_restart = std::filesystem::exists(CompactionIntentPath(path));
    std::error_code remove_ec;
    const bool alias_removed = std::filesystem::remove(alias, remove_ec) && !remove_ec;
    apfsaccess::rw::WriteAheadLog recovered_restart({ path, kVolume, 0 });
    const bool recovered_acquired = recovered_restart.AcquireExclusiveWriterLease();
    return Require(link_created, "before-clear race should create an alias to the replacement WAL") &&
           Require(
               result == apfsaccess::rw::WriteAheadLog::CompactionResult::BytesMayHavePersisted,
               "a new replacement alias before intent cleanup must fail closed") &&
           Require(!wal.HasExclusiveWriterLease(), "ambiguous before-clear race must drop writer trust") &&
           Require(intent_retained, "before-clear race must retain compaction intent") &&
           Require(!blocked_acquired, "restart must reject a replacement WAL with multiple links") &&
           Require(intent_retained_after_restart, "blocked restart must retain before-clear evidence") &&
           Require(alias_removed, "before-clear recovery fixture should remove its alias") &&
           Require(recovered_acquired, "restart should recover after the replacement alias is removed") &&
           Require(
               HasCompletedCompactionProof(path),
               "resolved before-clear recovery should retain a completion proof");
}

bool TestHardLinkHandoffProcessCrashRetainsIntent(const std::filesystem::path& root)
{
    const auto path = root / "hard-link-process-crash-source.wal";
    std::wstring executable(32768, L'\0');
    const auto executable_chars = GetModuleFileNameW(
        nullptr,
        executable.data(),
        static_cast<DWORD>(executable.size()));
    if (!Require(
            executable_chars > 0 && executable_chars < executable.size(),
            "compaction crash test should resolve its executable"))
    {
        return false;
    }
    executable.resize(executable_chars);

    SetEnvironmentVariableW(kCompactionChildPathEnv, path.wstring().c_str());
    SetEnvironmentVariableW(kCompactionCrashStageEnv, L"compact-after-replace");
    std::wstring command_line = L"\"" + executable + L"\" compaction-intent-crash-child";
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    const bool created = CreateProcessW(
        nullptr,
        command_line.data(),
        nullptr,
        nullptr,
        FALSE,
        CREATE_NO_WINDOW,
        nullptr,
        nullptr,
        &startup,
        &process) != FALSE;
    SetEnvironmentVariableW(kCompactionChildPathEnv, nullptr);
    SetEnvironmentVariableW(kCompactionCrashStageEnv, nullptr);
    if (!Require(created, "compaction crash child should launch"))
    {
        return false;
    }
    CloseHandle(process.hThread);

    const auto child_wait = WaitForSingleObject(process.hProcess, 10000);
    if (child_wait != WAIT_OBJECT_0)
    {
        TerminateProcess(process.hProcess, 24);
        WaitForSingleObject(process.hProcess, 10000);
    }
    DWORD child_exit = 25;
    GetExitCodeProcess(process.hProcess, &child_exit);
    CloseHandle(process.hProcess);

    std::filesystem::path predecessor_guard;
    const auto guard_prefix = path.filename().wstring() + L".compact.predecessor.";
    std::error_code enumerate_ec;
    for (const auto& entry : std::filesystem::directory_iterator(root, enumerate_ec))
    {
        if (entry.path().filename().wstring().starts_with(guard_prefix))
        {
            predecessor_guard = entry.path();
            break;
        }
    }
    const auto canonical = apfsaccess::rw::WriteAheadLog::ReadAll(path, kVolume);
    const auto predecessor = apfsaccess::rw::WriteAheadLog::ReadAll(predecessor_guard, kVolume);
    const bool intent_retained = std::filesystem::exists(CompactionIntentPath(path));
    apfsaccess::rw::WriteAheadLog recovered_restart({ path, kVolume, 0 });
    const bool recovered_acquired = recovered_restart.AcquireExclusiveWriterLease();
    return Require(
               child_wait == WAIT_OBJECT_0 && child_exit == kCompactionCrashExitCode,
               "compaction child should terminate at the post-replacement crash boundary") &&
           Require(intent_retained, "process death after replacement must leave durable intent") &&
           Require(
               canonical.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                   canonical.records.size() == 2 &&
                   canonical.records.front().sequence == 2,
               "post-crash canonical path should retain the compacted WAL") &&
           Require(
               predecessor.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                   predecessor.records.size() == 2 &&
                   predecessor.records.front().sequence == 1,
               "post-crash alias should retain the predecessor WAL") &&
           Require(!predecessor_guard.empty(), "post-crash recovery should retain its predecessor guard") &&
           Require(recovered_acquired, "post-crash restart should complete the guarded replacement") &&
           Require(
               IsZeroByteRegularFile(predecessor_guard),
               "post-crash recovery should retain a zero-byte predecessor tombstone") &&
           Require(
               HasCompletedCompactionProof(path),
               "post-crash recovery should retain a completion proof");
}

bool TestCompactionProcessCrashBoundaryMatrix(const std::filesystem::path& root)
{
    enum class RecoveryExpectation
    {
        Cleared,
        Completed,
        Blocked,
    };
    struct CrashCase
    {
        const wchar_t* suffix;
        const wchar_t* stage;
        std::uint64_t expected_first_sequence;
        bool expect_canonical_missing_before_recovery;
        bool expect_guard_after_crash;
        RecoveryExpectation recovery;
    };
    const std::array cases{
        CrashCase{ L"intent-published", L"compact-after-intent-publish", 1, false, false, RecoveryExpectation::Cleared },
        CrashCase{ L"publish-armed", L"compact-after-publish-armed", 1, false, true, RecoveryExpectation::Cleared },
        CrashCase{ L"guard-established", L"compact-before-replace", 1, false, true, RecoveryExpectation::Cleared },
        CrashCase{ L"canonical-unlinked", L"compact-after-canonical-unlink", 1, true, true, RecoveryExpectation::Cleared },
        CrashCase{ L"unlink-flush", L"compact-canonical-unlink-directory-flush", 1, true, true, RecoveryExpectation::Cleared },
        CrashCase{ L"publication-handoff", L"compact-publication-handoff", 1, true, true, RecoveryExpectation::Cleared },
        CrashCase{ L"replacement-published", L"compact-after-replace", 2, false, true, RecoveryExpectation::Completed },
        CrashCase{ L"checkpoint-proof", L"compact-after-resolution-proof", 2, false, true, RecoveryExpectation::Completed },
        CrashCase{ L"tombstone-proof", L"compact-after-predecessor-zero-link-proof", 2, false, true, RecoveryExpectation::Completed },
        CrashCase{ L"cleaned-proof", L"compact-after-predecessor-unlink", 2, false, true, RecoveryExpectation::Completed },
    };

    std::wstring executable(32768, L'\0');
    const auto executable_chars = GetModuleFileNameW(
        nullptr,
        executable.data(),
        static_cast<DWORD>(executable.size()));
    if (!Require(
            executable_chars > 0 && executable_chars < executable.size(),
            "compaction crash matrix should resolve its executable"))
    {
        return false;
    }
    executable.resize(executable_chars);

    bool ok = true;
    for (const auto& crash_case : cases)
    {
        const auto path = root / (std::wstring(L"compaction-crash-") + crash_case.suffix + L".wal");
        SetEnvironmentVariableW(kCompactionChildPathEnv, path.wstring().c_str());
        SetEnvironmentVariableW(kCompactionCrashStageEnv, crash_case.stage);
        std::wstring command_line = L"\"" + executable + L"\" compaction-intent-crash-child";
        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        PROCESS_INFORMATION process{};
        const bool created = CreateProcessW(
            nullptr,
            command_line.data(),
            nullptr,
            nullptr,
            FALSE,
            CREATE_NO_WINDOW,
            nullptr,
            nullptr,
            &startup,
            &process) != FALSE;
        SetEnvironmentVariableW(kCompactionChildPathEnv, nullptr);
        SetEnvironmentVariableW(kCompactionCrashStageEnv, nullptr);
        if (!Require(created, "compaction crash-matrix child should launch"))
        {
            return false;
        }
        CloseHandle(process.hThread);

        const auto child_wait = WaitForSingleObject(process.hProcess, 10000);
        if (child_wait != WAIT_OBJECT_0)
        {
            TerminateProcess(process.hProcess, 24);
            WaitForSingleObject(process.hProcess, 10000);
        }
        DWORD child_exit = 25;
        GetExitCodeProcess(process.hProcess, &child_exit);
        CloseHandle(process.hProcess);

        std::filesystem::path predecessor_guard;
        const auto guard_prefix = path.filename().wstring() + L".compact.predecessor.";
        std::error_code enumerate_ec;
        for (const auto& entry : std::filesystem::directory_iterator(root, enumerate_ec))
        {
            if (entry.path().filename().wstring().starts_with(guard_prefix))
            {
                predecessor_guard = entry.path();
                break;
            }
        }
        const auto canonical_before_recovery = apfsaccess::rw::WriteAheadLog::ReadAll(path, kVolume);
        const bool canonical_existed_before_recovery = std::filesystem::exists(path);
        const bool intent_retained = std::filesystem::exists(CompactionIntentPath(path));
        apfsaccess::rw::WriteAheadLog recovered({ path, kVolume, 0 });
        const bool recovered_acquired = recovered.AcquireExclusiveWriterLease();
        const auto canonical_after_recovery = apfsaccess::rw::WriteAheadLog::ReadAll(path, kVolume);
        const auto intent_after_recovery = apfsaccess::rw::WriteAheadLog::ReadAll(
            CompactionIntentPath(path),
            kVolume);

        ok &= Require(
            child_wait == WAIT_OBJECT_0 && child_exit == kCompactionCrashExitCode,
            "compaction crash-matrix child should terminate at its requested boundary");
        ok &= Require(intent_retained, "each durable compaction crash boundary should retain intent");
        ok &= Require(
            predecessor_guard.empty() != crash_case.expect_guard_after_crash,
            "compaction crash boundary should retain exactly its expected predecessor guard state");
        const bool canonical_before_matches =
            crash_case.expect_canonical_missing_before_recovery
                ? (!canonical_existed_before_recovery &&
                   canonical_before_recovery.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                   canonical_before_recovery.records.empty())
                : (canonical_before_recovery.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                   !canonical_before_recovery.records.empty() &&
                   canonical_before_recovery.records.front().sequence == crash_case.expected_first_sequence);
        ok &= Require(
            canonical_before_matches,
            "compaction crash boundary should expose its expected old, missing, or compacted canonical state");
        ok &= Require(
            recovered_acquired == (crash_case.recovery != RecoveryExpectation::Blocked),
            "restart should resolve only crash boundaries with sufficient durable proof");
        const bool predecessor_evidence_matches =
            crash_case.recovery == RecoveryExpectation::Completed
                ? !predecessor_guard.empty() && IsZeroByteRegularFile(predecessor_guard)
                : predecessor_guard.empty() || !std::filesystem::exists(predecessor_guard);
        ok &= Require(
            predecessor_evidence_matches,
            "restart should retain only the predecessor evidence required by its outcome");
        ok &= Require(
            canonical_after_recovery.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                !canonical_after_recovery.records.empty() &&
                canonical_after_recovery.records.front().sequence == crash_case.expected_first_sequence,
            "restart should preserve the coherent history selected before recovery");
        const bool recovery_evidence_matches = [&]()
        {
            switch (crash_case.recovery)
            {
            case RecoveryExpectation::Cleared:
                return !std::filesystem::exists(CompactionIntentPath(path));
            case RecoveryExpectation::Completed:
                return HasCompletedCompactionProof(path);
            case RecoveryExpectation::Blocked:
                return intent_after_recovery.status ==
                           apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                       !intent_after_recovery.records.empty() &&
                       intent_after_recovery.records.back().state ==
                           apfsaccess::rw::WriteAheadLog::RecordState::CleanupArmed &&
                       !HasCompletedCompactionProof(path);
            }
            return false;
        }();
        ok &= Require(
            recovery_evidence_matches,
            "restart should retain the proof appropriate to each crash boundary");
    }
    return ok;
}

bool TestPreIntentCrashOrphansAreReclaimedOnRestart(
    const std::filesystem::path& root)
{
    struct CrashCase
    {
        const wchar_t* suffix;
        const wchar_t* stage;
        bool expect_intent_staging_temp;
    };
    const std::array cases{
        CrashCase{ L"compacted-temp", L"compact-after-temp-write", false },
        CrashCase{ L"intent-staging-temp", L"compact-intent-publication-handoff", true },
    };

    std::wstring executable(32768, L'\0');
    const auto executable_chars = GetModuleFileNameW(
        nullptr,
        executable.data(),
        static_cast<DWORD>(executable.size()));
    if (!Require(
            executable_chars > 0 && executable_chars < executable.size(),
            "pre-intent crash test should resolve its executable"))
    {
        return false;
    }
    executable.resize(executable_chars);

    bool ok = true;
    for (const auto& crash_case : cases)
    {
        const auto path = root / (std::wstring(L"pre-intent-crash-") + crash_case.suffix + L".wal");
        SetEnvironmentVariableW(kCompactionChildPathEnv, path.wstring().c_str());
        SetEnvironmentVariableW(kCompactionCrashStageEnv, crash_case.stage);
        std::wstring command_line = L"\"" + executable + L"\" compaction-intent-crash-child";
        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        PROCESS_INFORMATION process{};
        const bool created = CreateProcessW(
            nullptr,
            command_line.data(),
            nullptr,
            nullptr,
            FALSE,
            CREATE_NO_WINDOW,
            nullptr,
            nullptr,
            &startup,
            &process) != FALSE;
        SetEnvironmentVariableW(kCompactionChildPathEnv, nullptr);
        SetEnvironmentVariableW(kCompactionCrashStageEnv, nullptr);
        if (!Require(created, "pre-intent compaction crash child should launch"))
        {
            return false;
        }
        CloseHandle(process.hThread);

        const auto child_wait = WaitForSingleObject(process.hProcess, 10000);
        if (child_wait != WAIT_OBJECT_0)
        {
            TerminateProcess(process.hProcess, 24);
            WaitForSingleObject(process.hProcess, 10000);
        }
        DWORD child_exit = 25;
        GetExitCodeProcess(process.hProcess, &child_exit);
        CloseHandle(process.hProcess);

        const auto compact_temps_before = FindCompactionTemps(path);
        const auto intent_temps_before = FindIntentStagingTemps(path);
        const bool intent_absent_before = !std::filesystem::exists(CompactionIntentPath(path));
        apfsaccess::rw::WriteAheadLog recovered({ path, kVolume, 0 });
        const bool recovered_acquired = recovered.AcquireExclusiveWriterLease();
        const auto history = recovered.ReadAll();

        ok &= Require(
            child_wait == WAIT_OBJECT_0 && child_exit == kCompactionCrashExitCode,
            "pre-intent compaction child should terminate at its requested boundary");
        ok &= Require(
            compact_temps_before.size() == 1,
            "each pre-intent crash boundary should retain one compacted temp");
        ok &= Require(
            intent_temps_before.size() == (crash_case.expect_intent_staging_temp ? 1u : 0u),
            "pre-intent crash boundary should retain only its expected intent staging temp");
        ok &= Require(intent_absent_before, "pre-intent crash must not publish compaction intent");
        ok &= Require(recovered_acquired, "restart should reclaim safe pre-intent crash orphans");
        ok &= Require(FindCompactionTemps(path).empty(), "restart should remove the compacted orphan") &&
              Require(FindIntentStagingTemps(path).empty(), "restart should remove the intent staging orphan");
        ok &= Require(
            history.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                history.records.size() == 2 &&
                history.records.front().sequence == 1,
            "pre-intent orphan cleanup must preserve predecessor WAL history");
    }
    return ok;
}

bool TestLeafSymlinkWalPathIsRejected(const std::filesystem::path& root)
{
    const auto target = root / "symlink-target.wal";
    const auto alias = root / "symlink-alias.wal";
    {
        apfsaccess::rw::WriteAheadLog seed({ target, kVolume, 0 });
        if (!Require(seed.Append(MakeRecord(1), false), "symlink fixture should append first record") ||
            !Require(seed.Append(MakeRecord(2)), "symlink fixture should append second record"))
        {
            return false;
        }
    }

    constexpr DWORD allow_unprivileged_create = 0x2;
    bool created = CreateSymbolicLinkW(
        alias.wstring().c_str(),
        target.wstring().c_str(),
        allow_unprivileged_create) != FALSE;
    auto create_error = created ? ERROR_SUCCESS : GetLastError();
    if (!created && create_error == ERROR_INVALID_PARAMETER)
    {
        created = CreateSymbolicLinkW(alias.wstring().c_str(), target.wstring().c_str(), 0) != FALSE;
        create_error = created ? ERROR_SUCCESS : GetLastError();
    }
    if (!created &&
        (create_error == ERROR_PRIVILEGE_NOT_HELD || create_error == ERROR_NOT_SUPPORTED))
    {
        std::cout << "[SKIP] leaf symlink WAL test requires local symbolic-link support." << std::endl;
        return true;
    }
    if (!Require(created, "symlink fixture should create a leaf file alias"))
    {
        return false;
    }

    apfsaccess::rw::WriteAheadLog linked({ alias, kVolume, 0 });
    const auto acquired = linked.AcquireExclusiveWriterLease();
    const auto result = linked.CompactWithResult(2);
    const auto target_history = apfsaccess::rw::WriteAheadLog::ReadAll(target, kVolume);
    const auto alias_attributes = GetFileAttributesW(alias.wstring().c_str());
    return Require(!acquired, "leaf symlink WAL paths must reject writer ownership") &&
           Require(
               result == apfsaccess::rw::WriteAheadLog::CompactionResult::RejectedBeforeWrite,
               "leaf symlink compaction must be rejected before pathname replacement") &&
           Require(!linked.HasExclusiveWriterLease(), "rejected symlink paths must not retain writer trust") &&
           Require(
               alias_attributes != INVALID_FILE_ATTRIBUTES &&
                   (alias_attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0,
               "rejected compaction must preserve the leaf symlink") &&
           Require(
               target_history.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                   target_history.records.size() == 2 &&
                   target_history.records.front().sequence == 1,
               "rejected symlink compaction must preserve the referenced WAL history");
}

bool TestPathAliasesShareWriterOwnership(const std::filesystem::path& root)
{
    const auto path = root / "path-alias.wal";
    const auto alias = root / "." / "PATH-ALIAS.WAL";
    apfsaccess::rw::WriteAheadLog owner({ path, kVolume, 0 });
    apfsaccess::rw::WriteAheadLog successor({ alias, kVolume, 0 });
    if (!Require(owner.Append(MakeRecord(1)), "path-alias owner should append") ||
        !Require(successor.AcquireExclusiveWriterLease(), "path alias should transfer the same physical writer lease") ||
        !Require(!owner.HasExclusiveWriterLease(), "path-alias transfer should invalidate the prior owner") ||
        !Require(successor.Append(MakeRecord(2)), "path-alias successor should append with its lease"))
    {
        return false;
    }
    const auto snapshot = successor.ReadAll();
    return Require(
        snapshot.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
            snapshot.records.size() == 2,
        "path aliases should serialize into one coherent WAL");
}

bool TestAppendBatchReadbackAndSizeLimit(const std::filesystem::path& root)
{
    const auto path = root / "append-batch.wal";
    apfsaccess::rw::WriteAheadLog wal({ path, kVolume, 0 });
    std::vector<apfsaccess::rw::WriteAheadLog::Record> records;
    records.push_back(MakeRecord(1));
    records.push_back(MakeRecord(2));
    records.push_back(MakeRecord(3));
    if (!Require(wal.AppendBatch(records), "batch append should succeed"))
    {
        return false;
    }

    const auto read = wal.ReadAll();
    if (!Require(read.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok, "batch readback status should be ok") ||
        !Require(read.records.size() == 3, "batch readback should return all records") ||
        !Require(read.records[0].sequence == 1, "batch readback should keep first sequence") ||
        !Require(read.records[1].sequence == 2, "batch readback should keep second sequence") ||
        !Require(read.records[2].sequence == 3, "batch readback should keep third sequence"))
    {
        return false;
    }

    const auto limited_path = root / "append-batch-limited.wal";
    apfsaccess::rw::WriteAheadLog limited({ limited_path, kVolume, 32 });
    if (!Require(!limited.AppendBatch(records), "batch append size limit should reject oversized batch"))
    {
        return false;
    }
    return Require(
        !std::filesystem::exists(limited_path),
        "rejected oversized batch should not create a WAL file");
}

bool TestInlinePayloadVersioningAndMixedReplay(const std::filesystem::path& root)
{
    const auto path = root / "inline-v2-mixed.wal";
    auto inline_record = MakeRecord(1);
    inline_record.inline_payload = {
        std::byte{0x01},
        std::byte{0x02},
        std::byte{0x03},
        std::byte{0x04},
    };
    inline_record.payload_length = inline_record.inline_payload.size();
    inline_record.logical_length = inline_record.inline_payload.size();
    inline_record.payload_sha256 = {
        0x9f, 0x64, 0xa7, 0x47, 0xe1, 0xb9, 0x7f, 0x13,
        0x1f, 0xab, 0xb6, 0xb4, 0x47, 0x29, 0x6c, 0x9b,
        0x6f, 0x02, 0x01, 0xe7, 0x9f, 0xb3, 0xc5, 0x35,
        0x6e, 0x6c, 0x77, 0xe8, 0x9b, 0x6a, 0x80, 0x6a,
    };
    auto legacy_record = MakeRecord(2);
    legacy_record.inline_payload.clear();

    const auto v2_bytes = apfsaccess::rw::WriteAheadLog::EncodeForTest(inline_record);
    const auto v1_bytes = apfsaccess::rw::WriteAheadLog::EncodeForTest(legacy_record, 1);
    if (!Require(!v2_bytes.empty(), "v2 inline record should encode") ||
        !Require(!v1_bytes.empty(), "v1 legacy record should encode") ||
        !Require(
            WriteBytes(path, v2_bytes, std::ios::trunc) &&
                WriteBytes(path, v1_bytes, std::ios::app),
            "mixed WAL fixture should be written"))
    {
        return false;
    }

    const auto read = apfsaccess::rw::WriteAheadLog::ReadAll(path, kVolume);
    return Require(read.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok, "mixed WAL should read cleanly") &&
           Require(read.records.size() == 2, "mixed WAL should return both records") &&
           Require(read.records[0].inline_payload == inline_record.inline_payload, "v2 should preserve inline payload bytes") &&
           Require(read.records[1].inline_payload.empty(), "v1 should have no inline payload") &&
           Require(read.records[0].sequence == 1 && read.records[1].sequence == 2, "mixed WAL should preserve sequence order");
}

bool TestInlinePayloadSizeLimit(const std::filesystem::path&)
{
    auto record = MakeRecord(1);
    record.inline_payload.assign(
        apfsaccess::rw::WriteAheadLog::MaxInlinePayloadBytes + 1,
        std::byte{0x5a});
    return Require(
        apfsaccess::rw::WriteAheadLog::EncodeForTest(record).empty(),
        "inline payload larger than the recovery limit should be rejected");
}

bool TestInlinePayloadRejectsInconsistentRecords(const std::filesystem::path&)
{
    auto record = MakeRecord(1);
    record.inline_payload = { std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04} };
    record.payload_length = record.inline_payload.size();
    record.logical_length = record.inline_payload.size();
    record.payload_sha256 = {
        0x9f, 0x64, 0xa7, 0x47, 0xe1, 0xb9, 0x7f, 0x13,
        0x1f, 0xab, 0xb6, 0xb4, 0x47, 0x29, 0x6c, 0x9b,
        0x6f, 0x02, 0x01, 0xe7, 0x9f, 0xb3, 0xc5, 0x35,
        0x6e, 0x6c, 0x77, 0xe8, 0x9b, 0x6a, 0x80, 0x6a,
    };

    auto wrong_length = record;
    ++wrong_length.payload_length;
    auto wrong_hash = record;
    wrong_hash.payload_sha256[0] ^= 0xff;
    auto wrong_operation = record;
    wrong_operation.operation = apfsaccess::rw::WriteAheadLog::OperationKind::Rename;

    return Require(
               apfsaccess::rw::WriteAheadLog::EncodeForTest(record, 1).empty(),
               "legacy WAL records must not silently drop inline payloads") &&
           Require(
               apfsaccess::rw::WriteAheadLog::EncodeForTest(wrong_length).empty(),
               "inline payload length must match the recovery payload length") &&
           Require(
               apfsaccess::rw::WriteAheadLog::EncodeForTest(wrong_hash).empty(),
               "inline payload hash must match the recovery payload bytes") &&
           Require(
               apfsaccess::rw::WriteAheadLog::EncodeForTest(wrong_operation).empty(),
               "only write mutations may carry inline recovery payloads");
}

bool TestInlinePayloadCorruptionFailsClosed(const std::filesystem::path& root)
{
    auto record = MakeRecord(1);
    record.inline_payload = { std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04} };
    record.payload_length = record.inline_payload.size();
    record.logical_length = record.inline_payload.size();
    record.payload_sha256 = {
        0x9f, 0x64, 0xa7, 0x47, 0xe1, 0xb9, 0x7f, 0x13,
        0x1f, 0xab, 0xb6, 0xb4, 0x47, 0x29, 0x6c, 0x9b,
        0x6f, 0x02, 0x01, 0xe7, 0x9f, 0xb3, 0xc5, 0x35,
        0x6e, 0x6c, 0x77, 0xe8, 0x9b, 0x6a, 0x80, 0x6a,
    };
    auto encoded = apfsaccess::rw::WriteAheadLog::EncodeForTest(record);
    if (!Require(!encoded.empty(), "inline corruption fixture should encode"))
    {
        return false;
    }
    encoded.back() ^= 0xffu;
    const auto path = root / "inline-payload-corrupt.wal";
    if (!WriteBytes(path, encoded, std::ios::trunc))
    {
        return false;
    }

    const auto read = apfsaccess::rw::WriteAheadLog::ReadAll(path, kVolume);
    return Require(
        read.status == apfsaccess::rw::WriteAheadLog::ReadStatus::ChecksumMismatch,
        "corrupted inline recovery bytes must fail the WAL closed");
}

bool TestLiveReadWriteOperationsAreSerialized(const std::filesystem::path& root)
{
    constexpr std::uint64_t record_count = 128;
    const auto path = root / "live-read-write-serialization.wal";
    apfsaccess::rw::WriteAheadLog writer({ path, kVolume, 0 });
    apfsaccess::rw::WriteAheadLog reader({ path, kVolume, 0 });
    std::atomic<bool> start{false};
    std::atomic<bool> writer_done{false};
    std::atomic<bool> writer_ok{true};
    std::atomic<bool> reader_ok{true};

    std::thread writer_thread([&]()
    {
        while (!start.load(std::memory_order_acquire))
        {
            std::this_thread::yield();
        }
        for (std::uint64_t sequence = 1; sequence <= record_count; ++sequence)
        {
            if (!writer.Append(MakeRecord(sequence), sequence == record_count))
            {
                writer_ok.store(false, std::memory_order_release);
                break;
            }
        }
        writer_done.store(true, std::memory_order_release);
    });

    std::thread reader_thread([&]()
    {
        start.store(true, std::memory_order_release);
        do
        {
            const auto snapshot = reader.ReadAll();
            if (snapshot.status != apfsaccess::rw::WriteAheadLog::ReadStatus::Ok)
            {
                reader_ok.store(false, std::memory_order_release);
                break;
            }
            for (std::size_t index = 0; index < snapshot.records.size(); ++index)
            {
                if (snapshot.records[index].sequence != index + 1)
                {
                    reader_ok.store(false, std::memory_order_release);
                    break;
                }
            }
        } while (reader_ok.load(std::memory_order_acquire) &&
                 !writer_done.load(std::memory_order_acquire));
    });

    writer_thread.join();
    reader_thread.join();
    const auto final_snapshot = reader.ReadAll();
    return Require(writer_ok.load(), "live writer should complete every serialized append") &&
           Require(reader_ok.load(), "live reads must observe only complete ordered WAL snapshots") &&
           Require(
               final_snapshot.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                   final_snapshot.records.size() == record_count,
               "serialized live read/write WAL should retain every appended record");
}
}

int main(int argc, char** argv)
{
    if (argc == 2 && argv[1] && std::string_view(argv[1]) == "cross-process-compaction-contender")
    {
        return RunCompactionContenderChild();
    }
    if (argc == 2 && argv[1] && std::string_view(argv[1]) == "cross-process-wal-contender")
    {
        return RunImmediateWalContenderChild();
    }
    if (argc == 2 && argv[1] && std::string_view(argv[1]) == "compaction-intent-crash-child")
    {
        return RunCompactionCrashChild();
    }

    const auto root = MakeRunRoot();
    std::array<char, 256> filter_buffer{};
    const auto filter_size = GetEnvironmentVariableA(
        "APFSACCESS_WAL_TEST_FILTER",
        filter_buffer.data(),
        static_cast<DWORD>(filter_buffer.size()));
    const std::string_view filter =
        filter_size > 0 && filter_size < filter_buffer.size()
            ? std::string_view(filter_buffer.data(), filter_size)
            : std::string_view{};
    bool ok = true;
    const auto run = [&](const char* name, bool (*test)(const std::filesystem::path&))
    {
        if (filter.empty() || std::string_view(name).find(filter) != std::string_view::npos)
        {
            ok &= test(root);
        }
    };
    run("TestAppendReadbackAndVolumeBinding", TestAppendReadbackAndVolumeBinding);
    run("TestAppendHandleOwnsExclusiveWriterLease", TestAppendHandleOwnsExclusiveWriterLease);
    run("TestTornTailRecovery", TestTornTailRecovery);
    run("TestExclusiveLeaseReadRepairsTornTail", TestExclusiveLeaseReadRepairsTornTail);
    run("TestStrictReadFailureRetainsCrossProcessWriterLease", TestStrictReadFailureRetainsCrossProcessWriterLease);
    run("TestStrictRepairFailuresRetainWriterLease", TestStrictRepairFailuresRetainWriterLease);
    run("TestChecksumAndVersionRejection", TestChecksumAndVersionRejection);
    run("TestAppendResultDistinguishesPrewriteAndAmbiguousFlush", TestAppendResultDistinguishesPrewriteAndAmbiguousFlush);
    run("TestCompactionAndSizeLimit", TestCompactionAndSizeLimit);
    run("TestCompactionPostReplaceFailureIsAmbiguous", TestCompactionPostReplaceFailureIsAmbiguous);
    run("TestAmbiguousRenameResultPreservesPublishedReplacement", TestAmbiguousRenameResultPreservesPublishedReplacement);
    run("TestResolvedCompactionIntentRecoversBeforeGuardDelete", TestResolvedCompactionIntentRecoversBeforeGuardDelete);
    run("TestCleanedIntentRecoversAfterPredecessorUnlink", TestCleanedIntentRecoversAfterPredecessorUnlink);
    run("TestCleanupArmedTombstoneRecoversAfterCrash", TestCleanupArmedTombstoneRecoversAfterCrash);
    run("TestPredecessorAliasBeforeTombstoneTruncationFailsClosed", TestPredecessorAliasBeforeTombstoneTruncationFailsClosed);
    run("TestHardLinkCreationAfterTombstoneTruncationFailsClosed", TestHardLinkCreationAfterTombstoneTruncationFailsClosed);
    run("TestCompactionNamespaceFlushFailuresRetainEvidence", TestCompactionNamespaceFlushFailuresRetainEvidence);
    run("TestPreReplacementCompactionIntentResolvesOnRestart", TestPreReplacementCompactionIntentResolvesOnRestart);
    run("TestCompactionReplaceFailureProvesPredecessorBeforeClearingIntent", TestCompactionReplaceFailureProvesPredecessorBeforeClearingIntent);
    run("TestAmbiguousIntentPublicationRetainsRecoveryEvidence", TestAmbiguousIntentPublicationRetainsRecoveryEvidence);
    run("TestAliasedRetainedCompactionTempFailsClosed", TestAliasedRetainedCompactionTempFailsClosed);
    run("TestRetainedCompactionTempRejectsLateHardLinkRace", TestRetainedCompactionTempRejectsLateHardLinkRace);
    run("TestUnsafePreIntentCompactionOrphansFailClosed", TestUnsafePreIntentCompactionOrphansFailClosed);
    run("TestPreIntentOrphanCleanupIgnoresLookalikes", TestPreIntentOrphanCleanupIgnoresLookalikes);
    run("TestPreIntentOrphanSharingConflictFailsClosed", TestPreIntentOrphanSharingConflictFailsClosed);
    run("TestPreIntentReparseOrphanFailsClosed", TestPreIntentReparseOrphanFailsClosed);
    run("TestIntentPublicationNeverOverwritesUnrelatedDestination", TestIntentPublicationNeverOverwritesUnrelatedDestination);
    run("TestIntentStateAppendNeverOverwritesSwappedDestination", TestIntentStateAppendNeverOverwritesSwappedDestination);
    run("TestCompactionUsesUnredirectableUniqueTemp", TestCompactionUsesUnredirectableUniqueTemp);
    run("TestMalformedCompactionIntentFailsClosed", TestMalformedCompactionIntentFailsClosed);
    run("TestMissingWalWithCompactionIntentFailsClosed", TestMissingWalWithCompactionIntentFailsClosed);
    run("TestCompactionRetainsCrossProcessWriterLease", TestCompactionRetainsCrossProcessWriterLease);
    run("TestHardLinkedWalFailsWriterLeaseClosed", TestHardLinkedWalFailsWriterLeaseClosed);
    run("TestWriterLeaseIsIndependentOfWalPath", TestWriterLeaseIsIndependentOfWalPath);
    run("TestMismatchedVolumeCannotTakeOverWalPath", TestMismatchedVolumeCannotTakeOverWalPath);
    run("TestOwnerlessWalAndExplicitRecordsRemainVolumeBound", TestOwnerlessWalAndExplicitRecordsRemainVolumeBound);
    run("TestCompactionHandoffBlocksRawWalAppend", TestCompactionHandoffBlocksRawWalAppend);
    run("TestHardLinkRaceDuringCompactionFailsBeforeReplace", TestHardLinkRaceDuringCompactionFailsBeforeReplace);
    run("TestHardLinkRaceAtReplacementHandoffFailsClosed", TestHardLinkRaceAtReplacementHandoffFailsClosed);
    run("TestCanonicalPathSwapAtReplacementHandoffFailsClosed", TestCanonicalPathSwapAtReplacementHandoffFailsClosed);
    run("TestCanonicalCollisionAfterUnlinkNeverOverwritesDestination", TestCanonicalCollisionAfterUnlinkNeverOverwritesDestination);
    run("TestPredecessorHardLinkDuringPublicationFailsClosed", TestPredecessorHardLinkDuringPublicationFailsClosed);
    run("TestHardLinkRaceBeforeIntentClearFailsClosed", TestHardLinkRaceBeforeIntentClearFailsClosed);
    run("TestHardLinkHandoffProcessCrashRetainsIntent", TestHardLinkHandoffProcessCrashRetainsIntent);
    run("TestCompactionProcessCrashBoundaryMatrix", TestCompactionProcessCrashBoundaryMatrix);
    run("TestPreIntentCrashOrphansAreReclaimedOnRestart", TestPreIntentCrashOrphansAreReclaimedOnRestart);
    run("TestLeafSymlinkWalPathIsRejected", TestLeafSymlinkWalPathIsRejected);
    run("TestPathAliasesShareWriterOwnership", TestPathAliasesShareWriterOwnership);
    run("TestAppendBatchReadbackAndSizeLimit", TestAppendBatchReadbackAndSizeLimit);
    run("TestInlinePayloadVersioningAndMixedReplay", TestInlinePayloadVersioningAndMixedReplay);
    run("TestInlinePayloadSizeLimit", TestInlinePayloadSizeLimit);
    run("TestInlinePayloadRejectsInconsistentRecords", TestInlinePayloadRejectsInconsistentRecords);
    run("TestInlinePayloadCorruptionFailsClosed", TestInlinePayloadCorruptionFailsClosed);
    run("TestLiveReadWriteOperationsAreSerialized", TestLiveReadWriteOperationsAreSerialized);

    std::error_code ec;
    std::array<char, 2> keep_buffer{};
    const bool keep_artifacts = GetEnvironmentVariableA(
        "APFSACCESS_KEEP_WAL_TEST_ARTIFACTS",
        keep_buffer.data(),
        static_cast<DWORD>(keep_buffer.size())) != 0;
    if (ok || !keep_artifacts)
    {
        std::filesystem::remove_all(root, ec);
    }
    else
    {
        std::cerr << "[INFO] Retained failed test artifacts at " << root << std::endl;
    }
    if (!ok)
    {
        return 1;
    }

    std::cout << "[PASS] WriteAheadLog tests passed." << std::endl;
    return 0;
}
