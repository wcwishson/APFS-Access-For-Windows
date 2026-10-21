#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <charconv>
#include <filesystem>
#include <iostream>
#include "../src/NativeAllocatedRangesClient.h"
#include "../src/NativeCloneProtocol.h"

namespace
{
struct Handle
{
    HANDLE value = INVALID_HANDLE_VALUE;
    ~Handle() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};
bool Decimal(const wchar_t* text, std::uint64_t& value)
{
    value = 0;
    if (!text || !*text || (*text == L'0' && text[1])) return false;
    for (; *text; ++text)
    {
        if (*text < L'0' || *text > L'9' || value > (static_cast<std::uint64_t>(INT64_MAX) - (*text - L'0')) / 10) return false;
        value = value * 10 + (*text - L'0');
    }
    return true;
}
bool ApfsHandle(HANDLE handle, bool directory, std::wstring& volume)
{
    wchar_t name[32]{}; FILE_STANDARD_INFO info{};
    if (!GetVolumeInformationByHandleW(handle, nullptr, 0, nullptr, nullptr, nullptr, name, 32) ||
        _wcsicmp(name, L"APFS") || !GetFileInformationByHandleEx(handle, FileStandardInfo, &info, sizeof(info)) ||
        static_cast<bool>(info.Directory) != directory) return false;
    const auto length = GetFinalPathNameByHandleW(handle, nullptr, 0, VOLUME_NAME_NT | FILE_NAME_NORMALIZED);
    if (!length || length > 32768) return false;
    std::wstring final(length, L'\0');
    const auto written = GetFinalPathNameByHandleW(handle, final.data(), length, VOLUME_NAME_NT | FILE_NAME_NORMALIZED);
    if (!written || written >= length) return false;
    final.resize(written);
    if (!final.starts_with(L"\\Device\\")) return false;
    const auto end = final.find(L'\\', 8);
    volume = final.substr(0, end); return true;
}
int Failure(const char* code, DWORD error, bool recovery = false)
{
    std::cout << "{\"schemaVersion\":1,\"success\":false,\"standardApi\":false,\"code\":\"" << code
        << "\",\"win32Error\":" << error << ",\"acceptedRecoveryMayBeRequired\":" << (recovery ? "true" : "false") << "}\n";
    return 1;
}
}

// Direct private Control client, intended for the existing bounded child-process
// supervisor. It never launches a service, mounts, copies on failure or emits a
// partial range result. The provider, not this client, owns mutation recovery.
int wmain(int argc, wchar_t** argv)
{
    using namespace apfsaccess::fshost;
    if (argc != 5 || (std::wstring_view(argv[1]) != L"ranges" && std::wstring_view(argv[1]) != L"clone"))
    {
        std::cerr << "NativeFileControls ranges <file> <offset> <length> | clone <source> <destination-directory> <new-leaf>\n";
        return 2;
    }
    Handle source{CreateFileW(argv[2], FILE_READ_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr)};
    if (source.value == INVALID_HANDLE_VALUE) return Failure("SourceOpenFailed", GetLastError());
    std::wstring source_volume;
    if (!ApfsHandle(source.value, false, source_volume)) return Failure("UnsupportedFile", ERROR_NOT_SUPPORTED);
    if (std::wstring_view(argv[1]) == L"ranges")
    {
        std::uint64_t offset = 0, length = 0;
        if (!Decimal(argv[3], offset) || !Decimal(argv[4], length) || length > static_cast<std::uint64_t>(INT64_MAX) - offset)
            return Failure("InvalidRange", ERROR_INVALID_PARAMETER);
        allocated_ranges_control::Collector collector(offset, length);
        do
        {
            auto request = collector.Next(); allocated_ranges_control::Reply reply; DWORD done = 0;
            if (!DeviceIoControl(source.value, allocated_ranges_control::Query, &request, sizeof(request),
                    &reply, sizeof(reply), &done, nullptr)) return Failure("RangeQueryRefused", GetLastError());
            if (done != sizeof(reply) || !collector.Accept(reply)) return Failure("InvalidRangeReply", ERROR_INVALID_DATA);
        } while (!collector.Complete());
        const auto& stamp = collector.Stamp();
        std::cout << "{\"schemaVersion\":1,\"success\":true,\"standardApi\":false,\"api\":\"private-allocated-ranges-v2\","
            << "\"inode\":\"" << stamp.inode << "\",\"checkpointXid\":\"" << stamp.checkpoint << "\",\"stateEpoch\":\"" << stamp.epoch
            << "\",\"fileSize\":\"" << stamp.file_size << "\",\"allocationSize\":\"" << stamp.allocation_size << "\",\"ranges\":[";
        bool first = true;
        for (const auto& range : collector.Ranges())
        {
            if (!first) std::cout << ','; first = false;
            std::cout << "{\"offset\":\"" << range.offset << "\",\"length\":\"" << range.length << "\"}";
        }
        std::cout << "]}\n"; return 0;
    }
    using namespace clone_control;
    const std::wstring leaf = argv[4];
    if (leaf.empty() || leaf.size() > 255 || leaf == L"." || leaf == L".." || leaf.find_first_of(L"\\/:") != std::wstring::npos)
        return Failure("InvalidLeaf", ERROR_INVALID_NAME);
    Handle directory{CreateFileW(argv[3], FILE_ADD_FILE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr)};
    if (directory.value == INVALID_HANDLE_VALUE) return Failure("DirectoryOpenFailed", GetLastError());
    std::wstring destination_volume;
    if (!ApfsHandle(directory.value, true, destination_volume) || _wcsicmp(source_volume.c_str(), destination_volume.c_str()))
        return Failure("DifferentOrUnsupportedVolume", ERROR_NOT_SUPPORTED);
    ExportRequest request; ExportReply reply; DWORD done = 0;
    if (!DeviceIoControl(source.value, Export, &request, sizeof(request), &reply, sizeof(reply), &done, nullptr))
        return Failure("CloneExportRefused", GetLastError());
    if (done != sizeof(reply) || reply.version != Version || reply.reserved) return Failure("InvalidCloneTicket", ERROR_INVALID_DATA);
    ImportRequest import; import.ticket = reply.ticket; import.leaf_chars = static_cast<std::uint32_t>(leaf.size());
    for (std::size_t i = 0; i < leaf.size(); ++i) import.leaf[i] = static_cast<std::uint16_t>(leaf[i]);
    if (!DeviceIoControl(directory.value, Import, &import, sizeof(import), nullptr, 0, &done, nullptr))
        return Failure("CloneImportFailed", GetLastError(), true);
    if (done) return Failure("InvalidCloneCompletion", ERROR_INVALID_DATA, true);
    std::cout << "{\"schemaVersion\":1,\"success\":true,\"standardApi\":false,\"api\":\"private-whole-file-clone-v1\",\"publication\":\"durable\"}\n";
    return 0;
}
