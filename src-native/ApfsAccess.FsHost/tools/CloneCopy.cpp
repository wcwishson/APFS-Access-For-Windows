#include <windows.h>
#include <filesystem>
#include <iostream>
#include "../src/NativeCloneProtocol.h"

namespace
{
std::wstring NativeVolume(HANDLE file)
{
    const DWORD flags = FILE_NAME_NORMALIZED | VOLUME_NAME_NT;
    const DWORD length = GetFinalPathNameByHandleW(file, nullptr, 0, flags);
    if (!length || length > 32768) return {};
    std::wstring name(length, L'\0');
    const DWORD written = GetFinalPathNameByHandleW(file, name.data(), length, flags);
    if (!written || written >= length) return {};
    name.resize(written);
    if (!name.starts_with(L"\\Device\\")) return {};
    const auto end = name.find(L'\\', 8);
    return end == std::wstring::npos ? name : name.substr(0, end);
}

bool CanAttemptClone(HANDLE source, HANDLE directory)
{
    wchar_t source_fs[32]{}, target_fs[32]{};
    if (!GetVolumeInformationByHandleW(source, nullptr, 0, nullptr, nullptr, nullptr, source_fs, 32) ||
        !GetVolumeInformationByHandleW(directory, nullptr, 0, nullptr, nullptr, nullptr, target_fs, 32) ||
        _wcsicmp(source_fs, L"APFS") || _wcsicmp(target_fs, L"APFS")) return false;
    const auto source_volume = NativeVolume(source);
    const auto target_volume = NativeVolume(directory);
    return !source_volume.empty() && !target_volume.empty() &&
        _wcsicmp(source_volume.c_str(), target_volume.c_str()) == 0;
}
}

// Optional client for the candidate's explicit protocol. Ordinary CopyFileW
// fallback enters WinFsp's normal Create/access/inheritance callbacks.
int wmain(int argc, wchar_t** argv)
{
    using namespace apfsaccess::fshost::clone_control;
    if (argc != 4) { std::wcerr << L"Usage: CloneCopy <source file> <destination directory> <new leaf name>\n"; return 2; }
    const std::wstring leaf = argv[3];
    if (leaf.empty() || leaf.size() > 255 || leaf == L"." || leaf == L".." ||
        leaf.find_first_of(L"\\/:") != std::wstring::npos) return 2;
    const auto destination = std::filesystem::path(argv[2]) / leaf;
    const auto source = CreateFileW(argv[1], FILE_READ_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (source == INVALID_HANDLE_VALUE) { std::wcerr << L"Source open failed: " << GetLastError() << L'\n'; return 1; }
    const auto directory = CreateFileW(argv[2], FILE_ADD_FILE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (directory == INVALID_HANDLE_VALUE) { const auto error = GetLastError(); CloseHandle(source); std::wcerr << L"Directory open failed: " << error << L'\n'; return 1; }
    ExportRequest request; ExportReply reply; DWORD done = 0;
    bool cloned = false;
    DWORD error = ERROR_NOT_SUPPORTED;
    if (CanAttemptClone(source, directory))
    {
        cloned = DeviceIoControl(source, Export, &request, sizeof(request), &reply, sizeof(reply), &done, nullptr) != FALSE;
        error = cloned ? ERROR_SUCCESS : GetLastError();
    }
    if (cloned)
    {
        if (done != sizeof(reply) || reply.version != Version || reply.reserved) { cloned = false; error = ERROR_INVALID_DATA; }
        else
        {
            ImportRequest import; import.ticket = reply.ticket; import.leaf_chars = static_cast<std::uint32_t>(leaf.size());
            for (std::size_t i = 0; i < leaf.size(); ++i) import.leaf[i] = leaf[i];
            cloned = DeviceIoControl(directory, Import, &import, sizeof(import), nullptr, 0, &done, nullptr) != FALSE;
            if (!cloned) error = GetLastError();
        }
    }
    CloseHandle(directory); CloseHandle(source);
    if (cloned) { std::wcout << L"Cloned with shared APFS extents.\n"; return 0; }
    // A failed accepted operation may require recovery. Never turn that result
    // into another mutation; fallback only on an explicit unsupported result.
    if (error == ERROR_NOT_SUPPORTED || error == ERROR_INVALID_FUNCTION)
    {
        if (CopyFileW(argv[1], destination.c_str(), TRUE))
        { std::wcout << L"Copied using ordinary Windows copy.\n"; return 0; }
        error = GetLastError();
    }
    std::wcerr << L"Copy failed: Windows error " << error << L".\n";
    return 1;
}
