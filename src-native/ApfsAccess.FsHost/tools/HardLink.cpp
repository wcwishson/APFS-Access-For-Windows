#include <windows.h>
#include <iostream>
#include <string>
#include "../src/NativeHardLinkProtocol.h"

namespace
{
struct File
{
    HANDLE value = INVALID_HANDLE_VALUE;
    ~File() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};
std::wstring NativeVolume(HANDLE file)
{
    constexpr DWORD flags = FILE_NAME_NORMALIZED | VOLUME_NAME_NT;
    const auto count = GetFinalPathNameByHandleW(file, nullptr, 0, flags);
    if (!count || count > 32768) return {};
    std::wstring name(count, L'\0');
    const auto length = GetFinalPathNameByHandleW(file, name.data(), count, flags);
    if (!length || length >= count || !name.starts_with(L"\\Device\\")) return {};
    name.resize(length);
    const auto end = name.find(L'\\', 8);
    return end == std::wstring::npos ? name : name.substr(0, end);
}
bool SameApfsMount(HANDLE source, HANDLE directory)
{
    wchar_t source_fs[32]{}, directory_fs[32]{};
    if (!GetVolumeInformationByHandleW(source, nullptr, 0, nullptr, nullptr, nullptr, source_fs, 32) ||
        !GetVolumeInformationByHandleW(directory, nullptr, 0, nullptr, nullptr, nullptr, directory_fs, 32) ||
        _wcsicmp(source_fs, L"APFS") || _wcsicmp(directory_fs, L"APFS")) return false;
    const auto first = NativeVolume(source), second = NativeVolume(directory);
    return !first.empty() && !second.empty() && _wcsicmp(first.c_str(), second.c_str()) == 0;
}
}

int wmain(int argc, wchar_t** argv)
{
    using namespace apfsaccess::fshost::hardlink_control;
    if (argc != 4)
    {
        std::wcerr << L"Usage: ApfsHardLink <source file> <destination directory> <new leaf name>\n";
        return 2;
    }
    const std::wstring leaf = argv[3];
    if (leaf.empty() || leaf.size() > 255 || leaf == L"." || leaf == L".." ||
        leaf.find_first_of(L"\\/:") != std::wstring::npos) return 2;
    File source{CreateFileW(argv[1], FILE_READ_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
    if (source.value == INVALID_HANDLE_VALUE)
    {
        std::wcerr << L"Source open failed: " << GetLastError() << L'\n'; return 1;
    }
    File directory{CreateFileW(argv[2], FILE_ADD_FILE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr)};
    if (directory.value == INVALID_HANDLE_VALUE)
    {
        std::wcerr << L"Directory open failed: " << GetLastError() << L'\n'; return 1;
    }
    if (!SameApfsMount(source.value, directory.value))
    {
        std::wcerr << L"Both handles must belong to the same APFS mount.\n"; return 1;
    }
    ExportRequest request; ExportReply exported; DWORD done = 0;
    if (!DeviceIoControl(source.value, Export, &request, sizeof(request), &exported, sizeof(exported), &done, nullptr))
    {
        std::wcerr << L"Hard-link export failed: " << GetLastError() << L'\n'; return 1;
    }
    if (done != sizeof(exported) || exported.version != Version || exported.reserved)
    {
        std::wcerr << L"Invalid hard-link export reply.\n"; return 1;
    }
    ImportRequest imported; imported.ticket = exported.ticket; imported.leaf_chars = static_cast<std::uint32_t>(leaf.size());
    for (std::size_t i = 0; i < leaf.size(); ++i) imported.leaf[i] = static_cast<std::uint16_t>(leaf[i]);
    ImportReply reply;
    if (!DeviceIoControl(directory.value, Import, &imported, sizeof(imported), &reply, sizeof(reply), &done, nullptr))
    {
        std::wcerr << L"Hard-link import failed: " << GetLastError() << L'\n'; return 1;
    }
    if (done != sizeof(reply) || reply.version != Version || reply.links < 2 || !reply.object_id ||
        !reply.accepted_sequence || !reply.checkpoint_xid)
    {
        std::wcerr << L"Invalid hard-link completion reply.\n"; return 1;
    }
    std::wcout << L"Created APFS hard link through the mounted helper. Inode " << reply.object_id
        << L", names " << reply.links << L", checkpoint " << reply.checkpoint_xid << L".\n";
    return 0;
}
