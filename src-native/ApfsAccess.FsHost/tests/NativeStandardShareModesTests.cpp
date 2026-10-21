#include "NativeStandardShareModes.h"
#include <array>
#include <filesystem>
#include <iostream>
#include <string>

using namespace apfsaccess::fshost::standard_mount;

int wmain(int argc, wchar_t** argv)
{
    if (argc != 2) return 2;
    const auto root = std::filesystem::absolute(argv[1]);
    if (!root.filename().wstring().starts_with(L"standard-native-share-")) return 2;
    if (!std::filesystem::create_directory(root)) return 2;
    const auto file = root / L"content.bin";
    HANDLE seed = CreateFileW(file.c_str(), GENERIC_WRITE, 7, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (seed == INVALID_HANDLE_VALUE) return 2;
    CloseHandle(seed);
    const auto alias = root / L"alias.bin";
    if (!CreateHardLinkW(alias.c_str(), file.c_str(), nullptr)) return 2;
    for (const auto* stream : {L":one", L":two"})
    {
        const auto path = file.wstring() + stream;
        seed = CreateFileW(path.c_str(), GENERIC_WRITE, 7, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (seed == INVALID_HANDLE_VALUE) return 2;
        CloseHandle(seed);
    }
    struct Case { DWORD first_access, first_share, next_access, next_share; const wchar_t* first_stream; const wchar_t* next_stream; bool alias; };
    const std::array cases{
        Case{FILE_READ_DATA, 7, FILE_WRITE_DATA, 7, L"", L"", false},
        Case{FILE_READ_DATA, FILE_SHARE_READ, FILE_WRITE_DATA, 7, L"", L"", false},
        Case{FILE_WRITE_DATA, 7, FILE_READ_DATA, 0, L"", L"", false},
        Case{FILE_READ_ATTRIBUTES, 0, FILE_WRITE_DATA, 0, L"", L"", false},
        Case{FILE_WRITE_DATA, 0, FILE_READ_ATTRIBUTES, 0, L"", L"", false},
        Case{FILE_EXECUTE, 7, FILE_WRITE_DATA, FILE_SHARE_WRITE, L"", L"", false},
        Case{FILE_APPEND_DATA, 7, FILE_READ_DATA, FILE_SHARE_READ, L"", L"", false},
        Case{DELETE, 7, FILE_READ_DATA, FILE_SHARE_READ, L"", L"", false},
        Case{FILE_READ_DATA, FILE_SHARE_READ, DELETE, 7, L"", L"", false},
        Case{FILE_READ_DATA, FILE_SHARE_READ, FILE_WRITE_DATA, 7, L"", L"", true},
        Case{FILE_READ_DATA, FILE_SHARE_READ, FILE_WRITE_DATA, 7, L":one", L":one", false},
        Case{FILE_READ_DATA, FILE_SHARE_READ, FILE_WRITE_DATA, 7, L":one", L":two", false},
        Case{FILE_READ_DATA, FILE_SHARE_READ, DELETE, 7, L":one", L"", false},
        Case{DELETE, 7, FILE_READ_DATA, FILE_SHARE_READ, L"", L":one", false},
        Case{FILE_READ_ATTRIBUTES, 0, DELETE, 7, L":one", L"", false},
        Case{FILE_READ_DATA, 0, FILE_READ_ATTRIBUTES, 0, L":one", L":one", false},
        Case{FILE_READ_DATA, 0, FILE_READ_DATA, 7, L":one", L":two", false},
        Case{FILE_READ_DATA, 7, FILE_WRITE_DATA, 7, L":one", L":one", true}
    };
    std::size_t passed = 0;
    for (const auto& test : cases)
    {
        const auto first = file.wstring() + test.first_stream;
        const auto next = (test.alias ? alias : file).wstring() + test.next_stream;
        const auto held = CreateFileW(first.c_str(), test.first_access, test.first_share, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (held == INVALID_HANDLE_VALUE) { std::cerr << "Initial oracle open failed " << GetLastError() << '\n'; return 1; }
        const auto opened = CreateFileW(next.c_str(), test.next_access, test.next_share, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        const auto error = opened == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
        const ShareOpen old{42, test.first_stream, test.first_access, test.first_share};
        const ShareOpen request{42, test.next_stream, test.next_access, test.next_share};
        const auto observed = CheckShareAdmission(request, {&old, 1});
        if (opened != INVALID_HANDLE_VALUE) CloseHandle(opened);
        CloseHandle(held);
        if ((error == ERROR_SUCCESS && observed != ShareAdmission::Allowed) ||
            (error == ERROR_SHARING_VIOLATION && observed != ShareAdmission::SharingViolation) ||
            (error != ERROR_SUCCESS && error != ERROR_SHARING_VIOLATION))
        {
            std::cerr << "NTFS disagreement case " << passed << " error " << error << " admission " << static_cast<int>(observed) << '\n';
            return 1;
        }
        ++passed;
    }
    const std::array invalid{ShareOpen{0, L"", FILE_READ_DATA, 7}, ShareOpen{42, L"", GENERIC_READ, 7},
        ShareOpen{42, L"", MAXIMUM_ALLOWED, 7}, ShareOpen{42, L"", FILE_READ_DATA, 8}};
    for (const auto& value : invalid) if (CheckShareAdmission(value, {}) != ShareAdmission::InvalidParameter) return 1;
    const ShareOpen unrelated{43, L"", FILE_READ_DATA, 0};
    const ShareOpen exclusive{42, L"", FILE_WRITE_DATA, 0};
    if (CheckShareAdmission(unrelated, {&exclusive, 1}) != ShareAdmission::Allowed) return 1;
    const ShareOpen request{42, L"", FILE_READ_DATA, 7};
    for (const auto& malformed : {ShareOpen{42, L"", GENERIC_READ, 7}, ShareOpen{42, L"", FILE_READ_DATA, 8}})
        if (CheckShareAdmission(request, {&malformed, 1}) != ShareAdmission::InvalidParameter) return 1;
    if (!DeleteFileW(alias.c_str()) || !DeleteFileW(file.c_str()) || !RemoveDirectoryW(root.c_str())) return 1;
    std::cout << "STANDARD_SHARE_NTFS_PASS " << passed << " oracle cases and 7 invalid/identity controls\n";
    return 0;
}
