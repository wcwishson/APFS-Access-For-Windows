// Harmless process: links the production receiver; never links/starts FsHost or WinFsp.
#include "EncryptedReadTransport.h"
#include <fstream>
#include <filesystem>
#include <string>
#include <thread>

int wmain(int argc, wchar_t** argv)
{
    if (argc < 5) return 2;
    const std::filesystem::path result(argv[1]);
    const std::wstring mode(argv[2]);
    const auto excluded = reinterpret_cast<HANDLE>(_wcstoui64(argv[3], nullptr, 10));
    const auto expected = _wtoi(argv[4]);
    if (mode == L"early") return 0;
    DWORD excluded_flags = 0;
    const bool excluded_inherited = excluded && GetHandleInformation(excluded, &excluded_flags);
    const bool output_inherited = GetFileType(GetStdHandle(STD_OUTPUT_HANDLE)) != FILE_TYPE_UNKNOWN ||
        GetFileType(GetStdHandle(STD_ERROR_HANDLE)) != FILE_TYPE_UNKNOWN;
    auto input = GetStdHandle(STD_INPUT_HANDLE);
    ULONG server = 0;
    const bool server_known = GetNamedPipeServerProcessId(input, &server);
    SetStdHandle(STD_INPUT_HANDLE, nullptr);
    std::atomic<bool> cancel{false};
    auto received = apfsaccess::transport::ReceiveCredential(input, std::chrono::milliseconds(5000), cancel);
    bool exact = received && received.bytes.Bytes().size() == static_cast<size_t>(expected);
    if (exact) for (int i = 0; i < expected; ++i)
        if (received.bytes.Bytes()[i] != std::byte(1 + i % 255)) exact = false;
    received.bytes.Clear();
    std::ofstream out(result);
    out << "{\"accepted\":" << (received ? "true" : "false")
        << ",\"exact\":" << (exact ? "true" : "false")
        << ",\"serverPid\":" << (server_known ? server : 0)
        << ",\"excludedInherited\":" << (excluded_inherited ? "true" : "false")
        << ",\"outputInherited\":" << (output_inherited ? "true" : "false")
        << ",\"stdoutHandle\":" << reinterpret_cast<uintptr_t>(GetStdHandle(STD_OUTPUT_HANDLE))
        << ",\"stderrHandle\":" << reinterpret_cast<uintptr_t>(GetStdHandle(STD_ERROR_HANDLE))
        << ",\"stdoutType\":" << GetFileType(GetStdHandle(STD_OUTPUT_HANDLE))
        << ",\"stderrType\":" << GetFileType(GetStdHandle(STD_ERROR_HANDLE))
        << ",\"error\":\"" << apfsaccess::transport::CredentialErrorName(received.error) << "\"}";
    out.close();
    if (mode == L"linger") Sleep(30000);
    if (mode == L"lifetime")
    {
        std::filesystem::path lifetime;
        for (int i = 5; i + 1 < argc; ++i) if (std::wstring_view(argv[i]) == L"--lifetime-file") lifetime = argv[++i];
        for (unsigned i = 0; i < 3000 && !lifetime.empty() && GetFileAttributesW(lifetime.c_str()) != INVALID_FILE_ATTRIBUTES; ++i) Sleep(10);
    }
    return exact && !excluded_inherited && !output_inherited ? 0 : 3;
}
