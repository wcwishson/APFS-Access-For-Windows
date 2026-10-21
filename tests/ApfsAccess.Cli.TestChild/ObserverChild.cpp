// Harmless test child for DriveLetterDiscoveryRepairTests.
// Writes its own identity proof (pid, image path, creation time) to a result
// file, then sleeps until killed. Never links/starts FsHost, WinFsp, or any
// APFS code; kernel32 only.
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>
#include <windows.h>

namespace
{

std::wstring EscapeJson(const std::wstring& value)
{
    std::wstring out;
    out.reserve(value.size());
    for (const wchar_t ch : value)
    {
        switch (ch)
        {
        case L'\\': out += L"\\\\"; break;
        case L'"': out += L"\\\""; break;
        case L'\n': out += L"\\n"; break;
        case L'\r': out += L"\\r"; break;
        case L'\t': out += L"\\t"; break;
        default:
            if (ch < 0x20)
            {
                wchar_t buf[8];
                swprintf_s(buf, L"\\u%04x", ch);
                out += buf;
            }
            else out += ch;
        }
    }
    return out;
}

} // namespace

int wmain(int argc, wchar_t** argv)
{
    std::wstring resultPath;
    unsigned sleepMs = 5000;
    for (int i = 1; i < argc; ++i)
    {
        const std::wstring arg(argv[i]);
        if (arg == L"--result-path" && i + 1 < argc) resultPath = argv[++i];
        else if (arg == L"--sleep-ms" && i + 1 < argc) sleepMs = static_cast<unsigned>(_wtoi(argv[++i]));
    }
    if (resultPath.empty()) return 2;

    wchar_t image[MAX_PATH];
    const DWORD imageLen = GetModuleFileNameW(nullptr, image, MAX_PATH);
    if (imageLen == 0 || imageLen >= MAX_PATH) return 2;

    FILETIME ftCreate{}, ftExit{}, ftKernel{}, ftUser{};
    if (!GetProcessTimes(GetCurrentProcess(), &ftCreate, &ftExit, &ftKernel, &ftUser)) return 2;
    const std::uint64_t filetime = (static_cast<std::uint64_t>(ftCreate.dwHighDateTime) << 32) | ftCreate.dwLowDateTime;
    // FILETIME (1601 epoch) -> .NET ticks (0001 epoch), matching
    // Process.StartTime.ToUniversalTime().Ticks exactly (same source).
    const std::uint64_t ticks = filetime + 504911232000000000ULL;

    const std::wstring temporaryPath = resultPath + L".tmp-" + std::to_wstring(GetCurrentProcessId());
    FILE* out = nullptr;
    if (_wfopen_s(&out, temporaryPath.c_str(), L"w") != 0 || !out) return 2;
    const int written = fwprintf_s(out, L"{\"processId\":%lu,\"imagePath\":\"%ls\",\"processStartTimeUtcTicks\":%llu}",
        GetCurrentProcessId(), EscapeJson(image).c_str(), ticks);
    const int closed = fclose(out);
    if (written < 0 || closed != 0 ||
        !MoveFileExW(temporaryPath.c_str(), resultPath.c_str(), MOVEFILE_WRITE_THROUGH))
    {
        DeleteFileW(temporaryPath.c_str());
        return 2;
    }

    Sleep(sleepMs);
    return 0;
}
