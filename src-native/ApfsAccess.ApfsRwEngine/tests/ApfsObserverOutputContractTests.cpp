// Standalone Windows proof using an existing observer and a regular synthetic image.
// Links the cached engine for fixture generation; no CMake changes required.
// Each observer child has a 60-second deadline.
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "ApfsExtendedRecordCodec.h"
#include "TestFixtureBuilder.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace
{
struct Handle
{
    HANDLE value = INVALID_HANDLE_VALUE;
    Handle() = default;
    explicit Handle(HANDLE handle) : value(handle) {}
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    ~Handle() { Reset(); }
    void Reset(HANDLE handle = INVALID_HANDLE_VALUE)
    {
        if (value != nullptr && value != INVALID_HANDLE_VALUE) CloseHandle(value);
        value = handle;
    }
};

void Require(bool condition, const char* detail)
{
    if (!condition) throw std::runtime_error(detail);
}

std::wstring Quote(const std::wstring& argument)
{
    std::wstring result = L"\"";
    std::size_t backslashes = 0;
    for (wchar_t ch : argument)
    {
        if (ch == L'\\') { ++backslashes; continue; }
        result.append(ch == L'"' ? backslashes * 2 + 1 : backslashes, L'\\');
        backslashes = 0;
        result.push_back(ch);
    }
    result.append(backslashes * 2, L'\\');
    result.push_back(L'"');
    return result;
}

std::string ReadCapture(HANDLE handle)
{
    LARGE_INTEGER size{}, start{};
    Require(GetFileSizeEx(handle, &size) && size.QuadPart >= 0 &&
        size.QuadPart <= 64ll * 1024 * 1024, "capture exceeds 64 MiB limit");
    Require(SetFilePointerEx(handle, start, nullptr, FILE_BEGIN) != FALSE, "rewind capture");
    std::string text(static_cast<std::size_t>(size.QuadPart), '\0');
    DWORD read = 0;
    Require(text.empty() || (ReadFile(handle, text.data(), static_cast<DWORD>(text.size()),
        &read, nullptr) && read == text.size()), "read capture");
    return text;
}

struct AttributeList
{
    std::vector<unsigned char> storage;
    LPPROC_THREAD_ATTRIBUTE_LIST value = nullptr;
    explicit AttributeList(const std::vector<HANDLE>& handles)
    {
        SIZE_T size = 0;
        InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
        Require(size != 0, "size handle inheritance list");
        storage.resize(size);
        auto* list = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
        Require(InitializeProcThreadAttributeList(list, 1, 0, &size) != FALSE,
            "initialize handle inheritance list");
        if (!UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            const_cast<HANDLE*>(handles.data()), handles.size() * sizeof(HANDLE), nullptr, nullptr))
        {
            DeleteProcThreadAttributeList(list);
            throw std::runtime_error("set handle inheritance list");
        }
        value = list;
    }
    AttributeList(const AttributeList&) = delete;
    ~AttributeList() { if (value) DeleteProcThreadAttributeList(value); }
};

struct Result
{
    DWORD exit_code = 0;
    std::string output, error;
};

Result Launch(const std::filesystem::path& observer, const std::vector<std::wstring>& arguments,
    const std::filesystem::path& directory, const std::string& label, bool broken_sink)
{
    SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
    Handle input(CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        &security, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    Require(input.value != INVALID_HANDLE_VALUE, "open child stdin");
    Handle error(CreateFileW((directory / (label + ".stderr")).c_str(),
        GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, &security, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL, nullptr));
    Require(error.value != INVALID_HANDLE_VALUE, "open stderr capture");
    Handle output;
    if (broken_sink)
    {
        Handle reader;
        Require(CreatePipe(&reader.value, &output.value, &security, 0) != FALSE, "create broken pipe");
        // No read end exists when the observer starts; only its write end is inherited.
        reader.Reset();
    }
    else
    {
        output.Reset(CreateFileW((directory / (label + ".stdout")).c_str(),
            GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, &security, CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL, nullptr));
        Require(output.value != INVALID_HANDLE_VALUE, "open stdout capture");
    }

    std::wstring command = Quote(observer.wstring());
    for (const auto& argument : arguments) command += L" " + Quote(argument);
    const std::vector<HANDLE> inherited{input.value, output.value, error.value};
    AttributeList attributes(inherited);
    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = input.value;
    startup.StartupInfo.hStdOutput = output.value;
    startup.StartupInfo.hStdError = error.value;
    startup.lpAttributeList = attributes.value;
    PROCESS_INFORMATION process{};
    Require(CreateProcessW(observer.c_str(), command.data(), nullptr, nullptr, TRUE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW, nullptr, nullptr,
        &startup.StartupInfo, &process) != FALSE, "launch observer");
    Handle child(process.hProcess), thread(process.hThread);
    const DWORD waited = WaitForSingleObject(child.value, 60000);
    if (waited != WAIT_OBJECT_0)
    {
        TerminateProcess(child.value, 99);
        WaitForSingleObject(child.value, 5000);
        throw std::runtime_error("observer did not finish within its deadline");
    }
    Result result;
    Require(GetExitCodeProcess(child.value, &result.exit_code) != FALSE, "read observer exit code");
    result.error = ReadCapture(error.value);
    if (!broken_sink) result.output = ReadCapture(output.value);
    std::cout << "RESULT " << label << " exit=" << result.exit_code
        << " stdoutBytes=" << result.output.size() << " stderrBytes=" << result.error.size()
        << '\n' << std::flush;
    return result;
}

void CheckMode(const std::filesystem::path& observer, const std::filesystem::path& directory,
    const std::string& mode, const std::vector<std::wstring>& arguments,
    const std::string& format, DWORD semantic_exit_code, bool unchecked_output = false)
{
    const auto control = Launch(observer, arguments, directory, mode + "-control", false);
    Require(control.exit_code == semantic_exit_code, "working stdout changed semantic exit code");
    Require(control.error.empty(), "working stdout emitted stderr");
    Require(control.output.starts_with("{\"format\": \"" + format + "\"") &&
        control.output.ends_with("\n"), "working stdout did not deliver evidence");

    const auto broken = Launch(observer, arguments, directory, mode + "-broken", true);
    if (unchecked_output)
    {
        Require(broken.exit_code == semantic_exit_code && broken.error.empty(),
            "pre-patch observer did not demonstrate unchecked output");
    }
    else
    {
        Require(broken.exit_code == 5, "broken stdout did not return transport exit 5");
        Require(broken.error == "error: observer stdout transport failed\r\n" ||
            broken.error == "error: observer stdout transport failed\n", "missing transport stderr");
    }

    const auto published_path = directory / (mode + "-published.json");
    auto out_arguments = arguments;
    out_arguments.insert(out_arguments.end(), {L"--out", published_path.wstring()});
    const auto published = Launch(observer, out_arguments, directory, mode + "-out", true);
    Require(published.exit_code == semantic_exit_code && published.error.empty(),
        "--out incorrectly depended on stdout or changed semantic exit code");
    Handle evidence(CreateFileW(published_path.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    Require(evidence.value != INVALID_HANDLE_VALUE, "--out did not publish evidence");
    auto expected_output = control.output;
    // stdout uses Windows text mode; --out publishes in binary mode.
    if (expected_output.ends_with("\r\n")) expected_output.erase(expected_output.size() - 2, 1);
    Require(ReadCapture(evidence.value) == expected_output, "--out evidence differs from stdout control");
    std::cout << (unchecked_output ? "RED CONFIRMED " : "PASS ") << mode
        << " working sink, broken sink, --out (semantic exit "
        << semantic_exit_code << ")\n";
}

void MintVerificationFixture(const std::filesystem::path& path)
{
    using namespace apfsaccess::catalog;
    using namespace apfsaccess::rw;
    using namespace apfsaccess::testfixture;
    Require(path.root_name() == L"D:" || path.root_name() == L"d:", "fixture must be on D:");
    Require(!std::filesystem::exists(path), "fixture must be a fresh path");
    BuilderStore spec;
    spec.block_size = 4096; spec.block_count = 512; spec.xid = 20;
    spec.volumes[0].uuid_hex = std::string(32, 'b');
    AppleInodeRecord root;
    root.object_id = root.private_id = root.parent_id = 2;
    root.mode = 0040755;
    BtreeRecord inode; std::string error;
    Require(EncodeAppleInodeRecord(root, inode, error), "encode fixture root");
    spec.volumes[0].filesystem_records = {inode};
    auto bytes = BuildAuthoritativeStoreImage(spec);
    // Match the existing verifier fixture's Apple container OMAP requirement.
    std::vector<std::byte> omap(bytes.begin() + 2 * 4096, bytes.begin() + 3 * 4096);
    apfsaccess::testfixture::PutU32LE(omap, 0x20, 1);
    FletcherForBlock(omap, 4096);
    std::copy(omap.begin(), omap.end(), bytes.begin() + 2 * 4096);
    std::ofstream file(path, std::ios::binary);
    file.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    file.close();
    Require(file.good(), "write verification fixture");
    std::cout << "Fixture container=" << std::string(32, 'a') << " volume="
        << std::string(32, 'b') << " oid=101 xid=20 offset=0 size=" << bytes.size() << '\n';
}
} // namespace

int wmain(int argc, wchar_t** argv)
{
    try
    {
        if (argc == 3 && std::wstring(argv[1]) == L"--mint-verification-fixture")
        {
            MintVerificationFixture(std::filesystem::absolute(argv[2]).lexically_normal());
            return 0;
        }
        Require(argc == 11 || argc == 12,
            "arguments: observer.exe synthetic-image container-uuid volume-uuid volume-oid "
            "checkpoint-xid store-offset store-size expected-verify-exit D:\\artifact-directory "
            "[--red|--verify-only|--verify-incomplete]");
        const std::wstring selection = argc == 12 ? argv[11] : L"";
        Require(selection.empty() || selection == L"--red" || selection == L"--verify-only" ||
            selection == L"--verify-incomplete", "unknown proof selection");
        const bool unchecked_output = selection == L"--red";
        const auto observer = std::filesystem::absolute(argv[1]);
        const auto image = std::filesystem::absolute(argv[2]);
        Require(std::filesystem::is_regular_file(observer) && std::filesystem::is_regular_file(image),
            "observer and synthetic image must be regular files");
        const std::wstring verify_exit(argv[9]);
        Require(verify_exit == L"0" || verify_exit == L"3" || verify_exit == L"4",
            "expected verification exit must be 0, 3, or 4");
        const auto root = std::filesystem::absolute(argv[10]).lexically_normal();
        Require(root.root_name() == L"D:" || root.root_name() == L"d:", "artifacts must be on D:");
        const auto directory = root / ("observer-output-" + std::to_string(GetCurrentProcessId()) +
            "-" + std::to_string(GetTickCount64()));
        std::filesystem::create_directories(root);
        Require(std::filesystem::create_directory(directory), "create fresh proof directory");
        std::cout << "Evidence: " << directory.string() << '\n' << std::flush;
        const std::vector<std::wstring> collect{L"--image", image.wstring(), L"--profile",
            L"output-contract", L"--mode", L"collect"};
        const std::vector<std::wstring> snapshots{L"--image", image.wstring(), L"--mode",
            L"snapshots", L"--container-uuid", argv[3], L"--volume-oid", argv[5]};
        std::vector<std::wstring> verify{L"--image", image.wstring(), L"--mode", L"verify",
            L"--container-uuid", argv[3], L"--volume-uuid", argv[4], L"--volume-oid", argv[5],
            L"--checkpoint-xid", argv[6], L"--store-offset-bytes", argv[7],
            L"--store-size-bytes", argv[8]};
        if (selection.empty() || unchecked_output)
        {
            CheckMode(observer, directory, "collect", collect, "apfs-access-raw-evidence", 0, unchecked_output);
            CheckMode(observer, directory, "snapshots", snapshots, "apfs-access-snapshot-inventory", 0, unchecked_output);
        }
        if (selection == L"--verify-incomplete") verify.push_back(L"--require-whole-volume");
        CheckMode(observer, directory, "verify", verify, "apfs-access-verification",
            static_cast<DWORD>(verify_exit[0] - L'0'), unchecked_output);
        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
