#pragma once
// Include after main.cpp and Require. Parent owns registration and execution.
#include <cerrno>

#ifdef APFSACCESS_HAS_RW_ENGINE
namespace fs_host_long_runtime_path_tests
{
inline std::filesystem::path FixturePath(const std::filesystem::path& ordinary)
{
    const auto value = ordinary.wstring();
    if (value.rfind(LR"(\\?\)", 0) == 0) return ordinary;
    if (value.rfind(LR"(\\)", 0) == 0)
        return std::filesystem::path(LR"(\\?\UNC\)" + value.substr(2));
    return std::filesystem::path(LR"(\\?\)" + value);
}

inline bool Save(const std::filesystem::path& path, const std::string& contents)
{
    std::ofstream output(FixturePath(path), std::ios::binary | std::ios::trunc);
    output.write(contents.data(), static_cast<std::streamsize>(contents.size()));
    output.close();
    return !output.fail();
}

inline std::string Load(const std::filesystem::path& path)
{
    std::ifstream input(FixturePath(path), std::ios::binary);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

inline bool Exists(const std::filesystem::path& path)
{
    return GetFileAttributesW(FixturePath(path).c_str()) != INVALID_FILE_ATTRIBUTES;
}

inline bool Symlink(const std::filesystem::path& link,
    const std::filesystem::path& target, bool directory, bool& ok)
{
    const DWORD flags = directory ? SYMBOLIC_LINK_FLAG_DIRECTORY : 0;
    if (CreateSymbolicLinkW(FixturePath(link).c_str(), FixturePath(target).c_str(), flags | 0x2))
        return true;
    auto error = GetLastError();
    if (error == ERROR_INVALID_PARAMETER)
    {
        if (CreateSymbolicLinkW(FixturePath(link).c_str(), FixturePath(target).c_str(), flags))
            return true;
        error = GetLastError();
    }
    const bool unsupported = error == ERROR_PRIVILEGE_NOT_HELD || error == ERROR_ACCESS_DENIED ||
        error == ERROR_NOT_SUPPORTED || error == ERROR_INVALID_FUNCTION;
    ok &= Require(unsupported, "long runtime: unexpected symbolic link fixture failure");
    if (unsupported) std::cout << "SKIP long runtime symbolic link fixture: Win32 " << error << '\n';
    return false;
}
} // namespace fs_host_long_runtime_path_tests

bool TestLongRuntimeControlAndDiagnostics()
{
    namespace fixture = fs_host_long_runtime_path_tests;
    std::error_code ec;
    const auto scratch = std::filesystem::temp_directory_path(ec);
    if (!Require(!ec && scratch.is_absolute(), "long runtime: configured temporary directory is absolute"))
        return false;
    const DWORD attributes = GetFileAttributesW(fixture::FixturePath(scratch).c_str());
    if (!Require(attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
            (attributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0,
            "long runtime: temporary directory exists without redirection")) return false;

    static std::atomic<std::uint64_t> next_fixture{0};
    const auto root = scratch / (L"fshost-long-runtime-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
        std::to_wstring(GetTickCount64()) + L"-" + std::to_wstring(next_fixture.fetch_add(1)));
    if (!Require(std::filesystem::create_directory(fixture::FixturePath(root), ec) && !ec,
            "long runtime: exclusively create private temporary fixture")) return false;
    ScopeExit cleanup{[&] {
        std::error_code ignored;
        std::filesystem::remove_all(fixture::FixturePath(root), ignored);
    }};

    auto deep = root;
    while (deep.native().size() < 310) deep /= std::wstring(48, L'p');
    std::filesystem::create_directories(fixture::FixturePath(deep), ec);
    if (!Require(!ec && deep.is_absolute() && deep.native().size() > MAX_PATH &&
            deep.native().rfind(LR"(\\?\)", 0) != 0,
            "long runtime: real directory exceeds MAX_PATH with ordinary input spelling")) return false;

    const std::string request_id = "0123456789abcdef0123456789abcdef";
    const std::string token(64, 'b');
    const std::string envelope = "APFS-CONTROL/1\n" + request_id + "\n" + token + "\ndetach\n101\n";
    ContainerControlRequest request{};
    std::string parse_error;
    if (!Require(ParseContainerControlRequestContents(envelope, token, request, parse_error),
            "long runtime: actual parser prepares authenticated detach request")) return false;
    const ContainerControlActionResult result{true, "Detached"};
    bool ok = true;

    // Keep both final endpoints short; only the native response temporary name is long.
    const auto request_length = (std::max)(std::size_t{248}, root.native().size() + 24);
    const auto boundary_request = root / (std::wstring(request_length - root.native().size() - 1 - 8, L'c') + L".control");
    for (const auto& endpoint : {boundary_request, deep / L"request.control"})
    {
        const auto response = std::filesystem::path(endpoint.wstring() + L".response");
        const auto temporary = response.wstring() + L".tmp-" + std::to_wstring(GetCurrentProcessId()) +
            L"-" + std::to_wstring(GetTickCount64());
        ok &= Require(endpoint.is_absolute() && endpoint.native().rfind(LR"(\\?\)", 0) != 0 &&
                temporary.size() > MAX_PATH,
            "long runtime: ordinary control path forces response temporary path above MAX_PATH");
        SetLastError(ERROR_SUCCESS);
        const auto plain = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr,
            CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        const auto plain_error = plain == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
        std::cout << "long runtime plain CreateFileW: length=" << temporary.size()
                  << " opened=" << (plain != INVALID_HANDLE_VALUE) << " error=" << plain_error << '\n';
        if (plain != INVALID_HANDLE_VALUE)
        {
            CloseHandle(plain);
            ok &= Require(DeleteFileW(fixture::FixturePath(temporary).c_str()) != FALSE,
                "long runtime: remove informational plain native open probe");
        }
        if (!Require(fixture::Save(endpoint, envelope),
                "long runtime: independently seed actual control file with extended fixture path")) return false;
        std::string consumed = "must-be-cleared";
        const bool read = ReadAndConsumeContainerControlRequest(endpoint, consumed);
        ok &= Require(read && consumed == envelope && !fixture::Exists(endpoint),
            "long runtime: native reader returns exact request bytes and deletes the ordinary long endpoint");
        ContainerControlRequest parsed{};
        ok &= Require(ParseContainerControlRequestContents(consumed, token, parsed, parse_error) &&
                parsed.request_id == request_id && parsed.action == ContainerControlAction::Detach &&
                parsed.volume_object_id == 101,
            "long runtime: consumed request retains exact authentication, request ID, action and volume");
        ok &= Require(WriteContainerControlResponse(endpoint, request, result),
            "long runtime: native response writes and atomically renames its long temporary file");
        ok &= Require(fixture::Load(response) == "APFS-CONTROL/1\n" + request_id + "\nok\nDetached\n",
            "long runtime: final native response contains the exact correlated protocol and result");
        bool temporary_remains = false;
        const auto prefix = endpoint.filename().wstring() + L".response.tmp-";
        std::filesystem::directory_iterator entry(fixture::FixturePath(endpoint.parent_path()), ec), end;
        for (; !ec && entry != end; entry.increment(ec))
            temporary_remains |= entry->path().filename().wstring().rfind(prefix, 0) == 0;
        ok &= Require(!ec && !temporary_remains, "long runtime: successful response leaves no temporary file");
    }

    const auto child = root / L"normalization-child";
    std::filesystem::create_directory(fixture::FixturePath(child), ec);
    if (!Require(!ec, "long runtime: create ordinary parent-normalization fixture")) return false;
    const auto actual = root / L"normalized.control";
    for (const auto& spelling : {root / L"." / actual.filename(), child / L".." / actual.filename()})
    {
        if (!Require(fixture::Save(actual, envelope), "long runtime: seed normalized endpoint")) return false;
        std::string consumed;
        ok &= Require(ReadAndConsumeContainerControlRequest(spelling, consumed) && consumed == envelope &&
                !fixture::Exists(actual) && WriteContainerControlResponse(spelling, request, result),
            "long runtime: ordinary dot and parent spellings preserve request/response semantics");
        const auto response = std::filesystem::path(actual.wstring() + L".response");
        ok &= Require(fixture::Load(response) == "APFS-CONTROL/1\n" + request_id + "\nok\nDetached\n" &&
                DeleteFileW(fixture::FixturePath(response).c_str()) != FALSE,
            "long runtime: normalized response reaches the exact original endpoint");
    }

    const std::wstring status_name = L"status.json";
    const auto status_length = (std::max)(std::size_t{234}, root.native().size() + 32);
    const auto boundary_status = root /
        std::wstring(status_length - root.native().size() - 2 - status_name.size(), L's') / status_name;
    std::filesystem::create_directories(fixture::FixturePath(boundary_status.parent_path()), ec);
    if (!Require(!ec && boundary_status.native().size() == status_length,
            "long runtime: reproduce the 234-character status boundary or exceed an already longer temporary root")) return false;
    for (const auto& status : {boundary_status, deep / status_name})
    {
        const auto base = status.wstring() + L".volume-101";
        const auto final_path = std::filesystem::path(base + L".callback.json");
        const auto temp_path = std::filesystem::path(final_path.wstring() + L".tmp");
        ok &= Require(temp_path.native().size() > MAX_PATH &&
                (status == boundary_status ? final_path.native().size() == status_length + 25 && temp_path.native().size() == status_length + 29
                                           : final_path.native().size() > MAX_PATH),
            "long runtime: cover both suffix-only overflow and callback final path above MAX_PATH");
        errno = 0;
        SetLastError(ERROR_SUCCESS);
        std::ofstream plain(temp_path, std::ios::binary | std::ios::trunc);
        const bool plain_opened = plain.is_open();
        const auto plain_errno = plain_opened ? 0 : errno;
        const auto plain_error = plain_opened ? ERROR_SUCCESS : GetLastError();
        plain.close();
        std::cout << "long runtime plain ofstream: length=" << temp_path.native().size()
                  << " opened=" << plain_opened << " errno=" << plain_errno << " error=" << plain_error << '\n';
        if (plain_opened)
            ok &= Require(DeleteFileW(fixture::FixturePath(temp_path).c_str()) != FALSE,
                "long runtime: remove informational plain stream open probe");
        MountContext context;
        context.args.volume_object_id = 101;
        context.active_callback_count.store(2);
        context.peak_callback_count.store(3);
        context.last_callback_name = "long-runtime-initial";
        MountContext::OperationActivity operation{};
        operation.kind = 7;
        operation.callback = "long-runtime-operation";
        operation.request_id = 42;
        context.operation_activity.emplace(17, operation);
        WriteCallbackWatchdogFile(context, base);
        const auto first = fixture::Load(final_path);
        ok &= Require(first.find("\"activeCallbacks\":2,") != std::string::npos &&
                first.find("\"peakCallbacks\":3,") != std::string::npos &&
                first.find("\"lastCallback\":\"long-runtime-initial\"") != std::string::npos &&
                first.find("\"requestId\":42,\"volumeObjectId\":101,") != std::string::npos &&
                first.find("\"callback\":\"long-runtime-operation\"") != std::string::npos,
            "long runtime: watchdog publishes actual counters, callback and operation identity at the long path");
        context.last_callback_name = "long-runtime-replaced";
        WriteCallbackWatchdogFile(context, base);
        const auto replaced = fixture::Load(final_path);
        ok &= Require(replaced.find("\"lastCallback\":\"long-runtime-replaced\"") != std::string::npos &&
                replaced.find("long-runtime-initial") == std::string::npos && !fixture::Exists(temp_path),
            "long runtime: watchdog atomically replaces existing diagnostic and removes temporary name");
    }

    const auto relative_traversal = std::filesystem::path(L"..") / root.filename() / L"request.control";
    std::string refused = "must-be-cleared";
    ok &= Require(!IsSafeContainerControlPath(relative_traversal, false) &&
            !ReadAndConsumeContainerControlRequest(relative_traversal, refused) && refused.empty() &&
            !WriteContainerControlResponse(relative_traversal, request, result),
        "long runtime: extending I/O paths cannot admit relative parent traversal endpoints");
    ok &= Require(!IsSafeContainerControlPath(deep, true),
        "long runtime: a real long directory cannot become a control request leaf");

    const auto target_directory = root / L"protected-target";
    std::filesystem::create_directory(fixture::FixturePath(target_directory), ec);
    const auto target_request = target_directory / L"request.control";
    const auto protected_response = target_directory / L"response.txt";
    if (!Require(!ec && fixture::Save(target_request, envelope) && fixture::Save(protected_response, "preserve-response"),
            "long runtime: create independent protected reparse targets")) return false;
    const auto parent_link = deep / L"parent-link";
    const auto leaf_link = deep / L"leaf.control";
    const auto response_request = deep / L"linked-response.control";
    const auto response_link = std::filesystem::path(response_request.wstring() + L".response");
    ScopeExit remove_links{[&] {
        DeleteFileW(fixture::FixturePath(response_link).c_str());
        DeleteFileW(fixture::FixturePath(leaf_link).c_str());
        RemoveDirectoryW(fixture::FixturePath(parent_link).c_str());
    }};
    if (fixture::Symlink(parent_link, target_directory, true, ok))
    {
        const auto redirected = parent_link / L"request.control";
        refused = "must-be-cleared";
        ok &= Require(!IsSafeContainerControlPath(redirected, true) &&
                !ReadAndConsumeContainerControlRequest(redirected, refused) && refused.empty() &&
                !WriteContainerControlResponse(redirected, request, result) &&
                !fixture::Exists(target_directory / L"request.control.response"),
            "long runtime: a long reparse parent cannot redirect control reads or responses");
    }
    if (fixture::Symlink(leaf_link, target_request, false, ok))
    {
        refused = "must-be-cleared";
        ok &= Require(!IsSafeContainerControlPath(leaf_link, true) &&
                !ReadAndConsumeContainerControlRequest(leaf_link, refused) && refused.empty() && fixture::Exists(leaf_link),
            "long runtime: native request reader refuses a long reparse leaf without consuming it");
    }
    if (fixture::Symlink(response_link, protected_response, false, ok))
    {
        ok &= Require(!WriteContainerControlResponse(response_request, request, result) && fixture::Exists(response_link),
            "long runtime: native response writer refuses to replace a long reparse leaf");
    }
    ok &= Require(fixture::Load(target_request) == envelope && fixture::Load(protected_response) == "preserve-response",
        "long runtime: refused reparse operations preserve both target files byte for byte");
    return ok;
}
#endif
