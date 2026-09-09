#define main ApfsObserverEntryForTest
#include "../tools/ApfsObserver.cpp"
#undef main
#include <stdexcept>
int main(int argc, char** argv)
{
#ifdef _WIN32
    try {
        if (argc == 3 && std::string(argv[2]) == "--writer-admission") {
            const auto path = ToWide(argv[1]);
            HANDLE writer = CreateFileW(path.c_str(), GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
            if (writer == INVALID_HANDLE_VALUE) throw std::runtime_error("writer setup");
            // The observer's public failure contract is exit 2 plus its fixed message.
            // A thrown exception is caught below (exit 1), so RED never invokes WER.
            VerificationImageLease denied(argv[1]);
            CloseHandle(writer);
            throw std::runtime_error("writer was admitted");
        }
        if (argc != 2) throw std::runtime_error("private test image path required");
        const std::string path = argv[1];
        { std::ofstream file(path, std::ios::binary); file << "stable image lease"; if (!file.good()) throw std::runtime_error("create fixture"); }
        unsigned checks = 0;
        const auto check = [&](bool ok, const char* reason) { ++checks; if (!ok) throw std::runtime_error(reason); };
        {
            VerificationImageLease lease(path);
            check(lease.SizeBytes() == 18 && lease.VerifyUnchanged(), "initial held identity");
            check(lease.Identity().find("windows-file:") == 0, "handle-bound identity");
            for (const auto access : {DWORD(GENERIC_WRITE), DWORD(DELETE)}) {
                HANDLE denied = CreateFileW(ToWide(path).c_str(), access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr, OPEN_EXISTING, 0, nullptr);
                const bool refused = denied == INVALID_HANDLE_VALUE && GetLastError() == ERROR_SHARING_VIOLATION;
                if (denied != INVALID_HANDLE_VALUE) CloseHandle(denied);
                check(refused, "lease denies writer or replacement handle");
            }
            HANDLE reader = CreateFileW(ToWide(path).c_str(), GENERIC_READ, FILE_SHARE_READ,
                nullptr, OPEN_EXISTING, 0, nullptr);
            check(reader != INVALID_HANDLE_VALUE, "read-only observer may coexist"); CloseHandle(reader);
            std::vector<std::byte> bytes;
            check(lease.Read(0, 18, bytes) && bytes.size() == 18 && lease.VerifyUnchanged(), "same leased handle supplies bytes");
            check(!lease.Read(17, 2, bytes) && bytes.empty(), "out-of-range read clears bytes");
        }
        HANDLE released = CreateFileW(ToWide(path).c_str(), GENERIC_WRITE, FILE_SHARE_READ,
            nullptr, OPEN_EXISTING, 0, nullptr);
        check(released != INVALID_HANDLE_VALUE, "lease closes after verification"); CloseHandle(released);
        std::cout << "PASS verifier observer lease " << checks << " checks\n"; return 0;
    } catch (const std::exception& e) { std::cerr << "FAIL " << e.what() << '\n'; return 1; }
#else
    (void)argc; (void)argv; return 2;
#endif
}
