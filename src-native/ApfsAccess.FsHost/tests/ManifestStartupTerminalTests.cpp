#include "../src/ManifestStartupTerminal.h"
#include <fstream>
#include <iostream>
#include <stdexcept>

namespace
{
unsigned checks = 0;
void Check(bool ok, const char* why) { ++checks; if (!ok) throw std::runtime_error(why); }
std::string Read(const std::filesystem::path& path)
{ std::ifstream input(path, std::ios::binary); return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()}; }
void Write(const std::filesystem::path& path, std::string_view text)
{ std::ofstream output(path, std::ios::binary); output << text; output.flush(); Check(output.good(), "private fixture write"); }
}
int wmain(int argc, wchar_t** argv)
{
    try {
        Check(argc == 2 || (argc == 3 && std::wstring_view(argv[2]) == L"--all"), "private evidence root");
        const std::filesystem::path root = argv[1]; std::filesystem::create_directories(root);
        FILETIME created{}, exited{}, kernel{}, user{};
        Check(GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user), "independent process creation identity");
        const auto started = (std::uint64_t(created.dwHighDateTime) << 32) | created.dwLowDateTime;
        Write(root / "expected-owner.json", "{\"ownerPid\":" + std::to_string(GetCurrentProcessId()) +
            ",\"ownerStartFileTimeUtc\":" + std::to_string(started) + "}");
        const auto path = root / "manifest.json";
        constexpr std::string_view digest = "3de48c78052c93b2aca823c6def75530e0e5cad8b388ee6f84a2c95be77434a3";
        const std::string text = R"({"format":"apfs-access-container-manifest","version":1,"containerUuid":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","device":"D:\\not-opened.img","deviceOffsetBytes":0,"manifestSha256":")" +
            std::string(digest) + R"(","volumes":[{"objectId":101,"containerUuid":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":"Pressure","mount":"D:\\not-mounted","requestedWrite":true,"recoveryIdentity":"apfs-recovery-v1-HC5Q1aNEk2JDEtznvahLwe3ulpApvzpCq-VL93IPLxE"}]})";
        Write(path, text); apfsaccess::catalog::ContainerManifest manifest; std::string error;
        const auto utf8 = path.u8string();
        Check(apfsaccess::catalog::ParseContainerManifest(std::string(utf8.begin(), utf8.end()), manifest, error), "actual checksum-bound manifest parser");
        Check(manifest.manifest_sha256 == digest, "independent fixture checksum");
        for (const auto* stage : {L"journal-root-required", L"argument-expansion-failed", L"container-open-failed"}) {
            const auto status = root / (std::wstring(stage) + L".json");
            const auto early_return = [&] {
                apfsaccess::host::ManifestStartupTerminal terminal(status.wstring(), manifest, digest);
                return 25;
            };
            Check(early_return() == 25 && std::filesystem::is_regular_file(status), "scope exit publishes pre-coordinator failure");
            const auto contents = Read(status);
            Check(contents.find("\"leaseHeld\":false") != contents.npos && contents.find("\"volumes\":[]") != contents.npos &&
                contents.find("\"checkpointXid\":0") != contents.npos && contents.find("\"ready\":true") == contents.npos,
                "no source checkpoint readiness or lease is invented");
        }
        const auto disarmed = root / "coordinator-owned.json";
        { apfsaccess::host::ManifestStartupTerminal terminal(disarmed.wstring(), manifest, digest); terminal.CoordinatorAcquired();
          Check(!terminal.Publish(), "coordinator ownership disarms empty settlement"); }
        Check(!std::filesystem::exists(disarmed), "normal coordinator settlement remains sole authority");
        const auto unbound = root / "unbound.json";
        { apfsaccess::host::ManifestStartupTerminal terminal(unbound.wstring(), manifest, std::string(64, '0'));
          Check(!terminal.Publish(), "launch checksum mismatch cannot publish"); }
        Check(!std::filesystem::exists(unbound), "untrusted manifest leaves status absent");
        auto malformed = text; malformed[malformed.find("Pressure")] = 'X'; Write(root / "corrupt-manifest.json", malformed);
        auto bad_path = (root / "corrupt-manifest.json").u8string(); apfsaccess::catalog::ContainerManifest rejected;
        Check(!apfsaccess::catalog::ParseContainerManifest(std::string(bad_path.begin(), bad_path.end()), rejected, error), "altered manifest fails original checksum");
        const auto stale = root / "stale-ready.json"; const std::string ready = "{\"leaseHeld\":true,\"volumes\":[{\"mounted\":true,\"ready\":true}]}";
        Write(stale, ready);
        { apfsaccess::host::ManifestStartupTerminal terminal(stale.wstring(), manifest, digest);
          Check(!terminal.Publish(), "existing ready proof retains veto"); terminal.CoordinatorAcquired(); }
        Check(Read(stale) == ready, "stale-ready bytes remain exact");
        const auto directory = root / "directory-status"; std::filesystem::create_directory(directory);
        { apfsaccess::host::ManifestStartupTerminal terminal(directory.wstring(), manifest, digest);
          Check(!terminal.Publish(), "directory target cannot become terminal file"); terminal.CoordinatorAcquired(); }
        std::cout << "PASS checks=" << checks << " noDeviceOpen=1 noMount=1\n"; return 0;
    } catch (const std::exception& ex) { std::cerr << "FAIL checks=" << checks << " " << ex.what() << '\n'; return 1; }
}
