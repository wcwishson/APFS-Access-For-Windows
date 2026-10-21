#define APFS_VOLUME_MANAGEMENT_TOOL_TESTING
#include "../tools/VolumeManagementImage.cpp"
#include "VolumeManagementTestFixture.h"
#include <bcrypt.h>
#include <sstream>

using namespace apfsaccess::volume_management_test;
namespace
{
unsigned checks = 0, documents = 0;
std::filesystem::path output;
void Check(bool b, const std::string& e) { ++checks; if (!b) throw std::runtime_error(e); }
Bytes IsolatedFixture()
{
    auto bytes = Fixture(); std::array<std::byte, 16> uuid{};
    Check(BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(uuid.data()), static_cast<ULONG>(uuid.size()),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0, "isolated fixture identity");
    for (std::size_t at = 0; at < bytes.size(); at += 4096) {
        Bytes nx(bytes.begin() + at, bytes.begin() + at + 4096);
        if (!ParseNxSuperblock(nx)) continue;
        std::copy(uuid.begin(), uuid.end(), nx.begin() + 0x48); FletcherForBlock(nx, 4096);
        std::copy(nx.begin(), nx.end(), bytes.begin() + at);
    }
    return bytes;
}
std::wstring W(const std::string& s) { return {s.begin(), s.end()}; }
std::vector<std::wstring> Args(const VolumeManagementRequest& r, const std::wstring& mode)
{
    std::vector<std::wstring> a{L"VolumeManagementImage", L"--operation", r.operation == VolumeManagementOperation::Create ? L"create" : L"delete",
        L"--mode", mode, L"--image", r.image.wstring(), L"--journal-directory", r.journal_directory.wstring(),
        L"--offset", std::to_wstring(r.offset_bytes), L"--container", W(r.container_uuid), L"--volume", W(r.volume_uuid),
        L"--oid", std::to_wstring(r.volume_oid), L"--xid", std::to_wstring(r.checkpoint_xid)};
    for (const auto& [id, path] : r.sibling_wals) { a.push_back(L"--wal"); a.push_back(std::to_wstring(id) + L"=" + path.wstring()); }
    if (r.operation == VolumeManagementOperation::Create)
        for (const auto& s : std::vector<std::wstring>{L"--name", W(r.name_utf8), L"--quota-blocks", std::to_wstring(r.quota_blocks),
            L"--reserve-blocks", std::to_wstring(r.reserve_blocks), L"--case-sensitive", r.case_sensitive ? L"true" : L"false"}) a.push_back(s);
    return a;
}
std::string Invoke(std::vector<std::wstring> args, int expected)
{
    std::vector<wchar_t*> pointers; for (auto& s : args) pointers.push_back(s.data());
    std::ostringstream captured; auto* before = std::cout.rdbuf(captured.rdbuf());
    const auto code = VolumeManagementImageMain(static_cast<int>(pointers.size()), pointers.data()); std::cout.rdbuf(before);
    const auto json = captured.str();
    Check(code == expected, "exit contract: " + json);
    Check(!json.empty() && json.front() == '{' && json.ends_with("}\n") && std::count(json.begin(), json.end(), '\n') == 1,
        "exactly one JSON document");
    Check(json.find("\"schemaVersion\":1") != std::string::npos, "schema version");
    std::ofstream f(output / ("document-" + std::to_string(++documents) + ".json")); f << json;
    Check(!!f, "persist JSON evidence"); return json;
}
std::string Token(const std::string& json)
{
    const std::string key = "\"confirmationToken\":\""; const auto at = json.find(key);
    Check(at != std::string::npos, "token field"); const auto value = json.substr(at + key.size(), 64);
    Check(value.size() == 64 && value.find_first_not_of("0123456789abcdef") == std::string::npos, "random confirmation field"); return value;
}
}
int wmain(int argc, wchar_t** argv)
{
    try {
        Check(argc == 2, "fresh evidence root argument required"); output = argv[1];
        Check(!std::filesystem::exists(output), "fresh directory required"); std::filesystem::create_directories(output);
        for (bool create : {true, false}) {
            const auto dir = output / (create ? "create" : "delete"); std::filesystem::create_directories(dir);
            const auto seed = IsolatedFixture(); auto r = Request(dir, create, seed); Save(r.image, seed);
            ProvisionOriginalWals(r);
            const auto bytes = Read(r.image);
            if (create) r.name_utf8 = "Name with \"quotes\" and \\ slash";
            const auto dry = Invoke(Args(r, L"dry-run"), 0); Check(Read(r.image) == bytes, "CLI preview never mutates image");
            auto apply = Args(r, L"apply"); apply.push_back(L"--confirm"); apply.push_back(W(Token(dry)));
            const auto done = Invoke(apply, 0); Check(done.find("\"outcome\":\"committed\"") != std::string::npos, "CLI real commit");
            Invoke(apply, 1); Invoke(Args(r, L"recover"), 0);
        }
        for (bool create : {true, false}) {
            const auto dir = output / (create ? "lost-create" : "lost-delete"); std::filesystem::create_directories(dir);
            const auto seed = IsolatedFixture(); auto r = Request(dir, create, seed); Save(r.image, seed);
            ProvisionOriginalWals(r);
            const auto bytes = Read(r.image);
            Invoke(Args(r, L"dry-run"), 0);
            const auto recovered = Invoke(Args(r, L"recover"), 0);
            Check(recovered.find("\"outcome\":\"cancelled\"") != std::string::npos &&
                recovered.find("\"confirmationToken\":\"\"") != std::string::npos, "lost prepare response is cancelled without token");
            Check(Read(r.image) == bytes, "prepared recovery is image-byte-identical");
            Invoke(Args(r, L"recover"), 0);
            const auto prepared = Invoke(Args(r, L"dry-run"), 0);
            auto cancel = Args(r, L"cancel"); cancel.push_back(L"--confirm"); cancel.push_back(W(Token(prepared)));
            Invoke(cancel, 0);
            const auto reconciled = Invoke(Args(r, L"recover"), 0);
            Check(reconciled.find("\"outcome\":\"cancelled\"") != std::string::npos && Read(r.image) == bytes,
                "lost cancel response is proved cancelled");
            auto apply = Args(r, L"apply"); apply.push_back(L"--confirm"); apply.push_back(W(Token(prepared))); Invoke(apply, 1);
        }
        {
            const auto dir = output / "observe"; std::filesystem::create_directories(dir);
            const auto bytes = IsolatedFixture(); const auto image = dir / "image.apfs"; Save(image, bytes);
            const std::vector<std::wstring> observed{L"VolumeManagementImage", L"--mode", L"observe", L"--image", image.wstring(),
                L"--offset", L"0"};
            const auto topology = Invoke(observed, 0);
            Check(topology.find("\"readOnly\":true") != std::string::npos && Read(image) == bytes &&
                topology.find("walPath") == std::string::npos && topology.find("siblingWals") == std::string::npos &&
                topology.find("spoolRoot") == std::string::npos, "read-only topology has no WAL authority");
            auto compatible = observed; compatible.push_back(L"--spool-root"); compatible.push_back((dir / "missing-spool").wstring());
            Check(Invoke(compatible, 0) == topology && !std::filesystem::exists(dir / "missing-spool"), "optional spool-root is unused compatibility input");
            for (const auto& option : {L"--operation", L"--oid", L"--wal", L"--journal-directory", L"--confirm"}) {
                auto invalid = observed; invalid.push_back(option); invalid.push_back(std::wstring(option) == L"--wal" ? L"101=D:\\unexpected.wal" : L"x");
                Invoke(invalid, 2);
            }
            auto invalid = observed; invalid[6] = L"00"; Invoke(invalid, 2);
            invalid = compatible; invalid.push_back(L"--spool-root"); invalid.push_back(dir.wstring()); Invoke(invalid, 2);
        }
        Invoke({L"VolumeManagementImage"}, 2);
        Invoke({L"VolumeManagementImage", L"--mode", L"dry-run", L"--mode", L"dry-run"}, 2);
        const auto r = Request(output, true, IsolatedFixture());
        auto args = Args(r, L"dry-run"); args.push_back(L"--confirm"); args.push_back(L"not-valid-for-dry-run"); Invoke(args, 2);
        args = Args(r, L"apply"); Invoke(args, 2);
        args = Args(r, L"dry-run"); args.push_back(L"--unknown"); args.push_back(L"x"); Invoke(args, 2);
        args = Args(r, L"dry-run"); const auto oid = std::find(args.begin(), args.end(), L"--oid"); *(oid + 1) = L"0x5000"; Invoke(args, 2);
        std::cout << "PASS CLI documents=" << documents << " checks=" << checks << '\n'; return 0;
    } catch (const std::exception& e) { std::cerr << "FAIL " << e.what() << '\n'; return 1; }
}
