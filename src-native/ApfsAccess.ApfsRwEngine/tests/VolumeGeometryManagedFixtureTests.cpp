#define wmain FormatStreamedFixtureMain
#include "VolumeFormatStreamedTests.cpp"
#undef wmain

int wmain(int argc, wchar_t** argv)
{
    try {
        Check(argc >= 3, "private fixture command and scope required");
        if (std::wstring_view(argv[1]) == L"create") {
            Check(argc == 3, "private fixture root required"); root = argv[2];
            const auto r = Large("source"); const auto source = Source(); const auto cp = mc::Load(source);
            VolumeImageResult manifest; manifest.pre_xid = r.checkpoint_xid;
            std::cout << VolumeImageJson(r, manifest) << '\n';
            for (const auto& v : cp.volumes)
                std::cout << v.superblock.object_id << ' ' << v.superblock.uuid_hex << '\n';
        } else if (std::wstring_view(argv[1]) == L"write") {
            Check(argc == 5, "completed image, journal directory and original identity required");
            Target target(argv[2]); const std::wstring wide_identity(argv[4]);
            Check(wide_identity.size() == 80 && std::all_of(wide_identity.begin(), wide_identity.end(),
                [](auto c) { return (c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f'); }), "exact original identity");
            std::string identity; for (const auto c : wide_identity) identity.push_back(static_cast<char>(c));
            auto history = AcquireVolumeKeeperHistory(identity, target, argv[3], {});
            mc::NativeWrite(target);
            std::cout << "PASS canonical native write with held completed history\n";
        } else throw std::runtime_error("unknown private fixture command");
        return 0;
    } catch (const std::exception& ex) { std::cerr << "FAIL " << ex.what() << '\n'; return 1; }
}
