#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "VolumeFormatCapacityCases.h"
#include "VolumeFormatMultichunkCases.h"
using namespace apfsaccess::volume_image_test;
int wmain(int argc, wchar_t** argv)
{
    try {
        Check(argc >= 2 && argc <= 4, "fresh absolute evidence directory required"); root = argv[1]; std::filesystem::create_directories(root);
        if (argc >= 3) {
            if (std::wstring_view(argv[2]) == L"--multichunk-only") {
                Check(argc == 3, "multichunk selector takes no reference image"); FormatMultichunk();
                std::cout << "PASS groups=" << groups << " checks=" << checks << '\n'; return 0;
            }
            if (std::wstring_view(argv[2]) == L"--multichunk-controls") {
                Check(argc == 3, "controls selector takes no reference image");
                Positive(VolumeImageOperation::Format); Refusals(VolumeImageOperation::Format); TokensAndWal(VolumeImageOperation::Erase);
                Interruptions(VolumeImageOperation::Format); PolicyAndTail(VolumeImageOperation::Format);
                BusyAndBinding(VolumeImageOperation::Format); multichunk::SourceSpacePolicy();
                std::cout << "PASS groups=" << groups << " checks=" << checks << '\n'; return 0;
            }
            if (std::wstring_view(argv[2]) == L"--capacity-only") {
                Check(argc == 3, "capacity selector takes no reference image"); FormatCapacity();
                std::cout << "PASS groups=" << groups << " checks=" << checks << '\n'; return 0;
            }
            Check(std::wstring_view(argv[2]) == L"--retention-only", "known focused selector");
            RetiredHistory(VolumeImageOperation::Format, argc == 4 ? argv[3] : nullptr);
            SnapshotOwners(true); std::cout << "PASS groups=" << groups << " checks=" << checks << '\n'; return 0;
        }
        const auto fixture = Fixture(); Save(root / "original.apfs", fixture);
        Positive(VolumeImageOperation::Format); Positive(VolumeImageOperation::Erase); Refusals(VolumeImageOperation::Format);
        TokensAndWal(VolumeImageOperation::Erase); Interruptions(VolumeImageOperation::Format); Interruptions(VolumeImageOperation::Erase);
        JournalTails(VolumeImageOperation::Erase); LongPath(VolumeImageOperation::Format);
        PolicyAndTail(VolumeImageOperation::Format); BusyAndBinding(VolumeImageOperation::Format);
        RecoveryConflicts(VolumeImageOperation::Format); SnapshotOwners(true); FormatThenResize(); FormatCapacity(); FormatMultichunk();
        std::cout << "PASS groups=" << groups << " checks=" << checks << '\n'; return 0;
    } catch (const std::exception& ex) { std::cerr << "FAIL checks=" << checks << " " << ex.what() << '\n'; return 1; }
}
