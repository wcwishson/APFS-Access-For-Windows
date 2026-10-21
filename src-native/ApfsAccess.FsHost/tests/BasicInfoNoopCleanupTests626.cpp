#define main UnusedFullSemanticsMain626
#include "FsHostSemanticsTests.cpp"
#undef main
#include "BasicInfoNoopCleanupTests626.h"
int main(int argc, char** argv)
{
    if (argc != 2) return 2;
    const bool passed = TestBasicInfoNoopCleanup626(argv[1]);
    std::cout << (passed ? "PASS " : "FAIL ") << argv[1] << '\n';
    return passed ? 0 : 1;
}
