#include "BlockDevice.h"
#include "../src/VolumePhysicalInstanceInternal.h"

namespace apfsaccess::rw::physical_instance
{
bool KeeperRawInstanceForTests(std::wstring_view, std::wstring&);
}

// Like the raw runtime device fixture, substitute only the transport observation
// in this test TU. The normal producer object has no test factory or override.
#define Selected KeeperRawInstanceForTests
#include "../src/VolumeKeeperAdmission.cpp"
#undef Selected
