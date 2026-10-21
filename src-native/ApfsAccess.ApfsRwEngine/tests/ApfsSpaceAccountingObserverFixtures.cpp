#define main SpaceAccountingUnitTestsMain
#include "ApfsSpaceAccountingTests.cpp"
#undef main

#include <filesystem>
#include <fstream>

int main(int argc, char** argv)
{
    try
    {
        if (argc != 2) throw std::runtime_error("private fixture directory required");
        const auto root = std::filesystem::path(argv[1]);
        std::filesystem::create_directories(root);
        const auto save = [&](const char* name, const SnapshotFixture& fixture) {
            const auto path = root / name;
            Check(!std::filesystem::exists(path), "fixture already exists");
            std::ofstream file(path, std::ios::binary);
            file.write(reinterpret_cast<const char*>(fixture.image.data()),
                static_cast<std::streamsize>(fixture.image.size()));
            file.close();
            Check(file.good(), "fixture write failed");
        };
        save("shared.img", Shared());
        auto partial = Shared(16384);
        Payload(partial, 7, 20, 222, 4);
        Refs(partial, 8, 20, {{220, 2, kApplePhysicalExtentKindUpdate, 30, -1},
            {224, 2, kApplePhysicalExtentKindNew, 30, 1}});
        Allocate(partial, {224, 225});
        save("partial.img", partial);

        SnapshotFixture empty;
        empty.snapshots.clear();
        empty.Inventory({});
        empty.Edit(5, [](auto& bytes) { PutU32LE(bytes, 0x2C, 0); PutU64LE(bytes, 0x38, 0); });
        save("empty.img", empty);

        auto backup = Shared();
        backup.Edit(4, [](auto& bytes) { PutU16LE(bytes, 0x3C4, 0x180); });
        save("backup.img", backup);
        auto invalid = Shared();
        Refs(invalid, 8, 20, {{220, 4, kApplePhysicalExtentKindUpdate, 30, -2}});
        save("bad-reference.img", invalid);

        SnapshotFixture multiple;
        BuilderStore spec;
        spec.block_count = 512;
        spec.xid = 20;
        spec.volumes.resize(2);
        spec.volumes[0].uuid_hex = std::string(32, 'b');
        spec.volumes[1].oid = 102;
        spec.volumes[1].uuid_hex = std::string(32, 'c');
        multiple.image = BuildAuthoritativeStoreImage(spec);
        multiple.Edit(2, [](auto& bytes) { PutU32LE(bytes, 0x20, 1); });
        save("multiple.img", multiple);
        std::cout << "PASS created six snapshot-space observer fixtures\n";
        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
