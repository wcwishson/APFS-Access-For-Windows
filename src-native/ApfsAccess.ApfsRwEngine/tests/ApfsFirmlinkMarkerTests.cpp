#include "ApfsContainerCatalog.h"
#include "ApfsFirmlinkRouter.h"
#include "NativeApfsReader.h"
#include "TestFixtureBuilder.h"

#include <filesystem>
#include <functional>
#include <iostream>
#include <stdexcept>

using namespace apfsaccess::catalog;
using namespace apfsaccess::rw;
using namespace apfsaccess::testfixture;

namespace
{
std::size_t assertions = 0;
void Check(bool condition, const char* message)
{
    ++assertions;
    if (!condition) throw std::runtime_error(message);
}

// One directory carrying (or not) a firmlink marker xattr. The marker
// payload is opaque: no production code may interpret it, and the
// projection must report it without routing anything.
struct MarkerFixture
{
    std::filesystem::path image_path;
    std::vector<std::byte> held_bytes;

    explicit MarkerFixture(const std::vector<std::pair<std::string, std::vector<std::byte>>>& markers)
    {
        BuilderStore spec;
        spec.authoritative_checkpoint = true;
        spec.block_count = 256;
        spec.volumes.resize(1);
        spec.volumes[0].oid = 101;
        auto& records = spec.volumes[0].filesystem_records;
        std::string error;
        apfsaccess::catalog::BtreeRecord encoded;
        AppleInodeRecord root;
        root.object_id = root.parent_id = root.private_id = 2;
        root.children_or_links = 1;
        root.mode = 0040755;
        Check(EncodeAppleInodeRecord(root, encoded, error), ("root encodes: " + error).c_str());
        records.push_back(encoded);
        std::uint64_t oid = 17;
        for (const auto& [name, bytes] : markers)
        {
            AppleInodeRecord dir;
            dir.object_id = dir.private_id = oid;
            dir.parent_id = 2;
            dir.children_or_links = 0;
            dir.mode = 0040755;
            Check(EncodeAppleInodeRecord(dir, encoded, error), ("dir encodes: " + error).c_str());
            records.push_back(encoded);
            AppleDirectoryRecord link;
            link.parent_id = 2;
            link.file_id = oid;
            link.flags = 4;
            link.name_utf8 = "dir" + std::to_string(oid);
            Check(EncodeAppleDirectoryRecord(link, encoded, error), ("link encodes: " + error).c_str());
            records.push_back(encoded);
            AppleXattrRecord marker;
            marker.object_id = oid;
            marker.name_utf8 = name;
            marker.flags = kAppleXattrDataEmbedded;
            marker.data = bytes;
            Check(EncodeAppleXattrRecord(marker, encoded, error), ("marker encodes: " + error).c_str());
            records.push_back(encoded);
            ++oid;
        }
        held_bytes = BuildStoreImage(spec);
        image_path = std::filesystem::temp_directory_path() / ("firmlink-marker-" + std::to_string(oid) + ".apfs");
        FILE* file = nullptr;
        Check(_wfopen_s(&file, image_path.c_str(), L"wb") == 0 && file != nullptr, "marker image opens");
        Check(fwrite(reinterpret_cast<const char*>(held_bytes.data()), 1, held_bytes.size(), file) == held_bytes.size(),
            "marker image writes");
        fclose(file);
    }

    ~MarkerFixture()
    {
        std::error_code ec;
        std::filesystem::remove(image_path, ec);
    }

    NativeApfsVolumeProjection Project()
    {
        BlockDevice device(image_path.wstring(), 0);
        NativeApfsVolumeProjection projection{};
        std::wstring error;
        Check(NativeApfsReader::TryLoadVolumeProjection(device, 101, projection, error),
            "marker volume projects");
        return projection;
    }
};

void MarkerReportedPreservedAndImportSucceeds()
{
    MarkerFixture fixture({{std::string(kFirmlinkEaName), {std::byte{0x12}, std::byte{0xab}, std::byte{0x34}}}});
    const auto projection = fixture.Project();
    Check(projection.firmlink_markers_unsupported == 1, "one opaque marker reported");
    const auto found = projection.extended_attributes_by_inode.find(17);
    Check(found != projection.extended_attributes_by_inode.end(), "marker owner projected");
    const auto marker = found->second.find(std::string(kFirmlinkEaName));
    const std::vector<std::byte> expected{std::byte{0x12}, std::byte{0xab}, std::byte{0x34}};
    Check(marker != found->second.end() && marker->second.data == expected,
        "opaque marker bytes preserved unrouted");
}

void CleanVolumeReportsZero()
{
    MarkerFixture fixture({});
    const auto projection = fixture.Project();
    Check(projection.firmlink_markers_unsupported == 0, "clean volume reports zero");
}

void MultipleMarkersCounted()
{
    MarkerFixture fixture({
        {std::string(kFirmlinkEaName), {std::byte{0x01}}},
        {std::string(kFirmlinkEaName), {std::byte{0x02}, std::byte{0x03}}},
    });
    const auto projection = fixture.Project();
    Check(projection.firmlink_markers_unsupported == 2, "two markers counted");
}

void NonMarkerXattrsIgnored()
{
    MarkerFixture fixture({{"user.comment", {std::byte{0x41}}}});
    const auto projection = fixture.Project();
    Check(projection.firmlink_markers_unsupported == 0, "ordinary xattr not counted");
}
} // namespace

int main()
{
    const std::vector<std::pair<const char*, std::function<void()>>> tests = {
        {"marker reported, preserved, import succeeds", MarkerReportedPreservedAndImportSucceeds},
        {"clean volume reports zero", CleanVolumeReportsZero},
        {"multiple markers counted", MultipleMarkersCounted},
        {"non-marker xattrs ignored", NonMarkerXattrsIgnored},
    };
    for (const auto& [name, test] : tests)
    {
        try { test(); std::cout << "PASS " << name << '\n'; }
        catch (const std::exception& ex) { std::cerr << "FAIL " << name << ": " << ex.what() << '\n'; return 1; }
    }
    std::cout << tests.size() << " tests, " << assertions << " assertions\n";
    return 0;
}
