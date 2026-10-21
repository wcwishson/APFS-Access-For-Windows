// Test-only minter for mountable Apple-format fixture images.
// Reuses the header-only synthetic builder (never a parser) to emit a small
// single-volume container with an authoritative checkpoint that the native
// reader, coordinator, and FsHost can open end to end. The output is
// synthetic validation media, not macOS formatter output.
#include "ApfsExtendedRecordCodec.h"
#include "ApfsFormat.h"
#include "RandomAccessSource.h"
#include "TestFixtureBuilder.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace
{
using namespace apfsaccess::catalog;
using namespace apfsaccess::rw;
using namespace apfsaccess::testfixture;

void Require(bool value, const std::string& error)
{
    if (!value) throw std::runtime_error(error);
}

// Empty projectable root: FsHost can mount and enumerate it, and the live
// commit path can create the first files.
std::vector<BtreeRecord> EmptyRootRecords()
{
    std::string error;
    std::vector<BtreeRecord> records;
    AppleInodeRecord root;
    root.object_id = 2;
    root.parent_id = 2;
    root.private_id = 9;
    root.children_or_links = 0;
    root.mode = 0040755;
    BtreeRecord encoded;
    Require(EncodeAppleInodeRecord(root, encoded, error), error);
    records.push_back(encoded);
    return records;
}

void Usage()
{
    std::cerr << "MintAppleFixtureImage --out <file.apfs.img> [--volume-name Main] [--blocks 1024]\n"
                 "Writes a synthetic Apple-format container (test media only).\n";
}
} // namespace

int main(int argc, char** argv)
{
    try
    {
        std::string out;
        std::string volume_name = "Main";
        std::uint64_t blocks = 1024;
        for (int i = 1; i < argc; ++i)
        {
            const std::string arg(argv[i]);
            auto need_value = [&](std::string& target)
            {
                Require(i + 1 < argc, "Missing value for " + arg);
                target = argv[++i];
            };
            if (arg == "--out") need_value(out);
            else if (arg == "--volume-name") need_value(volume_name);
            else if (arg == "--blocks")
            {
                std::string raw;
                need_value(raw);
                blocks = std::stoull(raw);
            }
            else
            {
                Usage();
                return 2;
            }
        }
        Require(!out.empty(), "Missing --out");
        Require(blocks >= 256 && blocks <= 16384, "blocks must be in [256, 16384]");
        Require(!volume_name.empty() && volume_name.size() <= 64, "bad volume name");

        BuilderStore spec;
        spec.authoritative_checkpoint = true;
        spec.block_count = blocks;
        spec.authoritative_internal_pool_blocks = 64;
        spec.authoritative_checkpoint_ring_blocks = 32;
        spec.volumes.resize(1);
        spec.volumes[0].oid = 101;
        spec.volumes[0].name = volume_name;
        spec.volumes[0].incompat = kIncompatCaseInsensitive;
        spec.volumes[0].projectable = true;
        spec.volumes[0].next_object_id = 1000;
        spec.volumes[0].additional_file_system_allocated_blocks = 4;
        spec.volumes[0].filesystem_records = EmptyRootRecords();

        auto bytes = BuildStoreImage(spec);
        {
            std::error_code ec;
            const auto parent = std::filesystem::path(out).parent_path();
            if (!parent.empty()) std::filesystem::create_directories(parent, ec);
            Require(!ec, "Cannot create output directory");
            std::ofstream file(out, std::ios::binary | std::ios::trunc);
            Require(!!file, "Cannot open output file");
            file.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
            Require(!!file, "Cannot write output file");
        }

        // Self-verify through the independent read path before reporting.
        VectorRandomAccessSource source(bytes);
        std::string error;
        auto view = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
        Require(view.has_value(), "Self-verify failed: " + error);
        Require(view->volumes.size() == 1, "Self-verify: expected one volume");
        std::cout << "minted " << out << "\n"
                  << "  bytes: " << bytes.size() << "\n"
                  << "  container: " << view->container.superblock.uuid_hex
                  << " xid=" << view->container.superblock.xid << "\n"
                  << "  volume: oid=" << view->volumes[0].superblock.object_id
                  << " name=" << view->volumes[0].superblock.name_utf8
                  << " uuid=" << view->volumes[0].superblock.uuid_hex << "\n";
        return 0;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "MintAppleFixtureImage failed: " << ex.what() << "\n";
        return 1;
    }
}
