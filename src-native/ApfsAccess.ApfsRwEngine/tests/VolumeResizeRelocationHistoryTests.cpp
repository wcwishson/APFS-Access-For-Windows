#define APFS_RELOCATION_KEEPER_FIXTURE_ONLY
#include "VolumeResizeRelocationKeeperTests.cpp"
#undef APFS_RELOCATION_KEEPER_FIXTURE_ONLY
#include <fstream>

int wmain(int argc, wchar_t** argv)
{
    try {
        Check(argc == 2 || (argc == 3 && std::wstring_view(argv[2]) == L"--all"), "private historical relocation fixture root");
        root = argv[1]; std::filesystem::create_directories(root); auto r = RelocationImage("historical-root", true);
        std::vector<apfsaccess::catalog::BtreeRecord> expected; AppleObjectLocation historical;
        {
            Target target(r.image); historical = AddFixtureHistoricalRoot(target); std::string error;
            Check(historical.physical_block >= r.target_bytes / 4096, "authored historical owner lies in removed tail");
            Check(ReadBtreeLeafRecords(target, 4096, historical.physical_block, false, mc::Load(target).volumes.front().superblock.omap_oid,
                historical.xid, expected, error), error);
            const auto inventory = vi::InspectResizeRelocationSource(target, r);
            Check(!inventory.unknown_blocks, "all historical fixture allocations have exact canonical owners");
        }
        const auto original = Digests(r.image); const auto prepared = PrepareVolumeResize(r);
        Check(prepared.outcome == VolumeImageOutcome::Prepared && original == Digests(r.image), "historical actual prepare preserves original: " + prepared.error);
        const auto done = ApplyVolumeResize(r, prepared.token); Check(done.outcome == VolumeImageOutcome::Committed, "historical actual relocation: " + done.error);
        {
            Target target(r.image); const auto cp = mc::Load(target); const auto& volume = cp.volumes.front(); std::string error;
            std::vector<apfsaccess::catalog::BtreeRecord> mappings;
            Check(ReadBtreeLeafRecords(target, 4096, volume.object_map.tree.physical_block, true, 0, cp.container.superblock.xid, mappings, error), error);
            const auto mapped = std::find_if(mappings.begin(), mappings.end(), [&](const auto& record) {
                return ReadU64LE(record.key, 0) == historical.object_id && ReadU64LE(record.key, 8) == historical.xid;
            });
            Check(mapped != mappings.end() && ReadU64LE(mapped->value, 8).value() < r.target_bytes / 4096,
                "exact historical OID/XID key survives below target");
            std::vector<apfsaccess::catalog::BtreeRecord> actual;
            Check(ReadBtreeLeafRecords(target, 4096, ReadU64LE(mapped->value, 8).value(), false, volume.superblock.omap_oid,
                historical.xid, actual, error), error);
            // Physical extent addresses change, while every other root record
            // and each extent's object/logical length/flags remain original.
            Check(actual.size() == expected.size(), "historical complete record count");
            std::ofstream oracle(r.image.parent_path() / "payload-ranges.txt"); oracle << r.image.filename().string() << '\n';
            std::uint64_t total = 0;
            for (std::size_t i = 0; i < actual.size(); ++i) {
                Check(actual[i].key == expected[i].key, "historical exact record key");
                if ((ReadU64LE(actual[i].key, 0).value_or(0) >> 60) != 8) { Check(actual[i].value == expected[i].value, "historical exact non-extent record"); continue; }
                AppleFileExtentRecord before, after;
                Check(DecodeAppleFileExtentRecord(expected[i], 4096, before, error) && DecodeAppleFileExtentRecord(actual[i], 4096, after, error), error);
                auto normalized = after; normalized.physical_block = before.physical_block;
                apfsaccess::catalog::BtreeRecord record; Check(EncodeAppleFileExtentRecord(normalized, record, error) && record.value == expected[i].value,
                    "historical extent changes physical address only");
                Bytes bytes; Check(target.Read(after.physical_block * 4096, static_cast<std::size_t>(after.length_bytes), bytes) &&
                    std::all_of(bytes.begin(), bytes.end(), [](auto value) { return value == std::byte{0x59}; }), "historical full stream payload exact");
                oracle << after.logical_address << ' ' << after.physical_block * 4096 << ' ' << after.length_bytes << '\n'; total += after.length_bytes;
            }
            Check(total == 8192 && oracle.good(), "complete canonical range oracle exported");
            RetainedPayload(target, true); mc::Verify(target, cp);
            auto history = AcquireVolumeKeeperHistory(prepared.source_identity, target, r.journal_directory, {});
            NativeMetadataWrite(target); RetainedPayload(target, true);
        }
        Check(RecoverVolumeResize(r).outcome == VolumeImageOutcome::Committed, "authored retained-root relocation permits later ordinary native reopen");
        Pass("actual authored historical root and payload relocate without losing original OID XID or records");
        std::cout << "PASS groups=" << groups << " checks=" << checks << " fixtureAuthoredHistory=1\n"; return 0;
    } catch (const std::exception& ex) { std::cerr << "FAIL checks=" << checks << " " << ex.what() << '\n'; return 1; }
}
