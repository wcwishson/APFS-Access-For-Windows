#define APFS_PHYSICAL_KEEPER_FIXTURE_ONLY
#include "VolumePhysicalKeeperTests.cpp"
#undef APFS_PHYSICAL_KEEPER_FIXTURE_ONLY

int wmain(int argc, wchar_t** argv)
{
    try {
        Check(argc == 2 || (argc == 3 && std::wstring_view(argv[2]) == L"--all"), "private physical WAL fixture root");
        root = argv[1]; std::filesystem::create_directories(root);
        for (unsigned variant = 0; variant < 5; ++variant) {
            PhysicalFixture fixture("physical-wal-" + std::to_string(variant), VolumeImageOperation::Format);
            const auto before = fixture.Digests(); const auto& r = fixture.request;
            auto id = DeriveVolumePhysicalRecoveryIdentity(fixture.file->binding, r.container_uuid, 201);
            if (variant == 1) id = DerivePartitionlessVolumeRecoveryIdentity(r.container_uuid, 201);
            if (variant == 2) { auto other = fixture.file->binding; other.media.partition_guid[0] ^= std::byte{1};
                id = DeriveVolumePhysicalRecoveryIdentity(other, r.container_uuid, 201); }
            if (variant == 4) {
                WriteAheadLog owner({r.sibling_wals.at(201), id}); Check(owner.AcquireWriterLeaseOnly(), "independent partitioned production owner");
                Check(PrepareVolumePhysicalFormat(fixture.source, r).error == "VolumeImageWalBusy", "partitioned active owner vetoes");
            } else {
                {
                    TransactionManager writer(L"Strict"); writer.SetJournalPath(r.sibling_wals.at(201).wstring());
                    writer.SetVolumeIdentity(std::wstring(id.begin(), id.end())); TransactionManager::MutationIntent intent;
                    intent.kind = TransactionManager::MutationKind::CreateFile; intent.path = L"\\not-published.txt";
                    intent.object_id = 500; intent.generation = r.checkpoint_xid + 1;
                    Check(writer.Begin() && writer.RecordMutation(intent), "original production WAL fixture prepared");
                    Check(variant == 3 ? writer.Accept(r.checkpoint_xid) : writer.Abort(), "actual WAL acceptance or abort boundary");
                }
                const auto prepared = PrepareVolumePhysicalFormat(fixture.source, r);
                if (!variant) {
                    Check(prepared.outcome == VolumeImageOutcome::Prepared, "exact partitioned aborted original is clean: " + prepared.error);
                    Check(CancelVolumePhysicalFormat(fixture.source, r, prepared.token).outcome == VolumeImageOutcome::Cancelled,
                        "clean partitioned intent cancels");
                } else Check(prepared.outcome == VolumeImageOutcome::Refused && prepared.error ==
                    (variant == 3 ? "VolumeImageWalDebtOrPins" : "VolumeImageWalIdentityUnproven"),
                    "wrong partitionless/partitioned identity or accepted debt refuses: " + prepared.error);
            }
            Check(before == fixture.Digests() && fixture.file->Current() && !fixture.file->writes && !fixture.file->zeros,
                "all physical WAL admission controls preserve target and outside bytes");
        }
        Pass("exact physical production WAL identity CLEAN debt and active owner controls");
        std::cout << "PASS groups=" << groups << " checks=" << checks << " simulatedAuthority=1 hardware=0\n"; return 0;
    } catch (const std::exception& ex) { std::cerr << "FAIL checks=" << checks << " " << ex.what() << '\n'; return 1; }
}
