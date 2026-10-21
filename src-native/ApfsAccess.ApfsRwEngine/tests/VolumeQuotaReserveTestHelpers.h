#define APPLE_CLONE_TEST_HELPERS_ONLY
#include "AppleCloneCowTests.cpp"
#include "MetadataStore.h"
#include "NativeVolumeRename.h"
#include "VolumeMetadata.h"
#include <filesystem>
#include <bcrypt.h>

namespace
{
using Store = MetadataStore;
void SaveImage(const std::filesystem::path& path, const std::vector<std::byte>& bytes)
{
    std::ofstream file(path, std::ios::binary);
    file.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    Check(!!file, "save image");
}
std::vector<std::byte> ReadImage(const std::filesystem::path& path)
{
    std::ifstream file(path, std::ios::binary);
    std::vector<char> raw((std::istreambuf_iterator<char>(file)), {});
    std::vector<std::byte> bytes(raw.size());
    memcpy(bytes.data(), raw.data(), raw.size()); return bytes;
}
BuilderStore RenameSpec()
{
    auto spec = CloneSpec(1);
    spec.uuid_hex = "64916491649164916491649164916491"; // private quota fixture lease namespace
    auto sibling = spec.volumes[0]; sibling.oid = 102; sibling.name = "Data";
    sibling.reserve_block_count = 16; sibling.quota_block_count = 128;
    for (auto& record : sibling.filesystem_records)
        if (Type(record) == 8) PutU64LE(record.value, 8, 144);
    PutU64LE(sibling.extentref_records[0].key, 0, (2ull << 60) | 144);
    for (unsigned i = 0; i != 4; ++i)
        spec.authoritative_seeded_main_blocks.push_back({144 + i, std::vector<std::byte>(kBlockSize, std::byte(90 + i))});
    spec.volumes.push_back(sibling);
    spec.volumes[0].reserve_block_count = 12; spec.volumes[0].quota_block_count = 128;
    return spec;
}
using Tx = TransactionManager;
using Owner = ContainerMountCoordinator;
std::unique_ptr<Owner> OpenOwner(const std::filesystem::path& path, Tx* journal = nullptr)
{
    std::string error;
    auto owner = Owner::Open(path.string(), 0, error, CatalogLoadPolicy::StrictApple, true, true);
    Check(!!owner, "open canonical image owner: " + error);
    std::vector<VolumeCheckpointPins> census;
    for (std::uint64_t oid : {101, 102})
    {
        ContainerVolumeSession session; session.volume_object_id = oid;
        session.container_uuid_hex = owner->ContainerUuidHex(); session.requested_write = true;
        session.use_canonical_transaction = true; session.recovery_identity = "unchanged-owner-" + std::to_string(oid);
        session.metadata_context.allow_legacy_scaffold_for_fixtures = false;
        Check(owner->MountVolume(session, error), "mount native image session: " + error);
        VolumeCheckpointPins pins; pins.volume_object_id = oid;
        if (oid == 101 && journal)
        {
            Check(journal->LoadRequiredCheckpointXidsSinceCleanup(pins.required_checkpoint_xids, &error), "load canonical recovery pins: " + error);
            pins.unapplied_accepted_work = journal->HasUnappliedAcceptedWork();
        }
        census.push_back(pins);
    }
    Check(owner->InitializeRequiredCheckpointCensus(census, error), "initialize complete two-volume census: " + error);
    return owner;
}
void Configure(Tx& journal, const std::filesystem::path& path)
{
    journal.SetJournalPath(std::filesystem::absolute(path).wstring());
    journal.SetVolumeIdentity(L"apfs-vol:64916491649164916491649164916491:101");
}
void CheckSuccess(const ContainerCommitResult& result)
{
    Check(result.committed && !result.commit_recovery_required &&
        result.commit_status_code == static_cast<int>(Store::CommitStatus::Committed),
        "durable rename succeeds: " + result.error + " stage=" + result.commit_stage);
}

}
