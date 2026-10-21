#include "AppleVolumeTransaction.h"
#include "ApfsSnapshotStore.h"
#include "ApfsExtendedRecordCodec.h"
#include "NativeApfsReader.h"
#include "../src/SnapshotPlanningSource.h"
#include "RandomAccessSource.h"
#include <algorithm>
#include <cctype>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#ifdef _WIN32
#include <Windows.h>
extern "C" const GUID GUID_DEVINTERFACE_DISK =
    {0x53f56307, 0xb6bf, 0x11d0, {0x94, 0xf2, 0x00, 0xa0, 0xc9, 0x1e, 0xfb, 0x8b}};
#endif

using namespace apfsaccess::catalog;
using namespace apfsaccess::rw;
namespace {
void Require(bool value, const std::string& message) {
    if (!value) throw std::runtime_error(message);
}
void Consumption(const char* phase, bool ok, const std::string& error, const ApfsReadBudget& budget) {
    const auto used = budget.Consumed();
    const auto refused = budget.ReservationFailure();
    std::cout << phase << " ok=" << ok << " error=" << error << " reads=" << used.reads
        << " read_bytes=" << used.read_bytes << " records=" << used.records
        << " record_bytes=" << used.record_bytes << " refused_count=" << refused.count
        << " refused_bytes=" << refused.bytes << '\n';
}
class MemoryTarget final : public AppleCheckpointWriteTarget {
public:
    explicit MemoryTarget(std::vector<std::byte> bytes) : bytes(std::move(bytes)) {}
    bool ReadBlock(std::uint64_t block, std::uint32_t size, std::vector<std::byte>& out) override {
        out.clear();
        if (size != 4096 || block >= bytes.size() / size) return false;
        out.assign(bytes.begin() + block * size, bytes.begin() + (block + 1) * size);
        return true;
    }
    bool WriteBlock(std::uint64_t block, std::span<const std::byte> value) override {
        if (value.size() != 4096 || block >= bytes.size() / 4096) return false;
        std::copy(value.begin(), value.end(), bytes.begin() + block * 4096);
        ++writes;
        return true;
    }
    bool Flush() override { return true; }
    std::vector<std::byte> bytes;
    std::uint64_t writes = 0;
};
void PreserveSnapshots(const RandomAccessSource& source, const AppleCheckpointView& checkpoint,
    const std::vector<std::byte>& original, const AppleSnapshotRetentionView& retained,
    const std::vector<std::uint64_t>& snapshot_metadata) {
    std::string error;
    AppleSnapshotRetentionView actual;
    Require(LoadAppleSnapshotRetention(source, checkpoint, actual, error), "published retention: " + error);
    Require(actual.identities.size() == retained.identities.size(), "snapshot count survives ordinary publication");
    const auto size = checkpoint.container.superblock.block_size;
    for (const auto block : snapshot_metadata) {
        std::vector<std::byte> current;
        Require(source.Read(block * size, size, current) &&
            std::equal(current.begin(), current.end(), original.begin() + block * size), "retained metadata preimage");
    }
    for (const auto& extent : retained.payload_extents) {
        std::vector<std::byte> current;
        Require(source.Read(extent.physical_block * size, extent.block_count * size, current) &&
            std::equal(current.begin(), current.end(), original.begin() + extent.physical_block * size),
            "retained payload preimage");
    }
    for (std::size_t i = 0; i < actual.identities.size(); ++i) {
        Require(actual.identities[i].snapshot_xid == retained.identities[i].snapshot_xid &&
            actual.identities[i].name_utf8 == retained.identities[i].name_utf8 &&
            actual.identities[i].superblock_physical_block == retained.identities[i].superblock_physical_block,
            "exact retained snapshot identity");
    }
}
void DeleteBudget(const RandomAccessSource& source, const AppleCheckpointView& checkpoint,
    const AppleSnapshotCatalogRecords& catalog) {
    std::string error;
    Require(catalog.inventory.size() == 2, "delete regression requires exactly two snapshots");
    const auto scope = ApfsSnapshotScope{0, source.SizeBytes(), checkpoint.container.superblock.uuid_hex,
        checkpoint.volumes.front().superblock.uuid_hex, 101, checkpoint.container.superblock.xid};
    std::vector<ApfsSnapshotInfo> inventory;
    Require(ApfsSnapshotStore::Enumerate(source, scope, inventory, error) && inventory.size() == 2,
        "exact delete inventory: " + error);
    const auto removed = std::find_if(inventory.begin(), inventory.end(), [](const auto& value) {
        return value.identity.snapshot_xid == 15171 && value.identity.name_utf8 ==
            "Q-raw-gate-2f9d1151c958413087efe6984324352b-101";
    });
    const auto survivor = std::find_if(inventory.begin(), inventory.end(), [](const auto& value) {
        return value.identity.snapshot_xid == 15162;
    });
    Require(checkpoint.container.superblock.xid == 15171 && removed != inventory.end() &&
        survivor != inventory.end() && catalog.live.filesystem.size() == 20775,
        "exact CP15171 / Alpha20775 / removed15171 / survivor15162 regression");
    AppleSnapshotDeleteRequest request;
    request.expected = removed->identity;
    request.modification_time_ns = 1;
    request.required_checkpoint_xids = {checkpoint.container.superblock.xid};
    auto allowance = std::make_shared<ApfsReadBudget>(65536, 256ull << 20, 1000000, 256ull << 20);
    BudgetedRandomAccessSource bounded(source, allowance);
    AppleSnapshotDeletePlan plan;
    const bool planned = PlanAppleSnapshotDelete(bounded, checkpoint, request, plan, error);
    Consumption("delete", planned, error, *allowance);
    Require(planned && !allowance->Failed() && plan.removed == request.expected &&
        plan.surviving.size() == 1 && plan.surviving.front().snapshot_xid == 15162,
        "exact newest deletion under all four unchanged allowances: " + error);
    for (const bool byte_limit : {false, true}) {
        auto low = std::make_shared<ApfsReadBudget>(65536, 256ull << 20,
            byte_limit ? 1000000 : 64, byte_limit ? 8192 : 256ull << 20);
        BudgetedRandomAccessSource limited(source, low);
        AppleSnapshotDeletePlan rejected = plan;
        Require(!PlanAppleSnapshotDelete(limited, checkpoint, request, rejected, error) && low->Failed() &&
            rejected.surviving.empty() && rejected.allocation.allocated_main_blocks.empty() &&
            rejected.commit.publication.before_superblock_writes.empty() &&
            rejected.commit.publication.superblock_write.bytes.empty(), "delete exhaustion clears every executable output");
        const auto before = low->Consumed();
        const auto refused = low->ReservationFailure();
        const std::string reason = low->Failure();
        Require(!PlanAppleSnapshotDelete(limited, checkpoint, request, rejected, error) &&
            error == reason && low->Consumed().reads == before.reads &&
            low->Consumed().read_bytes == before.read_bytes && low->Consumed().records == before.records &&
            low->Consumed().record_bytes == before.record_bytes && low->ReservationFailure().count == refused.count &&
            low->ReservationFailure().bytes == refused.bytes, "delete retry preserves sticky failure without further work");
    }
    auto wrong = request;
    wrong.expected.name_utf8 += "-wrong";
    AppleSnapshotDeletePlan rejected;
    Require(!PlanAppleSnapshotDelete(source, checkpoint, wrong, rejected, error) &&
        rejected.allocation.allocated_main_blocks.empty() && rejected.commit.publication.before_superblock_writes.empty(),
        "wrong exact snapshot identity refuses atomically");
    std::vector<std::byte> original;
    Require(source.Read(0, source.SizeBytes(), original), "read original memory preimage");
    const auto peer = std::find_if(checkpoint.volumes.begin(), checkpoint.volumes.end(),
        [](const auto& value) { return value.superblock.object_id == 102; });
    Require(peer != checkpoint.volumes.end(), "exact Beta peer exists");
    for (const auto block : {survivor->identity.root_physical_block, peer->superblock_object.physical_block}) {
        const auto guard = std::find_if(plan.commit.publication.guard_blocks.begin(),
            plan.commit.publication.guard_blocks.end(), [&](const auto& value) { return value.physical_block == block; });
        Require(guard != plan.commit.publication.guard_blocks.end(), "survivor and peer actual preimages are guarded");
        MemoryTarget changed(original);
        changed.bytes[block * 4096 + 128] ^= std::byte{1};
        Require(!ExecuteAppleCheckpointPublication(changed, plan.commit.publication, error) &&
            error == "AppleCheckpointGuardChanged" && changed.writes == 0,
            "changed survivor or peer preimage refuses before the first memory write");
    }
    AppleSnapshotRetirementProof proof;
    auto proof_budget = std::make_shared<ApfsReadBudget>(65536, 256ull << 20, 1000000, 256ull << 20);
    BudgetedRandomAccessSource proof_source(source, proof_budget);
    SnapshotPlanningSource proof_observation(proof_source);
    const bool proved = ProveAppleSnapshotRetirement(proof_observation, checkpoint, plan.commit.publication,
        101, request.required_checkpoint_xids, proof, error);
    Consumption("independent-retirement", proved, error, *proof_budget);
    Require(proved && proof_observation.VerifyUnchanged(error) &&
        proof.retired_volume_payload_blocks == plan.released_payload_blocks,
        "fresh independent graph proves all peer and preimage ownership: " + error);
    MemoryTarget target(original);
    Require(ExecuteAppleCheckpointPublication(target, plan.commit.publication, error), "delete memory publication: " + error);
    VectorRandomAccessSource reopened(target.bytes);
    const auto after = LoadAppleCheckpointView(reopened, 0, reopened.SizeBytes(), error);
    Require(after && after->container.superblock.xid == 15172, "fresh canonical CP15172 reopen: " + error);
    auto after_scope = scope;
    after_scope.checkpoint_xid = after->container.superblock.xid;
    inventory.clear();
    Require(ApfsSnapshotStore::Enumerate(reopened, after_scope, inventory, error) && inventory.size() == 1 &&
        inventory.front().identity == plan.surviving.front(), "fresh inventory preserves exact original snapshot only");
    AppleSnapshotCatalogRecords fresh;
    Require(LoadAppleSnapshotCatalog(reopened, *after, 101, fresh, error), "fresh survivor catalog: " + error);
    const auto same = [](const auto& a, const auto& b) {
        return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(),
            [](const auto& x, const auto& y) { return x.key == y.key && x.value == y.value; });
    };
    const auto old_index = std::find_if(catalog.inventory.begin(), catalog.inventory.end(),
        [](const auto& value) { return value.xid == 15162; }) - catalog.inventory.begin();
    Require(same(catalog.live.filesystem, fresh.live.filesystem) && fresh.snapshots.size() == 1 &&
        same(catalog.snapshots[old_index].filesystem, fresh.snapshots.front().filesystem),
        "fresh live namespace and original snapshot records remain byte exact");
    std::shared_ptr<const NativeApfsSnapshotProjection> projection;
    Require(NativeApfsReader::TryLoadSnapshotProjection(reopened, inventory.front().identity, projection, error),
        "fresh original snapshot data projection: " + error);
    std::uint64_t payload_bytes = 0, payload_extents = 0;
    for (const auto& [inode, extents] : projection->View().read_extents_by_inode) {
        for (const auto& extent : extents) {
            if (!extent.physical_address) continue;
            Require(extent.physical_address <= original.size() && extent.bytes <= original.size() - extent.physical_address,
                "original snapshot payload within image");
            std::vector<std::byte> actual;
            Require(reopened.Read(extent.physical_address, extent.bytes, actual) &&
                std::equal(actual.begin(), actual.end(), original.begin() + extent.physical_address),
                "fresh reader original snapshot data equals every original byte");
            payload_bytes += extent.bytes;
            ++payload_extents;
        }
    }
    Require(payload_extents != 0 && payload_bytes != 0, "actual nonempty original snapshot data checked");
    for (const auto block : catalog.metadata_blocks) {
        Require(std::equal(original.begin() + block * 4096, original.begin() + (block + 1) * 4096,
            target.bytes.begin() + block * 4096), "all preimage catalog metadata stays byte exact");
    }
    AppleSnapshotCatalogRecords before_peer, after_peer;
    Require(LoadAppleSnapshotCatalog(source, checkpoint, 102, before_peer, error) &&
        LoadAppleSnapshotCatalog(reopened, *after, 102, after_peer, error) &&
        before_peer.inventory.empty() && after_peer.inventory.empty() &&
        same(before_peer.live.filesystem, after_peer.live.filesystem), "Beta remains snapshot-free with exact namespace");
    for (const auto block : before_peer.metadata_blocks) {
        Require(std::equal(original.begin() + block * 4096, original.begin() + (block + 1) * 4096,
            target.bytes.begin() + block * 4096), "all Beta canonical metadata remains byte exact");
    }
    const auto after_peer_view = std::find_if(after->volumes.begin(), after->volumes.end(),
        [](const auto& value) { return value.superblock.object_id == 102; });
    Require(after_peer_view != after->volumes.end() && after_peer_view->superblock_object.physical_block ==
        peer->superblock_object.physical_block, "Beta physical descriptor is unchanged");
    const auto after_alpha = std::find_if(after->volumes.begin(), after->volumes.end(),
        [](const auto& value) { return value.superblock.object_id == 101; });
    Require(after_alpha != after->volumes.end(), "fresh Alpha descriptor exists");
    const auto before_alpha = std::find_if(checkpoint.volumes.begin(), checkpoint.volumes.end(),
        [](const auto& value) { return value.superblock.object_id == 101; });
    Require(before_alpha != checkpoint.volumes.end(), "original Alpha descriptor exists");
    std::vector<std::byte> before_apsb, after_apsb;
    Require(source.Read(before_alpha->superblock_object.physical_block * 4096, 4096, before_apsb) &&
        reopened.Read(after_alpha->superblock_object.physical_block * 4096, 4096, after_apsb), "read actual Alpha counters");
    Require(ReadU64LE(after_apsb, 0x58).value() + proof.retired_volume_blocks ==
            ReadU64LE(before_apsb, 0x58).value() + proof.allocated_volume_blocks &&
        ReadU64LE(after_apsb, 0xE0).value() == ReadU64LE(before_apsb, 0xE0).value() + proof.allocated_volume_blocks &&
        ReadU64LE(after_apsb, 0xE8).value() == ReadU64LE(before_apsb, 0xE8).value() + proof.retired_volume_blocks,
        "serialized Alpha accounting equals fresh independent retirement proof");
    auto stale_budget = std::make_shared<ApfsReadBudget>(65536, 256ull << 20, 1000000, 256ull << 20);
    BudgetedRandomAccessSource stale(reopened, stale_budget);
    Require(!PlanAppleSnapshotDelete(stale, *after, request, rejected, error) && rejected.surviving.empty() &&
        rejected.commit.publication.before_superblock_writes.empty(), "fresh reopen refuses stale delete identity");
    std::vector<AppleRecoveryCheckpointView> history;
    auto history_budget = std::make_shared<ApfsReadBudget>(65536, 256ull << 20, 1000000, 256ull << 20);
    BudgetedRandomAccessSource history_source(reopened, history_budget);
    Require(LoadAppleSnapshotRecoveryCheckpoints(history_source, *after, {15171}, history, error) && history.size() == 1,
        "fresh reopened predecessor retention and continuity: " + error);
    Require(std::binary_search(history.front().metadata_blocks.begin(), history.front().metadata_blocks.end(),
        peer->superblock_object.physical_block), "reopened predecessor closure retains Beta metadata owner");
    std::cout << "PASS exact identity and stale identity refusals; sticky record/byte retries; survivor/peer preimage guards; "
        << "independent accounting; fresh predecessor continuity\n";
    std::cout << "PASS exact newest Delete, memory publication, fresh reopen, original snapshot payload extents="
        << payload_extents << " bytes=" << payload_bytes << "; physicalOperations=0\n";
}
}
int main(int argc, char** argv) {
    try {
        const bool recovery = argc == 3 && std::string_view(argv[1]) == "--recovery-budget";
        const bool deletion = argc == 3 && std::string_view(argv[1]) == "--delete-budget";
        Require(argc == 2 || recovery || deletion, "one high-record private image required");
        const char* argument = argv[recovery || deletion ? 2 : 1];
        std::string input(argument);
        std::transform(input.begin(), input.end(), input.begin(), [](unsigned char c) {
            return c == '/' ? '\\' : static_cast<char>(std::tolower(c));
        });
        Require(!input.starts_with("\\\\.\\") && !input.starts_with("\\\\?\\physicaldrive") &&
            !input.starts_with("\\\\?\\globalroot\\") && !input.starts_with("\\??\\"), "raw device input refused");
        const auto path = std::filesystem::absolute(argument).lexically_normal();
        std::error_code file_error;
        const auto status = std::filesystem::symlink_status(path, file_error);
        Require(!file_error && std::filesystem::is_regular_file(status) && !std::filesystem::is_symlink(status),
            "regular non-symlink image required");
        const auto size = std::filesystem::file_size(path, file_error);
        Require(!file_error && size == 134217728, "exact 128 MiB image required");
        FileRandomAccessSource source(path.string());
        Require(source.IsOpen() && source.SizeBytes() == 134217728, "sealed 128 MiB source opens read-only");
        std::string error;
        auto checkpoint = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
        Require(checkpoint.has_value(), "source checkpoint: " + error);
        AppleSnapshotCatalogRecords catalog;
        Require(LoadAppleSnapshotCatalog(source, *checkpoint, 101, catalog, error), "source catalog: " + error);
        Require(!catalog.inventory.empty() && catalog.live.filesystem.size() >= 20000,
            "regression requires existing snapshot and at least 20000 live records");
        std::cout << "live_records=" << catalog.live.filesystem.size() << " snapshots=" << catalog.inventory.size()
            << " source_xid=" << checkpoint->container.superblock.xid << '\n';
        if (deletion) {
            DeleteBudget(source, *checkpoint, catalog);
            return 0;
        }
        if (recovery) {
            Require(catalog.inventory.size() >= 2 && checkpoint->container.superblock.xid > 1,
                "recovery regression requires two snapshots and a preceding checkpoint");
            auto allowance = std::make_shared<ApfsReadBudget>(65536, 256ull << 20, 1000000, 256ull << 20);
            BudgetedRandomAccessSource bounded(source, allowance);
            std::vector<AppleRecoveryCheckpointView> history;
            const auto prior = checkpoint->container.superblock.xid - 1;
            const bool loaded = LoadAppleSnapshotRecoveryCheckpoints(bounded, *checkpoint, {prior}, history, error);
            Consumption("recovery", loaded, error, *allowance);
            Require(loaded && history.size() == 1 && history.front().checkpoint.container.superblock.xid == prior &&
                !history.front().metadata_blocks.empty(), "exact high-record predecessor ownership: " + error);
            auto limited = std::make_shared<ApfsReadBudget>(65536, 256ull << 20, 1000, 256ull << 20);
            BudgetedRandomAccessSource low(source, limited);
            Require(!LoadAppleSnapshotRecoveryCheckpoints(low, *checkpoint, {prior}, history, error) &&
                limited->Failed() && history.empty(), "exhausted recovery clears its output");
            const auto consumed = limited->Consumed();
            Require(!LoadAppleSnapshotRecoveryCheckpoints(low, *checkpoint, {prior}, history, error) &&
                history.empty() && limited->Consumed().records == consumed.records &&
                limited->Consumed().reads == consumed.reads, "recovery retry retains the sticky allowance");
            std::cout << "PASS high-record recovery ownership and sticky allowance; physicalOperations=0\n";
            return 0;
        }
        std::vector<std::uint64_t> snapshot_metadata;
        for (std::size_t i = 0; i < catalog.inventory.size(); ++i) {
            const auto& view = catalog.inventory[i].volume;
            snapshot_metadata.insert(snapshot_metadata.end(), {view.superblock_object.physical_block,
                view.object_map.object.physical_block, view.object_map.tree.physical_block});
            const auto& trees = catalog.snapshots[i];
            snapshot_metadata.insert(snapshot_metadata.end(), trees.filesystem_blocks.begin(), trees.filesystem_blocks.end());
            snapshot_metadata.insert(snapshot_metadata.end(), trees.extentref_blocks.begin(), trees.extentref_blocks.end());
        }
        std::sort(snapshot_metadata.begin(), snapshot_metadata.end());
        snapshot_metadata.erase(std::unique(snapshot_metadata.begin(), snapshot_metadata.end()), snapshot_metadata.end());
        const auto volume = std::find_if(checkpoint->volumes.begin(), checkpoint->volumes.end(),
            [](const auto& v) { return v.superblock.object_id == 101; });
        Require(volume != checkpoint->volumes.end(), "selected volume exists");
        const auto oid = volume->superblock.next_object_id;
        const auto policy = ApfsNamePolicy::FromIncompatibleFeatures(volume->superblock.incompatible_features);
        AppleVolumeTransactionRequest request;
        request.volume_object_id = 101;
        request.required_checkpoint_xids = {checkpoint->container.superblock.xid};
        request.filesystem_records = catalog.live.filesystem;
        request.file_count_delta = 1;
        bool root_found = false;
        for (auto& record : request.filesystem_records) {
            if (ReadU64LE(record.key, 0).value_or(0) != ((3ull << 60) | 2)) continue;
            AppleInodeRecord root;
            Require(ApfsExtendedRecordCodec::DecodeInode(record, root, error), "root decode: " + error);
            ++root.children_or_links;
            Require(EncodeAppleInodeRecord(root, record, error), "root encode: " + error);
            root_found = true;
        }
        Require(root_found, "root inode present");
        AppleInodeRecord inode;
        inode.object_id = inode.private_id = oid;
        inode.parent_id = 2;
        inode.mode = 0100644;
        inode.children_or_links = 1;
        inode.create_time = inode.modification_time = inode.change_time = inode.access_time = 1;
        apfsaccess::catalog::BtreeRecord record;
        Require(EncodeAppleInodeRecord(inode, record, error), "new inode: " + error);
        request.filesystem_records.push_back(record);
        AppleDirectoryRecord directory;
        directory.parent_id = 2;
        directory.file_id = oid;
        directory.flags = 8;
        directory.name_utf8 = "snapshot-live-budget-created.bin";
        Require(EncodeAppleDirectoryRecord(directory, policy, record, error), "new directory entry: " + error);
        request.filesystem_records.push_back(record);
        auto budget = std::make_shared<ApfsReadBudget>(65536, 256ull << 20, 1000000, 256ull << 20);
        BudgetedRandomAccessSource bounded(source, budget);
        AppleVolumeTransactionPlan plan;
        const bool planned = PlanAppleSnapshotLiveTransaction(bounded, *checkpoint, request, plan, error);
        Consumption("create", planned, error, *budget);
        Require(planned, "high-record ordinary Create under unchanged production allowance: " + error);

        AppleSnapshotCatalogRecords peer_catalog;
        Require(LoadAppleSnapshotCatalog(source, *checkpoint, 102, peer_catalog, error), "snapshot-free peer catalog");
        const auto peer = std::find_if(checkpoint->volumes.begin(), checkpoint->volumes.end(),
            [](const auto& v) { return v.superblock.object_id == 102; });
        Require(peer != checkpoint->volumes.end() && peer_catalog.inventory.empty(), "snapshot-free sibling exists");
        AppleVolumeTransactionRequest sibling;
        sibling.volume_object_id = 102;
        sibling.required_checkpoint_xids = {checkpoint->container.superblock.xid};
        sibling.file_count_delta = 1;
        sibling.filesystem_records = peer_catalog.live.filesystem;
        for (auto& entry : sibling.filesystem_records) {
            if (ReadU64LE(entry.key, 0).value_or(0) != ((3ull << 60) | 2)) continue;
            AppleInodeRecord root;
            Require(ApfsExtendedRecordCodec::DecodeInode(entry, root, error), "peer root decode");
            ++root.children_or_links;
            Require(EncodeAppleInodeRecord(root, entry, error), "peer root encode");
        }
        auto peer_inode = inode;
        peer_inode.object_id = peer_inode.private_id = peer->superblock.next_object_id;
        Require(EncodeAppleInodeRecord(peer_inode, record, error), "peer create inode");
        sibling.filesystem_records.push_back(record);
        auto peer_directory = directory;
        peer_directory.file_id = peer_inode.object_id;
        const auto peer_policy = ApfsNamePolicy::FromIncompatibleFeatures(peer->superblock.incompatible_features);
        Require(EncodeAppleDirectoryRecord(peer_directory, peer_policy, record, error), "peer create directory entry");
        sibling.filesystem_records.push_back(record);
        auto peer_budget = std::make_shared<ApfsReadBudget>(65536, 256ull << 20, 1000000, 256ull << 20);
        BudgetedRandomAccessSource peer_source(source, peer_budget);
        AppleVolumeTransactionPlan peer_plan;
        const bool peer_planned = PlanAppleSnapshotSiblingTransaction(peer_source, *checkpoint, sibling, peer_plan, error);
        Consumption("sibling-create", peer_planned, error, *peer_budget);
        Require(peer_planned, "ordinary snapshot-free sibling Create preserves high-record snapshot cohort: " + error);

        auto tiny = std::make_shared<ApfsReadBudget>(65536, 256ull << 20, 64, 4096);
        BudgetedRandomAccessSource limited(source, tiny);
        AppleVolumeTransactionPlan denied;
        const bool refused = PlanAppleSnapshotLiveTransaction(limited, *checkpoint, request, denied, error);
        Consumption("sticky", refused, error, *tiny);
        Require(!refused && tiny->Failed() && denied.commit.publication.before_superblock_writes.empty(),
            "small shared budget refuses atomically");
        const auto failed = tiny->Consumed();
        Require(!PlanAppleSnapshotLiveTransaction(limited, *checkpoint, request, denied, error) &&
            tiny->Failed() && tiny->Consumed().records == failed.records && tiny->Consumed().reads == failed.reads,
            "retry cannot replenish or clear sticky allowance");

        std::vector<std::byte> original;
        Require(source.Read(0, source.SizeBytes(), original), "source preimage");
        AppleSnapshotRetentionView retained;
        Require(LoadAppleSnapshotRetention(source, *checkpoint, retained, error), "retained preimage: " + error);
        MemoryTarget target(original);
        Require(ExecuteAppleCheckpointPublication(target, plan.commit.publication, error), "memory publication: " + error);
        VectorRandomAccessSource created(target.bytes);
        checkpoint = LoadAppleCheckpointView(created, 0, created.SizeBytes(), error);
        Require(checkpoint.has_value(), "fresh create checkpoint: " + error);
        PreserveSnapshots(created, *checkpoint, original, retained, snapshot_metadata);
        Require(LoadAppleSnapshotCatalog(created, *checkpoint, 101, catalog, error), "fresh create catalog: " + error);
        request.filesystem_records = catalog.live.filesystem;
        request.required_checkpoint_xids = {checkpoint->container.superblock.xid};
        request.file_count_delta = 0;
        request.data_writes = {{oid, 0, 0, std::vector<std::byte>(4096, std::byte{0x5a})}};
        for (auto& entry : request.filesystem_records) {
            if (ReadU64LE(entry.key, 0).value_or(0) != ((3ull << 60) | oid)) continue;
            Require(ApfsExtendedRecordCodec::DecodeInode(entry, inode, error), "created inode decode");
            inode.uncompressed_size = 4096;
            AppleExtendedField stream{8, 0, std::vector<std::byte>(40)};
            for (unsigned n = 0; n < 8; ++n) stream.data[n] = stream.data[n + 8] = std::byte(4096ull >> (8 * n));
            inode.extended_fields.push_back(stream);
            Require(EncodeAppleInodeRecord(inode, entry, error), "created inode write metadata");
        }
        Require(EncodeAppleDataStreamIdRecord({oid, 1}, record, error), "created data stream identity");
        request.filesystem_records.push_back(record);
        auto write_budget = std::make_shared<ApfsReadBudget>(65536, 256ull << 20, 1000000, 256ull << 20);
        BudgetedRandomAccessSource write_source(created, write_budget);
        const bool written = PlanAppleSnapshotLiveTransaction(write_source, *checkpoint, request, plan, error);
        Consumption("write", written, error, *write_budget);
        Require(written, "high-record ordinary write: " + error);
        Require(ExecuteAppleCheckpointPublication(target, plan.commit.publication, error), "memory write publication: " + error);
        VectorRandomAccessSource committed(target.bytes);
        checkpoint = LoadAppleCheckpointView(committed, 0, committed.SizeBytes(), error);
        Require(checkpoint.has_value(), "fresh write checkpoint");
        PreserveSnapshots(committed, *checkpoint, original, retained, snapshot_metadata);
        Require(LoadAppleSnapshotCatalog(committed, *checkpoint, 101, catalog, error), "fresh write catalog");
        bool payload_found = false;
        for (const auto& entry : catalog.live.filesystem) {
            if (ReadU64LE(entry.key, 0).value_or(0) != ((8ull << 60) | oid)) continue;
            AppleFileExtentRecord extent;
            Require(DecodeAppleFileExtentRecord(entry, 4096, extent, error), "fresh written extent");
            std::vector<std::byte> bytes;
            Require(committed.Read(extent.physical_block * 4096, 4096, bytes) && bytes == request.data_writes[0].bytes,
                "fresh committed payload equals written bytes");
            payload_found = true;
        }
        Require(payload_found, "written file has durable extent");
        std::cout << "PASS high-record snapshot live Create/write, retained preimages, and sticky budget; physicalOperations=0\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "FAIL " << e.what() << '\n';
        return 1;
    }
}
