// Encrypted volumes must fail closed before Apple write admission: no
// planner may stage, allocate, or publish when the volume is not marked
// unencrypted. Actual encrypted writes do not exist yet; this gate pins the
// refusal contract (exact code, empty plans, byte-identical images) so a
// future writer cannot silently admit plaintext publication.
#include "AppleVolumeTransaction.h"
#include "SnapshotTestFixture.h"
#include "NativeApfsReader.h"
#include <algorithm>
#include <iostream>
#include <fstream>
#include <stdexcept>
using namespace apfsaccess::catalog;
using namespace apfsaccess::rw;
using namespace apfsaccess::testfixture;
namespace {
unsigned cases = 0, checks = 0;
void Check(bool value, const std::string& text) { ++checks; if (!value) throw std::runtime_error(text); }
void Pass(const std::string& text) { ++cases; std::cout << "PASS " << text << '\n'; }
struct EncryptedFixture : SnapshotFixture {
    AppleCheckpointView checkpoint;
    ApfsSnapshotIdentity backup{};
    explicit EncryptedFixture() {
        // Capture the pre-existing snapshot identity from the plain image:
        // the read path also refuses encrypted-marked volumes, so inventory
        // must be observed before the flag flip. Block layout is untouched
        // by the flip, keeping the observed identity exact.
        {
            VectorRandomAccessSource plain(image); std::string error;
            ApfsSnapshotScope scope{0, image.size(), std::string(32, 'a'), std::string(32, 'b'), 101, 20};
            std::vector<ApfsSnapshotInfo> inventory;
            if (!ApfsSnapshotStore::Enumerate(plain, scope, inventory, error) || inventory.empty())
                throw std::runtime_error("plain inventory: " + error);
            backup = inventory[0].identity;
        }
        // Clear kFsFlagUnencrypted (bit 0) in the LIVE volume superblock
        // (resolved through the checkpoint, not assumed by block number).
        // No crypto material is needed: planners must refuse before reading it.
        VectorRandomAccessSource probe(image); std::string error;
        auto live = LoadAppleCheckpointView(probe, 0, probe.SizeBytes(), error);
        Check(live.has_value() && !live->volumes.empty(), "live checkpoint: " + error);
        Edit(live->volumes[0].superblock_object.physical_block, [](auto& bytes) {
            const auto flags = ReadU64LE(bytes, 0x108).value_or(1);
            PutU64LE(bytes, 0x108, flags & ~1ULL);
        });
        Reload();
    }
    void Reload() {
        VectorRandomAccessSource source(image); std::string error;
        auto loaded = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
        Check(loaded.has_value(), "encrypted reload: " + error); checkpoint = std::move(*loaded);
    }
};
void FeatureGateUnit() {
    SnapshotFixture plain;
    VectorRandomAccessSource clean(plain.image); std::string error;
    auto unencrypted = LoadAppleCheckpointView(clean, 0, clean.SizeBytes(), error);
    Check(unencrypted.has_value(), "plain checkpoint loads: " + error);
    Check(CheckAppleVolumeWriteFeatures(unencrypted->container.superblock,
        unencrypted->volumes[0].superblock, error), "plain volume admits: " + error);
    EncryptedFixture f;
    Check(!CheckAppleVolumeWriteFeatures(f.checkpoint.container.superblock,
        f.checkpoint.volumes[0].superblock, error), "encrypted volume refuses features");
    Check(error == "NativeAppleTransactionEncryptionUnsupported", "exact refusal code: " + error);
    Pass("feature gate admits plain and refuses encrypted volumes");
}
void CreateRefused() {
    EncryptedFixture f;
    const auto before = f.image;
    AppleSnapshotCreateRequest request; request.volume_object_id = 101;
    request.name_utf8 = "nope"; request.creation_time_ns = 1700000000000000000ull;
    AppleSnapshotCreatePlan plan; std::string error;
    VectorRandomAccessSource source(f.image);
    Check(!PlanAppleSnapshotCreate(source, f.checkpoint, request, plan, error), "encrypted create refuses");
    Check(error == "NativeAppleTransactionEncryptionUnsupported", "exact create code: " + error);
    Check(f.image == before, "refused create leaves image byte-identical");
    Pass("snapshot create refuses encrypted volumes");
}
void DeleteRefused() {
    EncryptedFixture f;
    const auto before = f.image;
    VectorRandomAccessSource source(f.image); std::string error;
    AppleSnapshotDeleteRequest request; request.expected = f.backup;
    request.modification_time_ns = 1700000000000000000ull;
    AppleSnapshotDeletePlan plan;
    // Reference resolution reads the snapshot through the same encrypted
    // read gate, so it refuses before the write feature gate is reached.
    // Both orders are fail-closed; this pins the earlier refusal.
    Check(!PlanAppleSnapshotDelete(source, f.checkpoint, request, plan, error), "encrypted delete refuses");
    Check(error == "SnapshotVolumeFeaturesUnsupported", "exact delete code: " + error);
    Check(plan.allocation.allocated_main_blocks.empty(), "refused delete reserves nothing");
    Check(f.image == before, "refused delete leaves image byte-identical");
    Pass("snapshot delete refuses encrypted volumes");
}
void LiveRefused() {
    EncryptedFixture f;
    VectorRandomAccessSource source(f.image); std::string error;
    std::vector<BtreeRecord> records;
    Check(ReadAppleVolumeFileSystemRecords(source, f.checkpoint.container, f.checkpoint.volumes[0], records, error),
        "encrypted records read: " + error);
    Check(!records.empty(), "fixture carries filesystem records");
    AppleVolumeTransactionRequest request; request.volume_object_id = 101;
    request.filesystem_records = records;
    AppleVolumeTransactionPlan plan;
    Check(!PlanAppleSnapshotLiveTransaction(source, f.checkpoint, request, plan, error), "encrypted live refuses");
    Check(error == "NativeAppleTransactionEncryptionUnsupported", "exact live code: " + error);
    Pass("snapshot live transaction refuses encrypted volumes");
}
void VolumeTransactionRefused() {
    EncryptedFixture f;
    VectorRandomAccessSource source(f.image); std::string error;
    std::vector<BtreeRecord> records;
    Check(ReadAppleVolumeFileSystemRecords(source, f.checkpoint.container, f.checkpoint.volumes[0], records, error),
        "records read: " + error);
    AppleVolumeTransactionRequest request; request.volume_object_id = 101;
    request.filesystem_records = records;
    AppleVolumeTransactionPlan plan;
    Check(!PlanAppleVolumeTransaction(source, f.checkpoint, request, plan, error), "encrypted volume tx refuses");
    Check(error == "NativeAppleTransactionEncryptionUnsupported", "exact volume-tx code: " + error);
    Pass("ordinary volume transaction refuses encrypted volumes");
}
}
int main() {
    try { FeatureGateUnit(); CreateRefused(); DeleteRefused(); LiveRefused(); VolumeTransactionRefused();
        std::cout << "PASS " << cases << " cases, " << checks << " checks\n"; return 0;
    } catch(const std::exception& e){ std::cerr << "FAIL after " << cases << " cases, " << checks << " checks: " << e.what() << '\n'; return 1; }
}
