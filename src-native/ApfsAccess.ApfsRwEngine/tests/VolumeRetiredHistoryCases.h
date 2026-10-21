#pragma once
#include "VolumeResizeCases.h"
#include <bcrypt.h>

namespace apfsaccess::volume_image_test
{
inline std::string RetentionHash(std::span<const std::byte> bytes)
{
    BCRYPT_ALG_HANDLE algorithm{}; std::array<unsigned char, 32> digest{};
    Check(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0, "SHA256 provider");
    const auto result = BCryptHash(algorithm, nullptr, 0,
        reinterpret_cast<PUCHAR>(const_cast<std::byte*>(bytes.data())), static_cast<ULONG>(bytes.size()),
        digest.data(), static_cast<ULONG>(digest.size()));
    BCryptCloseAlgorithmProvider(algorithm, 0); Check(result >= 0, "SHA256 digest");
    const char* hex = "0123456789ABCDEF"; std::string out;
    for (const auto byte : digest) { out += hex[byte >> 4]; out += hex[byte & 15]; } return out;
}

class HistoryMemoryTarget final : public AppleCheckpointWriteTarget
{
public:
    explicit HistoryMemoryTarget(Bytes& bytes) : bytes_(bytes) {}
    bool ReadBlock(std::uint64_t block, std::uint32_t size, Bytes& out) override
    {
        if (size != 4096 || block >= bytes_.size() / size) return false;
        out.assign(bytes_.begin() + block * size, bytes_.begin() + (block + 1) * size); return true;
    }
    bool WriteBlock(std::uint64_t block, std::span<const std::byte> bytes) override
    {
        if (bytes.size() != 4096 || block >= bytes_.size() / 4096) return false;
        std::copy(bytes.begin(), bytes.end(), bytes_.begin() + block * 4096); return true;
    }
    bool Flush() override { return true; }
private:
    Bytes& bytes_;
};

inline Bytes ReclaimedHistoryFixture()
{
    auto image = Fixture(); const auto initial_xid = Checkpoint(image).container.superblock.xid;
    for (unsigned generation = 0; generation < 8; ++generation) {
        const auto cp = Checkpoint(image); const auto& volume = cp.volumes[generation % 2];
        VectorRandomAccessSource source(image); std::string e; std::vector<BtreeRecord> records;
        Check(ReadBtreeLeafRecords(source, 4096, volume.root_tree.physical_block,
            (volume.root_tree.type & kObjectStorageTypeMask) == kObjectPhysical,
            volume.superblock.omap_oid, cp.container.superblock.xid, records, e), e);
        AppleVolumeTransactionRequest request; request.volume_object_id = volume.superblock.object_id;
        for (const auto& record : records) {
            AppleFileExtentRecord extent;
            if (DecodeAppleFileExtentRecord(record, 4096, extent, e)) {
                Check(extent.object_id == 30 && extent.length_bytes == 4096, "one exact original stream extent");
                request.released_data_blocks.push_back({extent.physical_block, 1});
            } else request.filesystem_records.push_back(record);
        }
        AppleVolumeDataWrite data; data.file_private_id = 30; data.bytes.resize(4096);
        for (std::size_t i = 0; i < data.bytes.size(); ++i) data.bytes[i] = std::byte((i * 37 + 11 + generation) % 251);
        request.data_writes.push_back(std::move(data)); AppleVolumeTransactionPlan plan;
        Check(PlanAppleVolumeTransaction(source, cp, request, plan, e), "real canonical history mutation: " + e);
        HistoryMemoryTarget target(image);
        Check(ExecuteAppleCheckpointPublication(target, plan.commit.publication, e), "real canonical history publication: " + e);
        (void)Checkpoint(image);
    }
    const auto cp = Checkpoint(image); VectorRandomAccessSource source(image); std::string e;
    Check(cp.container.superblock.xid == initial_xid + 8, "eight real publication generations");
    Check(!LoadAppleCheckpointView(source, 0, image.size(), e, initial_xid), "initial metadata actually reclaimed");
    rw::volume_image::Verify(image, cp); ++checks;
    return image;
}

inline void RetiredHistoryPositive(VolumeImageOperation op, const Bytes& image, const std::string& name)
{
    auto r = Setup(name, op, image); const auto original = Read(r.image);
    const auto p = Prepare(r); Check(p.outcome == VolumeImageOutcome::Prepared, "retired-history prepare: " + p.error);
    Check(Read(r.image) == original, "retired-history preview does not mutate input");
    const auto interrupted = Apply(r, p.token, [](auto stage) { return stage != "after-image-anchor"; });
    Check(interrupted.outcome == VolumeImageOutcome::RecoveryRequired, "retired-history durable interruption: " + interrupted.error);
    const auto recovered = Recover(r); Check(recovered.outcome == VolumeImageOutcome::Committed, "retired-history fresh recovery: " + recovered.error);
    const auto post = Read(r.image); const auto cp = Checkpoint(post); rw::volume_image::Verify(post, cp); ++checks;
    Check(cp.container.superblock.xid == p.post_xid && post.size() == r.target_bytes, "exact recovered generation and geometry");
    if (!Format(op)) {
        VectorRandomAccessSource source(original); std::string e;
        for (const auto& volume : Checkpoint(original).volumes) {
            std::vector<BtreeRecord> records;
            Check(ReadBtreeLeafRecords(source, 4096, volume.root_tree.physical_block,
                (volume.root_tree.type & kObjectStorageTypeMask) == kObjectPhysical,
                volume.superblock.omap_oid, r.checkpoint_xid, records, e), e);
            for (const auto& record : records) {
                AppleFileExtentRecord extent;
                if (!DecodeAppleFileExtentRecord(record, 4096, extent, e) || !extent.physical_block) continue;
                const auto start = extent.physical_block * 4096;
                Check(start <= original.size() && extent.length_bytes <= original.size() - start &&
                    start <= post.size() && extent.length_bytes <= post.size() - start, "payload comparison bounds");
                Check(std::equal(original.begin() + start, original.begin() + start + extent.length_bytes,
                    post.begin() + start), "all original volume payload bytes preserved exactly");
                const auto before_hash = RetentionHash(std::span(original).subspan(start, extent.length_bytes));
                const auto after_hash = RetentionHash(std::span(post).subspan(start, extent.length_bytes));
                Check(before_hash == after_hash, "original payload SHA256 preserved");
                std::cout << "PAYLOAD " << name << " volume=" << volume.superblock.object_id
                    << " object=" << extent.object_id << " logical=" << extent.logical_address
                    << " length=" << extent.length_bytes << " before=" << before_hash << " after=" << after_hash << '\n';
            }
        }
    } else Check(cp.volumes.size() == 1 && cp.container.superblock.uuid_hex == r.new_container_uuid &&
        cp.volumes.front().superblock.uuid_hex == r.new_volume_uuid, "format exact new identity");
    Check(Recover(r).outcome == VolumeImageOutcome::Committed && Read(r.image) == post,
        "completed recovery is byte-identical and idempotent");
    Pass("reclaimed metadata admits guarded planning and durable recovery");
}

inline void RetiredHistoryRefusals(VolumeImageOperation op, const Bytes& image)
{
    for (unsigned variant = 0; variant < 3; ++variant) {
        auto r = Setup("retired-wal-refusal-" + std::to_string(variant), op, image); const auto original = Read(r.image);
        {
            TransactionManager writer(L"Strict"); writer.SetJournalPath(r.sibling_wals.at(202).wstring());
            const auto id = "apfs-vol:" + r.container_uuid + ":202"; writer.SetVolumeIdentity(std::wstring(id.begin(), id.end()));
            TransactionManager::MutationIntent intent; intent.kind = TransactionManager::MutationKind::CreateFile;
            intent.path = L"\\pending.txt"; intent.object_id = 500; intent.generation = r.checkpoint_xid + 1;
            Check(writer.Begin() && writer.RecordMutation(intent), "genuine unfinished WAL records");
            if (variant == 0) Check(writer.Accept(r.checkpoint_xid - 8), "real obsolete-generation accepted pin");
            else if (variant == 1) Check(writer.Commit(r.checkpoint_xid), "real direct Commit remains unclean");
            else Check(writer.FlushPreparedRecords(), "real durable unaccepted prepared records");
        }
        const auto wal = Read(r.sibling_wals.at(202)); const auto p = Prepare(r);
        Check(p.outcome == VolumeImageOutcome::Refused && (variant == 2
            ? p.error.starts_with("VolumeManagementWalSemanticsInvalid:") : p.error == "VolumeImageWalDebtOrPins"),
            "exact outstanding WAL refusal variant " + std::to_string(variant) + ": " + p.error);
        Check(Read(r.image) == original && Read(r.sibling_wals.at(202)) == wal, "refusal preserves image and original WAL");
    }
    auto r = Setup("retired-incomplete-census", op, image); r.sibling_wals.erase(202);
    Check(Prepare(r).error == "VolumeImageCompleteWalCensusRequired" && Read(r.image) == image, "partial census never authorizes empty pins");
    bool refused = false;
    try { if (Format(op)) (void)rw::volume_image::PlanFormat(image, r); else (void)rw::volume_image::PlanResize(image, r); }
    catch (const std::exception& ex) { refused = std::string(ex.what()) == "VolumeImageRetentionAuthorityRequired"; }
    Check(refused, "direct planner without held CLEAN authority must refuse");
    auto corrupt = image; const auto cp = Checkpoint(image); corrupt[cp.container_object_map.object.physical_block * 4096 + 64] ^= std::byte{1};
    r = Setup("retired-corrupt-current", op, image); Save(r.image, corrupt);
    const auto damaged = Prepare(r);
    Check(damaged.outcome == VolumeImageOutcome::Refused && damaged.error == "AppleContainerOmapChecksumInvalid" &&
        Read(r.image) == corrupt, "authoritative current OMAP checksum remains mandatory: " + damaged.error);
    Pass("retired history cannot bypass dirty WAL or unproved direct callers");
}

inline void RetiredHistory(VolumeImageOperation op, const wchar_t* saved_reference = nullptr)
{
    const auto image = ReclaimedHistoryFixture(); Save(root / "retired-reference.apfs", image);
    RetiredHistoryPositive(op, image, "retired-generated-positive"); RetiredHistoryRefusals(op, image);
    if (saved_reference) {
        const auto reference = Read(saved_reference); Check(reference.size() == 4194304, "saved reference exact byte bounds");
        Check(RetentionHash(reference) == "C984976743F6FD19840B15117AC22967A7DB460756B0CEF413D2F6AF1163DFBA",
            "saved diagnosed source exact SHA256 binding");
        Check(Checkpoint(reference).container.superblock.xid == 15, "saved original XID 15 authority");
        VectorRandomAccessSource source(reference); std::string e;
        Check(!LoadAppleCheckpointView(source, 0, reference.size(), e, 7) && e == "AppleContainerOmapChecksumInvalid",
            "saved reference exact diagnosed old OMAP failure");
        RetiredHistoryPositive(op, reference, "retired-saved-positive");
    }
}
}
