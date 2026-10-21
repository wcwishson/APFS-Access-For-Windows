#pragma once
#include "VolumeManagement.h"
#include "TestFixtureBuilder.h"
#include "TransactionManager.h"
#include "BlockDevice.h"
#include "AppleVolumeTransaction.h"
#include "ApfsExtendedRecordCodec.h"
#include "InodeMetadataPatch.h"
#include <bcrypt.h>
#include <fstream>
#include <stdexcept>
#undef CreateFile

namespace apfsaccess::volume_management_test
{
using namespace catalog;
using namespace rw;
using namespace testfixture;
using Bytes = std::vector<std::byte>;
inline Bytes Fixture(bool payload = true, std::uint64_t free_blocks = 0, std::uint64_t block_count = 512)
{
    BuilderStore spec; spec.authoritative_checkpoint = true; spec.block_count = block_count;
    spec.authoritative_checkpoint_ring_blocks = 32; spec.authoritative_internal_pool_blocks = 32;
    spec.authoritative_main_free_blocks = free_blocks;
    spec.uuid_hex = "11001100110044008800110011001100";
    spec.volumes.resize(2);
    for (unsigned i = 0; i < 2; ++i) {
        auto& v = spec.volumes[i]; v.oid = 101 + i; v.incompat = 0;
        AppleInodeRecord root; root.object_id = root.private_id = root.parent_id = 2; root.mode = 0040755;
        root.children_or_links = payload ? 1 : 0;
        catalog::BtreeRecord rec; std::string e;
        if (!EncodeAppleInodeRecord(root, rec, e)) throw std::runtime_error(e); v.filesystem_records.push_back(rec);
        if (!payload) continue;
        const auto block = 200 + i * 8;
        AppleInodeRecord file; file.object_id = file.private_id = 30; file.parent_id = 2; file.mode = 0100644;
        file.children_or_links = 1; file.uncompressed_size = 4096;
        AppleExtendedField stream{8, 0, Bytes(40)}; PutU64LE(stream.data, 0, 4096); PutU64LE(stream.data, 8, 4096);
        file.extended_fields.push_back(stream);
        if (!EncodeAppleInodeRecord(file, rec, e)) throw std::runtime_error(e); v.filesystem_records.push_back(rec);
        AppleDirectoryRecord entry; entry.parent_id = 2; entry.file_id = 30; entry.name_utf8 = "payload.bin"; entry.flags = 8;
        if (!EncodeAppleDirectoryRecord(entry, rec, e)) throw std::runtime_error(e); v.filesystem_records.push_back(rec);
        if (!EncodeAppleFileExtentRecord({30, 0, 4096, block, 0, 4096}, rec, e)) throw std::runtime_error(e); v.filesystem_records.push_back(rec);
        if (!EncodeAppleDataStreamIdRecord({30, 1}, rec, e)) throw std::runtime_error(e); v.filesystem_records.push_back(rec);
        if (!EncodeApplePhysicalExtentRecord({block, 1, 1, 30, 1}, rec, e)) throw std::runtime_error(e); v.extentref_records.push_back(rec);
        v.additional_file_system_allocated_blocks = 1;
        spec.authoritative_seeded_main_blocks.emplace_back(block, Bytes(4096, std::byte(0x41 + i)));
        if (!SortAppleBtreeRecords(v.filesystem_records, AppleBtreeKeyOrder::FileSystemCaseSensitive, e)) throw std::runtime_error(e);
    }
    auto bytes = BuildStoreImage(spec);
    for (std::size_t at = 0; at < bytes.size(); at += 4096) {
        Bytes nx(bytes.begin() + at, bytes.begin() + at + 4096);
        if (!ParseNxSuperblock(nx)) continue;
        PutU32LE(nx, 0xb4, 100); FletcherForBlock(nx, 4096);
        std::copy(nx.begin(), nx.end(), bytes.begin() + at);
    }
    {
        Bytes omap(bytes.begin() + kOmapOid * 4096, bytes.begin() + (kOmapOid + 1) * 4096);
        PutU32LE(omap, 0x20, 1); FletcherForBlock(omap, 4096);
        std::copy(omap.begin(), omap.end(), bytes.begin() + kOmapOid * 4096);
    }
    for (unsigned i = 0; i < 2; ++i) {
        const auto at = (kFirstVolumeBlock + i) * 4096;
        Bytes sb(bytes.begin() + at, bytes.begin() + at + 4096);
        PutU64LE(sb, 0xb8, payload ? 1 : 0); PutU64LE(sb, 0xc0, 1);
        PutU32LE(sb, 0x24, i); FletcherForBlock(sb, 4096);
        std::copy(sb.begin(), sb.end(), bytes.begin() + at);
    }
    return bytes;
}
inline void Save(const std::filesystem::path& p, const Bytes& b)
{
    std::ofstream f(p, std::ios::binary | std::ios::trunc); f.write(reinterpret_cast<const char*>(b.data()), b.size());
    if (!f) throw std::runtime_error("fixture save failed");
}
inline Bytes Read(const std::filesystem::path& p)
{
    std::ifstream f(p, std::ios::binary); std::vector<char> chars((std::istreambuf_iterator<char>(f)), {});
    Bytes b(chars.size()); std::memcpy(b.data(), chars.data(), chars.size()); return b;
}
inline AppleCheckpointView Checkpoint(const Bytes& b)
{
    VectorRandomAccessSource source(b); std::string e; auto cp = LoadAppleCheckpointView(source, 0, source.SizeBytes(), e);
    if (!cp) throw std::runtime_error(e); return *cp;
}
inline VolumeManagementRequest Request(const std::filesystem::path& dir, bool create, const Bytes& bytes)
{
    const auto cp = Checkpoint(bytes);
    VolumeManagementRequest r; r.operation = create ? VolumeManagementOperation::Create : VolumeManagementOperation::Delete;
    r.image = dir / "image.apfs"; r.journal_directory = dir; r.container_uuid = cp.container.superblock.uuid_hex;
    r.checkpoint_xid = cp.container.superblock.xid;
    r.volume_oid = create ? cp.container.superblock.next_oid : cp.volumes.front().superblock.object_id;
    r.volume_uuid = create ? "123456781234423482341234567890ab" : cp.volumes.front().superblock.uuid_hex;
    if (create) { r.name_utf8 = "Created Data"; r.quota_blocks = 64; r.reserve_blocks = 16; }
    for (const auto& v : cp.volumes) r.sibling_wals[v.superblock.object_id] = dir / (std::to_string(v.superblock.object_id) + ".wal");
    return r;
}
inline void RefreshManagementRequest(VolumeManagementRequest& r)
{
    const auto observed = ObserveVolumeManagement({r.image, r.offset_bytes});
    if (!observed.complete || observed.container_uuid != r.container_uuid)
        throw std::runtime_error("original fixture checkpoint observation failed: " + observed.error);
    r.checkpoint_xid = observed.checkpoint_xid;
    if (r.operation == VolumeManagementOperation::Create) r.volume_oid = observed.next_oid;
}
// Follow the native history fixture's real inode publication before recording CLEAN.
inline void ProvisionOriginalWal(VolumeManagementRequest& r, std::uint64_t id, bool production = false)
{
    const auto& path = r.sibling_wals.at(id);
    if (std::filesystem::exists(path)) throw std::runtime_error("original fixture WAL already exists");
    if (r.offset_bytes != 0) throw std::runtime_error("original fixture publication requires partitionless image");
    const auto identity = production ? DerivePartitionlessVolumeRecoveryIdentity(r.container_uuid, id) :
        "apfs-vol:" + r.container_uuid + ":" + std::to_string(id);
    {
        std::string error;
        auto device = BlockDevice::OpenExclusiveManagementImage(r.image.wstring(), 0, error);
        if (!device) throw std::runtime_error("original fixture image open failed: " + error);
        Bytes bytes;
        if (!device->Read(0, static_cast<std::size_t>(device->GetGeometry().total_bytes), bytes))
            throw std::runtime_error("original fixture image read failed");
        const auto cp = Checkpoint(bytes);
        const auto volume = std::find_if(cp.volumes.begin(), cp.volumes.end(),
            [&](const auto& v) { return v.superblock.object_id == id; });
        if (cp.container.superblock.uuid_hex != r.container_uuid || volume == cp.volumes.end())
            throw std::runtime_error("original fixture native volume identity mismatch");
        VectorRandomAccessSource source(bytes);
        std::vector<BtreeRecord> records;
        if (!ReadBtreeLeafRecords(source, 4096, volume->root_tree.physical_block,
            (volume->root_tree.type & kObjectStorageTypeMask) == kObjectPhysical,
            volume->superblock.omap_oid, cp.container.superblock.xid, records, error))
            throw std::runtime_error("original fixture root records failed: " + error);
        bool updated = false;
        const auto stamp = 1700000000000000000ull + cp.container.superblock.xid * 100;
        for (auto& record : records) {
            AppleInodeRecord inode;
            if (ApfsExtendedRecordCodec::DecodeInode(record, inode, error) && inode.object_id == 2) {
                inode.modification_time = stamp;
                if (!EncodeAppleInodeRecord(inode, record, error)) throw std::runtime_error(error);
                updated = true;
            }
        }
        if (!updated) throw std::runtime_error("original fixture root inode missing");
        AppleVolumeTransactionRequest request; request.volume_object_id = id;
        request.filesystem_records = std::move(records);
        AppleVolumeTransactionPlan plan;
        if (!PlanAppleVolumeTransaction(source, cp, request, plan, error))
            throw std::runtime_error("original fixture timestamp planning failed: " + error);
        TransactionManager writer(L"Strict"); writer.SetJournalPath(path.wstring());
        writer.SetVolumeIdentity(std::wstring(identity.begin(), identity.end()));
        TransactionManager::MutationIntent intent; intent.kind = TransactionManager::MutationKind::SetInodeMetadata;
        intent.path = L"\\"; intent.object_id = 2; intent.generation = plan.commit.publication.transaction_xid;
        InodeMetadataPatch patch; patch.mask = InodeMetadataPatch::ModificationTime;
        patch.modification_time_utc = InodeMetadataPatch::UnixEpochTicks + stamp / 100;
        if (!EncodeInodeMetadataPatch(patch, intent.inline_payload)) throw std::runtime_error("original fixture inode patch failed");
        intent.length = intent.payload_length = intent.inline_payload.size();
        BCRYPT_ALG_HANDLE algorithm{};
        if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
            throw std::runtime_error("original fixture hash algorithm failed");
        const auto hash_status = BCryptHash(algorithm, nullptr, 0, reinterpret_cast<PUCHAR>(intent.inline_payload.data()),
            static_cast<ULONG>(intent.inline_payload.size()), intent.payload_checksum.data(), static_cast<ULONG>(intent.payload_checksum.size()));
        BCryptCloseAlgorithmProvider(algorithm, 0);
        if (hash_status < 0) throw std::runtime_error("original fixture patch hash failed");
        if (!writer.Begin() || !writer.RecordMutation(intent) || !writer.Accept(cp.container.superblock.xid))
            throw std::runtime_error("original fixture native acceptance failed");
        const auto accepted = writer.Watermarks().accepted_sequence;
        if (!accepted) throw std::runtime_error("original fixture accepted boundary missing");
        if (!ExecuteAppleCheckpointPublication(*device, plan.commit.publication, error))
            throw std::runtime_error("original fixture timestamp publication failed: " + error);
        if (!writer.MarkApfsDurableThrough(accepted) || !writer.MarkCleanedThrough(accepted))
            throw std::runtime_error("original fixture native durable CLEAN failed");
        Bytes after;
        if (!device->Read(0, bytes.size(), after) || Checkpoint(after).container.superblock.xid != cp.container.superblock.xid + 1)
            throw std::runtime_error("original fixture published checkpoint readback failed");
    }
    const auto wal = WriteAheadLog::ReadAll(path, identity);
    if (wal.status != WriteAheadLog::ReadStatus::Ok || wal.recovered_torn_tail || wal.records.empty())
        throw std::runtime_error("original fixture WAL identity/history unproved");
    std::vector<TransactionManager::AcceptedTransaction> debt;
    TransactionManager::DurabilityWatermarks marks{}; std::string error;
    if (!TransactionManager::InspectAcceptedTransactionsReadOnly(path, identity, debt, marks, error) || !debt.empty() ||
        !marks.cleanup_sequence || marks.accepted_sequence != marks.apfs_durable_sequence || marks.apfs_durable_sequence != marks.cleanup_sequence)
        throw std::runtime_error("original fixture native CLEAN inspection failed: " + error);
    for (const auto& record : wal.records)
        if (record.state == WriteAheadLog::RecordState::Prepared && record.sequence > marks.cleanup_sequence)
            throw std::runtime_error("original fixture prepared record exceeds CLEAN boundary");
    RefreshManagementRequest(r);
}
inline void ProvisionOriginalWals(VolumeManagementRequest& r, bool production = false)
{
    for (const auto& member : r.sibling_wals) ProvisionOriginalWal(r, member.first, production);
}
}
