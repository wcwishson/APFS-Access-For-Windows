#include "NativeCloneRangePlan.h"
#include "ApfsExtendedRecordCodec.h"
#include "AppleCloneRangeMapping.h"
#include <algorithm>

namespace apfsaccess::rw
{
namespace
{
constexpr std::uint64_t ObjectMask = 0x0fffffffffffffffULL;
bool Fail(std::string& error, const char* text) { error = text; return false; }
std::uint64_t Header(const catalog::BtreeRecord& record)
{ return catalog::ReadU64LE(record.key, 0).value_or(0); }
void Put(std::vector<std::byte>& bytes, std::size_t at, std::uint64_t value)
{ for (unsigned n = 0; n != 8; ++n) bytes.at(at + n) = std::byte(value >> (n * 8)); }
bool Same(const std::vector<catalog::BtreeRecord>& a, const std::vector<catalog::BtreeRecord>& b)
{
    return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(),
        [](const auto& x, const auto& y) { return x.key == y.key && x.value == y.value; });
}
bool Quota(const std::vector<catalog::BtreeRecord>& records)
{
    if (records.size() > NativeSparseMaxRecords) return false;
    std::size_t bytes = 0;
    for (const auto& record : records) {
        if (record.key.size() > (1u << 20) - bytes) return false;
        bytes += record.key.size();
        if (record.value.size() > (1u << 20) - bytes) return false;
        bytes += record.value.size();
    }
    return true;
}
}
static bool PlanNativeCloneRangeTransactionImpl(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, std::uint64_t volume,
    std::uint64_t source_inode, std::uint64_t target_inode, const NativeCloneRangeRequest& operation,
    NativeCloneRangeState& before, AppleVolumeTransactionPlan& out, std::string& error, bool explicit_holes)
{
    before = {}; out = {}; error.clear();
    if (!source_inode || !target_inode || source_inode == target_inode ||
        source_inode > ObjectMask || target_inode > ObjectMask || !NativeCloneRangeRequestIsValid(operation))
        return Fail(error, "CloneRangeRequestOrSelfReferenceUnsupported");
    NativeCloneRangeState state;
    if (!ReadNativeSparseStateV2(source, checkpoint, volume, source_inode, state.source, error) ||
        !ReadNativeSparseStateV2(source, checkpoint, volume, target_inode, state.target, error)) return false;
    if (!Same(state.source.filesystem, state.target.filesystem) || !Same(state.source.references, state.target.references))
        return Fail(error, "CloneRangeCanonicalHistoryChanged");
    if (operation.source_offset > state.source.size || operation.length > state.source.size - operation.source_offset ||
        operation.target_offset > state.target.size || operation.length > state.target.size - operation.target_offset ||
        (state.source.sparse && !state.target.sparse)) return Fail(error, "CloneRangeEofOrSparseTargetMismatch");

    AppleVolumeTransactionRequest request;
    request.volume_object_id = volume;
    request.required_checkpoint_xids = {checkpoint.container.superblock.xid};
    request.filesystem_records = state.source.filesystem;
    request.last_modification_time = operation.timestamp_ns;
    const auto target_end = operation.target_offset + operation.length;
    const auto source_end = operation.source_offset + operation.length;
    std::uint64_t removed_bytes = 0, shared_bytes = 0;
    std::vector<catalog::BtreeRecord> extents;
    const auto emit = [&](AppleFileExtentRecord extent, std::uint64_t lo, std::uint64_t hi,
                          std::uint64_t logical, std::uint64_t inode) {
        if (lo >= hi) return true;
        if (extent.physical_block) extent.physical_block += (lo - extent.logical_address) / 4096;
        extent.object_id = inode; extent.logical_address = logical; extent.length_bytes = hi - lo;
        catalog::BtreeRecord record;
        if (!EncodeAppleFileExtentRecord(extent, record, error)) return false;
        extents.push_back(std::move(record));
        return extents.size() <= NativeSparseMaxRecords || Fail(error, "CloneRangeMetadataQuota");
    };
    for (const auto& extent : state.target.extents) {
        const auto end = extent.logical_address + extent.length_bytes;
        const auto lo = (std::max)(extent.logical_address, operation.target_offset), hi = (std::min)(end, target_end);
        if (lo >= hi) { if (!emit(extent, extent.logical_address, end, extent.logical_address, target_inode)) return false; continue; }
        if (!emit(extent, extent.logical_address, lo, extent.logical_address, target_inode) ||
            !emit(extent, hi, end, hi, target_inode)) return false;
        if (extent.physical_block) {
            removed_bytes += hi - lo;
            request.released_data_blocks.push_back({extent.physical_block + (lo - extent.logical_address) / 4096, (hi - lo) / 4096});
        }
    }
    for (const auto& extent : state.source.extents) {
        const auto lo = (std::max)(extent.logical_address, operation.source_offset);
        const auto hi = (std::min)(extent.logical_address + extent.length_bytes, source_end);
        if (lo >= hi) continue;
        if (!emit(extent, lo, hi, operation.target_offset + lo - operation.source_offset, target_inode)) return false;
        if (extent.physical_block) shared_bytes += hi - lo;
    }
    if (removed_bytes > state.target.allocated || shared_bytes > UINT64_MAX - (state.target.allocated - removed_bytes))
        return Fail(error, "CloneRangeProjectedAllocationInvalid");
    const auto allocated = state.target.allocated - removed_bytes + shared_bytes;
    const auto aligned_size = (state.target.size + 4095) / 4096 * 4096;
    if (allocated > aligned_size || (!state.target.sparse && allocated != aligned_size))
        return Fail(error, "CloneRangeProjectedAllocationInvalid");
    if (explicit_holes && state.target.sparse) {
        if (!CompleteNativeSparseExtentCoverage(target_inode, state.target.size, extents, {}, error)) return false;
        // A completed gap may span a clone edge. Each record must stay within
        // one mapping domain so the writer can prove its source independently.
        auto completed = std::move(extents); extents.clear();
        for (const auto& record : completed) {
            AppleFileExtentRecord extent;
            if (!DecodeAppleFileExtentRecord(record, 4096, extent, error)) return false;
            const auto end = extent.logical_address + extent.length_bytes;
            auto cursor = extent.logical_address;
            for (const auto edge : {operation.target_offset, target_end, end}) {
                const auto finish = (std::min)(edge, end);
                if (finish <= cursor) continue;
                if (!emit(extent, cursor, finish, cursor, target_inode)) return false;
                cursor = finish;
            }
        }
    }
    std::erase_if(request.filesystem_records, [&](const auto& record) {
        return Header(record) == ((8ull << 60) | target_inode);
    });
    request.filesystem_records.insert(request.filesystem_records.end(), extents.begin(), extents.end());
    if (explicit_holes && state.source.sparse) {
        std::vector<catalog::BtreeRecord> source_extents;
        for (const auto& record : request.filesystem_records)
            if (Header(record) == ((8ull << 60) | source_inode)) source_extents.push_back(record);
        if (!CompleteNativeSparseExtentCoverage(source_inode, state.source.size, source_extents, {}, error)) return false;
        std::erase_if(request.filesystem_records, [&](const auto& record) {
            return Header(record) == ((8ull << 60) | source_inode);
        });
        request.filesystem_records.insert(request.filesystem_records.end(), source_extents.begin(), source_extents.end());
    }
    unsigned sources = 0, targets = 0;
    for (auto& record : request.filesystem_records) {
        const auto header = Header(record), id = header & ObjectMask;
        if ((header >> 60) != 3 || (id != source_inode && id != target_inode)) continue;
        AppleInodeRecord inode;
        if (!ApfsExtendedRecordCodec::DecodeInode(record, inode, error)) return false;
        inode.internal_flags |= 0x400; // INODE_WAS_EVER_CLONED is not exclusivity evidence.
        if (id == source_inode) ++sources;
        else {
            ++targets; inode.change_time = inode.modification_time = operation.timestamp_ns;
            unsigned streams = 0, sparse = 0;
            for (auto& field : inode.extended_fields) {
                if (field.type == 8) { if (field.data.size() != 40) return Fail(error, "CloneRangeStreamInvalid"); Put(field.data, 8, allocated); ++streams; }
                if (field.type == kAppleInodeSparseBytesField) {
                    if (field.data.size() != 8) return Fail(error, "CloneRangeSparseAccountingInvalid");
                    Put(field.data, 0, aligned_size - allocated); ++sparse;
                }
            }
            if (streams != 1 || sparse != static_cast<unsigned>(state.target.sparse)) return Fail(error, "CloneRangeStreamInvalid");
        }
        if (!EncodeAppleInodeRecord(inode, record, error)) return false;
    }
    if (sources != 1 || targets != 1 || !Quota(request.filesystem_records)) return Fail(error, "CloneRangeMetadataQuota");
    const AppleCloneRangeMapping mapping{source_inode, target_inode, operation.source_offset, operation.target_offset, operation.length};
    if (!PlanAppleCloneRangeTransaction(source, checkpoint, request, mapping, out, error)) return false;
    before = std::move(state); return true;
}
bool PlanNativeCloneRangeTransaction(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, std::uint64_t volume,
    std::uint64_t source_inode, std::uint64_t target_inode, const NativeCloneRangeRequest& operation,
    NativeCloneRangeState& before, AppleVolumeTransactionPlan& out, std::string& error)
{
    return PlanNativeCloneRangeTransactionImpl(source, checkpoint, volume, source_inode, target_inode,
        operation, before, out, error, false);
}
bool PlanNativeCloneRangeTransactionV2(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, std::uint64_t volume,
    std::uint64_t source_inode, std::uint64_t target_inode, const NativeCloneRangeRequest& operation,
    NativeCloneRangeState& before, AppleVolumeTransactionPlan& out, std::string& error)
{
    return PlanNativeCloneRangeTransactionImpl(source, checkpoint, volume, source_inode, target_inode,
        operation, before, out, error, true);
}
}
