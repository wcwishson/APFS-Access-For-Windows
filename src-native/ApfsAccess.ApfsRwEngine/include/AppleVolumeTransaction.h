#pragma once

#include "AppleTransactionCommit.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace apfsaccess::rw
{

struct AppleVolumeDataWrite
{
    std::uint64_t file_private_id = 0;
    std::uint64_t logical_address = 0;
    std::uint64_t crypto_id = 0;
    std::vector<std::byte> bytes;
};

struct AppleVolumeTransactionRequest
{
    std::uint64_t volume_object_id = 0;
    // Complete replacement record set for the filesystem tree, excluding
    // extents generated for data_writes. Data-stream ID records are checked
    // and normalized against the old tree and data_writes.
    std::vector<catalog::BtreeRecord> filesystem_records;
    std::vector<AppleVolumeDataWrite> data_writes;
    std::vector<AppleSpacemanReleaseRequest> released_data_blocks;
    std::int64_t file_count_delta = 0;
    std::int64_t directory_count_delta = 0;
    std::int64_t symlink_count_delta = 0;
    std::int64_t other_object_count_delta = 0;
    // Zero preserves the existing APSB modification time.
    std::uint64_t last_modification_time = 0;
};

struct AppleVolumeTransactionPlan
{
    AppleSpacemanAllocationPlan allocation;
    AppleTransactionCommitPlan commit;
    std::vector<std::uint64_t> payload_blocks;
    std::vector<catalog::BtreeRecord> filesystem_records;
};

// Builds a complete single-volume Apple APFS copy-on-write transaction without
// performing I/O. Snapshot-bearing volumes remain fail-closed until snapshot
// reference accounting is implemented.
bool PlanAppleVolumeTransaction(
    const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint,
    const AppleVolumeTransactionRequest& request,
    AppleVolumeTransactionPlan& out_plan,
    std::string& out_error);

} // namespace apfsaccess::rw
