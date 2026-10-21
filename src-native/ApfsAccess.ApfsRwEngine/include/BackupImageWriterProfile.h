#pragma once
#include "AppleVolumeTransaction.h"

namespace apfsaccess::rw
{
// Explicit, regular-image snapshot-runtime profile. No role normalization is
// serialized: the sole current and every historical APSB retain role 0x0180.
// Requires 1..64 base snapshots, complete supported unencrypted graphs and a
// shared finite budget. Canonical compressed historical forks are immutable.
// Extended metadata, transformed current streams and inventory
// changes remain excluded. This validator performs no writes or WAL acceptance.
bool ValidateBackupImageWriterProfile(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& expected, std::uint64_t volume_oid,
    std::string& error);

// Separate from the ordinary writer entry, whose backup-role refusal remains.
// Re-reads canonical source authority, preserves the historical record sets and
// opaque APSB bytes outside ordinary accounting fields, and retains all original
// source/pin/publication proofs. Callers still need typed durable acceptance.
bool PlanAppleBackupImageTransaction(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& expected, const AppleVolumeTransactionRequest& request,
    AppleVolumeTransactionPlan& out, std::string& error);
}
