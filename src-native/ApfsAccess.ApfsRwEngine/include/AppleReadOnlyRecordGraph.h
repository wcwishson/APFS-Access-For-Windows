#pragma once
#include "AppleVolumeTransaction.h"

namespace apfsaccess::rw {
[[nodiscard]] bool ValidateAppleReadOnlyPayloadExtentGraph(
    const std::vector<catalog::BtreeRecord>& fs, const std::vector<catalog::BtreeRecord>& refs,
    std::uint32_t block_size, std::uint64_t blocks,
    std::vector<ApplePhysicalExtentRecord>& out, std::string& error);
[[nodiscard]] bool ResolveAppleReadOnlySnapshotExtentLayer(
    const std::vector<ApplePhysicalExtentRecord>& prior, const std::vector<ApplePhysicalExtentRecord>& historical,
    const std::vector<catalog::BtreeRecord>& fs, const std::vector<catalog::BtreeRecord>& refs,
    std::uint32_t block_size, std::uint64_t blocks,
    std::vector<ApplePhysicalExtentRecord>& out, std::string& error);
// Same signed-layer engine with the canonical ONEKEY generation-zero codec.
// This pure graph proof grants neither decryption nor mutation authority.
[[nodiscard]] bool ResolveAppleEncryptedReadOnlySnapshotExtentLayer(
    const std::vector<ApplePhysicalExtentRecord>& prior, const std::vector<ApplePhysicalExtentRecord>& historical,
    const std::vector<catalog::BtreeRecord>& fs, const std::vector<catalog::BtreeRecord>& refs,
    std::uint32_t block_size, std::uint64_t blocks,
    std::vector<ApplePhysicalExtentRecord>& out, std::string& error);
// Exact held member windows validate all NEW/UPDATE/history intervals before
// the ordinary signed-layer engine; the encoded address gap is never capacity.
[[nodiscard]] bool ResolveAppleFusionReadOnlySnapshotExtentLayer(
    const catalog::ApfsFusionStore& source,
    const std::vector<ApplePhysicalExtentRecord>& prior, const std::vector<ApplePhysicalExtentRecord>& historical,
    const std::vector<catalog::BtreeRecord>& fs, const std::vector<catalog::BtreeRecord>& refs,
    std::vector<ApplePhysicalExtentRecord>& out, std::string& error);
}
