#pragma once
#include "VolumeManagement.h"
#include "TransactionManager.h"
#include "VolumePhysicalMedia.h"
#include <map>
#include <memory>
#include <stdexcept>

namespace apfsaccess::rw
{
struct VolumeKeeperWalIdentities { std::string canonical, production; };

inline VolumeKeeperWalIdentities AcquireVolumeKeeperWalLeases(const std::filesystem::path& path,
    const VolumeKeeperWalIdentities& identities, std::vector<std::unique_ptr<WriteAheadLog>>& leases, std::string_view error_prefix)
{
    for (const auto& identity : {identities.canonical, identities.production}) {
        auto owner = std::make_unique<WriteAheadLog>(WriteAheadLog::Options{path, identity});
        if (!owner->AcquireWriterLeaseOnly()) throw std::runtime_error(std::string(error_prefix) + "WalBusy");
        leases.push_back(std::move(owner));
    }
    return identities;
}

// Caller proves a partitionless source and retains these leases and its WAL
// read fence through publication. No TransactionManager ownership handoff.
inline VolumeKeeperWalIdentities AcquireVolumeKeeperWalLeases(const std::filesystem::path& path,
    std::string_view container, std::uint64_t oid, std::vector<std::unique_ptr<WriteAheadLog>>& leases,
    std::string_view error_prefix)
{
    VolumeKeeperWalIdentities identities{
        "apfs-vol:" + std::string(container) + ":" + std::to_string(oid),
        DerivePartitionlessVolumeRecoveryIdentity(container, oid)};
    return AcquireVolumeKeeperWalLeases(path, identities, leases, error_prefix);
}
inline VolumeKeeperWalIdentities AcquireVolumeKeeperPhysicalWalLeases(const std::filesystem::path& path,
    const RawSnapshotBinding& binding, std::string_view container, std::uint64_t oid,
    std::vector<std::unique_ptr<WriteAheadLog>>& leases, std::string_view error_prefix)
{
    const VolumeKeeperWalIdentities identities{"apfs-vol:" + std::string(container) + ":" + std::to_string(oid),
        DeriveVolumePhysicalRecoveryIdentity(binding, container, oid)};
    (void)AcquireVolumeKeeperWalLeases(path, identities, leases, error_prefix);
    // Preserve exclusion against an already-running partitionless alias, without
    // accepting its records as the selected physical production identity.
    auto alias = std::make_unique<WriteAheadLog>(WriteAheadLog::Options{path, DerivePartitionlessVolumeRecoveryIdentity(container, oid)});
    if (!alias->AcquireWriterLeaseOnly()) throw std::runtime_error(std::string(error_prefix) + "WalBusy");
    leases.push_back(std::move(alias)); return identities;
}

// The file must already be fenced against writes/deletion. Empty files do not
// identify an owner; both legal identities stay leased even in that case.
inline TransactionManager::DurabilityWatermarks InspectVolumeKeeperWal(const std::filesystem::path& path,
    const VolumeKeeperWalIdentities& identities, std::string_view error_prefix, std::string_view debt_error)
{
    const auto require = [&](bool ok, std::string_view suffix) {
        if (!ok) throw std::runtime_error(std::string(error_prefix) + std::string(suffix));
    };
    const auto records = WriteAheadLog::ReadAll(path, "");
    require(records.status == WriteAheadLog::ReadStatus::Ok && !records.recovered_torn_tail, "WalReadOnlyInspectionFailed");
    auto identity = identities.production; bool first = true;
    for (const auto& record : records.records) {
        require(record.volume_identity == identities.canonical || record.volume_identity == identities.production, "WalIdentityUnproven");
        if (first) { identity = record.volume_identity; first = false; }
        else require(record.volume_identity == identity, "WalMixedIdentities");
    }
    std::vector<TransactionManager::AcceptedTransaction> transactions;
    TransactionManager::DurabilityWatermarks watermarks{}; std::string error;
    if (!TransactionManager::InspectAcceptedTransactionsReadOnly(path, identity, transactions, watermarks, error))
        throw std::runtime_error(error);
    require(transactions.empty() && watermarks.accepted_sequence == watermarks.apfs_durable_sequence &&
        watermarks.apfs_durable_sequence == watermarks.cleanup_sequence, debt_error);
    return watermarks;
}

// Native semantic inspection must already have succeeded for these immutable
// original records, with the file fence and both legal writer leases retained.
inline bool VolumeKeeperWalHasCleanBoundary(const std::vector<WriteAheadLog::Record>& records,
    std::uint64_t cleanup_sequence)
{
    std::map<std::uint64_t, const WriteAheadLog::Record*> aborted;
    for (const auto& record : records) {
        if (record.operation == WriteAheadLog::OperationKind::TransactionMarker &&
            record.state == WriteAheadLog::RecordState::Cleaned && record.flags == 0x2 &&
            record.transaction_id != 0 && !aborted.emplace(record.transaction_id, &record).second) return false;
    }
    for (const auto& record : records) {
        if (record.operation == WriteAheadLog::OperationKind::TransactionMarker &&
            record.state == WriteAheadLog::RecordState::Checkpointed && record.sequence > cleanup_sequence) return false;
        const bool prepared = record.operation != WriteAheadLog::OperationKind::TransactionMarker &&
            record.operation != WriteAheadLog::OperationKind::DurabilityWatermark &&
            record.operation != WriteAheadLog::OperationKind::CompactionIndex &&
            record.state == WriteAheadLog::RecordState::Prepared;
        if (!prepared || record.sequence <= cleanup_sequence) continue;
        const auto terminal = aborted.find(record.transaction_id);
        if (record.transaction_id == 0 || terminal == aborted.end() ||
            terminal->second->volume_identity != record.volume_identity || terminal->second->sequence <= record.sequence) return false;
    }
    return true;
}
}
