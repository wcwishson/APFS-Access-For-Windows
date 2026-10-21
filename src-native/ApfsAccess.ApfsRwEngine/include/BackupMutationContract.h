#pragma once
#include "MetadataStore.h"
#include "TransactionManager.h"

namespace apfsaccess::rw
{
bool IsBackupRetainedMutation(MetadataStore::MutationOperation) noexcept;
std::optional<TransactionManager::MutationKind> BackupMutationJournalKind(
    MetadataStore::MutationOperation) noexcept;
bool DecodeBackupAcceptedMutation(const WriteAheadLog::Record&, MetadataStore::MutationRequest&,
    std::string& error);
}
