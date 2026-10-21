#pragma once

#include "AppleVolumeTransaction.h"
#include "SoftwareVolumeTransition.h"

namespace apfsaccess::rw
{
bool PlanSoftwareTransitionPlainTransaction(const catalog::ImmutableEncryptedReadSource&,
    const catalog::AppleCheckpointView&, const AppleVolumeTransactionRequest&,
    std::shared_ptr<const catalog::SoftwareVolumeRetainedOwners>, const std::array<std::byte, 32>& actual_original_journal_identity,
    AppleVolumeTransactionPlan&, std::string&);
}
