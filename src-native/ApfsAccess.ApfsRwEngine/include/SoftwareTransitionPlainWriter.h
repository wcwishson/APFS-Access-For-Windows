#pragma once

#include "SoftwareVolumeTransition.h"
#include <functional>

namespace apfsaccess::rw
{
class MetadataStore;
class TransactionManager;
// Synchronous admission under the caller's ordinary image/original-WAL gate.
// The certificate supplies exclusions only; ordinary mutation acceptance and
// canonical commit/replay retain their existing authority checks.
bool WithSoftwareTransitionPlainWriter(MetadataStore&, TransactionManager&,
    std::shared_ptr<const catalog::SoftwareVolumeRetainedOwners>,
    const std::function<bool(std::string&)>& operation, std::string& error);
}
