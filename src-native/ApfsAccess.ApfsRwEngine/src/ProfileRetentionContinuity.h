#pragma once
#include "AppleTransactionCommit.h"

namespace apfsaccess::rw
{
// Private observational adapter. Inputs are canonical views reloaded on the
// same held profile source by the verifier. No allocator/write authority.
bool VerifyProfileRecoveryContinuity(const catalog::RandomAccessSource& source,
    const AppleRecoveryCheckpointView& pin,
    const std::vector<AppleRecoveryCheckpointView>& history,
    const catalog::AppleCheckpointView& current, bool fusion, std::string& error);
}
