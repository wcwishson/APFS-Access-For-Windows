#pragma once
#include "ApfsFusionSpaceman.h"

namespace apfsaccess::catalog
{
// Private planning reader. The output is parsed evidence, not write authority.
bool LoadFusionPlanningAllocation(const ApfsFusionStore& binding,
    const RandomAccessSource& staged, const ContainerCheckpointView& checkpoint,
    AppleSpacemanView& view, std::string& error);
}
