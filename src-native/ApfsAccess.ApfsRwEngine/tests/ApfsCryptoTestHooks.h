#pragma once

// Only available when every tested crypto unit is compiled with
// APFSACCESS_CRYPTO_TESTING. No runtime hook surface in production builds.
#ifndef APFSACCESS_CRYPTO_TESTING
#error Test hooks require APFSACCESS_CRYPTO_TESTING
#endif
#include <cstddef>
#include <cstdint>
namespace apfsaccess::crypto::testing
{
struct Hooks
{
    // Fail exactly the selected zero-based operation; -1 disables injection.
    int allocation_failure_at = -1;
    int lock_failure_at = -1;
    int cng_failure_at = -1;
    bool cng_fail_after_call = false; // Exercise cleanup after actual output/handle creation.
    int allocations = 0, locks = 0, cng_calls = 0;
    int wipes = 0, releases = 0, unlocks = 0;
    bool all_released_bytes_zero = true;
    std::size_t wiped_bytes = 0;
};
extern thread_local Hooks hooks;
}
