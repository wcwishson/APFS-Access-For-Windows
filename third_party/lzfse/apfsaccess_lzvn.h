// ApfsAccess private bridge. Upstream provenance and license: PROVENANCE.md, LICENSE.
#ifndef APFSACCESS_LZVN_H
#define APFSACCESS_LZVN_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Caller provides expected + 1 writable bytes, disjoint from source.
// Returns 1 only for a complete stream with exact output and input consumption.
// Scratch contents are unspecified on failure. No allocation or external I/O.
int apfsaccess_lzvn_decode_exact(const unsigned char *src, size_t src_size,
    unsigned char *scratch, size_t scratch_size, size_t expected);

#ifdef __cplusplus
}
#endif
#endif
