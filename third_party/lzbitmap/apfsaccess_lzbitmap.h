/* MIT; decoder derived from Corellium libzbitmap. See LZBITMAP-LICENSE.txt. */
#pragma once
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#define ZBM_INVAL (-2)
#define ZBM_RANGE (-3)
#define ZBM_LIMIT (-5)
#define ZBM_NONCANONICAL (-6)
size_t apfsaccess_lzbitmap_state_size(void);
/* No allocation. Exact input/output; caller provides non-overlapping buffers.
 * May modify dest on error. work is a shared decrementing operation budget. */
int apfsaccess_lzbitmap_decode_exact(void *dest, size_t dest_size,
    const void *src, size_t src_size, size_t expected, uint64_t *work);
#ifdef __cplusplus
}
#endif
