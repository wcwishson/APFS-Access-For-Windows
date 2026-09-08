#ifndef APFSACCESS_LZFSE_H
#define APFSACCESS_LZFSE_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef enum apfsaccess_lzfse_result {
  APFSACCESS_LZFSE_OK = 0,
  APFSACCESS_LZFSE_INVALID = 1,
  APFSACCESS_LZFSE_LIMIT = 2,
  APFSACCESS_LZFSE_ARGUMENT = 3
} apfsaccess_lzfse_result;

/* State storage is caller-owned, requires no alignment, and is never retained.
 * No heap allocation. The returned size includes alignment slack. */
size_t apfsaccess_lzfse_scratch_size(void);

/* Decode exactly one complete LZFSE stream, including bvx$.
 * All three buffers must be disjoint valid objects of the supplied lengths.
 * src and dst must be nonnull, even for zero expected output. dst_capacity
 * may exceed expected_size; bytes past expected_size are never touched.
 * dst is provisional scratch: its contents are unspecified on failure.
 * Publish/copy it only after OK. State scratch contents are always unspecified.
 * Work units: 1 per block/EOS, raw bytes, LZVN payload + output bytes,
 * or FSE 4096 + payload + literals + 3*matches + output bytes per block.
 * The conservative budget is charged before each block's work; LIMIT never
 * means a successfully decoded prefix. No resume/partial-success API. */
apfsaccess_lzfse_result apfsaccess_lzfse_decode_exact(
    const uint8_t *src, size_t src_size, uint8_t *dst,
    size_t dst_capacity, size_t expected_size, void *scratch,
    size_t scratch_size, uint64_t work_limit);

#ifdef __cplusplus
}
#endif
#endif
