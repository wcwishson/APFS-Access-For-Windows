#include "apfsaccess_lzfse.h"
#include "lzfse_internal.h"

/* Internal entry point; the public API never accepts decoder state. */
int apfsaccess_lzfse_decode_state(lzfse_decoder_state *, uint64_t);

size_t apfsaccess_lzfse_scratch_size(void) {
  return sizeof(lzfse_decoder_state) + 15;
}

static int overlaps(uintptr_t a, size_t an, uintptr_t b, size_t bn) {
  return an && bn && (a <= b ? b - a < an : a - b < bn);
}

apfsaccess_lzfse_result apfsaccess_lzfse_decode_exact(
    const uint8_t *src, size_t src_size, uint8_t *dst,
    size_t dst_capacity, size_t expected_size, void *scratch,
    size_t scratch_size, uint64_t work_limit) {
  uintptr_t sp = (uintptr_t)src, dp = (uintptr_t)dst;
  uintptr_t wp = (uintptr_t)scratch;
  lzfse_decoder_state *s;
  int status;
  if (!src || !dst || !scratch || expected_size > dst_capacity ||
      src_size > PTRDIFF_MAX || dst_capacity > PTRDIFF_MAX ||
      scratch_size > PTRDIFF_MAX || src_size > UINTPTR_MAX - sp ||
      dst_capacity > UINTPTR_MAX - dp || scratch_size > UINTPTR_MAX - wp ||
      overlaps(sp, src_size, dp, dst_capacity) ||
      overlaps(sp, src_size, wp, scratch_size) ||
      overlaps(dp, dst_capacity, wp, scratch_size))
    return APFSACCESS_LZFSE_ARGUMENT;
  if (scratch_size < apfsaccess_lzfse_scratch_size())
    return APFSACCESS_LZFSE_LIMIT;
  s = (lzfse_decoder_state *)((wp + 15) & ~(uintptr_t)15);
  memset(s, 0, sizeof(*s));
  s->src = s->src_begin = src;
  s->src_end = src + src_size;
  s->dst = s->dst_begin = dst;
  s->dst_end = dst + expected_size;
  status = apfsaccess_lzfse_decode_state(s, work_limit);
  if (status == -4) return APFSACCESS_LZFSE_LIMIT;
  if (status != LZFSE_STATUS_OK || !s->end_of_stream ||
      s->block_magic != LZFSE_NO_BLOCK_MAGIC || s->src != s->src_end ||
      s->dst != s->dst_end)
    return APFSACCESS_LZFSE_INVALID;
  return APFSACCESS_LZFSE_OK;
}
