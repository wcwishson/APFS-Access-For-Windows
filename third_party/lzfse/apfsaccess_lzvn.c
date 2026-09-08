// ApfsAccess private bridge. Upstream provenance and license: PROVENANCE.md, LICENSE.
#include "apfsaccess_lzvn.h"
#include "lzvn_decode_base.h"

int apfsaccess_lzvn_decode_exact(const unsigned char *src, size_t src_size,
    unsigned char *scratch, size_t scratch_size, size_t expected) {
  lzvn_decoder_state state = {0};
  if (!src || !scratch || src_size == 0 || src_size > PTRDIFF_MAX ||
      scratch_size == 0 || scratch_size > PTRDIFF_MAX ||
      expected != scratch_size - 1)
    return 0;
  state.src = src;
  state.src_end = src + src_size;
  state.dst_begin = scratch;
  state.dst = scratch;
  state.dst_end = scratch + scratch_size;
  state.dst_current = scratch;
  apfsaccess_lzvn_decode_lowlevel(&state);
  return state.end_of_stream == 1 && state.src == state.src_end &&
      state.dst == scratch + expected && state.L == 0 && state.M == 0;
}
