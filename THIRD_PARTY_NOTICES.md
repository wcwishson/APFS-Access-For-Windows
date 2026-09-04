# Third-Party Notices

## WinFsp headers

This repository vendors the minimal WinFsp user-mode header files needed to build the native mount host without requiring a local WinFsp SDK install:

- `third_party/winfsp/include/winfsp/winfsp.h`
- `third_party/winfsp/include/winfsp/fsctl.h`

The headers are part of WinFsp by Bill Zissimopoulos and are distributed under the WinFsp licensing terms stated in those files. The runtime dependency is not bundled by the source tree; users install the official WinFsp runtime separately through the app prerequisite flow or from https://winfsp.dev/.

## utf8proc

This repository vendors utf8proc 2.1.1 at commit
`d688ac122660e465dc65c8eb7b1c2444fcd52829` for Unicode 9.0 filename
normalization and case folding:

- `third_party/utf8proc/utf8proc.c`
- `third_party/utf8proc/utf8proc.h`
- `third_party/utf8proc/utf8proc_data.c`

utf8proc is distributed under the MIT/Expat license, with Unicode-derived data
under the terms reproduced in `third_party/utf8proc/LICENSE.md`. APFS Access
applies the Unicode 9 full-fold mappings that utf8proc 2.1.1's generator could
otherwise replace with simple-fold mappings; the pinned Unicode data itself is
unchanged.
