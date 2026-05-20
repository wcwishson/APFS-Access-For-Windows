# Third-Party Notices

## WinFsp headers

This repository vendors the minimal WinFsp user-mode header files needed to build the native mount host without requiring a local WinFsp SDK install:

- `third_party/winfsp/include/winfsp/winfsp.h`
- `third_party/winfsp/include/winfsp/fsctl.h`

The headers are part of WinFsp by Bill Zissimopoulos and are distributed under the WinFsp licensing terms stated in those files. The runtime dependency is not bundled by the source tree; users install the official WinFsp runtime separately through the app prerequisite flow or from https://winfsp.dev/.
