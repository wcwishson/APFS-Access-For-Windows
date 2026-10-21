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

## LZFSE / LZVN

This repository vendors the LZFSE and LZVN decoder sources used for APFS
compressed-file reads:

- `third_party/lzfse/` (`apfsaccess_lzfse.*`, `apfsaccess_lzvn.*`,
  `lzfse_*`, full license in `third_party/lzfse/LICENSE`)

The code is Copyright (c) 2015-2016 Apple Inc. and is distributed under the
3-clause BSD terms reproduced in that LICENSE file.

## zlib (inflate)

This repository vendors a minimal zlib inflate subset used by native metadata
decompression:

- `third_party/zlib/` (`inflate.*`, `inftrees.*`, `inffast.*`, `crc32.*`,
  `adler32.*`, `zutil.*`, plus `zlib.h`, `zconf.h`, `zutil.h`, `gzguts.h`,
  `inffixed.h`, `crc32.h`, `inflate.h`, `inftrees.h`, `inffast.h`;
  full license in `third_party/zlib/LICENSE`)

zlib is Copyright (C) 1995-2026 Jean-loup Gailly and Mark Adler and is
distributed under the zlib license terms stated in `third_party/zlib/zlib.h`:
free use including commercial applications with origin attribution and
unaltered-notice redistribution conditions.

## lzbitmap

This repository vendors the lzbitmap sources used for APFS spaceman bitmap
handling:

- `third_party/lzbitmap/` (`apfsaccess_lzbitmap.*`, license in
  `third_party/lzbitmap/LZBITMAP-LICENSE.txt`, upstream notes in
  `third_party/lzbitmap/UPSTREAM.md`)

lzbitmap is Copyright (c) 2022 Corellium LLC and is distributed under the MIT
terms reproduced in that license file.

## SMBLibrary

The explicit `standard-share` command uses SMBLibrary 1.5.8 by Tal Aloni,
upstream commit `2edbcf3161084b51dbe11b8a960b0bc7c224b851`, under the GNU
Lesser General Public License version 3 or later. It does not replace the
default WinFsp provider. Local changes add required signing, trusted clone
routing and corrected lock packet serialization.

Packages containing `SMBLibrary.dll` include its LGPL and GPL texts, pinned
upstream C# source, local patch and extension source, source hashes and build
instructions under `third_party/SMBLibrary/`. See `BUILD.md` in that directory
for rebuilding the separate library assembly. Original copyright notices are
preserved in the source files.

## Microsoft .NET components

Managed application packages include Microsoft .NET components. The Microsoft
license and third-party notice files supplied with the managed NuGet packages
are included by package name and version under `licenses/dotnet-packages/`.
Self-contained packages also
include the .NET runtime license and notices under `licenses/dotnet-runtime/`
and the Windows Desktop runtime license under `licenses/windowsdesktop/`.
