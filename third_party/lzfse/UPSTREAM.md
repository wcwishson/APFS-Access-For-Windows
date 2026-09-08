# LZFSE and LZVN Decoder Sources

Source: https://github.com/lzfse/lzfse

Revision: `e634ca58b4821d9f3d560cdc6df5dec02ffc93fd`.

The decoder subset is redistributed under the BSD 3-Clause license in
[LICENSE](LICENSE). Original copyright notices remain in each source file.
The APFS Access C bridges expose bounded decoding to the C++ reader; no encoder
is linked into the application.

Local changes add namespaced decoder entry points, MSVC-compatible internal
linkage, stricter match-distance and input-bound checks, explicit end-of-stream
validation, and a bounded decoding-work budget. The bridges require the expected
decoded size and report malformed or incomplete input as an error.
