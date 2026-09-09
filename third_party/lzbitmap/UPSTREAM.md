# LZBITMAP decoder

Adapted from [eafer/libzbitmap](https://github.com/eafer/libzbitmap), authored by
Ernesto A. Fernández. Copyright (c) 2022 Corellium LLC. Licensed under MIT;
the full notice is retained in [LZBITMAP-LICENSE.txt](LZBITMAP-LICENSE.txt).

Pinned revision: `574abeae25b25c3319b9b6a9225cc7464e08ae88`.
[Source](https://github.com/eafer/libzbitmap/blob/574abeae25b25c3319b9b6a9225cc7464e08ae88/libzbitmap.c),
[header](https://github.com/eafer/libzbitmap/blob/574abeae25b25c3319b9b6a9225cc7464e08ae88/libzbitmap.h),
[license](https://github.com/eafer/libzbitmap/blob/574abeae25b25c3319b9b6a9225cc7464e08ae88/LICENSE).

This decoder-only adaptation adds namespaced entry points, exact input/output
framing, separate region bounds, checked history and repetitions, and a bounded
work budget. Its core uses fixed stack state and no heap allocation. The
upstream format knowledge comes from reverse engineering, not an Apple
specification; compatibility with every APFS producer is not established.

The APFS reader supports ZBM09 streams and exact FF raw escapes for types 13/14,
and exact CC raw markers for types 9/10. Non-CC markers for types 9/10 and excluded
low-nibble-F raw escapes return `Unsupported`. Safely parsed unused whole region
bytes and nonzero reserved trailer bytes also return `Unsupported`; malformed
known streams remain `Corrupt`. The final unused instruction half-nibble may
have any value.

Streams require exact sizes and a six-byte terminator. Internal chunks decode
at most 32768 bytes; history can cross internal chunks but resets for each APFS
resource block. Type 14 uses absolute 32-bit offsets, at most 65536 decoded bytes
and 69632 encoded bytes per block. Exceeding the encoded ceiling returns
`LimitExceeded`, including for otherwise valid fragmented streams. Additional
caller-configurable size, state and work limits apply. Range reads validate the
whole resource table and decode only selected blocks.
