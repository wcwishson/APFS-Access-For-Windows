# APFS Access Performance Baselines

This file records physical-drive performance baselines for the `optimize/read-write-performance` branch. Add a row before and after each optimization checkpoint so speed changes are compared against the same drive and workflow.

| Date | Branch | Commit | Drive | Mode | Large write MB/s | Large read MB/s | Small copy files/s | Small move files/s | Delete files/s | p95 commit ms | Notes |
| --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 2026-05-26 | optimize/read-write-performance | pre-write-speed pass | APFS `E:` / PhysicalDrive2 | Baseline performance, 128 MiB large file + 40 small files | 38.921 | 1197.093 | 4.115 | 2.194 | 2.281 | n/a | Source: `artifacts/physical-rw-validation/physical-rw-performance-20260526-165031.json`; SHA-256 mismatches `0`, dirty transactions `0`. |
| 2026-05-27 | optimize/read-write-performance | `441b789` | APFS `E:` / PhysicalDrive2 | Full performance, 1 GiB large file + 1000 small files | 27.746 | 804.716 | 9.866 | 4.900 | 5.331 | n/a | Source: `physical-rw-performance-20260527-153356.json`; passed with SHA-256 mismatches `0`, but large-copy start/first-byte latency was high at about `19.8s` / `36.9s`. |
| 2026-05-27 | optimize/read-write-performance | `441b789` | APFS `E:` / PhysicalDrive2 | Experimental prepared payload write-through, 1 GiB + 1000 small files | 4.965 | 768.137 | 10.021 | 5.105 | 5.389 | n/a | Source: `physical-rw-performance-20260527-164712.json`; passed integrity, but large write regressed badly, so `APFSACCESS_PREPARED_PAYLOAD_WRITETHROUGH` remains disabled by default. |
| 2026-05-27 | optimize/read-write-performance | `441b789` | APFS `E:` / PhysicalDrive2 | Corrected default sanity, 256 MiB large file + 100 small files | 44.882 | 331.005 | 12.561 | 7.346 | 8.332 | n/a | Source: `physical-rw-performance-20260527-170850.json`; passed with SHA-256 mismatches `0`, dirty transactions `0`; close commit max was about `4.4s`. |

