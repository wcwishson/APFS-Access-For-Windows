# APFS Access Performance Baselines

This file records physical-drive performance baselines for the `optimize/read-write-performance` branch. Add a row before and after each optimization checkpoint so speed changes are compared against the same drive and workflow.

| Date | Branch | Commit | Drive | Mode | Large write MB/s | Large read MB/s | Small copy files/s | Small move files/s | p95 commit ms | Notes |
| --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| 2026-05-25 | optimize/read-write-performance | pending | pending physical run | pre-optimization | pending | pending | pending | pending | pending | Baseline row placeholder; fill from `scripts/run_physical_rw_validation.ps1 -Mode Performance` before comparing engine changes. |

