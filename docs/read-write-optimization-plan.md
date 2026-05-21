# APFS Read/Write Optimization Plan

This note preserves the current optimization backlog for the `optimize/read-write-performance` branch.

## Low Risk

1. Add timing counters and benchmark fields before deeper changes.
   - Measure wall-clock time, bytes, files touched, MB/s, and files/sec for physical validation phases.
   - Keep the existing correctness checks as the hard gate.
2. Reduce host status and journal chatter.
   - Keep status writes coalesced so unchanged JSON is not written repeatedly.
   - Add counters later if status churn becomes suspicious again.
3. Trim directory enumeration allocations in the WinFsp host.
   - Avoid allocating a fresh vector for every directory entry returned to Explorer.
4. Reduce duplicate service polling.
   - Reuse mount state inside one worker cycle instead of repeatedly polling native host status.
   - Avoid duplicate startup refresh and unbounded tray status broadcast backlog in a later small pass.

## Medium Risk

1. Add direct-buffer metadata reads for committed file ranges.
2. Avoid full temp hydration for read-only opens; hydrate only for write opens or cache chunks.
3. Move `BlockDevice` reads/writes to offset-based I/O so parallel operations do not serialize on seek position.
4. Cache APFS projection/object-map lookups during mount-time loading.

## High Risk

1. Add an incremental commit-validation fast path for clean small deltas.
2. Replace full mutation rollback snapshots with an undo/delta log.
3. Redesign write allocation for append growth, safe extent reuse, and eventually multi-extent writes.

## Gates

Every checkpoint should build, run targeted synthetic tests, and pass simple Explorer-style operations before moving to riskier work. Delete/recycle stability, eject behavior, write safety, and read/write robustness stay hard gates.
