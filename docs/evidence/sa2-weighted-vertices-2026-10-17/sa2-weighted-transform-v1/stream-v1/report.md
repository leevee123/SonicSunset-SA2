# Original first-stream dispatcher closure

Explicit test r13=803B52C0; SDA803AE0C4=matrix10000000; SDA803AE148=callerState; GQR0=0/GQR1=callerValue; own original-word BL/LR/SP/SDA+helpers execution, not retail/runtime/Dolphin execution; finite arithmetic RNnearest/NI0/nontrapping; disjoint source/matrix/scratch/stack/globals.

All100 original Sonic streams run under three declared matrices with identical fresh finite512-slot scratch. Initial state/GQR1 are explicit per-case fields, not inferred retail values. Original352 available words cover dispatcher8011D1D4 and helpersDA30/DAF0/DC98. This reuses the own raw-word interpreter and exact-rational PS math; no engine formula or actual Dolphin/game execution is used.

The interpreter executes original BL/LR/stack/SDA behavior. Dispatcher constructs helper descriptors on its own emulated stack; original state writes OR3 for op23, while weighted GQR1 writes persist. Original ENDlowFF stops before info read; unknown opcodes still read info and use encoded skip including4-byte overlap. Final end offset is a captured analysis trace value at the original exit, not an invented native return cursor; original r3 returns0.

Nine synthetic successful streams cover high-bit END,4-byte unknown/info overlap,12-byte unknown skip, state-bit carry/GQR preservation, op23 followed by weighted preserving rawslot+24, weighted bit15 mode0/clear mode2/set127, and overwrite followed by accumulation. Complete source binaries, before/after hashes, matrix/state/GQR values and logical end are in cases.jsonl; all native loads/stores/helpercalls/statewrites and final32-byte slots are retained in CSV.

Op2A is deliberately unsupported. A separately retained original prefix reaches its opaque helper call8011DC10 after stateOR2, with scratch unchanged at that stopping point. No op2A numerical body, return, or host rollback behavior is invented. Native aliases, unsafe zero-count loops, unmodeled FPSCR side effects, other GQR0 modes and actual matrix/caller binding remain excluded. No engine/repo/original/frozen/language changes; weighted core314-case boundary artifacts remain untouched.
