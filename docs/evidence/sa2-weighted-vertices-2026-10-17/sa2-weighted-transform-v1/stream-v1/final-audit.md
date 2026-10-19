# Stream closure final audit

All 309 successful stream cases reproduce complete scratch, state, GQR1, end offsets and original instruction counts exactly. All 470 native helper-call descriptors match independent packet metadata, including additive scratch base, count, input pointer, masked variant and GQR1 carry. Full per-lane original PS operations are retained in native-PS-operations.csv. 245856 rows cover 160219 distinct arithmetic operand cases; exact-rational results match independent CRT float/FMA bits with zero differences.

All352 original words are verified again with VA/DOL/ISO mappings in original-words-verified.csv. Successful supported cases execute345; only seven op2A-only words D278..D290 are unexecuted there. The separate unsupported original prefix executes its stateOR2 and opaque call throughD28C; no unsupported body/return is fabricated. All120 ordinary and160 weighted helper words execute across supported cases.

All314 weighted core before/after artifact pairs still match their original manifest hashes; 18 protected original/frozen/primary-source/own-oracle inputs rehash unchanged. Exact source paths and manifest hashes are retained in JSON. This is a bounded own original-word/CRT arithmetic reference under explicit test bindings, not actual Dolphin/game execution or retail-state recovery.
