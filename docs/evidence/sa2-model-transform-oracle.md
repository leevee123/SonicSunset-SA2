# Independent original-word vertex arithmetic reference

own original-word interpreter, not Dolphin execution; GQR0=0, RN-nearest-even, NI0/nontrapping; finite consumed inputs/intermediate results; exact rational MUL/FMA with signed zeros; PSQ final-store FTZ; disjoint memory; lookahead is loaded but not validated until consumed.

Executed 219 cases, 7017 output slots and 146070 original instructions. Full matrices/raw input records/copy-before and after hashes are retained per case in oracle-cases.jsonl; every output32-byte slot is retained in CSV; complete loads, stores and per-lane operations plus coverage are retained. The three declared matrix cases are explicit test inputs, not recovered live game matrices.

Real cases use the 2 op23 and 69 op29 Sonic packets from the existing raw CSV and original decoded bank. All original scratch start/count fields are retained. Each test initializes independent sentinel scratch, then executes native words. Every untouched byte, source bank, matrix and descriptor remains unchanged. Both helpers perform one unused lookahead record; those loads are logged separately, and an unused nonfinite lookahead is permitted rather than incorrectly rejected.

Synthetic fused cancellation, signed zero and signed subnormal cases are included for both helpers; their unused lookahead is deliberately quiet-NaN bytes. Consumed NaN/infinity and rounded overflow are explicitly rejected and retained, not silently converted. Bounded count-zero prefixes stop after 100 original instructions; neither returns. Their control-count hazard remains as described in raw-audit.md.

Finite arithmetic is evaluated as exact binary rational products/sums followed by nearest-even binary32 rounding after every original multiply/FMA. Exact-zero MUL uses XOR signs; exact-zero FMA is negative only when the zero product and zero addend are both negative, otherwise nearest-even cancellation is positive zero. Underflow-to-zero uses the exact nonzero result sign. Intermediate subnormals are retained; final GQR0 float PSQ stores flush their subnormal results to signed zero. Other FPSCR/GQR states, nonfinite arithmetic, exception flags/traps, native aliases and live runtime bindings are excluded. This is an independent scratch interpreter, not actual Dolphin or game execution.

All engine/repository/original/frozen/language/helper files remain read-only. No engine implementation was copied.
