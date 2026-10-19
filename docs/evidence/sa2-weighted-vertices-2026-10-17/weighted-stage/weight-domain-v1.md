# Full signed weight domain through C++

PASS: 8 actual weighted-API batches cover65536 signed16 inputs and393216 stored float words;2097408 full scratch bytes match. Independent original-quantization CSV supplies expected bits; matrices/positions are explicit synthetic identity/ones. Preserves last8B and extra sentinel slot. Unused quiet-NaN lookahead is not consumed.
