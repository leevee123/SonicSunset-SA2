# Original cleanup/helper word and graph audit

Verified all 519 frozen pointer-audit words against the original DOL. Audited 205 original words in four bounded function spans, 230 control-flow edges and 12 callsites. All 17 source input hashes remain unchanged.

Complete CSV retains raw file/ISO offsets, register fields, original retained-ASM matches, graph edges and incoming GPR3 definitions. Exported gaps remain marked as unowned original bytes. Both conditional successors are kept; structural reachability does not prove feasible execution. No Ghidra program, repository file or frozen helper was changed.
