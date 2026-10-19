# Node flags and integer operation order

Verified the static traversal's required flag masks from 14 original extraction instructions. The original rotation-index instruction matches (word & 0xffff) * 8 for 262144 cases including high-bit words. All 6 integer-only control traces read the three input words in +8,+4,+0 order for selector0 and +4,+0,+8 for selector0x20.

No FP/paired operation was executed; normal completion of opaque FP blocks is the trace condition. Full paths, inputs and digest are in the compact twin and raw CSV. Original Sonic consumer call windows and source hashes are retained, and original/frozen inputs remain unchanged.
