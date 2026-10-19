# Cleanup graph and local quirk checks

All 12 original callsites match both exported call graphs (24 matches). Original source hashes remain unchanged.

The node+0x10 zero store precedes its later comparison, with no intervening call or write to the node register and only the eight distinct zero stores. The same saved nonzero child register is tested again in the special branch. These branches remain recorded; their normal-entry zero arms are not treated as observed execution.

The exact lha/rlwinm/sth low-halfword operation matches input & 0xfffe for all 65536 original possible halfwords; the output digest is retained in the compact twin. This validates the integer operation, not a gameplay role or allocator backend.
