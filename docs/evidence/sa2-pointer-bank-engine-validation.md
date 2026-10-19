# Pointer-bank engine validation

The real 136360-byte sonicmdl.prs decoded sample matches every one of 64 entry fields, 529 pointer-store offsets/old/new values and their exact order. Result SHA-256 matches the independent original-loader simulation. 688 visits cover 200 unique minimum-span nodes and 115 opaque payloads; repeated visits are retained. Original bytes are preserved.

5 preservation cases and 11 host rejection cases passed; strict MSVC compilation passed. This only parses raw banks and creates a declared self-contained pointer view. Geometry, native registry/allocation/aliasing/runtime and other versions remain outside this result.
