# Evidence recheck v1 schema failure

An optional expected_sha256 cell was blank; v1 stopped before a completed audit. Recorded before/after digests were present. No source/engine changes. V2 chooses populated digests and requires agreement, preserving v1.
