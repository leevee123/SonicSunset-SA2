# Pointer-bank validation history

V1 passed the real Sonic sample and its original 4 preservation/10 rejection cases. Review then found that an aliased payload can modify a later ID or the sentinel, so the section view was changed to scan current bytes. The new strict compilation passed. V2 stopped at a stale repository-hash guard before launching the checker; this was a helper bookkeeping failure. The preserved V3 uses the current 244-file guard and passes the real sample plus 5 preservation/11 rejection cases. Earlier scripts and source-hash reports remain in the originating workspace.
