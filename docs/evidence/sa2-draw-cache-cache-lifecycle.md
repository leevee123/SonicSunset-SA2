# Original second-stream draw-cache lifecycle — bounded audit

This audit establishes the operations and bounded caller order around `0x8011CCF8`. It does **not** establish runtime initialization, a reserved table allocation, model execution order, or draw equivalence. No engine, repository, original, frozen export, Ghidra project, or language file was changed. No game code was run.

## Cache operation proved by original instructions

The interpreter entry is `0x8011ccf8` / DOL `0x119cf8` / ISO `0x1383f8`. Original `lha` at `0x8011d184` / DOL `0x11a184` / ISO `0x138884` reads a halfword; `0x8011d188` / DOL `0x11a188` / ISO `0x138888` advances the stream pointer by two; `0x8011d18c` / DOL `0x11a18c` / ISO `0x13888c` tests exact `0x00FF` before command dispatch. Exhaustively checking all 65,536 halfwords against the original rotate/mask fields gives 256 upper-byte indices and exactly one terminal (`0x00FF`).

The index is `(raw_header >> 8) & 0xFF`, and the table-entry address is `0x80357A58 + index*4`. The full index domain reaches exclusive `0x80357E58`; this is an **addressable span**, not proof of 256 allocated entries. The base lies in original DOL BSS, so it has no canonical DOL/ISO data bytes. Runtime zeroing was not investigated or claimed. At `0x8011867C`, generated C passes `0x80357C60` to file/parser helpers; `0x801199B0` stores pointers to `0x80357C80`, `0x80357CF8`, `0x80357D70`, `0x80357DE8` in other globals. These lie inside the full index domain. Their naming/uses do not prove table ownership or safe native bounds.

Command4 extracts the index at `0x8011cd90` / DOL `0x119d90` / ISO `0x138490`. At `0x8011cda8` / DOL `0x119da8` / ISO `0x1384a8`, it stores the already advanced stream pointer, so the cached pointer begins **after** the definition command. It increments the 32-bit word at SDA displacement `-0x71CC` and stores it at `0x8011cdb4` / DOL `0x119db4` / ISO `0x1384b4`. It branches directly to the current invocation's return epilogue at `0x8011cdb8` / DOL `0x119db8` / ISO `0x1384b8`. It does not execute the cached body during this definition invocation, and no table bounds/validity check is shown.

Command5 loads the selected cached pointer at `0x8011cdcc` / DOL `0x119dcc` / ISO `0x1384cc`, places the current saved second argument in r4 at `0x8011cdd0` / DOL `0x119dd0` / ISO `0x1384d0`, and recurses at `0x8011cdd4` / DOL `0x119dd4` / ISO `0x1384d4`. There is no NULL/defined-entry test between load and recursive call. After the recursive return it decrements the same SDA word and stores it at `0x8011cde0` / DOL `0x119de0` / ISO `0x1384e0`, then resumes the caller's already advanced pointer at the next halfword. No recursion-depth/cycle guard appears in this path.

Original entry words hold incoming r3 in r20 and incoming r4 in r21 (`0x8011cd0c` / DOL `0x119d0c` / ISO `0x13840c`; `0x8011cd10` / DOL `0x119d10` / ISO `0x138410`). The audited `0x8010AFB0`/`0x8010AFFC` helpers only save/restore GPR20..31 stack slots; the generated pair-return/void signatures are not trusted. A recursive invocation creates fresh local control state and clears SDA `-0x7174` at `0x8011cd20` / DOL `0x119d20` / ISO `0x138420` (`0x803AE14C` under startup r13). It does not explicitly clear the table or counter. The shared clear is not a restored per-frame value in this function.

## Counter, reset, and lifetime limit

Under startup `r13=0x803B52C0`, SDA `-0x71CC` is `0x803AE0F4`. All 376,848 original main-DOL text words were scanned for the exact applicable r13-relative immediate forms: only `0x8011CDAC`, `0x8011CDB4`, `0x8011CDD8`, `0x8011CDE0` match, the two load/store pairs above. Two table low-half materializations match, both in the interpreter. Two original direct branches target the interpreter, from its recursive site and dispatcher `0x8011D414`. There are no aligned literal pointer words equal to the interpreter/table/counter in the original DOL. These are **bounded explicit-form results**, not alias or indirect-call completeness proofs.

The 8,811-file primary/SDA generated-C named-symbol scan likewise finds the counter only in the interpreter. `0x8011D2F4` resets other globals `0x803AE140/144/148`, not an explicit table/counter store; `0x8011D410` is an original `blr` at `0x8011d410` / DOL `0x11a410` / ISO `0x138b10`. None of the inspected wrapper bodies explicitly resets this cache. Helper aliases, bulk clears, REL writes, and runtime startup state remain outside the proof. The counter's purpose is unknown: increment on definition and decrement after cached invocation do not by themselves prove recursion depth or number of active definitions. No reset or specific frame/model lifetime is inferred.

## Caller order supported by code

At `0x8011d414` / DOL `0x11a414` / ISO `0x138b14`, the dispatcher first calls `0x8011C18C`, saves `0x803AE15C`, processes nonnull payload+0 via `0x8011D1D4`, calls `0x801160E4`, and then processes nonnull payload+4 via `0x8011CCF8` with the saved context. This proves order **within a dispatcher invocation** only.

`0x8011D554` calls setup `0x8011D2F4` once, traverses `0x8011DFC0` with callback `0x8011D484`, then calls finish `0x8011D410`. The callback may gate out the dispatcher. The previously audited live links, flags and callbacks control node order. `0x8011D4EC` instead gates, then runs setup→dispatcher→finish for its forwarded payload. These paths do not supply a file-order rule.

An additional bounded provider path begins at `0x80120584` / DOL `0x11d584` / ISO `0x13bc84`: setup→`0x80121764`→finish. Original words `0x801205B8/BC` place `0x8011D414` in r5. In `0x80121764`, the callback is saved, `0x80113B10` is called with incoming r4, then the callback is stored into current provider+0x0C at `0x8012178c` / DOL `0x11e78c` / ISO `0x13ce8c` before `0x801217B0(original r3)`. The full floating-point/register ABI remains unknown.

In `0x801217B0`, transform helpers precede an optional shared callback (`0x803AE048(node)`); payload+4 and flags are then read live. A nonnull payload with node flag8 clear invokes current provider+0x0C, with r3 still holding that payload (`0x801217F0` through `0x80121818` / DOL `0x11e818` / ISO `0x13cf18`). Live link+0x2C recursion follows, then `0x801160E4`, then live link+0x30 iteration. No root selection, callback side effects, cache ownership or runtime equivalence is inferred from this path.

## Retail sample and validation result

Original decoded SONICMDL is 136,360 bytes, SHA256 `b7ea586ed0fa22330dc8a2cfe2bb8fa9ce4ac70d9561764f35af4ced5d371963`. All 30 initial cache/control stops from the earlier bounded scan were rechecked against exact big-endian bytes: 15 definitions and 15 references. Index 0 has 8 definitions/8 references; index 1 has 7/7. Repeated indices establish why an arbitrary reference cannot be assigned a definition by index or file order alone. This inventory stops at each initial cache operation; it is not a dynamic trace and does not establish later cached-body contents.

Original DOL SHA256 `a53335308d1f820be236fd2b6342fee850eaf048eb26aac21ddb1903b060db2e`; all 8 original header mappings and segment hashes agree with retained mapping metadata. The 14 bounded function/helper scopes retain 700 original words, and 915 retained ASM rows across the two views agree byte-for-byte and offset-for-offset. All 46 selected hashed source/metadata inputs remain unchanged at final guard. Complete raw CSV and source hashes are retained; canonical VA/DOL/ISO sites are in `canonical-evidence-sites.csv`. Sample offsets are decoded PRS offsets; no artificial ISO/runtime mapping is assigned to them.

## Unknowns and artifact status

Native allocated extent, initial/reset values, lifetime, active definition at each runtime reference, global-counter meaning/alias consumers, all indirect/module callers, concrete caller/root/culling state, recursive-cycle limits and second-stream state/GPU effects remain unknown. Conservative integration must keep caller/cache state explicit and must not claim native initialization or rendering.

`word-audit-v2/` is authoritative. The earlier v1 convenience decoder column reversed its arguments; original words and mapping/ASM comparisons were unaffected. Earlier decoded columns and their derived windows are superseded. The early discovery wording “256 slots” is superseded by the 256-value addressable-domain distinction above. The final report and corrected v2 evidence are the handoff sources.
