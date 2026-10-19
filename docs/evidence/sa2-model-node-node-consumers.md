# SA2 pointer-bank node consumers and transform order

The original Sonic drawing path consumes the relocated node `+4` payload and `+0x2C` / `+0x30` links. A static path and an animated path have different flags and guards. This report establishes field reads, integer selectors, pointer traversal and call order. It does not name a familiar model format, execute matrix/FP code, or establish complete geometry, animation/provider contracts or runtime draw selection.

Original evidence: GSNE8P0 `main.dol`, SHA256 `a53335308d1f820be236fd2b6342fee850eaf048eb26aac21ddb1903b060db2e`; frozen primary and startup-SDA generated C, retained ASM and original DOL words. All native VA/DOL/ISO offsets, original words and source hashes are retained in CSV and `word-audit.ai.json`. No project, original, engine, repository, frozen helper or export was changed. No leaked original source was encountered.

## Sonic path and field evidence

The already traced loader `0x800874C0` loads `SONICMDL.PRS` through `0x80050210`; the registry eligibility bound remains **0x214 = 532**, not decimal 214. Its original BL at `0x80087684` passes the node at `*(DAT_801E6734+0x2C)` into `0x8002ABC0`. The supplied stored-Sonic registry match identifies that root slot as ID 21, but registry lifetime, actual linkage and active draw selection belong to the separate registry audit.

The init C assigns callback `0x8007BFF4` to its task record `+0x14`. Original calls inside `0x8007BFF4` reach animated wrapper `0x8011E214` at `0x8007C458`, `0x8007C634`, `0x8007C648`; static wrapper `0x8011DF44` at multiple retained sites; and payload wrapper `0x8011DF20` at `0x8007C7C0`, `0x8007C80C`, `0x8007C870`, `0x8007C8BC`. All selected BL targets and preceding original words were checked. Some surrounding generated Sonic predicates/null alternatives are degraded; these call edges do not prove a frame, current registry root or all branch predicates.

| Node field | Bounded original use |
|---|---|
| `+0x00` | 32-bit flag word. Static traversal snapshots it at `0x8011DFEC`; animated code rereads it at its individual tests. |
| `+0x04` | Payload pointer passed in `r3` to the selected callback. Static loads at `0x8011E020` / `0x8011E0E8`; animated load at `0x8012046C`. |
| `+0x08`, `+0x0C`, `+0x10` | Original `lfs/stfs` fallback copies in `0x80113CD8` prove binary32 bit views. Used as the first transform triplet. No axis/unit names assigned. |
| `+0x14`, `+0x18`, `+0x1C` | Ordinary mode uses complete 32-bit words followed by low-16-bit lookup selection in `0x80115F68`. Full signed-32 semantics are not proved. Flag `0x400` instead selects float reads of these words with an additional `+0x34` value. Preserve their raw bits and mode dependence. |
| `+0x20`, `+0x24`, `+0x28` | Original `lfs/stfs` fallback copies in `0x80113CD8` prove binary32 bit views. Used as the final transform triplet. |
| `+0x2C` | Recursed link, before `+0x30`. Static loads at `0x8011E054` / `0x8011E11C`; animated load at `0x80120498`. |
| `+0x30` | Loop continuation link, read after recursion and local state restoration. Static `0x8011E12C`; animated `0x801204AC`. |
| `+0x34` | Conditional float read for the alternative four-value rotation path. It is not an unconditional extension of the loader's `0x34`-byte minimum footprint. Exact conditions appear below. |

`0x80089F48` copies fourteen 32-bit words (`0x38` bytes) from one selected node, allocates/copies six words (`0x18` bytes) from its `+4` payload, and replaces the copied payload pointer. `0x8002ABC0` also copies those spans. This proves the copy operations, not complete universal node/payload lengths or geometry meanings. The loader's proven minimum remains `0x34` bytes and payload minimum remains eight bytes; neither familiar layouts nor next-known-start partitions are substituted for native record sizes.

## Static traversal: 0x8011DFC0

Static wrapper `0x8011DF44` forwards into `0x8011D554`, which invokes `0x8011DFC0(root,0x8011D484)` between setup and finish helpers. The payload callback's lower endpoint `0x8011D414` and geometry are outside this scope. The shared save/restore helpers `0x8010AFCC` / `0x8010B018` each have six original words and preserve GPR3 through GPR7. Thus the decompiler's invented pair-return value at the traversal entry is not used as input provenance: original `r3` / `r4` become node `r27` / callback `r28` at `0x8011DFD4` / `DFD8`.

For each node, load the flags into `r30` at `0x8011DFEC` and initialize callback result `r29=0` at `0x8011DFF0`.

| Flag mask / original test | Observed static effect |
|---|---|
| `0x800` / `0x8011DFF4` | Call `0x80114F6C` with fixed block `0x803580B0` at `0x8011E004`. That helper forwards the current-state pointer and supplied block to `0x800ED08C`; complete lower copy/FP semantics are not reconstructed here. |
| `(flags & 7)==7` / `0x8011E008` | Fast path skips local push, three transform stages and local pop. Payload and link-A recursion remain subject to their own gates. |
| `1` / `0x8011E068` | When clear, call `0x8011616C(node+8)` at `0x8011E078`. |
| `2` / `0x8011E07C` | When clear, perform the middle transform stage. Its precedence is `0x1000` first, otherwise `0x400`, otherwise ordinary word triplet. |
| `0x1000` / `0x8011E088` | Call `0x8011DF70(0x803580B0)` at `0x8011E098`; it copies exactly input word indices `0,1,2,4,5,6,8,9,10` into the corresponding current-state indices, leaving other indices untouched. |
| `0x400` / `0x8011E0A0` | In the remaining middle-stage branch, load `f1` from node `+0x34` at `0x8011E0AC`, pass node `+0x14` in `r3`, and call `0x80115EAC` at `0x8011E0B4`. No quaternion or other familiar type is asserted. |
| `0x20` / `0x8011E0C0` | Ordinary middle stage passes this masked value as the second input to `0x80115F68(node+0x14,selector)` at `0x8011E0C4`. |
| `4` / `0x8011E0C8` | When clear, call `0x8011610C(node+0x20)` at `0x8011E0D8`. |
| `8` / `0x8011E014` or `E0DC` | When clear, pass node `+4` in `r3` and invoke the supplied callback at `0x8011E02C` or `E0F4`. This static path does not independently NULL-check the payload. Capture callback `r3` result in `r29`; if the callback was skipped, retain zero. |
| `0x10` / `0x8011E034` or `E0FC` | When set, skip link-A recursion. |
| `0x100` / `0x8011E040` or `E108` | With flag `0x10` clear, recurse unless this mask is set **and** the callback result is nonzero. There is no separate NULL test on link A before the recursive call. |

The general path calls `0x80116098` before the three transform stages. After payload handling and permitted recursion through current node `+0x2C` (`0x8011E05C` / `E124`), call `0x801160E4` for the general path, then load current node `+0x30` at `0x8011E12C` and continue if nonzero. The flags are the saved pre-callback word, while the link values are reread after callback/recursive effects; no immutable-link snapshot is invented.

There is no initial root NULL guard: the entry branches reach the flag load directly. A valid root and appropriate leaf gates are original input requirements, not added host repairs. Among the real 200 nodes, all 41 zero-link-A nodes have mask `0x10` set. That sample consistency does not prove arbitrary runtime inputs, termination or external callback behavior.

## Rotation word order and state helpers

The original integer part of `0x80115F68` selects an interleaved lookup index `(word & 0xFFFF) * 8`, using exact `rlwinm` mask `0x7FFF8`. It reads input offsets `+8,+4,+0` for selector zero, corresponding to node fields **`+0x1C,+0x18,+0x14`**. For any nonzero selector it reads `+4,+0,+8`, corresponding to **`+0x18,+0x14,+0x1C`**. The controlling selector comparison is `0x80115F94` / branch `F98`; angle comparisons use CR1, preserving the selector's CR0 for branches `0x80115FDC` / `0x80116078`. Zero selected indexes skip their numerical blocks but preserve this word-read order. No axis labels or angle units are inferred.

The helper contains GQR0 paired loads/stores, paired multiplies/adds and fused operations. Generated C includes lost paired-lane state and unsafe-looking overwrite expressions. Its numerical equivalence is **not** claimed. Likewise, `0x80116098` advances the current-state pointer by `0x30` and transfers state through GQR0 paired operations; `0x801160E4` conditionally subtracts `0x30` when it does not go below the stored lower bound. Call order is established without claiming an exact unquantized matrix copy or retail GQR/FPSCR state. Pointer-state addresses in SDA-only references use the separate startup assumption; literal addresses in `0x80115F68` remain literal original evidence.

## Animated traversal: 0x8012042C

Wrapper `0x8011E214` supplies payload callback `0x8011DF20` to `0x801203E0`. The latter passes incoming motion input to `0x80113B10`, stores the callback at current context `+0x0C` at `0x80120408`, then passes the root in `r3` to `0x8012042C` at `0x80120410`. The motion input/format and lower payload endpoint `0x8011D4EC` are not reconstructed here; original wrappers forward inputs despite incomplete generated signatures.

For each node, the original order is: `0x80116098` at `0x80120448`; `0x80113C4C(node)` at `0x80120450`; optional node callback loaded from `[r13-0x7278]` with `r3=node` at `0x80120468`; then payload handling. Payload `+4` must be nonzero (`0x8012046C..74`) and the **current**, post-node-callback flag `8` clear (`0x80120478..84`); pass that payload in `r3` unchanged to callback context `+0x0C` at `0x80120494`. Next load link A into `r3`, explicitly NULL-check it at `0x8012049C`, and recurse at `0x801204A4` if nonzero. Restore state at `0x801204A8`, load link B at `0x801204AC`, and loop if nonzero. No initial root NULL guard is added here either.

This traversal does **not** use static flags `0x10` / `0x100` to gate children. Its optional node callback, payload NULL guard, fresh flag read and explicit child NULL guard must not be normalized into the static path.

Transform application `0x80113C4C` calls `0x80113CD8` to prepare output groups, then calls `0x8011616C`, the selected middle helper, and `0x8011610C`, in that order. Original `0x80113F6C` sets `r3` to mode `r30`; the shared restore helper preserves `r3`, despite generated `void` C. Native caller tests mode 1 / mode 0 and otherwise invokes `0x80115E54`. Modes 0 and 1 call `0x80115F68` with selector 0 / 1 respectively; the same zero/nonzero read order above applies. Mode 2 uses four output words and an opaque lower transform operation.

In `0x80113CD8`, flag `0x40` controls whether the provider path is bypassed. With it clear: invoke provider `+0x30` for the first output group, select non-NULL provider `+0x34` or provider `+0x3C` for the middle group, invoke provider `+0x38` for the final group, and call `0x8011388C` afterwards. A zero provider result causes the corresponding original base-field copy. Provider targets, writes, lower helper effects and complete ABI remain unknown. With `0x40` set, copy base fields directly and do not invoke those provider/advance calls. The base path does not reuse static masks `1` / `2` / `4` to omit the output groups.

## Exact conditional +0x34 extent

Static `0x8011DFC0` reads node `+0x34` only when mask `2` is clear, `0x1000` is clear, and `0x400` is set. The outer `(flags&7)==7` fast path also skips it; mask-2-clear already excludes that path. Flag `0x400` alone is insufficient for this static read.

Animated `0x80113CD8` reads it at `0x80113F0C` when the flag-`0x40` bypass path reaches a set `0x400` test, without checking static mask `2`. On the provider path it reads at `0x80113D9C` only for a zero return from non-NULL provider `+0x34` plus set `0x400`; or at `0x80113E30` when provider `+0x34` is NULL, provider `+0x3C` returns zero and `0x400` is set. Successful providers avoid these node reads. Tests occur at their original sites; provider mutations can affect later flag reads.

Therefore retain the proven **52-byte minimum**, with a **conditional** additional word requiring an addressable `0x38`-byte footprint on those paths. A data reader exposing `+0x34` merely when flag `0x400` is present is a conservative host availability policy, not a claim that the native code always reads 56 bytes. The real Sonic sample contains no flag-`0x400` nodes, so that extension is supported by original code only and is not exercised by this sample.

## Validation, evidence and unknowns

Scripts ran once per version. Discovery scanned **8,811** frozen generated-C files and retained every source hash and complete textual candidates. Repeated offsets/recursion alone are not semantic proof; unrelated callback-record candidates remain text candidates. The supplied registry CSV contains `main` rows; the first discovery summary's empty SDA slot lists were a view-label filtering issue, corrected in `supplied-registry-consumer-groups.csv`, not absence evidence.

The native audit verified **984 original words in 21 bounded function spans**, **70 callsites**, **797 retained-ASM rows** and original bit extraction masks; the shared helper audit adds **12** checked words. All relied-on original/frozen source hashes remain unchanged. Integer index checking passed **262,144** cases with arbitrary high halves, and **six** original integer-control traces confirmed the zero/nonzero word-read order without executing FP blocks. Fifteen unique original Sonic/init call edges were checked in both export views, with complete narrow source windows.

The real original decoded Sonic file SHA256 is `b7ea586ed0fa22330dc8a2cfe2bb8fa9ce4ac70d9561764f35af4ced5d371963`. All **200** minimum node spans and **2,600** BE32 field words match the prior validated sample exactly; all **1,200** original-code-supported binary32 bit views are preserved, including **153** negative-zero patterns. Zero mode-`0x400` samples are explicitly recorded. All 41 zero-child nodes have static gate mask `0x10` set. This is sample data validation, not observed draw traversal or numerical transform equivalence.

Raw CSV includes complete source hashes, original words/VA/DOL/ISO mappings, calls, flags, retained ASM matches, original Sonic call windows, integer traces, real field bits and link-gate candidates. Compact reports retain result digests, per-function and input hashes. Remaining unknowns: complete structures and lengths; geometry and payload contracts; signed full-word rotation meaning, axis/units and four-value mode identity; provider formats/effects; callback mutation/lifetime and actual node selection/execution; all retail GQR/FPSCR, rounding, quantization and fused arithmetic; full ABI and unreviewed inherited boundaries. Registry lifecycle is owned by the separate task. **Engine files changed here: none.**
