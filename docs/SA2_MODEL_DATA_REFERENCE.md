# SA2 model data: nodes, vertex packets and drawing commands

The engine now exposes the proven raw fields of Sonic's loaded nodes and the first geometry packet stream. All **200 nodes / 2600 words** and **100 streams / 154 data packets / 100 end words / 3167 records** match original-derived references, including every raw packet byte. This is an additive CPU importer; model drawing, numerical transforms, skinning and animation remain unfinished.

The source is SA2 Battle **GSNE8P, disc 0, revision 0**, main DOL SHA-256 `a53335308d1f820be236fd2b6342fee850eaf048eb26aac21ddb1903b060db2e`. Existing REA/Ghidra Gekko exports are reused; C is read first and original words resolve omitted register inputs, flags, pointer arithmetic and processor/FIFO effects. No Ghidra program/project, installed language or frozen export changed. Internal asset offsets are decoded-file coordinates; native function tables and raw CSV retain VA/DOL/ISO coordinates. Synthetic bases and host models do not establish retail addresses or execution.

The two original-code audits below retain their distinct boundaries and source evidence. Their statements about no engine changes refer to those audits; the later importer implementation is described after them. The raw copied reports remain immutable historical evidence. Original code is not leaked source.

## Original node field and traversal audit

The original Sonic drawing path consumes the relocated node `+4` payload and `+0x2C` / `+0x30` links. A static path and an animated path have different flags and guards. This report establishes field reads, integer selectors, pointer traversal and call order. It does not name a familiar model format, execute matrix/FP code, or establish complete geometry, animation/provider contracts or runtime draw selection.

Original evidence: GSNE8P0 `main.dol`, SHA256 `a53335308d1f820be236fd2b6342fee850eaf048eb26aac21ddb1903b060db2e`; frozen primary and startup-SDA generated C, retained ASM and original DOL words. All native VA/DOL/ISO offsets, original words and source hashes are retained in CSV and `docs/evidence/sa2-model-node-word-audit.ai.json`. No project, original, engine, repository, frozen helper or export was changed. No leaked original source was encountered.

### Sonic path and field evidence

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

### Static traversal: 0x8011DFC0

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

### Rotation word order and state helpers

The original integer part of `0x80115F68` selects an interleaved lookup index `(word & 0xFFFF) * 8`, using exact `rlwinm` mask `0x7FFF8`. It reads input offsets `+8,+4,+0` for selector zero, corresponding to node fields **`+0x1C,+0x18,+0x14`**. For any nonzero selector it reads `+4,+0,+8`, corresponding to **`+0x18,+0x14,+0x1C`**. The controlling selector comparison is `0x80115F94` / branch `F98`; angle comparisons use CR1, preserving the selector's CR0 for branches `0x80115FDC` / `0x80116078`. Zero selected indexes skip their numerical blocks but preserve this word-read order. No axis labels or angle units are inferred.

The helper contains GQR0 paired loads/stores, paired multiplies/adds and fused operations. Generated C includes lost paired-lane state and unsafe-looking overwrite expressions. Its numerical equivalence is **not** claimed. Likewise, `0x80116098` advances the current-state pointer by `0x30` and transfers state through GQR0 paired operations; `0x801160E4` conditionally subtracts `0x30` when it does not go below the stored lower bound. Call order is established without claiming an exact unquantized matrix copy or retail GQR/FPSCR state. Pointer-state addresses in SDA-only references use the separate startup assumption; literal addresses in `0x80115F68` remain literal original evidence.

### Animated traversal: 0x8012042C

Wrapper `0x8011E214` supplies payload callback `0x8011DF20` to `0x801203E0`. The latter passes incoming motion input to `0x80113B10`, stores the callback at current context `+0x0C` at `0x80120408`, then passes the root in `r3` to `0x8012042C` at `0x80120410`. The motion input/format and lower payload endpoint `0x8011D4EC` are not reconstructed here; original wrappers forward inputs despite incomplete generated signatures.

For each node, the original order is: `0x80116098` at `0x80120448`; `0x80113C4C(node)` at `0x80120450`; optional node callback loaded from `[r13-0x7278]` with `r3=node` at `0x80120468`; then payload handling. Payload `+4` must be nonzero (`0x8012046C..74`) and the **current**, post-node-callback flag `8` clear (`0x80120478..84`); pass that payload in `r3` unchanged to callback context `+0x0C` at `0x80120494`. Next load link A into `r3`, explicitly NULL-check it at `0x8012049C`, and recurse at `0x801204A4` if nonzero. Restore state at `0x801204A8`, load link B at `0x801204AC`, and loop if nonzero. No initial root NULL guard is added here either.

This traversal does **not** use static flags `0x10` / `0x100` to gate children. Its optional node callback, payload NULL guard, fresh flag read and explicit child NULL guard must not be normalized into the static path.

Transform application `0x80113C4C` calls `0x80113CD8` to prepare output groups, then calls `0x8011616C`, the selected middle helper, and `0x8011610C`, in that order. Original `0x80113F6C` sets `r3` to mode `r30`; the shared restore helper preserves `r3`, despite generated `void` C. Native caller tests mode 1 / mode 0 and otherwise invokes `0x80115E54`. Modes 0 and 1 call `0x80115F68` with selector 0 / 1 respectively; the same zero/nonzero read order above applies. Mode 2 uses four output words and an opaque lower transform operation.

In `0x80113CD8`, flag `0x40` controls whether the provider path is bypassed. With it clear: invoke provider `+0x30` for the first output group, select non-NULL provider `+0x34` or provider `+0x3C` for the middle group, invoke provider `+0x38` for the final group, and call `0x8011388C` afterwards. A zero provider result causes the corresponding original base-field copy. Provider targets, writes, lower helper effects and complete ABI remain unknown. With `0x40` set, copy base fields directly and do not invoke those provider/advance calls. The base path does not reuse static masks `1` / `2` / `4` to omit the output groups.

### Exact conditional +0x34 extent

Static `0x8011DFC0` reads node `+0x34` only when mask `2` is clear, `0x1000` is clear, and `0x400` is set. The outer `(flags&7)==7` fast path also skips it; mask-2-clear already excludes that path. Flag `0x400` alone is insufficient for this static read.

Animated `0x80113CD8` reads it at `0x80113F0C` when the flag-`0x40` bypass path reaches a set `0x400` test, without checking static mask `2`. On the provider path it reads at `0x80113D9C` only for a zero return from non-NULL provider `+0x34` plus set `0x400`; or at `0x80113E30` when provider `+0x34` is NULL, provider `+0x3C` returns zero and `0x400` is set. Successful providers avoid these node reads. Tests occur at their original sites; provider mutations can affect later flag reads.

Therefore retain the proven **52-byte minimum**, with a **conditional** additional word requiring an addressable `0x38`-byte footprint on those paths. A data reader exposing `+0x34` merely when flag `0x400` is present is a conservative host availability policy, not a claim that the native code always reads 56 bytes. The real Sonic sample contains no flag-`0x400` nodes, so that extension is supported by original code only and is not exercised by this sample.

### Validation, evidence and unknowns

Scripts ran once per version. Discovery scanned **8,811** frozen generated-C files and retained every source hash and complete textual candidates. Repeated offsets/recursion alone are not semantic proof; unrelated callback-record candidates remain text candidates. The supplied registry CSV contains `main` rows; the first discovery summary's empty SDA slot lists were a view-label filtering issue, corrected in `docs/evidence/sa2-model-node-supplied-registry-consumer-groups.csv`, not absence evidence.

The native audit verified **984 original words in 21 bounded function spans**, **70 callsites**, **797 retained-ASM rows** and original bit extraction masks; the shared helper audit adds **12** checked words. All relied-on original/frozen source hashes remain unchanged. Integer index checking passed **262,144** cases with arbitrary high halves, and **six** original integer-control traces confirmed the zero/nonzero word-read order without executing FP blocks. Fifteen unique original Sonic/init call edges were checked in both export views, with complete narrow source windows.

The real original decoded Sonic file SHA256 is `b7ea586ed0fa22330dc8a2cfe2bb8fa9ce4ac70d9561764f35af4ced5d371963`. All **200** minimum node spans and **2,600** BE32 field words match the prior validated sample exactly; all **1,200** original-code-supported binary32 bit views are preserved, including **153** negative-zero patterns. Zero mode-`0x400` samples are explicitly recorded. All 41 zero-child nodes have static gate mask `0x10` set. This is sample data validation, not observed draw traversal or numerical transform equivalence.

Raw CSV includes complete source hashes, original words/VA/DOL/ISO mappings, calls, flags, retained ASM matches, original Sonic call windows, integer traces, real field bits and link-gate candidates. Compact reports retain result digests, per-function and input hashes. Remaining unknowns: complete structures and lengths; geometry and payload contracts; signed full-word rotation meaning, axis/units and four-value mode identity; provider formats/effects; callback mutation/lifetime and actual node selection/execution; all retail GQR/FPSCR, rounding, quantization and fused arithmetic; full ABI and unreviewed inherited boundaries. Registry lifecycle is owned by the separate task. **Engine files changed here: none.**

## Original payload and first-stream audit

The original draw path consumes each node+4 target as a payload containing two pointers. Pointer+0 supplies record packets; pointer+4 supplies drawing/state/cache commands. The **first-stream integer grammar and all real Sonic packet spans are established**. Numerical skinning, material semantics and a complete renderer are not established. No retail runtime execution was observed.

### Original code coordinates

|Original VA|DOL offset|ISO offset|Observed role|
|---|---|---|---|
|0x80089f48|0x86f48|0xa5648|Copies node and24-byte payload; count-derived stream copy|
|0x8008a230|0x87230|0xa5930|Consumes and transforms copied stream records|
|0x8008a718|0x87718|0xa5e18|Submits copied node|
|0x8011e17c|0x11b17c|0x13987c|Wrapper into shared node path|
|0x8011d554|0x11a554|0x138c54|Selects payload callback|
|0x8011dfc0|0x11afc0|0x1396c0|Node walker passes node+4 to callback|
|0x8011d484|0x11a484|0x138b84|Payload gate/culling callback|
|0x8011d414|0x11a414|0x138b14|Dispatches payload+0 and+4 streams|
|0x8011d1d4|0x11a1d4|0x1388d4|First-stream integer packet grammar|
|0x8011daf0|0x11aaf0|0x1391f0|Opcode29 record consumer|
|0x8011dc98|0x11ac98|0x139398|Opcode2C indexed weighted consumer|
|0x8011da30|0x11aa30|0x139130|Opcode23 record consumer|
|0x8011ccf8|0x119cf8|0x1383f8|Second-stream draw/state/cache parser|
|0x80101948|0xfe948|0x11d048|Writes primitive command byte and vertex count|
|0x8011d690|0x11a690|0x138d90|Writes three scalar floats to FIFO|
|0x8011d8e4|0x11a8e4|0x138fe4|Writes two halfwords to FIFO|

All36 selected functions,105 source artifacts and432 outgoing edge rows remain in complete source/call CSV. Original inspection verified2,427 exported ASM rows covering1,428 unique original addresses against main.dol and the ISO DOL at1E700. C was read before instruction evidence; generated signatures, FP expansions and FIFO stores were not treated as equivalent original behavior.

### Proven bridge from the real bank

80089F48 reads the registry-backed node pointer, copies38 hexadecimal bytes into an allocated node, copies its node+4 target into a separately allocated18 hexadecimal-byte payload, then derives a source-stream copy size from the second32-bit word atpayload+0. The copied node is submitted by8008A718 through8011E17C. 8011D554 supplies8011D484 as the callback to8011DFC0; that walker invokes the callback with node+4. 8011D484 can gate through8012192C; on its accepted path8011D414 passes nonzero payload+0 to8011D1D4 and nonzero payload+4 to8011CCF8, using the same recorded scratch-buffer argument. Node transform recursion remains a separate audit; this is a static pointer-consumption path, not proof that every bank node is drawn.

Real registry ID20 has decoded node offset1C7F0 and payload offset1C7D8. Its first stream is1C70C, first header00310023 and information word000C0000:12 opcode23 records starting atscratch index0. Original copy arithmetic produces204 bytes/51 words, covering8 header bytes,192 record bytes and4 EOS bytes. Its second stream is1C6A0. Source copies and update loops also access payload float words+8,+C,+10,+14; their complete rendering/shape interpretation remains outside this grammar.

### First-stream layout and exact pointer movement

All fields below are big-endian32-bit words, as consumed by original `lwz` instructions.

|Location|Original handling|
|---|---|
|Packet+0|Preserve the full word. Opcode=word&FF. If opcode==FF, return before reading the information word.|
|Packet+4|High16 bits give the record count; low16 give the starting scratch index.|
|Packet+8|Beginning of record bytes passed to the selected handler.|
|Header high16|Encoded count of4-byte units used by the main scanner; it is not the record count.|
|Next packet|`dataStart +4*((header>>16)-1)`, equivalently`packetStart +4*((header>>16)+1)` under original32-bit arithmetic.|
|Scratch start|Scratch argument plus `(informationWord &FFFF)*20hex`. Scratch capacity/lifetime is not established here.|

The dispatcher recognizes opcodes29,2C,2A,23; other non-FF opcodes have no selected handler and still follow the encoded skip. Opcode2A's record layout and other unused opcodes remain unvalidated. The scanner has no demonstrated bounds/EOS-capacity guard. In particular, an encoded high16 value0 moves to packet+4 after reading the information word; it must not silently be reinterpreted as an ordinary8-byte packet. Host validation policy for such unvalidated inputs is separate from original behavior.

|Sample opcode|Original handler|Bytes/record proven on this sample|Stored fields|
|---|---|---|---|
|29|8011DAF0|24|Six32-bit scalar slots loaded through GQR0 paired-single operations.|
|2C|8011DC98|28|Six32-bit scalar slots; signed16-bit field at+24 decimal; unsigned16-bit destination index at+26 decimal. Destination index is shifted left5 and added to the starting scratch pointer.|
|23|8011DA30|16|Three32-bit scalar slots plus packed32-bit word at+12 decimal. The original handler rotates the packed word left8.|

The scalar slots contain finite big-endian float values in this sample. Their exact paired-single interpretation depends on runtimeGQR0; numerical output equivalence, FPSCR controls and exact fused operations were not validated. The28-byte opcode2C stride is established by original source-pointer increments: input loads at0,8,16, then weight at24, destination index at26, then next record at28. A32-byte stride would be incorrect for these real records.

Opcode2C receives a variant extracted as `(header &7FFF)>>8`; native instructions first clear bit15 and then rotate/extract that byte. Its original handler distinguishes zero from nonzero variants when writing versus combining scratch values. The sample has38 zero-variant packets,2 variant1 packets and43 variant2 packets. No CPU skinning implementation or further variant naming is inferred from generated C.

### Exact original mask evidence

|VA|DOL offset|ISO offset|Original word|Role|
|---|---|---|---|---|
|0x8011d200|0x11a200|0x138900|0x5465043e|Header low16 extraction|
|0x8011d204|0x11a204|0x138904|0x5460001e|Header high16 mask|
|0x8011d208|0x11a208|0x138908|0x541d843e|Header high16 right extraction|
|0x8011d214|0x11a214|0x138914|0x54a5045e|Clear header bit15 before variant extraction|
|0x8011d218|0x11a218|0x138918|0x5460001e|Information word high16 mask|
|0x8011d21c|0x11a21c|0x13891c|0x5400843e|Information word high16 count extraction|
|0x8011d228|0x11a228|0x138928|0x5460043e|Information word low16 start extraction|
|0x8011d22c|0x11a22c|0x13892c|0x54002834|Start index times32|
|0x8011d264|0x11a264|0x138964|0x54a5c63e|Opcode2C high-byte variant extraction after bit15 clear|
|0x8011d2b4|0x11a2b4|0x1389b4|0x381dffff|Encoded header length minus1|
|0x8011d2b8|0x11a2b8|0x1389b8|0x5400103a|Length units times4|
|0x8011d2c8|0x11a2c8|0x1389c8|0x5460063e|Low-byte opcode/EOS extraction|
|0x8011d2cc|0x11a2cc|0x1389cc|0x280000ff|Compare opcode withFF|

All72 original words of8011D1D4 are retained in `docs/evidence/sa2-model-payload-first-stream-original-mask-words.csv`. The project-free bounded integer field selector was checked against135 existing Gekko rotate/mask instructions and267 existing word loads; unsupported instruction encodings remain explicitly undecoded rather than invented. The parser's complete C and direct call edges remain source evidence alongside those raw words.

### Real Sonic validation

One run of`validate_first_stream_v1.py` passed. Actual ISO data at479024A4 matches the protected102331-byte PRS file. The decoded136360-byte SHA-256 is`b7ea586ed0fa22330dc8a2cfe2bb8fa9ce4ac70d9561764f35af4ced5d371963`, matching the prior original PRS validation. Decoded offsets have no one-to-one compressed ISO coordinates.

The115 payloads contain100 nonzero first-stream pointers, all distinct, and15 zero pointers. The100 streams contain154 nonterminal packets and100 EOS words. Every sample data span equals8+count*recordStride:

|Opcode|Packets|Records|Bytes/record|
|---|---:|---:|---:|
|29|69|2273|24|
|2C|83|830|28|
|23|2|64|16|

There are3167 records total. Their possible scratch destinations cover509 distinct indices0..508 across the whole sample; this union does not prove per-draw initialization or capacity. Opcode2C's stored signed weight words range0..255. Complete raw header words, packet/record offsets, sizes, raw bytes, EOS positions, destination fields and opaque flags remain in CSV. No normalized weights or transformed/drawn results were produced.

### Original GQR1 and installed language caveat

8011DC98 writes **GQR1=08070807** using original words **38000807 at8011DCA4**, **64000807 at8011DCA8** and **7C11E3A6 at8011DCAC**. Complete DOL/ISO offsets are in `docs/evidence/sa2-model-payload-GQR1-original-setup-words.csv`. The original weight load at8011DD1C uses GQR1 with W1. The pinned primary Dolphin CPU definitions identify load type7 as signed16 and the scale field as6 bits; this original register value supplies load scale8, nominally2^-8. Exact transformed-vector results are not claimed.

The installed GameCubeLoader source **C:\decomp\sonic-adventure-gc\ghidra_12.1.4_PUBLIC\Extensions\Ghidra\GameCubeLoader\data\languages\ppc_gekko_broadway.slaspec**, also copied unchanged into the isolated language module, has SHA-256 **32ce4852d6243f5eea19cda1eb8cf0b2af8fb93532dcd9a585ee927a32c8eb75**. At line **1171**, its `load_ps` macro assigns `ls[0,3] = I[24,6];`: a6-bit scale is assigned to a3-bit target. Scale8 cannot be retained; its low3 bits are0. The frozen compiled SLA SHA-256 is **aa25bde9ffb8f6366e1e490c6a488b1aced4665dc6c4f2fdca9cc598d5530975**. Therefore its generated C is unsuitable evidence for exact weight scaling or weighted FP behavior. This is a source/decoding limitation, not an original game quirk. Installed source, isolated module, SLA and frozen exports were left unchanged.

### Initial bounded second-stream findings (2026-10-14)

8011CCF8 reads16-bit command headers. Its EOS check is the exact halfword00FF. It recognizes single-halfword controls, two-halfword operations for low-byte8..F, size-prefixed operations10..3F and geometry operations at40..42. Command4 stores the following stream pointer in a cache indexed by the header high byte and returns; command5 invokes a cached pointer. The sample's initial scans reached34 explicit EOS sites and30 cache/control stops, including15 definitions and15 references. Those stops are preserved, not misreported as completed render parsing.

The basic geometry readers issue native command98 and emit counts, three-float attributes and, for the textured forms, two signed halfwords. Original80101948 writes a command byte and then a halfword count toCC008000; several scalar emitters write three floats to that same address, and8011D8E4 writes two halfwords. Generated C retains only the last overlapping FIFO write, so it is not a complete draw transcript. Exact material meanings, primitive topology attribution, cache initialization/redefinition order, multi-stream batching, index/attribute interpretation and full second-stream consumption remain future evidence work. External reference lookups for topology/CPU implementation returned cache misses; no facts were inferred from those failed lookups.

This pass intentionally supplies a reviewable **CPU first-stream packet reader contract**: preserve headers, encoded spans, offsets, raw records, EOS and unknowns. It supplies no skinning, drawing, native calls or engine changes. It does not establish a complete named model format or gameplay. No leaked original source was encountered or used. No Ghidra project, native game runtime, installed/frozen source, repository or engine file was opened for mutation or changed.

Complete evidence: `docs/evidence/sa2-model-payload-consumer-source-verified.csv`, `docs/evidence/sa2-model-payload-consumer-original-words.csv`, `docs/evidence/sa2-model-payload-consumer-calls-verified.csv`, `docs/evidence/sa2-model-payload-sample-payload-headers.csv`, `docs/evidence/sa2-model-payload-sample-stream0-commands.csv`, `docs/evidence/sa2-model-payload-sample-stream4-commands.csv`, `docs/evidence/sa2-model-payload-first-stream-mask-reference.csv`, `docs/evidence/sa2-model-payload-first-stream-original-mask-words.csv`, `docs/evidence/sa2-model-payload-first-stream-sample-streams.csv`, `docs/evidence/sa2-model-payload-first-stream-sample-packets.csv`, `docs/evidence/sa2-model-payload-first-stream-sample-records.csv`, `docs/evidence/sa2-model-payload-GQR1-original-setup-words.csv`, `docs/evidence/sa2-model-payload-quantization-reference-source-lines.csv`, `docs/evidence/sa2-model-payload-slot20-real-payload.csv`, `docs/evidence/sa2-model-payload-FIFO-emitter-original-words.csv`, `docs/evidence/sa2-model-payload-input-artifacts.csv` and paired validation/inspection reports. Python versions were run once each; undefined source read probes were not converted into invented functions.

## C++ engine resource and conservative scope

Include `Importers/SA2/ModelData.h`. `SA2::readModelNodeFields(bytes,offset,includeField34=false)` returns `ModelNodeFields`: flags/payload pointer; offset-named raw BE32 arrays at `+8`, `+0x14`, `+0x20`; link words at `+0x2C/+0x30`; and an optional raw `+0x34` word. The default requires only the proven 52-byte minimum. Explicitly requesting the extra word requires 56 available bytes; it is a caller availability request, **not** a native branch selector. Static and animated provider conditions differ, so flag `0x400` alone is not used to infer a universal footprint. Raw words preserve negative zero, NaN payloads, high angle bits and mode-dependent interpretations; no axis/unit, signed full-angle or familiar four-value type is invented.

`SA2::readModelVertexStream(bytes,offset)` returns original file offsets, a copied raw byte span through END and metadata for every packet. Header low8 `0xFF` terminates before the info word is read; END occupies four bytes even if the ignored header upper bits are huge. Every other packet reads its raw info at `+4`, **including unknown opcodes**. An encoded four-byte nonterminal span can therefore have its info word overlap the next header; the reader retains that value and follows the original encoded movement rather than forcing an eight-byte skip. Known record strides are `0x23=16`, `0x29=24`, `0x2C=28`; record count is info high16 and start index info low16. Header and info bits are unchanged. Other opcodes, including the original dispatcher's unvalidated `0x2A`, retain opaque record bytes/stride zero; no handler is guessed.

Host guards reject short node/optional-word reads, out-of-buffer stream/header/info/spans, missing END, known packets shorter than eight bytes and known-record spans exceeding their declared packet. Such malformed-input safeguards are distinct from original unchecked behavior. Opaque four-byte spans are supported when their overlapping info is addressable. Padding and zero counts are preserved as metadata, without claiming native handler termination or scratch validity for arbitrary inputs. The API does not convert weights, normalize vertex counts, follow foreign pointers, allocate native scratch, execute providers/callbacks, interpret the second stream or upload GPU meshes. `3167` counts raw records, not unique rendered vertices.

The neutral resource name and offset-named fields are deliberate: the original consumers prove these reads/strides, while a complete named model format and processor/math contract remain unknown. Existing Ninja Basic/SADX and Shadow model readers remain untouched. No Lua gameplay prefab is inferred from these data-only findings.

## Engine validation and local test

`validate_model_data_v2.py`, run once, compares the C++ wire form with independently original-derived node and packet CSVs. It reports: **200 nodes / 2600 exact word bits; 100 streams / 154 data packets / 100 END words / 3167 raw records / 80448 raw stream bytes; every field, offset, span, byte and hash matches**. Packet counts are `0x29=69`, `0x2C=83`, `0x23=2`; corresponding records are 2273, 830, 64. The original decoded bank is 136360 bytes, SHA-256 `b7ea586ed0fa22330dc8a2cfe2bb8fa9ce4ac70d9561764f35af4ced5d371963`. Node metadata SHA-256 is `ea1161880cab792f914e0449cf5a7fa0eaf2141b9e18f3d9ec1b6100b4155e20`.

**Ten preservation and sixteen host rejection cases pass**, covering raw sign/NaN bits, explicit optional extent, END-before-info, huge ignored END length, all three strides, overlapping unknown info/headers, padding, zero counts and truncated/overflowing/missing-END inputs. Strict Windows x64 MSVC `/std:c++latest /W4 /WX /O2` and the full MSVC/Ninja Debug EDITOR ON engine build/link pass. The existing invocation-only Embedded debug workaround remains outside repo defaults. The first real-data version passed before final review added the opaque info-word read; the corrected implementation and regression case pass, with earlier helpers retained.

The local `outputs/SA2-Model-Data-Check/Start-SA2-Model-Data-Check.cmd` is a double-click checker using the existing original ISO and bundled Python. It passes all 200 nodes and 100 streams, saves paired Last-result files, includes no game media and does not modify the disc. Existing 95-module/bank checks and interactive texture preview remain available. The new checker does not draw geometry or run animation/gameplay. Other 243 guarded preexisting engine/content files are unchanged; the three engine changes are `ModelData.h`, `ModelData.cpp` and one CMake unit, listed in ENGINE_CHANGES.md.

## Additional real-bank inventory and next work

The separate raw inventory verifies 64 entries, 200 nodes, 115 payload headers, 688 converter visits and 230 inner pointer words. Sixty-six inner words are zero and 164 nonzero targets are distinct; 44 shared addresses occur in other pointer roles. No overlap occurs among the converter-proven minimum footprints, and no inner target points inside one. All 115 payload next-known-start partitions happen to be 24 bytes, while inner-target candidate partitions range from 4 to 12228 bytes. These are inspection partitions, not declared native lengths or a proof that full resources are disjoint. Source/header copy operations separately demonstrate particular 56-byte node and 24-byte payload copies. The real sample has no flag-`0x400` nodes. Node `+0x14/+0x18/+0x1C` has 15/16/43 NaN patterns under a hypothetical float reinterpretation; that does not make ordinary-mode angle words floats. The last triplet is raw `0x3F800000` in all sample nodes. Complete bytes, histograms, aliases and candidate spans are retained in `docs/evidence/sa2-model-bank-layout-*.csv` and paired reports; the exact decoded asset stays only in scratch.

The separate registry lifecycle audit is recorded in SA2_POINTER_BANK_REFERENCE.md. Whole-disc selected function counts are unchanged; these are bounded reviewed details within an otherwise unreviewed corpus. Remaining work: original second-stream cache lifetime/command closure and topology/material/index meaning; complete payload structures; correct numerical GQR/FPSCR/paired/FMA transforms and weights; provider animation formats/ABI; actual runtime node selection, ownership and execution; full engine drawing and eventual proven Lua content. The installed language's load-scale truncation and generated C's overlapping FIFO-write loss remain explicit limitations. No installed/frozen artifacts are patched to conceal them.

Human/AI current truth: this document and `docs/ai/SA2_MODEL_DATA.md`. Complete raw source/word/call/field/packet/record evidence is under `docs/evidence/sa2-model-node-*`, `sa2-model-payload-*`, `sa2-model-bank-layout-*`, with engine validation/build/package/history pairs. Each Python helper version ran once; failures remain preserved, not counted as native-game failures. No leaked original source was encountered or used.

## 2026-10-15: original drawing-command stream and cache control

The payload's second pointer is now read through a separate CPU resource, `Importers/SA2/ModelDrawData.h/.cpp`. The original bridge remains `0x8011D414 / DOL 0x11A414 / ISO 0x138B14`, which passes a nonzero second pointer to `0x8011CCF8 / DOL 0x119CF8 / ISO 0x1383F8` with the same scratch/context argument. Frozen context-free and SDA pseudocode were read first; original instructions settle cursor movement, signed loads and call/return details. No analysis database, installed language, frozen export or original asset was changed. This continuation supersedes the earlier bounded second-stream scan; that historical scan stopped at references as well as definitions and was not a full reader.

The byte order is big endian. Let `H` be the raw header at byte offset `p`, `op=H&0xFF`, and `L` the raw halfword at `p+2` where present. Exact `H==0x00FF` is tested before low-byte dispatch. A header such as `0x01FF` is therefore a nonterminal command in the last family.

| Header condition | Reads retained by the CPU resource | Following cursor / local return |
|---|---|---|
| Exact `0x00FF` | Header only | Return, consumed through `p+2` |
| `op` in `0x00..0x07`, except `0x04`/`0x05` | Header only | `p+2`; `0x01` also has a native state-handler path |
| `op==0x04` | Header, unsigned high-byte cache selector | Store following pointer `p+2` in selected cache location, then return immediately |
| `op==0x05` | Header, unsigned high-byte cache selector | Invoke selected pointer with the same context; after it returns, resume at `p+2` |
| `op` in `0x08..0x0F` | Header and raw argument at `p+2` | `p+4`; native argument is signed, preserved as bits here |
| `op` in `0x10..0x3F` | Header and raw size at `p+2` | `p+4+2*s16(L)`; state handler receives `p+4` |
| `op>=0x40` | Header, unsigned size at `p+2`, raw info at `p+4` | `p+4+2*u16(L)`; data pointer is `p+6` |

The last family includes unsupported opcodes above `0x42`: the outer interpreter still reads size/info and follows that cursor, although its explicit geometry emitter branches cover only `0x40..0x42`. The info read is unconditional, so size zero can make it overlap the next header. The reader preserves that overlap. Sized-state zero is likewise retained as metadata. These cases do not establish termination or memory safety of the native state/geometry handlers. The original uses unchecked 32-bit addresses; the host resource uses bounded file offsets and does not emulate backward or wrapped native addresses.

The geometry info load is signed. The original pending-group expression logically shifts the sign-extended value right by 14, whereas some child record skips mask `(value>>14)&3`. Those expressions cannot be interchanged for bit-15-set words. An exhaustive Python comparison of all 65536 raw halfwords finds 32768 differences between the outer expression and the raw top-two-bit interpretation. All 73 sample geometry headers have raw high2 zero, so this sample does not validate the other grouped paths. Raw words are retained without a group-count API or a guessed renderer.

Cache addressing uses base `0x80357A58` plus the unsigned header high byte times four. The 256 possible selectors prove an address domain, not a 1024-byte native table allocation: independently used named locations occur inside that address span. The address lies in the DOL's BSS range, so it has no stored DOL/ISO bytes; actual runtime initial contents remain unknown. Command `0x04` increments the word at `r13-0x71CC` after the pointer store and returns; command `0x05` recursively invokes the selected pointer, then decrements that word. Under the separately documented ordinary-poststartup `r13=0x803B52C0` assumption, that is `0x803AE0F4`; incoming runtime SDA state is not observed here. There is no native null-target guard in this path. The counter is not named a balanced stack depth: definition and call affect it differently. Entry also resets another word at `r13-0x7174` (`0x803AE14C` under that assumption), and state/GPU handlers have further effects. None of these graphics/global effects is executed by the CPU control trace.

The bounded whole-main-DOL text scan finds four exact accesses using the counter's SDA displacement, two literal table-base materializations and two direct branches to the interpreter. They are within the interpreter/bridge paths recorded in the evidence. This does not prove the absence of alias, module, callback or runtime writes. No cache reset, complete storage extent, lifetime, runtime initial value, actual binding or retail draw order is established. Additional callback/setup paths and independently used addresses are retained in the cache audit rather than converted into a scheduling assumption.

### Real-data results and explicit cache scenarios

The independent once-run inventory reports **64 nonzero payload second pointers plus 15 cached-body suffixes: 79 local invocations, 289 distinct physical commands, 42042 bytes, 64 exact-END returns and 15 definition returns**. All 115 payload headers and the decoded-bank identity are checked. There are 15 definition commands and 15 reference commands using two selectors. Selector 0 has eight definitions/eight references; selector 1 has seven/seven. Thus all same-selector static candidates total **113 pairs**. File order is storage order only and does not resolve those candidates.

There are **73 geometry spans: seven opcode `0x40`, sixty-six opcode `0x41`, no sample opcode `0x42`**. Their raw data spans total 40582 bytes. Full headers, signed and unsigned views, sizes, every halfword, raw bytes, ownership and offset/hash evidence are retained. No topology, material, coordinate scale, attribute meaning or full inner geometry grammar is inferred from that inventory.

A separate independent once-run control reference tests **128 explicitly constructed caller scenarios / 814 ordered command steps / maximum nesting depth one**: 15 definition roots with an empty host cache, and each of the 113 candidate pairs with exactly the matched selector seeded to that definition's following pointer. All complete without an unresolved reference. These are tests using real command bytes and declared initial state, not observations of native bindings or execution order. Synthetic nested-definition, redefinition, offset-zero target and recursive-limit cases separately exercise host control behavior.

Complete original grammar, cache/caller and data audit reports, sources, failures and complete raw CSVs are stored under `docs/evidence/sa2-draw-grammar-*`, `sa2-draw-cache-*` and `sa2-draw-data-*`. Those paired reports retain every additional finding and unresolved branch in their bounded scopes. Original function/word coordinates are VA/DOL/ISO; asset offsets are decoded `sonicmdl.prs` offsets, never observed live pointers.

### Additive engine API and host decisions

`SA2::readModelDrawStream(bytes,offset)` returns `ModelDrawStream`: original offset/end offset, ordered `ModelDrawCommand` metadata and copied raw bytes through the native local return. Commands retain the raw header, byte span and optional raw `+2/+4` words. It stops at exact END or a definition; it records a reference and follows the caller's local continuation without executing it. A saved suffix is read separately when explicitly requested. The neutral names avoid claiming a complete named model format.

`SA2::traceModelDrawControl(bytes,offset,initialCache,maxCommands,maxCallDepth)` returns ordered commands with call depth and the final copied cache. The explicit stack follows reference call/resume, exact-END return and definition store/return. Cache values are optional offsets into the same byte buffer; offset zero is a valid supplied value. Its array covers the eight-bit selector domain without claiming a native allocation size. Inputs are copied, so an exception does not modify the caller's cache. There are no assumed preloaded targets or implicit file-order scheduling.

Host safeguards reject unavailable headers/argument/info/declared spans, missing local returns, negative signed-state sizes, unresolved cache targets, out-of-buffer target reads, nonpositive limits and command/depth exhaustion. Bounded positive movement makes the raw stream reader terminate or reject. Negative sizes, cross-resource native pointers, 32-bit address wrap and native null dereferences are intentionally outside this copied-data API. The explicit limits are caller policy, not inferred retail limits. Geometry/state bodies remain opaque, so successful parsing does not certify safe native handler execution. These conservative choices are recorded because the original code supplies no host-safe contract.

The new path executes no graphics/state handlers, global counter updates, native scratch allocation, vertex transforms, weights, matrix operations, providers, GPU uploads or gameplay. Existing `ModelData`, pointer-bank, Ninja Basic/SADX and Shadow readers and public behavior remain unchanged. There are no existing callers to the new API. No gameplay prefab is invented before the corresponding behavior and data are proven.

### Engine validation, build and local check

`validate_draw_data_v1.py`, run once, reports **PASS: 79 streams / 289 commands / 42042 bytes; every offset, header, optional word, span and raw byte/hash matches the independent original-derived CSVs. All 128 explicit-cache scenarios / 814 steps match command metadata, order, nesting and final cache. Thirteen preservation and nineteen host rejection fixtures pass.** The source asset remains 136360 decoded bytes with SHA-256 `b7ea586ed0fa22330dc8a2cfe2bb8fa9ce4ac70d9561764f35af4ced5d371963`.

Strict Windows x64 MSVC `/std:c++latest /W4 /WX /O2` compilation/link and the full Windows x64 MSVC/Ninja Debug EDITOR ON engine build/link pass. The existing invocation-only Embedded debug-information workaround is unchanged. Two new engine files and one CMake source entry are the only engine changes; all other 245 previously guarded source/content files retain their hashes. Linux, EDITOR OFF and existing-game runtime behavior are not newly tested. Selected whole-disc corpus counts remain unchanged; generating C is still distinct from verifying a complete game.

The local `outputs/SA2-Drawing-Data-Check/Start-SA2-Drawing-Data-Check.cmd` double-click checker passes the packaged 79 streams and 128 scenarios, saves readable/compact Last-result files, includes no game media and reads the original disc without modification. It uses the existing local ISO/Python paths. It checks drawing data and control, not a playable model or game. Existing data checkers and the interactive Chao texture preview remain available.

Worker grammar validation v1's too-strong unique-definition assumption failed and is preserved; v2 corrects it to explicit candidate state. The cache audit retains its original convenience-decoder version and a separately corrected column. These helper issues are not native failures. No leaked original source was encountered or used. Remaining work includes actual cache lifecycle/bindings/caller closure; state/material and complete inner geometry/group/FIFO interpretation; exact GQR/FPSCR/paired/FMA transforms and weights; providers/animation; runtime node selection and ownership; engine model rendering and proven Lua gameplay/content.

## 2026-10-15 continuation: inner geometry counts and records

The count-led records inside the drawing commands now have a separate copied-data resource, `Importers/SA2/ModelGeometryData.h/.cpp`. This builds on the verified outer reader without changing it. Original generated C was inspected before raw words; successful core functions had no individual retained assembly export, so their exact original instructions were selected through matching main/SDA function-body ranges and compared with the original DOL/ISO. No database was opened and no frozen export, original or installed language was changed.

| Original function VA | DOL offset | ISO offset |
|---|---|---|
| `0x8011d594` | `0x11a594` | `0x138c94` |
| `0x8011d6a4` | `0x11a6a4` | `0x138da4` |
| `0x8011d7b4` | `0x11a7b4` | `0x138eb4` |
| `0x8011d91c` | `0x11a91c` | `0x13901c` |
| `0x8011fef4` | `0x11cef4` | `0x13b5f4` |
| `0x8011fff4` | `0x11cff4` | `0x13b6f4` |
| `0x80120158` | `0x11d158` | `0x13b858` |


### Count, index and record grammar

The outer interpreter supplies the data pointer at command `+6` and the raw info halfword at `+4`. Its unsigned size separately determines `command+4+2*size`, regardless of how many words the chosen inner helper consumes. Each single-stream helper masks info with `0x3FFF` for its count-led primitive count. It reads each primitive's first halfword with a signed load, negates a negative value in 32-bit arithmetic and uses the magnitude for the loop and emitted count. Raw `0x8000` therefore gives 32768 records; it is not an overflowing signed16 absolute operation. The raw sign is retained. These bodies do not establish a winding or topology interpretation for that sign.

Both the primitive loop and record loop are native do-while loops with no zero precheck. Zero wraps the corresponding 32-bit loop counter rather than representing an empty primitive; memory faults or other effects can intervene. The host reader rejects zero counts instead of emulating these unchecked malformed-input paths.

The first record word is always loaded as signed16 and scaled by `0x20` for a scratch address. Negative indices are not rejected by the native helper. The resource preserves the original unsigned bits without dereferencing scratch or guessing its lower/upper bounds. The masked per-record skip count is `g=(info>>14)&3`; this **masked** expression is distinct from the outer interpreter's sign-extended, unmasked pending-group expression documented above.

| Explicit layout | Original single-stream helpers | Words per record | Proven loads and skips |
|---|---|---|---|
| `IndexWithInfoSkips` | `8011D594`, `8011D6A4`, `8011FEF4`; opcode `0x40` path | `1+g` | Read signed index, then skip `g` halfwords |
| `IndexAndPair` | `8011D7B4`; opcode `0x41/0x42` path | `3` | Read signed index and two signed halfwords; high info skip bits do not enlarge the record |
| `IndexAndPairWithInfoSkips` | `8011FFF4`, `8011D91C`; opcode `0x41/0x42` paths | `3+g` | FFF4 reads index and pair then skips `g`; D91C reads only the index and skips `2+g` |

The last row shares byte boundaries but has different loads. The two words following the index remain raw/opaque in this resource; their presence is not evidence that D91C emits or interprets them. No normalized texture-coordinate scale or material meaning is assigned. Opcode `0x42` and nonzero skips are established from original code and synthetic cases; the current real sample contains neither.

The grouped helper `0x80120158` has a different contract: it mutates an external array of stream pointers, reads the run count from stream zero, skips secondary count words, reads the index from stream zero and reads pairs from each stream. Per-stream record movement is three halfwords, while shared count/control and pointer-array updates are separate. Its native capacities, alias behavior, actual grouped data and full caller contract remain unresolved. It is deliberately outside the new single-stream API.

### Dispatch, attribute setup and FIFO evidence

The caller must select a layout explicitly. Raw opcode/info alone cannot select the retail helper. The outer interpreter can defer a packet before drawing when its pending-group expression becomes nonzero. At the draw stage it also depends on a live state bit and an effective or saved high header byte, possibly modified by the original mask/override path. Thus the resource does not infer a helper from a header flag, assume an initial drawing mode or execute pending groups. The complete dispatch table and original coordinates are retained in the paired dispatch audit.

Original scalar helper paths load scratch words at byte offsets 0/4/8 and 12/16/20; alternate paths load 0/4/8 and a **raw word** at `+24`. Generated C's float-pointer spelling does not make that packed word a floating-point conversion. Original stores show three ordered `stfs` writes in scalar emitters, two ordered `sth` writes in pair emitters, and `stw` for the raw packed word. The command-begin helper writes a byte followed by a halfword. Generated C retains only the last overlapping FIFO store in several such bodies. Exact ordered writes, source addresses and file coordinates are retained; this is not yet a complete GPU transcript or a topology/material interpretation.

The numeric attribute setup for the pair helpers passes attribute number 13 with a final value of 8 when its separate selector is zero and 12 otherwise. Those numeric arguments are recorded without converting them into an unproven normalized coordinate contract. Another ABI caveat is now explicit: `0x8011D1AC` preserves incoming `r3..r6`, sets `r7=0` and `r8=0x7D`, then calls `0x801011D8` at `0x8011D1C0`. Its generated argument-free C wrapper loses those six-argument setup tuples. The dispatch report retains the exact tuples and canonical offsets rather than adopting that false prototype.

### Real Sonic validation

Independent once-run scripts agree on **73 geometry commands: 952 signed-count primitives and 6561 corner records** under the explicitly stated basic layouts. There are 675 positive and 277 negative primitive counts, with magnitudes 3..60. Opcode `0x40` contributes 25 primitives / 190 records; opcode `0x41` contributes 927 / 6371. All sample info high2 values are zero, so the two paired layouts have equal record boundaries on these real bytes. That agreement does not establish the actual runtime layout.

The 40582 declared data bytes split into 40510 bytes consumed by these layouts and **72 unconsumed bytes**. Thirty-six commands retain a two-byte `0000` tail; thirty-seven have no tail. The bytes are preserved without calling them alignment padding or assigning a purpose. There are 509 distinct raw indices, 0..508, and 12742 following halfwords whose signed inspection views range from -1 to 256. These are raw-record statistics, not a proof of scratch capacity, current initialization, unique rendered vertices or normalized coordinates.

Original grammar validation checks all 65536 raw count, parameter and index cases plus 17 boundary fixtures, with 713 original words across 34 scopes, 104 source artifacts, 244 retained assembly rows and 156 direct-call rows verified. The separate dispatch/FIFO audit and complete raw sample inventory preserve their own independent counts, source hashes and limitations. All reports and complete CSVs are copied under `docs/evidence/sa2-geometry-grammar-*`, `sa2-geometry-dispatch-*` and `sa2-geometry-data-*`. No original game execution is claimed.

### Additive CPU API and conservative decisions

`SA2::readModelGeometryData(bytes,offset,layout)` requires an explicit `ModelGeometryLayout`. It accepts opcode `0x40` with `IndexWithInfoSkips`, and `0x41/0x42` with either paired layout; unsupported combinations are host errors. It returns original offsets, raw header/info, record word count, raw signed-count words, every index and following/skipped word, the exact end of record consumption, the declared command end and every original command byte. The raw count sign and signed-index bit pattern are never silently changed in the returned data. Native attribute math, scratch dereferences and mode selection are not executed.

File bounds and containment inside the declared command are host safeguards: the native inner helpers do not enforce the outer encoded size. The reader rejects truncated headers/info/counts/records, unavailable declared spans, info outside its declared command, zero primitive/record counts, unsupported layouts/opcodes and extreme offsets. It retains unused tails and negative indices without treating them as invalid scratch accesses. The most-negative count is handled using 32-bit arithmetic. These policies provide a bounded data contract without claiming native malformed-input equivalence.

The new path is independent of the existing outer drawing reader, node/vertex readers, pointer-bank conversion, SA/SADX/Shadow importers and shared renderer/gameplay. No existing caller is switched to it. No state handler, transform, skinning, provider, GPU draw, cache scheduler or Lua gameplay prefab is inferred from the records.

### Engine checks, package and remaining work

`validate_geometry_data_v2.py`, run once after correcting the comparison helper's input schema, reports **PASS: 73 unique commands / 139 explicit layout views / 952 unique primitives / 6561 unique corner records; every header, info word, count, index, following word, offset, tail and raw byte/hash matches the independent original-derived oracle**. The 139 views exercise both paired helper layouts on the real zero-skip sample; they are not additional unique geometry or observed runtime paths. Sixteen preservation and nineteen host rejection fixtures pass, including nonzero skip distinctions, raw negative indices, count `0x8000`, opcode `0x42`, maximum encoded length, tails and zero/truncated/overrun cases.

Strict Windows x64 MSVC `/std:c++latest /W4 /WX /O2` compilation/link and the full Windows x64 MSVC/Ninja Debug EDITOR ON engine compile/link pass. The existing invocation-only Embedded debug-information workaround remains outside repository defaults. Only the two new ModelGeometryData files and one CMake source entry change the engine; all other 247 preexisting guarded engine/content hashes remain unchanged. Linux, EDITOR OFF and existing-game runtime behavior are not newly tested.

The local `outputs/SA2-Geometry-Data-Check/Start-SA2-Geometry-Data-Check.cmd` passes the packaged comparison and saves readable/compact Last-result files. It uses the existing local ISO/Python paths, includes no game media and reads the original disc without modification. This checks geometry records; it does not display a Sonic model or run animation/gameplay. Earlier checks and the interactive Chao texture preview remain available.

The first strict checker version failed because an integer initializer list was narrowed to `uint16_t` under warnings-as-errors; the production reader compiled. A separately retained checker version explicitly types that list. The first Python comparison treated pipe-separated oracle words as a list; C++ completed successfully, then the comparator stopped. V2 follows the actual schema and passes. Worker reports retain their own missing retained-assembly probes and the correction distinguishing a dirty-state store from FIFO stores. No such helper issue is reported as a native-game failure. No leaked original source was encountered or used.

Remaining work: actual runtime mode/caller/cache selection; multi-stream groups and capacities/aliasing; full state/material/topology/attribute/FIFO contract; scratch lifetime and correct GQR/FPSCR/paired/FMA transforms and skinning; providers/animation/ABI/ownership; engine model rendering and proven Lua gameplay/content. Whole-disc generated-corpus counts remain unchanged and do not establish a fully decompiled game.

Paired original reports: [geometry grammar](evidence/sa2-geometry-grammar-geometry-reference.md), [dispatch and FIFO contract](evidence/sa2-geometry-dispatch-dispatch-contract.md), [independent real-data inventory](evidence/sa2-geometry-data-summary.md). The dispatch audit verifies 1907 original words across 40 bounded functions, 1868 retained assembly rows, 44 direct FIFO store sites and 129 unchanged inputs. These scopes overlap the grammar audit and are not added as disjoint coverage.

## 2026-10-16: grouped-helper data, collector limits and wider sample search

A separate `ModelGeometryGroup` CPU resource now reproduces the grouped helper's bounded data reads with **explicit caller-supplied command offsets**. It does not discover retail groups, choose live drawing state or execute graphics. The completed search found no encoded grouped examples in its 23-model-bank boundary; actual native use remains unknown. The earlier single-stream API still excludes this path; this is a new parallel resource.

| Bounded original scope VA | DOL offset | ISO offset |
|---|---|---|
| `0x80120158` | `0x11d158` | `0x13b858` |
| `0x8011ccf8` | `0x119cf8` | `0x1383f8` |
| `0x8010afc4` | `0x107fc4` | `0x1266c4` |
| `0x8010b010` | `0x108010` | `0x126710` |


### Original grouped-helper contract

Original registers at `80120158` supply an array of stream pointers in r3, scratch in r4, the completing packet's info in r5, format/type storage in r6 and the number of additional streams in r7. Generated C's artificial save-helper return is not adopted as an ABI. Frozen C was read first; original words establish loads, stores and control order where C is incomplete.

The helper masks **the last/current packet's info** with `0x3FFF` for its outer primitive count. For every primitive it advances stream zero's pointer before loading that stream's signed16 prefix, skips one prefix halfword in every secondary stream, then negates a negative primary count in 32-bit arithmetic. Secondary prefixes are never compared and do not control iteration. Zero outer/inner counts have native do-while underflow behavior; the host reader rejects them.

For each record, stream zero supplies the signed scratch index. Secondary streams skip the corresponding first halfword. Every stream then supplies two signed16 words emitted as low halfwords. All streams advance three halfwords per record. A skipped secondary prefix/index may differ from the primary value, be zero or have bit15 set; this helper does not validate it. The resource retains every raw word, including skipped ones, without assigning normalized attribute units or topology. No scratch dereference or numerical transformation is performed.

Original cursor writes occur before their associated loads: notably at `80120224` before the count load at `80120228`, and at `80120328`, `80120380`, `80120390` before index/pair loads. Three original-word-model alias prefixes demonstrate that a native pointer-array store can change an unread count/index/pair when the pointer-array slots alias data bytes. That native memory-alias mode is excluded from the host resource. Equal or overlapping immutable byte-stream spans are different: each host cursor is owned independently, so those spans remain supported.

An original integer-word model checks 18 pointer-order cases, 12412 structural steps and 4848 memory events; three alias prefixes bring the retained event set to 4857. The unrolled secondary-prefix loop is checked for 257 k values, including the eight-word block boundary. Calls are opaque, floating loads are not reproduced and scratch word24 is supplied zero in that structural model; these results do not establish FP, MMIO or callee-side effects. The engine's eight-stream policy intentionally excludes the native collector alias cases described below.

### Collector, count provenance and independent storage window

`8011CCF8` takes pending from the **first** packet's sign-extended info logically shifted right by 14. Exhaustive 65536-halfword evaluation gives pending values `0`, `1`, `0x3FFFE`, `0x3FFFF`; it is not a raw two-bit field. The collection starts with stream index one, appends pointers and type flags in encounter order, and completes with pending+1 entries. Later info words do not replace pending and are not checked against the first count. At `8011D138`, r5 receives the **last/current** info before the call at `8011D144` to `80120158`.

All nonterminal opcodes `>=0x40` can enter the saved collection, even opcodes without a drawing emitter branch. Stored type is `(rawOpcode==0x42)`. The completing raw opcode selects the eventual branch; the grouped helper path completes on `0x41/0x42`, additionally depending on pending, saved/effective flags and live state. Header overrides and callbacks prevent treating this as a pure header-only runtime scheduler. The new resource receives an explicit ordered list and deliberately does not infer a collection from file order or enforce first-info/group-size equality.

Original stack coordinates prove separate storage for indices 0..7: types start at new SP+`0x10`, pointers at +`0x30`, saved GPR20 at +`0x50` through GPR31 at +`0x7C`, with saved LR at +`0x84`. Type[8] aliases pointer[0], while pointer[8] aliases saved GPR20. There is **no native index<8 check**. This proves a non-overlapping storage window, not a declared or intended allocation capacity. The host API accepts one through eight explicitly supplied streams to stay within that conservative window; larger inputs are rejected as host policy. One-stream and eight-stream probes exercise the helper with declared inputs and do not assert an encoded group of that width was observed or selected by this caller.

A previously obscured callback is retained in the collector evidence. `8011CAAC`, when reached, checks the state word's mask `0x80000`, loads a callback from `r13-0x7140`, checks for null and invokes it at `8011CAE8` with r3=0, bypassing its default setup. Generated SDA C's `||true` / null-call branch is contradicted by those original words. Under the documented ordinary-poststartup r13 assumption, that callback label is `803AE180`; live incoming SDA state and callback effects are unobserved. CCF8 reaches this state helper on the first/nonpending geometry flag-change path, then rereads dirty state before its next setup call. No engine callback or global-state execution is inferred here.

### Wider real-asset search and its boundary

The once-run search examined **all 23 FST basenames ending `MDL.PRS`**, case-insensitively; 20 matched the bounded original model-name literal set. Filename matching only selected candidates. Each asset separately passed bounded PRS identity, sentinel table, node/link/payload-pointer and outer drawing-stream checks. Complete carrier FST/ISO offsets, compressed/decoded hashes, pointer records, errors and command spans remain in raw evidence.

The scan reports 2462312 decoded bytes, 815 candidate table entries, 2311 unique asset-local nodes, 1311 payloads, 923 local drawing entries and 4839 command rows. All 923 local paths return at exact END or definition; continuation after a cache reference is conditional on the call returning. All **1595 geometry commands have info high2 zero**. There are zero nonzero-pending candidates and zero scan errors in that boundary. This is not an absence claim for other PRS names, other regions/revisions, mutations or runtime-generated data.

A separate once-run outer first-stream scan over those same candidates verifies decoded identities and records 1200 distinct asset-local first streams / 1738 nonterminal packets: opcode23=80,29=744,2C=914,2A=0. Only encoded movement/raw info/END is inspected; no unknown record grammar or numeric execution is inferred. Thus opcode2A remains unvalidated on real data outside this explicit boundary as well.

### Explicit real-byte probes and engine API

The independent oracle supplies **132 direct helper probes** from 66 real Sonic paired commands: 66 one-stream inputs and 66 duplicated two-stream inputs. They contain 198 stream views, 1854 primary primitives across probes, 12742 primary records and 19113 stream-record rows. These are explicitly constructed inputs using unchanged real bytes, not 132 encoded or observed native groups. Original prefix/index/pair words, offsets, final cursors, declared bytes and tails all remain available for comparison. A separate original-word model confirms a partially overlapping immutable-stream case.

`SA2::readModelGeometryGroup(bytes,orderedCommandOffsets)` returns raw per-stream header/info, declared end, final record cursor and every declared byte; all primitive prefix words; and each stream's first/pair words per record. It uses the last command's low14 info for primitive count and only the primary prefix magnitude for record count. Secondary skipped data is retained without equality checks. Earlier nonterminal high-family opcodes are accepted as collected streams; the final opcode must be41/42. The function does not select the original branch, interpret format/type arrays, invoke callbacks or emit GPU data.

The one-to-eight stream limit, file/declared-span containment, info-within-command check, completing-opcode check and rejection of zero counts are host safeguards. Raw negative bits and disagreeing secondary fields remain intact. Independent copied cursors support duplicate/overlapping byte spans while excluding native pointer-array/data and stack-array aliases. Unsafe native address wrap/underflow, zero-loop behavior, mutated native array storage and live state are not emulated. No first-info/count consistency rule is invented. No existing importer, runtime, shared renderer, SA/Shadow behavior or Lua/content caller changes.

`validate_group_data_v2.py`, run once after correcting the comparator's offset delimiter, reports **PASS: all132 probes /198 stream views /19113 stream-record rows match every independent metadata field, skipped word, cursor, tail and raw byte/hash**. Nine preservation and sixteen host rejection fixtures pass. Tests cover last-info versus primary-count authority, differing skipped fields, negative bits, one/two/eight streams, byte overlap and unsafe zero/span/window inputs. Strict MSVC `/std:c++latest /W4 /WX /O2` and full Windows x64 MSVC/Ninja Debug EDITOR ON compile/link pass with the existing invocation-only Embedded workaround. All other 249 preexisting guarded source/content files retain their hashes; two new files and one CMake entry are the only engine changes.

The local `outputs/SA2-Grouped-Data-Check/Start-SA2-Grouped-Data-Check.cmd` passes the packaged explicit probes, saves readable/compact Last-result files, includes no game media and reads the disc without modification. It does not display a Sonic model or establish native grouped use. Existing checks and the Chao texture preview remain available. Linux, EDITOR OFF and existing-game runtime are not newly tested.

### Evidence, corrections and remaining work

Complete paired reports/raw CSVs are stored under `docs/evidence/sa2-group-grammar-*`, `sa2-group-collector-*`, `sa2-group-samples-*` and `sa2-model-first-scan-*`. The grouped word audit verifies 479 original words /604 retained assembly rows /86 direct-call rows over four scopes. The collector audit verifies 897 words /957 assembly rows /138 direct-call rows over12 scopes, plus exhaustive info/opcode/cursor domains and five synthetic bindings. These scopes overlap and are not summed as disjoint coverage. All116 distinct recorded original/analysis/reference inputs were independently rehashed unchanged after worker usage limits interrupted final narrative handoffs; completed evidence was reused without restarting projects or analysis.

The first comparator expected pipe-separated command offsets, while the oracle uses semicolons; it stopped before launching C++. V2 follows the actual schema and passes. A read-only schema probe initially treated the oracle's numeric case count as a nested list; no inputs or engine files changed. All versions/corrections remain preserved. No leaked original source was encountered or used, and no original/frozen/installed artifact or analysis database was mutated.

Remaining work includes actual encoded grouped samples outside the search boundary and runtime branch/callback/cache selection; native array/alias behavior beyond the host boundary; material/topology/attribute/FIFO meaning; scratch ownership and exact GQR/FPSCR/paired/FMA transforms/skinning; animation/provider formats/ABI; model rendering, levels and proven Lua gameplay/content. Main/95-module generated-listing counts remain unchanged and do not establish a fully decompiled or playable game.

## 2026-10-16: explicit Float32 vertex calculation port

The new opt-in `ModelVertexTransform.h/.cpp` evaluates the original unweighted op23/op29 calculations into a copied native scratch buffer. It is a CPU arithmetic milestone, not a complete model renderer. The matrix is supplied explicitly; no live matrix, quantization register, animation/provider state or drawing mode is invented. Weighted op2C and op2A are unsupported by this API.

### Original functions and memory contract

| Original function VA | DOL offset | ISO offset |
|---|---|---|
|`80003140`|`140`|`1E840`|
|`80003330`|`330`|`1EA30`|
|`800E3D38`|`E0D38`|`FF438`|
|`800E5388`|`E2388`|`100A88`|
|`800E54AC`|`E24AC`|`100BAC`|
|`800E563C`|`E263C`|`100D3C`|
|`800E56BC`|`E26BC`|`100DBC`|
|`800ED368`|`EA368`|`108A68`|
|`800ED798`|`EA798`|`108E98`|
|`800ED7CC`|`EA7CC`|`108ECC`|
|`80100D44`|`FDD44`|`11C444`|
|`80102EF8`|`FFEF8`|`11E5F8`|
|`801057C4`|`1027C4`|`120EC4`|
|`801057F8`|`1027F8`|`120EF8`|
|`8010582C`|`10282C`|`120F2C`|
|`80105850`|`102850`|`120F50`|
|`8010588C`|`10288C`|`120F8C`|
|`80105908`|`102908`|`121008`|
|`8010A6B4`|`1076B4`|`125DB4`|
|`8010A86C`|`10786C`|`125F6C`|
|`8011C18C`|`11918C`|`13788C`|
|`8011C628`|`119628`|`137D28`|
|`8011C754`|`119754`|`137E54`|
|`8011C76C`|`11976C`|`137E6C`|
|`8011C960`|`119960`|`138060`|
|`8011C9AC`|`1199AC`|`1380AC`|
|`8011CC08`|`119C08`|`138308`|
|`8011D1D4`|`11A1D4`|`1388D4`|
|`8011D2F4`|`11A2F4`|`1389F4`|
|`8011DA30`|`11AA30`|`139130`|
|`8011DAF0`|`11AAF0`|`1391F0`|


The original dispatcher8011D1D4 reads count from info>>16 and the scratch start index from info&FFFF. Its direct calls at8011D24C and8011D2B0 select8011DAF0 for29 and8011DA30 for23. Op23 also ORs3 into the original drawing-state word; the new arithmetic helper does not mutate that global. Packet high flags do not choose another23/29 helper in this dispatcher. Records start eight bytes after the packet header. Native descriptors supply output pointer/input pointer/count at+0/+4/+8; these two helpers do not write the descriptor back.

Under the explicit GQR0=0 binary32 contract, the twelve matrix words supplied to the helpers have this memory layout. These are numerical component positions, not an inferred engine coordinate convention:

| Byte offsets | Words | Contribution |
|---|---|---|
|00,04,08|m0,m1,m2|first input scalar, three output components|
|0C,10,14|m3,m4,m5|second input scalar|
|18,1C,20|m6,m7,m8|third input scalar|
|24,28,2C|m9,m10,m11|translation in the first triple only|

For output component i=0..2, each FMA is independently rounded to binary32, with the multiplication and addition fused:

```
p = FMA(m[i],     x, m[9+i])
p = FMA(m[3+i],   y, p)
p = FMA(m[6+i],   z, p)

q = round_binary32(m[i] * u)
q = FMA(m[3+i],   v, q)
q = FMA(m[6+i],   w, q)
```

Both helpers calculate p. Op29 also calculates q without translation. No normalization or alternative transform order is inserted. Op23 has16-byte input records: three binary32 words and one raw packed word. It stores p at scratch+0/+4/+8 and ROL32(rawWord,8) at+24, preserving+12..23 and+28..31:16 untouched bytes per32-byte slot. Op29 has24-byte input records and stores p then q at+0..23, preserving+24..31:eight bytes. All other scratch slots and every untouched byte are copied exactly from the caller's initial scratch. Raw packed words are never treated as floats.

All original PS arithmetic lanes round as paired-single operations. Float PSQ loads preserve binary32 subnormal values. Importantly, float PSQ stores flush any subnormal result to its signed zero even when arithmetic NI=0. This is a final-store operation; intermediate subnormal arithmetic must remain enabled. The pinned official Dolphin paired/load-store sources and existing FPUtils reference support these hardware semantics; no emulator code is copied into the engine and neither Dolphin nor the game is executed by the oracle.

For positive count N, both original loops output N records but preload N+1, including an unused final record. Count1 still performs that lookahead. Count0 underflows CTR and enters an unsafe wrapping loop; bounded100-instruction probes do not return. The host rejects zero rather than reproducing unsafe memory traversal. It consumes only the required records, excluding unused lookahead reads, descriptor/input/output/matrix alias effects,32-bit address wrap, faults and FPSCR flags/traps. Original instruction/load/store CSVs retain these differences.

### Explicit numerical and host policies

`transformModelVertexPacketFloat32(bytes,packetOffset,matrix,initialScratch)` returns first index, count, opcode and an owned complete BE scratch copy. Matrix words retain the caller's raw binary32 bits. The declared contract is GQR0=0, nearest-even arithmetic, NI=0, nontrapping FP, finite consumed matrix/data values and finite retained-lane arithmetic results. It excludes live-state selection and discarded paired lanes/FPSCR effects. Some forced-one discarded lanes can overflow while all stored components remain finite: the independent oracle conservatively rejects two documented counterexamples, while the engine API's retained-lane contract excludes those discarded effects. They are not successful equivalence fixtures or proof of the original exception state.

The API checks host nearest rounding and subnormal input/output handling without changing their modes. Explicit `std::fma` preserves fusion; op29's first q product remains separate. CMake gives only this new unit `/fp:strict` on MSVC or `-ffp-contract=off` elsewhere. Linux is untested. NaN/infinity consumed inputs and nonfinite retained results are rejected; their payload/exception behavior is not guessed. Host file/declared-packet/full-slot bounds and positive counts are conservative guards, not original checks. Initial scratch must contain whole32-byte slots. Failure exposes no partial scratch result. Immutable host input/scratch aliases are copied; native pointer aliases are not emulated.

### Independent validation and runnable check

Quote from `validate_transform_data_v1.py` run once: **219 cases PASS;213 real-byte cases from71 distinct Sonic packets plus6 synthetic;7,017 output slots;458,112 complete scratch bytes compared;5 preservation/15 host rejection fixtures;0 production corrections.** The real packets are the original2 op23 and69 op29 packets under three declared matrices: identity, signed nonuniform scale plus translation, and a non-diagonal matrix. They are explicit test inputs, not captured live matrices. Every result byte and metadata field agrees with the independent original-word reference, including all untouched bytes. All source records, matrices, hashes and complete output slots remain in raw evidence.

The separate interpreter executes original words using exact rational multiplication/FMA and nearest-even binary32 rounding with signed-zero rules. Its219 successes cover all120 instructions in the two helpers and execute146,070 instructions. The dispatch/helper word audit checks192 original words. Complete logs retain657 unused-final-preload load events, three rejected nonfinite/overflow probes and two bounded zero-count prefixes. A separate CRT cross-check matches166,068 per-lane rows /102,818 distinct operation-and-operand cases with0 mismatches, plus12 explicit zero/subnormal boundary checks. Synthetic fused cancellation producesA8800000; the negative subnormal final-store case produces80000000. This is an instruction-model and arithmetic comparison, not hardware or retail execution.

Strict Windows x64 MSVC `/std:c++latest /O2 /fp:strict /W4 /WX` and the full MSVC/Ninja Debug EDITOR ON engine compile/link pass. Compile commands confirm `/fp:strict` applies to this source only. The prior invocation-only Embedded debug-information workaround remains unchanged. Other251 preexisting guarded source/content files retain their hashes; two files are new, with one CMake integration change. No previous SA2 API, SA/Shadow/shared renderer, pools, main, Lua or content caller changes. Existing gameplay, Linux and EDITOR OFF were not newly tested.

Double-click `outputs/SA2-Vertex-Check/Start-SA2-Vertex-Check.cmd` in the task workspace. The packaged check passes all219 cases plus host fixtures, reads the existing original disc, bundles no game media and saves paired Last-result files. It verifies calculations without displaying a model. The earlier texture preview and data checks remain available. Launcher paths are local-machine paths.

### Startup register proof and original drawing bootstrap

A complete376,848-word main-DOL text scan finds exactly two explicit GQR0 writes and one read. Startup80003140→80003330→800E3D38 reaches `li r3,0` at800E3D58 and `mtspr GQR0,r3` at800E3D5C. A separate snapshot reads GQR0 at8010A788 and stores it through8010A7B8 into802D6DA4. Restore8010A8A8 loads that saved word and8010A8AC writes it back; it is a memory-derived restore, not another literal-zero initializer. Both snapshot routines construct their own802D6AA8 base, independently of ordinary startup SDA assumptions. Snapshot storage is BSS with no original DOL/ISO bytes.

Ordinary context800E563C/800E56BC explicitly saves/restores GQR1..7. FP contexts800E5388/800E54AC contain64 implicit GQR0 paired instructions,32 loads/32 stores; they are not explicit SPR accesses. Startup zero narrows the earlier unknown but does not establish a live gameplay invariant: REL/apploader/copied code, aliases, snapshot order/mutation, other entry paths and runtime values remain unresolved. The current explicit arithmetic contract therefore remains necessary. Full boot offsets and scan boundaries are in the paired boot reference and raw GQR evidence.

Original8011D2F4 calls D44 three times with tuples(0,9,1,4,0),(0,A,0,4,0),(0,B,1,5,0), then2EF8(1). It writes0 / FFFFFFFF /0 to r13-7180/-717C/-7178; these are not three zero clears. It always uploads source80357880 via5850(index0) then588C(index0). If a fresh r13-71D8 load has00100000 clear, it builds stack blocks using ED7CC(-0.5,-0.5,+0), ED798(+0.5,+0.5,+1), calls ED368 twice, uploads5908(index2A,mode0), then reloads the state and ORs00100000. The second ED368 output aliases its second input. Exact ED368 numeric behavior is still unported. Constant addresses/raw words and all call/parameter order are in bootstrap CSVs; SDA labels/constants retain the documented r2/r13-base premise.

Each upload wrapper writes byte10 followed by a BE32 control toCC008000 before loading copy-source values.5850 uses((index<<2)mod32)|000B0000 and57C4;588C uses(3*index+400 mod32)|00080000 and57F8.5908 uses address(index<40?index*4:(index-40)*4+500), OR(mode==1?7:B)<<16. Only mode0 selects57C4; every nonzero mode selects582C, preserving the original control/payload discrepancy for modes other than0/1. At setup's actual arguments the three controls are000B0000,00080400 and conditional000B00A8. No GPU meanings are assigned from the numbers alone.

All loads precede the first repeated destination store in each copy helper. Under ordinary float layout57C4 transfers twelve sequential components;57F8 uses byte offsets00,04,08,10,14,18,20,24,28;582C transfers eight sequential components. PSQ store conversions still apply, so these are conditional component orders rather than universal bit copies.54 independent integer-wrapper cases /162 events match original words. Complete742 original words /19 scopes include root's682 and60 added words; these overlap previous audits and are not additional whole-corpus coverage.

Original8011C18C reads absolute803AE0C4, writes old+30 back before source loads, then branches into shared predecessor block8011C140..188. That block loads all six GQR0 pairs, permutes lanes and stores six pairs at old+30. Under float layout the component-source order is `[0,4,8,1,5,9,2,6,10,3,7,11]`. This establishes the transpose-shaped layout supplied to vertex helpers without proving storage initialization, ownership, capacity or live scalar values. The shared source80357880, pointer803AE0C4 and selected SDA-state locations all lie in header BSS and have no original file-backed bytes; analysis zeros are not initialized-value evidence. Native pointer/global aliases remain outside the CPU port.

Additional selected state/attribute/color/binding functions remain in the bounded generated-C and original-word evidence; they are not implemented drawing state. Raw function addresses and opaque numeric call tuples are retained rather than assigning unproved GPU/material meanings. The earlier GQR1 load-scale truncation in the frozen SLEIGH and generated-C repeated-FIFO-store loss remain unresolved tool limitations; no installed or frozen language was patched.

### Decisions, failures and remaining work

The conservative integration is an unused parallel SA2 helper with an explicit numerical contract. Proven CPU arithmetic is ported now; runtime state, weighted2C,2A, full matrix-stack math, animations/providers, materials/texture bindings/topology/attributes/FIFO integration and ownership still block faithful complete model rendering and later Lua prefabs/levels/gameplay. No partial character prefab is labelled complete.

184 distinct recorded original/frozen/helper/primary-reference inputs rehash unchanged. Complete evidence and manifests are retained in `docs/evidence/sa2-model-transform-*`, `sa2-model-bootstrap-*`, `sa2-gqr0-*` and `sa2-model-setup-*`. Root's initial selected-C report incorrectly labelled some100-line capped selections complete; full frozen C and the independent bootstrap audit supersede those selections. The official-reference web fetch cache-missed; an in-sandbox direct fetch failed DNS, then a bounded external read-only fetch saved the exact pinned files/hashes. Evidence-recheck v1 stopped on a blank optional expected digest; v2 checks populated before/after digests and passes. A worker's graph v1 link-bit assumption was corrected without changing original targets. Versions and paired failure notes are preserved. Arithmetic comparison, strict compilation, full build and package checks passed without production-code correction; the later header edit clarified excluded discarded lanes only.

Whole-disc generated counts remain60320 module C /2530 warned ASM /62850 artifacts and65146 canonical entry candidates plus one SDA alternative, with21 unowned foreign sites. Generated listings remain unreviewed outside bounded audits. The game is not fully decompiled, rendered or playable. No original/frozen/database/project changes or leaked original source were encountered or used.

## 2026-10-17: weighted vertices and complete first-stream CPU dispatch

The engine now reproduces the weighted `0x2C` vertex helper and executes complete first vertex streams containing `0x23`, `0x29`, `0x2C`, opaque skips and END. This is a CPU calculation path with explicit inputs. It is not a complete model renderer or an animated Sonic prefab. Earlier statements that weighted arithmetic is entirely unknown are superseded by this section; live matrix/animation/cache bindings remain unknown. The original game is not fully decompiled.

The source is GSNE8P USA disc0 rev0, original DOL SHA256 `a53335308d1f820be236fd2b6342fee850eaf048eb26aac21ddb1903b060db2e`. Both frozen Ghidra pseudocode views were read first. Original words resolve the quantization-scale loss and paired arithmetic that the generated C does not faithfully represent. The established REA6.3 DOL/PowerPC limitation still uses the existing Ghidra fallback; no project or frozen processor language was changed. No leaked original source was encountered or used.

### Original addresses

| Original function VA | DOL offset | ISO offset | Role |
|---|---|---|---|
|`8011D1D4`|`11A1D4`|`1388D4`|first vertex-stream dispatcher|
|`8011DA30`|`11AA30`|`139130`|unchanged op23 math|
|`8011DAF0`|`11AAF0`|`1391F0`|unchanged op29 math|
|`8011DC10`|`11AC10`|`139310`|unsupported op2A call boundary only|
|`8011DC98`|`11AC98`|`139398`|weighted op2C helper|


The raw evidence tables include VA, original DOL offset and ISO offset for every selected word and relevant load/store/control site. Decoded asset offsets are relative to the decompressed bank and are not disc addresses. The weighted helper is 160 words in `[8011DC98,8011DF18)`; the dispatcher is 72 words in `[8011D1D4,8011D2F4)`. Opcode2A's helper `8011DC10` is retained only as the unsupported call boundary; its numerical effects were not reconstructed here.

### Weighted packet and record layout

All stored fields are big endian. Every non-END packet reads its information word, even when the encoded four-byte packet span makes that read overlap the following header. The header low byte selects `2C`; bit15 is ignored by the helper variant extraction.

| Relative offset | Size | Meaning |
|---|---|---|
|packet `+0`|4|Header; declared byte span `4*((header>>16)+1)`; variant `(header&0x7FFF)>>8`|
|packet `+4`|4|Record count in high16; additive scratch base index in low16|
|packet `+8 + 28*r + 0`|12|First triple of raw binary32 components|
|record `+12`|12|Second triple of raw binary32 components|
|record `+24`|2|Signed16 weight, converted exactly to binary32 as `s16/256`|
|record `+26`|2|Unsigned16 destination index added to packet base|

The destination address is `scratch + 32*(base + unsignedDestination)`. It is not the record ordinal and is not limited to the packet count. Each helper writes six binary32 components at slot offsets0,4,8,12,16,20 and preserves bytes24..31. The port returns an owned copy of the entire initial scratch buffer, retaining every other slot and untouched byte.

At `8011DCA4/DCA8/DCAC`, original words construct and write `GQR1=08070807` (SPR913). This selects signed16 load type7 and load scale8; scalar PSQ loads set the other lane to1. The five original weight loads at `8011DD1C`, `DD74`, `DDEC`, `DE44`, `DEC4` are all word `E6679008`. No incoming GQR1 value is read or saved and no GQR1 restore occurs before normal return `8011DF14`. Saving FPR19 does not save GQR1. All65,536 signed inputs convert exactly: raw8000 gives−128 (`C3000000`), 7FFF gives127.99609375 (`42FFFE00`), and raw0000 gives positive zero. No weight clamp, normalization, complementary contribution or sum rule is inserted.

The frozen SLEIGH definition truncates the six-bit load-scale field to three bits, turning8 into0. Consequently this conversion cannot be taken literally from that generated C. Original words plus the pinned official Dolphin semantic reference establish the conversion; the frozen `.slaspec` and `.sla` remain unchanged. No Dolphin source was copied into the engine and Dolphin itself was not executed.

### Arithmetic and ordered writes

Use the same native matrix layout as the existing unweighted API: three contiguous columns at byte00,0C,18 and translation at byte24 hexadecimal. For row `i=0..2`, let column components be `A[i], B[i], C[i]`, translation `T[i]`, input triples `(x,y,z)` and `(u,v,w)`, and converted weight `q`:

```
P[i] = FMA(C[i], z, FMA(B[i], y, FMA(A[i], x, T[i])))
Q[i] = FMA(C[i], w, FMA(B[i], v, round32(A[i]*u)))
variant == 0: out = round32(transformed * q)
variant != 0: out = FMA(transformed, q, previous)
```

Each arithmetic result rounds to binary32; the translation-first order and separately rounded first product of the second triple are retained. Every nonzero seven-bit variant uses the accumulation branch, including variants2 and127. The nonzero branch does not first round a separate weighted contribution. Synthetic cancellation fixtures distinguish these operations: fused weighted cancellation `B0000000`, transform-then-weight cancellation `A8000000`.

All six previous components are loaded before a record's stores. Records execute in original order against the updated copied scratch: a repeated destination sees the previous record's final stored bytes, including subnormal flushing. At final PSQ float stores every subnormal becomes signed zero even with NI0. Intermediate NI0 arithmetic retains subnormals. Reversing a deliberate duplicate-destination fixture changes the final word from0 to`3F800000`; the port preserves that order. Slot tail bytes are never replaced by a guessed normal, color or padding structure.

The explicit host contract remains GQR0=0 for float loads/stores, nearest-even arithmetic, NI0, nontrapping FP, finite consumed inputs and finite retained-lane intermediate/results. Host rounding/subnormal probes reject unsupported environments without changing modes. Signed weight conversion itself is exact and finite across its whole domain. Native discarded lanes, FPSCR flags/traps, nonfinite propagation, pointer aliasing, address wrap and memory faults are outside this CPU contract. Bounds, complete slots, declared-span and positive-count checks are conservative host policy, not native guards.

The native pipelined loop preloads the next unused record. It reads at least24 bytes after the declared records; mode0 and nonzero counts>=2 also read the next weight/destination, requiring28 bytes. A nonzero one-record branch exits before that final weight/destination read. These are unused lookahead accesses, not extra records or format padding. Count0 underflows the loop counter toFFFFFFFF and is not a bounded empty packet; the port rejects it. The host consumes only the required records and does not reproduce unsafe lookahead/faults. The original-word oracle supplies readable lookahead explicitly.

### Whole first-stream dispatcher

`transformModelVertexStreamFloat32(bytes, offset, matrix, initialScratch, initialStateBits, initialGqr1Word)` calls the unchanged raw stream reader, then applies packets in stored order. Each packet receives the previous packet's output scratch. The returned end offset includes the END word; state bits and GQR1 are caller-owned modeled values. The native dispatcher returns literal r3=0 at `8011D2D4`; the host end offset is useful metadata and is not that native return value.

| Opcode | Native effect represented by this API |
|---|---|
|`FF`|Stop before reading an information word; retain state/GQR1/scratch|
|`23`|OR state with3 before matrix read/call; run existing `8011DA30` fragment|
|`29`|Run existing `8011DAF0` fragment; retain state/GQR1|
|`2C`|Run weighted `8011DC98`; leave modeled GQR1=08070807|
|other opaque opcode|Read info and skip encoded span; retain state/GQR1/scratch|
|`2A`|Host rejection: original OR2 and call boundary proven, numerical helper unsupported|

The native dispatcher advances `p + 4*((header>>16)+1)` with32-bit wrap. Its stack descriptor contains destination/source/count at offsets10/14/18 hexadecimal, written count then source then destination. The matrix pointer at `r13-71FC` is freshly read for each recognized helper call (`8011D248/D260/D288/D2AC`), and state uses `r13-7178`. Absolute labels803AE0C4 and803AE148 require the earlier post-startup SDA-base premise. The port does not infer a live r13, global address, initialized cache or traversal order.

The fixed matrix parameter is conservative only under declared no-alias/no-external-mutation bindings: scratch/stack/descriptor/source/global/matrix storage must not overlap. A typed audit of all280 words in23/29/2C finds no r13 writes, calls or r13-based stores; recognized store bases are r5, r1/r5, r1/r6 respectively. This supports conditional fixed binding, not a runtime proof. The host raw reader prevalidates the stream and uses bounded64-bit offsets, so malformed input/fault timing/partial side effects differ from native execution. Unsupported2A returns no guessed scratch or partial state. Opaque unused counts/bases/matrix values do not gain fictitious native scratch or finite guards.

### Real sample validation and bounded observations

The independent sample script reread ISO FST2428 and decompressed original `sonicmdl.prs`: ISO data offset479024A4,102331 compressed bytes, SHA256 `d8f90e6c724e709b8d3431e725a5db1d1a096bdf5118d2ecca9ad356e7862d99`;136360 decoded bytes, SHA256 `b7ea586ed0fa22330dc8a2cfe2bb8fa9ce4ac70d9561764f35af4ced5d371963`. It crosschecked all100 stored first streams,254 packet rows including100 ENDs and3167 record rows, plus72 original mask instructions. This one-version real sample validation passed.

There are83 weighted packets/830 records/4980 source float words. Variants0/1/2 contain38/2/43 packets and412/6/412 records. Every weighted header has bit15 set. Packet counts range1..66; weights range0..255 with30 zero and30 weight255; signed negatives,256 and higher are absent from this sample. Raw destinations range0..317; base-plus-destination range2..317 with248 distinct numeric destinations. No packet repeats a destination. Every packet's declared data is exactly count*28; there is no declared tail. All83 required lookahead windows are readable:81 need28 bytes,2 need24;65 follow an END word and18 another2C packet.

The65 stored weighted-stream sequences are:27 with2 alone,15 with0→2,21 with0 alone,one0→1→2,one0→1. None of57 within-stream weighted packet pairs intersects in destination. Across the entire stored bank, modes0 and2 each mention248 numeric targets and mode1 six; all weighted numeric targets also occur in op29 and in multiple streams. These are pooled numeric coincidences, not shared live cache identity, skeleton weights, weight-sum evidence or original frame traversal. The earlier23-bank search still found zero2A among1200 first streams; this is not a whole-disc absence claim.

### Differential checks, build and test package

Every script runs once per recorded version. The following results are quoted from the retained human/AI reports and complete raw tables:

- Weighted helper:314 successful cases,249 from83 real packets with three declared matrices and65 synthetic boundaries. C++ matches2567 record rows and13,326,784 complete scratch bytes, all metadata and every untouched byte. All160 helper words are covered by94,662 original instruction steps. Separate arithmetic crosscheck:82,144 lane rows/57,802 distinct CRT operand cases, zero differences.
- Complete streams:309 cases,300 from100 real streams with the same three declared matrices and9 synthetic streams. C++ matches5,062,656 complete scratch bytes,9507 final slot rows and all end/state/GQR1 metadata. The independent interpreter follows original BL/LR/SP/stack descriptors and explicitly bound globals through257,538 instruction steps and470 helper calls. A separate245,856 lane-row/160,219 distinct operand CRT crosscheck has zero differences.352 original words are verified;345 execute in successful cases, with the remaining7 confined to the unsupported2A arm. That arm is separately stopped at its original BL after OR2, never fabricated.
- All65,536 signed weights pass through the actual C++ weighted API in8 batches, checking393,216 stored float words and2,097,408 complete scratch bytes.
- Weighted host fixtures:12 preservation and17 rejection cases pass. Stream fixtures:6 preservation and6 rejection cases pass. They cover repeated destinations, variants1/2/127/129 masking, signed/zero weights, untouched tails, malformed bounds, unsupported2A, rounding, finite guards and unknown four-byte info overlap.
- Existing unweighted helpers/types and the independently validated weighted implementation are byte-identical prefixes beneath the new stream integration. No production correction was required after comparisons. Strict MSVC `/std:c++latest /O2 /fp:strict /W4 /WX` compilation passes. Full Windows x64 MSVC/Ninja Debug EDITOR ON compile and link passes; compile commands restrict strict FP to this existing source unit. The existing invocation-only Embedded debug workaround remains. Linux/EDITOR OFF and old gameplay were not rerun.

Matrices identity, signed nonuniform with translation, and non-diagonal are declared tests; initial scratch buffers and state/GQR1 are synthetic explicit inputs, not runtime captures. These are independent original-word semantic comparisons, not execution of the game on hardware or Dolphin.

The media-free `SA2-Weighted-Vertex-Check/Check-SA2-Weighted-Vertices.cmd` package reads the user's existing disc and writes a paired result. It tests calculations and dispatch; the separate Chao texture preview remains the available visual SA2 preview. No model display or playable SA2 level is claimed.

### Decisions, provenance and remaining work

Only `src/Importers/SA2/ModelVertexTransform.h/.cpp` change this pass: additive weighted result/API and complete-stream result/API. CMake, previous unweighted implementations, every existing importer/caller, SA/Shadow renderer/gameplay/main/pools/Lua and content remain unchanged;252 other guarded source/content files retain their hashes. No Lua prefab is added before animation, material and runtime bindings are established. All changes and limits are listed in ENGINE_CHANGES and architecture twins.

Preserved workflow failures do not change the original evidence: the first host harness failed `/WX` on an integer-to-uint8 initializer and was corrected to a typed array; sample lookahead v1 stopped on a bare-hex schema parse and v2 passed; dispatcher finalizer v1 lacked nonwriting compare classifiers and v2 passed; stream final auditor v1 passed math replay then stopped on ISO-offset metadata formatting and v2 passed. Evidence recheck v1 found two human-report digest fields computed over LF text before Windows CRLF output; the files match their sealed raw-byte manifests, and a paired adjudication records both identities before recheck v2. All failed versions and paired reports remain. Historical core source hashes refer to the preserved `core-validated` snapshots; the final stream candidate appends integration without changing those bodies.

Still unknown or unfinished:2A numerical behavior; live GQR0/FPSCR and aliases; matrix-stack initialization/math/ownership; animation/provider binding and skeleton traversal; original cache lifetime and cross-stream sharing; material/attribute/topology/FIFO binding and rendering; full ABI/ownership/indirect targets; level geometry/collision/objects, character physics, camera and Lua prefabs. Continue with those bounded questions from original evidence. Generated corpus counts are unchanged (60320 C plus2530 ASM for95 RELs;65146 canonical candidates plus one SDA alternative;21 unowned sites). Generated listings are not a fully understood or ported game.

Complete independent reports, source hashes, original words, native load/store/state/call traces, real sample records and failed versions are under the sibling weighted evidence directory linked below. All raw CSVs remain complete; all readable reports have compact companions.

Read-only provenance recheck v2: 250 path/digest identities, 683 recorded references and 41 unchanged ledgers; all four implementation-prefix checks pass. Original, frozen decompilation, primary semantic references and frozen language inputs retain their identities. Eight historical candidate references map to preserved core snapshots; the final stream source hashes match both the prepared and applied files. Exact LF/CRLF adjudication is limited to the two named report fields.

Evidence index: [weighted reports and complete raw tables](evidence/sa2-weighted-vertices-2026-10-17/README.md).
