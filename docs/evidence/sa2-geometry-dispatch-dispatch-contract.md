# Original geometry dispatch and raw attribute contract

This bounded pass establishes seven helper layouts and their dispatch conditions. It supplies a conservative raw-reader contract; it does not reproduce topology, floating-point calculations, GPU state or runtime cache binding. No engine/repository/original/frozen/project/language files changed, and no game code ran.

## Dispatch requires current state

The dispatcher is `0x8011ccf8` / DOL `0x119cf8` / ISO `0x1383f8`. It captures the raw low-byte opcode before optional header masking. When no group is pending and `0x803AE0E8 & 0x800` is set, the header used for flags becomes `(rawHeader & low 16(0x803AE0E4)) | low 16(0x803AE0E0)`. Its high byte is sign-extended and saved when a group begins. The draw branch uses bit 0x40 of this effective/saved high byte, live `0x803AE148 & 2`, and pending-group state. Those global names assume startup r13; runtime SDA/caller state is not newly proved.

A first geometry packet with zero pending and nonzero **logical32 shift of sign-extended info by 14** is saved and deferred before drawing. Negative info makes that pending expression differ from raw high 2 bits. Thus no helper can be selected from a raw header/info alone, and the following table only applies after the draw stage is reached.

For opcode 0x40, flag0x40 set selects D6A4; otherwise state mask 0x2 clear selects D594 and set selects FEF4, for either pending state. For opcodes 0x41/0x42, flag0x40 set selects D91C. With that flag clear, state mask 0x2 clear selects D7B4 on the current stream even after accumulation; state mask 0x2 set selects FFF4 when pending is zero and 20158 when pending is nonzero. Complete canonical sites and original words are retained.

## Raw layouts

| Helper | Raw opcodes | Halfwords per record | Following pair |
|---|---|---|---|
| `0x8011d594` | `0x40` | 1 + ((rawInfo>>14)&3) | not consumed as a pair; extra info skips opaque |
| `0x8011d6a4` | `0x40` | 1 + ((rawInfo>>14)&3) | not consumed as a pair; extra info skips opaque |
| `0x8011fef4` | `0x40` | 1 + ((rawInfo>>14)&3) | not consumed as a pair; extra info skips opaque |
| `0x8011d7b4` | `0x41|0x42` | 3 fixed; info skip bits discarded | two signed 16 loads and two sth; preserve raw bits |
| `0x8011fff4` | `0x41|0x42` | 3 + ((rawInfo>>14)&3) | two signed 16 loads and two sth; preserve raw bits |
| `0x8011d91c` | `0x41|0x42` | 3 + ((rawInfo>>14)&3) | two words skipped WITHOUT loads/emission; opaque |
| `0x80120158` | `0x41|0x42` | multiple streams mutated independently; excluded from single-stream reader | one pair from each stream; per-stream opcode0x42 format selector |

Each helper masks info low 14 to obtain its outer group count. Each group begins with a **signed 16** count prefix, made positive in 32-bit arithmetic if negative and passed low 16 to begin. Raw 0x8000 therefore means magnitude 32,768. Every helper calls begin with numeric command 0x98 and format 0 regardless of count sign. No sign-dependent topology or winding rule is inferred. These are native do-while loops without a pre-loop zero guard; rejecting zero group/prefix counts is a host safety policy.

Every single-stream record first loads a signed 16 scratch index, shifts it left 5 and adds the current scratch base. Preserve the raw index bits and signed interpretation; no capacity, valid range or safe dereference is established. D594/D6A4/D7B4/D91C load scalar words through lfs at scratch+0x00,+0x04,+0x08, then+0x0C,+0x10,+0x14. FEF4/FFF4/20158 load the first triple, then a raw lwz at scratch+0x18. That latter value is emitted with **stw**, despite float-looking generated call expressions. No color encoding or FP conversion is assigned by this audit.

D7B4 masks away info skip bits and uses a fixed three-halfword stride. FFF4 and D91C instead advance by `3 + ((rawInfo>>14)&3)`; D91C never loads or emits the following pair, so those words remain opaque under that path. D594/D6A4/FEF4 advance by `1 + skip`. Where D7B4/FFF4 use a pair, both halfwords are loaded signed and emitted as two sth stores, preserving their low 16 bits. They do not perform a coordinate conversion here.

20158 is a separate mutable pointer-array layout. It takes the group count and scratch index from stream 0, advances other streams past their count/index words, then emits a pair from each stream and mutates the saved pointers. Its per-stream format selectors come from recorded opcode0x42 tests. Single-stream decoding must exclude this path; the audit does not establish matching counts, concrete runtime groups or native array limits.

## Numeric attribute setup and original stores

Baseline setup `0x8011d2f4` / DOL `0x11a2f4` / ISO `0x1389f4` calls format helper `0x80100D44` with `(0,9,1,4,0)`, `(0,10,0,4,0)`, `(0,11,1,5,0)`. Each emitter resets descriptors through `0x80100CF8`, then enables numeric descriptor 9 and either 10 (six-scalar path) or 11 (packed-word path), each with value 1. Pair emitters also enable13;20158 enables 13+i for all collected streams. Exact per-handler tuples are in `handler-layout-contract.csv`; numeric identifiers are kept without inferring a complete SDK contract.

D7B4/FFF4 call the format helper with `(0,13,1,3,8)` for opcode0x41 and `(0,13,1,3,12)` for opcode0x42;20158 does this per collected stream. Those are original arguments, not a proved texture-coordinate unit or scaling rule. Descriptor/format helpers update the pointed state cache and dirty bits8/0x10. Begin `0x80101948` may flush other dirty-state helpers outside this bounded closure, so the dynamic GPU stream is not fully reconstructed.

Generated C makes `0x8011D1AC` look argument-free. Original `0x8011d1ac` / DOL `0x11a1ac` / ISO `0x1388ac` instead forwards incoming r3..r6, inserts r7=0 at 0x8011D1B8 and r8=0x7D at 0x8011D1BC, then calls 0x801011D8 at 0x8011D1C0. Dispatcher tuples are `(0,0,1,0x2A,0,0x7D)`, `(0,1,4,0x3C,0,0x7D)`, or `(i,1,i+4,0x3C,0,0x7D)` according to branch. No full register/FP return ABI is assigned.

Original local FIFO helpers restore the stores collapsed by C: every scalar-triple helper performs **stfs f1, stfs f2, stfs f3** in that order to 0xCC008000; D8E4/20128 perform **sth r3, sth r4**; FFD4/20138 perform **stw r3**. The empty finish helpers are original returns. Begin emits a command byte then a halfword count after its state work; C retained only the final overlapping store. `direct-FIFO-stores.csv` records all 44 directly identified static FIFO-store sites in this bounded set, including all 36 local-helper stores, the two begin stores, and six stores inside 011D8. These are source instruction sites, not a claim that all state-dependent GPU effects have been reconstructed.

## Minimal safe reader and verification

Require an explicit caller layout choice: IndexWithInfoSkips only for op40; IndexAndPair fixed3 or IndexAndPairWithInfoSkips only for op41/42. Preserve every count/index/pair/skip word and declared tail bytes. The pair under D91C stays opaque. Reject wrong opcode/mode combinations, zero low 14 group count, zero run prefix and truncated spans as documented host guards. Keep raw 0x8000 and magnitude 32,768. Do not infer actual dispatch, cache state, winding, UV conversion, scratch access or GPU behavior from this choice.

Original DOL SHA256 `a53335308d1f820be236fd2b6342fee850eaf048eb26aac21ddb1903b060db2e`. Validation result: 40 functions, 1,907 complete words, 1,868 retained ASM rows checked against original bytes/offsets, 44 FIFO sites, 65,536 exhaustive halfword cases, all 129 source guards unchanged. Canonical VA/DOL/ISO evidence is in the raw CSVs. Root owns independent real-sample reader validation; this audit did not rerun it.

Unknowns remain full GX/flush behavior, concrete runtime dispatch and grouped streams, scratch ownership/capacity, first-stream FP/GQR results, topology/winding, UV units/rasterization, cache binding/order and full ABI. No leaked original source was used.
