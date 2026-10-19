# GQR0 in the original main executable

The original startup path writes literal zero to GQR0. A separate global register snapshot saves and later restores GQR0 through a memory word. These facts narrow the previous unknown; they do not prove the register's live value at gameplay drawing calls. This audit changes no engine/repository/original/frozen/database/language file and observes no native execution.

## Bounded scan and source identity

One once-only scan covers all **376,848 aligned words in the two original DOL text sections**. Original DOL SHA-256 `a53335308d1f820be236fd2b6342fee850eaf048eb26aac21ddb1903b060db2e` matches real ISO bytes at header-selected DOL offset0x1E700. Exact GQR0 accesses are **two writes and one read**; all GQR0..7 accesses total72. No candidate with reserved bit0 set was accepted. The selector was validated against the immutable local Gekko SLEIGH definitions: primary opcode31; extended opcode339 for `mfspr`,467 for `mtspr`; bit0=0; SPR bits rearranged from their encoded halves. All1,024 SPR selector cases and GQR0..7 table labels were checked. Primary existing pinned Dolphin `Gekko.pinned.h` identifies GQR0 as SPR912/0x390. These are instruction/reference validations, not game-source substitutions.

Complete evidence: `original-text-segments.csv`, `all-GQR-accesses.csv`, `GQR-access-owners.csv`, `instruction-definition-lines.csv`, `SPR-selector-domain.csv` and source SHA guards. Both frozen views were used: context-free `main` and startup-SDA `main-sda-v1`. Generated C was read first; original words resolve the omitted architectural effects. The bounded selection retained704 original words,1,180 exported ASM rows matched original bytes,56 graph-reference rows, and66 distinct source files. Source-scope counts overlap earlier audits and do not add whole-corpus coverage.

| Original instruction VA | DOL file offset | ISO offset | Original word | Bounded decode |
|---|---|---|---|---|
| 0x80003144 | 0x144 | 0x1e844 | 0x480001ed | bl 80003330 |
| 0x80003340 | 0x340 | 0x1ea40 | 0x480e09f9 | bl 800e3d38 |
| 0x800e3d58 | 0xe0d58 | 0xff458 | 0x38600000 | addi r3,zero,0 |
| 0x800e3d5c | 0xe0d5c | 0xff45c | 0x7c70e3a6 | mtspr r3,SPR912 |
| 0x8010a788 | 0x107788 | 0x125e88 | 0x7e90e2a6 | mfspr r20,SPR912 |
| 0x8010a86c | 0x10786c | 0x125f6c | 0x3c40802d | addis r2,zero,-32723 |
| 0x8010a870 | 0x107870 | 0x125f70 | 0x60426aa8 | ori r2,r2,27304 |
| 0x8010a8a8 | 0x1078a8 | 0x125fa8 | 0xba8202fc | lmw r20..r31,764(r2) |
| 0x8010a8ac | 0x1078ac | 0x125fac | 0x7e90e3a6 | mtspr r20,SPR912 |
| 0x8010a7b8 | 0x1077b8 | 0x125eb8 | 0xbe8202fc | stmw r20..r31,764(r2) |

## Startup zero write

DOL entry80003140 calls80003330 at80003144; that helper calls800E3D38 at80003340. At800E3D58 the original executes `li r3,0`, immediately followed at800E3D5C by `mtspr GQR0,r3`. No branch or call intervenes. This is an unconditional zero write once that path reaches the instruction; the generated C for800E3D38 omits the SPR write and only exposes return0. Earlier calls in that helper modify other hardware state; they do not change the immediate literal feeding this write.

Under the pinned primary register definition, zero decodes as store type0/scale0 and load type0/scale0, with type0 named `QUANTIZE_FLOAT`. This describes a declared GQR0=0 contract. It is not evidence that a later draw instruction observed zero, nor exact floating-point equivalence of a port. Existing FPSCR RN/NI/VE uncertainty and frozen SLEIGH quantization limitations remain separate.

## Global snapshot read and restore

Function8010A6B4 constructs r2=802D6AA8 in its first two original instructions. At8010A788 it reads GQR0 into r20, then reads GQR1..7 into the following registers. At8010A7B8 `stmw r20..r31,0x2FC(r2)` stores GQR0's captured word at **802D6DA4**. This original global snapshot covers more than GQRs. C exposes the GQR0 capture as `DAT_802d6da4 = unaff_GQR0`.

Function8010A86C independently reconstructs the same r2 base. At8010A8A8 `lmw r20..r31,0x2FC(r2)` reloads the block; at8010A8AC it writes r20 to GQR0, followed by GQR1..7 restores. This writer is **memory-derived, not a zero initializer**. The nearby byte flags gate other SPR effects, but the GQR block load/write is on both local flag paths. C for8010A86C shows only two zero-byte stores and drops the architectural restores. The snapshot location is inside original DOL BSS and has **no original DOL/ISO file offset or sample bytes**. Analysis-view zeros or an initial BSS policy cannot establish its value at a later restore. Mutation, save/restore order and snapshot integrity remain unknown.

The absolute snapshot-base constructions are in the original instructions; they do not depend on the post-startup r2/r13 SDA assumption. These routines explicitly repurpose r2, so ordinary C calling-convention assumptions and generated void signatures cannot substitute for the original physical-register effects.

## Static callers, context paths and implicit uses

A complete main-text immediate-branch scan finds five exact-entry transfers in this selected path: entry→03330 at03144;03330→E3D38 at03340;80109838→A6B4 at80109964;8010A474→A6B4 at8010A4C0;80109B18→A86C at80109BA4. The latter owner has a return-from-interrupt path. These are original static transfers and source-context evidence, not observed interrupts or complete trigger/caller closure. Indirect calls, interior entry, other carriers and dynamically written/copied code remain outside the search.

Ordinary context owner800E563C explicitly captures GQR1..7 at800E5640..800E5670, into context words+1A8..+1C0. Restore owner800E56BC writes GQR1..7 at800E5714..800E5744. Neither has an explicit GQR0 SPR transfer in the complete main-text scan. Do not assign an unobserved purpose to the preceding context hole or infer a missing GQR0 load. Their C and complete original word selections are retained.

GQR0 is also consumed **implicitly** by paired quantized load/store instructions. The original FP-context functions800E5388 and800E54AC contain64 immediate paired instructions selecting index0:32 loads and32 stores, retained in `FP-context-implicit-GQR0-consumers.csv`. They are not `mfspr` reads and are therefore not included in the explicit three-access count. Generated C's `unaff_GQR0` expressions reflect that dependence. The global register snapshot path includes GQR0, while these ordinary context paths preserve/use it differently. No formal external ABI guarantee or live GQR0 invariant was established by this audit.

## Validation, selection limits and decisions

Quote from the passing bounded scan/value checks: **376,848 text words;72 GQR accesses;GQR0 two writes/one read;1,024 SPR selectors; startup write0; separate snapshot slot802D6DA4;live gameplay GQR0 not proven**. All source/original/mapping/reference hashes were reverified. `generic-context-original-words.csv` adds the ordinary context source words with both-view ownership; all original VA/DOL/ISO locations remain complete.

Inspection v1 stopped before completed output because it assumed every Ghidra direct-call graph row must have a native link bit1. Version2 retains native target and link separately. Four rows (two native sites represented in both views) are matching-target non-link transfers:80003250→8010B458 and8010A504→8010AA2C. This is a graph/classification distinction, not a mismatched original target. The failed v1 and paired failure report are preserved. Startup/global-restore functions were completed C-only and have no individual ASM exports, so original bytes were selected by matching body ranges. Oversized expanded FP C output was truncated; compact structural C selections and complete raw words remain available. No missing effect was filled in from a prototype.

Conservative integration decision: retain an explicit numerical GQR0 contract where needed, and keep raw-data ports as raw data. A path that demonstrably passes the startup write and subsequently preserves its snapshot without intervening mutation would conditionally preserve zero; the present audit does not establish those runtime premises. Do not set a blanket gameplay GQR0=0 assumption from this main-DOL-only scan or remove runtime FP/quantization unknowns.

Remaining unknowns: actual startup reach/execution; live register values at consumers; snapshot mutation/order/ownership; REL/apploader/copied/modified-code writes; asynchronous or external paths; complete ABI and indirect caller closure; FPSCR and exact paired/FMA/quantization semantics. No engine files changed, no projects/databases opened, no installed/frozen language modified, no native game executed, and no leaked original source encountered or used. No usage-limit tool response occurred in this bounded pass. All four team slots remained assigned to independent tasks, so source selection/value validation within this worker ran sequentially.
