# Original DOL callers of the apploader trailer loader

The bounded original DOL evidence establishes two routes to the trailer loader: a startup flag check and an exit from the game's outer loop. Both routes call **800E8F48 / DOL E5F48** with arguments `(0,0,0)`. Its mode-zero branch calls **800E8C40 / DOL E5C40**, the previously validated trailer load-and-transfer routine. This is a static control-flow reconstruction. No retail execution, successful disc read, hardware reset or trailer execution was observed.

`validate_callers_v3.py` was run once and passed: **44 unique source artifacts**, **2,231 exported ASM rows covering 1,694 unique addresses**, **39 independently parsed support words** and **52 selected control words** matched the original DOL and mapping. Each main view has one direct incoming edge to800E8C40. An independent scan of all **376,848 aligned words in both original DOL text sections** found the same exact-entry branch candidates as both exported graphs, through the selected caller scope. The 12 selected incoming edges include one edge into the third-tier boundary; the reverse graph itself was deliberately followed for three tiers. Raw counts, offsets, hashes and source paths remain in complete CSV files.

## Immediate dispatch and argument flow

The context-free and startup-SDA views agree on the immediate caller. At **800E90F8 / DOL E60F8**, original word `4BFFFB49` is a relative `bl 800E8C40`. There are no other aligned direct branch encodings to that exact entry in the scanned DOL text. Indirect calls, entry-interior transfers, REL code and copied code are outside that negative result.

800E8F48 saves incomingr3/r4/r5 to r26/r29/r30 at **800E8F58..800E8F60 / DOL E5F58..E5F60**. The test at **800E90A0 / DOL E60A0** compares the saved first argument with zero; the following branch skips the trailer path if it differs. The mode-one branch is selected separately at800E9074/E6074. Before the trailer call, **800E90F0/E60F0** copies the saved second argument tor3, and **800E90F4/E60F4** copies the third tor4. Every visible mode-zero direct call therefore suppliesr3=0,r4=0 to the loader. This narrows visible argument values; their full meanings and values from indirect callers remain unknown. Generated signatures disagree on the loader's arity, so no C prototype was treated as an original ABI declaration.

The dispatcher first calls800EBA84/E8A84 and800E4D30/E1D30. It walks a callback list atSDA-7618, calling node+0 with argument0 and following node+8; it repeats until every callback and800E9CB4/E6CB4 returns nonzero. After800E78AC/E48AC masks and writesMSR, it walks the same list with argument1, calls800E9CB4 and800E5074/E2074, and selects its mode branch. Mode zero additionally walks the list rooted at800000DC, calls800EC19C/E919C for objects whose halfword+2C8 equals1 or4, follows+2FC, and calls800EBAC4/E8AC4 before800E8C40. Callback registration, readiness meanings and object meanings were not reconstructed here. The startup-SDA view resolves the callback-list global to803ADCA8, subject to its explicit post-startupr13 assumption.

## Visible direct callers of the dispatcher

| Original caller / DOL entry | Original call site / DOL offset | Arguments to800E8F48 | Condition supported by original code |
|---|---|---|---|
|80003100 /100|8000312C /12C|0,0,0|Halfword800030E4 masked with0EEF equals0EEF.|
|800D3AD0 /D0AD0|800D3BF8 /D0BF8|0,0,0|Exit-state word atSDA-7714 equals1 after the outer loop and teardown calls.|
|800D3AD0 /D0AD0|800D3C14 /D0C14|1,0,0|That exit-state word equals3.|
|800D3AD0 /D0AD0|800D3C28 /D0C28|1,0,1|Other nonzero exit-state values.|
|800E2B78 /DFB78|800E2BC8 /DFBC8|1,0,0|Byte801CC17C differs from1 and80022D34/1FD34(0) returns nonzero.|
|800E30CC /E00CC|800E325C /E025C|1,0,0|The same byte/helper condition inside its active handling loop.|

The final two direct callers and the other two exit-state choices use mode one, which bypasses800E8C40. The selected upstream entries and all original branch words are recorded in `docs/evidence/sa2-boot-incoming-export-edges.csv` and `docs/evidence/sa2-boot-raw-branch-candidates.csv`; both views agree.

## Startup route

The real DOL entry is **80003140 / DOL140**. After startup and initialization calls, original instructions80003224..80003238/DOL224..238 read halfword800030E6. They call80003100 at **8000323C /DOL23C** when bit8000 is clear, or when the low7FFF bits equal1. 80003100 then reads halfword800030E4 at80003110/DOL110 and applies the0EEF predicate above. If both gates pass, it calls the mode-zero dispatcher before entry calls the outer loop at **8000324C /DOL24C**. The origins and observed values of those halfwords remain outside this audit; this is not a claim that ordinary retail startup takes the trailer path.

## Outer-loop route and a bounded original trigger

800D3AD0 repeatedly runs800D2DD4/CFDD4 and other per-iteration calls while the word atSDA-7714 is zero. Under the original startup pair at80003264/DOL264 (`lis`) and80003268/DOL268 (`ori`), r13=803B52C0 and that word is **803ADBAC**. At **800D3B30..800D3B48 /DOL D0B30..D0B48**, a return value1 from800D2DD4 sets the word to1 only if it was zero. The iteration continues through its remaining calls before the test at800D3B8C..800D3B94/D0B8C..D0B94. When nonzero, the routine waits on byte801CC17C, performs its teardown calls and selects the dispatcher arguments in the table. A branch-to-self at800D3C2C/D0C2C follows if those calls return.

The generated-SDA C has explicit textual references to803ADBAC in only800D2DD4 and800D3AD0. This search is a reference-selection aid, not an exhaustive alias/writer proof.

In800D2DD4, the original26-entry internal dispatch table at **801CC258 /DOL1C9258** maps state0E to **800D3478 /DOL D0478**. This state calls **80019E44 /DOL16E44** at800D3480/D0480 and tests its returnedr3. The original negative branch excludes-2, then accepts values greater than or equal to-2; together these conditions select **-1 exactly**. That path calls80019D78/16D78,80022D68/1FD68,80072998/6F998,80116DF8/113DF8 and800D2C20/CFC20, then writes1 toSDA-7714 at **800D3518 /DOL D0518** and to byte801CC1C0. The ordinary outer-loop exit test can then lead to the mode-zero trailer path.

State0D's C loads the original ASCII literal **ADVERTISE at80175718 /DOL172718** through80019E70/16E70 and changes the state to0E. The literal bytes and original table entry were validated, but no meaning was assigned to callback return-1 or to a particular user action. Another route arises when800D2DD4's local result is-2: its final block calls800F17AC/EE7AC; nonzero makes it return1, which the outer loop can convert to exit-state1, whereas zero writes exit-state3 at800D3AA8/D0AA8 and selects the separate mode-one path. The causes and meanings of that local result and helper status need further reconstruction.

## Architectural effects missing from generated C

Original **80019E44/16E44** loads a pointer fromSDA-7ABC at80019E50/16E50, loads a code pointer atpointer+14, setsLR and executes`blrl` at80019E5C/16E5C. Under the startup-SDA assumption, the pointer global is803AD804. Its generated C prints `(*pcRam00000014)()` with a void signature; the original instructions establish a dynamic pointer and allow returnedr3 to pass through the epilogue. The runtime pointer, target and callback result meanings remain unknown.

The separate mode-one path calls **800E8E90/E5E90** with the second argument shifted left3. Raw original trampoline branches pass through800E8EB0/E5EB0,800E8ED0/E5ED0,800E8EF0/E5EF0 and800E8EFC/E5EFC to800E8E94/E5E94. That code writesHID0 after OR8;800E8EB4/E5EB4 waits using the unsigned low-timebase difference against1124;800E8ED4/E5ED4 writes **3 and then incomingr3 toCC003024** at800E8EE0/E5EE0 and800E8EE4/E5EE4, followed by a spin at800E8EF4/E5EF4. Generated C drops theHID0 write, turns the timebase loop into an infinite loop, and retains only the secondMMIO write. These facts support describing separate restart/control paths, but an exact original symbol name or hardware outcome was not inferred.

## Scope, decisions and remaining unknowns

The existing `SA2_DECOMPILATION_PROGRESS.md` (Original trailer load and architectural effects) remains the byte-validated proof of header reading, trailer destination81300000, real disc payload andLR transfer. This caller audit narrows how that path is selected. It does not prove its successful execution or retailFPSCR state.

The conservative decision is to preserve neutral numeric modes and original state predicates instead of naming unverified SDK functions or user-facing events. No engine or repository changes, Ghidra project opens, function repairs, frozen-helper changes, repo-tool runs or installed/global settings changes were made. Only isolated language parsing and private scratch evidence were used. No leaked source was encountered or used.

Unknowns remain: callback targets/result meanings, indirect or aliased callers/writers, entry-interior/REL/copied-code closure, flags' origins and actual values, readiness/hardware results, full argument meanings, successful trailer I/O/transfer, exact runtime state andFPSCR controls. Failed selection/validation assumptions are preserved and explained in the preparation twin; each Python version was run once.

Evidence: `docs/evidence/sa2-boot-verified-source-artifacts.csv`, `docs/evidence/sa2-boot-verified-export-original-words.csv`, `docs/evidence/sa2-boot-verified-control-words.csv`, `docs/evidence/sa2-boot-support-original-words.csv`, `docs/evidence/sa2-boot-incoming-export-edges.csv`, `docs/evidence/sa2-boot-all-selected-incoming-edges.csv`, `docs/evidence/sa2-boot-raw-branch-candidates.csv`, `docs/evidence/sa2-boot-original-dispatch-table.csv`, `docs/evidence/sa2-boot-original-state-14-path.csv`, `docs/evidence/sa2-boot-exit-state-source-references.csv`, `docs/evidence/sa2-boot-input-artifacts.csv`, `docs/evidence/sa2-boot-local-preparation-artifacts.csv`, `validation.md` and `validation.ai.json`. All virtual addresses and file offsets in the evidence are original DOL coordinates; analysis flow overrides are recorded without being treated as original bytes.

## 2026-10-16: bounded GQR0 startup and snapshot proof

The original startup helper80003330 is called at80003144 (DOL144/ISO1E844) and calls800E3D38 at80003340 (DOL340/ISO1EA40). Original800E3D58 (DOL E0D58/ISO FF458) loads literal0 into r3;800E3D5C (DOL E0D5C/ISO FF45C) writes it to GQR0/SPR912. Generated C omits this architectural write. It is an unconditional literal-zero write when that path reaches it; no later live gameplay value is established.

A complete376,848-word main-DOL text scan has exactly two explicit GQR0 writes and one read (72 explicit GQR0..7 accesses). Snapshot8010A6B4 constructs its own r2=802D6AA8, reads GQR0 at8010A788 (DOL107788/ISO125E88), then8010A7B8 stores it in802D6DA4. Restore8010A86C independently constructs that base;8010A8A8 (DOL1078A8/ISO125FA8) loads the saved word and8010A8AC (DOL1078AC/ISO125FAC) writes it to GQR0. This is a memory-derived restore, not a second zero initializer. Snapshot storage is BSS, with no original DOL/ISO file offset/bytes. These absolute base constructions do not depend on ordinary post-startup SDA assumptions. C drops the architectural restores.

Ordinary context owners800E563C/800E56BC explicitly save/restore GQR1..7 only; the scan makes no claim about the context hole's purpose. FP-context owners800E5388/800E54AC contain64 implicit GQR0 paired instructions (32 load/32 store), outside the explicit SPR-transfer count. Immediate transfers into snapshot routines and return-from-interrupt context are retained in complete raw CSV; no interrupt/runtime/caller closure is claimed. Main-only bounded absence excludes REL/apploader/copied/modified code and indirect/interior/external paths. Snapshot order/mutation/ownership, runtime values, actual startup execution, full ABI and FPSCR remain unknown.

All1,024 SPR selectors and local definition/primary register-reference matches pass;66 source files from this audit rehash unchanged. A graph-v1 link-bit assumption failed on matching non-link transfers; v2 preserves target and link classifications separately. No original/frozen/installed language/project/database changes or native execution. GQR0=0 is consequently an explicit contract for the new ModelVertexTransform CPU fragment, not a blanket gameplay assertion. Complete source offsets/hashes/words/reports: docs/evidence/sa2-gqr0-*; numerical contract: paired SA2_MODEL_DATA reference.
