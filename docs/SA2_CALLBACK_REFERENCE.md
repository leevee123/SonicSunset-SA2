# SA2 callback records, cleanup and default allocation

The original instructions support a stored callback pointer and a list-dispatch call that explicitly passes the current block in `r3`. They do not establish the candidate's gameplay purpose, complete calling convention or actual runtime invocation. The file `ChaoStgOdekake.prs` entry at decoded offset `0xE0` remains in the separate candidate view, outside the selected generated corpus. No project, engine, repository document or frozen helper was changed.

## Original pointer and constructor

The module is original REL ID 73, decoded SHA256 `0ab8fd024aee271d8911c5212c24d4c23f208647e624e72827c544d747ef830c`. Its section 1 offset field is `0xE1`: stored code begins at file `0xE0`, with the executable bit retained separately. `0x810000E0` is the synthetic analysis address; the retail module base is unknown.

The existing caller at decoded file `0x1204` constructs this exact pointer in `r5`. Original words `3CA00000` / `38A50000` at `0x1240` / `0x1244` have self HA16/LO16 records on halfwords `0x1242` / `0x1246`, both targeting ID 73, section 1, addend 0. At `0x1238` / `0x123C` it explicitly sets `r3=2`, `r4=3`. Its original `48000001` word at `0x1250` has a main REL24 record targeting retail `0x80071E0C`. The pointer therefore has exact original relocation provenance; the original placeholder branch is not a runtime self-call before linking. The string passed in `r6` is not used to assign a gameplay role.

In main `0x80071E0C` (DOL `0x6EE0C`), instructions `0x80071E28` / `E2C` / `E30` forward incoming `r4` / `r5` / `r6` to `r3` / `r4` / `r5`, then the original BL at `0x80071E34` (DOL `0x6EE34`) calls `0x80071D04`.

Main `0x80071D04` (DOL `0x6ED04`) saves incoming callback `r4` in `r30` at `0x80071D1C`, calls allocation helper `0x801197D0` with `0x50` at `0x80071D2C`, and checks its returned `r3` against zero. For a nonzero callback, exact word `93C30010` at `0x80071D48` (DOL `0x6ED48`) writes `r30` into the returned block's `+0x10` field. For a zero callback, `0x80071D50` / `D54` / `D58` instead construct and store fixed address `0x80071F58`; that address's role is not inferred here.

The constructor's original list operations at `0x80071DB0..0x80071DEC` use table `0x801FCEB8` indexed by the forwarded group argument. They initialize an empty list as a self-linked node or insert before the existing head through node `+0` / `+4`. The Odekake caller's group value is 3. This is mechanical list-registration evidence, not a gameplay classification. Allocation success and initialization/alignment remain unobserved. The constructor also copies the prior block `+0x44` value to `+0x48` before storing the passed label at `+0x44`; its prior contents are unknown and the quirk is retained.

For the observed flags value 2, the wrapper tests bit 2 at `0x80071E48`, calls `0x801197FC(1,0x30)` at `0x80071E5C`, and on success stores the returned value at block `+0x34` with exact word `907E0034` at `0x80071E78` (DOL `0x6EE78`). On failure it calls `0x80071AF0` with the constructed block and returns zero. The candidate prefix at decoded `0xF8` copies incoming `r3` to `r29`, then exact word `83FD0034` at `0xFC` loads `+0x34` from that block. This agrees with the static input path without supplying an invented struct type or allocator initialization policy.

## Original consumers of block +0x10

| Declared main function | Original load / DOL offset | Explicit input setup / DOL offset | Indirect call / DOL offset |
|---|---|---|---|
| `0x80071A40` | `0x80071A74` / `0x6EA74`: `819D0010`, load `r12` from current node `r29+0x10` | `0x80071A8C` / `0x6EA8C`: `387D0000`, set `r3=r29` | `0x80071A90` / `0x6EA90`: `4E800021`, `blrl` |
| `0x800708D8` | `0x80070908` / `0x6D908`: `819F0010`, load `r12` from current node `r31+0x10` | `0x80070920` / `0x6D920`: `387F0000`, set `r3=r31` | `0x80070924` / `0x6D924`: `4E800021`, `blrl` |

Both sites null-check the loaded pointer, place it into LR (`7D8803A6` at `0x80071A88` / `0x8007091C`), and use a linked LR branch. The original next-node pointer is saved before the call. `0x80071A40` starts from the selected table slot; `0x800708D8` starts from its incoming block's child-list field `+0x0C`. Both subsequently invoke child traversal for a nonzero node `+0x0C`. The existing context-free and startup-SDA C views agree on this traversal; the raw instructions decide the input register and branch behavior.

Both dispatchers store the callback to `[r13-0x7878]` before calling and clear that location afterwards. Its absolute address is `0x803ADA48` only under the separate startup-SDA assumption `r13=0x803B52C0`; current runtime register state has not been observed. There is no inferred global name or gameplay meaning.

The original driver `0x80071214` (DOL `0x6E214`) sets its saved index to zero, forwards the index in `r3` at `0x80071228`, calls `0x80071A40` at `0x8007122C`, increments it and loops while less than 6. Thus its static group sequence includes the observed group 3. Frequency and actual execution remain unknown. The other recorded direct caller is `0x8001E89C`, callsite `0x8001E968` (DOL `0x1B968`), with group 0; its later unrelated object's `+0x10` is not treated as the constructor's returned block.

If successful construction/linking occurs and the registered node's `+0x10` still holds the candidate pointer, this list-dispatch path would call the candidate with that same node in `r3`. This is a conditional static path, not an observed execution.

## Return-register limit and callback replacement

The bounded original-word audit follows both conditional successors from each call's continuation and stops at the first explicit GPR3 overwrite, return, unsupported instruction or further call. Condition-code values are not emulated. The two dispatcher audits visit 25 / 31 words respectively and encounter no explicit GPR3 read before overwrite or return. Overwrites occur at `0x80071AA4` / `0x80071A8C` and `0x8007093C` / `0x80070920`; returns at `0x80071ADC` / `0x80070988` can retain an unread physical `r3` value. The driver audit after `0x8007122C` visits 9 words with the same no-read result and a possible unread `r3` at its return. The group-0 caller overwrites `r3` at `0x8001E970` after 2 visited words.

Therefore these inspected dispatch paths do not explicitly branch on, store or otherwise read a GPR3 callback result. A live physical register at return is not proof of a `void` callback or a complete return ABI. Other register/FP outputs, transitive callers, indirect users and callback side effects remain outside this bounded proof. The minimum proven call input is the current block in `r3`; a complete prototype is unknown.

The original helper `0x80071AE0` (DOL `0x6EAE0`) constructs address `0x80071AF0` and writes it to the incoming block's `+0x10` with `90030010` at `0x80071AE8`. It only replaces that pointer in this four-instruction body. The candidate prefix has an original main REL24 record at decoded `0x11C` to this helper, which agrees with its generated null-condition path. The broader cleanup routine has a zero store to `+0x10` at `0x80071B30`; its complete cleanup behavior and generated-C anomalies are not resolved by this pointer audit. No unconditional execution or task role is claimed.

## Validation, artifacts and remaining unknowns

`audit_odekake_pointer_abi_v1.py` ran once: **519 original DOL words in 8 existing function bodies; all 8 initialized DOL segment hashes verified; all 31 source-input hashes unchanged; all four bounded GPR3 path audits complete with no explicit read before overwrite/return**. `review_odekake_pointer_abi_v1.py` ran once: **4 selected import/relocation records verified directly from the original decoded REL streams; original module unchanged**. The original DOL SHA256 is `a53335308d1f820be236fd2b6342fee850eaf048eb26aac21ddb1903b060db2e`. Installed open-source Ghidra SLEIGH definitions support the audited branch/load/store encodings; they are tool source, not original game source. No leaked original source was encountered.

The compact twin is `docs/ai/SA2_CALLBACK.md`. Complete original words and offsets, register-use paths, selected windows, original relocation/import bytes, direct edges and encoding-source excerpts are retained in the `pointer-abi-*.csv` files. The reports `pointer-abi-evidence.md/.ai.json` and `original-relocation-review.md/.ai.json` retain the complete per-function/source hashes and validation details. Earlier broad textual matches remain raw search candidates and are not asserted to consume this particular block.

Remaining unknowns are the candidate's gameplay purpose, complete argument and return ABI, runtime module base/lifetime, actual link/allocation/list invocation, allocator initial contents/alignment, any additional indirect consumers, and full candidate behavior including unresolved foreign imports and exact FP behavior. Existing generated body boundaries are inherited evidence, not newly proved boundaries. The separate candidate stays outside the selected corpus. This callback audit adds evidence only. The separate stored REL reader and its three engine changes are recorded in ENGINE_CHANGES.md; no callback/gameplay implementation is added here.


Repository evidence is retained as `docs/evidence/sa2-callback-pointer-abi-*.csv`, `sa2-callback-pointer-abi-evidence.ai.json`, and `sa2-callback-original-relocation-review.ai.json`; the originating scratch reports and manifest remain unchanged.

## 2026-10-13 continuation: original cleanup and default allocator

The following cleanup audit reads both existing C views first and uses original words/retained assembly where C drops register inputs. Its default allocator is separately traced below. All findings are static; the existing Odekake body remains an unselected hypothesis. The original DOL and frozen exports are unchanged.

## Cleanup order and exact updates

1. Save incoming `r3` as node `r30` at `0x80071B04`. Read node `+0x18` into `r0` at `0x80071B0C`, store it at `[r13-0x7878]` at `0x80071B10`, then read node `+0x18` again into `r12` at `0x80071B14`. If that second value is nonzero, `0x80071B20` moves it to LR, `0x80071B24` explicitly sets `r3=node`, and `0x80071B28` (DOL `0x6EB28`, word `4E800021`) invokes it with `blrl`. There is no incoming-node NULL guard in this function. The callback is invoked before the following field clears and before snapshotting the list links.
2. Set `r0=0` at `0x80071B2C`. Stores at `0x80071B30..0x80071B4C` clear the eight 32-bit node fields `+0x10`, `+0x14`, `+0x18`, `+0x1C`, `+0x20`, `+0x24`, `+0x28`, `+0x2C`, in that order. The types of all eight fields are not assumed to be callbacks. Load child head from node `+0x0C` into `r5` at `0x80071B50`, next from node `+0` into `r31` at `0x80071B54`, and previous from node `+4` into `r29` at `0x80071B5C`. These snapshots occur after the entry callback; its effects are not guessed.
3. For a nonzero saved child head, retain the original comparison of node `+0x10` with address `0x8007098C` at `0x80071B68..0x80071B74`. Its special arm retests the same saved child register at `0x80071B78`; a zero value would install `0x80071AF0` into node `+0x10` at `0x80071B88`. The other arm repeatedly reloads the current child head into `r3` at `0x80071B98`, checks it against zero, and branches back to the original recursive BL at `0x80071B94` (DOL `0x6EB94`) when nonzero. Thus the omitted C argument is the current `node+0x0C` pointer, not the parent node or an invented value. After each child call the head is reread. Invalid links or a cleanup callback that fails to remove a child can prevent termination; no new guard or repair is inferred.
4. Unlink through the saved neighbor pointers: `0x80071BA4` writes `previous` to `next+4`; `0x80071BA8` writes `next` to `previous+0`. These pointers are not NULL-checked here. Load parent from node `+8` at `0x80071BAC`. If parent is nonzero and `parent+0x0C` equals this node, set that head to zero when `next==node` (`0x80071BCC..0x80071BD0`), otherwise to saved next (`0x80071BD8`). If the parent's head is another pointer, leave it unchanged. Parent-linked nodes do not take the global-table scan.
5. For a zero parent, replace saved next with zero when `next==node` at `0x80071BE0..0x80071BE8`. Then inspect up to **eight** 32-bit head slots starting at `0x801FCEB8`, using CTR=8 (`0x80071BEC..0x80071C2C`). On the first head equal to this node, store the saved next-or-zero in that slot at `0x80071C1C`, then stop scanning. If none matches, no table slot is written. Do not replace all matching slots, invent a group index or change the original bound.
6. Process nonzero allocation-pointer fields in original order: `+0x34`, `+0x3C`, `+0x38`, `+0x40`. The exact release calls and source registers appear below. For `+0x34`, if its pointee's `+0x2C` is nonzero, first call `0x800067F8(node)` at `0x80071C4C`; then **reload** node `+0x34` at `0x80071C50` for the release call. Each outer field is cleared after its release wrapper returns. No release is substituted for a zero outer field.
7. Load node `+0x30` into `r4` at `0x80071CA8`. If nonzero, load its signed halfword `+2` at `0x80071CB4`, use the exact `rlwinm` word `5463003C` at `0x80071CBC`, store the low halfword at `0x80071CC0`, and clear node `+0x30` at `0x80071CC4`. The stored result is precisely the original halfword with bit 0 cleared. There is no release-wrapper call for this `+0x30` pointer in the function; its object/flag meaning is unknown.
8. Set `r31=0`, clear node `+0x0C`, `+8`, `+4`, `+0` at `0x80071CCC` / `CD4` / `CD8` / `CDC`, and explicitly set `r3=node` at `0x80071CD0`. Call release wrapper `0x80119828` at `0x80071CE0` (DOL `0x6ECE0`), then clear `[r13-0x7878]` at `0x80071CE4`. There is no subsequent node-memory access in this body. There is no explicit current-callback-global clear immediately after the entry `+0x18` callback; called helpers/recursive calls may change that location, and its prior value is not explicitly restored here.

| Released argument | Original `r3` definition | Call to `0x80119828` / DOL offset | Field clear |
|---|---|---|---|
| Current node `+0x34` value, reread after nested cleanup | `0x80071C50`, `807E0034` | `0x80071C54` / `0x6EC54` | node `+0x34` at `0x80071C5C` |
| Node `+0x3C` value | `0x80071C60`, `807E003C` | `0x80071C6C` / `0x6EC6C` | node `+0x3C` at `0x80071C74` |
| Node `+0x38` value | `0x80071C78`, `807E0038` | `0x80071C84` / `0x6EC84` | node `+0x38` at `0x80071C8C` |
| Node `+0x40` value | `0x80071C90`, `807E0040` | `0x80071C9C` / `0x6EC9C` | node `+0x40` at `0x80071CA4` |
| Node itself | `0x80071CD0`, `7FC3F378` | `0x80071CE0` / `0x6ECE0` | node link fields already zero |

“Released” here identifies the pointer passed to the release wrapper. Actual reclamation, ownership, callback side effects and allocator policy are not established by this wrapper.

## Three bounded helpers

`0x800067F8` (DOL `0x37F8`) checks the incoming node, node `+0x34` and work `+0x2C` for zero. Save the latter pointer in `r31` at `0x80006828`. Load its unsigned halfword `+4` at `0x80006830`; exact word `54000421` at `0x80006834` selects bit `0x8000`. If that bit and nested pointer `+0x0C` are nonzero, load the nested pointer into `r3` at `0x8000683C`, call `0x80119828` at `0x80006848` (DOL `0x3848`), then clear nested object `+0x0C` at `0x80006850`. Regardless of whether that optional inner release occurred, set `r3` to the saved work `+0x2C` object at `0x80006854`, call `0x80119828` at `0x80006858` (DOL `0x3858`), **reload** node `+0x34` at `0x8000685C`, and clear its `+0x2C` at `0x80006864`. The flag's game meaning and ownership are unknown; omitted C arguments are recovered from the original register flow.

`0x80119828` (DOL `0x116828`) loads a table pointer from `[r13-0x71B8]` into `r4` at `0x80119834`, loads callback `table+4` into `r12` at `0x80119838`, moves it to LR at `0x8011983C`, and unconditionally invokes `blrl` at `0x80119840` (DOL `0x116840`). **Incoming `r3` is not overwritten before the call**, so it reaches that indirect callback unchanged. There is no table/target NULL guard here. Generated `void FUN_80119828(void)` and argumentless calls omit this register input and are not a proven complete prototype. The default backend is bounded in the following section; actual runtime selection, complete ABI and ownership remain unknown.

`0x8007098C` (DOL `0x6D98C`) preserves its incoming node in `r31`. If node `+0x10` equals address `0x8007098C`, it writes `0x80071AF0` to node `+0x10` at `0x800709C8` only when node `+0x0C` is zero; for a nonzero child head it returns without that write. For a different `+0x10` value it repeatedly loads the current child head into `r3` at `0x800709D8`, tests it, and calls `0x80071AF0(child)` at `0x800709D4` (DOL `0x6D9D4`) while nonzero. It performs no own-node unlink or release-wrapper call in this body. This establishes the pointer mechanics without naming a gameplay purpose.

The absolute current-callback location `0x803ADA48` and allocation-table-pointer location `0x803AE108` apply only under the existing separate startup-SDA assumption `r13=0x803B52C0`. Context-free instructions retain their relative displacements. Runtime register context and callback targets are unobserved.

## Retained quirks and body gaps

The main cleanup's node `+0x10` has already been zeroed at `0x80071B30` when it is reloaded at `0x80071B68`. The bounded interval has no intervening call, no write to node register `r30`, and only the eight distinct field-zero stores. Under sequential execution without external/asynchronous mutation, comparison with nonzero `0x8007098C` therefore cannot be equal. Furthermore, the special branch retests unchanged saved `r5`, whose nonzero value was required to enter that region, so its zero arm cannot execute from ordinary entry. These are original instruction facts. The original comparisons, special-arm pointer store and reason for their presence remain recorded; they are not removed or “fixed.”

Both exports omit one four-byte gap from each relevant declared body: at `0x80071B90` (DOL `0x6EB90`) raw word `48000008` branches to `0x80071B98`; at `0x800709D0` (DOL `0x6D9D0`) the same raw word branches to `0x800709D8`. Neither is reached from the declared entry in the retained structural graph. Their original bytes are retained separately; this audit does not seed them, redefine body ownership or rule out unknown incoming transfers.

## Validation and remaining unknowns

`audit_callback_cleanup_v1.py` ran once: **all 519 prior original-word rows reverified; 205 original words across four bounded raw spans; 230 control-flow edges; 12 callsites; zero unsupported data instructions; 132 cleanup and 11 release-wrapper retained-ASM rows byte/offset matched**. Raw spans contain 133 / 27 / 34 / 11 words respectively for cleanup / child helper / nested helper / release wrapper; the two gap words remain outside declared ownership. Primary and startup-SDA body ranges match for these four entries. The explicit GPR3 reaching definitions recover the missing child and release arguments, while treating call results as unknown.

`review_callback_cleanup_v1.py` ran once: **all 12 original callsites match each exported graph, 24 matches total; clear-before-compare and unchanged-saved-child intervals checked; all 65,536 signed-halfword inputs match the exact low-16-bit `input & 0xFFFE` result**. Complete result digest and source hashes are retained. All previous and current source hashes remain unchanged. These checks validate original words, graph metadata and bounded integer/register effects; they do not execute the game or emulate unknown callbacks.

Complete original words, DOL/ISO offsets, fields, control edges, callsite inputs, retained-ASM matches and exported graph matches are in the raw CSV files. `cleanup.ai.json` is the compact twin; `word-graph-audit.md/.ai.json` and `graph-quirk-review.md/.ai.json` retain validation and source hashes. No leaked original source was encountered.

Unknowns: gameplay identity; complete callback/return ABI and actual execution; valid input/list invariants and termination for mutated/invalid lists; runtime backend selection and ownership policy; runtime SDA state; concurrency/reentrancy and callback mutations; meanings of `+0x30` / nested flags / other cleared fields; unknown incoming transfers into gap/special-arm instructions. This cleanup-only audit stops at the release callback boundary; the following default-backend audit extends that boundary. No alias closure, candidate selection, behavior port or full-game completion is claimed. No callback scheduler or Lua behavior implementation is added; this pass's separate importer changes are listed in ENGINE_CHANGES.md.

## Original default allocation/release path

Initializer `0x8011979C` / DOL `0x11679C` installs the original table at VA `0x801770A0` / DOL `0x1740A0`; slots `+0/+4/+8` point to `0x8011989C`, `0x801198C4`, `0x801198EC`. Dispatch wrappers `0x801197D0`, `0x801197FC`, `0x80119828` preserve actual size/count/pointer inputs in original registers. Allocation results remain in `r3`. Their generated argumentless/void prototypes do not establish the complete ABI. This identifies an original default table, not its actual runtime use or an absence of overrides.

Default size allocation reaches `0x800E4554` / DOL `0xE1554`, returns cell `+0x20` or zero and **does not clear user payload**. The two-argument default uses the low 32 bits of count times size, calls that allocator, then byte-fill `0x80119778 → 0x8000532C → 0x8000535C` with **no NULL-result branch between allocation and fill**, and returns the saved allocation result. The multiplication overflow and missing NULL branch are retained; a hardware/invalid-pointer outcome is not guessed.

Required cell bytes are `(size + 0x3F) & ~0x1F`, with a `0x20` header. A `0x50` record request has minimum payload capacity **96 bytes** and a flags-2 `(1,0x30)` work request has minimum **64 bytes**. A remainder below `0x40` takes the entire free cell, so these are minima, not exact usable capacities. Only the requested product is cleared by the two-argument path; unsplit/alignment slack remains uncleared. Additional request arithmetic is preserved in the CSV: `(2,0x1C)` clears 56 bytes with minimum capacity 64; `(1,0x40)` clears 64 with minimum 64; `(1,0x10)` clears 16 with minimum 32. These are arithmetic checks, not live-heap observations. Heap creation can return `-1`, stored by its initializer without a local success guard.

Consequently the record constructor `0x80071D04` cannot assume fresh zero payload. It copies the existing record `+0x44` into `+0x48` before putting its incoming third value into `+0x44`. The flags-2 work request clears exactly 48 requested bytes on this default path. No extra zeroing is added to a future port. Explicit constructor stores are retained in the compact/raw evidence.

Release dispatch `0x80119828 → 0x801198C4 → 0x800E4650` / DOL `0xE1650` subtracts `0x20` from the pointer to recover its cell, then uses `0x800E44A8` / DOL `0xE14A8` to insert and coalesce free cells. The inspected backend **does not wipe payload**; record cleanup does not write `+0x44/+0x48`. Callback/destructor mutations, invalid inputs, ownership and full lifecycle remain unknown. This is the conservative distinction between now-known default behavior and unobserved runtime choice.

The corrected V2 word auditor ran once and verifies **18 bounded functions / 626 original words**, the three table pointers, argument-copy origins, saved result, constructor store order, allocation arithmetic and release sites. V1's overly strict direct-register assumption failed and remains preserved; V2 follows parameter-copy origins. No live heap fixture, native runtime or analysis project was executed. Complete original coordinates/source hashes/calls/stores/arithmetic are `docs/evidence/sa2-callback-default-v2-*.csv`, `sa2-callback-default-allocator-table.csv`, and their paired reports.

The complete bounded function coordinate table follows; ISO offsets are computed by the staging script from canonical DOL offsets and the verified `0x1E700` carrier placement. These entries were not re-decompiled or promoted to reviewed whole-game functions.

| Function VA | DOL offset | ISO offset | Original words |
|---|---|---|---|
| `0x8011979c` | `0x11679c` | `0x134e9c` | 13 |
| `0x801197d0` | `0x1167d0` | `0x134ed0` | 11 |
| `0x801197fc` | `0x1167fc` | `0x134efc` | 11 |
| `0x80119828` | `0x116828` | `0x134f28` | 11 |
| `0x8011989c` | `0x11689c` | `0x134f9c` | 10 |
| `0x801198c4` | `0x1168c4` | `0x134fc4` | 10 |
| `0x801198ec` | `0x1168ec` | `0x134fec` | 22 |
| `0x80119778` | `0x116778` | `0x134e78` | 9 |
| `0x8000532c` | `0x232c` | `0x20a2c` | 12 |
| `0x8000535c` | `0x235c` | `0x20a5c` | 49 |
| `0x800e4554` | `0xe1554` | `0xffc54` | 63 |
| `0x800e4650` | `0xe1650` | `0xffd50` | 31 |
| `0x800e44a8` | `0xe14a8` | `0xffba8` | 43 |
| `0x800e473c` | `0xe173c` | `0xffe3c` | 27 |
| `0x80071d04` | `0x6ed04` | `0x8d404` | 66 |
| `0x80071e0c` | `0x6ee0c` | `0x8d50c` | 72 |
| `0x80071af0` | `0x6eaf0` | `0x8d1f0` | 132 |
| `0x800067f8` | `0x37f8` | `0x21ef8` | 34 |

Cleanup raw evidence is `docs/evidence/sa2-callback-cleanup-*.csv` with paired cleanup/word-graph/quirk reports. The compact twin retains current truth; raw early reports retain their earlier boundary-only unknowns. Full callback purpose/ABI, runtime table/heap/list invariants, concurrency/reentrancy, field meanings and unknown gap transfers remain unresolved. No leaked original source was used.
