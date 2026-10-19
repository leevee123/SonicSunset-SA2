# SA2 Battle: Chao palette conversion

## Scope and status

The CPU path now also reproduces ChaoMain decoded offset `0x1F2E4`: it blends the 39 cached banks into 48 BE RGB565 words and exposes the three proven 16-color TLUT groups. All 2,112 reference cases match the original instruction interpreter under nearest-even rounding, NI=0 and VE=0. The retail floating-point configuration remains unverified. This helper is available to an explicit caller; live Chao rendering and gameplay remain unported.

Chao palette conversion now has a separate CPU resource path in the engine. It reproduces the original fixed 48-color BGRA bank, all four conversion branches, inverted alpha in mode 0 and the partial copy in mode 6. The existing GVP reader and GX texture decoder retain their APIs and behavior. All 49 retail palettes match independent Python output, including the 39 files named by the original initializer. Modes 0 and 2 are verified against original code and synthetic words; this disc has only mode 1 samples.

The user supplied a repository and a general porting request, with placeholder target and original-file fields. Continuing the documented palette unknown is the conservative next piece: port the proven conversion and blend math as CPU resources, record binding evidence and leave unresolved runtime behavior explicit. No Chao character, level or mechanic is introduced here, so no Lua prefab is needed. Playable SA2 remains unported.

## Executable identity and analysis limits

Evidence is NTSC-U GSNE8P revision 0. The main DOL SHA-256 is `a53335308d1f820be236fd2b6342fee850eaf048eb26aac21ddb1903b060db2e`. The PRS-decoded `ChaoMain.prs` is 4,408,160 bytes, module id 60, REL version 2, SHA-256 `8a92378c024fc18594e197571eda022b6b47acc052f66456fabeb8c0fffd549c`. Its executable section 1 starts at decoded file offset `0xE8` and occupies 366,736 bytes. Module offsets below refer to the **decompressed REL file**, not its PRS stream or the disc.

REA 6.3.0 cannot open this DOL or its PowerPC ELF representation. The already installed Ghidra headless fallback was used; no tool/configuration reinstall was required. To resolve imported calls, the scratch analysis maps Chao's stored sections at `0x81000000 + file offset` and its zero-storage section 6 at synthetic `0x81700000`. These are analysis addresses; the original runtime module/BSS addresses remain unknown. Main DOL sections retain their original addresses and bytes.

The retail linker rules below were used to apply 32,713 main/self relocations to a scratch analysis copy. All 335 remaining imports target module 61 (`ChaoMotionsD.rel`) and are ADDR32 data imports; no foreign code call is among those unresolved imports. The original module remains unchanged. The combined analysis input ELF SHA-256 is `3c248f6d77b4fd7ac0ce74d5a73d7d8ce14956ca761c7cbbba2ed33962c3a38d`. This partial mapping supports the functions inspected here, and does not establish a complete Chao program or runtime equivalence. The scratch linker implementation was not added to the engine.

## Original functions and tables

| ChaoMain decoded file offset | Synthetic analysis address | Observed behavior |
|---|---|---|
| `0x1FAF8` | `0x8101FAF8` | Allocate `0x2800` payload buffer, load 39 palettes, convert 48 colors each, free buffer, write mode state 6. |
| `0x1FCF4` | `0x8101FCF4` | Get shared file input buffer; load named uncompressed file; call the native GVPL reader. |
| `0x1FD60` | `0x8101FD60` | Expand a masked six-bit component: `(v & 63) << 2` OR `((v >> 4) & 3)`. |
| `0x1FD70` | `0x8101FD70` | Expand a masked five-bit component: `(v & 31) << 3` OR `((v >> 2) & 7)`. |
| `0x1FD80` | `0x8101FD80` | Expand a four-bit component by duplicating its low nibble. |
| `0x1FD90` | `0x8101FD90` | Return 0 if input bit 0 is set, otherwise 255. |
| `0x1FDA8` | `0x8101FDA8` | Forward assertion text to `0x800E5C70`, source label `al_palette.c`, line `0xAB`. |
| `0x1F1B8` | `0x8101F1B8` | Inspect byte at `*(*(object + 0x34) + 0x5C) + 0x80`; select texture group and assign three slots. |
| `0x1F230` | `0x8101F230` | Shared switch tail, not a standalone retail function: three calls to `0x801176FC`. |
| `0x1F284` | `0x8101F284` | Release the output pointer at `*(*(object+0x34)+0x670)`. |
| `0x1F2AC` | `0x8101F2AC` | Allocate `0x60` bytes and store the pointer at that same work field. |
| `0x1F2E4` | `0x8101F2E4` | Blend cache banks, pack 48 RGB565 words, cache-store the buffer, upload three TLUTs. |
| `0xA7410` | `0x810A7410` | Nineteen relocated targets for the blend switch; six supported type bytes. |
| `0xFB07C` | `0x810FB07C` | AL_BODY texture-list descriptor: pointer to `0xFA9C8`, count 143, entry stride 12. |
| `0xA7328` | `0x810A7328` | 39 BE pointer words to palette filenames; string offsets/path/disc offsets in the table CSV. |
| `0xA72E0` | `0x810A72E0` | Six rows of three BE texture entry indices. |
| `0xA73C4` | `0x810A73C4` | Nineteen BE relocated switch targets for type values 0 through 18. |

| Main DOL function | DOL file offset | Observed behavior |
|---|---|---|
| `0x8011773C` | `0x11473C` | GVPL reader: copy payload and four native BE header words into the caller's descriptor. |
| `0x801184B0` | `0x1154B0` | Return shared input buffer and capacity from r13 state. |
| `0x8011C3C0` | `0x1193C0` | Uncompressed file-to-buffer wrapper; returns 1/-1 and sets native error state. |
| `0x80005420` | `0x2420` | Forward/backward memory copy; third argument counts **bytes**. |
| `0x8000532C` / `0x8000535C` | `0x232C` / `0x235C` | Byte-fill wrapper/implementation; the linker passes zero for BSS initialization. |
| `0x800E5C70` / `0x800E34CC` | `0xE2C70` / `0xE04CC` | Print panic context/back-chain, then synchronize and enter a permanent loop. |
| `0x801176FC` | `0x1146FC` | Resolve current texture-list entry and forward its native object with the caller's slot. |
| `0x801176F4` | `0x1146F4` | Write the second argument to native object +8. |
| `0x80117734` | `0x114734` | Write the argument to r13-`0x721C`; its later consumer remains unknown. |

The GVPL reader had no caller found inside main.dol because Chao imports it from a compressed executable module. Chao relocation record `0x3F6298` patches section 1 offset `0x1FC5C`, decoded file offset `0x1FD44`, to call `0x8011773C`. This resolves that earlier search gap. Three palette-related import rows are retained in `evidence/sa2-chao-palette-imports.csv`.

Ghidra initially split internal switch labels into functions and added call-return flow overrides. The scratch analysis now removes those labels/overrides and assigns the contiguous binding and blend bodies. Both functions decompile completely. These are analysis corrections, not game patches. Assembly supplements the pseudocode where it loses fused floating-point order, CR unordered branch behavior, component assignments hidden in comma expressions, volatile FIFO writes or register-preserved wrapper arguments.

The blend spans 517 original four-byte words through return `0x1FAF4`. Ghidra lists 513 instructions because duplicate branches at `0x1F5F4`, `0x1F71C`, `0x1F7C8`, `0x1FA3C` follow unconditional branches to the same destinations. A script finds no incoming direct branch or relocated reference to those words. None executes in the reference corpus. The original words are retained in scratch evidence and remain unchanged.


## GVP conversion rules

The container layout remains documented in SA2_TEXTURE_REFERENCE.md. Header word at file +8, copied to descriptor +4, is the **Chao conversion mode**. Header words at +10/+12/+14 are not read by this initializer. All real samples have `(1, 0, 0, 48)`; the fourth word correlates with the payload's 48 words, but this caller always processes 48 colors regardless of that field. Its general meaning remains unknown.

The initializer writes B, G, R, A bytes in that order into a 192-byte bank, then advances by `0xC0` for the next file. Its bank base is section 6 BSS offset `0x38780`; it has no stored file bytes. The analysis base is `0x81738780`. Native REL linking zero-fills BSS through `0x8000532C`/`0x8000535C`; their pseudocode and the wrapper's preserved r4/r5 establish the zero byte/count arguments. Updates must retain existing bank bytes where the original does.

| Mode | Native input consumed | Output rule |
|---|---|---|
| 0 | First 48 BE u16 words | B=bits 0–4, G=5–9, R=10–14, expanded 5 bits; A=0 for bit 15 set, otherwise 255. |
| 1 | First 48 BE u16 words | RGB565: B=bits 0–4, G=5–10, R=11–15; A=255. |
| 2 | First 48 BE u16 words | B/G/R/A are successive low-to-high nibbles, each expanded by nibble replication. |
| 6 | First **48 bytes** | Copy exactly those bytes into the bank. Final **144 bytes remain unchanged**. |
| Other | No supported conversion | Original reports `ILLEGAL_COLOR_MODE`, dumps panic context/back-chain, then halts in a permanent loop. Host throws before changing the bank. |

Mode 0 is not the shared GX RGB5A3 rule. Mode 6's copy count is the original `0x30`, not a 48-color byte count. Neither quirk is corrected. Modes 0–2 ignore data beyond the first 96 bytes; mode 6 ignores bytes after the first 48. Unknown fields are retained by `GvpPalette` and do not change the fixed loop count. The initializer does not check the palette-loader return before conversion; the host instead rejects unsupported modes/truncated data before mutation, using the existing importer exception pattern.

## Texture slot evidence

At `0x1F1B8`, type values 2, 6, 9, 12, 15 and 18 select groups 0 through 5 respectively. All other values, including those above 18, return without assigning slots. The exact table is:

| Type byte | Texture entry indices | Slots assigned in order |
|---|---|---|
| 2 | 0, 1, 2 | `3 * argument2 + 0`, `+1`, `+2` |
| 6 | 3, 4, 5 | Same three-slot rule |
| 9 | 6, 7, 8 | Same three-slot rule |
| 12 | 9, 10, 11 | Same three-slot rule |
| 15 | 12, 13, 14 | Same three-slot rule |
| 18 | 15, 16, 17 | Same three-slot rule |

Native `0x801176FC` follows the current list pointer at r13-`0x7228`, its +`0x20` pointer, then that pointer's first word. It selects an entry with 12-byte stride, fetches entry +8, and writes the requested slot at that native object's +8. Python establishes that the table's 18 indices exactly match the 18 C4 entry ordinals in `al_body.prs`. The continuation below establishes the AL_BODY list on the inspected draw paths, argument2 from the object work byte +3, generated RGB565 words and contiguous 16-color groups. Allocation/reuse of that byte and the hardware TLUT region policy remain unknown. No automatic runtime binding or asset filenames are introduced in C++.

## Live palette blend and exact arithmetic

`0x1F2E4(object,data,slotBase)` reads type byte `data+0x80`, floats `data+0xA8/+0xAC/+0xB0/+0xC0`, and destination `*(*(object+0x34)+0x670)`. Gameplay names for the type and float fields are unknown; the API uses their offsets. Bank roles below describe arithmetic only.

| Type byte | Base bank | Shared bank | Positive/negative A8 banks | Positive/negative AC banks |
|---|---|---|---|---|
| 2 | 0 | Special route below | 7 / 6 | 5 / 4 |
| 6 | 9 | 10 | 14 / 13 | 12 / 11 |
| 9 | 15 | 16 | 20 / 19 | 18 / 17 |
| 12 | 21 | 22 | 26 / 25 | 24 / 23 |
| 15 | 27 | 28 | 32 / 31 | 30 / 29 |
| 18 | 33 | 34 | 38 / 37 | 36 / 35 |

Other byte values return without writing output or uploading TLUTs. Exact constants at decoded offsets `0x5FE5C/60/64/68` are binary32 1, 0, `9.999999974752427e-7`, -1; `0x5FE70` stores binary64 2^52 for integer-byte conversion. The evidence JSON retains their bytes. Zero A8/AC, including negative zero, becomes the positive epsilon. Values above 1/below -1 clamp to those bounds; negative values select the negative bank and become positive magnitudes x/y. NaN remains NaN. C0, called w below, clamps **only above 1**; negative and NaN values are retained.

Every ordinary operation below rounds to binary32, in the original order. `FMA(a,b,c)` means one fused multiply/add rounding. `nx=(1/(x+y))*x`, `ny=(1/(x+y))*y`; `sx=1-x`, `sy=1-y`, `sw=1-w`. For each BGRA byte of the selected banks, supported types other than 2 execute:

```text
yProduct = selectedY * y
yPart = FMA(shared, sy, yProduct)
xProduct = selectedX * x
xPart = FMA(shared, sx, xProduct)
weightedY = ny * yPart
mix = FMA(nx, xPart, weightedY)
weightedMix = mix * w
value = FMA(base, sw, weightedMix)
```

Type 2 uses q from B0. If q>=0, clamp above 1, use shared bank 3 and selected banks 7/6 and 5/4 for the same `mix`, then:

```text
weightedMix = mix * w
upper = FMA(bank2, sw, weightedMix)
weightedBank1 = bank1 * w
lower = FMA(bank0, sw, weightedBank1)
weightedUpper = upper * q
value = FMA(lower, 1-q, weightedUpper)
```

If q<0 or unordered, clamp only values below -1, multiply q by -1, then:

```text
weightedBank1 = bank1 * w
lower = FMA(bank0, sw, weightedBank1)
special = bank8 * q
value = FMA(lower, 1-q, special)
```

The original `ble` tests GT clear and `bge` tests LT clear; unordered comparisons take these branches. B0's `cror` route instead tests GT or EQ. This distinction preserves NaN behavior and cannot be replaced by a generic clamp. The initial C++ edge comparison exposed an incorrect NaN clamp; it was corrected against the raw branch predicates before the successful full comparisons.

All four components are computed. `fctiwz` truncates toward zero to signed 32-bit, then the code masks the low eight bits. Finite negative or >255 values **wrap**, without color clamping. Under VE=0, NaN and negative overflow yield `0x80000000` (low byte 0), positive overflow yields `0x7FFFFFFF` (low byte 255). The selector writes component 0 to blue, 1 to green, 2 to red and ignores component 3. Green is initialized; the decompiler's comma expressions obscured its assignment. Independent raw-word dispatch checks confirm all channels. Output word is `(R>>3)<<11 | (G>>2)<<5 | (B>>3)`, stored BE, always 48 words/96 bytes.

These numerical results use nearest-even rounding, gradual underflow (NI=0), disabled invalid-operation write suppression/traps (VE=0). `std::fma(float,float,float)` supplies single rounding; all its inputs here have binary32 precision. Official pinned Dolphin [floating instructions](https://github.com/dolphin-emu/dolphin/blob/e6f3ae17627e4344da95b13424af5baf4c892b08/Source/Core/Core/PowerPC/Interpreter/Interpreter_FloatingPoint.cpp) and [FP utilities](https://github.com/dolphin-emu/dolphin/blob/e6f3ae17627e4344da95b13424af5baf4c892b08/Source/Core/Core/PowerPC/Interpreter/Interpreter_FPUtils.h) support the instruction semantics; no GPL implementation was copied into engine code. Retail FPSCR state, NaN payloads, exception flags and enabled traps are not emulated or claimed. The CPU helper requires this rounding/underflow contract; no process-wide FP mode is changed.

## Upload, texture-list identity and lifetime

At blend tail `0x1FA88`, DOL `0x800E4E80(destination,0x60)` executes data-cache block stores in 32-byte steps and a syscall. Three iterations call `0x801039A0(temp,destination+i*0x20,1,0x10)`, then `0x801039E8(temp,3*slotBase+i)`. The temporary descriptor is at section-6 BSS +`0x3A4C0`, immediately after the 39-bank cache, not inside its final bank.

`0x801039A0` stores format in bits 10..11, encodes the source address shifted by 5 into a BP `0x64` word, and stores the u16 count at descriptor +8. Format 1 is RGB565. `0x801039E8` obtains the slot's region through the callback at GX state +`0x414`, then writes FIFO command byte `0x61` and the source/region words to `0xCC008000`, with `0x80104484` state writes on both sides. The decompiler hides repeated volatile stores; original assembly establishes their order. It combines region low ten bits into descriptor word 0 and copies three descriptor words to region +4/+8/+12. Pinned official [GX BP register definitions](https://github.com/dolphin-emu/dolphin/blob/e6f3ae17627e4344da95b13424af5baf4c892b08/Source/Core/VideoCommon/BPMemory.h) identify `0x64/0x65` as TLUT load registers and the format field. Callback selection/region allocation remain uninspected.

Startup helper DOL `0x80003254` establishes r13=`0x803B52C0` and r2=`0x803B6520`. Script arithmetic locates palette-mode state r13-`0x721C` at `0x803AE0A4`, texture state r13-`0x7228` at `0x803AE098`, GX pointer at `0x803AD640`, allocator table pointer at `0x803AE108`. Mode state's consumer remains unknown; `0x80357864` found in an earlier search is separate error state and is not assigned palette meaning.

Chao resource constructor `0x2884C` calls `0x28D38("AL_BODY",list@0xFB07C,0)` and then the palette initializer. `0x28D38` calls DOL `0x80072820` and records name/list pairs in a selected BSS registry. DOL `0x80072820` initializes a temporary texture descriptor, calls `0x80072458`, then copies fields +4/+8 from temporary 12-byte entries to the supplied list for its declared count. `0x80072458` uses the original format string `%s.PRS` (r2-`0x6FE0`), opens with up to three attempts, reads sector-rounded data with up to three attempts, closes, calls PRS decoder `0x800D2684`, then GVM loader `0x80118FC0`. Detailed I/O error/retry semantics remain unverified.

List `0xFB07C` points to 143 entries at decoded `0xFA9C8`; its entry fields are zero in the stored module before loading. Draw paths `0x89B4` and internal outer-switch case `0x8420` set this list through DOL `0x80116E18` before the three-entry palette binding. `0x8420` is a case label, not a standalone original function. `0x80116E18` writes its pointer to texture state +`0x20`. The 18 indices in the binding table now have a traced AL_BODY resource relationship, beyond their earlier numeric C4 match. C++ still receives palettes/resources explicitly.

Calls at `0x63A8`, `0x63CC` (owner `0x5FCC`) and `0x31A80` (owner `0x31A38`) pass object work byte +3 as slotBase. `0x1F2AC` requests exactly 96 bytes through `0x801197D0`, storing the result at work +`0x670`; setup `0x2679C` calls it before `0x5FCC` builds palettes. `0x1F284` frees that same pointer through `0x80119828`, called by cleanup `0x26584`. The two native wrappers dispatch through allocator-table entries +0/+4 and preserve r3, which their void pseudocode obscures. Allocator alignment/failure policy, initial buffer contents and allocation/reuse of the slot byte remain unknown. No slot ownership policy is invented.

## Engine API and decisions

Include `Importers/SA2/ChaoPalette.h`. Existing `ChaoPaletteBank`, `updateChaoPalette` and `chaoPaletteColors` retain their conversion behavior. New `ChaoPaletteParameters` exposes type and values named A8/AC/B0/C0; `ChaoPalette` owns the 96 BE RGB565 bytes. `buildChaoPalette(output,span-of-39-banks,parameters)` performs the evidenced arithmetic and returns false for unsupported type bytes without changing output. `chaoPaletteGroupColors(output,group)` returns exactly 16 RGBA colors for group 0/1/2 and rejects other groups. Feed that group explicitly into existing `decodeTexture` for the corresponding C4 entry. Array ownership replaces the native heap pointer; this is a data resource API, not a runtime object reconstruction.

Only `src/Importers/SA2/ChaoPalette.h/.cpp` change in this continuation. Both are listed in ENGINE_CHANGES.md and its compact twin. No asset names, slot allocator, content keys, renderer, scripting, physics, prefab behavior, shared decoder or legacy importer changes. The original conversion helper remains in the same unit; the new resource functions have no runtime caller until Chao's complete draw/model/animation state is reconstructed. Adding them here is conservative because the arithmetic and byte groups are independently established while content wiring is unresolved. No Lua character prefab is guessed.

## Validation

Scratch Python scripts were run once per version, using the original ISO and module bytes. `find_palette_modules.py` identified 19 executable PRS modules in addition to 76 direct REL files; only ChaoMain contained the 39 palette filename strings. `inspect_palette_relocations.py` checked section/import bounds and decoded relocation streams for all 95 modules. `inspect_chao_palette_tables.py` resolved relocated filename/switch pointers, matched all 39 disc paths and compared all 18 texture indices to the real C4 entries. Its result:

```text
palettes=39 matched_disc_paths=39 bank_colors=48 bank_bytes=192
texture_groups=[[0,1,2],[3,4,5],[6,7,8],[9,10,11],[12,13,14],[15,16,17]]
indexed_texture_count=18 all_groups_match_al_body_C4_ordinals=true
```

`validate_chao_palettes.py` compares the C++ reader/converter's BGRA and RGBA bytes against independent Python formulas from the original helpers. The real-file result covers every original initializer path and every GVP file on the disc. Packed words are tested exhaustively in modes 0/1/2; mode 6 tests varying lengths and updates after a full prior conversion. Invalid inputs verify unchanged output banks. Quoted result:

```text
real_palettes=49 real_mode_counts={1:49} real_converted_colors=2352
initializer_table_files=39 initializer_all_files_validated=true
exhaustive_words=65536 per mode 0/1/2
valid_boundary_cases=8 malformed_cases=13 failures_preserve_bank=true
mode6_bytes_updated=48 mode6_bytes_retained=144
protocol_requests=4168 all_BGRA_and_RGBA_bytes_match=true
```

Strict isolated MSVC x64 `/W4 /WX /O2` compilation passed. Full engine build: passed (Windows x64 MSVC/Ninja Debug, EDITOR ON, executable link and asset copies; invocation-only Embedded debug information). Linux, EDITOR OFF and the default PDB build mode remain unverified. The compiled game was not run. No new GPU/frame comparison is claimed: this change converts CPU palettes, and the unchanged texture decoder/upload were validated in the preceding texture task. Original mode 0/2/6 files, other revisions and live Chao rendering remain untested. The initial scratch compile could not find an unstaged sibling header; using the qualified existing texture header fixed it without changing the decoder.

Raw evidence is complete in `evidence/sa2-chao-palette-table.csv`, `sa2-chao-palette-validation.csv`, `sa2-chao-palette-imports.csv`, `sa2-chao-native-addresses.csv`, `sa2-executable-modules.csv`, `sa2-chao-palette-tables.json` and `sa2-chao-palette-evidence.json`. They contain hashes, offsets, original table data, module counts, synthetic mapping limits and exhaustive-result hashes. Large scratch relocation streams and original proprietary executables are not copied into the repository. Human/compact work reports accompany scratch logs.

## Live palette validation

Scratch scripts were run once per version. A separate evidence worker reconstructed the unchanged relocated PPC words and executed the narrow instruction subset from `0x1F2E4` to `0x1FA88`, stopping before cache/GX calls. The interpreter follows integer registers, CR/CTR branches, stack byte-to-double conversion, floating operations and original pack/store instructions; it does not reuse the C++ blend formula. Initial registers are seeded and alternate seeds give the same baseline output. The 39 real GVP files are read from their original disc offsets in initializer-table order. Their 7,488 converted bank bytes match the compiled reader/converter. Zero, maximum and gradient bank sets provide independent channel coverage.

The first corpus covers six type routes and 28 state vectors; the supplemental corpus adds 60 boundary vectors per route/bank set: signed zero, subnormals/minimum normals, adjacent +/-1, huge negative C0, overflow, quiet/signaling NaN (VE=0) and mixed infinities. Exact-rational rounding checks validate 62,355 distinct finite fused operand triples. Nonfinite result classes and subnormal behavior are checked separately. This validates arithmetic under the documented FP contract, not unknown retail FPSCR or a running console. Quoted compiled comparison results:

```text
real_GVP_files=39 real_bank_bytes=7488 real_banks_match_oracle=true
instruction_fixtures=2112 palette_bytes=202752 all_outputs_match_original_instruction_interpreter=true
TLUT_groups_checked=6336 all_RGB565_to_RGBA_groups_match=true
unsupported_types=250 unsupported_types_preserve_output=true invalid_TLUT_groups=3
body_texture_entries=18 body_texture_views=504 body_mip_views=504 body_RGBA_bytes=2064384
all_body_pixels_match_pinned_Dolphin=true
```

All three groups from each of the 168 real-bank state/type cases are supplied to the original corresponding AL_BODY C4 texture. Every resulting pixel matches the pinned official Dolphin decoder using that same generated BE TLUT. All these selected body textures have one mip. This is a resource/pixel comparison, not an in-game frame or material validation. The first isolated compile needed the unstaged sibling-header include path; a fixed-array BE word read also required explicit byte assembly because the existing BinaryRead API accepts vectors. Both compile issues were corrected in scratch before applying.

Strict isolated MSVC x64 `/W4 /WX /O2` compilation passed. Full engine build: passed (Windows x64 MSVC/Ninja Debug, EDITOR ON, executable link and asset copies; invocation-only Embedded debug information). Linux, EDITOR OFF, default PDB mode and game execution remain unverified. Raw evidence has eight CSVs and `sa2-chao-live-evidence.json` under `docs/evidence`, retaining every case's raw parameter bits/hash, body pixel hashes, call/cache/channel/float-order records, list entries and native DOL/disc offsets. Human/compact scratch oracle reports accompany complete fixtures and arithmetic audits; proprietary executables and reference-source code are not copied into the repo.

## Additional discoveries and unknowns

Retail REL linker `0x800E8128` (DOL `0xE5128`) matches imported module ids and reads eight-byte relocation records: BE delta u16, type byte, section byte, BE addend u32. Opcode 202 selects the source section; 201 advances without a patch; 203 ends the stream and calls cache helpers for executable sections. Type 1 writes absolute 32-bit target; 3/4 write low 16 bits; 5 writes high 16 bits; 6 writes high 16 bits plus a carry for target bit 15. Type 2 replaces branch bits `0x03FFFFFC`; type 10 replaces those bits with `target - patchAddress`. Both preserve `0xFC000003`. Module 0 uses the raw absolute addend, other modules use the selected target section's address with its executable flag cleared plus addend. Type 0 does nothing; unknown types print an error. Only patch types 1/4/6/10 occur in the inspected module corpus; other supported types have no sample validation here.

`0x800E839C` (DOL `0xE539C`) accepts REL versions below 3, checks version-2 alignment fields +`0x40`/+`0x44`, rebases the section/import/relocation pointers, assigns sequential BSS storage, rebases entry offsets using section bytes +`0x30`/+`0x31`/+`0x32`, and links both directions against modules in the list at `0x800030C8`/`0x800030CC`. It calls `0x8000532C(BSS,0,size)`, whose byte-fill implementation is `0x8000535C`. `0x800E85EC` (DOL `0xE55EC`) unlinks matching imports by clearing relocated fields; a relative branch is redirected to the module's +`0x3C` unresolved entry when its section byte +`0x32` is nonzero. Cache/list/allocator internals remain unknown. No shared GameCube::relocateRel change is made.

File wrapper `0x8011C3C0` calls open `0x80119D64`, query `0x80119EA4`, read `0x80119EF0` and close `0x80119E6C`. It compares `capacity >> 11` to the queried count, and sets `0x80357868` to 2 for open failure, 7 for capacity failure, or 5 for read failure. Internal I/O behavior/count units and allocation/retry details are uninspected. The Chao initializer ignores load failure and logs each name through `0x800E5BF0`.

Nearby native `0x80116EEC` (DOL `0x113EEC`) copies through `0x801196EC` and invokes `0x800E4E4C`; it is a memory/cache path, not proof of GPU TLUT upload. `0x80116E78`/`0x80117904`/`0x8011795C`/`0x80117E40` inspect, allocate, release and initialize state around r13-`0x7220`/`0x7224`, calling uninspected `0x800E47A8`/`0x800E4554`/`0x800E4650`/`0x800E473C`. The initialized pointer uses descriptor +`0x18` and +`0x1C`. Their full memory policy remains unknown. Full native address/file/disc-offset roster is in the CSV, including called functions whose bodies remain unread.

Unrelated neighboring Chao helpers were encountered and recorded, without assigning a gameplay identity: `0x1EE14` copies eight floats, changes output +4 to `480 - input +12` and output +12 to `480 - input +4`, then calls `0x8011A280`; assembly resolves the decompiler's ambiguous float casts. `0x1EE8C` returns `base + BE32(base + index*4)`. `0x1EE9C` calls `0x800709F8(2,callback=0x1EEDC,argument)` and stores `0x1EED8` at result +`0x18`. `0x1F284` forwards the pointer at `*(object+0x34)+0x670` to `0x80119828`. Callee bodies and object identities remain unknown.

Callback `0x1EEDC` follows object +`0x34` to a small state block. State 0 initializes floats +`0x18`=3, +`0x20`=0, +`0x28`=0 and u16 +6=0, then immediately executes state-1 work. State 1 updates +`0x28` by `0.4*(1 - float@+0x24)`, multiplies by 0.85, caps above 0.1 and adds it to +`0x24`; when its square is below `1e-5` and +`0x24` lies strictly between 0.999 and 1.001, it snaps that float to 1, resets byte +3 and enters state 2. It adds 15 to u16 +6, clamps values above 255 to 255, computes +`0x20`=`1.25 * float@+0x24` and +`0x18`=`2.5 * float@+0x24 + 3`. State 2 increments byte +3, tests its prior value >150, and tests bit `0x8000` at `*(*(object+8)+0x34)+4`; either condition changes state to 3. State 3 subtracts 8 from u16 +6, calls `0x80071AE0` if the unsigned result <5, subtracts 0.06 from +`0x20`, changes state to 4 if that float <0.8, and subtracts 0.05 from +`0x18`. State 4 repeats the u16 step, subtracts 0.06 from +`0x20` and 0.15 from +`0x18`, calling the same helper when either float is negative. The helper's termination semantics are unknown. Negative/other state values return. These neighboring effect observations have no execution comparison or verified floating-instruction precision; they are not a behavior-port claim. Original stored f32 constants at `0x5FC40`–`0x5FC80` are retained in the tables JSON, including their exact representable values; no effect prefab is guessed.

Still unknown: three GVP header meanings; slot allocation/reuse and hardware region callback policy; type/float gameplay names and retail FPSCR state; packed global-id selector/material binding; native flags/material/full-frame color; remaining module imports and full loader lifecycle; other game revisions. Dynamic blend math, contiguous RGB565 groups, the inspected AL_BODY list identity and 96-byte allocation/free path are now established. Models, animation, levels, SET objects and player physics remain future reverse-engineering work. No leaked original source was encountered or used; the retail string `al_palette.c` is debug/assertion metadata, not source code.

Additional inspected paths remain unported: `0x1BF4` prepares BSS pointers from work +C8/D8 and, if u16 work +AC mask 0x0002 is set, +C0/E0/F0; otherwise it clears the optional pointer. No palette update is inferred from it. `0x31A38` updates the palette before choosing draw routes with data byte +DD; it selects the body list on two paths and the list at `0xFBBD8` on another. `0x52670` selects the body list while branching on its second argument (including 0x1B), but its draw-state helpers remain uninspected. `0x5FCC` also prepares separate blend globals/pointers and dispatches model helpers after the palette update, then clears work +674 mask 0x0002; these side effects are not included in the CPU palette API. Setup `0x2679C` sets work +67C to `0xFF66BBFF` after successful resource setup; its model-conversion calls remain unported. Cleanup `0x26584` additionally releases nonzero work +5B4/+5B8/+5BC pointers and invokes a model cleanup helper.

Native `0x801166F0` iterates texture-list entries and releases their native objects; `0x80116788` performs a lookup, stores separate error context at `0x80357864` and error 1 at `0x80357868` on failure, otherwise invokes a transfer helper. These observations do not resolve palette-mode state at `0x803AE0A4`. New/relied native function addresses, file/disc offsets and unread-callee markers are retained in the live-native CSV. No leaked original source was encountered or used.
