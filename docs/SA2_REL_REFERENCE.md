# SA2 Battle REL modules and original linker

This reference applies to retail GSNE8P USA disc 0 revision 0. It describes immutable decoded files and bounded inspection of original loader code. A parallel C++ reader now exposes stored version-2 REL metadata and unchanged decoded bytes. Native-code execution and gameplay porting remain unfinished. Generated prototypes remain incomplete where the decompiler reports unrecovered registers.

## Original functions

| Original function | DOL file offset | Inspected purpose |
|---|---|---|
| `0x800E8128` | `0xE5128` | Find import matching source ID (null source means ID 0); apply relocation stream to destination module |
| `0x800E839C` | `0xE539C` | Version/alignment checks, BSS initialization, header/section pointer adjustment, loaded-list insertion and bidirectional import linking |
| `0x800E85EC` | `0xE55EC` | Remove references to an unlinked module; zero absolute fields / redirect REL24 to destination's unresolved callback |
| `0x800E87F8` | `0xE57F8` | Remove loaded-list node and visit remaining modules to unlink its imports |
| `0x800E8114`, `0x800E8118` | `0xE5114`, `0xE5118` | Observed single-`blr` link/unlink hooks |
| `0x80019E70` | `0x16E70` | Raw module filename selection/read/allocation/link/prolog call |
| `0x8001A5B0` | `0x175B0` | Compressed module read/PRS decode/aligned BSS/link/prolog call |
| `0x80019D78` | `0x16D78` | Observed prior indirect callback, module epilog, unlink and conditional allocation releases |

All absolute ISO function offsets and original first words/C evidence hashes are in `docs/evidence/sa2-rel-function_sources.csv` and `sa2-rel-additional_function_sources.csv`. DOL offsets are canonical; ISO location is DOL disc offset plus DOL file offset. The original diagnostic strings at `0x801CEEA8`/DOL `0x1CBEA8` and `0x801CEED0`/DOL `0x1CBED0` name OSLink and OSUnlink unknown relocation types. These are original debug data, not leaked source.

## Stored format

All multibyte fields below are big-endian. All 95 real module files use version 2. PRS modules must first be decoded using the original PRS rules; REL offsets are then offsets into those decoded bytes, not compressed-file offsets. No original runtime pointer is stored in the initial next/previous fields on these samples.

| Header offset | Size | Original observed field/use |
|---|---:|---|
| `0x00` | 4 | Module ID, compared with import target ID |
| `0x04`, `0x08` | 4 each | Runtime next/previous loaded-list pointers; both zero in every sample |
| `0x0C` | 4 | Section count |
| `0x10` | 4 | Section-table file offset; linker adds module base |
| `0x14`, `0x18` | 4 each | Name offset/raw name size; linker conditionally adds global `0x800030D0` to name offset; full name use unknown |
| `0x1C` | 4 | Version; original linker accepts unsigned values below 3, checks alignment fields for values >=2 |
| `0x20` | 4 | BSS byte count supplied to zero-fill helper |
| `0x24` | 4 | Relocation-region file offset; linker adds module base |
| `0x28`, `0x2C` | 4 each | Import-table file offset and byte length; entries have stride 8 |
| `0x30`, `0x31`, `0x32` | 1 each | Prolog, epilog and unresolved callback section indices; zero suppresses address adjustment |
| `0x33` | 1 | Preserved raw byte; not given an inferred meaning by these inspected functions |
| `0x34`, `0x38`, `0x3C` | 4 each | Callback offsets relative to selected section; linker adds section base with low executable bit cleared |
| `0x40`, `0x44` | 4 each | Module/BSS required alignments for version >=2; zero skips that test |

Each section entry is two u32 words: stored offset/low-bit flag, then byte size. Low bit 1 denotes executable cache treatment in the relocation helper. Nonzero stored offsets are adjusted by adding module base, retaining the low bit. An exactly zero offset with nonzero size is assigned the supplied BSS cursor, which then advances by that section size; the inspected linker does not add an extra per-section alignment. The BSS buffer is zeroed first by `0x8000532C`/`0x8000535C` (DOL `0x232C`/`0x235C`). The table's stored BSS sizes sum to header `+0x20` on every real sample.

Each import entry is `{u32 target_module_id, u32 relocation_stream_file_offset}`. The linker adds the current module base to each stream offset. ID 0 refers to the main executable's absolute-address addends in the inspected relocation helper. Foreign runtime identity comes from loaded module IDs, not a filename in this record.

Each relocation record is eight bytes: `{u16 cursor_delta, u8 type, u8 section, u32 addend}`. For an ordinary record, the patch cursor advances by delta. The source target base is zero for ID 0, otherwise source section entry offset with bit 0 cleared; target value T is base + addend. All 214 real streams begin with type 202 and delta 0, establishing the patch cursor before it is used. END is tested before applying its delta.

| Type | Original inspected operation |
|---:|---|
| 0 | Advance cursor, no write |
| 1 | Write 32-bit T |
| 2 | Write `(T & 0x03FFFFFC) | (old & 0xFC000003)` |
| 3,4 | Write low 16 bits of T |
| 5 | Write high 16 bits of T |
| 6 | Write high 16 bits plus 1 when T bit 15 is set, then truncate to 16 |
| 10 | Write `((T - patch_address) & 0x03FFFFFC) | (old & 0xFC000003)` |
| 201 | Advance cursor, no write |
| 202 | Select destination section cursor; flush/invalidate previous executable section before changing cache-tracked section |
| 203 | Flush/invalidate final executable section and return 1 |
| other | Issue original unknown-relocation diagnostic and continue to next record |

The original operations mask/truncate and preserve instruction opcode/AA/LK bits; they do not validate branch displacement or the observed foreign addend bounds here. The standalone analysis generator adds host-side bounds/range checks for its own mapping and does not reinterpret the original invalid-looking imports. Cache calls are `0x800E4E4C`/DOL `0xE1E4C` (data flush, then syscall) and `0x800E4F14`/DOL `0xE1F14` (instruction invalidate, sync/isync). Their byte length handling returns immediately for zero and adds 32 for an unaligned address; cache block iteration advances by 32. Full hardware/cache execution has not been replayed.

Only types 1,4,6,10 occur as actual patches in these 95 real files: respectively 488,311; 408,802; 408,802; 356,737. Other branches above come from the inspected original code, not manufactured test files. Precise unsupported-input behavior beyond those bounded operations remains unvalidated.

## Link and unlink order

`0x800E839C` checks version and required module/BSS alignment before inserting at the tail of the list rooted at `0x800030C8`/`0x800030CC`. It initializes BSS, turns header/import/section/callback offsets into runtime addresses, optionally adjusts the name pointer, links ID 0, then walks the loaded list. For every listed module it updates that destination module's matching import stream using the new source module; for every other listed source it also updates the new destination module's matching import stream. Self imports are handled by the same walk. The helper's missing-import return value is not used to abort this walk. Link finishes through the single-return hook and returns 1; failed initial version/alignment checks return 0.

The unlink helper first finds the importing entry matching the removed module ID. Absolute types 1..6 are zeroed (type 2 retains opcode/AA/LK bits); type 10 is masked to the importing module's unresolved callback displacement when its header `+0x32` is nonzero, otherwise displacement zero. It retains SECTION/NOP/END traversal and cache treatment. `0x800E87F8` removes the list node, visits the remaining modules with that helper, calls the return hook and returns 1. The inspected unloader does not restore the removed module's header offsets to their stored-file form. No host implementation substitutes another lifecycle.

## Game loader observations

String helpers `0x8010DFF8`, `0x8010DE18`, `0x8010DF88` (DOL `0x10AFF8`, `0x10AE18`, `0x10AF88`) perform the inspected copy, comparison and append operations. Using the original startup r2 literal `0x803B6520`, the raw path `0x80019E70` appends `D` except when the name compares equal to literal `CHAOMAIN`, then appends `.REL`. The actual literal bytes/addresses are recorded in `sa2-rel-strings.csv`. Its two allocation paths call the linker and then the adjusted prolog pointer. This identifies bounded filename construction, not every caller's selected basename, actual disc lookup case behavior or complete load lifetime.

The compressed path `0x8001A5B0` appends `.prs`, reads near the upper temporary region, calls original PRS decoder `0x800D2684` (DOL `0xCF684`), derives aligned BSS and end pointers from the decoded length/header BSS size, calls the linker and invokes the prolog. Its shown generated link prototype drops arguments; original instructions and caller register setup must be consulted before porting it. Decoder behavior is in `SA2_PRS_REFERENCE.md`; read/allocation error handling, capacity/lifetime and caller selection remain incompletely inspected.

`0x80019D78` invokes another callback from an object at the observed global pointer `r13-0x7ABC`, then module epilog, then unlink, and conditionally releases/zeros the two allocation pointers. The other callback's role, all error paths, allocator semantics, original loaded-module bases/order/lifetimes and stage/Chao filename dispatch remain unknown.

## ChaoMotions filename-specific path

ChaoMain decoded `+0x1AFD4` (analysis `0x8101AFD4`) reconstructs the 17 bytes including NUL at decoded `+0x5F8B8`: `ChaoMotionsD.rel`. It reads through decoded `+0x1B25C`, allocates BSS-size-plus-one, calls original linker `0x800E839C`, and invokes the adjusted prolog. The requested real file's header is ID 61. This is stronger than an ID-only guess: that load path names a specific original file. It still does not prove successful I/O/execution, the entire loaded-module lifetime or absence of another same-ID module; standalone ChaoMain foreign bytes remain untouched.

The reading helper calls original `0x80119D64` (DOL `0x116D64`) with the filename and zero; a zero return produces a zero buffer return. Otherwise it calls `0x80119EC4` (`0x116EC4`) to obtain the observed length field, optionally writes that length through the supplied output pointer, allocates through `0x801197FC` (`0x1167FC`) with arguments `(1,length)`, requests `((length+0x7FF)>>11)` units through `0x80119EF0` (`0x116EF0`), then closes through `0x80119E6C` (`0x116E6C`) and returns the allocation. No result check is visible for length query, allocation or read in the displayed helper. Exact lower helper semantics, unit/size safety and failed-query behavior remain unknown. The loading caller likewise shows no buffer/null or link-success check before its prolog invocation; this quirk is recorded, not repaired or implemented here.

Main selector routine `0x8001A3BC`/DOL `0x173BC` takes the narrowed selector from `0x8001DD78`/`0x1AD78` (observed global `0x803AD820`). Below `0x3C` it passes original format `stg%02d` to helper `0x8010C1B0`/`0x1091B0`, then calls the raw module loader. Its generated switch maps `0x3C..0x43` to the eight stored boss basenames, `0x46/0x47` to `Cart`, and `0x5A` to `CHAOMAIN` through the PRS module loader. Exact original string offsets and qualified selector table are in `sa2-main-module-dispatch.csv`. Python verified all 18 original direct BL words to the raw loader across this routine (ten) and `0x800D2DD4`/DOL `0xCFDD4` (eight). The latter's broader state machine and numeric selectors' game-facing names are not reconstructed here.

The Chao filename/call/source hashes and the main call/dispatch data are raw evidence in `docs/evidence/sa2-chao-motion-load-calls.csv`, `sa2-main-module-loader-callers.csv`, `sa2-main-module-dispatch.csv` and `sa2-main-module-function-sources.csv`. Generated prototypes, SDA assumptions and the unresolved ID61 lifetime remain qualified.

## Sample checks and conservative decisions

`audit_original_linker_v1.py`, run once, reported: 95 version-2 modules; 214 streams with first type 202/delta 0; all BSS sums matching; actual patches `{10:356737,6:408802,4:408802,1:488311}`. Alignment pairs `(module,BSS,count)` were `(8,1,1)`, `(8,8,4)`, `(32,1,9)`, `(32,8,77)`, `(32,32,4)`. The fresh full-disc header/stream/patch-bounds audit, mapping audit and image-byte review are retained with human/AI reports in the originating chat's scratch workspace. `docs/evidence/sa2-rel-headers.csv` retains each real header and decoded hash; the original module inventory is `sa2-executable-modules.csv`.

Keep ID 61's two filenames and the eight out-of-range imports unresolved. The original loaded-list algorithm supplies no safe filename choice from a REL header alone; it also does not justify repairing those addends. Generated analysis uses only checked main/self relocation and represents foreign calls with analysis-only metadata. It does not execute native PowerPC code in the C++ engine or invent Lua content. Full progress, decoder caveats and remaining behavior/type review: `SA2_DECOMPILATION_PROGRESS.md` and its compact twin.

The original linker investigation changed no installed tools or global configuration. The later reader adds two engine files and one CMake source entry, described below and in ENGINE_CHANGES.md. No leaked original source was used.

## Engine reader and validation

Include `Importers/SA2/Rel.h` and use `SA2::readRel(const std::vector<uint8_t>&)`, `readRelFile(GCDisc&,path)` for raw files, or `readRelPrsFile(GCDisc&,path)` for explicit PRS decoding. `RelModule` owns the entire decoded `data` buffer, a `RelHeader`, `RelSection` list and `RelImport` list. Records retain their physical decoded-file offsets plus delta/type/section/addend, including END's otherwise ignored delta and every unknown type. Stored next/previous/name/alignment/unknown-byte fields and callback section/offset pairs remain raw. `RelSection::fileOffset()` masks only bit zero, `isExecutable()` tests it, and `isBss()` tests exactly zero stored word plus nonzero size. No BSS buffer or relocated image is allocated.

This reader copies the existing SA2 importer pattern and uses unchanged BinaryRead, GCDisc and verified PRS routes. Only version 2 is supported because all 95 real modules and the layout validation use it; versions 0/1 are accepted by the original linker but are unvalidated here, and version 3 is likewise rejected. Host checks reject a short header, out-of-buffer section/table/record reads, a partial import entry and a stream without END. These are conservative engine safety policies, not reproductions of retail unsafe malformed-input behavior. Unknown types, duplicate IDs/streams, empty section/table offsets, inconsistent BSS sums/alignment and unvalidated callback indices are preserved instead of guessed or executed. Name, callback and foreign-target offsets are not followed; ID61 and eight beyond-section addends remain intact. The caller must retain disc path plus decoded hash when identifying modules; no ID-only registry is added.

`validate_rel_v1.py`, run once, reported: **95 modules (76 raw/19 PRS), 115971764 decoded bytes, 1848 sections, 214 imports, 1664013 relocation records including END; all parsed fields and original bytes/hash values match; 10 preservation cases and 15 unsupported/truncation rejection cases pass**. The comparison serializes every C++ header/section/import/record field in canonical BE order and checks an independently parsed original sample. The synthetic cases test host preservation/safety, not retail semantics. Per-module original and semantic SHA-256 values are in `docs/evidence/sa2-rel-reader-validation.csv`; the paired status/evidence is `sa2-rel-reader-validation.ai.json` and this section.

Strict Windows x64 MSVC `/std:c++latest /W4 /WX /O2` compilation and full MSVC/Ninja Debug EDITOR ON executable link/asset copies passed. The build uses only the previously documented invocation-only Embedded debug setting. No old SA/Shadow reader, shared decoder, CPU/GPU palette path, resource pool, main flow, Lua or content file changed. Engine changes are `src/Importers/SA2/Rel.h`, `src/Importers/SA2/Rel.cpp`, and one CMake source addition. The other 239 original protected engine/content files retain their hashes. This reader has no existing runtime caller; original module execution, indirect-call ABI, loaded bases/order/lifetimes, full field meanings and complete game behavior remain unknown.

Separate section-start pointer hypotheses and original trailer architectural effects are recorded in `SA2_DECOMPILATION_PROGRESS.md` with raw source evidence. Their incomplete prototypes are not turned into Lua prefabs or engine execution.

## 2026-10-13 continuation: copied main/self relocation views

The metadata reader above still preserves stored fields and bytes. A separate opt-in `SA2::buildRelocationView(module,moduleBase,bssBase)` now exposes `RelocationView`: ordered `RelImageSection {address,data}` copies, skipped import indices and unknown no-write relocation records. It allocates zero-filled host BSS bytes, applies only the first main-ID-zero and first self-ID streams, and never changes `RelModule::data`. The caller supplies the 32-bit addresses; they are data-view values, not retail-base claims or executable host mappings.

Two details are now explicit from original `0x800E8128` / DOL `0xE5128` and `0x800E839C` / `0xE539C`: the helper selects **the first matching import ID** rather than every duplicate, and alignment is checked by unsigned division/multiplication (equivalently modulo), with zero alignment skipping the check. It is not a power-of-two bitmask rule. All 95 samples have distinct target IDs within each import table. The original section walk advances BSS consecutively without added inter-section padding. The real files have 85 single-nonempty-BSS-section modules and ten without BSS; all assigned BSS addresses in this view are even.

The view reproduces original types 1/2/3/4/5/6/10, exact masks, high-adjust carry/truncation, unsigned 32-bit wrap, type-202 destination reset, type-203 END-before-delta and types 0/201 no-write. Unknown types advance the cursor without writing and are retained. ID zero uses absolute addends; self relocations use the declared source-section address. Later duplicate streams and all foreign imports remain unapplied, named by their original indices. ID61 ambiguity and the eight out-of-range foreign addends are not bound or repaired.

The view rejects unvalidated odd/overlapping/out-of-address-range spans, inconsistent version/count/BSS totals, insufficient alignment, invalid applied source/destination sections, out-of-buffer writes and unsupported streams without the observed initial SECTION or END. These are host policies; the raw reader continues to preserve metadata that the view cannot safely realize. Native link-list/header/name/callback mutation, cache instructions, foreign binding, module lifecycle and execution remain outside this API.

`validate_rel_view_v1.py`, run once, matched **all 95 original modules, all 1848 section entries and every address/byte** against the independently prepared frozen analysis ELF images: **102635025 initialized bytes + 1754728 BSS bytes = 104389753 section bytes**, with **24 foreign streams skipped**. Synthetic exact numeric rules, END delta, unknown no-write, first-ID selection and original-source preservation pass **three preservation and fourteen host rejection cases**. Strict Windows MSVC `/std:c++latest /W4 /WX /O2` and the full MSVC/Ninja Debug EDITOR ON engine build/link pass. Only explanatory comments changed in Rel after validation; token comparison guards confirm identical implementation.

The same code is in the local `outputs/SA2-Data-Check` double-click bundle, which passes all 95 views plus the Sonic bank described in [SA2_POINTER_BANK_REFERENCE.md](SA2_POINTER_BANK_REFERENCE.md). No game media is packaged. Old SA/Shadow readers, shared importers, main flow, renderer, pools, Lua and content stay unchanged. Evidence: `docs/evidence/sa2-rel-view-validation.csv`, paired validation/build/package reports, ENGINE_CHANGES.md and the importer architecture twin. Runtime bases, foreign bindings, lifetimes, callback ABI and full game behavior remain unknown.
