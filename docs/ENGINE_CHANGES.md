# Engine changes

## 2026-10-10: SA2 Battle PRS loading

SA2 callers can now load and decompress a PRS file from an already-open GameCube ISO. The retail decoder at `0x800D2684` matches the existing PRS implementation, so it is reused without changing existing entry points. Evidence and validation: `docs/SA2_PRS_REFERENCE.md`; compact twin: `docs/ai/SA2_PRS.md`.

| Engine file | Change | Why | Effect on SA / Shadow |
|---|---|---|---|
| `src/Importers/SA2/Prs.h` | New `SA2::decompressPrs` and `SA2::readPrsFile` declarations. | Give SA2 an explicit byte-loading API without changing existing APIs. | Additive; no existing caller is changed. |
| `src/Importers/SA2/Prs.cpp` | Delegate to the verified `STH2005::decompressPrs`; compose it with `GCDisc::readFile`. | Reuse exactly matching token rules and overlapping copies. | Shared decoder and disc reader are unchanged. SA2 retains their exceptions on invalid inputs. |
| `CMakeLists.txt` | Compile the new SA2 translation unit. | Make the entry points linkable in the engine. | Adds a unit; no build option, include order, library or runtime selection changes. |
| `src/Misc/PoolId.h` | Add the missing standard `<limits>` include. | Full-engine MSVC compilation failed at the existing `std::numeric_limits<uint32_t>::max()` use. Make the header declare its own dependency. | Compile-only header dependency; no pool logic, layout, default values or SA/Shadow behavior changes. |

Validation: all 1,782 retail PRS files matched independent Python output in both decoded length and SHA-256 through the C++ disc-loading entry point; 13 boundary and six malformed cases passed. Strict isolated MSVC x64 compilation passed. The full MSVC/Ninja Windows x64 Debug engine build with EDITOR ON passed using an invocation-only embedded-debug-information workaround for local compiler error C1902; no repository build setting was changed. Gameplay was not run. No rendering, physics, level, prefab, scripting or existing importer file was modified; the pool header only gained its standard-library include.

## 2026-10-10 continuation: SA2 GVM native texture resources

SA2 compressed texture archives now load as CPU resources with original metadata, native tiled payloads and all verified mip spans. The parallel path handles flag layouts and indexed data outside the existing SADX importer. It preserves the original native bytes instead of invoking the shared GPU path, which would regenerate mips/change transparent colors. Evidence: `docs/SA2_GVM_REFERENCE.md`; compact twin: `docs/ai/SA2_GVM.md`.

| Engine file | Change | Why | Effect on SA / Shadow |
|---|---|---|---|
| `src/Importers/SA2/Gvm.h` | New `GvmArchive`, entry/texture/mip/chunk CPU data types; `readGvm`, `readGvmPrsFile`. | Keep optional metadata and original native resources available for the later SA2 renderer. | Additive; no existing API, resource pool or caller changes. |
| `src/Importers/SA2/Gvm.cpp` | Bounds-checked variable-layout GVMH/GVRT reader, native index lookup and retail GX mip-size rules. | Read all compressed retail GVMs without losing mips/indexed payloads or guessing absent fields. | Parallel path; Ninja/Gvm, GXTexture, Texture::create and all SA/Shadow behavior remain unchanged. |
| `CMakeLists.txt` | Add `src/Importers/SA2/Gvm.cpp` to the engine target. | Link the new resource reader. | Add one unit; build options/include order/runtime selection unchanged. |

Validation: independent Python and C++ agree for 605/605 archives, 16,052/16,052 native payloads (225,090,768 bytes), and 90,719 original mip spans. Every header, payload length and SHA-256 matched. 23 valid boundary and 14 malformed cases passed; isolated MSVC x64 C++23 /W4 /WX /O2 passed. Full Windows x64 MSVC/Ninja Debug engine build with EDITOR ON passed: all compilation, executable link and asset-copy steps completed. The executable/assets are retained in this task’s `work/engine-build-gvm`; the moved build tree is retained as evidence and is not a reusable CMake cache. The prior `work/engine-build` cache remains separate. No runtime, rendering or gameplay check has been claimed; no Lua prefab is added for a container resource. The existing invocation-only embedded-debug-information compiler workaround is retained for the full build.

## 2026-10-10 continuation: SA2 standalone textures and original mip pixels

Standalone GVR/GVP readers, a parallel GX pixel decoder and an opt-in supplied-mip GPU upload now preserve the verified SA2 resource bytes and color rules. C4 palette selection stays explicit because live binding is unknown. Evidence/decisions: `docs/SA2_TEXTURE_REFERENCE.md` and `docs/ai/SA2_TEXTURE.md`.

| Engine file | Change | Why | Effect on SA / Shadow |
|---|---|---|---|
| `src/Importers/SA2/Gvm.h` | Add GvrFile/GBIX records and readGvr/readGvrFile. | Keep global id, prefixes and opaque tail available. | Additive; existing GVM declarations unchanged. |
| `src/Importers/SA2/Gvm.cpp` | Add standalone GBIX/GVRT scanner using the existing native resource reader. | Reproduce floor-to-four prefix length and last global id. | Existing GVM reader logic unchanged; shared importers untouched. |
| `src/Importers/SA2/Gvp.h` | Add GvpPalette and byte/disc reader declarations. | Expose original header words and native palette bytes. | New SA2-only API; no existing callers changed. |
| `src/Importers/SA2/Gvp.cpp` | Add bounds-checked GVPL reader. | Copy the original payload without guessing field or binding semantics. | Parallel SA2 path; no palette state changes elsewhere. |
| `src/Importers/SA2/Texture.h` | Add explicit palette conversion and native texture decode APIs. | Keep C4 palette choice in the caller. | New qualified SA2 API; no legacy GX decoder changes. |
| `src/Importers/SA2/Texture.cpp` | Decode RGB5A3, CMPR and explicitly paletted C4 at every supplied native mip. | Preserve GX color expansion, CMPR blends/transparent RGB and original mip pixels. | Parallel implementation; SADX/Shadow continue using their unchanged decoders. |
| `src/Graphics/Resources/TextureMip.h` | Add a CPU-only RGBA8 mip data type. | Pass dimensions/pixels between importer and optional GPU upload. | Additive data type; no GL context or pool required. |
| `src/Graphics/Resources/Texture.h` | Declare opt-in createWithMipLevels with explicit sampler parameters. | Provide upload that accepts supplied mips. | Existing create API/defaults unchanged; no existing caller converted. |
| `src/Graphics/Resources/Texture.cpp` | Add validated GL_RGBA8 mip upload and unpack/binding restoration. | Avoid regenerating original mips or changing transparent color/component bytes. | Only the new method uses this path; existing create/destroy/use bodies unchanged. |
| `CMakeLists.txt` | Add SA2/Gvp.cpp and SA2/Texture.cpp to the target. | Link the new reader/decoder. | Adds units only; build settings and runtime selection unchanged. |

Validation: 16,081 real textures / 90,773 mips / 1,389,730,980 RGBA bytes exactly match pinned official Dolphin; 49 GVP containers, 2,646 explicit palette diagnostic views, seven boundary/22 malformed cases and exhaustive 65,536-word RGB5A3/RGB565 checks pass. Hidden GL 4.5 readback: 39 levels / 97,968 bytes unchanged, ten rejected invalid uploads preserve unpack state; all six min filters exercised. Strict isolated MSVC x64 /W4 /WX /O2 compile passed. Full engine build: passed (Windows x64 MSVC/Ninja Debug, EDITOR ON, executable link and asset copies; invocation-only Embedded debug information). No gameplay, material/full-frame comparison or automatic palette binding is claimed. Protected shared importers and legacy texture bodies are audited unchanged.

## 2026-10-11 continuation: SA2 Chao palette conversion

The original Chao loader converts a fixed 48-color bank with inverted alpha in mode 0 and a partial 48-byte update in mode 6. A parallel CPU resource now preserves those rules and exposes RGBA colors to the existing texture decoder. Addresses, module mapping, decisions and remaining binding unknowns: `docs/SA2_PALETTE_REFERENCE.md` and `docs/ai/SA2_PALETTE.md`.

| Engine file | Change | Why | Effect on SA / Shadow |
|---|---|---|---|
| `src/Importers/SA2/ChaoPalette.h` | Add zero-initialized 192-byte BGRA bank, update and RGBA access APIs. | Preserve native bank layout and prior state for partial updates. | New SA2-only data/API; no existing callers changed. |
| `src/Importers/SA2/ChaoPalette.cpp` | Implement original modes 0/1/2/6, fixed count, bit replication, inverted alpha and 48-byte copy; validate before mutation. | Match the ChaoMain loader and expose all 48 RGBA colors without choosing a live texture palette. | Parallel CPU path; shared decoders, readers, GPU upload and runtime remain unchanged. |
| `src/Importers/SA2/Gvp.h` | Update the resource comment to point to Chao's separate interpretation of the first word. | Reflect new evidence while retaining raw fields. | Comment only; layout/API/reader behavior unchanged. |
| `CMakeLists.txt` | Add SA2/ChaoPalette.cpp to the target. | Link the new resource helper. | Adds one unit; no build-setting or runtime-selection change. |

Validation: all 49 real files / 2,352 colors match independent Python BGRA and RGBA output; all 39 original initializer filenames match disc entries and are included. Every 65,536-word input in modes 0/1/2 matches; eight valid boundary and 13 malformed cases pass, including exact 48-byte update/144-byte retention and unchanged banks on failure. Strict MSVC x64 /W4 /WX /O2 compilation passed. Full engine build: passed (Windows x64 MSVC/Ninja Debug, EDITOR ON, executable link and asset copies; invocation-only Embedded debug information). No Chao gameplay/rendering claim; dynamic palettes, slot lifetime, three header meanings and GPU TLUT behavior remain unknown. Protected shared/previous SA2 implementations are audited unchanged.

## 2026-10-11 continuation: SA2 generated Chao palettes

The native palette update blends 39 banks into 48 RGB565 words and uploads three groups of 16. An additive CPU helper now preserves the original single-operation/FMA order, clamping/NaN branches, truncation and byte wrapping. Evidence, offsets, FP contract and runtime unknowns: `docs/SA2_PALETTE_REFERENCE.md` and `docs/ai/SA2_PALETTE.md`.

| File | Change | Why | SA / Shadow impact |
|---|---|---|---|
| `src/Importers/SA2/ChaoPalette.h` | Add offset-named parameters, 96-byte BE RGB565 output, build and explicit 16-color group APIs. | Represent the proven generated resource without inventing type labels or slot ownership. | New SA2-only API; existing types/functions/callers retained. |
| `src/Importers/SA2/ChaoPalette.cpp` | Add original six-type bank selection, exact blend operation order, packing and TLUT group conversion. | Match ChaoMain +0x1F2E4 and its three RGB565 uploads under the documented FP contract. | Parallel CPU helper; no existing conversion/decoder/GPU/runtime logic changed. |

Validation: 39 real palette banks / 7,488 bytes match the compiled loader; 2,112 original-instruction reference cases / 202,752 palette bytes and 6,336 group conversions match. All 250 unsupported type bytes preserve output; three invalid groups reject. Generated palettes on 18 real body texture entries / 504 views / 2,064,384 RGBA bytes match pinned official Dolphin. Strict MSVC `/W4 /WX /O2` compilation passed. Full engine build: passed (Windows x64 MSVC/Ninja Debug, EDITOR ON, executable link and asset copies; invocation-only Embedded debug information). Retail FPSCR, slot allocation/region policy, gameplay field names and Chao model/animation/runtime wiring remain unverified. No game/frame or playable-Chao claim; CMake, shared importers/decoders and GPU upload are unchanged.

## 2026-10-11 continuation: interactive SA2 Chao texture preview

The verified palette and texture resources now have an opt-in editor view the user can run and interact with. It displays three original Chao body textures, six neutral family buttons, four mix sliders and Reset. It has its own window/resources and returns before normal game startup. It is a resource diagnostic; no new Chao actor, Lua mechanic or playable-level claim. Details, original addresses, display choices and unknowns: SA2_PREVIEW.md and its AI twin.

| Engine file | What changed | Why | SA / Shadow effect |
|---|---|---|---|
| `src/main.cpp` | Accept argv and route two explicit SA2 preview flags before the existing body; include the preview header under EDITOR. Non-editor requests return a readable error. | Let the user test the verified port without both existing-game discs. | Normal startup body preserved; only explicit new flags choose the private diagnostic. |
| `src/EngineEditor/SA2PalettePreview.h` | New isolated diagnostic entry point. | Keep the optional launch API out of gameplay/importers. | Additive EDITOR interface; no old caller changed. |
| `src/EngineEditor/SA2PalettePreview.cpp` | Manifest/disc guard, original-resource loading, private GLFW/ImGui loop, palette controls, exact group texture upload and cleanup; optional bounded hidden UI/GPU/frame check with readable/compact reports. | Provide an actual interactive view and verify its controls and displayed data. | Only selected by new flags; does not call existing game renderer, camera, pools, Lua or level startup. Shared CPU/GPU APIs remain unchanged. |
| `CMakeLists.txt` | Add the new preview implementation only to the EDITOR sources. | Link it with the existing ImGui backends. | One optional source addition; editor value, compiler flags, platform links and copy targets unchanged. |

Content is separate: `External/SA2/PalettePreview.json` records original bank paths and type/texture triples from retained evidence. No repository tools or Lua content are changed. The local compiled preview/launcher and paired readable/compact reports live in the chat outputs; the disc stays in its existing scratch location.

Validation: full Windows x64 MSVC/Ninja Debug EDITOR ON build/link/asset copies passed (invocation-only Embedded debug information). Strict isolated /W4 /WX /O2 compile passed. Hidden actual ImGui widgets responded for six-family resource coverage, family button, all four sliders and two Reset actions; 172,032 GPU bytes match the verified CPU decoder. Python checked 39 real GVP paths/headers/offsets, six original triples and 3,744 palette payload bytes; 307,200 displayed texture pixels restored exactly, all changed in the selected family/mix capture. Three startup error cases return 1; frame images visually checked. Fourteen protected prior/shared source files remain unchanged; default main body and all other CMake settings preserved. Evidence: SA2_PREVIEW.md / twin / docs/evidence/sa2-preview-validation.ai.json. Existing-game runtime, Linux, EDITOR OFF and another machine are untested. Retail model/material/gamma, field/type names, slot lifetime and gameplay remain unknown/unported. No leaked original source was used.

## 2026-10-12 continuation: whole-disc SA2 analysis

No engine, CMake, Lua prefab or content files changed in this pass. Work adds original-file inventories, generated unreviewed Gekko evidence, the bounded REL linker/layout reference and apploader/startup findings. Existing SA/Shadow and the testable SA2 texture preview are preserved. The 240 engine/content hashes captured before documentation staging guard the apply step. No build is needed for these documentation-only changes. Full progress and limitations: `docs/SA2_DECOMPILATION_PROGRESS.md` / `docs/ai/SA2_DECOMPILATION.md`, `docs/SA2_REL_REFERENCE.md` / `docs/ai/SA2_REL.md`.

## 2026-10-13 continuation: SA2 stored REL metadata

| Engine file | What changed | Why | SA / Shadow effect |
|---|---|---|---|
| `src/Importers/SA2/Rel.h` | New raw version-2 REL header, section, import/record and decoded-byte resource plus explicit raw/PRS reader APIs. | Give later SA2 importers the exact original metadata without guessing pointers or module IDs. | Parallel namespace/API; no existing caller, layout or shared resource changed. |
| `src/Importers/SA2/Rel.cpp` | BE table/stream parsing through END, physical record offsets, unknown-field/type preservation, host bounds/version guards; unchanged GCDisc/PRS reuse. | Load all 95 identified real module files safely while foreign identities/ABI remain unresolved. | No existing Rel/PRS implementation changed; no relocation/native execution, pools/rendering/main/Lua/content changes. |
| `CMakeLists.txt` | Add `src/Importers/SA2/Rel.cpp` to the existing executable sources. | Link the additive reader. | One source entry; all other build settings, editor selection and platform links unchanged. |

Validation: one Python/C++ comparison covers 95 modules (76 raw/19 PRS), 115971764 decoded bytes, 1848 sections, 214 imports and 1664013 records including END; every field/source byte/hash matches. Ten preservation boundary cases and fifteen unsupported/truncated-input cases pass. Strict MSVC /W4 /WX /O2 and full Windows x64 MSVC/Ninja Debug EDITOR ON executable link/asset copies pass, using the existing invocation-only Embedded debug workaround. All other 239 original protected engine/content hashes remain unchanged; two engine files are new. No existing gameplay was run and Linux/EDITOR OFF remain untested. Unknown module lifetime/ID61/invalid-looking addends/ABI and full SA2 gameplay remain recorded; they are not substituted with guesses. Human/twin: SA2_REL_REFERENCE.md / ai/SA2_REL.md; architecture updated with ARCH_IMPORTERS; raw validation evidence in docs/evidence/sa2-rel-reader-validation.csv and .ai.json. No leaked original source was used.

The optional local `outputs/SA2-REL-Check` launcher/checker passed all 95 originals against the field/source-hash reference and includes no game media. It uses the same reader implementation in a standalone check; no additional engine entry point, tools/ command, Lua or content file was added.

## 2026-10-13 continuation: SA2 copied relocation and pointer-bank data

This pass adds opt-in data resources that future SA2 content can use. It reproduces proven original pointer rules while retaining foreign bindings, payload meanings and gameplay as unknown. No callback scheduler or guessed Lua prefab is added.

| Engine file | What changed | Why | SA / Shadow effect |
|---|---|---|---|
| `src/Importers/SA2/Rel.h` | Add copied `RelImageSection` / `RelocationView` resources and `buildRelocationView`; raw reader API stays intact. | Expose main/self section bytes and explicit skipped/unknown imports for later SA2 loading. | Additive SA2 API, no existing caller or shared type changed. |
| `src/Importers/SA2/Rel.cpp` | Copy sections/zero BSS, apply first main/self streams with original masks/order/carry/wrap, retain foreign/unknown records, and guard unvalidated host ranges. | Reproduce the bounded original linker data effects without pretending to run its lifecycle/cache or bind ambiguous foreign modules. | Separate opt-in path; original metadata-reader bodies and SA/Shadow importers stay intact. |
| `src/Importers/SA2/PointerBank.h` | New raw sentinel table resource, eligibility helper, copied view and ordered pointer-write/visit records. | Represent the proven Sonic container without inventing geometry field names or a format family. | New qualified SA2 interface; no pools, rendering, Lua or old resources changed. |
| `src/Importers/SA2/PointerBank.cpp` | Parse BE ID/root records; mutable-ID scan; exact payload/A/B conversion order with repeated visits and 32-bit wrap; explicit stack and host bounds/cycle checks; existing PRS/disc reuse. | Match original `0x80050210` / `0x8002F88C`, including inner words without a high-bit test and aliases that can change later termination. | No existing caller/shared decoder or gameplay path changed; only explicit calls choose it. |
| `CMakeLists.txt` | Add only `src/Importers/SA2/PointerBank.cpp` to the existing executable source list. | Link the new data resource; Rel was already listed. | All other build defaults/editor/platform/copy settings remain unchanged. |

Validation: 95 REL views / 1848 section entries / 104389753 initialized-plus-BSS bytes match frozen independent ELF addresses/bytes; 24 foreign streams skipped; three preservation/fourteen rejection cases pass. Real Sonic bank: 136360 decoded bytes, 64 entries, 688 visits/200 distinct nodes, 115 opaque targets and all 529 pointer stores/order match the independently reconstructed original loader; five preservation/eleven rejection cases pass. Strict MSVC `/W4 /WX /O2` compilation and full Windows x64 MSVC/Ninja Debug EDITOR ON build/link pass. The final fix rebuild recompiles PointerBank, reusing the unchanged Rel object whose earlier full compile passed. Existing invocation-only Embedded debug workaround remains outside repo defaults.

All 239 unrelated preexisting protected engine/content files are unchanged; two files are new. Rel had only comment additions after numerical validation, verified by a comment-stripped token comparison. The standalone `outputs/SA2-Data-Check` bundle passes the same 95 section views and Sonic bank, includes no game media and does not modify the disc. V2 pointer validation stopped at a stale guard before C++ execution; corrected V3 passes and historical helpers/reports are preserved. Linux, EDITOR OFF and existing gameplay runtime remain untested. Geometry, animation, native module lifecycle/foreign bindings, callback roles/full ABI, actual runtime heap/registry/aliasing and full game reconstruction remain unknown or unfinished. No leaked source was used. Human/twins: SA2_REL_REFERENCE / ai/SA2_REL, SA2_POINTER_BANK_REFERENCE / ai/SA2_POINTER_BANK, SA2_CALLBACK_REFERENCE / ai/SA2_CALLBACK; architecture and evidence updated together.

## 2026-10-14 continuation: SA2 raw model fields and vertex packets

| Engine file | What changed | Why | SA / Shadow effect |
|---|---|---|---|
| `src/Importers/SA2/ModelData.h` | New offset-named raw node-field resource, explicit optional `+0x34` availability, vertex packet/stream metadata and CPU reader APIs. | Expose proven native reads without inventing full structures, signed angle semantics or numerical transforms. | Additive qualified SA2 API; no existing public type or caller changes. |
| `src/Importers/SA2/ModelData.cpp` | BE word extraction, 52-byte minimum/explicit extra word, exact encoded first-stream movement and END-before-info, every nonterminal info read including opaque overlap, three proven record strides, raw span preservation and host bounds checks. | Load the real Sonic node and vertex packet data while quantized math, remaining commands and native rendering are unresolved. | Opt-in independent CPU path; existing Ninja Basic/SA/Shadow/shared importers, renderer, pools, main and Lua remain untouched. |
| `CMakeLists.txt` | Add only `src/Importers/SA2/ModelData.cpp` to the existing source list. | Link the additive reader. | Other settings/editor/platform/copy targets remain unchanged. |

Validation: all 200 nodes / 2600 original word bits and 100 streams / 154 data packets / 100 END words / 3167 raw records / 80448 raw stream bytes match independent original-derived CSV fields and every byte/hash. Ten preservation and sixteen host rejection cases pass; strict MSVC `/std:c++latest /W4 /WX /O2` and full Windows x64 MSVC/Ninja Debug EDITOR ON compile/link pass using the existing invocation-only Embedded workaround. The final nonterminal-info overlap correction is validated and rebuilt; earlier real-data pass, helper compile/schema/subset failures and final results are preserved.

Other 243 preexisting guarded engine/content files retain their hashes; two files are new. The standalone SA2-Model-Data-Check bundle passes all real samples, saves paired results, packages no game media and does not modify the disc. Node reads remain raw/mode dependent; the explicit extra word is not native branch execution. Known packet strides are metadata only; unknown record types retain opaque bytes and info. No numerical matrix/GQR/weight/skinning, primitive/cache/material, animation/provider, native lifecycle or gameplay/prefab is implemented. Existing runtime, Linux and EDITOR OFF remain untested. Original static/animated guard differences, registry exact-match unloading, installed load-scale truncation and generated C's FIFO-write loss are documented without altering installed/frozen exports.

Human/twins: SA2_MODEL_DATA_REFERENCE.md / ai/SA2_MODEL_DATA.md and SA2_POINTER_BANK_REFERENCE.md / ai/SA2_POINTER_BANK.md, with architecture/index/progress/evidence updated. No leaked original source was encountered or used.

## 2026-10-15 continuation: SA2 drawing-data reader and explicit cache trace

| Engine file | What changed | Why | SA / Shadow effect |
|---|---|---|---|
| `src/Importers/SA2/ModelDrawData.h` | New raw drawing-command/stream resources, explicit optional-offset caller cache, ordered control-trace result and two opt-in APIs. | Keep original command boundaries and cache call/return available without guessing native lifetime, material names or a model format. | New qualified SA2 types only; no existing API or caller changes. |
| `src/Importers/SA2/ModelDrawData.cpp` | Exact halfword END, single/pair/signed-size/unsigned-size movement, raw optional words and overlap, definition return/reference continuation; explicit-stack control trace with caller state and host limits. | Port the proven outer second-stream reads and cache control using real Sonic data while native graphics/global/FP behavior remains unresolved. | Independent CPU path; SA/Shadow/shared importers, renderer, pools, main, Lua and content remain unchanged. |
| `CMakeLists.txt` | Add only `src/Importers/SA2/ModelDrawData.cpp` to the source list. | Link the new resource. | Existing platform/editor/build settings unchanged. |

Validation passes all 79 real local streams / 289 commands / 42042 bytes and all 128 explicitly seeded cache scenarios / 814 ordered steps against independent original-derived metadata, every raw byte/hash and final cache. Thirteen preservation and nineteen host rejection cases pass. Strict MSVC `/std:c++latest /W4 /WX /O2` and full Windows x64 MSVC/Ninja Debug EDITOR ON compile/link pass with the unchanged invocation-only Embedded workaround. Other 245 previously guarded engine/content files retain their hashes; two source files are new.

The SA2-Drawing-Data-Check bundle passes and saves paired results. It includes no game media and reads the disc without modification. Its cache scenarios supply initial targets explicitly: 256 host selectors do not assert native allocation size, and 113 candidates do not establish actual bindings or draw order. The trace executes no state/graphics handlers or global counter effects. Negative signed lengths, unresolved targets and exceeded bounds/explicit limits are host errors; the original unchecked malformed-input behavior is not reproduced. Same-buffer offsets are an explicit host boundary. No native cache initialization, geometry interpretation, numerical transforms, animation or gameplay is ported. Existing-game runtime, Linux and EDITOR OFF are not newly tested. Full evidence/decisions/unknowns: SA2_MODEL_DATA_REFERENCE.md / ai/SA2_MODEL_DATA.md, with architecture/index/progress updated. No leaked original source was encountered or used.

## 2026-10-15 continuation: SA2 inner geometry records

| Engine file | What changed | Why | SA / Shadow effect |
|---|---|---|---|
| `src/Importers/SA2/ModelGeometryData.h` | New three explicit helper-layout modes, raw count-led primitives/records and CPU reader API. | Retain original count/index/skipped-word bits and distinguish helper consumption from the declared command end. | Additive SA2 resource only; no existing public types or callers changed. |
| `src/Importers/SA2/ModelGeometryData.cpp` | Bounded BE count/index/following-word extraction, original single-stream strides, 32-bit negative-count magnitude, raw tails, explicit opcode/layout checks and host zero/bounds guards. | Load the proven inner geometry records without inferring live draw mode, topology, coordinate conversion or scratch safety. | Independent CPU path; SA/Shadow/shared importers, renderer, pools, main, Lua/content and previous SA2 readers remain unchanged. |
| `CMakeLists.txt` | Add only `src/Importers/SA2/ModelGeometryData.cpp` to the source list. | Link the new resource. | Existing settings and copy targets unchanged. |

All 73 original geometry commands / 139 explicitly selected layout views / 952 unique count-led groups / 6561 unique records match the independent raw oracle field-for-field and byte-for-byte. The 72 unconsumed tail bytes remain intact. Sixteen preservation/nineteen host rejection fixtures pass; strict Windows x64 MSVC `/std:c++latest /W4 /WX /O2`, full Windows x64 MSVC/Ninja Debug EDITOR ON compile/link and the packaged Geometry-Data-Check pass. Existing invocation-only Embedded workaround remains outside repo defaults. Other 247 previously guarded engine/content files retain their hashes; two source files are new.

Explicit layouts represent proven single-stream helpers, not retail dispatch. D91C's following pair is opaque skipped data. The native count loops have no zero guard; host zero rejection and declared-span containment are safety policies. Negative index bits, negative count signs, most-negative magnitude and tails are retained. Grouped80120158, scratch dereference, state/attribute/GPU effects, transforms/skinning/animation and Lua gameplay remain outside this port. Runtime mode/caller/cache selection, full topology/material/attribute contract and exact FP remain unknown. Existing-game runtime, Linux and EDITOR OFF are not newly tested. Original function/offset tables, six-argument wrapper/FIFO caveats, paired/raw evidence, failures/corrections and architecture/progress/index are updated with SA2_MODEL_DATA_REFERENCE.md / twin. No leaked original source was encountered or used.

## 2026-10-16: explicit grouped geometry helper data

| Engine file | What changed | Why | SA / Shadow effect |
|---|---|---|---|
| `src/Importers/SA2/ModelGeometryGroup.h` | New explicit grouped-helper raw resource/API: per-stream header/info, final cursor/raw bytes, all primitive prefixes and record first/pair words. | Keep primary/shared count authority and skipped secondary fields visible without selecting retail groups. | Additive qualified SA2 types; no existing APIs/callers changed. |
| `src/Importers/SA2/ModelGeometryGroup.cpp` | Independent copied cursors; last info controls primitive count, primary signed prefixes control records; preserve secondary skipped words and overlapping immutable spans; bounded host guards. | Reproduce original20158 data reads with declared inputs while native aliases/state/GPU remain unresolved. | Parallel CPU path; SA/Shadow/shared importers, previous SA2 readers, main, renderer, pools and Lua/content remain unchanged. |
| `CMakeLists.txt` | Add only `src/Importers/SA2/ModelGeometryGroup.cpp` to the source list. | Link the new resource. | Existing platform/editor/settings/copy targets unchanged. |

Validation passes132 explicit helper inputs from66 real commands /198 stream views /19113 stream-record rows, all metadata/raw words/cursors/tails/byte hashes matching independent original-derived CSV. Nine preservation/sixteen host rejection cases, strict MSVC, full Windows x64 MSVC/Ninja Debug EDITOR ON compile/link and the packaged Grouped-Data-Check pass; existing invocation-only Embedded workaround unchanged. Other249 previously guarded source/content files keep their hashes; two files are new. Existing runtime, Linux and EDITOR OFF are not newly tested.

No encoded group was found in the bounded search of23 MDL.PRS candidates; tests supply their own collections. The one-to-eight stream limit is conservative host policy from the proved independent stack-storage window, not a native guard or intended-capacity claim. Native pointer-array/data and stack aliases are excluded; immutable byte-stream overlap is supported. Host file/declared-span/zero guards do not emulate unsafe native input. No first-info/group-size equality check is invented. Actual branch/callback/cache selection, full aliases/FP/GPU/material/animation/gameplay remain unresolved. Original collector callback loss, stack overlaps, last-info provenance, search boundary and additional first-stream results are documented in SA2_MODEL_DATA_REFERENCE.md / twin, architecture/index/progress and complete paired/raw evidence. No leaked original source was encountered or used.

## 2026-10-16: explicit Float32 vertex transforms

| Engine file | What changed | Why | SA / Shadow effect |
|---|---|---|---|
| `src/Importers/SA2/ModelVertexTransform.h` | New raw12-word native-layout matrix, complete copied-scratch result and explicit Float32-contract API. | Expose proved op23/op29 arithmetic without inventing live state or weighted behavior. | Additive SA2 types/API; no current callers or old APIs changed. |
| `src/Importers/SA2/ModelVertexTransform.cpp` | Ordered fused first triple, separately rounded product then fused second triple, final PSQ store subnormal flushing, raw packed-word rotate and preserved untouched bytes; guarded copied-memory path. | Match original8011DA30/8011DAF0 under GQR0=0/nearest/NI0/nontrapping finite-input and retained-result contract. | Parallel CPU path only; SA/Shadow/shared renderer/pools/main/Lua/content unchanged. |
| `CMakeLists.txt` | Add one unit and source-local `/fp:strict` on MSVC /`-ffp-contract=off` elsewhere. | Preserve the original rounding/fusion sequence. | FP options affect only the new unit; existing options remain unchanged. |

219 independent-reference cases (213 real-byte probes from71 packets/three supplied matrices plus6 synthetic),7,017 output slots and458,112 complete scratch bytes match, including every untouched byte. Five preservation/fifteen host rejection fixtures, strict MSVC, full Windows x64 MSVC/Ninja Debug EDITOR ON compile/link and packaged SA2-Vertex-Check pass. Compile commands confirm strict FP applies only to this source; the existing invocation-only Embedded debug workaround is unchanged. Other251 protected preexisting source/content files retain their hashes; two files are new. Existing gameplay/Linux/EDITOR OFF were not newly tested.

Matrices are declared test inputs, not live runtime captures. Native unused lookahead, discarded lanes/FPSCR flags, pointer aliases/address wrap/faults and unsafe count0 traversal are excluded. Host bounds/positive-count/finite/environment guards are policy. Weighted2C,2A, actual matrix/state/quantization, complete rendering, animations and Lua gameplay remain unfinished. Original startup-zero/snapshot proof, matrix permutation/upload sequences, failures and184 unchanged source hashes are documented in paired model/boot/progress/architecture references and complete raw evidence. No leaked original source was encountered or used.

## 2026-10-17: weighted vertices and complete first-stream CPU dispatch

| Engine file | What changed | Why | SA / Shadow effect |
|---|---|---|---|
| `src/Importers/SA2/ModelVertexTransform.h` | Add explicit weighted packet and full first-stream result/API types with copied scratch, state and GQR1 metadata. | Expose original8011DC98/8011D1D4 behavior with caller-supplied matrix/cache/state. | Additive SA2 API; no existing caller or type changes. |
| `src/Importers/SA2/ModelVertexTransform.cpp` | Add exact signed16/256 weights, mode0 rounded products/nonzero fused accumulation, additive indexed destinations, ordered writes and stream dispatch through existing23/29 and new2C. | Match original arithmetic, state OR3, GQR1 clobber, opaque skipping and END under the documented finite Float32 contract. | Parallel CPU path; old helper bodies unchanged. No shared renderer, main, pools, Lua, gameplay or content changes. |

CMake and its source-local strict FP settings are unchanged.252 other guarded source/content files retain their hashes.314 weighted cases/13,326,784 complete scratch bytes,309 streams/5,062,656 complete bytes plus all state/GQR1/end metadata, and65,536 signed weights through8 C++ batches pass;12+6 preservation and17+6 rejection fixtures pass. Strict MSVC and full Windows x64 MSVC/Ninja Debug EDITOR ON compile/link pass. Strict FP remains limited to this unit; existing invocation-only Embedded workaround unchanged. No production correction after reference comparisons.

This does not establish live matrix/GQR0/FPSCR/cache/animation/material bindings, render a model or add gameplay. Unknown2A is rejected; native unsafe lookahead, count0, aliases/wrap/faults/discarded lanes/FPSCR are excluded by explicit host policy. Linux/EDITOR OFF and existing gameplay were not rerun. See the dated model-reference section, architecture twins and complete paired weighted evidence; no leaked original source was used. Earlier weighted-unknown statements describe the earlier pass, superseded by these explicit APIs.
