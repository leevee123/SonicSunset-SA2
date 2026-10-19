# SA2 Battle: standalone textures, palettes and GX pixels

## Scope and status

Continuing the verified PRS/GVM foundation, the conservative target is standalone GVR/GVP loading, GX pixel decoding and an opt-in engine upload of original mip levels on GSNE8P revision 0. The user supplied no concrete target beyond the repository, so this extends the next documented texture unknown without inventing level/gameplay behavior. All 29 standalone textures and 49 palette containers now load; all 16,081 retail textures decode across 90,773 original mip levels. GPU readback verifies representative RGB5A3, CMPR and C4 resources. C4 takes an explicit 16-color RGBA palette. No automatic game palette binding is claimed. Importers/resources introduce no level, character or mechanic, so this step needs no Lua prefab.

Retail DOL SHA-256: `a53335308d1f820be236fd2b6342fee850eaf048eb26aac21ddb1903b060db2e`. REA 6.3.0 rejects the DOL and its byte-preserving PowerPC ELF; the existing installed Ghidra headless analysis supplied pseudocode. The fallback and executable identity are documented in SA2_PRS_REFERENCE.md. No leaked original source was encountered or used. Official Dolphin source was retained only in scratch for comparison; its code was not added to the engine or repository dependencies.

## Original evidence

`stage_texture_docs.py` calculated these offsets from the DOL section map. Pseudocode is the primary evidence. The earlier save/restore-stub assembly resolves the standalone scanner's apparent undefined8 argument return: incoming r3 is header output, r4 is optional global-id output, r5 is source. The scanner initializes a supplied global output to -1. No additional instruction-level guess was needed for format layout.

| Function | DOL file offset | Observed operation |
|---|---|---|
| `0x8010AFCC` | `0x107FCC` | Standalone scanner save-register entry; previously verified assembly fall-through preserves argument registers. |
| `0x8010AFC8` | `0x107FC8` | File loader save-register entry; previously verified assembly fall-through preserves argument registers. |
| `0x8010B018` | `0x108018` | Standalone scanner restore-register entry; previously verified assembly fall-through preserves argument registers. |
| `0x8010B014` | `0x108014` | File loader restore-register entry; previously verified assembly fall-through preserves argument registers. |
| `0x80116204` | `0x113204` | Scan repeated GBIX prefixes; copy GVRT native header; return payload pointer. |
| `0x801161CC` | `0x1131CC` | In-place 32-bit byte swap used by the standalone scanner. |
| `0x8011773C` | `0x11473C` | Copy GVPL payload and four BE header words; success 1, failure -1. |
| `0x801176BC` | `0x1146BC` | In-place 32-bit byte swap used by the palette reader. |
| `0x801196EC` | `0x1166EC` | Forward the native byte-copy arguments to 0x8010BDF4. |
| `0x8010BDF4` | `0x108DF4` | Select backward copies when source < destination; otherwise forward; large-copy helpers below. |
| `0x80116EC4` | `0x113EC4` | Reset 0x80357860/64 to -1 and 0x80357868/6C/70 to zero. |
| `0x8011867C` | `0x11567C` | File texture loader: read 32-byte prefix, scan, override global id, register, read remaining native bytes. |
| `0x80118810` | `0x115810` | Memory texture loader: direct scanner, indirect scanner, then alternate descriptor fallback. |
| `0x801165B8` | `0x1135B8` | Filename construction around a final-four-byte temporary and supplied suffix; string callees not inspected. |
| `0x8011636C` | `0x11336C` | Return 1 when 0x80117994 returns zero; otherwise -1; memory loader polls until 1. |
| `0x8011741C` | `0x11441C` | Resolve texture and store native-info +4 in current state. |
| `0x8011746C` | `0x11446C` | Choose native transfer route by internal 0x80000000 and argument; poll transfer status. |
| `0x8011750C` | `0x11450C` | Decrement texture references; release allocation at zero; invalidate state and remove cache entry. |
| `0x801175A8` | `0x1145A8` | Reset native slots (40-byte stride), cache entries (24-byte stride), references and active indices. |
| `0x801176F4` | `0x1146F4` | Write second argument to first-argument object +8. |
| `0x801176FC` | `0x1146FC` | Forward selected entry +8 to 0x801176F4. |
| `0x801177FC` | `0x1147FC` | Return current native-info +0x14. |
| `0x80119284` | `0x116284` | Additional discovery: Ninja chunk reader and POF0 pointer relocations; not implemented/validated on files. |
| `0x8011921C` | `0x11621C` | In-place chunk word byte swap. |
| `0x80119254` | `0x116254` | Return a byte-swapped chunk word. |

Additional called addresses were recorded but their bodies were not inspected, so their internal semantics are unknown: `0x8010C044` (DOL `0x109044`), `0x8010C0F0` (DOL `0x1090F0`), `0x8010BED0` (DOL `0x108ED0`), `0x8010BF80` (DOL `0x108F80`), `0x8010E0AC` (DOL `0x10B0AC`), `0x8010DFF8` (DOL `0x10AFF8`), `0x80116560` (DOL `0x113560`), `0x8010DE18` (DOL `0x10AE18`), `0x8010DF88` (DOL `0x10AF88`), `0x800EEFF0` (DOL `0xEBFF0`), `0x800EF0B8` (DOL `0xEC0B8`), `0x801234CC` (DOL `0x1204CC`), `0x801197D0` (DOL `0x1167D0`), `0x800E4E4C` (DOL `0xE1E4C`). Previously decoded native registration/size/copy/cache helpers (including 0x801163A0, 0x8011733C, 0x80117290, 0x80117808, 0x801178A8 and 0x80103128) and their file offsets remain in SA2_GVM_REFERENCE.md.

No GVPL-reader caller was found inside main.dol. The Chao palette continuation found its imported caller in compressed ChaoMain.prs and reconstructed conversion plus the texture slot table; see SA2_PALETTE_REFERENCE.md. Dynamic palette updates and the GPU TLUT consumer remain unknown. File loader 0x8011867C reads a 32-byte prefix before allocation and can override the embedded global id with entry metadata. Memory loader 0x80118810 tries a direct file pointer, then its first pointed-to address; on two scanner failures it falls back to another descriptor (32-bit dimensions at +0x10/+0x14 narrowed to the native header). That descriptor's full layout remains unknown and is not accepted by the new host file reader. Runtime cache/refcounts, transfer routes and polling are observations, not implemented behavior.

## Standalone layouts

All chunk magic is ASCII. Chunk lengths are LE u32, although native texture/palette header words are BE. Inputs below are ordinary uncompressed FST files; no PRS layer is applied. GVRT's unchanged eight-byte native header and tiled mip layout are in SA2_GVM_REFERENCE.md.

| GVR offset relative to each prefix | Size | Meaning |
|---|---|---|
| +0 | 4 | `GBIX` |
| +4 | 4, LE | Declared prefix payload length |
| +8 | 4, BE | Global index; the final repeated GBIX wins |
| +12 | variable | Remaining opaque prefix bytes |
| next = +8 + (declared length & ~3) | variable | Another GBIX or GVRT; the original rounds DOWN to four bytes |
| GVRT +8 | 8 | Native reserved/flags/format/dimensions |
| GVRT +16 | variable | Native pixels; original scanner returns this pointer |

The original scanner accepts no unrelated prefix magic; failure sets 0x80357868 to 4 and returns zero. It ignores GVRT's chunk length. Host `readGvr` keeps the declared GBIX length and aligned bytes, follows the same rounded-down cursor, and uses GVRT length for bounded native data/mip spans. It rejects missing global words/truncated chunks and preserves ignored tail bytes. These bounds checks are explicit host safety differences, not a reconstruction of invalid-input memory reads. Absent GBIX is an absent optional global id, never a fabricated number.

| GVP offset | Size | Meaning established by 0x8011773C |
|---|---|---|
| 0 | 4 | `GVPL` |
| 4 | 4, LE | Chunk data length, including the eight-byte native header |
| 8, 10, 12, 14 | 2 each, BE | Four retained header fields; first word selects Chao conversion mode, remaining meanings unknown (SA2_PALETTE_REFERENCE.md) |
| 16 | length - 8 | Copied native palette payload |
| 8 + length | remaining file bytes | Ignored by original; retained by host |

The original destination contains a payload pointer at +0. Source words +8/+10/+12/+14 are copied to descriptor +4/+6/+8/+10 respectively. Return is 1 for GVPL and -1 otherwise. All 49 retail files contain header words `(1, 0, 0, 48)` and 96 payload bytes; payload word count equals field four on every sample. The later Chao caller proves the first word selects conversion mode: 1 is RGB565. It always processes 48 colors; the other three words and dynamic live palette selection remain unknown (SA2_PALETTE_REFERENCE.md). `GvpPalette` retains those words without interpreting them. Bounds/underflow checks supplement the original unchecked copy.

Example real files: `jet1.GVR`, ISO `0x3EA136C8`, 2,816 bytes, SHA-256 `697136706937aefc49621b6cad0d72938ed5af08f1c05474aa5c7d11ba834714`; `al_child02.GVP`, ISO `0xD33C30`, 112 bytes, SHA-256 `519c34cc2dc7f44a3b41d9c9518dd9be28f7edd0fcf2b281c3fe296d529be6e3`. Complete file offsets, headers and hashes: evidence/sa2-loose-texture-validation.csv.

## GX pixel interpretation and engine API

The retail code uploads native GX data rather than computing RGBA. Pixel interpretation therefore uses an explicit hardware reference: [Dolphin's official GX decoder at the pinned commit](https://raw.githubusercontent.com/dolphin-emu/dolphin/e6f3ae17627e4344da95b13424af5baf4c892b08/Source/Core/VideoCommon/TextureDecoder_Generic.cpp) and its [component expansion tables](https://raw.githubusercontent.com/dolphin-emu/dolphin/e6f3ae17627e4344da95b13424af5baf4c892b08/Source/Core/VideoCommon/LookUpTables.h). RGB5A3 uses 4x4 BE-word tiles; its high bit selects RGB555, otherwise A3/RGB444. Color components expand by bit replication. C4 uses 8x8 tiles with the left pixel in the high nibble. CMPR uses four 4x4 blocks per 8x8 tile: opaque interpolation weights are 5/8 and 3/8; the transparent selector keeps averaged endpoint RGB with alpha zero. These distinctions are why this path does not reuse the existing shared DXT1/color helpers. This reference establishes decoded component bytes, not complete original-game frame appearance.

Include qualified `Importers/SA2/Gvm.h`, `Gvp.h` and `Texture.h` through the existing src root. `readGvr/readGvrFile` return GvrFile; `readGvp/readGvpFile` return GvpPalette. `decodeTexture(GvmTexture, optional explicit RGBA palette)` returns a vector of CPU `Graphics::TextureMip` in original native level order; tile padding is consumed but cropped out of each visible image. Only verified formats 5, 8 and 14 are accepted. Format 8 requires exactly 16 supplied colors. `decodeRGB565Palette(bytes)` explicitly interprets caller-selected BE words; it does not read GVP fields or choose a bank. A caller may supply other established RGBA colors directly.

`Graphics::Texture(width,height,4).createWithMipLevels(levels,minFilter,magFilter,wrapS,wrapT)` is an opt-in primitive requiring a current GL context. It validates the entire RGBA8 dimension/byte chain and sampler values before allocating an object, uploads every supplied level as GL_RGBA8, and sets base/max levels to the supplied range. It neither generates mips nor bleeds transparent RGB. It temporarily clears an unpack PBO and row/skip settings, then restores the active-unit texture binding, unpack-buffer binding, alignment, row length and skips. Existing Texture::create/destroy/use bodies and SADX/Shadow callers remain unchanged. Explicit sampler parameters avoid inventing SA2's material settings. GL_RGBA8 is a byte-preserving storage decision; original shader/gamma/framebuffer behavior remains unknown.

## Validation

Short Python scripts were run once per version. `inspect_sa2_loose_textures.py` extracts only real GVR/GVP FST entries; `validate_sa2_loose_layouts.py` independently checks headers, bounds, tiled sizes and hashes. Quoted result:

```text
files=78 palettes=49 textures=29
palette_header_fields=(1,0,0,48):49; payload word count matches field four: true
standalone formats: RGB5A3=15 CMPR=14; native suffix=0:29; trailing_files=0
```

`validate_sa2_pixels.py` invokes the C++ disc APIs, compares each decoded visible row with unmodified Dolphin code (padded tile dimensions, then crop), and independently records RGBA SHA-256 for each real texture's concatenated original levels. Reference commit `e6f3ae17627e4344da95b13424af5baf4c892b08`, exact source hashes/URLs in evidence/sa2-gx-reference.json. Minimal type/header/XFB link adapters stay in scratch; they do not implement any tested decoder. Quoted result:

```text
real_textures=16081 real_mip_levels=90773 decoded_rgba_bytes=1389730980
formats=CMPR:13835 RGB5A3:2228 C4:18
boundary_cases=7 malformed_cases=22 exhaustive_RGB5A3=65536 exhaustive_RGB565=65536 passed
Dolphin reference: textures=18729 levels=93421 real_palettes=49 explicit_palette_texture_views=2646 all_RGBA_bytes_match
```

The 18 C4 resources use an explicitly supplied synthetic 16-color RGB565 palette for corpus hashes. Separately, each of the 49 real 48-word palette payloads is divided into three diagnostic 16-color windows and interpreted explicitly as RGB565, then tested against all 18 C4 textures: 2,646 comparisons. These test inputs validate C4 lookup/conversion, not which window/format the original game uses. Exhaustive color-word checks cover all 65,536 RGB5A3 and RGB565 values; synthetic CMPR covers endpoint ordering, opaque weights and transparent RGB.

Isolated new/modified C++ units compile with MSVC x64 C++23 /W4 /WX /O2. The GPU fixture uses a hidden GLFW 4.5 context, native samples from landtx13.prs, jet1.GVR and al_body.prs plus a rectangular four-level diagnostic chain. All six minification modes and distinct wrap axes are exercised. Quoted output:

```text
GPU=AMD Radeon RX 9060 XT OpenGL=4.5.0 Core Profile Context 26.8.1.260810
readback_levels=39 rgba_bytes=97968 malformed_uploads=10 unpack_state_restored all_GPU_RGBA_bytes_match
```

Ten invalid upload cases preserve caller state. GPU readback is a storage test on this device, not an original-game render comparison. CPU fixture compilation initially needed assert-expression parentheses; the hidden GPU fixture needed /MD to match vendored GLFW's runtime. Those corrections affect scratch fixtures only. Full engine build: passed (Windows x64 MSVC/Ninja Debug, EDITOR ON, executable link and asset copies; invocation-only Embedded debug information). Existing shared importer hashes and legacy texture method bodies are checked during application/final audit. Linux, EDITOR OFF and default PDB mode remain unverified.

## Decisions, additional discoveries and unknowns

The parallel decoder preserves verified GX math without changing existing SA/Shadow pixels. The additive GPU method preserves original mips without changing existing Texture::create behavior. Palette choice remains explicit: the Chao continuation proves conversion modes and a three-slot texture table, while dynamic palette generation and the GPU consumer remain unknown (SA2_PALETTE_REFERENCE.md). No automatic SA2 disc/key/pool/render/Lua path was invented.

Additional pseudocode observation 0x80119284: accepted four-character chunk tags are GCAM, GJBM, GJCM, GJTL, GLIM, GMDM, GSSM, NJCA, NJCM, NJIN, NJLI, NJTL, NMDM, NSSM; normalized outputs are NCAM, NJBM, NJCA, NJCM, NJIN, NJLI, NJTL, NLIM, NMDM, NSSM. It copies an allocated chunk body and examines a following POF0 chunk. Relocation bytes with top bits 01/10/11 encode 6/14/30-bit deltas in 1/2/4 bytes, accumulated in four-byte words; a nonzero addressed word receives the new body base. Top bits 00 consume one byte without relocation. Null words remain null. Allocation helper 0x801197D0 and post-copy helper 0x800E4E4C are uninspected. This is recorded for the future model target: no real model/POF0 validation, schema or importer is claimed here.

Remaining unknowns/work: three GVP header field meanings, dynamic TLUT/bank selection and packed global-id selector binding; downstream flag bits and retained 16-byte payload suffix; SA2 material sampling/wrapping and whole-frame color treatment; runtime allocation/cache/reference/error/retry behavior and alternate memory descriptors; other executable revisions; models/animation, level geometry/SET/object logic and physics. The bounded standalone-reader/pixel/upload scope is implemented and validated. Playable SA2 content remains unported because its schemas and behavior have not yet been reconstructed.

Engine file changes and impact are listed in ENGINE_CHANGES.md and ai/ENGINE_CHANGES.md; architecture twins and the AI index are updated in the same task.

Chao palette continuation: SA2_PALETTE_REFERENCE.md / ai/SA2_PALETTE.md now establish generated RGB565 blending, three contiguous 16-color groups, the inspected AL_BODY list and palette buffer allocation/free. The new explicit CPU group API feeds existing C4 decoding; runtime slot allocation/region policy, retail FPSCR and full Chao rendering remain unverified. Existing texture reader/decoder/GPU behavior is unchanged.
