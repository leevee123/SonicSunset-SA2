# SA2 Battle: GVM texture containers

## Scope and status

Continuing the verified PRS foundation, the conservative next target is the **compressed GVMH/GVRT container and native texture resource** on the supplied GSNE8P revision 0 disc. `SA2::readGvm` and `SA2::readGvmPrsFile` load entry metadata and every native mip level without needing OpenGL. All 605 compressed archives and 16,052 textures passed independent validation. The next continuation now decodes GX pixels and offers original-mip GPU upload, documented in SA2_TEXTURE_REFERENCE.md / ai/SA2_TEXTURE.md. Keeping indexed data and original mip bytes avoids guessing a live palette or replacing the original mip chain. A format importer is not a level or character, so it introduces no Lua prefab.

This is a parallel SA2 path. The existing SADX GVM importer accepts only header flags 0xF, two formats and mip level 0; retail SA2 includes other flags and indexed format 8. Its `Texture::create` also regenerates mipmaps and changes transparent pixel colors. Calling that path would lose verified retail data. At the container step no shared importer, GPU texture resource or renderer was changed. The later opt-in GPU method is listed separately in ENGINE_CHANGES.md; existing create behavior remains unchanged.

## Source and analysis

Retail identity, DOL extraction/mapping and PRS evidence remain in `SA2_PRS_REFERENCE.md` / `ai/SA2_PRS.md`: GSNE8P revision 0, DOL SHA-256 `a53335308d1f820be236fd2b6342fee850eaf048eb26aac21ddb1903b060db2e`. REA 6.3.0 cannot inspect this DOL or its byte-preserving PowerPC ELF wrapper; the existing installed Ghidra 12.1.4 headless project supplied the pseudocode. No app configuration was changed. No leaked original source was encountered or used.

The PRS caller `0x8007237C` (DOL `0x6F37C`) reaches the texture loader at `0x80118FC0` after decompression. All function offsets below were calculated from the extracted DOL section table by `stage_gvm_docs.py`, not by subtracting an assumed global base. Pseudocode is the main evidence. Raw instructions were used only for Ghidra's incorrect apparent argument returns through save/restore stubs: `0x8010AFB0..0x8010AFE0` saves r20..r31 and `0x8010AFFC..0x8010B02C` restores them. Neither range changes argument registers r3..r10. The loader's assembly at `0x80118FD4` / `0x80118FD8` retains incoming r3/r4 as source/list; the decompiled `undefined8` helper return is an analysis artifact.

| Retail function / stub | DOL file offset | Observed operation |
|---|---|---|
| `0x80118FC0` | `0x115FC0` | Load GVMH; assign each GVRT ordinal to the first matching stored entry index; require consecutive GVRT blocks after the first. |
| `0x80118BFC` | `0x115BFC` | Swap a 32-bit word; used on chunk magic and length, not on entry/header fields. |
| `0x80118C34` | `0x115C34` | Initialize base and current stream pointers. |
| `0x80118C44` | `0x115C44` | Return current pointer and advance by requested byte count; no bounds check. |
| `0x80118C5C` | `0x115C5C` | Seek relative to base (mode 0) or current pointer (mode 1). |
| `0x80118CEC` | `0x115CEC` | Read entries; optional name, skip format/dimension metadata, BE global value; bit 0x400 selects packed global/bank interpretation. |
| `0x80118E28` | `0x115E28` | Calculate entry stride from flags 1/2/4/8; high bits do not change stride. |
| `0x80118E78` | `0x115E78` | Skip arbitrary length-delimited chunks before first GVRT; rewind four bytes at GVRT. |
| `0x80118C94` | `0x115C94` | Copy two bytes without swapping. |
| `0x80118CB0` | `0x115CB0` | Copy four bytes without swapping. |
| `0x8011733C` | `0x11433C` | Find/register native texture; cached entries may bypass data allocation/copy. Runtime cache not ported. |
| `0x80117290` | `0x114290` | Copy native texture data into existing allocation using computed size. |
| `0x80117164` | `0x114164` | Allocate texture record; assign global id, indexed-format selector and reference counts. Runtime registry not ported. |
| `0x80116FD4` | `0x113FD4` | Find/reuse cache entry and increment native reference counts. Runtime registry not ported. |
| `0x80116F38` | `0x113F38` | Mask offset/count to four-byte alignment; copy min(requested bytes, remaining allocation); zero length succeeds, offset beyond allocation returns 7. |
| `0x801163A0` | `0x1133A0` | Decode native entry flags: 0x800000 full global id; 0x1000000 lower 26-bit global id plus upper 6-bit selector; 0x10000 non-first entry reuses previous native texture. |
| `0x80116310` | `0x113310` | Pass GVRT BE dimensions and combined header word to native setup. |
| `0x80116684` | `0x113684` | Return 1 for native format byte 8, 9 or 10; otherwise 0. |
| `0x80117418` | `0x114418` | No-op in this executable (blr). |
| `0x801166AC` | `0x1136AC` | Run texture setup, then allocate only when setup returns 0. |
| `0x80117808` | `0x114808` | Format = low byte; width/height; header bit 0x100 sets internal 0x80000000 and rejects nonsquare dimensions; bit 0x200 sets 0x8000. |
| `0x80117904` | `0x114904` | Allocate computed native byte count via unread helper 0x800E4554; zero allocation returns 3. |
| `0x801178A8` | `0x1148A8` | Call native size calculation with low 16-bit dimensions, format, mip flag, maximum 100 levels. |
| `0x80103128` | `0x100128` | Round native dimensions to whole tiles at every level; clamp halved dimensions to 1; stop at 1x1 or level cap. |
| `0x8010AFC4` | `0x107FC4` | Fall-through save r25..r31; does not return new loader arguments. |
| `0x8010AFB0` | `0x107FB0` | Fall-through save r20..r31. |
| `0x8010AFC8` | `0x107FC8` | Fall-through save r26..r31. |
| `0x8010AFCC` | `0x107FCC` | Save r27..r31, then return. |
| `0x8010B010` | `0x108010` | Fall-through restore r25..r31. |
| `0x8010AFFC` | `0x107FFC` | Fall-through restore r20..r31. |
| `0x8010B014` | `0x108014` | Fall-through restore r26..r31. |
| `0x8010B018` | `0x108018` | Restore r27..r31, then return. |

Complete pseudocode, raw gap evidence and source hashes remain in this task's `work/sa2-gvm-evidence`; the repository stores portable raw file/texture evidence in `docs/evidence/sa2-gvm-validation.csv`.

## GVMH layout

There is no relocation or compression inside this container. The enclosing PRS is decoded first. All offsets below address decoded bytes.

| Offset | Size | Encoding | Meaning / evidence |
|---|---|---|---|
| 0 | 4 | ASCII | `GVMH`; swapped-word comparison in 0x80118FC0. |
| 4 | 4 | little-endian u32 | Header chunk data length; first following chunk starts at 8 + this value, independently of entry-table length. |
| 8 | 2 | big-endian u16 | Flags. Lower bits select fields; bit 0x400 changes global-id interpretation. Preserve all bits. |
| 10 | 2 | big-endian s16 in original | Entry count. All observed counts are positive. Host accepts 1..32767. |
| 12 | variable | entry array | `count` entries of flag-dependent stride; any remaining header bytes are skipped by original and retained as `headerPadding`. |

Entry fields are consecutive, in this order (`0x80118E28`, `0x80118CEC`):

| Condition | Size | Encoding | Field |
|---|---|---|---|
| always | 2 | big-endian u16 | Stored texture index. GVRT ordinal 0..count-1 is mapped by this index to its entry, rather than by entry position. |
| flags & 1 | 28 | bytes | Name, zero-terminated when a zero occurs; host bounds the name to 28 bytes. |
| flags & 2 | 2 | big-endian raw u16 | Format metadata; original skips it. No invented interpretation. |
| flags & 4 | 2 | big-endian raw u16 | Dimension metadata; original skips it. No invented interpretation. |
| flags & 8 | 4 | big-endian u32 | Raw global value. With bit 0x400 clear the original stores a full global id; with it set, 0x801163A0 uses the low 26 bits and upper six-bit selector. Host retains the raw value. |

Stride is 2 + 28*(flags&1 != 0) + 2*(flags&2 != 0) + 2*(flags&4 != 0) + 4*(flags&8 != 0). Retail flags: 0xF (590 archives, stride 38), 0x109 (11, stride 34), 0x10F (3, stride 38), 0x509 (1, stride 34). Meaning of bit 0x100 is unknown; it changes no field reads in these functions. All 605 retail index tables are in order; shuffled valid indices are nevertheless supported and tested, matching the original lookup. Duplicate/out-of-range indices are rejected by the host, rather than emulating the original unchecked list access.

At the declared header end, `0x80118E78` scans chunks as `magic[4]`, LE u32 data length, raw data. It skips **any** non-GVRT chunk, including its listed COMM/PVMI/IMGC/GVPL/MDLN/CONV cases, until the first GVRT. Thereafter `0x80118FC0` requires exactly `count` consecutive GVRT chunks. Every observed compressed archive has only GVRT chunks after its header; the portable reader preserves skipped chunks, tested synthetically, without assigning meaning to them. The original returns after the texture count; the host retains any remaining bytes as `trailingBytes`.

## GVRT and native mip layout

| Offset from GVRT | Size | Encoding | Meaning |
|---|---|---|---|
| 0 | 4 | ASCII | `GVRT`. |
| 4 | 4 | little-endian u32 | Data length, including the eight-byte native header. Next block = current + 8 + length. |
| 8 | 2 | big-endian u16 | Reserved header word, zero in all 16,052 textures; retained. Native setup does not use its high 16 bits. |
| 10 | 1 | raw u8 | Data flags. Bit 0 sets the mip flag; bit 1 sets an internal 0x8000 flag. All flags retained. |
| 11 | 1 | raw u8 | Native format: 5 / 8 / 14 on this corpus (existing GX names RGB5A3 / C4 / CMPR). |
| 12 | 2 | big-endian u16 | Width. |
| 14 | 2 | big-endian u16 | Height. |
| 16 | length - 8 | bytes | Native tiled payload, all mip levels and suffix bytes retained unchanged. |

Native setup `0x80117808` takes the low-byte format, dimensions and flags. A mipmapped texture must be square or it returns 4. `0x801178A8` calls `0x80103128` with a 100-level limit. For the three observed formats: format 5 uses 4x4 / 32-byte tiles; 8 and 14 use 8x8 / 32-byte tiles. Each level independently rounds dimensions up to whole tiles. With bit 0 clear there is one level. Otherwise dimensions halve by integer shift, each clamps to one, and the chain stops after 1x1. The port exposes verified byte spans; it does not decode palette indices or colors.

Native allocation/copy uses this calculated chain size (`0x80117904`, `0x80117290`, `0x80116F38`), not the whole GVRT payload length. Of 16,052 payloads, 15,563 exactly match the calculation; 489 have a further 16 bytes (354 format 14, 117 format 5, all 18 format 8). No payload is too short. The host retains that suffix, but does not include it in a mip span. Its meaning is unknown, so it is not called padding. The original copy masks offsets/counts to four-byte alignment and clamps to allocation capacity; its cache/refcounts, allocator, errors and already-loaded-texture skip behavior are recorded above but not reproduced by this CPU data resource.

Formats: 13,821 native 14; 2,213 native 5; 18 native 8. Data flags: 0 (3,527), 1 (11,074), 8 (602), 2 (18), 9 (831). Native flag 2's internal 0x8000 and flag 8's meaning downstream remain unknown. Indexed format 8 appears in `al_body.prs`. There are also 29 loose `.gvr` and 49 `.gvp` files in the FST; the later standalone/pixel continuation validates those layouts (SA2_TEXTURE_REFERENCE.md), while live palette binding remains unknown.

## Validation and samples

Python `inspect_gvm_corpus.py` ran once and independently decoded all PRS files whose previously validated prefix is GVMH. It checked original decoded SHA-256, header bounds, flag stride, index permutation, every GVRT block end and declared count. `check_gvm_sizes.py` ran once and checked every native mip-size calculation. Their compact outputs were:

```
archives=605 textures=16052 flags={15:590,1289:1,265:11,271:3}
formats={14:13821,5:2213,8:18} data_flags={0:3527,1:11074,8:602,2:18,9:831}
reserved={0:16052} chunks={GVRT:16052} indices_in_order={true:605}
payload_minus_native_size={0:15563,16:489} short_count=0
```

| Sample | ISO offset | PRS bytes | Decoded bytes | Textures |
|---|---|---|---|---|
| `advShareData.prs` | `0x4BD7A4` | 3629 | 34960 | 2 |
| `landtx13.prs` | `0x3F35FA0C` | 863451 | 1036624 | 126 |
| `al_body.prs` | `0xD24414` | 63516 | 127712 | 143 |
| `al_body.prs` | `0xD24414` | 63516 | 127712 | 143 |

`compare_cpp_gvm.py` ran once through the C++ `readGvmPrsFile` ISO entry point and compared every header field, payload size/hash and native mip span to independent Python evidence:

```
boundary_cases=23 malformed_cases=14 passed
C++ SA2::readGvmPrsFile: 605/605 archives, 16052/16052 textures match Python headers, mip spans, payload lengths and SHA-256. native_bytes=225090768 mip_levels=90719
```

The 23 valid boundary cases cover all 16 optional-field combinations; non-file entry order; arbitrary skipped chunk/header/tail retention; native formats 5/8/14 including mip chains; whole native tiles for a 1x1 image; suffix retention; and a 28-byte name without NUL. The 14 malformed cases cover header/table/payload truncation, bad signatures/lengths, duplicate/out-of-range indices, nonsquare mip dimensions, zero dimensions/count, signed-negative count, and unsupported format. Host checks are deliberate safety differences from the original unchecked reader; valid corpus behavior is preserved.

The isolated MSVC x64 C++23 build used /W4 /WX /O2 and passed. Full Windows x64 MSVC/Ninja Debug engine build with EDITOR ON passed, including executable link and asset copies, with the same invocation-only embedded-debug-information workaround used for PRS. The executable/assets are retained in this task’s `work/engine-build-gvm` as build evidence; Linux, EDITOR OFF and the default PDB mode remain unverified. Details are also recorded in ENGINE_CHANGES.md and its twin. No SA2 rendering or gameplay was run. Raw evidence CSV includes each texture's PRS ISO offset, compressed size, archive decoded hash, decoded GVRT offset, complete native payload hash and header fields.

## Engine API, decisions and remaining unknowns

Include `Importers/SA2/Gvm.h` through the existing src include root, avoiding a basename collision with Ninja/Gvm.h. `SA2::readGvm(bytes)` returns `GvmArchive`; `SA2::readGvmPrsFile(disc,path)` composes the verified PRS reader. `textures` preserves entry-table order while `entry.index` identifies native block ordinal. Missing optional fields are std::optional, not fabricated defaults. `data` is unchanged native bytes; `mips` addresses offsets in data, including GX tile padding. Header padding, skipped prefix chunks and ignored trailing bytes are retained separately. No global SA2 resource pool, key, disc selection or Lua API is added.

This completes the compressed GVM **container/resource** scope on the supplied revision. Standalone GVR/GVP, hardware-referenced GX pixel conversion and opt-in original-mip upload are now implemented in SA2_TEXTURE_REFERENCE.md. Chao palette conversion and its three-slot table are now documented in SA2_PALETTE_REFERENCE.md. Remaining work: three palette header meanings, dynamic palette/GPU binding and upper-six-bit selector binding; downstream flags and the 16-byte suffix; original sampling/wrapping/material and whole-frame color state; runtime cache/refcounts and allocation/error/retry semantics; other versions. SA2 models, animation, stage geometry/SET/object logic and physics remain unported. Byte-layout observations about these textures do not establish playable content. No unknown value is filled in.
