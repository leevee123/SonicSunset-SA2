# SA2 Battle: PRS file loading

Status: the PRS stream and disc-file loading entry points are implemented and validated. This is an importer foundation, not a playable SA2 level or character. Compact twin: `docs/ai/SA2_PRS.md`.

## Scope and decisions

The request's target and original-file fields were placeholders. The supplied repository contains `Sonic Adventure 2 - Battle (USA) (En,Ja,Fr,De,Es).rvz`, and its existing importers have no SA2 entry point. The conservative first target is therefore **SA2 Battle PRS files**: recover the retail decoder, validate every `.prs` on that disc, and expose byte loading in C++. Resource layouts and gameplay are separate future tasks; assigning guessed models, textures or behavior to a Lua prefab would not implement this format correctly. No prefab is needed for a byte-stream importer.

The verified token rules match the existing `STH2005::decompressPrs`. The new `SA2` entry points reuse that implementation. This adds an API without modifying either existing game's loader or runtime behavior. The host reader's exceptions for malformed input are retained: reproducing the original's unchecked memory accesses is outside the engine's supported input behavior.

## Source identity and analysis limits

The retail disc identifies itself as **GSNE8P, revision 0, NTSC-U, Sonic Adventure 2 Battle**. DolphinTool converted the supplied RVZ to an ISO without scrubbing. The ISO file table contains 2,819 files, including 1,782 case-insensitive `.prs` names. The generated ISO is 1,459,978,240 bytes. These are file observations, not runtime observations.

`main.dol` starts at ISO offset `0x1E700`, is 1,960,448 bytes, and has SHA-256:

`a53335308d1f820be236fd2b6342fee850eaf048eb26aac21ddb1903b060db2e`

REA 6.3.0 was installed into this chat's scratch directory and its read-only diagnostic was run. Codex registration was missing; no client configuration was changed. REA rejected the DOL as `unsupported binary format`. An analysis-only ELF carrying the unchanged DOL sections was also rejected as `unsupported ELF architecture`. Thus **REA did not recover this decoder**. The connected Ghidra MCP import and subsequent session listing each timed out after 600 seconds without a session identity. Their server state is unconfirmed; no evidence from those requests is used here.

The fallback was the already-installed Ghidra 12.1.4 headless analyzer and JDK 21.0.12.1. Eight initialized DOL sections were mapped byte-for-byte at their original addresses into an ELF32 analysis image. Each copied section was compared against the DOL. The DOL's BSS interval overlaps initialized sections, so the final analysis image maps only the non-overlapping portions as uninitialized memory. The first exploratory image produced a BSS warning and selected e500 automatically; it was superseded by the corrected image and an explicit `PowerPC:BE:32:default` language. Neither executable instructions nor original game files were patched. This language does not establish Gekko-specific floating-point behavior; the PRS function uses ordinary integer instructions.

The corrected image has entry `0x80003140` and SHA-256:

`690b91d220ac6a4bf6e160e304e5de21e64407154d84cce4b0e577cec1dcb6da`

The reusable scratch evidence is under `C:\Users\naync\Documents\Codex\2026-10-10\you-are-reverse-engineering-sonic-adventure\work`: `disc-evidence.json`, `dol-elf-mapping-final.json`, `prs-evidence-final/`, the Python validators and `prs-validation-summary.json`. No original source tree was used and no leaked original source was encountered. This checkout has no `.git` directory; changes are supplied as a patch and original edited files are backed up in the chat workspace.

## Original functions and locations

All addresses below refer to the above retail `main.dol`. Offsets are relative to the DOL, not the disc. They were calculated from its section table with a scratch Python script.

| Function | DOL offset | Established behavior |
|---|---:|---|
| `FUN_800D2684` | `0xCF684` | PRS decoder: source pointer and destination pointer; returns destination bytes written. This is the source of every token rule below. |
| `FUN_8001A088` | `0x17088` | Calls `FUN_8001ACAC(param_1, 0x80FFFE60, 0)`; if its return is nonnegative, decodes that scratch buffer into `param_2`. The helper's internal I/O and capacity rules remain unread. |
| `FUN_8007237C` | `0x6F37C` | Includes three-attempt call loops, computes a read region using `0x800`-byte units, calls the decoder, then `FUN_80118FC0`. The called helpers' resource semantics remain unread; these operations are not implemented by the new stream API. |

Ghidra found these direct callsites. They establish calls, not the meaning of the callers' resources:

| Caller entry | Caller DOL offset | Decoder callsite | Callsite DOL offset |
|---|---:|---|---:|
| `0x8001A0DC` | `0x170DC` | `0x8001A118` | `0x17118` |
| `0x8001A8A8` | `0x178A8` | `0x8001A9B0` | `0x179B0` |
| `0x8001A190` | `0x17190` | `0x8001A238` | `0x17238` |
| `0x80072458` | `0x6F458` | `0x80072520` | `0x6F520` |
| `0x8001A3BC` | `0x173BC` | `0x8001A4BC` | `0x174BC` |
| `0x8001A5B0` | `0x175B0` | `0x8001A678` | `0x17678` |
| `0x8001A088` | `0x17088` | `0x8001A0C0` | `0x170C0` |
| `0x8007237C` | `0x6F37C` | `0x80072434` | `0x6F434` |

Other scalar-search candidates included `FUN_8013DADC` and `FUN_8014B8F4`; inspecting their pseudocode showed they were not the PRS decoder. No gameplay meaning is assigned to them. The search covered decoded functions with operands `0xE000`, `0x1FFF` or `0xFFFFE000`; the direct-caller list is an analysis result, not proof that every indirect use was found.

## Stream layout and order of operations

`FUN_800D2684` reads byte zero as control data. PRS itself has no magic, size header, name table, relocation table or stored pointers. The decompressed payload can have its own header, which is not described by this stream format.

Control bytes are interleaved with payload bytes. Consume their bits least-significant first, refilling from the current source cursor after eight consumed bits. Refill can occur between the two prefix bits or between short-copy length bits. Payload bytes do not consume control bits.

| Control bits, in consumption order | Payload bytes | Action |
|---|---|---|
| `1` | One byte | Append that literal byte. |
| `0 0 b1 b0` | One unsigned byte `d` | Length `2 + 2*b1 + b0`; displacement `d - 256`. |
| `0 1` | Two bytes `lo`, `hi` | Form little-endian word `v = lo + (hi << 8)`. **Raw `v == 0` terminates immediately**, before computing a displacement or reading an extended length. |
| `0 1`, `v != 0`, low three bits nonzero | No further bytes | Displacement `(v >> 3) - 8192`; length `(v & 7) + 2`. |
| `0 1`, `v != 0`, low three bits zero | One unsigned byte `n` | Same displacement; length `n + 1`. |

The short displacement is -256 through -1; its length is 2 through 5. The long displacement is -8192 through -1; inline lengths are 3 through 9 and extended lengths 1 through 256. Words 1 through 7 are not end markers: their displacement is -8192. All integer token fields have the above explicitly stated byte ordering even though the console is big-endian.

Copies read already-written output at the negative displacement and write forwards byte by byte. Overlap is required: newly written bytes may become source bytes for the same copy. `memcpy`, or reading an entire overlapping copy before any writes, would change this behavior. After an end marker the decoder returns without examining unused control bits or any following source bytes. It performs no input-length, output-capacity or backward-copy bounds checks.

### Pseudocode gap resolved with assembly

The decompiler's unrolled copy tail prints a `goto joined_r0x800d2808` that can look like it enters a copy loop with zero remaining bytes. The original instructions resolve this:

- `0x800D27B8` through `0x800D2800` alternate byte loads and stores for eight-byte groups, preserving overlap.
- `0x800D2804` masks the remaining length with 7.
- **`0x800D2808` (`main.dol` offset `0xCF808`) branches back to the token loop when that remainder is zero.**
- Otherwise `0x800D280C` through `0x800D2820` copy the remaining bytes.

The engine's existing forward byte-copy loop has the same resulting bytes. Validation exercised 1,337,824 real copy commands whose lengths are multiples of eight; the synthetic test also covers this branch. No other decoder gap remains unresolved.

## Validation on the supplied disc

`work/validate_sa2_prs.py` was run once against all real PRS files. It independently implements the recovered token rules, checks source exhaustion and copy bounds, and records complete per-file offsets, lengths and SHA-256 hashes in `docs/evidence/sa2-prs-validation.csv`. Overlapping copies use a repeated source period, which gives the same byte sequence as forward byte copies; the C++ comparison independently checks those resulting bytes.

Quoted result:

```text
files=1782; compressed_bytes=175266629; decoded_bytes=330438533
trailing_files=0; max_trailing_bytes=0
literal=99138243; short=13299774; long_inline=15807336; long_extended=2527754
overlapping=879962; multiple_of_eight=1337824
```

Every stream reached an end marker exactly at its file's end. No invalid backward copy or premature source exhaustion occurred. These findings validate this disc's files; they do not establish an inner model or texture format or simulate the original game's execution.

| Sample | ISO file offset | Compressed bytes | Decoded bytes | Decoded observation |
|---|---:|---:|---:|---|
| `advShareData.prs` | `0x4BD7A4` | 3,629 | 34,960 | Bytes 0..3 are ASCII `GVMH`. |
| `landtx13.prs` | `0x3F35FA0C` | 863,451 | 1,036,624 | Bytes 0..3 are ASCII `GVMH`. |
| `sonicmdl.prs` | `0x479024A4` | 102,331 | 136,360 | First 16 bytes: `0000000100010f2c000000020000cf68`; fields are unknown. |

Decoded SHA-256 values, in the same order:

```text
65bc0132950db993ce660f92e144694083d027726a10270c4a8228a31ea31c2b
d94f1c19a5dbdd15173ea07e88cc940ca5fdb36b7a7189bc70d8659fb191128d
b7ea586ed0fa22330dc8a2cfe2bb8fa9ce4ac70d9561764f35af4ced5d371963
```

A temporary MSVC x64 harness compiled the new entry points with `/std:c++latest /W4 /WX /O2`, the unchanged GameCube disc reader and the unchanged Shadow decoder. It loaded every file through `SA2::readPrsFile`. A second Python script was run once to compare the full decoded length and SHA-256 with the independent validator:

```text
C++ SA2::readPrsFile: 1782/1782 real files match Python length and SHA-256.
boundary_cases=13 malformed_cases=6 passed
```

The 13 synthetic cases cover empty streams, ignored trailing bytes, literals, all short lengths, inline and extended long copies, overlap, maximum extended length, eight-byte lengths, refills within a short command and raw long word 1. The six malformed cases cover missing control/payload/end bytes, impossible backward copies and missing extended length. Rejected malformed inputs are an explicit host-engine difference from the unchecked original.

### Full engine build

The first CMake/Ninja Debug configuration failed in the compiler's own ABI check with MSVC error `C1902: Program database manager mismatch`, before compiling engine code. An invocation-only `-DCMAKE_MSVC_DEBUG_INFORMATION_FORMAT=Embedded` workaround allowed configuration; no repository build setting was changed. The resulting full build compiled the SA2 unit and exposed an existing missing `<limits>` dependency in `src/Misc/PoolId.h` at its `std::numeric_limits<uint32_t>::max()` defaults. Adding that one include was the smallest build prerequisite; its layout, defaults and pool logic are unchanged. It is separately listed in `docs/ENGINE_CHANGES.md` and the architecture twins.

The subsequent full **Windows x64 MSVC/Ninja Debug, EDITOR ON** build succeeded, linked `SonicSunset.exe`, and copied the existing assets. Quoted result: `engine build exit 0`. The executable is in the chat's `work/engine-build/`; it was not launched for gameplay or visual verification. Linux, EDITOR OFF, the default local program-database debug mode and original-game runtime behavior were not validated by this build. The original compiler-debug-manager failure remains an environment limitation; the embedded-debug workaround is only a build invocation.

## Engine use and remaining work

Include `Importers/SA2/Prs.h`. `SA2::decompressPrs(bytes)` returns the decoded bytes. `SA2::readPrsFile(disc, path)` reads an exact disc-relative path with the existing `GameCube::GCDisc`, then decodes it. A caller supplies an already-open ISO/GCM disc; this API neither opens RVZ files nor adds a global SA2 disc or resource pool. Errors propagate as the existing disc/PRS exceptions. `CMakeLists.txt` compiles the new unit; existing include roots already resolve the qualified header.

Unknowns outside the completed stream target: the layouts and relocation rules of decoded model/motion payloads; original texture GPU state, palettes and standalone GVR/GVP (compressed GVM container compatibility is now resolved in `SA2_GVM_REFERENCE.md`; it requires the new parallel SA2 reader); stage placement and object dispatch; original resource allocation, buffering, error/retry and post-load processing; player behavior and constants; region/revision and Dreamcast differences; indirect decoder callers. The City Escape candidates `set0013_s.bin`, `set0013_u.bin`, `set0013_hd_s.bin`, `set0013_2p_s.bin` and `set0013_2p_u.bin` are observed file-table names only; their layouts and stage association are not established here. No level, character, object or enemy has been reconstructed from those names.

Also observed: the current CMake file supports Windows as well as Linux, despite the prior compact build summary saying Linux only. The architecture twins now reflect the actual build configuration. No unrelated engine cleanup was performed.
