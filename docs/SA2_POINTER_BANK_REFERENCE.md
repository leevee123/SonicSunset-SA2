# SA2 Sonic pointer-bank loading

The C++ engine can now read the original Sonic model-bank container and reproduce its bounded pointer conversion. The real `sonicmdl.prs` sample yields 64 table entries, 200 distinct linked nodes and 115 opaque payloads. All 529 pointer writes match the original routine's values and order. This establishes data loading; geometry, animation and gameplay remain unfinished.

## Original code and sample

The source is retail SA2 Battle **GSNE8P, disc 0, revision 0**, main DOL SHA-256 `a53335308d1f820be236fd2b6342fee850eaf048eb26aac21ddb1903b060db2e`. REA 6.3.0 does not handle these DOL/PPC inputs; this pass reuses the existing Ghidra 12.1.4 Gekko exports. Pseudocode is read first, with original words/assembly resolving omitted arguments and pointer order. No analysis project was opened or frozen export changed.

| Function VA | DOL offset | ISO offset | Observed use |
|---|---|---|---|
| `0x800874C0` | `0x844C0` | `0xA2BC0` | Filename selection and returned blob storage |
| `0x80050210` | `0x4D210` | `0x6B910` | Sentinel scan, registry and root traversal |
| `0x8001A190` | `0x17190` | `0x35890` | File-size/read/PRS/allocation/copy pipeline |
| `0x8002F88C` | `0x2C88C` | `0x4AF8C` | Node and opaque-payload pointer adjustment |
| `0x8001ACAC` | `0x17CAC` | `0x363AC` | Read wrapper |
| `0x800D2684` | `0xCF684` | `0xEDD84` | Verified PRS decoder |
| `0x801197D0` | `0x1167D0` | `0x134ED0` | Dynamic size-allocation dispatch |
| `0x800EECFC` | `0xEBCFC` | `0x10A3FC` | FST pathname lookup |
| `0x8010BA44` | `0x108A44` | `0x127144` | Byte comparison mapping |

All 17 selected functions, both C views and outgoing graphs have source hashes and coordinates in `docs/evidence/sa2-sonicmdl-loader-source-verified.csv` and `sa2-sonicmdl-loader-calls-verified.csv`. The ISO DOL at `0x1E700` matches the protected original. The sample is FST entry 2428, entry ISO `0x2042D0`, filename ISO `0x20DC97`, stored data ISO `0x479024A4`, length **102331 bytes**. Its compressed SHA-256 is `d8f90e6c724e709b8d3431e725a5db1d1a096bdf5118d2ecca9ad356e7862d99`; decoded length **136360 bytes**, SHA-256 `b7ea586ed0fa22330dc8a2cfe2bb8fa9ce4ac70d9561764f35af4ced5d371963`. Internal offsets are decoded-file offsets; PRS prevents assigning them individual ISO offsets. Synthetic view addresses are separate from retail addresses.

## Filename, read and allocation path

`0x800874C0` passes literal **SONICMDL.PRS** at VA `0x8017494C` / DOL `0x17194C` / ISO `0x19004C` to `0x80050210` at BL `0x800875F8` / DOL `0x845F8` / ISO `0xA2CF8`, then stores the returned blob at its allocated block `+0x398`. The branch is selected when byte `0x801CC186` is zero or the incoming-argument-indexed byte at `0x801CC1BB` is zero. An indexed value of one selects **SONIC1MDL.PRS**; an earlier condition can divert to `0x800871C4`. Those payloads and the conditions' gameplay meanings remain unvalidated. The discovery also retains a **METALSONICMDL.PRS** request at `0x80086BA4`; no format claim is made for it.

The scanner preserves the incoming filename in `r3` through BL `0x80050228` to `0x8001A190`; its generated argumentless signature drops that input. The latter saves the name, opens through `0x80119D64`, obtains byte length through `0x80119EC4`, closes through `0x80119E6C`, and computes compressed scratch space as `0x811FFE60 - (((size + 0x7FF) arithmetic-shift-right 11) << 11)`. It calls `0x8001ACAC` with that name/scratch address and, for a nonnegative wrapper result, decodes through `0x800D2684` into `0x80FFFE60`. The decoded length reaches `0x801197D0` in `r3`, and the allocation result remains in `r3`. The default backend is now bounded in [SA2_CALLBACK_REFERENCE.md](SA2_CALLBACK_REFERENCE.md); the actual runtime table choice and heap address remain unknown.

A nonzero returned pointer receives a word copy through `0x80119730`: `(decodedLength >> 2) + [low two bits != 0]` words, then the loader returns that pointer. Observed open/size, negative wrapper-result and allocation failure paths return zero. The read wrapper has an original quirk: after a successful open it calls `0x80119EF0`, closes, then returns zero without propagating the read result. Thus a static nonnegative result does not prove successful I/O.

For this sample the scratch reservation is **102400 bytes**, address `0x811E6E60`. The lower reader's final request rounds to 32 bytes, reading **102336 bytes**, including five bytes beyond the stored file length. PRS consumes all 102331 stored bytes and stops at its end marker. The decoded copy is exactly 136360 bytes with no added word padding. These numbers came from the one-run sample script, not visual estimation.

The wrapper's cached-read substring tests are `cam.prs`, `.bin`, `.BIN`, `.BMP`, `.bmp`; none matches SONICMDL.PRS. The visible route therefore uses the FST wrapper. `0x800EEFF0` resolves through `0x800EECFC`, which maps bytes through `0x8010BA44` and original table `0x801764B8`. The actual mapping equates the uppercase request with the FST's lowercase `sonicmdl.prs`; case handling was verified from those bytes.

## Established fields and conversion order

| Decoded location | Type/size | Original handling |
|---|---|---|
| Entry `+0` | BE signed 32-bit ID | Exactly `0xFFFFFFFF` terminates before the following word is read. Other entries advance eight bytes. Registration is eligible for `0 <= ID < 0x214`, or decimal 0..531. |
| Entry `+4` | BE 32-bit root pointer | Zero stays zero; nonzero with bit 31 clear gains the decoded-buffer base; a high-bit word is kept. Every nonzero root is traversed regardless of ID eligibility. |
| Node `+4` | BE 32-bit pointer | If nonzero/bit 31 clear, convert it and adjust its target's first two words. Already-high pointers skip that inner conversion. |
| Node `+4` target, `+0`/`+4` | Two BE 32-bit words | Each nonzero word gains the base **without an inner bit-31 test**, only during the preceding conversion step. Payload meanings remain unknown. |
| Node `+0x2C` | BE 32-bit link A | Convert low positive pointer, then recurse first. |
| Node `+0x30` | BE 32-bit link B | Convert low positive pointer, then recurse second. |

`0x8002F88C` saves node `+4`, `+0x2C` and `+0x30` before any store. It processes the payload, converts/traverses saved A, then converts/traverses saved B. Repeated nodes are revisited; there is no global visited-node pruning in the original. A node needs at least `0x34` (52) readable bytes and an opaque target at least eight. These are minimum observed spans, not complete structure sizes. Node fields `+0`, `+8..+0x28`, complete payloads, geometry, transforms, vertices and animation are unnamed.

The scanner computes registry slot `0x801E6688 + ID*8` and uses its word `+4`; it stores the converted root only for eligible IDs whose prior slot word is zero. The other word and prior contents are unknown. The exact compare at VA `0x8005025C` / DOL `0x4D25C` is word `0x2C000214`: **532 slots**, not decimal 214. The preserved early agent prose omitted hexadecimal notation; source, sample script and C++ already used `0x214`.

There is no proven count/header, magic, alignment condition, bounds check or cycle guard here. The table ID is reread from current bytes on every iteration; earlier pointer writes can alias a future ID or sentinel and change termination. The sample's sentinel is at decoded `0x200`, followed by a zero word that the original does not inspect for termination. Native registry/global-memory alias effects remain outside the engine view.

## Engine resource and validation

Include `Importers/SA2/PointerBank.h`. `SA2::readPointerBank(vector)` retains all decoded bytes, raw `{fileOffset,id,pointer}` entries and the original sentinel offset; `readPointerBankPrsFile(GCDisc&,path)` uses the unchanged disc/PRS route. `PointerBankEntry::isRegistryEligible()` exposes the proven range without filtering entries. `buildPointerBankView(bank,base)` copies bytes and produces ordered node visits, opaque-target visits and `{fileOffset,before,after}` stores. It scans its mutable copied IDs, so aliasing can change a later terminator. The original metadata and bytes are preserved.

The conservative supported scope is a declared high-bit 32-bit base with self-contained pointers. Host bounds, address-range and active-path cycle errors reject unverified cases; these guards are not original malformed-file behavior. Explicit stack frames reproduce recursion order without host recursion, and active-path checks allow repeated visits on separate paths. No native allocation, registry, execution, resource pool, rendering or Lua content is added. This neutral name avoids assigning GNO/Ninja semantics before the payload is proven.

`validate_sample_v1.py`, run once, verified **42 immutable source artifacts, 863 exported ASM rows and 195 independently parsed original words**, including both views' branch targets. The 64 sample IDs are distinct and eligible; every root is nonzero/relative. An independent original-order simulation with synthetic base `0x81000000` and initially empty registry visits **688 nodes (200 distinct)** and **115 opaque targets**, making **529 stores**, with no cycle/bounds failure. Its resulting SHA-256 is `7d67b1ed6d86009780b34cd52bd767f57fca364126711e62331fa0165914a90c`. This is a host experiment, not retail execution.

`validate_pointer_bank_v3.py`, run once, verifies every C++ entry, store offset/before/after/order, node visit count and payload target against that independent evidence; all bytes and the resulting hash match. **Five preservation and eleven host rejection cases pass**, including a converted later ID becoming a sentinel and an original sentinel being changed before it is reached. Strict Windows x64 MSVC `/std:c++latest /W4 /WX /O2` compilation passes. V1 passed the real sample before review added those overlap cases; V2 failed a stale repository-hash guard before launching C++, and its preserved V3 correction passes. Earlier failures are retained in the evidence history.

The full Windows x64 MSVC/Ninja Debug EDITOR ON engine build passes, including the new unit and executable link. The final overlap-fix rebuild recompiles PointerBank and reuses the unchanged compiled REL unit. Only the existing invocation-only Embedded debug workaround is used; repository build defaults stay unchanged. Linux, EDITOR OFF and existing-game runtime are untested. The other 239 preexisting guarded engine/content files remain unchanged. Engine file list and effect: [ENGINE_CHANGES.md](ENGINE_CHANGES.md).

The local `outputs/SA2-Data-Check/Start-SA2-Data-Check.cmd` is a double-click test using the existing disc and bundled Python. It passes all **95 REL views / 104389753 section bytes**, preserving **24 foreign import streams**, plus this Sonic bank. It saves paired `Last-result.md/.ai.json`, reads the original disc without modification and packages no game media. Geometry, animation and gameplay are still unfinished; the existing texture preview remains available separately.

## Evidence and remaining work

Compact current truth: `docs/ai/SA2_POINTER_BANK.md`. Complete raw evidence is `docs/evidence/sa2-sonicmdl-*.csv`, the paired original reports under that prefix, `sa2-pointer-bank-engine-validation.md/.ai.json`, `sa2-pointer-bank-registry-limit.md/.ai.json`, `sa2-pointer-bank-validator-history.md/.ai.json`, and `sa2-data-package-check.md/.ai.json`. The raw early agent reports remain historical; this document supersedes their hexadecimal prose and their earlier allocator-boundary unknown.

Actual heap/base, runtime callback choice, registry prior state/global aliasing, ownership/freeing, complete node and payload structures, geometry/GPU/drawing, animation, full indirect caller closure and successful native loading remain unknown. Other filenames/regions are unvalidated. No Lua prefab is invented from these data-only findings. No leaked original source was encountered or used.

## 2026-10-14 registry initialization and bank unloading

Original `0x800503C8` / DOL `0x4D3C8` / ISO `0x6BAC8` initializes **532 eight-byte slots** at `0x801E6688`: word `+0` receives its index `0..531`, word `+4` becomes zero. It writes 22 blocks of 24 slots, then four remainder slots. The first word is therefore established as an initialized index on this path; prior live contents and later uses remain separate questions. Four following groups of eight words at `0x801E7728`, `0x801E7748`, `0x801E7768`, `0x801E7788` are zeroed by the same prefix. Their complete meanings are unknown.

Original unregister routine `0x8005019C` / DOL `0x4D19C` / ISO `0x6B89C` scans the current sentinel table. It stops on ID `-1` before reading `+4`; negative/out-of-range IDs skip the slot operation. For an eligible ID it loads entry `+4` and registry slot `+4`, compares their exact words, and clears only on equality at VA `0x800501F0` / DOL `0x4D1F0` / ISO `0x6B8F0`. A mismatch is retained; no first-word rewrite, pointer conversion, node recursion, reference count or ownership repair is inferred. It has no initial bank NULL guard.

At `0x800501FC` / DOL `0x4D1FC`, it calls `0x8001A2B0` / DOL `0x172B0` / ISO `0x359B0`. Incoming `r3` remains the original bank pointer throughout the scan; `r7` advances the cursor. The wrapper's eight original words preserve that input through BL `0x8001A2BC` / DOL `0x172BC` to release dispatch `0x80119828`. Actual runtime allocator choice, other references and ownership remain unknown; the bounded default backend is documented in SA2_CALLBACK_REFERENCE.md. No engine native-free or registry execution API is added in this pass.

The initializer's later C/raw words also show a separate 300-entry eight-byte table at `0x801E5D28` using an index halfword, zero halfword and zero word. The bounded register model stops before its first halfword store and does not claim that table's payload format. Later conditional calls request literal PLCOMMTN.PRS through `0x80050094` when `[r13-0x78FC]` is zero, and `(1,0x6000)` allocations through `0x801197FC` when `[r13-0x7908]` or `[r13-0x7904]` is zero. Original source/calls/words are preserved; the dependent loader, failure semantics, names beyond the literal and runtime SDA values are not reconstructed here.

`audit_registry_lifecycle_v4.py`, run once, checks **310 original words (250 newly parsed, 60 prior scanner words), 426 retained ASM rows and eight new source artifacts** against original DOL/ISO bytes. A bounded original-integer-word model reproduces **1064 slot-initialization stores**, **64 real registration stores** and **64 matching unregister clears**. Delegating the already-proven pointer helper preserves the exact prior 529-write blob result; the original bank pointer reaches the release boundary. Match/mismatch, negative ID and limit-ID fixtures pass. This uses declared separate registry/bank/stack memory and known callees; it does not execute a native CPU, free memory, model XER carry or cover global aliasing/concurrency. Earlier CSV-field and integer-subset helper failures are retained; final V4 passes. Complete original words, store order/values, calls and native coordinates are in `docs/evidence/sa2-model-registry-*.csv` and paired reports.

Sonic node consumers and first-stream packet layout are now bounded in [SA2_MODEL_DATA_REFERENCE.md](SA2_MODEL_DATA_REFERENCE.md). The raw bank reader/converter remains unchanged, while its opaque fields have new consumption evidence; complete model/animation/runtime behavior still remains unknown.

Additional literal-byte check: PLCOMMTN.PRS at VA `0x80174414` / DOL `0x171414` / ISO `0x18fb14` matches original bytes. The call at `0x800506A8` reaches `0x80050094`; preceding raw instructions for both work requests preserve `(r3=1,r4=0x6000)`. CSV: `docs/evidence/sa2-model-registry-additional-literal.csv`. These are further static observations, not motion-payload/runtime proof.
