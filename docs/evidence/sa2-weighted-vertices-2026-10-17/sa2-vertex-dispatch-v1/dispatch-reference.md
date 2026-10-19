# Original first-stream dispatcher8011D1D4

The dispatcher supports an additive CPU stream path with explicit initial state,GQR1 and matrix under declared nonalias/finite numerical rules. Exact packet stepping, calls and state effects are established; op2A's math remains unsupported. No live SDA/matrix/FP binding, gameplay drawing or complete game behavior is inferred.

## Source and original coordinates

Both frozen generated C views were read first. The dispatcher is72 original words at8011D1D4/DOL11A1D4/ISO1388D4, ending just before8011D2F4. It was completed C-only and has no individual ASM export; complete original words are selected by matching both-view body ranges and DOL/ISO bytes. All17 source artifacts,386 selected words across dispatcher/23/29/2C and boundary-only2A scopes,632 retained ASM rows and14 graph-reference rows are preserved with source hashes. Scopes overlap prior audits and do not increase whole-corpus decompilation totals.

| Original VA | DOL offset | ISO offset | Original word | Established effect |
|---|---|---|---|---|
| 0x8011d20c | 0x11a20c | 0x13890c | 0x807e0000 | Every nonEND information-word read |
| 0x8011d220 | 0x11a220 | 0x138920 | 0x90010018 | Descriptor count atsp+18 |
| 0x8011d224 | 0x11a224 | 0x138924 | 0x93c10014 | Descriptor source atsp+14 |
| 0x8011d234 | 0x11a234 | 0x138934 | 0x90010010 | Descriptor destination atsp+10 |
| 0x8011d248 | 0x11a248 | 0x138948 | 0x808d8e04 | 29matrix pointer read |
| 0x8011d24c | 0x11a24c | 0x13894c | 0x480008a5 | 29helper call |
| 0x8011d260 | 0x11a260 | 0x138960 | 0x808d8e04 | 2Cmatrix pointer read |
| 0x8011d264 | 0x11a264 | 0x138964 | 0x54a5c63e | 2Cmasked mode extraction |
| 0x8011d268 | 0x11a268 | 0x138968 | 0x48000a31 | 2Chelper call |
| 0x8011d280 | 0x11a280 | 0x138980 | 0x900d8e88 | 2AprecallstateOR2store |
| 0x8011d288 | 0x11a288 | 0x138988 | 0x808d8e04 | 2Amatrix pointer read |
| 0x8011d28c | 0x11a28c | 0x13898c | 0x48000985 | 2Aunknownmathcall |
| 0x8011d2a4 | 0x11a2a4 | 0x1389a4 | 0x900d8e88 | 23precallstateOR3store |
| 0x8011d2ac | 0x11a2ac | 0x1389ac | 0x808d8e04 | 23matrix pointer read |
| 0x8011d2b0 | 0x11a2b0 | 0x1389b0 | 0x48000781 | 23helper call |
| 0x8011d2b4 | 0x11a2b4 | 0x1389b4 | 0x381dffff | Encoded headerupper16minus1 |
| 0x8011d2b8 | 0x11a2b8 | 0x1389b8 | 0x5400103a | Encodedskipunits*4mod32 |
| 0x8011d2bc | 0x11a2bc | 0x1389bc | 0x7fde0214 | Next cursor |
| 0x8011d2c0 | 0x11a2c0 | 0x1389c0 | 0x807e0000 | Header read |
| 0x8011d2cc | 0x11a2cc | 0x1389cc | 0x280000ff | LowopcodeFF test BEFOREinfo |
| 0x8011d2d4 | 0x11a2d4 | 0x1389d4 | 0x38600000 | Literal0 return register |

## Read order, descriptor and packet advancement

Incoming r3 is the stream pointer and r4 the scratch base, saved into r30/r31. AtD2C0 the dispatcher reads a BEu32 header and advances four bytes. Its low8 bits are compared withFF atD2CC **before any information read**. Any header whose low byte isFF returns; upper24 bits have no additional EOS meaning.

Every nonEND opcode, even unrecognized/opaque, reads the BEu32 information word at packet+4 (D20C), then advances to source data packet+8. A12-byte stack descriptor is written in this original order: count=info>>16 tosp+18; source pointer tosp+14; destination=scratchBase+((info&FFFF)<<5) modulo32 tosp+10. Thus descriptor offsets0/4/8 are destination/source/count. The two information fields are unsigned16. No native count,source,destination,packet-length or buffer-capacity guard is introduced by this dispatcher.

The header upper16 controls advancement. After the helper/opaque branch, D2B4..D2BC add4*(upper16-1) to the packet+8 data cursor, giving **next=packet+4*(upper16+1) modulo32**. Upper16=0 has an encoded span4 but still reads its information word atpacket+4, which is also the next header. It is not coerced to8. A lowFF END reads only its four-byte header and never that overlapping word. A host API must distinguish encoded span from required metadata reads, preserve opaque skips, and reject missing buffers/END as host policy. Arithmetic wrap tests do not execute native unaligned/faulting accesses.

## Exact branches and state order

| Low opcode | Before-call state effect | Native target / arguments |
|---|---|---|
| 29 | None | DAF0(descriptor,currentMatrixPointer) atD24C |
| 2C | None | DC98(descriptor,currentMatrixPointer,(header&7FFF)>>8) atD268 |
| 2A | State word OR2, stored atD280 | DC10(descriptor,currentMatrixPointer) atD28C; math unknown |
| 23 | State word OR3, stored atD2A4 | DA30(descriptor,currentMatrixPointer) atD2B0 |
| Every other nonFF | No dispatcher state/helper effect | Encoded skip after metadata read |

State is physically addressed through r13-0x7178. OR2 sets bit1 and preserves every other bit; OR3 sets bits0/1 and preserves every other bit. The dispatcher never resets this state at entry, between packets or before returning. The state read/write happens **before** the matrix-pointer read and helper call for23/2A. Under the previously documented startup r13=803B52C0 assumption, the state label is803AE148; this audit does not assume that register value is live.

The2C mode is exactly seven raw bits8..14, range0..127. Bit15 is cleared before extraction and upper16 does not contribute. Do not restrict the raw mode to sample values0/1/2. The dispatcher observes no helper return value: it resumes its local encoded skip, then overwrites r3 with the next header. On normal END it explicitly loads r3=0 atD2D4. This is an unconditional native return value, not a demonstrated success/error contract. Helpers' scratch/GQR/FPR/FP effects are separate from that result.

Opcode2A's established prefix is stateOR2→matrix pointer read→callDC10. Its boundary-only C source contains further calls; numerical effects and subsequent state/GQR consequences are not modeled. The CPU numerical stream API should reject2A rather than silently skip it or reuse another helper. No2A floating math was executed or emulated by this audit.

## Matrix binding and closed-helper effects

The dispatcher reads the pointer at **r13-0x71FC** afresh for every recognized packet, atD248(29),D260(2C),D288(2A),D2AC(23). Under the prior startup-SDA assumption this is label803AE0C4; its runtime content,matrix initialization,ownership and validity are unknown. The native dispatcher does not cache a matrix pointer for the stream. Opaque and END packets do not read it.

The selected23/29/2C helpers contain no direct or indirect calls; their only op19 transfer is normal `blr`. Complete typed GPR-write coverage across all280 helper words proves no r13 write. All their native memory store base registers are:23→r5;29→r1/r5;2C→r1/r6. There is no direct store through r13. These stores are scratch outputs and,for29/2C,private floating save frames as established in the separate helper audit. Indirect aliases still matter: a scratch destination or frame can physically overlap a global word,matrix bytes,descriptor or source.

Therefore a single explicit immutable matrix binding across a CPU stream is justified **only under the declared closed/nonalias/no-external-mutation scope**: output scratch and helper stack do not overlap matrix data,global pointer/state words,descriptor/source data; the binding and matrix are not changed asynchronously or externally; helpers return under their supported math/input contract. Under those premises these closed helpers cannot change the global matrix pointer or its matrix bytes,so each fresh read yields the same binding. This is conditional proof,not a statement that native aliases or runtime callbacks never exist. A deliberately external-mutation control fixture demonstrates that the original dispatcher would see a newly written pointer at the next recognized call; it is outside the closed API contract.

23/29 do not touch GQR1;2C writes0x08070807 and does not restore it on normal return, as independently proved by the quantization audit. The dispatcher does not read,initialize or reset GQR1. Thus an explicit initial GQR1 is retained until the first executed2C; thereafter it remains0x08070807 across23/29/opaque/END in this closed supported path.2A is excluded. No live GQR0/FPSCR claim follows; declared GQR0=0,RNnearest,NI0,nontrapping and finite consumed/retained numerical support remain separate contracts. Native floating flags and unused lookahead are outside this integer model.

## Validation and conservative integration

Quote from once-only validation: **all256 opcodes;48 upper16/address-wrap boundary cases;65,536 information-extraction cases;256 mode/bit15 cases;262,144 state-OR cases;four ordered traces with91 events;three opaque4-byte info/header-overlap cases—all passed**. State validation exhausts all low16 values across four upper16 patterns, while the original OR-immediate mask proves the unchanged upper bits algebraically for arbitrary32-bit inputs. Information vectors cover all values of both16-bit fields and original masks prove their independence; this is not an enumeration of all2^32 information words. Full raw CSV preserves each case and control event.

The original72-word integer model executes only dispatcher control/integer effects; numerical helpers are opaque hooks. Supported hooks record descriptor/count/source/destination/matrix/mode and the separately proved GQR1 clobber. The2A fixture stops at the unresolved call after its known prefix. These are explicit synthetic bindings and control traces,not native or game execution. The numerical agent independently validates full real-stream scratch results with explicit matrices; this audit does not duplicate or claim that numerical work.

Conservative opt-in API: consume raw packets in original order; copy caller scratch/state/GQR1; invoke only proved23/29/2C CPU fragments with explicit matrix; preserve all unknown-opcode metadata/encoded skips; stop before info on lowFF; return copied scratch and final explicit state/GQR1. Reject2A and unsupported numerical inputs with clear host guards. Do not require opaque packets' unused count/base to fit scratch or read unused matrix values as if a native call occurred. Zero recognized counts and out-of-declared records may be rejected by the numerical helpers' existing host rules; opaque count0 itself has no native math effect. A transactional host failure policy is not native rollback—the original2A path already storesOR2 before calling unknown code.

Unknowns remain actual SDA/global/matrix/scratch binding,initial state and GQRs/FPSCR,aliasing and asynchronous mutation,2A math,full numerical flags/preloads,resource lifetimes and gameplay/render integration. C-only ASM absence is preserved as a source-selection limit; frozen C/math warnings remain applicable. No engine/repository/original/frozen/language/DB file changed, no project opened, no native code executed and no leaked source encountered or used. Root owns integration/docs and final notification.
