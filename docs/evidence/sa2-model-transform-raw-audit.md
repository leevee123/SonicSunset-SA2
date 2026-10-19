# Original vertex-helper word audit

All 192 selected original DOL words match the project-free parse: 72 dispatch words, 48 words at `8011DA30`, and 72 at `8011DAF0`. The frozen C was inspected first, and its ordering/quantization expressions were not adopted as arithmetic truth. Exact original VA, DOL offset, word, instruction, PS operand fields and PSQ W/I/displacement fields are retained in CSV. Input hashes cover the original DOL, all selected frozen artifacts, and the pinned official semantic files.

## Dispatch and descriptor

Original `8011D1D4` routes op `23` to `8011DA30` and op `29` to `8011DAF0`. The helpers read r3 descriptor words +0=output start, +4=input start, +8=count, using `DA30/34/38` or `DAF0/F4/F8`; they do not store an updated descriptor. The dispatcher constructs the output start from scratch base + low16(info)*32, input packet+8, count high16(info). Its shared matrix pointer is passed in r4; actual live matrix/state identity is not inferred.

## Exact matrix interpretation, conditional on GQR0=0

Every PSQ instruction in these helpers uses I=0. All matrix loads use fixed r4-relative addresses. At GQR0=0, they load binary32 as: f0=(m0,m1) at +0; f1=(m2,1) at +8/W1; f2=(m3,m4) at +12; f3=(m5,1) at +20/W1; f4=(m6,m7) at +24; f5=(m8,1) at +32/W1; f6=(m9,m10) at +36; f7=(m11,1) at +44/W1. Their actual instruction order is retained in `matrix-load-order.csv` and differs between the helpers. No axis names are assigned.

For output component i=0,1,2, define A_i=(m0,m1,m2), B_i=(m3,m4,m5), C_i=(m6,m7,m8), T_i=(m9,m10,m11). The first triple is **FMA(C_i,z,FMA(B_i,y,FMA(A_i,x,T_i)))**, with a single binary32 rounding at each fused instruction. The x-stage includes translation in its first fused step; translation is not moved to the final addition. At DA30 these stages are `DA68/DA70`, `DA84/DA88`, `DA8C/DA90`, with equivalent pipelined loop instructions. At DAF0 they are `DB3C/DB44`, `DB5C/DB60`, `DB74/DB78`.

Op29's second triple is **FMA(C_i,w,FMA(B_i,v,MUL(A_i,u)))**: first product rounds to binary32 at `DB4C/DB54`, then fused steps `DB68/DB70` and `DB80/DB84`. There is no translation or normalization step in this helper. These are arithmetic roles of the two raw triples, not a claim about game-space attribute names.

## Loads, stores, and preload quirks

For a record beginning at R, op23 loads PS pair R+0, W1 scalar R+8, then raw `lwzu` R+12; input advances 16 bytes. It rotates the raw word left by 8 using original `rlwinm` at `DA78`/`DAD4`, without float conversion. Output slot S gets PS pair at S+0, W1 scalar at S+8, and raw rotated word at S+24 (`DAAC/DAB4/DABC` or final `DAE0/DAE4/DAE8`). Under GQR0=0 this leaves S+12..23 and S+28..31 untouched: **16 bytes** per 32-byte slot.

Op29 loads three PS pairs R+0/R+8/R+16 and advances input by 24 bytes. Its four output stores are S+0/W0, S+8/W1, S+12/W0, S+20/W1 (`DB98/DBA0/DBA8/DBB0` or final `DBE4/DBE8/DBEC/DBF0`). Under GQR0=0 only S+24..31 is untouched: **8 bytes** per slot.

Both helpers set CTR=count-1, compute record 0 and load record 1 before testing count-1. Positive count N outputs N records but loads **N+1 records**, including an unused final lookahead. Even count 1 reads the next record. If count is zero, CTR becomes FFFFFFFF and the body is entered: idealized fault-free loop control gives 2^32-1 body iterations plus a final output, with modulo-32-bit pointer changes. This is unsafe native behavior, not a zero-input guard or an allocation/capacity claim. Aliases/faults can change execution; host handling must be explicit.

## Numeric contract and primary-source boundary

Pinned official Dolphin paired arithmetic calls ForceSingle with the actual FPSCR; it does not unconditionally flush intermediates when NI=0. `ps_muls1` applies Force25Bit to selected C lane; `ps_madds0/1` use the selected C lane with NI_madd<true>. For binary32 operands, Force25Bit is a no-op, and under nearest-even/NI0 the per-lane finite operation maps to a correctly rounded float multiply or fused float FMA.

However, GQR0 float **PSQ stores call ConvertToSingleFTZ unconditionally**, flushing a nonzero subnormal final result to its signed zero even when NI=0. PSQ float loads preserve subnormal input via ConvertToDouble. A matching explicit host contract must preserve single-rounded intermediate subnormals and apply final PSQ-store FTZ. Matrix/input load widths and store widths differ for other live GQR0 formats; no live GQR0/FPSCR or axes are guessed here.

No repository, engine, native game, frozen project, installed language or helper file was modified. The parser uses only the existing project-free language API in private runtime folders; no ProgramDB or project was opened.
