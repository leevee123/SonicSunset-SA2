# Original op2C signed weight dequantization

The weight load in original helper8011DC98 is established exactly: **big-endian signed16 /256**, returned as an exactly representable binary32 value in paired lane0; lane1 is1.0. The helper programs GQR1 itself and leaves that register changed after its normal return. This closes the weight-conversion question within an explicit numerical contract; it does not prove live GQR0/FPSCR state or complete weighted transform equivalence.

## Original source and register effect

Read frozen context-free and startup-SDA generated C first; preserve warnings and use original words where architectural effects or quantization semantics are missing. Helper8011DC98/DOL11AC98/ISO139398 spans8011DC98..8011DF18 exclusive:160 original words,320 two-view ASM rows, four frozen source artifacts. Both exported body ranges and source SHA-256 values match; original DOL/ISO identity is unchanged.

AtDCA4 word38000807 loads r0=0x807; DCA8 word64000807 ORs0x08070000; DCAC word7C11E3A6 writes SPR913/GQR1 from r0. The result is **0x08070807**, decoded load type7(S16),load scale8,store type7(S16),store scale8. The immediate write is before all floating math and before the helper's stack allocation. Earlier input-pointer reads must succeed for that path to reach the write.

There is exactly one explicit GQR1 write and **no explicit incoming GQR1 read/save/restore** in the complete helper. It has no direct calls or indirect control transfer other than its one final `blr` at8011DF14. The FPR save/restore of f19 on the stack restores floating data, not GQR1. Thus on a normal uninterrupted return after the write, GQR1 remains0x08070807. This is a clobber effect; asynchronous external restore/hardware exceptions are outside this statement.

The previous complete main-DOL GQR SPR scan was reused and its 10 GQR1 words matched original bytes. No new broad scan was run. Its context save/restore sites and other GQR1 users do not turn this helper into a register-preserving function; lifetime outside this bounded call remains unknown.

| Original VA | DOL file offset | ISO offset | Original word |
|---|---|---|---|
| 0x8011dca4 | 0x11aca4 | 0x1393a4 | 0x38000807 |
| 0x8011dca8 | 0x11aca8 | 0x1393a8 | 0x64000807 |
| 0x8011dcac | 0x11acac | 0x1393ac | 0x7c11e3a6 |
| 0x8011dcf8 | 0x11acf8 | 0x1393f8 | 0xe5270008 |
| 0x8011dd10 | 0x11ad10 | 0x139410 | 0xe5470008 |
| 0x8011dd1c | 0x11ad1c | 0x13941c | 0xe6679008 |
| 0x8011dd20 | 0x11ad20 | 0x139420 | 0xa5470002 |
| 0x8011dd74 | 0x11ad74 | 0x139474 | 0xe6679008 |
| 0x8011ddec | 0x11adec | 0x1394ec | 0xe6679008 |
| 0x8011de44 | 0x11ae44 | 0x139544 | 0xe6679008 |
| 0x8011dec4 | 0x11aec4 | 0x1395c4 | 0xe6679008 |
| 0x8011df14 | 0x11af14 | 0x139614 | 0x4e800020 |

## Exact weight-load fields and address

There are **five static GQR1 weight-load sites**:8011DD1C,8011DD74,8011DDEC,8011DE44,8011DEC4. Every one is wordE6679008, decoded from original fields as primary57 `psq_lu`, destination f19,base r7,12-bit signed displacement+8,W=1,I=1. Successful execution reads one S16 at EA=oldr7+8, places its dequantized value in f19 lane0 and1.0 in lane1, and updates r7 to EA. This is one integer halfword, not an ordinary float read, and W1 does not consume a second input lane. The pinned reference's failed-load/LSQE exception paths are outside the host nontrapping contract.

For the initial record r7 starts at the source-record base; the preceding update loads atDCF8 andDD10 each advance it by8, so DD1C reaches record+24. DD20's unsigned `lhzu +2` reaches the separate destination-index field at record+26. The remaining identical load sites belong to the helper's alternate and pipelined paths; the static site count does not claim five loads per output record. Later preloads, unused lookahead, source/destination aliasing and full weighted instruction order belong to the separate numerical helper audit.

Complete per-PSQ W/I/RA/FPR/displacement/update fields are in `PSQ-fields-in-helper.csv`; GQR1-only sites, all original words, full retained ASM, control transfers and source hashes remain complete in their CSVs with VA/DOL/ISO coordinates.

## Hardware reference and frozen SLEIGH limitation

The existing pinned official Dolphin reference at commite6f3ae17627e4344da95b13424af5baf4c892b08 defines `UGQR` load type bits16..18 and six-bit load scale24..29; type7 isS16. `Interpreter_LoadStorePaired.cpp` selects `LoadAndDequantize<s16>`, reads a single unsigned memory halfword and reinterprets it as signed16 when W1, multiplies by the dequantize scale entry, sets lane1=1.0f and promotes the binary32 results to paired storage. Table entry8 is2^-8. This is a primary architecture/reference validation, not original game source or code copied into an engine. Reference SHA-256 `878f81e8a2b0800037102b1d73c9d4cc249b26dfadc3322459a0717423528e89`; exact source lines, manifest URL/commit provenance and input SHA guards are preserved.

The installed and isolated frozen Gekko SLEIGH sources are byte-identical, SHA-256 `32ce4852d6243f5eea19cda1eb8cf0b2af8fb93532dcd9a585ee927a32c8eb75`; compiled SLA SHA-256 `aa25bde9ffb8f6366e1e490c6a488b1aced4665dc6c4f2fdca9cc598d5530975`. Its load macro line1171 assigns six scale bits into a three-bit slice: `ls[0,3] = I[24,6];`. Scale8 cannot be represented in that three-bit destination (8&7=0). Generated C also contains opaque `ldexpf` expressions and expanded paired semantics. It is not an authoritative numerical weight conversion. This audit resolves the weight using original GQR/load fields plus the pinned reference; no installed/frozen language or analysis project was patched or reopened.

## Exhaustive exact binary32 validation

Quote from the once-only Python result: **65,536 raw16 inputs;65,535 normal values and one positive zero;zero negative zeros,subnormals,nonfinite values or rounding mismatches**. Every result matched both an independent integer construction of its binary32 bits and the host float conversion/multiply/pack path; every unpacked result equaled the exact rational signed16/256. `all-s16-weight-f32-oracle.csv` retains all inputs, exact rational values, binary32 lane bits and classifications. Scale2^-8 has bits3B800000 and lane1 always has bits3F800000.

| Raw input | Signed value | Exact weight | Lane0 binary32 bits |
|---|---|---|---|
| 0x8000 | -32768 | -128.0 | 0xc3000000 |
| 0x8001 | -32767 | -127.99609375 | 0xc2fffe00 |
| 0xffff | -1 | -0.00390625 | 0xbb800000 |
| 0x0 | 0 | 0.0 | 0x0 |
| 0x1 | 1 | 0.00390625 | 0x3b800000 |
| 0xff | 255 | 0.99609375 | 0x3f7f0000 |
| 0x100 | 256 | 1.0 | 0x3f800000 |
| 0x7fff | 32767 | 127.99609375 | 0x42fffe00 |

Every S16 is exactly representable as binary32 because its magnitude is at most32768. Multiplication by the power-of-two scale changes the exponent without losing significant bits. The smallest nonzero magnitude is2^-8, safely normal; endpoints are-128 and127.99609375. Zero has a unique integer representation and converts to+0 multiplied by a positive scale, so the conversion alone cannot create-0. Subsequent weighted multiply/add results can still contain signed zero; that separate arithmetic must preserve it. No clamp or zero/negative-weight rejection is present in the quantized load.

The830 real Sonic op2C records were checked against the immutable136360-byte decoded bank and prior complete record CSV. All28-byte records, weight offsets+24 and signed values match; their weights happen to be0..255, mapping0..255/256 exactly. This does not establish that all game weights are nonnegative, normalized or clamped. All real offsets are decoded-file offsets, not directly mapped compressed ISO bytes; original code locations retain their distinct native/file/ISO coordinates.

## Safe explicit host contract and remaining limits

For **weight conversion alone**, accept every raw16 bit pattern and calculate the exact S16/256 binary32 value. All results are finite and exact; no rounding-mode choice or subnormal policy changes these values. That does not remove floating controls from the rest of the weighted helper.

For a larger CPU numerical fragment, the conservative declared contract remains **GQR0=0,RN nearest,NI=0,nontrapping**, with finite consumed values and retained results governed by that fragment's explicit policy. GQR0 controls the other floating packet/matrix/scratch loads and stores; it is not needed to derive this integer weight conversion, and **no live GQR0 claim is made**. Finite-only is host support policy, not an original input check: matrix/source/accumulation NaNs,infinities,discarded lanes,exception flags,traps and unused lookahead are not certified by a finite weight. Internal or final subnormal behavior of subsequent math is separate from this oracle's lack of subnormal weight results. GQR1's original write and its externally visible clobber should be documented even when the CPU implementation models only the resulting arithmetic rather than native SPR state.

Unknowns remain actual reach/execution,live GQR0/FPSCR and asynchronous state,full weighted FMA/rounding/store order and flags,source/destination alias effects,all helper preloads/unsafe zero counts,ownership/capacity and gameplay integration. Initial reference source-manifest.json lookup was absent; the correct existing manifest.ai.json was reused. Expanded C output was oversized; compact weight excerpts and complete original evidence remain retained. No native/game execution or project/DB open occurred; no repository/engine/original/frozen/language files changed; no leaked source was encountered or used. Root owns engine/docs integration and final notification.
