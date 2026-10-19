# Original drawing-stream grammar: bounded static reference

The integer command framing and cache control in original `0x8011CCF8` are established. This supports a raw packet reader and an explicit-caller-state control trace. It does not establish drawing, material interpretation, handler safety, skinning, cache lifetime, or actual execution. No engine/repository/frozen file was changed by this audit.

## Evidence and coordinates

Read the frozen generated C first in both context-free and startup-SDA exports; use original instruction words to resolve lost ABI effects and signedness. Entry `0x8011CCF8`, DOL `0x119CF8`, ISO `0x1383F8`; the contiguous original body ends just before `0x8011D1AC`. `function-body-ranges.csv`, `sources.csv`, `original-instructions.csv`, `helper-original-words.csv`, `direct-calls.csv`, and `critical-original-words.csv` retain full source hashes and mapped addresses. Original DOL SHA-256 `a53335308d1f820be236fd2b6342fee850eaf048eb26aac21ddb1903b060db2e` matches the real ISO bytes at header-selected DOL offset `0x1e700`.

| Original function VA | DOL offset | ISO offset |
|---|---|---|
| 0x8010afb0 | 0x107fb0 | 0x1266b0 |
| 0x8010affc | 0x107ffc | 0x1266fc |
| 0x8011c628 | 0x119628 | 0x137d28 |
| 0x8011c754 | 0x119754 | 0x137e54 |
| 0x8011c76c | 0x11976c | 0x137e6c |
| 0x8011c85c | 0x11985c | 0x137f5c |
| 0x8011ccf8 | 0x119cf8 | 0x1383f8 |
| 0x8011d414 | 0x11a414 | 0x138b14 |

`0x8011D414` dispatches nonzero payload+4 to this parser. Incoming `r3` is the command pointer and `r4` is the scratch argument: original instructions copy them to r20/r21 after the save helper. The C's apparent two-value return from `0x8010AFB0` is decompiler ABI loss. All 26 original words in the save/restore helpers through their first `blr` are stores/loads of r20..r31 through r11 plus return; they do not supply stream/scratch values. The C signature and inferred local array sizes are not a verified public ABI or allocation contract.

| Original instruction VA | DOL offset | ISO offset | Original word | Proven effect |
|---|---|---|---|---|
| 0x8011cd0c | 0x119d0c | 0x13840c | 0x7c741b78 | incoming r3 saved as stream cursor r20 |
| 0x8011cd10 | 0x119d10 | 0x138410 | 0x7c952378 | incoming r4 saved as scratch r21 |
| 0x8011cda8 | 0x119da8 | 0x1384a8 | 0x92830000 | command04 stores following pointer |
| 0x8011cdb8 | 0x119db8 | 0x1384b8 | 0x480003dc | command04 branches to function return |
| 0x8011cdd4 | 0x119dd4 | 0x1384d4 | 0x4bffff25 | command05 recursive direct call |
| 0x8011cde4 | 0x119de4 | 0x1384e4 | 0x480003a0 | command05 continues caller cursor |
| 0x8011ce28 | 0x119e28 | 0x138528 | 0xab340000 | 10..3F signed16 length load |
| 0x8011ce68 | 0x119e68 | 0x138568 | 0xa3630000 | 40..FF unsigned16 length load |
| 0x8011ce6c | 0x119e6c | 0x13856c | 0xa8140000 | 40..FF unconditional signed16 info load |
| 0x8011cf2c | 0x119f2c | 0x13862c | 0x574093be | logical right14 of sign-extended info via rotate18/mask0003FFFF |
| 0x8011d18c | 0x11a18c | 0x13888c | 0x2c1c00ff | exact signed-header compareFF |

## Framing

All headers and following fields below are big-endian 16-bit values. Let p be the header byte offset and op its low byte. The original loads the full header with `lha`, advances the cursor by two, then compares the sign-extended whole header with 255. Only raw `0x00FF` ends the call. `0x01FF` and `0xFFFF` proceed through the op>=0x40 path. Header high bits must remain available as raw data.

| Condition, in original priority order | Fields read by parser | Next cursor / stop |
|---|---|---|
| Whole header exactly 00FF | Header only | Return; two-byte terminal |
| op=04 | Header only; high byte is cache selector | Save p+2 and return |
| op=05 | Header only; high byte is cache selector | Recursively invoke cache target, then resume p+2 |
| op=00,01,02,03,06,07 | Header only | p+2; op01 conditionally invokes C754 |
| op=08..0F | Signed16 argument at p+2 | p+4; C76C or pending-group C85C |
| op=10..3F | Signed16 length at p+2; pass data pointer p+4 to C628 | p+4+2*s16(length), modulo native 32-bit arithmetic |
| op=40..FF, excluding exact EOS already handled | Unsigned16 length p+2 AND signed16 information p+4 unconditionally; data pointer p+6 | p+4+2*u16(length), modulo native 32-bit arithmetic |

The low10..3F `lha` at CE28 is distinct from the high-family `lhz` at CE68. A signed length of -2 returns to p, -1 reaches p+2, and smaller values can move backward. This is not an original rejection rule. A conservative host reader can reject negative lengths or nonprogress, but must identify that as host policy.

For high-family length zero the encoded span is four bytes, but the parser still reads the two-byte information field at p+4; that field overlaps the next header. The information read is mandatory even for unsupported draw opcodes. A raw reader must check the six-byte parser read footprint separately from the encoded span. It must not silently replace the encoded span with six bytes. Low10..3F length zero has a four-byte span, yet the C628 handler is still invoked; odd low opcodes cause that handler to read two halfwords at p+4/p+6 regardless of the declared length. Parser boundary success therefore does not establish safe native handler inputs.

Op01 and low10..3F conditionally call `0x8011C754` when the control word at r13-0x71D8 has bit0x8000 clear. C754 stores header&0x3F00 to r13-0x71E4 and ORs8 into r13-0x717C. The 08..0F argument is sign-extended when passed, while the target helpers mask it with0x1FFF before their table chain. These helpers dereference external state; a complete four-byte packet is not proof those objects exist.

## Cache effects and precise stop rules

Cache base `0x80357A58` is formed by original absolute instructions; selector `(header>>8)&255` is multiplied by four. The selector domain has 256 values. This alone does not prove a 256-word native allocation or its initialization.

Command04 at CDA8 stores the already advanced cursor p+2 to the selected cache word, then increments the global word addressed as r13-0x71CC and branches to the function return at D194. It does not parse or execute the saved body in this call. Command05 loads the selected cache word, calls CCF8 with that target and the same r4 scratch, then decrements r13-0x71CC after the recursive call returns and continues the caller's p+2 cursor. The function has no local null-target guard, recursive depth guard, cache presence check, or counter-underflow guard. Do not describe the counter as recursion depth: definitions increment it, and calls decrement it after whatever mutations their recursive bodies made.

Each recursive entry resets the word at r13-0x7174 and initializes its own pending-group variables. Definitions and nested calls may alter the shared cache/counter. The startup-SDA C labels r13-0x71CC as DAT_803AE0F4 and r13-0x7174 as DAT_803AE14C; those labels depend on the recorded post-startup SDA assumption, not an observed register state.

A raw linear metadata scan stops only on exact00FF or op04. Op05 is a two-byte command and scan continues, without choosing or following a runtime cache target. An optional control-only trace must accept caller-supplied cache contents, roots/order, and initial counter. A missing cache entry in that host trace is unresolved input; it is not an original null check. Native pointers and host decoded-file offsets are distinct representations. Active-call cycle/depth/event limits are host safeguards.

## Pending groups and draw dispatch limits

At CE6C the information halfword is sign-extended into r26. CF2C rotates left18 and masks0x0003FFFF, exactly `(u32(s16(info))>>14)`, when starting a pending group. This is not generally `raw_info>>14`. Exhaustive integer comparison covered all65,536 information values; selected results are retained in the AI twin and complete `information-arithmetic.csv`. Values with bit15 clear produce groups0 or1; bit15 set produces a large count. No native local-array bounds check precedes pointer/flag stores. Do not impose the generated C array dimensions as original limits.

With no pending group, nonzero effective count saves data pointer/flag0, sets next index1 and the saved signed high-byte header flags, and skips to the encoded next command. While pending, each >=40 packet stores its data pointer and op==42 flag at the current index before comparing that old index with the pending count, then increments the index. A count k therefore collects entries0..k. When the old index reaches k, dispatch uses the saved flags and the current packet's op/information. Other command families between these packets do not themselves increment the group index; 08..0F chooses C85C with the current index. A recursive cache call uses a separate call's local group variables.

Only op40,41,42 enter drawing helper dispatch. Other >=40 opcodes still perform common header-state/group processing and use the same encoded cursor movement; they are not guaranteed side-effect-free no-ops. Following dispatch or the common unsupported-op skip, pending count/index and r13-0x7174 reset. Detailed draw helper record grammars, topology, attributes and external state are outside this slice. Preserve the existing GQR/FIFO decompiler caveats from `work/sa2-payload-consumers/payload-reference.md`; no claim of numerical C equivalence or GPU transcript is made here.

## Real sample validation

The real Sonic sample has 136360 decoded bytes, SHA-256 `b7ea586ed0fa22330dc8a2cfe2bb8fa9ce4ac70d9561764f35af4ced5d371963`. Compressed input is102331 bytes at ISO0x479024A4, SHA-256 `d8f90e6c724e709b8d3431e725a5db1d1a096bdf5118d2ecca9ad356e7862d99`. All packet/body/payload offsets in the sample CSV refer to decompressed file bytes; PRS compression gives them no direct ISO coordinate. Original function and instruction coordinates remain VA/DOL/ISO in their own CSVs.

Quote from the once-only passing v2 validation: **38 source artifacts;838 exported ASM rows matched original DOL;26 save/restore words;88 direct-call rows;64 payload+4 roots plus15 definition bodies=79 entries;289 unique commands;64 exact ends and15 define/returns**. Their encoded spans total **42042 bytes**. Fifty-two signed-length packets have lengths2..6;73 unsigned-length packets have lengths6..3738 and effective group count0;55 signed-argument packets,15 single-halfword op00,15 cache calls,15 definitions and64 EOS account for the rest. Full opcode counts are in the twin and complete packet CSV.

Same-index definitions are ambiguous: eight command05 sites have eight same-index candidate bodies each; seven have seven each. The saved-body candidates are literal following pointers from command04, not guessed pointer tables. Candidate pairing establishes neither cache lifetime nor runtime order. Four explicit-state control scenarios include one real-byte candidate selection; none is an execution trace. Cache call resumes were confirmed by synthetic continuation events and original code; counter wrap is preserved in the control model.

All65,536 headers,65,536 raw lengths,65,536 raw information fields and10 boundary fixtures were checked by Python. Version1 stopped at a mistaken selection assumption that some cache index would have exactly one file candidate. The original script, paired failure report and corrected once-only v2 are preserved. No original evidence failed that assertion. `validation.md`/`.ai.json` quote the successful result, and `control-traces.csv` retains complete events.

## Decisions, guards and remaining unknowns

Use conservative, additive raw data parsing with both encoded span and parser read footprint; retain raw halfwords and unsupported opcode values. Separate optional cache control from metadata reading. Bounds, finite buffers, missing-terminal rejection, negative-length rejection, active-path cycle/depth/event guards and explicit cache initialization are host policy. They do not show that the original function validates malformed inputs. A bounded parser cannot certify subsequent native handler safety or external table availability.

Unknowns: actual cache allocation/initialization/lifetime and draw ordering; real selected targets/counter/FP/SDA state; complete handler grammar and capacity; full drawing/material/attribute/topology/skin semantics; other banks/versions; effects of malformed inputs outside the scoped instruction proof. Static calls and bytes were inspected; no successful native execution was observed. No Ghidra project was opened, no original/frozen/language files changed, and no leaked source was encountered or used. All four team worker slots were active, so this cursor/cache slice was audited sequentially while other assigned team questions ran independently. No engine file changed in this subtask; root owns integration and documentation.
