"""Finalize paired audit and immutable input/output digests once."""
import csv
import hashlib
import json
from pathlib import Path

OUT = Path(__file__).resolve().parent


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read_csv(name):
    with (OUT / name).open(newline='', encoding='utf-8-sig') as f:
        return list(csv.DictReader(f))


assert not (OUT / 'draw-reference.ai.json').exists(), 'Finalizer version already run'
validation = json.loads((OUT / 'validation.ai.json').read_text())
sources = read_csv('sources.csv')
for source in sources:
    assert sha(Path(source['path']).read_bytes()) == source['sha256'], source['path']
packets = read_csv('sample-unique-packets.csv')
streams = read_csv('sample-streams.csv')
linear_bytes = sum(int(row['linear_bytes']) for row in streams)
encoded_bytes = sum(int(row['byte_size']) for row in packets)
assert linear_bytes == encoded_bytes
function_sources = {r['entry']: r for r in sources if r['view'] == 'startup_sda' and r['kind'] == 'pseudocode'}
function_table = '\n'.join(f"| {r['entry']} | {r['dol_offset']} | {r['iso_offset']} |" for r in function_sources.values())
info_examples = [r for r in read_csv('information-arithmetic.csv') if int(r['raw_u16']) in [0, 0x3fff, 0x4000, 0x7fff, 0x8000, 0xffff]]
critical = read_csv('critical-original-words.csv')
selected = {0x8011cd0c, 0x8011cd10, 0x8011cda8, 0x8011cdb8, 0x8011cdd4, 0x8011cde4, 0x8011ce28, 0x8011ce68, 0x8011ce6c, 0x8011cf2c, 0x8011d18c}
critical_table = '\n'.join(f"| {r['original_va']} | {r['dol_offset']} | {r['iso_offset']} | {r['word']} | {r['effect']} |" for r in critical if int(r['original_va'], 16) in selected)
human = f'''# Original drawing-stream grammar: bounded static reference

The integer command framing and cache control in original `0x8011CCF8` are established. This supports a raw packet reader and an explicit-caller-state control trace. It does not establish drawing, material interpretation, handler safety, skinning, cache lifetime, or actual execution. No engine/repository/frozen file was changed by this audit.

## Evidence and coordinates

Read the frozen generated C first in both context-free and startup-SDA exports; use original instruction words to resolve lost ABI effects and signedness. Entry `0x8011CCF8`, DOL `0x119CF8`, ISO `0x1383F8`; the contiguous original body ends just before `0x8011D1AC`. `function-body-ranges.csv`, `sources.csv`, `original-instructions.csv`, `helper-original-words.csv`, `direct-calls.csv`, and `critical-original-words.csv` retain full source hashes and mapped addresses. Original DOL SHA-256 `{validation['DOL_sha256']}` matches the real ISO bytes at header-selected DOL offset `{validation['DOL_ISO_offset']}`.

| Original function VA | DOL offset | ISO offset |
|---|---|---|
{function_table}

`0x8011D414` dispatches nonzero payload+4 to this parser. Incoming `r3` is the command pointer and `r4` is the scratch argument: original instructions copy them to r20/r21 after the save helper. The C's apparent two-value return from `0x8010AFB0` is decompiler ABI loss. All 26 original words in the save/restore helpers through their first `blr` are stores/loads of r20..r31 through r11 plus return; they do not supply stream/scratch values. The C signature and inferred local array sizes are not a verified public ABI or allocation contract.

| Original instruction VA | DOL offset | ISO offset | Original word | Proven effect |
|---|---|---|---|---|
{critical_table}

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

The real Sonic sample has {validation['sample']['decoded_bytes']} decoded bytes, SHA-256 `{validation['sample']['decoded_sha256']}`. Compressed input is102331 bytes at ISO0x479024A4, SHA-256 `{validation['sample']['stored_sha256']}`. All packet/body/payload offsets in the sample CSV refer to decompressed file bytes; PRS compression gives them no direct ISO coordinate. Original function and instruction coordinates remain VA/DOL/ISO in their own CSVs.

Quote from the once-only passing v2 validation: **38 source artifacts;838 exported ASM rows matched original DOL;26 save/restore words;88 direct-call rows;64 payload+4 roots plus15 definition bodies=79 entries;289 unique commands;64 exact ends and15 define/returns**. Their encoded spans total **{encoded_bytes} bytes**. Fifty-two signed-length packets have lengths2..6;73 unsigned-length packets have lengths6..3738 and effective group count0;55 signed-argument packets,15 single-halfword op00,15 cache calls,15 definitions and64 EOS account for the rest. Full opcode counts are in the twin and complete packet CSV.

Same-index definitions are ambiguous: eight command05 sites have eight same-index candidate bodies each; seven have seven each. The saved-body candidates are literal following pointers from command04, not guessed pointer tables. Candidate pairing establishes neither cache lifetime nor runtime order. Four explicit-state control scenarios include one real-byte candidate selection; none is an execution trace. Cache call resumes were confirmed by synthetic continuation events and original code; counter wrap is preserved in the control model.

All65,536 headers,65,536 raw lengths,65,536 raw information fields and10 boundary fixtures were checked by Python. Version1 stopped at a mistaken selection assumption that some cache index would have exactly one file candidate. The original script, paired failure report and corrected once-only v2 are preserved. No original evidence failed that assertion. `validation.md`/`.ai.json` quote the successful result, and `control-traces.csv` retains complete events.

## Decisions, guards and remaining unknowns

Use conservative, additive raw data parsing with both encoded span and parser read footprint; retain raw halfwords and unsupported opcode values. Separate optional cache control from metadata reading. Bounds, finite buffers, missing-terminal rejection, negative-length rejection, active-path cycle/depth/event guards and explicit cache initialization are host policy. They do not show that the original function validates malformed inputs. A bounded parser cannot certify subsequent native handler safety or external table availability.

Unknowns: actual cache allocation/initialization/lifetime and draw ordering; real selected targets/counter/FP/SDA state; complete handler grammar and capacity; full drawing/material/attribute/topology/skin semantics; other banks/versions; effects of malformed inputs outside the scoped instruction proof. Static calls and bytes were inspected; no successful native execution was observed. No Ghidra project was opened, no original/frozen/language files changed, and no leaked source was encountered or used. All four team worker slots were active, so this cursor/cache slice was audited sequentially while other assigned team questions ran independently. No engine file changed in this subtask; root owns integration and documentation.
'''
(OUT / 'draw-reference.md').write_text(human, encoding='utf-8')
compact = {
    'result': 'bounded framing/cache control established; native render and runtime state unknown',
    'human_report_sha256': sha(human.encode()),
    'function': validation['original_function'],
    'source_files': 'sources.csv (all SHA256); function-body-ranges.csv; original-instructions.csv; helper-original-words.csv; direct-calls.csv; critical-original-words.csv',
    'grammar': {'header': 'BEs16 raw retained; op=raw&FF', 'EOS': 'raw==00FF ONLY;2B', '04': 'cache[raw>>8]=p+2;counter++;RETURN', '05': 'recurse(cache[raw>>8],sameScratch);counter--;CONTINUE p+2', '00_03_06_07': '2B;01conditionalC754', '08_0F': 'BEs16 argument+2;nextp+4', '10_3F': 'BEs16 length+2;helper(data=p+4)evenzero;nextp+4+2*s16len modulo32', '40_FF': 'BEu16len+2;BEs16info+4 UNCONDITIONAL;data+6;nextp+4+2*u16len modulo32'},
    'boundaries': {'10_3F': 'negative/backward/nonprogress original possible; host policy separately', '40_FF_zero_length': 'encoded4B/minimum parser read6B;info overlaps nextheader', 'odd10_3F_helper': 'reads4B atp+4 regardlesslen;metadata boundary not handler safety'},
    'cache': {'absolute_base': '80357A58', 'selector_domain': 'rawhigh8:0..255;notnativeallocationproof', 'counter': 'r13-71CC;startup-SDA label803AE0F4;notdepth', 'entry_reset': 'r13-7174;startup-SDA label803AE14C pluslocalpendingstate', 'native_guards': 'no localtargetNULL/cachepresence/depth/cycle/counterunderflow checks established', 'runtime_selection': 'unknown;15calls have8or7sameindexcandidates'},
    'pending_groups': {'effective': '(u32(s16(info))>>14)', 'information_examples': info_examples, 'stores': 'first0 thenindices1..k;storebeforeoldindexcomparison;unknowncapacity', 'only_draw_opcodes': '40,41,42;othersstillcommonstate/group/skip', 'numeric_C_equivalence': False},
    'source_validation': {k: validation[k] for k in ['source_artifacts', 'ASM_rows_matched_original', 'unique_ASM_addresses', 'helper_words', 'direct_call_rows_matched_original', 'critical_words']},
    'sample_validation': {**validation['sample'], 'roots': 64, 'all_entries': 79, 'unique_commands': 289, 'encoded_bytes': encoded_bytes, 'unique_opcode_packets': validation['unique_opcode_packets'], 'stream_stops': validation['stream_stops'], 'signed_length_range': validation['signed_length_range'], 'unsigned_length_range': validation['unsigned_length_range'], 'information_effective_groups': validation['information_effective_groups'], 'cache_candidate_counts': validation['cache_candidate_counts']},
    'exhaustive': {'headers': 65536, 'lengths': 65536, 'information': 65536, 'boundary_fixtures': 10, 'explicit_state_traces': 4},
    'v1_failure': 'StopIteration atunique-candidate selection;preserved;v2explicitcandidate passed',
    'host_policies': validation['host_guards'] + ['negative-length rejection ifchosen','missingterminal','handler safety separate'],
    'unknowns': ['runtime cache/order/targets/counter/SDA/FP','native cache andscratchcapacity','full handler/render/material/topology/skin grammar','otherbanks/versions','malformednativeexecution'],
    'repository_engine_frozen_changes': [], 'project_opens': 0, 'native_execution': False, 'leaked_source': 'none encountered or used'
}
(OUT / 'draw-reference.ai.json').write_text(json.dumps(compact, indent=2) + '\n', encoding='utf-8')
manifest_rows = []
for p in sorted(OUT.iterdir()):
    if p.is_file() and not p.name.startswith('manifest'):
        manifest_rows.append({'path': p.name, 'bytes': p.stat().st_size, 'sha256': sha(p.read_bytes())})
with (OUT / 'manifest.csv').open('w', newline='', encoding='utf-8') as f:
    w = csv.DictWriter(f, ['path', 'bytes', 'sha256'])
    w.writeheader()
    w.writerows(manifest_rows)
manifest_sha = sha((OUT / 'manifest.csv').read_bytes())
(OUT / 'manifest.ai.json').write_text(json.dumps({'result': 'finalized', 'manifest_csv_sha256': manifest_sha, 'files': len(manifest_rows), 'source_artifacts_reverified_unchanged': len(sources), 'human_report_sha256': sha(human.encode()), 'raw_evidence_complete': True}, indent=2) + '\n', encoding='utf-8')
(OUT / 'manifest.md').write_text(f'# Final artifact digest\n\nFinalized {len(manifest_rows)} private audit files. All {len(sources)} input/source artifacts were reverified unchanged. Manifest CSV SHA-256: `{manifest_sha}`. Paired reference: draw-reference.md / draw-reference.ai.json. Complete rows and source hashes remain in the CSV files.\n', encoding='utf-8')
print(json.dumps({'result': 'finalized', 'encoded_bytes': encoded_bytes, 'source_artifacts_reverified_unchanged': len(sources), 'files': len(manifest_rows), 'manifest_sha256': manifest_sha, 'reference': str(OUT / 'draw-reference.md')}, separators=(',', ':')))
