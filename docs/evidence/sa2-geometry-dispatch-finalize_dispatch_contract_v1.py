import csv
import hashlib
import json
from pathlib import Path

OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[1]


def rows(path):
    with Path(path).open(newline='', encoding='utf-8') as stream:
        return list(csv.DictReader(stream))


def save(name, values, fields=None):
    with (OUT / name).open('w', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields or list(values[0]))
        writer.writeheader()
        writer.writerows(values)


raw = rows(OUT / 'original-words.csv')
fifo = rows(OUT / 'direct-FIFO-stores.csv')
by_address = {int(row['va'], 16): row for row in raw}
audit = json.loads((OUT / 'original-audit.ai.json').read_text(encoding='utf-8'))

"""/* Pin the original mask/load/attribute-thunk instructions used by this
contract. Exhaustive integer checks preserve signed prefixes without topology. */"""
expected = {
    0x8011D5B0: 0x54BF97BE, 0x8011D5B4: 0x54BC04BE,
    0x8011D5E0: 0xA81A0000, 0x8011D610: 0xA81A0000,
    0x8011D7D0: 0x54BB04BE, 0x8011D830: 0xA8190000,
    0x8011D860: 0xA8190000, 0x8011D870: 0xABD90000,
    0x8011D878: 0xABB90000, 0x80120010: 0x54BF97BE,
    0x80120014: 0x54BA04BE, 0x80120078: 0xA8180000,
    0x801200A8: 0xA8180000, 0x801200B8: 0xABB80000,
    0x801200C0: 0xAB980000,
    0x8011D1B8: 0x38E00000, 0x8011D1BC: 0x3900007D,
    0x8011D1C0: 0x4BFE4019,
}
for address, value in expected.items():
    assert int(by_address[address]['word'], 16) == value
domain = []
for value in range(0x10000):
    signed = value if value < 0x8000 else value - 0x10000
    magnitude = -signed if signed < 0 else signed
    skip = ((signed & 0xFFFFFFFF) >> 14) & 3
    assert skip == value >> 14
    domain.append({'raw_halfword': f'0x{value:04x}', 'signed_value': signed, 'absolute_prefix_count': magnitude, 'info_low14': value & 0x3FFF, 'record_skip_halfwords': skip, 'index_family_stride_halfwords': 1 + skip, 'pair_skip_family_stride_halfwords': 3 + skip, 'fixed_pair_stride_halfwords': 3})
assert domain[0x8000]['absolute_prefix_count'] == 32768
save('exhaustive-halfword-contract.csv', domain)

"""/* Check all local FIFO helpers have exactly the recorded direct stores.
This restores stores collapsed by C; it does not model GPU or FP execution. */"""
helper_sequences = {
    0x8011D678: [], 0x8011D67C: ['stfs:f1', 'stfs:f2', 'stfs:f3'], 0x8011D690: ['stfs:f1', 'stfs:f2', 'stfs:f3'],
    0x8011D788: [], 0x8011D78C: ['stfs:f1', 'stfs:f2', 'stfs:f3'], 0x8011D7A0: ['stfs:f1', 'stfs:f2', 'stfs:f3'],
    0x8011D8E0: [], 0x8011D8E4: ['sth:r3', 'sth:r4'], 0x8011D8F4: ['stfs:f1', 'stfs:f2', 'stfs:f3'], 0x8011D908: ['stfs:f1', 'stfs:f2', 'stfs:f3'],
    0x8011DA04: [], 0x8011DA08: ['stfs:f1', 'stfs:f2', 'stfs:f3'], 0x8011DA1C: ['stfs:f1', 'stfs:f2', 'stfs:f3'],
    0x8011FFD0: [], 0x8011FFD4: ['stw:r3'], 0x8011FFE0: ['stfs:f1', 'stfs:f2', 'stfs:f3'],
    0x80120124: [], 0x80120128: ['sth:r3', 'sth:r4'], 0x80120138: ['stw:r3'], 0x80120144: ['stfs:f1', 'stfs:f2', 'stfs:f3'],
}
for entry, sequence in helper_sequences.items():
    found = [row['store'] + ':' + row['source_register'] for row in fifo if int(row['entry'], 16) == entry]
    assert found == sequence, hex(entry)
    all_stores = [row for row in raw if int(row['entry'], 16) == entry and int(row['opcode']) in (36, 38, 44, 52, 54)]
    assert len(all_stores) == len(sequence)
begin_stores = [row for row in fifo if int(row['entry'], 16) == 0x80101948]
assert [row['store'] for row in begin_stores] == ['stb', 'sth']

layouts = [
    {'entry': '0x8011d594', 'raw_opcodes': '0x40', 'condition_at_draw_stage': 'effective flag0x40 clear; live state0x803AE148 bit2 clear; either pending state', 'record_halfwords': '1 + ((rawInfo>>14)&3)', 'first_word': 'signed16 scratch index; preserve raw bits', 'following_pair': 'not consumed as a pair; extra info skips opaque', 'scratch_reads': 'lfs+0,+4,+8 then lfs+C,+10,+14', 'descriptor_calls': 'reset; (9,1); (10,1)', 'FIFO_per_record': '3 stfs then3 stfs'},
    {'entry': '0x8011d6a4', 'raw_opcodes': '0x40', 'condition_at_draw_stage': 'effective flag0x40 set; state bit2 ignored; either pending state', 'record_halfwords': '1 + ((rawInfo>>14)&3)', 'first_word': 'signed16 scratch index; preserve raw bits', 'following_pair': 'not consumed as a pair; extra info skips opaque', 'scratch_reads': 'lfs+0,+4,+8 then lfs+C,+10,+14', 'descriptor_calls': 'reset; (9,1); (10,1)', 'FIFO_per_record': '3 stfs then3 stfs'},
    {'entry': '0x8011fef4', 'raw_opcodes': '0x40', 'condition_at_draw_stage': 'effective flag0x40 clear; live state0x803AE148 bit2 set; either pending state', 'record_halfwords': '1 + ((rawInfo>>14)&3)', 'first_word': 'signed16 scratch index; preserve raw bits', 'following_pair': 'not consumed as a pair; extra info skips opaque', 'scratch_reads': 'lfs+0,+4,+8 then lwz+18', 'descriptor_calls': 'reset; (9,1); (11,1)', 'FIFO_per_record': '3 stfs then1 stw'},
    {'entry': '0x8011d7b4', 'raw_opcodes': '0x41|0x42', 'condition_at_draw_stage': 'effective flag0x40 clear; live state0x803AE148 bit2 clear; either pending state; current stream only', 'record_halfwords': '3 fixed; info skip bits discarded', 'first_word': 'signed16 scratch index; preserve raw bits', 'following_pair': 'two signed16 loads and two sth; preserve raw bits', 'scratch_reads': 'lfs+0,+4,+8 then lfs+C,+10,+14', 'descriptor_calls': 'format(0,13,1,3,opcode42?12:8); reset; (9,1); (10,1); (13,1)', 'FIFO_per_record': '3 stfs then3 stfs then2 sth'},
    {'entry': '0x8011fff4', 'raw_opcodes': '0x41|0x42', 'condition_at_draw_stage': 'effective flag0x40 clear; live state0x803AE148 bit2 set; pending zero', 'record_halfwords': '3 + ((rawInfo>>14)&3)', 'first_word': 'signed16 scratch index; preserve raw bits', 'following_pair': 'two signed16 loads and two sth; preserve raw bits', 'scratch_reads': 'lfs+0,+4,+8 then lwz+18', 'descriptor_calls': 'format(0,13,1,3,opcode42?12:8); reset; (9,1); (11,1); (13,1)', 'FIFO_per_record': '3 stfs then1 stw then2 sth'},
    {'entry': '0x8011d91c', 'raw_opcodes': '0x41|0x42', 'condition_at_draw_stage': 'effective flag0x40 set; state bit2 ignored; either pending state', 'record_halfwords': '3 + ((rawInfo>>14)&3)', 'first_word': 'signed16 scratch index; preserve raw bits', 'following_pair': 'two words skipped WITHOUT loads/emission; opaque', 'scratch_reads': 'lfs+0,+4,+8 then lfs+C,+10,+14', 'descriptor_calls': 'reset; (9,1); (10,1)', 'FIFO_per_record': '3 stfs then3 stfs'},
    {'entry': '0x80120158', 'raw_opcodes': '0x41|0x42', 'condition_at_draw_stage': 'effective flag0x40 clear; live state0x803AE148 bit2 set; pending nonzero; pointer-array path', 'record_halfwords': 'multiple streams mutated independently; excluded from single-stream reader', 'first_word': 'scratch index from stream0 only; others skip corresponding word', 'following_pair': 'one pair from each stream; per-stream opcode42 format selector', 'scratch_reads': 'lfs+0,+4,+8 then lwz+18 from stream0 index', 'descriptor_calls': 'format(0,13+i,1,3,storedOpcode42[i]?12:8); reset; (9,1); (11,1); (13+i,1)', 'FIFO_per_record': '3 stfs then1 stw then2 sth per stream'},
]
save('handler-layout-contract.csv', layouts)

"""/* Verify selected original and frozen inputs again at handoff; keep the
search/function boundary explicit instead of claiming all GX state effects. */"""
guards = rows(OUT / 'input-source-hashes.csv')
for row in guards:
    assert hashlib.sha256((ROOT / row['path']).read_bytes()).hexdigest() == row['sha256'], row['path']
    row['final_unchanged'] = True
save('source-hash-guards.csv', guards)
anchors = sorted(set(expected) | {0x8011CCF8, 0x8011D594, 0x8011D6A4, 0x8011D7B4, 0x8011D91C, 0x8011FEF4, 0x8011FFF4, 0x80120158, 0x8011D1AC, 0x80101948, 0x801011D8, 0x80100CF8, 0x80100830, 0x80100D44, 0x8011D2F4})
save('canonical-contract-sites.csv', [by_address[address] for address in anchors])

def canonical(address):
    row = by_address[address]
    return f"`{row['va']}` / DOL `{row['dol_file_offset']}` / ISO `{row['iso_file_offset']}`"


result = {
    'status': 'bounded dispatch/attribute/raw-layout contract complete; GPU/FP/runtime not reproduced',
    'scope': audit,
    'handler_layouts': layouts,
    'dispatch_inputs': ['raw opcode captured before header override', 'effective signed high header byte; override under0x803AE0E8&0x800 using low16 masks0x803AE0E4/0x803AE0E0', 'saved effective flag byte for pending group', 'live0x803AE148&2 at draw selection', 'pending-group state and accumulated pointer array'],
    'dispatch_stage_caveat': 'First packet with zero pending and nonzero logical32-shift of sign-extended info>>14 is deferred. Table applies only once draw stage reached, not every raw geometry command.',
    'raw_info': {'group_count': 'info &0x3fff', 'record_skip': '(info>>14)&3', 'outer_pending': 'logical32 right-shift of signed16 info by14; not equivalent to raw high2 for bit15 set', 'group_count_zero': 'native do-while has no zero guard; host rejection is conservative policy'},
    'prefix': {'load': 'signed16', 'count': 'absolute value in32-bit integer, low16 passed to begin', 'min': 0, 'max': 32768, 'raw8000_magnitude': 32768, 'zero': 'native no pre-loop guard; host reject', 'sign_effect': 'all7 helpers use the same begin command0x98; no sign-dependent winding/topology conclusion'},
    'scratch_index': {'load': 'signed16 then shiftleft5 and add current r4 scratch base', 'capacity': 'unknown', 'raw_reader': 'retain bits and signed interpretation; do not dereference or normalize'},
    'pair': {'native_load_when_used': 'lha signed16', 'native_emit_when_used': 'sth low16 r3 then r4', 'conversion': 'none in these helpers', 'GX_format_numeric_arg': '8 for opcode41 /12 for opcode42 at attribute13, count1,type3; named units not assigned'},
    'attribute_calls': {'baseline0x8011D2F4': [[0, 9, 1, 4, 0], [0, 10, 0, 4, 0], [0, 11, 1, 5, 0]], 'descriptor_reset': '0x80100cf8; numeric descriptor IDs recorded per handler', 'format_set': '0x80100d44; state-cache dirty bit0x10', 'descriptor_set': '0x80100830; state-cache dirty bit8', 'thunk0x8011D1AC': 'preserves incoming r3..r6, inserts r7=0/r8=0x7D then calls0x801011D8', 'thunk_tuples_from_dispatch': [[0, 0, 1, 42, 0, 125], [0, 1, 4, 60, 0, 125], ['i', 1, 'i+4', 60, 0, 125]], 'GX_state_equivalence': 'not established'},
    'FIFO': {'address': '0xcc008000', 'all_identified_direct_static_store_sites': len(fifo), 'local_helper_store_sites': sum(len(value) for value in helper_sequences.values()), 'begin0x80101948': [{'va': row['va'], 'store': row['store'], 'source': row['source_register']} for row in begin_stores], 'helper_sequences': {hex(entry): sequence for entry, sequence in helper_sequences.items()}, 'packed_scratch18': 'lwz/stw raw32; generated float-looking call expression is not a float-conversion proof', 'limit': 'Full local helper stores and direct store sites retained; dirty-state flushes call other GX functions outside bounded closure, so this is not a complete dynamic GPU stream.'},
    'minimal_safe_reader': {'mode1': 'IndexWithInfoSkips: op40, index plus opaque skip words', 'mode2': 'IndexAndPair: op41/42, fixed3 halfwords', 'mode3': 'IndexAndPairWithInfoSkips: op41/42,3+skip halfwords; trailing pair opaque underD91C', 'caller': 'explicit helper-layout choice; do not infer native dispatch from header alone', 'preserve': ['raw info and all count/index/pair/skip words', 'signed count prefix and abs8000=32768', 'declared command tail/padding'], 'host_reject': ['wrong opcode/layout combination', 'info low14 zero', 'run prefix zero', 'truncated record spans or group prefixes'], 'exclude': ['0x80120158 multi-stream collection', 'scratch dereference/FP/GPU/UV conversion', 'topology/winding/cache binding and native memory safety claims']},
    'integer_validation': {'all_halfwords': len(domain), 'sample_geometry_validation': 'not rerun here; root owns independent sample/reader validation', 'source_guards_unchanged': len(guards)},
    'unknowns': ['full GX state/flush semantics', 'retail cache contents and root/callback/culling order', 'scratch capacity/ownership and exact first-stream FP/GQR results', 'topology/winding meaning of command0x98', 'UV coordinate units/scaling/wrapping and rasterization', 'grouped-stream concrete runtime contents and safe native limits', 'exact floating-point and full function return ABI'],
    'changes': {'engine': [], 'repository': [], 'frozen_or_original': [], 'database_or_language': []},
}
(OUT / 'dispatch-contract.ai.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')

table = '\n'.join(f"| `{row['entry']}` | `{row['raw_opcodes']}` | {row['record_halfwords']} | {row['following_pair']} |" for row in layouts)
human = f"""# Original geometry dispatch and raw attribute contract

This bounded pass establishes seven helper layouts and their dispatch conditions. It supplies a conservative raw-reader contract; it does not reproduce topology, floating-point calculations, GPU state or runtime cache binding. No engine/repository/original/frozen/project/language files changed, and no game code ran.

## Dispatch requires current state

The dispatcher is {canonical(0x8011CCF8)}. It captures the raw low-byte opcode before optional header masking. When no group is pending and `0x803AE0E8 & 0x800` is set, the header used for flags becomes `(rawHeader & low16(0x803AE0E4)) | low16(0x803AE0E0)`. Its high byte is sign-extended and saved when a group begins. The draw branch uses bit0x40 of this effective/saved high byte, live `0x803AE148 & 2`, and pending-group state. Those global names assume startup r13; runtime SDA/caller state is not newly proved.

A first geometry packet with zero pending and nonzero **logical32 shift of sign-extended info by14** is saved and deferred before drawing. Negative info makes that pending expression differ from raw high2 bits. Thus no helper can be selected from a raw header/info alone, and the following table only applies after the draw stage is reached.

For opcode40, flag0x40 set selects D6A4; otherwise state bit2 clear selects D594 and set selects FEF4, for either pending state. For opcode41/42, flag0x40 set selects D91C. With that flag clear, state bit2 clear selects D7B4 on the current stream even after accumulation; state bit2 set selects FFF4 when pending is zero and20158 when pending is nonzero. Complete canonical sites and original words are retained.

## Raw layouts

| Helper | Raw opcodes | Halfwords per record | Following pair |
|---|---|---|---|
{table}

Each helper masks info low14 to obtain its outer group count. Each group begins with a **signed16** count prefix, made positive in32-bit arithmetic if negative and passed low16 to begin. Raw0x8000 therefore means magnitude32,768. Every helper calls begin with numeric command0x98 and format0 regardless of count sign. No sign-dependent topology or winding rule is inferred. These are native do-while loops without a pre-loop zero guard; rejecting zero group/prefix counts is a host safety policy.

Every single-stream record first loads a signed16 scratch index, shifts it left5 and adds the current scratch base. Preserve the raw index bits and signed interpretation; no capacity, valid range or safe dereference is established. D594/D6A4/D7B4/D91C load scalar words through lfs at scratch+0,+4,+8, then+C,+10,+14. FEF4/FFF4/20158 load the first triple, then a raw lwz at scratch+18. That latter value is emitted with **stw**, despite float-looking generated call expressions. No color encoding or FP conversion is assigned by this audit.

D7B4 masks away info skip bits and uses a fixed three-halfword stride. FFF4 and D91C instead advance by `3 + ((rawInfo>>14)&3)`; D91C never loads or emits the following pair, so those words remain opaque under that path. D594/D6A4/FEF4 advance by `1 + skip`. Where D7B4/FFF4 use a pair, both halfwords are loaded signed and emitted as two sth stores, preserving their low16 bits. They do not perform a coordinate conversion here.

20158 is a separate mutable pointer-array layout. It takes the group count and scratch index from stream0, advances other streams past their count/index words, then emits a pair from each stream and mutates the saved pointers. Its per-stream format selectors come from recorded opcode42 tests. Single-stream decoding must exclude this path; the audit does not establish matching counts, concrete runtime groups or native array limits.

## Numeric attribute setup and original stores

Baseline setup {canonical(0x8011D2F4)} calls format helper `0x80100D44` with `(0,9,1,4,0)`, `(0,10,0,4,0)`, `(0,11,1,5,0)`. Each emitter resets descriptors through `0x80100CF8`, then enables numeric descriptor9 and either10 (six-scalar path) or11 (packed-word path), each with value1. Pair emitters also enable13;20158 enables13+i for all collected streams. Exact per-handler tuples are in `handler-layout-contract.csv`; numeric identifiers are kept without inferring a complete SDK contract.

D7B4/FFF4 call the format helper with `(0,13,1,3,8)` for opcode41 and `(0,13,1,3,12)` for opcode42;20158 does this per collected stream. Those are original arguments, not a proved texture-coordinate unit or scaling rule. Descriptor/format helpers update the pointed state cache and dirty bits8/0x10. Begin `0x80101948` may flush other dirty-state helpers outside this bounded closure, so the dynamic GPU stream is not fully reconstructed.

Generated C makes `0x8011D1AC` look argument-free. Original {canonical(0x8011D1AC)} instead preserves incoming r3..r6, inserts r7=0 at0x8011D1B8 and r8=0x7D at0x8011D1BC, then calls0x801011D8 at0x8011D1C0. Dispatcher tuples are `(0,0,1,0x2A,0,0x7D)`, `(0,1,4,0x3C,0,0x7D)`, or `(i,1,i+4,0x3C,0,0x7D)` according to branch. No full register/FP return ABI is assigned.

Original local FIFO helpers restore the stores collapsed by C: every scalar-triple helper performs **stfs f1, stfs f2, stfs f3** in that order to0xCC008000; D8E4/20128 perform **sth r3, sth r4**; FFD4/20138 perform **stw r3**. The empty finish helpers are original returns. Begin emits a command byte then a halfword count after its state work; C retained only the final overlapping store. `direct-FIFO-stores.csv` records all44 directly identified static FIFO-store sites in this bounded set, including all36 local-helper stores, the two begin stores, and six stores inside011D8. These are source instruction sites, not a claim that all state-dependent GPU effects have been reconstructed.

## Minimal safe reader and verification

Require an explicit caller layout choice: IndexWithInfoSkips only for op40; IndexAndPair fixed3 or IndexAndPairWithInfoSkips only for op41/42. Preserve every count/index/pair/skip word and declared tail bytes. The pair under D91C stays opaque. Reject wrong opcode/mode combinations, zero low14 group count, zero run prefix and truncated spans as documented host guards. Keep raw0x8000 and magnitude32,768. Do not infer actual dispatch, cache state, winding, UV conversion, scratch access or GPU behavior from this choice.

Original DOL SHA256`{audit['DOL_sha256']}`. Validation result:40 functions,1,907 complete words,1,868 retained ASM rows checked against original bytes/offsets,44 FIFO sites,65,536 exhaustive halfword cases, all129 source guards unchanged. Canonical VA/DOL/ISO evidence is in the raw CSVs. Root owns independent real-sample reader validation; this audit did not rerun it.

Unknowns remain full GX/flush behavior, concrete runtime dispatch and grouped streams, scratch ownership/capacity, first-stream FP/GQR results, topology/winding, UV units/rasterization, cache binding/order and full ABI. No leaked original source was used.
"""
for before, after in {
    'bit0x40': 'bit 0x40', 'by14': 'by 14', 'high2': 'high 2',
    'opcode40': 'opcode 40', 'opcode41/42': 'opcode 41/42',
    'and20158': 'and 20158', 'low14': 'low 14',
    'signed16': 'signed 16', 'in32-bit': 'in 32-bit',
    'low16': 'low 16', 'Raw0x8000': 'Raw 0x8000',
    'magnitude32,768': 'magnitude 32,768', 'command0x98': 'command 0x98',
    'format0': 'format 0', 'left5': 'left 5',
    'from stream0': 'from stream 0', 'enables13': 'enables 13',
    'descriptor9': 'descriptor 9', 'either10': 'either 10',
    'or11': 'or 11', 'value1': 'value 1', 'all44': 'all 44',
    'all36': 'all 36', 'inside011D8': 'inside 011D8',
    'at0x': 'at 0x', 'calls0x': 'calls 0x', 'to0x': 'to 0x',
    'SHA256`': 'SHA256 `', 'result:40': 'result: 40',
    'functions,1,907': 'functions, 1,907', 'words,1,868': 'words, 1,868',
    'offsets,44': 'offsets, 44', 'sites,65,536': 'sites, 65,536',
    'all129': 'all 129', 'raw0x8000': 'raw 0x8000',
}.items():
    human = human.replace(before, after)
(OUT / 'dispatch-contract.md').write_text(human, encoding='utf-8')
manifest = []
for path in sorted(OUT.iterdir()):
    if path.is_file() and not path.name.startswith('manifest.'):
        manifest.append({'path': path.name, 'bytes': path.stat().st_size, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
save('manifest.csv', manifest)
(OUT / 'manifest.ai.json').write_text(json.dumps({'files': manifest, 'source_guards': len(guards), 'changes': result['changes']}, indent=2) + '\n', encoding='utf-8')
(OUT / 'manifest.md').write_text(f"# Geometry dispatch manifest\n\n{len(manifest)} complete artifacts with SHA256 and size in CSV/AI twin. Handoff: dispatch-contract.md/.ai.json; full original words, FIFO sites, handler contracts and unchanged source guards. No repository/engine/original/frozen/project changes.\n", encoding='utf-8')
print(json.dumps({'status': 'ready', 'sources_unchanged': len(guards), 'halfword_cases': len(domain), 'helper_FIFO_stores': result['FIFO']['local_helper_store_sites'], 'all_direct_FIFO_sites': len(fifo), 'begin_stores': result['FIFO']['begin0x80101948'], 'report': str((OUT / 'dispatch-contract.md').resolve())}, separators=(',', ':')))
