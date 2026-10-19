"""One-run, project-free original drawing-stream audit; no engine or native execution."""
import collections
import csv
import hashlib
import json
import re
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
EXPECTED_DOL = 'a53335308d1f820be236fd2b6342fee850eaf048eb26aac21ddb1903b060db2e'
EXPECTED_SAMPLE = 'b7ea586ed0fa22330dc8a2cfe2bb8fa9ce4ac70d9561764f35af4ced5d371963'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def rows(path):
    with path.open(newline='', encoding='utf-8-sig') as f:
        return list(csv.DictReader(f))


def write_csv(name, data):
    if not data:
        return
    keys = list(dict.fromkeys(k for r in data for k in r))
    with (OUT / name).open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, keys)
        w.writeheader()
        w.writerows(data)


def s16(value):
    return value - 0x10000 if value & 0x8000 else value


def mask(mb, me):
    return sum(1 << (31 - i) for i in range(32) if (mb <= i <= me if mb <= me else i >= mb or i <= me))


def rotl(value, shift):
    return ((value << shift) | (value >> ((32 - shift) % 32))) & 0xffffffff


def classify(header):
    op = header & 255
    if header == 255:
        return 'exact_end'
    if op == 4:
        return 'cache_define_return'
    if op == 5:
        return 'cache_call_continue'
    if op < 8:
        return 'single_halfword'
    if op < 16:
        return 'signed_argument'
    if op < 64:
        return 'signed_length'
    return 'unsigned_length_information'


assert not (OUT / 'validation.ai.json').exists(), 'Version already run; preserve prior evidence.'
dol_path = ROOT / 'work/sa2-disc/main.dol'
sample_path = ROOT / 'work/sa2-disc/sonicmdl.prs.decoded'
dol, sample = dol_path.read_bytes(), sample_path.read_bytes()
assert sha(dol) == EXPECTED_DOL
assert sha(sample) == EXPECTED_SAMPLE
mapping_path = ROOT / 'work/dol-elf-mapping-final.json'
mapping = json.loads(mapping_path.read_text())['mappings']
with (ROOT / 'work/sa2.iso').open('rb') as f:
    f.seek(0x420)
    dol_iso = struct.unpack('>I', f.read(4))[0]
    f.seek(dol_iso)
    assert f.read(len(dol)) == dol
    f.seek(0x479024a4)
    compressed_sha = sha(f.read(102331))
assert compressed_sha == 'd8f90e6c724e709b8d3431e725a5db1d1a096bdf5118d2ecca9ad356e7862d99'


def coordinates(va):
    hits = [m for m in mapping if m['address'] <= va < m['address'] + m['size']]
    assert len(hits) == 1
    offset = hits[0]['dol_offset'] + va - hits[0]['address']
    return {'original_va': hex(va), 'dol_offset': hex(offset), 'iso_offset': hex(dol_iso + offset)}


def word(va):
    return struct.unpack_from('>I', dol, int(coordinates(va)['dol_offset'], 16))[0]


entries = {0x8011ccf8, 0x8011c628, 0x8011c754, 0x8011c76c, 0x8011c85c, 0x8010afb0, 0x8010affc, 0x8011d414}
sources, instructions, bodies, edges, catalogs = [], [], [], [], {}
asm_pattern = re.compile(r'^([0-9a-f]{8}) file=(0x[0-9a-f]+) ([0-9a-f]{8}) (.*?) flow=(.*)$')
for view, folder in [('context_free', 'main'), ('startup_sda', 'main-sda-v1')]:
    base = ROOT / 'work/full-decompile/gekko' / folder / 'export'
    catalog = {int(r['entry'], 16): r for r in rows(base / 'functions.csv')}
    catalogs[view] = catalog
    for name in ['functions.csv', 'function_body_ranges.csv', 'direct_calls.csv']:
        p = base / name
        sources.append({'view': view, 'entry': '', 'kind': 'catalog', 'path': str(p), 'sha256': sha(p.read_bytes())})
    for entry in sorted(entries):
        r = catalog[entry]
        assert int(r['canonical_file_offset'], 16) == int(coordinates(entry)['dol_offset'], 16)
        for kind in ['pseudocode', 'assembly']:
            if not r[kind + '_path']:
                continue
            p = base / r[kind + '_path']
            data = p.read_bytes()
            assert sha(data) == r[kind + '_sha256']
            sources.append({'view': view, 'entry': hex(entry), 'kind': kind, 'path': str(p), 'sha256': sha(data), **coordinates(entry), 'status': r['status'], 'body_ranges': r['body_ranges']})
            if kind == 'assembly':
                for line in data.decode('utf-8-sig').splitlines():
                    match = asm_pattern.match(line)
                    if not match:
                        continue
                    va, offset, opcode, instruction, override = match.groups()
                    va = int(va, 16)
                    assert word(va) == int(opcode, 16)
                    assert offset == coordinates(va)['dol_offset']
                    instructions.append({'view': view, 'owner': hex(entry), **coordinates(va), 'word': '0x' + opcode, 'instruction': instruction, 'flow_override': override, 'source_sha256': sha(data)})
        for b in rows(base / 'function_body_ranges.csv'):
            if int(b['entry'], 16) == entry:
                bodies.append({'view': view, **b, **coordinates(int(b['range_start'], 16))})
    for r in rows(base / 'direct_calls.csv'):
        if int(r['caller_entry'], 16) not in entries:
            continue
        va, target = int(r['call_site'], 16), int(r['target'], 16)
        w = word(va)
        assert w >> 26 == 18 and w & 1
        displacement = w & 0x03fffffc
        if displacement & 0x02000000:
            displacement -= 0x04000000
        actual = (displacement if w & 2 else va + displacement) & 0xffffffff
        assert actual == target
        edges.append({'view': view, **r, **coordinates(va), 'word': hex(w)})

# The generated C invents an aggregate return from a GPR-save fallthrough helper.
# Decode the bounded original helpers through their first blr to establish effects.
helper_words = []
for start, expected_primary in [(0x8010afb0, 36), (0x8010affc, 32)]:
    for va in range(start, start + 128, 4):
        w = word(va)
        primary = w >> 26
        if w == 0x4e800020:
            helper_words.append({'entry': hex(start), **coordinates(va), 'word': hex(w), 'verified_effect': 'blr'})
            break
        assert primary == expected_primary
        rt, ra = (w >> 21) & 31, (w >> 16) & 31
        assert 20 <= rt <= 31 and ra == 11
        helper_words.append({'entry': hex(start), **coordinates(va), 'word': hex(w), 'verified_effect': ('stw' if primary == 36 else 'lwz') + f' r{rt},{s16(w & 65535)}(r11)'})
    else:
        raise AssertionError('No bounded helper return')

critical = {
    0x8011cd0c: 'incoming r3 saved as stream cursor r20',
    0x8011cd10: 'incoming r4 saved as scratch r21',
    0x8011cd90: 'cache selector high byte via rotate24/maskFF',
    0x8011cd98: 'cache selector times4',
    0x8011cda8: 'command04 stores following pointer',
    0x8011cdb4: 'command04 stores incremented global counter',
    0x8011cdb8: 'command04 branches to function return',
    0x8011cdcc: 'command05 loads selected pointer without local null check',
    0x8011cdd4: 'command05 recursive direct call',
    0x8011cde0: 'command05 stores decremented global counter after return',
    0x8011cde4: 'command05 continues caller cursor',
    0x8011cdfc: '08..0F signed16 argument load',
    0x8011ce28: '10..3F signed16 length load',
    0x8011ce50: '10..3F invokes helper regardless declared length',
    0x8011ce54: 'signed length times2 modulo32',
    0x8011ce68: '40..FF unsigned16 length load',
    0x8011ce6c: '40..FF unconditional signed16 info load',
    0x8011ce84: 'pending group stores data pointer before count compare',
    0x8011cee8: 'arithmetic shift of sign-extended header high byte',
    0x8011cf2c: 'logical right14 of sign-extended info via rotate18/mask0003FFFF',
    0x8011cf3c: 'first pending group data pointer',
    0x8011cf68: 'draw dispatch40,41,42 only; common state still applies to others',
    0x8011d168: 'unsigned packet length minus1',
    0x8011d16c: 'length-minus1 times2 modulo32',
    0x8011d170: 'next cursor from current data pointer',
    0x8011d184: 'signed16 header load',
    0x8011d188: 'advance header cursor by2',
    0x8011d18c: 'exact signed-header compareFF',
}
critical_rows = []
for va, effect in critical.items():
    w = word(va)
    r = {**coordinates(va), 'word': hex(w), 'effect': effect, 'primary_opcode': w >> 26}
    if w >> 26 == 21:
        sh, mb, me = (w >> 11) & 31, (w >> 6) & 31, (w >> 1) & 31
        r.update(shift=sh, mask_begin=mb, mask_end=me, mask=hex(mask(mb, me)))
    critical_rows.append(r)
assert word(0x8011ce28) >> 26 == 42
assert word(0x8011ce68) >> 26 == 40
assert word(0x8011ce6c) >> 26 == 42
assert word(0x8011d184) >> 26 == 42


def read_packet(data, offset):
    assert 0 <= offset <= len(data) - 2, ('header_bounds', offset)
    header = struct.unpack_from('>H', data, offset)[0]
    kind, op = classify(header), header & 255
    r = {'offset': hex(offset), 'header': hex(header), 'header_s16': s16(header), 'opcode': hex(op), 'kind': kind, 'minimum_parser_read_bytes': 2, 'byte_size': 2, 'next_offset': hex(offset + 2), 'data_offset': '', 'raw_info': '', 'length_raw': '', 'length_s16': '', 'cache_index': '', 'raw_hex': data[offset:offset + 2].hex()}
    if kind in ['cache_define_return', 'cache_call_continue']:
        r['cache_index'] = header >> 8
    if kind in ['signed_argument', 'signed_length', 'unsigned_length_information']:
        assert offset + 4 <= len(data), ('argument_length_bounds', offset)
        value = struct.unpack_from('>H', data, offset + 2)[0]
        r['minimum_parser_read_bytes'] = 4
        if kind == 'signed_argument':
            r.update(argument_raw=hex(value), argument_s16=s16(value), byte_size=4, next_offset=hex(offset + 4))
        elif kind == 'signed_length':
            delta = 4 + 2 * s16(value)
            r.update(length_raw=value, length_s16=s16(value), byte_size=delta, next_offset=hex(offset + delta), next_offset_u32=hex((offset + delta) & 0xffffffff), data_offset=hex(offset + 4), minimum_helper_read_bytes=8 if op & 1 else 4)
        else:
            assert offset + 6 <= len(data), ('information_bounds', offset)
            info = struct.unpack_from('>H', data, offset + 4)[0]
            delta = 4 + 2 * value
            r.update(length_raw=value, byte_size=delta, next_offset=hex(offset + delta), data_offset=hex(offset + 6), minimum_parser_read_bytes=6, raw_info=hex(info), info_s16=s16(info), raw_top2=info >> 14, effective_group_count=(s16(info) & 0xffffffff) >> 14, raw_low14=info & 0x3fff)
    end = offset + max(r['byte_size'], r['minimum_parser_read_bytes'])
    assert end <= len(data), ('span_bounds_host_policy', offset, end)
    r['raw_hex'] = data[offset:end].hex()
    r['encoded_span_sha256'] = sha(data[offset:offset + r['byte_size']]) if r['byte_size'] >= 0 else ''
    return r


payload_path = ROOT / 'work/sa2-payload-consumers/sample-payload-headers.csv'
payloads = rows(payload_path)
roots = collections.defaultdict(list)
for r in payloads:
    offset = int(r['payload_offset'], 16)
    assert sample[offset:offset + 24].hex() == r['raw_24_bytes']
    pointer = struct.unpack_from('>I', sample, offset + 4)[0]
    assert pointer == int(r['stream_4'], 16)
    if pointer:
        roots[pointer].append(offset)
pending = collections.deque(sorted(roots))
provenance = {p: 'payload+4' for p in roots}
streams, packets, unique_packets = [], [], {}
while pending:
    root = pending.popleft()
    offset, seen, local = root, set(), []
    for index in range(10000):
        assert offset not in seen, ('active_linear_cycle_host_guard', offset)
        seen.add(offset)
        r = read_packet(sample, offset)
        assert r['byte_size'] > 0, ('nonprogress_host_guard', offset)
        local.append(r)
        packets.append({'stream_root': hex(root), 'stream_provenance': provenance[root], 'index': index, **r})
        unique_packets[offset] = r
        if r['kind'] == 'cache_define_return':
            body = offset + 2
            if body not in provenance:
                provenance[body] = 'following command04 at ' + hex(offset) + '; static candidate body, not executed'
                pending.append(body)
        if r['kind'] in ['cache_define_return', 'exact_end']:
            streams.append({'stream_root': hex(root), 'provenance': provenance[root], 'payload_references': ';'.join(hex(v) for v in roots.get(root, [])), 'packet_count': len(local), 'stop': r['kind'], 'stop_offset': r['offset'], 'end_exclusive': r['next_offset'], 'linear_bytes': offset + 2 - root})
            break
        offset = int(r['next_offset'], 16)
    else:
        raise AssertionError('Linear packet budget host guard')

definitions = collections.defaultdict(set)
for off, r in unique_packets.items():
    if r['kind'] == 'cache_define_return':
        definitions[r['cache_index']].add(off + 2)
cache_edges = []
for off, r in sorted(unique_packets.items()):
    if r['kind'] == 'cache_call_continue':
        candidates = sorted(definitions[r['cache_index']])
        cache_edges.append({'call_offset': hex(off), 'index': r['cache_index'], 'candidate_body_offsets': ';'.join(hex(c) for c in candidates), 'candidate_count': len(candidates), 'caller_continuation': hex(off + 2), 'qualification': 'same-index file candidates only; cache initialization/order/runtime target unknown'})

# Exhaustively verify the exact header classifier and the two distinct length paths.
header_cases = [{'header': hex(h), 'kind': classify(h), 'opcode': hex(h & 255), 'high_byte': h >> 8} for h in range(65536)]
length_cases, info_cases = [], []
for value in range(65536):
    signed = s16(value)
    narrow_next = (4 + 2 * signed) & 0xffffffff
    native_narrow = (4 + rotl(signed & 0xffffffff, 1) & 0xffffffff)
    # rlwinm shift1/maskFFFFFFFE is a logical shift-left modulo32.
    native_narrow = (4 + (rotl(signed & 0xffffffff, 1) & mask(0, 30))) & 0xffffffff
    wide_next = 4 + 2 * value
    native_wide = (6 + (rotl((value - 1) & 0xffffffff, 1) & mask(0, 30))) & 0xffffffff
    assert narrow_next == native_narrow
    assert wide_next == native_wide
    effective = (signed & 0xffffffff) >> 14
    assert effective == (rotl(signed & 0xffffffff, 18) & mask(14, 31))
    length_cases.append({'raw_u16': value, 'signed_s16': signed, '10_3f_delta_signed': 4 + 2 * signed, '10_3f_delta_u32': hex(narrow_next), '40_ff_delta_unsigned': wide_next})
    info_cases.append({'raw_u16': value, 'signed_s16': signed, 'raw_top2': value >> 14, 'effective_group_count': effective, 'raw_low14': value & 0x3fff})

# This bounded control model exposes cache effects only. The caller explicitly supplies
# initial cache/counter; these scenarios are not evidence of retail ordering or GPU effects.
trace_rows, trace_summaries = [], []


def trace(name, data, sequence, initial_cache, initial_counter=0):
    cache, counter, events, active = dict(initial_cache), initial_counter, [], set()
    def invoke(root, depth):
        nonlocal counter
        assert depth < 64, 'host depth budget'
        assert root not in active, 'host active-call cycle guard'
        active.add(root)
        offset, seen = root, set()
        while True:
            assert len(events) < 10000, 'host event budget'
            assert offset not in seen, 'host linear-cycle guard'
            seen.add(offset)
            r = read_packet(data, offset)
            e = {'scenario': name, 'event': len(events), 'depth': depth, 'root': hex(root), 'offset': hex(offset), 'header': r['header'], 'kind': r['kind'], 'counter_before': counter, 'cache_index': r['cache_index']}
            events.append(e)
            if r['kind'] == 'exact_end':
                e['counter_after'] = counter
                break
            if r['kind'] == 'cache_define_return':
                cache[r['cache_index']] = offset + 2
                counter = (counter + 1) & 0xffffffff
                e.update(saved_pointer=hex(offset + 2), counter_after=counter)
                break
            if r['kind'] == 'cache_call_continue':
                index = r['cache_index']
                if index not in cache:
                    e['result'] = 'unresolved caller-supplied cache; model stopped before native dereference'
                    active.remove(root)
                    return 'unresolved_cache'
                e['target'] = hex(cache[index])
                result = invoke(cache[index], depth + 1)
                if result != 'returned':
                    active.remove(root)
                    return result
                counter = (counter - 1) & 0xffffffff
            e['counter_after'] = counter
            assert r['byte_size'] > 0, 'host nonprogress guard'
            offset = int(r['next_offset'], 16)
        active.remove(root)
        return 'returned'
    results = [invoke(root, 0) for root in sequence]
    trace_rows.extend(events)
    trace_summaries.append({'scenario': name, 'initial_cache': {str(k): hex(v) for k, v in initial_cache.items()}, 'caller_sequence': [hex(v) for v in sequence], 'results': results, 'initial_counter': initial_counter, 'final_counter': counter, 'final_cache': {str(k): hex(v) for k, v in cache.items()}, 'events': len(events), 'qualification': 'explicit synthetic caller state/order; no graphics or native execution'})
    return results, counter, cache


fixture = bytes.fromhex('0704000100ff0705000100ff')
result, counter, cache = trace('synthetic_define_then_call_and_continue', fixture, [0, 6], {})
assert result == ['returned', 'returned'] and counter == 0 and cache[7] == 2
result, counter, cache = trace('synthetic_explicit_cache_counter_wrap', fixture, [6], {7: 2})
assert result == ['returned'] and counter == 0xffffffff
result, _, _ = trace('synthetic_unresolved_cache', fixture, [6], {})
assert result == ['unresolved_cache']
if cache_edges:
    selected = next(e for e in cache_edges if e['candidate_count'] == 1)
    index, call = selected['index'], int(selected['call_offset'], 16)
    body = int(selected['candidate_body_offsets'], 16)
    result, _, _ = trace('real_bytes_explicit_same_index_candidate', sample, [call], {index: body})
    assert result == ['returned']

fixtures = []
for name, data in [
    ('exact_end', bytes.fromhex('00ff')),
    ('high_byte_ff_is_not_end', bytes.fromhex('01ff000000ff')),
    ('negative_header_ff_is_not_end', bytes.fromhex('ffff000000ff')),
    ('unsigned_zero_length_reads_overlapping_next_header', bytes.fromhex('0040000000ff')),
    ('signed_zero_length_odd_handler_read_beyond_encoded_span', bytes.fromhex('0011000000ff0000')),
    ('signed_minus_two_nonprogress', bytes.fromhex('0010fffe')),
    ('signed_minus_one_next_is_length', bytes.fromhex('0010ffff')),
    ('signed_minimum_moves_back', bytes.fromhex('00108000')),
    ('argument_sign_extension', bytes.fromhex('0008ffff00ff')),
    ('highest_cache_index_define', bytes.fromhex('ff0400ff')),
]:
    r = read_packet(data, 0)
    fixtures.append({'scenario': name, **r})
assert fixtures[1]['kind'] != 'exact_end' and fixtures[2]['kind'] != 'exact_end'
assert fixtures[3]['byte_size'] == 4 and fixtures[3]['minimum_parser_read_bytes'] == 6
assert fixtures[5]['byte_size'] == 0 and fixtures[6]['byte_size'] == 2

source_inputs = [dol_path, sample_path, mapping_path, payload_path, ROOT / 'work/sonicmdl-loader/sample-validation.ai.json', ROOT / 'work/sa2-payload-consumers/payload-reference.ai.json', Path(__file__)]
for p in source_inputs:
    sources.append({'view': 'original_or_prior_validated', 'entry': '', 'kind': 'input', 'path': str(p), 'sha256': sha(p.read_bytes())})
write_csv('sources.csv', sources)
write_csv('function-body-ranges.csv', bodies)
write_csv('original-instructions.csv', instructions)
write_csv('helper-original-words.csv', helper_words)
write_csv('direct-calls.csv', edges)
write_csv('critical-original-words.csv', critical_rows)
write_csv('sample-streams.csv', streams)
write_csv('sample-packets.csv', packets)
write_csv('sample-unique-packets.csv', [unique_packets[k] for k in sorted(unique_packets)])
write_csv('sample-cache-candidates.csv', cache_edges)
write_csv('header-classification.csv', header_cases)
write_csv('length-arithmetic.csv', length_cases)
write_csv('information-arithmetic.csv', info_cases)
write_csv('boundary-fixtures.csv', fixtures)
write_csv('control-traces.csv', trace_rows)
summary = {
    'result': 'passed', 'original_function': coordinates(0x8011ccf8), 'DOL_sha256': sha(dol), 'DOL_ISO_offset': hex(dol_iso),
    'sample': {'decoded_bytes': len(sample), 'decoded_sha256': sha(sample), 'stored_ISO_offset': '0x479024a4', 'stored_bytes': 102331, 'stored_sha256': compressed_sha, 'coordinate_note': 'All sample packet offsets refer to decompressed bytes; no direct offset mapping into PRS/ISO.'},
    'source_artifacts': len(sources), 'ASM_rows_matched_original': len(instructions), 'unique_ASM_addresses': len({r['original_va'] for r in instructions}), 'helper_words': len(helper_words), 'direct_call_rows_matched_original': len(edges), 'critical_words': len(critical_rows),
    'sample_payloads': len(payloads), 'payloads_with_nonzero_stream4': sum(map(len, roots.values())), 'distinct_payload_stream4_roots': len(roots), 'all_linear_entries_including_definition_bodies': len(streams),
    'stream_stops': dict(collections.Counter(r['stop'] for r in streams)), 'packet_rows': len(packets), 'unique_packet_offsets': len(unique_packets),
    'unique_opcode_packets': dict(collections.Counter(r['opcode'] for r in unique_packets.values())),
    'unique_kind_packets': dict(collections.Counter(r['kind'] for r in unique_packets.values())),
    'definitions': {str(k): [hex(v) for v in sorted(values)] for k, values in definitions.items()}, 'cache_call_candidates': len(cache_edges), 'cache_candidate_counts': dict(collections.Counter(e['candidate_count'] for e in cache_edges)),
    'signed_length_range': [min(r['length_s16'] for r in unique_packets.values() if r['kind'] == 'signed_length'), max(r['length_s16'] for r in unique_packets.values() if r['kind'] == 'signed_length')],
    'unsigned_length_range': [min(r['length_raw'] for r in unique_packets.values() if r['kind'] == 'unsigned_length_information'), max(r['length_raw'] for r in unique_packets.values() if r['kind'] == 'unsigned_length_information')],
    'information_effective_groups': dict(collections.Counter(r['effective_group_count'] for r in unique_packets.values() if r['kind'] == 'unsigned_length_information')),
    'exhaustive_header_cases': len(header_cases), 'header_classes': dict(collections.Counter(r['kind'] for r in header_cases)), 'exhaustive_length_cases': len(length_cases), 'exhaustive_info_cases': len(info_cases), 'boundary_fixtures': len(fixtures),
    'control_trace_scenarios': trace_summaries,
    'host_guards': ['file read bounds', 'encoded positive progress for linear scans', 'linear cursor cycle/budget', 'explicit cache presence in trace', 'call active-path cycle/depth/event budgets'],
    'not_original_guards': True, 'native_execution': False, 'Ghidra_project_opens': 0, 'engine_repository_frozen_mutations': [], 'leaked_source': 'none encountered or used',
    'parallel_analysis': 'All four team slots active; parent owns engine/docs and other workers own independent audits; this cursor/cache slice sequential.'
}
(OUT / 'validation.ai.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
(OUT / 'validation.md').write_text('# Drawing-stream validation\n\nOne project-free run passed. Original DOL/ISO and decoded Sonic sample identities match the previously validated real disc.\n\n' + '\n'.join(f'- {k}: {json.dumps(summary[k])}' for k in ['source_artifacts', 'ASM_rows_matched_original', 'helper_words', 'direct_call_rows_matched_original', 'distinct_payload_stream4_roots', 'all_linear_entries_including_definition_bodies', 'stream_stops', 'unique_packet_offsets', 'unique_opcode_packets', 'cache_call_candidates', 'cache_candidate_counts', 'exhaustive_header_cases', 'exhaustive_length_cases', 'exhaustive_info_cases', 'boundary_fixtures']) + '\n\nSee validation.ai.json for complete summary, and the complete CSV files for every source/instruction/packet/arithmetic result. Cache traces use explicit hypothetical state/order; no native execution or graphics was observed.\n', encoding='utf-8')
print(json.dumps({k: summary[k] for k in ['result', 'source_artifacts', 'ASM_rows_matched_original', 'helper_words', 'direct_call_rows_matched_original', 'distinct_payload_stream4_roots', 'all_linear_entries_including_definition_bodies', 'stream_stops', 'unique_packet_offsets', 'unique_opcode_packets', 'cache_candidate_counts', 'information_effective_groups', 'boundary_fixtures']}, separators=(',', ':')))
