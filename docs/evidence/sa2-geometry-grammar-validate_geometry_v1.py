"""Validate bounded raw geometry grammar once against original-selected Sonic packets."""
import collections
import csv
import hashlib
import json
import struct
from pathlib import Path

OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[1]
assert not (OUT / 'validation.ai.json').exists()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def rows(path):
    with Path(path).open(newline='', encoding='utf-8-sig') as f:
        return list(csv.DictReader(f))


def save(name, values):
    fields = list(dict.fromkeys(k for r in values for k in r))
    with (OUT / name).open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fields)
        w.writeheader()
        w.writerows(values)


def signed(value):
    return value - 65536 if value & 32768 else value


def mask(mb, me):
    return sum(1 << (31 - i) for i in range(32) if (mb <= i <= me if mb <= me else i >= mb or i <= me))


def rotate(value, count):
    return ((value << count) | (value >> ((32 - count) % 32))) & 0xffffffff


sample_path = ROOT / 'work/sa2-disc/sonicmdl.prs.decoded'
sample = sample_path.read_bytes()
assert sha(sample) == 'b7ea586ed0fa22330dc8a2cfe2bb8fa9ce4ac70d9561764f35af4ced5d371963'
packet_path = ROOT / 'work/sa2-draw-grammar-v1/sample-unique-packets.csv'
packets = [r for r in rows(packet_path) if r['kind'] == 'unsigned_length_information']
native = rows(OUT / 'original-words.csv')
native_by_va = {int(r['va'], 16): r for r in native}
sources = rows(OUT / 'source-artifacts.csv')
for r in sources:
    assert sha(Path(r['path']).read_bytes()) == r['sha256']

# Exhaustive primitive arithmetic; do not attempt to execute billion-iteration zero loops.
count_cases, info_cases, index_cases = [], [], []
for value in range(65536):
    count = signed(value)
    magnitude = -count if count < 0 else count
    iterations = magnitude if magnitude else 1 << 32
    count_cases.append({'raw_u16': value, 'signed_count': count, 'magnitude_u32': magnitude, 'begin_count_low16': magnitude & 65535, 'native_inner_iterations_if_memory_survives': iterations, 'host_zero_rejection': magnitude == 0})
    info = signed(value) & 0xffffffff
    skips = (info >> 14) & 3
    assert skips == (rotate(info, 18) & mask(30, 31)) == value >> 14
    outer = info & 0x3fff
    assert outer == (info & mask(18, 31))
    info_cases.append({'raw_u16': value, 'helper_parameter_u32': hex(info), 'outer_low14': outer, 'native_outer_iterations_if_memory_survives': outer if outer else 1 << 32, 'masked_info_skips': skips, 'index_stride_halfwords': 1 + skips, 'pair_fixed_stride_halfwords': 3, 'pair_skips_stride_halfwords': 3 + skips})
    offset = (count * 32) & 0xffffffff
    assert offset == rotate(count & 0xffffffff, 5) & mask(0, 26)
    index_cases.append({'raw_u16': value, 'signed_index': count, 'scratch_byte_displacement_signed': count * 32, 'scratch_byte_displacement_u32': hex(offset)})

strips, records, packet_results = [], [], []


def parse(data, start, end, info, layout, packet_id, retain=True):
    count, skips = info & 0x3fff, (info >> 14) & 3
    if not count:
        raise ValueError('host zero outer-count rejection; native do-while would enter')
    cursor, rec_total = start, 0
    stride = 1 + skips if layout == 'index_info_skips' else 3 if layout == 'index_pair' else 3 + skips
    for strip in range(count):
        if cursor + 2 > end:
            raise ValueError('host run-header declared bounds')
        head = cursor
        raw = struct.unpack_from('>H', data, cursor)[0]
        run_signed, magnitude = signed(raw), abs(signed(raw))
        cursor += 2
        if not magnitude:
            raise ValueError('host zero run-count rejection; native do-while would enter')
        if cursor + magnitude * stride * 2 > end:
            raise ValueError('host record declared bounds')
        for i in range(magnitude):
            words = struct.unpack_from('>' + 'H' * stride, data, cursor)
            if retain:
                records.append({'packet_offset': hex(packet_id), 'layout': layout, 'run': strip, 'record': i, 'offset': hex(cursor), 'index_raw': hex(words[0]), 'index_s16': signed(words[0]), 'stride_halfwords': stride, 'tail_raw': ';'.join(hex(v) for v in words[1:]), 'pair_first_s16': signed(words[1]) if layout != 'index_info_skips' else '', 'pair_second_s16': signed(words[2]) if layout != 'index_info_skips' else '', 'byte_size': stride * 2, 'raw_hex': data[cursor:cursor + stride * 2].hex()})
            cursor += stride * 2
            rec_total += 1
        if retain:
            strips.append({'packet_offset': hex(packet_id), 'layout': layout, 'run': strip, 'count_offset': hex(head), 'raw_count': hex(raw), 'signed_count': run_signed, 'magnitude': magnitude, 'record_start': hex(head + 2), 'records_end_exclusive': hex(cursor), 'byte_size': cursor - head})
    return {'records_end': cursor, 'records': rec_total, 'runs': count, 'stride_halfwords': stride}


for p in packets:
    op, offset, start = int(p['opcode'], 16), int(p['offset'], 16), int(p['data_offset'], 16)
    end, info = int(p['next_offset'], 16), int(p['raw_info'], 16)
    assert int(p['effective_group_count']) == 0, 'Grouped real sample not established'
    assert sample[offset:offset + max(int(p['byte_size']), int(p['minimum_parser_read_bytes']))].hex() == p['raw_hex']
    layouts = ['index_info_skips'] if op == 0x40 else ['index_pair', 'index_pair_info_skips'] if op in [0x41, 0x42] else []
    assert layouts, ('unvalidated opcode', op)
    for layout in layouts:
        result = parse(sample, start, end, info, layout, offset)
        packet_results.append({'packet_offset': hex(offset), 'opcode': hex(op), 'layout': layout, 'information_raw': hex(info), 'data_offset': hex(start), 'declared_end': hex(end), 'declared_data_bytes': end - start, 'records_end': hex(result['records_end']), 'padding_bytes': end - result['records_end'], 'runs': result['runs'], 'records': result['records'], 'stride_halfwords': result['stride_halfwords'], 'raw_data_sha256': sha(sample[start:end]), 'padding_hex': sample[result['records_end']:end].hex()})

# Small explicit cases exercise edge rules without native code or pointer dereferences.
fixtures = []
for name, raw_count in [('positive_one', 1), ('negative_one', 65535), ('negative_minimum', 32768), ('zero_run', 0)]:
    n = abs(signed(raw_count))
    data = struct.pack('>H', raw_count) + struct.pack('>H', 65535) * n
    try:
        result = parse(data, 0, len(data), 1, 'index_info_skips', 0, False)
        assert result['records'] == n
        fixtures.append({'scenario': name, 'outcome': 'preserved', 'run_raw': hex(raw_count), 'signed_count': signed(raw_count), 'records': result['records'], 'records_end': result['records_end']})
    except ValueError as e:
        assert raw_count == 0
        fixtures.append({'scenario': name, 'outcome': 'host_reject', 'reason': str(e)})
for layout in ['index_info_skips', 'index_pair', 'index_pair_info_skips']:
    for skips in range(4):
        stride = 1 + skips if layout == 'index_info_skips' else 3 if layout == 'index_pair' else 3 + skips
        data = struct.pack('>H', 1) + struct.pack('>' + 'H' * stride, *range(65535, 65535 - stride, -1))
        result = parse(data, 0, len(data), 1 | (skips << 14), layout, 0, False)
        assert result['records_end'] == len(data)
        fixtures.append({'scenario': layout + '_skips' + str(skips), 'outcome': 'preserved', 'stride_halfwords': stride, 'records_end': result['records_end']})
try:
    parse(b'\x00\x01\x00\x00', 0, 4, 0, 'index_info_skips', 0, False)
except ValueError as e:
    fixtures.append({'scenario': 'zero_outer_count', 'outcome': 'host_reject', 'reason': str(e)})
else:
    raise AssertionError('Expected host rejection')

# Record explicit original masks/load/loop/store evidence, using source-verified words.
critical_addresses = [
    0x8011d5b0, 0x8011d5b4, 0x8011d5e0, 0x8011d5f4, 0x8011d610, 0x8011d618, 0x8011d640, 0x8011d644, 0x8011d64c, 0x8011d654, 0x8011d65c,
    0x8011d830, 0x8011d860, 0x8011d870, 0x8011d878, 0x8011d87c, 0x8011d8b4, 0x8011d8c4,
    0x8011d938, 0x8011d998, 0x8011d9a8, 0x8011d9cc,
    0x8011ff70, 0x8011ff90, 0x80120010, 0x801200a8, 0x801200b8, 0x801200c0, 0x801200d8, 0x801200ec,
    0x80120178, 0x8012021c, 0x80120228, 0x80120304, 0x8012032c, 0x80120330, 0x80120348, 0x80120384, 0x80120394, 0x801203b4, 0x801203c4
]
critical = [native_by_va[v] for v in critical_addresses]
fifo = [r for r in native if int(r['opcode']) in [36, 38, 44, 52] and int(r['entry'], 16) not in [0x8011d594, 0x8011d6a4, 0x8011d7b4, 0x8011d91c, 0x8011fef4, 0x8011fff4, 0x80120158] and int(r['field16']) != 1 and int(r['field16']) != 11]
save('run-count-arithmetic.csv', count_cases)
save('parameter-arithmetic.csv', info_cases)
save('index-arithmetic.csv', index_cases)
save('sample-packet-layouts.csv', packet_results)
save('sample-runs.csv', strips)
save('sample-records.csv', records)
save('boundary-fixtures.csv', fixtures)
save('critical-original-words.csv', critical)
save('FIFO-output-stores.csv', fifo)
save('validation-inputs.csv', [{'path': str(p), 'sha256': sha(p.read_bytes())} for p in [sample_path, packet_path, OUT / 'original-words.csv', OUT / 'source-artifacts.csv', Path(__file__)]])
single = [p for p in packet_results if p['layout'] != 'index_pair_info_skips']
single_records = [r for r in records if r['layout'] != 'index_pair_info_skips']
single_runs = [r for r in strips if r['layout'] != 'index_pair_info_skips']
result = {'result': 'passed', 'real_geometry_packets': len(packets), 'explicit_layout_parses': len(packet_results), 'unique_data_bytes': sum(int(r['declared_data_bytes']) for r in single), 'sample_unambiguous_base_layout_runs': len(single_runs), 'sample_unambiguous_base_layout_records': len(single_records), 'raw_count_signs': dict(collections.Counter('negative' if int(r['signed_count']) < 0 else 'zero' if int(r['signed_count']) == 0 else 'positive' for r in single_runs)), 'absolute_count_range': [min(int(r['magnitude']) for r in single_runs), max(int(r['magnitude']) for r in single_runs)], 'signed_index_range': [min(int(r['index_s16']) for r in single_records), max(int(r['index_s16']) for r in single_records)], 'padding_bytes': sum(int(r['padding_bytes']) for r in single), 'padding_values': sorted(set(r['padding_hex'] for r in single)), 'runs_by_opcode': dict(collections.Counter(r['opcode'] for r in single for _ in range(int(r['runs'])))), 'records_by_opcode': dict(collections.Counter(r['opcode'] for r in single for _ in range(int(r['records'])))), 'raw_info_skip_counts': dict(collections.Counter((int(r['information_raw'], 16) >> 14) & 3 for r in single)), 'full_count_cases': len(count_cases), 'full_parameter_cases': len(info_cases), 'full_index_cases': len(index_cases), 'boundary_fixtures': len(fixtures), 'critical_words': len(critical), 'FIFO_store_words': len(fifo), 'input_sources_reverified': len(sources), 'actual_runtime_layout_selection': 'unknown; explicit layout parses are structural comparisons', 'sample_not_covering': ['opcode42', 'nonzero info skips', 'outer groups', 'negative indices', 'zero count loops'], 'native_execution': False, 'engine_changes': []}
(OUT / 'validation.ai.json').write_text(json.dumps(result, indent=2) + '\n')
(OUT / 'validation.md').write_text('# Raw inner geometry validation\n\nOne run passed. The real Sonic packets were parsed under explicit helper-derived layouts; runtime branch selection was not observed. All primitive 16-bit count/parameter/index arithmetic was checked exhaustively. Zero native counters were analyzed algebraically, not executed. Complete counts are in the AI twin and complete input/run/record/word/fixture CSV.\n')
print(json.dumps(result, separators=(',', ':')))
print(json.dumps({'FIFO_stores': [{'entry': r['entry'], 'va': r['va'], 'decode': r['decode']} for r in fifo]}, separators=(',', ':')))
