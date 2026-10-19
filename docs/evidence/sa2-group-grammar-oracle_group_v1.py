"""Once-only complete N=1/N=2 explicit-helper probes from real paired command bytes."""
import ast
import csv
import hashlib
import json
import struct
from pathlib import Path

OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[1]
assert not (OUT / 'oracle.ai.json').exists()


def rows(path):
    with Path(path).open(newline='', encoding='utf-8-sig') as f:
        return list(csv.DictReader(f))


def save(name, values):
    keys = list(dict.fromkeys(k for r in values for k in r))
    with (OUT / name).open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, keys)
        w.writeheader()
        w.writerows(values)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def signed(value):
    return value - 65536 if value & 32768 else value


sample_path = ROOT / 'work/sa2-disc/sonicmdl.prs.decoded'
sample = sample_path.read_bytes()
assert sha(sample) == 'b7ea586ed0fa22330dc8a2cfe2bb8fa9ce4ac70d9561764f35af4ced5d371963'
packet_path = ROOT / 'work/sa2-draw-grammar-v1/sample-unique-packets.csv'
packets = [p for p in rows(packet_path) if p['opcode'] in ['0x41', '0x42']]
cases, streams, runs, records = [], [], [], []
case_id = 0
for p in packets:
    command, data, end, info = (int(p[k], 16) for k in ['offset', 'data_offset', 'next_offset', 'raw_info'])
    for stream_count in [1, 2]:
        case = case_id
        case_id += 1
        cursors = [data] * stream_count
        count = info & 0x3fff
        record_total = 0
        for run in range(count):
            raw_counts, starts = [], list(cursors)
            for stream in range(stream_count):
                raw_counts.append(struct.unpack_from('>H', sample, cursors[stream])[0])
                cursors[stream] += 2
            primary = signed(raw_counts[0])
            magnitude = abs(primary)
            assert magnitude > 0
            for stream in range(stream_count):
                runs.append({'case_id': case, 'run': run, 'stream': stream, 'count_offset': hex(starts[stream]), 'raw_count': hex(raw_counts[stream]), 'count_s16': signed(raw_counts[stream]), 'count_read_by_native': stream == 0, 'used_magnitude_from_stream0': magnitude, 'record_start': hex(cursors[stream])})
            for record in range(magnitude):
                for stream in range(stream_count):
                    offset = cursors[stream]
                    assert offset + 6 <= end
                    index, first, second = struct.unpack_from('>HHH', sample, offset)
                    records.append({'case_id': case, 'run': run, 'record': record, 'stream': stream, 'offset': hex(offset), 'byte_size': 6, 'index_offset': hex(offset), 'index_raw': hex(index), 'index_s16': signed(index), 'index_read_by_native': stream == 0, 'first_offset': hex(offset + 2), 'first_raw': hex(first), 'first_s16': signed(first), 'second_offset': hex(offset + 4), 'second_raw': hex(second), 'second_s16': signed(second), 'next_offset': hex(offset + 6), 'raw_hex': sample[offset:offset + 6].hex()})
                    cursors[stream] += 6
                record_total += 1
        for stream in range(stream_count):
            tail = sample[cursors[stream]:end]
            streams.append({'case_id': case, 'stream': stream, 'command_offset': hex(command), 'header_raw': p['header'], 'information_raw': p['raw_info'], 'data_offset': hex(data), 'declared_end': hex(end), 'records_end': hex(cursors[stream]), 'bytes_consumed': cursors[stream] - data, 'padding_bytes': len(tail), 'padding_hex': tail.hex(), 'raw_command_bytes': sample[command:end].hex(), 'raw_command_sha256': sha(sample[command:end]), 'raw_data_sha256': sha(sample[data:end]), 'format_flag_op_equals42': int(int(p['opcode'], 16) == 0x42)})
        cases.append({'case_id': case, 'command_offsets': ';'.join([hex(command)] * stream_count), 'stream_count': stream_count, 'extra_streams_k': stream_count - 1, 'completing_information_raw': hex(info), 'used_run_count_low14': count, 'run_count': count, 'record_count': record_total, 'final_cursor_offsets': ';'.join(hex(v) for v in cursors), 'qualification': 'explicit helper probe using real bytes; N=1 or duplicate-N=2 is NOT observed retail grouping'})

# Reuse only pure model definitions; never rerun the completed prior validation.
model_path = OUT / 'validate_group_v1.py'
tree = ast.parse(model_path.read_text())
names = {'s', 'mask', 'rot', 'Memory', 'model', 'reference'}
nodes = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name in names]
scope = {'struct': struct, 'native': {int(r['va'], 16): int(r['word'], 16) for r in rows(OUT / 'original-words.csv')}}
exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), str(model_path), 'exec'), scope)
memory = [scope['Memory']('partial_stream_overlap'), scope['Memory']('partial_stream_overlap')]
slots, base = 0x200000, 0x100000
for m in memory:
    m.put(base, struct.pack('>8H', 1, 2, 3, 4, 5, 6, 7, 8))
    m.put(slots, struct.pack('>II', base, base + 2))
a, steps = scope['model'](memory[0], slots, 1, 1)
b = scope['reference'](memory[1], slots, 1, 1)
norm = lambda m: [(r['kind'], r['address'], r['size'], r['value']) for r in m.events]
assert a == b == [base + 8, base + 10] and norm(memory[0]) == norm(memory[1])
save('oracle-cases.csv', cases)
save('oracle-streams.csv', streams)
save('oracle-runs.csv', runs)
save('oracle-records.csv', records)
save('partial-overlap-model-events.csv', memory[0].events)
save('oracle-input-sha256.csv', [{'path': str(p), 'sha256': sha(p.read_bytes())} for p in [sample_path, packet_path, model_path, OUT / 'original-words.csv', Path(__file__)]])
summary = {'result': 'passed', 'source_paired_commands': len(packets), 'explicit_N1_cases': sum(r['stream_count'] == 1 for r in cases), 'explicit_N2_duplicate_cases': sum(r['stream_count'] == 2 for r in cases), 'cases': len(cases), 'stream_rows': len(streams), 'run_stream_rows': len(runs), 'record_stream_rows': len(records), 'primary_runs_across_probes': sum(r['run_count'] for r in cases), 'primary_records_across_probes': sum(r['record_count'] for r in cases), 'partial_overlap_model': {'steps': steps, 'events': len(memory[0].events), 'final_cursors': [hex(v) for v in a], 'result': 'matches original integer-word order'}, 'caller_contract': {'input': 'ordered command offsets; previous high-family>=40; last41/42;copied independent cursors', 'run_count': 'last command info&3FFF, not first', 'counts': 'signed stream0 prefixes authority; preserve others without compare', 'records': 'allstreamstride3;only stream0 index read,othersskip;two pair words readevery stream', 'aliases': 'equal/overlapping immutable stream bytes allowed; native pointer-array/data alias excluded'}, 'observed_retail_groups': 0, 'native_execution': False}
(OUT / 'oracle.ai.json').write_text(json.dumps(summary, indent=2) + '\n')
(OUT / 'oracle.md').write_text('# Explicit grouped helper oracle\n\n132 explicit helper probes use the66 real Sonic paired packets as N=1 or duplicate-offset N=2 inputs. They are not observed encoded/retail groups. Complete raw commands, counts, signed views, indices, skipped words, pair words, source offsets, final cursors and per-stream tails remain in the CSV files. One partially overlapping-stream integer-model case also matches the independent ordered reference. No engine or native execution.\n')
print(json.dumps(summary, separators=(',', ':')))
