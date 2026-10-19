import csv
import hashlib
import json
import struct
from collections import Counter
from pathlib import Path

root = Path(__file__).resolve().parent
out = root / 'audit-v1'
out.mkdir(exist_ok=True)
assert not (out / 'summary.ai.json').exists(), 'Do not rerun a completed version.'
sha = lambda data: hashlib.sha256(data).hexdigest()
number = lambda value: int(value, 0)
rows = lambda path: list(csv.DictReader(path.open(newline='', encoding='utf-8-sig')))
summary = json.loads((root / 'summary.ai.json').read_text())
assert summary['result'] == 'bounded_scan_complete'
artifact_rows = []
for record in summary['artifacts']:
    path = root / record['name']
    data = path.read_bytes()
    assert len(data) == record['bytes'] and sha(data) == record['sha256'], str(path)
    artifact_rows.append({'path': record['name'], 'bytes': len(data), 'sha256': sha(data), 'matched': True})
assets = rows(root / 'candidate-assets.csv')
asset_by_path = {row['path']: row for row in assets}
decoded_by_path = {row['path']: Path(row['decoded_sample_path']).read_bytes() for row in assets}
for path, data in decoded_by_path.items():
    assert sha(data) == asset_by_path[path]['decoded_sha256']
commands = rows(root / 'candidate-stream4-commands.csv')
all_high = []
for row in commands:
    data = decoded_by_path[row['path']]
    offset, end = number(row['offset']), number(row['next_offset'])
    assert data[offset:end].hex() == row['raw_bytes'] and sha(data[offset:end]) == row['raw_sha256']
    header = struct.unpack_from('>H', data, offset)[0]
    assert header == number(row['header'])
    opcode = header & 0xff
    if header != 0xff and opcode >= 0x40:
        size, info = struct.unpack_from('>HH', data, offset + 2)
        assert offset + 4 + 2 * size == end
        signed = info if info < 0x8000 else info - 0x10000
        expression = (signed & 0xffffffff) >> 14
        assert expression == int(row['original_pending_expression'])
        all_high.append({'path': row['path'], 'offset': row['offset'], 'opcode': hex(opcode), 'size_word': hex(size), 'info_word': hex(info), 'original_pending_expression': expression, 'raw_info_high2': info >> 14})
literal_names = {row['text'].lower() for row in rows(root / 'original-model-name-literals.csv')}
selected_names = {row['basename'].lower() for row in assets}
boundary = [{'kind': 'selected_FST_basename_without_prior_literal', 'name': value} for value in sorted(selected_names - literal_names)] + [{'kind': 'prior_literal_without_selected_FST_basename', 'name': value} for value in sorted(literal_names - selected_names)]
def write(name, values, fields=None):
    if fields is None:
        fields = list(dict.fromkeys(key for row in values for key in row))
    with (out / name).open('w', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(values)
write('artifact-validation.csv', artifact_rows)
write('all-high-command-info.csv', all_high, ['path', 'offset', 'opcode', 'size_word', 'info_word', 'original_pending_expression', 'raw_info_high2'])
write('name-selection-boundaries.csv', boundary, ['kind', 'name'])
stats = {'version': 1, 'result': 'passed', 'artifact_files_hash_and_size_verified': len(artifact_rows), 'asset_carriers_verified': len(decoded_by_path), 'raw_command_rows_verified': len(commands), 'first_stream_entries': sum(int(row['first_stream_entries']) for row in assets), 'first_stream_outer_pass': sum(int(row['first_stream_outer_pass']) for row in assets), 'all_opcodes_ge40_excluding_exact_EOS': len(all_high), 'high_command_opcodes': dict(Counter(row['opcode'] for row in all_high)), 'all_high_commands_nonzero_original_pending_expression': sum(row['original_pending_expression'] != 0 for row in all_high), 'name_boundary_counts': dict(Counter(row['kind'] for row in boundary)), 'whole_disc_absence_proved': False, 'native_execution': False, 'script_runs': 'audit_group_search_v1.py once'}
(out / 'summary.ai.json').write_text(json.dumps(dict(stats, name_boundaries=boundary), indent=2) + '\n', encoding='utf-8')
(out / 'summary.md').write_text('# Grouped-sample search artifact audit v1\n\nOne run of audit_group_search_v1.py passed. It verified recorded artifact hashes/sizes and reread every raw command from the preserved decoded carriers. All high command codes were checked for the original signed pending expression, including any code beyond the explicit geometry dispatch range.\n\nMachine result: ' + json.dumps(stats, separators=(',', ':')) + '\n\nThe negative result applies only to the 23 selected MDL.PRS basenames and local stream roots reached through their checked candidate banks plus following cache-definition pointers. It does not prove that no grouped data exists elsewhere on the disc or at runtime. The complete filename differences are retained in name-selection-boundaries.csv; original literal presence does not prove file existence or caller reachability. No original, frozen, repository or engine file was modified.\n', encoding='utf-8')
print(json.dumps(stats, separators=(',', ':')))
