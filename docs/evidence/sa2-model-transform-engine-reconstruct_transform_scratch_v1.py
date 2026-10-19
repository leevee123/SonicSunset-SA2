from pathlib import Path
import csv
import hashlib
import json

work = Path(__file__).resolve().parent
stage = work / 'transform-stage'
oracle = work / 'sa2-model-transform-v1'
reference = json.loads((work.parent / 'outputs/SA2-Vertex-Check/Reference.ai.json').read_text())
slots = {}
for row in csv.DictReader((oracle / 'oracle-output-slots.csv').open(newline='')):
    slots.setdefault(row['case_id'], []).append(row)
rows = []
for case in reference['cases']:
    before = bytes((case['initial_seed'] + i * 37) & 255 for i in range(case['initial_size']))
    after = bytearray(before)
    for slot in slots[case['case_id']]:
        offset = int(slot['scratch_index']) * 32
        after[offset:offset+32] = bytes.fromhex(slot['after_hex'])
    assert hashlib.sha256(before).hexdigest() == case['before_sha256']
    assert hashlib.sha256(after).hexdigest() == case['after_sha256']
    rows.append({'case_id': case['case_id'], 'initial_size': case['initial_size'], 'initial_seed': case['initial_seed'], 'initial_byte_step': 37, 'first_scratch_index': case['start'], 'record_count': case['count'], 'before_sha256': case['before_sha256'], 'after_sha256': case['after_sha256']})
with (stage / 'scratch-reconstruction-v1.csv').open('w', newline='') as stream:
    writer = csv.DictWriter(stream, fieldnames=list(rows[0])); writer.writeheader(); writer.writerows(rows)
report = {'status': 'PASS', 'cases': len(rows), 'algorithm': 'before[i]=(initial_seed+i*initial_byte_step)&255 for i<initial_size; replace each 32-byte output slot using oracle-output-slots.csv after_hex at scratch_index*32', 'binary_game_media_copied_to_docs': False, 'raw_slot_CSV_complete': True, 'source_sha256': {str(oracle / 'oracle-output-slots.csv'): hashlib.sha256((oracle / 'oracle-output-slots.csv').read_bytes()).hexdigest()}}
(stage / 'scratch-reconstruction-v1.ai.json').write_text(json.dumps(report, indent=2) + '\n')
(stage / 'scratch-reconstruction-v1.md').write_text('# Complete scratch reconstruction\n\nPASS: all219 before/after scratch hashes reconstruct from sentinel seed/size/step CSV and complete32-byte output-slot CSV. No binary game media needs copying into documentation. Before byte i=(seed+i*step)&255; replace each declared slot with after_hex. Source/matrix data remains in the complete oracle case JSONL and original bank provenance.\n')
print(json.dumps({'status': 'PASS', 'cases': len(rows), 'complete_binary_hashes_reconstructed': len(rows) * 2}))
