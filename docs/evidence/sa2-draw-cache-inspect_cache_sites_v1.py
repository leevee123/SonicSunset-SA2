from pathlib import Path
import csv
import json

OUT = Path(__file__).resolve().parent
with (OUT / 'bounded-original-words.csv').open(newline='', encoding='utf-8') as stream:
    words = list(csv.DictReader(stream))
with (OUT / 'initial-sample-cache-controls.csv').open(newline='', encoding='utf-8') as stream:
    controls = list(csv.DictReader(stream))

"""/* Preserve selected register/control-flow windows without treating generated
function signatures as ABI facts. These windows are already original-word checked. */"""
ranges = ((0x8011CD08, 0x8011CD38), (0x8011CD90, 0x8011CDE8), (0x8011D184, 0x8011D1AC), (0x8011D414, 0x8011D484), (0x80120584, 0x801205D8), (0x80121764, 0x801218B0), (0x8010AFB0, 0x8010AFE4), (0x8010AFFC, 0x8010B030))
selected = [row for row in words if any(a <= int(row['va'], 16) < b for a, b in ranges)]
with (OUT / 'cache-register-control-windows.csv').open('w', newline='', encoding='utf-8') as stream:
    writer = csv.DictWriter(stream, fieldnames=list(selected[0]))
    writer.writeheader()
    writer.writerows(selected)
indices = sorted({int(row['cache_index']) for row in controls})
summary = []
for index in indices:
    group = [row for row in controls if int(row['cache_index']) == index]
    summary.append({'index': index, 'definition_stops': sum(int(row['opcode'], 16) == 4 for row in group), 'reference_stops': sum(int(row['opcode'], 16) == 5 for row in group), 'definition_payloads': '|'.join(row['payload_offset'] for row in group if int(row['opcode'], 16) == 4), 'reference_payloads': '|'.join(row['payload_offset'] for row in group if int(row['opcode'], 16) == 5)})
with (OUT / 'initial-sample-cache-indices.csv').open('w', newline='', encoding='utf-8') as stream:
    writer = csv.DictWriter(stream, fieldnames=list(summary[0]))
    writer.writeheader()
    writer.writerows(summary)

result = {'selected_window_rows': len(selected), 'sample_indices': summary, 'limitation': 'Bounded initial-stream inventory only; no file-offset, payload-list, or runtime ordering assumption.'}
(OUT / 'site-inspection.ai.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
(OUT / 'site-inspection.md').write_text(f"# Cache site inspection v1\n\nRetained {len(selected)} original-word register/control-window rows. The initial sample scan has {len(indices)} cache indices, recorded in the raw per-index CSV. Its rows are not an execution-order trace.\n", encoding='utf-8')
print(json.dumps({'sample_indices': summary}, separators=(',', ':')))
for row in selected:
    if int(row['owner'], 16) in (0x80120584, 0x80121764, 0x801217B0):
        print(row['va'], row['word'], row['decode'], row['retained_asm'])
