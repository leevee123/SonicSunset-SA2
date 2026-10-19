import csv
import json
from pathlib import Path

OUT = Path(__file__).resolve().parent
with (OUT / 'original-words.csv').open(newline='', encoding='utf-8') as stream:
    raw = list(csv.DictReader(stream))

"""/* Select exact original windows for dispatch, pointer stride, signed loads
and the argument-extending attribute thunk. No new decoding or execution occurs. */"""
windows = ((0x8011CE4C, 0x8011CF74), (0x8011CF7C, 0x8011D174), (0x8011D1AC, 0x8011D1D4))
selected = [row for row in raw if any(a <= int(row['va'], 16) < b for a, b in windows)]
for row in raw:
    if int(row['entry'], 16) in (0x8011D594, 0x8011D6A4, 0x8011D7B4, 0x8011D91C, 0x8011FEF4, 0x8011FFF4, 0x80120158):
        if row['opcode'] in ('42', '32', '14', '21'):
            selected.append(row)
with (OUT / 'dispatch-stride-load-windows.csv').open('w', newline='', encoding='utf-8') as stream:
    writer = csv.DictWriter(stream, fieldnames=list(raw[0]))
    writer.writeheader()
    writer.writerows(selected)
result = {'rows': len(selected), 'source': 'original-words.csv; already source-word and offset checked', 'scope': 'selected instructions only; full function bodies retained separately'}
(OUT / 'contract-sites.ai.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
(OUT / 'contract-sites.md').write_text(f"# Geometry contract sites\n\n{len(selected)} original instruction rows selected for branch, stride, signed load and attribute-thunk review. Full bodies remain in `original-words.csv`.\n", encoding='utf-8')
for row in selected:
    if int(row['entry'], 16) == 0x8011D1AC or (int(row['entry'], 16) in (0x8011D594, 0x8011D7B4, 0x8011FFF4) and row['opcode'] in ('42', '21')):
        print(row['va'], row['word'], row['retained_ASM'] or row['integer_decode'])
