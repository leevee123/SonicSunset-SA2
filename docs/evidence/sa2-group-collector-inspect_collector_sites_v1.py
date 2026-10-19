import csv
import json
from pathlib import Path

OUT = Path(__file__).resolve().parent
with (OUT / 'original-words.csv').open(newline='', encoding='utf-8') as stream:
    raw = list(csv.DictReader(stream))

"""/* Select exact original frame, collector and callback windows for review.
This is a view of already checked words, not a new disassembly or execution. */"""
windows = ((0x8011CCF8, 0x8011CD40), (0x8011CE60, 0x8011CF68), (0x8011D0E8, 0x8011D188), (0x8011CAAC, 0x8011CB08))
selected = [row for row in raw if any(a <= int(row['va'], 16) < b for a, b in windows) or int(row['entry'], 16) in (0x8010AFB0, 0x8010AFFC)]
with (OUT / 'collector-frame-control-sites.csv').open('w', newline='', encoding='utf-8') as stream:
    writer = csv.DictWriter(stream, fieldnames=list(raw[0]))
    writer.writeheader()
    writer.writerows(selected)
(OUT / 'site-review.ai.json').write_text(json.dumps({'source': 'original-words.csv', 'rows': len(selected), 'scope': 'frame,collector,multi-stream call/reset and callback prefix'}, indent=2) + '\n', encoding='utf-8')
(OUT / 'site-review.md').write_text(f"# Collector site review\n\n{len(selected)} selected original rows in the complete raw CSV. Covers exact frame storage, call arguments, reset and callback prefix.\n", encoding='utf-8')
for row in selected:
    if int(row['entry'], 16) == 0x8011CAAC or 0x8011CCF8 <= int(row['va'], 16) < 0x8011CD40:
        print(row['va'], row['word'], row['retained_ASM'] or row['integer_decode'])
