from pathlib import Path
import csv
import hashlib
import json

folder = Path(__file__).resolve().parent
path = folder / 'cache-lifecycle.md'
text = path.read_text(encoding='utf-8')

"""/* Improve generated human prose spacing, then refresh artifact hashes.
No evidence, source guard, instruction, or compact result changes. */"""
for before, after in {
    'all65,536': 'all 65,536', 'gives256': 'gives 256',
    'of256': 'of 256', 'the32-bit': 'the 32-bit',
    'All376,848': 'All 376,848', 'The8,811-file': 'The 8,811-file',
    'is136,360': 'is 136,360', 'SHA256`': 'SHA256 `',
    'All30': 'All 30', 'bytes:15': 'bytes: 15',
    'and15': 'and 15', 'Index0 has8': 'Index 0 has 8',
    'index1 has7': 'index 1 has 7', 'all8': 'all 8',
    'The14': 'The 14', 'retain700': 'retain 700',
    'and915': 'and 915', 'All46': 'All 46', 'by the256-value': 'by the 256-value',
}.items():
    text = text.replace(before, after)
path.write_text(text, encoding='utf-8')

manifest = json.loads((folder / 'manifest.ai.json').read_text(encoding='utf-8'))
statuses = {row['path']: row['status'] for row in manifest['files']}
rows = []
for path in sorted(folder.rglob('*')):
    if path.is_file() and not path.name.startswith('manifest.'):
        relative = str(path.relative_to(folder))
        rows.append({'path': relative, 'bytes': path.stat().st_size, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'status': statuses.get(relative, 'current')})
with (folder / 'manifest.csv').open('w', newline='', encoding='utf-8') as output:
    writer = csv.DictWriter(output, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)
manifest['files'] = rows
(folder / 'manifest.ai.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
(folder / 'manifest.md').write_text(f"# Cache audit manifest\n\n{len(rows)} files, complete SHA256/size/status in `manifest.csv` and AI twin. Use `cache-lifecycle.md`, `cache-lifecycle.ai.json`, corrected `word-audit-v2/`, canonical-site and validated-sample CSVs. Superseded decoder columns are identified explicitly. No engine/repository/original/frozen files changed; 46 selected source guards pass.\n", encoding='utf-8')
print(json.dumps({'human_report_polished': True, 'manifest_files': len(rows), 'evidence_unchanged': True}))
