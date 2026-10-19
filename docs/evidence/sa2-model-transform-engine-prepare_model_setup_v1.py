from pathlib import Path
import csv
import hashlib
import json
import re

work = Path(__file__).resolve().parent
out = work / 'sa2-model-setup-v1'
out.mkdir(exist_ok=False)
sha = lambda data: hashlib.sha256(data).hexdigest()
entries = {0x8011D2F4, 0x80100D44, 0x80102EF8, 0x80105850, 0x8010588C,
           0x800ED7CC, 0x800ED798, 0x800ED368, 0x80105908,
           0x8011C754, 0x8011C76C, 0x8011C628, 0x8011C960, 0x8011C9AC, 0x8011CC08}
sources, ranges, calls, extracts = [], [], [], []
for view in ('main', 'main-sda-v1'):
    folder = work / 'full-decompile/gekko' / view / 'export'
    functions = {int(r['entry'], 16): r for r in csv.DictReader((folder / 'functions.csv').open(newline='', encoding='utf-8-sig'))}
    for entry in sorted(entries):
        row = functions[entry]
        for kind in ('pseudocode', 'assembly'):
            if not row[kind + '_path']:
                continue
            path = folder / row[kind + '_path']
            digest = sha(path.read_bytes())
            assert digest == row[kind + '_sha256']
            sources.append({'view': view, 'entry': row['entry'], 'DOL_offset': row['canonical_file_offset'], 'ISO_offset': hex(int(row['canonical_file_offset'], 16) + 0x1E700), 'kind': kind, 'path': str(path), 'sha256': digest, 'status': row['status']})
            if kind == 'pseudocode' and view == 'main-sda-v1':
                text = path.read_text()
                lines = text.splitlines()
                selected = lines if len(text) < 7500 else [line for line in lines if re.search(r'FUN_|DAT_|\*\(|return|if \(', line) and 'GQR' not in line]
                extracts.append(f"### {row['entry']} ({len(lines)} lines; {'complete' if len(text) < 7500 else 'filtered'})\n\n```c\n" + '\n'.join(selected[:100]) + '\n```\n')
    if view == 'main':
        for row in csv.DictReader((folder / 'function_body_ranges.csv').open(newline='', encoding='utf-8-sig')):
            if int(row['entry'], 16) in entries:
                ranges.append({'owner': row['entry'], 'start': row['range_start'], 'end_exclusive': row['range_end_exclusive']})
    for row in csv.DictReader((folder / 'direct_calls.csv').open(newline='', encoding='utf-8-sig')):
        if int(row['caller_entry'], 16) in entries:
            calls.append({'view': view, **row})
for name, rows, delimiter in [('source-artifacts.csv', sources, ','), ('function-ranges.tsv', ranges, '\t'), ('outgoing-calls.csv', calls, ',')]:
    with (out / name).open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]), delimiter=delimiter)
        writer.writeheader()
        writer.writerows(rows)
(out / 'selected-pseudocode.md').write_text('# Original model setup: selected generated pseudocode\n\nGenerated C is unreviewed; full original artifacts and hashes are in source-artifacts.csv. Large quantization expansions are filtered and require original words.\n\n' + '\n'.join(extracts), encoding='utf-8')
report = {'status': 'prepared', 'selected_functions': len(entries), 'sources': len(sources), 'ranges': len(ranges), 'direct_call_rows': len(calls), 'selected_C_md_sha256': sha((out / 'selected-pseudocode.md').read_bytes()), 'source_sha256': {r['path']: r['sha256'] for r in sources}, 'no_database_or_repo_changes': True}
(out / 'preparation.ai.json').write_text(json.dumps(report, indent=2) + '\n')
(out / 'preparation.md').write_text(f"# Model setup audit preparation\n\nSelected {len(entries)} original functions, {len(sources)} matching frozen artifacts, {len(ranges)} body ranges and {len(calls)} direct call rows. Pseudocode is inspected before original words. No engine/repository or program/project changes.\n")
print(json.dumps({k: report[k] for k in ('status', 'selected_functions', 'sources', 'ranges', 'direct_call_rows')}))
