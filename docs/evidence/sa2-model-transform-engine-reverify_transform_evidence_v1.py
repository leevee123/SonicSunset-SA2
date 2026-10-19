from pathlib import Path
import csv
import hashlib
import json

work = Path(__file__).resolve().parent
stage = work / 'transform-stage'
folders = [work / n for n in ('sa2-gqr0-audit-v1', 'sa2-model-transform-v1', 'sa2-model-bootstrap-v1', 'sa2-model-setup-v1')]
sha = lambda b: hashlib.sha256(b).hexdigest()
ledger_schemas, sources, skips = [], {}, []
for folder in folders:
    for ledger in sorted(folder.glob('*.csv')):
        if not any(token in ledger.name for token in ('source', 'sha256', 'digest')):
            continue
        with ledger.open(newline='', encoding='utf-8-sig') as stream:
            reader = csv.DictReader(stream)
            keys = reader.fieldnames or []
            path_key = next((k for k in ('path', 'source_path', 'file_path', 'source', 'file') if k in keys), None)
            hash_key = next((k for k in ('sha256', 'expected_sha256', 'before_sha256', 'sha256_before') if k in keys), None)
            ledger_schemas.append({'ledger': str(ledger), 'columns': keys, 'selected_path': path_key, 'selected_hash': hash_key})
            if not path_key or not hash_key:
                skips.append(str(ledger)); continue
            for row in reader:
                path = Path(row[path_key])
                if not path.is_absolute(): path = folder / path
                digest = row[hash_key]
                assert len(digest) == 64, (ledger, path, digest)
                assert str(path) not in sources or sources[str(path)] == digest
                sources[str(path)] = digest
for folder in folders:
    for name in ('preparation.ai.json', 'parsing.ai.json', 'summary.ai.json', 'gqr0-reference.ai.json', 'raw-audit.ai.json', 'oracle-summary.ai.json', 'oracle-crosscheck.ai.json'):
        path = folder / name
        if not path.exists(): continue
        report = json.loads(path.read_text())
        for key in ('source_sha256', 'protected_sha256', 'input_sha256'):
            if not isinstance(report.get(key), dict): continue
            for source, digest in report[key].items():
                if isinstance(digest, str) and len(digest) == 64:
                    assert source not in sources or sources[source] == digest
                    sources[source] = digest
rows = []
for source, expected in sorted(sources.items()):
    path = Path(source)
    actual = sha(path.read_bytes())
    assert actual == expected, source
    rows.append({'path': source, 'bytes': path.stat().st_size, 'expected_sha256': expected, 'actual_sha256': actual, 'status': 'PASS'})
with (stage / 'evidence-recheck-v1.csv').open('w', newline='') as stream:
    writer = csv.DictWriter(stream, fieldnames=list(rows[0])); writer.writeheader(); writer.writerows(rows)
report = {'status': 'PASS', 'distinct_inputs': len(rows), 'ledger_schemas': ledger_schemas, 'non_hash_location_tables': skips, 'source_sha256': sources, 'original_DOL_sha256': sha((work / 'sa2-disc/main.dol').read_bytes()), 'scope': 'Recorded original/frozen/emulator/metadata/helper inputs rehashed without opening databases/projects; location-only tables excluded explicitly.'}
(stage / 'evidence-recheck-v1.ai.json').write_text(json.dumps(report, indent=2) + '\n')
(stage / 'evidence-recheck-v1.md').write_text(f"# Model arithmetic evidence recheck\n\nPASS: {len(rows)} distinct recorded original/analysis/reference/helper inputs rehashed unchanged. Complete paths/expected/actual SHA-256 in CSV; ledger schema decisions in AI twin. {len(skips)} source-location-only tables have no path/hash pair and are listed separately; they are not silently treated as hash guards. No program/project opened.\n")
print(json.dumps({'status': 'PASS', 'distinct_inputs': len(rows), 'non_hash_location_tables': len(skips), 'schemas': [{k: r[k] for k in ('ledger', 'selected_path', 'selected_hash')} for r in ledger_schemas]}))
