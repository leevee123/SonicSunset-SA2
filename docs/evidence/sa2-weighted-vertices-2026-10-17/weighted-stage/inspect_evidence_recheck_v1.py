import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'work/weighted-stage'
DIRS = [ROOT / 'work' / p for p in (
    'sa2-weighted-transform-v1', 'sa2-weighted-transform-v1/stream-v1',
    'sa2-weight-quantization-v1', 'sa2-weighted-samples-v1',
    'sa2-vertex-dispatch-v1', 'weighted-stage')]

def shape(value, depth=0):
    if isinstance(value, dict):
        if depth > 2:
            return {'type': 'dict', 'keys': list(value)[:8], 'length': len(value)}
        return {k: shape(v, depth + 1) for k, v in value.items()}
    if isinstance(value, list):
        return {'type': 'list', 'length': len(value), 'first': shape(value[0], depth + 1) if value else None}
    return value if isinstance(value, (str, int, float, bool)) and len(str(value)) < 300 else str(type(value).__name__)

schemas = []
jsons = {}
inventory = []
for directory in DIRS:
    for path in sorted(directory.iterdir()):
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT).as_posix()
        inventory.append({'path': rel, 'bytes': path.stat().st_size})
        if path.suffix.lower() == '.csv':
            with path.open(encoding='utf-8-sig', newline='') as f:
                reader = csv.DictReader(f)
                first = next(reader, None)
                schemas.append({'path': rel, 'columns': json.dumps(reader.fieldnames), 'first_row': json.dumps(first)})
        elif path.suffix.lower() == '.json' and not path.name.endswith('unknown.json'):
            try:
                jsons[rel] = shape(json.loads(path.read_text(encoding='utf-8-sig')))
            except Exception as e:
                jsons[rel] = {'read_error': str(e)}
for name, rows, fields in (
    ('evidence-recheck-schemas-v1.csv', schemas, ['path', 'columns', 'first_row']),
    ('evidence-recheck-inventory-v1.csv', inventory, ['path', 'bytes'])):
    with (OUT / name).open('x', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
(OUT / 'evidence-recheck-json-schemas-v1.json').write_text(json.dumps(jsons, indent=2) + '\n', encoding='utf-8')
selected = [r for r in schemas if any(s in r['path'] for s in ('source', 'sha', 'manifest', 'input-schema'))]
print(json.dumps({'directories': len(DIRS), 'top_level_files': len(inventory), 'CSV_schemas': len(schemas), 'JSON_schemas': len(jsons), 'source_schemas': selected}, indent=2))
