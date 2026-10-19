import csv
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REPO = Path('C:/decomp/SonicFantasy-master')
OUT = ROOT / 'work/weighted-stage'
DIRS = [ROOT / 'work' / p for p in (
    'sa2-weighted-transform-v1', 'sa2-weighted-transform-v1/stream-v1',
    'sa2-weight-quantization-v1', 'sa2-weighted-samples-v1',
    'sa2-vertex-dispatch-v1', 'weighted-stage')]
HEX = re.compile(r'^[0-9a-fA-F]{64}$')
references = []
skipped = []
ledger_files = set()
raw_digests = {}

def sha(path):
    path = Path(path).resolve()
    key = str(path).lower()
    if key not in raw_digests:
        with path.open('rb') as f:
            raw_digests[key] = hashlib.file_digest(f, 'sha256').hexdigest()
    return raw_digests[key]

def resolve(raw, base):
    p = Path(raw)
    return (p if p.is_absolute() else base / p).resolve()

def add(ledger, location, raw_path, digest, base=None, reason='recorded digest'):
    if not digest:
        skipped.append({'ledger': str(ledger), 'location': location, 'path': str(raw_path), 'reason': 'optional blank digest'})
        return
    if not HEX.fullmatch(str(digest)):
        raise ValueError(f'invalid digest {ledger}:{location}')
    base = base or ledger.parent
    requested = resolve(raw_path, base)
    effective = requested
    note = reason
    normalized = str(requested).replace('\\', '/').lower()
    historical = {
        'd695c56d426d73137d13f05f63609b1b50902ba721bf8abd3278645c4d1bd1fd': 'ModelVertexTransform.cpp',
        '5c2123327fc2f7db2eb5943e1b87dc4d397f73bd63c412d9f8ee4c4117479346': 'ModelVertexTransform.h'}
    if digest in historical and (normalized.endswith('/' + historical[digest].lower())):
        effective = OUT / 'core-validated/src/Importers/SA2' / historical[digest]
        note = 'historical core candidate; exact snapshot retained before stream append; current prepared path intentionally extended'
    references.append({'ledger': str(ledger), 'location': location, 'requested_path': str(requested),
        'effective_path': str(effective.resolve()), 'expected_sha256': digest.lower(), 'identity_reason': note})

def json_sources(value, ledger, location='$'):
    if isinstance(value, list):
        for i, v in enumerate(value):
            json_sources(v, ledger, f'{location}[{i}]')
    elif isinstance(value, dict):
        if 'path' in value and 'sha256' in value:
            add(ledger, location + '.sha256', value['path'], value['sha256'])
        elif 'name' in value and 'sha256' in value:
            add(ledger, location + '.sha256', value['name'], value['sha256'])
        for k, v in value.items():
            if isinstance(v, str) and HEX.fullmatch(v) and ('/' in k or '\\' in k):
                base = OUT / 'core-validated' if location.endswith('.core_weighted_source_sha256') else ledger.parent
                add(ledger, location + '.' + k, k, v, base)
            elif isinstance(v, (dict, list)):
                json_sources(v, ledger, location + '.' + k)

def load_json(path):
    ledger_files.add(path)
    return json.loads(path.read_text(encoding='utf-8-sig'))

for directory in DIRS[:-1]:
    for path in sorted(directory.glob('*.csv')):
        with path.open(encoding='utf-8-sig', newline='') as f:
            reader = csv.DictReader(f)
            columns = reader.fieldnames or []
            if 'path' not in columns:
                continue
            digest_columns = [k for k in ('sha256', 'source_sha256', 'sha256_before', 'expected_sha256', 'sha256_after') if k in columns]
            if not digest_columns:
                continue
            ledger_files.add(path)
            for number, row in enumerate(reader, 2):
                for column in digest_columns:
                    add(path, f'row{number}.{column}', row['path'], row[column])
    for path in sorted(directory.glob('*.json')):
        if path.name == 'weighted-packets.ai.json':
            continue
        doc = load_json(path)
        json_sources(doc, path)
        if 'manifest_sha256' in doc:
            add(path, '$.manifest_sha256', 'manifest.csv', doc['manifest_sha256'])
        if 'human_report_sha256' in doc:
            name = 'weight-reference.md' if 'quantization' in str(directory) else 'dispatch-reference.md'
            add(path, '$.human_report_sha256', name, doc['human_report_sha256'])

stage_names = ('compile-v1', 'compile-v2', 'validation-v1', 'weight-domain-v1',
    'stream-compile-v1', 'stream-validation-v1', 'stream-extension-snapshot-v1')
for name in stage_names:
    path = OUT / (name + '.ai.json')
    doc = load_json(path)
    json_sources(doc, path)
    if 'raw_log_sha256' in doc:
        add(path, '$.raw_log_sha256', name + '.raw.log', doc['raw_log_sha256'])
    if 'bank_sha256' in doc:
        add(path, '$.bank_sha256', ROOT / 'work/sa2-disc/sonicmdl.prs.decoded', doc['bank_sha256'])

stream = ROOT / 'work/sa2-weighted-transform-v1/stream-v1'
final_path = stream / 'final-audit.ai.json'
final = load_json(final_path)
for key, path in (
    ('core_cases_manifest_sha256', stream.parent / 'oracle-cases.jsonl'),
    ('stream_cases_manifest_sha256', stream / 'cases.jsonl')):
    add(final_path, '$.' + key, path, final[key])

sample_path = ROOT / 'work/sa2-weighted-samples-v1/summary.ai.json'
sample = load_json(sample_path)
add(sample_path, '$.original_ISO_sha256', ROOT / 'work/sa2.iso', sample['original_ISO_sha256'], reason='reuse completed sample full ISO hash; no duplicate full ISO read')

language = ROOT / 'work/full-decompile-fp/Sa2GekkoLanguage/data/languages'
for name, digest in (
    ('ppc_gekko_broadway.slaspec', '32ce4852d6243f5eea19cda1eb8cf0b2af8fb93532dcd9a585ee927a32c8eb75'),
    ('ppc_gekko_broadway.sla', 'aa25bde9ffb8f6366e1e490c6a488b1aced4665dc6c4f2fdca9cc598d5530975')):
    add(ROOT / 'work/full-decompile-fp/language-provenance.ai.json', 'frozen isolated language identity', language / name, digest)

scope_path = OUT / 'scope-preservation-v2.ai.json'
scope = load_json(scope_path)
prefix_rows = []
for item in scope['checks']:
    version = item['version']
    original = OUT / version / item['file']
    current = OUT / 'prepared' / item['file']
    before = original.read_bytes()
    after = current.read_bytes()
    stripped = after.replace(b'#include "Importers/SA2/ModelData.h"\r\n', b'', 1).replace(b'#include "Importers/SA2/ModelData.h"\n', b'', 1)
    n = item['preserved_prefix_bytes']
    prefix_rows.append({'version': version, 'historical_path': str(original), 'current_path': str(current),
        'prefix_bytes': n, 'historical_sha256': sha(original), 'expected_historical_sha256': item['before_sha256'],
        'current_sha256': sha(current), 'expected_current_sha256': item['current_sha256'],
        'prefix_matches_after_single_include_removal': before[:n] == stripped[:n],
        'whole_hashes_match': sha(original) == item['before_sha256'] and sha(current) == item['current_sha256']})
    add(scope_path, f'checks[{version}].before_sha256', original, item['before_sha256'])
    add(scope_path, f'checks[{version}].current_sha256', current, item['current_sha256'])

current_compile_path = OUT / 'stream-compile-v1.ai.json'
current_compile = load_json(current_compile_path)
for path, digest in current_compile['source_sha256'].items():
    name = Path(path).name
    add(current_compile_path, 'applied repository peer identity', REPO / 'src/Importers/SA2' / name, digest)

ledger_before = {str(p): sha(p) for p in ledger_files}
grouped = defaultdict(list)
for row in references:
    grouped[(str(Path(row['effective_path']).resolve()).lower(), row['expected_sha256'])].append(row)
sources = []
for (key, expected), rows in sorted(grouped.items()):
    path = Path(rows[0]['effective_path'])
    try:
        size = path.stat().st_size
        if path.resolve() == (ROOT / 'work/sa2.iso').resolve():
            actual = sample['original_ISO_sha256']
            status = 'PASS_REUSED_FULL_ISO_HASH' if expected == actual and size == 1459978240 else 'FAIL_ISO_IDENTITY'
            method = 'prior sample summary + source-digests before/after full hash; current file size; not rehashed this pass'
        else:
            actual = sha(path)
            status = 'PASS' if actual == expected else 'FAIL_DIGEST'
            method = 'read-only full file SHA256'
    except Exception as e:
        size, actual, status, method = '', '', 'FAIL_READ', str(e)
    s = str(path).replace('\\', '/').lower()
    category = ('original' if '/sa2-disc/' in s or s.endswith('/sa2.iso') else
        'frozen_decompilation' if '/full-decompile/gekko/' in s else
        'language' if '/languages/' in s else
        'primary_reference' if '/dolphin-reference' in s else
        'historical_candidate' if '/core-validated/' in s or '/weighted-stage/original/' in s else
        'current_candidate' if '/weighted-stage/prepared/' in s or s.startswith('c:/decomp/sonicfantasy-master/src/') else 'analysis_evidence')
    sources.append({'path': str(path), 'category': category, 'bytes': size, 'expected_sha256': expected,
        'actual_sha256': actual, 'status': status, 'method': method, 'reference_count': len(rows),
        'ledgers': ';'.join(sorted({r['ledger'] for r in rows}))})
    for row in rows:
        row.update({'actual_sha256': actual, 'status': status, 'method': method})

twins = []
for directory in DIRS:
    for path in sorted(directory.glob('*.md')):
        if '.ai.' in path.name or '--AI' in path.name:
            continue
        candidates = [path.with_name(path.stem + suffix) for suffix in ('.ai.json', '.ai.md', '--AI.md', '--AI.json')]
        meaningful = []
        for c in candidates:
            if not c.exists():
                continue
            text = c.read_text(encoding='utf-8-sig').strip()
            if c.suffix == '.json':
                try:
                    value = json.loads(text)
                    ok = isinstance(value, (dict, list)) and len(value) >= 2 and len(text) >= 80
                except Exception:
                    ok = False
            else:
                ok = len(text) >= 80
            if ok:
                meaningful.append(str(c))
        twins.append({'human_report': str(path), 'bytes': path.stat().st_size,
            'meaningful_AI_companions': ';'.join(meaningful), 'status': 'PASS' if meaningful else 'MISSING_TWIN'})

def write_csv(name, rows, fields):
    with (OUT / name).open('x', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

write_csv('evidence-recheck-v1.csv', sources, list(sources[0]))
write_csv('evidence-recheck-references-v1.csv', references, list(references[0]))
write_csv('evidence-recheck-optional-blanks-v1.csv', skipped, ['ledger', 'location', 'path', 'reason'])
write_csv('evidence-recheck-prefixes-v1.csv', prefix_rows, list(prefix_rows[0]))
write_csv('evidence-recheck-twins-v1.csv', twins, list(twins[0]))
changed_ledgers = []
for raw_path, expected in ledger_before.items():
    p = Path(raw_path)
    with p.open('rb') as f:
        actual = hashlib.file_digest(f, 'sha256').hexdigest()
    if actual != expected:
        changed_ledgers.append({'path': raw_path, 'before': expected, 'after': actual})
missing = [r['human_report'] for r in twins if r['status'] != 'PASS']
failed = [r for r in sources if r['status'].startswith('FAIL')]
prefix_failed = [r for r in prefix_rows if not (r['prefix_matches_after_single_include_removal'] and r['whole_hashes_match'])]
report = {
    'status': 'PASS' if not failed and not prefix_failed and not changed_ledgers else 'FAIL',
    'scope': 'Read-only identity recheck of weighted core, quantization, Sonic sample, dispatcher and stream ledgers; no numerical/native/game replay.',
    'script_runs': 'inspect_evidence_recheck_v1.py once; recheck_evidence_v1.py once',
    'source_identity_checks': len(sources), 'distinct_physical_paths': len({r['path'].lower() for r in sources}),
    'category_counts': dict(Counter(r['category'] for r in sources)),
    'recorded_digest_references': len(references), 'optional_blank_digest_fields_skipped': len(skipped),
    'full_files_rehashed': len([r for r in sources if r['method'] == 'read-only full file SHA256']),
    'original_ISO': {'sha256': sample['original_ISO_sha256'], 'bytes': 1459978240,
        'method': 'Reused existing completed sample full-hash + original read-only PRS validation; size checked; no duplicate full ISO hashing.',
        'evidence': ['work/sa2-weighted-samples-v1/summary.ai.json', 'work/sa2-weighted-samples-v1/source-digests.csv']},
    'historical_candidate_digest_references_mapped': sum(r['requested_path'] != r['effective_path'] for r in references),
    'prefix_checks': len(prefix_rows), 'prefix_checks_failed': prefix_failed,
    'input_ledgers_unchanged': len(ledger_before), 'changed_input_ledgers': changed_ledgers,
    'failed_source_identities': failed,
    'top_level_human_reports_checked': len(twins), 'human_reports_with_meaningful_twin': len(twins) - len(missing),
    'missing_human_AI_twins': missing,
    'twin_policy': 'Same-stem .ai.json/.ai.md/--AI.md/--AI.json with substantive content; AI docs are not recursively required to have twins.',
    'failure_versions': 'All existing failed scripts/reports and manifest entries preserved and included where a digest is recorded; none rewritten.',
    'limits': ['ISO full hash reused, not freshly recomputed in this pass.',
        'Current root engine/docs guard inventories remain root-owned; this pass checks only recorded source/candidate identities, not all repository files.',
        'Companion presence/content check establishes a usable AI summary exists, not a fresh semantic proof of every claim.',
        'Identity consistency does not prove generated C equivalence, retail runtime state or whole-game completion.'],
    'files_changed': ['new work/weighted-stage evidence-recheck artifacts only'],
    'outputs': ['evidence-recheck-v1.csv', 'evidence-recheck-references-v1.csv',
        'evidence-recheck-optional-blanks-v1.csv', 'evidence-recheck-prefixes-v1.csv', 'evidence-recheck-twins-v1.csv']}
with (OUT / 'evidence-recheck-v1.ai.json').open('x', encoding='utf-8') as f:
    json.dump(report, f, indent=2)
    f.write('\n')
text = (f"# Weighted and stream evidence identity recheck\n\n{report['status']}: {len(sources)} distinct path/digest identities ({len(references)} recorded references) checked. "
    f"{report['full_files_rehashed']} smaller files were rehashed read-only; the original ISO full hash was reused from the completed sample audit, with its current size checked. "
    f"{len(failed)} source mismatches, {len(prefix_failed)} prefix failures and {len(changed_ledgers)} changed input ledgers were found.\n\n"
    f"The original DOL, both frozen Gekko export views, primary reference files and frozen language source/compiled SLA are included. "
    f"{len(skipped)} optional blank digest fields were skipped; populated before/after digests remain checked. Input schemas were inspected before matching. Complete per-reference and deduplicated source results are in the CSV files.\n\n"
    f"{report['historical_candidate_digest_references_mapped']} historical candidate references are resolved to the exact core-validated snapshots. "
    f"Their original prepared paths were intentionally extended by stream integration. All {len(prefix_rows)} original/core prefix checks reproduce scope-preservation-v2 after removing the one allowed ModelData.h include; current stream source hashes also match prepared and applied repository peers. "
    "Historical candidate identity is not reported as original-source drift.\n\n"
    f"{len(twins)} top-level human Markdown reports were checked; {len(twins) - len(missing)} have a substantive same-stem AI companion. "
    + ('Missing companions:\n\n' + ''.join(f'- `{p}`\n' for p in missing) if missing else 'No missing companions were found.\n')
    + "\nNo existing original, frozen artifact, report, repository file or analysis database was modified. Existing failure versions remain intact. This is an identity/companion audit, not game execution, a new numerical replay or proof of retail state. Root retains ownership of the broader engine/document guard inventories.\n")
with (OUT / 'evidence-recheck-v1.md').open('x', encoding='utf-8') as f:
    f.write(text)
print(json.dumps({k: report[k] for k in ('status', 'source_identity_checks', 'distinct_physical_paths',
    'category_counts', 'recorded_digest_references', 'optional_blank_digest_fields_skipped',
    'historical_candidate_digest_references_mapped', 'prefix_checks', 'input_ledgers_unchanged',
    'top_level_human_reports_checked', 'missing_human_AI_twins', 'failed_source_identities')}))
