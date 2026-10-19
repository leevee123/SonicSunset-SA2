import csv
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'work/weighted-stage'
sha = lambda value: hashlib.sha256(value).hexdigest()
cases = (
    ('sa2-weight-quantization-v1', 'weight-reference', 'finalize_weight_v1.py'),
    ('sa2-vertex-dispatch-v1', 'dispatch-reference', 'finalize_dispatch_v2.py'))
rows = []
for directory, report, script in cases:
    folder = ROOT / 'work' / directory
    human_path = folder / (report + '.md')
    raw = human_path.read_bytes()
    lf = raw.replace(b'\r\n', b'\n')
    companion = json.loads((folder / (report + '.ai.json')).read_text())
    sealed = json.loads((folder / 'manifest.ai.json').read_text())
    with (folder / 'manifest.csv').open(newline='', encoding='utf-8-sig') as f:
        manifest = {r['path']: r for r in csv.DictReader(f)}
    finalizer = (folder / script).read_text(encoding='utf-8-sig')
    write = f"(OUT/'{report}.md').write_text(human,encoding='utf-8')"
    assert write in finalizer
    assert "'human_report_sha256':sha(human.encode())" in finalizer
    assert finalizer.index(write) < finalizer.index("'human_report_sha256':sha(human.encode())")
    assert sha(raw) == manifest[report + '.md']['sha256']
    assert sha((folder / 'manifest.csv').read_bytes()) == sealed['manifest_sha256']
    assert sha(lf) == companion['human_report_sha256'] == sealed['human_report_sha256']
    assert b'\r' not in lf and raw.count(b'\r\n') == raw.count(b'\n')
    rows.append({'human_path': str(human_path), 'raw_bytes': len(raw), 'CRLF_pairs': raw.count(b'\r\n'),
        'raw_sha256': sha(raw), 'LF_text_bytes': len(lf), 'LF_text_sha256': sha(lf),
        'recorded_human_report_sha256': companion['human_report_sha256'],
        'manifest_csv_sha256': sha((folder / 'manifest.csv').read_bytes()),
        'manifest_csv_raw_file_identity_matches': True, 'LF_text_identity_matches': True,
        'finalizer_path': str(folder / script), 'finalizer_sha256': sha((folder / script).read_bytes()),
        'cause': 'hash of LF human.encode() text vs write_text default Windows CRLF file bytes',
        'original_or_frozen_drift': False})
with (OUT / 'evidence-hash-adjudication-v1.csv').open('x', newline='', encoding='utf-8') as f:
    writer = csv.DictWriter(f, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)
report = {'status': 'PASS', 'rows': rows,
    'decision': 'Treat these exact two human_report_sha256 fields as LF-text identities. manifest.csv is the sealed raw-byte identity; preserve both immutable ledgers and both report bytes.',
    'proof': 'Both current raw human files match their sealed manifest CSV entries. Replacing every CRLF with LF exactly reproduces both historical text digests; finalizer writes human using default newline translation but hashes human.encode() before that translation.',
    'prior_recheck': 'evidence-recheck-v1 FAIL retained; it correctly found raw-byte versus LF-text digest mismatch, not original/frozen source drift.',
    'scope': 'Exact two named fields only; no blanket normalization or waiver for other mismatches.',
    'script_runs': 'adjudicate_evidence_hashes_v1.py once',
    'mutations': 'new adjudication artifacts only; originals, finalizers, reports, manifests, repository and analysis databases unchanged'}
with (OUT / 'evidence-hash-adjudication-v1.ai.json').open('x', encoding='utf-8') as f:
    json.dump(report, f, indent=2)
    f.write('\n')
with (OUT / 'evidence-hash-adjudication-v1.md').open('x', encoding='utf-8') as f:
    f.write('# Two historical text-hash fields\n\nPASS: both human reports match their sealed manifest CSV raw-file hashes. Their two human_report_sha256 fields instead exactly identify the same text with LF newlines. The finalizers write text with default Windows CRLF translation but hash human.encode(), which still contains LF. This accounts for every differing byte without changing report content.\n\nThe raw-byte identities and normalized-text identities are both retained in the CSV and AI companion. evidence-recheck-v1 remains unchanged with its strict raw-byte FAIL result. A new recheck may accept only these exact two LF-text fields after verifying this adjudication and sealed manifest identities; no other mismatch is waived. No original, frozen artifact, existing report, finalizer, manifest, repository file or database was changed.\n')
print(json.dumps({'status': 'PASS', 'exact_fields_adjudicated': len(rows), 'cause': report['proof']}))
