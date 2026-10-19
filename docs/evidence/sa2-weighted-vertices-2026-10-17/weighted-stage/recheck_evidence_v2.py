"""V2 identity audit: preserve V1 and adjudicate only two proven LF-text fields."""
import hashlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
source = (HERE / 'recheck_evidence_v1.py').read_text(encoding='utf-8')
replacements = {
    'evidence-recheck-v1.csv': 'evidence-recheck-v2.csv',
    'evidence-recheck-references-v1.csv': 'evidence-recheck-references-v2.csv',
    'evidence-recheck-optional-blanks-v1.csv': 'evidence-recheck-optional-blanks-v2.csv',
    'evidence-recheck-prefixes-v1.csv': 'evidence-recheck-prefixes-v2.csv',
    'evidence-recheck-twins-v1.csv': 'evidence-recheck-twins-v2.csv',
    'evidence-recheck-v1.ai.json': 'evidence-recheck-v2.ai.json',
    'evidence-recheck-v1.md': 'evidence-recheck-v2.md',
    "'script_runs': 'inspect_evidence_recheck_v1.py once; recheck_evidence_v1.py once'":
        "'script_runs': 'inspect_evidence_recheck_v1.py once; recheck_evidence_v1.py once (retained strict raw FAIL); adjudicate_evidence_hashes_v1.py once; recheck_evidence_v2.py once'",
    "'full_files_rehashed': len([r for r in sources if r['method'] == 'read-only full file SHA256'])":
        "'full_files_rehashed': len({r['path'].lower() for r in sources if r['method'] == 'read-only full file SHA256'})",
}
for before, after in replacements.items():
    assert before in source, before
    source = source.replace(before, after)

before = "ledger_before = {str(p): sha(p) for p in ledger_files}"
after = """adjudication_path = OUT / 'evidence-hash-adjudication-v1.ai.json'
adjudication = load_json(adjudication_path)
assert adjudication['status'] == 'PASS'
text_identities = {}
for item in adjudication['rows']:
    p = Path(item['human_path']).resolve()
    raw = p.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == item['raw_sha256']
    assert hashlib.sha256(raw.replace(b'\\r\\n', b'\\n')).hexdigest() == item['LF_text_sha256']
    assert item['manifest_csv_raw_file_identity_matches'] and item['LF_text_identity_matches']
    text_identities[(str(p).lower(), item['LF_text_sha256'])] = item
    add(adjudication_path, 'finalizer source identity', item['finalizer_path'], item['finalizer_sha256'])
assert len(text_identities) == 2
ledger_before = {str(p): sha(p) for p in ledger_files}"""
assert source.count(before) == 1
source = source.replace(before, after)

before = """            status = 'PASS' if actual == expected else 'FAIL_DIGEST'
            method = 'read-only full file SHA256'"""
after = """            status = 'PASS' if actual == expected else 'FAIL_DIGEST'
            method = 'read-only full file SHA256'
            if status == 'FAIL_DIGEST' and (str(path.resolve()).lower(), expected) in text_identities:
                item = text_identities[(str(path.resolve()).lower(), expected)]
                assert actual == item['raw_sha256']
                assert all(r['location'] == '$.human_report_sha256' and Path(r['ledger']).name in
                    ('manifest.ai.json', path.stem + '.ai.json') for r in rows)
                status = 'PASS_LF_TEXT_IDENTITY'
                method = 'verified exact LF-text identity; raw bytes separately match sealed manifest.csv; adjudication-v1'
"""
assert source.count(before) == 1
source = source.replace(before, after)

before = "    'prefix_checks': len(prefix_rows), 'prefix_checks_failed': prefix_failed,"
after = """    'prefix_checks': len(prefix_rows), 'prefix_checks_failed': prefix_failed,
    'LF_text_identities_adjudicated': [r for r in sources if r['status'] == 'PASS_LF_TEXT_IDENTITY'],
    'prior_strict_raw_recheck': 'evidence-recheck-v1 FAIL preserved unchanged; two LF-vs-CRLF fields only; raw sealed files already matched',
    'adjudication': 'evidence-hash-adjudication-v1.ai.json',"""
assert source.count(before) == 1
source = source.replace(before, after)

before = 'No existing original, frozen artifact, report, repository file or analysis database was modified.'
after = ('The two historical human_report_sha256 fields are separately adjudicated as exact LF-text identities; '
    'their raw CRLF files match sealed manifest CSV entries. The strict V1 failure and paired adjudication remain intact. '
    'No existing original, frozen artifact, report, repository file or analysis database was modified.')
assert source.count(before) == 1
source = source.replace(before, after)

exec(compile(source, str(HERE / 'recheck_evidence_v2-expanded-readonly'), 'exec'), globals())
