from pathlib import Path
import difflib
import hashlib
import json

root = Path(__file__).resolve().parent.parent
stage = root / 'work/weighted-stage'
repo = Path('C:/decomp/SonicFantasy-master').resolve()
sha = lambda b: hashlib.sha256(b).hexdigest()
snapshot = json.loads((stage / 'snapshot.ai.json').read_text())
compiled = json.loads((stage / 'stream-compile-v1.ai.json').read_text())
for name in ('validation-v1', 'stream-validation-v1', 'weight-domain-v1', 'scope-preservation-v2'):
    assert json.loads((stage / (name + '.ai.json')).read_text())['status'] == 'PASS', name
assert not (stage / 'applied.ai.json').exists()
for key in ('engine_before_sha256', 'prior_docs_evidence_sha256'):
    assert all(sha((repo / p).read_bytes()) == digest for p, digest in snapshot[key].items()), key
payloads = {}
for name in ('src/Importers/SA2/ModelVertexTransform.h', 'src/Importers/SA2/ModelVertexTransform.cpp'):
    source = stage / 'prepared' / name
    assert sha(source.read_bytes()) == compiled['source_sha256'][str(source)]
    assert (repo / name).read_bytes() == (stage / 'original' / name).read_bytes()
    payloads[name] = source.read_bytes()
patch = []
for name, data in payloads.items():
    before = (repo / name).read_bytes()
    for line in difflib.unified_diff(before.decode().splitlines(keepends=True), data.decode().splitlines(keepends=True), fromfile='a/' + name, tofile='b/' + name):
        patch.append(line if line.endswith('\n') else line + '\n\\ No newline at end of file\n')
review = root / 'outputs/SA2-weighted-vertex-port.patch'
review.write_bytes(''.join(patch).encode())
for name, data in payloads.items():
    target = (repo / name).resolve()
    assert target.is_relative_to(repo)
    target.write_bytes(data)
expected = dict(snapshot['engine_before_sha256'])
expected.update({p: sha(b) for p, b in payloads.items()})
assert all(sha((repo / p).read_bytes()) == digest for p, digest in expected.items())
report = {'status': 'applied', 'engine_after_sha256': expected, 'engine_files_changed': list(payloads), 'new_engine_files': 0, 'other_guarded_engine_content_files_unchanged': len(expected) - len(payloads), 'review_patch': str(review), 'validation': '314 weighted cases +309 complete streams +all65536 signed weights; exact complete scratch and metadata match; original helper bodies unchanged', 'build': 'pending'}
(stage / 'applied.ai.json').write_text(json.dumps(report, indent=2) + '\n')
(stage / 'applied.md').write_text('# Weighted vertex port applied\n\nTwo existing SA2 transform files extended with validated weighted and full-stream CPU APIs.252 other guarded source/content files, including CMake, unchanged. Full engine build pending. Explicit caller inputs; no live renderer/gameplay binding.\n')
print(json.dumps({k:v for k,v in report.items() if k != 'engine_after_sha256'}))
