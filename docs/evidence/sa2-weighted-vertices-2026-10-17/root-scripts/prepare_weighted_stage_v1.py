from pathlib import Path
import hashlib
import json

work = Path(__file__).resolve().parent
repo = Path('C:/decomp/SonicFantasy-master')
stage = work / 'weighted-stage'
stage.mkdir(exist_ok=False)
sha = lambda b: hashlib.sha256(b).hexdigest()
prior = json.loads((work / 'transform-stage/docs-applied-v2.ai.json').read_text())
for key in ('engine_after_sha256','docs_after_sha256'):
    assert all(sha((repo / n).read_bytes()) == digest for n,digest in prior[key].items()), key
docs = ['docs/SA2_MODEL_DATA_REFERENCE.md','docs/ai/SA2_MODEL_DATA.md','docs/SA2_DECOMPILATION_PROGRESS.md','docs/ai/SA2_DECOMPILATION.md','docs/ARCHITECTURE.md','docs/ai/ARCHITECTURE.md','docs/ai/ARCH_IMPORTERS.md','docs/ENGINE_CHANGES.md','docs/ai/ENGINE_CHANGES.md','docs/ai/README.md']
engine = ['src/Importers/SA2/ModelVertexTransform.h','src/Importers/SA2/ModelVertexTransform.cpp','CMakeLists.txt']
for name in docs + engine:
    target = stage / 'original' / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes((repo / name).read_bytes())
    if name.endswith(('.h','.cpp')):
        target = stage / 'prepared' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((repo / name).read_bytes())
report = {'status': 'snapshot', 'engine_before_sha256': prior['engine_after_sha256'], 'prior_docs_evidence_sha256': prior['docs_after_sha256'], 'docs_before_sha256': {n: sha((repo / n).read_bytes()) for n in docs}, 'scope': 'Append an explicit weighted op2C CPU helper using unchanged unweighted helpers and source-local strict FP; exact signed16/256 weights, mode0 product/nonzero fused accumulation, ordered duplicate destinations. No inferred live matrix/state/provider bindings or gameplay.'}
(stage / 'snapshot.ai.json').write_text(json.dumps(report, indent=2) + '\n')
(stage / 'snapshot.md').write_text(f"# Weighted vertex staging\n\nVerified{len(prior['engine_after_sha256'])} source/content and{len(prior['docs_after_sha256'])} prior docs/evidence hashes. Captured source/document preimages before edits. {report['scope']}\n")
print(json.dumps({'status': 'snapshot', 'source_content': len(prior['engine_after_sha256']), 'docs_evidence': len(prior['docs_after_sha256'])}))
