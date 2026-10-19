from pathlib import Path
import hashlib
import json

stage = Path(__file__).resolve().parent/'weighted-stage'
sha = lambda b: hashlib.sha256(b).hexdigest()
rows = []
for filename in ('ModelVertexTransform.h','ModelVertexTransform.cpp'):
    name = 'src/Importers/SA2/'+filename
    before = (stage/'original'/name).read_bytes()
    after = (stage/'prepared'/name).read_bytes()
    cut = before.rfind(b'\n}')
    assert cut > 0 and before[cut:] == b'\n}\n'
    assert after.startswith(before[:cut]), filename
    assert after.endswith(b'\n}\n')
    rows.append({'file':name,'unchanged_original_prefix_bytes':cut,'before_sha256':sha(before),'after_sha256':sha(after),'unweighted_scopes_byte_identical':True})
report = {'status':'PASS','files':rows,'scope':'Append-only before namespace close. Existing structs, public unweighted function, static helpers and all old function bodies stay byte-identical; existing CMake strict FP setting reused.'}
(stage/'scope-preservation-v1.ai.json').write_text(json.dumps(report,indent=2)+'\n')
(stage/'scope-preservation-v1.md').write_text('# Existing unweighted scope preservation\n\nPASS: both edited files retain every preexisting byte before the namespace close. All old types/functions/helper bodies are unchanged. New weighted types/functions append within the same namespace and existing source-local FP options. No old-runtime repeat needed absent further changes.\n')
print(json.dumps(report))
