from pathlib import Path
import hashlib
import json

stage=Path(__file__).resolve().parent/'weighted-stage'
validation=json.loads((stage/'validation-v1.ai.json').read_text())
assert validation['status']=='PASS' and validation['cases']==314
paths={}
for filename in ('ModelVertexTransform.h','ModelVertexTransform.cpp'):
    name='src/Importers/SA2/'+filename
    source=stage/'prepared'/name
    assert hashlib.sha256(source.read_bytes()).hexdigest()==validation['source_sha256'][str(source)]
    target=stage/'core-validated'/name
    target.parent.mkdir(parents=True,exist_ok=True)
    target.write_bytes(source.read_bytes());paths[name]=hashlib.sha256(source.read_bytes()).hexdigest()
report={'status':'snapshot','core_weighted_source_sha256':paths,'reason':'Preserve exact314-case/all65536-weight validated helper before append-only stream dispatcher integration. Existing helper function bodies will remain unchanged.','repository_edited':False}
(stage/'stream-extension-snapshot-v1.ai.json').write_text(json.dumps(report,indent=2)+'\n')
(stage/'stream-extension-snapshot-v1.md').write_text('# Vertex stream extension snapshot\n\nPreserved exact weighted source validated against314 cases and full signed16 domain. Stream integration is a separate append-only candidate pending original-dispatch oracle; no repository edit.\n')
print(json.dumps({'status':'snapshot','validated_files':len(paths)}))
