from pathlib import Path
import hashlib
import json

stage=Path(__file__).resolve().parent/'weighted-stage'
sha=lambda b:hashlib.sha256(b).hexdigest()
rows=[]
for version in ('original','core-validated'):
    for filename in ('ModelVertexTransform.h','ModelVertexTransform.cpp'):
        name='src/Importers/SA2/'+filename
        before=(stage/version/name).read_bytes()
        after=(stage/'prepared'/name).read_bytes()
        normalized=after
        if filename.endswith('.cpp'):
            include=b'#include "Importers/SA2/ModelData.h"\n'
            assert normalized.count(include)==1 and include not in before
            normalized=normalized.replace(include,b'')
        cut=before.rfind(b'\n}')
        assert cut>0 and before[cut:]==b'\n}\n' and normalized.startswith(before[:cut])
        rows.append({'version':version,'file':name,'preserved_prefix_bytes':cut,'before_sha256':sha(before),'current_sha256':sha(after),'allowed_preexisting_line_changes':'one ModelData.h include only; no old types/functions/helpers changed'})
report={'status':'PASS','checks':rows,'validation_binding':'Core314-case/all65536-weight candidate hashes preserved exactly in core-validated snapshots. Current candidate only adds stream declarations/function and one dependency include; every weighted/unweighted function body remains identical. New stream oracle and packaging test the complete current translation unit.'}
(stage/'scope-preservation-v2.ai.json').write_text(json.dumps(report,indent=2)+'\n')
(stage/'scope-preservation-v2.md').write_text('# Existing and weighted scope preservation after stream integration\n\nPASS: all original and already-validated weighted types/functions/helper bodies retain every byte before their old namespace close, after removing only the new ModelData.h include. Core validated source hashes remain recoverable from immutable core-validated snapshots. Stream logic is appended and requires its own oracle. No old arithmetic rewrite.\n')
print(json.dumps({'status':'PASS','scope_prefix_checks':len(rows),'old_algorithms_changed':False}))
