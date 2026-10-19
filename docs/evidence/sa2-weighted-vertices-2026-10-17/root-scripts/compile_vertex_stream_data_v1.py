from pathlib import Path
import hashlib
import json
import subprocess

work=Path(__file__).resolve().parent
stage=work/'weighted-stage'
sha=lambda b:hashlib.sha256(b).hexdigest()
guarded=[Path('C:/decomp/SonicFantasy-master/src/Importers/SA2')/n for n in ('ModelData.h','ModelData.cpp')]
guarded+=[work/'rel-validation'/n for n in ('sa2_prs.obj','shadow_prs.obj','gc_disc.obj')]
before={str(p):sha(p.read_bytes()) for p in guarded}
with (stage/'stream-compile-v1.raw.log').open('wb') as log:
    run=subprocess.run(['cmd.exe','/c',str(work/'build_vertex_stream_data.cmd')],cwd=work,stdout=log,stderr=subprocess.STDOUT)
assert all(sha(Path(p).read_bytes())==digest for p,digest in before.items())
report={'status':'PASS' if run.returncode==0 else 'FAIL','exit':run.returncode,'flags':'/std:c++latest /EHsc /O2 /fp:strict /W4 /WX','source_sha256':{str(p):sha(p.read_bytes()) for p in (stage/'prepared/src/Importers/SA2').glob('*')},'unchanged_reader_objects_sha256':before,'raw_log_sha256':sha((stage/'stream-compile-v1.raw.log').read_bytes()),'checker_sha256':sha((stage/'vertex_stream_data_check_iso.exe').read_bytes()) if run.returncode==0 else None}
(stage/'stream-compile-v1.ai.json').write_text(json.dumps(report,indent=2)+'\n')
(stage/'stream-compile-v1.md').write_text('# First-stream strict compilation\n\n'+report['status']+': '+report['flags']+'. Unchanged ModelData reader compiled and existing GCDisc/PRS objects linked; guards unchanged. No repository change.\n')
print(json.dumps({'status':report['status'],'exit':run.returncode}))
if run.returncode:print((stage/'stream-compile-v1.raw.log').read_text(errors='replace')[-2500:])
raise SystemExit(run.returncode)
