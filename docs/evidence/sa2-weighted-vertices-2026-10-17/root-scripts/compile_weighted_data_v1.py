from pathlib import Path
import hashlib
import json
import subprocess

work = Path(__file__).resolve().parent
out = work / 'weighted-stage'
sha = lambda b: hashlib.sha256(b).hexdigest()
protected = {str(work/'rel-validation'/n): sha((work/'rel-validation'/n).read_bytes()) for n in ('sa2_prs.obj','shadow_prs.obj','gc_disc.obj')}
with (out/'compile-v1.raw.log').open('wb') as log:
    run = subprocess.run(['cmd.exe','/c',str(work/'build_weighted_data.cmd')],cwd=work,stdout=log,stderr=subprocess.STDOUT)
assert all(sha(Path(p).read_bytes()) == digest for p,digest in protected.items())
report = {'status': 'PASS' if run.returncode == 0 else 'FAIL','exit':run.returncode,'flags':'/std:c++latest /EHsc /O2 /fp:strict /W4 /WX','source_sha256':{str(p):sha(p.read_bytes()) for p in (out/'prepared/src/Importers/SA2').glob('*')},'reused_object_sha256':protected,'raw_log_sha256':sha((out/'compile-v1.raw.log').read_bytes()),'checker_sha256':sha((out/'weighted_data_check_iso.exe').read_bytes()) if run.returncode == 0 else None}
(out/'compile-v1.ai.json').write_text(json.dumps(report,indent=2)+'\n')
(out/'compile-v1.md').write_text('# Weighted vertex strict build\n\n'+report['status']+': '+report['flags']+'. Existing GCDisc/PRS object hashes unchanged. No repository edit.\n')
print(json.dumps({'status':report['status'],'exit':run.returncode}))
if run.returncode: print((out/'compile-v1.raw.log').read_text(errors='replace')[-2500:])
raise SystemExit(run.returncode)
