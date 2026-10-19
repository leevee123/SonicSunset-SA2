from pathlib import Path
import hashlib
import json
import subprocess

out = Path(__file__).resolve().parent/'weighted-stage'
exe = out/'weighted_data_check_iso.exe'
run = subprocess.run([str(exe),'--fixtures'],capture_output=True)
raw = run.stdout+run.stderr
(out/'host-fixtures-v1.raw.log').write_bytes(raw)
report = {'status':'PASS' if run.returncode == 0 else 'FAIL','exit':run.returncode,'result':raw.decode().strip(),'checker_sha256':hashlib.sha256(exe.read_bytes()).hexdigest(),'scope':'Explicit signed weights, additive base, all-nonzero modes, ordered duplicate destinations, copied/untouched bytes and host finite/bounds/environment guards; numerical oracle remains independent.'}
(out/'host-fixtures-v1.ai.json').write_text(json.dumps(report,indent=2)+'\n')
(out/'host-fixtures-v1.md').write_text('# Weighted host fixtures\n\n'+report['status']+': '+report['result']+'\n\n'+report['scope']+'\n')
print(json.dumps(report))
raise SystemExit(run.returncode)
