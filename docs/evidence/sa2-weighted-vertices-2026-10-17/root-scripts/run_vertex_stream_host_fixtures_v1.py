from pathlib import Path
import hashlib
import json
import subprocess

stage=Path(__file__).resolve().parent/'weighted-stage'
exe=stage/'vertex_stream_data_check_iso.exe'
run=subprocess.run([str(exe),'--stream-fixtures'],capture_output=True)
raw=run.stdout+run.stderr
(stage/'stream-host-fixtures-v1.raw.log').write_bytes(raw)
report={'status':'PASS' if run.returncode==0 else 'FAIL','exit':run.returncode,'result':raw.decode().strip(),'checker_sha256':hashlib.sha256(exe.read_bytes()).hexdigest(),'scope':'END-before-info, opaque4B overlap/skip, unused nonfinite matrix, packed+weighted cross-packet accumulation/state/GQR1carry, offset,2Areject, missingEND/zero/hostbounds.'}
(stage/'stream-host-fixtures-v1.ai.json').write_text(json.dumps(report,indent=2)+'\n')
(stage/'stream-host-fixtures-v1.md').write_text('# First-stream host fixtures\n\n'+report['status']+': '+report['result']+'\n\n'+report['scope']+'\n')
print(json.dumps(report));raise SystemExit(run.returncode)
