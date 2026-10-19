from pathlib import Path
import hashlib
import json
import re
import subprocess

work = Path(__file__).resolve().parent
stage = work / 'weighted-stage'
log = stage / 'engine-build-v1.raw.log'
assert not log.exists()
with log.open('wb') as f:
    run = subprocess.run(['cmd.exe', '/c', str(work / 'build_engine.cmd')], cwd=work, stdout=f, stderr=subprocess.STDOUT)
raw = log.read_bytes(); text = raw.decode('utf-8', errors='replace')
exe = work / 'engine-build/SonicSunset.exe'
commands = json.loads((work / 'engine-build/compile_commands.json').read_text())
selected = [c for c in commands if c['file'].replace('\\', '/').endswith('/SA2/ModelVertexTransform.cpp')]
strict = [c['file'] for c in commands if '/fp:strict' in c['command']]
report = {'status': 'PASS' if run.returncode == 0 else 'FAIL', 'exit_code': run.returncode, 'build': 'Windows x64 MSVC/Ninja Debug EDITOR ON', 'transform_unit_compiled': bool(re.search(r'Importers[/\\]SA2[/\\]ModelVertexTransform\.cpp', text)), 'executable_linked': 'Linking CXX executable SonicSunset.exe' in text, 'compiler_errors': len(re.findall(r'error C\d+', text)), 'raw_log_sha256': hashlib.sha256(raw).hexdigest(), 'executable_sha256': hashlib.sha256(exe.read_bytes()).hexdigest(), 'source_local_strict_FP': len(selected) == 1 and '/fp:strict' in selected[0]['command'], 'strict_FP_source_files': strict, 'debug_information': 'Existing invocation-only Embedded workaround; repository defaults unchanged', 'scope': 'Opt-in explicit weighted and full-stream CPU APIs; no existing caller or GPU/gameplay execution'}
(stage / 'engine-build-v1.ai.json').write_text(json.dumps(report, indent=2) + '\n')
(stage / 'engine-build-v1.md').write_text(f"# Weighted vertex full engine build\n\n{report['status']}: {report['build']}; transform compiled {report['transform_unit_compiled']}; linked {report['executable_linked']}; errors {report['compiler_errors']}; strict FP limited to the existing transform unit. Invocation-only Embedded debug workaround; no gameplay run.\n")
print(json.dumps(report))
assert run.returncode == 0 and report['transform_unit_compiled'] and report['executable_linked'] and report['source_local_strict_FP'] and strict == [selected[0]['file']]
