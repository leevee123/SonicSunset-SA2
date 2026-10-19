from pathlib import Path
import csv
import hashlib
import json
import os
import subprocess

work = Path(__file__).resolve().parent
out = work / 'sa2-model-setup-v1'
sha = lambda b: hashlib.sha256(b).hexdigest()
java = Path('C:/decomp/sonic-adventure-gc/jdk-21.0.12.1+1/bin/java.exe')
ghidra = Path('C:/decomp/sonic-adventure-gc/ghidra_12.1.4_PUBLIC')
classes = work / 'sonicmdl-loader/classes'
module = work / 'full-decompile-fp/Sa2GekkoLanguage'
protected = {str(p): sha(p.read_bytes()) for p in (classes / 'DumpSonicLoader.class', work / 'sonicmdl-loader/DumpSonicLoader.java', work / 'sa2-disc/main.dol')}
protected.update({str(p): sha(p.read_bytes()) for p in module.rglob('*') if p.is_file()})
runtime = out / 'runtime'
for name in ('home', 'settings', 'cache', 'tmp'):
    (runtime / name).mkdir(parents=True, exist_ok=False)
args = ['-Djava.system.class.loader=ghidra.GhidraClassLoader', '-Djava.awt.headless=true', '-Dghidra.external.modules=' + str(module), '-Duser.home=' + str(runtime / 'home'), '-Dapplication.settingsdir=' + str(runtime / 'settings'), '-Dapplication.cachedir=' + str(runtime / 'cache'), '-Djava.io.tmpdir=' + str(runtime / 'tmp'), '-cp', os.pathsep.join([str(classes)] + [str(p) for p in sorted(ghidra.rglob('*.jar'))]), 'ghidra.Ghidra', 'DumpSonicLoader', str(work / 'sa2-disc/main.dol'), str(out / 'function-ranges.tsv'), str(out / 'original-words.csv')]
arg_file = out / 'java-arguments.txt'
arg_file.write_bytes(('\n'.join('"' + a.replace('\\', '\\\\').replace('"', '\\"') + '"' for a in args) + '\n').encode())
with (out / 'parser.raw.log').open('wb') as log:
    run = subprocess.run([str(java), '@' + str(arg_file)], stdout=log, stderr=subprocess.STDOUT, timeout=120)
assert all(sha(Path(p).read_bytes()) == digest for p, digest in protected.items())
words = list(csv.DictReader((out / 'original-words.csv').open(newline=''))) if run.returncode == 0 else []
report = {'status': 'PASS' if run.returncode == 0 else 'FAIL', 'exit': run.returncode, 'words': len(words), 'protected_sha256': protected, 'parser': 'project-free Ghidra language API; no ProgramDB', 'raw_log_sha256': sha((out / 'parser.raw.log').read_bytes()), 'original_word_sha256': sha((out / 'original-words.csv').read_bytes()) if words else None}
(out / 'parsing.ai.json').write_text(json.dumps(report, indent=2) + '\n')
(out / 'parsing.md').write_text(f"# Original model setup words\n\nProject-free original-word decoding: {report['status']}; {len(words)} instructions. Original DOL, helper and language inputs remained unchanged. Raw log retained; no native execution or project opened.\n")
print(json.dumps({k: report[k] for k in ('status', 'exit', 'words')}))
raise SystemExit(run.returncode)
