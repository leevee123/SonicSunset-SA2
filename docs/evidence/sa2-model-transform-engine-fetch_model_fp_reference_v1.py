from pathlib import Path
import hashlib
import json
import urllib.request

out = Path(__file__).resolve().parent / 'sa2-model-setup-v1/dolphin-reference'
out.mkdir(exist_ok=False)
commit = 'e6f3ae17627e4344da95b13424af5baf4c892b08'
files = []
for name in ('Interpreter_Paired.cpp', 'Interpreter_LoadStorePaired.cpp'):
    url = f'https://raw.githubusercontent.com/dolphin-emu/dolphin/{commit}/Source/Core/Core/PowerPC/Interpreter/{name}'
    try:
        with urllib.request.urlopen(url, timeout=25) as response:
            data = response.read(250000)
        assert len(data) < 250000
        (out / name).write_bytes(data)
        files.append({'name': name, 'url': url, 'status': 'saved', 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
    except Exception as exc:
        files.append({'name': name, 'url': url, 'status': 'failed', 'error': str(exc)})
report = {'commit': commit, 'files': files, 'prior_web_tool': 'cache miss for raw and GitHub blob URLs', 'use': 'primary hardware semantic reference only; no game source; no engine code copied', 'source': 'official dolphin-emu/dolphin'}
(out / 'manifest.ai.json').write_text(json.dumps(report, indent=2) + '\n')
(out / 'manifest.md').write_text('# Paired-single hardware semantic references\n\nOfficial Dolphin files pinned to commit `' + commit + '`. Web tool cache misses were retained; this bounded direct fetch records exact bytes and SHA-256. These are emulator sources, not original game source. No reference code is copied into the engine.\n\n' + '\n'.join(f"- {r['name']}: {r['status']}; {r.get('sha256', r.get('error'))}" for r in files) + '\n')
print(json.dumps({'saved': sum(r['status'] == 'saved' for r in files), 'failed': sum(r['status'] == 'failed' for r in files)}))
