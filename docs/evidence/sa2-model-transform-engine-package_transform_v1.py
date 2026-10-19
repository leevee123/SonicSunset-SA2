from pathlib import Path
import hashlib
import json
import shutil
import struct
import subprocess

root = Path(__file__).resolve().parent.parent
work = root / 'work'
stage = work / 'transform-stage'
oracle = work / 'sa2-model-transform-v1'
package = root / 'outputs/SA2-Vertex-Check'
package.mkdir(exist_ok=False)
sha = lambda b: hashlib.sha256(b).hexdigest()
validation = json.loads((stage / 'validation-v1.ai.json').read_text())
assert validation['status'] == 'PASS'
assert all(sha(Path(p).read_bytes()) == digest for p, digest in validation['source_sha256'].items())
checker = stage / 'transform_data_check_iso.exe'
assert sha(checker.read_bytes()) == validation['checker_sha256']
reference = {k: validation[k] for k in ('checker_sha256', 'bank_sha256', 'real_unique_packets', 'real_cases', 'synthetic_cases', 'output_slots', 'host_fixtures', 'scope')}
reference['contract'] = 'GQR0=0, RN-nearest, NI0, nontrapping; finite consumed inputs/retained-lane results; PSQ final-store FTZ; no native aliases, unused preloads/lanes or FPSCR flags; supplied matrices not live recovered matrices.'
reference['cases'] = []
for case in map(json.loads, (oracle / 'oracle-cases.jsonl').read_text().splitlines()):
    initial = (oracle / case['before_file']).read_bytes()
    seed = initial[0]
    assert bytes((seed + i * 37) & 255 for i in range(len(initial))) == initial
    row = {k: case[k] for k in ('case_id', 'source_kind', 'opcode', 'count', 'start', 'matrix_bits', 'matrix_name', 'before_sha256', 'after_sha256')}
    row.update(initial_seed=seed, initial_size=len(initial), packet_offset=int(case['packet_decoded_offset'], 0) if case['source_kind'] == 'real' else 0)
    if case['source_kind'] == 'synthetic':
        records = bytes.fromhex(case['records_hex'])
        header = (((8 + len(records)) // 4 - 1) << 16) | case['opcode']
        row['synthetic_packet_hex'] = (struct.pack('>II', header, case['count'] << 16 | case['start']) + records + bytes.fromhex(case['lookahead_hex'])).hex()
    reference['cases'].append(row)
(package / 'Reference.ai.json').write_text(json.dumps(reference, indent=2) + '\n')
shutil.copyfile(checker, package / checker.name)
shutil.copyfile(work / 'check_transform_package.py', package / 'check_vertices.py')
python = Path('C:/Users/naync/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/python.exe')
iso = work / 'sa2.iso'
(package / 'Start-SA2-Vertex-Check.cmd').write_text(f'@echo off\n@"{python}" -X utf8 "%~dp0check_vertices.py" "{iso}"\n@pause\n')
(package / 'README.md').write_text('''# Sonic vertex calculation check

Double-click **Start-SA2-Vertex-Check.cmd**. The console reports PASS or FAIL and waits for a key. Last-result.md keeps the result.

This checks 71 original Sonic packets under three supplied matrices, plus six arithmetic edge cases:219 checks and7,017 output slots. Every complete output buffer must match the independent original-instruction reference. Extra checks verify boundaries, copied bytes and unsupported inputs.

The supplied matrices test the recovered calculations; they are not captured live game matrices. The new engine helper covers op23/op29 with an explicit floating-point contract. Weighted op2C, live state, complete model display, animation, levels and gameplay remain unfinished. The detailed contract and per-case hashes are in Reference.ai.json and the repository's paired model reference.

The original disc is opened only for reading. No game media is bundled. Temporary files stay inside this folder and are removed after the check. Existing local disc/Python paths make this launcher specific to this computer. Earlier checks and the interactive Chao texture preview remain available.
''')
(package / 'README.ai.json').write_text(json.dumps({'launcher': 'Start-SA2-Vertex-Check.cmd', 'cases': len(reference['cases']), 'output_slots': reference['output_slots'], 'real_unique_packets': 71, 'game_media_included': False, 'disc_modified': False, 'playable_game': False, 'contract': reference['contract'], 'outputs': ['Last-result.md', 'Last-result.ai.json'], 'machine_paths': [str(python), str(iso)]}, indent=2) + '\n')
run = subprocess.run([str(python), '-X', 'utf8', str(package / 'check_vertices.py'), str(iso)], capture_output=True, timeout=60)
(package / 'Package-check.raw.log').write_bytes(run.stdout + run.stderr)
result = json.loads((package / 'Last-result.ai.json').read_text())
report = {'status': 'PASS' if run.returncode == 0 and result['status'] == 'PASS' else 'FAIL', 'package': str(package), 'launcher': str(package / 'Start-SA2-Vertex-Check.cmd'), 'result': result, 'package_files_sha256': {p.name: sha(p.read_bytes()) for p in sorted(package.iterdir()) if p.is_file()}, 'run': 'once/package-v1; packaging verification', 'game_media_included': False}
(stage / 'package-v1.ai.json').write_text(json.dumps(report, indent=2) + '\n')
(stage / 'package-v1.md').write_text('# Packaged vertex check\n\n' + report['status'] + ':219 cases/7017slots,71 original packets with three supplied matrices and six synthetic cases. Local read-only disc extraction; no game media bundled. Paired last-result files; no model display or gameplay claim.\n')
print(json.dumps({k: v for k, v in report.items() if k != 'package_files_sha256'}))
assert report['status'] == 'PASS', result
