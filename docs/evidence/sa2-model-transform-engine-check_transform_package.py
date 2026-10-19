from pathlib import Path
import hashlib
import json
import struct
import subprocess
import sys
import tempfile

base = Path(__file__).resolve().parent
sha = lambda b: hashlib.sha256(b).hexdigest()
report = {'status': 'FAIL', 'scope': 'Explicit vertex arithmetic with supplied test matrices; model display, weighted vertices, animation and gameplay remain unfinished.'}
try:
    assert len(sys.argv) == 2, 'Expected the existing original disc path.'
    reference = json.loads((base / 'Reference.ai.json').read_text())
    checker = base / 'transform_data_check_iso.exe'
    assert sha(checker.read_bytes()) == reference['checker_sha256'], 'Checker changed.'
    with tempfile.TemporaryDirectory(dir=base, prefix='.vertex-check-') as temporary:
        temp = Path(temporary).resolve()
        assert temp.is_relative_to(base.resolve()), 'Temporary path is outside this check folder.'
        decoded = temp / 'sonic.bin'
        run = subprocess.run([str(checker), '--extract', sys.argv[1], str(decoded)], capture_output=True, timeout=30)
        assert run.returncode == 0, run.stderr.decode(errors='replace').strip()
        assert sha(decoded.read_bytes()) == reference['bank_sha256'], 'Sonic data differs from the validated original.'
        for case in reference['cases']:
            caseid = case['case_id']
            initial = bytes((case['initial_seed'] + i * 37) & 255 for i in range(case['initial_size']))
            assert sha(initial) == case['before_sha256'], f'Initial bytes differ in {caseid}.'
            scratch = temp / 'initial.bin'; scratch.write_bytes(initial)
            matrix = temp / 'matrix.txt'; matrix.write_text(' '.join(case['matrix_bits']) + '\n')
            source = decoded
            offset = case['packet_offset']
            if case['source_kind'] == 'synthetic':
                source = temp / 'synthetic.bin'
                source.write_bytes(bytes.fromhex(case['synthetic_packet_hex']))
            output = temp / 'output.bin'
            metadata = temp / 'metadata.csv'
            run = subprocess.run([str(checker), str(source), hex(offset), str(matrix), str(scratch), str(output), str(metadata)], capture_output=True, timeout=10)
            assert run.returncode == 0, f"{caseid}: {run.stderr.decode(errors='replace').strip()}"
            assert sha(output.read_bytes()) == case['after_sha256'], f'Vertex bytes differ in {caseid}.'
            assert metadata.read_text().strip() == f"{case['start']},{case['count']},{case['opcode']}", f'Metadata differs in {caseid}.'
        run = subprocess.run([str(checker), '--fixtures'], capture_output=True, timeout=10)
        assert run.returncode == 0, run.stderr.decode(errors='replace').strip()
        assert run.stdout.decode().strip() == reference['host_fixtures']
    report.update(status='PASS', cases=len(reference['cases']), real_unique_packets=reference['real_unique_packets'], real_cases=reference['real_cases'], synthetic_cases=reference['synthetic_cases'], output_slots=reference['output_slots'], original_disc_modified=False, live_matrix_recovered=False, original_game_or_dolphin_executed=False, host_fixtures=reference['host_fixtures'])
    message = f"PASS: {report['cases']} vertex checks match the original-code reference ({report['output_slots']:,} output slots)."
except Exception as error:
    report['reason'] = str(error)
    message = f'FAIL: {error}'
(base / 'Last-result.ai.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
(base / 'Last-result.md').write_text(message + '\n\n' + report['scope'] + '\nThe original disc is unchanged.\n', encoding='utf-8')
print(message)
print('This checks calculations with supplied matrices. It does not display a model or run gameplay.')
raise SystemExit(0 if report['status'] == 'PASS' else 1)
