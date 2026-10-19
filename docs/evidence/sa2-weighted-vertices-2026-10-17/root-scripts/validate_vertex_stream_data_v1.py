from pathlib import Path
import csv
import hashlib
import json
import subprocess

work = Path(__file__).resolve().parent
stage = work / 'weighted-stage'
oracle = work / 'sa2-weighted-transform-v1/stream-v1'
out = stage / 'stream-comparison-v1'
out.mkdir(exist_ok=False)
sha = lambda b: hashlib.sha256(b).hexdigest()
report = {'status': 'FAIL', 'scope': 'Original dispatcher and helpers under explicit finite Float32, GQR0=0, RN-nearest, NI=0, nontrapping and nonalias matrix/global bindings; no hardware or Dolphin execution.'}
rows = []
try:
    compile_report = json.loads((stage / 'stream-compile-v1.ai.json').read_text())
    assert compile_report['status'] == 'PASS'
    for p, digest in compile_report['source_sha256'].items():
        assert sha(Path(p).read_bytes()) == digest
    exe = stage / 'vertex_stream_data_check_iso.exe'
    assert sha(exe.read_bytes()) == compile_report['checker_sha256']
    cases = [json.loads(line) for line in (oracle / 'cases.jsonl').read_text().splitlines()]
    for case in cases:
        cid = case['case_id']
        source = Path(case['source_file'])
        before = oracle / case['before_file']
        wanted = oracle / case['after_file']
        assert sha(source.read_bytes()) == case['source_sha256']
        assert sha(before.read_bytes()) == case['before_sha256']
        assert sha(wanted.read_bytes()) == case['after_sha256']
        matrix = out / (cid + '.matrix.txt')
        matrix.write_text(' '.join(case['matrix_bits']) + '\n')
        output = out / (cid + '.output.bin')
        metadata = out / (cid + '.metadata.csv')
        run = subprocess.run([str(exe), '--stream', str(source), str(case['stream_offset']), str(matrix), str(before), '0x' + case['initial_state'], '0x' + case['initial_gqr1'], str(output), str(metadata)], capture_output=True, timeout=15)
        assert run.returncode == 0, (cid, run.stderr.decode(errors='replace'))
        actual = output.read_bytes()
        assert actual == wanted.read_bytes(), (cid, sha(actual), case['after_sha256'])
        expected_meta = f"{case['end_offset']},{int(case['final_state'], 16)},{int(case['final_gqr1'], 16)}"
        assert metadata.read_text().strip() == expected_meta, (cid, metadata.read_text(), expected_meta)
        assert sha(before.read_bytes()) == case['before_sha256']
        rows.append({'case_id': cid, 'kind': case['kind'], 'stream_offset': case['stream_offset'], 'matrix_name': case['matrix_name'], 'scratch_bytes': len(actual), 'target_slots': len(case['target_indices']), 'end_offset': case['end_offset'], 'final_state': case['final_state'], 'final_gqr1': case['final_gqr1'], 'before_sha256': case['before_sha256'], 'after_sha256': sha(actual), 'status': 'PASS'})
    assert len(rows) == 309 and sum(r['kind'] == 'real' for r in rows) == 300
    fixtures = json.loads((stage / 'stream-host-fixtures-v1.ai.json').read_text())
    assert fixtures['status'] == 'PASS'
    report.update(status='PASS', cases=len(rows), real_cases=300, synthetic_cases=9, real_streams=100, whole_scratch_bytes_compared=sum(r['scratch_bytes'] for r in rows), target_slot_rows=sum(r['target_slots'] for r in rows), original_steps=sum(c['steps'] for c in cases), host_fixtures=fixtures, source_sha256=compile_report['source_sha256'], checker_sha256=sha(exe.read_bytes()), cases_sha256=sha((oracle / 'cases.jsonl').read_bytes()), production_corrections=0)
except Exception as error:
    report['reason'] = repr(error)
finally:
    if rows:
        with (stage / 'stream-validation-cases-v1.csv').open('w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0])); writer.writeheader(); writer.writerows(rows)
    (stage / 'stream-validation-v1.ai.json').write_text(json.dumps(report, indent=2) + '\n')
    (stage / 'stream-validation-v1.md').write_text('# Full vertex stream comparison\n\n' + report['status'] + ': ' + (f"{len(rows)} streams; {report['whole_scratch_bytes_compared']} complete scratch bytes and all state/GQR1/end metadata match." if report['status'] == 'PASS' else report.get('reason', 'unknown')) + '\n\n' + report['scope'] + '\n')
print(json.dumps({k: v for k, v in report.items() if k not in ('source_sha256', 'host_fixtures')}))
raise SystemExit(0 if report['status'] == 'PASS' else 1)
