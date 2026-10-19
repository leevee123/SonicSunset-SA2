from pathlib import Path
import csv
import hashlib
import json
import struct
import subprocess

work = Path(__file__).resolve().parent
stage = work / 'transform-stage'
oracle = work / 'sa2-model-transform-v1'
out = stage / 'comparison-v1'
out.mkdir(exist_ok=False)
sha = lambda b: hashlib.sha256(b).hexdigest()
report = {'status': 'FAIL', 'scope': 'Independent original-word finite Float32 contract; supplied matrices are test inputs, not live recovered matrices.'}
rows = []
try:
    compiled = json.loads((stage / 'compile-iso-v2.ai.json').read_text())
    assert compiled['status'] == 'PASS'
    assert all(sha(Path(p).read_bytes()) == digest for p, digest in compiled['source_sha256'].items())
    exe = stage / 'transform_data_check_iso.exe'
    assert sha(exe.read_bytes()) == compiled['exe_sha256']
    cases = [json.loads(s) for s in (oracle / 'oracle-cases.jsonl').read_text().splitlines()]
    reference = json.loads((oracle / 'oracle-summary.ai.json').read_text())
    assert reference['status'] == 'pass' and not reference['unsupported_cases']
    assert all(sha(Path(p).read_bytes()) == digest for p, digest in reference['source_sha256'].items())
    bankpath = work / 'sa2-bank-layout-v1/decoded-bank.bin'
    bank = bankpath.read_bytes()
    assert sha(bank) == 'b7ea586ed0fa22330dc8a2cfe2bb8fa9ce4ac70d9561764f35af4ced5d371963'
    slots = list(csv.DictReader((oracle / 'oracle-output-slots.csv').open(newline='')))
    slots_by_case = {}
    for slot in slots: slots_by_case.setdefault(slot['case_id'], []).append(slot)
    for case in cases:
        caseid = case['case_id']
        stride = 16 if case['opcode'] == 0x23 else 24
        records = bytes.fromhex(case['records_hex'])
        assert len(records) == case['count'] * stride
        if case['source_kind'] == 'real':
            offset = int(case['packet_decoded_offset'], 0)
            source = bankpath
            assert sha(bank) == case['input_source_sha256']
            assert bank[offset+8:offset+8+len(records)] == records
            header, info = struct.unpack_from('>II', bank, offset)
            assert (header & 255, info >> 16, info & 65535) == (case['opcode'], case['count'], case['start'])
        else:
            offset = 0
            source = out / (caseid + '.input.bin')
            lookahead = bytes.fromhex(case['lookahead_hex'])
            assert sha(records + lookahead) == case['input_source_sha256']
            header = (((8 + len(records)) // 4 - 1) << 16) | case['opcode']
            source.write_bytes(struct.pack('>II', header, case['count'] << 16 | case['start']) + records + lookahead)
        initial = oracle / case['before_file']
        expected = (oracle / case['after_file']).read_bytes()
        before = initial.read_bytes()
        assert sha(before) == case['before_sha256'] and sha(expected) == case['after_sha256']
        matrix = out / (caseid + '.matrix.txt')
        matrix.write_text(' '.join(case['matrix_bits']) + '\n')
        output = out / (caseid + '.output.bin')
        metadata = out / (caseid + '.metadata.csv')
        run = subprocess.run([str(exe), str(source), hex(offset), str(matrix), str(initial), str(output), str(metadata)], capture_output=True, timeout=10)
        assert run.returncode == 0, (caseid, run.stdout.decode(errors='replace'), run.stderr.decode(errors='replace'))
        actual = output.read_bytes()
        assert actual == expected, (caseid, next((i for i, (a, b) in enumerate(zip(actual, expected)) if a != b), None), sha(actual), case['after_sha256'])
        observed = tuple(map(int, metadata.read_text().strip().split(',')))
        assert observed == (case['start'], case['count'], case['opcode']), (caseid, observed)
        assert sha(initial.read_bytes()) == case['before_sha256']
        case_slots = slots_by_case[caseid]
        assert len(case_slots) == case['count']
        for slot in case_slots:
            start = int(slot['scratch_index']) * 32
            assert actual[start:start+32].hex() == slot['after_hex']
            assert before[start:start+32].hex() == slot['before_hex']
        rows.append({'case_id': caseid, 'source_kind': case['source_kind'], 'packet_offset': hex(offset), 'opcode': hex(case['opcode']), 'first_scratch_index': case['start'], 'record_count': case['count'], 'matrix_name': case['matrix_name'], 'scratch_bytes': len(actual), 'before_sha256': case['before_sha256'], 'after_sha256': sha(actual), 'status': 'PASS'})
    fixtures = json.loads((stage / 'host-fixtures-v1.ai.json').read_text())
    assert fixtures['status'] == 'PASS'
    assert len(rows) == reference['success_cases'] and sum(r['record_count'] for r in rows) == len(slots) == reference['total_output_slots']
    assert sha(bankpath.read_bytes()) == sha(bank)
    assert all(sha(Path(p).read_bytes()) == digest for p, digest in compiled['source_sha256'].items())
    report.update(status='PASS', cases=len(rows), real_cases=sum(r['source_kind'] == 'real' for r in rows), synthetic_cases=sum(r['source_kind'] == 'synthetic' for r in rows), real_unique_packets=len({r['packet_offset'] for r in rows if r['source_kind'] == 'real'}), output_slots=len(slots), complete_scratch_bytes_compared=sum(r['scratch_bytes'] for r in rows), source_sha256=compiled['source_sha256'], checker_sha256=sha(exe.read_bytes()), oracle_sha256={str(oracle / n): sha((oracle / n).read_bytes()) for n in ('oracle-cases.jsonl', 'oracle-output-slots.csv', 'oracle-summary.ai.json', 'vertex_oracle_v1.py')}, bank_sha256=sha(bank), host_fixtures=fixtures['result'], original_game_or_dolphin_executed=False, production_corrections=0)
except Exception as error:
    report['reason'] = repr(error)
finally:
    if rows:
        with (stage / 'validation-cases-v1.csv').open('w', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=list(rows[0])); writer.writeheader(); writer.writerows(rows)
    (stage / 'validation-v1.ai.json').write_text(json.dumps(report, indent=2) + '\n')
    (stage / 'validation-v1.md').write_text('# Vertex transform comparison\n\n' + report['status'] + ': ' + (f"{report['cases']} cases ({report['real_cases']} real-byte inputs from {report['real_unique_packets']} packets; {report['synthetic_cases']} synthetic), {report['output_slots']} output slots and {report['complete_scratch_bytes_compared']} complete scratch bytes match every original-word-reference byte. Host fixtures: {report['host_fixtures']}." if report['status'] == 'PASS' else report.get('reason', 'unknown failure')) + '\n\n' + report['scope'] + '\n')
print(json.dumps({k: v for k, v in report.items() if k not in ('source_sha256', 'oracle_sha256')}))
raise SystemExit(0 if report['status'] == 'PASS' else 1)
