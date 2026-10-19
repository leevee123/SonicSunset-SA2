from pathlib import Path
import csv
import hashlib
import json
import struct
import subprocess

work = Path(__file__).resolve().parent
stage = work/'weighted-stage'
out = stage/'weight-domain-v1'
out.mkdir(exist_ok=False)
sha = lambda b:hashlib.sha256(b).hexdigest()
compiled = json.loads((stage/'compile-v2.ai.json').read_text())
assert compiled['status'] == 'PASS'
assert all(sha(Path(p).read_bytes()) == digest for p,digest in compiled['source_sha256'].items())
exe = stage/'weighted_data_check_iso.exe'
assert sha(exe.read_bytes()) == compiled['checker_sha256']
source = work/'sa2-weight-quantization-v1/all-s16-weight-f32-oracle.csv'
reference = list(csv.DictReader(source.open(newline='')))
expected = {int(r['raw_u16'],0):int(r['PS0_f32_bits'],0) for r in reference}
assert set(expected) == set(range(65536)) and len(reference) == 65536
matrix = out/'identity.txt'
matrix.write_text('3f800000 00000000 00000000 00000000 3f800000 00000000 00000000 00000000 3f800000 00000000 00000000 00000000\n')
cases=[]
for begin in range(0,65536,8192):
    values = range(begin,min(begin+8192,65536))
    records = b''.join(struct.pack('>6IHH',*([0x3F800000]*6),raw,index) for index,raw in enumerate(values))
    count = len(values)
    header = (((8+len(records))//4-1)<<16)|0x802C
    lookahead = struct.pack('>6IHH',*([0x7FC00001]*6),0x8000,0xFFFF)
    packet = struct.pack('>II',header,count<<16)+records+lookahead
    initial = bytes((i*19+11)&255 for i in range((count+1)*32))
    wanted = bytearray(initial)
    for index,raw in enumerate(values): wanted[index*32:index*32+24] = struct.pack('>I',expected[raw])*6
    input_path = out/f'{begin:04x}.input.bin'; input_path.write_bytes(packet)
    before_path = out/f'{begin:04x}.before.bin'; before_path.write_bytes(initial)
    after_path = out/f'{begin:04x}.after.bin'
    metadata = out/f'{begin:04x}.metadata.csv'
    run = subprocess.run([str(exe),str(input_path),'0',str(matrix),str(before_path),str(after_path),str(metadata)],capture_output=True,timeout=20)
    assert run.returncode == 0,run.stderr.decode(errors='replace')
    actual = after_path.read_bytes()
    assert actual == wanted,begin
    assert metadata.read_text().strip() == f'0,{count},0'
    assert before_path.read_bytes() == initial
    cases.append({'case_id':f'weight_domain_{begin:04x}','raw_weight_begin':begin,'count':count,'scratch_bytes':len(initial),'source_sha256':sha(packet),'before_sha256':sha(initial),'expected_after_sha256':sha(wanted),'actual_after_sha256':sha(actual),'status':'PASS'})
assert all(sha(Path(p).read_bytes()) == digest for p,digest in compiled['source_sha256'].items())
with (stage/'weight-domain-cases-v1.csv').open('w',newline='') as stream:
    writer=csv.DictWriter(stream,fieldnames=list(cases[0]));writer.writeheader();writer.writerows(cases)
report={'status':'PASS','batches':len(cases),'signed16_weights':sum(c['count'] for c in cases),'stored_float_words':sum(c['count'] for c in cases)*6,'whole_scratch_bytes_compared':sum(c['scratch_bytes'] for c in cases),'reference_sha256':{str(source):sha(source.read_bytes())},'checker_sha256':sha(exe.read_bytes()),'source_sha256':compiled['source_sha256'],'scope':'Actual full weighted API with identity and six1.0inputcomponents; everyS16weight output equals independent quantization CSV, all untouched/tail/extra-slot bytes preserved. Mode0, raw bit15set, explicit host Float32 contract, no runtime game execution.'}
(stage/'weight-domain-v1.ai.json').write_text(json.dumps(report,indent=2)+'\n')
(stage/'weight-domain-v1.md').write_text(f"# Full signed weight domain through C++\n\nPASS: {report['batches']} actual weighted-API batches cover{report['signed16_weights']} signed16 inputs and{report['stored_float_words']} stored float words;{report['whole_scratch_bytes_compared']} full scratch bytes match. Independent original-quantization CSV supplies expected bits; matrices/positions are explicit synthetic identity/ones. Preserves last8B and extra sentinel slot. Unused quiet-NaN lookahead is not consumed.\n")
print(json.dumps({k:v for k,v in report.items() if k not in ('reference_sha256','source_sha256')}))
