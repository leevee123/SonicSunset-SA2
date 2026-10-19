from pathlib import Path
import csv,ctypes,hashlib,importlib.util,json,struct
from collections import Counter,defaultdict

OUT=Path(__file__).resolve().parent;CORE=OUT.parent
spec=importlib.util.spec_from_file_location('own_stream_oracle',OUT/'stream_oracle_v1.py')
stream=importlib.util.module_from_spec(spec);spec.loader.exec_module(stream)
own=stream.own
sha=lambda b:hashlib.sha256(b).hexdigest()
cases=[json.loads(line) for line in (OUT/'cases.jsonl').read_text().splitlines()]
assert sha((OUT/'cases.jsonl').read_bytes())=='2ec2e706c87cad90c67918b58a2c1481e1f973a2f8bd25d4da37f87d998f4a9f'
calls=defaultdict(list)
with (OUT/'native-helper-calls.csv').open(newline='') as f:
    for row in csv.DictReader(f):calls[row['case_id']].append(row)
descriptor_checks=0
for case in cases:
    expected=[r for r in case['commands'] if r['opcode'] in (0x23,0x29,0x2c)]
    assert len(expected)==len(calls[case['case_id']])
    gqr=case['initial_gqr1']
    for command,call in zip(expected,calls[case['case_id']]):
        assert int(call['opcode'],0)==command['opcode']
        assert int(call['packet_offset'],0)==command['offset'] and int(call['data_offset'])==command['offset']+8
        assert int(call['base_scratch_index'])==command['start'] and int(call['count'])==command['count']
        assert call['matrix_pointer']=='0x10000000' and call['gqr1_before']==gqr
        if command['opcode']==0x2c:assert int(call['variant'])==command['variant'];gqr='08070807'
        descriptor_checks+=1
    assert gqr==case['final_gqr1']
crt=ctypes.CDLL('ucrtbase.dll');fmaf=crt.fmaf;fmaf.argtypes=[ctypes.c_float]*3;fmaf.restype=ctypes.c_float
val=lambda b:struct.unpack('>f',struct.pack('>I',b))[0]
bits=lambda f:struct.unpack('>I',struct.pack('>f',f))[0]
original_mul=own.mul;original_fma=own.fma;seen=set()
def checked_mul(a,c):
    exact=original_mul(a,c);key=('mul',a,c)
    if key not in seen:assert exact==bits(val(a)*val(c));seen.add(key)
    return exact
def checked_fma(a,c,b):
    exact=original_fma(a,c,b);key=('fma',a,c,b)
    if key not in seen:assert exact==bits(fmaf(val(a),val(c),val(b)));seen.add(key)
    return exact
own.mul=checked_mul;own.fma=checked_fma
before=(OUT/'initial-scratch.bin').read_bytes();steps=0;oprows=0;coverage=Counter()
with (OUT/'native-PS-operations.csv').open('w',newline='') as f:
    writer=csv.DictWriter(f,fieldnames=['case_id','step','va','mnemonic','out_lane','frd','fra_bits','frc_bits','frb_bits','result_bits']);writer.writeheader()
    for case in cases:
        source=Path(case['source_file']).read_bytes();assert sha(source)==case['source_sha256']
        machine=stream.Machine(case['case_id'],source,case['stream_offset'],struct.pack('>12I',*(int(v,16) for v in case['matrix_bits'])),before,int(case['initial_state'],16),int(case['initial_gqr1'],16))
        after=machine.execute()
        assert sha(after)==case['after_sha256'] and after==(OUT/case['after_file']).read_bytes()
        assert machine.end_offset==case['end_offset'] and machine.peek(0x803ae148,4).hex()==case['final_state'] and f'{machine.gqr1:08x}'==case['final_gqr1']
        assert machine.step==case['steps'];steps+=machine.step;oprows+=len(machine.operations);writer.writerows(machine.operations);coverage.update(machine.coverage)
corecases=[json.loads(line) for line in (CORE/'oracle-cases.jsonl').read_text().splitlines()]
for case in corecases:
    for prefix in ('before','after'):assert sha((CORE/case[prefix+'_file']).read_bytes())==case[prefix+'_sha256']
inputs={}
for path in (CORE/'raw-audit.ai.json',CORE/'oracle-summary.ai.json',OUT/'summary.ai.json'):
    report=json.loads(path.read_text());inputs.update(report.get('inputs_sha256',report.get('source_hashes',{})))
for path,digest in inputs.items():assert sha(Path(path).read_bytes())==digest
dol=(CORE.parent/'sa2-disc/main.dol').read_bytes();iso_base=int(json.loads((CORE/'raw-audit.ai.json').read_text())['iso_dol_start'],0)
with (OUT/'original-words-verified.csv').open('w',newline='') as f:
    writer=csv.DictWriter(f,fieldnames=['owner','va','dol_offset','iso_offset','word','mnemonic','instruction','verified']);writer.writeheader()
    for va,row in sorted(stream.WORDS.items()):
        off=int(row['dol_offset'],0);assert int.from_bytes(dol[off:off+4],'big')==int(row['word'],16)
        writer.writerow({**{key:row[key] for key in ('owner','va','dol_offset','word','mnemonic','instruction')},'iso_offset':hex(iso_base+off),'verified':True})
uncovered=[hex(va) for va in sorted(set(stream.WORDS)-{int(v,0) for v in coverage})]
assert uncovered==[hex(v) for v in range(0x8011d278,0x8011d294,4)]
report={'status':'pass','cases_reproduced':len(cases),'original_steps_reproduced':steps,'native_PS_lane_rows':oprows,'distinct_finite_math_cases_CRT_checked':len(seen),'exact_vs_CRT_bit_mismatches':0,'native_call_descriptors_checked':descriptor_checks,'core_case_artifact_pairs_unchanged':len(corecases),'protected_source_paths_rehashed':len(inputs),'verified_original_words':len(stream.WORDS),'unexecuted_success_case_words':uncovered,'unexecuted_reason':'Only op2A-only arm words 8011D278..8011D290. Separate opaque prefix executes through8011D28C but no invented helperbody/return. Supported helper words all execute.','core_cases_manifest_sha256':sha((CORE/'oracle-cases.jsonl').read_bytes()),'stream_cases_manifest_sha256':sha((OUT/'cases.jsonl').read_bytes()),'source_hashes':inputs}
(OUT/'final-audit.ai.json').write_text(json.dumps(report,indent=2))
(OUT/'final-audit.md').write_text('# Stream closure final audit\n\nAll '+str(len(cases))+' successful stream cases reproduce complete scratch, state, GQR1, end offsets and original instruction counts exactly. All '+str(descriptor_checks)+' native helper-call descriptors match independent packet metadata, including additive scratch base, count, input pointer, masked variant and GQR1 carry. Full per-lane original PS operations are retained in native-PS-operations.csv. '+str(oprows)+' rows cover '+str(len(seen))+' distinct arithmetic operand cases; exact-rational results match independent CRT float/FMA bits with zero differences.\n\nAll352 original words are verified again with VA/DOL/ISO mappings in original-words-verified.csv. Successful supported cases execute345; only seven op2A-only words D278..D290 are unexecuted there. The separate unsupported original prefix executes its stateOR2 and opaque call throughD28C; no unsupported body/return is fabricated. All120 ordinary and160 weighted helper words execute across supported cases.\n\nAll314 weighted core before/after artifact pairs still match their original manifest hashes; '+str(len(inputs))+' protected original/frozen/primary-source/own-oracle inputs rehash unchanged. Exact source paths and manifest hashes are retained in JSON. This is a bounded own original-word/CRT arithmetic reference under explicit test bindings, not actual Dolphin/game execution or retail-state recovery.\n')
(OUT/'final-audit.ai.md').write_text('Stream309casesreproducedscratch/state/GQR/end/steps;470nativedescriptorscheckedmetadata/base/count/mode/pointer/GQRcarry;exactcountsJSON. PScompleteCSV/exactrationalvsCRT0bitsdiff. Raw352VADOLISOverified/success345/onlyop2Aarm7unexecuted;opaquePREFIXOR2throughD28Cseparate/noinventedbody-return. Allplain120+weighted160helperwordscovered. Core314artifactpairsunchanged/protectedsourcehashledgerJSON. Explicitbindingownoracle/notDolphin-gameexecution/noenginechange.\n')
print(json.dumps({key:report[key] for key in ('status','cases_reproduced','original_steps_reproduced','native_PS_lane_rows','distinct_finite_math_cases_CRT_checked','native_call_descriptors_checked','core_case_artifact_pairs_unchanged','protected_source_paths_rehashed','verified_original_words','unexecuted_success_case_words')}))
