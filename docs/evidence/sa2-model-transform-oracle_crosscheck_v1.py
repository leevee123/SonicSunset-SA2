from pathlib import Path
import csv,ctypes,hashlib,importlib.util,json,struct

OUT=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('original_vertex_oracle',OUT/'vertex_oracle_v1.py')
oracle=importlib.util.module_from_spec(spec);spec.loader.exec_module(oracle)
crt=ctypes.CDLL('ucrtbase.dll');fmaf=crt.fmaf
fmaf.argtypes=[ctypes.c_float]*3;fmaf.restype=ctypes.c_float
bits=lambda v:struct.unpack('>I',struct.pack('>f',v))[0]
value=lambda b:struct.unpack('>f',struct.pack('>I',b))[0]
assert bits(fmaf(1+2**-23,1-2**-23,-1))==0xa8800000
assert bits(fmaf(2**-126,.5,0))==0x00400000
checks={
    'mul_negative_zero':(oracle.mul(0x80000000,0x3f800000),0x80000000),
    'mul_double_negative_zero':(oracle.mul(0x80000000,0xbf800000),0),
    'fma_both_negative_zero':(oracle.fma(0x80000000,0x3f800000,0x80000000),0x80000000),
    'fma_opposite_zero_a':(oracle.fma(0x80000000,0x3f800000,0),0),
    'fma_opposite_zero_b':(oracle.fma(0,0x3f800000,0x80000000),0),
    'fma_negative_product_zero':(oracle.fma(0,0xbf800000,0x80000000),0x80000000),
    'fma_exact_cancellation':(oracle.fma(0x3f800000,0x3f800000,0xbf800000),0),
    'fma_positive_half_min_subnormal':(oracle.fma(1,0x3f000000,0),0),
    'fma_negative_half_min_subnormal':(oracle.fma(0x80000001,0x3f000000,0x80000000),0x80000000),
    'fma_normal_boundary':(oracle.fma(0x007fffff,0x3f800000,1),0x00800000),
    'mul_subnormal_intermediate':(oracle.mul(0x00800000,0x3f000000),0x00400000),
    'negative_subnormal_final_store':(oracle.ftz(0x80000001),0x80000000),
}
assert all(got==want for got,want in checks.values())
seen=set();mismatches=[];rows=0
with (OUT/'oracle-ps-operations.csv').open(newline='') as f:
    for row in csv.DictReader(f):
        rows+=1
        key=(row['mnemonic'],row['fra_bits'],row['frc_bits'],row['frb_bits'])
        if key in seen:continue
        seen.add(key)
        a,c=int(row['fra_bits'],16),int(row['frc_bits'],16)
        actual=int(row['result_bits'],16)
        expected=bits(value(a)*value(c)) if row['mnemonic']=='ps_muls1' else bits(fmaf(value(a),value(c),value(int(row['frb_bits'],16))))
        if actual!=expected:mismatches.append({'va':row['va'],'key':key,'exact_oracle_bits':f'{actual:08x}','CRT_bits':f'{expected:08x}'})
assert not mismatches,mismatches[:2]
with (OUT/'oracle-output-slots.csv').open(newline='') as f:slots=list(csv.DictReader(f))
synthetic_firsts={row['case_id']:row for row in slots if row['case_id'].startswith('synthetic_') and int(row['record_ordinal'])==0}
for name,row in synthetic_firsts.items():
    after=bytes.fromhex(row['after_hex'])
    if name.endswith('fused_cancellation'):assert after[:4].hex()=='a8800000'
    if name.endswith('signed_subnormal'):assert after[:4].hex()=='80000000'
original_inputs=json.loads((OUT/'raw-audit.ai.json').read_text())['inputs_sha256']
original_inputs.update(json.loads((OUT/'oracle-summary.ai.json').read_text())['source_sha256'])
for path,digest in original_inputs.items():assert hashlib.sha256(Path(path).read_bytes()).hexdigest()==digest
discarded_overflow=[]
matrix=[0]*12
for opcode in (0x23,0x29):
    words=[0x7f7fffff,0x7f7fffff,0x7f7fffff]+([0x12345678] if opcode==0x23 else [0,0,0])
    stride=16 if opcode==0x23 else 24
    raw=struct.pack('>'+str(len(words))+'I',*words)+bytes(stride)
    machine=oracle.Machine('discarded_lane_overflow',opcode,1,0,raw,0,bytes(48),bytes(64))
    try:machine.execute();raise AssertionError('expected conservative overflow rejection')
    except oracle.Unsupported as error:discarded_overflow.append({'opcode':hex(opcode),'pc':hex(machine.pc),'reason':str(error),'explanation':'The all-zero stored coefficients would yield finite stored components, but forced-one discarded lanes sum maximum finite source components and overflow. This oracle conservatively rejects all-lane overflow; engine retained-lane contract is narrower.'})
report={'status':'pass','per_lane_operation_rows':rows,'distinct_operation_operand_cases_CRT_checked':len(seen),'exact_oracle_vs_CRT_bit_mismatches':mismatches,'targeted_exact_zero_subnormal_checks':{name:{'actual':f'{got:08x}','expected':f'{want:08x}'} for name,(got,want) in checks.items()},'synthetic_first_output_words':{name:row['after_hex'][:8] for name,row in synthetic_firsts.items()},'input_paths_rehashed_unchanged':len(original_inputs),'discarded_lane_overflow_counterexamples':discarded_overflow,'CRT_note':'Independent arithmetic cross-check, not hardware/Dolphin execution; nearest rounding and subnormal sanity passed; oracle primary remains exact rational.'}
(OUT/'oracle-crosscheck.ai.json').write_text(json.dumps(report,indent=2))
(OUT/'oracle-crosscheck.md').write_text('# Vertex arithmetic cross-check\n\nAll '+str(rows)+' per-lane operation rows reduce to '+str(len(seen))+' distinct operation/operand cases. Exact-rational oracle result bits matched independent Windows CRT fmaf or exactly representable binary64 product followed by float conversion with zero differences, including signed zeros. Twelve targeted signed-zero/subnormal/boundary assertions passed; synthetic cancellation stores A8800000 and signed-subnormal stores 80000000 as expected. All '+str(len(original_inputs))+' original/frozen/primary-source input paths were rehashed unchanged.\n\nThe oracle deliberately rejects overflow in either paired lane. Two separate maximum-finite source/all-zero-matrix counterexamples show an unused forced-one lane can overflow while all three retained components would be finite. These are conservatively unsupported by this oracle and are not part of its 219 successful cases; they do not show an error in a host API whose contract checks only retained-lane intermediates. Exact PCs/reasons are retained in JSON. No engine implementation or native game was executed.\n')
(OUT/'oracle-crosscheck.ai.md').write_text('ExactrationalvsCRTallretainedoperationrowsbitmatch0errors;exactcountsJSON. Targeted12signedzero/subnormalboundaryassertionsPASS/cancellationA8800000/finalnegativeFTZ80000000. Allinputhashesunchanged. Conservativeoracleall-lanefinitevsengineonlyretainedlanecontractdistinguished:all-zeroM/maxfiniteXYZoverflowsforced-oneunusedlaneatDA88/DB60whilekeptoutputsfinite;2explicitunsupportedcounterexamplesJSON/not219successcases. OwnscratchnotDolphin/hardwareexecution/noenginecopy.\n')
print(json.dumps({key:report[key] for key in ('status','per_lane_operation_rows','distinct_operation_operand_cases_CRT_checked','input_paths_rehashed_unchanged','synthetic_first_output_words','discarded_lane_overflow_counterexamples')}))
