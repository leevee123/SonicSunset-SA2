from pathlib import Path
import csv,ctypes,hashlib,json,struct

OUT=Path(__file__).resolve().parent
crt=ctypes.CDLL('ucrtbase.dll');fmaf=crt.fmaf;fmaf.argtypes=[ctypes.c_float]*3;fmaf.restype=ctypes.c_float
value=lambda b:struct.unpack('>f',struct.pack('>I',b))[0]
bits=lambda v:struct.unpack('>I',struct.pack('>f',v))[0]
assert bits(fmaf(1+2**-23,1-2**-23,-1))==0xa8800000
assert bits(fmaf(2**-126,.5,0))==0x00400000
seen=set();rows=0
with (OUT/'oracle-PS-operations.csv').open(newline='') as f:
    for row in csv.DictReader(f):
        rows+=1;key=(row['mnemonic'],row['fra_bits'],row['frc_bits'],row['frb_bits'])
        if key in seen:continue
        seen.add(key);a,c=int(row['fra_bits'],16),int(row['frc_bits'],16)
        expected=bits(value(a)*value(c)) if row['mnemonic'].startswith('ps_muls') else bits(fmaf(value(a),value(c),value(int(row['frb_bits'],16))))
        assert int(row['result_bits'],16)==expected,(row,hex(expected))
cases={r['case_id']:r for r in (json.loads(line) for line in (OUT/'oracle-cases.jsonl').read_text().splitlines())}
def slot(name):
    row=cases['synthetic_'+name];data=(OUT/row['after_file']).read_bytes();offset=(row['start']+row['destinations'][0])*32
    return list(struct.unpack_from('>6I',data,offset))
zero=slot('zero_weight_FTZ_and_zero_sign');assert zero==[0,0x80000000,0,0,0x80000000,0]
assert slot('accum_fused_weight')[0]==0xb0000000
assert slot('transform_fused_before_weight')[0]==0xa8000000
ordered={}
for mode in (1,2):
    forward=slot(f'ordered_mode{mode}_reverse0')[0];reverse=slot(f'ordered_mode{mode}_reverse1')[0]
    assert (forward,reverse)==(0,0x3f800000)
    ordered[str(mode)]={'forward_bits':f'{forward:08x}','reverse_bits':f'{reverse:08x}'}
for mode in (0,1,2,127):
    assert cases[f'synthetic_mode{mode}_weight255']['after_sha256']==cases[f'synthetic_mode{1 if mode else 0}_weight255']['after_sha256']
inputs=json.loads((OUT/'raw-audit.ai.json').read_text())['inputs_sha256'];inputs.update(json.loads((OUT/'oracle-summary.ai.json').read_text())['source_hashes'])
for path,digest in inputs.items():assert hashlib.sha256(Path(path).read_bytes()).hexdigest()==digest
report={'status':'pass','PS_lane_rows':rows,'distinct_op_operand_cases_CRT_checked':len(seen),'exact_vs_CRT_mismatches':0,'zero_weight_FTZ_words':[f'{v:08x}' for v in zero],'weighted_fused_cancellation_word':'b0000000','transform_then_weight_fused_word':'a8000000','ordered_duplicate_examples':ordered,'nonzero_modes_1_2_127_equal':True,'unchanged_source_paths':len(inputs),'note':'CRT independent arithmetic cross-check only; primary oracle is exact rational original-word execution, not Dolphin/hardware'}
(OUT/'crosscheck.ai.json').write_text(json.dumps(report,indent=2))
(OUT/'crosscheck.md').write_text('# Independent weighted cross-check\n\nAll '+str(rows)+' per-lane arithmetic rows reduce to '+str(len(seen))+' distinct operation/operand cases. Every exact-rational result bit matches independent CRT fused float arithmetic or an exact binary64 product rounded to float. No differences were found. Original/frozen/primary-source inputs at '+str(len(inputs))+' paths rehash unchanged.\n\nWeighted fused cancellation is B0000000, while separately rounded weighted multiplication plus the old value would be zero. Transform-before-weight fused cancellation is A8000000. Zero-weight accumulation still performs final FTZ and signed-zero behavior: 00000000/80000000/00000000/00000000/80000000/00000000. Duplicate-destination order examples produce zero forward and one reversed in modes1 and2; nonzero modes1,2,127 agree for identical inputs. No weight-zero shortcut, normalization or reordered reduction was substituted. Full values and traces remain in the oracle artifacts.\n')
(OUT/'crosscheck.ai.md').write_text('CoreweightedexactrationalvsCRT0bitdifferences;row/unique/inputhashcountsJSON. FusedweightcancelB0000000vsseparateroundzero;transformbeforeweightA8000000. ZeroweightstillFTZ/signzero[0,80000000,0,0,80000000,0]. Duplicatedestforward0/reverse1 modes1/2;nonzeromodes1/2/127same. Noengine/Dolphin/gameexecution.\n')
print(json.dumps(report))
