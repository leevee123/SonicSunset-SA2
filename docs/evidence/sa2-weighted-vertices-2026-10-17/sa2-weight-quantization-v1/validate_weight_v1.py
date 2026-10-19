"""One-run original GQR1 field audit and exhaustive signed16 dequantization oracle."""
import collections
import csv
from fractions import Fraction
import hashlib
import json
import math
import re
import struct
from pathlib import Path

OUT=Path(__file__).resolve().parent
ROOT=OUT.parents[1]
assert not (OUT/'validation.ai.json').exists()
inputs={}


def read(path):
    p=Path(path)
    data=p.read_bytes()
    inputs[str(p)]=hashlib.sha256(data).hexdigest()
    return data


def rows(path):
    return list(csv.DictReader(read(path).decode('utf-8-sig').splitlines()))


def save(name,values):
    keys=list(dict.fromkeys(k for r in values for k in r)) or ['result']
    with (OUT/name).open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,keys)
        w.writeheader()
        w.writerows(values)


def signed(value,bits=16):
    return value-(1<<bits) if value&(1<<(bits-1)) else value


def bits(value):
    return struct.unpack('>I',struct.pack('>f',value))[0]


dol=read(ROOT/'work/sa2-disc/main.dol')
mapping=json.loads(read(ROOT/'work/dol-elf-mapping-final.json'))
assert hashlib.sha256(dol).hexdigest()==mapping['dol_sha256']=='a53335308d1f820be236fd2b6342fee850eaf048eb26aac21ddb1903b060db2e'
with (ROOT/'work/sa2.iso').open('rb') as f:
    f.seek(0x420)
    iso_base=struct.unpack('>I',f.read(4))[0]
    f.seek(iso_base)
    assert f.read(len(dol))==dol


def offset(va):
    m=next(m for m in mapping['mappings'] if m['address']<=va<m['address']+m['size'])
    return m['dol_offset']+va-m['address']


def word(va):
    return struct.unpack_from('>I',dol,offset(va))[0]


def coords(va):
    return {'va':hex(va),'dol_offset':hex(offset(va)),'iso_offset':hex(iso_base+offset(va))}


entry=0x8011dc98
sources,original,asmrows,c_lines,scope_rows=[],[],[],[],[]
scopes={}
for view in ['main','main-sda-v1']:
    base=ROOT/'work/full-decompile/gekko'/view/'export'
    catalog={int(r['entry'],16):r for r in rows(base/'functions.csv')}
    ranges=[r for r in rows(base/'function_body_ranges.csv') if int(r['entry'],16)==entry]
    scopes[view]=[(int(r['range_start'],16),int(r['range_end_exclusive'],16)) for r in ranges]
    scope_rows.extend({'view':view,**r} for r in ranges)
    row=catalog[entry]
    for kind in ['pseudocode','assembly']:
        path=base/row[kind+'_path']
        data=read(path)
        assert hashlib.sha256(data).hexdigest()==row[kind+'_sha256']
        sources.append({'view':view,'entry':hex(entry),'kind':kind,'path':str(path),'sha256':row[kind+'_sha256'],'status':row['status'],**coords(entry)})
        if kind=='assembly':
            for va,pos,value,instruction in re.findall(r'^([0-9a-f]{8}) file=(0x[0-9a-f]+) ([0-9a-f]{8}) (.*?) flow=',data.decode(),re.M):
                va=int(va,16)
                assert int(pos,16)==offset(va) and int(value,16)==word(va)
                asmrows.append({'view':view,**coords(va),'word':hex(word(va)),'instruction':instruction})
        else:
            lines=data.decode('utf-8-sig').splitlines()
            selected={j for i,line in enumerate(lines) if 'ldexpf(0xf8)' in line for j in range(max(0,i-3),min(len(lines),i+13))}
            c_lines.extend({'view':view,'line':i+1,'text':lines[i],'source_sha256':row['pseudocode_sha256']} for i in sorted(selected))
assert scopes['main']==scopes['main-sda-v1']
spr,psq,branches=[],[],[]
for start,end in scopes['main']:
    for va in range(start,end,4):
        w=word(va)
        row={**coords(va),'word':hex(w),'opcode':w>>26,'field21':(w>>21)&31,'field16':(w>>16)&31,'field11':(w>>11)&31,'xo':(w>>1)&1023}
        original.append(row)
        if w>>26==31 and (w>>1)&1023 in [339,467] and not w&1:
            spr.append({**row,'SPR':((w>>16)&31)|(((w>>11)&31)<<5),'access':'read' if (w>>1)&1023==339 else 'write'})
        if w>>26 in [56,57,60,61]:
            psq.append({**row,'FPR':(w>>21)&31,'RA':(w>>16)&31,'W':(w>>15)&1,'I':(w>>12)&7,'signed_displacement12':signed(w&4095,12),'RA_update':w>>26 in [57,61],'load':w>>26 in [56,57]})
        if w>>26 in [16,18]:
            disp=signed(w&(0xfffc if w>>26==16 else 0x3fffffc),16 if w>>26==16 else 26)
            branches.append({**row,'target':hex((disp if w&2 else va+disp)&0xffffffff),'link':bool(w&1)})
assert word(0x8011dca4)==0x38000807 and word(0x8011dca8)==0x64000807 and word(0x8011dcac)==0x7c11e3a6
gqr1=(word(0x8011dca4)&65535)|((word(0x8011dca8)&65535)<<16)
assert gqr1==0x08070807
gqr_fields={'store_type':gqr1&7,'store_scale':(gqr1>>8)&63,'load_type':(gqr1>>16)&7,'load_scale':(gqr1>>24)&63}
gqr1spr=[r for r in spr if r['SPR']==913]
assert len(gqr1spr)==1 and gqr1spr[0]['access']=='write'
weight_loads=[r for r in psq if r['I']==1]
assert weight_loads and all(r['load'] and r['opcode']==57 and r['FPR']==19 and r['RA']==7 and r['W']==1 and r['signed_displacement12']==8 for r in weight_loads)
assert not any(r['link'] for r in branches)
returns=[r for r in original if int(r['word'],16)==0x4e800020]
assert len(returns)==1

# Reuse the previously validated complete main SPR scan; do not rescan the corpus.
prior_scan_path=ROOT/'work/sa2-gqr0-audit-v1/all-GQR-accesses.csv'
prior_gqr1=[r for r in rows(prior_scan_path) if int(r['GQR'])==1]
for r in prior_gqr1:
    assert word(int(r['va'],16))==int(r['word'],16)
save('reused-main-GQR1-accesses.csv',prior_gqr1)

language=ROOT/'work/full-decompile-fp/Sa2GekkoLanguage/data/languages'
spec_path=language/'ppc_gekko_broadway.slaspec'
spec=read(spec_path).decode('utf-8-sig')
assert 'ls[0,3] = I[24,6];' in spec
assert re.search(r'I=\(12,14\)',spec) and re.search(r'W=\(15,15\)',spec) and 'SIMM_PS=(0,11) signed' in spec
assert ':psq_lu fD,dPlusRaAddressPS,W,I' in spec
installed_path=Path('C:/decomp/sonic-adventure-gc/ghidra_12.1.4_PUBLIC/Extensions/Ghidra/GameCubeLoader/data/languages/ppc_gekko_broadway.slaspec')
assert read(installed_path)==spec_path.read_bytes()
sla_path=language/'ppc_gekko_broadway.sla'
read(sla_path)
gekko_path=ROOT/'work/full-decompile-fp/Gekko.pinned.h'
gekko=read(gekko_path).decode()
assert 'QUANTIZE_S16 = 7' in gekko and 'BitField<24, 6, u32> ld_scale;' in gekko
reference_dir=ROOT/'work/sa2-model-setup-v1/dolphin-reference-v2'
manifest=json.loads(read(reference_dir/'manifest.ai.json'))
reference_path=reference_dir/'Interpreter_LoadStorePaired.cpp'
reference=read(reference_path).decode('utf-8-sig')
expected=next(r['sha256'] for r in manifest['files'] if r['name']==reference_path.name)
assert hashlib.sha256(reference_path.read_bytes()).hexdigest()==expected
assert 'LoadAndDequantize<s16>' in reference and 'ps0 = float(T(value)) * m_dequantizeTable[ld_scale];' in reference and 'ps1 = 1.0f;' in reference
table=reference.split('const float m_dequantizeTable[] = {',1)[1].split('};',1)[0]
scale_terms=[x.strip() for x in table.replace('\r','').replace('\n','').split(',') if x.strip()]
assert scale_terms[8]=='1.0 / (1ULL << 8)'
reference_lines=[]
for path,text,patterns in [(spec_path,spec,['I=(12,14)','W=(15,15)','SIMM_PS=(0,11)','ls[0,3] = I[24,6];',':psq_lu','A = EA;']), (gekko_path,gekko,['QUANTIZE_S16 = 7','BitField<0, 3','BitField<8, 6','BitField<16, 3','BitField<24, 6']), (reference_path,reference,['1.0 / (1ULL << 8)','LoadAndDequantize','float(T(value))','ps1 = 1.0f;','LoadAndDequantize<s16>','const u32 EA = ppc_state.gpr[inst.RA]','ppc_state.gpr[inst.RA] = EA;'])]:
    for i,line in enumerate(text.splitlines(),1):
        if any(p in line for p in patterns):
            reference_lines.append({'path':str(path),'line':i,'text':line,'source_sha256':inputs[str(path)]})

# Exact rational bit construction is independent of the host float conversion used for comparison.
oracle=[]
for raw in range(65536):
    n=signed(raw)
    a=abs(n)
    if a:
        highest=a.bit_length()-1
        expected_bits=((1<<31) if n<0 else 0)|((highest-8+127)<<23)|((a<<(23-highest))&0x7fffff)
    else:
        expected_bits=0
    host_bits=bits(float(n)*float(2**-8))
    assert host_bits==expected_bits
    value=struct.unpack('>f',struct.pack('>I',expected_bits))[0]
    exact=Fraction(n,256)
    assert Fraction.from_float(value)==exact and math.isfinite(value)
    exponent=(expected_bits>>23)&255
    assert exponent not in [255] and (a==0 or exponent!=0)
    oracle.append({'raw_u16':hex(raw),'signed_s16':n,'exact_numerator':exact.numerator,'exact_denominator':exact.denominator,'value_decimal':repr(value),'PS0_f32_bits':hex(expected_bits),'PS1_f32_bits':'0x3f800000','classification':'positive_zero' if not a else 'normal','exact_without_rounding':True,'host_f32_bits_match':True,'signed_zero':'positive' if not a else ''})
examples=[oracle[v] for v in [0x8000,0x8001,0xffff,0,1,255,256,32767]]
assert bits(2**-8)==0x3b800000 and oracle[0]['PS0_f32_bits']=='0x0'
assert not any(int(r['PS0_f32_bits'],16)==0x80000000 for r in oracle)

sample_path=ROOT/'work/sa2-disc/sonicmdl.prs.decoded'
sample=read(sample_path)
assert hashlib.sha256(sample).hexdigest()=='b7ea586ed0fa22330dc8a2cfe2bb8fa9ce4ac70d9561764f35af4ced5d371963'
record_path=ROOT/'work/sa2-payload-consumers/first-stream-sample-records.csv'
sample_rows=[]
for r in rows(record_path):
    if int(r['opcode'],16)!=0x2c:
        continue
    p=int(r['record_decoded_offset'],16)
    assert sample[p:p+28].hex()==r['raw_record']
    raw=struct.unpack_from('>H',sample,p+24)[0]
    assert signed(raw)==int(r['signed_weight_word24'])
    sample_rows.append({'record_offset':hex(p),'weight_offset':hex(p+24),'destination_offset':hex(p+26),'weight_raw':hex(raw),'weight_s16':signed(raw),'exact_weight_f32_bits':oracle[raw]['PS0_f32_bits'],'raw_28_bytes':sample[p:p+28].hex()})
save('source-artifacts.csv',sources)
save('function-scopes.csv',scope_rows)
save('original-words.csv',original)
save('retained-assembly.csv',asmrows)
save('SPR-accesses-in-helper.csv',spr)
save('PSQ-fields-in-helper.csv',psq)
save('GQR1-weight-load-sites.csv',weight_loads)
save('branches-in-helper.csv',branches)
save('generated-C-weight-excerpts.csv',c_lines)
save('primary-and-language-source-lines.csv',reference_lines)
save('all-s16-weight-f32-oracle.csv',oracle)
save('weight-endpoints.csv',examples)
save('real-Sonic-weight-records.csv',sample_rows)
read(Path(__file__))
save('input-sha256.csv',[{'path':p,'sha256':digest} for p,digest in sorted(inputs.items())])
result={'result':'passed','function':coords(entry),'body_ranges':[[hex(a),hex(b)] for a,b in scopes['main']],'original_words':len(original),'retained_ASM_rows_verified':len(asmrows),'source_artifacts':len(sources),'GQR1_value':hex(gqr1),'GQR1_fields':gqr_fields,'GQR1_explicit_reads_in_helper':0,'GQR1_explicit_writes_in_helper':1,'GQR1_restore_before_normal_return':False,'normal_return':returns[0]['va'],'direct_calls_in_helper':0,'weight_load_sites':weight_loads,'all_s16_weights':len(oracle),'normal_values':sum(r['classification']=='normal' for r in oracle),'positive_zeros':sum(r['classification']=='positive_zero' for r in oracle),'negative_zeros':0,'subnormals':0,'nonfinite':0,'rounding_mismatches':0,'weight_scale_f32_bits':hex(bits(2**-8)),'PS1_f32_bits':'0x3f800000','examples':examples,'real_Sonic_weight_records':len(sample_rows),'real_Sonic_signed_weight_range':[min(r['weight_s16'] for r in sample_rows),max(r['weight_s16'] for r in sample_rows)],'pinned_reference_commit':manifest['commit'],'pinned_loadstore_reference_sha256':expected,'SLEIGH_scale_loss':{'intended_load_scale':8,'retained_bits':3,'truncated_scale':8&7,'source_sha256':inputs[str(spec_path)],'compiled_SLA_sha256':inputs[str(sla_path)],'changed':False},'reused_main_GQR1_sites':len(prior_gqr1),'host_contract':{'GQR0':'explicit0forotherfloatloads/stores;notneededforintegerweightconversion','GQR1':'originalhelperwrites08070807;hostconversionexactlymatches','RN':'nearestforwholemathfragment;weightconversionitselfexact','NI':0,'trapping':'disabled/nontrappingdeclaredhostcontract','finite':'allintegerweightsconvertfinite;otherconsumedvalues/retainedresultsgovernedbyseparatefinitepolicy'},'live_GQR0_proven':False,'native_execution':False,'project_opens':0,'engine_changes':[],'source_selection_limits':['Initial referenced source-manifest.json did not exist; correct pinned manifest.ai.json reused.','Expanded C excerpts were oversized/truncated; compact CSV source excerpts and full original words retained.']}
(OUT/'validation.ai.json').write_text(json.dumps(result,indent=2)+'\n')
(OUT/'validation.md').write_text('# GQR1 weight conversion validation\n\nOne run passed: all65,536 signed16 words map exactly to n/256 as binary32, with65,535 normal values and one positive zero, no negative zero, subnormal, nonfinite or rounding mismatch. Original helper source/words and PSQ fields are verified; the helper writes GQR1 once and does not save/restore it before its normal return. This is an explicit math contract, not observed live GQR0 or complete weighted transformation. Full per-input bits and source addresses/digests remain in CSV/AI twin.\n')
print(json.dumps({k:result[k] for k in ['result','original_words','retained_ASM_rows_verified','GQR1_value','GQR1_fields','GQR1_restore_before_normal_return','weight_load_sites','all_s16_weights','normal_values','positive_zeros','negative_zeros','subnormals','rounding_mismatches','examples','real_Sonic_weight_records','real_Sonic_signed_weight_range']},separators=(',',':')))
