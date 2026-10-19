from pathlib import Path
import csv,hashlib,json,re,struct
from collections import Counter

OUT=Path(__file__).resolve().parent
WORK=OUT.parent
sha=lambda b:hashlib.sha256(b).hexdigest()
entries={0x8011d1d4,0x8011dc98}
dolpath=WORK/'sa2-disc/main.dol';dol=dolpath.read_bytes()
assert sha(dol)=='a53335308d1f820be236fd2b6342fee850eaf048eb26aac21ddb1903b060db2e'
with (WORK/'sa2.iso').open('rb') as iso:
    iso.seek(0x420);iso_dol_start=int.from_bytes(iso.read(4),'big')
    iso.seek(iso_dol_start);assert sha(iso.read(len(dol)))==sha(dol)
sources=[];parsed=[];features=[]
for view in ('main','main-sda-v1'):
    folder=WORK/'full-decompile/gekko'/view/'export'
    with (folder/'functions.csv').open(newline='',encoding='utf-8-sig') as f:table={int(r['entry'],16):r for r in csv.DictReader(f)}
    for entry in sorted(entries):
        row=table[entry]
        for kind in ('pseudocode','assembly'):
            if not row[kind+'_path']:continue
            path=folder/row[kind+'_path'];raw=path.read_bytes();assert sha(raw)==row[kind+'_sha256']
            sources.append({'view':view,'entry':hex(entry),'kind':kind,'path':str(path),'sha256':sha(raw)})
            if kind=='pseudocode':
                for number,line in enumerate(raw.decode().splitlines(),1):
                    if any(s in line for s in ('param_3','while (','ldexpf','GQR','dVar29 =','dVar30 =','dVar31 =','dVar34 =','dVar35 =','dVar36 =')):
                        features.append({'view':view,'entry':hex(entry),'line':number,'text':line.strip()})
            if kind=='assembly' and view=='main':
                for line in raw.decode().splitlines():
                    match=re.match(r'^([0-9a-fA-F]{8}) file=(0x[0-9a-fA-F]+) ([0-9a-fA-F]{8}) (.*?) flow=',line)
                    if not match:continue
                    va,off,word=int(match[1],16),int(match[2],0),int(match[3],16)
                    assert int.from_bytes(dol[off:off+4],'big')==word
                    sectionmatches=[]
                    for section in range(7):
                        base=struct.unpack_from('>I',dol,0x48+section*4)[0];size=struct.unpack_from('>I',dol,0x90+section*4)[0]
                        if base<=va<base+size:sectionmatches.append(struct.unpack_from('>I',dol,section*4)[0]+va-base)
                    assert sectionmatches==[off]
                    instruction=match[4];parsed.append({'owner':hex(entry),'va':hex(va),'dol_offset':hex(off),'iso_offset':hex(iso_dol_start+off),'word':f'{word:08x}','mnemonic':instruction.split()[0],'instruction':instruction})
helper=[r for r in parsed if int(r['owner'],0)==0x8011dc98]
assert {int(r['va'],0) for r in helper}==set(range(0x8011dc98,0x8011df18,4))
psq=[];ps=[];matrix=[]
for row in helper:
    w=int(row['word'],16);op=w>>26
    if op in (56,57,60,61):
        d,a=w>>21&31,w>>16&31;displacement=(w&0xfff)-(0x1000 if w&0x800 else 0)
        role='matrix' if a==4 and int(row['va'],0)<0x8011dd80 else 'input' if a==7 else 'scratch'
        item=dict(**row,register=d,base=a,displacement=displacement,W=w>>15&1,I=w>>12&7,role=role,updates=op in (57,61))
        psq.append(item)
        if role=='matrix':matrix.append(item)
    if op==4:ps.append(dict(**row,frd=w>>21&31,fra=w>>16&31,frb=w>>11&31,frc=w>>6&31,XO5=w>>1&31,Rc=w&1))
def write(name,rows):
    with (OUT/name).open('w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
write('source-artifacts.csv',sources);write('frozen-C-selected-features.csv',features);write('original-words.csv',parsed);write('PSQ-fields.csv',psq);write('PS-fields.csv',ps);write('matrix-load-order.csv',matrix)
gqr1=0x807|(0x807<<16)
inputs={str(dolpath):sha(dol)}
for source in sources:inputs[source['path']]=source['sha256']
for path in (WORK/'dolphin-reference/Interpreter_FPUtils.h',WORK/'sa2-model-setup-v1/dolphin-reference-v2/Interpreter_Paired.cpp',WORK/'sa2-model-setup-v1/dolphin-reference-v2/Interpreter_LoadStorePaired.cpp',WORK/'sa2-model-transform-v1/vertex_oracle_v1.py'):
    inputs[str(path)]=sha(path.read_bytes())
summary={'entry':'0x8011dc98','dol_offset':'0x11ac98','iso_offset':hex(iso_dol_start+0x11ac98),'iso_dol_start':hex(iso_dol_start),'verified_words':len(parsed),'helper_words':len(helper),'source_artifacts':len(sources),'matrix_loads':len(matrix),'helper_mnemonics':dict(Counter(r['mnemonic'] for r in helper)),'GQR1_written':hex(gqr1),'GQR1_load_type':gqr1>>16&7,'GQR1_load_scale':gqr1>>24&63,'signed_weight_nominal_min':-32768/256,'signed_weight_nominal_max':32767/256,'modes':'zero overwrite, any nonzero accumulation; dispatcher passes 7-bit variant','lookahead':'All modes N+1 scalar triples; zero mode N+1 full records; nonzero N1 has only N weight/dest, nonzero N>=2 has N+1 weight/dest','inputs_sha256':inputs}
(OUT/'raw-audit.ai.json').write_text(json.dumps(summary,indent=2))
(OUT/'raw-audit.md').write_text('''# Original weighted vertex helper

The original entry is **8011DC98**, DOL **11AC98**, ISO **13??** (exact ISO offset is recorded in CSV/JSON). Original retained assembly words are checked against the original DOL and DOL text-section mapping, and the ISO DOL slice hashes identically. No project or ProgramDB was opened. Frozen generated C was inspected first; its quantization expressions are not trusted because the known SLEIGH load-scale field truncates six bits to three.

The r3 descriptor supplies scratch base at +0, input pointer +4, count +8 (`DC98/D C9C/DCA0`; complete VAs in CSV). Dispatcher scratch base already includes info low16*32. For each 28-byte record, six input binary32 values are at +0..20 under explicit GQR0=0; signed weight is BE s16 at +24; BE u16 destination is +26. Destination address is descriptor[0]+32*destination. There is no descriptor writeback.

`DCA4/DCA8/DCAC` writes GQR1=08070807; load type=7 signed16 and load scale=8, so weight q=s16/256 exactly. It is **not restored on return**. This does not recover live GQR0/FPSCR or prove caller state. Negative weights and magnitudes above one are preserved by the source arithmetic, not clamped or normalized.

Matrix loads use the same three 3-word columns and 3-word translation as the earlier helpers, with all byte offsets and GQR0 W bits retained. Under GQR0=0, let columns A=(m0,m1,m2), B=(m3,m4,m5), C=(m6,m7,m8), T=(m9,m10,m11). First triple P_i=FMA(C_i,z,FMA(B_i,y,FMA(A_i,x,T_i))). Second triple Q_i=FMA(C_i,w,FMA(B_i,v,MUL(A_i,u))). Each MUL/FMA rounds once to binary32; translation is in the first fused x step. Initial arithmetic is at DCFC/DD04, DD2C/DD30, DD4C/DD50 (P), DD0C/DD14, DD38/DD40, DD54/DD58 (Q); corresponding nonzero-path final steps are DE08/DE10/DE18/DE20.

Variant is tested **only for zero** at DD44/DD48. Mode zero stores rounded MUL(P_i,q), MUL(Q_i,q), at DD60/DD64/DD6C/DD70 and corresponding loop operations. Every nonzero variant stores **FMA(P_i,q,old_i)** and **FMA(Q_i,q,old_i)**, at DE28/DE2C/DE34/DE38 and DEAC/DEB0/DEB8/DEBC. It does not separately round the weighted term before accumulation.

The four PSQ stores always target destination+0/W0, +8/W1, +12/W0, +20/W1; under GQR0=0 they update the first 24 bytes and preserve +24..31. PSQ float stores apply unconditional signed-zero FTZ for subnormal results, including NI=0. Intermediate PS arithmetic retains subnormals at NI=0. Accumulation reads those previously stored/FTZ values using the same four offsets.

First accumulation old values load DE04/DE0C/DE14/DE1C before its result. Loop previous-record stores DE58/DE60/DE68/DE70 happen **before** current-record old loads DE88/DE90/DE98/DEA0. Thus repeated destinations accumulate sequentially through the FTZ store boundary. The zero mode does not read old scratch values. Source/scratch/descriptor/stack aliases can change native behavior and are outside the independent disjoint-memory contract.

Both modes load the next record's six scalar words before count-1 tests. Mode zero always loads the next weight/destination too. Nonzero mode count1 branches at DE40 before DE44/DE48, so only the next six scalars are read; nonzero N>=2 loads N+1 full records through its loop. Count zero sets CTR=FFFFFFFF and enters an unsafe huge loop, with modulo-32-bit pointers and possible aliases/faults; there is no native zero guard. Ten scalar stfd/lfd pairs save/restore f14..f23 PS0 around a 128-byte frame; PS1 preservation is not inferred. GQR1, volatile GPR/FPR and FPSCR side effects are not represented by a CPU-only host API.

Complete raw words, PS operand fields, PSQ W/I/displacement/update fields, matrix load order, frozen-C feature lines, all source hashes and actual VA/DOL/ISO mappings are retained. No engine, repository, original game, frozen project, language or helper file was edited.
'''.replace('ISO **13??**','ISO **'+summary['iso_offset']+'**').replace('DC98/D C9C/DCA0','DC98/DC9C/DCA0'))
(OUT/'raw-audit.ai.md').write_text('OriginalDC98/DOL11AC98/ISOinJSON+rawCSV;retainedASMword/DOL/textsection/ISOsliceverified/noDB. Descriptor0base(includesinfoStart*32)/4input/8count;stride28,weightS16+24,destU16+26;dest=base+dest*32. GQR1write08070807/type7/scale8=qS16/256exact/notrestored;SLEIGH6to3scaleCuntrusted. ConditionalGQR0=0 P=FMA(C,z,FMA(B,y,FMA(A,x,T)));Q=FMA(C,w,FMA(B,v,MUL(A,u))). Mode0roundedMUL(PQ,q),ANYnonzeroFMA(PQ,q,old). Stores0W0/8W1/12W0/20W1 preserve24..31;finalPSQFTZ,intermediateNI0retains. OldfirstDE04/C/14/1C;loopstoresDE58/60/68/70BEFOREoldreadsDE88/90/98/A0;duplicatesorderedFTZfeedback. AllN+1scalars;mode0N+1full;nonzeroN1onlyNweightdest;nonzeroN>=2N+1full. Count0CTRFFFFFFFFunsafe/nozeroguard. Descriptorunchanged;alias/liveFP/GQR0/axes/runtime/ABIunknown. Completesourcehashes+PSfields+matrixorderCSV/noengineedits.\n')
print(json.dumps({k:summary[k] for k in ('entry','dol_offset','iso_offset','verified_words','helper_words','source_artifacts','matrix_loads','GQR1_written','GQR1_load_type','GQR1_load_scale','modes')}))
