"""Once-only C-first source/word/control footprint for original vertex dispatcher."""
import ast,csv,hashlib,json,re,struct
from pathlib import Path
OUT=Path(__file__).resolve().parent
ROOT=OUT.parents[1]
assert not (OUT/'inspection.ai.json').exists()
inputs={}
def read(path):
    p=Path(path);b=p.read_bytes();inputs[str(p)]=hashlib.sha256(b).hexdigest();return b
def rows(path):return list(csv.DictReader(read(path).decode('utf-8-sig').splitlines()))
def save(name,values):
    keys=list(dict.fromkeys(k for r in values for k in r)) or ['result']
    with (OUT/name).open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,keys);w.writeheader();w.writerows(values)
decoder=ROOT/'work/full-decompile/audit_odekake_pointer_abi_v1.py'
tree=ast.parse(read(decoder));ns={}
defs=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in ['sign','decode']]
exec(compile(ast.fix_missing_locations(ast.Module(body=defs,type_ignores=[])),str(decoder),'exec'),ns)
decode=ns['decode']
dol=read(ROOT/'work/sa2-disc/main.dol');maps=json.loads(read(ROOT/'work/dol-elf-mapping-final.json'))
assert hashlib.sha256(dol).hexdigest()==maps['dol_sha256']=='a53335308d1f820be236fd2b6342fee850eaf048eb26aac21ddb1903b060db2e'
with (ROOT/'work/sa2.iso').open('rb') as f:
    f.seek(0x420);iso=struct.unpack('>I',f.read(4))[0];f.seek(iso);assert f.read(len(dol))==dol
def off(a):
    m=next(m for m in maps['mappings'] if m['address']<=a<m['address']+m['size']);return m['dol_offset']+a-m['address']
def word(a):return struct.unpack_from('>I',dol,off(a))[0]
def coords(a):return {'va':hex(a),'dol_offset':hex(off(a)),'iso_offset':hex(iso+off(a))}
entries=[0x8011d1d4,0x8011da30,0x8011daf0,0x8011dc98,0x8011dc10]
sources,cfeatures,asm,calls,raw,stores,control,scopes=[],[],[],[],[],[],[],[]
views={}
for view in ['main','main-sda-v1']:
    base=ROOT/'work/full-decompile/gekko'/view/'export'
    cat={int(r['entry'],16):r for r in rows(base/'functions.csv')};ranges=rows(base/'function_body_ranges.csv');graph=rows(base/'direct_calls.csv');views[view]={}
    for e in entries:
        r=cat[e];views[view][e]=[(int(b['range_start'],16),int(b['range_end_exclusive'],16)) for b in ranges if int(b['entry'],16)==e]
        for kind in ['pseudocode','assembly']:
            if not r[kind+'_path']:continue
            path=base/r[kind+'_path'];data=read(path);assert hashlib.sha256(data).hexdigest()==r[kind+'_sha256']
            sources.append({'view':view,'entry':hex(e),'kind':kind,'path':str(path),'sha256':r[kind+'_sha256'],'status':r['status'],**coords(e)})
            if kind=='pseudocode':
                lines=data.decode('utf-8-sig').splitlines()
                for i,line in enumerate(lines):
                    if e==0x8011d1d4 or re.search(r'param_1\[|\*param_1|param_2|return;|FUN_',line):cfeatures.append({'view':view,'entry':hex(e),'line':i+1,'text':line})
            else:
                for a,p,w,text in re.findall(r'^([0-9a-f]{8}) file=(0x[0-9a-f]+) ([0-9a-f]{8}) (.*?) flow=',data.decode(),re.M):
                    a=int(a,16);assert int(p,16)==off(a) and int(w,16)==word(a);asm.append({'view':view,'entry':hex(e),**coords(a),'word':hex(word(a)),'assembly':text})
        for edge in graph:
            if int(edge['caller_entry'],16)==e:
                a=int(edge['call_site'],16);d=decode(word(a),a);calls.append({'view':view,**edge,**coords(a),'word':hex(word(a)),'native_target':hex(d['target']) if 'target' in d else '', 'native_link':d.get('link','')})
for e in entries:
    assert views['main'][e]==views['main-sda-v1'][e]
    for a,b in views['main'][e]:
        scopes.append({'entry':hex(e),'start':hex(a),'end_exclusive':hex(b),'words':(b-a)//4,**coords(a)})
        for va in range(a,b,4):
            w=word(va);d=decode(w,va)
            row={'entry':hex(e),**coords(va),'word':hex(w),'decode':d['decoded'],'opcode':w>>26,'d':(w>>21)&31,'a':(w>>16)&31,'b':(w>>11)&31,'xo':(w>>1)&1023,'imm':ns['sign'](w&65535,16),'GPR_writes_decoded':';'.join(map(str,d['writes']))}
            raw.append(row)
            if w>>26 in [36,37,38,39,44,45,47,52,53,54,55,60,61]:stores.append(row)
            if w>>26 in [16,18,19]:control.append({**row,'native_target':hex(d['target']) if 'target' in d else '', 'native_link':d.get('link','')})
save('source-artifacts.csv',sources);save('C-structural-lines.csv',cfeatures);save('retained-ASM.csv',asm);save('direct-call-references.csv',calls);save('original-words.csv',raw);save('native-store-footprints.csv',stores);save('native-control-footprints.csv',control);save('function-scopes.csv',scopes)
save('input-sha256.csv',[{'path':p,'sha256':d} for p,d in sorted(inputs.items())])
result={'result':'passed','source_artifacts':len(sources),'original_words':len(raw),'retained_ASM_rows_verified':len(asm),'function_scopes':scopes,'graph_rows':len(calls),'store_words':len(stores),'native_execution':False,'project_opens':0,'limit':'2A source retained only to identify unresolved outgoing effects; no2A numerical emulation.'}
(OUT/'inspection.ai.json').write_text(json.dumps(result,indent=2)+'\n');(OUT/'inspection.md').write_text('# Vertex dispatcher source inspection\n\nC-first exact dispatcher and structural helper sources, matching body ranges, original words, complete stores/controls and hashes were retained without project/native execution. Unsupported2A math remains excluded.\n')
print(json.dumps(result,separators=(',',':')))
print(json.dumps({'dispatcher_words':[{k:r[k] for k in ['va','word','decode']} for r in raw if r['entry']=='0x8011d1d4'],'helper_GPRwrites13':[r for r in raw if r['entry'] in ['0x8011da30','0x8011daf0','0x8011dc98'] and '13' in r['GPR_writes_decoded'].split(';')]},separators=(',',':')))
