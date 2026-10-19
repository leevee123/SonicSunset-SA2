from pathlib import Path
import csv,hashlib,json,os,subprocess

out=Path(__file__).resolve().parent
work=out.parent
sha=lambda b:hashlib.sha256(b).hexdigest()
entries={0x8011d1d4,0x8011da30,0x8011daf0}
sources=[];ranges=[]
for view in ('main','main-sda-v1'):
    folder=work/'full-decompile/gekko'/view/'export'
    with (folder/'functions.csv').open(newline='',encoding='utf-8-sig') as f:
        functions={int(r['entry'],16):r for r in csv.DictReader(f)}
    for entry in sorted(entries):
        row=functions[entry]
        for kind in ('pseudocode','assembly'):
            if not row[kind+'_path']:continue
            path=folder/row[kind+'_path']
            assert sha(path.read_bytes())==row[kind+'_sha256']
            sources.append({'view':view,'entry':row['entry'],'dol_file_offset':row['canonical_file_offset'],'kind':kind,'path':str(path),'sha256':sha(path.read_bytes()),'status':row['status']})
    if view=='main':
        with (folder/'function_body_ranges.csv').open(newline='',encoding='utf-8-sig') as f:
            for row in csv.DictReader(f):
                if int(row['entry'],16) in entries:ranges.append({'owner':row['entry'],'start':row['range_start'],'end_exclusive':row['range_end_exclusive']})
for name,rows,delimiter in (('source-artifacts.csv',sources,','),('function-ranges.tsv',ranges,'\t')):
    with (out/name).open('w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=list(rows[0]),delimiter=delimiter);writer.writeheader();writer.writerows(rows)
java=Path('C:/decomp/sonic-adventure-gc/jdk-21.0.12.1+1/bin/java.exe')
ghidra=Path('C:/decomp/sonic-adventure-gc/ghidra_12.1.4_PUBLIC')
classes=work/'sonicmdl-loader/classes'
language=work/'full-decompile-fp/Sa2GekkoLanguage'
protected={str(p):sha(p.read_bytes()) for p in (classes/'DumpSonicLoader.class',work/'sonicmdl-loader/DumpSonicLoader.java')}
protected.update({str(p):sha(p.read_bytes()) for p in language.rglob('*') if p.is_file()})
dol=work/'sa2-disc/main.dol'
original_sha=sha(dol.read_bytes())
assert original_sha=='a53335308d1f820be236fd2b6342fee850eaf048eb26aac21ddb1903b060db2e'
runtime=out/'runtime'
for name in ('home','settings','cache','tmp'):(runtime/name).mkdir(parents=True,exist_ok=False)
jars=sorted(ghidra.rglob('*.jar'))
assert java.exists() and jars and (classes/'DumpSonicLoader.class').exists()
args=['-Djava.system.class.loader=ghidra.GhidraClassLoader','-Djava.awt.headless=true','-Dghidra.external.modules='+str(language),'-Duser.home='+str(runtime/'home'),'-Dapplication.settingsdir='+str(runtime/'settings'),'-Dapplication.cachedir='+str(runtime/'cache'),'-Djava.io.tmpdir='+str(runtime/'tmp'),'-cp',os.pathsep.join([str(classes)]+[str(p) for p in jars]),'ghidra.Ghidra','DumpSonicLoader',str(dol),str(out/'function-ranges.tsv'),str(out/'parsed-original-words.csv')]
argfile=out/'java-arguments.txt'
argfile.write_text('\n'.join('"'+arg.replace('\\','\\\\').replace('"','\\"')+'"' for arg in args)+'\n')
with (out/'parser.raw.log').open('wb') as log:
    run=subprocess.run([str(java),'@'+str(argfile)],stdout=log,stderr=subprocess.STDOUT,timeout=120)
assert sha(dol.read_bytes())==original_sha
assert all(sha(Path(path).read_bytes())==digest for path,digest in protected.items())
report={'status':'parsed' if run.returncode==0 else 'parser_failed','parser_exit':run.returncode,'entries':[hex(i) for i in sorted(entries)],'source_artifacts':len(sources),'ranges':ranges,'dol_path':str(dol),'dol_sha256':original_sha,'protected_before_after':protected,'parser':'existing project-free DumpSonicLoader language parser only; no ProgramDB/project/native game','private_runtime':str(runtime),'raw_log_sha256':sha((out/'parser.raw.log').read_bytes())}
if run.returncode==0:
    with (out/'parsed-original-words.csv').open(newline='') as f:rows=list(csv.DictReader(f))
    report['parsed_words']=len(rows)
(out/'preparation.ai.json').write_text(json.dumps(report,indent=2))
(out/'preparation.md').write_text(f'# Vertex-helper original-word preparation\n\nSelected three original functions and {len(sources)} frozen artifacts. The existing project-free language parser exited {run.returncode}. Original DOL and protected helper/language bytes are unchanged. No ProgramDB, project, native game, engine or repository write was used. Full paths, hashes and ranges are retained in the compact JSON and complete CSV.\n')
print(json.dumps({k:report[k] for k in ('status','parser_exit','source_artifacts','ranges','parsed_words') if k in report}))
if run.returncode:print((out/'parser.raw.log').read_text(errors='replace')[-2400:])
raise SystemExit(run.returncode)
