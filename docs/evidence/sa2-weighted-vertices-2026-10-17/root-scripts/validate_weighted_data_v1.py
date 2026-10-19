from pathlib import Path
import csv
import hashlib
import json
import struct
import subprocess

work=Path(__file__).resolve().parent
stage=work/'weighted-stage'
oracle=work/'sa2-weighted-transform-v1'
out=stage/'comparison-v1'
out.mkdir(exist_ok=False)
sha=lambda b:hashlib.sha256(b).hexdigest()
report={'status':'FAIL','scope':'Weighted memory/metadata under explicit GQR0=0/RNnearest/NI0/nontrapping/finite-retained-lane contract. Supplied matrices/initial caches are tests, not live state.'}
rows=[]
try:
    compiled=json.loads((stage/'compile-v2.ai.json').read_text())
    assert compiled['status']=='PASS'
    assert all(sha(Path(p).read_bytes())==digest for p,digest in compiled['source_sha256'].items())
    exe=stage/'weighted_data_check_iso.exe'
    assert sha(exe.read_bytes())==compiled['checker_sha256']
    cases=[json.loads(s) for s in (oracle/'oracle-cases.jsonl').read_text().splitlines()]
    reference=json.loads((oracle/'oracle-summary.ai.json').read_text())
    assert reference['status']=='pass' and not reference['unknown']
    bankpath=work/'sa2-bank-layout-v1/decoded-bank.bin'
    bank=bankpath.read_bytes();assert sha(bank)=='b7ea586ed0fa22330dc8a2cfe2bb8fa9ce4ac70d9561764f35af4ced5d371963'
    slotrows={}
    for row in csv.DictReader((oracle/'oracle-output-slots.csv').open(newline='')):slotrows.setdefault(row['case_id'],[]).append(row)
    for case in cases:
        cid=case['case_id'];records=bytes.fromhex(case['records_hex'])
        assert len(records)==case['count']*28
        assert int(case['gqr1_after'],16)==0x08070807
        if case['kind']=='real':
            source=bankpath;offset=int(case['packet_offset'],0)
            assert sha(bank)==case['input_source_sha256']
            assert bank[offset+8:offset+8+len(records)]==records
            header,info=struct.unpack_from('>II',bank,offset)
            assert (header&255,info>>16,info&65535,(header&0x7FFF)>>8)==(0x2C,case['count'],case['start'],case['variant'])
        else:
            source=out/(cid+'.input.bin');offset=0
            lookahead=bytes.fromhex(case['lookahead_hex'])
            assert sha(records+lookahead)==case['input_source_sha256']
            header=(((8+len(records))//4-1)<<16)|(case['variant']<<8)|0x802C
            source.write_bytes(struct.pack('>II',header,(case['count']<<16)|case['start'])+records+lookahead)
        beforepath=oracle/case['before_file'];before=beforepath.read_bytes()
        wanted=(oracle/case['after_file']).read_bytes()
        assert sha(before)==case['before_sha256'] and sha(wanted)==case['after_sha256']
        matrix=out/(cid+'.matrix.txt');matrix.write_text(' '.join(case['matrix_bits'])+'\n')
        output=out/(cid+'.output.bin');metadata=out/(cid+'.metadata.csv')
        run=subprocess.run([str(exe),str(source),hex(offset),str(matrix),str(beforepath),str(output),str(metadata)],capture_output=True,timeout=15)
        assert run.returncode==0,(cid,run.stderr.decode(errors='replace'))
        actual=output.read_bytes()
        assert actual==wanted,(cid,next((i for i,(a,b) in enumerate(zip(actual,wanted)) if a!=b),None),sha(actual),case['after_sha256'])
        assert metadata.read_text().strip()==f"{case['start']},{case['count']},{case['variant']}"
        assert sha(beforepath.read_bytes())==case['before_sha256']
        assert len(slotrows[cid])==case['count']
        for slot in slotrows[cid]:
            index=int(slot['scratch_index'])*32
            assert actual[index:index+32].hex()==slot['after_hex']
            assert before[index:index+32].hex()==slot['before_hex']
        rows.append({'case_id':cid,'kind':case['kind'],'packet_offset':hex(offset),'base_index':case['start'],'variant':case['variant'],'record_count':case['count'],'unique_targets':case['unique_targets'],'matrix_name':case['matrix_name'],'scratch_bytes':len(actual),'before_sha256':case['before_sha256'],'after_sha256':sha(actual),'status':'PASS'})
    assert len(rows)==sum(reference['cases'][k] for k in ('real','synthetic'))
    assert sum(r['record_count'] for r in rows)==sum(reference['cases'][k] for k in ('real_records','synthetic_records'))
    assert all(sha(Path(p).read_bytes())==digest for p,digest in compiled['source_sha256'].items())
    assert sha(bankpath.read_bytes())==sha(bank)
    host=json.loads((stage/'host-fixtures-v1.ai.json').read_text());assert host['status']=='PASS'
    report.update(status='PASS',cases=len(rows),real_cases=sum(r['kind']=='real' for r in rows),synthetic_cases=sum(r['kind']=='synthetic' for r in rows),real_unique_packets=len({r['packet_offset'] for r in rows if r['kind']=='real'}),output_record_rows=sum(r['record_count'] for r in rows),whole_scratch_bytes_compared=sum(r['scratch_bytes'] for r in rows),host_fixtures=host['result'],source_sha256=compiled['source_sha256'],checker_sha256=sha(exe.read_bytes()),bank_sha256=sha(bank),oracle_sha256={str(oracle/n):sha((oracle/n).read_bytes()) for n in ('oracle-cases.jsonl','oracle-summary.ai.json','oracle-output-slots.csv','weighted_oracle_v1.py')},production_corrections=0,original_game_or_dolphin_executed=False)
except Exception as error:report['reason']=repr(error)
finally:
    if rows:
        with (stage/'validation-cases-v1.csv').open('w',newline='') as stream:
            writer=csv.DictWriter(stream,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
    (stage/'validation-v1.ai.json').write_text(json.dumps(report,indent=2)+'\n')
    (stage/'validation-v1.md').write_text('# Weighted original-word comparison\n\n'+report['status']+': '+(f"{report['cases']} cases/{report['real_cases']} real from{report['real_unique_packets']} packets/{report['synthetic_cases']} synthetic;{report['output_record_rows']} record rows/{report['whole_scratch_bytes_compared']} whole scratch bytes match. {report['host_fixtures']}; no production correction." if report['status']=='PASS' else report.get('reason','unknown'))+'\n\n'+report['scope']+'\n')
print(json.dumps({k:v for k,v in report.items() if k not in ('source_sha256','oracle_sha256')}))
raise SystemExit(0 if report['status']=='PASS' else 1)
