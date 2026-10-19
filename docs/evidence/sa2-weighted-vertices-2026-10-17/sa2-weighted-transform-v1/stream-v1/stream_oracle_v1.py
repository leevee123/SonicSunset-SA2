from pathlib import Path
import csv,hashlib,importlib.util,json,struct,time
from collections import Counter

OUT=Path(__file__).resolve().parent;CORE=OUT.parent;WORK=CORE.parent
spec=importlib.util.spec_from_file_location('own_weighted_oracle',CORE/'weighted_oracle_v1.py')
weighted=importlib.util.module_from_spec(spec);spec.loader.exec_module(weighted)
own=weighted.own;Unsupported=own.Unsupported;MASK=0xffffffff;sha=lambda b:hashlib.sha256(b).hexdigest()
WORDS={}
with (CORE/'original-words.csv').open(newline='') as f:
    for r in csv.DictReader(f):WORDS[int(r['va'],0)]=dict(r)
with (WORK/'sa2-model-transform-v1/raw-instructions-verified.csv').open(newline='') as f:
    for r in csv.DictReader(f):
        va=int(r['original_virtual_address'],0)
        if r['owner']=='0x8011d1d4':continue
        WORDS[va]={'owner':r['owner'],'va':r['original_virtual_address'],'dol_offset':r['dol_file_offset'],'word':r['word'],'mnemonic':r['mnemonic'],'instruction':r['instruction']}
dol=(WORK/'sa2-disc/main.dol').read_bytes()
for row in WORDS.values():assert int.from_bytes(dol[int(row['dol_offset'],0):int(row['dol_offset'],0)+4],'big')==int(row['word'],16)
assert len(WORDS)==352
weighted.WORDS=WORDS

class Machine(weighted.Machine):
    def __init__(self,cid,source,offset,matrix,before,state,gqr1):
        super().__init__(cid,0,0,0,source,offset,matrix,before)
        self.pc=0x8011d1d4;self.r[3]=0x20000000+offset;self.r[4]=0x30000000;self.r[13]=0x803b52c0
        self.lr=0;self.gqr1=gqr1;self.active=None;self.calls=[];self.state_writes=[];self.end_offset=None
        globals_data=bytearray(0x200);struct.pack_into('>I',globals_data,0xc4,0x10000000);struct.pack_into('>I',globals_data,0x148,state)
        self.regions.append(('declared_SDA',0x803ae000,globals_data))
    def peek(self,address,n):
        name,base,buf,off=self.region(address,n);return bytes(buf[off:off+n])
    def read(self,address,n,kind):
        name,base,buf,off=self.region(address,n);value=bytes(buf[off:off+n])
        if kind!='stack':
            relative=off;unused=False
            if name=='input' and self.active is not None:
                relative=off-self.active['data_offset'];unused=relative>=self.active['count']*self.active['stride']
            self.loads.append({'case_id':self.caseid,'step':self.step,'va':hex(self.pc),'kind':kind,'region':name,'relative_offset':relative,'size':n,'raw_hex':value.hex(),'unused_final_preload':unused})
        return value
    def write(self,address,value,kind):
        if address==0x803ae148:
            self.state_writes.append({'case_id':self.caseid,'step':self.step,'va':hex(self.pc),'old':self.peek(address,4).hex(),'new':value.hex()})
        super().write(address,value,kind)
    def execute(self,maxsteps=300000):
        while True:
            if self.step>=maxsteps:raise Unsupported('stream bounded instruction limit')
            if self.pc==0x8011d2d4:self.end_offset=self.r[30]-0x20000000
            row=WORDS.get(self.pc)
            if row is None:raise Unsupported(f'unmodeled instruction address {self.pc:#x}')
            w=int(row['word'],16);pc=self.pc;op=w>>26;d,a,b=w>>21&31,w>>16&31,w>>11&31;xo=w>>1&1023
            spr=(w>>16&31)|(w>>11&31)<<5
            preempt=(op in (10,18,21,24,33,36,61) or (op==31 and xo==339) or (op==31 and xo==467 and spr==8) or w==0x4e800020)
            if not preempt:
                limit=self.step+1
                try:super().execute(maxsteps=limit)
                except Unsupported as error:
                    if str(error)=='bounded instruction limit' and self.step==limit:continue
                    raise
                raise AssertionError('unexpected underlying return')
            self.step+=1;self.coverage[hex(pc)]+=1;nextpc=(pc+4)&MASK
            imm=own.signed(w&0xffff,16);ea=((self.r[a] if a else 0)+imm)&MASK
            if op==10:self.eq=self.r[a]==(w&0xffff)
            elif op==24:self.r[a]=self.r[d]|(w&0xffff)
            elif op==33:self.r[d]=int.from_bytes(self.read(ea,4,'raw_lwzu'),'big');self.r[a]=ea
            elif op==36:self.write(ea,struct.pack('>I',self.r[d]),'stw')
            elif op==21:
                sh=b;mb=w>>6&31;me=w>>1&31
                mask=sum(1<<(31-k) for k in range(32) if (mb<=k<=me if mb<=me else k>=mb or k<=me))
                rotated=((self.r[d]<<sh)|(self.r[d]>>(32-sh)))&MASK if sh else self.r[d]
                self.r[a]=rotated&mask
            elif op==31 and xo==339:
                if spr!=8:raise Unsupported('mfspr other than LR')
                self.r[d]=self.lr
            elif op==31 and xo==467:self.lr=self.r[d]
            elif op==61:
                W=w>>15&1;I=w>>12&7
                if I:raise Unsupported('nonzero store GQR')
                address=(self.r[a]+own.signed(w&0xfff,12))&MASK
                values=[own.ftz(v) for v in self.ps[d][:1 if W else 2]]
                self.write(address,struct.pack('>I' if W else '>II',*values),'psq_stu_W'+str(W));self.r[a]=address
            elif op==18:
                target=(own.signed(w&0x3fffffc,26) if w&2 else pc+own.signed(w&0x3fffffc,26))&MASK
                if w&1:
                    self.lr=(pc+4)&MASK
                    if target==0x8011dc10:raise Unsupported('op2A helper8011DC10 deliberately unmodeled after native stateOR2 prefix')
                    if target not in (0x8011da30,0x8011daf0,0x8011dc98):raise Unsupported(f'unmodeled BL {target:#x}')
                    destination,data,count=struct.unpack('>III',self.peek(self.r[3],12));opcode={0x8011da30:0x23,0x8011daf0:0x29,0x8011dc98:0x2c}[target]
                    self.active={'data_offset':data-0x20000000,'count':count,'stride':{0x23:16,0x29:24,0x2c:28}[opcode]}
                    self.calls.append({'case_id':self.caseid,'step':self.step,'call_va':hex(pc),'target':hex(target),'opcode':hex(opcode),'packet_offset':hex(data-0x20000000-8),'data_offset':data-0x20000000,'base_scratch_index':(destination-0x30000000)//32,'count':count,'variant':self.r[5] if opcode==0x2c else '', 'matrix_pointer':hex(self.r[4]),'gqr1_before':f'{self.gqr1:08x}'})
                    assert self.r[4]==0x10000000
                nextpc=target
            elif w==0x4e800020:
                if self.lr==0:break
                nextpc=self.lr&~3;self.active=None
            self.pc=nextpc
        return bytes(self.regions[2][2])

def scan(source,offset):
    p=offset;commands=[];targets=set()
    for _ in range(10000):
        header=int.from_bytes(source[p:p+4],'big');opcode=header&255
        if opcode==255:return commands,targets,p+4
        info=int.from_bytes(source[p+4:p+8],'big');count,start=info>>16,info&65535
        commands.append({'offset':p,'opcode':opcode,'count':count,'start':start,'variant':(header&0x7fff)>>8})
        if opcode in (0x23,0x29):targets.update(range(start,start+count))
        elif opcode==0x2c:targets.update(start+struct.unpack_from('>H',source,p+8+n*28+26)[0] for n in range(count))
        p+=4*((header>>16)+1)
        if p+4>len(source):raise Unsupported('scan bounds')
    raise Unsupported('scan limit')

def main():
    began=time.time();bankpath=WORK/'sa2-disc/sonicmdl.prs.decoded';bank=bankpath.read_bytes()
    streampath=WORK/'model-data-stage/docs-prepared-v1/docs/evidence/sa2-model-payload-first-stream-sample-streams.csv'
    with streampath.open(newline='') as f:streams=list(csv.DictReader(f))
    assert len(streams)==100
    matrices={name:tuple(int(v,16) for v in values) for name,values in json.loads((CORE/'matrix-cases.json').read_text()).items()}
    cases=[]
    for index,stream in enumerate(streams):
        offset=int(stream['stream_decoded_offset'],0);commands,targets,end=scan(bank,offset)
        assert end-offset==int(stream['consumed_bytes_through_EOS']) and sha(bank[offset:end])==stream['consumed_sha256']
        for matrixname,matrix in matrices.items():cases.append({'case_id':f'real_{index:03d}_{matrixname}','kind':'real','source':bank,'source_file':str(bankpath),'stream_offset':offset,'matrix_name':matrixname,'matrix_bits':matrix,'initial_state':0xa5a50040,'initial_gqr1':0x13572468,'commands':commands,'targets':targets,'expected_end':end})
    inputfolder=OUT/'inputs';inputfolder.mkdir(exist_ok=False)
    def add(name,source,state=0xdeadbeec,gqr=0x24681357,matrix=None):
        path=inputfolder/(name+'.bin');path.write_bytes(source);commands,targets,end=scan(source,0)
        cases.append({'case_id':'synthetic_'+name,'kind':'synthetic','source':source,'source_file':str(path),'stream_offset':0,'matrix_name':'identity','matrix_bits':matrix or matrices['identity'],'initial_state':state,'initial_gqr1':gqr,'commands':commands,'targets':targets,'expected_end':end})
    END=struct.pack('>I',0x123400ff);padding=bytes(24)
    words=tuple(own.bitsof(float(v)) for v in (1,2,3,4,5,6))
    def packet23():return struct.pack('>II4I',(5<<16)|0x8023,0x00010003,*words[:3],0x12345678)
    def packet2c(mode,source=words,weight=128,start=3,bit15=True):return struct.pack('>II',8<<16|mode<<8|(0x8000 if bit15 else 0)|0x2c,1<<16|start)+weighted.record(source,weight,0)
    add('END_highbits_only',struct.pack('>I',0xdeadbeff))
    add('unknown4_overlaps_ENDinfo',struct.pack('>I',0x55)+END)
    add('unknown12_skip',struct.pack('>III',0x00020055,0x89abcdef,0x7fc00001)+END)
    add('23_state_OR3_GQR_preserve',packet23()+END+padding,state=0xfffffffc)
    add('23_then_weighted_preserve_raw24',packet23()+packet2c(0)+END+padding)
    add('weighted_bit15_mode0',packet2c(0)+END+padding)
    add('weighted_bit15_clear_mode2',packet2c(2,bit15=False)+END+padding)
    add('weighted_bit15_set_mode127',packet2c(127)+END+padding)
    add('weighted_overwrite_then_accumulate',packet2c(0)+packet2c(2)+END+padding)
    before=weighted.sentinel(512);beforepath=OUT/'initial-scratch.bin';beforepath.write_bytes(before)
    outputfolder=OUT/'cases';outputfolder.mkdir(exist_ok=False)
    handles=[]
    def makecsv(name,fields):
        f=(OUT/name).open('w',newline='');handles.append(f);w=csv.DictWriter(f,fieldnames=fields);w.writeheader();return w
    loadwriter=makecsv('native-loads.csv',['case_id','step','va','kind','region','relative_offset','size','raw_hex','unused_final_preload'])
    storewriter=makecsv('native-stores.csv',['case_id','step','va','kind','scratch_offset','size','raw_hex'])
    callwriter=makecsv('native-helper-calls.csv',['case_id','step','call_va','target','opcode','packet_offset','data_offset','base_scratch_index','count','variant','matrix_pointer','gqr1_before'])
    statewriter=makecsv('native-state-writes.csv',['case_id','step','va','old','new'])
    slotwriter=makecsv('final-slots.csv',['case_id','scratch_index','before_hex','after_hex'])
    jf=(OUT/'cases.jsonl').open('w');handles.append(jf)
    coverage=Counter();unknown=[];counts=Counter();steps=0;written_slots=0;calls=Counter();outputs=[]
    try:
        for case in cases:
            matrixbytes=struct.pack('>12I',*case['matrix_bits']);machine=Machine(case['case_id'],case['source'],case['stream_offset'],matrixbytes,before,case['initial_state'],case['initial_gqr1'])
            try:after=machine.execute()
            except Unsupported as error:unknown.append({'case_id':case['case_id'],'pc':hex(machine.pc),'reason':str(error),'steps':machine.step});continue
            state=int.from_bytes(machine.peek(0x803ae148,4),'big')
            assert machine.end_offset==case['expected_end'] and machine.r[3]==0 and machine.r[1]==0x40000800 and machine.lr==0
            assert state==case['initial_state']|(3 if any(p['opcode']==0x23 for p in case['commands']) else 0)
            assert machine.gqr1==(0x08070807 if any(p['opcode']==0x2c for p in case['commands']) else case['initial_gqr1'])
            assert bytes(machine.regions[0][2])==matrixbytes and bytes(machine.regions[1][2])==case['source'] and machine.peek(0x803ae0c4,4)==struct.pack('>I',0x10000000)
            assert all(before[i]==after[i] for i in range(len(before)) if i not in machine.written)
            actualtargets=sorted({i//32 for i in machine.written});assert set(actualtargets)==case['targets']
            assert len(machine.calls)==sum(p['opcode'] in (0x23,0x29,0x2c) for p in case['commands'])
            path=outputfolder/(case['case_id']+'.after.bin');path.write_bytes(after)
            row={k:v for k,v in case.items() if k not in ('source','matrix_bits','targets')}
            row.update(matrix_bits=[f'{v:08x}' for v in case['matrix_bits']],initial_state=f'{case["initial_state"]:08x}',initial_gqr1=f'{case["initial_gqr1"]:08x}',final_state=f'{state:08x}',final_gqr1=f'{machine.gqr1:08x}',end_offset=machine.end_offset,before_file=str(beforepath.relative_to(OUT)),after_file=str(path.relative_to(OUT)),before_sha256=sha(before),after_sha256=sha(after),source_sha256=sha(case['source']),steps=machine.step,target_indices=actualtargets,helper_calls=len(machine.calls))
            jf.write(json.dumps(row,separators=(',',':'))+'\n');loadwriter.writerows(machine.loads);storewriter.writerows(machine.stores);callwriter.writerows(machine.calls);statewriter.writerows(machine.state_writes)
            for index in actualtargets:slotwriter.writerow({'case_id':case['case_id'],'scratch_index':index,'before_hex':before[index*32:index*32+32].hex(),'after_hex':after[index*32:index*32+32].hex()})
            coverage.update(machine.coverage);counts[case['kind']]+=1;steps+=machine.step;written_slots+=len(actualtargets);calls.update(r['opcode'] for r in machine.calls);outputs.append(row['after_sha256'])
    finally:
        for f in handles:f.close()
    opaque=struct.pack('>II6I',7<<16|0x802a,1<<16,*words)+END+padding
    machine=Machine('unsupported_op2A_prefix',opaque,0,struct.pack('>12I',*matrices['identity']),before,0xa5a50040,0x13572468)
    try:machine.execute();raise AssertionError('op2A unexpectedly executed')
    except Unsupported as error:unsupported={'reason':str(error),'pc':hex(machine.pc),'state_after_original_prefix':machine.peek(0x803ae148,4).hex(),'gqr1_after':f'{machine.gqr1:08x}','scratch_unchanged':bytes(machine.regions[2][2])==before}
    assert unsupported['state_after_original_prefix']=='a5a50042' and unsupported['scratch_unchanged']
    summary={'status':'pass' if not unknown else 'partial','cases':dict(counts),'steps':steps,'final_slot_rows':written_slots,'helper_calls_by_opcode':dict(calls),'distinct_executed_words':len(coverage),'coverage':dict(sorted(coverage.items())),'unknown':unknown,'unsupported_op2A_original_prefix':unsupported,'original_words_available':len(WORDS),'ordered_output_hashes_sha256':sha(''.join(outputs).encode()),'seconds':time.time()-began,'inputs_sha256':{str(bankpath):sha(bank),str(streampath):sha(streampath.read_bytes()),str(CORE/'original-words.csv'):sha((CORE/'original-words.csv').read_bytes()),str(WORK/'sa2-model-transform-v1/raw-instructions-verified.csv'):sha((WORK/'sa2-model-transform-v1/raw-instructions-verified.csv').read_bytes()),str(CORE/'weighted_oracle_v1.py'):sha((CORE/'weighted_oracle_v1.py').read_bytes()),str(WORK/'sa2-disc/main.dol'):sha(dol)},'binding_contract':'Explicit test r13=803B52C0; SDA803AE0C4=matrix10000000; SDA803AE148=callerState; GQR0=0/GQR1=callerValue; own original-word BL/LR/SP/SDA+helpers execution, not retail/runtime/Dolphin execution; finite arithmetic RNnearest/NI0/nontrapping; disjoint source/matrix/scratch/stack/globals'}
    (OUT/'summary.ai.json').write_text(json.dumps(summary,indent=2));(OUT/'unsupported.json').write_text(json.dumps(unknown,indent=2))
    with (OUT/'original-words.csv').open('w',newline='') as f:
        fields=['owner','va','dol_offset','word','mnemonic','instruction'];w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows({k:r[k] for k in fields} for va,r in sorted(WORDS.items()))
    (OUT/'report.md').write_text('# Original first-stream dispatcher closure\n\n'+summary['binding_contract']+'.\n\nAll100 original Sonic streams run under three declared matrices with identical fresh finite512-slot scratch. Initial state/GQR1 are explicit per-case fields, not inferred retail values. Original352 available words cover dispatcher8011D1D4 and helpersDA30/DAF0/DC98. This reuses the own raw-word interpreter and exact-rational PS math; no engine formula or actual Dolphin/game execution is used.\n\nThe interpreter executes original BL/LR/stack/SDA behavior. Dispatcher constructs helper descriptors on its own emulated stack; original state writes OR3 for op23, while weighted GQR1 writes persist. Original ENDlowFF stops before info read; unknown opcodes still read info and use encoded skip including4-byte overlap. Final end offset is a captured analysis trace value at the original exit, not an invented native return cursor; original r3 returns0.\n\nNine synthetic successful streams cover high-bit END,4-byte unknown/info overlap,12-byte unknown skip, state-bit carry/GQR preservation, op23 followed by weighted preserving rawslot+24, weighted bit15 mode0/clear mode2/set127, and overwrite followed by accumulation. Complete source binaries, before/after hashes, matrix/state/GQR values and logical end are in cases.jsonl; all native loads/stores/helpercalls/statewrites and final32-byte slots are retained in CSV.\n\nOp2A is deliberately unsupported. A separately retained original prefix reaches its opaque helper call8011DC10 after stateOR2, with scratch unchanged at that stopping point. No op2A numerical body, return, or host rollback behavior is invented. Native aliases, unsafe zero-count loops, unmodeled FPSCR side effects, other GQR0 modes and actual matrix/caller binding remain excluded. No engine/repo/original/frozen/language changes; weighted core314-case boundary artifacts remain untouched.\n')
    (OUT/'report.ai.md').write_text('OwnrawfirststreamD1D4+DA30/DAF0/DC98/352availablewords;real100*3declaredmatrices/freshfinite512slots/explicitcallerstateGQR. BL/LR/SP/originalstackdescriptor/SDA modeled;test r13=803B52C0,803AE0C4matrix10000000,803AE148state/GQR0=0 notliveproof. ExactrationalFP RNnearestNI0/nontrapping/storeFTZ/disjointbuffers. Original23OR3/weightedGQR1clobber/nohelper ENDorunknown preserve. CapturelogicalENDoffsetatnativeexit(r3native0). 9synthetics ENDhighbits/unknown4overlap/unknown12/statecarry/23thenweighted/raw24preserve/bit15mode0-clear2-set127/orderedcrosspacketaccum. Op2AopaqueatDC10/refusedafteroriginalOR2prefix/noinventedbody. Completecaseinputs/beforeafterbins+hash/calls/state/load/store/finalslotsCSV/sourcewords;exactcountsJSON. Noenginecopy/retailDolphinexecution/repochanges/coreartifactmutation.\n')
    print(json.dumps({k:summary[k] for k in ('status','cases','steps','final_slot_rows','helper_calls_by_opcode','distinct_executed_words','original_words_available','unsupported_op2A_original_prefix','seconds')}))
    if unknown:print('First unknown',json.dumps(unknown[0]))

if __name__=='__main__':main()
